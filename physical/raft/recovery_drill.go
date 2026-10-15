// Copyright IBM Corp. 2025
// SPDX-License-Identifier: BUSL-1.1

package raft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/raft"
)

// This file implements a read-only recovery drill for the raft backend. The
// drill simulates the checks performed during a real disaster recovery
// (snapshot verification, peer list reconstruction and node restart) without
// mutating any cluster state: it never calls raft.RecoverCluster or Restore,
// never adds or removes servers and never writes a peers.json file. A drill
// therefore cannot change cluster membership; an actual recovery still
// requires the operator's explicit, out-of-band confirmation.

const (
	// RecoveryDrillPhaseSnapshotVerify simulates verification of the local
	// snapshot and raft state stores.
	RecoveryDrillPhaseSnapshotVerify = "snapshot_verify"

	// RecoveryDrillPhasePeerRebuild simulates reconstruction of the raft
	// peer/configuration set and probes peer reachability.
	RecoveryDrillPhasePeerRebuild = "peer_rebuild"

	// RecoveryDrillPhaseNodeRestart simulates the pre-start checks a node
	// performs when it rejoins the cluster.
	RecoveryDrillPhaseNodeRestart = "node_restart"
)

var recoveryDrillPhaseOrder = []string{
	RecoveryDrillPhaseSnapshotVerify,
	RecoveryDrillPhasePeerRebuild,
	RecoveryDrillPhaseNodeRestart,
}

const (
	drillStatusRunning  = "running"
	drillStatusPassed   = "passed"
	drillStatusBlocked  = "blocked"
	drillStatusCanceled = "canceled"

	drillPhaseStatusRunning  = "running"
	drillPhaseStatusPassed   = "passed"
	drillPhaseStatusBlocked  = "blocked"
	drillPhaseStatusCanceled = "canceled"
	drillPhaseStatusSkipped  = "skipped"

	drillSeverityWarning = "warning"
	drillSeverityBlocker = "blocker"
)

var (
	// ErrRecoveryDrillNotFound is returned when no drill exists for the
	// supplied (or implicit) drill id.
	ErrRecoveryDrillNotFound = errors.New("raft recovery drill not found")

	// ErrRecoveryDrillNotActive is returned when an operation requires a
	// running drill but the most recent drill has already finished.
	ErrRecoveryDrillNotActive = errors.New("no active raft recovery drill")
)

var (
	defaultDrillProbeAttempts = 3
	defaultDrillProbeTimeout  = 2 * time.Second
	defaultDrillProbeBackoff  = 200 * time.Millisecond
	drillCancelWaitTimeout    = 5 * time.Second
)

// RecoveryDrillBlocker describes a single finding of a drill phase. Findings
// with Severity "warning" do not prevent recovery; findings with severity
// "blocker" do. Retriable findings (for example an unreachable peer) are
// expected to clear on their own and can be re-checked by resuming the drill
// from the reported checkpoint.
type RecoveryDrillBlocker struct {
	// Code is the machine readable identifier of the finding.
	Code string `json:"code"`

	// Message is a human readable description of the finding.
	Message string `json:"message"`

	// Phase is the drill phase that produced the finding.
	Phase string `json:"phase"`

	// Severity is either "warning" or "blocker".
	Severity string `json:"severity"`

	// Retriable is true when the condition is expected to be transient and a
	// re-run of the phase may succeed.
	Retriable bool `json:"retriable"`
}

// RecoveryDrillCheckpoint marks the point up to which the drill has verified
// state. A re-run or continuation can use it to report where a blocked or
// canceled drill would resume; it never encodes a mutation to perform.
type RecoveryDrillCheckpoint struct {
	// Phase that produced the checkpoint.
	Phase string `json:"phase"`

	// Resumable reports whether the drill can be continued from this
	// checkpoint.
	Resumable bool `json:"resumable"`

	// SnapshotID is the identifier of the verified snapshot.
	SnapshotID string `json:"snapshot_id,omitempty"`

	// SnapshotIndex is the raft index contained in the snapshot.
	SnapshotIndex uint64 `json:"snapshot_index,omitempty"`

	// ConfigIndex is the raft configuration index the peer rebuild was
	// evaluated against.
	ConfigIndex uint64 `json:"config_index,omitempty"`

	// AppliedIndex is the FSM applied index observed by the drill.
	AppliedIndex uint64 `json:"applied_index,omitempty"`

	// LastIndex is the last raft log index observed by the drill.
	LastIndex uint64 `json:"last_index,omitempty"`

	// Note carries checkpoint specific context.
	Note string `json:"note,omitempty"`
}

// RecoveryDrillProbe records the network probe results for a single peer
// address.
type RecoveryDrillProbe struct {
	// Address that was probed.
	Address string `json:"address"`

	// NodeIDs that use this address (multiple ids indicate a conflict).
	NodeIDs []string `json:"node_ids"`

	// Attempts is the number of probes that were issued.
	Attempts int `json:"attempts"`

	// Failures is the number of failed probe attempts.
	Failures int `json:"failures"`

	// Status is "reachable", "flaky" or "unreachable".
	Status string `json:"status"`

	// LastError contains the error of the final failed attempt.
	LastError string `json:"last_error,omitempty"`
}

// RecoveryDrillPhaseResult is the per-phase result of a drill.
type RecoveryDrillPhaseResult struct {
	// Name is the name of the phase.
	Name string `json:"name"`

	// Status is one of running, passed, blocked, canceled or skipped.
	Status string `json:"status"`

	// StartedAt is when the phase started executing.
	StartedAt time.Time `json:"started_at,omitempty"`

	// EndedAt is when the phase stopped executing.
	EndedAt time.Time `json:"ended_at,omitempty"`

	// Blockers contains all findings of the phase.
	Blockers []*RecoveryDrillBlocker `json:"blockers,omitempty"`

	// Checkpoint is the resumable checkpoint of the phase.
	Checkpoint RecoveryDrillCheckpoint `json:"checkpoint"`

	// Details contains phase specific, JSON-encodable diagnostic data.
	Details map[string]interface{} `json:"details,omitempty"`
}

// RecoveryDrillState is the full state and result of a recovery drill.
type RecoveryDrillState struct {
	mu sync.RWMutex `json:"-"`

	// ID uniquely identifies the drill run.
	ID string `json:"id"`

	// Status is the overall state of the drill: running, passed, blocked or
	// canceled.
	Status string `json:"status"`

	// CurrentPhase is the phase that is currently executing, if any.
	CurrentPhase string `json:"current_phase,omitempty"`

	// Phases holds the ordered per-phase results.
	Phases []*RecoveryDrillPhaseResult `json:"phases"`

	// StartedAt is when the drill was created.
	StartedAt time.Time `json:"started_at"`

	// FinishedAt is when the drill stopped executing.
	FinishedAt time.Time `json:"finished_at,omitempty"`

	// ReadyForRecovery is true when no blocking findings were reported. It
	// does not authorize recovery; ConfirmationRequired always remains true.
	ReadyForRecovery bool `json:"ready_for_recovery"`

	// ConfirmationRequired is always true: a drill never performs recovery
	// itself, an explicit, out-of-band confirmation is still required.
	ConfirmationRequired bool `json:"confirmation_required"`

	// MutatesMembership is true when the simulated recovery plan differs
	// from the current membership. The drill itself never applies the plan.
	MutatesMembership bool `json:"mutates_membership"`

	// Blockers is the flattened list of all phase findings.
	Blockers []*RecoveryDrillBlocker `json:"blockers,omitempty"`

	// Checkpoint is the latest checkpoint reached by the drill.
	Checkpoint *RecoveryDrillCheckpoint `json:"checkpoint,omitempty"`

	// Duplicate is true when the state was returned in response to a start
	// request while another drill was already running. The existing drill is
	// returned unchanged.
	Duplicate bool `json:"duplicate,omitempty"`
}

// RecoveryDrillOpts configures a read-only recovery drill.
type RecoveryDrillOpts struct {
	// IntendedPeers is the peer set a real recovery would use (equivalent
	// to the contents of peers.json). When nil, the current raft
	// configuration, or the last configuration persisted in the FSM when
	// raft is offline, is used as the reconstructed peer list.
	IntendedPeers []Peer `json:"-"`

	// ProbeAttempts is the number of reachability attempts made for each
	// peer address. Retries are what allow the drill to tolerate network
	// jitter. Defaults to 3.
	ProbeAttempts int `json:"probe_attempts,omitempty"`

	// ProbeTimeout is the timeout for a single probe attempt. Defaults to
	// 2 seconds.
	ProbeTimeout time.Duration `json:"-"`

	// ProbeBackoff is the wait between probe attempts. Defaults to 200ms.
	ProbeBackoff time.Duration `json:"-"`

	// PhaseDelay inserts an interruptible delay before each phase. It is
	// mostly useful to leave a window in which the drill can be canceled.
	PhaseDelay time.Duration `json:"-"`

	// Probe overrides the network probe function. When nil a TCP dial probe
	// is used. Tests inject it to simulate jitter and partitions.
	Probe func(ctx context.Context, address string) error `json:"-"`
}

// recoveryDrillRun tracks a single managed (background) drill.
type recoveryDrillRun struct {
	state  *RecoveryDrillState
	cancel context.CancelFunc
	doneCh chan struct{}
}

// drillRunCtx carries observations shared across drill phases.
type drillRunCtx struct {
	online   bool
	current  []raft.Server
	intended []raft.Server
	// probes is keyed by peer address.
	probes map[string]*RecoveryDrillProbe
	// mutates is set when the simulated recovery plan differs from the
	// current membership. The drill itself never applies the plan.
	mutates bool
}

func newRecoveryDrillState(id string) *RecoveryDrillState {
	phases := make([]*RecoveryDrillPhaseResult, 0, len(recoveryDrillPhaseOrder))
	for _, name := range recoveryDrillPhaseOrder {
		phases = append(phases, &RecoveryDrillPhaseResult{
			Name:       name,
			Status:     "pending",
			Checkpoint: RecoveryDrillCheckpoint{Phase: name},
		})
	}
	return &RecoveryDrillState{
		ID:                   id,
		Status:               drillStatusRunning,
		Phases:               phases,
		StartedAt:            time.Now().UTC(),
		ConfirmationRequired: true,
	}
}

func (s *RecoveryDrillState) id() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ID
}

// isActive reports whether the drill is still executing.
func (s *RecoveryDrillState) isActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Status == drillStatusRunning
}

// clone returns a detached, JSON round-tripped copy of the state.
func (s *RecoveryDrillState) clone() *RecoveryDrillState {
	s.mu.RLock()
	buf, err := json.Marshal(s)
	s.mu.RUnlock()

	// All state contents are JSON-encodable; if serialization ever fails
	// return a detached placeholder rather than a copy that carries the
	// mutex.
	if err != nil {
		return &RecoveryDrillState{
			ID:                   s.id(),
			Status:               "unknown",
			Phases:               []*RecoveryDrillPhaseResult{},
			ConfirmationRequired: true,
		}
	}
	var cp RecoveryDrillState
	if err := json.Unmarshal(buf, &cp); err != nil {
		return &RecoveryDrillState{
			ID:                   s.id(),
			Status:               "unknown",
			Phases:               []*RecoveryDrillPhaseResult{},
			ConfirmationRequired: true,
		}
	}
	return &cp
}

func (s *RecoveryDrillState) begin(name string) *RecoveryDrillPhaseResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentPhase = name
	for _, p := range s.Phases {
		if p.Name != name {
			continue
		}
		// begin is idempotent: the runner marks the phase running before its
		// interruptible delay, and the phase implementation enters it again.
		if p.Status == drillPhaseStatusRunning {
			return p
		}
		p.Status = drillPhaseStatusRunning
		p.StartedAt = time.Now().UTC()
		return p
	}
	return nil
}

func (s *RecoveryDrillState) addFinding(p *RecoveryDrillPhaseResult, code, message, severity string, retriable bool) {
	finding := &RecoveryDrillBlocker{
		Code:      code,
		Message:   message,
		Phase:     p.Name,
		Severity:  severity,
		Retriable: retriable,
	}
	s.mu.Lock()
	p.Blockers = append(p.Blockers, finding)
	s.mu.Unlock()
}

func (s *RecoveryDrillState) setCheckpoint(p *RecoveryDrillPhaseResult, cp RecoveryDrillCheckpoint) {
	cp.Phase = p.Name
	s.mu.Lock()
	p.Checkpoint = cp
	s.Checkpoint = &p.Checkpoint
	s.mu.Unlock()
}

func (s *RecoveryDrillState) setDetail(p *RecoveryDrillPhaseResult, key string, value interface{}) {
	s.mu.Lock()
	if p.Details == nil {
		p.Details = make(map[string]interface{})
	}
	p.Details[key] = value
	s.mu.Unlock()
}

func (s *RecoveryDrillState) setDetails(p *RecoveryDrillPhaseResult, details map[string]interface{}) {
	s.mu.Lock()
	p.Details = details
	s.mu.Unlock()
}

// finish computes the final status of a phase from its findings.
func (s *RecoveryDrillState) finish(p *RecoveryDrillPhaseResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.EndedAt = time.Now().UTC()
	if s.CurrentPhase == p.Name {
		s.CurrentPhase = ""
	}
	if p.Status == drillPhaseStatusCanceled {
		return
	}
	for _, f := range p.Blockers {
		if f.Severity == drillSeverityBlocker {
			p.Status = drillPhaseStatusBlocked
			return
		}
	}
	p.Status = drillPhaseStatusPassed
}

// promoteCheckpoint makes the phase checkpoint the aggregate drill
// checkpoint when none has been published yet.
func (s *RecoveryDrillState) promoteCheckpoint(p *RecoveryDrillPhaseResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Checkpoint == nil {
		cp := p.Checkpoint
		s.Checkpoint = &cp
	}
}

// cancelRemaining marks the current phase as canceled and all phases that did
// not run as skipped.
func (s *RecoveryDrillState) cancelRemaining() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, p := range s.Phases {
		switch p.Status {
		case drillPhaseStatusRunning:
			p.Status = drillPhaseStatusCanceled
			p.EndedAt = now
			p.Blockers = append(p.Blockers, &RecoveryDrillBlocker{
				Code:      "drill_canceled",
				Message:   "the recovery drill was canceled during this phase; it can be resumed from the reported checkpoint",
				Phase:     p.Name,
				Severity:  drillSeverityBlocker,
				Retriable: true,
			})
			p.Checkpoint.Resumable = true
			// Promote the interrupted phase checkpoint even when cancellation
			// arrived before the phase body populated it, so callers always
			// know where a resumed drill would continue.
			if s.Checkpoint == nil {
				cp := p.Checkpoint
				s.Checkpoint = &cp
			}
		case "pending":
			p.Status = drillPhaseStatusSkipped
		}
	}
	s.CurrentPhase = ""
}

// finalize computes the aggregate drill status after all phases ran (or the
// drill was canceled).
func (s *RecoveryDrillState) finalize(canceled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.FinishedAt = time.Now().UTC()
	s.CurrentPhase = ""

	if canceled {
		s.Status = drillStatusCanceled
	} else {
		s.Status = drillStatusPassed
		for _, p := range s.Phases {
			if p.Status == drillPhaseStatusBlocked {
				s.Status = drillStatusBlocked
			}
		}
	}

	for _, p := range s.Phases {
		s.Blockers = append(s.Blockers, p.Blockers...)
	}
	s.ReadyForRecovery = s.Status == drillStatusPassed
}

// RunRecoveryDrill executes a read-only recovery drill synchronously and
// returns its state. It never returns a Go error for findings: blocking
// conditions and internal errors are recorded in the returned state. The
// context governs cancellation: when it is canceled the drill stops at the
// current phase checkpoint and marks the remaining phases skipped.
func (b *RaftBackend) RunRecoveryDrill(ctx context.Context, opts RecoveryDrillOpts) *RecoveryDrillState {
	id, err := uuid.GenerateUUID()
	if err != nil {
		id = fmt.Sprintf("drill-%d", time.Now().UnixNano())
	}
	state := newRecoveryDrillState(id)
	opts = normalizeRecoveryDrillOpts(opts)
	b.runRecoveryDrill(ctx, state, opts)
	return state
}

// StartRecoveryDrill starts a read-only recovery drill in the background.
// Only one drill may run at a time: if a drill is already active the state of
// the existing drill is returned with Duplicate set to true and no second
// drill is created (an idempotent, duplicate "join" of the drill itself).
func (b *RaftBackend) StartRecoveryDrill(ctx context.Context, opts RecoveryDrillOpts) (*RecoveryDrillState, error) {
	b.drillMu.Lock()
	if b.drill != nil && b.drill.state.isActive() {
		current := b.drill.state.clone()
		current.Duplicate = true
		b.drillMu.Unlock()
		return current, nil
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		b.drillMu.Unlock()
		return nil, fmt.Errorf("failed to allocate recovery drill id: %w", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	state := newRecoveryDrillState(id)
	run := &recoveryDrillRun{
		state:  state,
		cancel: cancel,
		doneCh: make(chan struct{}),
	}
	// Retain the previous, finished drill so that callers targeting its id get
	// a precise "not active" answer rather than "not found".
	b.drillPrevious = b.drill
	b.drill = run
	b.drillMu.Unlock()

	go func() {
		defer close(run.doneCh)
		b.runRecoveryDrill(runCtx, state, normalizeRecoveryDrillOpts(opts))
	}()

	return state.clone(), nil
}

// findRecoveryDrillRun resolves a drill id (empty means the most recent
// drill) against the current and retained previous runs.
func (b *RaftBackend) findRecoveryDrillRun(drillID string) *recoveryDrillRun {
	if b.drill != nil && (drillID == "" || b.drill.state.id() == drillID) {
		return b.drill
	}
	if b.drillPrevious != nil && drillID != "" && b.drillPrevious.state.id() == drillID {
		return b.drillPrevious
	}
	return nil
}

// RecoveryDrillStatus returns the state of the most recent drill. When
// drillID is non-empty it must match the current or previous drill.
func (b *RaftBackend) RecoveryDrillStatus(drillID string) (*RecoveryDrillState, error) {
	b.drillMu.Lock()
	run := b.findRecoveryDrillRun(drillID)
	b.drillMu.Unlock()

	if run == nil {
		return nil, ErrRecoveryDrillNotFound
	}
	return run.state.clone(), nil
}

// CancelRecoveryDrill cancels the currently running drill and waits briefly
// for it to reach its canceled checkpoint.
func (b *RaftBackend) CancelRecoveryDrill(drillID string) (*RecoveryDrillState, error) {
	b.drillMu.Lock()
	run := b.findRecoveryDrillRun(drillID)
	if run == nil {
		b.drillMu.Unlock()
		return nil, ErrRecoveryDrillNotFound
	}
	if !run.state.isActive() {
		state := run.state.clone()
		b.drillMu.Unlock()
		return state, ErrRecoveryDrillNotActive
	}
	run.cancel()
	doneCh := run.doneCh
	state := run.state
	b.drillMu.Unlock()

	select {
	case <-doneCh:
	case <-time.After(drillCancelWaitTimeout):
	}
	return state.clone(), nil
}

// cancelActiveRecoveryDrill best-effort cancels a running drill. It is used
// when the backend is closed.
func (b *RaftBackend) cancelActiveRecoveryDrill() {
	b.drillMu.Lock()
	if b.drill != nil && b.drill.state.isActive() {
		b.drill.cancel()
	}
	b.drillMu.Unlock()
}

func normalizeRecoveryDrillOpts(opts RecoveryDrillOpts) RecoveryDrillOpts {
	if opts.ProbeAttempts <= 0 {
		opts.ProbeAttempts = defaultDrillProbeAttempts
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = defaultDrillProbeTimeout
	}
	if opts.ProbeBackoff <= 0 {
		opts.ProbeBackoff = defaultDrillProbeBackoff
	}
	if opts.Probe == nil {
		opts.Probe = defaultRecoveryDrillProbe
	}
	return opts
}

func (b *RaftBackend) runRecoveryDrill(ctx context.Context, state *RecoveryDrillState, opts RecoveryDrillOpts) {
	b.logger.Debug("raft recovery drill started")
	defer b.logger.Debug("raft recovery drill finished")

	rc := &drillRunCtx{
		probes: make(map[string]*RecoveryDrillProbe),
	}

	for _, name := range recoveryDrillPhaseOrder {
		// Enter the phase before any context check so that a cancellation
		// that arrives before the phase body runs is still attributed to the
		// phase (which keeps a resumable checkpoint) instead of leaving every
		// phase in a pending state.
		phase := state.begin(name)
		if ctx.Err() != nil {
			state.addFinding(phase, "drill_canceled",
				"the recovery drill was canceled before this phase ran; it can be resumed from the reported checkpoint",
				drillSeverityBlocker, true)
			phase.Checkpoint.Resumable = true
			state.promoteCheckpoint(phase)
			state.finishCanceled(phase)
			state.cancelRemaining()
			state.finalize(true)
			return
		}

		// The interruptible delay is taken inside the phase for the same
		// reason.
		if opts.PhaseDelay > 0 {
			if err := sleepWithContext(ctx, opts.PhaseDelay); err != nil {
				state.addFinding(phase, "drill_canceled",
					"the recovery drill was canceled during this phase; it can be resumed from the reported checkpoint",
					drillSeverityBlocker, true)
				phase.Checkpoint.Resumable = true
				state.promoteCheckpoint(phase)
				state.finishCanceled(phase)
				state.cancelRemaining()
				state.finalize(true)
				return
			}
		}

		switch name {
		case RecoveryDrillPhaseSnapshotVerify:
			phase = b.drillSnapshotVerify(ctx, state, rc, opts)
		case RecoveryDrillPhasePeerRebuild:
			phase = b.drillPeerRebuild(ctx, state, rc, opts)
		case RecoveryDrillPhaseNodeRestart:
			phase = b.drillNodeRestart(ctx, state, rc, opts)
		}

		if ctx.Err() != nil {
			// The phase may have been interrupted mid-flight; make sure its
			// status reflects the cancellation before skipping the rest.
			if phase != nil && phase.Status == drillPhaseStatusRunning {
				state.addFinding(phase, "drill_canceled",
					"the recovery drill was canceled during this phase; it can be resumed from the reported checkpoint",
					drillSeverityBlocker, true)
				state.finishCanceled(phase)
			}
			state.cancelRemaining()
			state.finalize(true)
			return
		}

		state.finish(phase)
	}

	state.mu.Lock()
	state.MutatesMembership = rc.mutatesMembership()
	state.mu.Unlock()
	state.finalize(false)
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// defaultRecoveryDrillProbe performs a best-effort TCP dial to a raft peer
// address. A failure is not fatal: the caller retries and classifies the peer
// according to the aggregate outcome.
func defaultRecoveryDrillProbe(ctx context.Context, address string) error {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}

// drillSnapshotVerify verifies, read-only, that local recovery state is
// present and readable: the raft stores contain state, a snapshot can be
// listed, opened and fully read (checksummed), and the snapshot metadata
// carries a raft configuration and sane indexes.
func (b *RaftBackend) drillSnapshotVerify(ctx context.Context, state *RecoveryDrillState, rc *drillRunCtx, opts RecoveryDrillOpts) *RecoveryDrillPhaseResult {
	phase := state.begin(RecoveryDrillPhaseSnapshotVerify)

	b.l.RLock()
	hasState, stateErr := raft.HasExistingState(b.logStore, b.stableStore, b.snapStore)
	online := b.raft != nil
	b.l.RUnlock()
	rc.online = online

	state.setDetail(phase, "raft_online", online)

	if stateErr != nil {
		state.addFinding(phase, "state_check_failed",
			fmt.Sprintf("failed to inspect local raft state: %v", stateErr),
			drillSeverityBlocker, false)
	}
	if !hasState {
		state.addFinding(phase, "no_existing_state",
			"no raft log, stable state or snapshot found on this node; there is nothing to recover from",
			drillSeverityBlocker, false)
	}

	cp := RecoveryDrillCheckpoint{Resumable: true, Note: "re-run the drill after preparing recovery state"}
	if online {
		cp.AppliedIndex = b.AppliedIndex()
		cp.LastIndex = b.CommittedIndex()
	} else if b.fsm != nil {
		if idx, _ := b.fsm.LatestState(); idx != nil {
			cp.AppliedIndex = idx.Index
		}
	}

	metas, err := b.snapStore.List()
	if err != nil {
		state.addFinding(phase, "snapshot_list_failed",
			fmt.Sprintf("failed to list local snapshots: %v", err),
			drillSeverityBlocker, true)
		state.setCheckpoint(phase, cp)
		return phase
	}
	state.setDetail(phase, "snapshot_count", len(metas))

	if len(metas) == 0 {
		state.addFinding(phase, "snapshot_unavailable",
			"no local snapshot is available; a real recovery would have to replay the raft log from index 1",
			drillSeverityBlocker, false)
		state.setCheckpoint(phase, cp)
		return phase
	}

	// Snapshots are normally returned newest-first, but do not rely on the
	// underlying store ordering.
	latest := metas[0]
	for _, meta := range metas[1:] {
		if meta.Index > latest.Index {
			latest = meta
		}
	}

	metaReader, readCloser, err := b.snapStore.Open(latest.ID)
	if err != nil {
		state.addFinding(phase, "snapshot_open_failed",
			fmt.Sprintf("snapshot %q could not be opened: %v", latest.ID, err),
			drillSeverityBlocker, true)
		state.setCheckpoint(phase, cp)
		return phase
	}

	hasher := sha256.New()
	bytesRead, copyErr := io.Copy(hasher, readCloser)
	closeErr := readCloser.Close()
	switch {
	case copyErr != nil:
		state.addFinding(phase, "snapshot_unreadable",
			fmt.Sprintf("snapshot %q could not be fully read: %v", latest.ID, copyErr),
			drillSeverityBlocker, true)
		state.setCheckpoint(phase, cp)
		return phase
	case closeErr != nil:
		state.addFinding(phase, "snapshot_unreadable",
			fmt.Sprintf("snapshot %q failed to close cleanly: %v", latest.ID, closeErr),
			drillSeverityBlocker, true)
		state.setCheckpoint(phase, cp)
		return phase
	}

	if metaReader.Index == 0 {
		state.addFinding(phase, "snapshot_metadata_invalid",
			"snapshot metadata reports index 0",
			drillSeverityBlocker, false)
	}
	// A zero-length payload is legitimate: the bolt snapshot store streams
	// only storage data, so a node that has applied configuration entries but
	// no user data produces an empty payload. Reachability of EOF without an
	// error is what validates the snapshot stream.
	if metaReader.Size > 0 && bytesRead != metaReader.Size {
		state.addFinding(phase, "snapshot_size_mismatch",
			fmt.Sprintf("snapshot metadata advertises %d bytes but %d bytes were readable",
				metaReader.Size, bytesRead),
			drillSeverityBlocker, true)
	}
	if metaReader.Index > 0 && len(metaReader.Configuration.Servers) == 0 {
		state.addFinding(phase, "snapshot_config_missing",
			"the latest snapshot does not embed a raft server configuration; raft cannot recover from it",
			drillSeverityBlocker, false)
	}

	var fsmIndex, fsmTerm uint64
	if b.fsm != nil {
		if idx, _ := b.fsm.LatestState(); idx != nil {
			fsmIndex, fsmTerm = idx.Index, idx.Term
		}
	}
	if fsmIndex > 0 && fsmIndex < metaReader.Index {
		state.addFinding(phase, "snapshot_index_ahead_of_fsm",
			fmt.Sprintf("snapshot index %d is ahead of the FSM applied index %d", metaReader.Index, fsmIndex),
			drillSeverityWarning, true)
	}
	if metaReader.Term > 0 && fsmTerm > 0 && metaReader.Term != fsmTerm {
		state.setDetail(phase, "snapshot_term_mismatch", map[string]interface{}{
			"snapshot_term": metaReader.Term,
			"fsm_term":      fsmTerm,
		})
	}

	state.setDetails(phase, map[string]interface{}{
		"snapshot_count":          len(metas),
		"snapshot_id":             metaReader.ID,
		"snapshot_index":          metaReader.Index,
		"snapshot_term":           metaReader.Term,
		"snapshot_size":           metaReader.Size,
		"snapshot_bytes_read":     bytesRead,
		"snapshot_config_servers": len(metaReader.Configuration.Servers),
		"snapshot_config_index":   metaReader.ConfigurationIndex,
		"snapshot_sha256":         hex.EncodeToString(hasher.Sum(nil)),
		"fsm_applied_index":       fsmIndex,
		"raft_online":             online,
		"read_only":               true,
	})

	cp.SnapshotID = metaReader.ID
	cp.SnapshotIndex = metaReader.Index
	cp.ConfigIndex = metaReader.ConfigurationIndex
	if fsmIndex > cp.AppliedIndex {
		cp.AppliedIndex = fsmIndex
	}
	state.setCheckpoint(phase, cp)
	return phase
}

// drillPeerRebuild reconstructs, read-only, the peer set a recovery would use,
// validates it (duplicate ids/addresses, voter counts, local membership),
// diffs it against the current configuration (including duplicate join
// scenarios) and probes every address with retries so transient network
// jitter is tolerated.
func (b *RaftBackend) drillPeerRebuild(ctx context.Context, state *RecoveryDrillState, rc *drillRunCtx, opts RecoveryDrillOpts) *RecoveryDrillPhaseResult {
	phase := state.begin(RecoveryDrillPhasePeerRebuild)

	current, configIndex := b.drillCurrentConfiguration(phase, state, rc)
	rc.current = current

	intended, supplied := b.drillIntendedConfiguration(opts, current)
	rc.intended = intended
	state.setDetail(phase, "peer_set_source", b.drillPeerSetSource(supplied))
	state.setDetail(phase, "config_index", configIndex)

	currentByID := make(map[string]raft.Server, len(current))
	addressToID := make(map[string]string, len(current))
	for _, srv := range current {
		currentByID[string(srv.ID)] = srv
		addressToID[string(srv.Address)] = string(srv.ID)
	}

	cp := RecoveryDrillCheckpoint{
		Resumable:    true,
		ConfigIndex:  configIndex,
		AppliedIndex: b.drillAppliedIndex(),
		Note:         "re-run the drill to re-check peer reachability and membership",
	}

	if len(intended) == 0 {
		state.addFinding(phase, "no_peers",
			"the reconstructed peer list is empty; raft cannot form a cluster without peers",
			drillSeverityBlocker, false)
	}

	// Validate the intended peer set itself.
	seenIDs := make(map[string]int)
	seenAddresses := make(map[string]int)
	for i, srv := range intended {
		position := i + 1
		if srv.ID == "" {
			state.addFinding(phase, "peer_missing_id",
				fmt.Sprintf("intended peer at position %d has no id", position),
				drillSeverityBlocker, false)
			continue
		}
		if srv.Address == "" {
			state.addFinding(phase, "peer_missing_address",
				fmt.Sprintf("intended peer %q has no address", srv.ID),
				drillSeverityBlocker, false)
		}
		if !nonVotersAllowed && srv.Suffrage == raft.Nonvoter {
			state.addFinding(phase, "non_voter_not_supported",
				fmt.Sprintf("intended peer %q is configured as non-voter, which is only supported in Vault Enterprise", srv.ID),
				drillSeverityBlocker, false)
		}
		if prev, ok := seenIDs[string(srv.ID)]; ok {
			state.addFinding(phase, "duplicate_peer_id",
				fmt.Sprintf("intended peer id %q is listed more than once (positions %d and %d)", srv.ID, prev, position),
				drillSeverityBlocker, false)
		}
		seenIDs[string(srv.ID)] = position
		if srv.Address != "" {
			if prev, ok := seenAddresses[string(srv.Address)]; ok {
				state.addFinding(phase, "duplicate_peer_address",
					fmt.Sprintf("intended peer address %q is listed more than once (positions %d and %d)", srv.Address, prev, position),
					drillSeverityBlocker, false)
			}
			seenAddresses[string(srv.Address)] = position
		}
	}

	// Diff the intended set against the live configuration. This is where
	// duplicate joins are detected: a join for an already-member node is
	// idempotent only when the address also matches.
	unchanged, wouldJoin, wouldRemove := 0, 0, 0
	for _, srv := range intended {
		if srv.ID == "" {
			continue
		}
		cur, idKnown := currentByID[string(srv.ID)]
		switch {
		case idKnown && cur.Address == srv.Address && cur.Suffrage == srv.Suffrage:
			unchanged++
			if supplied {
				state.addFinding(phase, "duplicate_join_idempotent",
					fmt.Sprintf("node %q is already a member at %q; a repeated join would be a no-op", srv.ID, srv.Address),
					drillSeverityWarning, false)
			}
		case idKnown && cur.Address != srv.Address:
			rc.markMembershipMutation()
			state.addFinding(phase, "duplicate_join_address_conflict",
				fmt.Sprintf("node %q is already a member at %q; joining again with address %q would force an address change during real recovery",
					srv.ID, cur.Address, srv.Address),
				drillSeverityBlocker, false)
		case idKnown:
			rc.markMembershipMutation()
			state.addFinding(phase, "peer_suffrage_change",
				fmt.Sprintf("node %q would change suffrage on recovery", srv.ID),
				drillSeverityWarning, false)
		default:
			if ownerID, addrInUse := addressToID[string(srv.Address)]; addrInUse && ownerID != string(srv.ID) {
				state.addFinding(phase, "peer_address_in_use",
					fmt.Sprintf("intended peer %q uses address %q which is already assigned to member %q",
						srv.ID, srv.Address, ownerID),
					drillSeverityBlocker, false)
			}
			wouldJoin++
			rc.markMembershipMutation()
			if supplied {
				state.addFinding(phase, "would_join",
					fmt.Sprintf("node %q would join the cluster during a real recovery; the drill does not add it", srv.ID),
					drillSeverityWarning, false)
			}
		}
	}
	for _, srv := range current {
		if _, ok := seenIDs[string(srv.ID)]; !ok {
			wouldRemove++
			rc.markMembershipMutation()
			if supplied {
				state.addFinding(phase, "would_be_removed",
					fmt.Sprintf("current member %q is absent from the intended peer set; a real recovery would remove it; the drill does not", srv.ID),
					drillSeverityWarning, false)
			}
		}
	}

	// Ensure the local node remains a member of the reconstructed set.
	localID := b.NodeID()
	localInIntended := false
	for _, srv := range intended {
		if string(srv.ID) == localID {
			localInIntended = true
			break
		}
	}
	if len(intended) > 0 && !localInIntended {
		state.addFinding(phase, "local_node_missing",
			fmt.Sprintf("the local node %q is not part of the reconstructed peer set; it could not rejoin the cluster on recovery", localID),
			drillSeverityBlocker, false)
	}

	// Voter / quorum analysis.
	voters := 0
	for _, srv := range intended {
		if srv.Suffrage == raft.Voter {
			voters++
		}
	}
	if voters == 0 && len(intended) > 0 {
		state.addFinding(phase, "no_voters",
			"the reconstructed peer set contains no voting servers",
			drillSeverityBlocker, false)
	}
	if voters > 0 && voters%2 == 0 {
		state.addFinding(phase, "even_voters",
			fmt.Sprintf("the reconstructed peer set has %d voters; an odd number is recommended to avoid tied elections", voters),
			drillSeverityWarning, false)
	}
	majority := voters/2 + 1
	state.setDetail(phase, "voters", voters)
	state.setDetail(phase, "majority_required", majority)
	state.setDetail(phase, "failure_tolerance", drillFailureTolerance(voters))

	// Probe every distinct address, with retries so network jitter does not
	// produce a false blocker.
	reachableVoters := 0
	for _, srv := range intended {
		if srv.Address == "" {
			continue
		}
		probe := rc.probes[string(srv.Address)]
		if probe == nil {
			probe = b.drillProbePeer(ctx, opts, srv)
			rc.probes[string(srv.Address)] = probe
			switch probe.Status {
			case "unreachable":
				state.addFinding(phase, "peer_unreachable",
					fmt.Sprintf("peer %q at %q could not be reached after %d attempt(s): %v",
						srv.ID, srv.Address, probe.Attempts, probe.errorOrNone()),
					drillSeverityBlocker, true)
			case "flaky":
				state.addFinding(phase, "network_jitter",
					fmt.Sprintf("peer %q at %q was reachable only after %d failed attempt(s); network is jittery but recovery can proceed",
						srv.ID, srv.Address, probe.Failures),
					drillSeverityWarning, true)
			}
		}
		if srv.Suffrage == raft.Voter && (probe.Status == "reachable" || probe.Status == "flaky") {
			reachableVoters++
		}
	}

	probeDetails := make([]interface{}, 0, len(rc.probes))
	for _, probe := range rc.probes {
		probeDetails = append(probeDetails, probe)
	}
	sort.Slice(probeDetails, func(i, j int) bool {
		return probeDetails[i].(*RecoveryDrillProbe).Address < probeDetails[j].(*RecoveryDrillProbe).Address
	})

	state.setDetail(phase, "current_peers", drillServerDetails(current))
	state.setDetail(phase, "rebuilt_peers", drillServerDetails(intended))
	state.setDetail(phase, "probes", probeDetails)
	state.setDetail(phase, "reachable_voters", reachableVoters)
	state.setDetail(phase, "unchanged_members", unchanged)
	state.setDetail(phase, "would_join_members", wouldJoin)
	state.setDetail(phase, "would_remove_members", wouldRemove)
	state.setDetail(phase, "read_only", true)

	state.setCheckpoint(phase, cp)
	return phase
}

// drillNodeRestart simulates, read-only, the checks a node performs when it
// restarts and rejoins: local identity, readable state directories, the
// peers.json recovery trigger, the removed marker, membership and quorum. It
// never shuts raft down and never restarts anything.
func (b *RaftBackend) drillNodeRestart(ctx context.Context, state *RecoveryDrillState, rc *drillRunCtx, opts RecoveryDrillOpts) *RecoveryDrillPhaseResult {
	phase := state.begin(RecoveryDrillPhaseNodeRestart)

	steps := make(map[string]interface{})
	cp := RecoveryDrillCheckpoint{
		Resumable:    true,
		AppliedIndex: b.drillAppliedIndex(),
		Note:         "re-run the drill after restarting the node to confirm the simulated plan holds",
	}

	// Local identity.
	localID := b.NodeID()
	steps["local_id_configured"] = localID != ""
	if localID == "" {
		state.addFinding(phase, "no_local_node_id",
			"no local node id is configured; the node could not start raft",
			drillSeverityBlocker, false)
	}
	state.setDetail(phase, "local_node_id", localID)

	// Local state directories must exist and be readable.
	raftDir := filepath.Join(b.dataDir, raftState)
	for label, path := range map[string]string{
		"data_dir":       b.dataDir,
		"raft_state_dir": raftDir,
	} {
		info, err := os.Stat(path)
		ok := err == nil && info.IsDir()
		steps[label+"_accessible"] = ok
		if !ok {
			state.addFinding(phase, "restart_path_inaccessible",
				fmt.Sprintf("required path %q is not an accessible directory: %v", path, err),
				drillSeverityBlocker, false)
		}
	}

	// Existing state determines whether a restart recovers or bootstraps.
	// All values that require the backend lock are gathered in one critical
	// section so the lock is not re-entered via AppliedIndex/CommittedIndex.
	b.l.RLock()
	hasState, stateErr := raft.HasExistingState(b.logStore, b.stableStore, b.snapStore)
	role := ""
	var appliedIndex, lastIndex uint64
	if b.raft != nil {
		role = b.raft.State().String()
		lastIndex = b.raft.LastIndex()
	}
	bootstrapPending := b.bootstrapConfig != nil
	removed := b.removed != nil && b.removed.Load()
	b.l.RUnlock()
	if b.fsm != nil {
		if idx, _ := b.fsm.LatestState(); idx != nil {
			appliedIndex = idx.Index
		}
	}
	steps["existing_state"] = hasState
	if stateErr != nil {
		state.addFinding(phase, "state_check_failed",
			fmt.Sprintf("failed to inspect local raft state: %v", stateErr),
			drillSeverityBlocker, false)
	}
	if !hasState {
		state.addFinding(phase, "restart_without_state",
			"the node has no raft state; a real restart would come up unbootstrapped instead of recovering",
			drillSeverityBlocker, false)
	}

	// A pending peers.json means a real restart would invoke raft.RecoverCluster:
	// the explicit recovery path the drill deliberately does not execute.
	peersFilePath := filepath.Join(raftDir, peersFileName)
	if _, err := os.Stat(peersFilePath); err == nil {
		steps["peers_json_pending"] = true
		state.addFinding(phase, "peers_json_pending",
			"a peers.json recovery file is present; a real restart would consume it and replace the raft configuration. The drill did not consume or modify it",
			drillSeverityWarning, false)
	} else {
		steps["peers_json_pending"] = false
	}

	steps["bootstrap_pending"] = bootstrapPending
	if bootstrapPending {
		state.addFinding(phase, "bootstrap_pending",
			"a bootstrap configuration is pending; a real restart would bootstrap a new cluster rather than recover",
			drillSeverityWarning, false)
	}
	if removed {
		state.addFinding(phase, "node_marked_removed",
			"this node is marked as removed from the cluster; local raft data must be cleaned up before it can rejoin",
			drillSeverityBlocker, false)
	}

	// Membership: the local node must be present in the reconstructed set.
	localMember := false
	localVoter := false
	for _, srv := range rc.intended {
		if string(srv.ID) == localID {
			localMember = true
			localVoter = srv.Suffrage == raft.Voter
		}
	}
	steps["local_node_in_rebuilt_set"] = localMember
	state.setDetail(phase, "local_node_voter", localVoter)
	if len(rc.intended) > 0 && !localMember {
		state.addFinding(phase, "restart_local_node_not_member",
			fmt.Sprintf("the local node %q is absent from the reconstructed peer set; restarting it would not rejoin quorum", localID),
			drillSeverityBlocker, false)
	}

	// Quorum: a majority of intended voters must be reachable.
	voters, reachableVoters := 0, 0
	for _, srv := range rc.intended {
		if srv.Suffrage != raft.Voter {
			continue
		}
		voters++
		if probe := rc.probes[string(srv.Address)]; probe != nil &&
			(probe.Status == "reachable" || probe.Status == "flaky") {
			reachableVoters++
		}
	}
	majority := voters/2 + 1
	steps["voters"] = voters
	steps["reachable_voters"] = reachableVoters
	steps["majority_required"] = majority
	if voters > 0 && reachableVoters < majority {
		state.addFinding(phase, "restart_quorum_unavailable",
			fmt.Sprintf("only %d of %d voters are reachable; a majority of %d is required before the node can catch up on restart",
				reachableVoters, voters, majority),
			drillSeverityBlocker, true)
	}

	// Current role information is purely observational.
	if rc.online {
		state.setDetail(phase, "current_raft_state", role)
		state.setDetail(phase, "applied_index", appliedIndex)
		state.setDetail(phase, "last_index", lastIndex)
	} else {
		state.setDetail(phase, "current_raft_state", "shutdown")
		if b.fsm != nil {
			if idx, _ := b.fsm.LatestState(); idx != nil {
				state.setDetail(phase, "applied_index", idx.Index)
				cp.AppliedIndex = idx.Index
			}
		}
	}

	state.setDetail(phase, "simulated", true)
	state.setDetail(phase, "restart_performed", false)
	state.setDetail(phase, "steps", steps)
	state.setDetail(phase, "read_only", true)

	if appliedIndex > 0 {
		cp.LastIndex = lastIndex
	}
	state.setCheckpoint(phase, cp)
	return phase
}

// drillCurrentConfiguration reads the live raft configuration when raft is
// running and the FSM persisted configuration when it is not.
func (b *RaftBackend) drillCurrentConfiguration(phase *RecoveryDrillPhaseResult, state *RecoveryDrillState, rc *drillRunCtx) ([]raft.Server, uint64) {
	if rc.online {
		resp, err := b.GetConfiguration(context.Background())
		if err != nil {
			state.addFinding(phase, "configuration_read_failed",
				fmt.Sprintf("failed to read live raft configuration: %v", err),
				drillSeverityBlocker, true)
			return nil, 0
		}
		return drillResponseToServers(resp.Servers), resp.Index
	}

	resp, err := b.GetConfigurationOffline()
	if err != nil {
		state.addFinding(phase, "configuration_read_failed",
			fmt.Sprintf("failed to read offline raft configuration: %v", err),
			drillSeverityBlocker, true)
		return nil, 0
	}
	if resp == nil {
		return nil, 0
	}
	return drillResponseToServers(resp.Servers), resp.Index
}

// drillIntendedConfiguration converts the requested peers into raft servers,
// or derives the set from the current configuration when none is supplied.
// The returned slice is always a copy; callers never mutate the shared raft
// configuration.
func (b *RaftBackend) drillIntendedConfiguration(opts RecoveryDrillOpts, current []raft.Server) ([]raft.Server, bool) {
	if len(opts.IntendedPeers) > 0 {
		servers := make([]raft.Server, len(opts.IntendedPeers))
		for i, p := range opts.IntendedPeers {
			servers[i] = raft.Server{
				ID:       raft.ServerID(p.ID),
				Address:  raft.ServerAddress(p.Address),
				Suffrage: raft.ServerSuffrage(p.Suffrage),
			}
		}
		return servers, true
	}

	// No supplied plan: reconstruct the peer set from the last known
	// configuration. This is a copy; the drill never rewrites configuration.
	servers := make([]raft.Server, len(current))
	copy(servers, current)
	return servers, false
}

func (b *RaftBackend) drillPeerSetSource(supplied bool) string {
	if supplied {
		return "requested"
	}
	return "current_configuration"
}

func (b *RaftBackend) drillAppliedIndex() uint64 {
	if b.fsm == nil {
		return 0
	}
	if idx, _ := b.fsm.LatestState(); idx != nil {
		return idx.Index
	}
	return 0
}

// drillProbePeer probes a single peer address with bounded retries and
// classifies reachability as reachable, flaky (reachable after failures) or
// unreachable.
func (b *RaftBackend) drillProbePeer(ctx context.Context, opts RecoveryDrillOpts, srv raft.Server) *RecoveryDrillProbe {
	probe := &RecoveryDrillProbe{
		Address: string(srv.Address),
		NodeIDs: []string{string(srv.ID)},
	}

	var lastErr error
	for attempt := 1; attempt <= opts.ProbeAttempts; attempt++ {
		if ctx.Err() != nil {
			probe.LastError = ctx.Err().Error()
			if probe.Attempts == 0 || probe.Status == "" {
				probe.Status = "unreachable"
				probe.Failures = probe.Attempts
			}
			return probe
		}

		probeCtx, cancel := context.WithTimeout(ctx, opts.ProbeTimeout)
		err := opts.Probe(probeCtx, string(srv.Address))
		cancel()

		probe.Attempts = attempt
		if err == nil {
			if attempt == 1 {
				probe.Status = "reachable"
			} else {
				probe.Status = "flaky"
			}
			probe.Failures = attempt - 1
			return probe
		}
		lastErr = err
		if attempt < opts.ProbeAttempts && opts.ProbeBackoff > 0 {
			if sleepErr := sleepWithContext(ctx, opts.ProbeBackoff); sleepErr != nil {
				probe.LastError = sleepErr.Error()
				probe.Status = "unreachable"
				probe.Failures = attempt
				return probe
			}
		}
	}

	probe.Status = "unreachable"
	probe.Failures = opts.ProbeAttempts
	if lastErr != nil {
		probe.LastError = lastErr.Error()
	}
	return probe
}

func drillResponseToServers(entries []*RaftServer) []raft.Server {
	servers := make([]raft.Server, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		srv := raft.Server{
			ID:      raft.ServerID(entry.NodeID),
			Address: raft.ServerAddress(entry.Address),
		}
		if entry.Voter {
			srv.Suffrage = raft.Voter
		} else {
			srv.Suffrage = raft.Nonvoter
		}
		servers = append(servers, srv)
	}
	return servers
}

func drillServerDetails(servers []raft.Server) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(servers))
	for _, srv := range servers {
		out = append(out, map[string]interface{}{
			"id":       string(srv.ID),
			"address":  string(srv.Address),
			"voter":    srv.Suffrage == raft.Voter,
			"suffrage": int(srv.Suffrage),
		})
	}
	return out
}

func drillFailureTolerance(voters int) int {
	if voters < 1 {
		return 0
	}
	return (voters - 1) / 2
}

func (r *drillRunCtx) markMembershipMutation() {
	r.mutates = true
}

func (r *drillRunCtx) mutatesMembership() bool {
	return r.mutates
}

// finishCanceled marks a phase interrupted mid-execution as canceled.
func (s *RecoveryDrillState) finishCanceled(p *RecoveryDrillPhaseResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.Status = drillPhaseStatusCanceled
	p.EndedAt = time.Now().UTC()
	if s.CurrentPhase == p.Name {
		s.CurrentPhase = ""
	}
}

func (p *RecoveryDrillProbe) errorOrNone() error {
	if p.LastError == "" {
		return nil
	}
	return errors.New(p.LastError)
}
