// Copyright IBM Corp. 2025
// SPDX-License-Identifier: BUSL-1.1

package raft

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/physical"
	"github.com/stretchr/testify/require"
)

// getDrillRaft creates a test raft backend, skipping the raft-wal variant on
// Windows: raft-wal syncs its metadata directory and non-elevated Windows
// sandboxes deny that operation. The drill itself is storage-backend
// agnostic, so the boltdb variant provides the same coverage there.
func getDrillRaft(t *testing.T, bootstrap, noStoreState bool, conf map[string]string) (*RaftBackend, string) {
	t.Helper()
	if runtime.GOOS == "windows" && conf["raft_wal"] == "true" {
		t.Skip("skipping raft-wal drill subtest on Windows: metadata directory sync is denied in this sandbox")
	}
	return GetRaftWithConfig(t, bootstrap, noStoreState, conf)
}

// okDrillProbe is a probe function that considers every address reachable.
func okDrillProbe(_ context.Context, _ string) error { return nil }

func waitDrillDone(t *testing.T, b *RaftBackend, drillID string) *RecoveryDrillState {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		state, err := b.RecoveryDrillStatus(drillID)
		require.NoError(t, err)
		if state.Status != drillStatusRunning {
			return state
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("recovery drill %q did not finish in time", drillID)
	return nil
}

func waitFSMApplied(t *testing.T, b *RaftBackend, index uint64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if idx, _ := b.fsm.LatestState(); idx != nil && idx.Index >= index {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for FSM applied index >= %d", index)
}

func waitFSMConfigServers(t *testing.T, b *RaftBackend, count int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, config := b.fsm.LatestState()
		if config != nil && len(config.Servers) == count {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d servers in the FSM config", count)
}

func drillPhase(state *RecoveryDrillState, name string) *RecoveryDrillPhaseResult {
	for _, p := range state.Phases {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func drillFinding(state *RecoveryDrillState, code string) (*RecoveryDrillBlocker, bool) {
	for _, f := range state.Blockers {
		if f.Code == code {
			return f, true
		}
	}
	return nil, false
}

func assertNoPeersJSON(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		_, err := os.Stat(filepath.Join(dir, raftState, peersFileName))
		require.True(t, os.IsNotExist(err), "drill must not create a peers.json file, found one in %s", dir)
	}
}

func samePeers(t *testing.T, want, got []Peer) {
	t.Helper()
	require.Len(t, got, len(want))
	wantByID := make(map[string]Peer, len(want))
	for _, p := range want {
		wantByID[p.ID] = p
	}
	for _, p := range got {
		expected, ok := wantByID[p.ID]
		require.True(t, ok, "unexpected peer %q after drill", p.ID)
		require.Equal(t, expected.Address, p.Address, "peer %q address changed by the drill", p.ID)
		require.Equal(t, expected.Suffrage, p.Suffrage, "peer %q suffrage changed by the drill", p.ID)
	}
}

// cleanupDrillBackends tears down and closes the backends so that their on-disk
// stores do not outlive the test (open handles prevent temp dir cleanup on
// Windows).
func cleanupDrillBackends(t *testing.T, backends ...*RaftBackend) {
	t.Helper()
	t.Cleanup(func() {
		for _, b := range backends {
			if b == nil {
				continue
			}
			_ = b.TeardownCluster(nil)
			_ = b.Close()
		}
	})
}

func newDrillThreeNodeCluster(t *testing.T, useWAL string) (*RaftBackend, *RaftBackend, *RaftBackend, string, string, string) {
	t.Helper()
	conf := map[string]string{
		"trailing_logs": "100",
		"raft_wal":      useWAL,
	}

	leader, dir1 := getDrillRaft(t, true, true, conf)
	follower1, dir2 := getDrillRaft(t, false, true, conf)
	follower2, dir3 := getDrillRaft(t, false, true, conf)
	cleanupDrillBackends(t, leader, follower1, follower2)

	addPeer(t, leader, follower1)
	addPeer(t, leader, follower2)
	waitFSMConfigServers(t, leader, 3)

	return leader, follower1, follower2, dir1, dir2, dir3
}

// TestRecoveryDrill_ThreeNode_Pass runs a full drill against a healthy
// three-node cluster and asserts that every phase passes, checkpoints are
// populated and nothing is mutated.
func TestRecoveryDrill_ThreeNode_Pass(t *testing.T) {
	testBothRaftBackends(t, func(t *testing.T, useWAL string) {
		leader, _, _, dir1, dir2, dir3 := newDrillThreeNodeCluster(t, useWAL)
		physical.ExerciseBackend(t, leader)

		before, err := leader.Peers(context.Background())
		require.NoError(t, err)

		started, err := leader.StartRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe:        okDrillProbe,
			ProbeBackoff: time.Millisecond,
		})
		require.NoError(t, err)
		require.NotEmpty(t, started.ID)

		state := waitDrillDone(t, leader, started.ID)
		require.Equalf(t, drillStatusPassed, state.Status, "blockers: %s", drillBlockerDump(state))
		require.True(t, state.ReadyForRecovery)
		require.True(t, state.ConfirmationRequired, "actual recovery must still require explicit confirmation")
		require.False(t, state.MutatesMembership, "the drill must not simulate any membership change")
		require.Empty(t, state.Blockers)

		for _, p := range state.Phases {
			require.Equal(t, drillPhaseStatusPassed, p.Status, "phase %s: %+v", p.Name, p.Blockers)
			require.True(t, p.Checkpoint.Resumable, "phase %s must report a resumable checkpoint", p.Name)
		}

		snapshot := drillPhase(state, RecoveryDrillPhaseSnapshotVerify)
		require.NotNil(t, snapshot)
		require.Greater(t, snapshot.Checkpoint.SnapshotIndex, uint64(0))
		require.NotEmpty(t, snapshot.Checkpoint.SnapshotID)
		require.Equal(t, true, snapshot.Details["read_only"])

		peerRebuild := drillPhase(state, RecoveryDrillPhasePeerRebuild)
		require.Len(t, peerRebuild.Details["rebuilt_peers"], 3)
		require.Equal(t, "current_configuration", peerRebuild.Details["peer_set_source"])
		probes := peerRebuild.Details["probes"].([]interface{})
		require.Len(t, probes, 3)
		for _, raw := range probes {
			probe := raw.(map[string]interface{})
			require.Equal(t, "reachable", probe["status"], "probe %v was not reachable", probe)
		}
		require.EqualValues(t, 3, peerRebuild.Details["reachable_voters"])
		require.EqualValues(t, 2, peerRebuild.Details["majority_required"])
		require.EqualValues(t, 1, peerRebuild.Details["failure_tolerance"])

		restart := drillPhase(state, RecoveryDrillPhaseNodeRestart)
		require.Equal(t, true, restart.Details["simulated"])
		require.Equal(t, false, restart.Details["restart_performed"], "the drill must never restart raft")

		after, err := leader.Peers(context.Background())
		require.NoError(t, err)
		samePeers(t, before, after)
		assertNoPeersJSON(t, dir1, dir2, dir3)
	})
}

// TestRecoveryDrill_DuplicateJoin covers the duplicate join scenarios: an
// identical re-join is an idempotent no-op (warning), while joining an
// existing node id with a different address, or listing the same node twice,
// blocks the drill. Membership must remain unchanged in every case.
func TestRecoveryDrill_DuplicateJoin(t *testing.T) {
	testBothRaftBackends(t, func(t *testing.T, useWAL string) {
		leader, _, _, dir1, dir2, dir3 := newDrillThreeNodeCluster(t, useWAL)

		before, err := leader.Peers(context.Background())
		require.NoError(t, err)

		// Case 1: the supplied plan is identical to the current membership.
		identical := append([]Peer(nil), before...)
		state := leader.RunRecoveryDrill(context.Background(), RecoveryDrillOpts{
			IntendedPeers: identical,
			Probe:         okDrillProbe,
			ProbeBackoff:  time.Millisecond,
		})
		require.Equal(t, drillStatusPassed, state.Status)
		require.False(t, state.MutatesMembership)
		require.Equal(t, 3, countFindings(state, "duplicate_join_idempotent"))

		after, err := leader.Peers(context.Background())
		require.NoError(t, err)
		samePeers(t, before, after)

		// Case 2: same node id joining with a different address and a
		// duplicated entry in the supplied plan.
		conflicting := append([]Peer(nil), before...)
		conflicting[0].Address = "conflicting-address"
		conflicting = append(conflicting, before[0])
		state = leader.RunRecoveryDrill(context.Background(), RecoveryDrillOpts{
			IntendedPeers: conflicting,
			Probe:         okDrillProbe,
			ProbeBackoff:  time.Millisecond,
		})
		require.Equal(t, drillStatusBlocked, state.Status)
		require.False(t, state.ReadyForRecovery)
		require.True(t, state.MutatesMembership, "the simulated plan changes membership, even though the drill does not")
		finding, ok := drillFinding(state, "duplicate_join_address_conflict")
		require.True(t, ok)
		require.Equal(t, drillSeverityBlocker, finding.Severity)
		_, ok = drillFinding(state, "duplicate_peer_id")
		require.True(t, ok)

		after, err = leader.Peers(context.Background())
		require.NoError(t, err)
		samePeers(t, before, after)
		assertNoPeersJSON(t, dir1, dir2, dir3)
	})
}

// TestRecoveryDrill_NetworkJitter verifies that transient probe failures are
// retried and classified as flaky, while persistent partitions produce
// retriable blockers and a missing-quorum finding for the restart phase.
func TestRecoveryDrill_NetworkJitter(t *testing.T) {
	testBothRaftBackends(t, func(t *testing.T, useWAL string) {
		leader, follower1, follower2, dir1, dir2, dir3 := newDrillThreeNodeCluster(t, useWAL)

		before, err := leader.Peers(context.Background())
		require.NoError(t, err)

		var mu sync.Mutex
		attempts := make(map[string]int)
		flakyProbe := func(_ context.Context, address string) error {
			mu.Lock()
			n := attempts[address]
			attempts[address] = n + 1
			mu.Unlock()

			switch address {
			case leader.NodeID():
				// Succeeds only from the third attempt: network jitter.
				if n < 2 {
					return fmt.Errorf("simulated transient failure to %s", address)
				}
				return nil
			default:
				// The other two peers stay partitioned.
				return fmt.Errorf("simulated partition of %s", address)
			}
		}

		state := leader.RunRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe:         flakyProbe,
			ProbeAttempts: 3,
			ProbeTimeout:  5 * time.Second,
			ProbeBackoff:  time.Millisecond,
		})
		require.Equal(t, drillStatusBlocked, state.Status)

		jitter, ok := drillFinding(state, "network_jitter")
		require.True(t, ok, "expected a network_jitter warning")
		require.Equal(t, drillSeverityWarning, jitter.Severity)
		require.True(t, jitter.Retriable)

		unreachable := countFindings(state, "peer_unreachable")
		require.Equal(t, 2, unreachable, "the two partitioned peers must be reported unreachable")
		for _, f := range state.Blockers {
			if f.Code == "peer_unreachable" {
				require.True(t, f.Retriable)
			}
		}

		_, ok = drillFinding(state, "restart_quorum_unavailable")
		require.True(t, ok, "quorum of reachable voters must not be available")

		peerRebuild := drillPhase(state, RecoveryDrillPhasePeerRebuild)
		probes := peerRebuild.Details["probes"].([]interface{})
		var sawFlaky, sawUnreachable bool
		for _, raw := range probes {
			probe := raw.(*RecoveryDrillProbe)
			switch probe.Address {
			case leader.NodeID():
				require.Equal(t, "flaky", probe.Status)
				require.Equal(t, 3, probe.Attempts)
				require.Equal(t, 2, probe.Failures)
				sawFlaky = true
			case follower1.NodeID(), follower2.NodeID():
				require.Equal(t, "unreachable", probe.Status)
				sawUnreachable = true
			}
		}
		require.True(t, sawFlaky && sawUnreachable)
		require.EqualValues(t, 1, peerRebuild.Details["reachable_voters"])

		// The drill itself did not change anything.
		after, err := leader.Peers(context.Background())
		require.NoError(t, err)
		samePeers(t, before, after)
		assertNoPeersJSON(t, dir1, dir2, dir3)
	})
}

// TestRecoveryDrill_Cancel verifies cancellation through both the managed
// API and a canceled context, that the drill stops at a resumable checkpoint
// and that a new drill can run afterwards.
func TestRecoveryDrill_Cancel(t *testing.T) {
	testBothRaftBackends(t, func(t *testing.T, useWAL string) {
		conf := map[string]string{
			"trailing_logs": "100",
			"raft_wal":      useWAL,
		}
		leader, dir := getDrillRaft(t, true, true, conf)
		cleanupDrillBackends(t, leader)
		// A data-free bootstrapped node applies its configuration at index 1;
		// that is enough for the bolt snapshot store to expose a snapshot.
		waitFSMApplied(t, leader, 1)

		started, err := leader.StartRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe: func(ctx context.Context, _ string) error {
				<-ctx.Done()
				return ctx.Err()
			},
			ProbeAttempts: 5,
			ProbeTimeout:  10 * time.Second,
			ProbeBackoff:  time.Millisecond,
			PhaseDelay:    300 * time.Millisecond,
		})
		require.NoError(t, err)

		canceled, err := leader.CancelRecoveryDrill(started.ID)
		require.NoError(t, err)
		require.Equal(t, drillStatusCanceled, canceled.Status)
		require.False(t, canceled.ReadyForRecovery)
		require.NotNil(t, canceled.Checkpoint)
		require.True(t, canceled.Checkpoint.Resumable)
		_, ok := drillFinding(canceled, "drill_canceled")
		require.True(t, ok)

		canceledCount, skippedCount := 0, 0
		for _, p := range canceled.Phases {
			switch p.Status {
			case drillPhaseStatusCanceled:
				canceledCount++
			case drillPhaseStatusSkipped:
				skippedCount++
			}
		}
		require.GreaterOrEqual(t, canceledCount+skippedCount, 1, "at least one phase must be canceled or skipped")
		require.Equal(t, 3, canceledCount+skippedCount, "all phases must be canceled or marked as skipped")
		require.Equal(t, 1, canceledCount, "exactly the interrupted phase must be canceled")

		// The slot is released: a fresh drill runs to completion.
		restarted, err := leader.StartRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe:        okDrillProbe,
			ProbeBackoff: time.Millisecond,
		})
		require.NoError(t, err)
		require.NotEqual(t, started.ID, restarted.ID)
		state := waitDrillDone(t, leader, restarted.ID)
		require.Equalf(t, drillStatusPassed, state.Status, "blockers: %s", drillBlockerDump(state))

		// Canceling a finished drill reports that none is active.
		_, err = leader.CancelRecoveryDrill(started.ID)
		require.ErrorIs(t, err, ErrRecoveryDrillNotActive)

		// A pre-canceled context aborts a synchronous drill before work.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		state = leader.RunRecoveryDrill(ctx, RecoveryDrillOpts{Probe: okDrillProbe})
		require.Equal(t, drillStatusCanceled, state.Status)
		require.NotEqual(t, drillPhaseStatusPassed, state.Phases[0].Status)

		assertNoPeersJSON(t, dir)
	})
}

// TestRecoveryDrill_OfflineAndNoState covers recovery preparedness when raft
// is shut down (configuration reconstructed from the FSM) and when a node
// has no raft state at all.
func TestRecoveryDrill_Offline(t *testing.T) {
	testBothRaftBackends(t, func(t *testing.T, useWAL string) {
		leader, _, _, dir1, _, _ := newDrillThreeNodeCluster(t, useWAL)
		physical.ExerciseBackend(t, leader)

		require.NoError(t, leader.TeardownCluster(nil))

		state := leader.RunRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe:        okDrillProbe,
			ProbeBackoff: time.Millisecond,
		})
		require.Equal(t, drillStatusPassed, state.Status, "offline drill should pass: %+v", state.Blockers)

		snapshot := drillPhase(state, RecoveryDrillPhaseSnapshotVerify)
		require.Equal(t, false, snapshot.Details["raft_online"])
		require.Greater(t, snapshot.Checkpoint.SnapshotIndex, uint64(0))

		peerRebuild := drillPhase(state, RecoveryDrillPhasePeerRebuild)
		require.Len(t, peerRebuild.Details["rebuilt_peers"], 3)
		require.Equal(t, "current_configuration", peerRebuild.Details["peer_set_source"])

		restart := drillPhase(state, RecoveryDrillPhaseNodeRestart)
		require.Equal(t, "shutdown", restart.Details["current_raft_state"])
		require.Equal(t, false, restart.Details["restart_performed"])
		assertNoPeersJSON(t, dir1)

		// A fresh, unbootstrapped backend has no state to recover from.
		fresh, freshDir := GetRaft(t, false, true)
		cleanupDrillBackends(t, fresh)
		state = fresh.RunRecoveryDrill(context.Background(), RecoveryDrillOpts{Probe: okDrillProbe})
		require.Equal(t, drillStatusBlocked, state.Status)
		_, ok := drillFinding(state, "no_existing_state")
		require.True(t, ok)
		_, ok = drillFinding(state, "no_peers")
		require.True(t, ok)
		assertNoPeersJSON(t, freshDir)
	})
}

// TestRecoveryDrill_DuplicateStart verifies that starting a drill while one
// is already running is idempotent and returns the existing drill.
func TestRecoveryDrill_DuplicateStart(t *testing.T) {
	testBothRaftBackends(t, func(t *testing.T, useWAL string) {
		conf := map[string]string{
			"trailing_logs": "100",
			"raft_wal":      useWAL,
		}
		leader, _ := getDrillRaft(t, true, true, conf)
		cleanupDrillBackends(t, leader)

		first, err := leader.StartRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe:        okDrillProbe,
			ProbeBackoff: time.Millisecond,
			PhaseDelay:   time.Second,
		})
		require.NoError(t, err)

		second, err := leader.StartRecoveryDrill(context.Background(), RecoveryDrillOpts{
			Probe:        okDrillProbe,
			PhaseDelay:   time.Second,
			ProbeTimeout: time.Hour,
		})
		require.NoError(t, err)
		require.True(t, second.Duplicate)
		require.Equal(t, first.ID, second.ID)

		canceled, err := leader.CancelRecoveryDrill("")
		require.NoError(t, err)
		require.Equal(t, first.ID, canceled.ID)
		require.Equal(t, drillStatusCanceled, canceled.Status)
	})
}

func drillBlockerDump(state *RecoveryDrillState) string {
	buf, err := json.Marshal(state.Blockers)
	if err != nil {
		return fmt.Sprintf("%v", state.Blockers)
	}
	return string(buf)
}

func countFindings(state *RecoveryDrillState, code string) int {
	count := 0
	for _, f := range state.Blockers {
		if f.Code == code {
			count++
		}
	}
	return count
}
