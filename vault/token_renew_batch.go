// Copyright IBM Corp. 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// renewBatchPrefix is the storage sub-view (under the token store view)
	// where idempotent renewal budget ledgers are persisted.
	renewBatchPrefix = "renew-batch/"

	// renewBatchMaxItems bounds the number of renewal items accepted in a
	// single batch request.
	renewBatchMaxItems = 100

	// renewBatchMaxKeyLength bounds the caller supplied idempotency key.
	renewBatchMaxKeyLength = 128

	// renewBatchRecordTTL is the lazy expiry for idempotency records.
	renewBatchRecordTTL = 24 * time.Hour

	renewBatchKindToken    = "token"
	renewBatchKindAccessor = "accessor"

	// Per-item result statuses returned to callers.
	renewBatchStatusSuccess      = "success"
	renewBatchStatusLimitReached = "limit_reached"
	renewBatchStatusRevoked      = "revoked"
	renewBatchStatusAuditFailed  = "audit_failed"
	renewBatchStatusError        = "error"

	// renewBatchStatusPending marks items that have not executed yet; it is
	// never returned to callers.
	renewBatchStatusPending = "pending"

	renewBatchAuditRequestPath = "auth/token/renew"
)

// renewBatchAuditPhase selects which audit event is emitted for a single
// renewal item.
type renewBatchAuditPhase int

const (
	renewBatchAuditPre renewBatchAuditPhase = iota
	renewBatchAuditPost
)

// renewBatchAuditorFunc audits a single item of a batch renewal. The default
// implementation routes through the core audit broker; tests may replace it
// to deterministically exercise audit failure and recovery.
type renewBatchAuditorFunc func(ctx context.Context, phase renewBatchAuditPhase, req *logical.Request, item renewBatchInputItem, auth *logical.Auth) error

// renewBatchInputItem is a validated element of a batch request.
type renewBatchInputItem struct {
	token     string
	accessor  string
	increment time.Duration
}

func (i renewBatchInputItem) kind() string {
	if i.accessor != "" {
		return renewBatchKindAccessor
	}
	return renewBatchKindToken
}

func (i renewBatchInputItem) identifier() string {
	if i.accessor != "" {
		return i.accessor
	}
	return i.token
}

// renewBatchInput is the validated batch request.
type renewBatchInput struct {
	idempotencyKey   string
	maxTotalDuration time.Duration
	items            []renewBatchInputItem
}

// renewBatchItemRecord is the persisted, per-item slice of an idempotent
// renewal ledger. Raw token values are never stored.
type renewBatchItemRecord struct {
	Kind      string        `json:"kind"`
	IdentHash string        `json:"ident_hash"`
	Increment time.Duration `json:"increment"`
	Status    string        `json:"status"`

	// FinalStatus/FinalReason hold the true terminal classification while an
	// item is parked as audit_failed after a post-renewal audit failure, so
	// audit recovery can replay the exact original result (including the
	// reason of a capped limit_reached renewal).
	FinalStatus string `json:"final_status,omitempty"`
	FinalReason string `json:"final_reason,omitempty"`

	Reason string `json:"reason,omitempty"`

	// GrantedTTL and ExpireTime are captured at the moment the renewal
	// succeeded so that replays return identical results regardless of
	// elapsed time or clock differences, and never trigger a second renewal.
	GrantedTTL time.Duration `json:"granted_ttl,omitempty"`
	ExpireTime time.Time     `json:"expire_time,omitempty"`

	Accessor  string `json:"accessor,omitempty"`
	Renewable bool   `json:"renewable"`
}

// renewBatchRecord is the persisted idempotent ledger for one batch request.
type renewBatchRecord struct {
	Key              string                  `json:"key"`
	CallerHash       string                  `json:"caller_hash"`
	Fingerprint      string                  `json:"fingerprint"`
	MaxTotalDuration time.Duration           `json:"max_total_duration"`
	CreatedTime      time.Time               `json:"created_time"`
	ExpireTime       time.Time               `json:"expire_time"`
	Items            []*renewBatchItemRecord `json:"items"`
}

func (r *renewBatchRecord) grantedTotal() time.Duration {
	var total time.Duration
	for _, item := range r.Items {
		total += item.GrantedTTL
	}
	return total
}

// tokenLeaseEntry loads the lease entry associated with a token entry,
// mirroring the lease ID computation in ExpirationManager.RenewToken. It
// returns nil, nil when no lease exists.
func (m *ExpirationManager) tokenLeaseEntry(ctx context.Context, te *logical.TokenEntry) (*leaseEntry, error) {
	tokenNS, err := NamespaceByID(ctx, te.NamespaceID, m.core)
	if err != nil {
		return nil, err
	}
	if tokenNS == nil {
		return nil, namespace.ErrNoNamespace
	}

	saltedID, err := m.tokenStore.SaltID(ctx, te.ID)
	if err != nil {
		return nil, err
	}

	leaseID := path.Join(te.Path, saltedID)
	if tokenNS.ID != namespace.RootNamespaceID {
		leaseID = fmt.Sprintf("%s.%s", leaseID, tokenNS.ID)
	}

	return m.loadEntry(ctx, leaseID)
}

// handleRenewBatch implements auth/token/renew-batch.
func (ts *TokenStore) handleRenewBatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	input, err := parseRenewBatchInput(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	view := ts.renewBatchStorage(ns)
	storageKey := renewBatchStorageKey(input.idempotencyKey)

	// Serialize concurrent requests carrying the same idempotency key. The
	// latecomer replays the ledger produced by the first request.
	keyLock := locksutil.LockForKey(ts.renewBatchLocks, storageKey)
	keyLock.Lock()
	defer keyLock.Unlock()

	now := ts.renewBatchNow()
	callerHash := renewBatchHash(req.ClientToken)
	fingerprint := renewBatchFingerprint(input)

	record, err := ts.loadRenewBatchRecord(ctx, view, storageKey, now)
	if err != nil {
		if errors.Is(err, errRenewBatchRecordCorrupt) {
			return logical.ErrorResponse("idempotency key %q has an unreadable stored record; use a new idempotency_key", input.idempotencyKey), logical.ErrInvalidRequest
		}
		return nil, err
	}

	replayed := true
	if record == nil {
		record = &renewBatchRecord{
			Key:              storageKey,
			CallerHash:       callerHash,
			Fingerprint:      fingerprint,
			MaxTotalDuration: input.maxTotalDuration,
			CreatedTime:      now,
			ExpireTime:       now.Add(renewBatchRecordTTL),
			Items:            make([]*renewBatchItemRecord, len(input.items)),
		}
		for i, item := range input.items {
			record.Items[i] = &renewBatchItemRecord{
				Kind:      item.kind(),
				IdentHash: renewBatchHash(item.kind() + ":" + item.identifier()),
				Increment: item.increment,
				Status:    renewBatchStatusPending,
			}
		}
		if err := ts.persistRenewBatchRecord(ctx, view, record); err != nil {
			return nil, err
		}
	} else {
		if record.CallerHash != callerHash {
			return logical.ErrorResponse("idempotency key %q is already in use by a different caller", input.idempotencyKey), logical.ErrInvalidRequest
		}
		if record.Fingerprint != fingerprint {
			return logical.ErrorResponse("idempotency key %q was already used with a different request payload", input.idempotencyKey), logical.ErrInvalidRequest
		}
		if len(record.Items) != len(input.items) {
			// Defensive guard: a truncated/corrupt ledger must never index
			// outside the request slice.
			return logical.ErrorResponse("idempotency key %q has an inconsistent stored record; use a new idempotency key", input.idempotencyKey), logical.ErrInvalidRequest
		}
	}

	for i, itemRecord := range record.Items {
		if itemRecord == nil {
			return logical.ErrorResponse("idempotency key %q has an inconsistent stored record; use a new idempotency key", input.idempotencyKey), logical.ErrInvalidRequest
		}
		if !renewBatchItemRequiresExecution(itemRecord) {
			continue
		}
		replayed = false
		item := input.items[i]

		if itemRecord.Status == renewBatchStatusAuditFailed && itemRecord.GrantedTTL > 0 {
			// Renewal already happened; only the post-renewal audit failed.
			// Retry the audit without renewing again.
			if err := ts.recoverPostAudit(ctx, req, view, record, itemRecord, item); err != nil {
				return nil, err
			}
			continue
		}

		if err := ts.executeRenewBatchItem(ctx, req, view, record, itemRecord, item); err != nil {
			return nil, err
		}
	}

	results := make([]map[string]interface{}, len(input.items))
	summary := map[string]int{
		renewBatchStatusSuccess:      0,
		renewBatchStatusLimitReached: 0,
		renewBatchStatusRevoked:      0,
		renewBatchStatusAuditFailed:  0,
		renewBatchStatusError:        0,
	}
	for i, itemRecord := range record.Items {
		summary[itemRecord.Status]++
		results[i] = renewBatchItemResult(i, itemRecord, input.items[i])
	}
	summary["total"] = len(input.items)

	return &logical.Response{
		Data: map[string]interface{}{
			"idempotency_key":          input.idempotencyKey,
			"max_total_duration":       int64(input.maxTotalDuration.Seconds()),
			"requested_total_duration": int64(renewBatchRequestedTotal(input).Seconds()),
			"granted_total_duration":   int64(record.grantedTotal().Seconds()),
			"replayed":                 replayed,
			"server_time":              ts.renewBatchNow().Truncate(time.Second),
			"results":                  results,
			"summary":                  summary,
		},
	}, nil
}

// renewBatchItemRequiresExecution reports whether an item must be executed or
// recovered during this request. Terminal items are always replayed.
func renewBatchItemRequiresExecution(item *renewBatchItemRecord) bool {
	switch item.Status {
	case renewBatchStatusSuccess,
		renewBatchStatusLimitReached,
		renewBatchStatusRevoked,
		renewBatchStatusError:
		return false
	}
	return true
}

// executeRenewBatchItem classifies and renews a single item, updating the
// ledger.
func (ts *TokenStore) executeRenewBatchItem(ctx context.Context, req *logical.Request, view logical.Storage, record *renewBatchRecord, itemRecord *renewBatchItemRecord, item renewBatchInputItem) error {
	setResult := func(status, reason string, grantedTTL time.Duration, expireTime time.Time, accessor string, renewable bool) error {
		itemRecord.Status = status
		itemRecord.Reason = reason
		itemRecord.GrantedTTL = grantedTTL
		itemRecord.ExpireTime = expireTime.Truncate(time.Second)
		itemRecord.Accessor = accessor
		itemRecord.Renewable = renewable
		itemRecord.FinalStatus = ""
		itemRecord.FinalReason = ""
		if err := ts.persistRenewBatchRecord(ctx, view, record); err != nil {
			// The renewal may already have happened: surface the storage
			// failure rather than returning a silent 200, which could lead a
			// retry to renew the token a second time.
			return fmt.Errorf("failed to persist renewal batch record: %w", err)
		}
		metrics.IncrCounter([]string{"token", "renew_batch", status}, 1)
		return nil
	}

	te, classifyErr := ts.resolveRenewBatchToken(ctx, item)
	if classifyErr != nil {
		switch classifyErr.kind {
		case renewBatchStatusRevoked, renewBatchStatusError:
			return setResult(classifyErr.kind, classifyErr.Error(), 0, time.Time{}, "", false)
		default:
			return setResult(renewBatchStatusError, classifyErr.Error(), 0, time.Time{}, "", false)
		}
	}

	itemRecord.Accessor = te.Accessor

	// A root token with no lease never expires: renewal is not applicable.
	nonexpiring, err := ts.isNonexpiringRoot(ctx, te)
	if err != nil {
		return setResult(renewBatchStatusError, fmt.Sprintf("error checking root token renewability: %s", err), 0, time.Time{}, te.Accessor, false)
	}
	if nonexpiring {
		return setResult(renewBatchStatusLimitReached, "root token does not expire and cannot be renewed", 0, time.Time{}, te.Accessor, false)
	}

	// Resolve the requested duration; an unspecified increment means the
	// mount default TTL applies.
	wanted := item.increment
	if wanted == 0 {
		if sysNS, sysErr := NamespaceByID(ctx, te.NamespaceID, ts.core); sysErr == nil && sysNS != nil {
			if sysView := ts.expiration.router.MatchingSystemView(namespace.ContextWithNamespace(ctx, sysNS), te.Path); sysView != nil {
				wanted = sysView.DefaultLeaseTTL()
			}
		}
	}

	// Enforce the aggregate renewal budget in input order.
	effectiveIncrement := item.increment
	budgetCapped := false
	if record.MaxTotalDuration > 0 {
		remaining := record.MaxTotalDuration - record.grantedTotal()
		switch {
		case remaining <= 0:
			return setResult(renewBatchStatusLimitReached, "renewal budget exhausted; the max_total_duration for this batch has already been granted", 0, time.Time{}, te.Accessor, false)
		case wanted > remaining:
			effectiveIncrement = remaining
			budgetCapped = true
		}
	}

	// Pre-renewal audit: a failure here means nothing was renewed and no
	// budget was consumed; the item remains retryable.
	if err := ts.renewBatchAuditor(ctx, renewBatchAuditPre, req, item, nil); err != nil {
		return setResult(renewBatchStatusAuditFailed, fmt.Sprintf("audit request logging failed: %s", err), 0, time.Time{}, te.Accessor, false)
	}

	resp, renewErr := ts.expiration.RenewToken(ctx, req, te, effectiveIncrement)
	if renewErr != nil {
		// RenewToken pairs logical error responses with the ErrInvalidRequest
		// sentinel; prefer the descriptive message from the response when
		// available (e.g. "lease is not renewable", "lease expired").
		reason := renewErr.Error()
		if resp != nil && resp.IsError() {
			if msg, ok := resp.Data["error"].(string); ok && msg != "" {
				reason = msg
			}
		}
		if errors.Is(renewErr, logical.ErrInvalidRequest) {
			return setResult(classifyRenewalMessage(reason), reason, 0, time.Time{}, te.Accessor, false)
		}
		return setResult(renewBatchStatusError, fmt.Sprintf("error renewing token: %s", reason), 0, time.Time{}, te.Accessor, false)
	}
	if resp == nil {
		return setResult(renewBatchStatusError, "no response returned while renewing token", 0, time.Time{}, te.Accessor, false)
	}
	if resp.IsError() {
		reason := resp.Data["error"].(string)
		status := classifyRenewalMessage(reason)
		return setResult(status, reason, 0, time.Time{}, te.Accessor, false)
	}
	if resp.Auth == nil {
		return setResult(renewBatchStatusError, "missing auth in token renewal response", 0, time.Time{}, te.Accessor, false)
	}

	grantedTTL := resp.Auth.TTL
	expireTime := resp.Auth.ExpirationTime()
	status, reason := classifyRenewalOutcome(wanted, effectiveIncrement, grantedTTL, budgetCapped, resp.Warnings)

	authForAudit := resp.Auth
	if item.kind() == renewBatchKindAccessor {
		// Mirror renew-accessor: never return the token value for accessor
		// based renewals.
		authCopy := *resp.Auth
		authCopy.ClientToken = ""
		authForAudit = &authCopy
	}

	// Post-renewal audit: the renewal stands when this fails, so the granted
	// TTL is recorded in the ledger (and charged to the budget); a retry with
	// the same idempotency key only replays this audit. The true terminal
	// status and reason are preserved so audit recovery replays the exact
	// original result.
	if err := ts.renewBatchAuditor(ctx, renewBatchAuditPost, req, item, authForAudit); err != nil {
		itemRecord.Status = renewBatchStatusAuditFailed
		itemRecord.FinalStatus = status
		itemRecord.FinalReason = reason
		itemRecord.Reason = fmt.Sprintf("audit response logging failed: %s", err)
		itemRecord.GrantedTTL = grantedTTL
		itemRecord.ExpireTime = expireTime.Truncate(time.Second)
		itemRecord.Accessor = te.Accessor
		itemRecord.Renewable = resp.Auth.Renewable
		if persistErr := ts.persistRenewBatchRecord(ctx, view, record); persistErr != nil {
			return fmt.Errorf("failed to persist renewal batch record: %w", persistErr)
		}
		metrics.IncrCounter([]string{"token", "renew_batch", renewBatchStatusAuditFailed}, 1)
		return nil
	}

	return setResult(status, reason, grantedTTL, expireTime, te.Accessor, resp.Auth.Renewable)
}

// recoverPostAudit retries only the post-renewal audit for an item whose
// renewal already succeeded. It never renews again.
func (ts *TokenStore) recoverPostAudit(ctx context.Context, req *logical.Request, view logical.Storage, record *renewBatchRecord, itemRecord *renewBatchItemRecord, item renewBatchInputItem) error {
	auth := &logical.Auth{
		Accessor:  itemRecord.Accessor,
		TTL:       itemRecord.GrantedTTL,
		Renewable: itemRecord.Renewable,
		IssueTime: itemRecord.ExpireTime.Add(-itemRecord.GrantedTTL),
	}
	if item.kind() == renewBatchKindToken {
		auth.ClientToken = item.token
	}

	if err := ts.renewBatchAuditor(ctx, renewBatchAuditPost, req, item, auth); err != nil {
		// Audit has still not recovered; leave the item as audit_failed so a
		// subsequent retry can try again. Persist to refresh record liveness.
		if persistErr := ts.persistRenewBatchRecord(ctx, view, record); persistErr != nil {
			return fmt.Errorf("failed to persist renewal batch record: %w", persistErr)
		}
		return nil
	}

	finalStatus := itemRecord.FinalStatus
	if finalStatus == "" {
		finalStatus = renewBatchStatusSuccess
	}
	itemRecord.Status = finalStatus
	itemRecord.FinalStatus = ""
	itemRecord.Reason = itemRecord.FinalReason
	itemRecord.FinalReason = ""
	if err := ts.persistRenewBatchRecord(ctx, view, record); err != nil {
		return fmt.Errorf("failed to persist renewal batch record: %w", err)
	}
	metrics.IncrCounter([]string{"token", "renew_batch", finalStatus}, 1)
	return nil
}

// renewBatchClassificationError carries a per-item classification decided
// before renewal is attempted.
type renewBatchClassificationError struct {
	kind string
	msg  string
}

func (e *renewBatchClassificationError) Error() string {
	return e.msg
}

// resolveRenewBatchToken turns a batch item (token or accessor) into a token
// entry, or returns a classified error.
func (ts *TokenStore) resolveRenewBatchToken(ctx context.Context, item renewBatchInputItem) (*logical.TokenEntry, *renewBatchClassificationError) {
	if item.accessor != "" {
		aEntry, err := ts.lookupByAccessor(ctx, item.accessor, false, false)
		if err != nil {
			return nil, &renewBatchClassificationError{kind: renewBatchStatusError, msg: fmt.Sprintf("error looking up accessor: %s", err)}
		}
		if aEntry == nil {
			return nil, &renewBatchClassificationError{kind: renewBatchStatusRevoked, msg: "invalid accessor; the associated token does not exist or has been revoked"}
		}
		te, err := ts.Lookup(ctx, aEntry.TokenID)
		if err != nil {
			return nil, &renewBatchClassificationError{kind: renewBatchStatusError, msg: fmt.Sprintf("error looking up token: %s", err)}
		}
		if te == nil {
			return nil, &renewBatchClassificationError{kind: renewBatchStatusRevoked, msg: "token not found; it may have expired or been revoked"}
		}
		return te, nil
	}

	normalizedID, err := ts.core.normalizeJwtForLookup(ctx, item.token)
	if err != nil {
		return nil, &renewBatchClassificationError{kind: renewBatchStatusError, msg: "invalid token"}
	}
	if IsOAuthJwtId(normalizedID) {
		return nil, &renewBatchClassificationError{kind: renewBatchStatusError, msg: "JWTs cannot be renewed"}
	}

	te, err := ts.Lookup(ctx, item.token)
	if err != nil {
		return nil, &renewBatchClassificationError{kind: renewBatchStatusError, msg: fmt.Sprintf("error looking up token to renew: %s", err)}
	}
	if te == nil {
		return nil, &renewBatchClassificationError{kind: renewBatchStatusRevoked, msg: "token not found; it may have expired or been revoked"}
	}
	if te.Type == logical.TokenTypeBatch {
		return nil, &renewBatchClassificationError{kind: renewBatchStatusError, msg: "batch tokens cannot be renewed"}
	}
	return te, nil
}

// isNonexpiringRoot reports whether a TTL-less root policy token has no
// renewable lease and therefore never expires.
func (ts *TokenStore) isNonexpiringRoot(ctx context.Context, te *logical.TokenEntry) (bool, error) {
	if te.TTL != 0 || !te.IsRoot() {
		return false, nil
	}
	le, err := ts.expiration.tokenLeaseEntry(ctx, te)
	if err != nil {
		return false, err
	}
	if le == nil || le.ExpireTime.IsZero() {
		return true, nil
	}
	return false, nil
}

// classifyRenewalMessage maps an error response from token renewal to a
// per-item result status.
func classifyRenewalMessage(msg string) string {
	switch {
	case strings.Contains(msg, "batch tokens cannot be renewed"),
		strings.Contains(msg, "JWTs cannot be renewed"):
		return renewBatchStatusError
	default:
		return renewBatchStatusRevoked
	}
}

// classifyRenewalOutcome decides success versus limit_reached after a
// successful renewal.
func classifyRenewalOutcome(wanted, effectiveIncrement, grantedTTL time.Duration, budgetCapped bool, warnings []string) (status, reason string) {
	ttlCapped := false
	for _, warning := range warnings {
		if strings.Contains(warning, "capped accordingly") {
			ttlCapped = true
			reason = warning
			break
		}
	}

	switch {
	case budgetCapped && ttlCapped:
		return renewBatchStatusLimitReached, fmt.Sprintf(
			"renewal requested %s but was capped by the batch renewal budget and the token maximum TTL; granted %s (%s)",
			wanted, grantedTTL, reason)
	case budgetCapped:
		return renewBatchStatusLimitReached, fmt.Sprintf(
			"renewal requested %s but was capped by the batch max_total_duration budget; granted %s",
			wanted, grantedTTL)
	case ttlCapped:
		return renewBatchStatusLimitReached, reason
	case wanted > 0 && grantedTTL < wanted:
		return renewBatchStatusLimitReached, fmt.Sprintf(
			"renewal requested %s but the server granted %s", wanted, grantedTTL)
	default:
		return renewBatchStatusSuccess, ""
	}
}

// renewBatchItemResult builds the externally visible result object for one
// item. Terminal results come straight from the persisted ledger; the token
// value (for token based items) is taken from the current request, which is
// guaranteed to match the original request by the idempotency fingerprint.
func renewBatchItemResult(index int, itemRecord *renewBatchItemRecord, item renewBatchInputItem) map[string]interface{} {
	result := map[string]interface{}{
		"index":               index,
		"identifier_type":     itemRecord.Kind,
		"status":              itemRecord.Status,
		"reason":              itemRecord.Reason,
		"renewable":           itemRecord.Renewable,
		"requested_increment": int64(itemRecord.Increment.Seconds()),
		"lease_duration":      int64(itemRecord.GrantedTTL.Seconds()),
	}
	if itemRecord.Accessor != "" {
		result["accessor"] = itemRecord.Accessor
	}
	if !itemRecord.ExpireTime.IsZero() {
		result["expire_time"] = itemRecord.ExpireTime
	}
	if item.kind() == renewBatchKindToken && itemRecord.GrantedTTL > 0 {
		result["client_token"] = item.token
	}
	return result
}

// defaultRenewBatchAudit routes per-item audit events through the core audit
// broker. With no audit backends configured the broker returns nil, matching
// the behavior of ordinary token renewal requests.
func (ts *TokenStore) defaultRenewBatchAudit(ctx context.Context, phase renewBatchAuditPhase, req *logical.Request, item renewBatchInputItem, auth *logical.Auth) error {
	if ts.core == nil || ts.core.auditBroker == nil {
		return nil
	}

	subReq := *req
	subReq.Path = renewBatchAuditRequestPath
	subReq.Operation = logical.UpdateOperation
	subReq.Data = map[string]interface{}{
		"increment": int64(item.increment.Seconds()),
	}
	if item.kind() == renewBatchKindAccessor {
		subReq.Data["accessor"] = item.accessor
	} else {
		subReq.Data["token"] = item.token
	}

	switch phase {
	case renewBatchAuditPre:
		return ts.core.auditBroker.LogRequest(ctx, &logical.LogInput{
			Request: &subReq,
		})
	case renewBatchAuditPost:
		return ts.core.auditBroker.LogResponse(ctx, &logical.LogInput{
			Request:  &subReq,
			Auth:     auth,
			Response: &logical.Response{Auth: auth},
		})
	}
	return nil
}

func renewBatchRequestedTotal(input renewBatchInput) time.Duration {
	var total time.Duration
	for _, item := range input.items {
		total += item.increment
	}
	return total
}

func renewBatchStorageKey(idempotencyKey string) string {
	return renewBatchHash(idempotencyKey)
}

func renewBatchHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// renewBatchFingerprint produces a stable hash over the request parameters
// that affect renewal outcomes: budget and each item's kind, identifier and
// increment.
func renewBatchFingerprint(input renewBatchInput) string {
	type fpItem struct {
		Kind       string `json:"kind"`
		Identifier string `json:"identifier"`
		Increment  int64  `json:"increment_seconds"`
	}
	fp := struct {
		MaxTotalDuration int64    `json:"max_total_duration_seconds"`
		Items            []fpItem `json:"items"`
	}{
		MaxTotalDuration: int64(input.maxTotalDuration.Seconds()),
		Items:            make([]fpItem, len(input.items)),
	}
	for i, item := range input.items {
		fp.Items[i] = fpItem{
			Kind:       item.kind(),
			Identifier: renewBatchHash(item.kind() + ":" + item.identifier()),
			Increment:  int64(item.increment.Seconds()),
		}
	}
	raw, err := json.Marshal(fp)
	if err != nil {
		// Every input value is a primitive string/int; marshal cannot fail.
		panic(fmt.Sprintf("failed to fingerprint renewal batch: %s", err))
	}
	return renewBatchHash(string(raw))
}

// errRenewBatchRecordCorrupt marks an unreadable idempotency record, which is
// derived state and can be discarded by the caller after surfacing an error.
var errRenewBatchRecordCorrupt = errors.New("renewal batch record is corrupt")

func (ts *TokenStore) renewBatchView(ns *namespace.Namespace) *BarrierView {
	return ts.baseView(ns).SubView(renewBatchPrefix)
}

// renewBatchStorage returns the ledger storage view. The unexported override is
// a test-only seam for simulating barrier write failures.
func (ts *TokenStore) renewBatchStorage(ns *namespace.Namespace) logical.Storage {
	if ts.renewBatchStorageOverride != nil {
		return ts.renewBatchStorageOverride
	}
	return ts.renewBatchView(ns)
}

func (ts *TokenStore) loadRenewBatchRecord(ctx context.Context, view logical.Storage, storageKey string, now time.Time) (*renewBatchRecord, error) {
	raw, err := view.Get(ctx, storageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read renewal batch record: %w", err)
	}
	if raw == nil {
		return nil, nil
	}

	record := new(renewBatchRecord)
	if err := jsonutil.DecodeJSON(raw.Value, record); err != nil {
		// Discard the corrupt, regenerable derived state so a fresh
		// idempotency key is unblocked, then surface a logical error for the
		// current request.
		if delErr := view.Delete(ctx, storageKey); delErr != nil {
			return nil, fmt.Errorf("failed to decode renewal batch record (%w) and delete it: %w", err, delErr)
		}
		return nil, fmt.Errorf("%w: %v", errRenewBatchRecordCorrupt, err)
	}

	if !record.ExpireTime.IsZero() && now.After(record.ExpireTime) {
		if err := view.Delete(ctx, storageKey); err != nil {
			return nil, fmt.Errorf("failed to delete expired renewal batch record: %w", err)
		}
		return nil, nil
	}
	return record, nil
}

func (ts *TokenStore) persistRenewBatchRecord(ctx context.Context, view logical.Storage, record *renewBatchRecord) error {
	entry, err := logical.StorageEntryJSON(record.Key, record)
	if err != nil {
		return fmt.Errorf("failed to encode renewal batch record: %w", err)
	}
	if err := view.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist renewal batch record: %w", err)
	}
	return nil
}

// parseRenewBatchInput validates and normalizes the renew-batch request.
func parseRenewBatchInput(data *framework.FieldData) (renewBatchInput, error) {
	var input renewBatchInput

	input.idempotencyKey = strings.TrimSpace(data.Get("idempotency_key").(string))
	if input.idempotencyKey == "" {
		return input, errors.New("missing idempotency_key")
	}
	if len(input.idempotencyKey) > renewBatchMaxKeyLength {
		return input, fmt.Errorf("idempotency_key exceeds the maximum length of %d characters", renewBatchMaxKeyLength)
	}

	maxTotalSeconds := data.Get("max_total_duration").(int)
	if maxTotalSeconds < 0 {
		return input, errors.New("max_total_duration must be zero (unlimited) or positive")
	}
	input.maxTotalDuration = time.Duration(maxTotalSeconds) * time.Second

	rawItems, ok := data.Get("tokens").([]interface{})
	if !ok || len(rawItems) == 0 {
		return input, errors.New("tokens must contain at least one item")
	}
	if len(rawItems) > renewBatchMaxItems {
		return input, fmt.Errorf("tokens exceeds the maximum batch size of %d", renewBatchMaxItems)
	}

	input.items = make([]renewBatchInputItem, 0, len(rawItems))
	seen := make(map[string]struct{}, len(rawItems))
	for i, raw := range rawItems {
		rawMap, ok := raw.(map[string]interface{})
		if !ok {
			return input, fmt.Errorf("tokens[%d]: item must be an object", i)
		}

		var item struct {
			Token     string      `json:"token"`
			Accessor  string      `json:"accessor"`
			Increment interface{} `json:"increment"`
		}
		encoded, err := json.Marshal(rawMap)
		if err != nil {
			return input, fmt.Errorf("tokens[%d]: invalid item: %w", i, err)
		}
		if err := json.Unmarshal(encoded, &item); err != nil {
			return input, fmt.Errorf("tokens[%d]: invalid item: %w", i, err)
		}
		item.Token = strings.TrimSpace(item.Token)
		item.Accessor = strings.TrimSpace(item.Accessor)

		switch {
		case item.Token == "" && item.Accessor == "":
			return input, fmt.Errorf("tokens[%d]: exactly one of token or accessor must be provided", i)
		case item.Token != "" && item.Accessor != "":
			return input, fmt.Errorf("tokens[%d]: only one of token or accessor may be provided", i)
		}

		increment := time.Duration(0)
		if item.Increment != nil {
			d, err := parseutil.ParseDurationSecond(item.Increment)
			if err != nil {
				return input, fmt.Errorf("tokens[%d]: invalid increment: %w", i, err)
			}
			if d < 0 {
				return input, fmt.Errorf("tokens[%d]: increment must be zero or positive", i)
			}
			increment = d
		}

		parsed := renewBatchInputItem{
			token:     item.Token,
			accessor:  item.Accessor,
			increment: increment,
		}
		dedupKey := parsed.kind() + ":" + parsed.identifier()
		if _, exists := seen[dedupKey]; exists {
			return input, fmt.Errorf("tokens[%d]: duplicate %s in batch request", i, parsed.kind())
		}
		seen[dedupKey] = struct{}{}

		input.items = append(input.items, parsed)
	}

	return input, nil
}
