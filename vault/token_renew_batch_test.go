// Copyright IBM Corp. 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/logical"
)

// renewBatchTestCore returns an unsealed core whose expiration manager has
// left restore mode, along with its token store and the initial root token.
func renewBatchTestCore(t *testing.T) (*Core, *TokenStore, string) {
	t.Helper()
	c, _, root := TestCoreUnsealed(t)

	deadline := time.Now().Add(10 * time.Second)
	for c.expiration.inRestoreMode() {
		if time.Now().After(deadline) {
			t.Fatal("expiration manager is still in restore mode after 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c, c.tokenStore, root
}

func renewBatchCtx() context.Context {
	return namespace.RootContext(nil)
}

// renewBatchCreateToken creates a service token with a caller chosen ID so it
// can be referenced deterministically from tests.
func renewBatchCreateToken(t *testing.T, c *Core, caller, id, ttl string, policies []string, extra map[string]interface{}) *logical.Auth {
	t.Helper()
	req := logical.TestRequest(t, logical.UpdateOperation, "auth/token/create")
	req.ClientToken = caller
	req.Data = map[string]interface{}{
		"id":       id,
		"ttl":      ttl,
		"policies": policies,
	}
	for k, v := range extra {
		req.Data[k] = v
	}
	resp, err := c.HandleRequest(renewBatchCtx(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err: %v\nresp: %#v", err, resp)
	}
	if resp == nil || resp.Auth == nil {
		t.Fatalf("expected auth in response, got %#v", resp)
	}
	return resp.Auth
}

// renewBatchCreateChild creates a service token entry with an explicit
// parent and a registered auth lease, bypassing HTTP ACL checks (the default
// policy does not permit auth/token/create).
func renewBatchCreateChild(t *testing.T, c *Core, parent, id, ttl string) {
	t.Helper()
	ts := c.tokenStore
	dur, err := time.ParseDuration(ttl)
	if err != nil {
		t.Fatal(err)
	}
	entry := &logical.TokenEntry{
		Parent:       parent,
		Policies:     []string{"default"},
		Path:         "auth/token/create",
		DisplayName:  "token",
		CreationTime: time.Now().Unix(),
		TTL:          dur,
		NamespaceID:  namespace.RootNamespaceID,
		Type:         logical.TokenTypeService,
		ID:           id,
	}
	if err := ts.create(renewBatchCtx(), entry); err != nil {
		t.Fatalf("create child token %q: %v", id, err)
	}
	auth := &logical.Auth{
		ClientToken: entry.ID,
		Accessor:    entry.Accessor,
		Policies:    entry.Policies,
		DisplayName: entry.DisplayName,
		LeaseOptions: logical.LeaseOptions{
			TTL:       dur,
			Renewable: true,
		},
	}
	if err := c.expiration.RegisterAuth(renewBatchCtx(), entry, auth, ""); err != nil {
		t.Fatalf("register lease for child %q: %v", id, err)
	}
}

func renewBatchLease(t *testing.T, c *Core, id string) *leaseEntry {
	t.Helper()
	te, err := c.tokenStore.Lookup(renewBatchCtx(), id)
	if err != nil || te == nil {
		t.Fatalf("lookup %q: err %v te %v", id, err, te)
	}
	le, err := c.expiration.tokenLeaseEntry(renewBatchCtx(), te)
	if err != nil || le == nil {
		t.Fatalf("lease %q: err %v le %v", id, err, le)
	}
	return le
}

func renewBatchRevoke(t *testing.T, c *Core, root, id string, orphan bool) {
	t.Helper()
	path := "auth/token/revoke"
	if orphan {
		path = "auth/token/revoke-orphan"
	}
	req := logical.TestRequest(t, logical.UpdateOperation, path)
	req.ClientToken = root
	req.Data = map[string]interface{}{"token": id}
	resp, err := c.HandleRequest(renewBatchCtx(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("revoke %q failed: err: %v resp: %#v", id, err, resp)
	}
}

func renewBatchItem(tokenOrAccessor string, increment interface{}, accessor bool) map[string]interface{} {
	item := map[string]interface{}{
		"increment": increment,
	}
	if accessor {
		item["accessor"] = tokenOrAccessor
	} else {
		item["token"] = tokenOrAccessor
	}
	return item
}

func renewBatchDo(t *testing.T, ts *TokenStore, caller, key string, maxTotal interface{}, items []map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	req := logical.TestRequest(t, logical.UpdateOperation, "renew-batch")
	req.ClientToken = caller
	req.Data = map[string]interface{}{
		"idempotency_key": key,
		"tokens":          items,
	}
	if maxTotal != nil {
		req.Data["max_total_duration"] = maxTotal
	}
	return ts.HandleRequest(renewBatchCtx(), req)
}

func renewBatchResults(t *testing.T, resp *logical.Response) []map[string]interface{} {
	t.Helper()
	if resp == nil || resp.IsError() {
		t.Fatalf("expected batch response, got %#v", resp)
	}
	raw, ok := resp.Data["results"].([]map[string]interface{})
	if !ok {
		t.Fatalf("results is not []map[string]interface{}: %T", resp.Data["results"])
	}
	return raw
}

func renewBatchSummary(resp *logical.Response) map[string]int {
	summary := map[string]int{}
	for k, v := range resp.Data["summary"].(map[string]int) {
		summary[k] = v
	}
	return summary
}

func renewBatchExpireFor(t *testing.T, c *Core, id string) time.Time {
	t.Helper()
	if id == "" {
		return time.Time{}
	}
	te, err := c.tokenStore.Lookup(renewBatchCtx(), id)
	if err != nil {
		t.Fatalf("lookup %q: %v", id, err)
	}
	if te == nil {
		return time.Time{}
	}
	le, err := c.expiration.tokenLeaseEntry(renewBatchCtx(), te)
	if err != nil {
		t.Fatalf("load lease %q: %v", id, err)
	}
	if le == nil {
		return time.Time{}
	}
	return le.ExpireTime
}

func renewBatchRawRecord(t *testing.T, ts *TokenStore, key string) []byte {
	t.Helper()
	view := ts.renewBatchView(namespace.RootNamespace)
	raw, err := view.Get(renewBatchCtx(), renewBatchStorageKey(key))
	if err != nil {
		t.Fatalf("read batch record: %v", err)
	}
	if raw == nil {
		return nil
	}
	return raw.Value
}

// TestTokenStore_RenewBatch_Validation covers AC-1: request validation never
// has side effects.
func TestTokenStore_RenewBatch_Validation(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)
	_ = c

	validItem := func(token string) map[string]interface{} {
		return map[string]interface{}{"token": token, "increment": 60}
	}

	cases := []struct {
		name     string
		key      string
		maxTotal interface{}
		items    []map[string]interface{}
	}{
		{
			name:  "missing key",
			key:   "",
			items: []map[string]interface{}{validItem("a-token")},
		},
		{
			name:  "empty items",
			key:   "k-empty",
			items: nil,
		},
		{
			name: "too many items",
			key:  "k-many",
			items: func() []map[string]interface{} {
				items := make([]map[string]interface{}, renewBatchMaxItems+1)
				for i := range items {
					items[i] = validItem(fmt.Sprintf("token-%03d", i))
				}
				return items
			}(),
		},
		{
			name: "both token and accessor",
			key:  "k-both",
			items: []map[string]interface{}{
				{"token": "a", "accessor": "b", "increment": 60},
			},
		},
		{
			name: "neither token nor accessor",
			key:  "k-neither",
			items: []map[string]interface{}{
				{"increment": 60},
			},
		},
		{
			name: "duplicate token",
			key:  "k-dup",
			items: []map[string]interface{}{
				validItem("dup-token"),
				validItem("dup-token"),
			},
		},
		{
			name: "duplicate across kinds",
			key:  "k-dup-mixed",
			items: []map[string]interface{}{
				{"accessor": "same-value", "increment": 60},
				{"accessor": "same-value", "increment": 60},
			},
		},
		{
			name:     "negative budget",
			key:      "k-neg-budget",
			maxTotal: -1,
			items:    []map[string]interface{}{validItem("a-token")},
		},
		{
			name: "bad increment",
			key:  "k-bad-inc",
			items: []map[string]interface{}{
				{"token": "a-token", "increment": "not-a-duration"},
			},
		},
		{
			name: "negative increment",
			key:  "k-neg-inc",
			items: []map[string]interface{}{
				{"token": "a-token", "increment": -5},
			},
		},
		{
			name:     "key too long",
			key:      strings.Repeat("x", renewBatchMaxKeyLength+1),
			maxTotal: nil,
			items:    []map[string]interface{}{validItem("a-token")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := renewBatchDo(t, ts, root, tc.key, tc.maxTotal, tc.items)
			// Framework level field validation may surface as a logical
			// error response without the sentinel error.
			if !errors.Is(err, logical.ErrInvalidRequest) && (resp == nil || !resp.IsError()) {
				t.Fatalf("expected invalid request, got err=%v resp=%#v", err, resp)
			}
		})
	}

	// No ledger records may exist after rejected requests.
	keys, err := logical.CollectKeys(renewBatchCtx(), ts.renewBatchView(namespace.RootNamespace))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no persisted batch records, got %v", keys)
	}
}

// TestTokenStore_RenewBatch_Budget covers AC-2: the aggregate budget is
// enforced in input order and items past the budget are not renewed.
func TestTokenStore_RenewBatch_Budget(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	renewBatchCreateToken(t, c, root, "budget-a1", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "budget-a2", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "budget-b1", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "budget-b2", "1h", []string{"default"}, nil)

	items := func(a, b string) []map[string]interface{} {
		return []map[string]interface{}{
			renewBatchItem(a, "3600s", false),
			renewBatchItem(b, "3600s", false),
		}
	}

	// Budget covers the full request: both renewed.
	resp, err := renewBatchDo(t, ts, root, "budget-full", "7200s", items("budget-a1", "budget-a2"))
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusSuccess || results[1]["status"] != renewBatchStatusSuccess {
		t.Fatalf("expected both success, got %#v", results)
	}
	if got := resp.Data["granted_total_duration"]; got != int64(7200) {
		t.Fatalf("granted total: got %v want 7200", got)
	}

	// Budget covers one item only: the second item must be untouched.
	b2ExpireBefore := renewBatchExpireFor(t, c, "budget-b2")
	resp, err = renewBatchDo(t, ts, root, "budget-half", 3600, items("budget-b1", "budget-b2"))
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results = renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusSuccess {
		t.Fatalf("first item should succeed: %#v", results[0])
	}
	if results[1]["status"] != renewBatchStatusLimitReached ||
		!strings.Contains(results[1]["reason"].(string), "budget") {
		t.Fatalf("second item should be budget limited: %#v", results[1])
	}
	if got := results[1]["lease_duration"]; got != int64(0) {
		t.Fatalf("limited item must not be granted TTL, got %v", got)
	}
	if got := resp.Data["granted_total_duration"]; got != int64(3600) {
		t.Fatalf("granted total: got %v want 3600", got)
	}
	summary := renewBatchSummary(resp)
	if summary[renewBatchStatusSuccess] != 1 || summary[renewBatchStatusLimitReached] != 1 {
		t.Fatalf("bad summary: %#v", summary)
	}

	b2ExpireAfter := renewBatchExpireFor(t, c, "budget-b2")
	if !b2ExpireAfter.Equal(b2ExpireBefore) {
		t.Fatalf("budget blocked token must not be renewed: before %s after %s", b2ExpireBefore, b2ExpireAfter)
	}
}

// TestTokenStore_RenewBatch_TTLLimit covers AC-3: renewal capped by the
// token's explicit maximum TTL is reported as limit_reached with a clear
// reason, and the granted TTL is charged against the budget.
func TestTokenStore_RenewBatch_TTLLimit(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)
	ctx := renewBatchCtx()

	renewBatchCreateToken(t, c, root, "ttl-limit-1", "1h", []string{"default"}, map[string]interface{}{
		"explicit_max_ttl": "1h",
	})

	// Backdate the lease so the token is 3595s into its 1h lifetime without
	// waiting on the wall clock.
	te, err := ts.Lookup(ctx, "ttl-limit-1")
	if err != nil || te == nil {
		t.Fatalf("lookup: err %v te %v", err, te)
	}
	le, err := c.expiration.tokenLeaseEntry(ctx, te)
	if err != nil || le == nil {
		t.Fatalf("lease: err %v le %v", err, le)
	}
	le.IssueTime = time.Now().Add(-3595 * time.Second)
	le.ExpireTime = le.IssueTime.Add(time.Hour)
	c.expiration.pendingLock.Lock()
	if err := c.expiration.persistEntry(ctx, le); err != nil {
		t.Fatal(err)
	}
	c.expiration.updatePendingInternal(le)
	c.expiration.pendingLock.Unlock()

	resp, err := renewBatchDo(t, ts, root, "ttl-limit-key", 3600, []map[string]interface{}{
		renewBatchItem("ttl-limit-1", "3600s", false),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusLimitReached {
		t.Fatalf("expected limit_reached, got %#v", results[0])
	}
	reason := results[0]["reason"].(string)
	if !strings.Contains(reason, "max_ttl") {
		t.Fatalf("reason should mention max_ttl: %q", reason)
	}
	granted := results[0]["lease_duration"].(int64)
	if granted < 3 || granted > 7 {
		t.Fatalf("granted TTL should be ~5s remaining, got %d", granted)
	}
	if resp.Data["granted_total_duration"] != granted {
		t.Fatalf("granted total should charge the capped TTL: %#v", resp.Data)
	}
}

// TestTokenStore_RenewBatch_Revoked covers AC-4: missing, revoked and
// non-renewable tokens are classified per item without affecting others.
func TestTokenStore_RenewBatch_Revoked(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	renewBatchCreateToken(t, c, root, "rev-valid", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "rev-gone", "1h", []string{"default"}, nil)
	renewBatchRevoke(t, c, root, "rev-gone", false)
	renewBatchCreateToken(t, c, root, "rev-norenew", "1h", []string{"default"}, map[string]interface{}{
		"renewable": false,
	})

	resp, err := renewBatchDo(t, ts, root, "revoked-key", 0, []map[string]interface{}{
		renewBatchItem("rev-valid", "60s", false),
		renewBatchItem("rev-gone", "60s", false),
		renewBatchItem("rev-norenew", "60s", false),
		renewBatchItem("definitely-not-a-real-token", "60s", false),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("batch must be 200 with per-item results: err=%v resp=%#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusSuccess {
		t.Fatalf("valid token should succeed: %#v", results[0])
	}
	if results[1]["status"] != renewBatchStatusRevoked ||
		!strings.Contains(results[1]["reason"].(string), "not found") {
		t.Fatalf("revoked token: %#v", results[1])
	}
	if results[2]["status"] != renewBatchStatusRevoked ||
		!strings.Contains(results[2]["reason"].(string), "not renewable") {
		t.Fatalf("non-renewable token: %#v", results[2])
	}
	if results[3]["status"] != renewBatchStatusRevoked ||
		!strings.Contains(results[3]["reason"].(string), "not found") {
		t.Fatalf("unknown token: %#v", results[3])
	}
	summary := renewBatchSummary(resp)
	if summary[renewBatchStatusSuccess] != 1 || summary[renewBatchStatusRevoked] != 3 {
		t.Fatalf("bad summary: %#v", summary)
	}
	if summary["total"] != 4 {
		t.Fatalf("bad total: %#v", summary)
	}
}

// TestTokenStore_RenewBatch_RootAndChildren covers AC-5: initial root tokens
// are non-expiring, parent/child renew independently, revocation tree
// removes children, and orphaned children survive.
func TestTokenStore_RenewBatch_RootAndChildren(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	// Healthy parent/child pair.
	renewBatchCreateToken(t, c, root, "rc-parent", "1h", []string{"default"}, nil)
	renewBatchCreateChild(t, c, "rc-parent", "rc-child", "1h")

	// Parent revoked with its tree: child must be gone as well.
	renewBatchCreateToken(t, c, root, "rc-dead-parent", "1h", []string{"default"}, nil)
	renewBatchCreateChild(t, c, "rc-dead-parent", "rc-dead-child", "1h")
	renewBatchRevoke(t, c, root, "rc-dead-parent", false)

	// Parent orphan-revoked: child survives and remains renewable.
	renewBatchCreateToken(t, c, root, "rc-orphan-parent", "1h", []string{"default"}, nil)
	renewBatchCreateChild(t, c, "rc-orphan-parent", "rc-orphan-child", "1h")
	renewBatchRevoke(t, c, root, "rc-orphan-parent", true)

	resp, err := renewBatchDo(t, ts, root, "root-children-key", 0, []map[string]interface{}{
		renewBatchItem(root, "60s", false),
		renewBatchItem("rc-parent", "60s", false),
		renewBatchItem("rc-child", "60s", false),
		renewBatchItem("rc-dead-parent", "60s", false),
		renewBatchItem("rc-dead-child", "60s", false),
		renewBatchItem("rc-orphan-child", "60s", false),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)

	expect := []struct {
		status string
		reason string
	}{
		{renewBatchStatusLimitReached, "root token does not expire"},
		{renewBatchStatusSuccess, ""},
		{renewBatchStatusSuccess, ""},
		{renewBatchStatusRevoked, ""},
		{renewBatchStatusRevoked, ""},
		{renewBatchStatusSuccess, ""},
	}
	for i, want := range expect {
		if results[i]["status"] != want.status {
			t.Fatalf("item %d: got status %v want %s (%#v)", i, results[i]["status"], want.status, results[i])
		}
		if want.reason != "" && !strings.Contains(results[i]["reason"].(string), want.reason) {
			t.Fatalf("item %d reason: got %q want contains %q", i, results[i]["reason"], want.reason)
		}
	}
	// Root renewal consumes no budget.
	if got := resp.Data["granted_total_duration"]; got != int64(180) {
		t.Fatalf("granted total: got %v want 180", got)
	}
	summary := renewBatchSummary(resp)
	if summary[renewBatchStatusSuccess] != 3 ||
		summary[renewBatchStatusLimitReached] != 1 ||
		summary[renewBatchStatusRevoked] != 2 {
		t.Fatalf("bad summary: %#v", summary)
	}
}

// TestTokenStore_RenewBatch_IdempotentReplay covers AC-6: repeated identical
// requests replay stored results, never renew twice, and clock drift does not
// change absolute expiration. Different payload or caller is rejected.
func TestTokenStore_RenewBatch_IdempotentReplay(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	renewBatchCreateToken(t, c, root, "idem-1", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "idem-2", "1h", []string{"default"}, nil)

	items := []map[string]interface{}{
		renewBatchItem("idem-1", "2h", false),
		renewBatchItem("idem-2", "2h", false),
	}

	expire1Before := renewBatchExpireFor(t, c, "idem-1")
	expire2Before := renewBatchExpireFor(t, c, "idem-2")

	resp, err := renewBatchDo(t, ts, root, "idem-key", 0, items)
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	first := renewBatchResults(t, resp)
	if resp.Data["replayed"] != false {
		t.Fatal("first call must not be a replay")
	}

	expire1After := renewBatchExpireFor(t, c, "idem-1")
	expire2After := renewBatchExpireFor(t, c, "idem-2")
	if !expire1After.After(expire1Before) || !expire2After.After(expire2Before) {
		t.Fatal("tokens should have been renewed on the first call")
	}

	// Simulate a retry ten minutes later on a drifted client/server clock.
	drifted := time.Now().Add(10 * time.Minute)
	ts.renewBatchNow = func() time.Time { return drifted }

	resp, err = renewBatchDo(t, ts, root, "idem-key", 0, items)
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	if resp.Data["replayed"] != true {
		t.Fatal("second call must be a replay")
	}
	replayed := renewBatchResults(t, resp)
	for i := range first {
		if replayed[i]["status"] != first[i]["status"] ||
			replayed[i]["lease_duration"] != first[i]["lease_duration"] ||
			replayed[i]["expire_time"] != first[i]["expire_time"] {
			t.Fatalf("item %d mismatch on replay:\nfirst: %#v\nreplay: %#v", i, first[i], replayed[i])
		}
	}
	if resp.Data["granted_total_duration"] != int64(14400) {
		t.Fatalf("granted total must not grow on replay: %#v", resp.Data)
	}
	if got := renewBatchExpireFor(t, c, "idem-1"); !got.Equal(expire1After) {
		t.Fatalf("token must not be renewed a second time: %s vs %s", got, expire1After)
	}
	if got := renewBatchExpireFor(t, c, "idem-2"); !got.Equal(expire2After) {
		t.Fatalf("token must not be renewed a second time: %s vs %s", got, expire2After)
	}

	// Same key, different budget/payload is rejected.
	if _, err := renewBatchDo(t, ts, root, "idem-key", 60, items); !errors.Is(err, logical.ErrInvalidRequest) {
		t.Fatalf("expected conflict error, got %v", err)
	}
	// Same key, different caller is rejected.
	if _, err := renewBatchDo(t, ts, "another-caller-token", "idem-key", 0, items); !errors.Is(err, logical.ErrInvalidRequest) {
		t.Fatalf("expected caller conflict error, got %v", err)
	}

	// After the record TTL elapses, the key behaves as a new request.
	ts.renewBatchNow = func() time.Time { return drifted.Add(25 * time.Hour) }
	resp, err = renewBatchDo(t, ts, root, "idem-key", 0, items)
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	if resp.Data["replayed"] != false {
		t.Fatal("expired ledger must result in a fresh execution")
	}
}

// renewBatchCountingAuditor counts pre/post audit invocations per item and
// optionally fails configured calls.
type renewBatchCountingAuditor struct {
	mu        sync.Mutex
	preCalls  map[string]int
	postCalls map[string]int
	fail      map[string]renewBatchAuditPhase // item -> phase to fail once
}

func newRenewBatchCountingAuditor() *renewBatchCountingAuditor {
	return &renewBatchCountingAuditor{
		preCalls:  map[string]int{},
		postCalls: map[string]int{},
		fail:      map[string]renewBatchAuditPhase{},
	}
}

func (a *renewBatchCountingAuditor) failOnce(item string, phase renewBatchAuditPhase) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail[item] = phase
}

func (a *renewBatchCountingAuditor) pre(item string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.preCalls[item]
}

func (a *renewBatchCountingAuditor) post(item string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.postCalls[item]
}

func (a *renewBatchCountingAuditor) hook() renewBatchAuditorFunc {
	return func(_ context.Context, phase renewBatchAuditPhase, _ *logical.Request, item renewBatchInputItem, _ *logical.Auth) error {
		id := item.identifier()
		a.mu.Lock()
		if phase == renewBatchAuditPre {
			a.preCalls[id]++
		} else {
			a.postCalls[id]++
		}
		if failedPhase, ok := a.fail[id]; ok && failedPhase == phase {
			delete(a.fail, id)
			a.mu.Unlock()
			return errors.New("simulated audit sink failure")
		}
		a.mu.Unlock()
		return nil
	}
}

// TestTokenStore_RenewBatch_AuditFailurePreRenew covers the pre-renewal audit
// branch of AC-7: failed items are not renewed and retry succeeds without
// re-renewing the other items.
func TestTokenStore_RenewBatch_AuditFailurePreRenew(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	for _, id := range []string{"audit-pre-1", "audit-pre-2", "audit-pre-3"} {
		renewBatchCreateToken(t, c, root, id, "1h", []string{"default"}, nil)
	}
	items := []map[string]interface{}{
		renewBatchItem("audit-pre-1", "60s", false),
		renewBatchItem("audit-pre-2", "60s", false),
		renewBatchItem("audit-pre-3", "60s", false),
	}

	auditor := newRenewBatchCountingAuditor()
	auditor.failOnce("audit-pre-2", renewBatchAuditPre)
	ts.renewBatchAuditor = auditor.hook()

	expire2Before := renewBatchExpireFor(t, c, "audit-pre-2")

	resp, err := renewBatchDo(t, ts, root, "audit-pre-key", 180, items)
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusSuccess ||
		results[1]["status"] != renewBatchStatusAuditFailed ||
		results[2]["status"] != renewBatchStatusSuccess {
		t.Fatalf("bad statuses: %#v", results)
	}
	if !strings.Contains(results[1]["reason"].(string), "audit") {
		t.Fatalf("audit failure reason: %#v", results[1])
	}
	if got := results[1]["lease_duration"]; got != int64(0) {
		t.Fatalf("pre-audit failure must not grant TTL, got %v", got)
	}
	if got := resp.Data["granted_total_duration"]; got != int64(120) {
		t.Fatalf("granted total excludes failed item: got %v", got)
	}
	if got := renewBatchExpireFor(t, c, "audit-pre-2"); !got.Equal(expire2Before) {
		t.Fatalf("failed item must not be renewed: %s vs %s", got, expire2Before)
	}

	// Retry with the same key; auditor now succeeds for all items.
	expire1AfterFirst := renewBatchExpireFor(t, c, "audit-pre-1")
	expire3AfterFirst := renewBatchExpireFor(t, c, "audit-pre-3")

	resp, err = renewBatchDo(t, ts, root, "audit-pre-key", 180, items)
	if err != nil || resp.IsError() {
		t.Fatalf("retry: err: %v resp: %#v", err, resp)
	}
	results = renewBatchResults(t, resp)
	for i, want := range []string{
		renewBatchStatusSuccess,
		renewBatchStatusSuccess,
		renewBatchStatusSuccess,
	} {
		if results[i]["status"] != want {
			t.Fatalf("retry item %d: got %v want %s (%#v)", i, results[i]["status"], want, results[i])
		}
	}
	if got := resp.Data["granted_total_duration"]; got != int64(180) {
		t.Fatalf("granted total after retry: got %v want 180 (no budget expansion)", got)
	}

	// Items 1 and 3 were terminal on the first call: they must not have been
	// audited again or renewed again.
	if auditor.post("audit-pre-1") != 1 || auditor.post("audit-pre-3") != 1 {
		t.Fatalf("terminal items must not be re-audited: 1=%d 3=%d",
			auditor.post("audit-pre-1"), auditor.post("audit-pre-3"))
	}
	if got := renewBatchExpireFor(t, c, "audit-pre-1"); !got.Equal(expire1AfterFirst) {
		t.Fatalf("item 1 renewed again: %s vs %s", got, expire1AfterFirst)
	}
	if got := renewBatchExpireFor(t, c, "audit-pre-3"); !got.Equal(expire3AfterFirst) {
		t.Fatalf("item 3 renewed again: %s vs %s", got, expire3AfterFirst)
	}
}

// TestTokenStore_RenewBatch_AuditFailurePostRenew covers the post-renewal
// audit branch of AC-7: renewal stands, budget is charged, and retry only
// replays the audit.
func TestTokenStore_RenewBatch_AuditFailurePostRenew(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	for _, id := range []string{"audit-post-1", "audit-post-2", "audit-post-3"} {
		renewBatchCreateToken(t, c, root, id, "1h", []string{"default"}, nil)
	}
	items := []map[string]interface{}{
		renewBatchItem("audit-post-1", "60s", false),
		renewBatchItem("audit-post-2", "60s", false),
		renewBatchItem("audit-post-3", "60s", false),
	}

	auditor := newRenewBatchCountingAuditor()
	auditor.failOnce("audit-post-2", renewBatchAuditPost)
	ts.renewBatchAuditor = auditor.hook()

	resp, err := renewBatchDo(t, ts, root, "audit-post-key", 180, items)
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[1]["status"] != renewBatchStatusAuditFailed {
		t.Fatalf("item 2 should be audit_failed: %#v", results[1])
	}
	if results[1]["lease_duration"] != int64(60) || results[1]["expire_time"] == nil {
		t.Fatalf("renewed item should carry its grant despite audit failure: %#v", results[1])
	}
	if got := resp.Data["granted_total_duration"]; got != int64(180) {
		t.Fatalf("post-audit failure still charges the granted TTL: got %v", got)
	}

	expire2 := renewBatchExpireFor(t, c, "audit-post-2")

	// Retry: audit recovery only.
	resp, err = renewBatchDo(t, ts, root, "audit-post-key", 180, items)
	if err != nil || resp.IsError() {
		t.Fatalf("retry: err: %v resp: %#v", err, resp)
	}
	results = renewBatchResults(t, resp)
	if results[1]["status"] != renewBatchStatusSuccess {
		t.Fatalf("item 2 should recover to success, got %#v", results[1])
	}
	if results[0]["status"] != renewBatchStatusSuccess || results[2]["status"] != renewBatchStatusSuccess {
		t.Fatalf("items 1/3 should remain successful: %#v", results)
	}
	if got := resp.Data["granted_total_duration"]; got != int64(180) {
		t.Fatalf("granted total must remain 180 after audit retry: %v", got)
	}
	// The second post-audit call happens, but no second renewal.
	if auditor.post("audit-post-2") != 2 {
		t.Fatalf("expected two post audits (failure + recovery), got %d", auditor.post("audit-post-2"))
	}
	if got := renewBatchExpireFor(t, c, "audit-post-2"); !got.Equal(expire2) {
		t.Fatalf("item 2 must not be renewed during audit recovery: %s vs %s", got, expire2)
	}
	if auditor.post("audit-post-1") != 1 || auditor.post("audit-post-3") != 1 {
		t.Fatalf("terminal items re-audited: 1=%d 3=%d",
			auditor.post("audit-post-1"), auditor.post("audit-post-3"))
	}
}

// TestTokenStore_RenewBatch_PartialFailureClockDriftRetry is the AC-7
// end-to-end combination: revoked + audit failure + success, clock advances,
// same key retried, then replayed once more; totals and absolute expiration
// stay stable across all calls.
func TestTokenStore_RenewBatch_PartialFailureClockDriftRetry(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	renewBatchCreateToken(t, c, root, "combo-good", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "combo-audit", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "combo-dead", "1h", []string{"default"}, nil)
	renewBatchRevoke(t, c, root, "combo-dead", false)

	items := []map[string]interface{}{
		renewBatchItem("combo-good", "60s", false),
		renewBatchItem("combo-audit", "60s", false),
		renewBatchItem("combo-dead", "60s", false),
	}

	auditor := newRenewBatchCountingAuditor()
	auditor.failOnce("combo-audit", renewBatchAuditPre)
	ts.renewBatchAuditor = auditor.hook()

	call := func(label string, now time.Time) *logical.Response {
		ts.renewBatchNow = func() time.Time { return now }
		resp, err := renewBatchDo(t, ts, root, "combo-key", 180, items)
		if err != nil || resp.IsError() {
			t.Fatalf("%s: err %v resp %#v", label, err, resp)
		}
		return resp
	}

	first := call("first", time.Now())
	if first.Data["granted_total_duration"] != int64(60) {
		t.Fatalf("first call grants only the successful item: %#v", first.Data)
	}
	goodExpire := renewBatchExpireFor(t, c, "combo-good")
	auditLeaseBefore := renewBatchLease(t, c, "combo-audit")
	if !auditLeaseBefore.LastRenewalTime.IsZero() {
		t.Fatalf("pre-audit failed item should not have been renewed: %#v", auditLeaseBefore)
	}

	retry := call("retry after drift", time.Now().Add(10*time.Minute))
	if retry.Data["granted_total_duration"] != int64(120) {
		t.Fatalf("retry grants the previously failed item only: %#v", retry.Data)
	}
	if got := renewBatchExpireFor(t, c, "combo-good"); !got.Equal(goodExpire) {
		t.Fatalf("good item renewed on retry: %s vs %s", got, goodExpire)
	}
	auditLeaseAfter := renewBatchLease(t, c, "combo-audit")
	if auditLeaseAfter.LastRenewalTime.IsZero() {
		t.Fatal("audit-failed item should have been renewed on retry")
	}
	retryResults := renewBatchResults(t, retry)
	if retryResults[0]["status"] != renewBatchStatusSuccess ||
		retryResults[1]["status"] != renewBatchStatusSuccess ||
		retryResults[2]["status"] != renewBatchStatusRevoked {
		t.Fatalf("retry statuses: %#v", retryResults)
	}

	// One more replay after further drift: everything stable.
	grantedBefore := retry.Data["granted_total_duration"]
	goodExpire2 := renewBatchExpireFor(t, c, "combo-good")
	third := call("second replay", time.Now().Add(1*time.Hour))
	if third.Data["replayed"] != true || third.Data["granted_total_duration"] != grantedBefore {
		t.Fatalf("third call must be a stable replay: %#v", third.Data)
	}
	if got := renewBatchExpireFor(t, c, "combo-good"); !got.Equal(goodExpire2) {
		t.Fatalf("good item renewed on third call: %s vs %s", got, goodExpire2)
	}
}

// TestTokenStore_RenewBatch_Accessor covers accessor based items and the
// client_token elision behavior, plus batch tokens being errors.
func TestTokenStore_RenewBatch_Accessor(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	auth := renewBatchCreateToken(t, c, root, "acc-good", "1h", []string{"default"}, nil)
	if auth.Accessor == "" {
		t.Fatal("expected accessor")
	}

	resp, err := renewBatchDo(t, ts, root, "accessor-key", 0, []map[string]interface{}{
		renewBatchItem(auth.Accessor, "60s", true),
		renewBatchItem("invalid-accessor-value", "60s", true),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusSuccess {
		t.Fatalf("accessor renewal: %#v", results[0])
	}
	if results[0]["accessor"] != auth.Accessor {
		t.Fatalf("accessor echo: %#v", results[0])
	}
	if _, present := results[0]["client_token"]; present {
		t.Fatalf("accessor result must not contain client_token: %#v", results[0])
	}
	if results[1]["status"] != renewBatchStatusRevoked {
		t.Fatalf("invalid accessor: %#v", results[1])
	}

	// Batch tokens cannot be renewed and surface as error status. Root
	// callers cannot mint batch tokens ("batch tokens cannot be root
	// tokens"), so construct the entry directly like other tests do.
	batchEntry := &logical.TokenEntry{
		Policies:     []string{"default"},
		Path:         "auth/token/create",
		DisplayName:  "token",
		CreationTime: time.Now().Unix(),
		TTL:          time.Hour,
		NamespaceID:  namespace.RootNamespaceID,
		Type:         logical.TokenTypeBatch,
	}
	testMakeTokenDirectly(t, ts, batchEntry)
	resp, err = renewBatchDo(t, ts, root, "accessor-batch-key", 0, []map[string]interface{}{
		renewBatchItem(batchEntry.ID, "60s", false),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results = renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusError ||
		!strings.Contains(results[0]["reason"].(string), "batch tokens cannot be renewed") {
		t.Fatalf("batch token: %#v", results[0])
	}
}

// TestTokenStore_RenewBatch_NoPlaintextInLedger covers NFR-2: persisted
// ledgers must not contain raw token values, and successful token items echo
// the token back in the response.
func TestTokenStore_RenewBatch_NoPlaintextInLedger(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	tokenID := "plaintext-token-1"
	renewBatchCreateToken(t, c, root, tokenID, "1h", []string{"default"}, nil)

	resp, err := renewBatchDo(t, ts, root, "plaintext-key", 0, []map[string]interface{}{
		renewBatchItem(tokenID, "60s", false),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("err: %v resp: %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["client_token"] != tokenID {
		t.Fatalf("successful token renewal should echo client_token: %#v", results[0])
	}

	raw := renewBatchRawRecord(t, ts, "plaintext-key")
	if raw == nil {
		t.Fatal("expected persisted ledger")
	}
	if strings.Contains(string(raw), tokenID) {
		t.Fatalf("ledger must not contain the raw token value:\n%s", string(raw))
	}
}

// TestTokenStore_RenewBatch_ConcurrentSameKey covers TR-2.4: concurrent
// requests carrying the same idempotency key serialize, and the latecomer
// replays the first request's result without renewing again.
func TestTokenStore_RenewBatch_ConcurrentSameKey(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	renewBatchCreateToken(t, c, root, "conc-1", "1h", []string{"default"}, nil)
	renewBatchCreateToken(t, c, root, "conc-2", "1h", []string{"default"}, nil)

	items := []map[string]interface{}{
		renewBatchItem("conc-1", "90m", false),
		renewBatchItem("conc-2", "90m", false),
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]*logical.Response, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx], errs[idx] = renewBatchDo(t, ts, root, "conc-key", 0, items)
		}(i)
	}
	close(start)
	wg.Wait()

	replayCount := 0
	var expireTimes [2]map[string]time.Time
	for i := 0; i < 2; i++ {
		if errs[i] != nil || results[i].IsError() {
			t.Fatalf("call %d: err %v resp %#v", i, errs[i], results[i])
		}
		if results[i].Data["replayed"] == true {
			replayCount++
		}
		items := renewBatchResults(t, results[i])
		expireTimes[i] = map[string]time.Time{}
		for _, item := range items {
			exp, ok := item["expire_time"].(time.Time)
			if !ok || exp.IsZero() {
				t.Fatalf("call %d missing expire_time: %#v", i, item)
			}
			expireTimes[i][item["identifier_type"].(string)+fmt.Sprint(item["index"])] = exp
		}
	}
	if replayCount != 1 {
		t.Fatalf("expected exactly one replay, got %d", replayCount)
	}
	if !expireTimes[0]["token0"].Equal(expireTimes[1]["token0"]) ||
		!expireTimes[0]["token1"].Equal(expireTimes[1]["token1"]) {
		t.Fatalf("concurrent results disagree on expiration:\n%v\n%v", expireTimes[0], expireTimes[1])
	}
	if got := renewBatchLease(t, c, "conc-1"); got.LastRenewalTime.IsZero() {
		t.Fatal("expected exactly one renewal of conc-1")
	}

	keys, err := logical.CollectKeys(renewBatchCtx(), ts.renewBatchView(namespace.RootNamespace))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected a single ledger record, got %v", keys)
	}
}

// TestTokenStore_RenewBatch_BatchSizeBoundary exercises the 100 item limit.
func TestTokenStore_RenewBatch_BatchSizeBoundary(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)

	makeIDs := func(n int) []string {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("boundary-%03d", i)
			renewBatchCreateToken(t, c, root, ids[i], "1h", []string{"default"}, nil)
		}
		return ids
	}

	ids := makeIDs(renewBatchMaxItems)
	items := make([]map[string]interface{}, len(ids))
	for i, id := range ids {
		items[i] = renewBatchItem(id, "1s", false)
	}
	resp, err := renewBatchDo(t, ts, root, "boundary-ok", 0, items)
	if err != nil || resp.IsError() {
		t.Fatalf("100 items should succeed: err %v resp %#v", err, resp)
	}
	if renewBatchSummary(resp)["total"] != renewBatchMaxItems {
		t.Fatalf("bad summary: %#v", resp.Data["summary"])
	}

	items = append(items, renewBatchItem("one-more", "1s", false))
	resp, err = renewBatchDo(t, ts, root, "boundary-bad", 0, items)
	if !errors.Is(err, logical.ErrInvalidRequest) {
		t.Fatalf("101 items must be rejected: err %v resp %#v", err, resp)
	}
}

// TestTokenStore_RenewBatch_LimitReasonSurvivesAuditRecovery covers Issue
// I-1: when a capped renewal (limit_reached) loses its post-renewal audit,
// audit recovery on retry must restore the exact terminal status and reason
// rather than returning an empty reason.
func TestTokenStore_RenewBatch_LimitReasonSurvivesAuditRecovery(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)
	ctx := renewBatchCtx()

	renewBatchCreateToken(t, c, root, "recover-limit-1", "1h", []string{"default"}, map[string]interface{}{
		"explicit_max_ttl": "1h",
	})

	// Backdate the lease so the token is near its explicit max TTL.
	te, err := ts.Lookup(ctx, "recover-limit-1")
	if err != nil || te == nil {
		t.Fatalf("lookup: err %v te %v", err, te)
	}
	le, err := c.expiration.tokenLeaseEntry(ctx, te)
	if err != nil || le == nil {
		t.Fatalf("lease: err %v le %v", err, le)
	}
	le.IssueTime = time.Now().Add(-3595 * time.Second)
	le.ExpireTime = le.IssueTime.Add(time.Hour)
	c.expiration.pendingLock.Lock()
	if err := c.expiration.persistEntry(ctx, le); err != nil {
		t.Fatal(err)
	}
	c.expiration.updatePendingInternal(le)
	c.expiration.pendingLock.Unlock()

	auditor := newRenewBatchCountingAuditor()
	auditor.failOnce("recover-limit-1", renewBatchAuditPost)
	ts.renewBatchAuditor = auditor.hook()

	items := []map[string]interface{}{
		renewBatchItem("recover-limit-1", "3600s", false),
	}
	resp, err := renewBatchDo(t, ts, root, "recover-limit-key", 0, items)
	if err != nil || resp.IsError() {
		t.Fatalf("first call: err %v resp %#v", err, resp)
	}
	first := renewBatchResults(t, resp)
	if first[0]["status"] != renewBatchStatusAuditFailed {
		t.Fatalf("expected audit_failed, got %#v", first[0])
	}
	// The renewal happened before the post-audit failure, so the grant is
	// honestly recorded alongside the audit_failed status.
	if first[0]["lease_duration"].(int64) <= 0 {
		t.Fatalf("post-audit failure should still record the granted TTL: %#v", first[0])
	}

	// Retry with the same key: audit recovers, the true limit_reached result
	// must be restored including its max_ttl reason.
	resp, err = renewBatchDo(t, ts, root, "recover-limit-key", 0, items)
	if err != nil || resp.IsError() {
		t.Fatalf("retry: err %v resp %#v", err, resp)
	}
	recovered := renewBatchResults(t, resp)[0]
	if recovered["status"] != renewBatchStatusLimitReached {
		t.Fatalf("expected limit_reached after recovery, got %#v", recovered)
	}
	reason, _ := recovered["reason"].(string)
	if !strings.Contains(reason, "max_ttl") {
		t.Fatalf("cap reason must survive audit recovery, got %q", reason)
	}
	if recovered["lease_duration"] == int64(0) {
		t.Fatalf("granted TTL must be reported after recovery: %#v", recovered)
	}
}

// failingRenewBatchStorage wraps a Storage and fails every Put so the
// idempotency ledger cannot be persisted.
type failingRenewBatchStorage struct {
	logical.Storage
}

func (f *failingRenewBatchStorage) Put(_ context.Context, _ *logical.StorageEntry) error {
	return errors.New("simulated barrier write failure")
}

// TestTokenStore_RenewBatch_LedgerWriteFailure covers Issue I-2/F2: when the
// ledger cannot be persisted the request must fail rather than silently
// returning 200 (which could allow a retry to renew twice).
func TestTokenStore_RenewBatch_LedgerWriteFailure(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)
	renewBatchCreateToken(t, c, root, "ledger-fail-1", "1h", []string{"default"}, nil)

	ts.renewBatchStorageOverride = &failingRenewBatchStorage{
		Storage: ts.renewBatchView(namespace.RootNamespace),
	}
	defer func() { ts.renewBatchStorageOverride = nil }()

	resp, err := renewBatchDo(t, ts, root, "ledger-fail-key", 0, []map[string]interface{}{
		renewBatchItem("ledger-fail-1", "60s", false),
	})
	if err == nil {
		t.Fatalf("expected request to fail when the ledger cannot be written, resp=%#v", resp)
	}
}

// TestTokenStore_RenewBatch_CorruptRecord covers Issue I-2/F4: corrupt or
// truncated ledger records produce a logical error and never panic.
func TestTokenStore_RenewBatch_CorruptRecord(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)
	ctx := renewBatchCtx()
	renewBatchCreateToken(t, c, root, "corrupt-1", "1h", []string{"default"}, nil)

	items := []map[string]interface{}{
		renewBatchItem("corrupt-1", "60s", false),
	}

	// 1) Unreadable JSON: surfaced as a logical error and the derived record
	// is discarded so a fresh key keeps working.
	view := ts.renewBatchView(namespace.RootNamespace)
	corruptKey := renewBatchStorageKey("corrupt-key")
	if err := view.Put(ctx, &logical.StorageEntry{Key: corruptKey, Value: []byte("{not-json")}); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("corrupt record panicked: %v", r)
			}
		}()
		resp, err := renewBatchDo(t, ts, root, "corrupt-key", 0, items)
		if !errors.Is(err, logical.ErrInvalidRequest) || resp == nil || !resp.IsError() {
			t.Fatalf("expected logical error for corrupt record, err=%v resp=%#v", err, resp)
		}
	}()

	// 2) Truncated item array with a matching fingerprint/caller binding must
	// be rejected by the length guard instead of indexing out of range.
	input := renewBatchInput{
		idempotencyKey:   "truncated-key",
		maxTotalDuration: 0,
		items: []renewBatchInputItem{
			{token: "corrupt-1", increment: time.Minute},
			{token: "corrupt-2", increment: time.Minute},
		},
	}
	now := time.Now()
	record := &renewBatchRecord{
		Key:              renewBatchStorageKey("truncated-key"),
		CallerHash:       renewBatchHash(root),
		Fingerprint:      renewBatchFingerprint(input),
		MaxTotalDuration: 0,
		CreatedTime:      now,
		ExpireTime:       now.Add(time.Hour),
		Items: []*renewBatchItemRecord{
			{Kind: renewBatchKindToken, Status: renewBatchStatusSuccess},
		},
	}
	if err := ts.persistRenewBatchRecord(ctx, ts.renewBatchView(namespace.RootNamespace), record); err != nil {
		t.Fatal(err)
	}
	resp, err := renewBatchDo(t, ts, root, "truncated-key", 0, []map[string]interface{}{
		renewBatchItem("corrupt-1", "60s", false),
		renewBatchItem("corrupt-2", "60s", false),
	})
	if !errors.Is(err, logical.ErrInvalidRequest) || resp == nil || !resp.IsError() {
		t.Fatalf("expected logical error for truncated record, err=%v resp=%#v", err, resp)
	}
}

// TestTokenStore_RenewBatch_RootTokenWithLease covers Issue I-3: a root
// policy token that has an expiring lease renews through the batch endpoint
// like an ordinary token (only the TTL-less initial root token is classified
// as limit_reached).
func TestTokenStore_RenewBatch_RootTokenWithLease(t *testing.T) {
	c, ts, root := renewBatchTestCore(t)
	ctx := renewBatchCtx()

	rootWithLease, err := ts.rootToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth := &logical.Auth{
		ClientToken: rootWithLease.ID,
		Accessor:    rootWithLease.Accessor,
		Policies:    []string{"root"},
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Hour,
			Renewable: true,
		},
	}
	if err := c.expiration.RegisterAuth(ctx, rootWithLease, auth, ""); err != nil {
		t.Fatal(err)
	}

	// Sanity: the initial root token remains non-expiring while the leased
	// root policy token renews normally.
	resp, err := renewBatchDo(t, ts, root, "root-with-lease-key", 0, []map[string]interface{}{
		renewBatchItem(root, "600s", false),
		renewBatchItem(rootWithLease.ID, "2h", false),
	})
	if err != nil || resp.IsError() {
		t.Fatalf("err %v resp %#v", err, resp)
	}
	results := renewBatchResults(t, resp)
	if results[0]["status"] != renewBatchStatusLimitReached ||
		!strings.Contains(results[0]["reason"].(string), "root token does not expire") {
		t.Fatalf("initial root token: %#v", results[0])
	}
	if results[1]["status"] != renewBatchStatusSuccess {
		t.Fatalf("leased root policy token should renew like an ordinary token: %#v", results[1])
	}
}
