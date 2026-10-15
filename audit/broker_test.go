// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/testhelpers/corehelpers"
	nshelper "github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// testAuditBackend will create an audit.Backend (which expects to use the eventlogger).
// NOTE: this will create the backend, it does not care whether Enterprise only options are in place.
func testAuditBackend(t *testing.T, path string, config map[string]string) Backend {
	t.Helper()

	headersCfg := &HeadersConfig{
		headerSettings: make(map[string]*headerSettings),
		view:           nil,
	}

	view := &logical.InmemStorage{}
	se := &logical.StorageEntry{Key: "salt", Value: []byte("juan")}
	err := view.Put(context.Background(), se)
	require.NoError(t, err)

	cfg := &BackendConfig{
		SaltView: view,
		SaltConfig: &salt.Config{
			HMAC:     sha256.New,
			HMACType: "hmac-sha256",
		},
		Logger:    corehelpers.NewTestLogger(t),
		Config:    config,
		MountPath: path,
	}

	be, err := NewSyslogBackend(cfg, headersCfg)
	require.NoError(t, err)
	require.NotNil(t, be)

	return be
}

// TestAuditBroker_Deregister_Multiple ensures that we can call deregister multiple
// times without issue if is no matching backend registered.
func TestAuditBroker_Deregister_Multiple(t *testing.T) {
	t.Parallel()

	l := corehelpers.NewTestLogger(t)
	a, err := NewBroker(l)
	require.NoError(t, err)
	require.NotNil(t, a)

	err = a.Deregister(context.Background(), "foo")
	require.NoError(t, err)

	err = a.Deregister(context.Background(), "foo2")
	require.NoError(t, err)
}

// TestAuditBroker_Register_MultipleFails checks for failure when we try to
// re-register an audit backend.
func TestAuditBroker_Register_MultipleFails(t *testing.T) {
	t.Parallel()

	l := corehelpers.NewTestLogger(t)
	a, err := NewBroker(l)
	require.NoError(t, err)
	require.NotNil(t, a)

	path := "b2-no-filter"
	noFilterBackend := testAuditBackend(t, path, map[string]string{})

	err = a.Register(noFilterBackend, false)
	require.NoError(t, err)

	err = a.Register(noFilterBackend, false)
	require.Error(t, err)
	require.EqualError(t, err, "backend already registered 'b2-no-filter': invalid configuration")
}

// BenchmarkAuditBroker_File_Request_DevNull Attempts to register a single `file`
// audit device on the broker, which points at /dev/null.
// It will then attempt to benchmark how long it takes Vault to complete logging
// a request, this really only shows us how Vault can handle lots of calls to the
// broker to trigger the eventlogger pipelines that audit devices are configured as.
// Since we aren't writing anything to file or doing any I/O.
// This test used to live in the file package for the file backend, but once the
// move to eventlogger was complete, there wasn't a way to create a file backend
// and manually just write to the underlying file itself, the old code used to do
// formatting and writing all together, but we've split this up with eventlogger
// with different nodes in a pipeline (think 1 audit device:1 pipeline) each
// handling a responsibility, for example:
// filter nodes filter events, so you can select which ones make it to your audit log
// formatter nodes format the events (to JSON/JSONX and perform HMACing etc)
// sink nodes handle sending the formatted data to a file, syslog or socket.
func BenchmarkAuditBroker_File_Request_DevNull(b *testing.B) {
	backendConfig := &BackendConfig{
		Config: map[string]string{
			"path": "/dev/null",
		},
		MountPath:  "test",
		SaltConfig: &salt.Config{},
		SaltView:   &logical.InmemStorage{},
		Logger:     hclog.NewNullLogger(),
	}

	sink, err := NewFileBackend(backendConfig, nil)
	require.NoError(b, err)

	broker, err := NewBroker(nil)
	require.NoError(b, err)

	err = broker.Register(sink, false)
	require.NoError(b, err)

	in := &logical.LogInput{
		Auth: &logical.Auth{
			ClientToken:     "foo",
			Accessor:        "bar",
			EntityID:        "foobarentity",
			DisplayName:     "testtoken",
			NoDefaultPolicy: true,
			Policies:        []string{"root"},
			TokenType:       logical.TokenTypeService,
		},
		Request: &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "/foo",
			Connection: &logical.Connection{
				RemoteAddr: "127.0.0.1",
			},
			WrapInfo: &logical.RequestWrapInfo{
				TTL: 60 * time.Second,
			},
			Headers: map[string][]string{
				"foo": {"bar"},
			},
		},
	}

	ctx := nshelper.RootContext(context.Background())
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := broker.LogRequest(ctx, in); err != nil {
				panic(err)
			}
		}
	})
}

// TestBroker_getAuditContext_NoNamespace checks that we get the right error when
// trying to get an audit context with no namespace.
func TestBroker_getAuditContext_NoNamespace(t *testing.T) {
	t.Parallel()

	_, _, err := getAuditContext(context.Background())
	require.Error(t, err)
	require.EqualError(t, err, "namespace missing from context: no namespace")
}

// orderedEntry pairs an entry with its position in a device's output.
type orderedEntry struct {
	entry *entry
	index int
}

// deviceRecords is the parsed audit record set captured from one device.
type deviceRecords struct {
	requestEntries  map[string]orderedEntry
	responseEntries map[string]orderedEntry
	// order records the raw append order of every formatted event.
	order []orderedEntry
}

// parseDeviceRecords decodes all formatted records produced by one noop
// device, keying request/response entries by request ID.
func parseDeviceRecords(t *testing.T, n *NoopAudit) deviceRecords {
	t.Helper()

	parsed := deviceRecords{
		requestEntries:  make(map[string]orderedEntry),
		responseEntries: make(map[string]orderedEntry),
	}
	n.l.RLock()
	records := make([][]byte, len(n.records))
	copy(records, n.records)
	n.l.RUnlock()
	for i, b := range records {
		e := new(entry)
		require.NoError(t, json.Unmarshal(b, e))
		require.NotEmpty(t, e.Request.ID)
		oe := orderedEntry{entry: e, index: i}
		parsed.order = append(parsed.order, oe)
		switch e.Type {
		case RequestType.String():
			_, present := parsed.requestEntries[e.Request.ID]
			require.False(t, present, "duplicate request entry for id %q", e.Request.ID)
			parsed.requestEntries[e.Request.ID] = oe
		case ResponseType.String():
			_, present := parsed.responseEntries[e.Request.ID]
			require.False(t, present, "duplicate response entry for id %q", e.Request.ID)
			parsed.responseEntries[e.Request.ID] = oe
		default:
			t.Fatalf("unexpected audit entry type %q", e.Type)
		}
	}
	return parsed
}

// TestAuditBroker_MultipleDevices_Concurrent ensures each mounted device
// receives a complete, de-duplicated, correctly ordered request/response
// pair per request under concurrency, with identical hashes across devices,
// and that one failing device neither loses other devices' events nor
// changes business results, while all devices failing makes the call fail.
func TestAuditBroker_MultipleDevices_Concurrent(t *testing.T) {
	t.Parallel()

	ctx := nshelper.RootContext(context.Background())
	const numRequests = 50

	setup := func(t *testing.T) (*Broker, []*NoopAudit) {
		t.Helper()
		b, err := NewBroker(corehelpers.NewTestLogger(t))
		require.NoError(t, err)
		a1 := TestNoopAudit(t, "one", nil)
		a2 := TestNoopAudit(t, "two", nil)
		require.NoError(t, b.Register(a1, false))
		require.NoError(t, b.Register(a2, false))
		return b, []*NoopAudit{a1, a2}
	}

	// All devices succeed: complete, ordered, identical content.
	t.Run("all-devices-succeed", func(t *testing.T) {
		t.Parallel()
		b, devices := setup(t)

		var wg sync.WaitGroup
		errCh := make(chan error, numRequests)
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			path := fmt.Sprintf("secret/%d", i)
			reqID := uuid.NewString()
			go func() {
				defer wg.Done()
				in := &logical.LogInput{
					Request: &logical.Request{
						ID:        reqID,
						Operation: logical.UpdateOperation,
						Path:      path,
						Connection: &logical.Connection{
							RemoteAddr: "127.0.0.1",
						},
						Data: map[string]interface{}{
							"secret": "super-secret",
							"keep":   "kept-readable",
						},
					},
					NonHMACReqDataKeys: []string{"keep"},
				}
				if err := b.LogRequest(ctx, in); err != nil {
					errCh <- err
					return
				}
				in.Response = &logical.Response{
					Data: map[string]interface{}{
						"secret": "super-secret-resp",
						"keep":   "kept-readable-resp",
					},
				}
				in.NonHMACRespDataKeys = []string{"keep"}
				if err := b.LogResponse(ctx, in); err != nil {
					errCh <- err
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}

		all := make([]deviceRecords, len(devices))
		for i, a := range devices {
			all[i] = parseDeviceRecords(t, a)
			require.Len(t, all[i].requestEntries, numRequests)
			require.Len(t, all[i].responseEntries, numRequests)
		}

		// The same salt is shared by every device (known in-memory "foo"
		// salt), so the same input must produce the same digest across
		// devices and both event sides.
		firstReqID := all[0].requestEntriesFirstID(t)
		secretReqHMAC := all[0].requestEntries[firstReqID].entry.Request.Data["secret"].(string)
		secretRespHMAC := all[0].responseEntries[firstReqID].entry.Response.Data["secret"].(string)
		require.Contains(t, secretReqHMAC, "hmac-sha256:")
		require.Contains(t, secretRespHMAC, "hmac-sha256:")

		for _, records := range all {
			for id, req := range records.requestEntries {
				resp, ok := records.responseEntries[id]
				require.True(t, ok, "missing response entry for request id %q", id)
				reqEntry := req.entry
				respEntry := resp.entry

				// The request event must precede its response event in
				// this device's serialized output, even while different
				// requests interleave with one another.
				require.Greaterf(t, resp.index, req.index,
					"response event for request id %q (path %q) was recorded before its request event (resp=%d req=%d)",
					id, reqEntry.Request.Path, resp.index, req.index)

				require.Equal(t, secretReqHMAC, reqEntry.Request.Data["secret"])
				require.Equal(t, "kept-readable", reqEntry.Request.Data["keep"])
				require.Equal(t, secretRespHMAC, respEntry.Response.Data["secret"])
				require.Equal(t, "kept-readable-resp", respEntry.Response.Data["keep"])

				// Identical masking across devices and event sides.
				require.Equal(t, secretReqHMAC, reqEntry.Request.Data["secret"])
				require.Equal(t, secretRespHMAC, respEntry.Response.Data["secret"])

				require.NotContains(t, fmt.Sprintf("%#v", reqEntry), "super-secret")
				require.NotContains(t, fmt.Sprintf("%#v", respEntry), "super-secret-resp")
			}

			// Entries were appended in strict pairs; nothing else.
			require.Len(t, records.order, 2*numRequests)
		}

		// Identical record sets across devices (no cross-device loss).
		// Compare canonical contents keyed by request ID; device-local
		// append indices and entry pointers must not be compared.
		canonicalize := func(records deviceRecords) map[string]map[string]string {
			out := make(map[string]map[string]string, 2)
			out["request"] = make(map[string]string, len(records.requestEntries))
			out["response"] = make(map[string]string, len(records.responseEntries))
			for id, oe := range records.requestEntries {
				b, err := json.Marshal(oe.entry)
				require.NoError(t, err)
				out["request"][id] = string(b)
			}
			for id, oe := range records.responseEntries {
				b, err := json.Marshal(oe.entry)
				require.NoError(t, err)
				out["response"][id] = string(b)
			}
			return out
		}
		require.Equal(t, canonicalize(all[0]), canonicalize(all[1]))

		// Both devices saw the events in their own append order: entry
		// counts match and every index holds an event (no cross-device
		// duplication), which together with the per-pair index checks
		// above covers completeness and ordering.
		require.Len(t, all[0].order, len(all[1].order))
	})

	// One failing device: business still succeeds and the healthy device
	// receives both events; the failing device's output is unaffected.
	t.Run("one-device-fails", func(t *testing.T) {
		t.Parallel()
		b, devices := setup(t)
		devices[0].ReqErr = fmt.Errorf("device one cannot write")
		devices[0].RespErr = devices[0].ReqErr

		in := &logical.LogInput{
			Request: &logical.Request{
				ID:        uuid.NewString(),
				Operation: logical.UpdateOperation,
				Path:      "secret/single",
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
				Data: map[string]interface{}{"secret": "super-secret"},
			},
		}
		require.NoError(t, b.LogRequest(ctx, in))

		in.Response = &logical.Response{Data: map[string]interface{}{"secret": "super-secret-resp"}}
		require.NoError(t, b.LogResponse(ctx, in))

		// The failing device produced no records; the healthy one got
		// exactly one request/response pair.
		require.Empty(t, devices[0].records)
		healthy := parseDeviceRecords(t, devices[1])
		require.Len(t, healthy.requestEntries, 1)
		require.Len(t, healthy.responseEntries, 1)
		require.Len(t, healthy.order, 2)
	})

	// All devices failing: the audit call returns an error rather than
	// silently succeeding.
	t.Run("all-devices-fail", func(t *testing.T) {
		t.Parallel()
		b, devices := setup(t)
		devices[0].ReqErr = fmt.Errorf("boom")
		devices[1].ReqErr = fmt.Errorf("boom2")

		in := &logical.LogInput{
			Request: &logical.Request{
				ID:        uuid.NewString(),
				Operation: logical.UpdateOperation,
				Path:      "secret/single",
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			},
		}
		err := b.LogRequest(ctx, in)
		require.Error(t, err)
	})
}

// requestEntriesFirstID returns any map key from the set, deterministically.
func (r deviceRecords) requestEntriesFirstID(t *testing.T) string {
	t.Helper()
	for id := range r.requestEntries {
		return id
	}
	t.Fatal("no request entries")
	return ""
}

// TestBroker_getAuditContext checks that we get a context back which isn't linked
// to the original context, and contains our namespace.
func TestBroker_getAuditContext(t *testing.T) {
	t.Parallel()

	// context with namespace
	ns := &nshelper.Namespace{
		ID:   "foo",
		Path: "foo/",
	}

	// Create a context with a namespace.
	originalContext, originalCancel := context.WithCancel(context.Background())
	t.Cleanup(originalCancel)
	nsContext := nshelper.ContextWithNamespace(originalContext, ns)

	// Get the audit context
	auditContext, auditCancel, err := getAuditContext(nsContext)
	t.Cleanup(auditCancel)

	require.NoError(t, err)
	require.NotNil(t, auditContext)
	require.NotNil(t, auditCancel)

	// Ensure the namespace is there too.
	val, err := nshelper.FromContext(auditContext)
	require.NoError(t, err)
	require.Equal(t, ns, val)

	// Now cancel the original context and ensure it is done but audit context isn't.
	originalCancel()
	require.NotNil(t, originalContext.Err())
	require.Nil(t, auditContext.Err())

	// Now cancel the audit context and ensure that it is done.
	auditCancel()
	require.NotNil(t, auditContext.Err())
}
