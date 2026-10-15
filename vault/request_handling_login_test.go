// Copyright IBM Corp. 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/builtin/credential/approle"
	credUserpass "github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// loginTestCredentialFactory returns a minimal credential backend whose
// login endpoint always authenticates the request and returns a renewable
// service token auth. Setting "empty_alias" in the login data makes it return
// an alias without a name, which exercises the alias/role mapping failure
// path without any test hooks.
func loginTestCredentialFactory(t *testing.T) logical.Factory {
	t.Helper()
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		login := func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
			auth := &logical.Auth{
				TokenType: logical.TokenTypeService,
				LeaseOptions: logical.LeaseOptions{
					TTL:       time.Hour,
					Renewable: true,
				},
				Alias: &logical.Alias{
					Name: "login-tester",
				},
			}
			if d.Get("empty_alias").(bool) {
				auth.Alias.Name = ""
			}
			return &logical.Response{Auth: auth}, nil
		}

		b := &framework.Backend{
			BackendType: logical.TypeCredential,
			PathsSpecial: &logical.Paths{
				Unauthenticated: []string{"login"},
			},
			Paths: []*framework.Path{
				{
					Pattern: "login$",
					Fields: map[string]*framework.FieldSchema{
						"empty_alias": {
							Type: framework.TypeBool,
						},
					},
					Operations: map[logical.Operation]framework.OperationHandler{
						logical.UpdateOperation: &framework.PathOperation{
							Callback: login,
						},
						logical.AliasLookaheadOperation: &framework.PathOperation{
							Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
								return &logical.Response{
									Auth: &logical.Auth{
										Alias: &logical.Alias{Name: "login-tester"},
									},
								}, nil
							},
						},
					},
				},
			},
		}
		require.NoError(t, b.Setup(ctx, conf))
		return b, nil
	}
}

func loginTestRequest(id string, data map[string]interface{}) *logical.Request {
	return &logical.Request{
		ID:         id,
		Path:       "auth/logintest/login",
		Operation:  logical.UpdateOperation,
		Data:       data,
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	}
}

// countServiceTokens lists the token store and returns the number of stored
// (service) tokens visible to the root token. Batch tokens are not stored and
// never appear here.
func countServiceTokens(t *testing.T, core *Core, root string) int {
	t.Helper()
	resp, err := core.HandleRequest(namespace.RootContext(nil), &logical.Request{
		Path:        "auth/token/accessors",
		Operation:   logical.ListOperation,
		ClientToken: root,
		Connection:  &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	require.NoError(t, err)
	if resp == nil || resp.Data == nil {
		return 0
	}
	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok, "unexpected token list response: %#v", resp.Data)
	return len(keys)
}

// TestHandleLoginRequest_PostAuthFailureConsistentResults verifies that the
// post-credential failure stages (entity/role mapping, mount accessor and the
// MFA challenge) all return the same permission-denied result and never create
// a token. It also verifies that a failure after token creation revokes the
// half-created (renewable) token instead of leaving it behind.
func TestHandleLoginRequest_PostAuthFailureConsistentResults(t *testing.T) {
	t.Parallel()

	core, _, root := TestCoreUnsealed(t)
	require.NoError(t, core.loadMounts(namespace.RootContext(nil)))
	core.credentialBackends["logintest"] = loginTestCredentialFactory(t)

	resp, err := core.HandleRequest(namespace.RootContext(nil), &logical.Request{
		Path:        "sys/auth/logintest",
		ClientToken: root,
		Operation:   logical.UpdateOperation,
		Data:        map[string]interface{}{"type": "logintest"},
		Connection:  &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// The mount accessor validation failure must be classified as a
	// permission (auth context) failure rather than an infrastructure error.
	mountEntry := core.router.MatchingMountEntry(namespace.RootContext(nil), "auth/logintest/login")
	require.NotNil(t, mountEntry)
	_, _, err = core.identityStore.CreateOrFetchEntity(namespace.RootContext(nil), &logical.Alias{
		Name:          "someone",
		MountAccessor: "auth_does-not-exist",
		MountType:     "logintest",
	})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
	_, _, err = core.identityStore.CreateOrFetchEntity(namespace.RootContext(nil), &logical.Alias{
		Name:          "someone",
		MountAccessor: mountEntry.Accessor,
		MountType:     "not-the-right-type",
	})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)

	// Baseline: a healthy login issues a renewable service token.
	resp, err = core.HandleRequest(namespace.RootContext(nil), loginTestRequest("baseline", nil))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Auth)
	require.NotEmpty(t, resp.Auth.ClientToken)
	require.Equal(t, logical.TokenTypeService, resp.Auth.TokenType)
	require.True(t, resp.Auth.Renewable)
	baselineTokens := countServiceTokens(t, core, root)

	cases := []struct {
		name  string
		stage string
	}{
		{"entity mapping failure", loginStageEntityMapping},
		{"mfa challenge failure", loginStageMFAChallenge},
		{"post token creation failure", loginStagePostTokenCreation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core.testLoginFailureHook = func(stage string, req *logical.Request) error {
				if stage != tc.stage {
					return nil
				}
				// Entity/mount accessor failures carry the invalid accessor
				// message, matching CreateOrFetchEntity classification.
				if stage == loginStageEntityMapping {
					return fmt.Errorf("%w: invalid mount accessor %q", logical.ErrPermissionDenied, mountEntry.Accessor+"-stale")
				}
				return logical.ErrPermissionDenied
			}
			t.Cleanup(func() { core.testLoginFailureHook = nil })

			resp, err := core.HandleRequest(namespace.RootContext(nil), loginTestRequest("failed-"+tc.stage, nil))
			require.ErrorIs(t, err, logical.ErrPermissionDenied)
			require.Nil(t, resp, "no response/token must be returned for a failed login")

			// The failed attempt must not leave behind a (renewable) token.
			require.Equal(t, baselineTokens, countServiceTokens(t, core, root),
				"failed login at stage %q changed the service token count", tc.stage)
		})
	}

	// The empty alias (role/identity mapping) failure is reachable without
	// hooks and must produce the same consistent result.
	resp, err = core.HandleRequest(namespace.RootContext(nil), loginTestRequest("failed-empty-alias",
		map[string]interface{}{"empty_alias": true}))
	require.ErrorIs(t, err, logical.ErrPermissionDenied)
	require.Nil(t, resp)
	require.Equal(t, baselineTokens, countServiceTokens(t, core, root))

	// After failures, healthy logins still succeed and issue tokens.
	core.testLoginFailureHook = nil
	resp, err = core.HandleRequest(namespace.RootContext(nil), loginTestRequest("after-recovery", nil))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Auth.ClientToken)
	require.Equal(t, baselineTokens+1, countServiceTokens(t, core, root))
}

// loginBackendSet is the set of builtin auth methods exercised by the real
// backend login failure/concurrency tests.
type loginBackendSet struct {
	roleID   string
	secretID string
	username string
	password string
}

func setupRealLoginBackends(t *testing.T, core *Core, root string) loginBackendSet {
	t.Helper()
	ctx := namespace.RootContext(nil)
	core.credentialBackends["approle"] = approle.Factory
	core.credentialBackends["userpass"] = credUserpass.Factory

	enable := func(path, typ string) {
		resp, err := core.HandleRequest(ctx, &logical.Request{
			Path:        "sys/auth/" + path,
			ClientToken: root,
			Operation:   logical.UpdateOperation,
			Data: map[string]interface{}{
				"type":              typ,
				"lockout_threshold": 0,
			},
			Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
		})
		require.NoError(t, err)
		require.Nil(t, resp)
	}
	enable("approle", "approle")
	enable("userpass", "userpass")

	// AppRole role + secret id.
	resp, err := core.HandleRequest(ctx, &logical.Request{
		Path:        "auth/approle/role/test-role",
		ClientToken: root,
		Operation:   logical.UpdateOperation,
		Data: map[string]interface{}{
			"token_ttl":     "1h",
			"token_max_ttl": "4h",
		},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = core.HandleRequest(ctx, &logical.Request{
		Path:        "auth/approle/role/test-role/role-id",
		ClientToken: root,
		Operation:   logical.ReadOperation,
		Connection:  &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	require.NoError(t, err)
	roleID, ok := resp.Data["role_id"].(string)
	require.True(t, ok)

	resp, err = core.HandleRequest(ctx, &logical.Request{
		Path:        "auth/approle/role/test-role/secret-id",
		ClientToken: root,
		Operation:   logical.UpdateOperation,
		Connection:  &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	require.NoError(t, err)
	secretID, ok := resp.Data["secret_id"].(string)
	require.True(t, ok)

	// Userpass user.
	resp, err = core.HandleRequest(ctx, &logical.Request{
		Path:        "auth/userpass/users/peasant",
		ClientToken: root,
		Operation:   logical.UpdateOperation,
		Data: map[string]interface{}{
			"password":  "p4ssw0rd",
			"token_ttl": "1h",
		},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	return loginBackendSet{
		roleID:   roleID,
		secretID: secretID,
		username: "peasant",
		password: "p4ssw0rd",
	}
}

func approleLoginRequest(id string, set loginBackendSet) *logical.Request {
	return &logical.Request{
		ID:        id,
		Path:      "auth/approle/login",
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"role_id":   set.roleID,
			"secret_id": set.secretID,
		},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	}
}

func userpassLoginRequest(id string, set loginBackendSet) *logical.Request {
	return &logical.Request{
		ID:        id,
		Path:      "auth/userpass/login/" + set.username,
		Operation: logical.UpdateOperation,
		Data: map[string]interface{}{
			"password": set.password,
		},
		Connection: &logical.Connection{RemoteAddr: "127.0.0.1"},
	}
}

// TestHandleLoginRequest_RealBackends_PostAuthFailures exercises the same
// failure contract through the builtin approle and userpass auth backends:
// every post-credential failure returns permission denied and must not leave
// behind a renewable service token.
func TestHandleLoginRequest_RealBackends_PostAuthFailures(t *testing.T) {
	// Failed credential handling (lockout) is out of scope for this test;
	// all login attempts here use valid credentials.
	t.Setenv("VAULT_DISABLE_USER_LOCKOUT", "true")

	core, _, root := TestCoreUnsealed(t)
	require.NoError(t, core.loadMounts(namespace.RootContext(nil)))
	set := setupRealLoginBackends(t, core, root)
	ctx := namespace.RootContext(nil)

	builders := map[string]func(string) *logical.Request{
		"approle":  func(id string) *logical.Request { return approleLoginRequest(id, set) },
		"userpass": func(id string) *logical.Request { return userpassLoginRequest(id, set) },
	}

	for backend, build := range builders {
		t.Run(backend, func(t *testing.T) {
			// Sanity: valid login succeeds with a renewable service token.
			resp, err := core.HandleRequest(ctx, build("sanity-"+backend))
			require.NoError(t, err)
			require.NotNil(t, resp.Auth)
			require.NotEmpty(t, resp.Auth.ClientToken)
			require.True(t, resp.Auth.Renewable)
			baseline := countServiceTokens(t, core, root)

			for _, stage := range []string{
				loginStageEntityMapping,
				loginStageMFAChallenge,
				loginStagePostTokenCreation,
			} {
				stage := stage
				t.Run(stage, func(t *testing.T) {
					core.testLoginFailureHook = func(s string, req *logical.Request) error {
						if s != stage {
							return nil
						}
						if s == loginStageEntityMapping {
							return fmt.Errorf("%w: invalid mount accessor %q", logical.ErrPermissionDenied, "auth_stale")
						}
						return logical.ErrPermissionDenied
					}
					t.Cleanup(func() { core.testLoginFailureHook = nil })

					resp, err := core.HandleRequest(ctx, build("fail-"+backend+"-"+stage))
					require.ErrorIs(t, err, logical.ErrPermissionDenied)
					require.Nil(t, resp)
					require.Equal(t, baseline, countServiceTokens(t, core, root),
						"failed %s login at %q left a token behind", backend, stage)
				})
			}

			// Successful logins still work and each produce exactly one token.
			core.testLoginFailureHook = nil
			resp, err = core.HandleRequest(ctx, build("healthy-"+backend))
			require.NoError(t, err)
			require.NotEmpty(t, resp.Auth.ClientToken)
			require.Equal(t, baseline+1, countServiceTokens(t, core, root))
		})
	}
}

// TestHandleLoginRequest_ConcurrentLogins hammers the login entry point with
// concurrent approle and userpass logins, a rotating subset of which fail at
// the entity mapping, MFA challenge or post-token-creation stages. It asserts
// that exactly the successful attempts produce service tokens and that no
// failed attempt leaves a renewable half-created token behind.
func TestHandleLoginRequest_ConcurrentLogins(t *testing.T) {
	t.Setenv("VAULT_DISABLE_USER_LOCKOUT", "true")

	core, _, root := TestCoreUnsealed(t)
	require.NoError(t, core.loadMounts(namespace.RootContext(nil)))
	set := setupRealLoginBackends(t, core, root)
	ctx := namespace.RootContext(nil)

	const total = 40 // 20 approle + 20 userpass

	var counter atomic.Int64
	modes := sync.Map{} // request ID -> failure mode
	core.testLoginFailureHook = func(stage string, req *logical.Request) error {
		v, _ := modes.LoadOrStore(req.ID, counter.Add(1)%4)
		switch v.(int64) {
		case 1:
			if stage == loginStageEntityMapping {
				return fmt.Errorf("%w: invalid mount accessor %q", logical.ErrPermissionDenied, "auth_stale")
			}
		case 2:
			if stage == loginStageMFAChallenge {
				return logical.ErrPermissionDenied
			}
		case 3:
			if stage == loginStagePostTokenCreation {
				return logical.ErrPermissionDenied
			}
		}
		return nil
	}
	t.Cleanup(func() { core.testLoginFailureHook = nil })

	before := countServiceTokens(t, core, root)

	var wg sync.WaitGroup
	var successes atomic.Int64
	var failures atomic.Int64
	var unexpected atomic.Int64
	start := make(chan struct{})

	for i := 0; i < total; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			var req *logical.Request
			if i%2 == 0 {
				req = approleLoginRequest(fmt.Sprintf("approle-%d", i), set)
			} else {
				req = userpassLoginRequest(fmt.Sprintf("userpass-%d", i), set)
			}
			<-start
			resp, err := core.HandleRequest(ctx, req)
			switch {
			case err == nil:
				if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
					unexpected.Add(1)
					return
				}
				successes.Add(1)
			case errors.Is(err, logical.ErrPermissionDenied):
				if resp != nil && resp.Auth != nil && resp.Auth.ClientToken != "" {
					unexpected.Add(1)
				}
				failures.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	require.Zero(t, unexpected.Load(), "all logins must either succeed or fail with permission denied")
	require.Equal(t, int64(total), successes.Load()+failures.Load())
	require.Greater(t, successes.Load(), int64(0))
	require.Greater(t, failures.Load(), int64(0))

	// Exactly the successful logins may have produced a service token.
	require.Equal(t, before+int(successes.Load()), countServiceTokens(t, core, root),
		"failed concurrent login attempts left tokens behind")

	// The core remains healthy and a follow-up login succeeds.
	core.testLoginFailureHook = nil
	resp, err := core.HandleRequest(ctx, approleLoginRequest("final-healthy", set))
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	require.NotEmpty(t, resp.Auth.ClientToken)
	require.Equal(t, before+int(successes.Load())+1, countServiceTokens(t, core, root))
}
