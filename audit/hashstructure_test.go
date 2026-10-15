// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	nshelper "github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/helper/wrapping"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/require"
)

func TestCopy_auth(t *testing.T) {
	// Make a non-pointer one so that it can't be modified directly
	expected := logical.Auth{
		LeaseOptions: logical.LeaseOptions{
			TTL: 1 * time.Hour,
		},

		ClientToken: "foo",
	}
	auth := expected

	// Copy it
	dup, err := copystructure.Copy(&auth)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check equality
	auth2 := dup.(*logical.Auth)
	if !reflect.DeepEqual(*auth2, expected) {
		t.Fatalf("bad:\n\n%#v\n\n%#v", *auth2, expected)
	}
}

func TestCopy_request(t *testing.T) {
	// Make a non-pointer one so that it can't be modified directly
	expected := logical.Request{
		Data: map[string]interface{}{
			"foo": "bar",
		},
		WrapInfo: &logical.RequestWrapInfo{
			TTL: 60 * time.Second,
		},
	}
	arg := expected

	// Copy it
	dup, err := copystructure.Copy(&arg)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check equality
	arg2 := dup.(*logical.Request)
	if !reflect.DeepEqual(*arg2, expected) {
		t.Fatalf("bad:\n\n%#v\n\n%#v", *arg2, expected)
	}
}

func TestCopy_response(t *testing.T) {
	// Make a non-pointer one so that it can't be modified directly
	expected := logical.Response{
		Data: map[string]interface{}{
			"foo": "bar",
		},
		WrapInfo: &wrapping.ResponseWrapInfo{
			TTL:             60,
			Token:           "foo",
			CreationTime:    time.Now(),
			WrappedAccessor: "abcd1234",
		},
	}
	arg := expected

	// Copy it
	dup, err := copystructure.Copy(&arg)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check equality
	arg2 := dup.(*logical.Response)
	if !reflect.DeepEqual(*arg2, expected) {
		t.Fatalf("bad:\n\n%#v\n\n%#v", *arg2, expected)
	}
}

// testSalter is a structure that implements the Salter interface in a trivial
// manner.
type testSalter struct{}

// Salt returns a salt.Salt pointer based on dummy data stored in an in-memory
// storage instance.
func (*testSalter) Salt(ctx context.Context) (*salt.Salt, error) {
	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	if err != nil {
		return nil, err
	}

	return salt.NewSalt(context.Background(), inmemStorage, &salt.Config{
		HMAC:     sha256.New,
		HMACType: "hmac-sha256",
	})
}

func TestHashString(t *testing.T) {
	salter := &testSalter{}

	out, err := hashString(context.Background(), salter, "foo")
	if err != nil {
		t.Fatalf("Error instantiating salt: %s", err)
	}
	if out != "hmac-sha256:08ba357e274f528065766c770a639abf6809b39ccfd37c2a3157c7f51954da0a" {
		t.Fatalf("err: hashString output did not match expected")
	}
}

func TestHashAuth(t *testing.T) {
	cases := map[string]struct {
		Input        *logical.Auth
		Output       *auth
		HMACAccessor bool
	}{
		"no-accessor-hmac": {
			&logical.Auth{
				ClientToken: "foo",
				Accessor:    "very-accessible",
				LeaseOptions: logical.LeaseOptions{
					TTL: 1 * time.Hour,
				},
				TokenType: logical.TokenTypeService,
			},
			&auth{
				ClientToken:   "hmac-sha256:08ba357e274f528065766c770a639abf6809b39ccfd37c2a3157c7f51954da0a",
				Accessor:      "very-accessible",
				TokenTTL:      3600,
				TokenType:     "service",
				RemainingUses: 5,
			},
			false,
		},
		"accessor-hmac": {
			&logical.Auth{
				Accessor:    "very-accessible",
				ClientToken: "foo",
				LeaseOptions: logical.LeaseOptions{
					TTL: 1 * time.Hour,
				},
				TokenType: logical.TokenTypeBatch,
			},
			&auth{
				ClientToken:   "hmac-sha256:08ba357e274f528065766c770a639abf6809b39ccfd37c2a3157c7f51954da0a",
				Accessor:      "hmac-sha256:5d6d7c8da5b699ace193ea453bbf77082a8aaca42a474436509487d646a7c0af",
				TokenTTL:      3600,
				TokenType:     "batch",
				RemainingUses: 5,
			},
			true,
		},
	}

	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	require.NoError(t, err)
	salter := &testSalter{}
	for _, tc := range cases {
		auditAuth, err := newAuth(tc.Input, 5)
		require.NoError(t, err)
		err = hashAuth(context.Background(), salter, auditAuth, tc.HMACAccessor)
		require.NoError(t, err)
		require.Equal(t, tc.Output, auditAuth)
	}
}

type testOptMarshaler struct {
	S string
	I int
}

func (o *testOptMarshaler) MarshalJSONWithOptions(options *logical.MarshalOptions) ([]byte, error) {
	return json.Marshal(&testOptMarshaler{S: options.ValueHasher(o.S), I: o.I})
}

var _ logical.OptMarshaler = &testOptMarshaler{}

func TestHashRequest(t *testing.T) {
	cases := []struct {
		Input           *logical.Request
		Output          *request
		NonHMACDataKeys []string
		HMACAccessor    bool
	}{
		{
			&logical.Request{
				Data: map[string]interface{}{
					"foo":              "bar",
					"baz":              "foobar",
					"private_key_type": certutil.PrivateKeyType("rsa"),
					"om":               &testOptMarshaler{S: "bar", I: 1},
				},
			},
			&request{
				Data: map[string]interface{}{
					"foo":              "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
					"baz":              "foobar",
					"private_key_type": "hmac-sha256:995230dca56fffd310ff591aa404aab52b2abb41703c787cfa829eceb4595bf1",
					"om":               json.RawMessage(`{"S":"hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317","I":1}`),
				},
				Namespace: &namespace{
					ID:   nshelper.RootNamespace.ID,
					Path: nshelper.RootNamespace.Path,
				},
			},
			[]string{"baz"},
			false,
		},
	}

	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	require.NoError(t, err)
	salter := &testSalter{}
	for _, tc := range cases {
		auditReq, err := newRequest(tc.Input, nshelper.RootNamespace)
		require.NoError(t, err)
		err = hashRequest(context.Background(), salter, auditReq, tc.HMACAccessor, tc.NonHMACDataKeys)
		require.NoError(t, err)
		require.Equal(t, tc.Output, auditReq)
	}
}

func TestHashResponse(t *testing.T) {
	now := time.Now()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"foo": "bar",
			"baz": "foobar",
			// Responses can contain time values, so test that with a known fixed value.
			"bar": now,
			"om":  &testOptMarshaler{S: "bar", I: 1},
		},
		WrapInfo: &wrapping.ResponseWrapInfo{
			TTL:             1 * time.Minute,
			Token:           "bar",
			Accessor:        "flimflam",
			CreationTime:    now,
			WrappedAccessor: "bar",
		},
		Auth: &logical.Auth{
			ClientToken: "hvs.QWERTY-T1q5lEjIWux1Tjx-VGqAYJdd4FZtbp1wpD5Ym9pGh4KHGh2cy5TSjRndGoxaU44NzNscm5MSlRLQXZ0ZGg",
			Accessor:    "ABClk9ZNLGOCuTrOEIAooJG3",
			TokenType:   logical.TokenTypeService,
		},
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL:       3,
				MaxTTL:    5,
				Renewable: false,
				Increment: 1,
				IssueTime: now,
			},
			InternalData: map[string]any{
				"foo": "bar",
			},
			LeaseID: "abc",
		},
	}

	req := &logical.Request{MountPoint: "/foo/bar"}
	req.SetMountClass("kv")
	req.SetMountIsExternalPlugin(true)
	req.SetMountRunningVersion("123")
	req.SetMountRunningSha256("256-256!")

	nonHMACDataKeys := []string{"baz"}

	expected := &response{
		Auth: &auth{
			Accessor:    "hmac-sha256:253184715b2d5a6c3a2fc7afe0d2294085f5e886a1275ca735646a6f23be2587",
			ClientToken: "hmac-sha256:2ce541100a8bcd687e8ec7712c8bb4c975a8d8599c02d98945e63ecd413bf0f3",
			TokenType:   "service",
		},
		Data: map[string]interface{}{
			"foo": "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
			"baz": "foobar",
			"bar": now.Format(time.RFC3339Nano),
			"om":  json.RawMessage(`{"S":"hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317","I":1}`),
		},
		WrapInfo: &responseWrapInfo{
			TTL:             60,
			Token:           "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
			Accessor:        "hmac-sha256:7c9c6fe666d0af73b3ebcfbfabe6885015558213208e6635ba104047b22f6390",
			CreationTime:    now.UTC().Format(time.RFC3339Nano),
			WrappedAccessor: "hmac-sha256:f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317",
		},
		MountClass:            "kv",
		MountIsExternalPlugin: true,
		MountPoint:            "/foo/bar",
		MountRunningVersion:   "123",
		MountRunningSha256:    "256-256!",
		Secret: &secret{
			LeaseID: "abc",
		},
	}

	inmemStorage := &logical.InmemStorage{}
	err := inmemStorage.Put(context.Background(), &logical.StorageEntry{
		Key:   "salt",
		Value: []byte("foo"),
	})
	require.NoError(t, err)
	salter := &testSalter{}
	auditResp, err := newResponse(resp, req, false)
	require.NoError(t, err)
	err = hashResponse(context.Background(), salter, auditResp, true, nonHMACDataKeys)
	require.NoError(t, err)
	require.Equal(t, expected, auditResp)
}

func TestHashWalker(t *testing.T) {
	replaceText := "foo"

	cases := []struct {
		Input  map[string]interface{}
		Output map[string]interface{}
	}{
		{
			map[string]interface{}{
				"hello": "foo",
			},
			map[string]interface{}{
				"hello": replaceText,
			},
		},

		{
			map[string]interface{}{
				"hello": []interface{}{"world"},
			},
			map[string]interface{}{
				"hello": []interface{}{replaceText},
			},
		},
	}

	for _, tc := range cases {
		err := hashStructure(tc.Input, func(string) string {
			return replaceText
		}, nil)
		if err != nil {
			t.Fatalf("err: %s\n\n%#v", err, tc.Input)
		}
		if !reflect.DeepEqual(tc.Input, tc.Output) {
			t.Fatalf("bad:\n\n%#v\n\n%#v", tc.Input, tc.Output)
		}
	}
}

func TestHashWalker_TimeStructs(t *testing.T) {
	replaceText := "bar"

	now := time.Now()
	cases := []struct {
		Input  map[string]interface{}
		Output map[string]interface{}
	}{
		// Should not touch map keys of type time.Time.
		{
			map[string]interface{}{
				"hello": map[time.Time]struct{}{
					now: {},
				},
			},
			map[string]interface{}{
				"hello": map[time.Time]struct{}{
					now: {},
				},
			},
		},
		// Should handle map values of type time.Time.
		{
			map[string]interface{}{
				"hello": now,
			},
			map[string]interface{}{
				"hello": now.Format(time.RFC3339Nano),
			},
		},
		// Should handle slice values of type time.Time.
		{
			map[string]interface{}{
				"hello": []interface{}{"foo", now, "foo2"},
			},
			map[string]interface{}{
				"hello": []interface{}{"foobar", now.Format(time.RFC3339Nano), "foo2bar"},
			},
		},
	}

	for _, tc := range cases {
		err := hashStructure(tc.Input, func(s string) string {
			return s + replaceText
		}, nil)
		if err != nil {
			t.Fatalf("err: %v\n\n%#v", err, tc.Input)
		}
		if !reflect.DeepEqual(tc.Input, tc.Output) {
			t.Fatalf("bad:\n\n%#v\n\n%#v", tc.Input, tc.Output)
		}
	}
}

// TestCopy_request_EnterpriseTokenFields verifies that copystructure.Copy
// correctly deep-copies a logical.Request that carries enterprise token fields,
// including JwtAuthorizationDetails which is []map[string]any and
// would silently lose data under a shallow copy.
func TestCopy_request_EnterpriseTokenFields(t *testing.T) {
	expected := logical.Request{
		Data: map[string]interface{}{
			"foo": "bar",
		},
		JwtUniqueId:         "test-token-abc",
		JwtIssuer:           "https://issuer.example.com",
		JwtTransactionClaim: "txn-copy-1",
		JwtAudienceClaim:    []string{"vault", "api"},
		JwtAuthorizationDetails: []logical.AuthorizationDetail{
			{
				"type":            "vault:path_access",
				"path_constraint": "secret/data/users/alice",
				"action":          "read",
			},
			{
				"type":            "vault:path_access",
				"path_constraint": "secret/data/config/general",
				"action":          "update",
			},
		},
	}
	arg := expected

	dup, err := copystructure.Copy(&arg)
	require.NoError(t, err)

	arg2 := dup.(*logical.Request)
	require.EqualValues(t, expected, *arg2)
}

// TestHashRequest_EnterpriseTokenFieldsInMetadata verifies that enterprise token
// fields stored in auth.Metadata are not HMAC'd by hashAuth. These values are
// not secrets and must appear as cleartext in the audit log.
func TestHashRequest_EnterpriseTokenFieldsInMetadata(t *testing.T) {
	// Enterprise token fields are now stored in auth.Metadata by createEntry().
	// Verify that hashAuth does not HMAC metadata values.
	auditAuth := &auth{
		ClientToken: "secret-token",
		Metadata: map[string]any{
			"enterprise_token_metadata":    "test-token-xyz",
			"enterprise_token_issuer":      "https://issuer.example.com",
			"enterprise_token_transaction": "txn-hash-1",
			"actor_entity_id":              "actor-123",
			"actor_entity_name":            "actor-service",
		},
	}

	salter := &testSalter{}
	err := hashAuth(context.Background(), salter, auditAuth, false)
	require.NoError(t, err)

	// ClientToken must be HMAC'd — it is a secret.
	require.NotEqual(t, "secret-token", auditAuth.ClientToken)
	require.Contains(t, auditAuth.ClientToken, "hmac-sha256:")

	// Metadata values must pass through unchanged — they are not secrets.
	require.Equal(t, "test-token-xyz", auditAuth.Metadata["enterprise_token_metadata"])
	require.Equal(t, "https://issuer.example.com", auditAuth.Metadata["enterprise_token_issuer"])
	require.Equal(t, "txn-hash-1", auditAuth.Metadata["enterprise_token_transaction"])
	require.Equal(t, "actor-123", auditAuth.Metadata["actor_entity_id"])
	require.Equal(t, "actor-service", auditAuth.Metadata["actor_entity_name"])
}

// hmacForTest returns the identified HMAC of s using the trivial test salter.
func hmacForTest(t *testing.T, s string) string {
	t.Helper()
	out, err := hashString(context.Background(), &testSalter{}, s)
	require.NoError(t, err)
	return out
}

// TestHashWalker_WhitelistNested ensures whitelisting is decided by a field's
// own map key regardless of nesting depth: the same field name at the top
// level and inside nested objects is treated identically, while a
// whitelisted container key keeps no exemption for its sub-tree (its
// children are still hashed unless their own key is whitelisted),
// including bare elements of arrays/slices.
func TestHashWalker_WhitelistNested(t *testing.T) {
	vHMAC := hmacForTest(t, "v")
	xHMAC := hmacForTest(t, "x")
	sHMAC := hmacForTest(t, "s")
	qHMAC := hmacForTest(t, "q")

	data := map[string]interface{}{
		// Same key name at the top level and deep inside nested structures:
		// whitelisted everywhere it appears.
		"foo": "bar",
		"nested": map[string]interface{}{
			"foo":    "baz",
			"secret": "v",
		},
		// Bare array elements have no field name of their own, so they are
		// never exempted by a whitelisted container key; maps inside arrays
		// still resolve by their own keys.
		"list": []interface{}{
			"x",
			map[string]interface{}{
				"foo":    "z",
				"secret": "q",
			},
		},
		// "container" is whitelisted, but neither its nested map values nor
		// its array elements inherit the exemption.
		"container": map[string]interface{}{
			"secret": "s",
		},
		"items": []interface{}{"q"},
	}

	err := hashStructure(data, (&testSalter{}).mustGetIdentifiedHMAC(t), []string{"foo", "container", "items"})
	require.NoError(t, err)

	require.Equal(t, "bar", data["foo"])
	nested := data["nested"].(map[string]interface{})
	require.Equal(t, "baz", nested["foo"])
	require.Equal(t, vHMAC, nested["secret"])

	list := data["list"].([]interface{})
	require.Equal(t, xHMAC, list[0])
	listMap := list[1].(map[string]interface{})
	require.Equal(t, "z", listMap["foo"])
	require.Equal(t, qHMAC, listMap["secret"])

	container := data["container"].(map[string]interface{})
	require.Equal(t, sHMAC, container["secret"])

	items := data["items"].([]interface{})
	require.Equal(t, qHMAC, items[0])
}

// TestHashWalker_BinaryValues ensures binary values are normalised to strings
// and HMAC'd (rather than leaking through JSON base64 encoding) at every
// nesting position, while pre-serialized JSON is left untouched and
// namedBytes is a named byte-slice type, as produced by plugins.
type namedBytes []byte

// whitelisted binary fields remain readable.
func TestHashWalker_BinaryValues(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x02, 'b', 'i', 'n'}
	rawHMAC := hmacForTest(t, string(raw))
	readable := []byte("readable-binary")
	ptr := &raw

	data := map[string]interface{}{
		"blob":    raw,
		"named":   namedBytes(raw),
		"nested":  map[string]interface{}{"blob2": raw},
		"list":    []interface{}{raw},
		"rawmsg":  json.RawMessage(`{"k":"v"}`),
		"safe":    readable,
		// Pointers to byte slices are binary just like byte slices.
		"blobptr": ptr,
		// Bare elements of a whitelisted slice are still hashed: a
		// container key exemption never reaches slice elements.
		"safeList": []string{"e"},
	}

	err := hashStructure(data, (&testSalter{}).mustGetIdentifiedHMAC(t), []string{"safe", "safeList"})
	require.NoError(t, err)

	require.Equal(t, rawHMAC, data["blob"])
	require.Equal(t, rawHMAC, data["named"])
	require.Equal(t, rawHMAC, data["nested"].(map[string]interface{})["blob2"])
	require.Equal(t, rawHMAC, data["list"].([]interface{})[0])
	// The whole pointer value was replaced by its hashed string.
	require.Equal(t, hmacForTest(t, string(raw)), data["blobptr"])

	// json.RawMessage stays embedded JSON, not a quoted digest string.
	require.Equal(t, json.RawMessage(`{"k":"v"}`), data["rawmsg"])

	// Whitelisted binary is readable as its original text content.
	require.Equal(t, "readable-binary", data["safe"])
	// Slice elements are never exempted by a whitelisted container key.
	require.Equal(t, hmacForTest(t, "e"), data["safeList"].([]string)[0])
}

// TestHashRequest_HTTPRawBodyBinary ensures a request's binary raw body is
// converted to a string and hashed exactly like a response raw body, rather
// than leaking through JSON base64 encoding.
func TestHashRequest_HTTPRawBodyBinary(t *testing.T) {
	body := []byte{0x00, 'b', 'o', 'd', 'y'}
	bodyHMAC := hmacForTest(t, string(body))
	barHMAC := hmacForTest(t, "bar")

	req, err := newRequest(&logical.Request{
		Data: map[string]interface{}{
			logical.HTTPRawBody: body,
			"foo":               "bar",
		},
	}, nshelper.RootNamespace)
	require.NoError(t, err)

	err = hashRequest(context.Background(), &testSalter{}, req, false, nil)
	require.NoError(t, err)

	require.Equal(t, bodyHMAC, req.Data[logical.HTTPRawBody])
	require.Equal(t, barHMAC, req.Data["foo"])

	// A whitelisted raw body stays readable.
	req2, err := newRequest(&logical.Request{
		Data: map[string]interface{}{
			logical.HTTPRawBody: body,
		},
	}, nshelper.RootNamespace)
	require.NoError(t, err)
	err = hashRequest(context.Background(), &testSalter{}, req2, false, []string{logical.HTTPRawBody})
	require.NoError(t, err)
	require.Equal(t, string(body), req2.Data[logical.HTTPRawBody])
}

// mustGetIdentifiedHMAC returns the identified HMAC function for the salter.
func (s *testSalter) mustGetIdentifiedHMAC(t *testing.T) hashCallback {
	t.Helper()
	salt, err := s.Salt(context.Background())
	require.NoError(t, err)
	return salt.GetIdentifiedHMAC
}

// TestRedactErrorString ensures the failure reason embedded in an audit entry
// stays readable while any secret request parameter / response value (or
// token) the message contains is replaced by its digest; whitelisted values
// stay readable.
func TestRedactErrorString(t *testing.T) {
	ctx := context.Background()
	salter := &testSalter{}

	cases := map[string]struct {
		Msg          string
		Input        *logical.LogInput
		HMACAccessor bool
		Expected     string
	}{
		"plain-reason-unchanged": {
			Msg:      "permission denied",
			Input:    &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{"foo": "bar"}}},
			Expected: "permission denied",
		},
		"request-value-redacted": {
			Msg:      `invalid value supplied: "bar"`,
			Input:    &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{"foo": "bar"}}},
			Expected: fmt.Sprintf(`invalid value supplied: %q`, hmacForTest(t, "bar")),
		},
		"whitelisted-value-readable": {
			Msg:      `invalid value supplied: "bar"`,
			Input:    &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{"foo": "bar"}}},
			Expected: `invalid value supplied: "bar"`,
		},
		"nested-value-redacted": {
			Msg: `invalid nested: "deep"`,
			Input: &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{
				"outer": map[string]interface{}{"k": "deep"},
			}}},
			Expected: fmt.Sprintf(`invalid nested: %q`, hmacForTest(t, "deep")),
		},
		"binary-value-redacted": {
			Msg:      `bad payload: "bin-body"`,
			Input: &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{
				"blob": []byte("bin-body"),
			}}},
			Expected: fmt.Sprintf(`bad payload: %q`, hmacForTest(t, "bin-body")),
		},
		"slice-element-value-redacted": {
			Msg: `bad element: "slice-val"`,
			Input: &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{
				"list": []interface{}{"slice-val"},
			}}},
			Expected: fmt.Sprintf(`bad element: %q`, hmacForTest(t, "slice-val")),
		},
		"response-value-redacted": {
			Msg: `processing failed: "resp-secret"`,
			Input: &logical.LogInput{
				Request:  &logical.Request{},
				Response: &logical.Response{Data: map[string]interface{}{"foo": "resp-secret"}},
			},
			Expected: fmt.Sprintf(`processing failed: %q`, hmacForTest(t, "resp-secret")),
		},
		"client-token-redacted": {
			Msg:      "token rejected: client-tok",
			Input:    &logical.LogInput{Auth: &logical.Auth{ClientToken: "client-tok"}, Request: &logical.Request{}},
			Expected: "token rejected: " + hmacForTest(t, "client-tok"),
		},
		"request-token-redacted": {
			Msg:      "token rejected: request-tok",
			Input:    &logical.LogInput{Request: &logical.Request{ClientToken: "request-tok"}},
			Expected: "token rejected: " + hmacForTest(t, "request-tok"),
		},
		"wrap-token-redacted": {
			Msg: "wrap failed: wrap-tok",
			Input: &logical.LogInput{
				Request:  &logical.Request{},
				Response: &logical.Response{WrapInfo: &wrapping.ResponseWrapInfo{Token: "wrap-tok"}},
			},
			Expected: "wrap failed: " + hmacForTest(t, "wrap-tok"),
		},
		"accessor-redacted-when-enabled": {
			Msg:           "accessor bad: accessor-tok",
			Input:         &logical.LogInput{Auth: &logical.Auth{Accessor: "accessor-tok"}, Request: &logical.Request{}},
			HMACAccessor:  true,
			Expected:      "accessor bad: " + hmacForTest(t, "accessor-tok"),
		},
		"accessor-readable-when-disabled": {
			Msg:           "accessor bad: accessor-tok",
			Input:         &logical.LogInput{Auth: &logical.Auth{Accessor: "accessor-tok"}, Request: &logical.Request{}},
			HMACAccessor:  false,
			Expected:      "accessor bad: accessor-tok",
		},
		"short-value-untouched": {
			Msg:      `x is bad`,
			Input: &logical.LogInput{Request: &logical.Request{Data: map[string]interface{}{"foo": "x"}}},
			Expected: `x is bad`,
		},
		"empty-message": {
			Msg:      "",
			Input:    &logical.LogInput{Request: &logical.Request{}},
			Expected: "",
		},
	}

	for name, tc := range cases {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			if name == "whitelisted-value-readable" {
				// Exercise the request whitelist for this single case.
				tc.Input.NonHMACReqDataKeys = []string{"foo"}
			}

			// Snapshot the request/response data to prove redaction never
			// mutates the caller's input.
			var reqData map[string]interface{}
			if tc.Input.Request != nil && tc.Input.Request.Data != nil {
				reqData = make(map[string]interface{}, len(tc.Input.Request.Data))
				for k, v := range tc.Input.Request.Data {
					reqData[k] = v
				}
			}
			var respData map[string]interface{}
			if tc.Input.Response != nil && tc.Input.Response.Data != nil {
				respData = tc.Input.Response.Data
			}

			got, err := redactErrorString(ctx, salter, tc.Msg, tc.Input, tc.HMACAccessor)
			require.NoError(t, err)
			require.Equal(t, tc.Expected, got)

			if tc.Input.Request != nil {
				require.Equal(t, reqData, tc.Input.Request.Data)
			}
			if respData != nil {
				require.Equal(t, respData, tc.Input.Response.Data)
			}
		})
	}
}
