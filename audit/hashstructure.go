// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/reflectwalk"
)

// hashString uses the Salter to hash the supplied opaque string and returns it.
func hashString(ctx context.Context, salter Salter, data string) (string, error) {
	salt, err := salter.Salt(ctx)
	if err != nil {
		return "", err
	}

	return salt.GetIdentifiedHMAC(data), nil
}

// hashAuth uses the Salter to hash the supplied auth (modifying it).
// hmacAccessor is used to indicate whether the accessor should also be HMAC'd
// when present.
func hashAuth(ctx context.Context, salter Salter, auth *auth, hmacAccessor bool) error {
	if auth == nil {
		return nil
	}

	salt, err := salter.Salt(ctx)
	if err != nil {
		return err
	}

	fn := salt.GetIdentifiedHMAC

	if auth.ClientToken != "" {
		auth.ClientToken = fn(auth.ClientToken)
	}
	if hmacAccessor && auth.Accessor != "" {
		auth.Accessor = fn(auth.Accessor)
	}

	return nil
}

// hashRequest uses the Salter to hash the supplied request (modifying it).
// nonHMACDataKeys is used when hashing any 'Data' field within the request which
// prevents those specific keys from HMAC'd.
// hmacAccessor is used to indicate whether some accessors should also be HMAC'd
// when present.
// nonHMACDataKeys is used when hashing any 'Data' field within the request which
// prevents those specific keys from HMAC'd.
func hashRequest(ctx context.Context, salter Salter, req *request, hmacAccessor bool, nonHMACDataKeys []string) error {
	if req == nil {
		return nil
	}

	salt, err := salter.Salt(ctx)
	if err != nil {
		return err
	}

	fn := salt.GetIdentifiedHMAC

	if req.ClientToken != "" {
		req.ClientToken = fn(req.ClientToken)
	}
	if hmacAccessor && req.ClientTokenAccessor != "" {
		req.ClientTokenAccessor = fn(req.ClientTokenAccessor)
	}

	if req.Data != nil {
		// Binary request bodies arrive as byte slices and would be silently
		// base64 encoded by the JSON encoder, bypassing HMAC. Convert to string
		// before hashing, mirroring the response handling.
		if b, ok := req.Data[logical.HTTPRawBody].([]byte); ok {
			req.Data[logical.HTTPRawBody] = string(b)
		}

		err = hashMap(fn, req.Data, nonHMACDataKeys)
		if err != nil {
			return err
		}
	}

	if req.SupplementalAuditData != nil {
		err = hashMap(fn, req.SupplementalAuditData, nonHMACDataKeys)
		if err != nil {
			return err
		}
	}

	return nil
}

func hashMap(hashFunc hashCallback, data map[string]interface{}, nonHMACDataKeys []string) error {
	for k, v := range data {
		if o, ok := v.(logical.OptMarshaler); ok {
			marshaled, err := o.MarshalJSONWithOptions(&logical.MarshalOptions{
				ValueHasher: hashFunc,
			})
			if err != nil {
				return err
			}
			data[k] = json.RawMessage(marshaled)
		}
	}

	return hashStructure(data, hashFunc, nonHMACDataKeys)
}

// hashResponse uses the Salter to hash the supplied response (modifying it).
// hmacAccessor is used to indicate whether some accessors should also be HMAC'd
// when present.
// nonHMACDataKeys is used when hashing any 'Data' field within the response which
// prevents those specific keys from HMAC'd.
// See: /vault/docs/audit#eliding-list-response-bodies
func hashResponse(ctx context.Context, salter Salter, resp *response, hmacAccessor bool, nonHMACDataKeys []string) error {
	if resp == nil {
		return nil
	}

	salt, err := salter.Salt(ctx)
	if err != nil {
		return err
	}

	fn := salt.GetIdentifiedHMAC

	err = hashAuth(ctx, salter, resp.Auth, hmacAccessor)
	if err != nil {
		return err
	}

	if resp.Data != nil {
		if b, ok := resp.Data[logical.HTTPRawBody].([]byte); ok {
			resp.Data[logical.HTTPRawBody] = string(b)
		}

		err = hashMap(fn, resp.Data, nonHMACDataKeys)
		if err != nil {
			return err
		}
	}

	if resp.SupplementalAuditData != nil {
		err = hashMap(fn, resp.SupplementalAuditData, nonHMACDataKeys)
		if err != nil {
			return err
		}
	}

	if resp.WrapInfo != nil {
		var err error
		err = hashWrapInfo(fn, resp.WrapInfo, hmacAccessor)
		if err != nil {
			return err
		}
	}

	return nil
}

// hashWrapInfo uses the supplied hashing function to hash responseWrapInfo (modifying it).
// hmacAccessor is used to indicate whether some accessors should also be HMAC'd
// when present.
func hashWrapInfo(hashFunc hashCallback, wrapInfo *responseWrapInfo, hmacAccessor bool) error {
	if wrapInfo == nil {
		return nil
	}

	wrapInfo.Token = hashFunc(wrapInfo.Token)

	if hmacAccessor {
		wrapInfo.Accessor = hashFunc(wrapInfo.Accessor)

		if wrapInfo.WrappedAccessor != "" {
			wrapInfo.WrappedAccessor = hashFunc(wrapInfo.WrappedAccessor)
		}
	}

	return nil
}

// hashStructure takes an interface and hashes all the values within
// the structure. Only _values_ are hashed: keys of objects are not.
//
// For the hashCallback, see the built-in HashCallbacks below.
func hashStructure(s interface{}, cb hashCallback, ignoredKeys []string) error {
	walker := &hashWalker{Callback: cb, IgnoredKeys: ignoredKeys}
	return reflectwalk.Walk(s, walker)
}

// hashCallback is the callback called for hashStructure to hash
// a value.
type hashCallback func(string) string

// hashKeyEntry records a single position on the hashWalker key stack.
// Map values carry the name of the enclosing map key; slice/array elements
// have no map key of their own, so they must not inherit the containing
// key's exemption (otherwise a whitelisted container key would keep its
// entire subtree in cleartext).
type hashKeyEntry struct {
	// name is the map key at this position. Only meaningful when sliceElem
	// is false.
	name string

	// sliceElem is true when the position is an element of a slice/array.
	sliceElem bool
}

// hashWalker implements interfaces for the reflectwalk package
// (github.com/mitchellh/reflectwalk) that can be used to automatically
// replace primitives with a hashed value.
type hashWalker struct {
	// Callback is the function to call with the primitive that is
	// to be hashed. If there is an error, walking will be halted
	// immediately and the error returned.
	Callback hashCallback

	// IgnoreKeys are the keys that won't have the hashCallback applied
	IgnoredKeys []string

	// MapElem appends the enclosing map key (not the reflect.Value) to key.
	// The last element in key is the most recently entered map key.
	// Since Exit pops the last element of key, only nesting to another
	// structure increases the size of this slice.
	// SliceElem appends a marker so that values nested within slice
	// elements can't inherit the containing map key's exemption.
	key []hashKeyEntry

	lastValue reflect.Value

	// Enter appends to loc and exit pops loc. The last element of loc is thus
	// the current location.
	loc []reflectwalk.Location

	// Map and Slice append to cs, Exit pops the last element off cs.
	// The last element in cs is the most recently entered map or slice.
	cs []reflect.Value

	// MapElem and SliceElem append to csKey. The last element in csKey is the
	// most recently entered map key or slice index. Since Exit pops the last
	// element of csKey, only nesting to another structure increases the size of
	// this slice.
	csKey []reflect.Value
}

// hashTimeType stores a pre-computed reflect.Type for a time.Time so
// we can quickly compare in hashWalker.Struct. We create an empty/invalid
// time.Time{} so we don't need to incur any additional startup cost vs.
// Now() or Unix().
var hashTimeType = reflect.TypeOf(time.Time{})

// rawMessageType stores the reflect.Type for json.RawMessage; pre-serialized
// JSON must be emitted verbatim rather than treated as a binary value.
var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

func (w *hashWalker) Enter(loc reflectwalk.Location) error {
	w.loc = append(w.loc, loc)
	return nil
}

func (w *hashWalker) Exit(loc reflectwalk.Location) error {
	w.loc = w.loc[:len(w.loc)-1]

	switch loc {
	case reflectwalk.Map:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.MapValue:
		w.key = w.key[:len(w.key)-1]
		w.csKey = w.csKey[:len(w.csKey)-1]
	case reflectwalk.Slice:
		w.cs = w.cs[:len(w.cs)-1]
	case reflectwalk.SliceElem:
		w.key = w.key[:len(w.key)-1]
		w.csKey = w.csKey[:len(w.csKey)-1]
	}

	return nil
}

func (w *hashWalker) Map(m reflect.Value) error {
	w.cs = append(w.cs, m)
	return nil
}

func (w *hashWalker) MapElem(m, k, v reflect.Value) error {
	w.csKey = append(w.csKey, k)
	w.key = append(w.key, hashKeyEntry{name: k.String()})
	w.lastValue = v
	return nil
}

// Slice intercepts byte slices so binary data can't bypass HMAC by being
// base64 encoded by the JSON serializer. Non-byte slices are walked as
// normal (their elements are not exempted just because the containing
// map key is whitelisted).
func (w *hashWalker) Slice(s reflect.Value) error {
	w.cs = append(w.cs, s)

	if s.Type().Elem().Kind() != reflect.Uint8 {
		return nil
	}

	// json.RawMessage is already serialized JSON and must be emitted as-is,
	// otherwise the embedded JSON would itself be quoted and HMAC'd.
	if s.Type() == rawMessageType {
		return nil
	}

	// Bytes() works for both []byte and named byte-slice types whose
	// underlying type is uint8.
	b := s.Bytes()

	replaceVal, _, err := w.hashValue(string(b))
	if err != nil {
		return err
	}

	// Replace the whole byte slice at its containing location (a map
	// value or a slice element, at any nesting depth); s itself is not
	// guaranteed to be addressable. The immediate container is the
	// second-to-top container stack entry (the top entry is this byte
	// slice itself).
	if len(w.cs) >= 2 {
		container := w.cs[len(w.cs)-2]
		containerKey := w.csKey[len(w.csKey)-1]
		switch container.Kind() {
		case reflect.Map:
			container.SetMapIndex(containerKey, reflect.ValueOf(replaceVal))
		case reflect.Slice, reflect.Array:
			si := int(containerKey.Int())
			container.Slice(si, si+1).Index(0).Set(reflect.ValueOf(replaceVal))
		}
	}

	return nil
}

func (w *hashWalker) SliceElem(i int, elem reflect.Value) error {
	w.csKey = append(w.csKey, reflect.ValueOf(i))
	w.key = append(w.key, hashKeyEntry{sliceElem: true})
	return nil
}

func (w *hashWalker) Struct(v reflect.Value) error {
	// We are looking for time values. If it isn't one, ignore it.
	if v.Type() != hashTimeType {
		return nil
	}

	if len(w.loc) < 3 {
		// The last element of w.loc is reflectwalk.Struct, by definition.
		// If len(w.loc) < 3 that means hashWalker.Walk was given a struct
		// value and this is the very first step in the walk, and we don't
		// currently support structs as inputs,
		return errors.New("structs as direct inputs not supported")
	}

	// Second to last element of w.loc is location that contains this struct.
	switch w.loc[len(w.loc)-2] {
	case reflectwalk.MapValue:
		// Create a string value of the time. IMPORTANT: this must never change
		// across Vault versions or the hash value of equivalent time.Time will
		// change.
		strVal := v.Interface().(time.Time).Format(time.RFC3339Nano)

		// Set the map value to the string instead of the time.Time object
		m := w.cs[len(w.cs)-1]
		mk := w.csKey[len(w.cs)-1]
		m.SetMapIndex(mk, reflect.ValueOf(strVal))
	case reflectwalk.SliceElem:
		// Create a string value of the time. IMPORTANT: this must never change
		// across Vault versions or the hash value of equivalent time.Time will
		// change.
		strVal := v.Interface().(time.Time).Format(time.RFC3339Nano)

		// Set the map value to the string instead of the time.Time object
		s := w.cs[len(w.cs)-1]
		si := int(w.csKey[len(w.cs)-1].Int())
		s.Slice(si, si+1).Index(0).Set(reflect.ValueOf(strVal))
	}

	// Skip this entry so that we don't walk the struct.
	return reflectwalk.SkipEntry
}

func (w *hashWalker) StructField(reflect.StructField, reflect.Value) error {
	return nil
}

// currentMapKey returns the name of the nearest enclosing map key for the
// walker's current position, and true. It returns false when the value is (or
// is nested within) a slice/array element: such values have no map key of
// their own, so a whitelisted container key never exempts them.
func (w *hashWalker) currentMapKey() (string, bool) {
	for i := len(w.key) - 1; i >= 0; i-- {
		if w.key[i].sliceElem {
			return "", false
		}
		if w.key[i].name != "" {
			return w.key[i].name, true
		}
	}
	return "", false
}

// hashValue applies the hash callback to the supplied value unless its own
// map key is whitelisted. Values inside slice/array elements are always hashed.
func (w *hashWalker) hashValue(s string) (string, bool, error) {
	if w.Callback == nil {
		return s, false, nil
	}

	if currentKey, ok := w.currentMapKey(); ok && strutil.StrListContains(w.IgnoredKeys, currentKey) {
		return s, true, nil
	}

	return w.Callback(s), false, nil
}

// replaceValue stores the supplied replacement value at the walker's current
// location (map value or slice element), or directly on an addressable value.
func (w *hashWalker) replaceValue(resultVal reflect.Value) error {
	switch w.loc[len(w.loc)-1] {
	case reflectwalk.MapValue:
		// If we're in a map, then the only way to set a map value is
		// to set it directly.
		m := w.cs[len(w.cs)-1]
		mk := w.csKey[len(w.csKey)-1]
		m.SetMapIndex(mk, resultVal)
	case reflectwalk.SliceElem:
		s := w.cs[len(w.cs)-1]
		si := int(w.csKey[len(w.csKey)-1].Int())
		s.Slice(si, si+1).Index(0).Set(resultVal)
	default:
		// Otherwise, we should be addressable
		if !w.lastValue.CanSet() {
			return nil
		}
		w.lastValue.Set(resultVal)
	}

	return nil
}

// Primitive calls Callback to transform strings in-place, except for map keys.
// Strings hiding within interfaces are also transformed.
func (w *hashWalker) Primitive(v reflect.Value) error {
	if w.Callback == nil {
		return nil
	}

	// We don't touch map keys
	if w.loc[len(w.loc)-1] == reflectwalk.MapKey {
		return nil
	}

	setV := v

	// We only care about strings
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	if v.Kind() != reflect.String {
		return nil
	}

	replaceVal, _, err := w.hashValue(v.String())
	if err != nil {
		return err
	}

	resultVal := reflect.ValueOf(replaceVal)
	switch w.loc[len(w.loc)-1] {
	case reflectwalk.MapValue:
		// If we're in a map, then the only way to set a map value is
		// to set it directly.
		m := w.cs[len(w.cs)-1]
		mk := w.csKey[len(w.cs)-1]
		m.SetMapIndex(mk, resultVal)
	case reflectwalk.SliceElem:
		s := w.cs[len(w.cs)-1]
		si := int(w.csKey[len(w.csKey)-1].Int())
		s.Slice(si, si+1).Index(0).Set(resultVal)
	default:
		// Otherwise, we should be addressable
		setV.Set(resultVal)
	}

	return nil
}

// minErrorRedactionValueLength is the shortest scalar value that will be
// redacted from an error message. Shorter values (single characters and the
// like) are far more likely to corrupt readable failure reasons than to be
// actual secrets.
const minErrorRedactionValueLength = 3

// redactErrorString replaces every secret scalar value that appears within an
// audit entry's failure reason (request parameters and response values that
// would otherwise be HMAC'd, plus tokens/accessors) with its digest. Values
// whitelisted by their containing map key remain readable, so the failure
// reason stays human-readable; only raw secret content is masked.
func redactErrorString(ctx context.Context, salter Salter, msg string, in *logical.LogInput, hmacAccessor bool) (string, error) {
	if msg == "" || in == nil {
		return msg, nil
	}

	salt, err := salter.Salt(ctx)
	if err != nil {
		return "", err
	}
	fn := salt.GetIdentifiedHMAC

	// raw -> digest replacements.
	replacements := make(map[string]string)

	addSecret := func(raw string) {
		if len(raw) < minErrorRedactionValueLength {
			return
		}
		if _, ok := replacements[raw]; !ok {
			replacements[raw] = fn(raw)
		}
	}

	// Tokens are always secret, regardless of configuration; accessors are
	// only HMAC'd when the device is configured to do so.
	if in.Request != nil {
		addSecret(in.Request.ClientToken)
		if hmacAccessor {
			addSecret(in.Request.ClientTokenAccessor)
		}
	}
	if in.Auth != nil {
		addSecret(in.Auth.ClientToken)
		if hmacAccessor {
			addSecret(in.Auth.Accessor)
		}
	}
	if in.Response != nil {
		if in.Response.Auth != nil {
			addSecret(in.Response.Auth.ClientToken)
			if hmacAccessor {
				addSecret(in.Response.Auth.Accessor)
			}
		}
		if in.Response.WrapInfo != nil {
			addSecret(in.Response.WrapInfo.Token)
			if hmacAccessor {
				addSecret(in.Response.WrapInfo.WrappedAccessor)
				addSecret(in.Response.WrapInfo.Accessor)
			}
		}
	}

	// Scalar data values that would otherwise be hashed are masked within
	// the failure reason; whitelisted key values stay readable. This is a
	// read-only traversal: it must never mutate the supplied LogInput data.
	var collectValue func(value interface{}, keyIgnored bool)
	collectMap := func(data map[string]interface{}, nonHMACKeys []string) {
		for k, v := range data {
			collectValue(v, strutil.StrListContains(nonHMACKeys, k))
		}
	}
	collectStringMap := func(data map[string]string, nonHMACKeys []string) {
		for k, v := range data {
			collectValue(v, strutil.StrListContains(nonHMACKeys, k))
		}
	}
	collectValue = func(value interface{}, keyIgnored bool) {
		switch vv := value.(type) {
		case string:
			if !keyIgnored {
				addSecret(vv)
			}
		case []byte:
			// Pre-serialized JSON stays as-is; all other binary values
			// follow the same rule as the text of the same field.
			if _, ok := value.(json.RawMessage); !ok {
				if !keyIgnored {
					addSecret(string(vv))
				}
			}
		case map[string]interface{}:
			collectMap(vv, nil)
		case map[string]string:
			collectStringMap(vv, nil)
		case []interface{}:
			for _, v := range vv {
				// Slice/array elements have no map key of their own, so
				// a container key exemption never applies to them.
				collectValue(v, false)
			}
		case []string:
			for _, v := range vv {
				collectValue(v, false)
			}
		default:
			// Other kinds (numbers, booleans, structs, ...) can't be
			// reliably located inside a free-form error message.
		}
	}
	collect := collectMap

	if in.Request != nil {
		collect(in.Request.Data, in.NonHMACReqDataKeys)
	}
	if in.Response != nil {
		collect(in.Response.Data, in.NonHMACRespDataKeys)
		collect(in.Response.SupplementalAuditResponseData, in.NonHMACRespDataKeys)
		collect(in.Response.SupplementalAuditRequestData, in.NonHMACReqDataKeys)
	}

	if len(replacements) == 0 {
		return msg, nil
	}

	// Replace longest values first so that overlapping values (e.g. "bar"
	// and "barbell") don't leave one partially substituted.
	values := make([]string, 0, len(replacements))
	for raw := range replacements {
		values = append(values, raw)
	}
	sort.Slice(values, func(i, j int) bool {
		return len(values[i]) > len(values[j])
	})

	pairs := make([]string, 0, 2*len(values))
	for _, raw := range values {
		// A value that is already an HMAC digest needs no replacement, and
		// substituting would only corrupt it.
		digest := replacements[raw]
		if raw == digest {
			continue
		}
		pairs = append(pairs, raw, digest)
	}
	if len(pairs) > 0 {
		return strings.NewReplacer(pairs...).Replace(msg), nil
	}

	return msg, nil
}
