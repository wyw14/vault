// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenAuth_RenewBatch(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path

		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		require.NoError(t, decoder.Decode(&gotBody))

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"data": {
				"idempotency_key": "batch-key-1",
				"max_total_duration": 3600,
				"requested_total_duration": 4200,
				"granted_total_duration": 3600,
				"replayed": false,
				"results": [
					{
						"index": 0,
						"identifier_type": "token",
						"status": "success",
						"reason": "",
						"accessor": "acc-1",
						"client_token": "hvs.child",
						"renewable": true,
						"requested_increment": 3600,
						"lease_duration": 3600
					},
					{
						"index": 1,
						"identifier_type": "accessor",
						"status": "revoked",
						"reason": "token not found; it may have expired or been revoked",
						"renewable": false,
						"requested_increment": 600,
						"lease_duration": 0
					}
				],
				"summary": {
					"success": 1,
					"limit_reached": 0,
					"revoked": 1,
					"audit_failed": 0,
					"error": 0,
					"total": 2
				}
			}
		}`)
	}))
	defer server.Close()

	client, err := NewClient(&Config{Address: server.URL})
	require.NoError(t, err)

	secret, err := client.Auth().Token().RenewBatchWithContext(context.Background(), &TokenRenewBatchRequest{
		IdempotencyKey:   "batch-key-1",
		MaxTotalDuration: 3600,
		Tokens: []*TokenRenewBatchItem{
			{Token: "hvs.child", Increment: 3600},
			{Accessor: "acc-2", Increment: 600},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, secret)

	require.Equal(t, http.MethodPut, gotMethod)
	require.Equal(t, "/v1/auth/token/renew-batch", gotPath)

	require.Equal(t, "batch-key-1", gotBody["idempotency_key"])
	require.Equal(t, json.Number("3600"), gotBody["max_total_duration"])
	bodyItems, ok := gotBody["tokens"].([]interface{})
	require.True(t, ok)
	require.Len(t, bodyItems, 2)
	first := bodyItems[0].(map[string]interface{})
	require.Equal(t, "hvs.child", first["token"])
	require.Equal(t, json.Number("3600"), first["increment"])
	second := bodyItems[1].(map[string]interface{})
	require.Equal(t, "acc-2", second["accessor"])
	_, hasTokenInAccessorItem := second["token"]
	require.False(t, hasTokenInAccessorItem, "omitempty should elide empty token")

	require.Equal(t, json.Number("3600"), secret.Data["granted_total_duration"])
	require.Equal(t, false, secret.Data["replayed"])
	results, ok := secret.Data["results"].([]interface{})
	require.True(t, ok)
	require.Len(t, results, 2)
	require.Equal(t, "success", results[0].(map[string]interface{})["status"])
	require.Equal(t, "revoked", results[1].(map[string]interface{})["status"])
	summary := secret.Data["summary"].(map[string]interface{})
	require.Equal(t, json.Number("1"), summary["success"])
	require.Equal(t, json.Number("1"), summary["revoked"])
}
