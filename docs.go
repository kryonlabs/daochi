package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	stats, err := s.store.PublicStats(r.Context(), s.cfg.DBPath)
	statusHTML := `<p class="status-error">Stats are temporarily unavailable.</p>`
	if err != nil {
		slog.Error("load public stats", "error", err)
	} else {
		usedGB := stats.StorageUsedGB
		if stats.StorageUsedBytes > 0 && usedGB == 0 {
			usedGB = 1
		}
		totalGB := usedGB + stats.AvailableGB
		statusHTML = fmt.Sprintf(`<footer class="status" aria-label="Users: %d; Storage: %d/%d GB">
<span><strong>Users</strong> %d</span>
<span><strong>Storage</strong> %d/%d GB</span>
</footer>`, stats.UserCount, usedGB, totalGB, stats.UserCount, usedGB, totalGB)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lyra Sync API</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:880px;margin:40px auto;padding:0 20px;line-height:1.5;color:#18202a;background:#f7f8fb}
main{background:white;border:1px solid #d9deea;padding:28px}
h1{margin-top:0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{overflow:auto;background:#111827;color:#f9fafb;padding:16px}
.endpoint{border-top:1px solid #e5e7eb;padding:14px 0}
.method{display:inline-block;min-width:56px;font-weight:700}
.status{border-top:1px solid #e5e7eb;margin-top:22px;padding-top:14px;display:flex;gap:18px;align-items:center;color:#5c6675;font-size:.9rem;flex-wrap:wrap}
.status strong{color:#18202a;font-weight:650}
.status-error{border-top:1px solid #e5e7eb;margin-top:22px;padding-top:14px;color:#5c6675}
a{color:#254da8}
@media (max-width:640px){.status{gap:10px}}
</style>
</head>
<body>
<main>
<h1>Lyra Sync API</h1>
<p>Stateless post-quantum sync relay for Inner Breeze. The server stores public keys and mirrored app data, never client private keys.</p>
<p><a href="/openapi.json">OpenAPI JSON</a> · <a href="/healthz">Health check</a></p>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/sync/challenge?user_id=&lt;sha256-public-key-hex&gt;</code><p>Issues a single-use 32-byte challenge nonce encoded as lowercase hex.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/sync/ws</code><p>Upgrades to a WebSocket event stream authenticated with <code>Authorization: Bearer &lt;token&gt;</code>.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/sync</code><p>Applies signed local changes and returns remote changes newer than <code>since_server_version</code>.</p></section>
<section class="endpoint"><span class="method">DELETE</span><code>/api/v1/account</code><p>Deletes all remote data for the signed sync account.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/account/delete-with-key</code><p>Deletes all remote data for the sync account after verifying exported account key text.</p></section>
<h2>Signed Message</h2>
<pre>inbe-sync-v1
&lt;HTTP_METHOD&gt;
&lt;HTTP_PATH&gt;
&lt;sha256 hex of exact raw request body bytes&gt;
&lt;challenge nonce hex&gt;</pre>
<p>Signed requests use <code>X-Inbe-User</code>, <code>X-Inbe-Signature</code>, and <code>Content-Type: application/json</code>.</p>
%s
</main>
</body>
</html>`, statusHTML)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.oai.openapi+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(openAPISpec())
}

func openAPISpec() map[string]any {
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Lyra Sync API",
			"version":     "1.0.0",
			"description": "Post-quantum sync relay for Inner Breeze.",
		},
		"paths": map[string]any{
			"/healthz": map[string]any{
				"get": map[string]any{
					"summary": "Health check",
					"responses": map[string]any{
						"200": map[string]any{"description": "Server is healthy"},
					},
				},
			},
			"/api/v1/sync/challenge": map[string]any{
				"get": map[string]any{
					"summary": "Issue sync challenge",
					"parameters": []map[string]any{
						{
							"name":     "user_id",
							"in":       "query",
							"required": true,
							"schema":   map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Challenge nonce"},
						"400": map[string]any{"description": "Invalid user id"},
					},
				},
			},
			"/api/v1/sync": map[string]any{
				"post": map[string]any{
					"summary":     "Apply signed sync changes",
					"description": "Body is signed through X-Inbe-Signature over the exact raw request body bytes.",
					"parameters":  signedHeaderParameters(),
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/SyncRequest"}},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Changes applied"},
						"400": map[string]any{"description": "Invalid request or missing challenge"},
						"401": map[string]any{"description": "Signature rejected"},
					},
				},
			},
			"/api/v1/sync/ws": map[string]any{
				"get": map[string]any{
					"summary":     "Subscribe to sync change events",
					"description": "WebSocket endpoint. Send Authorization: Bearer <auth_token>. The server emits sync_ready after connect and sync_changed whenever another client applies changes.",
					"parameters": []map[string]any{
						{
							"name":        "Authorization",
							"in":          "header",
							"required":    true,
							"description": "Bearer auth token returned by POST /api/v1/sync/login.",
							"schema":      map[string]any{"type": "string"},
						},
					},
					"responses": map[string]any{
						"101": map[string]any{"description": "WebSocket upgrade accepted"},
						"400": map[string]any{"description": "Invalid websocket handshake"},
						"401": map[string]any{"description": "Bearer token rejected"},
					},
				},
			},
			"/api/v1/account": map[string]any{
				"delete": map[string]any{
					"summary":     "Delete remote account data",
					"description": "Deletes server-side mirrored data for the signed account.",
					"parameters":  signedHeaderParameters(),
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/DeleteRequest"}},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Remote data deleted"},
						"400": map[string]any{"description": "Invalid request or missing challenge"},
						"401": map[string]any{"description": "Signature rejected"},
					},
				},
			},
			"/api/v1/account/delete-with-key": map[string]any{
				"post": map[string]any{
					"summary":     "Delete remote account using exported key",
					"description": "Accepts exported account key text. Generic account-key-v1 keys and legacy inbe-sync-key-v1 keys are supported.",
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/DeleteWithKeyRequest"}},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Remote data deleted"},
						"400": map[string]any{"description": "Invalid request or exported key"},
						"401": map[string]any{"description": "Exported key does not match sync account"},
						"404": map[string]any{"description": "Sync account not found"},
					},
				},
			},
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"SyncRequest": map[string]any{
					"type":     "object",
					"required": []string{"user_id_hash"},
					"properties": map[string]any{
						"user_id_hash": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						"public_key":   map[string]any{"type": "string", "description": "ML-DSA-44 public key as hex or base64; required on first sync."},
						"habits":       map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Habit"}},
						"habit_days":   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/HabitDay"}},
						"sessions":     map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Session"}},
					},
				},
				"DeleteRequest": map[string]any{
					"type":     "object",
					"required": []string{"user_id_hash"},
					"properties": map[string]any{
						"user_id_hash": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
					},
				},
				"DeleteWithKeyRequest": map[string]any{
					"type":     "object",
					"required": []string{"user_id_hash", "exported_key"},
					"properties": map[string]any{
						"user_id_hash": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						"exported_key": map[string]any{"type": "string", "description": "Full text of the exported account key file."},
					},
				},
				"Habit": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":              map[string]any{"type": "string"},
						"name":            map[string]any{"type": "string"},
						"color_r":         map[string]any{"type": "integer"},
						"color_g":         map[string]any{"type": "integer"},
						"color_b":         map[string]any{"type": "integer"},
						"sync_mode":       map[string]any{"type": "integer"},
						"sync_activity":   map[string]any{"type": "integer"},
						"counter_enabled": map[string]any{"type": "integer"},
						"sort_order":      map[string]any{"type": "integer"},
						"deleted_at":      map[string]any{"type": "integer"},
						"updated_at":      map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"HabitDay": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"habit_id":   map[string]any{"type": "string"},
						"local_date": map[string]any{"type": "integer"},
						"completed":  map[string]any{"type": "boolean"},
						"count":      map[string]any{"type": "integer"},
						"updated_at": map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"Session": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":          map[string]any{"type": "string"},
						"started_at":  map[string]any{"type": "string", "format": "date-time"},
						"local_date":  map[string]any{"type": "integer"},
						"topic":       map[string]any{"type": "string"},
						"activity":    map[string]any{"type": "integer"},
						"source":      map[string]any{"type": "string"},
						"rounds_hash": map[string]any{"type": "string"},
						"deleted_at":  map[string]any{"type": "integer"},
						"updated_at":  map[string]any{"type": "string", "format": "date-time"},
						"rounds":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SessionRound"}},
					},
				},
				"SessionRound": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"round_index":  map[string]any{"type": "integer"},
						"breaths":      map[string]any{"type": "integer"},
						"hold_seconds": map[string]any{"type": "integer"},
					},
				},
			},
		},
	}
}

func signedHeaderParameters() []map[string]any {
	return []map[string]any{
		{
			"name":        "X-Inbe-User",
			"in":          "header",
			"required":    true,
			"description": "SHA-256 hash of the ML-DSA-44 public key.",
			"schema":      map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
		},
		{
			"name":        "X-Inbe-Signature",
			"in":          "header",
			"required":    true,
			"description": "ML-DSA-44 signature as hex or base64.",
			"schema":      map[string]any{"type": "string"},
		},
	}
}
