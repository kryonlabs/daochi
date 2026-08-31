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
<title>Ksync Sync API</title>
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
<h1>Ksync Sync API</h1>
<p>Stateless post-quantum sync relay for Kryon apps. The server stores public keys and mirrored app data, never client private keys. Protocol v5 makes encrypted records the primary private-data surface while legacy typed rows remain available for compatibility, and released Inbe v4 encrypted collections remain valid.</p>
<p><a href="/openapi.json">OpenAPI JSON</a> · <a href="/healthz">Health check</a> · <a href="/readyz">Readiness</a> · <a href="/metrics">Metrics</a></p>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/apps</code><p>Lists registered apps, collection prefixes, visibility classes, and capabilities. Built-in registrations include Inbe and Uku.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/apps</code><p>Registers or updates an app when <code>KSYNC_ADMIN_TOKEN</code> is set and <code>X-Ksync-Admin</code> matches it.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/sync/challenge?user_id=&lt;sha256-public-key-hex&gt;</code><p>Issues a single-use 32-byte challenge nonce encoded as lowercase hex.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/sync/login</code><p>Verifies the challenge signature and returns a cacheable bearer token plus server clock time.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/sync/ws</code><p>Upgrades to a WebSocket event stream authenticated with <code>Authorization: Bearer &lt;token&gt;</code>, or browser subprotocols <code>ksync-sync-v1, bearer.&lt;token&gt;</code>.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/sync</code><p>Applies signed local changes and returns remote changes newer than <code>since_server_version</code>.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/sync/diagnostics</code><p>Returns bearer-authenticated sync state, table counts, compaction position, and legacy client hints.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/tokens/issuer</code><p>Returns the Waozi token issuer key. Official apps accept only Waozi-signed <code>waozi:token</code> receipts.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/tokens/products</code><p>Lists configured token products and direct Monero prices when direct purchases are enabled.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/tokens/balance</code><p>Returns the bearer-authenticated account's Waozi token balance computed from signed ledger events.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/tokens/spend</code><p>Debits Waozi tokens with app policy and idempotency enforcement.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/tokens/purchases/monero/invoices</code><p>Creates a bearer-authenticated Monero invoice for a configured token product.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/tokens/purchases/monero/invoices/{id}</code><p>Returns invoice status and settles a confirmed Monero payment against the authenticated account.</p></section>
<section class="endpoint"><span class="method">GET/POST</span><code>/api/v1/account/app-grants</code><p>Lists or creates bearer-authenticated grants for sharing registered app collection prefixes across apps.</p></section>
<section class="endpoint"><span class="method">GET</span><code>/api/v1/account/app-records</code><p>Returns encrypted records from a granted collection prefix for cross-app use.</p></section>
<section class="endpoint"><span class="method">GET/POST</span><code>/api/v1/friends</code><p>Bearer-authenticated friend requests, accepted friends, and app-neutral shared profile stats.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/account/delete</code><p>Deletes all remote data for the signed sync account without uploading the private key.</p></section>
<section class="endpoint"><span class="method">DELETE</span><code>/api/v1/account</code><p>Legacy signed deletion endpoint kept for older clients.</p></section>
<section class="endpoint"><span class="method">POST</span><code>/api/v1/account/delete-with-key</code><p>Deletes all remote data for the sync account after verifying exported account key text.</p></section>
<h2>Signed Message</h2>
<pre>ksync-sync-v1
&lt;HTTP_METHOD&gt;
&lt;HTTP_PATH&gt;
&lt;sha256 hex of exact raw request body bytes&gt;
&lt;challenge nonce hex&gt;</pre>
<p>Signed requests use <code>X-Ksync-User</code>, <code>X-Ksync-Signature</code>, and <code>Content-Type: application/json</code>.</p>
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
			"title":       "Ksync Sync API",
			"version":     "1.0.0",
			"description": "Post-quantum sync relay for Kryon apps.",
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
			"/readyz": map[string]any{
				"get": map[string]any{
					"summary": "Readiness check",
					"responses": map[string]any{
						"200": map[string]any{"description": "Server is ready for production traffic"},
						"503": map[string]any{"description": "Server is not ready"},
					},
				},
			},
			"/metrics": map[string]any{
				"get": map[string]any{
					"summary": "Prometheus metrics",
					"responses": map[string]any{
						"200": map[string]any{"description": "Prometheus text metrics"},
					},
				},
			},
			"/api/v1/tokens/assets": map[string]any{
				"get": map[string]any{
					"summary": "List token assets",
					"responses": map[string]any{
						"200": map[string]any{"description": "Token assets"},
					},
				},
			},
			"/api/v1/tokens/issuer": map[string]any{
				"get": map[string]any{
					"summary": "Get Waozi token issuer key",
					"responses": map[string]any{
						"200": map[string]any{"description": "Token issuer"},
					},
				},
			},
			"/api/v1/tokens/products": map[string]any{
				"get": map[string]any{
					"summary": "List configured token products",
					"responses": map[string]any{
						"200": map[string]any{"description": "Token products"},
					},
				},
			},
			"/api/v1/tokens/balance": map[string]any{
				"get": map[string]any{
					"summary":  "Get authenticated Waozi token balance",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"200": map[string]any{"description": "Token balance"},
						"401": map[string]any{"description": "Invalid bearer token"},
					},
				},
			},
			"/api/v1/tokens/ledger": map[string]any{
				"get": map[string]any{
					"summary":  "List authenticated Waozi token receipts",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"200": map[string]any{"description": "Token ledger events"},
					},
				},
			},
			"/api/v1/tokens/spend": map[string]any{
				"post": map[string]any{
					"summary":  "Spend Waozi tokens",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"200": map[string]any{"description": "Signed debit receipt"},
						"409": map[string]any{"description": "Insufficient balance"},
					},
				},
			},
			"/api/v1/tokens/purchases/google/verify": map[string]any{
				"post": map[string]any{
					"summary":  "Verify Google Play purchase and credit Waozi tokens",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"200": map[string]any{"description": "Signed credit receipt"},
					},
				},
			},
			"/api/v1/tokens/purchases/monero/invoices": map[string]any{
				"post": map[string]any{
					"summary":  "Create Monero token invoice",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"201": map[string]any{"description": "Monero invoice"},
					},
				},
			},
			"/api/v1/tokens/purchases/monero/invoices/{id}": map[string]any{
				"get": map[string]any{
					"summary":  "Get or settle Monero token invoice",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{
						{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Monero invoice status"},
						"404": map[string]any{"description": "Invoice not found"},
					},
				},
			},
			"/api/v1/tokens/checkpoints/latest": map[string]any{
				"get": map[string]any{
					"summary": "Get latest signed token checkpoint",
					"responses": map[string]any{
						"200": map[string]any{"description": "Token checkpoint"},
						"404": map[string]any{"description": "No checkpoint exists"},
					},
				},
			},
			"/api/v1/tokens/receipts/{receipt_id}": map[string]any{
				"get": map[string]any{
					"summary": "Get token receipt",
					"parameters": []map[string]any{
						{"name": "receipt_id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Signed token receipt"},
						"404": map[string]any{"description": "Receipt not found"},
					},
				},
			},
			"/api/v1/admin/tokens/manual-credit": map[string]any{
				"post": map[string]any{
					"summary": "Admin credit Waozi tokens",
					"responses": map[string]any{
						"200": map[string]any{"description": "Signed credit receipt"},
						"401": map[string]any{"description": "Invalid admin token"},
						"403": map[string]any{"description": "Admin disabled"},
					},
				},
			},
			"/api/v1/admin/tokens/checkpoint": map[string]any{
				"post": map[string]any{
					"summary": "Create signed token checkpoint",
					"responses": map[string]any{
						"200": map[string]any{"description": "Token checkpoint"},
						"401": map[string]any{"description": "Invalid admin token"},
						"403": map[string]any{"description": "Admin disabled"},
					},
				},
			},
			"/api/v1/apps": map[string]any{
				"get": map[string]any{
					"summary": "List registered apps",
					"responses": map[string]any{
						"200": map[string]any{"description": "App registry"},
					},
				},
				"post": map[string]any{
					"summary":     "Register or update an app",
					"description": "Requires KSYNC_ADMIN_TOKEN on the server and matching X-Ksync-Admin header.",
					"responses": map[string]any{
						"200": map[string]any{"description": "Registered app"},
						"401": map[string]any{"description": "Invalid admin token"},
						"403": map[string]any{"description": "Admin registration disabled"},
					},
				},
			},
			"/api/v1/apps/{app_id}": map[string]any{
				"get": map[string]any{
					"summary": "Get registered app",
					"parameters": []map[string]any{
						{"name": "app_id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "App registration"},
						"404": map[string]any{"description": "App not found"},
					},
				},
				"put": map[string]any{
					"summary":     "Register or update an app",
					"description": "Requires KSYNC_ADMIN_TOKEN on the server and matching X-Ksync-Admin header.",
					"parameters": []map[string]any{
						{"name": "app_id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Registered app"},
					},
				},
			},
			"/api/v1/apps/{app_id}/collections": map[string]any{
				"get": map[string]any{
					"summary": "List app collection prefixes",
					"parameters": []map[string]any{
						{"name": "app_id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Collection prefixes"},
						"404": map[string]any{"description": "App not found"},
					},
				},
			},
			"/api/v1/account/app-grants": map[string]any{
				"get": map[string]any{
					"summary":  "List cross-app grants",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"200": map[string]any{"description": "App grants"},
					},
				},
				"post": map[string]any{
					"summary":  "Create cross-app grant",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"201": map[string]any{"description": "Created app grant"},
						"400": map[string]any{"description": "Invalid or private collection"},
					},
				},
			},
			"/api/v1/account/app-records": map[string]any{
				"get": map[string]any{
					"summary":  "Read encrypted records from a granted app collection prefix",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{
						{"name": "source_app_id", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
						{"name": "target_app_id", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
						{"name": "collection_prefix", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Encrypted records"},
						"403": map[string]any{"description": "Grant required"},
					},
				},
			},
			"/api/v1/sync/diagnostics": map[string]any{
				"get": map[string]any{
					"summary":  "Inspect sync state for the authenticated account",
					"security": []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{
						"200": map[string]any{"description": "Sync diagnostic report"},
						"401": map[string]any{"description": "Invalid bearer token"},
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
			"/api/v1/sync/login": map[string]any{
				"post": map[string]any{
					"summary":     "Create bearer token",
					"description": "Body is signed through X-Ksync-Signature over the exact raw request body bytes. The response includes server_time for client token-expiry clock skew compensation.",
					"parameters":  signedHeaderParameters(),
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/LoginRequest"}},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Bearer token issued", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/LoginResponse"}}}},
						"400": map[string]any{"description": "Invalid request or missing challenge"},
						"401": map[string]any{"description": "Signature rejected"},
					},
				},
			},
			"/api/v1/sync": map[string]any{
				"post": map[string]any{
					"summary":     "Apply signed sync changes",
					"description": "Body is signed through X-Ksync-Signature over the exact raw request body bytes.",
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
					"description": "WebSocket endpoint. Send Authorization: Bearer <auth_token>. Browser clients may use Sec-WebSocket-Protocol: ksync-sync-v1, bearer.<auth_token>. The server emits sync_ready after connect and sync_changed whenever another client applies changes.",
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
					"description": "Legacy signed deletion endpoint kept for older clients. New clients should use POST /api/v1/account/delete.",
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
			"/api/v1/account/delete": map[string]any{
				"post": map[string]any{
					"summary":     "Delete remote account data",
					"description": "Deletes server-side mirrored data for the signed account without uploading the private key.",
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
			"/api/v1/account/export": map[string]any{
				"get": map[string]any{
					"summary":     "Export authenticated account data",
					"description": "Bearer-authenticated read-only dump of all Ksync rows owned by or directly attached to the authenticated account.",
					"parameters":  bearerHeaderParameters(),
					"responses": map[string]any{
						"200": map[string]any{"description": "Account data export"},
						"401": map[string]any{"description": "Bearer token rejected"},
						"404": map[string]any{"description": "Sync account not found"},
					},
				},
			},
			"/api/v1/account/delete-with-key": map[string]any{
				"post": map[string]any{
					"summary":     "Delete remote account using exported key",
					"description": "Accepts exported account key text. Current ksync-account-key-v1 keys and legacy lyra-account-key-v1, account-key-v1, and inbe-sync-key-v1 keys are supported.",
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
			"/api/v1/friends": map[string]any{
				"get": map[string]any{
					"summary":     "List accepted friends",
					"description": "Bearer-authenticated. Returns account-level Ksync friends.",
					"parameters":  bearerHeaderParameters(),
					"responses": map[string]any{
						"200": map[string]any{"description": "Friends list"},
						"401": map[string]any{"description": "Bearer token rejected"},
					},
				},
			},
			"/api/v1/friends/requests": map[string]any{
				"get": map[string]any{
					"summary":    "List pending friend requests",
					"parameters": bearerHeaderParameters(),
					"responses": map[string]any{
						"200": map[string]any{"description": "Incoming and outgoing requests"},
						"401": map[string]any{"description": "Bearer token rejected"},
					},
				},
				"post": map[string]any{
					"summary":    "Create friend request",
					"parameters": bearerHeaderParameters(),
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/FriendRequestCreateRequest"}},
						},
					},
					"responses": map[string]any{
						"201": map[string]any{"description": "Friend request created"},
						"404": map[string]any{"description": "Target account not found"},
						"409": map[string]any{"description": "Already friends or self-request"},
					},
				},
			},
			"/api/v1/profile/stats": map[string]any{
				"put": map[string]any{
					"summary":     "Publish app-neutral profile stats",
					"description": "Bearer-authenticated aggregate stats. Ksync stores only app/practice/metric/value rows.",
					"parameters":  bearerHeaderParameters(),
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/ProfileStatsRequest"}},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Stats stored"},
						"400": map[string]any{"description": "Invalid stat namespace"},
					},
				},
			},
			"/api/v1/friends/stats": map[string]any{
				"get": map[string]any{
					"summary":     "List friend leaderboard stats",
					"description": "Returns the caller and accepted friends only.",
					"parameters": append(bearerHeaderParameters(),
						map[string]any{"name": "app", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
						map[string]any{"name": "practice", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
						map[string]any{"name": "metric", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
					),
					"responses": map[string]any{
						"200": map[string]any{"description": "Leaderboard rows"},
						"400": map[string]any{"description": "Invalid stats query"},
					},
				},
			},
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"FriendRequestCreateRequest": map[string]any{
					"type":     "object",
					"required": []string{"target"},
					"properties": map[string]any{
						"target": map[string]any{"type": "string", "description": "Alias with optional @ prefix or 64-character public ID hash."},
					},
				},
				"ProfileStatsRequest": map[string]any{
					"type":     "object",
					"required": []string{"app", "metrics"},
					"properties": map[string]any{
						"app":     map[string]any{"type": "string"},
						"metrics": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/ProfileMetric"}},
					},
				},
				"ProfileMetric": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"practice":   map[string]any{"type": "string"},
						"metric":     map[string]any{"type": "string"},
						"value":      map[string]any{"type": "number"},
						"label":      map[string]any{"type": "string"},
						"local_date": map[string]any{"type": "integer"},
					},
				},
				"LoginRequest": map[string]any{
					"type":     "object",
					"required": []string{"user_id_hash", "client_id"},
					"properties": map[string]any{
						"user_id_hash": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						"client_id":    map[string]any{"type": "string"},
						"public_key":   map[string]any{"type": "string", "description": "ML-DSA-44 public key as hex or base64; required on first login."},
					},
				},
				"SyncRequest": map[string]any{
					"type":     "object",
					"required": []string{"user_id_hash"},
					"properties": map[string]any{
						"protocol_version":     map[string]any{"type": "integer", "description": "Use 5 for encrypted-record primary private data, or 4 for encrypted-record dual-write transition support. Version 3 clean hierarchical data responses and versions 1-2 legacy clients remain supported."},
						"app_id":               map[string]any{"type": "string", "description": "Optional through protocol v5. Future protocol v6 requires a registered app_id and registered encrypted record collections."},
						"client_capabilities":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"include_legacy_data":  map[string]any{"type": "boolean", "description": "Protocol v5 opt-in for receiving legacy typed private rows alongside encrypted records."},
						"user_id_hash":         map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						"client_id":            map[string]any{"type": "string"},
						"client_clock":         map[string]any{"type": "integer"},
						"since_server_version": map[string]any{"type": "integer"},
						"public_key":           map[string]any{"type": "string", "description": "ML-DSA-44 public key as hex or base64; required on first sync."},
						"habits":               map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Habit"}},
						"habit_days":           map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/HabitDay"}},
						"sessions":             map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Session"}},
						"ops":                  map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SyncOp"}},
						"encrypted_records":    map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EncryptedRecord"}},
					},
				},
				"LoginResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"status":             map[string]any{"type": "string"},
						"auth_token":         map[string]any{"type": "string"},
						"expires_in_seconds": map[string]any{"type": "integer"},
						"server_time":        map[string]any{"type": "integer", "description": "Unix seconds from the server clock. Clients can use it to compensate for local clock skew while caching bearer tokens."},
						"account_alias":      map[string]any{"type": "string"},
						"profile_icon":       map[string]any{"type": "integer"},
					},
				},
				"SyncResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"protocol_version":       map[string]any{"type": "integer"},
						"status":                 map[string]any{"type": "string"},
						"server_capabilities":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"transition_mode":        map[string]any{"type": "string"},
						"server_version":         map[string]any{"type": "integer"},
						"server_clock":           map[string]any{"type": "integer"},
						"changes":                map[string]any{"type": "object", "description": "Legacy v1/v2 table-array changes."},
						"data":                   map[string]any{"$ref": "#/components/schemas/CleanData"},
						"logs":                   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SyncLog"}},
						"deletes":                map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SyncLog"}},
						"upgrade_notice":         map[string]any{"type": "string"},
						"min_supported_protocol": map[string]any{"type": "integer"},
						"latest_protocol":        map[string]any{"type": "integer"},
						"legacy_clients":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"diagnostics":            map[string]any{"type": "object"},
					},
				},
				"CleanData": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"habits":            map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Habit"}},
						"habit_days":        map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/CleanHabitDay"}},
						"sessions":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Session"}},
						"meditation_logs":   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/MeditationLog"}},
						"social_cache":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SocialCache"}},
						"encrypted_records": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EncryptedRecord"}},
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
				"CleanHabitDay": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"habit_id":   map[string]any{"type": "string"},
						"habit_name": map[string]any{"type": "string"},
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
						"mood_before": map[string]any{"type": "integer"},
						"mood_after":  map[string]any{"type": "integer"},
						"energy":      map[string]any{"type": "integer"},
						"stress":      map[string]any{"type": "integer"},
						"note":        map[string]any{"type": "string"},
						"tags":        map[string]any{"type": "string"},
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
				"MeditationLog": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":               map[string]any{"type": "string"},
						"session_id":       map[string]any{"type": "string"},
						"duration_seconds": map[string]any{"type": "integer"},
						"completed_at":     map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"SocialCache": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"kind":       map[string]any{"type": "string"},
						"json":       map[string]any{"type": "object"},
						"updated_at": map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"EncryptedRecord": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"collection":     map[string]any{"type": "string"},
						"id":             map[string]any{"type": "string"},
						"key_id":         map[string]any{"type": "string"},
						"nonce":          map[string]any{"type": "string"},
						"ciphertext":     map[string]any{"type": "string"},
						"updated_at":     map[string]any{"type": "string", "format": "date-time"},
						"deleted_at":     map[string]any{"type": "integer"},
						"content_hash":   map[string]any{"type": "string", "description": "Optional lowercase SHA-256 hex hash of the canonical plaintext or ciphertext selected by the client protocol."},
						"schema_version": map[string]any{"type": "integer"},
						"parent_id":      map[string]any{"type": "string"},
					},
				},
				"SyncOp": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"op_id":       map[string]any{"type": "string"},
						"client_id":   map[string]any{"type": "string"},
						"seq":         map[string]any{"type": "integer"},
						"entity_type": map[string]any{"type": "string"},
						"entity_id":   map[string]any{"type": "string"},
						"local_date":  map[string]any{"type": "integer"},
						"op_type":     map[string]any{"type": "string"},
						"payload":     map[string]any{"type": "object"},
						"created_at":  map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"SyncLog": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"server_version": map[string]any{"type": "integer"},
						"kind":           map[string]any{"type": "string"},
						"entity_type":    map[string]any{"type": "string"},
						"entity_id":      map[string]any{"type": "string"},
						"local_date":     map[string]any{"type": "integer"},
						"op_type":        map[string]any{"type": "string"},
						"payload":        map[string]any{"type": "object"},
						"created_at":     map[string]any{"type": "string", "format": "date-time"},
					},
				},
			},
		},
	}
}

func signedHeaderParameters() []map[string]any {
	return []map[string]any{
		{
			"name":        "X-Ksync-User",
			"in":          "header",
			"required":    true,
			"description": "SHA-256 hash of the ML-DSA-44 public key.",
			"schema":      map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
		},
		{
			"name":        "X-Ksync-Signature",
			"in":          "header",
			"required":    true,
			"description": "ML-DSA-44 signature as hex or base64.",
			"schema":      map[string]any{"type": "string"},
		},
	}
}

func bearerHeaderParameters() []map[string]any {
	return []map[string]any{
		{
			"name":        "Authorization",
			"in":          "header",
			"required":    true,
			"description": "Bearer auth token returned by POST /api/v1/sync/login.",
			"schema":      map[string]any{"type": "string"},
		},
	}
}
