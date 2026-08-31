# Ksync

Ksync is the stateless sync relay for Kryon apps. It stores public keys and mirrored app data, but never stores client private keys.

## Privacy Model

Ksync uses the client account key for identity and authentication. A client proves control of the account by signing a short-lived challenge with ML-DSA-44, and Ksync then issues a bearer token for normal sync and social API calls.

Ksync's legacy typed sync surface is not end-to-end encrypted against the server. Mirrored app data is stored in SQLite as normal typed rows and JSON payloads so the service can sync, compact, export, derive friend leaderboard stats, and delete account data. This is intentional for compatibility. Operational access to the server database or a valid bearer token can read the typed data those credentials allow.

Protocol clients may also sync `encrypted_records`: opaque per-account private records identified by `collection` and `id`. Ksync stores and versions those blobs for relay, export, deletion, and diagnostics, but does not need to read their contents. Protocol v4 advertises this as the dual-write transition path: upgraded clients can keep sending legacy typed rows for compatibility while also seeding encrypted private records for future mesh-capable clients. Protocol v5 makes encrypted records the primary private-data surface for upgraded clients while legacy typed rows remain available through `include_legacy_data` for compatibility. The released Inbe v4 encrypted collections remain valid in v5 so clients do not need an immediate second backfill migration. Public/social projections such as aliases, friend requests, profile icons, and leaderboard stats remain readable server-side by design.

Clients that encrypt the whole sync payload may post an encrypted envelope to `POST /api/v1/sync` with JSON fields `v`, `nonce`, and `ciphertext`. Ksync authenticates the bearer token, stores the envelope bytes opaquely, assigns a normal `server_version`, and returns encrypted envelopes newer than `X-Ksync-Since-Version`. Existing typed Inbe clients keep using the same endpoint and JSON shape as before; the server only takes the envelope path when the request body has the explicit encrypted-envelope shape.

Ksync keeps an app registry so data ownership is app-neutral and can be shared across apps without hard-coding Inbe behavior. `inbe` and `uku` are seeded automatically. Inbe remains the lead migration client and sends `app_id:"inbe"` in v5 compatibility mode; older clients without `app_id` continue to sync. Future protocol v6 requests must include a registered `app_id`, and encrypted record collections must belong to that registered app.

API access is scoped by account, with explicit shared surfaces:

- accepted friends can see the account alias and selected profile/leaderboard stats;
- user-created app grants can share `shared.*`, `friends.*`, or `public.*` encrypted record prefixes with another registered app;
- pending friend request participants can see the request metadata;
- public governance processes, proposals, and votes are public by design.

## Endpoints

- `GET /api/v1/sync/challenge?user_id=<sha256-public-key-hex>`
- `GET /api/v1/sync/diagnostics`
- `GET /api/v1/sync/ws`
- `POST /api/v1/sync/login`
- `POST /api/v1/sync`
- `POST /api/v1/account/delete`
- `GET /api/v1/apps`
- `POST /api/v1/apps` with `X-Ksync-Admin` when `KSYNC_ADMIN_TOKEN` is set
- `GET /api/v1/apps/{app_id}`
- `GET /api/v1/apps/{app_id}/collections`
- `GET /api/v1/tokens/assets`
- `GET /api/v1/tokens/products`
- `GET /api/v1/tokens/issuer`
- `GET /api/v1/tokens/balance`
- `GET /api/v1/tokens/ledger`
- `POST /api/v1/tokens/spend`
- `POST /api/v1/tokens/purchases/google/verify`
- `POST /api/v1/tokens/purchases/monero/invoices`
- `GET /api/v1/tokens/purchases/monero/invoices/{id}`
- `GET /api/v1/tokens/checkpoints/latest`
- `GET /api/v1/tokens/receipts/{receipt_id}`
- `POST /api/v1/admin/tokens/manual-credit`
- `POST /api/v1/admin/tokens/checkpoint`
- `POST /api/v1/account/alias`
- `GET /api/v1/account/export`
- `GET /api/v1/account/app-grants`
- `POST /api/v1/account/app-grants`
- `DELETE /api/v1/account/app-grants/{id}`
- `GET /api/v1/account/app-records?source_app_id=&target_app_id=&collection_prefix=`
- `GET /api/v1/friends`
- `GET /api/v1/friends/requests`
- `POST /api/v1/friends/requests`
- `POST /api/v1/friends/requests/{id}/accept`
- `POST /api/v1/friends/requests/{id}/decline`
- `DELETE /api/v1/friends/{user_id_hash}`
- `PUT /api/v1/profile/stats`
- `GET /api/v1/friends/stats?app=&practice=&metric=`
- `GET /api/v1/processes`
- `POST /api/v1/processes`
- `GET /api/v1/processes/{id}`
- `PATCH /api/v1/processes/{id}`
- `POST /api/v1/processes/{id}/proposals`
- `POST /api/v1/processes/{id}/votes`
- `DELETE /api/v1/account`
- `POST /api/v1/account/delete-with-key`
- `GET /openapi.json`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /`

`api.waozi.xyz` should terminate TLS at a reverse proxy and forward to `KSYNC_ADDR`, for example `127.0.0.1:8080`.
Set `KSYNC_TOKEN_SECRET_HEX` to at least 32 random bytes encoded as hex in production.
`KSYNC_ALLOW_EPHEMERAL_TOKEN_SECRET=1` is only for local development because it invalidates tokens on restart and is not a stable server secret.

Bearer tokens are intentionally cacheable client-side credentials, not the user's durable login state. Clients should silently run the challenge/sign/login flow again when a token expires or receives a `401`, as long as the local account key still exists. Login responses include `server_time` as Unix seconds so clients can compensate for local clock skew when caching token expiry. Older clients may ignore it. Only an explicit user logout, account deletion, or local account reset should remove the account key.

The WebSocket endpoint accepts bearer auth through `Authorization: Bearer <token>`. Browser clients that cannot set custom WebSocket headers may send `Sec-WebSocket-Protocol: ksync-sync-v1, bearer.<token>`. Ksync rejects `?token=` WebSocket URLs so bearer tokens do not leak through request URLs, browser history, or proxy URL logs.

Encrypted envelope clients should send:

- `Authorization: Bearer <token>`
- `X-Ksync-User: <sha256-public-key-hex>` or legacy `X-Inbe-User`
- `X-Ksync-Client: <client-id>` when available
- `X-Ksync-Since-Version: <last-seen-server-version>` when requesting only newer envelopes

Envelope bodies are relayed as JSON `encrypted_payloads` in the sync response. Ksync does not parse the envelope contents beyond checking that `v` is `1` or `2` and `nonce` and `ciphertext` are non-empty.

## Signature Message

Clients must sign this exact byte string with ML-DSA-44:

```text
ksync-sync-v1
<HTTP_METHOD>
<HTTP_PATH>
<sha256 hex of exact raw request body bytes>
<challenge nonce hex>
```

The challenge response returns `nonce` as lowercase hex. The challenge is single-use and expires after 60 seconds by default.

Bearer-authenticated `POST /api/v1/sync` requests must include `Authorization: Bearer <token>`, `X-Ksync-User: <sha256-public-key-hex>`, and `Content-Type: application/json`. Legacy `X-Inbe-User` remains accepted.

Signed `POST /api/v1/account/delete` and legacy `DELETE /api/v1/account` requests must include:

- `X-Ksync-User: <sha256-public-key-hex>`
- `X-Ksync-Signature: <ML-DSA-44 signature>`
- `Content-Type: application/json`

Signed JSON bodies still include `user_id_hash`. The server accepts `public_key` and `X-Ksync-Signature` as either base64 or lowercase/uppercase hex. This matches the current C client account storage, which keeps ML-DSA-44 keys as hex strings.

The preferred account deletion endpoint is `POST /api/v1/account/delete`, using the same challenge/signature scheme as login and sync so the private key never leaves the device. `DELETE /api/v1/account` remains supported for older clients that already shipped with that wire shape.

The website deletion endpoint `POST /api/v1/account/delete-with-key` accepts `user_id_hash` plus the full exported account key text. Current exports start with `ksync-account-key-v1`; legacy `lyra-account-key-v1`, `account-key-v1`, and `inbe-sync-key-v1` exports are still accepted. Current key exports include `public_id`, and Ksync rejects a request if that public ID does not match `user_id_hash`. Ksync signs a fixed deletion proof with that private key, verifies it against the registered public key, deletes the account, and does not store the uploaded key.

## Build

From this project directory, build with:

```sh
make build
```

The Makefile builds a minimal static liboqs from `vendor/liboqs` with `SIG_ml_dsa_44` enabled, then passes the right cgo include/library flags to Go. Use `make test` for the same setup in tests.

Inspect a production database offline with:

```sh
./ksync inspect --db /var/lib/ksync/ksync.db summary
./ksync inspect --db /var/lib/ksync/ksync.db doctor <user_id_hash>
```

`inspect doctor` prints redacted account status, sync versions, table counts, recent client protocol hints, and recent sync audit metadata. Use `--full` only when you intentionally need unredacted IDs.

Without Nix, install liboqs headers and library on the host, then:

```sh
CGO_ENABLED=1 go build -o ksync .
```

Runtime configuration:

```sh
KSYNC_ADDR=127.0.0.1:8080
KSYNC_BASE_URL=https://api.waozi.xyz
KSYNC_DB=/var/lib/ksync/ksync.db
KSYNC_ADMIN_TOKEN=<optional app registry write token>
KSYNC_TOKEN_SECRET_HEX=<stable 64+ hex chars shared by every server instance>
KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX=<ed25519 public key hex>
KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX_FILE=/run/secrets/waozi_issuer_public.hex
KSYNC_WAOZI_ISSUER_PRIVATE_KEY_HEX=<ed25519 private key hex, issuer nodes only>
KSYNC_WAOZI_ISSUER_PRIVATE_KEY_HEX_FILE=/run/secrets/waozi_issuer_private.hex
KSYNC_TOKEN_PRODUCTS=waozi_tokens_small:5000000:1000000000000
KSYNC_GOOGLE_PACKAGE_NAMES=xyz.waozi.inbe
KSYNC_GOOGLE_SERVICE_ACCOUNT_JSON=<google service account json>
KSYNC_GOOGLE_SERVICE_ACCOUNT_JSON_FILE=/run/secrets/google_play_service_account.json
KSYNC_GOOGLE_OAUTH_CLIENT_JSON_FILE=/run/secrets/google_play_oauth_client.json
KSYNC_GOOGLE_OAUTH_REFRESH_TOKEN_FILE=/run/secrets/google_play_refresh_token.txt
KSYNC_TOKEN_DIRECT_PURCHASES_ENABLED=1
KSYNC_MONERO_WALLET_RPC_URL=http://127.0.0.1:18083
KSYNC_MONERO_WALLET_RPC_USER=<wallet rpc user>
KSYNC_MONERO_WALLET_RPC_PASSWORD=<wallet rpc password>
KSYNC_CHALLENGE_TTL_SECONDS=60
KSYNC_TOKEN_TTL_SECONDS=3600
KSYNC_MAX_BODY_BYTES=1048576
```

Generate a token secret once and keep it stable across restarts and every deployed instance:

```sh
openssl rand -hex 32
```

If `KSYNC_TOKEN_SECRET_HEX` is missing, Ksync generates a random in-memory secret at startup. That is only suitable for single-process local development: existing bearer tokens become invalid after restart, and multi-instance deployments will reject tokens issued by another instance.

## Waozi Tokens

Ksync can issue `waozi:token` receipts for official Waozi apps. The server verifies Google Play or Monero payments, writes an append-only ledger event, and signs the receipt with the Waozi Ed25519 issuer key. Official clients must verify the issuer key and accept only `issuer_id=waozi` with `asset_id=waozi:token`.

Self-hosted Ksync servers may use the same ledger shape for local assets later, but they cannot create official Waozi tokens without the Waozi private issuer key. If only `KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX` is configured, the server can expose and verify receipts but cannot credit or spend tokens.

Token ledger and payment-intent rows are financial audit records. They are scoped by account for balance and receipt lookup, but they are not included in normal account data export and are not deleted by account-data cascade.

## Encrypted Hierarchy

Protocol v5 clients should put all new private app data in `encrypted_records` and use typed sync only as a backward-compatibility mirror. Existing released Inbe v4 collections are grandfathered:

- `inbe.habits`;
- `inbe.habit_days`;
- `inbe.sessions`.

New v5 collection names use a dotted hierarchy:

- `account.v1.manifest` for the per-account hierarchy manifest;
- `private.<app>.v<version>.<collection>` for encrypted private app records;
- `shared.<app>.v<version>.<collection>` for user-grantable cross-app records;
- `friends.<app>.v<version>.<collection>` for friend-visible app records;
- `public.<app>.v<version>.<collection>` for intentionally public encrypted/public-record namespaces.

Future private features should add or extend encrypted collections first. Existing v4 encrypted collections may continue to sync without another migration; new private namespaces should use the v5 hierarchy. Legacy typed schema additions are reserved for compatibility with older clients or for public/server-readable projections.

## Reverse Proxy

Example nginx server block:

```nginx
server {
    server_name api.waozi.xyz;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Use your normal ACME flow for TLS certificates.

## Data Model

SQLite tables mirror the app data:

- `server_users`
- `server_meditation_logs`
- `server_habits`
- `server_habit_days`
- `server_sessions` including session check-in fields such as mood, energy, stress, notes, and tags
- `server_session_rounds`
- `server_friend_requests`
- `server_friendships`
- `server_apps`
- `server_app_collections`
- `server_app_capabilities`
- `server_app_grants`
- `server_app_grant_audit`
- `server_encrypted_payloads`
- `server_sync_audit`
- `server_profile_stats`
- `token_assets`
- `token_ledger`
- `token_processed_payments`
- `token_spend_nonces`
- `token_payment_intents`
- `token_checkpoints`

Deleting an account removes app sync, social, profile, and governance rows through foreign-key cascade. Token financial audit rows are retained as described above.
