# Daochi

Daochi is a mesh-native sync network for app-owned data. It stores public keys and mirrored app data, but never stores client private keys. New clients should use the `X-Daochi-*` wire headers. The server still accepts shipped `X-Ksync-*` and `X-Inbe-*` compatibility headers.

## Philosophy

Daochi is built for imperfect networks, older devices, and changing servers.
Its design rules are:

- local first: account authority begins on the user's device;
- respect old hardware: keep the relay useful on modest machines, old phones, small home nodes, and low-power servers;
- store less, reveal less: move and order private records without reading them whenever clients can carry that responsibility;
- keep old paths open: compatibility windows and migrations are part of the product;
- make trust inspectable: keys, signatures, app ownership, protocol versions, and node relationships should be understandable.

## Guides

- [Encrypted record profile v1](docs/encrypted-record-profile-v1.md) defines the recommended client-side envelope for private records.
- [Developer quickstart](docs/developer-quickstart.md) shows the shortest path from account key to encrypted sync.
- [Small node operations](docs/operations-small-node.md) records low-resource targets and trust inspection checks.

## Privacy Model

Daochi uses the client account key for identity and authentication. A client proves control of the account by signing a short-lived challenge with ML-DSA-44, and the server then issues a bearer token for normal sync and social API calls.

The legacy typed sync surface is not end-to-end encrypted against the server. Mirrored app data is stored in SQLite as normal typed rows and JSON payloads so the service can sync, compact, export, derive friend leaderboard stats, and delete account data. This is intentional for compatibility. Operational access to the server database or a valid bearer token can read the typed data those credentials allow.

Protocol clients may also sync `encrypted_records`: opaque per-account private records identified by `collection` and `id`. Daochi stores and versions those blobs for relay, export, deletion, and diagnostics, but does not need to read their contents. Protocol v4 advertises this as the dual-write transition path: upgraded clients can keep sending legacy typed rows for compatibility while also seeding encrypted private records for future mesh-capable clients. Protocol v5 makes encrypted records the primary private-data surface for upgraded clients while legacy typed rows remain available through `include_legacy_data` for compatibility. Released legacy encrypted collections remain valid in v5 so clients do not need an immediate second backfill migration. Public/social projections such as aliases, friend requests, profile icons, and leaderboard stats remain readable server-side by design.

Clients that encrypt the whole sync payload may post an encrypted envelope to `POST /api/v1/sync` with JSON fields `v`, `nonce`, and `ciphertext`. Daochi authenticates the bearer token, stores the envelope bytes opaquely, assigns a normal `server_version`, and returns encrypted envelopes newer than `X-Daochi-Since-Version`. Existing typed clients keep using the same endpoint and JSON shape as before; the server only takes the envelope path when the request body has the explicit encrypted-envelope shape.

Daochi keeps an app registry so data ownership is app-neutral and no product behavior is hard-coded into the service. Inbe is the sole built-in registration because its released sync formats are a compatibility contract. Every other app installs and maintains its own signed manifest, keys, collection scopes, and token policy. Registered apps can send `app_id` in v5 compatibility mode only when their manifest explicitly allows that protocol. Older shipped Inbe clients without `app_id` continue to sync during the compatibility window. Protocol v6 requests must include a registered `app_id`, a signed transaction envelope, and encrypted record collections declared by that app.

Protocol compatibility policy: protocol v1 through v5 are valid through **2027-09-01** for legacy clients covered by app policy. When a future protocol version is deprecated, the immediately previous version must remain valid for at least one additional year, and the current protocol version must always stay valid. App manifests declare their own compatibility windows through `compatibility_until` and `legacy_protocols`.

API access is scoped by account, with explicit shared surfaces:

- accepted friends can see the account alias and selected profile/leaderboard stats;
- user-created app grants can share `shared.*`, `friends.*`, or `public.*` encrypted record prefixes with another registered app;
- pending friend request participants can see the request metadata;

## Endpoints

- `GET /api/v1/sync/challenge?user_id=<sha256-public-key-hex>`
- `GET /api/v1/sync/diagnostics`
- `GET /api/v1/sync/ws`
- `POST /api/v1/sync/login`
- `POST /api/v1/sync`
- `POST /api/v1/account/delete`
- `GET /api/v1/apps`
- `POST /api/v1/apps` with `X-Daochi-Admin` when `DAOCHI_ADMIN_TOKEN` is set
- `POST /api/v1/apps/register-signed`
- `GET /api/v1/apps/{app_id}`
- `GET /api/v1/apps/{app_id}/collections`
- `GET /api/v1/node`
- `POST /api/v1/node/pairing/invites`
- `POST /api/v1/node/pairing/accept`
- `POST /api/v1/node/pairing/complete`
- `GET /api/v1/node/peers`
- `POST /api/v1/namespaces`
- `POST /api/v1/namespaces/claims`
- `GET /api/v1/namespaces/resolve?space_id=<id>&name=<name>`
- `POST /api/v1/node/mesh/export`
- `POST /api/v1/node/mesh/import`
- `GET /api/v1/tokens/assets`
- `GET /api/v1/tokens/products`
- `GET /api/v1/tokens/issuer`
- `GET /api/v1/tokens/balance?app_id=<optional-app-id>`
- `GET /api/v1/tokens/ledger?since=<optional-seq>&app_id=<optional-app-id>`
- `POST /api/v1/tokens/spend`
- `POST /api/v1/tokens/purchases/google/verify`
- `POST /api/v1/tokens/purchases/monero/invoices`
- `GET /api/v1/tokens/purchases/monero/invoices/{id}`
- `GET /api/v1/tokens/purchases/monero/address` (authenticated account)
- `GET /api/v1/tokens/purchases/monero/address/{alias-or-public-id}` (gift recipient)
- `GET /api/v1/tokens/purchases/monero/deposits`
- `GET /api/v1/tokens/checkpoints/latest`
- `GET /api/v1/tokens/receipts/{receipt_id}`
- `POST /api/v1/admin/tokens/manual-credit`
- `POST /api/v1/admin/tokens/checkpoint`
- `POST /api/v1/account/alias`
- `GET /api/v1/account/export`
- `GET /api/v1/account/app-grants`
- `POST /api/v1/account/app-grants`
- `POST /api/v1/account/app-grants/signed`
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
- `DELETE /api/v1/account`
- `POST /api/v1/account/delete-with-key`
- `GET /openapi.json`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /`

`GET /api/v1/node` includes aggregate `usage` counts for public node dashboards:
registered users, users active in the last 30 days, registered clients, clients
active in the last 30 days, distinct connected WebSocket users, and current
WebSocket client connections. `/metrics` publishes the same aggregate user and
client gauges with `daochi_*` names; legacy `ksync_*` metric aliases remain for
existing dashboards.

The public API hostname should terminate TLS at a reverse proxy and forward to `DAOCHI_ADDR`, for example `127.0.0.1:8080`.
Set `DAOCHI_TOKEN_SECRET_HEX` to at least 32 random bytes encoded as hex in production.
`DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET=1` is only for local development because it invalidates tokens on restart and is not a stable server secret.

Bearer tokens are intentionally cacheable client-side credentials, not the user's durable login state. Clients should silently run the challenge/sign/login flow again when a token expires or receives a `401`, as long as the local account key still exists. Login responses include `server_time` as Unix seconds so clients can compensate for local clock skew when caching token expiry. Older clients may ignore it. Only an explicit user logout, account deletion, or local account reset should remove the account key.

The WebSocket endpoint accepts bearer auth through `Authorization: Bearer <token>`. Browser clients that cannot set custom WebSocket headers may send `Sec-WebSocket-Protocol: daochi-sync-v1, bearer.<token>`. Legacy `ksync-sync-v1` and `inbe-sync-v1` subprotocols remain accepted. Daochi rejects `?token=` WebSocket URLs so bearer tokens do not leak through request URLs, browser history, or proxy URL logs.

Encrypted envelope clients should send:

- `Authorization: Bearer <token>`
- `X-Daochi-User: <sha256-public-key-hex>`
- `X-Daochi-Client: <client-id>` when available
- `X-Daochi-Since-Version: <last-seen-server-version>` when requesting only newer envelopes
- `X-Daochi-Limit: <count>` when deliberately paging envelope deltas

`X-Ksync-*` header names remain accepted as compatibility aliases. Envelope bodies are relayed as JSON `encrypted_payloads` in the sync response. Daochi does not parse the envelope contents beyond checking that `v` is `1` or `2` and `nonce` and `ciphertext` are non-empty. If a response is paged, `encrypted_payloads_truncated` is `true` and `encrypted_payloads_next_since_version` is the next value to send as `X-Daochi-Since-Version`.

## Signature Message

Clients must sign this exact byte string with ML-DSA-44:

```text
daochi-sync-v1
<HTTP_METHOD>
<HTTP_PATH>
<sha256 hex of exact raw request body bytes>
<challenge nonce hex>
```

Legacy `ksync-sync-v1` and `inbe-sync-v1` signed-message contexts remain accepted with their matching legacy signature headers.

The challenge response returns `nonce` as lowercase hex. The challenge is single-use and expires after 60 seconds by default.

Bearer-authenticated `POST /api/v1/sync` requests must include `Authorization: Bearer <token>`, `X-Daochi-User: <sha256-public-key-hex>`, and `Content-Type: application/json`. Legacy account headers remain accepted.

Protocol v6 `POST /api/v1/sync` requests must also include `X-Daochi-Tx`. The header is either raw JSON or base64url JSON with:

- `protocol_version: 6`
- `tx_id` and `nonce`, both replay-protected per account
- `account_id`, matching the bearer account
- `app_id`, matching the request body app ID
- `app_key_id`, matching an active key in the app manifest
- `method`, `path`, and `body_sha256` for the exact HTTP request
- `expires_at`, no more than 15 minutes in the future
- `signature`, an ML-DSA-44 account signature over the canonical transaction message
- `app_signature`, an Ed25519 app-key signature over the same canonical transaction message

The canonical transaction message is:

```text
daochi-tx-v1
<protocol_version>
<tx_id>
<account_id>
<app_id>
<app_key_id>
<HTTP_METHOD>
<HTTP_PATH>
<sha256 hex of exact raw request body bytes>
<nonce>
<expires_at unix seconds>
```

Signed `POST /api/v1/account/delete` and legacy `DELETE /api/v1/account` requests must include:

- `X-Daochi-User: <sha256-public-key-hex>`
- `X-Daochi-Signature: <ML-DSA-44 signature>`
- `Content-Type: application/json`

Signed JSON bodies still include `user_id_hash` for compatibility. The server accepts `public_key` and signatures as either base64 or lowercase/uppercase hex. This matches the current C client account storage, which keeps ML-DSA-44 keys as hex strings.

The preferred account deletion endpoint is `POST /api/v1/account/delete`, using the same challenge/signature scheme as login and sync so the private key never leaves the device. `DELETE /api/v1/account` remains supported for older clients that already shipped with that wire shape.

The website deletion endpoint `POST /api/v1/account/delete-with-key` accepts `user_id_hash` plus the full exported account key text. Current exports start with `ksync-account-key-v1`, and legacy account key exports are still accepted. Current key exports include `public_id`, and Daochi rejects a request if that public ID does not match `user_id_hash`. Daochi signs a fixed deletion proof with that private key, verifies it against the registered public key, deletes the account, and does not store the uploaded key.

## Build

From this project directory, build with:

```sh
make build
```

The Makefile builds a minimal static liboqs from `vendor/liboqs` with `SIG_ml_dsa_44` enabled, then passes the right cgo include/library flags to Go. Use `make test` for the same setup in tests.

Inspect a production database offline with:

```sh
./daochi inspect --db /var/lib/daochi/daochi.db summary
./daochi inspect --db /var/lib/daochi/daochi.db doctor <user_id_hash>
```

`inspect doctor` prints redacted account status, sync versions, table counts, recent client protocol hints, and recent sync audit metadata. Use `--full` only when you intentionally need unredacted IDs.

Without Nix, install liboqs headers and library on the host, then:

```sh
CGO_ENABLED=1 go build -o daochi .
```

Runtime configuration:

```sh
DAOCHI_ADDR=127.0.0.1:8080
DAOCHI_BASE_URL=https://api.example.com
DAOCHI_DB=/var/lib/daochi/daochi.db
DAOCHI_ADMIN_TOKEN=<optional admin token; also gates GET /metrics and app registry writes when set>
DAOCHI_TOKEN_SECRET_HEX=<stable 64+ hex chars shared by every server instance>
DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX=<ed25519 public key hex for signed app approvals>
DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE=/run/secrets/node_registry_public.hex
DAOCHI_NODE_NAME=Home
DAOCHI_NODE_IDENTITY_KEY_FILE=/var/lib/daochi/node.key
DAOCHI_LAN_DISCOVERY=1
DAOCHI_KNOWN_NODES=Public=https://api.example.com;sync=pull;apps=inbe;collections=private.inbe.v1.*;data=app_registry+encrypted_records
DAOCHI_NODE_SYNC_TOKEN=<shared secret for trusted node-to-node mesh sync>
DAOCHI_NODE_SYNC_INTERVAL_SECONDS=60
DAOCHI_NODE_SYNC_BATCH_LIMIT=500
DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX=<ed25519 public key hex>
DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE=/run/secrets/token_issuer_public.hex
DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX=<ed25519 private key hex, issuer nodes only>
DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE=/run/secrets/token_issuer_private.hex
DAOCHI_TOKEN_PRODUCTS=tokens_small:5000000:1000000000000
DAOCHI_GOOGLE_PACKAGE_NAMES=com.example.app
DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON=<google service account json>
DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE=/run/secrets/google_play_service_account.json
DAOCHI_GOOGLE_OAUTH_CLIENT_JSON_FILE=/run/secrets/google_play_oauth_client.json
DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN_FILE=/run/secrets/google_play_refresh_token.txt
DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED=1
MONERO_WALLET_RPC_URL=http://127.0.0.1:18083
MONERO_WALLET_RPC_USER=<wallet rpc user>
MONERO_WALLET_RPC_PASSWORD_FILE=/run/credentials/daochi.service/monero_rpc_password
MONERO_NETWORK=stagenet
MONERO_RATE_ATOMIC_AMOUNT=1000000000000
MONERO_RATE_TOKEN_UNITS=5000000
MONERO_MINIMUM_ATOMIC_AMOUNT=1000
MONERO_CONFIRMATIONS_REQUIRED=10
DAOCHI_CHALLENGE_TTL_SECONDS=60
DAOCHI_TOKEN_TTL_SECONDS=3600
DAOCHI_MAX_BODY_BYTES=1048576
DAOCHI_ENCRYPTED_PAYLOAD_MAX_RETURN=0
DAOCHI_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES=0
DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS=0
```

When `MONERO_RATE_ATOMIC_AMOUNT` and `MONERO_RATE_TOKEN_UNITS` are set, every
Daochi account receives one permanent Monero subaddress on first use. Sending
XMR to that address credits the account at the configured integer ratio after
the transfer reaches `MONERO_CONFIRMATIONS_REQUIRED`, is unlocked, has zero
`unlock_time`, and has not been marked as a double spend. Looking up an alias or
public ID returns the same address, so purchasing for yourself and gifting use
the same payment flow. Rate values are snapshotted when a transfer is first
observed. Existing product invoices remain available during migration.

The background reconciler runs whenever `MONERO_WALLET_RPC_URL` is configured,
even with `DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED` unset, so confirmed deposits
keep settling while purchase creation is disabled. The deposit scan keeps a
persisted height bookmark and only fetches transfers from that height onward,
plus the mempool pool. Fixed-price invoices accept partial payments that
accumulate across transfers until they cover the price. A payment that lands
after an invoice expired is still credited by the expired-invoice sweep;
partial funds on an expired invoice cannot be credited or refunded
automatically from a view-only wallet, so they are reported once through the
`daochi_monero_stuck_invoices_total` metric and a warning log for manual
disposition.

The wallet RPC should open a view-only wallet, bind only to loopback, and
require RPC authentication. Daochi needs the wallet-state-changing
`create_address` method, so do not enable `--restricted-rpc`; the view-only
wallet itself prevents spending. The full wallet, mnemonic seed, private spend
key, and their backups must never be copied to the Daochi node.

Create the cold wallet and encrypted view-only deployment bundle on the trusted
computer with:

```sh
MONERO_NETWORK=stagenet MONERO_RESTORE_HEIGHT=0 \
  ./scripts/create_monero_merchant_wallet.sh
```

The script generates independent random wallet and RPC passwords, displays the
mnemonic only through the Monero CLI for offline transcription, and creates two
GPG-encrypted files under `secrets/monero/`. The cold archive contains the
spend-capable wallet. The node archive contains only the view-only wallet and
its runtime credentials. For mainnet, restore the mnemonic offline and verify
the primary address before deploying the view-only archive.

Each node has a persistent Ed25519 identity. By default it is stored beside the database as a mode-`0600` key; production deployments should set `DAOCHI_NODE_IDENTITY_KEY_FILE` explicitly or supply `DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX_FILE`. `DAOCHI_LAN_DISCOVERY=1` advertises `_daochi._tcp.local` with mDNS. Discovery only finds candidates: it never grants trust or starts replication.

Pairing is operator-controlled. Create a short-lived, signed invite with `POST /api/v1/node/pairing/invites`, transfer its JSON as text or a QR payload, and accept it on the other node with `POST /api/v1/node/pairing/accept`. Acceptance automatically posts a signed completion to the inviter, so one invite establishes reciprocal trust while storing directional policy from each node's perspective. The invite is single-use and fixes the peer identity, addresses, direction, apps, collections, trust spaces, and data classes. Paired requests are signed, time-bounded, and replay-protected. If `DAOCHI_ADMIN_TOKEN` is configured, pairing and namespace writes require `X-Daochi-Admin`; without it they are limited to loopback callers. Both nodes need reachable `DAOCHI_BASE_URL` values during pairing.

`DAOCHI_KNOWN_NODES` remains the convenient public-node/bootstrap path. It is a comma-separated peer list whose entries can be `https://node.example`, `Name=https://node.example`, or `Name|https://node.example`. A peer can add `sync=<pull|push|bidirectional|none>`, `apps=inbe`, `collections=private.inbe.v1.*`, `spaces=<space-id>`, and `data=app_registry+encrypted_records+names`. The node worker tries configured and paired peers with pull permission. `DAOCHI_NODE_SYNC_INTERVAL_SECONDS` controls polling and `DAOCHI_NODE_SYNC_BATCH_LIMIT` caps record pages.

The mesh replicates signed app manifests, opaque encrypted app records, deletion tombstones, and signed trust-space names. App manifests are verified against the receiving node's configured registry authority and are installed before records, so a new home or neighbor node can validate collection ownership offline. Social/account projections, payments, and opaque whole-request envelopes remain API or online-authority owned. The old shared `DAOCHI_NODE_SYNC_TOKEN` is still accepted for configured-node migration, but signed pairing is the preferred trust path.

Trust-space naming is an application-level ICANN alternative, not public DNS. An operator creates a local authority with `POST /api/v1/namespaces`, signs names such as `daochi://<space-id>/home` through `POST /api/v1/namespaces/claims`, and resolves them with `GET /api/v1/namespaces/resolve`. Claims replicate to approved peers, but the authority private key does not. Different neighborhoods may intentionally resolve the same label differently; there is no global blockchain or automatic claim that browsers and the public DNS root will recognize these names.

Deletions replicate too: exports carry record tombstones in a separate
`deletions` field, and imports apply them when the tombstone timestamp is at
least as new as the stored record. Older peers that do not know the field
ignore it, so mixed-version meshes keep working. Account deletion and full
client re-syncs (`full_sync_requested`) propagate as per-record tombstones,
and applying an imported delete re-logs it locally, letting a deletion travel
multiple hops.

Generate a token secret once and keep it stable across restarts and every deployed instance:

```sh
openssl rand -hex 32
```

If `DAOCHI_TOKEN_SECRET_HEX` is missing, Daochi generates a random in-memory secret at startup. That is only suitable for single-process local development: existing bearer tokens become invalid after restart, and multi-instance deployments will reject tokens issued by another instance.

Malformed environment values abort startup with the offending key name instead of silently falling back. `GET /metrics` is public only while no admin token is configured; once `DAOCHI_ADMIN_TOKEN` is set, scrape it with `X-Daochi-Admin: <token>`. The exposition includes a `daochi_build_info{version=...}` gauge identifying the running build when the binary was stamped via `make build VERSION=<...>` or the Docker/CI build args.

Encrypted envelope limits are disabled by default to avoid surprising existing clients. Set `DAOCHI_ENCRYPTED_PAYLOAD_MAX_RETURN` to cap each envelope response, `DAOCHI_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES` to reject writes that would exceed an account quota, and `DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS` only after clients can tolerate older envelope pruning.

## Tokens

Daochi can issue signed token receipts for registered assets. The server verifies a payment provider or admin credit, writes an append-only ledger event, and signs the receipt with the configured Ed25519 issuer key. Clients must verify the issuer key and accept only issuer and asset IDs they trust.

Self-hosted Daochi servers may use the same ledger shape for local assets later, but they cannot create receipts for an issuer without that issuer's private key. If only the issuer public key is configured, the server can expose and verify receipts but cannot credit or spend tokens.

Token ledger and payment-intent rows are financial audit records. They are scoped by account for balance and receipt lookup, but they are not included in normal account data export and are not deleted by account-data cascade.

Token purchases, spends, invoices, receipts, and spend nonces carry `app_id`, and spend or purchase flows validate that the app is registered. `GET /api/v1/tokens/balance` and `GET /api/v1/tokens/ledger` stay account-wide by default for compatibility; adding `?app_id=<app>` returns the app-scoped balance or ledger view for that account and asset.

Signed app manifests can publish token policies with `asset_id`, `permission`, `status`, and optional `legacy_unsigned_until`. If an app has no token policies, token endpoints keep the legacy registered-app behavior. If policies exist, spends and purchases require the matching policy, and unsigned legacy requests are accepted only until that policy's `legacy_unsigned_until` timestamp. The registration validator caps that unsigned grace window at 365 days.

Daochi records app-scoped token events, but it does not yet move value between separate account and app allocation pools. Treat app-filtered balances as audit views over the ledger. Explicit account-to-app allocation events are still required before calling per-app token distribution fully complete.

## Signed App Registration

Nodes can accept self-contained, app-owned manifests through `POST /api/v1/apps/register-signed`. The request body contains:

- `manifest`, including `manifest_version`, `app_id`, display metadata, Ed25519 app keys, collection prefixes, capabilities, and optional token policies;
- `manifest_signature`, an Ed25519 signature from one active app key over `daochi-app-manifest-v1\n<canonical manifest json>`;
- `approval_signature`, an Ed25519 signature from the node registry key over `daochi-app-approval-v1\n<app_id>\n<manifest_hash>\n`.

Each node decides which registry approval key it trusts through `DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX` or `DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE`. That keeps registration cross-platform: CLI, TUI, web, mobile, and desktop apps all submit the same signed JSON manifest, and no platform-specific package name is the root of authority.

## Encrypted Hierarchy

Protocol v5 clients should put all new private app data in `encrypted_records` and use typed sync only as a backward-compatibility mirror. Existing released legacy encrypted collections are grandfathered.

New v5 collection names use a dotted hierarchy:

- `account.v1.manifest` for the per-account hierarchy manifest;
- `private.<app>.v<version>.<collection>` for encrypted private app records;
- `shared.<app>.v<version>.<collection>` for user-grantable cross-app records;
- `friends.<app>.v<version>.<collection>` for friend-visible app records;
- `public.<app>.v<version>.<collection>` for intentionally public encrypted/public-record namespaces.

The app ID in every declared collection scope must match the manifest's `app_id`, and the first segment must match the declared visibility. Features may reference only scopes declared in that same manifest. This prevents one app from claiming or describing another app's data.

Future private features should add or extend encrypted collections first. Existing v4 encrypted collections may continue to sync without another migration; new private namespaces should use the v5 hierarchy. Legacy typed schema additions are reserved for compatibility with older clients or for public/server-readable projections.

## Reverse Proxy

Example nginx server block:

```nginx
server {
    server_name api.example.com;

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
