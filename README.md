# Lyra Sync Server

Lyra is the stateless sync relay for Inbe. It stores public keys and mirrored app data, but never stores client private keys.

## Privacy Model

Lyra uses the client account key for identity and authentication. A client proves control of the account by signing a short-lived challenge with ML-DSA-44, and Lyra then issues a bearer token for normal sync and social API calls.

Lyra does not currently provide end-to-end encryption against the server. Mirrored app data is stored in SQLite as normal typed rows and JSON payloads so the service can sync, compact, export, derive friend leaderboard stats, and delete account data. This is intentional. Operational access to the server database or a valid bearer token can read the data those credentials allow.

API access is scoped by account, with explicit shared surfaces:

- accepted friends can see the account alias and selected profile/leaderboard stats;
- pending friend request participants can see the request metadata;
- public governance processes, proposals, and votes are public by design.

## Endpoints

- `GET /api/v1/sync/challenge?user_id=<sha256-public-key-hex>`
- `GET /api/v1/sync/ws`
- `POST /api/v1/sync/login`
- `POST /api/v1/sync`
- `POST /api/v1/account/alias`
- `GET /api/v1/account/export`
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
- `GET /`

`api.waozi.xyz` should terminate TLS at a reverse proxy and forward to `LYRA_ADDR`, for example `127.0.0.1:8080`.
Set `LYRA_TOKEN_SECRET_HEX` to at least 32 random bytes encoded as hex in production.
`LYRA_ALLOW_EPHEMERAL_TOKEN_SECRET=1` is only for local development because it invalidates tokens on restart and is not a stable server secret.

## Signature Message

Clients must sign this exact byte string with ML-DSA-44:

```text
inbe-sync-v1
<HTTP_METHOD>
<HTTP_PATH>
<sha256 hex of exact raw request body bytes>
<challenge nonce hex>
```

The challenge response returns `nonce` as lowercase hex. The challenge is single-use and expires after 60 seconds by default.

Signed `POST /api/v1/sync` and `DELETE /api/v1/account` requests must include:

- `X-Inbe-User: <sha256-public-key-hex>`
- `X-Inbe-Signature: <ML-DSA-44 signature>`
- `Content-Type: application/json`

The JSON body still includes `user_id_hash`, and first sync includes `public_key`. The server accepts `public_key` and `X-Inbe-Signature` as either base64 or lowercase/uppercase hex. This matches the current C client account storage, which keeps ML-DSA-44 keys as hex strings.

The website deletion endpoint `POST /api/v1/account/delete-with-key` accepts `user_id_hash` plus the full exported account key text. Generic exports start with `account-key-v1`; legacy Inbe exports starting with `inbe-sync-key-v1` are still accepted. Current key exports include `public_id`, and Lyra rejects a request if that public ID does not match `user_id_hash`. Lyra signs a fixed deletion proof with that private key, verifies it against the registered public key, deletes the account, and does not store the uploaded key.

## Build

From this project directory, build with:

```sh
make build
```

The Makefile builds a minimal static liboqs from `vendor/liboqs` with `SIG_ml_dsa_44` enabled, then passes the right cgo include/library flags to Go. Use `make test` for the same setup in tests.

Without Nix, install liboqs headers and library on the host, then:

```sh
CGO_ENABLED=1 go build -o lyra .
```

Runtime configuration:

```sh
LYRA_ADDR=127.0.0.1:8080
LYRA_BASE_URL=https://api.waozi.xyz
LYRA_DB=/var/lib/lyra/lyra.db
LYRA_TOKEN_SECRET_HEX=<stable 64+ hex chars shared by every server instance>
LYRA_CHALLENGE_TTL_SECONDS=60
LYRA_MAX_BODY_BYTES=1048576
```

Generate a token secret once and keep it stable across restarts and every deployed instance:

```sh
openssl rand -hex 32
```

If `LYRA_TOKEN_SECRET_HEX` is missing, Lyra generates a random in-memory secret at startup. That is only suitable for single-process local development: existing bearer tokens become invalid after restart, and multi-instance deployments will reject tokens issued by another instance.

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
- `server_sessions`
- `server_session_rounds`
- `server_friend_requests`
- `server_friendships`
- `server_profile_stats`

Deleting an account removes all rows through foreign-key cascade.
