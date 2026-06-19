# Lyra Sync Server

Lyra is the stateless sync relay for Inbe. It stores public keys and mirrored app data, but never stores client private keys.

## Endpoints

- `GET /api/v1/sync/challenge?user_id=<sha256-public-key-hex>`
- `POST /api/v1/sync`
- `DELETE /api/v1/account`
- `GET /healthz`

`api.waozi.xyz` should terminate TLS at a reverse proxy and forward to `LYRA_ADDR`, for example `127.0.0.1:8080`.

## Signature Message

Clients must sign this exact byte string with ML-DSA-44:

```text
inbe-sync-v1
<HTTP_METHOD>
<HTTP_PATH>
<sha256 hex of canonical signed payload>
<challenge nonce hex>
```

The canonical signed payload is the request JSON object with the top-level `signature` field removed, encoded as deterministic JSON with lexicographically sorted object keys and no insignificant whitespace. The challenge is single-use and expires after 60 seconds by default.

The server accepts `public_key` and `signature` as either base64 or lowercase/uppercase hex. This matches the current C client account storage, which keeps ML-DSA-44 keys as hex strings.

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
LYRA_CHALLENGE_TTL_SECONDS=60
LYRA_MAX_BODY_BYTES=1048576
```

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
- `server_preferences`
- `server_habits`
- `server_habit_days`
- `server_sessions`
- `server_session_rounds`

Deleting an account removes all rows through foreign-key cascade.
