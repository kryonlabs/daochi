# Daochi Small Node Operations

Daochi should remain practical on modest machines and home nodes. These targets
turn that value into an operational checklist.

## Small Node Target

A small node is expected to run with:

- one Go server process;
- SQLite storage on local disk;
- a reverse proxy terminating TLS;
- no background job queue beyond Daochi's own sync workers;
- enough memory to run comfortably on a 1 GB VM or small home server.

## Default Posture

- Keep `DAOCHI_ADDR` bound to loopback behind a reverse proxy.
- Set a stable `DAOCHI_TOKEN_SECRET_HEX` before production use.
- Set `DAOCHI_NODE_IDENTITY_KEY_FILE` explicitly so node identity survives
  process restarts and deploys.
- Leave direct purchases, LAN discovery, and node sync disabled until the node
  operator intentionally enables them.

## Resource Targets

- Idle CPU should be near zero when there are no active syncs, WebSockets, or
  background reconciliation tasks.
- SQLite is the primary state store; avoid adding external services for core
  sync paths.
- Batch limits should favor bounded memory over maximum throughput.
- Old protocol clients should remain compatible through the published window
  instead of forcing immediate upgrades.

## Inspectability Checklist

Operators should be able to answer:

- Which node identity key is this process using?
- Which protocol versions are accepted?
- Which app registry authority is trusted?
- Which apps and collection prefixes are active?
- Which peers are paired or configured?
- Which data surfaces are server-readable by design?

Current endpoints that help answer those questions:

- `GET /api/v1/node`
- `GET /api/v1/node/peers`
- `GET /api/v1/apps`
- `GET /api/v1/apps/{app_id}`
- `GET /api/v1/sync/diagnostics`
- `GET /metrics`

## Rollout Checks

Before exposing a node publicly:

- `GET /healthz` returns 200;
- `GET /readyz` returns 200;
- `GET /api/v1/node` shows the expected node name and protocol bounds;
- `/metrics` is protected by `X-Daochi-Admin` when an admin token is set;
- backups include the SQLite database and node identity key;
- restore has been tested on a separate machine or directory.
