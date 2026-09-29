# Daochi Ziran port

The target is a complete port of Daochi's first-party code to Ziran. This is
an incremental implementation: the running server currently combines generated
Go from canonical `.zi` files with substantial handwritten Go. Caller changes
alone do not count as a completed module.

The baseline is commit `30f291e`: 35 root production Go files (17,580 lines)
and 17 root Go test files (6,206 lines). The separate `daochi-client` repository
already uses Ziran; it is not a replacement for porting this server.

## Canonical source and verification

Edit root `.zi` files, then run:

```sh
make generate
make test-ziran
make test-ziran GOFLAGS='-mod=mod -race -count=1'
```

`make generate` invokes `../ziran/build/bin/zi2go` and formats the generated Go.
Set `ZI2GO` and `ZIRAN_STD` for another compiler or standard module location.
Generated Go is committed so ordinary Go and container builds work without
having a compiler checkout installed. `make check-generated` detects drift.

`make test-ziran` checks generation, runs the existing server suite, saves all
Ziran modules as checked `.zir`, regenerates Go from those saved modules, and
runs the same suite through a Go overlay. No alternate source checkout is used.
The existing Go tests remain regression oracles during the port; they have not
yet been ported in full.

Additional regression cases compare binary decoding, identifier grammars,
bearer-token bytes, HMAC results, malformed inputs, integer limits, and expiry
boundaries against the original contracts and Go standard library.

## Production inventory

| Baseline file | Status | Remaining work or canonical source |
|---|---|---|
| `app_manifest.go` | Go with ported callers | Manifest normalization, validation, signatures, registry transactions |
| `app_registry.go` | Go with ported callers | App scopes, grants, registration, handlers |
| `challenge.go` | Go | Random challenges, expiry, locking, single-use consumption |
| `codec.go` | Ziran | `codec.zi`: exact hexadecimal/base64 decoding and binary encoding |
| `config.go` | Go | Environment settings, products, URLs, keys |
| `device_keys.go` | Go with ported callers | Device registration, signatures, revocation, replay policy |
| `discovery.go` | Go | LAN discovery and runtime cancellation |
| `docs.go` | Go | Embedded public API documentation |
| `inspect.go` | Go with ported callers | Offline database commands and redaction |
| `log_safety.go` | Ziran | `log_safety.zi`: byte-preserving CR/LF removal |
| `main.go` | Go | Startup, worker supervision, HTTP lifecycle |
| `mesh.go` | Go | Peer requests, retries, authentication, replication |
| `mesh_apps.go` | Go | Registry replication and app projections |
| `mesh_store.go` | Go with ported callers | Mesh export/import and scope enforcement |
| `metrics.go` | Go | Concurrent counters, aggregate usage, text output |
| `monero_deposits.go` | Go with ported callers | Deposit reconciliation and credit transactions |
| `node_auth.go` | Go with ported callers | Node signatures, time window, trusted-peer lookup, nonce consumption |
| `node_identity.go` | Go with ported callers | Identity persistence, invites, pairing, namespace claims |
| `rate_limit.go` | Go | Concurrent request windows and eviction |
| `server.go` | Partial Ziran | Identifier/collection grammars in `identity.zi`; HTTP handlers remain Go |
| `signed_tx.go` | Go with ported callers | Transaction decoding, normalization, signatures, replay checks |
| `signing.go` | Ziran | `signing.zi`: canonical signed request bytes and raw-body hashing |
| `store.go` | Go with ported callers | Schema, migrations, sync transactions, conflicts, projections |
| `store_timestamps.go` | Go | One-time timestamp migration |
| `sync_ws.go` | Go with ported callers | Authenticated WebSocket framing and connection lifecycle |
| `token.go` | Ziran | `token.zi`: bearer-token issue/verify, decimal parsing, exact expiry behavior |
| `token_assets.go` | Go | Asset seeding transaction |
| `token_money.go` | Go with ported callers | Ledger, receipts, purchase verification, invoices, checkpoints |
| `trust_handlers.go` | Go with ported callers | Pairing and namespace HTTP handlers |
| `trust_store.go` | Go with ported callers | Peer trust, pairing, claims, nonce persistence |
| `types.go` | Go | Protocol records, JSON field names/omission, dynamic payloads |
| `verifier.go` | Go | Signature verifier contract |
| `verifier_nocgo.go` | Go | Unsupported-build error path |
| `verifier_oqs.go` | Go | ML-DSA-44 foreign-library boundary and resource ownership |
| `version.go` | Go | Build-stamped version |

`identity.zi` is a new canonical module extracted from `server.go`. Generated
`vec.go`, `constant_time.go`, and `hmac_sha256_go.go` come from Ziran's standard
modules; they do not represent additional completed baseline modules.

## Compiler work exercised by this port

Ziran now accepts explicit `go:` foreign package imports, including standard
packages with no slash. These are direct package calls in source and saved IR.
HMAC-SHA256 construction and constant-time byte-string comparison live in
standard Ziran modules; SHA-256 uses the Go standard cryptographic primitive.

Direct generic applications such as `Vec(u8)` retain their template and type
arguments across module boundaries and checked IR. Matching applications share
one concrete native type and work in portable bundles; different arguments or
different templates remain incompatible. Regression fixtures exercise source
and saved IR in C, C++, Go, and the portable runtime.

## Next dependencies

Protocol records need preserved JSON field names and omission rules, external
Go types such as `json.RawMessage`, and dynamic maps. Network and database code
also needs interfaces, multiple results/error handling, method calls,
variadic SQL arguments, contexts, synchronization, and worker lifecycle support.
These are reusable compiler/runtime capabilities to implement upstream in
Ziran as the corresponding application code moves; wrapping existing Go
application functions does not complete their port.

Completion requires auditing every remaining production module, the test
coverage, CLI and deployment paths, and compatibility with released clients.
The current mixed-language server is an intermediate checkpoint.
