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
bearer-token bytes, HMAC results, malformed inputs, Gregorian dates,
manifest scope/key policy, integer limits, and expiry boundaries against the original contracts and Go standard library.
A fixture extracted from the baseline protects the ported protocol records'
field names, Go storage types, order and reflection tags.

## Production inventory

| Baseline file | Status | Remaining work or canonical source |
|---|---|---|
| `app_manifest.go` | Partial Ziran | Normalization, validation and active-key verification in `manifest.zi`; JSON, approval verification and registry transactions remain Go |
| `app_registry.go` | Partial Ziran | Scope grammar/ownership/matching/SQL escaping in `scope.zi`; grants, registry, handlers remain Go |
| `challenge.go` | Go | Random challenges, expiry, locking, single-use consumption |
| `codec.go` | Ziran | `codec.zi`: exact hexadecimal/base64 decoding and binary encoding |
| `config.go` | Partial Ziran | Environment string sets in `sets.zi`; other settings, products, URLs and keys remain Go |
| `device_keys.go` | Go with ported callers | Device registration, signatures, revocation, replay policy |
| `discovery.go` | Go | LAN discovery and runtime cancellation |
| `docs.go` | Go | Embedded public API documentation |
| `inspect.go` | Go with ported callers | Offline database commands and redaction |
| `log_safety.go` | Ziran | `log_safety.zi`: byte-preserving CR/LF removal |
| `main.go` | Go | Startup, worker supervision, HTTP lifecycle |
| `mesh.go` | Go | Peer requests, retries, authentication, replication |
| `mesh_apps.go` | Partial Ziran | Normalized app sets in `sets.zi`; registry replication and app projections remain Go |
| `mesh_store.go` | Go with ported callers | Mesh export/import and scope enforcement |
| `metrics.go` | Go | Concurrent counters, aggregate usage, text output |
| `monero_deposits.go` | Go with ported callers | Deposit reconciliation and credit transactions |
| `node_auth.go` | Partial Ziran | Canonical message in `signing.zi`; signatures, time window, peer lookup, nonce consumption remain Go |
| `node_identity.go` | Go with ported callers | Identity persistence, invites, pairing, namespace claims |
| `rate_limit.go` | Go | Concurrent request windows and eviction |
| `server.go` | Partial Ziran | Identifier/collection grammars in `identity.zi`; HTTP handlers remain Go |
| `signed_tx.go` | Partial Ziran | Record, normalization, canonical bytes in `transaction.zi`; decoding, verification and replay remain Go |
| `signing.go` | Ziran | `signing.zi`: canonical account/node/approval bytes and raw-body hashing |
| `store.go` | Go with ported callers | Schema, migrations, sync transactions, conflicts, projections |
| `store_timestamps.go` | Go | One-time timestamp migration |
| `sync_ws.go` | Go with ported callers | Authenticated WebSocket framing and connection lifecycle |
| `token.go` | Ziran | `token.zi`: bearer-token issue/verify, decimal parsing, exact expiry behavior |
| `token_assets.go` | Go | Asset seeding transaction |
| `token_money.go` | Go with ported callers | Ledger, receipts, purchase verification, invoices, checkpoints |
| `trust_handlers.go` | Go with ported callers | Pairing and namespace HTTP handlers |
| `trust_store.go` | Go with ported callers | Peer trust, pairing, claims, nonce persistence |
| `types.go` | Ziran | All 77 original records and profile constants in `protocol.zi`, `manifest.zi`, `sync_types.zi` and `types.zi` |
| `verifier.go` | Go | Signature verifier contract |
| `verifier_nocgo.go` | Go | Unsupported-build error path |
| `verifier_oqs.go` | Go | ML-DSA-44 foreign-library boundary and resource ownership |
| `version.go` | Go | Build-stamped version |

`identity.zi` is a new canonical module extracted from `server.go`. Generated
`vec.go`, `constant_time.go`, `hmac_sha256_go.go`, `map_go.go` and `go_types.go`
come from Ziran's standard
modules; they do not represent additional completed baseline modules.
`manifest.zi` owns app manifest, key, token policy and registry records.
`transaction.zi` also owns the signed grant record. Their HTTP/database
operations still need to move. Manifest normalization and validation preserve
error text, byte limits, scopes, Gregorian dates and explicit expiry boundaries.
Active-key verification selects eligible keys in Ziran and uses Go Ed25519.

`sync_types.zi` owns sync requests, responses, changes, snapshots and operation
records. Its `RawMessage` declaration aliases `encoding/json.RawMessage`,
preserving raw JSON payloads and Go type identity. Maintained callers use
`SocialSnapshot` directly; released `social_cache` fields are unchanged.

`types.zi` owns account export and diagnostic records. Their map fields keep
the original `map[string][]map[string]any` and `map[string]int` Go types and
JSON behavior. `sets.zi` owns environment parsing and app-name normalization,
including Unicode whitespace/case conversion and allocated empty results.

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

`Map(K, V)` in `map_go` emits native Go maps with typed operations, shared
storage, automatic initialization on insertion and a nil zero value. Its
lookup operation distinguishes absent keys from zero values. Maps are currently
Go-specific; other targets and the portable ABI reject them. Map mutation in
parallel regions is rejected because copies share storage. Predeclared `any`
and `error` types are available through `go_types`; boxing owned vectors is
rejected to preserve ownership.

## Next dependencies

Protocol fields now support checked Go reflection tags, including JSON names
and omission rules. Opaque foreign Go type declarations preserve imported
type identity, interface values, zero values and custom JSON methods in source
and saved IR. Network and database code still needs interface operations,
multiple results/error handling, method calls,
variadic SQL arguments, contexts, synchronization, and worker lifecycle support.
These are reusable compiler/runtime capabilities to implement upstream in
Ziran as the corresponding application code moves; wrapping existing Go
application functions does not complete their port.

Completion requires auditing every remaining production module, the test
coverage, CLI and deployment paths, and compatibility with released clients.
The current mixed-language server is an intermediate checkpoint.
