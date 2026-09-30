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
manifest scope/key policy, integer limits, expiry boundaries, concurrent
request counts, single-use challenges and proxy trust against the original
contracts and Go standard library. Metrics cases also compare exact Prometheus
bytes and headers, label normalization, counter overflow, concurrent recording
and cleanup after response-writer panics with the original implementation.
Timestamp cases compare parsing, UTC formatting, fallback rules, database
contents, schema-version guards, cancellation and transaction rollback against
the original implementation.
A fixture extracted from the baseline protects the ported protocol records'
field names, Go storage types, order and reflection tags.

## Production inventory

| Baseline file | Status | Remaining work or canonical source |
|---|---|---|
| `app_manifest.go` | Partial Ziran | Normalization, validation and active-key verification in `manifest.zi`; JSON, approval verification and registry transactions remain Go |
| `app_registry.go` | Partial Ziran | Scope grammar/ownership/matching/SQL escaping in `scope.zi`; grants, registry, handlers remain Go |
| `challenge.go` | Ziran | `challenge.zi`: random challenges, expiry, locking, replacement, single-use consumption and base64 preview |
| `codec.go` | Ziran | `codec.zi`: exact hexadecimal/base64 decoding and binary encoding |
| `config.go` | Ziran | `config.zi`: all fields, environment/file loading, startup settings, strict errors, ephemeral secrets and Ed25519 keys; parsers in `config_values.zi` and `sets.zi` |
| `device_keys.go` | Go with ported callers | Device registration, signatures, revocation, replay policy |
| `discovery.go` | Go | LAN discovery and runtime cancellation |
| `docs.go` | Go | Embedded public API documentation |
| `inspect.go` | Go with ported callers | Offline database commands and redaction |
| `log_safety.go` | Ziran | `log_safety.zi`: byte-preserving CR/LF removal |
| `main.go` | Go | Startup, worker supervision, HTTP lifecycle |
| `mesh.go` | Go | Peer requests, retries, authentication, replication |
| `mesh_apps.go` | Partial Ziran | Normalized app sets in `sets.zi`; registry replication and app projections remain Go |
| `mesh_store.go` | Go with ported callers | Mesh export/import and scope enforcement |
| `metrics.go` | Ziran | `metrics.zi`: concurrent counters, route/reason normalization, escaped labels, sorted maps, aggregate usage and exact Prometheus output |
| `monero_deposits.go` | Go with ported callers | Deposit reconciliation and credit transactions |
| `node_auth.go` | Ziran | `node_auth.zi`: random nonces, exact request signatures, native HTTP fields/escaped paths, time windows, trusted-peer lookup and single-use consumption |
| `node_identity.go` | Ziran | `node_identity.zi`: copied native key material, private key-file persistence, pairing records/messages/signatures/validation and namespace claim records/messages/name grammar |
| `rate_limit.go` | Ziran | `rate_limit.zi`: concurrent request windows and eviction; `client_address.zi`: native HTTP/IP access, loopback-only proxy trust and address normalization |
| `server.go` | Partial Ziran | Identifier/collection grammars in `identity.zi`; HTTP handlers remain Go |
| `signed_tx.go` | Partial Ziran | Record, normalization, canonical bytes in `transaction.zi`; decoding, verification and replay remain Go |
| `signing.go` | Ziran | `signing.zi`: canonical account/node/approval bytes and raw-body hashing |
| `store.go` | Partial Ziran | Timestamp parsing/normalization in `timestamp.zi`; schema, sync transactions, conflicts and projections remain Go |
| `store_timestamps.go` | Ziran | `store_timestamps.zi`: version guard, all 14 columns, canonical rewrites, error wrapping and atomic transaction cleanup |
| `sync_ws.go` | Go with ported callers | Authenticated WebSocket framing and connection lifecycle |
| `token.go` | Ziran | `token.zi`: bearer-token issue/verify, decimal parsing, exact expiry behavior |
| `token_assets.go` | Ziran | `token_assets.zi`: native SQL upsert, released asset fields and error propagation |
| `token_money.go` | Go with ported callers | Ledger, receipts, purchase verification, invoices, checkpoints |
| `trust_handlers.go` | Go with ported callers | Pairing and namespace HTTP handlers |
| `trust_store.go` | Ziran | `trust_store.zi`: schema, atomic pairing, peer policy/list queries, trust spaces, namespace signing/resolution and scoped mesh name replication; nonces in `node_nonce.zi`, public-key lookup in `peer_trust.zi` |
| `types.go` | Ziran | All 77 original records and profile constants in `protocol.zi`, `manifest.zi`, `sync_types.zi` and `types.zi` |
| `verifier.go` | Go | Signature verifier contract |
| `verifier_nocgo.go` | Go | Unsupported-build error path |
| `verifier_oqs.go` | Go | ML-DSA-44 foreign-library boundary and resource ownership |
| `version.go` | Ziran | `version.zi`: default build version, stamped through Makefile and Docker linker arguments |

`identity.zi` is a new canonical module extracted from `server.go`. Generated
`vec.go`, `constant_time.go`, `hmac_sha256_go.go`, `map_go.go`, `go_types.go`,
`option.go`, `sync_go.go`, `time_go.go`, `random_go.go`, `text_go.go`,
`net_go.go`, `http_go.go`, `atomic_go.go`, `context_go.go`, `sql_go.go` and
`errors_go.go`, `ed25519_go.go`, `url_go.go`, `file_go.go` and `json_go.go`
come from Ziran's standard modules; they do not represent
additional completed baseline modules.
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
`config_values.zi` owns peer/product parsing and sync-policy normalization,
including duplicate selection, nil/empty results, integer limits, policy field
order and Unicode handling. Tests compare the baseline Go parsers against
source and saved IR on table cases and 1,000 arbitrary byte strings.
`config.zi` completes the configuration module, including file precedence,
native integer overflow, duration multiplication, strict startup failures,
random development secrets and Ed25519 seed/private/public key handling.
Tests compare every field and its native Go type against the original loader,
verify fallback storage and public-key copying, and compare fatal messages
and exit status in isolated subprocesses. Maintained startup and inspection
callers use the generated configuration surface directly.

`challenge.zi` and `rate_limit.zi` own their state, map updates, locking and
expiry decisions. They keep Go's monotonic timestamps and exact strict expiry
boundaries through standard primitives. Challenge consumption deletes the
nonce before checking its expiry, preserving single-use behavior. Race tests
exercise shared request counters and simultaneous consumers.

`client_address.zi` also owns every address helper originally in
`rate_limit.go`. It reads native HTTP fields through reusable compiler getters;
no handwritten application adapter remains. Regression cases compare Unicode
whitespace, malformed inputs, IPv4/IPv6 canonicalization and proxy trust with
the baseline policy. Forwarded addresses remain trusted only for direct
loopback peers, and only the first hop/header value can select the bucket.

`metrics.zi` owns the entire original metrics module. Atomic counters stay in
shared native storage. Map recording and scraping keep the original mutex,
lazy initialization and ordering. Prometheus output retains released metric
names, escapes, integer behavior and storage clamping. Scraping unlocks the
mutex during native panic unwinding as well as ordinary returns; a failing
response writer cannot leave subsequent recording blocked. The build version
comes from `version.zi`; Makefile and Docker builds stamp its native string
variable, and unstamped builds report `dev`.

`timestamp.zi` owns the original storage timestamp helpers, including RFC 3339
and SQLite parsing, fixed nanosecond fractions, UTC conversion and malformed
timestamp ordering. `store_timestamps.zi` owns the complete one-time migration.
It uses native SQL handles directly, gathers rewrites before updating each
column, leaves null/blank/unparseable values unchanged and commits the schema
version with all rewrites. Native deferred rollback preserves cleanup on error
and panic. Regression fixtures compare every migrated column with the original
implementation, verify that repeat runs are skipped and force a late failure
to check rollback of earlier changes and connection reuse.

`node_nonce.zi` owns peer-request nonce persistence. Expiry cleanup and nonce
insertion commit together, and failed insertion rolls back cleanup. Duplicate
nonces retain the released replay error, while begin, deletion and commit
errors retain native identity. Native Go error operations and package-value
getters preserve SQL/context sentinel errors without handwritten adapters.

`node_auth.zi` completes the original request authentication module. Signing
preserves the exact canonical message, raw URL base64 encoding, cryptographic
nonce generation and escaped URL path. Verification preserves Unicode header
trimming, the five-minute time window, validation order, peer revocation and
key-length checks, signature decoding and atomic nonce consumption. Native
SQL and cancellation errors retain their identity. Baseline comparisons also
exercise signature line breaks and malformed headers, and concurrent replay
tests accept a shared signed request exactly once. `peer_trust.zi` owns the
trusted-peer public-key query.

`node_identity.zi` completes key creation and persistence, pairing invitations
and acceptances, their signatures and validation, and namespace claim messages
and naming helpers. Key loading retains seed/private-key support, Unicode
whitespace, wrapped hexadecimal errors, private file/directory permissions,
atomic rename and removal of temporary secrets after rename failure. Identity
construction copies both keys into independent storage. Messages retain JSON
hashes, sorted address copies, exact integer formatting and raw URL base64
signatures. Validation retains its original order and expiry boundaries.
Independent baseline fixtures cover the six record layouts, key ownership,
filesystem/entropy failures, signatures, malformed input and native errors.

`trust_store.zi` completes the original trust store. It preserves schema,
single-use invite consumption, reciprocal policies, idempotent completion,
revocation filtering and nil/empty JSON results. Namespace operations retain
authority keys, claim signatures, expiry, sequence ordering and fork rejection.
Scoped imports commit together and roll back all writes on a late failure;
export never includes authority private keys. Baseline comparisons cover stored
state, malformed JSON, cancellation and entropy errors, failed commits,
connection reuse, concurrent invite consumers and record reflection tags.
`mesh_policy.zi` owns the shared data-scope and reciprocal-direction helpers.

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

Typed Go receiver expressions, native field getters and record-packed multiple
results now survive checked IR. `#go_results` preserves the native error
interface and result order. `#go_field` reads declared native fields without
redeclaring their opaque layout. Typed `go:builtin` operations provide heap
allocation, slice/map construction, copied byte strings and native lengths.
Typed single-element `append` preserves nil slices, lengths, capacities and
shared backing storage while rejecting owned vector elements.
Compiler tests compare source and saved IR, including altered diagnostic
declaration strings, to ensure typed metadata controls generation.
`#go_defer` schedules a checked foreign Go call at the calling function's exit,
captures its arguments immediately and preserves panic cleanup. The new
`atomic_go` module and native response-writer/header operations provide the
shared counter and HTTP primitives used by the metrics port. Foreign generic
signatures now normalize their concrete type applications before checking,
including ownership restrictions on deferred calls.
Explicit conversions between native Go aliases and slices preserve backing
storage and keep returned data alive. Typed Go `panic` preserves error
identity; configuration uses it for the cryptographic-random failure path.
The `context_go`, `sql_go` and extended `time_go` standard modules provide
native contexts, SQL iteration/cleanup and timestamp parsing/formatting.
Imported record fields retain their declared type identity through additional
modules, including qualified procedure parameters in portable bundles.
The `ed25519_go` and `url_go` modules provide native key types, signature
operations and escaped paths. Extended HTTP/time operations read the original
request method, URL pointer and Unix timestamp. `text_go.ToBytes` produces an
independent, byte-preserving slice, including allocated empty values.
The `file_go` and `json_go` modules provide native file permissions, path/error
operations and JSON serialization/deserialization. Go interface arguments
preserve record tags, nil/empty slices and pointer destinations. Native key
generation preserves public/private/error result order and entropy errors.
Native public-key equality and SQL affected-row results preserve Go key types,
64-bit counts and error identity in both source and saved IR.

## Next dependencies

Protocol fields now support checked Go reflection tags, including JSON names
and omission rules. Opaque foreign Go type declarations preserve imported
type identity, interface values, zero values and custom JSON methods in source
and saved IR. Go primitives now provide method calls, multiple results,
HTTP field access, error interfaces and mutex synchronization. Network and
database code still needs broader interface operations, reusable variadic SQL
arguments, cancellation/deadline operations and worker lifecycle support.
These are reusable compiler/runtime capabilities to implement upstream in
Ziran as the corresponding application code moves; wrapping existing Go
application functions does not complete their port.

Completion requires auditing every remaining production module, the test
coverage, CLI and deployment paths, and compatibility with released clients.
The current mixed-language server is an intermediate checkpoint.
