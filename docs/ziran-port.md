# Daochi Ziran port

The target is a complete port of Daochi's first-party code to Ziran. This is
an incremental implementation: the running server currently combines generated
Go from canonical `.zi` files with substantial handwritten Go. Caller changes
alone do not count as a completed module.

The goal is Daochi's complete port. Ziran's existing C compiler/bootstrap is
allowed to remain; upstream changes are made only when Daochi needs a language,
backend, or standard-library capability. Fully self-hosting Ziran is a separate
project and is not a prerequisite for this port.

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

`make generate` invokes `ziran build --project --target=go` and formats the
generated Go. The committed `ziran.lock` pins the compiler and standard library;
standard imports use explicit `std/` paths. Override `ZIRAN` to choose the
launcher. The launcher resolves the project's toolchain through package commands.
Without local overrides, generation and saved-IR checks require `--locked`.
For development in the organization-based workspace, create an ignored
`ziran.local.toml`:

```toml
[overrides]
ziran = "../../ziranlang/ziran"
```

With a local override, run `ziran lock` after committing an upstream compiler
change to record that checkout's exact commit. Run `ziran update ziran` to
refresh the pin from the published toolchain ref.
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
| `app_manifest.go` | Ziran | Normalization, validation and active-key verification in `manifest.zi`; manifest storage in `app_store.zi`; decoding, signed approval verification and exact JSON/hash bytes in `app_registration.zi`; signed registration HTTP handling in `app_http.zi` |
| `app_registry.go` | Ziran | Scope policy in `scope.zi`; app seeding, registry queries, metadata and collection ownership in `app_store.zi`; decoding in `app_registration.zi`; grant transactions and authorized reads in `app_grants.zi`; registry, grant and record HTTP handlers in `app_http.zi` |
| `challenge.go` | Ziran | `challenge.zi`: random challenges, expiry, locking, replacement, single-use consumption and base64 preview |
| `codec.go` | Ziran | `codec.zi`: exact hexadecimal/base64 decoding and binary encoding |
| `config.go` | Ziran | `config.zi`: all fields, environment/file loading, startup settings, strict errors, ephemeral secrets and Ed25519 keys; parsers in `config_values.zi` and `sets.zi` |
| `device_keys.go` | Ziran | Records, canonical messages, validation, signature verification, atomic registration/revocation, nonce cleanup and key queries in `device_keys.zi`; HTTP handling in `device_http.zi` |
| `device_handlers.go` | Ziran | `device_http.zi`: authenticated device listing, registration and revocation, ordered body/signature validation, replay errors and response serialization |
| `discovery.go` | Ziran | `discovery.zi`: LAN advertisement metadata, native registration/shutdown, listener ports and cancellable resource lifecycle |
| `docs.go` | Ziran | `docs.zi`: public HTML, typed OpenAPI map builders, cached JSON and both HTTP handlers; public statistics remain a storage dependency |
| `inspect.go` | Ziran | `inspect.zi`: read-only database access, native flag parsing, summary/user/doctor commands, warnings, ordered queries, byte-preserving redaction and output |
| `log_safety.go` | Ziran | `log_safety.zi`: byte-preserving CR/LF removal |
| `main.go` | Go | Startup, worker supervision, HTTP lifecycle |
| `mesh.go` | Ziran | `mesh.zi`: HTTP export/import, signed/token authentication, approved-scope checks, configured/trusted peer selection, signed outbound requests, pagination, cursor persistence and the cancellable recurring worker; wire records, cursors and scope predicates in `mesh_types.zi`, `mesh_cursor.zi` and `mesh_policy.zi`; native authentication error conversion is supplied by the caller |
| `mesh_apps.go` | Ziran | `mesh_apps.zi`: scoped signed registry export/import, manifest decoding, signature verification, version queries, downgrade/fork rejection and per-app transactions; native authentication error conversion remains supplied by the Go caller |
| `mesh_store.go` | Ziran | `mesh_store.zi`: encrypted-record export/import, stable change ordering, account tombstones, conflicts, deletion propagation, cursor persistence and atomic rollback; collection ownership in `collection_scope.zi`, record validation in `encrypted_record.zi` |
| `metrics.go` | Ziran | `metrics.zi`: concurrent counters, route/reason normalization, escaped labels, sorted maps, aggregate usage and exact Prometheus output |
| `monero_deposits.go` | Ziran | `monero_deposits.zi`: account address/deposit HTTP handling, transfer polling, confirmation checks and reconciliation; `monero_deposit_store.zi`: account addresses, scan height, transfer ownership, deposit upserts, atomic ledger crediting and ordered queries; wallet calls in `monero_wallet.zi` |
| `node_auth.go` | Ziran | `node_auth.zi`: random nonces, exact request signatures, native HTTP fields/escaped paths, time windows, trusted-peer lookup and single-use consumption |
| `node_identity.go` | Ziran | `node_identity.zi`: copied native key material, private key-file persistence, pairing records/messages/signatures/validation and namespace claim records/messages/name grammar |
| `rate_limit.go` | Ziran | `rate_limit.zi`: concurrent request windows and eviction; `client_address.zi`: native HTTP/IP access, loopback-only proxy trust and address normalization |
| `server.go` | Partial Ziran | Protocol bounds in `protocol.zi`; identifier/collection grammars in `identity.zi`, encrypted-record and metadata validation in `encrypted_record.zi`; random resource identifiers in `resource_id.zi`; bounded JSON bodies in `http_body.zi`, JSON responses in `response.zi`, header selection and bearer authentication in `http_auth.zi`; alias, profile icon and account export in `account_http.zi`; friend/request and profile-stat HTTP handling in `social_http.zi`; sync/login/deletion, operational handlers, middleware and server construction remain Go |
| `signed_tx.go` | Ziran | `signed_tx.zi`: header decoding, ordered validation, account/device signatures, expiry, replay recording and exact forgetting; record and canonical bytes in `transaction.zi`, JSON serialization in the standard library |
| `signing.go` | Ziran | `signing.zi`: canonical account/node/approval bytes and raw-body hashing |
| `store.go` | Partial Ziran | Public statistics record in `types.zi`; timestamp helpers in `timestamp.zi`, public-key lookup in `account_keys.zi`, transactional registration/account touch, version allocation, affected-row counts and tombstone queries in `account_state.zi`; aliases/icons in `account_profile.zi`, account resolution in `account_lookup.zi`, friendships and profile-stat storage in `friend_store.zi`, account export in `account_export.zi`, friend leaderboards in `leaderboard.zi`, social snapshot writes in `social_cache.zi`; key/hash checks in `encrypted_record.zi`, collection matching in `collection_scope.zi`; schema, operational statistics, sync transactions, conflicts and projections remain Go |
| `store_timestamps.go` | Ziran | `store_timestamps.zi`: version guard, all 14 columns, canonical rewrites, error wrapping and atomic transaction cleanup |
| `sync_ws.go` | Ziran | `sync_ws.zi`: authenticated upgrades, account and IP limits, reader worker, event/ping selection, deadlines and cancellation; `websocket.zi`: native handshakes and exact frame encoding/validation; `sync_hub.zi`: scoped subscriptions, bounded event delivery, counts and disconnect cleanup |
| `token.go` | Ziran | `token.zi`: bearer-token issue/verify, decimal parsing, exact expiry behavior |
| `token_assets.go` | Ziran | `token_assets.zi`: native SQL seed/upsert, sorted asset listing, released fields, row cleanup and error propagation |
| `token_money.go` | Ziran | `token_ledger.zi`: balances, scoped ledger/receipt queries, atomic payment crediting, collision checks, idempotent spending and rollback; `token_receipt.zi`: validation, canonical bytes, hashes and Ed25519 signatures; `token_checkpoint.zi`: signed ledger checkpoints; `token_policy.zi`: issuer and signed app authorization; `payment_request.zi`: purchase and spending request validation; `token_http.zi`: asset/product/issuer, balance/ledger/receipt, spend, checkpoint and admin HTTP handlers; Google verification and OAuth in `google_play.zi`, purchase HTTP in `google_play_http.zi`; Monero wallet operations in `monero_wallet.zi`, invoice storage in `monero_invoice_store.zi`, invoice HTTP and recurring reconciliation in `monero_invoices.zi`; payment errors in `payment_state.zi` |
| `trust_handlers.go` | Ziran | `trust_http.zi`: operator access, signed pairing invitations/acceptances, outbound completion and retries, trusted-peer listing, trust-space creation and namespace registration/resolution |
| `trust_store.go` | Ziran | `trust_store.zi`: schema, atomic pairing, peer policy/list queries, trust spaces, namespace signing/resolution and scoped mesh name replication; nonces in `node_nonce.zi`, public-key lookup in `peer_trust.zi` |
| `types.go` | Ziran | All 77 original records and profile constants in `protocol.zi`, `manifest.zi`, `sync_types.zi` and `types.zi` |
| `verifier.go` | Go | Signature verifier contract |
| `verifier_nocgo.go` | Go | Unsupported-build error path |
| `verifier_oqs.go` | Go | ML-DSA-44 foreign-library boundary and resource ownership |
| `version.go` | Ziran | `version.zi`: default build version, stamped through Makefile and Docker linker arguments |

`identity.zi` is a new canonical module extracted from `server.go`. Generated
`std_*.go` files come from the pinned Ziran standard modules; they do not
represent additional completed baseline modules.
`manifest.zi` owns app manifest, key, token policy and registry records.
`transaction.zi` also owns the signed grant record. Grant transactions live in
`app_grants.zi`; HTTP handlers live in `app_http.zi`. Manifest normalization and
validation preserve error text, byte limits, scopes, Gregorian dates and
explicit expiry boundaries.
Active-key verification selects eligible keys in Ziran and uses Go Ed25519.

`app_store.zi` owns app registry transactions, signed manifest persistence,
key and token-policy replacement, registry listing/detail queries, metadata
decoding, legacy protocol date/version checks and collection ownership. Native
SQL handles preserve atomic rollback, error identity and connection reuse.
Queries retain ordering, missing-row behavior and nil versus allocated empty
results. Built-in seeding preserves the released Inbe metadata and leaves
active signed manifests untouched. Baseline fixtures compare stored state,
key expiry/revocation filtering, replacement, malformed JSON and scan errors,
cancellation, failed writes and commits, and legacy date boundaries. Maintained
startup, HTTP, sync, token and mesh callers use the generated surface directly.
The corresponding HTTP handlers now live in `app_http.zi`.

`app_grants.zi` owns grant creation, detail/list queries, revocation and
authorized encrypted-record reads. Account, grant and audit changes commit
together; failures roll back all writes. Reads retain account isolation,
registered collection ownership, active read-grant checks, SQL wildcard
escaping, ordering and nil versus allocated empty results. The original
validation order and native SQL/context errors remain intact. Independent
baseline fixtures compare lifecycle state, private/unregistered scope denial,
cross-account access, malformed stored values, cancellation, failed writes and
commits, and connection reuse. `account_state.zi` owns the shared transactional
account-touch and sync-state initialization; `resource_id.zi` owns the exact
16-byte random hexadecimal identifiers. Entropy-failure comparisons run in
isolated subprocesses and preserve Go 1.24's fatal behavior. Maintained callers
use the generated functions directly; the HTTP handlers live in `app_http.zi`.

`app_registration.zi` owns signed/unsigned app and grant request decoding,
ordered normalization/validation, manifest JSON serialization, hashes and both
manifest and registry approval signatures. It preserves partial records on
decoding/validation errors, exact signature contexts, active-key selection and
HTTP rejection status/text. Signed grant decoding returns the original body
slice and preserves nil results on errors. Baseline comparisons cover malformed
JSON, arbitrary byte strings, Unicode whitespace, validation ordering, field
limits, invalid/expired/suspended keys, signature encodings, signature failures
and exact JSON escaping/hashes. `app_http.zi` owns the bounded request readers
and their HTTP responses.

`app_http.zi` completes the app registry and signed manifest HTTP boundary,
including admin registration, registry detail and collections, grant creation
and revocation, signed grants and authorized record reads. It preserves exact
status codes, JSON bytes and headers, authentication counters, validation order
and SQL error mapping. Signed requests retain their replay after a completed
write/read, including a later response panic; failed operations forget it even
when logging panics. Baseline HTTP comparisons cover successful registration
and grants, signature rejection, failed writes, cancellation, database errors,
scope denial and native panic identity. Server routes dispatch directly to the
generated handlers through a small dependency record.

`http_body.zi` owns bounded reads, JSON validity checks and body closure during
ordinary returns and panic unwinding. `response.zi` owns JSON/error status,
headers and streaming encoding. `http_auth.zi` owns released header precedence,
bearer token/account validation, sync bootstrap tombstone checks, constant-time
administrative token checks, local-operator access and failure responses/metrics.
Administrative access retains current/legacy header precedence and exact token
bytes. Local-operator access uses only the direct remote IP, accepts IPv4/IPv6
loopback without a configured token and requires the token when configured.
Spoofed forwarding headers never grant administrative access. Baseline comparisons
cover Unicode/byte strings, malformed remote addresses, header precedence and
exact rejection status/body. Existing Go consumers use these generated helpers
directly; their remaining application handlers still need porting. Comparisons preserve
nil/empty body results, error text, context identity, encoded bytes and cleanup.

`sync_types.zi` owns sync requests, responses, changes, snapshots and operation
records. Its `RawMessage` declaration aliases `encoding/json.RawMessage`,
preserving raw JSON payloads and Go type identity. Maintained callers use
`SocialSnapshot` directly; released `social_cache` fields are unchanged.

`sync_ws.zi`, `websocket.zi` and `sync_hub.zi` own the complete WebSocket sync
implementation. Upgrades retain the released subprotocol negotiation, token
precedence, query-token rejection, limits, metrics and exact handshake bytes.
Frame validation preserves mask requirements, reserved bits, opcodes, control
frame bounds, fragmented-frame rejection, size bounds and native EOF errors.
Subscribers retain eight buffered events, account isolation and nonblocking
delivery; concurrent publishers and disconnects share the hub lock. Typed Go
callbacks start the reader worker, and native deferred callbacks release
subscriptions, cancellation, ticker and connection during ordinary returns
and panic unwinding. Independent Go baseline fixtures compare every two-byte
frame header, truncated and large payloads, arbitrary headers, write and
upgrade errors, authentication, rate/connection limits, event delivery and
panic cleanup. The existing server routes dispatch to the generated handler.

`token_ledger.zi`, `token_receipt.zi` and `token_checkpoint.zi` own token-ledger
storage, receipt encoding/signatures and checkpoints. Credits preserve payment
identity, account/amount collision checks and atomic insertion of ledger and
processed-payment rows. Spending preserves request hashes, nonce reuse checks,
balance rejection and atomic ledger/nonce updates. Native transaction rollback
runs at every return and during panic unwinding; failed commits retain the
original result fields and release their connection. Asset, balance, receipt
and ledger queries preserve scope filters, ordering, nullable sums, nil versus
allocated results and SQL errors. Independent baseline fixtures compare exact
canonical bytes and signatures, malformed byte strings, validation order,
account/app filtering, receipt lookup, retries, collisions, hash-chain order,
checkpoint roots, cancellation, malformed stored rows, failed writes and failed
commits. Existing payment and deposit callers now use the generated functions
directly. Payment error identities now live in `payment_state.zi`; Google
purchase verification, Monero invoices and recurring reconciliation are also
implemented in the Ziran modules listed in the inventory.

`token_http.zi`, `token_policy.zi` and `payment_request.zi` own token HTTP
handlers, issuer selection, signed app authorization and purchase/spend request
decoding. Product listing uses the generic Ziran sort over native slices of
protocol records. Callback types in payment and registry modules retain
distinct native names. The pinned compiler preserves each generic library's
private helper scope while specializing for caller-owned records.
Independent Go baseline comparisons cover body limits, malformed and duplicate
JSON fields, arbitrary byte strings, issuer key/error identity, query filters,
sorted products, authentication and rejection counters, signed/unsigned policy,
replay state, SQL failure, cancellation and deferred replay cleanup during log
and response panics. Admin comparisons cover credit normalization, generated
source references, signature validity, checkpoint responses and failure paths.
Source and saved-IR generation run the same complete server regression suite.

`google_play.zi` owns Google purchase verification/consumption, service-account
JWT signing, refresh-token exchange and verifier selection. Native cryptographic,
JSON, HTTP and error primitives retain original bytes and error identity.
`google_play_http.zi` keeps authorization/replay cleanup, ledger crediting and
post-credit purchase consumption at the HTTP boundary. `monero_wallet.zi` owns
RPC encoding and bounded replies, subaddress creation, payment inspection and
overflow-checked token conversion. `monero_invoice_store.zi` owns invoice
persistence and state transitions; `monero_invoices.zi` owns signed invoice
HTTP, expiry/settlement and recurring reconciliation, including late confirmed
payments and one-time stuck-payment reporting. `monero_deposit_store.zi` and
`monero_deposits.zi` own permanent account subaddresses, transfer collection,
confirmation/height tracking and atomic deposit crediting. Existing payment
and reconciliation suites run against both source and saved Ziran IR, including
native panic cleanup, retries, double-credit prevention and cancellation.

`account_state.zi`, `account_profile.zi`, `account_lookup.zi` and
`friend_store.zi` own account registration, aliases/icons, account-reference
resolution, friend requests, friendships, authoritative social snapshots and
profile-stat writes. `account_export.zi` owns all nineteen account-export
queries and dynamic native SQL scanning; `account_http.zi` serves account
export, alias and profile-icon requests. Header precedence, validation order,
case/Unicode normalization, native errors, nil/empty results and JSON bytes
remain consistent with the original implementation.

`leaderboard.zi` owns friend visibility queries, daily streaks, practice-specific
averages, label rounding, cache validity and stable ordering. Non-friends stay
excluded; changes to source/calculation versions or the streak date invalidate
cached rows. `social_cache.zi` owns transactional snapshot writes, exact payload
comparison and version allocation; identical writes consume no extra version,
and failures roll back both snapshot and version changes. `social_http.zi`
owns friend/request endpoints, profile-stat handling and social-cache updates,
including notifications to the affected users. Independent baselines compare
HTTP bytes, headers, authentication order, body closure, database contents and
notifications for success, rejection, cancellation, write failure and native
panics. Storage comparisons cover cache invalidation, nil/empty results,
scan/query errors, failed writes/commits, connection reuse and concurrent
idempotent snapshot updates. Source and saved-IR server suites pass with race
detection.

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

`mesh_store.zi` completes encrypted mesh storage. Export walks sequence-ordered
changes, retains deletion tombstones and skips upserts whose record or account
is gone. Scope matching preserves the longest registered prefix and original
tie order. Import stably merges record and deletion sequences, validates account
key hashes and record metadata, filters explicit scopes and prevents deleted
accounts from being resurrected. User, sync-version, record and change-log writes
commit together; failed writes, validation or commits roll back the whole batch.
Conflict decisions preserve canonical timestamps and deterministic content ties.
Cursor persistence retains exact stored bytes, blank-write behavior and native
SQL/context errors. Maintained HTTP and peer consumers use the generated surface.
Independent baseline comparisons cover pagination, nil/empty results, excluded
data types, malformed cursors and records, denied scopes, cancelled operations,
query/scan failures, rollback, connection reuse and delete/recreate convergence.
`mesh_types.zi` preserves the original wire-field layouts; `mesh_cursor.zi`
preserves base64/JSON bytes, partial-decode rejection, integer bounds, batch limits
and URL/policy cursor keys. The native SQL scan found a Go backend truncation bug;
Ziran now uses the complete checked parameter list for procedure signatures and
foreign calls, with source and saved-IR regressions through 64 parameters.

`mesh_apps.zi` completes signed app registry replication. Export preserves
ordering, exact stored manifest/signature bytes, normalized app filters,
nil/empty results and wrapped JSON errors. Import preserves validation and
signature checks before version comparisons, refuses same-version forks and
skips older manifests. Each accepted app commits independently, as in the
released implementation: a later failure reports zero applied while leaving
earlier completed apps present. Tests compare this boundary, expired manifests
and keys, scope denial, exact wrapped authentication errors, cancelled SQL,
malformed stored data, failed writes/commits and connection reuse. The existing
Go authentication-error converter is a typed callback dependency; that adapter
and the remaining Go server modules still need porting for the complete goal.

`mesh.zi` completes mesh HTTP handling, peer replication and the recurring
worker. Bounded request reads still precede authentication. Signed peers take
precedence over shared-token access and must stay within their approved scopes;
replayed, expired and malformed signatures retain the released failures.
Export and import preserve JSON bytes, nil lists and the separate app, record
and name transaction boundaries. Peer pulls snapshot configured entries, add
paired peers in stored order, continue after an unavailable peer, and retain
the first-address policy. Outbound requests preserve exact shared-token bytes,
node signatures, native contexts, the twenty-second timeout, replayable bodies,
bounded error reads and response closure during panic unwinding. Pagination
saves each completed page, resumes after interruption, and retains the legacy
sequence-cursor fallback and empty-batch behavior. The worker pulls immediately,
then selects between native ticker delivery and context cancellation; disabled
intervals touch no dependencies, and deferred ticker cleanup runs on every exit.
Independent comparisons exercise both handlers, header precedence, denied
scopes, concurrent replay, cancelled/failed SQL, partial commits, malformed
responses, signing, body cleanup, reconnects, pagination and worker lifecycle
through source and saved IR. Maintained routes and startup call generated
functions directly; no handwritten mesh implementation remains.

`device_keys.zi` owns the device records and storage lifecycle. Canonical
messages preserve raw bytes, integer limits and trailing newlines; normalization
retains Unicode handling and key validation retains the exact time window.
Registration and revocation consume their nonce in the same transaction as the
key change, including expiry cleanup. Failed changes and commits roll back
nonce consumption; missing-key revocation returns the native SQL sentinel.
Replacement preserves creation time and clears revocation. Listing preserves
ordering and nil empty results. Baseline fixtures compare record layouts,
messages, lifecycle state, cancellation, commit failures and concurrent replay
identity. Registration/revocation signature checks now also live in Ziran and
preserve the original validation order, native account-key query failures and
exact signature messages. `device_http.zi` now owns their HTTP handlers.

`device_http.zi` owns device listing, registration and revocation at the HTTP
boundary. It keeps bearer/header authentication before body reads, released
normalization, exact signature arguments and failure counters, nonce replay
mapping, transactional writes and the original JSON responses. Independent
handler comparisons cover all three methods, nil lists and account isolation,
malformed/oversized/failed body reads, rejected signatures, replayed nonces,
missing resources, database/cancellation errors and failed writes. A response
panic retains committed device changes and closes a consumed body exactly as
the original implementation does. Routes dispatch directly to the generated
handlers; no handwritten device handler remains.

`trust_http.zi` completes the pairing and namespace HTTP handlers. Invitation
creation retains explicit scopes, lifetime arithmetic, configured address and
display-name fallbacks, signing and persistence. Acceptance verifies the
inviter before contacting it, completes reciprocal pairing before committing
local trust, and preserves replay rejection. Completion validates both signed
records and the issued invitation before trusting the accepting node. Outbound
requests retain the ten-second timeout, ordered address retries, native request
context/body replay, 2,048-byte response reads, body closure and wrapped errors.
Peer and namespace responses preserve JSON field order and nil lists; name
registration retains normalization, expiry validation, authority signing and
sequence updates. Baseline comparisons cover all seven handlers, successful
writes, unauthorized and malformed requests, signatures and expiry, unavailable
peers, cancellation, replay/idempotence, failed writes, and native panic cleanup.
`mesh_policy.zi` also owns the explicit inbound-scope check shared with mesh
handlers. Routes call the generated handlers through a dependency record.

`signed_tx.zi` completes signed-header decoding, transaction verification,
device signature verification and replay persistence. Header decoding preserves
raw JSON and both URL-base64 encodings, Unicode trimming, JSON errors and field
normalization. Verification retains protocol/context/ID validation order,
decoded request paths, body hashes, expiry limits, account lookup, both signature
checks and native errors. Cryptographic verification uses a typed function
argument bound to the existing foreign-library verifier. Replay recording
retains the original separate expiry cleanup and insertion; a failed device
touch leaves the replay recorded, matching the original behavior. Forgetting
requires all four identifiers to match and still ignores native SQL errors.
Baseline cases compare rejection status/text, callback bytes, database state,
malformed headers and simultaneous request verification. `authentication.zi`
owns the shared result and signature callback; `authentication_error.go` remains
a small conversion to the existing Go HTTP error interface. The HTTP boundary
and foreign-library verifier are still part of the unfinished server port.

`discovery.zi` completes the LAN advertiser. Discovery advertises only the
released identity/protocol metadata and never grants trust. Native registration
retains default interface selection, Unicode display-name trimming and byte
truncation of long node identifiers. Disabled discovery and invalid listeners
return before touching network resources. Successful registration waits for
native context cancellation and shuts down the exact registered resource;
deferred shutdown preserves panic behavior and log ordering. Independent
baseline comparisons cover arbitrary byte strings, native port error details,
registration failures, cancellation, resource identity and panic cleanup.
The real registration adapter is checked only with inputs rejected before any
network socket opens, so tests never advertise on the user's LAN.

`docs.zi` completes public HTML and OpenAPI handling. The spec retains every
map key, concrete native value type, schema, parameter list and JSON byte.
Builders allocate fresh maps and slices, while a native `sync.OnceValue`
callback retains the shared newline-terminated response payload across
concurrent requests. HTML preserves exact page bytes, status arithmetic,
storage rounding, failure logging, response headers and write ordering.
The storage query is an explicit typed callback dependency until storage itself
is fully ported. `types.zi` owns its unchanged public statistics record;
`protocol.zi` owns the shared released protocol bounds. Baseline comparisons
cover the full spec's native types, fresh nested storage, concurrent cache use,
writer errors and panics, query/context identity, unavailable statistics and
signed integer boundaries. Source and saved-IR server suites run these cases.

`inspect.zi` completes the offline database commands. Native flag parsing keeps
the original help/error output, option precedence and argument validation order.
The database opens read-only with one connection and closes on every return;
query iteration also closes during panic unwinding. Summary, user listing,
account detail and doctor output retain exact bytes, ordering, limits, nullable
fields, ignored version-query failures and warning thresholds. Redaction uses
the original byte boundaries, including arbitrary non-UTF-8 strings; a typed
nil writer retains its native interface behavior. Independent comparisons
cover every command, invalid flags/users, environment fallback, missing and
malformed databases, SQL scan failures, cancelled/expired contexts, read-only
enforcement, warning boundaries, output failures/panics and connection reuse.
Startup calls the generated inspection entry directly. The original Go module
is kept only as a test oracle; no handwritten inspection implementation remains
in production. Source and saved-IR server suites pass with race detection.

## Compiler work exercised by this port

This exposed two upstream compiler errors: generic foreign slice elements
were validated before type normalization, and native Go string constants could
misinterpret escaped quotes and alter punctuation. Ziran now resolves generic
slice returns before checking their concrete elements and preserves escaped
string bytes. Source and saved-IR compiler regressions cover both fixes.

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
Native decoded URL paths and Unix timestamp construction preserve request
encoding, signed 64-bit seconds and nanosecond normalization. Typed callbacks
carry native byte slices and imported authentication results through saved IR.
Typed native `call` bindings invoke a procedure argument with checked parameter
and result types. Void callbacks support `#go_defer`, capturing values when
scheduled and observing later state through explicit pointers. The `io_go`
module and extended HTTP, JSON and URL modules provide native stream interfaces,
request bodies/contexts, bounded reads, response status, JSON encoders and query
values. Source and saved-IR checks exercise reverse-order cleanup, error and
panic identity, immediate argument capture and ownership/signature rejection.
Foreign slice return validation now runs after the complete import graph is
linked. Public record types re-exported through intermediate modules therefore
resolve independently of module/declaration order in source and saved IR.
Void `#go_field` accessors assign a field through a pointer receiver, or assign
a package variable with one value argument. The checker rejects value receivers,
owned storage, wrong arity and incompatible accessor attributes. Source and
saved-IR regressions verify pointer identity, package assignments and rejected
signatures. The extended HTTP/I/O/time modules provide native timeout clients,
outbound requests, response fields, byte readers, bounded streams and deadline
arithmetic without application-specific adapters.

The JSON module now also exposes native streaming decoders, preserving
incremental decoder state, partial results, EOF and read-error identity.
`select_go` supplies receive, send and default cases over boxed native Go
channels using `reflect.Select`. Channel directions and send-value types are
validated at runtime. It preserves nil-channel disabling, closed-channel
results and ready-case selection; context cancellation channels and native
tickers come from `context_go` and `time_go`. Source and saved-IR regressions
cover ticker delivery, cancellation wakeups, deferred cleanup, receives, sends,
defaults and invalid native selections. These primitives are Go-specific.

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
