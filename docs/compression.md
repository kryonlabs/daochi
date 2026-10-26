# HTTP compression

Daochi can negotiate Zstandard, gzip or identity for sync JSON and public node
information. Clients that already advertise `zstd` receive it automatically;
clients advertising gzip retain the existing representation. No encrypted-record
format, account key, signature message or sync cursor changes are required.

## Response behavior

Zstandard uses the fastest Go preset, one worker, a 1 MiB window, and explicit
literal entropy compression. That last setting is necessary for large
base64 ciphertext pages. Both Zstandard and gzip reuse a shared pool of at
most four encoder contexts, including active contexts. Requests waiting for a
slot observe cancellation. Erroring or panicking streams discard the context
and return their slot. Completed streams detach the response writer before
becoming available for reuse.

Negotiation combines repeated `Accept-Encoding` fields, respects explicit
q-values and exclusions, and selects Zstandard when supported codecs have the
same preference. An absent header retains identity. If the client excludes all
supported representations, the response is 406. Negotiated responses include
`Vary: Accept-Encoding`, retaining an existing origin or wildcard selector.
Compressed responses do not retain an identity `Content-Length`. HEAD, 204 and
304 responses have no body, and partial representations are not recompressed.

The public `/api/v1/node` response includes `build_version`, allowing operators
to distinguish the installed revision from a successful local build. Its
capabilities include `http-zstd-v1` while Zstandard request decoding is enabled.

## Request limits and signatures

JSON requests accept identity, gzip and Zstandard. Each compressed request must
fit both the existing compressed-wire limit and decoded JSON limit. Zstandard
also enforces an 8 MiB maximum frame window. Malformed data, invalid trailing
bytes and stacked content codings are rejected; valid concatenated Zstandard
frames share the same total decoded limit. Decoding completes before validating
JSON and calculating the signed transaction's body digest. Signing compressed
wire bytes does not authenticate the decoded request.

The existing pre-encryption `gzip-v1` record codec is unchanged. Binary media
does not enter that record codec, and no `zstd-v1` record migration or shared
private dictionary is introduced by this HTTP upgrade.

## Rollback switches

Set either environment variable to `0` and restart the service through its
normal deployment path to disable that direction independently:

- `DAOCHI_HTTP_ZSTD_RESPONSES`: prefer Zstandard responses when accepted;
  defaults to enabled. Disabling it retains gzip/identity negotiation.
- `DAOCHI_HTTP_ZSTD_REQUESTS`: accept bounded Zstandard request bodies and
  advertise `http-zstd-v1`; defaults to enabled. Disabling it rejects such
  uploads and removes that capability.

Use the existing fixed encoder and decoder limits when operating small nodes.
Changing compression must not raise a node's managed CPU or memory budgets.

## Build and verification

The Go build baseline is 1.26. Canonical implementation remains Ziran:
`content_coding.zi`, `response.zi`, `http_body.zi`, `node_info.zi` and the node
handler in `operational_http.zi`. Generic Zstandard bindings belong upstream
in Ziran's `std/zstd_go.zi`; the consuming Go module pins the external provider.
Generated `.zi.go` files are build outputs and are not hand-edited or committed.

`content_coding_zstd_test.go` covers negotiation, malformed/oversized bodies,
literal entropy, reuse, bounded capacity, cancellation, write errors, native
panic cleanup, concurrent ownership, signed sync and native curl decoding.
Upstream tests verify source/saved IR and independent libzstd interoperability.
The benchmark in the same test file measures the actual generated response path
against a fresh gzip writer and includes allocation measurements.

## Performance and deployment

The [benchmark report](benchmarks/2026-10-26-compression.html) compares codec
speed, wire size, decoder cost and memory. Measurements of the actual generated
response path are in [implementation results](benchmarks/2026-10-26-implementation.json).
On the measured desktop, Zstandard reduced response processing time by about
32–39% compared with a fresh gzip writer. Allocated bytes per response fell by
about 24–77%; retained encoder-pool memory is a separate cost.

Use the existing deployment workflow, its readiness checks and rollback path.
After deployment, verify the installed `build_version` through `/api/v1/node`,
test gzip, Zstandard and identity responses, and verify decoded JSON. Record
target-device and production-node measurements separately from the synthetic
desktop results. A successful build or GitHub run alone does not identify the
binary currently serving requests.
