# Daochi compression study

The [compression guide](../../docs/compression.md) documents the implemented
behavior and deployment verification. Open the
[interactive results](../../docs/benchmarks/2026-10-26-compression.html) to filter
workloads, codecs and modeled bandwidth. JSON, CSV and a PNG plot are adjacent.

These files are benchmark tooling, not production implementation. The nested
Go module isolates experimental codec dependencies from Daochi's parent module.
Production changes remain authored in Ziran. The experiment uses generated
structured JSON and pseudorandom simulated ciphertext, never private databases.

## Reproduce

From the canonical Daochi checkout, execute through Harmony `desktop_run` with
project `kryonlabs/daochi`. Keep commands supervised; poll the returned command
ID rather than detaching a process. The run used one worker, a managed two-CPU
quota, a 6 GiB process-scope memory ceiling, and no display access. Do not raise
the managed limits or run the stages concurrently.

```sh
python3 bench/compression/benchmark.py --output build/scratch/compression-2026-10-26
```

Then, from `bench/compression`:

```sh
GOTOOLCHAIN=go1.26.10 GOMAXPROCS=1 GOFLAGS=-p=1 go mod download
GOTOOLCHAIN=go1.26.10 GOMAXPROCS=1 GOFLAGS=-p=1 go run . ../../build/scratch/compression-2026-10-26
GOTOOLCHAIN=go1.26.10 GOMAXPROCS=1 GOFLAGS=-p=1 go run ./http ../../build/scratch/compression-2026-10-26
GOTOOLCHAIN=go1.26.10 GOMAXPROCS=1 GOFLAGS=-p=1 go run ./memory ../../build/scratch/compression-2026-10-26
```

Finally, from the repository root:

```sh
python3 bench/compression/report.py build/scratch/compression-2026-10-26 docs/benchmarks
```

Python dependencies are `brotli`, `lz4` and `matplotlib`; native libraries are
zlib and libzstd (with its dictionary trainer). Record exact versions from
`metadata.json`. Check the installed Brotli package's security backport; the
upstream version string alone does not identify patched distro builds.

The corpus, trained dictionary, encoded frames and intermediate receipts stay
under ignored `build/scratch/`. The saved JSON includes the source revision,
corpus/dictionary digests, versions, timings and sample counts. Rerunning on a
shared machine will change timings; no performance threshold is asserted by the
harness. Use a new output directory for another run you want to preserve.

## Method and interpretation

- Native sweep: 19 profiles times 15 corpora. Fresh codec contexts, buffer
  allocations/copies included, with at least nine samples and 45 ms per
  direction when practical. High-effort Brotli 11 and Zstandard 19 use at least
  three encoder samples. Startup, imports and offline dictionary training are
  outside timing. Each direction's empirical p95 has the saved sample count.
- Go sweep: 30 profiles times 15 corpora, using fresh or reused writers. The
  gzip baseline matches the production level and writer lifecycle. The sink
  buffer stays warm, so these allocations describe the codec rather than a full
  application response. Zstandard and Brotli stream writes use 32 KiB chunks;
  no per-chunk flush is forced. Actual loopback timing is a separate experiment.
- Go Zstandard presets map approximately to native levels 1/3/7/11; matching
  numbers do not imply equivalent implementations or output. Compare the
  measured profile, not just its algorithm label. The entropy option is a
  separate measured variant, retained alongside the failing default case.
- HTTP sweep: three corpora, eight profiles, concurrency one/four, 24 measured
  requests each after four warmups. Private loopback, warm keepalive,
  `GOMAXPROCS=1`, automatic client compression disabled. Completion includes
  decompression and a byte comparison. First-response-byte latency measures
  response headers. No production routes, database, TLS or credentials are used.
- Memory sweep: retained encoder Go heap after GC, one/four writers, output
  discarded. The resident input corpus is excluded. Native RSS includes the
  interpreter and an inherited high-water floor; it cannot isolate small codec
  workspace differences. Neither result is a total server-memory forecast.
- Cross-runtime validation: all 330 Go-generated Brotli/Zstandard frames are
  decoded by native libraries and compared byte-for-byte. All 735 codec cases
  and 1,152 HTTP requests also perform their own roundtrip comparisons.
- Record packing comparison: the two pages derive from the same generated
  plaintext records, with the correct gzip frame plus 12-byte packing header
  modeled before ciphertext expansion. Encryption uses random bytes of equal
  length; its CPU and nested-envelope expansion are excluded. Synthetic notes
  use a small vocabulary, so these savings are not a representative-data claim.
- Dictionary training uses 256 separate synthetic records, disjoint IDs and a
  different seed. The 16 KiB dictionary and similar schemas are optimistic for
  cold or heterogeneous clients. Distribution, versioning, storage and missing
  dictionary behavior require separate evaluation before introducing dictionaries.
- Bandwidth exploration is a sequential encode + transfer + decode model. It
  excludes headers, TLS, RTT and overlap. Do not call it a measured network run.

The initial Go 1.25 sweep discovered the large-page entropy issue. It is retained
only in the ignored scratch receipts. The published Go comparisons were rerun
under the same Go 1.26.10 toolchain with the explicit entropy variants.
