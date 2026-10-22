# Package delivery cache

This Worker accelerates the existing `api.waozi.xyz/api/v2/packages/` artifact
routes. Existing applications keep their URLs and signed-hash checks. Metadata,
history, range requests and conditional requests continue through the node.

For every artifact request, the Worker first sends an uncached HEAD request to
the node. The existing node verifies the registry, publisher, release signature,
product grant and artifact integrity. A rejected or expired grant cannot read
cached bytes. The node remains the authority even when the bytes are warm at an
edge location. HEAD still performs the node's normal integrity check; this
cache saves transferring the large payload from the node, rather than removing
that check.

The bucket is private: do not enable its `r2.dev` URL or attach a public custom
domain. A named Cache API cache retains shared bytes separately from the public
default HTTP cache. Responses to paid-pack URLs keep `private, no-store`.
Per-request CORS headers come from the node. No account records or grant tokens
are stored in R2, and Worker request logging is disabled.

Missing objects and cache/storage failures fall back to the node. A GET never
creates an R2 object, so download traffic cannot grow storage or write usage.

## Activation

R2 must first be enabled in the existing Cloudflare account. The API currently
rejects bucket operations with code 10042 until that account step is complete.
Enabling R2 may require billing enrollment even when usage remains within its
free allowance. This repository does not activate billing or upgrade a plan.

After activation, create the dedicated private bucket:

```sh
npx --yes wrangler@4.141.0 r2 bucket create daochi-packages
```

Mirror the node's already published package store. This does not stage or
approve a new release. Review the local hash and size check first:

```sh
python3 cdn/mirror.py --store /absolute/node/package-store
python3 cdn/mirror.py --store /absolute/node/package-store --execute
```

The tool accepts only immutable hash-named files whose actual SHA-256 matches
the filename. It refuses symlinks and files over 512 MiB. An inventory reserves
space before uploads, including interrupted attempts, and caps this dedicated
mirror at 8 GiB. Use this one publisher and bucket for the mirror; other account
storage still counts toward Cloudflare's allowance. Keep the inventory and
existing objects when retrying. The tool never deletes old artifacts.

Deploy the reviewed Worker through its existing proxied hostname:

```sh
npx --yes wrangler@4.141.0 deploy --config cdn/wrangler.jsonc
```

This changes only the package route and requires no Inbe push, version bump or
client release. Keep the account on its intended free Workers plan; this config
does not request a paid plan. The Workers free request/CPU limits and R2's
storage/read/write allowances still apply.

Run the mirror after an approved package publication. Until a new hash has been
mirrored, downloads continue through the original server. Removing this Worker's
route restores direct node delivery without changing clients or package data.

## Checks

```sh
node cdn/worker.test.mjs
python3 cdn/mirror_test.py
npx --yes wrangler@4.141.0 deploy --dry-run --config cdn/wrangler.jsonc
```

`runtime.test.mjs` exercises real Workers streams, local R2 and named-cache
isolation with a 31 MiB synthetic artifact by default. It uses Miniflare 5;
`MINIFLARE_MODULE` can point to an existing Wrangler installation's Miniflare
dependency. Set `CDN_TEST_ARTIFACT` to verify a real already published pack.

After deployment, verify the actual package URL twice: delivery should change
from `r2` to `edge` in `X-Daochi-Delivery`, with identical SHA-256 bytes. Verify
that an expired/forged grant still returns 403 after warming the cache, and that
latest/history remain uncached. Compare origin and cached download timings
before claiming an improvement. A successful local build is not a deployment.
