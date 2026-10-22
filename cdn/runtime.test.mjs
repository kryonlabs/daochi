// Exercise real Workers streams, private R2 bindings and named edge caches.
// MINIFLARE_MODULE may name an existing Wrangler installation's dependency.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { Miniflare, Response } = require(process.env.MINIFLARE_MODULE || "miniflare");
const bytes = process.env.CDN_TEST_ARTIFACT
  ? await readFile(process.env.CDN_TEST_ARTIFACT)
  : Buffer.alloc(31 * 1024 * 1024, 90);
const digest = value => createHash("sha256").update(value).digest("hex");
const hash = digest(bytes);
const key = `inbe.practices/${hash}.zib`;
const route = `https://api.waozi.xyz/api/v2/packages/${key}`;
let allowed = true;
let checks = 0;

function authorize(request) {
  if (!new URL(request.url).pathname.startsWith("/api/v2/packages/")) {
    return new Response(null, { status: 404 });
  }
  assert.equal(request.method, "HEAD");
  checks++;
  return new Response(null, {
    status: allowed ? 200 : 403,
    headers: allowed ? {
      "Content-Length": String(bytes.length),
      "ETag": `"${hash}"`,
      "Cache-Control": "private, no-store",
    } : { "Cache-Control": "no-store" },
  });
}

const runtime = new Miniflare({
  host: "127.0.0.1",
  cf: false,
  telemetry: { enabled: false },
  workers: [{
    config: {
      name: "cdn-test",
      compatibilityDate: "2026-10-02",
      manifest: {
        mainModule: "worker.mjs",
        modules: {
          "worker.mjs": {
            type: "esm",
            contents: await readFile(new URL("worker.mjs", import.meta.url), "utf8"),
          },
        },
      },
      env: { ARTIFACTS: { type: "r2", name: "cdn-test-artifacts" } },
    },
    dev: { outboundService: { type: "fetcher", handler: authorize } },
  }],
});

try {
  const bucket = await runtime.getR2Bucket("ARTIFACTS");
  await bucket.put(key, bytes);
  console.log("Private R2 fixture loaded");
  let delivery;
  for (let attempt = 0; attempt < 10; attempt++) {
    const response = await runtime.dispatchFetch(`${route}/valid-grant`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "private, no-store");
    assert.equal(digest(Buffer.from(await response.arrayBuffer())), hash);
    delivery = response.headers.get("X-Daochi-Delivery");
    if (delivery === "edge") break;
    assert.equal(delivery, "r2");
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.equal(delivery, "edge");
  assert(checks >= 2);
  console.log("R2 and edge streams verified");

  const caches = await runtime.getCaches();
  const cacheKey = `https://api.waozi.xyz/.package-cache/${key}`;
  assert.equal(await caches.default.match(cacheKey), undefined);
  const privateCache = await caches.open("package-artifacts-v1");
  const retained = await privateCache.match(cacheKey);
  assert(retained);
  assert.equal(digest(Buffer.from(await retained.arrayBuffer())), hash);

  allowed = false;
  const denied = await runtime.dispatchFetch(`${route}/expired-grant`);
  assert.equal(denied.status, 403);
  assert.equal(await denied.text(), "");

  const hidden = await runtime.dispatchFetch(`https://api.waozi.xyz/.package-cache/${key}`);
  assert.equal(hidden.status, 404);
  assert.equal(await hidden.text(), "");
  console.log(`Workers runtime: ${bytes.length} bytes streamed through R2 and edge cache; grant denial and hidden cache path passed`);
} finally {
  await runtime.dispose();
}
