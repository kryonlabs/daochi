import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { deliver } from "./worker.mjs";

const bytes = new TextEncoder().encode("ZX\0\0verified fixture");
const hash = createHash("sha256").update(bytes).digest("hex");

function fixture(suffix = "zx") {
  const path = `/api/v2/packages/inbe.practices/${hash}.${suffix}`;
  const stored = new Map();
  const requests = [];
  const pending = [];
  const state = { status: 200, policy: "private, no-store", reads: 0, matches: 0, missing: false };
  const cache = {
    async match(key) {
      state.matches++;
      return stored.get(key.url)?.clone();
    },
    async put(key, response) {
      stored.set(key.url, response);
    },
    async delete(key) {
      stored.delete(key.url);
    },
  };
  const env = {
    ARTIFACTS: {
      async get(key) {
        state.reads++;
        assert.equal(key, `inbe.practices/${hash}.${suffix}`);
        if (state.missing) return null;
        return { size: bytes.length, body: new Blob([bytes]).stream() };
      },
    },
  };
  async function origin(request) {
    requests.push(request);
    if (request.method !== "HEAD") {
      return new Response(bytes, { headers: { "Cache-Control": state.policy } });
    }
    assert.equal(request.headers.get("If-None-Match"), null);
    assert.equal(request.redirect, "manual");
    return new Response(null, {
      status: state.status,
      headers: {
        "Cache-Control": state.policy,
        "Content-Length": String(bytes.length),
        "ETag": `"${hash}"`,
        "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
      },
    });
  }
  async function get(suffix = "/valid-grant", options = {}) {
    const request = new Request(`https://api.waozi.xyz${path}${suffix}`, options);
    const response = await deliver(request, env, { waitUntil(task) { pending.push(task); } }, origin, cache);
    await Promise.all(pending.splice(0));
    return response;
  }
  return { state, cache, stored, requests, env, origin, get };
}

test("R2 and edge responses keep paid bytes private and reauthorize every hit", async () => {
  const f = fixture();
  const first = await f.get();
  assert.deepEqual(new Uint8Array(await first.arrayBuffer()), bytes);
  assert.equal(first.headers.get("X-Daochi-Delivery"), "r2");
  assert.equal(first.headers.get("Cache-Control"), "private, no-store");
  const second = await f.get("/another-valid-grant");
  assert.deepEqual(new Uint8Array(await second.arrayBuffer()), bytes);
  assert.equal(second.headers.get("X-Daochi-Delivery"), "edge");
  assert.equal(second.headers.get("Cache-Control"), "private, no-store");
  assert.equal(f.state.reads, 1);
  assert.deepEqual(f.requests.map(request => request.method), ["HEAD", "HEAD"]);
  assert.equal([...f.stored.keys()].some(key => key.includes("grant")), false);
});

for (const status of [403, 404, 503]) {
  test(`a warm cache cannot bypass node rejection ${status}`, async () => {
    const f = fixture();
    await (await f.get()).arrayBuffer();
    f.state.status = status;
    const matches = f.state.matches;
    const response = await f.get("/expired-or-forged-grant");
    assert.equal(response.status, status);
    assert.equal(await response.text(), "");
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(f.state.matches, matches);
    assert.equal(f.state.reads, 1);
  });
}

test("legacy .zib artifacts keep their own key for hosts from before ZX", async () => {
  const f = fixture("zib");
  const response = await f.get();
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
  assert.equal(f.state.reads, 1);
  assert.equal([...f.stored.keys()].some(key => key.endsWith(`${hash}.zib`)), true);
});

test("public artifacts retain their immutable policy", async () => {
  const f = fixture();
  f.state.policy = "public, max-age=31536000, immutable";
  const response = await f.get("");
  assert.equal(response.headers.get("Cache-Control"), f.state.policy);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
});

test("CORS headers belong to the current request, including on an edge hit", async () => {
  const f = fixture();
  await (await f.get("/first", { headers: { Origin: "https://first.example" } })).arrayBuffer();
  const response = await f.get("/second", { headers: { Origin: "https://second.example" } });
  assert.equal(response.headers.get("X-Daochi-Delivery"), "edge");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://second.example");
});

test("metadata and malformed or noncanonical artifact paths stay with the node", async () => {
  for (const suffix of ["latest", "history", `${hash.toUpperCase()}.zx`, `${hash}.zx?grant=x`, `${hash}.zx/%2F`,
    `${hash}.ZX`, `${hash}.zx.zx`, `${hash}.zir`, `${hash.toUpperCase()}.zib`, `${hash}.zib?grant=x`]) {
    const f = fixture();
    const request = new Request(`https://api.waozi.xyz/api/v2/packages/inbe.practices/${suffix}`);
    await deliver(request, f.env, {}, f.origin, f.cache);
    assert.deepEqual(f.requests.map(item => item.method), ["GET"]);
    assert.equal(f.state.reads, 0);
    assert.equal(f.state.matches, 0);
  }
});

test("HEAD checks authorization without reading storage or returning a body", async () => {
  const f = fixture();
  const response = await f.get("/valid-grant", { method: "HEAD" });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "");
  assert.equal(f.state.reads, 0);
  assert.equal(f.state.matches, 0);
});

test("missing objects and storage outages preserve origin delivery", async () => {
  for (const outage of [false, true]) {
    const f = fixture();
    f.state.missing = true;
    if (outage) f.env.ARTIFACTS.get = async () => { throw new Error("storage unavailable"); };
    const response = await f.get();
    assert.equal(response.headers.get("X-Daochi-Delivery"), "origin");
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
    assert.deepEqual(f.requests.map(request => request.method), ["HEAD", "GET"]);
  }
});

test("wrong-size objects are discarded in favor of the verified origin", async () => {
  const f = fixture();
  f.env.ARTIFACTS.get = async () => ({ size: bytes.length + 1, body: new Blob([bytes]).stream() });
  const response = await f.get();
  assert.equal(response.headers.get("X-Daochi-Delivery"), "origin");
  assert.equal(f.stored.size, 0);
});

test("range and conditional requests retain the node's existing semantics", async () => {
  for (const headers of [{ Range: "bytes=0-7" }, { "If-None-Match": `"${hash}"` }]) {
    const f = fixture();
    const response = await f.get("/valid-grant", { headers });
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
    assert.equal(f.requests.at(-1).method, "GET");
    assert.equal(f.state.reads, 0);
    assert.equal(f.state.matches, 0);
  }
});
