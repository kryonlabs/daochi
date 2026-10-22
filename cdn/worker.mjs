// Cache immutable ZIB bytes, while the node remains the authority on every
// request. The R2 bucket is private and only the reviewed mirror tool writes it.
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const ARTIFACT_PATH = /^\/api\/v2\/packages\/([a-z0-9][a-z0-9.-]{0,127})\/([a-f0-9]{64})\.zib(?:\/[A-Za-z0-9_.-]+)?$/;

function artifactRequest(request) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return null;
  }
  const url = new URL(request.url);
  if (url.search || request.headers.has("Range")) {
    return null;
  }
  const match = ARTIFACT_PATH.exec(url.pathname);
  if (!match) {
    return null;
  }
  return {
    hash: match[2],
    key: `${match[1]}/${match[2]}.zib`,
    cacheKey: new Request(`${url.origin}/.package-cache/${match[1]}/${match[2]}.zib`),
  };
}

function authorizationRequest(request) {
  const headers = new Headers(request.headers);
  for (const name of ["If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "Range"]) {
    headers.delete(name);
  }
  headers.set("Accept-Encoding", "identity");
  headers.set("Cache-Control", "no-cache");
  return new Request(request.url, { method: "HEAD", headers, redirect: "manual" });
}

function artifactSize(headers) {
  const value = headers.get("Content-Length");
  if (value === null) {
    return null;
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    return -1;
  }
  const size = Number(value);
  return Number.isSafeInteger(size) && size <= MAX_ARTIFACT_BYTES ? size : -1;
}

function responseHeaders(authorization, hash, size, delivery) {
  // CORS and access policy come from this request's node response, never
  // another person's cached headers. Grant URLs stay private and uncached.
  const headers = new Headers(authorization.headers);
  headers.delete("Content-Encoding");
  headers.delete("Transfer-Encoding");
  headers.delete("Set-Cookie");
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Length", String(size));
  headers.set("ETag", `"${hash}"`);
  headers.set("X-Daochi-Delivery", delivery);
  return headers;
}

async function originResponse(request, fetchOrigin) {
  const response = await fetchOrigin(request);
  const headers = new Headers(response.headers);
  headers.set("X-Daochi-Delivery", "origin");
  return new Response(response.body, { status: response.status, headers });
}

export async function deliver(request, env, context, fetchOrigin, cache) {
  const artifact = artifactRequest(request);
  if (!artifact) {
    return fetchOrigin(request);
  }

  // HEAD follows exactly the existing registry, publisher, signature, grant
  // and artifact-integrity checks. Never use a cache hit before this succeeds.
  const authorization = await fetchOrigin(authorizationRequest(request), {
    cf: { cacheTtl: 0, cacheEverything: false },
  });
  if (authorization.status !== 200) {
    const headers = new Headers(authorization.headers);
    headers.set("Cache-Control", "no-store");
    return new Response(null, { status: authorization.status, headers });
  }
  const policy = authorization.headers.get("Cache-Control") || "";
  const expectedSize = artifactSize(authorization.headers);
  if (authorization.headers.get("ETag") !== `"${artifact.hash}"` || expectedSize === -1 ||
      (!policy.includes("immutable") && !policy.includes("private"))) {
    return originResponse(request, fetchOrigin);
  }
  if (request.method === "HEAD") {
    return new Response(null, { headers: authorization.headers });
  }

  // Conditional and range semantics stay with the node. This also prevents
  // a locally cached 304 from outliving a revoked publisher or expired grant.
  if (request.headers.has("If-None-Match") || request.headers.has("If-Modified-Since") ||
      request.headers.has("If-Match") || request.headers.has("If-Unmodified-Since")) {
    return originResponse(request, fetchOrigin);
  }

  try {
    const cached = await cache.match(artifact.cacheKey);
    if (cached) {
      const size = artifactSize(cached.headers);
      if (cached.headers.get("ETag") === `"${artifact.hash}"` && size > 0 &&
          (expectedSize === null || expectedSize === size)) {
        return new Response(cached.body, {
          headers: responseHeaders(authorization, artifact.hash, size, "edge"),
        });
      }
      await cached.body?.cancel();
      await cache.delete(artifact.cacheKey);
    }

    const object = await env.ARTIFACTS.get(artifact.key);
    if (!object || object.size <= 0 || object.size > MAX_ARTIFACT_BYTES ||
        (expectedSize !== null && object.size !== expectedSize)) {
      await object?.body?.cancel();
      return originResponse(request, fetchOrigin);
    }
    const headers = responseHeaders(authorization, artifact.hash, object.size, "r2");
    const response = new Response(object.body, { headers });
    const stored = new Response(response.clone().body, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(object.size),
        "ETag": `"${artifact.hash}"`,
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    });
    // Only this internal cache key holds shared bytes. The response to a
    // gated download retains the node's private/no-store policy.
    context.waitUntil(cache.put(artifact.cacheKey, stored).catch(() => {}));
    return response;
  } catch {
    // A storage/cache outage leaves the original verified delivery available.
    return originResponse(request, fetchOrigin);
  }
}

export default {
  async fetch(request, env, context) {
    // A named cache is isolated from Cloudflare's public default HTTP cache.
    // Its keys must never become an alternative public URL for a paid pack.
    let cache;
    try {
      cache = await caches.open("package-artifacts-v1");
    } catch {
      return fetch(request);
    }
    return deliver(request, env, context, fetch, cache);
  },
};
