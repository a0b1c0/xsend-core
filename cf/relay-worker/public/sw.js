const CACHE_NAME = "xsend-shell-v9";
const CORE_ASSETS = [
  "/",
  "/index.html",
  "/app.js",
  "/realtime.js",
  "/vendor/fast_qr_nomod/fast_qr.js",
  "/vendor/fast_qr_nomod/fast_qr_bg.wasm",
  "/vendor/pako/pako.min.js",
];
const NETWORK_FIRST_PATHS = new Set([
  "/",
  "/index.html",
  "/app.js",
  "/realtime.js",
  "/sw.js",
]);

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
      .catch(() => undefined),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== CACHE_NAME)
            .map((k) => caches.delete(k)),
        ),
      )
      .then(() => self.clients.claim())
      .catch(() => undefined),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (!req || req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/")) return;

  if (NETWORK_FIRST_PATHS.has(url.pathname)) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok) {
            caches
              .open(CACHE_NAME)
              .then((cache) => cache.put(req, res.clone()))
              .catch(() => undefined);
          }
          return res;
        })
        .catch(() => caches.match(req, { ignoreSearch: true }).then((cached) => cached || new Response("offline", { status: 503 }))),
    );
    return;
  }

  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((cached) => {
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          if (res && res.ok) {
            caches
              .open(CACHE_NAME)
              .then((cache) => cache.put(req, res.clone()))
              .catch(() => undefined);
          }
          return res;
        })
        .catch(() => cached || new Response("offline", { status: 503 }));
    }),
  );
});
