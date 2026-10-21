/* Digital Asset Center - Service Worker
 * Uygulama kabuğunu önbelleğe alır (çevrimdışı açılış). API ve Firebase istekleri asla önbelleğe alınmaz. */
const CACHE = "dac-shell-v4";
const SHELL = ["./", "index.html", "style.css", "app.js", "config.js", "plans.js", "manifest.json", "icon-192.png", "icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => Promise.all(SHELL.map((u) => c.add(u).catch(() => {})))).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  // Başka sunucular (Firebase, fontlar, scanner API) ve /api istekleri: dokunma
  if (url.origin !== self.location.origin || url.pathname.startsWith("/api/") || url.pathname === "/health") return;

  // Önce ağ (güncel kalsın), olmazsa önbellek
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req).then((hit) => hit || (req.mode === "navigate" ? caches.match("index.html") : undefined)))
  );
});
