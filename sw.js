/* Digital Asset Center - Service Worker
 * Uygulama kabuğunu önbelleğe alır (çevrimdışı açılış). API ve Firebase istekleri asla önbelleğe alınmaz. */
const CACHE = "dac-shell-v9";
const SHELL = ["/", "/css/style.css", "/js/app.js", "/js/config.js", "/js/plans.js", "/js/login.js", "/js/sw-register.js", "/js/lucide.min.js", "/js/company.js", "/js/legal.js", "/js/cookie-consent.js", "/manifest.json", "/icons/icon-192.png", "/icons/icon-512.png", "/fonts/inter-latin.woff2", "/fonts/inter-latin-ext.woff2"];

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
      .catch(() => caches.match(req).then((hit) => hit || (req.mode === "navigate" ? caches.match("/") : undefined)))
  );
});
