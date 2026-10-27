/* Digital Asset Center - Service Worker
 * Uygulama kabuğunu önbelleğe alır (çevrimdışı açılış). API ve Firebase istekleri asla önbelleğe alınmaz. */
const CACHE = "dac-shell-v20";
const SHELL = ["/", "/css/style.css", "/js/app.js", "/js/app-analysis.js", "/js/app-main.js", "/js/app-bulk.js", "/js/app-admin.js", "/js/app-admin-ops.js", "/js/app-support.js", "/js/config.js", "/js/plans.js", "/js/login.js", "/js/sw-register.js", "/js/lucide.min.js", "/js/company.js", "/js/legal.js", "/js/cookie-consent.js", "/manifest.json", "/icons/icon-192.png", "/icons/icon-512.png", "/fonts/inter-latin.woff2", "/fonts/inter-latin-ext.woff2"];

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

// ---------- Tarayıcı bildirimleri (Web Push) ----------
self.addEventListener("push", (e) => {
  let d = {}; try { d = e.data ? e.data.json() : {}; } catch { d = { title: "Digital Asset Center", body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(String(d.title || "Digital Asset Center").slice(0, 100), {
    body: String(d.body || "").slice(0, 300), icon: "/icons/icon-192.png", badge: "/icons/icon-192.png", tag: d.tag || undefined, renotify: !!d.tag, data: { url: typeof d.url === "string" && d.url.startsWith("/") ? d.url : "/" }
  }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || "/";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
    for (const c of list) { if (new URL(c.url).origin === self.location.origin && "focus" in c) { c.navigate(url).catch(() => {}); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});
