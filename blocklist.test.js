// Korumalı hedef listesi (blocklist.js) + yönetici kullanıcı/varlık uçları testleri. Firestore/Firebase için MOCK kullanılır.
process.env.NODE_ENV = "development";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");
const _p = require("path"), _fs = require("fs");
const ROOT = _fs.existsSync(_p.join(__dirname, "index.js")) ? __dirname : _p.join(__dirname, "..");
const LOAD = (n) => require(_fs.existsSync(_p.join(ROOT, "server", n + ".js")) ? _p.join(ROOT, "server", n) : _p.join(ROOT, n));
const INDEX = _p.join(ROOT, "index");
const B = LOAD("blocklist");

const listen = (app) => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const url = (s, p) => `http://127.0.0.1:${s.address().port}${p}`;
const post = (s, p, body, h = {}) => fetch(url(s, p), { method: "POST", headers: { "Content-Type": "application/json", ...h }, body: JSON.stringify(body || {}) });
const blocked = (assetType, targetUrl, extra) => B.checkScan({ assetType, targetUrl, extra }).blocked;

/* ---------------- Kural testleri ---------------- */
test("blocklist: devlet/kamu alan adları (TR ve dünya) engellenir", () => {
  for (const h of ["meb.gov.tr", "https://www.tbmm.gov.tr/x", "turkiye.gov.tr", "ankara.bel.tr", "x.k12.tr", "tsk.tr", "x.mil.tr", "itu.edu.tr", "whitehouse.gov", "army.mil", "service.gov.uk", "gouv.fr", "bund.de", "europa.int", "x.gob.mx"])
    assert.equal(blocked("WEBSITE", h), true, h);
});
test("blocklist: istenen büyük platformlar (google, yandex, render, github, ...) ve alt alan adları engellenir", () => {
  for (const h of ["google.com", "www.google.com", "mail.google.com", "google.com.tr", "google.de", "youtube.com", "yandex.com", "yandex.com.tr", "yandex.ru", "render.com", "dashboard.render.com", "github.com", "gist.github.com", "raw.githubusercontent.com", "gitlab.com", "cloudflare.com", "microsoft.com", "facebook.com", "isbank.com.tr", "trendyol.com"])
    assert.equal(blocked("WEBSITE", h), true, h);
});
test("blocklist: dacweb.tr ve DAC'ın kendi adresleri engellenir (alt alan adı, www, büyük harf, nokta, port, kimlik bilgisi hilesi)", () => {
  for (const h of ["dacweb.tr", "www.dacweb.tr", "API.DACWEB.TR", "dacweb.tr.", "https://dacweb.tr:443/admin", "https://x:y@dacweb.tr", "https://evil.com@dacweb.tr", "https://dacweb.tr%2f@dacweb.tr", "dac-web-tfqf.onrender.com", "hz-yazilim.github.io", "dacweb.xyz"])
    assert.equal(blocked("WEBSITE", h), true, h);
  assert.equal(B.checkScan({ assetType: "SEO", targetUrl: "dacweb.tr" }).category, "own");
});
test("blocklist: OWN_DOMAINS / SITE_URL ortam değişkeniyle eklenen alan adı da engellenir", () => {
  assert.equal(B.checkScan({ assetType: "WEBSITE", targetUrl: "panel.sirketim.com" }, { OWN_DOMAINS: "sirketim.com" }).blocked, true);
  assert.equal(B.checkScan({ assetType: "WEBSITE", targetUrl: "x.sirketim.com.tr" }, { SITE_URL: "https://x.sirketim.com.tr" }).blocked, true);
  assert.equal(B.checkScan({ assetType: "WEBSITE", targetUrl: "bilinmeyen.com" }, { BLOCKED_DOMAINS: "bilinmeyen.com" }).blocked, true);
});
test("blocklist: HİÇBİR tarama türünde analiz edilemez (extra.* alanları dahil)", () => {
  for (const t of ["WEB", "WEBSITE", "DOMAIN", "EMAIL", "SSL_CERTIFICATE", "SSL", "HOSTING", "SERVER", "SEO", "SECURITY", "PERFORMANCE", "UPTIME", "API", "ANALYTICS", "BRAND"]) {
    assert.equal(blocked(t, "meb.gov.tr"), true, t + " hedef"); assert.equal(blocked(t, "", { domain: "google.com" }), true, t + " extra.domain");
    assert.equal(blocked(t, "", { target: "https://www.dacweb.tr" }), true, t + " extra.target");
  }
  assert.equal(blocked("MOBILE_APP", "https://www.google.com"), true); assert.equal(blocked("REPOSITORY", "https://dacweb.tr"), true); assert.equal(blocked("REPOSITORY", "gitlab.com"), true);
});
test("blocklist: normal siteler ve müşteri alt alan adı platformları ENGELLENMEZ (yanlış engelleme yok)", () => {
  for (const h of ["example.com", "benimsitem.com.tr", "notgoogle.com", "googlefan.com", "my-github.com", "apple-orchard.com", "user.github.io", "app.onrender.com", "shop.myshopify.com", "x.azurewebsites.net", "x.workers.dev", "bucket.s3.amazonaws.com", "mysite.com/app.google.js", "https://mysite.com/?u=google.com"])
    assert.equal(blocked("WEBSITE", h), false, h);
});
test("blocklist: platform bağlantısı kullanan türler çalışır, SaaS ağ kullanmadığı için denetlenmez", () => {
  assert.equal(blocked("REPOSITORY", "https://github.com/owner/repo"), false); assert.equal(blocked("REPOSITORY", "owner/repo"), false); assert.equal(blocked("REPOSITORY", "github.com/owner/repo"), false);
  assert.equal(blocked("MOBILE_APP", "https://play.google.com/store/apps/details?id=com.x.y"), false); assert.equal(blocked("MOBILE_APP", "com.google.android.gm"), false); assert.equal(blocked("MOBILE_APP", "https://apps.apple.com/tr/app/x/id123456789"), false);
  assert.equal(blocked("SAAS_SUBSCRIPTION", "", { provider: "google.com" }), false);
  assert.equal(B.checkScan({ assetType: "REPOSITORY", targetUrl: "https://github.com/o/r" }, { BLOCK_STRICT_PLATFORMS: "true" }).blocked, true, "katı mod: platform istisnası kapanır");
});
test("blocklist: CNAME zinciri yalnızca kamu ve DAC'a işaret ediyorsa engeller (CDN/hosting CNAME'i normaldir)", async () => {
  assert.equal(B.checkChain(["x.fastly.net", "www.google.com"]).blocked, false);
  assert.equal(B.checkChain(["a.b.gov.tr"]).blocked, true); assert.equal(B.checkChain(["dacweb.tr"]).blocked, true);
  const map = { "evil.com": ["edge.cdn.net"], "edge.cdn.net": ["www.dacweb.tr"] };
  const chain = await B.resolveCnameChain(async (h) => { if (map[h]) return map[h]; throw new Error("ENODATA"); }, "evil.com");
  assert.deepEqual(chain, ["edge.cdn.net", "www.dacweb.tr"]); assert.equal(B.checkChain(chain).blocked, true);
  const loop = await B.resolveCnameChain(async (h) => (h === "a.com" ? ["b.com"] : ["a.com"]), "a.com"); assert.ok(loop.length <= 2, "CNAME döngüsü sonsuza gitmez");
});
test("blocklist: hata mesajları kural ayrıntısını sızdırmaz", () => {
  const r = B.checkScan({ assetType: "WEBSITE", targetUrl: "meb.gov.tr" }); assert.ok(/Devlet/.test(r.message)); assert.ok(!/gov\.tr/.test(r.message));
});

/* ---------------- Sunucu uçları ---------------- */
test("/api/scan: yasaklı hedef 403 TARGET_BLOCKED döner; hiçbir tarama, kota veya kayıt oluşmaz", async () => {
  process.env.DEV_AUTH_BYPASS = "true"; const s = await listen(require(INDEX));
  for (const [type, target] of [["WEBSITE", "https://www.google.com"], ["SEO", "meb.gov.tr"], ["DOMAIN", "dacweb.tr"], ["SERVER", "yandex.com"], ["SECURITY", "https://render.com"]]) {
    const r = await post(s, "/api/scan", { assetId: "a_" + type, type, targetUrl: target, consent: true }); const j = await r.json();
    assert.equal(r.status, 403, type + " " + target); assert.equal(j.code, "TARGET_BLOCKED"); assert.equal(j.success, false);
  }
  const r2 = await post(s, "/api/scan", { assetId: "b1", type: "DOMAIN", extra: { domain: "tbmm.gov.tr" } }); assert.equal(r2.status, 403, "extra.domain ile gizleme");
  s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("/api/scan: sık yasaklı deneme 429 ile geçici olarak durdurulur", async () => {
  process.env.DEV_AUTH_BYPASS = "true"; process.env.BLOCKED_ATTEMPT_LIMIT = "3";
  delete require.cache[require.resolve(INDEX)]; const s = await listen(require(INDEX)); const codes = [];
  for (let i = 0; i < 6; i++) codes.push((await post(s, "/api/scan", { assetId: "c" + i, type: "WEBSITE", targetUrl: "google.com" })).status);
  assert.deepEqual(codes.slice(0, 3), [403, 403, 403]); assert.ok(codes.slice(3).every((c) => c === 429), codes.join());
  s.close(); delete process.env.DEV_AUTH_BYPASS; delete process.env.BLOCKED_ATTEMPT_LIMIT; delete require.cache[require.resolve(INDEX)];
});
test("/api/jobs: tamamı yasaklı hedeflerden oluşan toplu istek 403 döner ve iş oluşmaz; yasaklı indeksler bildirilir", async () => {
  process.env.DEV_AUTH_BYPASS = "true"; const s = await listen(require(INDEX));
  const r = await post(s, "/api/jobs", { items: [{ assetId: "j1", type: "WEBSITE", target: "https://www.google.com" }, { assetId: "j2", type: "DOMAIN", target: "meb.gov.tr" }, { assetId: "j3", type: "SSL_CERTIFICATE", target: "dacweb.tr" }] });
  const j = await r.json(); assert.equal(r.status, 403); assert.equal(j.code, "TARGET_BLOCKED"); assert.deepEqual(j.blockedIndexes, [0, 1, 2]); assert.ok(j.rejected.every((x) => x.code === "TARGET_BLOCKED"));
  s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("toplu giriş ayıklama (cleanBulkItem): yasaklı hedef reddedilir, normal hedef geçer", () => {
  const { cleanBulkItem } = require(INDEX)._internals;
  for (const [type, target] of [["WEBSITE", "https://github.com"], ["DOMAIN", "yandex.com.tr"], ["SSL_CERTIFICATE", "www.dacweb.tr"], ["SERVER", "tcmb.gov.tr"], ["UPTIME", "https://google.com/x"]]) {
    const r = cleanBulkItem({ assetId: "a1", type, target }, true); assert.ok(r.error && r.blocked, type + " " + target);
  }
  assert.ok(cleanBulkItem({ assetId: "a1", type: "DOMAIN", target: "example.com" }, true).item);
});
test("executeScan son kapısı: yasaklı hedefte handler çağrılmaz, BLOCKED döner", async () => {
  const { executeScan } = require(INDEX)._internals; let called = false;
  const out = await executeScan({ uid: "u1", assetId: "a1", assetType: "WEBSITE", handler: async () => { called = true; return {}; }, targetUrl: "https://meb.gov.tr", extra: {}, name: "x", ip: null });
  assert.equal(out.scanStatus, "BLOCKED"); assert.equal(called, false); assert.equal(out.saved, false);
});
test("queueScanItem: kuyruktaki eski/atlatılmış yasaklı kayıt yeniden denenmeden reddedilir", async () => {
  const { queueScanItem } = require(INDEX)._internals;
  await assert.rejects(() => queueScanItem({ ownerId: "u1", type: "WEBSITE", assetId: "q1", targetUrl: "https://www.github.com", extra: {} }), (e) => e.code === "TARGET_BLOCKED" && e.retriable === false);
});
test("httpProbe: kullanıcının sitesi yasaklı bir siteye yönlendirirse zincir takip edilmez", async () => {
  const redirect = http.createServer((q, r) => { r.writeHead(301, { Location: "https://www.google.com/" }); r.end(); }).listen(0); await new Promise((r) => redirect.on("listening", r));
  process.env.ALLOW_PRIVATE_TARGETS = "true"; delete require.cache[require.resolve(INDEX)];
  const { httpProbe } = require(INDEX)._internals; const res = await httpProbe(`http://127.0.0.1:${redirect.address().port}/`, { maxRedirects: 5, noUaFallback: true, timeout: 4000 });
  assert.equal(res.redirectBlocked, true); assert.equal(res.status, 301); assert.equal(res.redirects, 0, "google.com'a gidilmedi");
  redirect.close(); delete process.env.ALLOW_PRIVATE_TARGETS; delete require.cache[require.resolve(INDEX)];
});

/* ---------------- Yönetici: kullanıcı listesi (yeni→eski) ve varlıklar ---------------- */
function fakeDb(seed = {}) {
  const store = new Map(Object.entries(seed)); let rid = 0;
  const get = (op) => (d) => d; void get;
  const cmp = (a, op, b) => (op === "==" ? a === b : op === ">=" ? a >= b : false);
  const docRef = (path) => ({ id: path.split("/").pop(), path, async get() { const d = store.get(path); return { exists: d !== undefined, id: path.split("/").pop(), data: () => (d === undefined ? undefined : { ...d }) }; }, async set(v, o) { store.set(path, o && o.merge ? { ...(store.get(path) || {}), ...v } : { ...v }); }, async delete() { store.delete(path); }, collection: (c) => col(path + "/" + c) });
  const col = (cpath, filters = [], ord = null, lim = null) => {
    const q = { where: (f, op, v) => col(cpath, [...filters, [f, op, v]], ord, lim), orderBy: (f, d = "asc") => col(cpath, filters, [f, d], lim), limit: (n) => col(cpath, filters, ord, n), doc: (id) => docRef(cpath + "/" + (id || "auto" + ++rid)), add: async (v) => { const r = docRef(cpath + "/auto" + ++rid); await r.set(v); return r; },
      async get() { let rows = [...store.entries()].filter(([k]) => k.startsWith(cpath + "/") && !k.slice(cpath.length + 1).includes("/")).filter(([, d]) => filters.every(([f, op, v]) => cmp(d[f], op, v)));
        if (ord) rows.sort(([, a], [, b]) => (ord[1] === "desc" ? -1 : 1) * ((a[ord[0]] > b[ord[0]]) - (a[ord[0]] < b[ord[0]]))); if (lim) rows = rows.slice(0, lim);
        const docs = rows.map(([k, d]) => ({ id: k.split("/").pop(), data: () => ({ ...d }), ref: docRef(k) })); return { docs, size: docs.length, empty: !docs.length }; },
      count: () => ({ get: async () => ({ data: () => ({ count: (store.size && [...store.keys()].filter((k) => k.startsWith(cpath + "/")).length) || 0 }) }) }) };
    return q;
  };
  return { store, collection: (c) => col(c), runTransaction: async (fn) => fn({ get: (r) => r.get(), set: (r, v) => r.set(v) }) };
}
const mkU = (uid, created, o = {}) => ({ uid, email: uid + "@ornek.com", emailVerified: true, disabled: false, metadata: { creationTime: created, lastSignInTime: created }, providerData: [{ providerId: "password" }], ...o });
function adminApp({ users, seed = {} }) {
  Object.assign(process.env, { ADMIN_UIDS: "root", ADMIN_EMAILS: "" });
  const db = fakeDb(seed); const U = Object.fromEntries(users.map((u) => [u.uid, u]));
  const adm = { apps: [1], auth: () => ({ listUsers: async (n, tok) => ({ users: Object.values(U).sort((a, b) => (a.uid < b.uid ? -1 : 1)), pageToken: undefined }), getUser: async (uid) => { if (!U[uid]) throw new Error("yok"); return U[uid]; }, getUsers: async (ids) => ({ users: ids.map((x) => U[x.uid]).filter(Boolean) }), getUserByEmail: async (e) => { const u = Object.values(U).find((x) => x.email === e); if (!u) throw new Error("yok"); return u; } }) };
  const app = express(); app.use(express.json());
  const verifyUser = async (req) => { const h = req.headers["x-test-user"]; if (!h) throw Object.assign(new Error("Giriş yapmanız gerekiyor."), { status: 401 }); const u = JSON.parse(h); return { uid: u.uid, email: u.email || null, emailVerified: true }; };
  const SEC = LOAD("security"), M = LOAD("metrics"), J = LOAD("jobs"), PLANS = (() => { try { return require(_p.join(ROOT, "plans")); } catch { return require(_p.join(ROOT, "public", "js", "plans")); } })();
  const jobs = J.createJobs({ store: J.memoryStore(), scanItem: async () => ({ scanStatus: "COMPLETED", summary: {} }) }); jobs.stop();
  LOAD("admin")({ app, db, admin: adm, verifyUser, SEC, metrics: M.createMetrics(), jobs, getHealth: async () => ({ ok: true }), platform: async () => ({}), commerce: LOAD("commerce")({ db, PLANS }) });
  return { app, db };
}
const as = (uid) => ({ "Content-Type": "application/json", "x-test-user": JSON.stringify({ uid, email: uid + "@ornek.com" }) });

test("Yönetici kullanıcı listesi: EN YENİ KAYIT EN ÜSTTE (UID sırasından bağımsız), sayfalama ve filtre", async () => {
  // UID alfabetik sırası kayıt sırasının TERSİ: a=en yeni, e=en eski
  const users = [mkU("aaa", "Fri, 30 Oct 2026 10:00:00 GMT"), mkU("bbb", "Thu, 29 Oct 2026 10:00:00 GMT"), mkU("ccc", "Wed, 28 Oct 2026 10:00:00 GMT"), mkU("ddd", "Tue, 27 Oct 2026 10:00:00 GMT"), mkU("eee", "Mon, 26 Oct 2026 10:00:00 GMT", { disabled: true }), mkU("root", "Sun, 01 Jan 2023 10:00:00 GMT")];
  const { app } = adminApp({ users: [...users].reverse() }); const s = await listen(app);
  let j = await (await fetch(url(s, "/api/admin/users?limit=3"), { headers: as("root") })).json();
  assert.deepEqual(j.users.map((u) => u.uid), ["aaa", "bbb", "ccc"]); assert.equal(j.nextPageToken, "3");
  j = await (await fetch(url(s, "/api/admin/users?limit=3&pageToken=3"), { headers: as("root") })).json();
  assert.deepEqual(j.users.map((u) => u.uid), ["ddd", "eee", "root"]); assert.equal(j.nextPageToken, null);
  j = await (await fetch(url(s, "/api/admin/users?status=disabled"), { headers: as("root") })).json(); assert.deepEqual(j.users.map((u) => u.uid), ["eee"]);
  j = await (await fetch(url(s, "/api/admin/users?pageToken=abc'--"), { headers: as("root") })).json(); assert.equal(j.users[0].uid, "aaa", "bozuk pageToken güvenle 0 sayılır");
  assert.equal((await fetch(url(s, "/api/admin/users"), { headers: as("aaa") })).status, 403); assert.equal((await fetch(url(s, "/api/admin/users"))).status, 401);
  s.close();
});
test("Yönetici: kullanıcı varlıkları — taranmış + henüz taranmamış (bulut durumu) birleşir, hassas alanlar dönmez, görüntüleme denetim kaydına yazılır", async () => {
  const state = { assets: [{ id: "w1", cat: "web", target: "ornek.com", name: "Ornek", createdAt: 1000 }, { id: "n1", cat: "domain", target: "yeni.com", name: "yeni.com", createdAt: 5000 }, { id: "s1", cat: "saas", target: "Notion", name: "Notion", extra: { cost: 999, provider: "Notion" }, createdAt: 3000 }], scans: [] };
  const seed = {
    "assets/w1": { ownerId: "u1", name: "Ornek", assetType: "WEBSITE", targetUrl: "https://ornek.com", healthScore: 82, healthLevel: "YEŞİL", status: "HEALTHY", scanStatus: "COMPLETED", findings: ["finding_a_warning", "finding_b_info"], lastCheck: 9000, scanExtra: { gizli: "x" }, specificAnalysis: { buyuk: "veri" } },
    "assets/other": { ownerId: "u2", name: "Baskasi", assetType: "WEBSITE" },
    "users/u1/state/app": { data: JSON.stringify(state), version: 3 },
    "blockedAttempts/b1": { uid: "u1", host: "meb.gov.tr", category: "government", assetType: "WEBSITE", where: "api", at: 7000, ip: "1.2.3.4" },
    "blockedAttempts/b2": { uid: "u2", host: "google.com", category: "protected", assetType: "SEO", where: "api", at: 8000 }
  };
  const { app, db } = adminApp({ users: [mkU("root", "Sun, 01 Jan 2023 10:00:00 GMT"), mkU("u1", "Fri, 30 Oct 2026 10:00:00 GMT"), mkU("u2", "Thu, 29 Oct 2026 10:00:00 GMT")], seed }); const s = await listen(app);
  const r = await fetch(url(s, "/api/admin/users/u1/assets"), { headers: as("root") }); const j = await r.json(); assert.equal(r.status, 200);
  assert.deepEqual(j.assets.map((a) => a.id), ["n1", "s1", "w1"], "en son eklenen üstte"); assert.equal(j.total, 3);
  const w = j.assets.find((a) => a.id === "w1"); assert.equal(w.scanned, true); assert.equal(w.healthScore, 82); assert.equal(w.findingCount, 2); assert.equal(w.type, "WEBSITE");
  assert.equal(j.assets.find((a) => a.id === "n1").scanned, false, "taranmamış varlık da görünür"); assert.equal(j.assets.find((a) => a.id === "s1").target, null);
  const raw = JSON.stringify(j); for (const sec of ["gizli", "buyuk", "scanExtra", "999", "1.2.3.4", "Baskasi"]) assert.ok(!raw.includes(sec), "sızıntı: " + sec);
  assert.equal(j.blocked.count, 1); assert.equal(j.blocked.recent[0].host, "meb.gov.tr");
  const audit = [...db.store.entries()].filter(([k]) => k.startsWith("adminAudit/")).map(([, v]) => v); assert.ok(audit.some((a) => a.action === "user.assets.view" && a.target === "u1" && a.adminUid === "root"), "denetim kaydı");
  const f = await (await fetch(url(s, "/api/admin/users/u1/assets?type=DOMAIN"), { headers: as("root") })).json(); assert.deepEqual(f.assets.map((a) => a.id), ["n1"]);
  assert.equal((await fetch(url(s, "/api/admin/users/u1/assets"), { headers: as("u2") })).status, 403); assert.equal((await fetch(url(s, "/api/admin/users/u1/assets"))).status, 401);
  assert.equal((await fetch(url(s, "/api/admin/users/..%2Fx/assets"), { headers: as("root") })).status, 400);
  s.close();
});
test("Yönetici: yasaklı deneme listesi yalnızca yöneticiye açık ve en yeni üstte", async () => {
  const seed = { "blockedAttempts/b1": { uid: "u1", host: "a.gov.tr", category: "government", at: 1 }, "blockedAttempts/b2": { uid: "u1", host: "google.com", category: "protected", at: 2 } };
  const { app } = adminApp({ users: [mkU("root", "Sun, 01 Jan 2023 10:00:00 GMT"), mkU("u1", "Fri, 30 Oct 2026 10:00:00 GMT")], seed }); const s = await listen(app);
  const j = await (await fetch(url(s, "/api/admin/blocked-attempts"), { headers: as("root") })).json(); assert.deepEqual(j.entries.map((e) => e.host), ["google.com", "a.gov.tr"]);
  assert.equal((await fetch(url(s, "/api/admin/blocked-attempts"), { headers: as("u1") })).status, 403); s.close();
});

/* ---------------- Site adresi (sitemap / robots / canonical) ---------------- */
test("sitemap.xml, robots.txt ve llms.txt dacweb.tr adresini kullanır; SITE_URL eski onrender adresindeyse yok sayılır", async () => {
  process.env.SITE_URL = "https://dac-web-tfqf.onrender.com"; delete require.cache[require.resolve(INDEX)];
  const s = await listen(require(INDEX));
  const sm = await (await fetch(url(s, "/sitemap.xml"))).text(), rb = await (await fetch(url(s, "/robots.txt"))).text(), ll = await (await fetch(url(s, "/llms.txt"))).text();
  for (const [n, t] of [["sitemap", sm], ["robots", rb], ["llms", ll]]) { assert.ok(t.includes("https://dacweb.tr"), n); assert.ok(!/onrender\.com/.test(t), n + " onrender içeriyor"); }
  assert.ok(/<loc>https:\/\/dacweb\.tr\/<\/loc>/.test(sm)); s.close(); delete process.env.SITE_URL; delete require.cache[require.resolve(INDEX)];
});
test("statik sayfalarda canonical/og/JSON-LD adresleri dacweb.tr (Render adresi kalmadı)", () => {
  for (const f of ["index.html", "kvkk.html", "gizlilik.html", "cerez-politikasi.html", "kullanim-kosullari.html", "kabul-edilebilir-kullanim.html", "mesafeli-satis.html", "iade-iptal.html", "hakkimizda.html", "iletisim.html", "sitemap.xml"]) {
    const p = _p.join(ROOT, f); if (!_fs.existsSync(p)) continue; const t = _fs.readFileSync(p, "utf8"); assert.ok(!/dac-web-[a-z]+\.onrender\.com/.test(t), f);
  }
});
