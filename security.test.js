// Güvenlik testleri. NOT: Firestore için MOCK kullanılır (gerçek Firestore entegrasyonunu KANITLAMAZ).
process.env.NODE_ENV = "development";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const SEC = require("../security");

function listen(app) { return new Promise(r => { const s = http.createServer(app).listen(0, () => r(s)); }); }
const call = (s, method, path, opts = {}) => fetch(`http://127.0.0.1:${s.address().port}${path}`, { method, headers: { "Content-Type": "application/json", ...(opts.headers || {}) }, body: opts.body ? JSON.stringify(opts.body) : undefined });

// ---------- SSRF ----------
test("SSRF: özel/yerel IP adresleri engellenir", () => {
  const { isPrivateIp } = require("../index")._internals;
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1"])
    assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34"]) assert.equal(isPrivateIp(ip), false, ip);
});
test("SSRF: localhost, metadata ve .internal adresleri reddedilir", async () => {
  const { assertPublicHost } = require("../index")._internals;
  for (const h of ["localhost", "foo.localhost", "169.254.169.254", "metadata.google.internal", "[::1]", "127.0.0.1"])
    await assert.rejects(() => assertPublicHost(h), /engellendi|yapılamaz/, h);
});

// ---------- Kimlik doğrulama (güvenli varsayılan) ----------
test("Üretimde sahte kullanıcı ASLA oluşmaz (NODE_ENV=production + DEV_AUTH_BYPASS=true)", () => {
  const old = process.env.NODE_ENV; process.env.NODE_ENV = "production"; process.env.DEV_AUTH_BYPASS = "true";
  assert.equal(SEC.devBypass(), false); assert.equal(SEC.isProd(), true);
  process.env.NODE_ENV = ""; assert.equal(SEC.isProd(), true, "tanımsız NODE_ENV = üretim");
  process.env.NODE_ENV = old; delete process.env.DEV_AUTH_BYPASS;
});
test("/api/scan: token yoksa reddedilir (geliştirmede bypass kapalıyken)", async () => {
  delete process.env.DEV_AUTH_BYPASS;
  const s = await listen(require("../index"));
  const r = await call(s, "POST", "/api/scan", { body: { assetId: "a1", type: "WEBSITE", targetUrl: "https://example.com" } });
  assert.ok([401, 503].includes(r.status), "durum: " + r.status); // Firebase yok → 503, token yok → 401
  s.close();
});
test("/api/scan: geliştirmede bypass açıkken özel IP hedefi yine reddedilir (400)", async () => {
  process.env.DEV_AUTH_BYPASS = "true";
  const s = await listen(require("../index"));
  const r = await call(s, "POST", "/api/scan", { body: { assetId: "a1", type: "WEBSITE", targetUrl: "http://169.254.169.254/" } });
  assert.equal(r.status, 400); s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("/api/scan: geçersiz tür ve geçersiz assetId 400 döner", async () => {
  process.env.DEV_AUTH_BYPASS = "true";
  const s = await listen(require("../index"));
  assert.equal((await call(s, "POST", "/api/scan", { body: { assetId: "a1", type: "HACK", targetUrl: "https://example.com" } })).status, 400);
  assert.equal((await call(s, "POST", "/api/scan", { body: { assetId: "../x", type: "WEBSITE", targetUrl: "https://example.com" } })).status, 400);
  s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("Gövde boyut sınırı: 256kb üstü reddedilir", async () => {
  process.env.DEV_AUTH_BYPASS = "true";
  const s = await listen(require("../index"));
  const r = await call(s, "POST", "/api/scan", { body: { assetId: "a1", type: "WEBSITE", targetUrl: "https://example.com", extra: { x: "a".repeat(300000) } } });
  assert.equal(r.status, 413); s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("/health: hassas yapılandırma bilgisi sızdırmaz", async () => {
  const s = await listen(require("../index")); const j = await (await call(s, "GET", "/health")).json();
  assert.deepEqual(Object.keys(j).sort(), ["ok", "payments", "timestamp", "version"]);
  assert.deepEqual(Object.keys(j.payments).sort(), ["iyzico", "stripe"]); s.close();
});
test("Güvenlik başlıkları ve CORS: izinsiz origin CORS başlığı almaz", async () => {
  const s = await listen(require("../index"));
  const r = await call(s, "GET", "/health", { headers: { Origin: "https://evil.example" } });
  assert.equal(r.headers.get("access-control-allow-origin"), null);
  assert.equal(r.headers.get("x-powered-by"), null);
  assert.ok(r.headers.get("content-security-policy-report-only") || r.headers.get("content-security-policy"));
  const ok = await call(s, "GET", "/health", { headers: { Origin: "https://dac-web-tfqf.onrender.com" } });
  assert.equal(ok.headers.get("access-control-allow-origin"), "https://dac-web-tfqf.onrender.com"); s.close();
});

// ---------- Hız / eşzamanlılık ----------
test("Hız sınırı: limit aşılınca false döner", () => { const l = SEC.makeLimiter(2, 1000); assert.ok(l("u") && l("u")); assert.equal(l("u"), false); assert.ok(l("v")); });
test("Eşzamanlılık: kullanıcı başına sınır ve serbest bırakma", () => {
  const c = SEC.makeConcurrency(2, 5); const a = c.acquire("u"), b = c.acquire("u");
  assert.ok(a && b); assert.equal(c.acquire("u"), null); a(); a(); assert.ok(c.acquire("u"));
});

// ---------- Sahiplik ve kota (MOCK Firestore) ----------
function fakeDb(docs = {}) {
  return {
    docs,
    collection: () => ({
      doc: (id) => ({ _id: id }),
      where: (f, op, v) => ({ count: () => ({ get: async () => ({ data: () => ({ count: Object.values(docs).filter(d => d[f] === v).length }) }) }) })
    }),
    runTransaction: async (fn) => fn({ get: async (ref) => ({ exists: ref._id in docs, data: () => docs[ref._id] }), set: (ref, d) => { docs[ref._id] = { ...(docs[ref._id] || {}), ...d }; } })
  };
}
test("Sahiplik: başkasının varlığı reddedilir, kendi varlığı kabul edilir, sahipsiz varlık sahiplenilir", async () => {
  const db = fakeDb({ a1: { ownerId: "alice" }, legacy: {} });
  assert.equal((await SEC.claimAsset(db, "a1", "bob")).ok, false);
  assert.equal((await SEC.claimAsset(db, "a1", "alice")).ok, true);
  assert.equal((await SEC.claimAsset(db, "legacy", "bob")).ok, true); assert.equal(db.docs.legacy.ownerId, "bob");
  const n = await SEC.claimAsset(db, "new1", "bob"); assert.deepEqual(n, { ok: true, isNew: true });
});
test("Kota: deneme paketi 3 varlıkla sınırlı", async () => {
  const db = fakeDb({ x1: { ownerId: "u" }, x2: { ownerId: "u" }, x3: { ownerId: "u" }, x4: { ownerId: "u" } });
  assert.equal((await SEC.checkAssetQuota(db, "u", "trial", true)).ok, false);
  assert.equal((await SEC.checkAssetQuota(db, "u", "trial", false)).ok, true, "mevcut varlığı yeniden taramak kotaya takılmaz");
  assert.equal((await SEC.checkAssetQuota(db, "u", "enterprise", true)).ok, true, "sınırsız paket");
});

// ---------- Ödeme: Stripe imzası ----------
test("Stripe webhook imza doğrulaması: geçerli kabul, bozuk/eski ret", () => {
  const crypto = require("crypto");
  const { verifyStripeSignature } = require("../payments")({ app: { get() {}, post() {} }, db: null, admin: { apps: [] }, http: null });
  const raw = Buffer.from('{"id":"evt_1"}'), secret = "whsec_test", t = Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac("sha256", secret).update(`${t}.`).update(raw).digest("hex");
  assert.equal(verifyStripeSignature(raw, `t=${t},v1=${sig}`, secret), true);
  assert.equal(verifyStripeSignature(raw, `t=${t},v1=${sig.replace(/.$/, "0")}`, secret), false);
  assert.equal(verifyStripeSignature(raw, `t=${t - 4000},v1=${sig}`, secret), false);
  assert.equal(verifyStripeSignature(Buffer.from("x"), `t=${t},v1=${sig}`, secret), false);
});
test("Paket fiyatları tutarlı (yıllık = 10 ay)", () => {
  const P = require("../plans"); assert.equal(P.price("kobi", "TRY", "yearly"), Math.round(4999.99 * 10 * 100) / 100);
  assert.equal(P.price("yok", "TRY", "monthly"), null);
});
