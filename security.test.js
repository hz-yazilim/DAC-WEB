// Güvenlik testleri. NOT: Firestore için MOCK kullanılır (gerçek Firestore entegrasyonunu KANITLAMAZ).
process.env.NODE_ENV = "development";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const SEC = require("../server/security");
const PUB = (...p) => require("path").join(__dirname, "..", "public", ...p);

function listen(app) { return new Promise(r => { const s = http.createServer(app).listen(0, () => r(s)); }); }
const call = (s, method, path, opts = {}) => fetch(`http://127.0.0.1:${s.address().port}${path}`, { method, headers: { "Content-Type": "application/json", ...(opts.headers || {}) }, body: opts.body ? JSON.stringify(opts.body) : undefined });

// ---------- SSRF ----------
test("SSRF: özel/yerel IP adresleri engellenir", () => {
  const { isPrivateIp } = require("../index")._internals;
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1"])
    assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2001:4860:4860::8888"]) assert.equal(isPrivateIp(ip), false, ip);
});
test("SSRF: IPv6 ile gizlenmiş yerel adresler engellenir (URL ayrıştırıcının ürettiği biçimler dahil)", () => {
  const { isPrivateIp } = require("../index")._internals;
  for (const u of ["http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.5]/", "http://[::ffff:169.254.169.254]/", "http://[::127.0.0.1]/", "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::]/", "http://2130706433/", "http://127.1/"]) {
    const h = new URL(u).hostname.replace(/^\[|\]$/g, "");
    assert.equal(isPrivateIp(h), true, u + " -> " + h);
  }
  assert.equal(isPrivateIp("::ffff:8.8.8.8"), false);
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
  assert.equal((await SEC.claimAsset(db, "legacy", "bob")).ok, false, "sahipsiz mevcut belge varsayılan olarak devredilmez");
  process.env.ALLOW_CLAIM_LEGACY_ASSETS = "true"; assert.equal((await SEC.claimAsset(db, "legacy", "bob")).ok, true); assert.equal(db.docs.legacy.ownerId, "bob"); delete process.env.ALLOW_CLAIM_LEGACY_ASSETS;
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
  const { verifyStripeSignature } = require("../server/payments")({ app: { get() {}, post() {} }, db: null, admin: { apps: [] }, http: null });
  const raw = Buffer.from('{"id":"evt_1"}'), secret = "whsec_test", t = Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac("sha256", secret).update(`${t}.`).update(raw).digest("hex");
  assert.equal(verifyStripeSignature(raw, `t=${t},v1=${sig}`, secret), true);
  assert.equal(verifyStripeSignature(raw, `t=${t},v1=${sig.slice(0, -1) + (sig.slice(-1) === "0" ? "1" : "0")}`, secret), false);
  assert.equal(verifyStripeSignature(raw, `t=${t - 4000},v1=${sig}`, secret), false);
  assert.equal(verifyStripeSignature(Buffer.from("x"), `t=${t},v1=${sig}`, secret), false);
});
test("Paket fiyatları tutarlı (yıllık = 10 ay)", () => {
  const P = require("../public/js/plans"); assert.equal(P.price("kobi", "TRY", "yearly"), Math.round(4999.99 * 10 * 100) / 100);
  assert.equal(P.price("yok", "TRY", "monthly"), null);
});

// ---------- Firebase token doğrulama (yerel üretilen anahtarla; gerçek Google anahtarını KANITLAMAZ) ----------
test("Token doğrulama: geçerli kabul; yanlış proje, süresi dolmuş, bozuk imza reddedilir", async () => {
  const crypto = require("crypto");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const P = "proje-x", now = Math.floor(Date.now() / 1000);
  const mk = (over = {}, key = privateKey) => {
    const h = Buffer.from(JSON.stringify({ alg: "RS256", kid: "k1" })).toString("base64url");
    const b = Buffer.from(JSON.stringify({ sub: "u1", email: "a@b.c", aud: P, iss: "https://securetoken.google.com/" + P, iat: now, exp: now + 3600, ...over })).toString("base64url");
    return `${h}.${b}.${crypto.sign("RSA-SHA256", Buffer.from(h + "." + b), key).toString("base64url")}`;
  };
  const o = { getKey: async (kid) => (kid === "k1" ? publicKey : null) };
  assert.equal((await SEC.verifyFirebaseToken(mk(), P, o)).uid, "u1");
  await assert.rejects(() => SEC.verifyFirebaseToken(mk({ aud: "baska" }), P, o), /doğrulanamadı/);
  await assert.rejects(() => SEC.verifyFirebaseToken(mk({ exp: now - 10 }), P, o), /doğrulanamadı/);
  await assert.rejects(() => SEC.verifyFirebaseToken(mk({}, other.privateKey), P, o), /doğrulanamadı/);
  await assert.rejects(() => SEC.verifyFirebaseToken("a.b.c", P, o), /doğrulanamadı/);
});

// ---------- Firebase yapılandırması / e-posta girişi / sahiplik (bu sürümde eklendi) ----------
test("Hizmet hesabı: eksik, bozuk JSON ve yanlış proje reddedilir; anahtar mesajda geçmez", () => {
  const FBI = require("../server/firebase-init");
  const mk = (o = {}) => ({ type: "service_account", project_id: "assetops-ed334", client_email: "x@assetops-ed334.iam.gserviceaccount.com", private_key: "-----BEGIN PRIVATE KEY-----\nSECRETKEY\n-----END PRIVATE KEY-----\n", ...o });
  assert.equal(FBI.parseServiceAccount({}).code, "MISSING");
  assert.equal(FBI.parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT: "{bozuk" }).code, "BAD_JSON");
  const old = FBI.parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT: JSON.stringify(mk({ project_id: "varlik-operasyonlari-ed334", client_email: "x@varlik-operasyonlari-ed334.iam.gserviceaccount.com" })) });
  assert.equal(old.ok, false); assert.equal(old.code, "OLD_PROJECT"); assert.ok(!JSON.stringify(old).includes("SECRETKEY"));
  assert.equal(FBI.parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT: JSON.stringify(mk({ project_id: "baska-proje" })) }).code, "PROJECT_MISMATCH");
  assert.equal(FBI.parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT: JSON.stringify(mk()), FIREBASE_PROJECT_ID: "varlik-operasyonlari-ed334" }).code, "BAD_PROJECT");
  assert.equal(FBI.parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT: JSON.stringify(mk()) }).ok, true);
  assert.equal(FBI.parseServiceAccount({ FIREBASE_SERVICE_ACCOUNT_B64: Buffer.from(JSON.stringify(mk())).toString("base64") }).ok, true);
});
test("Web yapılandırması: eksik değişkenler adıyla bildirilir, uydurulmaz", () => {
  const FBI = require("../server/firebase-init");
  const r = FBI.webConfig({}); assert.equal(r.ok, false);
  assert.deepEqual(r.missing.sort(), ["FIREBASE_WEB_API_KEY", "FIREBASE_WEB_APP_ID", "FIREBASE_WEB_AUTH_DOMAIN", "FIREBASE_WEB_MESSAGING_SENDER_ID"]);
  const ok = FBI.webConfig({ FIREBASE_WEB_API_KEY: "k", FIREBASE_WEB_AUTH_DOMAIN: "assetops-ed334.firebaseapp.com", FIREBASE_WEB_APP_ID: "1:1:web:1", FIREBASE_WEB_MESSAGING_SENDER_ID: "1" });
  assert.equal(ok.ok, true); assert.equal(ok.config.projectId, "assetops-ed334");
  assert.equal(FBI.webConfig({ FIREBASE_WEB_API_KEY: "k", FIREBASE_WEB_AUTH_DOMAIN: "varlik-operasyonlari-ed334.firebaseapp.com", FIREBASE_WEB_APP_ID: "1:1:web:1", FIREBASE_WEB_MESSAGING_SENDER_ID: "1" }).ok, false);
});
test("/api/firebase-config: env yokken 503 + eksik liste", async () => {
  for (const k of Object.keys(process.env)) if (k.startsWith("FIREBASE_WEB_")) delete process.env[k];
  const s = await listen(require("../index")); const r = await call(s, "GET", "/api/firebase-config");
  assert.equal(r.status, 503); s.close();
});
test("E-posta/şifre hesabı doğrulanmadan reddedilir; Google ve doğrulanmış hesap geçer", () => {
  const t = (provider, verified) => ({ firebase: { sign_in_provider: provider }, email_verified: verified });
  assert.throws(() => SEC.assertEmailVerified(t("password", false)), (e) => e.status === 403 && e.code === "EMAIL_NOT_VERIFIED");
  SEC.assertEmailVerified(t("password", true)); SEC.assertEmailVerified(t("google.com", false));
});
test("Sahipsiz mevcut belge devredilmez (ALLOW_CLAIM_LEGACY_ASSETS kapalıyken)", async () => {
  const docs = { legacy: { assetId: "legacy" } };
  const db = { collection: () => ({ doc: (id) => ({ id }) }), runTransaction: async (fn) => fn({ get: async (r) => ({ exists: !!docs[r.id], data: () => docs[r.id] }), set: () => { throw new Error("yazılmamalı"); } }) };
  delete process.env.ALLOW_CLAIM_LEGACY_ASSETS;
  const r = await SEC.claimAsset(db, "legacy", "bob"); assert.equal(r.ok, false); assert.equal(r.legacy, true);
});
test("Kullanıcı durumu: geçersiz yapı reddedilir, plan/apiUrl buluta yazılmaz, __proto__ temizlenir", () => {
  const { sanitizeState } = require("../server/user-state");
  assert.throws(() => sanitizeState(null)); assert.throws(() => sanitizeState({ assets: "x" })); assert.throws(() => sanitizeState({ assets: [{ nope: 1 }] }));
  const o = sanitizeState(JSON.parse('{"assets":[{"id":"a1","__proto__":{"x":1}}],"settings":{"plan":"enterprise","apiUrl":"http://x","org":"A"}}'));
  assert.equal(o.settings.plan, undefined); assert.equal(o.settings.apiUrl, undefined); assert.equal(o.settings.org, "A"); assert.equal({}.x, undefined);
});
test("/api/state: token yoksa reddedilir", async () => {
  delete process.env.DEV_AUTH_BYPASS; const s = await listen(require("../index"));
  const r = await call(s, "GET", "/api/state"); assert.ok([401, 503].includes(r.status), "durum: " + r.status); s.close();
});
test("ANALYTICS tarayıcısı: etiket ve ölçüm kimliği eşleşmesi, canlı veri alanları null", async () => {
  const { scanAnalytics } = require("../index")._internals; assert.equal(typeof scanAnalytics, "function");
});

// ===== v13 sertleştirme testleri =====
test("SSRF: IP-literal ve yerel adlar engellenir; HTTP istemcisi bağlantı kurmadan reddeder", async () => {
  delete process.env.ALLOW_PRIVATE_TARGETS;
  const I = require("../index")._internals;
  for (const h of ["127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.1", "172.16.5.5", "::1", "[::1]", "localhost", "foo.localhost", "db.internal", "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"]) assert.equal(I.blockedHost(h), true, h);
  for (const h of ["example.com", "8.8.8.8", "1.1.1.1"]) assert.equal(I.blockedHost(h), false, h);
  // yönlendirme zinciriyle gelebilecek adresler: ağ trafiği oluşmadan hata döner
  for (const u of ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:3000/", "http://[::1]/", "ftp://example.com/", "data:text/plain,x", "file:///etc/passwd"]) {
    const r = await I.request(u, { timeout: 3000 });
    assert.equal(r.ok, false, u); assert.equal(r.status, 0, u);
  }
});
test("HTML ayrıştırıcı: düşman girdiler doğrusal sürede biter (ReDoS yok)", () => {
  const I = require("../index")._internals;
  const bad = { meta: "<meta ".repeat(250000), script: "<script ".repeat(180000), h1: "<h1>".repeat(300000), title: "<title>".repeat(200000), lt: "<".repeat(1500000), comment: "<!--".repeat(300000), a: "<a href=".repeat(150000) };
  for (const [k, v] of Object.entries(bad)) { const t = Date.now(); I.analyzeHtml(v, "https://x.com/"); assert.ok(Date.now() - t < 6000, `${k} ${Date.now() - t}ms`); }
});
test("HTML ayrıştırıcı: normal sayfada beklenen alanlar çıkar", () => {
  const I = require("../index")._internals;
  const A = I.analyzeHtml('<!doctype html><html lang="tr"><head><title>Merhaba &amp; dünya</title><meta name="description" content="Açıklama"><link rel="canonical" href="https://x.com/"><script type="application/ld+json">{"@type":"Organization"}</script></head><body><h1>Başlık <b>bir</b></h1><img src="a.png"><a href="https://e.com/" rel="nofollow">e</a><script>var a=1<2;</script><script src="https://cdn.x/a.js"></script><form action="http://x.com/p"><input type="password"></form><!-- <h1>gizli</h1> --></body></html>', "https://x.com/");
  assert.equal(A.title, "Merhaba & dünya"); assert.equal(A.htmlLang, "tr"); assert.deepEqual(A.h1, ["Başlık bir"]); assert.equal(A.h1Count, 1);
  assert.equal(A.images.missingAlt, 1); assert.equal(A.inlineScripts, 2); /* JSON-LD + satır içi script */ assert.equal(A.externalScriptsNoSri, 1); assert.deepEqual(A.jsonld.types, ["Organization"]);
  assert.equal(A.insecureForm, true); assert.equal(A.hasPasswordField, true); assert.equal(A.metaDescription, "Açıklama"); assert.equal(A.canonical, "https://x.com/");
});
test("decodeEntities: çift çözümleme yok (&amp;lt; -> &lt;)", () => {
  const I = require("../index")._internals;
  assert.equal(I.decodeEntities("&amp;lt;script&amp;gt;"), "&lt;script&gt;"); assert.equal(I.decodeEntities("a &lt; b &amp; c"), "a < b & c");
});
test("/api/scan: Sunucu/Güvenlik taraması yetki beyanı olmadan 400 CONSENT_REQUIRED", async () => {
  process.env.DEV_AUTH_BYPASS = "true";
  const s = await listen(require("../index"));
  for (const type of ["SERVER", "SECURITY"]) {
    const r = await call(s, "POST", "/api/scan", { body: { assetId: "a1", type, targetUrl: "https://example.com" } });
    assert.equal(r.status, 400); assert.equal((await r.json()).code, "CONSENT_REQUIRED");
  }
  s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("/api/scan: targetUrl metin değilse 400", async () => {
  process.env.DEV_AUTH_BYPASS = "true";
  const s = await listen(require("../index"));
  const r = await call(s, "POST", "/api/scan", { body: { assetId: "a1", type: "WEBSITE", targetUrl: { toString: "x" } } });
  assert.equal(r.status, 400); s.close(); delete process.env.DEV_AUTH_BYPASS;
});
test("Hesap uç noktaları ve ödeme: token yoksa reddedilir", async () => {
  delete process.env.DEV_AUTH_BYPASS;
  const s = await listen(require("../index"));
  for (const [m, p] of [["GET", "/api/account/export"], ["DELETE", "/api/account"], ["POST", "/api/consent"], ["POST", "/api/checkout"], ["GET", "/api/state"]]) {
    const r = await call(s, m, p, { body: m === "GET" ? undefined : {} });
    assert.ok([401, 503].includes(r.status), `${m} ${p} -> ${r.status}`); await r.arrayBuffer();
  }
  s.close();
});
test("Stripe imzası: ASCII dışı / hatalı biçimli imza istisna fırlatmaz", () => {
  const { verifyStripeSignature } = require("../server/payments")({ app: { get() {}, post() {} }, db: null, admin: { apps: [] }, http: null });
  const t = Math.floor(Date.now() / 1000);
  assert.equal(verifyStripeSignature(Buffer.from("{}"), `t=${t},v1=${"é".repeat(64)}`, "whsec_x"), false);
  assert.equal(verifyStripeSignature(Buffer.from("{}"), `t=${t},v1=zz`, "whsec_x"), false);
});
test("Yasal sayfalar ve yerel varlıklar yayınlanır; üçüncü taraf CDN/font yok", async () => {
  const fs = require("fs"); const s = await listen(require("../index"));
  for (const p of ["/kvkk", "/gizlilik", "/cerez-politikasi", "/kullanim-kosullari", "/mesafeli-satis", "/iade-iptal", "/iletisim", "/kabul-edilebilir-kullanim", "/js/lucide.min.js", "/fonts/inter-latin.woff2", "/js/company.js", "/js/cookie-consent.js", "/js/legal.js", "/css/style.css", "/icons/icon-192.png", "/manifest.json", "/sw.js"]) {
    const r = await call(s, "GET", p); assert.equal(r.status, 200, p); await r.arrayBuffer();
  }
  const html = fs.readFileSync(PUB("index.html"), "utf8"), css = fs.readFileSync(PUB("css/style.css"), "utf8");
  assert.ok(!/fonts\.googleapis|fonts\.gstatic|cdn\.jsdelivr/.test(html + css), "dış CDN/font referansı kalmış");
  assert.ok(!/(?:^|[^a-z])\/api\/health/.test(html));
  const home = await call(s, "GET", "/"); const csp = home.headers.get("content-security-policy") || ""; await home.arrayBuffer();
  assert.ok(csp.includes("default-src"), "CSP başlığı yok"); assert.ok(!/jsdelivr|fonts\.g/.test(csp), csp); s.close();
});
test("Yasal sayfalar: şirket bilgileri tek kaynaktan, zorunlu belgeler mevcut", () => {
  const fs = require("fs");
  for (const f of ["kvkk", "gizlilik", "cerez-politikasi", "kullanim-kosullari", "mesafeli-satis", "iade-iptal", "iletisim", "kabul-edilebilir-kullanim"]) {
    const h = fs.readFileSync(PUB("legal/" + f + ".html"), "utf8"); assert.ok(h.includes("company.js") && h.includes("legal.js") && h.includes("data-co="), f);
  }
  assert.ok(fs.readFileSync(PUB("legal/kvkk.html"), "utf8").includes("m.11")); assert.ok(fs.readFileSync(PUB("legal/mesafeli-satis.html"), "utf8").includes("m.15/1-(ğ)"));
});

test("Dosya yapısı: sunucu kodu ve gizli dosyalar HTTP ile yayınlanmaz; eski adresler yönlendirilir", async () => {
  const s = await listen(require("../index"));
  for (const p of ["/index.js", "/index.py", "/package.json", "/server/security.js", "/server/payments.js", "/firestore.rules", "/.env", "/.gitignore", "/tests/security.test.js", "/docs/RAPOR_ve_EKSIKLIK_LISTESI.md", "/public/index.html", "/../index.js", "/%2e%2e/index.js", "/js/../../index.js"]) {
    const r = await call(s, "GET", p); assert.ok([301, 400, 404].includes(r.status) && !(r.headers.get("content-type") || "").includes("javascript"), `${p} -> ${r.status}`); await r.arrayBuffer();
  }
  for (const [from, to] of [["/style.css", "/css/style.css"], ["/app.js", "/js/app.js"], ["/kvkk.html", "/legal/kvkk.html"], ["/inter-latin.woff2", "/fonts/inter-latin.woff2"], ["/icon-192.png", "/icons/icon-192.png"]]) {
    const r = await fetch(`http://127.0.0.1:${s.address().port}${from}`, { redirect: "manual" }); assert.equal(r.status, 301, from); assert.equal(r.headers.get("location"), to); await r.arrayBuffer();
  }
  s.close();
});
test("Dosya yapısı: HTML/CSS/SW içindeki her yerel varlık yolu gerçekten mevcut", () => {
  const fs = require("fs"), path = require("path"), root = path.join(__dirname, "..", "public");
  const files = []; (function walk(d) { for (const f of fs.readdirSync(d)) { const p = path.join(d, f); fs.statSync(p).isDirectory() ? walk(p) : files.push(p); } })(root);
  const exists = (u) => { u = u.split("?")[0].split("#")[0]; if (!u || u === "/") return true; if (/^\/(kvkk|gizlilik|cerez-politikasi|kullanim-kosullari|kabul-edilebilir-kullanim|mesafeli-satis|iade-iptal|iletisim|health|api\/|\.well-known\/)/.test(u)) return true; return fs.existsSync(path.join(root, u)); };
  const bad = [];
  for (const f of files.filter((x) => /\.(html|css|json|js)$/.test(x) && !/lucide/.test(x))) {
    const src = fs.readFileSync(f, "utf8");
    for (const m of src.matchAll(/(?:href|src)="(\/[^"#]*)"/g)) if (!exists(m[1])) bad.push(path.relative(root, f) + " -> " + m[1]);
    if (f.endsWith("sw.js")) for (const m of src.matchAll(/"(\/[^"]+)"/g)) if (!exists(m[1])) bad.push("sw.js -> " + m[1]);
    if (f.endsWith("style.css")) for (const m of src.matchAll(/url\(([^)]+)\)/g)) { const u = m[1].replace(/["']/g, ""); if (!/^data:/.test(u) && !fs.existsSync(path.join(path.dirname(f), u))) bad.push("style.css -> " + u); }
    if (f.endsWith("manifest.json")) for (const m of src.matchAll(/"src":\s*"([^"]+)"/g)) if (!exists(m[1])) bad.push("manifest -> " + m[1]);
  }
  assert.deepEqual(bad, []);
});
