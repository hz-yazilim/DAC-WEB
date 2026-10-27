// DAC V13.2 testleri: yönetici fiyat/limit yönetimi, kupon, duyuru/bakım, gelir özeti, kullanıcı müdahaleleri.
// Firestore ve Firebase Auth için MOCK kullanılır (gerçek servisleri KANITLAMAZ).
process.env.NODE_ENV = "development";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const _p = require("path"), _fs = require("fs");
const ROOT = _fs.existsSync(_p.join(__dirname, "index.js")) ? __dirname : _p.join(__dirname, "..");
const LOAD = (n) => require(_fs.existsSync(_p.join(ROOT, "server", n + ".js")) ? _p.join(ROOT, "server", n) : _p.join(ROOT, n));
const PLANS = (() => { try { return require(_p.join(ROOT, "public", "js", "plans")); } catch { return require(_p.join(ROOT, "plans")); } })();
const express = require("express");
const listen = (app) => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const url = (s, p) => `http://127.0.0.1:${s.address().port}${p}`;
const as = (uid, extra = {}) => ({ "x-test-user": JSON.stringify({ uid, email: uid + "@ornek.com", emailVerified: true, ...extra }), "Content-Type": "application/json" });

// ---- Sahte Firestore ----
function memFs(seed = {}) {
  const store = { ...seed }; let n = 0;
  const docsOf = (c, f, dir) => { let rows = Object.entries(store).filter(([k]) => k.startsWith(c + "/")).map(([k, v]) => ({ id: k.slice(c.length + 1), data: () => v })); if (f) rows.sort((a, b) => (dir === "desc" ? -1 : 1) * ((a.data()[f] || 0) - (b.data()[f] || 0))); return { docs: rows, size: rows.length }; };
  const col = (c) => ({
    doc: (id) => { id = id || "auto" + ++n; const k = c + "/" + id; return { id, get: async () => ({ exists: k in store, id, data: () => store[k] }), set: async (d, o) => { store[k] = o && o.merge ? { ...(store[k] || {}), ...d } : { ...d }; }, delete: async () => { delete store[k]; } }; },
    add: async (d) => { const id = "auto" + ++n; store[c + "/" + id] = d; return { id }; },
    limit: () => ({ get: async () => docsOf(c) }), orderBy: (f, dir) => ({ limit: () => ({ get: async () => docsOf(c, f, dir) }) }),
    where: (f, op, v) => ({ count: () => ({ get: async () => ({ data: () => ({ count: docsOf(c).docs.filter((d) => d.data()[f] === v).length }) }) }), limit: () => ({ get: async () => { const d = docsOf(c).docs.filter((x) => x.data()[f] === v); return { docs: d, size: d.length }; } }) }),
    count: () => ({ get: async () => ({ data: () => ({ count: docsOf(c).docs.length }) }) })
  });
  const db = { collection: col, store, runTransaction: async (fn) => fn({ get: async (ref) => ref.get(), set: (ref, d, o) => { ref.set(d, o); } }) };
  return db;
}

// Her testten sonra canlı PLANS nesnesi özgün değerlere döner (bir testin başarısızlığı diğerlerini bozmasın)
const PRISTINE = JSON.stringify({ plans: PLANS.PLANS, y: PLANS.YEARLY_MONTHS });
test.afterEach(() => { const o = JSON.parse(PRISTINE); for (const id of Object.keys(o.plans)) Object.assign(PLANS.PLANS[id], o.plans[id]); PLANS.YEARLY_MONTHS = o.y; });

// ================= FİYAT / LİMİT (mantık) =================
test("Fiyat: geçersiz girişler reddedilir (metin, alt sınır, bilinmeyen paket, limit aralığı, yıllık ay)", async () => {
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const by = { uid: "root", email: "root@ornek.com" };
  const bad = async (input, re) => assert.rejects(() => C.savePricing(input, by), re);
  await bad({ plans: { freelance: { TRY: "abc" } } }, /geçerli bir sayı/);
  await bad({ plans: { freelance: { TRY: 0.5 } } }, /en az 1/);
  await bad({ plans: { freelance: { USD: 0.1 } } }, /en az 0.5/);
  await bad({ plans: { freelance: { TRY: -5 } } }, /en az 1/);
  await bad({ plans: { freelance: { TRY: Infinity } } }, /geçerli bir sayı/);
  await bad({ plans: { gizli: { TRY: 5 } } }, /Bilinmeyen paket/);
  await bad({ plans: { trial: { TRY: 5 } } }, /Bilinmeyen paket/); // deneme paketi düzenlenemez
  await bad({ plans: { freelance: { assets: 0 } } }, /1 ile/);
  await bad({ plans: { freelance: { assets: 1.5 } } }, /tam sayı/);
  await bad({ plans: { freelance: { history: null } } }, /boş bırakılamaz/);
  await bad({ plans: { freelance: { history: 5 } } }, /10 ile/);
  await bad({ yearlyMonths: 13 }, /1-12/); await bad({ yearlyMonths: 0 }, /1-12/);
  await bad({ plans: { freelance: { TRY: 499.99 } } }, /Değişiklik yok/);
  assert.equal(db.store["settings/pricing"], undefined, "hatalı istek hiçbir şey yazmaz");
  assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99);
});

test("Fiyat: kaydedilince canlı PLANS değişir (fiyat, limit, paket metni, yıllık hesap); geçmiş yazılır; sıfırlayınca varsayılana döner", async () => {
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const by = { uid: "root", email: "root@ornek.com" };
  const r = await C.savePricing({ plans: { freelance: { TRY: "599,90", USD: 14.5, assets: 40, team: 2 }, enterprise: { assets: 5000 } }, yearlyMonths: 9 }, by);
  assert.ok(r.changes.length >= 6);
  const f = PLANS.PLANS.freelance;
  assert.equal(f.prices.TRY, 599.9); assert.equal(f.priceTRY, 599.9); assert.equal(f.prices.USD, 14.5); assert.equal(f.assets, 40); assert.equal(f.team, 2);
  assert.equal(PLANS.price("freelance", "TRY", "monthly"), 599.9); assert.equal(PLANS.price("freelance", "TRY", "yearly"), 5399.1); assert.equal(PLANS.price("freelance", "USD", "yearly"), 130.5);
  assert.ok(f.features.includes("40 varlık") && f.features.includes("2 ekip kaydı") && !f.features.includes("25 varlık"), "kart metinleri güncellenir: " + f.features);
  assert.ok(PLANS.PLANS.enterprise.features.includes("5000 varlık") && !PLANS.PLANS.enterprise.features.includes("Sınırsız varlık"));
  assert.ok(PLANS.PLANS.kobi.features.includes("150 varlık"), "dokunulmayan paket aynı kalır");
  assert.equal(db.store["settings/pricing"].plans.freelance.TRY, 599.9); assert.equal(db.store["settings/pricing"].updatedByEmail, "root@ornek.com");
  const hist = await C.pricingHistory(); assert.equal(hist.length, 1); assert.equal(hist[0].action, "update");
  assert.equal(C.publicView().plans.freelance.prices.TRY, 599.9); assert.equal(C.publicView().custom, true);
  // sınırsız -> sayı -> tekrar sınırsız
  await C.savePricing({ plans: { enterprise: { assets: "sınırsız" } } }, by); assert.equal(PLANS.PLANS.enterprise.assets, null); assert.ok(PLANS.PLANS.enterprise.features.includes("Sınırsız varlık"));
  await C.resetPricing(by);
  assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99); assert.equal(PLANS.PLANS.freelance.assets, 25); assert.equal(PLANS.YEARLY_MONTHS, 10); assert.ok(PLANS.PLANS.freelance.features.includes("25 varlık"));
  assert.equal(db.store["settings/pricing"], undefined); assert.equal(C.publicView().custom, false);
});

test("Fiyat: aşırı büyük değişim (5 kat artış / %80 düşüş) force olmadan reddedilir", async () => {
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const by = { uid: "root" };
  await assert.rejects(() => C.savePricing({ plans: { freelance: { TRY: 49999 } } }, by), (e) => e.status === 409 && e.code === "LARGE_CHANGE" && e.large[0].to === 49999);
  await assert.rejects(() => C.savePricing({ plans: { kobi: { USD: 5 } } }, by), (e) => e.code === "LARGE_CHANGE");
  assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99);
  await C.savePricing({ plans: { freelance: { TRY: 49999 } }, force: true }, by); assert.equal(PLANS.PLANS.freelance.prices.TRY, 49999);
  await C.resetPricing(by); assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99);
});

test("Fiyat: Firestore'dan yükleme (başka sunucu örneğinin kaydı) uygulanır; bozuk kayıt varsayılanı bozmaz; Firestore yoksa kayıt reddedilir", async () => {
  const db = memFs({ "settings/pricing": { plans: { kobi: { TRY: 5555, USD: 130, assets: 200, team: 12, history: 1500 } }, yearlyMonths: 11, updatedAt: 123, updatedByEmail: "x@y.com" } });
  const C = LOAD("commerce")({ db, PLANS }); await C.loadPricing();
  assert.equal(PLANS.PLANS.kobi.prices.TRY, 5555); assert.equal(PLANS.PLANS.kobi.assets, 200); assert.equal(PLANS.YEARLY_MONTHS, 11); assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99);
  delete db.store["settings/pricing"]; await C.loadPricing(); assert.equal(PLANS.PLANS.kobi.prices.TRY, 4999.99, "kayıt silinince varsayılana döner"); assert.equal(PLANS.YEARLY_MONTHS, 10);
  db.store["settings/pricing"] = { plans: { kobi: { TRY: "bozuk" } } }; await C.loadPricing(); assert.equal(PLANS.PLANS.kobi.prices.TRY, 4999.99, "bozuk kayıt yok sayılır");
  await assert.rejects(() => LOAD("commerce")({ db: null, PLANS }).savePricing({ yearlyMonths: 8 }, { uid: "r" }), (e) => e.status === 503);
});

// ================= KUPON =================
test("Kupon: oluşturma doğrulaması, indirim hesabı, geçerlilik kuralları, kullanım sınırları ve iade", async () => {
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const by = { uid: "root", email: "r@o.com" };
  await assert.rejects(() => C.createCoupon({ code: "a b", type: "percent", value: 10 }, by), /Kupon kodu/);
  await assert.rejects(() => C.createCoupon({ code: "X1X", type: "percent", value: 95 }, by), /1-90/);
  await assert.rejects(() => C.createCoupon({ code: "X1X", type: "fixed", value: 10 }, by), /para birimi/);
  await assert.rejects(() => C.createCoupon({ code: "X1X", type: "percent", value: 10, plans: ["gizli"] }, by), /Bilinmeyen paket/);
  await assert.rejects(() => C.createCoupon({ code: "X1X", type: "percent", value: 10, validFrom: 2000, validUntil: 1000 }, by), /Bitiş/);
  const c = await C.createCoupon({ code: "yaz25", type: "percent", value: 25, maxUses: 2, perUser: 1 }, by); assert.equal(c.code, "YAZ25");
  await assert.rejects(() => C.createCoupon({ code: "YAZ25", type: "percent", value: 10 }, by), (e) => e.status === 409);
  const auto = await C.createCoupon({ type: "fixed", value: 100, currency: "TRY" }, by); assert.match(auto.code, /^[A-Z0-9]{8}$/);

  const q = await C.quoteCoupon("yaz25", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" });
  assert.equal(q.listAmount, 499.99); assert.equal(q.discount, 125); assert.equal(q.finalAmount, 374.99);
  const fx = await C.quoteCoupon(auto.code, { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" }); assert.equal(fx.finalAmount, 399.99);
  await assert.rejects(() => C.quoteCoupon(auto.code, { plan: "freelance", cycle: "monthly", currency: "USD", uid: "u1" }), /yalnızca TRY/);
  await assert.rejects(() => C.quoteCoupon("YOKKOD", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" }), (e) => e.status === 404);
  await assert.rejects(() => C.quoteCoupon("../x", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" }), (e) => e.status === 404);

  await C.redeemCoupon("YAZ25", "u1");
  await assert.rejects(() => C.quoteCoupon("YAZ25", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" }), /daha önce/);
  await assert.rejects(() => C.redeemCoupon("YAZ25", "u1"), /daha önce/);
  await C.redeemCoupon("YAZ25", "u2");
  await assert.rejects(() => C.quoteCoupon("YAZ25", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u3" }), /kullanım hakkı dolmuş/);
  await assert.rejects(() => C.redeemCoupon("YAZ25", "u3"), /kullanım hakkı dolmuş/);
  assert.equal(db.store["coupons/YAZ25"].usedCount, 2);
  await C.releaseCoupon("YAZ25", "u1"); assert.equal(db.store["coupons/YAZ25"].usedCount, 1);
  await C.quoteCoupon("YAZ25", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" }); // hak iade edildi, tekrar kullanabilir
  await C.releaseCoupon("YAZ25", "u1"); await C.releaseCoupon("YAZ25", "u1"); assert.equal(db.store["coupons/YAZ25"].usedCount, 0, "sayaç eksiye düşmez");

  await C.createCoupon({ code: "SADECEKOBI", type: "percent", value: 10, plans: ["kobi"], cycles: ["yearly"] }, by);
  await assert.rejects(() => C.quoteCoupon("SADECEKOBI", { plan: "freelance", cycle: "yearly", currency: "TRY", uid: "u1" }), /bu pakette/);
  await assert.rejects(() => C.quoteCoupon("SADECEKOBI", { plan: "kobi", cycle: "monthly", currency: "TRY", uid: "u1" }), /bu faturalama/);
  assert.equal((await C.quoteCoupon("SADECEKOBI", { plan: "kobi", cycle: "yearly", currency: "TRY", uid: "u1" })).discount, 4999.99);
  await C.createCoupon({ code: "ESKI", type: "percent", value: 10, validUntil: Date.now() - 1000 }, by); await assert.rejects(() => C.quoteCoupon("ESKI", { plan: "kobi", cycle: "monthly", currency: "TRY", uid: "u1" }), /süresi dolmuş/);
  await C.createCoupon({ code: "GELECEK", type: "percent", value: 10, validFrom: Date.now() + 864e5 }, by); await assert.rejects(() => C.quoteCoupon("GELECEK", { plan: "kobi", cycle: "monthly", currency: "TRY", uid: "u1" }), /henüz geçerli değil/);
  await C.createCoupon({ code: "BUYUK", type: "fixed", value: 499.5, currency: "TRY" }, by); await assert.rejects(() => C.quoteCoupon("BUYUK", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u1" }), /alt sınırının altında/);
  await C.setCouponActive("YAZ25", false); await assert.rejects(() => C.quoteCoupon("YAZ25", { plan: "freelance", cycle: "monthly", currency: "TRY", uid: "u9" }), (e) => e.status === 404);
  await C.deleteCoupon("YAZ25"); assert.equal(db.store["coupons/YAZ25"], undefined);
  assert.ok((await C.listCoupons()).length >= 5);
});

// ================= PAYMENTS ENTEGRASYONU =================
async function payApp(db, commerce) {
  const app = express(); app.use(express.json());
  const admin = { apps: [1], auth: () => ({ verifyIdToken: async (t) => ({ uid: t === "t2" ? "u2" : "u1", email: "a@b.com", email_verified: true, firebase: { sign_in_provider: "google.com" } }) }) };
  const pay = LOAD("payments")({ app, db, admin, http: null, commerce });
  return { s: await listen(app), pay };
}
const post = (s, path, body, tok = "t1") => fetch(url(s, path), { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + tok, Origin: "http://localhost:3000" }, body: JSON.stringify(body) });
const CB = { plan: "freelance", cycle: "monthly", currency: "TRY", billing: {}, consent: { distanceSales: true, withdrawalWaiver: true } };

test("Satın alma: yönetici fiyatı değiştirince sipariş yeni tutarla oluşur; eski tutarı bekleyen istemci 409 PRICE_CHANGED alır", async () => {
  delete process.env.IYZICO_API_KEY; delete process.env.IYZICO_SECRET_KEY; delete process.env.STRIPE_SECRET_KEY; delete process.env.ALLOW_FREE_ACTIVATION;
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const { s } = await payApp(db, C);
  await C.savePricing({ plans: { freelance: { TRY: 650 } } }, { uid: "root" });
  let r = await post(s, "/api/checkout", { ...CB, expectedAmount: 499.99 }); let j = await r.json();
  assert.equal(r.status, 409); assert.equal(j.code, "PRICE_CHANGED"); assert.equal(j.amount, 650); assert.equal(db.store["subscriptions/u1"], undefined, "fiyat uyuşmazsa paket verilmez");
  r = await post(s, "/api/checkout", { ...CB, expectedAmount: 650 }); j = await r.json(); assert.equal(r.status, 200); assert.equal(j.activated, true);
  const order = Object.entries(db.store).find(([k]) => k.startsWith("orders/"))[1]; assert.equal(order.amount, 650);
  await C.resetPricing({ uid: "root" }); s.close();
});

test("Satın alma: kupon indirimi sunucuda uygulanır, sipariş kuponu kaydeder, hak bir kez kullanılır; geçersiz kupon ödemeyi durdurur", async () => {
  delete process.env.IYZICO_API_KEY; delete process.env.IYZICO_SECRET_KEY; delete process.env.STRIPE_SECRET_KEY; delete process.env.ALLOW_FREE_ACTIVATION;
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const { s } = await payApp(db, C);
  await C.createCoupon({ code: "INDIRIM20", type: "percent", value: 20, maxUses: 5 }, { uid: "root" });
  let r = await post(s, "/api/checkout", { ...CB, coupon: "yok-kod" }); assert.equal(r.status, 404); assert.equal(db.store["subscriptions/u1"], undefined);
  r = await post(s, "/api/checkout", { ...CB, coupon: "indirim20", expectedAmount: 499.99 }); assert.equal(r.status, 409, "kuponlu tutar 399.99, istemci liste fiyatını beklerse reddedilir");
  assert.equal(db.store["coupons/INDIRIM20"].usedCount || 0, 0, "reddedilen istek kupon hakkı harcamaz");
  r = await post(s, "/api/checkout", { ...CB, coupon: "indirim20", expectedAmount: 399.99 }); const j = await r.json(); assert.equal(r.status, 200, JSON.stringify(j)); assert.equal(j.activated, true);
  const order = Object.entries(db.store).find(([k]) => k.startsWith("orders/"))[1];
  assert.equal(order.amount, 399.99); assert.equal(order.couponCode, "INDIRIM20"); assert.equal(order.listAmount, 499.99); assert.equal(order.discount, 100);
  assert.equal(db.store["coupons/INDIRIM20"].usedCount, 1);
  r = await post(s, "/api/checkout", { ...CB, coupon: "INDIRIM20" }); assert.equal(r.status, 400, "aynı kullanıcı ikinci kez kullanamaz");
  r = await post(s, "/api/checkout", { ...CB, coupon: "INDIRIM20" }, "t2"); assert.equal(r.status, 200, "başka kullanıcı kullanabilir");
  // kupon doğrulama ucu olmadan (commerce yok) kupon gönderilirse reddedilir
  const { s: s2 } = await payApp(memFs(), null); r = await post(s2, "/api/checkout", { ...CB, coupon: "X1X" }); assert.equal(r.status, 400); s.close(); s2.close();
});

test("Stripe webhook: invoice.paid sipariş kaydı yazar (idempotent); checkout.session.expired kupon hakkını iade eder", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_test_x"; process.env.STRIPE_WEBHOOK_SECRET = "whsec_test";
  const db = memFs(); const C = LOAD("commerce")({ db, PLANS }); const crypto = require("crypto");
  await C.createCoupon({ code: "USDKUP", type: "percent", value: 10, maxUses: 3 }, { uid: "root" }); await C.redeemCoupon("USDKUP", "u1"); assert.equal(db.store["coupons/USDKUP"].usedCount, 1);
  const app = express(); app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
  const http2 = { request: async ({ url: u }) => ({ status: 200, data: { id: "sub_1", status: "active", customer: "cus_1", current_period_end: Math.floor(Date.now() / 1000) + 86400 * 30, metadata: { uid: "u1", plan: "freelance", cycle: "monthly", coupon: "USDKUP" } } }) };
  LOAD("payments")({ app, db, admin: { apps: [1], auth: () => ({}) }, http: http2, commerce: C }); const s = await listen(app);
  const send = async (ev) => { const raw = JSON.stringify(ev), t = Math.floor(Date.now() / 1000), sig = crypto.createHmac("sha256", "whsec_test").update(`${t}.`).update(raw).digest("hex"); return fetch(url(s, "/api/stripe/webhook"), { method: "POST", headers: { "Content-Type": "application/json", "stripe-signature": `t=${t},v1=${sig}` }, body: raw }); };
  assert.equal((await send({ id: "evt_1", type: "invoice.paid", data: { object: { id: "in_123", subscription: "sub_1", amount_paid: 1079 } } })).status, 200);
  const o = db.store["orders/st_in_123"]; assert.ok(o, "Stripe tahsilatı siparişlerde görünür"); assert.equal(o.amount, 10.79); assert.equal(o.currency, "USD"); assert.equal(o.status, "paid"); assert.equal(o.couponCode, "USDKUP");
  assert.equal(db.store["subscriptions/u1"].status, "active");
  assert.equal((await send({ id: "evt_2", type: "invoice.paid", data: { object: { id: "in_123", subscription: "sub_1", amount_paid: 1079 } } })).status, 200);
  assert.equal(Object.keys(db.store).filter((k) => k.startsWith("orders/")).length, 1, "aynı fatura ikinci sipariş yaratmaz");
  assert.equal((await send({ id: "evt_3", type: "checkout.session.expired", data: { object: { metadata: { uid: "u1", coupon: "USDKUP" } } } })).status, 200);
  assert.equal(db.store["coupons/USDKUP"].usedCount, 0, "yarım kalan ödemenin kupon hakkı iade edilir"); s.close();
  delete process.env.STRIPE_SECRET_KEY; delete process.env.STRIPE_WEBHOOK_SECRET;
});

// ================= DUYURU / BAKIM =================
test("Duyuru ve bakım: doğrulama, genel durum ucu (süresi dolan duyuru gizlenir), bakım modunda yalnızca yönetici tarama başlatır", async () => {
  const db = memFs(); let t = 1_000_000; const C = LOAD("commerce")({ db, PLANS, now: () => t }); const by = { uid: "root", email: "r@o.com" };
  await assert.rejects(() => C.saveSite({ announcement: { enabled: true, text: "  " } }, by), /boş olamaz/);
  await assert.rejects(() => C.saveSite({ announcement: { enabled: true, text: "x".repeat(281) } }, by), /280/);
  await assert.rejects(() => C.saveSite({ announcement: { enabled: true, text: "a", level: "zzz" } }, by), /Seviye/);
  await assert.rejects(() => C.saveSite({ announcement: { enabled: true, text: "a", until: 5 } }, by), /geçmişte/);
  await assert.rejects(() => C.saveSite({ maintenance: { enabled: "evet" } }, by), /true\/false/);
  const SEC = LOAD("security"); const app = express(); app.use(express.json());
  const verify = async (req) => { const h = req.headers["x-test-user"]; if (!h) throw Object.assign(new Error("giriş"), { status: 401 }); return JSON.parse(h); };
  const pub = C.mountPublic(app, { SEC, getVerifyUser: () => verify, getIsAdmin: () => async (u) => u.uid === "root" });
  let scans = 0; app.post(["/api/scan", "/api/jobs"], pub.maintenanceGuard); app.post("/api/scan", (q, r) => { scans++; r.json({ ok: true }); }); app.get("/api/jobs", (q, r) => r.json({ ok: true })); const s = await listen(app);
  let j = await (await fetch(url(s, "/api/site-status"))).json(); assert.equal(j.announcement, null); assert.equal(j.maintenance.enabled, false);
  assert.equal((await fetch(url(s, "/api/scan"), { method: "POST", headers: as("u1"), body: "{}" })).status, 200);

  await C.saveSite({ announcement: { enabled: true, text: "Cuma 02:00'de kısa kesinti", level: "warn", until: t + 1000 } }, by);
  j = await (await fetch(url(s, "/api/site-status"))).json(); assert.equal(j.announcement.text, "Cuma 02:00'de kısa kesinti"); assert.equal(j.announcement.level, "warn");
  t += 2000; j = await (await fetch(url(s, "/api/site-status"))).json(); assert.equal(j.announcement, null, "süresi dolan duyuru görünmez");

  await C.saveSite({ maintenance: { enabled: true, message: "Güncelleme yapılıyor" } }, by); t += 25000; // önbellek süresi
  j = await (await fetch(url(s, "/api/site-status"))).json(); assert.equal(j.maintenance.enabled, true); assert.equal(j.maintenance.message, "Güncelleme yapılıyor");
  const blocked = await fetch(url(s, "/api/scan"), { method: "POST", headers: as("u1"), body: "{}" }); assert.equal(blocked.status, 503); const bj = await blocked.json(); assert.equal(bj.code, "MAINTENANCE");
  assert.equal((await fetch(url(s, "/api/jobs"), { method: "POST", headers: as("u1"), body: "{}" })).status, 503);
  assert.equal((await fetch(url(s, "/api/scan"), { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } })).status, 503, "oturumsuz istek de bakımda engellenir");
  assert.equal((await fetch(url(s, "/api/scan"), { method: "POST", headers: as("root"), body: "{}" })).status, 200, "yönetici bakım modunda tarayabilir");
  assert.equal((await fetch(url(s, "/api/jobs"), { headers: as("u1") })).status, 200, "okuma (GET) bakımdan etkilenmez");
  assert.equal(scans, 2); s.close();
});

// ================= YÖNETİCİ UÇLARI =================
function adminHarness({ users = {}, seed = {}, env = { ADMIN_UIDS: "root" } } = {}) {
  Object.assign(process.env, { ADMIN_UIDS: "", ADMIN_EMAILS: "", ...env });
  const db = memFs(seed); const U = { ...users }; const calls = [];
  const adm = { apps: [1], auth: () => ({ listUsers: async () => ({ users: Object.values(U) }), getUser: async (uid) => { if (!U[uid]) throw new Error("yok"); return U[uid]; }, getUsers: async (ids) => ({ users: ids.map((x) => U[x.uid]).filter(Boolean) }), getUserByEmail: async (e) => { const u = Object.values(U).find((x) => x.email === e); if (!u) throw new Error("yok"); return u; }, updateUser: async (uid, p) => { Object.assign(U[uid], p); }, revokeRefreshTokens: async (uid) => { calls.push(["revoke", uid]); }, generatePasswordResetLink: async (email) => { calls.push(["reset", email]); return "https://ornek.firebaseapp.com/reset?oobCode=GIZLI123"; } }) };
  const app = express(); app.use(express.json());
  const verifyUser = async (req) => { const h = req.headers["x-test-user"]; if (!h) throw Object.assign(new Error("Giriş yapmanız gerekiyor."), { status: 401 }); const u = JSON.parse(h); return { uid: u.uid, email: u.email || null, emailVerified: u.emailVerified === true }; };
  const SEC = LOAD("security"), M = LOAD("metrics"), J = LOAD("jobs"); const metrics = M.createMetrics(); const jobs = J.createJobs({ store: J.memoryStore(), scanItem: async () => ({ scanStatus: "COMPLETED", summary: {} }) }); jobs.stop();
  const commerce = LOAD("commerce")({ db, PLANS }); const api = LOAD("admin")({ app, db, admin: adm, verifyUser, SEC, metrics, jobs, getHealth: async () => ({ ok: true }), platform: async () => ({}), commerce });
  return { app, db, U, calls, commerce };
}
const mkU = (uid, o = {}) => ({ uid, email: uid + "@ornek.com", emailVerified: true, disabled: false, metadata: {}, providerData: [{ providerId: "password" }], ...o });
const jpost = (s, p, h, body) => fetch(url(s, p), { method: "POST", headers: h, body: JSON.stringify(body || {}) });

test("Yönetici: yeni uçlar yetkisiz kullanıcıya ve oturumsuza kapalı (GET ve yazma)", async () => {
  const { app, db } = adminHarness({ users: { u1: mkU("u1"), root: mkU("root") } }); const s = await listen(app);
  const gets = ["/api/admin/pricing", "/api/admin/coupons", "/api/admin/revenue", "/api/admin/site"];
  for (const p of gets) { assert.equal((await fetch(url(s, p), { headers: as("u1") })).status, 403, p); assert.equal((await fetch(url(s, p))).status, 401, p); }
  for (const [m, p] of [["POST", "/api/admin/pricing"], ["POST", "/api/admin/pricing/reset"], ["POST", "/api/admin/coupons"], ["POST", "/api/admin/coupons/X/active"], ["DELETE", "/api/admin/coupons/X"], ["POST", "/api/admin/site"], ["POST", "/api/admin/users/u1/revoke-sessions"], ["POST", "/api/admin/users/u1/password-reset"], ["POST", "/api/admin/users/u1/verify-email"], ["POST", "/api/admin/users/u1/note"]]) {
    assert.equal((await fetch(url(s, p), { method: m, headers: as("u1"), body: m === "DELETE" ? undefined : "{}" })).status, 403, m + p);
  }
  assert.equal(db.store["settings/pricing"], undefined); assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99);
  // istemciden gelen "rol" alanı yetki vermez
  assert.equal((await jpost(s, "/api/admin/pricing", as("u1", { admin: true, role: "admin" }), { plans: { freelance: { TRY: 1 } } })).status, 403); s.close();
});

test("Yönetici: fiyat kaydet / büyük değişimde onay / sıfırla; herkese açık fiyat ucu yeni değeri döner; işlem kaydı yazılır", async () => {
  const { app, db, commerce } = adminHarness({ users: { root: mkU("root") }, seed: { "subscriptions/a": { plan: "freelance", status: "active", provider: "stripe", periodEnd: Date.now() + 864e5 }, "subscriptions/b": { plan: "freelance", status: "active", provider: "iyzico", periodEnd: Date.now() + 864e5 }, "subscriptions/c": { plan: "kobi", status: "canceled" } } });
  commerce.mountPublic(app, { SEC: LOAD("security"), getVerifyUser: () => async () => ({ uid: "x" }), getIsAdmin: () => async () => false }); const s = await listen(app); const H = as("root");
  const g = await (await fetch(url(s, "/api/admin/pricing"), { headers: H })).json();
  assert.equal(g.current.plans.freelance.TRY, 499.99); assert.equal(g.defaults.plans.kobi.USD, 119.99); assert.equal(g.subscribers.freelance, 2); assert.equal(g.custom, false); assert.ok(g.notes.length >= 2);
  let r = await jpost(s, "/api/admin/pricing", H, { plans: { freelance: { TRY: "bozuk" } } }); assert.equal(r.status, 400);
  r = await jpost(s, "/api/admin/pricing", H, { plans: { freelance: { TRY: 12345 } } }); const lj = await r.json(); assert.equal(r.status, 409); assert.equal(lj.code, "LARGE_CHANGE");
  r = await jpost(s, "/api/admin/pricing", H, { plans: { freelance: { TRY: 12345 } }, force: true }); assert.equal(r.status, 200);
  assert.equal((await jpost(s, "/api/admin/pricing", H, { plans: { freelance: { TRY: 500 } } })).status, 409, "12345 -> 500 de büyük düşüş sayılır");
  assert.equal((await jpost(s, "/api/admin/pricing/reset", H)).status, 200);
  r = await jpost(s, "/api/admin/pricing", H, { plans: { freelance: { TRY: 549.5, USD: 13 }, kobi: { assets: 200 } } }); const sj = await r.json(); assert.equal(r.status, 200); assert.equal(sj.current.plans.freelance.TRY, 549.5); assert.equal(sj.public.plans.kobi.assets, 200);
  const pub = await (await fetch(url(s, "/api/pricing"))).json(); assert.equal(pub.success, true); assert.equal(pub.plans.freelance.prices.TRY, 549.5); assert.equal(pub.plans.freelance.prices.USD, 13); assert.ok(pub.plans.kobi.features.includes("200 varlık")); assert.equal(pub.custom, true); assert.ok(!("updatedBy" in pub), "genel uç yönetici bilgisi sızdırmaz");
  const aud = Object.entries(db.store).filter(([k]) => k.startsWith("adminAudit/")).map(([, v]) => v); assert.ok(aud.filter((a) => a.action === "pricing.update").length >= 2); assert.equal(aud.find((a) => a.action === "pricing.update" && a.detail.forced).adminUid, "root");
  const g2 = await (await fetch(url(s, "/api/admin/pricing"), { headers: H })).json(); assert.equal(g2.custom, true); assert.ok(g2.history.length >= 3);
  r = await jpost(s, "/api/admin/pricing/reset", H); assert.equal(r.status, 200); assert.equal(PLANS.PLANS.freelance.prices.TRY, 499.99); assert.equal(PLANS.PLANS.kobi.assets, 150);
  assert.equal((await (await fetch(url(s, "/api/pricing"))).json()).custom, false); s.close();
});

test("Yönetici: kupon oluştur / pasifleştir / sil + işlem kaydı; yinelenen kod 409", async () => {
  const { app, db } = adminHarness({ users: { root: mkU("root") } }); const s = await listen(app); const H = as("root");
  let r = await jpost(s, "/api/admin/coupons", H, { code: "KIS10", type: "percent", value: 10, plans: ["kobi"], maxUses: 50 }); assert.equal(r.status, 200); assert.equal((await r.json()).coupon.code, "KIS10");
  assert.equal((await jpost(s, "/api/admin/coupons", H, { code: "KIS10", type: "percent", value: 10 })).status, 409);
  assert.equal((await jpost(s, "/api/admin/coupons", H, { code: "BAD", type: "percent", value: 0 })).status, 400);
  assert.equal((await jpost(s, "/api/admin/coupons/KIS10/active", H, { active: "evet" })).status, 400);
  assert.equal((await jpost(s, "/api/admin/coupons/KIS10/active", H, { active: false })).status, 200); assert.equal(db.store["coupons/KIS10"].active, false);
  const list = await (await fetch(url(s, "/api/admin/coupons"), { headers: H })).json(); assert.equal(list.coupons.length, 1); assert.equal(list.coupons[0].maxUses, 50);
  assert.equal((await fetch(url(s, "/api/admin/coupons/YOKKOD"), { method: "DELETE", headers: H })).status, 404);
  assert.equal((await fetch(url(s, "/api/admin/coupons/KIS10"), { method: "DELETE", headers: H })).status, 200); assert.equal(db.store["coupons/KIS10"], undefined);
  const acts = Object.entries(db.store).filter(([k]) => k.startsWith("adminAudit/")).map(([, v]) => v.action); for (const a of ["coupon.create", "coupon.disable", "coupon.delete"]) assert.ok(acts.includes(a), a); s.close();
});

test("Yönetici: gelir özeti siparişlerden doğru toplar (ödenmiş/başarısız/ödemesiz ayrı), kupon indirimi, MRR tahmini ve yakında bitenler", async () => {
  const now = Date.now(), d = 864e5;
  const { app } = adminHarness({ users: { root: mkU("root"), a: mkU("a"), b: mkU("b") }, seed: {
    "orders/o1": { uid: "a", plan: "freelance", cycle: "monthly", currency: "TRY", amount: 399.99, status: "paid", createdAt: now - d, paidAt: now - d, couponCode: "K", listAmount: 499.99, discount: 100 },
    "orders/o2": { uid: "b", plan: "kobi", cycle: "monthly", currency: "TRY", amount: 4999.99, status: "paid", createdAt: now - 20 * d, paidAt: now - 20 * d },
    "orders/o3": { uid: "a", plan: "freelance", cycle: "monthly", currency: "USD", amount: 11.99, status: "paid", createdAt: now - 60 * d, paidAt: now - 60 * d },
    "orders/o4": { uid: "a", plan: "freelance", cycle: "monthly", currency: "TRY", amount: 499.99, status: "failed", createdAt: now - d },
    "orders/o5": { uid: "a", plan: "freelance", cycle: "monthly", currency: "TRY", amount: 499.99, status: "pending", createdAt: now - 5 * 36e5 },
    "orders/o6": { uid: "a", plan: "kobi", cycle: "monthly", currency: "TRY", amount: 4999.99, status: "activated-free", createdAt: now - d },
    "subscriptions/a": { plan: "freelance", status: "active", provider: "iyzico", currency: "TRY", cycle: "monthly", periodEnd: now + 3 * d },
    "subscriptions/b": { plan: "kobi", status: "active", provider: "stripe", currency: "USD", cycle: "yearly", periodEnd: now + 200 * d },
    "subscriptions/g": { plan: "enterprise", status: "active", provider: "admin", free: true, periodEnd: now + 2 * d }
  } }); const s = await listen(app);
  const j = await (await fetch(url(s, "/api/admin/revenue"), { headers: as("root") })).json();
  assert.equal(j.available, true); assert.equal(j.paid.count, 3); assert.deepEqual(j.paid.totals, { TRY: 5399.98, USD: 11.99 });
  assert.deepEqual(j.paid.last30d.totals, { TRY: 5399.98 }); assert.equal(j.paid.last7d.count, 1); assert.deepEqual(j.paid.last7d.totals, { TRY: 399.99 });
  assert.equal(j.failed, 1); assert.equal(j.stuckPending, 1); assert.equal(j.freeActivations, 1); assert.equal(j.coupons.orders, 1); assert.deepEqual(j.coupons.discountTotals, { TRY: 100 });
  assert.equal(j.byPlan.freelance.count, 2); assert.equal(j.mrr.activePayingSubscriptions, 2);
  assert.equal(j.mrr.estimate.TRY, 499.99); assert.equal(j.mrr.estimate.USD, 119.99 * 10 / 12 > 0 ? Math.round(1199.9 / 12 * 100) / 100 : 0);
  assert.deepEqual(j.expiringSoon.map((x) => x.uid), ["g", "a"], "yakında bitenler en yakın önce"); assert.equal(j.expiringSoon[1].email, "a@ornek.com");
  assert.ok(j.daily.length === 2); s.close();
});

test("Yönetici: siparişlerde kupon alanları görünür", async () => {
  const { app } = adminHarness({ users: { root: mkU("root") }, seed: { "orders/o1": { uid: "root", plan: "freelance", cycle: "monthly", currency: "TRY", amount: 400, status: "paid", createdAt: 5, couponCode: "AAA", listAmount: 500, discount: 100 } } }); const s = await listen(app);
  const j = await (await fetch(url(s, "/api/admin/orders"), { headers: as("root") })).json(); assert.equal(j.orders[0].couponCode, "AAA"); assert.equal(j.orders[0].discount, 100); s.close();
});

test("Yönetici: duyuru/bakım kaydı ve işlem kaydı", async () => {
  const { app, db } = adminHarness({ users: { root: mkU("root") } }); const s = await listen(app); const H = as("root");
  assert.equal((await jpost(s, "/api/admin/site", H, { announcement: { enabled: true, text: "" } })).status, 400);
  let r = await jpost(s, "/api/admin/site", H, { announcement: { enabled: true, text: "Merhaba", level: "info" }, maintenance: { enabled: true, message: "Bakımdayız" } }); const j = await r.json(); assert.equal(r.status, 200); assert.equal(j.site.maintenance.enabled, true);
  const g = await (await fetch(url(s, "/api/admin/site"), { headers: H })).json(); assert.equal(g.site.announcement.text, "Merhaba");
  const a = Object.values(db.store).filter((v) => v && v.action === "site.update")[0]; assert.equal(a.detail.maintenanceChanged, true);
  await jpost(s, "/api/admin/site", H, { maintenance: { enabled: false } }); s.close();
});

test("Yönetici: kullanıcı müdahaleleri (oturum kapat, şifre sıfırlama bağlantısı, e-posta doğrulama, not); bağlantı kayda yazılmaz", async () => {
  const { app, db, U, calls } = adminHarness({ users: { root: mkU("root"), u1: mkU("u1", { emailVerified: false }), g1: mkU("g1", { providerData: [{ providerId: "google.com" }] }), ne: mkU("ne", { email: null }) } }); const s = await listen(app); const H = as("root");
  assert.equal((await jpost(s, "/api/admin/users/u1/revoke-sessions", H)).status, 200); assert.deepEqual(calls[0], ["revoke", "u1"]);
  assert.equal((await jpost(s, "/api/admin/users/yok/revoke-sessions", H)).status, 404); assert.equal((await jpost(s, "/api/admin/users/a%2Fb/revoke-sessions", H)).status, 400);
  const pr = await jpost(s, "/api/admin/users/u1/password-reset", H); const pj = await pr.json(); assert.equal(pr.status, 200); assert.match(pj.link, /oobCode=/);
  assert.equal((await jpost(s, "/api/admin/users/g1/password-reset", H)).status, 400, "Google hesabında şifre sıfırlanmaz"); assert.equal((await jpost(s, "/api/admin/users/ne/password-reset", H)).status, 400);
  assert.ok(!JSON.stringify(db.store).includes("GIZLI123"), "sıfırlama bağlantısı hiçbir kayda yazılmamalı");
  assert.equal((await jpost(s, "/api/admin/users/u1/verify-email", H)).status, 200); assert.equal(U.u1.emailVerified, true); assert.equal((await jpost(s, "/api/admin/users/u1/verify-email", H)).status, 400);
  assert.equal((await jpost(s, "/api/admin/users/u1/note", H, { text: "x".repeat(1001) })).status, 400);
  assert.equal((await jpost(s, "/api/admin/users/u1/note", H, { text: "VIP müşteri, faturayı elle kes" })).status, 200);
  let d = await (await fetch(url(s, "/api/admin/users/u1"), { headers: H })).json(); assert.equal(d.note.text, "VIP müşteri, faturayı elle kes"); assert.equal(d.note.by, "root@ornek.com");
  assert.equal((await jpost(s, "/api/admin/users/u1/note", H, { text: "" })).status, 200); d = await (await fetch(url(s, "/api/admin/users/u1"), { headers: H })).json(); assert.equal(d.note, null);
  const acts = Object.values(db.store).filter((v) => v && v.action).map((v) => v.action); for (const a of ["user.revoke-sessions", "user.password-reset-link", "user.verify-email", "user.note", "user.note-clear"]) assert.ok(acts.includes(a), a); s.close();
});

// ================= İSTEMCİ / YAPI =================
test("İstemci: app.js sunucudaki fiyatı uygular, kupon/PRICE_CHANGED akışı ve yönetici sekmeleri mevcut; sunucu dosyaları statik olarak yayınlanmaz", () => {
  const src = ["app.js", "app-analysis.js", "app-main.js", "app-bulk.js", "app-admin.js", "app-admin-ops.js"].map((f) => _fs.readFileSync(_fs.existsSync(_p.join(ROOT, "public")) ? _p.join(ROOT, "public", "js", f) : _p.join(ROOT, f), "utf8")).join("\n");
  for (const needle of ["/api/pricing", "/api/site-status", "/api/coupon/validate", "PRICE_CHANGED", "expectedAmount", "adm-pricesave", "adm-cpncreate", "adm-sitemnt", "payRevenue", "csvCell"]) assert.ok(src.includes(needle), needle);
  assert.ok(/csvCell=v=>\{let s=v==null\?'':String\(v\);if\(\/\^\[=\+\\-@/.test(src), "CSV formül enjeksiyonu kaçışı");
  const idx = _fs.readFileSync(_p.join(ROOT, "index.js"), "utf8"); const m = /const FLAT_OK = new Set\(\[([\s\S]*?)\]\)/.exec(idx); assert.ok(m && !/commerce|(?<![-\w])(admin|ops|support|admin-ops)\.js|payments\.js|mailer|totp/.test(m[1]), "sunucu kodu yayın izin listesinde değil");
});
test("Güvenlik: gizli kupon/fiyat alanları herkese açık uçlarda sızmaz", async () => {
  const db = memFs({ "coupons/GIZLI": { code: "GIZLI", active: true, type: "percent", value: 10, usedCount: 0, note: "iç not", createdBy: "root" } }); const C = LOAD("commerce")({ db, PLANS }); const app = express(); app.use(express.json());
  C.mountPublic(app, { SEC: LOAD("security"), getVerifyUser: () => async () => ({ uid: "u1" }), getIsAdmin: () => async () => false }); const s = await listen(app);
  const r = await fetch(url(s, "/api/coupon/validate"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: "gizli", plan: "freelance" }) }); const j = await r.json();
  assert.equal(r.status, 200); assert.ok(!("note" in j) && !("createdBy" in j) && !("usedCount" in j) && !("maxUses" in j)); assert.equal(j.finalAmount, 449.99);
  assert.equal((await fetch(url(s, "/api/coupon/validate"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: "gizli", plan: "trial" }) })).status, 400);
  const site = await (await fetch(url(s, "/api/site-status"))).json(); assert.ok(!("updatedBy" in site)); s.close();
});
