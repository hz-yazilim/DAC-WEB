// DAC V13.3 testleri: e-posta, hatırlatma, iade/iptal, fatura, toplu işlem, kullanıcı silme, destek+CAPTCHA, 2FA, deneme suistimali, bayraklar, alarm, yedek.
// Firestore/Firebase/ödeme sağlayıcıları MOCK'tur (gerçek servisleri KANITLAMAZ).
process.env.NODE_ENV = "development";
const test = require("node:test"), assert = require("node:assert/strict"), http = require("node:http"), _p = require("path"), _fs = require("fs");
const ROOT = _fs.existsSync(_p.join(__dirname, "index.js")) ? __dirname : _p.join(__dirname, "..");
const LOAD = (n) => require(_fs.existsSync(_p.join(ROOT, "server", n + ".js")) ? _p.join(ROOT, "server", n) : _p.join(ROOT, n));
const PLANS = (() => { try { return require(_p.join(ROOT, "public", "js", "plans")); } catch { return require(_p.join(ROOT, "plans")); } })();
const express = require("express"), crypto = require("crypto");
const listen = (app) => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const url = (s, p) => `http://127.0.0.1:${s.address().port}${p}`;
const as = (uid, extra = {}) => ({ "x-test-user": JSON.stringify({ uid, email: uid + "@ornek.com", emailVerified: true, ...extra }), "Content-Type": "application/json" });
const jpost = (s, p, h, body) => fetch(url(s, p), { method: "POST", headers: h, body: JSON.stringify(body || {}) });
const ENVKEYS = ["RESEND_API_KEY", "MAIL_FROM", "ADMIN_REQUIRE_2FA", "TURNSTILE_SECRET", "TURNSTILE_SITE_KEY", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "ALERT_WEBHOOK_URL", "ALERT_EMAIL", "BACKUP_BUCKET", "STRIPE_SECRET_KEY", "IYZICO_API_KEY", "IYZICO_SECRET_KEY", "SUPPORT_RATE_LIMIT"];
test.afterEach(() => { for (const k of ENVKEYS) delete process.env[k]; });

function memFs(seed = {}) {
  const store = { ...seed }; let n = 0;
  const docsOf = (c, f, dir) => { let rows = Object.entries(store).filter(([k]) => k.startsWith(c + "/")).map(([k, v]) => ({ id: k.slice(c.length + 1), data: () => v })); if (f) rows.sort((a, b) => (dir === "desc" ? -1 : 1) * ((a.data()[f] || 0) - (b.data()[f] || 0))); return { docs: rows, size: rows.length }; };
  const col = (c) => ({ doc: (id) => { id = id || "auto" + ++n; const k = c + "/" + id; return { id, get: async () => ({ exists: k in store, id, data: () => store[k] }), set: async (d, o) => { store[k] = o && o.merge ? { ...(store[k] || {}), ...d } : { ...d }; }, delete: async () => { delete store[k]; } }; },
    limit: () => ({ get: async () => docsOf(c) }), orderBy: (f, dir) => ({ limit: () => ({ get: async () => docsOf(c, f, dir) }) }), count: () => ({ get: async () => ({ data: () => ({ count: docsOf(c).docs.length }) }) }),
    where: (f, op, v) => ({ count: () => ({ get: async () => ({ data: () => ({ count: 0 }) }) }), limit: () => ({ get: async () => ({ docs: [], size: 0 }) }) }) });
  return { collection: col, store, runTransaction: async (fn) => fn({ get: async (r) => r.get(), set: (r, d, o) => { r.set(d, o); } }) };
}
// Taklit HTTP istemcisi: istekleri kaydeder, url'ye göre yanıt verir
function fakeHttp(handler = () => ({ status: 200, data: {} })) { const calls = []; return { calls, request: async (o) => { calls.push(o); return handler(o); } }; }

// ================= TOTP / 2FA =================
test("TOTP: RFC 6238 test vektörü; aynı kod ikinci kez kullanılamaz (replay); jeton başka kullanıcıya/süre sonrası geçersiz", () => {
  const T = LOAD("totp"); assert.equal(T.hotp(Buffer.from("12345678901234567890"), 1), "287082");
  const sec = T.newSecret(), t0 = 1_700_000_000_000, step = Math.floor(t0 / 30000), code = T.hotp(T.b32dec(sec), step);
  assert.equal(T.verify(sec, code, t0), step); assert.equal(T.verify(sec, code, t0, step), null, "kullanılmış adım reddedilir"); assert.equal(T.verify(sec, "000000", t0), null); assert.equal(T.verify(sec, "abc", t0), null);
  assert.equal(T.verify(sec, T.hotp(T.b32dec(sec), step - 1), t0), step - 1, "±1 adım toleransı"); assert.equal(T.verify(sec, T.hotp(T.b32dec(sec), step - 3), t0), null);
  let now = 1_700_000_000_000; const tk = T.createTokens("sir", () => now); const tok = tk.issue("u1"); assert.equal(tk.check("u1", tok), true); assert.equal(tk.check("u2", tok), false); assert.equal(tk.check("u1", tok + "x"), false); now += 13 * 36e5; assert.equal(tk.check("u1", tok), false);
});

function adminHarness({ users = {}, seed = {}, env = {}, payments: payFactory = null, userState = null, httpImpl = null } = {}) {
  Object.assign(process.env, { ADMIN_UIDS: "root", ADMIN_EMAILS: "", ...env });
  const db = memFs(seed), U = { ...users }, calls = [], H = httpImpl || fakeHttp();
  const adm = { apps: [1], auth: () => ({ listUsers: async () => ({ users: Object.values(U) }), getUser: async (uid) => { if (!U[uid]) throw new Error("yok"); return U[uid]; }, getUsers: async (ids) => ({ users: ids.map((x) => U[x.uid]).filter(Boolean) }), getUserByEmail: async (e) => { const u = Object.values(U).find((x) => x.email === e); if (!u) throw new Error("yok"); return u; }, updateUser: async (uid, p) => { Object.assign(U[uid], p); }, revokeRefreshTokens: async (uid) => { calls.push(["revoke", uid]); } }) };
  const app = express(); app.use(express.json());
  const verifyUser = async (req) => { const h = req.headers["x-test-user"]; if (!h) throw Object.assign(new Error("Giriş yapmanız gerekiyor."), { status: 401 }); const u = JSON.parse(h); return { uid: u.uid, email: u.email || null, emailVerified: u.emailVerified === true }; };
  const SEC = LOAD("security"), M = LOAD("metrics"), J = LOAD("jobs"); const metrics = M.createMetrics(); const jobs = J.createJobs({ store: J.memoryStore(), scanItem: async () => ({}) }); jobs.stop();
  const mailer = LOAD("mailer")({ db, http: H }); const ops = LOAD("ops")({ db, admin: adm, http: H, mailer, metrics, PLANS });
  const commerce = LOAD("commerce")({ db, PLANS });
  const payments = typeof payFactory === "function" ? payFactory(db) : payFactory;
  LOAD("admin")({ app, db, admin: adm, verifyUser, SEC, metrics, jobs, getHealth: async () => ({}), platform: async () => ({}), commerce, payments, userState, ops, mailer });
  return { app, db, U, calls, H, mailer, ops, metrics };
}
const mkU = (uid, o = {}) => ({ uid, email: uid + "@ornek.com", emailVerified: true, disabled: false, metadata: {}, providerData: [{ providerId: "password" }], ...o });

test("2FA: ADMIN_REQUIRE_2FA açıkken kurulmadan yönetici uçları kapalı; kurulum → kod onayı → jetonla erişim; replay ve yanlış kod reddedilir", async () => {
  const { app, db } = adminHarness({ users: { root: mkU("root") }, env: { ADMIN_REQUIRE_2FA: "true" } }); const s = await listen(app), H = as("root"), T = LOAD("totp");
  let r = await fetch(url(s, "/api/admin/overview"), { headers: H }); assert.equal(r.status, 403); assert.equal((await r.json()).code, "2FA_SETUP");
  assert.equal((await fetch(url(s, "/api/admin/overview"), { headers: as("u9") })).status, 403, "yönetici olmayan 2FA mesajı görmez, düz 403");
  const st = await (await fetch(url(s, "/api/admin/2fa/status"), { headers: H })).json(); assert.equal(st.required, true); assert.equal(st.enrolled, false);
  const setup = await (await jpost(s, "/api/admin/2fa/setup", H)).json(); assert.match(setup.otpauth, /^otpauth:\/\/totp\//); assert.equal(db.store["adminTotp/root"].enabled, false);
  assert.equal((await jpost(s, "/api/admin/2fa/confirm", H, { code: "123456" })).status, 400);
  const code = T.hotp(T.b32dec(setup.secret), Math.floor(Date.now() / 30000)); const cj = await (await jpost(s, "/api/admin/2fa/confirm", H, { code })).json(); assert.ok(cj.token); assert.equal(db.store["adminTotp/root"].enabled, true);
  assert.equal((await fetch(url(s, "/api/admin/overview"), { headers: H })).status, 403); r = await fetch(url(s, "/api/admin/overview"), { headers: H }); assert.equal((await r.json()).code, "2FA_REQUIRED");
  assert.equal((await fetch(url(s, "/api/admin/overview"), { headers: { ...H, "x-admin-2fa": cj.token } })).status, 200, "jetonla erişim");
  assert.equal((await fetch(url(s, "/api/admin/overview"), { headers: { ...as("root2"), "x-admin-2fa": cj.token } })).status, 403, "jeton başka kullanıcıda geçmez");
  assert.equal((await jpost(s, "/api/admin/2fa/verify", H, { code })).status, 400, "aynı kod tekrar kullanılamaz");
  for (let i = 0; i < 8; i++) await jpost(s, "/api/admin/2fa/verify", H, { code: "000000" }); assert.equal((await jpost(s, "/api/admin/2fa/verify", H, { code: "000000" })).status, 429, "deneme sınırı"); s.close();
});
test("2FA: ADMIN_REQUIRE_2FA kapalıyken mevcut davranış değişmez", async () => {
  const { app } = adminHarness({ users: { root: mkU("root") } }); const s = await listen(app); assert.equal((await fetch(url(s, "/api/admin/overview"), { headers: as("root") })).status, 200); s.close();
});

// ================= E-POSTA + HATIRLATMA =================
test("E-posta: yapılandırılmamışsa gönderilmez; gönderim, yinelenen engeli, hatalı alıcı, HTML kaçışı, günlük (gövde yok, alıcı maskeli)", async () => {
  const db = memFs(), H = fakeHttp(); const M = LOAD("mailer")({ db, http: H });
  assert.deepEqual(await M.send({ to: "a@b.com", subject: "x", text: "y" }), { sent: false, reason: "disabled" }); assert.equal(H.calls.length, 0);
  process.env.RESEND_API_KEY = "re_x"; process.env.MAIL_FROM = "DAC <b@ornek.com>";
  assert.equal((await M.send({ to: "bozuk", subject: "x", text: "y" })).reason, "bad-recipient");
  const m = M.tpl.supportReply({ subject: "<b>x</b>", message: "<script>alert(1)</script>", ticketId: "AB12" }); assert.ok(!m.html.includes("<script>") && m.html.includes("&lt;script&gt;"));
  assert.equal((await M.send({ to: "kisi@ornek.com", ...m, type: "t", dedupeKey: "k1" })).sent, true); assert.equal((await M.send({ to: "kisi@ornek.com", ...m, type: "t", dedupeKey: "k1" })).reason, "duplicate"); assert.equal(H.calls.length, 1);
  assert.equal(H.calls[0].headers.Authorization, "Bearer re_x"); const log = Object.values(db.store).find((x) => x && x.type === "t" && x.to); assert.equal(log.to, "k***@ornek.com"); assert.ok(!JSON.stringify(db.store).includes("alert(1)"));
  const bad = LOAD("mailer")({ db: memFs(), http: fakeHttp(() => ({ status: 500, data: {} })) }); assert.equal((await bad.send({ to: "a@b.com", subject: "x", text: "y" })).reason, "provider");
});
test("Hatırlatma: iyzico/ödemesiz paket 7/3/1 gün kala ve deneme son 24 saatte bir kez e-posta alır; Stripe, süresi geçen ve devre dışı hesap almaz", async () => {
  process.env.RESEND_API_KEY = "re_x"; process.env.MAIL_FROM = "DAC <b@ornek.com>"; const now = Date.now(), d = 864e5;
  const { ops, H, db } = adminHarness({ users: { a: mkU("a"), b: mkU("b"), c: mkU("c"), s: mkU("s"), x: mkU("x", { disabled: true }), far: mkU("far"), t: mkU("t"), unv: mkU("unv", { emailVerified: false }) }, seed: {
    "subscriptions/a": { plan: "freelance", status: "active", provider: "iyzico", periodEnd: now + 2.5 * d }, "subscriptions/b": { plan: "kobi", status: "active", provider: "admin", free: true, periodEnd: now + 0.5 * d },
    "subscriptions/c": { plan: "kobi", status: "active", provider: "iyzico", periodEnd: now + 6.5 * d }, "subscriptions/s": { plan: "kobi", status: "active", provider: "stripe", periodEnd: now + 2 * d },
    "subscriptions/x": { plan: "kobi", status: "active", provider: "iyzico", periodEnd: now + 2 * d }, "subscriptions/far": { plan: "kobi", status: "active", provider: "iyzico", periodEnd: now + 30 * d },
    "subscriptions/unv": { plan: "kobi", status: "active", provider: "iyzico", periodEnd: now + 2 * d }, "users/t": { trialStart: now - 2.5 * d }, "users/far": { trialStart: now - 0.1 * d } } });
  const r1 = await ops.runReminders(); assert.equal(r1.sent, 4, JSON.stringify(r1)); const to = H.calls.map((c) => c.data.to[0]).sort(); assert.deepEqual(to, ["a@ornek.com", "b@ornek.com", "c@ornek.com", "t@ornek.com"]);
  assert.match(H.calls.find((c) => c.data.to[0] === "a@ornek.com").data.subject, /3 gün/); assert.match(H.calls.find((c) => c.data.to[0] === "b@ornek.com").data.subject, /yarın/);
  const r2 = await ops.runReminders(); assert.equal(r2.sent, 0, "ikinci çalıştırmada yinelenmez"); assert.equal(H.calls.length, 4);
  for (const k of ["RESEND_API_KEY", "MAIL_FROM"]) delete process.env[k]; const off = adminHarness({ users: {}, seed: {} }); assert.equal((await off.ops.runReminders()).skipped, "mail-disabled");
});

// ================= DENEME SUİSTİMALİ + KAYIT BAYRAĞI =================
test("Deneme suistimali: aynı e-posta (gmail noktaları/+etiket normalleştirilir) başka hesapla ikinci deneme alamaz; farklı e-posta alır; kayıt kapalıyken yeni kullanıcı reddedilir", async () => {
  const db = memFs(), U = { u1: { email: "Ali.Veli+a@gmail.com" }, u2: { email: "aliveli@googlemail.com" }, u3: { email: "baska@ornek.com" } };
  const admin = { apps: [1], auth: () => ({ getUser: async (uid) => U[uid] }) }; const C = LOAD("commerce")({ db, PLANS });
  const pay = LOAD("payments")({ app: express(), db, admin, http: null, commerce: C });
  assert.equal(pay.trialHash("Ali.Veli+a@gmail.com"), pay.trialHash("aliveli@googlemail.com")); assert.notEqual(pay.trialHash("x@ornek.com"), pay.trialHash("y@ornek.com")); assert.equal(pay.trialHash("bozuk"), null);
  assert.equal((await pay.getEntitlement("u1")).plan, "trial");
  const e2 = await pay.getEntitlement("u2"); assert.equal(e2.plan, "expired", "aynı kişi ikinci hesapla deneme alamaz"); assert.equal(db.store["users/u2"].trialBlocked, true);
  assert.equal((await pay.getEntitlement("u1")).plan, "trial", "ilk hesap etkilenmez"); assert.equal((await pay.getEntitlement("u3")).plan, "trial");
  assert.ok(!JSON.stringify(db.store).includes("gmail.com"), "e-posta düz metin saklanmaz");
  await C.saveSite({ flags: { registrationOpen: false } }, { uid: "r" }); await assert.rejects(() => pay.getEntitlement("yeni"), (e) => e.status === 403);
  assert.equal((await pay.getEntitlement("u1")).plan, "trial", "mevcut kullanıcılar kayıt kapalıyken etkilenmez");
});
test("Bayraklar: kapatılan tarama türü yöneticiler hariç 503 FEATURE_DISABLED; geçersiz bayrak reddedilir", async () => {
  const db = memFs(), C = LOAD("commerce")({ db, PLANS }); await assert.rejects(() => C.saveSite({ flags: { disabledScanTypes: ["../x"] } }, { uid: "r" }), /Geçersiz/); await assert.rejects(() => C.saveSite({ flags: { registrationOpen: "hayır" } }, { uid: "r" }), /true\/false/);
  await C.saveSite({ flags: { disabledScanTypes: ["security", "server"] } }, { uid: "r" });
  const app = express(); app.use(express.json()); const verify = async (q) => JSON.parse(q.headers["x-test-user"] || "{}"); const pub = C.mountPublic(app, { SEC: LOAD("security"), getVerifyUser: () => verify, getIsAdmin: () => async (u) => u.uid === "root" });
  app.post("/api/scan", pub.scanTypeGuard, (q, r) => r.json({ ok: 1 })); const s = await listen(app);
  const sc = (h, type) => fetch(url(s, "/api/scan"), { method: "POST", headers: h, body: JSON.stringify({ type }) });
  assert.equal((await sc(as("u1"), "SECURITY")).status, 503); assert.equal((await (await sc(as("u1"), "server")).json()).code, "FEATURE_DISABLED"); assert.equal((await sc(as("u1"), "SEO")).status, 200); assert.equal((await sc(as("root"), "SECURITY")).status, 200);
  assert.deepEqual((await (await fetch(url(s, "/api/site-status"))).json()).flags.disabledScanTypes, ["SECURITY", "SERVER"]); s.close();
});

// ================= İADE / İPTAL / FATURA =================
const payFor = (db, H, env = {}) => { Object.assign(process.env, { STRIPE_SECRET_KEY: "sk_test_x", ...env }); return LOAD("payments")({ app: express(), db, admin: { apps: [1], auth: () => ({}) }, http: H }); };
test("İade: Stripe kısmi + tam iade, fazla iade/ödenmemiş sipariş reddi, Idempotency-Key, durum ve toplam güncellenir, aboneliği bitirme", async () => {
  const H = fakeHttp((o) => (/\/refunds$/.test(o.url) ? { status: 200, data: { id: "re_" + H.calls.length } } : /\/subscriptions\//.test(o.url) ? { status: 200, data: { id: "sub_1" } } : { status: 200, data: {} }));
  const seed = { "orders/o1": { uid: "u1", plan: "kobi", cycle: "monthly", currency: "USD", amount: 100, status: "paid", paymentIntent: "pi_1", createdAt: 1 }, "orders/o2": { uid: "u1", plan: "kobi", currency: "USD", amount: 50, status: "pending" }, "orders/o3": { uid: "u1", plan: "kobi", currency: "USD", amount: 50, status: "paid", createdAt: 2 }, "subscriptions/u1": { plan: "kobi", status: "active", provider: "stripe", stripeSubscriptionId: "sub_1", periodEnd: Date.now() + 864e5 }, "users/dummy": {} };
  const h2 = adminHarness({ users: { root: mkU("root") }, seed, payments: (db) => payFor(db, H), httpImpl: H }); const s = await listen(h2.app), A = as("root");
  assert.equal((await jpost(s, "/api/admin/orders/o2/refund", A, {})).status, 400); assert.equal((await jpost(s, "/api/admin/orders/yok/refund", A, {})).status, 404);
  assert.equal((await jpost(s, "/api/admin/orders/o1/refund", A, { amount: 150 })).status, 400, "ödenenden fazla iade"); assert.equal((await jpost(s, "/api/admin/orders/o1/refund", A, { amount: -5 })).status, 400);
  let j = await (await jpost(s, "/api/admin/orders/o1/refund", A, { amount: 30 })).json(); assert.equal(j.success, true); assert.equal(j.total, 30); assert.equal(j.status, "paid");
  const rc = H.calls.find((c) => /refunds/.test(c.url)); assert.match(rc.data, /payment_intent=pi_1/); assert.match(rc.data, /amount=3000/); assert.ok(rc.headers["Idempotency-Key"].startsWith("dac_refund_o1_"));
  assert.equal((await jpost(s, "/api/admin/orders/o1/refund", A, { amount: 80 })).status, 400, "kalan 70'ten fazla");
  j = await (await jpost(s, "/api/admin/orders/o1/refund", A, { endSubscription: true })).json(); assert.equal(j.refunded, 70); assert.equal(j.status, "refunded"); assert.equal(h2.db.store["orders/o1"].refundedAmount, 100); assert.equal(h2.db.store["subscriptions/u1"].status, "canceled"); assert.ok(H.calls.some((c) => c.method === "DELETE" && /subscriptions\/sub_1/.test(c.url)));
  assert.equal((await jpost(s, "/api/admin/orders/o1/refund", A, {})).status, 400, "iade edilmiş sipariş tekrar iade edilmez");
  const rev = await (await fetch(url(s, "/api/admin/revenue"), { headers: A })).json(); assert.deepEqual(rev.paid.totals, { USD: 50 }, "gelir iade düşülerek hesaplanır"); assert.equal(rev.refunded.count, 1);
  // ödeme kimliği olmayan sipariş: panelden iade edilemez, açık mesaj
  h2.db.store["orders/o3"].invoiceId = undefined; const nr = await jpost(s, "/api/admin/orders/o3/refund", A, {}); assert.equal(nr.status, 409); assert.match((await nr.json()).error, /Stripe panelinden/); s.close();
});
test("İade: iyzico siparişinde işlem kimliği yoksa panelden iade yönlendirmesi; aksi halde yapılandırma hatası", async () => {
  const H = fakeHttp(); const h2 = adminHarness({ users: { root: mkU("root") }, seed: { "orders/i1": { uid: "u1", currency: "TRY", amount: 500, status: "paid", paidAt: 1 } }, payments: (db) => payFor(db, H, { IYZICO_API_KEY: "a", IYZICO_SECRET_KEY: "b" }) }); const s = await listen(h2.app);
  const r = await jpost(s, "/api/admin/orders/i1/refund", as("root"), {}); assert.equal(r.status, 409); assert.match((await r.json()).error, /iyzico panelinden/);
  delete process.env.IYZICO_API_KEY; const r2 = await jpost(s, "/api/admin/orders/i1/refund", as("root"), {}); assert.equal(r2.status, 503); s.close();
});
test("Abonelik iptali: Stripe dönem sonu / hemen; ödemesiz paket hemen; yönetici olmayan 403", async () => {
  const H = fakeHttp(); const h2 = adminHarness({ users: { root: mkU("root") }, seed: { "subscriptions/s": { plan: "kobi", status: "active", provider: "stripe", stripeSubscriptionId: "sub_9", periodEnd: Date.now() + 864e5 }, "subscriptions/m": { plan: "kobi", status: "active", provider: "admin", periodEnd: Date.now() + 864e5 } }, payments: (db) => payFor(db, H) }); const s = await listen(h2.app), A = as("root");
  assert.equal((await jpost(s, "/api/admin/users/s/subscription/cancel", as("u1"), {})).status, 403);
  let j = await (await jpost(s, "/api/admin/users/s/subscription/cancel", A, {})).json(); assert.equal(j.immediate, false); assert.match(H.calls.at(-1).data, /cancel_at_period_end=true/); assert.equal(h2.db.store["subscriptions/s"].status, "active");
  j = await (await jpost(s, "/api/admin/users/s/subscription/cancel", A, { immediate: true })).json(); assert.equal(j.immediate, true); assert.equal(h2.db.store["subscriptions/s"].status, "canceled");
  await jpost(s, "/api/admin/users/m/subscription/cancel", A, { immediate: true }); assert.equal(h2.db.store["subscriptions/m"].status, "canceled"); assert.equal((await jpost(s, "/api/admin/users/yok/subscription/cancel", A, {})).status, 404); s.close();
});
test("Fatura takibi: faturasız ödenmiş siparişler listelenir, numara işlenir/silinir, doğrulamalar; gelir özeti faturasız sayısını verir", async () => {
  const { app, db } = adminHarness({ users: { root: mkU("root"), a: mkU("a") }, seed: { "orders/p1": { uid: "a", plan: "kobi", currency: "TRY", amount: 100, status: "paid", createdAt: 3, paidAt: 3 }, "orders/p2": { uid: "a", plan: "kobi", currency: "TRY", amount: 100, status: "paid", createdAt: 2, paidAt: 2, invoice: { no: "A-1" } }, "orders/p3": { uid: "a", currency: "TRY", amount: 1, status: "pending", createdAt: 1 } } }); const s = await listen(app), A = as("root");
  let j = await (await fetch(url(s, "/api/admin/invoices"), { headers: A })).json(); assert.deepEqual(j.rows.map((r) => r.id), ["p1"]); assert.equal(j.counts.done, 1); assert.equal(j.rows[0].email, "a@ornek.com");
  assert.equal((await fetch(url(s, "/api/admin/invoices"), { headers: as("a") })).status, 403);
  assert.equal((await jpost(s, "/api/admin/orders/p1/invoice", A, { no: "x" })).status, 400); assert.equal((await jpost(s, "/api/admin/orders/p1/invoice", A, { no: "ARS-2026-001", url: "http://x.com/f" })).status, 400, "http bağlantı reddedilir"); assert.equal((await jpost(s, "/api/admin/orders/p3/invoice", A, { no: "ARS-2026-002" })).status, 400, "ödenmemiş siparişe fatura işlenmez");
  assert.equal((await jpost(s, "/api/admin/orders/p1/invoice", A, { no: "ARS-2026-001", url: "https://fatura.ornek.com/1" })).status, 200); assert.equal(db.store["orders/p1"].invoice.no, "ARS-2026-001");
  j = await (await fetch(url(s, "/api/admin/invoices"), { headers: A })).json(); assert.equal(j.rows.length, 0); assert.equal((await (await fetch(url(s, "/api/admin/invoices?filter=done"), { headers: A })).json()).rows.length, 2);
  assert.equal((await fetch(url(s, "/api/admin/orders/p1/invoice"), { method: "DELETE", headers: A })).status, 200); assert.equal((await (await fetch(url(s, "/api/admin/revenue"), { headers: A })).json()).uninvoiced, 1); s.close();
});

// ================= TOPLU İŞLEM / KULLANICI SİLME =================
test("Toplu işlem: paket verme/kaldırma/devre dışı/etkin/oturum kapatma; yönetici ve kendiniz korunur, sağlayıcılı abonelik ezilmez, sınırlar", async () => {
  const { app, db, U, calls } = adminHarness({ users: { root: mkU("root"), a: mkU("a"), b: mkU("b"), adm: mkU("adm") }, env: { ADMIN_UIDS: "root,adm" }, seed: { "subscriptions/b": { plan: "kobi", status: "active", provider: "stripe", periodEnd: Date.now() + 864e5 } } }); const s = await listen(app), A = as("root");
  assert.equal((await jpost(s, "/api/admin/bulk", as("a"), { action: "disable", uids: ["b"] })).status, 403); assert.equal((await jpost(s, "/api/admin/bulk", A, { action: "sil", uids: ["a"] })).status, 400); assert.equal((await jpost(s, "/api/admin/bulk", A, { action: "disable", uids: [] })).status, 400);
  assert.equal((await jpost(s, "/api/admin/bulk", A, { action: "disable", uids: Array.from({ length: 201 }, (_, i) => "u" + i) })).status, 400); assert.equal((await jpost(s, "/api/admin/bulk", A, { action: "grant", uids: ["a"], plan: "x", days: 5 })).status, 400);
  let j = await (await jpost(s, "/api/admin/bulk", A, { action: "grant", uids: ["a", "b", "yok"], plan: "freelance", days: 10 })).json(); assert.equal(j.ok, 1); assert.equal(j.failed, 2); assert.equal(db.store["subscriptions/a"].plan, "freelance"); assert.equal(db.store["subscriptions/b"].plan, "kobi", "Stripe aboneliği ezilmedi");
  j = await (await jpost(s, "/api/admin/bulk", A, { action: "disable", uids: ["a", "adm", "root"] })).json(); assert.equal(j.ok, 1); assert.equal(U.a.disabled, true); assert.equal(U.adm.disabled, false); assert.equal(U.root.disabled, false);
  await jpost(s, "/api/admin/bulk", A, { action: "enable", uids: ["a"] }); assert.equal(U.a.disabled, false); await jpost(s, "/api/admin/bulk", A, { action: "revoke-sessions", uids: ["a", "b"] }); assert.equal(calls.filter((c) => c[0] === "revoke").length >= 2, true);
  j = await (await jpost(s, "/api/admin/bulk", A, { action: "revoke", uids: ["a", "b"] })).json(); assert.equal(db.store["subscriptions/a"].status, "canceled"); assert.equal(j.ok, 1);
  assert.ok(Object.values(db.store).some((x) => x && x.action === "bulk.grant" && x.detail.ok === 1)); s.close();
});
test("Kullanıcı silme: e-posta onayı şart, yönetici/kendi hesabı silinemez, aktif Stripe aboneliği engeller (force ile geçer), kayıtlar denetime yazılır", async () => {
  const purged = []; const userState = { purgeAccount: async (uid, o) => { if (!o.force && uid === "st") return { blocked: true }; purged.push(uid); return { blocked: false, counts: { assets: 2 } }; } };
  const { app, db } = adminHarness({ users: { root: mkU("root"), a: mkU("a"), st: mkU("st"), adm: mkU("adm") }, env: { ADMIN_UIDS: "root,adm" }, userState }); const s = await listen(app), A = as("root");
  assert.equal((await jpost(s, "/api/admin/users/a/delete", as("a"), { confirm: "a@ornek.com" })).status, 403); assert.equal((await jpost(s, "/api/admin/users/a/delete", A, { confirm: "yanlis" })).status, 400);
  assert.equal((await jpost(s, "/api/admin/users/root/delete", A, { confirm: "root@ornek.com" })).status, 400); assert.equal((await jpost(s, "/api/admin/users/adm/delete", A, { confirm: "adm@ornek.com" })).status, 400); assert.equal((await jpost(s, "/api/admin/users/yok/delete", A, { confirm: "x" })).status, 404);
  assert.equal((await jpost(s, "/api/admin/users/st/delete", A, { confirm: "st@ornek.com" })).status, 409); assert.equal((await jpost(s, "/api/admin/users/st/delete", A, { confirm: "st@ornek.com", force: true })).status, 200);
  const j = await (await jpost(s, "/api/admin/users/a/delete", A, { confirm: "a@ornek.com" })).json(); assert.equal(j.deleted.assets, 2); assert.deepEqual(purged, ["st", "a"]); assert.ok(Object.values(db.store).some((x) => x && x.action === "user.delete" && x.target === "a")); s.close();
});

// ================= DESTEK + CAPTCHA =================
test("Destek formu: doğrulama, bal küpü kaydetmez, CAPTCHA zorunlu (Turnstile), hız sınırı; yönetici listeler/yanıtlar/kapatır; e-posta kapalıysa dürüst uyarı", async () => {
  process.env.SUPPORT_RATE_LIMIT = "9"; const db = memFs(); let ok = true; const H = fakeHttp((o) => (/turnstile/.test(o.url) ? { status: 200, data: { success: ok } } : { status: 200, data: {} })); const S = LOAD("support")({ db, http: H, mailer: null, SEC: LOAD("security") });
  const app = express(); app.use(express.json()); S.mount(app); const s = await listen(app); const body = { name: "Ali", email: "ali@ornek.com", subject: "Fatura", message: "Faturamı alamadım lütfen yardım" };
  const send = (b) => fetch(url(s, "/api/support"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
  assert.equal((await (await fetch(url(s, "/api/support/config"))).json()).captcha, null);
  assert.equal((await send({ ...body, email: "x" })).status, 400); assert.equal((await send({ ...body, message: "kısa" })).status, 400);
  let j = await (await send(body)).json(); assert.equal(j.success, true); assert.equal(Object.keys(db.store).filter((k) => k.startsWith("supportTickets/")).length, 1);
  await send({ ...body, website: "http://spam" }); assert.equal(Object.keys(db.store).filter((k) => k.startsWith("supportTickets/")).length, 1, "bal küpü dolu: kaydedilmez");
  process.env.TURNSTILE_SECRET = "sec"; process.env.TURNSTILE_SITE_KEY = "site"; assert.equal((await (await fetch(url(s, "/api/support/config"))).json()).captcha.siteKey, "site");
  assert.equal((await send(body)).status, 400, "token yok"); assert.equal((await send({ ...body, captchaToken: "tok" })).status, 200); ok = false; assert.equal((await send({ ...body, captchaToken: "tok" })).status, 400, "Turnstile reddederse engellenir");
  assert.ok(H.calls.some((c) => /turnstile/.test(c.url) && String(c.data).includes("secret=sec")));
  let st = 0; for (let i = 0; i < 6; i++) st = (await send({ ...body, captchaToken: "tok" })).status; assert.equal(st, 429); s.close();
  const h2 = adminHarness({ users: { root: mkU("root"), u1: mkU("u1") }, seed: db.store }); const s2 = await listen(h2.app), A = as("root");
  assert.equal((await fetch(url(s2, "/api/admin/support"), { headers: as("u1") })).status, 403); const list = await (await fetch(url(s2, "/api/admin/support"), { headers: A })).json(); assert.equal(list.counts.open, 2); const id = list.tickets[0].id;
  assert.equal((await jpost(s2, `/api/admin/support/${id}/reply`, A, { message: "x" })).status, 400); const rep = await (await jpost(s2, `/api/admin/support/${id}/reply`, A, { message: "Faturanız hazırlanıp iletildi." })).json(); assert.equal(rep.mailed, false); assert.match(rep.note, /kendiniz yazın/);
  assert.equal(h2.db.store["supportTickets/" + id].status, "answered"); assert.equal((await jpost(s2, `/api/admin/support/${id}/status`, A, { status: "closed" })).status, 200); assert.equal((await jpost(s2, `/api/admin/support/${id}/status`, A, { status: "x" })).status, 400);
  process.env.RESEND_API_KEY = "re"; process.env.MAIL_FROM = "D <d@o.com>"; const t2 = list.tickets[1].id; const r2 = await (await jpost(s2, `/api/admin/support/${t2}/reply`, A, { message: "Merhaba, çözüldü." })).json(); assert.equal(r2.mailed, true); assert.ok(h2.H.calls.some((c) => /resend/.test(c.url) && c.data.to[0] === "ali@ornek.com")); s2.close();
});

// ================= ALARM / HATA KAYDI / YEDEK =================
test("Kalıcı hata kaydı: Firestore'a yazılır, aynı hata sayaçla birleşir, dakikada en çok 30; yönetici geçmişi okur", async () => {
  const db = memFs(); const O = LOAD("ops")({ db, admin: null, http: fakeHttp(), mailer: null, metrics: null, PLANS, now: () => 1000 });
  for (let i = 0; i < 5; i++) O.persistError({ source: "api", status: 500, path: "/x", message: "boom" }); for (let i = 0; i < 60; i++) O.persistError({ source: "api", status: 500, path: "/p" + i, message: "m" + i });
  await new Promise((r) => setTimeout(r, 20)); assert.equal(Object.keys(db.store).filter((k) => k.startsWith("errorLog/")).length, 30); assert.equal((await O.errorHistory()).length, 30);
});
test("Alarm: 5xx oranı eşiği aşınca kanallara (Telegram/webhook/e-posta) bildirir; bekleme süresi; az istekte susar; kanal yoksa boş", async () => {
  const H = fakeHttp(); let rate = 20, reqs = 50; const metrics = { snapshot: () => ({ api: { requests: reqs, errorRate5xx: rate } }) }; process.env.TELEGRAM_BOT_TOKEN = "tg"; process.env.TELEGRAM_CHAT_ID = "1"; process.env.ALERT_WEBHOOK_URL = "https://hooks.ornek.com/x";
  const O = LOAD("ops")({ db: memFs(), admin: null, http: H, mailer: null, metrics, PLANS }); let r = await O.checkAlerts(); assert.equal(r.alerted, true); assert.deepEqual(r.channels, ["telegram", "webhook"]); assert.ok(H.calls[0].url.includes("api.telegram.org/bottg/sendMessage"));
  r = await O.checkAlerts(); assert.equal(r.cooldown, true); assert.equal(H.calls.length, 2); const O2 = LOAD("ops")({ db: memFs(), admin: null, http: H, mailer: null, metrics: { snapshot: () => ({ api: { requests: 5, errorRate5xx: 100 } }) }, PLANS }); assert.equal((await O2.checkAlerts()).alerted, false);
  process.env.ALERT_WEBHOOK_URL = "http://guvensiz.com/x"; delete process.env.TELEGRAM_BOT_TOKEN; const O3 = LOAD("ops")({ db: memFs(), admin: null, http: H, mailer: null, metrics, PLANS }); assert.deepEqual((await O3.checkAlerts()).channels, [], "http (güvensiz) webhook kullanılmaz");
});
test("Yedek: BACKUP_BUCKET yoksa 503; varsa Firestore exportDocuments çağrılır, kayıt tutulur, hata yönetilir", async () => {
  const db = memFs(); const H = fakeHttp((o) => (/exportDocuments/.test(o.url) ? { status: 200, data: { name: "projects/p/operations/1" } } : { status: 200, data: {} })); const admin = { apps: [1], app: () => ({ options: { projectId: "proj-1", credential: { getAccessToken: async () => ({ access_token: "AT" }) } } }) };
  const O = LOAD("ops")({ db, admin, http: H, mailer: null, metrics: null, PLANS }); await assert.rejects(() => O.backup("x"), (e) => e.status === 503);
  process.env.BACKUP_BUCKET = "dac-yedek"; const r = await O.backup("root@ornek.com"); assert.equal(r.status, "started"); assert.match(r.prefix, /^gs:\/\/dac-yedek\/dac-backups\//); const c = H.calls[0]; assert.match(c.url, /projects\/proj-1\/databases\/\(default\):exportDocuments/); assert.equal(c.headers.Authorization, "Bearer AT"); assert.equal((await O.backupHistory()).length, 1);
  const H2 = fakeHttp(() => ({ status: 403, data: { error: { message: "izin yok" } } })); await assert.rejects(() => LOAD("ops")({ db, admin, http: H2, mailer: null, metrics: null, PLANS }).backup("x"), /izin yok/);
  process.env.BACKUP_BUCKET = "../kotu"; await assert.rejects(() => O.backup("x"), /geçersiz/);
});
test("Yönetici operasyon uçları: durum (gizli değer sızmaz), test uyarısı, yedek, hatırlatma; yetkisiz 403", async () => {
  process.env.RESEND_API_KEY = "re_GIZLI"; process.env.MAIL_FROM = "DAC <x@ornek.com>"; process.env.TELEGRAM_BOT_TOKEN = "tgGIZLI"; process.env.TELEGRAM_CHAT_ID = "9";
  const { app } = adminHarness({ users: { root: mkU("root") } }); const s = await listen(app), A = as("root");
  assert.equal((await fetch(url(s, "/api/admin/ops"), { headers: as("u1") })).status, 403); assert.equal((await jpost(s, "/api/admin/ops/backup", as("u1"))).status, 403);
  const txt = await (await fetch(url(s, "/api/admin/ops"), { headers: A })).text(); assert.ok(!txt.includes("GIZLI") && !txt.includes("x@ornek.com"), "anahtar/adres sızmaz"); const j = JSON.parse(txt); assert.equal(j.mail.enabled, true); assert.equal(j.alerts.channels.telegram, true);
  assert.equal((await (await jpost(s, "/api/admin/ops/test-alert", A)).json()).channels[0], "telegram"); assert.equal((await jpost(s, "/api/admin/ops/backup", A)).status, 503); assert.equal((await (await jpost(s, "/api/admin/ops/reminders", A)).json()).success, true);
  assert.equal((await jpost(s, "/api/admin/ops/test-mail", A, { to: "x@y.com" })).status, 200); assert.equal((await (await fetch(url(s, "/api/admin/errors/history"), { headers: A })).json()).success, true); s.close();
});
test("Makbuz: Stripe invoice.paid doğrulanmış e-postaya makbuz gönderir (tekrarda yinelenmez)", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_x"; process.env.STRIPE_WEBHOOK_SECRET = "whsec_t"; process.env.RESEND_API_KEY = "re"; process.env.MAIL_FROM = "D <d@o.com>";
  const db = memFs(); const H = fakeHttp((o) => (/subscriptions/.test(o.url) ? { status: 200, data: { id: "sub_1", status: "active", customer: "c", current_period_end: Math.floor(Date.now() / 1000) + 86400 * 30, metadata: { uid: "u1", plan: "freelance", cycle: "monthly" } } } : { status: 200, data: {} }));
  const mailer = LOAD("mailer")({ db, http: H }); const app = express(); app.use(express.json({ verify: (q, r, b) => { q.rawBody = b; } }));
  LOAD("payments")({ app, db, admin: { apps: [1], auth: () => ({ getUser: async () => ({ email: "u1@ornek.com", emailVerified: true }) }) }, http: H, commerce: null, mailer }); const s = await listen(app);
  const send = async (id) => { const raw = JSON.stringify({ id, type: "invoice.paid", data: { object: { id: "in_7", subscription: "sub_1", amount_paid: 1199, payment_intent: "pi_77" } } }), t = Math.floor(Date.now() / 1000), sig = crypto.createHmac("sha256", "whsec_t").update(`${t}.`).update(raw).digest("hex"); return fetch(url(s, "/api/stripe/webhook"), { method: "POST", headers: { "Content-Type": "application/json", "stripe-signature": `t=${t},v1=${sig}` }, body: raw }); };
  assert.equal((await send("e1")).status, 200); await new Promise((r) => setTimeout(r, 50)); const mails = H.calls.filter((c) => /resend/.test(c.url)); assert.equal(mails.length, 1); assert.match(mails[0].data.subject, /Freelance/); assert.equal(db.store["orders/st_in_7"].paymentIntent, "pi_77");
  await send("e2"); await new Promise((r) => setTimeout(r, 50)); assert.equal(H.calls.filter((c) => /resend/.test(c.url)).length, 1, "aynı fatura için ikinci makbuz yok"); s.close(); delete process.env.STRIPE_WEBHOOK_SECRET;
});
