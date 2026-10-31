// Yönetici paneli eklemeleri: çevrimiçi durum, şifre değiştirme/sıfırlama e-postası, varlıkları toplu silme, ücretsiz deneme süresi. Firebase/Firestore için MOCK.
process.env.NODE_ENV = "development";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");
const _p = require("path"), _fs = require("fs");
const ROOT = _fs.existsSync(_p.join(__dirname, "index.js")) ? __dirname : _p.join(__dirname, "..");
const LOAD = (n) => require(_fs.existsSync(_p.join(ROOT, "server", n + ".js")) ? _p.join(ROOT, "server", n) : _p.join(ROOT, n));
const listen = (app) => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const url = (s, p) => `http://127.0.0.1:${s.address().port}${p}`;
const as = (uid) => ({ "Content-Type": "application/json", "x-test-user": JSON.stringify({ uid, email: uid + "@ornek.com" }) });
const post = (s, p, uid, body) => fetch(url(s, p), { method: "POST", headers: as(uid), body: JSON.stringify(body || {}) });

function fakeDb(seed = {}) {
  const store = new Map(Object.entries(seed));
  const docRef = (path) => ({ id: path.split("/").pop(), path, async get() { const d = store.get(path); return { exists: d !== undefined, id: path.split("/").pop(), data: () => (d === undefined ? undefined : { ...d }) }; }, async set(v, o) { store.set(path, o && o.merge ? { ...(store.get(path) || {}), ...v } : { ...v }); }, async delete() { store.delete(path); }, collection: (c) => col(path + "/" + c) });
  const col = (cpath, filters = [], lim = null) => ({
    where: (f, op, v) => col(cpath, [...filters, [f, op, v]], lim), limit: (n) => col(cpath, filters, n), orderBy: () => col(cpath, filters, lim),
    doc: (id) => docRef(cpath + "/" + (id || "auto" + Math.random().toString(36).slice(2))),
    async get() { let rows = [...store.entries()].filter(([k]) => k.startsWith(cpath + "/") && !k.slice(cpath.length + 1).includes("/")).filter(([, d]) => filters.every(([f, , v]) => d[f] === v)); if (lim) rows = rows.slice(0, lim); const docs = rows.map(([k, d]) => ({ id: k.split("/").pop(), data: () => ({ ...d }), ref: docRef(k) })); return { docs, size: docs.length, empty: !docs.length }; },
    count: () => ({ get: async () => ({ data: () => ({ count: [...store.entries()].filter(([k, d]) => k.startsWith(cpath + "/") && filters.every(([f, , v]) => d[f] === v)).length }) }) })
  });
  return { store, collection: (c) => col(c), batch: () => { const ops = []; return { delete: (r) => ops.push(r), commit: async () => { for (const r of ops) await r.delete(); } }; }, runTransaction: async (fn) => fn({ get: (r) => r.get(), set: (r, v) => r.set(v) }) };
}
const mkU = (uid, o = {}) => ({ uid, email: uid + "@ornek.com", emailVerified: true, disabled: false, metadata: { creationTime: "Fri, 30 Oct 2026 10:00:00 GMT", lastSignInTime: "Fri, 30 Oct 2026 10:00:00 GMT" }, providerData: [{ providerId: "password" }], ...o });

function build({ users, seed = {}, mailer = null }) {
  Object.assign(process.env, { ADMIN_UIDS: "root", ADMIN_EMAILS: "" });
  const db = fakeDb(seed); const U = Object.fromEntries(users.map((u) => [u.uid, u])); const calls = { update: [], revoke: [] };
  const adm = { apps: [1], auth: () => ({
    listUsers: async () => ({ users: Object.values(U), pageToken: undefined }), getUser: async (uid) => { if (!U[uid]) throw new Error("yok"); return U[uid]; },
    getUsers: async (ids) => ({ users: ids.map((x) => U[x.uid]).filter(Boolean) }), getUserByEmail: async (e) => { const u = Object.values(U).find((x) => x.email === e); if (!u) throw new Error("yok"); return u; },
    updateUser: async (uid, p) => { calls.update.push({ uid, ...p }); }, revokeRefreshTokens: async (uid) => { calls.revoke.push(uid); }, generatePasswordResetLink: async (e) => "https://sifre.test/reset?oob=" + encodeURIComponent(e), deleteUser: async () => {} }) };
  const app = express(); app.use(express.json());
  const verifyUser = async (req) => { const h = req.headers["x-test-user"]; if (!h) throw Object.assign(new Error("Giriş yapmanız gerekiyor."), { status: 401 }); const u = JSON.parse(h); return { uid: u.uid, email: u.email || null, emailVerified: true }; };
  const SEC = LOAD("security"), M = LOAD("metrics"), J = LOAD("jobs"), PLANS = LOAD("plans");
  const jobs = J.createJobs({ store: J.memoryStore(), scanItem: async () => ({ scanStatus: "COMPLETED", summary: {} }) }); jobs.stop();
  const userState = LOAD("user-state")({ app, db, admin: adm, verifyUser });
  const commerce = LOAD("commerce")({ db, PLANS });
  LOAD("admin")({ app, db, admin: adm, verifyUser, SEC, metrics: M.createMetrics(), jobs, getHealth: async () => ({ ok: true }), platform: async () => ({}), commerce, userState, mailer });
  return { app, db, calls, commerce, PLANS };
}

test("çevrimiçi durum: heartbeat atan kullanıcı 'sitede' görünür, atmayan görünmez; filtre ve genel bakış sayacı çalışır", async () => {
  const { app } = build({ users: [mkU("root"), mkU("u1"), mkU("u2")] }); const s = await listen(app);
  assert.equal((await fetch(url(s, "/api/presence"), { method: "POST" })).status, 401, "girişsiz kabul edilmez");
  assert.equal((await post(s, "/api/presence", "u1")).status, 200);
  let j = await (await fetch(url(s, "/api/admin/users"), { headers: as("root") })).json();
  assert.equal(j.users.find((u) => u.uid === "u1").online, true); assert.equal(j.users.find((u) => u.uid === "u2").online, false);
  j = await (await fetch(url(s, "/api/admin/users?status=online"), { headers: as("root") })).json(); assert.deepEqual(j.users.map((u) => u.uid), ["u1"]);
  j = await (await fetch(url(s, "/api/admin/overview"), { headers: as("root") })).json(); assert.equal(j.presence.online, 1);
  j = await (await fetch(url(s, "/api/admin/users/u1"), { headers: as("root") })).json(); assert.equal(j.user.online, true); assert.ok(j.user.lastSeenAt);
  s.close();
});

test("yönetici şifre değiştirme: yalnızca şifreli hesap, 8+ karakter, oturumlar kapanır, şifre kayda yazılmaz", async () => {
  const { app, db, calls } = build({ users: [mkU("root"), mkU("u1"), mkU("g1", { providerData: [{ providerId: "google.com" }] })] }); const s = await listen(app);
  assert.equal((await post(s, "/api/admin/users/u1/password", "u1", { password: "Yeni-Sifre-123" })).status, 403, "yönetici değil");
  assert.equal((await post(s, "/api/admin/users/u1/password", "root", { password: "kisa" })).status, 400);
  assert.equal((await post(s, "/api/admin/users/g1/password", "root", { password: "Yeni-Sifre-123" })).status, 400, "Google hesabı");
  assert.equal((await post(s, "/api/admin/users/root/password", "root", { password: "Yeni-Sifre-123" })).status, 400, "kendi şifresi");
  const r = await post(s, "/api/admin/users/u1/password", "root", { password: "Yeni-Sifre-123" }); assert.equal(r.status, 200);
  assert.deepEqual(calls.update, [{ uid: "u1", password: "Yeni-Sifre-123" }]); assert.deepEqual(calls.revoke, ["u1"]);
  const audit = [...db.store.entries()].filter(([k]) => k.startsWith("adminAudit/")).map(([, v]) => v);
  assert.ok(audit.some((a) => a.action === "user.password-set" && a.target === "u1")); assert.ok(!JSON.stringify(audit).includes("Yeni-Sifre-123"), "şifre denetim kaydına yazılmaz");
  s.close();
});

test("şifre sıfırlama: send=true e-posta gönderir (bağlantı yanıtta dönmez); e-posta kapalıysa bağlantı yöneticiye döner", async () => {
  const sent = []; const mailer = { enabled: () => true, tpl: { passwordReset: ({ link }) => ({ subject: "S", text: link, html: link }) }, send: async (m) => { sent.push(m); return { sent: true }; } };
  let b = build({ users: [mkU("root"), mkU("u1")], mailer }); let s = await listen(b.app);
  let j = await (await post(s, "/api/admin/users/u1/password-reset", "root", { send: true })).json();
  assert.equal(j.sent, true); assert.equal(j.link, undefined); assert.equal(sent[0].to, "u1@ornek.com"); assert.match(sent[0].text, /sifre\.test/); s.close();
  b = build({ users: [mkU("root"), mkU("u1")], mailer: { enabled: () => false, tpl: {}, send: async () => ({ sent: false }) } }); s = await listen(b.app);
  j = await (await post(s, "/api/admin/users/u1/password-reset", "root", { send: true })).json(); assert.equal(j.sent, false); assert.match(j.link, /sifre\.test/);
  j = await (await post(s, "/api/admin/users/u1/password-reset", "root", {})).json(); assert.match(j.link, /sifre\.test/, "send olmadan eski davranış: bağlantı döner");
  s.close();
});

test("varlıkları toplu sil: yalnızca o kullanıcının varlıkları gider; hesap kalır; bulut durumu boşalır ve tomb yazılır; onay şart", async () => {
  const state = { assets: [{ id: "a1", cat: "web" }, { id: "n1", cat: "domain" }], scans: [{ id: "x" }], team: [], projects: [], settings: {}, tomb: { old: 1 } };
  const seed = { "assets/a1": { ownerId: "u1", name: "A" }, "assets/a2": { ownerId: "u1", name: "B" }, "assets/z1": { ownerId: "u2", name: "Z" }, "assetChecks/c1": { ownerId: "u1" }, "assetChecks/c2": { ownerId: "u2" }, "users/u1/state/app": { data: JSON.stringify(state), version: 4 } };
  const { app, db } = build({ users: [mkU("root"), mkU("u1"), mkU("u2")], seed }); const s = await listen(app);
  assert.equal((await post(s, "/api/admin/users/u1/assets/delete", "u1", { confirm: true })).status, 403);
  assert.equal((await post(s, "/api/admin/users/u1/assets/delete", "root", {})).status, 400, "onay gerekli");
  const r = await post(s, "/api/admin/users/u1/assets/delete", "root", { confirm: true }); const j = await r.json(); assert.equal(r.status, 200);
  assert.equal(j.deleted.assets, 2); assert.equal(j.deleted.assetChecks, 1); assert.equal(j.deleted.stateAssets, 2);
  assert.ok(!db.store.has("assets/a1") && !db.store.has("assets/a2") && !db.store.has("assetChecks/c1")); assert.ok(db.store.has("assets/z1") && db.store.has("assetChecks/c2"), "başka kullanıcıya dokunulmaz");
  const st = db.store.get("users/u1/state/app"); const parsed = JSON.parse(st.data); assert.equal(st.version, 5); assert.deepEqual(parsed.assets, []); assert.ok(parsed.tomb.a1 && parsed.tomb.n1 && parsed.tomb.a2 && parsed.tomb.old === 1); assert.equal(parsed.scans.length, 1, "diğer veriler korunur");
  const a = await (await fetch(url(s, "/api/admin/users/u1/assets"), { headers: as("root") })).json(); assert.equal(a.total, 0);
  s.close();
});

test("ücretsiz deneme süresi: yönetici panelinden değişir, herkese açık fiyat uç noktasında görünür; geçersiz değer reddedilir", async () => {
  const { commerce, PLANS } = build({ users: [mkU("root")] }); const orig = PLANS.TRIAL_DAYS, feats = PLANS.PLANS.trial.features.slice();
  try {
    await assert.rejects(() => commerce.savePricing({ trialDays: 0 }, { uid: "root" }), /Ücretsiz deneme süresi/);
    await assert.rejects(() => commerce.savePricing({ trialDays: 400 }, { uid: "root" }), /Ücretsiz deneme süresi/);
    const r = await commerce.savePricing({ trialDays: "14" }, { uid: "root", email: "r@x.com" });
    assert.equal(PLANS.TRIAL_DAYS, 14); assert.equal(r.public.trialDays, 14); assert.ok(r.changes.some((c) => c.field === "trialDays" && c.from === orig && c.to === 14));
    assert.ok(PLANS.PLANS.trial.features.includes("14 gün ücretsiz"), "paket kartındaki metin de güncellenir");
    assert.equal(commerce.currentState().trialDays, 14);
    await commerce.resetPricing({ uid: "root" }); assert.equal(PLANS.TRIAL_DAYS, orig);
  } finally { PLANS.TRIAL_DAYS = orig; PLANS.PLANS.trial.features = feats; }
});
