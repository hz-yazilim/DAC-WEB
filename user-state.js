/* Digital Asset Center - Kullanıcı verisi kalıcılığı (localStorage yedeği)
 * Depolama: users/{uid}/state/app  (mevcut "users" belgelerine DOKUNMAZ; yeni bir alt koleksiyon)
 * - Kullanıcı kimliği yalnızca doğrulanmış Firebase ID token'ından alınır; istemciden uid kabul edilmez.
 * - Veri tek bir JSON metni olarak saklanır (Firestore iç içe dizi / alan adı kısıtlarına takılmaz).
 * - Sürüm kontrolü: eski sürümle yazma 409 döner ve güncel veri geri verilir (sessiz üzerine yazma yok).
 */
"use strict";
const express = require("express");
const SEC = require("./security");

const LIMITS = { assets: 5000, scans: 5000, team: 1000, projects: 1000, bytes: 900 * 1024 };
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function clean(v, depth = 0) {
  if (v === undefined || typeof v === "function") return undefined;
  if (v === null || typeof v === "number" || typeof v === "boolean") return typeof v === "number" && !Number.isFinite(v) ? null : v;
  if (typeof v === "string") return v.length > 20000 ? v.slice(0, 20000) : v;
  if (depth > 12) return null;
  if (Array.isArray(v)) return v.slice(0, 5000).map(x => { const c = clean(x, depth + 1); return c === undefined ? null : c; });
  if (typeof v === "object") { const o = {}; for (const k of Object.keys(v)) { if (FORBIDDEN_KEYS.has(k)) continue; const c = clean(v[k], depth + 1); if (c !== undefined) o[k] = c; } return o; }
  return undefined;
}

// İstemciden gelen durumu doğrular ve temizler. Geçersizse Error({status:400}) fırlatır.
function sanitizeState(input) {
  const bad = (m) => Object.assign(new Error(m), { status: 400 });
  if (!input || typeof input !== "object" || Array.isArray(input)) throw bad("Geçersiz veri.");
  const out = {};
  for (const k of ["assets", "scans", "team", "projects"]) {
    const a = input[k] === undefined ? [] : input[k];
    if (!Array.isArray(a)) throw bad(`"${k}" dizi olmalı.`);
    if (a.length > LIMITS[k]) throw Object.assign(new Error(`"${k}" sınırı aşıldı (${LIMITS[k]}).`), { status: 413, code: "STATE_TOO_LARGE" });
    out[k] = a.map(x => { if (!x || typeof x !== "object" || typeof x.id !== "string" && k !== "scans") throw bad(`"${k}" içinde geçersiz kayıt.`); return clean(x); });
  }
  const s = input.settings && typeof input.settings === "object" && !Array.isArray(input.settings) ? clean(input.settings) : {};
  // Paket/abonelik bilgisi sunucuda (subscriptions) tutulur; adres cihaza özeldir. İkisi de buluta yazılmaz.
  for (const k of ["plan", "planEnd", "provider", "trialStart", "apiUrl"]) delete s[k];
  out.settings = s;
  out.settingsAt = Number.isFinite(input.settingsAt) ? input.settingsAt : 0;
  const tomb = input.tomb && typeof input.tomb === "object" && !Array.isArray(input.tomb) ? input.tomb : {};
  out.tomb = {}; for (const [id, ts] of Object.entries(tomb).slice(0, 5000)) if (typeof ts === "number" && !FORBIDDEN_KEYS.has(id)) out.tomb[id] = ts;
  return out;
}

module.exports = function initUserState({ app, db, admin, verifyUser }) {
  const limiter = SEC.makeLimiter(SEC.int(process.env.STATE_RATE_LIMIT, 120), 5 * 60 * 1000);
  const guard = [
    (req, res, next) => (db ? next() : res.status(503).json({ success: false, error: "Sunucuda Firebase yapılandırılmamış; bulut kaydı kapalı." })),
    SEC.authenticate(verifyUser),
    (req, res, next) => (limiter(req.user.uid) ? next() : res.status(429).json({ success: false, error: "Çok fazla istek. Biraz sonra tekrar deneyin." }))
  ];
  const ref = (uid) => db.collection("users").doc(uid).collection("state").doc("app");
  const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { const code = e.status || 500; if (code >= 500) console.error("state:", e.message); res.status(code).json({ success: false, code: e.code, error: code >= 500 && !e.status ? "Sunucu hatası" : e.message }); } };

  app.get("/api/state", guard, wrap(async (req, res) => {
    const d = await ref(req.user.uid).get();
    if (!d.exists) return res.json({ success: true, exists: false, version: 0 });
    const x = d.data(); let state = null; try { state = JSON.parse(x.data); } catch { /* bozuk kayıt: istemci yerel veriyi korur */ }
    res.json({ success: true, exists: true, version: x.version || 0, updatedAt: x.updatedAt || null, state });
  }));

  app.put("/api/state", guard, express.json({ limit: "1mb" }), wrap(async (req, res) => {
    const body = req.body || {}; const uid = req.user.uid;
    const baseVersion = Number.isInteger(body.baseVersion) ? body.baseVersion : 0;
    const state = sanitizeState(body.state); const json = JSON.stringify(state);
    if (Buffer.byteLength(json) > LIMITS.bytes) return res.status(413).json({ success: false, code: "STATE_TOO_LARGE", error: "Veri çok büyük." });
    const r = ref(uid);
    const out = await db.runTransaction(async (t) => {
      const d = await t.get(r); const cur = d.exists ? (d.data().version || 0) : 0;
      if (cur !== baseVersion) return { conflict: true, version: cur, data: d.exists ? d.data().data : null };
      const version = cur + 1; t.set(r, { data: json, version, updatedAt: Date.now(), size: json.length });
      return { version };
    });
    if (out.conflict) { let remote = null; try { remote = out.data ? JSON.parse(out.data) : null; } catch { /* yok say */ } return res.status(409).json({ success: false, code: "VERSION_CONFLICT", error: "Veri başka bir cihazda güncellenmiş.", version: out.version, state: remote }); }
    res.json({ success: true, version: out.version });
  }));

  // ---------- KVKK m.11: açık rıza / onay kaydı, veri taşınabilirliği (dışa aktarma) ve silme ----------
  const CONSENT_TYPES = new Set(["terms", "privacy", "cookies-analytics", "distance-sales", "withdrawal-waiver"]);
  const accLimiter = SEC.makeLimiter(SEC.int(process.env.ACCOUNT_RATE_LIMIT, 10), 60 * 60 * 1000);
  const accGuard = [...guard, (req, res, next) => (accLimiter(req.user.uid) ? next() : res.status(429).json({ success: false, error: "Çok fazla hesap işlemi. Bir saat sonra tekrar deneyin." }))];
  const CHUNK = 400;
  async function deleteWhere(coll, field, uid) {
    let n = 0;
    for (let i = 0; i < 200; i++) {
      const snap = await db.collection(coll).where(field, "==", uid).limit(CHUNK).get(); if (snap.empty) break;
      const b = db.batch(); snap.docs.forEach(d => b.delete(d.ref)); await b.commit(); n += snap.size; if (snap.size < CHUNK) break;
    }
    return n;
  }
  const rows = async (coll, field, uid, max = 2000) => (await db.collection(coll).where(field, "==", uid).limit(max).get()).docs.map(d => ({ id: d.id, ...d.data() }));

  app.post("/api/consent", guard, wrap(async (req, res) => {
    const type = String((req.body || {}).type || ""), version = String((req.body || {}).version || "").slice(0, 40);
    if (!CONSENT_TYPES.has(type) || !version) return res.status(400).json({ success: false, error: "Geçersiz onay kaydı." });
    const granted = (req.body || {}).granted !== false;
    const row = { uid: req.user.uid, type, version, granted, at: Date.now(), ip: req.ip || null, ua: String(req.headers["user-agent"] || "").slice(0, 200) };
    if (type === "terms" || type === "privacy") {
      // Aynı kullanıcı + tür + sürüm için tek kayıt (yeniden denemede çift kayıt oluşmaz; ilk onay zamanı korunur)
      const d = db.collection("consents").doc(`${req.user.uid}_${type}_${version}`.replace(/[\/\s]/g, "_"));
      if (!(await d.get()).exists) await d.set(row);
    } else await db.collection("consents").add(row);
    res.json({ success: true });
  }));

  // Kullanıcının kendi onay kayıtları: arayüz, güncel sürüm için Kullanım Koşulları + KVKK onayının sunucuda olup olmadığını buradan kontrol eder
  app.get("/api/consent/status", guard, wrap(async (req, res) => {
    const version = String(req.query.version || "").slice(0, 40);
    const list = await rows("consents", "uid", req.user.uid, 200);
    const has = (t) => list.some(c => c.type === t && c.granted !== false && (!version || c.version === version));
    res.set("Cache-Control", "no-store");
    res.json({ success: true, version, terms: has("terms"), privacy: has("privacy"), records: list.map(({ type, version: v, granted, at }) => ({ type, version: v, granted, at })).sort((a, b) => b.at - a.at) });
  }));

  app.get("/api/account/export", accGuard, wrap(async (req, res) => {
    const uid = req.user.uid;
    const [st, sub, usr, assets, checks, orders, consents, blockedRaw] = await Promise.all([
      ref(uid).get(), db.collection("subscriptions").doc(uid).get(), db.collection("users").doc(uid).get(),
      rows("assets", "ownerId", uid), rows("assetChecks", "ownerId", uid), rows("orders", "uid", uid), rows("consents", "uid", uid),
      rows("blockedAttempts", "uid", uid).catch(() => [])
    ]);
    const blockedAttempts = (blockedRaw || []).map(({ host, category, assetType, where, at }) => ({ host, category, assetType, where, at })); // güvenlik kaydı (yasaklı hedef denemeleri); iç kural/IP alanları dışarıda
    let state = null; try { state = st.exists ? JSON.parse(st.data().data) : null; } catch { /* bozuk kayıt */ }
    res.set({ "Content-Disposition": 'attachment; filename="dac-verilerim.json"', "Cache-Control": "no-store" });
    res.json({ success: true, exportedAt: new Date().toISOString(), profile: { uid, email: req.user.email, name: req.user.name }, account: usr.exists ? usr.data() : null, subscription: sub.exists ? sub.data() : null, state, assets, assetChecks: checks, orders, consents, blockedAttempts });
  }));

  // Hesap verisini siler (kullanıcı kendi isteğiyle veya yönetici KVKK talebiyle). Aktif Stripe aboneliği varsa silmez (force ile geçilebilir).
  async function purgeAccount(uid, { force = false } = {}) {
    const sub = (await db.collection("subscriptions").doc(uid).get()).data();
    if (!force && sub && sub.provider === "stripe" && sub.status === "active") return { blocked: true };
    const counts = {};
    counts.assets = await deleteWhere("assets", "ownerId", uid);
    counts.assetChecks = await deleteWhere("assetChecks", "ownerId", uid);
    counts.pushSubs = await deleteWhere("pushSubs", "uid", uid);
    try { counts.blockedAttempts = await deleteWhere("blockedAttempts", "uid", uid); } catch { /* kayıt yok */ } // güvenlik kaydı: hesap silinince kişisel veri (uid/IP) kalmaz
    await ref(uid).delete();
    await db.collection("users").doc(uid).delete();
    try { await db.collection("adminNotes").doc(uid).delete(); } catch { /* not yok */ }
    // orders / subscriptions / consents: vergi ve ticari defter saklama yükümlülüğü ile ispat amacıyla yasal süre boyunca korunur (aydınlatma metninde belirtilir).
    if (admin && admin.auth) { try { await admin.auth().deleteUser(uid); } catch (e) { if (e.code !== "auth/user-not-found") throw e; } }
    return { blocked: false, counts };
  }

  app.delete("/api/account", accGuard, wrap(async (req, res) => {
    const uid = req.user.uid;
    if (String((req.body || {}).confirm || "") !== "HESABIMI SIL") return res.status(400).json({ success: false, error: 'Onay için "HESABIMI SIL" yazın.' });
    const r = await purgeAccount(uid); if (r.blocked) return res.status(409).json({ success: false, code: "ACTIVE_SUBSCRIPTION", error: "Aktif bir USD aboneliğiniz var. Önce Paket sayfasından aboneliği iptal edin, sonra hesabı silin." });
    const counts = r.counts;
    res.json({ success: true, deleted: counts });
  }));

  return { sanitizeState, purgeAccount };
};
module.exports.sanitizeState = sanitizeState;
