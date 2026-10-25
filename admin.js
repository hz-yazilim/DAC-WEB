/* Digital Asset Center - Yönetici (admin) API'si
 * GÜVENLİK MODELİ
 *  - Rol YALNIZCA sunucuda belirlenir: (1) ADMIN_UIDS / ADMIN_EMAILS ortam değişkenleri (ilk yönetici; e-posta için doğrulanmış e-posta şart),
 *    (2) Firestore `adminRoles/{uid}` (yalnızca bu API yazar; Firestore kuralları istemci erişimini tamamen kapatır).
 *  - Tarayıcıdan gelen hiçbir alan (localStorage, istek gövdesi, başlık) rolü etkilemez; her istekte Firebase ID token'ı Admin SDK ile doğrulanır.
 *  - Tüm /api/admin/* uçları: IP hız sınırı → kimlik doğrulama → kullanıcı hız sınırı → rol denetimi. Yetkisizse 403 (içerik sızdırmaz).
 *  - Gizli URL güvenlik yöntemi DEĞİLDİR; arayüzdeki menü yalnızca kolaylıktır, asıl denetim burada.
 *  - Hizmet hesabı bilgileri hiçbir yanıtta yer almaz. Yönetici işlemleri `adminAudit` koleksiyonuna yazılır (hassas veri temizlenerek).
 *  - Gerçek verisi olmayan alanlar uydurulmaz: { available:false, reason } döner. */
"use strict";
const { scrub } = require("./metrics");

module.exports = function createAdmin({ app, db, admin, verifyUser, SEC, metrics, jobs, getHealth, platform, getEntitlement = null, now = Date.now }) {
  const list = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
  const envUids = () => new Set(list(process.env.ADMIN_UIDS));
  const envEmails = () => new Set(list(process.env.ADMIN_EMAILS).map((e) => e.toLowerCase()));
  const roleCache = new Map(); const ROLE_TTL = 15000;
  const authOk = () => !!(admin && admin.apps && admin.apps.length);
  const unavailable = (reason) => ({ available: false, reason });

  async function roleOf(user) {
    const hit = roleCache.get(user.uid); if (hit && now() - hit.at < ROLE_TTL) return hit.val;
    let val = { admin: false, source: null };
    if (envUids().has(user.uid)) val = { admin: true, source: "env-uid" };
    else if (user.email && user.emailVerified === true && envEmails().has(String(user.email).toLowerCase())) val = { admin: true, source: "env-email" };
    else if (db) { try { const s = await db.collection("adminRoles").doc(user.uid).get(); if (s.exists && s.data().role === "admin") val = { admin: true, source: "firestore" }; } catch { /* rol okunamazsa yetki VERİLMEZ (fail-closed) */ } }
    roleCache.set(user.uid, { at: now(), val }); if (roleCache.size > 5000) roleCache.clear();
    return val;
  }

  const ipLimit = SEC.makeLimiter(SEC.int(process.env.ADMIN_IP_RATE_LIMIT, 120), 5 * 60 * 1000);
  const userLimit = SEC.makeLimiter(SEC.int(process.env.ADMIN_USER_RATE_LIMIT, 240), 5 * 60 * 1000);
  const writeLimit = SEC.makeLimiter(SEC.int(process.env.ADMIN_WRITE_RATE_LIMIT, 40), 5 * 60 * 1000);
  const deny = (res, code, error, extra = {}) => res.status(code).json({ success: false, error, ...extra });

  const authn = SEC.authenticate(verifyUser);
  const guard = [
    (req, res, next) => (ipLimit(req.ip) ? next() : deny(res, 429, "Çok fazla istek.")),
    authn,
    (req, res, next) => (userLimit(req.user.uid) ? next() : deny(res, 429, "Çok fazla istek.")),
    async (req, res, next) => { const r = await roleOf(req.user); if (!r.admin) return deny(res, 403, "Bu işlem için yönetici yetkisi gerekir.", { code: "ADMIN_REQUIRED" }); req.admin = r; res.set("Cache-Control", "no-store"); next(); }
  ];
  const writeGuard = (req, res, next) => (writeLimit(req.user.uid) ? next() : deny(res, 429, "Çok fazla yönetici işlemi. Biraz bekleyin."));
  const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { const code = e.status || (e.code && String(e.code).startsWith("auth/") ? 400 : 500); if (code >= 500) metrics.recordError({ source: "admin", status: code, path: req.path, message: e && e.message }); deny(res, code, code >= 500 ? "Sunucu hatası" : scrub(e.message)); } };

  const safeDetail = (d) => { try { const s = scrub(JSON.stringify(d || {})); return JSON.parse(s); } catch { return { note: scrub(JSON.stringify(d || {})).slice(0, 200) }; } };
  async function auditSafe(req, action, target, detail) {
    const rec = { at: now(), adminUid: req.user.uid, adminEmail: req.user.email || null, action, target: target ? String(target).slice(0, 200) : null, detail: safeDetail(detail), ip: req.ip || null };
    try { if (db) await db.collection("adminAudit").doc().set(rec); } catch (e) { metrics.recordError({ source: "audit", message: e.message }); }
  }

  /* ---------- Kullanıcı verileri (Firebase Authentication) ---------- */
  const pubUser = (u) => ({ uid: u.uid, email: u.email || null, displayName: u.displayName || null, disabled: !!u.disabled, emailVerified: !!u.emailVerified, providers: (u.providerData || []).map((p) => p.providerId), createdAt: u.metadata && u.metadata.creationTime || null, lastSignInAt: u.metadata && u.metadata.lastSignInTime || null });
  let userStatsCache = { at: 0, val: null };
  async function userStats(force) {
    if (!authOk()) return unavailable("Firebase Admin yapılandırılmamış");
    if (!force && userStatsCache.val && now() - userStatsCache.at < 60000) return userStatsCache.val;
    const CAP = SEC.int(process.env.ADMIN_USER_SCAN_CAP, 20000); let total = 0, disabled = 0, active30 = 0, unverified = 0, token, truncated = false; const cut = now() - 30 * 864e5;
    do {
      const page = await admin.auth().listUsers(1000, token);
      for (const u of page.users) { total++; if (u.disabled) disabled++; if (!u.emailVerified) unverified++; const ls = u.metadata && u.metadata.lastSignInTime ? Date.parse(u.metadata.lastSignInTime) : 0; if (ls >= cut) active30++; }
      token = page.pageToken; if (total >= CAP && token) { truncated = true; break; }
    } while (token);
    const val = { available: true, total, active: total - disabled, disabled, activeLast30Days: active30, emailUnverified: unverified, truncated, countedAt: new Date().toISOString() };
    userStatsCache = { at: now(), val }; return val;
  }
  const countOf = async (q) => { try { return (await q.count().get()).data().count; } catch (e) { return null; } };

  /* ---------- Uçlar ---------- */
  // Normal kullanıcı için güvenli rol sorgusu (menüyü göstermek için). Yetkisiz kullanıcıya hiçbir ayrıntı vermez.
  app.get("/api/me/admin", [(req, res, next) => (ipLimit(req.ip) ? next() : deny(res, 429, "Çok fazla istek.")), authn], wrap(async (req, res) => { res.set("Cache-Control", "no-store"); const r = await roleOf(req.user); res.json({ success: true, admin: r.admin }); }));

  app.get("/api/admin/me", guard, wrap(async (req, res) => res.json({ success: true, admin: true, uid: req.user.uid, email: req.user.email, source: req.admin.source })));

  app.get("/api/admin/overview", guard, wrap(async (req, res) => {
    const snap = metrics.snapshot();
    const [users, assetsTotal, checksTotal, checks24h, completed, partial, failed, timeout, jobStats, recentJobs] = await Promise.all([
      userStats().catch((e) => unavailable("Kullanıcı listesi alınamadı: " + scrub(e.message))),
      db ? countOf(db.collection("assets")) : null,
      db ? countOf(db.collection("assetChecks")) : null,
      db ? countOf(db.collection("assetChecks").where("checkedAt", ">=", new Date(now() - 864e5))) : null,
      db ? countOf(db.collection("assetChecks").where("scanStatus", "==", "COMPLETED")) : null,
      db ? countOf(db.collection("assetChecks").where("scanStatus", "==", "PARTIAL")) : null,
      db ? countOf(db.collection("assetChecks").where("scanStatus", "==", "FAILED")) : null,
      db ? countOf(db.collection("assetChecks").where("scanStatus", "==", "TIMEOUT")) : null,
      jobs.stats().catch(() => null), jobs.listAllJobs(200).catch(() => [])
    ]);
    const q = { pending: 0, running: 0, items: { PENDING: 0, RETRYING: 0, RUNNING: 0, COMPLETED: 0, PARTIAL: 0, FAILED: 0, CANCELED: 0 } };
    for (const j of recentJobs) for (const k of Object.keys(q.items)) q.items[k] += (j.counts && j.counts[k]) || 0;
    q.pending = q.items.PENDING + q.items.RETRYING; q.running = q.items.RUNNING;
    const n = (v, why) => (v == null ? unavailable(why || "Firestore bağlı değil veya sayım başarısız") : { available: true, value: v });
    res.json({ success: true, generatedAt: new Date().toISOString(),
      users, assets: n(assetsTotal),
      scans: { total: n(checksTotal), last24h: n(checks24h), completed: n(completed), partial: n(partial), failed: n(failed), timedOut: n(timeout), note: "Kalıcı sayımlar Firestore assetChecks koleksiyonundandır." },
      queue: { ...q, recentJobsConsidered: recentJobs.length, engine: jobStats },
      api: { ...snap.api, windowMinutes: snap.windowMinutes, volatile: true, sinceBoot: snap.sinceBoot },
      timings: snap.series, health: await getHealth(), recentErrors: metrics.recentErrors(10) });
  }));

  app.get("/api/admin/health", guard, wrap(async (req, res) => res.json({ success: true, health: await getHealth(), jobs: await jobs.stats().catch(() => null) })));
  app.get("/api/admin/errors", guard, wrap(async (req, res) => res.json({ success: true, volatile: true, errors: metrics.recentErrors(Math.min(200, +req.query.limit || 100)) })));

  app.get("/api/admin/users", guard, wrap(async (req, res) => {
    if (!authOk()) return deny(res, 503, "Firebase Admin yapılandırılmamış");
    const q = String(req.query.q || "").trim().toLowerCase().slice(0, 100), status = ["active", "disabled"].includes(req.query.status) ? req.query.status : "all";
    const limit = Math.min(100, Math.max(1, +req.query.limit || 50)); let out = [], token = req.query.pageToken ? String(req.query.pageToken).slice(0, 4000) : undefined, next = null, scanned = 0;
    const CAP = SEC.int(process.env.ADMIN_USER_SCAN_CAP, 20000);
    if (q && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(q)) { try { out = [pubUser(await admin.auth().getUserByEmail(q))]; } catch { out = []; } }
    else do {
      const page = await admin.auth().listUsers(1000, token); scanned += page.users.length;
      for (const u of page.users) { const p = pubUser(u); if (status === "active" && p.disabled) continue; if (status === "disabled" && !p.disabled) continue; if (q && !(`${p.email || ""} ${p.displayName || ""} ${p.uid}`.toLowerCase().includes(q))) continue; out.push(p); }
      token = page.pageToken;
      if (out.length >= limit) { next = token || null; break; }
    } while (token && scanned < CAP);
    out = out.slice(0, limit);
    const counts = await Promise.all(out.map((u) => (db ? countOf(db.collection("assets").where("ownerId", "==", u.uid)) : null)));
    out.forEach((u, i) => (u.assetCount = counts[i]));
    res.json({ success: true, users: out, nextPageToken: next, scanned, filtered: !!q || status !== "all" });
  }));

  app.get("/api/admin/users/:uid", guard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (!authOk()) return deny(res, 503, "Firebase Admin yapılandırılmamış");
    let u; try { u = await admin.auth().getUser(uid); } catch { return deny(res, 404, "Kullanıcı bulunamadı"); }
    let byType = null, assetCount = null, plan = null, userJobs = [];
    if (db) {
      try { const snap = await db.collection("assets").where("ownerId", "==", uid).limit(2000).get(); byType = {}; snap.docs.forEach((d) => { const t = d.data().assetType || d.data().type || "?"; byType[t] = (byType[t] || 0) + 1; }); assetCount = snap.size; } catch { /* sayılamadı */ }
      if (getEntitlement) { try { const e = await getEntitlement(uid); plan = { plan: e.plan, status: e.status, periodEnd: e.periodEnd || null, trialEnd: e.trialEnd || null }; } catch { /* paket okunamadı */ } }
    }
    try { userJobs = (await jobs.listJobs(uid, 10)).map((j) => ({ id: j.id, label: j.label, status: j.status, total: j.total, counts: j.counts, createdAt: j.createdAt })); } catch { /* */ }
    const r = await roleOf({ uid, email: u.email, emailVerified: u.emailVerified });
    res.json({ success: true, user: { ...pubUser(u), isAdmin: r.admin }, assets: { available: assetCount != null, count: assetCount, byType }, plan, jobs: userJobs });
  }));

  app.post("/api/admin/users/:uid/disable", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (typeof (req.body || {}).disabled !== "boolean") return deny(res, 400, "disabled (true/false) gerekli");
    if (uid === req.user.uid) return deny(res, 400, "Kendi hesabınızı devre dışı bırakamazsınız.");
    if (!authOk()) return deny(res, 503, "Firebase Admin yapılandırılmamış");
    let u; try { u = await admin.auth().getUser(uid); } catch { return deny(res, 404, "Kullanıcı bulunamadı"); }
    if ((await roleOf({ uid, email: u.email, emailVerified: u.emailVerified })).admin && req.body.disabled) return deny(res, 400, "Yönetici hesabı devre dışı bırakılamaz; önce yönetici yetkisini kaldırın.");
    await admin.auth().updateUser(uid, { disabled: req.body.disabled });
    if (req.body.disabled) await admin.auth().revokeRefreshTokens(uid).catch(() => {});
    userStatsCache = { at: 0, val: null };
    await auditSafe(req, req.body.disabled ? "user.disable" : "user.enable", uid, { email: u.email });
    res.json({ success: true, uid, disabled: req.body.disabled });
  }));

  /* ---------- Yetkili hesap yönetimi ---------- */
  app.get("/api/admin/admins", guard, wrap(async (req, res) => {
    const rows = [...envUids()].map((uid) => ({ uid, source: "env-uid", removable: false })).concat([...envEmails()].map((email) => ({ email, source: "env-email", removable: false })));
    if (db) { try { (await db.collection("adminRoles").limit(200).get()).docs.forEach((d) => rows.push({ uid: d.id, email: d.data().email || null, source: "firestore", grantedBy: d.data().grantedBy || null, grantedAt: d.data().grantedAt || null, removable: true })); } catch { /* */ } }
    res.json({ success: true, admins: rows, note: "env-* kayıtları Render ortam değişkenlerinden gelir; panelden silinemez." });
  }));
  app.post("/api/admin/admins", guard, writeGuard, wrap(async (req, res) => {
    if (!db || !authOk()) return deny(res, 503, "Firebase yapılandırılmamış");
    const email = String((req.body || {}).email || "").trim().toLowerCase(); if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 200) return deny(res, 400, "Geçerli bir e-posta girin");
    let u; try { u = await admin.auth().getUserByEmail(email); } catch { return deny(res, 404, "Bu e-postayla kayıtlı kullanıcı yok (önce kullanıcı DAC'a giriş yapmış olmalı)."); }
    if (!u.emailVerified) return deny(res, 400, "Kullanıcının e-postası doğrulanmamış; yönetici yapılamaz.");
    if (u.disabled) return deny(res, 400, "Devre dışı hesap yönetici yapılamaz.");
    await db.collection("adminRoles").doc(u.uid).set({ role: "admin", email: u.email, grantedBy: req.user.uid, grantedAt: now() }); roleCache.delete(u.uid);
    await auditSafe(req, "admin.grant", u.uid, { email: u.email }); res.json({ success: true, uid: u.uid, email: u.email });
  }));
  app.delete("/api/admin/admins/:uid", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (uid === req.user.uid) return deny(res, 400, "Kendi yönetici yetkinizi kaldıramazsınız.");
    if (envUids().has(uid)) return deny(res, 400, "Bu yönetici ortam değişkeniyle tanımlı; Render'dan kaldırın.");
    const s = await db.collection("adminRoles").doc(uid).get(); if (!s.exists) return deny(res, 404, "Yönetici kaydı bulunamadı");
    await db.collection("adminRoles").doc(uid).delete(); roleCache.delete(uid); await auditSafe(req, "admin.revoke", uid, {}); res.json({ success: true });
  }));

  /* ---------- Tarama kuyruğu izleme ---------- */
  app.get("/api/admin/jobs", guard, wrap(async (req, res) => {
    const rows = await jobs.listAllJobs(Math.min(200, +req.query.limit || 100)); const st = String(req.query.status || "").toUpperCase();
    res.json({ success: true, engine: await jobs.stats(), jobs: rows.filter((j) => !st || j.status === st).map((j) => ({ id: j.id, ownerId: j.ownerId, label: j.label, status: j.status, total: j.total, counts: j.counts, createdAt: j.createdAt, startedAt: j.startedAt, finishedAt: j.finishedAt, persistent: j.persistent })) });
  }));
  app.get("/api/admin/jobs/:id/items", guard, wrap(async (req, res) => res.json({ success: true, ...(await jobs.queryItems(String(req.params.id), null, req.query, true)) })));
  app.post("/api/admin/jobs/:id/retry", guard, writeGuard, wrap(async (req, res) => { const r = await jobs.retryItems(String(req.params.id), null, { admin: true, limit: 500 }); await auditSafe(req, "job.retry", req.params.id, r); res.json({ success: true, ...r }); }));
  app.post("/api/admin/jobs/:id/cancel", guard, writeGuard, wrap(async (req, res) => { const r = await jobs.cancelJob(String(req.params.id), null, true); await auditSafe(req, "job.cancel", req.params.id, { canceled: r.canceled }); res.json({ success: true, canceled: r.canceled }); }));

  app.get("/api/admin/audit", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", entries: [] });
    const snap = await db.collection("adminAudit").orderBy("at", "desc").limit(Math.min(200, +req.query.limit || 100)).get();
    res.json({ success: true, available: true, entries: snap.docs.map((d) => ({ id: d.id, ...d.data() })) });
  }));

  // AI / para birimi / affiliate altyapı durumu (hepsi şimdilik devre dışı; gerçek veri yoksa uydurulmaz)
  app.get("/api/admin/platform", guard, wrap(async (req, res) => res.json({ success: true, ...(await platform()) })));

  return { roleOf, audit: auditSafe, userStats };
};
