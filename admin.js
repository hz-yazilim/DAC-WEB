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
const PLANS = (() => { try { return require("../public/js/plans"); } catch (e) { return require("./plans"); } })(); // klasörlü (public/js) veya düz yerleşim

module.exports = function createAdmin({ app, db, admin, verifyUser, SEC, metrics, jobs, getHealth, platform, getEntitlement = null, commerce = null, payments = null, userState = null, ops = null, mailer = null, now = Date.now }) {
  if (!commerce) commerce = require("./commerce")({ db, PLANS, now }); // dışarıdan verilmezse (testler) yerel örnek
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
  const TOTP = require("./totp"); const tfa = { tokens: TOTP.createTokens(process.env.ADMIN_2FA_SECRET || require("crypto").randomBytes(32).toString("hex"), now) };
  const tfaEnrolled = async (uid) => { if (!db) return false; try { const t = await db.collection("adminTotp").doc(uid).get(); return !!(t.exists && t.data().enabled); } catch { return false; } };
  const guard = [
    (req, res, next) => (ipLimit(req.ip) ? next() : deny(res, 429, "Çok fazla istek.")),
    authn,
    (req, res, next) => (userLimit(req.user.uid) ? next() : deny(res, 429, "Çok fazla istek.")),
    async (req, res, next) => { const r = await roleOf(req.user); if (!r.admin) return deny(res, 403, "Bu işlem için yönetici yetkisi gerekir.", { code: "ADMIN_REQUIRED" }); req.admin = r; res.set("Cache-Control", "no-store");
      // /api/admin/badges yalnızca sayaç döndürür (arka plan yoklaması 2FA penceresi açamaz); yönetici rolü yine zorunludur.
      // ADMIN_REQUIRE_2FA=true: 2FA uçları dışında tüm yönetici uçları doğrulanmış jeton ister (jeton oturum başına kod girilerek alınır)
      if (process.env.ADMIN_REQUIRE_2FA === "true" && !req.path.startsWith("/api/admin/2fa/") && req.path !== "/api/admin/badges" && !tfa.tokens.check(req.user.uid, req.headers["x-admin-2fa"])) { const en = await tfaEnrolled(req.user.uid); return deny(res, 403, en ? "İki adımlı doğrulama kodu gerekli." : "Yönetici hesabı için iki adımlı doğrulamayı kurmalısınız (Yönetici Paneli > Güvenlik).", { code: en ? "2FA_REQUIRED" : "2FA_SETUP" }); }
      next(); }
  ];
  const writeGuard = (req, res, next) => (writeLimit(req.user.uid) ? next() : deny(res, 429, "Çok fazla yönetici işlemi. Biraz bekleyin."));
  const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { const code = e.status || (e.code && String(e.code).startsWith("auth/") ? 400 : 500); if (code >= 500) metrics.recordError({ source: "admin", status: code, path: req.path, message: e && e.message }); deny(res, code, code >= 500 ? "Sunucu hatası" : scrub(e.message), e.code === "LARGE_CHANGE" ? { code: "LARGE_CHANGE", large: e.large } : {}); } };

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

  /* ---------- Paket / abonelik yardımcıları ---------- */
  const PAID = PLANS.PAID || ["freelance", "kobi", "enterprise"];
  const planName = (id) => (PLANS.PLANS[id] && PLANS.PLANS[id].name) || id || "-";
  const ts = (v) => (v && typeof v.toMillis === "function" ? v.toMillis() : typeof v === "number" ? v : null);
  // subscriptions/{uid} belgesinden okunabilir paket özeti (yazma yapmaz)
  function planInfo(sub) {
    if (!sub) return { plan: "free", planName: "Ücretsiz", active: false, status: "none", free: false, provider: null, periodEnd: null };
    const pe = ts(sub.periodEnd); const active = PAID.includes(sub.plan) && sub.status === "active" && (!pe || pe > now());
    return { plan: active ? sub.plan : "free", planName: active ? planName(sub.plan) : "Ücretsiz", lastPlan: sub.plan || null, lastPlanName: sub.plan ? planName(sub.plan) : null,
      active, status: sub.status || "none", free: !!sub.free || sub.provider === "manual" || sub.provider === "admin", provider: sub.provider || null, currency: sub.currency || null, cycle: sub.cycle || null, periodEnd: pe, cancelAtPeriodEnd: active && sub.cancelAtPeriodEnd === true, updatedAt: ts(sub.updatedAt) };
  }
  async function subOf(uid) { if (!db) return null; try { const d = await db.collection("subscriptions").doc(uid).get(); return d.exists === false ? null : (d.data() || null); } catch { return null; } }
  async function emailsOf(uids) {
    const map = {}; if (!authOk() || !uids.length) return map; const u = [...new Set(uids)];
    for (let i = 0; i < u.length; i += 100) {
      const chunk = u.slice(i, i + 100);
      try { const r = await admin.auth().getUsers(chunk.map((uid) => ({ uid }))); (r.users || []).forEach((x) => { map[x.uid] = x.email || x.displayName || null; }); }
      catch { await Promise.all(chunk.map(async (uid) => { try { const x = await admin.auth().getUser(uid); map[uid] = x.email || null; } catch { /* kullanıcı silinmiş olabilir */ } })); }
    }
    return map;
  }
  const orderView = (id, o, emails) => ({ id, uid: o.uid, email: (emails && emails[o.uid]) || null, plan: o.plan, planName: planName(o.plan), cycle: o.cycle || null, currency: o.currency || null, amount: o.amount == null ? null : o.amount, status: o.status || null,
    provider: o.status === "activated-free" ? "manual" : (o.currency === "USD" ? "stripe" : "iyzico"), createdAt: ts(o.createdAt), paidAt: ts(o.paidAt), gatewayStatus: o.gatewayStatus || null, invoiceNo: (o.invoice && o.invoice.no) || null, refundedAmount: o.refundedAmount || 0, couponCode: o.couponCode || null, listAmount: o.listAmount == null ? null : o.listAmount, discount: o.discount == null ? null : o.discount });

  /* ---------- Uçlar ---------- */
  // Normal kullanıcı için güvenli rol sorgusu (menüyü göstermek için). Yetkisiz kullanıcıya hiçbir ayrıntı vermez.
  app.get("/api/me/admin", [(req, res, next) => (ipLimit(req.ip) ? next() : deny(res, 429, "Çok fazla istek.")), authn], wrap(async (req, res) => { res.set("Cache-Control", "no-store"); const r = await roleOf(req.user); res.json({ success: true, admin: r.admin, you: { uid: req.user.uid, email: req.user.email || null, emailVerified: req.user.emailVerified === true }, configured: { uids: envUids().size, emails: envEmails().size } }); }));

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

  /* Menü rozetleri: destek (bekleyen), yeni kullanıcı / sipariş / hata (istemcinin son baktığı zamandan beri). Hafif; arka planda yoklanır. */
  let createdCache = { at: 0, val: [] };
  async function userCreations() {
    if (!authOk()) return [];
    if (now() - createdCache.at < SEC.int(process.env.ADMIN_BADGE_CACHE_MS, 10000)) return createdCache.val;
    const CAP = SEC.int(process.env.ADMIN_USER_SCAN_CAP, 20000), arr = []; let token;
    do { const page = await admin.auth().listUsers(1000, token); for (const u of page.users) { const t = u.metadata && u.metadata.creationTime ? Date.parse(u.metadata.creationTime) : 0; if (t) arr.push(t); } token = page.pageToken; if (arr.length >= CAP && token) break; } while (token);
    createdCache = { at: now(), val: arr }; return arr;
  }
  app.get("/api/admin/badges", guard, wrap(async (req, res) => {
    const since = (k) => { const v = Number(req.query[k]); return Number.isFinite(v) && v > 0 ? v : now(); }; // süre verilmezse "şimdi": eskiler yeni sayılmaz
    const su = since("users"), so = since("orders"), se = since("errors"), out = { success: true, serverTime: now(), support: 0, users: 0, orders: 0, errors: 0 };
    if (db) {
      out.support = (await countOf(db.collection("supportTickets").where("status", "==", "open"))) || 0;
      try { const snap = await db.collection("orders").orderBy("createdAt", "desc").limit(100).get(); out.orders = snap.docs.filter((d) => { const o = d.data(); return o.status === "paid" && (ts(o.paidAt) || ts(o.createdAt) || 0) > so; }).length; } catch { /* sayılamadı */ }
    }
    try { out.users = (await userCreations()).filter((t) => t > su).length; } catch { /* kullanıcı listesi alınamadı */ }
    try { out.errors = metrics.recentErrors(200).filter((e) => Date.parse(e.at) > se).length; } catch { /* hata kaydı yok */ }
    res.json(out);
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
    const subs = await Promise.all(out.map((u) => subOf(u.uid))); out.forEach((u, i) => { u.plan = planInfo(subs[i]); });
    res.json({ success: true, users: out, nextPageToken: next, scanned, filtered: !!q || status !== "all" });
  }));

  app.get("/api/admin/users/:uid", guard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (!authOk()) return deny(res, 503, "Firebase Admin yapılandırılmamış");
    let u; try { u = await admin.auth().getUser(uid); } catch { return deny(res, 404, "Kullanıcı bulunamadı"); }
    let byType = null, assetCount = null, plan = null, userJobs = [], subscription = null, orders = [], trial = null;
    if (db) {
      try { const snap = await db.collection("assets").where("ownerId", "==", uid).limit(2000).get(); byType = {}; snap.docs.forEach((d) => { const t = d.data().assetType || d.data().type || "?"; byType[t] = (byType[t] || 0) + 1; }); assetCount = snap.size; } catch { /* sayılamadı */ }
      if (getEntitlement) { try { const e = await getEntitlement(uid); plan = { plan: e.plan, status: e.status, periodEnd: e.periodEnd || null, trialEnd: e.trialEnd || null }; } catch { /* paket okunamadı */ } }
    }
    try { userJobs = (await jobs.listJobs(uid, 10)).map((j) => ({ id: j.id, label: j.label, status: j.status, total: j.total, counts: j.counts, createdAt: j.createdAt })); } catch { /* */ }
    const r = await roleOf({ uid, email: u.email, emailVerified: u.emailVerified });
    if (db) {
      subscription = planInfo(await subOf(uid));
      try { const os = await db.collection("orders").where("uid", "==", uid).limit(50).get(); orders = os.docs.map((d) => orderView(d.id, d.data(), { [uid]: u.email })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 20); } catch { /* sipariş okunamadı */ }
    }
    let note = null; if (db) { try { const n = await db.collection("adminNotes").doc(uid).get(); if (n.exists) note = { text: n.data().text || "", by: n.data().byEmail || n.data().by || null, at: n.data().at || null }; } catch { /* not okunamadı */ } }
    res.json({ success: true, user: { ...pubUser(u), isAdmin: r.admin }, assets: { available: assetCount != null, count: assetCount, byType }, plan, subscription, orders, jobs: userJobs, note });
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

  /* ---------- Abonelikler ve siparişler (kim hangi paketi almış / kim ücretsiz) ---------- */
  app.get("/api/admin/subscriptions", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", rows: [], summary: null });
    const f = String(req.query.plan || "all"), q = String(req.query.q || "").trim().toLowerCase().slice(0, 100);
    const snap = await db.collection("subscriptions").limit(Math.min(5000, SEC.int(process.env.ADMIN_SUB_CAP, 2000))).get();
    const all = snap.docs.map((d) => ({ uid: d.id, ...planInfo(d.data()) }));
    const emails = await emailsOf(all.map((x) => x.uid)); all.forEach((x) => { x.email = emails[x.uid] || null; });
    const sum = { byPlan: {}, paidActive: 0, grantedFree: 0, expiredOrCanceled: 0, total: all.length };
    for (const x of all) { if (x.active) { sum.byPlan[x.plan] = (sum.byPlan[x.plan] || 0) + 1; sum.paidActive++; if (x.free) sum.grantedFree++; } else sum.expiredOrCanceled++; }
    const us = await userStats().catch(() => null); const totalUsers = us && us.available ? us.total : null;
    sum.totalUsers = totalUsers; sum.freeUsers = totalUsers == null ? null : Math.max(0, totalUsers - sum.paidActive);
    let rows = all;
    if (PAID.includes(f)) rows = rows.filter((x) => x.active && x.plan === f); else if (f === "granted") rows = rows.filter((x) => x.active && x.free); else if (f === "expired") rows = rows.filter((x) => !x.active);
    if (q) rows = rows.filter((x) => `${x.email || ""} ${x.uid}`.toLowerCase().includes(q));
    rows.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    res.json({ success: true, available: true, summary: sum, rows: rows.slice(0, 300), truncated: rows.length > 300, note: "Ücretsiz = aktif ücretli paketi olmayan (deneme/süresi dolmuş) kullanıcılar. 'Ödemesiz verildi' = ödeme sağlayıcısı olmadan etkinleştirilen veya yönetici tarafından verilen paket." });
  }));
  app.get("/api/admin/orders", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", orders: [] });
    const st = String(req.query.status || "").trim();
    const snap = await db.collection("orders").orderBy("createdAt", "desc").limit(Math.min(300, +req.query.limit || 100)).get();
    let rows = snap.docs.map((d) => ({ id: d.id, ...d.data() })); if (st) rows = rows.filter((o) => o.status === st);
    const emails = await emailsOf(rows.map((o) => o.uid));
    res.json({ success: true, available: true, orders: rows.map((o) => orderView(o.id, o, emails)) });
  }));

  /* ---------- Müdahale: paket ver / kaldır, deneme süresi uzat ---------- */
  const uidOk = (uid) => /^[A-Za-z0-9_-]{1,128}$/.test(uid);
  app.post("/api/admin/users/:uid/plan", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!uidOk(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (!db || !authOk()) return deny(res, 503, "Firebase yapılandırılmamış");
    const b = req.body || {}, plan = String(b.plan || ""), days = Math.floor(+b.days || 30);
    if (!PAID.includes(plan)) return deny(res, 400, "Geçerli bir paket seçin: " + PAID.join(", "));
    if (!(days >= 1 && days <= 3660)) return deny(res, 400, "Gün sayısı 1-3660 arasında olmalı");
    try { await admin.auth().getUser(uid); } catch { return deny(res, 404, "Kullanıcı bulunamadı"); }
    const prev = await subOf(uid);
    if (prev && prev.provider && ["stripe", "iyzico"].includes(prev.provider) && prev.status === "active" && ts(prev.periodEnd) > now()) return deny(res, 409, "Kullanıcının ödeme sağlayıcısıyla aktif aboneliği var; üzerine yazılmadı.");
    const periodEnd = now() + days * 864e5;
    await db.collection("subscriptions").doc(uid).set({ plan, status: "active", provider: "admin", free: true, cancelAtPeriodEnd: false, cycle: days >= 365 ? "yearly" : "monthly", periodEnd, grantedBy: req.user.uid, updatedAt: now() }, { merge: true });
    await auditSafe(req, "plan.grant", uid, { plan, days, previous: prev ? prev.plan || null : null });
    res.json({ success: true, uid, plan, periodEnd });
  }));
  app.post("/api/admin/users/:uid/plan/revoke", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!uidOk(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (!db) return deny(res, 503, "Firestore bağlı değil");
    const prev = await subOf(uid); if (!prev) return deny(res, 404, "Bu kullanıcının aboneliği yok");
    if (prev.provider === "stripe" || prev.provider === "iyzico") return deny(res, 409, "Ödeme sağlayıcılı abonelik buradan iptal edilmez; sağlayıcı panelinden iptal edin.");
    await db.collection("subscriptions").doc(uid).set({ status: "canceled", periodEnd: now(), revokedBy: req.user.uid, updatedAt: now() }, { merge: true });
    await auditSafe(req, "plan.revoke", uid, { plan: prev.plan || null });
    res.json({ success: true, uid });
  }));
  app.post("/api/admin/users/:uid/trial", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!uidOk(uid)) return deny(res, 400, "Geçersiz kullanıcı kimliği");
    if (!db || !authOk()) return deny(res, 503, "Firebase yapılandırılmamış");
    const days = Math.floor(+(req.body || {}).days || 0); if (!(days >= 1 && days <= 90)) return deny(res, 400, "Gün sayısı 1-90 arasında olmalı");
    try { await admin.auth().getUser(uid); } catch { return deny(res, 404, "Kullanıcı bulunamadı"); }
    const trialStart = now() - (PLANS.TRIAL_DAYS - days) * 864e5; // deneme bitişi = şimdi + days
    await db.collection("users").doc(uid).set({ trialStart }, { merge: true });
    await auditSafe(req, "trial.extend", uid, { days });
    res.json({ success: true, uid, trialEnd: now() + days * 864e5 });
  }));


  /* ---------- Fiyatlandırma ve paket limitleri (Ödemeler > Fiyatlar) ---------- */
  app.get("/api/admin/pricing", guard, wrap(async (req, res) => {
    await commerce.ensureFresh(0);
    const view = commerce.adminPricingView(); let subscribers = null;
    if (db) { try { const snap = await db.collection("subscriptions").limit(5000).get(); subscribers = {}; for (const d of snap.docs) { const i = planInfo(d.data()); if (i.active) subscribers[i.plan] = (subscribers[i.plan] || 0) + 1; } } catch { subscribers = null; } }
    res.json({ success: true, ...view, subscribers, history: await commerce.pricingHistory(30).catch(() => []), persistent: !!db,
      notes: ["Yeni fiyat yeni satın alımlarda ve yenilemelerde anında geçerlidir; mevcut Stripe aboneliklerinin fiyatı değişmez (Stripe'ta abonelik oluşturulurken sabitlenir).", "iyzico (TL) ödemeleri tek seferliktir; bir sonraki satın almada yeni fiyat uygulanır.", "Limit değişiklikleri (varlık/ekip/geçmiş) mevcut tüm kullanıcılar için anında uygulanır."] });
  }));
  app.post("/api/admin/pricing", guard, writeGuard, wrap(async (req, res) => {
    const r = await commerce.savePricing(req.body || {}, req.user);
    await auditSafe(req, "pricing.update", null, { changes: r.changes, forced: (req.body || {}).force === true });
    res.json({ success: true, changes: r.changes, public: r.public, ...{ current: commerce.currentState() } });
  }));
  app.post("/api/admin/pricing/reset", guard, writeGuard, wrap(async (req, res) => {
    const r = await commerce.resetPricing(req.user); await auditSafe(req, "pricing.reset", null, {}); res.json({ success: true, public: r.public, current: commerce.currentState() });
  }));

  /* ---------- Kuponlar ---------- */
  app.get("/api/admin/coupons", guard, wrap(async (req, res) => { if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", coupons: [] }); res.json({ success: true, available: true, coupons: await commerce.listCoupons(200), plans: PAID }); }));
  app.post("/api/admin/coupons", guard, writeGuard, wrap(async (req, res) => { const c = await commerce.createCoupon(req.body || {}, req.user); await auditSafe(req, "coupon.create", c.code, { type: c.type, value: c.value, currency: c.currency, plans: c.plans, maxUses: c.maxUses }); res.json({ success: true, coupon: c }); }));
  app.post("/api/admin/coupons/:code/active", guard, writeGuard, wrap(async (req, res) => { if (typeof (req.body || {}).active !== "boolean") return deny(res, 400, "active (true/false) gerekli"); const r = await commerce.setCouponActive(req.params.code, req.body.active); await auditSafe(req, req.body.active ? "coupon.enable" : "coupon.disable", r.code, {}); res.json({ success: true, ...r }); }));
  app.delete("/api/admin/coupons/:code", guard, writeGuard, wrap(async (req, res) => { const r = await commerce.deleteCoupon(req.params.code); await auditSafe(req, "coupon.delete", r.code, {}); res.json({ success: true, ...r }); }));

  /* ---------- Gelir özeti (siparişler + abonelikler) ---------- */
  app.get("/api/admin/revenue", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil" });
    await commerce.ensureFresh(0);
    const cap = Math.min(5000, SEC.int(process.env.ADMIN_ORDER_CAP, 2000)), t = now();
    const osnap = await db.collection("orders").orderBy("createdAt", "desc").limit(cap).get();
    const orders = osnap.docs.map((d) => ({ id: d.id, ...d.data() }));
    const sumBy = (arr, f = (o) => Number(o.amount || 0) - Number(o.refundedAmount || 0)) => { const m = {}; for (const o of arr) { const c = o.currency || "TRY"; m[c] = Math.round(((m[c] || 0) + f(o)) * 100) / 100; } return m; };
    const paid = orders.filter((o) => o.status === "paid"); const paidAt = (o) => ts(o.paidAt) || ts(o.createdAt) || 0;
    const in30 = paid.filter((o) => paidAt(o) >= t - 30 * 864e5), in7 = paid.filter((o) => paidAt(o) >= t - 7 * 864e5);
    const byPlan = {}; for (const o of paid) { const k = o.plan || "?"; byPlan[k] = byPlan[k] || { count: 0, totals: {} }; byPlan[k].count++; byPlan[k].totals[o.currency || "TRY"] = Math.round(((byPlan[k].totals[o.currency || "TRY"] || 0) + Number(o.amount || 0)) * 100) / 100; }
    const daily = {}; for (const o of in30) { const day = new Date(paidAt(o)).toISOString().slice(0, 10); daily[day] = daily[day] || {}; daily[day][o.currency || "TRY"] = Math.round(((daily[day][o.currency || "TRY"] || 0) + Number(o.amount || 0)) * 100) / 100; }
    const withCoupon = paid.filter((o) => o.couponCode);
    // abonelikler: tahmini aylık gelir (liste fiyatı) ve yakında bitenler
    let mrr = {}, expiring = [], activePaying = 0;
    try {
      const ssnap = await db.collection("subscriptions").limit(Math.min(5000, SEC.int(process.env.ADMIN_SUB_CAP, 2000))).get();
      const subs = ssnap.docs.map((d) => ({ uid: d.id, ...planInfo(d.data()) }));
      for (const x of subs) {
        if (!x.active) continue;
        if (!x.free && ["stripe", "iyzico"].includes(x.provider)) { activePaying++; const cur = x.currency || (x.provider === "stripe" ? "USD" : "TRY"); const p = PLANS.price(x.plan, cur, x.cycle === "yearly" ? "yearly" : "monthly"); if (p != null) mrr[cur] = Math.round(((mrr[cur] || 0) + (x.cycle === "yearly" ? p / 12 : p)) * 100) / 100; }
        if (x.periodEnd && x.periodEnd - t < 7 * 864e5) expiring.push(x);
      }
      expiring.sort((a, b) => a.periodEnd - b.periodEnd); expiring = expiring.slice(0, 50);
      const em = await emailsOf(expiring.map((x) => x.uid)); expiring = expiring.map((x) => ({ uid: x.uid, email: em[x.uid] || null, plan: x.plan, planName: x.planName, provider: x.provider, free: x.free, periodEnd: x.periodEnd }));
    } catch { /* abonelik okunamadı: MRR yok */ }
    res.json({ success: true, available: true, generatedAt: new Date().toISOString(), ordersConsidered: orders.length, truncated: orders.length >= cap,
      paid: { count: paid.length, totals: sumBy(paid), last30d: { count: in30.length, totals: sumBy(in30) }, last7d: { count: in7.length, totals: sumBy(in7) } },
      byPlan, daily: Object.entries(daily).sort(([a], [b]) => (a < b ? -1 : 1)).map(([day, v]) => ({ day, ...v })),
      coupons: { orders: withCoupon.length, discountTotals: sumBy(withCoupon, (o) => Number(o.discount || 0)) },
      freeActivations: orders.filter((o) => o.status === "activated-free").length, refunded: { count: orders.filter((o) => Number(o.refundedAmount) > 0).length, totals: sumBy(orders.filter((o) => Number(o.refundedAmount) > 0), (o) => Number(o.refundedAmount)) }, uninvoiced: paid.filter((o) => !o.invoice).length, failed: orders.filter((o) => o.status === "failed").length,
      stuckPending: orders.filter((o) => o.status === "pending" && t - (ts(o.createdAt) || t) > 2 * 36e5).length,
      mrr: { estimate: mrr, activePayingSubscriptions: activePaying, note: "Liste fiyatı üzerinden tahmindir (kupon/eski fiyatlar yansımaz). Gerçek tahsilat için ödeme sağlayıcısı panelini kullanın." }, expiringSoon: expiring,
      note: "Gelir yalnızca 'paid' siparişlerden hesaplanır. Ödemesiz etkinleştirilenler ve yönetici tarafından verilen paketler gelire sayılmaz." });
  }));

  /* ---------- Duyuru ve bakım modu ---------- */
  app.get("/api/admin/site", guard, wrap(async (req, res) => { res.json({ success: true, persistent: !!db, site: await commerce.getSite(true) }); }));
  app.post("/api/admin/site", guard, writeGuard, wrap(async (req, res) => { const before = await commerce.getSite(true); const site = await commerce.saveSite(req.body || {}, req.user); await auditSafe(req, "site.update", null, { announcement: site.announcement.enabled, maintenance: site.maintenance.enabled, maintenanceChanged: before.maintenance.enabled !== site.maintenance.enabled }); res.json({ success: true, site }); }));

  /* ---------- Kullanıcıya müdahale: oturumları kapat, şifre sıfırlama bağlantısı, e-posta doğrulama, not ---------- */
  const userGuard = async (req, res) => { const uid = String(req.params.uid || ""); if (!uidOk(uid)) { deny(res, 400, "Geçersiz kullanıcı kimliği"); return null; } if (!authOk()) { deny(res, 503, "Firebase Admin yapılandırılmamış"); return null; } try { return { uid, u: await admin.auth().getUser(uid) }; } catch { deny(res, 404, "Kullanıcı bulunamadı"); return null; } };
  app.post("/api/admin/users/:uid/revoke-sessions", guard, writeGuard, wrap(async (req, res) => { const g = await userGuard(req, res); if (!g) return; await admin.auth().revokeRefreshTokens(g.uid); await auditSafe(req, "user.revoke-sessions", g.uid, { email: g.u.email }); res.json({ success: true, uid: g.uid }); }));
  app.post("/api/admin/users/:uid/password-reset", guard, writeGuard, wrap(async (req, res) => {
    const g = await userGuard(req, res); if (!g) return; if (!g.u.email) return deny(res, 400, "Kullanıcının e-postası yok");
    if (!(g.u.providerData || []).some((p) => p.providerId === "password")) return deny(res, 400, "Bu hesap e-posta/şifre ile açılmamış (ör. Google girişi); şifre sıfırlanamaz.");
    const link = await admin.auth().generatePasswordResetLink(g.u.email); await auditSafe(req, "user.password-reset-link", g.uid, { email: g.u.email }); // bağlantı kayda yazılmaz
    res.json({ success: true, uid: g.uid, email: g.u.email, link, note: "Bağlantı tek kullanımlıktır; yalnızca kullanıcıya güvenli bir kanaldan iletin." });
  }));
  app.post("/api/admin/users/:uid/verify-email", guard, writeGuard, wrap(async (req, res) => { const g = await userGuard(req, res); if (!g) return; if (g.u.emailVerified) return deny(res, 400, "E-posta zaten doğrulanmış"); await admin.auth().updateUser(g.uid, { emailVerified: true }); userStatsCache = { at: 0, val: null }; await auditSafe(req, "user.verify-email", g.uid, { email: g.u.email }); res.json({ success: true, uid: g.uid }); }));
  app.post("/api/admin/users/:uid/note", guard, writeGuard, wrap(async (req, res) => {
    const g = await userGuard(req, res); if (!g) return; if (!db) return deny(res, 503, "Firestore bağlı değil");
    const text = String((req.body || {}).text || "").trim(); if (text.length > 1000) return deny(res, 400, "Not en çok 1000 karakter olabilir");
    if (!text) await db.collection("adminNotes").doc(g.uid).delete(); else await db.collection("adminNotes").doc(g.uid).set({ text, by: req.user.uid, byEmail: req.user.email || null, at: now() });
    await auditSafe(req, text ? "user.note" : "user.note-clear", g.uid, { length: text.length }); res.json({ success: true, uid: g.uid });
  }));

  app.get("/api/admin/audit", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", entries: [] });
    const snap = await db.collection("adminAudit").orderBy("at", "desc").limit(Math.min(200, +req.query.limit || 100)).get();
    res.json({ success: true, available: true, entries: snap.docs.map((d) => ({ id: d.id, ...d.data() })) });
  }));

  // AI / para birimi / affiliate altyapı durumu (hepsi şimdilik devre dışı; gerçek veri yoksa uydurulmaz)
  app.get("/api/admin/platform", guard, wrap(async (req, res) => res.json({ success: true, ...(await platform()) })));

  require("./admin-ops")({ app, db, admin, guard, writeGuard, wrap, deny, auditSafe, planInfo, emailsOf, ts, PLANS, PAID, now, roleOf, authOk, tfa, payments, userState, ops, mailer, SEC });
  return { roleOf, audit: auditSafe, userStats, commerce };
};
