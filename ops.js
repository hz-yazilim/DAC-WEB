/* Digital Asset Center - Operasyon (V13.3): kalıcı hata kaydı, 5xx alarmı, Firestore yedeği, yenileme/deneme hatırlatmaları
 * Alarm kanalları (hepsi isteğe bağlı): TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, ALERT_WEBHOOK_URL (Slack/Teams "text" biçimi), ALERT_EMAIL (+ mailer).
 * Yedek: BACKUP_BUCKET (GCS kovası). Hizmet hesabına "Cloud Datastore Import Export Admin" ve kovada "Storage Object Admin" rolü gerekir. */
"use strict";
const crypto = require("crypto");

module.exports = function createOps({ db, admin, http, mailer, metrics, PLANS, now = Date.now, log = () => {} }) {
  const ts = (v) => (v && typeof v.toMillis === "function" ? v.toMillis() : typeof v === "number" ? v : null);
  const hash = (s) => crypto.createHash("sha1").update(String(s)).digest("hex").slice(0, 20);

  /* ---------- Kalıcı hata kaydı (dakikada en çok 30 yazım; aynı hata 60 sn içinde sayaçla birleşir) ---------- */
  const recent = new Map(); let winStart = 0, winCount = 0;
  function persistError(e) {
    if (!db || !e) return;
    const t = now(); if (t - winStart > 60000) { winStart = t; winCount = 0; recent.clear(); }
    const key = hash(`${e.source}|${e.status}|${e.path}|${e.message}`);
    if (recent.has(key)) { recent.set(key, recent.get(key) + 1); return; }
    if (winCount >= 30) return; winCount++; recent.set(key, 1);
    db.collection("errorLog").doc().set({ at: t, source: e.source || "server", status: e.status || null, path: e.path || null, message: String(e.message || "").slice(0, 300) }).catch(() => {});
  }
  async function errorHistory(limit = 100) {
    if (!db) return [];
    const snap = await db.collection("errorLog").orderBy("at", "desc").limit(Math.min(300, limit)).get();
    return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  }

  /* ---------- Alarm gönderimi ---------- */
  const channels = () => ({ telegram: !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID), webhook: !!process.env.ALERT_WEBHOOK_URL, email: !!(process.env.ALERT_EMAIL && mailer && mailer.enabled()) });
  async function notify(text) {
    const used = [], c = channels();
    if (c.telegram) { try { await http.request({ method: "POST", url: `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, data: { chat_id: process.env.TELEGRAM_CHAT_ID, text: text.slice(0, 3500) }, validateStatus: () => true, timeout: 10000 }); used.push("telegram"); } catch (e) { log("telegram: " + e.message); } }
    if (c.webhook) { try { const u = new URL(process.env.ALERT_WEBHOOK_URL); if (u.protocol === "https:") { await http.request({ method: "POST", url: u.href, data: { text: text.slice(0, 3500) }, validateStatus: () => true, timeout: 10000 }); used.push("webhook"); } } catch (e) { log("webhook: " + e.message); } }
    if (c.email) { const m = mailer.tpl.alert({ text }); const r = await mailer.send({ to: process.env.ALERT_EMAIL, ...m, type: "alert" }); if (r.sent) used.push("email"); }
    return used;
  }
  let lastAlert = 0;
  async function checkAlerts() {
    if (!metrics) return { alerted: false };
    const a = metrics.snapshot().api, minReq = +process.env.ALERT_MIN_REQUESTS || 20, thr = +process.env.ALERT_5XX_PERCENT || 10, cool = (+process.env.ALERT_COOLDOWN_MIN || 30) * 60000;
    if (a.requests < minReq || a.errorRate5xx == null || a.errorRate5xx < thr) return { alerted: false, rate: a.errorRate5xx };
    if (now() - lastAlert < cool) return { alerted: false, cooldown: true, rate: a.errorRate5xx };
    lastAlert = now();
    const used = await notify(`⚠️ DAC: son ${Math.round(3600e3 / 60000)} dakikada 5xx hata oranı %${a.errorRate5xx} (${a.requests} istek). Yönetici Paneli > Sistem Hataları'na bakın.`);
    return { alerted: true, channels: used, rate: a.errorRate5xx };
  }

  /* ---------- Firestore yedeği (yönetilen dışa aktarma → GCS) ---------- */
  async function backup(by) {
    const bucket = String(process.env.BACKUP_BUCKET || "").trim(); if (!bucket || !/^[a-z0-9._-]{3,222}$/.test(bucket)) throw Object.assign(new Error("BACKUP_BUCKET tanımlı değil veya geçersiz."), { status: 503 });
    if (!admin || !admin.apps || !admin.apps.length) throw Object.assign(new Error("Firebase Admin yapılandırılmamış"), { status: 503 });
    const app = admin.app(), cred = app.options && app.options.credential; if (!cred || typeof cred.getAccessToken !== "function") throw Object.assign(new Error("Hizmet hesabı kimlik bilgisi alınamadı"), { status: 503 });
    const pid = process.env.FIREBASE_PROJECT_ID || (app.options && app.options.projectId) || cred.projectId; if (!pid) throw Object.assign(new Error("Proje kimliği bulunamadı (FIREBASE_PROJECT_ID)"), { status: 503 });
    const tok = await cred.getAccessToken(); const prefix = `gs://${bucket}/dac-backups/${new Date(now()).toISOString().replace(/[:.]/g, "-")}`;
    const r = await http.request({ method: "POST", url: `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(pid)}/databases/(default):exportDocuments`, headers: { Authorization: "Bearer " + (tok.access_token || tok), "Content-Type": "application/json" }, data: { outputUriPrefix: prefix }, validateStatus: () => true, timeout: 30000 });
    const ok = r.status >= 200 && r.status < 300;
    const rec = { at: now(), by: by || "cron", prefix, status: ok ? "started" : "failed", operation: ok && r.data ? r.data.name || null : null, error: ok ? null : String((r.data && r.data.error && r.data.error.message) || r.status).slice(0, 200) };
    if (db) await db.collection("backups").doc().set(rec).catch(() => {});
    if (!ok) throw Object.assign(new Error("Yedek başlatılamadı: " + rec.error), { status: 502 });
    return rec;
  }
  async function backupHistory(limit = 15) { if (!db) return []; const s = await db.collection("backups").orderBy("at", "desc").limit(limit).get(); return s.docs.map((d) => ({ id: d.id, ...d.data() })); }

  /* ---------- Hatırlatmalar: iyzico/ödemesiz paket bitişi (7/3/1 gün) ve deneme bitişi (son 24 saat) ---------- */
  async function emailsOf(uids) {
    const map = {}; if (!admin || !admin.apps || !admin.apps.length || !uids.length) return map; const u = [...new Set(uids)];
    for (let i = 0; i < u.length; i += 100) { try { const r = await admin.auth().getUsers(u.slice(i, i + 100).map((uid) => ({ uid }))); (r.users || []).forEach((x) => { if (x.email && x.emailVerified) map[x.uid] = { email: x.email, disabled: !!x.disabled }; }); } catch (e) { log("getUsers: " + e.message); } }
    return map;
  }
  async function runReminders() {
    if (!db) return { skipped: "db" }; if (!mailer || !mailer.enabled()) return { skipped: "mail-disabled" };
    const t = now(), PAID = PLANS.PAID, todo = [], activeUids = new Set();
    const subs = (await db.collection("subscriptions").limit(5000).get()).docs;
    for (const d of subs) {
      const s = d.data(); const pe = ts(s.periodEnd); if (!PAID.includes(s.plan) || s.status !== "active" || !pe || pe <= t) continue; activeUids.add(d.id);
      if (s.provider === "stripe") continue; // Stripe aboneliği kendiliğinden yenilenir
      const days = Math.ceil((pe - t) / 864e5); if (days > 7) continue; const level = days <= 1 ? 1 : days <= 3 ? 3 : 7;
      todo.push({ kind: "renew", uid: d.id, plan: s.plan, pe, level, free: !!s.free || s.provider === "admin" || s.provider === "manual" });
    }
    const users = (await db.collection("users").limit(5000).get()).docs;
    for (const d of users) { const u = d.data(); if (!u.trialStart || activeUids.has(d.id) || u.mailOptOut === true) continue; const end = u.trialStart + PLANS.TRIAL_DAYS * 864e5, left = end - t; if (left > 0 && left <= 864e5) todo.push({ kind: "trial", uid: d.id, trialStart: u.trialStart, hoursLeft: Math.max(1, Math.round(left / 36e5)) }); }
    const em = await emailsOf(todo.map((x) => x.uid)); let sent = 0, skipped = 0;
    for (const x of todo) {
      const rcp = em[x.uid]; if (!rcp || rcp.disabled) { skipped++; continue; }
      const m = x.kind === "renew" ? mailer.tpl.reminder({ planName: (PLANS.PLANS[x.plan] || {}).name || x.plan, days: x.level, periodEnd: x.pe, free: x.free }) : mailer.tpl.trialEnding({ hoursLeft: x.hoursLeft });
      const r = await mailer.send({ to: rcp.email, ...m, type: x.kind === "renew" ? "renew-reminder" : "trial-ending", uid: x.uid, dedupeKey: x.kind === "renew" ? `rem_${x.uid}_${x.level}_${x.pe}` : `trial_${x.uid}_${x.trialStart}` });
      if (r.sent) sent++; else skipped++;
    }
    return { candidates: todo.length, sent, skipped };
  }

  async function status() {
    let mails = [], backups = []; try { if (db) mails = (await db.collection("mailLog").orderBy("at", "desc").limit(15).get()).docs.map((d) => ({ id: d.id, ...d.data() })); } catch { /* */ } try { backups = await backupHistory(); } catch { /* */ }
    return { mail: { enabled: mailer ? mailer.enabled() : false, from: process.env.MAIL_FROM ? String(process.env.MAIL_FROM).replace(/<.*@/, "<***@") : null }, alerts: { channels: channels(), thresholdPercent: +process.env.ALERT_5XX_PERCENT || 10, minRequests: +process.env.ALERT_MIN_REQUESTS || 20 }, backup: { configured: !!process.env.BACKUP_BUCKET, recent: backups }, recentMails: mails, captcha: { turnstile: !!process.env.TURNSTILE_SECRET && !!process.env.TURNSTILE_SITE_KEY }, twoFactorRequired: process.env.ADMIN_REQUIRE_2FA === "true" };
  }
  let timer = null;
  const start = () => { timer = setInterval(() => { checkAlerts().catch(() => {}); }, 60000); if (timer.unref) timer.unref(); const h = setInterval(() => { runReminders().catch((e) => log("reminders: " + e.message)); }, 6 * 36e5); if (h.unref) h.unref(); };
  const stop = () => { if (timer) clearInterval(timer); timer = null; };
  return { persistError, errorHistory, notify, checkAlerts, backup, backupHistory, runReminders, status, channels, start, stop };
};
