/* Digital Asset Center - Yönetici panelinin işlem uçları (V13.3): fatura takibi, iade/iptal, toplu işlem, kullanıcı silme,
 * destek talepleri, operasyon (hata geçmişi, yedek, alarm, e-posta, hatırlatma), iki adımlı doğrulama.
 * admin.js tarafından, ortak koruma/denetim yardımcılarıyla çağrılır; her uç guard (IP limiti → kimlik → kullanıcı limiti → yönetici rolü [→ 2FA]) arkasındadır. */
"use strict";
const TOTP = require("./totp");

module.exports = function registerAdminOps(c) {
  const { app, db, admin, guard, writeGuard, wrap, deny, auditSafe, planInfo, emailsOf, ts, PLANS, PAID, now, roleOf, authOk, tfa, payments, userState, ops, mailer, SEC } = c;
  const uidOk = (uid) => /^[A-Za-z0-9_-]{1,128}$/.test(uid);
  const idOk = (id) => /^[A-Za-z0-9_-]{1,100}$/.test(String(id || ""));
  const need = (res, ok, code, msg) => { if (!ok) { deny(res, code, msg); return false; } return true; };

  /* ---------- Fatura takibi (e-arşiv entegrasyonu yok; kesilen fatura no panelden işlenir) ---------- */
  app.get("/api/admin/invoices", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", rows: [] });
    const f = req.query.filter === "done" ? "done" : "pending";
    const snap = await db.collection("orders").orderBy("createdAt", "desc").limit(Math.min(5000, SEC.int(process.env.ADMIN_ORDER_CAP, 2000))).get();
    const all = snap.docs.map((d) => ({ id: d.id, ...d.data() })).filter((o) => o.status === "paid" || o.status === "refunded");
    const pending = all.filter((o) => o.status === "paid" && !o.invoice), done = all.filter((o) => o.invoice);
    const rows = (f === "done" ? done : pending).slice(0, 300); const em = await emailsOf(rows.map((o) => o.uid));
    res.json({ success: true, available: true, filter: f, counts: { pending: pending.length, done: done.length }, rows: rows.map((o) => ({ id: o.id, uid: o.uid, email: em[o.uid] || null, plan: o.plan, planName: (PLANS.PLANS[o.plan] || {}).name || o.plan, cycle: o.cycle, currency: o.currency, amount: o.amount, refundedAmount: o.refundedAmount || 0, paidAt: ts(o.paidAt) || ts(o.createdAt), invoice: o.invoice || null, provider: o.currency === "USD" ? "stripe" : "iyzico" })),
      note: "Fatura kesme işlemi bu sistemde otomatik değildir: faturayı muhasebe/e-arşiv programınızda kesin, numarasını buraya işleyin." });
  }));
  app.post("/api/admin/orders/:id/invoice", guard, writeGuard, wrap(async (req, res) => {
    if (!need(res, idOk(req.params.id), 400, "Geçersiz sipariş")) return; if (!db) return deny(res, 503, "Firestore bağlı değil");
    const no = String((req.body || {}).no || "").trim(), url = String((req.body || {}).url || "").trim();
    if (!/^[\w./ -]{3,40}$/.test(no)) return deny(res, 400, "Fatura numarası 3-40 karakter (harf, rakam, - / . _)");
    if (url) { try { const u = new URL(url); if (u.protocol !== "https:") throw 0; } catch { return deny(res, 400, "Fatura bağlantısı https olmalı"); } }
    const ref = db.collection("orders").doc(req.params.id), s = await ref.get(); if (!s.exists) return deny(res, 404, "Sipariş bulunamadı");
    if (!["paid", "refunded"].includes(s.data().status)) return deny(res, 400, "Yalnızca ödenmiş siparişe fatura işlenir");
    await ref.set({ invoice: { no, url: url || null, by: req.user.email || req.user.uid, at: now() } }, { merge: true }); await auditSafe(req, "invoice.set", req.params.id, { no }); res.json({ success: true });
  }));
  app.delete("/api/admin/orders/:id/invoice", guard, writeGuard, wrap(async (req, res) => {
    if (!need(res, idOk(req.params.id), 400, "Geçersiz sipariş")) return; if (!db) return deny(res, 503, "Firestore bağlı değil");
    const ref = db.collection("orders").doc(req.params.id), s = await ref.get(); if (!s.exists) return deny(res, 404, "Sipariş bulunamadı");
    await ref.set({ invoice: null }, { merge: true }); await auditSafe(req, "invoice.clear", req.params.id, {}); res.json({ success: true });
  }));

  /* ---------- İade ve abonelik iptali ---------- */
  app.post("/api/admin/orders/:id/refund", guard, writeGuard, wrap(async (req, res) => {
    if (!need(res, idOk(req.params.id), 400, "Geçersiz sipariş")) return; if (!db || !payments) return deny(res, 503, "Ödeme sistemi bağlı değil");
    const ref = db.collection("orders").doc(req.params.id), s = await ref.get(); if (!s.exists) return deny(res, 404, "Sipariş bulunamadı"); const o = s.data();
    if (o.status !== "paid") return deny(res, 400, "Yalnızca ödenmiş sipariş iade edilir (durum: " + (o.status || "-") + ")");
    const b = req.body || {}; if (b.amount != null && !(typeof b.amount === "number" && b.amount > 0)) return deny(res, 400, "İade tutarı pozitif sayı olmalı");
    const r = await payments.refundOrder(o, req.params.id, b.amount, req.ip);
    const total = Math.round(((o.refundedAmount || 0) + r.amount) * 100) / 100, full = total >= Number(o.amount) - 0.009;
    await ref.set({ refundedAmount: total, status: full ? "refunded" : "paid", refundedAt: now(), refunds: [...(o.refunds || []), { at: now(), amount: r.amount, by: req.user.email || req.user.uid, provider: r.provider, ref: r.refundId || r.method || null }].slice(-20) }, { merge: true });
    let ended = null; if (b.endSubscription === true && full) { try { ended = await payments.cancelSubscription(o.uid, true); } catch (e) { ended = { error: e.message }; } }
    await auditSafe(req, "order.refund", req.params.id, { amount: r.amount, provider: r.provider, full, endSubscription: !!b.endSubscription }); res.json({ success: true, refunded: r.amount, total, status: full ? "refunded" : "paid", provider: r.provider, subscription: ended });
  }));
  app.post("/api/admin/users/:uid/subscription/cancel", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!need(res, uidOk(uid), 400, "Geçersiz kullanıcı kimliği")) return; if (!db || !payments) return deny(res, 503, "Ödeme sistemi bağlı değil");
    const r = await payments.cancelSubscription(uid, (req.body || {}).immediate === true); await auditSafe(req, "subscription.cancel", uid, { immediate: r.immediate, provider: r.provider }); res.json({ success: true, ...r });
  }));
  app.post("/api/admin/users/:uid/subscription/resume", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!need(res, uidOk(uid), 400, "Geçersiz kullanıcı kimliği")) return; if (!db || !payments) return deny(res, 503, "Ödeme sistemi bağlı değil");
    const r = await payments.resumeSubscription(uid); await auditSafe(req, "subscription.resume", uid, { provider: r.provider }); res.json({ success: true, ...r });
  }));

  /* ---------- Toplu işlemler (en çok 200 kullanıcı; her kullanıcı için ayrı sonuç) ---------- */
  app.post("/api/admin/bulk", guard, writeGuard, wrap(async (req, res) => {
    if (!authOk() || !db) return deny(res, 503, "Firebase yapılandırılmamış"); const b = req.body || {}, action = String(b.action || "");
    if (!["grant", "revoke", "disable", "enable", "revoke-sessions"].includes(action)) return deny(res, 400, "Geçersiz işlem");
    const uids = [...new Set(Array.isArray(b.uids) ? b.uids.map(String) : [])]; if (!uids.length || uids.length > 200 || !uids.every(uidOk)) return deny(res, 400, "1-200 geçerli kullanıcı seçin");
    let plan = null, days = 30; if (action === "grant") { plan = String(b.plan || ""); days = Math.floor(+b.days || 30); if (!PAID.includes(plan)) return deny(res, 400, "Geçerli bir paket seçin"); if (!(days >= 1 && days <= 3660)) return deny(res, 400, "Gün sayısı 1-3660"); }
    const results = [];
    for (const uid of uids) {
      try {
        let u; try { u = await admin.auth().getUser(uid); } catch { results.push({ uid, ok: false, error: "bulunamadı" }); continue; }
        const isAdm = (await roleOf({ uid, email: u.email, emailVerified: u.emailVerified })).admin;
        if (action === "disable") { if (uid === req.user.uid || isAdm) { results.push({ uid, ok: false, error: "yönetici/kendiniz" }); continue; } await admin.auth().updateUser(uid, { disabled: true }); await admin.auth().revokeRefreshTokens(uid).catch(() => {}); }
        else if (action === "enable") await admin.auth().updateUser(uid, { disabled: false });
        else if (action === "revoke-sessions") await admin.auth().revokeRefreshTokens(uid);
        else if (action === "grant") {
          const prev = (await db.collection("subscriptions").doc(uid).get()); const pv = prev.exists ? prev.data() : null;
          if (pv && ["stripe", "iyzico"].includes(pv.provider) && pv.status === "active" && ts(pv.periodEnd) > now()) { results.push({ uid, ok: false, error: "ödeme sağlayıcılı aktif abonelik" }); continue; }
          await db.collection("subscriptions").doc(uid).set({ plan, status: "active", provider: "admin", free: true, cancelAtPeriodEnd: false, cycle: days >= 365 ? "yearly" : "monthly", periodEnd: now() + days * 864e5, grantedBy: req.user.uid, updatedAt: now() }, { merge: true });
        } else if (action === "revoke") {
          const pv = (await db.collection("subscriptions").doc(uid).get()); const d = pv.exists ? pv.data() : null; if (!d) { results.push({ uid, ok: false, error: "abonelik yok" }); continue; }
          if (["stripe", "iyzico"].includes(d.provider)) { results.push({ uid, ok: false, error: "ödeme sağlayıcılı" }); continue; }
          await db.collection("subscriptions").doc(uid).set({ status: "canceled", periodEnd: now(), revokedBy: req.user.uid, updatedAt: now() }, { merge: true });
        }
        results.push({ uid, ok: true });
      } catch (e) { results.push({ uid, ok: false, error: String(e.message).slice(0, 80) }); }
    }
    const okN = results.filter((r) => r.ok).length; await auditSafe(req, "bulk." + action, null, { requested: uids.length, ok: okN, plan, days: action === "grant" ? days : undefined });
    res.json({ success: true, action, requested: uids.length, ok: okN, failed: uids.length - okN, results });
  }));

  /* ---------- Kullanıcı silme (KVKK talebi) ---------- */
  app.post("/api/admin/users/:uid/delete", guard, writeGuard, wrap(async (req, res) => {
    const uid = String(req.params.uid || ""); if (!need(res, uidOk(uid), 400, "Geçersiz kullanıcı kimliği")) return; if (!authOk() || !db || !userState) return deny(res, 503, "Firebase yapılandırılmamış");
    if (uid === req.user.uid) return deny(res, 400, "Kendi hesabınızı silemezsiniz.");
    let u; try { u = await admin.auth().getUser(uid); } catch { return deny(res, 404, "Kullanıcı bulunamadı"); }
    if ((await roleOf({ uid, email: u.email, emailVerified: u.emailVerified })).admin) return deny(res, 400, "Yönetici hesabı silinemez; önce yetkisini kaldırın.");
    const want = String((req.body || {}).confirm || ""); if (want !== (u.email || uid)) return deny(res, 400, "Onay için kullanıcının e-postasını (yoksa UID'sini) aynen yazın.");
    const r = await userState.purgeAccount(uid, { force: (req.body || {}).force === true }); if (r.blocked) return deny(res, 409, "Aktif Stripe aboneliği var. Önce aboneliği iptal edin (veya force:true).", { code: "ACTIVE_SUBSCRIPTION" });
    await auditSafe(req, "user.delete", uid, { email: u.email, counts: r.counts }); res.json({ success: true, deleted: r.counts, note: "Sipariş, abonelik ve onay kayıtları yasal saklama için korunur." });
  }));

  /* ---------- Destek talepleri ---------- */
  app.get("/api/admin/support", guard, wrap(async (req, res) => {
    if (!db) return res.json({ success: true, available: false, reason: "Firestore bağlı değil", tickets: [] }); const st = ["open", "answered", "resolved", "closed"].includes(req.query.status) ? req.query.status : "";
    const snap = await db.collection("supportTickets").orderBy("createdAt", "desc").limit(300).get(); let rows = snap.docs.map((d) => ({ id: d.id, ...d.data() })); const counts = { open: 0, answered: 0, resolved: 0, closed: 0 }; rows.forEach((t) => { counts[t.status] = (counts[t.status] || 0) + 1; }); if (st) rows = rows.filter((t) => t.status === st);
    res.json({ success: true, available: true, counts, tickets: rows.slice(0, 100).map((t) => ({ id: t.id, no: t.id.slice(0, 6).toUpperCase(), name: t.name, email: t.email, uid: t.uid || null, category: t.category || null, source: t.source || (t.uid ? "panel" : "form"), subject: t.subject, message: t.message, status: t.status, createdAt: t.createdAt, updatedAt: t.updatedAt, replies: (t.replies || []).map((r) => ({ at: r.at, by: r.by, role: r.role === "user" ? "user" : "admin", message: r.message })) })) });
  }));
  app.post("/api/admin/support/:id/reply", guard, writeGuard, wrap(async (req, res) => {
    if (!need(res, idOk(req.params.id), 400, "Geçersiz talep") || !db) return; const msg = String((req.body || {}).message || "").trim(); if (msg.length < 2 || msg.length > 4000) return deny(res, 400, "Yanıt 2-4000 karakter olmalı");
    const ref = db.collection("supportTickets").doc(req.params.id), s = await ref.get(); if (!s.exists) return deny(res, 404, "Talep bulunamadı"); const t = s.data();
    if (t.status === "closed" || t.status === "resolved") return deny(res, 409, "Talep " + (t.status === "closed" ? "kapalı" : "sonuçlandı") + ". Yanıt yazmak için önce yeniden açın.");
    let mailed = false; if (mailer && mailer.enabled()) mailed = (await mailer.send({ to: t.email, ...mailer.tpl.supportReply({ subject: t.subject, message: msg, ticketId: req.params.id.slice(0, 6).toUpperCase() }), type: "support-reply" })).sent === true;
    await ref.set({ replies: [...(t.replies || []), { at: now(), by: req.user.email || req.user.uid, role: "admin", message: msg, mailed }].slice(-50), status: "answered", updatedAt: now(), staffAt: now() }, { merge: true });
    await auditSafe(req, "support.reply", req.params.id, { mailed }); res.json({ success: true, mailed, note: mailed ? null : (t.uid ? "E-posta gönderilemedi/kapalı: yanıt kullanıcının Destek panelinde görünür." : "E-posta gönderilemedi/kapalı: yanıt yalnızca panelde kayıtlı. Kullanıcıya kendiniz yazın.") });
  }));
  app.post("/api/admin/support/:id/status", guard, writeGuard, wrap(async (req, res) => {
    if (!need(res, idOk(req.params.id), 400, "Geçersiz talep") || !db) return; const st = (req.body || {}).status; if (!["open", "answered", "resolved", "closed"].includes(st)) return deny(res, 400, "Durum open, answered, resolved veya closed olmalı");
    const ref = db.collection("supportTickets").doc(req.params.id); if (!(await ref.get()).exists) return deny(res, 404, "Talep bulunamadı"); await ref.set({ status: st, updatedAt: now(), staffAt: now() }, { merge: true }); await auditSafe(req, "support.status", req.params.id, { status: st }); res.json({ success: true });
  }));

  app.delete("/api/admin/support/:id", guard, writeGuard, wrap(async (req, res) => {
    if (!need(res, idOk(req.params.id), 400, "Geçersiz talep") || !db) return;
    const ref = db.collection("supportTickets").doc(req.params.id), s = await ref.get(); if (!s.exists) return deny(res, 404, "Talep bulunamadı");
    const t = s.data(); if (t.status !== "closed") return deny(res, 400, "Yalnızca kapalı talepler silinebilir. Önce talebi kapatın.");
    await ref.delete(); await auditSafe(req, "support.delete", req.params.id, { subject: String(t.subject || "").slice(0, 120) }); res.json({ success: true });
  }));

  /* ---------- Operasyon ---------- */
  app.get("/api/admin/errors/history", guard, wrap(async (req, res) => res.json({ success: true, persistent: !!db, errors: ops ? await ops.errorHistory(Math.min(300, +req.query.limit || 100)) : [] })));
  app.get("/api/admin/ops", guard, wrap(async (req, res) => res.json({ success: true, ...(ops ? await ops.status() : {}) })));
  app.post("/api/admin/ops/test-alert", guard, writeGuard, wrap(async (req, res) => { if (!ops) return deny(res, 503, "Operasyon modülü yok"); const used = await ops.notify("✅ DAC test uyarısı: alarm kanalı çalışıyor (" + new Date().toISOString() + ")"); await auditSafe(req, "ops.test-alert", null, { channels: used }); res.json({ success: true, channels: used, note: used.length ? null : "Hiçbir kanal yapılandırılmamış (TELEGRAM_*, ALERT_WEBHOOK_URL veya ALERT_EMAIL+e-posta)." }); }));
  app.post("/api/admin/ops/test-mail", guard, writeGuard, wrap(async (req, res) => {
    if (!mailer || !mailer.enabled()) return deny(res, 503, "E-posta kapalı (RESEND_API_KEY ve MAIL_FROM tanımlayın)"); const to = String((req.body || {}).to || req.user.email || "").trim();
    const r = await mailer.send({ to, subject: "DAC test e-postası", text: "E-posta altyapısı çalışıyor.", html: "<p>E-posta altyapısı çalışıyor.</p>", type: "test" }); await auditSafe(req, "ops.test-mail", null, { sent: r.sent }); res.json({ success: r.sent === true, ...r });
  }));
  app.post("/api/admin/ops/backup", guard, writeGuard, wrap(async (req, res) => { if (!ops) return deny(res, 503, "Operasyon modülü yok"); const r = await ops.backup(req.user.email || req.user.uid); await auditSafe(req, "ops.backup", null, { prefix: r.prefix }); res.json({ success: true, backup: r }); }));
  app.post("/api/admin/ops/reminders", guard, writeGuard, wrap(async (req, res) => { if (!ops) return deny(res, 503, "Operasyon modülü yok"); const r = await ops.runReminders(); await auditSafe(req, "ops.reminders", null, r); res.json({ success: true, ...r }); }));

  /* ---------- İki adımlı doğrulama (TOTP) ---------- */
  const tfaLimit = SEC.makeLimiter(SEC.int(process.env.ADMIN_2FA_RATE_LIMIT, 8), 5 * 60 * 1000);
  const tref = (uid) => db.collection("adminTotp").doc(uid);
  const getT = async (uid) => { const s = await tref(uid).get(); return s.exists ? s.data() : null; };
  app.get("/api/admin/2fa/status", guard, wrap(async (req, res) => { const t = db ? await getT(req.user.uid) : null; res.json({ success: true, required: process.env.ADMIN_REQUIRE_2FA === "true", enrolled: !!(t && t.enabled), pending: !!(t && !t.enabled), verified: tfa.tokens.check(req.user.uid, req.headers["x-admin-2fa"]), persistent: !!db }); }));
  app.post("/api/admin/2fa/setup", guard, writeGuard, wrap(async (req, res) => {
    if (!db) return deny(res, 503, "Firestore bağlı değil"); const t = await getT(req.user.uid); if (t && t.enabled) return deny(res, 409, "İki adımlı doğrulama zaten etkin");
    const secret = TOTP.newSecret(); await tref(req.user.uid).set({ secret, enabled: false, createdAt: now(), lastStep: -1 });
    await auditSafe(req, "2fa.setup", req.user.uid, {}); res.json({ success: true, secret, otpauth: TOTP.uri(secret, req.user.email || req.user.uid), note: "Authenticator uygulamasına (Google Authenticator, Authy, 1Password…) bu anahtarı elle ekleyin, sonra üretilen 6 haneli kodu onaylayın." });
  }));
  const codeCheck = async (req, res, { requireEnabled }) => {
    if (!db) { deny(res, 503, "Firestore bağlı değil"); return null; } if (!tfaLimit(req.user.uid)) { deny(res, 429, "Çok fazla deneme. 5 dakika sonra tekrar deneyin."); return null; }
    const t = await getT(req.user.uid); if (!t || (requireEnabled && !t.enabled) || (!requireEnabled && t.enabled)) { deny(res, 400, requireEnabled ? "İki adımlı doğrulama kurulu değil" : "Kurulum başlatılmamış veya zaten etkin"); return null; }
    const step = TOTP.verify(t.secret, (req.body || {}).code, now(), t.lastStep == null ? -1 : t.lastStep); if (step == null) { deny(res, 400, "Kod hatalı veya süresi geçmiş"); return null; }
    await tref(req.user.uid).set({ lastStep: step }, { merge: true }); return t;
  };
  app.post("/api/admin/2fa/confirm", guard, writeGuard, wrap(async (req, res) => { const t = await codeCheck(req, res, { requireEnabled: false }); if (!t) return; await tref(req.user.uid).set({ enabled: true, enabledAt: now() }, { merge: true }); await auditSafe(req, "2fa.enable", req.user.uid, {}); res.json({ success: true, token: tfa.tokens.issue(req.user.uid) }); }));
  app.post("/api/admin/2fa/verify", guard, wrap(async (req, res) => { const t = await codeCheck(req, res, { requireEnabled: true }); if (!t) return; res.json({ success: true, token: tfa.tokens.issue(req.user.uid) }); }));
  app.post("/api/admin/2fa/disable", guard, writeGuard, wrap(async (req, res) => { const t = await codeCheck(req, res, { requireEnabled: true }); if (!t) return; await tref(req.user.uid).delete(); await auditSafe(req, "2fa.disable", req.user.uid, {}); res.json({ success: true }); }));
};
