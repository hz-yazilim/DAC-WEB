/* Digital Asset Center - Destek talebi (iletişim formu) + CAPTCHA (V13.3) + kullanıcı destek paneli (V13.4)
 * Herkese açık: GET /api/support/config, POST /api/support. Yönetici uçları admin-ops.js içindedir.
 * Giriş yapmış kullanıcı (Bearer token): GET/POST /api/support/my, POST /api/support/my/:id/reply. Talebi yalnızca yönetici kapatır/sonuçlandırır; sonuçlanmamış talebi olan kullanıcı yeni talep açamaz.
 * Kullanıcı yalnızca KENDİ taleplerini görür/yazar (uid sunucuda doğrulanır); yönetici e-postası kullanıcıya asla gösterilmez.
 * CAPTCHA: Cloudflare Turnstile (TURNSTILE_SITE_KEY + TURNSTILE_SECRET). Tanımsızsa kapalıdır; bal küpü (honeypot) alanı ve IP hız sınırı her zaman çalışır. */
"use strict";
const bad = (status, message) => Object.assign(new Error(message), { status });
const clean = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").trim().slice(0, max);

const CATEGORIES = { general: "Genel", billing: "Fatura / ödeme", cancel: "Paket iptali / iade", technical: "Teknik sorun" };
const idOk = (id) => /^[A-Za-z0-9_-]{1,100}$/.test(String(id || ""));
const isFinal = (st) => st === "closed" || st === "resolved"; // kapalı / sonuçlandı: kullanıcı artık yazamaz, yeni talep açılabilir
const ACTIVE_MSG = "Sonuçlanmamış bir destek talebiniz var. Yeni talep açabilmek için mevcut talebin yönetici tarafından sonuçlandırılması veya kapatılması gerekir.";

module.exports = function createSupport({ db, http, mailer, SEC, verifyUser = null, now = Date.now, log = () => {} }) {
  const captchaOn = () => !!(process.env.TURNSTILE_SECRET && process.env.TURNSTILE_SITE_KEY);
  async function verifyCaptcha(token, ip) {
    if (!captchaOn()) return true; if (!token || typeof token !== "string" || token.length > 2048) return false;
    try { const r = await http.request({ method: "POST", url: "https://challenges.cloudflare.com/turnstile/v0/siteverify", data: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: token, ...(ip ? { remoteip: ip } : {}) }).toString(), headers: { "Content-Type": "application/x-www-form-urlencoded" }, validateStatus: () => true, timeout: 8000 }); return !!(r.data && r.data.success === true); }
    catch (e) { log("turnstile: " + e.message); return false; } // doğrulanamıyorsa güvenli taraf: reddet
  }
  function validate(b) {
    const email = clean(b.email, 200).toLowerCase(), name = clean(b.name, 80), subject = clean(b.subject, 120), message = clean(b.message, 4000);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email)) throw bad(400, "Geçerli bir e-posta girin");
    if (name.length < 2) throw bad(400, "Adınızı girin"); if (subject.length < 3) throw bad(400, "Konu en az 3 karakter olmalı"); if (message.length < 10) throw bad(400, "Mesaj en az 10 karakter olmalı");
    return { email, name, subject, message };
  }
  async function create(b, ip) {
    if (!db) throw bad(503, "Destek sistemi şu an kullanılamıyor"); const v = validate(b);
    const prev = await db.collection("supportTickets").where("email", "==", v.email).limit(100).get();
    if (prev.docs.some((d) => !isFinal(d.data().status))) throw bad(409, ACTIVE_MSG);
    const ref = db.collection("supportTickets").doc(); const doc = { ...v, status: "open", createdAt: now(), updatedAt: now(), replies: [], ipHash: ip ? require("crypto").createHash("sha256").update(String(ip) + "|dac").digest("hex").slice(0, 16) : null };
    await ref.set(doc); const short = ref.id.slice(0, 6).toUpperCase();
    if (mailer && mailer.enabled()) mailer.send({ to: v.email, ...mailer.tpl.supportReceived({ subject: v.subject, ticketId: short }), type: "support-received" }).catch(() => {});
    return { id: ref.id, ticketNo: short };
  }

  /* ---------- Kullanıcı destek paneli (giriş gerekli) ---------- */
  const ticketNo = (id) => id.slice(0, 6).toUpperCase();
  // Yönetici tarafının son işlem zamanı (yanıt / sonuçlandırma / kapatma / yeniden açma). Eski kayıtlarda yoksa yanıtlardan türetilir.
  const staffAtOf = (t) => {
    if (Number.isFinite(t.staffAt)) return t.staffAt;
    let m = 0; for (const r of t.replies || []) if (r.role !== "user" && Number.isFinite(r.at) && r.at > m) m = r.at;
    return isFinal(t.status) ? Math.max(m, t.updatedAt || 0) : m;
  };
  // Kullanıcıya giden görünüm: yönetici kimliği (e-posta) gizlenir; yanıtlar "staff" / "user" olarak etiketlenir.
  const userView = (id, t) => ({ id, no: ticketNo(id), subject: t.subject, category: t.category || "general", status: t.status, createdAt: t.createdAt, updatedAt: t.updatedAt, staffAt: staffAtOf(t),
    message: t.message, replies: (t.replies || []).map((r) => ({ at: r.at, from: r.role === "user" ? "user" : "staff", message: r.message })) });
  const authed = async (req) => { if (!verifyUser) throw bad(503, "Destek paneli şu an kullanılamıyor"); if (!db) throw bad(503, "Destek sistemi şu an kullanılamıyor"); return verifyUser(req); };
  async function listMine(uid) {
    const snap = await db.collection("supportTickets").where("uid", "==", uid).limit(100).get();
    return snap.docs.map((d) => userView(d.id, d.data())).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  }
  async function createMine(u, b) {
    const subject = clean(b.subject, 120), message = clean(b.message, 4000), category = CATEGORIES[b.category] ? String(b.category) : "general";
    if (subject.length < 3) throw bad(400, "Konu en az 3 karakter olmalı"); if (message.length < 10) throw bad(400, "Mesaj en az 10 karakter olmalı");
    if (!u.email) throw bad(400, "Hesabınızda e-posta adresi yok; iletişim sayfasındaki formu kullanın");
    const mine = await db.collection("supportTickets").where("uid", "==", u.uid).limit(100).get();
    if (mine.docs.some((d) => !isFinal(d.data().status))) throw bad(409, ACTIVE_MSG);
    const ref = db.collection("supportTickets").doc();
    const doc = { uid: u.uid, name: clean(u.name || u.email.split("@")[0], 80) || "Kullanıcı", email: u.email.toLowerCase(), subject, message, category, status: "open", source: "panel", createdAt: now(), updatedAt: now(), replies: [] };
    await ref.set(doc);
    if (mailer && mailer.enabled()) mailer.send({ to: doc.email, ...mailer.tpl.supportReceived({ subject, ticketId: ticketNo(ref.id) }), type: "support-received" }).catch(() => {});
    return userView(ref.id, doc);
  }
  async function mineOrThrow(id, uid) {
    if (!idOk(id)) throw bad(400, "Geçersiz talep");
    const ref = db.collection("supportTickets").doc(id), s = await ref.get();
    if (!s.exists || s.data().uid !== uid) throw bad(404, "Talep bulunamadı"); // başkasının talebi de 404: varlığı sızdırılmaz
    return { ref, t: s.data() };
  }
  async function replyMine(u, id, body) {
    const msg = clean(body.message, 4000); if (msg.length < 2) throw bad(400, "Mesaj en az 2 karakter olmalı");
    const { ref, t } = await mineOrThrow(id, u.uid);
    if (isFinal(t.status)) throw bad(409, "Bu talep " + (t.status === "closed" ? "kapatıldı" : "sonuçlandı") + ". Yeni bir talep açabilirsiniz.");
    if ((t.replies || []).length >= 50) throw bad(409, "Bu talepte mesaj sınırına ulaşıldı; lütfen yeni bir talep açın.");
    const replies = [...(t.replies || []), { at: now(), by: u.email || u.uid, role: "user", message: msg }].slice(-50);
    await ref.set({ replies, status: "open", updatedAt: now() }, { merge: true }); // kullanıcı yazınca talep "açık" olur (yalnızca açık/yanıtlandı talepte; kapalı/sonuçlanmış talep yeniden açılmaz)
    return userView(id, { ...t, replies, status: "open", updatedAt: now() });
  }
  function mount(app) {
    const lim = SEC.makeLimiter(SEC.int(process.env.SUPPORT_RATE_LIMIT, 5), 60 * 60 * 1000);
    const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { const c = e.status || 500; if (c >= 500) log("support: " + e.message); res.status(c).json({ success: false, error: c >= 500 && !e.status ? "Sunucu hatası" : e.message }); } };
    app.get("/api/support/config", (req, res) => { res.set("Cache-Control", "no-store"); res.json({ success: true, captcha: captchaOn() ? { provider: "turnstile", siteKey: process.env.TURNSTILE_SITE_KEY } : null }); });
    app.post("/api/support", wrap(async (req, res) => {
      if (!lim(req.ip)) throw bad(429, "Çok fazla talep gönderdiniz. Bir saat sonra tekrar deneyin.");
      const b = req.body || {}; if (clean(b.website, 50)) return res.json({ success: true, ticketNo: "000000" }); // bal küpü: botlara başarılı görünür, kaydedilmez
      if (!(await verifyCaptcha(b.captchaToken, req.ip))) throw bad(400, "Robot doğrulaması başarısız. Sayfayı yenileyip tekrar deneyin.");
      const r = await create(b, req.ip); res.json({ success: true, ticketNo: r.ticketNo });
    }));
    // --- Kullanıcı destek paneli ---
    const ipLim = SEC.makeLimiter(SEC.int(process.env.SUPPORT_PANEL_IP_LIMIT, 120), 10 * 60 * 1000), userLim = SEC.makeLimiter(SEC.int(process.env.SUPPORT_PANEL_WRITE_LIMIT, 20), 60 * 60 * 1000);
    const panel = (fn, { write = false } = {}) => wrap(async (req, res) => {
      if (!ipLim(req.ip)) throw bad(429, "Çok fazla istek. Biraz sonra tekrar deneyin.");
      const u = await authed(req); if (write && !userLim(u.uid)) throw bad(429, "Çok fazla mesaj gönderdiniz. Bir saat sonra tekrar deneyin.");
      res.set("Cache-Control", "no-store"); await fn(req, res, u);
    });
    // Rozet için hafif özet (tam mesajlar yok); kendi hız sınırı vardır
    const sumIpLim = SEC.makeLimiter(SEC.int(process.env.SUPPORT_SUMMARY_IP_LIMIT, 600), 10 * 60 * 1000);
    app.get("/api/support/my/summary", wrap(async (req, res) => {
      if (!sumIpLim(req.ip)) throw bad(429, "Çok fazla istek. Biraz sonra tekrar deneyin.");
      const u = await authed(req); res.set("Cache-Control", "no-store");
      const snap = await db.collection("supportTickets").where("uid", "==", u.uid).limit(100).get();
      res.json({ success: true, serverTime: now(), tickets: snap.docs.map((d) => { const t = d.data(); return { id: d.id, no: ticketNo(d.id), subject: t.subject, status: t.status, staffAt: staffAtOf(t), updatedAt: t.updatedAt }; }) });
    }));
    app.get("/api/support/my", panel(async (req, res, u) => res.json({ success: true, categories: CATEGORIES, tickets: await listMine(u.uid) })));
    app.post("/api/support/my", panel(async (req, res, u) => res.json({ success: true, ticket: await createMine(u, req.body || {}) }), { write: true }));
    app.post("/api/support/my/:id/reply", panel(async (req, res, u) => res.json({ success: true, ticket: await replyMine(u, String(req.params.id), req.body || {}) }), { write: true }));
  }
  return { mount, create, validate, verifyCaptcha, captchaOn, listMine, createMine, replyMine, CATEGORIES };
};
