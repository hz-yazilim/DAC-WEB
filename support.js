/* Digital Asset Center - Destek talebi (iletişim formu) + CAPTCHA (V13.3)
 * Herkese açık: GET /api/support/config, POST /api/support. Yönetici uçları admin-ops.js içindedir.
 * CAPTCHA: Cloudflare Turnstile (TURNSTILE_SITE_KEY + TURNSTILE_SECRET). Tanımsızsa kapalıdır; bal küpü (honeypot) alanı ve IP hız sınırı her zaman çalışır. */
"use strict";
const bad = (status, message) => Object.assign(new Error(message), { status });
const clean = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").trim().slice(0, max);

module.exports = function createSupport({ db, http, mailer, SEC, now = Date.now, log = () => {} }) {
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
    const ref = db.collection("supportTickets").doc(); const doc = { ...v, status: "open", createdAt: now(), updatedAt: now(), replies: [], ipHash: ip ? require("crypto").createHash("sha256").update(String(ip) + "|dac").digest("hex").slice(0, 16) : null };
    await ref.set(doc); const short = ref.id.slice(0, 6).toUpperCase();
    if (mailer && mailer.enabled()) mailer.send({ to: v.email, ...mailer.tpl.supportReceived({ subject: v.subject, ticketId: short }), type: "support-received" }).catch(() => {});
    return { id: ref.id, ticketNo: short };
  }
  function mount(app) {
    const lim = SEC.makeLimiter(SEC.int(process.env.SUPPORT_RATE_LIMIT, 5), 60 * 60 * 1000);
    const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { const c = e.status || 500; if (c >= 500) log("support: " + e.message); res.status(c).json({ success: false, error: c >= 500 ? "Sunucu hatası" : e.message }); } };
    app.get("/api/support/config", (req, res) => { res.set("Cache-Control", "no-store"); res.json({ success: true, captcha: captchaOn() ? { provider: "turnstile", siteKey: process.env.TURNSTILE_SITE_KEY } : null }); });
    app.post("/api/support", wrap(async (req, res) => {
      if (!lim(req.ip)) throw bad(429, "Çok fazla talep gönderdiniz. Bir saat sonra tekrar deneyin.");
      const b = req.body || {}; if (clean(b.website, 50)) return res.json({ success: true, ticketNo: "000000" }); // bal küpü: botlara başarılı görünür, kaydedilmez
      if (!(await verifyCaptcha(b.captchaToken, req.ip))) throw bad(400, "Robot doğrulaması başarısız. Sayfayı yenileyip tekrar deneyin.");
      const r = await create(b, req.ip); res.json({ success: true, ticketNo: r.ticketNo });
    }));
  }
  return { mount, create, validate, verifyCaptcha, captchaOn };
};
