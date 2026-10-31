/* Digital Asset Center - E-posta gönderimi (V13.3)
 * Sağlayıcı: Resend (HTTPS API; ek paket gerekmez). Ortam değişkenleri: RESEND_API_KEY, MAIL_FROM (ör. "DAC <bildirim@alanadiniz.com>"; alan adı Resend'de doğrulanmış olmalı).
 * Yapılandırılmamışsa sistem sessizce e-posta göndermez (panelde "kapalı" görünür). İşlemsel (hizmet) iletileridir: makbuz, süre hatırlatma, destek yanıtı.
 * Aynı ileti iki kez gitmesin diye `dedupeKey` ile `mailSent/{anahtar}` kaydı tutulur. Gövde saklanmaz; `mailLog` yalnızca maskeli alıcı, tür ve durumu içerir. */
"use strict";
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const mask = (e) => String(e || "").replace(/^(.).*(@.*)$/, "$1***$2");
const money = (n, c) => (c === "USD" ? "$" + Number(n).toFixed(2) : Number(n).toLocaleString("tr-TR", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + " ₺");
const dateTr = (ms) => new Date(ms).toLocaleDateString("tr-TR", { timeZone: "Europe/Istanbul" });

module.exports = function createMailer({ db, http, now = Date.now, log = () => {} }) {
  const enabled = () => !!(process.env.RESEND_API_KEY && process.env.MAIL_FROM);
  const site = () => String(process.env.SITE_URL || "").replace(/\/$/, "");
  const layout = (title, body) => `<!doctype html><html lang="tr"><body style="margin:0;background:#0a1020;font-family:Arial,sans-serif"><div style="max-width:560px;margin:0 auto;padding:24px"><div style="background:#111a2e;border:1px solid #243049;border-radius:16px;padding:24px;color:#e6ecf8"><h2 style="margin:0 0 12px;font-size:20px">${esc(title)}</h2>${body}<p style="color:#8b9bb8;font-size:12px;margin-top:24px">Bu ileti Digital Asset Center hizmetiyle ilgili bilgilendirmedir. ${site() ? `<a style="color:#7aa2ff" href="${esc(site())}">${esc(site())}</a>` : ""}</p></div></div></body></html>`;
  const btn = (href, label) => `<p><a href="${esc(href)}" style="display:inline-block;background:#2f6bff;color:#fff;text-decoration:none;padding:10px 20px;border-radius:20px">${esc(label)}</a></p>`;

  const tpl = {
    receipt: ({ planName, amount, currency, cycle, periodEnd, couponCode }) => ({ subject: `Ödemeniz alındı: ${planName}`, ...(() => { const t = `Ödemeniz alındı. Paket: ${planName} (${cycle === "yearly" ? "yıllık" : "aylık"}). Tutar: ${money(amount, currency)}.${couponCode ? " Kupon: " + couponCode + "." : ""}${periodEnd ? " Geçerlilik sonu: " + dateTr(periodEnd) + "." : ""}`; return { text: t, html: layout("Ödemeniz alındı", `<p>${esc(planName)} (${cycle === "yearly" ? "yıllık" : "aylık"}) paketiniz için <b>${esc(money(amount, currency))}</b> tahsil edildi.${couponCode ? ` Kupon: <b>${esc(couponCode)}</b>.` : ""}</p>${periodEnd ? `<p>Paketiniz <b>${esc(dateTr(periodEnd))}</b> tarihine kadar geçerlidir.</p>` : ""}<p>Fatura talebiniz için bu iletiyi yanıtlayabilir veya destek adresimize yazabilirsiniz.</p>`) }; })() }),
    reminder: ({ planName, days, periodEnd, free }) => ({ subject: days <= 1 ? `Paketiniz yarın sona eriyor: ${planName}` : `Paketiniz ${days} gün içinde sona eriyor: ${planName}`,
      text: `${planName} paketiniz ${dateTr(periodEnd)} tarihinde sona eriyor. Kesintisiz kullanım için yenileyin: ${site()}/#plan`, html: layout("Paketiniz sona eriyor", `<p><b>${esc(planName)}</b> paketiniz <b>${esc(dateTr(periodEnd))}</b> tarihinde sona eriyor.${free ? "" : " Süre dolmadan yeniden satın alırsanız kalan gün kaybolmaz; yeni süre mevcut bitişe eklenir."}</p><p>Süre dolunca yeni tarama yapılamaz ve otomatik izleme durur.</p>${site() ? btn(site() + "/#plan", "Paketi yenile") : ""}`) }),
    trialEnding: ({ hoursLeft }) => ({ subject: "Ücretsiz denemeniz bitmek üzere", text: `Ücretsiz denemenizin bitmesine yaklaşık ${hoursLeft} saat kaldı. Paket seçin: ${site()}/#plan`, html: layout("Denemeniz bitmek üzere", `<p>Ücretsiz denemenizin bitmesine yaklaşık <b>${esc(hoursLeft)} saat</b> kaldı. Verileriniz silinmez; ancak yeni tarama için bir paket seçmeniz gerekir.</p>${site() ? btn(site() + "/#plan", "Paketleri gör") : ""}`) }),
    supportReply: ({ subject, message, ticketId }) => ({ subject: `Destek talebiniz yanıtlandı: ${subject}`, text: `Destek talebiniz (#${ticketId}) yanıtlandı:\n\n${message}`, html: layout("Destek talebiniz yanıtlandı", `<p style="color:#8b9bb8">Talep #${esc(ticketId)} • ${esc(subject)}</p><div style="white-space:pre-wrap">${esc(message)}</div>`) }),
    supportReceived: ({ subject, ticketId }) => ({ subject: `Talebinizi aldık (#${ticketId})`, text: `"${subject}" konulu talebinizi aldık. Numara: #${ticketId}. En kısa sürede dönüş yapacağız.`, html: layout("Talebinizi aldık", `<p>"${esc(subject)}" konulu talebinizi aldık. Numara: <b>#${esc(ticketId)}</b>. En kısa sürede dönüş yapacağız.</p>`) }),
    passwordReset: ({ link }) => ({ subject: "Şifre sıfırlama bağlantınız", text: `Hesabınız için şifre sıfırlama bağlantısı: ${link}\n\nBu isteği siz yapmadıysanız bu iletiyi yok sayabilirsiniz.`, html: layout("Şifrenizi sıfırlayın", `<p>Hesabınız için bir şifre sıfırlama bağlantısı oluşturuldu.</p>${btn(link, "Şifremi sıfırla")}<p style="color:#8b9bb8">Bu isteği siz yapmadıysanız bu iletiyi yok sayabilirsiniz.</p>`) }),
    alert: ({ text }) => ({ subject: "DAC operasyon uyarısı", text, html: layout("Operasyon uyarısı", `<p style="white-space:pre-wrap">${esc(text)}</p>`) })
  };

  async function send({ to, subject, text, html, type = "other", uid = null, dedupeKey = null }) {
    if (!enabled()) return { sent: false, reason: "disabled" };
    if (!to || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(to)) || String(to).length > 200) return { sent: false, reason: "bad-recipient" };
    const key = dedupeKey ? String(dedupeKey).replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 200) : null;
    if (key && db) { try { if ((await db.collection("mailSent").doc(key).get()).exists) return { sent: false, reason: "duplicate" }; } catch { /* kontrol edilemedi: gönder */ } }
    let status = "sent", error = null;
    try {
      const r = await http.request({ method: "POST", url: "https://api.resend.com/emails", headers: { Authorization: "Bearer " + process.env.RESEND_API_KEY, "Content-Type": "application/json" }, data: { from: process.env.MAIL_FROM, to: [to], subject: String(subject).slice(0, 200), html, text }, validateStatus: () => true, timeout: 15000 });
      if (r.status >= 400) { status = "failed"; error = `HTTP ${r.status}`; }
    } catch (e) { status = "failed"; error = String(e.message).slice(0, 100); }
    if (db) {
      try { if (status === "sent" && key) await db.collection("mailSent").doc(key).set({ at: now(), type }); await db.collection("mailLog").doc().set({ at: now(), type, to: mask(to), uid, status, error }); } catch (e) { log("mailLog yazılamadı: " + e.message); }
    }
    return status === "sent" ? { sent: true } : { sent: false, reason: "provider", error };
  }
  return { enabled, send, tpl, esc, mask };
};
