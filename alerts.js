/* Digital Asset Center - Otomatik tarama aralıkları ve bildirim kararları (saf fonksiyonlar; ağ/veritabanı kullanmaz, test edilebilir) */
"use strict";
const HOUR = 36e5, DAY = 864e5;

// Tarama türüne göre otomatik tarama sıklığı (saat). Çökmeyi çabuk yakalamak için erişim türleri sık, ağır/yavaş değişenler seyrek taranır.
const INTERVAL_H = { UPTIME: 5, WEBSITE: 5, WEB: 5, API: 5, SSL_CERTIFICATE: 24, SSL: 24, DOMAIN: 24, EMAIL: 24, HOSTING: 24, SEO: 24, PERFORMANCE: 24, ANALYTICS: 24, SAAS_SUBSCRIPTION: 24, SECURITY: 168, SERVER: 168, BRAND: 168, MOBILE_APP: 168, REPOSITORY: 168 };
const intervalMs = (type) => (INTERVAL_H[type] || 24) * HOUR;

// Bitiş uyarı eşikleri (gün). Her eşik için bir kez bildirim gider; yenilenince (30 günden fazla kalınca) sıfırlanır.
const STEPS = [0, 1, 3, 7, 14, 30];

function expiryInfo(type, data, now) {
  const sa = (data && data.specificAnalysis) || {};
  if (type === "SSL_CERTIFICATE" || type === "SSL") return sa.cert && typeof sa.cert.daysRemaining === "number" ? { days: sa.cert.daysRemaining, what: "SSL sertifikası" } : null;
  if (type === "DOMAIN" || type === "EMAIL") return sa.registration && typeof sa.registration.remainingDays === "number" ? { days: sa.registration.remainingDays, what: "Alan adı" } : null;
  if (type === "SAAS_SUBSCRIPTION") {
    const t = Date.parse((data && data.renewalDate) || sa.renewalDate || "");
    return Number.isFinite(t) ? { days: Math.ceil((t - now) / DAY), what: "Abonelik" } : null;
  }
  return null;
}

/* prev: { status, findings, expiryLevel }   next: { status, findings, healthScore, data }
 * Döner: { notes: [{kind, title, body}], expiryLevel } */
function decide({ type, name, prev = {}, next, now = Date.now() }) {
  const notes = []; const label = name || "Varlık";
  const prevFind = Array.isArray(prev.findings) ? prev.findings : [];
  const findings = Array.isArray(next.findings) ? next.findings : [];
  const isDown = next.status === "DOWN", wasDown = prev.status === "DOWN";

  const ex = expiryInfo(type, next.data, now);
  let expiryLevel = prev.expiryLevel == null ? null : prev.expiryLevel;
  if (ex) {
    if (ex.days > 30) expiryLevel = null;
    else {
      const level = STEPS.find((s) => ex.days <= s);
      if (expiryLevel == null || level < expiryLevel) {
        expiryLevel = level;
        notes.push({ kind: "expiry", title: ex.days < 0 ? `🔴 ${ex.what} süresi doldu` : ex.days === 0 ? `🔴 ${ex.what} bugün bitiyor` : `⏰ ${ex.what} ${ex.days} gün içinde bitiyor`, body: `${label}: yenilemeyi unutmayın.` });
      }
    }
  }
  if (isDown && !wasDown) notes.push({ kind: "down", title: "🔴 Erişilemiyor", body: `${label} yanıt vermiyor.` });
  else if (!isDown && wasDown && next.status !== "ERROR" && next.status !== "UNKNOWN") notes.push({ kind: "up", title: "🟢 Yeniden çalışıyor", body: `${label} tekrar erişilebilir.` });
  if (!isDown && next.status !== "EXPIRED") {
    const fresh = findings.filter((f) => /_critical$/.test(String(f)) && !prevFind.includes(f));
    if (fresh.length && !(ex && ex.days <= 30 && fresh.every((f) => /expir/.test(String(f))))) notes.push({ kind: "critical", title: `⚠️ ${fresh.length} yeni kritik bulgu`, body: `${label}: ayrıntı için varlığı açın.` });
  }
  return { notes, expiryLevel };
}

module.exports = { INTERVAL_H, intervalMs, STEPS, expiryInfo, decide };
