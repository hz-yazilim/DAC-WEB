/* Tekil tarama için "yenilenen hak" + aynı hedefe bekleme süresi (bellek içi: Firestore okuması/yazması harcamaz).
 * - Hak (jeton kovası): her kullanıcı `capacity` tarama hakkıyla başlar; saatte `refillPerHour` hak geri yüklenir (dolu kovadan fazla birikmez).
 *   Böylece birkaç varlığı art arda taramak serbesttir; sürekli/otomatik taramayla sistemi yoran kullanıcı yavaşlar, bekleyince hakkı yenilenir.
 * - Bekleme: aynı kullanıcı aynı hedefi `cooldownMs` içinde yeniden tarayamaz (sonuç zaten değişmez; gereksiz yük).
 * Sunucu yeniden başlayınca sıfırlanır (tek örnek varsayımı, hız sınırlarıyla aynı). capacity=0 hakkı, cooldownMs=0 beklemeyi kapatır. */
function createScanQuota(o = {}) {
  const cap = o.capacity ?? 100, perHour = o.refillPerHour ?? 4, cool = o.cooldownMs ?? 300000, now = o.now || Date.now, maxEntries = o.maxEntries || 50000;
  const buckets = new Map(), last = new Map();
  function prune(t) {
    if (last.size > maxEntries) for (const [k, v] of last) if (t - v > cool) last.delete(k);
    if (last.size > maxEntries) last.clear();
    if (buckets.size > maxEntries) for (const [k, b] of buckets) if (b.tokens + (t - b.at) / 3600000 * perHour >= cap) buckets.delete(k);
    if (buckets.size > maxEntries) buckets.clear();
  }
  function status(uid, t = now()) {
    const b = buckets.get(uid); if (!b) return { remaining: cap, limit: cap };
    return { remaining: Math.floor(Math.min(cap, b.tokens + (t - b.at) / 3600000 * perHour)), limit: cap };
  }
  function take(uid, targetKey) {
    const t = now(), k = uid + "|" + targetKey, l = last.get(k);
    if (cool > 0 && l !== undefined && t - l < cool) return { ok: false, code: "SCAN_COOLDOWN", retryAfterSec: Math.ceil((cool - (t - l)) / 1000) };
    if (cap > 0) {
      let b = buckets.get(uid);
      if (!b) b = { tokens: cap, at: t }; else { b.tokens = Math.min(cap, b.tokens + (t - b.at) / 3600000 * perHour); b.at = t; }
      buckets.set(uid, b);
      if (b.tokens < 1) return { ok: false, code: "SCAN_QUOTA", retryAfterSec: Math.ceil((1 - b.tokens) / perHour * 3600), remaining: 0, limit: cap };
      b.tokens -= 1;
    }
    last.set(k, t); prune(t);
    return { ok: true, ...status(uid, t) };
  }
  function refund(uid, targetKey) { const b = buckets.get(uid); if (b && cap > 0) b.tokens = Math.min(cap, b.tokens + 1); last.delete(uid + "|" + targetKey); }
  return { take, refund, status };
}
const fmtWait = (s) => (s < 90 ? `${s} saniye` : s < 5400 ? `${Math.ceil(s / 60)} dakika` : `${Math.ceil(s / 3600)} saat`);
const denyMessage = (r) => (r.code === "SCAN_COOLDOWN"
  ? `Bu hedef az önce tarandı; sonuç değişmemiştir. ${fmtWait(r.retryAfterSec)} sonra yeniden tarayabilirsiniz.`
  : `Tarama hakkınız doldu (${r.limit}). Haklar zamanla yenilenir; yaklaşık ${fmtWait(r.retryAfterSec)} sonra yeni bir tarama yapabilirsiniz.`);
module.exports = { createScanQuota, denyMessage, fmtWait };
