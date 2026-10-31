/* Tarama hakkı: AYLIK hak (kalıcı, Firestore `scanQuota/{uid}`) + aynı hedefe BEKLEME süresi (bellek içi).
 * - Aylık hak: her kullanıcı ayda `monthlyLimit` tarama yapabilir; ay Türkiye saatine göre değişir (1'i 00:00). Sayaç bellekte tutulur ve Firestore'a
 *   gecikmeli yazılır (tarama başına en fazla 1 yazma, kullanıcı başına süreç ömründe 1 okuma). Okuma başarısız olursa sayaç bellekten devam eder (hizmet kesilmez) ve sonraki istekte yeniden yüklenir.
 * - Bekleme: aynı kullanıcı aynı hedefi `cooldownMs` (tekil) / `bulkCooldownMs` (toplu) dolmadan yeniden tarayamaz; son tarama zamanı tekil ve toplu yoldan ORTAKTIR (bir yoldan taratıp diğerinden atlatılamaz).
 * - Karar ve sayaç artışı aynı eşzamanlı adımda yapılır: art arda/paralel isteklerle sınır aşılamaz.
 * monthlyLimit=0 hakkı, cooldownMs=0 beklemeyi kapatır. */
const TR_OFFSET = 3 * 3600e3;
function createScanQuota(o = {}) {
  const limit = o.monthlyLimit ?? 100, cool = o.cooldownMs ?? 15 * 60e3, bulkCool = o.bulkCooldownMs ?? 45 * 60e3, now = o.now || Date.now;
  const db = o.db || null, coll = o.collection || "scanQuota", log = o.log || console, maxEntries = o.maxEntries || 100000, flushMs = o.flushMs ?? 1500;
  const users = new Map(), last = new Map();
  const monthKey = (t) => new Date(t + TR_OFFSET).toISOString().slice(0, 7);
  const resetsAt = (t) => { const d = new Date(t + TR_OFFSET); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) - TR_OFFSET; };
  async function load(e) {
    if (!db) return;
    try { const d = await db.collection(coll).doc(e.uid).get(); if (d.exists) { const v = d.data(); if (v.month === e.month) e.used = Math.max(e.used, Number(v.used) || 0); } }
    catch (err) { e.ready = null; log.warn && log.warn("tarama hakkı okunamadı (bellekten devam):", err.message); }
  }
  async function entry(uid) {
    const t = now(), m = monthKey(t); let e = users.get(uid);
    if (!e) { if (users.size > maxEntries) users.clear(); e = { uid, month: m, used: 0, ready: null, timer: null }; users.set(uid, e); }
    if (e.month !== m) { e.month = m; e.used = 0; e.ready = null; }
    if (!e.ready) e.ready = load(e);
    await e.ready; return e;
  }
  function persist(e) {
    if (!db || e.timer) return;
    const write = () => { e.timer = null; db.collection(coll).doc(e.uid).set({ month: e.month, used: e.used, updatedAt: now() }).catch((err) => log.warn && log.warn("tarama hakkı yazılamadı:", err.message)); };
    if (flushMs <= 0) return write(); e.timer = setTimeout(write, flushMs); if (e.timer.unref) e.timer.unref();
  }
  const view = (e, t) => ({ used: e.used, remaining: limit > 0 ? Math.max(0, limit - e.used) : null, limit, resetsAt: resetsAt(t) });
  function prune(t) { if (last.size <= maxEntries) return; const c = Math.max(cool, bulkCool); for (const [k, v] of last) if (t - v > c) last.delete(k); if (last.size > maxEntries) last.clear(); }

  /* keys: ["WEBSITE|ornek.com", ...]. Dönüş: { ok, allowed:[], skipped:[{key,retryAfterSec}], code?, retryAfterSec?, needed?, ...view } */
  async function reserve(uid, keys, { bulk = false } = {}) {
    const e = await entry(uid); // bu satırdan sonra await YOK: karar + artış tek adımdır
    const t = now(), cd = bulk ? bulkCool : cool, uniq = [...new Set(keys)], allowed = [], skipped = [];
    for (const key of uniq) { const l = last.get(uid + "|" + key); if (cd > 0 && l !== undefined && t - l < cd) skipped.push({ key, retryAfterSec: Math.ceil((cd - (t - l)) / 1000) }); else allowed.push(key); }
    if (!allowed.length) return { ok: false, code: "SCAN_COOLDOWN", retryAfterSec: Math.min(...skipped.map((s) => s.retryAfterSec)), allowed, skipped, ...view(e, t) };
    if (limit > 0 && e.used + allowed.length > limit) return { ok: false, code: "SCAN_QUOTA", needed: allowed.length, allowed: [], skipped, ...view(e, t) };
    e.used += allowed.length; for (const key of allowed) last.set(uid + "|" + key, t); prune(t); persist(e);
    return { ok: true, allowed, skipped, ...view(e, t) };
  }
  async function refund(uid, keys) { const e = await entry(uid); const n = keys.length; e.used = Math.max(0, e.used - n); for (const k of keys) last.delete(uid + "|" + k); persist(e); }
  async function charge(uid, n) { const e = await entry(uid); e.used += n; persist(e); } // zorunlu düşüm (ör. yeniden deneme)
  async function status(uid) { const e = await entry(uid), t = now(); return { ...view(e, t), cooldownSec: Math.round(cool / 1000), bulkCooldownSec: Math.round(bulkCool / 1000) }; }
  return { reserve, refund, charge, status };
}
// Bekleme anahtarı: tür + küçük harfli, "www." ve sondaki noktası atılmış ana makine adı (aynı hedefin farklı yazımları tek sayılır).
const targetKey = (type, host) => `${String(type || "").toUpperCase()}|${String(host || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "")}`;
const fmtWait = (s) => (s < 90 ? `${s} saniye` : s < 5400 ? `${Math.ceil(s / 60)} dakika` : `${Math.ceil(s / 3600)} saat`);
const fmtDate = (ms) => new Date(ms + TR_OFFSET).toISOString().slice(0, 10).split("-").reverse().join(".");
const denyMessage = (r, bulk = false) => (r.code === "SCAN_COOLDOWN"
  ? `${bulk ? "Bu hedef(ler)" : "Bu hedef"} az önce tarandı; sonuç değişmemiştir. ${fmtWait(r.retryAfterSec)} sonra yeniden taranabilir.`
  : `Aylık tarama hakkınız yetmiyor${r.needed > 1 ? ` (${r.needed} tarama gerekiyor, ${r.remaining} hakkınız var)` : ` (${r.limit}/${r.limit} kullanıldı)`}. Haklarınız ${fmtDate(r.resetsAt)} tarihinde yenilenir.`);
module.exports = { createScanQuota, targetKey, denyMessage, fmtWait };
