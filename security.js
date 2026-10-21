/* Digital Asset Center - Güvenlik katmanı
 * - Ortam ayrımı (varsayılan: ÜRETİM, güvenli)
 * - Backend'de kimlik doğrulama (Firebase ID token) + yalnızca geliştirmede test kullanıcısı
 * - CORS izin listesi
 * - Kullanıcı + IP bazlı hız sınırı, eşzamanlı tarama sınırı
 * - Varlık sahipliği (başkasının varlığı değiştirilemez) ve sunucu tarafı paket kotası
 */
"use strict";
const PLANS = require("./plans");

// NODE_ENV yalnızca "development" veya "test" ise geliştirme sayılır. Başka her durum ÜRETİM'dir.
const isProd = () => !["development", "test"].includes(String(process.env.NODE_ENV || "").toLowerCase());
// Sahte kullanıcı yalnızca üretim DEĞİLSE ve açıkça istenmişse çalışır.
const devBypass = () => !isProd() && process.env.DEV_AUTH_BYPASS === "true";
// Üretimde kontroller her zaman açık; geliştirmede ENFORCE_PLANS=false ile kapatılabilir.
const enforcePlans = () => isProd() || process.env.ENFORCE_PLANS === "true";

// ---------- CORS ----------
const DEFAULT_ORIGINS = ["https://dac-web-tfqf.onrender.com", "https://dac-web-yefr.onrender.com", "https://hz-yazilim.github.io"];
function allowedOrigins() {
  const extra = String(process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  const dev = isProd() ? [] : ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500"];
  return [...DEFAULT_ORIGINS, ...extra, ...dev];
}
const corsOptions = {
  origin(origin, cb) { cb(null, !origin || allowedOrigins().includes(origin)); }, // Origin yok = aynı site / sunucudan sunucuya
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 600
};

// ---------- Kimlik doğrulama ----------
// verifyUser: payments.verifyUser (Firebase ID token'ı Admin SDK ile doğrular)
function authenticate(verifyUser) {
  return async (req, res, next) => {
    try {
      if (devBypass()) { req.user = { uid: "dev-user", email: null, dev: true }; return next(); }
      req.user = await verifyUser(req);
      next();
    } catch (e) {
      res.status(e.status || 401).json({ success: false, error: e.message || "Giriş gerekli" });
    }
  };
}

// ---------- Hız sınırı (bellek içi; çoklu örnekte Redis gerekir) ----------
function makeLimiter(max, windowMs) {
  const hits = new Map();
  const t = setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(x => now - x < windowMs)) hits.delete(k); }, windowMs);
  if (t.unref) t.unref();
  return (key) => {
    const now = Date.now(); const arr = (hits.get(key) || []).filter(x => now - x < windowMs);
    if (arr.length >= max) { hits.set(key, arr); return false; }
    arr.push(now); hits.set(key, arr); return true;
  };
}
const int = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : d; };

// ---------- Eşzamanlılık ----------
function makeConcurrency(perUser, global) {
  const per = new Map(); let total = 0;
  return {
    acquire(uid) {
      if (total >= global || (per.get(uid) || 0) >= perUser) return null;
      total++; per.set(uid, (per.get(uid) || 0) + 1);
      let done = false;
      return () => { if (done) return; done = true; total--; const n = (per.get(uid) || 1) - 1; if (n <= 0) per.delete(uid); else per.set(uid, n); };
    },
    get total() { return total; }
  };
}

// ---------- Varlık sahipliği (transaction: eşzamanlı isteklerde de tutarlı) ----------
// true: kullanıcı bu varlığın sahibi (veya varlık sahipsiz/yeni olduğu için artık sahibi oldu). false: başkasına ait.
async function claimAsset(db, assetId, uid) {
  const ref = db.collection("assets").doc(assetId);
  return db.runTransaction(async (t) => {
    const s = await t.get(ref);
    const owner = s.exists ? s.data().ownerId : null;
    if (owner && owner !== uid) return { ok: false, isNew: false };
    if (!owner) t.set(ref, { ownerId: uid }, { merge: true });
    return { ok: true, isNew: !s.exists };
  });
}

// ---------- Paket kotası (sunucu tarafı) ----------
async function checkAssetQuota(db, uid, plan, isNew) {
  const limit = PLANS.PLANS[plan] ? PLANS.PLANS[plan].assets : 0; // null = sınırsız
  if (limit == null || !isNew) return { ok: true, limit };
  const snap = await db.collection("assets").where("ownerId", "==", uid).count().get();
  const used = snap.data().count;
  // Yeni varlık için ownerId zaten claimAsset ile yazıldı; kendisi sayıma dahil
  return { ok: used <= limit, used, limit };
}

module.exports = { isProd, devBypass, enforcePlans, corsOptions, allowedOrigins, authenticate, makeLimiter, makeConcurrency, claimAsset, checkAssetQuota, int };
