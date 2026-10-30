/* Digital Asset Center - Tarayıcı bildirimleri (Web Push)
 * - VAPID anahtarları: VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY ortam değişkenleri varsa onlar kullanılır;
 *   yoksa ilk açılışta otomatik üretilip Firestore'da config/vapid belgesine kaydedilir (istemci kuralları kapalı, yalnız sunucu okur).
 * - Abonelikler: pushSubs/{sha256(endpoint)} = { uid, sub, createdAt }
 * - Uç noktalar: GET /api/push/key • POST /api/push/subscribe • POST /api/push/unsubscribe • POST /api/push/test
 */
"use strict";
const crypto = require("crypto");
const SEC = require("./security");

module.exports = function initPush({ app, db, verifyUser }) {
  let webpush = null, keys = null, ready = null;
  try { webpush = require("web-push"); } catch { console.warn("web-push paketi yok: npm install web-push (bildirimler kapalı)"); }
  const idOf = (endpoint) => crypto.createHash("sha256").update(String(endpoint)).digest("hex").slice(0, 40);

  async function init() {
    if (!webpush || !db) return false;
    let pub = process.env.VAPID_PUBLIC_KEY, priv = process.env.VAPID_PRIVATE_KEY;
    if (!pub || !priv) {
      const ref = db.collection("config").doc("vapid"); const snap = await ref.get();
      if (snap.exists && snap.data().publicKey && snap.data().privateKey) ({ publicKey: pub, privateKey: priv } = snap.data());
      else { const k = webpush.generateVAPIDKeys(); pub = k.publicKey; priv = k.privateKey; await ref.set({ publicKey: pub, privateKey: priv, createdAt: Date.now() }); }
    }
    const contact = String(process.env.SECURITY_CONTACT || "").replace(/^mailto:/, "");
    const subject = process.env.VAPID_SUBJECT || (contact.includes("@") ? "mailto:" + contact : String(process.env.SITE_URL || "https://dacweb.tr"));
    webpush.setVapidDetails(subject, pub, priv);
    keys = { pub };
    return true;
  }
  const whenReady = () => (ready || (ready = init().catch((e) => { console.error("Push başlatılamadı:", e.message); ready = null; return false; })));

  async function subsOf(uid) {
    const snap = await db.collection("pushSubs").where("uid", "==", uid).get();
    return snap.docs.map((d) => ({ id: d.id, sub: d.data().sub }));
  }
  // Kullanıcının tüm cihazlarına bildirim gönderir; süresi dolmuş (404/410) abonelikleri siler. Başarılı gönderim sayısını döner.
  async function notify(uid, payload, subs) {
    if (!(await whenReady())) return 0;
    const list = subs || await subsOf(uid); let ok = 0;
    await Promise.all(list.map(async (s) => {
      try { await webpush.sendNotification(s.sub, JSON.stringify(payload), { TTL: 86400, urgency: "high" }); ok++; }
      catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await db.collection("pushSubs").doc(s.id).delete().catch(() => {}); else console.warn("push gönderilemedi:", e.statusCode || e.message); }
    }));
    return ok;
  }

  if (app) {
    const lim = SEC.makeLimiter(SEC.int(process.env.PUSH_RATE_LIMIT, 30), 10 * 60 * 1000);
    const guard = [SEC.authenticate(verifyUser), (req, res, next) => (lim(req.user.uid) ? next() : res.status(429).json({ success: false, error: "Çok fazla istek. Biraz sonra tekrar deneyin." }))];
    const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { console.error("push:", e.message); res.status(e.status || 500).json({ success: false, error: e.status ? e.message : "Sunucu hatası" }); } };

    app.get("/api/push/key", guard, wrap(async (req, res) => {
      if (!(await whenReady())) return res.status(503).json({ success: false, error: "Bildirim servisi hazır değil." });
      res.set("Cache-Control", "no-store"); res.json({ success: true, key: keys.pub });
    }));
    app.post("/api/push/subscribe", guard, wrap(async (req, res) => {
      if (!(await whenReady())) return res.status(503).json({ success: false, error: "Bildirim servisi hazır değil." });
      const sub = req.body && req.body.subscription;
      if (!sub || typeof sub.endpoint !== "string" || !/^https:\/\//.test(sub.endpoint) || sub.endpoint.length > 1000 || !sub.keys || typeof sub.keys.p256dh !== "string" || typeof sub.keys.auth !== "string") return res.status(400).json({ success: false, error: "Geçersiz abonelik." });
      const clean = { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh.slice(0, 200), auth: sub.keys.auth.slice(0, 100) } };
      const count = (await db.collection("pushSubs").where("uid", "==", req.user.uid).count().get()).data().count;
      if (count >= 10) return res.status(400).json({ success: false, error: "En fazla 10 cihaz için bildirim açılabilir." });
      await db.collection("pushSubs").doc(idOf(clean.endpoint)).set({ uid: req.user.uid, sub: clean, createdAt: Date.now(), ua: String(req.headers["user-agent"] || "").slice(0, 200) });
      // Bildirim açıldı: kullanıcının varlıkları bir sonraki zamanlayıcı turunda hemen taransın
      try { const a = await db.collection("assets").where("ownerId", "==", req.user.uid).limit(500).get(); const b = db.batch(); a.docs.forEach((d) => b.set(d.ref, { nextScanAt: Date.now() }, { merge: true })); await b.commit(); } catch { /* önemli değil */ }
      res.json({ success: true });
    }));
    app.post("/api/push/unsubscribe", guard, wrap(async (req, res) => {
      const ep = req.body && req.body.endpoint; if (typeof ep !== "string") return res.status(400).json({ success: false, error: "Geçersiz istek." });
      const ref = db.collection("pushSubs").doc(idOf(ep)); const s = await ref.get();
      if (s.exists && s.data().uid === req.user.uid) await ref.delete();
      res.json({ success: true });
    }));
    app.post("/api/push/test", guard, wrap(async (req, res) => {
      const n = await notify(req.user.uid, { title: "✅ Bildirimler çalışıyor", body: "Digital Asset Center artık kritik durumları size anında bildirecek.", url: "/#assets", tag: "test" });
      res.json({ success: n > 0, sent: n, error: n ? undefined : "Bu hesaba kayıtlı çalışan bir cihaz bulunamadı. Bildirimi kapatıp tekrar açın." });
    }));
  }
  return { notify, subsOf, whenReady, idOf };
};
