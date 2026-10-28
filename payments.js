/* Digital Asset Center - Ödeme ve abonelik altyapısı (PayTR)
 * TL ve (isteğe bağlı) USD -> PayTR iFrame API. Her ödeme TEK SEFERLİK dönem bedelidir (otomatik yenileme yoktur):
 * süre dolmadan yeniden satın alınarak uzatılır.
 * Gerekli ortam değişkenleri (Render > Environment):
 *   FIREBASE_SERVICE_ACCOUNT   (zorunlu: kullanıcı doğrulama + abonelik kaydı)
 *   PAYTR_MERCHANT_ID, PAYTR_MERCHANT_KEY, PAYTR_MERCHANT_SALT   (PayTR mağaza paneli > Bilgi)
 *   PAYTR_TEST_MODE=1        (opsiyonel: test modu; canlıda boş bırakın veya 0)
 *   PAYTR_USD=true           (opsiyonel: PayTR hesabınızda yabancı para birimi açıksa USD ödemesini etkinleştirir)
 *   PAYTR_NO_INSTALLMENT=1   (opsiyonel, varsayılan 1: taksit yok) / PAYTR_MAX_INSTALLMENT=0 / PAYTR_TIMEOUT_MIN=30
 *   PAYTR_DEFAULT_PHONE      (opsiyonel: kullanıcı telefon girmediyse PayTR'ye gönderilecek yer tutucu)
 *   ENFORCE_PLANS=true (opsiyonel: süresi biten deneme kullanıcılarının taramasını sunucuda da engeller)
 * PayTR panelinde (Destek & Kurulum > Ayarlar > Bildirim URL Ayarları) şu adresi tanımlayın:  https://<API adresiniz>/api/paytr/callback
 */
const crypto = require("crypto");
const PLANS = (() => { try { return require("../public/js/plans"); } catch (e) { return require("./plans"); } })(); // klasörlü (public/js) veya düz yerleşim
const SEC = require("./security");

const PAYTR_TOKEN_URL = "https://www.paytr.com/odeme/api/get-token";
const PAYTR_REFUND_URL = "https://www.paytr.com/odeme/iade";
const PAYTR_PAGE_URL = "https://www.paytr.com/odeme/guvenli/";
const PAID_PROVIDERS = ["paytr", "stripe", "iyzico"]; // stripe/iyzico: eski kayıtlar (yeni satış yalnızca PayTR)

module.exports = function initPayments({ app, db, admin, http, commerce = null, mailer = null }) {
  const fail = (status, message) => Object.assign(new Error(message), { status });
  const env = (k) => String(process.env[k] || "").trim();
  const paytrReady = () => !!(env("PAYTR_MERCHANT_ID") && env("PAYTR_MERCHANT_KEY") && env("PAYTR_MERCHANT_SALT"));
  const usdReady = () => paytrReady() && env("PAYTR_USD").toLowerCase() === "true";
  const testMode = () => (env("PAYTR_TEST_MODE") === "1" || env("PAYTR_TEST_MODE").toLowerCase() === "true" ? "1" : "0");
  // PayTR henüz bağlı değilse "Satın al" paketi doğrudan etkinleştirir (geçici test dönemi).
  // PayTR anahtarlarını Render > Environment'a ekleyince bu mod OTOMATİK kapanır; tamamen kapatmak için ALLOW_FREE_ACTIVATION=false yazın.
  const freeMode = () => process.env.ALLOW_FREE_ACTIVATION !== "false" && !paytrReady();
  const status = () => ({ paytr: paytrReady(), usd: usdReady(), auth: !!(admin && admin.apps && admin.apps.length && db), enforced: process.env.ENFORCE_PLANS === "true", free: freeMode() });
  const handler = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { console.error("payments:", e.message); const code = e.status || 500; res.status(code).json({ success: false, error: code >= 500 && !e.status ? "Sunucu hatası" : e.message, ...(e.pcode ? { code: e.pcode } : {}), ...(e.extra || {}) }); } };

  // ---------- Kullanıcı doğrulama ----------
  async function verifyUser(req) {
    if (!db || !admin.apps.length) throw fail(503, "Sunucuda Firebase yapılandırılmamış (FIREBASE_SERVICE_ACCOUNT gerekli).");
    const m = String(req.headers.authorization || "").match(/^Bearer (.+)$/i);
    if (!m) throw fail(401, "Giriş yapmanız gerekiyor.");
    // VERIFY_REVOKED=true: iptal edilmiş/çıkış yapılmış oturumlar da reddedilir (her istekte ek bir Firebase çağrısı yapar)
    let t; try { t = await admin.auth().verifyIdToken(m[1], process.env.VERIFY_REVOKED === "true"); } catch { throw fail(401, "Oturum doğrulanamadı, tekrar giriş yapın."); }
    SEC.assertEmailVerified(t); // şifreli hesapta doğrulanmamış e-posta → 403 EMAIL_NOT_VERIFIED
    return { uid: t.uid, email: t.email || null, name: t.name || null, emailVerified: t.email_verified === true };
  }

  // E-posta normalleştirme: küçük harf, +etiket atılır; gmail/googlemail için noktalar da atılır
  function trialHash(email) {
    let e = String(email || "").trim().toLowerCase(); const m = /^([^@\s]+)@([^@\s]+)$/.exec(e); if (!m) return null;
    let local = m[1].split("+")[0], dom = m[2]; if (dom === "googlemail.com") dom = "gmail.com"; if (dom === "gmail.com") local = local.replace(/\./g, "");
    return crypto.createHash("sha256").update((process.env.TRIAL_PEPPER || "dac-trial-v1") + "|" + local + "@" + dom).digest("hex").slice(0, 40);
  }
  // ---------- Yetki: abonelik > deneme > süresi dolmuş ----------
  async function getEntitlement(uid) {
    const now = Date.now();
    const sub = (await db.collection("subscriptions").doc(uid).get()).data();
    if (sub && PLANS.PAID.includes(sub.plan) && sub.status === "active" && (!sub.periodEnd || sub.periodEnd > now))
      return { plan: sub.plan, status: "active", periodEnd: sub.periodEnd || null, provider: sub.provider || null, currency: sub.currency || null, cycle: sub.cycle || null, cancelAtPeriodEnd: sub.cancelAtPeriodEnd === true };
    const uref = db.collection("users").doc(uid);
    let u = (await uref.get()).data() || {};
    if (!u.trialStart) {
      if (commerce && !(await commerce.registrationOpen())) throw fail(403, "Yeni kayıtlar geçici olarak kapalı.");
      // Deneme suistimali: aynı e-posta (takma ad/nokta/+etiket normalleştirilmiş) daha önce başka bir hesapla deneme aldıysa bu hesap denemeyi almaz.
      // Yalnızca tuzlanmış SHA-256 özeti saklanır (`trialUsed/{özet}`); hesap silinse bile kayıt kalır (aydınlatma metninde belirtilmelidir).
      let blocked = false;
      try {
        const em = admin && admin.apps.length ? (await admin.auth().getUser(uid)).email : null; const h = trialHash(em);
        if (h) { const tr = db.collection("trialUsed").doc(h), snap = await tr.get(); if (snap.exists && snap.data().uid !== uid) blocked = true; else if (!snap.exists) await tr.set({ uid, at: now }); }
      } catch { /* e-posta okunamadı: engelleme yapılmaz */ }
      u.trialStart = blocked ? now - (PLANS.TRIAL_DAYS + 1) * 864e5 : now; await uref.set({ trialStart: u.trialStart, ...(blocked ? { trialBlocked: true } : {}) }, { merge: true });
    }
    const trialEnd = u.trialStart + PLANS.TRIAL_DAYS * 864e5;
    if (now < trialEnd) return { plan: "trial", status: "trial", trialStart: u.trialStart, trialEnd };
    return { plan: "expired", status: sub && sub.status ? sub.status : "expired", trialStart: u.trialStart, trialEnd, lastPlan: sub ? sub.plan : null };
  }
  const activate = (uid, data) => db.collection("subscriptions").doc(uid).set({ ...data, updatedAt: Date.now() }, { merge: true });

  // ---------- Yardımcılar ----------
  // X-Forwarded-For istemci tarafından sahtelenebilir; Express'in "trust proxy" ile çözdüğü req.ip kullanılır.
  const clientIp = (req) => String(req.ip || req.socket.remoteAddress || "").replace(/^::ffff:/, "") || "0.0.0.0";
  const payLimiter = SEC.makeLimiter(SEC.int(process.env.PAY_RATE_LIMIT, 20), 10 * 60 * 1000);
  const payGuard = (req, res, next) => (payLimiter(req.ip) ? next() : res.status(429).json({ success: false, error: "Çok fazla istek. Biraz sonra tekrar deneyin." }));
  const LEGAL_VERSION = process.env.LEGAL_VERSION || "2026-10";
  const returnUrlOf = (req) => {
    const origin = req.get("origin");
    if (!origin || !SEC.allowedOrigins().includes(origin)) throw fail(400, "Geçersiz istek kaynağı.");
    let p = String((req.body && req.body.returnPath) || "/").replace(/[^\x21-\x7e]/g, "").slice(0, 200);
    if (!p.startsWith("/") || p.startsWith("//")) p = "/";
    return origin + p;
  };
  const withParam = (u, k, v) => u + (u.includes("?") ? "&" : "?") + k + "=" + v;
  const paytrCur = (c) => (c === "USD" ? "USD" : "TL");

  /* ---------- PayTR imza yardımcıları ----------
   * get-token : base64( HMAC-SHA256( merchant_id+user_ip+merchant_oid+email+payment_amount+user_basket+no_installment+max_installment+currency+test_mode + merchant_salt , merchant_key ) )
   * bildirim  : base64( HMAC-SHA256( merchant_oid + merchant_salt + status + total_amount , merchant_key ) )
   * iade      : base64( HMAC-SHA256( merchant_id + merchant_oid + return_amount + merchant_salt , merchant_key ) ) */
  const hmac64 = (data) => crypto.createHmac("sha256", env("PAYTR_MERCHANT_KEY")).update(data).digest("base64");
  const paytrFormPost = async (url, fields) => {
    const r = await http.request({ method: "POST", url, data: new URLSearchParams(fields).toString(), headers: { "Content-Type": "application/x-www-form-urlencoded" }, validateStatus: () => true, timeout: 20000 });
    let d = r.data; if (typeof d === "string") { try { d = JSON.parse(d); } catch { d = null; } }
    return { http: r.status, data: d || {} };
  };
  function verifyPaytrNotification(b) {
    if (!b || !paytrReady() || typeof b.hash !== "string" || b.hash.length > 100) return false;
    const expected = hmac64(String(b.merchant_oid || "") + env("PAYTR_MERCHANT_SALT") + String(b.status || "") + String(b.total_amount || ""));
    const a = Buffer.from(b.hash), e = Buffer.from(expected);
    return a.length === e.length && crypto.timingSafeEqual(a, e);
  }

  // ---------- Abonelik durumu ----------
  app.get("/api/subscription", payGuard, handler(async (req, res) => {
    const u = await verifyUser(req);
    res.json({ success: true, ...(await getEntitlement(u.uid)), serverTime: Date.now() });
  }));

  // ---------- Ödeme başlat ----------
  app.post("/api/checkout", payGuard, handler(async (req, res) => {
    const u = await verifyUser(req);
    const { plan, cycle = "monthly", currency = "TRY", billing = {}, consent, coupon, expectedAmount } = req.body || {};
    // 6502 sayılı Kanun / Mesafeli Sözleşmeler Yönetmeliği: ön bilgilendirme + satış sözleşmesi onayı ve anında ifa edilen dijital hizmette cayma hakkı beyanı
    if (!consent || consent.distanceSales !== true || consent.withdrawalWaiver !== true) throw fail(400, "Ödeme için Ön Bilgilendirme Formu, Mesafeli Satış Sözleşmesi ve cayma hakkı beyanını onaylamalısınız.");
    if (!u.email && !(billing && billing.email)) throw fail(400, "Ödeme için e-posta adresi gerekli.");
    // Sunucu tarafı fatura alanı doğrulaması (TC kimlik numarası toplanmaz; yalnızca isteğe bağlı 10 haneli vergi no)
    if (billing && typeof billing === "object") {
      const V = (() => { try { return require("./validators"); } catch { return require("./server/validators"); } })();
      if (billing.phone) { const r = V.normalizePhone(String(billing.phone)); if (!r.ok) throw fail(400, "Telefon: " + r.error); billing.phone = r.phone; }
      if (billing.taxId) { const r = V.normalizeTaxId(billing.taxId); if (!r.ok) throw fail(400, "Vergi no: " + r.error); billing.taxId = r.taxId; }
    }
    if (!PLANS.PAID.includes(plan)) throw fail(400, "Geçersiz paket.");
    if (!["monthly", "yearly"].includes(cycle)) throw fail(400, "Geçersiz dönem.");
    await db.collection("consents").add({ uid: u.uid, type: "distance-sales", version: LEGAL_VERSION, granted: true, plan: String(plan).slice(0, 30), at: Date.now(), ip: req.ip || null, ua: String(req.headers["user-agent"] || "").slice(0, 200) });
    await db.collection("consents").add({ uid: u.uid, type: "withdrawal-waiver", version: LEGAL_VERSION, granted: true, plan: String(plan).slice(0, 30), at: Date.now(), ip: req.ip || null, ua: String(req.headers["user-agent"] || "").slice(0, 200) });
    const P = PLANS.PLANS[plan]; const cur = currency === "USD" ? "USD" : "TRY";
    if (commerce) await commerce.ensureFresh(5000); // yönetici panelinden değişen fiyat/kupon anında geçerli olsun
    const listAmount = PLANS.price(plan, cur, cycle); let amount = listAmount, couponInfo = null;
    if (coupon) { if (!commerce) throw fail(400, "Kupon sistemi etkin değil."); couponInfo = await commerce.quoteCoupon(coupon, { plan, cycle, currency: cur, uid: u.uid }); amount = couponInfo.finalAmount; }
    // Ekranda görülen tutar ile sunucunun alacağı tutar farklıysa (fiyat az önce değişti) ödeme başlatılmaz
    if (expectedAmount != null && (!Number.isFinite(Number(expectedAmount)) || Math.abs(Number(expectedAmount) - amount) > 0.009)) throw Object.assign(fail(409, "Fiyat güncellendi. Yeni tutarı kontrol edip tekrar deneyin."), { pcode: "PRICE_CHANGED", extra: { amount, listAmount } });
    const back = returnUrlOf(req);
    const label = `Digital Asset Center - ${P.name} (${cycle === "yearly" ? "Yıllık" : "Aylık"})`;

    let redeemed = false;
    if (couponInfo) { await commerce.redeemCoupon(couponInfo.code, u.uid); redeemed = true; }
    try {
    // PayTR henüz bağlanmadı: paketi doğrudan ver (kart bilgisi istenmez). PayTR anahtarları girilince bu blok devre dışı kalır.
    if (freeMode()) {
      const sub0 = (await db.collection("subscriptions").doc(u.uid).get()).data() || {};
      const startFrom = sub0.status === "active" && sub0.periodEnd > Date.now() && sub0.plan === plan ? sub0.periodEnd : Date.now();
      const periodEnd = startFrom + (cycle === "yearly" ? 365 : 30) * 864e5;
      await activate(u.uid, { plan, status: "active", provider: "manual", currency: cur, cycle, periodEnd, free: true, cancelAtPeriodEnd: false });
      await db.collection("orders").add({ uid: u.uid, plan, cycle, currency: cur, amount, status: "activated-free", consentVersion: LEGAL_VERSION, createdAt: Date.now(), ...(couponInfo ? { couponCode: couponInfo.code, listAmount, discount: couponInfo.discount } : {}) });
      return res.json({ success: true, activated: true, plan, periodEnd, provider: "manual" });
    }

    if (!paytrReady()) throw fail(503, "Ödeme henüz yapılandırılmadı (PAYTR_MERCHANT_ID / PAYTR_MERCHANT_KEY / PAYTR_MERCHANT_SALT).");
    if (cur === "USD" && !usdReady()) throw fail(503, "USD ödemesi etkin değil. TL ile ödeme yapabilirsiniz.");
    if (!(amount > 0)) throw fail(400, "Ödenecek tutar sıfırdan büyük olmalıdır.");

    // PayTR zorunlu alanları (ad, adres, telefon) hesaptan türetilir; kullanıcı Ayarlar > Fatura Bilgileri'ni doldurduysa o değerler kullanılır
    const email = String(billing.email || u.email).trim().slice(0, 100);
    const mailName = String(u.email || billing.email || "musteri").split("@")[0].replace(/[._-]+/g, " ").trim() || "Musteri";
    const name = String(billing.name || u.name || (mailName.includes(" ") ? mailName : mailName + " Kullanici")).trim().slice(0, 60);
    const address = String(billing.address || "Dijital hizmet - adres beyan edilmedi").trim().slice(0, 200);
    const phone = String(billing.phone || env("PAYTR_DEFAULT_PHONE") || "05000000000").slice(0, 20);
    const orderRef = db.collection("orders").doc(); // PayTR merchant_oid: yalnızca harf/rakam olmalı (Firestore kimliği uygundur)
    const payAmount = String(Math.round(amount * 100)); // kuruş / cent
    const basket = Buffer.from(JSON.stringify([[label, amount.toFixed(2), 1]])).toString("base64");
    const noInst = env("PAYTR_NO_INSTALLMENT") === "0" ? "0" : "1", maxInst = noInst === "1" ? "0" : String(Math.max(0, Math.min(12, parseInt(env("PAYTR_MAX_INSTALLMENT") || "0", 10) || 0)));
    const currencyP = paytrCur(cur), tm = testMode(), ip = clientIp(req);
    await orderRef.set({ uid: u.uid, plan, cycle, currency: cur, amount, provider: "paytr", status: "pending", returnUrl: back, consentVersion: LEGAL_VERSION, createdAt: Date.now(), ...(couponInfo ? { couponCode: couponInfo.code, listAmount, discount: couponInfo.discount } : {}) });
    const paytr_token = hmac64(env("PAYTR_MERCHANT_ID") + ip + orderRef.id + email + payAmount + basket + noInst + maxInst + currencyP + tm + env("PAYTR_MERCHANT_SALT"));
    const r = await paytrFormPost(PAYTR_TOKEN_URL, {
      merchant_id: env("PAYTR_MERCHANT_ID"), user_ip: ip, merchant_oid: orderRef.id, email, payment_amount: payAmount, paytr_token, user_basket: basket,
      debug_on: tm === "1" ? "1" : "0", no_installment: noInst, max_installment: maxInst, user_name: name, user_address: address, user_phone: phone,
      merchant_ok_url: withParam(back, "paid", "1"), merchant_fail_url: withParam(back, "paid", "0"),
      timeout_limit: String(Math.max(1, Math.min(1440, parseInt(env("PAYTR_TIMEOUT_MIN") || "30", 10) || 30))), currency: currencyP, test_mode: tm, lang: "tr"
    });
    if (r.data.status !== "success" || !r.data.token) {
      await orderRef.set({ status: "failed", gatewayStatus: String(r.data.reason || "token alınamadı").slice(0, 200) }, { merge: true });
      throw fail(502, "PayTR: " + (r.data.reason || "ödeme formu oluşturulamadı"));
    }
    await orderRef.set({ paytrToken: String(r.data.token).slice(0, 100) }, { merge: true });
    res.json({ success: true, provider: "paytr", url: PAYTR_PAGE_URL + encodeURIComponent(r.data.token), orderId: orderRef.id });
    } catch (e) { if (redeemed) await commerce.releaseCoupon(couponInfo.code, u.uid).catch(() => {}); throw e; } // ödeme başlatılamadıysa kupon hakkı iade edilir
  }));

  // Makbuz e-postası (en iyi çaba; hata ödeme akışını bozmaz)
  function sendReceipt(uid, o) {
    if (!mailer || !mailer.enabled() || !admin || !admin.apps.length) return;
    (async () => { const u = await admin.auth().getUser(uid); if (!u.email || !u.emailVerified) return; const m = mailer.tpl.receipt({ planName: (PLANS.PLANS[o.plan] || {}).name || o.plan, ...o }); await mailer.send({ to: u.email, ...m, type: "receipt", uid, dedupeKey: o.dedupe || null }); })().catch(() => {});
  }

  // ---------- PayTR bildirimi (sunucudan sunucuya POST; PayTR panelindeki "Bildirim URL"si) ----------
  // Yanıt düz metin "OK" olmalıdır; aksi halde PayTR bildirimi tekrar tekrar gönderir. İmza doğrulanmadan hiçbir kayıt değiştirilmez.
  app.post("/api/paytr/callback", handler(async (req, res) => {
    if (!paytrReady() || !db) throw fail(503, "PayTR yapılandırılmadı.");
    const b = req.body || {};
    if (!verifyPaytrNotification(b)) throw fail(400, "PAYTR notification failed: bad hash");
    const ok = () => res.type("text/plain").send("OK");
    const oid = String(b.merchant_oid || ""); if (!/^[A-Za-z0-9]{10,40}$/.test(oid)) return ok();
    const ref = db.collection("orders").doc(oid), order = (await ref.get()).data();
    if (!order || order.provider !== "paytr") return ok(); // bilinmeyen sipariş: tekrar denemesin diye OK
    if (order.status === "paid") return ok();              // yinelenen bildirim

    if (b.status !== "success") {
      const reason = String(b.failed_reason_msg || b.failed_reason_code || "failed").slice(0, 200);
      await ref.set({ status: "failed", gatewayStatus: reason }, { merge: true });
      if (commerce && order.couponCode && order.status !== "failed") await commerce.releaseCoupon(order.couponCode, order.uid).catch(() => {});
      return ok();
    }
    // Tutar ve para birimi, sunucunun kaydettiği siparişle eşleşmeli (taksit/komisyon varsa toplam ≥ sipariş tutarı)
    const total = Number(b.total_amount), need = Math.round(Number(order.amount) * 100);
    const curOk = !b.currency || String(b.currency).toUpperCase() === paytrCur(order.currency);
    if (!(total >= need) || !curOk) {
      console.error("payments: PayTR tutar/para birimi uyuşmazlığı", oid, total, need, b.currency);
      await ref.set({ status: "failed", gatewayStatus: "TUTAR_UYUSMAZLIGI", paytrTotal: Number.isFinite(total) ? total : null }, { merge: true });
      return ok();
    }
    // Tekrar/eşzamanlı bildirim süreyi iki kez uzatmasın: sipariş durumu transaction içinde "paid"e çekilir
    const first = await db.runTransaction(async (t) => { const o = (await t.get(ref)).data(); if (!o || o.status === "paid") return false; t.set(ref, { status: "paid", paidAt: Date.now(), gatewayStatus: "paytr", paytrTotal: total, paymentType: String(b.payment_type || "").slice(0, 20), ...(b.test_mode === "1" || b.test_mode === 1 ? { testPayment: true } : {}) }, { merge: true }); return true; });
    if (first) {
      const cur = (await db.collection("subscriptions").doc(order.uid).get()).data() || {};
      const startFrom = cur.status === "active" && cur.periodEnd > Date.now() && cur.plan === order.plan ? cur.periodEnd : Date.now();
      const periodEnd = startFrom + (order.cycle === "yearly" ? 365 : 30) * 864e5;
      await activate(order.uid, { plan: order.plan, status: "active", provider: "paytr", currency: order.currency === "USD" ? "USD" : "TRY", cycle: order.cycle, periodEnd, cancelAtPeriodEnd: false });
      sendReceipt(order.uid, { plan: order.plan, cycle: order.cycle, amount: order.amount, currency: order.currency === "USD" ? "USD" : "TRY", periodEnd, couponCode: order.couponCode, dedupe: "rcpt_" + oid });
    }
    ok();
  }));

  /* ---------- Yönetici işlemleri: iade ve abonelik iptali (admin-ops.js çağırır) ---------- */
  async function refundOrder(order, orderId, amount) {
    const full = Number(order.amount), already = Number(order.refundedAmount || 0), left = Math.round((full - already) * 100) / 100;
    const amt = amount == null ? left : Math.round(Number(amount) * 100) / 100;
    if (!(amt > 0) || amt > left + 0.001) throw fail(400, `İade tutarı geçersiz (iade edilebilir: ${left})`);
    if (order.provider !== "paytr") throw fail(409, "Bu sipariş eski ödeme sağlayıcısıyla (Stripe/iyzico) alınmış; iadeyi o sağlayıcının panelinden yapın.");
    if (!paytrReady()) throw fail(503, "PayTR yapılandırılmadı.");
    const ret = amt.toFixed(2);
    const r = await paytrFormPost(PAYTR_REFUND_URL, {
      merchant_id: env("PAYTR_MERCHANT_ID"), merchant_oid: orderId, return_amount: ret,
      paytr_token: hmac64(env("PAYTR_MERCHANT_ID") + orderId + ret + env("PAYTR_MERCHANT_SALT")),
      reference_no: ("R" + orderId + Math.round((already + amt) * 100)).replace(/[^A-Za-z0-9]/g, "").slice(0, 64) // aynı iade tekrarlanırsa PayTR'de eşleşir
    });
    if (r.data.status !== "success") throw fail(502, "PayTR: " + (r.data.err_msg || r.data.reason || "iade başarısız"));
    return { provider: "paytr", method: "refund", amount: amt };
  }
  // Abonelik iptali (yönetici ve kullanıcı ortak): immediate=false → dönem sonunda biter (yenilenmez, ödenmiş dönem geçerli kalır); immediate=true → hemen sonlanır.
  // PayTR ödemeleri tek seferlik dönem bedelidir: sağlayıcıda iptal edilecek bir yenileme yoktur, yalnızca iptal bayrağı (cancelAtPeriodEnd) kaydedilir.
  async function cancelSubscription(uid, immediate, by = "admin") {
    const sub = (await db.collection("subscriptions").doc(uid).get()).data(); if (!sub) throw fail(404, "Abonelik bulunamadı");
    const mark = { cancelAtPeriodEnd: true, cancelRequestedAt: Date.now(), cancelRequestedBy: by };
    if (immediate) { await activate(uid, { status: "canceled", periodEnd: Date.now(), ...mark, cancelAtPeriodEnd: false }); return { provider: sub.provider || "manual", immediate: true }; }
    await activate(uid, mark);
    return { provider: sub.provider || "manual", immediate: false, periodEnd: sub.periodEnd || null, note: "Abonelik iptal edildi: yenilenmeyecek, süresi dolunca sona erecek (şimdiki dönem geçerli kalır)." };
  }
  // Dönem sonu iptalini geri alır (yalnızca hâlâ aktif ve süresi dolmamış abonelikte).
  async function resumeSubscription(uid) {
    const sub = (await db.collection("subscriptions").doc(uid).get()).data(); if (!sub) throw fail(404, "Abonelik bulunamadı");
    if (!(sub.status === "active" && (!sub.periodEnd || sub.periodEnd > Date.now()))) throw fail(409, "Abonelik artık aktif değil; yeniden satın alın.");
    await activate(uid, { cancelAtPeriodEnd: false, cancelRequestedAt: null, cancelRequestedBy: null });
    return { provider: sub.provider || "manual", note: "İptal geri alındı." };
  }

  /* ---------- Kullanıcının kendi aboneliğini iptali ---------- */
  // Ödeme sağlayıcılı (PayTR) pakette kullanıcı yalnızca DÖNEM SONUNDA iptal edebilir; hemen sonlandırma/iade yönetici işlemidir (Destek talebi açılır).
  // Ödemesiz (yönetici verdiği/test etkinleştirmesi) pakette kullanıcı isterse hemen sonlandırabilir.
  app.post("/api/subscription/cancel", payGuard, handler(async (req, res) => {
    const u = await verifyUser(req), sub = (await db.collection("subscriptions").doc(u.uid).get()).data();
    if (!sub || !PLANS.PAID.includes(sub.plan) || sub.status !== "active" || (sub.periodEnd && sub.periodEnd <= Date.now())) throw fail(409, "İptal edilecek aktif bir ücretli paketiniz yok.");
    const providerPaid = PAID_PROVIDERS.includes(sub.provider), immediate = !providerPaid && (req.body || {}).immediate === true;
    if (!immediate && sub.cancelAtPeriodEnd === true) return res.json({ success: true, already: true, immediate: false, periodEnd: sub.periodEnd || null, note: "Abonelik zaten iptal edilmiş; dönem sonunda sona erecek." });
    const r = await cancelSubscription(u.uid, immediate, "user"); console.log("payments: kullanıcı aboneliği iptal etti", u.uid, r.provider, r.immediate ? "hemen" : "dönem sonu");
    res.json({ success: true, ...r });
  }));
  app.post("/api/subscription/resume", payGuard, handler(async (req, res) => {
    const u = await verifyUser(req); const r = await resumeSubscription(u.uid); res.json({ success: true, ...r });
  }));

  return { verifyUser, getEntitlement, status, verifyPaytrNotification, refundOrder, cancelSubscription, resumeSubscription, trialHash };
};
