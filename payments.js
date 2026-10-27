/* Digital Asset Center - Ödeme ve abonelik altyapısı
 * TL  -> iyzico (Checkout Form)      USD -> Stripe (Checkout, aylık/yıllık abonelik)
 * Gerekli ortam değişkenleri (Render > Environment):
 *   FIREBASE_SERVICE_ACCOUNT   (zorunlu: kullanıcı doğrulama + abonelik kaydı; varlik-operasyonlari-ed334 projesine ait olmalı)
 *   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET            (USD için)
 *   IYZICO_API_KEY, IYZICO_SECRET_KEY, IYZICO_BASE_URL   (TL için; canlıda https://api.iyzipay.com)
 *   PUBLIC_API_URL   (opsiyonel: Render adresin, ör. https://dac-web-yefr.onrender.com)
 *   ENFORCE_PLANS=true (opsiyonel: süresi biten deneme kullanıcılarının taramasını sunucuda da engeller)
 */
const crypto = require("crypto");
const PLANS = (() => { try { return require("../public/js/plans"); } catch (e) { return require("./plans"); } })(); // klasörlü (public/js) veya düz yerleşim
const SEC = require("./security");

module.exports = function initPayments({ app, db, admin, http, commerce = null, mailer = null }) {
  const fail = (status, message) => Object.assign(new Error(message), { status });
  const stripeKey = () => process.env.STRIPE_SECRET_KEY || null;
  const iyziReady = () => !!(process.env.IYZICO_API_KEY && process.env.IYZICO_SECRET_KEY);
  // Ödeme sağlayıcısı (iyzico / Stripe) henüz bağlı değilse "Satın al" paketi doğrudan etkinleştirir.
  // Ödeme anahtarlarını Render > Environment'a ekleyince bu mod o para birimi için OTOMATİK kapanır; tamamen kapatmak için ALLOW_FREE_ACTIVATION=false yazın.
  const freeMode = () => process.env.ALLOW_FREE_ACTIVATION !== "false";
  const providerReady = (currency) => (currency === "USD" ? !!stripeKey() && !!process.env.STRIPE_WEBHOOK_SECRET : iyziReady());
  const status = () => ({ stripe: !!stripeKey() && !!process.env.STRIPE_WEBHOOK_SECRET, iyzico: iyziReady(), auth: !!(admin && admin.apps && admin.apps.length && db), enforced: process.env.ENFORCE_PLANS === "true", free: freeMode() });
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
      return { plan: sub.plan, status: "active", periodEnd: sub.periodEnd || null, provider: sub.provider || null, currency: sub.currency || null, cycle: sub.cycle || null };
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
  const selfUrl = (req) => process.env.PUBLIC_API_URL || `${req.headers["x-forwarded-proto"] || req.protocol}://${req.get("host")}`;
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
  function toForm(obj, prefix, out = []) {
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined || v === null) continue;
      const key = prefix ? `${prefix}[${k}]` : k;
      if (Array.isArray(v)) v.forEach((x, i) => (typeof x === "object" ? toForm(x, `${key}[${i}]`, out) : out.push(`${encodeURIComponent(`${key}[${i}]`)}=${encodeURIComponent(x)}`)));
      else if (typeof v === "object") toForm(v, key, out);
      else out.push(`${encodeURIComponent(key)}=${encodeURIComponent(v)}`);
    }
    return out;
  }
  async function stripeApi(method, path, params, extraHeaders = {}) {
    const r = await http.request({ method, url: "https://api.stripe.com/v1" + path, auth: { username: stripeKey(), password: "" }, data: params ? toForm(params).join("&") : undefined, headers: { "Content-Type": "application/x-www-form-urlencoded", ...extraHeaders }, validateStatus: () => true, timeout: 15000 });
    if (r.status >= 400) throw fail(502, "Stripe: " + (r.data?.error?.message || r.status));
    return r.data;
  }
  const periodEndOf = (sub) => ((sub.current_period_end ?? sub.items?.data?.[0]?.current_period_end) || 0) * 1000 || null;

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
    // Ödeme henüz entegre değil: paketi doğrudan ver (kart bilgisi istenmez). Sağlayıcı bağlanınca bu blok devre dışı kalır.
    if (!providerReady(currency === "USD" ? "USD" : "TRY") && freeMode()) {
      const cur = (await db.collection("subscriptions").doc(u.uid).get()).data() || {};
      const startFrom = cur.status === "active" && cur.periodEnd > Date.now() && cur.plan === plan ? cur.periodEnd : Date.now();
      const periodEnd = startFrom + (cycle === "yearly" ? 365 : 30) * 864e5;
      await activate(u.uid, { plan, status: "active", provider: "manual", currency: currency === "USD" ? "USD" : "TRY", cycle, periodEnd, free: true });
      await db.collection("orders").add({ uid: u.uid, plan, cycle, currency: currency === "USD" ? "USD" : "TRY", amount, status: "activated-free", consentVersion: LEGAL_VERSION, createdAt: Date.now(), ...(couponInfo ? { couponCode: couponInfo.code, listAmount, discount: couponInfo.discount } : {}) });
      return res.json({ success: true, activated: true, plan, periodEnd, provider: "manual" });
    }

    if (currency === "USD") {
      if (!stripeKey()) throw fail(503, "USD ödemesi henüz yapılandırılmadı (STRIPE_SECRET_KEY).");
      const prev = (await db.collection("subscriptions").doc(u.uid).get()).data() || {};
      const meta = { uid: u.uid, plan, cycle, ...(couponInfo ? { coupon: couponInfo.code } : {}) };
      const s = await stripeApi("POST", "/checkout/sessions", {
        mode: "subscription", success_url: withParam(back, "paid", "1"), cancel_url: withParam(back, "paid", "0"),
        client_reference_id: u.uid, ...(prev.stripeCustomerId ? { customer: prev.stripeCustomerId } : { customer_email: u.email }),
        line_items: [{ quantity: 1, price_data: { currency: "usd", unit_amount: Math.round(amount * 100), product_data: { name: label }, recurring: { interval: cycle === "yearly" ? "year" : "month" } } }],
        metadata: meta, subscription_data: { metadata: meta }
      });
      return res.json({ success: true, provider: "stripe", url: s.url });
    }

    if (!iyziReady()) throw fail(503, "TL ödemesi henüz yapılandırılmadı (IYZICO_API_KEY / IYZICO_SECRET_KEY).");
    const name = String(billing.name || "").trim(), address = String(billing.address || "").trim(), city = String(billing.city || "").trim();
    if (!name || !address || !city) throw fail(400, "TL ödemesi için Ayarlar > Fatura Bilgileri (ad soyad, adres, şehir) doldurulmalı.");
    const orderRef = db.collection("orders").doc();
    const priceStr = amount.toFixed(2);
    await orderRef.set({ uid: u.uid, plan, cycle, currency: "TRY", amount, status: "pending", returnUrl: back, consentVersion: LEGAL_VERSION, createdAt: Date.now(), ...(couponInfo ? { couponCode: couponInfo.code, listAmount, discount: couponInfo.discount } : {}) });
    const Iyzipay = require("iyzipay");
    const iyzi = new Iyzipay({ apiKey: process.env.IYZICO_API_KEY, secretKey: process.env.IYZICO_SECRET_KEY, uri: process.env.IYZICO_BASE_URL || "https://sandbox-api.iyzipay.com" });
    const parts = name.split(/\s+/); const surname = parts.length > 1 ? parts.pop() : "-"; const first = parts.join(" ");
    const addr = { contactName: name, city, country: billing.country || "Turkey", address };
    const result = await new Promise((resolve, reject) => iyzi.checkoutFormInitialize.create({
      locale: "tr", conversationId: orderRef.id, price: priceStr, paidPrice: priceStr, currency: "TRY", basketId: orderRef.id,
      paymentGroup: "PRODUCT", callbackUrl: selfUrl(req) + "/api/iyzico/callback", enabledInstallments: [1],
      buyer: { id: u.uid, name: first, surname, email: String(billing.email || u.email).slice(0, 120), identityNumber: "11111111111", registrationAddress: address, ip: clientIp(req), city, country: billing.country || "Turkey", ...(billing.phone ? { gsmNumber: billing.phone } : {}) },
      shippingAddress: addr, billingAddress: addr,
      basketItems: [{ id: plan + "_" + cycle, name: label, category1: "Yazılım", itemType: "VIRTUAL", price: priceStr }]
    }, (err, r) => (err ? reject(err) : resolve(r))));
    if (result.status !== "success") throw fail(502, "iyzico: " + (result.errorMessage || "ödeme formu oluşturulamadı"));
    res.json({ success: true, provider: "iyzico", url: result.paymentPageUrl || null, html: result.paymentPageUrl ? null : result.checkoutFormContent });
    } catch (e) { if (redeemed) await commerce.releaseCoupon(couponInfo.code, u.uid).catch(() => {}); throw e; } // ödeme başlatılamadıysa kupon hakkı iade edilir
  }));

  // Makbuz e-postası (en iyi çaba; hata ödeme akışını bozmaz)
  function sendReceipt(uid, o) {
    if (!mailer || !mailer.enabled() || !admin || !admin.apps.length) return;
    (async () => { const u = await admin.auth().getUser(uid); if (!u.email || !u.emailVerified) return; const m = mailer.tpl.receipt({ planName: (PLANS.PLANS[o.plan] || {}).name || o.plan, ...o }); await mailer.send({ to: u.email, ...m, type: "receipt", uid, dedupeKey: o.dedupe || null }); })().catch(() => {});
  }
  // ---------- iyzico geri dönüş (tarayıcı POST) ----------
  app.post("/api/iyzico/callback", payGuard, handler(async (req, res) => {
    const token = req.body && typeof req.body.token === "string" && req.body.token.length < 300 ? req.body.token : null;
    const back = (u, ok) => res.redirect(303, withParam(u || "/", "paid", ok ? "1" : "0") + "#plan");
    if (!token || !iyziReady()) return back(null, false);
    const Iyzipay = require("iyzipay");
    const iyzi = new Iyzipay({ apiKey: process.env.IYZICO_API_KEY, secretKey: process.env.IYZICO_SECRET_KEY, uri: process.env.IYZICO_BASE_URL || "https://sandbox-api.iyzipay.com" });
    const r = await new Promise((resolve, reject) => iyzi.checkoutForm.retrieve({ locale: "tr", token }, (err, x) => (err ? reject(err) : resolve(x))));
    const orderId = String(r.basketId || r.conversationId || ""); if (!/^[A-Za-z0-9]{10,40}$/.test(orderId)) return back(null, false);
    const ref = db.collection("orders").doc(orderId);
    const order = (await ref.get()).data();
    if (!order) return back(null, false);
    const paid = r.status === "success" && r.paymentStatus === "SUCCESS" && Number(r.paidPrice) + 0.01 >= order.amount;
    if (!paid) { await ref.set({ status: "failed", gatewayStatus: r.paymentStatus || r.errorMessage || null }, { merge: true }); if (commerce && order.couponCode && order.status !== "failed" && order.status !== "paid") await commerce.releaseCoupon(order.couponCode, order.uid).catch(() => {}); return back(order.returnUrl, false); }
    // Tekrar/eşzamanlı callback süreyi iki kez uzatmasın: sipariş durumu transaction içinde "paid"e çekilir
    const first = await db.runTransaction(async (t) => { const o = (await t.get(ref)).data(); if (!o || o.status === "paid") return false; t.set(ref, { status: "paid", paidAt: Date.now(), paymentId: r.paymentId || null, txIds: Array.isArray(r.itemTransactions) ? r.itemTransactions.map((x) => ({ id: String(x.paymentTransactionId || ""), price: Number(x.paidPrice || x.price || 0) })).filter((x) => x.id).slice(0, 5) : [] }, { merge: true }); return true; });
    if (first) {
      const cur = (await db.collection("subscriptions").doc(order.uid).get()).data() || {};
      const startFrom = cur.status === "active" && cur.periodEnd > Date.now() && cur.plan === order.plan ? cur.periodEnd : Date.now();
      const periodEnd = startFrom + (order.cycle === "yearly" ? 365 : 30) * 864e5;
      await activate(order.uid, { plan: order.plan, status: "active", provider: "iyzico", currency: "TRY", cycle: order.cycle, periodEnd });
      sendReceipt(order.uid, { plan: order.plan, cycle: order.cycle, amount: order.amount, currency: "TRY", periodEnd, couponCode: order.couponCode });
    }
    back(order.returnUrl, true);
  }));

  // ---------- Stripe webhook ----------
  function verifyStripeSignature(raw, header, secret, tolerance = 300) {
    const parts = Object.fromEntries(String(header || "").split(",").map(p => p.split("=")).filter(p => p.length === 2).map(([k, v]) => [k.trim(), v]));
    const sigs = String(header || "").split(",").filter(p => p.trim().startsWith("v1=")).map(p => p.trim().slice(3));
    if (!parts.t || !sigs.length) return false;
    if (Math.abs(Date.now() / 1000 - Number(parts.t)) > tolerance) return false;
    const expected = crypto.createHmac("sha256", secret).update(`${parts.t}.`).update(raw).digest("hex");
    return sigs.some(s => /^[0-9a-f]{64}$/i.test(s) && crypto.timingSafeEqual(Buffer.from(s.toLowerCase()), Buffer.from(expected)));
  }
  async function stripeSync(sub, extra = {}) {
    const m = sub.metadata || {}; if (!m.uid) return;
    const st = ["active", "trialing"].includes(sub.status) ? "active" : sub.status === "canceled" ? "canceled" : "past_due";
    await activate(m.uid, { plan: m.plan, cycle: m.cycle, status: st, provider: "stripe", currency: "USD", periodEnd: periodEndOf(sub), stripeCustomerId: sub.customer, stripeSubscriptionId: sub.id, ...extra });
  }
  app.post("/api/stripe/webhook", handler(async (req, res) => {
    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!secret || !req.rawBody || !db) throw fail(503, "Webhook yapılandırılmadı.");
    if (!verifyStripeSignature(req.rawBody, req.headers["stripe-signature"], secret)) throw fail(400, "İmza doğrulanamadı.");
    const ev = req.body; const o = ev && ev.data && ev.data.object;
    if (!ev || !ev.id || !o) throw fail(400, "Geçersiz olay.");
    const evRef = db.collection("webhookEvents").doc(String(ev.id));
    const isNew = await db.runTransaction(async (t) => { if ((await t.get(evRef)).exists) return false; t.set(evRef, { type: ev.type, at: Date.now() }); return true; });
    if (!isNew) return res.json({ received: true, duplicate: true });
    try {
      if (ev.type === "checkout.session.completed" && o.subscription) await stripeSync(await stripeApi("GET", "/subscriptions/" + o.subscription));
      else if (ev.type === "invoice.paid") {
        const id = o.subscription || o.parent?.subscription_details?.subscription;
        if (id) {
          const sub = await stripeApi("GET", "/subscriptions/" + id); await stripeSync(sub);
          // Yönetici panelinde Stripe tahsilatları da görünsün (idempotent: fatura kimliği belge kimliği olur)
          try { const m = sub.metadata || {}, oid = "st_" + String(o.id || "").replace(/[^A-Za-z0-9_]/g, "").slice(0, 60); if (m.uid && oid.length > 3) await db.collection("orders").doc(oid).set({ uid: m.uid, plan: m.plan, cycle: m.cycle, currency: "USD", amount: Math.round(Number(o.amount_paid || 0)) / 100, status: "paid", gatewayStatus: "stripe", paidAt: Date.now(), createdAt: Date.now(), invoiceId: String(o.id || "").slice(0, 80), ...(o.payment_intent ? { paymentIntent: String(o.payment_intent) } : {}), ...(o.charge ? { charge: String(o.charge) } : {}), ...(m.coupon ? { couponCode: m.coupon } : {}) }, { merge: true }); } catch (e) { console.error("payments: stripe sipariş kaydı yazılamadı:", e.message); }
          try { const m = sub.metadata || {}; if (m.uid && Number(o.amount_paid) > 0) sendReceipt(m.uid, { plan: m.plan, cycle: m.cycle, amount: Number(o.amount_paid) / 100, currency: "USD", periodEnd: periodEndOf(sub), couponCode: m.coupon, dedupe: "rcpt_" + String(o.id || "") }); } catch { /* makbuz opsiyonel */ }
        }
      }
      else if (ev.type === "checkout.session.expired") { const m = o.metadata || {}; if (commerce && m.coupon && m.uid) await commerce.releaseCoupon(m.coupon, m.uid).catch(() => {}); }
      else if (ev.type === "customer.subscription.updated" || ev.type === "customer.subscription.deleted") await stripeSync(o);
    } catch (e) { await evRef.delete().catch(() => {}); throw e; } // işlenemediyse Stripe tekrar deneyebilsin
    res.json({ received: true });
  }));

  // ---------- Stripe müşteri portalı (iptal / kart değiştirme) ----------
  app.post("/api/billing-portal", payGuard, handler(async (req, res) => {
    const u = await verifyUser(req); if (!stripeKey()) throw fail(503, "Stripe yapılandırılmadı.");
    const sub = (await db.collection("subscriptions").doc(u.uid).get()).data();
    if (!sub || !sub.stripeCustomerId) throw fail(404, "Stripe aboneliği bulunamadı.");
    const s = await stripeApi("POST", "/billing_portal/sessions", { customer: sub.stripeCustomerId, return_url: returnUrlOf(req) });
    res.json({ success: true, url: s.url });
  }));

  /* ---------- Yönetici işlemleri: iade ve abonelik iptali (admin-ops.js çağırır) ---------- */
  const iyziClient = () => { const Iyzipay = require("iyzipay"); return new Iyzipay({ apiKey: process.env.IYZICO_API_KEY, secretKey: process.env.IYZICO_SECRET_KEY, uri: process.env.IYZICO_BASE_URL || "https://sandbox-api.iyzipay.com" }); };
  const iyziCall = (fn, body) => new Promise((resolve, reject) => fn(body, (err, r) => (err ? reject(err) : resolve(r))));
  const istDay = (ms) => new Date(ms + 3 * 36e5).toISOString().slice(0, 10); // iyzico iptali aynı gün (TR saati) içindir
  async function refundOrder(order, orderId, amount, ip) {
    const full = Number(order.amount), already = Number(order.refundedAmount || 0), left = Math.round((full - already) * 100) / 100;
    const amt = amount == null ? left : Math.round(Number(amount) * 100) / 100;
    if (!(amt > 0) || amt > left + 0.001) throw fail(400, `İade tutarı geçersiz (iade edilebilir: ${left})`);
    if (order.currency === "USD") {
      if (!stripeKey()) throw fail(503, "Stripe yapılandırılmadı."); let pi = order.paymentIntent, ch = order.charge;
      if (!pi && !ch && order.invoiceId) { const inv = await stripeApi("GET", "/invoices/" + encodeURIComponent(order.invoiceId)); pi = inv.payment_intent || null; ch = inv.charge || null; }
      if (!pi && !ch) throw fail(409, "Bu siparişte Stripe ödeme kimliği yok; iadeyi Stripe panelinden yapın.");
      const r = await stripeApi("POST", "/refunds", { ...(pi ? { payment_intent: pi } : { charge: ch }), amount: Math.round(amt * 100) }, { "Idempotency-Key": `dac_refund_${orderId}_${Math.round((already + amt) * 100)}` });
      return { provider: "stripe", refundId: r.id, amount: amt };
    }
    if (!iyziReady()) throw fail(503, "iyzico yapılandırılmadı."); const iyzi = iyziClient(), ipx = String(ip || "127.0.0.1");
    if (order.paymentId && already === 0 && amt === full && order.paidAt && istDay(order.paidAt) === istDay(Date.now())) {
      const c = await iyziCall(iyzi.cancel.create.bind(iyzi.cancel), { locale: "tr", conversationId: orderId, paymentId: order.paymentId, ip: ipx });
      if (c.status === "success") return { provider: "iyzico", method: "cancel", amount: amt };
    }
    const tx = (order.txIds || [])[0]; if (!tx || !tx.id) throw fail(409, "Bu siparişte iyzico işlem kimliği yok; iadeyi iyzico panelinden yapın.");
    const r = await iyziCall(iyzi.refund.create.bind(iyzi.refund), { locale: "tr", conversationId: orderId, paymentTransactionId: tx.id, price: amt.toFixed(2), currency: "TRY", ip: ipx });
    if (r.status !== "success") throw fail(502, "iyzico: " + (r.errorMessage || "iade başarısız"));
    return { provider: "iyzico", method: "refund", amount: amt };
  }
  async function cancelSubscription(uid, immediate) {
    const sub = (await db.collection("subscriptions").doc(uid).get()).data(); if (!sub) throw fail(404, "Abonelik bulunamadı");
    if (sub.provider === "stripe" && sub.stripeSubscriptionId) {
      if (!stripeKey()) throw fail(503, "Stripe yapılandırılmadı.");
      if (immediate) { await stripeApi("DELETE", "/subscriptions/" + encodeURIComponent(sub.stripeSubscriptionId)); await activate(uid, { status: "canceled", periodEnd: Date.now() }); return { provider: "stripe", immediate: true }; }
      await stripeApi("POST", "/subscriptions/" + encodeURIComponent(sub.stripeSubscriptionId), { cancel_at_period_end: "true" }); return { provider: "stripe", immediate: false, note: "Dönem sonunda sona erecek (şimdiki dönem geçerli kalır)." };
    }
    if (immediate) { await activate(uid, { status: "canceled", periodEnd: Date.now() }); return { provider: sub.provider || "manual", immediate: true }; }
    return { provider: sub.provider || "manual", immediate: false, note: "Bu paket otomatik yenilenmiyor; süresi dolunca kendiliğinden sona erer." };
  }

  return { verifyUser, getEntitlement, status, verifyStripeSignature, _stripeSync: stripeSync, refundOrder, cancelSubscription, trialHash };
};
