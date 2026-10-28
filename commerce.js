/* Digital Asset Center - Ticari ayarlar (V13.2)
 *  1) Fiyat ve paket limiti yönetimi: yönetici panelinden değiştirilir, Firestore `settings/pricing` içinde saklanır ve
 *     plans.js içindeki canlı PLANS nesnesine uygulanır (checkout, kota denetimi ve arayüz aynı değeri görür). plans.js varsayılan olarak kalır.
 *  2) Kupon / indirim kodları: `coupons/{KOD}` (+ kullanıcı başına sayaç `couponUsers/{KOD__uid}`).
 *  3) Site duyurusu ve bakım modu: `settings/site`.
 * Tüm yazma işlemleri yalnızca admin.js üzerinden (rol denetimiyle) yapılır; burada yetki denetimi yoktur. Genel (herkese açık) uçlar mountPublic() ile bağlanır. */
"use strict";
const crypto = require("crypto");

const round2 = (n) => Math.round(n * 100) / 100;
const bad = (status, message, extra = {}) => Object.assign(new Error(message), { status, ...extra });
const CODE_RE = /^[A-Z0-9][A-Z0-9_-]{2,31}$/;
const normCode = (c) => String(c || "").trim().toUpperCase();
const LEVELS = ["info", "warn", "bad"];

module.exports = function createCommerce({ db, PLANS, now = Date.now, log = () => {} }) {
  const PAID = PLANS.PAID;

  /* =================== FİYAT / LİMİT =================== */
  const DEFAULTS = {}; PAID.forEach((id) => { const p = PLANS.PLANS[id]; DEFAULTS[id] = { TRY: p.prices.TRY, USD: p.prices.USD, assets: p.assets, team: p.team, history: p.history, features: p.features.slice() }; });
  const DEFAULT_YEARLY = PLANS.YEARLY_MONTHS;
  const defaultState = () => ({ plans: Object.fromEntries(PAID.map((id) => [id, { TRY: DEFAULTS[id].TRY, USD: DEFAULTS[id].USD, assets: DEFAULTS[id].assets, team: DEFAULTS[id].team, history: DEFAULTS[id].history }])), yearlyMonths: DEFAULT_YEARLY });
  const currentState = () => ({ plans: Object.fromEntries(PAID.map((id) => { const p = PLANS.PLANS[id]; return [id, { TRY: p.prices.TRY, USD: p.prices.USD, assets: p.assets, team: p.team, history: p.history }]; })), yearlyMonths: PLANS.YEARLY_MONTHS });
  let meta = { custom: false, updatedAt: null, updatedBy: null }; let lastLoad = 0;

  // Paket kartındaki metinler (ör. "25 varlık") limit değişince güncel kalsın
  function featureText(f, p) {
    if (/^(Sınırsız|\d+) varlık$/.test(f)) return p.assets == null ? "Sınırsız varlık" : `${p.assets} varlık`;
    if (/^(Sınırsız|\d+) ekip kaydı$/.test(f)) return p.team == null ? "Sınırsız ekip kaydı" : `${p.team} ekip kaydı`;
    if (/^Son \d+ tarama geçmişi$/.test(f)) return `Son ${p.history} tarama geçmişi`;
    return f;
  }
  function applyState(st) {
    for (const id of PAID) {
      const s = st.plans[id]; if (!s) continue; const p = PLANS.PLANS[id];
      p.prices = { ...(p.prices || {}), TRY: s.TRY, USD: s.USD }; p.priceTRY = s.TRY; p.priceUSD = s.USD;
      p.assets = s.assets; p.team = s.team; p.history = s.history;
      p.features = DEFAULTS[id].features.map((f) => featureText(f, p));
    }
    PLANS.YEARLY_MONTHS = st.yearlyMonths;
  }
  function parsePrice(v, cur, label) {
    const n = typeof v === "string" ? Number(v.trim().replace(",", ".")) : v;
    if (typeof n !== "number" || !Number.isFinite(n)) throw bad(400, `${label}: geçerli bir sayı girin`);
    const min = cur === "USD" ? 0.5 : 1;
    if (n < min) throw bad(400, `${label}: en az ${min} olmalı (ödeme sağlayıcısı alt sınırı)`);
    if (n > 10000000) throw bad(400, `${label}: çok yüksek`);
    return round2(n);
  }
  function parseLimit(v, label, { min, max, nullable }) {
    if (v === null || v === "" || v === undefined) { if (nullable) return null; throw bad(400, `${label}: boş bırakılamaz`); }
    if (typeof v === "string" && /^(sınırsız|unlimited)$/i.test(v.trim())) { if (nullable) return null; throw bad(400, `${label}: sınırsız olamaz`); }
    const n = typeof v === "string" ? Number(v.trim()) : v;
    if (!Number.isInteger(n) || n < min || n > max) throw bad(400, `${label}: ${min} ile ${max} arasında tam sayı olmalı`);
    return n;
  }
  // input: { plans: { freelance: { TRY, USD, assets, team, history } }, yearlyMonths, force }  (kısmi güncelleme desteklenir)
  function normalize(input, base) {
    if (!input || typeof input !== "object") throw bad(400, "Geçersiz istek");
    const out = JSON.parse(JSON.stringify(base)), changes = [], large = [];
    const inPlans = input.plans && typeof input.plans === "object" ? input.plans : {};
    for (const id of Object.keys(inPlans)) if (!PAID.includes(id)) throw bad(400, `Bilinmeyen paket: ${String(id).slice(0, 30)}`);
    for (const id of PAID) {
      const src = inPlans[id]; if (!src || typeof src !== "object") continue; const name = PLANS.PLANS[id].name;
      const set = (field, val) => { if (val !== out.plans[id][field]) { changes.push({ plan: id, field, from: out.plans[id][field], to: val }); out.plans[id][field] = val; } };
      if (src.TRY !== undefined) { const v = parsePrice(src.TRY, "TRY", `${name} TL fiyatı`); const old = out.plans[id].TRY; if (old && v !== old && (v / old > 5 || v / old < 0.2)) large.push({ plan: id, field: "TRY", from: old, to: v }); set("TRY", v); }
      if (src.USD !== undefined) { const v = parsePrice(src.USD, "USD", `${name} USD fiyatı`); const old = out.plans[id].USD; if (old && v !== old && (v / old > 5 || v / old < 0.2)) large.push({ plan: id, field: "USD", from: old, to: v }); set("USD", v); }
      if (src.assets !== undefined) set("assets", parseLimit(src.assets, `${name} varlık limiti`, { min: 1, max: 1000000, nullable: true }));
      if (src.team !== undefined) set("team", parseLimit(src.team, `${name} ekip limiti`, { min: 1, max: 100000, nullable: true }));
      if (src.history !== undefined) set("history", parseLimit(src.history, `${name} geçmiş limiti`, { min: 10, max: 100000, nullable: false }));
    }
    if (input.yearlyMonths !== undefined) {
      const m = typeof input.yearlyMonths === "string" ? Number(input.yearlyMonths) : input.yearlyMonths;
      if (!Number.isInteger(m) || m < 1 || m > 12) throw bad(400, "Yıllık ödemede ücretlendirilen ay sayısı 1-12 arasında tam sayı olmalı");
      if (m !== out.yearlyMonths) { changes.push({ plan: null, field: "yearlyMonths", from: out.yearlyMonths, to: m }); out.yearlyMonths = m; }
    }
    return { state: out, changes, large };
  }
  const publicView = () => {
    const plans = {}; for (const id of PAID) { const p = PLANS.PLANS[id]; plans[id] = { prices: { TRY: p.prices.TRY, USD: p.prices.USD }, priceTRY: p.prices.TRY, priceUSD: p.prices.USD, assets: p.assets, team: p.team, history: p.history, features: p.features.slice() }; }
    return { plans, yearlyMonths: PLANS.YEARLY_MONTHS, trialDays: PLANS.TRIAL_DAYS, version: meta.updatedAt || 0, custom: meta.custom };
  };
  async function loadPricing() {
    if (!db) return; const s = await db.collection("settings").doc("pricing").get(); lastLoad = now();
    if (!s.exists) { if (meta.custom) { applyState(defaultState()); meta = { custom: false, updatedAt: null, updatedBy: null }; } return; }
    const d = s.data() || {};
    try { const { state } = normalize({ plans: d.plans, yearlyMonths: d.yearlyMonths }, defaultState()); applyState(state); meta = { custom: true, updatedAt: d.updatedAt || null, updatedBy: d.updatedByEmail || d.updatedBy || null }; }
    catch (e) { log("Fiyat ayarı okunamadı, varsayılan kullanılıyor: " + e.message); }
  }
  const ensureFresh = async (maxAgeMs = 15000) => { if (db && now() - lastLoad > maxAgeMs) { lastLoad = now(); await loadPricing().catch((e) => log("Fiyat yenilenemedi: " + e.message)); } };
  async function savePricing(input, by) {
    if (!db) throw bad(503, "Firestore bağlı değil; fiyatlar kalıcı saklanamaz.");
    const { state, changes, large } = normalize(input, currentState());
    if (!changes.length) throw bad(400, "Değişiklik yok");
    if (large.length && input.force !== true) throw bad(409, "Fiyat değişimi çok büyük (5 kattan fazla artış veya %80'den fazla düşüş). Yazım hatası olmadığından emin olup onaylayın.", { code: "LARGE_CHANGE", large });
    const at = now();
    await db.collection("settings").doc("pricing").set({ plans: state.plans, yearlyMonths: state.yearlyMonths, updatedAt: at, updatedBy: by.uid, updatedByEmail: by.email || null });
    try { await db.collection("pricingHistory").doc().set({ at, action: "update", by: by.uid, byEmail: by.email || null, changes }); } catch (e) { log("pricingHistory yazılamadı: " + e.message); }
    applyState(state); meta = { custom: true, updatedAt: at, updatedBy: by.email || by.uid }; lastLoad = at;
    return { changes, public: publicView() };
  }
  async function resetPricing(by) {
    if (!db) throw bad(503, "Firestore bağlı değil");
    const before = currentState(), at = now();
    await db.collection("settings").doc("pricing").delete();
    try { await db.collection("pricingHistory").doc().set({ at, action: "reset", by: by.uid, byEmail: by.email || null, changes: [{ plan: null, field: "reset", from: before, to: defaultState() }] }); } catch (e) { log("pricingHistory yazılamadı: " + e.message); }
    applyState(defaultState()); meta = { custom: false, updatedAt: null, updatedBy: null }; lastLoad = at;
    return { public: publicView() };
  }
  async function pricingHistory(limit = 30) {
    if (!db) return [];
    const snap = await db.collection("pricingHistory").orderBy("at", "desc").limit(Math.min(100, limit)).get();
    return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  }
  const adminPricingView = () => ({ current: currentState(), defaults: defaultState(), custom: meta.custom, updatedAt: meta.updatedAt, updatedBy: meta.updatedBy, plans: Object.fromEntries(PAID.map((id) => [id, { name: PLANS.PLANS[id].name, features: PLANS.PLANS[id].features.slice() }])), public: publicView() });

  /* =================== KUPONLAR =================== */
  const couponRef = (code) => db.collection("coupons").doc(code);
  const genCode = () => { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; const b = crypto.randomBytes(8); return Array.from(b, (x) => A[x % A.length]).join(""); };
  const toMs = (v, label) => { if (v === null || v === undefined || v === "") return null; const n = typeof v === "number" ? v : Date.parse(v); if (!Number.isFinite(n) || n < 0) throw bad(400, `${label}: geçersiz tarih`); return n; };
  function validateCoupon(b) {
    if (!b || typeof b !== "object") throw bad(400, "Geçersiz istek");
    const code = b.code ? normCode(b.code) : genCode(); if (!CODE_RE.test(code)) throw bad(400, "Kupon kodu 3-32 karakter; yalnızca harf, rakam, - ve _ içerebilir");
    const type = b.type; if (!["percent", "fixed"].includes(type)) throw bad(400, "Tür percent (yüzde) veya fixed (sabit tutar) olmalı");
    const value = typeof b.value === "string" ? Number(b.value.replace(",", ".")) : b.value; if (typeof value !== "number" || !Number.isFinite(value)) throw bad(400, "İndirim değeri sayı olmalı");
    let currency = null;
    if (type === "percent") { if (!(value >= 1 && value <= 90)) throw bad(400, "Yüzde indirim 1-90 arasında olmalı (tamamen ücretsiz için panelden paket verin)"); }
    else { currency = String(b.currency || "").toUpperCase(); if (!["TRY", "USD"].includes(currency)) throw bad(400, "Sabit tutarlı kuponda para birimi (TRY/USD) seçilmeli"); if (!(value > 0 && value <= 1000000)) throw bad(400, "İndirim tutarı geçersiz"); }
    const plans = Array.isArray(b.plans) ? [...new Set(b.plans.map(String))] : []; for (const p of plans) if (!PAID.includes(p)) throw bad(400, "Bilinmeyen paket: " + p.slice(0, 30));
    const cycles = Array.isArray(b.cycles) ? [...new Set(b.cycles.map(String))] : []; for (const c of cycles) if (!["monthly", "yearly"].includes(c)) throw bad(400, "Geçersiz dönem");
    let maxUses = b.maxUses; if (maxUses === "" || maxUses === undefined) maxUses = null; if (maxUses !== null) { maxUses = Number(maxUses); if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 1000000) throw bad(400, "Toplam kullanım sınırı 1-1.000.000 arasında tam sayı olmalı"); }
    let perUser = b.perUser === undefined || b.perUser === "" ? 1 : Number(b.perUser); if (!Number.isInteger(perUser) || perUser < 1 || perUser > 100) throw bad(400, "Kullanıcı başına hak 1-100 arasında olmalı");
    const validFrom = toMs(b.validFrom, "Başlangıç"), validUntil = toMs(b.validUntil, "Bitiş"); if (validFrom && validUntil && validUntil <= validFrom) throw bad(400, "Bitiş tarihi başlangıçtan sonra olmalı");
    const note = String(b.note || "").slice(0, 200);
    return { code, type, value: round2(value), currency, plans, cycles, maxUses, perUser, validFrom, validUntil, note, active: b.active !== false };
  }
  async function createCoupon(b, by) {
    if (!db) throw bad(503, "Firestore bağlı değil");
    const c = validateCoupon(b); const ref = couponRef(c.code);
    if ((await ref.get()).exists) throw bad(409, "Bu kupon kodu zaten var");
    const doc = { ...c, usedCount: 0, createdAt: now(), createdBy: by.uid, createdByEmail: by.email || null };
    await ref.set(doc); return doc;
  }
  async function listCoupons(limit = 200) {
    if (!db) return [];
    const snap = await db.collection("coupons").limit(Math.min(500, limit)).get();
    return snap.docs.map((d) => ({ id: d.id, ...d.data() })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  }
  async function setCouponActive(codeIn, active) {
    const code = normCode(codeIn); if (!CODE_RE.test(code)) throw bad(400, "Geçersiz kupon kodu"); if (!db) throw bad(503, "Firestore bağlı değil");
    const s = await couponRef(code).get(); if (!s.exists) throw bad(404, "Kupon bulunamadı");
    await couponRef(code).set({ active: !!active }, { merge: true }); return { code, active: !!active };
  }
  async function deleteCoupon(codeIn) {
    const code = normCode(codeIn); if (!CODE_RE.test(code)) throw bad(400, "Geçersiz kupon kodu"); if (!db) throw bad(503, "Firestore bağlı değil");
    const s = await couponRef(code).get(); if (!s.exists) throw bad(404, "Kupon bulunamadı");
    await couponRef(code).delete(); return { code };
  }
  async function quoteCoupon(codeIn, { plan, cycle, currency, uid }) {
    if (!db) throw bad(503, "Kupon sistemi kullanılamıyor");
    const code = normCode(codeIn); if (!CODE_RE.test(code)) throw bad(404, "Geçersiz kupon kodu");
    const s = await couponRef(code).get(); const c = s.exists ? s.data() : null; if (!c || c.active !== true) throw bad(404, "Geçersiz kupon kodu");
    const t = now();
    if (c.validFrom && t < c.validFrom) throw bad(400, "Kupon henüz geçerli değil");
    if (c.validUntil && t > c.validUntil) throw bad(400, "Kuponun süresi dolmuş");
    if (c.maxUses != null && (c.usedCount || 0) >= c.maxUses) throw bad(400, "Kuponun kullanım hakkı dolmuş");
    if (c.plans && c.plans.length && !c.plans.includes(plan)) throw bad(400, "Kupon bu pakette geçerli değil");
    if (c.cycles && c.cycles.length && !c.cycles.includes(cycle)) throw bad(400, "Kupon bu faturalama döneminde geçerli değil");
    if (c.type === "fixed" && c.currency !== currency) throw bad(400, `Kupon yalnızca ${c.currency} ödemelerinde geçerli`);
    if (uid) { const u = await db.collection("couponUsers").doc(code + "__" + uid).get(); if (u.exists && (u.data().count || 0) >= (c.perUser || 1)) throw bad(400, "Bu kuponu daha önce kullandınız"); }
    const list = PLANS.price(plan, currency, cycle); if (list == null) throw bad(400, "Bu paket için fiyat tanımlı değil");
    const discount = c.type === "percent" ? round2(list * c.value / 100) : round2(Math.min(c.value, list));
    const finalAmount = round2(list - discount), min = currency === "USD" ? 0.5 : 1;
    if (finalAmount < min) throw bad(400, "Kupon bu pakette uygulanamıyor (kalan tutar ödeme alt sınırının altında)");
    return { code, type: c.type, value: c.value, currency, listAmount: list, discount, finalAmount };
  }
  async function redeemCoupon(codeIn, uid) {
    const code = normCode(codeIn);
    await db.runTransaction(async (t) => {
      const cr = couponRef(code), ur = db.collection("couponUsers").doc(code + "__" + uid);
      const cs = await t.get(cr), us = await t.get(ur); const c = cs.exists ? cs.data() : null;
      if (!c || c.active !== true) throw bad(400, "Kupon geçersiz");
      if (c.maxUses != null && (c.usedCount || 0) >= c.maxUses) throw bad(400, "Kuponun kullanım hakkı dolmuş");
      const uc = us.exists ? (us.data().count || 0) : 0; if (uc >= (c.perUser || 1)) throw bad(400, "Bu kuponu daha önce kullandınız");
      t.set(cr, { usedCount: (c.usedCount || 0) + 1 }, { merge: true }); t.set(ur, { code, uid, count: uc + 1, at: now() }, { merge: true });
    });
  }
  async function releaseCoupon(codeIn, uid) {
    const code = normCode(codeIn); if (!db || !CODE_RE.test(code) || !uid) return;
    await db.runTransaction(async (t) => {
      const cr = couponRef(code), ur = db.collection("couponUsers").doc(code + "__" + uid);
      const cs = await t.get(cr), us = await t.get(ur);
      if (cs.exists) t.set(cr, { usedCount: Math.max(0, (cs.data().usedCount || 0) - 1) }, { merge: true });
      if (us.exists) t.set(ur, { count: Math.max(0, (us.data().count || 0) - 1) }, { merge: true });
    });
  }

  /* =================== DUYURU / BAKIM =================== */
  const defaultSite = () => ({ announcement: { enabled: false, text: "", level: "info", until: null, at: null }, maintenance: { enabled: false, message: "" }, flags: { registrationOpen: true, disabledScanTypes: [] }, updatedAt: null, updatedBy: null });
  function sanitizeSite(d) {
    const base = defaultSite(), a = (d && d.announcement) || {}, m = (d && d.maintenance) || {};
    return { announcement: { enabled: a.enabled === true, text: String(a.text || "").slice(0, 280), level: LEVELS.includes(a.level) ? a.level : "info", until: Number.isFinite(a.until) ? a.until : null, at: Number.isFinite(a.at) ? a.at : null }, maintenance: { enabled: m.enabled === true, message: String(m.message || "").slice(0, 280) }, flags: { registrationOpen: !(d && d.flags && d.flags.registrationOpen === false), disabledScanTypes: Array.isArray(d && d.flags && d.flags.disabledScanTypes) ? d.flags.disabledScanTypes.filter((x) => /^[A-Z_]{2,30}$/.test(x)).slice(0, 40) : [] }, updatedAt: (d && d.updatedAt) || base.updatedAt, updatedBy: (d && d.updatedBy) || base.updatedBy };
  }
  let siteCache = { at: 0, val: defaultSite() };
  async function getSite(force) {
    if (!db) return siteCache.val; if (!force && now() - siteCache.at < 20000) return siteCache.val;
    try { const s = await db.collection("settings").doc("site").get(); siteCache = { at: now(), val: s.exists ? sanitizeSite(s.data()) : defaultSite() }; } catch (e) { log("Site ayarı okunamadı: " + e.message); siteCache = { at: now(), val: siteCache.val }; }
    return siteCache.val;
  }
  async function saveSite(input, by) {
    if (!db) throw bad(503, "Firestore bağlı değil");
    if (!input || typeof input !== "object") throw bad(400, "Geçersiz istek");
    const cur = await getSite(true), next = JSON.parse(JSON.stringify(cur));
    if (input.announcement !== undefined) {
      const a = input.announcement || {}; if (typeof a.enabled !== "boolean") throw bad(400, "announcement.enabled true/false olmalı");
      const text = String(a.text || "").trim(); if (a.enabled && !text) throw bad(400, "Duyuru metni boş olamaz"); if (text.length > 280) throw bad(400, "Duyuru en çok 280 karakter olabilir");
      const level = a.level === undefined ? "info" : a.level; if (!LEVELS.includes(level)) throw bad(400, "Seviye info, warn veya bad olmalı");
      let until = a.until === undefined || a.until === null || a.until === "" ? null : (typeof a.until === "number" ? a.until : Date.parse(a.until)); if (until !== null && !Number.isFinite(until)) throw bad(400, "Bitiş tarihi geçersiz");
      if (a.enabled && until !== null && until <= now()) throw bad(400, "Bitiş tarihi geçmişte olamaz");
      const pv = cur.announcement || {}; const fresh = a.enabled && (!pv.enabled || pv.text !== text || pv.level !== level); // yeni yayın/değişiklik: kullanıcıda rozet çıkar
      next.announcement = { enabled: a.enabled, text, level, until, at: fresh ? now() : (pv.at || null) };
    }
    if (input.maintenance !== undefined) {
      const m = input.maintenance || {}; if (typeof m.enabled !== "boolean") throw bad(400, "maintenance.enabled true/false olmalı");
      const message = String(m.message || "").trim(); if (message.length > 280) throw bad(400, "Bakım mesajı en çok 280 karakter olabilir");
      next.maintenance = { enabled: m.enabled, message };
    }
    if (input.flags !== undefined) {
      const f = input.flags || {}; next.flags = next.flags || { registrationOpen: true, disabledScanTypes: [] };
      if (f.registrationOpen !== undefined) { if (typeof f.registrationOpen !== "boolean") throw bad(400, "registrationOpen true/false olmalı"); next.flags.registrationOpen = f.registrationOpen; }
      if (f.disabledScanTypes !== undefined) { if (!Array.isArray(f.disabledScanTypes) || f.disabledScanTypes.length > 40) throw bad(400, "disabledScanTypes liste olmalı"); const t = [...new Set(f.disabledScanTypes.map((x) => String(x).toUpperCase()))]; for (const x of t) if (!/^[A-Z_]{2,30}$/.test(x)) throw bad(400, "Geçersiz tarama türü: " + x.slice(0, 30)); next.flags.disabledScanTypes = t; }
    }
    next.updatedAt = now(); next.updatedBy = by.email || by.uid;
    await db.collection("settings").doc("site").set(next); siteCache = { at: now(), val: next }; return next;
  }
  async function publicSite() {
    const s = await getSite(); const a = s.announcement, t = now();
    return { announcement: a.enabled && a.text && (!a.until || a.until > t) ? { text: a.text, level: a.level, until: a.until, at: a.at || null } : null, maintenance: { enabled: s.maintenance.enabled, message: s.maintenance.message || "Sistem bakımda. Kısa süre sonra tekrar deneyin." }, flags: { registrationOpen: s.flags.registrationOpen, disabledScanTypes: s.flags.disabledScanTypes }, serverTime: t };
  }

  /* =================== GENEL UÇLAR =================== */
  // getVerifyUser / getIsAdmin: payments ve admin modülleri sonradan oluştuğu için tembel (lazy) alınır
  function mountPublic(app, { SEC, getVerifyUser, getIsAdmin }) {
    const couponLimit = SEC.makeLimiter(SEC.int(process.env.COUPON_RATE_LIMIT, 30), 10 * 60 * 1000);
    const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { const code = e.status || 500; if (code >= 500) log("commerce: " + e.message); res.status(code).json({ success: false, error: code >= 500 ? "Sunucu hatası" : e.message }); } };
    app.get("/api/pricing", wrap(async (req, res) => { await ensureFresh(15000); res.set("Cache-Control", "no-store"); res.json({ success: true, ...publicView() }); }));
    app.get("/api/site-status", wrap(async (req, res) => { res.set("Cache-Control", "no-store"); res.json({ success: true, ...(await publicSite()) }); }));
    app.post("/api/coupon/validate", wrap(async (req, res) => {
      if (!couponLimit(req.ip)) throw bad(429, "Çok fazla deneme. Biraz sonra tekrar deneyin.");
      const u = await getVerifyUser()(req); const b = req.body || {};
      const plan = String(b.plan || ""), cycle = b.cycle === "yearly" ? "yearly" : "monthly", currency = b.currency === "USD" ? "USD" : "TRY";
      if (!PAID.includes(plan)) throw bad(400, "Geçersiz paket");
      await ensureFresh(5000);
      res.set("Cache-Control", "no-store"); res.json({ success: true, ...(await quoteCoupon(b.code, { plan, cycle, currency, uid: u.uid })) });
    }));
    // Bakım modu: yeni tarama / toplu iş başlatmayı yöneticiler dışında durdurur (okuma ve ödeme etkilenmez)
    const maintenanceGuard = async (req, res, next) => {
      try {
        const s = await getSite(); if (!s.maintenance.enabled) return next();
        try { const u = await getVerifyUser()(req); if (await getIsAdmin()(u)) return next(); } catch { /* doğrulanamadı: yönetici değil */ }
        res.status(503).json({ success: false, code: "MAINTENANCE", error: s.maintenance.message || "Sistem bakımda. Kısa süre sonra tekrar deneyin." });
      } catch (e) { next(); }
    };
    // Kapatılan tarama türleri: yöneticiler hariç yeni taramada 503 FEATURE_DISABLED
    const scanTypeGuard = async (req, res, next) => {
      try {
        const s = await getSite(); const t = String((req.body && req.body.type) || "WEBSITE").toUpperCase(); if (!s.flags.disabledScanTypes.includes(t)) return next();
        try { const u = await getVerifyUser()(req); if (await getIsAdmin()(u)) return next(); } catch { /* yönetici değil */ }
        res.status(503).json({ success: false, code: "FEATURE_DISABLED", error: "Bu tarama türü geçici olarak kapalı. Lütfen daha sonra tekrar deneyin." });
      } catch (e) { next(); }
    };
    return { maintenanceGuard, scanTypeGuard };
  }

  let timer = null;
  const registrationOpen = async () => (await getSite()).flags.registrationOpen !== false;
  const start = () => { loadPricing().catch((e) => log("Fiyat ayarı yüklenemedi: " + e.message)); getSite(true).catch(() => {}); timer = setInterval(() => loadPricing().catch(() => {}), 60000); if (timer.unref) timer.unref(); };
  const stop = () => { if (timer) clearInterval(timer); timer = null; };

  return { start, stop, loadPricing, ensureFresh, savePricing, resetPricing, pricingHistory, adminPricingView, publicView, currentState, defaultState, normalize,
    createCoupon, listCoupons, setCouponActive, deleteCoupon, quoteCoupon, redeemCoupon, releaseCoupon, validateCoupon,
    getSite, saveSite, publicSite, mountPublic, registrationOpen };
};
