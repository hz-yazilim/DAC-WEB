/* Digital Asset Center - Para birimi, kur sağlayıcısı ve affiliate altyapısı (HAZIRLIK; hiçbiri etkin değil)
 * - Fiyatlar para birimi KODUYLA saklanır (plans.js > PLANS[x].prices). Burada desteklenen para birimleri ve kur adaptörü arayüzü tanımlanır.
 * - Kur sağlayıcısı bağlı DEĞİL: gerçek kur yokken kur uydurulmaz ve dönüştürme yapılmaz.
 * - Affiliate: yalnızca veri modeli + doğrulama. Etkinleştirme için sağlayıcı yapılandırması ve AFFILIATE_ENABLED=true gerekir (şu an kapalı). */
"use strict";

// minor: küçük birim basamağı (TRY/USD/EUR = 2). enabled: fiyatlandırma bu para birimi için yapılandırıldı mı (plans.js'te fiyat var mı).
const CURRENCIES = Object.freeze({
  TRY: { code: "TRY", symbol: "₺", minor: 2, name: "Türk Lirası" },
  USD: { code: "USD", symbol: "$", minor: 2, name: "ABD Doları" },
  EUR: { code: "EUR", symbol: "€", minor: 2, name: "Euro" }
});
const isCurrency = (c) => typeof c === "string" && Object.prototype.hasOwnProperty.call(CURRENCIES, c.toUpperCase());

function currencyStatus(PLANS) {
  return Object.values(CURRENCIES).map((c) => {
    const priced = Object.values(PLANS.PLANS).filter((p) => p.prices && p.prices[c.code] != null).length;
    return { ...c, pricedPlans: priced, enabled: priced > 0 && priced === Object.keys(PLANS.PLANS).length };
  });
}

/* Kur sağlayıcı arayüzü: { id, async getRate(from, to): Promise<{ rate:number, asOf:string }> }  — bağlı sağlayıcı yok */
const rateProvider = { id: null, configured: false };
let customRateProvider = null;
function registerRateProvider(p) { if (!p || typeof p.getRate !== "function" || !p.id) throw new Error("Geçersiz kur sağlayıcısı"); customRateProvider = p; rateProvider.id = p.id; rateProvider.configured = true; }
async function convert(amount, from, to) {
  if (!isCurrency(from) || !isCurrency(to)) return { ok: false, reason: "Desteklenmeyen para birimi" };
  if (from.toUpperCase() === to.toUpperCase()) return { ok: true, amount, rate: 1 };
  if (!customRateProvider) return { ok: false, reason: "Kur sağlayıcısı yapılandırılmadı; kur uydurulmaz." };
  const r = await customRateProvider.getRate(from.toUpperCase(), to.toUpperCase());
  return { ok: true, amount: Math.round(amount * r.rate * 100) / 100, rate: r.rate, asOf: r.asOf };
}

/* Affiliate öneri veri modeli (Firestore: affiliateOffers/{id}) */
const AFFILIATE_FIELDS = Object.freeze({
  category: "string (ör. ssl, hosting, domain-registrar, security-tool)", relatedFindingId: "string (ör. finding_ssl_expiring_soon_critical)",
  provider: "string (sağlayıcı adı)", affiliateUrl: "https URL", disclosure: "string (reklam/ortaklık bildirimi metni)", status: "DRAFT|ACTIVE|PAUSED"
});
function validateAffiliateOffer(o) {
  const errors = [];
  if (!o || typeof o !== "object") return { ok: false, errors: ["Geçersiz kayıt"] };
  for (const k of ["category", "relatedFindingId", "provider"]) if (typeof o[k] !== "string" || !o[k].trim() || o[k].length > 120) errors.push(`${k} gerekli (en çok 120 karakter)`);
  try { const u = new URL(o.affiliateUrl); if (u.protocol !== "https:" || u.username || u.password) errors.push("affiliateUrl https olmalı ve kimlik bilgisi içermemeli"); } catch { errors.push("affiliateUrl geçersiz"); }
  if (typeof o.disclosure !== "string" || o.disclosure.trim().length < 10) errors.push("Ortaklık/reklam bildirimi (disclosure) zorunlu");
  if (!["DRAFT", "ACTIVE", "PAUSED"].includes(o.status || "DRAFT")) errors.push("status DRAFT, ACTIVE veya PAUSED olmalı");
  return { ok: errors.length === 0, errors };
}
const affiliateEnabled = () => false; // sağlayıcı/yönetim ekranı yapılandırılana kadar kapalı (env ile açılamaz)

function describe(PLANS) {
  return {
    currencies: currencyStatus(PLANS), rateProvider: { configured: rateProvider.configured, id: rateProvider.id, note: rateProvider.configured ? null : "Kur sağlayıcısı bağlı değil; dönüştürme yapılmaz." },
    affiliate: { enabled: affiliateEnabled(), fields: AFFILIATE_FIELDS, offersStored: 0, note: "Yalnızca veri modeli ve doğrulama hazır; aktif öneri/gelir yok." },
    payments: { note: "Ödeme sağlayıcıları (Stripe/iyzico) /health ve payments.js durumundan okunur; burada gelir verisi uydurulmaz." }
  };
}
module.exports = { CURRENCIES, isCurrency, currencyStatus, registerRateProvider, convert, AFFILIATE_FIELDS, validateAffiliateOffer, affiliateEnabled, describe };
