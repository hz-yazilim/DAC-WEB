/* Digital Asset Center - Merkezi skor modülü
 * TEK yapılandırma noktası: aşağıdaki iki ağırlık tablosu. Başka hiçbir dosyada skor ağırlığı bulunmaz.
 *
 * 1) COMPOSITE (bileşik/genel skor): SEO %35 + Güvenlik %50 + Performans %15 (toplam = %100).
 *    Kritik bulgu sınırı: doğrulanmış bir "_critical" bulgusu varsa genel skor en fazla CRITICAL_CAP (75) olur.
 *    GEREKÇE: Ağırlıklı ortalama, tek bir ciddi güvenlik açığını yüksek SEO/performans ile "seyreltir". Kritik bulgusu olan
 *    bir varlığın "yeşil" görünmesi yanıltıcıdır; 75 sınırı onu en fazla "iyi ama sorunlu" bandında tutar (YEŞİL eşiği 80).
 *    "Doğrulanmış" = bulgu, tarama motorunun gerçekten yaptığı bir denetimden gelmiştir (tahmin/varsayım bulgusu değildir);
 *    taranmamış varlıklar için bulgu üretilmediğinden sınır uygulanmaz.
 *    Eksik skor ASLA 0 veya 100 sayılmaz: yalnızca mevcut kategoriler yeniden ağırlıklandırılır ve sonuç `complete:false` olur.
 *
 * 2) WEB_LEGACY: mevcut WEB taramasının "overall" skoru (erişilebilirlik dahil). DAVRANIŞ DEĞİŞMEDİ; yalnızca buraya taşındı.
 */
"use strict";

const COMPOSITE_WEIGHTS = Object.freeze({ seo: 35, security: 50, performance: 15 });
const CRITICAL_CAP = 75;
const WEB_LEGACY_WEIGHTS = Object.freeze({ availability: 35, security: 25, seo: 20, performance: 20 });

const isNum = (v) => typeof v === "number" && Number.isFinite(v);
const clamp = (n) => Math.max(0, Math.min(100, n));

function assertWeights(w = COMPOSITE_WEIGHTS) {
  const sum = Object.values(w).reduce((a, b) => a + b, 0);
  if (sum !== 100) throw new Error(`Skor ağırlıklarının toplamı 100 olmalı (şu an ${sum})`);
  return true;
}
assertWeights();

const hasCritical = (findings) => (Array.isArray(findings) ? findings : []).some((f) => typeof f === "string" && /_critical$/.test(f));
const level = (s) => (s == null ? "BELİRSİZ" : s >= 80 ? "YEŞİL" : s >= 50 ? "SARI" : "KIRMIZI");

/** scores: { seo, security, performance } (0-100 veya null/undefined = taranmadı); findings: bulgu kimlikleri */
function computeComposite(scores = {}, findings = [], weights = COMPOSITE_WEIGHTS) {
  const used = {}, missing = [];
  let wSum = 0, acc = 0;
  for (const k of Object.keys(weights)) {
    const v = scores[k];
    if (isNum(v)) { used[k] = clamp(v); wSum += weights[k]; acc += weights[k] * clamp(v); } else missing.push(k);
  }
  if (!wSum) return { score: null, rawScore: null, level: level(null), complete: false, coverage: 0, missing, capped: false, reason: "Hiçbir kategori taranmadı" };
  const rawScore = Math.round(acc / wSum);
  const critical = hasCritical(findings);
  const score = critical ? Math.min(rawScore, CRITICAL_CAP) : rawScore;
  return { score, rawScore, level: level(score), complete: missing.length === 0, coverage: wSum, missing, capped: critical && rawScore > CRITICAL_CAP, cap: critical ? CRITICAL_CAP : null, weights: { ...weights } };
}

/** Mevcut WEB skoru (erişilebilirlik dahil), davranış değişmeden. Kategorisi null olan hesaba katılmaz. */
function webLegacyOverall(gs, weights = WEB_LEGACY_WEIGHTS) {
  let tw = 0, ts = 0;
  for (const k in gs) if (gs[k] != null && weights[k]) { tw += weights[k]; ts += weights[k] * gs[k]; }
  return tw ? Math.round(ts / tw) : null;
}

/** Varlık listesinden (type + healthScore + findings) host başına bileşik skor: SEO/SECURITY/PERFORMANCE varlıkları ve WEB alt skorları. */
function compositeForHost(assets) {
  const s = {}, f = [];
  for (const a of assets) {
    const t = String(a.assetType || a.type || "").toUpperCase();
    const sc = a.specificAnalysis && a.specificAnalysis.scores;
    if (t === "SEO" && isNum(a.healthScore)) s.seo = a.healthScore;
    if (t === "SECURITY" && isNum(a.healthScore)) s.security = a.healthScore;
    if (t === "PERFORMANCE" && isNum(a.healthScore)) s.performance = a.healthScore;
    if ((t === "WEB" || t === "WEBSITE") && sc) for (const k of ["seo", "security", "performance"]) if (isNum(sc[k]) && s[k] == null) s[k] = sc[k];
    if (isNum(a.healthScore) || sc) f.push(...(Array.isArray(a.findings) ? a.findings : []));
  }
  return computeComposite(s, f);
}

module.exports = { COMPOSITE_WEIGHTS, CRITICAL_CAP, WEB_LEGACY_WEIGHTS, assertWeights, computeComposite, webLegacyOverall, compositeForHost, hasCritical, level };
