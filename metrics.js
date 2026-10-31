/* Digital Asset Center - Ölçümler (bellek içi; süreç yeniden başlayınca sıfırlanır — bu bilinçli ve admin panelinde belirtilir)
 * - API gecikmesi: P50 / P95 / P99 (nearest-rank), hata oranı (5xx / toplam)
 * - Tarama süresi, kuyruk bekleme süresi, iş tamamlanma süresi
 * - Son sistem hataları halkası (gizli veri temizlenerek)
 * NOT: Gecikme (ms) ile performans PUANI (0-100, taranan sitenin kalitesi) farklı kavramlardır; birbirine karıştırılmaz. */
"use strict";

const percentile = (sorted, p) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))] : null);
const round1 = (n) => (n == null ? null : Math.round(n * 10) / 10);

function summarize(values) {
  const s = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  return { count: s.length, p50: round1(percentile(s, 50)), p95: round1(percentile(s, 95)), p99: round1(percentile(s, 99)), max: s.length ? round1(s[s.length - 1]) : null, avg: s.length ? round1(s.reduce((a, b) => a + b, 0) / s.length) : null };
}

// Hata iletilerinden gizli veri temizle (belirteç, e-posta, anahtar benzeri uzun diziler)
function scrub(msg) {
  return String(msg == null ? "" : msg)
    .replace(/Bearer\s+[A-Za-z0-9._~+\/=-]+/gi, "Bearer [gizli]")
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g, "[jwt]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[e-posta]")
    .replace(/\b(sk|pk|rk|whsec)_[A-Za-z0-9_]{8,}/g, "[anahtar]")
    .replace(/[A-Za-z0-9_-]{40,}/g, "[gizli]")
    .slice(0, 300);
}

function createMetrics({ windowMs = 3600e3, maxSamples = 20000, maxErrors = 200, now = Date.now, onError = null } = {}) {
  const req = []; // { t, ms, status }
  const series = new Map(); // ad -> [{t, v}]
  const errors = [];
  let totalRequests = 0, total5xx = 0, total4xx = 0; const startedAt = now();

  const trim = (arr) => { const cut = now() - windowMs; while (arr.length && arr[0].t < cut) arr.shift(); while (arr.length > maxSamples) arr.shift(); };
  function observeRequest(ms, status) { req.push({ t: now(), ms, status }); totalRequests++; if (status >= 500) total5xx++; else if (status >= 400) total4xx++; trim(req); }
  function observe(name, v) { if (!Number.isFinite(v)) return; if (!series.has(name)) series.set(name, []); const a = series.get(name); a.push({ t: now(), v }); trim(a); }
  function recordError({ source = "server", message, status = null, path = null } = {}) {
    errors.push({ at: new Date(now()).toISOString(), source, status, path: path ? String(path).split("?")[0].slice(0, 120) : null, message: scrub(message) });
    while (errors.length > maxErrors) errors.shift();
    if (onError) { try { onError(errors[errors.length - 1]); } catch { /* kayıt hatası asıl işi bozmasın */ } }
  }
  function middleware(prefix = "/api") {
    return (req_, res, next) => {
      if (!req_.path.startsWith(prefix) && req_.path !== "/health") return next();
      const t0 = process.hrtime.bigint();
      res.on("finish", () => { const expected = !!(res.locals && res.locals.expectedBlock); observeRequest(Number(process.hrtime.bigint() - t0) / 1e6, expected ? 403 : res.statusCode); if (res.statusCode >= 500 && !expected) recordError({ source: "api", status: res.statusCode, path: req_.path, message: `HTTP ${res.statusCode} ${req_.method}` + (res.locals && res.locals.errDetail ? ` — ${res.locals.errDetail}` : "") }); });
      next();
    };
  }
  function snapshot() {
    trim(req);
    const lat = summarize(req.map((x) => x.ms));
    const n = req.length, e5 = req.filter((x) => x.status >= 500).length, e4 = req.filter((x) => x.status >= 400 && x.status < 500).length;
    const named = {}; for (const [k, a] of series) { trim(a); named[k] = summarize(a.map((x) => x.v)); }
    return {
      windowMinutes: Math.round(windowMs / 60000), sinceBoot: new Date(startedAt).toISOString(), volatile: true,
      api: { requests: n, latencyMs: lat, errorRate5xx: n ? round1((e5 / n) * 100) : null, errorRate4xx: n ? round1((e4 / n) * 100) : null, totals: { requests: totalRequests, status5xx: total5xx, status4xx: total4xx } },
      series: named
    };
  }
  const recentErrors = (limit = 50) => errors.slice(-limit).reverse();
  return { observeRequest, observe, recordError, middleware, snapshot, recentErrors, summarize, percentile };
}

module.exports = { createMetrics, summarize, percentile, scrub };
