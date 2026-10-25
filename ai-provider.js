/* Digital Asset Center - AI sağlayıcı mimarisi (ŞİMDİLİK DEVRE DIŞI)
 * - Gemini (veya başka bir sağlayıcı) için API çağrısı YAPILMAZ, anahtar İSTENMEZ, hiçbir AI sonucu üretilmez.
 * - Bu dosya yalnızca gelecekte bir adaptör eklemek için sabit bir arayüz, yapılandırma/hata yönetimi ve kullanım/maliyet veri modeli tanımlar.
 * - Rapor servisi (buildPeriodReport) AI OLMADAN çalışır: tarama geçmişinden skor ve bulgu değişimini deterministik hesaplar.
 *
 * Gelecekte Gemini eklemek için: `registerProvider({ id:"gemini", name:"Google Gemini", isConfigured(){...}, async generate(request){...} })`
 * çağrısı yapan bir adaptör dosyası ekleyin VE AI_ENABLED=true ayarlayın. İkisi birden olmadan AI etkin OLMAZ. */
"use strict";

const AI_DISABLED_REASON = "AI özellikleri bilinçli olarak devre dışı: sağlayıcı adaptörü bağlanmadı ve API anahtarı tanımlanmadı.";
const providers = new Map();

/** Sağlayıcı arayüzü: { id, name, isConfigured(): boolean, generate(request): Promise<{ text, usage:{promptTokens,completionTokens}, model }> } */
function registerProvider(p) {
  if (!p || typeof p.id !== "string" || typeof p.generate !== "function" || typeof p.isConfigured !== "function") throw new Error("Geçersiz AI sağlayıcı arayüzü");
  providers.set(p.id, p);
}
const flagOn = () => String(process.env.AI_ENABLED || "").toLowerCase() === "true";
const activeProvider = () => providers.get(String(process.env.AI_PROVIDER || "gemini").toLowerCase()) || null;

function status() {
  const p = activeProvider(); const wanted = String(process.env.AI_PROVIDER || "gemini").toLowerCase();
  let enabled = false, reason = AI_DISABLED_REASON;
  if (!flagOn()) reason = AI_DISABLED_REASON + " (AI_ENABLED=true değil)";
  else if (!p) reason = `AI_ENABLED=true ancak "${wanted}" adaptörü kodda kayıtlı değil.`;
  else if (!p.isConfigured()) reason = `"${p.id}" adaptörü kayıtlı fakat yapılandırılmamış (anahtar eksik).`;
  else { enabled = true; reason = null; }
  return { enabled, reason, requestedProvider: wanted, registeredProviders: [...providers.keys()], geminiKeyRequested: false };
}

/** AI raporu isteği. Devre dışıyken ASLA başarılı sonuç döndürmez. */
async function generateAiReport(reportData) {
  const st = status();
  if (!st.enabled) return { ok: false, status: "DISABLED", reason: st.reason, ai: null };
  const p = activeProvider();
  try {
    const out = await p.generate({ kind: "period-report", data: reportData });
    return { ok: true, status: "GENERATED", provider: p.id, model: out.model || null, ai: { text: String(out.text || "") }, usage: out.usage || null };
  } catch (e) { return { ok: false, status: "ERROR", reason: String(e && e.message || e).slice(0, 200), ai: null }; }
}

/* ---------- Kullanım ve maliyet takibi veri modeli (Firestore: aiUsage/{auto}) — şu an hiç kayıt yazılmaz ---------- */
const USAGE_FIELDS = Object.freeze({
  at: "number (ms)", uid: "string", provider: "string", model: "string", feature: "string (ör. period-report)",
  promptTokens: "number", completionTokens: "number", costMicros: "number (para biriminin milyonda biri; kayan nokta yok)",
  currency: "string (TRY|USD|EUR…)", status: "OK|ERROR|DISABLED", errorCode: "string|null", reportId: "string|null"
});
async function recordUsage(db, rec) {
  if (!db) return false;
  const clean = { at: Date.now(), uid: String(rec.uid || ""), provider: String(rec.provider || ""), model: String(rec.model || ""), feature: String(rec.feature || ""), promptTokens: +rec.promptTokens || 0, completionTokens: +rec.completionTokens || 0, costMicros: Math.round(+rec.costMicros || 0), currency: String(rec.currency || "USD").toUpperCase().slice(0, 3), status: ["OK", "ERROR", "DISABLED"].includes(rec.status) ? rec.status : "ERROR", errorCode: rec.errorCode || null, reportId: rec.reportId || null };
  await db.collection("aiUsage").doc().set(clean); return true;
}

/* ---------- Aylık / yıllık rapor veri modeli (AI'siz, deterministik) ----------
 * checks: [{ assetId, type, healthScore, findings:[...], checkedAt(ms) }]  → asset başına dönem başı/sonu skor, fark, yeni/çözülen bulgular */
function periodBounds(periodType, year, month) {
  if (periodType === "yearly") return { from: Date.UTC(year, 0, 1), to: Date.UTC(year + 1, 0, 1) };
  if (periodType === "monthly") return { from: Date.UTC(year, month - 1, 1), to: Date.UTC(year, month, 1) };
  throw new Error("periodType monthly veya yearly olmalı");
}
function buildPeriodReport(checks, { periodType, year, month }) {
  const { from, to } = periodBounds(periodType, year, month);
  const byAsset = new Map();
  for (const c of checks) { const t = +c.checkedAt; if (!Number.isFinite(t) || t < from || t >= to) continue; if (!byAsset.has(c.assetId)) byAsset.set(c.assetId, []); byAsset.get(c.assetId).push(c); }
  const assets = [];
  for (const [assetId, arr] of byAsset) {
    arr.sort((a, b) => a.checkedAt - b.checkedAt); const first = arr[0], last = arr[arr.length - 1];
    const f0 = new Set(first.findings || []), f1 = new Set(last.findings || []);
    const s0 = Number.isFinite(first.healthScore) ? first.healthScore : null, s1 = Number.isFinite(last.healthScore) ? last.healthScore : null;
    assets.push({ assetId, type: last.type, scans: arr.length, scoreStart: s0, scoreEnd: s1, scoreDelta: s0 != null && s1 != null ? s1 - s0 : null,
      newFindings: [...f1].filter((f) => !f0.has(f)).slice(0, 50), resolvedFindings: [...f0].filter((f) => !f1.has(f)).slice(0, 50) });
  }
  const deltas = assets.map((a) => a.scoreDelta).filter((d) => d != null);
  return { schema: "dac.period-report/1", periodType, year, month: periodType === "monthly" ? month : null, from: new Date(from).toISOString(), to: new Date(to).toISOString(),
    totals: { assets: assets.length, scans: assets.reduce((n, a) => n + a.scans, 0), improved: deltas.filter((d) => d > 0).length, declined: deltas.filter((d) => d < 0).length, unchanged: deltas.filter((d) => d === 0).length },
    assets, ai: { status: status().enabled ? "AVAILABLE" : "DISABLED", summary: null, note: "AI özeti üretilmedi." } };
}

function describe() {
  return { status: status(), usageModel: { collection: "aiUsage", fields: USAGE_FIELDS, recordsWritten: 0, note: "AI çağrısı yapılmadığı için hiç kullanım/maliyet kaydı yok." },
    reportModel: { schema: "dac.period-report/1", periods: ["monthly", "yearly"], aiIndependent: true, endpoint: "GET /api/reports/period?type=monthly|yearly&year=YYYY&month=M" },
    configuration: { env: ["AI_ENABLED (varsayılan kapalı)", "AI_PROVIDER (varsayılan gemini)", "GEMINI_API_KEY (şimdilik İSTENMİYOR, okunmuyor)"], extensionPoint: "registerProvider() — ai-provider.js" } };
}

module.exports = { registerProvider, status, generateAiReport, recordUsage, buildPeriodReport, periodBounds, describe, USAGE_FIELDS };
