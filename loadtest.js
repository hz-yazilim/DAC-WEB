// Basit gecikme ölçüm aracı (bağımlılıksız): P50/P95/P99 ve hata oranı. Kullanım:
//   node loadtest.js https://dac-web-tfqf.onrender.com/health 200 10
// (url, toplam istek, eşzamanlılık). Sunucunun /api/admin/overview içindeki P95 değeriyle karşılaştırın.
// NOT: Bu ölçüm HTTP gecikmesidir (ms); taranan sitenin "performans puanı" (0-100) ile ilgisi yoktur.
const url = process.argv[2] || "http://127.0.0.1:3000/health", total = +process.argv[3] || 200, conc = +process.argv[4] || 10;
const lat = []; let err = 0, next = 0;
const pct = (a, p) => (a.length ? a[Math.min(a.length - 1, Math.ceil((p / 100) * a.length) - 1)] : null);
async function worker() { while (next++ < total) { const t0 = process.hrtime.bigint(); try { const r = await fetch(url); await r.arrayBuffer(); if (r.status >= 500) err++; } catch { err++; } lat.push(Number(process.hrtime.bigint() - t0) / 1e6); } }
(async () => { const t0 = Date.now(); await Promise.all(Array.from({ length: conc }, worker)); lat.sort((a, b) => a - b); const f = (x) => (x == null ? null : Math.round(x * 10) / 10);
  console.log(JSON.stringify({ url, requests: lat.length, concurrency: conc, seconds: (Date.now() - t0) / 1000, errorRate: Math.round((err / lat.length) * 1000) / 10 + "%", p50: f(pct(lat, 50)), p95: f(pct(lat, 95)), p99: f(pct(lat, 99)), max: f(lat[lat.length - 1]) }, null, 2)); })();
