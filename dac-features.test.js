// DAC V13.1 yeni özellik testleri: skor, doğrulama, kuyruk, admin erişimi, SSRF, ölçüm.
// Firestore için MOCK kullanılır (gerçek Firestore entegrasyonunu KANITLAMAZ). Ağ erişimi gerektiren gerçek tarama testi yoktur.
process.env.NODE_ENV = "development";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const _p = require("path"), _fs = require("fs");
const ROOT = _fs.existsSync(_p.join(__dirname, "index.js")) ? __dirname : _p.join(__dirname, "..");
const LOAD = (n) => require(_fs.existsSync(_p.join(ROOT, "server", n + ".js")) ? _p.join(ROOT, "server", n) : _p.join(ROOT, n));
const PUBFILE = (n) => { const a = _p.join(ROOT, "public"); if (!_fs.existsSync(a)) return _p.join(ROOT, n); const f = _p.join(a, n); return _fs.existsSync(f) ? f : (_fs.readdirSync(a, { recursive: true }).map((x) => _p.join(a, x)).find((x) => _p.basename(x) === n) || f); };
const APP_FILES = ["app.js", "app-analysis.js", "app-main.js", "app-bulk.js", "app-admin.js", "app-admin-ops.js", "app-support.js"];
const SRC = (n) => _fs.readFileSync(_fs.existsSync(_p.join(ROOT, "server", n)) ? _p.join(ROOT, "server", n) : _p.join(ROOT, n), "utf8");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = (app) => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const url = (s, p) => `http://127.0.0.1:${s.address().port}${p}`;
const express = require("express");

// ================= SKOR =================
const SC = LOAD("scoring");
test("Skor: ağırlıklar tek noktada ve toplamı %100 (SEO 35, Güvenlik 50, Performans 15)", () => {
  assert.deepEqual({ ...SC.COMPOSITE_WEIGHTS }, { seo: 35, security: 50, performance: 15 });
  assert.equal(Object.values(SC.COMPOSITE_WEIGHTS).reduce((a, b) => a + b, 0), 100);
  assert.equal(SC.assertWeights({ a: 60, b: 40 }), true);
  assert.throws(() => SC.assertWeights({ a: 60, b: 30 }), /100/);
});
test("Skor: SEO 100 / Güvenlik 70 / Performans 90 → 84 (kritik bulgu yok)", () => {
  const r = SC.computeComposite({ seo: 100, security: 70, performance: 90 }, ["finding_x_warning"]);
  assert.equal(r.score, 84); assert.equal(r.rawScore, 84); assert.equal(r.capped, false); assert.equal(r.complete, true);
});
test("Skor: doğrulanmış kritik bulgu genel skoru 75'e sınırlar; sınırın altındaki skor değişmez", () => {
  const hi = SC.computeComposite({ seo: 100, security: 100, performance: 100 }, ["finding_ssl_expired_critical"]);
  assert.equal(hi.score, 75); assert.equal(hi.rawScore, 100); assert.equal(hi.capped, true); assert.equal(hi.level, "SARI");
  const lo = SC.computeComposite({ seo: 40, security: 50, performance: 60 }, ["finding_x_critical"]);
  assert.equal(lo.score, 50 * 0.5 + 40 * 0.35 + 60 * 0.15); assert.equal(lo.capped, false);
  assert.equal(SC.computeComposite({ seo: 100, security: 100, performance: 100 }, ["finding_x_critical_note"]).score, 100, "yalnızca _critical ile biten bulgular sınır uygular");
});
test("Skor: eksik skor ASLA 0 veya 100 sayılmaz; hiç veri yoksa null", () => {
  const none = SC.computeComposite({}, []); assert.equal(none.score, null); assert.equal(none.level, "BELİRSİZ");
  const p = SC.computeComposite({ security: 70 }, []); assert.equal(p.score, 70); assert.equal(p.complete, false); assert.deepEqual(p.missing.sort(), ["performance", "seo"]); assert.equal(p.coverage, 50);
  assert.equal(SC.computeComposite({ seo: null, security: undefined, performance: "90" }, []).score, null, "sayı olmayan değer taranmamış sayılır");
});
test("Skor: mevcut WEB skoru (erişilebilirlik dahil) davranışı değişmedi", () => {
  assert.equal(SC.webLegacyOverall({ availability: 100, security: 80, seo: 60, performance: 40 }), Math.round((35 * 100 + 25 * 80 + 20 * 60 + 20 * 40) / 100));
  assert.equal(SC.webLegacyOverall({ availability: 100, security: null, seo: 60, performance: null }), Math.round((35 * 100 + 20 * 60) / 55));
  assert.equal(SC.webLegacyOverall({ availability: null }), null);
});
test("Skor: taranmamış varlıklar host bileşik skoruna eklenmez", () => {
  const h = SC.compositeForHost([{ assetType: "SEO", healthScore: 90, findings: [] }, { assetType: "SECURITY", healthScore: null, findings: [] }]);
  assert.equal(h.score, 90); assert.equal(h.complete, false);
  assert.equal(SC.compositeForHost([{ assetType: "SSL_CERTIFICATE", healthScore: 99 }]).score, null);
});

// ================= DOĞRULAMA =================
const V = LOAD("validators");
test("Doğrulama: domain biçimi — geçerli, IDN, hatalı, IP ve tehlikeli girdiler", () => {
  assert.equal(V.normalizeDomain("https://WWW.Ornek.com/yol?x=1#a").domain, "ornek.com");
  assert.equal(V.normalizeDomain("alt.ornek.com.tr:8443").domain, "alt.ornek.com.tr");
  assert.equal(V.normalizeDomain("örnek.com").domain, "xn--rnek-4qa.com");
  for (const bad of ["", "   ", "localhost", "tek", "127.0.0.1", "10.0.0.1", "[::1]", "a_b.com", "-a.com", "a-.com", "a..com", "ornek.123", "user:pw@ornek.com", "ornek.com\n.evil", "x".repeat(64) + ".com", ("a.".repeat(130)) + "com"]) assert.equal(V.normalizeDomain(bad).ok, false, JSON.stringify(bad));
  for (const bad of [null, undefined, 5, {}, []]) assert.equal(V.normalizeDomain(bad).ok, false);
});
test("Doğrulama: URL yalnızca http/https, kimlik bilgisi yok", () => {
  assert.equal(V.normalizeUrl("ornek.com/a").url, "https://ornek.com/a");
  for (const bad of ["ftp://x.com", "file:///etc/passwd", "javascript:alert(1)", "https://u:p@x.com", "", "http://" + "a".repeat(3000) + ".com"]) assert.equal(V.normalizeUrl(bad).ok, false, bad.slice(0, 30));
});
test("Doğrulama: telefon biçimi ve uzunluğu", () => {
  assert.equal(V.normalizePhone("+90 532 123 45 67").phone, "+905321234567"); assert.equal(V.normalizePhone("0532-123-45-67").phone, "+905321234567"); assert.equal(V.normalizePhone("+1 (202) 555-0143").phone, "+12025550143");
  for (const bad of ["", "123", "abc", "+90 212 123 45 67", "+90 532 123 45", "+9" + "1".repeat(20), "5321234567" + "9".repeat(30), "++905321234567"]) assert.equal(V.normalizePhone(bad).ok, false, bad);
});
test("Doğrulama: vergi no isteğe bağlı 10 hane; TC kimlik alanı artık yok", () => {
  assert.equal(V.normalizeTaxId("").ok, true); assert.equal(V.normalizeTaxId("1234567890").taxId, "1234567890"); assert.equal(V.normalizeTaxId("12345678901").ok, false); assert.equal(V.normalizeTaxId("abc").ok, false);
  assert.ok(!/TC Kimlik/i.test(APP_FILES.map(SRC).join("\n")), "arayüzde TC Kimlik alanı kalmamalı");
  assert.ok(!/identityNumber:\s*String\(billing\.taxId/.test(SRC("payments.js")), "ödeme sağlayıcıya kullanıcıdan TC aktarılmamalı");
});
test("Doğrulama: toplu içe aktarma — 250 satır, yinelenen, hatalı, başlık ve sınır", () => {
  const lines = ["domain"]; for (let i = 0; i < 250; i++) lines.push(`site${i}.com`); lines.push("site1.com", "kötü domain", "http://www.site2.com/x", "", "127.0.0.1");
  const r = V.parseBulkDomains(lines.join("\n"));
  assert.equal(r.valid.length, 250); assert.equal(r.duplicates.length, 2); assert.equal(r.invalid.length, 2); assert.equal(r.truncated, false);
  const big = V.parseBulkDomains(Array.from({ length: 50 }, (_, i) => `d${i}.com`).join(","), { max: 10 }); assert.equal(big.valid.length, 10); assert.equal(big.truncated, true);
  assert.deepEqual(V.parseBulkDomains(12345).valid, []);
});

// ================= ÖLÇÜM =================
const M = LOAD("metrics");
test("Ölçüm: P50/P95/P99 (nearest-rank) ve hata oranı", () => {
  const m = M.createMetrics(); for (let i = 1; i <= 100; i++) m.observeRequest(i, i <= 95 ? 200 : 500);
  const s = m.snapshot().api; assert.equal(s.latencyMs.p50, 50); assert.equal(s.latencyMs.p95, 95); assert.equal(s.latencyMs.p99, 99); assert.equal(s.errorRate5xx, 5); assert.equal(s.requests, 100);
  assert.equal(M.createMetrics().snapshot().api.latencyMs.p95, null, "veri yokken P95 uydurulmaz");
});
test("Ölçüm: hata kayıtlarında belirteç, e-posta ve anahtar maskelenir", () => {
  const m = M.createMetrics(); m.recordError({ message: "Authorization: Bearer abc.DEF-123_xyz mail ali@ornek.com sk_live_ABCDEFGHIJ1234 " + "k".repeat(60) });
  const e = m.recentErrors(1)[0].message; assert.ok(!/abc\.DEF|ali@ornek|sk_live_ABC|kkkkkkkk/.test(e), e);
});
test("Ölçüm: gerçek HTTP isteklerinde sunucu P95 değeri istemci ölçümüyle tutarlı", async () => {
  const m = M.createMetrics(), app = express(); app.use(m.middleware("/api")); app.get("/api/x", (q, r) => setTimeout(() => r.json({ ok: 1 }), 5 + (Math.random() * 10 | 0)));
  const s = await listen(app), client = [];
  for (let i = 0; i < 120; i++) { const t0 = process.hrtime.bigint(); await (await fetch(url(s, "/api/x"))).json(); client.push(Number(process.hrtime.bigint() - t0) / 1e6); }
  s.close(); client.sort((a, b) => a - b); const cP95 = client[Math.ceil(0.95 * client.length) - 1], sP95 = m.snapshot().api.latencyMs.p95;
  assert.ok(sP95 >= 5 && sP95 <= cP95 + 1, `sunucu P95=${sP95} istemci P95=${cP95}`);
});

// ================= KUYRUK =================
const J = LOAD("jobs");
const mkItems = (n, prefix = "a") => Array.from({ length: n }, (_, i) => ({ assetId: `${prefix}${i}`, type: "DOMAIN", targetUrl: `d${i}.com`, name: `d${i}.com` }));
async function drain(q, jobId, owner, ms = 8000) { const t0 = Date.now(); for (;;) { const j = await q.getJob(jobId, owner); if (!["PENDING", "RUNNING"].includes(j.status)) return j; if (Date.now() - t0 > ms) throw new Error("kuyruk bitmedi: " + JSON.stringify(j.counts)); await q.tick(); await sleep(5); } }
test("Kuyruk: 250 domain tek istekte kaydedilir, eşzamanlılık sınırına uyarak tamamlanır", async () => {
  let cur = 0, peak = 0; const per = new Map(); const metrics = M.createMetrics();
  const q = J.createJobs({ store: J.memoryStore(), metrics, config: { concurrency: 5, perUser: 5, tickMs: 5 }, scanItem: async (it) => { cur++; peak = Math.max(peak, cur); await sleep(2); cur--; return { scanStatus: "COMPLETED", summary: { score: 90, expiresAt: "2027-01-01T00:00:00.000Z", remainingDays: 100 + (+it.assetId.slice(1)) } }; } });
  const job = await q.createJob({ ownerId: "u1", items: mkItems(250) }); assert.equal(job.total, 250); assert.equal(job.status, "PENDING");
  const done = await drain(q, job.id, "u1"); assert.equal(done.status, "COMPLETED"); assert.equal(done.counts.COMPLETED, 250); assert.ok(peak <= 5 && peak >= 2, "peak=" + peak);
  assert.equal(Object.values(done.counts).reduce((a, b) => a + b, 0), 250);
  const page = await q.queryItems(job.id, "u1", { page: 2, pageSize: 100, sort: "remainingDays", order: "desc" }); assert.equal(page.total, 250); assert.equal(page.items.length, 100);
  assert.ok(metrics.snapshot().series.queueWaitMs.count === 250 && metrics.snapshot().series.jobCompletionMs.count === 1);
});
test("Kuyruk: durum kalıcıdır — süreç çökerse yarım kalan işler yeniden başlayınca tamamlanır", async () => {
  const store = J.memoryStore(); let hang = true;
  const q1 = J.createJobs({ store, config: { concurrency: 3, perUser: 3, tickMs: 5 }, scanItem: () => new Promise(() => {}) });
  const job = await q1.createJob({ ownerId: "u1", items: mkItems(8) }); await q1.tick(); await sleep(20);
  assert.equal((await store.getJob(job.id)).counts.RUNNING, 3, "3 öğe çalışırken 'çökme'");
  // q1 atılır (stop çağrılmaz = çökme). Yeni örnek aynı depodan devam eder:
  const q2 = J.createJobs({ store, config: { concurrency: 4, perUser: 4, tickMs: 5 }, scanItem: async () => ({ scanStatus: "COMPLETED", summary: { score: 80 } }) });
  const r = await q2.recover(); assert.equal(r.recovered, 3);
  const done = await drain(q2, job.id, "u1"); assert.equal(done.status, "COMPLETED"); assert.equal(done.counts.COMPLETED, 8);
  assert.equal((await store.listItemsByJob(job.id)).filter((i) => i.recovered).length, 3);
});
test("Kuyruk: kontrollü yeniden deneme, zaman aşımı, kalıcı hata ve iptal", async () => {
  let n = 0; const fails = new Map();
  const q = J.createJobs({ store: J.memoryStore(), config: { concurrency: 4, perUser: 4, tickMs: 5, maxAttempts: 3, backoffBaseMs: 10, timeoutMs: 40 }, scanItem: async (it) => {
    if (it.assetId === "ok") return { scanStatus: "COMPLETED", summary: {} };
    if (it.assetId === "flaky") { if (++n < 3) throw Object.assign(new Error("geçici"), { code: "SCAN_FAILED", retriable: true }); return { scanStatus: "PARTIAL", summary: {} }; }
    if (it.assetId === "always") throw Object.assign(new Error("hep hata"), { code: "SCAN_FAILED", retriable: true });
    if (it.assetId === "slow") { await sleep(500); return { scanStatus: "COMPLETED", summary: {} }; }
    if (it.assetId === "forbidden") throw Object.assign(new Error("size ait değil"), { code: "FORBIDDEN", retriable: false });
  } });
  const job = await q.createJob({ ownerId: "u1", items: ["ok", "flaky", "always", "slow", "forbidden"].map((id) => ({ assetId: id, type: "DOMAIN", targetUrl: id + ".com" })) });
  const done = await drain(q, job.id, "u1"); const it = Object.fromEntries((await q._store.listItemsByJob(job.id)).map((i) => [i.assetId, i]));
  assert.equal(it.ok.status, "COMPLETED"); assert.equal(it.flaky.status, "PARTIAL"); assert.equal(it.flaky.attempts, 3);
  assert.equal(it.always.status, "FAILED"); assert.equal(it.always.attempts, 3); assert.equal(it.slow.status, "FAILED"); assert.equal(it.slow.error.code, "TIMEOUT");
  assert.equal(it.forbidden.status, "FAILED"); assert.equal(it.forbidden.attempts, 1, "kalıcı hata yeniden denenmez");
  assert.equal(done.status, "PARTIAL"); assert.equal(done.counts.FAILED, 3);
  // güvenli yeniden deneme: yalnızca FAILED öğeler, tamamlananlara dokunmaz
  const r = await q.retryItems(job.id, "u1", { itemIds: [it.forbidden.id, it.ok.id] }); assert.equal(r.requeued, 1);
  assert.equal((await q._store.getItem(it.ok.id)).attempts, 1);
});
test("Kuyruk: iptal bekleyenleri durdurur; iptal edilen iş yeniden denenebilir; çalışanlar tamamlanır", async () => {
  const q = J.createJobs({ store: J.memoryStore(), config: { concurrency: 1, perUser: 1, tickMs: 5 }, scanItem: async () => { await sleep(30); return { scanStatus: "COMPLETED", summary: {} }; } });
  const job = await q.createJob({ ownerId: "u1", items: mkItems(6) }); await q.tick(); await sleep(5);
  const c = await q.cancelJob(job.id, "u1"); assert.equal(c.canceled, 5);
  const done = await drain(q, job.id, "u1"); assert.equal(done.counts.CANCELED, 5); assert.equal(done.counts.COMPLETED, 1); assert.equal(done.status, "PARTIAL");
  const r = await q.retryItems(job.id, "u1", { includeCanceled: true }); assert.equal(r.requeued, 5); const d2 = await drain(q, job.id, "u1"); assert.equal(d2.status, "COMPLETED");
});
test("Kuyruk: kullanıcılar arası izolasyon, kullanıcı başına eşzamanlılık ve kota sınırları", async () => {
  const q = J.createJobs({ store: J.memoryStore(), config: { concurrency: 4, perUser: 1, tickMs: 5, maxItemsPerJob: 10, maxActiveJobsPerUser: 2, maxQueuedPerUser: 15 }, scanItem: async () => { await sleep(10); return { scanStatus: "COMPLETED", summary: {} }; } });
  q.stop(); // elle tick
  const a = await q.createJob({ ownerId: "alice", items: mkItems(4, "a") }); const b = await q.createJob({ ownerId: "bob", items: mkItems(4, "b") });
  await assert.rejects(() => q.getJob(a.id, "bob"), (e) => e.status === 404); await assert.rejects(() => q.queryItems(a.id, "bob", {}), (e) => e.status === 404);
  await assert.rejects(() => q.cancelJob(a.id, "bob"), (e) => e.status === 404); await assert.rejects(() => q.retryItems(a.id, "bob", {}), (e) => e.status === 404);
  assert.deepEqual((await q.listJobs("alice")).map((j) => j.id), [a.id]); assert.equal((await q.listAllJobs()).length, 2, "yönetici görünümü hepsini listeler");
  await assert.rejects(() => q.createJob({ ownerId: "alice", items: mkItems(11, "x") }), (e) => e.code === "TOO_MANY_ITEMS");
  await q.createJob({ ownerId: "alice", items: mkItems(2, "y") }); await assert.rejects(() => q.createJob({ ownerId: "alice", items: mkItems(2, "z") }), (e) => e.code === "TOO_MANY_JOBS");
  await assert.rejects(() => q.createJob({ ownerId: "alice", items: [] }), (e) => e.status === 400);
});
test("Kuyruk: Firestore bağdaştırıcısı (sahte Firestore) ile kalıcılık ve yeniden başlatma", async () => {
  const data = {};
  const colAPI = (c) => ({ doc: (id) => ({ set: async (d, o) => { data[c] = data[c] || {}; data[c][id] = o && o.merge ? { ...(data[c][id] || {}), ...d } : d; }, get: async () => ({ exists: !!(data[c] && data[c][id]), data: () => data[c][id] }), delete: async () => { delete data[c][id]; } }),
    where: (f, op, v) => ({ limit: (n) => ({ get: async () => ({ docs: Object.values(data[c] || {}).filter((x) => x[f] === v).slice(0, n).map((x) => ({ data: () => x })) }), }), count: () => ({ get: async () => ({ data: () => ({ count: Object.values(data[c] || {}).filter((x) => x[f] === v).length }) }) }) }), limit: (n) => ({ get: async () => ({ docs: Object.values(data[c] || {}).slice(0, n).map((x) => ({ data: () => x })) }) }) });
  const db = { collection: colAPI, batch: () => { const ops = []; return { set: (ref, d) => ops.push([ref, d]), commit: async () => { for (const [ref, d] of ops) await ref.set(d); } }; } };
  const q1 = J.createJobs({ store: J.firestoreStore(db), config: { concurrency: 2, perUser: 2, tickMs: 5 }, scanItem: () => new Promise(() => {}) });
  const job = await q1.createJob({ ownerId: "u1", items: mkItems(5) }); await q1.tick(); await sleep(10); assert.equal(job.persistent, true);
  const q2 = J.createJobs({ store: J.firestoreStore(db), config: { concurrency: 5, perUser: 5, tickMs: 5 }, scanItem: async () => ({ scanStatus: "COMPLETED", summary: { score: 1 } }) });
  assert.equal((await q2.recover()).recovered, 2); const done = await drain(q2, job.id, "u1"); assert.equal(done.status, "COMPLETED");
  assert.ok(data.scanJobs[job.id] && Object.keys(data.scanJobItems).length === 5, "scanJobs / scanJobItems koleksiyonlarına yazıldı");
});
test("Kuyruk: CSV dışa aktarma formül enjeksiyonunu ve tırnakları güvenli yazar", () => {
  const csv = J.itemsToCsv([{ name: '=HYPERLINK("http://x")', targetUrl: "a,b.com", type: "DOMAIN", status: "FAILED", attempts: 1, error: { code: "X", message: "satır\nsonu" } }]);
  assert.ok(csv.includes("\"'=HYPERLINK(\"\"http://x\"\")\"") || csv.includes("'=HYPERLINK"), csv); assert.ok(!/(^|,)=HYPERLINK/.test(csv.split("\r\n")[1])); assert.ok(csv.includes('"a,b.com"')); assert.equal(J.csvCell("+1"), "'+1");
});

// ================= HTTP: toplu iş uçları (geliştirme kullanıcısı) =================
const APP = require(_p.join(ROOT, "index")); const I = APP._internals;
async function withDevAuth(fn) { const old = process.env.DEV_AUTH_BYPASS; process.env.DEV_AUTH_BYPASS = "true"; const s = await listen(APP); try { await I.JOBS.stop(); await fn(s); } finally { s.close(); if (old === undefined) delete process.env.DEV_AUTH_BYPASS; else process.env.DEV_AUTH_BYPASS = old; } }
const api = (s, m, p, body) => fetch(url(s, p), { method: m, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
test("HTTP: 250 domain POST /api/jobs ile kaydedilir; arama/filtre/sıralama/sayfalama/CSV/iptal çalışır", async () => {
  await withDevAuth(async (s) => {
    const items = Array.from({ length: 250 }, (_, i) => ({ assetId: "t_" + i, type: "DOMAIN", target: i % 50 === 0 ? `https://www.Site${i}.com/x` : `site${i}.com`, name: `Site ${i}` }));
    items.push({ assetId: "bad1", type: "DOMAIN", target: "127.0.0.1" }, { assetId: "bad2", type: "DOMAIN", target: "kötü alan" }, { assetId: "t_1", type: "DOMAIN", target: "dup.com" }, { assetId: "../x", type: "DOMAIN", target: "x.com" }, { assetId: "p1", type: "SERVER", target: "x.com" }, { assetId: "z", type: "BRAND", target: "x" });
    const r = await api(s, "POST", "/api/jobs", { items, label: "test" }); const j = await r.json(); assert.equal(r.status, 201, JSON.stringify(j)); assert.equal(j.accepted, 250); assert.equal(j.rejectedCount, 6); assert.equal(j.job.total, 250); assert.equal(j.job.counts.PENDING, 250);
    const id = j.job.id;
    assert.equal((await (await api(s, "GET", "/api/jobs/" + id)).json()).job.status, "PENDING");
    const pg = await (await api(s, "GET", `/api/jobs/${id}/items?page=3&pageSize=100&sort=name&order=desc`)).json(); assert.equal(pg.total, 250); assert.equal(pg.items.length, 50);
    const q = await (await api(s, "GET", `/api/jobs/${id}/items?q=site7`)).json(); assert.ok(q.total >= 11 && q.items.every((x) => /site7/i.test(x.name + x.targetUrl)));
    assert.equal((await (await api(s, "GET", `/api/jobs/${id}/items?status=FAILED`)).json()).total, 0);
    const csv = await (await api(s, "GET", `/api/jobs/${id}/export.csv`)).text(); assert.equal(csv.trim().split("\r\n").length, 251);
    assert.equal((await api(s, "GET", "/api/jobs/not-a-job")).status, 400); assert.equal((await api(s, "GET", "/api/jobs/job_doesnotexist123")).status, 404);
    const c = await (await api(s, "POST", `/api/jobs/${id}/cancel`)).json(); assert.equal(c.canceled, 250); assert.equal(c.job.status, "CANCELED");
    assert.equal((await api(s, "POST", "/api/jobs", { items: [] })).status, 400); assert.equal((await api(s, "POST", "/api/jobs", {})).status, 400);
  });
});
test("HTTP: toplu iş uçları oturum olmadan reddedilir", async () => {
  const s = await listen(APP); const old = process.env.DEV_AUTH_BYPASS; delete process.env.DEV_AUTH_BYPASS;
  for (const [m, p] of [["POST", "/api/jobs"], ["GET", "/api/jobs"], ["GET", "/api/jobs/job_abcdefgh"], ["GET", "/api/reports/period"], ["GET", "/api/scores/hosts"], ["GET", "/api/admin/overview"], ["GET", "/api/admin/users"], ["POST", "/api/admin/admins"], ["GET", "/api/me/admin"]]) { const r = await api(s, m, p, m === "POST" ? {} : undefined); assert.ok([401, 503].includes(r.status), `${m} ${p} -> ${r.status}`); await r.arrayBuffer(); }
  s.close(); if (old !== undefined) process.env.DEV_AUTH_BYPASS = old;
});

// ================= SSRF (kuyruk yolu dahil) =================
test("SSRF: kuyruk işleyicisi özel/yerel/metadata hedeflerini taramadan reddeder (yeniden denemez)", async () => {
  for (const host of ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.5", "192.168.1.1", "metadata.google.internal", "[::1]", "2130706433", "0x7f000001"]) {
    await assert.rejects(() => I.queueScanItem({ ownerId: "dev-user", assetId: "s1", type: "DOMAIN", targetUrl: host }), (e) => e.code === "BLOCKED_TARGET" && e.retriable === false, host);
  }
  await assert.rejects(() => I.queueScanItem({ ownerId: "dev-user", assetId: "s2", type: "SERVER", targetUrl: "example.com" }), (e) => e.code === "CONSENT_REQUIRED");
  await assert.rejects(() => I.queueScanItem({ ownerId: "dev-user", assetId: "s3", type: "NOPE", targetUrl: "example.com" }), (e) => e.code === "UNSUPPORTED_TYPE");
});

// ================= DOMAIN BİTİŞ TARİHİ =================
test("Domain bitiş tarihi yalnızca RDAP kaydından okunur; veri yoksa uydurulmaz", () => {
  const ev = (a, d) => ({ events: [{ eventAction: a, eventDate: d }] });
  assert.equal(I.toDateOrNull(I.rdapDate(ev("expiration", "2027-03-01T00:00:00Z"), ["expiration", "expiry"])).toISOString(), "2027-03-01T00:00:00.000Z");
  assert.equal(I.toDateOrNull(I.rdapDate(ev("registration", "2020-01-01T00:00:00Z"), ["expiration", "expiry"])), null);
  const ok = I.scanSummary({ scanStatus: "COMPLETED", assetUpdate: { healthScore: 80, status: "HEALTHY", specificAnalysis: { registration: { expiresAt: new Date("2027-03-01T00:00:00Z"), remainingDays: 130, source: "rdap" } } } }, "DOMAIN");
  assert.equal(ok.expiresAt, "2027-03-01T00:00:00.000Z"); assert.equal(ok.remainingDays, 130);
  const none = I.scanSummary({ scanStatus: "PARTIAL", assetUpdate: { healthScore: 60, specificAnalysis: { registration: {} } } }, "DOMAIN"); assert.equal(none.expiresAt, null); assert.equal(none.remainingDays, null);
  assert.equal(I.scanSummary({ scanStatus: "COMPLETED", assetUpdate: { healthScore: 60 } }, "WEBSITE").expiresAt, undefined, "domain dışı türler tarih alanı taşımaz");
  const src = SRC("index.js"); assert.ok(/expiration = toDateOrNull\(rd \? rdapDate\(rd, EXPIRY_ACTIONS\)/.test(src) && /\|\| \(wh && wh\.expiry\)/.test(src), "bitiş tarihi yalnızca RDAP veya WHOIS kaydından"); assert.ok(!/expiration\s*=\s*[^;]*(headers|Date\.now)/.test(src.slice(src.indexOf("async function scanDomain"), src.indexOf("async function scanDomain") + 9000)), "HTTP yanıtından tahmin yok");
});

// ================= YÖNETİCİ =================
function adminApp({ env = {}, users = {}, roles = {}, limits = {} } = {}) {
  Object.assign(process.env, { ADMIN_UIDS: "", ADMIN_EMAILS: "", ...env }); const store = { adminRoles: { ...roles }, adminAudit: {}, assets: { a1: { ownerId: "u1", assetType: "DOMAIN" }, a2: { ownerId: "u1", assetType: "SEO" }, a3: { ownerId: "u2", assetType: "DOMAIN" } } }; let aid = 0;
  const col = (c) => ({ doc: (id) => { id = id || "auto" + ++aid; return { id, get: async () => ({ exists: !!(store[c] && store[c][id]), data: () => store[c][id] }), set: async (d) => { (store[c] = store[c] || {})[id] = d; }, delete: async () => { delete store[c][id]; } }; },
    where: (f, op, v) => ({ count: () => ({ get: async () => ({ data: () => ({ count: Object.values(store[c] || {}).filter((x) => x[f] === v).length }) }) }), limit: () => ({ get: async () => ({ size: Object.values(store[c] || {}).filter((x) => x[f] === v).length, docs: Object.values(store[c] || {}).filter((x) => x[f] === v).map((x) => ({ data: () => x })) }) }) }),
    count: () => ({ get: async () => ({ data: () => ({ count: Object.keys(store[c] || {}).length }) }) }), orderBy: () => ({ limit: () => ({ get: async () => ({ docs: Object.entries(store[c] || {}).sort((a, b) => b[1].at - a[1].at).map(([id, d]) => ({ id, data: () => d })) }) }) }), limit: () => ({ get: async () => ({ docs: Object.entries(store[c] || {}).map(([id, d]) => ({ id, data: () => d })) }) }) });
  const db = { collection: col }; const U = { ...users };
  const adm = { apps: [1], auth: () => ({ listUsers: async () => ({ users: Object.values(U), pageToken: undefined }), getUser: async (uid) => { if (!U[uid]) throw new Error("yok"); return U[uid]; }, getUserByEmail: async (e) => { const u = Object.values(U).find((x) => x.email === e); if (!u) throw new Error("yok"); return u; }, updateUser: async (uid, p) => { Object.assign(U[uid], p); }, revokeRefreshTokens: async () => {} }) };
  const app = express(); app.use(express.json());
  const verifyUser = async (req) => { const h = req.headers["x-test-user"]; if (!h) throw Object.assign(new Error("Giriş yapmanız gerekiyor."), { status: 401 }); const u = JSON.parse(h); return { uid: u.uid, email: u.email || null, emailVerified: u.emailVerified === true }; };
  const SEC = LOAD("security"); const metrics = M.createMetrics(); const jobs = J.createJobs({ store: J.memoryStore(), scanItem: async () => ({ scanStatus: "COMPLETED", summary: {} }) }); jobs.stop();
  const adminApi = LOAD("admin")({ app, db, admin: adm, verifyUser, SEC, metrics, jobs, getHealth: async () => ({ ok: true }), platform: async () => ({ ai: LOAD("ai-provider").describe() }) });
  return { app, store, U, jobs };
}
const as = (uid, extra = {}) => ({ "x-test-user": JSON.stringify({ uid, email: uid + "@ornek.com", emailVerified: true, ...extra }), "Content-Type": "application/json" });
const ADMIN_GETS = ["/api/admin/me", "/api/admin/overview", "/api/admin/health", "/api/admin/errors", "/api/admin/users", "/api/admin/users/u1", "/api/admin/admins", "/api/admin/jobs", "/api/admin/jobs/job_x/items", "/api/admin/audit", "/api/admin/platform"];
test("Admin erişimi: oturumsuz 401, normal kullanıcı 403 (tüm uçlar); rol tarayıcıdan değiştirilemez", async () => {
  const { app } = adminApp({ env: { ADMIN_UIDS: "root" }, users: { u1: { uid: "u1", email: "u1@ornek.com", emailVerified: true, metadata: {} } } }); const s = await listen(app);
  for (const p of ADMIN_GETS) { assert.equal((await fetch(url(s, p))).status, 401, p); const r = await fetch(url(s, p), { headers: as("u1") }); assert.equal(r.status, 403, p); assert.equal((await r.json()).code, "ADMIN_REQUIRED"); }
  for (const [m, p] of [["POST", "/api/admin/admins"], ["DELETE", "/api/admin/admins/root"], ["POST", "/api/admin/users/u1/disable"], ["POST", "/api/admin/jobs/job_x/retry"], ["POST", "/api/admin/jobs/job_x/cancel"]]) assert.equal((await fetch(url(s, p), { method: m, headers: as("u1"), body: m === "POST" ? "{}" : undefined })).status, 403, m + p);
  // sahte alanlarla rol yükseltme denemeleri
  for (const h of [{ ...as("u1"), "x-admin": "true", "x-role": "admin", "x-test-role": "admin" }, { ...as("u1", { admin: true, role: "admin", isAdmin: true, claims: { admin: true } }) }]) assert.equal((await fetch(url(s, "/api/admin/overview?role=admin&admin=true"), { headers: h })).status, 403);
  assert.equal((await fetch(url(s, "/api/admin/overview"), { method: "POST", headers: as("u1"), body: JSON.stringify({ role: "admin", admin: true }) })).status, 404);
  const me = await (await fetch(url(s, "/api/me/admin"), { headers: as("u1") })).json(); assert.equal(me.admin, false);
  s.close();
});
test("Admin erişimi: ADMIN_UIDS, doğrulanmış ADMIN_EMAILS ve Firestore rolü yönetici yapar; doğrulanmamış e-posta yapmaz", async () => {
  const { app, store } = adminApp({ env: { ADMIN_UIDS: "root", ADMIN_EMAILS: "boss@ornek.com" }, roles: { granted: { role: "admin" } }, users: { u1: { uid: "u1", metadata: {} } } }); const s = await listen(app);
  const code = async (h, p = "/api/admin/me") => (await fetch(url(s, p), { headers: h })).status;
  assert.equal(await code(as("root")), 200); assert.equal(await code(as("granted")), 200);
  assert.equal(await code({ ...as("x"), "x-test-user": JSON.stringify({ uid: "x", email: "boss@ornek.com", emailVerified: true }) }), 200);
  assert.equal(await code({ ...as("y"), "x-test-user": JSON.stringify({ uid: "y", email: "boss@ornek.com", emailVerified: false }) }), 403, "doğrulanmamış e-posta ADMIN_EMAILS ile yönetici olamaz");
  assert.equal(await code({ ...as("z"), "x-test-user": JSON.stringify({ uid: "z", email: "BOSS@ornek.com.evil.com", emailVerified: true }) }), 403);
  assert.equal(await code(as("root"), "/api/admin/overview"), 200); const ov = await (await fetch(url(s, "/api/admin/overview"), { headers: as("root") })).json();
  assert.equal(ov.success, true); assert.equal(ov.users.available, true); assert.equal(ov.assets.value, 3); assert.equal(ov.api.volatile, true); assert.ok(!JSON.stringify(ov).match(/private_key|BEGIN/));
  s.close();
});
test("Admin: kullanıcı arama/devre dışı bırakma, yönetici yetkisi verme/alma, denetim kaydı ve kendini koruma", async () => {
  const mk = (uid, o = {}) => ({ uid, email: uid + "@ornek.com", displayName: uid, emailVerified: true, disabled: false, providerData: [{ providerId: "password" }], metadata: { creationTime: "2026-01-01", lastSignInTime: "2026-10-01" }, ...o });
  const { app, store, U } = adminApp({ env: { ADMIN_UIDS: "root" }, users: { root: mk("root"), u1: mk("u1"), u2: mk("u2", { disabled: true }), u3: mk("u3", { emailVerified: false }) } }); const s = await listen(app); const H = as("root");
  const list = await (await fetch(url(s, "/api/admin/users?status=disabled"), { headers: H })).json(); assert.deepEqual(list.users.map((u) => u.uid), ["u2"]);
  const q = await (await fetch(url(s, "/api/admin/users?q=u1"), { headers: H })).json(); assert.equal(q.users[0].assetCount, 2); assert.ok(!("phoneNumber" in q.users[0]) && !("passwordHash" in q.users[0]));
  const d = await (await fetch(url(s, "/api/admin/users/u1"), { headers: H })).json(); assert.deepEqual(d.assets.byType, { DOMAIN: 1, SEO: 1 }); assert.equal(d.user.isAdmin, false);
  assert.equal((await fetch(url(s, "/api/admin/users/root/disable"), { method: "POST", headers: H, body: JSON.stringify({ disabled: true }) })).status, 400, "kendini devre dışı bırakamaz");
  assert.equal((await fetch(url(s, "/api/admin/users/u1/disable"), { method: "POST", headers: H, body: JSON.stringify({ disabled: "yes" }) })).status, 400);
  assert.equal((await fetch(url(s, "/api/admin/users/u1/disable"), { method: "POST", headers: H, body: JSON.stringify({ disabled: true }) })).status, 200); assert.equal(U.u1.disabled, true);
  assert.equal((await fetch(url(s, "/api/admin/admins"), { method: "POST", headers: H, body: JSON.stringify({ email: "u3@ornek.com" }) })).status, 400, "doğrulanmamış e-posta yönetici yapılamaz");
  assert.equal((await fetch(url(s, "/api/admin/admins"), { method: "POST", headers: H, body: JSON.stringify({ email: "yok@ornek.com" }) })).status, 404);
  const g = await fetch(url(s, "/api/admin/admins"), { method: "POST", headers: H, body: JSON.stringify({ email: "u2@ornek.com" }) }); assert.equal(g.status, 400, "devre dışı hesap yönetici yapılamaz");
  U.u2.disabled = false; assert.equal((await fetch(url(s, "/api/admin/admins"), { method: "POST", headers: H, body: JSON.stringify({ email: "u2@ornek.com" }) })).status, 200); assert.equal(store.adminRoles.u2.role, "admin");
  assert.equal((await fetch(url(s, "/api/admin/me"), { headers: as("u2") })).status, 200);
  assert.equal((await fetch(url(s, "/api/admin/users/u2/disable"), { method: "POST", headers: H, body: JSON.stringify({ disabled: true }) })).status, 400, "yönetici hesabı önce yetkisi alınmadan kapatılamaz");
  assert.equal((await fetch(url(s, "/api/admin/admins/root"), { method: "DELETE", headers: H })).status, 400, "env yöneticisi panelden silinemez");
  assert.equal((await fetch(url(s, "/api/admin/admins/u2"), { method: "DELETE", headers: as("u2") })).status, 400, "kendi yetkisini kaldıramaz");
  assert.equal((await fetch(url(s, "/api/admin/admins/u2"), { method: "DELETE", headers: H })).status, 200); assert.equal((await fetch(url(s, "/api/admin/me"), { headers: as("u2") })).status, 403, "yetki alınınca anında 403");
  const audit = await (await fetch(url(s, "/api/admin/audit"), { headers: H })).json(); assert.deepEqual(audit.entries.map((e) => e.action).sort(), ["admin.grant", "admin.revoke", "user.disable"].sort()); assert.ok(audit.entries.every((e) => e.adminUid && e.at && e.ip !== undefined));
  s.close();
});
test("Admin: yönetici işlem hız sınırı uygulanır", async () => {
  const { app } = adminApp({ env: { ADMIN_UIDS: "root", ADMIN_WRITE_RATE_LIMIT: "3" }, users: { u1: { uid: "u1", metadata: {} } } }); const s = await listen(app); const codes = [];
  for (let i = 0; i < 6; i++) { const r = await fetch(url(s, "/api/admin/jobs/job_x/cancel"), { method: "POST", headers: as("root"), body: "{}" }); codes.push(r.status); await r.arrayBuffer(); }
  assert.ok(codes.includes(429), codes.join()); s.close(); delete process.env.ADMIN_WRITE_RATE_LIMIT;
});
test("Admin: tarama kuyruğu izleme ve güvenli yeniden deneme", async () => {
  const { app, jobs } = adminApp({ env: { ADMIN_UIDS: "root" }, users: { u1: { uid: "u1", metadata: {} } } }); const s = await listen(app);
  const j = await jobs.createJob({ ownerId: "u1", items: mkItems(3) }); const it = await jobs._store.listItemsByJob(j.id);
  await jobs._store.updateItem(it[0].id, { status: "FAILED" }); const jj = await jobs._store.getJob(j.id); jj.counts.PENDING = 2; jj.counts.FAILED = 1; await jobs._store.putJob(jj);
  const list = await (await fetch(url(s, "/api/admin/jobs"), { headers: as("root") })).json(); assert.equal(list.jobs[0].id, j.id); assert.equal(list.engine.persistent, false);
  const r = await (await fetch(url(s, `/api/admin/jobs/${j.id}/retry`), { method: "POST", headers: as("root"), body: "{}" })).json(); assert.equal(r.requeued, 1);
  s.close();
});

// ================= AI / PARA BİRİMİ / AFFILIATE =================
test("AI: devre dışı; anahtar istenmez; başarılı AI raporu üretilmez; rapor servisi AI'siz çalışır", async () => {
  const AI = LOAD("ai-provider"); process.env.AI_ENABLED = "true"; process.env.GEMINI_API_KEY = "x";
  const st = AI.status(); assert.equal(st.enabled, false); assert.match(st.reason, /kayıtlı değil/); assert.equal(st.geminiKeyRequested, false);
  const r = await AI.generateAiReport({}); assert.equal(r.ok, false); assert.equal(r.ai, null); delete process.env.AI_ENABLED; delete process.env.GEMINI_API_KEY;
  assert.equal(AI.status().enabled, false); assert.equal((await AI.generateAiReport({})).status, "DISABLED");
  const d = Date.UTC; const checks = [{ assetId: "a", type: "SEO", healthScore: 60, findings: ["f1", "f2"], checkedAt: d(2026, 9, 2) }, { assetId: "a", type: "SEO", healthScore: 80, findings: ["f2", "f3"], checkedAt: d(2026, 9, 20) }, { assetId: "a", type: "SEO", healthScore: 10, findings: [], checkedAt: d(2026, 10, 1) }, { assetId: "b", type: "SEO", healthScore: null, findings: [], checkedAt: d(2026, 9, 5) }];
  const m = AI.buildPeriodReport(checks, { periodType: "monthly", year: 2026, month: 10 }); const a = m.assets.find((x) => x.assetId === "a"); assert.equal(a.scoreStart, 60); assert.equal(a.scoreEnd, 80); assert.equal(a.scoreDelta, 20); assert.deepEqual(a.newFindings, ["f3"]); assert.deepEqual(a.resolvedFindings, ["f1"]);
  assert.equal(m.assets.find((x) => x.assetId === "b").scoreDelta, null); assert.equal(m.ai.status, "DISABLED"); assert.equal(m.ai.summary, null);
  assert.equal(AI.buildPeriodReport(checks, { periodType: "yearly", year: 2026 }).totals.scans, 4); assert.throws(() => AI.buildPeriodReport([], { periodType: "weekly", year: 2026 }));
  assert.equal(await AI.recordUsage(null, {}), false);
});
test("Para birimi / affiliate: fiyatlar kodla saklanır, kur uydurulmaz, yapılandırılmamış servis etkin görünmez", async () => {
  const B = LOAD("billing-catalog"), P = require(PUBFILE("plans.js"));
  assert.equal(P.price("kobi", "TRY", "monthly"), 4999.99); assert.equal(P.price("kobi", "USD", "yearly"), 1199.9); assert.equal(P.price("kobi", "EUR", "monthly"), null); assert.equal(P.PLANS.kobi.prices.TRY, 4999.99);
  const cs = Object.fromEntries(B.currencyStatus(P).map((c) => [c.code, c.enabled])); assert.deepEqual(cs, { TRY: true, USD: true, EUR: false });
  assert.equal((await B.convert(10, "TRY", "USD")).ok, false); assert.equal((await B.convert(10, "TRY", "TRY")).rate, 1); assert.equal((await B.convert(1, "TRY", "XXX")).ok, false);
  assert.equal(B.affiliateEnabled(), false); assert.equal(B.validateAffiliateOffer({ category: "ssl", relatedFindingId: "finding_ssl_expired_critical", provider: "X", affiliateUrl: "https://x.com/?a=1", disclosure: "Ortaklık bağlantısı", status: "DRAFT" }).ok, true);
  assert.equal(B.validateAffiliateOffer({ category: "ssl", relatedFindingId: "f", provider: "X", affiliateUrl: "http://x.com", disclosure: "kısa" }).ok, false);
});

// ================= GİZLİ ANAHTAR SIZINTISI / DAĞITIM =================
test("Gizli anahtarlar: tarayıcıya giden dosyalarda ve statik yayında sızıntı yok; sunucu dosyaları yayınlanmaz", async () => {
  const pubFiles = [...APP_FILES, "support-form.js", "login.js", "config.js", "plans.js", "company.js", "legal.js", "cookie-consent.js", "sw-register.js", "sw.js", "index.html", "style.css", "manifest.json"];
  for (const f of pubFiles) { const t = _fs.readFileSync(PUBFILE(f), "utf8"); assert.ok(!/private_key|BEGIN (RSA |EC )?PRIVATE|FIREBASE_SERVICE_ACCOUNT|sk_live_|whsec_|CRON_SECRET|IYZICO_SECRET|PAYTR_MERCHANT_KEY|PAYTR_MERCHANT_SALT|ADMIN_UIDS|"type":\s*"service_account"/.test(t), f + " içinde gizli bilgi"); }
  const s = await listen(APP); for (const p of ["/admin.js", "/jobs.js", "/scoring.js", "/metrics.js", "/validators.js", "/ai-provider.js", "/billing-catalog.js", "/server/admin.js", "/.env", "/.env.example", "/dac-features.test.js", "/package.json"]) { const r = await fetch(url(s, p)); assert.ok([301, 404].includes(r.status) && !(r.headers.get("content-type") || "").includes("javascript"), `${p} -> ${r.status}`); await r.arrayBuffer(); } s.close();
});
test("Dağıtım: Render başlangıcı, ortam örneği, .gitignore ve sağlık ucu", () => {
  const pkg = JSON.parse(_fs.readFileSync(_p.join(ROOT, "package.json"), "utf8")); assert.equal(pkg.scripts.start, "node index.js"); assert.ok(/>=\s*18/.test(pkg.engines.node)); assert.ok(pkg.dependencies.express && pkg.dependencies["firebase-admin"] && !pkg.dependencies.jsdom);
  const src = SRC("index.js"); assert.ok(/app\.listen\(PORT/.test(src) && /process\.env\.PORT \|\| 3000/.test(src) && /app\.get\("\/health"/.test(src));
  const env = _fs.readFileSync(_p.join(ROOT, ".env.example"), "utf8"); for (const k of ["FIREBASE_SERVICE_ACCOUNT", "ADMIN_UIDS", "ADMIN_EMAILS", "JOB_CONCURRENCY", "CRON_SECRET", "AI_ENABLED", "NODE_ENV"]) assert.ok(env.includes(k), k + " .env.example'da yok");
  assert.ok(!/"private_key"|sk_live_[A-Za-z0-9]{8}|whsec_[A-Za-z0-9]{8}/.test(env)); assert.ok(/^\.env$/m.test(_fs.readFileSync(_p.join(ROOT, ".gitignore"), "utf8")));
  assert.ok(_fs.readFileSync(_p.join(ROOT, "firestore.rules"), "utf8").includes("allow read, write: if false"), "Firestore istemci erişimi kapalı");
});

// ================= FRONTEND ↔ BACKEND BAĞLANTILARI (statik kaynak testleri) =================
test("Frontend-backend: arayüzün çağırdığı her /api yolu sunucuda tanımlı", () => {
  const front = APP_FILES.map(SRC).join("\n"), back = SRC("index.js") + SRC("admin.js") + SRC("payments.js") + SRC("user-state.js") + SRC("push.js") + SRC("commerce.js") + SRC("support.js") + SRC("admin-ops.js") + SRC("ops.js");
  const called = new Set([...front.matchAll(/['"`](\/api\/[A-Za-z0-9_\-\/]+)/g)].map((m) => m[1].replace(/\/$/, "")));
  const missing = [...called].filter((p) => !back.includes(p) && !back.includes(p.replace(/\/[^/]*$/, "/:")) && !back.includes(p.replace(/\/[^/]+$/, "")));
  assert.deepEqual(missing, []); for (const need of ["/api/jobs", "/api/admin/overview", "/api/admin/users", "/api/me/admin"]) assert.ok(called.has(need) || front.includes(need), need + " arayüzde kullanılmıyor");
});
test("Ortak yenileme: yeni tarama BAŞLATMAZ (yalnızca durum/özet çeker)", () => {
  const f = APP_FILES.map(SRC).join("\n"), i = f.indexOf("async function refreshAll"); assert.ok(i > 0, "refreshAll tanımlı olmalı");
  const body = f.slice(i, f.indexOf("\n}\n", i) + 3); assert.ok(!/runScan|rescan\(|\/api\/scan|POST|method:\s*['"]POST/.test(body), "refreshAll tarama başlatmamalı: " + body.slice(0, 300)); assert.ok(/pullLatest|\/api\/jobs/.test(body));
});
test("XSS: yeni arayüz kodunda dış kaynaklı değerler esc() ile kodlanır", () => {
  const f = APP_FILES.map(SRC).join("\n"); const i = f.indexOf("/* ---------- toplu tarama + admin"); assert.ok(i > 0, "yeni bölüm işaretçisi yok"); const part = f.slice(i);
  const raw = [...part.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]).filter((e) => /\b(name|targetUrl|email|displayName|uid|message|error|label|target|code)\b/.test(e) && !/esc\(|ic\(|\.length|\?|fmt|tone|badge|Number|toLocaleString|slice\(0,\s*\d\)\.toUpperCase/.test(e));
  assert.deepEqual(raw, [], "esc'siz enterpolasyon: " + raw.join(" | "));
});

// ================= YÖNETİCİ: PAKETLER / SİPARİŞLER / MÜDAHALE =================
test("Admin: paket/sipariş uçları yetkisiz 403; paket verme, listeleme, kaldırma ve doğrulamalar", async () => {
  const { app, store } = adminApp({ env: { ADMIN_UIDS: "root" }, users: { root: { uid: "root", email: "root@ornek.com", emailVerified: true, metadata: {} }, u1: { uid: "u1", email: "u1@ornek.com", emailVerified: true, metadata: {} }, u2: { uid: "u2", email: "u2@ornek.com", emailVerified: true, metadata: {} } } }); const s = await listen(app);
  for (const [m, p] of [["GET", "/api/admin/subscriptions"], ["GET", "/api/admin/orders"], ["POST", "/api/admin/users/u1/plan"], ["POST", "/api/admin/users/u1/plan/revoke"], ["POST", "/api/admin/users/u1/trial"]])
    assert.equal((await fetch(url(s, p), { method: m, headers: as("u1"), body: m === "POST" ? "{}" : undefined })).status, 403, m + p);
  const post = (p, b) => fetch(url(s, p), { method: "POST", headers: as("root"), body: JSON.stringify(b) });
  assert.equal((await post("/api/admin/users/u1/plan", { plan: "gizli", days: 30 })).status, 400, "bilinmeyen paket reddedilir");
  assert.equal((await post("/api/admin/users/u1/plan", { plan: "kobi", days: 99999 })).status, 400, "gün sınırı");
  assert.equal((await post("/api/admin/users/yok/plan", { plan: "kobi", days: 30 })).status, 404);
  const g = await post("/api/admin/users/u1/plan", { plan: "kobi", days: 30 }); assert.equal(g.status, 200);
  assert.equal(store.subscriptions.u1.plan, "kobi"); assert.equal(store.subscriptions.u1.provider, "admin"); assert.ok(store.subscriptions.u1.periodEnd > Date.now());
  const subs = await (await fetch(url(s, "/api/admin/subscriptions"), { headers: as("root") })).json();
  assert.equal(subs.summary.paidActive, 1); assert.equal(subs.summary.byPlan.kobi, 1); assert.equal(subs.summary.grantedFree, 1); assert.equal(subs.summary.freeUsers, 2, "3 kullanıcıdan 2'si ücretsiz");
  assert.equal(subs.rows[0].email, "u1@ornek.com");
  const list = await (await fetch(url(s, "/api/admin/users"), { headers: as("root") })).json(); const u1 = list.users.find((x) => x.uid === "u1"), r0 = list.users.find((x) => x.uid === "root");
  assert.equal(u1.plan.plan, "kobi"); assert.equal(r0.plan.plan, "free");
  assert.equal((await post("/api/admin/users/u1/plan/revoke", {})).status, 200); assert.equal(store.subscriptions.u1.status, "canceled");
  assert.equal((await post("/api/admin/users/root/plan/revoke", {})).status, 404, "aboneliği olmayanda 404");
  store.subscriptions.u2 = { plan: "freelance", status: "active", provider: "stripe", periodEnd: Date.now() + 864e5 };
  assert.equal((await post("/api/admin/users/u2/plan", { plan: "kobi", days: 30 })).status, 409, "ödeme sağlayıcılı aktif aboneliğin üzerine yazılmaz");
  assert.equal((await post("/api/admin/users/u2/plan/revoke", {})).status, 409);
  assert.equal((await post("/api/admin/users/u1/trial", { days: 5 })).status, 200); assert.ok(Math.abs(store.users.u1.trialStart + 3 * 864e5 - (Date.now() + 5 * 864e5)) < 5000, "deneme bitişi = şimdi + 5 gün");
  assert.equal((await post("/api/admin/users/u1/trial", { days: 999 })).status, 400);
  const aud = Object.values(store.adminAudit).map((x) => x.action); assert.ok(aud.includes("plan.grant") && aud.includes("plan.revoke") && aud.includes("trial.extend"), aud.join());
  s.close();
});

// ================= v13.5 ANALİZ MOTORU =================
test("WHOIS/tarih ayrıştırma: nic.tr, Verisign, bulunamadı; bitiş profili", () => {
  const d = (x) => x && x.toISOString().slice(0, 10);
  assert.equal(d(I.parseLooseDate("2027-Mar-04.")), "2027-03-04"); assert.equal(d(I.parseLooseDate("04-Mar-2027")), "2027-03-04"); assert.equal(I.parseLooseDate("2027-02-30"), null);
  const tr = I.parseWhois("** Registrar:\n   Organization Name : Ornek Bilisim\n\n** Domain Servers:\nns1.ornek.com.tr\nns2.ornek.com.tr\n\n** Additional Info:\nCreated on..............: 2005-Mar-04.\nExpires on..............: 2027-Mar-04.\n");
  assert.equal(d(tr.expiry), "2027-03-04"); assert.equal(tr.registrar, "Ornek Bilisim"); assert.deepEqual(tr.nameservers, ["ns1.ornek.com.tr", "ns2.ornek.com.tr"]);
  const vs = I.parseWhois("Registry Expiry Date: 2026-08-13T04:00:00Z\nRegistrar Registration Expiration Date: 2027-01-01T00:00:00Z\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited");
  assert.equal(d(vs.expiry), "2026-08-13"); assert.ok(vs.statuses.includes("clientTransferProhibited"));
  assert.ok(I.parseWhois('No match for "X.COM".').notFound);
  assert.deepEqual(I.expiryProfile(-1, ["redemptionPeriod"]), { state: "EXPIRED", phase: "REDEMPTION" }); assert.equal(I.expiryProfile(7, []).state, "CRITICAL"); assert.equal(I.expiryProfile(null, []).state, "UNKNOWN");
});
test("scanSummary: SSL sertifikası bitiş günü kuyruğa taşınır", () => {
  const r = I.scanSummary({ scanStatus: "COMPLETED", assetUpdate: { healthScore: 70, specificAnalysis: { cert: { validTo: "2027-01-01T00:00:00.000Z", daysRemaining: 40 } } } }, "SSL_CERTIFICATE");
  assert.equal(r.remainingDays, 40); assert.equal(r.expiresAt, "2027-01-01T00:00:00.000Z");
});
