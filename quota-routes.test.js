// Tarama hakkı (HTTP): aylık hak, 45 dk toplu bekleme, ya-hep-ya-hiç, tekil tarama ve yeniden dene de aynı hakka bağlı. Firebase yok.
process.env.NODE_ENV = "development"; process.env.DEV_AUTH_BYPASS = "true";
process.env.SCAN_MONTHLY_LIMIT = "4"; process.env.BULK_MAX_ITEMS = "50"; process.env.SCAN_TARGET_COOLDOWN_SEC = "900"; process.env.BULK_TARGET_COOLDOWN_SEC = "2700";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const _p = require("path"), _fs = require("fs");
const ROOT = _fs.existsSync(_p.join(__dirname, "index.js")) ? __dirname : _p.join(__dirname, "..");
const app = require(_p.join(ROOT, "index"));
const listen = () => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const call = (s, m, p, body) => fetch(`http://127.0.0.1:${s.address().port}${p}`, { method: m, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
const items = (...hosts) => hosts.map((h, i) => ({ assetId: "a" + h.replace(/\W/g, "") + i, type: "DOMAIN", target: h }));
test.after(() => setTimeout(() => process.exit(0), 200).unref()); // arka plandaki tarama denemeleri süreci tutmasın

test("toplu: hak ve bekleme düşümü; bekleyenler atlanır; hak yetmezse hiçbiri düşmez; tekil tarama ve yeniden dene de hakka bağlı", async () => {
  const s = await listen(); const q = async () => (await (await call(s, "GET", "/api/scan/quota")).json());
  try {
    let r = await call(s, "POST", "/api/jobs", { items: items("bir.example.org", "iki.example.org", "uc.example.org") }); let j = await r.json();
    assert.equal(r.status, 201, JSON.stringify(j)); assert.equal(j.accepted, 3); assert.equal((await q()).remaining, 1);
    r = await call(s, "POST", "/api/jobs", { items: items("bir.example.org", "iki.example.org") }); j = await r.json();
    assert.equal(r.status, 429); assert.equal(j.code, "SCAN_COOLDOWN"); assert.ok(j.retryAfterSec > 2600 && j.retryAfterSec <= 2700, "toplu bekleme 45 dk"); assert.equal((await q()).remaining, 1);
    r = await call(s, "POST", "/api/jobs", { items: items("bir.example.org", "yeni1.example.org") }); j = await r.json(); // biri bekliyor, biri yeni
    assert.equal(r.status, 201, JSON.stringify(j)); assert.equal(j.accepted, 1); assert.equal(j.rejectedCount, 1); assert.equal(j.rejected[0].code, "SCAN_COOLDOWN"); assert.equal((await q()).remaining, 0);
    r = await call(s, "POST", "/api/jobs", { items: items("yeni2.example.org", "yeni3.example.org") }); j = await r.json();
    assert.equal(r.status, 429); assert.equal(j.code, "SCAN_QUOTA"); assert.equal(j.remaining, 0); assert.match(j.error, /yenilenir/);
    r = await call(s, "POST", "/api/scan", { assetId: "tekil1", type: "SERVER", targetUrl: "93.184.216.34", consent: true }); j = await r.json();
    assert.equal(r.status, 429); assert.equal(j.code, "SCAN_QUOTA", "tekil tarama da aynı aylık hakkı kullanır");
    r = await call(s, "POST", "/api/jobs/job_abcdef123/retry", {}); j = await r.json();
    assert.equal(r.status, 429); assert.equal(j.code, "SCAN_QUOTA", "hak bitmişken yeniden dene ile hak atlatılamaz");
  } finally { s.close(); }
});
