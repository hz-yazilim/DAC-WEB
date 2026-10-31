// Tarama hakkı (HTTP): toplu işte en fazla N hedef ve "aynı anda kuyrukta en fazla N" sınırı. Firebase yok (bellek içi kuyruk).
process.env.NODE_ENV = "development"; process.env.DEV_AUTH_BYPASS = "true";
process.env.SCAN_MONTHLY_LIMIT = "50"; process.env.BULK_MAX_ITEMS = "3";
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

test("kalan hak ucu: kota bilgisi ve sınırlar döner", async () => {
  const s = await listen(); try { const r = await call(s, "GET", "/api/scan/quota"); const j = await r.json(); assert.equal(r.status, 200);
    assert.equal(j.limit, 50); assert.equal(j.remaining, 50); assert.equal(j.bulkCooldownSec, 2700); assert.equal(j.cooldownSec, 900); assert.equal(j.bulkMaxItems, 3); assert.ok(j.resetsAt > Date.now()); } finally { s.close(); }
});
test("toplu: tek istekte en fazla 3 hedef; kuyrukta 3 bekliyorken küçük işlerle sınır aşılamaz (hak düşmez)", async () => {
  const s = await listen(); const q = async () => (await (await call(s, "GET", "/api/scan/quota")).json());
  try {
    let r = await call(s, "POST", "/api/jobs", { items: items("bir.example.org", "iki.example.org", "uc.example.org", "dort.example.org") }); let j = await r.json();
    assert.equal(r.status, 400); assert.equal(j.code, "TOO_MANY_ITEMS"); assert.equal(j.limit, 3); assert.equal((await q()).used, 0);
    r = await call(s, "POST", "/api/jobs", { items: items("bir.example.org", "iki.example.org", "uc.example.org") }); j = await r.json(); assert.equal(r.status, 201, JSON.stringify(j)); assert.equal((await q()).used, 3);
    r = await call(s, "POST", "/api/jobs", { items: items("kuyruk.example.org") }); j = await r.json(); assert.equal(r.status, 429); assert.equal(j.code, "TOO_MANY_QUEUED"); assert.equal((await q()).used, 3);
  } finally { s.close(); }
});
