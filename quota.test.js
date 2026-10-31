const test = require("node:test");
const assert = require("node:assert/strict");
const _p = require("path"), _fs = require("fs");
const { createScanQuota, denyMessage } = require(_fs.existsSync(_p.join(__dirname, "quota.js")) ? "./quota" : "./server/quota");

test("hak: dolu kovadan kullanılır, bitince reddedilir, zamanla yenilenir; kullanıcılar birbirini etkilemez", () => {
  let t = 0; const q = createScanQuota({ capacity: 3, refillPerHour: 2, cooldownMs: 0, now: () => t });
  assert.equal(q.take("u1", "a").remaining, 2); assert.equal(q.take("u1", "b").remaining, 1); assert.equal(q.take("u1", "c").remaining, 0);
  const r = q.take("u1", "d"); assert.equal(r.ok, false); assert.equal(r.code, "SCAN_QUOTA"); assert.equal(r.retryAfterSec, 1800, "saatte 2 hak = 30 dk");
  assert.equal(q.take("u2", "a").ok, true, "başka kullanıcı etkilenmez");
  t += 1800e3; assert.equal(q.take("u1", "d").ok, true, "30 dk sonra 1 hak yenilendi"); assert.equal(q.take("u1", "e").ok, false);
  t += 100 * 3600e3; assert.equal(q.status("u1").remaining, 3, "kova kapasiteden fazla dolmaz");
});

test("bekleme: aynı hedef süre dolmadan reddedilir (hak harcanmaz); farklı hedef serbest", () => {
  let t = 0; const q = createScanQuota({ capacity: 10, refillPerHour: 1, cooldownMs: 300e3, now: () => t });
  assert.equal(q.take("u1", "WEBSITE|ornek.com").ok, true);
  t += 60e3; const r = q.take("u1", "WEBSITE|ornek.com"); assert.equal(r.ok, false); assert.equal(r.code, "SCAN_COOLDOWN"); assert.equal(r.retryAfterSec, 240);
  assert.equal(q.status("u1").remaining, 9, "reddedilen deneme hak yemez");
  assert.equal(q.take("u1", "WEBSITE|baska.com").ok, true);
  t += 241e3; assert.equal(q.take("u1", "WEBSITE|ornek.com").ok, true);
});

test("kapatma ve iade: capacity=0 / cooldownMs=0 sınırsız; refund hakkı ve beklemeyi geri verir", () => {
  const off = createScanQuota({ capacity: 0, cooldownMs: 0 }); for (let i = 0; i < 500; i++) assert.equal(off.take("u", "x").ok, true);
  let t = 0; const q = createScanQuota({ capacity: 1, refillPerHour: 1, cooldownMs: 300e3, now: () => t });
  assert.equal(q.take("u", "x").ok, true); q.refund("u", "x"); assert.equal(q.take("u", "x").ok, true);
});

test("mesajlar anlaşılır ve süreyi gösterir", () => {
  assert.match(denyMessage({ code: "SCAN_COOLDOWN", retryAfterSec: 240 }), /4 dakika/);
  assert.match(denyMessage({ code: "SCAN_QUOTA", retryAfterSec: 900, limit: 100 }), /hakkınız doldu.*15 dakika/);
});
