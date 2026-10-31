const test = require("node:test");
const assert = require("node:assert/strict");
const _p = require("path"), _fs = require("fs");
const { createScanQuota, targetKey, denyMessage } = require(_fs.existsSync(_p.join(__dirname, "quota.js")) ? "./quota" : "./server/quota");
const T0 = Date.UTC(2026, 9, 31, 9, 0, 0); // 31 Ekim 2026 12:00 TR
const mk = (o = {}) => { let t = T0; const q = createScanQuota({ monthlyLimit: 3, cooldownMs: 900e3, bulkCooldownMs: 2700e3, now: () => t, flushMs: 0, ...o }); return { q, adv: (ms) => { t += ms; }, set: (v) => { t = v; } }; };

test("aylık hak: kullanıldıkça düşer, bitince reddedilir; kalan sayı doğru; başka kullanıcı etkilenmez", async () => {
  const { q } = mk({ cooldownMs: 0 });
  assert.equal((await q.reserve("u1", [targetKey("WEBSITE", "a.com")])).remaining, 2);
  assert.equal((await q.reserve("u1", [targetKey("WEBSITE", "b.com")])).remaining, 1);
  assert.equal((await q.reserve("u1", [targetKey("WEBSITE", "c.com")])).remaining, 0);
  const r = await q.reserve("u1", [targetKey("WEBSITE", "d.com")]); assert.equal(r.ok, false); assert.equal(r.code, "SCAN_QUOTA"); assert.equal(r.remaining, 0);
  assert.match(denyMessage(r), /3\/3 kullanıldı.*01\.11\.2026/);
  assert.equal((await q.reserve("u2", [targetKey("WEBSITE", "a.com")])).ok, true);
});

test("ay değişince (Türkiye saatiyle) hak yenilenir; resetsAt ayın 1'i 00:00 TR", async () => {
  const { q, set } = mk({ monthlyLimit: 1, cooldownMs: 0 });
  const r1 = await q.reserve("u1", ["WEBSITE|a.com"]); assert.equal(r1.ok, true); assert.equal(r1.resetsAt, Date.UTC(2026, 9, 31, 21, 0, 0));
  assert.equal((await q.reserve("u1", ["WEBSITE|b.com"])).ok, false);
  set(Date.UTC(2026, 9, 31, 20, 59, 0)); assert.equal((await q.reserve("u1", ["WEBSITE|b.com"])).ok, false, "TR saatiyle hâlâ Ekim");
  set(Date.UTC(2026, 9, 31, 21, 0, 1)); assert.equal((await q.reserve("u1", ["WEBSITE|b.com"])).ok, true, "TR saatiyle 1 Kasım");
});

test("bekleme: aynı hedef 15 dk (tekil) dolmadan reddedilir ve hak harcamaz; www/büyük harf/nokta aynı hedeftir", async () => {
  const { q, adv } = mk();
  assert.equal((await q.reserve("u1", [targetKey("WEBSITE", "Ornek.com")])).ok, true);
  adv(60e3);
  for (const h of ["ornek.com", "www.ornek.com", "WWW.ORNEK.COM.", "Ornek.com."]) { const r = await q.reserve("u1", [targetKey("WEBSITE", h)]); assert.equal(r.ok, false, h); assert.equal(r.code, "SCAN_COOLDOWN"); assert.equal(r.retryAfterSec, 840); }
  assert.equal((await q.status("u1")).remaining, 2, "reddedilen denemeler hak yemez");
  assert.equal((await q.reserve("u1", [targetKey("SSL_CERTIFICATE", "ornek.com")])).ok, true, "farklı tür ayrı tarama");
  adv(841e3); assert.equal((await q.reserve("u1", [targetKey("WEBSITE", "ornek.com")])).ok, true);
});

test("toplu: bekleme 45 dk; bekleyenler atlanır, kalanlar geçer; son tarama zamanı tekil ve toplu yolda ORTAK", async () => {
  const { q, adv } = mk({ monthlyLimit: 10 });
  assert.equal((await q.reserve("u1", ["WEBSITE|a.com"])).ok, true); // tekil
  adv(20 * 60e3); // tekil için süre doldu (15 dk), toplu için dolmadı (45 dk)
  const r = await q.reserve("u1", ["WEBSITE|a.com", "WEBSITE|b.com", "WEBSITE|b.com"], { bulk: true });
  assert.equal(r.ok, true); assert.deepEqual(r.allowed, ["WEBSITE|b.com"], "yinelenen tek sayılır, a.com atlanır"); assert.equal(r.skipped[0].key, "WEBSITE|a.com"); assert.equal(r.skipped[0].retryAfterSec, 25 * 60);
  assert.equal((await q.status("u1")).used, 2);
  assert.equal((await q.reserve("u1", ["WEBSITE|b.com"])).ok, false, "toplu taranan hedef tekil yoldan da bekler");
  const all = await q.reserve("u1", ["WEBSITE|a.com", "WEBSITE|b.com"], { bulk: true }); assert.equal(all.ok, false); assert.equal(all.code, "SCAN_COOLDOWN");
});

test("toplu hak yetmezse HİÇBİRİ düşmez (ya hep ya hiç) ve kaç hak gerektiği bildirilir", async () => {
  const { q } = mk({ monthlyLimit: 5, cooldownMs: 0, bulkCooldownMs: 0 });
  await q.reserve("u1", ["WEBSITE|x.com"]); await q.reserve("u1", ["WEBSITE|y.com"]); await q.reserve("u1", ["WEBSITE|z.com"]);
  const r = await q.reserve("u1", ["A|1", "A|2", "A|3"], { bulk: true }); assert.equal(r.ok, false); assert.equal(r.code, "SCAN_QUOTA"); assert.equal(r.needed, 3); assert.equal(r.remaining, 2);
  assert.match(denyMessage(r, true), /3 tarama gerekiyor, 2 hakkınız var/); assert.equal((await q.status("u1")).used, 3);
});

test("paralel istekler sınırı aşamaz (karar + artış tek adım)", async () => {
  const { q } = mk({ monthlyLimit: 5, cooldownMs: 0 });
  const rs = await Promise.all(Array.from({ length: 40 }, (_, i) => q.reserve("u1", ["WEBSITE|h" + i + ".com"])));
  assert.equal(rs.filter((r) => r.ok).length, 5); assert.equal((await q.status("u1")).used, 5);
  const w = mk({ monthlyLimit: 50 }).q; const same = await Promise.all(Array.from({ length: 10 }, () => w.reserve("u2", ["WEBSITE|ayni.com"]))); assert.equal(same.filter((r) => r.ok).length, 1, "aynı hedefe paralel 10 istekten yalnızca 1'i geçer"); assert.equal((await w.status("u2")).used, 1);
});

test("iade ve zorunlu düşüm: refund hak+beklemeyi geri verir; charge ekler; alt sınır 0", async () => {
  const { q } = mk({ monthlyLimit: 4 });
  await q.reserve("u1", ["WEBSITE|a.com"]); await q.refund("u1", ["WEBSITE|a.com"]); assert.equal((await q.status("u1")).used, 0);
  assert.equal((await q.reserve("u1", ["WEBSITE|a.com"])).ok, true, "iade sonrası bekleme de kalkar");
  await q.charge("u1", 2); assert.equal((await q.status("u1")).used, 3); await q.refund("u1", ["x", "y", "z", "w", "v"]); assert.equal((await q.status("u1")).used, 0);
});

test("kalıcılık: sayaç Firestore'a yazılır, yeniden başlatmada okunur; okuma hatasında bellekten devam eder", async () => {
  const store = new Map(), db = { collection: () => ({ doc: (id) => ({ get: async () => ({ exists: store.has(id), data: () => store.get(id) }), set: async (v) => { store.set(id, v); } }) }) };
  let a = mk({ db, cooldownMs: 0 }); await a.q.reserve("u1", ["WEBSITE|a.com"]); await a.q.reserve("u1", ["WEBSITE|b.com"]);
  assert.equal(store.get("u1").used, 2); assert.equal(store.get("u1").month, "2026-10");
  const b = mk({ db, cooldownMs: 0 }); assert.equal((await b.q.status("u1")).used, 2, "yeniden başlatma sayaçı sıfırlamaz");
  store.set("u9", { month: "2026-09", used: 99 }); assert.equal((await b.q.status("u9")).used, 0, "geçen ayın sayacı yok sayılır");
  const bad = { collection: () => ({ doc: () => ({ get: async () => { throw new Error("8 RESOURCE_EXHAUSTED"); }, set: async () => { throw new Error("x"); } }) }) };
  const c = mk({ db: bad, cooldownMs: 0, log: { warn() {} } }); assert.equal((await c.q.reserve("u1", ["WEBSITE|a.com"])).ok, true, "Firestore kotası dolsa bile tarama durmaz");
});

test("kapalı: monthlyLimit=0 ve cooldown=0 sınırsız", async () => {
  const { q } = mk({ monthlyLimit: 0, cooldownMs: 0, bulkCooldownMs: 0 });
  for (let i = 0; i < 300; i++) assert.equal((await q.reserve("u", ["WEBSITE|x.com"])).ok, true);
  assert.equal((await q.status("u")).remaining, null);
});
