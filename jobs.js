/* Digital Asset Center - Kalıcı toplu tarama kuyruğu
 * - İşler tek bir uzun HTTP isteğine bağlı DEĞİLDİR: istek işi kaydeder ve hemen döner; işleyici arka planda çalışır.
 * - Durumlar kalıcıdır: Firestore varsa (scanJobs / scanJobItems) sunucu yeniden başlasa da korunur; çalışırken kesilen
 *   öğeler açılışta PENDING'e döner. Firestore YOKSA bellek deposu kullanılır ve `persistent:false` olarak açıkça bildirilir.
 * - Eşzamanlılık sınırı (genel + kullanıcı başına), zaman aşımı, kontrollü yeniden deneme (üstel bekleme), iptal, güvenli yeniden deneme.
 * - TEK SUNUCU ÖRNEĞİ varsayımı (Render tek instance). Çoklu örnek için dağıtık kilit/Redis gerekir (bkz. README).
 * Durumlar: PENDING, RETRYING (bekleme süresi), RUNNING, COMPLETED, PARTIAL, FAILED, CANCELED */
"use strict";
const crypto = require("crypto");

const ITEM_STATES = ["PENDING", "RETRYING", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELED"];
const FINAL = new Set(["COMPLETED", "PARTIAL", "FAILED", "CANCELED"]);
const newId = (p) => p + crypto.randomBytes(9).toString("base64url");
const emptyCounts = () => Object.fromEntries(ITEM_STATES.map((s) => [s, 0]));

function deriveStatus(job) {
  const c = job.counts, total = job.total, waiting = c.PENDING + c.RETRYING, done = total - waiting - c.RUNNING;
  if (waiting + c.RUNNING > 0) return c.RUNNING === 0 && done === 0 ? "PENDING" : "RUNNING";
  if (c.CANCELED === total) return "CANCELED";
  if (c.FAILED === total) return "FAILED";
  if (c.FAILED + c.PARTIAL + c.CANCELED > 0) return "PARTIAL";
  return "COMPLETED";
}

/* ---------- Depolar ---------- */
function memoryStore() {
  const jobs = new Map(), items = new Map();
  const clone = (x) => (x ? JSON.parse(JSON.stringify(x)) : x);
  return {
    persistent: false, kind: "memory",
    async putJob(j) { jobs.set(j.id, clone(j)); },
    async getJob(id) { return clone(jobs.get(id)) || null; },
    async listJobs({ ownerId, limit = 100 } = {}) { return [...jobs.values()].filter((j) => !ownerId || j.ownerId === ownerId).sort((a, b) => b.createdAt - a.createdAt).slice(0, limit).map(clone); },
    async putItems(arr) { for (const i of arr) items.set(i.id, clone(i)); },
    async getItem(id) { return clone(items.get(id)) || null; },
    async updateItem(id, patch) { const i = items.get(id); if (!i) return null; Object.assign(i, clone(patch)); return clone(i); },
    async listItemsByJob(jobId, limit = 5000) { return [...items.values()].filter((i) => i.jobId === jobId).slice(0, limit).map(clone); },
    async listItemsByStatus(status, limit = 100) { return [...items.values()].filter((i) => i.status === status).slice(0, limit).map(clone); },
    async countJobsByStatus() { const o = {}; for (const j of jobs.values()) o[j.status] = (o[j.status] || 0) + 1; return o; }
  };
}

function firestoreStore(db, { jobsCol = "scanJobs", itemsCol = "scanJobItems" } = {}) {
  const J = () => db.collection(jobsCol), I = () => db.collection(itemsCol);
  const strip = (o) => JSON.parse(JSON.stringify(o)); // undefined alanları at
  return {
    persistent: true, kind: "firestore",
    async putJob(j) { await J().doc(j.id).set(strip(j)); },
    async getJob(id) { const s = await J().doc(id).get(); return s.exists ? s.data() : null; },
    async listJobs({ ownerId, limit = 100 } = {}) {
      const q = ownerId ? J().where("ownerId", "==", ownerId) : J();
      const snap = await q.limit(500).get(); // tek alan eşitliği: bileşik indeks gerektirmez; sıralama bellekte
      return snap.docs.map((d) => d.data()).sort((a, b) => b.createdAt - a.createdAt).slice(0, limit);
    },
    async putItems(arr) { for (let i = 0; i < arr.length; i += 400) { const b = db.batch(); arr.slice(i, i + 400).forEach((x) => b.set(I().doc(x.id), strip(x))); await b.commit(); } },
    async getItem(id) { const s = await I().doc(id).get(); return s.exists ? s.data() : null; },
    async updateItem(id, patch) { const ref = I().doc(id); await ref.set(strip(patch), { merge: true }); const s = await ref.get(); return s.exists ? s.data() : null; },
    async listItemsByJob(jobId, limit = 5000) { return (await I().where("jobId", "==", jobId).limit(limit).get()).docs.map((d) => d.data()); },
    async listItemsByStatus(status, limit = 100) { return (await I().where("status", "==", status).limit(limit).get()).docs.map((d) => d.data()); },
    async countJobsByStatus() { const o = {}; for (const s of ["PENDING", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELED"]) { try { o[s] = (await J().where("status", "==", s).count().get()).data().count; } catch { o[s] = null; } } return o; }
  };
}

/* ---------- Kuyruk ---------- */
function createJobs({ store, scanItem, metrics = null, now = Date.now, config = {}, log = console }) {
  const cfg = {
    concurrency: config.concurrency ?? 3, perUser: config.perUser ?? 2, timeoutMs: config.timeoutMs ?? 75000, maxAttempts: config.maxAttempts ?? 3,
    backoffBaseMs: config.backoffBaseMs ?? 30000, backoffMaxMs: config.backoffMaxMs ?? 300000, tickMs: config.tickMs ?? 3000,
    maxItemsPerJob: config.maxItemsPerJob ?? 1000, maxActiveJobsPerUser: config.maxActiveJobsPerUser ?? 5, maxQueuedPerUser: config.maxQueuedPerUser ?? 3000,
    recoverImmediately: config.recoverImmediately ?? true
  };
  const running = new Map(); // itemId -> ownerId
  let timer = null, ticking = false, stopped = false;
  const locks = new Map();
  const withLock = async (key, fn) => { const prev = locks.get(key) || Promise.resolve(); let rel; const p = new Promise((r) => (rel = r)); locks.set(key, prev.then(() => p)); await prev; try { return await fn(); } finally { rel(); if (locks.get(key) === p) locks.delete(key); } };

  async function transition(item, patch, expect = null) {
    return withLock("job:" + item.jobId, async () => {
      const cur = await store.getItem(item.id); if (!cur) return null;
      if (expect && !expect.includes(cur.status)) return null; // başka bir işlem durumu zaten değiştirdi (ör. iptal)
      const from = cur.status, to = patch.status || from;
      const upd = await store.updateItem(item.id, patch);
      if (from !== to) {
        const job = await store.getJob(item.jobId);
        if (job) {
          job.counts[from] = Math.max(0, (job.counts[from] || 0) - 1); job.counts[to] = (job.counts[to] || 0) + 1;
          const prev = job.status; job.status = deriveStatus(job); job.updatedAt = now();
          if (!job.startedAt && to === "RUNNING") job.startedAt = now();
          if (FINAL.has(to) || to === "RETRYING") { /* sayaçlar güncel */ }
          if (!["PENDING", "RUNNING"].includes(job.status) && prev !== job.status) { job.finishedAt = now(); if (metrics) metrics.observe("jobCompletionMs", job.finishedAt - job.createdAt); } else if (["PENDING", "RUNNING"].includes(job.status)) job.finishedAt = null;
          await store.putJob(job);
        }
      }
      return upd;
    });
  }

  /* ----- iş oluşturma ----- */
  async function createJob({ ownerId, items, label = "Toplu tarama", source = "bulk" }) {
    if (!ownerId) throw Object.assign(new Error("Kullanıcı gerekli"), { status: 401 });
    if (!Array.isArray(items) || !items.length) throw Object.assign(new Error("En az bir hedef gerekli"), { status: 400 });
    if (items.length > cfg.maxItemsPerJob) throw Object.assign(new Error(`Bir işte en fazla ${cfg.maxItemsPerJob} hedef olabilir`), { status: 400, code: "TOO_MANY_ITEMS" });
    const mine = await store.listJobs({ ownerId, limit: 200 });
    const active = mine.filter((j) => ["PENDING", "RUNNING"].includes(j.status));
    if (active.length >= cfg.maxActiveJobsPerUser) throw Object.assign(new Error(`Aynı anda en fazla ${cfg.maxActiveJobsPerUser} aktif toplu iş çalışabilir`), { status: 429, code: "TOO_MANY_JOBS" });
    const queued = active.reduce((n, j) => n + (j.counts.PENDING + j.counts.RETRYING + j.counts.RUNNING), 0);
    if (queued + items.length > cfg.maxQueuedPerUser) throw Object.assign(new Error("Kuyrukta bekleyen çok fazla tarama var"), { status: 429, code: "QUEUE_FULL" });
    const t = now(), id = newId("job_");
    const rows = items.map((x) => ({ id: newId("itm_"), jobId: id, ownerId, assetId: x.assetId, type: x.type, targetUrl: x.targetUrl, name: x.name || x.targetUrl, extra: x.extra || {}, consent: x.consent === true, status: "PENDING", attempts: 0, queuedAt: t, nextAttemptAt: 0 }));
    const counts = emptyCounts(); counts.PENDING = rows.length;
    const job = { id, ownerId, label: String(label).slice(0, 80), source, total: rows.length, counts, status: "PENDING", cancelRequested: false, createdAt: t, updatedAt: t, startedAt: null, finishedAt: null, persistent: store.persistent };
    await store.putJob(job); await store.putItems(rows);
    kick();
    return job;
  }

  /* ----- işleme ----- */
  const backoff = (attempts) => Math.min(cfg.backoffMaxMs, cfg.backoffBaseMs * 2 ** Math.max(0, attempts - 1));
  async function runItem(item) {
    const t0 = now();
    if (metrics) metrics.observe("queueWaitMs", t0 - (item.queuedAt || t0));
    try {
      const job = await store.getJob(item.jobId);
      if (job && job.cancelRequested) { await transition(item, { status: "CANCELED", finishedAt: now() }); return; }
      const res = await Promise.race([Promise.resolve().then(() => scanItem(item)), new Promise((_, rej) => { const h = setTimeout(() => rej(Object.assign(new Error("Tarama zaman aşımı"), { code: "TIMEOUT", retriable: true })), cfg.timeoutMs); if (h.unref) h.unref(); })]);
      const st = res && res.scanStatus === "PARTIAL" ? "PARTIAL" : "COMPLETED";
      if (metrics) metrics.observe("jobItemMs", now() - t0);
      await transition(item, { status: st, finishedAt: now(), durationMs: now() - t0, error: null, result: res && res.summary ? res.summary : null });
    } catch (e) {
      const retriable = e && (e.retriable === true || e.code === "TIMEOUT" || e.code === "SCAN_FAILED") && !(e && e.retriable === false);
      const attempts = item.attempts; // claim sırasında artırıldı
      if (retriable && attempts < cfg.maxAttempts) await transition(item, { status: "RETRYING", nextAttemptAt: now() + backoff(attempts), error: { code: e.code || "ERROR", message: String(e.message || e).slice(0, 200) } });
      else await transition(item, { status: "FAILED", finishedAt: now(), durationMs: now() - t0, error: { code: e.code || "ERROR", message: String((e && e.message) || e).slice(0, 200) } });
    } finally { running.delete(item.id); if (!stopped) setImmediate(() => tick().catch(() => {})); }
  }

  async function tick() {
    if (ticking || stopped) return { skipped: true };
    ticking = true; let started = 0;
    try {
      // 1) bekleme süresi dolan yeniden denemeleri PENDING'e al
      for (const it of await store.listItemsByStatus("RETRYING", 50)) if ((it.nextAttemptAt || 0) <= now()) await transition(it, { status: "PENDING" }, ["RETRYING"]);
      // 2) boş yuva kadar öğe başlat
      const free = cfg.concurrency - running.size;
      if (free > 0) {
        const perUser = new Map(); for (const o of running.values()) perUser.set(o, (perUser.get(o) || 0) + 1);
        const pend = (await store.listItemsByStatus("PENDING", Math.max(free * 5, 25))).sort((a, b) => a.queuedAt - b.queuedAt);
        for (const it of pend) {
          if (running.size >= cfg.concurrency) break;
          if ((perUser.get(it.ownerId) || 0) >= cfg.perUser) continue;
          const claimed = await transition(it, { status: "RUNNING", startedAt: now(), attempts: (it.attempts || 0) + 1, workerBoot: BOOT }, ["PENDING"]);
          if (!claimed) continue;
          running.set(it.id, it.ownerId); perUser.set(it.ownerId, (perUser.get(it.ownerId) || 0) + 1); started++;
          runItem({ ...it, attempts: (it.attempts || 0) + 1 }).catch((e) => log.error && log.error("kuyruk öğesi hatası:", e.message));
        }
      }
    } catch (e) { log.error && log.error("kuyruk tick hatası:", e.message); }
    finally { ticking = false; }
    return { started, running: running.size };
  }
  const BOOT = newId("boot_");
  const kick = () => { if (!stopped) setImmediate(() => tick().catch(() => {})); };

  /* ----- açılışta kurtarma: yarım kalan RUNNING öğeler PENDING'e döner ----- */
  async function recover() {
    let n = 0;
    if (!cfg.recoverImmediately) return { recovered: 0 };
    for (const it of await store.listItemsByStatus("RUNNING", 1000)) {
      if (running.has(it.id)) continue;
      if (await transition(it, { status: "PENDING", recovered: true }, ["RUNNING"])) n++;
    }
    return { recovered: n };
  }

  /* ----- iptal / yeniden deneme / sorgu ----- */
  async function ownedJob(id, ownerId, admin = false) {
    const job = await store.getJob(id);
    if (!job || (!admin && job.ownerId !== ownerId)) throw Object.assign(new Error("İş bulunamadı"), { status: 404 });
    return job;
  }
  async function cancelJob(id, ownerId, admin = false) {
    const job = await ownedJob(id, ownerId, admin);
    await withLock("job:" + id, async () => { const j = await store.getJob(id); j.cancelRequested = true; j.updatedAt = now(); await store.putJob(j); });
    let n = 0;
    for (const st of ["PENDING", "RETRYING"]) for (const it of await store.listItemsByJob(id)) if (it.status === st && await transition(it, { status: "CANCELED", finishedAt: now() }, [st])) n++;
    return { canceled: n, job: await store.getJob(job.id) };
  }
  // Yalnızca FAILED (ve istenirse CANCELED) öğeler yeniden denenir; çalışan/tamamlanan öğelere dokunulmaz.
  async function retryItems(id, ownerId, { itemIds = null, includeCanceled = false, admin = false, limit = 500 } = {}) {
    await ownedJob(id, ownerId, admin);
    const ok = new Set(["FAILED", ...(includeCanceled ? ["CANCELED"] : [])]);
    const sel = itemIds ? new Set(itemIds) : null; let n = 0;
    await withLock("job:" + id, async () => { const j = await store.getJob(id); if (j.cancelRequested) { j.cancelRequested = false; await store.putJob(j); } });
    for (const it of await store.listItemsByJob(id)) {
      if (n >= limit) break; if (!ok.has(it.status) || (sel && !sel.has(it.id))) continue;
      if (await transition(it, { status: "PENDING", attempts: 0, nextAttemptAt: 0, error: null, finishedAt: null, retriedAt: now() }, [...ok])) n++;
    }
    kick(); return { requeued: n };
  }
  async function cancelItems(id, ownerId, itemIds, admin = false) {
    await ownedJob(id, ownerId, admin); const sel = new Set(itemIds || []); let n = 0;
    for (const it of await store.listItemsByJob(id)) if (sel.has(it.id) && ["PENDING", "RETRYING"].includes(it.status) && await transition(it, { status: "CANCELED", finishedAt: now() }, ["PENDING", "RETRYING"])) n++;
    return { canceled: n };
  }
  async function getJob(id, ownerId, admin = false) { return ownedJob(id, ownerId, admin); }
  async function listJobs(ownerId, limit = 50) { return store.listJobs({ ownerId, limit }); }
  async function listAllJobs(limit = 100) { return store.listJobs({ limit }); }

  // Sunucu tarafı arama/filtre/sıralama/sayfalama
  async function queryItems(id, ownerId, { status, q, sort = "queuedAt", order = "asc", page = 1, pageSize = 50 } = {}, admin = false) {
    await ownedJob(id, ownerId, admin);
    let rows = await store.listItemsByJob(id);
    if (status && status !== "ALL") rows = rows.filter((r) => (status === "PENDING" ? ["PENDING", "RETRYING"].includes(r.status) : r.status === status));
    if (q) { const s = String(q).toLowerCase(); rows = rows.filter((r) => (r.name + " " + r.targetUrl).toLowerCase().includes(s)); }
    const key = { queuedAt: (r) => r.queuedAt, name: (r) => String(r.name || "").toLowerCase(), status: (r) => r.status, score: (r) => r.result?.score ?? -1, remainingDays: (r) => r.result?.remainingDays ?? 1e9, duration: (r) => r.durationMs ?? -1 }[sort] || ((r) => r.queuedAt);
    rows.sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0)); if (order === "desc") rows.reverse();
    pageSize = Math.min(200, Math.max(1, +pageSize || 50)); page = Math.max(1, +page || 1);
    return { total: rows.length, page, pageSize, items: rows.slice((page - 1) * pageSize, page * pageSize).map(publicItem) };
  }
  const publicItem = (r) => ({ id: r.id, assetId: r.assetId, type: r.type, name: r.name, targetUrl: r.targetUrl, status: r.status, attempts: r.attempts, queuedAt: r.queuedAt, startedAt: r.startedAt || null, finishedAt: r.finishedAt || null, durationMs: r.durationMs ?? null, nextAttemptAt: r.nextAttemptAt || null, error: r.error || null, result: r.result || null });

  function start() {
    if (timer) return; stopped = false;
    recover().then((r) => { if (r.recovered && log.log) log.log(`Kuyruk: ${r.recovered} yarım kalan tarama yeniden sıraya alındı`); }).catch((e) => log.error && log.error("kuyruk kurtarma hatası:", e.message)).finally(() => tick().catch(() => {}));
    timer = setInterval(() => tick().catch(() => {}), cfg.tickMs); if (timer.unref) timer.unref();
  }
  async function stop() { stopped = true; if (timer) clearInterval(timer); timer = null; // zarif kapanış: çalışanları PENDING'e döndür
    for (const id of [...running.keys()]) { const it = await store.getItem(id).catch(() => null); if (it && it.status === "RUNNING") await transition(it, { status: "PENDING", recovered: true }).catch(() => {}); } }
  async function stats() {
    const byStatus = await store.countJobsByStatus();
    return { persistent: store.persistent, store: store.kind, running: running.size, concurrency: cfg.concurrency, perUserConcurrency: cfg.perUser, timeoutMs: cfg.timeoutMs, maxAttempts: cfg.maxAttempts, jobsByStatus: byStatus };
  }
  return { createJob, tick, start, stop, recover, cancelJob, cancelItems, retryItems, getJob, listJobs, listAllJobs, queryItems, stats, config: cfg, _store: store, _running: running };
}

// CSV: Excel'de formül çalıştırmayı (CSV injection) engellemek için tehlikeli başlangıçlı hücrelere ' eklenir
const csvCell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function itemsToCsv(rows) {
  const head = ["ad", "hedef", "tür", "durum", "skor", "tarama_durumu", "bitiş_tarihi", "kalan_gün", "deneme", "süre_ms", "hata_kodu", "hata"];
  const lines = [head.join(",")];
  for (const r of rows) lines.push([r.name, r.targetUrl, r.type, r.status, r.result?.score ?? "", r.result?.scanStatus ?? "", r.result?.expiresAt ?? "", r.result?.remainingDays ?? "", r.attempts, r.durationMs ?? "", r.error?.code ?? "", r.error?.message ?? ""].map(csvCell).join(","));
  return "\ufeff" + lines.join("\r\n");
}

module.exports = { createJobs, memoryStore, firestoreStore, deriveStatus, itemsToCsv, csvCell, ITEM_STATES };
