/**
 * Digital Asset Center - Scraper API v10.0 FULL FIXED CLEAN
 * - Duplicate tanımları (STATUS, TRANSFER_LOCK_STATUS, dohQuery, parseDomain, collectDnsRecords vs) tekilleştirildi
 * - DOMAIN scanner: tri-state VALID/INACTIVE/UNKNOWN, DNSSEC DS+AD, transferLock tri-state, Firebase uyumlu
 * - WEB / SSL / HOSTING / SAAS korundu
 * - Firebase yapısı: specificAnalysis, commonAnalysis, findings, status, score %100 uyumlu
 */

require("dns").setServers(['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4']);
const dns = require("dns").promises;
const express = require("express");
const axios = require("axios");
const sslChecker = require("ssl-checker");
const admin = require("firebase-admin");
const net = require("net");

// Firebase OPSİYONEL: site verileri tarayıcıda (localStorage) tutulur.
// FIREBASE_SERVICE_ACCOUNT tanımlı değilse sunucu sadece tarama yapar, Firestore'a yazmaz.
let db = null;
try {
  if (!admin.apps.length) {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
    } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT) {
      admin.initializeApp();
    }
  }
  if (admin.apps.length) {
    db = admin.firestore();
    db.settings({ ignoreUndefinedProperties: true });
  } else {
    console.warn("Firebase kimlik bilgisi yok: Firestore kaydı kapalı, sadece tarama yapılacak.");
  }
} catch (e) {
  console.error("Firebase başlatılamadı, Firestore kaydı kapalı:", e.message);
  db = null;
}

const app = express();
app.use(require("cors")());
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb", verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
const PORT = process.env.PORT || 3000;

const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
  "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
  "Accept": "text/html,application/xhtml+xml"
};

// ============ STATUS CONSTANTS - SADECE 1 KEZ ============
const STATUS = { VALID: "VALID", INACTIVE: "INACTIVE", UNKNOWN: "UNKNOWN", NOT_REQUIRED: "NOT_REQUIRED", MISSING: "MISSING", SELECTOR_NOT_DISCOVERED: "SELECTOR_NOT_DISCOVERED" };
const TRANSFER_LOCK_STATUS = { LOCKED: "LOCKED", UNLOCKED: "UNLOCKED", UNKNOWN: "UNKNOWN" };

// ============ COMMON HELPERS - TEKILLEŞTİRİLDİ ============
function normalizeTxtRecords(records) {
  if (!Array.isArray(records)) return [];
  return records.flat(Infinity).map(v => String(v || "")).map(v => v.trim()).map(v => v.replace(/^"+|"+$/g, "")).filter(Boolean);
}
function findSpfRecord(records) {
  const txt = normalizeTxtRecords(records);
  return txt.find(r => /^v=spf1(?:\s|$|;)/i.test(r)) || null;
}
function findDmarcRecord(records) {
  const txt = normalizeTxtRecords(records);
  return txt.find(r => /^v=dmarc1(?:\s|;|$)/i.test(r)) || null;
}
function extractDmarcPolicy(record) {
  if (!record) return null;
  const m = record.match(/(?:^|[;\s])p\s*=\s*([^;\s]+)/i);
  return m ? m[1].toLowerCase() : null;
}
function extractDmarcPct(record) {
  if (!record) return null;
  const m = record.match(/pct\s*=\s*(\d+)/i);
  return m ? parseInt(m[1], 10) : 100;
}
function isValidSpfSyntax(record) {
  if (!record) return false;
  return /^v=spf1\s+/i.test(record) && /(?:\+?include:|\+?ip4:|\+?ip6:|\+?a\b|\+?mx\b|~all|-all|\?all)/i.test(record);
}
function parseDomain(input) {
  if (!input) return null;
  try {
    const u = new URL(input.includes('://') ? input : `https://${input}`);
    return u.hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    let s = String(input).trim().toLowerCase();
    s = s.replace(/^https?:\/\//, '').replace(/^.*@/, '').split('/')[0].split(':')[0].split('?')[0];
    s = s.replace(/^\.+|\.+$/g, '').replace(/^www\./, '');
    if (!s.includes('.')) return null;
    return s;
  }
}
function toDateOrNull(s) { if (!s) return null; const d = new Date(s); return isNaN(d.getTime()) ? null : d; }
function daysUntil(dateStr) {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return null;
  return Math.floor((d.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}
function detectDnsProvider(nsRecords) {
  if (!nsRecords?.length) return null;
  const j = nsRecords.join(",").toLowerCase();
  if (j.includes("cloudflare")) return "Cloudflare";
  if (j.includes("google")) return "Google Cloud DNS";
  if (j.includes("awsdns") || j.includes("amazon")) return "AWS Route53";
  if (j.includes("azure")) return "Azure DNS";
  if (j.includes("godaddy")) return "GoDaddy";
  if (j.includes("natro")) return "Natro";
  if (j.includes("turhost")) return "Turhost";
  if (j.includes("hostinger")) return "Hostinger";
  if (j.includes("digitalocean")) return "DigitalOcean";
  return nsRecords[0] || "unknown";
}
function detectHostingFromHeaders(headers, ip) {
  const server = (headers['server'] || '').toLowerCase();
  const via = (headers['via'] || '').toLowerCase();
  if (server.includes('cloudflare') || via.includes('cloudflare')) return 'Cloudflare';
  if (server.includes('awselb') || server.includes('amazon')) return 'AWS';
  if (server.includes('gws') || server.includes('gse')) return 'Google Cloud';
  return null;
}
async function dohQuery(name, type) {
  try {
    const r = await axios.get(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" }, timeout: 6000
    });
    return r.data;
  } catch { return null; }
}
async function dohTxt(domain) {
  const data = await dohQuery(domain, "TXT");
  const ans = data?.Answer;
  if (!ans?.length) return null;
  return ans.map(a => {
    let txt = a.data || "";
    txt = txt.replace(/^"|"$/g, "").replace(/" "/g, "").replace(/\\"/g, '"');
    if (txt.startsWith('"') && txt.endsWith('"')) txt = txt.slice(1, -1);
    return [txt];
  });
}
async function safeResolve(fn, ...args) { try { return await fn(...args); } catch { return null; } }
async function safeResolveWithDoh(fn, domain) {
  try { const res = await fn(domain); if (res?.length) return res; } catch {}
  return await dohTxt(domain);
}
async function httpProbe(url, { method = "GET", timeout = 9000, headers = {}, maxRedirects = 5 } = {}) {
  const startedAt = Date.now();
  try {
    const res = await axios.request({
      url, method, timeout,
      headers: { ...BROWSER_HEADERS, ...headers },
      validateStatus: () => true,
      maxRedirects,
      beforeRedirect: (o) => { if (process.env.ALLOW_PRIVATE_TARGETS !== "true" && o && net.isIP(String(o.hostname || "")) && isPrivateIp(String(o.hostname))) throw new Error("Özel adrese yönlendirme engellendi"); }
    });
    return {
      ok: res.status < 400,
      status: res.status,
      responseTimeMs: Date.now() - startedAt,
      headers: res.headers || {},
      body: typeof res.data === "string" ? res.data : JSON.stringify(res.data).slice(0, 20000),
      finalUrl: res.request?.res?.responseUrl || url
    };
  } catch (e) {
    return { ok: false, status: 0, responseTimeMs: Date.now() - startedAt, error: e.message, headers: {}, body: "", finalUrl: url };
  }
}
function tcpPortCheck(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const startedAt = Date.now();
    let done = false;
    const finish = (open) => {
      if (done) return; done = true; socket.destroy();
      resolve({ port, open, latencyMs: Date.now() - startedAt });
    };
    socket.setTimeout(timeout);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, host);
  });
}
async function collectDnsRecords(domain) {
  const [a, aaaa, cname, mx, ns, txt, caa, soa] = await Promise.all([
    safeResolve(dns.resolve4, domain),
    safeResolve(dns.resolve6, domain),
    safeResolve(dns.resolveCname, domain),
    safeResolve(dns.resolveMx, domain),
    safeResolve(dns.resolveNs, domain),
    safeResolveWithDoh(dns.resolveTxt, domain),
    safeResolve(dns.resolveCaa, domain),
    safeResolve(dns.resolveSoa, domain)
  ]);
  let ds = null;
  try {
    const dsData = await dohQuery(domain, "DS");
    if (dsData?.Answer?.length) ds = dsData.Answer.map(a => a.data);
  } catch {}
  return { a: a || [], aaaa: aaaa || [], cname: cname || [], mx: mx || [], ns: ns || [], txt: txt || [], caa: caa || [], soa: soa || null, ds: ds || [] };
}
async function resolveTxtRobust(name) {
  try { const native = await dns.resolveTxt(name); if (native && native.length) return native; } catch {}
  try { const cf = await dohTxt(name); if (cf && cf.length) return cf; } catch {}
  try {
    const r = await axios.get(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=16`, { timeout: 6000, validateStatus: () => true });
    if (r.data && r.data.Answer) {
      const txts = r.data.Answer.map(a => {
        let d = a.data || "";
        d = d.replace(/^"|"$/g, '').replace(/" "/g, '').replace(/\\"/g, '"');
        if (d.startsWith('"') && d.endsWith('"')) d = d.slice(1, -1);
        return [d];
      });
      if (txts.length) return txts;
    }
  } catch {}
  return [];
}
async function fetchRdapRobust(domain, errors) {
  const endpoints = [
    `https://rdap.org/domain/${domain}`,
    `https://rdap.verisign.com/com/v1/domain/${domain}`,
    `https://rdap.iana.org/domain/${domain}`,
  ];
  if (domain.endsWith('.tr')) endpoints.unshift(`https://rdap.nic.tr/domain/${domain}`);
  for (const url of endpoints) {
    try {
      const res = await axios.get(url, { timeout: 8000, validateStatus: () => true, headers: { 'Accept': 'application/rdap+json, application/json', 'User-Agent': BROWSER_HEADERS['User-Agent'] } });
      if (res.status === 200 && res.data && !res.data.errorCode) return { data: res.data, source: url };
      else errors.push(`RDAP ${url} status:${res.status}`);
    } catch (e) { errors.push(`RDAP ${url} error:${e.message}`); }
  }
  return null;
}
function extractRegistrar(data) {
  if (!data) return null;
  if (data.registrar) {
    if (typeof data.registrar === "string") return data.registrar;
    if (typeof data.registrar === "object") {
      if (data.registrar.name) return String(data.registrar.name);
      if (data.registrar.organization) return String(data.registrar.organization);
    }
  }
  const entities = Array.isArray(data.entities) ? data.entities : [];
  const registrarEntity = entities.find(e => Array.isArray(e.roles) && e.roles.some(r => String(r).toLowerCase() === "registrar"));
  if (!registrarEntity) return null;
  try {
    const vcard = registrarEntity.vcardArray?.[1];
    if (Array.isArray(vcard)) {
      const fn = vcard.find(v => v?.[0] === "fn");
      if (fn?.[3]) { if (typeof fn[3] === "string") return fn[3]; if (fn[3].text) return fn[3].text; if (Array.isArray(fn[3])) return fn[3].join(" "); }
      const org = vcard.find(v => v?.[0] === "org");
      if (org?.[3]) { if (Array.isArray(org[3])) return org[3].join(" "); return String(org[3]); }
    }
  } catch {}
  return registrarEntity.name || registrarEntity.organization || registrarEntity.handle || null;
}
function extractDateByActions(data, actions) {
  if (!Array.isArray(data?.events)) return null;
  const lowerActions = actions.map(a => a.toLowerCase());
  const ev = data.events.find(e => lowerActions.includes(String(e.eventAction || "").toLowerCase()));
  return ev?.eventDate || null;
}
function getRdapStatuses(data) {
  if (!Array.isArray(data?.status)) return [];
  return data.status.map(s => typeof s === 'string' ? s : (s?.status || String(s))).filter(Boolean);
}
function checkTransferLock(statuses) {
  if (!statuses || statuses.length === 0) return null;
  const joined = statuses.join(" ").toLowerCase();
  if (joined.includes("clienttransferprohibited") || joined.includes("servertransferprohibited") || joined.includes("transfer prohibited")) return true;
  return false;
}
async function checkDnssec(domain, dsRecords) {
  try {
    if (dsRecords && dsRecords.length > 0) return { enabled: true, status: STATUS.VALID, method: "DS_FOUND" };
    const dohRes = await axios.get(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A&do=true&cd=false`, { headers: { accept: "application/dns-json" }, timeout: 5000 });
    if (dohRes.data?.AD === true) return { enabled: true, status: STATUS.VALID, method: "AD_FLAG" };
    const dnskeyData = await dohQuery(domain, "DNSKEY");
    if (dnskeyData?.Answer?.length) return { enabled: true, status: STATUS.VALID, method: "DNSKEY_FOUND" };
    return { enabled: false, status: STATUS.INACTIVE, method: "NO_DS_NO_AD" };
  } catch (e) {
    return { enabled: false, status: STATUS.UNKNOWN, method: "ERROR", error: e.message };
  }
}

const CRITICAL_HINTS = ["_down","_unreachable","_expired","_error","_exposed","_risk","_invalid","_failed","_publicly","_blacklisted","_not_resolving","_untrusted","_takeover"];
const WARNING_HINTS = ["_missing","_not_configured","_expiring_soon","_approaching","_stale","_pending","_incomplete","_unknown","_passive","_open","_none","_monitoring_only"];
function classifyFinding(f) {
  const lower = String(f).toLowerCase();
  if (CRITICAL_HINTS.some(h => lower.includes(h))) return "critical";
  if (WARNING_HINTS.some(h => lower.includes(h))) return "warning";
  return "ok";
}
function computeHealth(findings = []) {
  let c = 0, w = 0;
  for (const f of findings) {
    const cls = classifyFinding(f);
    if (cls === "critical") c++; else if (cls === "warning") w++;
  }
  let score = 100 - Math.min(c, 2) * 40 - Math.min(w, 4) * 15;
  score = Math.max(0, Math.min(100, score));
  const healthLevel = score >= 80 ? "YEŞİL" : score >= 50 ? "SARI" : "KIRMIZI";
  return { healthScore: score, healthLevel };
}
function computeConfidence(findings = [], hadError = false) {
  let conf = 100; if (hadError) conf -= 20;
  const unk = findings.filter(f => String(f).includes('_unknown')).length;
  conf -= Math.min(unk * 5, 20);
  return Math.max(0, conf);
}
function defaultStatusFromHealth(level) {
  if (level === "YEŞİL") return "ACTIVE";
  if (level === "SARI") return "WARNING";
  return "CRITICAL";
}

// ============ BOT KORUMASI ALGILAMA ============
// Cloudflare vb. koruma "doğrulama sayfası" döndürürse site çalışıyor ama taranamıyor demektir.
function detectBotProtection(probe) {
  const h = probe.headers || {};
  const body = String(probe.body || "").slice(0, 20000).toLowerCase();
  const server = String(h["server"] || "").toLowerCase();
  const blocked = [401, 403, 429, 503].includes(probe.status);
  const cfHeader = String(h["cf-mitigated"] || "").toLowerCase() === "challenge";
  const isCf = server.includes("cloudflare") || !!h["cf-ray"];
  if (cfHeader) return "Cloudflare";
  if (!blocked) return null;
  if (isCf && /just a moment|cf-chl|challenge-platform|attention required|checking your browser|cf-browser-verification|enable javascript and cookies/.test(body)) return "Cloudflare";
  if (h["x-sucuri-id"] || /sucuri website firewall/.test(body)) return "Sucuri";
  if (h["x-iinfo"] || /incapsula incident/.test(body)) return "Imperva Incapsula";
  if (server.includes("ddos-guard") || /ddos-guard/.test(body)) return "DDoS-Guard";
  if (server.includes("akamaighost") && /access denied/.test(body)) return "Akamai";
  return null;
}

// ============ 1. WEB SCANNER ============
async function scanWebsite(targetUrl, extra = {}) {
  const startedAt = Date.now();
  const findings = []; const errors = [];
  if (!targetUrl) { findings.push("finding_web_missing_target_critical"); return { data: null, findings, errors: ["targetUrl yok"] }; }
  const main = await httpProbe(targetUrl);
  const protection = detectBotProtection(main);
  if (protection) {
    // Gerçek içerik görülemedi: DOWN/SEO/güvenlik başlığı sonuçları güvenilmez, uydurma skor verme
    findings.push("finding_web_bot_protection_info");
    const specificAnalysis = {
      url: targetUrl, finalUrl: main.finalUrl, status: main.status, responseTimeMs: main.responseTimeMs,
      server: main.headers["server"] || null,
      techStack: [protection],
      botProtection: { detected: true, provider: protection, note: "Site bot koruması arkasında; tarayıcı doğrulama sayfası aldı. Site büyük olasılıkla çalışıyor, SEO ve güvenlik başlığı analizi yapılamadı." }
    };
    const commonAnalysis = { analyzerVersion: "web-analyzer-v3.1", executionTimeMs: Date.now() - startedAt, findings, scannedAt: new Date().toISOString(), score: null, status: "PROTECTED", target: targetUrl };
    return { data: { assetType: "WEB", commonAnalysis, specificAnalysis, analysisMeta: { scannerVersion: "web-analyzer-v3.1", analyzer: "web", limited: true } }, findings, errors, statusHint: "PROTECTED" };
  }
  if (!main.ok) findings.push("finding_web_down_critical");
  if (main.responseTimeMs > 3000) findings.push("finding_web_slow_warning");
  if (main.status >= 400) findings.push(`finding_web_status_${main.status}_critical`);
  const body = main.body || "";
  const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : null;
  const metaDescMatch = body.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i);
  const metaDescription = metaDescMatch ? metaDescMatch[1] : null;
  const h1Count = (body.match(/<h1/gi) || []).length;
  if (!title) findings.push("finding_web_missing_title_warning");
  if (!metaDescription) findings.push("finding_web_missing_meta_description_warning");
  if (h1Count === 0) findings.push("finding_web_missing_h1_warning");
  const h = main.headers;
  const securityHeaders = { hsts: !!h['strict-transport-security'], csp: !!h['content-security-policy'], xFrame: !!h['x-frame-options'], xContentType: !!h['x-content-type-options'], referrerPolicy: !!h['referrer-policy'] };
  if (!securityHeaders.hsts) findings.push("finding_web_missing_hsts_warning");
  if (!securityHeaders.csp) findings.push("finding_web_missing_csp_warning");
  if (!securityHeaders.xFrame) findings.push("finding_web_missing_xframe_warning");
  const techStack = []; const serverHeader = (h['server'] || '').toLowerCase();
  if (body.includes('wp-content')) techStack.push('WordPress');
  if (body.includes('__NEXT_DATA__')) techStack.push('Next.js');
  if (body.includes('shopify')) techStack.push('Shopify');
  if (serverHeader.includes('cloudflare')) techStack.push('Cloudflare');
  if (h['x-powered-by']) techStack.push(h['x-powered-by']);
  let robots = null, sitemap = null;
  try {
    const robotsUrl = new URL('/robots.txt', targetUrl).toString();
    const robotsRes = await httpProbe(robotsUrl, { timeout: 5000 });
    robots = { exists: robotsRes.ok, status: robotsRes.status };
    if (!robotsRes.ok) findings.push("finding_web_missing_robots_warning");
    const sitemapUrl = new URL('/sitemap.xml', targetUrl).toString();
    const sitemapRes = await httpProbe(sitemapUrl, { timeout: 5000 });
    sitemap = { exists: sitemapRes.ok, status: sitemapRes.status };
    if (!sitemapRes.ok) findings.push("finding_web_missing_sitemap_warning");
  } catch (e) { errors.push(e.message); }
  const securityScore = Object.values(securityHeaders).filter(Boolean).length * 20;
  const seoScore = (title ? 30 : 0) + (metaDescription ? 30 : 0) + (h1Count > 0 ? 20 : 0) + (robots?.exists ? 10 : 0) + (sitemap?.exists ? 10 : 0);
  const performanceScore = main.ok ? Math.max(0, 100 - Math.floor(main.responseTimeMs / 30)) : 0;
  const specificAnalysis = { url: targetUrl, finalUrl: main.finalUrl, status: main.status, responseTimeMs: main.responseTimeMs, title, metaDescription, h1Count, securityHeaders, techStack, robots, sitemap, server: h['server'] || null, scores: { security: securityScore, seo: seoScore, performance: performanceScore, overall: Math.round((securityScore + seoScore + performanceScore) / 3) } };
  const commonAnalysis = { analyzerVersion: "web-analyzer-v3", executionTimeMs: Date.now() - startedAt, findings, scannedAt: new Date().toISOString(), score: specificAnalysis.scores.overall, status: specificAnalysis.scores.overall >= 80 ? "HEALTHY" : specificAnalysis.scores.overall >= 50 ? "WARNING" : "CRITICAL", target: targetUrl };
  return { data: { assetType: "WEB", commonAnalysis, specificAnalysis, analysisMeta: { scannerVersion: "web-analyzer-v3", analyzer: "web" } }, findings, errors, statusHint: main.ok ? "ACTIVE" : "DOWN" };
}

// ============ 2. DOMAIN SCANNER v10.0 - FULL FIXED CLEAN - FINAL VERIFIED ============
// Bu versiyon Firebase buglarını çözüyor + kalan süre hesabı düzeltildi

// ---- BİTİŞ ve KALAN SÜRE için doğru helperlar - BUNLARI KULLAN ----
function toDateOrNull(s) {
  if (!s) return null;
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  return d; // Firestore Timestamp için Date
}
function daysUntil(dateInput) {
  if (!dateInput) return null;
  const target = dateInput instanceof Date ? dateInput : new Date(dateInput);
  if (isNaN(target.getTime())) return null;
  const now = new Date();
  // UTC gün bazlı - saat farkından 1 gün kayma olmuyor
  const targetUTC = Date.UTC(target.getUTCFullYear(), target.getUTCMonth(), target.getUTCDate());
  const nowUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.floor((targetUTC - nowUTC) / (1000*60*60*24));
}
function extractDateByActions(data, actions) {
  if (!Array.isArray(data?.events)) return null;
  const lowerActions = actions.map(a => a.toLowerCase());
  const ev = data.events.find(e => {
    const action = String(e.eventAction || "").toLowerCase();
    return lowerActions.some(a => action.includes(a) || a.includes(action));
  });
  return ev?.eventDate || null;
}

// ---- SCAN DOMAIN ----
async function scanDomain(input, extra = {}) {
  const startedAt = Date.now();
  const findings = []; const errors = [];
  const debug = { input, parsedDomain: null, txtRaw: null, dmarcRaw: null, dkimAttempts: [], rdapAttempts: [], registrarSource: null };

  const domain = parseDomain(input);
  debug.parsedDomain = domain;
  if (!domain) {
    findings.push("finding_domain_invalid_critical");
    return { data: null, findings, errors: ["domain parse edilemedi"], debug };
  }

  const dnsRecords = await collectDnsRecords(domain);
  debug.txtRaw = dnsRecords.txt;
  const dnsProvider = detectDnsProvider(dnsRecords.ns);
  const normalizedRootTxt = normalizeTxtRecords(dnsRecords.txt);
  const hasAddress = dnsRecords.a.length > 0 || dnsRecords.aaaa.length > 0 || dnsRecords.cname.length > 0;
  if (!hasAddress) findings.push("finding_domain_not_resolving_critical");
  if (!dnsRecords.ns.length) findings.push("finding_domain_missing_ns_critical");
  else if (dnsRecords.ns.length < 2) findings.push("finding_domain_single_ns_warning");
  const hasMx = dnsRecords.mx.length > 0;
  if (!hasMx) findings.push("finding_domain_missing_mx_warning");
  if (!dnsRecords.caa?.length) findings.push("finding_domain_missing_caa_warning");
  else findings.push("EMAIL_CAA_VALID");

  let spfRecord = findSpfRecord(normalizedRootTxt);
  if (!spfRecord) {
    const robustTxt = await resolveTxtRobust(domain);
    spfRecord = findSpfRecord(robustTxt);
    if (robustTxt.length) {
      const merged = [...new Set([...normalizeTxtRecords(debug.txtRaw), ...normalizeTxtRecords(robustTxt)])];
      debug.txtRaw = merged;
    }
  }
  let spfStatus;
  if (spfRecord) {
    if (isValidSpfSyntax(spfRecord)) { spfStatus = STATUS.VALID; findings.push("EMAIL_SPF_VALID"); }
    else { spfStatus = STATUS.INACTIVE; findings.push("finding_domain_invalid_spf_warning"); }
  } else if (hasMx) { spfStatus = STATUS.INACTIVE; findings.push("finding_domain_missing_spf_warning"); }
  else spfStatus = STATUS.NOT_REQUIRED;
  const spfStatusLegacy = spfStatus === STATUS.VALID ? "VALID" : spfStatus === STATUS.NOT_REQUIRED ? "NOT_REQUIRED" : "MISSING";

  const dmarcDomain = `_dmarc.${domain}`;
  const dmarcTxt = await resolveTxtRobust(dmarcDomain);
  const normalizedDmarcTxt = normalizeTxtRecords(dmarcTxt);
  debug.dmarcRaw = normalizedDmarcTxt;
  const dmarcRecord = findDmarcRecord(normalizedDmarcTxt);
  let dmarcStatus, dmarcPolicy = null, dmarcPct = null;
  if (dmarcRecord) {
    dmarcPolicy = extractDmarcPolicy(dmarcRecord);
    dmarcPct = extractDmarcPct(dmarcRecord) ?? 100;
    if (dmarcPolicy === 'none') findings.push("finding_domain_dmarc_policy_none_warning");
    dmarcStatus = STATUS.VALID;
    findings.push("EMAIL_DMARC_VALID");
  } else if (hasMx) { dmarcStatus = STATUS.INACTIVE; findings.push("finding_domain_missing_dmarc_warning"); }
  else dmarcStatus = STATUS.NOT_REQUIRED;
  const dmarcStatusLegacy = dmarcStatus === STATUS.VALID ? "VALID" : dmarcStatus === STATUS.NOT_REQUIRED ? "NOT_REQUIRED" : "MISSING";

  let dkimValid = false; let dkimSelectorFound = null; let dkimRecordRaw = null;
  const dkimSelectors = ["default","google","googlemail","k1","selector1","selector2","selector","s1","s2","mail","dkim","smtp","email","mandrill","sendgrid","protonmail","protonmail2","protonmail3","zoho","everlytickey1","eversrv","mxvault","k2"];
  for (const selector of dkimSelectors) {
    const dkimName = `${selector}._domainkey.${domain}`;
    try {
      const dkimTxt = await resolveTxtRobust(dkimName);
      const normalized = normalizeTxtRecords(dkimTxt);
      const found = normalized.length > 0;
      if (found) {
        const joined = normalized.join(" ").toLowerCase();
        const rawJoined = normalized.join(" ").slice(0, 300);
        debug.dkimAttempts.push({ selector, domain: dkimName, found: true, raw: rawJoined });
        if (joined.includes("v=dkim1") || joined.includes("k=rsa") || joined.includes("p=")) { dkimValid = true; dkimSelectorFound = selector; dkimRecordRaw = normalized[0]; findings.push("EMAIL_DKIM_VALID"); break; }
      } else {
        debug.dkimAttempts.push({ selector, domain: dkimName, found: false, raw: null });
      }
    } catch (e) { debug.dkimAttempts.push({ selector, domain: dkimName, found: false, error: e.message, raw: null }); }
  }
  let dkimStatus;
  if (dkimValid) dkimStatus = STATUS.VALID;
  else if (hasMx) dkimStatus = STATUS.SELECTOR_NOT_DISCOVERED;
  else dkimStatus = STATUS.NOT_REQUIRED;
  const dkimStatusLegacy = dkimValid ? "VALID" : hasMx ? "SELECTOR_NOT_DISCOVERED" : "NOT_REQUIRED";

  const dnssecResult = await checkDnssec(domain, dnsRecords.ds);
  const dnssecEnabled = dnssecResult.enabled;
  const dnssecStatus = dnssecResult.status;
  if (dnssecStatus === STATUS.VALID) findings.push("DNS_SEC_ACTIVE");
  else if (dnssecStatus === STATUS.INACTIVE) findings.push("finding_domain_missing_dnssec_warning");
  else findings.push("finding_domain_dnssec_unknown_warning");

  let registrar = null; let registrarStatus = STATUS.UNKNOWN;
  let createdAt = null, updatedAt = null, expiration = null, daysUntilExpiry = null;
  let transferLocked = null; let transferLockStatus = TRANSFER_LOCK_STATUS.UNKNOWN; let rdapStatuses = [];
  const rdapResult = await fetchRdapRobust(domain, errors);
  debug.rdapAttempts = errors.filter(e => e.startsWith("RDAP"));
  if (rdapResult?.data) {
    debug.registrarSource = rdapResult.source;
    registrar = extractRegistrar(rdapResult.data);
    registrarStatus = registrar ? "FOUND" : STATUS.UNKNOWN;
    if (!registrar) findings.push("finding_domain_registrar_unknown_warning");
    createdAt = toDateOrNull(extractDateByActions(rdapResult.data, ["registration","registered","creation","created"]));
    updatedAt = toDateOrNull(extractDateByActions(rdapResult.data, ["last changed","last changed date","last update","last updated","updated"]));
    expiration = toDateOrNull(extractDateByActions(rdapResult.data, ["expiration","expiry","expiration date","registrar expiration","expiration time","registry expiry"]));
    if (expiration) {
      daysUntilExpiry = daysUntil(expiration);
      if (daysUntilExpiry < 0) findings.push("finding_domain_expired_critical");
      else if (daysUntilExpiry < 14) findings.push("finding_domain_expiring_critical_warning");
      else if (daysUntilExpiry < 30) findings.push("finding_domain_expiring_soon_warning");
      else if (daysUntilExpiry < 60) findings.push("finding_domain_expiring_soon_info");
    } else findings.push("finding_domain_missing_expiry_warning");
    rdapStatuses = getRdapStatuses(rdapResult.data);
    const lockCheck = checkTransferLock(rdapStatuses);
    transferLocked = lockCheck;
    if (transferLocked === true) { transferLockStatus = TRANSFER_LOCK_STATUS.LOCKED; findings.push("DOMAIN_TRANSFER_LOCKED"); }
    else if (transferLocked === false) { transferLockStatus = TRANSFER_LOCK_STATUS.UNLOCKED; findings.push("finding_domain_transfer_unlocked_warning"); }
    else { transferLockStatus = TRANSFER_LOCK_STATUS.UNKNOWN; findings.push("finding_domain_transfer_lock_unknown_warning"); }
  } else {
    errors.push("RDAP tüm endpointler başarısız");
    registrarStatus = "LOOKUP_FAILED";
    findings.push("finding_domain_rdap_failed_warning");
  }

  let subdomainTakeoverRisk = false; let takeoverEvidence = null;
  if (dnsRecords.cname.length) {
    const risky = ["github.io","herokuapp.com","s3.amazonaws.com","shopify.com","azurewebsites.net","cloudapp.azure.com","pages.dev","netlify.app","vercel.app","myshopify.com","unbouncepages.com","cargocollective.com","ghost.io"];
    const cnameStr = dnsRecords.cname.join(" ").toLowerCase();
    const matched = risky.find(p => cnameStr.includes(p));
    if (matched && dnsRecords.a.length === 0 && dnsRecords.aaaa.length === 0) {
      subdomainTakeoverRisk = true; takeoverEvidence = matched; findings.push("finding_domain_takeover_risk_critical");
    }
  }

  const emailScore = !hasMx ? 100 : ((spfStatus === STATUS.VALID ? 35 : 0) + (dmarcStatus === STATUS.VALID ? (dmarcPolicy === 'reject' ? 35 : dmarcPolicy === 'quarantine' ? 25 : 15) : 0) + (dkimStatus === STATUS.VALID ? 30 : 0));
  const dnsScore = ((hasAddress ? 30 : 0) + (dnsRecords.ns.length >= 2 ? 30 : dnsRecords.ns.length === 1 ? 15 : 0) + (dnsRecords.caa?.length ? 15 : 0) + (dnsRecords.soa ? 10 : 0) + (dnssecStatus === STATUS.VALID ? 15 : 0));
  const securityScore = ((dnssecStatus === STATUS.VALID ? 35 : dnssecStatus === STATUS.UNKNOWN ? 10 : 0) + (transferLockStatus === TRANSFER_LOCK_STATUS.LOCKED ? 35 : transferLockStatus === TRANSFER_LOCK_STATUS.UNKNOWN ? 15 : 0) + (!subdomainTakeoverRisk ? 30 : 0));
  const renewalScore = daysUntilExpiry != null ? (daysUntilExpiry > 60 ? 100 : daysUntilExpiry > 30 ? 70 : daysUntilExpiry > 14 ? 40 : daysUntilExpiry > 0 ? 20 : 0) : 50;
  const overall = Math.round((dnsScore + emailScore + securityScore + renewalScore) / 4);

  const specificAnalysis = {
    domain,
    dns: {
      a: dnsRecords.a,
      aaaa: dnsRecords.aaaa,
      cname: dnsRecords.cname,
      caa: dnsRecords.caa || [],
      mx: dnsRecords.mx,
      ns: dnsRecords.ns,
      soa: dnsRecords.soa ? {
        nsname: dnsRecords.soa.nsname || null,
        hostmaster: dnsRecords.soa.hostmaster || dnsRecords.soa.admin || null,
        serial: dnsRecords.soa.serial || null,
        refresh: dnsRecords.soa.refresh || null,
        retry: dnsRecords.soa.retry || null,
        expire: dnsRecords.soa.expire || null,
        minttl: dnsRecords.soa.minttl || null,
        raw: `${dnsRecords.soa.nsname || ""} ${dnsRecords.soa.hostmaster || dnsRecords.soa.admin || ""} ${dnsRecords.soa.serial || ""}`.trim()
      } : null,
      txt: normalizeTxtRecords(debug.txtRaw || dnsRecords.txt),
      ds: dnsRecords.ds || []
    },
    dnsProvider,
    dnsSecurity: {
      dnssecEnabled: !!dnssecEnabled,
      dnssecStatus: dnssecStatus,
      dnssecMethod: dnssecResult.method || null,
      transferLocked: transferLocked,
      transferLockStatus: transferLockStatus
    },
    emailSecurity: {
      spf: spfRecord || null,
      spfStatus: spfStatusLegacy,
      spfStatusDetailed: spfStatus,
      spfValid: spfStatus === STATUS.VALID,
      dmarc: dmarcRecord || null,
      dmarcStatus: dmarcStatusLegacy,
      dmarcStatusDetailed: dmarcStatus,
      dmarcPolicy: dmarcPolicy,
      dmarcPct: dmarcPct,
      dmarcValid: dmarcStatus === STATUS.VALID,
      dkim: !!dkimValid,
      dkimRecord: dkimRecordRaw || null,
      dkimStatus: dkimStatusLegacy,
      dkimStatusDetailed: dkimStatus,
      dkimSelector: dkimSelectorFound,
      dkimValid: !!dkimValid,
      hasMx: !!hasMx,
      mxRecords: dnsRecords.mx || []
    },
    registration: {
      registrar: registrar,
      registrarStatus: registrarStatus,
      createdAt: createdAt,
      updatedAt: updatedAt,
      expiresAt: expiration,
      remainingDays: daysUntilExpiry,
      transferLocked: transferLocked,
      transferLockStatus: transferLockStatus,
      statuses: rdapStatuses,
      source: rdapResult?.source || null,
      target: domain
    },
    scores: { dns: dnsScore, email: emailScore, security: securityScore, renewal: renewalScore, overall: overall },
    threatAnalysis: { blacklistStatus: "NOT_CHECKED", subdomainTakeoverRisk: subdomainTakeoverRisk, takeoverEvidence: takeoverEvidence, typosquattingRisk: "NOT_CHECKED", target: domain },
    debug
  };

  const commonAnalysis = {
    analyzerVersion: "domain-analyzer-v10.0",
    executionTimeMs: Date.now() - startedAt,
    findings,
    scannedAt: new Date().toISOString(),
    score: overall,
    status: overall >= 80 ? "HEALTHY" : overall >= 50 ? "WARNING" : "CRITICAL",
    target: domain
  };

  return {
    data: {
      assetType: "DOMAIN",
      commonAnalysis,
      specificAnalysis,
      analysisMeta: { scannerVersion: "domain-analyzer-v10.0", analyzer: "domain" },
      target: domain,
      dnsProvider,
      registrar,
      remainingDays: daysUntilExpiry,
      transferLocked
    },
    findings, errors
  };
}

// ============ YARDIMCILAR ============
function parseDomain(input) {
  try {
    if (!input) return null;
    let d = input.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    return d.toLowerCase();
  } catch { return null; }
}
function daysUntil(dateStr) {
  return Math.ceil((new Date(dateStr) - new Date()) / (1000 * 60 * 60 * 24));
}

// Gerçek TLS'den detaylı bilgi alan fonksiyon
async function getTlsDetails(domain) {
  const tls = await import('tls');
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: 6000
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol(); // TLSv1.3
      const cipher = socket.getCipher();
      let chain = [];
      let current = cert;
      while (current && current.issuerCertificate && current.fingerprint!== current.issuerCertificate.fingerprint) {
        chain.push(current.issuerCertificate.subject?.CN || current.issuerCertificate.O || 'Intermediate');
        current = current.issuerCertificate;
        if(chain.length > 5) break;
      }
      socket.end();
      if (!cert ||!Object.keys(cert).length) return reject(new Error('Sertifika alınamadı'));
      resolve({ cert, protocol, cipher, chain });
    });
    socket.on('error', reject);
    socket.setTimeout(6000, () => { socket.destroy(); reject(new Error('TLS timeout')); });
  });
}

// ============ 3. SSL SCANNER V4 - GELİŞTİRİLMİŞ ============
async function scanSslCertificate(input, extra = {}) {
  const startedAt = Date.now();
  const findings = [];
  const errors = [];
  const domain = parseDomain(input);

  if (!domain) {
    return { data: null, findings: ["finding_ssl_invalid_target_critical"], errors: ["domain yok"], statusHint: "INVALID" };
  }

  let certInfo = null;
  let tlsInfo = null;
  let httpInfo = null;

  try {
    // 1. Detaylı TLS taraması
    const tlsData = await getTlsDetails(domain);
    const rawCert = tlsData.cert;

    const validFrom = new Date(rawCert.valid_from);
    const validTo = new Date(rawCert.valid_to);
    const daysRemaining = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));

    const sanList = rawCert.subjectaltname? rawCert.subjectaltname.replace(/DNS:/g, '').split(', ').map(s=>s.trim()) : [rawCert.subject?.CN].filter(Boolean);
    const issuerOrg = rawCert.issuer?.O || rawCert.issuer?.CN || 'Unknown';
    const isSelfSigned = rawCert.subject?.CN === rawCert.issuer?.CN && rawCert.subject?.O === rawCert.issuer?.O;
    const isWildcard = sanList.some(d => d.includes('*'));
    const keySize = rawCert.bits || 0; // 2048, 4096
    const sigAlg = rawCert.sigopt? 'SHA256' : (rawCert.issuerCertificate?.sigopt || rawCert.fingerprint256? 'SHA256' : 'SHA1'); // basitleştirildi, gerçekte rawCert.signatureAlgorithm okunur

    certInfo = {
      valid: daysRemaining > 0 &&!isSelfSigned,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      daysRemaining,
      issuer: `${rawCert.issuer?.O || ''} ${rawCert.issuer?.CN || ''}`.trim(),
      issuerOrg,
      issuerCN: rawCert.issuer?.CN || null,
      subject: rawCert.subject?.CN || domain,
      subjectO: rawCert.subject?.O || null,
      subjectAltNames: sanList,
      serialNumber: rawCert.serialNumber,
      fingerprint: rawCert.fingerprint256,
      keySize,
      signatureAlgorithm: rawCert.signatureAlgorithm || 'SHA256WithRSAEncryption',
      isWildcard,
      isSelfSigned,
      isEV: issuerOrg.includes('Extended Validation') || false, // EV kontrolü issuer'dan anlaşılır
    };

    tlsInfo = {
      protocol: tlsData.protocol, // TLSv1.3
      cipherName: tlsData.cipher.name,
      cipherVersion: tlsData.cipher.version,
      supportsTls13: tlsData.protocol === 'TLSv1.3',
      supportsTls12: tlsData.protocol === 'TLSv1.2' || tlsData.protocol === 'TLSv1.3',
      chainLength: tlsData.chain.length + 1,
      chainComplete: tlsData.chain.length > 0,
      trusted:!isSelfSigned
    };

    // FINDINGS LOGIC
    if (daysRemaining < 0) findings.push("finding_ssl_expired_critical");
    else if (daysRemaining < 7) findings.push("finding_ssl_expiring_soon_critical");
    else if (daysRemaining < 14) findings.push("finding_ssl_expiring_soon_critical");
    else if (daysRemaining < 30) findings.push("finding_ssl_expiring_soon_warning");

    if (isSelfSigned) findings.push("finding_ssl_self_signed_critical");
    if (keySize > 0 && keySize < 2048) findings.push("finding_ssl_weak_key_critical");
    if (certInfo.signatureAlgorithm.toLowerCase().includes('sha1')) findings.push("finding_ssl_weak_signature_critical");
    if (isWildcard) findings.push("finding_ssl_wildcard_warning");
    if (!tlsInfo.chainComplete) findings.push("finding_ssl_chain_incomplete_warning");
    if (!tlsInfo.supportsTls13) findings.push("finding_ssl_tls_old_version_warning");

  } catch (e) {
    errors.push(e.message);
    findings.push("finding_ssl_check_failed_critical");
    certInfo = { valid: false, error: e.message, daysRemaining: -1 };
  }

  // 2. HTTP Security Headers (HSTS)
  try {
    const probe = await httpProbe(`https://${domain}`, { timeout: 6000 });
    const hsts = probe.headers?.['strict-transport-security'] || probe.headers?.['Strict-Transport-Security'];
    httpInfo = {
      httpOk: probe.ok,
      status: probe.status,
      serverHeader: probe.headers?.server || null,
      hstsEnabled:!!hsts,
      hstsMaxAge: hsts? parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0') : 0,
      hstsIncludeSubdomains: hsts? hsts.includes('includeSubDomains') : false,
    };
    if (!httpInfo.hstsEnabled) findings.push("finding_ssl_hsts_missing_warning");
  } catch (e) { errors.push('httpProbe: ' + e.message); }

  // 3. SKORLAMA
  const scores = {
    validity: certInfo?.valid? 100 : 0,
    renewal: certInfo?.daysRemaining!= null? (certInfo.daysRemaining > 30? 100 : certInfo.daysRemaining > 14? 60 : certInfo.daysRemaining > 0? 20 : 0) : 0,
    security: 100,
    chainTrust: tlsInfo?.trusted? 100 : 0,
    hsts: httpInfo?.hstsEnabled? 100 : 40,
    overall: 0
  };
  // Güvenlik düşür
  if (certInfo?.keySize < 2048) scores.security -= 40;
  if (tlsInfo?.protocol === 'TLSv1.0' || tlsInfo?.protocol === 'TLSv1.1') scores.security = 0;

  scores.overall = Math.round((scores.validity * 0.4) + (scores.renewal * 0.3) + (scores.security * 0.2) + (scores.chainTrust * 0.1));

  const specificAnalysis = { domain, cert: certInfo, tls: tlsInfo, httpSecurity: httpInfo, scores };
  const commonAnalysis = {
    analyzerVersion: "ssl-analyzer-v4",
    executionTimeMs: Date.now() - startedAt,
    findings, // bunları UI'da Türkçeye çevir
    scannedAt: new Date().toISOString(),
    score: certInfo?.error ? null : scores.overall,
    status: certInfo?.error ? "ERROR" : scores.overall >= 80? "HEALTHY" : scores.overall >= 50? "WARNING" : "CRITICAL",
    target: domain
  };

  return {
    data: {
      assetType: "SSL_CERTIFICATE",
      commonAnalysis,
      specificAnalysis,
      analysisMeta: { scannerVersion: "ssl-analyzer-v4", analyzer: "ssl" }
    },
    findings, errors,
    statusHint: certInfo?.error ? "ERROR" : certInfo?.daysRemaining < 0 ? "EXPIRED" : !certInfo?.valid ? "CRITICAL" : certInfo.daysRemaining < 30 ? "EXPIRING_SOON" : "ACTIVE"
  };
}
// ============ 5. SAAS SCANNER ============
async function scanSaasSubscription(extra = {}) {
  const startedAt = Date.now(); const findings = [];
  const provider = (extra.provider || extra.name || "unknown").toLowerCase();
  const renewalDate = extra.renewalDate || extra.expiryDate || null;
  const remainingDays = renewalDate ? daysUntil(renewalDate) : (extra.remainingDays ?? null);
  const cost = extra.cost || 0; const plan = extra.plan || "unknown";
  let expiryStatus = "HEALTHY";
  if (remainingDays !== null) {
    if (remainingDays < 0) { expiryStatus = "EXPIRED"; findings.push("finding_saas_expired_critical"); }
    else if (remainingDays < 14) { expiryStatus = "CRITICAL"; findings.push("finding_saas_expiring_soon_critical"); }
    else if (remainingDays < 30) { expiryStatus = "WARNING"; findings.push("finding_saas_expiring_soon_warning"); }
  }
  if (!renewalDate) findings.push("finding_saas_missing_renewal_warning");
  if ((extra.usagePercent || 0) > 90) findings.push("finding_saas_usage_critical");
  const specificAnalysis = { provider, plan, renewalDate: renewalDate ? toDateOrNull(renewalDate) : null, remainingDays, cost, scores: { renewal: expiryStatus === "HEALTHY" ? 100 : expiryStatus === "WARNING" ? 60 : expiryStatus === "CRITICAL" ? 30 : 0, cost: cost <= 50 ? 90 : 70, usage: (extra.usagePercent || 50) < 80 ? 85 : 50, overall: 0 } };
  specificAnalysis.scores.overall = Math.round((specificAnalysis.scores.renewal + specificAnalysis.scores.cost + specificAnalysis.scores.usage) / 3);
  const commonAnalysis = { analyzerVersion: "saas-analyzer-v3", executionTimeMs: Date.now() - startedAt, findings, scannedAt: new Date().toISOString(), score: specificAnalysis.scores.overall, status: expiryStatus === "EXPIRED" ? "CRITICAL" : expiryStatus === "HEALTHY" ? "HEALTHY" : "WARNING", target: provider };
  return { data: { assetId: extra.assetId || `saas_${provider.replace(/\W/g, '_')}_${Date.now()}`, assetType: "SAAS_SUBSCRIPTION", commonAnalysis, specificAnalysis, provider, plan, renewalDate: specificAnalysis.renewalDate, remainingDays, cost }, findings, statusHint: expiryStatus === "EXPIRED" ? "EXPIRED" : "ACTIVE" };
}

function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error("Firestore zaman aşımı")), ms))]);
}

// ============ ROUTER ============
// =====================================================================
// ============ YENİ TARAYICILAR (v11) =================================
// =====================================================================
const tlsMod = require("tls");
const zlib = require("zlib");

// ---------- Güvenlik: yerel/özel adreslere tarama (SSRF) engeli ----------
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === "::1" || l === "::" || /^f[cd]/.test(l) || l.startsWith("fe80") || /^::ffff:(127|10|0)\./.test(l) || l.startsWith("::ffff:192.168.") || l.startsWith("::ffff:169.254.");
  }
  return false;
}
async function assertPublicHost(host) {
  if (process.env.ALLOW_PRIVATE_TARGETS === "true" || !host) return;
  const h = String(host).replace(/^\[|\]$/g, "").toLowerCase();
  const deny = new Error("Yerel veya özel ağ adreslerine tarama yapılamaz");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) throw deny;
  if (net.isIP(h)) { if (isPrivateIp(h)) throw deny; return; }
  let addrs = [];
  try { addrs = await dns.lookup(h, { all: true }); } catch { return; } // çözülemiyorsa tarayıcı kendi hatasını verir
  if (addrs.some(a => isPrivateIp(a.address))) throw deny;
}

// ---------- Ortak yardımcılar ----------
const ensureUrl = (t) => /^https?:\/\//i.test(String(t || "").trim()) ? String(t).trim() : "https://" + String(t || "").trim();
const hostOf = (t) => { try { return new URL(ensureUrl(t)).hostname.toLowerCase(); } catch { return null; } };
const statusFromScore = (s) => s >= 80 ? "HEALTHY" : s >= 50 ? "WARNING" : "CRITICAL";
const avg = (a) => a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null;
const daysSince = (d) => { const t = new Date(d).getTime(); return isNaN(t) ? null : Math.floor((Date.now() - t) / 864e5); };

function makeChecker() {
  const items = [];
  const calc = (list) => { const t = list.reduce((s, i) => s + i.w, 0); return t ? Math.round(list.filter(i => i.pass).reduce((s, i) => s + i.w, 0) / t * 100) : null; };
  return {
    add(pass, w, finding, group) { items.push({ pass: !!pass, w, finding, group: group || "genel" }); },
    findings: () => items.filter(i => !i.pass && i.finding).map(i => i.finding),
    score: (group) => calc(group ? items.filter(i => i.group === group) : items),
    groups: () => [...new Set(items.map(i => i.group))],
    summary: () => ({ passed: items.filter(i => i.pass).length, total: items.length })
  };
}
function buildResult({ assetType, version, startedAt, target, findings, specific, score, status, errors = [], hint }) {
  const st = status || statusFromScore(score);
  const commonAnalysis = { analyzerVersion: version, executionTimeMs: Date.now() - startedAt, findings, scannedAt: new Date().toISOString(), score, status: st, target };
  const scores = { ...(specific.scores || {}) }; if (score != null) scores.overall = score;
  return { data: { assetType, commonAnalysis, specificAnalysis: { ...specific, scores }, analysisMeta: { scannerVersion: version, analyzer: assetType.toLowerCase() } }, findings, errors, statusHint: hint || st };
}
// İçerik görülemedi (bot koruması / hız sınırı vb.): uydurma skor verme
function unavailableResult({ assetType, version, startedAt, target, finding, status, note, specific = {} }) {
  const findings = [finding];
  const commonAnalysis = { analyzerVersion: version, executionTimeMs: Date.now() - startedAt, findings, scannedAt: new Date().toISOString(), score: null, status, target };
  return { data: { assetType, commonAnalysis, specificAnalysis: { ...specific, note }, analysisMeta: { scannerVersion: version, analyzer: assetType.toLowerCase(), limited: true } }, findings, errors: [], statusHint: status };
}
const protectedResult = (assetType, version, startedAt, target, main, provider) => unavailableResult({
  assetType, version, startedAt, target, finding: "finding_web_bot_protection_info", status: "PROTECTED",
  note: "Site bot koruması arkasında; tarayıcı doğrulama sayfası aldı. Site büyük olasılıkla çalışıyor, bu analiz yapılamadı.",
  specific: { url: target, status: main.status, server: main.headers["server"] || null, botProtection: { detected: true, provider } }
});
const downResult = (assetType, version, startedAt, target, main, code) => buildResult({
  assetType, version, startedAt, target, findings: [code], score: 0, status: "DOWN",
  specific: { url: target, status: main.status, error: main.error || null }
});

function metaContent(html, key, attr = "name") {
  const m = html.match(new RegExp(`<meta[^>]+${attr}=["']${key}["'][^>]*>`, "i"));
  if (!m) return null;
  const c = m[0].match(/content=["']([^"']*)["']/i);
  return c ? c[1].trim() : null;
}
function linkHref(html, rel) {
  const m = html.match(new RegExp(`<link[^>]+rel=["'][^"']*${rel}[^"']*["'][^>]*>`, "i"));
  if (!m) return null;
  const h = m[0].match(/href=["']([^"']*)["']/i);
  return h ? h[1] : null;
}
async function followRedirects(url, max = 6) {
  const chain = []; let cur = url;
  for (let i = 0; i < max; i++) {
    const r = await httpProbe(cur, { timeout: 8000, maxRedirects: 0 });
    chain.push({ url: cur, status: r.status });
    const loc = r.headers && r.headers["location"];
    if (r.status >= 300 && r.status < 400 && loc) { try { cur = new URL(loc, cur).toString(); } catch { break; } } else return { chain, final: r, finalUrl: cur };
  }
  return { chain, final: null, finalUrl: cur };
}
function tlsAlpn(host, timeout = 5000) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const s = tlsMod.connect({ host, port: 443, servername: host, ALPNProtocols: ["h2", "http/1.1"], timeout }, () => {
      const r = { alpn: s.alpnProtocol || null, tlsVersion: s.getProtocol(), handshakeMs: Date.now() - t0 };
      s.end(); resolve(r);
    });
    s.on("error", () => resolve(null));
    s.on("timeout", () => { s.destroy(); resolve(null); });
  });
}
// Ham (sıkıştırılmış) boyutu ve ilk bayt süresini ölçen GET
async function timedGet(url, timeout = 12000) {
  const t0 = Date.now();
  try {
    const res = await axios.request({ url, method: "GET", responseType: "stream", decompress: false, timeout, headers: { ...BROWSER_HEADERS, "Accept-Encoding": "gzip, deflate, br" }, validateStatus: () => true, maxRedirects: 5 });
    const ttfb = Date.now() - t0;
    const enc = String(res.headers["content-encoding"] || "").toLowerCase();
    let transfer = 0, rawBytes = 0; const chunks = [];
    res.data.on("data", d => { transfer += d.length; });
    const z = enc === "gzip" ? zlib.createGunzip() : enc === "br" ? zlib.createBrotliDecompress() : enc === "deflate" ? zlib.createInflate() : null;
    const out = z ? res.data.pipe(z) : res.data;
    await new Promise((resolve) => {
      const done = () => resolve();
      out.on("data", d => { rawBytes += d.length; if (rawBytes <= 2e6) chunks.push(d); });
      out.on("end", done); out.on("error", done); out.on("close", done); res.data.on("error", done);
      setTimeout(done, timeout);
    });
    return { ok: res.status < 400, status: res.status, ttfb, total: Date.now() - t0, transferBytes: transfer, rawBytes, encoding: enc || null, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), finalUrl: res.request?.res?.responseUrl || url };
  } catch (e) {
    return { ok: false, status: 0, error: e.message, ttfb: null, total: Date.now() - t0, transferBytes: 0, rawBytes: 0, encoding: null, headers: {}, body: "", finalUrl: url };
  }
}

// ---------- IP / platform bilgisi ----------
async function ipInfo(ip) {
  try {
    const r = await axios.get(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 6000, validateStatus: () => true });
    if (r.data && r.data.success) return { ip, country: r.data.country || null, countryCode: r.data.country_code || null, city: r.data.city || null, region: r.data.region || null, asn: r.data.connection?.asn || null, org: r.data.connection?.org || null, isp: r.data.connection?.isp || null };
  } catch {}
  return { ip, country: null, city: null, asn: null, org: null, isp: null };
}
const DDOS_CAPABLE = ["Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Sucuri", "Imperva", "DDoS-Guard", "Azure Front Door", "Vercel"];
function detectPlatforms(h) {
  const s = (k) => String(h[k] || "").toLowerCase(); const out = [];
  if (h["cf-ray"] || s("server").includes("cloudflare")) out.push("Cloudflare");
  if (h["x-amz-cf-id"] || s("via").includes("cloudfront")) out.push("AWS CloudFront");
  if (s("server").includes("akamai") || h["x-akamai-transformed"]) out.push("Akamai");
  if (h["x-fastly-request-id"] || (h["x-served-by"] && /cache-/.test(s("x-served-by")))) out.push("Fastly");
  if (h["x-vercel-id"] || s("server") === "vercel") out.push("Vercel");
  if (h["x-nf-request-id"] || s("server").includes("netlify")) out.push("Netlify");
  if (h["x-github-request-id"]) out.push("GitHub Pages");
  if (h["x-sucuri-id"]) out.push("Sucuri");
  if (h["x-iinfo"]) out.push("Imperva");
  if (s("server").includes("ddos-guard")) out.push("DDoS-Guard");
  if (h["x-azure-ref"]) out.push("Azure Front Door");
  if (h["rndr-id"] || h["x-render-origin-server"]) out.push("Render");
  if (h["fly-request-id"]) out.push("Fly.io");
  return [...new Set(out)];
}
async function resolveIps(host) {
  if (net.isIPv4(host)) return { v4: [host], v6: [] };
  if (net.isIPv6(host)) return { v4: [], v6: [host] };
  const [v4, v6] = await Promise.all([safeResolve(dns.resolve4, host), safeResolve(dns.resolve6, host)]);
  return { v4: v4 || [], v6: v6 || [] };
}

// ============ HOSTING ============
async function scanHosting(input) {
  const startedAt = Date.now(); const V = "hosting-analyzer-v2";
  const host = parseDomain(input);
  if (!host) return buildResult({ assetType: "HOSTING", version: V, startedAt, target: String(input || ""), findings: ["finding_hosting_invalid_target_critical"], score: 0, status: "ERROR", specific: {} });
  const ips = await resolveIps(host);
  const c = makeChecker();
  const resolves = ips.v4.length + ips.v6.length > 0;
  c.add(resolves, 25, "finding_hosting_not_resolving_critical");
  let main = { ok: false, status: 0, headers: {}, responseTimeMs: null }, geo = null, rdns = null, tlsi = null;
  if (resolves) {
    const first = ips.v4[0] || ips.v6[0];
    [main, geo, tlsi] = await Promise.all([httpProbe(`https://${host}`, { timeout: 9000 }), ipInfo(first), tlsAlpn(host)]);
    rdns = await safeResolve(dns.reverse, first);
  }
  const platforms = detectPlatforms(main.headers || {});
  const ddos = platforms.some(p => DDOS_CAPABLE.includes(p));
  const reachable = main.status > 0 && main.status < 500;
  c.add(reachable, 25, "finding_hosting_unreachable_critical");
  c.add(!!tlsi, 15, "finding_hosting_no_https_critical");
  c.add(ddos, 15, "finding_hosting_no_cdn_waf_warning");
  c.add(ips.v6.length > 0, 5, "finding_hosting_no_ipv6_info");
  c.add(ips.v4.length + ips.v6.length > 1, 5, "finding_hosting_single_ip_info");
  c.add(main.responseTimeMs != null && main.responseTimeMs < 1500, 10, "finding_hosting_slow_response_warning");
  const score = c.score();
  const findings = c.findings();
  if (main.status === 403 && detectBotProtection(main)) findings.push("finding_web_bot_protection_info");
  return buildResult({
    assetType: "HOSTING", version: V, startedAt, target: host, findings, score, status: !resolves || !reachable ? "DOWN" : undefined,
    specific: {
      host,
      network: { ipv4: ips.v4, ipv6: ips.v6, reverseDns: (rdns && rdns[0]) || null },
      provider: geo ? { name: geo.org || geo.isp, asn: geo.asn, country: geo.country, city: geo.city } : null,
      platform: platforms, ddosProtection: ddos,
      http: { status: main.status, responseTimeMs: main.responseTimeMs, server: (main.headers || {})["server"] || null, protocol: tlsi?.alpn || null, tlsVersion: tlsi?.tlsVersion || null, tlsHandshakeMs: tlsi?.handshakeMs ?? null }
    }
  });
}

// ============ SUNUCU (port taraması) ============
const SERVER_PORTS = [[21, "FTP", "warn"], [22, "SSH", null], [23, "Telnet", "crit"], [25, "SMTP", null], [80, "HTTP", null], [443, "HTTPS", null], [445, "SMB", "crit"], [1433, "MSSQL", "crit"], [3306, "MySQL", "crit"], [3389, "RDP", "crit"], [5432, "PostgreSQL", "crit"], [5900, "VNC", "crit"], [6379, "Redis", "crit"], [8080, "HTTP-Alt", null], [8443, "HTTPS-Alt", null], [9200, "Elasticsearch", "crit"], [11211, "Memcached", "crit"], [27017, "MongoDB", "crit"]];
async function scanServer(input) {
  const startedAt = Date.now(); const V = "server-analyzer-v2";
  const host = parseDomain(input);
  if (!host) return buildResult({ assetType: "SERVER", version: V, startedAt, target: String(input || ""), findings: ["finding_server_invalid_target_critical"], score: 0, status: "ERROR", specific: {} });
  const ips = await resolveIps(host);
  const ip = ips.v4[0] || ips.v6[0];
  if (!ip) return buildResult({ assetType: "SERVER", version: V, startedAt, target: host, findings: ["finding_server_not_resolving_critical"], score: 0, status: "DOWN", specific: { host } });
  const res = await Promise.all(SERVER_PORTS.map(async ([port, name, risk]) => ({ ...(await tcpPortCheck(ip, port, 2500)), name, risk })));
  const open = res.filter(r => r.open);
  const findings = []; let score = 100;
  for (const r of open) {
    if (r.risk === "crit") { findings.push(`finding_server_exposed_port_${r.port}_critical`); score -= 25; }
    else if (r.risk === "warn") { findings.push(`finding_server_exposed_port_${r.port}_warning`); score -= 10; }
  }
  const alive = open.some(r => [22, 25, 80, 443, 8080, 8443].includes(r.port));
  if (!open.length) { findings.push("finding_server_unreachable_critical"); score = 0; }
  else if (!alive) { findings.push("finding_server_no_service_ports_warning"); score -= 10; }
  score = Math.max(0, score);
  const lat = open.map(r => r.latencyMs);
  const geo = await ipInfo(ip);
  return buildResult({
    assetType: "SERVER", version: V, startedAt, target: host, findings, score, status: !open.length ? "DOWN" : undefined,
    specific: {
      host, ip, provider: geo.org || geo.isp, country: geo.country, city: geo.city,
      checkedPorts: SERVER_PORTS.length, openCount: open.length, avgConnectMs: avg(lat),
      openPorts: open.map(r => `${r.port}/${r.name} (${r.latencyMs}ms)`),
      note: "Yalnızca yaygın 18 porta bağlantı denendi; hiçbir veri gönderilmedi."
    }
  });
}

// ============ SEO ============
async function scanSeo(targetUrl) {
  const startedAt = Date.now(); const V = "seo-analyzer-v1"; const url = ensureUrl(targetUrl);
  const main = await httpProbe(url);
  const prot = detectBotProtection(main);
  if (prot) return protectedResult("SEO", V, startedAt, url, main, prot);
  if (!main.ok) return downResult("SEO", V, startedAt, url, main, "finding_seo_unreachable_critical");
  const html = main.body || ""; const c = makeChecker(); const h = main.headers;
  const title = ((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "").replace(/\s+/g, " ").trim() || null;
  const desc = metaContent(html, "description");
  const robotsMeta = (metaContent(html, "robots") || "").toLowerCase();
  const xrobots = String(h["x-robots-tag"] || "").toLowerCase();
  const h1 = (html.match(/<h1[\s>]/gi) || []).length, h2 = (html.match(/<h2[\s>]/gi) || []).length;
  const imgs = html.match(/<img\b[^>]*>/gi) || []; const noAlt = imgs.filter(i => !/\balt=["'][^"']+["']/i.test(i)).length;
  const hreflang = (html.match(/<link[^>]+hreflang=/gi) || []).length; const xdefault = /hreflang=["']x-default["']/i.test(html);
  const jsonld = (html.match(/application\/ld\+json/gi) || []).length;
  const ogOk = !!(metaContent(html, "og:title", "property") && metaContent(html, "og:description", "property") && metaContent(html, "og:image", "property"));
  const text = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<[^>]+>/gi, " ").replace(/\s+/g, " ").trim();
  const words = text ? text.split(" ").length : 0;
  const links = (html.match(/<a\s[^>]*href=["'][^"']+["']/gi) || []);
  let internal = 0, external = 0; const baseHost = hostOf(main.finalUrl || url);
  for (const l of links) { const m = l.match(/href=["']([^"']+)["']/i)[1]; if (/^(mailto:|tel:|javascript:|#)/i.test(m)) continue; try { (new URL(m, main.finalUrl || url).hostname === baseHost) ? internal++ : external++; } catch {} }
  const origin = new URL(main.finalUrl || url).origin;
  const [robots, sitemap] = await Promise.all([httpProbe(origin + "/robots.txt", { timeout: 6000 }), httpProbe(origin + "/sitemap.xml", { timeout: 6000 })]);
  const robotsTxt = robots.ok ? robots.body : "";
  const blocksAll = /user-agent:\s*\*\s*[\r\n]+(?:(?:allow|crawl-delay|disallow:\s*\/[^\s]+)[^\r\n]*[\r\n]+)*disallow:\s*\/\s*(?:[\r\n]|$)/i.test(robotsTxt);
  const sitemapOk = (sitemap.ok && /<urlset|<sitemapindex/i.test(sitemap.body || "")) || /^\s*sitemap:/im.test(robotsTxt);
  c.add(!!title, 10, "finding_seo_missing_title_critical", "icerik");
  if (title) c.add(title.length >= 30 && title.length <= 65, 5, "finding_seo_title_length_warning", "icerik");
  c.add(!!desc, 10, "finding_seo_missing_description_warning", "icerik");
  if (desc) c.add(desc.length >= 70 && desc.length <= 165, 4, "finding_seo_description_length_warning", "icerik");
  c.add(h1 === 1, 8, h1 === 0 ? "finding_seo_missing_h1_warning" : "finding_seo_multiple_h1_warning", "icerik");
  c.add(!imgs.length || noAlt / imgs.length <= 0.1, 5, "finding_seo_images_missing_alt_warning", "icerik");
  c.add(words >= 300, 4, "finding_seo_thin_content_warning", "icerik");
  c.add(!/noindex/.test(robotsMeta) && !/noindex/.test(xrobots), 15, "finding_seo_noindex_critical", "teknik");
  c.add(!blocksAll, 15, "finding_seo_robots_blocks_all_critical", "teknik");
  c.add(!!linkHref(html, "canonical"), 5, "finding_seo_missing_canonical_warning", "teknik");
  c.add(robots.ok, 4, "finding_seo_missing_robots_warning", "teknik");
  c.add(sitemapOk, 6, "finding_seo_missing_sitemap_warning", "teknik");
  c.add(/^https:/i.test(main.finalUrl || url), 6, "finding_seo_not_https_warning", "teknik");
  c.add(!!metaContent(html, "viewport"), 6, "finding_seo_missing_viewport_warning", "teknik");
  c.add(/<html[^>]+lang=["'][^"']+["']/i.test(html), 4, "finding_seo_missing_lang_warning", "teknik");
  c.add(!!linkHref(html, "icon"), 2, "finding_seo_missing_favicon_warning", "teknik");
  if (hreflang > 0) c.add(xdefault, 3, "finding_seo_hreflang_no_default_warning", "sosyal");
  c.add(ogOk, 4, "finding_seo_missing_open_graph_warning", "sosyal");
  c.add(!!metaContent(html, "twitter:card"), 2, "finding_seo_missing_twitter_card_warning", "sosyal");
  c.add(jsonld > 0, 4, "finding_seo_missing_structured_data_warning", "sosyal");
  const scores = { icerik: c.score("icerik"), teknik: c.score("teknik"), sosyal: c.score("sosyal") };
  return buildResult({
    assetType: "SEO", version: V, startedAt, target: url, findings: c.findings(), score: c.score(),
    specific: { url, finalUrl: main.finalUrl, status: main.status, title, titleLength: title ? title.length : 0, metaDescriptionLength: desc ? desc.length : 0, canonical: linkHref(html, "canonical"), htmlLang: (html.match(/<html[^>]+lang=["']([^"']+)["']/i) || [])[1] || null, h1Count: h1, h2Count: h2, wordCount: words, images: { total: imgs.length, missingAlt: noAlt }, links: { internal, external }, hreflangCount: hreflang, structuredDataBlocks: jsonld, openGraph: ogOk, robotsTxt: robots.ok, sitemap: sitemapOk, checks: c.summary(), scores }
  });
}

// ============ GÜVENLİK ============
const EXPOSED = [
  ["env", "/.env", (b) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(b) && !/<html/i.test(b)],
  ["git", "/.git/HEAD", (b) => /^ref:\s*refs\//.test(b.trim())],
  ["gitconfig", "/.git/config", (b) => /\[core\]/.test(b) && !/<html/i.test(b)],
  ["phpinfo", "/phpinfo.php", (b) => /phpinfo\(\)|PHP Version/i.test(b)],
  ["dsstore", "/.DS_Store", (b) => b.startsWith("\u0000\u0000\u0000\u0001Bud1")],
  ["serverstatus", "/server-status", (b) => /Apache Server Status/i.test(b)],
  ["wpconfig", "/wp-config.php.bak", (b) => /DB_PASSWORD/.test(b)],
  ["sqldump", "/backup.sql", (b) => /CREATE TABLE|INSERT INTO/i.test(b) && !/<html/i.test(b)],
  ["htpasswd", "/.htpasswd", (b) => /^[^:\s<]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})/m.test(b) && !/<html/i.test(b)]
];
async function scanSecurity(targetUrl) {
  const startedAt = Date.now(); const V = "security-analyzer-v1"; const url = ensureUrl(targetUrl);
  const main = await httpProbe(url);
  const prot = detectBotProtection(main);
  if (prot) return protectedResult("SECURITY", V, startedAt, url, main, prot);
  if (!main.ok && main.status === 0) return downResult("SECURITY", V, startedAt, url, main, "finding_security_unreachable_critical");
  const h = main.headers; const c = makeChecker(); const host = hostOf(main.finalUrl || url); const https = /^https:/i.test(main.finalUrl || url);
  const hsts = String(h["strict-transport-security"] || ""); const maxAge = parseInt((hsts.match(/max-age=(\d+)/i) || [])[1] || "0", 10);
  const csp = String(h["content-security-policy"] || "");
  c.add(https, 12, "finding_security_not_https_critical", "aktarim");
  c.add(!!hsts && maxAge >= 15552000, 12, hsts ? "finding_security_hsts_short_warning" : "finding_security_missing_hsts_warning", "basliklar");
  c.add(!!csp, 12, "finding_security_missing_csp_warning", "basliklar");
  if (csp) c.add(!/unsafe-inline|unsafe-eval/.test(csp), 5, "finding_security_csp_unsafe_warning", "basliklar");
  c.add(!!h["x-frame-options"] || /frame-ancestors/.test(csp), 8, "finding_security_missing_clickjacking_warning", "basliklar");
  c.add(/nosniff/i.test(String(h["x-content-type-options"] || "")), 6, "finding_security_missing_nosniff_warning", "basliklar");
  c.add(!!h["referrer-policy"], 5, "finding_security_missing_referrer_policy_warning", "basliklar");
  c.add(!!h["permissions-policy"], 4, "finding_security_missing_permissions_policy_warning", "basliklar");
  const disclosure = /\d+\.\d+/.test(String(h["server"] || "")) || /\d+\.\d+/.test(String(h["x-powered-by"] || ""));
  c.add(!disclosure, 4, "finding_security_version_disclosure_warning", "basliklar");
  // http -> https yönlendirmesi
  let httpRedirect = null;
  if (host) {
    const r = await httpProbe(`http://${host}`, { timeout: 7000, maxRedirects: 0 });
    httpRedirect = r.status >= 300 && r.status < 400 && /^https:/i.test(String(r.headers["location"] || ""));
    c.add(r.status === 0 || httpRedirect, 8, "finding_security_no_https_redirect_warning", "aktarim");
  }
  // karışık içerik
  const mixed = https ? (main.body.match(/(?:src|href)=["']http:\/\/[^"']+/gi) || []).filter(x => /\.(js|css|png|jpe?g|gif|svg|webp|woff2?)|script|iframe/i.test(x)).length : 0;
  c.add(mixed === 0, 6, "finding_security_mixed_content_warning", "aktarim");
  // çerezler (değerler asla saklanmaz)
  const sc = [].concat(h["set-cookie"] || []);
  const cookies = sc.map(x => ({ name: String(x).split("=")[0], secure: /;\s*secure/i.test(x), httpOnly: /;\s*httponly/i.test(x), sameSite: (String(x).match(/samesite=(\w+)/i) || [])[1] || null }));
  c.add(!cookies.length || cookies.every(k => (!https || k.secure) && k.httpOnly && k.sameSite), 6, "finding_security_cookie_flags_warning", "aktarim");
  // sertifika süresi
  let cert = null;
  if (https && host) { try { const t = await getTlsDetails(host); const d = Math.floor((new Date(t.cert.valid_to) - Date.now()) / 864e5); cert = { daysRemaining: d, protocol: t.protocol }; c.add(d >= 14, 8, "finding_security_cert_expiring_critical", "aktarim"); c.add(d >= 30 || d < 14, 2, "finding_security_cert_expiring_warning", "aktarim"); c.add(["TLSv1.3", "TLSv1.2"].includes(t.protocol), 6, "finding_security_tls_old_warning", "aktarim"); } catch {} }
  // açıkta kalan hassas dosyalar
  const origin = new URL(main.finalUrl || url).origin;
  const probes = await Promise.all(EXPOSED.map(async ([slug, p, test]) => { const r = await httpProbe(origin + p, { timeout: 5000, maxRedirects: 2 }); return r.status === 200 && test(String(r.body || "").slice(0, 4000)) ? slug : null; }));
  const exposed = probes.filter(Boolean);
  c.add(!exposed.length, 25, null, "dosyalar");
  const findings = [...c.findings(), ...exposed.map(s => `finding_security_exposed_${s}_critical`)];
  const scores = {}; for (const g of c.groups()) scores[g] = c.score(g);
  const score = Math.min(c.score(), exposed.length ? 40 : 100);
  return buildResult({
    assetType: "SECURITY", version: V, startedAt, target: url, findings, score,
    specific: { url, finalUrl: main.finalUrl, https, hsts: hsts || null, hstsMaxAgeDays: Math.floor(maxAge / 86400), csp: !!csp, httpToHttpsRedirect: httpRedirect, mixedContentCount: mixed, serverHeader: h["server"] || null, poweredBy: h["x-powered-by"] || null, cookies, certificate: cert, exposedFiles: exposed, checkedFiles: EXPOSED.length, checks: c.summary(), scores }
  });
}

// ============ PERFORMANS ============
async function scanPerformance(targetUrl) {
  const startedAt = Date.now(); const V = "performance-analyzer-v1"; const url = ensureUrl(targetUrl);
  const page = await timedGet(url);
  const prot = detectBotProtection(page);
  if (prot) return protectedResult("PERFORMANCE", V, startedAt, url, page, prot);
  if (!page.ok) return downResult("PERFORMANCE", V, startedAt, url, page, "finding_perf_unreachable_critical");
  const c = makeChecker(); const html = page.body || ""; const host = hostOf(page.finalUrl || url);
  const [chainRes, tlsi] = await Promise.all([followRedirects(url), host ? tlsAlpn(host) : null]);
  const hops = Math.max(0, chainRes.chain.length - 1);
  const compressed = ["gzip", "br", "deflate", "zstd"].includes(page.encoding || "");
  const textType = /text|json|javascript|xml/i.test(String(page.headers["content-type"] || ""));
  // sayfa içindeki kaynaklar
  const scripts = [...html.matchAll(/<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi)];
  const blocking = scripts.filter(m => !/\b(async|defer|type=["']module["'])\b/i.test(m[0])).length;
  const css = [...html.matchAll(/<link\b[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["']/gi)].map(m => m[1]);
  const imgs = (html.match(/<img\b/gi) || []).length; const lazy = (html.match(/<img\b[^>]*loading=["']lazy["']/gi) || []).length;
  const abs = (u) => { try { return new URL(u, page.finalUrl || url).toString(); } catch { return null; } };
  const sample = [...new Set([...css.slice(0, 2), ...scripts.slice(0, 2).map(m => m[1])].map(abs).filter(Boolean))].slice(0, 3);
  const assets = await Promise.all(sample.map(u => timedGet(u, 8000)));
  const cacheOk = assets.length ? assets.filter(a => /max-age=(\d+)/.test(String(a.headers["cache-control"] || "")) && parseInt(String(a.headers["cache-control"]).match(/max-age=(\d+)/)[1], 10) >= 86400).length : null;
  const assetsCompressed = assets.length ? assets.filter(a => a.encoding).length : null;
  c.add(page.ttfb < 600, 18, "finding_perf_slow_ttfb_warning", "sunucu");
  c.add(page.ttfb < 1500, 12, "finding_perf_very_slow_ttfb_critical", "sunucu");
  c.add(page.total < 3000, 10, "finding_perf_slow_load_warning", "sunucu");
  c.add(!textType || compressed, 12, "finding_perf_no_compression_warning", "agi");
  c.add(tlsi?.alpn === "h2" || /h3/.test(String(page.headers["alt-svc"] || "")), 8, "finding_perf_no_http2_warning", "agi");
  c.add(hops <= 2, 6, "finding_perf_redirect_chain_warning", "agi");
  c.add(page.transferBytes < 500000, 8, "finding_perf_heavy_page_warning", "sayfa");
  c.add(blocking <= 3, 6, "finding_perf_render_blocking_scripts_warning", "sayfa");
  c.add(scripts.length <= 20, 4, "finding_perf_too_many_scripts_warning", "sayfa");
  c.add(imgs < 5 || lazy > 0, 4, "finding_perf_no_lazy_loading_warning", "sayfa");
  if (cacheOk !== null) c.add(cacheOk === assets.length, 8, "finding_perf_weak_caching_warning", "agi");
  if (assetsCompressed !== null) c.add(assetsCompressed === assets.length || assets.every(a => !/javascript|css/.test(String(a.headers["content-type"] || ""))), 4, "finding_perf_assets_not_compressed_warning", "agi");
  const scores = {}; for (const g of c.groups()) scores[g] = c.score(g);
  return buildResult({
    assetType: "PERFORMANCE", version: V, startedAt, target: url, findings: c.findings(), score: c.score(),
    specific: { url, finalUrl: page.finalUrl, status: page.status, ttfbMs: page.ttfb, totalLoadMs: page.total, htmlTransferKB: Math.round(page.transferBytes / 102.4) / 10, htmlRawKB: Math.round(page.rawBytes / 102.4) / 10, compression: page.encoding, protocol: tlsi?.alpn || null, tlsVersion: tlsi?.tlsVersion || null, tlsHandshakeMs: tlsi?.handshakeMs ?? null, http3Advertised: /h3/.test(String(page.headers["alt-svc"] || "")), redirectHops: hops, redirectChain: chainRes.chain.map(x => `${x.status} ${x.url}`), externalScripts: scripts.length, renderBlockingScripts: blocking, stylesheets: css.length, images: imgs, lazyImages: lazy, sampledAssets: assets.map((a, i) => `${a.status} ${a.encoding || "sıkıştırmasız"} ${Math.round(a.transferBytes / 1024)}KB cache:${a.headers["cache-control"] || "yok"}`), checks: c.summary(), scores }
  });
}

// ============ UPTIME & GECİKME ============
async function scanUptime(targetUrl, extra = {}) {
  const startedAt = Date.now(); const V = "uptime-analyzer-v1"; const url = ensureUrl(targetUrl);
  const N = 6, samples = [];
  for (let i = 0; i < N; i++) {
    const r = await httpProbe(url, { timeout: 8000, method: "GET" });
    samples.push({ status: r.status, ms: r.responseTimeMs, up: r.status > 0 && r.status < 500, protectedBy: r.status >= 400 ? detectBotProtection(r) : null });
    if (i < N - 1) await new Promise(r2 => setTimeout(r2, 350));
  }
  const host = hostOf(url);
  const t0 = Date.now(); let dnsMs = null; try { await dns.lookup(host); dnsMs = Date.now() - t0; } catch {}
  let uPort = /^https:/i.test(url) ? 443 : 80; try { const pu = new URL(url); if (pu.port) uPort = parseInt(pu.port, 10); } catch {}
  const tcp = host ? await tcpPortCheck(host, uPort, 4000) : null;
  const ups = samples.filter(s => s.up); const times = ups.map(s => s.ms).sort((a, b) => a - b);
  const rate = Math.round(ups.length / N * 100);
  const mean = avg(times); const jitter = times.length > 1 ? Math.round(Math.sqrt(times.reduce((s, t) => s + (t - mean) ** 2, 0) / times.length)) : 0;
  const p95 = times.length ? times[Math.min(times.length - 1, Math.ceil(times.length * 0.95) - 1)] : null;
  const c = makeChecker();
  c.add(rate === 100, 40, rate === 0 ? "finding_uptime_down_critical" : "finding_uptime_intermittent_critical", "erisim");
  c.add(rate >= 80, 10, null, "erisim");
  c.add(mean != null && mean < 800, 20, "finding_uptime_slow_response_warning", "gecikme");
  c.add(p95 != null && p95 < 2000, 10, "finding_uptime_high_p95_warning", "gecikme");
  c.add(jitter < 300, 10, "finding_uptime_unstable_latency_warning", "gecikme");
  c.add(dnsMs != null && dnsMs < 300, 5, "finding_uptime_slow_dns_warning", "gecikme");
  c.add(!!tcp && tcp.open && tcp.latencyMs < 500, 5, "finding_uptime_slow_connect_warning", "gecikme");
  const findings = c.findings();
  if (ups.length && samples.some(s => s.protectedBy)) findings.push("finding_web_bot_protection_info");
  const scores = { erisim: c.score("erisim"), gecikme: c.score("gecikme") };
  return buildResult({
    assetType: "UPTIME", version: V, startedAt, target: url, findings, score: c.score(), status: rate === 0 ? "DOWN" : undefined,
    specific: { url, samples: N, successRatePct: rate, statusCodes: samples.map(s => s.status), minMs: times[0] ?? null, avgMs: mean, p95Ms: p95, maxMs: times[times.length - 1] ?? null, jitterMs: jitter, dnsLookupMs: dnsMs, tcpConnectMs: tcp?.open ? tcp.latencyMs : null, note: "Tek noktadan (sunucu konumu) ölçüm; 4xx yanıtlar 'sunucu ayakta' sayılır.", checks: c.summary(), scores }
  });
}

// ============ API ============
async function scanApi(targetUrl) {
  const startedAt = Date.now(); const V = "api-analyzer-v1"; const url = ensureUrl(targetUrl);
  const main = await httpProbe(url, { headers: { Accept: "application/json" } });
  const prot = detectBotProtection(main);
  if (prot) return protectedResult("API", V, startedAt, url, main, prot);
  if (main.status === 0 || main.status >= 500) return downResult("API", V, startedAt, url, main, main.status === 0 ? "finding_api_unreachable_critical" : "finding_api_server_error_critical");
  const h = main.headers; const c = makeChecker(); const ct = String(h["content-type"] || "");
  const authRequired = main.status === 401 || main.status === 403;
  let jsonOk = null; if (/json/i.test(ct)) { try { JSON.parse(main.body); jsonOk = true; } catch { jsonOk = false; } }
  const origin = (() => { try { return new URL(url).origin; } catch { return url; } })();
  const pre = await httpProbe(url, { method: "OPTIONS", timeout: 6000, headers: { Origin: "https://example.com", "Access-Control-Request-Method": "GET" } });
  const acao = pre.headers["access-control-allow-origin"] || h["access-control-allow-origin"] || null;
  const creds = String(pre.headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
  const bad404 = await httpProbe(origin + "/__dac_not_found__" + Date.now(), { timeout: 6000, headers: { Accept: "application/json" } });
  const rl = Object.keys(h).filter(k => /ratelimit|retry-after/i.test(k));
  c.add(main.status < 400 || authRequired, 25, "finding_api_error_status_critical", "erisim");
  c.add(main.responseTimeMs < 1000, 15, "finding_api_slow_response_warning", "erisim");
  c.add(/^https:/i.test(url), 10, "finding_api_not_https_critical", "guvenlik");
  c.add(!(acao === "*" && creds) && !(acao && acao !== "*" && acao === "https://example.com" && creds), 10, "finding_api_cors_credentials_critical", "guvenlik");
  c.add(/nosniff/i.test(String(h["x-content-type-options"] || "")), 5, "finding_api_missing_nosniff_warning", "guvenlik");
  c.add(!!h["strict-transport-security"], 5, "finding_api_missing_hsts_warning", "guvenlik");
  c.add(!/\d+\.\d+/.test(String(h["server"] || "") + String(h["x-powered-by"] || "")), 4, "finding_api_version_disclosure_warning", "guvenlik");
  if (jsonOk !== null) c.add(jsonOk, 10, "finding_api_invalid_json_critical", "tasarim");
  else if (!authRequired) c.add(false, 6, "finding_api_not_json_warning", "tasarim");
  c.add(rl.length > 0, 8, "finding_api_no_rate_limit_headers_warning", "tasarim");
  c.add(/json/i.test(String(bad404.headers["content-type"] || "")), 4, "finding_api_error_not_json_warning", "tasarim");
  c.add(/\/v\d+(\/|$)/i.test(url) || !!h["api-version"] || !!h["x-api-version"], 4, "finding_api_no_versioning_warning", "tasarim");
  const findings = c.findings(); if (authRequired) findings.push("finding_api_auth_required_info");
  const scores = {}; for (const g of c.groups()) scores[g] = c.score(g);
  return buildResult({
    assetType: "API", version: V, startedAt, target: url, findings, score: c.score(),
    specific: { url, status: main.status, responseTimeMs: main.responseTimeMs, contentType: ct || null, validJson: jsonOk, authRequired, cors: { allowOrigin: acao, allowCredentials: creds }, rateLimitHeaders: rl, unknownRouteStatus: bad404.status, server: h["server"] || null, checks: c.summary(), scores }
  });
}

// ============ MOBİL UYGULAMA (Google Play / App Store) ============
async function scanMobileApp(input) {
  const startedAt = Date.now(); const V = "mobile-analyzer-v1"; const raw = String(input || "").trim();
  let store = null, id = null, country = "tr";
  const play = raw.match(/[?&]id=([A-Za-z0-9._]+)/) || raw.match(/^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)$/);
  const apple = raw.match(/apps\.apple\.com\/(?:([a-z]{2})\/)?[^?#]*id(\d{5,})/i) || raw.match(/^(?:id)?(\d{7,})$/i);
  if (/play\.google\.com/i.test(raw) && play) { store = "play"; id = play[1]; }
  else if (apple) { store = "appstore"; id = apple[2] || apple[1]; if (apple[2] && apple[1]) country = apple[1]; }
  else if (play) { store = "play"; id = play[1]; }
  if (!store) return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: ["finding_mobile_invalid_target_critical"], score: 0, status: "ERROR", specific: { hint: "Paket adı (com.firma.uygulama), Play Store linki veya App Store linki girin." } });
  const c = makeChecker(); let info = {};
  if (store === "appstore") {
    const r = await axios.get(`https://itunes.apple.com/lookup?id=${id}&country=${country}`, { timeout: 9000, validateStatus: () => true });
    const a = r.data?.results?.[0];
    if (!a) return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: ["finding_mobile_not_found_critical"], score: 0, status: "DOWN", specific: { store: "App Store", id } });
    const age = daysSince(a.currentVersionReleaseDate);
    info = { store: "App Store", id, name: a.trackName, developer: a.sellerName, version: a.version, rating: a.averageUserRating ? Math.round(a.averageUserRating * 10) / 10 : null, ratingCount: a.userRatingCount || 0, lastUpdate: a.currentVersionReleaseDate, daysSinceUpdate: age, minOs: a.minimumOsVersion, price: a.formattedPrice, category: a.primaryGenreName };
  } else {
    const r = await httpProbe(`https://play.google.com/store/apps/details?id=${encodeURIComponent(id)}&hl=en&gl=US`, { timeout: 10000 });
    if (r.status === 404) return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: ["finding_mobile_not_found_critical"], score: 0, status: "DOWN", specific: { store: "Google Play", id } });
    if (!r.ok) return unavailableResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, finding: "finding_mobile_store_unavailable_info", status: "UNKNOWN", note: "Google Play yanıt vermedi veya erişimi kısıtladı.", specific: { store: "Google Play", id, status: r.status } });
    const b = r.body || "";
    const rating = parseFloat((b.match(/"ratingValue":\s*"?([\d.]+)"?/) || [])[1]);
    const rc = parseInt((b.match(/"ratingCount":\s*"?(\d+)"?/) || [])[1], 10);
    const name = ((b.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1] || "").replace(/\s*-\s*Apps on Google Play.*/i, "").trim();
    const installs = (b.match(/>([\d.,]+[KMB]?\+)<\/div><div[^>]*>Downloads/i) || [])[1] || null;
    info = { store: "Google Play", id, name: name || null, rating: isNaN(rating) ? null : rating, ratingCount: isNaN(rc) ? null : rc, downloads: installs, note: "Play Store resmi API sunmaz; ayrıntılar sayfadan okunur, bulunamayan alanlar boş kalır." };
  }
  c.add(true, 40, null, "yayin");
  if (info.rating != null) c.add(info.rating >= 4.0, 25, "finding_mobile_low_rating_warning", "kalite");
  if (info.ratingCount != null) c.add(info.ratingCount >= 50, 10, "finding_mobile_few_ratings_info", "kalite");
  if (info.daysSinceUpdate != null) { c.add(info.daysSinceUpdate <= 365, 15, "finding_mobile_stale_critical", "bakim"); c.add(info.daysSinceUpdate <= 180 || info.daysSinceUpdate > 365, 10, "finding_mobile_aging_warning", "bakim"); }
  const scores = {}; for (const g of c.groups()) scores[g] = c.score(g);
  return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: c.findings(), score: c.score(), specific: { ...info, scores } });
}

// ============ KOD DEPOSU (GitHub) ============
async function scanRepository(input) {
  const startedAt = Date.now(); const V = "repo-analyzer-v1"; const raw = String(input || "").trim();
  const m = raw.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/?#]|$)/i) || raw.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (!m) return buildResult({ assetType: "REPOSITORY", version: V, startedAt, target: raw, findings: ["finding_repo_invalid_target_critical"], score: 0, status: "ERROR", specific: { hint: "sahip/depo biçiminde veya GitHub linki girin." } });
  const [, owner, repo] = m;
  const H = { "User-Agent": "DigitalAssetCenter", Accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };
  const gh = (p) => axios.get(`https://api.github.com/repos/${owner}/${repo}${p}`, { headers: H, timeout: 9000, validateStatus: () => true });
  const r = await gh("");
  if (r.status === 403 && String(r.headers["x-ratelimit-remaining"]) === "0") return unavailableResult({ assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, finding: "finding_repo_rate_limited_info", status: "UNKNOWN", note: "GitHub hız sınırına takıldı. Sunucuya GITHUB_TOKEN ekleyerek sınırı yükseltebilirsiniz." });
  if (r.status === 404) return buildResult({ assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, findings: ["finding_repo_not_found_critical"], score: 0, status: "DOWN", specific: { owner, repo, note: "Depo yok ya da özel (private)." } });
  if (r.status !== 200) return unavailableResult({ assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, finding: "finding_repo_api_error_info", status: "UNKNOWN", note: `GitHub API ${r.status} döndürdü.` });
  const d = r.data;
  const [rel, com] = await Promise.all([gh("/releases/latest"), gh("/community/profile")]);
  const pushAge = daysSince(d.pushed_at); const relAge = rel.status === 200 ? daysSince(rel.data.published_at) : null;
  const files = com.status === 200 ? com.data.files || {} : {};
  const c = makeChecker();
  c.add(!d.archived, 20, "finding_repo_archived_warning", "bakim");
  c.add(pushAge != null && pushAge <= 365, 20, "finding_repo_inactive_critical", "bakim");
  c.add(pushAge != null && pushAge <= 90, 10, "finding_repo_stale_warning", "bakim");
  c.add(!!d.license, 10, "finding_repo_no_license_warning", "topluluk");
  if (com.status === 200) { c.add(!!files.readme, 8, "finding_repo_no_readme_warning", "topluluk"); c.add(!!files.contributing || !!files.code_of_conduct, 4, "finding_repo_no_contributing_info", "topluluk"); }
  c.add((d.open_issues_count || 0) < 100, 8, "finding_repo_many_open_issues_warning", "bakim");
  c.add(rel.status === 200, 5, "finding_repo_no_releases_info", "bakim");
  const scores = {}; for (const g of c.groups()) scores[g] = c.score(g);
  return buildResult({
    assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, findings: c.findings(), score: c.score(),
    specific: { repo: d.full_name, visibility: d.visibility || (d.private ? "private" : "public"), language: d.language, license: d.license?.spdx_id || null, stars: d.stargazers_count, forks: d.forks_count, openIssues: d.open_issues_count, defaultBranch: d.default_branch, archived: d.archived, lastPush: d.pushed_at, daysSinceLastPush: pushAge, latestRelease: rel.status === 200 ? `${rel.data.tag_name} (${relAge} gün önce)` : null, communityHealthPct: com.status === 200 ? com.data.health_percentage : null, sizeKB: d.size, scores }
  });
}

// ============ MARKA KORUMASI ============
const MULTI_TLDS = ["com.tr", "net.tr", "org.tr", "gen.tr", "web.tr", "co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.za", "com.mx", "co.in"];
const BRAND_TLDS = ["com", "net", "org", "io", "co", "app", "dev", "info", "biz", "online", "store", "tech", "ai", "com.tr", "net.tr", "org.tr", "de", "fr", "es", "it", "nl", "co.uk", "eu", "us", "ae", "sa"];
function splitDomain(d) {
  const p = d.split("."); const l2 = p.slice(-2).join(".");
  if (MULTI_TLDS.includes(l2) && p.length >= 3) return { label: p[p.length - 3], tld: l2 };
  return { label: p[p.length - 2] || p[0], tld: p[p.length - 1] };
}
function typoVariants(label, cap = 30) {
  const out = new Set(); const hg = { o: "0", l: "1", i: "l", a: "e", e: "a" };
  for (let i = 0; i < label.length; i++) {
    out.add(label.slice(0, i) + label.slice(i + 1));                       // harf eksik
    out.add(label.slice(0, i) + label[i] + label.slice(i));                // harf çift
    if (i < label.length - 1) out.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2)); // yer değiştirme
    if (hg[label[i]]) out.add(label.slice(0, i) + hg[label[i]] + label.slice(i + 1));                    // benzer karakter
  }
  if (label.includes("m")) out.add(label.replace("m", "rn"));
  if (label.length > 4) out.add(label.slice(0, Math.floor(label.length / 2)) + "-" + label.slice(Math.floor(label.length / 2)));
  out.delete(label);
  const ok = [...out].filter(v => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(v) && v.length >= 2);
  if (ok.length <= cap) return ok;
  const step = ok.length / cap; return Array.from({ length: cap }, (_, i) => ok[Math.floor(i * step)]);
}
async function dnsRegistered(name, resolver) {
  try { const ns = await resolver.resolveNs(name); return { state: "registered", ns: ns.map(x => x.toLowerCase()).sort() }; }
  catch (e) {
    if (e.code === "ENOTFOUND") return { state: "free", ns: [] };
    if (e.code === "ENODATA") { try { const a = await resolver.resolve4(name); return { state: "registered", ns: [], a }; } catch (e2) { return { state: e2.code === "ENOTFOUND" ? "free" : "unknown", ns: [] }; } }
    return { state: "unknown", ns: [] };
  }
}
async function scanBrand(input, extra = {}, resolverOverride) {
  const startedAt = Date.now(); const V = "brand-analyzer-v1"; const domain = parseDomain(input);
  if (!domain) return buildResult({ assetType: "BRAND", version: V, startedAt, target: String(input || ""), findings: ["finding_brand_invalid_target_critical"], score: 0, status: "ERROR", specific: {} });
  const { label, tld } = splitDomain(domain); const base = `${label}.${tld}`;
  const resolver = resolverOverride || new (require("dns").promises.Resolver)({ timeout: 3000, tries: 2 });
  if (!resolverOverride) resolver.setServers(["1.1.1.1", "8.8.8.8"]);
  const own = await dnsRegistered(base, resolver);
  const ownNs = own.ns.join(","); let ownA = []; try { ownA = await resolver.resolve4(base); } catch {}
  const tlds = BRAND_TLDS.filter(t => t !== tld).map(t => `${label}.${t}`);
  const typos = typoVariants(label).map(v => `${v}.${tld}`);
  const names = [...tlds.map(n => ({ n, kind: "tld" })), ...typos.map(n => ({ n, kind: "typo" }))];
  const results = []; const queue = [...names];
  await Promise.all(Array.from({ length: 12 }, async () => { while (queue.length) { const it = queue.shift(); const r = await dnsRegistered(it.n, resolver); let a = r.a || []; if (r.state === "registered" && !a.length) { try { a = await resolver.resolve4(it.n); } catch {} } results.push({ ...it, ...r, a }); } }));
  const mine = (r) => r.state === "registered" && ((ownNs && r.ns.join(",") === ownNs) || (r.a || []).some(ip => ownA.includes(ip)));
  const reg = results.filter(r => r.state === "registered");
  const thirdTld = reg.filter(r => r.kind === "tld" && !mine(r)), thirdTypo = reg.filter(r => r.kind === "typo" && !mine(r));
  const freeTld = results.filter(r => r.kind === "tld" && r.state === "free");
  const unknown = results.filter(r => r.state === "unknown").length;
  const findings = [];
  if (thirdTypo.length) findings.push(`finding_brand_${thirdTypo.length}_lookalike_registered_warning`);
  if (thirdTld.length) findings.push(`finding_brand_${thirdTld.length}_tld_thirdparty_warning`);
  if (freeTld.length) findings.push(`finding_brand_${freeTld.length}_tld_unprotected_info`);
  if (own.state === "free") findings.push("finding_brand_base_not_registered_warning");
  if (unknown > results.length / 2) findings.push("finding_brand_dns_unreliable_info");
  const score = unknown > results.length / 2 ? null : Math.max(0, 100 - Math.min(thirdTypo.length * 5, 40) - Math.min(thirdTld.length * 8, 40));
  const fmt = (a) => a.map(r => `${r.n}${r.ns[0] ? " → " + r.ns[0] : ""}`);
  const base_ = { domain: base, checkedTldVariants: tlds.length, checkedTypoVariants: typos.length, ownedOrSameOwner: reg.filter(mine).map(r => r.n), thirdPartyTldVariants: fmt(thirdTld), thirdPartyLookalikes: fmt(thirdTypo), unregisteredTlds: freeTld.map(r => r.n), undetermined: unknown, note: "Kayıt tespiti DNS'e dayanır: aynı nameserver/IP'ye sahip olanlar 'sizin' sayılır. DNS'i olmayan ama kayıtlı alan adları görünmez; kesin sahiplik için WHOIS/RDAP gerekir." };
  if (score == null) return unavailableResult({ assetType: "BRAND", version: V, startedAt, target: base, finding: "finding_brand_dns_unreliable_info", status: "UNKNOWN", note: "DNS sorguları yeterince yanıt vermedi.", specific: base_ });
  return buildResult({ assetType: "BRAND", version: V, startedAt, target: base, findings, score, specific: base_ });
}


const TYPE_HANDLERS = {
  WEB: ({ targetUrl, extra }) => scanWebsite(targetUrl, extra),
  WEBSITE: ({ targetUrl, extra }) => scanWebsite(targetUrl, extra),
  DOMAIN: ({ targetUrl, extra }) => scanDomain(targetUrl || extra.domain || extra.target, extra),
  EMAIL: ({ targetUrl, extra }) => scanDomain(targetUrl || extra.domain || extra.target, extra),
  SSL_CERTIFICATE: ({ targetUrl, extra }) => scanSslCertificate(targetUrl || extra.domain || extra.target, extra),
  HOSTING: ({ targetUrl, extra }) => scanHosting(targetUrl || extra.domain || extra.target),
  SERVER: ({ targetUrl, extra }) => scanServer(targetUrl || extra.domain || extra.target),
  SEO: ({ targetUrl, extra }) => scanSeo(targetUrl || extra.target),
  SECURITY: ({ targetUrl, extra }) => scanSecurity(targetUrl || extra.target),
  PERFORMANCE: ({ targetUrl, extra }) => scanPerformance(targetUrl || extra.target),
  UPTIME: ({ targetUrl, extra }) => scanUptime(targetUrl || extra.target, extra),
  API: ({ targetUrl, extra }) => scanApi(targetUrl || extra.target),
  MOBILE_APP: ({ targetUrl, extra }) => scanMobileApp(targetUrl || extra.target),
  REPOSITORY: ({ targetUrl, extra }) => scanRepository(targetUrl || extra.target),
  BRAND: ({ targetUrl, extra }) => scanBrand(targetUrl || extra.target, extra),
  SAAS_SUBSCRIPTION: ({ extra }) => scanSaasSubscription(extra)
};

// ===== Site dosyalarını aynı sunucudan yayınla =====
const path = require("path");
const STATIC_FILES = ["index.html", "style.css", "app.js", "config.js", "plans.js", "manifest.json", "icon-192.png", "icon-512.png"];
STATIC_FILES.forEach(f => app.get("/" + f, (q, r) => r.sendFile(path.join(__dirname, f))));
// Service worker: her zaman güncel çekilsin, tüm site kapsamında çalışsın
app.get("/sw.js", (q, r) => {
  r.set({ "Cache-Control": "no-cache", "Service-Worker-Allowed": "/" });
  r.type("application/javascript").sendFile(path.join(__dirname, "sw.js"));
});
app.get("/", (q, r) => r.sendFile(path.join(__dirname, "index.html")));

// ---- Basit hız sınırı (IP başına) ----
const rateHits = new Map();
const rateLimit = (max, windowMs) => (req, res, next) => {
  const now = Date.now(); const arr = (rateHits.get(req.ip + req.path) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) return res.status(429).json({ success: false, error: "Çok fazla istek. Biraz sonra tekrar deneyin." });
  arr.push(now); rateHits.set(req.ip + req.path, arr); next();
};
setInterval(() => { const now = Date.now(); for (const [k, v] of rateHits) if (!v.some(t => now - t < 600000)) rateHits.delete(k); }, 300000).unref();

const payments = require("./payments")({ app, db, admin, http: axios });

app.post("/api/scan", rateLimit(parseInt(process.env.SCAN_RATE_LIMIT || "60", 10), 5 * 60 * 1000), async (req, res) => {
  const { assetId, type, targetUrl, extra = {}, name, notes, organizationId, ownerId } = req.body || {};
  if (!assetId) return res.status(400).json({ success: false, error: "assetId gerekli" });
  const assetType = (type || "WEBSITE").toUpperCase();
  const handler = TYPE_HANDLERS[assetType];
  if (!handler) return res.status(400).json({ success: false, error: `Desteklenmeyen tür: ${assetType}` });

  // Yerel/özel ağlara tarama engeli (SSRF)
  if (!["SAAS_SUBSCRIPTION", "MOBILE_APP", "REPOSITORY"].includes(assetType)) {
    try { await assertPublicHost(hostOf(targetUrl || extra.domain || extra.target)); }
    catch (e) { return res.status(400).json({ success: false, error: e.message }); }
  }
  // Sunucu tarafı plan kontrolü (ENFORCE_PLANS=true ise)
  if (process.env.ENFORCE_PLANS === "true") {
    try {
      const u = await payments.verifyUser(req); const ent = await payments.getEntitlement(u.uid);
      if (ent.plan === "expired") return res.status(402).json({ success: false, code: "PLAN_REQUIRED", error: "Deneme süreniz bitti. Devam etmek için bir paket seçin." });
    } catch (e) { return res.status(e.status || 401).json({ success: false, error: e.message }); }
  }

  const scanStartedAt = Date.now();
  let findings = [], scanErrors = [], typeData = {}, statusHint = null, failed = false;

  try {
    const result = await handler({ targetUrl, extra });
    typeData = result?.data || {};
    findings = Array.isArray(result?.findings) ? result.findings : [];
    if (Array.isArray(result?.errors)) scanErrors.push(...result.errors);
    statusHint = result?.statusHint || null;
  } catch (e) {
    findings.push("finding_scan_error");
    scanErrors.push(e?.message || "Unknown");
    statusHint = "ERROR"; failed = true;
  }

  const healthResult = computeHealth(findings);
  const confidence = computeConfidence(findings, scanErrors.length > 0);

  const scoreUnavailable = failed || (typeData?.commonAnalysis && typeData.commonAnalysis.score === null);
  let finalHealthScore = scoreUnavailable ? null : (typeData?.commonAnalysis?.score ?? healthResult.healthScore);
  let finalHealthLevel = scoreUnavailable ? "BELİRSİZ" : healthResult.healthLevel;
  if (finalHealthScore != null && !scoreUnavailable) finalHealthLevel = finalHealthScore >= 80 ? "YEŞİL" : finalHealthScore >= 50 ? "SARI" : "KIRMIZI";
  let finalStatus = statusHint || (typeData?.commonAnalysis?.status) || defaultStatusFromHealth(finalHealthLevel);
  if (assetType === "DOMAIN" && typeData?.commonAnalysis?.score != null) {
    finalHealthScore = typeData.commonAnalysis.score;
    finalHealthLevel = finalHealthScore >= 80 ? "YEŞİL" : finalHealthScore >= 50 ? "SARI" : "KIRMIZI";
    finalStatus = typeData.commonAnalysis.status;
  }

  const nowIso = new Date().toISOString();
  const assetUpdate = {
    assetId,
    assetType: assetType,
    type: assetType,
    ...typeData,
    findings,
    healthLevel: finalHealthLevel,
    healthScore: finalHealthScore,
    confidence,
    status: finalStatus,
    latencyMs: Date.now() - scanStartedAt,
    lastCheck: nowIso,
    updatedAt: nowIso
  };
  if (name) assetUpdate.name = name;
  if (targetUrl) assetUpdate.targetUrl = targetUrl;
  if (organizationId) assetUpdate.organizationId = organizationId;
  if (ownerId) assetUpdate.ownerId = ownerId;

  // Firestore kaydı opsiyonel: hata verse bile tarama sonucu kullanıcıya döner
  let saved = false, checkId = null, saveError = null;
  if (db) {
    try {
      const ts = admin.firestore.FieldValue.serverTimestamp();
      await withTimeout((async () => {
        await db.collection("assets").doc(assetId).set({ ...assetUpdate, lastCheck: ts, updatedAt: ts }, { merge: true });
        const checkRef = db.collection("assetChecks").doc();
        checkId = checkRef.id;
        await checkRef.set({
          assetId, checkId, type: assetType,
          targetUrl: targetUrl || null,
          checkedAt: ts,
          errors: scanErrors, findings,
          healthScore: finalHealthScore,
          healthLevel: finalHealthLevel,
          confidence, latencyMs: Date.now() - scanStartedAt,
          status: finalStatus,
          scannerVersion: typeData?.analysisMeta?.scannerVersion || null
        });
      })(), 8000);
      saved = true;
    } catch (e) {
      saveError = e?.message || "Firestore hatası";
      console.error("Firestore kayıt hatası:", saveError);
    }
  }
  return res.json({ success: true, assetId, checkId, saved, saveError, errors: scanErrors, result: assetUpdate });
});

app.get("/health", (req, res) => res.json({ ok: true, types: Object.keys(TYPE_HANDLERS), version: "v11.0", firestore: !!db, payments: payments.status(), timestamp: new Date().toISOString() }));
app.listen(PORT, () => console.log(`Scraper v10.0 FULL FIXED CLEAN ${PORT} portunda`));
module.exports = app;
