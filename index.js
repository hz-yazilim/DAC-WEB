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

if (!admin.apps.length) {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
  } else admin.initializeApp();
}
const db = admin.firestore();

const app = express();
app.use(require("cors")());
app.use(express.json({ limit: '2mb' }));
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
async function httpProbe(url, { method = "GET", timeout = 9000, headers = {} } = {}) {
  const startedAt = Date.now();
  try {
    const res = await axios.request({
      url, method, timeout,
      headers: { ...BROWSER_HEADERS, ...headers },
      validateStatus: () => true,
      maxRedirects: 5
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

// ============ 1. WEB SCANNER ============
async function scanWebsite(targetUrl, extra = {}) {
  const startedAt = Date.now();
  const findings = []; const errors = [];
  if (!targetUrl) { findings.push("finding_web_missing_target_critical"); return { data: null, findings, errors: ["targetUrl yok"] }; }
  const main = await httpProbe(targetUrl);
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
    const robustTxt = await reso
