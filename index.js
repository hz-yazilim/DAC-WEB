// Render ücretsiz plan (~512MB): V8 yığın sınırını düşür ki OOM-kill yerine erken GC çalışsın (NODE_OPTIONS ile ezilebilir)
try { if (!/max-old-space-size/.test(process.env.NODE_OPTIONS || "")) require("v8").setFlagsFromString("--max-old-space-size=" + (process.env.HEAP_MB || 300)); } catch {}
/**
 * Digital Asset Center - Scanner API v12.0 "DEEP"
 * ---------------------------------------------------------------------------
 * Bu sürümde tüm tarama türleri baştan, derin analiz yapacak şekilde yazıldı:
 *  - Tek ve güvenilir ağ katmanı: SSRF korumalı (DNS seviyesinde), yönlendirme
 *    zinciri, çerez desteği, gzip/br açma, TLS hatasında yedek deneme, UA yedeği,
 *    www/apex yedek denemesi, hatanın nedenini sınıflandırma (DNS/TLS/zaman aşımı...)
 *  - Yinelenen fonksiyon tanımları temizlendi (eski sürümde sondaki zayıf
 *    parseDomain/daysUntil, doğru olanları eziyordu)
 *  - DOMAIN: kayıtlı alan adı tespiti (subdomain girilse bile), IANA RDAP bootstrap,
 *    SPF (10 lookup limiti, +all, çoklu kayıt), DMARC (sp/pct/rua), DKIM (anahtar
 *    uzunluğu, MX'ten sağlayıcı tahmini), MTA-STS, TLS-RPT, BIMI, DNSSEC (DS/DNSKEY),
 *    NS tutarlılığı (SOA serial), CAA, dangling-CNAME/subdomain takeover, CT log,
 *    DNSBL kara liste
 *  - SSL: gerçek imza algoritması (DER), anahtar tipi/uzunluğu, hostname eşleşmesi,
 *    zincir/güven durumu, TLS 1.0-1.3 desteği, OCSP stapling
 *  - WEB / SEO / SECURITY / PERFORMANCE / UPTIME / API / HOSTING / SERVER / MOBILE /
 *    REPOSITORY / BRAND / SAAS derinleştirildi; bilinemeyen durumda uydurma skor yok.
 *
 * Çıktı sözleşmesi (Firestore + site) korunur: commonAnalysis, specificAnalysis,
 * findings (finding_<anahtar>_<critical|warning|info>), status, score.
 */
"use strict";

require("dns").setServers(["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]);
const dnsCb = require("dns");
const dns = dnsCb.promises;
const http = require("http");
const https = require("https");
const express = require("express");
const axios = require("axios");
const admin = require("firebase-admin");
const net = require("net");
const tlsMod = require("tls");
const zlib = require("zlib");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
// Dosyalar klasörlü (server/, public/) da düz (hepsi aynı klasörde) da yüklenmiş olsa çalışsın
const STRUCT = fs.existsSync(path.join(__dirname, "public"));
const SRV = (n) => require(fs.existsSync(path.join(__dirname, "server", n + ".js")) ? "./server/" + n : "./" + n);

// Firebase OPSİYONEL: geçerli hizmet hesabı yoksa sunucu sadece tarama yapar (ayrıntı: firebase-init.js).
const FB = SRV("firebase-init");
const fbInit = FB.initFirebase(admin);
let db = fbInit.db;
const firebaseStatus = fbInit.status;

const app = express();
const SEC = SRV("security");
let OPS = null; // ops.js sonradan oluşturulur (db/admin hazır olduktan sonra)
const METRICS = SRV("metrics").createMetrics({ onError: (e) => { if (OPS) OPS.persistError(e); } });       // API gecikme (P50/P95/P99), hata oranı, kuyruk/tarama süreleri
const SCORING = SRV("scoring");                       // merkezi skor ağırlıkları ve kritik bulgu sınırı
const VALID = SRV("validators");                      // domain / URL / telefon doğrulama
const BLOCK = SRV("blocklist");                       // korumalı hedefler: devlet/kamu, büyük platformlar, dacweb.tr (hiçbir türde taranamaz)
const AI = SRV("ai-provider");                        // AI mimarisi (şimdilik devre dışı) + dönemsel rapor modeli
const BILLING = SRV("billing-catalog");               // para birimi / kur adaptörü / affiliate hazırlığı (etkin değil)
const JOBLIB = SRV("jobs");                           // kalıcı toplu tarama kuyruğu
const PLANS = (() => { try { return require("../public/js/plans"); } catch (e) { return require("./plans"); } })();
app.disable("x-powered-by");
app.set("trust proxy", 1);
// HTTPS zorunlu: üretimde düz HTTP istekleri https'e 301/308 ile yönlendirilir (Render/Cloudflare X-Forwarded-Proto ile). /health (sağlayıcı sağlık kontrolü) ve yerel adresler hariç.
// Kapatmak için FORCE_HTTPS=false. HSTS başlığı aşağıda helmet ile zaten gönderilir.
app.use((req, res, next) => {
  if (process.env.FORCE_HTTPS === "false" || (process.env.NODE_ENV !== "production" && process.env.FORCE_HTTPS !== "true")) return next();
  if (req.secure || req.path === "/health") return next();
  const host = String(req.headers.host || "").toLowerCase().split(":")[0];
  if (!host || host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".local") || !/^[a-z0-9.-]+$/.test(host)) return next();
  return res.redirect(req.method === "GET" || req.method === "HEAD" ? 301 : 308, "https://" + host + req.originalUrl);
});
// Yanıt sıkıştırma (gzip/br): "compression" paketi yüklüyse etkinleşir
try { app.use(require("compression")()); } catch (e) { console.warn("compression paketi yok: npm install compression"); }
// SEO: API yanıtları arama sonuçlarına girmesin (robots.txt ile birlikte çift koruma)
app.use(["/api", "/health"], (q, r, n) => { r.set("X-Robots-Tag", "noindex, nofollow"); n(); });
// Firebase Auth: giriş penceresi/iframe'i authDomain'den yüklenir (özel alan adı veya *.web.app olabilir) ve reCAPTCHA (google.com) gerekebilir
const AUTH_DOMAIN_SRC = (() => { const d = String(process.env.FIREBASE_WEB_AUTH_DOMAIN || "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, ""); return /^[a-z0-9.-]+$/i.test(d) ? ["https://" + d] : []; })();
app.use(require("helmet")({
  // Google ile giriş penceresi (popup) için COOP gevşetildi
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "same-site" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
  xContentTypeOptions: true,
  // CSP artık varsayılan olarak ZORUNLU. Sorun çıkarsa geçici olarak CSP_MODE=report ile rapor moduna alınabilir.
  contentSecurityPolicy: {
    reportOnly: process.env.CSP_MODE === "report",
    directives: {
      defaultSrc: ["'self'"],
      // 'unsafe-inline' kaldırıldı: tüm script'ler harici dosyada (login.js, sw-register.js, app.js ...)
      scriptSrc: ["'self'", "https://www.gstatic.com", "https://apis.google.com", "https://www.google.com", "https://www.googletagmanager.com", "https://challenges.cloudflare.com"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'"],
      styleSrcAttr: ["'unsafe-inline'"], // app.js dinamik stil nitelikleri (style="color:...") kullanıyor
      fontSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://*.onrender.com", "https://*.googleapis.com", "https://*.google-analytics.com", "https://*.analytics.google.com", "https://*.googletagmanager.com", "https://*.firebaseio.com", "https://*.firebaseapp.com", "https://*.web.app", "https://www.gstatic.com", "https://www.google.com", ...AUTH_DOMAIN_SRC],
      frameSrc: ["'self'", "https://accounts.google.com", "https://*.firebaseapp.com", "https://*.web.app", "https://www.google.com", "https://recaptcha.google.com", ...AUTH_DOMAIN_SRC, "https://www.paytr.com", "https://challenges.cloudflare.com"],
      formAction: ["'self'", "https://www.paytr.com"],
      manifestSrc: ["'self'"], workerSrc: ["'self'"],
      objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    }
  }
}));
// Helmet'in vermediği başlıklar + ek sertleştirme
app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(self), usb=(), serial=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), interest-cohort=()");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.removeHeader("Server");
  next();
});
app.use(require("cors")(SEC.corsOptions));
app.use(METRICS.middleware("/api"));
const globalApiLimit = SEC.makeLimiter(SEC.int(process.env.API_RATE_LIMIT, 600), 5 * 60 * 1000);
app.use("/api", (req, res, next) => (globalApiLimit(req.ip) ? next() : res.status(429).json({ success: false, error: "Çok fazla istek. Biraz sonra tekrar deneyin." })));
const jsonParser = express.json({ limit: "256kb", verify: (req, res, buf) => { req.rawBody = buf; } });
app.use((req, res, next) => (req.path === "/api/state" ? next() : jsonParser(req, res, next)));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
const PORT = process.env.PORT || 3000;
const SCANNER_VERSION = "v13.6";

const UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const UA_BOT = "Mozilla/5.0 (compatible; DigitalAssetCenterBot/12.0; +https://dacweb.tr)";
const BROWSER_HEADERS = {
  "User-Agent": UA_BROWSER,
  "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Encoding": "gzip, deflate, br"
};

const STATUS = { VALID: "VALID", INACTIVE: "INACTIVE", UNKNOWN: "UNKNOWN", NOT_REQUIRED: "NOT_REQUIRED", MISSING: "MISSING", SELECTOR_NOT_DISCOVERED: "SELECTOR_NOT_DISCOVERED" };
const TRANSFER_LOCK_STATUS = { LOCKED: "LOCKED", UNLOCKED: "UNLOCKED", UNKNOWN: "UNKNOWN" };

// =====================================================================
// GENEL YARDIMCILAR (her biri SADECE 1 KEZ tanımlı)
// =====================================================================
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const avg = (a) => a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null;
const clamp = (n, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, n));
const statusFromScore = (s) => s >= 80 ? "HEALTHY" : s >= 50 ? "WARNING" : "CRITICAL";
const ensureUrl = (t) => /^https?:\/\//i.test(String(t || "").trim()) ? String(t).trim() : "https://" + String(t || "").trim();
const hostOf = (t) => { try { return new URL(ensureUrl(t)).hostname.toLowerCase().replace(/\.$/, ""); } catch { return null; } };
const toDateOrNull = (s) => { if (!s) return null; const d = s instanceof Date ? s : new Date(s); return isNaN(d.getTime()) ? null : d; };
// UTC gün bazlı kalan gün: saat farkından 1 gün kayma olmaz
function daysUntil(dateInput) {
  const t = toDateOrNull(dateInput); if (!t) return null;
  const n = new Date();
  return Math.floor((Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate()) - Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate())) / 864e5);
}
function daysSince(d) { const t = toDateOrNull(d); return t ? Math.floor((Date.now() - t.getTime()) / 864e5) : null; }
function withTimeout(promise, ms, label = "İşlem") {
  let t; return Promise.race([promise, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${label} zaman aşımı`)), ms); })]).finally(() => clearTimeout(t));
}
async function pool(items, limit, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const k = i++; try { out[k] = await fn(items[k], k); } catch (e) { out[k] = undefined; } }
  }));
  return out;
}
const decodeEntities = (s) => String(s || "")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'")
  .replace(/&#(\d{1,7});/g, (_, n) => { try { return String.fromCodePoint(+n); } catch { return ""; } })
  .replace(/&#x([0-9a-f]{1,6});/gi, (_, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch { return ""; } })
  .replace(/&amp;/g, "&");

// ---------- Hedef/alan adı ayrıştırma ----------
// Çok parçalı kamu son ekleri (tam PSL yerine yaygın olanlar; yeni bağımlılık gerektirmez)
const MULTI_TLDS = new Set(("com.tr net.tr org.tr gen.tr web.tr biz.tr info.tr tv.tr name.tr av.tr dr.tr bel.tr k12.tr edu.tr gov.tr mil.tr pol.tr kep.tr " +
  "co.uk org.uk me.uk ltd.uk plc.uk net.uk ac.uk gov.uk sch.uk com.au net.au org.au edu.au gov.au id.au co.nz net.nz org.nz govt.nz ac.nz " +
  "co.jp ne.jp or.jp ac.jp go.jp com.br net.br org.br gov.br edu.br co.za org.za net.za web.za com.mx org.mx gob.mx edu.mx co.in net.in org.in firm.in gen.in ind.in " +
  "com.cn net.cn org.cn gov.cn edu.cn com.hk org.hk edu.hk com.sg org.sg edu.sg com.my org.my com.ph org.ph com.tw org.tw com.vn com.pk com.bd com.np com.lk " +
  "com.sa org.sa gov.sa com.eg org.eg gov.eg com.ng org.ng gov.ng co.ke or.ke co.il org.il ac.il co.kr or.kr go.kr co.th or.th co.id or.id web.id " +
  "com.ar org.ar com.co org.co com.pe com.ve com.uy com.ec com.ua org.ua com.pl org.pl net.pl com.pt org.pt com.es org.es nom.es com.ru org.ru com.gr org.gr com.cy org.cy " +
  "com.tn com.dz com.ma co.ma com.lb com.jo com.qa com.kw com.om com.bh com.ae net.ae org.ae gov.ae co.ae").split(/\s+/));
function parseHostLoose(input) {
  if (input == null) return null;
  let s = String(input).trim().toLowerCase();
  if (!s) return null;
  try { const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(s) ? s : "https://" + s); s = u.hostname; }
  catch { s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^.*@/, "").split(/[/?#]/)[0].split(":")[0]; }
  s = s.replace(/^\[|\]$/g, "").replace(/^\.+|\.+$/g, "");
  return s || null;
}
function registrableDomain(host) {
  if (!host || net.isIP(host)) return host || null;
  const p = host.split(".").filter(Boolean);
  if (p.length <= 2) return p.join(".");
  const l2 = p.slice(-2).join(".");
  if (MULTI_TLDS.has(l2) && p.length >= 3) return p.slice(-3).join(".");
  return l2;
}
// Alan adı olarak parse (www. atılır; IP kabul edilmez). Domain/e-posta/SSL tipleri için.
function parseDomain(input) {
  const h = parseHostLoose(input);
  if (!h || net.isIP(h) || !h.includes(".")) return null;
  const d = h.replace(/^www\./, "");
  if (!/^[a-z0-9_.\-\u00a1-\uffff]+$/i.test(d) || d.length > 253) return null;
  return d;
}
// Sunucu/Hosting/Uptime için IP de olabilen hedef
function parseTargetHost(input) {
  const h = parseHostLoose(input);
  if (!h) return null;
  if (net.isIP(h)) return h;
  return h.includes(".") ? h : null;
}
function splitDomain(d) {
  const p = d.split("."); const l2 = p.slice(-2).join(".");
  if (MULTI_TLDS.has(l2) && p.length >= 3) return { label: p[p.length - 3], tld: l2 };
  return { label: p[p.length - 2] || p[0], tld: p[p.length - 1] };
}

// =====================================================================
// SSRF KORUMASI (DNS seviyesinde: yönlendirme ve DNS rebinding dahil)
// =====================================================================
function isPrivateV4(p) {
  const [a, b, c] = p;
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0 && c === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
}
// IPv6 adresini 16 baytlık diziye çevirir (geçersizse null). URL ayrıştırıcı ::ffff:127.0.0.1 adresini ::ffff:7f00:1 biçimine çevirdiği için metin eşlemesi yetmez.
function ipv6ToBytes(ip) {
  let s = String(ip).split("%")[0];
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) { const p = m[2].split(".").map(Number); if (p.some(n => !(n >= 0 && n <= 255))) return null; s = m[1] + ((p[0] << 8) | p[1]).toString(16) + ":" + ((p[2] << 8) | p[3]).toString(16); }
  const halves = s.split("::"); if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : []; const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups;
  if (halves.length === 2) { const fill = 8 - head.length - rest.length; if (fill < 0) return null; groups = [...head, ...Array(fill).fill("0"), ...rest]; } else groups = head;
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) { if (!/^[0-9a-f]{1,4}$/.test(g)) return null; const n = parseInt(g, 16); out.push(n >> 8, n & 255); }
  return out;
}
function isPrivateIp(ip) {
  ip = String(ip || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (net.isIPv4(ip)) return isPrivateV4(ip.split(".").map(Number));
  if (net.isIPv6(ip)) {
    const b = ipv6ToBytes(ip); if (!b) return true; // ayrıştırılamayan IPv6: güvenli tarafta kal
    const zeros = (n) => b.slice(0, n).every(x => x === 0);
    const v4 = (o) => isPrivateV4([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    if (zeros(10) && b[10] === 0xff && b[11] === 0xff) return v4(12);              // ::ffff:a.b.c.d (IPv4-eşlemeli)
    if (zeros(12)) return true;                                                    // ::, ::1, ::a.b.c.d
    if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.slice(4, 12).every(x => x === 0)) return v4(12); // NAT64 64:ff9b::/96
    if (b[0] === 0x20 && b[1] === 0x02) return v4(2);                              // 6to4 2002::/16
    if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0) return true;   // Teredo 2001::/32
    if ((b[0] & 0xfe) === 0xfc) return true;                                       // fc00::/7 (ULA)
    if (b[0] === 0xfe && (b[1] & 0x80) === 0x80) return true;                      // fe80::/10 ve fec0::/10
    if (b[0] === 0xff) return true;                                                // multicast
    return false;
  }
  return false;
}
const allowPrivate = () => process.env.ALLOW_PRIVATE_TARGETS === "true";
function safeLookup(hostname, options, cb) {
  if (typeof options === "function") { cb = options; options = {}; }
  dnsCb.lookup(hostname, options, (err, address, family) => {
    if (err) return cb(err);
    if (!allowPrivate()) {
      const list = Array.isArray(address) ? address.map(a => a.address) : [address];
      if (list.some(isPrivateIp)) { const e = new Error("Yerel veya özel ağ adreslerine erişim engellendi"); e.code = "EPRIVATE"; return cb(e); }
    }
    cb(null, address, family);
  });
}
async function assertPublicHost(host) {
  if (allowPrivate() || !host) return;
  const h = String(host).replace(/^\[|\]$/g, "").toLowerCase();
  const deny = new Error("Yerel veya özel ağ adreslerine tarama yapılamaz");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) throw deny;
  if (net.isIP(h)) { if (isPrivateIp(h)) throw deny; return; }
  let addrs = []; try { addrs = await dns.lookup(h, { all: true }); } catch { return; }
  if (addrs.some(a => isPrivateIp(a.address))) throw deny;
}
// IP-literal hedeflerde Node "lookup" çağırmaz; bu yüzden özel adresler burada ayrıca engellenir (yönlendirme zinciri dahil).
function blockedHost(host) {
  if (allowPrivate() || !host) return false;
  const h = String(host).replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  return net.isIP(h) ? isPrivateIp(h) : false;
}
const privateError = () => Object.assign(new Error("Yerel veya özel ağ adreslerine erişim engellendi"), { code: "EPRIVATE" });
const httpAgent = new http.Agent({ lookup: safeLookup, keepAlive: false });
const httpsStrict = new https.Agent({ lookup: safeLookup, keepAlive: false, rejectUnauthorized: true });
const httpsLoose = new https.Agent({ lookup: safeLookup, keepAlive: false, rejectUnauthorized: false });

// =====================================================================
// AĞ KATMANI: tek, güvenilir HTTP istemcisi
// =====================================================================
const TLS_ERR = /CERT|SSL|TLS|ALTNAME|SELF.SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_OSSL/i;
function classifyNetError(e) {
  const code = String(e?.code || ""); const msg = String(e?.message || e || "");
  let kind = "other";
  if (/ENOTFOUND|EAI_NODATA|EAI_NONAME/.test(code) || /getaddrinfo ENOTFOUND/.test(msg)) kind = "dns";
  else if (/EAI_AGAIN/.test(code)) kind = "dns_temp";
  else if (/ECONNREFUSED/.test(code)) kind = "refused";
  else if (/ETIMEDOUT|ECONNABORTED|ESOCKETTIMEDOUT/.test(code) || /timeout/i.test(msg)) kind = "timeout";
  else if (/ECONNRESET|EPIPE|socket hang up/.test(code + msg)) kind = "reset";
  else if (/EHOSTUNREACH|ENETUNREACH/.test(code)) kind = "unreachable";
  else if (/EPRIVATE/.test(code)) kind = "private";
  else if (TLS_ERR.test(code) || TLS_ERR.test(msg)) kind = "tls";
  else if (/redirect/i.test(msg)) kind = "redirect";
  return { code: code || null, kind, message: msg };
}
const decoderFor = (enc) => enc === "gzip" || enc === "x-gzip" ? zlib.createGunzip() : enc === "br" ? zlib.createBrotliDecompress() : enc === "deflate" ? zlib.createInflate() : null;

// Tek istek (yönlendirme takip ETMEZ). TTFB, sıkıştırılmış/ham boyut ve gövdeyi ölçer.
async function request(url, o = {}) {
  const { method = "GET", timeout = 10000, headers = {}, maxBytes = 2e6, readBody = true, insecure = false } = o;
  const t0 = Date.now();
  const base = { ok: false, status: 0, ttfb: null, total: null, responseTimeMs: null, transferBytes: 0, rawBytes: 0, encoding: null, headers: {}, body: "", finalUrl: url, truncated: false };
  let res;
  try {
    let pu; try { pu = new URL(url); } catch { throw Object.assign(new Error("Geçersiz adres"), { code: "EINVALIDURL" }); }
    if (pu.protocol !== "http:" && pu.protocol !== "https:") throw Object.assign(new Error("Yalnızca http/https desteklenir"), { code: "EINVALIDURL" });
    if (blockedHost(pu.hostname)) throw privateError();
    res = await axios.request({
      url, method, timeout, headers: { ...BROWSER_HEADERS, ...headers }, responseType: "stream", decompress: false,
      maxRedirects: 0, validateStatus: () => true, httpAgent, httpsAgent: insecure ? httpsLoose : httpsStrict, proxy: false
    });
  } catch (e) {
    const ni = classifyNetError(e); const total = Date.now() - t0;
    return { ...base, total, responseTimeMs: total, error: ni.message, errorInfo: ni };
  }
  const ttfb = Date.now() - t0;
  const h = res.headers || {}; const enc = String(h["content-encoding"] || "").toLowerCase() || null;
  const ctype = String(h["content-type"] || "").toLowerCase();
  const textual = !ctype || /text|json|xml|javascript|html|svg/.test(ctype);
  let transfer = 0, raw = 0, truncated = false; const chunks = [];
  if (method === "HEAD") { res.data.destroy(); }
  else await new Promise((resolve) => {
    let finished = false; const done = () => { if (finished) return; finished = true; clearTimeout(timer); resolve(); };
    const timer = setTimeout(() => { truncated = true; try { res.data.destroy(); } catch {} done(); }, Math.max(3000, timeout));
    const dec = enc ? decoderFor(enc) : null;
    res.data.on("data", d => { transfer += d.length; if (transfer > maxBytes * 2 && !dec) { truncated = true; res.data.destroy(); done(); } });
    res.data.on("error", done);
    const out = dec ? res.data.pipe(dec) : res.data;
    // Sıkıştırılmışsa bitiş, AÇICI akıştan beklenir (kaynak akış önce kapanıp gövdeyi yarım bırakmasın)
    if (dec) { dec.on("error", done); dec.on("close", done); } else res.data.on("close", done);
    out.on("data", d => { raw += d.length; if (readBody && textual && raw <= maxBytes) chunks.push(d); else if (raw > maxBytes) { truncated = true; try { res.data.destroy(); } catch {} done(); } });
    out.on("end", done);
  });
  const total = Date.now() - t0;
  const clen = parseInt(h["content-length"] || "0", 10);
  return { ok: res.status < 400, status: res.status, ttfb, total, responseTimeMs: total, transferBytes: truncated ? Math.max(transfer, clen) : (transfer || clen || 0), rawBytes: raw, encoding: enc, headers: h,
    body: readBody && textual ? Buffer.concat(chunks).toString("utf8") : "", finalUrl: url, truncated, contentType: ctype };
}
// Geçici ağ hatalarında 1 kez yeniden dener; TLS sertifika hatasında doğrulamasız tekrar dener (hata kaydedilir)
async function requestRetry(url, o = {}) {
  let r = await request(url, o);
  if (r.status === 0 && r.errorInfo) {
    const k = r.errorInfo.kind;
    if (k === "tls" && !o.insecure) {
      const r2 = await request(url, { ...o, insecure: true });
      if (r2.status > 0) { r2.tlsError = r.errorInfo.code || r.errorInfo.message; return r2; }
      return r;
    }
    // Zaman aşımında yeniden deneme yok (engelleyen/yanıt vermeyen sitede süreyi ikiye katlamasın)
    if (["reset", "dns_temp", "other"].includes(k) && !o.noRetry) { await sleep(300); return await request(url, o); }
  }
  return r;
}
function parseSetCookie(arr) { return [].concat(arr || []).map(c => String(c).split(";")[0]).filter(c => c.includes("=")); }
// Yönlendirmeleri elle takip eder (SSRF/çerez/döngü kontrollü). Eski httpProbe arayüzünü korur.
async function httpProbe(url, o = {}) {
  const max = o.maxRedirects ?? 5; const chain = []; const jar = new Map(); let cur = url, res = null, tlsError = null, loop = false;
  const seen = new Set();
  for (let i = 0; i <= max; i++) {
    const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    res = await requestRetry(cur, { ...o, headers: { ...(o.headers || {}), ...(cookie ? { Cookie: cookie } : {}) } });
    if (i === 0 && !o.noUaFallback && (o.method || "GET") === "GET" && [403, 406, 429].includes(res.status) && !detectBotProtection(res)) {
      const alt = await requestRetry(cur, { ...o, headers: { ...(o.headers || {}), "User-Agent": UA_BOT } });
      if (alt.status > 0 && alt.status < 400) { res = alt; res.uaFallback = true; }
    }
    if (res.tlsError) tlsError = res.tlsError;
    chain.push({ url: cur, status: res.status, ms: res.total, ttfb: res.ttfb });
    parseSetCookie(res.headers["set-cookie"]).forEach(c => { const [k, ...v] = c.split("="); jar.set(k, v.join("=")); });
    const loc = res.headers && res.headers["location"];
    if (res.status >= 300 && res.status < 400 && loc && i < max) {
      let nxt; try { nxt = new URL(loc, cur).toString(); } catch { break; }
      if (seen.has(nxt)) { loop = true; break; }
      // Korumalı hedef politikası: kullanıcının sitesi → devlet/büyük platform/dacweb.tr yönlendirmesi TAKİP EDİLMEZ (başkasının sitesi dolaylı yoldan analiz edilmesin).
      // Zaten korumalı bir platforma yapılan sabit çağrılarda (ör. Play Store) uygulanmaz: yalnızca "korumasız → korumalı" geçişi durdurulur.
      try { const nh = new URL(nxt).hostname, ch = new URL(cur).hostname; if (!BLOCK.classifyHost(ch).blocked && BLOCK.classifyHost(nh).blocked) { res.redirectBlocked = true; break; } } catch { break; }
      seen.add(cur); cur = nxt; continue;
    }
    break;
  }
  res.chain = chain; res.finalUrl = cur; res.redirects = Math.max(0, chain.length - 1); res.tlsError = tlsError; res.redirectLoop = loop;
  res.cookies = [].concat(res.headers["set-cookie"] || []);
  return res;
}
const timedGet = (url, timeout = 12000) => httpProbe(url, { timeout, maxRedirects: 5, noUaFallback: true });

function tcpPortCheck(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket(); const startedAt = Date.now(); let done = false;
    const finish = (open, err) => { if (done) return; done = true; socket.destroy(); resolve({ port, open, latencyMs: Date.now() - startedAt, error: err || null }); };
    socket.setTimeout(timeout);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (e) => finish(false, e.code || e.message));
    if (blockedHost(host)) return finish(false, "EPRIVATE");
    socket.connect({ port, host, lookup: safeLookup });
  });
}

// ---------- Bot koruması algılama ----------
function detectBotProtection(probe) {
  const h = probe.headers || {}; const body = String(probe.body || "").slice(0, 30000).toLowerCase();
  const server = String(h["server"] || "").toLowerCase();
  const blocked = [401, 403, 429, 503].includes(probe.status);
  if (String(h["cf-mitigated"] || "").toLowerCase() === "challenge") return "Cloudflare";
  if (!blocked) return null;
  const isCf = server.includes("cloudflare") || !!h["cf-ray"];
  if (isCf && /just a moment|cf-chl|challenge-platform|attention required|checking your browser|cf-browser-verification|enable javascript and cookies/.test(body)) return "Cloudflare";
  if (h["x-sucuri-id"] || /sucuri website firewall/.test(body)) return "Sucuri";
  if (h["x-iinfo"] || /incapsula incident/.test(body)) return "Imperva Incapsula";
  if (server.includes("ddos-guard") || /ddos-guard/.test(body)) return "DDoS-Guard";
  if (server.includes("akamaighost") && /access denied/.test(body)) return "Akamai";
  if (/px-captcha|perimeterx|datadome|human verification/.test(body) || h["x-datadome"]) return "Bot koruma servisi";
  if (/aws.?waf|request blocked.*cloudfront/.test(body)) return "AWS WAF";
  return null;
}

// =====================================================================
// DNS KATMANI
// =====================================================================
const TRANSIENT_DNS = new Set(["ETIMEOUT", "ETIMEDOUT", "ESERVFAIL", "ECONNREFUSED", "EREFUSED", "ECONNRESET", "EAI_AGAIN", "ECANCELLED", "EBADRESP"]);
// {data, code}: code null = başarılı, ENODATA/ENOTFOUND = kesin yok, diğerleri = geçici hata (bilinmiyor)
async function dq(method, name, resolver) {
  const r = resolver || dns;
  for (let i = 0; i < 2; i++) {
    try { const data = await r[method](name); return { data: data || [], code: null }; }
    catch (e) { const code = e.code || "EUNKNOWN"; if (TRANSIENT_DNS.has(code) && i === 0) { await sleep(250); continue; } return { data: [], code }; }
  }
  return { data: [], code: "EUNKNOWN" };
}
const dnsMissing = (c) => c === "ENODATA" || c === "ENOTFOUND";
const safeResolve = async (fn, ...args) => { try { return await fn(...args); } catch { return null; } };

async function dohQuery(name, type, extra = "") {
  const eps = [`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}${extra}`, `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}${extra}`];
  for (const u of eps) {
    try { const r = await axios.get(u, { headers: { accept: "application/dns-json" }, timeout: 6000, proxy: false, validateStatus: () => true }); if (r.status === 200 && r.data && typeof r.data === "object") return r.data; } catch {}
  }
  return null;
}
const cleanTxt = (d) => { let t = String(d || ""); if (/^".*"$/.test(t.trim()) || t.includes('" "')) t = t.replace(/"\s+"/g, "").replace(/^"|"$/g, ""); return t.replace(/\\"/g, '"'); };
async function dohTxt(domain) {
  const data = await dohQuery(domain, "TXT"); const ans = (data?.Answer || []).filter(a => a.type === 16);
  return ans.length ? ans.map(a => [cleanTxt(a.data)]) : null;
}
function normalizeTxtRecords(records) {
  if (!Array.isArray(records)) return [];
  return records.map(r => Array.isArray(r) ? r.join("") : String(r || "")).map(v => v.trim().replace(/^"+|"+$/g, "")).filter(Boolean);
}
// TXT: yerel çözümleyici → Cloudflare DoH → Google DoH. Kesin "yok" ile "sorgu başarısız" ayrılır.
async function resolveTxtRobust(name) {
  const r = await dq("resolveTxt", name);
  if (r.data.length) return { records: r.data, state: "ok" };
  const d = await dohTxt(name);
  if (d && d.length) return { records: d, state: "ok" };
  return { records: [], state: dnsMissing(r.code) ? "none" : (d === null && r.code && !dnsMissing(r.code)) ? "error" : "none" };
}
async function collectDnsRecords(domain) {
  const [a, aaaa, cname, mx, ns, caa, soa, txtR] = await Promise.all([
    dq("resolve4", domain), dq("resolve6", domain), dq("resolveCname", domain), dq("resolveMx", domain),
    dq("resolveNs", domain), dq("resolveCaa", domain), dq("resolveSoa", domain), resolveTxtRobust(domain)
  ]);
  let ds = [];
  const dsData = await dohQuery(domain, "DS"); if (dsData?.Answer?.length) ds = dsData.Answer.filter(x => x.type === 43).map(x => x.data);
  const soaVal = Array.isArray(soa.data) ? null : (soa.data && soa.data.nsname ? soa.data : null);
  const codes = [a, aaaa, cname, mx, ns].map(x => x.code);
  let resolverBroken = false;
  if (!a.data.length && !aaaa.data.length && !ns.data.length && !cname.data.length) {
    // Kontrol sorgusu: çözücünün kendisi bozuksa "alan adı yok" denmesin
    const ctl = await dq("resolve4", "cloudflare.com"); const ctl2 = ctl.data.length ? ctl : await dohQuery("cloudflare.com", "A");
    resolverBroken = !(ctl.data.length || (ctl2 && ctl2.Answer && ctl2.Answer.length));
  }
  return {
    a: a.data, aaaa: aaaa.data, cname: cname.data, mx: (mx.data || []).sort((x, y) => x.priority - y.priority), ns: (ns.data || []).map(x => x.toLowerCase()).sort(),
    txt: txtR.records, txtState: txtR.state, caa: caa.data || [], soa: soaVal, ds,
    nxdomain: !resolverBroken && codes.includes("ENOTFOUND") && !a.data.length && !aaaa.data.length && !ns.data.length,
    allFailed: resolverBroken || codes.every(c => c && !dnsMissing(c))
  };
}
async function resolveIps(host) {
  if (net.isIPv4(host)) return { v4: [host], v6: [] };
  if (net.isIPv6(host)) return { v4: [], v6: [host] };
  const [v4, v6] = await Promise.all([dq("resolve4", host), dq("resolve6", host)]);
  let a4 = v4.data, a6 = v6.data;
  if (!a4.length && !a6.length) { try { const l = await dns.lookup(host, { all: true }); a4 = l.filter(x => x.family === 4).map(x => x.address); a6 = l.filter(x => x.family === 6).map(x => x.address); } catch {} }
  return { v4: a4, v6: a6, code: v4.code };
}

// ---------- Yardımcı: bulgu sınıflandırma / skor ----------
const CRITICAL_HINTS = ["_down", "_unreachable", "_expired", "_error", "_exposed", "_risk", "_invalid", "_failed", "_publicly", "_blacklisted", "_not_resolving", "_untrusted", "_takeover"];
const WARNING_HINTS = ["_missing", "_not_configured", "_expiring_soon", "_approaching", "_stale", "_pending", "_incomplete", "_unknown", "_passive", "_open", "_none", "_monitoring_only"];
function classifyFinding(f) {
  const s = String(f);
  if (/_critical$/.test(s)) return "critical"; if (/_warning$/.test(s)) return "warning"; if (/_info$/.test(s)) return "info";
  const lower = s.toLowerCase();
  if (CRITICAL_HINTS.some(h => lower.includes(h))) return "critical";
  if (WARNING_HINTS.some(h => lower.includes(h))) return "warning";
  return "ok";
}
function computeHealth(findings = []) {
  let c = 0, w = 0; for (const f of findings) { const k = classifyFinding(f); if (k === "critical") c++; else if (k === "warning") w++; }
  const score = clamp(100 - Math.min(c, 2) * 40 - Math.min(w, 4) * 15);
  return { healthScore: score, healthLevel: score >= 80 ? "YEŞİL" : score >= 50 ? "SARI" : "KIRMIZI" };
}
function computeConfidence(findings = [], hadError = false) {
  let conf = 100; if (hadError) conf -= 20;
  conf -= Math.min(findings.filter(f => /unknown|unreliable|unavailable|limited/.test(String(f))).length * 5, 20);
  return clamp(conf);
}
function defaultStatusFromHealth(level) { return level === "YEŞİL" ? "ACTIVE" : level === "SARI" ? "WARNING" : "CRITICAL"; }
const sevRank = (f) => ({ critical: 0, warning: 1, info: 2, ok: 3 }[classifyFinding(f)]);
const sortFindings = (arr) => [...new Set(arr)].sort((a, b) => sevRank(a) - sevRank(b));

// Ağırlıklı kontrol listesi: bilinmeyen (null) kontroller skoru ETKİLEMEZ
function makeChecker() {
  const items = [];
  const calc = (list) => { const t = list.reduce((s, i) => s + i.w, 0); return t ? Math.round(list.filter(i => i.pass).reduce((s, i) => s + i.w, 0) / t * 100) : null; };
  return {
    add(pass, w, finding, group) { if (pass === null || pass === undefined) return; items.push({ pass: !!pass, w, finding, group: group || "genel" }); },
    findings: () => items.filter(i => !i.pass && i.finding).map(i => i.finding),
    score: (group) => calc(group ? items.filter(i => i.group === group) : items),
    groups: () => [...new Set(items.map(i => i.group))],
    summary: () => ({ passed: items.filter(i => i.pass).length, total: items.length }),
    groupScores() { const o = {}; for (const g of this.groups()) o[g] = calc(items.filter(i => i.group === g)); return o; }
  };
}
function buildResult({ assetType, version, startedAt, target, findings, specific, score, status, errors = [], hint, confidence }) {
  const st = status || (score == null ? "UNKNOWN" : statusFromScore(score));
  const fl = sortFindings(findings || []);
  const commonAnalysis = { analyzerVersion: version, executionTimeMs: Date.now() - startedAt, findings: fl, scannedAt: new Date().toISOString(), score, status: st, target };
  const scores = { ...(specific.scores || {}) }; if (score != null) scores.overall = score;
  const out = { data: { assetType, commonAnalysis, specificAnalysis: { ...specific, scores }, analysisMeta: { scannerVersion: version, analyzer: assetType.toLowerCase() } }, findings: fl, errors, statusHint: hint || st };
  if (confidence != null) out.confidence = confidence;
  return out;
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
// Erişim hatasının nedenini bulguya çevirir (DNS mi, TLS mi, zaman aşımı mı?)
function netErrorFinding(prefix, main) {
  const k = main.errorInfo?.kind;
  if (main.redirectLoop) return `finding_${prefix}_redirect_loop_critical`;
  return ({ dns: `finding_${prefix}_dns_failure_critical`, refused: `finding_${prefix}_connection_refused_critical`, timeout: `finding_${prefix}_timeout_critical`,
    tls: `finding_${prefix}_tls_failure_critical`, reset: `finding_${prefix}_connection_reset_critical`, unreachable: `finding_${prefix}_network_unreachable_critical`,
    private: `finding_${prefix}_private_target_critical` })[k] || `finding_${prefix}_unreachable_critical`;
}
function downResult(assetType, version, startedAt, target, main, code) {
  return buildResult({ assetType, version, startedAt, target, findings: [code], score: 0, status: "DOWN",
    specific: { url: target, status: main.status, error: main.error || null, errorKind: main.errorInfo?.kind || null, errorCode: main.errorInfo?.code || null } });
}

// =====================================================================
// DOMAIN / E-POSTA ANALİZ YARDIMCILARI
// =====================================================================
function findSpfRecords(records) { return normalizeTxtRecords(records).filter(r => /^v=spf1(?:\s|$)/i.test(r)); }
function findDmarcRecords(records) { return normalizeTxtRecords(records).filter(r => /^v=dmarc1(?:\s*;|\s|$)/i.test(r)); }
function parseTags(rec) {
  const o = {}; String(rec || "").split(";").forEach(p => { const i = p.indexOf("="); if (i > 0) o[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim(); });
  return o;
}
function detectDnsProvider(nsRecords) {
  if (!nsRecords?.length) return null; const j = nsRecords.join(",").toLowerCase();
  const map = [["cloudflare", "Cloudflare"], ["googledomains", "Google Domains"], ["google", "Google Cloud DNS"], ["awsdns", "AWS Route53"], ["azure-dns", "Azure DNS"], ["godaddy", "GoDaddy"], ["domaincontrol", "GoDaddy"],
    ["natro", "Natro"], ["turhost", "Turhost"], ["hostinger", "Hostinger"], ["digitalocean", "DigitalOcean"], ["namecheap", "Namecheap"], ["registrar-servers", "Namecheap"], ["dnsimple", "DNSimple"],
    ["nsone", "NS1"], ["ultradns", "UltraDNS"], ["dynect", "Dyn"], ["hetzner", "Hetzner"], ["ovh", "OVH"], ["gandi", "Gandi"], ["name.com", "Name.com"], ["wixdns", "Wix"], ["squarespace", "Squarespace"], ["vercel-dns", "Vercel"], ["netlify", "Netlify"], ["linode", "Linode"], ["yandex", "Yandex"], ["isimtescil", "İsimtescil"], ["metunic", "METUnic"], ["nic.tr", "TRABIS (nic.tr)"]];
  for (const [k, v] of map) if (j.includes(k)) return v;
  return nsRecords[0] || "unknown";
}
function detectMailProvider(mx) {
  const j = (mx || []).map(m => String(m.exchange || m).toLowerCase()).join(",");
  const map = [["google.com", "Google Workspace", ["google", "20230601", "20221208"]], ["googlemail.com", "Google Workspace", ["google"]], ["outlook.com", "Microsoft 365", ["selector1", "selector2"]], ["protection.outlook", "Microsoft 365", ["selector1", "selector2"]],
    ["zoho.", "Zoho Mail", ["zoho", "zmail", "default"]], ["yandex", "Yandex Mail", ["mail", "yandex"]], ["protonmail", "Proton Mail", ["protonmail", "protonmail2", "protonmail3"]], ["mailgun", "Mailgun", ["k1", "mailo", "krs", "smtp", "mg"]],
    ["pphosted", "Proofpoint", ["default"]], ["mimecast", "Mimecast", ["default"]], ["secureserver.net", "GoDaddy Mail", ["default"]], ["hostinger", "Hostinger Mail", ["hostingermail-a", "hostingermail-b", "hostingermail-c", "default"]],
    ["registrar-servers", "Namecheap Mail", ["default", "privateemail"]], ["improvmx", "ImprovMX", ["dkim", "default"]], ["icloud", "iCloud Mail", ["sig1"]], ["fastmail", "Fastmail", ["fm1", "fm2", "fm3"]], ["mailchannels", "MailChannels", ["mailchannels"]]];
  for (const [k, name, sel] of map) if (j.includes(k)) return { provider: name, selectors: sel };
  return { provider: j ? "Özel / diğer" : null, selectors: [] };
}

// ---------- SPF derin analiz (10 DNS lookup limiti, all mekanizması, çoklu kayıt) ----------
async function analyzeSpf(domain, txtRecords) {
  const spfs = findSpfRecords(txtRecords); const res = { record: spfs[0] || null, count: spfs.length, lookups: 0, all: null, issues: [], includes: [], ptr: false, brokenIncludes: [], tooManyLookups: false, strength: null };
  if (!spfs.length) return res;
  const visited = new Set([domain]); let fetches = 0;
  async function walk(rec, d, depth) {
    const terms = rec.trim().split(/\s+/).slice(1);
    for (const raw of terms) {
      const m = raw.match(/^([+\-~?])?([a-z0-9]+)(?:[:=](.+))?$/i); if (!m) continue;
      const q = m[1] || "+"; const mech = m[2].toLowerCase(); const arg = m[3];
      if (mech === "all") { if (depth === 0) res.all = q + "all"; continue; }
      if (["include", "a", "mx", "ptr", "exists", "redirect"].includes(mech)) res.lookups++;
      if (mech === "ptr") res.ptr = true;
      if ((mech === "include" || mech === "redirect") && arg) {
        const tgt = arg.toLowerCase(); if (depth === 0) res.includes.push(tgt);
        if (visited.has(tgt) || depth >= 6 || fetches >= 14) continue; visited.add(tgt); fetches++;
        const r = await resolveTxtRobust(tgt); const sub = findSpfRecords(r.records)[0];
        if (!sub) { if (r.state === "none") res.brokenIncludes.push(tgt); continue; }
        if (mech === "redirect" && depth === 0 && !res.all) { const mm = sub.match(/\s([+\-~?])all\b/i); if (mm) res.all = mm[1] + "all"; }
        await walk(sub, tgt, depth + 1);
      }
    }
  }
  try { await withTimeout(walk(spfs[0], domain, 0), 9000, "SPF"); } catch {}
  res.tooManyLookups = res.lookups > 10;
  res.strength = res.all === "-all" ? "strict" : res.all === "~all" ? "soft" : res.all === "?all" ? "neutral" : res.all === "+all" ? "open" : (res.record && /redirect=/i.test(res.record) ? "redirect" : "none");
  return res;
}

// ---------- DKIM ----------
const DKIM_BASE = ["default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "smtp", "email", "mandrill", "sendgrid", "zoho", "zmail", "mailo", "krs",
  "mxvault", "everlytickey1", "everlytickey2", "eversrv", "protonmail", "protonmail2", "protonmail3", "dkim1", "dkim2", "key1", "key2", "mta", "mailjet", "cm", "pm", "smtpapi", "mg", "selector", "x", "mimecast20190104", "scph0123", "turbo-smtp", "hostingermail-a", "hostingermail-b", "hostingermail-c", "fm1", "fm2", "fm3"];
function dkimKeyInfo(rec) {
  const t = parseTags(rec); const p = (t.p || "").replace(/\s+/g, "");
  const info = { keyType: (t.k || "rsa").toLowerCase(), revoked: t.p !== undefined && p === "", testMode: /(^|:)y(:|$)/.test(t.t || ""), bits: null };
  if (p && info.keyType === "rsa") { try { const k = crypto.createPublicKey({ key: Buffer.from(p, "base64"), format: "der", type: "spki" }); info.bits = k.asymmetricKeyDetails?.modulusLength || null; } catch {} }
  return info;
}
async function discoverDkim(domain, extraSelectors) {
  const sels = [...new Set([...(extraSelectors || []), ...DKIM_BASE])]; const found = [];
  await pool(sels, 10, async (s) => {
    const r = await dq("resolveTxt", `${s}._domainkey.${domain}`); if (!r.data.length) return;
    const txt = normalizeTxtRecords(r.data).join(""); if (!/v=dkim1|k=rsa|k=ed25519|;\s*p=|^p=/i.test(txt)) return;
    found.push({ selector: s, record: txt.slice(0, 200), ...dkimKeyInfo(txt) });
  });
  found.sort((a, b) => DKIM_BASE.indexOf(a.selector) - DKIM_BASE.indexOf(b.selector));
  return found;
}

// ---------- MTA-STS / TLS-RPT / BIMI ----------
async function checkMailPolicies(domain) {
  const out = { mtaSts: { present: false, mode: null, maxAge: null, policyReachable: null }, tlsRpt: false, bimi: false };
  const [sts, rpt, bimi] = await Promise.all([dq("resolveTxt", `_mta-sts.${domain}`), dq("resolveTxt", `_smtp._tls.${domain}`), dq("resolveTxt", `default._bimi.${domain}`)]);
  out.mtaSts.present = normalizeTxtRecords(sts.data).some(r => /^v=STSv1/i.test(r));
  out.tlsRpt = normalizeTxtRecords(rpt.data).some(r => /^v=TLSRPTv1/i.test(r));
  out.bimi = normalizeTxtRecords(bimi.data).some(r => /^v=BIMI1/i.test(r));
  if (out.mtaSts.present) {
    const r = await request(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { timeout: 6000 });
    out.mtaSts.policyReachable = r.status === 200 && /version:\s*STSv1/i.test(r.body || "");
    if (out.mtaSts.policyReachable) { out.mtaSts.mode = ((r.body.match(/mode:\s*(\w+)/i) || [])[1] || "").toLowerCase() || null; out.mtaSts.maxAge = parseInt((r.body.match(/max_age:\s*(\d+)/i) || [])[1] || "0", 10) || null; }
  }
  return out;
}

// ---------- DNSSEC ----------
async function checkDnssec(domain, dsRecords) {
  const hasDs = !!(dsRecords && dsRecords.length);
  const [validated, dnskey] = await Promise.all([dohQuery(domain, "A", "&do=true"), dohQuery(domain, "DNSKEY")]);
  const hasKey = !!(dnskey?.Answer || []).some(a => a.type === 48);
  if (hasDs) {
    if (validated && validated.Status === 2) return { enabled: false, status: "BROKEN", method: "DS_BUT_VALIDATION_FAILS" };
    return { enabled: true, status: STATUS.VALID, method: validated?.AD === true ? "DS_AND_AD" : "DS_FOUND" };
  }
  if (hasKey) return { enabled: false, status: STATUS.INACTIVE, method: "DNSKEY_WITHOUT_DS" };
  if (!validated && !dnskey) return { enabled: false, status: STATUS.UNKNOWN, method: "DOH_UNAVAILABLE" };
  return { enabled: false, status: STATUS.INACTIVE, method: "NO_DS_NO_DNSKEY" };
}

// ---------- Nameserver sağlığı ----------
async function checkNameservers(domain, nsList) {
  const list = nsList.slice(0, 6);
  const rows = await pool(list, 4, async (ns) => {
    const ips = (await dq("resolve4", ns)).data; if (!ips.length) return { ns, ip: null, responds: false, reason: "NS adresi çözülemedi" };
    const r = new dns.Resolver({ timeout: 2500, tries: 1 }); r.setServers([ips[0]]);
    const t0 = Date.now(); const soa = await dq("resolveSoa", domain, r);
    const ok = !!(soa.data && soa.data.nsname);
    return { ns, ip: ips[0], responds: ok, serial: ok ? soa.data.serial : null, ms: Date.now() - t0, reason: ok ? null : (soa.code || "yanıt yok") };
  });
  const res = rows.filter(Boolean); const responding = res.filter(r => r.responds);
  const serials = [...new Set(responding.map(r => r.serial))];
  const nets = res.filter(r => r.ip).map(r => r.ip.split(".").slice(0, 3).join("."));
  return { servers: res, respondingCount: responding.length, inconclusive: responding.length === 0, serialMismatch: serials.length > 1, serials,
    sameNetwork: res.filter(r => r.ip).length >= 2 && new Set(nets).size === 1 };
}

// ---------- RDAP (IANA bootstrap) ----------
let rdapBoot = { at: 0, map: null };
async function rdapBases(domain) {
  if (!rdapBoot.map || Date.now() - rdapBoot.at > 864e5) {
    try {
      const r = await axios.get("https://data.iana.org/rdap/dns.json", { timeout: 7000, proxy: false });
      const map = new Map(); for (const [tlds, urls] of (r.data.services || [])) for (const t of tlds) map.set(String(t).toLowerCase(), urls);
      rdapBoot = { at: Date.now(), map, ok: true };
    } catch { if (!rdapBoot.map) rdapBoot = { at: Date.now() - 864e5 + 60000, map: new Map(), ok: false }; }
  }
  const tld = domain.split(".").pop();
  return (rdapBoot.map.get(tld) || []).map(u => u.replace(/\/$/, ""));
}
async function fetchRdap(domain, errors) {
  const bases = await rdapBases(domain); const tld = domain.split(".").pop();
  const urls = bases.map(b => `${b}/domain/${domain}`);
  if (!bases.length) { if (["com", "net"].includes(tld)) urls.push(`https://rdap.verisign.com/${tld}/v1/domain/${domain}`); }
  urls.push(`https://rdap.org/domain/${domain}`);
  let notFound = false;
  for (const url of [...new Set(urls)]) {
    try {
      const res = await axios.get(url, { timeout: 8000, validateStatus: () => true, proxy: false, maxRedirects: 4, headers: { Accept: "application/rdap+json, application/json", "User-Agent": UA_BROWSER } });
      if (res.status === 200 && res.data && !res.data.errorCode) return { data: res.data, source: url, noRdap: false };
      if (res.status === 404) { notFound = true; errors.push(`RDAP ${url} status:404`); continue; }
      errors.push(`RDAP ${url} status:${res.status}`);
    } catch (e) { errors.push(`RDAP ${url} error:${e.message}`); }
  }
  return { data: null, source: null, noRdap: !bases.length && rdapBoot.ok === true, notFound };
}
function extractRegistrar(data) {
  if (!data) return null;
  if (typeof data.registrar === "string") return data.registrar;
  if (data.registrar && typeof data.registrar === "object") return String(data.registrar.name || data.registrar.organization || "") || null;
  const ent = (Array.isArray(data.entities) ? data.entities : []).find(e => Array.isArray(e.roles) && e.roles.some(r => String(r).toLowerCase() === "registrar"));
  if (!ent) return null;
  try {
    const v = ent.vcardArray?.[1];
    if (Array.isArray(v)) {
      const fn = v.find(x => x?.[0] === "fn"); if (fn?.[3]) return typeof fn[3] === "string" ? fn[3] : (fn[3].text || (Array.isArray(fn[3]) ? fn[3].join(" ") : null));
      const org = v.find(x => x?.[0] === "org"); if (org?.[3]) return Array.isArray(org[3]) ? org[3].join(" ") : String(org[3]);
    }
  } catch {}
  return ent.name || ent.organization || (ent.publicIds && ent.publicIds[0]?.identifier ? `IANA #${ent.publicIds[0].identifier}` : null) || ent.handle || null;
}
function rdapDate(data, actions) {
  if (!Array.isArray(data?.events)) return null;
  const set = actions.map(a => a.toLowerCase());
  const ev = data.events.find(e => set.includes(String(e.eventAction || "").toLowerCase().trim()));
  return ev?.eventDate || null;
}
const rdapStatuses = (data) => Array.isArray(data?.status) ? data.status.map(s => typeof s === "string" ? s : (s?.status || String(s))).filter(Boolean) : [];
const normStatus = (s) => String(s).toLowerCase().replace(/[\s_-]/g, "");
// Transfer kilidi anlamlı olan (EPP) uzantılar
const LOCKABLE_TLDS = new Set(["com", "net", "org", "info", "biz", "io", "co", "app", "dev", "online", "store", "tech", "ai", "xyz", "site", "me", "us", "mobi", "tv", "cc", "club", "shop"]);

// ---------- v13.5: tarih ayrıştırma, WHOIS yedeği, bitiş profili ----------
const EXPIRY_ACTIONS = ["expiration", "expiry", "expiration date", "registrar expiration", "registry expiry date", "expires", "expire", "expiry date"];
// Bitiş tarihini herkese açık yayınlamayan uzantılar (RDAP ve WHOIS'te de yoktur; yalnızca kayıt kuruluşu panelinde görünür)
const NO_PUBLIC_EXPIRY = new Set(["de", "nl", "eu", "ch", "li", "at", "be"]);
const MON3 = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
function parseLooseDate(input) {
  if (input == null) return null;
  if (input instanceof Date) return Number.isNaN(input.getTime()) ? null : input;
  let s = String(input).trim().replace(/\s*\(.*?\)\s*$/, "").replace(/[.\s]+$/, "").replace(/\s+(UTC|GMT)$/i, "");
  if (!s) return null;
  const mk = (y, mo, d, hh, mi, ss) => { const dt = new Date(Date.UTC(+y, +mo, +d, +(hh || 0), +(mi || 0), +(ss || 0))); return dt.getUTCFullYear() === +y && dt.getUTCMonth() === +mo && dt.getUTCDate() === +d ? dt : null; };
  let m;
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) { const t = Date.parse(s); return Number.isFinite(t) ? new Date(t) : null; }
  if ((m = s.match(/^(\d{4})-([A-Za-z]{3})[a-z]*-(\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/))) { const mo = MON3[m[2].toLowerCase()]; return mo == null ? null : mk(m[1], mo, m[3], m[4], m[5], m[6]); }
  if ((m = s.match(/^(\d{1,2})[-\s]([A-Za-z]{3})[a-z]*[-\s](\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/))) { const mo = MON3[m[2].toLowerCase()]; return mo == null ? null : mk(m[3], mo, m[1], m[4], m[5], m[6]); }
  if ((m = s.match(/^([A-Za-z]{3})[a-z]*\.?\s+(\d{1,2}),?\s+(\d{4})/))) { const mo = MON3[m[1].toLowerCase()]; return mo == null ? null : mk(m[3], mo, m[2]); }
  if ((m = s.match(/^(\d{4})[./-](\d{1,2})[./-](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/))) return mk(m[1], +m[2] - 1, m[3], m[4], m[5], m[6]);
  if ((m = s.match(/^(\d{1,2})[./-](\d{1,2})[./-](\d{4})/))) return mk(m[3], +m[2] - 1, m[1]);
  if ((m = s.match(/^(\d{4})(\d{2})(\d{2})$/))) return mk(m[1], +m[2] - 1, m[3]);
  const t = Date.parse(s); return Number.isFinite(t) ? new Date(t) : null;
}
// WHOIS metnini ayrıştırır (Verisign/ICANN, nic.tr, Nominet, JPRS vb. biçimleri). Uydurma yok: bulunamayan alan null kalır.
function parseWhois(textIn) {
  const text = String(textIn || "").slice(0, 200000); const lines = text.split(/\r?\n/);
  const out = { expiry: null, created: null, updated: null, registrar: null, statuses: [], nameservers: [], notFound: false };
  const pick = (labels) => { for (const l of lines) { const m = l.match(new RegExp("^\\s*(?:" + labels + ")\\b[.\\s]*:\\s*(.+?)\\s*$", "i")); if (m && m[1] && !/^(n\/a|-|none|not disclosed|redacted.*)$/i.test(m[1])) { const d = parseLooseDate(m[1]); if (d) return d; } } return null; };
  out.expiry = pick("Registry Expiry Date") || pick("Registrar Registration Expiration Date|Expiration Date|Expiry Date|Expires On|Expires|Expire Date|Expire|Renewal Date|paid-till|Expiration Time|Domain Expiration Date|Valid Until");
  out.created = pick("Creation Date|Created On|Created|Registered On|Registered|Registration Time|Domain Registration Date");
  out.updated = pick("Updated Date|Last Updated|Last Modified|Last Update|Modified|Changed");
  const txt = (labels) => { for (const l of lines) { const m = l.match(new RegExp("^\\s*(?:" + labels + ")\\b[.\\s]*:\\s*(.+?)\\s*$", "i")); if (m && m[1] && m[1].trim()) return m[1].trim(); } return null; };
  out.registrar = txt("Sponsoring Registrar|Registrar Name|Registrar");
  if (!out.registrar) { const i = lines.findIndex(l => /^\s*\*\*\s*Registrar/i.test(l)); if (i >= 0) { for (let k = i + 1; k < Math.min(lines.length, i + 12); k++) { const m = lines[k].match(/Organization Name\s*:\s*(.+?)\s*$/i); if (m) { out.registrar = m[1]; break; } if (/^\s*\*\*/.test(lines[k])) break; } } }
  for (const l of lines) { const m = l.match(/^\s*(?:Domain Status|Status|state)\s*:\s*([A-Za-z][A-Za-z -]*[A-Za-z])(?:\s+https?:\S+)?\s*$/i); if (m && !/^(active|ok|registered)$/i.test(m[1].trim()) ) out.statuses.push(m[1].replace(/\s+/g, "")); else if (m) out.statuses.push(m[1].trim()); }
  out.statuses = [...new Set(out.statuses)].slice(0, 12);
  const ns = new Set();
  for (const l of lines) { const m = l.match(/^\s*(?:Name Server|Nameserver|nserver|Name servers?)\s*:\s*([A-Za-z0-9._-]+\.[A-Za-z]{2,})/i); if (m) ns.add(m[1].toLowerCase().replace(/\.$/, "")); }
  const di = lines.findIndex(l => /^\s*\*\*\s*Domain Servers/i.test(l));
  if (di >= 0) for (let k = di + 1; k < Math.min(lines.length, di + 12); k++) { const v = lines[k].trim(); if (!v) { if (ns.size) break; continue; } if (/^\*\*/.test(v)) break; const m = v.match(/^([A-Za-z0-9._-]+\.[A-Za-z]{2,})\b/); if (m) ns.add(m[1].toLowerCase()); }
  out.nameservers = [...ns].slice(0, 13);
  if (!out.expiry && !out.created && !out.registrar && /(^|\n)\s*%?\s*(No match for|NOT FOUND|No Data Found|Domain not found|No entries found|No match|Status:\s*(AVAILABLE|free)\b|.*is available for registration|The queried object does not exist)/i.test(text)) out.notFound = true;
  return out;
}
const WHOIS_OVERRIDE = { tr: "whois.nic.tr", com: "whois.verisign-grs.com", net: "whois.verisign-grs.com", org: "whois.pir.org", io: "whois.nic.io", ai: "whois.nic.ai", co: "whois.nic.co", uk: "whois.nic.uk", info: "whois.afilias.net", biz: "whois.nic.biz", me: "whois.nic.me", app: "whois.nic.google", dev: "whois.nic.google", xyz: "whois.nic.xyz", online: "whois.nic.online" };
const whoisSrvCache = new Map();
function whoisQuery(server, query, timeout = 9000, maxBytes = 120000, port = 43) {
  return new Promise((resolve, reject) => {
    if (!/^[a-z0-9][a-z0-9.-]{2,252}$/i.test(String(server)) || blockedHost(server)) return reject(new Error("WHOIS sunucusu geçersiz"));
    let buf = "", done = false; const sock = new net.Socket(); let timer;
    const fin = (err) => { if (done) return; done = true; clearTimeout(timer); sock.destroy(); if (err && !buf) reject(err); else resolve(buf); };
    timer = setTimeout(() => fin(buf ? null : new Error("WHOIS zaman aşımı")), timeout);
    sock.on("data", d => { buf += d.toString("utf8"); if (buf.length > maxBytes) fin(null); });
    sock.on("error", fin); sock.on("end", () => fin(null)); sock.on("close", () => fin(null));
    sock.connect({ port, host: server, lookup: safeLookup }, () => sock.write(String(query).replace(/[\r\n]/g, "") + "\r\n"));
  });
}
async function whoisServerFor(tld) {
  if (WHOIS_OVERRIDE[tld]) return WHOIS_OVERRIDE[tld];
  const hit = whoisSrvCache.get(tld); if (hit && Date.now() - hit.at < 864e5) return hit.server;
  let server = null;
  try { const r = await whoisQuery("whois.iana.org", tld, 7000, 30000); const m = r.match(/^\s*whois:\s*([a-z0-9.-]+)\s*$/im); server = m ? m[1].toLowerCase() : null; } catch { /* IANA yanıt vermedi */ }
  if (whoisSrvCache.size > 300) whoisSrvCache.clear(); whoisSrvCache.set(tld, { at: Date.now(), server }); return server;
}
async function fetchWhois(domain, errors) {
  const tld = domain.split(".").pop();
  try {
    const server = await whoisServerFor(tld);
    if (!server) { errors.push(`WHOIS sunucusu bulunamadı (.${tld})`); return null; }
    const p = parseWhois(await whoisQuery(server, domain)); p.server = server;
    if (!p.expiry && !p.notFound) errors.push(`WHOIS ${server}: bitiş tarihi bulunamadı`);
    return p;
  } catch (e) { errors.push("WHOIS hata: " + e.message); return null; }
}
// İnce kayıt defterleri (ör. .com) bitişi vermezse kayıt kuruluşunun RDAP'ı (links.related) izlenir
async function followRelatedRdap(data, errors) {
  const link = (Array.isArray(data && data.links) ? data.links : []).find(l => String(l && l.rel).toLowerCase() === "related" && /rdap/i.test(String(l.type || l.href || "")) && /^https:\/\//i.test(String(l.href || "")));
  if (!link) return data;
  try {
    const r = await request(link.href, { timeout: 8000, headers: { Accept: "application/rdap+json, application/json" }, maxBytes: 600000 });
    if (r.status !== 200) { errors.push(`RDAP related status:${r.status}`); return data; }
    const j = JSON.parse(r.body); if (!j || typeof j !== "object" || !Array.isArray(j.events)) return data;
    return { ...data, events: [...(data.events || []), ...j.events], status: [...new Set([...(Array.isArray(data.status) ? data.status : []), ...(Array.isArray(j.status) ? j.status : [])])], nameservers: (data.nameservers && data.nameservers.length) ? data.nameservers : j.nameservers, entities: (data.entities && data.entities.length) ? data.entities : j.entities };
  } catch (e) { errors.push("RDAP related hata: " + e.message); return data; }
}
async function fetchRegistration(domain, errors) {
  let rdap; try { rdap = await fetchRdap(domain, errors); } catch (e) { errors.push("RDAP hata: " + e.message); rdap = { data: null, noRdap: false }; }
  const hasExp = (d) => !!(d && toDateOrNull(rdapDate(d, EXPIRY_ACTIONS)));
  if (rdap.data && !hasExp(rdap.data)) rdap = { ...rdap, data: await followRelatedRdap(rdap.data, errors) };
  if (!hasExp(rdap.data)) { const w = await withTimeout(fetchWhois(domain, errors), 16000, "WHOIS").catch(() => null); if (w) rdap = { ...rdap, whois: w }; }
  return rdap;
}
// Bitiş durumu + yaşam döngüsü (kalan güne ve EPP durum kodlarına göre)
function expiryProfile(days, statuses) {
  const st = (statuses || []).map(normStatus); let phase = "ACTIVE";
  if (st.some(x => /pendingdelete/.test(x))) phase = "PENDING_DELETE"; else if (st.some(x => /redemption/.test(x))) phase = "REDEMPTION";
  else if (st.some(x => /autorenewperiod|renewperiod/.test(x))) phase = "GRACE"; else if (st.some(x => /serverhold|clienthold/.test(x))) phase = "ON_HOLD";
  const state = days == null ? "UNKNOWN" : days < 0 ? "EXPIRED" : days <= 7 ? "CRITICAL" : days <= 14 ? "URGENT" : days <= 30 ? "SOON" : days <= 60 ? "WATCH" : "OK";
  return { state, phase };
}
const isoDay = (d) => d.toISOString().slice(0, 10);

// ---------- Subdomain keşfi + dangling CNAME / takeover ----------
const TAKEOVER_SIGS = [
  { p: "github.io", body: /There isn't a GitHub Pages site here/i }, { p: "herokuapp.com", body: /no such app|herokucdn\.com\/error-pages/i }, { p: "herokudns.com", body: /no such app/i },
  { p: "s3.amazonaws.com", body: /NoSuchBucket|specified bucket does not exist/i }, { p: "s3-website", body: /NoSuchBucket|specified bucket does not exist/i },
  { p: "azurewebsites.net", nx: true }, { p: "cloudapp.azure.com", nx: true }, { p: "trafficmanager.net", nx: true }, { p: "blob.core.windows.net", nx: true }, { p: "azureedge.net", nx: true },
  { p: "elasticbeanstalk.com", nx: true }, { p: "myshopify.com", body: /Sorry, this shop is currently unavailable|Only one step left/i }, { p: "ghost.io", body: /The thing you were looking for is no longer here/i },
  { p: "netlify.app", body: /Not Found - Request ID/i }, { p: "vercel.app", body: /DEPLOYMENT_NOT_FOUND|deployment could not be found/i }, { p: "pages.dev", body: /There is nothing here yet/i },
  { p: "unbouncepages.com", body: /requested URL was not found on this server/i }, { p: "surge.sh", body: /project not found/i }, { p: "bitbucket.io", body: /Repository not found/i },
  { p: "zendesk.com", body: /Help Center Closed|this help center no longer exists/i }, { p: "readme.io", body: /Project doesnt exist/i }, { p: "fastly.net", body: /Fastly error: unknown domain/i },
  { p: "tumblr.com", body: /Whatever you were looking for doesn't currently exist/i }, { p: "helpscoutdocs.com", body: /No settings were found for this company/i }, { p: "cargocollective.com", body: /404 Not Found/i },
  { p: "wordpress.com", body: /Do you want to register/i }, { p: "statuspage.io", body: /Page not found|status page is not available/i }, { p: "webflow.io", body: /The page you are looking for doesn't exist or has been moved/i }
];
const COMMON_SUBS = ["www", "mail", "blog", "shop", "store", "app", "api", "dev", "staging", "test", "cdn", "docs", "status", "support", "help", "portal", "admin", "m", "git", "static", "assets", "img", "media", "beta", "demo", "old", "web", "crm", "panel", "login", "go"];
async function ctSubdomains(domain) {
  try {
    const r = await axios.get(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 8000, proxy: false, validateStatus: () => true });
    if (r.status !== 200 || !Array.isArray(r.data)) return { ok: false, names: [] };
    const set = new Set();
    for (const row of r.data.slice(0, 5000)) for (const n of String(row.name_value || "").split(/\s+/)) { const h = n.toLowerCase().replace(/^\*\./, ""); if (h.endsWith("." + domain) && !h.includes("*") && /^[a-z0-9.-]+$/.test(h)) set.add(h); }
    return { ok: true, names: [...set].slice(0, 300) };
  } catch { return { ok: false, names: [] }; }
}
async function checkTakeover(domain, ctNames) {
  const hosts = [...new Set([domain, ...COMMON_SUBS.map(s => `${s}.${domain}`), ...ctNames])].slice(0, 90);
  const found = [];
  await pool(hosts, 12, async (h) => {
    const c = await dq("resolveCname", h); if (!c.data.length) return;
    const target = String(c.data[0]).toLowerCase().replace(/\.$/, "");
    const [a4, a6] = await Promise.all([dq("resolve4", target), dq("resolve6", target)]);
    const resolves = a4.data.length + a6.data.length > 0; const dead = !resolves && (a4.code === "ENOTFOUND");
    const sig = TAKEOVER_SIGS.find(s => target.includes(s.p));
    const row = { host: h, cname: target, provider: sig ? sig.p : null, resolves, dangling: dead, takeover: false, evidence: null };
    if (sig && dead) { row.takeover = true; row.evidence = "CNAME hedefi artık mevcut değil"; }
    else if (sig && resolves && sig.body) {
      const r = await request(`https://${h}/`, { timeout: 6000, maxBytes: 60000, insecure: true }); const r2 = r.status ? r : await request(`http://${h}/`, { timeout: 6000, maxBytes: 60000 });
      if (r2.body && sig.body.test(r2.body)) { row.takeover = true; row.evidence = "Sağlayıcı 'sahipsiz' hata sayfası döndürüyor"; }
    }
    found.push(row);
  });
  return found;
}

// ---------- DNSBL (kara liste) ----------
const DNSBLS = [["zen.spamhaus.org", "Spamhaus ZEN", true], ["bl.spamcop.net", "SpamCop"], ["psbl.surriel.com", "PSBL"], ["dnsbl-1.uceprotect.net", "UCEProtect-1"], ["all.s5h.net", "s5h.net"], ["dnsbl.dronebl.org", "DroneBL"]];
async function checkDnsbl(ips) {
  const list = [...new Set(ips.filter(net.isIPv4))].slice(0, 4); const hits = []; let answered = 0, queries = 0;
  await pool(list.flatMap(ip => DNSBLS.map(z => [ip, z])), 8, async ([ip, [zone, name, strong]]) => {
    queries++; const rev = ip.split(".").reverse().join(".");
    const r = await dq("resolve4", `${rev}.${zone}`);
    if (r.data.length) { const code = r.data[0]; if (/^127\.255\.255\./.test(code)) return; /* sorgu reddedildi */ answered++; hits.push({ ip, list: name, code, strong: !!strong }); }
    else if (r.code === "ENOTFOUND" || r.code === "ENODATA") answered++;
  });
  const status = !list.length ? "NOT_CHECKED" : answered === 0 ? "NOT_CHECKED" : hits.length ? "LISTED" : "CLEAN";
  return { status, hits, checkedIps: list, listsQueried: DNSBLS.length, answered, strongHit: hits.some(h => h.strong), multiHit: new Set(hits.map(h => h.list)).size >= 2 };
}

// =====================================================================
// 2. DOMAIN SCANNER v12
// =====================================================================
async function scanDomain(input, extra = {}) {
  const startedAt = Date.now(); const V = "domain-analyzer-v13.5"; const errors = [];
  const debug = { input, parsedDomain: null, txtRaw: null, dmarcRaw: null, rdapAttempts: [] };
  const inputHost = parseDomain(input);
  if (!inputHost) return { data: null, findings: ["finding_domain_invalid_critical"], errors: ["domain parse edilemedi"], debug };
  const domain = registrableDomain(inputHost); debug.parsedDomain = domain;
  const c = makeChecker(); const info = []; const findings = [];
  if (inputHost !== domain) info.push("finding_domain_scanned_root_info");

  // ---- DNS ----
  const dnsRecords = await collectDnsRecords(domain);
  const www = await Promise.all([dq("resolve4", `www.${domain}`), dq("resolveCname", `www.${domain}`)]);
  const wwwResolves = www[0].data.length > 0 || www[1].data.length > 0;
  debug.txtRaw = normalizeTxtRecords(dnsRecords.txt);
  const dnsProvider = detectDnsProvider(dnsRecords.ns);
  const hasAddress = dnsRecords.a.length > 0 || dnsRecords.aaaa.length > 0 || dnsRecords.cname.length > 0 || wwwResolves;
  const dnsUnknown = dnsRecords.allFailed;
  if (dnsUnknown) {
    // Çözücü yanıt vermiyorsa eksik kayıt/uyarı uydurma: sonucu "belirsiz" döndür
    return unavailableResult({ assetType: "DOMAIN", version: V, startedAt, target: domain, finding: "finding_domain_dns_unreliable_info", status: "UNKNOWN",
      note: "DNS sorguları yanıt vermedi (sunucunun ağ erişimi veya DNS sağlayıcısı geçici olarak sorunlu olabilir). Bir süre sonra yeniden tarayın.", specific: { domain, inputHost } });
  }
  c.add(hasAddress, 25, "finding_domain_not_resolving_critical", "dns");
  c.add(dnsRecords.ns.length > 0, 20, "finding_domain_missing_ns_critical", "dns");
  if (dnsRecords.ns.length === 1) c.add(false, 10, "finding_domain_single_ns_warning", "dns");
  else if (dnsRecords.ns.length > 1) c.add(true, 10, null, "dns");
  c.add(!!dnsRecords.soa, 5, null, "dns");
  const hasMx = dnsRecords.mx.length > 0 && !(dnsRecords.mx.length === 1 && /^\.?$/.test(String(dnsRecords.mx[0].exchange || "")));
  if (!hasMx) info.push("finding_domain_missing_mx_warning");
  const mailProv = detectMailProvider(dnsRecords.mx);

  // ---- Paralel ağır işler ----
  const errs2 = [];
  const ctPromise = withTimeout(ctSubdomains(domain), 8000, "CT").catch(() => ({ ok: false, names: [] }));
  const takePromise = ctPromise.then(ct => withTimeout(checkTakeover(domain, ct.names), 15000, "Takeover").catch(() => []));
  const blPromise = (async () => {
    const mxIps = []; await pool(dnsRecords.mx.slice(0, 3), 3, async (m) => { const r = await dq("resolve4", m.exchange); mxIps.push(...r.data.slice(0, 1)); });
    return withTimeout(checkDnsbl([...dnsRecords.a.slice(0, 2), ...mxIps]), 12000, "DNSBL").catch(() => ({ status: "NOT_CHECKED", hits: [], checkedIps: [] }));
  })();
  const [nsHealth, rdap, ctRes, mailPolicies, dnssecResult, spf, dmarcTxt, dkimFound, takeRows, bl] = await Promise.all([
    dnsRecords.ns.length ? withTimeout(checkNameservers(domain, dnsRecords.ns), 10000, "NS").catch(() => null) : null,
    withTimeout(fetchRegistration(domain, errs2), 40000, "RDAP/WHOIS").catch(() => ({ data: null, noRdap: false, timeout: true })),
    ctPromise,
    hasMx ? checkMailPolicies(domain).catch(() => null) : null,
    checkDnssec(domain, dnsRecords.ds).catch(() => ({ enabled: false, status: STATUS.UNKNOWN, method: "ERROR" })),
    analyzeSpf(domain, dnsRecords.txt),
    resolveTxtRobust(`_dmarc.${domain}`),
    hasMx ? withTimeout(discoverDkim(domain, mailProv.selectors), 12000, "DKIM").catch(() => []) : [],
    takePromise, blPromise
  ]);
  errors.push(...errs2); debug.rdapAttempts = errs2;

  // NS sağlığı
  if (nsHealth) {
    if (nsHealth.inconclusive) info.push("finding_domain_ns_check_inconclusive_info");
    else {
      const failing = nsHealth.servers.filter(s => !s.responds);
      c.add(failing.length === 0, 15, "finding_domain_ns_partial_failure_warning", "dns");
      c.add(!nsHealth.serialMismatch, 8, "finding_domain_ns_serial_mismatch_warning", "dns");
    }
    if (nsHealth.sameNetwork) c.add(false, 5, "finding_domain_ns_same_network_warning", "dns");
  }

  // ---- SPF ----
  let spfStatus;
  if (spf.record) {
    const valid = /^v=spf1\s+/i.test(spf.record) && /(?:include:|ip4:|ip6:|\ba\b|\bmx\b|[~\-?+]all|redirect=|exists:)/i.test(spf.record);
    spfStatus = valid ? STATUS.VALID : STATUS.INACTIVE;
    if (valid) findings.push("EMAIL_SPF_VALID");
    c.add(valid, 25, "finding_domain_invalid_spf_warning", "email");
    if (valid) {
      c.add(spf.count === 1, 8, "finding_domain_spf_multiple_records_critical", "email");
      c.add(!spf.tooManyLookups, 10, "finding_domain_spf_too_many_lookups_critical", "email");
      c.add(spf.all !== "+all", 8, "finding_domain_spf_allows_all_critical", "email");
      c.add(spf.all !== "?all", 4, "finding_domain_spf_neutral_all_warning", "email");
      c.add(spf.strength !== "none", 4, "finding_domain_spf_no_all_warning", "email");
      c.add(!spf.ptr, 2, "finding_domain_spf_ptr_warning", "email");
      c.add(spf.brokenIncludes.length === 0, 4, "finding_domain_spf_broken_include_warning", "email");
    }
  } else if (hasMx) { spfStatus = STATUS.INACTIVE; c.add(false, 25, "finding_domain_missing_spf_warning", "email"); }
  else spfStatus = STATUS.NOT_REQUIRED;

  // ---- DMARC ----
  debug.dmarcRaw = normalizeTxtRecords(dmarcTxt.records);
  const dmarcAll = findDmarcRecords(dmarcTxt.records); const dmarcRecord = dmarcAll[0] || null; const dt = parseTags(dmarcRecord);
  let dmarcStatus, dmarcPolicy = null, dmarcPct = null;
  if (dmarcRecord) {
    dmarcPolicy = (dt.p || "").toLowerCase() || null; dmarcPct = dt.pct !== undefined ? parseInt(dt.pct, 10) : 100;
    const validP = ["none", "quarantine", "reject"].includes(dmarcPolicy);
    dmarcStatus = validP ? STATUS.VALID : STATUS.INACTIVE; if (validP) findings.push("EMAIL_DMARC_VALID");
    c.add(validP, 20, "finding_domain_invalid_dmarc_warning", "email");
    if (validP) {
      c.add(dmarcPolicy !== "none", 15, "finding_domain_dmarc_policy_none_warning", "email");
      c.add(dmarcPct >= 100, 5, "finding_domain_dmarc_pct_partial_warning", "email");
      const sp = (dt.sp || "").toLowerCase();
      if (sp) c.add(!(sp === "none" && dmarcPolicy !== "none"), 3, "finding_domain_dmarc_subdomain_weak_warning", "email");
      c.add(!!dt.rua, 3, "finding_domain_dmarc_no_reporting_info", "email");
      c.add(dmarcAll.length === 1, 3, "finding_domain_dmarc_multiple_records_warning", "email");
    }
  } else if (hasMx) { dmarcStatus = STATUS.INACTIVE; c.add(false, 20, "finding_domain_missing_dmarc_warning", "email"); }
  else dmarcStatus = STATUS.NOT_REQUIRED;

  // ---- DKIM ----
  let dkimList = [], dkimStatus = STATUS.NOT_REQUIRED;
  if (hasMx) {
    dkimList = dkimFound || [];
    if (dkimList.length) {
      dkimStatus = STATUS.VALID; findings.push("EMAIL_DKIM_VALID"); c.add(true, 20, null, "email");
      const weak = dkimList.filter(k => k.bits && k.bits < 1024), mid = dkimList.filter(k => k.bits && k.bits >= 1024 && k.bits < 2048);
      c.add(weak.length === 0, 6, "finding_domain_dkim_weak_key_critical", "email");
      c.add(mid.length === 0, 3, "finding_domain_dkim_short_key_warning", "email");
      c.add(!dkimList.some(k => k.revoked), 2, "finding_domain_dkim_revoked_warning", "email");
      c.add(!dkimList.some(k => k.testMode), 2, "finding_domain_dkim_test_mode_warning", "email");
    } else { dkimStatus = STATUS.SELECTOR_NOT_DISCOVERED; info.push("finding_domain_dkim_not_discovered_info"); }
  }
  if (mailPolicies) {
    const st = mailPolicies.mtaSts;
    if (!st.present) info.push("finding_domain_missing_mta_sts_info");
    else {
      c.add(st.policyReachable !== false, 4, "finding_domain_mta_sts_policy_unreachable_warning", "email");
      if (st.mode && st.mode !== "enforce") info.push("finding_domain_mta_sts_not_enforced_info");
    }
    if (!mailPolicies.tlsRpt) info.push("finding_domain_missing_tls_rpt_info");
  }

  // ---- CAA ----
  const caaTags = (dnsRecords.caa || []).map(r => ({ tag: r.issue ? "issue" : r.issuewild ? "issuewild" : r.iodef ? "iodef" : "other", value: r.issue || r.issuewild || r.iodef || "" }));
  if (!dnsRecords.caa?.length) { c.add(false, 10, "finding_domain_missing_caa_warning", "security"); } else { c.add(true, 10, null, "security"); findings.push("EMAIL_CAA_VALID"); }

  // ---- DNSSEC ----
  const dnssecStatus = dnssecResult.status;
  if (dnssecStatus === STATUS.VALID) { findings.push("DNS_SEC_ACTIVE"); c.add(true, 25, null, "security"); }
  else if (dnssecStatus === "BROKEN") { c.add(false, 25, "finding_domain_dnssec_broken_critical", "security"); }
  else if (dnssecResult.method === "DNSKEY_WITHOUT_DS") { c.add(false, 25, "finding_domain_dnssec_ds_missing_warning", "security"); }
  else if (dnssecStatus === STATUS.INACTIVE) { c.add(false, 25, "finding_domain_missing_dnssec_warning", "security"); }
  else info.push("finding_domain_dnssec_unknown_warning");

  // ---- Kayıt ve bitiş: RDAP, olmazsa WHOIS yedeği ----
  let registrar = null, registrarStatus = STATUS.UNKNOWN, createdAt = null, updatedAt = null, expiration = null, daysUntilExpiry = null;
  let transferLocked = null, transferLockStatus = TRANSFER_LOCK_STATUS.UNKNOWN, statuses = [], domainAgeDays = null, registryNs = [], regSource = null, regProfile = { state: "UNKNOWN", phase: "ACTIVE" };
  const wh = rdap.whois || null, tldOf = domain.split(".").pop();
  const whHas = !!(wh && (wh.expiry || wh.created || wh.registrar || (wh.statuses && wh.statuses.length)));
  if (wh && wh.notFound && !rdap.data) rdap.notFound = true;
  if (rdap.data || whHas) {
    const rd = rdap.data;
    registrar = (rd ? extractRegistrar(rd) : null) || (wh && wh.registrar) || null; registrarStatus = registrar ? "FOUND" : STATUS.UNKNOWN;
    if (!registrar) info.push("finding_domain_registrar_unknown_warning");
    createdAt = toDateOrNull(rd ? rdapDate(rd, ["registration", "registered", "creation", "created"]) : null) || (wh && wh.created) || null;
    updatedAt = toDateOrNull(rd ? rdapDate(rd, ["last changed", "last update", "last updated", "updated"]) : null) || (wh && wh.updated) || null;
    expiration = toDateOrNull(rd ? rdapDate(rd, EXPIRY_ACTIONS) : null) || (wh && wh.expiry) || null;
    regSource = rd ? rdap.source : (whHas ? `whois://${wh.server}` : null);
    if (createdAt) domainAgeDays = daysSince(createdAt);
    statuses = rd ? rdapStatuses(rd) : []; if (!statuses.length && wh) statuses = wh.statuses || [];
    registryNs = rd && Array.isArray(rd.nameservers) ? rd.nameservers.map(n => String((n && (n.ldhName || n.unicodeName)) || "").toLowerCase().replace(/\.$/, "")).filter(Boolean) : (wh ? wh.nameservers || [] : []);
    if (expiration) {
      daysUntilExpiry = daysUntil(expiration);
      c.add(daysUntilExpiry >= 0, 50, "finding_domain_expired_critical", "renewal");
      if (daysUntilExpiry >= 0) { c.add(daysUntilExpiry >= 14, 20, "finding_domain_expiring_critical_critical", "renewal"); c.add(daysUntilExpiry >= 30 || daysUntilExpiry < 14, 15, "finding_domain_expiring_soon_warning", "renewal"); c.add(daysUntilExpiry >= 60 || daysUntilExpiry < 30, 15, "finding_domain_expiring_soon_info", "renewal"); }
    } else info.push(NO_PUBLIC_EXPIRY.has(tldOf) ? "finding_domain_expiry_not_published_info" : "finding_domain_missing_expiry_warning");
    regProfile = expiryProfile(daysUntilExpiry, statuses);
    const ns = statuses.map(normStatus);
    if (ns.some(x => /serverhold|clienthold/.test(x))) c.add(false, 20, "finding_domain_on_hold_critical", "security");
    if (ns.some(x => /pendingdelete|redemption/.test(x))) c.add(false, 20, "finding_domain_redemption_critical", "security");
    if (ns.length) {
      transferLocked = ns.some(x => x.includes("transferprohibited"));
      transferLockStatus = transferLocked ? TRANSFER_LOCK_STATUS.LOCKED : TRANSFER_LOCK_STATUS.UNLOCKED;
      if (transferLocked) { findings.push("DOMAIN_TRANSFER_LOCKED"); c.add(true, 15, null, "security"); }
      else if (LOCKABLE_TLDS.has(tldOf)) c.add(false, 15, "finding_domain_transfer_unlocked_warning", "security");
      else info.push("finding_domain_transfer_unlocked_info");
    } else info.push("finding_domain_transfer_lock_unknown_warning");
    // Kayıt defterindeki NS listesi ile canlı DNS'in NS listesi farklıysa delegasyon bozuk olabilir
    const norm = (a) => [...new Set(a.map(x => String(x).toLowerCase().replace(/\.$/, "")))].sort().join(",");
    if (registryNs.length && dnsRecords.ns.length && norm(registryNs) !== norm(dnsRecords.ns)) info.push("finding_domain_ns_delegation_mismatch_info");
  } else if (rdap.notFound && !dnsRecords.ns.length) { info.push("finding_domain_not_registered_critical"); }
  else if (rdap.noRdap) { registrarStatus = "NO_RDAP"; info.push("finding_domain_registry_no_rdap_info"); }
  else { errors.push("RDAP tüm endpointler başarısız"); registrarStatus = "LOOKUP_FAILED"; info.push("finding_domain_rdap_failed_warning"); }

  // ---- Takeover / subdomain ----
  const takeovers = takeRows.filter(r => r.takeover), dangling = takeRows.filter(r => r.dangling && !r.takeover);
  c.add(takeovers.length === 0, 25, "finding_domain_takeover_risk_critical", "security");
  if (dangling.length) c.add(false, 5, "finding_domain_dangling_cname_warning", "security");

  // ---- Kara liste (bl yukarıda paralel hesaplandı) ----
  if (bl.status === "LISTED") { if (bl.strongHit || bl.multiHit) c.add(false, 20, "finding_domain_ip_blacklisted_critical", "security"); else c.add(false, 10, "finding_domain_ip_listed_warning", "security"); }
  else if (bl.status === "CLEAN") c.add(true, 15, null, "security");

  // ---- Skor ----
  const g = c.groupScores();
  const scores = { dns: g.dns ?? null, email: g.email ?? null, security: g.security ?? null, renewal: g.renewal ?? null };
  const parts = Object.values(scores).filter(v => v != null);
  let overall = parts.length ? Math.round(parts.reduce((a, b) => a + b, 0) / parts.length) : null;
  const allF = sortFindings([...c.findings(), ...info, ...findings]);
  const has = (code) => allF.includes(code);
  if (overall != null) {
    if (has("finding_domain_expired_critical") || has("finding_domain_redemption_critical")) overall = Math.min(overall, 15);
    if (has("finding_domain_not_resolving_critical") || has("finding_domain_missing_ns_critical") || has("finding_domain_on_hold_critical")) overall = Math.min(overall, 35);
    if (has("finding_domain_takeover_risk_critical") || has("finding_domain_dnssec_broken_critical")) overall = Math.min(overall, 40);
    if (has("finding_domain_ip_blacklisted_critical")) overall = Math.min(overall, 60);
    if (has("finding_domain_expiring_critical_critical")) overall = Math.min(overall, 55);
  }
  if (rdap.notFound && !dnsRecords.ns.length) overall = 0;
  scores.overall = overall;
  const critical = allF.some(f => classifyFinding(f) === "critical");
  const status = overall == null ? "UNKNOWN" : (overall >= 80 && !critical) ? "HEALTHY" : overall >= 50 ? "WARNING" : "CRITICAL";

  const soa = dnsRecords.soa;
  const specificAnalysis = {
    domain, inputHost,
    dns: {
      a: dnsRecords.a, aaaa: dnsRecords.aaaa, cname: dnsRecords.cname, caa: dnsRecords.caa || [], mx: dnsRecords.mx, ns: dnsRecords.ns, wwwResolves,
      soa: soa ? { nsname: soa.nsname || null, hostmaster: soa.hostmaster || null, serial: soa.serial || null, refresh: soa.refresh || null, retry: soa.retry || null, expire: soa.expire || null, minttl: soa.minttl || null, raw: `${soa.nsname || ""} ${soa.hostmaster || ""} ${soa.serial || ""}`.trim() } : null,
      txt: normalizeTxtRecords(debug.txtRaw), ds: dnsRecords.ds || []
    },
    dnsProvider, nameservers: nsHealth ? { responding: `${nsHealth.respondingCount}/${nsHealth.servers.length}`, serialsConsistent: !nsHealth.serialMismatch, servers: nsHealth.servers.map(s => `${s.ns}${s.ip ? " (" + s.ip + ")" : ""} ${s.responds ? "✔ serial " + s.serial + " " + s.ms + "ms" : "✘ " + s.reason}`) } : null,
    dnsSecurity: { dnssecEnabled: !!dnssecResult.enabled, dnssecStatus, dnssecMethod: dnssecResult.method || null, transferLocked, transferLockStatus, caaRecords: caaTags },
    emailSecurity: {
      hasMx: !!hasMx, mxRecords: dnsRecords.mx || [], mailProvider: mailProv.provider,
      spf: spf.record, spfStatus: spfStatus === STATUS.VALID ? "VALID" : spfStatus === STATUS.NOT_REQUIRED ? "NOT_REQUIRED" : "MISSING", spfStatusDetailed: spfStatus, spfValid: spfStatus === STATUS.VALID,
      spfDetails: { recordCount: spf.count, dnsLookups: spf.lookups, lookupLimit: 10, all: spf.all, strength: spf.strength, includes: spf.includes, brokenIncludes: spf.brokenIncludes, usesPtr: spf.ptr },
      dmarc: dmarcRecord, dmarcStatus: dmarcStatus === STATUS.VALID ? "VALID" : dmarcStatus === STATUS.NOT_REQUIRED ? "NOT_REQUIRED" : "MISSING", dmarcStatusDetailed: dmarcStatus, dmarcPolicy, dmarcPct, dmarcValid: dmarcStatus === STATUS.VALID,
      dmarcDetails: dmarcRecord ? { subdomainPolicy: dt.sp || null, rua: dt.rua || null, ruf: dt.ruf || null, adkim: dt.adkim || "r", aspf: dt.aspf || "r" } : null,
      dkim: dkimList.length > 0, dkimRecord: dkimList[0]?.record || null, dkimStatus: dkimList.length ? "VALID" : hasMx ? "SELECTOR_NOT_DISCOVERED" : "NOT_REQUIRED", dkimStatusDetailed: dkimStatus,
      dkimSelector: dkimList[0]?.selector || null, dkimValid: dkimList.length > 0, dkimSelectors: dkimList.map(k => `${k.selector} (${k.keyType}${k.bits ? " " + k.bits + " bit" : ""}${k.revoked ? ", iptal" : ""}${k.testMode ? ", test modu" : ""})`),
      mtaSts: mailPolicies ? mailPolicies.mtaSts : null, tlsRpt: mailPolicies ? mailPolicies.tlsRpt : null, bimi: mailPolicies ? mailPolicies.bimi : null
    },
    registration: { registrar, registrarStatus, createdAt, updatedAt, expiresAt: expiration, remainingDays: daysUntilExpiry, domainAgeDays, transferLocked, transferLockStatus, statuses, source: regSource, target: domain,
      expiryState: regProfile.state, lifecyclePhase: regProfile.phase, expiredDaysAgo: daysUntilExpiry != null && daysUntilExpiry < 0 ? -daysUntilExpiry : null, dataSource: rdap.data ? "RDAP" : whHas ? "WHOIS" : null, whoisServer: whHas ? wh.server : null, expiryPublished: !NO_PUBLIC_EXPIRY.has(tldOf),
      reminderDates: expiration ? Object.fromEntries([60, 30, 14, 7].map(n => [`d${n}`, isoDay(new Date(expiration.getTime() - n * 864e5))])) : null, registryNameservers: registryNs },
    subdomains: { certificateTransparency: ctRes.ok ? "ok" : "failed", discovered: ctRes.names.length, sample: ctRes.names.slice(0, 25), cnameChecked: takeRows.length, takeoverRisks: takeovers.map(t => `${t.host} → ${t.cname} (${t.evidence})`), danglingCnames: dangling.map(t => `${t.host} → ${t.cname}`) },
    scores,
    threatAnalysis: { blacklistStatus: bl.status, blacklistHits: bl.hits.map(h => `${h.ip} → ${h.list}`), blacklistCheckedIps: bl.checkedIps, subdomainTakeoverRisk: takeovers.length > 0, takeoverEvidence: takeovers[0] ? `${takeovers[0].host} → ${takeovers[0].cname}` : null, typosquattingRisk: "BRAND taramasında kontrol edilir", target: domain },
    debug
  };
  const unknownCount = [!rdap.data && !whHas, dnssecStatus === STATUS.UNKNOWN, bl.status === "NOT_CHECKED", !nsHealth || nsHealth.inconclusive].filter(Boolean).length;
  const commonAnalysis = { analyzerVersion: V, executionTimeMs: Date.now() - startedAt, findings: allF, scannedAt: new Date().toISOString(), score: overall, status, target: domain };
  return {
    data: { assetType: "DOMAIN", commonAnalysis, specificAnalysis, analysisMeta: { scannerVersion: V, analyzer: "domain" }, target: domain, dnsProvider, registrar, remainingDays: daysUntilExpiry, transferLocked },
    findings: allF, errors, statusHint: status, confidence: clamp(100 - unknownCount * 8 - (errors.length ? 5 : 0))
  };
}

// =====================================================================
// IP / PLATFORM / TLS YARDIMCILARI
// =====================================================================
async function ipInfoWeb(ip) {
  try {
    const r = await axios.get(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 6000, validateStatus: () => true, proxy: false });
    if (r.data && r.data.success) return { ip, country: r.data.country || null, countryCode: r.data.country_code || null, city: r.data.city || null, region: r.data.region || null, asn: r.data.connection?.asn || null, org: r.data.connection?.org || null, isp: r.data.connection?.isp || null };
  } catch {}
  try {
    const r = await axios.get(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { timeout: 6000, validateStatus: () => true, proxy: false });
    if (r.data && !r.data.error && r.data.ip) return { ip, country: r.data.country_name || null, countryCode: r.data.country_code || null, city: r.data.city || null, region: r.data.region || null, asn: r.data.asn ? Number(String(r.data.asn).replace(/\D/g, "")) : null, org: r.data.org || null, isp: r.data.org || null };
  } catch {}
  return { ip, country: null, countryCode: null, city: null, region: null, asn: null, org: null, isp: null };
}
// Team Cymru IP→ASN (DNS TXT): HTTP API'leri sınırlanınca bile ASN, kuruluş ve ülke verir
async function cymruAsn(ip) {
  let q;
  if (net.isIPv4(ip)) q = ip.split(".").reverse().join(".") + ".origin.asn.cymru.com";
  else if (net.isIPv6(ip)) { const b = ipv6ToBytes(ip); if (!b) return null; q = b.map(x => x.toString(16).padStart(2, "0")).join("").split("").reverse().join(".") + ".origin6.asn.cymru.com"; }
  else return null;
  const r = await dq("resolveTxt", q); const line = r.data.length ? [].concat(r.data[0]).join("") : "";
  const m = line.match(/^\s*(\d+)(?:\s+\d+)*\s*\|\s*([^|]*)\|\s*([A-Za-z]{2})?\s*\|/); if (!m) return null;
  const asn = Number(m[1]), cc = (m[3] || "").toUpperCase() || null;
  const r2 = await dq("resolveTxt", `AS${asn}.asn.cymru.com`); const l2 = r2.data.length ? [].concat(r2.data[0]).join("") : "";
  const nm = (l2.split("|")[4] || "").trim().replace(/,\s*[A-Z]{2}$/, "") || null;
  let country = cc; try { if (cc) country = new Intl.DisplayNames(["tr"], { type: "region" }).of(cc) || cc; } catch {}
  return { asn, org: nm, country, countryCode: cc, prefix: (m[2] || "").trim() || null };
}
const IPINFO_CACHE = new Map();
async function ipInfo(ip) {
  const hit = IPINFO_CACHE.get(ip); if (hit && Date.now() - hit.at < 6 * 36e5) return hit.v;
  let v = await ipInfoWeb(ip); v.source = v.org || v.country ? "web" : null;
  if (!v.org || !v.asn) { const cy = await cymruAsn(ip).catch(() => null); if (cy) v = { ...v, asn: v.asn || cy.asn, org: v.org || cy.org, isp: v.isp || cy.org, country: v.country || cy.country, countryCode: v.countryCode || cy.countryCode, prefix: cy.prefix, source: v.source ? v.source + "+cymru" : "cymru" }; }
  if (v.org || v.country) { if (IPINFO_CACHE.size > 500) IPINFO_CACHE.clear(); IPINFO_CACHE.set(ip, { at: Date.now(), v }); }
  return v;
}
const DDOS_CAPABLE = ["Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Sucuri", "Imperva", "DDoS-Guard", "Azure Front Door", "Vercel", "Netlify", "Google Cloud CDN", "Bunny CDN", "KeyCDN", "StackPath"];
function detectPlatforms(h, geo) {
  const s = (k) => String(h[k] || "").toLowerCase(); const out = []; const org = String(geo?.org || geo?.isp || "").toLowerCase();
  if (h["cf-ray"] || s("server").includes("cloudflare") || org.includes("cloudflare")) out.push("Cloudflare");
  if (h["x-amz-cf-id"] || s("via").includes("cloudfront")) out.push("AWS CloudFront");
  if (s("server").includes("akamai") || h["x-akamai-transformed"] || org.includes("akamai")) out.push("Akamai");
  if (h["x-fastly-request-id"] || (h["x-served-by"] && /cache-/.test(s("x-served-by"))) || org.includes("fastly")) out.push("Fastly");
  if (h["x-vercel-id"] || s("server") === "vercel") out.push("Vercel");
  if (h["x-nf-request-id"] || s("server").includes("netlify")) out.push("Netlify");
  if (h["x-github-request-id"]) out.push("GitHub Pages");
  if (h["x-sucuri-id"] || h["x-sucuri-cache"]) out.push("Sucuri");
  if (h["x-iinfo"] || h["x-cdn"] === "Imperva") out.push("Imperva");
  if (s("server").includes("ddos-guard")) out.push("DDoS-Guard");
  if (h["x-azure-ref"]) out.push("Azure Front Door");
  if (h["rndr-id"] || h["x-render-origin-server"]) out.push("Render");
  if (h["fly-request-id"]) out.push("Fly.io");
  if (h["x-bunny-cache"] || s("server").includes("bunnycdn")) out.push("Bunny CDN");
  if (h["x-wix-request-id"]) out.push("Wix");
  if (h["x-shopify-stage"] || h["x-shopid"]) out.push("Shopify");
  if (s("x-powered-by").includes("wp engine") || h["x-wpe-request-id"]) out.push("WP Engine");
  if (h["x-kinsta-cache"]) out.push("Kinsta");
  if (s("server").includes("litespeed") && h["x-litespeed-cache"]) out.push("LiteSpeed Cache");
  if (h["x-heroku-queue-wait-time"] || s("via").includes("vegur")) out.push("Heroku");
  return [...new Set(out)];
}
function cloudFamily(org) {
  const o = String(org || "").toLowerCase();
  const map = [["amazon", "AWS"], ["google", "Google Cloud"], ["microsoft", "Microsoft Azure"], ["digitalocean", "DigitalOcean"], ["hetzner", "Hetzner"], ["ovh", "OVH"], ["linode", "Linode/Akamai"], ["vultr", "Vultr"], ["oracle", "Oracle Cloud"],
    ["cloudflare", "Cloudflare"], ["alibaba", "Alibaba Cloud"], ["contabo", "Contabo"], ["scaleway", "Scaleway"], ["hostinger", "Hostinger"], ["godaddy", "GoDaddy"], ["natro", "Natro"], ["turkcell", "Turkcell"], ["turk telekom", "Türk Telekom"], ["türk telekom", "Türk Telekom"], ["vodafone", "Vodafone"], ["netinternet", "Netinternet"], ["veridyen", "Veridyen"], ["radore", "Radore"], ["guzel hosting", "Güzel Hosting"], ["fastly", "Fastly"], ["akamai", "Akamai"]];
  for (const [k, v] of map) if (o.includes(k)) return v;
  return null;
}
// ---------- TLS ----------
function readTL(buf, p) {
  const tag = buf[p]; let len = buf[p + 1]; let off = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len * 256) + buf[p + 2 + i]; off = 2 + n; }
  return { tag, len, start: p + off, end: p + off + len };
}
const SIG_OIDS = { "1.2.840.113549.1.1.2": "md2WithRSA", "1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA", "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA", "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.10045.4.1": "sha1WithECDSA", "1.2.840.10045.4.3.2": "sha256WithECDSA", "1.2.840.10045.4.3.3": "sha384WithECDSA", "1.2.840.10045.4.3.4": "sha512WithECDSA", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448" };
function derSignatureAlgorithm(der) {
  try {
    const cert = readTL(der, 0); const tbs = readTL(der, cert.start); const sig = readTL(der, tbs.end); const oid = readTL(der, sig.start);
    if (oid.tag !== 0x06) return null; const b = der.subarray(oid.start, oid.end); const parts = [Math.floor(b[0] / 40), b[0] % 40]; let v = 0;
    for (let i = 1; i < b.length; i++) { v = (v << 7) | (b[i] & 0x7f); if (!(b[i] & 0x80)) { parts.push(v); v = 0; } }
    const o = parts.join("."); return { oid: o, name: SIG_OIDS[o] || o };
  } catch { return null; }
}
function getTlsDetails(host, port = 443, timeout = 7000, opts = {}) {
  return new Promise((resolve, reject) => {
    const target = opts.ip || host;
    if (blockedHost(host) || blockedHost(target)) return reject(privateError());
    let ocsp = false, settled = false; const finish = (fn, v) => { if (settled) return; settled = true; fn(v); };
    const socket = tlsMod.connect({ host: target, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, ALPNProtocols: ["h2", "http/1.1"], requestOCSP: true, lookup: safeLookup, timeout }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert || !Object.keys(cert).length) { socket.destroy(); return finish(reject, new Error("Sertifika alınamadı")); }
        const chain = []; let cur = cert; const seen = new Set();
        while (cur && cur.fingerprint256 && !seen.has(cur.fingerprint256)) {
          seen.add(cur.fingerprint256);
          chain.push({ subject: cur.subject?.CN || cur.subject?.O || "?", issuer: cur.issuer?.CN || cur.issuer?.O || "?", validTo: cur.valid_to, validFrom: cur.valid_from, bits: cur.bits || null, selfIssued: cur.subject?.CN === cur.issuer?.CN && cur.subject?.O === cur.issuer?.O, raw: cur.raw });
          if (!cur.issuerCertificate || cur.issuerCertificate === cur) break; cur = cur.issuerCertificate;
        }
        const res = { cert, chain, protocol: socket.getProtocol(), cipher: socket.getCipher(), authorized: socket.authorized, authError: socket.authorizationError ? String(socket.authorizationError.code || socket.authorizationError) : null, alpn: socket.alpnProtocol || null, ocspStapled: ocsp, ip: socket.remoteAddress };
        socket.end(); finish(resolve, res);
      } catch (e) { socket.destroy(); finish(reject, e); }
    });
    socket.on("OCSPResponse", (r) => { if (r && r.length) ocsp = true; });
    socket.on("error", (e) => finish(reject, e));
    socket.setTimeout(timeout, () => { socket.destroy(); finish(reject, Object.assign(new Error("TLS timeout"), { code: "ETIMEDOUT" })); });
  });
}
function tlsAlpn(host, timeout = 5000) {
  return new Promise((resolve) => {
    if (blockedHost(host)) return resolve(null);
    const t0 = Date.now(); let done = false; const fin = (v) => { if (!done) { done = true; resolve(v); } };
    const s = tlsMod.connect({ host, port: 443, servername: net.isIP(host) ? undefined : host, ALPNProtocols: ["h2", "http/1.1"], rejectUnauthorized: false, lookup: safeLookup, timeout }, () => {
      const r = { alpn: s.alpnProtocol || null, tlsVersion: s.getProtocol(), handshakeMs: Date.now() - t0 }; s.end(); fin(r);
    });
    s.on("error", () => fin(null)); s.on("timeout", () => { s.destroy(); fin(null); });
  });
}
// Hangi TLS sürümleri kabul ediliyor? true/false/null(test edilemedi)
async function probeTlsVersions(host, port = 443) {
  const vers = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
  if (blockedHost(host)) return Object.fromEntries(vers.map(v => [v, null]));
  const out = await Promise.all(vers.map(v => new Promise((resolve) => {
    let done = false; const fin = (x) => { if (!done) { done = true; resolve(x); } };
    let s; try {
      s = tlsMod.connect({ host, port, servername: net.isIP(host) ? undefined : host, minVersion: v, maxVersion: v, ciphers: v === "TLSv1.3" ? undefined : "ALL:@SECLEVEL=0", rejectUnauthorized: false, lookup: safeLookup, timeout: 5000 }, () => { s.destroy(); fin(true); });
    } catch { return fin(null); }
    s.on("error", (e) => { const m = String(e.code || "") + " " + String(e.message || ""); fin(/NO_PROTOCOLS_AVAILABLE|no protocols available|unsupported|not supported|ENOTFOUND|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT/i.test(m) ? null : false); });
    s.on("timeout", () => { s.destroy(); fin(null); });
  })));
  const o = {}; vers.forEach((v, i) => { o[v] = out[i]; }); return o;
}
function parseHostPort(input, defPort) {
  try { const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(String(input).trim()) ? String(input).trim() : "https://" + String(input).trim()); return { host: u.hostname.replace(/^\[|\]$/g, "").toLowerCase(), port: u.port ? parseInt(u.port, 10) : defPort }; }
  catch { return { host: parseHostLoose(input), port: defPort }; }
}

// =====================================================================
// 3. SSL SCANNER v12
// =====================================================================
const SSL_PORTS = new Set([443, 465, 636, 853, 993, 995, 8443, 9443]);
async function scanSslCertificate(input, extra = {}) {
  const startedAt = Date.now(); const V = "ssl-analyzer-v13.5"; const errors = []; const findings = []; const c = makeChecker();
  const hp = parseHostPort(input, 443); const host = hp.host && (net.isIP(hp.host) || hp.host.includes(".")) ? hp.host : null;
  if (host && !SSL_PORTS.has(hp.port)) return { data: null, findings: ["finding_ssl_invalid_target_critical"], errors: ["Desteklenmeyen SSL portu (izin verilenler: " + [...SSL_PORTS].join(", ") + ")"], statusHint: "INVALID" };
  if (!host) return { data: null, findings: ["finding_ssl_invalid_target_critical"], errors: ["geçersiz hedef"], statusHint: "INVALID" };
  let t;
  try { t = await getTlsDetails(host, hp.port); }
  catch (e) {
    const ni = classifyNetError(e); errors.push(e.message);
    const code = ({ dns: "finding_ssl_dns_failure_critical", refused: "finding_ssl_port_closed_critical", timeout: "finding_ssl_timeout_critical", reset: "finding_ssl_handshake_failed_critical", tls: "finding_ssl_handshake_failed_critical" })[ni.kind] || "finding_ssl_check_failed_critical";
    return buildResult({ assetType: "SSL_CERTIFICATE", version: V, startedAt, target: host, findings: [code], score: null, status: "ERROR", errors,
      specific: { domain: host, port: hp.port, cert: { valid: false, error: e.message, errorKind: ni.kind }, note: "TLS bağlantısı kurulamadı; sertifika değerlendirilemedi." } });
  }
  const raw = t.cert; const leafDer = raw.raw; let x509 = null; try { x509 = new crypto.X509Certificate(leafDer); } catch {}
  // v13.5: aynı alan adının DİĞER IP'leri ve www/apex varyantı (bir arka uçta süresi dolmuş sertifika klasik kesinti nedenidir)
  const hostIsIp = net.isIP(host) > 0;
  const ipProbeP = hostIsIp ? Promise.resolve([]) : (async () => {
    const ipv = await resolveIps(host).catch(() => null); if (!ipv) return [];
    const others = [...ipv.v4, ...ipv.v6].filter(ip => ip !== t.ip).slice(0, 4);
    return (await pool(others, 4, async (ip) => { try { const x = await getTlsDetails(host, hp.port, 5000, { ip }); return { ip, ok: true, days: Math.floor((new Date(x.cert.valid_to) - Date.now()) / 864e5), validTo: new Date(x.cert.valid_to).toISOString(), fingerprint: x.cert.fingerprint256 }; } catch (e) { return { ip, ok: false, error: e.code || e.message }; } })).filter(Boolean);
  })().catch(() => []);
  const altHost = hostIsIp ? null : (/^www\./.test(host) ? host.slice(4) : "www." + host);
  const altP = altHost && altHost.includes(".") ? getTlsDetails(altHost, hp.port, 5000).then(x => { let match = null; try { match = !!new crypto.X509Certificate(x.cert.raw).checkHost(altHost); } catch {} return { host: altHost, ok: true, days: Math.floor((new Date(x.cert.valid_to) - Date.now()) / 864e5), validTo: new Date(x.cert.valid_to).toISOString(), issuer: x.cert.issuer?.O || x.cert.issuer?.CN || null, fingerprint: x.cert.fingerprint256, hostnameMatches: match }; }).catch(() => null) : Promise.resolve(null);
  const validFrom = new Date(raw.valid_from), validTo = new Date(raw.valid_to);
  const daysRemaining = Math.floor((validTo - Date.now()) / 864e5); const validityDays = Math.round((validTo - validFrom) / 864e5);
  const sanList = raw.subjectaltname ? raw.subjectaltname.split(/,\s*/).map(s => s.replace(/^(DNS|IP Address):/, "").trim()).filter(Boolean) : [raw.subject?.CN].filter(Boolean);
  const issuerOrg = raw.issuer?.O || raw.issuer?.CN || "Unknown";
  const selfSigned = raw.issuerCertificate ? (raw.fingerprint256 === raw.issuerCertificate.fingerprint256) : (raw.subject?.CN === raw.issuer?.CN && raw.subject?.O === raw.issuer?.O);
  const isWildcard = sanList.some(d => d.startsWith("*."));
  let keyType = null, keyBits = raw.bits || null, curve = null;
  if (x509) { try { const pk = x509.publicKey; keyType = pk.asymmetricKeyType; keyBits = pk.asymmetricKeyDetails?.modulusLength || keyBits; curve = pk.asymmetricKeyDetails?.namedCurve || null; } catch {} }
  if (!keyType) keyType = raw.modulus ? "rsa" : raw.pubkey ? "ec" : null;
  const sig = derSignatureAlgorithm(leafDer); const sigName = sig?.name || null;
  let hostMatch = null, wwwCovered = null;
  if (x509) { try { hostMatch = net.isIP(host) ? !!x509.checkIP(host) : !!x509.checkHost(host); if (!net.isIP(host)) { const alt = /^www\./.test(host) ? host.replace(/^www\./, "") : "www." + host; wwwCovered = !!x509.checkHost(alt); } } catch {} }
  const authErr = t.authError;
  const trustedChain = t.authorized || (authErr === "ERR_TLS_CERT_ALTNAME_INVALID");
  const chainIncomplete = ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_GET_ISSUER_CERT"].includes(authErr) && !selfSigned;
  const untrusted = !t.authorized && authErr && !chainIncomplete && !["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "ERR_TLS_CERT_ALTNAME_INVALID"].includes(authErr) && !selfSigned;
  const chainExpired = t.chain.slice(1).some(x => new Date(x.validTo) < new Date());
  const protos = await withTimeout(probeTlsVersions(host, hp.port), 9000, "TLS").catch(() => ({}));
  const oldTls = ["TLSv1", "TLSv1.1"].filter(v => protos[v] === true);
  const httpsProbe = await httpProbe(`https://${host}${hp.port === 443 ? "" : ":" + hp.port}`, { timeout: 8000, maxRedirects: 0, noUaFallback: true, readBody: false });
  const hstsRaw = httpsProbe.headers?.["strict-transport-security"] || null;
  const hsts = hstsRaw ? { enabled: true, maxAge: parseInt((hstsRaw.match(/max-age=(\d+)/i) || [])[1] || "0", 10), includeSubDomains: /includesubdomains/i.test(hstsRaw), preload: /preload/i.test(hstsRaw) } : { enabled: false, maxAge: 0, includeSubDomains: false, preload: false };
  const certInfo = {
    valid: daysRemaining >= 0 && validFrom <= new Date() && !selfSigned && (hostMatch !== false) && !untrusted, validFrom: validFrom.toISOString(), validTo: validTo.toISOString(), daysRemaining, validityPeriodDays: validityDays,
    issuer: `${raw.issuer?.O || ""} ${raw.issuer?.CN || ""}`.trim(), issuerOrg, issuerCN: raw.issuer?.CN || null, subject: raw.subject?.CN || host, subjectO: raw.subject?.O || null, subjectAltNames: sanList,
    serialNumber: raw.serialNumber, fingerprint: raw.fingerprint256, keyType, keySize: keyBits, curve, signatureAlgorithm: sigName, isWildcard, isSelfSigned: selfSigned, hostnameMatches: hostMatch, coversWwwVariant: wwwCovered,
    isEV: /extended validation|\bEV\b/i.test(String(raw.issuer?.CN || "")) || undefined
  };
  const tlsInfo = {
    protocol: t.protocol, cipherName: t.cipher?.name, cipherVersion: t.cipher?.version, alpn: t.alpn, supportsTls13: protos["TLSv1.3"] === true || t.protocol === "TLSv1.3", supportsTls12: protos["TLSv1.2"] === true || ["TLSv1.2", "TLSv1.3"].includes(t.protocol),
    legacyProtocolsEnabled: oldTls, protocolSupport: Object.fromEntries(Object.entries(protos).map(([k, v]) => [k, v === true ? "destekleniyor" : v === false ? "kapalı" : "test edilemedi"])),
    ocspStapling: t.ocspStapled, chainLength: t.chain.length, chain: t.chain.map(x => `${x.subject} ← ${x.issuer} (bitiş ${new Date(x.validTo).toISOString().slice(0, 10)})`), chainComplete: !chainIncomplete, trusted: !!trustedChain && !untrusted, trustError: authErr, remoteIp: t.ip
  };
  // ---- bulgular / skor ----
  c.add(daysRemaining >= 0, 30, "finding_ssl_expired_critical", "validity");
  c.add(validFrom <= new Date(), 10, "finding_ssl_not_yet_valid_critical", "validity");
  c.add(hostMatch !== false, 25, "finding_ssl_hostname_mismatch_critical", "validity");
  c.add(!selfSigned, 25, "finding_ssl_self_signed_critical", "validity");
  c.add(!untrusted, 25, "finding_ssl_untrusted_critical", "chainTrust");
  c.add(!chainIncomplete, 15, "finding_ssl_chain_incomplete_warning", "chainTrust");
  c.add(!chainExpired, 10, "finding_ssl_chain_expired_critical", "chainTrust");
  if (daysRemaining >= 0) { c.add(daysRemaining >= 7, 50, "finding_ssl_expiring_soon_critical", "renewal"); c.add(daysRemaining >= 21, 30, "finding_ssl_expiring_soon_warning", "renewal"); c.add(daysRemaining >= 30, 20, null, "renewal"); } else c.add(false, 100, null, "renewal");
  if (keyBits) c.add(keyType === "rsa" ? keyBits >= 2048 : keyType === "ec" ? keyBits >= 224 : true, 20, "finding_ssl_weak_key_critical", "security");
  if (sigName) c.add(!/md2|md5|sha1/i.test(sigName), 20, "finding_ssl_weak_signature_critical", "security");
  c.add(oldTls.length === 0, 20, "finding_ssl_tls_old_version_warning", "security");
  c.add(tlsInfo.supportsTls12 || tlsInfo.supportsTls13, 10, "finding_ssl_tls12_unsupported_critical", "security");
  c.add(tlsInfo.supportsTls13, 5, "finding_ssl_no_tls13_info", "security");
  c.add(!/RC4|3DES|NULL|EXPORT|MD5|DES-CBC/i.test(String(t.cipher?.name || "")), 10, "finding_ssl_weak_cipher_critical", "security");
  c.add(hsts.enabled, 40, "finding_ssl_hsts_missing_warning", "hsts");
  if (hsts.enabled) { c.add(hsts.maxAge >= 15552000, 30, "finding_ssl_hsts_short_warning", "hsts"); c.add(hsts.includeSubDomains, 15, "finding_ssl_hsts_no_subdomains_info", "hsts"); c.add(hsts.preload, 15, null, "hsts"); }
  if (httpsProbe.status === 0 && httpsProbe.errorInfo && httpsProbe.errorInfo.kind !== "tls") errors.push("HTTPS isteği: " + httpsProbe.error);
  const extraF = [];
  if (isWildcard) extraF.push("finding_ssl_wildcard_info");
  if (wwwCovered === false) extraF.push("finding_ssl_www_not_covered_warning");
  if (validityDays > 398 && !selfSigned) extraF.push("finding_ssl_long_validity_info");
  if (t.ocspStapled === false) extraF.push("finding_ssl_no_ocsp_stapling_info");
  // ---- v13.5: diğer IP'ler, www/apex varyantı, ara sertifika bitişi, otomatik yenileme şüphesi ----
  const ipRows = await ipProbeP, altRes = await altP;
  const certsSeen = new Set([raw.fingerprint256, ...ipRows.filter(r => r.ok).map(r => r.fingerprint)]);
  if (ipRows.some(r => r.ok && r.days < 0)) c.add(false, 25, "finding_ssl_ip_cert_expired_critical", "validity");
  else if (ipRows.some(r => r.ok && r.days >= 0 && r.days < 21 && r.days < daysRemaining)) extraF.push("finding_ssl_ip_cert_expiring_warning");
  if (altRes && altRes.days < 0) c.add(false, 15, "finding_ssl_variant_expired_critical", "validity");
  else if (altRes && altRes.days >= 0 && altRes.days < 21 && altRes.days < daysRemaining) extraF.push("finding_ssl_variant_expiring_warning");
  const interm = t.chain.slice(1).filter(x => !x.selfIssued).map(x => ({ subject: x.subject, validTo: new Date(x.validTo).toISOString(), days: Math.floor((new Date(x.validTo) - Date.now()) / 864e5) })).sort((a, b) => a.days - b.days);
  const chainNearest = interm[0] || null;
  if (chainNearest && chainNearest.days >= 0 && chainNearest.days < 30) extraF.push("finding_ssl_chain_expiring_warning");
  const acme = /let'?s encrypt|zerossl|google trust services|buypass|ssl\.com|sectigo.*acme/i.test(`${raw.issuer?.O || ""} ${raw.issuer?.CN || ""}`) && validityDays <= 100;
  if (acme && daysRemaining >= 0 && daysRemaining < 14) extraF.push("finding_ssl_autorenew_stalled_warning");
  const expiryInfo = { daysRemaining, expiresAt: validTo.toISOString(), state: daysRemaining < 0 ? "EXPIRED" : daysRemaining <= 7 ? "CRITICAL" : daysRemaining <= 14 ? "URGENT" : daysRemaining <= 30 ? "SOON" : "OK",
    lifetimeUsedPct: validityDays > 0 ? Math.max(0, Math.min(100, Math.round(((Date.now() - validFrom.getTime()) / (validTo.getTime() - validFrom.getTime())) * 100))) : null, issuedDaysAgo: daysSince(validFrom),
    acmeIssuer: acme, autoRenewal: acme ? (daysRemaining < 14 ? "STALLED_SUSPECTED" : "EXPECTED") : "UNKNOWN", chainNearest, renewBy: daysRemaining >= 0 ? isoDay(new Date(validTo.getTime() - (acme ? 30 : 14) * 864e5)) : null };
  const g = c.groupScores();
  const scores = { validity: g.validity ?? null, renewal: g.renewal ?? null, security: g.security ?? null, chainTrust: g.chainTrust ?? null, hsts: g.hsts ?? null };
  let overall = c.score();
  const all = sortFindings([...c.findings(), ...extraF]);
  if (all.includes("finding_ssl_expired_critical")) overall = Math.min(overall, 10);
  if (all.some(f => /hostname_mismatch|self_signed|untrusted|chain_expired|not_yet_valid|ip_cert_expired/.test(f))) overall = Math.min(overall, 30);
  if (all.includes("finding_ssl_variant_expired_critical")) overall = Math.min(overall, 50);
  if (all.some(f => /weak_key|weak_signature|weak_cipher/.test(f))) overall = Math.min(overall, 55);
  if (all.includes("finding_ssl_expiring_soon_critical")) overall = Math.min(overall, 50);
  const hint = daysRemaining < 0 ? "EXPIRED" : !certInfo.valid ? "CRITICAL" : daysRemaining < 21 ? "EXPIRING_SOON" : overall >= 80 ? "ACTIVE" : overall >= 50 ? "WARNING" : "CRITICAL";
  const specificAnalysis = { domain: host, port: hp.port, cert: certInfo, tls: tlsInfo, httpSecurity: { httpOk: httpsProbe.ok, status: httpsProbe.status, serverHeader: httpsProbe.headers?.server || null, hstsEnabled: hsts.enabled, hstsMaxAge: hsts.maxAge, hstsIncludeSubdomains: hsts.includeSubDomains, hstsPreload: hsts.preload },
    expiry: expiryInfo, endpoints: { primary: { ip: t.ip, days: daysRemaining, fingerprint: raw.fingerprint256 }, others: ipRows, distinctCerts: certsSeen.size }, variant: altRes, scores: { ...scores, overall } };
  const commonAnalysis = { analyzerVersion: V, executionTimeMs: Date.now() - startedAt, findings: all, scannedAt: new Date().toISOString(), score: overall, status: statusFromScore(overall), target: host };
  return { data: { assetType: "SSL_CERTIFICATE", commonAnalysis, specificAnalysis, analysisMeta: { scannerVersion: V, analyzer: "ssl" }, remainingDays: daysRemaining, expiresAt: validTo.toISOString() }, findings: all, errors, statusHint: hint,
    confidence: clamp(100 - Object.values(protos).filter(v => v === null).length * 4) };
}

// =====================================================================
// HOSTING v3
// =====================================================================
async function scanHosting(input) {
  const startedAt = Date.now(); const V = "hosting-analyzer-v13.5"; const host = parseTargetHost(input);
  if (!host) return buildResult({ assetType: "HOSTING", version: V, startedAt, target: String(input || ""), findings: ["finding_hosting_invalid_target_critical"], score: 0, status: "ERROR", specific: {} });
  const ips = await resolveIps(host); const c = makeChecker(); const resolves = ips.v4.length + ips.v6.length > 0;
  if (!resolves && ips.code && !dnsMissing(ips.code)) return unavailableResult({ assetType: "HOSTING", version: V, startedAt, target: host, finding: "finding_hosting_dns_unreliable_info", status: "UNKNOWN", note: "DNS sorguları yanıt vermedi; sonuç belirlenemedi.", specific: { host } });
  c.add(resolves, 20, "finding_hosting_not_resolving_critical", "erisim");
  let main = { ok: false, status: 0, headers: {}, responseTimeMs: null, ttfb: null, redirects: 0 }, geo = null, geo2 = null, rdns = null, tlsi = null, httpPlain = null, samples = [], tcp = null, hcert = null;
  if (resolves) {
    const first = ips.v4[0] || ips.v6[0];
    [main, geo, tlsi, httpPlain, tcp, hcert] = await Promise.all([
      httpProbe(`https://${host}`, { timeout: 10000, maxRedirects: 4 }), ipInfo(first), tlsAlpn(host),
      net.isIP(host) ? null : httpProbe(`http://${host}`, { timeout: 7000, maxRedirects: 0, noUaFallback: true, readBody: false }), tcpPortCheck(first, 443, 4000),
      getTlsDetails(host, 443, 6000).catch(() => null)
    ]);
    rdns = await safeResolve(dns.reverse, first);
    if (ips.v4.length + ips.v6.length > 1) geo2 = await ipInfo(ips.v4[1] || ips.v6[1]);
    if (main.status > 0) { for (let i = 0; i < 2; i++) { const r = await request(`https://${host}`, { timeout: 8000, readBody: false, insecure: true }); if (r.status) samples.push(r.ttfb); } if (main.ttfb != null) samples.push(main.ttfb); }
  }
  const platforms = detectPlatforms(main.headers || {}, geo); const ddos = platforms.some(p => DDOS_CAPABLE.includes(p)); const family = cloudFamily(geo?.org || geo?.isp);
  const prot = main.status ? detectBotProtection(main) : null;
  const reachable = main.status > 0 && (main.status < 500 || !!prot);
  c.add(reachable, 20, main.status === 0 ? netErrorFinding("hosting", main) : "finding_hosting_server_error_critical", "erisim");
  c.add(!!tlsi, 15, "finding_hosting_no_https_critical", "guvenlik");
  if (tlsi) c.add(["TLSv1.2", "TLSv1.3"].includes(tlsi.tlsVersion), 5, "finding_hosting_tls_old_warning", "guvenlik");
  const certDays = hcert && hcert.cert && hcert.cert.valid_to ? Math.floor((new Date(hcert.cert.valid_to) - Date.now()) / 864e5) : null;
  if (certDays != null) { c.add(certDays >= 0, 15, "finding_hosting_cert_expired_critical", "guvenlik"); if (certDays >= 0) c.add(certDays >= 14, 5, "finding_hosting_cert_expiring_warning", "guvenlik"); }
  if (httpPlain && httpPlain.status > 0) c.add(httpPlain.status >= 300 && httpPlain.status < 400 && /^https:/i.test(String(httpPlain.headers.location || "")), 6, "finding_hosting_no_https_redirect_warning", "guvenlik");
  c.add(ddos, 8, "finding_hosting_no_cdn_waf_warning", "dayaniklilik");
  c.add(ips.v6.length > 0, 3, "finding_hosting_no_ipv6_info", "dayaniklilik");
  c.add(ips.v4.length + ips.v6.length > 1 || ddos, 4, "finding_hosting_single_ip_info", "dayaniklilik");
  const ttfbAvg = samples.length ? avg(samples) : null;
  if (ttfbAvg != null) { c.add(ttfbAvg < 1500, 8, "finding_hosting_slow_response_warning", "performans"); c.add(ttfbAvg < 800, 6, null, "performans"); }
  if (tcp) c.add(tcp.open ? tcp.latencyMs < 500 : false, 4, tcp.open ? "finding_hosting_slow_connect_warning" : null, "performans");
  const findings = c.findings(); if (prot) findings.push("finding_web_bot_protection_info");
  if (!geo?.org && !geo?.country && resolves) findings.push("finding_hosting_geo_unknown_info");
  const score = c.score(); const down = !resolves || !reachable;
  const specific = {
    host, network: { ipv4: ips.v4, ipv6: ips.v6, reverseDns: (rdns && rdns[0]) || null },
    provider: geo ? { name: geo.org || geo.isp, family, asn: geo.asn, country: geo.country, countryCode: geo.countryCode, city: geo.city, region: geo.region } : null,
    secondaryIp: geo2 ? { ip: geo2.ip, org: geo2.org, country: geo2.country } : null, geoSource: geo ? geo.source || null : null, prefix: geo ? geo.prefix || null : null,
    certificate: hcert && hcert.cert ? { daysRemaining: certDays, validTo: new Date(hcert.cert.valid_to).toISOString(), issuer: hcert.cert.issuer?.O || hcert.cert.issuer?.CN || null, subject: hcert.cert.subject?.CN || null } : null,
    platform: platforms, ddosProtection: ddos, botProtection: prot ? { provider: prot } : undefined,
    http: { status: main.status, ttfbMs: ttfbAvg, responseTimeMs: main.responseTimeMs, server: (main.headers || {})["server"] || null, poweredBy: (main.headers || {})["x-powered-by"] || null, protocol: tlsi?.alpn || null, tlsVersion: tlsi?.tlsVersion || null, tlsHandshakeMs: tlsi?.handshakeMs ?? null, tcpConnectMs: tcp?.open ? tcp.latencyMs : null, redirects: main.redirects, httpToHttps: httpPlain && httpPlain.status ? (httpPlain.status >= 300 && httpPlain.status < 400 && /^https:/i.test(String(httpPlain.headers.location || ""))) : null },
    scores: c.groupScores(), checks: c.summary()
  };
  return buildResult({ assetType: "HOSTING", version: V, startedAt, target: host, findings, score, status: down ? "DOWN" : undefined, specific, errors: main.error ? [main.error] : [] });
}

// =====================================================================
// SUNUCU (port + banner) v3
// =====================================================================
const SERVER_PORTS = [[21, "FTP", "warn"], [22, "SSH", null], [23, "Telnet", "crit"], [25, "SMTP", null], [53, "DNS", null], [80, "HTTP", null], [110, "POP3", null], [135, "MS-RPC", "crit"], [139, "NetBIOS", "crit"], [143, "IMAP", null], [443, "HTTPS", null], [445, "SMB", "crit"],
  [465, "SMTPS", null], [587, "Submission", null], [993, "IMAPS", null], [995, "POP3S", null], [1433, "MSSQL", "crit"], [1521, "Oracle", "crit"], [2375, "Docker API", "crit"], [2379, "etcd", "crit"], [3306, "MySQL", "crit"], [3389, "RDP", "crit"],
  [5432, "PostgreSQL", "crit"], [5601, "Kibana", "crit"], [5672, "AMQP", "warn"], [5900, "VNC", "crit"], [5984, "CouchDB", "crit"], [6379, "Redis", "crit"], [6443, "Kubernetes API", "warn"], [8080, "HTTP-Alt", null], [8443, "HTTPS-Alt", null],
  [9092, "Kafka", "crit"], [9200, "Elasticsearch", "crit"], [10000, "Webmin", "warn"], [11211, "Memcached", "crit"], [15672, "RabbitMQ Mgmt", "warn"], [27017, "MongoDB", "crit"],
  [389, "LDAP", "warn"], [636, "LDAPS", null], [873, "rsync", "warn"], [1883, "MQTT", "warn"], [2049, "NFS", "crit"], [2082, "cPanel", "warn"], [2083, "cPanel SSL", null], [2086, "WHM", "warn"], [2087, "WHM SSL", "warn"],
  [3000, "Geliştirme sunucusu", "warn"], [5985, "WinRM", "crit"], [5986, "WinRM SSL", "warn"], [8000, "HTTP-Dev", "warn"], [8888, "HTTP-Alt2", null], [9000, "Portainer/PHP-FPM", "warn"], [9090, "Cockpit/Prometheus", "warn"]];
const BANNER_PORTS = new Set([21, 22, 25, 110, 143, 587]);
function grabBanner(ip, port, timeout = 2500) {
  return new Promise((resolve) => {
    const s = new net.Socket(); let buf = ""; let done = false; const fin = () => { if (done) return; done = true; s.destroy(); resolve(buf.replace(/[^\x20-\x7e]/g, " ").trim().slice(0, 160) || null); };
    s.setTimeout(timeout); s.on("data", d => { buf += d.toString("latin1"); if (buf.includes("\n") || buf.length > 200) fin(); }); s.on("timeout", fin); s.on("error", fin); s.on("close", fin);
    if (blockedHost(ip)) return fin();
    s.connect({ port, host: ip, lookup: safeLookup });
  });
}
async function scanServer(input) {
  const startedAt = Date.now(); const V = "server-analyzer-v13.5"; const host = parseTargetHost(input);
  if (!host) return buildResult({ assetType: "SERVER", version: V, startedAt, target: String(input || ""), findings: ["finding_server_invalid_target_critical"], score: 0, status: "ERROR", specific: {} });
  const ips = await resolveIps(host); const ip = ips.v4[0] || ips.v6[0];
  if (!ip) {
    if (ips.code && !dnsMissing(ips.code)) return unavailableResult({ assetType: "SERVER", version: V, startedAt, target: host, finding: "finding_server_dns_unreliable_info", status: "UNKNOWN", note: "DNS sorguları yanıt vermedi.", specific: { host } });
    return buildResult({ assetType: "SERVER", version: V, startedAt, target: host, findings: ["finding_server_not_resolving_critical"], score: 0, status: "DOWN", specific: { host } });
  }
  if (!allowPrivate() && isPrivateIp(ip)) return buildResult({ assetType: "SERVER", version: V, startedAt, target: host, findings: ["finding_server_private_target_critical"], score: null, status: "ERROR", specific: { host, ip } });
  const geo = await ipInfo(ip); const behindCdn = DDOS_CAPABLE.includes(cloudFamily(geo.org || geo.isp) || "") || /cloudflare|akamai|fastly|cloudfront/i.test(String(geo.org || ""));
  const res = await pool(SERVER_PORTS, 16, async ([port, name, risk]) => ({ ...(await tcpPortCheck(ip, port, 2500)), name, risk }));
  const rows = res.filter(Boolean); const open = rows.filter(r => r.open);
  const banners = {}; await pool(open.filter(r => BANNER_PORTS.has(r.port)), 6, async (r) => { const b = await grabBanner(ip, r.port); if (b) banners[r.port] = b; });
  const findings = []; let score = 100;
  // v13.5: TLS sunan servis portlarında sertifika bitişi (yalnızca el sıkışma; veri gönderilmez) — süresi dolmuş posta/panel sertifikası sık kaçan kesinti nedenidir
  const TLS_SVC = new Set([443, 8443, 465, 993, 995, 636, 2083, 2087, 5986]);
  const tlsServices = (await pool(open.filter(r => TLS_SVC.has(r.port)), 4, async (r) => {
    try { const x = await getTlsDetails(host, r.port, 5000, { ip }); const days = Math.floor((new Date(x.cert.valid_to) - Date.now()) / 864e5);
      let hostMatch = null; try { hostMatch = net.isIP(host) ? null : !!new crypto.X509Certificate(x.cert.raw).checkHost(host); } catch {}
      return { port: r.port, service: r.name, days, validTo: new Date(x.cert.valid_to).toISOString(), subject: x.cert.subject?.CN || null, issuer: x.cert.issuer?.O || x.cert.issuer?.CN || null, protocol: x.protocol, hostnameMatches: hostMatch };
    } catch { return null; }
  })).filter(Boolean);
  // v13.5: aynı adın diğer IP'lerinde de riskli (kritik) port var mı? (CDN arkasında değilse)
  let secondary = [];
  if (!behindCdn && ips.v4.length + ips.v6.length > 1) {
    const critPorts = SERVER_PORTS.filter(x => x[2] === "crit"); const others = [...ips.v4, ...ips.v6].filter(x => x !== ip).slice(0, 2);
    secondary = (await pool(others, 2, async (oip) => { if (!allowPrivate() && isPrivateIp(oip)) return null; const rs = await pool(critPorts, 16, async ([port, name]) => ({ ...(await tcpPortCheck(oip, port, 2000)), name })); return { ip: oip, openCritical: rs.filter(r => r && r.open).map(r => `${r.port}/${r.name}`) }; })).filter(Boolean);
  }
  const reverseDns = ((await safeResolve(dns.reverse, ip)) || [])[0] || null;
  const ignoreCdn = (p) => behindCdn && [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8880].includes(p);
  for (const r of open) {
    if (ignoreCdn(r.port)) continue;
    if (r.risk === "crit") { findings.push(`finding_server_exposed_port_${r.port}_critical`); score -= 22; }
    else if (r.risk === "warn") { findings.push(`finding_server_exposed_port_${r.port}_warning`); score -= 8; }
  }
  if (!behindCdn) {
    if (tlsServices.some(x => x.days < 0)) { findings.push("finding_server_cert_expired_critical"); score -= 15; }
    else if (tlsServices.some(x => x.days < 14)) { findings.push("finding_server_cert_expiring_warning"); score -= 5; }
    if (tlsServices.some(x => x.hostnameMatches === false)) { findings.push("finding_server_cert_hostname_mismatch_warning"); score -= 4; }
  }
  if (secondary.some(x => x.openCritical.length)) { findings.push("finding_server_secondary_ip_exposed_critical"); score -= 15; }
  if (banners[22]) {
    const m = banners[22].match(/SSH-(\d)\.(\d+)-OpenSSH[_-](\d+)\.(\d+)/i);
    if (/SSH-1\./.test(banners[22])) { findings.push("finding_server_ssh_v1_critical"); score -= 20; }
    else if (m && (+m[3] < 8 || (+m[3] === 8 && +m[4] < 5))) { findings.push("finding_server_ssh_outdated_warning"); score -= 8; }
  }
  if (banners[21] && /vsftpd 2\.3\.4|ProFTPD 1\.3\.[0-3]\b/i.test(banners[21])) { findings.push("finding_server_ftp_vulnerable_version_critical"); score -= 15; }
  if (open.some(r => r.port === 21) && !open.some(r => r.port === 22) && !behindCdn) { findings.push("finding_server_ftp_without_ssh_info"); }
  const mailPlain = open.some(r => [110, 143].includes(r.port)) && !open.some(r => [993, 995].includes(r.port));
  if (mailPlain) { findings.push("finding_server_plain_mail_ports_warning"); score -= 6; }
  const web = open.some(r => [80, 443, 8080, 8443].includes(r.port)); const alive = open.some(r => [22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443].includes(r.port));
  if (behindCdn) findings.push("finding_server_behind_cdn_info");
  if (!open.length) { findings.push("finding_server_unreachable_critical"); score = 0; }
  else if (!alive && !behindCdn) { findings.push("finding_server_no_service_ports_warning"); score -= 10; }
  score = clamp(score); const lat = open.map(r => r.latencyMs); const timeouts = rows.filter(r => r.error === "timeout").length;
  return buildResult({
    assetType: "SERVER", version: V, startedAt, target: host, findings, score, status: !open.length ? "DOWN" : undefined,
    specific: { host, ip, allIps: [...ips.v4, ...ips.v6], provider: geo.org || geo.isp, country: geo.country, city: geo.city, asn: geo.asn, behindCdn, checkedPorts: SERVER_PORTS.length, openCount: open.length, filteredCount: timeouts, avgConnectMs: avg(lat),
      openPorts: open.map(r => `${r.port}/${r.name} (${r.latencyMs}ms)`), banners: Object.entries(banners).map(([p, b]) => `${p}: ${b}`), webServiceOpen: web, reverseDns, tlsServices, secondaryIps: secondary,
      note: behindCdn ? "Hedef bir CDN/WAF arkasında; port sonuçları gerçek sunucuyu değil CDN'i yansıtır." : `Yalnızca ${SERVER_PORTS.length} yaygın porta bağlantı denendi; hiçbir veri gönderilmedi, sadece karşılama (banner) satırı okundu.` }
  });
}

// =====================================================================
// SAYFA ANALİZİ (WEB / SEO / SECURITY / PERFORMANCE ortak çekirdeği)
// =====================================================================
// ---------- HTML ayrıştırma (DOĞRUSAL zamanlı: düşman sayfalar olay döngüsünü kilitleyemez) ----------
// Eski sürüm [\s\S]*? / [^>]+ kalıplarını 2 MB'lık gövdede kullanıyordu; kapanışsız <script, <meta, <h1 tekrarları
// O(n²) çalışıp sunucuyu dakikalarca kilitleyebilirdi. Burada tek geçişli bir ayrıştırıcı kullanılır.
const MAX_HTML = 1500000, MAX_TAG = 8192, RAW_TEXT = new Set(["script", "style", "title", "textarea"]), SKIP_TEXT = new Set(["noscript", "svg", "template"]);
function parseAttrStr(inner) {
  const o = {}; const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g; let m, guard = 0;
  while ((m = re.exec(inner)) && guard++ < 400) { const k = m[1].toLowerCase(); if (!(k in o)) o[k] = m[2] ?? m[3] ?? m[4] ?? ""; if (m[0] === "") re.lastIndex++; }
  return o;
}
function tokenizeHtml(src) {
  const html = String(src || "").slice(0, MAX_HTML), n = html.length, tags = []; let i = 0;
  while (i < n) {
    const lt = html.indexOf("<", i); if (lt < 0) break;
    if (html.startsWith("<!--", lt)) { const g = html.indexOf("-->", lt + 4); if (g < 0) { tags.push({ n: "#c", c: false, s: lt, e: n, a: "" }); break; } tags.push({ n: "#c", c: false, s: lt, e: g + 3, a: "" }); i = g + 3; continue; }
    let j = lt + 1, end = -1; const lim = Math.min(n, lt + MAX_TAG);
    while (j < lim) { const c = html.charCodeAt(j); if (c === 62) { end = j; break; } if (c === 60) break; j++; }
    if (end < 0) { i = j < lim ? j : lt + 1; continue; }
    const m = /^<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)/.exec(html.slice(lt, lt + 48));
    if (!m) { i = end + 1; continue; }
    const t = { n: m[2].toLowerCase(), c: !!m[1], s: lt, e: end + 1, a: html.slice(lt + m[0].length, end).replace(/\/$/, "") };
    tags.push(t); i = end + 1;
    if (!t.c && RAW_TEXT.has(t.n)) {
      const re = new RegExp("</" + t.n + "[\\s/>]", "gi"); re.lastIndex = i; const cm = re.exec(html); const stop = cm ? cm.index : n;
      t.body = html.slice(i, Math.min(stop, i + 200000)); t.bodyLen = stop - i; i = stop; if (!cm) break;
    }
  }
  return { html, tags };
}
function textOfTokens(tk) {
  const { html, tags } = tk; const out = []; let pos = 0, skip = 0;
  for (const t of tags) {
    if (t.s > pos && !skip) out.push(html.slice(pos, t.s));
    pos = Math.max(pos, t.e);
    if (SKIP_TEXT.has(t.n)) skip = Math.max(0, skip + (t.c ? -1 : 1));
    if (!t.c && t.bodyLen) pos = t.e + t.bodyLen;
  }
  if (pos < html.length && !skip) out.push(html.slice(pos));
  return out.join(" ").replace(/\s+/g, " ").trim();
}
const stripTags = (h) => String(h || "").replace(/<[^<>]{0,8192}>/g, " ").replace(/\s+/g, " ").trim();
function extractTitle(body) { const tk = tokenizeHtml(String(body || "").slice(0, 200000)); const t = tk.tags.find(x => x.n === "title" && !x.c); return t && t.body ? decodeEntities(t.body.replace(/\s+/g, " ").trim()) : ""; }

function analyzeHtml(htmlIn, baseUrl) {
  const rawLen = String(htmlIn || "").length; const tk = tokenizeHtml(htmlIn); const html = tk.html; const A = {};
  const by = {}; for (const t of tk.tags) { if (t.n[0] === "#") continue; (by[t.n] || (by[t.n] = [])).push(t); }
  const open = (name) => (by[name] || []).filter(t => !t.c);
  const attrs = (name) => open(name).map(t => parseAttrStr(t.a));
  const headAttrs = (name) => open(name).filter(t => t.s < 200000).map(t => parseAttrStr(t.a));
  const titleTag = open("title")[0];
  A.title = decodeEntities(((titleTag && titleTag.body) || "").replace(/\s+/g, " ").trim()) || null;
  const metas = headAttrs("meta"); const meta = (n, by2 = "name") => { const m = metas.find(x => String(x[by2] || "").toLowerCase() === n); return m && m.content != null ? decodeEntities(m.content.trim()) : null; };
  A.metaDescription = meta("description"); A.robotsMeta = (meta("robots") || "").toLowerCase(); A.googlebotMeta = (meta("googlebot") || "").toLowerCase();
  A.viewport = meta("viewport"); A.generator = meta("generator"); A.themeColor = meta("theme-color");
  A.charset = (metas.find(x => x.charset) || {}).charset || (String((metas.find(x => String(x["http-equiv"] || "").toLowerCase() === "content-type") || {}).content || "").match(/charset=([\w-]+)/i) || [])[1] || null;
  A.og = { title: meta("og:title", "property"), description: meta("og:description", "property"), image: meta("og:image", "property"), url: meta("og:url", "property"), type: meta("og:type", "property") };
  A.twitterCard = meta("twitter:card");
  const links = headAttrs("link"); const rel = (r) => links.filter(l => String(l.rel || "").toLowerCase().split(/\s+/).includes(r));
  A.canonical = (rel("canonical")[0] || {}).href || null; A.hasFavicon = links.some(l => /\bicon\b/i.test(l.rel || "")); A.appleTouchIcon = rel("apple-touch-icon").length > 0; A.manifest = (rel("manifest")[0] || {}).href || null;
  A.hreflang = links.filter(l => l.hreflang).map(l => ({ lang: l.hreflang, href: l.href })); A.rssFeed = links.some(l => /alternate/i.test(l.rel || "") && /rss|atom/i.test(l.type || ""));
  const htmlTag = attrs("html")[0] || {}; A.htmlLang = /^[A-Za-z-]+$/.test(htmlTag.lang || "") ? htmlTag.lang : null;
  // başlıklar: açılıştan sonraki ilk kapanışa kadar (kapanış yoksa o başlık atlanır)
  const h1c = (by.h1 || []).filter(t => t.c).map(t => t.s); A.h1 = []; let hp = 0;
  for (const t of open("h1")) { while (hp < h1c.length && h1c[hp] < t.e) hp++; if (hp >= h1c.length) break; const x = decodeEntities(stripTags(html.slice(t.e, h1c[hp]))); if (x) A.h1.push(x); }
  A.h1Count = open("h1").length; A.h2Count = open("h2").length; A.h3Count = open("h3").length;
  const imgs = attrs("img"); A.images = { total: imgs.length, missingAlt: imgs.filter(i => i.alt === undefined || (i.alt.trim() === "" && !/^(presentation|none)$/i.test(i.role || ""))).length, lazy: imgs.filter(i => /lazy/i.test(i.loading || "")).length, noDimensions: imgs.filter(i => !(i.width && i.height)).length, modernFormat: imgs.filter(i => /\.(webp|avif)(\?|$)/i.test(i.src || i["data-src"] || "")).length, srcs: imgs.map(i => i.src || i["data-src"]).filter(Boolean) };
  const scriptTags = open("script"); const scripts = scriptTags.map(t => parseAttrStr(t.a));
  A.scripts = scripts.filter(s => s.src).map(s => ({ src: s.src, async: "async" in s, defer: "defer" in s, module: /module/i.test(s.type || ""), integrity: !!s.integrity }));
  A.inlineScripts = scripts.filter(s => !s.src).length;
  A.stylesheets = links.filter(l => /stylesheet/i.test(l.rel || "") && l.href).map(l => ({ href: l.href, integrity: !!l.integrity }));
  A.jsonld = { blocks: 0, invalid: 0, types: [] };
  scriptTags.forEach((t, k) => {
    if (!/application\/ld\+json/i.test(scripts[k].type || "")) return;
    A.jsonld.blocks++; try { const j = JSON.parse(String(t.body || "").trim()); const walk = (o, d = 0) => { if (d > 12) return; if (Array.isArray(o)) o.forEach(x => walk(x, d + 1)); else if (o && typeof o === "object") { if (o["@type"]) [].concat(o["@type"]).forEach(x => A.jsonld.types.push(String(x))); if (o["@graph"]) walk(o["@graph"], d + 1); } }; walk(j); } catch { A.jsonld.invalid++; }
  });
  A.jsonld.types = [...new Set(A.jsonld.types)].slice(0, 50);
  const text = textOfTokens(tk); A.text = text.slice(0, 20000); A.wordCount = text ? text.split(/\s+/).length : 0;
  A.htmlBytes = rawLen; A.domNodes = tk.tags.filter(t => !t.c && t.n[0] !== "#").length;
  A.spaShell = A.wordCount < 60 && open("div").some(t => /\bid\s*=\s*["']?(root|app|__next|__nuxt|___gatsby)["']?/i.test(t.a)) && (A.scripts.length > 0 || A.inlineScripts > 0);
  let base = null; try { base = new URL(baseUrl); } catch {}
  const anchors = attrs("a").filter(a => a.href); let internal = 0, external = 0, nofollowExt = 0, emptyHref = 0; const extHosts = new Set();
  for (const a of anchors.slice(0, 5000)) {
    const h = a.href.trim(); if (!h || h === "#") { emptyHref++; continue; } if (/^(mailto:|tel:|javascript:|#|sms:|whatsapp:)/i.test(h)) continue;
    try { const u = new URL(h, baseUrl); if (base && u.hostname.replace(/^www\./, "") === base.hostname.replace(/^www\./, "")) internal++; else { external++; extHosts.add(u.hostname); if (/nofollow/i.test(a.rel || "")) nofollowExt++; } } catch {}
  }
  A.links = { internal, external, nofollowExternal: nofollowExt, emptyHref, externalHosts: [...extHosts].slice(0, 15) };
  const thirdParty = new Set(); const abs = (u) => { try { return new URL(u, baseUrl); } catch { return null; } };
  for (const s of A.scripts) { const u = abs(s.src); if (u && base && u.hostname !== base.hostname) thirdParty.add(u.hostname); }
  for (const s of A.stylesheets) { const u = abs(s.href); if (u && base && u.hostname !== base.hostname) thirdParty.add(u.hostname); }
  A.thirdPartyHosts = [...thirdParty];
  A.externalScriptsNoSri = A.scripts.filter(s => { const u = abs(s.src); return u && base && u.hostname !== base.hostname && !s.integrity; }).length;
  A.externalScriptsTotal = A.scripts.filter(s => { const u = abs(s.src); return u && base && u.hostname !== base.hostname; }).length;
  A.mixed = { active: 0, passive: 0 };
  if (/^https:/i.test(baseUrl)) {
    for (const s of A.scripts) if (/^http:\/\//i.test(s.src)) A.mixed.active++;
    for (const s of A.stylesheets) if (/^http:\/\//i.test(s.href)) A.mixed.active++;
    for (const f of attrs("iframe")) if (/^http:\/\//i.test(f.src || "")) A.mixed.active++;
    for (const s of A.images.srcs) if (/^http:\/\//i.test(s)) A.mixed.passive++;
  }
  A.forms = attrs("form").map(f => ({ action: f.action || "", method: (f.method || "get").toLowerCase() }));
  A.hasPasswordField = attrs("input").some(i => /^password$/i.test(i.type || ""));
  A.insecureForm = /^https:/i.test(baseUrl) ? A.forms.some(f => /^http:\/\//i.test(f.action)) : (A.hasPasswordField || A.forms.some(f => /^http:/i.test(f.action)));
  A.directoryListing = /^Index of \//i.test(A.title || "") || A.h1.some(x => /^Index of \//i.test(x));
  return A;
}

// ---------- Teknoloji tespiti ----------
function detectTech(html, headers, cookies, genMeta) {
  const out = []; const h = headers || {}; const s = (k) => String(h[k] || ""); const add = (name, cat, version) => { if (!out.find(o => o.name === name)) out.push({ name, category: cat, version: version || null }); };
  const server = s("server"); const sv = server.match(/^([A-Za-z\-]+)\/?([\d.]+)?/);
  if (/nginx/i.test(server)) add("nginx", "Sunucu", (server.match(/nginx\/([\d.]+)/i) || [])[1]);
  if (/apache/i.test(server)) add("Apache", "Sunucu", (server.match(/Apache\/([\d.]+)/i) || [])[1]);
  if (/microsoft-iis/i.test(server)) add("IIS", "Sunucu", (server.match(/IIS\/([\d.]+)/i) || [])[1]);
  if (/litespeed/i.test(server)) add("LiteSpeed", "Sunucu"); if (/openresty/i.test(server)) add("OpenResty", "Sunucu"); if (/caddy/i.test(server)) add("Caddy", "Sunucu"); if (/gunicorn/i.test(server)) add("Gunicorn", "Sunucu"); if (/kestrel/i.test(server)) add("Kestrel", "Sunucu");
  const xp = s("x-powered-by"); if (xp) { const m = xp.match(/^([A-Za-z.\-+ ]+?)\/?([\d.]+)?$/); add(m ? m[1].trim() : xp, "Çatı", m && m[2]); }
  if (h["x-aspnet-version"]) add("ASP.NET", "Çatı", s("x-aspnet-version")); if (h["x-drupal-cache"] || /drupal/i.test(s("x-generator"))) add("Drupal", "CMS");
  if (h["cf-ray"]) add("Cloudflare", "CDN/WAF"); if (h["x-vercel-id"]) add("Vercel", "Barındırma"); if (h["x-nf-request-id"]) add("Netlify", "Barındırma"); if (h["x-amz-cf-id"]) add("CloudFront", "CDN/WAF");
  const gen = genMeta ? String(genMeta).slice(0, 200) : null;
  if (gen) { const m = gen.match(/^([A-Za-z .]+?)\s*v?([\d.]+)?$/); if (/wordpress/i.test(gen)) add("WordPress", "CMS", (gen.match(/([\d.]+)/) || [])[1]); else if (/joomla/i.test(gen)) add("Joomla", "CMS"); else if (/drupal/i.test(gen)) add("Drupal", "CMS"); else if (/wix/i.test(gen)) add("Wix", "CMS"); else if (/ghost/i.test(gen)) add("Ghost", "CMS"); else if (/hugo/i.test(gen)) add("Hugo", "Statik"); else if (/gatsby/i.test(gen)) add("Gatsby", "Statik"); else if (/webflow/i.test(gen)) add("Webflow", "CMS"); else add(m ? m[1].trim() : gen, "CMS", m && m[2]); }
  const T = [[/wp-content|wp-includes/i, "WordPress", "CMS"], [/\/sites\/(default|all)\/(files|modules|themes)/i, "Drupal", "CMS"], [/cdn\.shopify\.com|Shopify\.theme/i, "Shopify", "E-ticaret"], [/static\.wixstatic\.com/i, "Wix", "CMS"], [/squarespace\.com|static1\.squarespace/i, "Squarespace", "CMS"],
    [/assets\.website-files\.com|data-wf-page/i, "Webflow", "CMS"], [/__NEXT_DATA__|\/_next\/static/i, "Next.js", "Çatı"], [/__NUXT__|\/_nuxt\//i, "Nuxt", "Çatı"], [/id=["']___gatsby/i, "Gatsby", "Çatı"], [/ng-version=|ng-app|<app-root/i, "Angular", "Çatı"], [/data-reactroot|react(?:\.production|-dom)/i, "React", "Kütüphane"],
    [/vue(?:\.runtime|\.min)?\.js|data-v-[a-f0-9]{6,}|__vue__/i, "Vue.js", "Kütüphane"], [/svelte-[a-z0-9]{5,}/i, "Svelte", "Kütüphane"], [/prestashop/i, "PrestaShop", "E-ticaret"], [/\/skin\/frontend\/|Mage\.Cookies|magento/i, "Magento", "E-ticaret"], [/woocommerce/i, "WooCommerce", "E-ticaret"],
    [/ticimax|tsoft|ideasoft|ikas/i, "TR E-ticaret altyapısı", "E-ticaret"], [/googletagmanager\.com\/gtm\.js/i, "Google Tag Manager", "Analitik"], [/google-analytics\.com\/(analytics|ga)\.js|gtag\/js\?id=G-|googletagmanager\.com\/gtag/i, "Google Analytics", "Analitik"], [/connect\.facebook\.net\/[^"'\s]{0,200}fbevents/i, "Meta Pixel", "Analitik"],
    [/static\.hotjar\.com/i, "Hotjar", "Analitik"], [/js\.hs-scripts\.com|hubspot/i, "HubSpot", "Pazarlama"], [/cdn\.jsdelivr|cdnjs\.cloudflare/i, "Genel CDN kütüphaneleri", "CDN"], [/bootstrap(?:\.min)?\.(?:css|js)|class=["'][^"']*\bcol-(?:md|lg|sm)-\d/i, "Bootstrap", "UI"], [/tailwind/i, "Tailwind CSS", "UI"],
    [/recaptcha\/api\.js|g-recaptcha/i, "reCAPTCHA", "Güvenlik"], [/challenges\.cloudflare\.com\/turnstile/i, "Cloudflare Turnstile", "Güvenlik"], [/cookiebot|cookieconsent|onetrust|kvkk|cerez/i, "Çerez onay aracı", "Uyumluluk"]];
  for (const [re, name, cat] of T) if (re.test(html)) add(name, cat);
  const jq = html.match(/jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i) || html.match(/jquery\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)/i); if (jq || /jquery/i.test(html)) add("jQuery", "Kütüphane", jq && jq[1]);
  const bs = html.match(/bootstrap(?:@|\/|-)(\d+\.\d+(?:\.\d+)?)/i); if (bs) { const b = out.find(o => o.name === "Bootstrap"); if (b) b.version = bs[1]; else add("Bootstrap", "UI", bs[1]); }
  const ck = (cookies || []).map(c => String(c).split("=")[0]); if (ck.includes("PHPSESSID")) add("PHP", "Dil"); if (ck.some(c => /^ASP\.NET_SessionId|ASPSESSIONID/i.test(c))) add("ASP.NET", "Çatı"); if (ck.includes("JSESSIONID")) add("Java", "Dil"); if (ck.some(c => /laravel_session/.test(c))) add("Laravel", "Çatı"); if (ck.includes("csrftoken") || ck.includes("django_language")) add("Django", "Çatı");
  return out;
}
// ---------- Sayfa durumu: askıya alınmış / park / varsayılan sunucu sayfası ----------
function detectPageState(html, title, status, bytes) {
  const t = String(title || "").toLowerCase(); const b = String(html || "").slice(0, 60000).toLowerCase(); const states = [];
  if (/account (has been )?suspended|this account is suspended|hesab[ıi]n[ıi]z askıya|bandwidth limit exceeded|resource limit is reached|site (is )?suspended/.test(b)) states.push("suspended");
  if (/this domain (is|may be) for sale|buy this domain|domain is parked|parked (free|domain)|sedo\.com\/search|domain satılık|bu alan adı satılık|hugedomains|dan\.com\/|afternic|parkingcrew|bodis\.com|this web page is parked/.test(b) || /^(domain for sale|parked)/.test(t)) states.push("parked");
  if (/welcome to nginx!|apache2 (ubuntu|debian) default page|apache http server test page|it works!?<\/h1>|iis windows server|welcome to iis|default web site page|test page for the (apache|nginx)|plesk (obsidian|onyx)|cpanel.*default|congratulations.*(web ?server|installed)|web server's default page/.test(b) || /^(welcome to nginx|apache2.*default page|iis windows server)/.test(t)) states.push("default_page");
  if (/under construction|coming soon|yapım aşamasında|çok yakında|site is being built|launching soon/.test(b) && (bytes || b.length) < 25000) states.push("under_construction");
  if (/maintenance mode|scheduled maintenance|we('| a)re (currently )?(down for|undergoing) maintenance|bakım(da| çalışması)|site bakımda|be right back/.test(b) || (status === 503 && /maintenance|bakım/.test(b))) states.push("maintenance");
  if (/error establishing a database connection|fatal error:.{0,300}on line \d+|warning:.{0,300}on line \d+|parse error:|mysqli?_connect|sqlstate\[|unhandled exception|server error in '\/' application|stack trace:/.test(b)) states.push("app_error");
  return states;
}

// ---------- robots.txt + sitemap ----------
async function loadSiteFiles(origin, pageHost) {
  const [robots, sm] = await Promise.all([httpProbe(origin + "/robots.txt", { timeout: 7000, maxRedirects: 3, noUaFallback: true, maxBytes: 300000 }), httpProbe(origin + "/sitemap.xml", { timeout: 8000, maxRedirects: 3, noUaFallback: true, maxBytes: 1500000 })]);
  const robotsOk = robots.status === 200 && !/<html[\s>]/i.test(String(robots.body).slice(0, 500)); const rtxt = robotsOk ? robots.body : "";
  const groups = []; let cur = null;
  for (const line of rtxt.split(/\r?\n/)) { const l = line.replace(/#.*/, "").trim(); if (!l) continue; const m = l.match(/^([a-z\-]+)\s*:\s*(.*)$/i); if (!m) continue; const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === "user-agent") { if (!cur || cur.rules.length) { cur = { agents: [], rules: [] }; groups.push(cur); } cur.agents.push(v.toLowerCase()); } else if (cur && ["allow", "disallow", "crawl-delay"].includes(k)) cur.rules.push([k, v]); }
  const star = groups.find(g => g.agents.includes("*")); const blocksAll = !!star && star.rules.some(([k, v]) => k === "disallow" && v === "/") && !star.rules.some(([k, v]) => k === "allow" && v === "/");
  const blocksGoogle = groups.some(g => g.agents.includes("googlebot") && g.rules.some(([k, v]) => k === "disallow" && v === "/"));
  const sitemapsInRobots = [...rtxt.matchAll(/^\s*sitemap\s*:\s*(\S+)/gim)].map(m => m[1]);
  let smBody = sm.status === 200 ? sm.body : ""; let smUrl = origin + "/sitemap.xml";
  if (!/<urlset|<sitemapindex/i.test(smBody) && sitemapsInRobots.length) { const r2 = await httpProbe(sitemapsInRobots[0], { timeout: 8000, maxRedirects: 3, noUaFallback: true, maxBytes: 1500000 }); if (r2.status === 200) { smBody = r2.body; smUrl = sitemapsInRobots[0]; } }
  const isSm = /<urlset|<sitemapindex/i.test(smBody); const locs = isSm ? [...smBody.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map(m => decodeEntities(m[1])) : [];
  let sample = null;
  if (isSm && locs.length && !/<sitemapindex/i.test(smBody)) { const pick = locs[0]; const r = await httpProbe(pick, { timeout: 8000, maxRedirects: 3, noUaFallback: true, readBody: false }); sample = { url: pick, status: r.status }; }
  return { robots: { exists: robotsOk, status: robots.status, blocksAll, blocksGooglebot: blocksGoogle, groups: groups.length, sitemapDirectives: sitemapsInRobots.length, crawlDelay: !!(star && star.rules.some(([k]) => k === "crawl-delay")), size: rtxt.length },
    sitemap: { exists: isSm || sitemapsInRobots.length > 0, valid: isSm, url: isSm ? smUrl : null, isIndex: /<sitemapindex/i.test(smBody), urlCount: locs.length, firstUrl: sample, otherHost: locs.length ? locs.slice(0, 20).some(u => { try { return new URL(u).hostname.replace(/^www\./, "") !== String(pageHost).replace(/^www\./, ""); } catch { return false; } }) : false } };
}

// ---------- Ortak kontrol setleri ----------
function seoChecks(c, ctx) {
  const { main, A, files, finalUrl } = ctx; const h = main.headers || {}; const xrobots = String(h["x-robots-tag"] || "").toLowerCase();
  const spa = A.spaShell; const title = A.title, desc = A.metaDescription;
  c.add(!!title, 10, "finding_seo_missing_title_critical", "icerik");
  if (title) c.add(title.length >= 30 && title.length <= 65, 5, "finding_seo_title_length_warning", "icerik");
  c.add(!!desc, 10, "finding_seo_missing_description_warning", "icerik");
  if (desc) c.add(desc.length >= 70 && desc.length <= 165, 4, "finding_seo_description_length_warning", "icerik");
  if (!spa) { c.add(A.h1Count === 1, 8, A.h1Count === 0 ? "finding_seo_missing_h1_warning" : "finding_seo_multiple_h1_warning", "icerik"); c.add(A.wordCount >= 300, 4, "finding_seo_thin_content_warning", "icerik"); }
  c.add(!A.images.total || A.images.missingAlt / A.images.total <= 0.1, 5, "finding_seo_images_missing_alt_warning", "icerik");
  const noindex = /noindex/.test(A.robotsMeta) || /noindex/.test(A.googlebotMeta) || /noindex/.test(xrobots);
  c.add(!noindex, 15, "finding_seo_noindex_critical", "teknik");
  c.add(!files.robots.blocksAll && !files.robots.blocksGooglebot, 15, "finding_seo_robots_blocks_all_critical", "teknik");
  c.add(!!A.canonical, 5, "finding_seo_missing_canonical_warning", "teknik");
  if (A.canonical) { try { const cu = new URL(A.canonical, finalUrl); const fu = new URL(finalUrl); c.add(cu.hostname.replace(/^www\./, "") === fu.hostname.replace(/^www\./, ""), 4, "finding_seo_canonical_other_host_warning", "teknik"); } catch { c.add(false, 4, "finding_seo_canonical_invalid_warning", "teknik"); } }
  c.add(files.robots.exists, 4, "finding_seo_missing_robots_warning", "teknik");
  c.add(files.sitemap.exists, 6, "finding_seo_missing_sitemap_warning", "teknik");
  if (files.sitemap.valid) { c.add(files.sitemap.urlCount > 0, 3, "finding_seo_sitemap_empty_warning", "teknik"); if (files.sitemap.firstUrl) c.add(files.sitemap.firstUrl.status >= 200 && files.sitemap.firstUrl.status < 400, 3, "finding_seo_sitemap_broken_urls_warning", "teknik"); if (files.sitemap.otherHost) c.add(false, 3, "finding_seo_sitemap_other_host_warning", "teknik"); }
  c.add(/^https:/i.test(finalUrl), 6, "finding_seo_not_https_warning", "teknik");
  c.add(!!A.viewport, 6, "finding_seo_missing_viewport_warning", "teknik");
  c.add(!!A.htmlLang, 4, "finding_seo_missing_lang_warning", "teknik");
  c.add(A.hasFavicon, 2, "finding_seo_missing_favicon_warning", "teknik");
  c.add(!!A.charset || /charset=/i.test(String(h["content-type"] || "")), 2, "finding_seo_missing_charset_warning", "teknik");
  c.add(main.status === 200, 5, "finding_seo_final_status_warning", "teknik");
  c.add((main.redirects || 0) <= 2, 3, "finding_seo_redirect_chain_warning", "teknik");
  if (A.hreflang.length) { c.add(A.hreflang.some(x => /x-default/i.test(x.lang)), 3, "finding_seo_hreflang_no_default_warning", "sosyal"); }
  const og = A.og; c.add(!!(og.title && og.description && og.image), 4, "finding_seo_missing_open_graph_warning", "sosyal");
  c.add(!!A.twitterCard, 2, "finding_seo_missing_twitter_card_warning", "sosyal");
  c.add(A.jsonld.blocks > 0, 4, "finding_seo_missing_structured_data_warning", "sosyal");
  if (A.jsonld.blocks) c.add(A.jsonld.invalid === 0, 3, "finding_seo_structured_data_invalid_warning", "sosyal");
  c.add(A.links.internal >= 3 || spa, 3, "finding_seo_few_internal_links_warning", "sosyal");
  return spa ? ["finding_seo_client_rendered_info"] : [];
}
function securityHeaderChecks(c, ctx) {
  const { main, A, finalUrl } = ctx; const h = main.headers || {}; const https = /^https:/i.test(finalUrl);
  const hsts = String(h["strict-transport-security"] || ""); const maxAge = parseInt((hsts.match(/max-age=(\d+)/i) || [])[1] || "0", 10); const csp = String(h["content-security-policy"] || "");
  c.add(https, 12, "finding_security_not_https_critical", "aktarim");
  if (https) c.add(!!hsts && maxAge >= 15552000, 12, hsts ? "finding_security_hsts_short_warning" : "finding_security_missing_hsts_warning", "basliklar");
  c.add(!!csp, 12, "finding_security_missing_csp_warning", "basliklar");
  if (csp) { c.add(!/unsafe-inline|unsafe-eval/.test(csp), 5, "finding_security_csp_unsafe_warning", "basliklar"); c.add(!/(default-src|script-src)[^;]*(\s\*|\sdata:|\shttp:)/i.test(csp), 3, "finding_security_csp_weak_warning", "basliklar"); }
  c.add(!!h["x-frame-options"] || /frame-ancestors/.test(csp), 8, "finding_security_missing_clickjacking_warning", "basliklar");
  c.add(/nosniff/i.test(String(h["x-content-type-options"] || "")), 6, "finding_security_missing_nosniff_warning", "basliklar");
  c.add(!!h["referrer-policy"], 5, "finding_security_missing_referrer_policy_warning", "basliklar");
  c.add(!!h["permissions-policy"] || !!h["feature-policy"], 4, "finding_security_missing_permissions_policy_warning", "basliklar");
  const disclosure = /\d+\.\d+/.test(String(h["server"] || "")) || /\d+\.\d+/.test(String(h["x-powered-by"] || "")) || !!h["x-aspnet-version"] || !!h["x-aspnetmvc-version"];
  c.add(!disclosure, 4, "finding_security_version_disclosure_warning", "basliklar");
  const cookies = [].concat(main.cookies || h["set-cookie"] || []).map(x => ({ name: String(x).split("=")[0], secure: /;\s*secure/i.test(x), httpOnly: /;\s*httponly/i.test(x), sameSite: (String(x).match(/samesite=(\w+)/i) || [])[1] || null }));
  c.add(!cookies.length || cookies.every(k => (!https || k.secure) && k.httpOnly && k.sameSite), 6, "finding_security_cookie_flags_warning", "aktarim");
  if (cookies.some(k => k.sameSite && k.sameSite.toLowerCase() === "none" && !k.secure)) c.add(false, 3, "finding_security_cookie_samesite_none_warning", "aktarim");
  c.add(A.mixed.active === 0, 6, "finding_security_mixed_content_critical", "aktarim"); c.add(A.mixed.passive === 0, 2, "finding_security_mixed_content_passive_warning", "aktarim");
  c.add(!A.insecureForm, 8, "finding_security_insecure_form_critical", "aktarim");
  c.add(!A.directoryListing, 6, "finding_security_directory_listing_critical", "dosyalar");
  if (A.externalScriptsTotal) c.add(A.externalScriptsNoSri === 0, 3, "finding_security_no_sri_info", "basliklar");
  return { cookies, hsts: hsts || null, hstsMaxAgeDays: Math.floor(maxAge / 86400), csp: !!csp, disclosure };
}

// =====================================================================
// SAYFA ÇEKME (www/apex yedeği, http yedeği, hata nedeni)
// =====================================================================
async function getPage(targetUrl, o = {}) {
  const url = ensureUrl(targetUrl); const typedScheme = /^https?:\/\//i.test(String(targetUrl || "").trim());
  let main = await httpProbe(url, { timeout: 10000, maxRedirects: 8, ...o }); let variant = null, httpOnly = false;
  const kind = main.errorInfo?.kind;
  // Yedek denemeler yalnızca HIZLI başarısızlıklarda (DNS/ret/TLS/reset); zaman aşımında beklemeyi uzatmayız
  if (main.status === 0 && ["dns", "refused", "reset", "unreachable", "tls"].includes(kind)) {
    try {
      const u = new URL(url); const tasks = [];
      if (!net.isIP(u.hostname)) { const alt = new URL(url); alt.hostname = u.hostname.startsWith("www.") ? u.hostname.slice(4) : "www." + u.hostname; tasks.push(httpProbe(alt.toString(), { timeout: 8000, maxRedirects: 8, ...o }).then(r => ({ t: "variant", r, host: alt.hostname }))); }
      if (u.protocol === "https:" && (!typedScheme || ["refused", "tls", "reset"].includes(kind))) { const hu = new URL(url); hu.protocol = "http:"; tasks.push(httpProbe(hu.toString(), { timeout: 8000, maxRedirects: 8, ...o }).then(r => ({ t: "http", r }))); }
      const outs = await Promise.all(tasks);
      const v = outs.find(x => x.t === "variant" && x.r.status > 0); if (v) { main = v.r; variant = { from: u.hostname, to: v.host }; }
      else { const h = outs.find(x => x.t === "http" && x.r.status > 0); if (h) { main = h.r; httpOnly = !/^https:/i.test(h.r.finalUrl); } }
    } catch {}
  }
  return { url, main, variant, httpOnly, prot: main.status ? detectBotProtection(main) : null };
}
const isHtml = (m) => /html|xml/i.test(String(m.contentType || m.headers?.["content-type"] || "")) || /<html|<!doctype/i.test(String(m.body || "").slice(0, 2000));

// ---------- Performans kontrol seti ----------
async function sampleAssets(A, baseUrl, imgLimit = 5) {
  const abs = (u) => { try { return new URL(u, baseUrl).toString(); } catch { return null; } };
  const css = A.stylesheets.map(s => ({ u: abs(s.href), kind: "css" })), js = A.scripts.map(s => ({ u: abs(s.src), kind: "js" })), img = A.images.srcs.slice(0, imgLimit).map(s => ({ u: abs(s), kind: "img" }));
  const seen = new Set(); const list = [...css.slice(0, 6), ...js.slice(0, 8), ...img].filter(x => x.u && /^https?:/i.test(x.u) && !seen.has(x.u) && seen.add(x.u)).slice(0, 18);
  const rows = await pool(list, 6, async (x) => { const r = await request(x.u, { timeout: 8000, readBody: false, maxBytes: 1500000, insecure: true }); return { ...x, status: r.status, transfer: r.transferBytes, raw: r.rawBytes, enc: r.encoding, cache: String(r.headers["cache-control"] || ""), ctype: r.contentType || "", ttfb: r.ttfb }; });
  return rows.filter(Boolean);
}
function perfChecks(c, ctx) {
  const { main, A, assets, tlsi, dnsMs } = ctx; const h = main.headers || {};
  const compressed = ["gzip", "br", "deflate", "zstd"].includes(main.encoding || ""); const textType = /text|json|javascript|xml/i.test(String(h["content-type"] || ""));
  const ttfb = main.ttfb; const chainMs = (main.chain || []).reduce((s, x) => s + (x.ms || 0), 0);
  c.add(ttfb != null ? ttfb < 600 : null, 18, "finding_perf_slow_ttfb_warning", "sunucu"); c.add(ttfb != null ? ttfb < 1500 : null, 12, "finding_perf_very_slow_ttfb_critical", "sunucu"); c.add(chainMs < 3000, 10, "finding_perf_slow_load_warning", "sunucu");
  c.add(!textType || compressed, 12, "finding_perf_no_compression_warning", "agi");
  c.add(tlsi ? (tlsi.alpn === "h2" || /h3/.test(String(h["alt-svc"] || ""))) : null, 8, "finding_perf_no_http2_warning", "agi");
  c.add((main.redirects || 0) <= 2, 6, "finding_perf_redirect_chain_warning", "agi");
  if (tlsi) c.add(tlsi.handshakeMs < 600, 3, "finding_perf_slow_tls_warning", "agi");
  if (dnsMs != null) c.add(dnsMs < 300, 2, "finding_perf_slow_dns_warning", "agi");
  const sized = assets.filter(a => a.status > 0 && a.status < 400); const sum = (k) => sized.filter(a => a.kind === k).reduce((s, a) => s + (a.transfer || 0), 0);
  const weight = (main.transferBytes || 0) + sized.reduce((s, a) => s + (a.transfer || 0), 0); const jsBytes = sum("js"), cssBytes = sum("css"), imgBytes = sum("img");
  c.add(weight < 2000000, 8, "finding_perf_heavy_page_warning", "sayfa"); c.add(jsBytes < 600000, 5, "finding_perf_heavy_js_warning", "sayfa"); c.add(cssBytes < 200000, 3, "finding_perf_heavy_css_warning", "sayfa");
  const blocking = A.scripts.filter(s => !s.async && !s.defer && !s.module).length;
  c.add(blocking <= 3, 6, "finding_perf_render_blocking_scripts_warning", "sayfa"); c.add(A.scripts.length <= 20, 4, "finding_perf_too_many_scripts_warning", "sayfa");
  c.add(A.images.total < 5 || A.images.lazy > 0, 4, "finding_perf_no_lazy_loading_warning", "sayfa");
  c.add(!A.images.total || A.images.noDimensions / A.images.total <= 0.3, 3, "finding_perf_images_no_dimensions_warning", "sayfa");
  c.add(A.thirdPartyHosts.length <= 10, 4, "finding_perf_many_third_parties_warning", "sayfa"); c.add(A.domNodes < 2500, 3, "finding_perf_large_dom_warning", "sayfa");
  const bigImgs = sized.filter(a => a.kind === "img" && a.transfer > 400000).length; c.add(bigImgs === 0, 4, "finding_perf_large_images_warning", "sayfa");
  const stat = sized.filter(a => a.kind !== "img");
  if (stat.length) { const cached = stat.filter(a => { const m = a.cache.match(/max-age=(\d+)/); return m && parseInt(m[1], 10) >= 86400 || /immutable/.test(a.cache); }).length; c.add(cached === stat.length, 8, "finding_perf_weak_caching_warning", "agi"); const comp = stat.filter(a => a.enc).length; c.add(comp === stat.length || stat.every(a => !/javascript|css/.test(a.ctype)), 4, "finding_perf_assets_not_compressed_warning", "agi"); }
  return { blocking, weight, jsBytes, cssBytes, imgBytes, sized, chainMs };
}

// =====================================================================
// 1. WEB SCANNER v4 (erişim + içerik durumu + güvenlik başlıkları + SEO + performans + teknoloji)
// =====================================================================
async function scanWebsite(targetUrl, extra = {}) {
  const startedAt = Date.now(); const V = "web-analyzer-v13.5"; const errors = [];
  if (!targetUrl) return { data: null, findings: ["finding_web_missing_target_critical"], errors: ["targetUrl yok"] };
  const { url, main, variant, httpOnly, prot } = await getPage(targetUrl);
  const host = hostOf(main.finalUrl || url);
  if (prot) {
    const tlsQuick = host && /^https:/i.test(main.finalUrl) ? await getTlsDetails(host).catch(() => null) : null;
    const specificAnalysis = { url, finalUrl: main.finalUrl, status: main.status, responseTimeMs: main.responseTimeMs, server: main.headers["server"] || null, techStack: [prot], botProtection: { detected: true, provider: prot, note: "Site bot koruması arkasında; tarayıcı doğrulama sayfası aldı. Site büyük olasılıkla çalışıyor, SEO ve güvenlik başlığı analizi yapılamadı." },
      certificate: tlsQuick ? { daysRemaining: Math.floor((new Date(tlsQuick.cert.valid_to) - Date.now()) / 864e5), issuer: tlsQuick.cert.issuer?.O || tlsQuick.cert.issuer?.CN, protocol: tlsQuick.protocol } : null };
    const commonAnalysis = { analyzerVersion: V, executionTimeMs: Date.now() - startedAt, findings: ["finding_web_bot_protection_info"], scannedAt: new Date().toISOString(), score: null, status: "PROTECTED", target: url };
    return { data: { assetType: "WEB", commonAnalysis, specificAnalysis, analysisMeta: { scannerVersion: V, analyzer: "web", limited: true } }, findings: ["finding_web_bot_protection_info"], errors, statusHint: "PROTECTED" };
  }
  const cAv = makeChecker(), cSec = makeChecker(), cSeo = makeChecker(), cPerf = makeChecker(); const findings = [];
  if (main.status === 0) {
    findings.push(netErrorFinding("web", main), "finding_web_down_critical"); errors.push(main.error || "erişilemedi");
    const dnsInfo = host ? await resolveIps(host) : null;
    return buildResult({ assetType: "WEB", version: V, startedAt, target: url, findings, score: 0, status: "DOWN", errors,
      specific: { url, status: 0, error: main.error || null, errorKind: main.errorInfo?.kind || null, errorCode: main.errorInfo?.code || null, dnsResolves: dnsInfo ? (dnsInfo.v4.length + dnsInfo.v6.length > 0) : null, triedVariants: variant, scores: { availability: 0 } } });
  }
  const finalUrl = main.finalUrl; const html = main.body || ""; const html_ = isHtml(main);
  const A = analyzeHtml(html, finalUrl); const origin = new URL(finalUrl).origin; const finalHost = new URL(finalUrl).hostname;
  const alt = (() => { try { const u = new URL(finalUrl); u.hostname = u.hostname.startsWith("www.") ? u.hostname.slice(4) : "www." + u.hostname; u.pathname = "/"; u.search = ""; return net.isIP(finalHost) ? null : u.toString(); } catch { return null; } })();
  const [files, altProbe, soft404, tlsDet, tlsi, assets, dnsT] = await Promise.all([
    html_ ? loadSiteFiles(origin, finalHost).catch(() => ({ robots: { exists: false }, sitemap: { exists: false } })) : { robots: { exists: false }, sitemap: { exists: false } },
    alt ? httpProbe(alt, { timeout: 8000, maxRedirects: 3, noUaFallback: true, readBody: false }) : null,
    httpProbe(origin + "/__dac_" + Math.random().toString(36).slice(2, 9), { timeout: 7000, maxRedirects: 1, noUaFallback: true, readBody: false }),
    /^https:/i.test(finalUrl) ? getTlsDetails(finalHost, new URL(finalUrl).port || 443).catch(() => null) : null,
    /^https:/i.test(finalUrl) ? tlsAlpn(finalHost) : null,
    html_ ? sampleAssets(A, finalUrl, 3).catch(() => []) : [],
    (async () => { const t = Date.now(); try { await dns.lookup(finalHost); return Date.now() - t; } catch { return null; } })()
  ]);
  // --- erişilebilirlik ---
  const state = html_ ? detectPageState(html, A.title, main.status, A.htmlBytes) : [];
  cAv.add(main.status < 500, 30, "finding_web_server_error_critical"); 
  cAv.add(main.status < 400, 25, `finding_web_status_${main.status}_${[401, 403].includes(main.status) ? "warning" : "critical"}`);
  cAv.add(!main.redirectLoop, 10, "finding_web_redirect_loop_critical");
  cAv.add(main.responseTimeMs < 3000, 8, "finding_web_slow_warning"); cAv.add(main.responseTimeMs < 1500, 4, null);
  cAv.add(!state.includes("suspended"), 25, "finding_web_suspended_critical"); cAv.add(!state.includes("parked"), 20, "finding_web_parked_warning");
  cAv.add(!state.includes("default_page"), 12, "finding_web_default_page_warning"); cAv.add(!state.includes("app_error"), 12, "finding_web_app_error_critical");
  cAv.add(!(html_ && main.status === 200 && A.htmlBytes < 120 && !A.title), 6, "finding_web_empty_response_warning");
  if (httpOnly) cAv.add(false, 15, "finding_web_no_https_critical");
  if (main.tlsError) cAv.add(false, 20, "finding_web_tls_error_critical");
  if (variant) cAv.add(false, 4, "finding_web_variant_unreachable_warning");
  if (altProbe) cAv.add(altProbe.status > 0 && altProbe.status < 500, 4, "finding_web_www_inconsistent_warning");
  if (main.status < 400) cAv.add(soft404.status === 404 || soft404.status === 410 || soft404.status === 0 || (soft404.status >= 300 && soft404.status < 400), 4, "finding_web_soft_404_warning");
  const extraF = []; if (state.includes("under_construction")) extraF.push("finding_web_under_construction_info"); if (state.includes("maintenance")) extraF.push("finding_web_maintenance_info");
  if (main.uaFallback) extraF.push("finding_web_blocks_unknown_agents_info");
  // --- güvenlik başlıkları (hafif) ---
  const sec = securityHeaderChecks(cSec, { main, A, finalUrl });
  if (tlsDet) { const d = Math.floor((new Date(tlsDet.cert.valid_to) - Date.now()) / 864e5); cSec.add(d >= 0, 15, "finding_web_ssl_expired_critical", "aktarim"); if (d >= 0) { cSec.add(d >= 14, 8, "finding_web_ssl_expiring_critical", "aktarim"); cSec.add(d >= 30, 2, "finding_web_ssl_expiring_warning", "aktarim"); } cSec.add(["TLSv1.2", "TLSv1.3"].includes(tlsDet.protocol), 5, "finding_security_tls_old_warning", "aktarim"); }
  // --- SEO ---
  let seoInfo = []; if (html_) seoInfo = seoChecks(cSeo, { main, A, files, finalUrl }); else cSeo.add(null, 1, null);
  // --- performans ---
  const perf = html_ ? perfChecks(cPerf, { main, A, assets, tlsi, dnsMs: dnsT }) : { blocking: 0, weight: main.transferBytes, sized: [] };
  // --- teknoloji ve sürüm uyarıları ---
  const tech = detectTech(html, main.headers, main.cookies || [], A.generator);
  const verOf = (n) => (tech.find(t => t.name === n) || {}).version;
  const php = verOf("PHP"); if (php && /^[0-5]\.|^7\.[0-3]/.test(php)) cSec.add(false, 5, "finding_web_eol_php_warning", "basliklar");
  const jq = verOf("jQuery"); if (jq && /^1\.|^2\./.test(jq)) cSec.add(false, 3, "finding_web_old_jquery_warning", "basliklar");
  const bs = verOf("Bootstrap"); if (bs && /^[1-3]\./.test(bs)) cSec.add(false, 2, "finding_web_old_bootstrap_warning", "basliklar");
  const wp = verOf("WordPress"); if (tech.find(t => t.name === "WordPress") && wp && parseFloat(wp) < 6.0) cSec.add(false, 5, "finding_web_old_wordpress_warning", "basliklar");
  // --- skor ---
  const gs = { availability: cAv.score(), security: cSec.score(), seo: cSeo.score(), performance: cPerf.score() };
  let overall = SCORING.webLegacyOverall(gs); // ağırlıklar scoring.js > WEB_LEGACY_WEIGHTS (davranış değişmedi)
  const all = sortFindings([...cAv.findings(), ...cSec.findings(), ...cSeo.findings(), ...cPerf.findings(), ...extraF, ...seoInfo]);
  if (overall != null) {
    if (all.some(f => /web_suspended|web_app_error|web_server_error|web_redirect_loop|web_tls_error|web_no_https|web_status_\d+_critical/.test(f))) overall = Math.min(overall, 35);
    if (all.includes("finding_web_parked_warning")) overall = Math.min(overall, 45);
    if (all.includes("finding_web_ssl_expired_critical")) overall = Math.min(overall, 25);
    if (all.includes("finding_seo_noindex_critical") || all.includes("finding_seo_robots_blocks_all_critical")) overall = Math.min(overall, 60);
  }
  // Bileşik skor (SEO %35 + Güvenlik %50 + Performans %15; kritik bulguda 75 sınırı) — ayrıntı ve gerekçe: scoring.js
  const composite = SCORING.computeComposite({ seo: gs.seo, security: gs.security, performance: gs.performance }, all);
  const down = main.status >= 500 || (main.status >= 400 && ![401, 403].includes(main.status)) || state.includes("suspended");
  const status = down ? (main.status >= 500 || state.includes("suspended") ? "DOWN" : "CRITICAL") : statusFromScore(overall ?? 0);
  const securityHeaders = { hsts: !!main.headers["strict-transport-security"], csp: !!main.headers["content-security-policy"], xFrame: !!main.headers["x-frame-options"], xContentType: !!main.headers["x-content-type-options"], referrerPolicy: !!main.headers["referrer-policy"], permissionsPolicy: !!(main.headers["permissions-policy"] || main.headers["feature-policy"]) };
  const specific = {
    url, finalUrl, status: main.status, responseTimeMs: main.responseTimeMs, ttfbMs: main.ttfb, redirectChain: (main.chain || []).map(x => `${x.status} ${x.url}`), triedVariants: variant, httpOnly,
    title: A.title, metaDescription: A.metaDescription, h1Count: A.h1Count, pageState: state, wordCount: A.wordCount, clientRenderedShell: A.spaShell,
    securityHeaders, cookies: sec.cookies.map(k => `${k.name} (${k.secure ? "Secure" : "!Secure"}, ${k.httpOnly ? "HttpOnly" : "!HttpOnly"}, SameSite=${k.sameSite || "yok"})`),
    techStack: tech.map(t => t.version ? `${t.name} ${t.version}` : t.name), technologies: tech, server: main.headers["server"] || null,
    robots: { exists: !!files.robots.exists, status: files.robots.status ?? null, blocksAll: !!files.robots.blocksAll }, sitemap: { exists: !!files.sitemap.exists, valid: !!files.sitemap.valid, urlCount: files.sitemap.urlCount ?? null },
    tls: tlsDet ? (() => { const d = Math.floor((new Date(tlsDet.cert.valid_to) - Date.now()) / 864e5); return { protocol: tlsDet.protocol, cipher: tlsDet.cipher?.name, daysRemaining: d, validTo: new Date(tlsDet.cert.valid_to).toISOString(), expiryState: d < 0 ? "EXPIRED" : d <= 7 ? "CRITICAL" : d <= 14 ? "URGENT" : d <= 30 ? "SOON" : "OK", issuer: tlsDet.cert.issuer?.O || tlsDet.cert.issuer?.CN, http2: tlsi?.alpn === "h2" }; })() : null,
    content: { htmlKB: Math.round(A.htmlBytes / 102.4) / 10, images: A.images.total, scripts: A.scripts.length, stylesheets: A.stylesheets.length, thirdPartyHosts: A.thirdPartyHosts.length, links: A.links },
    performance: { ttfbMs: main.ttfb, compression: main.encoding, measuredWeightKB: Math.round((perf.weight || 0) / 102.4) / 10, renderBlockingScripts: perf.blocking },
    scores: { availability: gs.availability, security: gs.security, seo: gs.seo, performance: gs.performance, overall, composite: composite.score, compositeDetail: { rawScore: composite.rawScore, complete: composite.complete, coverage: composite.coverage, capped: composite.capped, missing: composite.missing } }
  };
  const commonAnalysis = { analyzerVersion: V, executionTimeMs: Date.now() - startedAt, findings: all, scannedAt: new Date().toISOString(), score: overall, status, target: url };
  return { data: { assetType: "WEB", commonAnalysis, specificAnalysis: specific, analysisMeta: { scannerVersion: V, analyzer: "web" } }, findings: all, errors, statusHint: status,
    confidence: clamp(100 - (tlsDet === null && /^https:/i.test(finalUrl) ? 10 : 0) - (!html_ ? 10 : 0)) };
}

// =====================================================================
// SEO v2
// =====================================================================
async function scanSeo(targetUrl) {
  const startedAt = Date.now(); const V = "seo-analyzer-v2.0";
  const { url, main, variant, prot } = await getPage(targetUrl);
  if (prot) return protectedResult("SEO", V, startedAt, url, main, prot);
  if (main.status === 0) return downResult("SEO", V, startedAt, url, main, netErrorFinding("seo", main));
  if (main.status >= 500 || main.status === 404 || main.status === 410) return downResult("SEO", V, startedAt, url, main, "finding_seo_unreachable_critical");
  if (!isHtml(main)) return unavailableResult({ assetType: "SEO", version: V, startedAt, target: url, finding: "finding_seo_not_html_info", status: "UNKNOWN", note: "Adres HTML sayfası döndürmüyor (içerik türü: " + (main.contentType || "?") + ").", specific: { url, status: main.status } });
  const finalUrl = main.finalUrl; const A = analyzeHtml(main.body, finalUrl); const origin = new URL(finalUrl).origin; const c = makeChecker();
  const files = await loadSiteFiles(origin, new URL(finalUrl).hostname).catch(() => ({ robots: { exists: false }, sitemap: { exists: false } }));
  const info = seoChecks(c, { main, A, files, finalUrl });
  const state = detectPageState(main.body, A.title, main.status, A.htmlBytes); if (state.includes("parked")) info.push("finding_seo_parked_page_critical");
  let score = c.score(); if (score != null && state.includes("parked")) score = Math.min(score, 30);
  return buildResult({
    assetType: "SEO", version: V, startedAt, target: url, findings: [...c.findings(), ...info], score,
    specific: { url, finalUrl, status: main.status, title: A.title, titleLength: A.title ? A.title.length : 0, metaDescription: A.metaDescription, metaDescriptionLength: A.metaDescription ? A.metaDescription.length : 0, canonical: A.canonical, htmlLang: A.htmlLang,
      h1Count: A.h1Count, h1: A.h1.slice(0, 3), h2Count: A.h2Count, h3Count: A.h3Count, wordCount: A.wordCount, clientRenderedShell: A.spaShell, images: { total: A.images.total, missingAlt: A.images.missingAlt, lazy: A.images.lazy }, links: A.links,
      hreflangCount: A.hreflang.length, hreflang: A.hreflang.slice(0, 10).map(x => x.lang), structuredDataBlocks: A.jsonld.blocks, structuredDataTypes: A.jsonld.types, openGraph: !!(A.og.title && A.og.description && A.og.image), twitterCard: A.twitterCard || null,
      robotsMeta: A.robotsMeta || null, xRobotsTag: main.headers["x-robots-tag"] || null, robotsTxt: !!files.robots.exists, robotsDetails: files.robots, sitemap: !!files.sitemap.exists, sitemapDetails: files.sitemap, pageState: state, triedVariants: variant,
      checks: c.summary(), scores: c.groupScores() }
  });
}

// =====================================================================
// GÜVENLİK v2
// =====================================================================
const jsonHas = (re) => (b) => re.test(b) && !/^\s*<(!doctype|html)/i.test(b);
const EXPOSED = [
  ["env", "/.env", "critical", (b) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(b) && !/<html/i.test(b)], ["git", "/.git/HEAD", "critical", (b) => /^ref:\s*refs\//.test(b.trim())], ["gitconfig", "/.git/config", "critical", (b) => /\[core\]/.test(b) && !/<html/i.test(b)],
  ["svn", "/.svn/wc.db", "critical", (b) => b.startsWith("SQLite format 3")], ["phpinfo", "/phpinfo.php", "critical", (b) => /phpinfo\(\)|PHP Version/i.test(b)], ["dsstore", "/.DS_Store", "warning", (b) => b.startsWith("\u0000\u0000\u0000\u0001Bud1")],
  ["serverstatus", "/server-status", "warning", (b) => /Apache Server Status/i.test(b)], ["wpconfig", "/wp-config.php.bak", "critical", (b) => /DB_PASSWORD|DB_NAME/.test(b)], ["wpconfig", "/wp-config.php.old", "critical", (b) => /DB_PASSWORD|DB_NAME/.test(b)], ["wpconfig", "/wp-config.php~", "critical", (b) => /DB_PASSWORD|DB_NAME/.test(b)],
  ["sqldump", "/backup.sql", "critical", (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) && !/<html/i.test(b)], ["sqldump", "/dump.sql", "critical", (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) && !/<html/i.test(b)], ["sqldump", "/db.sql", "critical", (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) && !/<html/i.test(b)],
  ["htpasswd", "/.htpasswd", "critical", (b) => /^[^:\s<]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})/m.test(b) && !/<html/i.test(b)], ["awscreds", "/.aws/credentials", "critical", (b) => /aws_access_key_id/i.test(b)], ["npmrc", "/.npmrc", "critical", (b) => /_authToken|_password/i.test(b) && !/<html/i.test(b)],
  ["webconfig", "/web.config", "critical", (b) => /<configuration[\s>]/i.test(b)], ["dockercompose", "/docker-compose.yml", "warning", (b) => /^services:/m.test(b) && !/<html/i.test(b)],
  ["actuatorenv", "/actuator/env", "critical", jsonHas(/"propertySources"|"activeProfiles"/)], ["actuator", "/actuator", "warning", jsonHas(/"_links"/)],
  ["phpmyadmin", "/phpmyadmin/", "warning", (b) => /phpMyAdmin/i.test(b)], ["adminer", "/adminer.php", "warning", (b) => /Adminer/i.test(b) && /login/i.test(b)],
  ["wpusers", "/wp-json/wp/v2/users", "warning", (b) => /^\s*\[\s*\{[\s\S]*"slug"/.test(b)], ["xmlrpc", "/xmlrpc.php", "warning", (b) => /XML-RPC server accepts POST requests only/i.test(b)],
  ["swagger", "/swagger.json", "info", jsonHas(/"swagger"|"openapi"/)], ["swagger", "/openapi.json", "info", jsonHas(/"openapi"|"swagger"/)],
  ["backuparchive", "/backup.zip", "critical", (b, r) => r.status === 200 && /zip|octet-stream|gzip|x-tar/i.test(r.contentType || "") && (r.transferBytes || 0) > 2000], ["backuparchive", "/site.zip", "critical", (b, r) => r.status === 200 && /zip|octet-stream|gzip|x-tar/i.test(r.contentType || "") && (r.transferBytes || 0) > 2000], ["backuparchive", "/www.zip", "critical", (b, r) => r.status === 200 && /zip|octet-stream|gzip|x-tar/i.test(r.contentType || "") && (r.transferBytes || 0) > 2000]
];
async function scanSecurity(targetUrl) {
  const startedAt = Date.now(); const V = "security-analyzer-v2.0";
  const { url, main, prot, httpOnly } = await getPage(targetUrl);
  if (prot) return protectedResult("SECURITY", V, startedAt, url, main, prot);
  if (main.status === 0) return downResult("SECURITY", V, startedAt, url, main, netErrorFinding("security", main));
  const finalUrl = main.finalUrl; const c = makeChecker(); const host = hostOf(finalUrl); const A = analyzeHtml(isHtml(main) ? main.body : "", finalUrl); const https = /^https:/i.test(finalUrl);
  const sec = securityHeaderChecks(c, { main, A, finalUrl });
  if (httpOnly) c.add(false, 10, "finding_security_https_unavailable_critical", "aktarim");
  if (main.tlsError) c.add(false, 12, "finding_security_invalid_certificate_critical", "aktarim");
  let httpRedirect = null;
  if (host && https) { const r = await httpProbe(`http://${host}`, { timeout: 7000, maxRedirects: 0, noUaFallback: true, readBody: false }); httpRedirect = r.status >= 300 && r.status < 400 && /^https:/i.test(String(r.headers["location"] || "")); if (r.status > 0) c.add(httpRedirect, 8, "finding_security_no_https_redirect_warning", "aktarim"); }
  let cert = null, legacy = null;
  if (https && host) {
    const [t, pv] = await Promise.all([getTlsDetails(host).catch(() => null), probeTlsVersions(host).catch(() => null)]);
    if (t) { const d = Math.floor((new Date(t.cert.valid_to) - Date.now()) / 864e5); cert = { daysRemaining: d, protocol: t.protocol, trusted: t.authorized, trustError: t.authError }; c.add(d >= 0, 10, "finding_security_cert_expired_critical", "aktarim"); if (d >= 0) { c.add(d >= 14, 8, "finding_security_cert_expiring_critical", "aktarim"); c.add(d >= 30 || d < 14, 2, "finding_security_cert_expiring_warning", "aktarim"); } c.add(["TLSv1.3", "TLSv1.2"].includes(t.protocol), 6, "finding_security_tls_old_warning", "aktarim"); }
    if (pv) { legacy = ["TLSv1", "TLSv1.1"].filter(v => pv[v] === true); c.add(legacy.length === 0, 6, "finding_security_tls_legacy_enabled_warning", "aktarim"); }
  }
  const origin = new URL(finalUrl).origin;
  const probes = await pool(EXPOSED, 8, async ([slug, p, sev, test]) => { const r = await httpProbe(origin + p, { timeout: 5000, maxRedirects: 1, noUaFallback: true, maxBytes: 20000 }); return r.status === 200 && test(String(r.body || "").slice(0, 4000), r) ? { slug, path: p, sev } : null; });
  const exposed = probes.filter(Boolean); const uniq = []; for (const e of exposed) if (!uniq.find(u => u.slug === e.slug)) uniq.push(e);
  const sectxt = await httpProbe(origin + "/.well-known/security.txt", { timeout: 5000, maxRedirects: 2, noUaFallback: true, maxBytes: 20000 }); const hasSecTxt = sectxt.status === 200 && /contact:/i.test(sectxt.body || "");
  const critExposed = uniq.filter(e => e.sev === "critical"); c.add(critExposed.length === 0, 25, null, "dosyalar"); c.add(uniq.filter(e => e.sev === "warning").length === 0, 8, null, "dosyalar");
  const extraF = [...uniq.map(e => `finding_security_exposed_${e.slug}_${e.sev}`)]; if (!hasSecTxt) extraF.push("finding_security_missing_security_txt_info");
  const findings = [...c.findings(), ...extraF]; const scores = c.groupScores();
  let score = c.score(); if (score != null && critExposed.length) score = Math.min(score, 35); if (score != null && findings.some(f => /mixed_content_critical|insecure_form_critical|invalid_certificate|cert_expired|https_unavailable/.test(f))) score = Math.min(score, 45);
  return buildResult({
    assetType: "SECURITY", version: V, startedAt, target: url, findings, score,
    specific: { url, finalUrl, https, hsts: sec.hsts, hstsMaxAgeDays: sec.hstsMaxAgeDays, csp: sec.csp, httpToHttpsRedirect: httpRedirect, mixedContent: A.mixed, serverHeader: main.headers["server"] || null, poweredBy: main.headers["x-powered-by"] || null,
      cookies: sec.cookies.map(k => `${k.name} (${k.secure ? "Secure" : "!Secure"}, ${k.httpOnly ? "HttpOnly" : "!HttpOnly"}, SameSite=${k.sameSite || "yok"})`), certificate: cert, legacyTlsEnabled: legacy, securityTxt: hasSecTxt,
      thirdPartyScriptsWithoutSri: A.externalScriptsNoSri, exposedFiles: uniq.map(e => `${e.path} (${e.sev})`), checkedFiles: EXPOSED.length, checks: c.summary(), scores }
  });
}

// =====================================================================
// PERFORMANS v2
// =====================================================================
async function scanPerformance(targetUrl) {
  const startedAt = Date.now(); const V = "performance-analyzer-v2.0";
  const { url, main, prot } = await getPage(targetUrl, { noUaFallback: false });
  if (prot) return protectedResult("PERFORMANCE", V, startedAt, url, main, prot);
  if (main.status === 0) return downResult("PERFORMANCE", V, startedAt, url, main, netErrorFinding("perf", main));
  if (main.status >= 400 && ![401, 403].includes(main.status)) return downResult("PERFORMANCE", V, startedAt, url, main, "finding_perf_unreachable_critical");
  const finalUrl = main.finalUrl; const host = hostOf(finalUrl); const c = makeChecker(); const A = analyzeHtml(isHtml(main) ? main.body : "", finalUrl);
  const [tlsi, assets, dnsMs, repeat] = await Promise.all([
    /^https:/i.test(finalUrl) && host ? tlsAlpn(host) : null, isHtml(main) ? sampleAssets(A, finalUrl, 6).catch(() => []) : [],
    (async () => { const t = Date.now(); try { await dns.lookup(host); return Date.now() - t; } catch { return null; } })(),
    (async () => { const xs = []; for (let i = 0; i < 2; i++) { const r = await request(finalUrl, { timeout: 10000, readBody: false, insecure: true }); if (r.status) xs.push(r.ttfb); } return xs; })()
  ]);
  const ttfbs = [main.ttfb, ...repeat].filter(x => x != null).sort((a, b) => a - b); main.ttfb = ttfbs.length ? ttfbs[Math.floor(ttfbs.length / 2)] : main.ttfb; // medyan: tek yavaş ölçüm skoru bozmasın
  const p = perfChecks(c, { main, A, assets, tlsi, dnsMs });
  const h = main.headers; const scores = c.groupScores();
  return buildResult({
    assetType: "PERFORMANCE", version: V, startedAt, target: url, findings: c.findings(), score: c.score(),
    specific: { url, finalUrl, status: main.status, ttfbMs: main.ttfb, ttfbSamplesMs: ttfbs, totalLoadMs: main.total, redirectChainMs: p.chainMs, htmlTransferKB: Math.round(main.transferBytes / 102.4) / 10, htmlRawKB: Math.round(main.rawBytes / 102.4) / 10, compression: main.encoding, protocol: tlsi?.alpn || null, tlsVersion: tlsi?.tlsVersion || null, tlsHandshakeMs: tlsi?.handshakeMs ?? null, dnsLookupMs: dnsMs,
      http3Advertised: /h3/.test(String(h["alt-svc"] || "")), redirectHops: main.redirects, redirectChain: (main.chain || []).map(x => `${x.status} ${x.url}`), externalScripts: A.scripts.length, renderBlockingScripts: p.blocking, stylesheets: A.stylesheets.length, images: A.images.total, lazyImages: A.images.lazy, imagesWithoutDimensions: A.images.noDimensions,
      thirdPartyHosts: A.thirdPartyHosts.slice(0, 12), domNodes: A.domNodes, measuredWeightKB: Math.round(p.weight / 102.4) / 10, jsKB: Math.round(p.jsBytes / 102.4) / 10, cssKB: Math.round(p.cssBytes / 102.4) / 10, imageKBSampled: Math.round(p.imgBytes / 102.4) / 10,
      sampledAssets: p.sized.map(a => `${a.kind.toUpperCase()} ${a.status} ${a.enc || "sıkıştırmasız"} ${Math.round(a.transfer / 1024)}KB cache:${a.cache || "yok"}`),
      note: "Tarayıcıda çalışan JavaScript ile sonradan yüklenen kaynaklar ölçülmez; ölçüm HTML'deki kaynaklara dayanır.", checks: c.summary(), scores }
  });
}

// =====================================================================
// UPTIME & GECİKME v2
// =====================================================================
async function scanUptime(targetUrl, extra = {}) {
  const startedAt = Date.now(); const V = "uptime-analyzer-v2.0"; const url = ensureUrl(targetUrl);
  // P95 anlamlı olsun diye EN AZ 100 örnek alınır (env ile artırılabilir, 100'ün altına inemez). Eşzamanlı çalışır; süre bütçesi aşılırsa kalan örnekler alınmaz.
  const N0 = Math.max(100, parseInt(process.env.UPTIME_SAMPLES || "100", 10) || 100);
  const CONC = Math.min(10, Math.max(1, parseInt(process.env.UPTIME_CONCURRENCY || "5", 10) || 5));
  const BUDGET = Math.max(10000, parseInt(process.env.UPTIME_BUDGET_MS || "45000", 10) || 45000);
  const samples = []; let launched = 0, stopAll = false;
  const worker = async () => {
    while (!stopAll && launched < N0 && Date.now() - startedAt < BUDGET) {
      launched++;
      const r = await request(url, { timeout: 6000, readBody: true, maxBytes: 60000, insecure: true });
      samples.push({ status: r.status, ms: r.total, ttfb: r.ttfb, up: r.status > 0 && r.status < 500, protectedBy: r.status >= 400 ? detectBotProtection(r) : null, err: r.errorInfo?.kind || null, retryAfter: r.headers["retry-after"] || null, maint: r.status === 503 });
      if (samples.length === 5 && samples.every(s => !s.up)) stopAll = true; // ilk 5 örnek başarısızsa boşuna 100'e tamamlama
      await sleep(100);
    }
  };
  await Promise.all(Array.from({ length: CONC }, worker));
  const N = samples.length; const host = hostOf(url); const t0 = Date.now(); let dnsMs = null; try { await dns.lookup(host); dnsMs = Date.now() - t0; } catch {}
  let uPort = /^https:/i.test(url) ? 443 : 80; try { const pu = new URL(url); if (pu.port) uPort = parseInt(pu.port, 10); } catch {}
  const [tcp, tlsi] = await Promise.all([host ? tcpPortCheck(host, uPort, 4000) : null, /^https:/i.test(url) && host ? tlsAlpn(host) : null]);
  const ups = samples.filter(s => s.up); const times = ups.map(s => s.ttfb ?? s.ms).sort((a, b) => a - b); const rate = Math.round(ups.length / N * 100);
  const mean = avg(times); const jitter = times.length > 1 ? Math.round(Math.sqrt(times.reduce((s, t) => s + (t - mean) ** 2, 0) / times.length)) : 0;
  const p95 = times.length ? times[Math.min(times.length - 1, Math.ceil(times.length * 0.95) - 1)] : null; const median = times.length ? times[Math.floor(times.length / 2)] : null;
  const c = makeChecker(); const serverErrs = samples.filter(s => s.status >= 500).length;
  c.add(N >= 50 ? rate >= 98 : rate === 100, 40, rate === 0 ? "finding_uptime_down_critical" : "finding_uptime_intermittent_critical", "erisim"); c.add(rate >= 80, 10, null, "erisim");
  c.add(serverErrs === 0, 5, "finding_uptime_server_errors_critical", "erisim");
  if (times.length) { c.add(median < 800, 20, "finding_uptime_slow_response_warning", "gecikme"); c.add(p95 < 2000, 10, "finding_uptime_high_p95_warning", "gecikme"); c.add(jitter < 300, 10, "finding_uptime_unstable_latency_warning", "gecikme"); }
  c.add(dnsMs != null ? dnsMs < 300 : null, 5, "finding_uptime_slow_dns_warning", "gecikme");
  c.add(tcp ? (tcp.open && tcp.latencyMs < 500) : null, 5, "finding_uptime_slow_connect_warning", "gecikme");
  const findings = c.findings(); const lastErr = samples.find(s => s.err);
  if (rate === 0 && lastErr) { const k = lastErr.err; findings.push(({ dns: "finding_uptime_dns_failure_critical", refused: "finding_uptime_connection_refused_critical", timeout: "finding_uptime_timeout_critical", tls: "finding_uptime_tls_failure_critical" })[k] || "finding_uptime_unreachable_critical"); }
  if (ups.length && samples.some(s => s.protectedBy)) findings.push("finding_web_bot_protection_info");
  if (samples.some(s => s.maint)) findings.push("finding_uptime_maintenance_info");
  const scores = c.groupScores();
  return buildResult({
    assetType: "UPTIME", version: V, startedAt, target: url, findings, score: rate === 0 ? 0 : c.score(), status: rate === 0 ? "DOWN" : undefined,
    specific: { url, samples: N, successRatePct: rate, statusCodes: samples.map(s => s.status), failures: samples.filter(s => !s.up).map(s => s.err || `HTTP ${s.status}`), minMs: times[0] ?? null, avgMs: mean, medianMs: median, p95Ms: p95, maxMs: times[times.length - 1] ?? null, jitterMs: jitter, dnsLookupMs: dnsMs, tcpConnectMs: tcp?.open ? tcp.latencyMs : null, tlsHandshakeMs: tlsi?.handshakeMs ?? null,
      note: `Tek noktadan (sunucu konumu) anlık ölçüm; sürekli izleme değildir. ${N} örnekle hesaplandı${N < 100 ? " (süre sınırı veya erişilemezlik nedeniyle 100'ün altında kaldı; P95 güvenilir değildir)" : ""}. 4xx yanıtlar 'sunucu ayakta' sayılır, ölçüm ilk bayta kadar geçen süreyi (TTFB) esas alır.`, checks: c.summary(), scores }
  });
}

// =====================================================================
// API v2
// =====================================================================
const STACK_LEAK = /(\bat [\w$.<>]+\([\w$.]+\.(java|kt|cs):\d+\))|Traceback \(most recent call last\)|SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|System\.(NullReference|InvalidOperation)Exception|node_modules\/|\/var\/www\/|C:\\\\inetpub|stack trace:/i;
async function scanApi(targetUrl) {
  const startedAt = Date.now(); const V = "api-analyzer-v2.0"; const url = ensureUrl(targetUrl);
  const main = await httpProbe(url, { headers: { Accept: "application/json" }, timeout: 12000, maxRedirects: 4 });
  const prot = main.status ? detectBotProtection(main) : null;
  if (prot) return protectedResult("API", V, startedAt, url, main, prot);
  if (main.status === 0) return downResult("API", V, startedAt, url, main, netErrorFinding("api", main));
  if (main.status >= 500) return downResult("API", V, startedAt, url, main, "finding_api_server_error_critical");
  const finalUrl = main.finalUrl; const h = main.headers; const c = makeChecker(); const ct = String(h["content-type"] || ""); const authRequired = main.status === 401 || main.status === 403;
  let jsonOk = null, jsonKeys = null; if (/json/i.test(ct)) { try { const j = JSON.parse(main.body); jsonOk = true; jsonKeys = Array.isArray(j) ? `array(${j.length})` : j && typeof j === "object" ? Object.keys(j).slice(0, 8) : typeof j; } catch { jsonOk = false; } }
  let origin; try { origin = new URL(finalUrl).origin; } catch { origin = url; }
  const evil = "https://dac-cors-test.example";
  const [pre, corsGet, bad404, repeat, allow] = await Promise.all([
    httpProbe(finalUrl, { method: "OPTIONS", timeout: 7000, maxRedirects: 0, noUaFallback: true, readBody: false, headers: { Origin: evil, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization" } }),
    httpProbe(finalUrl, { timeout: 7000, maxRedirects: 0, noUaFallback: true, readBody: false, headers: { Origin: evil, Accept: "application/json" } }),
    httpProbe(origin + "/__dac_not_found__" + Date.now(), { timeout: 7000, maxRedirects: 0, noUaFallback: true, headers: { Accept: "application/json" } }),
    (async () => { const xs = []; for (let i = 0; i < 2; i++) { const r = await request(finalUrl, { timeout: 9000, readBody: false, insecure: true, headers: { Accept: "application/json" } }); if (r.status) xs.push(r.total); } return xs; })(),
    null
  ]);
  const acao = pre.headers["access-control-allow-origin"] || corsGet.headers["access-control-allow-origin"] || null; const creds = String(pre.headers["access-control-allow-credentials"] || corsGet.headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
  const reflects = acao === evil; const rl = Object.keys(h).filter(k => /ratelimit|retry-after/i.test(k)); const times = [main.responseTimeMs, ...repeat].filter(x => x != null).sort((a, b) => a - b); const med = times[Math.floor(times.length / 2)];
  const methods = String(pre.headers["allow"] || pre.headers["access-control-allow-methods"] || "") || null;
  c.add(main.status < 400 || authRequired, 25, "finding_api_error_status_critical", "erisim"); c.add(med < 1000, 15, "finding_api_slow_response_warning", "erisim"); c.add(!!main.encoding || main.rawBytes < 1400 || !/json|text/i.test(ct), 3, "finding_api_no_compression_warning", "erisim");
  c.add(/^https:/i.test(finalUrl), 10, "finding_api_not_https_critical", "guvenlik");
  c.add(!((reflects || acao === "*") && creds), 12, "finding_api_cors_credentials_critical", "guvenlik"); c.add(!reflects || creds === false, 3, "finding_api_cors_reflects_origin_warning", "guvenlik");
  c.add(/nosniff/i.test(String(h["x-content-type-options"] || "")), 5, "finding_api_missing_nosniff_warning", "guvenlik"); if (/^https:/i.test(finalUrl)) c.add(!!h["strict-transport-security"], 5, "finding_api_missing_hsts_warning", "guvenlik");
  c.add(!/\d+\.\d+/.test(String(h["server"] || "") + String(h["x-powered-by"] || "")), 4, "finding_api_version_disclosure_warning", "guvenlik");
  c.add(!STACK_LEAK.test(String(bad404.body || "")) && !STACK_LEAK.test(String(main.body || "")), 10, "finding_api_error_leaks_stacktrace_critical", "guvenlik");
  c.add(!h["x-debug-token"] && !h["x-debug-token-link"], 3, "finding_api_debug_headers_warning", "guvenlik");
  if (jsonOk !== null) c.add(jsonOk, 10, "finding_api_invalid_json_critical", "tasarim"); else if (!authRequired) c.add(false, 6, "finding_api_not_json_warning", "tasarim");
  if (jsonOk) c.add(/charset|json/i.test(ct), 1, null, "tasarim");
  c.add(rl.length > 0, 8, "finding_api_no_rate_limit_headers_warning", "tasarim"); c.add(/json/i.test(String(bad404.headers["content-type"] || "")), 4, "finding_api_error_not_json_warning", "tasarim");
  c.add(bad404.status === 404 || bad404.status === 401 || bad404.status === 403, 4, "finding_api_unknown_route_status_warning", "tasarim");
  c.add(/\/v\d+(\/|$)/i.test(finalUrl) || !!h["api-version"] || !!h["x-api-version"], 4, "finding_api_no_versioning_warning", "tasarim");
  const findings = c.findings(); if (authRequired) findings.push("finding_api_auth_required_info");
  const scores = c.groupScores();
  return buildResult({
    assetType: "API", version: V, startedAt, target: url, findings, score: c.score(),
    specific: { url, finalUrl, status: main.status, responseTimeMs: main.responseTimeMs, medianResponseMs: med, contentType: ct || null, compression: main.encoding, validJson: jsonOk, jsonShape: jsonKeys, authRequired, cors: { allowOrigin: acao, allowCredentials: creds, reflectsArbitraryOrigin: reflects, allowMethods: methods }, rateLimitHeaders: rl, unknownRouteStatus: bad404.status, server: h["server"] || null, redirects: main.redirects, checks: c.summary(), scores }
  });
}

// =====================================================================
// MOBİL UYGULAMA v2 (Google Play / App Store)
// =====================================================================
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
function parseEnDate(s) { const m = String(s || "").match(/([A-Za-z]{3})[a-z]*\.? (\d{1,2}), (\d{4})/); return m && MONTHS[m[1].toLowerCase()] !== undefined ? new Date(Date.UTC(+m[3], MONTHS[m[1].toLowerCase()], +m[2])) : null; }
async function scanMobileApp(input) {
  const startedAt = Date.now(); const V = "mobile-analyzer-v2.0"; const raw = String(input || "").trim();
  let store = null, id = null, country = "tr";
  const play = raw.match(/[?&]id=([A-Za-z0-9._]+)/) || raw.match(/^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)$/);
  const apple = raw.match(/apps\.apple\.com\/(?:([a-z]{2})\/)?[^?#]*id(\d{5,})/i) || raw.match(/^(?:id)?(\d{7,})$/i);
  if (/play\.google\.com/i.test(raw) && play) { store = "play"; id = play[1]; } else if (apple) { store = "appstore"; id = apple[2] || apple[1]; if (apple[2] && apple[1]) country = apple[1]; } else if (play) { store = "play"; id = play[1]; }
  if (!store) return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: ["finding_mobile_invalid_target_critical"], score: 0, status: "ERROR", specific: { hint: "Paket adı (com.firma.uygulama), Play Store linki veya App Store linki girin." } });
  const c = makeChecker(); let info = {}; const extraF = [];
  if (store === "appstore") {
    let a = null, usedCountry = null;
    for (const cc of [...new Set([country, "tr", "us", "de", "gb"])]) {
      const r = await axios.get(`https://itunes.apple.com/lookup?id=${id}&country=${cc}`, { timeout: 9000, validateStatus: () => true, proxy: false }).catch(() => null);
      if (r && r.status === 429) return unavailableResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, finding: "finding_mobile_store_unavailable_info", status: "UNKNOWN", note: "App Store sorgu sınırına takıldı; biraz sonra tekrar deneyin.", specific: { store: "App Store", id } });
      a = r?.data?.results?.[0]; if (a) { usedCountry = cc; break; }
    }
    if (!a) return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: ["finding_mobile_not_found_critical"], score: 0, status: "DOWN", specific: { store: "App Store", id, note: "Uygulama kontrol edilen mağazalarda (TR, US, DE, GB) bulunamadı: kaldırılmış olabilir." } });
    const age = daysSince(a.currentVersionReleaseDate);
    info = { store: "App Store", id, name: a.trackName, developer: a.sellerName, bundleId: a.bundleId, version: a.version, rating: a.averageUserRating ? Math.round(a.averageUserRating * 10) / 10 : null, ratingCount: a.userRatingCount || 0,
      ratingCurrentVersion: a.averageUserRatingForCurrentVersion ? Math.round(a.averageUserRatingForCurrentVersion * 10) / 10 : null, ratingCountCurrentVersion: a.userRatingCountForCurrentVersion || 0, lastUpdate: a.currentVersionReleaseDate, daysSinceUpdate: age, firstRelease: a.releaseDate,
      minOs: a.minimumOsVersion, price: a.formattedPrice, category: a.primaryGenreName, sizeMB: a.fileSizeBytes ? Math.round(a.fileSizeBytes / 1048576) : null, contentRating: a.contentAdvisoryRating, languages: (a.languageCodesISO2A || []).length, availableInCountry: usedCountry, releaseNotes: a.releaseNotes ? String(a.releaseNotes).slice(0, 160) : null };
    if (usedCountry !== country) extraF.push("finding_mobile_not_in_home_store_info");
    if (info.ratingCurrentVersion != null && info.ratingCountCurrentVersion >= 10) c.add(info.ratingCurrentVersion >= 3.5, 10, "finding_mobile_low_current_rating_warning", "kalite");
    if (info.minOs && parseFloat(info.minOs) < 13) extraF.push("finding_mobile_old_min_os_info");
  } else {
    let r = null, usedGl = null;
    for (const gl of ["US", "TR", "DE"]) { r = await httpProbe(`https://play.google.com/store/apps/details?id=${encodeURIComponent(id)}&hl=en&gl=${gl}`, { timeout: 10000, maxRedirects: 3, noUaFallback: true }); if (r.status === 200) { usedGl = gl; break; } if (r.status !== 404) break; }
    if (r.status === 404) return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: ["finding_mobile_not_found_critical"], score: 0, status: "DOWN", specific: { store: "Google Play", id, note: "Uygulama kontrol edilen mağazalarda (US, TR, DE) bulunamadı: kaldırılmış olabilir." } });
    if (!r.ok) return unavailableResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, finding: "finding_mobile_store_unavailable_info", status: "UNKNOWN", note: "Google Play yanıt vermedi veya erişimi kısıtladı.", specific: { store: "Google Play", id, status: r.status } });
    const b = r.body || ""; let ld = null;
    for (const m of b.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)) { try { const j = JSON.parse(m[1]); if (j && (j.aggregateRating || j["@type"] === "SoftwareApplication")) { ld = j; break; } } catch {} }
    let rating = ld?.aggregateRating?.ratingValue != null ? parseFloat(ld.aggregateRating.ratingValue) : parseFloat((b.match(/"ratingValue":\s*"?([\d.]+)"?/) || [])[1]);
    let rc = ld?.aggregateRating ? parseInt(ld.aggregateRating.ratingCount || ld.aggregateRating.reviewCount, 10) : parseInt((b.match(/"ratingCount":\s*"?(\d+)"?/) || [])[1], 10);
    const name = ld?.name || ((b.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1] || "").replace(/\s*-\s*Apps on Google Play.*/i, "").trim();
    const installs = (b.match(/>([\d.,]+[KMB]?\+)<\/div><div[^>]*>Downloads/i) || [])[1] || null;
    const upd = parseEnDate((b.match(/Updated on<\/div><div[^>]*>([^<]+)</i) || b.match(/Updated on[^A-Za-z0-9]{0,40}([A-Za-z]{3,9} \d{1,2}, \d{4})/i) || [])[1]);
    const daysSinceUpdate = upd ? daysSince(upd) : null;
    info = { store: "Google Play", id, name: name || null, developer: ld?.author?.name || null, category: ld?.applicationCategory || null, price: ld?.offers?.price != null ? String(ld.offers.price) : null, rating: isNaN(rating) ? null : Math.round(rating * 10) / 10, ratingCount: isNaN(rc) ? null : rc, downloads: installs, lastUpdate: upd ? upd.toISOString() : null, daysSinceUpdate, availableInCountry: usedGl,
      note: "Play Store resmi API sunmaz; ayrıntılar sayfadan okunur, bulunamayan alanlar boş kalır." };
    if (info.rating == null && info.daysSinceUpdate == null) extraF.push("finding_mobile_details_unavailable_info");
  }
  c.add(true, 40, null, "yayin");
  if (info.rating != null) c.add(info.rating >= 4.0, 25, "finding_mobile_low_rating_warning", "kalite");
  if (info.ratingCount != null) c.add(info.ratingCount >= 50, 10, "finding_mobile_few_ratings_info", "kalite");
  if (info.daysSinceUpdate != null) { c.add(info.daysSinceUpdate <= 365, 15, "finding_mobile_stale_critical", "bakim"); if (info.daysSinceUpdate <= 365) c.add(info.daysSinceUpdate <= 180, 10, "finding_mobile_aging_warning", "bakim"); }
  const scores = c.groupScores(); const measurable = info.rating != null || info.daysSinceUpdate != null;
  return buildResult({ assetType: "MOBILE_APP", version: V, startedAt, target: raw, findings: [...c.findings(), ...extraF], score: measurable ? c.score() : null, status: measurable ? undefined : "ACTIVE", specific: { ...info, scores } });
}

// =====================================================================
// KOD DEPOSU (GitHub) v2
// =====================================================================
const SECRET_FILES = /^(\.env(\..*)?|id_rsa|id_dsa|.*\.pem|.*\.p12|.*\.pfx|credentials\.json|serviceaccountkey\.json|.*-firebase-adminsdk-.*\.json|secrets?\.(json|ya?ml)|\.npmrc|\.pypirc|terraform\.tfstate)$/i;
async function scanRepository(input) {
  const startedAt = Date.now(); const V = "repo-analyzer-v2.0"; const raw = String(input || "").trim();
  const m = raw.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/?#]|$)/i) || raw.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (!m) return buildResult({ assetType: "REPOSITORY", version: V, startedAt, target: raw, findings: ["finding_repo_invalid_target_critical"], score: 0, status: "ERROR", specific: { hint: "sahip/depo biçiminde veya GitHub linki girin." } });
  const [, owner, repo] = m; const token = process.env.GITHUB_TOKEN; const deep = !!token;
  const H = { "User-Agent": "DigitalAssetCenter", Accept: "application/vnd.github+json", ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const gh = (p) => axios.get(`https://api.github.com/repos/${owner}/${repo}${p}`, { headers: H, timeout: 9000, validateStatus: () => true, proxy: false }).catch(() => ({ status: 0, data: null, headers: {} }));
  const r = await gh("");
  if ((r.status === 403 || r.status === 429) && String(r.headers["x-ratelimit-remaining"]) === "0") return unavailableResult({ assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, finding: "finding_repo_rate_limited_info", status: "UNKNOWN", note: "GitHub hız sınırına takıldı. Sunucuya GITHUB_TOKEN ekleyerek sınırı yükseltebilirsiniz." });
  if (r.status === 404) return buildResult({ assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, findings: ["finding_repo_not_found_critical"], score: 0, status: "DOWN", specific: { owner, repo, note: "Depo yok ya da özel (private)." } });
  if (r.status === 301 && r.headers.location) { /* yeniden adlandırılmış */ }
  if (r.status !== 200) return unavailableResult({ assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, finding: "finding_repo_api_error_info", status: "UNKNOWN", note: `GitHub API ${r.status} döndürdü.` });
  const d = r.data;
  const [rel, com, root, ghDir, contrib, pulls, langs] = await Promise.all([gh("/releases/latest"), gh("/community/profile"), gh("/contents/"), gh("/contents/.github"), deep ? gh("/contributors?per_page=1&anon=true") : null, deep ? gh("/pulls?state=open&per_page=1") : null, deep ? gh("/languages") : null]);
  const pushAge = daysSince(d.pushed_at); const relAge = rel.status === 200 ? daysSince(rel.data.published_at) : null; const files = com.status === 200 ? com.data.files || {} : {};
  const names = root.status === 200 && Array.isArray(root.data) ? root.data.map(x => String(x.name)) : null; const ghNames = ghDir.status === 200 && Array.isArray(ghDir.data) ? ghDir.data.map(x => String(x.name)) : [];
  const secrets = names ? names.filter(n => SECRET_FILES.test(n) && !/\.(example|sample|template)$/i.test(n)) : [];
  const hasSecurity = names ? (names.some(n => /^security\.md$/i.test(n)) || ghNames.some(n => /^security\.md$/i.test(n))) : null;
  const hasCI = names ? (ghNames.includes("workflows") || names.some(n => /^(\.travis\.yml|\.gitlab-ci\.yml|azure-pipelines\.yml|\.circleci|Jenkinsfile|bitbucket-pipelines\.yml)$/i.test(n))) : null;
  const hasDependabot = names ? (ghNames.some(n => /^dependabot\.ya?ml$/i.test(n)) || names.some(n => /^renovate\.json5?$/i.test(n)) || ghNames.some(n => /^renovate\.json5?$/i.test(n))) : null;
  const hasTests = names ? names.some(n => /^(tests?|__tests__|spec|specs)$/i.test(n)) : null; const hasLock = names ? names.some(n => /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/i.test(n)) : null;
  const countFromLink = (res) => { const l = String(res?.headers?.link || ""); const mm = l.match(/[?&]page=(\d+)>; rel="last"/); return mm ? parseInt(mm[1], 10) : (Array.isArray(res?.data) ? res.data.length : null); };
  const contributors = contrib && contrib.status === 200 ? countFromLink(contrib) : null; const openPrs = pulls && pulls.status === 200 ? countFromLink(pulls) : null;
  const c = makeChecker(); const extraF = [];
  c.add(!d.archived, 20, "finding_repo_archived_warning", "bakim"); c.add(pushAge != null && pushAge <= 365, 20, "finding_repo_inactive_critical", "bakim"); if (pushAge != null && pushAge <= 365) c.add(pushAge <= 90, 10, "finding_repo_stale_warning", "bakim");
  c.add(d.license ? true : false, 10, "finding_repo_no_license_warning", "topluluk");
  if (com.status === 200) { c.add(!!files.readme, 8, "finding_repo_no_readme_warning", "topluluk"); c.add(!!files.contributing || !!files.code_of_conduct, 4, "finding_repo_no_contributing_info", "topluluk"); }
  c.add((d.open_issues_count || 0) < 100, 8, "finding_repo_many_open_issues_warning", "bakim"); c.add(rel.status === 200, 5, "finding_repo_no_releases_info", "bakim");
  if (names) { c.add(secrets.length === 0, 20, "finding_repo_secret_file_committed_critical", "guvenlik"); c.add(hasSecurity, 4, "finding_repo_no_security_policy_info", "guvenlik"); c.add(hasCI, 4, "finding_repo_no_ci_info", "bakim"); if (hasLock === false && /javascript|typescript|python|go|rust|php|ruby/i.test(d.language || "")) c.add(false, 3, "finding_repo_no_lockfile_info", "guvenlik"); }
  if (deep && names) c.add(hasDependabot, 4, "finding_repo_no_dependency_updates_info", "guvenlik");
  if (contributors === 1) extraF.push("finding_repo_single_contributor_info");
  if (d.fork) extraF.push("finding_repo_is_fork_info"); if (d.has_issues === false) extraF.push("finding_repo_issues_disabled_info");
  const scores = c.groupScores();
  return buildResult({
    assetType: "REPOSITORY", version: V, startedAt, target: `${owner}/${repo}`, findings: [...c.findings(), ...extraF], score: c.score(),
    specific: { repo: d.full_name, description: d.description || null, visibility: d.visibility || (d.private ? "private" : "public"), language: d.language, languages: langs && langs.status === 200 ? Object.keys(langs.data).slice(0, 6) : undefined, license: d.license?.spdx_id || null, stars: d.stargazers_count, forks: d.forks_count, watchers: d.subscribers_count ?? null, openIssues: d.open_issues_count, openPullRequests: openPrs, contributors,
      defaultBranch: d.default_branch, archived: d.archived, isFork: d.fork, createdAt: d.created_at, ageDays: daysSince(d.created_at), lastPush: d.pushed_at, daysSinceLastPush: pushAge, latestRelease: rel.status === 200 ? `${rel.data.tag_name} (${relAge} gün önce)` : null, communityHealthPct: com.status === 200 ? com.data.health_percentage : null, sizeKB: d.size,
      hygiene: names ? { securityPolicy: hasSecurity, ci: hasCI, dependencyUpdates: deep ? hasDependabot : "GITHUB_TOKEN gerekli", tests: hasTests, lockfile: hasLock, committedSecretFiles: secrets } : "Kök dizin listelenemedi",
      note: deep ? undefined : "Token tanımlı değil: GitHub hız sınırını korumak için bazı derin kontroller (katkıcı, PR, bağımlılık güncelleme) atlandı. Sunucuya GITHUB_TOKEN ekleyin.", scores }
  });
}

// =====================================================================
// MARKA KORUMASI v2
// =====================================================================
const BRAND_TLDS = ["com", "net", "org", "io", "co", "app", "dev", "info", "biz", "online", "store", "tech", "ai", "com.tr", "net.tr", "org.tr", "de", "fr", "es", "it", "nl", "co.uk", "eu", "us", "ae", "sa", "shop", "site", "xyz"];
const HOMOGLYPH = { o: ["0"], l: ["1", "i"], i: ["l", "1"], a: ["e"], e: ["a"], s: ["5"], g: ["q"], q: ["g"], m: ["rn"], w: ["vv"], d: ["cl"], b: ["6"] };
function typoVariants(label, cap = 30) {
  const out = new Set();
  for (let i = 0; i < label.length; i++) {
    out.add(label.slice(0, i) + label.slice(i + 1)); out.add(label.slice(0, i) + label[i] + label.slice(i));
    if (i < label.length - 1) out.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
    for (const g of (HOMOGLYPH[label[i]] || [])) out.add(label.slice(0, i) + g + label.slice(i + 1));
  }
  if (label.length > 4) out.add(label.slice(0, Math.floor(label.length / 2)) + "-" + label.slice(Math.floor(label.length / 2)));
  out.delete(label);
  const ok = [...out].filter(v => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(v) && v.length >= 2);
  if (ok.length <= cap) return ok; const step = ok.length / cap; return Array.from({ length: cap }, (_, i) => ok[Math.floor(i * step)]);
}
const KEYWORDS = ["login", "secure", "support", "account", "my", "pay", "official", "app"];
async function dnsRegistered(name, resolver) {
  try { const ns = await resolver.resolveNs(name); return { state: "registered", ns: ns.map(x => x.toLowerCase()).sort() }; }
  catch (e) {
    if (e.code === "ENOTFOUND") return { state: "free", ns: [] };
    if (e.code === "ENODATA") { try { const a = await resolver.resolve4(name); return { state: "registered", ns: [], a }; } catch (e2) { return { state: e2.code === "ENOTFOUND" ? "free" : "unknown", ns: [] }; } }
    return { state: "unknown", ns: [] };
  }
}
async function scanBrand(input, extra = {}, resolverOverride) {
  const startedAt = Date.now(); const V = "brand-analyzer-v2.0"; const parsed = parseDomain(input);
  if (!parsed) return buildResult({ assetType: "BRAND", version: V, startedAt, target: String(input || ""), findings: ["finding_brand_invalid_target_critical"], score: 0, status: "ERROR", specific: {} });
  const domain = registrableDomain(parsed); const { label, tld } = splitDomain(domain); const base = `${label}.${tld}`;
  const resolver = resolverOverride || new dns.Resolver({ timeout: 3000, tries: 2 }); if (!resolverOverride) resolver.setServers(["1.1.1.1", "8.8.8.8"]);
  { // Çözücü sağlık kontrolü: bozuksa "hepsi boş" diye sahte sonuç üretme
    let ok = false; try { ok = (await resolver.resolve4("cloudflare.com")).length > 0; } catch {}
    if (!ok) return unavailableResult({ assetType: "BRAND", version: V, startedAt, target: base, finding: "finding_brand_dns_unreliable_info", status: "UNKNOWN", note: "DNS çözücü yanıt vermedi; marka taraması yapılamadı.", specific: { domain: base } });
  }
  const own = await dnsRegistered(base, resolver); const ownNs = own.ns.join(","); let ownA = []; try { ownA = await resolver.resolve4(base); } catch {}
  const wildcard = await (async () => { try { await resolver.resolve4(`dac-${Math.random().toString(36).slice(2, 10)}.${tld}`); return true; } catch { return false; } })();
  const tlds = BRAND_TLDS.filter(t => t !== tld).map(t => `${label}.${t}`); const typos = typoVariants(label).map(v => `${v}.${tld}`);
  const kw = KEYWORDS.flatMap(k => [`${label}-${k}.${tld}`, `${k}-${label}.${tld}`]).slice(0, 12);
  const names = [...tlds.map(n => ({ n, kind: "tld" })), ...typos.map(n => ({ n, kind: "typo" })), ...kw.map(n => ({ n, kind: "keyword" }))];
  const results = await pool(names, 14, async (it) => { const r = await dnsRegistered(it.n, resolver); let a = r.a || []; if (r.state === "registered" && !a.length) { try { a = await resolver.resolve4(it.n); } catch {} } return { ...it, ...r, a }; });
  const res = results.filter(Boolean); const mine = (r) => r.state === "registered" && ((ownNs && r.ns.join(",") === ownNs) || (r.a || []).some(ip => ownA.includes(ip)));
  const reg = res.filter(r => r.state === "registered"); const third = reg.filter(r => !mine(r));
  const thirdTld = third.filter(r => r.kind === "tld"), thirdTypo = third.filter(r => r.kind === "typo"), thirdKw = third.filter(r => r.kind === "keyword"); const freeTld = res.filter(r => r.kind === "tld" && r.state === "free"); const unknown = res.filter(r => r.state === "unknown").length;
  // Üçüncü kişi benzer alan adlarında yayında site var mı, markadan söz ediyor mu?
  const live = []; await pool([...thirdTypo, ...thirdKw].filter(r => r.a && r.a.length).slice(0, 10), 5, async (r) => {
    const p = await request(`http://${r.n}/`, { timeout: 5000, maxBytes: 80000 }); if (!p.status) return;
    const body = String(p.body || "").toLowerCase(); const title = extractTitle(p.body).slice(0, 80);
    live.push({ n: r.n, status: p.status, title, mentionsBrand: body.includes(label.toLowerCase()), loginForm: /type\s*=\s*["']?password/.test(body) });
  });
  const phishy = live.filter(l => l.mentionsBrand && l.loginForm), mention = live.filter(l => l.mentionsBrand);
  const findings = [];
  if (phishy.length) findings.push(`finding_brand_${phishy.length}_lookalike_phishing_critical`);
  if (thirdTypo.length) findings.push(`finding_brand_${thirdTypo.length}_lookalike_registered_warning`);
  if (thirdKw.length) findings.push(`finding_brand_${thirdKw.length}_keyword_registered_warning`);
  if (mention.length && !phishy.length) findings.push(`finding_brand_${mention.length}_lookalike_active_warning`);
  if (thirdTld.length) findings.push(`finding_brand_${thirdTld.length}_tld_thirdparty_warning`);
  if (freeTld.length) findings.push(`finding_brand_${freeTld.length}_tld_unprotected_info`);
  if (own.state === "free") findings.push("finding_brand_base_not_registered_warning");
  if (wildcard) findings.push("finding_brand_wildcard_dns_info");
  const unreliable = unknown > res.length / 2;
  if (unreliable) findings.push("finding_brand_dns_unreliable_info");
  const score = unreliable ? null : clamp(100 - Math.min(thirdTypo.length * 5, 35) - Math.min(thirdKw.length * 3, 12) - Math.min(thirdTld.length * 6, 30) - Math.min(mention.length * 6, 18) - phishy.length * 25);
  const fmt = (a) => a.map(r => `${r.n}${r.ns[0] ? " → " + r.ns[0] : ""}`);
  const spec = { domain: base, checkedTldVariants: tlds.length, checkedTypoVariants: typos.length, checkedKeywordVariants: kw.length, ownedOrSameOwner: reg.filter(mine).map(r => r.n), thirdPartyTldVariants: fmt(thirdTld), thirdPartyLookalikes: fmt(thirdTypo), thirdPartyKeywordDomains: fmt(thirdKw),
    activeLookalikeSites: live.map(l => `${l.n} (HTTP ${l.status}${l.title ? ", '" + l.title + "'" : ""}${l.mentionsBrand ? ", marka adı geçiyor" : ""}${l.loginForm ? ", GİRİŞ FORMU var" : ""})`), unregisteredTlds: freeTld.map(r => r.n), undetermined: unknown,
    note: "Kayıt tespiti DNS'e dayanır: aynı nameserver/IP'ye sahip olanlar 'sizin' sayılır. DNS'i olmayan ama kayıtlı alan adları görünmez; kesin sahiplik için WHOIS/RDAP gerekir." };
  if (score == null) return unavailableResult({ assetType: "BRAND", version: V, startedAt, target: base, finding: "finding_brand_dns_unreliable_info", status: "UNKNOWN", note: "DNS sorguları yeterince yanıt vermedi.", specific: spec });
  return buildResult({ assetType: "BRAND", version: V, startedAt, target: base, findings, score, specific: spec });
}

// =====================================================================
// SAAS ABONELİK v4 (girilen verileri değerlendirir; uydurma skor üretmez)
// =====================================================================
async function scanSaasSubscription(extra = {}) {
  const startedAt = Date.now(); const V = "saas-analyzer-v4.0"; const findings = [];
  const provider = String(extra.provider || extra.name || "unknown").trim().toLowerCase(); const renewalDate = extra.renewalDate || extra.expiryDate || null;
  const rd = toDateOrNull(renewalDate); const remainingDays = rd ? daysUntil(rd) : (extra.remainingDays ?? null);
  const cost = Number(extra.cost) || 0; const currency = extra.currency || "TRY"; const plan = extra.plan || "unknown"; const usage = extra.usagePercent === "" || extra.usagePercent == null ? null : Number(extra.usagePercent);
  const autoRenew = extra.autoRenew === undefined ? null : (extra.autoRenew === true || extra.autoRenew === "true");
  const c = makeChecker(); let expiryStatus = "HEALTHY";
  if (remainingDays !== null) {
    if (remainingDays < 0) { expiryStatus = "EXPIRED"; c.add(false, 60, "finding_saas_expired_critical", "renewal"); }
    else { c.add(remainingDays >= 14, 25, "finding_saas_expiring_soon_critical", "renewal"); c.add(remainingDays >= 30, 15, "finding_saas_expiring_soon_warning", "renewal"); expiryStatus = remainingDays < 14 ? "CRITICAL" : remainingDays < 30 ? "WARNING" : "HEALTHY"; if (remainingDays >= 30) c.add(true, 60, null, "renewal"); }
    if (autoRenew === false && remainingDays >= 0 && remainingDays < 30) c.add(false, 15, "finding_saas_manual_renewal_due_warning", "renewal");
  } else findings.push("finding_saas_missing_renewal_warning");
  if (usage != null && !isNaN(usage)) {
    c.add(usage <= 90, 40, "finding_saas_usage_critical", "usage"); if (usage <= 90) c.add(usage <= 80, 20, "finding_saas_usage_high_warning", "usage");
    if (cost > 0) c.add(usage >= 20, 30, "finding_saas_underused_warning", "usage");
  }
  const scored = c.score(); const g = c.groupScores();
  const monthly = extra.billingCycle === "yearly" ? cost / 12 : cost;
  const specific = { provider, plan, renewalDate: rd, remainingDays, cost, currency, billingCycle: extra.billingCycle || "monthly", monthlyCost: Math.round(monthly * 100) / 100, yearlyCost: Math.round(monthly * 12 * 100) / 100, usagePercent: usage, autoRenew, scores: { renewal: g.renewal ?? null, usage: g.usage ?? null },
    note: scored == null ? "Yenileme tarihi ve kullanım oranı girilmediği için skor hesaplanamadı." : undefined };
  const allF = sortFindings([...c.findings(), ...findings]);
  const status = scored == null ? "UNKNOWN" : expiryStatus === "EXPIRED" ? "CRITICAL" : expiryStatus === "HEALTHY" && scored >= 80 ? "HEALTHY" : "WARNING";
  const commonAnalysis = { analyzerVersion: V, executionTimeMs: Date.now() - startedAt, findings: allF, scannedAt: new Date().toISOString(), score: scored, status, target: provider };
  return { data: { assetId: extra.assetId || `saas_${provider.replace(/\W/g, "_")}_${Date.now()}`, assetType: "SAAS_SUBSCRIPTION", commonAnalysis, specificAnalysis: { ...specific, scores: { ...specific.scores, ...(scored != null ? { overall: scored } : {}) } }, analysisMeta: { scannerVersion: V, analyzer: "saas" }, provider, plan, renewalDate: rd, remainingDays, cost }, findings: allF, errors: [], statusHint: expiryStatus === "EXPIRED" ? "EXPIRED" : status === "UNKNOWN" ? "UNKNOWN" : "ACTIVE" };
}

// =====================================================================
// ROUTER
// =====================================================================
// ===== ANALYTICS (Google Analytics 4 / GTM) =====
// Firestore'daki ANALYTICS belge yapısı korunur: commonAnalysis + specificAnalysis{health, property, traffic}.
// GA Data API kimlik bilgisi olmadan canlı trafik ölçülemez: dataReceiving / activeUsers24h / bounceRate / realtimeUsers
// UYDURULMAZ, null döner. Burada yalnızca sitede doğrulanabilen etiket kurulumu denetlenir.
async function scanAnalytics(targetUrl, extra = {}) {
  const startedAt = Date.now(); const V = "analytics-analyzer-v1.0"; const url = ensureUrl(targetUrl);
  const declared = String(extra.measurementId || "").trim().toUpperCase();
  const declaredValid = /^G-[A-Z0-9]{4,14}$/.test(declared);
  const main = await httpProbe(url, { timeout: 12000, maxRedirects: 4 });
  const prot = main.status ? detectBotProtection(main) : null;
  if (prot) return protectedResult("ANALYTICS", V, startedAt, url, main, prot);
  if (main.status === 0) return downResult("ANALYTICS", V, startedAt, url, main, netErrorFinding("analytics", main));
  const body = String(main.body || "");
  const uniq = (re, g = 1) => [...new Set([...body.matchAll(re)].map(m => m[g].toUpperCase()))].slice(0, 10);
  const ga4 = [...new Set([...uniq(/googletagmanager\.com\/gtag\/js\?id=(G-[A-Z0-9]+)/gi), ...uniq(/gtag\(\s*['"]config['"]\s*,\s*['"](G-[A-Z0-9]+)['"]/gi)])];
  const gtm = uniq(/googletagmanager\.com\/gtm\.js\?id=(GTM-[A-Z0-9]+)/gi);
  const ua = uniq(/\b(UA-\d{4,10}-\d{1,4})\b/gi);
  const legacyJs = /google-analytics\.com\/(analytics|ga)\.js/i.test(body);
  const tagType = ga4.length ? "gtag" : gtm.length ? "gtm" : legacyJs || ua.length ? "legacy" : null;
  const c = makeChecker();
  c.add(main.status < 400, 15, "finding_analytics_site_error_status_critical", "erisim");
  c.add(/^https:/i.test(main.finalUrl || url), 5, "finding_analytics_not_https_warning", "erisim");
  c.add(!!(ga4.length || gtm.length), 40, "finding_analytics_no_tag_critical", "yayin");
  let idMatch = null;
  if (declaredValid && ga4.length) idMatch = ga4.includes(declared);
  if (idMatch !== null) c.add(idMatch, 25, "finding_analytics_measurement_id_mismatch_critical", "yayin");
  c.add(!(ua.length || legacyJs) || ga4.length > 0, 10, "finding_analytics_legacy_ua_warning", "kalite");
  let scriptOk = null;
  const checkId = declaredValid ? declared : ga4[0];
  if (checkId) { const sp = await httpProbe("https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(checkId), { timeout: 8000, maxRedirects: 1, noUaFallback: true, readBody: false }); scriptOk = sp.status === 200; c.add(scriptOk, 5, "finding_analytics_tag_script_unreachable_warning", "kalite"); }
  const findings = c.findings();
  if (extra.measurementId && !declaredValid) findings.push("finding_analytics_measurement_id_invalid_warning");
  if (gtm.length && !ga4.length) findings.push("finding_analytics_gtm_only_info");
  findings.push("finding_analytics_live_data_unavailable_info");
  const specific = {
    health: { tagDetected: !!tagType, tagType, measurementIdMatches: idMatch, tagScriptReachable: scriptOk, dataReceiving: null, conversionEventsCount: null, lastDataReceivedAt: null },
    property: { measurementId: declaredValid ? declared : (ga4[0] || null), propertyName: extra.propertyName ? String(extra.propertyName).slice(0, 120) : null, provider: "Google Analytics 4", detectedMeasurementIds: ga4, gtmContainers: gtm, legacyIds: ua },
    traffic: { activeUsers24h: null, bounceRate: null, realtimeUsers: null },
    scores: c.groupScores(),
    note: "Canlı trafik, dönüşüm ve veri alımı değerleri Google Analytics Data API yetkisi gerektirir; bağlanmadığı için boş bırakıldı."
  };
  return buildResult({ assetType: "ANALYTICS", version: V, startedAt, target: url, findings, specific, score: c.score() });
}

const TYPE_HANDLERS = {
  WEB: ({ targetUrl, extra }) => scanWebsite(targetUrl, extra),
  WEBSITE: ({ targetUrl, extra }) => scanWebsite(targetUrl, extra),
  DOMAIN: ({ targetUrl, extra }) => scanDomain(targetUrl || extra.domain || extra.target, extra),
  EMAIL: ({ targetUrl, extra }) => scanDomain(targetUrl || extra.domain || extra.target, extra),
  SSL_CERTIFICATE: ({ targetUrl, extra }) => scanSslCertificate(targetUrl || extra.domain || extra.target, extra),
  SSL: ({ targetUrl, extra }) => scanSslCertificate(targetUrl || extra.domain || extra.target, extra),
  HOSTING: ({ targetUrl, extra }) => scanHosting(targetUrl || extra.domain || extra.target),
  SERVER: ({ targetUrl, extra }) => scanServer(targetUrl || extra.domain || extra.target),
  SEO: ({ targetUrl, extra }) => scanSeo(targetUrl || extra.target),
  SECURITY: ({ targetUrl, extra }) => scanSecurity(targetUrl || extra.target),
  PERFORMANCE: ({ targetUrl, extra }) => scanPerformance(targetUrl || extra.target),
  UPTIME: ({ targetUrl, extra }) => scanUptime(targetUrl || extra.target, extra),
  API: ({ targetUrl, extra }) => scanApi(targetUrl || extra.target),
  ANALYTICS: ({ targetUrl, extra }) => scanAnalytics(targetUrl || extra.target, extra),
  MOBILE_APP: ({ targetUrl, extra }) => scanMobileApp(targetUrl || extra.target),
  REPOSITORY: ({ targetUrl, extra }) => scanRepository(targetUrl || extra.target),
  BRAND: ({ targetUrl, extra }) => scanBrand(targetUrl || extra.target, extra),
  SAAS_SUBSCRIPTION: ({ extra }) => scanSaasSubscription(extra)
};
const NO_HOST_TYPES = ["SAAS_SUBSCRIPTION", "MOBILE_APP", "REPOSITORY"];
const ACTIVE_PROBE_TYPES = ["SERVER", "SECURITY"]; // port taraması / hassas dosya yoklaması: yetki beyanı gerekir
const SCAN_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS || "75000", 10);

// Firestore: iç içe dizi yasak, 1 MB belge sınırı, NaN/Infinity sorunlu. Güvenli hale getir.
function forFirestore(v, depth = 0) {
  if (v == null) return v === undefined ? undefined : null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string") return v.length > 4000 ? v.slice(0, 4000) + "…" : v;
  if (typeof v === "boolean" || v instanceof Date) return v;
  if (depth > 8) return null;
  if (Array.isArray(v)) return v.slice(0, 200).map(x => Array.isArray(x) ? JSON.stringify(x).slice(0, 2000) : forFirestore(x, depth + 1)).filter(x => x !== undefined);
  if (typeof v === "object") { const o = {}; for (const k of Object.keys(v)) { if (k === "debug" || k.includes(".") && false) continue; const x = forFirestore(v[k], depth + 1); if (x !== undefined) o[k.replace(/[.\/\[\]*`~]/g, "_")] = x; } return o; }
  return String(v);
}

// ===== Site dosyalarını aynı sunucudan yayınla (yalnızca public/ klasörü; sunucu kodu asla yayınlanmaz) =====
const PUBLIC_DIR = STRUCT ? path.join(__dirname, "public") : __dirname;
const LEGAL_PAGES = { "/kvkk": "kvkk.html", "/gizlilik": "gizlilik.html", "/kullanim-kosullari": "kullanim-kosullari.html", "/cerez-politikasi": "cerez-politikasi.html", "/mesafeli-satis": "mesafeli-satis.html", "/iade-iptal": "iade-iptal.html", "/iletisim": "iletisim.html", "/kabul-edilebilir-kullanim": "kabul-edilebilir-kullanim.html", "/hakkimizda": "hakkimizda.html" };
// Herkese açık site adresi (sitemap, robots, llms.txt, security.txt). Varsayılan: https://dacweb.tr.
// Render'da SITE_URL hâlâ *.onrender.com ise YOK SAYILIR (arama motorlarına yanlış adres verilmesin); gerçekten başka bir alan adı kullanacaksanız onrender dışı bir adres girin.
const SITE_URL = (() => { const d = "https://dacweb.tr"; const v = String(process.env.SITE_URL || "").trim().replace(/\/+$/, ""); if (!/^https:\/\/[a-z0-9.-]+$/i.test(v)) return d; if (/\.onrender\.com$/i.test(v)) { console.warn("SITE_URL bir onrender.com adresi: yok sayıldı, " + d + " kullanılıyor. Render > Environment'tan SITE_URL'yi güncelleyin veya silin."); return d; } return v; })();
app.get("/robots.txt", (q, r) => { r.type("text/plain; charset=utf-8").set("Cache-Control", "public, max-age=3600").send(`User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /health\n\nSitemap: ${SITE_URL}/sitemap.xml\n`); });
// Sitemap: sayfa dosyasının son değişiklik tarihi lastmod olarak yazılır (Google için güvenilir sinyal)
const SITEMAP_PAGES = [["/", 1.0, "weekly"], ["/hakkimizda", 0.8, "monthly"], ["/iletisim", 0.7, "monthly"], ["/kvkk", 0.4, "yearly"], ["/gizlilik", 0.4, "yearly"], ["/cerez-politikasi", 0.3, "yearly"], ["/kullanim-kosullari", 0.4, "yearly"], ["/kabul-edilebilir-kullanim", 0.3, "yearly"], ["/mesafeli-satis", 0.3, "yearly"], ["/iade-iptal", 0.3, "yearly"]];
const pageFile = (u) => u === "/" ? path.join(PUBLIC_DIR, "index.html") : (STRUCT ? path.join(PUBLIC_DIR, "legal", LEGAL_PAGES[u] || "") : path.join(__dirname, LEGAL_PAGES[u] || ""));
const lastmodOf = (u) => { try { return fs.statSync(pageFile(u)).mtime.toISOString().slice(0, 10); } catch { return new Date().toISOString().slice(0, 10); } };
app.get("/sitemap.xml", (q, r) => {
  const urls = SITEMAP_PAGES.map(([u, p, f]) => `  <url>\n    <loc>${SITE_URL}${u === "/" ? "/" : u}</loc>\n    <lastmod>${lastmodOf(u)}</lastmod>\n    <changefreq>${f}</changefreq>\n    <priority>${p.toFixed(1)}</priority>\n  </url>`).join("\n");
  r.type("application/xml; charset=utf-8").set("Cache-Control", "public, max-age=3600").send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`);
});
app.get("/llms.txt", (q, r) => { r.type("text/plain; charset=utf-8").set("Cache-Control", "public, max-age=86400").send(`# Digital Asset Center (DAC)\n\n> Domain, SSL, DNS, web güvenliği, SEO ve performans taramalarını tek panelden yapan, yenileme tarihlerini takip eden dijital varlık yönetim uygulaması. HZ Yazılım tarafından geliştirilir.\n\nUygulamaya Google veya e-posta ile giriş yapılır; bu yüzden aşağıdaki sayfalar herkese açık bilgi kaynağıdır.\n\n## Hakkında\n- [Hakkımızda: HZ Yazılım ve ürün](${SITE_URL}/hakkimizda)\n- [İletişim ve şirket bilgileri](${SITE_URL}/iletisim)\n\n## Yasal metinler\n- [KVKK Aydınlatma Metni](${SITE_URL}/kvkk)\n- [Gizlilik Politikası](${SITE_URL}/gizlilik)\n- [Çerez Politikası](${SITE_URL}/cerez-politikasi)\n- [Kullanım Koşulları](${SITE_URL}/kullanim-kosullari)\n- [Kabul Edilebilir Kullanım](${SITE_URL}/kabul-edilebilir-kullanim)\n- [Mesafeli Satış Sözleşmesi](${SITE_URL}/mesafeli-satis)\n- [İptal ve İade](${SITE_URL}/iade-iptal)\n`); });
if (SEC.isProd() && !process.env.SECURITY_CONTACT) console.warn("UYARI: SECURITY_CONTACT tanımlı değil; /.well-known/security.txt içinde yer tutucu adres görünür. Render > Environment'a SECURITY_CONTACT=mailto:guvenlik@alanadiniz.com ekleyin.");
const securityTxt = (q, r) => { const exp = new Date(Date.now() + 365 * 864e5).toISOString(); r.type("text/plain").set("Cache-Control", "public, max-age=86400").send(`Contact: ${process.env.SECURITY_CONTACT || "mailto:security@example.com"}\nExpires: ${exp}\nPreferred-Languages: tr, en\nCanonical: ${SITE_URL}/.well-known/security.txt\n`); };
app.get("/.well-known/security.txt", securityTxt); app.get("/security.txt", securityTxt);
app.get("/sw.js", (q, r) => { r.set({ "Cache-Control": "no-cache", "Service-Worker-Allowed": "/" }); r.type("application/javascript").sendFile(path.join(PUBLIC_DIR, "sw.js")); });
app.get("/", (q, r) => { r.set("Cache-Control", "no-cache"); r.sendFile(path.join(PUBLIC_DIR, "index.html")); });
Object.entries(LEGAL_PAGES).forEach(([route, file]) => app.get(route, (q, r) => { r.set("Cache-Control", "no-cache"); r.sendFile(STRUCT ? path.join(PUBLIC_DIR, "legal", file) : path.join(__dirname, file)); }));
if (STRUCT) {
// Eski (düz klasör) adreslerden yeni konumlara kalıcı yönlendirme: eski önbellekli sayfalar/sekmeler kırılmasın
const LEGACY_URLS = { "/style.css": "/css/style.css", "/app.js": "/js/app.js", "/login.js": "/js/login.js", "/config.js": "/js/config.js", "/plans.js": "/js/plans.js", "/company.js": "/js/company.js", "/legal.js": "/js/legal.js",
  "/cookie-consent.js": "/js/cookie-consent.js", "/sw-register.js": "/js/sw-register.js", "/lucide.min.js": "/js/lucide.min.js", "/icon-192.png": "/icons/icon-192.png", "/icon-512.png": "/icons/icon-512.png", "/index.html": "/" };
for (const f of ["inter-latin", "inter-latin-ext", "jbmono-400-latin", "jbmono-400-ext", "jbmono-500-latin", "jbmono-500-ext"]) LEGACY_URLS[`/${f}.woff2`] = `/fonts/${f}.woff2`;
for (const f of Object.values(LEGAL_PAGES)) LEGACY_URLS["/" + f] = "/legal/" + f;
Object.entries(LEGACY_URLS).forEach(([from, to]) => app.get(from, (q, r) => r.redirect(301, to)));
app.use(express.static(PUBLIC_DIR, { index: false, redirect: false, dotfiles: "ignore", etag: true, setHeaders: (res, file) => {
  const base = path.basename(file);
  res.setHeader("Cache-Control", /\.(js|css|html)$/i.test(base) ? "no-cache" : base === "manifest.json" ? "public, max-age=3600" : "public, max-age=86400, stale-while-revalidate=604800");
} }));
} else {
  // Düz yerleşim: yalnızca bu izin listesindeki dosyalar yayınlanır (sunucu kodu asla yayınlanmaz)
  const FLAT_OK = new Set(["style.css", "i18n.js", "i18n-en.js", "landing.js", "app.js", "app-analysis.js", "app-main.js", "app-bulk.js", "app-admin.js", "app-admin-ops.js", "app-support.js", "login.js", "config.js", "plans.js", "company.js", "legal.js", "cookie-consent.js", "sw-register.js", "lucide.min.js", "manifest.json", "icon-192.png", "icon-512.png",
    "support-form.js", "inter-latin.woff2", "inter-latin-ext.woff2", "jbmono-400-latin.woff2", "jbmono-400-ext.woff2", "jbmono-500-latin.woff2", "jbmono-500-ext.woff2"]);
  app.get("/index.html", (q, r) => r.redirect(301, "/"));
  app.use((req, res, next) => {
    if (req.method !== "GET" && req.method !== "HEAD") return next();
    const m = /^\/(?:(?:css|js|fonts|icons)\/)?([A-Za-z0-9._-]+)$/.exec(req.path);
    if (!m || !FLAT_OK.has(m[1])) return next();
    res.set("Cache-Control", /\.(js|css|html)$/i.test(m[1]) ? "no-cache" : m[1] === "manifest.json" ? "public, max-age=3600" : "public, max-age=86400, stale-while-revalidate=604800");
    res.sendFile(path.join(__dirname, m[1]));
  });
}

// Ticari ayarlar (V13.2): yönetici panelinden değişen fiyat/limit, kupon, duyuru ve bakım modu (commerce.js)
const COMMERCE = SRV("commerce")({ db, PLANS, log: (m) => console.warn("commerce:", m) });
const MAILER = SRV("mailer")({ db, http: axios, log: (m) => console.warn("mailer:", m) });
const payments = SRV("payments")({ app, db, admin, http: axios, commerce: COMMERCE, mailer: MAILER });
OPS = SRV("ops")({ db, admin, http: axios, mailer: MAILER, metrics: METRICS, PLANS, log: (m) => console.warn("ops:", m) });
const SUPPORT = SRV("support")({ db, http: axios, mailer: MAILER, SEC, verifyUser: payments.verifyUser, log: (m) => console.warn("support:", m) }); SUPPORT.mount(app);
const COMMERCE_PUBLIC = COMMERCE.mountPublic(app, { SEC, getVerifyUser: () => payments.verifyUser, getIsAdmin: () => async (u) => (await ADMIN.roleOf(u)).admin });
app.post(["/api/scan", "/api/jobs"], COMMERCE_PUBLIC.maintenanceGuard); // bakım modunda yeni tarama başlatma (yönetici hariç)
app.post("/api/scan", COMMERCE_PUBLIC.scanTypeGuard); // yönetici panelinden kapatılan tarama türleri
COMMERCE.start(); if (db && !process.env.NODE_TEST) OPS.start();
const USER_STATE = SRV("user-state")({ app, db, admin, verifyUser: payments.verifyUser });
const ALERTS = SRV("alerts");
const PUSH = SRV("push")({ app, db, verifyUser: payments.verifyUser }); // tarayıcı bildirimleri (Web Push)

// Tarayıcı için herkese açık Firebase web yapılandırması (Render ortam değişkenlerinden; kodda sabit değer yok)
app.get("/api/firebase-config", (req, res) => {
  res.set("Cache-Control", "no-store");
  const w = FB.webConfig();
  if (!w.ok) return res.status(503).json({ success: false, error: w.error || "Firebase web yapılandırması eksik.", missing: w.missing });
  res.json({ success: true, config: w.config });
});

// ---- Hız ve eşzamanlılık sınırları (bellek içi: tek Render örneği için; çoklu örnekte Redis gerekir) ----
const ipLimit = SEC.makeLimiter(SEC.int(process.env.SCAN_RATE_LIMIT, 60), 5 * 60 * 1000);
const userLimit = SEC.makeLimiter(SEC.int(process.env.SCAN_USER_RATE_LIMIT, 30), 5 * 60 * 1000);
const concurrency = SEC.makeConcurrency(SEC.int(process.env.SCAN_CONCURRENCY_PER_USER, 2), SEC.int(process.env.SCAN_CONCURRENCY_GLOBAL, 8));
const tooMany = (res, msg) => res.status(429).json({ success: false, error: msg || "Çok fazla istek. Biraz sonra tekrar deneyin." });
const scanGuard = [
  (req, res, next) => (ipLimit(req.ip) ? next() : tooMany(res)),
  SEC.authenticate(async (req) => {
    if (db) return payments.verifyUser(req); // Firebase Admin varsa onunla doğrula
    const m = String(req.headers.authorization || "").match(/^Bearer (.+)$/i); // yoksa Google'ın açık anahtarlarıyla doğrula
    if (!m) throw Object.assign(new Error("Giriş yapmanız gerekiyor."), { status: 401 });
    return SEC.verifyFirebaseToken(m[1], FB.EXPECTED_PROJECT_ID);
  }),
  (req, res, next) => (userLimit(req.user.uid) ? next() : tooMany(res))
];

// ===== Korumalı hedef politikası (blocklist.js) =====
// Yasaklı deneme sayısı sınırlanır (keşif/suistimal): 10 dakikada 6'dan fazla yasaklı deneme yapan kullanıcı geçici olarak engellenir. Denemeler `blockedAttempts` koleksiyonuna yazılır (yönetici görür).
const blockedLimit = SEC.makeLimiter(SEC.int(process.env.BLOCKED_ATTEMPT_LIMIT, 6), 10 * 60 * 1000);
function recordBlocked({ uid, ip, assetType, pol, where }) {
  try { METRICS.observe("scan.BLOCKED", 1); } catch {}
  console.warn(`[blocked] uid=${uid} type=${assetType} category=${pol.category} where=${where || "api"}`);
  if (db) db.collection("blockedAttempts").doc().set({ uid: uid || null, ip: ip || null, assetType: assetType || null, host: String(pol.matched || "").slice(0, 253), category: pol.category, rule: String(pol.rule || "").slice(0, 120), via: pol.viaCname || null, where: where || "api", at: Date.now(), expireAt: new Date(Date.now() + 180 * 864e5) }).catch(() => {}); // expireAt: Firestore TTL ilkesi tanımlanırsa 180 gün sonra silinir (KVKK saklama süresi)
}
// Sözdizimsel denetim + CNAME zinciri (takma ad olarak devlet/DAC alan adına işaret eden hedefler)
async function policyCheck({ assetType, targetUrl, extra }) {
  const r = BLOCK.checkScan({ assetType, targetUrl, extra }); if (r.blocked) return r;
  if (!NO_HOST_TYPES.includes(assetType)) {
    const host = hostOf(targetUrl || (extra && (extra.domain || extra.target)));
    if (host && !net.isIP(host)) { try { const chain = await withTimeout(BLOCK.resolveCnameChain((h) => dns.resolveCname(h), host), 3000, "CNAME"); const c = BLOCK.checkChain(chain); if (c.blocked) return { ...c, matched: host }; } catch { /* çözülemedi: engelleme kararı verilemez, sözdizimsel kontrol geçerli */ } }
  }
  return { blocked: false };
}
function blockedReply(res, req, pol, assetType) {
  res.locals.expectedBlock = true; // beklenen yanıt: sistem hatası / hata rozeti olarak sayılmaz
  recordBlocked({ uid: req.user && req.user.uid, ip: req.ip, assetType, pol });
  if (req.user && !blockedLimit(req.user.uid)) return res.status(429).json({ success: false, code: "TOO_MANY_BLOCKED", error: "Çok fazla yasaklı hedef denemesi yaptınız. Bir süre sonra tekrar deneyin." });
  return res.status(403).json({ success: false, code: "TARGET_BLOCKED", error: pol.message || BLOCK.MESSAGE_GENERIC });
}

// Tek bir taramayı çalıştırır ve sonucu kaydeder. Hem POST /api/scan hem toplu tarama kuyruğu AYNI çekirdeği kullanır
// (doğrulama, sahiplik ve kota denetimleri çağıran tarafta yapılır).
async function executeScan({ uid, assetId, assetType, handler, targetUrl, extra, name, ip }) {
  { const pol = BLOCK.checkScan({ assetType, targetUrl, extra }); if (pol.blocked) { recordBlocked({ uid, ip, assetType, pol, where: "execute" }); return { scanStatus: "BLOCKED", assetId, checkId: null, saved: false, saveError: null, scanErrors: [pol.message], assetUpdate: {}, blocked: pol }; } } // son kapı: önceki katmanlar atlansa bile yasaklı hedef taranmaz, hiçbir kayıt yazılmaz
  const scanStartedAt = Date.now(); let findings = [], scanErrors = [], typeData = {}, statusHint = null, failed = false, scanConfidence = null;
  try {
    const result = await withTimeout(Promise.resolve(handler({ targetUrl, extra })), SCAN_TIMEOUT_MS, "Tarama");
    typeData = result?.data || {}; findings = Array.isArray(result?.findings) ? result.findings : [];
    if (Array.isArray(result?.errors)) scanErrors.push(...result.errors); statusHint = result?.statusHint || null; scanConfidence = result?.confidence ?? null;
  } catch (e) {
    console.error(`[${assetType}] tarama hatası:`, e && e.stack || e);
    findings.push(/zaman aşımı/i.test(e?.message || "") ? "finding_scan_timeout_warning" : "finding_scan_error"); scanErrors.push(e?.message || "Unknown"); statusHint = "ERROR"; failed = true;
  }
  const noData = !typeData || !typeData.commonAnalysis;
  const healthResult = computeHealth(findings); const confidence = scanConfidence != null ? scanConfidence : computeConfidence(findings, scanErrors.length > 0);
  const scoreUnavailable = failed || noData || typeData.commonAnalysis.score == null;
  let finalHealthScore = scoreUnavailable ? null : typeData.commonAnalysis.score; let finalHealthLevel = "BELİRSİZ";
  if (finalHealthScore != null) finalHealthLevel = finalHealthScore >= 80 ? "YEŞİL" : finalHealthScore >= 50 ? "SARI" : "KIRMIZI";
  let finalStatus = noData || failed ? "ERROR" : (statusHint || typeData.commonAnalysis.status || defaultStatusFromHealth(finalHealthLevel));
  const timedOut = failed && scanErrors.some(m => /zaman aşımı/i.test(String(m)));
  const scanStatus = timedOut ? "TIMEOUT" : (failed || noData) ? "FAILED" : scanErrors.length ? "PARTIAL" : "COMPLETED";
  const nowIso = new Date().toISOString();
  const assetUpdate = { assetId, scanStatus, assetType, type: assetType, ...typeData, findings, healthLevel: finalHealthLevel, healthScore: finalHealthScore, confidence, status: finalStatus, latencyMs: Date.now() - scanStartedAt, lastCheck: nowIso, updatedAt: nowIso };
  if (name) assetUpdate.name = String(name).slice(0, 200); if (targetUrl) assetUpdate.targetUrl = targetUrl.slice(0, 2048); assetUpdate.ownerId = uid; // sahip bilgisi yalnızca doğrulanmış oturumdan gelir
  let saved = false, checkId = null, saveError = null;
  if (db) {
    try {
      const ts = admin.firestore.FieldValue.serverTimestamp(); const doc = forFirestore({ ...assetUpdate, lastCheck: undefined, updatedAt: undefined });
      await withTimeout((async () => {
        await db.collection("assets").doc(assetId).set({ ...doc, target: typeData?.commonAnalysis?.target ?? targetUrl ?? null, scannedAt: ts, lastCheck: ts, updatedAt: ts, auto: false, nextScanAt: Date.now() + ALERTS.intervalMs(assetType), scanExtra: forFirestore(extra), ...(ACTIVE_PROBE_TYPES.includes(assetType) ? { authorizationConfirmed: true } : {}) }, { merge: true }); // scannedAt/target: Firestore'daki mevcut varlık belge yapısıyla uyum
        const checkRef = db.collection("assetChecks").doc(); checkId = checkRef.id;
        await checkRef.set(forFirestore({ assetId, checkId, type: assetType, targetUrl: targetUrl || null, errors: scanErrors, findings, healthScore: finalHealthScore, healthLevel: finalHealthLevel, confidence, latencyMs: Date.now() - scanStartedAt, status: finalStatus, scanStatus, ownerId: uid, scannerVersion: typeData?.analysisMeta?.scannerVersion || null, scores: typeData?.specificAnalysis?.scores || null, checkedAt: ts, ...(ACTIVE_PROBE_TYPES.includes(assetType) ? { authorizationConfirmed: true, authorizationIp: ip || null } : {}) }) );
      })(), 8000, "Firestore");
      saved = true;
    } catch (e) { saveError = e?.message || "Firestore hatası"; console.error("Firestore kayıt hatası:", saveError); }
  }
  METRICS.observe("scanDurationMs", Date.now() - scanStartedAt); METRICS.observe("scan." + scanStatus, 1);
  return { scanStatus, assetId, checkId, saved, saveError, scanErrors, assetUpdate };
}
const dateIso = (d) => (d instanceof Date ? d.toISOString() : d || null);
// Kuyruk için küçük sonuç özeti (domain bitişi yalnızca RDAP'tan gelen kayıttan okunur; tarih uydurulmaz)
function scanSummary(out, assetType) {
  const u = out.assetUpdate || {}, reg = (u.specificAnalysis && u.specificAnalysis.registration) || {};
  const base = { scanStatus: out.scanStatus, score: u.healthScore ?? null, status: u.status || null, latencyMs: u.latencyMs ?? null };
  if (assetType === "DOMAIN" || assetType === "EMAIL") Object.assign(base, { expiresAt: dateIso(reg.expiresAt), remainingDays: Number.isFinite(reg.remainingDays) ? reg.remainingDays : null, expirySource: reg.source || null });
  if (assetType === "SSL_CERTIFICATE" || assetType === "SSL") { const cert = (u.specificAnalysis && u.specificAnalysis.cert) || {}; Object.assign(base, { expiresAt: dateIso(cert.validTo), remainingDays: Number.isFinite(cert.daysRemaining) ? cert.daysRemaining : null, expirySource: "tls" }); }
  return base;
}

app.post("/api/scan", scanGuard, async (req, res) => {
  const body = req.body || {}; const { assetId, type, name, notes } = body; const uid = req.user.uid;
  const targetUrl = typeof body.targetUrl === "string" ? body.targetUrl.trim().slice(0, 2048) : "";
  if (body.targetUrl != null && typeof body.targetUrl !== "string") return res.status(400).json({ success: false, error: "targetUrl metin olmalı" });
  const extra = body.extra && typeof body.extra === "object" && !Array.isArray(body.extra) ? body.extra : {};
  if (!assetId || typeof assetId !== "string" || assetId.length > 200 || !/^[A-Za-z0-9_-]+$/.test(assetId)) return res.status(400).json({ success: false, error: "assetId gerekli (harf, rakam, - ve _)" });
  const assetType = String(type || "WEBSITE").toUpperCase(); const handler = TYPE_HANDLERS[assetType];
  if (!handler) return res.status(400).json({ success: false, error: `Desteklenmeyen tür: ${assetType}` });
  for (const k of ["domain", "target"]) if (extra[k] != null && typeof extra[k] !== "string") return res.status(400).json({ success: false, error: `extra.${k} metin olmalı` });
  if (!NO_HOST_TYPES.includes(assetType) && !(targetUrl || extra.domain || extra.target)) return res.status(400).json({ success: false, error: "Hedef adres gerekli" });
  // Korumalı hedefler (devlet/kamu, büyük platformlar, dacweb.tr): HİÇBİR türde taranamaz. Yetki beyanından, SSRF denetiminden ve kota/sahiplik kaydından ÖNCE.
  { const pol = await policyCheck({ assetType, targetUrl, extra }); if (pol.blocked) return blockedReply(res, req, pol, assetType); }
  // Aktif sondalama (port taraması, açık dosya yoklama) yalnızca kullanıcı yetkisini açıkça beyan ederse yapılır; beyan kayda alınır.
  if (ACTIVE_PROBE_TYPES.includes(assetType) && body.consent !== true) return res.status(400).json({ success: false, code: "CONSENT_REQUIRED", error: "Bu tarama türü için hedefi taramaya yetkili olduğunuzu onaylamalısınız." });
  if (!NO_HOST_TYPES.includes(assetType)) {
    const hostForCheck = hostOf(targetUrl || extra.domain || extra.target);
    if (!hostForCheck) return res.status(400).json({ success: false, error: "Geçerli bir hedef adres girin" });
    try { await assertPublicHost(hostForCheck); } catch (e) { return res.status(400).json({ success: false, error: e.message }); }
  }
  // Fail-closed: üretimde Firestore yoksa paket/sahiplik/kota denetlenemez; ücretli ürünü denetimsiz çalıştırmayız.
  if (SEC.enforcePlans() && !req.user.dev && !db && process.env.ALLOW_SCAN_WITHOUT_DB !== "true") return res.status(503).json({ success: false, error: "Sunucu yapılandırması eksik (veritabanı). Lütfen daha sonra tekrar deneyin." });
  // Eşzamanlılık yuvası, veritabanına yazmadan ÖNCE alınır (yuva yoksa kota tüketen boş varlık kaydı oluşmaz).
  const release = concurrency.acquire(uid);
  if (!release) return tooMany(res, "Aynı anda çok fazla tarama var. Birinin bitmesini bekleyin.");
  res.on("close", release);
  // Paket: üretimde her zaman sunucuda zorunlu (geliştirme test kullanıcısı hariç)
  let ent = null;
  if (SEC.enforcePlans() && !req.user.dev && db) { // paket bilgisi Firestore gerektirir; yoksa yalnızca giriş + hız sınırı uygulanır
    try { ent = await payments.getEntitlement(uid); } catch (e) { return res.status(e.status || 503).json({ success: false, error: e.message }); }
    if (ent.plan === "expired") return res.status(402).json({ success: false, code: "PLAN_REQUIRED", error: "Deneme süreniz bitti. Devam etmek için bir paket seçin." });
  }
  // Sahiplik + kota: başkasına ait varlık değiştirilemez
  if (db) {
    try {
      const claim = await SEC.claimAsset(db, assetId, uid);
      if (!claim.ok) return res.status(403).json({ success: false, code: "FORBIDDEN", error: claim.legacy ? "Bu kayıt sistem/eski veridir, kullanıcıya devredilemez." : "Bu varlık size ait değil." });
      if (ent) {
        const q = await SEC.checkAssetQuota(db, uid, ent.plan, claim.isNew);
        if (!q.ok) { if (claim.isNew) await db.collection("assets").doc(assetId).delete().catch(() => {}); return res.status(402).json({ success: false, code: "QUOTA_EXCEEDED", error: `Paket varlık limiti doldu (${q.limit}).` }); }
      }
    } catch (e) { console.error("Sahiplik/kota kontrolü hatası:", e.message); return res.status(503).json({ success: false, error: "Veritabanına ulaşılamadı, tekrar deneyin." }); }
  }
  const out = await executeScan({ uid, assetId, assetType, handler, targetUrl, extra, name, ip: req.ip });
  const { scanStatus, checkId, saved, saveError, scanErrors, assetUpdate } = out;
  if (scanStatus === "BLOCKED") res.locals.expectedBlock = true;
  if (scanStatus === "BLOCKED") return res.status(403).json({ success: false, code: "TARGET_BLOCKED", error: (out.blocked && out.blocked.message) || BLOCK.MESSAGE_GENERIC });
  if (scanStatus === "FAILED" || scanStatus === "TIMEOUT") {
    return res.status(scanStatus === "TIMEOUT" ? 504 : 502).json({ success: false, scanStatus, assetId, checkId, saved, error: scanStatus === "TIMEOUT" ? "Tarama zaman aşımına uğradı. Hedef yanıt vermiyor olabilir." : "Tarama tamamlanamadı. Hedefe ulaşılamadı veya analiz sırasında hata oluştu.", errors: scanErrors });
  }
  return res.json({ success: true, scanStatus, assetId, checkId, saved, saveError: saveError ? "Sonuç kaydedilemedi" : null, errors: scanErrors, result: assetUpdate });
});

// Varlık silme: kullanıcı arayüzden sildiğinde sunucudaki güncel kayıt da silinir (yoksa kota sayacında kalır). Tarama geçmişi (assetChecks) saklanır.
app.delete("/api/assets/:id", scanGuard, async (req, res) => {
  const id = String(req.params.id || "");
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(id)) return res.status(400).json({ success: false, error: "Geçersiz varlık kimliği" });
  if (!db) return res.status(503).json({ success: false, error: "Veritabanı yapılandırılmamış" });
  try {
    const ref = db.collection("assets").doc(id); const snap = await ref.get();
    if (!snap.exists) return res.json({ success: true, deleted: false });
    if (snap.data().ownerId !== req.user.uid) return res.status(403).json({ success: false, code: "FORBIDDEN", error: "Bu varlık size ait değil." });
    await ref.delete();
    res.json({ success: true, deleted: true });
  } catch (e) { console.error("Varlık silme hatası:", e.message); res.status(503).json({ success: false, error: "Silinemedi, tekrar deneyin." }); }
});

// ===== Otomatik tarama + tarayıcı bildirimi =====
// Her varlık türü kendi aralığında (alerts.js > INTERVAL_H) taranır. Yalnızca bildirimi açmış (pushSubs kaydı olan) ve paketi geçerli kullanıcıların varlıkları taranır.
// Sunucu içi zamanlayıcı yalnızca uyanıkken çalışır; Render ücretsiz planda uyuyorsa dışarıdan POST /api/cron/scan?key=CRON_SECRET çağıran bir cron (ör. cron-job.org, her 15 dk) kurun.
const MEM_SOFT_LIMIT = SEC.int(process.env.MEM_SOFT_MB, 380) * 1048576, MEM_HARD_LIMIT = SEC.int(process.env.MEM_HARD_MB, 450) * 1048576;
const AUTO_ENABLED = process.env.AUTO_SCAN !== "false";
const AUTO_BATCH = SEC.int(process.env.AUTO_SCAN_BATCH, 10);
let autoRunning = false;
async function autoScanOne(snap, ctx) {
  const d = snap.data(), ref = snap.ref, uid = d.ownerId, type = d.assetType || d.type;
  const later = (ms) => ref.set({ nextScanAt: Date.now() + ms }, { merge: true });
  if (!uid || !TYPE_HANDLERS[type]) return later(7 * 864e5);
  if (!ctx.subs.has(uid)) ctx.subs.set(uid, await PUSH.subsOf(uid));
  const subs = ctx.subs.get(uid); if (!subs.length) return later(24 * 36e5);
  if (SEC.enforcePlans()) {
    if (!ctx.ent.has(uid)) ctx.ent.set(uid, await payments.getEntitlement(uid).catch(() => ({ plan: "trial" })));
    if (ctx.ent.get(uid).plan === "expired") return later(24 * 36e5);
  }
  const prev = { status: d.status, findings: d.findings, expiryLevel: d.expiryLevel };
  const send = async (notes) => { for (const n of notes) await PUSH.notify(uid, { title: n.title, body: n.body, url: "/#assets", tag: `${snap.id}:${n.kind}` }, subs); };
  // Abonelik (SaaS): internetten taranmaz; yenileme tarihine göre yalnızca süre uyarısı verilir
  if (type === "SAAS_SUBSCRIPTION") {
    const r = ALERTS.decide({ type, name: d.name || d.provider, prev, next: { status: d.status, findings: d.findings, data: d }, now: Date.now() });
    await send(r.notes.filter((n) => n.kind === "expiry")); return ref.set({ expiryLevel: r.expiryLevel, nextScanAt: Date.now() + ALERTS.intervalMs(type) }, { merge: true });
  }
  { const targetUrl0 = String(d.targetUrl || "").slice(0, 2048), extra0 = d.scanExtra && typeof d.scanExtra === "object" ? d.scanExtra : {}; const pol = await policyCheck({ assetType: type, targetUrl: targetUrl0, extra: extra0 }); if (pol.blocked) { recordBlocked({ uid, ip: null, assetType: type, pol, where: "auto" }); return ref.set({ nextScanAt: Date.now() + 30 * 864e5, blocked: true, blockedCategory: pol.category }, { merge: true }); } } // eski kayıtlar da yasaklı hedefe karşı otomatik taranmaz
  if (ACTIVE_PROBE_TYPES.includes(type) && d.authorizationConfirmed !== true) return later(7 * 864e5); // yetki beyanı yoksa otomatik aktif sondalama yapılmaz
  const targetUrl = String(d.targetUrl || "").slice(0, 2048); const extra = d.scanExtra && typeof d.scanExtra === "object" ? { ...d.scanExtra } : {};
  if (type === "ANALYTICS" && !extra.measurementId && d.specificAnalysis?.property?.measurementId) extra.measurementId = d.specificAnalysis.property.measurementId;
  if (!NO_HOST_TYPES.includes(type)) { try { await assertPublicHost(hostOf(targetUrl || extra.domain || extra.target)); } catch { return later(7 * 864e5); } }
  const run = async () => withTimeout(Promise.resolve(TYPE_HANDLERS[type]({ targetUrl, extra })), SCAN_TIMEOUT_MS, "Tarama");
  const t0 = Date.now(); let result;
  try {
    result = await run();
    if ((result?.statusHint || result?.data?.commonAnalysis?.status) === "DOWN") { await sleep(20000); result = await run(); } // geçici kesintiden yanlış alarm olmasın: bir kez daha doğrula
  } catch (e) { console.warn(`[auto ${type}] tarama hatası:`, e.message); return later(36e5); }
  const typeData = result?.data || {}; if (!typeData.commonAnalysis) return later(36e5);
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const score = typeData.commonAnalysis.score ?? null; const level = score == null ? "BELİRSİZ" : score >= 80 ? "YEŞİL" : score >= 50 ? "SARI" : "KIRMIZI";
  const status = result.statusHint || typeData.commonAnalysis.status || defaultStatusFromHealth(level);
  const dec = ALERTS.decide({ type, name: d.name || targetUrl, prev, next: { status, findings, healthScore: score, data: typeData }, now: Date.now() });
  const ts = admin.firestore.FieldValue.serverTimestamp(); const nowIso = new Date().toISOString();
  const upd = forFirestore({ assetId: snap.id, scanStatus: "COMPLETED", assetType: type, type, ...typeData, findings, healthLevel: level, healthScore: score, confidence: result.confidence ?? computeConfidence(findings, false), status, latencyMs: Date.now() - t0, ownerId: uid, auto: true });
  await ref.set({ ...upd, scannedAt: ts, lastCheck: ts, updatedAt: ts, expiryLevel: dec.expiryLevel, nextScanAt: Date.now() + ALERTS.intervalMs(type) }, { merge: true });
  await db.collection("assetChecks").doc().set(forFirestore({ assetId: snap.id, type, targetUrl: targetUrl || null, errors: result.errors || [], findings, healthScore: score, healthLevel: level, confidence: result.confidence ?? null, latencyMs: Date.now() - t0, status, scanStatus: "COMPLETED", ownerId: uid, scannerVersion: typeData.analysisMeta?.scannerVersion || null, scores: typeData.specificAnalysis?.scores || null, checkedAt: ts, auto: true }));
  await send(dec.notes);
}
async function runDueScans() {
  if (!db || autoRunning) return { skipped: true }; if (process.memoryUsage().rss > MEM_SOFT_LIMIT) { console.warn("[mem] bellek yüksek, otomatik tarama turu atlandı"); return { skipped: true, reason: "memory" }; } autoRunning = true; const ctx = { subs: new Map(), ent: new Map() }; let done = 0;
  try {
    const snap = await db.collection("assets").where("nextScanAt", "<=", Date.now()).orderBy("nextScanAt").limit(AUTO_BATCH).get();
    await pool(snap.docs, SEC.int(process.env.AUTO_SCAN_POOL, 1), async (doc) => { try { await autoScanOne(doc, ctx); done++; } catch (e) { console.error("Otomatik tarama hatası:", e.message); await doc.ref.set({ nextScanAt: Date.now() + 36e5 }, { merge: true }).catch(() => {}); } });
  } catch (e) { console.error("Otomatik tarama turu hatası:", e.message); }
  finally { autoRunning = false; }
  return { scanned: done };
}
// Eski varlıklarda nextScanAt alanı yoksa bir kez ekle (sorgu onları bulabilsin)
async function backfillNextScan() {
  try { const snap = await db.collection("assets").select("nextScanAt").limit(2000).get(); const todo = snap.docs.filter((d) => d.data().nextScanAt == null); for (let i = 0; i < todo.length; i += 400) { const b = db.batch(); todo.slice(i, i + 400).forEach((d) => b.set(d.ref, { nextScanAt: Date.now() }, { merge: true })); await b.commit(); } }
  catch (e) { console.warn("nextScanAt doldurulamadı:", e.message); }
}
if (db && AUTO_ENABLED && !process.env.NODE_TEST) {
  setTimeout(() => backfillNextScan().then(runDueScans), 90000).unref();
  setInterval(runDueScans, SEC.int(process.env.AUTO_SCAN_TICK_MIN, 15) * 60000).unref();
}
// Dışarıdan tetikleme (uyuyan Render için): CRON_SECRET tanımlı değilse uç nokta kapalıdır
app.all("/api/cron/scan", async (req, res) => {
  const secret = process.env.CRON_SECRET; if (!secret) return res.status(404).json({ success: false, error: "Bulunamadı" });
  const given = String(req.headers["x-cron-secret"] || req.query.key || ""); const a = Buffer.from(given), b = Buffer.from(secret);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).json({ success: false, error: "Yetkisiz" });
  res.json({ success: true, ...(await runDueScans()), queue: await JOBS.tick().catch(() => null) });
});
// Dış cron: hatırlatma e-postaları + alarm denetimi (+ ?backup=1 ile yedek). CRON_SECRET gerekir; tanımsızsa kapalı.
app.all("/api/cron/ops", async (req, res) => {
  const secret = process.env.CRON_SECRET; if (!secret) return res.status(404).json({ success: false, error: "Bulunamadı" });
  const given = String(req.headers["x-cron-secret"] || req.query.key || ""); const a = Buffer.from(given), b = Buffer.from(secret);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).json({ success: false, error: "Yetkisiz" });
  const out = { success: true, reminders: await OPS.runReminders().catch((e) => ({ error: e.message })), alerts: await OPS.checkAlerts().catch((e) => ({ error: e.message })) };
  if (req.query.backup === "1") out.backup = await OPS.backup("cron").catch((e) => ({ error: e.message })); res.json(out);
});
// Otomatik taramaların sonuçlarını arayüze taşır: since (ms) sonrasında güncellenen varlıkların son sonucu
app.get("/api/assets/latest", scanGuard, async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: "Veritabanı yapılandırılmamış" });
  const since = Number(req.query.since) || 0; res.set("Cache-Control", "no-store");
  try {
    const snap = await db.collection("assets").where("ownerId", "==", req.user.uid).limit(500).get(); const items = [];
    for (const doc of snap.docs) {
      const d = doc.data(), ms = d.scannedAt && d.scannedAt.toMillis ? d.scannedAt.toMillis() : 0; if (!ms || ms <= since) continue;
      const { ownerId, scannedAt, lastCheck, updatedAt, nextScanAt, scanExtra, expiryLevel, authorizationConfirmed, ...result } = d;
      items.push({ assetId: doc.id, scannedAtMs: ms, auto: !!d.auto, result: { ...result, lastCheck: new Date(ms).toISOString(), updatedAt: new Date(ms).toISOString() } });
    }
    res.json({ success: true, items: items.sort((x, y) => y.scannedAtMs - x.scannedAtMs).slice(0, 100) });
  } catch (e) { console.error("latest:", e.message); res.status(503).json({ success: false, error: "Sonuçlar alınamadı" }); }
});

// ===== Toplu tarama kuyruğu (kalıcı) =====
// İşler tek bir uzun HTTP isteğine bağlanmaz: POST /api/jobs işi kaydeder ve hemen döner; işleyici arka planda çalışır (jobs.js).
// Firestore varsa durum (scanJobs / scanJobItems) sunucu yeniden başlasa da korunur; yoksa bellek deposu kullanılır ve persistent:false bildirilir.
const nonRetriable = (code, message) => Object.assign(new Error(message), { code, retriable: false });
async function queueScanItem(item) {
  const uid = item.ownerId, assetType = item.type, handler = TYPE_HANDLERS[assetType], assetId = item.assetId;
  if (!handler) throw nonRetriable("UNSUPPORTED_TYPE", `Desteklenmeyen tür: ${assetType}`);
  if (ACTIVE_PROBE_TYPES.includes(assetType) && item.consent !== true) throw nonRetriable("CONSENT_REQUIRED", "Bu tarama türü için yetki beyanı gerekir.");
  const host = hostOf(item.targetUrl); if (!host) throw nonRetriable("INVALID_TARGET", "Geçerli bir hedef adres yok");
  try { await assertPublicHost(host); } catch (e) { throw nonRetriable("BLOCKED_TARGET", e.message); } // SSRF: özel/yerel/metadata adresleri
  { const pol = await policyCheck({ assetType, targetUrl: item.targetUrl, extra: item.extra || {} }); if (pol.blocked) { recordBlocked({ uid, ip: null, assetType, pol, where: "queue" }); throw nonRetriable("TARGET_BLOCKED", pol.message); } } // korumalı hedef (devlet/büyük platform/dacweb.tr)
  if (SEC.enforcePlans() && uid !== "dev-user" && !db && process.env.ALLOW_SCAN_WITHOUT_DB !== "true") throw nonRetriable("NO_DATABASE", "Sunucu yapılandırması eksik (veritabanı).");
  let ent = null;
  if (SEC.enforcePlans() && uid !== "dev-user" && db) {
    try { ent = await payments.getEntitlement(uid); } catch (e) { throw Object.assign(new Error(e.message || "Paket bilgisi alınamadı"), { code: "ENTITLEMENT_UNAVAILABLE", retriable: true }); }
    if (ent.plan === "expired") throw nonRetriable("PLAN_REQUIRED", "Deneme süresi bitti; paket gerekli.");
  }
  if (db) {
    let claim; try { claim = await SEC.claimAsset(db, assetId, uid); } catch (e) { throw Object.assign(new Error("Veritabanına ulaşılamadı"), { code: "DB_UNAVAILABLE", retriable: true }); }
    if (!claim.ok) throw nonRetriable("FORBIDDEN", claim.legacy ? "Bu kayıt sistem/eski veridir." : "Bu varlık size ait değil.");
    if (ent) { const q = await SEC.checkAssetQuota(db, uid, ent.plan, claim.isNew); if (!q.ok) { if (claim.isNew) await db.collection("assets").doc(assetId).delete().catch(() => {}); throw nonRetriable("QUOTA_EXCEEDED", `Paket varlık limiti doldu (${q.limit}).`); } }
  }
  const out = await executeScan({ uid, assetId, assetType, handler, targetUrl: item.targetUrl, extra: item.extra || {}, name: item.name, ip: null });
  if (out.scanStatus === "BLOCKED") throw nonRetriable("TARGET_BLOCKED", (out.blocked && out.blocked.message) || BLOCK.MESSAGE_GENERIC);
  if (out.scanStatus === "FAILED" || out.scanStatus === "TIMEOUT") throw Object.assign(new Error(out.scanStatus === "TIMEOUT" ? "Tarama zaman aşımına uğradı" : "Tarama tamamlanamadı"), { code: out.scanStatus === "TIMEOUT" ? "TIMEOUT" : "SCAN_FAILED", retriable: true });
  return { scanStatus: out.scanStatus, summary: scanSummary(out, assetType) };
}
const JOBS = JOBLIB.createJobs({
  store: db ? JOBLIB.firestoreStore(db) : JOBLIB.memoryStore(), scanItem: queueScanItem, metrics: METRICS,
  config: { concurrency: SEC.int(process.env.JOB_CONCURRENCY, 3), perUser: SEC.int(process.env.JOB_PER_USER_CONCURRENCY, 2), timeoutMs: SCAN_TIMEOUT_MS, maxAttempts: SEC.int(process.env.JOB_MAX_ATTEMPTS, 3), maxItemsPerJob: SEC.int(process.env.JOB_MAX_ITEMS, 1000), maxActiveJobsPerUser: SEC.int(process.env.JOB_MAX_ACTIVE_PER_USER, 5), maxQueuedPerUser: SEC.int(process.env.JOB_MAX_QUEUED_PER_USER, 3000), backoffBaseMs: SEC.int(process.env.JOB_BACKOFF_MS, 30000) }
});
const HOST_TYPES = ["DOMAIN", "EMAIL", "SSL_CERTIFICATE", "HOSTING", "SERVER"];
const URL_TYPES = ["WEBSITE", "WEB", "SEO", "SECURITY", "PERFORMANCE", "UPTIME", "API", "ANALYTICS"];
function cleanBulkItem(x, authorized) {
  if (!x || typeof x !== "object" || Array.isArray(x)) return { error: "Geçersiz kayıt" };
  const assetId = x.assetId, type = String(x.type || "").toUpperCase();
  if (typeof assetId !== "string" || !/^[A-Za-z0-9_-]{1,200}$/.test(assetId)) return { error: "assetId geçersiz" };
  if (![...HOST_TYPES, ...URL_TYPES].includes(type)) return { error: `Toplu taramada desteklenmeyen tür: ${type}` };
  if (ACTIVE_PROBE_TYPES.includes(type) && !authorized) return { error: "Bu tür için yetki beyanı (consent) gerekir" };
  if (typeof x.target !== "string") return { error: "target metin olmalı" };
  let targetUrl;
  if (URL_TYPES.includes(type)) { const r = VALID.normalizeUrl(x.target); if (!r.ok) return { error: r.error }; targetUrl = r.url; }
  else if (type === "SERVER" && net.isIP(x.target.trim())) targetUrl = x.target.trim();
  else { const r = VALID.normalizeDomain(x.target); if (!r.ok) return { error: r.error }; targetUrl = r.domain; }
  { const pol = BLOCK.checkScan({ assetType: type, targetUrl, extra: {} }); if (pol.blocked) return { error: pol.message, blocked: pol }; } // korumalı hedef
  const extra = {}; if (type === "ANALYTICS" && typeof x.extra?.measurementId === "string" && /^G-[A-Z0-9]{4,20}$/i.test(x.extra.measurementId)) extra.measurementId = x.extra.measurementId;
  const port = x.extra && Number.isInteger(x.extra.port) ? x.extra.port : null; if (port && port > 0 && port < 65536 && ["SSL_CERTIFICATE", "SERVER"].includes(type)) extra.port = port;
  return { item: { assetId, type, targetUrl, name: typeof x.name === "string" && x.name.trim() ? x.name.trim().slice(0, 200) : (URL_TYPES.includes(type) ? hostOf(targetUrl) : targetUrl), extra, consent: authorized === true } };
}
const jobIpLimit = SEC.makeLimiter(SEC.int(process.env.JOB_IP_RATE_LIMIT, 1200), 5 * 60 * 1000);
const jobReadLimit = SEC.makeLimiter(SEC.int(process.env.JOB_READ_RATE_LIMIT, 600), 5 * 60 * 1000);
const jobWriteLimit = SEC.makeLimiter(SEC.int(process.env.JOB_WRITE_RATE_LIMIT, 20), 10 * 60 * 1000);
const jobRead = [(req, res, next) => (jobIpLimit(req.ip) ? next() : tooMany(res)), scanGuard[1], (req, res, next) => (jobReadLimit(req.user.uid) ? next() : tooMany(res))];
const jobWrite = [...jobRead, (req, res, next) => (jobWriteLimit(req.user.uid) ? next() : tooMany(res, "Çok fazla toplu işlem. Biraz bekleyin."))];
const jobWrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { res.locals.errDetail = (e && e.code ? e.code + ": " : "") + String(e && e.message || "").slice(0, 300); const code = e.status || 500; if (code >= 500) { console.error("jobs:", e.message); METRICS.recordError({ source: "jobs", status: code, path: req.path, message: e.message }); } res.status(code).json({ success: false, ...(e.code ? { code: e.code } : {}), error: code >= 500 ? "Sunucu hatası" : e.message }); } };
const pubJob = (j) => ({ id: j.id, label: j.label, status: j.status, total: j.total, counts: j.counts, createdAt: j.createdAt, startedAt: j.startedAt, finishedAt: j.finishedAt, cancelRequested: !!j.cancelRequested, persistent: !!j.persistent });
const jobId = (req) => { const id = String(req.params.id || ""); if (!/^job_[A-Za-z0-9_-]{6,40}$/.test(id)) throw Object.assign(new Error("Geçersiz iş kimliği"), { status: 400 }); return id; };

app.post("/api/jobs", jobWrite, jobWrap(async (req, res) => {
  const body = req.body || {}; if (!Array.isArray(body.items)) return res.status(400).json({ success: false, error: "items dizisi gerekli" });
  const authorized = body.consent === true, seen = new Set(), items = [], rejected = [], blockedHits = [], blockedIdx = [];
  body.items.forEach((x, i) => { const r = cleanBulkItem(x, authorized); if (r.error) { if (r.blocked) { rejected.push({ index: i, code: "TARGET_BLOCKED", error: r.error }); blockedHits.push(r.blocked); blockedIdx.push(i); return; } return rejected.push({ index: i, error: r.error }); } if (seen.has(r.item.assetId)) return rejected.push({ index: i, error: "Aynı assetId iki kez gönderildi" }); seen.add(r.item.assetId); items.push(r.item); });
  if (blockedHits.length) { for (const pol of blockedHits.slice(0, 5)) recordBlocked({ uid: req.user.uid, ip: req.ip, assetType: "BULK", pol, where: "jobs" }); if (!blockedLimit(req.user.uid)) return res.status(429).json({ success: false, code: "TOO_MANY_BLOCKED", blockedIndexes: blockedIdx, error: "Çok fazla yasaklı hedef denemesi yaptınız. Bir süre sonra tekrar deneyin." }); }
  if (!items.length) return res.status(blockedHits.length ? 403 : 400).json({ success: false, ...(blockedHits.length ? { code: "TARGET_BLOCKED", blockedIndexes: blockedIdx } : {}), error: blockedHits.length ? "Gönderilen hedeflerin tümü korumalı (devlet/kamu, büyük platform veya DAC) alan adı olduğundan taranamaz." : "Geçerli hedef yok", rejected: rejected.slice(0, 50) });
  if (SEC.enforcePlans() && req.user.uid !== "dev-user" && db) { const e = await payments.getEntitlement(req.user.uid).catch(() => null); if (e && e.plan === "expired") return res.status(402).json({ success: false, code: "PLAN_REQUIRED", error: "Deneme süreniz bitti. Devam etmek için bir paket seçin." }); }
  const job = await JOBS.createJob({ ownerId: req.user.uid, items, label: typeof body.label === "string" ? body.label : "Toplu tarama", source: body.source === "domains-overview" ? "domains-overview" : "bulk" });
  res.status(201).json({ success: true, job: pubJob(job), accepted: items.length, rejected: rejected.slice(0, 100), rejectedCount: rejected.length, blockedIndexes: blockedIdx });
}));
app.get("/api/jobs", jobRead, jobWrap(async (req, res) => { res.set("Cache-Control", "no-store"); res.json({ success: true, persistent: JOBS._store.persistent, jobs: (await JOBS.listJobs(req.user.uid, Math.min(100, +req.query.limit || 30))).map(pubJob) }); }));
app.get("/api/jobs/:id", jobRead, jobWrap(async (req, res) => { res.set("Cache-Control", "no-store"); res.json({ success: true, job: pubJob(await JOBS.getJob(jobId(req), req.user.uid)) }); }));
app.get("/api/jobs/:id/items", jobRead, jobWrap(async (req, res) => { res.set("Cache-Control", "no-store"); res.json({ success: true, ...(await JOBS.queryItems(jobId(req), req.user.uid, req.query)) }); }));
app.get("/api/jobs/:id/export.csv", jobRead, jobWrap(async (req, res) => {
  const all = await JOBS.queryItems(jobId(req), req.user.uid, { ...req.query, page: 1, pageSize: 200 }); let rows = all.items;
  for (let p = 2; rows.length < all.total && p <= 20; p++) rows = rows.concat((await JOBS.queryItems(jobId(req), req.user.uid, { ...req.query, page: p, pageSize: 200 })).items);
  res.set({ "Cache-Control": "no-store", "Content-Disposition": 'attachment; filename="toplu-tarama.csv"' }); res.type("text/csv").send(JOBLIB.itemsToCsv(rows));
}));
app.post("/api/jobs/:id/cancel", jobWrite, jobWrap(async (req, res) => { const r = await JOBS.cancelJob(jobId(req), req.user.uid); res.json({ success: true, canceled: r.canceled, job: pubJob(r.job) }); }));
app.post("/api/jobs/:id/retry", jobWrite, jobWrap(async (req, res) => { const ids = Array.isArray(req.body && req.body.itemIds) ? req.body.itemIds.filter((x) => typeof x === "string").slice(0, 1000) : null; res.json({ success: true, ...(await JOBS.retryItems(jobId(req), req.user.uid, { itemIds: ids, includeCanceled: req.body && req.body.includeCanceled === true })) }); }));
app.post("/api/jobs/:id/items/cancel", jobWrite, jobWrap(async (req, res) => { const ids = Array.isArray(req.body && req.body.itemIds) ? req.body.itemIds.filter((x) => typeof x === "string").slice(0, 1000) : []; res.json({ success: true, ...(await JOBS.cancelItems(jobId(req), req.user.uid, ids)) }); }));

// ===== Raporlar ve bileşik skor (AI'siz) =====
app.get("/api/reports/period", scanGuard, jobWrap(async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: "Veritabanı yapılandırılmamış" });
  const type = req.query.type === "yearly" ? "yearly" : "monthly", year = parseInt(req.query.year, 10) || new Date().getUTCFullYear(), month = Math.min(12, Math.max(1, parseInt(req.query.month, 10) || new Date().getUTCMonth() + 1));
  if (year < 2020 || year > 2100) return res.status(400).json({ success: false, error: "Geçersiz yıl" });
  const snap = await db.collection("assetChecks").where("ownerId", "==", req.user.uid).limit(2000).get();
  const checks = snap.docs.map((d) => { const x = d.data(); return { assetId: x.assetId, type: x.type, healthScore: x.healthScore, findings: x.findings, checkedAt: x.checkedAt && x.checkedAt.toMillis ? x.checkedAt.toMillis() : null }; });
  res.json({ success: true, report: AI.buildPeriodReport(checks, { periodType: type, year, month }) });
}));
app.get("/api/scores/hosts", scanGuard, jobWrap(async (req, res) => {
  if (!db) return res.status(503).json({ success: false, error: "Veritabanı yapılandırılmamış" });
  const snap = await db.collection("assets").where("ownerId", "==", req.user.uid).limit(1000).get(); const by = new Map();
  for (const d of snap.docs) { const a = d.data(); const h = hostOf(a.targetUrl || a.target || ""); if (!h) continue; if (!by.has(h)) by.set(h, []); by.get(h).push(a); }
  res.json({ success: true, weights: SCORING.COMPOSITE_WEIGHTS, criticalCap: SCORING.CRITICAL_CAP, hosts: [...by].map(([host, list]) => ({ host, ...SCORING.compositeForHost(list), assets: list.length })).sort((a, b) => (a.score ?? 101) - (b.score ?? 101)) });
}));

// ===== Yönetici paneli (rol sunucuda doğrulanır: admin.js) =====
async function getHealthDetail() {
  const p = payments.status(), mem = process.memoryUsage(); let fsState = { configured: !!db, reachable: null, latencyMs: null };
  if (db) { const t0 = Date.now(); try { await withTimeout(db.collection("adminRoles").limit(1).get(), 4000, "Firestore"); fsState = { configured: true, reachable: true, latencyMs: Date.now() - t0 }; } catch (e) { fsState = { configured: true, reachable: false, latencyMs: Date.now() - t0, error: String(e.message).slice(0, 120) }; } }
  return { version: SCANNER_VERSION, node: process.version, environment: SEC.isProd() ? "production" : "development", uptimeSeconds: Math.round(process.uptime()), memoryMB: { rss: Math.round(mem.rss / 1048576), heapUsed: Math.round(mem.heapUsed / 1048576) },
    firebase: { adminReady: !!firebaseStatus.ok, mode: firebaseStatus.mode || null }, firestore: fsState, auth: { verifiesTokens: !!p.auth },
    payments: { paytr: p.paytr, usd: p.usd, freeMode: p.free }, autoScan: { enabled: AUTO_ENABLED && !!db, running: autoRunning, cronEndpoint: !!process.env.CRON_SECRET },
    rdap: { bootstrapLoaded: rdapBoot.ok === true }, scoring: { weights: SCORING.COMPOSITE_WEIGHTS, criticalCap: SCORING.CRITICAL_CAP }, ai: AI.status(), devBypassActive: SEC.devBypass() };
}
const ADMIN = SRV("admin")({ app, db, admin, verifyUser: payments.verifyUser, SEC, metrics: METRICS, jobs: JOBS, getHealth: getHealthDetail, platform: async () => ({ ai: AI.describe(), billing: BILLING.describe(PLANS), scoring: { weights: SCORING.COMPOSITE_WEIGHTS, criticalCap: SCORING.CRITICAL_CAP, legacyWebWeights: SCORING.WEB_LEGACY_WEIGHTS } }), getEntitlement: db ? payments.getEntitlement : null, commerce: COMMERCE, payments, userState: USER_STATE, ops: OPS, mailer: MAILER });

app.get("/health", (req, res) => { const p = payments.status(); res.set("Cache-Control", "no-store"); res.json({ ok: true, version: SCANNER_VERSION, payments: { paytr: p.paytr, usd: p.usd, free: p.free }, timestamp: new Date().toISOString() }); });
// JSON ayrıştırma vb. hatalar için düzgün yanıt
// Tüm rotalardan SONRA: bilinmeyen adresler için JSON 404 (Python sürümüyle aynı biçim)
app.use((q, r) => r.status(404).json({ success: false, error: "Bulunamadı" }));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const code = err.status && err.status >= 400 && err.status < 600 ? err.status : 400;
  if (code >= 500) { console.error("Sunucu hatası:", err && err.stack || err); METRICS.recordError({ source: "express", status: code, path: req.path, message: err && err.message }); }
  res.status(code).json({ success: false, error: err.type === "entity.parse.failed" ? "Geçersiz JSON" : err.type === "entity.too.large" ? "İstek çok büyük" : code >= 500 ? "Sunucu hatası" : (err.message || "İstek hatası") });
});
process.on("unhandledRejection", (e) => { console.error("unhandledRejection:", e && e.stack || e); METRICS.recordError({ source: "unhandledRejection", message: e && e.message || e }); });
// Düşman hedeflerden gelen sahipsiz soket hataları süreci düşürmesin; ama kısa sürede tekrarlanıyorsa süreç bozuktur -> çık, Render yeniden başlatsın.
const crashTimes = [];
// Bellek bekçisi: Render ücretsiz plan ~512MB. Aşılırsa süreç sessizce OOM ile öldürülür (log kalmaz).
// Burada kullanım loglanır; sert sınıra yaklaşınca temiz kapanıp yeniden başlar.
const MB = 1048576;
function memLog() { const m = process.memoryUsage(); const rss = Math.round(m.rss / MB); console.log(`[mem] rss=${rss}MB heap=${Math.round(m.heapUsed / MB)}/${Math.round(m.heapTotal / MB)}MB ext=${Math.round(m.external / MB)}MB`); return m.rss; }
if (!process.env.NODE_TEST) {
  setInterval(() => {
    const rss = memLog() ;
    if (rss > MEM_HARD_LIMIT) { console.error(`[mem] rss ${Math.round(rss / MB)}MB sınırı aştı: temiz yeniden başlatma`); JOBS.stop().catch(() => {}); setTimeout(() => process.exit(1), 2000).unref(); }
  }, 60000).unref();
}
process.on("uncaughtException", (e) => {
  console.error("uncaughtException:", e && e.stack || e);
  const now = Date.now(); crashTimes.push(now); while (crashTimes.length && now - crashTimes[0] > 60000) crashTimes.shift();
  if (crashTimes.length >= 5) { console.error("60 sn içinde 5 yakalanmamış hata: süreç yeniden başlatılıyor"); process.exit(1); }
});
if (require.main === module) {
  if (firebaseStatus.ok) console.log("Firebase hazır: proje " + firebaseStatus.projectId + " (" + firebaseStatus.mode + ")");
  if (SEC.isProd() && !db) console.warn("UYARI: Üretim modunda Firebase yapılandırılmamış; kimlik doğrulama gerektiren uç noktalar 503 döndürür.");
  if (SEC.devBypass()) console.warn("UYARI: DEV_AUTH_BYPASS aktif (yalnızca geliştirme). Üretimde ASLA kullanmayın.");
  if (!process.env.NODE_TEST) JOBS.start();
  const server = app.listen(PORT, () => { console.log(`Scanner ${SCANNER_VERSION} DEEP ${PORT} portunda (${SEC.isProd() ? "üretim" : "geliştirme"})`); memLog(); });
  server.keepAliveTimeout = 65000; server.headersTimeout = 66000; // Render proxy 502 önlemi
  process.on("SIGTERM", () => { console.log("SIGTERM: kapanıyor (Render: boşta uyku veya yeni deploy)"); memLog(); JOBS.stop().catch(() => {}); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 10000).unref(); });
}
module.exports = app;
module.exports._internals = { BLOCK, policyCheck, JOBS, METRICS, executeScan, queueScanItem, scanSummary, rdapDate, toDateOrNull, cleanBulkItem, isPrivateIp, assertPublicHost, scanDomain, scanSslCertificate, scanWebsite, scanSeo, scanSecurity, scanPerformance, scanUptime, scanApi, scanAnalytics, scanHosting, scanServer, scanBrand, scanSaasSubscription, scanMobileApp, scanRepository, analyzeSpf, analyzeHtml, detectTech, detectPageState, derSignatureAlgorithm, parseDomain, registrableDomain, httpProbe, forFirestore , blockedHost, request, decodeEntities, tokenizeHtml, extractTitle, parseWhois, parseLooseDate, whoisQuery, expiryProfile, cymruAsn, getTlsDetails, followRelatedRdap, fetchRegistration };
