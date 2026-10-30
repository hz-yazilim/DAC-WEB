/* Digital Asset Center - Korumalı hedef listesi (yasaklı alan adları)
 *
 * AMAÇ: Kullanıcıların; devlet/kamu siteleri, büyük platformlar, kritik altyapı ve DAC'ın kendi alan adlarını
 * HİÇBİR tarama türüyle (WEB, SEO, SECURITY, SERVER, DOMAIN, SSL, HOSTING, UPTIME, API, ANALYTICS, BRAND, EMAIL...) taramasını engellemek.
 * Gerekçe: başkasının sistemine izinsiz aktif sondalama hukuki risk (TCK 243-245), IP kara listeye alınma ve DAC'ın kendi sitesine yük/saldırı riski.
 *
 * KATMANLAR (hepsi sunucuda; istemci kontrolü yalnızca kolaylıktır):
 *   1) /api/scan girişi  2) /api/jobs (toplu) girişi  3) kuyruk işleyici  4) otomatik tarama  5) executeScan son kapısı
 *   6) yönlendirme takibi (httpProbe: hedef site → korumalı siteye yönlendirirse zincir durur)
 *   7) CNAME zinciri (benim-sitem.com → www.google.com gibi takma adlar)
 * Saf modül: ağ erişimi yoktur (CNAME denetimi için çağıran taraf çözücü verir). */
"use strict";
const { domainToASCII } = require("url");
const net = require("net");

/* ---------- Ortam değişkenleriyle genişletme ----------
 *  OWN_DOMAINS     : DAC'ın kendi alan adları (virgülle). Varsayılan: dacweb.tr + SITE_URL alan adı + Firebase auth alan adı.
 *  BLOCKED_DOMAINS : ek yasaklı alan adları (virgülle; alt alan adları dahil)
 *  BLOCKED_ALLOW   : YALNIZCA test/acil durum için istisna (virgülle, tam eşleşme). Resmî listedeki kamu/dacweb.tr istisnası verilemez. */
const list = (v) => String(v || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

// Sunucunun tarama sırasında kullandığı ayrıştırıcıyla (WHATWG URL) AYNI sonucu üretir: ayrıştırma farkıyla aşılamaz.
function norm(host) {
  if (host == null) return "";
  let s = String(host).trim();
  if (!s || s.length > 2048) return "";
  s = s.replace(/[\u200b-\u200d\u2060\ufeff]/g, "");              // sıfır genişlikli karakterler
  let h = "";
  try { h = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "https://" + s).hostname; } catch { h = ""; }
  if (!h) { // yedek: elle ayrıştırma
    h = s.toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^[^/?#\\]*@/, "").split(/[/?#\\]/)[0].replace(/:\d{1,5}$/, "");
  }
  h = h.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  try { h = domainToASCII(h) || h; } catch { /* olduğu gibi */ }
  return h.toLowerCase();
}

/* ---------- 1) Genel/kamu sektörü son ekleri ---------- */
// Türkiye kamu uzantıları: devlet, askerî, belediye, okul, polis, TSK, üniversite
const TR_PUBLIC_SUFFIXES = ["gov.tr", "mil.tr", "bel.tr", "k12.tr", "pol.tr", "tsk.tr", "edu.tr"];
// Dünya genelinde devlet/askerî/uluslararası: .gov .mil .int .edu + ikinci seviye gov/gob/gouv/govt/mil
const PUBLIC_TLDS = new Set(["gov", "mil", "int", "edu"]);
const PUBLIC_SLD = /(^|\.)(gov|gob|gouv|govt|gv|go|mil|admin|overheid|bund|regierung|gouvernement)\.[a-z]{2}$/;

/* ---------- 2) Büyük platformlar / kritik altyapı (alt alan adları dahil) ---------- */
const PROTECTED_DOMAINS = [
  // Google ve hizmetleri
  "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com", "googletagmanager.com", "google-analytics.com", "googlesyndication.com",
  "doubleclick.net", "googleadservices.com", "ggpht.com", "gmail.com", "youtube.com", "youtu.be", "ytimg.com", "withgoogle.com", "goo.gl", "blogger.com", "firebase.com", "gvt1.com", "gvt2.com", "chromium.org", "android.com", "golang.org", "dart.dev", "flutter.dev", "web.dev", "g.co",
  // Yandex
  "yandex.com", "yandex.ru", "yandex.com.tr", "yandex.net", "yandex.by", "yandex.kz", "yandex.ua", "ya.ru", "yastatic.net", "yandexcloud.net", "yandex.cloud", "dzen.ru", "kinopoisk.ru",
  // Barındırma/DevOps platformlarının KENDİ siteleri. Müşteri alt alan adı barındıran uzantılar (*.onrender.com, *.github.io, *.myshopify.com, *.azurewebsites.net, *.amazonaws.com, *.workers.dev vb.)
  // bilerek listede YOKTUR: kullanıcılar kendi sitelerini tarayabilmeli.
  "render.com", "github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "bitbucket.org", "atlassian.com", "heroku.com", "vercel.com", "netlify.com",
  "cloudflare.com", "cloudflare-dns.com", "fastly.com", "akamai.com", "digitalocean.com",
  "aws.amazon.com", "azure.com", "microsoftonline.com", "oracle.com", "ibm.com", "alibabacloud.com", "aliyun.com",
  "hetzner.com", "ovh.com", "ovhcloud.com", "linode.com", "vultr.com", "fly.io", "supabase.com", "mongodb.com", "docker.com", "docker.io", "npmjs.com", "npmjs.org", "pypi.org",
  "godaddy.com", "namecheap.com", "name.com", "wix.com", "shopify.com", "stripe.com", "paypal.com", "iyzico.com", "paytr.com", "iyzipay.com",
  "letsencrypt.org", "digicert.com", "sectigo.com", "globalsign.com", "verisign.com", "icann.org", "iana.org", "ripe.net", "arin.net", "apnic.net", "lacnic.net", "afrinic.net", "crt.sh", "rdap.org",
  // Büyük küresel markalar / sosyal ağlar / teknoloji
  "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "bing.com", "msn.com", "skype.com", "linkedin.com", "xbox.com",
  "apple.com", "icloud.com", "amazon.com", "amazon.com.tr", "amazon.de", "amazon.co.uk", "twitch.tv", "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net", "meta.com", "messenger.com", "threads.net",
  "twitter.com", "x.com", "t.co", "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com", "telegram.org", "t.me", "discord.com", "discord.gg", "zoom.us", "slack.com", "notion.so", "dropbox.com", "box.com",
  "wikipedia.org", "wikimedia.org", "mozilla.org", "firefox.com", "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "netflix.com", "spotify.com", "adobe.com", "salesforce.com", "tesla.com",
  "samsung.com", "huawei.com", "nvidia.com", "intel.com", "amd.com", "cisco.com", "baidu.com", "qq.com", "taobao.com", "alibaba.com", "aliexpress.com", "tencent.com", "vk.com", "ok.ru", "mail.ru",
  "ebay.com", "booking.com", "airbnb.com", "uber.com", "binance.com", "coinbase.com", "visa.com", "mastercard.com", "mastercard.com.tr", "troy.com.tr",
  // Türkiye: kritik altyapı, bankalar, büyük e-ticaret/medya/telekom (kamu uzantıları 1. kuralda ayrıca engelli)
  "turkiye.gov.tr", "e-devlet.gov.tr", "turk.net", "turktelekom.com.tr", "turkcell.com.tr", "vodafone.com.tr", "superonline.net", "ttnet.com.tr", "turksat.com.tr", "ptt.gov.tr", "btk.gov.tr",
  "isbank.com.tr", "ziraatbank.com.tr", "halkbank.com.tr", "vakifbank.com.tr", "garantibbva.com.tr", "bbva.com.tr", "akbank.com", "yapikredi.com.tr", "qnbfinansbank.com", "qnb.com.tr", "denizbank.com", "teb.com.tr",
  "ingbank.com.tr", "sekerbank.com.tr", "kuveytturk.com.tr", "albaraka.com.tr", "ziraatkatilim.com.tr", "vakifkatilim.com.tr", "emlakkatilim.com.tr", "odeabank.com.tr", "fibabanka.com.tr", "enpara.com", "papara.com", "tosla.com",
  "borsaistanbul.com", "takasbank.com.tr", "merkezbankasi.gov.tr", "tcmb.gov.tr", "spk.gov.tr", "bddk.org.tr", "tbb.org.tr", "kap.org.tr", "mkk.com.tr", "kkb.com.tr", "findeks.com",
  "trendyol.com", "hepsiburada.com", "n11.com", "sahibinden.com", "gittigidiyor.com", "ciceksepeti.com", "yemeksepeti.com", "getir.com", "migros.com.tr", "bim.com.tr", "a101.com.tr", "sok.com.tr", "carrefoursa.com",
  "teknosa.com", "mediamarkt.com.tr", "vatanbilgisayar.com", "koctas.com.tr", "lcwaikiki.com", "defacto.com.tr", "boyner.com.tr", "turkishairlines.com", "thy.com", "pegasus.com.tr", "pegasusair.com", "tcddtasimacilik.gov.tr",
  "hurriyet.com.tr", "milliyet.com.tr", "sabah.com.tr", "sozcu.com.tr", "cumhuriyet.com.tr", "haberturk.com", "ntv.com.tr", "cnnturk.com", "trthaber.com", "trt.net.tr", "aa.com.tr", "iha.com.tr", "dha.com.tr", "bbc.com", "cnn.com", "nytimes.com", "reuters.com",
  "turkiyesigorta.com.tr", "anadolusigorta.com.tr", "allianz.com.tr", "axasigorta.com.tr", "mapfre.com.tr", "sbm.org.tr", "tsb.org.tr", "emniyet.gov.tr", "mebbis.meb.gov.tr", "hes.gov.tr", "turkpatent.gov.tr", "tubitak.gov.tr", "nic.tr",
  // DAC'ın kendi alan adı (OWN_DOMAINS ile ek olarak genişler)
  "dacweb.tr", "dacweb.com.tr", "dacweb.com"
];
// Marka etiketi kuralı: yalnız benzersiz markalar (sıradan kelime olan apple/amazon gibi etiketler listede açıkça yazılı alan adlarıyla engellenir). "google" + herhangi uzantı (google.de, google.com.tr); "notgoogle.com" engellenmez.
const BRAND_LABELS = ["google", "youtube", "yandex", "facebook", "instagram", "whatsapp", "microsoft", "dacweb", "paypal"];
const BRAND_RE = BRAND_LABELS.map((b) => ({ b, re: new RegExp(`(^|\\.)${b.replace(/[-.]/g, "\\$&")}\\.(?:[a-z]{2,24}|(?:com|co|net|org|gen|web|biz|info|edu|gov|ac|nom)\\.[a-z]{2})$`) }));

/* DAC'ın kendi alan adları: ortam + SITE_URL + Firebase auth alan adı + sabit liste */
function ownDomains(env = process.env) {
  const set = new Set(["dacweb.tr", "dacweb.com.tr", "dacweb.com", "dac-web-tfqf.onrender.com", "dac-web-yefr.onrender.com", "hz-yazilim.github.io"]);
  for (const d of list(env.OWN_DOMAINS)) { const n = norm(d); if (n) set.add(n); }
  for (const u of [env.SITE_URL, env.PUBLIC_API_URL, env.FIREBASE_AUTH_DOMAIN, env.RENDER_EXTERNAL_URL, env.RENDER_EXTERNAL_HOSTNAME]) { const n = norm(u); if (n && !net.isIP(n)) set.add(n); }
  return set;
}
function extraBlocked(env = process.env) { return list(env.BLOCKED_DOMAINS).map(norm).filter(Boolean); }
function allowOverride(env = process.env) { return new Set(list(env.BLOCKED_ALLOW).map(norm).filter(Boolean)); }

const isSubOf = (h, d) => h === d || h.endsWith("." + d);

/* Çekirdek karar: host korumalı mı? → { blocked, category, rule } */
function classifyHost(host, env = process.env) {
  const h = norm(host).replace(/^www\./, "");
  if (!h) return { blocked: false };
  if (net.isIP(h)) return { blocked: false }; // IP engeli SSRF katmanında (blockedHost); kamu IP'si alan adından ayırt edilemez
  const labels = h.split(".");
  const tld = labels[labels.length - 1];
  // DAC'ın kendi alan adı: istisna verilemez
  for (const d of ownDomains(env)) if (isSubOf(h, d)) return { blocked: true, category: "own", rule: d };
  for (const brand of BRAND_RE) if (brand.re.test(h) && (brand.b === "dacweb")) return { blocked: true, category: "own", rule: brand.b + ".*" };
  // Kamu: Türkiye
  for (const s of TR_PUBLIC_SUFFIXES) if (isSubOf(h, s)) return { blocked: true, category: "government", rule: "." + s };
  // Kamu: dünya geneli
  if (PUBLIC_TLDS.has(tld)) return { blocked: true, category: "government", rule: "." + tld };
  if (PUBLIC_SLD.test(h)) return { blocked: true, category: "government", rule: "gov-sld" };
  // İstisna (yalnızca kamu/dacweb dışı) — tam eşleşme
  if (allowOverride(env).has(h)) return { blocked: false };
  for (const d of PROTECTED_DOMAINS) if (isSubOf(h, d)) return { blocked: true, category: "protected", rule: d };
  for (const d of extraBlocked(env)) if (isSubOf(h, d)) return { blocked: true, category: "protected", rule: d };
  for (const brand of BRAND_RE) if (brand.re.test(h)) return { blocked: true, category: "protected", rule: brand.b + ".*" };
  return { blocked: false };
}

const MESSAGES = {
  government: "Devlet/kamu kurumu alan adları taranamaz.",
  own: "Bu alan adı DAC'a aittir ve taranamaz.",
  protected: "Bu alan adı büyük bir platforma/kritik altyapıya aittir ve taranamaz."
};
const MESSAGE_GENERIC = "Bu hedef güvenlik politikası gereği taranamaz.";

/* Bir adresten (URL / alan adı / IP / "host:port") korumalı olup olmadığını döndürür. Kullanıcıya hangi kuralın eşleştiğini AÇIKLAMAYIZ (kara liste keşfini zorlaştırır). */
function checkTarget(input, env = process.env) {
  const r = classifyHost(input, env);
  if (!r.blocked) return { blocked: false };
  return { blocked: true, code: "TARGET_BLOCKED", category: r.category, rule: r.rule, message: MESSAGES[r.category] || MESSAGE_GENERIC };
}

/* Türe göre denetlenecek adaylar: hedef adres + extra.domain/target/url/host/website.
 *  - SAAS_SUBSCRIPTION: ağ erişimi yok (yalnızca yenileme tarihi takibi) → denetlenmez.
 *  - MOBILE_APP / REPOSITORY: hedef bir platform bağlantısıdır (play.google.com, apps.apple.com, github.com/sahip/depo); yalnızca ilgili genel API sorgulanır,
 *    hedef siteye bağlanılmaz. Bu yüzden platformun kendisi bu türlerde istisnadır; paket adı (com.firma.uygulama) ve "sahip/depo" biçimleri alan adı değildir, atlanır.
 *    Platformun ana sayfası veya başka bir korumalı alan adı yine engellenir. BLOCK_STRICT_PLATFORMS=true ile istisna kapatılır. */
const PLATFORM_EXEMPT = { REPOSITORY: ["github.com"], MOBILE_APP: ["play.google.com", "apps.apple.com", "itunes.apple.com"] };
function candidatesOf({ targetUrl, extra }) {
  const out = [];
  const push = (v) => { if (typeof v === "string" && v.trim()) out.push(v.trim()); };
  push(targetUrl);
  if (extra && typeof extra === "object") for (const k of ["domain", "target", "url", "host", "website"]) push(extra[k]);
  return [...new Set(out)];
}
function checkScan({ assetType, targetUrl, extra } = {}, env = process.env) {
  const type = String(assetType || "").toUpperCase();
  if (type === "SAAS_SUBSCRIPTION") return { blocked: false };
  const strict = String(env.BLOCK_STRICT_PLATFORMS || "") === "true";
  for (const c of candidatesOf({ targetUrl, extra })) {
    if ((type === "MOBILE_APP" || type === "REPOSITORY") && !/^[a-z][a-z0-9+.-]*:\/\//i.test(c) && !/^(?:www\.)?github\.com[/:]/i.test(c) && !/^[\w.-]+\.[a-z]{2,24}(?:\/|$)/i.test(c)) continue; // paket adı / "sahip/depo"
    if (type === "MOBILE_APP" && !/^[a-z][a-z0-9+.-]*:\/\//i.test(c)) continue;                                                              // paket adı alan adı değildir
    const h = norm(c).replace(/^www\./, "");
    if (!h) continue;
    if (!strict && PLATFORM_EXEMPT[type] && PLATFORM_EXEMPT[type].some((d) => isSubOf(h, d))) continue;
    if (!/\./.test(h) && !net.isIP(h)) continue;
    const r = checkTarget(c, env);
    if (r.blocked) return { ...r, matched: h };
  }
  return { blocked: false };
}

/* CNAME zinciri: çağıran, çözücüsüyle zinciri verir (örn. ["www.dacweb.tr"]).
 * YALNIZCA kamu ve DAC'a ait alan adlarını engeller: müşteri sitelerinin Cloudflare/Fastly/CloudFront/GitHub Pages/Render gibi altyapıya CNAME vermesi sıradandır. */
function checkChain(names, env = process.env) {
  for (const n of names || []) { const r = checkTarget(n, env); if (r.blocked && (r.category === "government" || r.category === "own")) return { ...r, viaCname: norm(n) }; }
  return { blocked: false };
}
async function resolveCnameChain(resolver, host, depth = 6) {
  const chain = []; let cur = norm(host);
  for (let i = 0; i < depth && cur && !net.isIP(cur); i++) {
    let next = null;
    try { const r = await resolver(cur); next = Array.isArray(r) && r.length ? norm(r[0]) : null; } catch { next = null; }
    if (!next || chain.includes(next)) break;
    chain.push(next); cur = next;
  }
  return chain;
}

module.exports = { norm, classifyHost, checkTarget, checkScan, checkChain, resolveCnameChain, ownDomains, MESSAGES, MESSAGE_GENERIC, PROTECTED_DOMAINS, TR_PUBLIC_SUFFIXES };
