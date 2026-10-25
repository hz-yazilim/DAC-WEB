/* Digital Asset Center - Girdi doğrulama (sunucu tarafı; istemci aynı kuralları yalnızca kullanım kolaylığı için taklit eder)
 * Saf fonksiyonlar: ağ erişimi yok. SSRF denetimi ayrıca index.js > assertPublicHost ile yapılır. */
"use strict";
const { domainToASCII } = require("url");

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;

// Alan adı: "https://www.Örnek.com/yol?x" → { ok, domain: "xn--...com" }. IP adresi ve tek etiketli adlar reddedilir.
function normalizeDomain(input, { stripWww = true } = {}) {
  if (typeof input !== "string") return { ok: false, error: "Alan adı metin olmalı" };
  let v = input.trim().toLowerCase();
  if (!v) return { ok: false, error: "Alan adı boş" };
  if (v.length > 2048) return { ok: false, error: "Alan adı çok uzun" };
  if (/[\s\u0000-\u001f\u007f]/.test(v)) return { ok: false, error: "Alan adında boşluk veya kontrol karakteri olamaz" };
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");            // protokolü at
  if (/^[^/?#]*@/.test(v)) return { ok: false, error: "Kullanıcı adı/parola içeren adres kabul edilmez" };
  v = v.split(/[/?#]/)[0].replace(/:\d{1,5}$/, "").replace(/\.$/, ""); // yol, sorgu, port, sondaki nokta
  if (stripWww) v = v.replace(/^www\./, "");
  if (!v) return { ok: false, error: "Alan adı boş" };
  if (/^[\d.]+$/.test(v) || v.includes(":") || v.startsWith("[")) return { ok: false, error: "IP adresi değil, alan adı girin" };
  const ascii = domainToASCII(v);
  if (!ascii) return { ok: false, error: "Geçersiz alan adı" };
  if (ascii.length > 253) return { ok: false, error: "Alan adı çok uzun" };
  const labels = ascii.split(".");
  if (labels.length < 2) return { ok: false, error: "Alan adı en az iki bölümden oluşmalı (ör. ornek.com)" };
  if (!labels.every((l) => LABEL.test(l))) return { ok: false, error: "Alan adında geçersiz karakter var" };
  if (!TLD.test(labels[labels.length - 1])) return { ok: false, error: "Geçersiz alan adı uzantısı" };
  return { ok: true, domain: ascii };
}

// URL: yalnızca http/https, kimlik bilgisi yok, ≤2048
function normalizeUrl(input) {
  if (typeof input !== "string") return { ok: false, error: "Adres metin olmalı" };
  let v = input.trim();
  if (!v) return { ok: false, error: "Adres boş" };
  if (v.length > 2048) return { ok: false, error: "Adres çok uzun" };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = "https://" + v;
  let u; try { u = new URL(v); } catch { return { ok: false, error: "Geçersiz adres" }; }
  if (!["http:", "https:"].includes(u.protocol)) return { ok: false, error: "Yalnızca http/https adresleri kabul edilir" };
  if (u.username || u.password) return { ok: false, error: "Kullanıcı adı/parola içeren adres kabul edilmez" };
  const d = normalizeDomain(u.hostname, { stripWww: false });
  if (!d.ok && !/^[\d.]+$|:/.test(u.hostname)) return d; // IP adresleri URL'de olabilir; SSRF denetimi ayrı yapılır
  return { ok: true, url: u.toString() };
}

// Telefon: +90 5xx xxx xx xx, 05xx..., 5xx..., uluslararası E.164 (10–15 hane). Çıktı: +905321234567
function normalizePhone(input) {
  if (typeof input !== "string") return { ok: false, error: "Telefon metin olmalı" };
  const raw = input.trim();
  if (!raw) return { ok: false, error: "Telefon boş" };
  if (raw.length > 30 || /[^\d+\s().-]/.test(raw)) return { ok: false, error: "Telefon yalnızca rakam, boşluk, +, -, ( ) içerebilir" };
  let d = raw.replace(/[^\d+]/g, "");
  if (d.startsWith("00")) d = "+" + d.slice(2);
  if (d.indexOf("+") > 0 || (d.match(/\+/g) || []).length > 1) return { ok: false, error: "Telefondaki + işareti yalnızca başta olabilir" };
  if (!d.startsWith("+")) {
    if (/^0?5\d{9}$/.test(d)) d = "+90" + d.replace(/^0/, "");
    else return { ok: false, error: "Ülke kodu ile yazın (ör. +90 5xx xxx xx xx)" };
  }
  if (!/^\+[1-9]\d{9,14}$/.test(d)) return { ok: false, error: "Telefon 10–15 haneli olmalı" };
  if (d.startsWith("+90") && !/^\+905\d{9}$/.test(d)) return { ok: false, error: "Türkiye cep numarası +90 5xx xxx xx xx biçiminde olmalı" };
  return { ok: true, phone: d };
}

// Vergi numarası (VKN): isteğe bağlı fatura alanı; 10 hane. (TC kimlik numarası DAC'ta toplanmaz.)
function normalizeTaxId(input) {
  if (input == null || String(input).trim() === "") return { ok: true, taxId: "" };
  const d = String(input).replace(/[\s.-]/g, "");
  if (!/^\d{10}$/.test(d)) return { ok: false, error: "Vergi numarası 10 haneli olmalı" };
  return { ok: true, taxId: d };
}

// Toplu içe aktarma: satır/virgül/noktalı virgül/sekme ayrımlı veya CSV (her hücre ayrı hedef; "domain" başlığı atlanır).
function parseBulkDomains(text, { max = 2000 } = {}) {
  const out = { valid: [], invalid: [], duplicates: [], truncated: false };
  if (typeof text !== "string") return out;
  const seen = new Set();
  const lines = text.split(/\r?\n/);
  let n = 0;
  for (let i = 0; i < lines.length; i++) {
    const cells = lines[i].split(/[,;\t]/).map((c) => c.trim().replace(/^"|"$/g, "")).filter(Boolean);
    for (let k = 0; k < cells.length; k++) {
      const raw = cells[k];
      if (i === 0 && k === 0 && /^(domain|alan ?ad[ıi]|host|url|site)$/i.test(raw)) continue;
      if (++n > max) { out.truncated = true; return out; }
      const r = normalizeDomain(raw);
      if (!r.ok) { out.invalid.push({ line: i + 1, raw: raw.slice(0, 120), error: r.error }); continue; }
      if (seen.has(r.domain)) { out.duplicates.push({ line: i + 1, domain: r.domain }); continue; }
      seen.add(r.domain); out.valid.push({ line: i + 1, domain: r.domain });
    }
  }
  return out;
}

module.exports = { normalizeDomain, normalizeUrl, normalizePhone, normalizeTaxId, parseBulkDomains };
