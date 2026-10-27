/* Digital Asset Center - Yönetici iki adımlı doğrulama (TOTP, RFC 6238) — ek paket gerektirmez.
 * Akış: yönetici Authenticator uygulamasına gizli anahtarı ekler → kodu onaylar (kayıt) → her oturumda kodu girerek 12 saatlik imzalı jeton alır.
 * Jeton: "<bitiş>.<HMAC>" (uid'ye bağlı; sunucu sırrıyla imzalı). ADMIN_REQUIRE_2FA=true iken tüm /api/admin/* uçları (2fa uçları hariç) jeton ister. */
"use strict";
const crypto = require("crypto");
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const b32enc = (buf) => { let bits = "", out = ""; for (const b of buf) bits += b.toString(2).padStart(8, "0"); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)]; return out; };
const b32dec = (s) => { let bits = ""; for (const c of String(s).toUpperCase().replace(/=+$/, "")) { const i = B32.indexOf(c); if (i < 0) throw new Error("geçersiz base32"); bits += i.toString(2).padStart(5, "0"); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const hotp = (key, counter, digits = 6) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac("sha1", key).update(b).digest(); const o = h[h.length - 1] & 15; const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]; return String(n % 10 ** digits).padStart(digits, "0"); };
const newSecret = () => b32enc(crypto.randomBytes(20));
// Geçerli kodsa eşleşen zaman adımını (replay'i engellemek için) döner, değilse null. Pencere ±1 adım (30 sn).
function verify(secret, code, nowMs = Date.now(), lastStep = -1) {
  const c = String(code || "").replace(/\s/g, ""); if (!/^\d{6}$/.test(c)) return null; const key = b32dec(secret), step = Math.floor(nowMs / 30000);
  for (const d of [0, -1, 1]) { const st = step + d; if (st <= lastStep) continue; const exp = hotp(key, st); if (crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(c))) return st; }
  return null;
}
const uri = (secret, account, issuer = "Digital Asset Center") => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
function createTokens(serverSecret, now = Date.now) {
  const sig = (uid, exp) => crypto.createHmac("sha256", serverSecret).update(`${uid}.${exp}`).digest("base64url");
  return {
    issue: (uid, ttlMs = 12 * 36e5) => { const exp = now() + ttlMs; return `${exp}.${sig(uid, exp)}`; },
    check: (uid, token) => { const m = /^(\d{10,16})\.([A-Za-z0-9_-]{20,64})$/.exec(String(token || "")); if (!m || +m[1] < now()) return false; const a = Buffer.from(m[2]), b = Buffer.from(sig(uid, m[1])); return a.length === b.length && crypto.timingSafeEqual(a, b); }
  };
}
module.exports = { b32enc, b32dec, hotp, newSecret, verify, uri, createTokens };
