#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Digital Asset Center - Scanner API (Python / FastAPI)  --  index.py
==========================================================================
index.js (Node/Express) ile AYNI HTTP sözleşmesini sunan, tek dosyalık Python sürümü.
Ön yüz (index.html, app.js ...) hiçbir değişiklik gerektirmez; aynı uç noktalar, aynı JSON alanları, aynı
bulgu anahtarları (finding_<anahtar>_<critical|warning|info>) kullanılır.

ÇALIŞTIRMA (Render > yeni "Python" Web Service):
  Build Command : pip install fastapi "uvicorn[standard]" aiohttp dnspython cryptography firebase-admin iyzipay brotli
  Start Command : uvicorn index:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*" --no-server-header
  Ortam değişkenleri: Node sürümündekilerin aynısı (FIREBASE_SERVICE_ACCOUNT, STRIPE_*, IYZICO_* ...).

Güvenlik tasarımı:
  * SSRF: hostname çözümlemesi bağlantı ANINDA, doğrulanmış çözümleyici ile yapılır (DNS rebinding ve yönlendirme dahil);
    IP-literal hedefler ve http/https dışı şemalar ayrıca engellenir.
  * Düşman sayfalar: HTML ayrıştırma standart kütüphane HTMLParser ile DOĞRUSAL zamanlıdır (ReDoS yok); gövde, açılım
    (gzip/br/deflate) ve toplam süre sınırlıdır.
  * Aktif sondalama (port/dosya yolu) yalnızca kullanıcı yetki beyanıyla (consent) yapılır ve kayda alınır.
"""
from __future__ import annotations

import asyncio, base64, hashlib, hmac, ipaddress, json, math, os, random, re
import socket, ssl, time, traceback, urllib.parse, zlib
from datetime import datetime, timezone, timedelta
from typing import Optional

import aiohttp
import aiohttp.abc
import dns.asyncresolver, dns.reversename, dns.exception, dns.flags, dns.name, dns.rdatatype, dns.resolver, dns.rcode
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

try:  # Brotli açma (isteğe bağlı; yoksa "br" ilan edilmez)
    import brotli as _brotli  # type: ignore
except Exception:  # pragma: no cover
    _brotli = None

SCANNER_VERSION = "v12.0-py"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =====================================================================
# Küçük yardımcılar
# =====================================================================
class J(dict):
    """JS nesnesi gibi davranan sözlük: j.alan okur/yazar, olmayan alan None döner (JS 'undefined')."""
    __slots__ = ()
    def __getattr__(self, k):
        if k.startswith("__"):
            raise AttributeError(k)
        return self.get(k)
    def __setattr__(self, k, v):
        self[k] = v


def jj(o):
    if isinstance(o, dict) and not isinstance(o, J):
        return J({k: jj(v) for k, v in o.items()})
    if isinstance(o, J):
        for k, v in list(o.items()):
            o[k] = jj(v)
        return o
    if isinstance(o, list):
        return [jj(x) for x in o]
    return o


def env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return default if v is None else v


def env_int(name: str, default: int) -> int:
    try:
        n = int(os.environ.get(name, ""))
        return n if n > 0 else default
    except ValueError:
        return default


def is_prod() -> bool:
    return env("NODE_ENV", env("APP_ENV", "")).strip().lower() not in ("development", "test")


def dev_bypass() -> bool:
    return (not is_prod()) and env("DEV_AUTH_BYPASS") == "true"


def enforce_plans() -> bool:
    return is_prod() or env("ENFORCE_PLANS") == "true"


def allow_private() -> bool:
    return env("ALLOW_PRIVATE_TARGETS") == "true"


def now_ms() -> int:
    return int(time.time() * 1000)


def clamp(n, lo=0, hi=100):
    return max(lo, min(hi, n))


def avg(a):
    return round(sum(a) / len(a)) if a else None


def js_round(x):
    """JS Math.round (yarım yukarı)."""
    return math.floor(x + 0.5)


def status_from_score(s):
    return "HEALTHY" if s >= 80 else "WARNING" if s >= 50 else "CRITICAL"


async def sleep(ms):
    await asyncio.sleep(ms / 1000)


async def with_timeout(coro, ms, label="İşlem"):
    try:
        return await asyncio.wait_for(coro, ms / 1000)
    except asyncio.TimeoutError:
        raise RuntimeError(f"{label} zaman aşımı")


async def pool(items, limit, fn):
    out = [None] * len(items)
    sem = asyncio.Semaphore(max(1, limit))
    async def run(i, it):
        async with sem:
            try:
                out[i] = await fn(it, i)
            except Exception:
                out[i] = None
    await asyncio.gather(*(run(i, it) for i, it in enumerate(items)))
    return out


def decode_entities(s) -> str:
    # &amp; EN SON çözülür (çift çözümleme olmaz)
    s = str(s or "")
    s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    s = re.sub(r"&#0?39;|&apos;", "'", s)
    def dec(m, base):
        try:
            return chr(int(m.group(1), base))
        except Exception:
            return ""
    s = re.sub(r"&#(\d{1,7});", lambda m: dec(m, 10), s)
    s = re.sub(r"&#x([0-9a-fA-F]{1,6});", lambda m: dec(m, 16), s)
    return s.replace("&amp;", "&")


def iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def to_date(s) -> Optional[datetime]:
    if not s:
        return None
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    if isinstance(s, (int, float)):
        try:
            return datetime.fromtimestamp(s / 1000, tz=timezone.utc)
        except Exception:
            return None
    t = str(s).strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", t):
            return datetime.strptime(t, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        t2 = t.replace("Z", "+00:00")
        d = datetime.fromisoformat(t2)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z", "%b %d %H:%M:%S %Y %Z", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            d = datetime.strptime(t, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def days_until(d) -> Optional[int]:
    t = to_date(d)
    if not t:
        return None
    n = datetime.now(timezone.utc)
    return (datetime(t.year, t.month, t.day, tzinfo=timezone.utc) - datetime(n.year, n.month, n.day, tzinfo=timezone.utc)).days


def days_since(d) -> Optional[int]:
    t = to_date(d)
    return int((datetime.now(timezone.utc) - t).total_seconds() // 86400) if t else None


# ---------- URL / hedef ayrıştırma ----------
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)


def normalize_host(h: str) -> str:
    """WHATWG URL gibi: 127.1 / 2130706433 / 0x7f.1 biçimlerini noktalı IPv4'e çevirir."""
    h = (h or "").strip().lower().strip("[]").rstrip(".")
    if _NUMERIC_HOST.match(h):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except Exception:
            return h
    try:
        h.encode("ascii")
    except UnicodeEncodeError:
        try:
            h = h.encode("idna").decode("ascii")
        except Exception:
            pass
    return h


def ensure_url(t) -> str:
    s = str(t or "").strip()
    return s if re.match(r"^https?://", s, re.I) else "https://" + s


def split_url(url: str):
    try:
        return urllib.parse.urlsplit(url)
    except Exception:
        return None


def host_of(t) -> Optional[str]:
    sp = split_url(ensure_url(t))
    if not sp:
        return None
    try:
        h = sp.hostname
    except Exception:
        return None
    if not h:
        return None
    return normalize_host(h)


def is_ip(h) -> bool:
    try:
        ipaddress.ip_address(str(h).strip("[]").split("%")[0])
        return True
    except Exception:
        return False


def is_ipv4(h) -> bool:
    try:
        return isinstance(ipaddress.ip_address(str(h)), ipaddress.IPv4Address)
    except Exception:
        return False


def is_ipv6(h) -> bool:
    try:
        return isinstance(ipaddress.ip_address(str(h).split("%")[0]), ipaddress.IPv6Address)
    except Exception:
        return False


MULTI_TLDS = set(("com.tr net.tr org.tr gen.tr web.tr biz.tr info.tr tv.tr name.tr av.tr dr.tr bel.tr k12.tr edu.tr gov.tr mil.tr pol.tr kep.tr "
    "co.uk org.uk me.uk ltd.uk plc.uk net.uk ac.uk gov.uk sch.uk com.au net.au org.au edu.au gov.au id.au co.nz net.nz org.nz govt.nz ac.nz "
    "co.jp ne.jp or.jp ac.jp go.jp com.br net.br org.br gov.br edu.br co.za org.za net.za web.za com.mx org.mx gob.mx edu.mx co.in net.in org.in firm.in gen.in ind.in "
    "com.cn net.cn org.cn gov.cn edu.cn com.hk org.hk edu.hk com.sg org.sg edu.sg com.my org.my com.ph org.ph com.tw org.tw com.vn com.pk com.bd com.np com.lk "
    "com.sa org.sa gov.sa com.eg org.eg gov.eg com.ng org.ng gov.ng co.ke or.ke co.il org.il ac.il co.kr or.kr go.kr co.th or.th co.id or.id web.id "
    "com.ar org.ar com.co org.co com.pe com.ve com.uy com.ec com.ua org.ua com.pl org.pl net.pl com.pt org.pt com.es org.es nom.es com.ru org.ru com.gr org.gr com.cy org.cy "
    "com.tn com.dz com.ma co.ma com.lb com.jo com.qa com.kw com.om com.bh com.ae net.ae org.ae gov.ae co.ae").split())


def parse_host_loose(inp) -> Optional[str]:
    if inp is None:
        return None
    s = str(inp).strip().lower()
    if not s:
        return None
    try:
        sp = urllib.parse.urlsplit(s if re.match(r"^[a-z][a-z0-9+.-]*://", s) else "https://" + s)
        h = sp.hostname
        if not h:
            raise ValueError("no host")
        s = h
    except Exception:
        s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
        s = re.sub(r"^.*@", "", s)
        s = re.split(r"[/?#]", s)[0].split(":")[0]
    s = s.strip("[]")
    s = re.sub(r"^\.+|\.+$", "", s)
    return normalize_host(s) or None


def registrable_domain(host):
    if not host or is_ip(host):
        return host or None
    p = [x for x in host.split(".") if x]
    if len(p) <= 2:
        return ".".join(p)
    l2 = ".".join(p[-2:])
    if l2 in MULTI_TLDS and len(p) >= 3:
        return ".".join(p[-3:])
    return l2


def parse_domain(inp) -> Optional[str]:
    h = parse_host_loose(inp)
    if not h or is_ip(h) or "." not in h:
        return None
    d = re.sub(r"^www\.", "", h)
    if not re.fullmatch(r"[a-z0-9_.\-\u00a1-\uffff]+", d, re.I) or len(d) > 253:
        return None
    return d


def parse_target_host(inp) -> Optional[str]:
    h = parse_host_loose(inp)
    if not h:
        return None
    if is_ip(h):
        return h
    return h if "." in h else None


def split_domain(d: str):
    p = d.split(".")
    l2 = ".".join(p[-2:])
    if l2 in MULTI_TLDS and len(p) >= 3:
        return J(label=p[-3], tld=l2)
    return J(label=p[-2] if len(p) >= 2 else p[0], tld=p[-1])


# =====================================================================
# SSRF KORUMASI
# =====================================================================
def _private_v4(a, b, c):
    return (a == 0 or a == 10 or a == 127 or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or
            (a == 100 and 64 <= b <= 127) or (a == 192 and b == 0 and c == 0) or (a == 198 and b in (18, 19)) or a >= 224)


def is_private_ip(ip) -> bool:
    s = str(ip or "").lower().strip("[]").split("%")[0]
    try:
        addr = ipaddress.ip_address(s)
    except Exception:
        return False  # IP değil (JS ile aynı: IP olmayan metin için false)
    if isinstance(addr, ipaddress.IPv4Address):
        b = addr.packed
        return _private_v4(b[0], b[1], b[2])
    b = addr.packed
    zeros = lambda n: all(x == 0 for x in b[:n])
    v4 = lambda o: _private_v4(b[o], b[o + 1], b[o + 2])
    if zeros(10) and b[10] == 0xFF and b[11] == 0xFF:
        return v4(12)                                    # ::ffff:a.b.c.d
    if zeros(12):
        return True                                      # ::, ::1, ::a.b.c.d
    if b[0] == 0 and b[1] == 0x64 and b[2] == 0xFF and b[3] == 0x9B and all(x == 0 for x in b[4:12]):
        return v4(12)                                    # NAT64
    if b[0] == 0x20 and b[1] == 0x02:
        return v4(2)                                     # 6to4
    if b[0] == 0x20 and b[1] == 0x01 and b[2] == 0 and b[3] == 0:
        return True                                      # Teredo
    if (b[0] & 0xFE) == 0xFC:
        return True                                      # ULA
    if b[0] == 0xFE and (b[1] & 0x80) == 0x80:
        return True                                      # link-local / site-local
    if b[0] == 0xFF:
        return True                                      # multicast
    return False


class PrivateAddressError(OSError):
    pass


def private_error() -> PrivateAddressError:
    e = PrivateAddressError("Yerel veya özel ağ adreslerine erişim engellendi")
    e.errno = None
    return e


def blocked_host(host) -> bool:
    """IP-literal ve yerel adlar (yönlendirme zinciri dahil her bağlantıdan önce çağrılır)."""
    if allow_private() or not host:
        return False
    h = normalize_host(str(host))
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True
    return is_private_ip(h) if is_ip(h) else False


async def safe_addrinfo(host: str, port: int = 0, family=socket.AF_UNSPEC):
    """Çözümler ve doğrular; özel adres varsa PrivateAddressError. [(family, ip), ...] döner."""
    host = normalize_host(host)
    if is_ip(host):
        if blocked_host(host):
            raise private_error()
        return [(socket.AF_INET6 if is_ipv6(host) else socket.AF_INET, host)]
    if blocked_host(host):
        raise private_error()
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    out = []
    for fam, _t, _p, _c, sa in infos:
        ip = sa[0]
        if not allow_private() and is_private_ip(ip):
            raise private_error()
        if (fam, ip) not in out:
            out.append((fam, ip))
    if not out:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return out


class SafeResolver(aiohttp.abc.AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        res = await safe_addrinfo(host, port, family if family in (socket.AF_INET, socket.AF_INET6) else socket.AF_UNSPEC)
        return [{"hostname": host, "host": ip, "port": port, "family": fam, "proto": 0, "flags": socket.AI_NUMERICHOST} for fam, ip in res]

    async def close(self):
        return None


async def assert_public_host(host):
    if allow_private() or not host:
        return
    h = str(host).strip("[]").lower()
    deny = RuntimeError("Yerel veya özel ağ adreslerine tarama yapılamaz")
    if h == "localhost" or h.endswith(".local") or h.endswith(".internal") or h.endswith(".localhost"):
        raise deny
    h = normalize_host(h)
    if is_ip(h):
        if is_private_ip(h):
            raise deny
        return
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except Exception:
        return
    if any(is_private_ip(i[4][0]) for i in infos):
        raise deny


# =====================================================================
# AĞ KATMANI
# =====================================================================
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
UA_BOT = "Mozilla/5.0 (compatible; DigitalAssetCenterBot/12.0; +https://dac-web-yefr.onrender.com)"
BROWSER_HEADERS = {
    "User-Agent": UA_BROWSER,
    "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br" if _brotli else "gzip, deflate",
}
_TLS_ERR = re.compile(r"CERT|SSL|TLS|ALTNAME|SELF.SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_OSSL|certificate", re.I)


def _tls_text(msg: str) -> str:
    m = re.search(r"certificate verify failed: ([^(\]]+?)\s*(?:\(|$)", msg)
    if m:
        t = m.group(1).strip()
        return {"unable to get local issuer certificate": "unable to verify the first certificate"}.get(t, t)
    m = re.search(r"Hostname mismatch|IP address mismatch", msg)
    if m:
        return "Hostname/IP does not match certificate's altnames"
    return msg


def classify_net_error(e, host=None, port=None, timeout=None) -> J:
    msg = str(e) or e.__class__.__name__
    oe = getattr(e, "os_error", None) or e
    hp = f" {host}:{port}" if host else ""
    if isinstance(oe, PrivateAddressError) or "EPRIVATE" in msg or "özel ağ" in msg:
        return J(code="EPRIVATE", kind="private", message="Yerel veya özel ağ adreslerine erişim engellendi")
    if isinstance(oe, socket.gaierror):
        en = getattr(oe, "errno", None)
        if en == getattr(socket, "EAI_AGAIN", -3):
            return J(code="EAI_AGAIN", kind="dns_temp", message=f"getaddrinfo EAI_AGAIN {host or ''}".strip())
        return J(code="ENOTFOUND", kind="dns", message=f"getaddrinfo ENOTFOUND {host or ''}".strip())
    if isinstance(e, (ssl.SSLError, aiohttp.ClientSSLError, aiohttp.ClientConnectorCertificateError)) or isinstance(oe, ssl.SSLError):
        return J(code="ERR_TLS", kind="tls", message=_tls_text(msg))
    if isinstance(e, asyncio.TimeoutError) or isinstance(oe, (asyncio.TimeoutError, TimeoutError)) or "timeout" in msg.lower() or "timed out" in msg.lower():
        return J(code="ETIMEDOUT", kind="timeout", message=f"timeout of {timeout}ms exceeded" if timeout else "timeout")
    if isinstance(oe, ConnectionRefusedError) or "Connect call failed" in msg and "111" in msg:
        return J(code="ECONNREFUSED", kind="refused", message=f"connect ECONNREFUSED{hp}")
    if isinstance(oe, (ConnectionResetError, BrokenPipeError)) or isinstance(e, aiohttp.ServerDisconnectedError):
        return J(code="ECONNRESET", kind="reset", message="socket hang up")
    if isinstance(oe, OSError) and getattr(oe, "errno", None) in (113, 101):
        return J(code="EHOSTUNREACH", kind="unreachable", message=f"connect {'EHOSTUNREACH' if getattr(oe, 'errno', 0) == 113 else 'ENETUNREACH'}{hp}")
    if "redirect" in msg.lower():
        return J(code=None, kind="redirect", message=msg)
    if _TLS_ERR.search(msg) and "Connect call failed" not in msg:
        return J(code="ERR_TLS", kind="tls", message=_tls_text(msg))
    return J(code=None, kind="other", message=msg)


_DISCARD_DUP = {"age", "authorization", "content-length", "content-type", "etag", "expires", "from", "host", "if-modified-since", "if-unmodified-since", "last-modified", "location",
                "max-forwards", "proxy-authorization", "referer", "retry-after", "server", "user-agent"}


class _GunzipBomb(Exception):
    pass


def _make_decoder(enc: Optional[str]):
    if enc in ("gzip", "x-gzip"):
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    if enc == "deflate":
        return zlib.decompressobj()
    if enc == "br" and _brotli is not None:
        try:
            return _brotli.Decompressor()
        except Exception:
            return None
    return None


def _decode_chunk(dec, chunk: bytes, room: int) -> bytes:
    """Açılım bombası koruması: en fazla 'room' bayt üretir."""
    if dec is None:
        return chunk
    if isinstance(dec, zlib.Decompress if hasattr(zlib, "Decompress") else type(zlib.decompressobj())):
        out = dec.decompress(chunk, max(1, room))
        return out
    try:  # brotli
        return dec.process(chunk)
    except Exception:
        return b""


async def request(url: str, *, method: str = "GET", timeout: int = 10000, headers: Optional[dict] = None,
                  max_bytes: int = 2_000_000, read_body: bool = True, insecure: bool = False) -> J:
    t0 = time.monotonic()
    base = J(ok=False, status=0, ttfb=None, total=None, responseTimeMs=None, transferBytes=0, rawBytes=0, encoding=None,
             headers={}, body="", finalUrl=url, truncated=False)
    def ms():
        return int((time.monotonic() - t0) * 1000)
    session = None
    try:
        try:
            pu = urllib.parse.urlsplit(url)
            host = pu.hostname
        except Exception:
            raise OSError("Geçersiz adres")
        if pu.scheme not in ("http", "https") or not host:
            raise OSError("Yalnızca http/https desteklenir")
        if blocked_host(host):
            raise private_error()
        ctx = None
        if pu.scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if not insecure else ssl.TLSVersion.MINIMUM_SUPPORTED
        connector = aiohttp.TCPConnector(resolver=SafeResolver(), ssl=ctx if ctx else False, force_close=True, limit=0, ttl_dns_cache=0, use_dns_cache=False)
        session = aiohttp.ClientSession(connector=connector, auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
                                        timeout=aiohttp.ClientTimeout(total=None, connect=timeout / 1000, sock_connect=timeout / 1000, sock_read=max(3.0, timeout / 1000)),
                                        max_line_size=16384, max_field_size=16384)
        hdrs = {**BROWSER_HEADERS, **(headers or {})}
        resp = await asyncio.wait_for(session.request(method, url, headers=hdrs, allow_redirects=False, ssl=ctx if ctx else False), timeout=timeout / 1000)
    except BaseException as e:  # noqa
        if isinstance(e, (asyncio.CancelledError, KeyboardInterrupt)):
            if session:
                await session.close()
            raise
        if session:
            try:
                await session.close()
            except Exception:
                pass
        try:
            _sp = urllib.parse.urlsplit(url)
            _port = _sp.port or (443 if _sp.scheme == 'https' else 80)
            ni = classify_net_error(e, _sp.hostname, _port, timeout)
        except Exception:
            ni = classify_net_error(e)
        total = ms()
        r = J(base)
        r.update(total=total, responseTimeMs=total, error=ni.message, errorInfo=ni)
        return r
    ttfb = ms()
    try:
        h: dict = {}
        cookies = []
        for k, v in resp.headers.items():
            lk = k.lower()
            if lk == "set-cookie":
                cookies.append(v)
            elif lk in h:
                if lk in _DISCARD_DUP:
                    continue  # Node.js ile aynı: bu başlıklarda yinelenen değerler atılır (ilki tutulur)
                h[lk] = h[lk] + ("; " if lk == "cookie" else ", ") + v
            else:
                h[lk] = v
        if cookies:
            h["set-cookie"] = cookies
        enc = (h.get("content-encoding") or "").lower() or None
        ctype = (h.get("content-type") or "").lower()
        textual = (not ctype) or bool(re.search(r"text|json|xml|javascript|html|svg", ctype))
        transfer = raw = 0
        truncated = False
        chunks: list[bytes] = []
        if method != "HEAD":
            dec = _make_decoder(enc) if enc else None
            deadline = time.monotonic() + max(3.0, timeout / 1000)
            try:
                async for chunk in resp.content.iter_chunked(16384):
                    transfer += len(chunk)
                    if time.monotonic() > deadline:
                        truncated = True
                        break
                    if dec is None and transfer > max_bytes * 2:
                        truncated = True
                        break
                    try:
                        out = _decode_chunk(dec, chunk, max_bytes - raw + 1) if dec is not None else chunk
                    except Exception:
                        break
                    raw += len(out)
                    if read_body and textual and raw <= max_bytes:
                        chunks.append(out)
                    elif raw > max_bytes:
                        truncated = True
                        break
            except (aiohttp.ClientPayloadError, aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError, OSError):
                pass
        total = ms()
        try:
            clen = int(h.get("content-length") or 0)
        except ValueError:
            clen = 0
        body = b"".join(chunks).decode("utf-8", "replace") if (read_body and textual) else ""
        return J(ok=resp.status < 400, status=resp.status, ttfb=ttfb, total=total, responseTimeMs=total,
                 transferBytes=max(transfer, clen) if truncated else (transfer or clen or 0), rawBytes=raw, encoding=enc,
                 headers=h, body=body, finalUrl=url, truncated=truncated, contentType=ctype)
    finally:
        try:
            resp.close()
        except Exception:
            pass
        await session.close()


async def request_retry(url, **o) -> J:
    r = await request(url, **o)
    if r.status == 0 and r.errorInfo:
        k = r.errorInfo.kind
        if k == "tls" and not o.get("insecure"):
            r2 = await request(url, **{**o, "insecure": True})
            if r2.status > 0:
                r2.tlsError = r.errorInfo.code or r.errorInfo.message
                return r2
            return r
        # Zaman aşımında yeniden deneme yok (engelleyen/yanıt vermeyen sitede süreyi ikiye katlamasın)
        if k in ("reset", "dns_temp", "other") and not o.get("noRetry"):
            await sleep(300)
            return await request(url, **o)
    return r


def parse_set_cookie(arr) -> list:
    if arr is None:
        return []
    arr = arr if isinstance(arr, list) else [arr]
    return [c for c in (str(x).split(";")[0] for x in arr) if "=" in c]


def detect_bot_protection(probe: J):
    h = probe.headers or {}
    body = str(probe.body or "")[:30000].lower()
    server = str(h.get("server") or "").lower()
    blocked = probe.status in (401, 403, 429, 503)
    if str(h.get("cf-mitigated") or "").lower() == "challenge":
        return "Cloudflare"
    if not blocked:
        return None
    is_cf = "cloudflare" in server or bool(h.get("cf-ray"))
    if is_cf and re.search(r"just a moment|cf-chl|challenge-platform|attention required|checking your browser|cf-browser-verification|enable javascript and cookies", body):
        return "Cloudflare"
    if h.get("x-sucuri-id") or "sucuri website firewall" in body:
        return "Sucuri"
    if h.get("x-iinfo") or "incapsula incident" in body:
        return "Imperva Incapsula"
    if "ddos-guard" in server or "ddos-guard" in body:
        return "DDoS-Guard"
    if "akamaighost" in server and "access denied" in body:
        return "Akamai"
    if re.search(r"px-captcha|perimeterx|datadome|human verification", body) or h.get("x-datadome"):
        return "Bot koruma servisi"
    if re.search(r"aws.?waf|request blocked.*cloudfront", body):
        return "AWS WAF"
    return None


async def http_probe(url: str, **o) -> J:
    mx = o.pop("maxRedirects", 5)
    no_ua = o.pop("noUaFallback", False)
    chain = []
    jar: dict = {}
    cur = url
    res = None
    tls_error = None
    loop = False
    seen = set()
    method = o.get("method", "GET")
    for i in range(mx + 1):
        cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
        hdrs = {**(o.get("headers") or {}), **({"Cookie": cookie} if cookie else {})}
        oo = {**o, "headers": hdrs}
        res = await request_retry(cur, **oo)
        if i == 0 and not no_ua and method == "GET" and res.status in (403, 406, 429) and not detect_bot_protection(res):
            alt = await request_retry(cur, **{**o, "headers": {**(o.get("headers") or {}), "User-Agent": UA_BOT}})
            if 0 < alt.status < 400:
                res = alt
                res.uaFallback = True
        if res.tlsError:
            tls_error = res.tlsError
        chain.append(J(url=cur, status=res.status, ms=res.total, ttfb=res.ttfb))
        for c in parse_set_cookie((res.headers or {}).get("set-cookie")):
            k, _, v = c.partition("=")
            jar[k] = v
        loc = (res.headers or {}).get("location")
        if 300 <= res.status < 400 and loc and i < mx:
            try:
                nxt = urllib.parse.urljoin(cur, loc)
                urllib.parse.urlsplit(nxt)
            except Exception:
                break
            if nxt in seen:
                loop = True
                break
            seen.add(cur)
            cur = nxt
            continue
        break
    res.chain = chain
    res.finalUrl = cur
    res.redirects = max(0, len(chain) - 1)
    res.tlsError = tls_error
    res.redirectLoop = loop
    ck = (res.headers or {}).get("set-cookie")
    res.cookies = ck if isinstance(ck, list) else ([ck] if ck else [])
    return res


async def timed_get(url, timeout=12000):
    return await http_probe(url, timeout=timeout, maxRedirects=5, noUaFallback=True)


async def tcp_port_check(host: str, port: int, timeout: int = 3000) -> J:
    t0 = time.monotonic()
    def out(open_, err=None):
        return J(port=port, open=open_, latencyMs=int((time.monotonic() - t0) * 1000), error=err)
    if blocked_host(host):
        return out(False, "EPRIVATE")
    try:
        addrs = await asyncio.wait_for(safe_addrinfo(host, port), timeout / 1000)
    except PrivateAddressError:
        return out(False, "EPRIVATE")
    except asyncio.TimeoutError:
        return out(False, "timeout")
    except socket.gaierror:
        return out(False, "ENOTFOUND")
    except Exception as e:
        return out(False, getattr(e, "strerror", None) or str(e))
    fam, ip = addrs[0]
    w = None
    try:
        r_, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout / 1000)
        return out(True)
    except asyncio.TimeoutError:
        return out(False, "timeout")
    except ConnectionRefusedError:
        return out(False, "ECONNREFUSED")
    except OSError as e:
        return out(False, {101: "ENETUNREACH", 113: "EHOSTUNREACH"}.get(e.errno, e.__class__.__name__))
    finally:
        if w:
            try:
                w.close()
            except Exception:
                pass


# =====================================================================
# DNS KATMANI
# =====================================================================
_RES = None


def _resolver():
    global _RES
    if _RES is None:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]
        r.timeout = 3.0
        r.lifetime = 6.0
        _RES = r
    return _RES


TRANSIENT_DNS = {"ETIMEOUT", "ETIMEDOUT", "ESERVFAIL", "ECONNREFUSED", "EREFUSED", "ECONNRESET", "EAI_AGAIN", "ECANCELLED", "EBADRESP"}


def _txt_chunks(rdata):
    return [c.decode("utf-8", "replace") if isinstance(c, (bytes, bytearray)) else str(c) for c in rdata.strings]


def _convert(kind: str, ans):
    if kind in ("A", "AAAA"):
        return [r.address for r in ans]
    if kind in ("CNAME", "NS"):
        return [str(r.target if kind == "CNAME" else r.target).rstrip(".") for r in ans]
    if kind == "MX":
        return [J(exchange=str(r.exchange).rstrip("."), priority=r.preference) for r in ans]
    if kind == "TXT":
        return [_txt_chunks(r) for r in ans]
    if kind == "CAA":
        out = []
        for r in ans:
            tag = r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag)
            val = r.value.decode("utf-8", "replace") if isinstance(r.value, bytes) else str(r.value)
            out.append(J(critical=r.flags, **{tag: val}))
        return out
    if kind == "SOA":
        r = ans[0]
        return J(nsname=str(r.mname).rstrip("."), hostmaster=str(r.rname).rstrip("."), serial=r.serial, refresh=r.refresh, retry=r.retry, expire=r.expire, minttl=r.minimum)
    return [str(r) for r in ans]


async def dq(kind: str, name: str, resolver=None) -> J:
    """{data, code}: code None = başarılı; ENODATA/ENOTFOUND = kesin yok; diğerleri = geçici hata."""
    for i in range(2):
        try:
            ans = await (resolver or _resolver()).resolve(name, kind, raise_on_no_answer=True)
            return J(data=_convert(kind, ans), code=None)
        except dns.resolver.NXDOMAIN:
            return J(data=[], code="ENOTFOUND")
        except dns.resolver.NoAnswer:
            return J(data=[], code="ENODATA")
        except (dns.exception.Timeout, asyncio.TimeoutError):
            code = "ETIMEOUT"
        except dns.resolver.NoNameservers:
            code = "ESERVFAIL"
        except Exception:
            code = "EUNKNOWN"
        if code in TRANSIENT_DNS and i == 0:
            await sleep(250)
            continue
        return J(data=[], code=code)
    return J(data=[], code="EUNKNOWN")


def dns_missing(c) -> bool:
    return c in ("ENODATA", "ENOTFOUND")


async def http_json(url: str, timeout: int = 8000, headers: Optional[dict] = None, method: str = "GET", json_body=None, form=None, text=False):
    """Dış servis çağrısı (sabit/güvenilir adresler); (status, data) döner. Hata: (0, None)."""
    try:
        connector = aiohttp.TCPConnector(resolver=SafeResolver(), force_close=True, limit=0)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout / 1000),
                                         headers={"User-Agent": UA_BOT, **(headers or {})}) as s:
            async with s.request(method, url, json=json_body, data=form, max_redirects=4) as r:
                if text:
                    return r.status, (await r.content.read(2_000_000)).decode("utf-8", "replace")
                raw = await r.content.read(4_000_000)
                try:
                    return r.status, json.loads(raw.decode("utf-8", "replace"))
                except Exception:
                    return r.status, None
    except Exception:
        return 0, None


async def doh_query(name: str, rtype, extra: str = ""):
    q = urllib.parse.quote(name, safe="")
    for u in (f"https://cloudflare-dns.com/dns-query?name={q}&type={rtype}{extra}", f"https://dns.google/resolve?name={q}&type={rtype}{extra}"):
        st, data = await http_json(u, 6000, {"accept": "application/dns-json"})
        if st == 200 and isinstance(data, dict):
            return J(jj(data))
    return None


def clean_txt(d) -> str:
    t = str(d or "")
    if re.fullmatch(r'".*"', t.strip(), re.S) or '" "' in t:
        t = re.sub(r'"\s+"', "", t)
        t = re.sub(r'^"|"$', "", t)
    return t.replace('\\"', '"')


async def doh_txt(domain: str):
    data = await doh_query(domain, "TXT")
    ans = [a for a in ((data.Answer if data else None) or []) if a.get("type") == 16]
    return [[clean_txt(a.get("data"))] for a in ans] if ans else None


def normalize_txt_records(records) -> list:
    if not isinstance(records, list):
        return []
    out = []
    for r in records:
        v = "".join(r) if isinstance(r, list) else str(r or "")
        v = re.sub(r'^"+|"+$', "", v.strip())
        if v:
            out.append(v)
    return out


async def resolve_txt_robust(name: str) -> J:
    r = await dq("TXT", name)
    if r.data:
        return J(records=r.data, state="ok")
    d = await doh_txt(name)
    if d:
        return J(records=d, state="ok")
    state = "none" if dns_missing(r.code) else ("error" if (d is None and r.code and not dns_missing(r.code)) else "none")
    return J(records=[], state=state)


async def collect_dns_records(domain: str) -> J:
    a, aaaa, cname, mx, ns, caa, soa, txt_r = await asyncio.gather(
        dq("A", domain), dq("AAAA", domain), dq("CNAME", domain), dq("MX", domain), dq("NS", domain), dq("CAA", domain), dq("SOA", domain), resolve_txt_robust(domain))
    ds = []
    ds_data = await doh_query(domain, "DS")
    if ds_data and ds_data.Answer:
        ds = [x.get("data") for x in ds_data.Answer if x.get("type") == 43]
    soa_val = soa.data if isinstance(soa.data, dict) and soa.data.get("nsname") else None
    codes = [x.code for x in (a, aaaa, cname, mx, ns)]
    resolver_broken = False
    if not a.data and not aaaa.data and not ns.data and not cname.data:
        ctl = await dq("A", "cloudflare.com")
        ctl2 = ctl if ctl.data else await doh_query("cloudflare.com", "A")
        resolver_broken = not (ctl.data or (ctl2 and ctl2.get("Answer")))
    return J(a=a.data, aaaa=aaaa.data, cname=cname.data, mx=sorted(mx.data or [], key=lambda x: x.priority), ns=sorted(x.lower() for x in (ns.data or [])),
             txt=txt_r.records, txtState=txt_r.state, caa=caa.data or [], soa=soa_val, ds=ds,
             nxdomain=(not resolver_broken) and ("ENOTFOUND" in codes) and not a.data and not aaaa.data and not ns.data,
             allFailed=resolver_broken or all(c and not dns_missing(c) for c in codes))


async def resolve_ips(host: str) -> J:
    if is_ipv4(host):
        return J(v4=[host], v6=[])
    if is_ipv6(host):
        return J(v4=[], v6=[host])
    v4, v6 = await asyncio.gather(dq("A", host), dq("AAAA", host))
    a4, a6 = list(v4.data), list(v6.data)
    if not a4 and not a6:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            a4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
            a6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
        except Exception:
            pass
    return J(v4=a4, v6=a6, code=v4.code)


# =====================================================================
# Bulgu sınıflandırma / skor / sonuç oluşturucular
# =====================================================================
STATUS = J(VALID="VALID", INACTIVE="INACTIVE", UNKNOWN="UNKNOWN", NOT_REQUIRED="NOT_REQUIRED", MISSING="MISSING", SELECTOR_NOT_DISCOVERED="SELECTOR_NOT_DISCOVERED")
TRANSFER_LOCK_STATUS = J(LOCKED="LOCKED", UNLOCKED="UNLOCKED", UNKNOWN="UNKNOWN")
CRITICAL_HINTS = ["_down", "_unreachable", "_expired", "_error", "_exposed", "_risk", "_invalid", "_failed", "_publicly", "_blacklisted", "_not_resolving", "_untrusted", "_takeover"]
WARNING_HINTS = ["_missing", "_not_configured", "_expiring_soon", "_approaching", "_stale", "_pending", "_incomplete", "_unknown", "_passive", "_open", "_none", "_monitoring_only"]


def classify_finding(f) -> str:
    s = str(f)
    if s.endswith("_critical"):
        return "critical"
    if s.endswith("_warning"):
        return "warning"
    if s.endswith("_info"):
        return "info"
    lower = s.lower()
    if any(h in lower for h in CRITICAL_HINTS):
        return "critical"
    if any(h in lower for h in WARNING_HINTS):
        return "warning"
    return "ok"


def compute_health(findings=()) -> J:
    c = w = 0
    for f in findings:
        k = classify_finding(f)
        if k == "critical":
            c += 1
        elif k == "warning":
            w += 1
    score = clamp(100 - min(c, 2) * 40 - min(w, 4) * 15)
    return J(healthScore=score, healthLevel="YEŞİL" if score >= 80 else "SARI" if score >= 50 else "KIRMIZI")


def compute_confidence(findings=(), had_error=False):
    conf = 100
    if had_error:
        conf -= 20
    conf -= min(len([f for f in findings if re.search(r"unknown|unreliable|unavailable|limited", str(f))]) * 5, 20)
    return clamp(conf)


def default_status_from_health(level):
    return "ACTIVE" if level == "YEŞİL" else "WARNING" if level == "SARI" else "CRITICAL"


_SEV = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def sort_findings(arr):
    uniq = list(dict.fromkeys(arr))
    return sorted(uniq, key=lambda f: _SEV[classify_finding(f)])


class Checker:
    """Ağırlıklı kontrol listesi: bilinmeyen (None) kontroller skoru ETKİLEMEZ."""
    def __init__(self):
        self.items: list[J] = []

    @staticmethod
    def _calc(lst):
        t = sum(i.w for i in lst)
        return js_round(sum(i.w for i in lst if i.pass_) / t * 100) if t else None

    def add(self, passed, w, finding=None, group=None):
        if passed is None:
            return
        self.items.append(J(pass_=bool(passed), w=w, finding=finding, group=group or "genel"))

    def findings(self):
        return [i.finding for i in self.items if not i.pass_ and i.finding]

    def score(self, group=None):
        return self._calc([i for i in self.items if i.group == group] if group else self.items)

    def groups(self):
        return list(dict.fromkeys(i.group for i in self.items))

    def summary(self):
        return J(passed=len([i for i in self.items if i.pass_]), total=len(self.items))

    def group_scores(self):
        return {g: self._calc([i for i in self.items if i.group == g]) for g in self.groups()}


def build_result(*, assetType, version, startedAt, target, findings, specific, score, status=None, errors=None, hint=None, confidence=None) -> J:
    st = status or ("UNKNOWN" if score is None else status_from_score(score))
    fl = sort_findings(findings or [])
    common = J(analyzerVersion=version, executionTimeMs=now_ms() - startedAt, findings=fl, scannedAt=iso(datetime.now(timezone.utc)), score=score, status=st, target=target)
    scores = dict(specific.get("scores") or {})
    if score is not None:
        scores["overall"] = score
    out = J(data=J(assetType=assetType, commonAnalysis=common, specificAnalysis=J({**specific, "scores": scores}),
                   analysisMeta=J(scannerVersion=version, analyzer=assetType.lower())), findings=fl, errors=errors or [], statusHint=hint or st)
    if confidence is not None:
        out.confidence = confidence
    return out


def unavailable_result(*, assetType, version, startedAt, target, finding, status, note, specific=None) -> J:
    findings = [finding]
    common = J(analyzerVersion=version, executionTimeMs=now_ms() - startedAt, findings=findings, scannedAt=iso(datetime.now(timezone.utc)), score=None, status=status, target=target)
    return J(data=J(assetType=assetType, commonAnalysis=common, specificAnalysis=J({**(specific or {}), "note": note}),
                    analysisMeta=J(scannerVersion=version, analyzer=assetType.lower(), limited=True)), findings=findings, errors=[], statusHint=status)


def protected_result(assetType, version, startedAt, target, main, provider) -> J:
    return unavailable_result(assetType=assetType, version=version, startedAt=startedAt, target=target, finding="finding_web_bot_protection_info", status="PROTECTED",
        note="Site bot koruması arkasında; tarayıcı doğrulama sayfası aldı. Site büyük olasılıkla çalışıyor, bu analiz yapılamadı.",
        specific=J(url=target, status=main.status, server=(main.headers or {}).get("server"), botProtection=J(detected=True, provider=provider)))


def net_error_finding(prefix, main) -> str:
    k = main.errorInfo.kind if main.errorInfo else None
    if main.redirectLoop:
        return f"finding_{prefix}_redirect_loop_critical"
    return {"dns": f"finding_{prefix}_dns_failure_critical", "refused": f"finding_{prefix}_connection_refused_critical", "timeout": f"finding_{prefix}_timeout_critical",
            "tls": f"finding_{prefix}_tls_failure_critical", "reset": f"finding_{prefix}_connection_reset_critical", "unreachable": f"finding_{prefix}_network_unreachable_critical",
            "private": f"finding_{prefix}_private_target_critical"}.get(k, f"finding_{prefix}_unreachable_critical")


def down_result(assetType, version, startedAt, target, main, code) -> J:
    return build_result(assetType=assetType, version=version, startedAt=startedAt, target=target, findings=[code], score=0, status="DOWN",
        specific=J(url=target, status=main.status, error=main.error, errorKind=main.errorInfo.kind if main.errorInfo else None, errorCode=main.errorInfo.code if main.errorInfo else None))


# =====================================================================
# DOMAIN / E-POSTA ANALİZ YARDIMCILARI
# =====================================================================
def find_spf_records(records):
    return [r for r in normalize_txt_records(records) if re.match(r"^v=spf1(?:\s|$)", r, re.I)]


def find_dmarc_records(records):
    return [r for r in normalize_txt_records(records) if re.match(r"^v=dmarc1(?:\s*;|\s|$)", r, re.I)]


def parse_tags(rec) -> dict:
    o = {}
    for p in str(rec or "").split(";"):
        i = p.find("=")
        if i > 0:
            o[p[:i].strip().lower()] = p[i + 1:].strip()
    return o


_DNS_MAP = [("cloudflare", "Cloudflare"), ("googledomains", "Google Domains"), ("google", "Google Cloud DNS"), ("awsdns", "AWS Route53"), ("azure-dns", "Azure DNS"), ("godaddy", "GoDaddy"), ("domaincontrol", "GoDaddy"),
    ("natro", "Natro"), ("turhost", "Turhost"), ("hostinger", "Hostinger"), ("digitalocean", "DigitalOcean"), ("namecheap", "Namecheap"), ("registrar-servers", "Namecheap"), ("dnsimple", "DNSimple"),
    ("nsone", "NS1"), ("ultradns", "UltraDNS"), ("dynect", "Dyn"), ("hetzner", "Hetzner"), ("ovh", "OVH"), ("gandi", "Gandi"), ("name.com", "Name.com"), ("wixdns", "Wix"), ("squarespace", "Squarespace"), ("vercel-dns", "Vercel"), ("netlify", "Netlify"), ("linode", "Linode"), ("yandex", "Yandex"), ("isimtescil", "İsimtescil"), ("metunic", "METUnic"), ("nic.tr", "TRABIS (nic.tr)")]


def detect_dns_provider(ns):
    if not ns:
        return None
    j = ",".join(ns).lower()
    for k, v in _DNS_MAP:
        if k in j:
            return v
    return ns[0] or "unknown"


_MAIL_MAP = [("google.com", "Google Workspace", ["google", "20230601", "20221208"]), ("googlemail.com", "Google Workspace", ["google"]), ("outlook.com", "Microsoft 365", ["selector1", "selector2"]), ("protection.outlook", "Microsoft 365", ["selector1", "selector2"]),
    ("zoho.", "Zoho Mail", ["zoho", "zmail", "default"]), ("yandex", "Yandex Mail", ["mail", "yandex"]), ("protonmail", "Proton Mail", ["protonmail", "protonmail2", "protonmail3"]), ("mailgun", "Mailgun", ["k1", "mailo", "krs", "smtp", "mg"]),
    ("pphosted", "Proofpoint", ["default"]), ("mimecast", "Mimecast", ["default"]), ("secureserver.net", "GoDaddy Mail", ["default"]), ("hostinger", "Hostinger Mail", ["hostingermail-a", "hostingermail-b", "hostingermail-c", "default"]),
    ("registrar-servers", "Namecheap Mail", ["default", "privateemail"]), ("improvmx", "ImprovMX", ["dkim", "default"]), ("icloud", "iCloud Mail", ["sig1"]), ("fastmail", "Fastmail", ["fm1", "fm2", "fm3"]), ("mailchannels", "MailChannels", ["mailchannels"])]


def detect_mail_provider(mx) -> J:
    j = ",".join(str((m.get("exchange") if isinstance(m, dict) else m) or "").lower() for m in (mx or []))
    for k, name, sel in _MAIL_MAP:
        if k in j:
            return J(provider=name, selectors=sel)
    return J(provider="Özel / diğer" if j else None, selectors=[])


async def analyze_spf(domain: str, txt_records) -> J:
    spfs = find_spf_records(txt_records)
    res = J(record=spfs[0] if spfs else None, count=len(spfs), lookups=0, all=None, issues=[], includes=[], ptr=False, brokenIncludes=[], tooManyLookups=False, strength=None)
    if not spfs:
        return res
    visited = {domain}
    st = J(fetches=0)

    async def walk(rec, d, depth):
        for raw in rec.strip().split()[1:]:
            m = re.match(r"^([+\-~?])?([a-z0-9]+)(?:[:=](.+))?$", raw, re.I)
            if not m:
                continue
            q = m.group(1) or "+"
            mech = m.group(2).lower()
            arg = m.group(3)
            if mech == "all":
                if depth == 0:
                    res.all = q + "all"
                continue
            if mech in ("include", "a", "mx", "ptr", "exists", "redirect"):
                res.lookups += 1
            if mech == "ptr":
                res.ptr = True
            if mech in ("include", "redirect") and arg:
                tgt = arg.lower()
                if depth == 0:
                    res.includes.append(tgt)
                if tgt in visited or depth >= 6 or st.fetches >= 14:
                    continue
                visited.add(tgt)
                st.fetches += 1
                r = await resolve_txt_robust(tgt)
                subs = find_spf_records(r.records)
                sub = subs[0] if subs else None
                if not sub:
                    if r.state == "none":
                        res.brokenIncludes.append(tgt)
                    continue
                if mech == "redirect" and depth == 0 and not res.all:
                    mm = re.search(r"\s([+\-~?])all\b", sub, re.I)
                    if mm:
                        res.all = mm.group(1) + "all"
                await walk(sub, tgt, depth + 1)
    try:
        await asyncio.wait_for(walk(spfs[0], domain, 0), 9)
    except Exception:
        pass
    res.tooManyLookups = res.lookups > 10
    res.strength = ("strict" if res.all == "-all" else "soft" if res.all == "~all" else "neutral" if res.all == "?all" else "open" if res.all == "+all"
                    else ("redirect" if (res.record and re.search(r"redirect=", res.record, re.I)) else "none"))
    return res


DKIM_BASE = ["default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "smtp", "email", "mandrill", "sendgrid", "zoho", "zmail", "mailo", "krs",
    "mxvault", "everlytickey1", "everlytickey2", "eversrv", "protonmail", "protonmail2", "protonmail3", "dkim1", "dkim2", "key1", "key2", "mta", "mailjet", "cm", "pm", "smtpapi", "mg", "selector", "x", "mimecast20190104", "scph0123", "turbo-smtp", "hostingermail-a", "hostingermail-b", "hostingermail-c", "fm1", "fm2", "fm3"]


def dkim_key_info(rec) -> J:
    t = parse_tags(rec)
    p = re.sub(r"\s+", "", t.get("p", ""))
    info = J(keyType=(t.get("k") or "rsa").lower(), revoked=("p" in t and p == ""), testMode=bool(re.search(r"(^|:)y(:|$)", t.get("t", ""))), bits=None)
    if p and info.keyType == "rsa":
        try:
            k = serialization.load_der_public_key(base64.b64decode(p + "=" * (-len(p) % 4)))
            info.bits = getattr(k, "key_size", None)
        except Exception:
            pass
    return info


async def discover_dkim(domain, extra_selectors=None) -> list:
    sels = list(dict.fromkeys([*(extra_selectors or []), *DKIM_BASE]))
    found = []

    async def one(s, _i):
        r = await dq("TXT", f"{s}._domainkey.{domain}")
        if not r.data:
            return
        txt = "".join(normalize_txt_records(r.data))
        if not re.search(r"v=dkim1|k=rsa|k=ed25519|;\s*p=|^p=", txt, re.I):
            return
        found.append(J(selector=s, record=txt[:200], **dkim_key_info(txt)))
    await pool(sels, 10, one)
    found.sort(key=lambda x: DKIM_BASE.index(x.selector) if x.selector in DKIM_BASE else -1)
    return found


async def check_mail_policies(domain) -> J:
    out = J(mtaSts=J(present=False, mode=None, maxAge=None, policyReachable=None), tlsRpt=False, bimi=False)
    sts, rpt, bimi = await asyncio.gather(dq("TXT", f"_mta-sts.{domain}"), dq("TXT", f"_smtp._tls.{domain}"), dq("TXT", f"default._bimi.{domain}"))
    out.mtaSts.present = any(re.match(r"^v=STSv1", r, re.I) for r in normalize_txt_records(sts.data))
    out.tlsRpt = any(re.match(r"^v=TLSRPTv1", r, re.I) for r in normalize_txt_records(rpt.data))
    out.bimi = any(re.match(r"^v=BIMI1", r, re.I) for r in normalize_txt_records(bimi.data))
    if out.mtaSts.present:
        r = await request(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=6000)
        out.mtaSts.policyReachable = r.status == 200 and bool(re.search(r"version:\s*STSv1", r.body or "", re.I))
        if out.mtaSts.policyReachable:
            m = re.search(r"mode:\s*(\w+)", r.body, re.I)
            out.mtaSts.mode = (m.group(1).lower() if m else "") or None
            m2 = re.search(r"max_age:\s*(\d+)", r.body, re.I)
            out.mtaSts.maxAge = (int(m2.group(1)) if m2 else 0) or None
    return out


async def check_dnssec(domain, ds_records) -> J:
    has_ds = bool(ds_records)
    validated, dnskey = await asyncio.gather(doh_query(domain, "A", "&do=true"), doh_query(domain, "DNSKEY"))
    has_key = any(a.get("type") == 48 for a in ((dnskey.Answer if dnskey else None) or []))
    if has_ds:
        if validated and validated.Status == 2:
            return J(enabled=False, status="BROKEN", method="DS_BUT_VALIDATION_FAILS")
        return J(enabled=True, status=STATUS.VALID, method="DS_AND_AD" if (validated and validated.AD is True) else "DS_FOUND")
    if has_key:
        return J(enabled=False, status=STATUS.INACTIVE, method="DNSKEY_WITHOUT_DS")
    if not validated and not dnskey:
        return J(enabled=False, status=STATUS.UNKNOWN, method="DOH_UNAVAILABLE")
    return J(enabled=False, status=STATUS.INACTIVE, method="NO_DS_NO_DNSKEY")


async def check_nameservers(domain, ns_list) -> J:
    lst = ns_list[:6]

    async def one(ns, _i):
        ips = (await dq("A", ns)).data
        if not ips:
            return J(ns=ns, ip=None, responds=False, reason="NS adresi çözülemedi")
        if is_private_ip(ips[0]) and not allow_private():
            return J(ns=ns, ip=ips[0], responds=False, reason="özel adres")
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [ips[0]]
        r.timeout = 2.5
        r.lifetime = 2.5
        t0 = time.monotonic()
        soa = await dq("SOA", domain, r)
        ok = bool(isinstance(soa.data, dict) and soa.data.get("nsname"))
        return J(ns=ns, ip=ips[0], responds=ok, serial=soa.data["serial"] if ok else None, ms=int((time.monotonic() - t0) * 1000), reason=None if ok else (soa.code or "yanıt yok"))
    rows = await pool(lst, 4, one)
    res = [r for r in rows if r]
    responding = [r for r in res if r.responds]
    serials = list(dict.fromkeys(r.serial for r in responding))
    nets = [".".join(r.ip.split(".")[:3]) for r in res if r.ip]
    return J(servers=res, respondingCount=len(responding), inconclusive=len(responding) == 0, serialMismatch=len(serials) > 1, serials=serials,
             sameNetwork=len([r for r in res if r.ip]) >= 2 and len(set(nets)) == 1)


_RDAP_BOOT = J(at=0.0, map=None, ok=None)


async def rdap_bases(domain):
    global _RDAP_BOOT
    if _RDAP_BOOT.map is None or time.time() - _RDAP_BOOT.at > 86400:
        st, data = await http_json("https://data.iana.org/rdap/dns.json", 7000)
        if st == 200 and isinstance(data, dict):
            mp = {}
            for svc in data.get("services", []):
                for t in svc[0]:
                    mp[str(t).lower()] = svc[1]
            _RDAP_BOOT = J(at=time.time(), map=mp, ok=True)
        elif _RDAP_BOOT.map is None:
            _RDAP_BOOT = J(at=time.time() - 86400 + 60, map={}, ok=False)
    tld = domain.split(".")[-1]
    return [u.rstrip("/") for u in (_RDAP_BOOT.map.get(tld) or [])]


async def fetch_rdap(domain, errors) -> J:
    bases = await rdap_bases(domain)
    tld = domain.split(".")[-1]
    urls = [f"{b}/domain/{domain}" for b in bases]
    if not bases and tld in ("com", "net"):
        urls.append(f"https://rdap.verisign.com/{tld}/v1/domain/{domain}")
    urls.append(f"https://rdap.org/domain/{domain}")
    not_found = False
    for url in dict.fromkeys(urls):
        st, data = await http_json(url, 8000, {"Accept": "application/rdap+json, application/json", "User-Agent": UA_BROWSER})
        if st == 0:
            errors.append(f"RDAP {url} error:ağ hatası")
            continue
        if st == 200 and isinstance(data, dict) and not data.get("errorCode"):
            return J(data=jj(data), source=url, noRdap=False)
        if st == 404:
            not_found = True
            errors.append(f"RDAP {url} status:404")
            continue
        errors.append(f"RDAP {url} status:{st}")
    return J(data=None, source=None, noRdap=(not bases) and _RDAP_BOOT.ok is True, notFound=not_found)


def extract_registrar(data):
    if not data:
        return None
    if isinstance(data.registrar, str):
        return data.registrar
    if isinstance(data.registrar, dict):
        return str(data.registrar.get("name") or data.registrar.get("organization") or "") or None
    ents = data.entities if isinstance(data.entities, list) else []
    ent = next((e for e in ents if isinstance(e.get("roles"), list) and any(str(r).lower() == "registrar" for r in e["roles"])), None)
    if not ent:
        return None
    ent = jj(ent)
    try:
        va = ent.vcardArray
        v = va[1] if va and len(va) > 1 else None
        if isinstance(v, list):
            fn = next((x for x in v if x and x[0] == "fn"), None)
            if fn and len(fn) > 3 and fn[3]:
                f3 = fn[3]
                return f3 if isinstance(f3, str) else (f3.get("text") if isinstance(f3, dict) and f3.get("text") else (" ".join(f3) if isinstance(f3, list) else None))
            org = next((x for x in v if x and x[0] == "org"), None)
            if org and len(org) > 3 and org[3]:
                return " ".join(org[3]) if isinstance(org[3], list) else str(org[3])
    except Exception:
        pass
    pid = ent.publicIds[0].get("identifier") if (ent.publicIds and isinstance(ent.publicIds, list) and ent.publicIds) else None
    return ent.name or ent.organization or (f"IANA #{pid}" if pid else None) or ent.handle or None


def rdap_date(data, actions):
    if not data or not isinstance(data.events, list):
        return None
    st = [a.lower() for a in actions]
    ev = next((e for e in data.events if str(e.get("eventAction") or "").lower().strip() in st), None)
    return ev.get("eventDate") if ev else None


def rdap_statuses(data):
    if not data or not isinstance(data.status, list):
        return []
    return [x for x in ((s if isinstance(s, str) else (s.get("status") if isinstance(s, dict) and s.get("status") else str(s))) for s in data.status) if x]


def norm_status(s):
    return re.sub(r"[\s_-]", "", str(s).lower())


LOCKABLE_TLDS = {"com", "net", "org", "info", "biz", "io", "co", "app", "dev", "online", "store", "tech", "ai", "xyz", "site", "me", "us", "mobi", "tv", "cc", "club", "shop"}

TAKEOVER_SIGS = [
    J(p="github.io", body=re.compile(r"There isn't a GitHub Pages site here", re.I)), J(p="herokuapp.com", body=re.compile(r"no such app|herokucdn\.com/error-pages", re.I)), J(p="herokudns.com", body=re.compile(r"no such app", re.I)),
    J(p="s3.amazonaws.com", body=re.compile(r"NoSuchBucket|specified bucket does not exist", re.I)), J(p="s3-website", body=re.compile(r"NoSuchBucket|specified bucket does not exist", re.I)),
    J(p="azurewebsites.net", nx=True), J(p="cloudapp.azure.com", nx=True), J(p="trafficmanager.net", nx=True), J(p="blob.core.windows.net", nx=True), J(p="azureedge.net", nx=True),
    J(p="elasticbeanstalk.com", nx=True), J(p="myshopify.com", body=re.compile(r"Sorry, this shop is currently unavailable|Only one step left", re.I)), J(p="ghost.io", body=re.compile(r"The thing you were looking for is no longer here", re.I)),
    J(p="netlify.app", body=re.compile(r"Not Found - Request ID", re.I)), J(p="vercel.app", body=re.compile(r"DEPLOYMENT_NOT_FOUND|deployment could not be found", re.I)), J(p="pages.dev", body=re.compile(r"There is nothing here yet", re.I)),
    J(p="unbouncepages.com", body=re.compile(r"requested URL was not found on this server", re.I)), J(p="surge.sh", body=re.compile(r"project not found", re.I)), J(p="bitbucket.io", body=re.compile(r"Repository not found", re.I)),
    J(p="zendesk.com", body=re.compile(r"Help Center Closed|this help center no longer exists", re.I)), J(p="readme.io", body=re.compile(r"Project doesnt exist", re.I)), J(p="fastly.net", body=re.compile(r"Fastly error: unknown domain", re.I)),
    J(p="tumblr.com", body=re.compile(r"Whatever you were looking for doesn't currently exist", re.I)), J(p="helpscoutdocs.com", body=re.compile(r"No settings were found for this company", re.I)), J(p="cargocollective.com", body=re.compile(r"404 Not Found", re.I)),
    J(p="wordpress.com", body=re.compile(r"Do you want to register", re.I)), J(p="statuspage.io", body=re.compile(r"Page not found|status page is not available", re.I)), J(p="webflow.io", body=re.compile(r"The page you are looking for doesn't exist or has been moved", re.I)),
]
COMMON_SUBS = ["www", "mail", "blog", "shop", "store", "app", "api", "dev", "staging", "test", "cdn", "docs", "status", "support", "help", "portal", "admin", "m", "git", "static", "assets", "img", "media", "beta", "demo", "old", "web", "crm", "panel", "login", "go"]


async def ct_subdomains(domain) -> J:
    try:
        st, data = await http_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain, safe='')}&output=json", 8000)
        if st != 200 or not isinstance(data, list):
            return J(ok=False, names=[])
        names = {}
        for row in data[:5000]:
            for n in str((row or {}).get("name_value") or "").split():
                h = re.sub(r"^\*\.", "", n.lower())
                if h.endswith("." + domain) and "*" not in h and re.fullmatch(r"[a-z0-9.-]+", h):
                    names[h] = 1
        return J(ok=True, names=list(names)[:300])
    except Exception:
        return J(ok=False, names=[])


async def check_takeover(domain, ct_names) -> list:
    hosts = list(dict.fromkeys([domain, *[f"{s}.{domain}" for s in COMMON_SUBS], *ct_names]))[:90]
    found = []

    async def one(h, _i):
        c = await dq("CNAME", h)
        if not c.data:
            return
        target = str(c.data[0]).lower().rstrip(".")
        a4, a6 = await asyncio.gather(dq("A", target), dq("AAAA", target))
        resolves = len(a4.data) + len(a6.data) > 0
        dead = (not resolves) and a4.code == "ENOTFOUND"
        sig = next((s for s in TAKEOVER_SIGS if s.p in target), None)
        row = J(host=h, cname=target, provider=sig.p if sig else None, resolves=resolves, dangling=dead, takeover=False, evidence=None)
        if sig and dead:
            row.takeover = True
            row.evidence = "CNAME hedefi artık mevcut değil"
        elif sig and resolves and sig.body:
            r = await request(f"https://{h}/", timeout=6000, max_bytes=60000, insecure=True)
            r2 = r if r.status else await request(f"http://{h}/", timeout=6000, max_bytes=60000)
            if r2.body and sig.body.search(r2.body):
                row.takeover = True
                row.evidence = "Sağlayıcı 'sahipsiz' hata sayfası döndürüyor"
        found.append(row)
    await pool(hosts, 12, one)
    return found


DNSBLS = [("zen.spamhaus.org", "Spamhaus ZEN", True), ("bl.spamcop.net", "SpamCop", False), ("psbl.surriel.com", "PSBL", False), ("dnsbl-1.uceprotect.net", "UCEProtect-1", False), ("all.s5h.net", "s5h.net", False), ("dnsbl.dronebl.org", "DroneBL", False)]


async def check_dnsbl(ips) -> J:
    lst = list(dict.fromkeys(ip for ip in ips if is_ipv4(ip)))[:4]
    hits = []
    st = J(answered=0, queries=0)

    async def one(pair, _i):
        ip, (zone, name, strong) = pair
        st.queries += 1
        rev = ".".join(reversed(ip.split(".")))
        r = await dq("A", f"{rev}.{zone}")
        if r.data:
            code = r.data[0]
            if re.match(r"^127\.255\.255\.", code):
                return  # sorgu reddedildi
            st.answered += 1
            hits.append(J(ip=ip, list=name, code=code, strong=bool(strong)))
        elif r.code in ("ENOTFOUND", "ENODATA"):
            st.answered += 1
    await pool([(ip, z) for ip in lst for z in DNSBLS], 8, one)
    status = "NOT_CHECKED" if not lst else "NOT_CHECKED" if st.answered == 0 else "LISTED" if hits else "CLEAN"
    return J(status=status, hits=hits, checkedIps=lst, listsQueried=len(DNSBLS), answered=st.answered, strongHit=any(h.strong for h in hits), multiHit=len(set(h.list for h in hits)) >= 2)


async def _ret(v):
    return v


async def _safe(coro, default=None):
    try:
        return await coro
    except Exception:
        return default


async def _wt(coro, ms, default=None, label="İşlem"):
    try:
        return await asyncio.wait_for(coro, ms / 1000)
    except Exception:
        return default


def _num(v):
    """JS 'x || null' benzeri: 0/None/'' -> None"""
    return v if v else None


# =====================================================================
# 2. DOMAIN SCANNER v12
# =====================================================================
async def scan_domain(inp, extra=None) -> J:
    extra = extra or {}
    started = now_ms()
    V = "domain-analyzer-v12.0"
    errors: list = []
    debug = J(input=inp, parsedDomain=None, txtRaw=None, dmarcRaw=None, rdapAttempts=[])
    input_host = parse_domain(inp)
    if not input_host:
        return J(data=None, findings=["finding_domain_invalid_critical"], errors=["domain parse edilemedi"], debug=debug)
    domain = registrable_domain(input_host)
    debug.parsedDomain = domain
    c = Checker()
    info: list = []
    findings: list = []
    if input_host != domain:
        info.append("finding_domain_scanned_root_info")

    dns_records = await collect_dns_records(domain)
    www = await asyncio.gather(dq("A", f"www.{domain}"), dq("CNAME", f"www.{domain}"))
    www_resolves = len(www[0].data) > 0 or len(www[1].data) > 0
    debug.txtRaw = normalize_txt_records(dns_records.txt)
    dns_provider = detect_dns_provider(dns_records.ns)
    has_address = len(dns_records.a) > 0 or len(dns_records.aaaa) > 0 or len(dns_records.cname) > 0 or www_resolves
    if dns_records.allFailed:
        return unavailable_result(assetType="DOMAIN", version=V, startedAt=started, target=domain, finding="finding_domain_dns_unreliable_info", status="UNKNOWN",
            note="DNS sorguları yanıt vermedi (sunucunun ağ erişimi veya DNS sağlayıcısı geçici olarak sorunlu olabilir). Bir süre sonra yeniden tarayın.", specific=J(domain=domain, inputHost=input_host))
    c.add(has_address, 25, "finding_domain_not_resolving_critical", "dns")
    c.add(len(dns_records.ns) > 0, 20, "finding_domain_missing_ns_critical", "dns")
    if len(dns_records.ns) == 1:
        c.add(False, 10, "finding_domain_single_ns_warning", "dns")
    elif len(dns_records.ns) > 1:
        c.add(True, 10, None, "dns")
    c.add(bool(dns_records.soa), 5, None, "dns")
    has_mx = len(dns_records.mx) > 0 and not (len(dns_records.mx) == 1 and re.fullmatch(r"\.?", str(dns_records.mx[0].exchange or "")))
    if not has_mx:
        info.append("finding_domain_missing_mx_warning")
    mail_prov = detect_mail_provider(dns_records.mx)

    errs2: list = []
    ct_task = asyncio.ensure_future(_wt(ct_subdomains(domain), 8000, J(ok=False, names=[])))

    async def take_job():
        ct = await ct_task
        return await _wt(check_takeover(domain, ct.names), 15000, [])

    async def bl_job():
        mx_ips: list = []
        async def one(m, _i):
            r = await dq("A", m.exchange)
            mx_ips.extend(r.data[:1])
        await pool(dns_records.mx[:3], 3, one)
        return await _wt(check_dnsbl([*dns_records.a[:2], *mx_ips]), 12000, J(status="NOT_CHECKED", hits=[], checkedIps=[]))

    (ns_health, rdap, ct_res, mail_policies, dnssec_result, spf, dmarc_txt, dkim_found, take_rows, bl) = await asyncio.gather(
        _wt(check_nameservers(domain, dns_records.ns), 10000, None) if dns_records.ns else _ret(None),
        _wt(fetch_rdap(domain, errs2), 20000, J(data=None, noRdap=False, timeout=True)),
        ct_task,
        _safe(check_mail_policies(domain), None) if has_mx else _ret(None),
        _safe(check_dnssec(domain, dns_records.ds), J(enabled=False, status=STATUS.UNKNOWN, method="ERROR")),
        analyze_spf(domain, dns_records.txt),
        resolve_txt_robust(f"_dmarc.{domain}"),
        _wt(discover_dkim(domain, mail_prov.selectors), 12000, []) if has_mx else _ret([]),
        take_job(), bl_job())
    errors.extend(errs2)
    debug.rdapAttempts = errs2

    if ns_health:
        if ns_health.inconclusive:
            info.append("finding_domain_ns_check_inconclusive_info")
        else:
            failing = [s for s in ns_health.servers if not s.responds]
            c.add(len(failing) == 0, 15, "finding_domain_ns_partial_failure_warning", "dns")
            c.add(not ns_health.serialMismatch, 8, "finding_domain_ns_serial_mismatch_warning", "dns")
        if ns_health.sameNetwork:
            c.add(False, 5, "finding_domain_ns_same_network_warning", "dns")

    # ---- SPF ----
    if spf.record:
        valid = bool(re.match(r"^v=spf1\s+", spf.record, re.I)) and bool(re.search(r"(?:include:|ip4:|ip6:|\ba\b|\bmx\b|[~\-?+]all|redirect=|exists:)", spf.record, re.I))
        spf_status = STATUS.VALID if valid else STATUS.INACTIVE
        if valid:
            findings.append("EMAIL_SPF_VALID")
        c.add(valid, 25, "finding_domain_invalid_spf_warning", "email")
        if valid:
            c.add(spf.count == 1, 8, "finding_domain_spf_multiple_records_critical", "email")
            c.add(not spf.tooManyLookups, 10, "finding_domain_spf_too_many_lookups_critical", "email")
            c.add(spf.all != "+all", 8, "finding_domain_spf_allows_all_critical", "email")
            c.add(spf.all != "?all", 4, "finding_domain_spf_neutral_all_warning", "email")
            c.add(spf.strength != "none", 4, "finding_domain_spf_no_all_warning", "email")
            c.add(not spf.ptr, 2, "finding_domain_spf_ptr_warning", "email")
            c.add(len(spf.brokenIncludes) == 0, 4, "finding_domain_spf_broken_include_warning", "email")
    elif has_mx:
        spf_status = STATUS.INACTIVE
        c.add(False, 25, "finding_domain_missing_spf_warning", "email")
    else:
        spf_status = STATUS.NOT_REQUIRED

    # ---- DMARC ----
    debug.dmarcRaw = normalize_txt_records(dmarc_txt.records)
    dmarc_all = find_dmarc_records(dmarc_txt.records)
    dmarc_record = dmarc_all[0] if dmarc_all else None
    dt = parse_tags(dmarc_record)
    dmarc_policy = None
    dmarc_pct = None
    if dmarc_record:
        dmarc_policy = (dt.get("p") or "").lower() or None
        try:
            dmarc_pct = int(re.match(r"\s*([+-]?\d+)", dt["pct"]).group(1)) if "pct" in dt else 100
        except Exception:
            dmarc_pct = None
        valid_p = dmarc_policy in ("none", "quarantine", "reject")
        dmarc_status = STATUS.VALID if valid_p else STATUS.INACTIVE
        if valid_p:
            findings.append("EMAIL_DMARC_VALID")
        c.add(valid_p, 20, "finding_domain_invalid_dmarc_warning", "email")
        if valid_p:
            c.add(dmarc_policy != "none", 15, "finding_domain_dmarc_policy_none_warning", "email")
            c.add(dmarc_pct is not None and dmarc_pct >= 100, 5, "finding_domain_dmarc_pct_partial_warning", "email")
            sp = (dt.get("sp") or "").lower()
            if sp:
                c.add(not (sp == "none" and dmarc_policy != "none"), 3, "finding_domain_dmarc_subdomain_weak_warning", "email")
            c.add(bool(dt.get("rua")), 3, "finding_domain_dmarc_no_reporting_info", "email")
            c.add(len(dmarc_all) == 1, 3, "finding_domain_dmarc_multiple_records_warning", "email")
    elif has_mx:
        dmarc_status = STATUS.INACTIVE
        c.add(False, 20, "finding_domain_missing_dmarc_warning", "email")
    else:
        dmarc_status = STATUS.NOT_REQUIRED

    # ---- DKIM ----
    dkim_list: list = []
    dkim_status = STATUS.NOT_REQUIRED
    if has_mx:
        dkim_list = dkim_found or []
        if dkim_list:
            dkim_status = STATUS.VALID
            findings.append("EMAIL_DKIM_VALID")
            c.add(True, 20, None, "email")
            weak = [k for k in dkim_list if k.bits and k.bits < 1024]
            mid = [k for k in dkim_list if k.bits and 1024 <= k.bits < 2048]
            c.add(len(weak) == 0, 6, "finding_domain_dkim_weak_key_critical", "email")
            c.add(len(mid) == 0, 3, "finding_domain_dkim_short_key_warning", "email")
            c.add(not any(k.revoked for k in dkim_list), 2, "finding_domain_dkim_revoked_warning", "email")
            c.add(not any(k.testMode for k in dkim_list), 2, "finding_domain_dkim_test_mode_warning", "email")
        else:
            dkim_status = STATUS.SELECTOR_NOT_DISCOVERED
            info.append("finding_domain_dkim_not_discovered_info")
    if mail_policies:
        st = mail_policies.mtaSts
        if not st.present:
            info.append("finding_domain_missing_mta_sts_info")
        else:
            c.add(st.policyReachable is not False, 4, "finding_domain_mta_sts_policy_unreachable_warning", "email")
            if st.mode and st.mode != "enforce":
                info.append("finding_domain_mta_sts_not_enforced_info")
        if not mail_policies.tlsRpt:
            info.append("finding_domain_missing_tls_rpt_info")

    # ---- CAA ----
    caa_tags = []
    for r in (dns_records.caa or []):
        tag = "issue" if r.get("issue") else "issuewild" if r.get("issuewild") else "iodef" if r.get("iodef") else "other"
        caa_tags.append(J(tag=tag, value=r.get("issue") or r.get("issuewild") or r.get("iodef") or ""))
    if not dns_records.caa:
        c.add(False, 10, "finding_domain_missing_caa_warning", "security")
    else:
        c.add(True, 10, None, "security")
        findings.append("EMAIL_CAA_VALID")

    # ---- DNSSEC ----
    dnssec_status = dnssec_result.status
    if dnssec_status == STATUS.VALID:
        findings.append("DNS_SEC_ACTIVE")
        c.add(True, 25, None, "security")
    elif dnssec_status == "BROKEN":
        c.add(False, 25, "finding_domain_dnssec_broken_critical", "security")
    elif dnssec_result.method == "DNSKEY_WITHOUT_DS":
        c.add(False, 25, "finding_domain_dnssec_ds_missing_warning", "security")
    elif dnssec_status == STATUS.INACTIVE:
        c.add(False, 25, "finding_domain_missing_dnssec_warning", "security")
    else:
        info.append("finding_domain_dnssec_unknown_warning")

    # ---- RDAP ----
    registrar = None
    registrar_status = STATUS.UNKNOWN
    created_at = updated_at = expiration = None
    days_until_expiry = None
    transfer_locked = None
    transfer_lock_status = TRANSFER_LOCK_STATUS.UNKNOWN
    statuses: list = []
    domain_age_days = None
    if rdap.data:
        registrar = extract_registrar(rdap.data)
        registrar_status = "FOUND" if registrar else STATUS.UNKNOWN
        if not registrar:
            info.append("finding_domain_registrar_unknown_warning")
        created_at = to_date(rdap_date(rdap.data, ["registration", "registered", "creation", "created"]))
        updated_at = to_date(rdap_date(rdap.data, ["last changed", "last update", "last updated", "updated"]))
        expiration = to_date(rdap_date(rdap.data, ["expiration", "expiry", "expiration date", "registrar expiration", "registry expiry date"]))
        if created_at:
            domain_age_days = days_since(created_at)
        if expiration:
            days_until_expiry = days_until(expiration)
            c.add(days_until_expiry >= 0, 50, "finding_domain_expired_critical", "renewal")
            if days_until_expiry >= 0:
                c.add(days_until_expiry >= 14, 20, "finding_domain_expiring_critical_critical", "renewal")
                c.add(days_until_expiry >= 30 or days_until_expiry < 14, 15, "finding_domain_expiring_soon_warning", "renewal")
                c.add(days_until_expiry >= 60 or days_until_expiry < 30, 15, "finding_domain_expiring_soon_info", "renewal")
        else:
            info.append("finding_domain_missing_expiry_warning")
        statuses = rdap_statuses(rdap.data)
        ns_ = [norm_status(s) for s in statuses]
        if any(re.search(r"serverhold|clienthold", s) for s in ns_):
            c.add(False, 20, "finding_domain_on_hold_critical", "security")
        if any(re.search(r"pendingdelete|redemption", s) for s in ns_):
            c.add(False, 20, "finding_domain_redemption_critical", "security")
        if ns_:
            transfer_locked = any("transferprohibited" in s for s in ns_)
            transfer_lock_status = TRANSFER_LOCK_STATUS.LOCKED if transfer_locked else TRANSFER_LOCK_STATUS.UNLOCKED
            if transfer_locked:
                findings.append("DOMAIN_TRANSFER_LOCKED")
                c.add(True, 15, None, "security")
            elif domain.split(".")[-1] in LOCKABLE_TLDS:
                c.add(False, 15, "finding_domain_transfer_unlocked_warning", "security")
            else:
                info.append("finding_domain_transfer_unlocked_info")
        else:
            info.append("finding_domain_transfer_lock_unknown_warning")
    elif rdap.notFound and not dns_records.ns:
        info.append("finding_domain_not_registered_critical")
    elif rdap.noRdap:
        registrar_status = "NO_RDAP"
        info.append("finding_domain_registry_no_rdap_info")
    else:
        errors.append("RDAP tüm endpointler başarısız")
        registrar_status = "LOOKUP_FAILED"
        info.append("finding_domain_rdap_failed_warning")

    takeovers = [r for r in take_rows if r.takeover]
    dangling = [r for r in take_rows if r.dangling and not r.takeover]
    c.add(len(takeovers) == 0, 25, "finding_domain_takeover_risk_critical", "security")
    if dangling:
        c.add(False, 5, "finding_domain_dangling_cname_warning", "security")

    if bl.status == "LISTED":
        if bl.strongHit or bl.multiHit:
            c.add(False, 20, "finding_domain_ip_blacklisted_critical", "security")
        else:
            c.add(False, 10, "finding_domain_ip_listed_warning", "security")
    elif bl.status == "CLEAN":
        c.add(True, 15, None, "security")

    g = c.group_scores()
    scores = J(dns=g.get("dns"), email=g.get("email"), security=g.get("security"), renewal=g.get("renewal"))
    parts = [v for v in scores.values() if v is not None]
    overall = js_round(sum(parts) / len(parts)) if parts else None
    all_f = sort_findings([*c.findings(), *info, *findings])
    has = lambda code: code in all_f
    if overall is not None:
        if has("finding_domain_expired_critical") or has("finding_domain_redemption_critical"):
            overall = min(overall, 15)
        if has("finding_domain_not_resolving_critical") or has("finding_domain_missing_ns_critical") or has("finding_domain_on_hold_critical"):
            overall = min(overall, 35)
        if has("finding_domain_takeover_risk_critical") or has("finding_domain_dnssec_broken_critical"):
            overall = min(overall, 40)
        if has("finding_domain_ip_blacklisted_critical"):
            overall = min(overall, 60)
        if has("finding_domain_expiring_critical_critical"):
            overall = min(overall, 55)
    if rdap.notFound and not dns_records.ns:
        overall = 0
    scores.overall = overall
    critical = any(classify_finding(f) == "critical" for f in all_f)
    status = "UNKNOWN" if overall is None else "HEALTHY" if (overall >= 80 and not critical) else "WARNING" if overall >= 50 else "CRITICAL"

    soa = dns_records.soa
    soa_out = None
    if soa:
        soa_out = J(nsname=soa.get("nsname") or None, hostmaster=soa.get("hostmaster") or None, serial=_num(soa.get("serial")), refresh=_num(soa.get("refresh")),
                    retry=_num(soa.get("retry")), expire=_num(soa.get("expire")), minttl=_num(soa.get("minttl")),
                    raw=f"{soa.get('nsname') or ''} {soa.get('hostmaster') or ''} {soa.get('serial') or ''}".strip())
    sv = lambda s, ok_: "VALID" if s == STATUS.VALID else "NOT_REQUIRED" if s == STATUS.NOT_REQUIRED else "MISSING"
    specific = J(
        domain=domain, inputHost=input_host,
        dns=J(a=dns_records.a, aaaa=dns_records.aaaa, cname=dns_records.cname, caa=dns_records.caa or [], mx=dns_records.mx, ns=dns_records.ns, wwwResolves=www_resolves,
              soa=soa_out, txt=normalize_txt_records(debug.txtRaw), ds=dns_records.ds or []),
        dnsProvider=dns_provider,
        nameservers=(J(responding=f"{ns_health.respondingCount}/{len(ns_health.servers)}", serialsConsistent=not ns_health.serialMismatch,
                       servers=[f"{s.ns}{' (' + s.ip + ')' if s.ip else ''} {('✔ serial ' + str(s.serial) + ' ' + str(s.ms) + 'ms') if s.responds else ('✘ ' + str(s.reason))}" for s in ns_health.servers]) if ns_health else None),
        dnsSecurity=J(dnssecEnabled=bool(dnssec_result.enabled), dnssecStatus=dnssec_status, dnssecMethod=dnssec_result.method or None, transferLocked=transfer_locked, transferLockStatus=transfer_lock_status, caaRecords=caa_tags),
        emailSecurity=J(
            hasMx=bool(has_mx), mxRecords=dns_records.mx or [], mailProvider=mail_prov.provider,
            spf=spf.record, spfStatus=sv(spf_status, 0), spfStatusDetailed=spf_status, spfValid=spf_status == STATUS.VALID,
            spfDetails=J(recordCount=spf.count, dnsLookups=spf.lookups, lookupLimit=10, all=spf.all, strength=spf.strength, includes=spf.includes, brokenIncludes=spf.brokenIncludes, usesPtr=spf.ptr),
            dmarc=dmarc_record, dmarcStatus=sv(dmarc_status, 0), dmarcStatusDetailed=dmarc_status, dmarcPolicy=dmarc_policy, dmarcPct=dmarc_pct, dmarcValid=dmarc_status == STATUS.VALID,
            dmarcDetails=(J(subdomainPolicy=dt.get("sp") or None, rua=dt.get("rua") or None, ruf=dt.get("ruf") or None, adkim=dt.get("adkim") or "r", aspf=dt.get("aspf") or "r") if dmarc_record else None),
            dkim=len(dkim_list) > 0, dkimRecord=dkim_list[0].record if dkim_list else None,
            dkimStatus="VALID" if dkim_list else "SELECTOR_NOT_DISCOVERED" if has_mx else "NOT_REQUIRED", dkimStatusDetailed=dkim_status,
            dkimSelector=dkim_list[0].selector if dkim_list else None, dkimValid=len(dkim_list) > 0,
            dkimSelectors=[f"{k.selector} ({k.keyType}{' ' + str(k.bits) + ' bit' if k.bits else ''}{', iptal' if k.revoked else ''}{', test modu' if k.testMode else ''})" for k in dkim_list],
            mtaSts=mail_policies.mtaSts if mail_policies else None, tlsRpt=mail_policies.tlsRpt if mail_policies else None, bimi=mail_policies.bimi if mail_policies else None),
        registration=J(registrar=registrar, registrarStatus=registrar_status, createdAt=iso(created_at), updatedAt=iso(updated_at), expiresAt=iso(expiration), remainingDays=days_until_expiry,
                       domainAgeDays=domain_age_days, transferLocked=transfer_locked, transferLockStatus=transfer_lock_status, statuses=statuses, source=rdap.source or None, target=domain),
        subdomains=J(certificateTransparency="ok" if ct_res.ok else "failed", discovered=len(ct_res.names), sample=ct_res.names[:25], cnameChecked=len(take_rows),
                     takeoverRisks=[f"{t.host} → {t.cname} ({t.evidence})" for t in takeovers], danglingCnames=[f"{t.host} → {t.cname}" for t in dangling]),
        scores=scores,
        threatAnalysis=J(blacklistStatus=bl.status, blacklistHits=[f"{h.ip} → {h.list}" for h in bl.hits], blacklistCheckedIps=bl.checkedIps, subdomainTakeoverRisk=len(takeovers) > 0,
                         takeoverEvidence=f"{takeovers[0].host} → {takeovers[0].cname}" if takeovers else None, typosquattingRisk="BRAND taramasında kontrol edilir", target=domain),
        debug=debug)
    unknown_count = len([x for x in (not rdap.data, dnssec_status == STATUS.UNKNOWN, bl.status == "NOT_CHECKED", (not ns_health) or ns_health.inconclusive) if x])
    common = J(analyzerVersion=V, executionTimeMs=now_ms() - started, findings=all_f, scannedAt=iso(datetime.now(timezone.utc)), score=overall, status=status, target=domain)
    return J(data=J(assetType="DOMAIN", commonAnalysis=common, specificAnalysis=specific, analysisMeta=J(scannerVersion=V, analyzer="domain"), target=domain, dnsProvider=dns_provider,
                    registrar=registrar, remainingDays=days_until_expiry, transferLocked=transfer_locked),
             findings=all_f, errors=errors, statusHint=status, confidence=clamp(100 - unknown_count * 8 - (5 if errors else 0)))


# =====================================================================
# IP / PLATFORM
# =====================================================================
async def ip_info(ip) -> J:
    q = urllib.parse.quote(str(ip), safe="")
    st, d = await http_json(f"https://ipwho.is/{q}", 6000)
    if isinstance(d, dict) and d.get("success"):
        conn = d.get("connection") or {}
        return J(ip=ip, country=d.get("country") or None, countryCode=d.get("country_code") or None, city=d.get("city") or None, region=d.get("region") or None,
                 asn=conn.get("asn") or None, org=conn.get("org") or None, isp=conn.get("isp") or None)
    st, d = await http_json(f"https://ipapi.co/{q}/json/", 6000)
    if isinstance(d, dict) and not d.get("error") and d.get("ip"):
        asn = d.get("asn")
        try:
            asn_n = int(re.sub(r"\D", "", str(asn))) if asn else None
        except ValueError:
            asn_n = None
        return J(ip=ip, country=d.get("country_name") or None, countryCode=d.get("country_code") or None, city=d.get("city") or None, region=d.get("region") or None,
                 asn=asn_n, org=d.get("org") or None, isp=d.get("org") or None)
    return J(ip=ip, country=None, countryCode=None, city=None, region=None, asn=None, org=None, isp=None)


DDOS_CAPABLE = ["Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Sucuri", "Imperva", "DDoS-Guard", "Azure Front Door", "Vercel", "Netlify", "Google Cloud CDN", "Bunny CDN", "KeyCDN", "StackPath"]


def detect_platforms(h, geo) -> list:
    s = lambda k: str(h.get(k) or "").lower()
    out = []
    org = str((geo.org or geo.isp) if geo else "").lower()
    if h.get("cf-ray") or "cloudflare" in s("server") or "cloudflare" in org: out.append("Cloudflare")
    if h.get("x-amz-cf-id") or "cloudfront" in s("via"): out.append("AWS CloudFront")
    if "akamai" in s("server") or h.get("x-akamai-transformed") or "akamai" in org: out.append("Akamai")
    if h.get("x-fastly-request-id") or (h.get("x-served-by") and re.search(r"cache-", s("x-served-by"))) or "fastly" in org: out.append("Fastly")
    if h.get("x-vercel-id") or s("server") == "vercel": out.append("Vercel")
    if h.get("x-nf-request-id") or "netlify" in s("server"): out.append("Netlify")
    if h.get("x-github-request-id"): out.append("GitHub Pages")
    if h.get("x-sucuri-id") or h.get("x-sucuri-cache"): out.append("Sucuri")
    if h.get("x-iinfo") or h.get("x-cdn") == "Imperva": out.append("Imperva")
    if "ddos-guard" in s("server"): out.append("DDoS-Guard")
    if h.get("x-azure-ref"): out.append("Azure Front Door")
    if h.get("rndr-id") or h.get("x-render-origin-server"): out.append("Render")
    if h.get("fly-request-id"): out.append("Fly.io")
    if h.get("x-bunny-cache") or "bunnycdn" in s("server"): out.append("Bunny CDN")
    if h.get("x-wix-request-id"): out.append("Wix")
    if h.get("x-shopify-stage") or h.get("x-shopid"): out.append("Shopify")
    if "wp engine" in s("x-powered-by") or h.get("x-wpe-request-id"): out.append("WP Engine")
    if h.get("x-kinsta-cache"): out.append("Kinsta")
    if "litespeed" in s("server") and h.get("x-litespeed-cache"): out.append("LiteSpeed Cache")
    if h.get("x-heroku-queue-wait-time") or "vegur" in s("via"): out.append("Heroku")
    return list(dict.fromkeys(out))


_CLOUD_MAP = [("amazon", "AWS"), ("google", "Google Cloud"), ("microsoft", "Microsoft Azure"), ("digitalocean", "DigitalOcean"), ("hetzner", "Hetzner"), ("ovh", "OVH"), ("linode", "Linode/Akamai"), ("vultr", "Vultr"), ("oracle", "Oracle Cloud"),
    ("cloudflare", "Cloudflare"), ("alibaba", "Alibaba Cloud"), ("contabo", "Contabo"), ("scaleway", "Scaleway"), ("hostinger", "Hostinger"), ("godaddy", "GoDaddy"), ("natro", "Natro"), ("turkcell", "Turkcell"), ("turk telekom", "Türk Telekom"), ("türk telekom", "Türk Telekom"), ("vodafone", "Vodafone"), ("netinternet", "Netinternet"), ("veridyen", "Veridyen"), ("radore", "Radore"), ("guzel hosting", "Güzel Hosting"), ("fastly", "Fastly"), ("akamai", "Akamai")]


def cloud_family(org):
    o = str(org or "").lower()
    for k, v in _CLOUD_MAP:
        if k in o:
            return v
    return None


# =====================================================================
# TLS
# =====================================================================
SIG_OIDS = {"1.2.840.113549.1.1.2": "md2WithRSA", "1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA", "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "RSASSA-PSS", "1.2.840.10045.4.1": "sha1WithECDSA", "1.2.840.10045.4.3.2": "sha256WithECDSA", "1.2.840.10045.4.3.3": "sha384WithECDSA",
    "1.2.840.10045.4.3.4": "sha512WithECDSA", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}


def der_signature_algorithm(der: bytes):
    try:
        cert = x509.load_der_x509_certificate(der)
        o = cert.signature_algorithm_oid.dotted_string
        return J(oid=o, name=SIG_OIDS.get(o, o))
    except Exception:
        return None


_VERIFY_CODES = {2: "UNABLE_TO_GET_ISSUER_CERT", 7: "CERT_SIGNATURE_FAILURE", 9: "CERT_NOT_YET_VALID", 10: "CERT_HAS_EXPIRED", 18: "DEPTH_ZERO_SELF_SIGNED_CERT", 19: "SELF_SIGNED_CERT_IN_CHAIN",
    20: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", 21: "UNABLE_TO_VERIFY_LEAF_SIGNATURE", 23: "CERT_REVOKED", 24: "INVALID_CA", 26: "INVALID_PURPOSE", 27: "CERT_UNTRUSTED", 62: "ERR_TLS_CERT_ALTNAME_INVALID", 64: "ERR_TLS_CERT_ALTNAME_INVALID"}


def _peer_chain(ssl_obj) -> list:
    certs = None
    for getter in (lambda: ssl_obj.get_unverified_chain(), lambda: ssl_obj._sslobj.get_unverified_chain()):
        try:
            certs = getter()
            if certs:
                break
        except Exception:
            continue
    out = []
    for c in certs or []:
        try:
            out.append(c if isinstance(c, (bytes, bytearray)) else c.public_bytes(ssl._ssl.ENCODING_DER))  # type: ignore[attr-defined]
        except Exception:
            pass
    return out


def _cert_dt(cert, which):
    try:
        return getattr(cert, f"not_valid_{which}_utc")
    except AttributeError:
        return getattr(cert, f"not_valid_{which}").replace(tzinfo=timezone.utc)


def _name_attr(name, oid):
    try:
        a = name.get_attributes_for_oid(oid)
        return str(a[0].value) if a else None
    except Exception:
        return None


def _key_info(cert):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "rsa", pk.key_size, None
    if isinstance(pk, ec.EllipticCurvePublicKey):
        nm = pk.curve.name
        return "ec", pk.curve.key_size, {"secp256r1": "prime256v1"}.get(nm, nm)
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "ed25519", 256, None
    if isinstance(pk, ed448.Ed448PublicKey):
        return "ed448", 456, None
    if isinstance(pk, dsa.DSAPublicKey):
        return "dsa", pk.key_size, None
    return None, None, None


def _fingerprint256(der: bytes) -> str:
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


def _san(cert) -> tuple[list, list]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return list(ext.get_values_for_type(x509.DNSName)), [str(i) for i in ext.get_values_for_type(x509.IPAddress)]
    except Exception:
        return [], []


def cert_matches_host(cert, host: str) -> bool:
    host = host.lower().rstrip(".")
    dns_names, ips = _san(cert)
    if is_ip(host):
        try:
            return any(ipaddress.ip_address(i) == ipaddress.ip_address(host) for i in ips)
        except Exception:
            return False
    names = [n.lower().rstrip(".") for n in dns_names]
    if not names:
        cn = _name_attr(cert.subject, x509.NameOID.COMMON_NAME)
        names = [cn.lower()] if cn else []
    hl = host.split(".")
    for n in names:
        if n == host:
            return True
        nl = n.split(".")
        if nl[0] == "*" and len(nl) >= 3 and len(nl) == len(hl) and nl[1:] == hl[1:]:
            return True
    return False


async def _tls_connect(host, port, ctx, timeout_s, sni=True):
    fam, ip = (await safe_addrinfo(host, port))[0]
    sn = None if is_ip(host) or not sni else host
    return await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sn, ssl_handshake_timeout=timeout_s), timeout_s + 1), ip


async def get_tls_details(host, port=443, timeout=7000) -> J:
    if blocked_host(host):
        raise private_error()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    (reader, writer), ip = await _tls_connect(host, port, ctx, timeout / 1000)
    try:
        so = writer.get_extra_info("ssl_object")
        der = so.getpeercert(True)
        if not der:
            raise RuntimeError("Sertifika alınamadı")
        chain_ders = _peer_chain(so) or [der]
        if chain_ders[0] != der:
            chain_ders = [der] + [d for d in chain_ders if d != der]
        proto = so.version()
        ci = so.cipher()
        alpn = so.selected_alpn_protocol()
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:
            pass
    chain = []
    seen = set()
    for d in chain_ders:
        fp = _fingerprint256(d)
        if fp in seen:
            continue
        seen.add(fp)
        try:
            cc = x509.load_der_x509_certificate(d)
        except Exception:
            continue
        kt, kb, _cv = _key_info(cc)
        subj_cn = _name_attr(cc.subject, x509.NameOID.COMMON_NAME)
        subj_o = _name_attr(cc.subject, x509.NameOID.ORGANIZATION_NAME)
        iss_cn = _name_attr(cc.issuer, x509.NameOID.COMMON_NAME)
        iss_o = _name_attr(cc.issuer, x509.NameOID.ORGANIZATION_NAME)
        chain.append(J(subject=subj_cn or subj_o or "?", issuer=iss_cn or iss_o or "?", validTo=_cert_dt(cc, "after"), validFrom=_cert_dt(cc, "before"), bits=kb,
                       selfIssued=(subj_cn == iss_cn and subj_o == iss_o), raw=d, fingerprint256=fp, obj=cc))
    # Doğrulamalı ikinci el sıkışma: güven zinciri / ana makine adı sonucu (Node'daki socket.authorized karşılığı)
    authorized, auth_error = False, None
    try:
        vctx = ssl.create_default_context()
        vctx.check_hostname = not is_ip(host)
        (r2, w2), _ip2 = await _tls_connect(host, port, vctx, timeout / 1000)
        authorized = True
        try:
            w2.close()
        except Exception:
            pass
    except ssl.SSLCertVerificationError as e:
        auth_error = _VERIFY_CODES.get(getattr(e, "verify_code", None), (getattr(e, "verify_message", None) or "CERT_ERROR").upper().replace(" ", "_"))
    except Exception:
        pass
    return J(cert=chain[0] if chain else None, chain=chain, protocol=proto, cipher=J(name=ci[0], version=ci[1]) if ci else None, authorized=authorized, authError=auth_error,
             alpn=alpn, ocspStapled=None, ip=ip, leafDer=der)


async def tls_alpn(host, timeout=5000):
    if blocked_host(host):
        return None
    t0 = time.monotonic()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        (reader, writer), _ip = await _tls_connect(host, 443, ctx, timeout / 1000)
        so = writer.get_extra_info("ssl_object")
        r = J(alpn=so.selected_alpn_protocol(), tlsVersion=so.version(), handshakeMs=int((time.monotonic() - t0) * 1000))
        writer.close()
        return r
    except Exception:
        return None


_TLS_VERS = [("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")]


async def probe_tls_versions(host, port=443) -> J:
    if blocked_host(host):
        return J({v: None for v, _ in _TLS_VERS})

    async def one(label, attr):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ver = getattr(ssl.TLSVersion, attr)
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            if label != "TLSv1.3":
                ctx.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            return None  # bu istemci derlemesi sürümü desteklemiyor: test edilemedi
        try:
            (r, w), _ip = await _tls_connect(host, port, ctx, 5.0)
            w.close()
            return True
        except ssl.SSLError as e:
            m = str(e)
            return None if re.search(r"NO_PROTOCOLS_AVAILABLE|no protocols available|unsupported|not supported", m, re.I) else False
        except (OSError, asyncio.TimeoutError):
            return None
        except Exception:
            return None
    res = await asyncio.gather(*(one(l, a) for l, a in _TLS_VERS))
    return J({v: res[i] for i, (v, _) in enumerate(_TLS_VERS)})


def parse_host_port(inp, def_port) -> J:
    s = str(inp).strip()
    try:
        u = urllib.parse.urlsplit(s if re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I) else "https://" + s)
        h = u.hostname
        if not h:
            raise ValueError("host yok")
        port = u.port
        return J(host=normalize_host(h), port=port if port else def_port)
    except Exception:
        return J(host=parse_host_loose(inp), port=def_port)


# =====================================================================
# 3. SSL SCANNER v12
# =====================================================================
SSL_PORTS = {443, 465, 636, 853, 993, 995, 8443, 9443}


async def scan_ssl_certificate(inp, extra=None) -> J:
    started = now_ms()
    V = "ssl-analyzer-v12.0"
    errors: list = []
    c = Checker()
    hp = parse_host_port(inp, 443)
    host = hp.host if (hp.host and (is_ip(hp.host) or "." in hp.host)) else None
    if host and hp.port not in SSL_PORTS:
        return J(data=None, findings=["finding_ssl_invalid_target_critical"], errors=["Desteklenmeyen SSL portu (izin verilenler: " + ", ".join(str(p) for p in sorted(SSL_PORTS)) + ")"], statusHint="INVALID")
    if not host:
        return J(data=None, findings=["finding_ssl_invalid_target_critical"], errors=["geçersiz hedef"], statusHint="INVALID")
    try:
        t = await get_tls_details(host, hp.port)
    except Exception as e:
        ni = classify_net_error(e)
        errors.append(str(e) or e.__class__.__name__)
        code = {"dns": "finding_ssl_dns_failure_critical", "refused": "finding_ssl_port_closed_critical", "timeout": "finding_ssl_timeout_critical", "reset": "finding_ssl_handshake_failed_critical",
                "tls": "finding_ssl_handshake_failed_critical"}.get(ni.kind, "finding_ssl_check_failed_critical")
        return build_result(assetType="SSL_CERTIFICATE", version=V, startedAt=started, target=host, findings=[code], score=None, status="ERROR", errors=errors,
                            specific=J(domain=host, port=hp.port, cert=J(valid=False, error=ni.message, errorKind=ni.kind), note="TLS bağlantısı kurulamadı; sertifika değerlendirilemedi."))
    leaf = t.cert
    x = leaf.obj
    leaf_der = t.leafDer
    valid_from = leaf.validFrom
    valid_to = leaf.validTo
    now = datetime.now(timezone.utc)
    days_remaining = math.floor((valid_to - now).total_seconds() / 86400)
    validity_days = js_round((valid_to - valid_from).total_seconds() / 86400)
    dns_names, ip_sans = _san(x)
    san_list = [*dns_names, *ip_sans] if (dns_names or ip_sans) else [v for v in [_name_attr(x.subject, x509.NameOID.COMMON_NAME)] if v]
    issuer_o = _name_attr(x.issuer, x509.NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(x.issuer, x509.NameOID.COMMON_NAME)
    subj_cn = _name_attr(x.subject, x509.NameOID.COMMON_NAME)
    subj_o = _name_attr(x.subject, x509.NameOID.ORGANIZATION_NAME)
    issuer_org = issuer_o or issuer_cn or "Unknown"
    self_signed = (subj_cn == issuer_cn and subj_o == issuer_o)
    is_wildcard = any(d.startswith("*.") for d in san_list)
    key_type, key_bits, curve = _key_info(x)
    sig = der_signature_algorithm(leaf_der)
    sig_name = sig.name if sig else None
    host_match = None
    www_covered = None
    try:
        host_match = cert_matches_host(x, host)
        if not is_ip(host):
            alt = re.sub(r"^www\.", "", host) if host.startswith("www.") else "www." + host
            www_covered = cert_matches_host(x, alt)
    except Exception:
        pass
    auth_err = t.authError
    trusted_chain = t.authorized or auth_err == "ERR_TLS_CERT_ALTNAME_INVALID"
    chain_incomplete = auth_err in ("UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_GET_ISSUER_CERT") and not self_signed
    untrusted = bool((not t.authorized) and auth_err and not chain_incomplete and auth_err not in ("CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "ERR_TLS_CERT_ALTNAME_INVALID") and not self_signed)
    chain_expired = any(ch.validTo < now for ch in t.chain[1:])
    protos = await _wt(probe_tls_versions(host, hp.port), 9000, J())
    old_tls = [v for v in ("TLSv1", "TLSv1.1") if protos.get(v) is True]
    https_probe = await http_probe(f"https://{host}{'' if hp.port == 443 else ':' + str(hp.port)}", timeout=8000, maxRedirects=0, noUaFallback=True, read_body=False)
    hsts_raw = (https_probe.headers or {}).get("strict-transport-security")
    if hsts_raw:
        mm = re.search(r"max-age=(\d+)", hsts_raw, re.I)
        hsts = J(enabled=True, maxAge=int(mm.group(1)) if mm else 0, includeSubDomains=bool(re.search(r"includesubdomains", hsts_raw, re.I)), preload=bool(re.search(r"preload", hsts_raw, re.I)))
    else:
        hsts = J(enabled=False, maxAge=0, includeSubDomains=False, preload=False)
    serial = format(x.serial_number, "X")
    if len(serial) % 2:
        serial = "0" + serial
    cert_info = J(valid=days_remaining >= 0 and valid_from <= now and not self_signed and (host_match is not False) and not untrusted,
                  validFrom=iso(valid_from), validTo=iso(valid_to), daysRemaining=days_remaining, validityPeriodDays=validity_days,
                  issuer=f"{issuer_o or ''} {issuer_cn or ''}".strip(), issuerOrg=issuer_org, issuerCN=issuer_cn or None, subject=subj_cn or host, subjectO=subj_o or None, subjectAltNames=san_list,
                  serialNumber=serial, fingerprint=leaf.fingerprint256, keyType=key_type, keySize=key_bits, curve=curve, signatureAlgorithm=sig_name, isWildcard=is_wildcard, isSelfSigned=self_signed,
                  hostnameMatches=host_match, coversWwwVariant=www_covered)
    if re.search(r"extended validation|\bEV\b", str(issuer_cn or ""), re.I):
        cert_info.isEV = True
    tls_info = J(protocol=t.protocol, cipherName=t.cipher.name if t.cipher else None, cipherVersion=t.cipher.version if t.cipher else None, alpn=t.alpn,
                 supportsTls13=protos.get("TLSv1.3") is True or t.protocol == "TLSv1.3", supportsTls12=protos.get("TLSv1.2") is True or t.protocol in ("TLSv1.2", "TLSv1.3"),
                 legacyProtocolsEnabled=old_tls, protocolSupport=J({k: ("destekleniyor" if v is True else "kapalı" if v is False else "test edilemedi") for k, v in protos.items()}),
                 ocspStapling=t.ocspStapled, chainLength=len(t.chain), chain=[f"{ch.subject} ← {ch.issuer} (bitiş {ch.validTo.strftime('%Y-%m-%d')})" for ch in t.chain],
                 chainComplete=not chain_incomplete, trusted=bool(trusted_chain) and not untrusted, trustError=auth_err, remoteIp=t.ip)
    c.add(days_remaining >= 0, 30, "finding_ssl_expired_critical", "validity")
    c.add(valid_from <= now, 10, "finding_ssl_not_yet_valid_critical", "validity")
    c.add(host_match is not False, 25, "finding_ssl_hostname_mismatch_critical", "validity")
    c.add(not self_signed, 25, "finding_ssl_self_signed_critical", "validity")
    c.add(not untrusted, 25, "finding_ssl_untrusted_critical", "chainTrust")
    c.add(not chain_incomplete, 15, "finding_ssl_chain_incomplete_warning", "chainTrust")
    c.add(not chain_expired, 10, "finding_ssl_chain_expired_critical", "chainTrust")
    if days_remaining >= 0:
        c.add(days_remaining >= 7, 50, "finding_ssl_expiring_soon_critical", "renewal")
        c.add(days_remaining >= 21, 30, "finding_ssl_expiring_soon_warning", "renewal")
        c.add(days_remaining >= 30, 20, None, "renewal")
    else:
        c.add(False, 100, None, "renewal")
    if key_bits:
        c.add((key_bits >= 2048) if key_type == "rsa" else (key_bits >= 224) if key_type == "ec" else True, 20, "finding_ssl_weak_key_critical", "security")
    if sig_name:
        c.add(not re.search(r"md2|md5|sha1", sig_name, re.I), 20, "finding_ssl_weak_signature_critical", "security")
    c.add(len(old_tls) == 0, 20, "finding_ssl_tls_old_version_warning", "security")
    c.add(tls_info.supportsTls12 or tls_info.supportsTls13, 10, "finding_ssl_tls12_unsupported_critical", "security")
    c.add(tls_info.supportsTls13, 5, "finding_ssl_no_tls13_info", "security")
    c.add(not re.search(r"RC4|3DES|NULL|EXPORT|MD5|DES-CBC", str(t.cipher.name if t.cipher else ""), re.I), 10, "finding_ssl_weak_cipher_critical", "security")
    c.add(hsts.enabled, 40, "finding_ssl_hsts_missing_warning", "hsts")
    if hsts.enabled:
        c.add(hsts.maxAge >= 15552000, 30, "finding_ssl_hsts_short_warning", "hsts")
        c.add(hsts.includeSubDomains, 15, "finding_ssl_hsts_no_subdomains_info", "hsts")
        c.add(hsts.preload, 15, None, "hsts")
    if https_probe.status == 0 and https_probe.errorInfo and https_probe.errorInfo.kind != "tls":
        errors.append("HTTPS isteği: " + str(https_probe.error))
    extra_f = []
    if is_wildcard:
        extra_f.append("finding_ssl_wildcard_info")
    if www_covered is False:
        extra_f.append("finding_ssl_www_not_covered_warning")
    if validity_days > 398 and not self_signed:
        extra_f.append("finding_ssl_long_validity_info")
    if t.ocspStapled is False:
        extra_f.append("finding_ssl_no_ocsp_stapling_info")
    g = c.group_scores()
    scores = J(validity=g.get("validity"), renewal=g.get("renewal"), security=g.get("security"), chainTrust=g.get("chainTrust"), hsts=g.get("hsts"))
    overall = c.score()
    all_f = sort_findings([*c.findings(), *extra_f])
    if "finding_ssl_expired_critical" in all_f:
        overall = min(overall, 10)
    if any(re.search(r"hostname_mismatch|self_signed|untrusted|chain_expired|not_yet_valid", f) for f in all_f):
        overall = min(overall, 30)
    if any(re.search(r"weak_key|weak_signature|weak_cipher", f) for f in all_f):
        overall = min(overall, 55)
    if "finding_ssl_expiring_soon_critical" in all_f:
        overall = min(overall, 50)
    hint = ("EXPIRED" if days_remaining < 0 else "CRITICAL" if not cert_info.valid else "EXPIRING_SOON" if days_remaining < 21 else "ACTIVE" if overall >= 80 else "WARNING" if overall >= 50 else "CRITICAL")
    specific = J(domain=host, port=hp.port, cert=cert_info, tls=tls_info,
                 httpSecurity=J(httpOk=https_probe.ok, status=https_probe.status, serverHeader=(https_probe.headers or {}).get("server"), hstsEnabled=hsts.enabled, hstsMaxAge=hsts.maxAge,
                                hstsIncludeSubdomains=hsts.includeSubDomains, hstsPreload=hsts.preload), scores=J({**scores, "overall": overall}))
    common = J(analyzerVersion=V, executionTimeMs=now_ms() - started, findings=all_f, scannedAt=iso(datetime.now(timezone.utc)), score=overall, status=status_from_score(overall), target=host)
    return J(data=J(assetType="SSL_CERTIFICATE", commonAnalysis=common, specificAnalysis=specific, analysisMeta=J(scannerVersion=V, analyzer="ssl")), findings=all_f, errors=errors, statusHint=hint,
             confidence=clamp(100 - len([v for v in protos.values() if v is None]) * 4))


async def reverse_dns(ip):
    try:
        name = dns.reversename.from_address(ip)
        r = await dq("PTR", str(name))
        return [str(x).rstrip(".") for x in (r.data or [])] or None
    except Exception:
        return None


# =====================================================================
# HOSTING v3
# =====================================================================
async def scan_hosting(inp) -> J:
    started = now_ms()
    V = "hosting-analyzer-v3.0"
    host = parse_target_host(inp)
    if not host:
        return build_result(assetType="HOSTING", version=V, startedAt=started, target=str(inp or ""), findings=["finding_hosting_invalid_target_critical"], score=0, status="ERROR", specific=J())
    ips = await resolve_ips(host)
    c = Checker()
    resolves = len(ips.v4) + len(ips.v6) > 0
    if not resolves and ips.code and not dns_missing(ips.code):
        return unavailable_result(assetType="HOSTING", version=V, startedAt=started, target=host, finding="finding_hosting_dns_unreliable_info", status="UNKNOWN", note="DNS sorguları yanıt vermedi; sonuç belirlenemedi.", specific=J(host=host))
    c.add(resolves, 20, "finding_hosting_not_resolving_critical", "erisim")
    main = J(ok=False, status=0, headers={}, responseTimeMs=None, ttfb=None, redirects=0)
    geo = geo2 = rdns = tlsi = http_plain = tcp = None
    samples: list = []
    if resolves:
        first = ips.v4[0] if ips.v4 else ips.v6[0]
        main, geo, tlsi, http_plain, tcp = await asyncio.gather(
            http_probe(f"https://{host}", timeout=10000, maxRedirects=4), ip_info(first), tls_alpn(host),
            _ret(None) if is_ip(host) else http_probe(f"http://{host}", timeout=7000, maxRedirects=0, noUaFallback=True, read_body=False), tcp_port_check(first, 443, 4000))
        rdns = await reverse_dns(first)
        if len(ips.v4) + len(ips.v6) > 1:
            geo2 = await ip_info(ips.v4[1] if len(ips.v4) > 1 else ips.v6[0] if not ips.v4 else ips.v6[0])
        if main.status > 0:
            for _ in range(2):
                r = await request(f"https://{host}", timeout=8000, read_body=False, insecure=True)
                if r.status:
                    samples.append(r.ttfb)
            if main.ttfb is not None:
                samples.append(main.ttfb)
    platforms = detect_platforms(main.headers or {}, geo)
    ddos = any(p in DDOS_CAPABLE for p in platforms)
    family = cloud_family((geo.org or geo.isp) if geo else None)
    prot = detect_bot_protection(main) if main.status else None
    reachable = main.status > 0 and (main.status < 500 or bool(prot))
    c.add(reachable, 20, net_error_finding("hosting", main) if main.status == 0 else "finding_hosting_server_error_critical", "erisim")
    c.add(bool(tlsi), 15, "finding_hosting_no_https_critical", "guvenlik")
    if tlsi:
        c.add(tlsi.tlsVersion in ("TLSv1.2", "TLSv1.3"), 5, "finding_hosting_tls_old_warning", "guvenlik")
    if http_plain and http_plain.status > 0:
        c.add(300 <= http_plain.status < 400 and bool(re.match(r"^https:", str((http_plain.headers or {}).get("location") or ""), re.I)), 6, "finding_hosting_no_https_redirect_warning", "guvenlik")
    c.add(ddos, 8, "finding_hosting_no_cdn_waf_warning", "dayaniklilik")
    c.add(len(ips.v6) > 0, 3, "finding_hosting_no_ipv6_info", "dayaniklilik")
    c.add(len(ips.v4) + len(ips.v6) > 1 or ddos, 4, "finding_hosting_single_ip_info", "dayaniklilik")
    ttfb_avg = avg(samples) if samples else None
    if ttfb_avg is not None:
        c.add(ttfb_avg < 1500, 8, "finding_hosting_slow_response_warning", "performans")
        c.add(ttfb_avg < 800, 6, None, "performans")
    if tcp:
        c.add((tcp.latencyMs < 500) if tcp.open else False, 4, "finding_hosting_slow_connect_warning" if tcp.open else None, "performans")
    findings = c.findings()
    if prot:
        findings.append("finding_web_bot_protection_info")
    if not (geo and geo.org) and not (geo and geo.country) and resolves:
        findings.append("finding_hosting_geo_unknown_info")
    score = c.score()
    down = (not resolves) or (not reachable)
    h = main.headers or {}
    specific = J(
        host=host, network=J(ipv4=ips.v4, ipv6=ips.v6, reverseDns=(rdns[0] if rdns else None)),
        provider=(J(name=geo.org or geo.isp, family=family, asn=geo.asn, country=geo.country, countryCode=geo.countryCode, city=geo.city, region=geo.region) if geo else None),
        secondaryIp=(J(ip=geo2.ip, org=geo2.org, country=geo2.country) if geo2 else None),
        platform=platforms, ddosProtection=ddos,
        http=J(status=main.status, ttfbMs=ttfb_avg, responseTimeMs=main.responseTimeMs, server=h.get("server") or None, poweredBy=h.get("x-powered-by") or None,
               protocol=(tlsi.alpn if tlsi else None) or None, tlsVersion=(tlsi.tlsVersion if tlsi else None) or None, tlsHandshakeMs=(tlsi.handshakeMs if tlsi else None),
               tcpConnectMs=tcp.latencyMs if (tcp and tcp.open) else None, redirects=main.redirects,
               httpToHttps=((300 <= http_plain.status < 400 and bool(re.match(r"^https:", str((http_plain.headers or {}).get("location") or ""), re.I))) if (http_plain and http_plain.status) else None)),
        scores=c.group_scores(), checks=c.summary())
    if prot:
        specific.botProtection = J(provider=prot)
    return build_result(assetType="HOSTING", version=V, startedAt=started, target=host, findings=findings, score=score, status="DOWN" if down else None, specific=specific, errors=[main.error] if main.error else [])


# =====================================================================
# SUNUCU (port + banner) v3
# =====================================================================
SERVER_PORTS = [(21, "FTP", "warn"), (22, "SSH", None), (23, "Telnet", "crit"), (25, "SMTP", None), (53, "DNS", None), (80, "HTTP", None), (110, "POP3", None), (135, "MS-RPC", "crit"), (139, "NetBIOS", "crit"), (143, "IMAP", None), (443, "HTTPS", None), (445, "SMB", "crit"),
    (465, "SMTPS", None), (587, "Submission", None), (993, "IMAPS", None), (995, "POP3S", None), (1433, "MSSQL", "crit"), (1521, "Oracle", "crit"), (2375, "Docker API", "crit"), (2379, "etcd", "crit"), (3306, "MySQL", "crit"), (3389, "RDP", "crit"),
    (5432, "PostgreSQL", "crit"), (5601, "Kibana", "crit"), (5672, "AMQP", "warn"), (5900, "VNC", "crit"), (5984, "CouchDB", "crit"), (6379, "Redis", "crit"), (6443, "Kubernetes API", "warn"), (8080, "HTTP-Alt", None), (8443, "HTTPS-Alt", None),
    (9092, "Kafka", "crit"), (9200, "Elasticsearch", "crit"), (10000, "Webmin", "warn"), (11211, "Memcached", "crit"), (15672, "RabbitMQ Mgmt", "warn"), (27017, "MongoDB", "crit")]
BANNER_PORTS = {21, 22, 25, 110, 143, 587}


async def grab_banner(ip, port, timeout=2500):
    if blocked_host(ip):
        return None
    buf = b""
    w = None
    try:
        async def go():
            nonlocal buf, w
            fam, addr = (await safe_addrinfo(ip, port))[0]
            r, w = await asyncio.open_connection(addr, port)
            while b"\n" not in buf and len(buf) <= 200:
                d = await r.read(256)
                if not d:
                    break
                buf += d
        await asyncio.wait_for(go(), timeout / 1000)
    except Exception:
        pass
    finally:
        if w:
            try:
                w.close()
            except Exception:
                pass
    txt = re.sub(r"[^\x20-\x7e]", " ", buf.decode("latin1")).strip()[:160]
    return txt or None


async def scan_server(inp) -> J:
    started = now_ms()
    V = "server-analyzer-v3.0"
    host = parse_target_host(inp)
    if not host:
        return build_result(assetType="SERVER", version=V, startedAt=started, target=str(inp or ""), findings=["finding_server_invalid_target_critical"], score=0, status="ERROR", specific=J())
    ips = await resolve_ips(host)
    ip = ips.v4[0] if ips.v4 else (ips.v6[0] if ips.v6 else None)
    if not ip:
        if ips.code and not dns_missing(ips.code):
            return unavailable_result(assetType="SERVER", version=V, startedAt=started, target=host, finding="finding_server_dns_unreliable_info", status="UNKNOWN", note="DNS sorguları yanıt vermedi.", specific=J(host=host))
        return build_result(assetType="SERVER", version=V, startedAt=started, target=host, findings=["finding_server_not_resolving_critical"], score=0, status="DOWN", specific=J(host=host))
    if not allow_private() and is_private_ip(ip):
        return build_result(assetType="SERVER", version=V, startedAt=started, target=host, findings=["finding_server_private_target_critical"], score=None, status="ERROR", specific=J(host=host, ip=ip))
    geo = await ip_info(ip)
    behind_cdn = (cloud_family(geo.org or geo.isp) or "") in DDOS_CAPABLE or bool(re.search(r"cloudflare|akamai|fastly|cloudfront", str(geo.org or ""), re.I))

    async def chk(p, _i):
        port, name, risk = p
        r = await tcp_port_check(ip, port, 2500)
        return J(**r, name=name, risk=risk)
    res = await pool(SERVER_PORTS, 16, chk)
    rows = [r for r in res if r]
    open_ = [r for r in rows if r.open]
    banners: dict = {}

    async def bn(r, _i):
        b = await grab_banner(ip, r.port)
        if b:
            banners[r.port] = b
    await pool([r for r in open_ if r.port in BANNER_PORTS], 6, bn)
    findings: list = []
    score = 100
    ignore_cdn = lambda p: behind_cdn and p in (80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8880)
    for r in open_:
        if ignore_cdn(r.port):
            continue
        if r.risk == "crit":
            findings.append(f"finding_server_exposed_port_{r.port}_critical")
            score -= 22
        elif r.risk == "warn":
            findings.append(f"finding_server_exposed_port_{r.port}_warning")
            score -= 8
    if banners.get(22):
        m = re.search(r"SSH-(\d)\.(\d+)-OpenSSH[_-](\d+)\.(\d+)", banners[22], re.I)
        if re.search(r"SSH-1\.", banners[22]):
            findings.append("finding_server_ssh_v1_critical")
            score -= 20
        elif m and (int(m.group(3)) < 8 or (int(m.group(3)) == 8 and int(m.group(4)) < 5)):
            findings.append("finding_server_ssh_outdated_warning")
            score -= 8
    if banners.get(21) and re.search(r"vsftpd 2\.3\.4|ProFTPD 1\.3\.[0-3]\b", banners[21], re.I):
        findings.append("finding_server_ftp_vulnerable_version_critical")
        score -= 15
    if any(r.port == 21 for r in open_) and not any(r.port == 22 for r in open_) and not behind_cdn:
        findings.append("finding_server_ftp_without_ssh_info")
    mail_plain = any(r.port in (110, 143) for r in open_) and not any(r.port in (993, 995) for r in open_)
    if mail_plain:
        findings.append("finding_server_plain_mail_ports_warning")
        score -= 6
    web = any(r.port in (80, 443, 8080, 8443) for r in open_)
    alive = any(r.port in (22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443) for r in open_)
    if behind_cdn:
        findings.append("finding_server_behind_cdn_info")
    if not open_:
        findings.append("finding_server_unreachable_critical")
        score = 0
    elif not alive and not behind_cdn:
        findings.append("finding_server_no_service_ports_warning")
        score -= 10
    score = clamp(score)
    lat = [r.latencyMs for r in open_]
    timeouts = len([r for r in rows if r.error == "timeout"])
    return build_result(assetType="SERVER", version=V, startedAt=started, target=host, findings=findings, score=score, status="DOWN" if not open_ else None,
        specific=J(host=host, ip=ip, allIps=[*ips.v4, *ips.v6], provider=geo.org or geo.isp, country=geo.country, city=geo.city, asn=geo.asn, behindCdn=behind_cdn,
                   checkedPorts=len(SERVER_PORTS), openCount=len(open_), filteredCount=timeouts, avgConnectMs=avg(lat),
                   openPorts=[f"{r.port}/{r.name} ({r.latencyMs}ms)" for r in open_], banners=[f"{p}: {b}" for p, b in sorted(banners.items())], webServiceOpen=web,
                   note=("Hedef bir CDN/WAF arkasında; port sonuçları gerçek sunucuyu değil CDN'i yansıtır." if behind_cdn else f"Yalnızca {len(SERVER_PORTS)} yaygın porta bağlantı denendi; hiçbir veri gönderilmedi, sadece karşılama (banner) satırı okundu.")))


# =====================================================================
# HTML AYRIŞTIRMA (DOĞRUSAL zamanlı: düşman sayfalar olay döngüsünü kilitleyemez)
# =====================================================================
MAX_HTML, MAX_TAG, MAX_TAGS = 1_500_000, 8192, 150_000
RAW_TEXT = {"script", "style", "title", "textarea"}
SKIP_TEXT = {"noscript", "svg", "template"}
_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?""")
_TAGNAME_RE = re.compile(r"^<(/?)([a-zA-Z][a-zA-Z0-9:-]*)")


def parse_attr_str(inner: str) -> dict:
    o: dict = {}
    for guard, m in enumerate(_ATTR_RE.finditer(inner)):
        if guard >= 400:
            break
        k = m.group(1).lower()
        if k not in o:
            v = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4) if m.group(4) is not None else ""
            o[k] = v
    return o


def tokenize_html(src) -> J:
    html = str(src or "")[:MAX_HTML]
    n = len(html)
    tags: list = []
    i = 0
    while i < n:
        if len(tags) >= MAX_TAGS:
            break  # düşman sayfa: etiket sayısı sınırı (CPU/bellek koruması)
        lt = html.find("<", i)
        if lt < 0:
            break
        if html.startswith("<!--", lt):
            g = html.find("-->", lt + 4)
            if g < 0:
                tags.append(J(n="#c", c=False, s=lt, e=n, a=""))
                break
            tags.append(J(n="#c", c=False, s=lt, e=g + 3, a=""))
            i = g + 3
            continue
        j = lt + 1
        end = -1
        lim = min(n, lt + MAX_TAG)
        while j < lim:
            ch = html[j]
            if ch == ">":
                end = j
                break
            if ch == "<":
                break
            j += 1
        if end < 0:
            i = j if j < lim else lt + 1
            continue
        m = _TAGNAME_RE.match(html[lt:lt + 48])
        if not m:
            i = end + 1
            continue
        a = html[lt + len(m.group(0)):end]
        if a.endswith("/"):
            a = a[:-1]
        t = J(n=m.group(2).lower(), c=bool(m.group(1)), s=lt, e=end + 1, a=a)
        tags.append(t)
        i = end + 1
        if (not t.c) and t.n in RAW_TEXT:
            cm = re.compile("</" + t.n + r"[\s/>]", re.I).search(html, i)
            stop = cm.start() if cm else n
            t.body = html[i:min(stop, i + 200000)]
            t.bodyLen = stop - i
            i = stop
            if not cm:
                break
    return J(html=html, tags=tags)


def text_of_tokens(tk) -> str:
    html, tags = tk.html, tk.tags
    out = []
    pos = 0
    skip = 0
    for t in tags:
        if t.s > pos and not skip:
            out.append(html[pos:t.s])
        pos = max(pos, t.e)
        if t.n in SKIP_TEXT:
            skip = max(0, skip + (-1 if t.c else 1))
        if (not t.c) and t.bodyLen:
            pos = t.e + t.bodyLen
    if pos < len(html) and not skip:
        out.append(html[pos:])
    return re.sub(r"\s+", " ", " ".join(out)).strip()


_STRIP_RE = re.compile(r"<[^<>]{0,8192}>")


def strip_tags(h) -> str:
    return re.sub(r"\s+", " ", _STRIP_RE.sub(" ", str(h or ""))).strip()


def extract_title(body) -> str:
    tk = tokenize_html(str(body or "")[:200000])
    t = next((x for x in tk.tags if x.n == "title" and not x.c), None)
    return decode_entities(re.sub(r"\s+", " ", t.body).strip()) if (t and t.body) else ""


def analyze_html(html_in, base_url) -> J:
    raw_len = len(str(html_in or ""))
    tk = tokenize_html(html_in)
    html = tk.html
    A = J()
    by: dict = {}
    for t in tk.tags:
        if t.n[0] == "#":
            continue
        by.setdefault(t.n, []).append(t)
    open_ = lambda name: [t for t in by.get(name, []) if not t.c]
    attrs = lambda name: [parse_attr_str(t.a) for t in open_(name)]
    head_attrs = lambda name: [parse_attr_str(t.a) for t in open_(name) if t.s < 200000]
    title_tag = open_("title")[0] if open_("title") else None
    A.title = decode_entities(re.sub(r"\s+", " ", (title_tag.body if title_tag and title_tag.body else "")).strip()) or None
    metas = head_attrs("meta")

    def meta(n, by2="name"):
        for m in metas:
            if str(m.get(by2) or "").lower() == n:
                return decode_entities(m["content"].strip()) if m.get("content") is not None else None
        return None
    A.metaDescription = meta("description")
    A.robotsMeta = (meta("robots") or "").lower()
    A.googlebotMeta = (meta("googlebot") or "").lower()
    A.viewport = meta("viewport")
    A.generator = meta("generator")
    A.themeColor = meta("theme-color")
    cs = next((m for m in metas if m.get("charset")), None)
    ct = next((m for m in metas if str(m.get("http-equiv") or "").lower() == "content-type"), None)
    A.charset = (cs.get("charset") if cs else None) or ((re.search(r"charset=([\w-]+)", str(ct.get("content") or ""), re.I) or [None, None])[1] if ct else None) or None
    A.og = J(title=meta("og:title", "property"), description=meta("og:description", "property"), image=meta("og:image", "property"), url=meta("og:url", "property"), type=meta("og:type", "property"))
    A.twitterCard = meta("twitter:card")
    links = head_attrs("link")
    rel = lambda r: [l for l in links if r in str(l.get("rel") or "").lower().split()]
    A.canonical = (rel("canonical")[0].get("href") if rel("canonical") else None) or None
    A.hasFavicon = any(re.search(r"\bicon\b", l.get("rel") or "", re.I) for l in links)
    A.appleTouchIcon = len(rel("apple-touch-icon")) > 0
    A.manifest = (rel("manifest")[0].get("href") if rel("manifest") else None) or None
    A.hreflang = [J(lang=l["hreflang"], href=l.get("href")) for l in links if l.get("hreflang")]
    A.rssFeed = any(re.search(r"alternate", l.get("rel") or "", re.I) and re.search(r"rss|atom", l.get("type") or "", re.I) for l in links)
    html_tag = (attrs("html") or [{}])[0]
    A.htmlLang = html_tag.get("lang") if re.fullmatch(r"[A-Za-z-]+", html_tag.get("lang") or "") else None
    h1c = [t.s for t in by.get("h1", []) if t.c]
    A.h1 = []
    hp = 0
    for t in open_("h1"):
        while hp < len(h1c) and h1c[hp] < t.e:
            hp += 1
        if hp >= len(h1c):
            break
        x = decode_entities(strip_tags(html[t.e:h1c[hp]]))
        if x:
            A.h1.append(x)
    A.h1Count = len(open_("h1"))
    A.h2Count = len(open_("h2"))
    A.h3Count = len(open_("h3"))
    imgs = attrs("img")
    A.images = J(total=len(imgs),
                 missingAlt=len([i for i in imgs if i.get("alt") is None or (i["alt"].strip() == "" and not re.fullmatch(r"(presentation|none)", i.get("role") or "", re.I))]),
                 lazy=len([i for i in imgs if re.search(r"lazy", i.get("loading") or "", re.I)]), noDimensions=len([i for i in imgs if not (i.get("width") and i.get("height"))]),
                 modernFormat=len([i for i in imgs if re.search(r"\.(webp|avif)(\?|$)", i.get("src") or i.get("data-src") or "", re.I)]),
                 srcs=[s for s in (i.get("src") or i.get("data-src") for i in imgs) if s])
    script_tags = open_("script")
    scripts = [parse_attr_str(t.a) for t in script_tags]
    A.scripts = [J(src=s["src"], **{"async": "async" in s}, defer="defer" in s, module=bool(re.search(r"module", s.get("type") or "", re.I)), integrity=bool(s.get("integrity"))) for s in scripts if s.get("src")]
    A.inlineScripts = len([s for s in scripts if not s.get("src")])
    A.stylesheets = [J(href=l["href"], integrity=bool(l.get("integrity"))) for l in links if re.search(r"stylesheet", l.get("rel") or "", re.I) and l.get("href")]
    A.jsonld = J(blocks=0, invalid=0, types=[])
    for k, t in enumerate(script_tags):
        if not re.search(r"application/ld\+json", scripts[k].get("type") or "", re.I):
            continue
        A.jsonld.blocks += 1
        try:
            j = json.loads(str(t.body or "").strip())

            def walk(o, d=0):
                if d > 12:
                    return
                if isinstance(o, list):
                    for x in o:
                        walk(x, d + 1)
                elif isinstance(o, dict):
                    if o.get("@type"):
                        tt = o["@type"]
                        for x in (tt if isinstance(tt, list) else [tt]):
                            A.jsonld.types.append(str(x))
                    if o.get("@graph"):
                        walk(o["@graph"], d + 1)
            walk(j)
        except Exception:
            A.jsonld.invalid += 1
    A.jsonld.types = list(dict.fromkeys(A.jsonld.types))[:50]
    text = text_of_tokens(tk)
    A.text = text[:20000]
    A.wordCount = len(text.split()) if text else 0
    A.htmlBytes = raw_len
    A.domNodes = len([t for t in tk.tags if not t.c and t.n[0] != "#"])
    A.spaShell = A.wordCount < 60 and any(re.search(r"\bid\s*=\s*[\"']?(root|app|__next|__nuxt|___gatsby)[\"']?", t.a, re.I) for t in open_("div")) and (len(A.scripts) > 0 or A.inlineScripts > 0)
    base = split_url(base_url)
    base_host = (base.hostname or "") if base else ""
    anchors = [a for a in attrs("a") if a.get("href")]
    internal = external = nofollow_ext = empty_href = 0
    ext_hosts: dict = {}
    for a in anchors[:5000]:
        h = a["href"].strip()
        if not h or h == "#":
            empty_href += 1
            continue
        if re.match(r"^(mailto:|tel:|javascript:|#|sms:|whatsapp:)", h, re.I):
            continue
        try:
            u = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, h))
            uh = u.hostname or ""
            if base and re.sub(r"^www\.", "", uh) == re.sub(r"^www\.", "", base_host):
                internal += 1
            else:
                external += 1
                ext_hosts[uh] = 1
                if re.search(r"nofollow", a.get("rel") or "", re.I):
                    nofollow_ext += 1
        except Exception:
            pass
    A.links = J(internal=internal, external=external, nofollowExternal=nofollow_ext, emptyHref=empty_href, externalHosts=list(ext_hosts)[:15])
    third: dict = {}

    def absu(u):
        try:
            return urllib.parse.urlsplit(urllib.parse.urljoin(base_url, u))
        except Exception:
            return None
    for s in A.scripts:
        u = absu(s.src)
        if u and base and u.hostname != base_host:
            third[u.hostname] = 1
    for s in A.stylesheets:
        u = absu(s.href)
        if u and base and u.hostname != base_host:
            third[u.hostname] = 1
    A.thirdPartyHosts = list(third)
    A.externalScriptsNoSri = len([s for s in A.scripts if (lambda u: u and base and u.hostname != base_host and not s.integrity)(absu(s.src))])
    A.externalScriptsTotal = len([s for s in A.scripts if (lambda u: u and base and u.hostname != base_host)(absu(s.src))])
    A.mixed = J(active=0, passive=0)
    if re.match(r"^https:", str(base_url), re.I):
        for s in A.scripts:
            if re.match(r"^http://", s.src, re.I):
                A.mixed.active += 1
        for s in A.stylesheets:
            if re.match(r"^http://", s.href, re.I):
                A.mixed.active += 1
        for f in attrs("iframe"):
            if re.match(r"^http://", f.get("src") or "", re.I):
                A.mixed.active += 1
        for s in A.images.srcs:
            if re.match(r"^http://", s, re.I):
                A.mixed.passive += 1
    A.forms = [J(action=f.get("action") or "", method=(f.get("method") or "get").lower()) for f in attrs("form")]
    A.hasPasswordField = any(re.fullmatch(r"password", i.get("type") or "", re.I) for i in attrs("input"))
    if re.match(r"^https:", str(base_url), re.I):
        A.insecureForm = any(re.match(r"^http://", f.action, re.I) for f in A.forms)
    else:
        A.insecureForm = A.hasPasswordField or any(re.match(r"^http:", f.action, re.I) for f in A.forms)
    A.directoryListing = bool(re.match(r"^Index of /", A.title or "", re.I)) or any(re.match(r"^Index of /", x, re.I) for x in A.h1)
    return A


# ---------- Teknoloji tespiti ----------
_TECH = [(re.compile(p, re.I), n, c) for p, n, c in [
    (r"wp-content|wp-includes", "WordPress", "CMS"), (r"/sites/(default|all)/(files|modules|themes)", "Drupal", "CMS"), (r"cdn\.shopify\.com|Shopify\.theme", "Shopify", "E-ticaret"), (r"static\.wixstatic\.com", "Wix", "CMS"),
    (r"squarespace\.com|static1\.squarespace", "Squarespace", "CMS"), (r"assets\.website-files\.com|data-wf-page", "Webflow", "CMS"), (r"__NEXT_DATA__|/_next/static", "Next.js", "Çatı"), (r"__NUXT__|/_nuxt/", "Nuxt", "Çatı"),
    (r"id=[\"']___gatsby", "Gatsby", "Çatı"), (r"ng-version=|ng-app|<app-root", "Angular", "Çatı"), (r"data-reactroot|react(?:\.production|-dom)", "React", "Kütüphane"),
    (r"vue(?:\.runtime|\.min)?\.js|data-v-[a-f0-9]{6,}|__vue__", "Vue.js", "Kütüphane"), (r"svelte-[a-z0-9]{5,}", "Svelte", "Kütüphane"), (r"prestashop", "PrestaShop", "E-ticaret"),
    (r"/skin/frontend/|Mage\.Cookies|magento", "Magento", "E-ticaret"), (r"woocommerce", "WooCommerce", "E-ticaret"), (r"ticimax|tsoft|ideasoft|ikas", "TR E-ticaret altyapısı", "E-ticaret"),
    (r"googletagmanager\.com/gtm\.js", "Google Tag Manager", "Analitik"), (r"google-analytics\.com/(analytics|ga)\.js|gtag/js\?id=G-|googletagmanager\.com/gtag", "Google Analytics", "Analitik"),
    (r"connect\.facebook\.net/[^\"'\s]{0,200}fbevents", "Meta Pixel", "Analitik"), (r"static\.hotjar\.com", "Hotjar", "Analitik"), (r"js\.hs-scripts\.com|hubspot", "HubSpot", "Pazarlama"),
    (r"cdn\.jsdelivr|cdnjs\.cloudflare", "Genel CDN kütüphaneleri", "CDN"), (r"bootstrap(?:\.min)?\.(?:css|js)|class=[\"'][^\"']*\bcol-(?:md|lg|sm)-\d", "Bootstrap", "UI"), (r"tailwind", "Tailwind CSS", "UI"),
    (r"recaptcha/api\.js|g-recaptcha", "reCAPTCHA", "Güvenlik"), (r"challenges\.cloudflare\.com/turnstile", "Cloudflare Turnstile", "Güvenlik"), (r"cookiebot|cookieconsent|onetrust|kvkk|cerez", "Çerez onay aracı", "Uyumluluk")]]


def detect_tech(html, headers, cookies, gen_meta=None) -> list:
    out: list = []
    h = headers or {}
    s = lambda k: str(h.get(k) or "")

    def add(name, cat, version=None):
        if not any(o.name == name for o in out):
            out.append(J(name=name, category=cat, version=version or None))
    g1 = lambda pat, text: (lambda m: m.group(1) if m else None)(re.search(pat, text, re.I))
    server = s("server")
    if re.search(r"nginx", server, re.I): add("nginx", "Sunucu", g1(r"nginx/([\d.]+)", server))
    if re.search(r"apache", server, re.I): add("Apache", "Sunucu", g1(r"Apache/([\d.]+)", server))
    if re.search(r"microsoft-iis", server, re.I): add("IIS", "Sunucu", g1(r"IIS/([\d.]+)", server))
    for pat, nm in ((r"litespeed", "LiteSpeed"), (r"openresty", "OpenResty"), (r"caddy", "Caddy"), (r"gunicorn", "Gunicorn"), (r"kestrel", "Kestrel")):
        if re.search(pat, server, re.I): add(nm, "Sunucu")
    xp = s("x-powered-by")
    if xp:
        m = re.match(r"^([A-Za-z.\-+ ]+?)/?([\d.]+)?$", xp)
        add(m.group(1).strip() if m else xp, "Çatı", m.group(2) if m else None)
    if h.get("x-aspnet-version"): add("ASP.NET", "Çatı", s("x-aspnet-version"))
    if h.get("x-drupal-cache") or re.search(r"drupal", s("x-generator"), re.I): add("Drupal", "CMS")
    if h.get("cf-ray"): add("Cloudflare", "CDN/WAF")
    if h.get("x-vercel-id"): add("Vercel", "Barındırma")
    if h.get("x-nf-request-id"): add("Netlify", "Barındırma")
    if h.get("x-amz-cf-id"): add("CloudFront", "CDN/WAF")
    gen = str(gen_meta)[:200] if gen_meta else None
    if gen:
        m = re.match(r"^([A-Za-z .]+?)\s*v?([\d.]+)?$", gen)
        if re.search(r"wordpress", gen, re.I): add("WordPress", "CMS", g1(r"([\d.]+)", gen))
        elif re.search(r"joomla", gen, re.I): add("Joomla", "CMS")
        elif re.search(r"drupal", gen, re.I): add("Drupal", "CMS")
        elif re.search(r"wix", gen, re.I): add("Wix", "CMS")
        elif re.search(r"ghost", gen, re.I): add("Ghost", "CMS")
        elif re.search(r"hugo", gen, re.I): add("Hugo", "Statik")
        elif re.search(r"gatsby", gen, re.I): add("Gatsby", "Statik")
        elif re.search(r"webflow", gen, re.I): add("Webflow", "CMS")
        else: add(m.group(1).strip() if m else gen, "CMS", m.group(2) if m else None)
    for rx, name, cat in _TECH:
        if rx.search(html):
            add(name, cat)
    jq = re.search(r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", html, re.I) or re.search(r"jquery\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)", html, re.I)
    if jq or re.search(r"jquery", html, re.I):
        add("jQuery", "Kütüphane", jq.group(1) if jq else None)
    bs = re.search(r"bootstrap(?:@|/|-)(\d+\.\d+(?:\.\d+)?)", html, re.I)
    if bs:
        b = next((o for o in out if o.name == "Bootstrap"), None)
        if b:
            b.version = bs.group(1)
        else:
            add("Bootstrap", "UI", bs.group(1))
    ck = [str(c).split("=")[0] for c in (cookies or [])]
    if "PHPSESSID" in ck: add("PHP", "Dil")
    if any(re.match(r"^ASP\.NET_SessionId|ASPSESSIONID", c, re.I) for c in ck): add("ASP.NET", "Çatı")
    if "JSESSIONID" in ck: add("Java", "Dil")
    if any(re.search(r"laravel_session", c) for c in ck): add("Laravel", "Çatı")
    if "csrftoken" in ck or "django_language" in ck: add("Django", "Çatı")
    return out


def detect_page_state(html, title, status, nbytes) -> list:
    t = str(title or "").lower()
    b = str(html or "")[:60000].lower()
    states = []
    if re.search(r"account (has been )?suspended|this account is suspended|hesab[ıi]n[ıi]z askıya|bandwidth limit exceeded|resource limit is reached|site (is )?suspended", b): states.append("suspended")
    if re.search(r"this domain (is|may be) for sale|buy this domain|domain is parked|parked (free|domain)|sedo\.com/search|domain satılık|bu alan adı satılık|hugedomains|dan\.com/|afternic|parkingcrew|bodis\.com|this web page is parked", b) or re.match(r"^(domain for sale|parked)", t): states.append("parked")
    if re.search(r"welcome to nginx!|apache2 (ubuntu|debian) default page|apache http server test page|it works!?</h1>|iis windows server|welcome to iis|default web site page|test page for the (apache|nginx)|plesk (obsidian|onyx)|cpanel.*default|congratulations.*(web ?server|installed)|web server's default page", b) or re.match(r"^(welcome to nginx|apache2.*default page|iis windows server)", t): states.append("default_page")
    if re.search(r"under construction|coming soon|yapım aşamasında|çok yakında|site is being built|launching soon", b) and (nbytes or len(b)) < 25000: states.append("under_construction")
    if re.search(r"maintenance mode|scheduled maintenance|we('| a)re (currently )?(down for|undergoing) maintenance|bakım(da| çalışması)|site bakımda|be right back", b) or (status == 503 and re.search(r"maintenance|bakım", b)): states.append("maintenance")
    if re.search(r"error establishing a database connection|fatal error:.{0,300}on line \d+|warning:.{0,300}on line \d+|parse error:|mysqli?_connect|sqlstate\[|unhandled exception|server error in '/' application|stack trace:", b): states.append("app_error")
    return states


# ---------- robots.txt + sitemap ----------
async def load_site_files(origin, page_host) -> J:
    robots, sm = await asyncio.gather(http_probe(origin + "/robots.txt", timeout=7000, maxRedirects=3, noUaFallback=True, max_bytes=300000),
                                      http_probe(origin + "/sitemap.xml", timeout=8000, maxRedirects=3, noUaFallback=True, max_bytes=1500000))
    robots_ok = robots.status == 200 and not re.search(r"<html[\s>]", str(robots.body)[:500], re.I)
    rtxt = robots.body if robots_ok else ""
    groups: list = []
    cur = None
    for line in re.split(r"\r?\n", rtxt):
        l = re.sub(r"#.*", "", line).strip()
        if not l:
            continue
        m = re.match(r"^([a-z\-]+)\s*:\s*(.*)$", l, re.I)
        if not m:
            continue
        k, v = m.group(1).lower(), m.group(2).strip()
        if k == "user-agent":
            if cur is None or cur.rules:
                cur = J(agents=[], rules=[])
                groups.append(cur)
            cur.agents.append(v.lower())
        elif cur is not None and k in ("allow", "disallow", "crawl-delay"):
            cur.rules.append((k, v))
    star = next((g for g in groups if "*" in g.agents), None)
    blocks_all = bool(star) and any(k == "disallow" and v == "/" for k, v in star.rules) and not any(k == "allow" and v == "/" for k, v in star.rules)
    blocks_google = any("googlebot" in g.agents and any(k == "disallow" and v == "/" for k, v in g.rules) for g in groups)
    sitemaps_in_robots = [m.group(1) for m in re.finditer(r"^\s*sitemap\s*:\s*(\S+)", rtxt, re.I | re.M)]
    sm_body = sm.body if sm.status == 200 else ""
    sm_url = origin + "/sitemap.xml"
    if not re.search(r"<urlset|<sitemapindex", sm_body, re.I) and sitemaps_in_robots:
        r2 = await http_probe(sitemaps_in_robots[0], timeout=8000, maxRedirects=3, noUaFallback=True, max_bytes=1500000)
        if r2.status == 200:
            sm_body = r2.body
            sm_url = sitemaps_in_robots[0]
    is_sm = bool(re.search(r"<urlset|<sitemapindex", sm_body, re.I))
    locs = [decode_entities(m.group(1)) for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", sm_body, re.I)] if is_sm else []
    sample = None
    if is_sm and locs and not re.search(r"<sitemapindex", sm_body, re.I):
        pick = locs[0]
        r = await http_probe(pick, timeout=8000, maxRedirects=3, noUaFallback=True, read_body=False)
        sample = J(url=pick, status=r.status)

    def other_host(u):
        try:
            return re.sub(r"^www\.", "", urllib.parse.urlsplit(u).hostname or "") != re.sub(r"^www\.", "", str(page_host))
        except Exception:
            return False
    return J(robots=J(exists=robots_ok, status=robots.status, blocksAll=blocks_all, blocksGooglebot=blocks_google, groups=len(groups), sitemapDirectives=len(sitemaps_in_robots),
                      crawlDelay=bool(star and any(k == "crawl-delay" for k, _ in star.rules)), size=len(rtxt)),
             sitemap=J(exists=is_sm or len(sitemaps_in_robots) > 0, valid=is_sm, url=sm_url if is_sm else None, isIndex=bool(re.search(r"<sitemapindex", sm_body, re.I)), urlCount=len(locs), firstUrl=sample,
                       otherHost=any(other_host(u) for u in locs[:20]) if locs else False))


# =====================================================================
# Ortak kontrol setleri
# =====================================================================
def seo_checks(c, ctx) -> list:
    main, A, files, final_url = ctx.main, ctx.A, ctx.files, ctx.finalUrl
    h = main.headers or {}
    xrobots = str(h.get("x-robots-tag") or "").lower()
    spa = A.spaShell
    title, desc = A.title, A.metaDescription
    c.add(bool(title), 10, "finding_seo_missing_title_critical", "icerik")
    if title:
        c.add(30 <= len(title) <= 65, 5, "finding_seo_title_length_warning", "icerik")
    c.add(bool(desc), 10, "finding_seo_missing_description_warning", "icerik")
    if desc:
        c.add(70 <= len(desc) <= 165, 4, "finding_seo_description_length_warning", "icerik")
    if not spa:
        c.add(A.h1Count == 1, 8, "finding_seo_missing_h1_warning" if A.h1Count == 0 else "finding_seo_multiple_h1_warning", "icerik")
        c.add(A.wordCount >= 300, 4, "finding_seo_thin_content_warning", "icerik")
    c.add((not A.images.total) or A.images.missingAlt / A.images.total <= 0.1, 5, "finding_seo_images_missing_alt_warning", "icerik")
    noindex = "noindex" in A.robotsMeta or "noindex" in A.googlebotMeta or "noindex" in xrobots
    c.add(not noindex, 15, "finding_seo_noindex_critical", "teknik")
    c.add((not files.robots.blocksAll) and (not files.robots.blocksGooglebot), 15, "finding_seo_robots_blocks_all_critical", "teknik")
    c.add(bool(A.canonical), 5, "finding_seo_missing_canonical_warning", "teknik")
    if A.canonical:
        try:
            cu = urllib.parse.urlsplit(urllib.parse.urljoin(final_url, A.canonical))
            fu = urllib.parse.urlsplit(final_url)
            c.add(re.sub(r"^www\.", "", cu.hostname or "") == re.sub(r"^www\.", "", fu.hostname or ""), 4, "finding_seo_canonical_other_host_warning", "teknik")
        except Exception:
            c.add(False, 4, "finding_seo_canonical_invalid_warning", "teknik")
    c.add(files.robots.exists, 4, "finding_seo_missing_robots_warning", "teknik")
    c.add(files.sitemap.exists, 6, "finding_seo_missing_sitemap_warning", "teknik")
    if files.sitemap.valid:
        c.add(files.sitemap.urlCount > 0, 3, "finding_seo_sitemap_empty_warning", "teknik")
        if files.sitemap.firstUrl:
            c.add(200 <= files.sitemap.firstUrl.status < 400, 3, "finding_seo_sitemap_broken_urls_warning", "teknik")
        if files.sitemap.otherHost:
            c.add(False, 3, "finding_seo_sitemap_other_host_warning", "teknik")
    c.add(bool(re.match(r"^https:", final_url, re.I)), 6, "finding_seo_not_https_warning", "teknik")
    c.add(bool(A.viewport), 6, "finding_seo_missing_viewport_warning", "teknik")
    c.add(bool(A.htmlLang), 4, "finding_seo_missing_lang_warning", "teknik")
    c.add(A.hasFavicon, 2, "finding_seo_missing_favicon_warning", "teknik")
    c.add(bool(A.charset) or bool(re.search(r"charset=", str(h.get("content-type") or ""), re.I)), 2, "finding_seo_missing_charset_warning", "teknik")
    c.add(main.status == 200, 5, "finding_seo_final_status_warning", "teknik")
    c.add((main.redirects or 0) <= 2, 3, "finding_seo_redirect_chain_warning", "teknik")
    if A.hreflang:
        c.add(any(re.search(r"x-default", x.lang or "", re.I) for x in A.hreflang), 3, "finding_seo_hreflang_no_default_warning", "sosyal")
    og = A.og
    c.add(bool(og.title and og.description and og.image), 4, "finding_seo_missing_open_graph_warning", "sosyal")
    c.add(bool(A.twitterCard), 2, "finding_seo_missing_twitter_card_warning", "sosyal")
    c.add(A.jsonld.blocks > 0, 4, "finding_seo_missing_structured_data_warning", "sosyal")
    if A.jsonld.blocks:
        c.add(A.jsonld.invalid == 0, 3, "finding_seo_structured_data_invalid_warning", "sosyal")
    c.add(A.links.internal >= 3 or bool(spa), 3, "finding_seo_few_internal_links_warning", "sosyal")
    return ["finding_seo_client_rendered_info"] if spa else []


def security_header_checks(c, ctx) -> J:
    main, A, final_url = ctx.main, ctx.A, ctx.finalUrl
    h = main.headers or {}
    https = bool(re.match(r"^https:", final_url, re.I))
    hsts = str(h.get("strict-transport-security") or "")
    mm = re.search(r"max-age=(\d+)", hsts, re.I)
    max_age = int(mm.group(1)) if mm else 0
    csp = str(h.get("content-security-policy") or "")
    c.add(https, 12, "finding_security_not_https_critical", "aktarim")
    if https:
        c.add(bool(hsts) and max_age >= 15552000, 12, "finding_security_hsts_short_warning" if hsts else "finding_security_missing_hsts_warning", "basliklar")
    c.add(bool(csp), 12, "finding_security_missing_csp_warning", "basliklar")
    if csp:
        c.add(not re.search(r"unsafe-inline|unsafe-eval", csp), 5, "finding_security_csp_unsafe_warning", "basliklar")
        c.add(not re.search(r"(default-src|script-src)[^;]*(\s\*|\sdata:|\shttp:)", csp, re.I), 3, "finding_security_csp_weak_warning", "basliklar")
    c.add(bool(h.get("x-frame-options")) or "frame-ancestors" in csp, 8, "finding_security_missing_clickjacking_warning", "basliklar")
    c.add(bool(re.search(r"nosniff", str(h.get("x-content-type-options") or ""), re.I)), 6, "finding_security_missing_nosniff_warning", "basliklar")
    c.add(bool(h.get("referrer-policy")), 5, "finding_security_missing_referrer_policy_warning", "basliklar")
    c.add(bool(h.get("permissions-policy")) or bool(h.get("feature-policy")), 4, "finding_security_missing_permissions_policy_warning", "basliklar")
    disclosure = bool(re.search(r"\d+\.\d+", str(h.get("server") or ""))) or bool(re.search(r"\d+\.\d+", str(h.get("x-powered-by") or ""))) or bool(h.get("x-aspnet-version")) or bool(h.get("x-aspnetmvc-version"))
    c.add(not disclosure, 4, "finding_security_version_disclosure_warning", "basliklar")
    raw_ck = main.cookies or h.get("set-cookie") or []
    raw_ck = raw_ck if isinstance(raw_ck, list) else [raw_ck]
    cookies = []
    for x in raw_ck:
        ss = re.search(r"samesite=(\w+)", str(x), re.I)
        cookies.append(J(name=str(x).split("=")[0], secure=bool(re.search(r";\s*secure", x, re.I)), httpOnly=bool(re.search(r";\s*httponly", x, re.I)), sameSite=ss.group(1) if ss else None))
    c.add((not cookies) or all(((not https) or k.secure) and k.httpOnly and k.sameSite for k in cookies), 6, "finding_security_cookie_flags_warning", "aktarim")
    if any(k.sameSite and k.sameSite.lower() == "none" and not k.secure for k in cookies):
        c.add(False, 3, "finding_security_cookie_samesite_none_warning", "aktarim")
    c.add(A.mixed.active == 0, 6, "finding_security_mixed_content_critical", "aktarim")
    c.add(A.mixed.passive == 0, 2, "finding_security_mixed_content_passive_warning", "aktarim")
    c.add(not A.insecureForm, 8, "finding_security_insecure_form_critical", "aktarim")
    c.add(not A.directoryListing, 6, "finding_security_directory_listing_critical", "dosyalar")
    if A.externalScriptsTotal:
        c.add(A.externalScriptsNoSri == 0, 3, "finding_security_no_sri_info", "basliklar")
    return J(cookies=cookies, hsts=hsts or None, hstsMaxAgeDays=max_age // 86400, csp=bool(csp), disclosure=disclosure)


# =====================================================================
# SAYFA ÇEKME (www/apex yedeği, http yedeği, hata nedeni)
# =====================================================================
def _swap(url: str, host: Optional[str] = None, scheme: Optional[str] = None) -> str:
    sp = urllib.parse.urlsplit(url)
    netloc = sp.netloc
    if host is not None:
        userinfo = netloc.rsplit("@", 1)[0] + "@" if "@" in netloc else ""
        port = f":{sp.port}" if sp.port else ""
        netloc = userinfo + host + port
    return urllib.parse.urlunsplit((scheme or sp.scheme, netloc, sp.path, sp.query, sp.fragment))


async def get_page(target_url, **o) -> J:
    url = ensure_url(target_url)
    typed_scheme = bool(re.match(r"^https?://", str(target_url or "").strip(), re.I))
    opts = {"timeout": 10000, "maxRedirects": 8, **o}
    main = await http_probe(url, **opts)
    variant = None
    http_only = False
    kind = main.errorInfo.kind if main.errorInfo else None
    if main.status == 0 and kind in ("dns", "refused", "reset", "unreachable", "tls"):
        try:
            u = urllib.parse.urlsplit(url)
            uh = u.hostname or ""
            tasks = []
            if not is_ip(uh):
                alt_host = uh[4:] if uh.startswith("www.") else "www." + uh
                alt = _swap(url, host=alt_host)
                async def tv():
                    return J(t="variant", r=await http_probe(alt, **{**opts, "timeout": 8000}), host=alt_host)
                tasks.append(tv())
            if u.scheme == "https" and ((not typed_scheme) or kind in ("refused", "tls", "reset")):
                hu = _swap(url, scheme="http")
                async def th():
                    return J(t="http", r=await http_probe(hu, **{**opts, "timeout": 8000}))
                tasks.append(th())
            outs = await asyncio.gather(*tasks)
            v = next((x for x in outs if x.t == "variant" and x.r.status > 0), None)
            if v:
                main = v.r
                variant = J(**{"from": uh, "to": v.host})
            else:
                hh = next((x for x in outs if x.t == "http" and x.r.status > 0), None)
                if hh:
                    main = hh.r
                    http_only = not re.match(r"^https:", hh.r.finalUrl, re.I)
        except Exception:
            pass
    return J(url=url, main=main, variant=variant, httpOnly=http_only, prot=detect_bot_protection(main) if main.status else None)


def is_html(m) -> bool:
    return bool(re.search(r"html|xml", str(m.contentType or (m.headers or {}).get("content-type") or ""), re.I)) or bool(re.search(r"<html|<!doctype", str(m.body or "")[:2000], re.I))


async def sample_assets(A, base_url, img_limit=5) -> list:
    def absu(u):
        try:
            return urllib.parse.urljoin(base_url, u)
        except Exception:
            return None
    css = [J(u=absu(s.href), kind="css") for s in A.stylesheets]
    js = [J(u=absu(s.src), kind="js") for s in A.scripts]
    img = [J(u=absu(s), kind="img") for s in A.images.srcs[:img_limit]]
    seen = set()
    lst = []
    for x in [*css[:6], *js[:8], *img]:
        if x.u and re.match(r"^https?:", x.u, re.I) and x.u not in seen:
            seen.add(x.u)
            lst.append(x)
    lst = lst[:18]

    async def one(x, _i):
        r = await request(x.u, timeout=8000, read_body=False, max_bytes=1500000, insecure=True)
        return J(**x, status=r.status, transfer=r.transferBytes, raw=r.rawBytes, enc=r.encoding, cache=str((r.headers or {}).get("cache-control") or ""), ctype=r.contentType or "", ttfb=r.ttfb)
    return [r for r in await pool(lst, 6, one) if r]


def perf_checks(c, ctx) -> J:
    main, A, assets, tlsi, dns_ms = ctx.main, ctx.A, ctx.assets, ctx.tlsi, ctx.dnsMs
    h = main.headers or {}
    compressed = (main.encoding or "") in ("gzip", "br", "deflate", "zstd")
    text_type = bool(re.search(r"text|json|javascript|xml", str(h.get("content-type") or ""), re.I))
    ttfb = main.ttfb
    chain_ms = sum((x.ms or 0) for x in (main.chain or []))
    c.add(ttfb < 600 if ttfb is not None else None, 18, "finding_perf_slow_ttfb_warning", "sunucu")
    c.add(ttfb < 1500 if ttfb is not None else None, 12, "finding_perf_very_slow_ttfb_critical", "sunucu")
    c.add(chain_ms < 3000, 10, "finding_perf_slow_load_warning", "sunucu")
    c.add((not text_type) or compressed, 12, "finding_perf_no_compression_warning", "agi")
    c.add((tlsi.alpn == "h2" or bool(re.search(r"h3", str(h.get("alt-svc") or "")))) if tlsi else None, 8, "finding_perf_no_http2_warning", "agi")
    c.add((main.redirects or 0) <= 2, 6, "finding_perf_redirect_chain_warning", "agi")
    if tlsi:
        c.add(tlsi.handshakeMs < 600, 3, "finding_perf_slow_tls_warning", "agi")
    if dns_ms is not None:
        c.add(dns_ms < 300, 2, "finding_perf_slow_dns_warning", "agi")
    sized = [a for a in assets if 0 < a.status < 400]
    sm = lambda k: sum((a.transfer or 0) for a in sized if a.kind == k)
    weight = (main.transferBytes or 0) + sum((a.transfer or 0) for a in sized)
    js_b, css_b, img_b = sm("js"), sm("css"), sm("img")
    c.add(weight < 2000000, 8, "finding_perf_heavy_page_warning", "sayfa")
    c.add(js_b < 600000, 5, "finding_perf_heavy_js_warning", "sayfa")
    c.add(css_b < 200000, 3, "finding_perf_heavy_css_warning", "sayfa")
    blocking = len([s for s in A.scripts if not s["async"] and not s.defer and not s.module])
    c.add(blocking <= 3, 6, "finding_perf_render_blocking_scripts_warning", "sayfa")
    c.add(len(A.scripts) <= 20, 4, "finding_perf_too_many_scripts_warning", "sayfa")
    c.add(A.images.total < 5 or A.images.lazy > 0, 4, "finding_perf_no_lazy_loading_warning", "sayfa")
    c.add((not A.images.total) or A.images.noDimensions / A.images.total <= 0.3, 3, "finding_perf_images_no_dimensions_warning", "sayfa")
    c.add(len(A.thirdPartyHosts) <= 10, 4, "finding_perf_many_third_parties_warning", "sayfa")
    c.add(A.domNodes < 2500, 3, "finding_perf_large_dom_warning", "sayfa")
    big_imgs = len([a for a in sized if a.kind == "img" and a.transfer > 400000])
    c.add(big_imgs == 0, 4, "finding_perf_large_images_warning", "sayfa")
    stat = [a for a in sized if a.kind != "img"]
    if stat:
        def cached_ok(a):
            m = re.search(r"max-age=(\d+)", a.cache)
            return bool(m and int(m.group(1)) >= 86400) or bool(re.search(r"immutable", a.cache))
        cached = len([a for a in stat if cached_ok(a)])
        c.add(cached == len(stat), 8, "finding_perf_weak_caching_warning", "agi")
        comp = len([a for a in stat if a.enc])
        c.add(comp == len(stat) or all(not re.search(r"javascript|css", a.ctype) for a in stat), 4, "finding_perf_assets_not_compressed_warning", "agi")
    return J(blocking=blocking, weight=weight, jsBytes=js_b, cssBytes=css_b, imgBytes=img_b, sized=sized, chainMs=chain_ms)


def origin_of(url: str) -> str:
    sp = urllib.parse.urlsplit(url)
    host = sp.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = sp.port
    default = {"http": 80, "https": 443}.get(sp.scheme)
    return f"{sp.scheme}://{host}" + (f":{port}" if port and port != default else "")


def tls_days_remaining(t) -> int:
    return math.floor((t.cert.validTo - datetime.now(timezone.utc)).total_seconds() / 86400)


def tls_issuer(t):
    o = _name_attr(t.cert.obj.issuer, x509.NameOID.ORGANIZATION_NAME)
    return o or _name_attr(t.cert.obj.issuer, x509.NameOID.COMMON_NAME)


async def _dns_lookup_ms(host):
    t = time.monotonic()
    try:
        await asyncio.get_running_loop().getaddrinfo(host, None)
        return int((time.monotonic() - t) * 1000)
    except Exception:
        return None


def _rand_token(n=7):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


EMPTY_FILES = lambda: J(robots=J(exists=False), sitemap=J(exists=False))


# =====================================================================
# 1. WEB SCANNER v4
# =====================================================================
async def scan_website(target_url, extra=None) -> J:
    started = now_ms()
    V = "web-analyzer-v4.0"
    errors: list = []
    if not target_url:
        return J(data=None, findings=["finding_web_missing_target_critical"], errors=["targetUrl yok"])
    pg = await get_page(target_url)
    url, main, variant, http_only, prot = pg.url, pg.main, pg.variant, pg.httpOnly, pg.prot
    host = host_of(main.finalUrl or url)
    if prot:
        tls_quick = await _safe(get_tls_details(host), None) if (host and re.match(r"^https:", main.finalUrl, re.I)) else None
        specific = J(url=url, finalUrl=main.finalUrl, status=main.status, responseTimeMs=main.responseTimeMs, server=(main.headers or {}).get("server"), techStack=[prot],
                     botProtection=J(detected=True, provider=prot, note="Site bot koruması arkasında; tarayıcı doğrulama sayfası aldı. Site büyük olasılıkla çalışıyor, SEO ve güvenlik başlığı analizi yapılamadı."),
                     certificate=(J(daysRemaining=tls_days_remaining(tls_quick), issuer=tls_issuer(tls_quick), protocol=tls_quick.protocol) if tls_quick else None))
        common = J(analyzerVersion=V, executionTimeMs=now_ms() - started, findings=["finding_web_bot_protection_info"], scannedAt=iso(datetime.now(timezone.utc)), score=None, status="PROTECTED", target=url)
        return J(data=J(assetType="WEB", commonAnalysis=common, specificAnalysis=specific, analysisMeta=J(scannerVersion=V, analyzer="web", limited=True)), findings=["finding_web_bot_protection_info"], errors=errors, statusHint="PROTECTED")
    c_av, c_sec, c_seo, c_perf = Checker(), Checker(), Checker(), Checker()
    findings: list = []
    if main.status == 0:
        findings.extend([net_error_finding("web", main), "finding_web_down_critical"])
        errors.append(main.error or "erişilemedi")
        dns_info = await resolve_ips(host) if host else None
        return build_result(assetType="WEB", version=V, startedAt=started, target=url, findings=findings, score=0, status="DOWN", errors=errors,
                            specific=J(url=url, status=0, error=main.error or None, errorKind=main.errorInfo.kind if main.errorInfo else None, errorCode=main.errorInfo.code if main.errorInfo else None,
                                       dnsResolves=(len(dns_info.v4) + len(dns_info.v6) > 0) if dns_info else None, triedVariants=variant, scores=J(availability=0)))
    final_url = main.finalUrl
    html = main.body or ""
    html_ = is_html(main)
    A = analyze_html(html, final_url)
    origin = origin_of(final_url)
    fsp = urllib.parse.urlsplit(final_url)
    final_host = fsp.hostname or ""
    alt = None
    try:
        if not is_ip(final_host):
            alt_host = final_host[4:] if final_host.startswith("www.") else "www." + final_host
            alt = urllib.parse.urlunsplit((fsp.scheme, _swap(final_url, host=alt_host).split("://", 1)[1].split("/", 1)[0], "/", "", ""))
    except Exception:
        alt = None
    is_https = bool(re.match(r"^https:", final_url, re.I))
    files, alt_probe, soft404, tls_det, tlsi, assets, dns_t = await asyncio.gather(
        _safe(load_site_files(origin, final_host), EMPTY_FILES()) if html_ else _ret(EMPTY_FILES()),
        http_probe(alt, timeout=8000, maxRedirects=3, noUaFallback=True, read_body=False) if alt else _ret(None),
        http_probe(origin + "/__dac_" + _rand_token(), timeout=7000, maxRedirects=1, noUaFallback=True, read_body=False),
        _safe(get_tls_details(final_host, fsp.port or 443), None) if is_https else _ret(None),
        tls_alpn(final_host) if is_https else _ret(None),
        _safe(sample_assets(A, final_url, 3), []) if html_ else _ret([]),
        _dns_lookup_ms(final_host))
    state = detect_page_state(html, A.title, main.status, A.htmlBytes) if html_ else []
    c_av.add(main.status < 500, 30, "finding_web_server_error_critical")
    c_av.add(main.status < 400, 25, f"finding_web_status_{main.status}_{'warning' if main.status in (401, 403) else 'critical'}")
    c_av.add(not main.redirectLoop, 10, "finding_web_redirect_loop_critical")
    c_av.add((main.responseTimeMs or 0) < 3000, 8, "finding_web_slow_warning")
    c_av.add((main.responseTimeMs or 0) < 1500, 4, None)
    c_av.add("suspended" not in state, 25, "finding_web_suspended_critical")
    c_av.add("parked" not in state, 20, "finding_web_parked_warning")
    c_av.add("default_page" not in state, 12, "finding_web_default_page_warning")
    c_av.add("app_error" not in state, 12, "finding_web_app_error_critical")
    c_av.add(not (html_ and main.status == 200 and A.htmlBytes < 120 and not A.title), 6, "finding_web_empty_response_warning")
    if http_only:
        c_av.add(False, 15, "finding_web_no_https_critical")
    if main.tlsError:
        c_av.add(False, 20, "finding_web_tls_error_critical")
    if variant:
        c_av.add(False, 4, "finding_web_variant_unreachable_warning")
    if alt_probe:
        c_av.add(0 < alt_probe.status < 500, 4, "finding_web_www_inconsistent_warning")
    if main.status < 400:
        c_av.add(soft404.status in (404, 410, 0) or (300 <= soft404.status < 400), 4, "finding_web_soft_404_warning")
    extra_f: list = []
    if "under_construction" in state:
        extra_f.append("finding_web_under_construction_info")
    if "maintenance" in state:
        extra_f.append("finding_web_maintenance_info")
    if main.uaFallback:
        extra_f.append("finding_web_blocks_unknown_agents_info")
    sec = security_header_checks(c_sec, J(main=main, A=A, finalUrl=final_url))
    if tls_det:
        d = tls_days_remaining(tls_det)
        c_sec.add(d >= 0, 15, "finding_web_ssl_expired_critical", "aktarim")
        if d >= 0:
            c_sec.add(d >= 14, 8, "finding_web_ssl_expiring_critical", "aktarim")
            c_sec.add(d >= 30, 2, "finding_web_ssl_expiring_warning", "aktarim")
        c_sec.add(tls_det.protocol in ("TLSv1.2", "TLSv1.3"), 5, "finding_security_tls_old_warning", "aktarim")
    see_info: list = []
    if html_:
        see_info = seo_checks(c_seo, J(main=main, A=A, files=files, finalUrl=final_url))
    else:
        c_seo.add(None, 1, None)
    perf = perf_checks(c_perf, J(main=main, A=A, assets=assets, tlsi=tlsi, dnsMs=dns_t)) if html_ else J(blocking=0, weight=main.transferBytes, sized=[])
    tech = detect_tech(html, main.headers, main.cookies or [], A.generator)
    ver_of = lambda n: next((t.version for t in tech if t.name == n), None)
    php = ver_of("PHP")
    if php and re.search(r"^[0-5]\.|^7\.[0-3]", php):
        c_sec.add(False, 5, "finding_web_eol_php_warning", "basliklar")
    jq = ver_of("jQuery")
    if jq and re.search(r"^1\.|^2\.", jq):
        c_sec.add(False, 3, "finding_web_old_jquery_warning", "basliklar")
    bs = ver_of("Bootstrap")
    if bs and re.search(r"^[1-3]\.", bs):
        c_sec.add(False, 2, "finding_web_old_bootstrap_warning", "basliklar")
    wp = ver_of("WordPress")
    if any(t.name == "WordPress" for t in tech) and wp:
        try:
            if float(re.match(r"\d+(\.\d+)?", wp).group(0)) < 6.0:
                c_sec.add(False, 5, "finding_web_old_wordpress_warning", "basliklar")
        except Exception:
            pass
    gs = J(availability=c_av.score(), security=c_sec.score(), seo=c_seo.score(), performance=c_perf.score())
    W = {"availability": 35, "security": 25, "seo": 20, "performance": 20}
    tw = ts = 0
    for k in gs:
        if gs[k] is not None:
            tw += W[k]
            ts += W[k] * gs[k]
    overall = js_round(ts / tw) if tw else None
    all_f = sort_findings([*c_av.findings(), *c_sec.findings(), *c_seo.findings(), *c_perf.findings(), *extra_f, *see_info])
    if overall is not None:
        if any(re.search(r"web_suspended|web_app_error|web_server_error|web_redirect_loop|web_tls_error|web_no_https|web_status_\d+_critical", f) for f in all_f):
            overall = min(overall, 35)
        if "finding_web_parked_warning" in all_f:
            overall = min(overall, 45)
        if "finding_web_ssl_expired_critical" in all_f:
            overall = min(overall, 25)
        if "finding_seo_noindex_critical" in all_f or "finding_seo_robots_blocks_all_critical" in all_f:
            overall = min(overall, 60)
    down = main.status >= 500 or (main.status >= 400 and main.status not in (401, 403)) or "suspended" in state
    status = ("DOWN" if (main.status >= 500 or "suspended" in state) else "CRITICAL") if down else status_from_score(overall if overall is not None else 0)
    mh = main.headers or {}
    security_headers = J(hsts=bool(mh.get("strict-transport-security")), csp=bool(mh.get("content-security-policy")), xFrame=bool(mh.get("x-frame-options")), xContentType=bool(mh.get("x-content-type-options")),
                         referrerPolicy=bool(mh.get("referrer-policy")), permissionsPolicy=bool(mh.get("permissions-policy") or mh.get("feature-policy")))
    specific = J(
        url=url, finalUrl=final_url, status=main.status, responseTimeMs=main.responseTimeMs, ttfbMs=main.ttfb, redirectChain=[f"{x.status} {x.url}" for x in (main.chain or [])], triedVariants=variant, httpOnly=http_only,
        title=A.title, metaDescription=A.metaDescription, h1Count=A.h1Count, pageState=state, wordCount=A.wordCount, clientRenderedShell=A.spaShell,
        securityHeaders=security_headers, cookies=[f"{k.name} ({'Secure' if k.secure else '!Secure'}, {'HttpOnly' if k.httpOnly else '!HttpOnly'}, SameSite={k.sameSite or 'yok'})" for k in sec.cookies],
        techStack=[f"{t.name} {t.version}" if t.version else t.name for t in tech], technologies=tech, server=mh.get("server") or None,
        robots=J(exists=bool(files.robots.exists), status=files.robots.status, blocksAll=bool(files.robots.blocksAll)), sitemap=J(exists=bool(files.sitemap.exists), valid=bool(files.sitemap.valid), urlCount=files.sitemap.urlCount),
        tls=(J(protocol=tls_det.protocol, cipher=tls_det.cipher.name if tls_det.cipher else None, daysRemaining=tls_days_remaining(tls_det), issuer=tls_issuer(tls_det), http2=bool(tlsi and tlsi.alpn == "h2")) if tls_det else None),
        content=J(htmlKB=js_round(A.htmlBytes / 102.4) / 10, images=A.images.total, scripts=len(A.scripts), stylesheets=len(A.stylesheets), thirdPartyHosts=len(A.thirdPartyHosts), links=A.links),
        performance=J(ttfbMs=main.ttfb, compression=main.encoding, measuredWeightKB=js_round((perf.weight or 0) / 102.4) / 10, renderBlockingScripts=perf.blocking),
        scores=J(availability=gs.availability, security=gs.security, seo=gs.seo, performance=gs.performance, overall=overall))
    common = J(analyzerVersion=V, executionTimeMs=now_ms() - started, findings=all_f, scannedAt=iso(datetime.now(timezone.utc)), score=overall, status=status, target=url)
    return J(data=J(assetType="WEB", commonAnalysis=common, specificAnalysis=specific, analysisMeta=J(scannerVersion=V, analyzer="web")), findings=all_f, errors=errors, statusHint=status,
             confidence=clamp(100 - (10 if (tls_det is None and is_https) else 0) - (10 if not html_ else 0)))


# =====================================================================
# SEO v2
# =====================================================================
async def scan_seo(target_url) -> J:
    started = now_ms()
    V = "seo-analyzer-v2.0"
    pg = await get_page(target_url)
    url, main, variant, prot = pg.url, pg.main, pg.variant, pg.prot
    if prot:
        return protected_result("SEO", V, started, url, main, prot)
    if main.status == 0:
        return down_result("SEO", V, started, url, main, net_error_finding("seo", main))
    if main.status >= 500 or main.status in (404, 410):
        return down_result("SEO", V, started, url, main, "finding_seo_unreachable_critical")
    if not is_html(main):
        return unavailable_result(assetType="SEO", version=V, startedAt=started, target=url, finding="finding_seo_not_html_info", status="UNKNOWN",
                                  note="Adres HTML sayfası döndürmüyor (içerik türü: " + str(main.contentType or "?") + ").", specific=J(url=url, status=main.status))
    final_url = main.finalUrl
    A = analyze_html(main.body, final_url)
    origin = origin_of(final_url)
    c = Checker()
    files = await _safe(load_site_files(origin, urllib.parse.urlsplit(final_url).hostname), EMPTY_FILES())
    info = seo_checks(c, J(main=main, A=A, files=files, finalUrl=final_url))
    state = detect_page_state(main.body, A.title, main.status, A.htmlBytes)
    if "parked" in state:
        info.append("finding_seo_parked_page_critical")
    score = c.score()
    if score is not None and "parked" in state:
        score = min(score, 30)
    return build_result(assetType="SEO", version=V, startedAt=started, target=url, findings=[*c.findings(), *info], score=score,
        specific=J(url=url, finalUrl=final_url, status=main.status, title=A.title, titleLength=len(A.title) if A.title else 0, metaDescription=A.metaDescription,
                   metaDescriptionLength=len(A.metaDescription) if A.metaDescription else 0, canonical=A.canonical, htmlLang=A.htmlLang,
                   h1Count=A.h1Count, h1=A.h1[:3], h2Count=A.h2Count, h3Count=A.h3Count, wordCount=A.wordCount, clientRenderedShell=A.spaShell,
                   images=J(total=A.images.total, missingAlt=A.images.missingAlt, lazy=A.images.lazy), links=A.links,
                   hreflangCount=len(A.hreflang), hreflang=[x.lang for x in A.hreflang[:10]], structuredDataBlocks=A.jsonld.blocks, structuredDataTypes=A.jsonld.types,
                   openGraph=bool(A.og.title and A.og.description and A.og.image), twitterCard=A.twitterCard or None,
                   robotsMeta=A.robotsMeta or None, xRobotsTag=(main.headers or {}).get("x-robots-tag") or None, robotsTxt=bool(files.robots.exists), robotsDetails=files.robots,
                   sitemap=bool(files.sitemap.exists), sitemapDetails=files.sitemap, pageState=state, triedVariants=variant, checks=c.summary(), scores=c.group_scores()))


# =====================================================================
# GÜVENLİK v2
# =====================================================================
def _json_has(rx):
    r = re.compile(rx)
    return lambda b, resp=None: bool(r.search(b)) and not re.match(r"^\s*<(!doctype|html)", b, re.I)


_NOHTML = lambda b: not re.search(r"<html", b, re.I)
_ARCH = lambda b, r: r.status == 200 and bool(re.search(r"zip|octet-stream|gzip|x-tar", r.contentType or "", re.I)) and (r.transferBytes or 0) > 2000
_SQL = lambda b, r=None: bool(re.search(r"CREATE TABLE|INSERT INTO|DROP TABLE", b, re.I)) and _NOHTML(b)
_WPCFG = lambda b, r=None: bool(re.search(r"DB_PASSWORD|DB_NAME", b))
EXPOSED = [
    ("env", "/.env", "critical", lambda b, r=None: bool(re.search(r"^[A-Z][A-Z0-9_]{2,}\s*=", b, re.M)) and _NOHTML(b)),
    ("git", "/.git/HEAD", "critical", lambda b, r=None: bool(re.match(r"^ref:\s*refs/", b.strip()))),
    ("gitconfig", "/.git/config", "critical", lambda b, r=None: "[core]" in b and _NOHTML(b)),
    ("svn", "/.svn/wc.db", "critical", lambda b, r=None: b.startswith("SQLite format 3")),
    ("phpinfo", "/phpinfo.php", "critical", lambda b, r=None: bool(re.search(r"phpinfo\(\)|PHP Version", b, re.I))),
    ("dsstore", "/.DS_Store", "warning", lambda b, r=None: b.startswith("\u0000\u0000\u0000\u0001Bud1")),
    ("serverstatus", "/server-status", "warning", lambda b, r=None: bool(re.search(r"Apache Server Status", b, re.I))),
    ("wpconfig", "/wp-config.php.bak", "critical", _WPCFG), ("wpconfig", "/wp-config.php.old", "critical", _WPCFG), ("wpconfig", "/wp-config.php~", "critical", _WPCFG),
    ("sqldump", "/backup.sql", "critical", _SQL), ("sqldump", "/dump.sql", "critical", _SQL), ("sqldump", "/db.sql", "critical", _SQL),
    ("htpasswd", "/.htpasswd", "critical", lambda b, r=None: bool(re.search(r"^[^:\s<]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})", b, re.M)) and _NOHTML(b)),
    ("awscreds", "/.aws/credentials", "critical", lambda b, r=None: bool(re.search(r"aws_access_key_id", b, re.I))),
    ("npmrc", "/.npmrc", "critical", lambda b, r=None: bool(re.search(r"_authToken|_password", b, re.I)) and _NOHTML(b)),
    ("webconfig", "/web.config", "critical", lambda b, r=None: bool(re.search(r"<configuration[\s>]", b, re.I))),
    ("dockercompose", "/docker-compose.yml", "warning", lambda b, r=None: bool(re.search(r"^services:", b, re.M)) and _NOHTML(b)),
    ("actuatorenv", "/actuator/env", "critical", _json_has(r'"propertySources"|"activeProfiles"')), ("actuator", "/actuator", "warning", _json_has(r'"_links"')),
    ("phpmyadmin", "/phpmyadmin/", "warning", lambda b, r=None: bool(re.search(r"phpMyAdmin", b, re.I))),
    ("adminer", "/adminer.php", "warning", lambda b, r=None: bool(re.search(r"Adminer", b, re.I)) and bool(re.search(r"login", b, re.I))),
    ("wpusers", "/wp-json/wp/v2/users", "warning", lambda b, r=None: bool(re.match(r'^\s*\[\s*\{[\s\S]*"slug"', b))),
    ("xmlrpc", "/xmlrpc.php", "warning", lambda b, r=None: bool(re.search(r"XML-RPC server accepts POST requests only", b, re.I))),
    ("swagger", "/swagger.json", "info", _json_has(r'"swagger"|"openapi"')), ("swagger", "/openapi.json", "info", _json_has(r'"openapi"|"swagger"')),
    ("backuparchive", "/backup.zip", "critical", _ARCH), ("backuparchive", "/site.zip", "critical", _ARCH), ("backuparchive", "/www.zip", "critical", _ARCH),
]


async def scan_security(target_url) -> J:
    started = now_ms()
    V = "security-analyzer-v2.0"
    pg = await get_page(target_url)
    url, main, prot, http_only = pg.url, pg.main, pg.prot, pg.httpOnly
    if prot:
        return protected_result("SECURITY", V, started, url, main, prot)
    if main.status == 0:
        return down_result("SECURITY", V, started, url, main, net_error_finding("security", main))
    final_url = main.finalUrl
    c = Checker()
    host = host_of(final_url)
    A = analyze_html(main.body if is_html(main) else "", final_url)
    https = bool(re.match(r"^https:", final_url, re.I))
    sec = security_header_checks(c, J(main=main, A=A, finalUrl=final_url))
    if http_only:
        c.add(False, 10, "finding_security_https_unavailable_critical", "aktarim")
    if main.tlsError:
        c.add(False, 12, "finding_security_invalid_certificate_critical", "aktarim")
    http_redirect = None
    if host and https:
        r = await http_probe(f"http://{host}", timeout=7000, maxRedirects=0, noUaFallback=True, read_body=False)
        http_redirect = 300 <= r.status < 400 and bool(re.match(r"^https:", str((r.headers or {}).get("location") or ""), re.I))
        if r.status > 0:
            c.add(http_redirect, 8, "finding_security_no_https_redirect_warning", "aktarim")
    cert = legacy = None
    if https and host:
        t, pv = await asyncio.gather(_safe(get_tls_details(host), None), _safe(probe_tls_versions(host), None))
        if t:
            d = tls_days_remaining(t)
            cert = J(daysRemaining=d, protocol=t.protocol, trusted=t.authorized, trustError=t.authError)
            c.add(d >= 0, 10, "finding_security_cert_expired_critical", "aktarim")
            if d >= 0:
                c.add(d >= 14, 8, "finding_security_cert_expiring_critical", "aktarim")
                c.add(d >= 30 or d < 14, 2, "finding_security_cert_expiring_warning", "aktarim")
            c.add(t.protocol in ("TLSv1.3", "TLSv1.2"), 6, "finding_security_tls_old_warning", "aktarim")
        if pv:
            legacy = [v for v in ("TLSv1", "TLSv1.1") if pv.get(v) is True]
            c.add(len(legacy) == 0, 6, "finding_security_tls_legacy_enabled_warning", "aktarim")
    origin = origin_of(final_url)

    async def probe_one(e, _i):
        slug, p, sev, test = e
        r = await http_probe(origin + p, timeout=5000, maxRedirects=1, noUaFallback=True, max_bytes=20000)
        return J(slug=slug, path=p, sev=sev) if (r.status == 200 and test(str(r.body or "")[:4000], r)) else None
    probes = await pool(EXPOSED, 8, probe_one)
    exposed = [p for p in probes if p]
    uniq: list = []
    for e in exposed:
        if not any(u.slug == e.slug for u in uniq):
            uniq.append(e)
    sectxt = await http_probe(origin + "/.well-known/security.txt", timeout=5000, maxRedirects=2, noUaFallback=True, max_bytes=20000)
    has_sec_txt = sectxt.status == 200 and bool(re.search(r"contact:", sectxt.body or "", re.I))
    crit_exposed = [e for e in uniq if e.sev == "critical"]
    c.add(len(crit_exposed) == 0, 25, None, "dosyalar")
    c.add(len([e for e in uniq if e.sev == "warning"]) == 0, 8, None, "dosyalar")
    extra_f = [f"finding_security_exposed_{e.slug}_{e.sev}" for e in uniq]
    if not has_sec_txt:
        extra_f.append("finding_security_missing_security_txt_info")
    findings = [*c.findings(), *extra_f]
    scores = c.group_scores()
    score = c.score()
    if score is not None and crit_exposed:
        score = min(score, 35)
    if score is not None and any(re.search(r"mixed_content_critical|insecure_form_critical|invalid_certificate|cert_expired|https_unavailable", f) for f in findings):
        score = min(score, 45)
    mh = main.headers or {}
    return build_result(assetType="SECURITY", version=V, startedAt=started, target=url, findings=findings, score=score,
        specific=J(url=url, finalUrl=final_url, https=https, hsts=sec.hsts, hstsMaxAgeDays=sec.hstsMaxAgeDays, csp=sec.csp, httpToHttpsRedirect=http_redirect, mixedContent=A.mixed,
                   serverHeader=mh.get("server") or None, poweredBy=mh.get("x-powered-by") or None,
                   cookies=[f"{k.name} ({'Secure' if k.secure else '!Secure'}, {'HttpOnly' if k.httpOnly else '!HttpOnly'}, SameSite={k.sameSite or 'yok'})" for k in sec.cookies],
                   certificate=cert, legacyTlsEnabled=legacy, securityTxt=has_sec_txt, thirdPartyScriptsWithoutSri=A.externalScriptsNoSri,
                   exposedFiles=[f"{e.path} ({e.sev})" for e in uniq], checkedFiles=len(EXPOSED), checks=c.summary(), scores=scores))


# =====================================================================
# PERFORMANS v2
# =====================================================================
async def scan_performance(target_url) -> J:
    started = now_ms()
    V = "performance-analyzer-v2.0"
    pg = await get_page(target_url, noUaFallback=False)
    url, main, prot = pg.url, pg.main, pg.prot
    if prot:
        return protected_result("PERFORMANCE", V, started, url, main, prot)
    if main.status == 0:
        return down_result("PERFORMANCE", V, started, url, main, net_error_finding("perf", main))
    if main.status >= 400 and main.status not in (401, 403):
        return down_result("PERFORMANCE", V, started, url, main, "finding_perf_unreachable_critical")
    final_url = main.finalUrl
    host = host_of(final_url)
    c = Checker()
    A = analyze_html(main.body if is_html(main) else "", final_url)

    async def repeat_job():
        xs = []
        for _ in range(2):
            r = await request(final_url, timeout=10000, read_body=False, insecure=True)
            if r.status:
                xs.append(r.ttfb)
        return xs
    tlsi, assets, dns_ms, repeat = await asyncio.gather(
        tls_alpn(host) if (re.match(r"^https:", final_url, re.I) and host) else _ret(None),
        _safe(sample_assets(A, final_url, 6), []) if is_html(main) else _ret([]),
        _dns_lookup_ms(host), repeat_job())
    ttfbs = sorted(x for x in [main.ttfb, *repeat] if x is not None)
    if ttfbs:
        main.ttfb = ttfbs[len(ttfbs) // 2]  # medyan
    p = perf_checks(c, J(main=main, A=A, assets=assets, tlsi=tlsi, dnsMs=dns_ms))
    h = main.headers or {}
    scores = c.group_scores()
    kb = lambda n: js_round((n or 0) / 102.4) / 10
    return build_result(assetType="PERFORMANCE", version=V, startedAt=started, target=url, findings=c.findings(), score=c.score(),
        specific=J(url=url, finalUrl=final_url, status=main.status, ttfbMs=main.ttfb, ttfbSamplesMs=ttfbs, totalLoadMs=main.total, redirectChainMs=p.chainMs,
                   htmlTransferKB=kb(main.transferBytes), htmlRawKB=kb(main.rawBytes), compression=main.encoding, protocol=(tlsi.alpn if tlsi else None) or None,
                   tlsVersion=(tlsi.tlsVersion if tlsi else None) or None, tlsHandshakeMs=(tlsi.handshakeMs if tlsi else None), dnsLookupMs=dns_ms,
                   http3Advertised=bool(re.search(r"h3", str(h.get("alt-svc") or ""))), redirectHops=main.redirects, redirectChain=[f"{x.status} {x.url}" for x in (main.chain or [])],
                   externalScripts=len(A.scripts), renderBlockingScripts=p.blocking, stylesheets=len(A.stylesheets), images=A.images.total, lazyImages=A.images.lazy,
                   imagesWithoutDimensions=A.images.noDimensions, thirdPartyHosts=A.thirdPartyHosts[:12], domNodes=A.domNodes, measuredWeightKB=kb(p.weight), jsKB=kb(p.jsBytes),
                   cssKB=kb(p.cssBytes), imageKBSampled=kb(p.imgBytes),
                   sampledAssets=[f"{a.kind.upper()} {a.status} {a.enc or 'sıkıştırmasız'} {js_round(a.transfer / 1024)}KB cache:{a.cache or 'yok'}" for a in p.sized],
                   note="Tarayıcıda çalışan JavaScript ile sonradan yüklenen kaynaklar ölçülmez; ölçüm HTML'deki kaynaklara dayanır.", checks=c.summary(), scores=scores))


# =====================================================================
# UPTIME & GECİKME v2
# =====================================================================
async def scan_uptime(target_url, extra=None) -> J:
    started = now_ms()
    V = "uptime-analyzer-v2.0"
    url = ensure_url(target_url)
    N0 = 6
    samples: list = []
    for i in range(N0):
        if i >= 3 and all(not s.up for s in samples):
            break
        r = await request(url, timeout=8000, read_body=True, max_bytes=200000, insecure=True)
        samples.append(J(status=r.status, ms=r.total, ttfb=r.ttfb, up=0 < r.status < 500, protectedBy=detect_bot_protection(r) if r.status >= 400 else None,
                         err=r.errorInfo.kind if r.errorInfo else None, retryAfter=(r.headers or {}).get("retry-after"), maint=r.status == 503))
        if i < N0 - 1:
            await sleep(500)
    N = len(samples)
    host = host_of(url)
    dns_ms = await _dns_lookup_ms(host) if host else None
    u_port = 443 if re.match(r"^https:", url, re.I) else 80
    try:
        pp = urllib.parse.urlsplit(url).port
        if pp:
            u_port = pp
    except Exception:
        pass
    tcp, tlsi = await asyncio.gather(tcp_port_check(host, u_port, 4000) if host else _ret(None), tls_alpn(host) if (re.match(r"^https:", url, re.I) and host) else _ret(None))
    ups = [s for s in samples if s.up]
    times = sorted((s.ttfb if s.ttfb is not None else s.ms) for s in ups)
    rate = js_round(len(ups) / N * 100)
    mean = avg(times)
    jitter = js_round(math.sqrt(sum((t - mean) ** 2 for t in times) / len(times))) if len(times) > 1 else 0
    p95 = times[min(len(times) - 1, math.ceil(len(times) * 0.95) - 1)] if times else None
    median = times[len(times) // 2] if times else None
    c = Checker()
    server_errs = len([s for s in samples if s.status >= 500])
    c.add(rate == 100, 40, "finding_uptime_down_critical" if rate == 0 else "finding_uptime_intermittent_critical", "erisim")
    c.add(rate >= 80, 10, None, "erisim")
    c.add(server_errs == 0, 5, "finding_uptime_server_errors_critical", "erisim")
    if times:
        c.add(median < 800, 20, "finding_uptime_slow_response_warning", "gecikme")
        c.add(p95 < 2000, 10, "finding_uptime_high_p95_warning", "gecikme")
        c.add(jitter < 300, 10, "finding_uptime_unstable_latency_warning", "gecikme")
    c.add(dns_ms < 300 if dns_ms is not None else None, 5, "finding_uptime_slow_dns_warning", "gecikme")
    c.add((tcp.open and tcp.latencyMs < 500) if tcp else None, 5, "finding_uptime_slow_connect_warning", "gecikme")
    findings = c.findings()
    last_err = next((s for s in samples if s.err), None)
    if rate == 0 and last_err:
        findings.append({"dns": "finding_uptime_dns_failure_critical", "refused": "finding_uptime_connection_refused_critical", "timeout": "finding_uptime_timeout_critical",
                         "tls": "finding_uptime_tls_failure_critical"}.get(last_err.err, "finding_uptime_unreachable_critical"))
    if ups and any(s.protectedBy for s in samples):
        findings.append("finding_web_bot_protection_info")
    if any(s.maint for s in samples):
        findings.append("finding_uptime_maintenance_info")
    scores = c.group_scores()
    return build_result(assetType="UPTIME", version=V, startedAt=started, target=url, findings=findings, score=0 if rate == 0 else c.score(), status="DOWN" if rate == 0 else None,
        specific=J(url=url, samples=N, successRatePct=rate, statusCodes=[s.status for s in samples], failures=[(s.err or f"HTTP {s.status}") for s in samples if not s.up],
                   minMs=times[0] if times else None, avgMs=mean, medianMs=median, p95Ms=p95, maxMs=times[-1] if times else None, jitterMs=jitter, dnsLookupMs=dns_ms,
                   tcpConnectMs=tcp.latencyMs if (tcp and tcp.open) else None, tlsHandshakeMs=tlsi.handshakeMs if tlsi else None,
                   note="Tek noktadan (sunucu konumu) anlık ölçüm; sürekli izleme değildir. 4xx yanıtlar 'sunucu ayakta' sayılır, ölçüm ilk bayta kadar geçen süreyi (TTFB) esas alır.",
                   checks=c.summary(), scores=scores))


# =====================================================================
# API v2
# =====================================================================
STACK_LEAK = re.compile(r"(\bat [\w$.<>]+\([\w$.]+\.(java|kt|cs):\d+\))|Traceback \(most recent call last\)|SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|System\.(NullReference|InvalidOperation)Exception|node_modules/|/var/www/|C:\\\\inetpub|stack trace:", re.I)


def _js_typeof(j):
    if isinstance(j, bool):
        return "boolean"
    if isinstance(j, (int, float)):
        return "number"
    if isinstance(j, str):
        return "string"
    return "object"


async def scan_api(target_url) -> J:
    started = now_ms()
    V = "api-analyzer-v2.0"
    url = ensure_url(target_url)
    main = await http_probe(url, headers={"Accept": "application/json"}, timeout=12000, maxRedirects=4)
    prot = detect_bot_protection(main) if main.status else None
    if prot:
        return protected_result("API", V, started, url, main, prot)
    if main.status == 0:
        return down_result("API", V, started, url, main, net_error_finding("api", main))
    if main.status >= 500:
        return down_result("API", V, started, url, main, "finding_api_server_error_critical")
    final_url = main.finalUrl
    h = main.headers or {}
    c = Checker()
    ct = str(h.get("content-type") or "")
    auth_required = main.status in (401, 403)
    json_ok = json_keys = None
    if re.search(r"json", ct, re.I):
        try:
            j = json.loads(main.body)
            json_ok = True
            json_keys = f"array({len(j)})" if isinstance(j, list) else list(j.keys())[:8] if isinstance(j, dict) else _js_typeof(j)
        except Exception:
            json_ok = False
    try:
        origin = origin_of(final_url)
    except Exception:
        origin = url
    evil = "https://dac-cors-test.example"

    async def repeat_job():
        xs = []
        for _ in range(2):
            r = await request(final_url, timeout=9000, read_body=False, insecure=True, headers={"Accept": "application/json"})
            if r.status:
                xs.append(r.total)
        return xs
    pre, cors_get, bad404, repeat = await asyncio.gather(
        http_probe(final_url, method="OPTIONS", timeout=7000, maxRedirects=0, noUaFallback=True, read_body=False,
                   headers={"Origin": evil, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"}),
        http_probe(final_url, timeout=7000, maxRedirects=0, noUaFallback=True, read_body=False, headers={"Origin": evil, "Accept": "application/json"}),
        http_probe(origin + "/__dac_not_found__" + str(now_ms()), timeout=7000, maxRedirects=0, noUaFallback=True, headers={"Accept": "application/json"}),
        repeat_job())
    ph, ch, bh = pre.headers or {}, cors_get.headers or {}, bad404.headers or {}
    acao = ph.get("access-control-allow-origin") or ch.get("access-control-allow-origin") or None
    creds = str(ph.get("access-control-allow-credentials") or ch.get("access-control-allow-credentials") or "").lower() == "true"
    reflects = acao == evil
    rl = [k for k in h.keys() if re.search(r"ratelimit|retry-after", k, re.I)]
    times = sorted(x for x in [main.responseTimeMs, *repeat] if x is not None)
    med = times[len(times) // 2]
    methods = str(ph.get("allow") or ph.get("access-control-allow-methods") or "") or None
    c.add(main.status < 400 or auth_required, 25, "finding_api_error_status_critical", "erisim")
    c.add(med < 1000, 15, "finding_api_slow_response_warning", "erisim")
    c.add(bool(main.encoding) or main.rawBytes < 1400 or not re.search(r"json|text", ct, re.I), 3, "finding_api_no_compression_warning", "erisim")
    c.add(bool(re.match(r"^https:", final_url, re.I)), 10, "finding_api_not_https_critical", "guvenlik")
    c.add(not ((reflects or acao == "*") and creds), 12, "finding_api_cors_credentials_critical", "guvenlik")
    c.add((not reflects) or creds is False, 3, "finding_api_cors_reflects_origin_warning", "guvenlik")
    c.add(bool(re.search(r"nosniff", str(h.get("x-content-type-options") or ""), re.I)), 5, "finding_api_missing_nosniff_warning", "guvenlik")
    if re.match(r"^https:", final_url, re.I):
        c.add(bool(h.get("strict-transport-security")), 5, "finding_api_missing_hsts_warning", "guvenlik")
    c.add(not re.search(r"\d+\.\d+", str(h.get("server") or "") + str(h.get("x-powered-by") or "")), 4, "finding_api_version_disclosure_warning", "guvenlik")
    c.add((not STACK_LEAK.search(str(bad404.body or ""))) and (not STACK_LEAK.search(str(main.body or ""))), 10, "finding_api_error_leaks_stacktrace_critical", "guvenlik")
    c.add((not h.get("x-debug-token")) and (not h.get("x-debug-token-link")), 3, "finding_api_debug_headers_warning", "guvenlik")
    if json_ok is not None:
        c.add(json_ok, 10, "finding_api_invalid_json_critical", "tasarim")
    elif not auth_required:
        c.add(False, 6, "finding_api_not_json_warning", "tasarim")
    if json_ok:
        c.add(bool(re.search(r"charset|json", ct, re.I)), 1, None, "tasarim")
    c.add(len(rl) > 0, 8, "finding_api_no_rate_limit_headers_warning", "tasarim")
    c.add(bool(re.search(r"json", str(bh.get("content-type") or ""), re.I)), 4, "finding_api_error_not_json_warning", "tasarim")
    c.add(bad404.status in (404, 401, 403), 4, "finding_api_unknown_route_status_warning", "tasarim")
    c.add(bool(re.search(r"/v\d+(/|$)", final_url, re.I)) or bool(h.get("api-version")) or bool(h.get("x-api-version")), 4, "finding_api_no_versioning_warning", "tasarim")
    findings = c.findings()
    if auth_required:
        findings.append("finding_api_auth_required_info")
    scores = c.group_scores()
    return build_result(assetType="API", version=V, startedAt=started, target=url, findings=findings, score=c.score(),
        specific=J(url=url, finalUrl=final_url, status=main.status, responseTimeMs=main.responseTimeMs, medianResponseMs=med, contentType=ct or None, compression=main.encoding, validJson=json_ok,
                   jsonShape=json_keys, authRequired=auth_required, cors=J(allowOrigin=acao, allowCredentials=creds, reflectsArbitraryOrigin=reflects, allowMethods=methods), rateLimitHeaders=rl,
                   unknownRouteStatus=bad404.status, server=h.get("server") or None, redirects=main.redirects, checks=c.summary(), scores=scores))


async def http_fetch(url: str, timeout: int = 9000, headers: Optional[dict] = None) -> J:
    """JSON GET; durum, gövde ve (küçük harfli) başlıkları döndürür. Ağ hatasında status=0."""
    try:
        connector = aiohttp.TCPConnector(resolver=SafeResolver(), force_close=True, limit=0)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout / 1000), headers={"User-Agent": UA_BOT, **(headers or {})}) as s:
            async with s.get(url, max_redirects=4) as r:
                raw = await r.content.read(4_000_000)
                try:
                    data = json.loads(raw.decode("utf-8", "replace"))
                except Exception:
                    data = None
                return J(status=r.status, data=data, headers={k.lower(): v for k, v in r.headers.items()})
    except Exception:
        return J(status=0, data=None, headers={})


def pfloat(x):
    try:
        m = re.match(r"\s*([+-]?(?:\d+\.?\d*|\.\d+))", str(x))
        return float(m.group(1)) if m else None
    except Exception:
        return None


def pint(x):
    try:
        m = re.match(r"\s*([+-]?\d+)", str(x))
        return int(m.group(1)) if m else None
    except Exception:
        return None


# =====================================================================
# MOBİL UYGULAMA v2 (Google Play / App Store)
# =====================================================================
MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}


def parse_en_date(s):
    m = re.search(r"([A-Za-z]{3})[a-z]*\.? (\d{1,2}), (\d{4})", str(s or ""))
    if m and m.group(1).lower() in MONTHS:
        try:
            return datetime(int(m.group(3)), MONTHS[m.group(1).lower()], int(m.group(2)), tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


async def scan_mobile_app(inp) -> J:
    started = now_ms()
    V = "mobile-analyzer-v2.0"
    raw = str(inp or "").strip()
    store = id_ = None
    country = "tr"
    play = re.search(r"[?&]id=([A-Za-z0-9._]+)", raw) or re.match(r"^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)$", raw)
    apple = re.search(r"apps\.apple\.com/(?:([a-z]{2})/)?[^?#]*id(\d{5,})", raw, re.I) or re.match(r"^(?:id)?(\d{7,})$", raw, re.I)
    if re.search(r"play\.google\.com", raw, re.I) and play:
        store, id_ = "play", play.group(1)
    elif apple:
        store = "appstore"
        g = apple.groups()
        id_ = (g[1] if len(g) > 1 and g[1] else g[0])
        if len(g) > 1 and g[1] and g[0]:
            country = g[0]
    elif play:
        store, id_ = "play", play.group(1)
    if not store:
        return build_result(assetType="MOBILE_APP", version=V, startedAt=started, target=raw, findings=["finding_mobile_invalid_target_critical"], score=0, status="ERROR",
                            specific=J(hint="Paket adı (com.firma.uygulama), Play Store linki veya App Store linki girin."))
    c = Checker()
    info = J()
    extra_f: list = []
    if store == "appstore":
        a = None
        used_country = None
        for cc in dict.fromkeys([country, "tr", "us", "de", "gb"]):
            r = await http_fetch(f"https://itunes.apple.com/lookup?id={id_}&country={cc}", 9000)
            if r.status == 429:
                return unavailable_result(assetType="MOBILE_APP", version=V, startedAt=started, target=raw, finding="finding_mobile_store_unavailable_info", status="UNKNOWN",
                                          note="App Store sorgu sınırına takıldı; biraz sonra tekrar deneyin.", specific=J(store="App Store", id=id_))
            res = (r.data or {}).get("results") if isinstance(r.data, dict) else None
            a = jj(res[0]) if res else None
            if a:
                used_country = cc
                break
        if not a:
            return build_result(assetType="MOBILE_APP", version=V, startedAt=started, target=raw, findings=["finding_mobile_not_found_critical"], score=0, status="DOWN",
                                specific=J(store="App Store", id=id_, note="Uygulama kontrol edilen mağazalarda (TR, US, DE, GB) bulunamadı: kaldırılmış olabilir."))
        age = days_since(a.currentVersionReleaseDate)
        r1 = lambda v: js_round(v * 10) / 10
        info = J(store="App Store", id=id_, name=a.trackName, developer=a.sellerName, bundleId=a.bundleId, version=a.version, rating=r1(a.averageUserRating) if a.averageUserRating else None,
                 ratingCount=a.userRatingCount or 0, ratingCurrentVersion=r1(a.averageUserRatingForCurrentVersion) if a.averageUserRatingForCurrentVersion else None,
                 ratingCountCurrentVersion=a.userRatingCountForCurrentVersion or 0, lastUpdate=a.currentVersionReleaseDate, daysSinceUpdate=age, firstRelease=a.releaseDate,
                 minOs=a.minimumOsVersion, price=a.formattedPrice, category=a.primaryGenreName, sizeMB=js_round(a.fileSizeBytes / 1048576) if a.fileSizeBytes else None,
                 contentRating=a.contentAdvisoryRating, languages=len(a.languageCodesISO2A or []), availableInCountry=used_country,
                 releaseNotes=str(a.releaseNotes)[:160] if a.releaseNotes else None)
        if used_country != country:
            extra_f.append("finding_mobile_not_in_home_store_info")
        if info.ratingCurrentVersion is not None and info.ratingCountCurrentVersion >= 10:
            c.add(info.ratingCurrentVersion >= 3.5, 10, "finding_mobile_low_current_rating_warning", "kalite")
        if info.minOs and (pfloat(info.minOs) or 0) < 13:
            extra_f.append("finding_mobile_old_min_os_info")
    else:
        r = None
        used_gl = None
        for gl in ("US", "TR", "DE"):
            r = await http_probe(f"https://play.google.com/store/apps/details?id={urllib.parse.quote(id_, safe='')}&hl=en&gl={gl}", timeout=10000, maxRedirects=3, noUaFallback=True)
            if r.status == 200:
                used_gl = gl
                break
            if r.status != 404:
                break
        if r.status == 404:
            return build_result(assetType="MOBILE_APP", version=V, startedAt=started, target=raw, findings=["finding_mobile_not_found_critical"], score=0, status="DOWN",
                                specific=J(store="Google Play", id=id_, note="Uygulama kontrol edilen mağazalarda (US, TR, DE) bulunamadı: kaldırılmış olabilir."))
        if not r.ok:
            return unavailable_result(assetType="MOBILE_APP", version=V, startedAt=started, target=raw, finding="finding_mobile_store_unavailable_info", status="UNKNOWN",
                                      note="Google Play yanıt vermedi veya erişimi kısıtladı.", specific=J(store="Google Play", id=id_, status=r.status))
        b = r.body or ""
        ld = None
        tk = tokenize_html(b)
        for t in tk.tags:
            if t.n == "script" and not t.c and re.search(r"application/ld\+json", t.a, re.I):
                try:
                    j = json.loads(t.body or "")
                    if isinstance(j, dict) and (j.get("aggregateRating") or j.get("@type") == "SoftwareApplication"):
                        ld = jj(j)
                        break
                except Exception:
                    continue
        ar = ld.aggregateRating if ld else None
        mrat = re.search(r'"ratingValue":\s*"?([\d.]+)"?', b)
        rating = pfloat(ar.ratingValue) if (ar and ar.ratingValue is not None) else pfloat(mrat.group(1) if mrat else None)
        if ar:
            rc = pint(ar.ratingCount or ar.reviewCount)
        else:
            mrc = re.search(r'"ratingCount":\s*"?(\d+)"?', b)
            rc = pint(mrc.group(1) if mrc else None)
        tt = next((t for t in tk.tags if t.n == "title" and not t.c), None)
        title_txt = re.sub(r"\s*-\s*Apps on Google Play.*", "", (tt.body if tt and tt.body else ""), flags=re.I).strip()
        name = (ld.name if ld and ld.name else None) or title_txt
        mi = re.search(r">([\d.,]+[KMB]?\+)</div><div[^>]*>Downloads", b, re.I)
        installs = mi.group(1) if mi else None
        mu = re.search(r"Updated on</div><div[^>]*>([^<]+)<", b, re.I) or re.search(r"Updated on[^A-Za-z0-9]{0,40}([A-Za-z]{3,9} \d{1,2}, \d{4})", b, re.I)
        upd = parse_en_date(mu.group(1) if mu else None)
        dsu = days_since(upd) if upd else None
        price = ld.offers.price if (ld and ld.offers and ld.offers.price is not None) else None
        info = J(store="Google Play", id=id_, name=name or None, developer=(ld.author.name if ld and ld.author else None) or None, category=(ld.applicationCategory if ld else None) or None,
                 price=str(price) if price is not None else None, rating=js_round(rating * 10) / 10 if rating is not None else None, ratingCount=rc, downloads=installs,
                 lastUpdate=iso(upd) if upd else None, daysSinceUpdate=dsu, availableInCountry=used_gl, note="Play Store resmi API sunmaz; ayrıntılar sayfadan okunur, bulunamayan alanlar boş kalır.")
        if info.rating is None and info.daysSinceUpdate is None:
            extra_f.append("finding_mobile_details_unavailable_info")
    c.add(True, 40, None, "yayin")
    if info.rating is not None:
        c.add(info.rating >= 4.0, 25, "finding_mobile_low_rating_warning", "kalite")
    if info.ratingCount is not None:
        c.add(info.ratingCount >= 50, 10, "finding_mobile_few_ratings_info", "kalite")
    if info.daysSinceUpdate is not None:
        c.add(info.daysSinceUpdate <= 365, 15, "finding_mobile_stale_critical", "bakim")
        if info.daysSinceUpdate <= 365:
            c.add(info.daysSinceUpdate <= 180, 10, "finding_mobile_aging_warning", "bakim")
    scores = c.group_scores()
    measurable = info.rating is not None or info.daysSinceUpdate is not None
    return build_result(assetType="MOBILE_APP", version=V, startedAt=started, target=raw, findings=[*c.findings(), *extra_f], score=c.score() if measurable else None,
                        status=None if measurable else "ACTIVE", specific=J(**info, scores=scores))


# =====================================================================
# KOD DEPOSU (GitHub) v2
# =====================================================================
SECRET_FILES = re.compile(r"^(\.env(\..*)?|id_rsa|id_dsa|.*\.pem|.*\.p12|.*\.pfx|credentials\.json|serviceaccountkey\.json|.*-firebase-adminsdk-.*\.json|secrets?\.(json|ya?ml)|\.npmrc|\.pypirc|terraform\.tfstate)$", re.I)


async def scan_repository(inp) -> J:
    started = now_ms()
    V = "repo-analyzer-v2.0"
    raw = str(inp or "").strip()
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/?#]|$)", raw, re.I) or re.match(r"^([\w.-]+)/([\w.-]+)$", raw)
    if not m:
        return build_result(assetType="REPOSITORY", version=V, startedAt=started, target=raw, findings=["finding_repo_invalid_target_critical"], score=0, status="ERROR", specific=J(hint="sahip/depo biçiminde veya GitHub linki girin."))
    owner, repo = m.group(1), m.group(2)
    token = env("GITHUB_TOKEN")
    deep = bool(token)
    H = {"User-Agent": "DigitalAssetCenter", "Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
    gh = lambda p: http_fetch(f"https://api.github.com/repos/{owner}/{repo}{p}", 9000, H)
    r = await gh("")
    if r.status in (403, 429) and str(r.headers.get("x-ratelimit-remaining")) == "0":
        return unavailable_result(assetType="REPOSITORY", version=V, startedAt=started, target=f"{owner}/{repo}", finding="finding_repo_rate_limited_info", status="UNKNOWN",
                                  note="GitHub hız sınırına takıldı. Sunucuya GITHUB_TOKEN ekleyerek sınırı yükseltebilirsiniz.")
    if r.status == 404:
        return build_result(assetType="REPOSITORY", version=V, startedAt=started, target=f"{owner}/{repo}", findings=["finding_repo_not_found_critical"], score=0, status="DOWN", specific=J(owner=owner, repo=repo, note="Depo yok ya da özel (private)."))
    if r.status != 200:
        return unavailable_result(assetType="REPOSITORY", version=V, startedAt=started, target=f"{owner}/{repo}", finding="finding_repo_api_error_info", status="UNKNOWN", note=f"GitHub API {r.status} döndürdü.")
    d = jj(r.data or {})
    rel, com, root, gh_dir, contrib, pulls, langs = await asyncio.gather(
        gh("/releases/latest"), gh("/community/profile"), gh("/contents/"), gh("/contents/.github"),
        gh("/contributors?per_page=1&anon=true") if deep else _ret(None), gh("/pulls?state=open&per_page=1") if deep else _ret(None), gh("/languages") if deep else _ret(None))
    push_age = days_since(d.pushed_at)
    rel_age = days_since(rel.data.get("published_at")) if (rel.status == 200 and isinstance(rel.data, dict)) else None
    files = (com.data.get("files") or {}) if (com.status == 200 and isinstance(com.data, dict)) else {}
    names = [str(x.get("name")) for x in root.data] if (root.status == 200 and isinstance(root.data, list)) else None
    gh_names = [str(x.get("name")) for x in gh_dir.data] if (gh_dir.status == 200 and isinstance(gh_dir.data, list)) else []
    secrets = [n for n in names if SECRET_FILES.match(n) and not re.search(r"\.(example|sample|template)$", n, re.I)] if names is not None else []
    has_security = (any(re.match(r"^security\.md$", n, re.I) for n in names) or any(re.match(r"^security\.md$", n, re.I) for n in gh_names)) if names is not None else None
    has_ci = ("workflows" in gh_names or any(re.match(r"^(\.travis\.yml|\.gitlab-ci\.yml|azure-pipelines\.yml|\.circleci|Jenkinsfile|bitbucket-pipelines\.yml)$", n, re.I) for n in names)) if names is not None else None
    has_dep = (any(re.match(r"^dependabot\.ya?ml$", n, re.I) for n in gh_names) or any(re.match(r"^renovate\.json5?$", n, re.I) for n in names) or any(re.match(r"^renovate\.json5?$", n, re.I) for n in gh_names)) if names is not None else None
    has_tests = any(re.match(r"^(tests?|__tests__|spec|specs)$", n, re.I) for n in names) if names is not None else None
    has_lock = any(re.match(r"^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$", n, re.I) for n in names) if names is not None else None

    def count_from_link(res):
        l = str(((res.headers if res else None) or {}).get("link") or "")
        mm = re.search(r'[?&]page=(\d+)>; rel="last"', l)
        if mm:
            return int(mm.group(1))
        return len(res.data) if (res and isinstance(res.data, list)) else None
    contributors = count_from_link(contrib) if (contrib and contrib.status == 200) else None
    open_prs = count_from_link(pulls) if (pulls and pulls.status == 200) else None
    c = Checker()
    extra_f: list = []
    c.add(not d.archived, 20, "finding_repo_archived_warning", "bakim")
    c.add(push_age is not None and push_age <= 365, 20, "finding_repo_inactive_critical", "bakim")
    if push_age is not None and push_age <= 365:
        c.add(push_age <= 90, 10, "finding_repo_stale_warning", "bakim")
    c.add(bool(d.license), 10, "finding_repo_no_license_warning", "topluluk")
    if com.status == 200:
        c.add(bool(files.get("readme")), 8, "finding_repo_no_readme_warning", "topluluk")
        c.add(bool(files.get("contributing")) or bool(files.get("code_of_conduct")), 4, "finding_repo_no_contributing_info", "topluluk")
    c.add((d.open_issues_count or 0) < 100, 8, "finding_repo_many_open_issues_warning", "bakim")
    c.add(rel.status == 200, 5, "finding_repo_no_releases_info", "bakim")
    if names is not None:
        c.add(len(secrets) == 0, 20, "finding_repo_secret_file_committed_critical", "guvenlik")
        c.add(has_security, 4, "finding_repo_no_security_policy_info", "guvenlik")
        c.add(has_ci, 4, "finding_repo_no_ci_info", "bakim")
        if has_lock is False and re.search(r"javascript|typescript|python|go|rust|php|ruby", d.language or "", re.I):
            c.add(False, 3, "finding_repo_no_lockfile_info", "guvenlik")
    if deep and names is not None:
        c.add(has_dep, 4, "finding_repo_no_dependency_updates_info", "guvenlik")
    if contributors == 1:
        extra_f.append("finding_repo_single_contributor_info")
    if d.fork:
        extra_f.append("finding_repo_is_fork_info")
    if d.has_issues is False:
        extra_f.append("finding_repo_issues_disabled_info")
    scores = c.group_scores()
    specific = J(repo=d.full_name, description=d.description or None, visibility=d.visibility or ("private" if d.private else "public"), language=d.language,
                 license=(d.license.spdx_id if d.license else None) or None, stars=d.stargazers_count, forks=d.forks_count, watchers=d.subscribers_count, openIssues=d.open_issues_count,
                 openPullRequests=open_prs, contributors=contributors, defaultBranch=d.default_branch, archived=d.archived, isFork=d.fork, createdAt=d.created_at, ageDays=days_since(d.created_at),
                 lastPush=d.pushed_at, daysSinceLastPush=push_age,
                 latestRelease=(f"{rel.data.get('tag_name')} ({rel_age} gün önce)" if (rel.status == 200 and isinstance(rel.data, dict)) else None),
                 communityHealthPct=(com.data.get("health_percentage") if (com.status == 200 and isinstance(com.data, dict)) else None), sizeKB=d.size,
                 hygiene=(J(securityPolicy=has_security, ci=has_ci, dependencyUpdates=has_dep if deep else "GITHUB_TOKEN gerekli", tests=has_tests, lockfile=has_lock, committedSecretFiles=secrets) if names is not None else "Kök dizin listelenemedi"),
                 scores=scores)
    if langs and langs.status == 200 and isinstance(langs.data, dict):
        specific.languages = list(langs.data.keys())[:6]
    if not deep:
        specific.note = "Token tanımlı değil: GitHub hız sınırını korumak için bazı derin kontroller (katkıcı, PR, bağımlılık güncelleme) atlandı. Sunucuya GITHUB_TOKEN ekleyin."
    return build_result(assetType="REPOSITORY", version=V, startedAt=started, target=f"{owner}/{repo}", findings=[*c.findings(), *extra_f], score=c.score(), specific=specific)


# =====================================================================
# MARKA KORUMASI v2
# =====================================================================
BRAND_TLDS = ["com", "net", "org", "io", "co", "app", "dev", "info", "biz", "online", "store", "tech", "ai", "com.tr", "net.tr", "org.tr", "de", "fr", "es", "it", "nl", "co.uk", "eu", "us", "ae", "sa", "shop", "site", "xyz"]
HOMOGLYPH = {"o": ["0"], "l": ["1", "i"], "i": ["l", "1"], "a": ["e"], "e": ["a"], "s": ["5"], "g": ["q"], "q": ["g"], "m": ["rn"], "w": ["vv"], "d": ["cl"], "b": ["6"]}
KEYWORDS = ["login", "secure", "support", "account", "my", "pay", "official", "app"]


def typo_variants(label: str, cap: int = 30) -> list:
    out: dict = {}
    n = len(label)
    for i in range(n):
        out[label[:i] + label[i + 1:]] = 1
        out[label[:i] + label[i] + label[i:]] = 1
        if i < n - 1:
            out[label[:i] + label[i + 1] + label[i] + label[i + 2:]] = 1
        for g in HOMOGLYPH.get(label[i], []):
            out[label[:i] + g + label[i + 1:]] = 1
    if n > 4:
        out[label[:n // 2] + "-" + label[n // 2:]] = 1
    out.pop(label, None)
    ok = [v for v in out if re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", v) and len(v) >= 2]
    if len(ok) <= cap:
        return ok
    step = len(ok) / cap
    return [ok[math.floor(i * step)] for i in range(cap)]


async def dns_registered(name, resolver) -> J:
    r = await dq("NS", name, resolver)
    if r.code is None:
        return J(state="registered", ns=sorted(x.lower() for x in r.data))
    if r.code == "ENOTFOUND":
        return J(state="free", ns=[])
    if r.code == "ENODATA":
        a = await dq("A", name, resolver)
        if a.code is None:
            return J(state="registered", ns=[], a=a.data)
        return J(state="free" if a.code == "ENOTFOUND" else "unknown", ns=[])
    return J(state="unknown", ns=[])


async def scan_brand(inp, extra=None, resolver_override=None) -> J:
    started = now_ms()
    V = "brand-analyzer-v2.0"
    parsed = parse_domain(inp)
    if not parsed:
        return build_result(assetType="BRAND", version=V, startedAt=started, target=str(inp or ""), findings=["finding_brand_invalid_target_critical"], score=0, status="ERROR", specific=J())
    domain = registrable_domain(parsed)
    sd = split_domain(domain)
    label, tld = sd.label, sd.tld
    base = f"{label}.{tld}"
    resolver = resolver_override
    if resolver is None:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = 3.0
        resolver.lifetime = 6.0
    ctl = await dq("A", "cloudflare.com", resolver)
    if not (ctl.code is None and ctl.data):
        return unavailable_result(assetType="BRAND", version=V, startedAt=started, target=base, finding="finding_brand_dns_unreliable_info", status="UNKNOWN",
                                  note="DNS çözücü yanıt vermedi; marka taraması yapılamadı.", specific=J(domain=base))
    own = await dns_registered(base, resolver)
    own_ns = ",".join(own.ns)
    own_a_r = await dq("A", base, resolver)
    own_a = own_a_r.data if own_a_r.code is None else []
    wc = await dq("A", f"dac-{_rand_token(8)}.{tld}", resolver)
    wildcard = wc.code is None and bool(wc.data)
    tlds = [f"{label}.{t}" for t in BRAND_TLDS if t != tld]
    typos = [f"{v}.{tld}" for v in typo_variants(label)]
    kw = [n for k in KEYWORDS for n in (f"{label}-{k}.{tld}", f"{k}-{label}.{tld}")][:12]
    names = [*[J(n=n, kind="tld") for n in tlds], *[J(n=n, kind="typo") for n in typos], *[J(n=n, kind="keyword") for n in kw]]

    async def one(it, _i):
        r = await dns_registered(it.n, resolver)
        a = list(r.a or [])
        if r.state == "registered" and not a:
            ar = await dq("A", it.n, resolver)
            a = ar.data if ar.code is None else []
        return J(**it, **{k: v for k, v in r.items() if k != "a"}, a=a)
    res = [r for r in await pool(names, 14, one) if r]
    mine = lambda r: r.state == "registered" and ((own_ns and ",".join(r.ns) == own_ns) or any(ip in own_a for ip in (r.a or [])))
    reg = [r for r in res if r.state == "registered"]
    third = [r for r in reg if not mine(r)]
    third_tld = [r for r in third if r.kind == "tld"]
    third_typo = [r for r in third if r.kind == "typo"]
    third_kw = [r for r in third if r.kind == "keyword"]
    free_tld = [r for r in res if r.kind == "tld" and r.state == "free"]
    unknown = len([r for r in res if r.state == "unknown"])
    live: list = []

    async def probe(r, _i):
        p = await request(f"http://{r.n}/", timeout=5000, max_bytes=80000)
        if not p.status:
            return
        body = str(p.body or "").lower()
        title = extract_title(p.body)[:80]
        live.append(J(n=r.n, status=p.status, title=title, mentionsBrand=label.lower() in body, loginForm=bool(re.search(r"type\s*=\s*[\"']?password", body))))
    await pool([r for r in [*third_typo, *third_kw] if r.a][:10], 5, probe)
    phishy = [l for l in live if l.mentionsBrand and l.loginForm]
    mention = [l for l in live if l.mentionsBrand]
    findings: list = []
    if phishy:
        findings.append(f"finding_brand_{len(phishy)}_lookalike_phishing_critical")
    if third_typo:
        findings.append(f"finding_brand_{len(third_typo)}_lookalike_registered_warning")
    if third_kw:
        findings.append(f"finding_brand_{len(third_kw)}_keyword_registered_warning")
    if mention and not phishy:
        findings.append(f"finding_brand_{len(mention)}_lookalike_active_warning")
    if third_tld:
        findings.append(f"finding_brand_{len(third_tld)}_tld_thirdparty_warning")
    if free_tld:
        findings.append(f"finding_brand_{len(free_tld)}_tld_unprotected_info")
    if own.state == "free":
        findings.append("finding_brand_base_not_registered_warning")
    if wildcard:
        findings.append("finding_brand_wildcard_dns_info")
    unreliable = unknown > len(res) / 2
    if unreliable:
        findings.append("finding_brand_dns_unreliable_info")
    score = None if unreliable else clamp(100 - min(len(third_typo) * 5, 35) - min(len(third_kw) * 3, 12) - min(len(third_tld) * 6, 30) - min(len(mention) * 6, 18) - len(phishy) * 25)
    fmt = lambda a: [f"{r.n}{' → ' + r.ns[0] if r.ns else ''}" for r in a]
    spec = J(domain=base, checkedTldVariants=len(tlds), checkedTypoVariants=len(typos), checkedKeywordVariants=len(kw), ownedOrSameOwner=[r.n for r in reg if mine(r)],
             thirdPartyTldVariants=fmt(third_tld), thirdPartyLookalikes=fmt(third_typo), thirdPartyKeywordDomains=fmt(third_kw),
             activeLookalikeSites=[f"{l.n} (HTTP {l.status}{', ' + chr(39) + l.title + chr(39) if l.title else ''}{', marka adı geçiyor' if l.mentionsBrand else ''}{', GİRİŞ FORMU var' if l.loginForm else ''})" for l in live],
             unregisteredTlds=[r.n for r in free_tld], undetermined=unknown,
             note="Kayıt tespiti DNS'e dayanır: aynı nameserver/IP'ye sahip olanlar 'sizin' sayılır. DNS'i olmayan ama kayıtlı alan adları görünmez; kesin sahiplik için WHOIS/RDAP gerekir.")
    if score is None:
        return unavailable_result(assetType="BRAND", version=V, startedAt=started, target=base, finding="finding_brand_dns_unreliable_info", status="UNKNOWN", note="DNS sorguları yeterince yanıt vermedi.", specific=spec)
    return build_result(assetType="BRAND", version=V, startedAt=started, target=base, findings=findings, score=score, specific=spec)


# =====================================================================
# SAAS ABONELİK v4
# =====================================================================
def _js_number(x):
    if x is None or x == "":
        return 0 if x == "" else None
    if isinstance(x, bool):
        return int(x)
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


async def scan_saas_subscription(extra=None) -> J:
    extra = jj(extra or {})
    started = now_ms()
    V = "saas-analyzer-v4.0"
    findings: list = []
    provider = str(extra.provider or extra.name or "unknown").strip().lower()
    renewal_date = extra.renewalDate or extra.expiryDate or None
    rd = to_date(renewal_date)
    remaining_days = days_until(rd) if rd else (extra.remainingDays if extra.remainingDays is not None else None)
    cn = _js_number(extra.cost)
    cost = cn if (cn and not (isinstance(cn, float) and math.isnan(cn))) else 0
    currency = extra.currency or "TRY"
    plan = extra.plan or "unknown"
    up = extra.usagePercent
    usage = None if (up == "" or up is None) else _js_number(up)
    auto_renew = None if extra.autoRenew is None else (extra.autoRenew is True or extra.autoRenew == "true")
    c = Checker()
    expiry_status = "HEALTHY"
    if remaining_days is not None:
        if remaining_days < 0:
            expiry_status = "EXPIRED"
            c.add(False, 60, "finding_saas_expired_critical", "renewal")
        else:
            c.add(remaining_days >= 14, 25, "finding_saas_expiring_soon_critical", "renewal")
            c.add(remaining_days >= 30, 15, "finding_saas_expiring_soon_warning", "renewal")
            expiry_status = "CRITICAL" if remaining_days < 14 else "WARNING" if remaining_days < 30 else "HEALTHY"
            if remaining_days >= 30:
                c.add(True, 60, None, "renewal")
        if auto_renew is False and 0 <= remaining_days < 30:
            c.add(False, 15, "finding_saas_manual_renewal_due_warning", "renewal")
    else:
        findings.append("finding_saas_missing_renewal_warning")
    if usage is not None and not (isinstance(usage, float) and math.isnan(usage)):
        c.add(usage <= 90, 40, "finding_saas_usage_critical", "usage")
        if usage <= 90:
            c.add(usage <= 80, 20, "finding_saas_usage_high_warning", "usage")
        if cost > 0:
            c.add(usage >= 20, 30, "finding_saas_underused_warning", "usage")
    scored = c.score()
    g = c.group_scores()
    monthly = cost / 12 if extra.billingCycle == "yearly" else cost
    specific = J(provider=provider, plan=plan, renewalDate=iso(rd) if rd else None, remainingDays=remaining_days, cost=cost, currency=currency, billingCycle=extra.billingCycle or "monthly",
                 monthlyCost=js_round(monthly * 100) / 100, yearlyCost=js_round(monthly * 12 * 100) / 100,
                 usagePercent=(None if (usage is not None and isinstance(usage, float) and math.isnan(usage)) else usage), autoRenew=auto_renew,
                 scores=J(renewal=g.get("renewal"), usage=g.get("usage")))
    if scored is None:
        specific.note = "Yenileme tarihi ve kullanım oranı girilmediği için skor hesaplanamadı."
    all_f = sort_findings([*c.findings(), *findings])
    status = "UNKNOWN" if scored is None else "CRITICAL" if expiry_status == "EXPIRED" else "HEALTHY" if (expiry_status == "HEALTHY" and scored >= 80) else "WARNING"
    common = J(analyzerVersion=V, executionTimeMs=now_ms() - started, findings=all_f, scannedAt=iso(datetime.now(timezone.utc)), score=scored, status=status, target=provider)
    spec_scores = J(**specific.scores, **({"overall": scored} if scored is not None else {}))
    specific.scores = spec_scores
    return J(data=J(assetId=extra.assetId or f"saas_{re.sub(r'[^A-Za-z0-9_]', '_', provider)}_{now_ms()}", assetType="SAAS_SUBSCRIPTION", commonAnalysis=common, specificAnalysis=specific,
                    analysisMeta=J(scannerVersion=V, analyzer="saas"), provider=provider, plan=plan, renewalDate=iso(rd) if rd else None, remainingDays=remaining_days, cost=cost),
             findings=all_f, errors=[], statusHint="EXPIRED" if expiry_status == "EXPIRED" else "UNKNOWN" if status == "UNKNOWN" else "ACTIVE")


# =====================================================================
# ANALYTICS (Google Analytics 4 / GTM)
# =====================================================================
async def scan_analytics(target_url, extra=None) -> J:
    extra = jj(extra or {})
    started = now_ms()
    V = "analytics-analyzer-v1.0"
    url = ensure_url(target_url)
    declared = str(extra.measurementId or "").strip().upper()
    declared_valid = bool(re.fullmatch(r"G-[A-Z0-9]{4,14}", declared))
    main = await http_probe(url, timeout=12000, maxRedirects=4)
    prot = detect_bot_protection(main) if main.status else None
    if prot:
        return protected_result("ANALYTICS", V, started, url, main, prot)
    if main.status == 0:
        return down_result("ANALYTICS", V, started, url, main, net_error_finding("analytics", main))
    body = str(main.body or "")

    def uniq(rx, g=1):
        return list(dict.fromkeys(m.group(g).upper() for m in re.finditer(rx, body, re.I)))[:10]
    ga4 = list(dict.fromkeys([*uniq(r"googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]+)"), *uniq(r"""gtag\(\s*['"]config['"]\s*,\s*['"](G-[A-Z0-9]+)['"]""")]))
    gtm = uniq(r"googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)")
    ua = uniq(r"\b(UA-\d{4,10}-\d{1,4})\b")
    legacy_js = bool(re.search(r"google-analytics\.com/(analytics|ga)\.js", body, re.I))
    tag_type = "gtag" if ga4 else "gtm" if gtm else "legacy" if (legacy_js or ua) else None
    c = Checker()
    c.add(main.status < 400, 15, "finding_analytics_site_error_status_critical", "erisim")
    c.add(bool(re.match(r"^https:", main.finalUrl or url, re.I)), 5, "finding_analytics_not_https_warning", "erisim")
    c.add(bool(ga4 or gtm), 40, "finding_analytics_no_tag_critical", "yayin")
    id_match = None
    if declared_valid and ga4:
        id_match = declared in ga4
    if id_match is not None:
        c.add(id_match, 25, "finding_analytics_measurement_id_mismatch_critical", "yayin")
    c.add((not (ua or legacy_js)) or len(ga4) > 0, 10, "finding_analytics_legacy_ua_warning", "kalite")
    script_ok = None
    check_id = declared if declared_valid else (ga4[0] if ga4 else None)
    if check_id:
        sp = await http_probe("https://www.googletagmanager.com/gtag/js?id=" + urllib.parse.quote(check_id, safe=""), timeout=8000, maxRedirects=1, noUaFallback=True, read_body=False)
        script_ok = sp.status == 200
        c.add(script_ok, 5, "finding_analytics_tag_script_unreachable_warning", "kalite")
    findings = c.findings()
    if extra.measurementId and not declared_valid:
        findings.append("finding_analytics_measurement_id_invalid_warning")
    if gtm and not ga4:
        findings.append("finding_analytics_gtm_only_info")
    findings.append("finding_analytics_live_data_unavailable_info")
    specific = J(
        health=J(tagDetected=bool(tag_type), tagType=tag_type, measurementIdMatches=id_match, tagScriptReachable=script_ok, dataReceiving=None, conversionEventsCount=None, lastDataReceivedAt=None),
        property=J(measurementId=declared if declared_valid else (ga4[0] if ga4 else None), propertyName=str(extra.propertyName)[:120] if extra.propertyName else None, provider="Google Analytics 4",
                   detectedMeasurementIds=ga4, gtmContainers=gtm, legacyIds=ua),
        traffic=J(activeUsers24h=None, bounceRate=None, realtimeUsers=None), scores=c.group_scores(),
        note="Canlı trafik, dönüşüm ve veri alımı değerleri Google Analytics Data API yetkisi gerektirir; bağlanmadığı için boş bırakıldı.")
    return build_result(assetType="ANALYTICS", version=V, startedAt=started, target=url, findings=findings, specific=specific, score=c.score())


def _tgt(a, e, *keys):
    return a or next((e.get(k) for k in keys if e.get(k)), None) or None


TYPE_HANDLERS = {
    "WEB": lambda t, e: scan_website(t, e), "WEBSITE": lambda t, e: scan_website(t, e),
    "DOMAIN": lambda t, e: scan_domain(t or e.get("domain") or e.get("target"), e), "EMAIL": lambda t, e: scan_domain(t or e.get("domain") or e.get("target"), e),
    "SSL_CERTIFICATE": lambda t, e: scan_ssl_certificate(t or e.get("domain") or e.get("target"), e), "SSL": lambda t, e: scan_ssl_certificate(t or e.get("domain") or e.get("target"), e),
    "HOSTING": lambda t, e: scan_hosting(t or e.get("domain") or e.get("target")), "SERVER": lambda t, e: scan_server(t or e.get("domain") or e.get("target")),
    "SEO": lambda t, e: scan_seo(t or e.get("target")), "SECURITY": lambda t, e: scan_security(t or e.get("target")), "PERFORMANCE": lambda t, e: scan_performance(t or e.get("target")),
    "UPTIME": lambda t, e: scan_uptime(t or e.get("target"), e), "API": lambda t, e: scan_api(t or e.get("target")), "ANALYTICS": lambda t, e: scan_analytics(t or e.get("target"), e),
    "MOBILE_APP": lambda t, e: scan_mobile_app(t or e.get("target")), "REPOSITORY": lambda t, e: scan_repository(t or e.get("target")),
    "BRAND": lambda t, e: scan_brand(t or e.get("target"), e), "SAAS_SUBSCRIPTION": lambda t, e: scan_saas_subscription(e),
}
NO_HOST_TYPES = ["SAAS_SUBSCRIPTION", "MOBILE_APP", "REPOSITORY"]
ACTIVE_PROBE_TYPES = ["SERVER", "SECURITY"]  # port taraması / hassas dosya yoklaması: yetki beyanı gerekir
SCAN_TIMEOUT_MS = env_int("SCAN_TIMEOUT_MS", 75000)


def for_firestore(v, depth=0):
    """Firestore: iç içe dizi yasak, 1 MB belge sınırı, NaN/Infinity sorunlu. Güvenli hale getirir."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v if (not isinstance(v, float) or math.isfinite(v)) else None
    if isinstance(v, str):
        return v[:4000] + "…" if len(v) > 4000 else v
    if isinstance(v, datetime):
        return v
    if depth > 8:
        return None
    if isinstance(v, (list, tuple)):
        out = []
        for x in list(v)[:200]:
            if isinstance(x, (list, tuple)):
                out.append(json.dumps(x, default=str, ensure_ascii=False)[:2000])
            else:
                out.append(for_firestore(x, depth + 1))
        return out
    if isinstance(v, dict):
        o = {}
        for k, val in v.items():
            if k == "debug":
                continue
            x = for_firestore(val, depth + 1)
            o[re.sub(r"[./\[\]*`~]", "_", str(k))] = x
        return o
    return str(v)


# =====================================================================
# SUNUCU KATMANI (FastAPI): Firebase, kimlik, ödeme, durum, hesap, statik dosyalar
# =====================================================================
import logging

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse, Response

log = logging.getLogger("dac")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

EXPECTED_PROJECT_ID = "assetops-ed334"
FORBIDDEN_PROJECT_IDS = ["varlik-operasyonlari-ed334"]


# ---------- Paketler (plans.js ile AYNI olmalı; açılışta karşılaştırılır) ----------
PLANS = {
    "trial": J(id="trial", name="Ücretsiz Deneme", assets=3, team=1, history=50, priceTRY=0, priceUSD=0),
    "freelance": J(id="freelance", name="Freelance", assets=25, team=1, history=200, priceTRY=499.99, priceUSD=11.99),
    "kobi": J(id="kobi", name="KOBİ", assets=150, team=10, history=1000, priceTRY=4999.99, priceUSD=119.99),
    "enterprise": J(id="enterprise", name="Enterprise", assets=None, team=None, history=5000, priceTRY=24999.99, priceUSD=599.99),
}
PAID = ["freelance", "kobi", "enterprise"]
TRIAL_DAYS = 3
YEARLY_MONTHS = 10


def plan_price(plan_id, currency, cycle):
    p = PLANS.get(plan_id)
    if not p:
        return None
    base = p.priceUSD if currency == "USD" else p.priceTRY
    return js_round(base * (YEARLY_MONTHS if cycle == "yearly" else 1) * 100) / 100


def _verify_plans_against_js():
    try:
        src = open(os.path.join(BASE_DIR, "public", "js", "plans.js"), encoding="utf-8").read()
        for pid, p in PLANS.items():
            m = re.search(rf'{pid}:\s*{{[^}}]*?assets:\s*(\w+)[^}}]*?priceTRY:\s*([\d.]+)[^}}]*?priceUSD:\s*([\d.]+)', src, re.S)
            if not m:
                continue
            a = None if m.group(1) == "null" else int(m.group(1))
            if a != p.assets or abs(float(m.group(2)) - p.priceTRY) > 1e-9 or abs(float(m.group(3)) - p.priceUSD) > 1e-9:
                log.warning("UYARI: index.py içindeki '%s' paketi plans.js ile uyuşmuyor (varlık/fiyat). index.py PLANS tablosunu güncelleyin.", pid)
    except Exception:
        pass


# ---------- Firebase ----------
def project_id_of() -> str:
    return (env("FIREBASE_PROJECT_ID") or EXPECTED_PROJECT_ID).strip()


def parse_service_account():
    pid = project_id_of()
    if pid != EXPECTED_PROJECT_ID:
        return J(ok=False, code="BAD_PROJECT", message=f'FIREBASE_PROJECT_ID "{pid}" geçersiz: bu uygulama yalnızca "{EXPECTED_PROJECT_ID}" projesiyle çalışır.')
    raw = None if env("FIREBASE_SERVICE_ACCOUNT_B64") else env("FIREBASE_SERVICE_ACCOUNT")
    if env("FIREBASE_SERVICE_ACCOUNT_B64"):
        try:
            raw = base64.b64decode(env("FIREBASE_SERVICE_ACCOUNT_B64").strip()).decode("utf-8")
        except Exception:
            return J(ok=False, code="BAD_B64", message="FIREBASE_SERVICE_ACCOUNT_B64 base64 olarak çözülemedi.")
    if not raw or not raw.strip():
        return J(ok=False, code="MISSING", message="FIREBASE_SERVICE_ACCOUNT tanımlı değil. Render > Environment bölümüne hizmet hesabı JSON'unun tamamını ekleyin.")
    try:
        acc = json.loads(raw.strip())
    except Exception:
        return J(ok=False, code="BAD_JSON", message="FIREBASE_SERVICE_ACCOUNT geçerli bir JSON değil (veya FIREBASE_SERVICE_ACCOUNT_B64 kullanın).")
    if not isinstance(acc, dict) or acc.get("type") != "service_account":
        return J(ok=False, code="BAD_TYPE", message="Hizmet hesabı JSON'unda type=service_account yok.")
    for k in ("project_id", "client_email", "private_key"):
        if not acc.get(k) or not isinstance(acc[k], str):
            return J(ok=False, code="MISSING_FIELD", message=f'Hizmet hesabı JSON\'unda "{k}" alanı eksik.')
    acc["private_key"] = acc["private_key"].replace("\\n", "\n")
    if "-----BEGIN PRIVATE KEY-----" not in acc["private_key"]:
        return J(ok=False, code="BAD_KEY", message="Hizmet hesabı özel anahtarı (private_key) biçimi geçersiz.")
    if acc["project_id"] in FORBIDDEN_PROJECT_IDS:
        return J(ok=False, code="OLD_PROJECT", message=f"Hizmet hesabı yanlış projeye ({acc['project_id']}) ait.")
    if acc["project_id"] != pid:
        return J(ok=False, code="PROJECT_MISMATCH", message=f'Hizmet hesabı "{acc["project_id"]}" projesine ait, beklenen "{pid}".')
    if not acc["client_email"].endswith(f"@{pid}.iam.gserviceaccount.com"):
        return J(ok=False, code="EMAIL_MISMATCH", message=f'Hizmet hesabı e-postası "{pid}" projesine ait görünmüyor.')
    return J(ok=True, account=acc)


FB = J(db=None, auth=None, firestore=None, status=J(ok=False, projectId=project_id_of(), mode=None, code="NOT_INIT"))


def init_firebase():
    try:
        import firebase_admin
        from firebase_admin import auth as fb_auth, credentials, firestore as fb_fs
    except Exception as e:  # pragma: no cover
        FB.status = J(ok=False, projectId=project_id_of(), mode=None, code="NO_SDK", message=str(e)[:200])
        log.error("firebase-admin yüklenemedi: %s", e)
        return
    pid = project_id_of()
    try:
        if not firebase_admin._apps:
            if env("FIREBASE_SERVICE_ACCOUNT") or env("FIREBASE_SERVICE_ACCOUNT_B64"):
                p = parse_service_account()
                if not p.ok:
                    FB.status = J(ok=False, projectId=pid, mode=None, code=p.code, message=p.message)
                    log.error("Firebase başlatılamadı [%s]: %s", p.code, p.message)
                    return
                firebase_admin.initialize_app(credentials.Certificate(p.account), {"projectId": pid})
            elif env("GOOGLE_APPLICATION_CREDENTIALS"):
                firebase_admin.initialize_app(options={"projectId": pid})
            else:
                p = parse_service_account()
                FB.status = J(ok=False, projectId=pid, mode=None, code=p.code, message=p.message)
                log.warning("Firebase kimlik bilgisi yok: %s", p.message)
                return
        FB.db = fb_fs.client()
        FB.auth = fb_auth
        FB.firestore = fb_fs
        FB.status = J(ok=True, projectId=pid, mode="service-account" if (env("FIREBASE_SERVICE_ACCOUNT") or env("FIREBASE_SERVICE_ACCOUNT_B64")) else "adc")
    except Exception as e:
        FB.status = J(ok=False, projectId=pid, mode=None, code="INIT_ERROR", message=str(e)[:200])
        log.error("Firebase başlatılamadı [INIT_ERROR]: %s", str(e)[:200])


def web_config():
    cfg = {"projectId": project_id_of()}
    missing = []
    for k, e in {"apiKey": "FIREBASE_WEB_API_KEY", "authDomain": "FIREBASE_WEB_AUTH_DOMAIN", "appId": "FIREBASE_WEB_APP_ID", "messagingSenderId": "FIREBASE_WEB_MESSAGING_SENDER_ID"}.items():
        v = env(e).strip()
        if v:
            cfg[k] = v
        else:
            missing.append(e)
    for k, e in {"storageBucket": "FIREBASE_WEB_STORAGE_BUCKET", "measurementId": "FIREBASE_WEB_MEASUREMENT_ID"}.items():
        v = env(e).strip()
        if v:
            cfg[k] = v
    if cfg["projectId"] != EXPECTED_PROJECT_ID:
        return J(ok=False, missing=[], error=f'FIREBASE_PROJECT_ID "{cfg["projectId"]}" geçersiz; beklenen "{EXPECTED_PROJECT_ID}".')
    for k in ("authDomain", "storageBucket"):
        if cfg.get(k) and any(p in cfg[k] for p in FORBIDDEN_PROJECT_IDS):
            return J(ok=False, missing=[], error=f"{k} yanlış projeyi gösteriyor.")
    if cfg.get("appId") and ":web:" not in cfg["appId"]:
        return J(ok=False, missing=[], error="FIREBASE_WEB_APP_ID bir web uygulaması kimliği olmalı (1:...:web:...).")
    return J(ok=False, missing=missing) if missing else J(ok=True, config=cfg)


# ---------- Hız sınırı / eşzamanlılık ----------
class Limiter:
    def __init__(self, mx: int, window_ms: int):
        self.mx, self.w, self.hits = mx, window_ms / 1000, {}

    def __call__(self, key) -> bool:
        now = time.monotonic()
        if len(self.hits) > 100000:
            for k in list(self.hits.keys())[:50000]:
                self.hits.pop(k, None)
        arr = [x for x in self.hits.get(key, []) if now - x < self.w]
        if len(arr) >= self.mx:
            self.hits[key] = arr
            return False
        arr.append(now)
        self.hits[key] = arr
        return True


class Concurrency:
    def __init__(self, per_user: int, glob: int):
        self.per_user, self.glob, self.total, self.per = per_user, glob, 0, {}

    def acquire(self, uid):
        if self.total >= self.glob or self.per.get(uid, 0) >= self.per_user:
            return None
        self.total += 1
        self.per[uid] = self.per.get(uid, 0) + 1
        done = [False]

        def release():
            if done[0]:
                return
            done[0] = True
            self.total -= 1
            n = self.per.get(uid, 1) - 1
            if n <= 0:
                self.per.pop(uid, None)
            else:
                self.per[uid] = n
        return release


DEFAULT_ORIGINS = ["https://dac-web-tfqf.onrender.com", "https://dac-web-yefr.onrender.com", "https://hz-yazilim.github.io"]


def allowed_origins() -> list:
    extra = [s.strip() for s in env("ALLOWED_ORIGINS").split(",") if s.strip()]
    dev = [] if is_prod() else ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500"]
    return [*DEFAULT_ORIGINS, *extra, *dev]


class HttpError(Exception):
    def __init__(self, status: int, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


def _nan_safe(o):
    if isinstance(o, float):
        return o if math.isfinite(o) else None
    if isinstance(o, dict):
        return {k: _nan_safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_nan_safe(v) for v in o]
    return o


def jres(data, status=200, headers=None) -> Response:
    body = json.dumps(_nan_safe(data), ensure_ascii=False, default=str, allow_nan=False)
    return Response(content=body, status_code=status, media_type="application/json", headers=headers)


def err(status, message, **extra) -> Response:
    return jres({"success": False, "error": message, **extra}, status)


def client_ip(request: Request) -> str:
    """Render gibi TEK güvenilir vekil (trust proxy=1): X-Forwarded-For'un SAĞDAKİ girdisi."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "0.0.0.0"


async def read_body(request: Request, limit: int) -> bytes:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit:
        raise HttpError(413, "İstek çok büyük")
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > limit:
            raise HttpError(413, "İstek çok büyük")
    return bytes(buf)


async def read_json(request: Request, limit: int = 256 * 1024):
    raw = await read_body(request, limit)
    request.state.raw = raw
    if not raw.strip():
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise HttpError(400, "Geçersiz JSON")


def assert_email_verified(claims: dict):
    provider = ((claims or {}).get("firebase") or {}).get("sign_in_provider")
    if provider == "password" and claims.get("email_verified") is not True:
        raise HttpError(403, "E-posta adresinizi doğrulayın: gelen kutunuza gönderilen bağlantıya tıklayıp tekrar giriş yapın.", "EMAIL_NOT_VERIFIED")


def _bearer(request: Request) -> str:
    m = re.match(r"^Bearer (.+)$", request.headers.get("authorization", ""), re.I)
    if not m:
        raise HttpError(401, "Giriş yapmanız gerekiyor.")
    return m.group(1)


async def verify_user(request: Request) -> J:
    if not FB.db:
        raise HttpError(503, "Sunucuda Firebase yapılandırılmamış (FIREBASE_SERVICE_ACCOUNT gerekli).")
    tok = _bearer(request)
    try:
        t = await asyncio.to_thread(FB.auth.verify_id_token, tok, env("VERIFY_REVOKED") == "true")
    except Exception:
        raise HttpError(401, "Oturum doğrulanamadı, tekrar giriş yapın.")
    assert_email_verified(t)
    return J(uid=t["uid"], email=t.get("email"), name=t.get("name"))


async def verify_token_without_db(request: Request) -> J:
    """Firestore yokken: Google'ın açık anahtarlarıyla (RS256) Firebase ID token doğrulama."""
    tok = _bearer(request)

    def work():
        from google.auth.transport import requests as greq
        from google.oauth2 import id_token
        return id_token.verify_firebase_token(tok, greq.Request(), audience=EXPECTED_PROJECT_ID)
    try:
        c = await asyncio.to_thread(work)
    except Exception:
        raise HttpError(401, "Oturum doğrulanamadı, tekrar giriş yapın.")
    if not c or not c.get("sub"):
        raise HttpError(401, "Oturum doğrulanamadı, tekrar giriş yapın.")
    assert_email_verified(c)
    return J(uid=c["sub"], email=c.get("email"), name=c.get("name"))


async def authenticate(request: Request, use_db_verify=True) -> J:
    if dev_bypass():
        return J(uid="dev-user", email=None, dev=True)
    return await (verify_user(request) if (FB.db and use_db_verify) else verify_token_without_db(request))


# ---------- Firestore yardımcıları (senkron SDK iş parçacığında) ----------
def _doc(coll, did):
    return FB.db.collection(coll).document(did)


async def get_doc(coll, did) -> Optional[dict]:
    snap = await asyncio.to_thread(lambda: _doc(coll, did).get())
    return snap.to_dict() if snap.exists else None


async def get_entitlement(uid: str) -> J:
    now = now_ms()
    sub = await get_doc("subscriptions", uid)
    if sub and sub.get("plan") in PAID and sub.get("status") == "active" and (not sub.get("periodEnd") or sub["periodEnd"] > now):
        return J(plan=sub["plan"], status="active", periodEnd=sub.get("periodEnd") or None, provider=sub.get("provider"), currency=sub.get("currency"), cycle=sub.get("cycle"))
    u = (await get_doc("users", uid)) or {}
    if not u.get("trialStart"):
        u["trialStart"] = now
        await asyncio.to_thread(lambda: _doc("users", uid).set({"trialStart": now}, merge=True))
    trial_end = u["trialStart"] + TRIAL_DAYS * 86400000
    if now < trial_end:
        return J(plan="trial", status="trial", trialStart=u["trialStart"], trialEnd=trial_end)
    return J(plan="expired", status=(sub or {}).get("status") or "expired", trialStart=u["trialStart"], trialEnd=trial_end, lastPlan=(sub or {}).get("plan"))


async def activate(uid, data: dict):
    await asyncio.to_thread(lambda: _doc("subscriptions", uid).set({**{k: v for k, v in data.items() if v is not None}, "updatedAt": now_ms()}, merge=True))


async def claim_asset(asset_id: str, uid: str) -> J:
    def work():
        fs = FB.firestore
        ref = _doc("assets", asset_id)

        @fs.transactional
        def txn(t):
            s = ref.get(transaction=t)
            owner = (s.to_dict() or {}).get("ownerId") if s.exists else None
            if owner and owner != uid:
                return J(ok=False, isNew=False)
            if s.exists and not owner and env("ALLOW_CLAIM_LEGACY_ASSETS") != "true":
                return J(ok=False, isNew=False, legacy=True)
            if not owner:
                t.set(ref, {"ownerId": uid}, merge=True)
            return J(ok=True, isNew=not s.exists)
        return txn(FB.db.transaction())
    return await asyncio.to_thread(work)


async def check_asset_quota(uid, plan, is_new) -> J:
    limit = PLANS[plan].assets if plan in PLANS else 0
    if limit is None or not is_new:
        return J(ok=True, limit=limit)

    def work():
        from google.cloud.firestore_v1.base_query import FieldFilter
        q = FB.db.collection("assets").where(filter=FieldFilter("ownerId", "==", uid)).count()
        return q.get()[0][0].value
    used = await asyncio.to_thread(work)
    return J(ok=used <= limit, used=used, limit=limit)


# ---------- Ödeme: Stripe (USD) ve iyzico (TL) ----------
LEGAL_VERSION = env("LEGAL_VERSION", "2026-10")
stripe_key = lambda: env("STRIPE_SECRET_KEY") or None
iyzi_ready = lambda: bool(env("IYZICO_API_KEY") and env("IYZICO_SECRET_KEY"))


def payments_status() -> J:
    return J(stripe=bool(stripe_key()) and bool(env("STRIPE_WEBHOOK_SECRET")), iyzico=iyzi_ready(), auth=bool(FB.db), enforced=env("ENFORCE_PLANS") == "true")


def to_form(obj, prefix="", out=None):
    out = [] if out is None else out
    for k, v in obj.items():
        if v is None:
            continue
        key = f"{prefix}[{k}]" if prefix else str(k)
        if isinstance(v, list):
            for i, x in enumerate(v):
                if isinstance(x, dict):
                    to_form(x, f"{key}[{i}]", out)
                else:
                    out.append((f"{key}[{i}]", str(x)))
        elif isinstance(v, dict):
            to_form(v, key, out)
        else:
            out.append((key, ("true" if v is True else "false" if v is False else str(v))))
    return out


async def stripe_api(method, path, params=None):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), auth=aiohttp.BasicAuth(stripe_key(), "")) as s:
            async with s.request(method, "https://api.stripe.com/v1" + path, data=dict_to_pairs(params) if params else None) as r:
                data = await r.json(content_type=None)
                if r.status >= 400:
                    raise HttpError(502, "Stripe: " + str(((data or {}).get("error") or {}).get("message") or r.status))
                return jj(data)
    except HttpError:
        raise
    except Exception:
        raise HttpError(502, "Stripe: bağlantı hatası")


def dict_to_pairs(params):
    return to_form(params)


def period_end_of(sub) -> Optional[int]:
    v = sub.get("current_period_end")
    if v is None:
        items = (sub.get("items") or {}).get("data") or []
        v = items[0].get("current_period_end") if items else None
    return int(v) * 1000 if v else None


def verify_stripe_signature(raw: bytes, header, secret, tolerance=300) -> bool:
    parts = {}
    for p in str(header or "").split(","):
        kv = p.split("=")
        if len(kv) == 2:
            parts[kv[0].strip()] = kv[1]
    sigs = [p.strip()[3:] for p in str(header or "").split(",") if p.strip().startswith("v1=")]
    if not parts.get("t") or not sigs:
        return False
    try:
        if abs(time.time() - float(parts["t"])) > tolerance:
            return False
    except ValueError:
        return False
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + raw, hashlib.sha256).hexdigest()
    return any(re.fullmatch(r"[0-9a-fA-F]{64}", s) and hmac.compare_digest(s.lower(), expected) for s in sigs)


async def stripe_sync(sub, extra=None):
    m = sub.metadata or {}
    if not m.get("uid"):
        return
    st = "active" if sub.status in ("active", "trialing") else "canceled" if sub.status == "canceled" else "past_due"
    await activate(m["uid"], {"plan": m.get("plan"), "cycle": m.get("cycle"), "status": st, "provider": "stripe", "currency": "USD", "periodEnd": period_end_of(sub),
                              "stripeCustomerId": sub.customer, "stripeSubscriptionId": sub.id, **(extra or {})})


def return_url_of(request: Request, body: dict) -> str:
    origin = request.headers.get("origin")
    if not origin or origin not in allowed_origins():
        raise HttpError(400, "Geçersiz istek kaynağı.")
    p = re.sub(r"[^\x21-\x7e]", "", str((body or {}).get("returnPath") or "/"))[:200]
    if not p.startswith("/") or p.startswith("//"):
        p = "/"
    return origin + p


def with_param(u, k, v):
    return u + ("&" if "?" in u else "?") + f"{k}={v}"


def self_url(request: Request) -> str:
    if env("PUBLIC_API_URL"):
        return env("PUBLIC_API_URL")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{proto}://{request.headers.get('host')}"


def _iyzi_options():
    base = (env("IYZICO_BASE_URL") or "https://sandbox-api.iyzipay.com")
    return {"api_key": env("IYZICO_API_KEY"), "secret_key": env("IYZICO_SECRET_KEY"), "base_url": re.sub(r"^https?://", "", base).rstrip("/")}


def _iyzi_call(kind: str, req: dict) -> dict:
    import iyzipay
    if kind == "init":
        res = iyzipay.CheckoutFormInitialize().create(req, _iyzi_options())
    else:
        res = iyzipay.CheckoutForm().retrieve(req, _iyzi_options())
    return json.loads(res.read().decode("utf-8"))


# ---------- Kullanıcı durumu ----------
STATE_LIMITS = {"assets": 5000, "scans": 5000, "team": 1000, "projects": 1000, "bytes": 900 * 1024}
FORBIDDEN_KEYS = {"__proto__", "constructor", "prototype"}


def clean_state(v, depth=0):
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v if (not isinstance(v, float) or math.isfinite(v)) else None
    if isinstance(v, str):
        return v[:20000]
    if depth > 12:
        return None
    if isinstance(v, list):
        return [clean_state(x, depth + 1) for x in v[:5000]]
    if isinstance(v, dict):
        return {k: clean_state(val, depth + 1) for k, val in v.items() if k not in FORBIDDEN_KEYS}
    return None


def sanitize_state(inp) -> dict:
    if not isinstance(inp, dict):
        raise HttpError(400, "Geçersiz veri.")
    out = {}
    for k in ("assets", "scans", "team", "projects"):
        a = inp.get(k, [])
        if a is None:
            a = []
        if not isinstance(a, list):
            raise HttpError(400, f'"{k}" dizi olmalı.')
        if len(a) > STATE_LIMITS[k]:
            raise HttpError(413, f'"{k}" sınırı aşıldı ({STATE_LIMITS[k]}).', "STATE_TOO_LARGE")
        for x in a:
            if not isinstance(x, dict) or (not isinstance(x.get("id"), str) and k != "scans"):
                raise HttpError(400, f'"{k}" içinde geçersiz kayıt.')
        out[k] = [clean_state(x) for x in a]
    s = clean_state(inp["settings"]) if isinstance(inp.get("settings"), dict) else {}
    for k in ("plan", "planEnd", "provider", "trialStart", "apiUrl"):
        s.pop(k, None)
    out["settings"] = s
    sa = inp.get("settingsAt")
    out["settingsAt"] = sa if isinstance(sa, (int, float)) and not isinstance(sa, bool) and math.isfinite(sa) else 0
    tomb = inp.get("tomb") if isinstance(inp.get("tomb"), dict) else {}
    out["tomb"] = {i: ts for i, ts in list(tomb.items())[:5000] if isinstance(ts, (int, float)) and not isinstance(ts, bool) and i not in FORBIDDEN_KEYS}
    return out


# =====================================================================
# UYGULAMA, ARA KATMANLAR VE UÇ NOKTALAR
# =====================================================================
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_app):
    loop = asyncio.get_running_loop()

    def on_loop_error(_loop, ctx):  # düşman hedeflerden gelen sahipsiz görev/soket hataları süreci düşürmesin
        log.error("asyncio hata: %s", ctx.get("message") or ctx.get("exception"))
    loop.set_exception_handler(on_loop_error)
    init_firebase()
    _verify_plans_against_js()
    if is_prod() and not env("SECURITY_CONTACT"):
        log.warning("UYARI: SECURITY_CONTACT tanımlı değil; /.well-known/security.txt içinde yer tutucu adres görünür.")
    log.info("DAC Scanner %s hazır (firebase=%s)", SCANNER_VERSION, FB.status.mode or FB.status.code)
    yield


app = FastAPI(title="Digital Asset Center", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

CSP = "; ".join([
    "default-src 'self'", "script-src 'self' https://www.gstatic.com https://apis.google.com https://www.googletagmanager.com", "script-src-attr 'none'",
    "style-src 'self'", "style-src-attr 'unsafe-inline'", "font-src 'self'", "img-src 'self' data: https:",
    "connect-src 'self' https://*.onrender.com https://*.googleapis.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com https://*.firebaseio.com https://*.firebaseapp.com https://www.gstatic.com",
    "frame-src 'self' https://accounts.google.com https://*.firebaseapp.com https://*.iyzipay.com https://js.stripe.com",
    "form-action 'self' https://*.iyzipay.com https://checkout.stripe.com", "manifest-src 'self'", "worker-src 'self'", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "upgrade-insecure-requests"])
SEC_HEADERS = {
    "Content-Security-Policy-Report-Only" if env("CSP_MODE") == "report" else "Content-Security-Policy": CSP,
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups", "Cross-Origin-Resource-Policy": "same-site",
    "Referrer-Policy": "strict-origin-when-cross-origin", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN",
    "X-DNS-Prefetch-Control": "off", "X-Permitted-Cross-Domain-Policies": "none", "Origin-Agent-Cluster": "?1",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(self), usb=(), serial=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), interest-cohort=()",
}
global_api_limit = Limiter(env_int("API_RATE_LIMIT", 600), 5 * 60 * 1000)


@app.middleware("http")
async def mw(request: Request, call_next):
    origin = request.headers.get("origin")
    cors_ok = bool(origin) and origin in allowed_origins()
    cors = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"} if cors_ok else {}
    if request.method == "OPTIONS" and request.headers.get("access-control-request-method"):
        h = {**SEC_HEADERS, **cors}
        if cors_ok:
            h.update({"Access-Control-Allow-Methods": "GET,POST,PUT,DELETE", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Max-Age": "600"})
        return Response(status_code=204, headers=h)
    if request.url.path.startswith("/api") and not global_api_limit(client_ip(request)):
        resp = err(429, "Çok fazla istek. Biraz sonra tekrar deneyin.")
    else:
        try:
            resp = await call_next(request)
        except HttpError as e:
            resp = err(e.status, e.message, **({"code": e.code} if e.code else {}))
        except Exception as e:  # noqa
            log.error("işlenmeyen hata %s %s: %s", request.method, request.url.path, e)
            resp = err(500, "Sunucu hatası")
    for k, v in {**SEC_HEADERS, **cors}.items():
        resp.headers[k] = v
    if "server" in resp.headers:
        del resp.headers["server"]
    return resp


from starlette.exceptions import HTTPException as StarletteHTTPException


@app.exception_handler(StarletteHTTPException)
async def starlette_http_error(request: Request, exc: StarletteHTTPException):
    return err(exc.status_code, "Bulunamadı" if exc.status_code == 404 else "İstek işlenemedi")


@app.exception_handler(HttpError)
async def http_error_handler(request: Request, exc: HttpError):
    return err(exc.status, exc.message, **({"code": exc.code} if exc.code else {}))


def route_guard(fn):
    """HttpError -> JSON; beklenmeyen hata -> 500 (ayrıntı sızdırmadan)."""
    import functools

    @functools.wraps(fn)
    async def inner(request: Request):
        try:
            return await fn(request)
        except HttpError as e:
            return err(e.status, e.message, **({"code": e.code} if e.code else {}))
        except Exception as e:  # noqa
            log.error("%s: %s", fn.__name__, e)
            return err(500, "Sunucu hatası")
    return inner


# ---------- Statik dosyalar (YALNIZCA izin listesi) ----------
LEGAL_PAGES = {"/kvkk": "kvkk.html", "/gizlilik": "gizlilik.html", "/kullanim-kosullari": "kullanim-kosullari.html", "/cerez-politikasi": "cerez-politikasi.html", "/mesafeli-satis": "mesafeli-satis.html",
               "/iade-iptal": "iade-iptal.html", "/iletisim": "iletisim.html", "/kabul-edilebilir-kullanim": "kabul-edilebilir-kullanim.html"}
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
STATIC_CACHE = {"index.html": "no-cache", "manifest.json": "public, max-age=3600"}
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".png": "image/png", ".woff2": "font/woff2"}
LEGACY_URLS = {"/style.css": "/css/style.css", "/app.js": "/js/app.js", "/login.js": "/js/login.js", "/config.js": "/js/config.js", "/plans.js": "/js/plans.js", "/company.js": "/js/company.js", "/legal.js": "/js/legal.js",
               "/cookie-consent.js": "/js/cookie-consent.js", "/sw-register.js": "/js/sw-register.js", "/lucide.min.js": "/js/lucide.min.js", "/icon-192.png": "/icons/icon-192.png", "/icon-512.png": "/icons/icon-512.png", "/index.html": "/"}
for _f in ("inter-latin", "inter-latin-ext", "jbmono-400-latin", "jbmono-400-ext", "jbmono-500-latin", "jbmono-500-ext"):
    LEGACY_URLS[f"/{_f}.woff2"] = f"/fonts/{_f}.woff2"
for _f in LEGAL_PAGES.values():
    LEGACY_URLS["/" + _f] = "/legal/" + _f


def _scan_public() -> dict:
    """public/ altındaki dosyaların izin listesi (nokta ile başlayanlar hariç). Sunucu kodu bu klasörde değildir."""
    m = {}
    for root, dirs, files in os.walk(PUBLIC_DIR):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in files:
            if not f.startswith("."):
                full = os.path.join(root, f)
                m["/" + os.path.relpath(full, PUBLIC_DIR).replace(os.sep, "/")] = full
    return m


STATIC_MAP = _scan_public()


def send_file(full: str, cache: str, extra: Optional[dict] = None):
    if not os.path.isfile(full):
        return err(404, "Bulunamadı")
    return FileResponse(full, media_type=MIME.get(os.path.splitext(full)[1], "application/octet-stream"), headers={"Cache-Control": cache, **(extra or {})})


def _register_legal():
    for route, f in LEGAL_PAGES.items():
        def make(name):
            async def h():
                return send_file(os.path.join(PUBLIC_DIR, "legal", name), "no-cache")
            return h
        app.add_api_route(route, make(f), methods=["GET"], include_in_schema=False)


_register_legal()


@app.get("/")
async def home():
    return send_file(os.path.join(PUBLIC_DIR, "index.html"), "no-cache")


@app.get("/sw.js")
async def sw():
    return send_file(os.path.join(PUBLIC_DIR, "sw.js"), "no-cache", {"Service-Worker-Allowed": "/"})


SITE_URL = env("SITE_URL", "https://dac-web-tfqf.onrender.com").rstrip("/")


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse(f"User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: {SITE_URL}/sitemap.xml\n", headers={"Cache-Control": "public, max-age=86400"})


@app.get("/sitemap.xml")
async def sitemap():
    legal = "".join(f"  <url><loc>{SITE_URL}{u}</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>\n" for u in LEGAL_PAGES)
    body = f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>{SITE_URL}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n{legal}</urlset>'
    return Response(body, media_type="application/xml", headers={"Cache-Control": "public, max-age=86400"})


async def _security_txt():
    exp = iso(datetime.now(timezone.utc) + timedelta(days=365))
    return PlainTextResponse(f"Contact: {env('SECURITY_CONTACT') or 'mailto:security@example.com'}\nExpires: {exp}\nPreferred-Languages: tr, en\nCanonical: {SITE_URL}/.well-known/security.txt\n", headers={"Cache-Control": "public, max-age=86400"})


app.add_api_route("/.well-known/security.txt", _security_txt, methods=["GET"], include_in_schema=False)
app.add_api_route("/security.txt", _security_txt, methods=["GET"], include_in_schema=False)


@app.get("/health")
async def health():
    p = payments_status()
    return jres({"ok": True, "version": SCANNER_VERSION, "payments": {"stripe": p.stripe, "iyzico": p.iyzico}, "timestamp": iso(datetime.now(timezone.utc))}, headers={"Cache-Control": "no-store"})


@app.get("/api/firebase-config")
async def firebase_config():
    w = web_config()
    if not w.ok:
        return jres({"success": False, "error": w.error or "Firebase web yapılandırması eksik.", "missing": w.missing}, 503, {"Cache-Control": "no-store"})
    return jres({"success": True, "config": w.config}, headers={"Cache-Control": "no-store"})


# ---------- Kullanıcı durumu ----------
state_limiter = Limiter(env_int("STATE_RATE_LIMIT", 120), 5 * 60 * 1000)
acc_limiter = Limiter(env_int("ACCOUNT_RATE_LIMIT", 10), 60 * 60 * 1000)
pay_limiter = Limiter(env_int("PAY_RATE_LIMIT", 20), 10 * 60 * 1000)


async def state_guard(request: Request, limiter=state_limiter, msg="Çok fazla istek. Biraz sonra tekrar deneyin.") -> J:
    if not FB.db:
        raise HttpError(503, "Sunucuda Firebase yapılandırılmamış; bulut kaydı kapalı.")
    user = await authenticate(request)
    if not limiter(user.uid):
        raise HttpError(429, msg)
    return user


def _state_ref(uid):
    return FB.db.collection("users").document(uid).collection("state").document("app")


@app.get("/api/state")
@route_guard
async def get_state(request: Request):
    u = await state_guard(request)
    d = await asyncio.to_thread(lambda: _state_ref(u.uid).get())
    if not d.exists:
        return jres({"success": True, "exists": False, "version": 0})
    x = d.to_dict()
    try:
        st = json.loads(x.get("data"))
    except Exception:
        st = None
    return jres({"success": True, "exists": True, "version": x.get("version") or 0, "updatedAt": x.get("updatedAt"), "state": st})


@app.put("/api/state")
@route_guard
async def put_state(request: Request):
    u = await state_guard(request)
    body = await read_json(request, 1024 * 1024)
    bv = body.get("baseVersion")
    base_version = bv if isinstance(bv, int) and not isinstance(bv, bool) else 0
    state = sanitize_state(body.get("state"))
    js = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    if len(js.encode("utf-8")) > STATE_LIMITS["bytes"]:
        return err(413, "Veri çok büyük.", code="STATE_TOO_LARGE")

    def work():
        fs = FB.firestore
        r = _state_ref(u.uid)

        @fs.transactional
        def txn(t):
            d = r.get(transaction=t)
            cur = (d.to_dict() or {}).get("version") or 0 if d.exists else 0
            if cur != base_version:
                return J(conflict=True, version=cur, data=(d.to_dict() or {}).get("data") if d.exists else None)
            ver = cur + 1
            t.set(r, {"data": js, "version": ver, "updatedAt": now_ms(), "size": len(js)})
            return J(version=ver)
        return txn(FB.db.transaction())
    out = await asyncio.to_thread(work)
    if out.conflict:
        try:
            remote = json.loads(out.data) if out.data else None
        except Exception:
            remote = None
        return jres({"success": False, "code": "VERSION_CONFLICT", "error": "Veri başka bir cihazda güncellenmiş.", "version": out.version, "state": remote}, 409)
    return jres({"success": True, "version": out.version})


CONSENT_TYPES = {"terms", "privacy", "cookies-analytics", "distance-sales", "withdrawal-waiver"}


@app.post("/api/consent")
@route_guard
async def post_consent(request: Request):
    u = await state_guard(request)
    body = await read_json(request)
    typ, ver = str(body.get("type") or ""), str(body.get("version") or "")[:40]
    if typ not in CONSENT_TYPES or not ver:
        return err(400, "Geçersiz onay kaydı.")
    await asyncio.to_thread(lambda: FB.db.collection("consents").add({"uid": u.uid, "type": typ, "version": ver, "granted": body.get("granted") is not False, "at": now_ms(), "ip": client_ip(request),
                                                                      "ua": request.headers.get("user-agent", "")[:200]}))
    return jres({"success": True})


async def _rows(coll, field, uid, mx=2000):
    from google.cloud.firestore_v1.base_query import FieldFilter

    def work():
        return [{"id": d.id, **d.to_dict()} for d in FB.db.collection(coll).where(filter=FieldFilter(field, "==", uid)).limit(mx).stream()]
    return await asyncio.to_thread(work)


async def _delete_where(coll, field, uid) -> int:
    from google.cloud.firestore_v1.base_query import FieldFilter

    def work():
        n = 0
        for _ in range(200):
            snaps = list(FB.db.collection(coll).where(filter=FieldFilter(field, "==", uid)).limit(400).stream())
            if not snaps:
                break
            b = FB.db.batch()
            for s in snaps:
                b.delete(s.reference)
            b.commit()
            n += len(snaps)
            if len(snaps) < 400:
                break
        return n
    return await asyncio.to_thread(work)


@app.get("/api/account/export")
@route_guard
async def account_export(request: Request):
    u = await state_guard(request, acc_limiter, "Çok fazla hesap işlemi. Bir saat sonra tekrar deneyin.")
    uid = u.uid
    st, sub, usr, assets, checks, orders, consents = await asyncio.gather(
        asyncio.to_thread(lambda: _state_ref(uid).get()), get_doc("subscriptions", uid), get_doc("users", uid),
        _rows("assets", "ownerId", uid), _rows("assetChecks", "ownerId", uid), _rows("orders", "uid", uid), _rows("consents", "uid", uid))
    state = None
    if st.exists:
        try:
            state = json.loads(st.to_dict().get("data"))
        except Exception:
            state = None
    return jres({"success": True, "exportedAt": iso(datetime.now(timezone.utc)), "profile": {"uid": uid, "email": u.email, "name": u.name}, "account": usr, "subscription": sub, "state": state,
                 "assets": assets, "assetChecks": checks, "orders": orders, "consents": consents}, headers={"Content-Disposition": 'attachment; filename="dac-verilerim.json"', "Cache-Control": "no-store"})


@app.delete("/api/account")
@route_guard
async def account_delete(request: Request):
    u = await state_guard(request, acc_limiter, "Çok fazla hesap işlemi. Bir saat sonra tekrar deneyin.")
    uid = u.uid
    body = await read_json(request, 4096)
    if str(body.get("confirm") or "") != "HESABIMI SIL":
        return err(400, 'Onay için "HESABIMI SIL" yazın.')
    sub = await get_doc("subscriptions", uid)
    if sub and sub.get("provider") == "stripe" and sub.get("status") == "active":
        return err(409, "Aktif bir USD aboneliğiniz var. Önce Paket sayfasından aboneliği iptal edin, sonra hesabı silin.", code="ACTIVE_SUBSCRIPTION")
    counts = {"assets": await _delete_where("assets", "ownerId", uid), "assetChecks": await _delete_where("assetChecks", "ownerId", uid)}
    await asyncio.to_thread(lambda: _state_ref(uid).delete())
    await asyncio.to_thread(lambda: _doc("users", uid).delete())
    # orders / subscriptions / consents: vergi ve ticari defter saklama yükümlülüğü ile ispat amacıyla yasal süre boyunca korunur.
    try:
        await asyncio.to_thread(FB.auth.delete_user, uid)
    except Exception as e:
        if "USER_NOT_FOUND" not in str(e).upper() and "user-not-found" not in str(e):
            raise
    return jres({"success": True, "deleted": counts})


# ---------- Abonelik / ödeme ----------
async def pay_guard(request: Request):
    if not pay_limiter(client_ip(request)):
        raise HttpError(429, "Çok fazla istek. Biraz sonra tekrar deneyin.")


@app.get("/api/subscription")
@route_guard
async def subscription(request: Request):
    await pay_guard(request)
    u = await verify_user(request)
    return jres({"success": True, **(await get_entitlement(u.uid)), "serverTime": now_ms()})


@app.post("/api/checkout")
@route_guard
async def checkout(request: Request):
    await pay_guard(request)
    u = await verify_user(request)
    body = await read_json(request)
    plan, cycle, currency = body.get("plan"), body.get("cycle") or "monthly", body.get("currency") or "TRY"
    billing = body.get("billing") if isinstance(body.get("billing"), dict) else {}
    consent = body.get("consent")
    if not isinstance(consent, dict) or consent.get("distanceSales") is not True or consent.get("withdrawalWaiver") is not True:
        raise HttpError(400, "Ödeme için Ön Bilgilendirme Formu, Mesafeli Satış Sözleşmesi ve cayma hakkı beyanını onaylamalısınız.")
    if not u.email and not billing.get("email"):
        raise HttpError(400, "Ödeme için e-posta adresi gerekli.")
    if plan not in PAID:
        raise HttpError(400, "Geçersiz paket.")
    if cycle not in ("monthly", "yearly"):
        raise HttpError(400, "Geçersiz dönem.")
    await asyncio.to_thread(lambda: FB.db.collection("consents").add({"uid": u.uid, "type": "distance-sales", "version": LEGAL_VERSION, "granted": True, "plan": str(plan)[:30], "at": now_ms(),
                                                                      "ip": client_ip(request), "ua": request.headers.get("user-agent", "")[:200]}))
    P = PLANS[plan]
    amount = plan_price(plan, "USD" if currency == "USD" else "TRY", cycle)
    back = return_url_of(request, body)
    label = f"Digital Asset Center - {P.name} ({'Yıllık' if cycle == 'yearly' else 'Aylık'})"
    if currency == "USD":
        if not stripe_key():
            raise HttpError(503, "USD ödemesi henüz yapılandırılmadı (STRIPE_SECRET_KEY).")
        prev = (await get_doc("subscriptions", u.uid)) or {}
        meta = {"uid": u.uid, "plan": plan, "cycle": cycle}
        s = await stripe_api("POST", "/checkout/sessions", {
            "mode": "subscription", "success_url": with_param(back, "paid", "1"), "cancel_url": with_param(back, "paid", "0"), "client_reference_id": u.uid,
            **({"customer": prev["stripeCustomerId"]} if prev.get("stripeCustomerId") else {"customer_email": u.email}),
            "line_items": [{"quantity": 1, "price_data": {"currency": "usd", "unit_amount": js_round(amount * 100), "product_data": {"name": label}, "recurring": {"interval": "year" if cycle == "yearly" else "month"}}}],
            "metadata": meta, "subscription_data": {"metadata": meta}})
        return jres({"success": True, "provider": "stripe", "url": s.url})
    if not iyzi_ready():
        raise HttpError(503, "TL ödemesi henüz yapılandırılmadı (IYZICO_API_KEY / IYZICO_SECRET_KEY).")
    name, address, city = str(billing.get("name") or "").strip(), str(billing.get("address") or "").strip(), str(billing.get("city") or "").strip()
    if not name or not address or not city:
        raise HttpError(400, "TL ödemesi için Ayarlar > Fatura Bilgileri (ad soyad, adres, şehir) doldurulmalı.")
    order_ref = FB.db.collection("orders").document()
    price_str = f"{amount:.2f}"
    await asyncio.to_thread(lambda: order_ref.set({"uid": u.uid, "plan": plan, "cycle": cycle, "currency": "TRY", "amount": amount, "status": "pending", "returnUrl": back, "consentVersion": LEGAL_VERSION, "createdAt": now_ms()}))
    parts = name.split()
    surname = parts.pop() if len(parts) > 1 else "-"
    first = " ".join(parts)
    addr = {"contactName": name, "city": city, "country": billing.get("country") or "Turkey", "address": address}
    tax = re.sub(r"\D", "", str(billing.get("taxId") or ""))
    buyer = {"id": u.uid, "name": first, "surname": surname, "email": str(billing.get("email") or u.email)[:120], "identityNumber": tax if len(tax) == 11 else "11111111111", "registrationAddress": address,
             "ip": client_ip(request).replace("::ffff:", "") or "0.0.0.0", "city": city, "country": billing.get("country") or "Turkey"}
    if billing.get("phone"):
        buyer["gsmNumber"] = billing["phone"]
    req = {"locale": "tr", "conversationId": order_ref.id, "price": price_str, "paidPrice": price_str, "currency": "TRY", "basketId": order_ref.id, "paymentGroup": "PRODUCT",
           "callbackUrl": self_url(request) + "/api/iyzico/callback", "enabledInstallments": [1], "buyer": buyer, "shippingAddress": addr, "billingAddress": addr,
           "basketItems": [{"id": f"{plan}_{cycle}", "name": label, "category1": "Yazılım", "itemType": "VIRTUAL", "price": price_str}]}
    result = jj(await asyncio.to_thread(_iyzi_call, "init", req))
    if result.status != "success":
        raise HttpError(502, "iyzico: " + str(result.errorMessage or "ödeme formu oluşturulamadı"))
    return jres({"success": True, "provider": "iyzico", "url": result.paymentPageUrl or None, "html": None if result.paymentPageUrl else result.checkoutFormContent})


@app.post("/api/iyzico/callback")
@route_guard
async def iyzico_callback(request: Request):
    await pay_guard(request)
    raw = await read_body(request, 100 * 1024)
    form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
    token = (form.get("token") or [None])[0]
    if not isinstance(token, str) or len(token) >= 300:
        token = None

    def back(u, ok):
        return RedirectResponse(with_param(u or "/", "paid", "1" if ok else "0") + "#plan", status_code=303)
    if not token or not iyzi_ready() or not FB.db:
        return back(None, False)
    r = jj(await asyncio.to_thread(_iyzi_call, "retrieve", {"locale": "tr", "token": token}))
    order_id = str(r.basketId or r.conversationId or "")
    if not re.fullmatch(r"[A-Za-z0-9]{10,40}", order_id):
        return back(None, False)
    order = await get_doc("orders", order_id)
    if not order:
        return back(None, False)
    ref = _doc("orders", order_id)
    try:
        paid_price = float(r.paidPrice)
    except (TypeError, ValueError):
        paid_price = -1
    paid = r.status == "success" and r.paymentStatus == "SUCCESS" and paid_price + 0.01 >= order["amount"]
    if not paid:
        await asyncio.to_thread(lambda: ref.set({"status": "failed", "gatewayStatus": r.paymentStatus or r.errorMessage or None}, merge=True))
        return back(order.get("returnUrl"), False)

    def mark():
        fs = FB.firestore

        @fs.transactional
        def txn(t):
            o = (ref.get(transaction=t).to_dict())
            if not o or o.get("status") == "paid":
                return False
            t.set(ref, {"status": "paid", "paidAt": now_ms(), "paymentId": r.paymentId or None}, merge=True)
            return True
        return txn(FB.db.transaction())
    first = await asyncio.to_thread(mark)
    if first:
        cur = (await get_doc("subscriptions", order["uid"])) or {}
        start_from = cur["periodEnd"] if (cur.get("status") == "active" and (cur.get("periodEnd") or 0) > now_ms() and cur.get("plan") == order["plan"]) else now_ms()
        await activate(order["uid"], {"plan": order["plan"], "status": "active", "provider": "iyzico", "currency": "TRY", "cycle": order["cycle"], "periodEnd": start_from + (365 if order["cycle"] == "yearly" else 30) * 86400000})
    return back(order.get("returnUrl"), True)


@app.post("/api/stripe/webhook")
@route_guard
async def stripe_webhook(request: Request):
    secret = env("STRIPE_WEBHOOK_SECRET")
    body = await read_body(request, 256 * 1024)
    if not secret or not body or not FB.db:
        raise HttpError(503, "Webhook yapılandırılmadı.")
    if not verify_stripe_signature(body, request.headers.get("stripe-signature"), secret):
        raise HttpError(400, "İmza doğrulanamadı.")
    try:
        ev = jj(json.loads(body.decode("utf-8")))
    except Exception:
        raise HttpError(400, "Geçersiz olay.")
    o = ev.data.object if (ev and ev.data) else None
    if not ev or not ev.id or not o:
        raise HttpError(400, "Geçersiz olay.")
    ev_ref = _doc("webhookEvents", str(ev.id))

    def claim():
        fs = FB.firestore

        @fs.transactional
        def txn(t):
            if ev_ref.get(transaction=t).exists:
                return False
            t.set(ev_ref, {"type": ev.type, "at": now_ms()})
            return True
        return txn(FB.db.transaction())
    if not await asyncio.to_thread(claim):
        return jres({"received": True, "duplicate": True})
    try:
        if ev.type == "checkout.session.completed" and o.subscription:
            await stripe_sync(await stripe_api("GET", "/subscriptions/" + str(o.subscription)))
        elif ev.type == "invoice.paid":
            sid = o.subscription or (((o.parent or {}).get("subscription_details") or {}).get("subscription"))
            if sid:
                await stripe_sync(await stripe_api("GET", "/subscriptions/" + str(sid)))
        elif ev.type in ("customer.subscription.updated", "customer.subscription.deleted"):
            await stripe_sync(o)
    except Exception:
        try:
            await asyncio.to_thread(ev_ref.delete)
        except Exception:
            pass
        raise  # işlenemediyse Stripe tekrar deneyebilsin
    return jres({"received": True})


@app.post("/api/billing-portal")
@route_guard
async def billing_portal(request: Request):
    await pay_guard(request)
    u = await verify_user(request)
    body = await read_json(request)
    if not stripe_key():
        raise HttpError(503, "Stripe yapılandırılmadı.")
    sub = await get_doc("subscriptions", u.uid)
    if not sub or not sub.get("stripeCustomerId"):
        raise HttpError(404, "Stripe aboneliği bulunamadı.")
    s = await stripe_api("POST", "/billing_portal/sessions", {"customer": sub["stripeCustomerId"], "return_url": return_url_of(request, body)})
    return jres({"success": True, "url": s.url})


# ---------- Tarama ----------
ip_limit = Limiter(env_int("SCAN_RATE_LIMIT", 60), 5 * 60 * 1000)
user_limit = Limiter(env_int("SCAN_USER_RATE_LIMIT", 30), 5 * 60 * 1000)
concurrency = Concurrency(env_int("SCAN_CONCURRENCY_PER_USER", 2), env_int("SCAN_CONCURRENCY_GLOBAL", 8))
ASSET_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@app.post("/api/scan")
@route_guard
async def api_scan(request: Request):
    if not ip_limit(client_ip(request)):
        return err(429, "Çok fazla istek. Biraz sonra tekrar deneyin.")
    user = await authenticate(request)
    if not user_limit(user.uid):
        return err(429, "Çok fazla istek. Biraz sonra tekrar deneyin.")
    body = await read_json(request)
    if not isinstance(body, dict):
        return err(400, "Geçersiz istek")
    uid = user.uid
    asset_id, typ, name = body.get("assetId"), body.get("type"), body.get("name")
    if body.get("targetUrl") is not None and not isinstance(body.get("targetUrl"), str):
        return err(400, "targetUrl metin olmalı")
    target_url = (body.get("targetUrl") or "").strip()[:2048]
    extra = body.get("extra") if isinstance(body.get("extra"), dict) else {}
    if not asset_id or not isinstance(asset_id, str) or len(asset_id) > 200 or not ASSET_ID_RE.match(asset_id):
        return err(400, "assetId gerekli (harf, rakam, - ve _)")
    asset_type = str(typ or "WEBSITE").upper()
    handler = TYPE_HANDLERS.get(asset_type)
    if not handler:
        return err(400, f"Desteklenmeyen tür: {asset_type}")
    for k in ("domain", "target"):
        if extra.get(k) is not None and not isinstance(extra.get(k), str):
            return err(400, f"extra.{k} metin olmalı")
    if asset_type not in NO_HOST_TYPES and not (target_url or extra.get("domain") or extra.get("target")):
        return err(400, "Hedef adres gerekli")
    if asset_type in ACTIVE_PROBE_TYPES and body.get("consent") is not True:
        return err(400, "Bu tarama türü için hedefi taramaya yetkili olduğunuzu onaylamalısınız.", code="CONSENT_REQUIRED")
    if asset_type not in NO_HOST_TYPES:
        host_check = host_of(target_url or extra.get("domain") or extra.get("target"))
        if not host_check:
            return err(400, "Geçerli bir hedef adres girin")
        try:
            await assert_public_host(host_check)
        except RuntimeError as e:
            return err(400, str(e))
    if enforce_plans() and not user.dev and not FB.db and env("ALLOW_SCAN_WITHOUT_DB") != "true":
        return err(503, "Sunucu yapılandırması eksik (veritabanı). Lütfen daha sonra tekrar deneyin.")
    release = concurrency.acquire(uid)
    if not release:
        return err(429, "Aynı anda çok fazla tarama var. Birinin bitmesini bekleyin.")
    try:
        return await _run_scan(request, uid, user, asset_id, asset_type, handler, name, target_url, extra, body)
    finally:
        release()


async def _run_scan(request, uid, user, asset_id, asset_type, handler, name, target_url, extra, body):
    ent = None
    if enforce_plans() and not user.dev and FB.db:
        try:
            ent = await get_entitlement(uid)
        except HttpError as e:
            return err(e.status, e.message)
        if ent.plan == "expired":
            return err(402, "Deneme süreniz bitti. Devam etmek için bir paket seçin.", code="PLAN_REQUIRED")
    if FB.db:
        try:
            claim = await claim_asset(asset_id, uid)
            if not claim.ok:
                return err(403, "Bu kayıt sistem/eski veridir, kullanıcıya devredilemez." if claim.legacy else "Bu varlık size ait değil.", code="FORBIDDEN")
            if ent:
                q = await check_asset_quota(uid, ent.plan, claim.isNew)
                if not q.ok:
                    if claim.isNew:
                        try:
                            await asyncio.to_thread(lambda: _doc("assets", asset_id).delete())
                        except Exception:
                            pass
                    return err(402, f"Paket varlık limiti doldu ({q.limit}).", code="QUOTA_EXCEEDED")
        except Exception as e:
            log.error("Sahiplik/kota kontrolü hatası: %s", e)
            return err(503, "Veritabanına ulaşılamadı, tekrar deneyin.")
    scan_started = now_ms()
    findings: list = []
    scan_errors: list = []
    type_data = J()
    status_hint = None
    failed = False
    scan_conf = None
    try:
        result = await asyncio.wait_for(handler(target_url, extra), SCAN_TIMEOUT_MS / 1000)
        result = jj(result) if not isinstance(result, J) else result
        type_data = result.data or J()
        findings = list(result.findings) if isinstance(result.findings, list) else []
        if isinstance(result.errors, list):
            scan_errors.extend(result.errors)
        status_hint = result.statusHint or None
        scan_conf = result.confidence
    except asyncio.TimeoutError:
        findings.append("finding_scan_timeout_warning")
        scan_errors.append("Tarama zaman aşımı")
        status_hint = "ERROR"
        failed = True
    except Exception as e:
        log.error("[%s] tarama hatası: %s\n%s", asset_type, e, traceback.format_exc())
        findings.append("finding_scan_error")
        scan_errors.append(str(e) or "Unknown")
        status_hint = "ERROR"
        failed = True
    no_data = not type_data or not type_data.commonAnalysis
    confidence = scan_conf if scan_conf is not None else compute_confidence(findings, len(scan_errors) > 0)
    score_unavailable = failed or no_data or type_data.commonAnalysis.score is None
    final_score = None if score_unavailable else type_data.commonAnalysis.score
    level = "BELİRSİZ"
    if final_score is not None:
        level = "YEŞİL" if final_score >= 80 else "SARI" if final_score >= 50 else "KIRMIZI"
    final_status = "ERROR" if (no_data or failed) else (status_hint or type_data.commonAnalysis.status or default_status_from_health(level))
    timed_out = failed and any(re.search(r"zaman aşımı", str(m), re.I) for m in scan_errors)
    scan_status = "TIMEOUT" if timed_out else "FAILED" if (failed or no_data) else "PARTIAL" if scan_errors else "COMPLETED"
    now_iso = iso(datetime.now(timezone.utc))
    # JS: { assetId, scanStatus, assetType, type, ...typeData, findings, ... } — typeData alanları öncekileri ezer
    asset_update = J(assetId=asset_id, scanStatus=scan_status, assetType=asset_type, type=asset_type)
    asset_update.update(type_data)
    asset_update.update(findings=findings, healthLevel=level, healthScore=final_score, confidence=confidence, status=final_status, latencyMs=now_ms() - scan_started, lastCheck=now_iso, updatedAt=now_iso)
    if name:
        asset_update.name = str(name)[:200]
    if target_url:
        asset_update.targetUrl = target_url[:2048]
    asset_update.ownerId = uid
    saved, check_id, save_error = False, None, None
    if FB.db:
        try:
            ts = FB.firestore.SERVER_TIMESTAMP
            doc = for_firestore({k: v for k, v in asset_update.items() if k not in ("lastCheck", "updatedAt")})
            ca = type_data.commonAnalysis
            tgt = (ca.target if (ca and ca.target is not None) else None) or target_url or None

            def write():
                nonlocal check_id
                _doc("assets", asset_id).set({**doc, "target": tgt, "scannedAt": ts, "lastCheck": ts, "updatedAt": ts}, merge=True)
                cref = FB.db.collection("assetChecks").document()
                check_id = cref.id
                chk = for_firestore({"assetId": asset_id, "checkId": check_id, "type": asset_type, "targetUrl": target_url or None, "errors": scan_errors, "findings": findings, "healthScore": final_score,
                                     "healthLevel": level, "confidence": confidence, "latencyMs": now_ms() - scan_started, "status": final_status, "scanStatus": scan_status, "ownerId": uid,
                                     "scannerVersion": (type_data.analysisMeta.scannerVersion if type_data.analysisMeta else None), "scores": (type_data.specificAnalysis.scores if type_data.specificAnalysis else None),
                                     **({"authorizationConfirmed": True, "authorizationIp": client_ip(request)} if asset_type in ACTIVE_PROBE_TYPES else {})})
                cref.set({**chk, "checkedAt": ts})
            await asyncio.wait_for(asyncio.to_thread(write), 8)
            saved = True
        except Exception as e:
            save_error = str(e) or "Firestore hatası"
            log.error("Firestore kayıt hatası: %s", save_error)
    if scan_status in ("FAILED", "TIMEOUT"):
        return jres({"success": False, "scanStatus": scan_status, "assetId": asset_id, "checkId": check_id, "saved": saved,
                     "error": "Tarama zaman aşımına uğradı. Hedef yanıt vermiyor olabilir." if scan_status == "TIMEOUT" else "Tarama tamamlanamadı. Hedefe ulaşılamadı veya analiz sırasında hata oluştu.",
                     "errors": scan_errors}, 504 if scan_status == "TIMEOUT" else 502)
    return jres({"success": True, "scanStatus": scan_status, "assetId": asset_id, "checkId": check_id, "saved": saved, "saveError": "Sonuç kaydedilemedi" if save_error else None, "errors": scan_errors, "result": asset_update})


@app.get("/{full_path:path}", include_in_schema=False)
async def static_catch_all(full_path: str):
    """Tüm API ve sayfa rotalarından SONRA: eski adresleri yönlendirir, public/ içindeki dosyaları sunar, gerisi 404."""
    p = "/" + full_path
    if p in LEGACY_URLS:
        return RedirectResponse(LEGACY_URLS[p], status_code=301)
    full = STATIC_MAP.get(p)
    if not full or p in ("/index.html", "/sw.js"):
        return err(404, "Bulunamadı")
    base = os.path.basename(full)
    return send_file(full, STATIC_CACHE.get(base, "public, max-age=86400, stale-while-revalidate=604800"))


def main():  # yerel çalıştırma: python index.py
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(env("PORT", "3000")), proxy_headers=True, forwarded_allow_ips="*", server_header=False, date_header=False)


if __name__ == "__main__":
    main()
