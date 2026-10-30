/* Digital Asset Center - Dil katmanı (Türkçe / English)
 * Kaynak dil Türkçedir. Dil Türkçe ise bu dosya yalnızca dil seçiciyi çalıştırır (ek indirme yok).
 * Dil İngilizce ise i18n-en.js (sözlük) yüklenir ve ekrandaki Türkçe metinler İngilizceye çevrilir:
 *   - sayfa metinleri, placeholder / title / aria-label değerleri, belge başlığı
 *   - confirm / alert / prompt pencereleri
 * Tarih ve para biçimleri için window.DAC_LOC (tr-TR / en-US) kullanılır.
 * Dil seçimi tarayıcıda "dac_lang" anahtarıyla saklanır; ?lang=en veya ?lang=tr ile de ayarlanabilir. */
(function (w, d) {
  "use strict";
  var KEY = "dac_lang", LOCALES = { tr: "tr-TR", en: "en-US" }, DICT_URL = "/js/i18n-en.js?v=20261030a";

  function pick() {
    var q = "";
    try { q = (new URLSearchParams(location.search).get("lang") || "").toLowerCase(); } catch (e) {}
    if (LOCALES[q]) { try { localStorage.setItem(KEY, q); } catch (e) {} return q; }
    try { var s = localStorage.getItem(KEY); if (LOCALES[s]) return s; } catch (e) {}
    var n = String((navigator.languages && navigator.languages[0]) || navigator.language || "tr").toLowerCase();
    return n.indexOf("tr") === 0 ? "tr" : "en";
  }

  var lang = pick(), de = d.documentElement;
  var W = null, F = null, FRE = null, PRE = null, RULES = [], memo = new Map(), started = false, obs = null;
  var HAS_LETTER = /[A-Za-zÇĞİÖŞÜçğıöşü]/;
  var ATTRS = ["placeholder", "title", "aria-label", "alt"];
  var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, NOSCRIPT: 1 };

  var api = w.DAC_I18N = {
    lang: lang, isEN: lang === "en", locale: LOCALES[lang],
    // Kaynak (Türkçe) metni geçerli dile çevirir; {ad} yer tutucularını vars ile doldurur
    t: function (s, vars) {
      var o = api.isEN && W ? conv(String(s)) : String(s);
      if (vars) for (var k in vars) if (Object.prototype.hasOwnProperty.call(vars, k)) o = o.split("{" + k + "}").join(vars[k]);
      return o;
    },
    tr: function (s) { return api.isEN && W ? tr(s) : s; },
    set: function (l) {
      if (!LOCALES[l]) return;
      try { localStorage.setItem(KEY, l); } catch (e) {}
      if (l === lang) return;
      // not: sayfada global "history" adlı bir fonksiyon var; History API yerine location kullanılır
      try { var u = new URL(location.href); if (u.searchParams.has("lang")) { u.searchParams.delete("lang"); location.replace(u.pathname + u.search + u.hash); return; } } catch (e) {}
      location.reload();
    },
    _load: function (D) { build(D); begin(); }
  };
  w.DAC_LOC = LOCALES[lang];
  de.lang = lang;
  try { if (localStorage.getItem("dac_last_uid")) de.classList.add("ret"); } catch (e) {}

  /* ---------- çeviri motoru (yalnızca İngilizce) ---------- */
  var esc = function (s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); };
  function build(D) {
    W = D.W || {}; F = D.F || {};
    var fk = Object.keys(F).sort(function (a, b) { return b.length - a.length; });
    FRE = fk.length ? new RegExp(fk.map(esc).join("|"), "g") : null;
    var pk = Object.keys(W).filter(function (k) { return k.indexOf(" ") > 0 && k.length >= 14; }).sort(function (a, b) { return b.length - a.length; });
    try { PRE = pk.length ? new RegExp("(^|[^\\p{L}\\p{N}])(" + pk.map(esc).join("|") + ")(?![\\p{L}\\p{N}])", "gu") : null; } catch (e) { PRE = null; }
    RULES = (D.R || []).map(function (r) { return [new RegExp(r[0], r[1] || ""), r[2]]; });
  }
  function conv(s) {
    var m = /^(\s*)([\s\S]*?)(\s*)$/.exec(s), core = m[2];
    if (!core || !HAS_LETTER.test(core)) return s;
    if (Object.prototype.hasOwnProperty.call(W, core)) return m[1] + W[core] + m[3];
    for (var i = 0; i < RULES.length; i++) {
      var rm = RULES[i][0].exec(core);
      if (rm) return m[1] + RULES[i][1].replace(/\$(\d)/g, function (x, k) { var g = rm[+k]; return g == null ? "" : conv(g); }) + m[3];
    }
    var norm = s.replace(/\s+/g, " "), o = norm;
    if (FRE) o = o.replace(FRE, function (x) { return F[x]; });
    if (PRE) o = o.replace(PRE, function (x, a, b) { return a + W[b]; });
    return o !== norm ? o : s;
  }
  function tr(s) {
    if (s == null) return s;
    s = String(s);
    var c = memo.get(s); if (c !== undefined) return c;
    var o = conv(s);
    if (memo.size > 6000) memo.clear();
    memo.set(s, o);
    return o;
  }
  function skipText(n) {
    var p = n.parentNode;
    if (!p || SKIP_TAGS[p.nodeName]) return true;
    return !!(p.closest && p.closest("main.legal,noscript,[data-i18n-skip]"));
  }
  function textNode(n) {
    if (skipText(n)) return;
    var v = n.nodeValue; if (!v || !HAS_LETTER.test(v)) return;
    var t = tr(v); if (t !== v) n.nodeValue = t;
  }
  function attrs(el) {
    if (!el.getAttribute || (el.closest && el.closest("main.legal,[data-i18n-skip]"))) return;
    for (var i = 0; i < ATTRS.length; i++) {
      if (el.hasAttribute(ATTRS[i])) { var v = el.getAttribute(ATTRS[i]), t = tr(v); if (t !== v) el.setAttribute(ATTRS[i], t); }
    }
    if (el.nodeName === "INPUT" && /^(button|submit)$/i.test(el.type || "") && el.value) { var tv = tr(el.value); if (tv !== el.value) el.value = tv; }
  }
  function walk(root) {
    if (!root) return;
    if (root.nodeType === 3) { textNode(root); return; }
    if (root.nodeType !== 1) return;
    attrs(root);
    if (SKIP_TAGS[root.nodeName]) return;
    var tw = d.createTreeWalker(root, 5, null), n;
    while ((n = tw.nextNode())) { if (n.nodeType === 3) textNode(n); else attrs(n); }
  }
  function meta() {
    if (d.title) { var t = tr(d.title); if (t !== d.title) d.title = t; }
    d.querySelectorAll('meta[name="description"],meta[property="og:title"],meta[property="og:description"],meta[name="twitter:title"],meta[name="twitter:description"]').forEach(function (m) {
      var v = m.getAttribute("content"), t = tr(v); if (t !== v) m.setAttribute("content", t);
    });
  }
  function begin() {
    if (started) return; started = true;
    ["confirm", "alert", "prompt"].forEach(function (n) {
      var o = w[n]; if (typeof o !== "function") return;
      w[n] = function (m, x) { return o.call(w, tr(m), x); };
    });
    var go = function () {
      walk(d.body); meta();
      de.classList.remove("i18n-wait");
      obs = new MutationObserver(function (list) {
        for (var i = 0; i < list.length; i++) {
          var m = list[i];
          if (m.type === "childList") { for (var j = 0; j < m.addedNodes.length; j++) walk(m.addedNodes[j]); }
          else if (m.type === "characterData") textNode(m.target);
          else if (m.type === "attributes") attrs(m.target);
        }
      });
      obs.observe(d.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
    };
    if (d.body) go(); else d.addEventListener("DOMContentLoaded", go);
  }

  /* ---------- dil seçici düğmeleri ---------- */
  function mark() {
    d.querySelectorAll("[data-lang]").forEach(function (b) {
      var on = b.getAttribute("data-lang") === lang;
      b.classList.toggle("on", on); b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }
  d.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest("[data-lang]");
    if (b) { e.preventDefault(); api.set(b.getAttribute("data-lang")); }
  });

  /* Yasal sayfalar: üst çubuğa dil seçici ve (İngilizce iken) bilgi notu */
  function legalExtras() {
    if (!d.body || !d.body.classList.contains("legalpage")) return;
    var head = d.querySelector(".lhead");
    if (head && !head.querySelector(".langsw")) {
      var g = d.createElement("div"); g.className = "langsw"; g.setAttribute("role", "group"); g.setAttribute("aria-label", "Dil / Language");
      g.innerHTML = '<button type="button" data-lang="tr">TR</button><button type="button" data-lang="en">EN</button>';
      head.insertBefore(g, head.firstChild);
    }
    if (api.isEN && !d.querySelector(".legal-note")) {
      var n = d.createElement("div"); n.className = "legal-note"; n.setAttribute("data-i18n-skip", "");
      n.textContent = "The legal documents on this page are provided in Turkish, as required by applicable Turkish law. For questions, please contact us in English or Turkish.";
      var m = d.querySelector("main.legal"); if (m && m.parentNode) m.parentNode.insertBefore(n, m);
    }
  }
  function ready() { legalExtras(); mark(); }
  if (d.readyState === "loading") d.addEventListener("DOMContentLoaded", ready); else ready();

  /* ---------- sözlüğü yükle (yalnızca İngilizce) ---------- */
  if (api.isEN) {
    de.classList.add("i18n-wait");
    var s = d.createElement("script"); s.src = DICT_URL; s.async = false;
    s.onerror = function () { de.classList.remove("i18n-wait"); };
    (d.head || de).appendChild(s);
    setTimeout(function () { de.classList.remove("i18n-wait"); }, 4000);
  }
})(window, document);
