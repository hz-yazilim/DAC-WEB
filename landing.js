/* Digital Asset Center - Karşılama (landing) sayfası davranışları
 * - Giriş ekranı ikinci adımdır: #giris / #kayit adresleri giriş penceresini açar, "geri" tanıtım sayfasına döner.
 * - Üye olmayanlar tanıtım sayfasını gezebilir; analiz / varlık ekleme / paket seçimi giriş ister.
 * - Paket kartları plans.js (ve varsa /api/pricing'deki güncel fiyatlar) ile çizilir. */
(function (w, d) {
  "use strict";
  var I = w.DAC_I18N || { t: function (s, v) { v = v || {}; for (var k in v) s = s.split("{" + k + "}").join(v[k]); return s; }, locale: "tr-TR" };
  var T = function (s, v) { return I.t(s, v); };
  var B = d.body, $ = function (s, r) { return (r || d).querySelector(s); }, $$ = function (s, r) { return Array.prototype.slice.call((r || d).querySelectorAll(s)); };
  var savedY = 0;

  function icons() { try { if (w.lucide) w.lucide.createIcons(); } catch (e) {} }
  function loginHash() { return location.hash === "#giris" || location.hash === "#kayit"; }
  function setMsg(m) { var e = $("#lmsg"); if (e) e.textContent = m || ""; }

  /* ---------- giriş penceresi (ikinci adım) ---------- */
  function sync() {
    var on = loginHash(), was = B.classList.contains("showlogin");
    if (on === was) return;
    B.classList.toggle("showlogin", on);
    if (on) { setTimeout(function () { var e = $("#lemail"); if (e && !B.classList.contains("authed")) { try { e.focus({ preventScroll: true }); } catch (x) {} } }, 60); w.scrollTo(0, 0); }
    else { w.scrollTo(0, savedY); }
  }
  function openLogin(mode, msg) {
    savedY = w.scrollY || 0;
    setMsg(msg || "");
    var h = mode === "register" ? "#kayit" : "#giris";
    if (location.hash === h) sync(); else location.hash = h;
  }
  function closeLogin() {
    setMsg("");
    if (location.hash) location.hash = ""; else sync(); // not: sayfada global "history" adlı bir fonksiyon var; History API kullanılmaz
  }
  addEventListener("hashchange", sync);

  d.addEventListener("click", function (e) {
    var t = e.target.closest ? e.target : null; if (!t) return;
    var lg = t.closest("[data-login]");
    if (lg) { e.preventDefault(); openLogin(lg.getAttribute("data-login")); return; }
    var go = t.closest("[data-go]");
    if (go) { var el = d.getElementById(go.getAttribute("data-go")); if (el) { e.preventDefault(); el.scrollIntoView({ behavior: "smooth", block: "start" }); } return; }
    var pl = t.closest("[data-plan]");
    if (pl) {
      try { localStorage.setItem("dac_after_login", pl.getAttribute("data-plan") === "trial" ? "#dash" : "#plan"); } catch (x) {}
      openLogin("register", T("Paket seçmek için giriş yapın veya hesap oluşturun."));
      return;
    }
    if (t.closest("#lp-back")) { closeLogin(); return; }
    var cu = t.closest("[data-cur]"); if (cu) { cur = cu.getAttribute("data-cur"); mark("#lp-cur", "data-cur", cur); plans(); return; }
    var cy = t.closest("[data-cyc]"); if (cy) { cyc = cy.getAttribute("data-cyc"); mark("#lp-cyc", "data-cyc", cyc); plans(); return; }
  });
  d.addEventListener("keydown", function (e) { if (e.key === "Escape" && B.classList.contains("showlogin") && !B.classList.contains("authed")) closeLogin(); });
  function mark(sel, attr, val) { $$(sel + " button").forEach(function (b) { b.classList.toggle("on", b.getAttribute(attr) === val); }); }

  /* ---------- paketler ---------- */
  var P = w.DAC_PLANS, cur = "TRY", cyc = "monthly", live = null;
  function money(n, c) {
    if (n == null) return "—";
    var o = { minimumFractionDigits: 2, maximumFractionDigits: 2 };
    return c === "TRY" ? n.toLocaleString(I.locale || "tr-TR", o) + " ₺" : "$" + n.toLocaleString("en-US", o);
  }
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); };
  function price(id) {
    var base = live && live.plans && live.plans[id] && live.plans[id].prices && live.plans[id].prices[cur] != null ? live.plans[id].prices[cur] : (P.PLANS[id].prices || {})[cur];
    if (base == null) return null;
    var m = cyc === "yearly" ? (live && live.yearlyMonths) || P.YEARLY_MONTHS : 1;
    return Math.round(base * m * 100) / 100;
  }
  function plans() {
    var box = $("#lp-plans"); if (!box || !P) return;
    var ym = (live && live.yearlyMonths) || P.YEARLY_MONTHS, td = (live && live.trialDays) || P.TRIAL_DAYS;
    var note = $("#lp-yearnote"); if (note) note.textContent = T("Yıllık ödemede 12 ay yerine {m} ay ücret alınır.", { m: ym });
    box.innerHTML = ["trial"].concat(P.PAID).map(function (id) {
      var p = P.PLANS[id]; if (!p) return "";
      var feats = (live && live.plans && live.plans[id] && live.plans[id].features) || p.features;
      if (id === "trial") feats = feats.map(function (f) { return /^\d+ gün ücretsiz$/.test(f) ? T("{n} gün ücretsiz", { n: td }) : f; });
      var pr = id === "trial" ? T("Ücretsiz") : money(price(id), cur);
      var per = id === "trial" ? "" : " <small>" + (cyc === "yearly" ? "/ yıl" : "/ ay") + "</small>";
      return '<div class="card plan' + (p.popular ? " on" : "") + '">' + (p.popular ? '<span class="badge ok pop">Popüler</span>' : "") +
        "<h3>" + esc(p.name) + '</h3><div class="hint">' + esc(p.audience) + "</div>" +
        '<div class="price">' + esc(pr) + per + "</div>" +
        '<ul class="ul">' + feats.map(function (f) { return "<li>" + esc(f) + "</li>"; }).join("") + "</ul>" +
        '<button class="btn p w" type="button" data-plan="' + esc(id) + '">' + (id === "trial" ? "Ücretsiz dene" : "Bu paketi seç") + "</button></div>";
    }).join("");
    $$("[data-trial-days]").forEach(function (e) { e.textContent = td; });
    var n = $("#lp-note"); if (n) n.textContent = T("{n} gün ücretsiz deneme, kart bilgisi istenmez.", { n: td });
  }
  function loadLive() {
    var base = ((w.DAC_CONFIG || {}).API_URL || "").replace(/\/$/, "");
    if (!base || !w.fetch) return;
    fetch(base + "/api/pricing", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (j) { if (j && j.success && j.plans) { live = j; plans(); } }).catch(function () {});
  }

  /* ---------- giriş sonrası: hedef sayfa ve hazır adres ---------- */
  function wrapStart() {
    var o = w.dacStart; if (typeof o !== "function" || o._lp) return;
    var n = function (u) {
      var after = null;
      try { after = localStorage.getItem("dac_after_login"); localStorage.removeItem("dac_after_login"); } catch (e) {}
      if (loginHash() || after) { try { location.replace(location.pathname + location.search + (after || "#dash")); } catch (e) {} }
      B.classList.remove("showlogin");
      var r = o.apply(this, arguments);
      prefill();
      return r;
    };
    n._lp = 1; w.dacStart = n;
  }
  function prefill() {
    var v = null;
    try { var o = JSON.parse(localStorage.getItem("dac_pending_target") || "null"); localStorage.removeItem("dac_pending_target"); if (o && o.v && Date.now() - o.at < 36e5) v = o.v; } catch (e) {}
    if (!v) return;
    setTimeout(function () {
      var i = $('[data-form="quick"] [name="t"]');
      if (i) { i.value = v; try { i.focus({ preventScroll: true }); } catch (e) {} }
      try { if (typeof toast === "function") toast(T("Adresiniz hazır. Kategoriyi seçip taramayı başlatabilirsiniz.")); } catch (e) {}
    }, 400);
  }
  wrapStart();

  /* ---------- başlat ---------- */
  var y = $("#lp-year"); if (y) y.textContent = new Date().getFullYear();
  plans(); loadLive(); sync(); icons();
})(window, document);
