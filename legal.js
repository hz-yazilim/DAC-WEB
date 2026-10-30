/* Yasal sayfalar: şirket bilgilerini [data-co] alanlarına, paket tablosunu #plan-table içine yazar. */
(function () {
  if (!window.DAC_I18N) { var sc = document.createElement("script"); sc.src = "/js/i18n.js?v=20261030a"; document.head.appendChild(sc); }
  var C = window.DAC_COMPANY || {}, missing = [];
  document.querySelectorAll("[data-co]").forEach(function (el) {
    var k = el.getAttribute("data-co"), v = C[k];
    if (v == null) { el.textContent = "—"; return; }
    el.textContent = v;
    if (/^\[.*\]$/.test(String(v).trim())) { el.className += " ph"; if (missing.indexOf(k) < 0) missing.push(k); }
  });
  var yr = document.getElementById("yil"); if (yr) yr.textContent = new Date().getFullYear();
  if (missing.length) {
    var b = document.createElement("div"); b.className = "draft-banner"; b.setAttribute("role", "alert");
    b.textContent = "TASLAK: Şirket bilgileri (company.js) henüz doldurulmamış. Bu sayfa yayına alınmadan önce eksik alanlar tamamlanmalıdır.";
    document.body.insertBefore(b, document.body.firstChild);
  }
  var t = document.getElementById("plan-table"), P = window.DAC_PLANS;
  if (t && P) {
    var money = function (n, c) { return c === "TRY" ? n.toLocaleString("tr-TR", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + " ₺" : "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); };
    var rows = P.PAID.map(function (id) { var p = P.PLANS[id]; return "<tr><td>" + p.name + "</td><td>" + (p.assets == null ? "Sınırsız" : p.assets) + " varlık</td><td>" + money(P.price(id, "TRY", "monthly"), "TRY") + " / " + money(P.price(id, "USD", "monthly"), "USD") + "</td><td>" + money(P.price(id, "TRY", "yearly"), "TRY") + " / " + money(P.price(id, "USD", "yearly"), "USD") + "</td></tr>"; }).join("");
    t.innerHTML = "<table><thead><tr><th>Paket</th><th>Kapsam</th><th>Aylık (TL / USD)</th><th>Yıllık (TL / USD)</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }
})();
