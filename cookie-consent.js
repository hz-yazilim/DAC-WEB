/* Çerez / yerel depolama tercihi (KVKK Kurulu çerez rehberi): zorunlu olmayan (analitik) kullanım yalnızca açık onayla başlar.
 * Tercih: localStorage "dac_cookie_consent" = "all" | "essential". Analitik yüklemesi login.js tarafından bu değere göre yapılır. */
(function () {
  var KEY = "dac_cookie_consent", get = function () { try { return localStorage.getItem(KEY); } catch (e) { return null; } };
  window.DAC_COOKIE = {
    get: get,
    set: function (v) { try { localStorage.setItem(KEY, v); localStorage.setItem(KEY + "_at", new Date().toISOString()); } catch (e) {} window.dispatchEvent(new CustomEvent("dac-cookie-consent", { detail: v })); },
    reopen: function () { try { localStorage.removeItem(KEY); } catch (e) {} show(); }
  };
  function show() {
    if (document.getElementById("ckbar")) return;
    var d = document.createElement("div"); d.id = "ckbar"; d.setAttribute("role", "dialog"); d.setAttribute("aria-label", "Çerez tercihleri");
    d.innerHTML = '<p>Oturumunuzu sürdürmek ve verilerinizi saklamak için <b>zorunlu</b> çerez/yerel depolama kullanırız. İsteğe bağlı <b>analitik</b> ölçüm yalnızca onayınızla çalışır. Ayrıntı: <a href="/cerez-politikasi">Çerez Politikası</a> • <a href="/kvkk">KVKK Aydınlatma Metni</a></p><div class="ckbtns"><button type="button" class="btn" id="ck-ess">Yalnızca zorunlu</button><button type="button" class="btn p" id="ck-all">Tümünü kabul et</button></div>';
    document.body.appendChild(d);
    d.querySelector("#ck-ess").onclick = function () { window.DAC_COOKIE.set("essential"); d.remove(); };
    d.querySelector("#ck-all").onclick = function () { window.DAC_COOKIE.set("all"); d.remove(); };
  }
  // İlk açılışta çerez çubuğu GÖSTERİLMEZ: tercih giriş kutusunda alınır (zorunlu onay + isteğe bağlı analitik kutusu; bkz. index.html / login.js).
  // Tercih hiç verilmemişse yalnızca zorunlu çerezler kullanılır. Çerez tercihi, alt bağlantıdaki "Çerez tercihleri" ile istenildiğinde değiştirilebilir.
  function init() {}
  document.addEventListener("click", function (e) { var a = e.target.closest && e.target.closest("[data-cookie-settings]"); if (a) { e.preventDefault(); window.DAC_COOKIE.reopen(); } });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
