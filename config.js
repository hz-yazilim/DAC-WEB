// HTTPS zorunlu: düz http ile açılırsa (yerel geliştirme hariç) aynı adres https ile yeniden açılır. Sunucu da ayrıca yönlendirir (index.js).
(function () { try { if (location.protocol === "http:" && !/^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|.*\.local)$/i.test(location.hostname)) location.replace("https:" + location.href.substring(location.protocol.length)); } catch (e) {} })();
// Tarama sunucusu adresi.
// Site, tarama sunucusuyla aynı Render servisinden açılıyorsa (…onrender.com) otomatik olarak kendi adresi kullanılır.
// Başka bir yerden (GitHub Pages vb.) açılırsa aşağıdaki FALLBACK adresi kullanılır.
(function () {
  var FALLBACK = "https://dac-web-tfqf.onrender.com";
  var h = location.hostname;
  var sameOrigin = /(\.onrender\.com|^(www\.)?dacweb\.tr)$/i.test(h) ? location.origin : "";
  window.DAC_CONFIG = { API_URL: sameOrigin || FALLBACK };
})();
