// Tarama sunucusu adresi.
// Site, tarama sunucusuyla aynı Render servisinden açılıyorsa (…onrender.com) otomatik olarak kendi adresi kullanılır.
// Başka bir yerden (GitHub Pages vb.) açılırsa aşağıdaki FALLBACK adresi kullanılır.
(function () {
  var FALLBACK = "https://dac-web-tfqf.onrender.com";
  var h = location.hostname;
  var sameOrigin = /\.onrender\.com$/i.test(h) ? location.origin : "";
  window.DAC_CONFIG = { API_URL: sameOrigin || FALLBACK };
})();
