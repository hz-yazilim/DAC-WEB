/* İletişim sayfası destek formu: POST /api/support (bal küpü + isteğe bağlı Cloudflare Turnstile) */
(function () {
  var f = document.getElementById("support-form"); if (!f) return;
  var api = ((window.DAC_CONFIG || {}).API_URL || "").replace(/\/$/, ""), msg = document.getElementById("support-msg"), token = "";
  var say = function (t, bad) { msg.textContent = t; msg.style.color = bad ? "#ef4444" : "#10b981"; };
  fetch(api + "/api/support/config").then(function (r) { return r.json(); }).then(function (j) {
    if (!j || !j.captcha || j.captcha.provider !== "turnstile") return;
    var s = document.createElement("script"); s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"; s.async = true;
    s.onload = function () { window.turnstile.render("#cf-box", { sitekey: j.captcha.siteKey, callback: function (t) { token = t; }, "expired-callback": function () { token = ""; } }); };
    document.head.appendChild(s);
  }).catch(function () {});
  f.addEventListener("submit", function (e) {
    e.preventDefault(); var d = new FormData(f), btn = f.querySelector("button[type=submit]"); btn.disabled = true; say("Gönderiliyor…");
    fetch(api + "/api/support", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: d.get("name"), email: d.get("email"), subject: d.get("subject"), message: d.get("message"), website: d.get("website"), captchaToken: token }) })
      .then(function (r) { return r.json(); }).then(function (j) { if (!j.success) throw new Error(j.error || "Gönderilemedi"); say("Talebiniz alındı. Numara: #" + j.ticketNo); f.reset(); if (window.turnstile) try { window.turnstile.reset(); } catch (x) {} token = ""; })
      .catch(function (x) { say(x.message, true); }).then(function () { btn.disabled = false; });
  });
})();
