  // Firebase JS SDK sürümü (gstatic CDN). Güncellemek için yalnızca bu satırı değiştirin.
  const FB = "https://www.gstatic.com/firebasejs/12.18.0/";

  // Firebase web yapılandırması KODDA TUTULMAZ: sunucudaki /api/firebase-config uç noktasından (Render ortam değişkenleri) alınır.
  // Proje: varlik-operasyonlari-ed334. Değerler eksikse sunucu eksik değişken adlarını döndürür ve aşağıda gösterilir.

  // ====== GİRİŞ ANAHTARI ======
  // false: giriş pasif (test modu). true: giriş AKTİF (Google + e-posta/şifre)
  const LOGIN_ENABLED = true;

  const $ = (id) => document.getElementById(id);
  const lerr = $("lerr"), gbtn = $("gbtn");
  let auth = null, provider = null, A = null; // A: firebase-auth modülü

  const ERR = {
    "auth/unauthorized-domain": "Bu alan adı Firebase'de yetkili değil (Authentication > Settings > Authorized domains listesine ekleyin).",
    "auth/operation-not-allowed": "Bu giriş yöntemi Firebase'de etkin değil (Authentication > Sign-in method).",
    "auth/popup-blocked": "Açılır pencere engellendi, izin verip tekrar deneyin.",
    "auth/network-request-failed": "İnternet bağlantısı hatası.",
    "auth/invalid-api-key": "Firebase API anahtarı geçersiz.",
    "auth/api-key-not-valid.-please-pass-a-valid-api-key.": "Firebase API anahtarı geçersiz veya kısıtlı.",
    "auth/too-many-requests": "Çok fazla deneme yapıldı, biraz bekleyip tekrar deneyin.",
    "auth/user-disabled": "Bu hesap devre dışı bırakılmış.",
    "auth/web-storage-unsupported": "Tarayıcı depolaması kapalı (gizli mod / çerez engeli). Ayarlardan izin verin.",
    "auth/operation-not-supported-in-this-environment": "Bu tarayıcı Google girişini desteklemiyor. Chrome veya Safari'de açın.",
    "auth/internal-error": "Firebase iç hatası. Sayfayı yenileyip tekrar deneyin.",
    "auth/invalid-credential": "E-posta veya şifre hatalı.",
    "auth/wrong-password": "E-posta veya şifre hatalı.",
    "auth/user-not-found": "E-posta veya şifre hatalı.",
    "auth/invalid-email": "Geçerli bir e-posta adresi girin.",
    "auth/missing-password": "Şifre girin.",
    "auth/email-already-in-use": "Bu e-posta ile zaten bir hesap var. Giriş yapın veya \"Şifremi unuttum\" ile sıfırlayın.",
    "auth/weak-password": "Şifre çok zayıf: en az 8 karakter kullanın.",
    "auth/account-exists-with-different-credential": "Bu e-posta başka bir yöntemle kayıtlı. O yöntemle giriş yapın."
  };
  const msgOf = (e) => ERR[e.code] || ("Giriş hatası: " + (e.code || e.message));

  function fatal(msg) { document.body.classList.remove("init", "authed"); lerr.textContent = msg; }
  function say(msg, ok) { lerr.textContent = msg; lerr.style.color = ok ? "var(--ok, #22c55e)" : ""; }

  window.dacLogout = () => {
    if (!LOGIN_ENABLED) { if (typeof toast === "function") toast("Giriş pasif (test modu): çıkış yapılacak oturum yok", "warn"); return; }
    return A ? A.signOut(auth) : undefined;
  };
  window.dacToken = async () => (auth && auth.currentUser ? await auth.currentUser.getIdToken() : null);

  // E-posta/şifre hesabı doğrulanmadan uygulamaya alınmaz (sunucu da aynı kuralı uygular)
  const unverified = (u) => u.providerData.some(p => p.providerId === "password") && !u.emailVerified;

  const busyForm = (b) => { for (const id of ["ebtn", "rbtn", "fbtn", "gbtn"]) $(id).disabled = b; };

  async function emailLogin(ev) {
    ev && ev.preventDefault(); say("");
    if (!auth) return say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin.");
    const email = $("lemail").value.trim(), pass = $("lpass").value;
    if (!email || !pass) return say("E-posta ve şifre girin.");
    busyForm(true);
    try {
      const cred = await A.signInWithEmailAndPassword(auth, email, pass);
      if (unverified(cred.user)) {
        try { await A.sendEmailVerification(cred.user); } catch (e) {}
        await A.signOut(auth);
        say("E-posta adresiniz doğrulanmamış. Doğrulama bağlantısını e-postanıza gönderdik; tıkladıktan sonra tekrar giriş yapın.");
      }
    } catch (e) { say(msgOf(e)); }
    busyForm(false);
  }
  async function emailRegister() {
    say("");
    if (!auth) return say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin.");
    const email = $("lemail").value.trim(), pass = $("lpass").value;
    if (!email) return say("E-posta adresi girin.");
    if (pass.length < 8) return say("Şifre en az 8 karakter olmalı.");
    busyForm(true);
    try {
      const cred = await A.createUserWithEmailAndPassword(auth, email, pass);
      try { await A.sendEmailVerification(cred.user); } catch (e) {}
      await A.signOut(auth);
      $("lpass").value = "";
      say("Hesap oluşturuldu. E-postanıza doğrulama bağlantısı gönderdik; tıkladıktan sonra giriş yapabilirsiniz.", true);
    } catch (e) { say(msgOf(e)); }
    busyForm(false);
  }
  async function resetPass() {
    say("");
    const email = $("lemail").value.trim();
    if (!auth) return say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin.");
    if (!email) return say("Önce e-posta adresinizi yazın.");
    busyForm(true);
    try { await A.sendPasswordResetEmail(auth, email); say("Bu adres kayıtlıysa şifre sıfırlama bağlantısı gönderildi.", true); }
    catch (e) { say(e.code === "auth/invalid-email" ? msgOf(e) : "Bu adres kayıtlıysa şifre sıfırlama bağlantısı gönderildi.", e.code !== "auth/invalid-email"); }
    busyForm(false);
  }
  $("eform").addEventListener("submit", emailLogin);
  $("rbtn").onclick = emailRegister;
  $("fbtn").onclick = resetPass;

  gbtn.onclick = async () => {
    say("");
    if (!auth) { say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin."); return; }
    try { await A.signInWithPopup(auth, provider); }
    catch (e) {
      if (e.code === "auth/popup-closed-by-user" || e.code === "auth/cancelled-popup-request") return;
      say(msgOf(e));
    }
  };

  async function loadConfig() {
    const base = ((window.DAC_CONFIG || {}).API_URL || "").replace(/\/$/, "");
    let r, j;
    try { r = await fetch(base + "/api/firebase-config", { cache: "no-store" }); j = await r.json(); }
    catch (e) { throw new Error("Sunucuya ulaşılamadı (" + base + "). Render uyanıyor olabilir; 30 sn sonra sayfayı yenileyin."); }
    if (!r.ok || !j.success) throw new Error((j && j.error ? j.error + " " : "Firebase yapılandırması alınamadı. ") + (j && j.missing && j.missing.length ? "Render > Environment'a şu değişkenleri ekleyin: " + j.missing.join(", ") : ""));
    return j.config;
  }

  (async () => {
    if (!LOGIN_ENABLED) {
      let uid = "test-user";
      try { uid = localStorage.getItem("dac_last_uid") || uid; } catch (e) {}
      document.body.classList.remove("init");
      document.body.classList.add("authed");
      window.dacStart({ uid, displayName: "Test Modu", email: "Giriş pasif", photoURL: null, metadata: {} });
      return;
    }
    try {
      const firebaseConfig = await loadConfig();
      const [appMod, authMod] = await Promise.all([import(FB + "firebase-app.js"), import(FB + "firebase-auth.js")]);
      A = authMod;
      const app = appMod.initializeApp(firebaseConfig);
      auth = A.getAuth(app);
      provider = new A.GoogleAuthProvider();
      provider.setCustomParameters({ prompt: "select_account" });
      // Analytics isteğe bağlı: yalnızca measurementId tanımlıysa; yüklenemezse girişi etkilemez
      if (firebaseConfig.measurementId) import(FB + "firebase-analytics.js").then((m) => { try { m.getAnalytics(app); } catch (e) {} }).catch(() => {});
      A.onAuthStateChanged(auth, (u) => {
        const ok = !!u && !unverified(u);
        if (ok) { try { localStorage.setItem("dac_last_uid", u.uid); } catch (e) {} }
        document.body.classList.remove("init");
        document.body.classList.toggle("authed", ok);
        if (ok) window.dacStart(u); else window.dacStop();
      });
    } catch (e) {
      console.error("Firebase yüklenemedi:", e);
      fatal(e && e.message && !/import|fetch/i.test(e.message) ? e.message : "Giriş servisi yüklenemedi (Firebase SDK). İnternet bağlantınızı, reklam engelleyiciyi ve sayfayı yenilemeyi deneyin.");
    }
  })();
