  // Firebase JS SDK sürümü (gstatic CDN). Güncellemek için yalnızca bu satırı değiştirin.
  const FB = "https://www.gstatic.com/firebasejs/12.18.0/";

  // Firebase web yapılandırması KODDA TUTULMAZ: sunucudaki /api/firebase-config uç noktasından (Render ortam değişkenleri) alınır.
  // Proje: varlik-operasyonlari-ed334. Değerler eksikse sunucu eksik değişken adlarını döndürür ve aşağıda gösterilir.

  // ====== GİRİŞ ANAHTARI ======
  // false: giriş pasif (test modu). true: giriş AKTİF (Google + e-posta/şifre)
  const LOGIN_ENABLED = true;

  // ====== OTURUM KALICILIĞI ======
  // false: oturum SADECE o sayfa açıkken yaşar. Sayfa yenilenir, kapanır veya başka siteye gidip geri dönülürse giriş YENİDEN istenir.
  // true : (eski davranış) oturum tarayıcıda kalıcıdır, site tekrar açıldığında girişli gelir.
  const KEEP_SESSION = false;
  const REDIR_KEY = "dac_redirect_pending"; // yalnızca Google yönlendirmeli girişte (popup engelliyse) o sekmede geçici kullanılır

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

  function fatal(msg) { document.body.classList.remove("init", "authed"); document.body.classList.add("showlogin"); lerr.textContent = msg; }
  function say(msg, ok) { lerr.textContent = msg; lerr.style.color = ok ? "var(--ok, #22c55e)" : ""; }

  window.dacLogout = () => {
    if (!LOGIN_ENABLED) { if (typeof toast === "function") toast("Giriş pasif (test modu): çıkış yapılacak oturum yok", "warn"); return; }
    return A ? A.signOut(auth) : undefined;
  };
  window.dacToken = async () => (auth && auth.currentUser ? await auth.currentUser.getIdToken() : null);

  // E-posta/şifre hesabı doğrulanmadan uygulamaya alınmaz (sunucu da aynı kuralı uygular)
  const unverified = (u) => u.providerData.some(p => p.providerId === "password") && !u.emailVerified;

  // Üyelik/giriş onayı: Giriş butonuna basılınca açılan pencerede TÜM yasal metinler gösterilir; en altta tek onay kutusu vardır.
  // Onay zorunludur (isteğe bağlı onay yoktur). Onaylanmazsa giriş yapılamaz. Onay, giriş sonrası sunucuya kaydedilir (app-main.js > sendConsents).
  const LEGAL_V = (window.DAC_COMPANY && window.DAC_COMPANY.surum) || "2026-10";
  const LEGAL_DOCS = [
    ["/kullanim-kosullari", "Kullanım Koşulları"],
    ["/kvkk", "KVKK Aydınlatma Metni"],
    ["/gizlilik", "Gizlilik Politikası"],
    ["/cerez-politikasi", "Çerez Politikası"],
    ["/kabul-edilebilir-kullanim", "Kabul Edilebilir Kullanım ve Tarama Yetkisi"]
  ];
  let legalLoaded = false, legalLoading = null, cmCb = null;

  function loadLegal() {
    if (legalLoaded) return Promise.resolve();
    if (legalLoading) return legalLoading;
    const C = window.DAC_COMPANY || {}, box = $("cm-docs");
    legalLoading = Promise.all(LEGAL_DOCS.map(async ([url, title], i) => {
      const sec = document.createElement("section"); sec.className = "cm-doc";
      const h = document.createElement("h2"); h.className = "cm-doct"; h.textContent = (i + 1) + ". " + title; sec.appendChild(h);
      try {
        const r = await fetch(url, { cache: "no-cache" }); if (!r.ok) throw new Error("http");
        const doc = new DOMParser().parseFromString(await r.text(), "text/html");
        const m = doc.querySelector("main.legal"); if (!m) throw new Error("main");
        m.querySelectorAll("script,style,iframe,object,embed,link,h1,#plan-table").forEach((n) => n.remove());
        m.querySelectorAll("[data-co]").forEach((el) => { const v = C[el.getAttribute("data-co")]; el.textContent = v == null ? "—" : v; el.removeAttribute("data-co"); });
        m.querySelectorAll("a[data-cookie-settings]").forEach((a) => a.replaceWith(...a.childNodes));
        m.querySelectorAll("*").forEach((el) => { for (const a of Array.from(el.attributes)) if (/^on/i.test(a.name)) el.removeAttribute(a.name); });
        m.querySelectorAll("a[href]").forEach((a) => { if (/^(\/|https?:)/i.test(a.getAttribute("href"))) { a.target = "_blank"; a.rel = "noopener"; } });
        while (m.firstChild) sec.appendChild(m.firstChild);
      } catch (e) {
        const p = document.createElement("p"); p.className = "hint";
        p.appendChild(document.createTextNode("Bu metin şu an yüklenemedi. Lütfen yeni sekmede okuyun: "));
        const a = document.createElement("a"); a.href = url; a.target = "_blank"; a.rel = "noopener"; a.textContent = title; p.appendChild(a); sec.appendChild(p);
      }
      return sec;
    })).then((secs) => { box.textContent = ""; secs.forEach((x) => box.appendChild(x)); legalLoaded = true; }).catch(() => { legalLoading = null; });
    return legalLoading;
  }

  function closeConsent() { $("cmodal").classList.remove("on"); document.body.classList.remove("cm-open"); cmCb = null; }
  // cb: onay verilince, kullanıcı tıklamasıyla AYNI olay içinde çağrılır (açılır pencere engelleyicileri bozulmasın diye)
  function askConsent(cb) {
    cmCb = cb;
    const chk = $("cm-chk"), yes = $("cm-yes");
    chk.checked = false; yes.disabled = true; $("cm-hint").textContent = "";
    $("cmodal").classList.add("on"); document.body.classList.add("cm-open");
    $("cm-body").scrollTop = 0;
    loadLegal();
  }
  function approveConsent() {
    if (!$("cm-chk").checked) { $("cm-hint").textContent = "Devam etmek için onay kutusunu işaretlemeniz gerekir."; return; }
    try { localStorage.setItem("dac_terms_pending", LEGAL_V); } catch (e) {}
    if (window.DAC_COOKIE) window.DAC_COOKIE.set("all"); // tek onayın parçası: zorunlu çerezler + analitik ölçüm
    const cb = cmCb; closeConsent();
    if (cb) cb();
  }
  $("cm-chk").onchange = () => { $("cm-yes").disabled = !$("cm-chk").checked; if ($("cm-chk").checked) $("cm-hint").textContent = ""; };
  $("cm-yes").onclick = approveConsent;
  $("cm-no").onclick = closeConsent;
  $("cm-x").onclick = closeConsent;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("cmodal").classList.contains("on")) closeConsent(); });
  const busyForm = (b) => { for (const id of ["ebtn", "rbtn", "fbtn", "gbtn"]) $(id).disabled = b; };

  // Alanlar doğruysa onay penceresini açar; onaylanınca asıl işlem çalışır
  function emailLogin(ev) {
    ev && ev.preventDefault(); say("");
    if (!auth) return say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin.");
    const email = $("lemail").value.trim(), pass = $("lpass").value;
    if (!email || !pass) return say("E-posta ve şifre girin.");
    askConsent(() => doEmailLogin(email, pass));
  }
  async function doEmailLogin(email, pass) {
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
  function emailRegister() {
    say("");
    if (!auth) return say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin.");
    const email = $("lemail").value.trim(), pass = $("lpass").value;
    if (!email) return say("E-posta adresi girin.");
    if (pass.length < 8) return say("Şifre en az 8 karakter olmalı.");
    askConsent(() => doRegister(email, pass));
  }
  async function doRegister(email, pass) {
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

  gbtn.onclick = () => {
    say("");
    if (!auth) { say("Giriş servisi henüz yüklenmedi. Sayfayı yenileyin."); return; }
    askConsent(doGoogle);
  };
  async function doGoogle() {
    const t0 = Date.now();
    busyForm(true);
    try { await A.signInWithPopup(auth, provider); }
    catch (e) {
      // Açılır pencere engellendi / desteklenmiyor (mobil, uygulama içi tarayıcı, PWA): sayfa yönlendirmesiyle dene
      if (e.code === "auth/popup-blocked" || e.code === "auth/operation-not-supported-in-this-environment") {
        try { try { sessionStorage.setItem(REDIR_KEY, "1"); } catch (x) {} await A.signInWithRedirect(auth, provider); return; } catch (e2) { try { sessionStorage.removeItem(REDIR_KEY); } catch (x) {} say(msgOf(e2)); }
      } else if (e.code === "auth/cancelled-popup-request") {
        // başka bir pencere isteği: sessiz geç
      } else if (e.code === "auth/popup-closed-by-user") {
        // Pencere çok hızlı kapandıysa kullanıcı vazgeçmemiştir: çoğunlukla çerez/depolama engeli veya yetkisiz alan adıdır
        if (Date.now() - t0 < 4000) say("Google giriş penceresi hemen kapandı. Tarayıcıda 3. taraf çerezlere izin verin veya açılır pencere engelleyiciyi kapatın; sorun sürerse Firebase > Authentication > Settings > Authorized domains listesinde bu sitenin alan adını kontrol edin.");
      } else { console.error("Google giriş hatası:", e); say(msgOf(e)); }
    }
    busyForm(false);
  }

  // Firebase'in tarayıcıda sakladığı oturum kayıtlarını siler (IndexedDB + localStorage + sessionStorage)
  function wipeStoredAuth() {
    try { for (const st of [localStorage, sessionStorage]) for (let i = st.length - 1; i >= 0; i--) { const k = st.key(i); if (k && k.indexOf("firebase:authUser:") === 0) st.removeItem(k); } } catch (e) {}
    try { indexedDB.deleteDatabase("firebaseLocalStorageDb"); } catch (e) {}
  }
  if (!KEEP_SESSION) {
    try { localStorage.removeItem("dac_last_uid"); } catch (e) {}
    // Geri/ileri düğmesiyle önbellekten (bfcache) dönülen sayfa girişli kalmasın: sayfayı baştan yükle
    addEventListener("pageshow", (e) => { if (e.persisted) location.reload(); });
  }

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
      if (KEEP_SESSION) {
        auth = A.getAuth(app);
      } else {
        // Oturum yalnızca bellekte tutulur: sayfa kapanınca / yenilenince / başka siteden geri dönülünce çıkış yapılmış sayılır.
        const redirecting = (() => { try { return sessionStorage.getItem(REDIR_KEY) === "1"; } catch (e) { return false; } })();
        if (!redirecting) wipeStoredAuth(); // eski sürümden kalan kalıcı oturumları sil
        auth = A.initializeAuth(app, { persistence: redirecting ? [A.browserSessionPersistence] : [A.inMemoryPersistence], popupRedirectResolver: A.browserPopupRedirectResolver });
      }
      provider = new A.GoogleAuthProvider();
      provider.setCustomParameters({ prompt: "select_account" });
      A.getRedirectResult(auth).catch((e) => { if (e && e.code && e.code !== "auth/no-auth-event") say(msgOf(e)); }).finally(() => { try { sessionStorage.removeItem(REDIR_KEY); } catch (e) {} });
      // Analytics isteğe bağlı: yalnızca measurementId tanımlıysa; yüklenemezse girişi etkilemez
      // Analytics: yalnızca ölçüm kimliği tanımlıysa VE kullanıcı giriş kutusundaki isteğe bağlı analitik kutusunu işaretlediyse (KVKK açık rıza)
      let analyticsOn = false;
      const startAnalytics = () => { if (analyticsOn || !firebaseConfig.measurementId) return; if (!window.DAC_COOKIE || window.DAC_COOKIE.get() !== "all") return; analyticsOn = true; import(FB + "firebase-analytics.js").then((m) => { try { m.getAnalytics(app); } catch (e) {} }).catch(() => {}); };
      startAnalytics(); window.addEventListener("dac-cookie-consent", startAnalytics);
      A.onAuthStateChanged(auth, (u) => {
        const ok = !!u && !unverified(u);
        if (ok && KEEP_SESSION) { try { localStorage.setItem("dac_last_uid", u.uid); } catch (e) {} }
        document.body.classList.remove("init");
        document.body.classList.toggle("authed", ok);
        if (ok) window.dacStart(u); else window.dacStop();
      });
    } catch (e) {
      console.error("Firebase yüklenemedi:", e);
      fatal(e && e.message && !/import|fetch/i.test(e.message) ? e.message : "Giriş servisi yüklenemedi (Firebase SDK). İnternet bağlantınızı, reklam engelleyiciyi ve sayfayı yenilemeyi deneyin.");
    }
  })();
