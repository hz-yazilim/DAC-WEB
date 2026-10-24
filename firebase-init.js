/* Digital Asset Center - Firebase Admin SDK güvenli başlatma
 * - Hizmet hesabı SADECE ortam değişkeninden okunur (kaynak koda / GitHub'a yazılmaz).
 * - JSON ayrıştırma, alan ve proje doğrulaması yapılır; hata mesajları anahtar içeriğini ASLA yazdırmaz.
 * - Hizmet hesabı başka bir Firebase projesine aitse (ör. "varlik-operasyonlari-ed334") BAŞLATILMAZ.
 * - Admin SDK Firestore Security Rules'u atlar; bu yüzden yetkilendirme sunucu kodunda yapılır (security.js, payments.js).
 */
"use strict";

const EXPECTED_PROJECT_ID = "assetops-ed334"; // verilerin (assets, assetChecks, users) bulunduğu Firestore projesi
const FORBIDDEN_PROJECT_IDS = ["varlik-operasyonlari-ed334"]; // yanlışlıkla kullanılan boş proje

const projectIdOf = (env = process.env) => String(env.FIREBASE_PROJECT_ID || EXPECTED_PROJECT_ID).trim();

// Dönen: { ok:true, account } veya { ok:false, code, message }
function parseServiceAccount(env = process.env) {
  const pid = projectIdOf(env);
  if (pid !== EXPECTED_PROJECT_ID) {
    return { ok: false, code: "BAD_PROJECT", message: `FIREBASE_PROJECT_ID "${pid}" geçersiz: bu uygulama yalnızca "${EXPECTED_PROJECT_ID}" projesiyle çalışır (değişkeni silin veya bu değere ayarlayın).` };
  }

  let raw = env.FIREBASE_SERVICE_ACCOUNT_B64 ? null : env.FIREBASE_SERVICE_ACCOUNT;
  if (env.FIREBASE_SERVICE_ACCOUNT_B64) {
    try { raw = Buffer.from(String(env.FIREBASE_SERVICE_ACCOUNT_B64).trim(), "base64").toString("utf8"); }
    catch { return { ok: false, code: "BAD_B64", message: "FIREBASE_SERVICE_ACCOUNT_B64 base64 olarak çözülemedi." }; }
  }
  if (!raw || !String(raw).trim()) {
    return { ok: false, code: "MISSING", message: "FIREBASE_SERVICE_ACCOUNT tanımlı değil. Render > Environment bölümüne hizmet hesabı JSON'unun tamamını ekleyin (bkz. .env.example)." };
  }
  let acc;
  try { acc = JSON.parse(String(raw).trim()); }
  catch { return { ok: false, code: "BAD_JSON", message: "FIREBASE_SERVICE_ACCOUNT geçerli bir JSON değil. JSON'un tamamını (süslü parantezler dahil) tek değer olarak yapıştırın veya FIREBASE_SERVICE_ACCOUNT_B64 kullanın." }; }
  if (!acc || typeof acc !== "object" || acc.type !== "service_account") return { ok: false, code: "BAD_TYPE", message: "Hizmet hesabı JSON'unda type=service_account yok; Firebase Console > Project settings > Service accounts > Generate new private key ile indirilen dosya kullanılmalı." };
  for (const k of ["project_id", "client_email", "private_key"]) if (!acc[k] || typeof acc[k] !== "string") return { ok: false, code: "MISSING_FIELD", message: `Hizmet hesabı JSON'unda "${k}" alanı eksik.` };
  acc.private_key = acc.private_key.replace(/\\n/g, "\n"); // Render'da \n kaçışlı gelebilir
  if (!/-----BEGIN PRIVATE KEY-----/.test(acc.private_key)) return { ok: false, code: "BAD_KEY", message: "Hizmet hesabı özel anahtarı (private_key) biçimi geçersiz." };
  if (FORBIDDEN_PROJECT_IDS.includes(acc.project_id)) return { ok: false, code: "OLD_PROJECT", message: `Hizmet hesabı yanlış projeye (${acc.project_id}) ait. ${pid} projesinden yeni anahtar üretin.` };
  if (acc.project_id !== pid) return { ok: false, code: "PROJECT_MISMATCH", message: `Hizmet hesabı "${acc.project_id}" projesine ait, ancak beklenen proje "${pid}".` };
  if (!acc.client_email.endsWith(`@${pid}.iam.gserviceaccount.com`)) return { ok: false, code: "EMAIL_MISMATCH", message: `Hizmet hesabı e-postası "${pid}" projesine ait görünmüyor.` };
  return { ok: true, account: acc };
}

// admin: firebase-admin modülü. Dönen: { db, status:{ ok, projectId, mode, code?, message? } }
function initFirebase(admin, env = process.env, log = console) {
  const projectId = projectIdOf(env);
  const fail = (r) => { log.error("Firebase başlatılamadı [" + r.code + "]: " + r.message); return { db: null, status: { ok: false, projectId, mode: null, code: r.code, message: r.message } }; };
  if (projectId !== EXPECTED_PROJECT_ID) return fail({ code: "BAD_PROJECT", message: `FIREBASE_PROJECT_ID "${projectId}" geçersiz; beklenen "${EXPECTED_PROJECT_ID}".` });
  try {
    if (!admin.apps.length) {
      if (env.FIREBASE_SERVICE_ACCOUNT || env.FIREBASE_SERVICE_ACCOUNT_B64) {
        const p = parseServiceAccount(env); if (!p.ok) return fail(p);
        admin.initializeApp({ credential: admin.credential.cert(p.account), projectId });
      } else if (env.GOOGLE_APPLICATION_CREDENTIALS) {
        // Yerel geliştirme: ADC dosyası. Proje kimliği açıkça sabitlenir.
        admin.initializeApp({ projectId });
      } else {
        const p = parseServiceAccount(env); log.warn("Firebase kimlik bilgisi yok: " + p.message); return { db: null, status: { ok: false, projectId, mode: null, code: p.code, message: p.message } };
      }
    }
    const db = admin.firestore(); db.settings({ ignoreUndefinedProperties: true });
    return { db, status: { ok: true, projectId, mode: (env.FIREBASE_SERVICE_ACCOUNT || env.FIREBASE_SERVICE_ACCOUNT_B64) ? "service-account" : "adc" } };
  } catch (e) { return fail({ code: "INIT_ERROR", message: e && e.message ? String(e.message).slice(0, 200) : "bilinmeyen hata" }); }
}

// Tarayıcıya verilen (herkese açık) Firebase web yapılandırması: değerler Render ortamından gelir, kodda sabit YOK.
const WEB_REQUIRED = { apiKey: "FIREBASE_WEB_API_KEY", authDomain: "FIREBASE_WEB_AUTH_DOMAIN", appId: "FIREBASE_WEB_APP_ID", messagingSenderId: "FIREBASE_WEB_MESSAGING_SENDER_ID" };
const WEB_OPTIONAL = { storageBucket: "FIREBASE_WEB_STORAGE_BUCKET", measurementId: "FIREBASE_WEB_MEASUREMENT_ID" };
function webConfig(env = process.env) {
  const cfg = { projectId: projectIdOf(env) }, missing = [];
  for (const [k, e] of Object.entries(WEB_REQUIRED)) { const v = String(env[e] || "").trim(); if (v) cfg[k] = v; else missing.push(e); }
  for (const [k, e] of Object.entries(WEB_OPTIONAL)) { const v = String(env[e] || "").trim(); if (v) cfg[k] = v; }
  if (cfg.projectId !== EXPECTED_PROJECT_ID) return { ok: false, missing: [], error: `FIREBASE_PROJECT_ID "${cfg.projectId}" geçersiz; beklenen "${EXPECTED_PROJECT_ID}".` };
  for (const k of ["authDomain", "storageBucket"]) if (cfg[k] && FORBIDDEN_PROJECT_IDS.some(p => cfg[k].includes(p))) return { ok: false, missing: [], error: `${k} yanlış projeyi gösteriyor.` };
  if (cfg.appId && !cfg.appId.includes(":web:")) return { ok: false, missing: [], error: "FIREBASE_WEB_APP_ID bir web uygulaması kimliği olmalı (1:...:web:...)." };
  return missing.length ? { ok: false, missing } : { ok: true, config: cfg };
}

module.exports = { EXPECTED_PROJECT_ID, FORBIDDEN_PROJECT_IDS, projectIdOf, parseServiceAccount, initFirebase, webConfig };
