# Digital Asset Center (DAC)

Alan adı, SSL, DNS, web sitesi, SEO, güvenlik, performans, uptime, API, sunucu, marka, mobil uygulama, kod deposu ve SaaS aboneliklerini tarayan ve izleyen web uygulaması.
Sunucu **Node.js (Express)** ile çalışır; aynı API'yi sunan isteğe bağlı **Python (FastAPI)** sürümü `index.py` içindedir.

## V13.1 yenilikleri
- **Yönetici paneli** (`#admin`, yalnızca yöneticilere görünür) + `/api/admin/*` (rol **sunucuda** doğrulanır; `admin.js`).
- **Kalıcı toplu tarama kuyruğu** (`jobs.js`, `/api/jobs*`, Toplu Tarama sayfası; 200+ domain). Domain sayfasında **Genel Tarama** (`#domains`).
- **Merkezi skor** (`scoring.js`): SEO %35 + Güvenlik %50 + Performans %15, kritik bulguda en çok 75.
- **Girdi doğrulama** (`validators.js`), ölçümler (`metrics.js`: P50/P95/P99), **AI mimarisi (kapalı)** (`ai-provider.js`), para birimi/affiliate hazırlığı (`billing-catalog.js`).
- Ortak **Yenile** düğmesi yalnızca durumları çeker, tarama başlatmaz. TC kimlik alanı kaldırıldı (isteğe bağlı 10 haneli vergi no).

## Yönetici kurulumu (Render > Environment)
1. `FIREBASE_SERVICE_ACCOUNT` tanımlı olmalı (admin paneli Firebase Admin olmadan 503 verir).
2. `ADMIN_UIDS` (Firebase Console > Authentication > Kullanıcı UID) **veya** `ADMIN_EMAILS` (e-postası doğrulanmış hesap) girin. Sonraki yöneticiler panelden eklenir (`adminRoles` koleksiyonu).
3. Deploy sonrası bu hesapla giriş yapın; sol menüde **Yönetici Paneli** görünür. Menü yalnızca kolaylıktır; yetki her istekte sunucuda denetlenir.

## Toplu tarama notları
- Firestore bağlıysa iş durumu (`scanJobs`, `scanJobItems`) sunucu yeniden başlasa da korunur; yarım kalan taramalar açılışta yeniden sıraya alınır. Firestore yoksa bellek deposu kullanılır ve panelde "kalıcı değil" yazar.
- **Tek sunucu örneği** varsayılır (Render tek instance). Birden fazla örnek için dağıtık kilit (Redis) gerekir.
- Render ücretsiz plan uyursa kuyruk da durur: `POST /api/cron/scan?key=CRON_SECRET` adresini cron-job.org ile 5-15 dk'da bir çağırın (kuyruğu da dürter).
- Ayarlar: `JOB_CONCURRENCY`, `JOB_PER_USER_CONCURRENCY`, `JOB_MAX_ATTEMPTS`, `JOB_MAX_ITEMS` (bkz. `.env.example`).

## Gecikme ölçümü
`node loadtest.js http://127.0.0.1:3000/health 300 10` → P50/P95/P99. Sunucu içi değerler admin panelinde (yeniden başlayınca sıfırlanır). Gecikme (ms) ile performans puanı (0-100) farklı kavramlardır.

## Klasör yapısı
```
/
├─ index.js                 Node giriş noktası (tarama motoru + API + statik dosya servisi)
├─ index.py                 Python giriş noktası (aynı API; ayrı servis olarak çalışır)
├─ package.json / package-lock.json
├─ firestore.rules          Firestore güvenlik kuralları (tarayıcıdan doğrudan erişim kapalı)
├─ .env.example             Ortam değişkenleri örneği
├─ server/                  Sunucu modülleri (tarayıcıya ASLA gönderilmez)
│   ├─ security.js          Hız sınırı, eşzamanlılık, kimlik doğrulama, sahiplik, kota
│   ├─ payments.js          Stripe + iyzico, abonelik, webhook
│   ├─ user-state.js        Bulut durumu, onay kaydı, veri indirme, hesap silme
│   └─ firebase-init.js     Firebase Admin başlatma ve web yapılandırması
├─ public/                  Tarayıcıya sunulan her şey (yalnızca bu klasör yayınlanır)
│   ├─ index.html, manifest.json, sw.js
│   ├─ css/style.css
│   ├─ js/                  app.js, login.js, config.js, plans.js, company.js, legal.js,
│   │                       cookie-consent.js, sw-register.js, lucide.min.js
│   ├─ legal/               KVKK, gizlilik, çerez, kullanım koşulları, mesafeli satış, iade, iletişim…
│   ├─ fonts/               Kendi sunucumuzdan yazı tipleri (Google Fonts kullanılmaz)
│   └─ icons/
├─ tests/security.test.js   Otomatik testler (npm test)
├─ docs/RAPOR_ve_EKSIKLIK_LISTESI.md
└─ .github/workflows/ci.yml GitHub Actions: kontrol + test
```

> Not: Depodaki mevcut yerleşim **düz** (tüm dosyalar kökte) olabilir; kod her iki yerleşimi de destekler (`SRV()` / `PUBLIC_DIR`).

## Yayına alma (Render – Node, mevcut yöntem)
- **Root Directory:** boş bırakın (repo kökü) • **Build:** `npm install` • **Start:** `node index.js`
- Ortam değişkenleri: `.env.example`
- **Önce `public/js/company.js` içindeki şirket bilgilerini doldurun** (yasal sayfalar buradan beslenir).

## Python sürümü (isteğe bağlı, ayrı Render "Python" servisi)
- **Build:** `pip install fastapi "uvicorn[standard]" aiohttp dnspython cryptography firebase-admin iyzipay brotli`
- **Start:** `uvicorn index:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*" --no-server-header`

## Geliştirme
```
npm install
npm run check     # sözdizimi kontrolü (Node + Python)
npm test          # 82 otomatik test (security.test.js + dac-features.test.js)
```
