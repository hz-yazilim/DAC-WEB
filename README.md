# Digital Asset Center (DAC)

Alan adı, SSL, DNS, web sitesi, SEO, güvenlik, performans, uptime, API, sunucu, marka, mobil uygulama, kod deposu ve SaaS aboneliklerini tarayan ve izleyen web uygulaması.
Sunucu **Node.js (Express)** ile çalışır. (Eski Python/FastAPI sürümü `index.py` V13.3 ile **kaldırıldı**: yeni özellikler yalnızca Node'dadır; iki kod tabanını eşit tutmak yerine tek tabanda test kapsamını artırmak daha güvenlidir.)

## V13.1 yenilikleri
- **Yönetici paneli** (`#admin`, yalnızca yöneticilere görünür) + `/api/admin/*` (rol **sunucuda** doğrulanır; `admin.js`).
- **Kalıcı toplu tarama kuyruğu** (`jobs.js`, `/api/jobs*`, Toplu Tarama sayfası; 200+ domain). Domain sayfasında **Genel Tarama** (`#domains`).
- **Merkezi skor** (`scoring.js`): SEO %35 + Güvenlik %50 + Performans %15, kritik bulguda en çok 75.
- **Girdi doğrulama** (`validators.js`), ölçümler (`metrics.js`: P50/P95/P99), **AI mimarisi (kapalı)** (`ai-provider.js`), para birimi/affiliate hazırlığı (`billing-catalog.js`).
- Ortak **Yenile** düğmesi yalnızca durumları çeker, tarama başlatmaz. TC kimlik alanı kaldırıldı (isteğe bağlı 10 haneli vergi no).

## V13.4 yenilikleri
- **Kullanıcı destek paneli** (`#support`, menüde *Destek*): giriş yapan kullanıcı talep açar, yöneticinin yanıtını görür, mesaj yazar, talebi kapatır. Uçlar: `GET/POST /api/support/my`, `POST /api/support/my/:id/reply|close` (`support.js`); yeni istemci dosyası `app-support.js`. Yönetici > Destek sekmesi kullanıcı yazışmalarını, kategoriyi ve "Kullanıcıyı aç" kısayolunu gösterir.
- **Abonelik iptali**: kullanıcı *Paket ve Faturalandırma > Aboneliğim* kartından iptal eder / iptali geri alır (`POST /api/subscription/cancel|resume`). Ödeme sağlayıcılı pakette yalnızca dönem sonunda iptal; hemen sonlandırma ve iade yönetici işlemidir. Yönetici: Paketler listesi, kullanıcı detayı ve Ödemeler > Siparişler'de *Aboneliği iptal et* / *İptali geri al* (`/api/admin/users/:uid/subscription/cancel|resume`).
- Yeni ortam değişkenleri (isteğe bağlı): `SUPPORT_MAX_OPEN` (varsayılan 10), `SUPPORT_PANEL_WRITE_LIMIT` (saatlik, varsayılan 20), `SUPPORT_PANEL_IP_LIMIT`.

## V13.3 yenilikleri
- **E-posta** (`mailer.js`, Resend): ödeme makbuzu, paket bitiş hatırlatması (PayTR/ödemesiz paket 7/3/1 gün kala), deneme bitiyor, destek yanıtı. `RESEND_API_KEY` + `MAIL_FROM` yoksa kapalıdır. Hatırlatmalar 6 saatte bir otomatik ve `/api/cron/ops` (CRON_SECRET) ile çalışır.
- **Yönetici > Ödemeler**: *Faturalar* (faturasız ödemeler listesi, fatura no işleme; e-arşiv entegrasyonu yoktur), siparişte *İade* (PayTR iadesi; kısmi iade desteklenir), kullanıcı detayında *abonelik iptali*.
- **Toplu işlemler** (paket ver/kaldır, devre dışı bırak/etkinleştir, oturum kapat; en çok 200), **kullanıcı silme (KVKK)**, **destek talebi kutusu** (iletişim formu + yanıt), **CSV**.
- **Operasyon**: kalıcı hata kaydı (`errorLog`), 5xx alarmı (Telegram / Slack-Teams webhook / e-posta), Firestore yedeği (`BACKUP_BUCKET`), test araçları.
- **Güvenlik**: yönetici **iki adımlı doğrulama (TOTP)** — `ADMIN_REQUIRE_2FA=true` ile zorunlu; **CAPTCHA** (Cloudflare Turnstile) destek formunda; **deneme suistimali engeli** (tuzlanmış e-posta özeti, `trialUsed`); **özellik bayrakları** (yeni kaydı kapat, tarama türünü kapat).
- Arayüz kodu `app.js` tek dosyadan 6 dosyaya bölündü (`app.js`, `app-analysis.js`, `app-main.js`, `app-bulk.js`, `app-admin.js`, `app-admin-ops.js`); index.html'de bu sırayla yüklenir.
- Yeni Firestore koleksiyonları: `mailSent`, `mailLog`, `errorLog`, `backups`, `supportTickets`, `adminTotp`, `trialUsed`. Yeni sunucu dosyaları: `mailer.js`, `ops.js`, `support.js`, `totp.js`, `admin-ops.js`; istemci: `support-form.js`.

## V13.2 yenilikleri (yönetici paneli)
- **Yönetici > Ödemeler > Fiyatlar**: paket fiyatları (TL/USD), yıllık ödemede ücretlenen ay sayısı ve paket limitleri (varlık/ekip/geçmiş) panelden değişir; Firestore `settings/pricing` içinde saklanır, kod yeniden dağıtılmadan **anında** yayına girer (checkout, kota ve arayüz). Değişiklik geçmişi (`pricingHistory`), 5 kattan büyük değişimde onay, "varsayılana dön". Mevcut (eski) Stripe aboneliklerinin fiyatı değişmez; PayTR ödemeleri tek seferlik olduğundan yeni fiyat bir sonraki satın almada geçerlidir.
- **Kuponlar** (`coupons`): yüzde/sabit tutar, paket/dönem kısıtı, toplam ve kişi başı kullanım, tarih aralığı. Ödeme ekranında kupon alanı; indirim sunucuda hesaplanır. Ekrandaki tutar ile sunucu tutarı farklıysa ödeme durdurulur (`PRICE_CHANGED`).
- **Gelir** sekmesi: tahsilat (7/30 gün/toplam), tahmini MRR, paket bazında dağılım, başarısız/takılı sipariş, 7 gün içinde bitecek paketler. PayTR tahsilatları bildirim geldiğinde `orders` içine "paid" olarak işlenir.
- **Duyuru ve Bakım**: tüm kullanıcılara şerit duyuru; bakım modunda yöneticiler dışında yeni tarama/toplu iş başlatılamaz.
- Kullanıcı detayında: oturumları kapat, şifre sıfırlama bağlantısı, e-postayı doğrulandı say, yönetici notu. Kullanıcı/abonelik/sipariş/işlem kaydı **CSV** dışa aktarma.
- Yeni dosya: `commerce.js` (sunucu). Yeni Firestore koleksiyonları: `settings`, `pricingHistory`, `coupons`, `couponUsers`, `adminNotes`. Not: `index.py` (Python) bu özellikleri içermez.

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
├─ package.json / package-lock.json
├─ firestore.rules          Firestore güvenlik kuralları (tarayıcıdan doğrudan erişim kapalı)
├─ .env.example             Ortam değişkenleri örneği
├─ server/                  Sunucu modülleri (tarayıcıya ASLA gönderilmez)
│   ├─ security.js          Hız sınırı, eşzamanlılık, kimlik doğrulama, sahiplik, kota
│   ├─ payments.js          PayTR (iFrame API + bildirim + iade), abonelik
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
- **Build:** `pip install fastapi "uvicorn[standard]" aiohttp dnspython cryptography firebase-admin brotli`
- **Start:** `uvicorn index:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*" --no-server-header`

## Geliştirme
```
npm install
npm run check     # sözdizimi kontrolü (Node + Python)
npm test          # 82 otomatik test (security.test.js + dac-features.test.js)
```
