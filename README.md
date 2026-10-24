# Digital Asset Center (DAC)

Alan adı, SSL, DNS, web sitesi, SEO, güvenlik, performans, uptime, API, sunucu, marka, mobil uygulama, kod deposu ve SaaS aboneliklerini tarayan ve izleyen web uygulaması.
Sunucu **Node.js (Express)** ile çalışır; aynı API'yi sunan isteğe bağlı **Python (FastAPI)** sürümü `index.py` içindedir.

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
npm test          # 37 otomatik test
```
