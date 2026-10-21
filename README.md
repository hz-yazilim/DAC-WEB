# Digital Asset Center (DAC)

Node.js/Express tarama API'si + statik web arayüzü (aynı Render servisinden yayınlanır).

## Çalıştırma
- `npm install` → `npm start` (PORT ortam değişkenini kullanır)
- Test: `npm test` — Sözdizimi: `npm run check`
- Yerel geliştirme: `NODE_ENV=development DEV_AUTH_BYPASS=true npm start` (giriş olmadan test kullanıcısı; üretimde çalışmaz)

## Güvenlik özeti
- `NODE_ENV` development/test değilse **üretim** sayılır; sahte kullanıcı üretimde oluşmaz.
- `/api/scan` Firebase ID token ister; varlık sahipliği, paket kotası, hız ve eşzamanlılık sınırı sunucuda uygulanır.
- Özel/yerel IP hedefleri bağlantı anında (DNS sonrası, yönlendirmeler dahil) engellenir.
- Hız sınırı bellek içidir: tek Render örneği için yeterli, birden fazla örnekte Redis gerekir.

## Render
Build: `npm install` · Start: `npm start` · Env: `.env.example` dosyasındaki adlar.
Stripe webhook adresi: `/api/stripe/webhook` · iyzico callback: `/api/iyzico/callback`

## Geri dönüş
Render > Deploys > önceki başarılı sürüm > Rollback. Veri taşıma yapılmadı; `assets` kayıtlarına yalnızca `ownerId` eklenir.

## Firebase kurulum kontrol listesi
1. Authentication > Sign-in method > **Google** etkin olmalı.
2. Authentication > Settings > **Authorized domains**: `dac-web-yefr.onrender.com`, `dac-web-tfqf.onrender.com` (kullandığınız Render adresi) ve GitHub Pages kullanıyorsanız `hz-yazilim.github.io` ekli olmalı.
3. Firestore > Rules: `firestore.rules` dosyasındaki içerik (istemci erişimi kapalı) yayınlanmalı.
4. Render > Environment: `FIREBASE_SERVICE_ACCOUNT` (aynı proje: assetops-ed334), `ALLOWED_ORIGINS`, `PUBLIC_API_URL`.
5. Sağlık kontrolü: `https://<render-adresiniz>/health` → `"ok": true` dönmeli. Render > Logs içinde "Firebase kimlik bilgisi yok" uyarısı **görünmemeli** (görünüyorsa `FIREBASE_SERVICE_ACCOUNT` eksik/hatalı).
