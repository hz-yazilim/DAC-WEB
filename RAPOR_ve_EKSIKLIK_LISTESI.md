# Digital Asset Center – Güvenlik, Analiz, Python ve Yasal Uyum Raporu

Test özeti: Node 35/35 birim testi; Python sunucusu için 59 akış testi (sahte Firestore ile ödeme, kota, hesap silme, webhook) + 47 saldırı testi; JS ↔ Python farkı testi (aynı sahte sitelerde WEB/SEO/SECURITY/PERFORMANCE/UPTIME/API/ANALYTICS/SERVER/SSL/DOMAIN/BRAND/SAAS çıktıları **birebir aynı**, yalnız aşağıda yazılı istisnalar).
**Test edemediklerim (sandbox'ta internet/Firebase/ödeme yok):** gerçek Firebase girişi, gerçek Stripe/iyzico çağrıları, gerçek internet DNS/RDAP/crt.sh/GitHub/Play Store sorguları, tarayıcıda arayüz görünümü. Bunları canlıya almadan önce kendiniz bir kez deneyin.

---
## 1. BULUNAN VE DÜZELTİLEN AÇIKLAR

### Kritik / Yüksek
| # | Açık | Etki | Düzeltme |
|---|------|------|----------|
| 1 | **SSRF – yönlendirme ile iç ağ**: IP adresli hedeflerde Node `lookup` çağırmadığı için kötü bir site `Location: http://169.254.169.254/...` ile sunucuyu iç ağa/bulut meta verisine yönlendirebiliyordu (HTTP ve TLS bağlantılarında) | Bulut kimlik bilgisi/iç servis sızıntısı | `blockedHost()` her bağlantıdan önce (yönlendirme dahil); yalnız http/https; 127.1, 2130706433, 0x7f… biçimleri dahil |
| 2 | **ReDoS / sunucu kilitlenmesi**: HTML'de `[\s\S]*?`, `[^>]+` kalıpları; 160 KB'lık kötü sayfa taramayı **9,4 sn**, 1,5 MB **dakikalar** kilitliyordu (tek iş parçacığı → tüm kullanıcılar durur) | Kolay servis dışı bırakma (DoS) | Doğrusal zamanlı tek geçişli ayrıştırıcı; en kötü girdiler artık <0,3 sn |
| 3 | **Oturum belirteci sızıntısı**: Ayarlar'daki "Scanner API adresi" alanı Firebase belirtecinin gönderileceği adresi kullanıcıya bıraktı (sosyal mühendislikle çalınabilir) | Hesap ele geçirme | Yalnız yapılandırmadaki adres / aynı alan adı / localhost |
| 4 | `firebase-admin@12` bağımlılığında **yüksek** önem derecesi açık (node-forge) | Zincirleme açık | `firebase-admin@13` (Node ≥18 ile uyumlu); `npm audit`: yüksek = 0 |
| 5 | Eşzamanlılık sınırı dolunca **kota tüketen boş varlık kaydı** kalıyordu | Kullanıcı kendi kotasını kaybeder | Yuva, DB yazımından önce alınır |
| 6 | Üretimde Firestore yoksa tarama **plan denetimi olmadan** çalışıyordu (fail-open) | Ücretli ürün bedava | Fail-closed (503); gerekirse `ALLOW_SCAN_WITHOUT_DB=true` |
| 7 | Başkasının sunucusuna **izinsiz port/dosya taraması** riski (hukuki: TCK 243-245) | Hukuki sorumluluk, IP kara listesi | Sunucu/Güvenlik taramalarında yetki beyanı zorunlu + tarih/IP ile kayıt |

### Orta / Düşük
- Stripe imzası ASCII dışı karakterde **500 hatası/istisna** (webhook çöküyordu) → doğrulama regex'li; webhook gövdesi `null` ise TypeError → düzeltildi.
- `X-Forwarded-For` istemciden sahtelenebiliyordu (iyzico IP'si) → `req.ip`.
- Ödeme uçlarında ve genel `/api` için **hız sınırı yoktu** → eklendi (`PAY_RATE_LIMIT`, `API_RATE_LIMIT`).
- Ödeme sonrası yönlendirme yolu sertleştirildi; sipariş kimliği doğrulama; dummy e-posta (`musteri@example.com`) kaldırıldı.
- SSL taraması kullanıcı portuyla **rastgele port tarayıcısına** dönüşebiliyordu → yalnız TLS portları.
- `decodeEntities` çift çözümleme (`&amp;lt;`) → düzeltildi.
- `/health` ayrıntı sızıntısı azaltıldı; hız sınırı haritası sınırsız büyüyordu → sınır; sürekli `uncaughtException` döngüsünde (60 sn'de 5) süreç yeniden başlar.
- İstemci: bozuk `localStorage` ve geçersiz varlık türü **uygulamayı çökertiyordu** → dayanıklı; `Math.random` kimlikler → `crypto`; `data-id` kaçışı; `targetUrl` tür doğrulaması.
- Gizlilik/tedarik zinciri: Google Fonts ve jsDelivr (kullanıcı IP'si 3. tarafa gidiyordu, SRI yoktu) → **kendi sunucunuzdan** (CSP'den de çıkarıldı).
- CORS'a `DELETE` eklendi (hesap silme için gerekli).

---
## 2. YASAL / KVKK İŞLERİ (YAPILDI)
Yeni sayfalar: **KVKK Aydınlatma Metni, Gizlilik, Çerez Politikası, Kullanım Koşulları, Kabul Edilebilir Kullanım, Mesafeli Satış Sözleşmesi + Ön Bilgilendirme Formu, İptal/İade, İletişim**.
- Tüm şirket bilgileri **tek dosyada**: `company.js` (doldurulana kadar sayfalarda kırmızı "TASLAK" uyarısı çıkar).
- Giriş/kayıtta zorunlu onay kutusu (sunucuya kaydedilir); ödeme öncesi **Ön Bilgilendirme + Satış Sözleşmesi + cayma hakkı beyanı** onayı (sunucu zorunlu tutar, sürüm/IP/tarih kaydı).
- Çerez çubuğu: analitik yalnız açık onayla çalışır. Sürüm değişince `company.js > surum` güncelleyin.
- KVKK m.11: **"Tüm verilerimi indir"** ve **"Hesabımı sil"** (fatura/sipariş kayıtları yasal saklama için tutulur).

---
## 3. SİZİN YAPMANIZ GEREKENLER (eksik listesi, A'dan Z'ye)
**Yasal / idari**
1. `company.js` içindeki **tüm** alanları doldurun (ünvan, MERSİS, vergi, adres, KEP, e-postalar, VERBİS durumu, KDV notu, yetkili şehir).
2. Metinleri **bir avukata okutun** (özellikle yurt dışı aktarım, sorumluluk sınırı, cayma istisnası). Ben avukat değilim; metinler iyi niyetli ve güncel mevzuata göre hazırlanmış taslaktır, "hiç sorun çıkmaz" garantisi veremem.
3. **VERBİS** kayıt yükümlülüğünüzü kontrol edin; yurt dışı aktarım için (Google, Render, Stripe) KVKK m.9 mekanizmasını (standart sözleşme / bildirim) belgeleyin; sağlayıcılarla veri işleme sözleşmelerini (DPA) arşivleyin.
4. **Fatura**: otomatik e-fatura/e-arşiv yok. Ödeme sonrası fatura kesme süreci kurun; fiyatların KDV dahil/hariç olduğunu netleştirin.
5. **iyzico**: canlıda alıcı kimlik numarası için sahte `11111111111` gönderiliyor (kullanıcı vermezse). iyzico/BDDK kuralları gereği canlıda gerçek TC/VKN toplamanız gerekebilir; iyzico ile teyit edin. iyzico ve Stripe başvurularında bu yasal sayfaların URL'lerini isteyecekler.
6. ETBİS (e-ticaret bilgi sistemi) kaydı gereksinimini muhasebecinizle kontrol edin.
7. `SECURITY_CONTACT` ortam değişkenini gerçek adresle ayarlayın (şu an yer tutucu görünür).
8. Silinen hesabın yeniden kayıtla **yeni deneme hakkı** alması engellenmiyor (ör. e-posta özetinin saklanması KVKK açısından ayrıca değerlendirilmeli).

**Güvenlik / operasyon**
9. Render'da `VERIFY_REVOKED=true` önerilir (çıkış yapılan oturumlar anında geçersiz olur; her istekte +1 Firebase çağrısı).
10. Hız sınırları **bellek içi**: Render'da birden fazla örnek açarsanız Redis gerekir.
11. Firebase SDK `gstatic.com`'dan dinamik yükleniyor (SRI mümkün değil). Tam bağımsızlık için SDK'yı da kendi sunucunuza alabilirsiniz.
12. Yedekleme (Firestore otomatik dışa aktarma), hata izleme (Sentry vb.), dış uptime izleme kurulu değil. Dosya sahipliği `assetId` genel ad alanında (tahmin edilen kimlikle "ön rezervasyon" mümkün; istemci artık rastgele üretiyor).
13. İki faktörlü doğrulama, CAPTCHA/bot koruması yok (kayıt sahtekârlığı).
14. Otomatik CI yok: GitHub Actions ile `npm test` çalıştırmanızı öneririm.
15. Kalan `npm audit` bulguları (11 orta) alt bağımlılıklarda (`iyzipay`→`postman-request`, Google kütüphaneleri); acil değil, düzenli güncelleyin.

**Ürün**
16. Analytics taraması gerçek trafik verisi vermiyor (Google Analytics Data API bağlı değil). `app.js` tek dev dosya; erişilebilirlik (ekran okuyucu) ve İngilizce arayüz eksik. Uygulama içi paket tabloları `plans.js`'ten; Python `index.py` içinde ikinci kopya var (uyuşmazlıkta açılışta uyarı verir).

---
## 4. PYTHON SÜRÜMÜ (`index.py`)
**Evet, çalışır ve aynı API'yi sunar** (ön yüz değişmez). Ancak Node **şu an ürettiğiniz sürüm**; Python'a geçmek zorunlu değil ve **Render'da mevcut Node servisini Python'a çeviremezsiniz** – yeni bir "Python" Web Service açmanız gerekir. Güvenli geçiş: iki servisi yan yana çalıştırın, Python'u test edin, sonra alan adını/`PUBLIC_API_URL`'yi taşıyın.

Render (yeni servis, aynı repo, aynı ortam değişkenleri):
- Build: `pip install fastapi "uvicorn[standard]" aiohttp dnspython cryptography firebase-admin iyzipay brotli`
- Start: `uvicorn index:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*" --no-server-header`

Bilinen farklar (Node'a göre): OCSP stapling bilgisi okunamaz (`ocspStapling: null`, ilgili bilgi bulgusu çıkmaz); sertifika zinciri yalnız sunucunun gönderdiği sertifikalardan oluşur (kök CA eklenmez); `trustError` kodu bazı bileşik hatalarda farklı çıkabilir; RDAP/ağ hata metinleri farklı yazılır; 404 gövdesi JSON'dur; crt.sh çok büyük yanıtları (>4 MB) atlar. Python 3.10+ gerekir.

## 5. YÜKLEME (yeni klasör yapısı)
1. GitHub'daki **tüm eski dosya ve klasörleri silin** (kökte hiçbir şey kalmasın).
2. Zip'i bilgisayarınızda **açın**; zip'in içinde sarmalayıcı klasör yoktur, dosyalar doğrudan kök düzeyindedir. **Açılan her şeyi** (klasörler dahil) GitHub'a sürükleyin. Gizli dosyalar (`.github`, `.gitignore`, `.env.example`) görünmüyorsa dosya yöneticisinde "gizli dosyaları göster"i açın.
3. Render: **Root Directory boş**, Build `npm install`, Start `node index.js` (değişmedi).
4. Tarayıcıda Ctrl+F5 (servis çalışanı önbelleği v8'e yükselir; eski adresler 301 ile yeni konumlara yönlenir).


---
# V13.1 EKİ — Tam proje denetimi ve geliştirme raporu

## Sürüm bilgisi (ZIP'ten doğrulandı)
`package.json`: 13.0.0 → **13.1.0**; `index.js` başlığı v12.0 → `SCANNER_VERSION` **v13.1**; arayüz başlığı "v11". Talimattaki "V10.3.0" ZIP'te **bulunmuyor**; sürüm bilgileri daha önce tutarsızdı.

## Test sonuçları (gerçek çalıştırma)
`npm test`: **82 test, 81 geçti, 0 başarısız, 1 atlandı** (klasörlü yerleşime özel varlık-yolu testi). Ayrıca `npm run check` 26 dosya hatasız; gerçek sunucu açılıp 300 istekle ölçüldü (P50 20 ms, P95 43 ms, P99 82 ms, hata 0 %; yerel makine, 10 eşzamanlı). Arayüz geçici jsdom ile duman testinden geçti (proje bağımlılığına eklenmedi). Eski test dosyası düz yerleşimde zaten **çalışmıyordu** (`../server/..` yolları); düzeltildi.

## Özellik durumu
| Özellik | Durum |
|---|---|
| Tarama motorları, SSRF (bağlantı anı DNS denetimi, yönlendirmede yeniden doğrulama, boyut/süre sınırı), ödeme, bildirim | Çalışıyor, mevcut testlerle doğrulandı (değiştirilmedi) |
| Admin paneli (API + arayüz) | Çalışıyor: sahte Firebase ile 14 test + arayüz duman testi. **Gerçek Firebase ile denenmedi** |
| Toplu tarama kuyruğu | Çalışıyor: 250 öğe, yeniden başlatma kurtarma, yeniden deneme, iptal, izolasyon (bellek ve sahte Firestore ile). **Gerçek Firestore/internet taraması denenmedi** |
| Genel Tarama (domain) | Çalışıyor (arayüz duman testi); gerçek RDAP bitiş tarihi canlıda doğrulanmalı |
| Skor modülü | Çalışıyor, testli. WEB'in eski "overall" skoru **aynen korundu**; yeni bileşik skor `scores.composite` olarak eklendi |
| Girdi doğrulama | Sunucu tarafı: toplu iş + fatura telefon/vergi no. Diğer eski formlar mevcut denetimleriyle kaldı |
| AI / Gemini | Bilinçli **devre dışı** (anahtar istenmiyor, çağrı yok) |
| Para birimi / affiliate | Altyapı hazır, **etkin değil**; EUR için fiyat tanımlı değil, kur sağlayıcısı yok |
| Python (`index.py`) | **Güncellenmedi** (admin/kuyruk yalnızca Node'da). Python servisi kullanılıyorsa bu özellikler orada yok |

## Yapılmayanlar / dikkat
1. **"8" ve "minimum 100" hedefi**: anlamı belirtilmediği için **uygulanmadı**. Neyi ifade ettiğini bildirirseniz eklenir.
2. P95 için "mevcut test aracı" ZIP'te yoktu; `loadtest.js` eklendi.
3. iyzico canlıda alıcı kimlik no isteyebilir; TC alanı kaldırıldığı için sabit değer gönderiliyor (eskiden de kullanıcı girmezse böyleydi). iyzico ile teyit edin.
4. Metrikler ve hata halkası **bellek içi**: yeniden başlayınca sıfırlanır (panelde belirtilir). Hız sınırları çoklu örnekte Redis ister.
5. Gerçek tarayıcıda (mobil dahil) görsel kontrol, gerçek Firebase girişi, gerçek RDAP/DNS taraması yapılmadı.
6. `ci.yml` kökte duruyor; GitHub'ın çalıştırması için `.github/workflows/ci.yml` yolunda olmalı.
7. Yeni Firestore koleksiyonları: `scanJobs`, `scanJobItems`, `adminRoles`, `adminAudit` (kurallar zaten istemci erişimini kapatıyor; indeks gerekmez).
