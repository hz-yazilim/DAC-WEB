/* Digital Asset Center v11 - veriler tarayıcıda (localStorage), tarama/ödeme için scanner API kullanılır */
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>Math.random().toString(36).slice(2,10)+Date.now().toString(36);
const P=window.DAC_PLANS;

/* ---------- Kategoriler: ne taranır, neden önemli ---------- */
const GROUPS=[['web','WEB & ALTYAPI'],['perf','PERFORMANS & GÜVENLİK'],['brand','MARKA & İLETİŞİM'],['soft','YAZILIM & ABONELİK']];
const CATS={
web:{g:'web',label:'Web Sitesi',icon:'globe',c:'#3b82f6',api:'WEBSITE',desc:'Erişim, yanıt süresi, temel SEO ve güvenlik başlıkları',ph:'ornek.com',
 what:['Siteye erişim ve HTTP durum kodu','Yanıt süresi','Başlık (title), meta açıklama ve H1','robots.txt ve sitemap.xml','HSTS, CSP, X-Frame-Options başlıkları','Cloudflare/WAF bot koruması algılama'],
 why:'Müşterinin gördüğü ilk şey sitenizdir; kesinti ve eksik temel ayarlar doğrudan gelir kaybıdır.'},
domain:{g:'web',label:'Domain',icon:'link-2',c:'#8b5cf6',api:'DOMAIN',desc:'DNS kayıtları, e-posta kimliği, kayıt kuruluşu ve bitiş tarihi',ph:'ornek.com',
 what:['A, AAAA, NS, MX, TXT, SOA kayıtları','SPF, DKIM, DMARC ve CAA','DNSSEC ve transfer kilidi','Kayıt kuruluşu ve bitiş tarihi (RDAP)','Subdomain devralma riski'],
 why:'Alan adı süresinin dolması ya da çalınması, markanızın internetten silinmesi demektir.'},
ssl:{g:'web',label:'SSL Sertifikası',icon:'lock',c:'#10b981',api:'SSL_CERTIFICATE',desc:'Sertifika geçerliliği, kalan gün, zincir ve TLS gücü',ph:'ornek.com',
 what:['Sertifika bitiş tarihi (kalan gün)','Veren kuruluş, zincir ve SAN listesi','Anahtar uzunluğu ve imza algoritması','TLS sürümü ve şifre','Kendinden imzalı sertifika ve HSTS'],
 why:'Süresi dolan sertifika tarayıcıda "güvenli değil" uyarısı çıkarır; giriş ve ödemeler durur.'},
hosting:{g:'web',label:'Hosting',icon:'hard-drive',c:'#f59e0b',api:'HOSTING',desc:'Sağlayıcı, ülke, CDN/DDoS koruması ve IPv6',ph:'ornek.com',
 what:['IPv4/IPv6 adresleri ve ters DNS','Sağlayıcı, ASN, ülke ve şehir','CDN/WAF tespiti (Cloudflare, CloudFront, Akamai…)','HTTPS, HTTP/2 ve yanıt süresi','Tek IP (yedeksiz) riski'],
 why:'Verinizin hangi ülkede, kimin altyapısında durduğunu bilmek hem uyumluluk (KVKK/GDPR) hem süreklilik için gerekir.'},
server:{g:'web',label:'Sunucu',icon:'server',c:'#06b6d4',api:'SERVER',desc:'Açık port taraması ve internete açık riskli servisler',ph:'sunucu.com veya 203.0.113.10',
 what:['18 yaygın port (SSH, RDP, SMB, FTP, Telnet…)','Veritabanı portları (MySQL, PostgreSQL, MongoDB, Redis…)','Bağlantı gecikmesi','Sunucunun konumu ve sağlayıcısı'],
 why:'İnternete açık bir veritabanı ya da RDP portu, fidye yazılımı saldırılarının en yaygın giriş kapısıdır.',
 hint:'Yalnızca bağlantı denenir, veri gönderilmez. Sadece kendi sunucularınızı tarayın.'},
uptime:{g:'perf',label:'Uptime & Gecikme',icon:'activity',c:'#22c55e',api:'UPTIME',desc:'Ardışık denemelerle erişilebilirlik ve gecikme ölçümü',ph:'ornek.com',
 what:['6 ardışık istekle başarı oranı','Ortalama, en yavaş ve p95 yanıt süresi','Gecikme dalgalanması (jitter)','DNS ve TCP bağlantı süreleri'],
 why:'Müşteri şikâyet etmeden önce kesinti ve yavaşlamayı siz görürsünüz.',
 hint:'Tek noktadan anlık ölçümdür, sürekli izleme değildir.'},
performance:{g:'perf',label:'Performans',icon:'gauge',c:'#eab308',api:'PERFORMANCE',desc:'Sayfa hızı, sıkıştırma, önbellek ve HTTP/2',ph:'ornek.com',
 what:['İlk bayt süresi (TTFB) ve toplam yükleme','gzip / brotli sıkıştırma','HTTP/2-3 ve TLS el sıkışma süresi','Yönlendirme zinciri','Sayfa ağırlığı, bloklayan scriptler, lazy-load','Statik dosya önbellek süreleri'],
 why:'Yavaş site hem dönüşüm oranını hem arama sıralamasını düşürür.'},
seo:{g:'perf',label:'SEO',icon:'search',c:'#f97316',api:'SEO',desc:'Başlık, meta, canonical, hreflang ve yapısal veri',ph:'ornek.com',
 what:['Title ve meta açıklama uzunluğu','H1/H2, görsel alt metinleri, kelime sayısı','Canonical, noindex ve robots.txt engeli','sitemap.xml','hreflang (çok dilli / çok ülkeli siteler)','Open Graph, Twitter Card ve JSON-LD'],
 why:'Çok ülkeli bir şirkette yanlış hreflang ya da unutulmuş bir noindex, trafiği sessizce yok eder.'},
security:{g:'perf',label:'Güvenlik',icon:'shield-check',c:'#ef4444',api:'SECURITY',desc:'Güvenlik başlıkları, çerezler, açıkta kalan dosyalar, HTTPS',ph:'ornek.com',
 what:['HSTS, CSP, X-Frame-Options, nosniff, Referrer/Permissions-Policy','Çerez bayrakları (Secure, HttpOnly, SameSite)','HTTP→HTTPS yönlendirmesi ve karışık içerik','Sertifika süresi ve TLS sürümü','Açıkta kalan .env, .git, yedek ve phpinfo dosyaları','Sunucu sürüm bilgisi sızıntısı'],
 why:'Bir veri sızıntısı itibar ve yasal yaptırım (KVKK/GDPR) maliyetidir; çoğu sızıntı basit bir yapılandırma hatasıdır.',
 hint:'Yalnızca sahibi olduğunuz siteleri tarayın.'},
api:{g:'perf',label:'API',icon:'code-2',c:'#6366f1',api:'API',desc:'Endpoint erişimi, JSON geçerliliği, CORS ve rate-limit',ph:'api.ornek.com/v1/health',
 what:['Durum kodu ve yanıt süresi (401/403 "korumalı" sayılır)','JSON geçerliliği ve hata formatı','CORS ayarları','Rate-limit başlıkları','HTTPS, HSTS ve sürüm bilgisi','API sürümleme (/v1)'],
 why:'Müşteriniz ürününüzü API ile kullanıyorsa, API kesintisi sizin kesintinizdir.'},
brand:{g:'brand',label:'Marka Koruması',icon:'fingerprint',c:'#d946ef',api:'BRAND',desc:'Benzer alan adı ve farklı uzantı (TLD) kayıtlarını bulur',ph:'sirketim.com',
 what:['25+ uzantıda (.net, .io, .com.tr, .de…) kayıt durumu','Yazım hatası ve benzer karakter varyasyonları (kimlik avı riski)','Aynı nameserver/IP ile "sizin" olanları ayırır','Henüz kayıt edilmemiş önemli uzantılar'],
 why:'Markanızı taklit eden alan adları kimlik avı ve müşteri kaybı yaratır; yeni ülkelere açılırken ülke uzantılarını sahiplenmek gerekir.',
 hint:'Sadece ana alan adınızı yazın. Kayıt tespiti DNS\'e dayanır.'},
email:{g:'brand',label:'Email',icon:'mail',c:'#14b8a6',api:'DOMAIN',desc:'Sahte e-posta (spoofing) koruması ve e-posta teslim kayıtları',ph:'ornek.com',
 what:['SPF, DKIM ve DMARC kayıtları ve politikaları','MX kayıtları','CAA kaydı','Alan adı DNS bütünlüğü'],
 why:'DMARC olmayan bir alan adı, müşterilerinize şirketiniz adına sahte e-posta gönderilmesine açıktır.',
 hint:'Domain taramasıyla aynı motoru kullanır; sonuçta e-posta satırlarına odaklanın.'},
mobile:{g:'soft',label:'Mobil Uygulama',icon:'smartphone',c:'#0ea5e9',api:'MOBILE_APP',desc:'Google Play / App Store: yayın durumu, puan ve güncelleme',ph:'com.firma.uygulama veya mağaza linki',
 what:['Mağazada yayında mı?','Puan ve değerlendirme sayısı','Son güncelleme tarihi (bakım durumu)','Sürüm ve minimum işletim sistemi (App Store)'],
 why:'Güncellenmeyen ya da mağazadan kalkan uygulama, kullanıcı ve gelir kaybıdır.',
 hint:'Play Store resmi API sunmaz; ayrıntılar sayfadan okunur, bulunamayan alanlar boş kalabilir.'},
repo:{g:'soft',label:'Kod Deposu',icon:'git-branch',c:'#64748b',api:'REPOSITORY',desc:'GitHub deposu: aktiflik, lisans ve topluluk sağlığı',ph:'sahip/depo veya github.com/sahip/depo',
 what:['Son commit ve arşiv durumu','Lisans, README ve katkı dosyaları','Açık issue ve yayın (release) durumu','Topluluk sağlık yüzdesi'],
 why:'Terk edilmiş ya da lisanssız bir depo, ürün ve hukuk riski demektir.',
 hint:'Özel (private) depolar taranamaz.'},
saas:{g:'soft',label:'SaaS Abonelik',icon:'layers',c:'#ec4899',api:'SAAS_SUBSCRIPTION',desc:'Yenileme tarihi, maliyet ve kullanım takibi',ph:'Sağlayıcı (ör: Notion)',
 what:['Yenileme/bitiş tarihine kalan gün','Maliyet takibi (para birimiyle)','Kullanım oranı (israf tespiti)'],
 why:'Unutulan abonelikler bütçeyi sessizce eritir; yenilemeyi kaçırmak servis kesintisi demektir.',
 hint:'Bu kategori internetten tarama yapmaz; girdiğiniz bilgileri değerlendirir.'}
};
const URLCATS=['web','api','seo','security','performance','uptime'];
const LISTS={
team:{title:'Ekip Yönetimi',icon:'users',f:[['name','Ad Soyad'],['email','Email'],['role','Rol']]},
projects:{title:'Müşteri Projeleri',icon:'briefcase',f:[['name','Proje adı'],['client','Müşteri'],['note','Not']]}
};
let KEY='dac_v1',S=null,U=null,PAYCFG=null,DEFERRED=null,HEALTH_TRIED=false;
const blank=()=>({assets:[],scans:[],team:[],projects:[],settings:{org:'HZ Yazılım',plan:'trial',apiUrl:'',trialStart:Date.now(),alertBelow:50,currency:/^tr/i.test(navigator.language)?'TRY':'USD',cycle:'monthly',billing:{}}});
const save=()=>{if(S)localStorage.setItem(KEY,JSON.stringify(S))};
const apiUrl=()=>(S.settings.apiUrl||(window.DAC_CONFIG||{}).API_URL||'').trim().replace(/\/$/,'');

/* ---------- Paket / deneme durumu ---------- */
function planState(){
 const st=S.settings,now=Date.now();
 if(P.PAID.includes(st.plan)&&(!st.planEnd||st.planEnd>now))return{id:st.plan,p:P.PLANS[st.plan],paid:true};
 const end=(st.trialStart||now)+P.TRIAL_DAYS*864e5;
 if(now<end)return{id:'trial',p:P.PLANS.trial,trial:true,end,left:end-now};
 return{id:'expired',p:P.PLANS.trial,expired:true,end};
}
const limitOf=ps=>ps.p.assets==null?Infinity:ps.p.assets;
const limTxt=ps=>ps.p.assets==null?'∞':ps.p.assets;
const leftTxt=ms=>{const d=Math.floor(ms/864e5),h=Math.floor(ms%864e5/36e5);return d?`${d} gün ${h} sa`:`${h} sa ${Math.floor(ms%36e5/6e4)} dk`};
const money=(n,c)=>c==='TRY'?n.toLocaleString('tr-TR',{minimumFractionDigits:2,maximumFractionDigits:2})+' ₺':'$'+n.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
const planName=ps=>ps.expired?'Süre doldu':ps.p.name;
function gate(){const ps=planState();if(ps.expired){toast('Deneme süreniz bitti. Devam etmek için bir paket seçin.','err');location.hash='plan';return false}return true}

/* ---------- yardımcılar ---------- */
const normKey=(cat,v)=>{v=String(v).trim().toLowerCase();if(['saas','mobile'].includes(cat))return v;if(cat==='repo')return v.replace(/^https?:\/\/(www\.)?github\.com\//,'').replace(/\.git$/,'').replace(/\/+$/,'');v=v.replace(/^https?:\/\//,'').replace(/^www\./,'').replace(/\/+$/,'');return URLCATS.includes(cat)?v:v.split('/')[0].split(':')[0]};
const proto=u=>/^https?:\/\//i.test(u)?u:'https://'+u;
const sev=f=>/_critical$/.test(f)?'bd':/_warning$/.test(f)?'wn':'mu';
const sevL={bd:'Kritik',wn:'Uyarı',mu:'Bilgi'};
/* Bulgu çevirileri (kod -> Türkçe). Bulunamazsa kod okunabilir hale getirilir. */
const FT={
web_bot_protection:'Bot koruması taramayı engelledi — site büyük olasılıkla çalışıyor, ayrıntılı analiz yapılamadı',web_down:'Site erişilemiyor',web_missing_target:'Hedef adres girilmemiş',web_slow:'Yanıt süresi yavaş',web_missing_title:'Sayfa başlığı (title) yok',web_missing_meta_description:'Meta açıklaması yok',web_missing_h1:'Sayfada H1 başlığı yok',web_missing_hsts:'HSTS başlığı yok',web_missing_csp:'Content-Security-Policy başlığı yok',web_missing_xframe:'Clickjacking koruması (X-Frame-Options) yok',web_missing_robots:'robots.txt bulunamadı',web_missing_sitemap:'sitemap.xml bulunamadı',
domain_invalid:'Geçersiz alan adı',domain_not_resolving:'Alan adı DNS\'te çözülmüyor',domain_missing_ns:'Nameserver (NS) kaydı yok',domain_single_ns:'Tek nameserver var (yedeksiz)',domain_missing_mx:'MX (e-posta) kaydı yok',domain_missing_caa:'CAA kaydı yok',domain_missing_spf:'SPF kaydı yok',domain_invalid_spf:'SPF kaydı hatalı',domain_missing_dmarc:'DMARC kaydı yok',domain_dmarc_policy_none:'DMARC politikası "none" (koruma uygulanmıyor)',domain_missing_dnssec:'DNSSEC kapalı',domain_dnssec_unknown:'DNSSEC durumu belirlenemedi',domain_expired:'Alan adının süresi dolmuş',domain_expiring_critical:'Alan adı süresi çok yakında doluyor',domain_expiring_soon:'Alan adı süresi yakında doluyor',domain_missing_expiry:'Bitiş tarihi okunamadı',domain_rdap_failed:'WHOIS/RDAP sorgusu başarısız',domain_registrar_unknown:'Kayıt kuruluşu belirlenemedi',domain_transfer_unlocked:'Domain transfer kilidi kapalı',domain_transfer_lock_unknown:'Transfer kilidi durumu belirlenemedi',domain_takeover_risk:'Subdomain devralma (takeover) riski',
DNS_SEC_ACTIVE:'DNSSEC aktif',DOMAIN_TRANSFER_LOCKED:'Transfer kilidi açık (iyi)',EMAIL_CAA_VALID:'CAA kaydı geçerli',EMAIL_DKIM_VALID:'DKIM kaydı geçerli',EMAIL_DMARC_VALID:'DMARC kaydı geçerli',EMAIL_SPF_VALID:'SPF kaydı geçerli',
ssl_chain_incomplete:'Sertifika zinciri eksik',ssl_check_failed:'SSL bağlantısı kurulamadı',ssl_expired:'Sertifikanın süresi dolmuş',ssl_expiring_soon:'Sertifika süresi yakında doluyor',ssl_hsts_missing:'HSTS etkin değil',ssl_invalid_target:'Geçersiz hedef',ssl_self_signed:'Sertifika kendinden imzalı',ssl_tls_old_version:'Eski TLS sürümü kullanılıyor',ssl_weak_key:'Zayıf şifreleme anahtarı',ssl_weak_signature:'Zayıf imza algoritması',ssl_wildcard:'Wildcard sertifika kullanılıyor',
saas_expired:'Abonelik süresi dolmuş',saas_expiring_soon:'Abonelik yakında yenilenecek / bitecek',saas_missing_renewal:'Yenileme tarihi girilmemiş',saas_usage:'Kullanım oranı kritik seviyede',scan_error:'Tarama sırasında hata oluştu',
hosting_invalid_target:'Geçersiz hedef',hosting_not_resolving:'Alan adı IP adresine çözülmüyor',hosting_unreachable:'Sunucuya HTTPS ile ulaşılamıyor',hosting_no_https:'HTTPS (TLS) bağlantısı kurulamadı',hosting_no_cdn_waf:'CDN / DDoS koruması algılanmadı',hosting_no_ipv6:'IPv6 desteği yok',hosting_single_ip:'Tek IP adresi (yedeksiz)',hosting_slow_response:'Yanıt süresi yavaş (1,5 sn üzeri)',
server_invalid_target:'Geçersiz hedef',server_not_resolving:'Adres IP\'ye çözülmüyor',server_unreachable:'Hiçbir porta bağlanılamadı',server_no_service_ports:'Web/SSH/e-posta portu açık değil',
seo_unreachable:'Sayfaya ulaşılamadı',seo_missing_title:'Sayfa başlığı (title) yok',seo_title_length:'Başlık uzunluğu ideal değil (30–65 karakter)',seo_missing_description:'Meta açıklaması yok',seo_description_length:'Meta açıklama uzunluğu ideal değil (70–165 karakter)',seo_missing_h1:'H1 başlığı yok',seo_multiple_h1:'Birden fazla H1 var',seo_images_missing_alt:'Görsellerin çoğunda alt metni yok',seo_thin_content:'İçerik çok kısa (300 kelimenin altı)',seo_noindex:'Sayfa arama motorlarından gizlenmiş (noindex)',seo_robots_blocks_all:'robots.txt tüm siteyi engelliyor',seo_missing_canonical:'Canonical bağlantısı yok',seo_missing_robots:'robots.txt yok',seo_missing_sitemap:'sitemap.xml yok',seo_not_https:'Site HTTPS kullanmıyor',seo_missing_viewport:'Mobil uyumluluk (viewport) etiketi yok',seo_missing_lang:'Sayfa dili (html lang) belirtilmemiş',seo_missing_favicon:'Favicon yok',seo_hreflang_no_default:'hreflang için x-default eksik',seo_missing_open_graph:'Open Graph etiketleri eksik (sosyal paylaşım)',seo_missing_twitter_card:'Twitter Card etiketi yok',seo_missing_structured_data:'Yapısal veri (JSON-LD) yok',
security_unreachable:'Siteye ulaşılamadı',security_not_https:'Site HTTPS kullanmıyor',security_hsts_short:'HSTS süresi çok kısa (en az 6 ay olmalı)',security_missing_hsts:'HSTS başlığı yok',security_missing_csp:'Content-Security-Policy yok',security_csp_unsafe:'CSP "unsafe-inline / unsafe-eval" içeriyor',security_missing_clickjacking:'Clickjacking koruması yok (X-Frame-Options)',security_missing_nosniff:'X-Content-Type-Options: nosniff yok',security_missing_referrer_policy:'Referrer-Policy yok',security_missing_permissions_policy:'Permissions-Policy yok',security_version_disclosure:'Sunucu yazılım sürümü başlıkta açık',security_no_https_redirect:'HTTP → HTTPS yönlendirmesi yok',security_mixed_content:'Karışık içerik (HTTPS sayfada HTTP kaynak)',security_cookie_flags:'Çerezlerde Secure / HttpOnly / SameSite eksik',security_cert_expiring:'SSL sertifikası yakında doluyor',security_tls_old:'Eski TLS sürümü kullanılıyor',
perf_unreachable:'Sayfaya ulaşılamadı',perf_slow_ttfb:'Sunucu yanıtı yavaş (TTFB 600 ms üzeri)',perf_very_slow_ttfb:'Sunucu yanıtı çok yavaş (TTFB 1,5 sn üzeri)',perf_slow_load:'Sayfa yüklenmesi 3 sn üzeri',perf_no_compression:'Sıkıştırma (gzip/brotli) kapalı',perf_no_http2:'HTTP/2 veya HTTP/3 desteği yok',perf_redirect_chain:'Çok fazla yönlendirme',perf_heavy_page:'Sayfa boyutu büyük (500 KB üzeri)',perf_render_blocking_scripts:'Sayfayı geciktiren (async/defer olmayan) scriptler var',perf_too_many_scripts:'Çok fazla harici script',perf_no_lazy_loading:'Görseller lazy-load kullanmıyor',perf_weak_caching:'Statik dosyalar için önbellek süresi kısa',perf_assets_not_compressed:'JS/CSS dosyaları sıkıştırılmamış',
uptime_down:'Site tüm denemelerde yanıt vermedi',uptime_intermittent:'Kesintili erişim: bazı denemeler başarısız',uptime_slow_response:'Ortalama yanıt süresi yavaş',uptime_high_p95:'En yavaş istekler çok yavaş (p95)',uptime_unstable_latency:'Gecikme dalgalı (kararsız)',uptime_slow_dns:'DNS çözümlemesi yavaş',uptime_slow_connect:'Bağlantı kurma süresi yavaş',
api_unreachable:'API\'ye ulaşılamadı',api_server_error:'API sunucu hatası (5xx) döndürüyor',api_error_status:'API hata kodu döndürüyor',api_slow_response:'Yanıt süresi yavaş',api_not_https:'API HTTPS kullanmıyor',api_cors_credentials:'CORS: kimlik bilgisiyle birlikte geniş origin izni (riskli)',api_missing_nosniff:'X-Content-Type-Options yok',api_missing_hsts:'HSTS başlığı yok',api_version_disclosure:'Sunucu sürüm bilgisi başlıkta açık',api_invalid_json:'Yanıt geçersiz JSON',api_not_json:'Yanıt JSON değil',api_no_rate_limit_headers:'Hız sınırı (rate-limit) başlıkları yok',api_error_not_json:'Hata yanıtları JSON formatında değil',api_no_versioning:'API sürümlemesi yok (/v1 gibi)',api_auth_required:'API kimlik doğrulama istiyor (401/403) — beklenen davranış olabilir',
mobile_invalid_target:'Geçersiz paket adı veya mağaza linki',mobile_not_found:'Uygulama mağazada bulunamadı',mobile_store_unavailable:'Mağaza yanıt vermedi',mobile_low_rating:'Puan 4,0\'ın altında',mobile_few_ratings:'Değerlendirme sayısı az (50\'nin altı)',mobile_stale:'Uygulama 1 yıldan uzun süredir güncellenmedi',mobile_aging:'Uygulama 6 aydan uzun süredir güncellenmedi',
repo_invalid_target:'Geçersiz depo adresi',repo_not_found:'Depo bulunamadı ya da özel (private)',repo_rate_limited:'GitHub hız sınırına takıldı — sonuç alınamadı',repo_api_error:'GitHub API hatası',repo_archived:'Depo arşivlenmiş',repo_inactive:'1 yıldan uzun süredir commit yok',repo_stale:'3 aydan uzun süredir commit yok',repo_no_license:'Lisans dosyası yok',repo_no_readme:'README yok',repo_no_contributing:'CONTRIBUTING / davranış kuralları yok',repo_many_open_issues:'Açık issue sayısı çok (100+)',repo_no_releases:'Yayınlanmış sürüm (release) yok',
brand_invalid_target:'Geçersiz alan adı',brand_base_not_registered:'Ana alan adı DNS\'te görünmüyor',brand_dns_unreliable:'DNS sorguları güvenilir sonuç vermedi'};
const EXPO={env:'.env dosyası dışarıdan okunabiliyor!',git:'.git klasörü açıkta!',gitconfig:'.git/config açıkta!',phpinfo:'phpinfo sayfası açık',dsstore:'.DS_Store dosyası açık',serverstatus:'Apache server-status sayfası açık',wpconfig:'wp-config yedeği açıkta!',sqldump:'Veritabanı yedeği (.sql) açıkta!',htpasswd:'.htpasswd dosyası açıkta!'};
const PORTN={21:'FTP',23:'Telnet',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',9200:'Elasticsearch',11211:'Memcached',27017:'MongoDB'};
function finT(f){
 const k=String(f).replace(/^finding_/,'').replace(/_(critical|warning|info)$/,'');let m;
 if(FT[k])return FT[k];
 if((m=k.match(/^web_status_(\d+)$/)))return'Site HTTP '+m[1]+' hata kodu döndürüyor';
 if((m=k.match(/^server_exposed_port_(\d+)$/)))return`Port ${m[1]} internete açık${PORTN[m[1]]?' ('+PORTN[m[1]]+')':''}`;
 if((m=k.match(/^security_exposed_(\w+)$/)))return EXPO[m[1]]||'Hassas dosya açıkta';
 if((m=k.match(/^brand_(\d+)_lookalike_registered$/)))return`${m[1]} benzer (yazım hatalı) alan adı başkası tarafından kayıtlı`;
 if((m=k.match(/^brand_(\d+)_tld_thirdparty$/)))return`${m[1]} farklı uzantı (TLD) başkası tarafından kayıtlı`;
 if((m=k.match(/^brand_(\d+)_tld_unprotected$/)))return`${m[1]} önemli uzantı henüz kayıt edilmemiş — satın almayı düşünün`;
 return k.replace(/_/g,' ');
}
const SL={PROTECTED:'KORUMALI',UNKNOWN:'BİLİNMİYOR',HEALTHY:'SAĞLIKLI',ACTIVE:'AKTİF',WARNING:'UYARI',CRITICAL:'KRİTİK',DOWN:'ERİŞİLEMİYOR',EXPIRED:'SÜRESİ DOLMUŞ',EXPIRING_SOON:'SÜRESİ YAKLAŞIYOR',ERROR:'HATA'};
const SCL={icerik:'İçerik',teknik:'Teknik',sosyal:'Sosyal/Yapı',basliklar:'Başlıklar',aktarim:'Aktarım',dosyalar:'Açık dosya',sunucu:'Sunucu',agi:'Ağ',sayfa:'Sayfa',erisim:'Erişim',gecikme:'Gecikme',guvenlik:'Güvenlik',tasarim:'Tasarım',yayin:'Yayın',kalite:'Kalite',bakim:'Bakım',topluluk:'Topluluk',overall:'Genel',security:'Güvenlik',seo:'SEO',performance:'Performans',dns:'DNS',email:'E-posta',renewal:'Yenileme',validity:'Geçerlilik',chainTrust:'Zincir',cost:'Maliyet',usage:'Kullanım'};
const isBad=s=>['CRITICAL','EXPIRED','DOWN','ERROR'].includes(s);
const isOk=s=>['ACTIVE','HEALTHY'].includes(s);
const tone=n=>n>=80?'ok':n>=50?'wn':'bd';
const col=n=>n>=80?'var(--ok)':n>=50?'var(--wn)':'var(--bad)';
const fmt=t=>t?new Date(t).toLocaleString('tr-TR',{dateStyle:'short',timeStyle:'short'}):'-';
const sc=a=>a.result?.healthScore;
const alerts=()=>S.assets.filter(a=>a.result&&(isBad(a.result.status)||(a.result.findings||[]).some(f=>sev(f)==='bd')||(sc(a)!=null&&sc(a)<(S.settings.alertBelow??50))));
const find=id=>S.assets.find(a=>a.id===id);
const ic=(n,s='')=>`<i data-lucide="${n}" ${s}></i>`;
function toast(m,t=''){const d=document.createElement('div');d.className='t '+t;d.textContent=m;$('#toast').append(d);setTimeout(()=>d.remove(),4200)}
const busy=b=>document.body.classList.toggle('busy',b);
const authH=async()=>{try{const t=window.dacToken?await window.dacToken():null;return t?{Authorization:'Bearer '+t}:{}}catch{return{}}};

/* ---------- tarama ---------- */
async function mock(a){
 await new Promise(r=>setTimeout(r,1200));
 let h=0;for(const ch of a.key)h=(h*31+ch.charCodeAt(0))>>>0;
 const score=55+h%41,f=[];if(score<85)f.push(`finding_${a.cat}_demo_warning`);
 return{assetType:CATS[a.cat].api,healthScore:score,status:score>=80?'HEALTHY':score>=50?'WARNING':'CRITICAL',findings:f,latencyMs:1200,
  commonAnalysis:{analyzerVersion:'demo',executionTimeMs:1200,scannedAt:new Date().toISOString(),score,target:a.target},
  specificAnalysis:{target:a.target,note:'DEMO veri — gerçek analiz için Ayarlar\'dan API adresi girin',scores:{overall:score}}};
}
async function runScan(a){
 const t0=Date.now(),api=apiUrl();let res;
 if(api){
  const target=URLCATS.includes(a.cat)?proto(a.target):a.target;
  const r=await fetch(api+'/api/scan',{method:'POST',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({assetId:a.id,type:CATS[a.cat].api,targetUrl:target,name:a.name,extra:a.extra||{}})});
  let j;try{j=await r.json()}catch{throw new Error('Sunucu geçersiz yanıt verdi ('+r.status+'). Render uyanıyor olabilir, 30 sn sonra tekrar deneyin.')}
  if(r.status===402){location.hash='plan';throw new Error(j.error||'Paket gerekli')}
  if(!j.success)throw new Error(j.error||'Tarama başarısız');res=j.result;
 }else res=await mock(a);
 a.result=res;a.lastScan=Date.now();
 S.scans.unshift({id:uid(),assetId:a.id,name:a.name,cat:a.cat,score:res.healthScore,status:res.status,at:Date.now(),ms:Date.now()-t0,mock:!api});
 S.scans=S.scans.slice(0,planState().p.history||300);save();
}
async function rescan(id,open){
 const a=find(id);if(!a||!gate())return;busy(true);
 try{await runScan(a)}catch(e){toast('Tarama hatası: '+e.message,'err')}
 busy(false);render();if(open&&a.result)showDetail(id);
}
async function addAndScan(cat,raw,extra={},name=''){
 const target=String(cat==='saas'?(extra.provider||raw):raw).trim();
 if(!target)return toast('Hedef boş olamaz','err');
 if(!gate())return;
 const key=normKey(cat,target),ex=S.assets.find(a=>a.cat===cat&&a.key===key);
 if(ex){toast('Bu varlık zaten ekli, yeniden taranıyor','warn');return rescan(ex.id,true)}
 const ps=planState();
 if(S.assets.length>=limitOf(ps)){toast(`${ps.p.name} paketinde en fazla ${limTxt(ps)} varlık eklenebilir. Paket sayfasından yükseltin.`,'err');location.hash='plan';return}
 const a={id:uid(),cat,target,key,name:name||target,extra,createdAt:Date.now()};
 S.assets.push(a);save();render();await rescan(a.id,true);
}

/* ---------- ortak parçalar ---------- */
function assetRow(a){
 const s=sc(a),st=a.result?.status;
 return`<div class="item"><div class="ico" style="color:${CATS[a.cat].c}">${ic(CATS[a.cat].icon)}</div>
 <div class="g"><b>${esc(a.name)}</b><span>${CATS[a.cat].label} • ${a.lastScan?fmt(a.lastScan):'taranmadı'}</span></div>
 ${s!=null?`<span class="badge ${tone(s)}">${s}/100</span>`:`<span class="badge mu">${st?(SL[st]||'?'):'-'}</span>`}
 <div class="acts"><button class="btn s" data-act="detail" data-id="${a.id}">Detay</button><button class="btn s" data-act="rescan" data-id="${a.id}">${ic('refresh-cw')}</button><button class="btn s d" data-act="del" data-id="${a.id}">${ic('trash-2')}</button></div></div>`;
}
const scanRow=s=>`<div class="item"><div class="ico" style="color:${CATS[s.cat]?.c}">${ic(CATS[s.cat]?.icon||'scan')}</div><div class="g"><b>${esc(s.name)}</b><span>${fmt(s.at)} • ${s.ms}ms${s.mock?' • demo':''}</span></div>${s.score!=null?`<span class="badge ${tone(s.score)}">${s.score}/100</span>`:`<span class="badge mu">${SL[s.status]||'?'}</span>`}</div>`;
const stat=(i,n,l,h,c)=>`<div class="card stat"><div class="top"><div class="ico" style="color:${c}">${ic(i)}</div><span class="tag">LIVE</span></div><div class="num">${n}</div><div class="lbl">${l}</div><div class="hint">${h}</div></div>`;
function planBanner(){
 const ps=planState();
 if(ps.expired)return`<div class="card banner bad"><div><b>Deneme süreniz doldu</b><div class="hint">Verileriniz duruyor; yeni tarama için bir paket seçin. En düşük paket: Freelance (${money(P.PLANS.freelance.priceTRY,'TRY')} / ay).</div></div><a class="btn p" href="#plan">Paketleri gör</a></div>`;
 if(ps.trial)return`<div class="card banner"><div><b>Ücretsiz deneme: ${leftTxt(ps.left)} kaldı</b><div class="hint">${S.assets.length}/${limTxt(ps)} varlık hakkı kullanıldı. Deneme bitince bir paket seçmeniz gerekir.</div></div><a class="btn" href="#plan">Paketleri gör</a></div>`;
 return'';
}
function renewItems(){
 const out=[];
 for(const a of S.assets){const r=a.result;if(!r)continue;const sa=r.specificAnalysis||{};
  if(['domain','email'].includes(a.cat)&&sa.registration?.expiresAt)out.push({a,kind:'Domain bitişi',at:new Date(sa.registration.expiresAt).getTime()});
  if(a.cat==='ssl'&&sa.cert?.validTo)out.push({a,kind:'SSL bitişi',at:new Date(sa.cert.validTo).getTime()});
  if(a.cat==='saas'&&(a.extra?.renewalDate||sa.renewalDate))out.push({a,kind:'Abonelik yenileme',at:new Date(a.extra?.renewalDate||sa.renewalDate).getTime(),cost:a.extra?.cost,cur:a.extra?.currency||'TRY'});
 }
 return out.filter(x=>!isNaN(x.at)).sort((x,y)=>x.at-y.at);
}
const dayTone=d=>d<=7?'bd':d<=30?'wn':'ok';
const renewRow=x=>{const d=Math.ceil((x.at-Date.now())/864e5);return`<div class="item"><div class="ico" style="color:${CATS[x.a.cat].c}">${ic(CATS[x.a.cat].icon)}</div><div class="g"><b>${esc(x.a.name)}</b><span>${x.kind} • ${new Date(x.at).toLocaleDateString('tr-TR')}${x.cost?' • '+sym(+x.cost,x.cur):''}</span></div><span class="badge ${dayTone(d)}">${d<0?Math.abs(d)+' gün geçti':d+' gün'}</span></div>`};
const costTotals=()=>{const t={};S.assets.filter(a=>a.cat==='saas'&&a.extra?.cost).forEach(a=>{const c=a.extra.currency||'TRY';t[c]=(t[c]||0)+ +a.extra.cost});return t};
const sym=(n,c)=>c==='TRY'?n.toLocaleString('tr-TR',{maximumFractionDigits:2})+' ₺':c==='EUR'?'€'+n.toLocaleString('en-US',{maximumFractionDigits:2}):'$'+n.toLocaleString('en-US',{maximumFractionDigits:2});

/* ---------- sayfalar ---------- */
function dash(){
 const A=S.assets,scored=A.filter(a=>sc(a)!=null),avg=scored.length?Math.round(scored.reduce((t,a)=>t+sc(a),0)/scored.length):0;
 const crit=A.reduce((t,a)=>t+(a.result?.findings||[]).filter(f=>sev(f)==='bd').length,0);
 const m30=S.scans.filter(s=>Date.now()-s.at<2592e6).length,ok=A.filter(a=>isOk(a.result?.status)).length;
 const al=alerts(),ps=planState(),rn=renewItems().filter(x=>x.at-Date.now()<60*864e5).slice(0,3);
 return`<h2>Genel Bakış</h2><p class="sub">Tüm dijital varlıklar tek merkezde</p>${planBanner()}
 <div class="grid">${stat('database',A.length,'Toplam Varlık',`${A.length}/${limTxt(ps)} kullanımda`,'#8b9bb8')}
 ${stat('activity',m30,'Tarama Sayısı','Son 30 gün','#8b9bb8')}
 ${stat('shield-alert',crit,'Sorun Tespit',crit?`${crit} kritik`:'Kritik değil','#f59e0b')}
 ${stat('bar-chart-3',avg,'Ortalama Skor',scored.length?'Tüm varlıklar':'Henüz veri yok','#8b9bb8')}
 ${stat('circle-check',ok,'Çalışan Varlıklar','Aktif','#10b981')}</div>
 <div class="card" style="margin-top:14px"><div class="item" style="border:0"><div class="ico" style="color:var(--bl)">${ic('zap')}</div><div class="g"><b style="font-size:18px">Hızlı Tarama</b><span style="white-space:normal">Domain veya URL girin, kategori seçin ve tarayın${apiUrl()?'':' • demo mod'}</span></div></div>
 <form data-form="quick"><input class="field" name="t" placeholder="örn: google.com veya https://ornek.com" autocomplete="off"><select class="field" name="c">${GROUPS.map(([g,l])=>`<optgroup label="${l}">${Object.entries(CATS).filter(([,v])=>v.g===g).map(([k,v])=>`<option value="${k}">${v.label}</option>`).join('')}</optgroup>`).join('')}</select>
 <button class="btn p w" type="submit">${ic('scan-search')} Tara</button></form>
 <div class="chips" style="margin-top:14px">ÖNERİ: ${['google.com','github.com','vercel.com'].map(d=>`<button class="chip" data-act="sug" data-v="${d}">${d}</button>`).join('')}</div>
 <div class="hint" style="margin-top:10px">• aynı varlık tekrar eklenmez • duplicate engelleme aktif</div></div>
 <div class="card"><div class="mh"><b>${ic('triangle-alert','style="color:var(--wn)"')} Aktif Uyarılar</b><span class="badge mu">${al.length}</span></div>
 ${al.length?al.slice(0,6).map(assetRow).join(''):`<div class="empty">${ic('circle-check')}<br>Aktif uyarı yok</div>`}</div>
 ${rn.length?`<div class="card"><div class="mh"><b>${ic('calendar-clock','style="color:var(--bl)"')} Yaklaşan Yenilemeler</b><a class="btn s" href="#renewals">Tümü</a></div>${rn.map(renewRow).join('')}</div>`:''}
 <div class="card"><div class="mh"><b>${ic('clock')} Son Taramalar</b></div>${S.scans.length?S.scans.slice(0,5).map(scanRow).join(''):`<div class="empty"><b style="color:var(--tx)">Henüz tarama yok</b><br><span class="hint">Tarama geçmişi burada kronolojik listelenecek</span></div>`}</div>
 <div class="mh" style="margin-top:24px"><b style="font-size:18px">${ic('layers','style="color:var(--bl)"')} Tüm Tarama Araçları</b><span class="hint">${Object.keys(CATS).length} kategori</span></div>
 ${GROUPS.map(([g,l])=>`<h6 class="gh">${l}</h6><div class="tools">${Object.entries(CATS).filter(([,v])=>v.g===g).map(([k,v])=>`<a class="tool" href="#cat/${k}"><div class="ico" style="color:${v.c}">${ic(v.icon)}</div><h3 style="margin:12px 0 0;font-size:17px">${v.label}</h3><p>${v.desc}</p><div class="bar" style="--c:${v.c}"></div></a>`).join('')}</div>`).join('')}`;
}
function catPage(k){
 const v=CATS[k],list=S.assets.filter(a=>a.cat===k);
 const form=k==='saas'?`<form data-form="add" data-cat="${k}"><input class="field" name="provider" placeholder="Sağlayıcı (ör: Notion)" required>
 <div class="row2"><input class="field" name="plan" placeholder="Plan (ör: Pro)"><input class="field" name="cost" type="number" min="0" step="any" placeholder="Aylık maliyet"></div>
 <div class="row2"><select class="field" name="currency"><option value="TRY">₺ TRY</option><option value="USD">$ USD</option><option value="EUR">€ EUR</option></select><input class="field" name="usagePercent" type="number" min="0" max="100" placeholder="Kullanım %"></div>
 <label class="hint">Yenileme tarihi</label><input class="field" name="renewalDate" type="date">
 <button class="btn p w" type="submit">${ic('plus')} Ekle ve Tara</button></form>`
 :`<form data-form="add" data-cat="${k}"><input class="field" name="t" placeholder="${v.ph}" required autocomplete="off"><input class="field" name="name" placeholder="Görünen ad (opsiyonel)"><button class="btn p w" type="submit">${ic('plus')} Ekle ve Tara</button></form>`;
 return`<h2>${v.label}</h2><p class="sub">${v.desc}</p>
 <div class="card info"><b>${ic('list-checks','style="color:'+v.c+'"')} Ne taranır?</b><ul class="ul">${v.what.map(x=>`<li>${x}</li>`).join('')}</ul><div class="why"><b>Neden önemli?</b> ${v.why}</div>${v.hint?`<div class="hint" style="margin-top:8px">${ic('info')} ${v.hint}</div>`:''}</div>
 <div class="card"><b>Yeni ${v.label} ekle</b><div style="height:12px"></div>${form}</div>
 <div class="card"><div class="mh"><b>Varlıklar</b><span class="badge mu">${list.length}</span></div>${list.length?list.map(assetRow).join(''):`<div class="empty">Bu kategoride henüz varlık yok</div>`}</div>`;
}
function assets(){const q=($('#q')?.value||'').toLowerCase();const l=S.assets.filter(a=>!q||(a.name+a.target).toLowerCase().includes(q));
 return`<h2>Varlıklarım</h2><p class="sub">${S.assets.length} varlık</p><div class="card">${l.length?l.map(assetRow).join(''):`<div class="empty">Varlık yok. Sol menüden bir kategori seçip ekleyin.</div>`}</div>`}
function history(){return`<div class="mh"><div><h2>Tarama Geçmişi</h2><p class="sub">${S.scans.length} kayıt • bu pakette son ${planState().p.history}</p></div>${S.scans.length?`<button class="btn s d" data-act="clearhist">Temizle</button>`:''}</div><div class="card">${S.scans.length?S.scans.map(scanRow).join(''):`<div class="empty">Henüz tarama yok</div>`}</div>`}
function renewals(){
 const l=renewItems(),tot=costTotals();
 return`<h2>Yenileme Takvimi</h2><p class="sub">Domain, SSL ve abonelik bitiş tarihleri tek listede</p>
 ${Object.keys(tot).length?`<div class="card"><b>Abonelik maliyeti (aylık, girilen tutarlar)</b><div class="chips" style="margin-top:10px">${Object.entries(tot).map(([c,n])=>`<span class="badge ok">${sym(n,c)} / ay</span><span class="badge mu">${sym(n*12,c)} / yıl</span>`).join('')}</div></div>`:''}
 <div class="card">${l.length?l.map(renewRow).join(''):`<div class="empty">Henüz tarih bilgisi yok.<br><span class="hint">Domain ve SSL varlıklarını tarayın ya da SaaS aboneliklerine yenileme tarihi girin.</span></div>`}</div>`;
}
function reports(){
 const rows=Object.entries(CATS).map(([k,v])=>{const l=S.assets.filter(a=>a.cat===k);if(!l.length)return'';const s=l.filter(a=>sc(a)!=null);return`<tr><td>${v.label}</td><td>${l.length} varlık</td><td>${s.length?Math.round(s.reduce((t,a)=>t+sc(a),0)/s.length):'-'}</td></tr>`}).join('');
 const tot=costTotals(),worst=S.assets.filter(a=>sc(a)!=null).sort((x,y)=>sc(x)-sc(y)).slice(0,5);
 return`<h2>Raporlar</h2><p class="sub">Kategori bazlı özet</p>
 <div class="card">${rows?`<table><tr><td>Kategori</td><td>Adet</td><td>Ort. skor</td></tr>${rows}</table>`:'<div class="empty">Henüz varlık yok</div>'}</div>
 ${worst.length?`<div class="card"><b>Dikkat gerektiren varlıklar</b>${worst.map(assetRow).join('')}</div>`:''}
 ${Object.keys(tot).length?`<div class="card"><b>Abonelik maliyeti</b><div class="chips" style="margin-top:10px">${Object.entries(tot).map(([c,n])=>`<span class="badge ok">${sym(n,c)} / ay</span><span class="badge mu">${sym(n*12,c)} / yıl</span>`).join('')}</div></div>`:''}
 <div class="acts"><button class="btn" data-act="csv">${ic('download')} CSV indir</button><button class="btn" data-act="json">${ic('download')} JSON indir</button><button class="btn" onclick="print()">${ic('printer')} Yazdır</button></div>`}
function listPage(k){const L=LISTS[k],ps=planState(),lim=k==='team'?ps.p.team:null;
 return`<h2>${L.title}</h2><p class="sub">${S[k].length} kayıt${lim?` • bu pakette en fazla ${lim}`:''}</p><div class="card"><form data-form="list" data-k="${k}">${L.f.map(([n,p],i)=>`<input class="field" name="${n}" placeholder="${p}" ${i?'':'required'}>`).join('')}<button class="btn p w" type="submit">${ic('plus')} Ekle</button></form></div>
 <div class="card">${S[k].length?S[k].map(x=>`<div class="item"><div class="ico">${ic(L.icon)}</div><div class="g"><b>${esc(x[L.f[0][0]])}</b><span>${L.f.slice(1).map(([n])=>esc(x[n])).filter(Boolean).join(' • ')}</span></div><button class="btn s d" data-act="dellist" data-k="${k}" data-id="${x.id}">${ic('trash-2')}</button></div>`).join(''):`<div class="empty">Kayıt yok</div>`}</div>`}

/* ---------- paket sayfası ---------- */
function plan(){
 const st=S.settings,ps=planState(),cur=st.currency||'TRY',cyc=st.cycle||'monthly',alt=cur==='TRY'?'USD':'TRY';
 if(!PAYCFG&&!HEALTH_TRIED&&apiUrl()){HEALTH_TRIED=true;fetchHealth().then(()=>{if(location.hash==='#plan')render()})}
 const status=ps.paid?`<span class="badge ok">${ps.p.name} aktif</span>${st.planEnd?` <span class="hint">bitiş: ${new Date(st.planEnd).toLocaleDateString('tr-TR')}</span>`:''}`
  :ps.trial?`<span class="badge wn">Ücretsiz deneme: ${leftTxt(ps.left)} kaldı</span>`:`<span class="badge bd">Deneme süresi doldu</span>`;
 const ready=c=>!PAYCFG||(c==='TRY'?PAYCFG.iyzico:PAYCFG.stripe);
 const cards=P.PAID.map(id=>{const p=P.PLANS[id],main=P.price(id,cur,cyc),a2=P.price(id,alt,cyc),isCur=ps.paid&&ps.id===id;
  const btn=!ready(cur)?`<button class="btn w" disabled>${cur==='TRY'?'TL':'USD'} ödeme yakında</button>`:`<button class="btn p w" data-act="buy" data-p="${id}">${isCur?'Süreyi uzat':ps.paid?'Bu pakete geç':'Satın al'}</button>`;
  return`<div class="card plan ${isCur?'on':''}">${p.popular?'<span class="badge ok pop">Popüler</span>':''}<h3>${p.name}</h3><div class="hint">${p.audience}</div>
  <div class="price">${money(main,cur)}<small> / ${cyc==='yearly'?'yıl':'ay'}</small></div><div class="hint">≈ ${money(a2,alt)} / ${cyc==='yearly'?'yıl':'ay'}</div>
  <ul class="ul">${p.features.map(f=>`<li>${f}</li>`).join('')}</ul>${btn}</div>`}).join('');
 return`<h2>Paket ve Faturalandırma</h2><p class="sub">${status} • ${S.assets.length}/${limTxt(ps)} varlık</p>
 ${ps.trial||ps.expired?`<div class="card banner ${ps.expired?'bad':''}"><div><b>${ps.expired?'Deneme süreniz doldu':'Ücretsiz deneme'}</b><div class="hint">${P.TRIAL_DAYS} gün ücretsiz, ${P.PLANS.trial.assets} varlık hakkı. Sonrasında en az Freelance paketini seçmeniz gerekir.</div></div></div>`:''}
 <div class="card"><div class="row2"><div><div class="hint">Para birimi / ödeme yöntemi</div><div class="seg"><button class="${cur==='TRY'?'on':''}" data-act="cur" data-v="TRY">₺ TL</button><button class="${cur==='USD'?'on':''}" data-act="cur" data-v="USD">$ USD</button></div></div>
 <div><div class="hint">Faturalama dönemi</div><div class="seg"><button class="${cyc==='monthly'?'on':''}" data-act="cycle" data-v="monthly">Aylık</button><button class="${cyc==='yearly'?'on':''}" data-act="cycle" data-v="yearly">Yıllık (2 ay bedava)</button></div></div></div></div>
 <div class="plans">${cards}</div>
 <p class="hint">${cur==='TRY'?'TL ödemeleri iyzico ile alınır; kart bilgisi bu sitede saklanmaz. Süre dolmadan yeniden satın alarak uzatabilirsiniz. Ödeme için Ayarlar > Fatura Bilgileri doldurulmalıdır.':'USD ödemeleri Stripe ile alınır, abonelik otomatik yenilenir ve istediğiniz zaman iptal edilebilir.'}</p>
 ${ps.paid&&st.provider==='stripe'?`<button class="btn" data-act="portal">${ic('credit-card')} Aboneliği yönet / iptal et</button>`:''}
 <button class="btn" data-act="syncplan" style="margin-top:8px">${ic('refresh-cw')} Ödememi kontrol et</button>`;
}

/* ---------- ayarlar ---------- */
const standalone=()=>matchMedia('(display-mode: standalone)').matches||navigator.standalone;
function settings(){
 const s=S.settings,b=s.billing||{},ps=planState(),kb=Math.round(JSON.stringify(S).length/1024);
 const f=(n,l,ph='',t='text')=>`<label class="hint">${l}</label><input class="field" name="${n}" type="${t}" value="${esc(b[n])}" placeholder="${ph}">`;
 return`<h2>Ayarlar</h2><p class="sub">Hesap, fatura, bağlantı ve veri yönetimi</p>
 <div class="card"><b>${ic('user-round')} Hesap</b><div class="item" style="border:0">${U?.photoURL?`<img class="pfp" src="${esc(U.photoURL)}" alt="">`:`<div class="ico">${ic('user-round')}</div>`}<div class="g"><b>${esc(U?.displayName||'Kullanıcı')}</b><span>${esc(U?.email||'')}</span></div></div>
 <div class="hint">Son giriş: ${U?.metadata?.lastSignInTime?fmt(U.metadata.lastSignInTime):'-'} • Paket: ${esc(planName(ps))}</div>
 <div class="acts" style="margin-top:12px"><button class="btn s" data-act="copyuid">${ic('copy')} Kullanıcı ID kopyala</button><button class="btn s" data-act="logout">${ic('log-out')} Çıkış yap</button></div></div>
 <div class="card"><form data-form="settings"><b>${ic('building-2')} Organizasyon ve uyarılar</b><div style="height:10px"></div>
 <label class="hint">Organizasyon adı</label><input class="field" name="org" value="${esc(s.org)}" required>
 <label class="hint">Uyarı eşiği: skoru bunun altında kalan varlıklar "Aktif Uyarılar"a düşer</label><input class="field" name="alertBelow" type="number" min="10" max="95" value="${s.alertBelow??50}">
 <label class="hint">Scanner API adresi (boşsa demo mod)</label><input class="field" name="apiUrl" value="${esc(s.apiUrl)}" placeholder="${esc((window.DAC_CONFIG||{}).API_URL||'https://scanner.onrender.com')}">
 <button class="btn p w" type="submit">Kaydet</button></form>
 <div class="acts" style="margin-top:10px"><button class="btn s" data-act="ping">${ic('plug-zap')} Bağlantıyı test et</button></div><div class="hint" id="pingres" style="margin-top:8px"></div></div>
 <div class="card"><form data-form="billing"><b>${ic('receipt')} Fatura bilgileri</b><div class="hint">TL ödemesi (iyzico) için ad soyad, adres ve şehir zorunludur.</div><div style="height:10px"></div>
 ${f('name','Ad Soyad','Ali Veli')}${f('company','Şirket ünvanı (opsiyonel)')}
 <div class="row2"><div>${f('email','Fatura e-postası','fatura@sirket.com','email')}</div><div>${f('phone','Telefon','+90 5xx xxx xx xx','tel')}</div></div>
 ${f('taxId','TC Kimlik / Vergi No','11 haneli')}${f('address','Adres','Mahalle, cadde, no')}
 <div class="row2"><div>${f('city','Şehir','İstanbul')}</div><div>${f('zip','Posta kodu')}</div></div>
 ${f('country','Ülke','Turkey')}
 <button class="btn p w" type="submit">Fatura bilgilerini kaydet</button></form></div>
 <div class="card"><b>${ic('smartphone')} Uygulama (PWA)</b><div class="hint" style="margin:6px 0 10px">${standalone()?'Uygulama olarak çalışıyor.':DEFERRED?'Ana ekrana yükleyerek uygulama gibi kullanabilirsiniz.':'Tarayıcı menüsünden "Uygulamayı yükle / Ana ekrana ekle" seçeneğini kullanın.'}</div>
 <div class="acts">${DEFERRED&&!standalone()?`<button class="btn p" data-act="install">${ic('download')} Uygulamayı yükle</button>`:''}<button class="btn" data-act="clearcache">${ic('refresh-cw')} Önbelleği temizle ve yenile</button></div></div>
 <div class="card"><b>${ic('database')} Veri yönetimi</b><div class="hint" style="margin:6px 0 10px">${S.assets.length} varlık • ${S.scans.length} tarama kaydı • ~${kb} KB (yalnızca bu cihazda saklanır)</div>
 <div class="acts"><button class="btn" data-act="backup">${ic('download')} Yedek indir</button><button class="btn" data-act="import">${ic('upload')} Yedekten yükle</button></div><input type="file" id="imp" accept="application/json" hidden></div>
 <div class="card"><b style="color:var(--bad)">${ic('triangle-alert')} Tehlikeli bölge</b><div class="hint" style="margin:6px 0 10px">Bu cihazdaki tüm varlık, tarama ve ayarlar silinir.</div><button class="btn d" data-act="wipe">${ic('trash-2')} Tüm verileri sil</button></div>
 <div class="hint">Sürüm v11 • ${esc(U?.uid||'')}</div>`;
}

/* ---------- ödeme ve abonelik ---------- */
async function fetchHealth(){const api=apiUrl();if(!api)return null;try{const j=await (await fetch(api+'/health')).json();PAYCFG=j.payments||null;return j}catch{return null}}
async function syncPlan(){
 const api=apiUrl();if(!api||!U)return null;
 try{
  const h=await authH();if(!h.Authorization)return null;
  const r=await fetch(api+'/api/subscription',{headers:h}),j=await r.json();if(!r.ok||!j.success)return null;
  const st=S.settings;
  if(P.PAID.includes(j.plan)){st.plan=j.plan;st.planEnd=j.periodEnd||null;st.provider=j.provider||null}
  else{st.plan='trial';st.planEnd=null;st.provider=null}
  if(j.trialStart)st.trialStart=j.trialStart;
  save();render();return j.plan;
 }catch{return null}
}
async function checkout(plan){
 const st=S.settings,cur=st.currency||'TRY',api=apiUrl();
 if(!api)return toast('Önce Ayarlar\'dan Scanner API adresini girin','err');
 const b=st.billing||{};
 if(cur==='TRY'&&(!b.name||!b.address||!b.city)){toast('TL ödemesi için önce Fatura Bilgilerini doldurun','warn');location.hash='settings';return}
 busy(true);
 try{
  const r=await fetch(api+'/api/checkout',{method:'POST',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({plan,cycle:st.cycle||'monthly',currency:cur,billing:b,returnPath:location.pathname})});
  const j=await r.json();if(!j.success||!j.url)throw new Error(j.error||'Ödeme sayfası alınamadı');
  location.href=j.url;
 }catch(e){toast(e.message,'err')}
 busy(false);
}
async function portal(){
 const api=apiUrl();busy(true);
 try{const r=await fetch(api+'/api/billing-portal',{method:'POST',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({returnPath:location.pathname})});const j=await r.json();if(!j.success)throw new Error(j.error);location.href=j.url}
 catch(e){toast(e.message,'err')}busy(false);
}
function handleReturn(){
 const p=new URLSearchParams(location.search).get('paid');if(p===null)return;
 history.replaceState(null,'',location.pathname+'#plan');
 if(p!=='1')return toast('Ödeme tamamlanmadı','warn');
 toast('Ödeme alındı, paketiniz etkinleştiriliyor…');
 let n=0;const t=setInterval(async()=>{n++;await syncPlan();if(P.PAID.includes(S.settings.plan)||n>=8){clearInterval(t);if(P.PAID.includes(S.settings.plan))toast('Paketiniz etkinleştirildi')}},3000);
}
async function ping(){
 const el=$('#pingres'),api=apiUrl();if(!el)return;
 if(!api){el.textContent='API adresi yok (demo mod).';return}
 el.textContent='Bağlanıyor…';const t0=Date.now(),j=await fetchHealth(),ms=Date.now()-t0;
 el.textContent=j?`✔ Bağlandı (${ms} ms) • sürüm ${j.version} • ${j.types?.length} tarama türü • Firebase: ${j.firestore?'bağlı':'yok'} • TL ödeme: ${j.payments?.iyzico?'hazır':'yok'} • USD ödeme: ${j.payments?.stripe?'hazır':'yok'}`:'✘ Bağlanılamadı. Adresi kontrol edin; Render uyanıyor olabilir, 30 sn sonra tekrar deneyin.';
}
async function clearCache(){
 try{const rs=await navigator.serviceWorker?.getRegistrations();for(const r of rs||[])await r.unregister();for(const k of await caches.keys())await caches.delete(k)}catch{}
 location.reload();
}
addEventListener('beforeinstallprompt',e=>{e.preventDefault();DEFERRED=e;if(S&&location.hash==='#settings')render()});
addEventListener('appinstalled',()=>{DEFERRED=null;toast('Uygulama yüklendi');if(S)render()});

/* ---------- detay penceresi ---------- */
function flat(o,p='',d=0,out=[]){
 if(o==null||typeof o!=='object'){out.push([p,o]);return out}
 if(Array.isArray(o)){if(o.every(x=>x==null||typeof x!=='object'))out.push([p,o.join(', ')]);else if(d<3)o.slice(0,8).forEach((x,i)=>flat(x,`${p}[${i}]`,d+1,out));return out}
 for(const k in o){if(k==='debug'||k==='scores'||out.length>90)continue;flat(o[k],p?`${p}.${k}`:k,d+1,out)}return out}
function showDetail(id){
 const a=find(id);if(!a)return;const r=a.result;
 let h=`<div class="mh"><div><h2 style="margin:0">${esc(a.name)}</h2><span class="hint">${CATS[a.cat].label} • ${esc(a.target)}</span></div><button class="btn s" data-act="close">${ic('x')}</button></div>`;
 if(!r)h+=`<div class="empty">Henüz taranmadı</div><button class="btn p w" data-act="rescan" data-id="${id}">Tara</button>`;
 else{
  const s=r.healthScore??0,noScore=r.healthScore==null,sa=r.specificAnalysis||{},ca=r.commonAnalysis||{};
  h+=`<div class="card" style="display:flex;gap:16px;align-items:center"><div class="ring" style="--p:${noScore?0:s};--rc:${noScore?'var(--mu)':col(s)}"><span>${noScore?'?':s}</span></div><div><span class="badge ${isBad(r.status)?'bd':isOk(r.status)?'ok':'wn'}">${SL[r.status]||esc(r.status)}</span><div class="hint">Son tarama: ${fmt(a.lastScan)}<br>${esc(ca.analyzerVersion||'')} • ${ca.executionTimeMs??r.latencyMs??'-'}ms</div></div></div>`;
  const sco=Object.entries(sa.scores||{}).filter(([,v])=>typeof v==='number');
  if(sco.length)h+=`<div class="card"><b>Skorlar</b>${sco.map(([k,v])=>`<div class="sc" style="--rc:${col(v)}"><span>${esc(SCL[k]||k)}</span><i><u style="width:${Math.min(100,v)}%"></u></i><span>${v}</span></div>`).join('')}</div>`;
  const f=r.findings||[];
  h+=`<div class="card"><b>Bulgular (${f.length})</b>${f.length?f.map(x=>`<div class="find"><span class="badge ${sev(x)}">${sevL[sev(x)]}</span><span>${esc(finT(x))}</span></div>`).join(''):'<div class="hint">Sorun bulunmadı</div>'}</div>`;
  h+=`<div class="card"><b>Detaylı analiz</b><table>${flat(sa).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v===true?'evet':v===false?'hayır':v??'-')}</td></tr>`).join('')}</table><details><summary>Ham veri (JSON)</summary><pre>${esc(JSON.stringify(r,null,2))}</pre></details></div>
  <button class="btn p w" data-act="rescan" data-id="${id}">${ic('refresh-cw')} Yeniden Tara</button>`;
 }
 $('#box').innerHTML=h;$('#modal').classList.add('on');icons();
}

/* ---------- ana render ---------- */
const NAV=()=>[['GENEL',[['dash','Genel Bakış','layout-grid']]],...GROUPS.map(([g,l])=>[l,Object.entries(CATS).filter(([,v])=>v.g===g).map(([k,v])=>['cat/'+k,v.label,v.icon])]),
 ['YÖNETİM',[['assets','Varlıklarım','database'],['history','Tarama Geçmişi','history'],['renewals','Yenileme Takvimi','calendar-clock'],['reports','Raporlar','bar-chart-3'],['team','Ekip Yönetimi','users'],['projects','Müşteri Projeleri','briefcase'],['plan','Paket ve Faturalandırma','credit-card'],['settings','Ayarlar','settings']]]];
const icons=()=>window.lucide&&lucide.createIcons();
function render(){
 if(!S)return;
 const r=location.hash.slice(1)||'dash',[p,k]=r.split('/'),ps=planState();
 const counts={};Object.keys(CATS).forEach(c=>counts[c]=S.assets.filter(a=>a.cat===c).length);
 $('#side').innerHTML=`<div class="brand"><div class="logo">${ic('shield')}</div><div><b>Digital Asset Center</b><small>v11 • ${esc(planName(ps))}</small></div></div>
 <nav class="nav">${NAV().map(([t,it])=>`<h6>${t}</h6>`+it.map(([h,l,i])=>`<a href="#${h}" class="${h===r?'on':''}">${ic(i)}${l}${h.startsWith('cat/')?`<b>${counts[h.slice(4)]}</b>`:''}</a>`).join('')).join('')}</nav>
 <div class="org"><div class="orgc"><div class="r"><div class="av">${esc(S.settings.org.slice(0,2).toUpperCase())}</div><div><b>${esc(S.settings.org)}</b><br><small>${esc(planName(ps))} • ${S.assets.length}/${limTxt(ps)} varlık${ps.trial?' • '+leftTxt(ps.left):''}</small></div></div>
 <div class="btns"><a class="btn s" href="#settings">${ic('settings')} Ayarlar</a><button class="btn s" data-act="logout">${ic('log-out')} Çıkış</button></div></div></div>`;
 $('#av').textContent=S.settings.org.slice(0,2).toUpperCase();
 $('#dot').style.display=alerts().length?'block':'none';
 $('#view').innerHTML=p==='cat'&&CATS[k]?catPage(k):p==='assets'?assets():p==='history'?history():p==='reports'?reports():p==='renewals'?renewals():LISTS[p]?listPage(p):p==='plan'?plan():p==='settings'?settings():dash();
 icons();
}

/* ---------- olaylar ---------- */
const close=()=>{$('#modal').classList.remove('on');$('#side').classList.remove('open');$('#shade').classList.remove('on')};
const dl=(n,t,m)=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:m}));a.download=n;a.click()};
document.addEventListener('click',async e=>{
 const b=e.target.closest('[data-act]');
 if(!e.target.closest('.search'))$('#sres').classList.remove('on');
 if(!e.target.closest('.rel'))$('#bell').classList.remove('on');
 if(e.target.id==='modal')return close();
 if(e.target.id==='shade')return close();
 if(!b){if(e.target.closest('#side a'))close();return}
 const {act,id}=b.dataset,A=id&&find(id),st=S&&S.settings;
 if(act==='menu'){$('#side').classList.add('open');$('#shade').classList.add('on')}
 else if(act==='close')close();
 else if(act==='detail')showDetail(id);
 else if(act==='rescan')rescan(id,$('#modal').classList.contains('on'));
 else if(act==='del'){if(A&&confirm(`"${A.name}" silinsin mi?`)){S.assets=S.assets.filter(x=>x.id!==id);save();close();render();toast('Varlık silindi')}}
 else if(act==='sug'){const i=$('[name=t]');if(i)i.value=b.dataset.v}
 else if(act==='goto')location.hash=b.dataset.to;
 else if(act==='bell'){const al=alerts();$('#bell').innerHTML=al.length?al.map(a=>`<a data-act="detail" data-id="${a.id}">${ic('triangle-alert')} ${esc(a.name)} <span class="badge ${sc(a)!=null?tone(sc(a)):'bd'}">${sc(a)??'!'}</span></a>`).join(''):'<div class="it hint">Bildirim yok</div>';$('#bell').classList.toggle('on');icons()}
 else if(act==='clearhist'){S.scans=[];save();render()}
 else if(act==='cur'){st.currency=b.dataset.v;save();render()}
 else if(act==='cycle'){st.cycle=b.dataset.v;save();render()}
 else if(act==='buy')checkout(b.dataset.p);
 else if(act==='portal')portal();
 else if(act==='syncplan'){const p=await syncPlan();toast(p===null?'Sunucudan abonelik bilgisi alınamadı (API adresi ve Firebase yapılandırmasını kontrol edin)':P.PAID.includes(p)?'Paketiniz aktif: '+P.PLANS[p].name:'Aktif ücretli paket bulunamadı',p===null?'warn':'')}
 else if(act==='ping')ping();
 else if(act==='install'){if(DEFERRED){DEFERRED.prompt();await DEFERRED.userChoice;DEFERRED=null;render()}}
 else if(act==='clearcache')clearCache();
 else if(act==='copyuid'){try{await navigator.clipboard.writeText(U.uid);toast('Kopyalandı')}catch{toast(U.uid)}}
 else if(act==='dellist'){const k=b.dataset.k;S[k]=S[k].filter(x=>x.id!==id);save();render()}
 else if(act==='logout'){window.dacLogout&&window.dacLogout()}
 else if(act==='wipe'){if(confirm('Bu cihazdaki tüm veriler silinecek. Emin misiniz?')){localStorage.removeItem(KEY);location.hash='';location.reload()}}
 else if(act==='csv'){const q=v=>`"${String(v??'').replace(/"/g,'""')}"`;dl('varliklar.csv','\ufeff'+['Ad;Tür;Hedef;Skor;Durum;Son tarama',...S.assets.map(a=>[a.name,CATS[a.cat].label,a.target,sc(a)??'',SL[a.result?.status]||a.result?.status||'',fmt(a.lastScan)].map(q).join(';'))].join('\n'),'text/csv;charset=utf-8')}
 else if(act==='json')dl('varliklar.json',JSON.stringify(S.assets,null,2),'application/json');
 else if(act==='backup'){const {billing,plan,planEnd,trialStart,provider,...rest}=st;dl(`dac-yedek-${new Date().toISOString().slice(0,10)}.json`,JSON.stringify({version:11,exportedAt:new Date().toISOString(),assets:S.assets,scans:S.scans,team:S.team,projects:S.projects,settings:rest},null,2),'application/json')}
 else if(act==='import')$('#imp').click();
});
document.addEventListener('change',async e=>{
 if(e.target.id!=='imp'||!e.target.files[0])return;
 try{
  const d=JSON.parse(await e.target.files[0].text());
  if(!Array.isArray(d.assets))throw new Error('Geçersiz yedek dosyası');
  if(!confirm(`${d.assets.length} varlık yüklenecek, mevcut veriler değiştirilecek. Devam edilsin mi?`))return;
  S.assets=d.assets.filter(a=>a&&CATS[a.cat]);S.scans=Array.isArray(d.scans)?d.scans:[];S.team=Array.isArray(d.team)?d.team:[];S.projects=Array.isArray(d.projects)?d.projects:[];
  const s=d.settings||{};['org','apiUrl','alertBelow','currency','cycle'].forEach(k=>{if(s[k]!=null)S.settings[k]=s[k]});
  save();render();toast('Yedek yüklendi');
 }catch(err){toast(err.message||'Dosya okunamadı','err')}
 e.target.value='';
});
document.addEventListener('submit',e=>{
 const f=e.target.closest('[data-form]');if(!f)return;e.preventDefault();
 const d=Object.fromEntries(new FormData(f)),t=f.dataset.form;
 if(t==='quick')addAndScan(d.c,d.t,d.c==='saas'?{provider:d.t}:{});
 else if(t==='add'){const c=f.dataset.cat;if(c==='saas')addAndScan(c,d.provider,{provider:d.provider,plan:d.plan||'unknown',cost:+d.cost||0,currency:d.currency||'TRY',renewalDate:d.renewalDate||null,usagePercent:d.usagePercent?+d.usagePercent:undefined});else addAndScan(c,d.t,{},d.name)}
 else if(t==='list'){const k=f.dataset.k,n=LISTS[k].f[0][0],ps=planState();
  if(k==='team'&&ps.p.team!=null&&S.team.length>=ps.p.team)return toast(`${ps.p.name} paketinde en fazla ${ps.p.team} ekip kaydı eklenebilir`,'err');
  if(S[k].some(x=>String(x[n]).toLowerCase()===d[n].trim().toLowerCase()))return toast('Bu kayıt zaten var','warn');S[k].push({id:uid(),...d});save();render()}
 else if(t==='settings'){const s=S.settings;s.org=d.org.trim();s.apiUrl=d.apiUrl.trim();s.alertBelow=Math.min(95,Math.max(10,+d.alertBelow||50));PAYCFG=null;HEALTH_TRIED=false;save();render();toast('Kaydedildi')}
 else if(t==='billing'){const o={};for(const k in d)o[k]=String(d[k]).trim();S.settings.billing=o;save();toast('Fatura bilgileri kaydedildi')}
});
$('#q').addEventListener('input',e=>{
 const q=e.target.value.toLowerCase().trim(),r=$('#sres');
 const l=q?S.assets.filter(a=>(a.name+a.target).toLowerCase().includes(q)).slice(0,8):[];
 r.innerHTML=q?(l.length?l.map(a=>`<a data-act="detail" data-id="${a.id}">${esc(a.name)} <span class="hint">${CATS[a.cat].label}</span></a>`).join(''):'<div class="it hint">Sonuç yok</div>'):'';
 r.classList.toggle('on',!!q);
});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();$('#q').focus()}if(e.key==='Escape')close()});
addEventListener('hashchange',()=>{render();scrollTo(0,0)});
addEventListener('focus',()=>{if(S&&U&&apiUrl()&&!document.hidden)syncPlan()});

/* ---------- giriş (Firebase Auth index.html içinden çağırır) ---------- */
window.dacStart=u=>{
 U=u;KEY='dac_v1_'+u.uid;
 let raw=localStorage.getItem(KEY);
 if(!raw){const old=localStorage.getItem('dac_v1');if(old){raw=old;localStorage.setItem(KEY,old);localStorage.removeItem('dac_v1')}}
 S=JSON.parse(raw||'null')||blank();
 const st=S.settings=Object.assign({},blank().settings,S.settings||{});
 if(!P.PAID.includes(st.plan))st.plan='trial';   // eski yerel "free/pro" değerleri deneme sayılır
 st.billing=st.billing||{};
 save();render();syncPlan();handleReturn();
};
window.dacStop=()=>{S=null;U=null;close();$('#view').innerHTML='';location.hash=''};
