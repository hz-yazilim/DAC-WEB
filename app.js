/* Digital Asset Center v11 - veriler tarayıcıda (localStorage), tarama/ödeme için scanner API kullanılır */
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>{try{const a=new Uint32Array(3);crypto.getRandomValues(a);return Array.from(a,x=>x.toString(36)).join('').slice(0,16)+Date.now().toString(36)}catch{return Math.random().toString(36).slice(2,10)+Date.now().toString(36)}};
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
 what:['36 yaygın port (SSH, RDP, SMB, FTP, Telnet, Docker, Kubernetes…)','Veritabanı portları (MySQL, PostgreSQL, MongoDB, Redis…)','Bağlantı gecikmesi','Sunucunun konumu ve sağlayıcısı'],
 why:'İnternete açık bir veritabanı ya da RDP portu, fidye yazılımı saldırılarının en yaygın giriş kapısıdır.',
 hint:'Yalnızca bağlantı denenir ve karşılama (banner) satırı okunur; veri gönderilmez. Sadece kendi sunucularınızı tarayın.'},
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
analytics:{g:'perf',label:'Analitik (GA4)',icon:'bar-chart-3',c:'#f59e0b',api:'ANALYTICS',desc:'Google Analytics 4 / GTM etiket kurulumu ve ölçüm kimliği doğrulaması',ph:'ornek.com',
 what:['GA4 (gtag) veya Google Tag Manager etiketi sitede var mı?','Girdiğiniz Ölçüm Kimliği (G-XXXX) sitedeki etiketle eşleşiyor mu?','Eski Universal Analytics (UA-) kalıntısı','Etiket betiğine erişim'],
 why:'Yanlış ya da eksik etiket, reklam ve dönüşüm verisinin sessizce kaybolması demektir.',
 hint:'Canlı kullanıcı, çıkma oranı ve dönüşüm değerleri Google Analytics Data API yetkisi gerektirir; şu an boş (—) görünür.'},
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
const URLCATS=['web','api','seo','security','performance','uptime','analytics'];
const LISTS={
team:{title:'Ekip Yönetimi',icon:'users',f:[['name','Ad Soyad'],['email','Email'],['role','Rol']]},
projects:{title:'Müşteri Projeleri',icon:'briefcase',f:[['name','Proje adı'],['client','Müşteri'],['note','Not']]}
};
let KEY='dac_v1',S=null,U=null,PAYCFG=null,DEFERRED=null,HEALTH_TRIED=false;
const blank=()=>({assets:[],scans:[],team:[],projects:[],settings:{org:'',plan:'trial',apiUrl:'',trialStart:Date.now(),alertBelow:50,currency:/^tr/i.test(navigator.language)?'TRY':'USD',cycle:'monthly',billing:{}}});
const save=np=>{if(S){localStorage.setItem(KEY,JSON.stringify(S));if(!np)schedulePush()}};

/* ---------- bulut senkronu (users/{uid}/state/app, sunucu üzerinden) ----------
 * Yerel veri her zaman önce gelir; buluttan gelen veri ASLA silici değil BİRLEŞTİRİCİDİR (id'ye göre).
 * Silmeler "tomb" kayıtlarıyla taşınır. Birleştirme veriyi değiştirecekse önce yerel yedek alınır. İlk başarılı çekmeden önce bulut yazılmaz. */
const SYNC={ver:0,pulled:false,timer:null,busy:false,dirty:false,lastErr:0};
const syncReset=()=>{clearTimeout(SYNC.timer);Object.assign(SYNC,{ver:0,pulled:false,timer:null,busy:false,dirty:false})};
const syncSay=m=>{const n=Date.now();if(n-SYNC.lastErr>30000){SYNC.lastErr=n;toast(m,'warn')}};
function remotePayload(){
 const {plan,planEnd,provider,trialStart,apiUrl,...settings}=S.settings;
 let p={assets:S.assets,scans:S.scans,team:S.team,projects:S.projects,settings,settingsAt:S.settingsAt||0,tomb:S.tomb||{}};
 if(JSON.stringify(p).length>800000)p={...p,assets:p.assets.map(({result,...r})=>r)};
 if(JSON.stringify(p).length>800000)p={...p,scans:p.scans.slice(0,1000)};
 return p;
}
function mergeState(r){
 const now=Date.now(),T={};
 for(const [k,v] of Object.entries({...(r.tomb||{}),...(S.tomb||{})}))if(now-v<90*864e5)T[k]=v;
 S.tomb=T;
 const ts=x=>x.lastScan||x.createdAt||0;
 const uni=(a,b,newer)=>{const m=new Map();for(const x of [...a,...b]){if(!x||!x.id||T[x.id])continue;const o=m.get(x.id);if(!o||newer(x,o)&&x!==o)m.set(x.id,x)}return [...m.values()]};
 // yerel öğeler önce gelir; uzak öğe yalnızca kesin olarak daha yeniyse yerel olanın yerine geçer
 S.assets=uni(S.assets||[],r.assets||[],(x,o)=>ts(x)>ts(o));
 S.team=uni(S.team||[],r.team||[],()=>false);S.projects=uni(S.projects||[],r.projects||[],()=>false);
 S.scans=uni(S.scans||[],r.scans||[],()=>false).sort((a,b)=>b.at-a.at).slice(0,planState().p.history||300);
 if((r.settingsAt||0)>(S.settingsAt||0)){S.settings=Object.assign({},S.settings,r.settings||{});S.settingsAt=r.settingsAt}
}
async function pullState(){
 const api=apiUrl();if(!api||!S||!U)return;const my=U.uid;
 try{
  const r=await fetch(api+'/api/state',{headers:await authH()});const j=await r.json().catch(()=>({}));
  if(!r.ok||!j.success)throw new Error(j.error||('HTTP '+r.status));
  if(!S||!U||U.uid!==my)return;
  SYNC.ver=j.version||0;
  if(j.exists&&j.state){
   const before=JSON.stringify(S);mergeState(j.state);
   if(JSON.stringify(S)!==before){try{localStorage.setItem(KEY+'_bak',before)}catch{}save(true);render()}
  }
  SYNC.pulled=true;await pushState();
 }catch(e){syncSay('Bulut senkronu başarısız: '+e.message+'. Verileriniz bu cihazda güvende; tekrar denenecek.')}
}
function schedulePush(){if(!SYNC.pulled||!U)return;clearTimeout(SYNC.timer);SYNC.timer=setTimeout(pushState,1500)}
async function pushState(){
 const api=apiUrl();if(!api||!S||!U||!SYNC.pulled)return;
 if(SYNC.busy){SYNC.dirty=true;return}
 SYNC.busy=true;const my=U.uid;
 try{
  for(let i=0;i<3;i++){
   const r=await fetch(api+'/api/state',{method:'PUT',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({state:remotePayload(),baseVersion:SYNC.ver})});
   const j=await r.json().catch(()=>({}));
   if(!S||!U||U.uid!==my)return;
   if(r.status===409){SYNC.ver=j.version||0;if(j.state){const b=JSON.stringify(S);mergeState(j.state);if(JSON.stringify(S)!==b){try{localStorage.setItem(KEY+'_bak',b)}catch{}save(true);render()}}continue}
   if(!r.ok||!j.success)throw new Error(j.error||('HTTP '+r.status));
   SYNC.ver=j.version;return;
  }
  throw new Error('Çakışma çözülemedi');
 }catch(e){syncSay('Buluta kaydedilemedi: '+e.message+'. Değişiklikler bu cihazda saklanıyor; tekrar denenecek.')}
 finally{SYNC.busy=false;if(SYNC.dirty){SYNC.dirty=false;schedulePush()}}
}
addEventListener('online',()=>{if(S&&U)SYNC.pulled?schedulePush():pullState()});
// Güvenlik: Firebase oturum belirteci bu adrese gönderilir. Kullanıcı tanımlı adres yalnızca aynı alan adı veya localhost olabilir;
// aksi halde (ör. sosyal mühendislikle girilen yabancı adres) yapılandırmadaki resmi adres kullanılır.
const apiUrl=()=>{const cfg=((window.DAC_CONFIG||{}).API_URL||'').trim().replace(/\/$/,'');const c=(S&&S.settings.apiUrl||'').trim().replace(/\/$/,'');
 if(c&&c!==cfg){try{const u=new URL(c);if(u.origin===location.origin||(u.protocol==='http:'&&/^(localhost|127\.0\.0\.1)$/.test(u.hostname)))return u.origin}catch{}}return cfg};

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
analytics_site_error_status:'Site hata kodu döndürüyor; etiket denetlenemedi',analytics_not_https:'Site HTTPS değil',analytics_no_tag:'Sitede GA4 / Google Tag Manager etiketi bulunamadı',analytics_measurement_id_mismatch:'Girilen Ölçüm Kimliği sitedeki etiketle eşleşmiyor',analytics_legacy_ua:'Yalnızca eski Universal Analytics (UA-) etiketi var; GA4\'e geçilmeli',analytics_tag_script_unreachable:'GA etiket betiğine erişilemedi',analytics_measurement_id_invalid:'Ölçüm Kimliği biçimi geçersiz (G-XXXXXXXXXX olmalı)',analytics_gtm_only:'Yalnızca GTM bulundu; GA4 etiketinin konteyner içinde olduğu buradan doğrulanamaz',analytics_live_data_unavailable:'Canlı trafik/dönüşüm verisi için Google Analytics Data API bağlantısı gerekir (henüz bağlı değil)',
web_bot_protection:'Bot koruması taramayı engelledi — site büyük olasılıkla çalışıyor, ayrıntılı analiz yapılamadı',web_down:'Site erişilemiyor',web_missing_target:'Hedef adres girilmemiş',web_slow:'Yanıt süresi yavaş',web_missing_title:'Sayfa başlığı (title) yok',web_missing_meta_description:'Meta açıklaması yok',web_missing_h1:'Sayfada H1 başlığı yok',web_missing_hsts:'HSTS başlığı yok',web_missing_csp:'Content-Security-Policy başlığı yok',web_missing_xframe:'Clickjacking koruması (X-Frame-Options) yok',web_missing_robots:'robots.txt bulunamadı',web_missing_sitemap:'sitemap.xml bulunamadı',
domain_invalid:'Geçersiz alan adı',domain_not_resolving:'Alan adı DNS\'te çözülmüyor',domain_missing_ns:'Nameserver (NS) kaydı yok',domain_single_ns:'Tek nameserver var (yedeksiz)',domain_missing_mx:'MX (e-posta) kaydı yok',domain_missing_caa:'CAA kaydı yok',domain_missing_spf:'SPF kaydı yok',domain_invalid_spf:'SPF kaydı hatalı',domain_missing_dmarc:'DMARC kaydı yok',domain_dmarc_policy_none:'DMARC politikası "none" (koruma uygulanmıyor)',domain_missing_dnssec:'DNSSEC kapalı',domain_dnssec_unknown:'DNSSEC durumu belirlenemedi',domain_expired:'Alan adının süresi dolmuş',domain_expiring_critical:'Alan adı süresi çok yakında doluyor',domain_expiring_soon:'Alan adı süresi yakında doluyor',domain_missing_expiry:'Bitiş tarihi okunamadı',domain_rdap_failed:'WHOIS/RDAP sorgusu başarısız',domain_registrar_unknown:'Kayıt kuruluşu belirlenemedi',domain_transfer_unlocked:'Domain transfer kilidi kapalı',domain_transfer_lock_unknown:'Transfer kilidi durumu belirlenemedi',domain_takeover_risk:'Subdomain devralma (takeover) riski',
DNS_SEC_ACTIVE:'DNSSEC aktif',DOMAIN_TRANSFER_LOCKED:'Transfer kilidi aktif (iyi)',EMAIL_CAA_VALID:'CAA kaydı geçerli',EMAIL_DKIM_VALID:'DKIM kaydı geçerli',EMAIL_DMARC_VALID:'DMARC kaydı geçerli',EMAIL_SPF_VALID:'SPF kaydı geçerli',
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
const EXPO={svn:'.svn klasörü açıkta!',awscreds:'AWS kimlik bilgileri açıkta!',npmrc:'.npmrc (token) açıkta!',webconfig:'web.config dosyası okunabiliyor!',dockercompose:'docker-compose.yml açıkta',actuatorenv:'Spring Actuator /env açıkta (gizli ayarlar)!',actuator:'Spring Actuator uç noktaları açık',phpmyadmin:'phpMyAdmin girişi internete açık',adminer:'Adminer (veritabanı yöneticisi) açık',wpusers:'WordPress kullanıcı listesi herkese açık',xmlrpc:'WordPress xmlrpc.php açık',swagger:'API dokümantasyonu (Swagger/OpenAPI) herkese açık',backuparchive:'Yedek arşivi (.zip) indirilebilir durumda!',env:'.env dosyası dışarıdan okunabiliyor!',git:'.git klasörü açıkta!',gitconfig:'.git/config açıkta!',phpinfo:'phpinfo sayfası açık',dsstore:'.DS_Store dosyası açık',serverstatus:'Apache server-status sayfası açık',wpconfig:'wp-config yedeği açıkta!',sqldump:'Veritabanı yedeği (.sql) açıkta!',htpasswd:'.htpasswd dosyası açıkta!'};
const PORTN={53:'DNS',110:'POP3',135:'MS-RPC',139:'NetBIOS',1521:'Oracle',2375:'Docker API',2379:'etcd',5601:'Kibana',5672:'AMQP',5984:'CouchDB',6443:'Kubernetes API',9092:'Kafka',10000:'Webmin',15672:'RabbitMQ Yönetim',21:'FTP',23:'Telnet',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',9200:'Elasticsearch',11211:'Memcached',27017:'MongoDB'};
/* v12 ek bulgu çevirileri */
Object.assign(FT,{
domain_scanned_root:'Girilen adres bir alt alan adı; kayıt ve e-posta analizi ana alan adı üzerinden yapıldı',domain_dns_unreliable:'DNS sorguları yanıt vermedi, sonuç belirlenemedi',domain_ns_check_inconclusive:'Nameserver\'lara doğrudan sorgu yapılamadı (ağ kısıtı olabilir)',domain_ns_partial_failure:'Bazı nameserver\'lar yanıt vermiyor',domain_ns_serial_mismatch:'Nameserver\'ların SOA serial değerleri farklı (senkron değil)',domain_ns_same_network:'Tüm nameserver\'lar aynı ağda (tek hata noktası)',
domain_spf_multiple_records:'Birden fazla SPF kaydı var — SPF geçersiz sayılır (permerror)',domain_spf_too_many_lookups:'SPF 10 DNS sorgu sınırını aşıyor — SPF geçersiz sayılır',domain_spf_allows_all:'SPF "+all" içeriyor: herkes adınıza e-posta gönderebilir!',domain_spf_neutral_all:'SPF "?all" ile bitiyor (koruma yok)',domain_spf_no_all:'SPF kaydında "all" mekanizması yok',domain_spf_ptr:'SPF "ptr" mekanizması kullanıyor (önerilmez)',domain_spf_broken_include:'SPF içindeki bir include hedefi bulunamıyor',
domain_invalid_dmarc:'DMARC kaydı geçersiz (p= değeri hatalı)',domain_dmarc_pct_partial:'DMARC politikası e-postaların yalnızca bir kısmına uygulanıyor (pct<100)',domain_dmarc_subdomain_weak:'DMARC alt alan adı politikası (sp) ana politikadan zayıf',domain_dmarc_no_reporting:'DMARC raporlama adresi (rua) yok',domain_dmarc_multiple_records:'Birden fazla DMARC kaydı var',
domain_dkim_weak_key:'DKIM anahtarı 1024 bitten kısa (zayıf)',domain_dkim_short_key:'DKIM anahtarı 1024 bit; 2048 önerilir',domain_dkim_revoked:'Bir DKIM anahtarı iptal edilmiş (boş p=)',domain_dkim_test_mode:'DKIM test modunda (t=y)',domain_dkim_not_discovered:'DKIM selector\'ı otomatik bulunamadı (özel selector kullanılıyor olabilir)',
domain_missing_mta_sts:'MTA-STS yok (e-posta aktarımında TLS zorunlu değil)',domain_mta_sts_policy_unreachable:'MTA-STS kaydı var ama politika dosyasına ulaşılamıyor',domain_mta_sts_not_enforced:'MTA-STS "enforce" modunda değil',domain_missing_tls_rpt:'TLS-RPT raporlama kaydı yok',
domain_dnssec_broken:'DNSSEC bozuk: DS kaydı var ama doğrulama başarısız (alan adı bazı çözücülerde çözülmeyebilir)',domain_dnssec_ds_missing:'DNSKEY var ama kayıt kuruluşunda DS kaydı yok (DNSSEC etkisiz)',domain_on_hold:'Alan adı "hold" durumunda (devre dışı)',domain_redemption:'Alan adı silinme/kurtarma (redemption) sürecinde',domain_not_registered:'Alan adı kayıtlı görünmüyor',domain_registry_no_rdap:'Bu uzantının kayıt otoritesi RDAP sunmuyor: bitiş tarihi/kayıt kuruluşu okunamadı',domain_dangling_cname:'Var olmayan bir hedefe işaret eden CNAME kaydı var',domain_ip_blacklisted:'Alan adının IP adresi kara listelerde (spam/zararlı)',domain_ip_listed:'Alan adının IP adresi bir kara listede görünüyor',
ssl_dns_failure:'Alan adı çözülemedi, SSL kontrol edilemedi',ssl_port_closed:'Hedefte SSL portu (443) kapalı',ssl_timeout:'SSL bağlantısı zaman aşımına uğradı',ssl_handshake_failed:'TLS el sıkışması başarısız',ssl_not_yet_valid:'Sertifika henüz geçerli değil',ssl_hostname_mismatch:'Sertifika bu alan adı için düzenlenmemiş (isim uyuşmazlığı)',ssl_untrusted:'Sertifika güvenilir bir otorite tarafından imzalanmamış',ssl_chain_expired:'Zincirdeki bir ara sertifikanın süresi dolmuş',ssl_tls12_unsupported:'Sunucu TLS 1.2 veya üstünü desteklemiyor',ssl_no_tls13:'TLS 1.3 desteklenmiyor',ssl_weak_cipher:'Zayıf şifreleme algoritması kullanılıyor',ssl_hsts_short:'HSTS süresi 6 aydan kısa',ssl_hsts_no_subdomains:'HSTS alt alan adlarını kapsamıyor (includeSubDomains yok)',ssl_www_not_covered:'Sertifika www / çıplak alan adı eşini kapsamıyor',ssl_long_validity:'Sertifika geçerlilik süresi 398 günden uzun',ssl_no_ocsp_stapling:'OCSP stapling kapalı',
hosting_dns_unreliable:'DNS sorguları yanıt vermedi',hosting_server_error:'Sunucu 5xx hata döndürüyor',hosting_tls_old:'Eski TLS sürümü kullanılıyor',hosting_no_https_redirect:'HTTP, HTTPS\'e yönlendirilmiyor',hosting_slow_connect:'Bağlantı kurma süresi yavaş',hosting_geo_unknown:'Sunucunun konum/sağlayıcı bilgisi alınamadı',
server_dns_unreliable:'DNS sorguları yanıt vermedi',server_private_target:'Hedef özel/yerel ağ adresi, taranamaz',server_ssh_v1:'SSH protokol sürüm 1 kullanılıyor (güvensiz)',server_ssh_outdated:'Eski OpenSSH sürümü (8.5 altı)',server_ftp_vulnerable_version:'FTP sunucusu bilinen zafiyetli sürümde',server_ftp_without_ssh:'FTP açık ama SSH yok (şifresiz aktarım riski)',server_plain_mail_ports:'Şifresiz POP3/IMAP portları açık (SSL portları kapalı)',server_behind_cdn:'Hedef CDN/WAF arkasında; port sonuçları CDN\'i yansıtır',
seo_canonical_other_host:'Canonical adresi başka bir alan adına işaret ediyor',seo_canonical_invalid:'Canonical adresi geçersiz',seo_sitemap_empty:'Sitemap boş',seo_sitemap_broken_urls:'Sitemap\'teki adreslere ulaşılamıyor',seo_sitemap_other_host:'Sitemap başka alan adlarının adreslerini içeriyor',seo_missing_charset:'Karakter kodlaması (charset) belirtilmemiş',seo_final_status:'Sayfa nihai durum kodu 200 değil',seo_redirect_chain:'Çok fazla yönlendirme var',seo_structured_data_invalid:'JSON-LD yapısal veri geçersiz',seo_few_internal_links:'Sayfada çok az iç bağlantı var',seo_client_rendered:'Sayfa JavaScript ile oluşturuluyor; içerik kontrolleri sınırlı',seo_not_html:'Adres HTML sayfası döndürmüyor',seo_parked_page:'Alan adı "park edilmiş / satılık" sayfası gösteriyor',
security_csp_weak:'CSP çok geniş kaynaklara izin veriyor (* / data: / http:)',security_cookie_samesite_none:'SameSite=None çerez Secure bayrağı olmadan',security_mixed_content_passive:'HTTPS sayfada HTTP görsel/medya kaynağı var',security_insecure_form:'Form/parola alanı şifresiz (HTTP) kullanıyor',security_directory_listing:'Dizin listeleme açık',security_no_sri:'Harici scriptlerde SRI (integrity) yok',security_https_unavailable:'Site HTTPS sunmuyor',security_invalid_certificate:'Sertifika geçersiz (güvenilmez/süresi dolmuş/isim uyuşmuyor)',security_cert_expired:'Sertifikanın süresi dolmuş',security_tls_legacy_enabled:'Eski TLS 1.0/1.1 hâlâ açık',security_missing_security_txt:'security.txt yok (güvenlik açığı bildirim adresi)',
perf_slow_tls:'TLS el sıkışması yavaş',perf_slow_dns:'DNS çözümleme yavaş',perf_heavy_js:'JavaScript boyutu büyük (600 KB üzeri)',perf_heavy_css:'CSS boyutu büyük (200 KB üzeri)',perf_images_no_dimensions:'Görsellerin çoğunda width/height yok (düzen kayması)',perf_many_third_parties:'Çok fazla üçüncü taraf kaynak (10+ alan adı)',perf_large_dom:'DOM çok büyük (2500+ öğe)',perf_large_images:'400 KB üzeri görseller var',
web_server_error:'Sunucu 5xx hata döndürüyor',web_redirect_loop:'Sonsuz yönlendirme döngüsü',web_suspended:'Site barındırma hesabı askıya alınmış görünüyor',web_parked:'Alan adı park edilmiş / satılık sayfası gösteriyor',web_default_page:'Sunucunun varsayılan karşılama sayfası görünüyor (site yayında değil)',web_app_error:'Sayfada uygulama/veritabanı hatası görünüyor',web_empty_response:'Sayfa boş yanıt döndürüyor',web_no_https:'Site yalnızca HTTP ile açılıyor (HTTPS yok)',web_tls_error:'SSL sertifika hatası (tarayıcılar uyarı gösterir)',web_variant_unreachable:'Girilen adres açılmıyor, www/çıplak eşi açılıyor',web_www_inconsistent:'www ve çıplak alan adından biri çalışmıyor',web_soft_404:'Olmayan sayfalar 404 yerine 200 dönüyor (soft-404)',web_under_construction:'Site "yapım aşamasında" sayfası gösteriyor',web_maintenance:'Site bakım modunda',web_blocks_unknown_agents:'Site bilinmeyen istemcileri engelliyor',web_ssl_expired:'SSL sertifikasının süresi dolmuş',web_ssl_expiring:'SSL sertifikası 14 günden kısa sürede doluyor',web_eol_php:'Desteği biten PHP sürümü kullanılıyor',web_old_jquery:'Eski jQuery (1.x/2.x) kullanılıyor',web_old_bootstrap:'Eski Bootstrap (3 ve altı) kullanılıyor',web_old_wordpress:'Eski WordPress sürümü kullanılıyor',
uptime_server_errors:'Bazı denemelerde sunucu 5xx hata verdi',uptime_dns_failure:'DNS çözümlenemedi',uptime_connection_refused:'Bağlantı reddedildi',uptime_timeout:'Bağlantı zaman aşımına uğradı',uptime_tls_failure:'TLS/SSL hatası nedeniyle bağlanılamadı',uptime_unreachable:'Siteye ulaşılamadı',uptime_maintenance:'Sunucu 503 (bakım) döndürdü',
api_no_compression:'Yanıt sıkıştırılmıyor',api_cors_reflects_origin:'CORS rastgele Origin değerini yansıtıyor',api_error_leaks_stacktrace:'Hata yanıtında yığın izi / iç bilgi sızıyor',api_debug_headers:'Debug başlıkları açık',api_unknown_route_status:'Olmayan yol için 404 yerine farklı kod dönüyor',
mobile_not_in_home_store:'Uygulama seçilen ülke mağazasında değil, başka ülkede bulundu',mobile_low_current_rating:'Güncel sürümün puanı düşük (3,5 altı)',mobile_old_min_os:'Minimum iOS sürümü çok eski',mobile_details_unavailable:'Mağaza sayfasından puan/güncelleme bilgisi okunamadı',
repo_secret_file_committed:'Depoda gizli bilgi dosyası var (.env, anahtar, kimlik bilgisi)!',repo_no_security_policy:'SECURITY.md (güvenlik politikası) yok',repo_no_ci:'CI/CD yapılandırması bulunamadı',repo_no_lockfile:'Bağımlılık kilit dosyası (lockfile) yok',repo_no_dependency_updates:'Otomatik bağımlılık güncelleme (Dependabot/Renovate) yok',repo_single_contributor:'Tek katkıcı var (bus factor riski)',repo_is_fork:'Depo bir fork',repo_issues_disabled:'Issue özelliği kapalı',
brand_wildcard_dns:'Uzantıda wildcard DNS var, bazı sonuçlar yanılabilir',saas_manual_renewal_due:'Otomatik yenileme kapalı ve süre yaklaşıyor',saas_usage_high:'Kullanım oranı yüksek (80% üzeri)',saas_underused:'Kullanım çok düşük: ücret israfı olabilir',scan_timeout:'Tarama süre sınırını aştı, tekrar deneyin',
domain_expiring:'Alan adı süresi dolmak üzere'});
const NETERR={dns_failure:'Alan adı çözülemedi (DNS)',connection_refused:'Bağlantı reddedildi (port kapalı)',timeout:'Bağlantı zaman aşımına uğradı',tls_failure:'TLS/SSL hatası nedeniyle bağlanılamadı',connection_reset:'Bağlantı sunucu tarafından sıfırlandı',network_unreachable:'Sunucuya ağ yolu yok',private_target:'Özel/yerel ağ adresi taranamaz',redirect_loop:'Sonsuz yönlendirme döngüsü',unreachable:'Hedefe ulaşılamadı'};
function finT(f){
 const k=String(f).replace(/^finding_/,'').replace(/_(critical|warning|info)$/,'');let m;
 if(FT[k])return FT[k];
 if((m=k.match(/^web_status_(\d+)$/)))return'Site HTTP '+m[1]+' hata kodu döndürüyor';
 if((m=k.match(/^(?:web|seo|security|perf|api|hosting|uptime)_(dns_failure|connection_refused|timeout|tls_failure|connection_reset|network_unreachable|private_target|redirect_loop)$/)))return NETERR[m[1]];
 if((m=k.match(/^brand_(\d+)_lookalike_phishing$/)))return`${m[1]} benzer alan adında marka adı + giriş formu var: OLASI KİMLİK AVI SİTESİ!`;
 if((m=k.match(/^brand_(\d+)_lookalike_active$/)))return`${m[1]} benzer alan adında yayında site var ve marka adınızı kullanıyor`;
 if((m=k.match(/^brand_(\d+)_keyword_registered$/)))return`${m[1]} anahtar kelimeli (login-, secure- vb.) benzer alan adı başkasında kayıtlı`;
 if((m=k.match(/^server_exposed_port_(\d+)$/)))return`Port ${m[1]} internete açık${PORTN[m[1]]?' ('+PORTN[m[1]]+')':''}`;
 if((m=k.match(/^security_exposed_(\w+)$/)))return EXPO[m[1]]||'Hassas dosya açıkta';
 if((m=k.match(/^brand_(\d+)_lookalike_registered$/)))return`${m[1]} benzer (yazım hatalı) alan adı başkası tarafından kayıtlı`;
 if((m=k.match(/^brand_(\d+)_tld_thirdparty$/)))return`${m[1]} farklı uzantı (TLD) başkası tarafından kayıtlı`;
 if((m=k.match(/^brand_(\d+)_tld_unprotected$/)))return`${m[1]} önemli uzantı henüz kayıt edilmemiş — satın almayı düşünün`;
 return k.replace(/_/g,' ');
}
const SL={PROTECTED:'KORUMALI',UNKNOWN:'BİLİNMİYOR',HEALTHY:'SAĞLIKLI',ACTIVE:'AKTİF',WARNING:'UYARI',CRITICAL:'KRİTİK',DOWN:'ERİŞİLEMİYOR',EXPIRED:'SÜRESİ DOLMUŞ',EXPIRING_SOON:'SÜRESİ YAKLAŞIYOR',ERROR:'HATA'};
const SCL={availability:'Erişilebilirlik',hsts:'HSTS',dayaniklilik:'Dayanıklılık',performans:'Performans',icerik:'İçerik',teknik:'Teknik',sosyal:'Sosyal/Yapı',basliklar:'Başlıklar',aktarim:'Aktarım',dosyalar:'Açık dosya',sunucu:'Sunucu',agi:'Ağ',sayfa:'Sayfa',erisim:'Erişim',gecikme:'Gecikme',guvenlik:'Güvenlik',tasarim:'Tasarım',yayin:'Yayın',kalite:'Kalite',bakim:'Bakım',topluluk:'Topluluk',overall:'Genel',security:'Güvenlik',seo:'SEO',performance:'Performans',dns:'DNS',email:'E-posta',renewal:'Yenileme',validity:'Geçerlilik',chainTrust:'Zincir',cost:'Maliyet',usage:'Kullanım'};
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
async function runScan(a){
 const t0=Date.now(),api=apiUrl();let res;
 if(api){
  const target=URLCATS.includes(a.cat)?proto(a.target):a.target;
  if(['SERVER','SECURITY'].includes(CATS[a.cat].api)&&!a.consent){if(!confirm('Bu tarama hedefe bağlantı denemeleri (port / dosya yolu) yapar.\n\n"'+a.target+'" adresini taramaya yetkili olduğunuzu (sahibi olduğunuzu veya yazılı izniniz bulunduğunu) onaylıyor musunuz?\nİzinsiz tarama suç oluşturabilir; onayınız kaydedilir.'))throw new Error('Tarama, yetki onayı verilmediği için iptal edildi');a.consent=true;save()}
  let r;try{r=await fetch(api+'/api/scan',{method:'POST',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({assetId:a.id,type:CATS[a.cat].api,targetUrl:target,name:a.name,extra:a.extra||{},consent:a.consent===true})})}catch{throw new Error('Tarama sunucusuna ulaşılamadı ('+api+'). Adres yanlış olabilir veya Render uyanıyor, 30 sn sonra tekrar deneyin. Ayarlar > Scanner API adresini kontrol edin.')}
  let j;try{j=await r.json()}catch{throw new Error('Sunucu geçersiz yanıt verdi ('+r.status+'). Render uyanıyor olabilir, 30 sn sonra tekrar deneyin.')}
  if(r.status===402){location.hash='plan';throw new Error(j.error||'Paket gerekli')}
  if(!j.success)throw new Error(j.error||'Tarama başarısız');res=j.result;
 }else throw new Error('Tarama sunucusu adresi bulunamadı. Ayarlar > Scanner API adresini girin.');
 a.result=res;a.lastScan=Date.now();
 S.scans.unshift({id:uid(),assetId:a.id,name:a.name,cat:a.cat,score:res.healthScore,status:res.status,at:Date.now(),ms:Date.now()-t0});
 S.scans=S.scans.slice(0,planState().p.history||300);save();
}
/* ---------- tarayıcı bildirimleri (Web Push) ---------- */
let NTF={on:false,perm:typeof Notification!=='undefined'?Notification.permission:'denied',checked:false};
const ntfSupported=()=>'serviceWorker' in navigator&&'PushManager' in window&&'Notification' in window;
const b64u=u=>{const s=(u+'='.repeat((4-u.length%4)%4)).replace(/-/g,'+').replace(/_/g,'/'),r=atob(s);return Uint8Array.from(r,c=>c.charCodeAt(0))};
async function ntfRefresh(){
 if(!ntfSupported())return;
 try{const reg=await navigator.serviceWorker.ready,sub=await reg.pushManager.getSubscription();NTF.on=!!sub&&Notification.permission==='granted';NTF.perm=Notification.permission;NTF.checked=true}catch{}
 if(location.hash==='#settings')render();
}
async function ntfEnable(){
 const api=apiUrl();if(!api)return toast('Sunucu adresi yok','err');
 if(!ntfSupported())return toast('Bu tarayıcı bildirimleri desteklemiyor. iPhone için siteyi önce Ana Ekrana ekleyin.','err');
 busy(true);
 try{
  const perm=await Notification.requestPermission();NTF.perm=perm;
  if(perm!=='granted')throw new Error('Bildirim izni verilmedi. Tarayıcı ayarlarından bu site için bildirimlere izin verin.');
  const h=await authH();const kr=await fetch(api+'/api/push/key',{headers:h}),kj=await kr.json();if(!kj.success)throw new Error(kj.error||'Bildirim anahtarı alınamadı');
  const reg=await navigator.serviceWorker.ready;let sub=await reg.pushManager.getSubscription();
  if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:b64u(kj.key)});
  const r=await fetch(api+'/api/push/subscribe',{method:'POST',headers:{'Content-Type':'application/json',...h},body:JSON.stringify({subscription:sub.toJSON()})}),j=await r.json();
  if(!j.success)throw new Error(j.error||'Abonelik kaydedilemedi');
  NTF.on=true;toast('Bildirimler açıldı');
 }catch(e){toast(e.message,'err')}
 busy(false);render();
}
async function ntfDisable(){
 const api=apiUrl();busy(true);
 try{const reg=await navigator.serviceWorker.ready,sub=await reg.pushManager.getSubscription();
  if(sub){const h=await authH();if(api)await fetch(api+'/api/push/unsubscribe',{method:'POST',headers:{'Content-Type':'application/json',...h},body:JSON.stringify({endpoint:sub.endpoint})}).catch(()=>{});await sub.unsubscribe()}
  NTF.on=false;toast('Bildirimler kapatıldı')}catch(e){toast(e.message,'err')}
 busy(false);render();
}
async function ntfTest(){
 const api=apiUrl();if(!api)return;busy(true);
 try{const r=await fetch(api+'/api/push/test',{method:'POST',headers:{'Content-Type':'application/json',...await authH()},body:'{}'}),j=await r.json();toast(j.success?'Test bildirimi gönderildi':(j.error||'Gönderilemedi'),j.success?'':'err')}catch{toast('Sunucuya ulaşılamadı','err')}
 busy(false);
}
/* Sunucunun otomatik taradığı varlıkların son sonuçlarını al ve birleştir */
let LAST_PULL=0;
async function pullLatest(force){
 const api=apiUrl();if(!api||!U||!S||(!force&&Date.now()-LAST_PULL<120000))return;LAST_PULL=Date.now();
 try{
  const h=await authH();if(!h.Authorization)return;
  const since=Math.max(0,...S.assets.map(a=>a.lastScan||0));
  const r=await fetch(api+'/api/assets/latest?since='+since,{headers:h}),j=await r.json();if(!j.success)return;
  let ch=0;
  for(const it of j.items){const a=find(it.assetId);if(!a||it.scannedAtMs<=(a.lastScan||0)+1000)continue;
   a.result=it.result;a.lastScan=it.scannedAtMs;ch++;
   S.scans.unshift({id:uid(),assetId:a.id,name:a.name,cat:a.cat,score:it.result.healthScore,status:it.result.status,at:it.scannedAtMs,ms:it.result.latencyMs||0,auto:true})}
  if(ch){S.scans=S.scans.slice(0,planState().p.history||300);save();render()}
 }catch{}
}
async function delRemote(id){const api=apiUrl();if(!api||!U)return;try{const h=await authH();if(h.Authorization)await fetch(api+'/api/assets/'+encodeURIComponent(id),{method:'DELETE',headers:h})}catch{}}
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
 <div class="acts"><button class="btn s" data-act="detail" data-id="${esc(a.id)}">Detay</button><button class="btn s" data-act="rescan" data-id="${esc(a.id)}">${ic('refresh-cw')}</button><button class="btn s d" data-act="del" data-id="${esc(a.id)}">${ic('trash-2')}</button></div></div>`;
}
const scanRow=s=>`<div class="item"><div class="ico" style="color:${CATS[s.cat]?.c}">${ic(CATS[s.cat]?.icon||'scan')}</div><div class="g"><b>${esc(s.name)}</b><span>${fmt(s.at)} • ${s.ms}ms</span></div>${s.score!=null?`<span class="badge ${tone(s.score)}">${s.score}/100</span>`:`<span class="badge mu">${SL[s.status]||'?'}</span>`}</div>`;
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
 <div class="card" style="margin-top:14px"><div class="item" style="border:0"><div class="ico" style="color:var(--bl)">${ic('zap')}</div><div class="g"><b style="font-size:18px">Hızlı Tarama</b><span style="white-space:normal">Domain veya URL girin, kategori seçin ve tarayın</span></div></div>
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
 :`<form data-form="add" data-cat="${k}"><input class="field" name="t" placeholder="${v.ph}" required autocomplete="off"><input class="field" name="name" placeholder="Görünen ad (opsiyonel)">${k==='analytics'?'<input class="field" name="measurementId" placeholder="Ölçüm Kimliği (G-XXXXXXXXXX, opsiyonel)" autocomplete="off"><input class="field" name="propertyName" placeholder="Özellik (property) adı (opsiyonel)">':''}<button class="btn p w" type="submit">${ic('plus')} Ekle ve Tara</button></form>`;
 return`<h2>${v.label}</h2><p class="sub">${v.desc}</p>
 <div class="card info"><b>${ic('list-checks','style="color:'+v.c+'"')} Ne taranır?</b><ul class="ul">${v.what.map(x=>`<li>${x}</li>`).join('')}</ul><div class="why"><b>Neden önemli?</b> ${v.why}</div>${v.hint?`<div class="hint" style="margin-top:8px">${ic('info')} ${v.hint}</div>`:''}</div>
 <div class="card"><b>Yeni ${v.label} ekle</b><div style="height:12px"></div>${form}</div>${k==='domain'?domExtra():''}
 <div class="card"><div class="mh"><b>Varlıklar</b><span class="badge mu">${list.length}</span></div>${list.length?list.map(assetRow).join(''):`<div class="empty">Bu kategoride henüz varlık yok</div>`}</div>`;
}
function assets(){const q=($('#q')?.value||'').toLowerCase();const l=S.assets.filter(a=>!q||(a.name+a.target).toLowerCase().includes(q));
 return`<div class="mh"><h2>Varlıklarım</h2><button class="btn s" data-act="bk-refresh">${ic('refresh-cw')} Yenile</button></div><p class="sub">${S.assets.length} varlık</p><div class="card">${l.length?l.map(assetRow).join(''):`<div class="empty">Varlık yok. Sol menüden bir kategori seçip ekleyin.</div>`}</div>`}
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
 <div class="acts"><button class="btn" data-act="csv">${ic('download')} CSV indir</button><button class="btn" data-act="json">${ic('download')} JSON indir</button><button class="btn" data-act="print">${ic('printer')} Yazdır</button></div>`}
function listPage(k){const L=LISTS[k],ps=planState(),lim=k==='team'?ps.p.team:null;
 return`<h2>${L.title}</h2><p class="sub">${S[k].length} kayıt${lim?` • bu pakette en fazla ${lim}`:''}</p><div class="card"><form data-form="list" data-k="${k}">${L.f.map(([n,p],i)=>`<input class="field" name="${n}" placeholder="${p}" ${i?'':'required'}>`).join('')}<button class="btn p w" type="submit">${ic('plus')} Ekle</button></form></div>
 <div class="card">${S[k].length?S[k].map(x=>`<div class="item"><div class="ico">${ic(L.icon)}</div><div class="g"><b>${esc(x[L.f[0][0]])}</b><span>${L.f.slice(1).map(([n])=>esc(x[n])).filter(Boolean).join(' • ')}</span></div><button class="btn s d" data-act="dellist" data-k="${k}" data-id="${x.id}">${ic('trash-2')}</button></div>`).join(''):`<div class="empty">Kayıt yok</div>`}</div>`}

/* ---------- paket sayfası ---------- */
function plan(){
 const st=S.settings,ps=planState(),cur=st.currency||'TRY',cyc=st.cycle||'monthly',alt=cur==='TRY'?'USD':'TRY';
 if(!PAYCFG&&!HEALTH_TRIED&&apiUrl()){HEALTH_TRIED=true;fetchHealth().then(()=>{if(location.hash==='#plan')render()})}
 const status=ps.paid?`<span class="badge ok">${ps.p.name} aktif</span>${st.planEnd?` <span class="hint">bitiş: ${new Date(st.planEnd).toLocaleDateString('tr-TR')}</span>`:''}`
  :ps.trial?`<span class="badge wn">Ücretsiz deneme: ${leftTxt(ps.left)} kaldı</span>`:`<span class="badge bd">Deneme süresi doldu</span>`;
 const provOk=c=>!PAYCFG||(c==='TRY'?PAYCFG.iyzico:PAYCFG.stripe),free=!!(PAYCFG&&PAYCFG.free),ready=c=>provOk(c)||free;
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
 ${free&&!provOk(cur)?`<div class="paynote">Ödeme sistemi henüz bağlanmadı: <b>Satın al</b> butonu paketi kart bilgisi istemeden doğrudan etkinleştirir (geçici test dönemi).</div>`:''}
 <p class="hint">${cur==='TRY'?'TL ödemeleri iyzico ile alınır; kart bilgisi bu sitede saklanmaz. Süre dolmadan yeniden satın alarak uzatabilirsiniz. Ödeme için Ayarlar > Fatura Bilgileri doldurulmalıdır.':'USD ödemeleri Stripe ile alınır, abonelik otomatik yenilenir ve istediğiniz zaman iptal edilebilir.'}</p>
 ${ps.paid&&st.provider==='stripe'?`<button class="btn" data-act="portal">${ic('credit-card')} Aboneliği yönet / iptal et</button>`:''}
 <button class="btn" data-act="syncplan" style="margin-top:8px">${ic('refresh-cw')} Ödememi kontrol et</button>`;
}

/* ---------- ayarlar ---------- */
const standalone=()=>matchMedia('(display-mode: standalone)').matches||navigator.standalone;
function ntfCard(){
 if(!NTF.checked)ntfRefresh();
 const sup=ntfSupported(),blocked=NTF.perm==='denied';
 return`<div class="card"><b>${ic('bell-ring')} Bildirimler</b>
 <div class="hint">Site çöktüğünde, SSL/alan adı/abonelik bitmek üzereyken ya da yeni kritik bir sorun çıktığında tarayıcınız size anında haber verir. Varlıklarınız arka planda otomatik taranır (erişim türleri 5 saatte bir, SSL/Domain günde bir, ağır taramalar haftada bir).</div>
 ${!sup?'<div class="paynote">Bu tarayıcı bildirim desteklemiyor. iPhone/iPad için siteyi Paylaş menüsünden “Ana Ekrana Ekle” ile yükleyip oradan açın.</div>':blocked?'<div class="paynote">Bildirimler tarayıcıda engellenmiş. Adres çubuğundaki kilit simgesinden bu site için bildirime izin verin.</div>':''}
 <div class="acts" style="margin-top:12px">${NTF.on?`<span class="badge ok">Açık</span><button class="btn s" data-act="ntf-test">${ic('send')} Test gönder</button><button class="btn s d" data-act="ntf-off">${ic('bell-off')} Kapat</button>`:`<button class="btn p s" data-act="ntf-on" ${sup&&!blocked?'':'disabled'}>${ic('bell')} Bildirimleri aç</button>`}</div></div>`;
}
function settings(){
 const s=S.settings,b=s.billing||{},ps=planState(),kb=Math.round(JSON.stringify(S).length/1024);
 const f=(n,l,ph='',t='text')=>`<label class="hint">${l}</label><input class="field" name="${n}" type="${t}" value="${esc(b[n])}" placeholder="${ph}">`;
 return`<h2>Ayarlar</h2><p class="sub">Hesap, fatura, bağlantı ve veri yönetimi</p>
 ${ntfCard()}
 <div class="card"><b>${ic('user-round')} Hesap</b><div class="item" style="border:0">${U?.photoURL?`<img class="pfp" src="${esc(U.photoURL)}" alt="">`:`<div class="ico">${ic('user-round')}</div>`}<div class="g"><b>${esc(U?.displayName||'Kullanıcı')}</b><span>${esc(U?.email||'')}</span></div></div>
 <div class="hint">Son giriş: ${U?.metadata?.lastSignInTime?fmt(U.metadata.lastSignInTime):'-'} • Paket: ${esc(planName(ps))}</div>
 <div class="acts" style="margin-top:12px"><button class="btn s" data-act="copyuid">${ic('copy')} Kullanıcı ID kopyala</button><button class="btn s" data-act="logout">${ic('log-out')} Çıkış yap</button></div></div>
 <div class="card"><form data-form="settings"><b>${ic('building-2')} Organizasyon ve uyarılar</b><div style="height:10px"></div>
 <label class="hint">Organizasyon adı</label><input class="field" name="org" value="${esc(s.org)}" required>
 <label class="hint">Uyarı eşiği: skoru bunun altında kalan varlıklar "Aktif Uyarılar"a düşer</label><input class="field" name="alertBelow" type="number" min="10" max="95" value="${s.alertBelow??50}">
 <label class="hint">Scanner API adresi (boş bırakın; yalnızca aynı alan adı veya localhost kabul edilir)</label><input class="field" name="apiUrl" value="${esc(s.apiUrl)}" placeholder="${esc((window.DAC_CONFIG||{}).API_URL||'https://scanner.onrender.com')}">
 <button class="btn p w" type="submit">Kaydet</button></form>
 <div class="acts" style="margin-top:10px"><button class="btn s" data-act="ping">${ic('plug-zap')} Bağlantıyı test et</button></div><div class="hint" id="pingres" style="margin-top:8px"></div></div>
 <div class="card"><form data-form="billing"><b>${ic('receipt')} Fatura bilgileri</b><div class="hint">TL ödemesi (iyzico) için ad soyad, adres ve şehir zorunludur.</div><div style="height:10px"></div>
 ${f('name','Ad Soyad','Ali Veli')}${f('company','Şirket ünvanı (opsiyonel)')}
 <div class="row2"><div>${f('email','Fatura e-postası','fatura@sirket.com','email')}</div><div>${f('phone','Telefon','+90 5xx xxx xx xx','tel')}</div></div>
 ${f('taxId','Vergi No (isteğe bağlı)','10 haneli')}${f('address','Adres','Mahalle, cadde, no')}
 <div class="row2"><div>${f('city','Şehir','İstanbul')}</div><div>${f('zip','Posta kodu')}</div></div>
 ${f('country','Ülke','Turkey')}
 <button class="btn p w" type="submit">Fatura bilgilerini kaydet</button></form></div>
 <div class="card"><b>${ic('smartphone')} Uygulama (PWA)</b><div class="hint" style="margin:6px 0 10px">${standalone()?'Uygulama olarak çalışıyor.':DEFERRED?'Ana ekrana yükleyerek uygulama gibi kullanabilirsiniz.':'Tarayıcı menüsünden "Uygulamayı yükle / Ana ekrana ekle" seçeneğini kullanın.'}</div>
 <div class="acts">${DEFERRED&&!standalone()?`<button class="btn p" data-act="install">${ic('download')} Uygulamayı yükle</button>`:''}<button class="btn" data-act="clearcache">${ic('refresh-cw')} Önbelleği temizle ve yenile</button></div></div>
 <div class="card"><b>${ic('database')} Veri yönetimi</b><div class="hint" style="margin:6px 0 10px">${S.assets.length} varlık • ${S.scans.length} tarama kaydı • ~${kb} KB (cihazınızda ve hesabınıza bağlı bulut kopyasında saklanır)</div>
 <div class="acts"><button class="btn" data-act="backup">${ic('download')} Yedek indir</button><button class="btn" data-act="import">${ic('upload')} Yedekten yükle</button><button class="btn" data-act="export-account">${ic('file-json')} Tüm verilerimi indir (KVKK)</button></div><input type="file" id="imp" accept="application/json" hidden></div>
 <div class="card"><b style="color:var(--bad)">${ic('triangle-alert')} Tehlikeli bölge</b><div class="hint" style="margin:6px 0 10px">Yalnızca bu cihazdaki yerel kopyayı silmek için "Bu cihazdaki verileri sil"; hesabınızı ve bulutta saklanan tüm verilerinizi kalıcı silmek için "Hesabımı sil" (KVKK m.7, m.11).</div><div class="acts"><button class="btn d" data-act="wipe">${ic('trash-2')} Bu cihazdaki verileri sil</button><button class="btn d" data-act="delete-account">${ic('user-x')} Hesabımı sil</button></div></div>
 <div class="card"><b>${ic('scale')} Yasal</b><div class="legalbox"><a href="/kvkk" target="_blank" rel="noopener">KVKK Aydınlatma Metni</a> • <a href="/gizlilik" target="_blank" rel="noopener">Gizlilik Politikası</a> • <a href="/cerez-politikasi" target="_blank" rel="noopener">Çerez Politikası</a> • <a href="/kullanim-kosullari" target="_blank" rel="noopener">Kullanım Koşulları</a> • <a href="/kabul-edilebilir-kullanim" target="_blank" rel="noopener">Kabul Edilebilir Kullanım</a> • <a href="/mesafeli-satis" target="_blank" rel="noopener">Mesafeli Satış Sözleşmesi</a> • <a href="/iade-iptal" target="_blank" rel="noopener">İptal ve İade</a> • <a href="/iletisim" target="_blank" rel="noopener">İletişim</a> • <a href="#" data-cookie-settings>Çerez tercihleri</a></div></div>
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
// 6502 sayılı Kanun: ödeme öncesi ön bilgilendirme + mesafeli satış sözleşmesi + (anında ifa edilen hizmette) cayma hakkı beyanı onayı
function checkout(plan){
 const st=S.settings,cur=st.currency||'TRY',api=apiUrl();
 if(!api)return toast('Scanner API adresi yapılandırılmamış','err');
 const b=st.billing||{};
 const freeNow=!!(PAYCFG&&PAYCFG.free&&!(cur==='TRY'?PAYCFG.iyzico:PAYCFG.stripe));
 if(cur==='TRY'&&!freeNow&&(!b.name||!b.address||!b.city)){toast('TL ödemesi için önce Fatura Bilgilerini doldurun','warn');location.hash='settings';return}
 $('#box').innerHTML=`<div class="mh"><h2 style="margin:0">Siparişi onayla</h2><button class="btn s" data-act="close">${ic('x')}</button></div>
 <p class="hint">${freeNow?'Paketi etkinleştirmeden önce':'Ödeme sayfasına yönlendirilmeden önce'} aşağıdaki belgeleri okuyup onaylamanız gerekir.</p>
 <label class="consent"><input type="checkbox" id="c1"><span><a href="/mesafeli-satis" target="_blank" rel="noopener">Ön Bilgilendirme Formu</a>'nu ve <a href="/mesafeli-satis" target="_blank" rel="noopener">Mesafeli Satış Sözleşmesi</a>'ni okudum, kabul ediyorum.</span></label>
 <label class="consent"><input type="checkbox" id="c2"><span>Hizmetin ödeme anında elektronik ortamda ifa edilmeye başlanmasını onaylıyorum ve bu nedenle <b>cayma hakkımın bulunmadığı</b> konusunda bilgilendirildiğimi kabul ediyorum. (<a href="/iade-iptal" target="_blank" rel="noopener">İptal ve İade</a>)</span></label>
 <button class="btn p w" id="cgo" type="button">${freeNow?'Paketi etkinleştir':'Ödemeye geç'}</button>`;
 $('#modal').classList.add('on');icons();
 $('#cgo').onclick=()=>{if(!$('#c1').checked||!$('#c2').checked)return toast('Devam etmek için iki onay kutusunu da işaretleyin','warn');close();doCheckout(plan)};
}
async function doCheckout(plan){
 const st=S.settings,cur=st.currency||'TRY',api=apiUrl(),b=st.billing||{};
 busy(true);
 try{
  const r=await fetch(api+'/api/checkout',{method:'POST',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({plan,cycle:st.cycle||'monthly',currency:cur,billing:b,consent:{distanceSales:true,withdrawalWaiver:true},returnPath:location.pathname})});
  const j=await r.json();if(!j.success)throw new Error(j.error||'İşlem tamamlanamadı');
  if(j.activated){await syncPlan();render();toast('Paketiniz etkinleştirildi: '+(P.PLANS[j.plan]?.name||j.plan));busy(false);return}
  if(!j.url)throw new Error('Ödeme sayfası alınamadı');
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
 if(!api){el.textContent='API adresi yok.';return}
 el.textContent='Bağlanıyor…';const t0=Date.now(),j=await fetchHealth(),ms=Date.now()-t0;
 el.textContent=j?`✔ Bağlandı (${ms} ms) • sürüm ${j.version} • TL ödeme: ${j.payments?.iyzico?'hazır':'yok'} • USD ödeme: ${j.payments?.stripe?'hazır':'yok'}`:'✘ Bağlanılamadı. Adresi kontrol edin; Render uyanıyor olabilir, 30 sn sonra tekrar deneyin.';
}
async function clearCache(){
 try{const rs=await navigator.serviceWorker?.getRegistrations();for(const r of rs||[])await r.unregister();for(const k of await caches.keys())await caches.delete(k)}catch{}
 location.reload();
}
addEventListener('beforeinstallprompt',e=>{e.preventDefault();DEFERRED=e;if(S&&location.hash==='#settings')render()});
addEventListener('appinstalled',()=>{DEFERRED=null;toast('Uygulama yüklendi');if(S)render()});

/* ---------- Tür'e özel analiz ekranları (v13) ----------
 * Her varlık türü kendi bölümleriyle gösterilir: özet kutucukları, kontrol listeleri, tablolar ve bulgu başına "ne yapmalı" önerisi.
 * Veri sunucudaki specificAnalysis alanından gelir; burada yalnızca gösterim yapılır. */
const NA='<span class="mu2">—</span>';
const fv=v=>{
 if(v===null||v===undefined||v==='')return NA;
 if(v===true)return'<span class="ok2">Evet</span>';
 if(v===false)return'<span class="bd2">Hayır</span>';
 if(Array.isArray(v))return v.length?v.map(x=>typeof x==='object'&&x?esc(JSON.stringify(x)):fv(x)).join(', '):NA;
 if(typeof v==='object')return esc(JSON.stringify(v));
 return esc(v)};
const msF=n=>n==null?NA:esc(Math.round(n))+' ms';
const kbF=n=>n==null?NA:esc(n)+' KB';
const dF=t=>{if(!t)return NA;const d=new Date(t);return isNaN(d)?esc(t):d.toLocaleDateString('tr-TR')};
const tn=b=>b===true?'ok':b===false?'bd':'na';
const thr=(v,g,w)=>v==null?'na':v<=g?'ok':v<=w?'wn':'bd';
const thrUp=(v,g,w)=>v==null?'na':v>=g?'ok':v>=w?'wn':'bd';
const scTone=n=>n==null?'na':n>=80?'ok':n>=50?'wn':'bd';
const kvt=rows=>{const r=rows.filter(Boolean);return r.length?`<table class="kv">${r.map(([k,v,raw])=>`<tr><td>${esc(k)}</td><td>${raw?v:fv(v)}</td></tr>`).join('')}</table>`:''};
const tile=(l,v,t)=>`<div class="tile ${t||''}"><span>${esc(l)}</span><b>${v}</b></div>`;
const tiles=a=>`<div class="tiles">${a.filter(Boolean).join('')}</div>`;
const sect=(t,i,b,h)=>b?`<div class="card an"><b class="ah">${ic(i)} ${esc(t)}</b>${h?`<div class="hint">${esc(h)}</div>`:''}${b}</div>`:'';
const chk=(label,st,detail)=>`<div class="chk ${st}"><i>${st==='ok'?'✓':st==='bd'?'✕':st==='wn'?'!':'–'}</i><span>${esc(label)}${detail!=null&&detail!==''?`<small>${detail}</small>`:''}</span></div>`;
const chips=(a,t)=>a&&a.length?`<div class="chipl">${a.map(x=>`<span class="cp ${t||''}">${esc(x)}</span>`).join('')}</div>`:'';
const listF=(a,max=12)=>a&&a.length?`<ul class="ul">${a.slice(0,max).map(x=>`<li>${esc(typeof x==='object'?JSON.stringify(x):x)}</li>`).join('')}${a.length>max?`<li class="mu2">… ve ${a.length-max} kayıt daha</li>`:''}</ul>`:'';
const noteBox=t=>t?`<div class="why"><b>Not:</b> ${esc(t)}</div>`:'';
const lenChk=(label,len,lo,hi)=>len==null||len===0?chk(label,'bd','Yok'):chk(label,len>=lo&&len<=hi?'ok':'wn',`${len} karakter • ideal ${lo}–${hi}`);
const mxF=a=>Array.isArray(a)?a.map(x=>x&&typeof x==='object'?`${x.priority??''} ${x.exchange||''}`.trim():String(x)):[];
const caaF=a=>Array.isArray(a)?a.map(x=>x&&typeof x==='object'?Object.entries(x).filter(([k])=>k!=='critical').map(([k,v])=>k+' '+v).join(' '):String(x)):[];
const soaF=s=>s?`${s.nsname||''} • serial ${s.serial||'-'} • yenileme ${s.refresh||'-'} sn`:null;

/* Bulgu başına öneri (finding anahtarı -> ne yapılmalı). Eşleşme yoksa bulgu tipine göre genel öneri verilir. */
const FIX={
web_down:'Sunucunun ve alan adının çalıştığını kontrol edin; hosting panelinden hata günlüklerine bakın.',web_slow:'Önbellek (cache), görsel sıkıştırma ve CDN kullanın; yavaş sorguları azaltın.',web_missing_title:'<head> içine 30–65 karakterlik bir <title> ekleyin.',web_missing_meta_description:'70–165 karakterlik bir meta description ekleyin.',web_missing_h1:'Sayfaya konuyu anlatan tek bir <h1> ekleyin.',
web_no_https:'SSL sertifikası kurup tüm trafiği HTTPS\'e yönlendirin (ücretsiz: Let\'s Encrypt).',web_tls_error:'Sertifikayı yenileyin ya da doğru alan adı için yeniden düzenletin.',web_ssl_expired:'Sertifikayı hemen yenileyin.',web_ssl_expiring:'Sertifikayı süresi dolmadan yenileyin; otomatik yenilemeyi açın.',web_soft_404:'Olmayan sayfalar için gerçek 404 durum kodu döndürün.',web_eol_php:'PHP sürümünü desteklenen en yeni sürüme yükseltin.',web_old_jquery:'jQuery\'yi 3.x sürümüne güncelleyin.',web_old_bootstrap:'Bootstrap\'ı 5.x sürümüne geçirin.',web_old_wordpress:'WordPress ve eklentileri güncelleyin.',web_parked:'Alan adını gerçek sitenize yönlendirin.',web_default_page:'Sunucudaki varsayılan sayfayı kendi sitenizle değiştirin.',web_www_inconsistent:'www ve çıplak alan adından birini diğerine 301 ile yönlendirin.',web_redirect_loop:'Yönlendirme kurallarını (htaccess/nginx/CDN) kontrol edin; döngüyü kırın.',web_suspended:'Hosting firmanızla hesabın askı durumunu kontrol edin.',
domain_expired:'Alan adını hemen yenileyin; süre dolunca başkası alabilir.',domain_expiring_critical:'Alan adını bugün yenileyin ve otomatik yenilemeyi açın.',domain_expiring_soon:'Alan adı yenilemesini planlayın; otomatik yenilemeyi açın.',domain_expiring:'Alan adı yenilemesini planlayın.',domain_missing_spf:'DNS\'e TXT kaydı olarak SPF ekleyin (ör. v=spf1 include:_spf.google.com ~all).',domain_missing_dmarc:'_dmarc.alanadi TXT kaydı ekleyin: v=DMARC1; p=quarantine; rua=mailto:...',domain_dmarc_policy_none:'DMARC politikasını önce quarantine, sonra reject yapın.',domain_missing_dnssec:'Kayıt kuruluşunuzda DNSSEC\'i etkinleştirip DS kaydını girin.',domain_missing_caa:'CAA kaydı ekleyerek sertifika verebilecek kuruluşları sınırlayın.',domain_transfer_unlocked:'Kayıt kuruluşu panelinden transfer kilidini açık (kilitli) duruma getirin.',domain_single_ns:'En az iki farklı nameserver kullanın.',domain_missing_mx:'E-posta kullanıyorsanız MX kayıtlarını ekleyin; kullanmıyorsanız null MX tanımlayın.',domain_takeover_risk:'Kullanılmayan servislere işaret eden CNAME kayıtlarını silin.',domain_dangling_cname:'Hedefi olmayan CNAME kayıtlarını silin ya da düzeltin.',domain_ip_blacklisted:'IP\'nin neden listelendiğini bulup liste sahibinden çıkarma talep edin.',domain_spf_allows_all:'SPF içindeki +all ifadesini ~all ya da -all yapın.',domain_spf_multiple_records:'Tek bir SPF kaydı bırakın; diğerlerini birleştirin.',domain_spf_too_many_lookups:'SPF include sayısını azaltın (en fazla 10 DNS sorgusu).',domain_dkim_weak_key:'DKIM anahtarını 2048 bit ile yeniden oluşturun.',domain_missing_mta_sts:'MTA-STS politikasını yayınlayın (e-posta aktarımında TLS zorunlu olur).',domain_missing_tls_rpt:'_smtp._tls TXT kaydı ile TLS-RPT raporlamasını açın.',domain_dmarc_no_reporting:'DMARC kaydına rua=mailto:... ekleyin; raporları izleyin.',
ssl_expired:'Sertifikayı hemen yenileyin.',ssl_expiring_soon:'Sertifikayı yenileyin; otomatik yenilemeyi (certbot/ACME) açın.',ssl_self_signed:'Güvenilir bir otoriteden (ör. Let\'s Encrypt) sertifika alın.',ssl_hostname_mismatch:'Sertifikaya bu alan adını (SAN) ekleterek yeniden düzenletin.',ssl_chain_incomplete:'Sunucuya ara sertifikaları (fullchain) da yükleyin.',ssl_tls_old_version:'TLS 1.2 ve 1.3\'ü etkinleştirin; 1.0/1.1\'i kapatın.',ssl_tls_legacy:'Eski TLS 1.0/1.1\'i kapatın.',ssl_weak_key:'En az 2048 bit RSA ya da ECDSA P-256 anahtar kullanın.',ssl_weak_signature:'SHA-256 ya da üzeri imza algoritmalı sertifika alın.',ssl_hsts_missing:'Strict-Transport-Security başlığını ekleyin.',ssl_no_tls13:'Sunucuda TLS 1.3\'ü etkinleştirin.',ssl_no_ocsp_stapling:'OCSP stapling\'i etkinleştirin (hız ve gizlilik).',ssl_www_not_covered:'Sertifikayı hem alanadi.com hem www.alanadi.com için alın.',
hosting_no_cdn_waf:'Cloudflare gibi bir CDN/WAF arkasına geçin.',hosting_no_ipv6:'Sağlayıcınızdan IPv6 (AAAA) desteği isteyin.',hosting_single_ip:'Yedek sunucu ya da yük dengeleyici düşünün.',hosting_slow_response:'Sunucu kaynaklarını ve önbelleği gözden geçirin.',hosting_no_https_redirect:'HTTP isteklerini HTTPS\'e 301 ile yönlendirin.',hosting_tls_old:'TLS 1.2+ kullanın.',
server_exposed_port:'Bu port gerçekten internete açık olmalı mı? Güvenlik duvarından (firewall) yalnızca gerekli IP\'lere izin verin.',server_ssh_outdated:'OpenSSH\'ı güncelleyin; parola yerine anahtar ile giriş kullanın.',server_ssh_v1:'SSH protokol 2\'ye geçin.',server_ftp_without_ssh:'FTP yerine SFTP kullanın.',server_plain_mail_ports:'Şifresiz POP3/IMAP\'ı kapatıp SSL portlarını kullanın.',server_unreachable:'Sunucunun açık olduğundan ve güvenlik duvarının taramaya izin verdiğinden emin olun.',
seo_missing_title:'30–65 karakterlik özgün bir <title> yazın.',seo_title_length:'Başlığı 30–65 karaktere getirin.',seo_missing_description:'70–165 karakterlik meta description ekleyin.',seo_description_length:'Açıklamayı 70–165 karaktere getirin.',seo_missing_h1:'Sayfaya tek bir <h1> ekleyin.',seo_multiple_h1:'Tek <h1> bırakın; diğerlerini <h2> yapın.',seo_images_missing_alt:'Görsellere anlamlı alt metin ekleyin.',seo_thin_content:'Sayfaya en az 300 kelimelik özgün içerik ekleyin.',seo_noindex:'Arama motorlarında görünmesini istiyorsanız noindex etiketini kaldırın.',seo_robots_blocks_all:'robots.txt içindeki "Disallow: /" satırını kaldırın.',seo_missing_canonical:'<link rel="canonical"> ekleyin.',seo_missing_robots:'Kökte bir robots.txt oluşturun.',seo_missing_sitemap:'sitemap.xml oluşturup robots.txt içinde belirtin; Search Console\'a gönderin.',seo_not_https:'Siteyi HTTPS\'e taşıyın.',seo_missing_viewport:'<meta name="viewport" content="width=device-width, initial-scale=1"> ekleyin.',seo_missing_lang:'<html lang="tr"> gibi dil belirtin.',seo_missing_favicon:'Bir favicon ekleyin.',seo_hreflang_no_default:'hreflang listesine x-default ekleyin.',seo_missing_open_graph:'og:title, og:description, og:image etiketlerini ekleyin.',seo_missing_twitter_card:'twitter:card etiketlerini ekleyin.',seo_missing_structured_data:'JSON-LD ile Organization / Product / Article gibi yapısal veri ekleyin.',seo_structured_data_invalid:'JSON-LD\'yi Google Rich Results Test ile doğrulayın.',seo_sitemap_broken_urls:'Sitemap\'teki erişilemeyen adresleri temizleyin.',seo_client_rendered:'İçeriği sunucu tarafında (SSR/ön oluşturma) üretin.',seo_parked_page:'Alan adını gerçek içeriğe yönlendirin.',seo_few_internal_links:'Sayfalar arası iç bağlantıları artırın.',
security_missing_hsts:'Strict-Transport-Security: max-age=31536000; includeSubDomains ekleyin.',security_hsts_short:'HSTS max-age değerini en az 15552000 (6 ay) yapın.',security_missing_csp:'Content-Security-Policy başlığı tanımlayın.',security_csp_unsafe:'CSP\'den unsafe-inline / unsafe-eval ifadelerini kaldırın (nonce/hash kullanın).',security_csp_weak:'CSP\'de * , data: ve http: kaynaklarını daraltın.',security_missing_clickjacking:'X-Frame-Options: DENY ya da CSP frame-ancestors ekleyin.',security_missing_nosniff:'X-Content-Type-Options: nosniff ekleyin.',security_missing_referrer_policy:'Referrer-Policy: strict-origin-when-cross-origin ekleyin.',security_missing_permissions_policy:'Permissions-Policy ile kamera, mikrofon, konum gibi özellikleri kapatın.',security_version_disclosure:'Server / X-Powered-By başlıklarındaki sürüm bilgisini gizleyin.',security_no_https_redirect:'HTTP\'den HTTPS\'e 301 yönlendirme ekleyin.',security_not_https:'Siteyi HTTPS\'e taşıyın.',security_mixed_content:'Sayfadaki http:// kaynakları https:// yapın.',security_cookie_flags:'Çerezlere Secure, HttpOnly ve SameSite ekleyin.',security_cookie_samesite_none:'SameSite=None kullanan çerezlere Secure ekleyin.',security_directory_listing:'Sunucuda dizin listelemeyi (autoindex / Options -Indexes) kapatın.',security_no_sri:'Harici script/stil etiketlerine integrity (SRI) ekleyin.',security_missing_security_txt:'/.well-known/security.txt dosyası oluşturun.',security_tls_legacy_enabled:'TLS 1.0/1.1\'i kapatın.',security_insecure_form:'Form ve parola alanlarını yalnızca HTTPS üzerinden sunun.',security_cert_expired:'Sertifikayı hemen yenileyin.',security_exposed:'Bu dosyayı hemen herkese kapatın; içinde gizli bilgi varsa anahtarları/parolaları değiştirin.',
perf_slow_ttfb:'Sunucu önbelleği, daha hızlı hosting ve veritabanı sorgu iyileştirmesi deneyin.',perf_very_slow_ttfb:'Sunucu yanıtı çok yavaş: hosting planını, PHP/DB ayarlarını ve önbelleği inceleyin.',perf_slow_load:'Görselleri küçültün, script/stilleri birleştirip erteleyin.',perf_no_compression:'Sunucuda gzip ya da brotli sıkıştırmayı açın.',perf_no_http2:'Sunucuda HTTP/2 (ve mümkünse HTTP/3) açın.',perf_redirect_chain:'Yönlendirmeleri tek adıma indirin.',perf_heavy_page:'Sayfa boyutunu 500 KB altına çekin: görsel optimizasyonu, gereksiz script temizliği.',perf_render_blocking_scripts:'Scriptlere defer ya da async ekleyin.',perf_too_many_scripts:'Harici script sayısını azaltın.',perf_no_lazy_loading:'Görsellere loading="lazy" ekleyin.',perf_weak_caching:'Statik dosyalara Cache-Control: max-age=31536000 verin.',perf_assets_not_compressed:'JS/CSS dosyalarını sıkıştırın (gzip/brotli).',perf_heavy_js:'JavaScript\'i bölün, kullanılmayan kodu temizleyin.',perf_heavy_css:'Kritik CSS\'i ayırın, kullanılmayan stilleri silin.',perf_images_no_dimensions:'<img> etiketlerine width ve height ekleyin (düzen kayması önlenir).',perf_many_third_parties:'Üçüncü taraf script sayısını azaltın.',perf_large_dom:'DOM boyutunu küçültün (2500 öğe altı).',perf_large_images:'Büyük görselleri WebP/AVIF\'e çevirip küçültün.',perf_slow_dns:'Daha hızlı bir DNS sağlayıcısı kullanın.',perf_slow_tls:'TLS 1.3 ve OCSP stapling açın.',
uptime_down:'Sunucuyu ve alan adını hemen kontrol edin.',uptime_intermittent:'Aralıklı kesintiler: sunucu kaynaklarını (RAM/CPU) ve günlükleri inceleyin.',uptime_slow_response:'Önbellek ve sunucu kaynaklarını gözden geçirin.',uptime_high_p95:'Yavaş istekleri günlüklerden bulup optimize edin.',uptime_unstable_latency:'Paylaşımlı hosting ya da yoğun saatlerde kaynak sıkıntısı olabilir.',uptime_slow_dns:'Daha hızlı bir DNS sağlayıcısı kullanın.',uptime_slow_connect:'Sunucu konumunu ve ağ yolunu kontrol edin; CDN kullanın.',uptime_server_errors:'5xx hatalarının günlük kayıtlarına bakın.',
api_unreachable:'API sunucusunun açık olduğunu ve adresin doğru olduğunu kontrol edin.',api_server_error:'API günlüklerinde 5xx hatasının nedenini bulun.',api_slow_response:'Veritabanı sorgularını ve önbelleği iyileştirin.',api_not_https:'API\'yi yalnızca HTTPS üzerinden sunun.',api_cors_credentials:'Access-Control-Allow-Origin için belirli alan adları verin; * ile kimlik bilgisini birlikte kullanmayın.',api_cors_reflects_origin:'CORS\'ta gelen Origin\'i olduğu gibi yansıtmayın; izin listesi kullanın.',api_missing_nosniff:'X-Content-Type-Options: nosniff ekleyin.',api_missing_hsts:'HSTS başlığı ekleyin.',api_version_disclosure:'Sürüm bilgisi içeren başlıkları gizleyin.',api_invalid_json:'Yanıt gövdesini geçerli JSON yapın.',api_not_json:'Content-Type: application/json ile JSON döndürün.',api_no_rate_limit_headers:'Hız sınırı uygulayın ve RateLimit-* başlıklarını ekleyin.',api_error_not_json:'Hata yanıtlarını da JSON biçiminde döndürün.',api_no_versioning:'/v1 gibi sürümleme kullanın.',api_error_leaks_stacktrace:'Üretimde hata ayrıntılarını/stack trace\'i istemciye göndermeyin.',api_debug_headers:'Debug başlıklarını üretimde kapatın.',api_unknown_route_status:'Olmayan yollar için 404 döndürün.',api_no_compression:'Yanıt sıkıştırmayı (gzip/br) açın.',
analytics_no_tag:'Sitenize GA4 (gtag.js) ya da Google Tag Manager kodunu ekleyin.',analytics_measurement_id_mismatch:'Sitedeki etiketin Ölçüm Kimliği ile buraya girdiğiniz kimliği eşitleyin.',analytics_legacy_ua:'Universal Analytics (UA-) kapatıldı; GA4\'e geçin.',analytics_tag_script_unreachable:'Etiket betiğinin engellenmediğini (CSP, reklam engelleyici, ağ) kontrol edin.',analytics_not_https:'Siteyi HTTPS\'e taşıyın.',analytics_measurement_id_invalid:'Ölçüm Kimliği G- ile başlamalı (ör. G-ABCDE12345).',analytics_gtm_only:'GTM içinde GA4 yapılandırma etiketinin yayında olduğunu GTM Önizleme ile doğrulayın.',
mobile_not_found:'Uygulama mağazadan kalkmış olabilir; mağaza konsolundan yayın durumunu kontrol edin.',mobile_low_rating:'Düşük puanlı yorumları inceleyip sorunları giderin; mutlu kullanıcılardan değerlendirme isteyin.',mobile_few_ratings:'Uygulama içinde uygun anda değerlendirme isteyin.',mobile_stale:'Uygulamayı güncelleyip yeni sürüm yayınlayın.',mobile_aging:'Yakında bir güncelleme yayınlamayı planlayın.',mobile_low_current_rating:'Son sürümde ortaya çıkan hataları giderin.',mobile_old_min_os:'Minimum işletim sistemi sürümünü yükseltmeyi düşünün.',
repo_not_found:'Depo adını kontrol edin; özel (private) depolar taranamaz.',repo_archived:'Depo arşivli: devam edecekse arşivden çıkarın.',repo_inactive:'Depo bir yıldır hareketsiz: bakım planı yapın ya da arşivleyin.',repo_stale:'Son commit 3 aydan eski: bakım durumunu gözden geçirin.',repo_no_license:'LICENSE dosyası ekleyin (MIT, Apache-2.0 vb.).',repo_no_readme:'Kurulum ve kullanımı anlatan bir README ekleyin.',repo_no_contributing:'CONTRIBUTING.md ve davranış kuralları ekleyin.',repo_many_open_issues:'Açık issue\'ları sınıflandırıp kapatın.',repo_no_releases:'Sürüm etiketleri (release) yayınlayın.',repo_secret_file_committed:'Dosyayı depodan ve geçmişten silin, içindeki tüm anahtar/parolaları HEMEN değiştirin.',repo_no_security_policy:'SECURITY.md ekleyip açık bildirim yolunu belirtin.',repo_no_ci:'GitHub Actions ile otomatik test/derleme kurun.',repo_no_lockfile:'Bağımlılık kilit dosyasını (package-lock, poetry.lock vb.) depoya ekleyin.',repo_no_dependency_updates:'Dependabot ya da Renovate\'i açın.',repo_single_contributor:'Başka birine depo erişimi/bilgisi verin (bus factor).',repo_issues_disabled:'Geri bildirim için Issues\'ı açın.',
brand_base_not_registered:'Ana alan adınız DNS\'te görünmüyor; kayıt ve DNS ayarını kontrol edin.',brand_lookalike_phishing:'ACİL: Benzer alan adı kimlik avı yapıyor olabilir. Barındırıcıya ve Google Safe Browsing\'e bildirin; hukuki yollara başvurun.',brand_lookalike_active:'Benzer alan adındaki siteyi inceleyin; marka ihlali varsa ihbar edin.',brand_lookalike_registered:'Benzer alan adlarını izleyin; kritik olanları satın almayı düşünün.',brand_keyword_registered:'login-/secure- gibi alan adlarını izleyin; ihlal varsa ihbar edin.',brand_tld_thirdparty:'Başkasında olan uzantıları izleyin; gerekirse UDRP/ihtilaf süreci başlatın.',brand_tld_unprotected:'Önemli uzantıları (.net, .com.tr, hedef ülke uzantıları) satın alın.',
saas_expired:'Aboneliği yenileyin ya da kapatın; kullanıcı kaybı yaşanmasın.',saas_expiring_soon:'Yenileme öncesi hâlâ gerekli olup olmadığına karar verin.',saas_missing_renewal:'Yenileme tarihini girerek takibi etkinleştirin.',saas_usage:'Kullanım kritik: paketi yükseltmeyi düşünün.',saas_usage_high:'Kullanım yüksek: kotayı aşmadan paketi büyütün.',saas_underused:'Kullanım çok düşük: daha ucuz pakete geçin ya da iptal edin.',saas_manual_renewal_due:'Otomatik yenileme kapalı: tarihi kaçırmamak için hatırlatıcı kurun.',
scan_error:'Biraz sonra tekrar deneyin; sürerse adresi kontrol edin.',scan_timeout:'Hedef yavaş yanıtlıyor; biraz sonra tekrar deneyin.'};
const fixT=f=>{
 const k=String(f).replace(/^finding_/,'').replace(/_(critical|warning|info)$/,'');
 if(FIX[k])return FIX[k];
 let m;
 if((m=k.match(/^server_exposed_port_/)))return FIX.server_exposed_port;
 if((m=k.match(/^security_exposed_/)))return FIX.security_exposed;
 if((m=k.match(/^brand_\d+_(lookalike_phishing|lookalike_active|lookalike_registered|keyword_registered|tld_thirdparty|tld_unprotected)$/)))return FIX['brand_'+m[1]];
 if((m=k.match(/^(web|seo|security|perf|api|hosting|uptime)_(dns_failure|connection_refused|timeout|tls_failure|connection_reset|network_unreachable|redirect_loop|unreachable)$/)))return({dns_failure:'Alan adının DNS kayıtlarını (A/AAAA/NS) kontrol edin.',connection_refused:'Sunucu servisinin çalıştığını ve portun açık olduğunu kontrol edin.',timeout:'Sunucu yanıt vermiyor: yük, güvenlik duvarı ve ağ ayarlarına bakın.',tls_failure:'SSL/TLS ayarlarını ve sertifikayı kontrol edin.',connection_reset:'Güvenlik duvarı/WAF bağlantıyı kesiyor olabilir.',network_unreachable:'Sunucunun ağ bağlantısını kontrol edin.',redirect_loop:'Yönlendirme kurallarındaki döngüyü düzeltin.',unreachable:'Sunucunun ve DNS\'in çalıştığını kontrol edin.'})[m[2]];
 return null};

/* Bulgular: önem sırasına göre, her birinin altında öneri */
function findingsHtml(f){
 if(!f.length)return'<div class="hint">Sorun bulunmadı</div>';
 return f.map(x=>{const fx=sev(x)==='mu'?null:fixT(x);return`<div class="find2"><div class="find"><span class="badge ${sev(x)}">${sevL[sev(x)]}</span><span>${esc(finT(x))}</span></div>${fx?`<div class="fix">${ic('wrench')} ${esc(fx)}</div>`:''}</div>`}).join('')}

/* ---- Tür çözümleyicileri ---- */
const AN={};
AN.web=sa=>{
 if(sa.botProtection?.detected)return sect('Bot koruması','shield',kvt([['Koruma sağlayıcı',sa.botProtection.provider],['HTTP durum',sa.status],['Sunucu',sa.server]])+noteBox(sa.botProtection.note));
 const sh=sa.securityHeaders||{},rb=sa.robots||{},sm=sa.sitemap||{},c=sa.content||{},l=c.links||{};
 let h=tiles([tile('HTTP durum',esc(sa.status??'—'),!sa.status||sa.status>=500?'bd':sa.status>=400?'wn':'ok'),tile('Yanıt süresi',msF(sa.responseTimeMs),thr(sa.responseTimeMs,800,2000)),tile('İlk bayt (TTFB)',msF(sa.ttfbMs),thr(sa.ttfbMs,600,1500)),tile('Kelime sayısı',esc(sa.wordCount??'—'),sa.wordCount==null?'na':sa.wordCount>=300?'ok':'wn')]);
 h+=sect('Erişim ve yönlendirme','globe',kvt([['Girilen adres',sa.url],['Son adres',sa.finalUrl],['HTTPS ile açılıyor',sa.httpOnly===undefined?null:!sa.httpOnly],['Denenen varyantlar',sa.triedVariants],['Sunucu',sa.server]])+(sa.redirectChain&&sa.redirectChain.length>1?`<div class="hint">Yönlendirme zinciri</div>${listF(sa.redirectChain)}`:''));
 if(sa.pageState&&sa.pageState.length)h+=sect('Sayfa durumu','triangle-alert',chips(sa.pageState,'wn'),'Sayfada algılanan olağan dışı durumlar');
 h+=sect('Temel SEO','search',lenChk('Sayfa başlığı (title)',(sa.title||'').length,30,65)+(sa.title?`<div class="hint">${esc(sa.title)}</div>`:'')+lenChk('Meta açıklaması',(sa.metaDescription||'').length,70,165)+chk('Tek H1 başlığı',sa.h1Count===1?'ok':sa.h1Count?'wn':'bd',`${sa.h1Count??0} adet`)+chk('robots.txt',rb.exists?(rb.blocksAll?'bd':'ok'):'wn',rb.exists?(rb.blocksAll?'Tüm siteyi engelliyor!':'Var'):'Yok')+chk('sitemap.xml',sm.exists?(sm.valid?'ok':'wn'):'wn',sm.exists?`${sm.urlCount??0} adres`:'Yok'));
 h+=sect('Güvenlik başlıkları','shield-check',[['HSTS',sh.hsts],['Content-Security-Policy',sh.csp],['X-Frame-Options',sh.xFrame],['X-Content-Type-Options',sh.xContentType],['Referrer-Policy',sh.referrerPolicy],['Permissions-Policy',sh.permissionsPolicy]].map(([n,v])=>chk(n,v?'ok':'wn',v?'Tanımlı':'Eksik')).join('')+(sa.cookies&&sa.cookies.length?`<div class="hint">Çerezler</div>${listF(sa.cookies)}`:''));
 const tech=(sa.technologies||[]).map(t=>t.name+(t.version?' '+t.version:'')+(t.category?' ('+t.category+')':''));
 h+=sect('Kullanılan teknolojiler','cpu',tech.length?chips(tech):chips(sa.techStack),'Başlık ve sayfa kaynağından tahmin edilir');
 h+=sect('Sayfa yapısı','layout-grid',kvt([['HTML boyutu',c.htmlKB!=null?c.htmlKB+' KB':null],['Görsel',c.images],['Script',c.scripts],['Stil dosyası',c.stylesheets],['Üçüncü taraf alan adı',c.thirdPartyHosts],['İç bağlantı',l.internal],['Dış bağlantı',l.external],['Boş href',l.emptyHref]]));
 return h};
AN.seo=sa=>{
 const rd=sa.robotsDetails||{},sd=sa.sitemapDetails||{},im=sa.images||{},l=sa.links||{},ch=sa.checks||{};
 let h=tiles([tile('Başarılı kontrol',esc((ch.passed??'—')+' / '+(ch.total??'—')),ch.total?scTone(Math.round(ch.passed/ch.total*100)):'na'),tile('Başlık uzunluğu',esc(sa.titleLength??'—'),sa.titleLength>=30&&sa.titleLength<=65?'ok':'wn'),tile('Açıklama uzunluğu',esc(sa.metaDescriptionLength??'—'),sa.metaDescriptionLength>=70&&sa.metaDescriptionLength<=165?'ok':'wn'),tile('Kelime',esc(sa.wordCount??'—'),sa.wordCount>=300?'ok':'wn')]);
 if(sa.pageState&&sa.pageState.length)h+=sect('Sayfa durumu','triangle-alert',chips(sa.pageState,'wn'));
 if(sa.clientRenderedShell)h+=noteBox('Sayfa içeriği JavaScript ile oluşturuluyor; arama motoru botları içeriği eksik görebilir.');
 h+=sect('Başlık ve açıklama','type',lenChk('Title',sa.titleLength,30,65)+(sa.title?`<div class="hint">${esc(sa.title)}</div>`:'')+lenChk('Meta description',sa.metaDescriptionLength,70,165)+(sa.metaDescription?`<div class="hint">${esc(sa.metaDescription)}</div>`:''));
 h+=sect('Başlık yapısı','heading',chk('H1',sa.h1Count===1?'ok':sa.h1Count?'wn':'bd',`${sa.h1Count??0} adet`+(sa.h1&&sa.h1[0]?' • '+esc(sa.h1[0]):''))+kvt([['H2 sayısı',sa.h2Count],['H3 sayısı',sa.h3Count],['Sayfa dili (lang)',sa.htmlLang]]));
 h+=sect('İndeksleme','list-checks',chk('Canonical',sa.canonical?'ok':'wn',sa.canonical?esc(sa.canonical):'Yok')+chk('noindex yok',/noindex/i.test((sa.robotsMeta||'')+(sa.xRobotsTag||''))?'bd':'ok',sa.robotsMeta||sa.xRobotsTag||'Engel yok')+chk('robots.txt',rd.exists?(rd.blocksAll||rd.blocksGooglebot?'bd':'ok'):'wn',rd.exists?(rd.blocksAll?'Tüm siteyi engelliyor':rd.blocksGooglebot?'Googlebot engelli':`Var • ${rd.groups??0} grup • ${rd.sitemapDirectives??0} sitemap satırı`):'Yok')+chk('sitemap.xml',sd.exists?(sd.valid?'ok':'wn'):'wn',sd.exists?`${sd.urlCount??0} adres${sd.isIndex?' (indeks)':''}${sd.otherHost?' • başka alan adı içeriyor':''}`:'Yok'));
 h+=sect('Çok dilli / çok ülkeli','languages',kvt([['hreflang sayısı',sa.hreflangCount],['hreflang değerleri',sa.hreflang]]),'Birden fazla dil ya da ülkede yayın yapıyorsanız hreflang gerekir');
 h+=sect('Sosyal paylaşım ve yapısal veri','share-2',chk('Open Graph',sa.openGraph?'ok':'wn',sa.openGraph?'Var':'Eksik')+chk('Twitter Card',sa.twitterCard?'ok':'wn',sa.twitterCard?'Var':'Eksik')+chk('JSON-LD yapısal veri',sa.structuredDataBlocks?'ok':'wn',sa.structuredDataBlocks?`${sa.structuredDataBlocks} blok`:'Yok')+chips(sa.structuredDataTypes));
 h+=sect('Görseller ve bağlantılar','image',chk('Görsel alt metinleri',!im.total?'na':im.missingAlt?(im.missingAlt/im.total>.5?'bd':'wn'):'ok',im.total?`${im.total} görselden ${im.missingAlt||0} tanesinde alt yok`:'Görsel yok')+kvt([['Lazy-load görsel',im.lazy],['İç bağlantı',l.internal],['Dış bağlantı',l.external],['Boş href',l.emptyHref]]));
 return h};
AN.security=sa=>{
 const ex=sa.exposedFiles||[],mc=sa.mixedContent||{},ch=sa.checks||{},ce=sa.certificate;
 let h=tiles([tile('HTTPS',sa.https?'Var':'Yok',sa.https?'ok':'bd'),tile('HSTS süresi',sa.hsts?esc(sa.hstsMaxAgeDays)+' gün':'Yok',sa.hsts?(sa.hstsMaxAgeDays>=180?'ok':'wn'):'bd'),tile('Açıkta dosya',esc(ex.length),ex.length?'bd':'ok'),tile('Başarılı kontrol',esc((ch.passed??'—')+' / '+(ch.total??'—')),ch.total?scTone(Math.round(ch.passed/ch.total*100)):'na')]);
 h+=sect('Aktarım güvenliği','lock',chk('HTTPS',sa.https?'ok':'bd',sa.https?'Aktif':'Site şifresiz')+chk('HSTS',sa.hsts?(sa.hstsMaxAgeDays>=180?'ok':'wn'):'bd',sa.hsts?`${sa.hstsMaxAgeDays} gün`:'Yok')+chk('HTTP → HTTPS yönlendirme',sa.httpToHttpsRedirect==null?'na':sa.httpToHttpsRedirect?'ok':'bd')+chk('Karışık içerik',(mc.active||mc.passive)?(mc.active?'bd':'wn'):'ok',`${mc.active||0} aktif, ${mc.passive||0} pasif`)+chk('Eski TLS (1.0/1.1) kapalı',sa.legacyTlsEnabled==null?'na':sa.legacyTlsEnabled?'bd':'ok'));
 if(ce&&typeof ce==='object')h+=sect('Sertifika','badge-check',kvt(Object.entries(ce).filter(([k])=>!/^(chain|raw)/i.test(k)).map(([k,v])=>[k,v])));
 h+=sect('Başlıklar ve bilgi sızıntısı','shield-check',chk('Content-Security-Policy',sa.csp?'ok':'wn',sa.csp?'Tanımlı':'Eksik')+chk('Sunucu sürümü gizli',sa.serverHeader&&/\d/.test(sa.serverHeader)?'wn':'ok',sa.serverHeader||'Başlık yok')+chk('X-Powered-By gizli',sa.poweredBy?'wn':'ok',sa.poweredBy||'')+chk('security.txt',sa.securityTxt?'ok':'wn',sa.securityTxt?'Var':'Yok')+chk('Harici scriptlerde SRI',sa.thirdPartyScriptsWithoutSri?'wn':'ok',sa.thirdPartyScriptsWithoutSri?`${sa.thirdPartyScriptsWithoutSri} scriptte integrity yok`:'Tamam'));
 h+=sect('Çerezler','cookie',sa.cookies&&sa.cookies.length?listF(sa.cookies):'<div class="hint">Çerez ayarlanmıyor</div>');
 h+=sect('Açıkta kalan dosyalar','file-warning',(ex.length?listF(ex,30):chk('Hassas dosya bulunamadı','ok',`${sa.checkedFiles||0} yaygın yol denendi`))+'<div class="hint">.env, .git, yedek, phpinfo, veritabanı dökümü gibi yollar denenir.</div>');
 return h};
AN.performance=sa=>{
 const ch=sa.checks||{};
 let h=tiles([tile('İlk bayt (TTFB)',msF(sa.ttfbMs),thr(sa.ttfbMs,600,1500)),tile('Toplam yükleme',msF(sa.totalLoadMs),thr(sa.totalLoadMs,3000,6000)),tile('Sayfa ağırlığı',kbF(sa.measuredWeightKB),thr(sa.measuredWeightKB,500,1500)),tile('Sıkıştırma',sa.compression?esc(sa.compression):'Yok',sa.compression?'ok':'wn')]);
 h+=sect('Sunucu ve ağ','server',kvt([['TTFB örnekleri',sa.ttfbSamplesMs?sa.ttfbSamplesMs.join(' / ')+' ms':null],['DNS çözümleme',sa.dnsLookupMs!=null?sa.dnsLookupMs+' ms':null],['TLS el sıkışma',sa.tlsHandshakeMs!=null?sa.tlsHandshakeMs+' ms':null],['Protokol',sa.protocol],['TLS sürümü',sa.tlsVersion],['HTTP/3 duyuruluyor',sa.http3Advertised],['Yönlendirme',sa.redirectHops!=null?sa.redirectHops+' adım ('+(sa.redirectChainMs||0)+' ms)':null]]));
 h+=sect('Sayfa kaynakları','package',kvt([['HTML (aktarılan / ham)',sa.htmlTransferKB!=null?sa.htmlTransferKB+' / '+sa.htmlRawKB+' KB':null],['JavaScript',sa.jsKB!=null?sa.jsKB+' KB':null],['CSS',sa.cssKB!=null?sa.cssKB+' KB':null],['Örneklenen görseller',sa.imageKBSampled!=null?sa.imageKBSampled+' KB':null],['Harici script',sa.externalScripts],['Bloklayan script',sa.renderBlockingScripts],['Stil dosyası',sa.stylesheets],['Görsel',sa.images],['Lazy-load görsel',sa.lazyImages],['Boyutsuz görsel',sa.imagesWithoutDimensions],['DOM öğesi',sa.domNodes]]));
 h+=sect('Üçüncü taraf kaynaklar','plug',chips(sa.thirdPartyHosts)||'<div class="hint">Yok</div>');
 h+=sect('Örneklenen dosyalar','files',listF(sa.sampledAssets),'Yanıt boyutu, sıkıştırma ve önbellek durumu');
 return h+noteBox(sa.note)};
AN.uptime=sa=>{
 let h=tiles([tile('Başarı oranı',esc(sa.successRatePct??'—')+'%',thrUp(sa.successRatePct,100,80)),tile('Ortalama',msF(sa.avgMs),thr(sa.avgMs,600,1500)),tile('p95 (yavaş %5)',msF(sa.p95Ms),thr(sa.p95Ms,1000,2500)),tile('Dalgalanma',msF(sa.jitterMs),thr(sa.jitterMs,150,500))]);
 h+=sect('Deneme sonuçları','activity',`<div class="spark">${(sa.statusCodes||[]).map(c=>`<span class="cp ${c>=500||!c?'bd':c>=400?'wn':'ok'}">${esc(c||'ERR')}</span>`).join('')}</div>`+kvt([['Deneme sayısı',sa.samples],['En hızlı',sa.minMs!=null?sa.minMs+' ms':null],['Ortanca',sa.medianMs!=null?sa.medianMs+' ms':null],['En yavaş',sa.maxMs!=null?sa.maxMs+' ms':null]])+(sa.failures&&sa.failures.length?`<div class="hint">Başarısızlıklar</div>${listF(sa.failures)}`:''));
 h+=sect('Bağlantı süreleri','network',kvt([['DNS çözümleme',sa.dnsLookupMs!=null?sa.dnsLookupMs+' ms':null],['TCP bağlantı',sa.tcpConnectMs!=null?sa.tcpConnectMs+' ms':null],['TLS el sıkışma',sa.tlsHandshakeMs!=null?sa.tlsHandshakeMs+' ms':null]]));
 return h+noteBox(sa.note)};
AN.api=sa=>{
 const co=sa.cors||{},ch=sa.checks||{};
 let h=tiles([tile('HTTP durum',esc(sa.status??'—'),!sa.status||sa.status>=500?'bd':sa.status>=400?(sa.authRequired?'wn':'bd'):'ok'),tile('Yanıt süresi',msF(sa.responseTimeMs),thr(sa.responseTimeMs,500,1500)),tile('Ortanca',msF(sa.medianResponseMs),thr(sa.medianResponseMs,500,1500)),tile('Başarılı kontrol',esc((ch.passed??'—')+' / '+(ch.total??'—')),ch.total?scTone(Math.round(ch.passed/ch.total*100)):'na')]);
 h+=sect('Yanıt','braces',chk('Geçerli JSON',sa.validJson==null?'na':sa.validJson?'ok':'wn',sa.contentType||'')+chk('Kimlik doğrulama',sa.authRequired?'wn':'ok',sa.authRequired?'401/403: korumalı (beklenen olabilir)':'Doğrulama istemiyor')+chk('Sıkıştırma',sa.compression?'ok':'wn',sa.compression||'Yok')+chk('Olmayan yol için 404',sa.unknownRouteStatus===404?'ok':'wn',sa.unknownRouteStatus!=null?'Dönen kod: '+sa.unknownRouteStatus:'')+kvt([['Son adres',sa.finalUrl],['Sunucu',sa.server],['Yönlendirme',sa.redirects],['JSON yapısı',sa.jsonShape]]));
 h+=sect('CORS','shuffle',chk('Rastgele Origin yansıtılmıyor',co.reflectsArbitraryOrigin?'bd':'ok')+chk('Kimlik bilgisi + geniş izin yok',co.allowCredentials&&(co.allowOrigin==='*'||co.reflectsArbitraryOrigin)?'bd':'ok')+kvt([['Allow-Origin',co.allowOrigin],['Allow-Credentials',co.allowCredentials],['Allow-Methods',co.allowMethods]]));
 h+=sect('Hız sınırı','gauge',sa.rateLimitHeaders&&sa.rateLimitHeaders.length?chips(sa.rateLimitHeaders,'ok'):chk('Rate-limit başlıkları','wn','Bulunamadı'));
 return h};
AN.analytics=sa=>{
 const hl=sa.health||{},pr=sa.property||{};
 let h=tiles([tile('Etiket',hl.tagDetected?esc(hl.tagType||'Var'):'Yok',hl.tagDetected?'ok':'bd'),tile('Kimlik eşleşmesi',hl.measurementIdMatches==null?'—':hl.measurementIdMatches?'Evet':'Hayır',tn(hl.measurementIdMatches)),tile('Etiket betiği',hl.tagScriptReachable==null?'—':hl.tagScriptReachable?'Erişilebilir':'Erişilemiyor',tn(hl.tagScriptReachable)),tile('Veri akışı',hl.dataReceiving==null?'Bağlı değil':hl.dataReceiving?'Var':'Yok','na')]);
 h+=sect('Sitedeki kurulum','bar-chart-3',chk('GA4 / GTM etiketi sitede',hl.tagDetected?'ok':'bd',hl.tagType||'')+chk('Girilen ölçüm kimliği sitedeki etiketle aynı',hl.measurementIdMatches==null?'na':hl.measurementIdMatches?'ok':'bd')+chk('Etiket betiğine erişilebiliyor',hl.tagScriptReachable==null?'na':hl.tagScriptReachable?'ok':'wn')+chk('Eski UA- etiketi yok',pr.legacyIds&&pr.legacyIds.length?'wn':'ok',pr.legacyIds&&pr.legacyIds.length?pr.legacyIds.join(', '):''));
 h+=sect('Mülk bilgisi','tag',kvt([['Sağlayıcı',pr.provider],['Girilen ölçüm kimliği',pr.measurementId],['Mülk adı',pr.propertyName],['Sitede bulunan kimlikler',pr.detectedMeasurementIds],['GTM konteynerleri',pr.gtmContainers],['Eski (UA-) kimlikler',pr.legacyIds]]));
 h+=sect('Canlı trafik','users',kvt([['Son 24 saat aktif kullanıcı',sa.traffic?.activeUsers24h],['Çıkma oranı',sa.traffic?.bounceRate],['Anlık kullanıcı',sa.traffic?.realtimeUsers],['Dönüşüm olayları',hl.conversionEventsCount],['Son veri alımı',hl.lastDataReceivedAt]])+noteBox(sa.note));
 return h};
AN.domain=sa=>{
 const d=sa.dns||{},reg=sa.registration||{},sec=sa.dnsSecurity||{},sub=sa.subdomains||{},th=sa.threatAnalysis||{},ns=sa.nameservers;
 let h=tiles([tile('Bitişe kalan',reg.remainingDays!=null?esc(reg.remainingDays)+' gün':'—',reg.remainingDays==null?'na':reg.remainingDays<0?'bd':reg.remainingDays<30?'bd':reg.remainingDays<90?'wn':'ok'),tile('DNSSEC',sec.dnssecEnabled?'Açık':'Kapalı',sec.dnssecEnabled?'ok':'wn'),tile('Transfer kilidi',sec.transferLocked==null?'—':sec.transferLocked?'Kilitli':'Açık',tn(sec.transferLocked)),tile('Kara liste',th.blacklistStatus==='LISTED'?esc((th.blacklistHits||[]).length)+' kayıt':th.blacklistStatus==='CLEAN'?'Temiz':'Kontrol edilemedi',th.blacklistStatus==='LISTED'?'bd':th.blacklistStatus==='CLEAN'?'ok':'na')]);
 h+=sect('Kayıt ve süre','calendar-clock',kvt([['Alan adı',sa.domain],['Kayıt kuruluşu',reg.registrar],['Oluşturulma',dF(reg.createdAt),1],['Son güncelleme',dF(reg.updatedAt),1],['Bitiş tarihi',dF(reg.expiresAt),1],['Alan adı yaşı',reg.domainAgeDays!=null?Math.floor(reg.domainAgeDays/365*10)/10+' yıl':null],['Durum kodları',reg.statuses],['Veri kaynağı',reg.source]]));
 h+=sect('DNS kayıtları','network',kvt([['A (IPv4)',d.a],['AAAA (IPv6)',d.aaaa],['CNAME',d.cname],['NS',d.ns],['MX',mxF(d.mx)],['CAA',caaF(d.caa)],['SOA',soaF(d.soa)],['www çözümleniyor',d.wwwResolves],['DNS sağlayıcı',sa.dnsProvider]]));
 if(ns)h+=sect('Nameserver sağlığı','server',chk('Yanıt veren nameserver',(ns.responding||'').split('/')[0]===(ns.responding||'').split('/')[1]?'ok':'wn',ns.responding)+chk('SOA serial tutarlı',ns.serialsConsistent?'ok':'wn')+listF(ns.servers));
 h+=sect('DNS güvenliği','shield-check',chk('DNSSEC',sec.dnssecEnabled?'ok':'wn',sec.dnssecStatus||'')+chk('Transfer kilidi',tn(sec.transferLocked),sec.transferLockStatus||'')+chk('CAA kaydı',sec.caaRecords&&sec.caaRecords.length?'ok':'wn',sec.caaRecords&&sec.caaRecords.length?sec.caaRecords.join(', '):'Yok'));
 h+=sect('Alt alan adları ve devralma riski','sitemap',kvt([['Sertifika şeffaflık kaydı (CT)',sub.certificateTransparency==='ok'?'Sorgulandı':'Sorgulanamadı'],['Bulunan alt alan adı',sub.discovered],['CNAME kontrol edilen',sub.cnameChecked]])+chk('Subdomain devralma riski',sub.takeoverRisks&&sub.takeoverRisks.length?'bd':'ok',sub.takeoverRisks&&sub.takeoverRisks.length?'':'Risk bulunmadı')+listF(sub.takeoverRisks)+chk('Boşta (dangling) CNAME',sub.danglingCnames&&sub.danglingCnames.length?'wn':'ok')+listF(sub.danglingCnames)+(sub.sample&&sub.sample.length?`<div class="hint">Örnek alt alan adları</div>${chips(sub.sample.slice(0,25))}`:''));
 h+=sect('IP itibarı','ban',chk('IP kara listelerde değil',th.blacklistStatus==='LISTED'?'bd':th.blacklistStatus==='CLEAN'?'ok':'na',`${(th.blacklistCheckedIps||[]).length} IP kontrol edildi`)+listF(th.blacklistHits));
 return h};
AN.email=sa=>{
 const e=sa.emailSecurity||{},sd=e.spfDetails||{},dd=e.dmarcDetails;
 const st=s=>s==='VALID'?'ok':s==='NOT_REQUIRED'?'na':s==='SELECTOR_NOT_DISCOVERED'?'wn':'bd';
 let h=tiles([tile('MX',e.hasMx?'Var':'Yok',e.hasMx?'ok':'wn'),tile('SPF',e.spfValid?'Geçerli':'Yok',e.spfValid?(sd.strength==='weak'?'wn':'ok'):e.hasMx?'bd':'na'),tile('DKIM',e.dkimValid?'Geçerli':e.dkimStatus==='SELECTOR_NOT_DISCOVERED'?'Bulunamadı':'Yok',e.dkimValid?'ok':'wn'),tile('DMARC',e.dmarcValid?esc(e.dmarcPolicy||'Var'):'Yok',e.dmarcValid?(e.dmarcPolicy==='none'?'wn':'ok'):e.hasMx?'bd':'na')]);
 h+=sect('E-posta altyapısı','mail',kvt([['MX kayıtları',mxF(e.mxRecords)],['E-posta sağlayıcı',e.mailProvider],['DNS sağlayıcı',sa.dnsProvider]]));
 h+=sect('SPF (gönderen doğrulama)','send',chk('SPF kaydı',st(e.spfStatus),e.spf?esc(e.spf):'Yok')+(e.spf?kvt([['Kayıt sayısı',sd.recordCount],['DNS sorgu sayısı',sd.dnsLookups!=null?sd.dnsLookups+' / '+(sd.lookupLimit||10):null],['Sonlanış (all)',sd.all],['Güç',sd.strength],['include listesi',sd.includes],['Kırık include',sd.brokenIncludes],['ptr kullanımı',sd.usesPtr]]):''));
 h+=sect('DKIM (imza)','key-round',chk('DKIM kaydı',st(e.dkimStatus),e.dkimValid?'Selector: '+esc(e.dkimSelector||''):e.dkimStatus==='SELECTOR_NOT_DISCOVERED'?'Yaygın selector\'larda bulunamadı; özel selector kullanılıyor olabilir':'')+listF(e.dkimSelectors));
 h+=sect('DMARC (politika)','shield',chk('DMARC kaydı',st(e.dmarcStatus),e.dmarc?esc(e.dmarc):'Yok')+(e.dmarc?chk('Politika',e.dmarcPolicy==='reject'?'ok':e.dmarcPolicy==='quarantine'?'ok':'wn',e.dmarcPolicy||'')+kvt([['Uygulama yüzdesi (pct)',e.dmarcPct],['Alt alan adı politikası (sp)',dd?.subdomainPolicy],['Toplu rapor (rua)',dd?.rua],['Adli rapor (ruf)',dd?.ruf],['DKIM hizalama',dd?.adkim],['SPF hizalama',dd?.aspf]]):''));
 const ms=e.mtaSts||{};
 h+=sect('Ek e-posta güvenliği','lock',chk('MTA-STS',ms.present?(ms.policyReachable&&ms.mode==='enforce'?'ok':'wn'):'wn',ms.present?(ms.policyReachable?'Politika erişilebilir • mod: '+esc(ms.mode||'-'):'Kayıt var ama politika dosyasına ulaşılamıyor'):'Yok')+chk('TLS-RPT (TLS raporlama)',e.tlsRpt?'ok':'wn',e.tlsRpt?'Var':'Yok')+chk('BIMI (marka logosu)',e.bimi?'ok':'na',e.bimi?'Var':'Yok (isteğe bağlı)'),'MTA-STS e-posta aktarımında şifrelemeyi zorunlu kılar');
 h+=sect('CAA kaydı','file-badge',chk('CAA',(sa.dnsSecurity?.caaRecords||[]).length?'ok':'wn',(sa.dnsSecurity?.caaRecords||[]).join(', ')||'Yok'));
 return h};
AN.ssl=sa=>{
 const c=sa.cert||{},t=sa.tls||{},hs=sa.httpSecurity||{};
 let h=tiles([tile('Kalan gün',c.daysRemaining!=null?esc(c.daysRemaining):'—',c.daysRemaining==null?'na':c.daysRemaining<0?'bd':c.daysRemaining<21?'bd':c.daysRemaining<45?'wn':'ok'),tile('Geçerlilik',c.valid?'Geçerli':'Geçersiz',c.valid?'ok':'bd'),tile('TLS',esc(t.protocol||'—'),t.protocol==='TLSv1.3'?'ok':t.protocol==='TLSv1.2'?'ok':'wn'),tile('Anahtar',c.keySize?esc((c.keyType||'')+' '+c.keySize):esc(c.keyType||'—'),c.keySize&&c.keySize<2048&&/rsa/i.test(c.keyType||'')?'bd':'ok')]);
 h+=sect('Sertifika','badge-check',kvt([['Konu (CN)',c.subject],['Kuruluş',c.subjectO],['Veren',c.issuer],['Başlangıç',dF(c.validFrom),1],['Bitiş',dF(c.validTo),1],['Geçerlilik süresi',c.validityPeriodDays!=null?c.validityPeriodDays+' gün':null],['İmza algoritması',c.signatureAlgorithm],['Anahtar',c.keySize?(c.keyType||'')+' '+c.keySize+(c.curve?' ('+c.curve+')':''):c.keyType],['Seri no',c.serialNumber],['Parmak izi (SHA-256)',c.fingerprint],['EV sertifika',c.isEV]]));
 h+=sect('Doğrulama','check-circle',chk('Süresi dolmamış',c.daysRemaining>=0?'ok':'bd')+chk('Alan adı eşleşiyor',tn(c.hostnameMatches))+chk('Kendinden imzalı değil',c.isSelfSigned?'bd':'ok')+chk('Güvenilir zincir',tn(t.trusted),t.trustError||'')+chk('Zincir eksiksiz',tn(t.chainComplete))+chk('www / çıplak eş kapsanıyor',tn(c.coversWwwVariant))+chk('Wildcard sertifika',c.isWildcard?'wn':'ok',c.isWildcard?'Evet (*.alanadi)':'Hayır'));
 h+=sect('Kapsanan adlar (SAN)','list',chips(c.subjectAltNames));
 h+=sect('TLS ve şifreleme','lock',chk('TLS 1.3',tn(t.supportsTls13))+chk('TLS 1.2',tn(t.supportsTls12))+chk('Eski TLS kapalı',t.legacyProtocolsEnabled&&t.legacyProtocolsEnabled.length?'bd':'ok',(t.legacyProtocolsEnabled||[]).join(', '))+chk('OCSP stapling',tn(t.ocspStapling))+kvt([['Şifre',t.cipherName],['ALPN',t.alpn],['Sunucu IP',t.remoteIp],['Protokol desteği',t.protocolSupport?Object.entries(t.protocolSupport).map(([k,v])=>k+': '+v).join(' • '):null]]));
 h+=sect('Sertifika zinciri','link',listF(t.chain),`${t.chainLength||0} sertifika`);
 h+=sect('HTTPS ve HSTS','shield-check',chk('HSTS',hs.hstsEnabled?(hs.hstsMaxAge>=15552000?'ok':'wn'):'bd',hs.hstsEnabled?Math.round(hs.hstsMaxAge/86400)+' gün':'Yok')+chk('includeSubDomains',tn(hs.hstsIncludeSubdomains))+chk('preload',tn(hs.hstsPreload))+kvt([['HTTPS yanıt kodu',hs.status],['Sunucu',hs.serverHeader]]));
 return h};
AN.hosting=sa=>{
 const n=sa.network||{},p=sa.provider||{},ht=sa.http||{};
 let h=tiles([tile('Sağlayıcı',esc(p.name||p.family||'—'),'na'),tile('Ülke',esc(p.country||'—'),'na'),tile('CDN / DDoS',sa.ddosProtection?'Var':'Yok',sa.ddosProtection?'ok':'wn'),tile('IPv6',n.ipv6&&n.ipv6.length?'Var':'Yok',n.ipv6&&n.ipv6.length?'ok':'wn')]);
 h+=sect('Ağ bilgisi','network',kvt([['IPv4',n.ipv4],['IPv6',n.ipv6],['Ters DNS',n.reverseDns],['İkincil IP',sa.secondaryIp]]));
 h+=sect('Sağlayıcı ve konum','map-pin',kvt([['Sağlayıcı',p.name],['Bulut ailesi',p.family],['ASN',p.asn],['Ülke',p.country],['Şehir',p.city],['Bölge',p.region]]),'KVKK/GDPR için verinin hangi ülkede durduğunu bilin');
 h+=sect('Platform','layers',chips(sa.platform)||'<div class="hint">Belirlenemedi</div>');
 h+=sect('HTTP bağlantısı','zap',chk('HTTPS',ht.status?'ok':'bd',ht.status?'HTTP '+ht.status:'Bağlanılamadı')+chk('HTTP → HTTPS yönlendirme',tn(ht.httpToHttps))+kvt([['Sunucu',ht.server],['X-Powered-By',ht.poweredBy],['Protokol',ht.protocol],['TLS sürümü',ht.tlsVersion],['Bağlantı süresi',ht.tcpConnectMs!=null?ht.tcpConnectMs+' ms':null],['TLS el sıkışma',ht.tlsHandshakeMs!=null?ht.tlsHandshakeMs+' ms':null],['TTFB',ht.ttfbMs!=null?ht.ttfbMs+' ms':null],['Yönlendirme',ht.redirects]]));
 return h};
AN.server=sa=>{
 const op=sa.openPorts||[],risky=op.filter(p=>p&&typeof p==='object'&&p.risk);
 let h=tiles([tile('Açık port',esc(sa.openCount??op.length),op.length>6?'wn':'ok'),tile('Denenen port',esc(sa.checkedPorts??'—'),'na'),tile('Ort. bağlantı',msF(sa.avgConnectMs),thr(sa.avgConnectMs,300,800)),tile('Web servisi',sa.webServiceOpen?'Açık':'Kapalı','na')]);
 h+=sect('Sunucu','server',kvt([['Adres',sa.host],['IP',sa.ip],['Tüm IP\'ler',sa.allIps],['Sağlayıcı',sa.provider],['Ülke / şehir',[sa.country,sa.city].filter(Boolean).join(' / ')||null],['ASN',sa.asn],['CDN/WAF arkasında',sa.behindCdn]]));
 h+=sect('Açık portlar','door-open',op.length?`<table class="kv">${op.map(p=>typeof p==='object'?`<tr><td>${esc(p.port)}${p.service?' • '+esc(p.service):''}</td><td>${p.risk?`<span class="badge ${p.risk==='high'||p.risk==='critical'?'bd':'wn'}">${esc(p.risk)}</span> `:''}${esc(p.banner||p.note||'')}</td></tr>`:`<tr><td>${esc(p)}</td><td></td></tr>`).join('')}</table>`:chk('Açık port bulunamadı','na','Sunucu kapalı olabilir ya da güvenlik duvarı bağlantıları engelliyor'));
 h+=sect('Karşılama satırları (banner)','terminal',listF(sa.banners));
 return h+noteBox(sa.note)};
AN.mobile=sa=>{
 let h=tiles([tile('Mağaza',esc(sa.store||'—'),'na'),tile('Puan',sa.rating!=null?esc(sa.rating)+' ★':'—',thrUp(sa.rating,4,3.5)),tile('Değerlendirme',sa.ratingCount!=null?esc(sa.ratingCount.toLocaleString('tr-TR')):'—',thrUp(sa.ratingCount,50,10)),tile('Son güncelleme',sa.daysSinceUpdate!=null?esc(sa.daysSinceUpdate)+' gün önce':'—',thr(sa.daysSinceUpdate,180,365))]);
 h+=sect('Uygulama','smartphone',kvt([['Ad',sa.name],['Geliştirici',sa.developer],['Paket / kimlik',sa.bundleId||sa.id],['Kategori',sa.category],['Fiyat',sa.price],['İndirme',sa.downloads],['Sürüm',sa.version],['Minimum işletim sistemi',sa.minOs],['Son güncelleme',dF(sa.lastUpdate||sa.lastUpdated),1],['Mağaza ülkesi',sa.availableInCountry]]));
 h+=sect('Kalite','star',chk('Puan 4,0 ve üzeri',sa.rating==null?'na':sa.rating>=4?'ok':'wn',sa.rating!=null?sa.rating+' / 5':'')+chk('En az 50 değerlendirme',sa.ratingCount==null?'na':sa.ratingCount>=50?'ok':'wn',sa.ratingCount!=null?String(sa.ratingCount):'')+(sa.ratingCurrentVersion!=null?chk('Güncel sürüm puanı',sa.ratingCurrentVersion>=3.5?'ok':'wn',sa.ratingCurrentVersion+' ('+(sa.ratingCountCurrentVersion||0)+' değerlendirme)'):''));
 h+=sect('Bakım','wrench',chk('Son 6 ayda güncellendi',sa.daysSinceUpdate==null?'na':sa.daysSinceUpdate<=180?'ok':'wn',sa.daysSinceUpdate!=null?sa.daysSinceUpdate+' gün önce':'')+chk('Son 1 yılda güncellendi',sa.daysSinceUpdate==null?'na':sa.daysSinceUpdate<=365?'ok':'bd'));
 return h+noteBox(sa.note||sa.hint)};
AN.repo=sa=>{
 const hy=sa.hygiene&&typeof sa.hygiene==='object'?sa.hygiene:null;
 let h=tiles([tile('Yıldız',esc(sa.stars??'—'),'na'),tile('Son commit',sa.daysSinceLastPush!=null?esc(sa.daysSinceLastPush)+' gün önce':'—',thr(sa.daysSinceLastPush,90,365)),tile('Açık issue',esc(sa.openIssues??'—'),thr(sa.openIssues,50,100)),tile('Topluluk sağlığı',sa.communityHealthPct!=null?esc(sa.communityHealthPct)+'%':'—',thrUp(sa.communityHealthPct,80,50))]);
 h+=sect('Depo','git-branch',kvt([['Depo',sa.repo],['Açıklama',sa.description],['Görünürlük',sa.visibility],['Ana dil',sa.language],['Diller',sa.languages],['Varsayılan dal',sa.defaultBranch],['Oluşturulma',sa.createdAt?dF(sa.createdAt):null,1],['Yaş',sa.ageDays!=null?Math.floor(sa.ageDays/365*10)/10+' yıl':null],['Boyut',sa.sizeKB!=null?sa.sizeKB+' KB':null],['Fork',sa.forks],['İzleyen',sa.watchers],['Açık PR',sa.openPullRequests],['Katkıcı',sa.contributors],['Son sürüm',sa.latestRelease]]));
 h+=sect('Yaşam belirtileri','heart-pulse',chk('Arşivlenmemiş',sa.archived?'bd':'ok')+chk('Son 3 ayda commit',sa.daysSinceLastPush==null?'na':sa.daysSinceLastPush<=90?'ok':sa.daysSinceLastPush<=365?'wn':'bd',sa.daysSinceLastPush!=null?sa.daysSinceLastPush+' gün önce':'')+chk('Lisans',sa.license&&sa.license!=='NOASSERTION'?'ok':'wn',sa.license||'Yok')+chk('Yayınlanmış sürüm',sa.latestRelease?'ok':'wn',sa.latestRelease||'Yok')+chk('Fork değil',sa.isFork?'wn':'ok'));
 h+=sect('Güvenlik ve hijyen','shield-check',hy?[['Güvenlik politikası (SECURITY.md)',hy.securityPolicy],['CI/CD yapılandırması',hy.ci],['Otomatik bağımlılık güncelleme',hy.dependencyUpdates],['Testler',hy.tests],['Bağımlılık kilit dosyası',hy.lockfile]].map(([n,v])=>chk(n,typeof v==='boolean'?(v?'ok':'wn'):'na',typeof v==='string'?esc(v):'')).join('')+chk('Depoda gizli dosya yok',hy.committedSecretFiles&&hy.committedSecretFiles.length?'bd':'ok',(hy.committedSecretFiles||[]).join(', ')):`<div class="hint">${esc(sa.hygiene||'Bilgi alınamadı')}</div>`);
 return h+noteBox(sa.note)};
AN.brand=sa=>{
 const n=a=>(a||[]).length;
 let h=tiles([tile('Sizin olanlar',esc(n(sa.ownedOrSameOwner)),'ok'),tile('Başkasında (uzantı)',esc(n(sa.thirdPartyTldVariants)),n(sa.thirdPartyTldVariants)?'wn':'ok'),tile('Benzer alan adı',esc(n(sa.thirdPartyLookalikes)),n(sa.thirdPartyLookalikes)?'wn':'ok'),tile('Yayında taklit',esc(n(sa.activeLookalikeSites)),n(sa.activeLookalikeSites)?'bd':'ok')]);
 h+=sect('Tarama kapsamı','radar',kvt([['Ana alan adı',sa.domain],['Denenen uzantı',sa.checkedTldVariants],['Denenen yazım hatası varyasyonu',sa.checkedTypoVariants],['Denenen anahtar kelime varyasyonu',sa.checkedKeywordVariants],['Belirlenemeyen',sa.undetermined]]));
 h+=sect('Yayında benzer siteler','siren',n(sa.activeLookalikeSites)?listF(sa.activeLookalikeSites,20):chk('Yayında taklit site bulunmadı','ok'),'GİRİŞ FORMU olanlar kimlik avı (phishing) olabilir');
 h+=sect('Benzer (yazım hatalı) alan adları — başkasında','copy',n(sa.thirdPartyLookalikes)?listF(sa.thirdPartyLookalikes,20):chk('Bulunmadı','ok'));
 h+=sect('Anahtar kelimeli alan adları — başkasında','key',n(sa.thirdPartyKeywordDomains)?listF(sa.thirdPartyKeywordDomains,20):chk('Bulunmadı','ok'),'login-, secure-, account- gibi');
 h+=sect('Farklı uzantılar — başkasında','globe',n(sa.thirdPartyTldVariants)?listF(sa.thirdPartyTldVariants,20):chk('Bulunmadı','ok'));
 h+=sect('Sizin olan alan adları','badge-check',n(sa.ownedOrSameOwner)?chips(sa.ownedOrSameOwner,'ok'):'<div class="hint">Aynı nameserver/IP ile eşleşen yok</div>');
 h+=sect('Henüz kayıtsız önemli uzantılar','shopping-cart',n(sa.unregisteredTlds)?chips(sa.unregisteredTlds,'wn'):chk('Önemli uzantıların hepsi kayıtlı','ok'),'Satın almayı düşünün');
 return h+noteBox(sa.note)};
AN.saas=sa=>{
 const cs=sa.currency||'TRY';
 let h=tiles([tile('Yenilemeye kalan',sa.remainingDays!=null?esc(sa.remainingDays)+' gün':'—',sa.remainingDays==null?'na':sa.remainingDays<0?'bd':sa.remainingDays<14?'bd':sa.remainingDays<30?'wn':'ok'),tile('Aylık maliyet',sa.monthlyCost!=null?esc(sym(sa.monthlyCost,cs)):'—','na'),tile('Yıllık maliyet',sa.yearlyCost!=null?esc(sym(sa.yearlyCost,cs)):'—','na'),tile('Kullanım',sa.usagePercent!=null?esc(sa.usagePercent)+'%':'—',sa.usagePercent==null?'na':sa.usagePercent>=95?'bd':sa.usagePercent>=80?'wn':sa.usagePercent<20?'wn':'ok')]);
 h+=sect('Abonelik','layers',kvt([['Sağlayıcı',sa.provider],['Paket',sa.plan],['Yenileme tarihi',dF(sa.renewalDate),1],['Faturalama dönemi',sa.billingCycle==='yearly'?'Yıllık':'Aylık'],['Tutar',sa.cost!=null?sym(+sa.cost,cs):null],['Otomatik yenileme',sa.autoRenew]]));
 h+=sect('Değerlendirme','scale',chk('Yenileme tarihi girilmiş',sa.renewalDate?'ok':'wn')+chk('Süresi dolmamış',sa.remainingDays==null?'na':sa.remainingDays>=0?'ok':'bd')+chk('Yenileme yaklaşmıyor (30 gün)',sa.remainingDays==null?'na':sa.remainingDays>30?'ok':'wn',sa.remainingDays!=null?sa.remainingDays+' gün':'')+chk('Kullanım dengeli',sa.usagePercent==null?'na':sa.usagePercent>=20&&sa.usagePercent<80?'ok':'wn',sa.usagePercent==null?'Kullanım oranı girilmemiş':sa.usagePercent<20?'Çok düşük: israf olabilir':sa.usagePercent>=80?'Kota dolmak üzere':''));
 return h};
const ANMAP={web:'web',domain:'domain',email:'email',ssl:'ssl',hosting:'hosting',server:'server',uptime:'uptime',performance:'performance',seo:'seo',security:'security',api:'api',analytics:'analytics',mobile:'mobile',repo:'repo',brand:'brand',saas:'saas'};
function analysisHtml(cat,sa){
 try{const f=AN[ANMAP[cat]];return f?f(sa||{}):''}catch(e){console.error('analiz ekranı',e);return''}}

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
  h+=`<div class="card"><b>Bulgular ve öneriler (${f.length})</b>${findingsHtml(f)}</div>`;
  h+=analysisHtml(a.cat,sa);
  h+=`<details class="card raw"><summary>Ham teknik veri</summary><table>${flat(sa).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v===true?'evet':v===false?'hayır':v??'-')}</td></tr>`).join('')}</table></details>
  <button class="btn p w" data-act="rescan" data-id="${id}">${ic('refresh-cw')} Yeniden Tara</button>`;
 }
 $('#box').innerHTML=h;$('#modal').classList.add('on');icons();
}

/* ---------- ana render ---------- */
const NAV0=()=>[['GENEL',[['dash','Genel Bakış','layout-grid']]],...GROUPS.map(([g,l])=>[l,Object.entries(CATS).filter(([,v])=>v.g===g).map(([k,v])=>['cat/'+k,v.label,v.icon])]),
 ['YÖNETİM',[['assets','Varlıklarım','database'],['history','Tarama Geçmişi','history'],['renewals','Yenileme Takvimi','calendar-clock'],['reports','Raporlar','bar-chart-3'],['team','Ekip Yönetimi','users'],['projects','Müşteri Projeleri','briefcase'],['bulk','Toplu Tarama','list-checks'],['plan','Paket ve Faturalandırma','credit-card'],['settings','Ayarlar','settings']]]];
const NAV=()=>{const n=NAV0();if(BK.isAdmin)n.push(['SİSTEM',[['admin','Yönetici Paneli','shield']]]);return n};
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
 $('#view').innerHTML=p==='cat'&&CATS[k]?catPage(k):p==='assets'?assets():p==='bulk'?bulkPage():p==='domains'?domainsPage():p==='admin'&&BK.isAdmin?adminPage():p==='history'?history():p==='reports'?reports():p==='renewals'?renewals():LISTS[p]?listPage(p):p==='plan'?plan():p==='settings'?settings():dash();
 icons();bkPoll();
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
 else if(act==='del'){if(A&&confirm(`"${A.name}" silinsin mi?`)){S.assets=S.assets.filter(x=>x.id!==id);(S.tomb=S.tomb||{})[id]=Date.now();save();close();render();delRemote(id);toast('Varlık silindi')}}
 else if(act==='sug'){const i=$('[name=t]');if(i)i.value=b.dataset.v}
 else if(act==='goto')location.hash=b.dataset.to;
 else if(act==='bell'){const al=alerts();$('#bell').innerHTML=al.length?al.map(a=>`<a data-act="detail" data-id="${esc(a.id)}">${ic('triangle-alert')} ${esc(a.name)} <span class="badge ${sc(a)!=null?tone(sc(a)):'bd'}">${sc(a)??'!'}</span></a>`).join(''):'<div class="it hint">Bildirim yok</div>';$('#bell').classList.toggle('on');icons()}
 else if(act==='clearhist'){S.scans=[];save();render()}
 else if(act==='cur'){st.currency=b.dataset.v;save();render()}
 else if(act==='cycle'){st.cycle=b.dataset.v;save();render()}
 else if(act==='buy')checkout(b.dataset.p);
 else if(act==='portal')portal();
 else if(act==='syncplan'){const p=await syncPlan();toast(p===null?'Sunucudan abonelik bilgisi alınamadı (API adresi ve Firebase yapılandırmasını kontrol edin)':P.PAID.includes(p)?'Paketiniz aktif: '+P.PLANS[p].name:'Aktif ücretli paket bulunamadı',p===null?'warn':'')}
 else if(act==='ping')ping();
 else if(act==='ntf-on')ntfEnable();else if(act==='ntf-off')ntfDisable();else if(act==='ntf-test')ntfTest();
 else if(act==='install'){if(DEFERRED){DEFERRED.prompt();await DEFERRED.userChoice;DEFERRED=null;render()}}
 else if(act==='clearcache')clearCache();
 else if(act==='copyuid'){try{await navigator.clipboard.writeText(U.uid);toast('Kopyalandı')}catch{toast(U.uid)}}
 else if(act==='dellist'){const k=b.dataset.k;S[k]=S[k].filter(x=>x.id!==id);(S.tomb=S.tomb||{})[id]=Date.now();save();render()}
 else if(act==='logout'){window.dacLogout&&window.dacLogout()}
 else if(act==='wipe'){if(confirm('Bu cihazdaki yerel veriler silinecek. Bulut kopyası durur ve bir sonraki girişte geri yüklenir. Emin misiniz?')){localStorage.removeItem(KEY);location.hash='';location.reload()}}
 else if(act==='export-account'){exportAccount()}else if(act==='delete-account'){deleteAccount()}
 else if(act==='print'){window.print()}else if(act==='csv'){const q=v=>`"${String(v??'').replace(/"/g,'""')}"`;dl('varliklar.csv','\ufeff'+['Ad;Tür;Hedef;Skor;Durum;Son tarama',...S.assets.map(a=>[a.name,CATS[a.cat].label,a.target,sc(a)??'',SL[a.result?.status]||a.result?.status||'',fmt(a.lastScan)].map(q).join(';'))].join('\n'),'text/csv;charset=utf-8')}
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
 else if(t==='add'){const c=f.dataset.cat;if(c==='saas')addAndScan(c,d.provider,{provider:d.provider,plan:d.plan||'unknown',cost:+d.cost||0,currency:d.currency||'TRY',renewalDate:d.renewalDate||null,usagePercent:d.usagePercent?+d.usagePercent:undefined});else if(c==='analytics')addAndScan(c,d.t,{measurementId:(d.measurementId||'').trim().toUpperCase(),propertyName:(d.propertyName||'').trim()},d.name);else addAndScan(c,d.t,{},d.name)}
 else if(t==='list'){const k=f.dataset.k,n=LISTS[k].f[0][0],ps=planState();
  if(k==='team'&&ps.p.team!=null&&S.team.length>=ps.p.team)return toast(`${ps.p.name} paketinde en fazla ${ps.p.team} ekip kaydı eklenebilir`,'err');
  if(S[k].some(x=>String(x[n]).toLowerCase()===d[n].trim().toLowerCase()))return toast('Bu kayıt zaten var','warn');S[k].push({id:uid(),...d});save();render()}
 else if(t==='settings'){const s=S.settings;s.org=d.org.trim();s.apiUrl=d.apiUrl.trim();s.alertBelow=Math.min(95,Math.max(10,+d.alertBelow||50));PAYCFG=null;HEALTH_TRIED=false;S.settingsAt=Date.now();save();render();toast('Kaydedildi')}
 else if(t==='billing'){const o={};for(const k in d)o[k]=String(d[k]).trim();S.settings.billing=o;S.settingsAt=Date.now();save();toast('Fatura bilgileri kaydedildi')}
});
$('#q').addEventListener('input',e=>{
 const q=e.target.value.toLowerCase().trim(),r=$('#sres');
 const l=q?S.assets.filter(a=>(a.name+a.target).toLowerCase().includes(q)).slice(0,8):[];
 r.innerHTML=q?(l.length?l.map(a=>`<a data-act="detail" data-id="${esc(a.id)}">${esc(a.name)} <span class="hint">${CATS[a.cat].label}</span></a>`).join(''):'<div class="it hint">Sonuç yok</div>'):'';
 r.classList.toggle('on',!!q);
});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();$('#q').focus()}if(e.key==='Escape')close()});
addEventListener('hashchange',()=>{render();scrollTo(0,0)});
addEventListener('focus',()=>{if(S&&U&&apiUrl()&&!document.hidden){pullLatest();syncPlan();SYNC.pulled?schedulePush():pullState()}});

/* ---------- giriş (Firebase Auth index.html içinden çağırır) ---------- */
window.dacStart=u=>{
 U=u;KEY='dac_v1_'+u.uid;
 let raw=localStorage.getItem(KEY);
 if(!raw){const old=localStorage.getItem('dac_v1');if(old){raw=old;localStorage.setItem(KEY,old);localStorage.removeItem('dac_v1')}}
 let parsed=null;try{parsed=JSON.parse(raw||'null')}catch{try{localStorage.setItem(KEY+'_corrupt',raw)}catch{}toast('Yerel veri okunamadı; bozuk kopya yedeklendi, bulut verisi yüklenecek','warn')}
 S=(parsed&&typeof parsed==='object'&&!Array.isArray(parsed))?parsed:blank();
 const st=S.settings=Object.assign({},blank().settings,S.settings||{});
 if(!P.PAID.includes(st.plan))st.plan='trial';   // eski yerel "free/pro" değerleri deneme sayılır
 st.billing=st.billing||{};
 // Şirket adı her kullanıcı için kendi hesabından gelir (ad/e-posta); sabit bir şirket adı yok. Kullanıcı Ayarlar'dan değiştirebilir.
 if(!String(st.org||'').trim()||(st.org==='HZ Yazılım'&&!S.settingsAt))st.org=String(u.displayName||(u.email||'').split('@')[0]||'').trim().slice(0,60)||'Şirketim';
 // Eski sürümlerden kalan demo (örnek) tarama verilerini temizle: yalnızca gerçek sonuçlar kalır
 S.assets=Array.isArray(S.assets)?S.assets.filter(a=>a&&typeof a==='object'&&CATS[a.cat]&&typeof a.id==='string'):[];S.scans=Array.isArray(S.scans)?S.scans.filter(x=>x&&!x.mock):[];S.team=Array.isArray(S.team)?S.team:[];S.projects=Array.isArray(S.projects)?S.projects:[];
 (S.assets||[]).forEach(a=>{if(a.result?.commonAnalysis?.analyzerVersion==='demo'){delete a.result;delete a.lastScan}});
 syncReset();save(true);render();syncPlan();handleReturn();pullState().then(()=>pullLatest(true));sendConsents();bkInit();
};
async function exportAccount(){const api=apiUrl();if(!api)return toast('Sunucu adresi yok','err');busy(true);try{const r=await fetch(api+'/api/account/export',{headers:await authH()});const j=await r.json();if(!r.ok||!j.success)throw new Error(j.error||'Dışa aktarılamadı');dl('dac-verilerim-'+new Date().toISOString().slice(0,10)+'.json',JSON.stringify(j,null,2));toast('Verileriniz indirildi')}catch(e){toast(e.message,'err')}busy(false)}
async function deleteAccount(){const api=apiUrl();if(!api)return toast('Sunucu adresi yok','err');
 if(!confirm('Hesabınız ve buluttaki TÜM verileriniz (varlıklar, tarama geçmişi, ayarlar) kalıcı olarak silinir. Bu işlem geri alınamaz. Devam edilsin mi?'))return;
 const t=prompt('Onaylamak için HESABIMI SIL yazın:');if(t!=='HESABIMI SIL')return toast('İptal edildi','warn');
 busy(true);try{const r=await fetch(api+'/api/account',{method:'DELETE',headers:{'Content-Type':'application/json',...await authH()},body:JSON.stringify({confirm:'HESABIMI SIL'})});const j=await r.json();if(!r.ok||!j.success)throw new Error(j.error||'Hesap silinemedi');
  try{localStorage.removeItem(KEY);localStorage.removeItem(KEY+'_bak');localStorage.removeItem('dac_last_uid')}catch{}
  toast('Hesabınız silindi');setTimeout(()=>{try{window.dacLogout&&window.dacLogout()}catch{}location.hash='';location.reload()},800)}catch(e){toast(e.message,'err')}busy(false)}
// Üyelik onayı (giriş ekranındaki kutu) sunucuya kayıt olarak iletilir
async function sendConsents(){let v=null;try{v=localStorage.getItem('dac_terms_pending')}catch{}if(!v)return;const api=apiUrl();if(!api)return;try{const h=await authH();if(!h.Authorization)return;for(const type of['terms','privacy']){const r=await fetch(api+'/api/consent',{method:'POST',headers:{'Content-Type':'application/json',...h},body:JSON.stringify({type,version:v})});if(!r.ok)return}localStorage.removeItem('dac_terms_pending')}catch{}}
window.dacStop=()=>{BK.isAdmin=false;clearInterval(BK.timer);BK.timer=null;syncReset();S=null;U=null;close();$('#view').innerHTML='';location.hash=''};

/* ---------- toplu tarama + admin (V13.1) ---------- */
const BK={isAdmin:false,timer:null,jobs:[],job:null,rows:[],total:0,page:1,pageSize:50,q:'',st:'ALL',sort:'queuedAt',order:'asc',sel:new Set(),tab:'overview',adm:{},domJob:null,busy:false};
const ST={PENDING:'Bekliyor',RETRYING:'Yeniden denenecek',RUNNING:'Çalışıyor',COMPLETED:'Tamamlandı',PARTIAL:'Kısmen tamamlandı',FAILED:'Başarısız',CANCELED:'İptal edildi'};
const stTone=x=>x==='COMPLETED'?'ok':x==='FAILED'?'bd':x==='PARTIAL'||x==='RETRYING'?'wn':'mu';
const BULKCATS=[['domain','Domain'],['ssl','SSL Sertifikası'],['hosting','Hosting'],['web','Web Sitesi'],['seo','SEO'],['performance','Performans'],['uptime','Uptime']];
async function bkApi(method,path,body){
 const api=apiUrl();if(!api)throw new Error('Sunucu adresi yok');
 const r=await fetch(api+path,{method,headers:{'Content-Type':'application/json',...await authH()},body:body?JSON.stringify(body):undefined});
 let j=null;try{j=await r.json()}catch{}
 if(!r.ok||!j||j.success===false){const e=new Error((j&&j.error)||'İstek başarısız ('+r.status+')');e.status=r.status;e.code=j&&j.code;throw e}
 return j;
}
async function bkInit(){try{const j=await bkApi('GET','/api/me/admin');if(j.admin&&!BK.isAdmin){BK.isAdmin=true;render()}}catch{}}
const bkDomain=v=>{v=String(v).trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//,'').split(/[\/?#]/)[0].replace(/:\d{1,5}$/,'').replace(/\.$/,'').replace(/^www\./,'');return /^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/.test(v)&&!/^[\d.]+$/.test(v)?v:null};
const daysLeft=a=>{const e=a.result?.specificAnalysis?.registration?.expiresAt;if(!e)return null;const t=new Date(e).getTime();return isNaN(t)?null:Math.ceil((t-Date.now())/864e5)};
const dayTxt=d=>d==null?'Bilinmiyor':d<0?Math.abs(d)+' gün geçti':d+' gün';

/* ortak yenileme: varlıkları ve tarama durumlarını sunucudan çeker; YENİ TARAMA BAŞLATMAZ */
async function refreshAll(){
 busy(true);
 try{await pullLatest(true);await bkLoadView()}catch(e){toast(e.message,'err')}
 busy(false);render();toast('Güncellendi (yeni tarama başlatılmadı)');
}
async function bkLoadView(){
 const r=(location.hash.slice(1)||'dash').split('/')[0];
 if(r==='bulk'||r==='domains'){const j=await bkApi('GET','/api/jobs?limit=30');BK.jobs=j.jobs;const cur=BK.job?BK.jobs.find(x=>x.id===BK.job):null;if(r==='bulk'&&cur)await bkItems();}
 if(r==='admin')await admLoad(BK.tab);
}
async function bkItems(){
 if(!BK.job)return;const qs=new URLSearchParams({page:BK.page,pageSize:BK.pageSize,status:BK.st,q:BK.q,sort:BK.sort,order:BK.order});
 const j=await bkApi('GET','/api/jobs/'+encodeURIComponent(BK.job)+'/items?'+qs);BK.rows=j.items;BK.total=j.total;
}
function bkPoll(){
 const r=(location.hash.slice(1)||'dash').split('/')[0],on=['bulk','domains','admin'].includes(r);
 if(!on){clearInterval(BK.timer);BK.timer=null;return}
 if(BK.timer)return;
 BK.timer=setInterval(async()=>{
  const rr=(location.hash.slice(1)||'dash').split('/')[0];if(!['bulk','domains','admin'].includes(rr)||document.hidden||BK.busy)return;
  try{await bkLoadView();const active=BK.jobs.some(j=>['PENDING','RUNNING'].includes(j.status));
   if(rr==='domains'&&BK.domJob&&!active){await pullLatest(true);BK.domJob=null;}
   if(rr==='admin'){admPaint()}else bkPaint();
   if(rr!=='admin'&&!active&&BK.wasActive){BK.wasActive=false;await pullLatest(true);render()}BK.wasActive=active}catch{}
 },3000);
}
function bkPaint(){const el=$('#bk-body');if(el)el.innerHTML=(location.hash.slice(1)||'').startsWith('domains')?domBody():bulkBody();icons()}

/* --- Domain: Genel Tarama --- */
function domExtra(){const n=S.assets.filter(a=>a.cat==='domain').length;return`<div class="card"><b>${ic('radar')} Genel Tarama</b><div class="hint" style="margin:6px 0 10px">Ekli ${n} domaini sırayla tarar ve bitişe en az kalandan en çok kalana doğru listeler. Tek tek varlık taramasındaki ayrıntılı analiz değişmez.</div><div class="btns"><button class="btn p" data-act="bk-domscan"${n?'':' disabled'}>${ic('radar')} Genel Tarama</button><a class="btn s" href="#domains">Listeyi gör</a><a class="btn s" href="#bulk">Toplu domain ekle</a></div></div>`}
function domainsPage(){return`<div class="mh"><h2>Domain Bitiş Süreleri</h2><div class="btns"><button class="btn s" data-act="bk-refresh">${ic('refresh-cw')} Yenile</button><button class="btn p" data-act="bk-domscan">${ic('radar')} Genel Tarama</button></div></div><p class="sub">Bitişe en yakından en uzağa doğru sıralıdır. Bitiş tarihi yalnızca kayıt kuruluşunun (RDAP) verisinden gelir.</p><div id="bk-body">${domBody()}</div>`}
function domBody(){
 const doms=S.assets.filter(a=>a.cat==='domain').map(a=>({a,d:daysLeft(a)})).sort((x,y)=>(x.d==null)-(y.d==null)||(x.d??0)-(y.d??0));
 const j=BK.jobs.filter(x=>x.source!==undefined||true).find(x=>BK.domJob&&x.id===BK.domJob);
 const prog=j?`<div class="card"><div class="mh"><b>Tarama sürüyor</b><span class="badge ${stTone(j.status)}">${esc(ST[j.status]||j.status)}</span></div>${bkBar(j)}</div>`:'';
 if(!doms.length)return prog+'<div class="card"><div class="empty">Ekli domain yok. Domain sayfasından ekleyin.</div></div>';
 return prog+`<div class="card">${doms.map(({a,d})=>`<div class="item"><div class="ico" style="color:${CATS.domain.c}">${ic('link-2')}</div><div class="g"><b>${esc(a.name)}</b></div><span class="badge ${d==null?'mu':dayTone(d)}">${esc(dayTxt(d))}</span></div>`).join('')}</div>`;
}
async function bkDomScan(){
 if(!gate())return;const doms=S.assets.filter(a=>a.cat==='domain');if(!doms.length)return toast('Ekli domain yok','warn');
 busy(true);BK.busy=true;
 try{let last=null;for(let i=0;i<doms.length;i+=1000){const items=doms.slice(i,i+1000).map(a=>({assetId:a.id,type:'DOMAIN',target:a.target,name:a.name}));const j=await bkApi('POST','/api/jobs',{items,label:'Genel domain taraması',source:'domains-overview'});last=j.job.id}
  BK.domJob=last;BK.wasActive=true;toast('Genel tarama kuyruğa alındı');location.hash='domains';await bkLoadView()}
 catch(e){toast(e.status===402?'Paket gerekli: '+e.message:e.message,'err');if(e.status===402)location.hash='plan'}
 BK.busy=false;busy(false);render();
}

/* --- Toplu tarama sayfası --- */
const bkBar=j=>{const done=j.total-j.counts.PENDING-j.counts.RETRYING-j.counts.RUNNING,pc=j.total?Math.round(done/j.total*100):0;return`<div class="bkbar"><i style="width:${pc}%"></i></div><div class="hint">${done}/${j.total} bitti • ${j.counts.RUNNING} çalışıyor • ${j.counts.PENDING+j.counts.RETRYING} bekliyor • ${j.counts.FAILED} başarısız</div>`};
function bulkPage(){
 const opts=BULKCATS.map(([k,l])=>`<option value="${k}">${esc(l)}</option>`).join('');
 return`<div class="mh"><h2>Toplu Tarama</h2><button class="btn s" data-act="bk-refresh">${ic('refresh-cw')} Yenile</button></div><p class="sub">Yüzlerce hedefi tek seferde ekleyin. İşler sunucuda sırayla çalışır; sayfayı kapatabilirsiniz.</p>
 <div class="card"><form data-bkform="import"><b>Toplu ekle</b><div style="height:10px"></div><select class="field" name="cat">${opts}</select>
 <textarea class="field" name="text" rows="6" placeholder="Her satıra bir adres (veya virgülle ayırın). CSV de yapıştırabilirsiniz." required></textarea>
 <input class="field" type="file" accept=".csv,.txt,text/plain,text/csv" data-bkfile>
 <button class="btn p w" type="submit">${ic('plus')} Ekle ve Tara</button></form></div>
 <div id="bk-body">${bulkBody()}</div>`;
}
function bulkBody(){
 const jl=BK.jobs.length?BK.jobs.map(j=>`<div class="item"><div class="g"><b>${esc(j.label)}</b><span>${esc(fmt(j.createdAt))} • ${j.total} hedef${j.persistent?'':' • kalıcı değil'}</span>${bkBar(j)}</div><span class="badge ${stTone(j.status==='PENDING'||j.status==='RUNNING'?'':j.status)}">${esc(ST[j.status]||j.status)}</span><div class="acts"><button class="btn s" data-act="bk-open" data-id="${esc(j.id)}">Aç</button>${['PENDING','RUNNING'].includes(j.status)?`<button class="btn s d" data-act="bk-cancel" data-id="${esc(j.id)}">İptal</button>`:''}</div></div>`).join(''):'<div class="empty">Henüz toplu iş yok</div>';
 return`<div class="card"><div class="mh"><b>İşler</b><span class="badge mu">${BK.jobs.length}</span></div>${jl}</div>${BK.job?bkDetail():''}`;
}
function bkDetail(){
 const j=BK.jobs.find(x=>x.id===BK.job);if(!j)return'';const pages=Math.max(1,Math.ceil(BK.total/BK.pageSize));
 const chips=Object.entries(j.counts).filter(([,n])=>n>0).map(([k,n])=>`<span class="badge ${stTone(k)}">${esc(ST[k]||k)}: ${n}</span>`).join(' ');
 const so=[['queuedAt','Sıra'],['name','Ad'],['status','Durum'],['score','Skor'],['remainingDays','Kalan gün'],['duration','Süre']].map(([v,l])=>`<option value="${v}"${BK.sort===v?' selected':''}>${esc(l)}</option>`).join('');
 const fo=['ALL','PENDING','RUNNING','COMPLETED','PARTIAL','FAILED','CANCELED'].map(v=>`<option value="${v}"${BK.st===v?' selected':''}>${esc(v==='ALL'?'Tümü':ST[v])}</option>`).join('');
 const rows=BK.rows.map(r=>`<div class="item"><input type="checkbox" data-bksel="${esc(r.id)}"${BK.sel.has(r.id)?' checked':''} aria-label="Seç"><div class="g"><b>${esc(r.name)}</b><span>${esc(r.targetUrl)}${r.error?' • '+esc(r.error.message):''}${r.attempts>1?' • '+r.attempts+'. deneme':''}</span></div>${r.result&&r.result.remainingDays!=null?`<span class="badge ${dayTone(r.result.remainingDays)}">${esc(dayTxt(r.result.remainingDays))}</span>`:''}${r.result&&r.result.score!=null?`<span class="badge ${tone(r.result.score)}">${r.result.score}/100</span>`:''}<span class="badge ${stTone(r.status)}">${esc(ST[r.status]||r.status)}</span></div>`).join('')||'<div class="empty">Kayıt yok</div>';
 return`<div class="card"><div class="mh"><b>${esc(j.label)}</b><div class="btns"><button class="btn s" data-act="bk-csv">${ic('download')} CSV</button><button class="btn s" data-act="bk-retry">${ic('rotate-cw')} Seçilenleri yeniden dene</button><button class="btn s d" data-act="bk-itemcancel">Seçilenleri iptal et</button></div></div><div style="margin:8px 0">${chips}</div>
 <div class="row2"><input class="field" data-bkq placeholder="Ara (ad veya adres)" value="${esc(BK.q)}"><select class="field" data-bkst>${fo}</select></div>
 <div class="row2"><select class="field" data-bksort>${so}</select><button class="btn s" data-act="bk-order">${BK.order==='asc'?'Artan ↑':'Azalan ↓'}</button></div>
 <label class="hint"><input type="checkbox" data-bkall> Bu sayfadakilerin tümünü seç (${BK.sel.size} seçili)</label>${rows}
 <div class="mh" style="margin-top:10px"><button class="btn s" data-act="bk-prev"${BK.page<=1?' disabled':''}>Önceki</button><span class="hint">Sayfa ${BK.page}/${pages} • ${BK.total} kayıt</span><button class="btn s" data-act="bk-next"${BK.page>=pages?' disabled':''}>Sonraki</button></div></div>`;
}
async function bkImport(f){
 if(!gate())return;const d=Object.fromEntries(new FormData(f)),cat=d.cat,api=CATS[cat].api,seen=new Set(),items=[];let bad=0,existing=0,added=0;
 const cells=String(d.text||'').split(/[\n,;\t]/).map(x=>x.trim().replace(/^"|"$/g,'')).filter(Boolean);
 if(cells.length&&/^(domain|alan ?ad[ıi]|host|url|site)$/i.test(cells[0]))cells.shift();
 if(cells.length>2000)return toast('En fazla 2000 hedef girin','err');
 const ps=planState(),room=limitOf(ps)-S.assets.length;
 for(const raw of cells){const host=bkDomain(raw);if(!host){bad++;continue}
  const target=URLCATS.includes(cat)?proto(raw.includes('/')?raw:host):host,key=normKey(cat,target);if(seen.has(key))continue;seen.add(key);
  let a=S.assets.find(x=>x.cat===cat&&x.key===key);
  if(a)existing++;else{if(added>=room){bad++;continue}a={id:uid(),cat,target:host,key,name:host,extra:{},createdAt:Date.now()};S.assets.push(a);added++}
  items.push({assetId:a.id,type:api,target:URLCATS.includes(cat)?target:host,name:a.name})}
 if(!items.length){return toast(bad?'Geçerli hedef bulunamadı ('+bad+' hatalı veya limit dışı)':'Hedef yok','err')}
 save();busy(true);BK.busy=true;
 try{let last=null;for(let i=0;i<items.length;i+=1000){const j=await bkApi('POST','/api/jobs',{items:items.slice(i,i+1000),label:'Toplu '+CATS[cat].label,source:'bulk'});last=j.job.id}
  BK.job=last;BK.page=1;BK.sel=new Set();BK.wasActive=true;toast(`${items.length} hedef kuyruğa alındı (${added} yeni, ${existing} mevcut, ${bad} atlandı)`);f.reset();await bkLoadView()}
 catch(e){toast(e.message,'err');if(e.status===402)location.hash='plan'}
 BK.busy=false;busy(false);render();
}
document.addEventListener('submit',e=>{const f=e.target.closest('[data-bkform]');if(!f)return;e.preventDefault();if(f.dataset.bkform==='import')bkImport(f)});
document.addEventListener('change',async e=>{
 const t=e.target;
 if(t.matches('[data-bkfile]')){const file=t.files&&t.files[0];if(!file)return;if(file.size>1e6)return toast('Dosya 1 MB'+"'"+'dan küçük olmalı','err');const r=new FileReader();r.onload=()=>{const ta=$('[name=text]');if(ta)ta.value=String(r.result||'')};r.readAsText(file)}
 else if(t.matches('[data-bkst]')){BK.st=t.value;BK.page=1;await bkItems().catch(x=>toast(x.message,'err'));bkPaint()}
 else if(t.matches('[data-bksort]')){BK.sort=t.value;BK.page=1;await bkItems().catch(x=>toast(x.message,'err'));bkPaint()}
 else if(t.matches('[data-bksel]')){t.checked?BK.sel.add(t.dataset.bksel):BK.sel.delete(t.dataset.bksel)}
 else if(t.matches('[data-bkall]')){BK.rows.forEach(r=>t.checked?BK.sel.add(r.id):BK.sel.delete(r.id));bkPaint()}
});
document.addEventListener('input',e=>{if(e.target.matches('[data-bkq]')){clearTimeout(BK.qt);const v=e.target.value;BK.qt=setTimeout(async()=>{BK.q=v;BK.page=1;await bkItems().catch(()=>{});bkPaint();const i=$('[data-bkq]');if(i){i.focus();i.setSelectionRange(v.length,v.length)}},350)}});
document.addEventListener('click',async e=>{
 const b=e.target.closest('[data-act^="bk-"],[data-act^="adm-"]');if(!b)return;const act=b.dataset.act,id=b.dataset.id;
 try{
  if(act==='bk-refresh')return refreshAll();
  if(act==='bk-domscan')return bkDomScan();
  if(act==='bk-open'){BK.job=id;BK.page=1;BK.sel=new Set();await bkItems();return bkPaint()}
  if(act==='bk-prev'||act==='bk-next'){BK.page+=act==='bk-next'?1:-1;await bkItems();return bkPaint()}
  if(act==='bk-order'){BK.order=BK.order==='asc'?'desc':'asc';await bkItems();return bkPaint()}
  if(act==='bk-cancel'){if(!confirm('Bekleyen taramalar iptal edilsin mi?'))return;const j=await bkApi('POST','/api/jobs/'+encodeURIComponent(id)+'/cancel');toast(j.canceled+' tarama iptal edildi');await bkLoadView();return bkPaint()}
  if(act==='bk-retry'){const ids=[...BK.sel];if(!ids.length)return toast('Önce kayıt seçin','warn');const j=await bkApi('POST','/api/jobs/'+encodeURIComponent(BK.job)+'/retry',{itemIds:ids,includeCanceled:true});toast(j.requeued+' kayıt yeniden sıraya alındı (yalnızca başarısız/iptal edilenler)');BK.sel=new Set();await bkLoadView();return bkPaint()}
  if(act==='bk-itemcancel'){const ids=[...BK.sel];if(!ids.length)return toast('Önce kayıt seçin','warn');const j=await bkApi('POST','/api/jobs/'+encodeURIComponent(BK.job)+'/items/cancel',{itemIds:ids});toast(j.canceled+' kayıt iptal edildi');BK.sel=new Set();await bkLoadView();return bkPaint()}
  if(act==='bk-csv'){const qs=new URLSearchParams({status:BK.st,q:BK.q,sort:BK.sort,order:BK.order});const r=await fetch(apiUrl()+'/api/jobs/'+encodeURIComponent(BK.job)+'/export.csv?'+qs,{headers:await authH()});if(!r.ok)throw new Error('CSV indirilemedi');return dl('toplu-tarama.csv',await r.text(),'text/csv')}
  if(act.startsWith('adm-'))return admAct(act,id,b)
 }catch(x){toast(x.message,'err')}
});

/* --- Yönetici paneli (tüm veriler sunucudan; gerçek veri yoksa "veri yok" yazılır) --- */
const ADMTABS=[['overview','Genel Bakış'],['users','Kullanıcılar'],['jobs','Tarama Kuyruğu'],['errors','Sistem Hataları'],['audit','İşlem Kayıtları'],['admins','Yetkili Hesaplar'],['health','Sağlık'],['platform','AI ve Altyapı']];
const admPath={overview:'/api/admin/overview',users:'/api/admin/users',jobs:'/api/admin/jobs',errors:'/api/admin/errors',audit:'/api/admin/audit',admins:'/api/admin/admins',health:'/api/admin/health',platform:'/api/admin/platform'};
async function admLoad(tab){BK.tab=tab;const qs=tab==='users'?'?'+new URLSearchParams({q:BK.adm.uq||'',status:BK.adm.us||'all'}):'';try{BK.adm[tab]=await bkApi('GET',admPath[tab]+qs);BK.adm.err=null}catch(e){BK.adm.err=e.message}}
function adminPage(){if(!BK.adm[BK.tab]&&!BK.adm.err)admLoad(BK.tab).then(admPaint);return`<div class="mh"><h2>Yönetici Paneli</h2><button class="btn s" data-act="adm-refresh">${ic('refresh-cw')} Yenile</button></div><div class="bktabs">${ADMTABS.map(([k,l])=>`<button class="btn s${BK.tab===k?' p':''}" data-act="adm-tab" data-id="${k}">${esc(l)}</button>`).join('')}</div><div id="adm-body">${admBody()}</div>`}
function admPaint(){const el=$('#adm-body');if(el){el.innerHTML=admBody();icons()}}
const av=x=>x&&x.available===false?`<span class="hint">Veri yok: ${esc(x.reason||'')}</span>`:x&&x.value!=null?String(x.value):'-';
const kv=(l,v)=>`<div class="item"><div class="g"><b>${esc(l)}</b></div><span>${v}</span></div>`;
const ms=x=>x==null?'-':x+' ms';
function admBody(){
 const d=BK.adm[BK.tab];if(BK.adm.err)return`<div class="card"><div class="empty">${esc(BK.adm.err)}</div></div>`;if(!d)return'<div class="card"><div class="empty">Yükleniyor…</div></div>';
 if(BK.tab==='overview'){const u=d.users,a=d.api,q=d.queue,sc=d.scans,h=d.health||{};const lat=a.latencyMs||{};
  return`<div class="card">${kv('Toplam kullanıcı',u.available===false?av(u):u.total)}${kv('Aktif / devre dışı',u.available===false?'-':u.active+' / '+u.disabled)}${kv('Son 30 gün aktif',u.available===false?'-':u.activeLast30Days)}${kv('Kayıtlı varlık',av(d.assets))}</div>
  <div class="card"><b>Taramalar (kalıcı)</b>${kv('Toplam',av(sc.total))}${kv('Son 24 saat',av(sc.last24h))}${kv('Başarılı',av(sc.completed))}${kv('Kısmen',av(sc.partial))}${kv('Başarısız',av(sc.failed))}${kv('Zaman aşımı',av(sc.timedOut))}</div>
  <div class="card"><b>Kuyruk</b>${kv('Bekleyen',q.pending)}${kv('Devam eden',q.running)}${kv('Tamamlanan',q.items.COMPLETED)}${kv('Kısmen tamamlanan',q.items.PARTIAL)}${kv('Başarısız',q.items.FAILED)}${kv('İptal edilen',q.items.CANCELED)}${kv('Kalıcı depo',q.engine&&q.engine.persistent?'Evet (Firestore)':'<b>Hayır (bellek)</b>')}</div>
  <div class="card"><b>API (son ${a.windowMinutes} dk, yeniden başlayınca sıfırlanır)</b>${kv('İstek',a.requests)}${kv('P50',ms(lat.p50))}${kv('P95',ms(lat.p95))}${kv('P99',ms(lat.p99))}${kv('5xx hata oranı',a.errorRate5xx==null?'-':'%'+a.errorRate5xx)}${kv('Kuyruk bekleme P95',ms(d.timings.queueWaitMs&&d.timings.queueWaitMs.p95))}${kv('Tarama süresi P95',ms(d.timings.scanDurationMs&&d.timings.scanDurationMs.p95))}</div>
  <div class="card"><b>Backend</b>${kv('Sürüm',esc(h.version||'-'))}${kv('Firestore',h.firestore&&h.firestore.reachable?'Bağlı ('+ms(h.firestore.latencyMs)+')':'<b>Bağlı değil</b>')}</div>`}
 if(BK.tab==='users'){const rows=(d.users||[]).map(u=>`<div class="item"><div class="g"><b>${esc(u.email||u.uid)}</b><span>${esc(u.uid)} • ${u.assetCount==null?'varlık: -':u.assetCount+' varlık'} • ${esc(u.lastSignInAt||'giriş yok')}</span></div><span class="badge ${u.disabled?'bd':'ok'}">${u.disabled?'Devre dışı':'Aktif'}</span><div class="acts"><button class="btn s" data-act="adm-user" data-id="${esc(u.uid)}">Detay</button><button class="btn s d" data-act="adm-disable" data-id="${esc(u.uid)}" data-v="${u.disabled?'0':'1'}">${u.disabled?'Etkinleştir':'Devre dışı bırak'}</button></div></div>`).join('')||'<div class="empty">Kullanıcı yok</div>';
  return`<div class="card"><div class="row2"><input class="field" id="adm-uq" placeholder="E-posta, ad veya UID" value="${esc(BK.adm.uq||'')}"><select class="field" id="adm-us"><option value="all">Tümü</option><option value="active"${BK.adm.us==='active'?' selected':''}>Aktif</option><option value="disabled"${BK.adm.us==='disabled'?' selected':''}>Devre dışı</option></select></div><button class="btn p w" data-act="adm-search">Ara</button></div><div class="card">${rows}</div><div id="adm-detail"></div>`}
 if(BK.tab==='jobs')return`<div class="card">${kv('Motor',d.engine.persistent?'Kalıcı (Firestore)':'<b>Kalıcı değil (bellek)</b>')}${kv('Çalışan / eşzamanlılık',d.engine.running+' / '+d.engine.concurrency)}</div><div class="card">${(d.jobs||[]).map(j=>`<div class="item"><div class="g"><b>${esc(j.label)}</b><span>${esc(j.ownerId)} • ${j.total} hedef • ${esc(fmt(j.createdAt))}</span></div><span class="badge ${stTone(j.status==='PENDING'||j.status==='RUNNING'?'':j.status)}">${esc(ST[j.status]||j.status)}</span><div class="acts"><button class="btn s" data-act="adm-jretry" data-id="${esc(j.id)}">Başarısızları yeniden dene</button><button class="btn s d" data-act="adm-jcancel" data-id="${esc(j.id)}">İptal</button></div></div>`).join('')||'<div class="empty">İş yok</div>'}</div>`;
 if(BK.tab==='errors')return`<div class="card"><div class="hint">Bellek içi kayıt: sunucu yeniden başlayınca silinir. Hassas veriler maskelenir.</div>${(d.errors||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.source)}${x.status?' '+x.status:''}</b><span>${esc(x.at)} ${esc(x.path||'')}</span><span>${esc(x.message)}</span></div></div>`).join('')||'<div class="empty">Kayıtlı hata yok</div>'}</div>`;
 if(BK.tab==='audit')return d.available===false?`<div class="card"><div class="empty">Veri yok: ${esc(d.reason||'')}</div></div>`:`<div class="card">${(d.entries||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.action)}</b><span>${esc(new Date(x.at).toLocaleString('tr-TR'))} • ${esc(x.adminEmail||x.adminUid)} → ${esc(x.target||'-')}</span></div></div>`).join('')||'<div class="empty">Kayıt yok</div>'}</div>`;
 if(BK.tab==='admins')return`<div class="card"><form data-admform="grant"><b>Yönetici ekle</b><div class="hint">Kullanıcı DAC'a giriş yapmış ve e-postasını doğrulamış olmalı.</div><input class="field" name="email" type="email" placeholder="E-posta" required><button class="btn p w" type="submit">Yönetici yap</button></form></div><div class="card">${(d.admins||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.email||x.uid)}</b><span>${esc(x.source)}</span></div>${x.removable?`<button class="btn s d" data-act="adm-revoke" data-id="${esc(x.uid)}">Yetkiyi kaldır</button>`:'<span class="badge mu">Render ayarı</span>'}</div>`).join('')}<div class="hint">${esc(d.note||'')}</div></div>`;
 if(BK.tab==='health'){const h=d.health||{};return`<div class="card">${kv('Sürüm',esc(h.version))}${kv('Ortam',esc(h.environment))}${kv('Çalışma süresi',Math.round((h.uptimeSeconds||0)/60)+' dk')}${kv('Bellek (RSS)',(h.memoryMB&&h.memoryMB.rss)+' MB')}${kv('Firebase Admin',h.firebase&&h.firebase.adminReady?'Hazır':'Yok')}${kv('Firestore',h.firestore&&h.firestore.reachable?'Bağlı':'Bağlı değil')}${kv('Stripe / iyzico',(h.payments&&h.payments.stripe?'Açık':'Kapalı')+' / '+(h.payments&&h.payments.iyzico?'Açık':'Kapalı'))}${kv('Otomatik tarama',h.autoScan&&h.autoScan.enabled?'Açık':'Kapalı')}${kv('Dış cron ucu',h.autoScan&&h.autoScan.cronEndpoint?'Tanımlı':'Tanımsız')}${kv('RDAP verisi',h.rdap&&h.rdap.bootstrapLoaded?'Yüklü':'Henüz yüklenmedi')}${kv('Geliştirme bypass',h.devBypassActive?'<b>AÇIK (kapatın)</b>':'Kapalı')}</div>`}
 if(BK.tab==='platform'){const ai=d.ai||{},bl=d.billing||{},st=ai.status||{};return`<div class="card"><b>AI</b>${kv('Durum',st.enabled?'Etkin':'<b>Devre dışı</b>')}<div class="hint">${esc(st.reason||'')}</div>${kv('Kayıtlı sağlayıcı',esc((st.registeredProviders||[]).join(', ')||'yok'))}${kv('Kullanım kaydı',ai.usageModel?ai.usageModel.recordsWritten:0)}<div class="hint">Rapor veri modeli: ${esc((ai.reportModel&&ai.reportModel.schema)||'')} (aylık/yıllık, AI'siz çalışır)</div></div>
 <div class="card"><b>Para birimleri</b>${(bl.currencies||[]).map(c=>kv(c.code+' '+c.name,c.enabled?'Fiyatlı':'Fiyat tanımlı değil')).join('')}<div class="hint">${esc((bl.rateProvider&&bl.rateProvider.note)||'')}</div></div>
 <div class="card"><b>Affiliate</b>${kv('Durum',bl.affiliate&&bl.affiliate.enabled?'Etkin':'Devre dışı')}<div class="hint">${esc((bl.affiliate&&bl.affiliate.note)||'')}</div></div>
 <div class="card"><b>Skor ağırlıkları</b>${Object.entries((d.scoring&&d.scoring.weights)||{}).map(([k,v])=>kv(k.toUpperCase(),'%'+v)).join('')}${kv('Kritik bulgu üst sınırı',d.scoring&&d.scoring.criticalCap)}</div>`}
 return'';
}
async function admAct(act,id,b){
 if(act==='adm-refresh'){await admLoad(BK.tab);return admPaint()}
 if(act==='adm-tab'){await admLoad(id);return admPaint()}
 if(act==='adm-search'){BK.adm.uq=$('#adm-uq').value.trim();BK.adm.us=$('#adm-us').value;await admLoad('users');return admPaint()}
 if(act==='adm-user'){const j=await bkApi('GET','/api/admin/users/'+encodeURIComponent(id));const u=j.user;$('#adm-detail').innerHTML=`<div class="card"><b>${esc(u.email||u.uid)}</b>${kv('UID',esc(u.uid))}${kv('Kayıt',esc(u.createdAt||'-'))}${kv('Son giriş',esc(u.lastSignInAt||'-'))}${kv('Yönetici',u.isAdmin?'Evet':'Hayır')}${kv('Varlık sayısı',j.assets.available?j.assets.count:'Veri yok')}${kv('Paket',j.plan?esc(j.plan.plan):'Veri yok')}${Object.entries(j.assets.byType||{}).map(([k,n])=>kv(k,n)).join('')}</div>`;return}
 if(act==='adm-disable'){const dis=b.dataset.v==='1';if(!confirm(dis?'Kullanıcı devre dışı bırakılsın mı? Oturumları kapatılır.':'Kullanıcı yeniden etkinleştirilsin mi?'))return;await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/disable',{disabled:dis});toast('Güncellendi');await admLoad('users');return admPaint()}
 if(act==='adm-revoke'){if(!confirm('Yönetici yetkisi kaldırılsın mı?'))return;await bkApi('DELETE','/api/admin/admins/'+encodeURIComponent(id));toast('Yetki kaldırıldı');await admLoad('admins');return admPaint()}
 if(act==='adm-jretry'){const j=await bkApi('POST','/api/admin/jobs/'+encodeURIComponent(id)+'/retry',{});toast(j.requeued+' başarısız kayıt yeniden sıraya alındı');await admLoad('jobs');return admPaint()}
 if(act==='adm-jcancel'){if(!confirm('İş iptal edilsin mi?'))return;const j=await bkApi('POST','/api/admin/jobs/'+encodeURIComponent(id)+'/cancel',{});toast(j.canceled+' kayıt iptal edildi');await admLoad('jobs');return admPaint()}
}
document.addEventListener('submit',async e=>{const f=e.target.closest('[data-admform]');if(!f)return;e.preventDefault();try{await bkApi('POST','/api/admin/admins',{email:String(new FormData(f).get('email')||'').trim()});toast('Yönetici eklendi');await admLoad('admins');admPaint()}catch(x){toast(x.message,'err')}});
window.addEventListener('hashchange',()=>setTimeout(async()=>{bkPoll();const r=(location.hash.slice(1)||'dash').split('/')[0];if(r==='bulk'||r==='domains'){try{await bkLoadView();bkPaint()}catch{}}},0));
