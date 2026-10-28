/* Digital Asset Center - ana render, olaylar ve giriş/başlatma (app-analysis.js'den sonra yüklenir) */
/* ---------- ana render ---------- */
const NAV0=()=>[['GENEL',[['dash','Genel Bakış','layout-grid']]],...GROUPS.map(([g,l])=>[l,Object.entries(CATS).filter(([,v])=>v.g===g).map(([k,v])=>['cat/'+k,v.label,v.icon])]),
 ['YÖNETİM',[['assets','Varlıklarım','database'],['history','Tarama Geçmişi','history'],['renewals','Yenileme Takvimi','calendar-clock'],['reports','Raporlar','bar-chart-3'],['team','Ekip Yönetimi','users'],['projects','Müşteri Projeleri','briefcase'],['bulk','Toplu Tarama','list-checks'],['plan','Paket ve Faturalandırma','credit-card'],['support','Destek','life-buoy'],['settings','Ayarlar','settings']]]];
const NAV=()=>{const n=NAV0();if(BK.isAdmin)n.push(['SİSTEM',[['admin','Yönetici Paneli','shield']]]);return n};
const icons=()=>window.lucide&&lucide.createIcons();
function render(){
 if(!S)return;
 const nv0=$('#side .nav'),navTop=nv0?nv0.scrollTop:0; // yan menü kaydırması yeniden çizimde sıfırlanmasın
 const r=location.hash.slice(1)||'dash',[p,k]=r.split('/'),ps=planState();
 const counts={};Object.keys(CATS).forEach(c=>counts[c]=S.assets.filter(a=>a.cat===c).length);
 $('#side').innerHTML=`<div class="brand"><div class="logo">${ic('shield')}</div><div><b>Digital Asset Center</b><small>v11 • ${esc(planName(ps))}</small></div></div>
 <nav class="nav">${NAV().map(([t,it])=>`<h6>${t}</h6>`+it.map(([h,l,i])=>`<a href="#${h}" class="${h===r?'on':''}" data-nb="${h}">${ic(i)}${l}${h.startsWith('cat/')?`<b>${counts[h.slice(4)]}</b>`:''}${nbHtml(...nbOf(h))}</a>`).join('')).join('')}</nav>
 <div class="org"><div class="orgc"><div class="r"><div class="av">${esc(S.settings.org.slice(0,2).toUpperCase())}</div><div><b>${esc(S.settings.org)}</b><br><small>${esc(planName(ps))} • ${S.assets.length}/${limTxt(ps)} varlık${ps.trial?' • '+leftTxt(ps.left):''}</small></div></div>
 <div class="btns"><a class="btn s" href="#settings">${ic('settings')} Ayarlar</a><button class="btn s" data-act="logout">${ic('log-out')} Çıkış</button></div></div></div>`;
 $('#av').textContent=S.settings.org.slice(0,2).toUpperCase();
 $('#dot').style.display=alerts().length?'block':'none';
 $('#view').innerHTML=siteBanner()+(p==='cat'&&CATS[k]?catPage(k):p==='assets'?assets():p==='bulk'?bulkPage():p==='whoami'?whoamiPage():p==='domains'?domainsPage():p==='admin'&&BK.isAdmin?adminPage():p==='history'?history():p==='reports'?reports():p==='renewals'?renewals():LISTS[p]?listPage(p):p==='plan'?plan():p==='support'?supportPage():p==='settings'?settings():dash());
 icons();bkPoll();
 const nv1=$('#side .nav');if(nv1){nv1.scrollTop=navTop;navShowActive(false)}
 bdgPaint();
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
 if(act==='menu'){$('#side').classList.add('open');$('#shade').classList.add('on');navShowActive(true)}
 else if(act==='close')close();
 else if(act==='detail')showDetail(id);
 else if(act==='rescan')rescan(id,$('#modal').classList.contains('on'));
 else if(act==='cat-refresh')refreshCat(id);
 else if(act==='del'){if(A&&confirm(`"${A.name}" silinsin mi?`)){S.assets=S.assets.filter(x=>x.id!==id);(S.tomb=S.tomb||{})[id]=Date.now();save();close();render();delRemote(id);toast('Varlık silindi')}}
 else if(act==='sug'){const i=$('[name=t]');if(i)i.value=b.dataset.v}
 else if(act==='goto'){$('#bell').classList.remove('on');if(b.dataset.tab&&typeof BK!=='undefined'){BK.tab=b.dataset.tab;BK.adm.err=null}if(location.hash==='#'+b.dataset.to){render();if(b.dataset.tab)bdgAdmSeen(b.dataset.tab)}else location.hash=b.dataset.to}
 else if(act==='bell'){const al=alerts(),sp=bdgUserSupport(),an=bdgUserAnn(),ad=SITE&&SITE.announcement,parts=[];
  if(an&&ad)parts.push(`<div class="it">${ic('megaphone')} <b>Duyuru</b><div class="hint">${esc(ad.text)}</div></div>`);
  if(BK.isAdmin){const AD=BADGE.adm||{};[['support','life-buoy','bekleyen destek talebi'],['users','user-plus','yeni kullanıcı'],['orders','credit-card','yeni ödeme'],['errors','triangle-alert','yeni sistem hatası']].forEach(([k,i,t])=>{if((AD[k]|0)>0)parts.push(`<a data-act="goto" data-to="admin" data-tab="${k}">${ic(i)} <b>Yönetici:</b> ${AD[k]|0} ${t}</a>`)})}
  sp.forEach(t=>parts.push(`<a data-act="goto" data-to="support">${ic('life-buoy')} #${esc(t.no)} ${esc(bdgSupTxt(t))}</a>`));
  al.forEach(a=>parts.push(`<a data-act="detail" data-id="${esc(a.id)}">${ic('triangle-alert')} ${esc(a.name)} <span class="badge ${sc(a)!=null?tone(sc(a)):'bd'}">${sc(a)??'!'}</span></a>`));
  $('#bell').innerHTML=parts.length?parts.join(''):'<div class="it hint">Bildirim yok</div>';$('#bell').classList.toggle('on');icons();
  if(an&&ad&&$('#bell').classList.contains('on')){bdgSet('aseen',ad.at);bdgPaint()}}
 else if(act==='clearhist'){S.scans=[];save();render()}
 else if(act==='cur'){st.currency=b.dataset.v;save();render()}
 else if(act==='cycle'){st.cycle=b.dataset.v;save();render()}
 else if(act==='buy')checkout(b.dataset.p);
 else if(act==='portal')portal();
 else if(act==='pcpn-apply')planCpnApply();else if(act==='pcpn-clear')planCpnClear();
 else if(act==='sub-cancel')subCancelAsk();else if(act==='sub-cancel-go')subCancelGo(b.dataset.v==='1');else if(act==='sub-resume')subResume();
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
 syncReset();save(true);render();syncPlan();handleReturn();pullState().then(()=>pullLatest(true));sendConsents();bkInit();loadPricing(true);loadSite(true);startSiteTimer();bdgStart();
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
window.dacStop=()=>{BK.isAdmin=false;clearInterval(BK.timer);BK.timer=null;bdgStop();syncReset();S=null;U=null;close();$('#view').innerHTML='';location.hash=''};

/* ---------- rozetler: yönetici = kırmızı, kullanıcı = koyu mor ---------- */
/* Yönetici: bekleyen destek + son baktığından beri yeni kullanıcı/sipariş/hata. Kullanıcı: yöneticiden gelen destek yanıtı/kapatma ve yeni duyuru. */
var BADGE={adm:{support:0,users:0,orders:0,errors:0},sup:[],off:0,timer:null,busy:false,again:false};
const BDG_ADM=['users','orders','errors'];
const bdgKey=n=>'dac_bdg_'+n+'_'+(U&&U.uid||'');
const bdgGet=(n,d)=>{try{const v=JSON.parse(localStorage.getItem(bdgKey(n)));return v==null?d:v}catch{return d}};
const bdgSet=(n,v)=>{try{localStorage.setItem(bdgKey(n),JSON.stringify(v))}catch{}};
const bdgNow=()=>Date.now()+(BADGE.off||0); // sunucu saatine göre (cihaz saati kaymasına karşı)
const nbHtml=(n,c)=>n>0?`<em class="nb ${c}">${n>99?'99+':n}</em>`:'';
const bdgAdmTotal=()=>BK.isAdmin?Object.values(BADGE.adm).reduce((a,b)=>a+(b|0),0):0;
const nbOf=h=>h==='support'?[bdgUserSupport().length,'nb-p']:h==='admin'?[bdgAdmTotal(),'nb-r']:[0,''];
const bdgSupTxt=t=>t.status==='closed'?'talebiniz kapatıldı':t.status==='resolved'?'talebiniz sonuçlandı':t.status==='answered'?'talebinize yanıt geldi':'talebiniz yeniden açıldı';
function bdgUserSupport(){const base=bdgGet('sbase',0),seen=bdgGet('sseen',{});return BADGE.sup.filter(t=>t.staffAt>Math.max(base,seen[t.id]||0))}
function bdgUserAnn(){const a=SITE&&SITE.announcement;if(!a||!a.at)return 0;return a.at>Math.max(bdgGet('abase',0),bdgGet('aseen',0))?1:0}
function bdgSupSeen(list){const seen=bdgGet('sseen',{});let ch=false;(list||[]).forEach(t=>{if((seen[t.id]||0)<t.staffAt){seen[t.id]=t.staffAt;ch=true}});if(ch)bdgSet('sseen',seen);bdgPaint()}
function bdgAdmSeen(tab){if(!BDG_ADM.includes(tab))return;const s=bdgGet('admseen',{});s[tab]=bdgNow();bdgSet('admseen',s);if(BADGE.adm[tab]){BADGE.adm[tab]=0;bdgPaint()}}
function setNb(host,n,cls){if(!host)return;let el=host.querySelector(':scope > .nb');if(!n){if(el)el.remove();return}if(!el){el=document.createElement('em');host.append(el)}el.className='nb '+cls;el.textContent=n>99?'99+':String(n)}
function bdgPaint(){
 if(!S)return;
 const sp=bdgUserSupport().length,an=bdgUserAnn(),adm=bdgAdmTotal();
 document.querySelectorAll('#side .nav a[data-nb]').forEach(a=>{const [n,c]=nbOf(a.dataset.nb);setNb(a,n,c)});
 setNb($('[data-act=bell]'),sp+an+adm,adm?'nb-r':'nb-p');
 setNb($('[data-act=menu]'),adm||sp+an,adm?'nb-r':'nb-p');
 if(typeof admTabs==='function'){const t=$('#adm-tabs');if(t)t.innerHTML=admTabs()}
}
/* sunucu çağrısı: arka plan yoklaması hiçbir zaman 2FA penceresi açmaz, hata verirse sessiz kalır */
async function bdgFetch(path){const api=apiUrl();if(!api)return null;try{const r=await fetch(api+path,{headers:{...await authH(),...(path.startsWith('/api/admin/')?a2faH():{})}});if(!r.ok)return null;const j=await r.json();if(!j||j.success===false)return null;if(j.serverTime)BADGE.off=j.serverTime-Date.now();return j}catch{return null}}
async function bdgUserPull(){
 const j=await bdgFetch('/api/support/my/summary');
 if(j&&Array.isArray(j.tickets)){if(bdgGet('sbase',null)==null)bdgSet('sbase',j.serverTime||Date.now());BADGE.sup=j.tickets}
 if(SITE&&bdgGet('abase',null)==null)bdgSet('abase',SITE.serverTime||Date.now());
}
async function bdgAdminPull(){
 if(!BK.isAdmin)return;
 const seen=bdgGet('admseen',{});let ch=false;BDG_ADM.forEach(k=>{if(!seen[k]){seen[k]=bdgNow()-864e5;ch=true}});if(ch)bdgSet('admseen',seen);
 const j=await bdgFetch('/api/admin/badges?'+new URLSearchParams({users:seen.users,orders:seen.orders,errors:seen.errors}));
 if(j)BADGE.adm={support:j.support|0,users:j.users|0,orders:j.orders|0,errors:j.errors|0};
}
async function bdgPull(){
 if(!S||!U)return;
 if(BADGE.busy){BADGE.again=true;return}
 BADGE.busy=true;
 try{await Promise.all([bdgUserPull(),bdgAdminPull()])}catch{}
 BADGE.busy=false;
 const r=(location.hash.slice(1)||'').split('/')[0];
 if(r==='support')bdgSupSeen(BADGE.sup);
 if(r==='admin')bdgAdmSeen(BK.tab);
 bdgPaint();
 if(BADGE.again){BADGE.again=false;return bdgPull()}
}
function bdgStart(){if(BADGE.timer)return;bdgPull();BADGE.timer=setInterval(()=>{if(!document.hidden)bdgPull()},60000)}
function bdgStop(){clearInterval(BADGE.timer);BADGE.timer=null;BADGE.adm={support:0,users:0,orders:0,errors:0};BADGE.sup=[]}
addEventListener('focus',()=>{if(S&&U)bdgPull()});
addEventListener('hashchange',()=>{const r=(location.hash.slice(1)||'').split('/')[0];if(r==='support')bdgSupSeen(BADGE.sup);if(r==='admin')bdgAdmSeen(BK.tab)});

/* ---------- yan menü: seçili öğeyi görünür tut ---------- */
function navShowActive(center){
 const nv=$('#side .nav'),on=nv&&nv.querySelector('a.on');if(!on)return;
 const a=on.getBoundingClientRect(),b=nv.getBoundingClientRect();
 if(center||a.top<b.top||a.bottom>b.bottom)nv.scrollTop=Math.max(0,a.top-b.top+nv.scrollTop-(b.height-a.height)/2);
}
