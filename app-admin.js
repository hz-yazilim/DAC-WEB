/* Digital Asset Center - yönetici paneli çekirdeği + fiyat/kupon/duyuru (app.js'den sonra yüklenir) */
/* --- Yönetici paneli (tüm veriler sunucudan; gerçek veri yoksa "veri yok" yazılır) --- */
const ADMTABS=[['overview','Genel Bakış'],['users','Kullanıcılar'],['jobs','Tarama Kuyruğu'],['subs','Paketler'],['orders','Ödemeler'],['errors','Sistem Hataları'],['audit','İşlem Kayıtları'],['admins','Yetkili Hesaplar'],['health','Sağlık'],['site','Duyuru ve Bakım'],['support','Destek'],['ops','Operasyon'],['security','Güvenlik'],['platform','AI ve Altyapı']];
const admPath={overview:'/api/admin/overview',users:'/api/admin/users',jobs:'/api/admin/jobs',subs:'/api/admin/subscriptions',orders:'/api/admin/orders',errors:'/api/admin/errors',audit:'/api/admin/audit',admins:'/api/admin/admins',health:'/api/admin/health',site:'/api/admin/site',support:'/api/admin/support',ops:'/api/admin/ops',security:'/api/admin/2fa/status',platform:'/api/admin/platform'};
async function admLoad0(tab){BK.tab=tab;const qs=tab==='users'?'?'+new URLSearchParams({q:BK.adm.uq||'',status:BK.adm.us||'all'}):tab==='subs'?'?'+new URLSearchParams({q:BK.adm.sq||'',plan:BK.adm.sp||'all'}):tab==='orders'?'?'+new URLSearchParams({status:BK.adm.os||''}):'';try{BK.adm[tab]=await bkApi('GET',admPath[tab]+qs);BK.adm.err=null}catch(e){BK.adm.err=e.message}}
function adminPage(){if(!BK.adm[BK.tab]&&!BK.adm.err)admLoad(BK.tab).then(admPaint);return`<div class="mh"><div><h2>Yönetici Paneli</h2><div class="hint">Panel sürümü: 20261030a</div></div><button class="btn s" data-act="adm-refresh">${ic('refresh-cw')} Yenile</button></div><div class="bktabs" id="adm-tabs">${admTabs()}</div><div id="adm-body">${admBody()}</div>`}
const admTabs=()=>ADMTABS.map(([k,l])=>`<button class="btn s${BK.tab===k?' p':''}" data-act="adm-tab" data-id="${k}">${esc(l)}${nbHtml(((typeof BADGE!=='undefined'&&BADGE.adm)||{})[k==='orders'?'orders':k]|0,'nb-r')}</button>`).join('');
function admPaint(){const t=$('#adm-tabs');if(t)t.innerHTML=admTabs();const el=$('#adm-body');if(el){el.innerHTML=admBody();icons()}}
const av=x=>x&&x.available===false?`<span class="hint">Veri yok: ${esc(x.reason||'')}</span>`:x&&x.value!=null?String(x.value):'-';
const kv=(l,v)=>`<div class="item"><div class="g"><b>${esc(l)}</b></div><span>${v}</span></div>`;
const ms=x=>x==null?'-':x+' ms';
const fdt=t=>t?new Date(t).toLocaleString('tr-TR'):'-';
const planBadge=p=>!p?'':p.active?`<span class="badge ok">${esc(p.planName)}${p.free?' (ödemesiz)':''}${p.cancelAtPeriodEnd?' • iptal edildi':''}</span>`:`<span class="badge mu">Ücretsiz</span>`;
const ORD={paid:['Ödendi','ok'],pending:['Bekliyor','wn'],failed:['Başarısız','bd'],'activated-free':['Ödemesiz etkinleştirildi','mu']};
const ordBadge=s=>{const o=ORD[s]||[s||'-','mu'];return`<span class="badge ${o[1]}">${esc(o[0])}</span>`};
const ordRow=(o,mail)=>`<div class="item"><div class="g"><b>${esc(o.planName||o.plan||'-')} • ${o.cycle==='yearly'?'Yıllık':'Aylık'}${mail?' • '+esc(o.email||o.uid):''}</b><span>${esc(fdt(o.createdAt))} • ${esc(o.provider||'-')}${o.amount!=null?' • '+esc(o.amount)+' '+esc(o.currency||''):''}${o.gatewayStatus?' • '+esc(o.gatewayStatus):''}${o.couponCode?' • kupon '+esc(o.couponCode)+(o.discount?' (-'+esc(o.discount)+')':''):''}</span></div>${ordBadge(o.status)}</div>`;
function admDetail(j){
 const u=j.user,sb=j.subscription||null,orders=(j.orders||[]).map(o=>ordRow(o,false)).join('')||'<div class="hint">Sipariş kaydı yok</div>';
 const opts=P.PAID.map(k=>`<option value="${k}">${esc(P.PLANS[k].name)}</option>`).join('');
 return`<div class="card" id="adm-detail"><div class="mh"><b>${esc(u.email||u.uid)}</b><button class="btn s" data-act="adm-close">Kapat</button></div>${kv('UID',esc(u.uid))}${kv('Kayıt',esc(fdt(u.createdAt)))}${kv('Son giriş',esc(fdt(u.lastSignInAt)))}${kv('Durum',u.disabled?'Devre dışı':'Aktif')}${kv('E-posta doğrulanmış',u.emailVerified?'Evet':'Hayır')}${kv('Yönetici',u.isAdmin?'Evet':'Hayır')}${kv('Varlık sayısı',j.assets.available?j.assets.count:'Veri yok')}${Object.entries(j.assets.byType||{}).map(([k,n])=>kv(k,n)).join('')}
 <b>Paket</b>${kv('Güncel paket',sb?planBadge(sb):'Veri yok')}${sb&&sb.active?kv('Bitiş',esc(fdt(sb.periodEnd))):''}${sb&&sb.provider?kv('Sağlayıcı',esc(sb.provider)):''}${sb&&sb.cycle?kv('Dönem',sb.cycle==='yearly'?'Yıllık':'Aylık'):''}${sb&&sb.active?kv('Yenileme',sb.cancelAtPeriodEnd?'<b>İptal edildi</b> (dönem sonunda biter)':(sb.provider==='stripe'?'Otomatik yenilenir':'Otomatik yenilenmez')):''}${j.plan&&j.plan.plan==='trial'?kv('Deneme bitişi',esc(fdt(j.plan.trialEnd))):''}${j.plan&&j.plan.plan==='expired'?kv('Durum','<b>Deneme/paket süresi dolmuş</b>'):''}
 <div class="hint" style="margin:8px 0 4px">Müdahale: paket ver (ödemesiz) veya deneme süresi uzat</div>
 <div class="row2"><select class="field" id="adm-gplan">${opts}</select><input class="field" id="adm-gdays" type="number" min="1" max="3660" value="30" aria-label="Gün"></div>
 <div class="btns"><button class="btn p" data-act="adm-grant" data-id="${esc(u.uid)}">Paketi ver</button><button class="btn s d" data-act="adm-planrevoke" data-id="${esc(u.uid)}">Paketi kaldır</button></div>
 ${sb&&(sb.active||(sb.provider==='stripe'&&sb.status!=='canceled'&&sb.status!=='none'))?`<div class="btns" style="margin-top:8px"><button class="btn s d" data-act="adm-subcancel" data-id="${esc(u.uid)}">${ic('circle-x')} Aboneliği iptal et</button>${sb.cancelAtPeriodEnd?`<button class="btn s" data-act="adm-subresume" data-id="${esc(u.uid)}">${ic('rotate-ccw')} İptali geri al</button>`:''}</div>`:''}
 <div class="row2" style="margin-top:8px"><input class="field" id="adm-tdays" type="number" min="1" max="90" value="3" aria-label="Deneme günü"><button class="btn s" data-act="adm-trial" data-id="${esc(u.uid)}">Denemeyi uzat (gün)</button></div>
 <div class="hint" style="margin:10px 0 4px">Hesap işlemleri</div>
 <div class="btns"><button class="btn s" data-act="adm-revsess" data-id="${esc(u.uid)}">Oturumları kapat</button><button class="btn s d" data-act="adm-deluser" data-id="${esc(u.uid)}">Hesabı sil (KVKK)</button><button class="btn s" data-act="adm-pwreset" data-id="${esc(u.uid)}">Şifre sıfırlama bağlantısı</button>${u.emailVerified?'':`<button class="btn s" data-act="adm-verify" data-id="${esc(u.uid)}">E-postayı doğrulandı say</button>`}</div>
 <div class="hint" style="margin:10px 0 4px">Yönetici notu (yalnızca yöneticiler görür)${j.note?' • '+esc(j.note.by||'')+' • '+esc(fdt(j.note.at)):''}</div><textarea class="field" id="adm-note" maxlength="1000" placeholder="Bu kullanıcı hakkında not…">${esc(j.note?j.note.text:'')}</textarea><button class="btn s" data-act="adm-notesave" data-id="${esc(u.uid)}">Notu kaydet</button>
 <b style="display:block;margin-top:10px">Son siparişler</b>${orders}</div>`;
}
function admBody(){
 const inner=admBody0();
 return inner+(['users','subs'].includes(BK.tab)&&BK.adm.detail&&!BK.adm.err?admDetail(BK.adm.detail):'');
}
function admBody0(){
 if(BK.tab==='orders')return payNav()+payBody();
 const d=BK.adm[BK.tab];if(BK.adm.err)return`<div class="card"><div class="empty">${esc(BK.adm.err)}</div></div>`;if(!d)return'<div class="card"><div class="empty">Yükleniyor…</div></div>';
 if(BK.tab==='overview'){const u=d.users,a=d.api,q=d.queue,sc=d.scans,h=d.health||{};const lat=a.latencyMs||{};
  return`<div class="card">${kv('Toplam kullanıcı',u.available===false?av(u):u.total)}${kv('Aktif / devre dışı',u.available===false?'-':u.active+' / '+u.disabled)}${kv('Son 30 gün aktif',u.available===false?'-':u.activeLast30Days)}${kv('Kayıtlı varlık',av(d.assets))}</div>
  <div class="card"><b>Taramalar (kalıcı)</b>${kv('Toplam',av(sc.total))}${kv('Son 24 saat',av(sc.last24h))}${kv('Başarılı',av(sc.completed))}${kv('Kısmen',av(sc.partial))}${kv('Başarısız',av(sc.failed))}${kv('Zaman aşımı',av(sc.timedOut))}</div>
  <div class="card"><b>Kuyruk</b>${kv('Bekleyen',q.pending)}${kv('Devam eden',q.running)}${kv('Tamamlanan',q.items.COMPLETED)}${kv('Kısmen tamamlanan',q.items.PARTIAL)}${kv('Başarısız',q.items.FAILED)}${kv('İptal edilen',q.items.CANCELED)}${kv('Kalıcı depo',q.engine&&q.engine.persistent?'Evet (Firestore)':'<b>Hayır (bellek)</b>')}</div>
  <div class="card"><b>API (son ${a.windowMinutes} dk, yeniden başlayınca sıfırlanır)</b>${kv('İstek',a.requests)}${kv('P50',ms(lat.p50))}${kv('P95',ms(lat.p95))}${kv('P99',ms(lat.p99))}${kv('5xx hata oranı',a.errorRate5xx==null?'-':'%'+a.errorRate5xx)}${kv('Kuyruk bekleme P95',ms(d.timings.queueWaitMs&&d.timings.queueWaitMs.p95))}${kv('Tarama süresi P95',ms(d.timings.scanDurationMs&&d.timings.scanDurationMs.p95))}</div>
  <div class="card"><b>Backend</b>${kv('Sürüm',esc(h.version||'-'))}${kv('Firestore',h.firestore&&h.firestore.reachable?'Bağlı ('+ms(h.firestore.latencyMs)+')':'<b>Bağlı değil</b>')}</div>`}
 if(BK.tab==='users'){const rows=(d.users||[]).map(u=>`<div class="item"><input type="checkbox" class="ub" value="${esc(u.uid)}" aria-label="Seç"><div class="g"><b>${esc(u.email||u.uid)}</b><span>${esc(u.uid)} • ${u.assetCount==null?'varlık: -':u.assetCount+' varlık'} • ${esc(u.lastSignInAt||'giriş yok')}</span></div>${planBadge(u.plan)}<span class="badge ${u.disabled?'bd':'ok'}">${u.disabled?'Devre dışı':'Aktif'}</span><div class="acts"><button class="btn s" data-act="adm-user" data-id="${esc(u.uid)}">Detay</button><button class="btn s d" data-act="adm-disable" data-id="${esc(u.uid)}" data-v="${u.disabled?'0':'1'}">${u.disabled?'Etkinleştir':'Devre dışı bırak'}</button></div></div>`).join('')||'<div class="empty">Kullanıcı yok</div>';
  return`<div class="card"><div class="row2"><input class="field" id="adm-uq" placeholder="E-posta, ad veya UID" value="${esc(BK.adm.uq||'')}"><select class="field" id="adm-us"><option value="all">Tümü</option><option value="active"${BK.adm.us==='active'?' selected':''}>Aktif</option><option value="disabled"${BK.adm.us==='disabled'?' selected':''}>Devre dışı</option></select></div><div class="btns"><button class="btn p" data-act="adm-search">Ara</button><button class="btn s" data-act="adm-csv" data-id="users">CSV indir</button></div></div><div class="card"><div class="hint">Toplu işlem (seçili kullanıcılar, en çok 200)</div><div class="row2"><select class="field" id="bulk-act"><option value="grant">Paket ver</option><option value="revoke">Verilen paketi kaldır</option><option value="disable">Devre dışı bırak</option><option value="enable">Etkinleştir</option><option value="revoke-sessions">Oturumları kapat</option></select><select class="field" id="bulk-plan">${P.PAID.map(k=>`<option value="${k}">${esc(P.PLANS[k].name)}</option>`).join('')}</select></div><div class="row2"><input class="field" id="bulk-days" type="number" min="1" max="3660" value="30" aria-label="Gün"><button class="btn s" data-act="adm-bulkall">Tümünü seç/bırak</button></div><button class="btn p w" data-act="adm-bulk">Seçililere uygula</button></div><div class="card">${rows}</div>`}
 if(BK.tab==='subs'){
  if(d.available===false)return`<div class="card"><div class="empty">Veri yok: ${esc(d.reason||'')}</div></div>`;
  const m=d.summary||{},byPlan=m.byPlan||{};
  const fo=[['all','Tümü'],...P.PAID.map(k=>[k,P.PLANS[k].name]),['granted','Ödemesiz verilen'],['expired','Süresi dolan / iptal']].map(([v,l])=>`<option value="${v}"${(BK.adm.sp||'all')===v?' selected':''}>${esc(l)}</option>`).join('');
  const rows=(d.rows||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.email||x.uid)}</b><span>${esc(x.uid)} • ${x.active?'Bitiş: '+esc(fdt(x.periodEnd)):'Son paket: '+esc(x.lastPlanName||'-')+' ('+esc(x.status)+')'} • ${esc(x.provider||'-')}${x.cycle?' • '+(x.cycle==='yearly'?'Yıllık':'Aylık'):''}</span></div>${planBadge(x)}<div class="acts"><button class="btn s" data-act="adm-user" data-id="${esc(x.uid)}">Detay</button>${x.active||(x.provider==='stripe'&&x.status!=='canceled'&&x.status!=='none')?`<button class="btn s d" data-act="adm-subcancel" data-id="${esc(x.uid)}">İptal</button>`:''}${x.active&&x.cancelAtPeriodEnd?`<button class="btn s" data-act="adm-subresume" data-id="${esc(x.uid)}">İptali geri al</button>`:''}</div></div>`).join('')||'<div class="empty">Kayıt yok</div>';
  return`<div class="card"><b>Özet</b>${kv('Toplam kullanıcı',m.totalUsers==null?'-':m.totalUsers)}${kv('Ücretsiz (aktif paketi yok)',m.freeUsers==null?'-':m.freeUsers)}${kv('Aktif ücretli paket',m.paidActive)}${P.PAID.map(k=>kv(esc(P.PLANS[k].name),byPlan[k]||0)).join('')}${kv('Ödemesiz verilen / ödeme sağlayıcısız',m.grantedFree)}${kv('Süresi dolan / iptal',m.expiredOrCanceled)}<div class="hint">${esc(d.note||'')}</div></div>
  <div class="card"><div class="row2"><input class="field" id="adm-sq" placeholder="E-posta veya UID" value="${esc(BK.adm.sq||'')}"><select class="field" id="adm-sp">${fo}</select></div><div class="btns"><button class="btn p" data-act="adm-subsearch">Filtrele</button><button class="btn s" data-act="adm-csv" data-id="subs">CSV indir</button></div></div><div class="card">${rows}</div>${d.truncated?'<div class="hint">İlk 300 kayıt gösteriliyor; aramayı daraltın.</div>':''}`}
 if(BK.tab==='site')return siteBody(d);
 if(BK.tab==='support')return supportBody(d);
 if(BK.tab==='ops')return opsBody(d);
 if(BK.tab==='security')return securityBody(d);
 if(BK.tab==='jobs')return`<div class="card">${kv('Motor',d.engine.persistent?'Kalıcı (Firestore)':'<b>Kalıcı değil (bellek)</b>')}${kv('Çalışan / eşzamanlılık',d.engine.running+' / '+d.engine.concurrency)}</div><div class="card">${(d.jobs||[]).map(j=>`<div class="item"><div class="g"><b>${esc(j.label)}</b><span>${esc(j.ownerId)} • ${j.total} hedef • ${esc(fmt(j.createdAt))}</span></div><span class="badge ${stTone(j.status==='PENDING'||j.status==='RUNNING'?'':j.status)}">${esc(ST[j.status]||j.status)}</span><div class="acts"><button class="btn s" data-act="adm-jretry" data-id="${esc(j.id)}">Başarısızları yeniden dene</button><button class="btn s d" data-act="adm-jcancel" data-id="${esc(j.id)}">İptal</button></div></div>`).join('')||'<div class="empty">İş yok</div>'}</div>`;
 if(BK.tab==='errors')return`<div class="card"><div class="hint">Bellek içi kayıt: sunucu yeniden başlayınca silinir. Hassas veriler maskelenir.</div>${(d.errors||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.source)}${x.status?' '+x.status:''}</b><span>${esc(x.at)} ${esc(x.path||'')}</span><span>${esc(x.message)}</span></div></div>`).join('')||'<div class="empty">Kayıtlı hata yok</div>'}</div>`;
 if(BK.tab==='audit')return d.available===false?`<div class="card"><div class="empty">Veri yok: ${esc(d.reason||'')}</div></div>`:`<div class="card"><button class="btn s" data-act="adm-csv" data-id="audit">CSV indir</button>${(d.entries||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.action)}</b><span>${esc(new Date(x.at).toLocaleString('tr-TR'))} • ${esc(x.adminEmail||x.adminUid)} → ${esc(x.target||'-')}</span></div></div>`).join('')||'<div class="empty">Kayıt yok</div>'}</div>`;
 if(BK.tab==='admins')return`<div class="card"><form data-admform="grant"><b>Yönetici ekle</b><div class="hint">Kullanıcı DAC'a giriş yapmış ve e-postasını doğrulamış olmalı.</div><input class="field" name="email" type="email" placeholder="E-posta" required><button class="btn p w" type="submit">Yönetici yap</button></form></div><div class="card">${(d.admins||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.email||x.uid)}</b><span>${esc(x.source)}</span></div>${x.removable?`<button class="btn s d" data-act="adm-revoke" data-id="${esc(x.uid)}">Yetkiyi kaldır</button>`:'<span class="badge mu">Render ayarı</span>'}</div>`).join('')}<div class="hint">${esc(d.note||'')}</div></div>`;
 if(BK.tab==='health'){const h=d.health||{};return`<div class="card">${kv('Sürüm',esc(h.version))}${kv('Ortam',esc(h.environment))}${kv('Çalışma süresi',Math.round((h.uptimeSeconds||0)/60)+' dk')}${kv('Bellek (RSS)',(h.memoryMB&&h.memoryMB.rss)+' MB')}${kv('Firebase Admin',h.firebase&&h.firebase.adminReady?'Hazır':'Yok')}${kv('Firestore',h.firestore&&h.firestore.reachable?'Bağlı':'Bağlı değil')}${kv('Stripe / iyzico',(h.payments&&h.payments.stripe?'Açık':'Kapalı')+' / '+(h.payments&&h.payments.iyzico?'Açık':'Kapalı'))}${kv('Otomatik tarama',h.autoScan&&h.autoScan.enabled?'Açık':'Kapalı')}${kv('Dış cron ucu',h.autoScan&&h.autoScan.cronEndpoint?'Tanımlı':'Tanımsız')}${kv('RDAP verisi',h.rdap&&h.rdap.bootstrapLoaded?'Yüklü':'Henüz yüklenmedi')}${kv('Geliştirme bypass',h.devBypassActive?'<b>AÇIK (kapatın)</b>':'Kapalı')}</div>`}
 if(BK.tab==='platform'){const ai=d.ai||{},bl=d.billing||{},st=ai.status||{};return`<div class="card"><b>AI</b>${kv('Durum',st.enabled?'Etkin':'<b>Devre dışı</b>')}<div class="hint">${esc(st.reason||'')}</div>${kv('Kayıtlı sağlayıcı',esc((st.registeredProviders||[]).join(', ')||'yok'))}${kv('Kullanım kaydı',ai.usageModel?ai.usageModel.recordsWritten:0)}<div class="hint">Rapor veri modeli: ${esc((ai.reportModel&&ai.reportModel.schema)||'')} (aylık/yıllık, AI'siz çalışır)</div></div>
 <div class="card"><b>Para birimleri</b>${(bl.currencies||[]).map(c=>kv(c.code+' '+c.name,c.enabled?'Fiyatlı':'Fiyat tanımlı değil')).join('')}<div class="hint">${esc((bl.rateProvider&&bl.rateProvider.note)||'')}</div></div>
 <div class="card"><b>Affiliate</b>${kv('Durum',bl.affiliate&&bl.affiliate.enabled?'Etkin':'Devre dışı')}<div class="hint">${esc((bl.affiliate&&bl.affiliate.note)||'')}</div></div>
 <div class="card"><b>Skor ağırlıkları</b>${Object.entries((d.scoring&&d.scoring.weights)||{}).map(([k,v])=>kv(k.toUpperCase(),'%'+v)).join('')}${kv('Kritik bulgu üst sınırı',d.scoring&&d.scoring.criticalCap)}</div>`}
 return'';
}
async function admReloadDetail(uid){
 BK.adm.detail=await bkApi('GET','/api/admin/users/'+encodeURIComponent(uid));
 if(['users','subs','orders'].includes(BK.tab))await admLoad(BK.tab);
 admPaint();
}
async function admAct(act,id,b){
 if(ADM2.has(act))return ADM2_ROUTE(act,id,b);
 if(act==='adm-refresh'){await admLoad(BK.tab);return admPaint()}
 if(act==='adm-tab'){BK.tab=id;BK.adm.err=null;bdgAdmSeen(id);admPaint();await admLoad(id);return admPaint()}
 if(act==='adm-search'){BK.adm.uq=$('#adm-uq').value.trim();BK.adm.us=$('#adm-us').value;await admLoad('users');return admPaint()}
 if(act==='adm-user'){BK.adm.detail=await bkApi('GET','/api/admin/users/'+encodeURIComponent(id));admPaint();const el=$('#adm-detail');if(el&&el.scrollIntoView)el.scrollIntoView({block:'start',behavior:'smooth'});return}
 if(act==='adm-close'){BK.adm.detail=null;return admPaint()}
 if(act==='adm-subsearch'){BK.adm.sq=$('#adm-sq').value.trim();BK.adm.sp=$('#adm-sp').value;await admLoad('subs');return admPaint()}
 if(act==='adm-ordsearch'){BK.adm.os=$('#adm-os').value;await admLoad('orders');return admPaint()}
 if(act==='adm-grant'){const plan=$('#adm-gplan').value,days=Math.floor(+$('#adm-gdays').value||0);if(!(days>=1&&days<=3660))return toast('Gün sayısı 1-3660 olmalı','warn');if(!confirm('Kullanıcıya '+P.PLANS[plan].name+' paketi '+days+' gün ÖDEMESİZ verilsin mi?'))return;await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/plan',{plan,days});toast('Paket verildi');return admReloadDetail(id)}
 if(act==='adm-planrevoke'){if(!confirm('Kullanıcının paketi hemen sonlandırılsın mı?'))return;await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/plan/revoke',{});toast('Paket kaldırıldı');return admReloadDetail(id)}
 if(act==='adm-trial'){const days=Math.floor(+$('#adm-tdays').value||0);if(!(days>=1&&days<=90))return toast('Gün sayısı 1-90 olmalı','warn');if(!confirm('Deneme süresi bugünden itibaren '+days+' gün olarak ayarlansın mı?'))return;await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/trial',{days});toast('Deneme süresi güncellendi');return admReloadDetail(id)}
 if(act==='adm-disable'){const dis=b.dataset.v==='1';if(!confirm(dis?'Kullanıcı devre dışı bırakılsın mı? Oturumları kapatılır.':'Kullanıcı yeniden etkinleştirilsin mi?'))return;await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/disable',{disabled:dis});toast('Güncellendi');await admLoad('users');if(BK.adm.detail&&BK.adm.detail.user.uid===id)BK.adm.detail=await bkApi('GET','/api/admin/users/'+encodeURIComponent(id));return admPaint()}
 if(act==='adm-revoke'){if(!confirm('Yönetici yetkisi kaldırılsın mı?'))return;await bkApi('DELETE','/api/admin/admins/'+encodeURIComponent(id));toast('Yetki kaldırıldı');await admLoad('admins');return admPaint()}
 if(act==='adm-jretry'){const j=await bkApi('POST','/api/admin/jobs/'+encodeURIComponent(id)+'/retry',{});toast(j.requeued+' başarısız kayıt yeniden sıraya alındı');await admLoad('jobs');return admPaint()}
 if(act==='adm-jcancel'){if(!confirm('İş iptal edilsin mi?'))return;const j=await bkApi('POST','/api/admin/jobs/'+encodeURIComponent(id)+'/cancel',{});toast(j.canceled+' kayıt iptal edildi');await admLoad('jobs');return admPaint()}
}
/* ---------- V13.2: canlı fiyat, duyuru/bakım, kupon, Ödemeler sekmesi, kullanıcı müdahaleleri ---------- */
function applyPricing(pub){
 if(!pub||!pub.plans)return false;let ch=false;
 P.PAID.forEach(id=>{const n=pub.plans[id],p=P.PLANS[id];if(!n||!p||!n.prices)return;
  const key=JSON.stringify([p.prices,p.assets,p.team,p.history,p.features]);
  p.prices={...p.prices,TRY:n.prices.TRY,USD:n.prices.USD};p.priceTRY=n.prices.TRY;p.priceUSD=n.prices.USD;p.assets=n.assets;p.team=n.team;p.history=n.history;if(Array.isArray(n.features))p.features=n.features;
  if(key!==JSON.stringify([p.prices,p.assets,p.team,p.history,p.features]))ch=true});
 if(Number.isInteger(pub.yearlyMonths)&&pub.yearlyMonths!==P.YEARLY_MONTHS){P.YEARLY_MONTHS=pub.yearlyMonths;ch=true}
 return ch;
}
async function loadPricing(force){const api=apiUrl();if(!api||(!force&&Date.now()-PRICE_AT<60000))return;PRICE_AT=Date.now();try{const j=await (await fetch(api+'/api/pricing')).json();if(j&&j.success&&applyPricing(j))render()}catch{}}
async function loadSite(force){
 const api=apiUrl();if(!api||(!force&&Date.now()-SITE_AT<60000))return;SITE_AT=Date.now();
 try{const j=await (await fetch(api+'/api/site-status')).json();if(j&&j.success){const k=x=>JSON.stringify([x&&x.announcement,x&&x.maintenance&&x.maintenance.enabled,x&&x.maintenance&&x.maintenance.message]);const ch=k(j)!==k(SITE);SITE=j;if(ch)render()}}catch{}
}
function startSiteTimer(){if(window.__dacSiteT)return;window.__dacSiteT=setInterval(()=>{loadSite();loadPricing()},120000)}
function siteBanner(){
 if(!SITE)return'';let h='';
 if(SITE.maintenance&&SITE.maintenance.enabled)h+=`<div class="card banner bad" role="alert"><div><b>Bakım modu</b><div class="hint">${esc(SITE.maintenance.message)} Bu sırada yeni tarama başlatılamaz.</div></div></div>`;
 const a=SITE.announcement;if(a&&a.text)h+=`<div class="card banner ${a.level==='bad'?'bad':a.level==='warn'?'warn':''}" role="status"><div><b>${esc(a.text)}</b></div></div>`;
 return h;
}

/* CSV (Excel için ; ayırıcı + BOM; formül enjeksiyonuna karşı = + - @ ile başlayan hücreler kaçışlanır) */
const csvCell=v=>{let s=v==null?'':String(v);if(/^[=+\-@\t\r]/.test(s))s="'"+s;return /[";\n\r]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s};
function csvDl(name,head,rows){dl(name+'-'+new Date().toISOString().slice(0,10)+'.csv','\ufeff'+[head,...rows].map(r=>r.map(csvCell).join(';')).join('\r\n'),'text/csv;charset=utf-8')}
function admCsv(kind){
 const A=BK.adm;
 if(kind==='users'){const r=(A.users&&A.users.users)||[];return csvDl('kullanicilar',['UID','E-posta','Ad','E-posta doğrulandı','Devre dışı','Kayıt','Son giriş','Paket','Varlık'],r.map(u=>[u.uid,u.email,u.displayName,u.emailVerified?'Evet':'Hayır',u.disabled?'Evet':'Hayır',u.createdAt,u.lastSignInAt,u.plan&&u.plan.planName,u.assetCount]))}
 if(kind==='subs'){const r=(A.subs&&A.subs.rows)||[];return csvDl('abonelikler',['UID','E-posta','Paket','Aktif','Sağlayıcı','Dönem','Bitiş','Ödemesiz'],r.map(x=>[x.uid,x.email,x.active?x.planName:x.lastPlanName,x.active?'Evet':'Hayır',x.provider,x.cycle,x.periodEnd?new Date(x.periodEnd).toISOString():'',x.free?'Evet':'Hayır']))}
 if(kind==='orders'){const r=(A.pay&&A.pay.orders&&A.pay.orders.orders)||[];return csvDl('siparisler',['Sipariş','UID','E-posta','Paket','Dönem','Tutar','Para birimi','Durum','Sağlayıcı','Kupon','İndirim','Oluşturma','Ödeme'],r.map(o=>[o.id,o.uid,o.email,o.planName,o.cycle,o.amount,o.currency,o.status,o.provider,o.couponCode,o.discount,o.createdAt?new Date(o.createdAt).toISOString():'',o.paidAt?new Date(o.paidAt).toISOString():'']))}
 if(kind==='invoices'){const r=(A.pay&&A.pay.invoices&&A.pay.invoices.rows)||[];return csvDl('faturalar',['Sipariş','E-posta','Paket','Dönem','Tutar','Para birimi','İade','Ödeme tarihi','Fatura no'],r.map(o=>[o.id,o.email,o.planName,o.cycle,o.amount,o.currency,o.refundedAmount,o.paidAt?new Date(o.paidAt).toISOString():'',o.invoice&&o.invoice.no]))}
 if(kind==='audit'){const r=(A.audit&&A.audit.entries)||[];return csvDl('islem-kayitlari',['Zaman','Yönetici','İşlem','Hedef','Ayrıntı','IP'],r.map(x=>[new Date(x.at).toISOString(),x.adminEmail||x.adminUid,x.action,x.target,JSON.stringify(x.detail||{}),x.ip]))}
}

/* --- Ödemeler sekmesi: Fiyatlar | Siparişler | Gelir | Kuponlar --- */
const PAYSUB=[['prices','Fiyatlar'],['orders','Siparişler'],['invoices','Faturalar'],['revenue','Gelir'],['coupons','Kuponlar']];
const payPath={prices:'/api/admin/pricing',orders:'/api/admin/orders',invoices:'/api/admin/invoices',revenue:'/api/admin/revenue',coupons:'/api/admin/coupons'};
async function admLoad(tab){
 if(tab==='ops'){await admLoad0('ops');try{BK.adm.opsErr=(await bkApi('GET','/api/admin/errors/history?limit=30')).errors}catch{BK.adm.opsErr=[]}return}
 if(tab!=='orders')return admLoad0(tab);
 BK.tab='orders';const sub=BK.adm.paySub||'prices';
 try{const j=await bkApi('GET',payPath[sub]+(sub==='orders'?'?'+new URLSearchParams({status:BK.adm.os||''}):sub==='invoices'?'?filter='+(BK.adm.invf||'pending'):''));BK.adm.pay=BK.adm.pay||{};BK.adm.pay[sub]=j;BK.adm.orders=j;BK.adm.err=null}catch(e){BK.adm.err=e.message}
}
const payNav=()=>`<div class="bktabs">${PAYSUB.map(([k,l])=>`<button class="btn s${(BK.adm.paySub||'prices')===k?' p':''}" data-act="adm-paysub" data-id="${k}">${esc(l)}</button>`).join('')}</div>`;
const fmtTot=o=>{const k=Object.keys(o||{});return k.length?k.map(c=>money(o[c],c==='USD'?'USD':'TRY')).join(' • '):'—'};
function payBody(){
 const sub=BK.adm.paySub||'prices',d=BK.adm.pay&&BK.adm.pay[sub];
 if(BK.adm.err)return`<div class="card"><div class="empty">${esc(BK.adm.err)}</div></div>`;
 if(!d)return'<div class="card"><div class="empty">Yükleniyor…</div></div>';
 if(d.available===false)return`<div class="card"><div class="empty">Veri yok: ${esc(d.reason||'')}</div></div>`;
 return sub==='prices'?priceEditor(d):sub==='orders'?payOrders(d):sub==='invoices'?payInvoices(d):sub==='revenue'?payRevenue(d):payCoupons(d);
}
const FLD={TRY:'TL fiyatı',USD:'USD fiyatı',assets:'varlık limiti',team:'ekip limiti',history:'geçmiş limiti',yearlyMonths:'yıllık ödemede ücretlenen ay'};
const lv=v=>v==null?'sınırsız':v;
const numIn=x=>parseFloat(String(x).trim().replace(',','.'));
const yrTxt=(t,u,m)=>{const a=numIn(t),b=numIn(u);return Number.isFinite(a)&&Number.isFinite(b)&&m>=1&&m<=12?`Yıllık ödeme (${m} ay ücret): ${money(Math.round(a*m*100)/100,'TRY')} • ${money(Math.round(b*m*100)/100,'USD')}`:'Geçerli bir sayı girin'};
function prYrRefresh(){const d=BK.adm.pay&&BK.adm.pay.prices;if(!d)return;const m=Math.floor(+($('#pr-yearly')||{}).value);P.PAID.forEach(id=>{const el=$('#pr-'+id+'-yr'),t=$('#pr-'+id+'-TRY'),u=$('#pr-'+id+'-USD');if(el&&t&&u)el.textContent=yrTxt(t.value,u.value,m)})}
document.addEventListener('input',e=>{if(e.target&&e.target.id&&/^pr-/.test(e.target.id))prYrRefresh()});
function priceEditor(d){
 const cur=d.current,def=d.defaults,subs=d.subscribers||{};
 const cards=P.PAID.map(id=>{const c=cur.plans[id],df=def.plans[id],nm=(d.plans[id]||{}).name||id;
  return`<div class="card"><div class="mh"><b>${esc(nm)}</b><span class="badge mu">${subs[id]!=null?esc(subs[id])+' aktif abone':'abone: -'}</span></div>
  <div class="row2"><div><div class="hint">Aylık fiyat (₺ TL)</div><input class="field" id="pr-${id}-TRY" inputmode="decimal" value="${esc(c.TRY)}"></div><div><div class="hint">Aylık fiyat ($ USD)</div><input class="field" id="pr-${id}-USD" inputmode="decimal" value="${esc(c.USD)}"></div></div>
  <div class="hint" id="pr-${id}-yr">${esc(yrTxt(c.TRY,c.USD,cur.yearlyMonths))}</div>
  <div class="row2" style="margin-top:8px"><div><div class="hint">Varlık limiti (boş = sınırsız)</div><input class="field" id="pr-${id}-assets" type="number" min="1" placeholder="Sınırsız" value="${c.assets==null?'':esc(c.assets)}"></div><div><div class="hint">Ekip limiti (boş = sınırsız)</div><input class="field" id="pr-${id}-team" type="number" min="1" placeholder="Sınırsız" value="${c.team==null?'':esc(c.team)}"></div></div>
  <div class="hint">Tarama geçmişi limiti</div><input class="field" id="pr-${id}-history" type="number" min="10" value="${esc(c.history)}">
  <div class="hint">Varsayılan (kod): ${money(df.TRY,'TRY')} • ${money(df.USD,'USD')} • ${lv(df.assets)} varlık • ${lv(df.team)} ekip • ${df.history} geçmiş</div></div>`}).join('');
 const hist=(d.history||[]).map(h=>`<div class="item"><div class="g"><b>${h.action==='reset'?'Varsayılana dönüldü':(h.changes||[]).map(c=>`${esc(((d.plans[c.plan]||{}).name||'Genel'))} ${esc(FLD[c.field]||c.field)}: ${esc(lv(c.from))} → ${esc(lv(c.to))}`).join('<br>')}</b><span>${esc(fdt(h.at))} • ${esc(h.byEmail||h.by)}</span></div></div>`).join('')||'<div class="empty">Henüz değişiklik yok</div>';
 return`<div class="card"><b>Paket fiyatları ve limitleri</b><div class="hint">Durum: ${d.custom?`<b>Özel fiyat yayında</b> (son güncelleme: ${esc(fdt(d.updatedAt))} • ${esc(d.updatedBy||'-')})`:'Varsayılan (plans.js) fiyatlar yayında'}</div>${d.persistent===false?'<div class="hint"><b>Firestore bağlı değil: fiyatlar kaydedilemez.</b></div>':''}${(d.notes||[]).map(n=>`<div class="hint">• ${esc(n)}</div>`).join('')}</div>
 ${cards}
 <div class="card"><div class="hint">Yıllık ödemede kaç aylık ücret alınsın? (12 = indirim yok, 10 = 2 ay bedava)</div><input class="field" id="pr-yearly" type="number" min="1" max="12" value="${esc(cur.yearlyMonths)}">
 <div class="btns"><button class="btn p" data-act="adm-pricesave">Kaydet ve yayına al</button>${d.custom?'<button class="btn s d" data-act="adm-pricereset">Varsayılana dön</button>':''}</div></div>
 <div class="card"><b>Değişiklik geçmişi</b>${hist}</div>`;
}
function prCollect(d){
 const cur=d.current,body={plans:{},yearlyMonths:$('#pr-yearly').value.trim()},diff=[];
 P.PAID.forEach(id=>{const g=f=>$('#pr-'+id+'-'+f).value.trim(),c=cur.plans[id],nm=(d.plans[id]||{}).name||id;
  const nT=g('TRY'),nU=g('USD'),nA=g('assets'),nE=g('team'),nH=g('history');
  body.plans[id]={TRY:nT,USD:nU,assets:nA===''?'sınırsız':+nA,team:nE===''?'sınırsız':+nE,history:nH===''?'':+nH};
  if(numIn(nT)!==c.TRY)diff.push(`${nm} TL fiyatı: ${c.TRY} → ${nT}`);
  if(numIn(nU)!==c.USD)diff.push(`${nm} USD fiyatı: ${c.USD} → ${nU}`);
  if((nA===''?null:+nA)!==c.assets)diff.push(`${nm} varlık limiti: ${lv(c.assets)} → ${nA===''?'sınırsız':nA}`);
  if((nE===''?null:+nE)!==c.team)diff.push(`${nm} ekip limiti: ${lv(c.team)} → ${nE===''?'sınırsız':nE}`);
  if(+nH!==c.history)diff.push(`${nm} geçmiş limiti: ${c.history} → ${nH||'(boş)'}`)});
 if(+body.yearlyMonths!==cur.yearlyMonths)diff.push(`Yıllık ödemede ücretlenen ay: ${cur.yearlyMonths} → ${body.yearlyMonths||'(boş)'}`);
 return{body,diff};
}
function payOrders(d){
 const fo=[['','Tümü'],['paid','Ödendi'],['pending','Bekliyor'],['failed','Başarısız'],['activated-free','Ödemesiz etkinleştirildi']].map(([v,l])=>`<option value="${v}"${(BK.adm.os||'')===v?' selected':''}>${esc(l)}</option>`).join('');
 return`<div class="card"><select class="field" id="adm-os">${fo}</select><div class="btns"><button class="btn p" data-act="adm-ordsearch">Filtrele</button><button class="btn s" data-act="adm-csv" data-id="orders">CSV indir</button></div></div><div class="card">${(d.orders||[]).map(o=>{const h=ordRow(o,true);return o.status==='paid'?h.replace(/<\/div>$/,`<div class="acts"><button class="btn s d" data-act="adm-refund" data-id="${esc(o.id)}">İade</button><button class="btn s" data-act="adm-subcancel" data-id="${esc(o.uid)}">Aboneliği iptal et</button></div></div>`):h}).join('')||'<div class="empty">Sipariş yok</div>'}</div>`;
}
function payRevenue(d){
 const p=d.paid||{},m=d.mrr||{},c=d.coupons||{},days=d.daily||[];
 const mx=Math.max(1,...days.map(x=>(x.TRY||0)+(x.USD||0)));
 const bars=days.map(x=>`<div class="item"><div class="g"><b>${esc(x.day)}</b><span>${esc(fmtTot({TRY:x.TRY,USD:x.USD}).replace('—',''))}</span></div><div style="flex:1 1 120px;height:8px;border-radius:6px;background:var(--bl);opacity:.75;max-width:${Math.max(4,Math.round(((x.TRY||0)+(x.USD||0))/mx*100))}%"></div></div>`).join('')||'<div class="empty">Son 30 günde ödeme yok</div>';
 const byp=Object.entries(d.byPlan||{}).map(([k,v])=>kv(esc((P.PLANS[k]||{}).name||k)+' ('+v.count+' ödeme)',esc(fmtTot(v.totals)))).join('')||'<div class="hint">Veri yok</div>';
 const exp=(d.expiringSoon||[]).map(x=>`<div class="item"><div class="g"><b>${esc(x.email||x.uid)}</b><span>${esc(x.planName)} • ${esc(x.provider||'-')}${x.free?' (ödemesiz)':''} • bitiş: ${esc(fdt(x.periodEnd))}</span></div><div class="acts"><button class="btn s" data-act="adm-user" data-id="${esc(x.uid)}">Detay</button></div></div>`).join('')||'<div class="empty">7 gün içinde bitecek paket yok</div>';
 return`<div class="card"><b>Tahsilat (ödenmiş siparişler)</b>${kv('Son 7 gün',esc(fmtTot(p.last7d&&p.last7d.totals))+' ('+((p.last7d&&p.last7d.count)||0)+')')}${kv('Son 30 gün',esc(fmtTot(p.last30d&&p.last30d.totals))+' ('+((p.last30d&&p.last30d.count)||0)+')')}${kv('Toplam (incelenen siparişler)',esc(fmtTot(p.totals))+' ('+(p.count||0)+')')}<div class="hint">${esc(d.note||'')}${d.truncated?' • Yalnızca en yeni '+d.ordersConsidered+' sipariş incelendi.':''}</div></div>
 <div class="card"><b>Tahmini aylık yinelenen gelir (MRR)</b>${kv('MRR',esc(fmtTot(m.estimate)))}${kv('Ödeme yapan aktif abonelik',m.activePayingSubscriptions||0)}<div class="hint">${esc(m.note||'')}</div></div>
 <div class="card"><b>Paket bazında</b>${byp}</div>
 <div class="card"><b>Sağlık göstergeleri</b>${kv('Kuponlu ödeme',c.orders||0)}${kv('Toplam indirim',esc(fmtTot(c.discountTotals)))}${kv('Başarısız ödeme',d.failed||0)}${kv('2 saatten uzun bekleyen sipariş',d.stuckPending||0)}${kv('Ödemesiz etkinleştirme',d.freeActivations||0)}</div>
 <div class="card"><b>Yakında bitecek paketler (7 gün)</b>${exp}</div>
 <div class="card"><b>Son 30 gün (günlük)</b>${bars}</div>`;
}
function payCoupons(d){
 const plans=d.plans||P.PAID;
 const rows=(d.coupons||[]).map(c=>{const val=c.type==='percent'?'%'+c.value:money(c.value,c.currency),pl=(c.plans||[]).length?c.plans.map(k=>(P.PLANS[k]||{}).name||k).join(', '):'tüm paketler',cy=(c.cycles||[]).length?(c.cycles[0]==='yearly'?'yıllık':'aylık'):'her dönem';
  const va=[c.validFrom?'başlangıç '+new Date(c.validFrom).toLocaleDateString('tr-TR'):'',c.validUntil?'bitiş '+new Date(c.validUntil).toLocaleDateString('tr-TR'):''].filter(Boolean).join(' • ')||'süresiz';
  const expd=c.validUntil&&c.validUntil<Date.now(),full=c.maxUses!=null&&(c.usedCount||0)>=c.maxUses;
  return`<div class="item"><div class="g"><b>${esc(c.code)}</b><span>${esc(val)} indirim • ${esc(pl)} • ${cy} • kullanım ${c.usedCount||0}/${c.maxUses==null?'∞':c.maxUses} • kişi başı ${c.perUser||1} • ${esc(va)}${c.note?' • '+esc(c.note):''}</span></div><span class="badge ${!c.active?'mu':expd||full?'wn':'ok'}">${!c.active?'Pasif':expd?'Süresi doldu':full?'Hakkı doldu':'Aktif'}</span><div class="acts"><button class="btn s" data-act="adm-cpntoggle" data-id="${esc(c.code)}" data-v="${c.active?'0':'1'}">${c.active?'Pasifleştir':'Etkinleştir'}</button><button class="btn s d" data-act="adm-cpndel" data-id="${esc(c.code)}">Sil</button></div></div>`}).join('')||'<div class="empty">Kupon yok</div>';
 return`<div class="card"><b>Yeni kupon</b><div class="hint">Kod boş bırakılırsa otomatik üretilir. Kupon, ödeme anında sunucuda doğrulanır; kullanıcı kendi ekranında tutarı değiştiremez.</div>
 <input class="field" id="cp-code" placeholder="Kod (boş = otomatik, ör. YAZ25)" maxlength="32" autocapitalize="characters">
 <div class="row2"><select class="field" id="cp-type"><option value="percent">Yüzde indirim (%)</option><option value="fixed">Sabit tutar indirimi</option></select><input class="field" id="cp-val" inputmode="decimal" placeholder="Değer (ör. 20)"></div>
 <div class="row2"><select class="field" id="cp-cur"><option value="TRY">Sabit tutar için: TL</option><option value="USD">Sabit tutar için: USD</option></select><select class="field" id="cp-cycle"><option value="all">Her dönem</option><option value="monthly">Yalnızca aylık</option><option value="yearly">Yalnızca yıllık</option></select></div>
 <div class="hint">Geçerli paketler (hiçbiri seçilmezse tümü)</div><div class="btns">${plans.map(k=>`<label class="consent" style="margin:4px 10px 4px 0"><input type="checkbox" class="cp-plan" value="${esc(k)}"><span>${esc((P.PLANS[k]||{}).name||k)}</span></label>`).join('')}</div>
 <div class="row2"><input class="field" id="cp-max" type="number" min="1" placeholder="Toplam kullanım (boş = sınırsız)"><input class="field" id="cp-per" type="number" min="1" max="100" value="1" aria-label="Kişi başı hak"></div>
 <div class="row2"><div><div class="hint">Başlangıç (isteğe bağlı)</div><input class="field" id="cp-from" type="date"></div><div><div class="hint">Bitiş (isteğe bağlı)</div><input class="field" id="cp-until" type="date"></div></div>
 <input class="field" id="cp-note" placeholder="Not (yalnızca yöneticiler görür)" maxlength="200">
 <button class="btn p w" data-act="adm-cpncreate">Kuponu oluştur</button>
 <div class="hint">Stripe (USD) aboneliklerinde indirim her yenilemede geçerli kalır; iyzico (TL) ödemeleri tek seferlik olduğundan yalnızca o dönemi etkiler. Kupon hakkı ödeme başlatılınca ayrılır; ödeme başarısız olursa iade edilir.</div></div>
 <div class="card"><b>Kuponlar</b>${rows}</div>`;
}

/* --- Duyuru ve bakım modu --- */
function siteBody(d){
 const fl=(d.site.flags)||{registrationOpen:true,disabledScanTypes:[]};
 const a=d.site.announcement,m=d.site.maintenance,until=a.until?new Date(a.until-new Date().getTimezoneOffset()*6e4).toISOString().slice(0,10):'';
 return`<div class="card"><b>Site duyurusu</b><div class="hint">Tüm kullanıcıların üst kısmında bir şerit olarak görünür (2 dakikada bir yenilenir).</div>
 <label class="consent"><input type="checkbox" id="st-aen"${a.enabled?' checked':''}><span>Duyuru yayında</span></label>
 <input class="field" id="st-atx" maxlength="280" placeholder="Duyuru metni (en çok 280 karakter)" value="${esc(a.text)}">
 <div class="row2"><select class="field" id="st-alv"><option value="info"${a.level==='info'?' selected':''}>Bilgi</option><option value="warn"${a.level==='warn'?' selected':''}>Uyarı</option><option value="bad"${a.level==='bad'?' selected':''}>Önemli</option></select><input class="field" id="st-aun" type="date" value="${esc(until)}" aria-label="Bitiş tarihi"></div>
 <button class="btn p w" data-act="adm-siteann">Duyuruyu kaydet</button><button class="btn s d w" data-act="adm-anndel">Duyuruyu sil</button></div>
 <div class="card"><b>Bakım modu</b><div class="hint">Açıkken yöneticiler dışında kimse yeni tarama veya toplu iş başlatamaz; giriş, mevcut veriler ve ödeme çalışmaya devam eder. Üstte kırmızı bir bakım şeridi gösterilir.</div>
 <label class="consent"><input type="checkbox" id="st-men"${m.enabled?' checked':''}><span>Bakım modu açık</span></label>
 <input class="field" id="st-mms" maxlength="280" placeholder="Kullanıcıya gösterilecek mesaj" value="${esc(m.message)}">
 <button class="btn p w" data-act="adm-sitemnt">Bakım ayarını kaydet</button><button class="btn s d w" data-act="adm-mntdel">Bakım ayarını sıfırla</button>
 <div class="hint">Son güncelleme: ${esc(fdt(d.site.updatedAt))} • ${esc(d.site.updatedBy||'-')}${d.persistent===false?' • Firestore bağlı değil, kaydedilemez':''}</div></div>
 <div class="card"><b>Özellik bayrakları</b><div class="hint">Tikli = açık. Tiki kaldırdığınız tarama türü kullanıcılar için kapanır; kullanıcı denediğinde "Bu özellik yönetici tarafından kapatıldı" uyarısını görür. Yöneticiler etkilenmez.</div><label class="consent"><input type="checkbox" id="st-reg"${fl.registrationOpen?' checked':''}><span>Yeni kayıtlara açık</span></label>
  <div class="hint" style="margin-top:8px">Tarama türleri</div>${Object.entries(CATS).filter(([,v])=>v.api).map(([k,v])=>`<label class="consent"><input type="checkbox" class="st-ft" value="${esc(v.api)}"${(fl.disabledScanTypes||[]).includes(v.api)?'':' checked'}><span>${esc(v.label)}</span></label>`).join('')}<button class="btn p w" data-act="adm-siteflags">Bayrakları kaydet</button><button class="btn s d w" data-act="adm-flagdel">Bayrakları sıfırla (hepsi açık)</button></div></div>`;
}

/* --- Yönetici eylemleri (Ödemeler, kupon, site, kullanıcı müdahaleleri) --- */
async function admAct2(act,id,b){
 if(act==='adm-paysub'){BK.adm.paySub=id;BK.adm.err=null;admPaint();await admLoad('orders');return admPaint()}
 if(act==='adm-csv')return admCsv(id);
 if(act==='adm-pricesave'){
  const d=BK.adm.pay&&BK.adm.pay.prices;if(!d)return;const{body,diff}=prCollect(d);
  if(!diff.length)return toast('Değişiklik yok','warn');
  if(!confirm('Şu değişiklikler HEMEN yayına alınacak:\n\n'+diff.join('\n')+'\n\nMevcut Stripe abonelikleri etkilenmez. Onaylıyor musunuz?'))return;
  try{let j;try{j=await bkApi('POST','/api/admin/pricing',body)}catch(e){if(e.code==='LARGE_CHANGE'&&confirm(e.message+'\n\nYine de kaydedilsin mi?'))j=await bkApi('POST','/api/admin/pricing',{...body,force:true});else throw e}
   applyPricing(j.public);await admLoad('orders');admPaint();toast('Fiyatlar kaydedildi ve yayında')}catch(e){toast(e.message,'err')}return;
 }
 if(act==='adm-pricereset'){if(!confirm('Tüm fiyat ve limitler kod içindeki varsayılan değerlere dönsün mü?'))return;try{const j=await bkApi('POST','/api/admin/pricing/reset',{});applyPricing(j.public);await admLoad('orders');admPaint();toast('Varsayılan fiyatlara dönüldü')}catch(e){toast(e.message,'err')}return}
 if(act==='adm-cpncreate'){
  const g=x=>$('#'+x).value.trim(),type=g('cp-type'),cyc=g('cp-cycle');
  const day=(v,end)=>v?Date.parse(v+(end?'T23:59:59':'T00:00:00')):null;
  const body={code:g('cp-code'),type,value:g('cp-val'),currency:type==='fixed'?g('cp-cur'):undefined,plans:[...document.querySelectorAll('.cp-plan:checked')].map(x=>x.value),cycles:cyc==='all'?[]:[cyc],maxUses:g('cp-max')===''?null:+g('cp-max'),perUser:+g('cp-per')||1,validFrom:day(g('cp-from'),false),validUntil:day(g('cp-until'),true),note:g('cp-note')};
  try{const j=await bkApi('POST','/api/admin/coupons',body);toast('Kupon oluşturuldu: '+j.coupon.code);await admLoad('orders');admPaint()}catch(e){toast(e.message,'err')}return;
 }
 if(act==='adm-cpntoggle'){try{await bkApi('POST','/api/admin/coupons/'+encodeURIComponent(id)+'/active',{active:b.dataset.v==='1'});await admLoad('orders');admPaint()}catch(e){toast(e.message,'err')}return}
 if(act==='adm-cpndel'){if(!confirm(id+' kuponu silinsin mi? (Kullanım sayacı da silinir)'))return;try{await bkApi('DELETE','/api/admin/coupons/'+encodeURIComponent(id));toast('Kupon silindi');await admLoad('orders');admPaint()}catch(e){toast(e.message,'err')}return}
 if(act==='adm-siteann'){try{const un=$('#st-aun').value;await bkApi('POST','/api/admin/site',{announcement:{enabled:$('#st-aen').checked,text:$('#st-atx').value.trim(),level:$('#st-alv').value,until:un?Date.parse(un+'T23:59:59'):null}});toast('Duyuru kaydedildi');await admLoad('site');admPaint();loadSite(true)}catch(e){toast(e.message,'err')}return}
 if(act==='adm-sitemnt'){const on=$('#st-men').checked;if(on&&!confirm('Bakım modu açılsın mı? Yöneticiler dışında kimse yeni tarama başlatamaz.'))return;try{await bkApi('POST','/api/admin/site',{maintenance:{enabled:on,message:$('#st-mms').value.trim()}});toast(on?'Bakım modu AÇIK':'Bakım modu kapalı');await admLoad('site');admPaint();loadSite(true)}catch(e){toast(e.message,'err')}return}
 if(act==='adm-revsess'){if(!confirm('Kullanıcının tüm oturumları kapatılsın mı? (Yeniden giriş yapması gerekir)'))return;try{await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/revoke-sessions',{});toast('Oturumlar kapatıldı')}catch(e){toast(e.message,'err')}return}
 if(act==='adm-pwreset'){if(!confirm('Bu kullanıcı için şifre sıfırlama bağlantısı oluşturulsun mu? (İşlem kayda geçer)'))return;try{const j=await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/password-reset',{});try{await navigator.clipboard.writeText(j.link);toast('Bağlantı panoya kopyalandı')}catch{window.prompt('Şifre sıfırlama bağlantısı (kopyalayın):',j.link)}}catch(e){toast(e.message,'err')}return}
 if(act==='adm-verify'){if(!confirm('Kullanıcının e-postası doğrulanmış olarak işaretlensin mi?'))return;try{await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/verify-email',{});toast('E-posta doğrulandı olarak işaretlendi');return admReloadDetail(id)}catch(e){toast(e.message,'err')}return}
 if(act==='adm-notesave'){try{await bkApi('POST','/api/admin/users/'+encodeURIComponent(id)+'/note',{text:$('#adm-note').value});toast('Not kaydedildi');return admReloadDetail(id)}catch(e){toast(e.message,'err')}return}
}
