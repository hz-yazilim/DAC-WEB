/* Digital Asset Center - toplu tarama sayfası (app.js ile aynı genel kapsamı paylaşır; index.html'de app.js'den SONRA yüklenir) */
/* ---------- toplu tarama + admin (V13.1) ---------- */
const BK={isAdmin:false,timer:null,jobs:[],job:null,rows:[],total:0,page:1,pageSize:50,q:'',st:'ALL',sort:'queuedAt',order:'asc',sel:new Set(),tab:'overview',adm:{},domJob:null,busy:false};
const ST={PENDING:'Bekliyor',RETRYING:'Yeniden denenecek',RUNNING:'Çalışıyor',COMPLETED:'Tamamlandı',PARTIAL:'Kısmen tamamlandı',FAILED:'Başarısız',CANCELED:'İptal edildi'};
const stTone=x=>x==='COMPLETED'?'ok':x==='FAILED'?'bd':x==='PARTIAL'||x==='RETRYING'?'wn':'mu';
const BULKCATS=[['domain','Domain'],['ssl','SSL Sertifikası'],['hosting','Hosting'],['web','Web Sitesi'],['seo','SEO'],['performance','Performans'],['uptime','Uptime']];
async function bkApi(method,path,body,retried){
 const api=apiUrl();if(!api)throw new Error('Sunucu adresi yok');
 const r=await fetch(api+path,{method,headers:{'Content-Type':'application/json',...await authH(),...(path.startsWith('/api/admin/')?a2faH():{})},body:body?JSON.stringify(body):undefined});
 let j=null;try{j=await r.json()}catch{}
 if(!r.ok||!j||j.success===false){const e=new Error((j&&j.error)||'İstek başarısız ('+r.status+')');e.status=r.status;e.code=j&&j.code;if(e.code==='2FA_REQUIRED'&&!retried&&await a2faPrompt())return bkApi(method,path,body,true);throw e}
 return j;
}
async function bkInit(n){
 n=n|0;
 try{const j=await bkApi('GET','/api/me/admin');if(j.admin&&!BK.isAdmin){BK.isAdmin=true;render()}if(j.admin&&typeof bdgPull==='function')bdgPull()}
 catch{if(n<3&&S&&U)setTimeout(()=>bkInit(n+1),4000*(n+1))} // geçici hata/429: yönetici rozeti sessizce kaybolmasın, yeniden dene
}
const bkDomain=v=>{v=String(v).trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//,'').split(/[\/?#]/)[0].replace(/:\d{1,5}$/,'').replace(/\.$/,'').replace(/^www\./,'');return /^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/.test(v)&&!/^[\d.]+$/.test(v)?v:null};
const daysLeft=a=>{const e=a.result?.specificAnalysis?.registration?.expiresAt||a.result?.specificAnalysis?.cert?.validTo;if(!e)return null;const t=new Date(e).getTime();return isNaN(t)?null:Math.ceil((t-Date.now())/864e5)};
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
  if(rr==='admin'){const ae=document.activeElement;if(!['overview','jobs','health','errors'].includes(BK.tab)||(ae&&/^(INPUT|SELECT|TEXTAREA)$/.test(ae.tagName)&&ae.closest('#adm-body')))return}
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
