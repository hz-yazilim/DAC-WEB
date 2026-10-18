/* Digital Asset Center - tüm veriler tarayıcıda (localStorage) tutulur, tarama için scanner API kullanılır */
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>Math.random().toString(36).slice(2,10)+Date.now().toString(36);
const CATS={
 web:{label:'Web Sitesi',icon:'globe',c:'#3b82f6',api:'WEBSITE',desc:'HTTP/HTTPS katmanı, güvenlik başlıkları ve SEO',ph:'ornek.com'},
 domain:{label:'Domain',icon:'link-2',c:'#8b5cf6',api:'DOMAIN',desc:'DNS bütünlüğü, email güvenliği ve sahiplik',ph:'ornek.com'},
 ssl:{label:'SSL Sertifikası',icon:'lock',c:'#10b981',api:'SSL_CERTIFICATE',desc:'Zincir doğrulama, şifreleme gücü ve HSTS',ph:'ornek.com'},
 hosting:{label:'Hosting',icon:'hard-drive',c:'#f59e0b',api:'HOSTING',desc:'Altyapı, coğrafi konum ve DDoS koruması',ph:'ornek.com'},
 saas:{label:'SaaS Abonelik',icon:'layers',c:'#ec4899',api:'SAAS_SUBSCRIPTION',desc:'Yenileme tarihi, maliyet ve kullanım',ph:'Sağlayıcı (ör: Notion)'},
 server:{label:'Sunucu',icon:'server',c:'#06b6d4',api:'SERVER',desc:'Port, erişilebilirlik ve altyapı kontrolü',ph:'sunucu.com veya IP'},
 api:{label:'API',icon:'code-2',c:'#6366f1',api:'WEBSITE',desc:'Endpoint erişimi, yanıt süresi ve başlıklar',ph:'api.ornek.com/v1'},
 email:{label:'Email',icon:'mail',c:'#14b8a6',api:'DOMAIN',desc:'SPF, DKIM, DMARC ve MX kayıtları',ph:'ornek.com'}
};
const LISTS={
 team:{title:'Ekip Yönetimi',icon:'users',f:[['name','Ad Soyad'],['email','Email'],['role','Rol']]},
 projects:{title:'Müşteri Projeleri',icon:'briefcase',f:[['name','Proje adı'],['client','Müşteri'],['note','Not']]}
};
let KEY='dac_v1',S=null,U=null;
const blank=()=>({assets:[],scans:[],team:[],projects:[],settings:{org:'HZ Yazılım',plan:'free',apiUrl:''}});
const save=()=>{if(S)localStorage.setItem(KEY,JSON.stringify(S))};
const apiUrl=()=>(S.settings.apiUrl||(window.DAC_CONFIG||{}).API_URL||'').trim();
const LIMIT=5;

/* ---------- yardımcılar ---------- */
const normKey=(cat,v)=>{v=String(v).trim().toLowerCase();if(cat==='saas')return v;v=v.replace(/^https?:\/\//,'').replace(/^www\./,'').replace(/\/+$/,'');return ['web','api'].includes(cat)?v:v.split('/')[0].split(':')[0]};
const proto=u=>/^https?:\/\//i.test(u)?u:'https://'+u;
const sev=f=>/_critical$/.test(f)?'bd':/_warning$/.test(f)?'wn':'mu';
const sevL={bd:'Kritik',wn:'Uyarı',mu:'Bilgi'};
const finT=f=>String(f).replace(/^finding_/,'').replace(/_(critical|warning|info)$/,'').replace(/_/g,' ');
const isBad=s=>['CRITICAL','EXPIRED','DOWN','ERROR'].includes(s);
const isOk=s=>['ACTIVE','HEALTHY'].includes(s);
const tone=n=>n>=80?'ok':n>=50?'wn':'bd';
const col=n=>n>=80?'var(--ok)':n>=50?'var(--wn)':'var(--bad)';
const fmt=t=>t?new Date(t).toLocaleString('tr-TR',{dateStyle:'short',timeStyle:'short'}):'-';
const sc=a=>a.result?.healthScore;
const alerts=()=>S.assets.filter(a=>a.result&&(isBad(a.result.status)||(a.result.findings||[]).some(f=>sev(f)==='bd')));
const find=id=>S.assets.find(a=>a.id===id);
const ic=(n,s='')=>`<i data-lucide="${n}" ${s}></i>`;
function toast(m,t=''){const d=document.createElement('div');d.className='t '+t;d.textContent=m;$('#toast').append(d);setTimeout(()=>d.remove(),3800)}
const busy=b=>document.body.classList.toggle('busy',b);

/* ---------- tarama ---------- */
async function mock(a){
 await new Promise(r=>setTimeout(r,1200));
 let h=0;for(const ch of a.key)h=(h*31+ch.charCodeAt(0))>>>0;
 const score=a.key==='google.com'?92:55+h%41;
 const f=[];if(score<85)f.push(`finding_${a.cat}_demo_warning`);if(score<60)f.push(`finding_${a.cat}_demo_critical`);
 return{assetType:CATS[a.cat].api,healthScore:score,status:score>=80?'HEALTHY':score>=50?'WARNING':'CRITICAL',findings:f,latencyMs:1200,
  commonAnalysis:{analyzerVersion:'mock-v1',executionTimeMs:1200,scannedAt:new Date().toISOString(),score,target:a.target},
  specificAnalysis:{target:a.target,note:'DEMO veri — gerçek analiz için config.js içine API_URL yazın',scores:{overall:score}}};
}
async function runScan(a){
 const t0=Date.now(),api=apiUrl();let res;
 if(api){
  const r=await fetch(api.replace(/\/$/,'')+'/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assetId:a.id,type:CATS[a.cat].api,targetUrl:['web','api'].includes(a.cat)?proto(a.target):a.target,name:a.name,extra:a.extra||{}})});
  let j;try{j=await r.json()}catch{throw new Error('Sunucu geçersiz yanıt verdi ('+r.status+'). Render uyanıyor olabilir, 30 sn sonra tekrar deneyin.')}
  if(!j.success)throw new Error(j.error||'Tarama başarısız');res=j.result;
 }else res=await mock(a);
 a.result=res;a.lastScan=Date.now();
 S.scans.unshift({id:uid(),assetId:a.id,name:a.name,cat:a.cat,score:res.healthScore,status:res.status,at:Date.now(),ms:Date.now()-t0,mock:!api});
 S.scans=S.scans.slice(0,300);save();
}
async function rescan(id,open){
 const a=find(id);if(!a)return;busy(true);
 try{await runScan(a)}catch(e){toast('Tarama hatası: '+e.message,'err')}
 busy(false);render();if(open&&a.result)showDetail(id);
}
async function addAndScan(cat,raw,extra={},name=''){
 const target=String(cat==='saas'?(extra.provider||raw):raw).trim();
 if(!target)return toast('Hedef boş olamaz','err');
 const key=normKey(cat,target),ex=S.assets.find(a=>a.cat===cat&&a.key===key);
 if(ex){toast('Bu varlık zaten ekli, yeniden taranıyor','warn');return rescan(ex.id,true)}
 if(S.settings.plan==='free'&&S.assets.length>=LIMIT)return toast(`Free pakette en fazla ${LIMIT} varlık eklenebilir. Paket sayfasından yükseltin.`,'err');
 const a={id:uid(),cat,target,key,name:name||target,extra,createdAt:Date.now()};
 S.assets.push(a);save();render();await rescan(a.id,true);
}

/* ---------- görünümler ---------- */
function assetRow(a){
 const s=sc(a),st=a.result?.status;
 return`<div class="item"><div class="ico" style="color:${CATS[a.cat].c}">${ic(CATS[a.cat].icon)}</div>
 <div class="g"><b>${esc(a.name)}</b><span>${CATS[a.cat].label} • ${a.lastScan?fmt(a.lastScan):'taranmadı'}</span></div>
 ${s!=null?`<span class="badge ${tone(s)}">${s}/100</span>`:'<span class="badge mu">-</span>'}
 <div class="acts"><button class="btn s" data-act="detail" data-id="${a.id}">Detay</button><button class="btn s" data-act="rescan" data-id="${a.id}">${ic('refresh-cw')}</button><button class="btn s d" data-act="del" data-id="${a.id}">${ic('trash-2')}</button></div></div>`;
}
const stat=(i,n,l,h,c)=>`<div class="card stat"><div class="top"><div class="ico" style="color:${c}">${ic(i)}</div><span class="tag">LIVE</span></div><div class="num">${n}</div><div class="lbl">${l}</div><div class="hint">${h}</div></div>`;
function dash(){
 const A=S.assets,scored=A.filter(a=>sc(a)!=null),avg=scored.length?Math.round(scored.reduce((t,a)=>t+sc(a),0)/scored.length):0;
 const crit=A.reduce((t,a)=>t+(a.result?.findings||[]).filter(f=>sev(f)==='bd').length,0);
 const m30=S.scans.filter(s=>Date.now()-s.at<2592e6).length,ok=A.filter(a=>isOk(a.result?.status)).length;
 const al=alerts();
 return`<h2>Genel Bakış</h2><p class="sub">Tüm dijital varlıklar tek merkezde</p>
 <div class="grid">${stat('database',A.length,'Toplam Varlık',`${A.length}/${S.settings.plan==='free'?LIMIT:'∞'} kullanımda`,'#8b9bb8')}
 ${stat('activity',m30,'Tarama Sayısı','Son 30 gün','#8b9bb8')}
 ${stat('shield-alert',crit,'Sorun Tespit',crit?`${crit} kritik`:'Kritik değil','#f59e0b')}
 ${stat('bar-chart-3',avg,'Ortalama Skor',scored.length?'Tüm varlıklar':'Henüz veri yok','#8b9bb8')}
 ${stat('circle-check',ok,'Çalışan Varlıklar','Aktif','#10b981')}</div>
 <div class="card" style="margin-top:14px"><div class="item" style="border:0"><div class="ico" style="color:var(--bl)">${ic('zap')}</div><div class="g"><b style="font-size:18px">Hızlı Tarama</b><span style="white-space:normal">Domain veya URL girin, kategori seçin ve tarayın${apiUrl()?'':' • demo mod'}</span></div></div>
 <form data-form="quick"><input class="field" name="t" placeholder="örn: google.com veya https://ornek.com" autocomplete="off"><select class="field" name="c">${Object.entries(CATS).map(([k,v])=>`<option value="${k}">${v.label}</option>`).join('')}</select>
 <button class="btn p w" type="submit">${ic('scan-search')} Tara</button></form>
 <div class="chips" style="margin-top:14px">ÖNERİ: ${['google.com','github.com','vercel.com'].map(d=>`<button class="chip" data-act="sug" data-v="${d}">${d}</button>`).join('')}</div>
 <div class="hint" style="margin-top:10px">• aynı varlık tekrar eklenmez • duplicate engelleme aktif</div></div>
 <div class="card"><div class="mh"><b>${ic('triangle-alert','style="color:var(--wn)"')} Aktif Uyarılar</b><span class="badge mu">${al.length}</span></div>
 ${al.length?al.map(assetRow).join(''):`<div class="empty">${ic('circle-check')}<br>Aktif uyarı yok</div>`}</div>
 <div class="card"><div class="mh"><b>${ic('clock')} Son Taramalar</b></div>${S.scans.length?S.scans.slice(0,5).map(scanRow).join(''):`<div class="empty"><b style="color:var(--tx)">Henüz tarama yok</b><br><span class="hint">Tarama geçmişi burada kronolojik listelenecek</span></div>`}</div>
 <div class="mh" style="margin-top:24px"><b style="font-size:18px">${ic('layers','style="color:var(--bl)"')} Tüm Tarama Araçları</b><span class="hint">8 kategori</span></div>
 <div class="tools">${Object.entries(CATS).map(([k,v])=>`<a class="tool" href="#cat/${k}"><div class="ico" style="color:${v.c}">${ic(v.icon)}</div><h3 style="margin:12px 0 0;font-size:17px">${v.label}</h3><p>${v.desc}</p><div class="bar" style="--c:${v.c}"></div></a>`).join('')}</div>`;
}
const scanRow=s=>`<div class="item"><div class="ico" style="color:${CATS[s.cat]?.c}">${ic(CATS[s.cat]?.icon||'scan')}</div><div class="g"><b>${esc(s.name)}</b><span>${fmt(s.at)} • ${s.ms}ms${s.mock?' • demo':''}</span></div><span class="badge ${tone(s.score)}">${s.score}/100</span></div>`;
function catPage(k){
 const v=CATS[k],list=S.assets.filter(a=>a.cat===k);
 const form=k==='saas'?`<form data-form="add" data-cat="${k}"><input class="field" name="provider" placeholder="Sağlayıcı (ör: Notion)" required>
 <div class="row2"><input class="field" name="plan" placeholder="Plan (ör: Pro)"><input class="field" name="cost" type="number" min="0" step="any" placeholder="Maliyet"></div>
 <div class="row2"><input class="field" name="renewalDate" type="date" title="Yenileme tarihi"><input class="field" name="usagePercent" type="number" min="0" max="100" placeholder="Kullanım %"></div>
 <button class="btn p w" type="submit">${ic('plus')} Ekle ve Tara</button></form>`
 :`<form data-form="add" data-cat="${k}"><input class="field" name="t" placeholder="${v.ph}" required autocomplete="off"><input class="field" name="name" placeholder="Görünen ad (opsiyonel)"><button class="btn p w" type="submit">${ic('plus')} Ekle ve Tara</button></form>`;
 return`<h2>${v.label}</h2><p class="sub">${v.desc}</p><div class="card"><b>Yeni ${v.label} ekle</b><div style="height:12px"></div>${form}</div>
 <div class="card"><div class="mh"><b>Varlıklar</b><span class="badge mu">${list.length}</span></div>${list.length?list.map(assetRow).join(''):`<div class="empty">Bu kategoride henüz varlık yok</div>`}</div>`;
}
function assets(){const q=($('#q')?.value||'').toLowerCase();const l=S.assets.filter(a=>!q||(a.name+a.target).toLowerCase().includes(q));
 return`<h2>Varlıklarım</h2><p class="sub">${S.assets.length} varlık</p><div class="card">${l.length?l.map(assetRow).join(''):`<div class="empty">Varlık yok. Sol menüden bir kategori seçip ekleyin.</div>`}</div>`}
function history(){return`<div class="mh"><div><h2>Tarama Geçmişi</h2><p class="sub">${S.scans.length} kayıt</p></div>${S.scans.length?`<button class="btn s d" data-act="clearhist">Temizle</button>`:''}</div><div class="card">${S.scans.length?S.scans.map(scanRow).join(''):`<div class="empty">Henüz tarama yok</div>`}</div>`}
function reports(){
 const rows=Object.entries(CATS).map(([k,v])=>{const l=S.assets.filter(a=>a.cat===k),s=l.filter(a=>sc(a)!=null);return`<tr><td>${v.label}</td><td>${l.length} varlık</td><td>${s.length?Math.round(s.reduce((t,a)=>t+sc(a),0)/s.length):'-'}</td></tr>`}).join('');
 return`<h2>Raporlar</h2><p class="sub">Kategori bazlı özet</p><div class="card"><table><tr><td>Kategori</td><td>Adet</td><td>Ort. skor</td></tr>${rows}</table></div>
 <div class="acts"><button class="btn" data-act="csv">${ic('download')} CSV indir</button><button class="btn" data-act="json">${ic('download')} JSON indir</button><button class="btn" onclick="print()">${ic('printer')} Yazdır</button></div>`}
function listPage(k){const L=LISTS[k];
 return`<h2>${L.title}</h2><p class="sub">${S[k].length} kayıt</p><div class="card"><form data-form="list" data-k="${k}">${L.f.map(([n,p],i)=>`<input class="field" name="${n}" placeholder="${p}" ${i?'':'required'}>`).join('')}<button class="btn p w" type="submit">${ic('plus')} Ekle</button></form></div>
 <div class="card">${S[k].length?S[k].map(x=>`<div class="item"><div class="ico">${ic(L.icon)}</div><div class="g"><b>${esc(x[L.f[0][0]])}</b><span>${L.f.slice(1).map(([n])=>esc(x[n])).filter(Boolean).join(' • ')}</span></div><button class="btn s d" data-act="dellist" data-k="${k}" data-id="${x.id}">${ic('trash-2')}</button></div>`).join(''):`<div class="empty">Kayıt yok</div>`}</div>`}
function plan(){const p=S.settings.plan;
 return`<h2>Paket ve Faturalandırma</h2><p class="sub">Şu an: ${p==='free'?'Free':'Pro'} • ${S.assets.length}/${p==='free'?LIMIT:'∞'} varlık</p><div class="plans">
 <div class="card ${p==='free'?'on':''}"><h3>Free</h3><p class="lbl">${LIMIT} varlık, tüm tarayıcılar</p>${p==='free'?'<span class="badge ok">Aktif</span>':`<button class="btn" data-act="plan" data-p="free">Free'ye geç</button>`}</div>
 <div class="card ${p==='pro'?'on':''}"><h3>Pro</h3><p class="lbl">Sınırsız varlık</p>${p==='pro'?'<span class="badge ok">Aktif</span>':`<button class="btn p" data-act="plan" data-p="pro">Pro'ya geç</button>`}</div></div>
 <p class="hint">Ödeme sistemi bağlı değil; paket değişimi şimdilik yerel olarak yapılır.</p>`}
function settings(){const s=S.settings;
 return`<h2>Ayarlar</h2><p class="sub">${esc(U?.email||'Hesap ve bağlantı')}</p><div class="card"><form data-form="settings">
 <label class="hint">Organizasyon adı</label><input class="field" name="org" value="${esc(s.org)}" required>
 <label class="hint">Scanner API adresi (boşsa demo mod)</label><input class="field" name="apiUrl" value="${esc(s.apiUrl)}" placeholder="${esc((window.DAC_CONFIG||{}).API_URL||'https://scanner.onrender.com')}">
 <button class="btn p w" type="submit">Kaydet</button></form></div>
 <button class="btn d" data-act="wipe">${ic('trash-2')} Tüm verileri sil</button>`}

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
  const s=r.healthScore??0,sa=r.specificAnalysis||{},ca=r.commonAnalysis||{};
  h+=`<div class="card" style="display:flex;gap:16px;align-items:center"><div class="ring" style="--p:${s};--rc:${col(s)}"><span>${s}</span></div><div><span class="badge ${isBad(r.status)?'bd':isOk(r.status)?'ok':'wn'}">${esc(r.status)}</span><div class="hint">Son tarama: ${fmt(a.lastScan)}<br>${esc(ca.analyzerVersion||'')} • ${ca.executionTimeMs??r.latencyMs??'-'}ms</div></div></div>`;
  const sco=Object.entries(sa.scores||{}).filter(([,v])=>typeof v==='number');
  if(sco.length)h+=`<div class="card"><b>Skorlar</b>${sco.map(([k,v])=>`<div class="sc" style="--rc:${col(v)}"><span>${esc(k)}</span><i><u style="width:${Math.min(100,v)}%"></u></i><span>${v}</span></div>`).join('')}</div>`;
  const f=r.findings||[];
  h+=`<div class="card"><b>Bulgular (${f.length})</b>${f.length?f.map(x=>`<div class="find"><span class="badge ${sev(x)}">${sevL[sev(x)]}</span><span>${esc(finT(x))}</span></div>`).join(''):'<div class="hint">Sorun bulunmadı</div>'}</div>`;
  h+=`<div class="card"><b>Detaylı analiz</b><table>${flat(sa).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v===true?'evet':v===false?'hayır':v??'-')}</td></tr>`).join('')}</table><details><summary>Ham veri (JSON)</summary><pre>${esc(JSON.stringify(r,null,2))}</pre></details></div>
  <button class="btn p w" data-act="rescan" data-id="${id}">${ic('refresh-cw')} Yeniden Tara</button>`;
 }
 $('#box').innerHTML=h;$('#modal').classList.add('on');icons();
}

/* ---------- ana render ---------- */
const NAV=[['GENEL',[['dash','Genel Bakış','layout-grid']]],['TARAMA KATEGORİLERİ',Object.entries(CATS).map(([k,v])=>['cat/'+k,v.label,v.icon])],
 ['YÖNETİM',[['assets','Varlıklarım','database'],['history','Tarama Geçmişi','history'],['reports','Raporlar','bar-chart-3'],['team','Ekip Yönetimi','users'],['projects','Müşteri Projeleri','briefcase'],['plan','Paket ve Faturalandırma','credit-card'],['settings','Ayarlar','settings']]]];
const icons=()=>window.lucide&&lucide.createIcons();
function render(){
 if(!S)return;
 const r=location.hash.slice(1)||'dash',[p,k]=r.split('/');
 const counts={};Object.keys(CATS).forEach(c=>counts[c]=S.assets.filter(a=>a.cat===c).length);
 $('#side').innerHTML=`<div class="brand"><div class="logo">${ic('shield')}</div><div><b>Digital Asset Center</b><small>v10.3 • Enterprise</small></div></div>
 <nav class="nav">${NAV.map(([t,it])=>`<h6>${t}</h6>`+it.map(([h,l,i])=>`<a href="#${h}" class="${h===r?'on':''}">${ic(i)}${l}${h.startsWith('cat/')?`<b>${counts[h.slice(4)]}</b>`:''}</a>`).join('')).join('')}</nav>
 <div class="org"><div class="orgc"><div class="r"><div class="av">${esc(S.settings.org.slice(0,2).toUpperCase())}</div><div><b>${esc(S.settings.org)}</b><br><small>${S.settings.plan==='free'?'Free Paket':'Pro Paket'} • ${S.assets.length}/${S.settings.plan==='free'?LIMIT:'∞'} varlık</small></div></div>
 <div class="btns"><a class="btn s" href="#settings">${ic('settings')} Ayarlar</a><button class="btn s" data-act="logout">${ic('log-out')} Çıkış</button></div></div></div>`;
 $('#av').textContent=S.settings.org.slice(0,2).toUpperCase();
 $('#dot').style.display=alerts().length?'block':'none';
 $('#view').innerHTML=p==='cat'&&CATS[k]?catPage(k):p==='assets'?assets():p==='history'?history():p==='reports'?reports():LISTS[p]?listPage(p):p==='plan'?plan():p==='settings'?settings():dash();
 icons();
}

/* ---------- olaylar ---------- */
const close=()=>{$('#modal').classList.remove('on');$('#side').classList.remove('open');$('#shade').classList.remove('on')};
const dl=(n,t,m)=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:m}));a.download=n;a.click()};
document.addEventListener('click',e=>{
 const b=e.target.closest('[data-act]');
 if(!e.target.closest('.search'))$('#sres').classList.remove('on');
 if(!e.target.closest('.rel'))$('#bell').classList.remove('on');
 if(e.target.id==='modal')return close();
 if(e.target.id==='shade')return close();
 if(!b){if(e.target.closest('#side a'))close();return}
 const {act,id}=b.dataset,A=id&&find(id);
 if(act==='menu'){$('#side').classList.add('open');$('#shade').classList.add('on')}
 else if(act==='close')close();
 else if(act==='detail')showDetail(id);
 else if(act==='rescan')rescan(id,$('#modal').classList.contains('on'));
 else if(act==='del'){if(A&&confirm(`"${A.name}" silinsin mi?`)){S.assets=S.assets.filter(x=>x.id!==id);save();close();render();toast('Varlık silindi')}}
 else if(act==='sug'){const i=$('[name=t]');if(i)i.value=b.dataset.v}
 else if(act==='goto')location.hash=b.dataset.to;
 else if(act==='bell'){const al=alerts();$('#bell').innerHTML=al.length?al.map(a=>`<a data-act="detail" data-id="${a.id}">${ic('triangle-alert')} ${esc(a.name)} <span class="badge ${tone(sc(a))}">${sc(a)}</span></a>`).join(''):'<div class="it hint">Bildirim yok</div>';$('#bell').classList.toggle('on');icons()}
 else if(act==='clearhist'){S.scans=[];save();render()}
 else if(act==='plan'){S.settings.plan=b.dataset.p;save();render()}
 else if(act==='dellist'){const k=b.dataset.k;S[k]=S[k].filter(x=>x.id!==id);save();render()}
 else if(act==='logout'){window.dacLogout&&window.dacLogout()}
 else if(act==='wipe'){if(confirm('Tüm veriler silinecek. Emin misiniz?')){localStorage.removeItem(KEY);location.hash='';location.reload()}}
 else if(act==='csv'){const q=v=>`"${String(v??'').replace(/"/g,'""')}"`;dl('varliklar.csv',['Ad;Tür;Hedef;Skor;Durum;Son tarama',...S.assets.map(a=>[a.name,CATS[a.cat].label,a.target,sc(a)??'',a.result?.status??'',fmt(a.lastScan)].map(q).join(';'))].join('\n'),'text/csv')}
 else if(act==='json')dl('varliklar.json',JSON.stringify(S.assets,null,2),'application/json');
});
document.addEventListener('submit',e=>{
 const f=e.target.closest('[data-form]');if(!f)return;e.preventDefault();
 const d=Object.fromEntries(new FormData(f)),t=f.dataset.form;
 if(t==='quick')addAndScan(d.c,d.t,d.c==='saas'?{provider:d.t}:{});
 else if(t==='add'){const c=f.dataset.cat;if(c==='saas')addAndScan(c,d.provider,{provider:d.provider,plan:d.plan||'unknown',cost:+d.cost||0,renewalDate:d.renewalDate||null,usagePercent:d.usagePercent?+d.usagePercent:undefined});else addAndScan(c,d.t,{},d.name)}
 else if(t==='list'){const k=f.dataset.k,n=LISTS[k].f[0][0];if(S[k].some(x=>String(x[n]).toLowerCase()===d[n].trim().toLowerCase()))return toast('Bu kayıt zaten var','warn');S[k].push({id:uid(),...d});save();render()}
 else if(t==='settings'){S.settings.org=d.org.trim();S.settings.apiUrl=d.apiUrl.trim();save();render();toast('Kaydedildi')}
});
$('#q').addEventListener('input',e=>{
 const q=e.target.value.toLowerCase().trim(),r=$('#sres');
 const l=q?S.assets.filter(a=>(a.name+a.target).toLowerCase().includes(q)).slice(0,8):[];
 r.innerHTML=q?(l.length?l.map(a=>`<a data-act="detail" data-id="${a.id}">${esc(a.name)} <span class="hint">${CATS[a.cat].label}</span></a>`).join(''):'<div class="it hint">Sonuç yok</div>'):'';
 r.classList.toggle('on',!!q);
});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();$('#q').focus()}if(e.key==='Escape')close()});
addEventListener('hashchange',()=>{render();scrollTo(0,0)});

/* ---------- giriş (Firebase Auth index.html içinden çağırır) ---------- */
window.dacStart=u=>{
 U=u;KEY='dac_v1_'+u.uid;
 let raw=localStorage.getItem(KEY);
 if(!raw){const old=localStorage.getItem('dac_v1');if(old){raw=old;localStorage.setItem(KEY,old);localStorage.removeItem('dac_v1')}}
 S=JSON.parse(raw||'null')||blank();
 render();
};
window.dacStop=()=>{S=null;U=null;close();$('#view').innerHTML='';location.hash=''};
