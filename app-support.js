/* Digital Asset Center - kullanıcı destek paneli (#support) (app-admin-ops.js'den sonra yüklenir) */
/* ---------- kullanıcı destek paneli (V13.4): talep aç, yanıtları oku, mesaj yaz, talebi kapat ---------- */
const SUP={loaded:false,loading:false,err:null,tickets:[],open:null,form:{subject:'',message:'',category:'general'},drafts:{},busy:false,timer:null,sig:'',at:0};
const SUPCAT={general:'Genel',billing:'Fatura / ödeme',cancel:'Paket iptali / iade',technical:'Teknik sorun'};
const SUPST={open:['Açık','wn'],answered:['Yanıtlandı','ok'],resolved:['Sonuçlandı','ok'],closed:['Kapalı','mu']};
const supFinal=t=>t.status==='closed'||t.status==='resolved';
const supSig=t=>t.map(x=>x.id+':'+x.status+':'+x.updatedAt+':'+x.replies.length).join('|');
const supFocused=()=>{const a=document.activeElement,b=$('#sup-body');return !!(a&&b&&b.contains(a)&&/^(TEXTAREA|INPUT|SELECT)$/.test(a.tagName))};
function supPaint(){const el=$('#sup-body');if(el){el.innerHTML=supBody();icons()}}
function supPut(t){const i=SUP.tickets.findIndex(x=>x.id===t.id);if(i<0)SUP.tickets.unshift(t);else SUP.tickets[i]=t;SUP.tickets.sort((a,b)=>(b.updatedAt||0)-(a.updatedAt||0));SUP.sig=supSig(SUP.tickets)}
async function supLoad(quiet){
 if(SUP.loading)return;SUP.loading=true;
 try{
  const j=await bkApi('GET','/api/support/my'),sig=supSig(j.tickets);
  if(quiet&&sig===SUP.sig&&SUP.loaded){SUP.at=Date.now();SUP.loading=false;return}
  if(quiet&&supFocused()){SUP.loading=false;return} // kullanıcı yazarken ekranı yenileme; sonraki turda güncellenir
  SUP.tickets=j.tickets;SUP.sig=sig;SUP.err=null;SUP.loaded=true;SUP.at=Date.now();supPaint();if((location.hash.slice(1)||'').split('/')[0]==='support')bdgSupSeen(j.tickets);
 }catch(e){if(!quiet||!SUP.loaded){SUP.err=e.message;SUP.loaded=true;supPaint()}}
 SUP.loading=false;
}
function supportPage(){
 if(!SUP.loaded&&!SUP.loading)supLoad();else if(SUP.loaded&&!SUP.loading&&Date.now()-SUP.at>15000)supLoad(true);
 if(!SUP.timer)SUP.timer=setInterval(()=>{if((location.hash.slice(1)||'').split('/')[0]!=='support'||document.hidden)return;supLoad(true)},45000);
 return`<div class="mh"><div><h2>Destek</h2><div class="hint">Sorunuzu yazın; yanıtlar burada görünür (ayrıca e-posta ile de bildirilir).</div></div><button class="btn s" data-act="sup-refresh">${ic('refresh-cw')} Yenile</button></div><div id="sup-body">${supBody()}</div>`;
}
function supTicket(t){
 const st=SUPST[t.status]||[t.status,'mu'],on=SUP.open===t.id;
 const head=`<div class="mh sup-h" data-act="sup-toggle" data-id="${esc(t.id)}" role="button" tabindex="0"><b>#${esc(t.no)} • ${esc(t.subject)}</b><span class="badge ${st[1]}">${esc(st[0])}</span></div><div class="hint">${esc(SUPCAT[t.category]||SUPCAT.general)} • ${esc(fdt(t.createdAt))}${t.replies.length?' • '+t.replies.length+' yanıt':''}</div>`;
 if(!on)return`<div class="card">${head}</div>`;
 const bub=(who,at,msg)=>`<div class="sup-msg ${who==='user'?'sup-me':'sup-staff'}"><div class="hint"><b>${who==='user'?'Siz':'Destek ekibi'}</b> • ${esc(fdt(at))}</div><div class="sup-tx">${esc(msg)}</div></div>`;
 const thread=bub('user',t.createdAt,t.message)+t.replies.map(r=>bub(r.from,r.at,r.message)).join('');
 const fin=supFinal(t);
 return`<div class="card">${head}<div class="sup-thread">${thread}</div>
 ${fin?`<div class="hint">Bu talep ${t.status==='closed'?'kapatıldı':'sonuçlandı'}; artık mesaj yazılamaz. Yeni bir talep açabilirsiniz.</div>`:`<textarea class="field" id="sup-rp-${esc(t.id)}" maxlength="4000" placeholder="Mesajınız…">${esc(SUP.drafts[t.id]||'')}</textarea>
 <div class="btns"><button class="btn p" data-act="sup-reply" data-id="${esc(t.id)}">${ic('send')} Gönder</button></div>`}</div>`;
}
function supBody(){
 if(!SUP.loaded)return'<div class="card"><div class="empty">Yükleniyor…</div></div>';
 const f=SUP.form,cats=Object.entries(SUPCAT).map(([k,l])=>`<option value="${k}"${f.category===k?' selected':''}>${esc(l)}</option>`).join('');
 const act=SUP.tickets.find(t=>!supFinal(t));
 const form=act?`<div class="card"><b>${ic('life-buoy')} Açık destek talebiniz var</b><div class="hint">#${esc(act.no)} numaralı talebiniz sonuçlanana kadar yeni talep açamazsınız. Eklemek istediğiniz bir şey varsa aşağıdan o talebe mesaj yazın.</div><button class="btn s" data-act="sup-toggle" data-id="${esc(act.id)}">Talebi aç</button></div>`:`<div class="card"><b>${ic('life-buoy')} Yeni destek talebi</b>
 <select class="field" id="sup-cat" aria-label="Kategori">${cats}</select>
 <input class="field" id="sup-subject" maxlength="120" placeholder="Konu" value="${esc(f.subject)}" autocomplete="off">
 <textarea class="field" id="sup-message" maxlength="4000" placeholder="Sorununuzu veya talebinizi yazın (en az 10 karakter)">${esc(f.message)}</textarea>
 <button class="btn p w" data-act="sup-new">${ic('send')} Talebi gönder</button>
 <div class="hint">Paket iptali veya iade için kategori olarak <b>Paket iptali / iade</b> seçin; sipariş numaranızı ve nedeni yazın.</div></div>`;
 const err=SUP.err?`<div class="card"><div class="empty">${esc(SUP.err)}</div><button class="btn s" data-act="sup-refresh">Tekrar dene</button></div>`:'';
 const list=SUP.tickets.length?SUP.tickets.map(supTicket).join(''):(SUP.err?'':'<div class="card"><div class="empty">Henüz destek talebiniz yok.</div></div>');
 return form+err+(SUP.tickets.length?'<h3 style="margin:18px 0 8px">Taleplerim</h3>':'')+list;
}
document.addEventListener('input',e=>{const t=e.target;if(!t||!t.id)return;
 if(t.id==='sup-subject')SUP.form.subject=t.value;else if(t.id==='sup-message')SUP.form.message=t.value;else if(t.id==='sup-cat')SUP.form.category=t.value;
 else if(t.id.startsWith('sup-rp-'))SUP.drafts[t.id.slice(7)]=t.value});
document.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&e.target&&e.target.classList&&e.target.classList.contains('sup-h')){e.preventDefault();e.target.click()}});
document.addEventListener('click',async e=>{
 const b=e.target.closest('[data-act^="sup-"]');if(!b)return;const act=b.dataset.act,id=b.dataset.id;
 try{
  if(act==='sup-refresh'){SUP.loaded=false;SUP.err=null;supPaint();await supLoad();return}
  if(act==='sup-toggle'){SUP.open=SUP.open===id?null:id;return supPaint()}
  if(SUP.busy)return;
  if(act==='sup-new'){
   const f=SUP.form;if(f.subject.trim().length<3)return toast('Konu en az 3 karakter olmalı','warn');if(f.message.trim().length<10)return toast('Mesaj en az 10 karakter olmalı','warn');
   SUP.busy=true;try{const j=await bkApi('POST','/api/support/my',{subject:f.subject.trim(),message:f.message.trim(),category:f.category});SUP.form={subject:'',message:'',category:'general'};supPut(j.ticket);SUP.open=j.ticket.id;toast('Talebiniz alındı: #'+j.ticket.no);supPaint()}finally{SUP.busy=false}return}
  if(act==='sup-reply'){
   const m=(SUP.drafts[id]||'').trim();if(m.length<2)return toast('Önce mesajınızı yazın','warn');
   SUP.busy=true;try{const j=await bkApi('POST','/api/support/my/'+encodeURIComponent(id)+'/reply',{message:m});delete SUP.drafts[id];supPut(j.ticket);toast('Mesajınız gönderildi');supPaint()}finally{SUP.busy=false}return}
 }catch(x){toast(x.message,'err')}
});
