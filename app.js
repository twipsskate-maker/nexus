/* NEXUS ออนไลน์ — ข้อมูลเข้ารหัสใน OneDrive ของเจ้าของ
   ล็อกอิน Microsoft (OAuth2 PKCE, สิทธิ์ Files.ReadWrite) → ดาวน์โหลด key.json/index.enc → ถอดรหัสในเครื่องด้วยรหัสเว็บ (PBKDF2 + AES-GCM)
   v2.1.8: แสดงเฉพาะ เป้าหมาย/กำลังติดตาม/สิ้นสุด • รูปบุคคล • แก้สถานะ/เช็กหมาย/การติดตาม (เข้ารหัสแล้ววางไว้ที่ NEXUS-web/inbox ให้คอมรับไปบันทึก)
   • ส่งต่อ LINE เลือกได้ ข้อความ หรือ ภาพเป้า
   ไม่มีสคริปต์ภายนอก ไม่ส่งข้อมูลไปที่อื่นนอกจาก Microsoft login/Graph/OneDrive */
(()=>{'use strict';
 const C=window.NEXUS_WEB_CONFIG||{};
 const $=s=>document.querySelector(s);
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const SEC=['setup','signin','unlock','search','detail','viewer'];
 const show=id=>{for(const s of SEC)$('#'+s).hidden=s!==id;if(id!=='viewer'){$('#viewerBody').innerHTML='';}$('#lock').hidden=!['search','detail','viewer'].includes(id);closeSheet();};
 const REDIRECT=location.origin+location.pathname;
 const local=(()=>{const p=new URLSearchParams(location.search).get('local');return p&&/^(127\.0\.0\.1|localhost)$/.test(location.hostname)?p.replace(/\/?$/,'/'):'';})(); // โหมดทดสอบในเครื่องเท่านั้น
 const SS={get:k=>{try{return sessionStorage.getItem(k)}catch{return null}},set:(k,v)=>{try{sessionStorage.setItem(k,v)}catch{}},del:k=>{try{sessionStorage.removeItem(k)}catch{}}};
 const LS={get:k=>{try{return localStorage.getItem(k)}catch{return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch{}},del:k=>{try{localStorage.removeItem(k)}catch{}}};
 const b64u=buf=>btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const AUTH=`https://login.microsoftonline.com/${encodeURIComponent(C.authority||'consumers')}/oauth2/v2.0`;
 const SCOPE='Files.ReadWrite offline_access openid';
 const GRAPH='https://graph.microsoft.com/v1.0/me/drive/root:/';
 const DEFAULT_SHOW=['เป้าหมาย','กำลังติดตาม','สิ้นสุด'];
 const CARD_FILE='nexus-card-v218';

 // ---------- Microsoft login (PKCE) ----------
 async function login(){
  const ver=b64u(crypto.getRandomValues(new Uint8Array(48)));const st=b64u(crypto.getRandomValues(new Uint8Array(16)));
  const ch=b64u(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ver)));SS.set('nx-pkce',ver);SS.set('nx-state',st);
  location.assign(`${AUTH}/authorize?`+new URLSearchParams({client_id:C.clientId,response_type:'code',redirect_uri:REDIRECT,scope:SCOPE,code_challenge:ch,code_challenge_method:'S256',state:st,prompt:'select_account'}));
 }
 async function tokenRequest(params){
  const r=await fetch(`${AUTH}/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:C.clientId,scope:SCOPE,...params})});
  const d=await r.json().catch(()=>({}));if(!r.ok||!d.access_token)throw Error(d.error_description||d.error||'token');
  SS.set('nx-at',d.access_token);SS.set('nx-exp',String(Date.now()+(d.expires_in-120)*1000));LS.set('nx-scope',SCOPE);if(d.refresh_token){LS.set('nx-rt',d.refresh_token);LS.set('nx-rt-at',String(Date.now()));}
  return d.access_token;
 }
 async function handleRedirect(){
  const p=new URLSearchParams(location.search);if(!p.get('code')&&!p.get('error'))return false;
  history.replaceState(null,'',REDIRECT);
  if(p.get('error')){$('#signinMsg').textContent='เข้าสู่ระบบไม่สำเร็จ: '+(p.get('error_description')||p.get('error'));return false;}
  if(p.get('state')!==SS.get('nx-state')){$('#signinMsg').textContent='เข้าสู่ระบบไม่สำเร็จ (state)';return false;}
  await tokenRequest({grant_type:'authorization_code',code:p.get('code'),redirect_uri:REDIRECT,code_verifier:SS.get('nx-pkce')||''});SS.del('nx-pkce');SS.del('nx-state');return true;
 }
 async function accessToken(){
  // รุ่นก่อนขอสิทธิ์อ่านอย่างเดียว — ต้องล็อกอินใหม่ 1 ครั้งเพื่อให้แก้ข้อมูลได้
  if(LS.get('nx-scope')!==SCOPE){SS.del('nx-at');LS.del('nx-rt');return null;}
  const at=SS.get('nx-at'),exp=+(SS.get('nx-exp')||0);if(at&&exp>Date.now())return at;
  const rt=LS.get('nx-rt');if(rt){try{return await tokenRequest({grant_type:'refresh_token',refresh_token:rt})}catch{LS.del('nx-rt');}}
  return null;
 }
 const graphPath=rel=>`${C.folder||'NEXUS-web'}/${rel}`.split('/').map(encodeURIComponent).join('/');
 // ---------- อ่าน/เขียนไฟล์ OneDrive ----------
 async function getFile(rel){
  if(local){const r=await fetch(local+rel,{cache:'no-store'});if(!r.ok)throw Object.assign(Error('missing'),{status:r.status});return new Uint8Array(await r.arrayBuffer());}
  const at=await accessToken();if(!at)throw Object.assign(Error('login'),{status:401});
  const path=graphPath(rel);
  // OneDrive ส่วนตัว: ถ้าใส่ $select จะไม่ส่ง downloadUrl มา จึงขอแบบเต็ม
  const meta=await fetch(GRAPH+path,{headers:{authorization:'Bearer '+at}});
  if(meta.status===401){SS.del('nx-at');throw Object.assign(Error('login'),{status:401});}
  if(!meta.ok)throw Object.assign(Error('missing'),{status:meta.status});
  const j=await meta.json();const url=j['@microsoft.graph.downloadUrl']||j['@content.downloadUrl'];
  const r=url?await fetch(url,{cache:'no-store'}):await fetch(GRAPH+path+':/content',{headers:{authorization:'Bearer '+at}});
  if(!r.ok)throw Object.assign(Error('download '+r.status),{status:r.status===404?404:0});return new Uint8Array(await r.arrayBuffer());
 }
 const localInbox=[]; // โหมดทดสอบ: เก็บไฟล์ที่จะส่งไว้ในหน่วยความจำ
 async function putInbox(name,bytes){
  if(local){localInbox.push({name,b64:btoa(String.fromCharCode(...bytes))});return;}
  const at=await accessToken();if(!at)throw Object.assign(Error('login'),{status:401});
  const r=await fetch(GRAPH+graphPath('inbox/'+name)+':/content',{method:'PUT',headers:{authorization:'Bearer '+at,'content-type':'application/octet-stream'},body:bytes});
  if(r.status===401||r.status===403){throw Object.assign(Error('write'),{status:401});}
  if(!r.ok)throw Error('upload '+r.status);
 }
 async function listInbox(){
  if(local)return localInbox.map(x=>({name:x.name,bytes:b64d(x.b64)}));
  const at=await accessToken();if(!at)return [];
  const r=await fetch(GRAPH+graphPath('inbox')+':/children?$top=200',{headers:{authorization:'Bearer '+at}});if(!r.ok)return [];
  const out=[];for(const it of ((await r.json()).value||[]).filter(x=>x.file&&/\.enc$/.test(x.name)).slice(0,100)){
   try{const u=it['@microsoft.graph.downloadUrl'];const d=u?await fetch(u,{cache:'no-store'}):await fetch(GRAPH+graphPath('inbox/'+it.name)+':/content',{headers:{authorization:'Bearer '+at}});if(d.ok)out.push({name:it.name,bytes:new Uint8Array(await d.arrayBuffer())});}catch{}
  }
  return out;
 }
 // ---------- ถอด/เข้ารหัส ----------
 let dek=null,index=null;
 const importDek=raw=>crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
 async function aesOpen(key,blob){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:blob.slice(0,12)},key,blob.slice(12)));}
 async function aesSeal(key,plain){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,plain));const out=new Uint8Array(12+ct.length);out.set(iv);out.set(ct,12);return out;}
 async function gunzip(bytes){const ds=new DecompressionStream('gzip');return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer());}
 async function unlock(pw){
  const k=JSON.parse(new TextDecoder().decode(await getFile('key.json')));
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  const kek=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:b64d(k.salt),iterations:k.iter},base,{name:'AES-GCM',length:256},false,['decrypt']);
  const raw=await aesOpen(kek,b64d(k.blob));dek=await importDek(raw);
  SS.set('nx-dek',btoa(String.fromCharCode(...raw)));
 }
 const showList=()=>(index&&index.meta&&Array.isArray(index.meta.show)&&index.meta.show.length?index.meta.show:DEFAULT_SHOW);
 async function loadIndex(){const blob=await getFile('index.enc');index=JSON.parse(new TextDecoder().decode(await gunzip(await aesOpen(dek,blob))));
  index.meta=index.meta||{};const sh=showList();index.records=(index.records||[]).filter(r=>sh.includes(r.s&&r.s.status));
  $('#stamp').textContent='ข้อมูล ณ '+new Date(index.at).toLocaleString('th-TH',{day:'2-digit',month:'2-digit',year:'2-digit',hour:'2-digit',minute:'2-digit'});
  try{await loadPending();}catch{}}
 async function restoreDek(){const s=SS.get('nx-dek');if(!s)return false;try{dek=await importDek(b64d(s));return true}catch{return false}}
 const fileCache=new Map();
 async function fileBlob(f){const bytes=await aesOpen(dek,await getFile('f/'+f.fid+'.enc'));return new Blob([bytes],{type:f.type||'application/octet-stream'});}
 async function fileUrl(f){if(fileCache.has(f.fid))return fileCache.get(f.fid);const u=URL.createObjectURL(await fileBlob(f));fileCache.set(f.fid,u);return u;}

 // ---------- การแก้ที่รอคอมรับ (overlay) ----------
 const FIELDS=['work','wanted','end','latestActionDate','latestAction','expectedProvince','expectedAddress'];
 function overlay(r,set,pending){
  r.e=r.e||{};for(const k of FIELDS)if(k in set)r.e[k]=set[k];
  if('work' in set&&set.work)r.s.status=set.work;if('wanted' in set&&set.wanted)r.s.wanted=set.wanted;
  if('expectedProvince' in set)r.s.province=set.expectedProvince||r.s.province;
  if('latestAction' in set)r.s.tracking=set.latestAction;if('latestActionDate' in set)r.s.trackingDate=set.latestActionDate;
  if(pending)r.pend=(r.pend||0)+1;
 }
 async function loadPending(){
  if(!index||!dek)return;const items=await listInbox();const list=[];
  for(const it of items){try{const e=JSON.parse(new TextDecoder().decode(await aesOpen(dek,it.bytes)));if(e&&e.v===1&&e.id&&e.set)list.push(e);}catch{}}
  list.sort((a,b)=>String(a.at).localeCompare(String(b.at)));
  for(const e of list){const r=index.records.find(x=>String(x.id)===String(e.id));if(r&&String(e.at)>String(index.at))overlay(r,e.set,true);}
 }

 // ---------- UI ----------
 let statusFilter=SS.get('nx-filter')||'เป้าหมาย';
 function renderFilters(){const counts={};for(const r of index.records)counts[r.s.status]=(counts[r.s.status]||0)+1;const sh=showList();if(statusFilter!=='ทั้งหมด'&&!sh.includes(statusFilter))statusFilter=sh[0];
  $('#filters').innerHTML=[...sh,'ทั้งหมด'].map(s=>`<button type="button" class="chip ${s===statusFilter?'on':''}" data-filter="${esc(s)}">${esc(s)} ${s==='ทั้งหมด'?index.records.length:(counts[s]||0)}</button>`).join('');}
 function search(){
  const q=$('#q').value.trim().toLowerCase(),qd=q.replace(/\D/g,'');SS.set('nx-q',$('#q').value);
  let list=index.records;if(statusFilter!=='ทั้งหมด'&&!q)list=list.filter(r=>r.s.status===statusFilter);
  if(q)list=list.filter(r=>r.k.includes(q)||(qd.length>=4&&r.k.includes(qd)));
  list=list.slice().sort((a,b)=>String(b.s.updated).localeCompare(String(a.s.updated)));
  $('#searchMsg').textContent=list.length?`พบ ${list.length} รายการ`+(list.length>80?' (แสดง 80 แรก)':''):'ไม่พบ';
  const shown=list.slice(0,80);
  $('#results').innerHTML=shown.map(r=>{const x=r.s;const files=(r.files||[]).filter(f=>f.fileId!==CARD_FILE);
   const hasW=files.some(f=>/^ไฟล์หมายจับ/.test(f.label)),has14=files.some(f=>/^ทร\.14/.test(f.label));
   const yn=(l,ok)=>`<span class="chip ${ok?'yes':'no'}">${ok?'✓':'✗'} ${l}${ok?'มี':'ไม่มี'}</span>`;
   const where=[x.sso&&['🏢','ประกันสังคม',x.sso],x.parcel&&['📦','พัสดุล่าสุด',x.parcel],x.health&&['🏥','สิทธิรักษา',x.health]].filter(Boolean);
   if(!where.length&&x.area)where.push(['📍','คาดว่าอยู่',x.area]);
   return `<li><button type="button" data-id="${esc(r.id)}">${r.p?`<img class="thumb" src="${esc(r.p)}" alt="">`:`<span class="thumb none" data-thumb="${esc(r.id)}">👤</span>`}<span class="r-body"><span class="r-top"><b>${esc(x.name)}</b>${x.age?` <small>อายุ ${esc(x.age)}</small>`:''}</span>
   <span class="chips">${x.status?`<span class="chip st">${esc(x.status)}</span>`:''}${x.wanted?`<span class="chip">${esc(x.wanted)}</span>`:''}${yn('ไฟล์หมายจับ ',hasW)}${yn('ทร.14 ',has14)}${r.pend?'<span class="chip pend">⏳ รอเข้าคอม</span>':''}</span>
   <span class="r-lines">${x.warrant?`<span><b>หมายจับเลขที่</b> ${esc(x.warrant)}</span>`:''}${x.charge?`<span><b>ข้อหา</b> ${esc(x.charge)}</span>`:''}${x.owner?`<span>🏛️ ${esc(x.owner)}</span>`:''}</span>
   ${where.length?`<span class="where">${where.map(([i,l,v])=>`<span>${i} <b>${l}</b> ${esc(v)}</span>`).join('')}</span>`:''}</span></button></li>`;}).join('');
  lazyThumbs(shown);
 }
 // รูปในรายการ: ถ้าคอมยังไม่ได้ส่งรูปย่อ ให้ดึงรูปบุคคลจากไฟล์ในแฟ้มแทน
 let thumbRun=0;const thumbUrl=new Map();
 async function lazyThumbs(list){const run=++thumbRun;for(const r of list){if(run!==thumbRun)return;const el=document.querySelector(`[data-thumb="${CSS.escape(String(r.id))}"]`);if(!el)continue;
  try{let u=thumbUrl.get(r.id);if(!u){const f=(r.files||[]).find(f=>/^รูปบุคคล/.test(f.label)&&/^image\//.test(f.type||''));if(!f)continue;u=await fileUrl(f);thumbUrl.set(r.id,u);}
   if(run!==thumbRun)return;const img=new Image();img.className='thumb';img.alt='';img.src=u;el.replaceWith(img);}catch{}}}
 let current=null;
 const opt=(list,val)=>{const l=list.slice();if(val&&!l.includes(val))l.unshift(val);return l.map(x=>`<option ${x===val?'selected':''}>${esc(x)}</option>`).join('');};
 function renderEdit(){
  const box=$('#edit');if(!current){box.innerHTML='';return;}
  const M=index.meta||{};if(!M.edit){box.innerHTML='<p class="msg">แก้จากเว็บได้หลังอัปเดตโปรแกรม NEXUS ในคอมเป็นรุ่นล่าสุด</p>';return;}
  const e=current.e||{};const isEnd=e.work==='สิ้นสุด';
  box.innerHTML=`<div class="edit"><div class="edit-head"><b>✏️ แก้ไขสถานะ / การติดตาม</b><button type="button" class="ghost" data-edit-close>ปิด</button></div>
   <form id="editForm" class="edit-grid">
    <label>สถานะงาน<select name="work">${opt(M.work||DEFAULT_SHOW,e.work)}</select></label>
    <label data-end ${isEnd?'':'hidden'}>ผลเมื่อสิ้นสุด<select name="end">${opt(M.end||[],e.end||'')}</select></label>
    <label>เช็กหมาย<select name="wanted">${opt(M.wanted||[],e.wanted)}</select></label>
    <label>วันที่ดำเนินการล่าสุด<input name="latestActionDate" value="${esc(e.latestActionDate||'')}" placeholder="วัน/เดือน/ปี เช่น 18/11/69"></label>
    <label class="wide">ล่าสุดที่บันทึก<textarea name="latestAction" rows="2" placeholder="เช่น ลงพื้นที่ตรวจสอบ ไม่พบตัว">${esc(e.latestAction||'')}</textarea></label>
    <label>จังหวัดที่คาดว่าอยู่<input name="expectedProvince" value="${esc(e.expectedProvince||'')}"></label>
    <label class="wide">คาดว่าอยู่ / จุดที่น่าจะอยู่<textarea name="expectedAddress" rows="2">${esc(e.expectedAddress||'')}</textarea></label>
    <div class="wide edit-actions"><button type="submit">💾 บันทึก</button><span id="editMsg" class="msg" aria-live="polite"></span></div>
    <p class="wide hint">บันทึกแล้วเข้ารหัสเก็บใน OneDrive • NEXUS ในคอมจะรับไปบันทึกในแฟ้มเองตอนเปิดโปรแกรม</p>
   </form></div>`;
 }
 function setEditOpen(on){const box=$('#edit');if(on){renderEdit();box.hidden=false;box.scrollIntoView({block:'start',behavior:'smooth'});}else{box.hidden=true;box.innerHTML='';}$('#editBtn').hidden=!!on;}
 function renderPend(){const b=$('#pendNote');if(b)b.hidden=!(current&&current.pend);}
 async function saveEdit(form){
  const msg=$('#editMsg');const fd=new FormData(form);const e=current.e||{};const set={};
  for(const k of FIELDS){if(!fd.has(k))continue;const v=String(fd.get(k)||'').trim();if(k==='end'&&fd.get('work')!=='สิ้นสุด')continue;if(v!==String(e[k]||''))set[k]=v;}
  if(!Object.keys(set).length){msg.textContent='ไม่มีอะไรเปลี่ยน';return;}
  const btn=form.querySelector('button[type=submit]');btn.disabled=true;msg.textContent='กำลังบันทึก…';
  try{const edit={v:1,id:current.id,at:new Date().toISOString(),base:current.s.updated||'',set};
   const name=`${Date.now()}-${b64u(crypto.getRandomValues(new Uint8Array(6))).replace(/[^\w]/g,'x')}.enc`;
   await putInbox(name,await aesSeal(dek,new TextEncoder().encode(JSON.stringify(edit))));
   overlay(current,set,true);setEditOpen(false);renderPend();$('#pendNote').textContent='✓ บันทึกการแก้ไขแล้ว • ⏳ รอ NEXUS ในคอมรับเข้าแฟ้ม';
  }catch(err){msg.textContent=err.status===401?'ต้องเข้าสู่ระบบ Microsoft ใหม่เพื่ออนุญาตการแก้ไข':'บันทึกไม่สำเร็จ: '+err.message;if(err.status===401){LS.del('nx-scope');setTimeout(()=>{if(confirm('ต้องเข้าสู่ระบบ Microsoft ใหม่ 1 ครั้งเพื่ออนุญาตการแก้ไข — ไปเลยไหม?'))login();},50);}}
  finally{btn.disabled=false;}
 }
 const cardFile=()=>(current&&current.files||[]).find(f=>f.fileId===CARD_FILE);
 let cardPrep=null;
 function prepCard(){const f=cardFile();if(!f){cardPrep=Promise.resolve(null);return;}const id=current.id;cardPrep=fileBlob(f).then(b=>id===current?.id?new File([b],`NEXUS ${current.s.name}.jpg`.replace(/[\\/:*?"<>|]/g,' '),{type:'image/jpeg'}):null).catch(()=>null);}
 async function open(id){
  current=index.records.find(r=>r.id===id);if(!current)return;show('detail');window.scrollTo(0,0);
  $('#card').innerHTML='<div class="nx-web-head"><img src="emblem.jpg" alt=""><div><div class="sys">NEXUS · WARRANT &amp; TARGET INTELLIGENCE</div><b>บุคคลเป้าหมายตามหมายจับ</b><span>กก.สส.3 บก.สส.ภ.1 · ข้อมูลเพื่อการสืบสวนและติดตามตัว</span></div></div>'+current.html;
  const files=(current.files||[]).filter(f=>f.fileId!==CARD_FILE);
  $('#files').innerHTML=files.length?'<b class="files-title">📎 ไฟล์ในแฟ้ม</b>'+files.map(f=>{const i=current.files.indexOf(f);return `<div class="file-row"><span>${esc(f.label)}</span><button type="button" data-view="${i}">👁 ดูไฟล์</button><button type="button" class="ghost" data-dl="${i}">⬇️ ดาวน์โหลด</button></div>`;}).join(''):'<p class="msg">ไม่มีไฟล์แนบในแฟ้มนี้</p>';
  const box=document.querySelector('[data-v213-photo]');
  if(box){if(current.p){const img=new Image();img.alt='ภาพบุคคล';img.src=current.p;box.append(img);}else{const photo=files.find(f=>/^รูปบุคคล/.test(f.label)&&/^image\//.test(f.type));if(photo){try{const img=new Image();img.alt='ภาพบุคคล';img.src=await fileUrl(photo);box.append(img);}catch{box.textContent='👤';}}else box.textContent='👤';}}
  setEditOpen(false);$('#pendNote').textContent='⏳ มีการแก้ไขจากเว็บ รอ NEXUS ในคอมรับเข้าแฟ้ม';renderPend();prepCard();
  history.pushState({id},'','#'+encodeURIComponent(id));
 }
 async function viewFile(i,download){const f=current.files[i];const btn=document.querySelector(download?`[data-dl="${i}"]`:`[data-view="${i}"]`);const old=btn?btn.textContent:'';if(btn){btn.textContent='กำลังโหลด…';btn.disabled=true;}
  try{const u=await fileUrl(f);const name=`${f.label}${/pdf/.test(f.type)?'.pdf':/png/.test(f.type)?'.png':/jpe?g/.test(f.type)?'.jpg':''}`;
   if(download){const a=document.createElement('a');a.href=u;a.download=name;document.body.append(a);a.click();a.remove();return;}
   $('#viewerTitle').textContent=f.label;$('#viewerDl').href=u;$('#viewerDl').download=name;$('#viewerOpen').href=u;
   $('#viewerBody').innerHTML=/^image\//.test(f.type)?`<img src="${u}" alt="${esc(f.label)}">`:`<iframe src="${u}" title="${esc(f.label)}"></iframe>`;
   $('#detail').hidden=true;$('#viewer').hidden=false;window.scrollTo(0,0);history.pushState({viewer:1},'',location.hash+'-v');
  }catch{alert('เปิดไฟล์ไม่สำเร็จ (ไฟล์อาจยังซิงก์ไม่เสร็จ)');}finally{if(btn){btn.textContent=old;btn.disabled=false;}}}

 // ---------- ส่งต่อ LINE: ข้อความ หรือ ภาพเป้า ----------
 function closeSheet(){const s=$('#shareSheet');if(s)s.hidden=true;}
 async function openSheet(){
  const s=$('#shareSheet');s.hidden=false;const ib=$('#shareImage');const has=!!cardFile();
  ib.hidden=!has;$('#shareNoImg').hidden=has;if(!has)return;
  ib.disabled=true;ib.textContent='กำลังเตรียมภาพเป้า…';if(!cardPrep)prepCard();
  const file=await cardPrep;ib.disabled=!file;ib.textContent=file?'🖼️ แชร์ภาพเป้า':'เตรียมภาพไม่สำเร็จ';
 }
 async function shareImage(){
  const file=await cardPrep;if(!file)return;
  if(navigator.canShare&&navigator.canShare({files:[file]})){try{await navigator.share({files:[file],title:current.s.name});closeSheet();return;}catch(err){if(err&&err.name==='AbortError')return;}}
  // แชร์ไฟล์ไม่ได้ (เช่น คอม) → เปิดภาพให้กดค้าง/บันทึก
  const u=URL.createObjectURL(file);$('#viewerTitle').textContent='ภาพเป้า';$('#viewerDl').href=u;$('#viewerDl').download=file.name;$('#viewerOpen').href=u;
  $('#viewerBody').innerHTML=`<img src="${u}" alt="ภาพเป้า">`;closeSheet();$('#detail').hidden=true;$('#viewer').hidden=false;window.scrollTo(0,0);history.pushState({viewer:1},'',location.hash+'-v');
 }

 $('#msLogin').addEventListener('click',login);
 $('#signout').addEventListener('click',()=>{for(const k of ['nx-at','nx-exp','nx-dek'])SS.del(k);LS.del('nx-rt');location.assign(`${AUTH}/logout?post_logout_redirect_uri=${encodeURIComponent(REDIRECT)}`);});
 $('#lock').addEventListener('click',()=>{SS.del('nx-dek');dek=null;index=null;for(const u of fileCache.values())URL.revokeObjectURL(u);fileCache.clear();show('unlock');});
 $('#unlockForm').addEventListener('submit',async e=>{e.preventDefault();const m=$('#unlockMsg');m.textContent='กำลังถอดรหัส…';
  try{await unlock($('#pw').value);$('#pw').value='';await loadIndex();m.textContent='';afterOpen();}
  catch(err){$('#pw').value='';m.textContent=err.status===401?'ต้องเข้าสู่ระบบ Microsoft ใหม่':err.status===404?'ยังไม่พบข้อมูลใน OneDrive — ตั้งรหัสเว็บในคอมก่อน':err.name==='OperationError'?'รหัสไม่ถูกต้อง (ตรวจว่าพิมพ์ภาษาอังกฤษ/ตัวเลขตรงกับที่ตั้งในคอม)':'เปิดไม่สำเร็จ: '+err.message;if(err.status===401)show('signin');}});
 $('#searchForm').addEventListener('submit',e=>{e.preventDefault();search();});
 $('#filters').addEventListener('click',e=>{const b=e.target.closest('[data-filter]');if(!b)return;statusFilter=b.dataset.filter;SS.set('nx-filter',statusFilter);$('#q').value='';renderFilters();search();});
 $('#results').addEventListener('click',e=>{const b=e.target.closest('button[data-id]');if(b)open(b.dataset.id);});
 $('#files').addEventListener('click',e=>{const v=e.target.closest('[data-view]');if(v)return viewFile(+v.dataset.view,false);const d=e.target.closest('[data-dl]');if(d)return viewFile(+d.dataset.dl,true);});
 $('#edit').addEventListener('submit',e=>{if(e.target.id==='editForm'){e.preventDefault();saveEdit(e.target);}});
 $('#edit').addEventListener('change',e=>{if(e.target.name==='work'){const l=$('#edit [data-end]');if(l)l.hidden=e.target.value!=='สิ้นสุด';}});
 $('#edit').addEventListener('click',e=>{if(e.target.closest('[data-edit-close]'))setEditOpen(false);});
 $('#editBtn').addEventListener('click',()=>setEditOpen(true));
 $('#back').addEventListener('click',()=>history.back());
 $('#viewerBack').addEventListener('click',()=>history.back());
 window.addEventListener('popstate',()=>{closeSheet();if(!$('#viewer').hidden){$('#viewer').hidden=true;$('#viewerBody').innerHTML='';$('#detail').hidden=false;return;}if(!location.hash&&index){show('search');search();}});
 $('#lineShare').addEventListener('click',()=>openSheet());
 $('#shareText').addEventListener('click',()=>{if(!current)return;closeSheet();window.open('https://line.me/R/share?text='+encodeURIComponent(current.text),'_blank','noopener');});
 $('#shareImage').addEventListener('click',()=>shareImage());
 $('#shareClose').addEventListener('click',closeSheet);
 $('#shareSheet').addEventListener('click',e=>{if(e.target.id==='shareSheet')closeSheet();});
 $('#copy').addEventListener('click',async()=>{if(!current)return;let ok=false;try{await navigator.clipboard.writeText(current.text);ok=true}catch{}
  if(!ok){const ta=document.createElement('textarea');ta.value=current.text;ta.className='offscreen';document.body.append(ta);ta.select();try{ok=document.execCommand('copy')}catch{}ta.remove();}
  $('#copy').textContent=ok?'คัดลอกแล้ว ✓':'คัดลอกไม่ได้';setTimeout(()=>$('#copy').textContent='คัดลอกข้อความ',1800);});
 function afterOpen(){show('search');renderFilters();$('#q').value=SS.get('nx-q')||'';search();}

 async function boot(){
  if(!local&&!C.clientId){show('setup');return;}
  try{if(!local)await handleRedirect();}catch(err){$('#signinMsg').textContent='เข้าสู่ระบบไม่สำเร็จ: '+err.message;}
  if(!local&&!(await accessToken())){if(LS.get('nx-rt-at')&&LS.get('nx-scope')!==SCOPE)$('#signinMsg').textContent='เว็บรุ่นใหม่แก้ข้อมูลได้แล้ว — เข้าสู่ระบบอีกครั้ง แล้วกด “ยอมรับ” สิทธิ์ใหม่';show('signin');return;}
  if(await restoreDek()){try{await loadIndex();afterOpen();return;}catch{}}
  show('unlock');$('#pw').focus();
 }
 boot();
 window.NEXUS_WEB={state:()=>({unlocked:!!dek,records:index?index.records.length:0,statuses:index?[...new Set(index.records.map(r=>r.s.status))]:[]}),outbox:()=>localInbox.slice(),current:()=>current&&{id:current.id,pend:current.pend||0,e:current.e}};
})();
