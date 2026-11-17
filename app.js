/* NEXUS ออนไลน์ — อ่านอย่างเดียว ข้อมูลเข้ารหัสใน OneDrive ของเจ้าของ
   ล็อกอิน Microsoft (OAuth2 PKCE, สิทธิ์ Files.Read) → ดาวน์โหลด key.json/index.enc → ถอดรหัสในเครื่องด้วยรหัสเว็บ (PBKDF2 + AES-GCM)
   ไม่มีสคริปต์ภายนอก ไม่ส่งข้อมูลไปที่อื่นนอกจาก Microsoft login/Graph/OneDrive */
(()=>{'use strict';
 const C=window.NEXUS_WEB_CONFIG||{};
 const $=s=>document.querySelector(s);
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const SEC=['setup','signin','unlock','search','detail','viewer'];
 const show=id=>{for(const s of SEC)$('#'+s).hidden=s!==id;if(id!=='viewer'){$('#viewerBody').innerHTML='';}$('#lock').hidden=!['search','detail','viewer'].includes(id);};
 const REDIRECT=location.origin+location.pathname;
 const local=(()=>{const p=new URLSearchParams(location.search).get('local');return p&&/^(127\.0\.0\.1|localhost)$/.test(location.hostname)?p.replace(/\/?$/,'/'):'';})(); // โหมดทดสอบในเครื่องเท่านั้น
 const SS={get:k=>{try{return sessionStorage.getItem(k)}catch{return null}},set:(k,v)=>{try{sessionStorage.setItem(k,v)}catch{}},del:k=>{try{sessionStorage.removeItem(k)}catch{}}};
 const LS={get:k=>{try{return localStorage.getItem(k)}catch{return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch{}},del:k=>{try{localStorage.removeItem(k)}catch{}}};
 const b64u=buf=>btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const AUTH=`https://login.microsoftonline.com/${encodeURIComponent(C.authority||'consumers')}/oauth2/v2.0`;
 const SCOPE='Files.Read offline_access openid';

 // ---------- Microsoft login (PKCE) ----------
 async function login(){
  const ver=b64u(crypto.getRandomValues(new Uint8Array(48)));const st=b64u(crypto.getRandomValues(new Uint8Array(16)));
  const ch=b64u(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ver)));SS.set('nx-pkce',ver);SS.set('nx-state',st);
  location.assign(`${AUTH}/authorize?`+new URLSearchParams({client_id:C.clientId,response_type:'code',redirect_uri:REDIRECT,scope:SCOPE,code_challenge:ch,code_challenge_method:'S256',state:st,prompt:'select_account'}));
 }
 async function tokenRequest(params){
  const r=await fetch(`${AUTH}/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:C.clientId,scope:SCOPE,...params})});
  const d=await r.json().catch(()=>({}));if(!r.ok||!d.access_token)throw Error(d.error_description||d.error||'token');
  SS.set('nx-at',d.access_token);SS.set('nx-exp',String(Date.now()+(d.expires_in-120)*1000));if(d.refresh_token){LS.set('nx-rt',d.refresh_token);LS.set('nx-rt-at',String(Date.now()));}
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
  const at=SS.get('nx-at'),exp=+(SS.get('nx-exp')||0);if(at&&exp>Date.now())return at;
  const rt=LS.get('nx-rt');if(rt){try{return await tokenRequest({grant_type:'refresh_token',refresh_token:rt})}catch{LS.del('nx-rt');}}
  return null;
 }
 // ---------- อ่านไฟล์จาก OneDrive ----------
 async function getFile(rel){
  if(local){const r=await fetch(local+rel,{cache:'no-store'});if(!r.ok)throw Object.assign(Error('missing'),{status:r.status});return new Uint8Array(await r.arrayBuffer());}
  const at=await accessToken();if(!at)throw Object.assign(Error('login'),{status:401});
  const path=`${C.folder||'NEXUS-web'}/${rel}`.split('/').map(encodeURIComponent).join('/');
  // OneDrive ส่วนตัว: ถ้าใส่ $select จะไม่ส่ง downloadUrl มา จึงขอแบบเต็ม
  const meta=await fetch(`https://graph.microsoft.com/v1.0/me/drive/root:/${path}`,{headers:{authorization:'Bearer '+at}});
  if(meta.status===401){SS.del('nx-at');throw Object.assign(Error('login'),{status:401});}
  if(!meta.ok)throw Object.assign(Error('missing'),{status:meta.status});
  const j=await meta.json();const url=j['@microsoft.graph.downloadUrl']||j['@content.downloadUrl'];
  const r=url?await fetch(url,{cache:'no-store'}):await fetch(`https://graph.microsoft.com/v1.0/me/drive/root:/${path}:/content`,{headers:{authorization:'Bearer '+at}});
  if(!r.ok)throw Object.assign(Error('download '+r.status),{status:r.status===404?404:0});return new Uint8Array(await r.arrayBuffer());
 }
 // ---------- ถอดรหัส ----------
 let dek=null,index=null;
 async function aesOpen(key,blob){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:blob.slice(0,12)},key,blob.slice(12)));}
 async function gunzip(bytes){const ds=new DecompressionStream('gzip');return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer());}
 async function unlock(pw){
  const k=JSON.parse(new TextDecoder().decode(await getFile('key.json')));
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  const kek=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:b64d(k.salt),iterations:k.iter},base,{name:'AES-GCM',length:256},false,['decrypt']);
  const raw=await aesOpen(kek,b64d(k.blob));dek=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
  SS.set('nx-dek',btoa(String.fromCharCode(...raw)));
 }
 async function loadIndex(){const blob=await getFile('index.enc');index=JSON.parse(new TextDecoder().decode(await gunzip(await aesOpen(dek,blob))));
  $('#stamp').textContent='ข้อมูล ณ '+new Date(index.at).toLocaleString('th-TH',{day:'2-digit',month:'2-digit',year:'2-digit',hour:'2-digit',minute:'2-digit'});}
 async function restoreDek(){const s=SS.get('nx-dek');if(!s)return false;try{dek=await crypto.subtle.importKey('raw',b64d(s),'AES-GCM',false,['decrypt']);return true}catch{return false}}
 const fileCache=new Map();
 async function fileUrl(f){if(fileCache.has(f.fid))return fileCache.get(f.fid);const bytes=await aesOpen(dek,await getFile('f/'+f.fid+'.enc'));const u=URL.createObjectURL(new Blob([bytes],{type:f.type||'application/octet-stream'}));fileCache.set(f.fid,u);return u;}

 // ---------- UI ----------
 const STATUS_ORDER=['เป้าหมาย','กำลังติดตาม','ข้อมูลไม่พอ','ยังไม่ได้ตรวจสอบ','ติดคุก','สิ้นสุด'];
 let statusFilter=SS.get('nx-filter')||'เป้าหมาย';
 function renderFilters(){const counts={};for(const r of index.records)counts[r.s.status]=(counts[r.s.status]||0)+1;
  $('#filters').innerHTML=['ทั้งหมด',...STATUS_ORDER.filter(s=>counts[s])].map(s=>`<button type="button" class="chip ${s===statusFilter?'on':''}" data-filter="${esc(s)}">${esc(s)} ${s==='ทั้งหมด'?index.records.length:counts[s]}</button>`).join('');}
 function search(){
  const q=$('#q').value.trim().toLowerCase(),qd=q.replace(/\D/g,'');SS.set('nx-q',$('#q').value);
  let list=index.records;if(statusFilter!=='ทั้งหมด'&&!q)list=list.filter(r=>r.s.status===statusFilter);
  if(q)list=list.filter(r=>r.k.includes(q)||(qd.length>=4&&r.k.includes(qd)));
  list=list.slice().sort((a,b)=>String(b.s.updated).localeCompare(String(a.s.updated)));
  $('#searchMsg').textContent=list.length?`พบ ${list.length} รายการ`+(list.length>80?' (แสดง 80 แรก)':''):'ไม่พบ';
  $('#results').innerHTML=list.slice(0,80).map(r=>{const x=r.s;return `<li><button type="button" data-id="${esc(r.id)}"><div class="r-top"><b>${esc(x.name)}</b>${x.age?` <small>อายุ ${esc(x.age)}</small>`:''}</div>
   <div class="chips">${x.status?`<span class="chip st">${esc(x.status)}</span>`:''}${x.wanted?`<span class="chip">${esc(x.wanted)}</span>`:''}${x.province?`<span class="chip">📍 ${esc(x.province)}</span>`:''}${x.pin?'<span class="chip">🗺️ มีหมุด</span>':''}${r.files.length?`<span class="chip">📎 ${r.files.length}</span>`:''}</div>
   <span>${esc([x.warrant&&`หมาย ${x.warrant}`,x.charge,x.owner].filter(Boolean).join(' • '))}</span>${x.tracking?`<span class="track">📝 ${esc(x.tracking)}${x.trackingDate?` <small>(${esc(x.trackingDate)})</small>`:''}</span>`:''}</button></li>`;}).join('');
 }
 let current=null;
 async function open(id){
  current=index.records.find(r=>r.id===id);if(!current)return;show('detail');window.scrollTo(0,0);
  $('#card').innerHTML=current.html;$('#lineShare').href='https://line.me/R/share?text='+encodeURIComponent(current.text);
  const files=current.files||[];
  $('#files').innerHTML=files.length?'<b class="files-title">📎 ไฟล์ในแฟ้ม</b>'+files.map((f,i)=>`<div class="file-row"><span>${esc(f.label)}</span><button type="button" data-view="${i}">👁 ดูไฟล์</button><button type="button" class="ghost" data-dl="${i}">⬇️ ดาวน์โหลด</button></div>`).join(''):`<p class="msg">${current.filesOnPc==='?'?'ไฟล์แนบของแฟ้มสถานะนี้อยู่ในคอม (เว็บเก็บไฟล์เฉพาะ เป้าหมาย / กำลังติดตาม / ข้อมูลไม่พอ)':'ไม่มีไฟล์แนบในแฟ้มนี้'}</p>`;
  const box=document.querySelector('[data-v213-photo]');const photo=files.find(f=>/^รูปบุคคล/.test(f.label)&&/^image\//.test(f.type));
  if(box){if(photo){try{const img=new Image();img.alt='ภาพบุคคล';img.src=await fileUrl(photo);box.append(img);}catch{box.textContent='👤';}}else box.textContent='👤';}
  history.pushState({id},'','#'+encodeURIComponent(id));
 }
 async function viewFile(i,download){const f=current.files[i];const btn=document.querySelector(download?`[data-dl="${i}"]`:`[data-view="${i}"]`);const old=btn.textContent;btn.textContent='กำลังโหลด…';btn.disabled=true;
  try{const u=await fileUrl(f);const name=`${f.label}${/pdf/.test(f.type)?'.pdf':/png/.test(f.type)?'.png':/jpe?g/.test(f.type)?'.jpg':''}`;
   if(download){const a=document.createElement('a');a.href=u;a.download=name;document.body.append(a);a.click();a.remove();return;}
   $('#viewerTitle').textContent=f.label;$('#viewerDl').href=u;$('#viewerDl').download=name;$('#viewerOpen').href=u;
   $('#viewerBody').innerHTML=/^image\//.test(f.type)?`<img src="${u}" alt="${esc(f.label)}">`:`<iframe src="${u}" title="${esc(f.label)}"></iframe>`;
   $('#detail').hidden=true;$('#viewer').hidden=false;window.scrollTo(0,0);history.pushState({viewer:1},'',location.hash+'-v');
  }catch{alert('เปิดไฟล์ไม่สำเร็จ (ไฟล์อาจยังซิงก์ไม่เสร็จ)');}finally{btn.textContent=old;btn.disabled=false;}}

 $('#msLogin').addEventListener('click',login);
 $('#signout').addEventListener('click',()=>{for(const k of ['nx-at','nx-exp','nx-dek'])SS.del(k);LS.del('nx-rt');location.assign(`${AUTH}/logout?post_logout_redirect_uri=${encodeURIComponent(REDIRECT)}`);});
 $('#lock').addEventListener('click',()=>{SS.del('nx-dek');dek=null;index=null;for(const u of fileCache.values())URL.revokeObjectURL(u);fileCache.clear();show('unlock');});
 $('#unlockForm').addEventListener('submit',async e=>{e.preventDefault();const m=$('#unlockMsg');m.textContent='กำลังถอดรหัส…';
  try{await unlock($('#pw').value);$('#pw').value='';await loadIndex();m.textContent='';afterOpen();}
  catch(err){$('#pw').value='';m.textContent=err.status===401?'ต้องเข้าสู่ระบบ Microsoft ใหม่':err.status===404?'ยังไม่พบข้อมูลใน OneDrive — ตั้งรหัสเว็บในคอมก่อน':err.name==='OperationError'?'รหัสไม่ถูกต้อง':'เปิดไม่สำเร็จ: '+err.message;if(err.status===401)show('signin');}});
 $('#searchForm').addEventListener('submit',e=>{e.preventDefault();search();});
 $('#filters').addEventListener('click',e=>{const b=e.target.closest('[data-filter]');if(!b)return;statusFilter=b.dataset.filter;SS.set('nx-filter',statusFilter);$('#q').value='';renderFilters();search();});
 $('#results').addEventListener('click',e=>{const b=e.target.closest('button[data-id]');if(b)open(b.dataset.id);});
 $('#files').addEventListener('click',e=>{const v=e.target.closest('[data-view]');if(v)return viewFile(+v.dataset.view,false);const d=e.target.closest('[data-dl]');if(d)return viewFile(+d.dataset.dl,true);});
 $('#back').addEventListener('click',()=>history.back());
 $('#viewerBack').addEventListener('click',()=>history.back());
 window.addEventListener('popstate',()=>{if(!$('#viewer').hidden){$('#viewer').hidden=true;$('#viewerBody').innerHTML='';$('#detail').hidden=false;return;}if(!location.hash&&index)show('search');});
 $('#copy').addEventListener('click',async()=>{if(!current)return;let ok=false;try{await navigator.clipboard.writeText(current.text);ok=true}catch{}
  if(!ok){const ta=document.createElement('textarea');ta.value=current.text;ta.className='offscreen';document.body.append(ta);ta.select();try{ok=document.execCommand('copy')}catch{}ta.remove();}
  $('#copy').textContent=ok?'คัดลอกแล้ว ✓':'คัดลอกไม่ได้';setTimeout(()=>$('#copy').textContent='คัดลอกข้อความ',1800);});
 function afterOpen(){show('search');renderFilters();$('#q').value=SS.get('nx-q')||'';search();}

 async function boot(){
  if(!local&&!C.clientId){show('setup');return;}
  try{if(!local)await handleRedirect();}catch(err){$('#signinMsg').textContent='เข้าสู่ระบบไม่สำเร็จ: '+err.message;}
  if(!local&&!(await accessToken())){show('signin');return;}
  if(await restoreDek()){try{await loadIndex();afterOpen();return;}catch{}}
  show('unlock');$('#pw').focus();
 }
 boot();
 window.NEXUS_WEB={state:()=>({unlocked:!!dek,records:index?index.records.length:0})};
})();
