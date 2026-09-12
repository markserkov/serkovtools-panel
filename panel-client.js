const ADMIN = window.__ADMIN__ || {};
let cachedAdmins=[];
let cachedStats={};
let cachedWeek='';

async function api(url,method='GET',body=null){
  try{const o={method,headers:{'Content-Type':'application/json','Accept':'application/json'},credentials:'include'};if(body!==null)o.body=JSON.stringify(body);const r=await fetch(url,o);const t=await r.text();let d={};try{d=t?JSON.parse(t):{};}catch{d={error:t||`Ошибка ${r.status}`};}if(r.status===401){location.href='/login';return {error:'Не авторизован'};}if(!r.ok&&!d.error)d.error=`Ошибка ${r.status}`;return d;}catch(e){console.error(e);toast('Нет соединения с сервером',true);return {error:'Нет соединения с сервером'};}}
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function toast(msg,bad=false){const old=document.querySelector('.toast');old?.remove();const x=document.createElement('div');x.className='toast'+(bad?' bad':'');x.textContent=msg;document.body.appendChild(x);setTimeout(()=>x.remove(),3200);}
function showPage(name){document.querySelectorAll('.page').forEach(x=>x.classList.toggle('active',x.id==='page-'+name));document.querySelectorAll('.navBtn').forEach(x=>x.classList.toggle('active',x.dataset.page===name));if(name==='me')loadMine();if(name==='admins')loadAdmins();closeSidebar();try{scrollTo({top:0,behavior:'smooth'});}catch{scrollTo(0,0);}}
function openSidebar(){document.getElementById('sidebar')?.classList.add('open');document.getElementById('sidebarOverlay')?.classList.add('open');}
function closeSidebar(){document.getElementById('sidebar')?.classList.remove('open');document.getElementById('sidebarOverlay')?.classList.remove('open');}
function formatDate(v){if(!v)return '—';return new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});}
function fmtStatus(s){return s==='online'?'<span class="online">● Онлайн</span>':'<span class="offline">● Оффлайн</span>';}

async function loadMine(){
  const d=await api('/api/admins'); if(d.error)return;
  cachedAdmins=d.admins||[];cachedStats=d.stats||{};cachedWeek=d.week||'';
  const me=cachedAdmins.find(x=>Number(x.id)===Number(ADMIN.id));
  const count=me?(cachedStats[String(me.discord_id)]||0):0;
  document.getElementById('myMessages').textContent=count;
  document.getElementById('weekLabel').textContent=cachedWeek?cachedWeek.split(' / ')[0]:'—';
  document.getElementById('updatedAt').textContent=bridgeUpdatedAt?formatDate(bridgeUpdatedAt):'—';
  await loadStatus(false);
}
let bridgeUpdatedAt=null;let lastStats={};
async function loadStatus(show=true){
  const d=await api('/api/status');if(d.error){if(show)toast(d.error,true);return;}
  bridgeUpdatedAt=new Date();
  const g=d.guild||{};
  const cells=[['Discord',d.discord],['VK',d.vk],['Telegram',d.telegram],['Anti-Sliv',d.antiSliv?'online':'offline']];
  document.getElementById('statusGrid').innerHTML=cells.map(([n,s])=>`<div class="status"><small>${n}</small><b>${fmtStatus(s)}</b></div>`).join('')+`<div style="grid-column:1/-1;color:var(--muted);padding:4px 2px">Ping: <b style="color:#fff">${d.ping==null?'—':esc(d.ping+' ms')}</b> · Uptime: <b style="color:#fff">${esc(fmtUptime(d.uptime))}</b> · Сервер: <b style="color:#fff">${esc(g.name||'Discord')}</b></div>`;
  if(show)toast('Статус обновлён');
  return d;
}
function fmtUptime(sec){sec=Number(sec)||0;const d=Math.floor(sec/86400);sec%=86400;const h=Math.floor(sec/3600);sec%=3600;const m=Math.floor(sec/60);return (d?d+'д ':'')+String(h).padStart(2,'0')+'ч '+String(m).padStart(2,'0')+'м';}
async function openStats(){
  const d=await api('/api/stats');if(d.error){toast(d.error,true);return;}lastStats=d;const g=d.guild||{},a=d.attempts||{};
  const items=[['Участники',g.members||0],['Люди',g.humans||0],['Боты',g.bots||0],['Онлайн',g.online||0],['Каналы',g.channels||0],['Роли',g.roles||0],['Бусты',g.boosts||0],['Anti-Sliv сегодня',a.total||0]];
  document.getElementById('modalStats').innerHTML=items.map(x=>`<div class="modalStat"><small>${x[0]}</small><b>${esc(x[1])}</b></div>`).join('')+`<div class="modalStat"><small>Период сообщений</small><b>${esc(d.week||'—')}</b></div><div class="modalStat"><small>Обновление</small><b>каждые 6 ч МСК</b></div>`;
  document.getElementById('statsModal').classList.add('open');
}
function closeModal(id){document.getElementById(id)?.classList.remove('open');}
async function loadAdmins(){
  const d=await api('/api/admins');if(d.error){toast(d.error,true);return;}cachedAdmins=d.admins||[];cachedStats=d.stats||{};cachedWeek=d.week||'';renderAdmins();loadRoles();
}
function renderAdmins(){
  const q=(document.getElementById('adminSearch')?.value||'').toLowerCase();
  const arr=cachedAdmins.filter(a=>`${a.nickname||''} ${a.position||''}`.toLowerCase().includes(q));
  const wrap=document.getElementById('adminsList');
  if(!arr.length){wrap.innerHTML='<div class="empty">Администраторы не найдены.</div>';return;}
  let html='<table class="adminTable"><thead><tr><th>Администратор</th><th>Уровень</th><th>Сообщения</th><th></th></tr></thead><tbody>';
  for(const a of arr){const count=Number(cachedStats[String(a.discord_id)]||0);const canDelete=Number(ADMIN.level||0)>Number(a.admin_level||0)&&Number(a.id)!==Number(ADMIN.id);html+=`<tr><td><div class="adminUser"><img class="adminAvatar" src="${esc(a.avatar||a.vk_avatar||'')}" onerror="this.style.visibility='hidden'"><div class="adminName"><b>${esc(a.nickname||'VK '+a.vk_id)}</b><span>${esc(a.position||'Без должности')}</span></div></div></td><td><span class="level ${Number(a.admin_level)===8?'level8':''}">◈ ${Number(a.admin_level||0)}</span></td><td class="count">${count}</td><td>${canDelete?`<button class="btn danger" onclick="deleteAdmin(${a.id})">Удалить</button>`:''}</td></tr>`;}
  html+='</tbody></table>';wrap.innerHTML=html;
}
async function deleteAdmin(id){if(!confirm('Удалить этот профиль администратора? Вход в этот аккаунт после этого будет запрещён.'))return;const d=await api('/api/admins/'+id,'DELETE');if(d.error){toast(d.error,true);return;}toast('Профиль удалён');loadAdmins();}
async function createAdmin(e){e.preventDefault();const f=new FormData(e.target);const body=Object.fromEntries(f.entries());body.admin_level=Number(body.admin_level);const d=await api('/api/admins','POST',body);if(d.error){toast(d.error,true);return;}toast('Профиль администратора создан');e.target.reset();closeModal('createModal');loadAdmins();}
async function loadRoles(){
  if(Number(ADMIN.level||0)<8)return;
  const d=await api('/api/roles');if(!Array.isArray(d))return;
  let box=document.getElementById('rolesBox');if(!box){box=document.createElement('div');box.id='rolesBox';box.className='section';document.getElementById('page-admins').appendChild(box);}
  box.innerHTML=`<div class="sectionHead"><div><h2>Роли панели</h2><span class="muted">Максимальный уровень — 8. Роль удаляется только если на ней нет администраторов.</span></div></div><div class="roleCreate" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:15px"><input id="roleName" class="search" style="max-width:300px" placeholder="Название роли"><input id="roleLevel" class="search" style="max-width:140px" type="number" min="1" max="8" placeholder="Уровень"><button class="btn primary" onclick="createRole()">Создать роль</button></div><div style="display:grid;gap:8px">${d.map(r=>`<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 15px;border:1px solid var(--line);border-radius:14px;background:#ffffff04"><span><b>${esc(r.name)}</b> <span class="muted">· уровень ${r.level}</span></span>${r.level===8&&d.filter(x=>x.level===8).length<=1?'':`<button class="btn danger" onclick="deleteRole(${r.id})">Удалить</button>`}</div>`).join('')}</div>`;
}
async function createRole(){const name=document.getElementById('roleName')?.value.trim();const level=Number(document.getElementById('roleLevel')?.value);if(!name||level<1||level>8)return toast('Введите название и уровень 1–8',true);if(level>Number(ADMIN.level||0))return toast('Нельзя создать роль выше своего уровня',true);const d=await api('/api/roles','POST',{name,level,permissions:['view_status','view_stats']});if(d.error)return toast(d.error,true);toast('Роль создана');loadRoles();}
async function deleteRole(id){if(!confirm('Удалить роль панели?'))return;const d=await api('/api/roles/'+id,'DELETE');if(d.error)return toast(d.error,true);toast('Роль удалена');loadRoles();}

document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.navBtn').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));
  document.getElementById('menuBtn')?.addEventListener('click',openSidebar);document.getElementById('sidebarOverlay')?.addEventListener('click',closeSidebar);
  document.getElementById('refreshBtn')?.addEventListener('click',()=>{loadStatus(true);loadMine();});
  document.getElementById('statusBtn')?.addEventListener('click',async()=>{const d=await loadStatus(false);if(d){const m=document.getElementById('modalStats');m.innerHTML=`<div class="modalStat"><small>Discord</small><b>${fmtStatus(d.discord)}</b></div><div class="modalStat"><small>VK</small><b>${fmtStatus(d.vk)}</b></div><div class="modalStat"><small>Telegram</small><b>${fmtStatus(d.telegram)}</b></div><div class="modalStat"><small>Anti-Sliv</small><b>${fmtStatus(d.antiSliv?'online':'offline')}</b></div><div class="modalStat"><small>Ping</small><b>${d.ping==null?'—':esc(d.ping+' ms')}</b></div><div class="modalStat"><small>Uptime</small><b>${esc(fmtUptime(d.uptime))}</b></div>`;document.getElementById('statsModal').classList.add('open');}});
  document.getElementById('statsBtn')?.addEventListener('click',openStats);document.getElementById('closeStats')?.addEventListener('click',()=>closeModal('statsModal'));document.getElementById('closeCreate')?.addEventListener('click',()=>closeModal('createModal'));document.getElementById('statsModal')?.addEventListener('click',e=>{if(e.target.id==='statsModal')closeModal('statsModal')});document.getElementById('createModal')?.addEventListener('click',e=>{if(e.target.id==='createModal')closeModal('createModal')});
  document.getElementById('openCreate')?.addEventListener('click',()=>document.getElementById('createModal').classList.add('open'));document.getElementById('createForm')?.addEventListener('submit',createAdmin);document.getElementById('adminSearch')?.addEventListener('input',renderAdmins);
  loadMine();
});
window.showPage=showPage;window.deleteAdmin=deleteAdmin;window.createAdmin=createAdmin;window.deleteRole=deleteRole;window.createRole=createRole;
