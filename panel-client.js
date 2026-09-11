
const myLevel = Number(document.body.dataset.myLevel || 0);

function toggleSidebar(ev){if(ev)ev.stopPropagation();document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('open');}
function closeSidebar(){document.getElementById('sidebar')?.classList.remove('open');document.getElementById('sidebarOverlay')?.classList.remove('open');}
function showTab(name, ev) {
  const target=document.getElementById('tab-' + name);
  if(!target){if(typeof showToast==='function')showToast('Раздел недоступен',true);return false;}
  document.querySelectorAll('[id^=tab-]').forEach(el => el.classList.add('hidden'));
  target.classList.remove('hidden');
  document.querySelectorAll('.sideItem').forEach(t => t.classList.toggle('active', t.dataset.tab===name));
  closeSidebar();
  if(ev && ev.currentTarget) ev.currentTarget.blur?.();
  try { window.scrollTo({top:0,behavior:'smooth'}); } catch(_) { window.scrollTo(0,0); }
  try {
    if (name === 'admins') loadAdmins();
    if (name === 'roles') loadRoles();
    if (name === 'logs') { loadLogs(); loadActions(); }
    if (name === 'antisliv') loadAntiSliv();
    if (name === 'ipbans') loadIpBans();
    if (name === 'users') loadUsers();
    if (name === 'droles') loadDiscordRoles();
  } catch(e){showToast('Не удалось открыть раздел',true);console.error(e);}
}

async function api(url, method='GET', body=null) {
  try {
    const opts = { method, headers: {'Content-Type':'application/json','Accept':'application/json'}, credentials:'include' };
    if (body !== null) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    const text = await res.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch { data = {error:text || 'Сервер вернул некорректный ответ'}; }
    if(res.status===401){showToast('Сессия закончилась. Войдите снова.',true);setTimeout(()=>location.href='/login',700);return {error:'Не авторизован'};}
    if(!res.ok && !data.error) data.error='Ошибка запроса ('+res.status+')';
    return data;
  } catch(e){ console.error(e); showToast('Нет соединения с сервером',true); return {error:'Нет соединения с сервером'}; }
}

// Единый ripple-эффект и обработка Enter для быстрых форм.
document.addEventListener('click',function(e){const b=e.target.closest('button');if(!b||b.disabled)return;const r=document.createElement('span');r.className='ripple';const rect=b.getBoundingClientRect();const size=Math.max(rect.width,rect.height);r.style.width=r.style.height=size+'px';r.style.left=(e.clientX-rect.left-size/2)+'px';r.style.top=(e.clientY-rect.top-size/2)+'px';b.appendChild(r);setTimeout(()=>r.remove(),600);});

async function getStatus() {
  document.getElementById('result').textContent = JSON.stringify(await api('/api/status'), null, 2);
}
async function toggleAntiSliv() {
  document.getElementById('result').textContent = JSON.stringify(await api('/api/antisliv/toggle','POST'), null, 2);
}
async function restartBot() {
  if (!confirm('Точно перезапустить бота?')) return;
  document.getElementById('result').textContent = JSON.stringify(await api('/api/restart','POST'), null, 2);
}
async function getStats() {
  document.getElementById('result').textContent = JSON.stringify(await api('/api/stats'), null, 2);
}

async function loadAntiSliv() {
  const d = await api('/api/antisliv/settings');
  document.getElementById('maxAttempts').value = d.maxAttempts;
  document.getElementById('protectedRoles').value = (d.protectedRoles||[]).join(', ');
  document.getElementById('allowedRoles').value = (d.allowedRoles||[]).join(', ');
  document.getElementById('allowedUsers').value = (d.allowedUsers||[]).join(', ');
  document.getElementById('commandAccessRoles').value = (d.commandAccessRoles||[]).join(', ');
  document.getElementById('resetRole').value = d.resetAttemptsRoleId || '';
}
async function saveAntiSliv() {
  const body = {
    maxAttempts: document.getElementById('maxAttempts').value,
    protectedRoles: document.getElementById('protectedRoles').value.split(',').map(s=>s.trim()).filter(Boolean),
    allowedRoles: document.getElementById('allowedRoles').value.split(',').map(s=>s.trim()).filter(Boolean),
    allowedUsers: document.getElementById('allowedUsers').value.split(',').map(s=>s.trim()).filter(Boolean),
    commandAccessRoles: document.getElementById('commandAccessRoles').value.split(',').map(s=>s.trim()).filter(Boolean),
    resetAttemptsRoleId: document.getElementById('resetRole').value.trim()
  };
  const res = await api('/api/antisliv/settings','POST',body);
  alert(res.message || 'Сохранено');
}

async function loadAdmins() {
  const data = await api('/api/admins');
  if (!Array.isArray(data)) { showToast(data.error || 'Не удалось загрузить админов', true); return; }
  const roles = await api('/api/roles');
  if (!Array.isArray(roles)) { showToast(roles.error || 'Не удалось загрузить роли', true); return; }
  let html = '<table><tr><th>Логин</th><th>Роль</th><th>Уровень</th><th>Действия</th></tr>';
  data.forEach(a => {
    html += `<tr><td>${a.username}</td><td>${a.role_name||'—'}</td><td>${a.level||0}</td><td>
      <select onchange="changeRole(${a.id},this.value)"><option value="">Сменить роль</option></select>
      ${myLevel > (a.level||0) ? `<button class="red" onclick="deleteAdmin(${a.id})">Удалить</button>` : ''}
    </td></tr>`;
  });
  html += '</table>';
  document.getElementById('adminsList').innerHTML = html;
  document.querySelectorAll('#adminsList select').forEach(sel => {
    roles.forEach(r => {
      const o = document.createElement('option');
      o.value = r.id; o.textContent = r.name + ' (' + r.level + ')';
      sel.appendChild(o);
    });
  });
  const ns = document.getElementById('newRole');
  ns.innerHTML = '';
  roles.forEach(r => {
    const o = document.createElement('option');
    o.value = r.id; o.textContent = r.name + ' (' + r.level + ')';
    ns.appendChild(o);
  });
}
async function createAdmin() {
  const res = await api('/api/admins','POST',{
    username: document.getElementById('newUser').value,
    password: document.getElementById('newPass').value,
    role_id: document.getElementById('newRole').value
  });
  alert(res.message || res.error); loadAdmins();
}
async function changeRole(id, roleId) {
  if (!roleId) return;
  await api('/api/admins/'+id+'/role','POST',{role_id:roleId});
  loadAdmins();
}
async function deleteAdmin(id) {
  if (!confirm('Удалить админа?')) return;
  await api('/api/admins/'+id,'DELETE'); loadAdmins();
}

async function loadRoles() {
  const data = await api('/api/roles');
  if (!Array.isArray(data)) { showToast(data.error || 'Не удалось загрузить уровни', true); return; }
  let html = '<table><tr><th>Название</th><th>Уровень</th><th>Права</th><th></th></tr>';
  data.forEach(r => {
    const p = JSON.parse(r.permissions||'[]');
    html += '<tr><td>'+esc(r.name)+'</td><td>'+r.level+'</td><td>'+esc(p.join(', '))+'</td><td>'+(r.name !== 'Владелец' ? '<button class="red" onclick="deleteWebRole('+r.id+')">Удалить</button>' : '')+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('rolesList').innerHTML = html;
}
async function deleteWebRole(id){if(!confirm('Удалить роль?'))return;const r=await api('/api/roles/'+id,'DELETE');alert(r.message||r.error);loadRoles();}
async function createRole() {
  const permissions = [...document.querySelectorAll('#tab-roles input[type=checkbox]:checked')].map(c=>c.value);
  const res = await api('/api/roles','POST',{
    name: document.getElementById('roleName').value,
    level: document.getElementById('roleLevel').value,
    permissions
  });
  alert(res.message || res.error); loadRoles();
}

let cachedIpBans=[];
function renderIpBans(data){document.getElementById('ipBanCount').textContent=data.length;let html='';if(!data.length)html='<div class="empty">Заблокированных IP не найдено</div>';else{html='<table><tr><th>IP</th><th>Причина</th><th>Кто забанил</th><th>Дата</th><th>Действие</th></tr>';data.forEach(function(b){html+='<tr><td><span class="badge">'+esc(b.ip)+'</span></td><td>'+esc(b.reason||'—')+'</td><td>'+esc(b.banned_by||'—')+'</td><td>'+new Date(b.created_at).toLocaleString('ru')+'</td><td><button class="green" onclick="unbanIp('+b.id+')">🔓 Разбанить</button></td></tr>';});html+='</table>';}document.getElementById('ipBansList').innerHTML=html;}
function filterIpBans(){const q=(document.getElementById('ipBanSearch')?.value||'').toLowerCase();renderIpBans(cachedIpBans.filter(function(b){return [b.ip,b.reason,b.banned_by].some(function(x){return String(x||'').toLowerCase().includes(q);});}));}
async function loadIpBans(){try{const d=await api('/api/ipbans');if(!Array.isArray(d)){showToast(d.error||'Не удалось загрузить список IP',true);return;}cachedIpBans=d;renderIpBans(cachedIpBans);filterIpBans();}catch(e){showToast('Не удалось загрузить список IP',true);}}
async function banIp() {
  const res = await api('/api/ipbans','POST',{
    ip: document.getElementById('banIp').value.trim(),
    reason: document.getElementById('banReason').value.trim()
  });
  showToast(res.message || res.error || 'Готово', !res.message); loadIpBans();
}
async function unbanIp(id) {
  if (!confirm('Разбанить этот IP? Доступ к панели будет снова разрешён.')) return;
  const r=await api('/api/ipbans/'+id,'DELETE');
  showToast(r.message||'IP успешно разбанен');
  loadIpBans();
}

async function loadUsers(){ const d=await api('/api/users'); bridgeUsers=d.users||[]; renderUsers(); }
function renderUsers(){ const q=(document.getElementById('userSearch')?.value||'').toLowerCase(); const data=bridgeUsers.filter(u=>!q||[u.id,u.username,u.displayName,u.globalName].some(x=>String(x||'').toLowerCase().includes(q))); let html='<table><tr><th>Пользователь</th><th>ID</th><th>Статус</th><th>Роли</th><th>Действия</th></tr>'; data.forEach(u=>{ let roles=(u.roles||[]).slice(0,4).map(r=>'<span class="pill">'+esc(r.name)+'</span>').join('')||'—'; let actions='<button class="blue" onclick="openProfile(\''+u.id+'\')">Профиль</button>'; if(myLevel>=50&&!u.bot) actions+='<button class="red" onclick="kickUser(\''+u.id+'\',\''+esc(u.displayName||u.username).replace(/'/g,'&#39;')+'\')">Удалить</button>'; html+='<tr class="userrow"><td onclick="openProfile(\''+u.id+'\')"><img class="avatar" src="'+(u.avatar||'')+'" onerror="this.style.display=\'none\'"><b>'+esc(u.displayName||u.username)+'</b><div class="sub">@'+esc(u.username)+'</div></td><td>'+u.id+'</td><td>'+(u.bot?'🤖 Бот':'👤 Пользователь')+'</td><td>'+roles+'</td><td>'+actions+'</td></tr>'; }); html+='</table>'; document.getElementById('usersList').innerHTML=html; }
function esc(s){return String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
async function openProfile(id){ const r=await api('/api/users/'+id); if(r.error){alert(r.error);return;} const u=r.user, roles=r.roles||[]; document.querySelectorAll('[id^=tab-]').forEach(el=>el.classList.add('hidden')); document.getElementById('tab-profile').classList.remove('hidden'); let roleOpts=''; roles.forEach(x=>{roleOpts+='<label><input type="checkbox" class="urole" value="'+x.id+'" '+((u.roles||[]).some(rr=>rr.id===x.id)?'checked':'')+'> '+esc(x.name)+'</label>';}); const box=document.getElementById('profileBox'); box.innerHTML='<div class="card hero"><button class="ghost" onclick="showTab(\'users\', event)">← Назад</button><div class="profile" style="margin-top:20px"><img class="profileAvatar" src="'+(u.avatar||'')+'"><div><h2>'+esc(u.displayName||u.username)+'</h2><div class="sub">@'+esc(u.username)+' · '+u.id+'</div><div class="kv"><span>Создан</span><b>'+new Date(u.createdAt).toLocaleString('ru')+'</b></div><div class="kv"><span>Вступил</span><b>'+(u.joinedAt?new Date(u.joinedAt).toLocaleString('ru'):'—')+'</b></div><div class="kv"><span>Бот</span><b>'+(u.bot?'Да':'Нет')+'</b></div></div></div></div><div class="card"><h3>Редактирование профиля</h3><label>Никнейм<br><input id="editNick" value="'+esc(u.nickname||'')+'" maxlength="32"></label><h4>Роли</h4><div style="line-height:2">'+(roleOpts||'Нет ролей')+'</div><button class="green" onclick="saveUser(\''+u.id+'\')">💾 Сохранить изменения</button></div><div class="card dangerZone"><h3>Опасная зона</h3><p class="sub">Удаление пользователя = исключение с Discord-сервера.</p><button class="red" onclick="kickUser(\''+u.id+'\',\''+esc(u.displayName||u.username).replace(/'/g,'&#39;')+'\')">Удалить с сервера</button></div>'; }
async function saveUser(id){const roles=[...document.querySelectorAll('.urole:checked')].map(x=>x.value); const r=await api('/api/users/'+id,'PATCH',{nickname:document.getElementById('editNick').value,roles}); alert(r.message||r.error||'Готово'); openProfile(id);}
async function kickUser(id,name){if(!confirm('Удалить '+name+' с сервера?'))return;const r=await api('/api/users/'+id,'DELETE');alert(r.message||r.error);loadUsers();}
async function loadDiscordRoles(){const d=await api('/api/discord-roles');bridgeDiscordRoles=d.roles||[];let h='<table><tr><th>Роль</th><th>ID</th><th>Участников</th><th>Цвет</th><th></th></tr>';bridgeDiscordRoles.forEach(r=>{let act=(!r.managed&&r.id!=='@everyone')?'<button class="red" onclick="deleteDiscordRole(\''+r.id+'\')">Удалить</button>':'';h+='<tr><td><b>'+esc(r.name)+'</b></td><td>'+r.id+'</td><td>'+(r.members||0)+'</td><td>'+esc(r.color||'—')+'</td><td>'+act+'</td></tr>';});h+='</table>';document.getElementById('drolesList').innerHTML=h;}
async function createDiscordRole(){const r=await api('/api/discord-roles','POST',{name:document.getElementById('droleName').value,color:document.getElementById('droleColor').value,hoist:document.getElementById('droleHoist').checked});alert(r.message||r.error);loadDiscordRoles();}
async function deleteDiscordRole(id){if(!confirm('Удалить роль Discord?'))return;const r=await api('/api/discord-roles/'+id,'DELETE');alert(r.message||r.error);loadDiscordRoles();}

let cachedLoginLogs=[]; let cachedActionLogs=[];
function escHtml(v){return String(v??'').replace(/[&<>'"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c];});}
function showToast(message,bad){const old=document.querySelector('.toast');if(old)old.remove();const t=document.createElement('div');t.className='toast'+(bad?' bad':'');t.textContent=message;document.body.appendChild(t);setTimeout(function(){t.remove();},3200);}
function filterLogs(){const q=(document.getElementById('logSearch')?.value||'').toLowerCase();const type=document.getElementById('logType')?.value||'all';const cards=document.querySelectorAll('#tab-logs .card');if(cards[1])cards[1].style.display=type==='action'?'none':'block';if(cards[2])cards[2].style.display=type==='login'?'none':'block';renderLoginLogs(cachedLoginLogs.filter(function(x){return JSON.stringify(x).toLowerCase().includes(q);}));renderActionLogs(cachedActionLogs.filter(function(x){return JSON.stringify(x).toLowerCase().includes(q);}));}
function renderLoginLogs(data){document.getElementById('loginCount').textContent=data.length;let html='';if(!data.length)html='<div class="empty">Нет записей по заданному фильтру</div>';else data.forEach(function(l,i){html+='<div class="log-row" style="animation-delay:'+(Math.min(i,12)*.025)+'s"><div><div class="log-time">'+new Date(l.created_at).toLocaleString('ru')+'</div><div class="log-ip">'+escHtml(l.ip||'—')+'</div></div><div class="log-main"><div class="log-title"><span class="status-dot '+(l.success?'':'bad')+'"></span>'+escHtml(l.username||'—')+' <span class="badge">'+(l.success?'Успешный вход':'Ошибка входа')+'</span></div><div class="log-details" title="'+escHtml(l.user_agent||'')+'">'+escHtml(l.user_agent||'Устройство не определено')+'</div></div><div class="'+(l.success?'success':'fail')+'">'+(l.success?'OK':'FAIL')+'</div></div>';});document.getElementById('logsList').innerHTML=html;}
function renderActionLogs(data){document.getElementById('actionCount').textContent=data.length;let html='';if(!data.length)html='<div class="empty">Нет записей по заданному фильтру</div>';else data.forEach(function(a,i){html+='<div class="log-row" style="animation-delay:'+(Math.min(i,12)*.025)+'s"><div><div class="log-time">'+new Date(a.created_at).toLocaleString('ru')+'</div><div class="log-ip">'+escHtml(a.ip||'—')+'</div></div><div class="log-main"><div class="log-title"><span class="status-dot"></span>'+escHtml(a.action||'СОБЫТИЕ')+' <span class="badge">'+escHtml(a.username||'system')+'</span></div><div class="log-details" title="'+escHtml(a.details||'')+'">'+escHtml(a.details||'Без деталей')+'</div></div><div class="sub">ACTION</div></div>';});document.getElementById('actionsList').innerHTML=html;}
async function loadLogs(){try{cachedLoginLogs=await api('/api/logs');renderLoginLogs(cachedLoginLogs);filterLogs();}catch(e){showToast('Не удалось загрузить логи входов',true);}}
async function loadActions(){try{cachedActionLogs=await api('/api/actions');renderActionLogs(cachedActionLogs);filterLogs();}catch(e){showToast('Не удалось загрузить логи действий',true);}}
window.toggleSidebar=toggleSidebar; window.closeSidebar=closeSidebar; window.showTab=showTab;
window.getStatus=getStatus; window.toggleAntiSliv=toggleAntiSliv; window.restartBot=restartBot; window.getStats=getStats;
window.saveAntiSliv=saveAntiSliv; window.createAdmin=createAdmin; window.deleteAdmin=deleteAdmin; window.createRole=createRole; window.deleteWebRole=deleteWebRole;
window.banIp=banIp; window.unbanIp=unbanIp; window.loadIpBans=loadIpBans; window.filterIpBans=filterIpBans;
window.loadUsers=loadUsers; window.renderUsers=renderUsers; window.openProfile=openProfile; window.saveUser=saveUser; window.kickUser=kickUser; window.changeRole=changeRole; window.loadAdmins=loadAdmins; window.loadRoles=loadRoles; window.loadAntiSliv=loadAntiSliv;
window.loadDiscordRoles=loadDiscordRoles; window.createDiscordRole=createDiscordRole; window.deleteDiscordRole=deleteDiscordRole;
window.loadLogs=loadLogs; window.loadActions=loadActions; window.filterLogs=filterLogs; window.showToast=showToast;
window.addEventListener('error', function(e){ console.error('[PANEL JS]', e.error || e.message); try{showToast('Ошибка интерфейса: '+(e.message||'неизвестная ошибка'), true);}catch(_){} });
window.addEventListener('unhandledrejection', function(e){ console.error('[PANEL Promise]', e.reason); try{showToast('Ошибка операции. Проверьте соединение и права.', true);}catch(_){} });

// Fallback event delegation: avoids relying on inline onclick handlers on mobile browsers.
document.addEventListener('click', function (e) {
  const nav = e.target.closest('.sideItem[data-tab]');
  if (nav) {
    e.preventDefault();
    e.stopPropagation();
    showTab(nav.dataset.tab);
    return;
  }
  const menu = e.target.closest('.menuBtn');
  if (menu) {
    e.preventDefault();
    toggleSidebar();
  }
}, true);

// iOS/Android touch fallback for buttons/links.
document.addEventListener('touchend', function (e) {
  const nav = e.target.closest('.sideItem[data-tab]');
  if (nav) {
    e.preventDefault();
    showTab(nav.dataset.tab);
  }
}, {passive:false});

showTab('main');
