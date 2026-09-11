require('dotenv').config({ path: '/home/container/.env' });
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

(async () => {
  const db = await open({ filename: process.env.PANEL_DB || 'panel.sqlite', driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS daily_attempts (user_id TEXT PRIMARY KEY, date TEXT, count INTEGER);
  `);
// ============================================================
// ====================== WEB PANEL ===========================
// ============================================================

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');

const app = express();
const WEB_PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'смени_этот_пароль';
const SESSION_SECRET = process.env.SESSION_SECRET || 'смени_этот_секрет_тоже';
const PANEL_BRIDGE_SECRET = process.env.PANEL_BRIDGE_SECRET || '';
let bridgeState = null;
let bridgeSettings = null;
let bridgeStats = null;
let nextCommandId = 1;
const commandQueue = [];

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}
function queueCommand(type, payload) {
    const cmd = { id: `${Date.now()}-${nextCommandId++}`, type, payload: payload || {}, createdAt: Date.now() };
    commandQueue.push(cmd);
    while (commandQueue.length > 100) commandQueue.shift();
    return cmd;
}
function checkBridgeSecret(req, res) {
    if (!PANEL_BRIDGE_SECRET || req.headers['x-panel-secret'] !== PANEL_BRIDGE_SECRET) {
        res.status(401).json({ error: 'Unauthorized' }); return false;
    }
    return true;
}

app.post('/bridge/poll', (req, res) => {
    if (!checkBridgeSecret(req, res)) return;
    const body = req.body || {};
    if (body.state) bridgeState = body.state;
    if (body.settings) bridgeSettings = body.settings;
    if (body.stats) bridgeStats = body.stats;
    const commands = commandQueue.splice(0, commandQueue.length);
    res.json({ commands });
});


app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// ---------- Таблицы ----------
await db.exec(`
CREATE TABLE IF NOT EXISTS web_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    permissions TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS web_admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES web_roles(id)
);

CREATE TABLE IF NOT EXISTS web_logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip TEXT,
    user_agent TEXT,
    success INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS web_ip_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT,
    banned_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS web_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    details TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// Базовые роли
const rolesCount = await db.get(`SELECT COUNT(*) as c FROM web_roles`);
if (rolesCount.c === 0) {
    await db.run(`INSERT INTO web_roles (name, level, permissions) VALUES 
        ('Владелец', 100, ?),
        ('Админ', 50, ?),
        ('Модератор', 10, ?)`,
        [
            JSON.stringify(['view_status','toggle_antisliv','restart_bot','view_logs','manage_admins','manage_roles','view_stats','manage_ipbans']),
            JSON.stringify(['view_status','toggle_antisliv','view_logs','view_stats']),
            JSON.stringify(['view_status','view_logs'])
        ]
    );
}

// Главный админ
const mainAdmin = await db.get(`SELECT * FROM web_admins WHERE username = ?`, [ADMIN_USERNAME]);
if (!mainAdmin) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    const ownerRole = await db.get(`SELECT id FROM web_roles WHERE name = 'Владелец'`);
    await db.run(`INSERT INTO web_admins (username, password_hash, role_id) VALUES (?, ?, ?)`, 
        [ADMIN_USERNAME, hash, ownerRole.id]);
    console.log('[WEB] Главный админ создан');
}

// ---------- Анти-DDoS + Бан IP ----------
const rateLimitMap = new Map();

function checkRateLimit(key, limit = 40, windowMs = 60000) {
    const now = Date.now();
    const data = rateLimitMap.get(key) || { count: 0, last: now };
    if (now - data.last > windowMs) {
        data.count = 1;
        data.last = now;
    } else {
        data.count++;
    }
    rateLimitMap.set(key, data);
    return data.count <= limit;
}

setInterval(() => {
    const now = Date.now();
    for (const [key, data] of rateLimitMap) {
        if (now - data.last > 300000) rateLimitMap.delete(key);
    }
}, 300000);

async function isIpBanned(ip) {
    const ban = await db.get(`SELECT id FROM web_ip_bans WHERE ip = ?`, [ip]);
    return !!ban;
}

app.use(async (req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

    if (await isIpBanned(ip)) {
        return res.status(403).send(`<h1 style="color:#ef4444;text-align:center;margin-top:120px">Ваш IP заблокирован</h1>`);
    }

    if (!checkRateLimit(ip, 45, 60000)) {
        return res.status(429).send(`<h1 style="color:#f59e0b;text-align:center;margin-top:120px">Слишком много запросов</h1>`);
    }

    if (req.path === '/login' && req.method === 'POST') {
        if (!checkRateLimit(ip + '_login', 7, 300000)) {
            return res.status(429).send(`<h1 style="color:#ef4444;text-align:center;margin-top:120px">Слишком много попыток входа</h1>`);
        }
    }

    next();
});

// ---------- Helpers ----------
async function getAdminWithRole(username) {
    return await db.get(`
        SELECT a.*, r.name as role_name, r.level, r.permissions
        FROM web_admins a
        LEFT JOIN web_roles r ON a.role_id = r.id
        WHERE a.username = ?
    `, [username]);
}

function hasPermission(admin, perm) {
    if (!admin) return false;
    if (admin.level >= 100) return true;
    try {
        return JSON.parse(admin.permissions || '[]').includes(perm);
    } catch { return false; }
}

function requireAdmin(req, res, next) {
    if (req.session?.isAdmin) return next();
    return res.redirect('/login');
}

function requirePermission(perm) {
    return async (req, res, next) => {
        if (!req.session?.isAdmin) return res.status(401).json({ error: 'Не авторизован' });
        const admin = await getAdminWithRole(req.session.username);
        if (!admin || !hasPermission(admin, perm)) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
        req.admin = admin;
        next();
    };
}

async function logAction(username, action, details, ip) {
    try {
        await db.run(`INSERT INTO web_actions (username, action, details, ip) VALUES (?, ?, ?, ?)`,
            [username, action, details || '', ip || '']);
    } catch (e) {}
}

async function logLogin(username, ip, userAgent, success) {
    try {
        await db.run(`INSERT INTO web_logins (username, ip, user_agent, success) VALUES (?, ?, ?, ?)`,
            [username, ip, userAgent, success ? 1 : 0]);
    } catch (e) {}
}

// ---------- LOGIN ----------
app.get('/login', (req, res) => {
    if (req.session?.isAdmin) return res.redirect('/');
    res.send(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>Вход</title>
<style>body{font-family:system-ui;background:#0f0f13;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#1a1a22;padding:40px;border-radius:16px;width:340px}input{width:100%;padding:12px;margin:8px 0;border:none;border-radius:8px;background:#111;color:#fff;box-sizing:border-box}
button{width:100%;padding:14px;margin-top:15px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer}</style></head>
<body><form method="POST" action="/login"><h2 style="text-align:center;margin:0 0 25px">Вход в панель</h2>
<input name="username" placeholder="Логин" required autocomplete="username">
<input name="password" type="password" placeholder="Пароль" required autocomplete="current-password">
<button type="submit">Войти</button></form></body></html>`);
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const ua = req.headers['user-agent'] || '';

    const admin = await getAdminWithRole(username);
    if (admin && await bcrypt.compare(password, admin.password_hash)) {
        req.session.isAdmin = true;
        req.session.username = username;
        await logLogin(username, ip, ua, true);
        await logAction(username, 'LOGIN_SUCCESS', 'Успешный вход', ip);
        return res.redirect('/');
    }

    await logLogin(username || 'unknown', ip, ua, false);
    await logAction(username || 'unknown', 'LOGIN_FAIL', 'Неудачная попытка входа', ip);
    res.send(`<h2 style="color:#ef4444;text-align:center;margin-top:100px">Неверный логин или пароль</h2>
              <p style="text-align:center"><a href="/login" style="color:#3b82f6">Попробовать снова</a></p>`);
});

app.get('/logout', async (req, res) => {
    const username = req.session?.username || 'unknown';
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await logAction(username, 'LOGOUT', 'Выход из панели', ip);
    req.session.destroy();
    res.redirect('/login');
});

// ---------- ГЛАВНАЯ ПАНЕЛЬ ----------
app.get('/', requireAdmin, async (req, res) => {
    const admin = await getAdminWithRole(req.session.username);
    const perms = admin ? JSON.parse(admin.permissions || '[]') : [];

    res.send(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Панель управления</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f0f13;color:#e5e7eb;margin:0;padding:20px}
.container{max-width:1150px;margin:0 auto}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.card{background:#1a1a22;padding:20px;border-radius:14px;margin-bottom:18px;border:1px solid #2a2a35}
h1{margin:0;font-size:1.6rem}h3{margin:0 0 14px}
button{padding:9px 16px;margin:4px;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500}
.green{background:#22c55e;color:#000}.red{background:#ef4444;color:#fff}
.blue{background:#3b82f6;color:#fff}.gray{background:#374151;color:#fff}.purple{background:#8b5cf6;color:#fff}
pre{background:#111;padding:16px;border-radius:10px;overflow:auto;font-size:13px;line-height:1.45}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #2e2e3a}
th{color:#9ca3af;font-weight:600}
input,select{padding:9px 12px;border-radius:8px;border:1px solid #333;background:#111;color:#fff;margin:4px 0}
.badge{display:inline-block;padding:3px 11px;border-radius:20px;font-size:12px;background:#3b82f6}
.tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.tab{padding:10px 18px;background:#1a1a22;border-radius:10px;cursor:pointer;border:1px solid #2a2a35}
.tab.active{background:#3b82f6;border-color:#3b82f6}
.hidden{display:none}
.success{color:#22c55e}.fail{color:#ef4444}
label{margin-right:14px;font-size:14px}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>🛠 Панель бота</h1>
      <div style="margin-top:6px;opacity:.85">Вы: <b>${admin.username}</b> · <span class="badge">${admin.role_name || 'Без роли'}</span> (ур. ${admin.level || 0})</div>
    </div>
    <a href="/logout"><button class="gray">Выйти</button></a>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="showTab('main', event)">Главная</div>
    ${hasPermission(admin,'toggle_antisliv') ? '<div class="tab" onclick="showTab(\'antisliv\')">Anti-Sliv</div>' : ''}
    ${hasPermission(admin,'manage_admins') ? '<div class="tab" onclick="showTab(\'admins\')">Админы</div>' : ''}
    ${hasPermission(admin,'manage_roles') ? '<div class="tab" onclick="showTab(\'roles\')">Уровни</div>' : ''}
    ${hasPermission(admin,'manage_ipbans') || hasPermission(admin,'manage_admins') ? '<div class="tab" onclick="showTab(\'ipbans\')">Баны IP</div>' : ''}
    ${hasPermission(admin,'view_logs') ? '<div class="tab" onclick="showTab(\'logs\')">Логи</div>' : ''}
  </div>

  <!-- ГЛАВНАЯ -->
  <div id="tab-main">
    <div class="card">
      <h3>Управление</h3>
      ${hasPermission(admin,'view_status') ? '<button class="blue" onclick="getStatus()">⚡ Статус</button>' : ''}
      ${hasPermission(admin,'toggle_antisliv') ? '<button class="green" onclick="toggleAntiSliv()">🛡 Anti-Sliv</button>' : ''}
      ${hasPermission(admin,'restart_bot') ? '<button class="red" onclick="restartBot()">🔄 Рестарт</button>' : ''}
      ${hasPermission(admin,'view_stats') ? '<button class="purple" onclick="getStats()">📊 Статистика</button>' : ''}
    </div>
    <div class="card"><h3>Результат</h3><pre id="result">Выберите действие</pre></div>
  </div>

  <!-- ANTI-SLIV -->
  <div id="tab-antisliv" class="hidden">
    <div class="card">
      <h3>Настройки Anti-Sliv</h3>
      <div style="margin:10px 0"><label>Лимит попыток:</label><br><input type="number" id="maxAttempts" min="1" max="100" style="width:120px"></div>
      <div style="margin:10px 0"><label>Защищаемые роли (ID через запятую, пусто = все):</label><br><input id="protectedRoles" style="width:100%"></div>
      <div style="margin:10px 0"><label>Разрешённые роли (могут выдавать):</label><br><input id="allowedRoles" style="width:100%"></div>
      <div style="margin:10px 0"><label>Пользователи-исключения:</label><br><input id="allowedUsers" style="width:100%"></div>
      <div style="margin:10px 0"><label>Роли с доступом к командам:</label><br><input id="commandAccessRoles" style="width:100%"></div>
      <div style="margin:10px 0"><label>Роль /сброспопыток:</label><br><input id="resetRole" style="width:100%"></div>
      <button class="green" onclick="saveAntiSliv()">💾 Сохранить</button>
    </div>
  </div>

  <!-- АДМИНЫ -->
  <div id="tab-admins" class="hidden">
    <div class="card">
      <h3>Создать админа</h3>
      <input id="newUser" placeholder="Логин">
      <input id="newPass" type="password" placeholder="Пароль">
      <select id="newRole"></select>
      <button class="green" onclick="createAdmin()">Создать</button>
    </div>
    <div class="card"><h3>Список админов</h3><div id="adminsList"></div></div>
  </div>

  <!-- УРОВНИ -->
  <div id="tab-roles" class="hidden">
    <div class="card">
      <h3>Создать уровень</h3>
      <input id="roleName" placeholder="Название">
      <input id="roleLevel" type="number" placeholder="Уровень (1-99)" style="width:140px">
      <div style="margin:14px 0;line-height:2">
        <label><input type="checkbox" value="view_status"> Статус</label>
        <label><input type="checkbox" value="toggle_antisliv"> Anti-Sliv</label>
        <label><input type="checkbox" value="restart_bot"> Рестарт</label>
        <label><input type="checkbox" value="view_logs"> Логи</label>
        <label><input type="checkbox" value="manage_admins"> Админы</label>
        <label><input type="checkbox" value="manage_roles"> Уровни</label>
        <label><input type="checkbox" value="view_stats"> Статистика</label>
        <label><input type="checkbox" value="manage_ipbans"> Баны IP</label>
      </div>
      <button class="green" onclick="createRole()">Создать уровень</button>
    </div>
    <div class="card"><h3>Существующие уровни</h3><div id="rolesList"></div></div>
  </div>

  <!-- БАНЫ IP -->
  <div id="tab-ipbans" class="hidden">
    <div class="card">
      <h3>Забанить IP</h3>
      <input id="banIp" placeholder="IP адрес">
      <input id="banReason" placeholder="Причина">
      <button class="red" onclick="banIp()">Забанить</button>
    </div>
    <div class="card">
      <h3>Забаненные IP</h3>
      <button class="blue" onclick="loadIpBans()">Обновить</button>
      <div id="ipBansList" style="margin-top:14px"></div>
    </div>
  </div>

  <!-- ЛОГИ -->
  <div id="tab-logs" class="hidden">
    <div class="card">
      <h3>Логи входов</h3>
      <button class="blue" onclick="loadLogs()">Обновить логи входов</button>
      <div id="logsList" style="margin-top:14px"></div>
    </div>
    <div class="card">
      <h3>Логи действий</h3>
      <button class="blue" onclick="loadActions()">Обновить логи действий</button>
      <div id="actionsList" style="margin-top:14px"></div>
    </div>
  </div>
</div>

<script>
const myLevel = ${admin.level || 0};

function showTab(name, ev) {
  document.querySelectorAll('[id^=tab-]').forEach(el => el.classList.add('hidden'));
  document.getElementById('tab-' + name).classList.remove('hidden');
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  if (ev && ev.currentTarget) ev.currentTarget.classList.add('active');
  if (name === 'admins') loadAdmins();
  if (name === 'roles') loadRoles();
  if (name === 'logs') { loadLogs(); loadActions(); }
  if (name === 'antisliv') loadAntiSliv();
  if (name === 'ipbans') loadIpBans();
}

async function api(url, method='GET', body=null) {
  const opts = { method, headers: {'Content-Type':'application/json'}, credentials:'include' };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  return res.json();
}

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
  const roles = await api('/api/roles');
  let html = '<table><tr><th>Логин</th><th>Роль</th><th>Уровень</th><th>Действия</th></tr>';
  data.forEach(a => {
    html += \`<tr><td>\${a.username}</td><td>\${a.role_name||'—'}</td><td>\${a.level||0}</td><td>
      <select onchange="changeRole(\${a.id},this.value)"><option value="">Сменить роль</option></select>
      \${myLevel > (a.level||0) ? \`<button class="red" onclick="deleteAdmin(\${a.id})">Удалить</button>\` : ''}
    </td></tr>\`;
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
  let html = '<table><tr><th>Название</th><th>Уровень</th><th>Права</th></tr>';
  data.forEach(r => {
    const p = JSON.parse(r.permissions||'[]');
    html += \`<tr><td>\${r.name}</td><td>\${r.level}</td><td>\${p.join(', ')}</td></tr>\`;
  });
  html += '</table>';
  document.getElementById('rolesList').innerHTML = html;
}
async function createRole() {
  const permissions = [...document.querySelectorAll('#tab-roles input[type=checkbox]:checked')].map(c=>c.value);
  const res = await api('/api/roles','POST',{
    name: document.getElementById('roleName').value,
    level: document.getElementById('roleLevel').value,
    permissions
  });
  alert(res.message || res.error); loadRoles();
}

async function loadIpBans() {
  const data = await api('/api/ipbans');
  let html = '<table><tr><th>IP</th><th>Причина</th><th>Кто забанил</th><th>Дата</th><th></th></tr>';
  data.forEach(b => {
    html += \`<tr><td>\${b.ip}</td><td>\${b.reason||'—'}</td><td>\${b.banned_by}</td>
      <td>\${new Date(b.created_at).toLocaleString('ru')}</td>
      <td><button class="green" onclick="unbanIp(\${b.id})">Разбанить</button></td></tr>\`;
  });
  html += '</table>';
  document.getElementById('ipBansList').innerHTML = html;
}
async function banIp() {
  const res = await api('/api/ipbans','POST',{
    ip: document.getElementById('banIp').value.trim(),
    reason: document.getElementById('banReason').value.trim()
  });
  alert(res.message || res.error); loadIpBans();
}
async function unbanIp(id) {
  if (!confirm('Разбанить IP?')) return;
  await api('/api/ipbans/'+id,'DELETE'); loadIpBans();
}

async function loadLogs() {
  const data = await api('/api/logs');
  let html = '<table><tr><th>Время</th><th>Логин</th><th>IP</th><th>Устройство / Браузер</th><th>Результат</th></tr>';
  data.forEach(l => {
    html += \`<tr>
      <td>\${new Date(l.created_at).toLocaleString('ru')}</td>
      <td>\${l.username||'—'}</td>
      <td>\${l.ip||'—'}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis" title="\${l.user_agent||''}">\${(l.user_agent||'—').substring(0,70)}</td>
      <td class="\${l.success?'success':'fail'}">\${l.success?'✅ Успех':'❌ Ошибка'}</td>
    </tr>\`;
  });
  html += '</table>';
  document.getElementById('logsList').innerHTML = html;
}

async function loadActions() {
  const data = await api('/api/actions');
  let html = '<table><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Детали</th><th>IP</th></tr>';
  data.forEach(a => {
    html += \`<tr>
      <td>\${new Date(a.created_at).toLocaleString('ru')}</td>
      <td>\${a.username||'—'}</td>
      <td>\${a.action}</td>
      <td>\${a.details||'—'}</td>
      <td>\${a.ip||'—'}</td>
    </tr>\`;
  });
  html += '</table>';
  document.getElementById('actionsList').innerHTML = html;
}
</script>
</body>
</html>`);
});

// ---------- API ----------
app.get('/api/status', requirePermission('view_status'), (req, res) => {
    res.json(bridgeState || { discord:'offline', vk:'offline', telegram:'offline', antiSliv:false, ping:null, uptime:0, members:0, maxAttempts:0 });
});

app.post('/api/antisliv/toggle', requirePermission('toggle_antisliv'), async (req, res) => {
    const cmd = queueCommand('toggle_antisliv', {});
    await logAction(req.session.username, 'TOGGLE_ANTISLIV', 'Запрошено переключение Anti-Sliv', getClientIp(req));
    res.json({ message: 'Команда отправлена боту', commandId: cmd.id });
});

app.post('/api/restart', requirePermission('restart_bot'), async (req, res) => {
    const cmd = queueCommand('restart_bot', {});
    await logAction(req.session.username, 'RESTART_BOT', 'Запрошен рестарт', getClientIp(req));
    res.json({ message: 'Команда на рестарт отправлена боту', commandId: cmd.id });
});

app.get('/api/stats', requirePermission('view_stats'), (req, res) => {
    res.json(bridgeStats || { date: '', limit: 0, attempts: [] });
});

app.get('/api/antisliv/settings', requirePermission('toggle_antisliv'), (req, res) => {
    res.json(bridgeSettings || { enabled:false, maxAttempts:0, protectedRoles:[], allowedRoles:[], allowedUsers:[], commandAccessRoles:[], resetAttemptsRoleId:'' });
});

app.post('/api/antisliv/settings', requirePermission('toggle_antisliv'), async (req, res) => {
    const cmd = queueCommand('update_antisliv_settings', req.body || {});
    await logAction(req.session.username, 'EDIT_ANTISLIV', 'Изменены настройки Anti-Sliv', getClientIp(req));
    res.json({ success: true, message: 'Настройки отправлены боту', commandId: cmd.id });
});

app.get('/api/logs', requirePermission('view_logs'), async (req, res) => {
    const rows = await db.all(`SELECT * FROM web_logins ORDER BY id DESC LIMIT 150`);
    res.json(rows);
});

app.get('/api/actions', requirePermission('view_logs'), async (req, res) => {
    const rows = await db.all(`SELECT * FROM web_actions ORDER BY id DESC LIMIT 150`);
    res.json(rows);
});

app.get('/api/admins', requirePermission('manage_admins'), async (req, res) => {
    const rows = await db.all(`
        SELECT a.id, a.username, r.name as role_name, r.level
        FROM web_admins a LEFT JOIN web_roles r ON a.role_id = r.id
        ORDER BY r.level DESC`);
    res.json(rows);
});

app.post('/api/admins', requirePermission('manage_admins'), async (req, res) => {
    const { username, password, role_id } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
    try {
        const hash = await bcrypt.hash(password, 10);
        await db.run(`INSERT INTO web_admins (username, password_hash, role_id) VALUES (?, ?, ?)`,
            [username, hash, role_id || null]);
        const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
        await logAction(req.session.username, 'CREATE_ADMIN', `Создан админ: ${username}`, ip);
        res.json({ message: 'Админ создан' });
    } catch {
        res.status(400).json({ error: 'Такой логин уже существует' });
    }
});

app.post('/api/admins/:id/role', requirePermission('manage_admins'), async (req, res) => {
    await db.run(`UPDATE web_admins SET role_id = ? WHERE id = ?`, [req.body.role_id, req.params.id]);
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await logAction(req.session.username, 'CHANGE_ROLE', `Сменена роль админа ID ${req.params.id}`, ip);
    res.json({ ok: true });
});

app.delete('/api/admins/:id', requirePermission('manage_admins'), async (req, res) => {
    await db.run(`DELETE FROM web_admins WHERE id = ?`, [req.params.id]);
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await logAction(req.session.username, 'DELETE_ADMIN', `Удалён админ ID ${req.params.id}`, ip);
    res.json({ ok: true });
});

app.get('/api/roles', requirePermission('manage_roles'), async (req, res) => {
    const rows = await db.all(`SELECT * FROM web_roles ORDER BY level DESC`);
    res.json(rows);
});

app.post('/api/roles', requirePermission('manage_roles'), async (req, res) => {
    const { name, level, permissions } = req.body;
    try {
        await db.run(`INSERT INTO web_roles (name, level, permissions) VALUES (?, ?, ?)`,
            [name, Number(level)||1, JSON.stringify(permissions||[])]);
        const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
        await logAction(req.session.username, 'CREATE_ROLE', `Создан уровень: ${name}`, ip);
        res.json({ message: 'Уровень создан' });
    } catch {
        res.status(400).json({ error: 'Ошибка создания уровня' });
    }
});

app.get('/api/ipbans', requirePermission('manage_ipbans'), async (req, res) => {
    const rows = await db.all(`SELECT * FROM web_ip_bans ORDER BY id DESC`);
    res.json(rows);
});

app.post('/api/ipbans', requirePermission('manage_ipbans'), async (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'Укажите IP' });
    try {
        await db.run(`INSERT INTO web_ip_bans (ip, reason, banned_by) VALUES (?, ?, ?)`,
            [ip.trim(), reason || 'Без причины', req.session.username]);
        await logAction(req.session.username, 'BAN_IP', `Забанен IP: ${ip}`, ip);
        res.json({ message: `IP ${ip} заблокирован` });
    } catch {
        res.status(400).json({ error: 'Этот IP уже забанен' });
    }
});

app.delete('/api/ipbans/:id', requirePermission('manage_ipbans'), async (req, res) => {
    await db.run(`DELETE FROM web_ip_bans WHERE id = ?`, [req.params.id]);
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await logAction(req.session.username, 'UNBAN_IP', `Разбанен ID ${req.params.id}`, ip);
    res.json({ ok: true });
});

app.listen(WEB_PORT, () => {
    console.log(`[WEB] Панель запущена на порту ${WEB_PORT}`);
});


})();
