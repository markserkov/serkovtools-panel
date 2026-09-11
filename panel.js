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
let bridgeUsers = [];
let bridgeDiscordRoles = [];
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
    if (Array.isArray(body.users)) bridgeUsers = body.users;
    if (Array.isArray(body.discordRoles)) bridgeDiscordRoles = body.discordRoles;
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
            JSON.stringify(['view_status','toggle_antisliv','restart_bot','view_logs','manage_admins','manage_roles','view_stats','manage_ipbans','view_users','edit_users','delete_users','manage_discord_roles']),
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

await db.run(`UPDATE web_roles SET permissions = ? WHERE name = 'Владелец'`, [JSON.stringify(['view_status','toggle_antisliv','restart_bot','view_logs','manage_admins','manage_roles','view_stats','manage_ipbans','view_users','edit_users','delete_users','manage_discord_roles'])]);
await db.run(`UPDATE web_roles SET permissions = ? WHERE name = 'Админ'`, [JSON.stringify(['view_status','toggle_antisliv','view_logs','view_stats','view_users','edit_users'])]);
await db.run(`UPDATE web_roles SET permissions = ? WHERE name = 'Модератор'`, [JSON.stringify(['view_status','view_logs','view_users'])]);

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
    res.send(`<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход — SerkovTools</title><style>
:root{--a:#8b5cf6;--b:#c026d3;--bg:#07050c;--text:#f8f5ff;--muted:#a59abf}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;overflow:hidden;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--text);background:radial-gradient(circle at 20% 15%,rgba(124,58,237,.32),transparent 32%),radial-gradient(circle at 85% 80%,rgba(192,38,211,.18),transparent 30%),var(--bg)}body:before{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(167,139,250,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(167,139,250,.035) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(#000,transparent 90%);pointer-events:none}.orb{position:fixed;width:320px;height:320px;border-radius:50%;filter:blur(70px);opacity:.22;background:#7c3aed;animation:drift 9s ease-in-out infinite}.orb.one{left:-100px;top:-80px}.orb.two{right:-120px;bottom:-120px;background:#c026d3;animation-delay:-3s}.loginWrap{width:min(440px,calc(100% - 28px));position:relative;z-index:2}.loginCard{padding:34px;border:1px solid rgba(196,181,253,.17);border-radius:28px;background:linear-gradient(145deg,rgba(27,18,48,.86),rgba(10,7,18,.88));box-shadow:0 30px 100px rgba(0,0,0,.48),0 0 70px rgba(124,58,237,.13);backdrop-filter:blur(24px);animation:enter .6s cubic-bezier(.2,.8,.2,1)}.brand{display:flex;align-items:center;gap:13px;margin-bottom:28px}.logo{width:56px;height:56px;display:grid;place-items:center;border-radius:18px;background:linear-gradient(135deg,#6366f1,#a855f7 55%,#d946ef);font-size:25px;box-shadow:0 0 40px rgba(139,92,246,.35);animation:float 4s ease-in-out infinite}.brand h1{font-size:24px;margin:0;letter-spacing:-.03em}.brand p{margin:4px 0 0;color:var(--muted);font-size:12px}.eyebrow{display:inline-flex;padding:6px 9px;border-radius:999px;background:rgba(139,92,246,.12);border:1px solid rgba(196,181,253,.13);color:#d8b4fe;font-size:10px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:10px}h2{margin:0 0 7px;font-size:25px}.desc{margin:0 0 24px;color:var(--muted);font-size:13px;line-height:1.5}.field{margin:13px 0}.field label{display:block;font-size:11px;color:#c8bedb;margin:0 0 7px}input{width:100%;padding:14px 15px;border-radius:14px;border:1px solid rgba(167,139,250,.17);background:rgba(5,3,11,.7);color:#fff;outline:none;font-size:14px;transition:.2s}input:focus{border-color:#8b5cf6;box-shadow:0 0 0 4px rgba(139,92,246,.1),0 0 25px rgba(139,92,246,.08);transform:translateY(-1px)}button{position:relative;overflow:hidden;width:100%;padding:14px;border:0;border-radius:14px;color:#fff;font-size:14px;font-weight:800;cursor:pointer;background:linear-gradient(135deg,#6366f1,#8b5cf6 55%,#c026d3);box-shadow:0 12px 30px rgba(124,58,237,.25);transition:transform .2s,filter .2s}button:hover{transform:translateY(-2px);filter:brightness(1.08)}.foot{margin-top:18px;text-align:center;color:#756b8e;font-size:10px}@keyframes enter{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:none}}@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}@keyframes drift{0%,100%{transform:translate(0,0)}50%{transform:translate(35px,-25px)}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body><div class="orb one"></div><div class="orb two"></div><main class="loginWrap"><section class="loginCard"><div class="brand"><div class="logo">⚡</div><div><h1>SerkovTools</h1><p>Центр управления сервером</p></div></div><span class="eyebrow">Secure access</span><h2>Добро пожаловать</h2><p class="desc">Войдите в административную панель, чтобы управлять сервером и его пользователями.</p><form method="POST" action="/login"><div class="field"><label>ЛОГИН</label><input name="username" placeholder="Введите логин" required autocomplete="username"></div><div class="field"><label>ПАРОЛЬ</label><input name="password" type="password" placeholder="Введите пароль" required autocomplete="current-password"></div><button type="submit">Войти в панель <span>→</span></button></form><div class="foot">SerkovTools • защищённая панель администратора</div></section></main></body></html>`);
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
<title>SerkovTools — Панель управления</title>
<style>
:root{--bg:#09070f;--panel:rgba(19,14,34,.72);--panel2:rgba(28,20,48,.72);--line:rgba(196,181,253,.14);--text:#f7f3ff;--muted:#9f96b8;--accent:#8b5cf6;--accent2:#c084fc;--good:#34d399;--bad:#fb7185;--warn:#fbbf24}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 15% -10%,rgba(124,58,237,.35),transparent 32%),radial-gradient(circle at 105% 15%,rgba(192,132,252,.18),transparent 28%),#09070f;color:var(--text);margin:0;min-height:100vh;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(167,139,250,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(167,139,250,.035) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,#000,transparent 85%);z-index:-1}
.container{max-width:1320px;margin:0 auto;padding:30px 22px 70px}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;gap:15px;animation:fadeUp .55s ease both}.brand{display:flex;align-items:center;gap:14px}.logo{width:52px;height:52px;border-radius:18px;background:linear-gradient(135deg,#6366f1,#a855f7 55%,#d946ef);display:grid;place-items:center;font-size:25px;box-shadow:0 0 40px rgba(139,92,246,.32);animation:float 5s ease-in-out infinite}h1{margin:0;font-size:1.6rem;letter-spacing:-.02em}h2,h3{margin-top:0}.sub{color:var(--muted);font-size:13px;margin-top:4px}.card{position:relative;background:linear-gradient(145deg,rgba(31,22,55,.78),rgba(13,10,24,.72));padding:21px;border-radius:22px;margin-bottom:18px;border:1px solid var(--line);box-shadow:0 18px 60px rgba(0,0,0,.24);backdrop-filter:blur(18px);animation:fadeUp .42s ease both;transition:transform .25s ease,border-color .25s ease,box-shadow .25s ease}.card:hover{border-color:rgba(196,181,253,.24);box-shadow:0 22px 70px rgba(0,0,0,.3)}.hero{padding:30px;background:linear-gradient(135deg,rgba(99,102,241,.18),rgba(168,85,247,.13) 55%,rgba(217,70,239,.08));border-color:rgba(196,181,253,.2)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat{padding:18px;border-radius:18px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.07);transition:transform .25s ease,background .25s ease}.stat:hover{transform:translateY(-4px);background:rgba(139,92,246,.08)}.stat b{display:block;font-size:27px;color:#d8b4fe}.stat span{font-size:12px;color:var(--muted)}
.tabs{display:flex;gap:8px;margin:18px 0 20px;flex-wrap:wrap;position:sticky;top:10px;z-index:20}.tab{padding:11px 16px;background:rgba(18,13,31,.78);border-radius:14px;cursor:pointer;border:1px solid rgba(196,181,253,.12);transition:all .25s cubic-bezier(.2,.8,.2,1);backdrop-filter:blur(16px);user-select:none}.tab:hover{transform:translateY(-2px);border-color:rgba(167,139,250,.45);background:rgba(38,25,64,.86)}.tab.active{background:linear-gradient(135deg,#6366f1,#a855f7);border-color:transparent;box-shadow:0 9px 30px rgba(124,58,237,.28);transform:translateY(-1px)}
button{padding:10px 15px;margin:4px;border:0;border-radius:12px;cursor:pointer;font-size:13px;font-weight:700;color:#fff;transition:transform .2s ease,filter .2s ease,box-shadow .2s ease;position:relative;overflow:hidden}button:after{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 25%,rgba(255,255,255,.14),transparent 75%);transform:translateX(-120%);transition:transform .55s ease}button:hover:after{transform:translateX(120%)}button:hover{transform:translateY(-2px);filter:brightness(1.08);box-shadow:0 8px 22px rgba(0,0,0,.2)}button{-webkit-tap-highlight-color:transparent;touch-action:manipulation}button:active{transform:translateY(0) scale(.98)}.green{background:linear-gradient(135deg,#059669,#10b981)}.red{background:linear-gradient(135deg,#be123c,#ef4444)}.blue{background:linear-gradient(135deg,#4f46e5,#7c3aed)}.gray{background:#29243b}.purple{background:linear-gradient(135deg,#7e22ce,#a855f7)}.cyan{background:linear-gradient(135deg,#0e7490,#06b6d4)}.ghost{background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.12)}
pre{background:#080611;padding:16px;border-radius:15px;overflow:auto;font-size:13px;line-height:1.5;border:1px solid rgba(255,255,255,.07)}table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px;overflow:hidden}th,td{padding:13px 11px;text-align:left;border-bottom:1px solid rgba(255,255,255,.065);vertical-align:middle}th{color:#a9a0bf;font-weight:650;text-transform:uppercase;font-size:10px;letter-spacing:.08em}tbody tr,.log-row{transition:background .2s ease,transform .2s ease}.userrow:hover,tbody tr:hover,.log-row:hover{background:rgba(139,92,246,.065)}
input,select,textarea{padding:11px 12px;border-radius:12px;border:1px solid rgba(167,139,250,.18);background:rgba(10,7,19,.78);color:#fff;margin:4px 0;outline:none;width:auto;transition:border-color .2s ease,box-shadow .2s ease,transform .2s ease}input:focus,select:focus,textarea:focus{border-color:#8b5cf6;box-shadow:0 0 0 4px rgba(139,92,246,.11);transform:translateY(-1px)}textarea{width:100%;min-height:90px}.badge{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:11px;background:rgba(139,92,246,.17);color:#d8b4fe;border:1px solid rgba(196,181,253,.14)}.online{color:var(--good)}.offline{color:var(--bad)}.success{color:var(--good);font-weight:700}.fail{color:var(--bad);font-weight:700}.hidden{display:none!important}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.search{width:min(390px,100%)}.profile{display:grid;grid-template-columns:120px 1fr;gap:22px}.profileAvatar{width:110px;height:110px;border-radius:30px;object-fit:cover;background:#2b2348;box-shadow:0 12px 40px rgba(0,0,0,.25)}.kv{display:grid;grid-template-columns:150px 1fr;gap:8px;margin:8px 0}.kv span:first-child{color:var(--muted)}.pill{display:inline-block;margin:3px;padding:5px 9px;border-radius:9px;background:rgba(99,102,241,.14);font-size:11px}.dangerZone{border-color:rgba(239,68,68,.28);background:linear-gradient(145deg,rgba(127,29,29,.14),rgba(20,10,18,.6))}
.log-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}.log-toolbar input{flex:1;min-width:190px}.log-list{display:grid;gap:9px}.log-row{display:grid;grid-template-columns:155px 1fr auto;gap:14px;align-items:center;padding:14px 15px;border:1px solid rgba(255,255,255,.065);border-radius:15px;background:rgba(255,255,255,.025);animation:logIn .32s ease both}.log-main{min-width:0}.log-title{font-weight:750;display:flex;gap:8px;align-items:center;flex-wrap:wrap}.log-details{color:var(--muted);font-size:12px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.log-time{font-size:11px;color:#9f96b8}.log-ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#c4b5fd}.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--good);box-shadow:0 0 12px rgba(52,211,153,.7)}.status-dot.bad{background:var(--bad);box-shadow:0 0 12px rgba(251,113,133,.6)}.empty{padding:35px;text-align:center;color:var(--muted);border:1px dashed rgba(196,181,253,.14);border-radius:16px}.toast{position:fixed;right:22px;bottom:22px;z-index:1000;min-width:240px;max-width:380px;padding:14px 16px;border:1px solid rgba(196,181,253,.18);border-radius:15px;background:rgba(20,14,34,.94);box-shadow:0 18px 55px rgba(0,0,0,.38);backdrop-filter:blur(18px);animation:toastIn .3s ease}.toast.bad{border-color:rgba(251,113,133,.3)}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}@keyframes logIn{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}@keyframes toastIn{from{opacity:0;transform:translateY(14px) scale(.97)}to{opacity:1;transform:none}}@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.log-row{grid-template-columns:1fr}.log-ip{text-align:left}}@media(max-width:800px){.profile{grid-template-columns:1fr}.kv{grid-template-columns:110px 1fr}table{display:block;overflow-x:auto;white-space:nowrap}.tabs{position:static}}@media(max-width:520px){.container{padding:18px 12px}.grid{grid-template-columns:1fr 1fr}.header{align-items:flex-start}.brand{align-items:flex-start}.logo{width:44px;height:44px}.toast{left:12px;right:12px;bottom:12px}}

/* ===== SerkovTools V5 responsive UI ===== */
html,body{width:100%;overflow-x:hidden}
body{font-size:15px;line-height:1.45}
.container{max-width:1280px;margin:0 auto;padding:24px 20px 72px}
.header{min-height:76px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:8px 0 22px}
.header .brand{min-width:0;display:flex;align-items:center;gap:12px}
.header .brand>div:last-child{min-width:0}
.header h1{font-size:clamp(1.35rem,4vw,2rem);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.header .sub{font-size:12px}
.headerActions{display:flex;align-items:center;gap:10px;flex-shrink:0}
.livePill{display:inline-flex;align-items:center;gap:7px;padding:9px 12px;border-radius:999px;background:rgba(52,211,153,.09);border:1px solid rgba(52,211,153,.18);font-size:12px;color:#c8f7df;white-space:nowrap}
.livePill i{width:7px;height:7px;border-radius:50%;background:#34d399;box-shadow:0 0 12px rgba(52,211,153,.8);animation:pulse 1.8s infinite}
.menuBtn{width:48px!important;height:48px!important;padding:0!important;margin:0!important;display:grid!important;place-items:center!important;font-size:22px!important;flex:0 0 48px!important;border-radius:15px!important}
.headerActions .gray{width:auto!important;margin:0!important;padding:11px 18px!important}
/* Off-canvas navigation */
.sidebarOverlay{position:fixed;inset:0;background:rgba(3,2,8,.62);backdrop-filter:blur(5px);opacity:0;visibility:hidden;pointer-events:none;transition:opacity .25s ease,visibility .25s ease;z-index:998}
.sidebarOverlay.open{opacity:1;visibility:visible;pointer-events:auto}
.sidebar{position:fixed;z-index:999;left:0;top:0;bottom:0;width:min(310px,86vw);padding:18px;display:flex;flex-direction:column;background:linear-gradient(160deg,rgba(25,17,47,.98),rgba(8,6,16,.99));border-right:1px solid rgba(196,181,253,.16);box-shadow:25px 0 80px rgba(0,0,0,.45);backdrop-filter:blur(24px);transform:translateX(-105%);transition:transform .3s cubic-bezier(.2,.8,.2,1);overflow-y:auto;overscroll-behavior:contain}
.sidebar.open{transform:translateX(0)}
.sideTop{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:4px 2px 18px;border-bottom:1px solid rgba(255,255,255,.07)}
.sideTitle{display:flex;align-items:center;gap:10px;min-width:0}.sideTitle>div{display:flex;flex-direction:column;min-width:0}.sideTitle b{font-size:16px}.sideTitle small{color:var(--muted);font-size:11px;margin-top:2px}
.miniLogo{width:38px;height:38px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(135deg,#6366f1,#c026d3);box-shadow:0 0 25px rgba(139,92,246,.3)}
.closeBtn{width:42px!important;height:42px!important;padding:0!important;margin:0!important;font-size:24px!important;display:grid!important;place-items:center!important;flex:0 0 42px!important}
.sideNav{display:grid;gap:7px;padding:16px 0}.sideItem{width:100%!important;min-height:48px!important;margin:0!important;padding:11px 13px!important;display:flex!important;align-items:center!important;gap:11px!important;justify-content:flex-start!important;text-align:left!important;background:transparent!important;border:1px solid transparent!important;box-shadow:none!important;border-radius:14px!important;color:#d8d1e8!important;font-size:14px!important;font-weight:650!important}.sideItem span{width:25px;text-align:center;font-size:18px}.sideItem:hover{background:rgba(139,92,246,.09)!important;border-color:rgba(196,181,253,.12)!important;transform:none!important;filter:none!important}.sideItem.active{background:linear-gradient(135deg,rgba(99,102,241,.95),rgba(168,85,247,.95))!important;color:#fff!important;border-color:transparent!important;box-shadow:0 10px 28px rgba(124,58,237,.28)!important}.sideBottom{margin-top:auto;padding-top:15px;border-top:1px solid rgba(255,255,255,.07)}.sideAccount{display:flex;align-items:center;gap:10px;padding:10px;border-radius:14px;background:rgba(255,255,255,.035)}.sideAccount>div:last-child{display:flex;flex-direction:column;min-width:0}.sideAccount b,.sideAccount small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sideAccount small{color:var(--muted);font-size:11px}.accountAvatar{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#7c3aed,#c026d3);font-weight:800}
/* Hide old navigation completely */
.legacyTabs{display:none!important}
/* Buttons */
button{font-family:inherit;min-height:42px;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
button:focus-visible,.sideItem:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid rgba(192,132,252,.8);outline-offset:2px}
.card{overflow:hidden}.toolbar{width:100%}.toolbar button,.log-toolbar button{flex:0 0 auto}.toolbar input,.log-toolbar input,.log-toolbar select{min-width:0}
input,select,textarea{max-width:100%;font-size:14px}
input[type=checkbox]{width:auto;max-width:none;accent-color:#8b5cf6}
/* Mobile-friendly controls and tables */
.tableWrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
table{min-width:650px}
.avatar{width:36px;height:36px;border-radius:12px;object-fit:cover;vertical-align:middle;margin-right:8px}
.userrow td:first-child{cursor:pointer}
.profile{align-items:start}.profile h2{overflow-wrap:anywhere}.kv{min-width:0}.kv b{overflow-wrap:anywhere}
.log-row{min-width:0}.log-details{overflow-wrap:anywhere;white-space:normal;word-break:break-word}.log-ip{overflow-wrap:anywhere;word-break:break-word}
.ripple{position:absolute!important;border-radius:50%;pointer-events:none;background:rgba(255,255,255,.25);transform:scale(0);animation:ripple .6s ease-out}
@keyframes ripple{to{transform:scale(2.4);opacity:0}}@keyframes pulse{0%,100%{opacity:.65;transform:scale(.9)}50%{opacity:1;transform:scale(1.15)}}
@media(max-width:700px){
 .container{padding:14px 12px 55px}
 .header{padding-bottom:16px;align-items:flex-start}
 .header .brand{gap:9px;align-items:flex-start}
 .header .logo{width:44px;height:44px;flex:0 0 44px;border-radius:14px;font-size:21px}
 .header h1{font-size:1.25rem}.header .sub{font-size:11px}.header .brand>div:last-child>div:last-child{font-size:12px;white-space:normal}
 .headerActions{gap:6px}.livePill{display:none}.headerActions .gray{padding:9px 12px!important;font-size:12px}
 .card{padding:16px;border-radius:18px;margin-bottom:12px}.hero{padding:20px}
 .grid{gap:9px}.stat{padding:13px}.stat b{font-size:22px}
 .toolbar,.log-toolbar{display:grid;grid-template-columns:1fr;gap:8px}.toolbar>* , .log-toolbar>*{width:100%!important;margin:0!important}.toolbar button,.log-toolbar button{min-height:44px}
 .profile{grid-template-columns:1fr;gap:14px}.profileAvatar{width:86px;height:86px;border-radius:22px}.kv{grid-template-columns:105px minmax(0,1fr);font-size:13px}
 .log-row{grid-template-columns:1fr;gap:7px;padding:13px}.log-title{font-size:13px}.log-time,.log-ip{font-size:10px}
 .card>button:not(.ghost){margin:5px 0;width:100%}
 .sideItem{min-height:50px!important;font-size:15px!important}
}
@media(max-width:380px){.grid{grid-template-columns:1fr}.header h1{font-size:1.1rem}.header .menuBtn{width:44px!important;height:44px!important;flex-basis:44px!important}.kv{grid-template-columns:1fr}.kv b{margin-bottom:8px}}

</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand"><button class="menuBtn ghost" onclick="toggleSidebar()" aria-label="Открыть меню">☰</button><div class="logo">⚡</div><div><h1>SerkovTools</h1><div class="sub">Центр управления сервером</div><div style="margin-top:6px">Вы: <b>${admin.username}</b> · <span class="badge">${admin.role_name || 'Без роли'}</span> <span class="mutedSep">•</span> ур. ${admin.level || 0}</div>
    </div></div>
    <div class="headerActions"><span class="livePill"><i></i> Панель онлайн</span><a href="/logout"><button class="gray">Выйти</button></a></div>
  </div>

  <div id="sidebarOverlay" class="sidebarOverlay" onclick="closeSidebar()"></div>
  <aside id="sidebar" class="sidebar">
    <div class="sideTop"><div class="sideTitle"><span class="miniLogo">⚡</span><div><b>SerkovTools</b><small>Навигация</small></div></div><button class="ghost closeBtn" onclick="closeSidebar()">×</button></div>
    <div class="sideNav">
      <button class="sideItem active" data-tab="main" onclick="showTab('main');closeSidebar()"><span>⌂</span><b>Главная</b></button>
      ${hasPermission(admin,'toggle_antisliv') ? '<button class="sideItem" data-tab="antisliv" onclick="showTab(\'antisliv\', event);closeSidebar()"><span>🛡</span><b>Anti-Sliv</b></button>' : ''}
      ${hasPermission(admin,'manage_admins') ? '<button class="sideItem" data-tab="admins" onclick="showTab(\'admins\', event);closeSidebar()"><span>♟</span><b>Админы</b></button>' : ''}
      ${hasPermission(admin,'manage_roles') ? '<button class="sideItem" data-tab="roles" onclick="showTab(\'roles\', event);closeSidebar()"><span>◈</span><b>Уровни</b></button>' : ''}
      ${hasPermission(admin,'manage_ipbans') || hasPermission(admin,'manage_admins') ? '<button class="sideItem" data-tab="ipbans" onclick="showTab(\'ipbans\', event);closeSidebar()"><span>⌁</span><b>Баны IP</b></button>' : ''}
      ${hasPermission(admin,'view_users') ? '<button class="sideItem" data-tab="users" onclick="showTab(\'users\', event);closeSidebar()"><span>♙</span><b>Пользователи</b></button>' : ''}
      ${hasPermission(admin,'manage_discord_roles') ? '<button class="sideItem" data-tab="droles" onclick="showTab(\'droles\', event);closeSidebar()"><span>◎</span><b>Роли Discord</b></button>' : ''}
      ${hasPermission(admin,'view_logs') ? '<button class="sideItem" data-tab="logs" onclick="showTab(\'logs\', event);closeSidebar()"><span>▤</span><b>Логи</b></button>' : ''}
    </div>
    <div class="sideBottom"><div class="sideAccount"><div class="accountAvatar">${String(admin.username||'A').slice(0,1).toUpperCase()}</div><div><b>${admin.username}</b><small>${admin.role_name || 'Без роли'}</small></div></div></div>
  </aside>

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
        <label><input type="checkbox" value="view_users"> Пользователи</label><label><input type="checkbox" value="edit_users"> Изменение пользователей</label><label><input type="checkbox" value="delete_users"> Удаление пользователей</label><label><input type="checkbox" value="manage_discord_roles"> Роли Discord</label>
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
      <h3>Забаненные IP <span class="badge" id="ipBanCount">0</span></h3>
      <div class="log-toolbar"><input id="ipBanSearch" placeholder="Поиск IP или причине..." oninput="filterIpBans()"><button class="blue" onclick="loadIpBans()">↻ Обновить</button></div>
      <div id="ipBansList" style="margin-top:14px"></div>
    </div>
  </div>

  <!-- ПОЛЬЗОВАТЕЛИ -->
  <div id="tab-users" class="hidden">
    <div class="card hero"><h2>Пользователи сервера</h2><div class="sub">Открой профиль пользователя, чтобы посмотреть и изменить доступные данные.</div><div class="toolbar" style="margin-top:15px"><input class="search" id="userSearch" placeholder="Поиск по имени, ID или никнейму" oninput="renderUsers()"><button class="blue" onclick="loadUsers()">↻ Обновить</button></div></div>
    <div class="card"><div id="usersList">Загрузка...</div></div>
  </div>

  <!-- ПРОФИЛЬ -->
  <div id="tab-profile" class="hidden"><div id="profileBox"></div></div>

  <!-- DISCORD РОЛИ -->
  <div id="tab-droles" class="hidden">
    <div class="card hero"><h2>Роли Discord</h2><div class="sub">Создание, изменение и удаление серверных ролей.</div></div>
    <div class="card"><h3>Создать роль</h3><input id="droleName" placeholder="Название роли"><input id="droleColor" placeholder="Цвет #8b5cf6"><label><input type="checkbox" id="droleHoist"> Показывать отдельно</label><button class="green" onclick="createDiscordRole()">Создать роль</button></div>
    <div class="card"><div id="drolesList">Загрузка...</div></div>
  </div>

  <!-- ЛОГИ -->
  <div id="tab-logs" class="hidden">
    <div class="card hero">
      <h2>Журнал событий</h2><div class="sub">Входы, действия администраторов и безопасность в одном месте.</div>
      <div class="log-toolbar"><input id="logSearch" placeholder="Поиск по логам..." oninput="filterLogs()"><select id="logType" onchange="filterLogs()"><option value="all">Все события</option><option value="login">Входы</option><option value="action">Действия</option></select><button class="blue" onclick="loadLogs();loadActions()">↻ Обновить</button></div>
    </div>
    <div class="card"><h3>Логи входов <span class="badge" id="loginCount">0</span></h3><div id="logsList" class="log-list"></div></div>
    <div class="card"><h3>Логи действий <span class="badge" id="actionCount">0</span></h3><div id="actionsList" class="log-list"></div></div>
  </div>
</div>

<script>
const myLevel = ${admin.level || 0};

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
showTab('main');
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


app.patch('/api/roles/:id', requirePermission('manage_roles'), async (req,res)=>{const row=await db.get('SELECT * FROM web_roles WHERE id=?',[req.params.id]);if(!row)return res.status(404).json({error:'Роль не найдена'});if(req.body.name)await db.run('UPDATE web_roles SET name=? WHERE id=?',[String(req.body.name),req.params.id]);if(req.body.level!==undefined)await db.run('UPDATE web_roles SET level=? WHERE id=?',[Number(req.body.level)||1,req.params.id]);if(Array.isArray(req.body.permissions))await db.run('UPDATE web_roles SET permissions=? WHERE id=?',[JSON.stringify(req.body.permissions),req.params.id]);await logAction(req.session.username,'EDIT_ROLE',`Изменена веб-роль ${row.name}`,getClientIp(req));res.json({message:'Роль изменена'});});
app.delete('/api/roles/:id', requirePermission('manage_roles'), async (req,res)=>{const row=await db.get('SELECT * FROM web_roles WHERE id=?',[req.params.id]);if(!row)return res.status(404).json({error:'Роль не найдена'});if(row.name==='Владелец')return res.status(400).json({error:'Нельзя удалить роль Владелец'});await db.run('UPDATE web_admins SET role_id=NULL WHERE role_id=?',[req.params.id]);await db.run('DELETE FROM web_roles WHERE id=?',[req.params.id]);await logAction(req.session.username,'DELETE_ROLE',`Удалена веб-роль ${row.name}`,getClientIp(req));res.json({message:'Роль удалена'});});

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
    const row = await db.get(`SELECT ip FROM web_ip_bans WHERE id = ?`, [req.params.id]);
    if (!row) return res.status(404).json({ error: 'IP не найден' });
    await db.run(`DELETE FROM web_ip_bans WHERE id = ?`, [req.params.id]);
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await logAction(req.session.username, 'UNBAN_IP', `Разбанен ID ${req.params.id}`, ip);
    res.json({ ok: true, message: `IP ${row.ip} разблокирован`, ip: row.ip });
});

app.get('/api/users', requirePermission('view_users'), (req,res)=>res.json({users:bridgeUsers}));
app.get('/api/users/:id', requirePermission('view_users'), (req,res)=>{ const u=bridgeUsers.find(x=>x.id===req.params.id); if(!u)return res.status(404).json({error:'Пользователь не найден'}); res.json({user:u,roles:bridgeDiscordRoles}); });
app.patch('/api/users/:id', requirePermission('edit_users'), async (req,res)=>{ const cmd=queueCommand('edit_user',{userId:String(req.params.id),nickname:String(req.body.nickname||''),roles:Array.isArray(req.body.roles)?req.body.roles.map(String):[]}); await logAction(req.session.username,'EDIT_USER',`Изменён пользователь ${req.params.id}`,getClientIp(req)); res.json({message:'Изменения отправлены боту',commandId:cmd.id}); });
app.delete('/api/users/:id', requirePermission('delete_users'), async (req,res)=>{ const cmd=queueCommand('kick_user',{userId:String(req.params.id)}); await logAction(req.session.username,'DELETE_USER',`Удалён пользователь ${req.params.id}`,getClientIp(req)); res.json({message:'Команда на удаление отправлена',commandId:cmd.id}); });
app.get('/api/discord-roles', requirePermission('manage_discord_roles'), (req,res)=>res.json({roles:bridgeDiscordRoles}));
app.post('/api/discord-roles', requirePermission('manage_discord_roles'), async (req,res)=>{if(!req.body.name)return res.status(400).json({error:'Укажите название'});const cmd=queueCommand('create_role',{name:String(req.body.name).slice(0,100),color:String(req.body.color||''),hoist:!!req.body.hoist});await logAction(req.session.username,'CREATE_DISCORD_ROLE',`Создание роли ${req.body.name}`,getClientIp(req));res.json({message:'Команда отправлена',commandId:cmd.id});});
app.delete('/api/discord-roles/:id', requirePermission('manage_discord_roles'), async (req,res)=>{const cmd=queueCommand('delete_role',{roleId:String(req.params.id)});await logAction(req.session.username,'DELETE_DISCORD_ROLE',`Удаление роли ${req.params.id}`,getClientIp(req));res.json({message:'Команда отправлена',commandId:cmd.id});});

app.listen(WEB_PORT, () => {
    console.log(`[WEB] Панель запущена на порту ${WEB_PORT}`);
});


})();
