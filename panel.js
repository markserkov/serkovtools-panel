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
const path = require('path');

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

app.post('/bridge/poll', async (req, res) => {
    if (!checkBridgeSecret(req, res)) return;
    const body = req.body || {};
    if (body.state) bridgeState = body.state;
    if (body.settings) bridgeSettings = body.settings;
    if (body.stats) bridgeStats = body.stats;
    if (Array.isArray(body.users)) bridgeUsers = body.users;
    if (Array.isArray(body.discordRoles)) bridgeDiscordRoles = body.discordRoles;
    if (Array.isArray(body.adminProfiles)) {
        for (const a of body.adminProfiles) {
            if (!a || !a.vk_id) continue;
            await db.run(`UPDATE web_admins SET nickname=COALESCE(NULLIF(?,'') ,nickname), vk_avatar=COALESCE(NULLIF(?,'') ,vk_avatar) WHERE vk_id=?`, [String(a.nickname||''), String(a.vk_avatar||''), String(a.vk_id)]);
        }
    }
    const adminProfiles = await db.all(`SELECT id,vk_id,discord_id,nickname,position,admin_level,vk_avatar FROM web_admins ORDER BY admin_level DESC, id ASC`);
    const commands = commandQueue.splice(0, commandQueue.length);
    res.json({ commands, adminProfiles });
});

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

// Миграция старой схемы в VK-only модель
const columns = await db.all(`PRAGMA table_info(web_admins)`);
const have = new Set(columns.map(x=>x.name));
for (const [name,type] of [['vk_id','TEXT'],['discord_id','TEXT'],['nickname','TEXT'],['position','TEXT'],['appointment_reason','TEXT'],['vk_avatar','TEXT'],['admin_level','INTEGER']]) {
  if(!have.has(name)) await db.exec(`ALTER TABLE web_admins ADD COLUMN ${name} ${type}`);
}
await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_web_admins_vk_id ON web_admins(vk_id) WHERE vk_id IS NOT NULL AND vk_id <> ''`);
await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_web_admins_discord_id ON web_admins(discord_id) WHERE discord_id IS NOT NULL AND discord_id <> ''`);
await db.run(`UPDATE web_roles SET level=8 WHERE name='Владелец'`);
await db.run(`UPDATE web_roles SET level=CASE WHEN level>8 THEN 8 WHEN level<1 THEN 1 ELSE level END`);
await db.run(`UPDATE web_admins SET admin_level=CASE WHEN admin_level>8 THEN 8 WHEN admin_level<1 THEN 1 ELSE admin_level END WHERE admin_level IS NOT NULL`);
const roleRows = await db.all(`SELECT * FROM web_roles ORDER BY level DESC`);
if(!roleRows.length){
  await db.run(`INSERT INTO web_roles(name,level,permissions) VALUES (?,?,?),(?,?,?),(?,?,?)`,[
    'Владелец',8,JSON.stringify(['view_status','view_stats','manage_admins','manage_roles']),
    'Администратор',6,JSON.stringify(['view_status','view_stats','manage_admins']),
    'Модератор',3,JSON.stringify(['view_status','view_stats'])
  ]);
}
await db.run(`CREATE TABLE IF NOT EXISTS admin_message_stats (week_key TEXT NOT NULL, discord_id TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(week_key,discord_id))`);

app.get('/auth/vk', (req,res)=>{
  const clientId = process.env.VK_CLIENT_ID || '';
  const redirectUri = process.env.VK_REDIRECT_URI || `https://${req.get('host')}/auth/vk/callback`;
  if(!clientId) return res.status(503).send('<h2 style="font-family:system-ui;text-align:center;margin-top:15vh">VK ID авторизация ещё не настроена.</h2><p style="text-align:center">Добавьте VK_CLIENT_ID, VK_CLIENT_SECRET и VK_REDIRECT_URI в Render.</p>');
  const state = require('crypto').randomBytes(24).toString('hex');
  req.session.vkState = state;
  const url = 'https://oauth.vk.com/authorize?' + new URLSearchParams({client_id:clientId,display:'page',redirect_uri:redirectUri,scope:'email',response_type:'code',v:'5.199',state}).toString();
  res.redirect(url);
});

app.get('/auth/vk/callback', async (req,res)=>{
  try{
    if(!req.query.code || !req.query.state || req.query.state !== req.session.vkState) return res.status(400).send('<h2 style="font-family:system-ui;text-align:center;margin-top:15vh">Некорректная VK-сессия. Попробуйте снова.</h2>');
    delete req.session.vkState;
    const clientId=process.env.VK_CLIENT_ID||''; const clientSecret=process.env.VK_CLIENT_SECRET||'';
    const redirectUri=process.env.VK_REDIRECT_URI || `https://${req.get('host')}/auth/vk/callback`;
    if(!clientId||!clientSecret) return res.status(503).send('VK OAuth не настроен.');
    const tokenUrl='https://oauth.vk.com/access_token?'+new URLSearchParams({client_id:clientId,client_secret:clientSecret,redirect_uri:redirectUri,code:String(req.query.code)}).toString();
    const tokenResp=await fetch(tokenUrl); const tokenData=await tokenResp.json();
    if(!tokenResp.ok || !tokenData.user_id) throw new Error(tokenData.error_description||tokenData.error||'VK token error');
    const userUrl='https://api.vk.com/method/users.get?'+new URLSearchParams({user_ids:String(tokenData.user_id),fields:'photo_200',access_token:tokenData.access_token,v:'5.199'}).toString();
    const userResp=await fetch(userUrl); const userData=await userResp.json();
    const vk=userData.response?.[0]; if(!vk) throw new Error('Не удалось получить профиль VK');
    const vkId=String(vk.id);
    let admin=await db.get(`SELECT a.*, r.name AS role_name, r.level, r.permissions FROM web_admins a LEFT JOIN web_roles r ON a.role_id=r.id WHERE a.vk_id=?`,[vkId]);
    if(!admin){
      const bootstrap=String(process.env.VK_BOOTSTRAP_ID||'');
      if(bootstrap && bootstrap===vkId){
        const ownerRole=await db.get(`SELECT id FROM web_roles WHERE level=8 ORDER BY id LIMIT 1`);
        const roleId=ownerRole?.id || (await db.get(`SELECT id FROM web_roles WHERE name='Владелец'`))?.id;
        await db.run(`INSERT INTO web_admins (username,password_hash,role_id,vk_id,discord_id,nickname,position,appointment_reason,vk_avatar,admin_level) VALUES (?,?,?,?,?,?,?,?,?,?)`,[`vk_${vkId}`,'',roleId,vkId,process.env.VK_BOOTSTRAP_DISCORD_ID||'',`${vk.first_name||''} ${vk.last_name||''}`.trim(),'Владелец','Первичная настройка панели',vk.photo_200||'',8]);
        admin=await db.get(`SELECT a.*, r.name AS role_name, r.level, r.permissions FROM web_admins a LEFT JOIN web_roles r ON a.role_id=r.id WHERE a.vk_id=?`,[vkId]);
      }
    }
    if(!admin){
      return res.status(403).send(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#080611;color:#fff;font-family:system-ui"><div style="max-width:460px;padding:28px;text-align:center;border:1px solid #3b2b5e;border-radius:24px;background:#120c20"><h2>Доступ не предоставлен</h2><p style="color:#aaa">Ваш VK ID <b>${vkId}</b> ещё не добавлен в администрацию. Попросите администратора создать профиль.</p><a href="/auth/vk" style="color:#a78bfa">Войти другим VK</a></div></body></html>`);
    }
    await db.run(`UPDATE web_admins SET nickname=?, vk_avatar=? WHERE id=?`,[`${vk.first_name||''} ${vk.last_name||''}`.trim(),vk.photo_200||admin.vk_avatar||'',admin.id]);
    req.session.adminId=admin.id; req.session.vkId=vkId; req.session.isAdmin=true;
    res.redirect('/');
  }catch(e){ console.error('[VK AUTH]',e); res.status(500).send('<h2 style="font-family:system-ui;text-align:center;margin-top:15vh">Ошибка авторизации VK. Попробуйте ещё раз.</h2><p style="text-align:center"><a href="/auth/vk">Повторить</a></p>'); }
});

app.get('/login',(req,res)=>res.send(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SerkovTools — VK</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 20% 10%,#40208055,transparent 35%),#080611;color:#fff;font-family:Inter,system-ui}.card{width:min(420px,calc(100% - 32px));padding:34px;border:1px solid #ffffff18;border-radius:28px;background:linear-gradient(145deg,#1d1230e8,#0b0813ee);box-shadow:0 30px 90px #0008;text-align:center}.logo{font-size:42px;margin-bottom:12px}.muted{color:#a99fba;line-height:1.6}.vk{display:block;margin-top:24px;padding:15px;border-radius:16px;text-decoration:none;color:#fff;font-weight:800;background:linear-gradient(135deg,#0077ff,#4aa3ff);box-shadow:0 14px 34px #0878ff33}.foot{margin-top:16px;color:#756b8e;font-size:12px}</style></head><body><main class="card"><div class="logo">⚡</div><h1>SerkovTools</h1><p class="muted">Закрытая панель администрации.<br>Вход выполняется только через VK.</p><a class="vk" href="/auth/vk">Войти через VK</a><div class="foot">Доступ получают только созданные администраторы.</div></main></body></html>`));

app.get('/logout', async (req,res)=>{ await logAction(req.session?.vkId||'unknown','LOGOUT','Выход из панели',getClientIp(req)); req.session.destroy(()=>res.redirect('/login')); });

// ---------- Auth helpers ----------
async function getAdminById(id){ return db.get(`SELECT a.*, r.name AS role_name, r.level AS role_level, r.permissions FROM web_admins a LEFT JOIN web_roles r ON a.role_id=r.id WHERE a.id=?`,[id]); }
function hasPermission(admin,perm){ if(!admin)return false; if(Number(admin.admin_level||admin.role_level||0)>=8)return true; try{return JSON.parse(admin.permissions||'[]').includes(perm);}catch{return false;} }
function requireAdmin(req,res,next){ if(req.session?.isAdmin && req.session.adminId)return next(); return res.redirect('/login'); }
function requirePermission(perm){return async(req,res,next)=>{if(!req.session?.isAdmin)return res.status(401).json({error:'Не авторизован'});const admin=await getAdminById(req.session.adminId);if(!admin||!hasPermission(admin,perm))return res.status(403).json({error:'Недостаточно прав'});req.admin=admin;next();};}
async function logAction(username,action,details,ip){try{await db.run(`INSERT INTO web_actions (username,action,details,ip) VALUES (?,?,?,?)`,[String(username||''),action,details||'',ip||'']);}catch{}}

// ---------- Main panel ----------
app.get('/panel-client.js',(req,res)=>res.sendFile(path.join(__dirname,'panel-client.js')));
app.get('/',requireAdmin,async(req,res)=>{
  const admin=await getAdminById(req.session.adminId); if(!admin)return res.redirect('/logout');
  const safe=JSON.stringify({id:admin.id,vkId:admin.vk_id||'',discordId:admin.discord_id||'',nickname:admin.nickname||'',position:admin.position||'',level:Number(admin.admin_level||admin.role_level||0),role:admin.role_name||'',avatar:admin.vk_avatar||''}).replace(/</g,'\\u003c');
  res.send(`<!doctype html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SerkovTools — Администрация</title><style>
:root{--bg:#070711;--panel:rgba(18,17,28,.84);--panel2:rgba(27,24,43,.82);--line:rgba(255,255,255,.10);--text:#f7f5ff;--muted:#a39bb7;--blue:#238cff;--purple:#8b5cf6;--pink:#d946ef;--good:#42e6a4;--bad:#ff6682}*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--text);background:radial-gradient(circle at 15% 0%,#43208455,transparent 34%),radial-gradient(circle at 100% 30%,#0b5fff22,transparent 30%),var(--bg)}body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(#a78bfa08 1px,transparent 1px),linear-gradient(90deg,#a78bfa08 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(#000,transparent 88%);z-index:-1}.app{display:flex;min-height:100vh}.sidebar{width:300px;flex:0 0 300px;padding:18px;position:fixed;inset:0 auto 0 0;z-index:50;background:linear-gradient(180deg,#111021ee,#0a0914f5);border-right:1px solid var(--line);backdrop-filter:blur(26px);transform:translateX(0);transition:.28s}.sideUser{display:flex;align-items:center;gap:12px;padding:10px 10px 16px;border-bottom:1px solid var(--line);cursor:pointer}.avatar{width:52px;height:52px;border-radius:17px;object-fit:cover;background:linear-gradient(135deg,#246bff,#7c3aed);border:2px solid #ffffff1b}.sideUser b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.sideUser small{display:block;color:var(--muted);margin-top:4px}.sideNav{padding-top:16px}.navBtn{width:100%;border:1px solid transparent;background:transparent;color:#e7e2f1;padding:13px 14px;border-radius:14px;text-align:left;display:flex;align-items:center;gap:11px;font-weight:750;cursor:pointer;margin:4px 0}.navBtn:hover{background:#ffffff08;border-color:#ffffff12}.navBtn.active{background:linear-gradient(135deg,#1f73d7,#6d43df);box-shadow:0 14px 34px #347df733}.sideBottom{position:absolute;left:18px;right:18px;bottom:18px}.logout{display:block;text-decoration:none;color:#bfb7ce;padding:11px 12px;border-radius:12px;background:#ffffff05;text-align:center}.content{margin-left:300px;width:calc(100% - 300px);padding:28px;max-width:1500px}.mobileHead{display:none}.page{display:none;animation:fade .3s ease}.page.active{display:block}@keyframes fade{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}.hero{padding:28px;border:1px solid var(--line);border-radius:28px;background:linear-gradient(145deg,#21153bd9,#0d0b17e8);box-shadow:0 25px 70px #0005}.eyebrow{color:#c7b8ff;font-size:11px;letter-spacing:.16em;text-transform:uppercase}.hero h1{font-size:38px;margin:9px 0 6px;letter-spacing:-.035em}.muted{color:var(--muted)}.profileTop{display:flex;align-items:center;gap:24px}.profileAvatar{width:118px;height:118px;border-radius:32px;object-fit:cover;background:linear-gradient(135deg,#1978ff,#8b5cf6);border:1px solid #ffffff22;box-shadow:0 20px 60px #0006}.level{display:inline-flex;align-items:center;gap:7px;padding:8px 13px;border-radius:999px;background:#1674dd26;color:#64aaff;border:1px solid #2e8dff55;font-weight:800}.position{font-size:19px;margin-top:9px}.links{display:flex;gap:9px;margin-top:16px;flex-wrap:wrap}.chip{padding:9px 12px;border-radius:12px;background:#ffffff08;border:1px solid #ffffff0d;color:#ddd7e8;text-decoration:none}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin-top:18px}.metric{padding:20px;border:1px solid var(--line);border-radius:20px;background:#11101ae8;position:relative;overflow:hidden}.metric:after{content:"";position:absolute;width:90px;height:90px;right:-30px;bottom:-35px;border-radius:50%;background:#7437ff2c;filter:blur(2px)}.metric b{font-size:32px;display:block;margin-top:7px}.metric span{color:var(--muted);font-size:13px}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.btn{border:0;border-radius:14px;padding:12px 16px;color:#fff;font-weight:800;cursor:pointer;background:#ffffff0d;border:1px solid #ffffff10}.btn.primary{background:linear-gradient(135deg,#1676ff,#8146ef)}.btn.danger{background:linear-gradient(135deg,#e21b4d,#ff465a)}.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}.section{margin-top:18px;padding:22px;border:1px solid var(--line);border-radius:24px;background:#11101ae8}.sectionHead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:15px}.section h2,.section h3{margin:0}.statusGrid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.status{padding:16px;border:1px solid var(--line);border-radius:17px;background:#ffffff04}.status small{color:var(--muted)}.status b{display:block;margin-top:8px;font-size:17px}.online{color:#74f2b4}.offline{color:#ff6d88}.adminHead{display:flex;align-items:flex-end;justify-content:space-between;gap:16px}.search{width:100%;padding:13px 15px;border-radius:14px;border:1px solid var(--line);background:#08070f;color:#fff;outline:none}.search:focus{border-color:#5f9dff;box-shadow:0 0 0 4px #258cff16}.adminTable{width:100%;border-collapse:separate;border-spacing:0 8px}.adminTable th{padding:8px 14px;color:#8f879f;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.08em}.adminTable td{padding:14px;background:#111018;border-top:1px solid #ffffff09;border-bottom:1px solid #ffffff09}.adminTable td:first-child{border-left:1px solid #ffffff09;border-radius:15px 0 0 15px}.adminTable td:last-child{border-right:1px solid #ffffff09;border-radius:0 15px 15px 0}.adminUser{display:flex;align-items:center;gap:11px;min-width:210px}.adminAvatar{width:44px;height:44px;border-radius:14px;object-fit:cover;background:#262332}.adminName b{display:block}.adminName span{display:block;color:#8f9bd0;font-size:12px;margin-top:3px}.level8{color:#b28cff}.count{font-size:19px;font-weight:850}.empty{text-align:center;padding:40px;color:var(--muted)}.modal{position:fixed;inset:0;z-index:100;display:none;align-items:center;justify-content:center;padding:18px;background:#0009;backdrop-filter:blur(12px)}.modal.open{display:flex}.modalCard{width:min(720px,100%);max-height:86vh;overflow:auto;padding:25px;border:1px solid #ffffff16;border-radius:25px;background:linear-gradient(145deg,#1b1430,#0b0a13);box-shadow:0 35px 100px #000b}.modalGrid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.modalStat{padding:15px;border-radius:16px;background:#ffffff06;border:1px solid #ffffff0d}.modalStat small{color:var(--muted)}.modalStat b{display:block;font-size:24px;margin-top:5px}.close{float:right;width:auto}.toast{position:fixed;right:20px;bottom:20px;z-index:200;padding:13px 16px;border-radius:14px;background:#191523;border:1px solid #ffffff15;box-shadow:0 18px 40px #0008}.toast.bad{border-color:#ff5c7733;color:#ff9aad}.createForm{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.createForm label{font-size:11px;color:#aaa0b8}.createForm input,.createForm select,.createForm textarea{width:100%;margin-top:6px;padding:12px;border-radius:12px;border:1px solid var(--line);background:#090811;color:#fff}.createForm textarea{min-height:90px;resize:vertical}.createForm .full{grid-column:1/-1}.danger{color:#ff7b92}.hidden{display:none!important}@media(max-width:900px){.sidebar{transform:translateX(-105%);box-shadow:20px 0 70px #0008}.sidebar.open{transform:translateX(0)}.content{margin-left:0;width:100%;padding:14px}.mobileHead{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.menu{width:auto;padding:10px 13px}.statusGrid{grid-template-columns:1fr 1fr}.metrics{grid-template-columns:1fr 1fr}.hero h1{font-size:31px}.profileTop{align-items:flex-start}.adminTable{min-width:720px}.tableWrap{overflow-x:auto}.sidebarOverlay{display:none;position:fixed;inset:0;z-index:40;background:#0008}.sidebarOverlay.open{display:block}}@media(max-width:560px){.hero{padding:20px;border-radius:22px}.profileTop{flex-direction:column}.profileAvatar{width:96px;height:96px}.metrics{grid-template-columns:1fr}.statusGrid{grid-template-columns:1fr 1fr}.modalGrid{grid-template-columns:1fr}.createForm{grid-template-columns:1fr}.createForm .full{grid-column:auto}.adminHead{align-items:stretch;flex-direction:column}}
</style></head><body data-admin='${safe}'><div class="app"><div id="sidebarOverlay" class="sidebarOverlay"></div><aside class="sidebar" id="sidebar"><div class="sideUser" onclick="showPage('me')"><img id="sideAvatar" class="avatar" src="${admin.vk_avatar||''}" onerror="this.style.display='none'"><div><b>${escapeHtml(admin.nickname||'Администратор')}</b><small>${escapeHtml(admin.position||'Администратор')} · уровень ${Number(admin.admin_level||admin.role_level||0)}</small></div></div><nav class="sideNav"><button class="navBtn active" data-page="me">👤 <span>Моя страница</span></button><button class="navBtn" data-page="admins">👥 <span>Администрация</span></button></nav><div class="sideBottom"><a class="logout" href="/logout">Выйти</a></div></aside><main class="content"><div class="mobileHead"><button class="btn menu" id="menuBtn">☰</button><b>SerkovTools</b><span></span></div><section id="page-me" class="page active"><div class="hero"><span class="eyebrow">ЛИЧНЫЙ ПРОФИЛЬ</span><div class="profileTop" style="margin-top:15px"><img class="profileAvatar" src="${admin.vk_avatar||''}" onerror="this.style.visibility='hidden'"><div><h1>${escapeHtml(admin.nickname||'Администратор')}</h1><span class="level">◈ ${Number(admin.admin_level||admin.role_level||0)} уровень</span><div class="position">${escapeHtml(admin.position||'Администратор')}</div><div class="links"><a class="chip" href="https://vk.com/id${encodeURIComponent(admin.vk_id||'')}" target="_blank">VK</a><a class="chip" href="https://discord.com/users/${encodeURIComponent(admin.discord_id||'')}" target="_blank">Discord</a></div></div></div></div><div class="metrics"><div class="metric"><span>Сообщения за неделю</span><b id="myMessages">0</b></div><div class="metric"><span>Текущий период</span><b id="weekLabel">—</b></div><div class="metric"><span>Обновлено</span><b id="updatedAt">—</b></div></div><div class="section"><div class="sectionHead"><div><h2>Состояние сервера</h2><span class="muted">Данные приходят через защищённый мост с Wispbyte.</span></div><button class="btn primary" id="refreshBtn">↻ Обновить</button></div><div id="statusGrid" class="statusGrid"><div class="empty">Загрузка…</div></div><div class="actions"><button class="btn primary" id="statusBtn">⚡ Проверить статус</button><button class="btn" id="statsBtn">📊 Подробная статистика</button></div></div></section><section id="page-admins" class="page"><div class="hero"><div class="adminHead"><div><span class="eyebrow">АДМИНИСТРАЦИЯ</span><h1 style="margin-bottom:4px">Администраторы</h1><div class="muted">Только ник, должность, уровень и сообщения за текущую неделю.</div></div>${hasPermission(admin,'manage_admins')?'<button class="btn primary" id="openCreate">＋ Добавить</button>':''}</div><div style="margin-top:18px"><input id="adminSearch" class="search" placeholder="Поиск по нику или должности"></div></div><div class="section"><div id="adminsList" class="tableWrap"><div class="empty">Загрузка…</div></div></div></section></main></div><div class="modal" id="statsModal"><div class="modalCard"><button class="btn close" id="closeStats">Закрыть</button><span class="eyebrow">LIVE STATISTICS</span><h2 style="margin:8px 0 5px">Статистика сервера</h2><p class="muted">Без сырого JSON — показатели отображаются карточками.</p><div id="modalStats" class="modalGrid" style="margin-top:16px"></div></div></div><div class="modal" id="createModal"><div class="modalCard"><button class="btn close" id="closeCreate">Закрыть</button><span class="eyebrow">РЕГИСТРАЦИЯ</span><h2 style="margin:8px 0 5px">Создать администратора</h2><p class="muted">Профиль получает доступ только после создания здесь.</p><form id="createForm" class="createForm"><label>VK ID<input name="vk_id" required placeholder="Например: 123456789"></label><label>Discord ID<input name="discord_id" required placeholder="Например: 123456789012345678"></label><label>Уровень 1–8<select name="admin_level" required>${Array.from({length:8},(_,i)=>`<option value="${i+1}">${i+1}</option>`).join('')}</select></label><label>Должность<input name="position" required placeholder="Например: Старший модератор"></label><label class="full">Причина постановления на пост<textarea name="appointment_reason" required placeholder="Причина назначения"></textarea></label><div class="full"><button class="btn primary" type="submit">Создать профиль</button></div></form></div></div><script>window.__ADMIN__=${safe}</script><script src="/panel-client.js?v=10" defer></script></body></html>`);
});

// ---------- API ----------
app.get('/api/status',requirePermission('view_status'),(req,res)=>res.json(bridgeState||{discord:'offline',vk:'offline',telegram:'offline',antiSliv:false,ping:null,uptime:0,members:0}));
app.get('/api/stats',requirePermission('view_stats'),(req,res)=>res.json(bridgeStats||{}));
app.get('/api/my-profile',requireAdmin,async(req,res)=>{const a=await getAdminById(req.session.adminId);res.json(a||{});});
app.get('/api/admins',requireAdmin,async(req,res)=>{const rows=await db.all(`SELECT a.id,a.vk_id,a.discord_id,a.nickname,a.position,a.admin_level,a.vk_avatar FROM web_admins a ORDER BY a.admin_level DESC,a.nickname COLLATE NOCASE ASC`);res.json({admins:rows,stats:bridgeStats?.adminMessages||{},week:bridgeStats?.week||''});});
app.post('/api/admins',requirePermission('manage_admins'),async(req,res)=>{const {vk_id,discord_id,position,appointment_reason,admin_level}=req.body;const level=Number(admin_level);if(!/^\\d+$/.test(String(vk_id||''))||!/^\\d+$/.test(String(discord_id||'')))return res.status(400).json({error:'VK ID и Discord ID должны быть числами'});if(level<1||level>8)return res.status(400).json({error:'Максимальный уровень — 8'});if(!position||!appointment_reason)return res.status(400).json({error:'Заполните должность и причину'});const exists=await db.get(`SELECT id FROM web_admins WHERE vk_id=? OR discord_id=?`,[String(vk_id),String(discord_id)]);if(exists)return res.status(400).json({error:'Такой VK ID или Discord ID уже зарегистрирован'});if(level>=Number(req.admin.admin_level||0))return res.status(403).json({error:'Нельзя создать администратора равного или выше вашего уровня'});let vkName='',avatar='';try{const tok=process.env.VK_SERVICE_TOKEN||'';if(tok){const u=await fetch('https://api.vk.com/method/users.get?'+new URLSearchParams({user_ids:String(vk_id),fields:'photo_200',access_token:tok,v:'5.199'})).then(r=>r.json());const x=u.response?.[0];if(x){vkName=`${x.first_name||''} ${x.last_name||''}`.trim();avatar=x.photo_200||'';}}}catch{}if(!vkName)vkName='VK '+String(vk_id);const role=await db.get(`SELECT id FROM web_roles WHERE level=? ORDER BY id LIMIT 1`,[level]);await db.run(`INSERT INTO web_admins (username,password_hash,role_id,vk_id,discord_id,nickname,position,appointment_reason,vk_avatar,admin_level) VALUES (?,?,?,?,?,?,?,?,?,?)`,[`vk_${vk_id}`,'',role?.id||null,String(vk_id),String(discord_id),vkName,String(position).trim(),String(appointment_reason).trim(),avatar,level]);await logAction(req.session.vkId,'CREATE_ADMIN',`Создан администратор VK ${vk_id}`,getClientIp(req));res.json({ok:true});});
app.delete('/api/admins/:id',requirePermission('manage_admins'),async(req,res)=>{const row=await db.get(`SELECT * FROM web_admins WHERE id=?`,[req.params.id]);if(!row)return res.status(404).json({error:'Профиль не найден'});if(Number(row.admin_level||0)>=Number(req.admin.admin_level||0))return res.status(403).json({error:'Нельзя удалить администратора равного или более высокого уровня'});if(Number(row.id)===Number(req.admin.id))return res.status(400).json({error:'Нельзя удалить себя'});await db.run(`DELETE FROM web_admins WHERE id=?`,[req.params.id]);await logAction(req.session.vkId,'DELETE_ADMIN',`Удалён профиль ID ${req.params.id}`,getClientIp(req));res.json({ok:true});});
app.get('/api/roles',requirePermission('manage_roles'),async(req,res)=>res.json(await db.all(`SELECT id,name,level,permissions FROM web_roles ORDER BY level DESC`)));
app.post('/api/roles',requirePermission('manage_roles'),async(req,res)=>{const level=Number(req.body.level);if(level<1||level>8)return res.status(400).json({error:'Уровень должен быть от 1 до 8'});try{await db.run(`INSERT INTO web_roles(name,level,permissions) VALUES(?,?,?)`,[String(req.body.name||'Роль'),level,JSON.stringify(Array.isArray(req.body.permissions)?req.body.permissions:[])]);res.json({ok:true});}catch(e){res.status(400).json({error:'Такая роль уже существует'});}});
app.delete('/api/roles/:id',requirePermission('manage_roles'),async(req,res)=>{const row=await db.get(`SELECT * FROM web_roles WHERE id=?`,[req.params.id]);if(!row)return res.status(404).json({error:'Роль не найдена'});const used=await db.get(`SELECT COUNT(*) c FROM web_admins WHERE role_id=?`,[row.id]);if(Number(used.c)>0)return res.status(400).json({error:'Сначала переназначьте администраторов с этой роли'});const owners=await db.get(`SELECT COUNT(*) c FROM web_roles WHERE level=8`);if(Number(row.level)===8&&Number(owners.c)<=1)return res.status(400).json({error:'Нельзя удалить последнюю роль 8 уровня'});await db.run(`DELETE FROM web_roles WHERE id=?`,[row.id]);await logAction(req.session.vkId,'DELETE_ROLE',`Удалена роль ${row.name}`,getClientIp(req));res.json({ok:true});});
app.listen(WEB_PORT,()=>console.log(`[WEB] Панель запущена на порту ${WEB_PORT}`));

})();
