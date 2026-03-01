const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'codeplay-secret-2026';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'codeplay.db');

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Database ───────────────────────────────────────────────────
const fs = require('fs');
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email     TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password  TEXT    NOT NULL,
    avatar    TEXT    DEFAULT '👤',
    wallet    REAL    DEFAULT 1000.00,
    level     INTEGER DEFAULT 1,
    xp        INTEGER DEFAULT 0,
    created_at TEXT   DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS apps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    name        TEXT    NOT NULL,
    description TEXT,
    category    TEXT    DEFAULT 'Utilitário',
    price       REAL    DEFAULT 0,
    emoji       TEXT    DEFAULT '✨',
    color       TEXT    DEFAULT '#7c3aed',
    code        TEXT,
    downloads   INTEGER DEFAULT 0,
    rating      REAL    DEFAULT 5.0,
    auto_detected INTEGER DEFAULT 0,
    created_at  TEXT    DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS purchases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    app_id     INTEGER NOT NULL REFERENCES apps(id),
    price_paid REAL    DEFAULT 0,
    purchased_at TEXT  DEFAULT (datetime('now')),
    UNIQUE(user_id, app_id)
  );
  CREATE TABLE IF NOT EXISTS hack_tools (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    name     TEXT    NOT NULL,
    type     TEXT    NOT NULL,
    power    INTEGER DEFAULT 50,
    emoji    TEXT    DEFAULT '☠️',
    code     TEXT,
    preset   INTEGER DEFAULT 0,
    created_at TEXT  DEFAULT (datetime('now'))
  );
`);

// ── Auth Middleware ────────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token necessário' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ── Health ─────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

// ── AUTH ROUTES ────────────────────────────────────────────────
// POST /api/auth/register
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, avatar } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'username, email e password são obrigatórios' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Senha deve ter no mínimo 4 caracteres' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const stmt = db.prepare(`INSERT INTO users (username, email, password, avatar) VALUES (?,?,?,?)`);
    const info = stmt.run(username.trim(), email.trim().toLowerCase(), hash, avatar || '👤');
    const user = db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE id=?').get(info.lastInsertRowid);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ user, token });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      const field = e.message.includes('email') ? 'email' : 'username';
      return res.status(409).json({ error: `${field} já está em uso` });
    }
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'username e password são obrigatórios' });
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username.trim(), username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Credenciais inválidas' });
  const { password: _, ...safeUser } = user;
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: safeUser, token });
});

// GET /api/auth/me
app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  res.json(user);
});

// ── USERS ──────────────────────────────────────────────────────
// GET /api/users  (leaderboard)
app.get('/api/users', (_, res) => {
  const users = db.prepare('SELECT id,username,avatar,wallet,level,xp,created_at FROM users ORDER BY wallet DESC LIMIT 50').all();
  res.json(users);
});

// GET /api/users/:id
app.get('/api/users/:id', (req, res) => {
  const user = db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE id=?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  res.json(user);
});

// PATCH /api/users/me  (update profile)
app.patch('/api/users/me', auth, (req, res) => {
  const { avatar } = req.body;
  if (avatar) db.prepare('UPDATE users SET avatar=? WHERE id=?').run(avatar, req.user.id);
  const user = db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE id=?').get(req.user.id);
  res.json(user);
});

// ── APPS ───────────────────────────────────────────────────────
// GET /api/apps
app.get('/api/apps', (_, res) => {
  const apps = db.prepare(`
    SELECT a.*, u.username as owner_name, u.avatar as owner_avatar
    FROM apps a JOIN users u ON a.owner_id = u.id
    ORDER BY a.created_at DESC LIMIT 100
  `).all();
  res.json(apps);
});

// GET /api/apps/mine  (requires auth)
app.get('/api/apps/mine', auth, (req, res) => {
  const apps = db.prepare('SELECT * FROM apps WHERE owner_id=? ORDER BY created_at DESC').all(req.user.id);
  res.json(apps);
});

// GET /api/apps/:id
app.get('/api/apps/:id', (req, res) => {
  const app_ = db.prepare(`SELECT a.*, u.username as owner_name FROM apps a JOIN users u ON a.owner_id=u.id WHERE a.id=?`).get(req.params.id);
  if (!app_) return res.status(404).json({ error: 'App não encontrado' });
  res.json(app_);
});

// POST /api/apps  (create)
app.post('/api/apps', auth, (req, res) => {
  const { name, description, category, price, emoji, color, code, auto_detected } = req.body;
  if (!name) return res.status(400).json({ error: 'name é obrigatório' });
  const info = db.prepare(`
    INSERT INTO apps (owner_id, name, description, category, price, emoji, color, code, auto_detected)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).run(req.user.id, name, description||'', category||'Utilitário', price||0, emoji||'✨', color||'#7c3aed', code||'', auto_detected?1:0);
  // XP reward
  db.prepare('UPDATE users SET xp=xp+50, level=1+(xp/500) WHERE id=?').run(req.user.id);
  const newApp = db.prepare('SELECT * FROM apps WHERE id=?').get(info.lastInsertRowid);
  res.status(201).json(newApp);
});

// DELETE /api/apps/:id
app.delete('/api/apps/:id', auth, (req, res) => {
  const app_ = db.prepare('SELECT * FROM apps WHERE id=? AND owner_id=?').get(req.params.id, req.user.id);
  if (!app_) return res.status(404).json({ error: 'App não encontrado ou sem permissão' });
  db.prepare('DELETE FROM apps WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// POST /api/apps/:id/purchase
app.post('/api/apps/:id/purchase', auth, (req, res) => {
  const app_ = db.prepare('SELECT * FROM apps WHERE id=?').get(req.params.id);
  if (!app_) return res.status(404).json({ error: 'App não encontrado' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (app_.owner_id === req.user.id) return res.status(400).json({ error: 'Você já é o dono deste app' });
  if (user.wallet < app_.price) return res.status(400).json({ error: 'Saldo insuficiente' });
  try {
    db.prepare('INSERT INTO purchases (user_id, app_id, price_paid) VALUES (?,?,?)').run(req.user.id, app_.id, app_.price);
    db.prepare('UPDATE users SET wallet=wallet-? WHERE id=?').run(app_.price, req.user.id);
    db.prepare('UPDATE users SET wallet=wallet+? WHERE id=?').run(app_.price * 0.85, app_.owner_id);
    db.prepare('UPDATE apps SET downloads=downloads+1 WHERE id=?').run(app_.id);
    res.json({ ok: true, spent: app_.price });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'App já comprado' });
    res.status(500).json({ error: e.message });
  }
});

// ── HACK TOOLS ─────────────────────────────────────────────────
// GET /api/hack-tools/mine
app.get('/api/hack-tools/mine', auth, (req, res) => {
  const tools = db.prepare('SELECT * FROM hack_tools WHERE owner_id=? ORDER BY created_at DESC').all(req.user.id);
  res.json(tools);
});

// POST /api/hack-tools
app.post('/api/hack-tools', auth, (req, res) => {
  const { name, type, power, emoji, code, preset } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'name e type são obrigatórios' });
  const info = db.prepare('INSERT INTO hack_tools (owner_id,name,type,power,emoji,code,preset) VALUES (?,?,?,?,?,?,?)')
    .run(req.user.id, name, type, power||50, emoji||'☠️', code||'', preset?1:0);
  res.status(201).json(db.prepare('SELECT * FROM hack_tools WHERE id=?').get(info.lastInsertRowid));
});

// DELETE /api/hack-tools/:id
app.delete('/api/hack-tools/:id', auth, (req, res) => {
  const t = db.prepare('SELECT * FROM hack_tools WHERE id=? AND owner_id=?').get(req.params.id, req.user.id);
  if (!t) return res.status(404).json({ error: 'Ferramenta não encontrada ou sem permissão' });
  db.prepare('DELETE FROM hack_tools WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});


// POST /api/missions/reward
app.post('/api/missions/reward', auth, (req, res) => {
  const { xp, money } = req.body;
  if (!xp && !money) return res.status(400).json({ error: 'xp ou money necessário' });
  if (xp)    db.prepare('UPDATE users SET xp=xp+?, level=1+(xp/?) WHERE id=?').run(Number(xp)||0, 500, req.user.id);
  if (money) db.prepare('UPDATE users SET wallet=wallet+? WHERE id=?').run(Number(money)||0, req.user.id);
  const user = db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE id=?').get(req.user.id);
  res.json(user);
});

// ── Start ──────────────────────────────────────────────────────
// ── Admin tables
db.exec(`
  CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS features (
    key TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);
['missions','cloak','cloner','chat','tracker','hacker_lab','simuladores'].forEach(
  k => db.prepare('INSERT OR IGNORE INTO features (key,enabled) VALUES (?,1)').run(k)
);

// ── Admin config
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'codeplay-admin-2026';

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token admin necessario' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload.isAdmin) return res.status(403).json({ error: 'Acesso negado' });
    req.user = payload;
    next();
  } catch(_e) {
    res.status(401).json({ error: 'Token invalido ou expirado' });
  }
}

function logAdmin(adminId, action, target, detail) {
  db.prepare('INSERT INTO admin_logs (admin_id,action,target,detail) VALUES (?,?,?,?)')
    .run(adminId, action, target || null, detail || null);
}

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { secret } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(401).json({ error: 'Senha admin incorreta' });
  const token = jwt.sign({ isAdmin: true, username: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// GET /api/admin/stats
app.get('/api/admin/stats', adminAuth, (_req, res) => {
  res.json({
    users:     db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    apps:      db.prepare('SELECT COUNT(*) as c FROM apps').get().c,
    purchases: db.prepare('SELECT COUNT(*) as c FROM purchases').get().c,
    revenue:   db.prepare('SELECT COALESCE(SUM(price_paid),0) as s FROM purchases').get().s,
    logs:      db.prepare('SELECT COUNT(*) as c FROM admin_logs').get().c,
  });
});

// GET /api/admin/users
app.get('/api/admin/users', adminAuth, (req, res) => {
  const limit  = parseInt(req.query.limit)  || 50;
  const offset = parseInt(req.query.offset) || 0;
  const q      = req.query.q || '';
  const users  = q
    ? db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?')
        .all('%'+q+'%','%'+q+'%',limit,offset)
    : db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?')
        .all(limit,offset);
  res.json(users);
});

// POST /api/admin/users
app.post('/api/admin/users', adminAuth, (req, res) => {
  const { username, email, password, wallet } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'username, email e password obrigatorios' });
  const bcr = require('bcryptjs');
  try {
    const hash = bcr.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (username,email,password,wallet) VALUES (?,?,?,?)')
      .run(username.trim(), email.trim().toLowerCase(), hash, wallet || 1000);
    const user = db.prepare('SELECT id,username,email,wallet,level,xp,created_at FROM users WHERE id=?').get(info.lastInsertRowid);
    logAdmin(0,'create_user','user:'+user.id, username);
    res.status(201).json(user);
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'username ou email ja existe' });
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/users/:id
app.patch('/api/admin/users/:id', adminAuth, (req, res) => {
  const { wallet, level, xp, banned } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Usuario nao encontrado' });
  if (wallet  !== undefined) db.prepare('UPDATE users SET wallet=? WHERE id=?').run(Number(wallet), u.id);
  if (level   !== undefined) db.prepare('UPDATE users SET level=?  WHERE id=?').run(Number(level),  u.id);
  if (xp      !== undefined) db.prepare('UPDATE users SET xp=?     WHERE id=?').run(Number(xp),     u.id);
  if (banned  !== undefined) db.prepare('UPDATE users SET avatar=? WHERE id=?').run(banned ? 'BANNED' : u.avatar, u.id);
  logAdmin(0,'edit_user','user:'+u.id, JSON.stringify(req.body));
  res.json(db.prepare('SELECT id,username,email,avatar,wallet,level,xp,created_at FROM users WHERE id=?').get(u.id));
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Usuario nao encontrado' });
  db.prepare('DELETE FROM purchases  WHERE user_id=?').run(u.id);
  db.prepare('DELETE FROM hack_tools WHERE owner_id=?').run(u.id);
  db.prepare('DELETE FROM apps       WHERE owner_id=?').run(u.id);
  db.prepare('DELETE FROM users      WHERE id=?').run(u.id);
  logAdmin(0,'delete_user','user:'+u.id, u.username);
  res.json({ ok: true });
});

// GET /api/admin/apps
app.get('/api/admin/apps', adminAuth, (req, res) => {
  const q = req.query.q || '';
  const apps = q
    ? db.prepare('SELECT a.*,u.username as owner_name FROM apps a JOIN users u ON a.owner_id=u.id WHERE a.name LIKE ? OR u.username LIKE ? ORDER BY a.created_at DESC LIMIT 100')
        .all('%'+q+'%','%'+q+'%')
    : db.prepare('SELECT a.*,u.username as owner_name FROM apps a JOIN users u ON a.owner_id=u.id ORDER BY a.created_at DESC LIMIT 100')
        .all();
  res.json(apps);
});

// POST /api/admin/apps
app.post('/api/admin/apps', adminAuth, (req, res) => {
  const { owner_id, name, description, category, price, emoji, color, code } = req.body;
  if (!owner_id || !name) return res.status(400).json({ error: 'owner_id e name obrigatorios' });
  const info = db.prepare('INSERT INTO apps (owner_id,name,description,category,price,emoji,color,code) VALUES (?,?,?,?,?,?,?,?)')
    .run(owner_id, name, description||'', category||'Utilitario', price||0, emoji||'*', color||'#7c3aed', code||'');
  logAdmin(0,'inject_app','app:'+info.lastInsertRowid, name);
  res.status(201).json(db.prepare('SELECT * FROM apps WHERE id=?').get(info.lastInsertRowid));
});

// DELETE /api/admin/apps/:id
app.delete('/api/admin/apps/:id', adminAuth, (req, res) => {
  const a = db.prepare('SELECT * FROM apps WHERE id=?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'App nao encontrado' });
  db.prepare('DELETE FROM purchases WHERE app_id=?').run(a.id);
  db.prepare('DELETE FROM apps      WHERE id=?').run(a.id);
  logAdmin(0,'delete_app','app:'+a.id, a.name);
  res.json({ ok: true });
});

// GET /api/admin/features
app.get('/api/admin/features', adminAuth, (_req, res) => {
  res.json(db.prepare('SELECT * FROM features ORDER BY key').all());
});

// PATCH /api/admin/features/:key
app.patch('/api/admin/features/:key', adminAuth, (req, res) => {
  const { enabled } = req.body;
  db.prepare("INSERT OR REPLACE INTO features (key,enabled,updated_at) VALUES (?,?,datetime('now'))")
    .run(req.params.key, enabled ? 1 : 0);
  logAdmin(0,'toggle_feature',req.params.key, enabled ? 'on' : 'off');
  res.json({ key: req.params.key, enabled: !!enabled });
});

// GET /api/admin/logs
app.get('/api/admin/logs', adminAuth, (_req, res) => {
  res.json(db.prepare('SELECT * FROM admin_logs ORDER BY id DESC LIMIT 100').all());
});

// GET /api/admin/interactions
app.get('/api/admin/interactions', adminAuth, (_req, res) => {
  const purchases = db.prepare(
    'SELECT p.id,p.purchased_at,p.price_paid,u.username,a.name as app_name FROM purchases p JOIN users u ON p.user_id=u.id JOIN apps a ON p.app_id=a.id ORDER BY p.purchased_at DESC LIMIT 50'
  ).all();
  res.json({ purchases });
});

// Public: GET /api/features
app.get('/api/features', (_req, res) => {
  const out = {};
  db.prepare('SELECT key,enabled FROM features').all().forEach(r => { out[r.key] = !!r.enabled; });
  res.json(out);
});


app.listen(PORT, () => console.log(`🚀 CodePlay API rodando na porta ${PORT}`));
