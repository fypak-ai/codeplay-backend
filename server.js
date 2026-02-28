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

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 CodePlay API rodando na porta ${PORT}`));
