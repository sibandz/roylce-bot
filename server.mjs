import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import express from 'express';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(process.env.DATA_DIR || path.join(root, 'data'));
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const db = new Database(path.join(dataDir, 'rolyce-pilot.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
 CREATE TABLE IF NOT EXISTS users (
   id INTEGER PRIMARY KEY,
   username TEXT NOT NULL UNIQUE COLLATE NOCASE,
   salt TEXT NOT NULL,
   password_hash TEXT NOT NULL,
   created_at INTEGER NOT NULL,
   demo_state TEXT
 );
 CREATE TABLE IF NOT EXISTS signup_codes (
   code_hash TEXT PRIMARY KEY,
   label TEXT NOT NULL,
   expires_at INTEGER NOT NULL,
   used_at INTEGER,
   created_at INTEGER NOT NULL
 );
 CREATE TABLE IF NOT EXISTS sessions (
   token_hash TEXT PRIMARY KEY,
   user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
   expires_at INTEGER NOT NULL
 );
 CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
`);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SESSION_COOKIE = 'rolyce_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const scrypt = promisify(crypto.scrypt);
const production = process.env.NODE_ENV === 'production';
const limits = new Map();

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  });
  next();
});
app.use(express.json({ limit: '32kb', strict: true }));

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: production,
    path: '/',
    maxAge,
  };
}

function readCookie(req, name) {
  const prefix = `${name}=`;
  for (const part of (req.headers.cookie || '').split(';')) {
    const item = part.trim();
    if (item.startsWith(prefix)) {
      try {
        return decodeURIComponent(item.slice(prefix.length));
      } catch {
        return '';
      }
    }
  }
  return '';
}

function sameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin) {
    try {
      if (new URL(origin).host !== req.get('host')) {
        return res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
      }
    } catch {
      return res.status(403).json({ error: 'Invalid request origin.' });
    }
  }
  next();
}

function rateLimit(bucket, maximum, windowMs) {
  return (req, res, next) => {
    const key = `${bucket}:${req.ip}`;
    const now = Date.now();
    const record = limits.get(key);
    if (!record || record.resetAt <= now) {
      limits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (record.count >= maximum) {
      res.set('Retry-After', String(Math.ceil((record.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'Too many attempts. Please wait and try again.' });
    }
    record.count++;
    next();
  };
}

function requireUser(req, res, next) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) return res.status(401).json({ error: 'Please log in.' });
  const session = db.prepare(`
    SELECT users.id, users.username, sessions.expires_at
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(hash(token));
  if (!session || session.expires_at <= Date.now()) {
    if (session) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash(token));
    res.clearCookie(SESSION_COOKIE, cookieOptions(0));
    return res.status(401).json({ error: 'Your session expired. Please log in again.' });
  }
  req.user = { id: session.id, username: session.username };
  next();
}

function issueSession(userId, res) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + SESSION_SECONDS * 1000;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(hash(token), userId, expiresAt);
  res.cookie(SESSION_COOKIE, token, cookieOptions(SESSION_SECONDS * 1000));
}

function validDemoState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (!Number.isFinite(value.balance) || value.balance < 0 || value.balance > 1e12) return false;
  if (!Array.isArray(value.trades) || value.trades.length > 50
    || !value.trades.every(trade => trade && typeof trade === 'object'
      && /^[A-Z]{3}\/[A-Z]{3}$/.test(trade.pair)
      && [-1, 1].includes(trade.dir)
      && ['entry', 'exit', 'pnl', 'closedAt'].every(key => Number.isFinite(trade[key])))) return false;
  if (value.position !== null) {
    const position = value.position;
    if (!position || typeof position !== 'object'
      || !/^[A-Z]{3}\/[A-Z]{3}$/.test(position.pair)
      || ![-1, 1].includes(position.dir)
      || !['entry', 'stop', 'take', 'units', 'lastPrice'].every(key => Number.isFinite(position[key]))
      || position.units <= 0
      || (position.seconds !== undefined && ![300, 900, 3600, 14400, 86400].includes(position.seconds))
      || (position.quoteToUsd !== undefined && (!Number.isFinite(position.quoteToUsd) || position.quoteToUsd <= 0))
      || (position.openedAt !== undefined && !Number.isFinite(position.openedAt))) return false;
  }
  return true;
}

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/auth/me', requireUser, (req, res) => res.json({ user: req.user }));

app.post('/api/auth/signup', sameOrigin, rateLimit('signup', 8, 15 * 60 * 1000), async (req, res, next) => {
  try {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const code = typeof req.body?.code === 'string' ? req.body.code.trim().toUpperCase() : '';
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3–32 letters, numbers, dots, underscores, or hyphens.' });
    }
    if (password.length < 12 || password.length > 256) {
      return res.status(400).json({ error: 'Use a password between 12 and 256 characters.' });
    }
    if (!/^[A-Z0-9_-]{20,80}$/.test(code)) {
      return res.status(400).json({ error: 'Enter a valid one-time signup code.' });
    }
    const invitation = db.prepare('SELECT code_hash, expires_at, used_at FROM signup_codes WHERE code_hash = ?')
      .get(hash(code));
    if (!invitation || invitation.used_at || invitation.expires_at <= Date.now()) {
      return res.status(400).json({ error: 'That signup code is invalid, expired, or already used.' });
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
    const createUser = db.transaction(() => {
      const current = db.prepare('SELECT expires_at, used_at FROM signup_codes WHERE code_hash = ?')
        .get(invitation.code_hash);
      if (!current || current.used_at || current.expires_at <= Date.now()) {
        throw new Error('INVITE_USED');
      }
      const result = db.prepare('INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(username, salt, passwordHash, Date.now());
      db.prepare('UPDATE signup_codes SET used_at = ? WHERE code_hash = ?')
        .run(Date.now(), invitation.code_hash);
      return Number(result.lastInsertRowid);
    });
    let userId;
    try {
      userId = createUser();
    } catch (error) {
      if (error.message === 'INVITE_USED') return res.status(400).json({ error: 'That signup code has already been used.' });
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That username is already taken.' });
      throw error;
    }
    issueSession(userId, res);
    res.status(201).json({ user: { id: userId, username } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', sameOrigin, rateLimit('login', 10, 15 * 60 * 1000), async (req, res, next) => {
  try {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = db.prepare('SELECT id, username, salt, password_hash FROM users WHERE username = ?')
      .get(username);
    const salt = user?.salt || 'rolyce-pilot-invalid-user-salt';
    const expected = user?.password_hash || '0'.repeat(128);
    const candidate = (await scrypt(password.slice(0, 256), salt, 64)).toString('hex');
    const match = crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(expected, 'hex'));
    if (!user || !match) return res.status(401).json({ error: 'Username or password is incorrect.' });
    issueSession(user.id, res);
    res.json({ user: { id: user.id, username: user.username } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', sameOrigin, (req, res) => {
  const token = readCookie(req, SESSION_COOKIE);
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash(token));
  res.clearCookie(SESSION_COOKIE, cookieOptions(0));
  res.json({ status: 'ok' });
});

app.get('/api/demo', requireUser, (req, res) => {
  const row = db.prepare('SELECT demo_state FROM users WHERE id = ?').get(req.user.id);
  res.json({ account: row.demo_state ? JSON.parse(row.demo_state) : null });
});

app.put('/api/demo', sameOrigin, requireUser, (req, res) => {
  if (!validDemoState(req.body?.account)) return res.status(400).json({ error: 'Invalid demo-account state.' });
  const account = JSON.stringify(req.body.account);
  db.prepare('UPDATE users SET demo_state = ? WHERE id = ?').run(account, req.user.id);
  res.json({ status: 'saved' });
});

app.get('/', (req, res) => res.sendFile(path.join(root, 'index.html')));
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((error, req, res, next) => {
  console.error('Request failed:', error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'The server could not complete this request.' });
});

function generateInvite(label = 'standard') {
  const code = crypto.randomBytes(18).toString('base64url').toUpperCase();
  db.prepare('INSERT INTO signup_codes (code_hash, label, expires_at, created_at) VALUES (?, ?, ?, ?)')
    .run(hash(code), label.slice(0, 80), Date.now() + 30 * 24 * 60 * 60 * 1000, Date.now());
  return code;
}

if (process.argv[2] === 'invite') {
  const label = process.argv.slice(3).join(' ').trim() || 'standard';
  console.log(`One-time Rolyce Pilot signup code (${label}; expires in 30 days):\n${generateInvite(label)}\nGive this code to the invited user. It will only be shown once.`);
  db.close();
} else {
  const server = app.listen(PORT, () => console.log(`Rolyce Pilot listening on port ${PORT}`));
  const close = () => server.close(() => {
    db.close();
    process.exit(0);
  });
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
}
