import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { neon } from '@neondatabase/serverless';

const SESSION_COOKIE = 'rolyce_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const scrypt = promisify(crypto.scrypt);
const attempts = new Map();
let schemaReady;

function getSql() {
  const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!connectionString) {
    const error = new Error('Neon database is not configured. Add DATABASE_URL in Vercel Project Settings → Environment Variables, then redeploy.');
    error.code = 'DATABASE_URL_MISSING';
    throw error;
  }
  return neon(connectionString);
}

async function ensureSchema(sql) {
  if (!schemaReady) {
    schemaReady = (async () => {
      await sql`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
        created_at BIGINT NOT NULL,
        demo_state JSONB
      )`;
      await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'`;
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (LOWER(username))`;
      await sql`CREATE TABLE IF NOT EXISTS signup_codes (
        code_hash TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        used_at BIGINT,
        created_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at BIGINT NOT NULL
      )`;
      await sql`CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id)`;
    })().catch(error => {
      schemaReady = undefined;
      throw error;
    });
  }
  await schemaReady;
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function setSecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

function sendJson(res, status, value) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(value));
}

function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try {
      return JSON.parse(req.body);
    } catch {
      return null;
    }
  }
  return null;
}

function rejectCrossOrigin(req, res) {
  const origin = req.headers.origin;
  if (!origin) return false;
  try {
    if (new URL(origin).host === req.headers.host) return false;
  } catch {
    // An invalid Origin must fail closed.
  }
  sendJson(res, 403, { error: 'Cross-origin requests are not allowed.' });
  return true;
}

function limited(req, res, bucket, maximum) {
  const now = Date.now();
  const key = `${bucket}:${req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown'}`;
  let record = attempts.get(key);
  if (!record || record.resetAt <= now) {
    record = { count: 0, resetAt: now + 15 * 60 * 1000 };
    attempts.set(key, record);
  }
  if (record.count >= maximum) {
    res.setHeader('Retry-After', String(Math.ceil((record.resetAt - now) / 1000)));
    sendJson(res, 429, { error: 'Too many attempts. Please wait and try again.' });
    return true;
  }
  record.count++;
  return false;
}

function readCookie(req, name) {
  const prefix = `${name}=`;
  for (const item of (req.headers.cookie || '').split(';')) {
    const cookie = item.trim();
    if (!cookie.startsWith(prefix)) continue;
    try {
      return decodeURIComponent(cookie.slice(prefix.length));
    } catch {
      return '';
    }
  }
  return '';
}

function writeSessionCookie(req, res, token, maxAge) {
  const secure = process.env.NODE_ENV === 'production' || req.headers['x-forwarded-proto'] === 'https';
  const value = `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict;${secure ? ' Secure;' : ''} Max-Age=${maxAge}`;
  res.setHeader('Set-Cookie', value);
}

async function requireUser(req, res, sql) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) {
    sendJson(res, 401, { error: 'Please log in.' });
    return null;
  }
  const [user] = await sql`
    SELECT users.id, users.username, users.role, sessions.expires_at
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ${hash(token)}
  `;
  if (!user || Number(user.expires_at) <= Date.now()) {
    if (user) await sql`DELETE FROM sessions WHERE token_hash = ${hash(token)}`;
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session expired. Please log in again.' });
    return null;
  }
  return { id: user.id, username: user.username, role: user.role };
}

async function issueSession(sql, req, res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + SESSION_SECONDS * 1000;
  await sql`INSERT INTO sessions (token_hash, user_id, expires_at)
    VALUES (${hash(token)}, ${userId}, ${expiresAt})`;
  writeSessionCookie(req, res, token, SESSION_SECONDS);
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

async function handleLogin(req, res, sql) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed.' });
  if (rejectCrossOrigin(req, res) || limited(req, res, 'login', 10)) return;
  const body = readBody(req);
  const username = typeof body?.username === 'string' ? body.username.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (password.length > 256) return sendJson(res, 400, { error: 'Password is too long.' });
  const [user] = await sql`SELECT id, username, salt, password_hash, role FROM users
    WHERE LOWER(username) = LOWER(${username})`;
  const salt = user?.salt || 'rolyce-pilot-invalid-user-salt';
  const expected = user?.password_hash || '0'.repeat(128);
  const candidate = (await scrypt(password.slice(0, 256), salt, 64)).toString('hex');
  const match = crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(expected, 'hex'));
  if (!user || !match) return sendJson(res, 401, { error: 'Username or password is incorrect.' });
  await issueSession(sql, req, res, user.id);
  return sendJson(res, 200, { user: { id: user.id, username: user.username, role: user.role } });
}

async function handleSignup(req, res, sql) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed.' });
  if (rejectCrossOrigin(req, res) || limited(req, res, 'signup', 8)) return;
  const body = readBody(req);
  const username = typeof body?.username === 'string' ? body.username.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  const code = typeof body?.code === 'string' ? body.code.trim().toUpperCase() : '';
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    return sendJson(res, 400, { error: 'Username must be 3–32 letters, numbers, dots, underscores, or hyphens.' });
  }
  if (password.length < 12 || password.length > 256) {
    return sendJson(res, 400, { error: 'Use a password between 12 and 256 characters.' });
  }
  if (!/^[A-Z0-9_-]{20,80}$/.test(code)) return sendJson(res, 400, { error: 'Enter a valid one-time signup code.' });
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
  const userId = crypto.randomUUID();
  try {
    const rows = await sql`
      WITH consumed AS (
        UPDATE signup_codes SET used_at = ${Date.now()}
        WHERE code_hash = ${hash(code)} AND used_at IS NULL AND expires_at > ${Date.now()}
        RETURNING 1
      )
      INSERT INTO users (id, username, salt, password_hash, role, created_at)
      SELECT ${userId}, ${username}, ${salt}, ${passwordHash}, 'user', ${Date.now()}
      FROM consumed
      RETURNING id
    `;
    if (!rows.length) return sendJson(res, 400, { error: 'That signup code is invalid, expired, or already used.' });
  } catch (error) {
    if (error.code === '23505') return sendJson(res, 409, { error: 'That username is already taken.' });
    throw error;
  }
  await issueSession(sql, req, res, userId);
  return sendJson(res, 201, { user: { id: userId, username, role: 'user' } });
}

export async function handleApi(req, res, route) {
  setSecurityHeaders(res);
  try {
    const sql = getSql();
    await ensureSchema(sql);
    if (route === 'health') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'Method not allowed.' });
      return sendJson(res, 200, { status: 'ok' });
    }
    if (route === 'auth/login') return await handleLogin(req, res, sql);
    if (route === 'auth/signup') return await handleSignup(req, res, sql);
    if (route === 'auth/me') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'Method not allowed.' });
      const user = await requireUser(req, res, sql);
      if (user) return sendJson(res, 200, { user });
      return;
    }
    if (route === 'auth/logout') {
      if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed.' });
      if (rejectCrossOrigin(req, res)) return;
      const token = readCookie(req, SESSION_COOKIE);
      if (token) await sql`DELETE FROM sessions WHERE token_hash = ${hash(token)}`;
      writeSessionCookie(req, res, '', 0);
      return sendJson(res, 200, { status: 'ok' });
    }
    if (route === 'demo') {
      const user = await requireUser(req, res, sql);
      if (!user) return;
      if (req.method === 'GET') {
        const [row] = await sql`SELECT demo_state FROM users WHERE id = ${user.id}`;
        return sendJson(res, 200, { account: row.demo_state });
      }
      if (req.method === 'PUT') {
        if (rejectCrossOrigin(req, res)) return;
        const account = readBody(req)?.account;
        if (!validDemoState(account)) return sendJson(res, 400, { error: 'Invalid demo-account state.' });
        await sql`UPDATE users SET demo_state = ${JSON.stringify(account)}::jsonb WHERE id = ${user.id}`;
        return sendJson(res, 200, { status: 'saved' });
      }
      return sendJson(res, 405, { error: 'Method not allowed.' });
    }
    return sendJson(res, 404, { error: 'Not found.' });
  } catch (error) {
    console.error('Vercel API request failed:', error);
    return sendJson(res, 500, {
      error: error.code === 'DATABASE_URL_MISSING'
        ? error.message
        : process.env.NODE_ENV === 'production'
        ? 'The account service could not complete this request. Check the Vercel function logs and database configuration.'
        : error.message,
    });
  }
}

export async function ensureDatabaseSchema() {
  await ensureSchema(getSql());
}

export async function createCloudAdmin(username = 'admin') {
  const sql = getSql();
  await ensureSchema(sql);
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    throw new Error('Choose a username that is 3–32 letters, numbers, dots, underscores, or hyphens.');
  }
  const [existing] = await sql`SELECT 1 FROM users WHERE LOWER(username) = LOWER(${username})`;
  if (existing) throw new Error(`The username "${username}" already exists. No existing account was changed.`);
  const password = crypto.randomBytes(24).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
  await sql`INSERT INTO users (id, username, salt, password_hash, role, created_at)
    VALUES (${crypto.randomUUID()}, ${username}, ${salt}, ${passwordHash}, 'admin', ${Date.now()})`;
  return password;
}

export async function createCloudInvite(label = 'standard') {
  const sql = getSql();
  await ensureSchema(sql);
  const code = crypto.randomBytes(18).toString('base64url').toUpperCase();
  const safeLabel = label.slice(0, 80);
  await sql`INSERT INTO signup_codes (code_hash, label, expires_at, created_at)
    VALUES (${hash(code)}, ${safeLabel}, ${Date.now() + 30 * 24 * 60 * 60 * 1000}, ${Date.now()})`;
  return code;
}
