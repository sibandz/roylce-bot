import crypto from 'node:crypto';
import { promisify } from 'node:util';

const SESSION_COOKIE = 'rolyce_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const scrypt = promisify(crypto.scrypt);
const attempts = new Map();

function getDatabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    const error = new Error('Supabase is not configured. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Vercel Project Settings → Environment Variables, then redeploy.');
    error.code = 'SUPABASE_CREDENTIALS_MISSING';
    throw error;
  }
  let projectUrl;
  try {
    projectUrl = new URL(url);
  } catch {
    throw new Error('SUPABASE_URL must be a valid project URL.');
  }
  if (!['https:', 'http:'].includes(projectUrl.protocol)) {
    throw new Error('SUPABASE_URL must use HTTP or HTTPS.');
  }
  return {
    async request(path, { method = 'GET', body, prefer } = {}) {
      const headers = {
        apikey: key,
        Authorization: `Bearer ${key}`,
      };
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      if (prefer) headers.Prefer = prefer;
      const response = await fetch(`${projectUrl.origin}/rest/v1/${path}`, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      const text = await response.text();
      let result = null;
      if (text) {
        try {
          result = JSON.parse(text);
        } catch {
          throw new Error('Supabase returned an unreadable response.');
        }
      }
      if (!response.ok) {
        const error = new Error(result?.message || `Supabase request failed (${response.status}).`);
        error.code = result?.code;
        throw error;
      }
      return result;
    },
  };
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function queryString(params) {
  return new URLSearchParams(params).toString();
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

async function requireUser(req, res, db) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) {
    sendJson(res, 401, { error: 'Please log in.' });
    return null;
  }
  const tokenHash = hash(token);
  const sessions = await db.request(`sessions?${queryString({
    token_hash: `eq.${tokenHash}`,
    select: 'user_id,expires_at',
    limit: '1',
  })}`);
  const session = sessions[0];
  if (!session) {
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session expired. Please log in again.' });
    return null;
  }
  if (Number(session.expires_at) <= Date.now()) {
    await db.request(`sessions?${queryString({ token_hash: `eq.${tokenHash}` })}`, { method: 'DELETE' });
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session expired. Please log in again.' });
    return null;
  }
  const userRows = await db.request(`users?${queryString({
    id: `eq.${session.user_id}`,
    select: 'id,username,role',
    limit: '1',
  })}`);
  const user = userRows[0];
  if (!user) {
    await db.request(`sessions?${queryString({ token_hash: `eq.${tokenHash}` })}`, { method: 'DELETE' });
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session is no longer valid. Please log in again.' });
    return null;
  }
  return { id: user.id, username: user.username, role: user.role };
}

async function issueSession(db, req, res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.request('sessions', {
    method: 'POST',
    body: { token_hash: hash(token), user_id: userId, expires_at: Date.now() + SESSION_SECONDS * 1000 },
    prefer: 'return=minimal',
  });
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

async function handleLogin(req, res, db) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed.' });
  if (rejectCrossOrigin(req, res) || limited(req, res, 'login', 10)) return;
  const body = readBody(req);
  const username = typeof body?.username === 'string' ? body.username.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (password.length > 256) return sendJson(res, 400, { error: 'Password is too long.' });
  const rows = await db.request(`users?${queryString({
    username_key: `eq.${username.toLowerCase()}`,
    select: 'id,username,password_salt,password_hash,role',
    limit: '1',
  })}`);
  const user = rows[0];
  const salt = user?.password_salt || 'rolyce-pilot-invalid-user-salt';
  const expected = /^[a-f0-9]{128}$/i.test(user?.password_hash || '') ? user.password_hash : '0'.repeat(128);
  const candidate = (await scrypt(password.slice(0, 256), salt, 64)).toString('hex');
  const match = crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(expected, 'hex'));
  if (!user || !match) return sendJson(res, 401, { error: 'Username or password is incorrect.' });
  await issueSession(db, req, res, user.id);
  return sendJson(res, 200, { user: { id: user.id, username: user.username, role: user.role } });
}

async function handleSignup(req, res, db) {
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
    await db.request('rpc/redeem_signup', {
      method: 'POST',
      body: {
        p_user_id: userId,
        p_username: username,
        p_password_salt: salt,
        p_password_hash: passwordHash,
        p_code_hash: hash(code),
        p_now: Date.now(),
      },
    });
  } catch (error) {
    if (error.message === 'USERNAME_TAKEN') return sendJson(res, 409, { error: 'That username is already taken.' });
    if (error.message === 'INVITE_INVALID') return sendJson(res, 400, { error: 'That signup code is invalid, expired, or already used.' });
    throw error;
  }
  await issueSession(db, req, res, userId);
  return sendJson(res, 201, { user: { id: userId, username, role: 'user' } });
}

export async function handleApi(req, res, route) {
  setSecurityHeaders(res);
  try {
    const db = getDatabase();
    if (route === 'health') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'Method not allowed.' });
      await db.request(`users?${queryString({ select: 'id', limit: '1' })}`);
      return sendJson(res, 200, { status: 'ok', database: 'supabase' });
    }
    if (route === 'auth/login') return await handleLogin(req, res, db);
    if (route === 'auth/signup') return await handleSignup(req, res, db);
    if (route === 'auth/me') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'Method not allowed.' });
      const user = await requireUser(req, res, db);
      if (user) return sendJson(res, 200, { user });
      return;
    }
    if (route === 'auth/logout') {
      if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed.' });
      if (rejectCrossOrigin(req, res)) return;
      const token = readCookie(req, SESSION_COOKIE);
      if (token) {
        await db.request(`sessions?${queryString({ token_hash: `eq.${hash(token)}` })}`, { method: 'DELETE' });
      }
      writeSessionCookie(req, res, '', 0);
      return sendJson(res, 200, { status: 'ok' });
    }
    if (route === 'demo') {
      const user = await requireUser(req, res, db);
      if (!user) return;
      if (req.method === 'GET') {
        const rows = await db.request(`users?${queryString({
          id: `eq.${user.id}`,
          select: 'demo_state',
          limit: '1',
        })}`);
        return sendJson(res, 200, { account: rows[0]?.demo_state || null });
      }
      if (req.method === 'PUT') {
        if (rejectCrossOrigin(req, res)) return;
        const account = readBody(req)?.account;
        if (!validDemoState(account)) return sendJson(res, 400, { error: 'Invalid demo-account state.' });
        await db.request(`users?${queryString({ id: `eq.${user.id}` })}`, {
          method: 'PATCH',
          body: { demo_state: account },
          prefer: 'return=minimal',
        });
        return sendJson(res, 200, { status: 'saved' });
      }
      return sendJson(res, 405, { error: 'Method not allowed.' });
    }
    return sendJson(res, 404, { error: 'Not found.' });
  } catch (error) {
    console.error('Vercel API request failed:', error);
    return sendJson(res, 500, {
      error: error.code === 'SUPABASE_CREDENTIALS_MISSING'
        ? error.message
        : process.env.NODE_ENV === 'production'
          ? 'The account service could not complete this request. Check the Vercel function logs and Supabase configuration.'
          : error.message,
    });
  }
}

export async function createCloudAdmin(username = 'admin') {
  const db = getDatabase();
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    throw new Error('Choose a username that is 3–32 letters, numbers, dots, underscores, or hyphens.');
  }
  const existing = await db.request(`users?${queryString({
    username_key: `eq.${username.toLowerCase()}`,
    select: 'id',
    limit: '1',
  })}`);
  if (existing.length) {
    throw new Error(`The username "${username}" already exists. No existing account was changed.`);
  }
  const password = crypto.randomBytes(24).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
  try {
    await db.request('users', {
      method: 'POST',
      body: {
        id: crypto.randomUUID(),
        username,
        password_salt: salt,
        password_hash: passwordHash,
        role: 'admin',
        created_at: Date.now(),
      },
      prefer: 'return=minimal',
    });
  } catch (error) {
    if (error.code === '23505') {
      throw new Error(`The username "${username}" already exists. No existing account was changed.`);
    }
    throw error;
  }
  return password;
}

export async function createCloudInvite(label = 'standard') {
  const db = getDatabase();
  const code = crypto.randomBytes(18).toString('base64url').toUpperCase();
  await db.request('signup_codes', {
    method: 'POST',
    body: {
      code_hash: hash(code),
      label: label.slice(0, 80),
      expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000,
      created_at: Date.now(),
    },
    prefer: 'return=minimal',
  });
  return code;
}
