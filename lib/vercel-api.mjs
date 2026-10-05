import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

const SESSION_COOKIE = 'rolyce_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const scrypt = promisify(crypto.scrypt);
const attempts = new Map();

function getDatabase() {
  if (!getApps().length) {
    const rawCredentials = process.env.FIREBASE_SERVICE_ACCOUNT
      || (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64
        ? Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8')
        : '');
    if (!rawCredentials) {
      const error = new Error('Firebase is not configured. Add FIREBASE_SERVICE_ACCOUNT in Vercel Project Settings → Environment Variables, then redeploy.');
      error.code = 'FIREBASE_CREDENTIALS_MISSING';
      throw error;
    }
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(rawCredentials);
    } catch {
      throw new Error('FIREBASE_SERVICE_ACCOUNT must contain valid service-account JSON.');
    }
    if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
      throw new Error('Firebase service-account JSON is missing project_id, client_email, or private_key.');
    }
    initializeApp({
      credential: cert({
        projectId: serviceAccount.project_id,
        clientEmail: serviceAccount.client_email,
        privateKey: serviceAccount.private_key.replace(/\\n/g, '\n'),
      }),
      projectId: serviceAccount.project_id,
    });
  }
  return getFirestore();
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

async function requireUser(req, res, db) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) {
    sendJson(res, 401, { error: 'Please log in.' });
    return null;
  }
  const sessionRef = db.collection('sessions').doc(hash(token));
  const sessionSnapshot = await sessionRef.get();
  if (!sessionSnapshot.exists) {
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session expired. Please log in again.' });
    return null;
  }
  const session = sessionSnapshot.data();
  if (session.expiresAt <= Date.now()) {
    await sessionRef.delete();
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session expired. Please log in again.' });
    return null;
  }
  const userSnapshot = await db.collection('users').doc(session.userId).get();
  if (!userSnapshot.exists) {
    await sessionRef.delete();
    writeSessionCookie(req, res, '', 0);
    sendJson(res, 401, { error: 'Your session is no longer valid. Please log in again.' });
    return null;
  }
  const user = userSnapshot.data();
  return { id: userSnapshot.id, username: user.username, role: user.role };
}

async function issueSession(db, req, res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.collection('sessions').doc(hash(token)).set({
    userId,
    expiresAt: Date.now() + SESSION_SECONDS * 1000,
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
  const usernameRef = db.collection('usernames').doc(username.toLowerCase());
  const usernameSnapshot = await usernameRef.get();
  const userSnapshot = usernameSnapshot.exists
    ? await db.collection('users').doc(usernameSnapshot.data().userId).get()
    : null;
  const user = userSnapshot?.exists ? userSnapshot.data() : null;
  const salt = user?.salt || 'rolyce-pilot-invalid-user-salt';
  const expected = user?.passwordHash || '0'.repeat(128);
  const candidate = (await scrypt(password.slice(0, 256), salt, 64)).toString('hex');
  const match = crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(expected, 'hex'));
  if (!user || !match) return sendJson(res, 401, { error: 'Username or password is incorrect.' });
  await issueSession(db, req, res, userSnapshot.id);
  return sendJson(res, 200, { user: { id: userSnapshot.id, username: user.username, role: user.role } });
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
  const usernameRef = db.collection('usernames').doc(username.toLowerCase());
  const inviteRef = db.collection('signup_codes').doc(hash(code));
  const userRef = db.collection('users').doc(userId);
  try {
    await db.runTransaction(async transaction => {
      const [usernameSnapshot, inviteSnapshot] = await Promise.all([
        transaction.get(usernameRef),
        transaction.get(inviteRef),
      ]);
      if (usernameSnapshot.exists) throw Object.assign(new Error('That username is already taken.'), { code: 'USERNAME_TAKEN' });
      if (!inviteSnapshot.exists
        || inviteSnapshot.data().usedAt
        || inviteSnapshot.data().expiresAt <= Date.now()) {
        throw Object.assign(new Error('That signup code is invalid, expired, or already used.'), { code: 'INVITE_INVALID' });
      }
      transaction.create(userRef, {
        username,
        salt,
        passwordHash,
        role: 'user',
        createdAt: Date.now(),
        demoState: null,
      });
      transaction.create(usernameRef, { userId });
      transaction.update(inviteRef, { usedAt: Date.now() });
    });
  } catch (error) {
    if (error.code === 'USERNAME_TAKEN') return sendJson(res, 409, { error: error.message });
    if (error.code === 'INVITE_INVALID') return sendJson(res, 400, { error: error.message });
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
      await db.collection('users').limit(1).get();
      return sendJson(res, 200, { status: 'ok', database: 'firestore' });
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
      if (token) await db.collection('sessions').doc(hash(token)).delete();
      writeSessionCookie(req, res, '', 0);
      return sendJson(res, 200, { status: 'ok' });
    }
    if (route === 'demo') {
      const user = await requireUser(req, res, db);
      if (!user) return;
      const userRef = db.collection('users').doc(user.id);
      if (req.method === 'GET') {
        const snapshot = await userRef.get();
        return sendJson(res, 200, { account: snapshot.data().demoState || null });
      }
      if (req.method === 'PUT') {
        if (rejectCrossOrigin(req, res)) return;
        const account = readBody(req)?.account;
        if (!validDemoState(account)) return sendJson(res, 400, { error: 'Invalid demo-account state.' });
        await userRef.update({ demoState: account });
        return sendJson(res, 200, { status: 'saved' });
      }
      return sendJson(res, 405, { error: 'Method not allowed.' });
    }
    return sendJson(res, 404, { error: 'Not found.' });
  } catch (error) {
    console.error('Vercel API request failed:', error);
    return sendJson(res, 500, {
      error: error.code === 'FIREBASE_CREDENTIALS_MISSING'
        ? error.message
        : process.env.NODE_ENV === 'production'
          ? 'The account service could not complete this request. Check the Vercel function logs and Firebase configuration.'
          : error.message,
    });
  }
}

export async function createCloudAdmin(username = 'admin') {
  const db = getDatabase();
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    throw new Error('Choose a username that is 3–32 letters, numbers, dots, underscores, or hyphens.');
  }
  const usernameRef = db.collection('usernames').doc(username.toLowerCase());
  const userRef = db.collection('users').doc(crypto.randomUUID());
  const password = crypto.randomBytes(24).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
  await db.runTransaction(async transaction => {
    const existing = await transaction.get(usernameRef);
    if (existing.exists) throw new Error(`The username "${username}" already exists. No existing account was changed.`);
    transaction.create(userRef, {
      username,
      salt,
      passwordHash,
      role: 'admin',
      createdAt: Date.now(),
      demoState: null,
    });
    transaction.create(usernameRef, { userId: userRef.id });
  });
  return password;
}

export async function createCloudInvite(label = 'standard') {
  const db = getDatabase();
  const code = crypto.randomBytes(18).toString('base64url').toUpperCase();
  await db.collection('signup_codes').doc(hash(code)).create({
    label: label.slice(0, 80),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
    usedAt: null,
    createdAt: Date.now(),
  });
  return code;
}
