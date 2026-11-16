import express from 'express';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const users = [
  { id: '1', name: 'Satish', email: 'satish@example.com', city: 'Tirupati' },
  { id: '2', name: 'Ananya', email: 'ananya@example.com', city: 'Bengaluru' },
  { id: '3', name: 'Rahul', email: 'rahul@example.com', city: 'Hyderabad' },
  { id: '4', name: 'Priya', email: 'priya@example.com', city: 'Chennai' }
];

export const ACCESS_TTL_SECONDS = 10 * 60;
export const REFRESH_TTL_SECONDS = 30 * 60;
export const DEV_JWT_SECRET = 'dev-only-jwt-secret-change-me';

const fail = (status, code, message) => Object.assign(new Error(message), { status, code });

function isRecord(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function resolveJwtSecret(override, envValue = process.env.JWT_SECRET) {
  if (override !== undefined) {
    if (typeof override !== 'string' || !override.trim()) {
      throw new Error('jwtSecret must be a non-empty string');
    }
    return override;
  }
  if (typeof envValue === 'string' && envValue.trim()) return envValue.trim();
  return DEV_JWT_SECRET;
}

function emptyState() {
  return { refreshTokens: {}, revokedSessions: {} };
}

function loadStore(file) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`Token store is not valid JSON: ${file}`);
    throw error;
  }
  if (!isRecord(parsed)) throw new Error(`Token store is not valid JSON: ${file}`);
  if (parsed.refreshTokens !== undefined && !isRecord(parsed.refreshTokens)) {
    throw new Error(`Token store is not valid JSON: ${file}`);
  }
  if (parsed.revokedSessions !== undefined && !isRecord(parsed.revokedSessions)) {
    throw new Error(`Token store is not valid JSON: ${file}`);
  }
  const state = emptyState();
  for (const [jti, row] of Object.entries(parsed.refreshTokens ?? {})) {
    if (
      !isRecord(row) ||
      typeof row.userId !== 'string' ||
      typeof row.sid !== 'string' ||
      typeof row.expiresAt !== 'number' ||
      typeof row.revoked !== 'boolean'
    ) {
      throw new Error(`Token store is not valid JSON: ${file}`);
    }
    state.refreshTokens[jti] = {
      userId: row.userId,
      sid: row.sid,
      expiresAt: row.expiresAt,
      revoked: row.revoked
    };
  }
  for (const [sid, expiresAt] of Object.entries(parsed.revokedSessions ?? {})) {
    if (typeof expiresAt !== 'number') throw new Error(`Token store is not valid JSON: ${file}`);
    state.revokedSessions[sid] = expiresAt;
  }
  return state;
}

function saveStore(file, state) {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`);
  renameSync(tmp, file);
}

function prune(state, nowMs) {
  for (const [jti, row] of Object.entries(state.refreshTokens)) {
    if (row.expiresAt <= nowMs) delete state.refreshTokens[jti];
  }
  for (const [sid, expiresAt] of Object.entries(state.revokedSessions)) {
    if (expiresAt <= nowMs) delete state.revokedSessions[sid];
  }
}

function createStore(dataDir, now) {
  mkdirSync(dataDir, { recursive: true });
  const file = join(dataDir, 'tokens.json');
  const existed = existsSync(file);
  const state = existed ? loadStore(file) : emptyState();
  const before = JSON.stringify(state);
  prune(state, now());
  const save = () => {
    prune(state, now());
    saveStore(file, state);
  };
  if (existed && JSON.stringify(state) !== before) save();
  return { state, save };
}

async function readJson(req) {
  if (!req.headers['content-type']?.toLowerCase().startsWith('application/json')) {
    throw fail(415, 'UNSUPPORTED_MEDIA_TYPE', 'Use Content-Type: application/json');
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16384) throw fail(413, 'BODY_TOO_LARGE', 'Maximum body size is 16 KiB');
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error();
    return body;
  } catch {
    throw fail(400, 'INVALID_JSON', 'Expected a JSON object');
  }
}

function bearerFailure(kind) {
  if (kind === 'expired') return fail(401, 'TOKEN_EXPIRED', 'Token expired. Log in again.');
  return fail(401, 'UNAUTHORIZED', 'A valid bearer token is required');
}

function refreshFailure(kind) {
  if (kind === 'expired') return fail(401, 'TOKEN_EXPIRED', 'Refresh token expired. Log in again.');
  return fail(401, 'UNAUTHORIZED', 'Unknown refresh token');
}

export function createApp({
  now = Date.now,
  logger = console.log,
  jwtSecret,
  dataDir = join(process.cwd(), 'data'),
  accessTtlSeconds = ACCESS_TTL_SECONDS,
  refreshTtlSeconds = REFRESH_TTL_SECONDS
} = {}) {
  if (typeof now !== 'function') throw new Error('now must be a function');
  if (!Number.isInteger(accessTtlSeconds) || accessTtlSeconds < 1) {
    throw new Error('accessTtlSeconds must be a positive integer');
  }
  if (!Number.isInteger(refreshTtlSeconds) || refreshTtlSeconds < 1) {
    throw new Error('refreshTtlSeconds must be a positive integer');
  }
  const secret = resolveJwtSecret(jwtSecret);
  const store = createStore(dataDir, now);

  function signToken(claims) {
    return jwt.sign(claims, secret, { algorithm: 'HS256' });
  }

  function readClaims(token, typ, current) {
    const clockTimestamp = Math.floor(current / 1000);
    let payload;
    try {
      payload = jwt.verify(token, secret, {
        algorithms: ['HS256'],
        clockTimestamp,
        ignoreExpiration: true
      });
    } catch {
      return { error: 'invalid' };
    }
    if (!payload || typeof payload !== 'object' || payload.typ !== typ) return { error: 'invalid' };
    if (typeof payload.sub !== 'string' || typeof payload.sid !== 'string' || typeof payload.jti !== 'string') {
      return { error: 'invalid' };
    }
    if (typeof payload.exp !== 'number' || clockTimestamp >= payload.exp) return { error: 'expired' };
    return { payload };
  }

  function sessionRevoked(sid, current) {
    const until = store.state.revokedSessions[sid];
    return typeof until === 'number' && until > current;
  }

  function issueTokens(user, sid) {
    const current = now();
    const iat = Math.floor(current / 1000);
    const accessExp = iat + accessTtlSeconds;
    const refreshExp = iat + refreshTtlSeconds;
    const accessToken = signToken({
      sub: user.id,
      sid,
      jti: randomBytes(16).toString('hex'),
      typ: 'access',
      iat,
      exp: accessExp
    });
    const refreshJti = randomBytes(16).toString('hex');
    const refreshToken = signToken({
      sub: user.id,
      sid,
      jti: refreshJti,
      typ: 'refresh',
      iat,
      exp: refreshExp
    });
    store.state.refreshTokens[refreshJti] = {
      userId: user.id,
      sid,
      expiresAt: refreshExp * 1000,
      revoked: false
    };
    store.save();
    return {
      AccessToken: accessToken,
      RefreshToken: refreshToken,
      accessToken,
      tokenType: 'Bearer',
      expiresIn: accessTtlSeconds
    };
  }

  function requireAccess(req) {
    const current = now();
    const token = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? '')?.[1];
    if (!token) throw bearerFailure('invalid');
    const result = readClaims(token, 'access', current);
    if (result.error) throw bearerFailure(result.error);
    if (sessionRevoked(result.payload.sid, current)) throw bearerFailure('invalid');
    const user = users.find((entry) => entry.id === result.payload.sub);
    if (!user) throw bearerFailure('invalid');
    return { user, claims: result.payload };
  }

  function revokeSession(sid, accessExpMs) {
    let until = accessExpMs;
    for (const row of Object.values(store.state.refreshTokens)) {
      if (row.sid !== sid) continue;
      row.revoked = true;
      if (row.expiresAt > until) until = row.expiresAt;
    }
    const existing = store.state.revokedSessions[sid] ?? 0;
    store.state.revokedSessions[sid] = Math.max(existing, until);
    store.save();
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);

  app.use(async (req, res) => {
    const url = new URL(req.originalUrl || req.url, 'http://localhost');
    const send = (status, body) => {
      if (res.destroyed || res.headersSent) return;
      res.status(status);
      res.set('Content-Type', 'application/json; charset=utf-8');
      res.set('Cache-Control', 'no-store');
      res.send(JSON.stringify(body));
    };
    // Never log passwords, authorization headers, or response tokens.
    res.on('finish', () => logger(`${req.method} ${url.pathname} ${res.statusCode}`));
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        return send(200, { data: { status: 'ok' } });
      }
      if (req.method === 'POST' && url.pathname === '/auth/login') {
        const body = await readJson(req);
        if (typeof body.email !== 'string' || typeof body.password !== 'string') {
          throw fail(400, 'VALIDATION_ERROR', 'email and password must be strings');
        }
        const user = users.find((entry) => entry.email === body.email);
        if (!user || body.password !== 'Password123!') {
          throw fail(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
        }
        return send(200, { data: issueTokens(user, randomBytes(16).toString('hex')) });
      }
      if (req.method === 'POST' && url.pathname === '/auth/refresh') {
        const body = await readJson(req);
        const refreshToken = body.RefreshToken ?? body.refreshToken;
        if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
          throw fail(400, 'VALIDATION_ERROR', 'RefreshToken must be a string');
        }
        const current = now();
        const result = readClaims(refreshToken, 'refresh', current);
        if (result.error) throw refreshFailure(result.error);
        const row = store.state.refreshTokens[result.payload.jti];
        if (
          !row ||
          row.revoked ||
          row.sid !== result.payload.sid ||
          row.userId !== result.payload.sub ||
          sessionRevoked(result.payload.sid, current)
        ) {
          throw refreshFailure('invalid');
        }
        if (row.expiresAt <= current) throw refreshFailure('expired');
        const user = users.find((entry) => entry.id === row.userId);
        if (!user) throw refreshFailure('invalid');
        row.revoked = true;
        return send(200, { data: issueTokens(user, result.payload.sid) });
      }
      const session = requireAccess(req);
      if (req.method === 'POST' && url.pathname === '/auth/logout') {
        revokeSession(session.claims.sid, session.claims.exp * 1000);
        return send(200, { data: { loggedOut: true } });
      }
      // Test controls on protected GET requests only.
      if (req.method === 'GET') {
        const delayMs = Number(url.searchParams.get('delayMs') ?? 0);
        if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 30000) {
          throw fail(400, 'VALIDATION_ERROR', 'delayMs must be an integer from 0 to 30000');
        }
        if (delayMs) {
          const connected = await new Promise(resolve => {
            const onClose = () => { clearTimeout(timer); logger(`CLIENT_DISCONNECTED ${url.pathname}`); resolve(false); };
            const timer = setTimeout(() => { res.off('close', onClose); resolve(true); }, delayMs);
            res.once('close', onClose);
          });
          if (!connected) return;
        }
        if (url.searchParams.get('fail') === '500') throw fail(500, 'SERVER_ERROR', 'Simulated server failure');
      }
      if (req.method === 'GET' && url.pathname === '/users/me') return send(200, { data: session.user });
      if (req.method === 'GET' && url.pathname === '/users') {
        const q = (url.searchParams.get('q') ?? '').trim().toLowerCase();
        return send(200, { data: users.filter(u => `${u.name} ${u.email} ${u.city}`.toLowerCase().includes(q)) });
      }
      if (req.method === 'GET' && /^\/users\/[^/]+$/.test(url.pathname)) {
        const user = users.find(u => u.id === url.pathname.split('/')[2]);
        if (!user) throw fail(404, 'USER_NOT_FOUND', 'User does not exist');
        return send(200, { data: user });
      }
      throw fail(404, 'NOT_FOUND', 'Endpoint does not exist');
    } catch (error) {
      send(error.status ?? 500, {
        error: {
          code: error.code ?? 'INTERNAL_ERROR',
          message: error.status ? error.message : 'Unexpected server error'
        }
      });
    }
  });

  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 0) throw new Error('PORT must be a non-negative integer');
  const secretSource = process.env.JWT_SECRET?.trim() ? 'JWT_SECRET' : 'dev fallback';
  const app = createApp();
  app.listen(port, '0.0.0.0', () => {
    console.log(
      `Mock API listening on 0.0.0.0:${port} (access token ${ACCESS_TTL_SECONDS}s, refresh token ${REFRESH_TTL_SECONDS}s, jwt secret: ${secretSource})`
    );
  });
}
