import express from 'express';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const users = [
  { id: '1', name: 'Satish', email: 'satish@example.com', city: 'Tirupati' },
  { id: '2', name: 'Ananya', email: 'ananya@example.com', city: 'Bengaluru' },
  { id: '3', name: 'Rahul', email: 'rahul@example.com', city: 'Hyderabad' },
  { id: '4', name: 'Priya', email: 'priya@example.com', city: 'Chennai' }
];

const fail = (status, code, message) => Object.assign(new Error(message), { status, code });

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

export function createApp({ tokenTtlSeconds = 300, now = Date.now, logger = console.log } = {}) {
  const sessions = new Map();
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
        const user = users.find(u => u.email === body.email);
        if (!user || body.password !== 'Password123!') {
          throw fail(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
        }
        for (const [key, value] of sessions) if (value.expiresAt <= now()) sessions.delete(key);
        const accessToken = randomBytes(32).toString('hex');
        sessions.set(accessToken, { user, expiresAt: now() + tokenTtlSeconds * 1000 });
        return send(200, { data: { accessToken, tokenType: 'Bearer', expiresIn: tokenTtlSeconds, user } });
      }
      const token = /^Bearer (\S+)$/i.exec(req.headers.authorization ?? '')?.[1];
      const session = token && sessions.get(token);
      if (!session) throw fail(401, 'UNAUTHORIZED', 'A valid bearer token is required');
      if (session.expiresAt <= now()) {
        throw fail(401, 'TOKEN_EXPIRED', 'Token expired. Log in again.');
      }
      if (req.method === 'POST' && url.pathname === '/auth/logout') {
        sessions.delete(token);
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
  const ttl = Number(process.env.TOKEN_TTL_SECONDS ?? 300);
  if (!Number.isInteger(port) || port < 0) throw new Error('PORT must be a non-negative integer');
  if (!Number.isInteger(ttl) || ttl < 1) throw new Error('TOKEN_TTL_SECONDS must be a positive integer');
  const app = createApp({ tokenTtlSeconds: ttl });
  app.listen(port, '0.0.0.0', () => {
    console.log(`Mock API listening on 0.0.0.0:${port} (token lifetime ${ttl}s)`);
  });
}
