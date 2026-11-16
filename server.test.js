import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, test } from 'node:test';
import jwt from 'jsonwebtoken';
import {
  ACCESS_TTL_SECONDS,
  createApp,
  DEV_JWT_SECRET,
  REFRESH_TTL_SECONDS,
  resolveJwtSecret
} from './server.js';

const dirs = [];

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'mock-jwt-'));
  dirs.push(dir);
  return dir;
}

function appOptions(extra = {}) {
  return { dataDir: tempDir(), jwtSecret: 'test-secret', logger() {}, ...extra };
}

async function listen(options) {
  const app = createApp(options);
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  const { port } = server.address();
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
  };
}

async function api(base, method, pathname, { body, token, contentType = 'application/json' } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = contentType;
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(base + pathname, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: response.status, json, text, headers: response.headers };
}

async function login(base, email = 'satish@example.com', password = 'Password123!') {
  return api(base, 'POST', '/auth/login', { body: { email, password } });
}

describe('JWT auth', () => {
  test('documents the dev secret and fixed lifetimes', () => {
    const readme = readFileSync(new URL('./README.md', import.meta.url), 'utf8');
    const blueprint = readFileSync(new URL('./render.yaml', import.meta.url), 'utf8');
    assert.match(readme, new RegExp(DEV_JWT_SECRET));
    assert.match(readme, /10 minutes/);
    assert.match(readme, /30 minutes/);
    assert.match(blueprint, /JWT_SECRET/);
    assert.match(blueprint, /generateValue:\s*true/);
    assert.equal(resolveJwtSecret(undefined, undefined), DEV_JWT_SECRET);
    assert.equal(resolveJwtSecret(undefined, '  '), DEV_JWT_SECRET);
    assert.equal(resolveJwtSecret(undefined, ' from-env '), 'from-env');
    assert.equal(ACCESS_TTL_SECONDS, 600);
    assert.equal(REFRESH_TTL_SECONDS, 1800);
  });

  test('login returns access and refresh JWTs without the user object', async () => {
    const options = appOptions();
    const server = await listen(options);
    try {
      const bad = await login(server.base, 'satish@example.com', 'nope');
      assert.equal(bad.status, 401);
      assert.equal(bad.json.error.code, 'INVALID_CREDENTIALS');

      const missing = await api(server.base, 'POST', '/auth/login', { body: { email: 1, password: 'Password123!' } });
      assert.equal(missing.status, 400);
      assert.equal(missing.json.error.code, 'VALIDATION_ERROR');

      const response = await login(server.base);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      const data = response.json.data;
      assert.deepEqual(Object.keys(data), ['AccessToken', 'RefreshToken', 'accessToken', 'tokenType', 'expiresIn']);
      assert.equal(data.accessToken, data.AccessToken);
      assert.equal(data.tokenType, 'Bearer');
      assert.equal(data.expiresIn, 600);
      const access = jwt.verify(data.AccessToken, 'test-secret', { algorithms: ['HS256'] });
      const refresh = jwt.verify(data.RefreshToken, 'test-secret', { algorithms: ['HS256'] });
      assert.equal(access.typ, 'access');
      assert.equal(refresh.typ, 'refresh');
      assert.equal(access.exp - access.iat, 600);
      assert.equal(refresh.exp - refresh.iat, 1800);
      assert.equal(access.sub, '1');
      assert.notEqual(data.AccessToken, data.RefreshToken);

      const stored = readFileSync(join(options.dataDir, 'tokens.json'), 'utf8');
      assert.equal(stored.includes(data.AccessToken), false);
      assert.equal(stored.includes(data.RefreshToken), false);
      assert.match(stored, new RegExp(refresh.jti));
    } finally {
      await server.close();
    }
  });

  test('protected routes accept the access token and reject missing, invalid, and non-access tokens', async () => {
    const server = await listen(appOptions());
    try {
      const health = await api(server.base, 'GET', '/health');
      assert.deepEqual(health.json, { data: { status: 'ok' } });

      const loggedIn = await login(server.base, 'ananya@example.com');
      const { AccessToken, RefreshToken } = loggedIn.json.data;

      const missing = await api(server.base, 'GET', '/users/me');
      assert.equal(missing.status, 401);
      assert.equal(missing.json.error.code, 'UNAUTHORIZED');
      assert.equal(missing.json.error.message, 'A valid bearer token is required');

      const garbage = await api(server.base, 'GET', '/users/me', { token: 'not-a-jwt' });
      assert.equal(garbage.status, 401);
      assert.equal(garbage.json.error.code, 'UNAUTHORIZED');

      const wrongSecret = jwt.sign({ sub: '2', sid: 's', jti: 'j', typ: 'access' }, 'other', {
        algorithm: 'HS256',
        expiresIn: 60
      });
      const forged = await api(server.base, 'GET', '/users/me', { token: wrongSecret });
      assert.equal(forged.status, 401);

      const otherAlg = jwt.sign({ sub: '2', sid: 's', jti: 'j', typ: 'access', exp: Math.floor(Date.now() / 1000) + 60 }, 'test-secret', {
        algorithm: 'HS384'
      });
      const rejectedAlg = await api(server.base, 'GET', '/users/me', { token: otherAlg });
      assert.equal(rejectedAlg.status, 401);

      const refreshAsAccess = await api(server.base, 'GET', '/users/me', { token: RefreshToken });
      assert.equal(refreshAsAccess.status, 401);
      assert.equal(refreshAsAccess.json.error.code, 'UNAUTHORIZED');

      const me = await api(server.base, 'GET', '/users/me', { token: AccessToken });
      assert.equal(me.status, 200);
      assert.equal(me.json.data.email, 'ananya@example.com');

      const list = await api(server.base, 'GET', '/users?q=tirupati', { token: AccessToken });
      assert.equal(list.status, 200);
      assert.deepEqual(list.json.data.map((user) => user.id), ['1']);

      const missingUser = await api(server.base, 'GET', '/users/missing', { token: AccessToken });
      assert.equal(missingUser.status, 404);
      assert.equal(missingUser.json.error.code, 'USER_NOT_FOUND');

      const found = await api(server.base, 'GET', '/users/4', { token: AccessToken });
      assert.equal(found.status, 200);
      assert.equal(found.json.data.name, 'Priya');

      const unauthenticatedDelayStarted = Date.now();
      const unauthenticatedDelay = await api(server.base, 'GET', '/users/me?delayMs=5000');
      assert.equal(unauthenticatedDelay.status, 401);
      assert.ok(Date.now() - unauthenticatedDelayStarted < 1000);

      const unauthenticatedFail = await api(server.base, 'GET', '/users/me?fail=500');
      assert.equal(unauthenticatedFail.status, 401);

      const failed = await api(server.base, 'GET', '/users/me?fail=500', { token: AccessToken });
      assert.equal(failed.status, 500);
      assert.equal(failed.json.error.code, 'SERVER_ERROR');

      const badDelay = await api(server.base, 'GET', '/users/me?delayMs=30001', { token: AccessToken });
      assert.equal(badDelay.status, 400);

      const delayStarted = Date.now();
      const delayed = await api(server.base, 'GET', '/users/me?delayMs=40', { token: AccessToken });
      assert.equal(delayed.status, 200);
      assert.ok(Date.now() - delayStarted >= 30);
    } finally {
      await server.close();
    }
  });

  test('refresh rotates the refresh token and a restarted process keeps the store', async () => {
    const options = appOptions();
    const first = await listen(options);
    let issued;
    try {
      issued = (await login(first.base)).json.data;
      const camel = await api(first.base, 'POST', '/auth/refresh', { body: { refreshToken: issued.RefreshToken } });
      assert.equal(camel.status, 200);
      assert.notEqual(camel.json.data.RefreshToken, issued.RefreshToken);
      assert.notEqual(camel.json.data.AccessToken, issued.AccessToken);
      assert.equal(camel.json.data.accessToken, camel.json.data.AccessToken);
      assert.equal(camel.json.data.expiresIn, 600);
      assert.deepEqual(Object.keys(camel.json.data), ['AccessToken', 'RefreshToken', 'accessToken', 'tokenType', 'expiresIn']);

      const replay = await api(first.base, 'POST', '/auth/refresh', { body: { RefreshToken: issued.RefreshToken } });
      assert.equal(replay.status, 401);
      assert.equal(replay.json.error.code, 'UNAUTHORIZED');
      assert.equal(replay.json.error.message, 'Unknown refresh token');

      const oldAccess = await api(first.base, 'GET', '/users/me', { token: issued.AccessToken });
      assert.equal(oldAccess.status, 200);
      const newAccess = await api(first.base, 'GET', '/users', { token: camel.json.data.AccessToken });
      assert.equal(newAccess.status, 200);
      issued = camel.json.data;
    } finally {
      await first.close();
    }

    const restarted = await listen(options);
    try {
      const refreshed = await api(restarted.base, 'POST', '/auth/refresh', { body: { RefreshToken: issued.RefreshToken } });
      assert.equal(refreshed.status, 200);
      const me = await api(restarted.base, 'GET', '/users/me', { token: refreshed.json.data.AccessToken });
      assert.equal(me.status, 200);
      assert.equal(me.json.data.id, '1');

      const accessAsRefresh = await api(restarted.base, 'POST', '/auth/refresh', {
        body: { RefreshToken: refreshed.json.data.AccessToken }
      });
      assert.equal(accessAsRefresh.status, 401);
      assert.equal(accessAsRefresh.json.error.message, 'Unknown refresh token');

      const empty = await api(restarted.base, 'POST', '/auth/refresh', { body: {} });
      assert.equal(empty.status, 400);
      const notJson = await api(restarted.base, 'POST', '/auth/refresh', {
        body: { RefreshToken: 'x' },
        contentType: 'text/plain'
      });
      assert.equal(notJson.status, 415);
    } finally {
      await restarted.close();
    }
  });

  test('logout revokes the access token and refresh token across a restart', async () => {
    const options = appOptions();
    const server = await listen(options);
    let tokens;
    try {
      const firstLogin = (await login(server.base)).json.data;
      const secondLogin = (await login(server.base, 'priya@example.com')).json.data;
      const loggedOut = await api(server.base, 'POST', '/auth/logout', { token: firstLogin.AccessToken });
      assert.equal(loggedOut.status, 200);
      assert.deepEqual(loggedOut.json, { data: { loggedOut: true } });

      const me = await api(server.base, 'GET', '/users/me', { token: firstLogin.AccessToken });
      assert.equal(me.status, 401);
      assert.equal(me.json.error.code, 'UNAUTHORIZED');
      const refresh = await api(server.base, 'POST', '/auth/refresh', { body: { RefreshToken: firstLogin.RefreshToken } });
      assert.equal(refresh.status, 401);
      assert.equal(refresh.json.error.message, 'Unknown refresh token');

      const other = await api(server.base, 'GET', '/users/me', { token: secondLogin.AccessToken });
      assert.equal(other.status, 200);
      assert.equal(other.json.data.email, 'priya@example.com');
      tokens = secondLogin;
    } finally {
      await server.close();
    }

    const restarted = await listen(options);
    try {
      const stillOut = await api(restarted.base, 'GET', '/users/1', { token: tokens.AccessToken });
      assert.equal(stillOut.status, 200);
    } finally {
      await restarted.close();
    }
  });

  test('expired access and refresh tokens are rejected, including after restart', async () => {
    let clock = Date.parse('2026-11-16T00:00:00Z');
    const options = appOptions({ now: () => clock });
    const server = await listen(options);
    let tokens;
    try {
      tokens = (await login(server.base)).json.data;
      clock += ACCESS_TTL_SECONDS * 1000;
      const expiredAccess = await api(server.base, 'GET', '/users/me', { token: tokens.AccessToken });
      assert.equal(expiredAccess.status, 401);
      assert.equal(expiredAccess.json.error.code, 'TOKEN_EXPIRED');
      assert.equal(expiredAccess.json.error.message, 'Token expired. Log in again.');

      const refreshStillValid = await api(server.base, 'POST', '/auth/refresh', {
        body: { RefreshToken: tokens.RefreshToken }
      });
      assert.equal(refreshStillValid.status, 200);
      tokens = refreshStillValid.json.data;
    } finally {
      await server.close();
    }

    clock += REFRESH_TTL_SECONDS * 1000;
    const restarted = await listen(options);
    try {
      const expiredRefresh = await api(restarted.base, 'POST', '/auth/refresh', {
        body: { RefreshToken: tokens.RefreshToken }
      });
      assert.equal(expiredRefresh.status, 401);
      assert.equal(expiredRefresh.json.error.code, 'TOKEN_EXPIRED');
      assert.equal(expiredRefresh.json.error.message, 'Refresh token expired. Log in again.');
    } finally {
      await restarted.close();
    }
  });

  test('logout revocation survives a restart', async () => {
    const options = appOptions();
    const server = await listen(options);
    let tokens;
    try {
      tokens = (await login(server.base)).json.data;
      const loggedOut = await api(server.base, 'POST', '/auth/logout', { token: tokens.AccessToken });
      assert.equal(loggedOut.status, 200);
    } finally {
      await server.close();
    }
    const restarted = await listen(options);
    try {
      const me = await api(restarted.base, 'GET', '/users/me', { token: tokens.AccessToken });
      assert.equal(me.status, 401);
      const refresh = await api(restarted.base, 'POST', '/auth/refresh', { body: { RefreshToken: tokens.RefreshToken } });
      assert.equal(refresh.status, 401);
      assert.equal(refresh.json.error.message, 'Unknown refresh token');
    } finally {
      await restarted.close();
    }
  });

  test('a corrupt token store fails closed', () => {
    const dataDir = tempDir();
    writeFileSync(join(dataDir, 'tokens.json'), '{');
    assert.throws(() => createApp({ dataDir, jwtSecret: 'test-secret', logger() {} }), /not valid JSON/);
  });
});
