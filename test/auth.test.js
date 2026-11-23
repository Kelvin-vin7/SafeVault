const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { startServer, SECRET, PASSWORD } = require('./helpers');

const open = { authLimit: { windowMs: 60_000, max: 1000 } };

test('register: creates a normal user, stores a bcrypt hash and ignores a requested role', async () => {
  const s = await startServer(open);
  try {
    const r = await s.call('POST', '/api/register', { body: { username: 'carol', email: 'carol@example.com', password: PASSWORD, role: 'admin' } });
    assert.equal(r.status, 201);
    assert.equal(r.json.user.role, 'user');
    const row = s.db.prepare('SELECT password_hash, role FROM users WHERE username = ?').get('carol');
    assert.equal(row.role, 'user');
    assert.match(row.password_hash, /^\$2[aby]\$/);
    assert.ok(!row.password_hash.includes(PASSWORD));
    assert.ok(!r.text.includes('password'));
  } finally { await s.close(); }
});

test('register: duplicate username or email gives 409', async () => {
  const s = await startServer(open);
  try {
    assert.equal((await s.call('POST', '/api/register', { body: { username: 'ALICE', email: 'new@example.com', password: PASSWORD } })).status, 409);
    assert.equal((await s.call('POST', '/api/register', { body: { username: 'newuser', email: 'alice@example.com', password: PASSWORD } })).status, 409);
  } finally { await s.close(); }
});

test('login: correct credentials return a token (by username or email)', async () => {
  const s = await startServer(open);
  try {
    assert.ok(await s.login('alice'));
    assert.ok(await s.login('alice@example.com'));
  } finally { await s.close(); }
});

test('login: wrong password and unknown user give the same generic error', async () => {
  const s = await startServer(open);
  try {
    const a = await s.call('POST', '/api/login', { body: { identifier: 'alice', password: 'WrongPassw0rd' } });
    const b = await s.call('POST', '/api/login', { body: { identifier: 'ghost', password: 'WrongPassw0rd' } });
    assert.equal(a.status, 401); assert.equal(b.status, 401);
    assert.deepEqual(a.json, b.json);
  } finally { await s.close(); }
});

test('login: object payloads such as {"$ne": ""} are rejected', async () => {
  const s = await startServer(open);
  try {
    const r = await s.call('POST', '/api/login', { body: { identifier: { $ne: '' }, password: { $ne: '' } } });
    assert.equal(r.status, 400);
  } finally { await s.close(); }
});

test('login: account locks after 5 failed attempts, even for the correct password', async () => {
  const s = await startServer(open);
  try {
    for (let i = 0; i < 5; i++) {
      const r = await s.call('POST', '/api/login', { body: { identifier: 'bob', password: 'WrongPassw0rd' } });
      assert.equal(r.status, 401);
    }
    const locked = await s.call('POST', '/api/login', { body: { identifier: 'bob', password: PASSWORD } });
    assert.equal(locked.status, 423);
    assert.equal(locked.json.error.code, 'ACCOUNT_LOCKED');
  } finally { await s.close(); }
});

test('login: rate limit returns 429 with Retry-After', async () => {
  const s = await startServer({ authLimit: { windowMs: 60_000, max: 3 } });
  try {
    let last;
    for (let i = 0; i < 4; i++) last = await s.call('POST', '/api/login', { body: { identifier: 'ghost', password: 'x' } });
    assert.equal(last.status, 429);
    assert.ok(last.headers.get('retry-after'));
  } finally { await s.close(); }
});

test('protected routes: no token, malformed token and garbage token give 401', async () => {
  const s = await startServer(open);
  try {
    assert.equal((await s.call('GET', '/api/vault')).status, 401);
    assert.equal((await s.call('GET', '/api/vault', { token: 'not.a.jwt' })).status, 401);
    assert.equal((await s.call('GET', '/api/vault', { token: 'Bearer' })).status, 401);
  } finally { await s.close(); }
});

test('tokens: wrong signature, expired, alg=none and wrong issuer are rejected', async () => {
  const s = await startServer(open);
  try {
    const id = s.db.prepare("SELECT id FROM users WHERE username = 'alice'").get().id;
    const forged = jwt.sign({ sub: String(id) }, 'a-different-secret-a-different-secret-1', { algorithm: 'HS256', issuer: 'safevault' });
    const expired = jwt.sign({ sub: String(id) }, SECRET, { algorithm: 'HS256', issuer: 'safevault', expiresIn: -10 });
    const wrongIssuer = jwt.sign({ sub: String(id) }, SECRET, { algorithm: 'HS256', issuer: 'evil' });
    const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: String(id), iss: 'safevault' })}.`;
    for (const token of [forged, expired, wrongIssuer, none])
      assert.equal((await s.call('GET', '/api/vault', { token })).status, 401);
    const good = jwt.sign({ sub: String(id) }, SECRET, { algorithm: 'HS256', issuer: 'safevault', expiresIn: '5m' });
    assert.equal((await s.call('GET', '/api/vault', { token: good })).status, 200);
  } finally { await s.close(); }
});

test('tokens: a "role: admin" claim inside a valid token grants nothing (role comes from the database)', async () => {
  const s = await startServer(open);
  try {
    const id = s.db.prepare("SELECT id FROM users WHERE username = 'alice'").get().id;
    const token = jwt.sign({ sub: String(id), role: 'admin' }, SECRET, { algorithm: 'HS256', issuer: 'safevault', expiresIn: '5m' });
    assert.equal((await s.call('GET', '/api/admin/users', { token })).status, 403);
  } finally { await s.close(); }
});

test('input handling: invalid JSON gives 400 and oversized body gives 413', async () => {
  const s = await startServer(open);
  try {
    assert.equal((await s.call('POST', '/api/login', { raw: '{bad json' })).status, 400);
    const big = await s.call('POST', '/api/register', { body: { username: 'x'.repeat(20000), email: 'a@b.co', password: 'x' } });
    assert.equal(big.status, 413);
  } finally { await s.close(); }
});

test('errors do not leak internals (no stack traces, no SQL)', async () => {
  const s = await startServer(open);
  try {
    const r = await s.call('GET', '/api/does-not-exist');
    assert.equal(r.status, 404);
    assert.ok(!/at .*\.js|SELECT|sqlite/i.test(r.text));
  } finally { await s.close(); }
});
