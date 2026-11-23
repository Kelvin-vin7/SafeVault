/**
 * SQL injection tests.
 * Part 1 shows WHY the original code was dangerous (string concatenation) using a deliberately vulnerable copy.
 * Part 2 proves the fixed code (parameterized queries) is not affected, directly and through the HTTP API.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/db');
const { createUser } = require('../src/users');
const { startServer, PASSWORD } = require('./helpers');

const PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1 --",
  "admin'--",
  "'; DROP TABLE users; --",
  "' UNION SELECT id, username, password_hash FROM users --",
  "x' OR username LIKE '%",
  "' UNION SELECT 1,2,3 --",
];

// The ORIGINAL (vulnerable) approach: user input glued into the SQL text. Kept ONLY to demonstrate the bug.
function vulnerableLogin(db, username) {
  return db.prepare(`SELECT * FROM users WHERE username = '${username}'`).get();
}
// The FIXED approach: user input is bound as a parameter.
function fixedLogin(db, username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

test('BEFORE the fix: concatenated SQL lets "\' OR \'1\'=\'1" log in without a username', () => {
  const db = openDatabase(':memory:');
  createUser(db, { username: 'alice', email: 'a@example.com', password: PASSWORD }, 4);
  const row = vulnerableLogin(db, "nobody' OR '1'='1");
  assert.ok(row, 'injection returned a user although the username does not exist');
  assert.equal(row.username, 'alice');
});

test('BEFORE the fix: "admin\'--" comments out the rest of the query', () => {
  const db = openDatabase(':memory:');
  createUser(db, { username: 'admin', email: 'a@example.com', password: PASSWORD, role: 'admin' }, 4);
  assert.equal(vulnerableLogin(db, "admin'--").username, 'admin');
});

test('AFTER the fix: parameterized query treats every payload as plain text', () => {
  const db = openDatabase(':memory:');
  createUser(db, { username: 'alice', email: 'a@example.com', password: PASSWORD }, 4);
  for (const p of PAYLOADS) assert.equal(fixedLogin(db, p), undefined, p);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 1);   // table still exists, nothing dropped
});

test('API login: injection payloads cannot authenticate', async () => {
  const s = await startServer({ authLimit: { windowMs: 60_000, max: 1000 } });
  try {
    for (const p of PAYLOADS) {
      const r = await s.call('POST', '/api/login', { body: { identifier: p, password: p } });
      assert.equal(r.status, 401, p);
      assert.equal(r.json.error.code, 'INVALID_CREDENTIALS');
    }
    assert.equal(s.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 3);
  } finally { await s.close(); }
});

test('API login: injection inside the password field does not bypass the check', async () => {
  const s = await startServer({ authLimit: { windowMs: 60_000, max: 1000 } });
  try {
    const r = await s.call('POST', '/api/login', { body: { identifier: 'alice', password: "' OR '1'='1" } });
    assert.equal(r.status, 401);
  } finally { await s.close(); }
});

test('API search: payloads return nothing extra and never expose other users\' data', async () => {
  const s = await startServer({ authLimit: { windowMs: 60_000, max: 1000 } });
  try {
    const alice = await s.login('alice');
    const bob = await s.login('bob');
    await s.call('POST', '/api/vault', { token: alice, body: { title: 'alice note', content: 'public text' } });
    await s.call('POST', '/api/vault', { token: bob, body: { title: 'bob secret', content: 'TOP-SECRET-BOB' } });
    for (const p of PAYLOADS) {
      const r = await s.call('GET', `/api/vault/search?q=${encodeURIComponent(p)}`, { token: alice });
      // Either rejected by validation (too long -> 400) or searched literally (-> 200 with no results).
      assert.ok([200, 400].includes(r.status), p);
      if (r.status === 200) assert.deepEqual(r.json.items, [], p);
      assert.ok(!r.text.includes('TOP-SECRET-BOB'));
      assert.ok(!r.text.includes('password_hash') && !r.text.includes('$2'));
    }
    const ok = await s.call('GET', '/api/vault/search?q=alice', { token: alice });
    assert.equal(ok.json.items.length, 1);
  } finally { await s.close(); }
});

test('API search: LIKE wildcards are matched literally', async () => {
  const s = await startServer();
  try {
    const alice = await s.login('alice');
    await s.call('POST', '/api/vault', { token: alice, body: { title: 'plain', content: 'abc' } });
    await s.call('POST', '/api/vault', { token: alice, body: { title: '100% done', content: 'x' } });
    const all = await s.call('GET', '/api/vault/search?q=%25', { token: alice });   // q="%"
    assert.equal(all.json.items.length, 1);
    assert.equal(all.json.items[0].title, '100% done');
  } finally { await s.close(); }
});

test('API register: injection in username/email is rejected by validation and stored nowhere', async () => {
  const s = await startServer({ authLimit: { windowMs: 60_000, max: 1000 } });
  try {
    const r = await s.call('POST', '/api/register', { body: { username: "x'; DROP TABLE users;--", email: 'x@example.com', password: PASSWORD } });
    assert.equal(r.status, 422);
    assert.equal(s.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 3);
  } finally { await s.close(); }
});

test('stored text with quotes is saved literally (parameter binding), not executed', async () => {
  const s = await startServer();
  try {
    const alice = await s.login('alice');
    const title = "Robert'); DROP TABLE vault_items;--";
    const r = await s.call('POST', '/api/vault', { token: alice, body: { title, content: "it's fine" } });
    assert.equal(r.status, 201);
    const list = await s.call('GET', '/api/vault', { token: alice });
    assert.equal(list.json.items[0].title, title);
  } finally { await s.close(); }
});
