const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('./helpers');

const open = { authLimit: { windowMs: 60_000, max: 1000 } };

test('RBAC: admin can list users; password hashes are never returned', async () => {
  const s = await startServer(open);
  try {
    const admin = await s.login('admin');
    const r = await s.call('GET', '/api/admin/users', { token: admin });
    assert.equal(r.status, 200);
    assert.equal(r.json.users.length, 3);
    assert.ok(!r.text.includes('password_hash') && !r.text.includes('$2'));
  } finally { await s.close(); }
});

test('RBAC: a normal user gets 403 on every admin route', async () => {
  const s = await startServer(open);
  try {
    const alice = await s.login('alice');
    assert.equal((await s.call('GET', '/api/admin/users', { token: alice })).status, 403);
    assert.equal((await s.call('GET', '/api/admin/vault', { token: alice })).status, 403);
    assert.equal((await s.call('DELETE', '/api/admin/users/3', { token: alice })).status, 403);
    assert.equal(s.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 3);   // nothing deleted
  } finally { await s.close(); }
});

test('RBAC: anonymous callers get 401 (not 403) on admin routes', async () => {
  const s = await startServer(open);
  try {
    assert.equal((await s.call('GET', '/api/admin/users')).status, 401);
    assert.equal((await s.call('DELETE', '/api/admin/users/2')).status, 401);
  } finally { await s.close(); }
});

test('RBAC: admin can delete another user (cascade removes their items) but not themselves', async () => {
  const s = await startServer(open);
  try {
    const admin = await s.login('admin');
    const bob = await s.login('bob');
    await s.call('POST', '/api/vault', { token: bob, body: { title: 't', content: 'c' } });
    const bobId = s.db.prepare("SELECT id FROM users WHERE username = 'bob'").get().id;
    const adminId = s.db.prepare("SELECT id FROM users WHERE username = 'admin'").get().id;
    assert.equal((await s.call('DELETE', `/api/admin/users/${adminId}`, { token: admin })).status, 400);
    assert.equal((await s.call('DELETE', `/api/admin/users/${bobId}`, { token: admin })).status, 204);
    assert.equal(s.db.prepare('SELECT COUNT(*) AS n FROM vault_items').get().n, 0);
    assert.equal((await s.call('DELETE', '/api/admin/users/999', { token: admin })).status, 404);
    assert.equal((await s.call('DELETE', '/api/admin/users/abc', { token: admin })).status, 400);
  } finally { await s.close(); }
});

test('authorization: users only see their own vault items', async () => {
  const s = await startServer(open);
  try {
    const alice = await s.login('alice');
    const bob = await s.login('bob');
    await s.call('POST', '/api/vault', { token: alice, body: { title: 'alice only', content: 'a' } });
    const bobList = await s.call('GET', '/api/vault', { token: bob });
    assert.deepEqual(bobList.json.items, []);
  } finally { await s.close(); }
});

test('authorization: opening another user\'s item by id returns 404 (no IDOR)', async () => {
  const s = await startServer(open);
  try {
    const alice = await s.login('alice');
    const bob = await s.login('bob');
    const made = await s.call('POST', '/api/vault', { token: alice, body: { title: 'private', content: 'secret' } });
    const stolen = await s.call('GET', `/api/vault/${made.json.item.id}/view`, { token: bob });
    assert.equal(stolen.status, 404);
    assert.ok(!stolen.text.includes('secret'));
    assert.equal((await s.call('GET', `/api/vault/${made.json.item.id}/view`, { token: alice })).status, 200);
    assert.equal((await s.call('GET', '/api/vault/1%20OR%201=1/view', { token: alice })).status, 404);
  } finally { await s.close(); }
});

test('authorization: a deleted user\'s still-valid token stops working', async () => {
  const s = await startServer(open);
  try {
    const admin = await s.login('admin');
    const bob = await s.login('bob');
    const bobId = s.db.prepare("SELECT id FROM users WHERE username = 'bob'").get().id;
    await s.call('DELETE', `/api/admin/users/${bobId}`, { token: admin });
    assert.equal((await s.call('GET', '/api/vault', { token: bob })).status, 401);
  } finally { await s.close(); }
});
