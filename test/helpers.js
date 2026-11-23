const { openDatabase } = require('../src/db');
const { createApp } = require('../src/app');
const { createUser } = require('../src/users');

const SECRET = 'test-secret-test-secret-test-secret-123456';
const PASSWORD = 'Str0ngPassw0rd!';

/** Fresh in-memory database + server on a random port, with an admin, alice and bob. */
async function startServer(options = {}) {
  const db = openDatabase(':memory:');
  createUser(db, { username: 'admin', email: 'admin@example.com', password: PASSWORD, role: 'admin' }, 4);
  createUser(db, { username: 'alice', email: 'alice@example.com', password: PASSWORD }, 4);
  createUser(db, { username: 'bob', email: 'bob@example.com', password: PASSWORD }, 4);
  const app = createApp(db, { jwtSecret: SECRET, bcryptRounds: 4, ...options });
  const server = await new Promise(resolve => { const s = app.listen(0, () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  async function call(method, path, { token, body, raw } = {}) {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined || raw !== undefined) headers['content-type'] = 'application/json';
    const res = await fetch(base + path, { method, headers, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)) });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, headers: res.headers, text, json };
  }
  async function login(identifier, password = PASSWORD) {
    const r = await call('POST', '/api/login', { body: { identifier, password } });
    return r.json && r.json.token;
  }
  return { db, call, login, close: () => new Promise(r => server.close(r)) };
}

module.exports = { startServer, SECRET, PASSWORD };
