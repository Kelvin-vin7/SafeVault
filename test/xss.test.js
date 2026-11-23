const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('./helpers');

const XSS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '"><svg/onload=alert(1)>',
  "'><iframe src=javascript:alert(1)>",
];

test('stored XSS: HTML view encodes title and content', async () => {
  const s = await startServer();
  try {
    const alice = await s.login('alice');
    for (const payload of XSS) {
      const created = await s.call('POST', '/api/vault', { token: alice, body: { title: payload, content: payload } });
      assert.equal(created.status, 201);
      const view = await s.call('GET', `/api/vault/${created.json.item.id}/view`, { token: alice });
      assert.equal(view.status, 200);
      assert.match(view.headers.get('content-type'), /text\/html/);
      // Apart from our own fixed tags, no raw "<" from user input may appear.
      const userPart = view.text.replace(/<!doctype html>|<meta charset="utf-8">|<\/?title>|<\/?h1>|<\/?p>/g, '');
      assert.ok(!userPart.includes('<'), `raw "<" found for ${payload}`);
      assert.ok(!/<script/i.test(view.text) && !/<img/i.test(view.text) && !/<svg/i.test(view.text) && !/<iframe/i.test(view.text));
      assert.ok(view.text.includes('&lt;'));
    }
  } finally { await s.close(); }
});

test('responses carry a locked-down Content-Security-Policy and anti-sniffing headers', async () => {
  const s = await startServer();
  try {
    const r = await s.call('GET', '/api/health');
    assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('x-powered-by'), null);
  } finally { await s.close(); }
});

test('JSON API responses are served as application/json (never as HTML)', async () => {
  const s = await startServer();
  try {
    const alice = await s.login('alice');
    await s.call('POST', '/api/vault', { token: alice, body: { title: '<b>x</b>', content: 'y' } });
    const r = await s.call('GET', '/api/vault', { token: alice });
    assert.match(r.headers.get('content-type'), /application\/json/);
  } finally { await s.close(); }
});
