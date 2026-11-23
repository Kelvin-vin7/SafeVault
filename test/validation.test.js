const test = require('node:test');
const assert = require('node:assert/strict');
const { validateRegistration, validateLogin, validateVaultItem, validateSearchTerm } = require('../src/validation');
const { escapeHtml, escapeLike } = require('../src/security');

const good = { username: 'alice_01', email: 'alice@example.com', password: 'Str0ngPassw0rd!' };
const fields = r => r.errors.map(e => e.field);

test('registration: valid input is accepted', () => {
  assert.deepEqual(validateRegistration(good).errors, []);
});

test('registration: injection and script characters in username are rejected', () => {
  for (const username of ["admin'--", "x' OR '1'='1", 'a;DROP TABLE users', '<script>alert(1)</script>', 'a b', 'ab', 'a'.repeat(31)])
    assert.ok(fields(validateRegistration({ ...good, username })).includes('username'), username);
});

test('registration: malformed or dangerous emails are rejected', () => {
  for (const email of ['not-an-email', 'a@b', "o'brien@example.com", '<x>@example.com', 'a@b.com;DROP', ''])
    assert.ok(fields(validateRegistration({ ...good, email })).includes('email'), email);
});

test('registration: weak passwords are rejected', () => {
  for (const password of ['short1A', 'alllowercase123', 'ALLUPPERCASE123', 'NoDigitsHereAtAll', 'x'.repeat(73)])
    assert.ok(fields(validateRegistration({ ...good, password })).includes('password'), password);
});

test('registration: non-string values (objects, arrays, numbers) are rejected', () => {
  for (const bad of [{ $ne: '' }, ['alice'], 42, null])
    assert.ok(validateRegistration({ ...good, username: bad }).errors.length > 0);
  assert.ok(validateRegistration(null).errors.length === 3);
});

test('registration: a client-supplied role is never read (no mass assignment)', () => {
  const r = validateRegistration({ ...good, role: 'admin' });
  assert.equal(r.value.role, undefined);
});

test('login: only plain strings with sane length are accepted', () => {
  assert.ok(validateLogin({ identifier: { $ne: '' }, password: 'x' }).error);
  assert.ok(validateLogin({ identifier: 'a', password: ['x'] }).error);
  assert.ok(validateLogin({ identifier: '', password: 'x' }).error);
  assert.ok(validateLogin({ identifier: 'a'.repeat(300), password: 'x' }).error);
  assert.ok(validateLogin({ identifier: 'alice', password: 'x'.repeat(100) }).error);
  assert.ok(validateLogin({ identifier: 'alice', password: 'x' }).value);
});

test('vault item: length limits and control characters', () => {
  assert.equal(validateVaultItem({ title: '', content: 'x' }).errors.length, 1);
  assert.equal(validateVaultItem({ title: 'x'.repeat(101), content: 'x' }).errors.length, 1);
  assert.equal(validateVaultItem({ title: 'ok', content: 'x'.repeat(2001) }).errors.length, 1);
  assert.equal(validateVaultItem({ title: 'a\u0000b', content: 'x' }).value.title, 'ab');   // NUL byte stripped
});

test('search term: arrays and long values are rejected', () => {
  assert.ok(validateSearchTerm(['a', 'b']).error);
  assert.ok(validateSearchTerm('x'.repeat(51)).error);
  assert.equal(validateSearchTerm(undefined).value, '');
});

test('escapeHtml encodes every dangerous character', () => {
  assert.equal(escapeHtml(`<script>alert("x")</script>`), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
  assert.equal(escapeHtml(`'"&\`<>`), '&#39;&quot;&amp;&#96;&lt;&gt;');
  assert.equal(escapeHtml('<img src=x onerror=alert(1)>').includes('<'), false);
});

test('escapeLike neutralises LIKE wildcards', () => {
  assert.equal(escapeLike('100%_done\\'), '100\\%\\_done\\\\');
});
