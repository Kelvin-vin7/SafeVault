const express = require('express');
const bcrypt = require('bcryptjs');
const { validateRegistration, validateLogin, validateVaultItem, validateSearchTerm } = require('./validation');
const { escapeHtml, escapeLike, securityHeaders, rateLimit } = require('./security');
const { signToken, requireAuth, requireRole, deny } = require('./auth');
const { createUser } = require('./users');

const MAX_FAILED_LOGINS = 5;
const LOCK_MS = 15 * 60 * 1000;
// Hash of a throw-away password: compared when the user does not exist so response time does not reveal valid usernames.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

function createApp(db, { jwtSecret, bcryptRounds = 12, authLimit = { windowMs: 60_000, max: 20 } } = {}) {
  if (!jwtSecret || jwtSecret.length < 32) throw new Error('jwtSecret (at least 32 characters) is required');
  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(express.json({ limit: '10kb' }));

  const auth = requireAuth(db, jwtSecret);
  const limiter = rateLimit(authLimit);

  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

  // ---- Activity 1: registration with input validation + parameterized INSERT -------------------
  app.post('/api/register', limiter, (req, res) => {
    const { errors, value } = validateRegistration(req.body);
    if (errors.length) return res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Invalid input.', details: errors } });
    try {
      const user = createUser(db, value, bcryptRounds);   // role is always 'user' here
      res.status(201).json({ user });
    } catch (e) {
      if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return deny(res, 409, 'CONFLICT', 'Username or email is already registered.');
      throw e;
    }
  });

  // ---- Activity 2: authentication (bcrypt, JWT, lockout, generic errors) ----------------------
  app.post('/api/login', limiter, (req, res) => {
    const { error, value } = validateLogin(req.body);
    if (error) return deny(res, 400, 'BAD_REQUEST', error);
    const invalid = () => deny(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password.'); // same message for every failure
    // Parameterized query: the identifier is bound as data and can never change the SQL.
    const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(value.identifier, value.identifier);
    if (!user) { bcrypt.compareSync(value.password, DUMMY_HASH); return invalid(); }
    if (user.locked_until > Date.now()) return deny(res, 423, 'ACCOUNT_LOCKED', 'Account temporarily locked. Try again later.');
    if (!bcrypt.compareSync(value.password, user.password_hash)) {
      const failed = user.failed_logins + 1;
      const lockedUntil = failed >= MAX_FAILED_LOGINS ? Date.now() + LOCK_MS : 0;
      db.prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?').run(lockedUntil ? 0 : failed, lockedUntil, user.id);
      return invalid();
    }
    db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(user.id);
    res.json({ token: signToken(user, jwtSecret), user: { id: user.id, username: user.username, role: user.role } });
  });

  // ---- Vault items: any authenticated user, but only THEIR OWN data -------------------------
  app.post('/api/vault', auth, (req, res) => {
    const { errors, value } = validateVaultItem(req.body);
    if (errors.length) return res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Invalid input.', details: errors } });
    const info = db.prepare('INSERT INTO vault_items (user_id, title, content) VALUES (?, ?, ?)').run(req.user.id, value.title, value.content);
    res.status(201).json({ item: { id: Number(info.lastInsertRowid), ...value } });
  });

  app.get('/api/vault', auth, (req, res) => {
    res.json({ items: db.prepare('SELECT id, title, content, created_at FROM vault_items WHERE user_id = ? ORDER BY id').all(req.user.id) });
  });

  // Search: the term is validated, LIKE wildcards are escaped, and it is passed as a bound parameter.
  app.get('/api/vault/search', auth, (req, res) => {
    const { error, value } = validateSearchTerm(req.query.q);
    if (error) return deny(res, 400, 'BAD_REQUEST', error);
    const items = db
      .prepare("SELECT id, title, content FROM vault_items WHERE user_id = ? AND (title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\') ORDER BY id")
      .all(req.user.id, `%${escapeLike(value)}%`, `%${escapeLike(value)}%`);
    res.json({ items });
  });

  // HTML view: every user-controlled value is HTML-encoded, so stored XSS payloads are shown as text.
  app.get('/api/vault/:id/view', auth, (req, res) => {
    const id = Number(req.params.id);
    const item = Number.isInteger(id) ? db.prepare('SELECT * FROM vault_items WHERE id = ? AND user_id = ?').get(id, req.user.id) : undefined;
    if (!item) return deny(res, 404, 'NOT_FOUND', 'Item not found.');   // 404 (not 403) so other users' ids are not revealed
    res.type('html').send(`<!doctype html><meta charset="utf-8"><title>${escapeHtml(item.title)}</title><h1>${escapeHtml(item.title)}</h1><p>${escapeHtml(item.content)}</p>`);
  });

  // ---- Activity 2: RBAC - admin only -----------------------------------------------------------
  const adminOnly = [auth, requireRole('admin')];

  app.get('/api/admin/users', ...adminOnly, (req, res) => {
    res.json({ users: db.prepare('SELECT id, username, email, role, created_at FROM users ORDER BY id').all() });
  });

  app.get('/api/admin/vault', ...adminOnly, (req, res) => {
    res.json({ items: db.prepare('SELECT id, user_id, title FROM vault_items ORDER BY id').all() });
  });

  app.delete('/api/admin/users/:id', ...adminOnly, (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return deny(res, 400, 'BAD_REQUEST', 'Invalid id.');
    if (id === req.user.id) return deny(res, 400, 'BAD_REQUEST', 'You cannot delete your own account.');
    const info = db.prepare('DELETE FROM users WHERE id = ?').run(id);
    if (!info.changes) return deny(res, 404, 'NOT_FOUND', 'User not found.');
    res.status(204).end();
  });

  app.use((req, res) => deny(res, 404, 'NOT_FOUND', 'Route not found.'));
  // Error handler: never leak stack traces or SQL errors to the client.
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') return deny(res, 400, 'INVALID_JSON', 'Request body is not valid JSON.');
    if (err.type === 'entity.too.large') return deny(res, 413, 'PAYLOAD_TOO_LARGE', 'Request body is too large.');
    console.error(err);
    deny(res, 500, 'SERVER_ERROR', 'Something went wrong.');
  });
  return app;
}

module.exports = { createApp };
