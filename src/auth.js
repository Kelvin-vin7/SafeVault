const jwt = require('jsonwebtoken');

const ISSUER = 'safevault';
const deny = (res, status, code, message) => res.status(status).json({ error: { code, message } });

function signToken(user, secret, expiresIn = '15m') {
  return jwt.sign({ sub: String(user.id) }, secret, { algorithm: 'HS256', issuer: ISSUER, expiresIn });
}

/**
 * Authentication: checks the Bearer token (algorithm pinned to HS256, so "alg: none" tokens are rejected),
 * then loads the user from the database. The role is read from the DATABASE, never from the token,
 * so a tampered or outdated token cannot grant extra privileges.
 */
function requireAuth(db, secret) {
  return (req, res, next) => {
    const match = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!match) return deny(res, 401, 'UNAUTHENTICATED', 'Authentication required.');
    try {
      const payload = jwt.verify(match[1], secret, { algorithms: ['HS256'], issuer: ISSUER });
      const user = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(Number(payload.sub));
      if (!user) return deny(res, 401, 'UNAUTHENTICATED', 'Authentication required.');
      req.user = user;
      next();
    } catch {
      deny(res, 401, 'UNAUTHENTICATED', 'Authentication required.');
    }
  };
}

/** Authorization (RBAC): allow only the listed roles. */
function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.user.role) ? next() : deny(res, 403, 'FORBIDDEN', 'You do not have permission to do this.');
}

module.exports = { signToken, requireAuth, requireRole, deny };
