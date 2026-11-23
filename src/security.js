/** Output encoding, security headers and a small rate limiter. */

// Encode characters that have meaning in HTML so user text is always displayed, never executed.
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
const escapeHtml = value => String(value).replace(/[&<>"'`]/g, ch => HTML_ESCAPES[ch]);

// Escape LIKE wildcards so a user typing % or _ searches for the literal character.
const escapeLike = value => String(value).replace(/[\\%_]/g, ch => '\\' + ch);

function securityHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Cross-Origin-Resource-Policy': 'same-origin',
  });
  next();
}

/** Fixed-window limiter per client IP (in-memory; use a shared store such as Redis when running several servers). */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip;
    let entry = hits.get(key);
    if (!entry || now >= entry.resetAt) { entry = { count: 0, resetAt: now + windowMs }; hits.set(key, entry); }
    entry.count += 1;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests. Try again later.' } });
    }
    next();
  };
}

module.exports = { escapeHtml, escapeLike, securityHeaders, rateLimit };
