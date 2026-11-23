/**
 * Input validation (allow-list approach): accept only what is expected,
 * reject everything else. Validation is a first layer; the real protection
 * against SQL injection is parameterized queries and against XSS is output encoding.
 */
const USERNAME = /^[A-Za-z0-9_]{3,30}$/;
const EMAIL = /^[^\s@<>"'`;()\\]+@[^\s@<>"'`;()\\]+\.[A-Za-z]{2,}$/;

// control characters except tab (\t), line feed (\n) and carriage return (\r)
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

const clean = value => String(value).replace(CONTROL_CHARS, '').trim();
const isText = value => typeof value === 'string';

function validateRegistration(body) {
  const b = body && typeof body === 'object' ? body : {};
  const errors = [];
  // NOTE: only these three fields are ever read. A "role" sent by the client is ignored (no mass assignment).
  const username = isText(b.username) ? clean(b.username) : '';
  const email = isText(b.email) ? clean(b.email) : '';
  const password = isText(b.password) ? b.password : '';

  if (!USERNAME.test(username))
    errors.push({ field: 'username', message: 'Username must be 3-30 characters: letters, digits or underscore only.' });
  if (email.length > 254 || !EMAIL.test(email))
    errors.push({ field: 'email', message: 'Email address is not valid.' });
  if (password.length < 10 || password.length > 72 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password))
    errors.push({ field: 'password', message: 'Password must be 10-72 characters with upper-case, lower-case and a digit.' });

  return { errors, value: { username, email, password } };
}

function validateLogin(body) {
  const b = body && typeof body === 'object' ? body : {};
  // Must be plain strings (blocks object/array payloads such as {"$ne": ""}) with sane lengths.
  if (!isText(b.identifier) || !isText(b.password)) return { error: 'identifier and password are required.' };
  if (b.identifier.length === 0 || b.identifier.length > 254 || b.password.length === 0 || b.password.length > 72)
    return { error: 'identifier and password are required.' };
  return { value: { identifier: clean(b.identifier), password: b.password } };
}

function validateVaultItem(body) {
  const b = body && typeof body === 'object' ? body : {};
  const errors = [];
  const title = isText(b.title) ? clean(b.title) : '';
  const content = isText(b.content) ? clean(b.content) : '';
  if (title.length < 1 || title.length > 100) errors.push({ field: 'title', message: 'Title must be 1-100 characters.' });
  if (content.length < 1 || content.length > 2000) errors.push({ field: 'content', message: 'Content must be 1-2000 characters.' });
  return { errors, value: { title, content } };
}

function validateSearchTerm(q) {
  if (q === undefined) return { value: '' };
  if (!isText(q)) return { error: 'q must be a single text value.' };   // blocks ?q[]=a&q[]=b
  const term = clean(q);
  if (term.length > 50) return { error: 'q must be at most 50 characters.' };
  return { value: term };
}

module.exports = { validateRegistration, validateLogin, validateVaultItem, validateSearchTerm, clean };
