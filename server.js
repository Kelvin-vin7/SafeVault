const crypto = require('node:crypto');
const { openDatabase } = require('./src/db');
const { createApp } = require('./src/app');
const { createUser } = require('./src/users');
const { validateRegistration } = require('./src/validation');

const db = openDatabase(process.env.DB_FILE || 'safevault.db');

// Secrets come from the environment, never from source code. Without JWT_SECRET a random one is used (tokens end on restart).
const jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
if (!process.env.JWT_SECRET) console.warn('JWT_SECRET not set: using a random secret for this run.');

// Optional first admin: ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD (same rules as normal registration).
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
  const { errors, value } = validateRegistration({
    username: process.env.ADMIN_USERNAME,
    email: process.env.ADMIN_EMAIL || `${process.env.ADMIN_USERNAME}@safevault.local`,
    password: process.env.ADMIN_PASSWORD,
  });
  if (errors.length) { console.error('Invalid admin settings:', errors.map(e => e.message).join(' ')); process.exit(1); }
  if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get(value.username)) {
    createUser(db, { ...value, role: 'admin' });
    console.log(`Admin user "${value.username}" created.`);
  }
}

const port = Number(process.env.PORT) || 3000;
createApp(db, { jwtSecret }).listen(port, () => console.log(`SafeVault listening on http://localhost:${port}`));
