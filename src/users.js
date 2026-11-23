const bcrypt = require('bcryptjs');

/** Hashes the password (salted bcrypt) and inserts the user with a parameterized query. */
function createUser(db, { username, email, password, role = 'user' }, rounds = 12) {
  const hash = bcrypt.hashSync(password, rounds);
  const info = db
    .prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(username, email, hash, role);
  return { id: Number(info.lastInsertRowid), username, email, role };
}

module.exports = { createUser };
