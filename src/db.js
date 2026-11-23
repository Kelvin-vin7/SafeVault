const Database = require('better-sqlite3');

/** Opens the database and creates the schema. Use ':memory:' for tests. */
function openDatabase(file = ':memory:') {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');            // enforce relations (deleting a user deletes their items)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
      email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,                       -- bcrypt hash, never the password
      role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until  INTEGER NOT NULL DEFAULT 0,          -- epoch milliseconds
      created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS vault_items (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT NOT NULL,
      content    TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_vault_user ON vault_items(user_id);
  `);
  return db;
}

module.exports = { openDatabase };
