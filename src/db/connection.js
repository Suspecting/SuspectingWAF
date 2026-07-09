// src/db/connection.js
// SQLite connection setup. We use better-sqlite3 because it's synchronous
// which makes things simpler — no async/await needed for db calls.
// For a self-hosted WAF handling a few hundred RPS, this is fine.

const Database = require('better-sqlite3');
const path = require('path');
const config = require('../utils/config');
const logger = require('../utils/logger');

let db = null;

function getDb() {
  if (db) return db;

  const dbPath = path.resolve(config.dbPath);
  logger.info('Opening database', { path: dbPath });

  db = new Database(dbPath);

  // enable WAL mode for better concurrent read performance
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // reasonable busy timeout so we don't fail immediately on contention
  db.pragma('busy_timeout = 5000');

  return db;
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
    logger.info('Database connection closed');
  }
}

// cleanup on exit
process.on('exit', closeDb);
process.on('SIGINT', () => { closeDb(); process.exit(0); });
process.on('SIGTERM', () => { closeDb(); process.exit(0); });

module.exports = { getDb, closeDb };
