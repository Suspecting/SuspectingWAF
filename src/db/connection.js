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
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
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
process.on('exit', closeDb);
process.on('SIGINT', () => { closeDb(); process.exit(0); });
process.on('SIGTERM', () => { closeDb(); process.exit(0); });

module.exports = { getDb, closeDb };
