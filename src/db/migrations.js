// src/db/migrations.js
// creates all the tables we need on first run
// idempotent — safe to run multiple times (uses IF NOT EXISTS)

const { getDb } = require('./connection');
const { hashPassword } = require('../utils/crypto');
const config = require('../utils/config');
const logger = require('../utils/logger');

async function runMigrations() {
  const db = getDb();

  logger.info('Running database migrations...');

  // admin users
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      api_key TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )
  `);

  // protected sites (upstream backends)
  db.exec(`
    CREATE TABLE IF NOT EXISTS sites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      listen_port INTEGER NOT NULL DEFAULT 80,
      upstream_url TEXT NOT NULL,
      server_names TEXT DEFAULT '',
      ssl_enabled INTEGER DEFAULT 0,
      cert_id INTEGER,
      waf_enabled INTEGER DEFAULT 1,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // attack logs — this is the big one, needs indexes
  db.exec(`
    CREATE TABLE IF NOT EXISTS attack_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      src_ip TEXT,
      method TEXT,
      host TEXT,
      url TEXT,
      rule_id TEXT,
      rule_name TEXT,
      severity TEXT DEFAULT 'medium',
      payload TEXT,
      action TEXT DEFAULT 'blocked',
      user_agent TEXT,
      request_headers TEXT,
      response_code INTEGER,
      FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE SET NULL
    )
  `);

  // indexes for attack_logs — queries hit these columns a lot
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON attack_logs(timestamp)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON attack_logs(src_ip)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_rule_id ON attack_logs(rule_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_site_id ON attack_logs(site_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_severity ON attack_logs(severity)`);

  // custom rules (user-defined block/allow)
  db.exec(`
    CREATE TABLE IF NOT EXISTS custom_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      type TEXT NOT NULL DEFAULT 'block',
      field TEXT NOT NULL DEFAULT 'ip',
      operator TEXT NOT NULL DEFAULT 'equals',
      value TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      priority INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // IP blocklist / allowlist
  db.exec(`
    CREATE TABLE IF NOT EXISTS ip_list (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'block',
      reason TEXT DEFAULT '',
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iplist_ip ON ip_list(ip)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_iplist_type ON ip_list(type)`);

  // SSL certificates
  db.exec(`
    CREATE TABLE IF NOT EXISTS certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      domain TEXT NOT NULL,
      cert_path TEXT,
      key_path TEXT,
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // rate limit configuration
  db.exec(`
    CREATE TABLE IF NOT EXISTS rate_limits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER,
      requests_per_second INTEGER DEFAULT 100,
      burst INTEGER DEFAULT 200,
      ban_duration INTEGER DEFAULT 300,
      enabled INTEGER DEFAULT 1,
      FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
    )
  `);

  // aggregated request stats — filled by a background job
  db.exec(`
    CREATE TABLE IF NOT EXISTS request_stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER,
      bucket DATETIME NOT NULL,
      total_requests INTEGER DEFAULT 0,
      blocked_requests INTEGER DEFAULT 0,
      unique_ips INTEGER DEFAULT 0,
      avg_response_time REAL DEFAULT 0
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_stats_bucket ON request_stats(bucket)`);

  // global settings (key-value store)
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

  // seed default admin user if none exists
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    const hash = await hashPassword(config.adminPass);
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(
      config.adminUser,
      hash
    );
    logger.info('Created default admin user', { username: config.adminUser });
  }

  // seed default settings
  const settingsCount = db.prepare('SELECT COUNT(*) as count FROM settings').get();
  if (settingsCount.count === 0) {
    const defaults = {
      waf_mode: config.wafMode,
      log_retention_days: '30',
      stats_interval: '60',
      block_page_title: 'Request Blocked — SuspectingWAF',
      block_page_message: 'Your request has been blocked by the web application firewall.',
    };
    const insert = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
    for (const [key, value] of Object.entries(defaults)) {
      insert.run(key, value);
    }
    logger.info('Seeded default settings');
  }

  logger.info('Migrations complete');
}

module.exports = { runMigrations };

// if run directly: node src/db/migrations.js
if (require.main === module) {
  runMigrations().then(() => {
    console.log('Done.');
    process.exit(0);
  }).catch(err => {
    console.error('Migration failed:', err);
    process.exit(1);
  });
}
