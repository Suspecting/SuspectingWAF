// src/utils/config.js
// loads config from .env and provides defaults for everything
// so the app doesn't crash if someone forgets to set stuff

const path = require('path');
const dotenv = require('dotenv');

// load .env from project root
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  // server ports
  mgtPort: parseInt(process.env.MGT_PORT, 10) || 9443,
  proxyPort: parseInt(process.env.PROXY_PORT, 10) || 80,
  proxySslPort: parseInt(process.env.PROXY_SSL_PORT, 10) || 443,

  // auth
  jwtSecret: process.env.JWT_SECRET || 'default-insecure-secret-change-me',
  jwtExpiry: process.env.JWT_EXPIRY || '24h',
  adminUser: process.env.ADMIN_USER || 'admin',
  adminPass: process.env.ADMIN_PASS || 'suspecting123',

  // database
  dbPath: process.env.DB_PATH || './data/suspecting.db',

  // logging
  logLevel: process.env.LOG_LEVEL || 'info',

  // data dir for certs, logs, etc
  dataDir: process.env.DATA_DIR || './data',

  // waf mode: block, monitor, off
  wafMode: process.env.WAF_MODE || 'block',

  // rate limiting defaults
  defaultRateLimit: parseInt(process.env.DEFAULT_RATE_LIMIT, 10) || 100,
  defaultRateBurst: parseInt(process.env.DEFAULT_RATE_BURST, 10) || 200,
  defaultBanDuration: parseInt(process.env.DEFAULT_BAN_DURATION, 10) || 300,
};

// make sure data dir exists
const fs = require('fs');
const dirs = [
  config.dataDir,
  path.join(config.dataDir, 'certs'),
  path.join(config.dataDir, 'logs'),
];
for (const dir of dirs) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

module.exports = config;
