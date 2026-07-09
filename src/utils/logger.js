const fs = require('fs');
const path = require('path');
const config = require('./config');

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLevel = LOG_LEVELS[config.logLevel] || LOG_LEVELS.info;
const logFile = path.join(config.dataDir, 'logs', 'suspecting.log');
let logStream = null;

try {
  logStream = fs.createWriteStream(logFile, { flags: 'a' });
} catch (err) {
  console.error('Failed to open log file:', err.message);
}

function formatTimestamp() {
  return new Date().toISOString();
}

function log(level, msg, meta = {}) {
  if (LOG_LEVELS[level] < currentLevel) return;

  const entry = {
    time: formatTimestamp(),
    level: level.toUpperCase(),
    msg,
    ...meta,
  };

  const line = JSON.stringify(entry);
  if (level === 'error') {
    process.stderr.write(line + '\n');
  } else {
    process.stdout.write(line + '\n');
  }
  if (logStream && !logStream.destroyed) {
    logStream.write(line + '\n');
  }
}

module.exports = {
  debug: (msg, meta) => log('debug', msg, meta),
  info: (msg, meta) => log('info', msg, meta),
  warn: (msg, meta) => log('warn', msg, meta),
  error: (msg, meta) => log('error', msg, meta),
  req: (req, extra = {}) => {
    log('info', 'request', {
      method: req.method,
      url: req.url,
      ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress,
      ua: req.headers['user-agent'],
      ...extra,
    });
  },
};
