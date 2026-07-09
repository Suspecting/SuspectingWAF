// src/utils/logger.js
// simple structured logger, writes to stdout and optionally to file
// nothing fancy, just gets the job done

const fs = require('fs');
const path = require('path');
const config = require('./config');

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLevel = LOG_LEVELS[config.logLevel] || LOG_LEVELS.info;

// log file path — we rotate daily but that's a TODO for later
const logFile = path.join(config.dataDir, 'logs', 'suspecting.log');
let logStream = null;

try {
  logStream = fs.createWriteStream(logFile, { flags: 'a' });
} catch (err) {
  // if we can't write to file, just use stdout
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

  // always write to stdout
  if (level === 'error') {
    process.stderr.write(line + '\n');
  } else {
    process.stdout.write(line + '\n');
  }

  // write to file if we have a stream
  if (logStream && !logStream.destroyed) {
    logStream.write(line + '\n');
  }
}

module.exports = {
  debug: (msg, meta) => log('debug', msg, meta),
  info: (msg, meta) => log('info', msg, meta),
  warn: (msg, meta) => log('warn', msg, meta),
  error: (msg, meta) => log('error', msg, meta),

  // convenience method for request logging
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
