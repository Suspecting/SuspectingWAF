// src/engine/ratelimit.js
// per-IP rate limiting using a sliding window counter
// stored in memory — resets on process restart, which is fine for this use case
// if you need persistence, swap the Map for a Redis store or whatever

const logger = require('../utils/logger');
const config = require('../utils/config');

// { ip: { count: number, windowStart: timestamp, banned: boolean, bannedUntil: timestamp } }
const counters = new Map();

// cleanup old entries every 5 minutes so we don't leak memory
const CLEANUP_INTERVAL = 5 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of counters) {
    // remove entries that haven't been seen in 10 minutes and aren't banned
    if (now - data.windowStart > 600000 && !data.banned) {
      counters.delete(ip);
    }
    // lift expired bans
    if (data.banned && data.bannedUntil && now > data.bannedUntil) {
      data.banned = false;
      data.count = 0;
      data.windowStart = now;
    }
  }
}, CLEANUP_INTERVAL);

/**
 * Check if an IP has exceeded the rate limit
 * @param {string} ip - client IP address
 * @param {object} limits - { rps, burst, banDuration } override for this site
 * @returns {{ limited: boolean, remaining: number, retryAfter?: number }}
 */
function checkRateLimit(ip, limits = {}) {
  const rps = limits.rps || config.defaultRateLimit;
  const burst = limits.burst || config.defaultRateBurst;
  const banDuration = (limits.banDuration || config.defaultBanDuration) * 1000; // convert to ms

  const now = Date.now();

  if (!counters.has(ip)) {
    counters.set(ip, { count: 1, windowStart: now, banned: false, bannedUntil: null });
    return { limited: false, remaining: rps - 1 };
  }

  const data = counters.get(ip);

  // if currently banned, reject
  if (data.banned) {
    if (data.bannedUntil && now > data.bannedUntil) {
      // ban expired, reset
      data.banned = false;
      data.count = 1;
      data.windowStart = now;
      return { limited: false, remaining: rps - 1 };
    }
    const retryAfter = Math.ceil((data.bannedUntil - now) / 1000);
    return { limited: true, remaining: 0, retryAfter };
  }

  // sliding window: if we're in the same second, increment
  const elapsed = now - data.windowStart;
  if (elapsed < 1000) {
    data.count++;
  } else {
    // new window
    data.count = 1;
    data.windowStart = now;
  }

  // check against limit
  if (data.count > rps) {
    // exceeded rate limit — check if this is sustained (ban-worthy)
    if (data.count > burst) {
      data.banned = true;
      data.bannedUntil = now + banDuration;
      logger.warn('IP banned for rate limit abuse', { ip, count: data.count, banDuration: banDuration / 1000 });
      return { limited: true, remaining: 0, retryAfter: Math.ceil(banDuration / 1000) };
    }
    return { limited: true, remaining: 0, retryAfter: 1 };
  }

  return { limited: false, remaining: rps - data.count };
}

/**
 * manually ban an IP
 */
function banIp(ip, durationSeconds) {
  counters.set(ip, {
    count: 0,
    windowStart: Date.now(),
    banned: true,
    bannedUntil: Date.now() + durationSeconds * 1000,
  });
}

/**
 * manually unban an IP
 */
function unbanIp(ip) {
  counters.delete(ip);
}

/**
 * get current status for an IP
 */
function getStatus(ip) {
  return counters.get(ip) || null;
}

/**
 * get all currently banned IPs
 */
function getBannedIps() {
  const banned = [];
  const now = Date.now();
  for (const [ip, data] of counters) {
    if (data.banned && (!data.bannedUntil || data.bannedUntil > now)) {
      banned.push({ ip, until: data.bannedUntil ? new Date(data.bannedUntil).toISOString() : null });
    }
  }
  return banned;
}

module.exports = { checkRateLimit, banIp, unbanIp, getStatus, getBannedIps };
