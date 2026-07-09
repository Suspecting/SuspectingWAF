const logger = require('../utils/logger');
const config = require('../utils/config');
const counters = new Map();
const CLEANUP_INTERVAL = 5 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of counters) {
    if (now - data.windowStart > 600000 && !data.banned) {
      counters.delete(ip);
    }
    if (data.banned && data.bannedUntil && now > data.bannedUntil) {
      data.banned = false;
      data.count = 0;
      data.windowStart = now;
    }
  }
}, CLEANUP_INTERVAL);

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
  if (data.banned) {
    if (data.bannedUntil && now > data.bannedUntil) {
      data.banned = false;
      data.count = 1;
      data.windowStart = now;
      return { limited: false, remaining: rps - 1 };
    }
    const retryAfter = Math.ceil((data.bannedUntil - now) / 1000);
    return { limited: true, remaining: 0, retryAfter };
  }
  const elapsed = now - data.windowStart;
  if (elapsed < 1000) {
    data.count++;
  } else {
    data.count = 1;
    data.windowStart = now;
  }
  if (data.count > rps) {
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

function banIp(ip, durationSeconds) {
  counters.set(ip, {
    count: 0,
    windowStart: Date.now(),
    banned: true,
    bannedUntil: Date.now() + durationSeconds * 1000,
  });
}

function unbanIp(ip) {
  counters.delete(ip);
}

function getStatus(ip) {
  return counters.get(ip) || null;
}

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
