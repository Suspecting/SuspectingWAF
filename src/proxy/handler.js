// src/proxy/handler.js
// request interception and forwarding logic
// this is the glue between the HTTP proxy and the detection engine

const url = require('url');
const { inspect } = require('../engine/inspector');
const queries = require('../db/queries');
const logger = require('../utils/logger');
const { getClientIp } = require('../utils/ip');

// in-memory request counter for stats
let requestCount = 0;
let blockedCount = 0;

// flush stats to db every 60 seconds
setInterval(() => {
  if (requestCount > 0) {
    try {
      const db = require('../db/connection').getDb();
      db.prepare(`
        INSERT INTO request_stats (site_id, bucket, total_requests, blocked_requests, unique_ips)
        VALUES (NULL, datetime('now', '-1 minute'), ?, ?, 0)
      `).run(requestCount, blockedCount);
    } catch (err) {
      // not critical, just stats
    }
    requestCount = 0;
    blockedCount = 0;
  }
}, 60000);

/**
 * handle an incoming proxied request
 * returns the upstream target if allowed, or null if blocked
 */
function handleRequest(req, res) {
  requestCount++;

  const host = req.headers.host || '';
  const site = findSiteForRequest(host, req.socket?.localPort);

  if (!site) {
    // no site configured for this host — return 404
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getNotFoundPage());
    return null;
  }

  // collect body data for inspection (only for POST/PUT/PATCH)
  // for GET requests we just inspect the URL and headers
  const result = inspect(req, site);

  if (result.blocked) {
    blockedCount++;
    const ip = getClientIp(req);
    logger.warn('Request blocked', {
      ip, method: req.method, url: req.url,
      rule: result.rule, detail: result.detail,
    });

    // rate limit has a special response
    if (result.retryAfter) {
      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': String(result.retryAfter),
      });
    } else {
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
    }
    res.end(getBlockPage(result));
    return null;
  }

  return site;
}

/**
 * find which configured site matches this request
 * matching logic: check host header against server_names, then listen_port
 */
function findSiteForRequest(host, port) {
  const sites = queries.getAllSites();
  const hostname = host.split(':')[0]; // strip port from host header

  for (const site of sites) {
    if (site.status !== 'active') continue;

    // check server_names (comma-separated list)
    const serverNames = (site.server_names || '').split(',').map(s => s.trim()).filter(Boolean);
    if (serverNames.length > 0) {
      if (serverNames.includes(hostname) || serverNames.includes(host)) {
        return site;
      }
    }

    // check listen_port
    if (port && site.listen_port === port) {
      return site;
    }
  }

  // fallback: return the first active site (catch-all)
  return sites.find(s => s.status === 'active') || null;
}

function getBlockPage(result) {
  const title = 'Request Blocked';
  const code = result.retryAfter ? 429 : 403;
  const message = result.retryAfter
    ? 'Too many requests. Please slow down and try again later.'
    : 'Your request has been blocked by the web application firewall.';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — SuspectingWAF</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0d1117; color: #c9d1d9;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 20px;
    }
    .container {
      max-width: 520px; width: 100%; text-align: center;
      background: #161b22; border: 1px solid #30363d;
      border-radius: 12px; padding: 48px 32px;
    }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { font-size: 24px; color: #f0f6fc; margin-bottom: 8px; }
    .code { font-size: 64px; font-weight: 700; color: #da3633; margin-bottom: 12px; }
    p { color: #8b949e; line-height: 1.6; margin-bottom: 16px; }
    .rule { 
      background: #1c2128; border: 1px solid #30363d;
      border-radius: 6px; padding: 12px; margin-top: 16px;
      font-family: monospace; font-size: 13px; color: #8b949e;
    }
    .footer { margin-top: 24px; font-size: 12px; color: #484f58; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🛡️</div>
    <div class="code">${code}</div>
    <h1>${title}</h1>
    <p>${message}</p>
    <div class="rule">Rule: ${result.ruleName || result.rule || 'N/A'}</div>
    <div class="footer">Protected by SuspectingWAF</div>
  </div>
</body>
</html>`;
}

function getNotFoundPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>404 — Not Found</title>
  <style>
    body { font-family: sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .c { text-align: center; }
    h1 { font-size: 48px; color: #da3633; }
    p { color: #8b949e; }
  </style>
</head>
<body><div class="c"><h1>404</h1><p>No site configured for this domain.</p></div></body>
</html>`;
}

module.exports = { handleRequest, findSiteForRequest };
