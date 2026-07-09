const url = require('url');
const { inspect } = require('../engine/inspector');
const queries = require('../db/queries');
const logger = require('../utils/logger');
const { getClientIp } = require('../utils/ip');
let requestCount = 0;
let blockedCount = 0;
setInterval(() => {
  if (requestCount > 0) {
    try {
      const db = require('../db/connection').getDb();
      db.prepare(`
        INSERT INTO request_stats (site_id, bucket, total_requests, blocked_requests, unique_ips)
        VALUES (NULL, datetime('now', '-1 minute'), ?, ?, 0)
      `).run(requestCount, blockedCount);
    } catch (err) {
    }
    requestCount = 0;
    blockedCount = 0;
  }
}, 60000);

function handleRequest(req, res) {
  requestCount++;

  const host = req.headers.host || '';
  const site = findSiteForRequest(host, req.socket?.localPort);

  if (!site) {
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getNotFoundPage());
    return null;
  }
  const result = inspect(req, site);

  if (result.blocked) {
    blockedCount++;
    const ip = getClientIp(req);
    logger.warn('Request blocked', {
      ip, method: req.method, url: req.url,
      rule: result.rule, detail: result.detail,
    });
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

function findSiteForRequest(host, port) {
  const sites = queries.getAllSites();
  const hostname = host.split(':')[0]; // strip port from host header

  for (const site of sites) {
    if (site.status !== 'active') continue;
    const serverNames = (site.server_names || '').split(',').map(s => s.trim()).filter(Boolean);
    if (serverNames.length > 0) {
      if (serverNames.includes(hostname) || serverNames.includes(host)) {
        return site;
      }
    }
    if (port && site.listen_port === port) {
      return site;
    }
  }
  return sites.find(s => s.status === 'active') || null;
}

const svgStr = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="160" height="160">
  <g id="bones">
    <g transform="rotate(38 100 100)">
      <line x1="20" y1="100" x2="180" y2="100" stroke="#000" stroke-width="24" stroke-linecap="round"/>
      <circle cx="16" cy="85" r="12" fill="#000" />
      <circle cx="16" cy="115" r="12" fill="#000" />
      <circle cx="184" cy="85" r="12" fill="#000" />
      <circle cx="184" cy="115" r="12" fill="#000" />
      <line x1="20" y1="100" x2="180" y2="100" stroke="#fff" stroke-width="16" stroke-linecap="round"/>
      <circle cx="16" cy="85" r="8" fill="#fff" />
      <circle cx="16" cy="115" r="8" fill="#fff" />
      <circle cx="184" cy="85" r="8" fill="#fff" />
      <circle cx="184" cy="115" r="8" fill="#fff" />
    </g>
    <g transform="rotate(-38 100 100)">
      <line x1="20" y1="100" x2="180" y2="100" stroke="#000" stroke-width="24" stroke-linecap="round"/>
      <circle cx="16" cy="85" r="12" fill="#000" />
      <circle cx="16" cy="115" r="12" fill="#000" />
      <circle cx="184" cy="85" r="12" fill="#000" />
      <circle cx="184" cy="115" r="12" fill="#000" />
      <line x1="20" y1="100" x2="180" y2="100" stroke="#fff" stroke-width="16" stroke-linecap="round"/>
      <circle cx="16" cy="85" r="8" fill="#fff" />
      <circle cx="16" cy="115" r="8" fill="#fff" />
      <circle cx="184" cy="85" r="8" fill="#fff" />
      <circle cx="184" cy="115" r="8" fill="#fff" />
    </g>
  </g>

  <!-- Lower Jaw -->
  <path d="M 75 140 C 75 175, 125 175, 125 140 Z" fill="#fff" stroke="#000" stroke-width="4"/>

  <!-- Skull Base -->
  <circle cx="100" cy="100" r="44" fill="#fff" stroke="#000" stroke-width="4"/>

  <!-- Teeth Grid -->
  <polygon points="65,115 135,115 125,145 75,145" fill="#fff" stroke="#000" stroke-width="4" stroke-linejoin="round"/>
  <line x1="70" y1="130" x2="130" y2="130" stroke="#000" stroke-width="3"/>
  <line x1="85" y1="115" x2="85" y2="145" stroke="#000" stroke-width="3"/>
  <line x1="100" y1="115" x2="100" y2="145" stroke="#000" stroke-width="3"/>
  <line x1="115" y1="115" x2="115" y2="145" stroke="#000" stroke-width="3"/>

  <!-- Eyes and Nose -->
  <circle cx="78" cy="100" r="12" fill="#000" />
  <circle cx="122" cy="100" r="12" fill="#000" />
  <circle cx="100" cy="112" r="4" fill="#000" />

  <!-- Hat Dome -->
  <path d="M 54 75 C 54 15, 146 15, 146 75 Z" fill="#fcd303" stroke="#000" stroke-width="4"/>
  
  <!-- Hat Ticks -->
  <line x1="68" y1="45" x2="72" y2="52" stroke="#000" stroke-width="3" stroke-linecap="round"/>
  <line x1="78" y1="35" x2="82" y2="45" stroke="#000" stroke-width="3" stroke-linecap="round"/>
  <line x1="90" y1="30" x2="92" y2="40" stroke="#000" stroke-width="3" stroke-linecap="round"/>
  <line x1="132" y1="45" x2="128" y2="52" stroke="#000" stroke-width="3" stroke-linecap="round"/>
  <line x1="122" y1="35" x2="118" y2="45" stroke="#000" stroke-width="3" stroke-linecap="round"/>
  <line x1="110" y1="30" x2="108" y2="40" stroke="#000" stroke-width="3" stroke-linecap="round"/>

  <!-- Red Band -->
  <path d="M 54 75 L 56 60 Q 100 56 144 60 L 146 75 Z" fill="#e62222" stroke="#000" stroke-width="4"/>

  <!-- Hat Brim -->
  <rect x="15" y="75" width="170" height="10" rx="5" fill="#fcd303" stroke="#000" stroke-width="4"/>
</svg>`;
const dangerIconBase64 = Buffer.from(svgStr).toString('base64');

function getBlockPage(result) {
  const title = queries.getSetting('block_page_title') || 'Request Blocked';
  const code = result.retryAfter ? '429' : '403';
  const message = result.retryAfter
    ? 'Rate limit exceeded. Please try again later.'
    : queries.getSetting('block_page_message') || 'Your request has been blocked by the web application firewall.';

  const imageTag = `<img src="data:image/svg+xml;base64,${dangerIconBase64}" width="140" height="140" alt="Straw Hat Pirate" style="margin-bottom: 24px;" />`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — SuspectingWAF</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap');
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'JetBrains Mono', monospace;
      background: #2a080c;
      color: #ffcccc;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 20px;
      -webkit-user-select: none;
      -moz-user-select: none;
      -ms-user-select: none;
      user-select: none;
    }
    .container {
      max-width: 520px; width: 100%; text-align: center;
      background: transparent;
      padding: 48px 32px;
    }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { font-size: 28px; color: #ff6b6b; margin-bottom: 8px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; }
    .code { font-size: 72px; font-weight: 900; color: #da3633; margin-bottom: 12px; }
    p { color: #ffb3b3; line-height: 1.6; margin-bottom: 16px; font-size: 16px; }
    .rule { 
      background: transparent;
      padding: 14px; margin-top: 24px;
      font-family: 'Courier New', Courier, monospace; font-size: 14px; color: #ff9999;
      font-weight: bold;
    }
    .footer { margin-top: 32px; font-size: 12px; color: #da3633; letter-spacing: 1px; text-transform: uppercase; }
  </style>
</head>
<body>
  <div class="container">
    ${imageTag}
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
