const http = require('http');
const httpProxy = require('http-proxy');
const logger = require('../utils/logger');
const config = require('../utils/config');
const { handleRequest } = require('./handler');

let proxyServer = null;
let httpServer = null;

function startProxy() {
  // Initialize core proxy engine
  proxyServer = httpProxy.createProxyServer({
    xfwd: true,           // add x-forwarded-* headers
    ws: true,              // support websocket proxying
    changeOrigin: true,    // change the origin header to match the target
  });
  proxyServer.on('error', (err, req, res) => {
    logger.error('Proxy error', { error: err.message, url: req.url });
    if (res && !res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html>
<html><head><title>502 Bad Gateway</title>
<style>body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.c{text-align:center}h1{color:#d29922;font-size:48px}p{color:#8b949e}</style></head>
<body><div class="c"><h1>502</h1><p>Bad Gateway — upstream server is not responding.</p>
<p style="font-size:12px;margin-top:16px;color:#484f58">SuspectingWAF</p></div></body></html>`);
    }
  });
  proxyServer.on('proxyReq', (proxyReq, req, res, options) => {
    // Rewrite buffered body to upstream request if it was consumed during inspection
    if (req.rawBody) {
      proxyReq.setHeader('Content-Length', Buffer.byteLength(req.rawBody));
      proxyReq.write(req.rawBody);
    }
  });

  proxyServer.on('proxyRes', (proxyRes, req, res) => {
    // Harden Set-Cookie headers (Disabled by default to prevent breaking SPAs)
    if (proxyRes.headers['set-cookie']) {
      let cookies = proxyRes.headers['set-cookie'];
      if (!Array.isArray(cookies)) cookies = [cookies];
      proxyRes.headers['set-cookie'] = cookies.map(c => {
        // if (!/HttpOnly/i.test(c)) c += '; HttpOnly';
        // if (!/SameSite/i.test(c)) c += '; SameSite=Lax';
        return c;
      });
    }

    // Inject global security headers (CSP, Clickjacking, MIME-sniffing protection)
    // proxyRes.headers['content-security-policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; object-src 'none';";
    proxyRes.headers['x-frame-options'] = 'SAMEORIGIN';
    proxyRes.headers['x-content-type-options'] = 'nosniff';
    proxyRes.headers['x-xss-protection'] = '1; mode=block';
  });

  httpServer = http.createServer((req, res) => {
    // Buffer streaming request bodies for inspection (POST, PUT, PATCH)
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
        // Protection against Buffer Overflow / Denial of Service (DoS)
        if (body.length > 1024 * 1024) { // Limit bodies to 1MB
          req.destroy();
          return;
        }
      });
      req.on('end', () => {
        req.rawBody = body;
        try {
          req.body = JSON.parse(body);
        } catch {
          if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
            req.body = require('querystring').parse(body);
          } else {
            req.body = body;
          }
        }
        processRequest(req, res);
      });
    } else {
      processRequest(req, res);
    }
  });
  httpServer.on('upgrade', (req, socket, head) => {
    const { findSiteForRequest } = require('./handler');
    const host = req.headers.host || '';
    const site = findSiteForRequest(host, req.socket?.localPort);
    if (site) {
      proxyServer.ws(req, socket, head, { target: site.upstream_url });
    } else {
      socket.destroy();
    }
  });

  httpServer.listen(config.proxyPort, () => {
    logger.info(`Reverse proxy listening on port ${config.proxyPort}`);
  });

  return httpServer;
}

function processRequest(req, res) {
  const site = handleRequest(req, res);

  if (site) {
    try {
      proxyServer.web(req, res, { target: site.upstream_url });
    } catch (err) {
      logger.error('Failed to proxy request', { error: err.message });
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('Bad Gateway');
      }
    }
  }
}

function stopProxy() {
  if (httpServer) {
    httpServer.close();
    logger.info('Proxy server stopped');
  }
  if (proxyServer) {
    proxyServer.close();
  }
}

module.exports = { startProxy, stopProxy };
