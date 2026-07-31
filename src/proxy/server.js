const http = require('http');
const https = require('https');
const httpProxy = require('http-proxy');
const logger = require('../utils/logger');
const config = require('../utils/config');
const { handleRequest } = require('./handler');
const { sniCallback, ensureDefaultCert } = require('./ssl');

let proxyServer = null;
let httpServer = null;
let httpsServer = null;

function startProxy() {
  // Initialize core proxy engine
  proxyServer = httpProxy.createProxyServer({
    xfwd: true,           // add x-forwarded-* headers
    ws: true,              // support websocket proxying
    changeOrigin: true,    // change the origin header to match the target
    cookieDomainRewrite: { '*': '' } // strip explicit domains from cookies so they match the proxy host
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
    // Ensure Content-Length is correct if we buffered the body
    if (req.rawBody !== undefined) {
      proxyReq.setHeader('Content-Length', Buffer.byteLength(req.rawBody));
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

  // --- Shared request handler (buffers POST bodies, then inspects + proxies) ---
  function createRequestHandler() {
    return (req, res) => {
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
    };
  }

  // --- HTTP server: redirect all traffic to HTTPS ---
  httpServer = http.createServer((req, res) => {
    const host = (req.headers.host || 'localhost').split(':')[0];
    const httpsUrl = `https://${host}:${config.proxySslPort}${req.url}`;
    res.writeHead(301, { Location: httpsUrl });
    res.end();
  });
  // Keep-alive: reuse TCP connections instead of opening a new socket per request
  httpServer.keepAliveTimeout = 65000;
  httpServer.headersTimeout = 66000;
  httpServer.listen(config.proxyPort, () => {
    logger.info(`HTTP proxy on port ${config.proxyPort} → redirecting to HTTPS :${config.proxySslPort}`);
  });

  // --- HTTPS server: full WAF inspection over TLS ---
  const certResult = ensureDefaultCert();
  if (certResult) {
    httpsServer = https.createServer({ SNICallback: sniCallback }, createRequestHandler());
    // Keep-alive: reuse TCP connections for high throughput under stress
    httpsServer.keepAliveTimeout = 65000;
    httpsServer.headersTimeout = 66000;
    httpsServer.on('upgrade', (req, socket, head) => {
      const { findSiteForRequest } = require('./handler');
      const host = req.headers.host || '';
      const site = findSiteForRequest(host, req.socket?.localPort);
      if (site) {
        proxyServer.ws(req, socket, head, { target: site.upstream_url });
      } else {
        socket.destroy();
      }
    });
    httpsServer.listen(config.proxySslPort, () => {
      logger.info(`HTTPS proxy listening on port ${config.proxySslPort} (TLS)`);
    });
  } else {
    logger.error('SSL certificate unavailable — HTTPS server not started. Check data/certs/ directory.');
  }

  return httpServer;
}

function processRequest(req, res) {
  const site = handleRequest(req, res);

  if (site) {
    try {
      const options = { target: site.upstream_url };
      if (req.rawBody !== undefined) {
        options.buffer = require('stream').Readable.from([req.rawBody]);
      }
      proxyServer.web(req, res, options);
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
    logger.info('HTTP proxy stopped');
  }
  if (httpsServer) {
    httpsServer.close();
    logger.info('HTTPS proxy stopped');
  }
  if (proxyServer) {
    proxyServer.close();
  }
}

module.exports = { startProxy, stopProxy };
