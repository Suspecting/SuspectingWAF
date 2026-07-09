const http = require('http');
const httpProxy = require('http-proxy');
const logger = require('../utils/logger');
const config = require('../utils/config');
const { handleRequest } = require('./handler');

let proxyServer = null;
let httpServer = null;

function startProxy() {
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
  httpServer = http.createServer((req, res) => {
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
        if (body.length > 1024 * 1024) { // 1MB
          req.destroy();
          return;
        }
      });
      req.on('end', () => {
        try {
          req.body = JSON.parse(body);
        } catch {
          req.body = body;
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
