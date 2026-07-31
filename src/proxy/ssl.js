const fs = require('fs');
const path = require('path');
const tls = require('tls');
const { execSync } = require('child_process');
const logger = require('../utils/logger');
const config = require('../utils/config');
const certCache = new Map();

function loadCert(certPath, keyPath) {
  try {
    const cert = fs.readFileSync(certPath, 'utf8');
    const key = fs.readFileSync(keyPath, 'utf8');
    return { cert, key };
  } catch (err) {
    logger.error('Failed to load certificate', { certPath, error: err.message });
    return null;
  }
}

function createSecureContext(certPath, keyPath) {
  const pair = loadCert(certPath, keyPath);
  if (!pair) return null;

  try {
    return tls.createSecureContext({
      cert: pair.cert,
      key: pair.key,
    });
  } catch (err) {
    logger.error('Failed to create secure context', { error: err.message });
    return null;
  }
}

function sniCallback(hostname, cb) {
  if (certCache.has(hostname)) {
    return cb(null, certCache.get(hostname));
  }
  const certsDir = path.join(config.dataDir, 'certs');
  const certPath = path.join(certsDir, `${hostname}.crt`);
  const keyPath = path.join(certsDir, `${hostname}.key`);

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    const ctx = createSecureContext(certPath, keyPath);
    if (ctx) {
      certCache.set(hostname, ctx);
      return cb(null, ctx);
    }
  }
  const defaultCert = path.join(certsDir, 'default.crt');
  const defaultKey = path.join(certsDir, 'default.key');
  if (fs.existsSync(defaultCert) && fs.existsSync(defaultKey)) {
    const ctx = createSecureContext(defaultCert, defaultKey);
    if (ctx) return cb(null, ctx);
  }
  cb(null, null);
}

function ensureDefaultCert() {
  const certsDir = path.join(config.dataDir, 'certs');
  const certPath = path.join(certsDir, 'default.crt');
  const keyPath = path.join(certsDir, 'default.key');

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { certPath, keyPath };
  }
  
  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
  }

  logger.info('Generating self-signed certificate for management UI');

  try {
    const subj = '/CN=localhost/O=SuspectingWAF/C=IN';
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "${subj}"`,
      { stdio: 'pipe' }
    );
    fs.chmodSync(keyPath, 0o600);
    logger.warn('⚠️  Self-signed certificate generated. Browser will show a security warning — click Advanced → Proceed.');
    logger.info(`Certificate saved to: ${certPath}`);
    return { certPath, keyPath };
  } catch (err) {
    logger.error('Could not generate self-signed cert', { error: err.message });
    return null;
  }
}

function clearCertCache() {
  certCache.clear();
}

module.exports = { loadCert, createSecureContext, sniCallback, ensureDefaultCert, clearCertCache };
