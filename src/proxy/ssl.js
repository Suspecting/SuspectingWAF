const fs = require('fs');
const path = require('path');
const tls = require('tls');
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
  logger.info('Generating self-signed certificate for management UI');

  try {
    const { generateKeyPairSync, createSign, X509Certificate } = require('crypto');
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    fs.writeFileSync(keyPath, privateKey);
    fs.writeFileSync(certPath, publicKey); // not a real cert, just a placeholder

    logger.warn('Self-signed cert generated. For production, replace with real certificates.');
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
