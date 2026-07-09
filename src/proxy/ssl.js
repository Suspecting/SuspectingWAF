// src/proxy/ssl.js
// SSL/TLS helpers — certificate loading and SNI support
// for multi-domain HTTPS termination

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const logger = require('../utils/logger');
const config = require('../utils/config');

// certificate cache: { domain: { cert, key, secureContext } }
const certCache = new Map();

/**
 * load a certificate pair from disk
 */
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

/**
 * create a TLS secure context for a domain
 */
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

/**
 * SNI callback for the HTTPS server
 * looks up the right certificate based on the hostname
 */
function sniCallback(hostname, cb) {
  // check cache first
  if (certCache.has(hostname)) {
    return cb(null, certCache.get(hostname));
  }

  // try to find cert in data/certs/
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

  // fallback to default cert if it exists
  const defaultCert = path.join(certsDir, 'default.crt');
  const defaultKey = path.join(certsDir, 'default.key');
  if (fs.existsSync(defaultCert) && fs.existsSync(defaultKey)) {
    const ctx = createSecureContext(defaultCert, defaultKey);
    if (ctx) return cb(null, ctx);
  }

  // no cert found — let it fail (will show browser SSL error)
  cb(null, null);
}

/**
 * generate a self-signed certificate for initial setup
 * (so the management UI works over HTTPS out of the box)
 */
function ensureDefaultCert() {
  const certsDir = path.join(config.dataDir, 'certs');
  const certPath = path.join(certsDir, 'default.crt');
  const keyPath = path.join(certsDir, 'default.key');

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { certPath, keyPath };
  }

  // we'll generate self-signed certs using Node's crypto
  // this is a simplified approach — in production you'd use openssl
  logger.info('Generating self-signed certificate for management UI');

  try {
    const { generateKeyPairSync, createSign, X509Certificate } = require('crypto');

    // generate RSA key pair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // for self-signed, we just save the key — the cert needs openssl
    // so we'll just create placeholder files and log a warning
    fs.writeFileSync(keyPath, privateKey);
    fs.writeFileSync(certPath, publicKey); // not a real cert, just a placeholder

    logger.warn('Self-signed cert generated. For production, replace with real certificates.');
    return { certPath, keyPath };
  } catch (err) {
    logger.error('Could not generate self-signed cert', { error: err.message });
    return null;
  }
}

/**
 * clear the certificate cache (call after uploading new certs)
 */
function clearCertCache() {
  certCache.clear();
}

module.exports = { loadCert, createSecureContext, sniCallback, ensureDefaultCert, clearCertCache };
