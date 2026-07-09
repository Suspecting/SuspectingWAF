// src/utils/crypto.js
// password hashing and token generation
// using bcryptjs because it's pure JS (no native build issues in docker)

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const config = require('./config');

const SALT_ROUNDS = 10;

async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function generateToken(payload) {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: config.jwtExpiry });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (err) {
    return null;
  }
}

function generateApiKey() {
  // format: swaf_xxxx_xxxx_xxxx
  const id = randomUUID().replace(/-/g, '');
  return `swaf_${id.slice(0, 8)}_${id.slice(8, 16)}_${id.slice(16, 24)}`;
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  verifyToken,
  generateApiKey,
};
