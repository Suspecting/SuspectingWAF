// src/api/middleware/auth.js
// JWT authentication middleware for the management API

const { verifyToken } = require('../../utils/crypto');
const queries = require('../../db/queries');

function authMiddleware(req, res, next) {
  // skip auth for login endpoint
  if (req.path === '/api/v1/auth/login') {
    return next();
  }

  // check for API token header first (for programmatic access)
  const apiToken = req.headers['x-swaf-api-token'];
  if (apiToken) {
    // look up the token in the users table
    // TODO: implement proper API key lookup
    // for now, just check JWT in the header
  }

  // check Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // attach user info to the request
  const user = queries.getUserById(payload.userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  req.user = user;
  next();
}

module.exports = authMiddleware;
