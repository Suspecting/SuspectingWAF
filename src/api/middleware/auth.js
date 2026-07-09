const { verifyToken } = require('../../utils/crypto');
const queries = require('../../db/queries');

function authMiddleware(req, res, next) {
  if (req.path === '/api/v1/auth/login') {
    return next();
  }
  const apiToken = req.headers['x-swaf-api-token'];
  if (apiToken) {
  }
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  const user = queries.getUserById(payload.userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  req.user = user;
  next();
}

module.exports = authMiddleware;
