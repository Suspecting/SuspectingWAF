const express = require('express');
const router = express.Router();
const { verifyPassword, generateToken, hashPassword } = require('../../utils/crypto');
const queries = require('../../db/queries');
const logger = require('../../utils/logger');
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = queries.getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      logger.warn('Failed login attempt', { username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken({ userId: user.id, username: user.username });
    queries.updateUserLogin(user.id);

    logger.info('User logged in', { username, ip: req.ip });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    logger.error('Login error', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});
router.get('/me', (req, res) => {
  res.json({ user: req.user });
});
router.put('/password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = queries.getUserByUsername(req.user.username);
    const valid = await verifyPassword(currentPassword, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hash = await hashPassword(newPassword);
    queries.updateUserPassword(user.id, hash);

    logger.info('Password changed', { username: user.username });
    res.json({ message: 'Password updated' });
  } catch (err) {
    logger.error('Password change error', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
