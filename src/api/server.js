const express = require('express');
const path = require('path');
const logger = require('../utils/logger');
const config = require('../utils/config');
const authMiddleware = require('./middleware/auth');

function createApiServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-SWAF-API-Token');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
  });
  app.use('/dashboard', express.static(path.join(__dirname, '../../dashboard')));
  app.get('/', (req, res) => res.redirect('/dashboard'));
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', version: '1.0.0', uptime: process.uptime() });
  });
  app.use('/api/v1/auth', require('./routes/auth'));
  app.use('/api/v1', authMiddleware);
  app.use('/api/v1/sites', require('./routes/sites'));
  app.use('/api/v1/logs', require('./routes/logs'));
  app.use('/api/v1/stats', require('./routes/stats'));
  app.use('/api/v1/rules', require('./routes/rules'));
  app.use('/api/v1/iplist', require('./routes/iplist'));
  app.use('/api/v1/certs', require('./routes/certs'));
  app.use('/api/v1/settings', require('./routes/settings'));
  app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
  });
  app.use((err, req, res, next) => {
    logger.error('Unhandled API error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

function startApiServer() {
  const app = createApiServer();

  app.listen(config.mgtPort, () => {
    logger.info(`Management dashboard running on http://localhost:${config.mgtPort}/dashboard`);
    logger.info(`API available at http://localhost:${config.mgtPort}/api/v1`);
  });

  return app;
}

module.exports = { createApiServer, startApiServer };
