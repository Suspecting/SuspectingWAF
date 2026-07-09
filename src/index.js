// src/index.js
// ============================================
// SuspectingWAF — entry point
// starts the reverse proxy and management API
// ============================================

const logger = require('./utils/logger');
const config = require('./utils/config');

async function main() {
  console.log(`
  ╔═══════════════════════════════════════════════╗
  ║          SuspectingWAF  v1.0.0                ║
  ║   Self-hosted Web Application Firewall        ║
  ╚═══════════════════════════════════════════════╝
  `);

  // 1. run database migrations (creates tables on first run)
  logger.info('Initializing database...');
  const { runMigrations } = require('./db/migrations');
  await runMigrations();

  // 2. start the management API + dashboard
  logger.info('Starting management API...');
  const { startApiServer } = require('./api/server');
  startApiServer();

  // 3. start the reverse proxy
  logger.info('Starting reverse proxy...');
  const { startProxy } = require('./proxy/server');
  startProxy();

  logger.info('SuspectingWAF is running', {
    proxy: `http://0.0.0.0:${config.proxyPort}`,
    dashboard: `http://0.0.0.0:${config.mgtPort}/dashboard`,
    wafMode: config.wafMode,
  });

  // handle graceful shutdown
  const shutdown = (signal) => {
    logger.info(`Received ${signal}, shutting down...`);
    const { stopProxy } = require('./proxy/server');
    const { closeDb } = require('./db/connection');
    stopProxy();
    closeDb();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
