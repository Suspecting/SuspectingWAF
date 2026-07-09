// src/api/routes/logs.js
const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');
const { validateId } = require('../middleware/validate');

// GET /api/v1/logs
router.get('/', (req, res) => {
  try {
    const { page, limit, site_id, rule_id, severity, src_ip, start_date, end_date } = req.query;
    const result = queries.getAttackLogs({
      page: parseInt(page) || 1,
      limit: Math.min(parseInt(limit) || 50, 200),
      site_id: site_id ? parseInt(site_id) : undefined,
      rule_id, severity, src_ip,
      startDate: start_date, endDate: end_date,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/logs/:id
router.get('/:id', validateId, (req, res) => {
  try {
    const log = queries.getAttackLogById(req.params.id);
    if (!log) return res.status(404).json({ error: 'Log entry not found' });
    // parse headers back from JSON
    if (log.request_headers) {
      try { log.request_headers = JSON.parse(log.request_headers); } catch {}
    }
    res.json({ log });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
