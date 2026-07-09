// src/api/routes/stats.js
const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');

// GET /api/v1/stats/overview
router.get('/overview', (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const stats = queries.getOverviewStats(hours);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/stats/timeseries
router.get('/timeseries', (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const data = queries.getTimeseries(hours);
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
