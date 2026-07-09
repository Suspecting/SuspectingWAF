const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');
const { upsertRateLimit, getRateLimits } = queries;
router.get('/', (req, res) => {
  try {
    const settings = queries.getSettings();
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.put('/', (req, res) => {
  try {
    const allowed = ['waf_mode', 'log_retention_days', 'stats_interval', 'block_page_title', 'block_page_message'];
    for (const [key, value] of Object.entries(req.body)) {
      if (allowed.includes(key)) {
        queries.setSetting(key, String(value));
      }
    }
    res.json({ message: 'Settings updated', settings: queries.getSettings() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.get('/ratelimit', (req, res) => {
  try {
    const limits = getRateLimits();
    res.json({ limits });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.put('/ratelimit', (req, res) => {
  try {
    const { site_id, requests_per_second, burst, ban_duration, enabled } = req.body;
    if (!site_id) return res.status(400).json({ error: 'site_id required' });

    upsertRateLimit({
      site_id,
      requests_per_second: requests_per_second || 100,
      burst: burst || 200,
      ban_duration: ban_duration || 300,
      enabled: enabled !== false,
    });
    res.json({ message: 'Rate limit updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
