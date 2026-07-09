const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');
const { requireFields, validateId } = require('../middleware/validate');
router.get('/', (req, res) => {
  try {
    const sites = queries.getAllSites();
    res.json({ sites });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.get('/:id', validateId, (req, res) => {
  try {
    const site = queries.getSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'Site not found' });
    res.json({ site });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post('/', requireFields('name', 'upstream_url'), (req, res) => {
  try {
    const site = queries.createSite({
      name: req.body.name,
      listen_port: req.body.listen_port || 80,
      upstream_url: req.body.upstream_url,
      server_names: req.body.server_names || '',
      ssl_enabled: req.body.ssl_enabled || false,
      cert_id: req.body.cert_id || null,
      waf_enabled: req.body.waf_enabled !== false,
    });
    res.status(201).json({ site });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.put('/:id', validateId, (req, res) => {
  try {
    const existing = queries.getSiteById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Site not found' });

    queries.updateSite(req.params.id, req.body);
    const updated = queries.getSiteById(req.params.id);
    res.json({ site: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.delete('/:id', validateId, (req, res) => {
  try {
    const existing = queries.getSiteById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Site not found' });

    queries.deleteSite(req.params.id);
    res.json({ message: 'Site deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
