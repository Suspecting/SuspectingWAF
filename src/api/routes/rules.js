// src/api/routes/rules.js
const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');
const { invalidateCache } = require('../../engine/inspector');
const { requireFields, validateId } = require('../middleware/validate');

// GET /api/v1/rules
router.get('/', (req, res) => {
  try {
    const rules = queries.getCustomRules();
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/rules
router.post('/', requireFields('name', 'type', 'field', 'operator', 'value'), (req, res) => {
  try {
    const result = queries.createCustomRule(req.body);
    invalidateCache();
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/v1/rules/:id
router.put('/:id', validateId, (req, res) => {
  try {
    queries.updateCustomRule(req.params.id, req.body);
    invalidateCache();
    res.json({ message: 'Rule updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/v1/rules/:id
router.delete('/:id', validateId, (req, res) => {
  try {
    queries.deleteCustomRule(req.params.id);
    invalidateCache();
    res.json({ message: 'Rule deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
