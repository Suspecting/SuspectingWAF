const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');
const { invalidateCache } = require('../../engine/inspector');
const { requireFields, validateId } = require('../middleware/validate');
router.get('/', (req, res) => {
  try {
    const rules = queries.getCustomRules();
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post('/', requireFields('name', 'type', 'field', 'operator', 'value'), (req, res) => {
  try {
    const result = queries.createCustomRule(req.body);
    invalidateCache();
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.put('/:id', validateId, (req, res) => {
  try {
    queries.updateCustomRule(req.params.id, req.body);
    invalidateCache();
    res.json({ message: 'Rule updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
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
