const express = require('express');
const router = express.Router();
const queries = require('../../db/queries');
const { invalidateCache } = require('../../engine/inspector');
const { requireFields, validateId } = require('../middleware/validate');
router.get('/', (req, res) => {
  try {
    const type = req.query.type; // 'block' or 'allow' or undefined for all
    const list = queries.getIpList(type);
    res.json({ list });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post('/', requireFields('ip', 'type'), (req, res) => {
  try {
    if (!['block', 'allow'].includes(req.body.type)) {
      return res.status(400).json({ error: 'Type must be "block" or "allow"' });
    }
    const result = queries.addIpToList(req.body);
    invalidateCache();
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.delete('/:id', validateId, (req, res) => {
  try {
    queries.removeIpFromList(req.params.id);
    invalidateCache();
    res.json({ message: 'Entry removed' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
