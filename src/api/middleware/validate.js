function requireFields(...fields) {
  return (req, res, next) => {
    const missing = fields.filter(f => req.body[f] === undefined || req.body[f] === null || req.body[f] === '');
    if (missing.length > 0) {
      return res.status(400).json({
        error: 'Missing required fields',
        fields: missing,
      });
    }
    next();
  };
}

function validateId(req, res, next) {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id < 1) {
    return res.status(400).json({ error: 'Invalid ID' });
  }
  req.params.id = id;
  next();
}

module.exports = { requireFields, validateId };
