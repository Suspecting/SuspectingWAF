const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const queries = require('../../db/queries');
const config = require('../../utils/config');
const { clearCertCache } = require('../../proxy/ssl');
const { validateId } = require('../middleware/validate');
router.get('/', (req, res) => {
  try {
    const certs = queries.getCertificates();
    res.json({ certs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.post('/', (req, res) => {
  try {
    const { name, domain, cert_content, key_content } = req.body;
    if (!name || !domain || !cert_content || !key_content) {
      return res.status(400).json({ error: 'name, domain, cert_content, and key_content required' });
    }

    const certsDir = path.join(config.dataDir, 'certs');
    const certPath = path.join(certsDir, `${domain}.crt`);
    const keyPath = path.join(certsDir, `${domain}.key`);
    fs.writeFileSync(certPath, cert_content);
    fs.writeFileSync(keyPath, key_content);

    const result = queries.createCertificate({ name, domain, cert_path: certPath, key_path: keyPath });
    clearCertCache();

    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
router.delete('/:id', validateId, (req, res) => {
  try {
    const cert = queries.getCertById(req.params.id);
    if (!cert) return res.status(404).json({ error: 'Certificate not found' });
    try {
      if (cert.cert_path && fs.existsSync(cert.cert_path)) fs.unlinkSync(cert.cert_path);
      if (cert.key_path && fs.existsSync(cert.key_path)) fs.unlinkSync(cert.key_path);
    } catch {} // best effort

    queries.deleteCertificate(req.params.id);
    clearCertCache();
    res.json({ message: 'Certificate deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
