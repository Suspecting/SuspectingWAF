const RULE_ID = 'ssrf';
const RULE_NAME = 'Server-Side Request Forgery';

const { isInternalIp } = require('../../utils/ip');
const INTERNAL_URL_PATTERNS = [
  /https?:\/\/127\./i,
  /https?:\/\/0\./i,
  /https?:\/\/localhost/i,
  /https?:\/\/\[::1\]/i,
  /https?:\/\/10\.\d+\.\d+\.\d+/i,
  /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i,
  /https?:\/\/192\.168\.\d+\.\d+/i,
  /https?:\/\/169\.254\.\d+\.\d+/i,     // AWS metadata
  /https?:\/\/metadata\.google/i,        // GCP metadata
  /https?:\/\/100\.100\.100\.200/i,      // Alibaba metadata
];
const METADATA_PATTERNS = [
  /169\.254\.169\.254/,                   // AWS/Azure metadata
  /metadata\.google\.internal/i,          // GCP
  /metadata\.google\.com/i,
  /100\.100\.100\.200/,                   // Alibaba Cloud
];
const DANGEROUS_SCHEMES = [
  /^file:\/\//i,
  /^gopher:\/\//i,
  /^dict:\/\//i,
  /^ftp:\/\//i,
  /^ldap:\/\//i,
  /^tftp:\/\//i,
];

function check(req) {
  const targets = [];
  if (req.query) {
    for (const [k, v] of Object.entries(req.query)) targets.push({ source: `query.${k}`, value: String(v) });
  }
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) {
      if (typeof v === 'string') targets.push({ source: `body.${k}`, value: v });
    }
  } else if (req.body && typeof req.body === 'string') {
    targets.push({ source: 'body', value: req.body });
  }

  for (const { source, value } of targets) {
    if (!value || value.length < 5) continue;
    let decoded;
    try { decoded = decodeURIComponent(value); } catch { decoded = value; }
    for (const pattern of INTERNAL_URL_PATTERNS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'high',
          detail: `Internal URL access attempt in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
    for (const pattern of METADATA_PATTERNS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'critical',
          detail: `Cloud metadata endpoint access in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
    for (const pattern of DANGEROUS_SCHEMES) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'high',
          detail: `Dangerous URI scheme in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
