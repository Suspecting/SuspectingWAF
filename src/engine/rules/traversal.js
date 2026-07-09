const RULE_ID = 'traversal';
const RULE_NAME = 'Path Traversal';

const TRAVERSAL_SEQUENCES = [
  /\.\.[\/\\]/,                    // ../ or ..\
  /\.\.(\/|\\)/,
  /%2e%2e[\/\\%]/i,               // URL-encoded ../
  /%2e%2e%2f/i,                   // %2e%2e%2f
  /%2e%2e%5c/i,                   // %2e%2e%5c
  /\.\.%2f/i,                     // ..%2f
  /\.\.%5c/i,                     // ..%5c
  /%252e%252e/i,                  // double-encoded
  /\.\.\%c0%af/i,                 // overlong UTF-8
  /\.\.\%c1%9c/i,
  /\.\.%255c/i,
];
const SENSITIVE_FILES = [
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\/etc\/hosts/i,
  /\/etc\/group/i,
  /\/etc\/resolv\.conf/i,
  /\/proc\/self\//i,
  /\/proc\/version/i,
  /\/proc\/cmdline/i,
  /\/var\/log\/(auth|syslog|messages)/i,
  /\.htaccess/i,
  /\.htpasswd/i,
  /web\.config/i,
  /wp-config\.php/i,
  /\.env$/i,
  /\.git\/(config|HEAD)/i,
  /\.svn\//i,
  /\.ssh\/(id_rsa|authorized_keys)/i,
  /boot\.ini/i,
  /win\.ini/i,
  /system\.ini/i,
  /windows\/system32/i,
  /\/etc\/nginx\//i,
  /\/etc\/apache2\//i,
];

function check(req) {
  const url = req.url || '';
  const decoded = decodeURISafe(decodeURISafe(url)); // double decode
  for (const pattern of TRAVERSAL_SEQUENCES) {
    if (pattern.test(decoded) || pattern.test(url)) {
      return {
        blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
        severity: 'high',
        detail: 'Path traversal sequence detected in URL',
        payload: decoded.slice(0, 500),
      };
    }
  }
  for (const pattern of SENSITIVE_FILES) {
    if (pattern.test(decoded) || pattern.test(url)) {
      return {
        blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
        severity: 'high',
        detail: 'Sensitive file access attempt',
        payload: decoded.slice(0, 500),
      };
    }
  }
  const params = getAllParams(req);
  for (const { source, value } of params) {
    if (!value || value.length < 3) continue;
    const dec = decodeURISafe(value);

    for (const pattern of TRAVERSAL_SEQUENCES) {
      if (pattern.test(dec)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'high',
          detail: `Path traversal in ${source}`,
          payload: dec.slice(0, 500),
        };
      }
    }

    for (const pattern of SENSITIVE_FILES) {
      if (pattern.test(dec)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'medium',
          detail: `Sensitive file reference in ${source}`,
          payload: dec.slice(0, 500),
        };
      }
    }
  }

  return { blocked: false };
}

function getAllParams(req) {
  const params = [];
  if (req.query) {
    for (const [k, v] of Object.entries(req.query)) {
      params.push({ source: `query.${k}`, value: String(v) });
    }
  }
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) {
      if (typeof v === 'string') params.push({ source: `body.${k}`, value: v });
    }
  }
  return params;
}

function decodeURISafe(str) {
  try { return decodeURIComponent(str); } catch { return str; }
}

module.exports = { check, RULE_ID, RULE_NAME };
