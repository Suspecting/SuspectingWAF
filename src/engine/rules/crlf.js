// src/engine/rules/crlf.js
// CRLF injection detection
// prevents HTTP response splitting by blocking \r\n in headers and params

const RULE_ID = 'crlf';
const RULE_NAME = 'CRLF Injection';

const CRLF_PATTERNS = [
  /%0d%0a/i,         // URL-encoded \r\n
  /%0d/i,            // URL-encoded \r (alone is also suspicious)
  /%0a/i,            // URL-encoded \n
  /\r\n/,            // raw CRLF
  /%e5%98%8a/i,      // Unicode CRLF variant
  /%c0%8d%c0%8a/i,   // overlong UTF-8 CRLF
];

// if CRLF is combined with these, it's almost certainly an attack
const HEADER_INJECTION_PATTERNS = [
  /Set-Cookie:/i,
  /Location:/i,
  /Content-Type:/i,
  /Content-Length:/i,
  /HTTP\/\d/i,
  /X-Forwarded/i,
];

function check(req) {
  const url = req.url || '';

  // check URL for CRLF
  for (const pattern of CRLF_PATTERNS) {
    if (pattern.test(url)) {
      // check if it's combined with header injection
      let decoded;
      try { decoded = decodeURIComponent(url); } catch { decoded = url; }

      const hasHeaderInjection = HEADER_INJECTION_PATTERNS.some(p => p.test(decoded));
      return {
        blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
        severity: hasHeaderInjection ? 'high' : 'medium',
        detail: hasHeaderInjection ? 'HTTP response splitting attempt' : 'CRLF sequence in URL',
        payload: url.slice(0, 500),
      };
    }
  }

  // check query params
  if (req.query) {
    for (const [k, v] of Object.entries(req.query)) {
      const val = String(v);
      for (const pattern of CRLF_PATTERNS) {
        if (pattern.test(val)) {
          return {
            blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
            severity: 'medium',
            detail: `CRLF injection in query parameter ${k}`,
            payload: val.slice(0, 500),
          };
        }
      }
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
