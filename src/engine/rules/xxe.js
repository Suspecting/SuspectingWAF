const RULE_ID = 'xxe';
const RULE_NAME = 'XML External Entity';

const XXE_PATTERNS = [
  /<!DOCTYPE[^>]*\[/i,                              // DOCTYPE with internal subset
  /<!ENTITY\s/i,                                      // ENTITY declaration
  /SYSTEM\s*["'][^"']*["']/i,                         // SYSTEM "uri"
  /PUBLIC\s*["'][^"']*["']/i,                          // PUBLIC "id"
  /<!ENTITY\s+\S+\s+SYSTEM/i,                         // ENTITY x SYSTEM
  /<!ENTITY\s+%\s/i,                                   // parameter entity
  /xmlns:xi\s*=\s*["']http:\/\/www\.w3\.org.*XInclude/i,  // XInclude
  /<xi:include/i,
  /<!ENTITY[^>]*(file|http|ftp|php|expect|data|gopher|dict):\/\//i, // external resource
];

function check(req) {
  const ct = (req.headers?.['content-type'] || '').toLowerCase();
  const isXml = ct.includes('xml') || ct.includes('soap');
  const body = typeof req.body === 'string' ? req.body : '';
  if (!isXml && !body.includes('<?xml') && !body.includes('<!DOCTYPE')) {
    return { blocked: false };
  }

  for (const pattern of XXE_PATTERNS) {
    if (pattern.test(body)) {
      return {
        blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
        severity: 'critical',
        detail: 'XXE payload detected in request body',
        payload: body.slice(0, 500),
      };
    }
  }
  if (req.url) {
    let decoded;
    try { decoded = decodeURIComponent(req.url); } catch { decoded = req.url; }
    for (const pattern of XXE_PATTERNS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'critical',
          detail: 'XXE payload in URL',
          payload: decoded.slice(0, 500),
        };
      }
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
