const RULE_ID = 'csrf';
const RULE_NAME = 'Cross-Site Request Forgery';

const STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];

function check(req) {
  // CSRF protection only applies to state-changing requests
  if (!STATE_CHANGING_METHODS.includes(req.method)) {
    return { blocked: false };
  }

  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  const host = req.headers['host'];

  if (!host) {
    return { blocked: false }; // Can't validate without host
  }

  // Helper to extract hostname from URL
  const getHostname = (urlStr) => {
    try {
      if (!urlStr.startsWith('http')) return null;
      const url = new URL(urlStr);
      return url.host; // includes port
    } catch {
      return null;
    }
  };

  if (origin) {
    const originHost = getHostname(origin);
    if (originHost && originHost !== host) {
      return {
        blocked: true,
        rule: RULE_ID,
        ruleName: RULE_NAME,
        severity: 'high',
        detail: `Cross-site origin detected: ${originHost} !== ${host}`,
        payload: origin,
      };
    }
  } else if (referer) {
    const refererHost = getHostname(referer);
    if (refererHost && refererHost !== host) {
      return {
        blocked: true,
        rule: RULE_ID,
        ruleName: RULE_NAME,
        severity: 'high',
        detail: `Cross-site referer detected: ${refererHost} !== ${host}`,
        payload: referer,
      };
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
