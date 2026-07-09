const RULE_ID = 'bot';
const RULE_NAME = 'Bot Detection';
const BAD_BOT_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /masscan/i,
  /dirbuster/i,
  /gobuster/i,
  /wfuzz/i,
  /ffuf/i,
  /nuclei/i,
  /burpsuite/i,
  /owasp/i,
  /acunetix/i,
  /nessus/i,
  /openvas/i,
  /qualys/i,
  /w3af/i,
  /arachni/i,
  /skipfish/i,
  /zaproxy/i,
  /havij/i,
  /python-requests/i,  // not always bad, but suspicious on web endpoints
  /python-urllib/i,
  /libwww-perl/i,
  /lwp-trivial/i,
  /wget/i,
  /curl\/\d/i,         // curl with version (automated)
  /httpclient/i,
  /go-http-client/i,
  /java\/\d/i,
  /ahrefsbot/i,        // SEO crawler, often abusive
  /semrushbot/i,
  /dotbot/i,
  /mj12bot/i,
];
const EXPECTED_BROWSER_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
];

function check(req) {
  const ua = req.headers?.['user-agent'] || '';
  if (!ua || ua.trim() === '') {
    return {
      blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
      severity: 'low',
      detail: 'Request with empty User-Agent',
      payload: '(empty UA)',
    };
  }
  for (const pattern of BAD_BOT_PATTERNS) {
    if (pattern.test(ua)) {
      return {
        blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
        severity: 'medium',
        detail: `Known scanner/bot User-Agent: ${ua.slice(0, 100)}`,
        payload: ua.slice(0, 500),
      };
    }
  }
  if (/Mozilla/i.test(ua)) {
    const missingHeaders = EXPECTED_BROWSER_HEADERS.filter(h => !req.headers?.[h]);
    if (missingHeaders.length >= 2) {
      return {
        blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
        severity: 'low',
        detail: `Browser UA but missing headers: ${missingHeaders.join(', ')}`,
        payload: ua.slice(0, 500),
      };
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
