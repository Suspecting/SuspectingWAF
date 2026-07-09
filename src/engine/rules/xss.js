const RULE_ID = 'xss';
const RULE_NAME = 'Cross-Site Scripting';
const SCRIPT_PATTERNS = [
  /<script[\s>]/i,
  /<\/script>/i,
  /<script\b[^>]*>[\s\S]*?<\/script>/i,
];
const EVENT_HANDLERS = [
  /\bon\w+\s*=\s*['"]/i,           // onload="..." onerror="..." etc
  /\bon(load|error|click|mouseover|mouseout|focus|blur|submit|change|input|keydown|keyup|keypress)\s*=/i,
  /\bon(abort|beforeunload|hashchange|message|offline|online|pagehide|pageshow|popstate|resize|scroll|unload)\s*=/i,
  /\bon(animationstart|animationend|animationiteration|transitionend)\s*=/i,
];
const JS_URI_PATTERNS = [
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /data\s*:\s*text\/html/i,
  /data\s*:\s*application\/x?html/i,
];
const DANGEROUS_TAGS = [
  /<iframe[\s>]/i,
  /<embed[\s>]/i,
  /<object[\s>]/i,
  /<applet[\s>]/i,
  /<form[\s>]/i,
  /<meta[\s][^>]*http-equiv/i,
  /<link[\s][^>]*rel\s*=\s*['"]?import/i,
  /<svg[\s][^>]*onload/i,
  /<img[\s][^>]*onerror/i,
  /<body[\s][^>]*onload/i,
  /<input[\s][^>]*onfocus/i,
  /<details[\s][^>]*ontoggle/i,
  /<marquee[\s][^>]*onstart/i,
  /<video[\s][^>]*onerror/i,
  /<audio[\s][^>]*onerror/i,
  /<source[\s][^>]*onerror/i,
];
const EVAL_PATTERNS = [
  /\beval\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bFunction\s*\(/i,
  /\bdocument\s*\.\s*(cookie|domain|write|writeln)/i,
  /\bwindow\s*\.\s*location/i,
  /\balert\s*\(/i,
  /\bprompt\s*\(/i,
  /\bconfirm\s*\(/i,
  /\.innerHTML\s*=/i,
  /\.outerHTML\s*=/i,
  /\.insertAdjacentHTML\s*\(/i,
];
const ENCODING_PATTERNS = [
  /&#x?[0-9a-f]+;/i,       // HTML entities (&#60; &#x3c;)
  /\\u[0-9a-f]{4}/i,        // Unicode escapes (\u003c)
  /\\x[0-9a-f]{2}/i,        // Hex escapes (\x3c)
  /%3c/i,                    // URL-encoded <
  /%3e/i,                    // URL-encoded >
  /%22/i,                    // URL-encoded "
  /%27/i,                    // URL-encoded '
];

function check(req) {
  const targets = collectTargets(req);

  for (const { source, value } of targets) {
    if (!value || value.length < 3) continue;
    const decoded = fullyDecode(value);
    for (const pattern of SCRIPT_PATTERNS) {
      if (pattern.test(decoded)) {
        return hit(source, decoded, 'Script tag injection', 'high');
      }
    }
    for (const pattern of EVENT_HANDLERS) {
      if (pattern.test(decoded)) {
        return hit(source, decoded, 'Event handler injection', 'high');
      }
    }
    for (const pattern of JS_URI_PATTERNS) {
      if (pattern.test(decoded)) {
        return hit(source, decoded, 'JavaScript URI injection', 'high');
      }
    }
    for (const pattern of DANGEROUS_TAGS) {
      if (pattern.test(decoded)) {
        return hit(source, decoded, 'Dangerous HTML tag', 'medium');
      }
    }
    for (const pattern of EVAL_PATTERNS) {
      if (pattern.test(decoded)) {
        if (/<[a-z]/i.test(decoded) || /['"]/.test(decoded)) {
          return hit(source, decoded, 'DOM manipulation attempt', 'medium');
        }
      }
    }
  }

  return { blocked: false };
}

function hit(source, value, detail, severity) {
  return {
    blocked: true,
    rule: RULE_ID,
    ruleName: RULE_NAME,
    severity,
    detail: `${detail} in ${source}`,
    payload: value.slice(0, 500),
  };
}

function fullyDecode(str) {
  let decoded = str;
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch { break; }
  }
  decoded = decoded.replace(/&#x([0-9a-f]+);/gi, (_, hex) => 
    String.fromCharCode(parseInt(hex, 16))
  );
  decoded = decoded.replace(/&#(\d+);/g, (_, dec) => 
    String.fromCharCode(parseInt(dec, 10))
  );
  decoded = decoded.replace(/&lt;/gi, '<');
  decoded = decoded.replace(/&gt;/gi, '>');
  decoded = decoded.replace(/&amp;/gi, '&');
  decoded = decoded.replace(/&quot;/gi, '"');
  decoded = decoded.replace(/&apos;/gi, "'");

  return decoded;
}

function collectTargets(req) {
  const targets = [];
  if (req.url) targets.push({ source: 'url', value: req.url });
  if (req.query) {
    for (const [k, v] of Object.entries(req.query)) {
      targets.push({ source: `query.${k}`, value: String(v) });
    }
  }
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) {
      if (typeof v === 'string') targets.push({ source: `body.${k}`, value: v });
    }
  } else if (req.body && typeof req.body === 'string') {
    targets.push({ source: 'body', value: req.body });
  }
  if (req.headers?.cookie) {
    targets.push({ source: 'cookie', value: req.headers.cookie });
  }
  if (req.headers?.referer) {
    targets.push({ source: 'referer', value: req.headers.referer });
  }
  return targets;
}

module.exports = { check, RULE_ID, RULE_NAME };
