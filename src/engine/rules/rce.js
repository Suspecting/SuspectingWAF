// src/engine/rules/rce.js
// Remote Code Execution detection
// catches eval-like patterns, serialization attacks, template injection

const RULE_ID = 'rce';
const RULE_NAME = 'Remote Code Execution';

const PATTERNS = [
  // PHP
  /\b(eval|assert|preg_replace|create_function|call_user_func|system|passthru|exec|shell_exec|popen|proc_open)\s*\(/i,
  /\bphp:\/\/(input|filter|data)/i,
  /\b__autoload\b/i,

  // Java deserialization
  /\brmi:\/\//i,
  /\bjavax\.naming/i,
  /\borg\.apache\.commons\.collections/i,
  /\bRuntime\.getRuntime\(\)\.exec/i,

  // Python
  /\b(os\.system|os\.popen|subprocess\.(call|Popen|run|check_output))\b/i,
  /\b__import__\s*\(/i,
  /\bpickle\.(loads|load)\b/i,

  // Node.js
  /\brequire\s*\(\s*['"]child_process['"]\s*\)/i,
  /\bchild_process\b/i,
  /\bprocess\.binding\b/i,

  // Template injection (SSTI)
  /\{\{.*?(config|self|request|application|os\.|import|__class__|__mro__)/i,
  /\{%.*?(import|include|extends)/i,
  /<\%=.*?(Runtime|exec|system)/i,
  /\$\{.*?(Runtime|getRuntime|exec|ProcessBuilder)/i,

  // OGNL injection (Java)
  /\b(#|%23)(cmd|command|exec)\b/i,
  /@java\.lang\.Runtime/i,

  // Expression Language
  /\$\{.*?java\.lang/i,
  /\#\{.*?Runtime/i,
];

function check(req) {
  const targets = [];
  if (req.url) targets.push({ source: 'url', value: req.url });
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
  // check content-type for deserialization attacks
  const ct = req.headers?.['content-type'] || '';
  if (/java-serialized-object/i.test(ct) || /application\/x-java/i.test(ct)) {
    return {
      blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
      severity: 'critical',
      detail: 'Java serialized object in Content-Type',
      payload: ct,
    };
  }

  for (const { source, value } of targets) {
    if (!value || value.length < 5) continue;
    let decoded;
    try { decoded = decodeURIComponent(value); } catch { decoded = value; }

    for (const pattern of PATTERNS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'critical',
          detail: `RCE pattern in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
