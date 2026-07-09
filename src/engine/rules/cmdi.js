const RULE_ID = 'cmdi';
const RULE_NAME = 'Command Injection';
const SHELL_METACHAR_PATTERNS = [
  /;\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|perl|python|ruby|php|node)\b/i,
  /\|\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|perl|python|ruby|php|node)\b/i,
  /&&\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh)\b/i,
  /\|\|\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh)\b/i,
];
const SUBSTITUTION_PATTERNS = [
  /`[^`]*`/,                               // `command`
  /\$\([^)]+\)/,                            // $(command)
  /\$\{[^}]*\}/,                            // ${variable} (could be used for injection)
];
const DANGEROUS_COMMANDS = [
  /\b(\/bin\/(sh|bash|dash|zsh|csh|ksh))\b/,
  /\b(\/usr\/bin\/(env|perl|python|ruby|php|node))\b/,
  /\bcmd(\.exe)?\s*\/c\b/i,               // Windows cmd /c
  /\bpowershell(\.exe)?\b/i,              // PowerShell
  /\bwget\s+https?:\/\//i,                // wget downloading stuff
  /\bcurl\s+(-[a-z]+\s+)*https?:\/\//i,   // curl fetching URLs
  /\bnc\s+-[a-z]*\s+/i,                   // netcat
  /\bncat\b/i,
  /\bchmod\s+[0-7]{3,4}\b/,               // chmod with octal perms
  /\bchown\b/i,
  /\brm\s+(-rf?|--force)\b/i,             // rm -rf
  /\bmkfifo\b/i,                           // named pipes (reverse shells)
  /\b\/dev\/(tcp|udp)\//i,                 // bash /dev/tcp reverse shell
  /\b(ping|nslookup|netstat|ifconfig|ipconfig|whoami|net user|type|dir|arp|route|traceroute|tracert)(\.exe)?\s+/i, // direct raw commands
];
const REVERSE_SHELL_PATTERNS = [
  /bash\s+-i\s+>&\s*\/dev\/(tcp|udp)\//i,
  /\bexec\s+\d+<>\/dev\/(tcp|udp)\//i,
  /\bnc\b.*-e\s*(\/bin\/(sh|bash))\b/i,
  /\bpython\b.*socket.*connect/i,
  /\bperl\b.*socket.*INET/i,
  /\bruby\b.*TCPSocket/i,
  /\bphp\b.*fsockopen/i,
];

function check(req) {
  const targets = collectTargets(req);

  for (const { source, value } of targets) {
    if (!value || value.length < 3) continue;

    const decoded = decodeURISafe(value);
    for (const pattern of REVERSE_SHELL_PATTERNS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'critical',
          detail: `Reverse shell attempt detected in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
    for (const pattern of SHELL_METACHAR_PATTERNS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'high',
          detail: `Command injection via shell metacharacter in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
    for (const pattern of SUBSTITUTION_PATTERNS) {
      if (pattern.test(decoded)) {
        const inner = decoded.match(pattern);
        if (inner && DANGEROUS_COMMANDS.some(dc => dc.test(inner[0]))) {
          return {
            blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
            severity: 'high',
            detail: `Command substitution with dangerous command in ${source}`,
            payload: decoded.slice(0, 500),
          };
        }
      }
    }
    for (const pattern of DANGEROUS_COMMANDS) {
      if (pattern.test(decoded)) {
        return {
          blocked: true, rule: RULE_ID, ruleName: RULE_NAME,
          severity: 'medium',
          detail: `Dangerous command pattern in ${source}`,
          payload: decoded.slice(0, 500),
        };
      }
    }
  }

  return { blocked: false };
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
    targets.push({ source: 'body', value: decodeURISafe(req.body.replace(/\+/g, ' ')) });
  }
  return targets;
}

function decodeURISafe(str) {
  try { return decodeURIComponent(str); } catch { return str; }
}

module.exports = { check, RULE_ID, RULE_NAME };
