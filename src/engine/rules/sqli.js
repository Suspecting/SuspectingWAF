// src/engine/rules/sqli.js
// SQL injection detection
//
// We use a layered approach here:
// 1. pattern matching for known SQLi payloads
// 2. structural analysis (unbalanced quotes, comment sequences)
// 3. keyword combinations that strongly indicate injection
//
// this isn't meant to be perfect — no WAF catches everything.
// but it should catch the vast majority of automated scanners
// and script kiddies. For targeted attacks... that's what monitoring mode is for.

const RULE_ID = 'sqli';
const RULE_NAME = 'SQL Injection';

// common SQL keywords used in injection. we check for combos, not individual words
// because blocking "SELECT" alone would cause too many false positives
const SQL_KEYWORDS = [
  'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
  'ALTER', 'CREATE', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST',
  'CONVERT', 'TRUNCATE', 'INFORMATION_SCHEMA', 'SYSOBJECTS',
  'SYSCOLUMNS', 'WAITFOR', 'DELAY', 'BENCHMARK', 'SLEEP',
  'LOAD_FILE', 'INTO OUTFILE', 'INTO DUMPFILE',
];

// patterns that are almost always malicious
const DANGEROUS_PATTERNS = [
  /(\bunion\b[\s/\*]+\bselect\b)/i,                    // UNION SELECT
  /(\bselect\b[\s\S]+\bfrom\b[\s\S]+\bwhere\b)/i,      // SELECT...FROM...WHERE
  /(\binsert\b[\s]+\binto\b)/i,                         // INSERT INTO
  /(\bdelete\b[\s]+\bfrom\b)/i,                         // DELETE FROM
  /(\bdrop\b[\s]+\b(table|database|schema)\b)/i,        // DROP TABLE/DATABASE
  /(\balter\b[\s]+\btable\b)/i,                         // ALTER TABLE
  /(\bexec\b[\s]*\()/i,                                 // EXEC(
  /(\bexecute\b[\s]+\bimmediate\b)/i,                   // EXECUTE IMMEDIATE
  /(\bwaitfor\b[\s]+\bdelay\b)/i,                       // WAITFOR DELAY (MSSQL)
  /(\bbenchmark\b[\s]*\()/i,                            // BENCHMARK( (MySQL)
  /(\bsleep\b[\s]*\()/i,                                // SLEEP( (MySQL)
  /(\bload_file\b[\s]*\()/i,                            // LOAD_FILE(
  /(into[\s]+(out|dump)file)/i,                         // INTO OUTFILE/DUMPFILE
  /(\binformation_schema\b)/i,                          // INFORMATION_SCHEMA
  /(\bsys\.(objects|columns|tables)\b)/i,               // sys.objects (MSSQL)
];

// tautology patterns — common in auth bypass
const TAUTOLOGY_PATTERNS = [
  /['"][\s]*or[\s]+['"]?\d+['"]?[\s]*=[\s]*['"]?\d+/i,     // ' OR '1'='1
  /['"][\s]*or[\s]+['"]?[\w]+['"]?[\s]*=[\s]*['"]?[\w]+/i,  // ' OR 'x'='x
  /[\s]or[\s]+1[\s]*=[\s]*1/i,                               // OR 1=1
  /[\s]or[\s]+true/i,                                         // OR TRUE
  /['"][\s]*;/i,                                               // '; (statement termination)
];

// comment-based evasion
const COMMENT_PATTERNS = [
  /\/\*.*?\*\//,           // /* inline comment */
  /\/\*!/,                 // /*! MySQL conditional comment
  /--[\s]/,                // -- line comment (SQL)
  /#[\s]/,                 // # line comment (MySQL)
];

// hex/char encoding tricks
const ENCODING_PATTERNS = [
  /0x[0-9a-f]{4,}/i,                    // hex literals
  /char\s*\(\s*\d+(\s*,\s*\d+)*\s*\)/i, // CHAR(xx,xx,xx)
  /concat\s*\(/i,                         // CONCAT( — string building
  /group_concat\s*\(/i,                   // GROUP_CONCAT(
];

function check(req) {
  // collect all the input fields we want to inspect
  const targets = collectTargets(req);

  for (const { source, value } of targets) {
    // skip short values — very unlikely to be SQLi
    if (!value || value.length < 4) continue;

    // check dangerous patterns first (most specific)
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(value)) {
        return {
          blocked: true,
          rule: RULE_ID,
          ruleName: RULE_NAME,
          severity: 'high',
          detail: `SQL injection pattern detected in ${source}`,
          payload: value.slice(0, 500),
        };
      }
    }

    // tautology checks
    for (const pattern of TAUTOLOGY_PATTERNS) {
      if (pattern.test(value)) {
        return {
          blocked: true,
          rule: RULE_ID,
          ruleName: RULE_NAME,
          severity: 'high',
          detail: `SQL injection tautology detected in ${source}`,
          payload: value.slice(0, 500),
        };
      }
    }

    // structural analysis — check for suspicious character combos
    const structural = checkStructural(value);
    if (structural) {
      return {
        blocked: true,
        rule: RULE_ID,
        ruleName: RULE_NAME,
        severity: 'medium',
        detail: `${structural} in ${source}`,
        payload: value.slice(0, 500),
      };
    }
  }

  return { blocked: false };
}

function checkStructural(value) {
  // count single quotes — odd number is suspicious
  const singleQuotes = (value.match(/'/g) || []).length;
  const hasKeywords = SQL_KEYWORDS.some(kw => 
    new RegExp('\\b' + kw + '\\b', 'i').test(value)
  );

  if (singleQuotes > 0 && singleQuotes % 2 !== 0 && hasKeywords) {
    return 'Unbalanced quotes with SQL keywords';
  }

  // comment sequences + keywords = evasion attempt
  const hasComments = COMMENT_PATTERNS.some(p => p.test(value));
  if (hasComments && hasKeywords) {
    return 'SQL comment evasion with keywords';
  }

  // encoding tricks + keywords
  const hasEncoding = ENCODING_PATTERNS.some(p => p.test(value));
  if (hasEncoding && hasKeywords) {
    return 'Encoded SQL injection attempt';
  }

  return null;
}

function collectTargets(req) {
  const targets = [];

  // URL and query string
  if (req.url) {
    targets.push({ source: 'url', value: decodeURISafe(req.url) });
  }

  // parsed query params (if available)
  if (req.query) {
    for (const [key, val] of Object.entries(req.query)) {
      targets.push({ source: `query.${key}`, value: String(val) });
    }
  }

  // request body
  if (req.body && typeof req.body === 'object') {
    for (const [key, val] of Object.entries(req.body)) {
      if (typeof val === 'string') {
        targets.push({ source: `body.${key}`, value: val });
      }
    }
  } else if (req.body && typeof req.body === 'string') {
    targets.push({ source: 'body', value: req.body });
  }

  // cookies
  const cookies = req.headers?.cookie;
  if (cookies) {
    targets.push({ source: 'cookie', value: cookies });
  }

  return targets;
}

function decodeURISafe(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

module.exports = { check, RULE_ID, RULE_NAME };
