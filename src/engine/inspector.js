// src/engine/inspector.js
// the main inspection pipeline — this is where all the pieces come together
//
// every incoming request passes through here. we run it against:
// 1. IP allowlist/blocklist (fast path)
// 2. custom rules
// 3. rate limiting
// 4. all detection rule modules
//
// the first match wins. if anything flags it, we return the block decision.
// in "monitor" mode, we still log but don't actually block.

const logger = require('../utils/logger');
const { getClientIp, isIpInList } = require('../utils/ip');
const { checkRateLimit } = require('./ratelimit');
const queries = require('../db/queries');

// import all rule modules
const sqli = require('./rules/sqli');
const xss = require('./rules/xss');
const cmdi = require('./rules/cmdi');
const traversal = require('./rules/traversal');
const rce = require('./rules/rce');
const ssrf = require('./rules/ssrf');
const xxe = require('./rules/xxe');
const crlf = require('./rules/crlf');
const botdetect = require('./botdetect');

// rule modules in order of execution
// order matters — put fast/common checks first
const RULE_MODULES = [
  sqli,
  xss,
  traversal,
  cmdi,
  crlf,
  ssrf,
  xxe,
  rce,
  botdetect,
];

// cache for IP lists so we don't hit the DB on every request
let blockedIpsCache = [];
let allowedIpsCache = [];
let customRulesCache = [];
let lastCacheRefresh = 0;
const CACHE_TTL = 30000; // refresh every 30 seconds

function refreshCache() {
  const now = Date.now();
  if (now - lastCacheRefresh < CACHE_TTL) return;

  try {
    blockedIpsCache = queries.getActiveBlockedIps();
    allowedIpsCache = queries.getActiveAllowedIps();
    customRulesCache = queries.getEnabledCustomRules();
    lastCacheRefresh = now;
  } catch (err) {
    logger.error('Failed to refresh inspector cache', { error: err.message });
  }
}

/**
 * Inspect an incoming request
 * @param {object} req - the HTTP request object
 * @param {object} site - the site config this request matches (if any)
 * @returns {{ blocked: boolean, rule?: string, ruleName?: string, severity?: string, detail?: string, payload?: string, action?: string }}
 */
function inspect(req, site = null) {
  refreshCache();

  const ip = getClientIp(req);
  const wafMode = queries.getSetting('waf_mode') || 'block';

  // if WAF is off, pass everything
  if (wafMode === 'off') {
    return { blocked: false };
  }

  // if site has WAF disabled, pass
  if (site && !site.waf_enabled) {
    return { blocked: false };
  }

  // --- fast path: IP allowlist ---
  if (isIpInList(ip, allowedIpsCache)) {
    return { blocked: false };
  }

  // --- fast path: IP blocklist ---
  if (isIpInList(ip, blockedIpsCache)) {
    const result = {
      blocked: true,
      rule: 'ipblock',
      ruleName: 'IP Blocklist',
      severity: 'medium',
      detail: `IP ${ip} is in the blocklist`,
      payload: ip,
      action: 'blocked',
    };
    logAttack(req, result, site);
    return result;
  }

  // --- custom rules ---
  const customResult = checkCustomRules(req, ip);
  if (customResult.blocked) {
    logAttack(req, customResult, site);
    return customResult;
  }
  // custom allow rules can whitelist specific requests
  if (customResult.allowed) {
    return { blocked: false };
  }

  // --- rate limiting ---
  let rateLimits = {};
  if (site) {
    const rl = queries.getRateLimitForSite(site.id);
    if (rl && rl.enabled) {
      rateLimits = { rps: rl.requests_per_second, burst: rl.burst, banDuration: rl.ban_duration };
    }
  }
  const rateResult = checkRateLimit(ip, rateLimits);
  if (rateResult.limited) {
    const result = {
      blocked: true,
      rule: 'ratelimit',
      ruleName: 'Rate Limit',
      severity: 'medium',
      detail: `Rate limit exceeded for ${ip}`,
      payload: `${rateResult.retryAfter}s retry`,
      action: 'blocked',
      retryAfter: rateResult.retryAfter,
    };
    logAttack(req, result, site);
    return result;
  }

  // --- detection rules ---
  // parse query params for rule modules
  if (req.url && !req.query) {
    req.query = parseQuery(req.url);
  }

  for (const rule of RULE_MODULES) {
    try {
      const result = rule.check(req);
      if (result.blocked) {
        const action = wafMode === 'monitor' ? 'monitored' : 'blocked';
        const fullResult = { ...result, action };
        logAttack(req, fullResult, site);

        // in monitor mode, log but don't block
        if (wafMode === 'monitor') {
          return { blocked: false, monitored: true, ...result };
        }
        return fullResult;
      }
    } catch (err) {
      // if a rule module throws, log it but don't block the request
      // we'd rather let a request through than crash the pipeline
      logger.error('Rule module error', { rule: rule.RULE_ID, error: err.message });
    }
  }

  return { blocked: false };
}

function checkCustomRules(req, ip) {
  for (const rule of customRulesCache) {
    const matched = matchCustomRule(req, ip, rule);
    if (matched) {
      if (rule.type === 'allow') {
        return { blocked: false, allowed: true };
      }
      return {
        blocked: true,
        rule: `custom_${rule.id}`,
        ruleName: `Custom: ${rule.name}`,
        severity: 'medium',
        detail: rule.description || `Matched custom rule: ${rule.name}`,
        payload: `${rule.field} ${rule.operator} ${rule.value}`,
        action: 'blocked',
      };
    }
  }
  return { blocked: false };
}

function matchCustomRule(req, ip, rule) {
  let target = '';

  switch (rule.field) {
    case 'ip':
      target = ip;
      break;
    case 'url':
      target = req.url || '';
      break;
    case 'user_agent':
      target = req.headers?.['user-agent'] || '';
      break;
    case 'header':
      // value format: "Header-Name: pattern"
      const parts = rule.value.split(':');
      if (parts.length >= 2) {
        const headerName = parts[0].trim().toLowerCase();
        target = req.headers?.[headerName] || '';
        rule = { ...rule, value: parts.slice(1).join(':').trim() };
      }
      break;
    case 'host':
      target = req.headers?.host || '';
      break;
    default:
      return false;
  }

  switch (rule.operator) {
    case 'equals':
      return target === rule.value;
    case 'contains':
      return target.includes(rule.value);
    case 'regex':
      try {
        return new RegExp(rule.value, 'i').test(target);
      } catch { return false; }
    case 'cidr':
      return isIpInList(target, [rule.value]);
    default:
      return false;
  }
}

function logAttack(req, result, site) {
  const ip = getClientIp(req);
  try {
    queries.insertAttackLog({
      site_id: site?.id || null,
      src_ip: ip,
      method: req.method,
      host: req.headers?.host || '',
      url: req.url,
      rule_id: result.rule,
      rule_name: result.ruleName,
      severity: result.severity,
      payload: result.payload || '',
      action: result.action || 'blocked',
      user_agent: req.headers?.['user-agent'] || '',
      request_headers: req.headers,
      response_code: 403,
    });
  } catch (err) {
    logger.error('Failed to log attack', { error: err.message });
  }
}

function parseQuery(url) {
  const idx = url.indexOf('?');
  if (idx === -1) return {};
  const qs = url.slice(idx + 1);
  const params = {};
  for (const pair of qs.split('&')) {
    const [key, ...rest] = pair.split('=');
    if (key) {
      try {
        params[decodeURIComponent(key)] = decodeURIComponent(rest.join('='));
      } catch {
        params[key] = rest.join('=');
      }
    }
  }
  return params;
}

// force cache refresh (called when rules/IPs are updated via API)
function invalidateCache() {
  lastCacheRefresh = 0;
}

module.exports = { inspect, invalidateCache };
