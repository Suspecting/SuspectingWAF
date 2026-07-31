const logger = require('../utils/logger');
const { getClientIp, isIpInList } = require('../utils/ip');
const { checkRateLimit } = require('./ratelimit');
const queries = require('../db/queries');
const sqli = require('./rules/sqli');
const xss = require('./rules/xss');
const cmdi = require('./rules/cmdi');
const traversal = require('./rules/traversal');
const rce = require('./rules/rce');
const ssrf = require('./rules/ssrf');
const xxe = require('./rules/xxe');
const crlf = require('./rules/crlf');
const botdetect = require('./botdetect');
const csrf = require('./rules/csrf');
const fileupload = require('./rules/fileupload');

const RULE_MODULES = [
  sqli,
  xss,
  traversal,
  cmdi,
  crlf,
  ssrf,
  xxe,
  rce,
  csrf,
  fileupload,
  botdetect,
];
let blockedIpsCache = [];
let allowedIpsCache = [];
let customRulesCache = [];
let wafModeCache = 'block';
let rateLimitCache = {}; // keyed by site.id
let lastCacheRefresh = 0;
const CACHE_TTL = 10000; // refresh every 10 seconds

function refreshCache() {
  const now = Date.now();
  if (now - lastCacheRefresh < CACHE_TTL) return;

  try {
    blockedIpsCache = queries.getActiveBlockedIps();
    allowedIpsCache = queries.getActiveAllowedIps();
    customRulesCache = queries.getEnabledCustomRules();
    wafModeCache = queries.getSetting('waf_mode') || 'block';
    // Pre-load rate limits for all active sites
    const allSites = queries.getAllSites();
    rateLimitCache = {};
    for (const site of allSites) {
      const rl = queries.getRateLimitForSite(site.id);
      if (rl && rl.enabled) {
        rateLimitCache[site.id] = { rps: rl.requests_per_second, burst: rl.burst, banDuration: rl.ban_duration };
      }
    }
    lastCacheRefresh = now;
  } catch (err) {
    logger.error('Failed to refresh inspector cache', { error: err.message });
  }
}

/**
 * Core inspection engine. Evaluates an incoming HTTP request against the 
 * configured blocklists, allowlists, custom rules, rate limits, and built-in WAF rules.
 * Returns an object indicating whether the request should be blocked.
 * 
 * @param {import('http').IncomingMessage} req - The incoming HTTP request
 * @param {Object} [site] - Optional site configuration containing WAF status and limits
 * @returns {{blocked: boolean, rule?: string, action?: string, detail?: string}} Inspection result
 */
function inspect(req, site = null) {
  // Refresh in-memory cache to avoid disk I/O bottlenecks
  refreshCache();

  const ip = getClientIp(req);
  const wafMode = wafModeCache;
  if (wafMode === 'off') {
    return { blocked: false };
  }
  if (site && !site.waf_enabled) {
    return { blocked: false };
  }
  if (isIpInList(ip, allowedIpsCache)) {
    return { blocked: false };
  }
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
  const customResult = checkCustomRules(req, ip);
  if (customResult.blocked) {
    logAttack(req, customResult, site);
    return customResult;
  }
  if (customResult.allowed) {
    return { blocked: false };
  }
  let rateLimits = {};
  if (site) {
    rateLimits = rateLimitCache[site.id] || {};
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
  if (req.url && !req.query) {
    req.query = parseQuery(req.url);
  }

  // Evaluate request against all active detection rules
  for (const rule of RULE_MODULES) {
    try {
      const result = rule.check(req);
      if (result.blocked) {
        const action = wafMode === 'monitor' ? 'monitored' : 'blocked';
        const fullResult = { ...result, action };
        logAttack(req, fullResult, site);
        if (wafMode === 'monitor') {
          return { blocked: false, monitored: true, ...result };
        }
        return fullResult;
      }
    } catch (err) {
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
  // Custom query parser to prevent HTTP Parameter Pollution bypasses
  const idx = url.indexOf('?');
  if (idx === -1) return {};
  const qs = url.slice(idx + 1);
  const params = {};
  for (const pair of qs.split('&')) {
    const [key, ...rest] = pair.split('=');
    if (key) {
      try {
        params[decodeURIComponent(key.replace(/\+/g, ' '))] = decodeURIComponent(rest.join('=').replace(/\+/g, ' '));
      } catch {
        params[key] = rest.join('=').replace(/\+/g, ' ');
      }
    }
  }
  return params;
}
function invalidateCache() {
  lastCacheRefresh = 0;
}

module.exports = { inspect, invalidateCache };
