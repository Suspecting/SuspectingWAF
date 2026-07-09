// src/db/queries.js
// pre-built query functions so we're not writing raw SQL everywhere
// each function gets a fresh db handle from the connection pool

const { getDb } = require('./connection');

// ---- SITES ----

function getAllSites() {
  return getDb().prepare(`
    SELECT s.*, c.domain as cert_domain 
    FROM sites s 
    LEFT JOIN certificates c ON s.cert_id = c.id 
    ORDER BY s.created_at DESC
  `).all();
}

function getSiteById(id) {
  return getDb().prepare('SELECT * FROM sites WHERE id = ?').get(id);
}

function createSite({ name, listen_port, upstream_url, server_names, ssl_enabled, cert_id, waf_enabled }) {
  const result = getDb().prepare(`
    INSERT INTO sites (name, listen_port, upstream_url, server_names, ssl_enabled, cert_id, waf_enabled) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(name, listen_port, upstream_url, server_names || '', ssl_enabled ? 1 : 0, cert_id || null, waf_enabled !== false ? 1 : 0);
  return { id: result.lastInsertRowid, ...arguments[0] };
}

function updateSite(id, fields) {
  const allowed = ['name', 'listen_port', 'upstream_url', 'server_names', 'ssl_enabled', 'cert_id', 'waf_enabled', 'status'];
  const updates = [];
  const values = [];

  for (const [key, val] of Object.entries(fields)) {
    if (allowed.includes(key)) {
      updates.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (updates.length === 0) return null;

  updates.push('updated_at = CURRENT_TIMESTAMP');
  values.push(id);

  return getDb().prepare(`UPDATE sites SET ${updates.join(', ')} WHERE id = ?`).run(...values);
}

function deleteSite(id) {
  return getDb().prepare('DELETE FROM sites WHERE id = ?').run(id);
}

// ---- ATTACK LOGS ----

function getAttackLogs({ page = 1, limit = 50, site_id, rule_id, severity, src_ip, startDate, endDate } = {}) {
  let where = [];
  let params = [];

  if (site_id) { where.push('site_id = ?'); params.push(site_id); }
  if (rule_id) { where.push('rule_id = ?'); params.push(rule_id); }
  if (severity) { where.push('severity = ?'); params.push(severity); }
  if (src_ip) { where.push('src_ip = ?'); params.push(src_ip); }
  if (startDate) { where.push('timestamp >= ?'); params.push(startDate); }
  if (endDate) { where.push('timestamp <= ?'); params.push(endDate); }

  const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';
  const offset = (page - 1) * limit;

  const rows = getDb().prepare(`
    SELECT al.*, s.name as site_name 
    FROM attack_logs al 
    LEFT JOIN sites s ON al.site_id = s.id 
    ${whereClause} 
    ORDER BY al.timestamp DESC 
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  const total = getDb().prepare(`SELECT COUNT(*) as count FROM attack_logs ${whereClause}`).get(...params);

  return { rows, total: total.count, page, limit };
}

function getAttackLogById(id) {
  return getDb().prepare(`
    SELECT al.*, s.name as site_name 
    FROM attack_logs al 
    LEFT JOIN sites s ON al.site_id = s.id 
    WHERE al.id = ?
  `).get(id);
}

function insertAttackLog(log) {
  return getDb().prepare(`
    INSERT INTO attack_logs (site_id, src_ip, method, host, url, rule_id, rule_name, severity, payload, action, user_agent, request_headers, response_code)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    log.site_id || null, log.src_ip, log.method, log.host, log.url,
    log.rule_id, log.rule_name, log.severity || 'medium',
    log.payload, log.action || 'blocked', log.user_agent,
    log.request_headers ? JSON.stringify(log.request_headers) : null,
    log.response_code || 403
  );
}

// ---- CUSTOM RULES ----

function getCustomRules() {
  return getDb().prepare('SELECT * FROM custom_rules ORDER BY priority DESC, created_at DESC').all();
}

function getEnabledCustomRules() {
  return getDb().prepare('SELECT * FROM custom_rules WHERE enabled = 1 ORDER BY priority DESC').all();
}

function createCustomRule(rule) {
  const result = getDb().prepare(`
    INSERT INTO custom_rules (name, description, type, field, operator, value, enabled, priority)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(rule.name, rule.description || '', rule.type, rule.field, rule.operator, rule.value, rule.enabled !== false ? 1 : 0, rule.priority || 0);
  return { id: result.lastInsertRowid };
}

function updateCustomRule(id, fields) {
  const allowed = ['name', 'description', 'type', 'field', 'operator', 'value', 'enabled', 'priority'];
  const updates = [];
  const values = [];

  for (const [key, val] of Object.entries(fields)) {
    if (allowed.includes(key)) {
      updates.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (updates.length === 0) return null;
  values.push(id);

  return getDb().prepare(`UPDATE custom_rules SET ${updates.join(', ')} WHERE id = ?`).run(...values);
}

function deleteCustomRule(id) {
  return getDb().prepare('DELETE FROM custom_rules WHERE id = ?').run(id);
}

// ---- IP LIST ----

function getIpList(type) {
  let query = 'SELECT * FROM ip_list';
  const params = [];
  if (type) {
    query += ' WHERE type = ?';
    params.push(type);
  }
  query += ' ORDER BY created_at DESC';
  return getDb().prepare(query).all(...params);
}

function getActiveBlockedIps() {
  return getDb().prepare(`
    SELECT ip FROM ip_list 
    WHERE type = 'block' 
    AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).all().map(r => r.ip);
}

function getActiveAllowedIps() {
  return getDb().prepare(`
    SELECT ip FROM ip_list 
    WHERE type = 'allow' 
    AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).all().map(r => r.ip);
}

function addIpToList({ ip, type, reason, expires_at }) {
  const result = getDb().prepare(`
    INSERT INTO ip_list (ip, type, reason, expires_at) VALUES (?, ?, ?, ?)
  `).run(ip, type, reason || '', expires_at || null);
  return { id: result.lastInsertRowid };
}

function removeIpFromList(id) {
  return getDb().prepare('DELETE FROM ip_list WHERE id = ?').run(id);
}

// ---- CERTIFICATES ----

function getCertificates() {
  return getDb().prepare('SELECT * FROM certificates ORDER BY created_at DESC').all();
}

function getCertById(id) {
  return getDb().prepare('SELECT * FROM certificates WHERE id = ?').get(id);
}

function createCertificate({ name, domain, cert_path, key_path, expires_at }) {
  const result = getDb().prepare(`
    INSERT INTO certificates (name, domain, cert_path, key_path, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(name, domain, cert_path, key_path, expires_at || null);
  return { id: result.lastInsertRowid };
}

function deleteCertificate(id) {
  return getDb().prepare('DELETE FROM certificates WHERE id = ?').run(id);
}

// ---- RATE LIMITS ----

function getRateLimits() {
  return getDb().prepare(`
    SELECT rl.*, s.name as site_name 
    FROM rate_limits rl 
    LEFT JOIN sites s ON rl.site_id = s.id
  `).all();
}

function getRateLimitForSite(siteId) {
  return getDb().prepare('SELECT * FROM rate_limits WHERE site_id = ?').get(siteId);
}

function upsertRateLimit({ site_id, requests_per_second, burst, ban_duration, enabled }) {
  const existing = getDb().prepare('SELECT id FROM rate_limits WHERE site_id = ?').get(site_id);
  if (existing) {
    return getDb().prepare(`
      UPDATE rate_limits SET requests_per_second = ?, burst = ?, ban_duration = ?, enabled = ? WHERE site_id = ?
    `).run(requests_per_second, burst, ban_duration, enabled ? 1 : 0, site_id);
  } else {
    return getDb().prepare(`
      INSERT INTO rate_limits (site_id, requests_per_second, burst, ban_duration, enabled) VALUES (?, ?, ?, ?, ?)
    `).run(site_id, requests_per_second, burst, ban_duration, enabled ? 1 : 0);
  }
}

// ---- STATS ----

function getOverviewStats(hours = 24) {
  const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();

  const total = getDb().prepare('SELECT COUNT(*) as count FROM attack_logs WHERE timestamp >= ?').get(since);
  const bySeverity = getDb().prepare(`
    SELECT severity, COUNT(*) as count FROM attack_logs WHERE timestamp >= ? GROUP BY severity
  `).all(since);
  const byRule = getDb().prepare(`
    SELECT rule_name, COUNT(*) as count FROM attack_logs WHERE timestamp >= ? GROUP BY rule_name ORDER BY count DESC LIMIT 10
  `).all(since);
  const topIps = getDb().prepare(`
    SELECT src_ip, COUNT(*) as count FROM attack_logs WHERE timestamp >= ? GROUP BY src_ip ORDER BY count DESC LIMIT 10
  `).all(since);
  const siteCount = getDb().prepare('SELECT COUNT(*) as count FROM sites WHERE status = ?').get('active');
  const uniqueIps = getDb().prepare('SELECT COUNT(DISTINCT src_ip) as count FROM attack_logs WHERE timestamp >= ?').get(since);

  return {
    total_attacks: total.count,
    by_severity: bySeverity,
    by_rule: byRule,
    top_ips: topIps,
    active_sites: siteCount.count,
    unique_attackers: uniqueIps.count,
  };
}

function getTimeseries(hours = 24) {
  const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  // group by hour
  return getDb().prepare(`
    SELECT 
      strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
      COUNT(*) as attacks,
      COUNT(DISTINCT src_ip) as unique_ips
    FROM attack_logs 
    WHERE timestamp >= ?
    GROUP BY hour 
    ORDER BY hour ASC
  `).all(since);
}

// ---- SETTINGS ----

function getSettings() {
  const rows = getDb().prepare('SELECT * FROM settings').all();
  const obj = {};
  for (const r of rows) obj[r.key] = r.value;
  return obj;
}

function getSetting(key) {
  const row = getDb().prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  return getDb().prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = ?
  `).run(key, value, value);
}

// ---- USERS ----

function getUserByUsername(username) {
  return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
  return getDb().prepare('SELECT id, username, created_at, last_login FROM users WHERE id = ?').get(id);
}

function updateUserLogin(id) {
  return getDb().prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(id);
}

function updateUserPassword(id, hash) {
  return getDb().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
}

module.exports = {
  // sites
  getAllSites, getSiteById, createSite, updateSite, deleteSite,
  // logs
  getAttackLogs, getAttackLogById, insertAttackLog,
  // rules
  getCustomRules, getEnabledCustomRules, createCustomRule, updateCustomRule, deleteCustomRule,
  // ip list
  getIpList, getActiveBlockedIps, getActiveAllowedIps, addIpToList, removeIpFromList,
  // certs
  getCertificates, getCertById, createCertificate, deleteCertificate,
  // rate limits
  getRateLimits, getRateLimitForSite, upsertRateLimit,
  // stats
  getOverviewStats, getTimeseries,
  // settings
  getSettings, getSetting, setSetting,
  // users
  getUserByUsername, getUserById, updateUserLogin, updateUserPassword,
};
