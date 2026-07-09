// src/utils/ip.js
// IP address utilities — parsing, CIDR matching, internal range checks
// used by the detection engine and the IP blocklist/allowlist

const net = require('net');

/**
 * parse an IP from a request, handling proxied connections
 * checks x-forwarded-for, x-real-ip, then falls back to socket address
 */
function getClientIp(req) {
  // x-forwarded-for can have multiple IPs: client, proxy1, proxy2
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = xff.split(',')[0].trim();
    if (net.isIP(first)) return first;
  }

  const xri = req.headers['x-real-ip'];
  if (xri && net.isIP(xri)) return xri;

  // fallback to socket
  let addr = req.socket?.remoteAddress || '0.0.0.0';
  // strip ipv6 prefix if it's actually ipv4
  if (addr.startsWith('::ffff:')) {
    addr = addr.slice(7);
  }
  return addr;
}

/**
 * check if an IP is in a CIDR range
 * supports both IPv4 and basic IPv4-mapped IPv6
 */
function isIpInCidr(ip, cidr) {
  // handle plain IP (no mask) as /32
  if (!cidr.includes('/')) {
    return ip === cidr;
  }

  const [range, bits] = cidr.split('/');
  const mask = parseInt(bits, 10);

  // only handle ipv4 for now
  const ipNum = ipToNumber(ip);
  const rangeNum = ipToNumber(range);

  if (ipNum === null || rangeNum === null) return false;

  const maskBits = ~((1 << (32 - mask)) - 1) >>> 0;
  return (ipNum & maskBits) === (rangeNum & maskBits);
}

/**
 * convert dotted IPv4 to a 32-bit number
 */
function ipToNumber(ip) {
  // strip ipv6 prefix
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);

  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let num = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) + octet;
  }
  return num >>> 0; // unsigned
}

/**
 * check if an IP is in a private/internal range
 * used by SSRF detection
 */
function isInternalIp(ip) {
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);

  const internalRanges = [
    '127.0.0.0/8',      // loopback
    '10.0.0.0/8',       // class A private
    '172.16.0.0/12',    // class B private
    '192.168.0.0/16',   // class C private
    '169.254.0.0/16',   // link-local
    '0.0.0.0/8',        // this network
  ];

  for (const range of internalRanges) {
    if (isIpInCidr(ip, range)) return true;
  }

  // also check for localhost hostnames
  if (ip === 'localhost' || ip === '::1') return true;

  return false;
}

/**
 * check if an IP matches any entry in a list
 * entries can be plain IPs or CIDR ranges
 */
function isIpInList(ip, list) {
  for (const entry of list) {
    if (isIpInCidr(ip, entry)) return true;
  }
  return false;
}

module.exports = {
  getClientIp,
  isIpInCidr,
  ipToNumber,
  isInternalIp,
  isIpInList,
};
