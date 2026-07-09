const net = require('net');

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = xff.split(',')[0].trim();
    if (net.isIP(first)) return first;
  }

  const xri = req.headers['x-real-ip'];
  if (xri && net.isIP(xri)) return xri;
  let addr = req.socket?.remoteAddress || '0.0.0.0';
  if (addr.startsWith('::ffff:')) {
    addr = addr.slice(7);
  }
  return addr;
}

function isIpInCidr(ip, cidr) {
  if (!cidr.includes('/')) {
    return ip === cidr;
  }

  const [range, bits] = cidr.split('/');
  const mask = parseInt(bits, 10);
  const ipNum = ipToNumber(ip);
  const rangeNum = ipToNumber(range);

  if (ipNum === null || rangeNum === null) return false;

  const maskBits = ~((1 << (32 - mask)) - 1) >>> 0;
  return (ipNum & maskBits) === (rangeNum & maskBits);
}

function ipToNumber(ip) {
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
  if (ip === 'localhost' || ip === '::1') return true;

  return false;
}

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
