const RULE_ID = 'fileupload';
const RULE_NAME = 'Malicious File Upload';

const DANGEROUS_EXTENSIONS = [
  /\.php[345678]?$/i,
  /\.phtml$/i,
  /\.phar$/i,
  /\.exe$/i,
  /\.dll$/i,
  /\.cmd$/i,
  /\.bat$/i,
  /\.sh$/i,
  /\.cgi$/i,
  /\.pl$/i,
  /\.jspx?$/i,
  /\.asp[x]?$/i,
];

function check(req) {
  // Only check POST/PUT with a body
  if (!req.rawBody || typeof req.rawBody !== 'string') {
    return { blocked: false };
  }

  // Check if it's a multipart upload
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('multipart/form-data')) {
    return { blocked: false };
  }

  // Quick scan for filename="..."
  const filenameRegex = /Content-Disposition:.*?filename="([^"]+)"/gi;
  let match;
  while ((match = filenameRegex.exec(req.rawBody)) !== null) {
    const filename = match[1];
    
    for (const ext of DANGEROUS_EXTENSIONS) {
      if (ext.test(filename)) {
        return {
          blocked: true,
          rule: RULE_ID,
          ruleName: RULE_NAME,
          severity: 'critical',
          detail: `Attempted to upload dangerous file extension: ${filename}`,
          payload: filename,
        };
      }
    }
  }

  return { blocked: false };
}

module.exports = { check, RULE_ID, RULE_NAME };
