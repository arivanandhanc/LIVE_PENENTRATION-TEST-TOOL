// Central configuration. Override via environment variables in production.
export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.HOST || '0.0.0.0',

  // Where scan results are persisted (JSON files).
  dataDir: process.env.DATA_DIR || 'data',

  // Default network timeouts (ms).
  httpTimeout: parseInt(process.env.HTTP_TIMEOUT || '12000', 10),
  tcpTimeout: parseInt(process.env.TCP_TIMEOUT || '2500', 10),

  // Concurrency limit for port scanning.
  portConcurrency: parseInt(process.env.PORT_CONCURRENCY || '60', 10),

  // Safety: refuse to scan these hosts unless EXPLICITLY allowed.
  // Loopback / link-local / metadata endpoints are blocked by default to
  // prevent the hosted tool from being abused for SSRF against internal infra.
  blockPrivateTargets: process.env.ALLOW_PRIVATE !== 'true',

  // User-Agent presented by the scanner. Identifying yourself is good practice
  // for authorised testing.
  userAgent:
    process.env.SCANNER_UA ||
    'PenTestTool/0.1 (+https://pentest.arivanandhan.in; authorised-scanning-only)',

  // Branding used in generated reports.
  brand: {
    company: process.env.BRAND_COMPANY || 'Arivanandhan',
    product: process.env.BRAND_PRODUCT || 'Security Assessment',
    site: process.env.BRAND_SITE || 'sectools.arivanandhan.in',
  },
};
