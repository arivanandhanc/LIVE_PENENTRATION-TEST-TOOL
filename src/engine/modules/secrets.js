// Scans crawled HTML pages and JavaScript assets for hard-coded secrets and
// API keys. Uses high-confidence patterns to limit false positives.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Exposed Secrets';

const PATTERNS = [
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/, sev: 'high' },
  { name: 'AWS Secret Access Key', re: /aws_secret_access_key["'\s:=]+([A-Za-z0-9/+]{40})\b/i, sev: 'critical' },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/, sev: 'high' },
  { name: 'Google OAuth Client Secret', re: /\bGOCSPX-[0-9A-Za-z\-_]{20,}\b/, sev: 'high' },
  { name: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, sev: 'high' },
  { name: 'Stripe Secret Key', re: /\bsk_live_[0-9A-Za-z]{20,}\b/, sev: 'critical' },
  { name: 'Stripe Restricted Key', re: /\brk_live_[0-9A-Za-z]{20,}\b/, sev: 'high' },
  { name: 'GitHub Token', re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/, sev: 'high' },
  { name: 'GitLab Token', re: /\bglpat-[0-9A-Za-z\-_]{20,}\b/, sev: 'high' },
  { name: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, sev: 'critical' },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, sev: 'low' },
  { name: 'Twilio Account SID', re: /\bAC[0-9a-f]{32}\b/, sev: 'medium' },
  { name: 'SendGrid API Key', re: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/, sev: 'critical' },
  { name: 'Mailgun API Key', re: /\bkey-[0-9a-f]{32}\b/, sev: 'high' },
  { name: 'Firebase Cloud Messaging Key', re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/, sev: 'high' },
  { name: 'Generic Secret Assignment', re: /(?:api[_-]?key|secret|passwd|password|token)["'\s:=]{1,4}["']([A-Za-z0-9\-_/+]{16,})["']/i, sev: 'medium' },
];

function scan(text, sourceUrl, hits) {
  for (const pat of PATTERNS) {
    const m = pat.re.exec(text);
    if (m) {
      const raw = m[0];
      const masked = raw.length > 12 ? raw.slice(0, 6) + '…' + raw.slice(-4) : raw;
      hits.push({ name: pat.name, sev: pat.sev, masked, source: sourceUrl });
    }
  }
}

export default {
  id: 'secrets',
  name: 'Exposed Secrets',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const hits = [];

    // Scan crawled page bodies (re-fetch a few) + all JS assets (capped).
    const jsAssets = (surface.jsAssets || []).slice(0, 25);
    for (const js of jsAssets) {
      const res = await request(js, { redirect: 'follow', maxBytes: 1024 * 1024, timeout: 9000 });
      if (res.ok && res.body) scan(res.body, js, hits);
    }
    // Also scan the landing page HTML.
    const home = await request(ctx.target.url, { redirect: 'follow', maxBytes: 512 * 1024 });
    if (home.ok && home.body) scan(home.body, ctx.target.url, hits);

    // De-dup by name+masked.
    const seen = new Set();
    const unique = hits.filter((h) => {
      const k = h.name + h.masked;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });

    ctx.log(`Secret scan: ${jsAssets.length} JS asset(s), ${unique.length} potential secret(s)`);

    const findings = unique.map((h) =>
      finding({
        module: MOD, category: CAT, severity: h.sev,
        title: `Potential exposed secret: ${h.name}`,
        description: `A string matching the signature of a ${h.name} was found in client-delivered code. Secrets embedded in front-end assets are visible to anyone and must be treated as compromised. ${h.name === 'JWT' || h.name === 'Generic Secret Assignment' ? 'This pattern can produce false positives — verify manually.' : ''}`,
        evidence: `Source: ${h.source}\nMatch (masked): ${h.masked}`,
        recommendation: 'Remove secrets from client-side code. Move them server-side, rotate any exposed credential immediately, and add secret-scanning to CI to prevent recurrence.',
        owasp: 'A07:2021 Identification and Authentication Failures', cwe: 'CWE-798',
        references: ['https://cwe.mitre.org/data/definitions/798.html'],
      })
    );

    return { findings, info: { secretsFound: unique.length } };
  },
};
