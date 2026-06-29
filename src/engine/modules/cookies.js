// Cookie security-flag analysis (Secure, HttpOnly, SameSite).
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Cookie Security';

function parseSetCookies(res) {
  // Node's fetch coalesces multiple Set-Cookie into one comma-joined string;
  // use getSetCookie() when available for correctness.
  const list = res.rawHeaders?.getSetCookie?.() || [];
  if (list.length) return list;
  const raw = res.headers['set-cookie'];
  return raw ? [raw] : [];
}

export default {
  id: 'cookies',
  name: 'Cookie Security',
  category: CAT,
  default: true,
  async run(ctx) {
    const res = await request(ctx.target.url, { redirect: 'follow' });
    if (!res.ok) return { findings: [] };
    const cookies = parseSetCookies(res);
    if (!cookies.length) {
      ctx.log('No Set-Cookie headers observed.');
      return { findings: [] };
    }

    const findings = [];
    const https = ctx.target.protocol === 'https';

    for (const c of cookies) {
      const name = c.split('=')[0].trim();
      const low = c.toLowerCase();
      const issues = [];
      if (https && !low.includes('secure')) issues.push('missing `Secure`');
      if (!low.includes('httponly')) issues.push('missing `HttpOnly`');
      if (!low.includes('samesite')) issues.push('missing `SameSite`');
      else if (low.includes('samesite=none') && !low.includes('secure'))
        issues.push('`SameSite=None` without `Secure`');

      if (issues.length) {
        const sessionish = /sess|sid|token|auth|jwt/i.test(name);
        findings.push(
          finding({
            module: MOD, category: CAT,
            severity: sessionish ? 'medium' : 'low',
            title: `Cookie "${name}" missing security attributes`,
            description:
              `The cookie "${name}" is set with weak attributes: ${issues.join(', ')}. ` +
              (sessionish
                ? 'As this appears to be a session/authentication cookie, weak flags increase the risk of session hijacking via XSS (no HttpOnly) or interception (no Secure) and CSRF (no SameSite).'
                : 'Weak cookie flags broaden the application’s exposure to theft and cross-site request forgery.'),
            evidence: c.length > 200 ? c.slice(0, 200) + '…' : c,
            recommendation:
              'Set `Secure`, `HttpOnly`, and an explicit `SameSite` (Lax or Strict) on session cookies. Use `SameSite=None; Secure` only when cross-site delivery is required.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-614',
            references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
          })
        );
      }
    }

    return { findings, info: { cookieCount: cookies.length } };
  },
};
