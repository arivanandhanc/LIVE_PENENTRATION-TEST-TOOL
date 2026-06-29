// Cross-Site Request Forgery detection. Flags state-changing (POST) forms that
// lack an anti-CSRF token field, which — combined with cookie-based auth and
// weak SameSite — exposes users to forged requests.
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Cross-Site Request Forgery';

const TOKEN_HINT = /csrf|xsrf|authenticity_token|__requestverificationtoken|_token|nonce|anti.?forgery/i;

export default {
  id: 'csrf',
  name: 'Cross-Site Request Forgery',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const postForms = (surface.forms || []).filter((f) => f.method === 'POST');
    if (!postForms.length) {
      ctx.log('CSRF: no POST forms discovered.');
      return { findings: [] };
    }

    const findings = [];
    const seen = new Set();
    for (const f of postForms) {
      const hasToken = f.inputs.some(
        (i) => TOKEN_HINT.test(i.name || '') || (i.type === 'hidden' && /token|nonce/i.test(i.name || ''))
      );
      if (hasToken) continue;
      const key = f.action;
      if (seen.has(key)) continue;
      seen.add(key);

      const fieldNames = f.inputs.map((i) => i.name).filter(Boolean);
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium', cvss: 6.5,
          title: `POST form without CSRF token (${new URL(f.action).pathname})`,
          description:
            `A state-changing form submitting to \`${f.action}\` contains no recognisable anti-CSRF token field. If the application relies on ambient cookie authentication and cookies are not strictly SameSite, an attacker's site can forge this request on behalf of an authenticated victim (Cross-Site Request Forgery).`,
          evidence: `Form action: ${f.action}\nMethod: POST\nFields: ${fieldNames.join(', ') || '(none named)'}\nNo CSRF/nonce field detected.`,
          recommendation:
            'Implement anti-CSRF tokens (synchroniser-token or double-submit) on all state-changing requests, and set authentication cookies to `SameSite=Lax` or `Strict`. Prefer framework CSRF middleware.',
          owasp: 'A01:2021 Broken Access Control', cwe: 'CWE-352',
          references: ['https://owasp.org/www-community/attacks/csrf', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
        })
      );
      ctx.log(`CSRF: token-less POST form at ${f.action}`, 'warn');
    }

    return { findings };
  },
};
