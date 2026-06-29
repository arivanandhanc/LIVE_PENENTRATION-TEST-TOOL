// CORS misconfiguration probe: reflects an arbitrary Origin and inspects the
// Access-Control-Allow-* response. Non-destructive (a single GET).
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'CORS Configuration';

export default {
  id: 'cors',
  name: 'CORS Configuration',
  category: CAT,
  default: true,
  async run(ctx) {
    const evil = 'https://evil-cors-probe.example';
    const res = await request(ctx.target.url, {
      headers: { Origin: evil },
      redirect: 'manual',
    });
    if (!res.ok) return { findings: [] };

    const acao = res.headers['access-control-allow-origin'];
    const acac = (res.headers['access-control-allow-credentials'] || '').toLowerCase();
    const findings = [];

    if (acao === '*') {
      findings.push(
        finding({
          module: MOD, category: CAT,
          severity: acac === 'true' ? 'high' : 'low',
          title:
            acac === 'true'
              ? 'Wildcard CORS with credentials (invalid but dangerous)'
              : 'Wildcard CORS (Access-Control-Allow-Origin: *)',
          description:
            acac === 'true'
              ? 'The server returns `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. While browsers reject this exact combination, the configuration signals a permissive CORS policy and any environment-specific handling may still expose authenticated data cross-origin.'
              : 'The server allows any origin to read responses. This is acceptable for fully public, unauthenticated data, but becomes a data-exposure risk if any authenticated or sensitive endpoints share the policy.',
          evidence: `Access-Control-Allow-Origin: *${acac ? `\nAccess-Control-Allow-Credentials: ${acac}` : ''}`,
          recommendation:
            'Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins. Never combine credentialed responses with a wildcard or reflected origin.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-942',
          references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
        })
      );
    } else if (acao && acao.toLowerCase() === evil) {
      findings.push(
        finding({
          module: MOD, category: CAT,
          severity: acac === 'true' ? 'high' : 'medium',
          title: 'CORS reflects arbitrary Origin',
          description:
            `The server reflected an attacker-supplied Origin (\`${evil}\`) back in Access-Control-Allow-Origin` +
            (acac === 'true'
              ? ' together with Access-Control-Allow-Credentials: true. This allows any malicious site to issue credentialed cross-origin requests and read the authenticated responses — a serious data-exfiltration vector.'
              : '. Origin reflection without a strict allow-list is unsafe and typically a precursor to credentialed data exposure.'),
          evidence: `Sent: Origin: ${evil}\nGot:  Access-Control-Allow-Origin: ${acao}${acac ? `\n      Access-Control-Allow-Credentials: ${acac}` : ''}`,
          recommendation:
            'Validate the Origin header against a server-side allow-list and only echo back known-good origins. Do not reflect arbitrary Origins, especially with credentials enabled.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-942', cvss: 7.5,
        })
      );
    }

    return { findings };
  },
};
