// Information-disclosure checks: server/version banners, framework fingerprints.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Information Disclosure';

export default {
  id: 'infodisclosure',
  name: 'Information Disclosure',
  category: CAT,
  default: true,
  async run(ctx) {
    const res = await request(ctx.target.url, { redirect: 'follow' });
    if (!res.ok) return { findings: [] };
    const h = res.headers;
    const findings = [];
    const disclosed = [];

    // Version-bearing banners.
    const banners = {
      server: h['server'],
      'x-powered-by': h['x-powered-by'],
      'x-aspnet-version': h['x-aspnet-version'],
      'x-aspnetmvc-version': h['x-aspnetmvc-version'],
      'x-generator': h['x-generator'],
    };
    for (const [k, v] of Object.entries(banners)) {
      if (v && /\d/.test(v)) disclosed.push(`${k}: ${v}`);
      else if (v && (k === 'x-powered-by' || k === 'x-generator')) disclosed.push(`${k}: ${v}`);
    }

    if (disclosed.length) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'low',
          title: 'Server / framework version disclosure',
          description:
            'Response headers reveal the underlying server software, framework, and/or version numbers. This intelligence helps an attacker target known CVEs for the exact stack in use.',
          evidence: disclosed.join('\n'),
          recommendation:
            'Suppress or genericise version banners (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`). Most servers/frameworks support disabling these.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-200',
        })
      );
    }

    // Detected tech stack (informational, also stored for the report).
    const stack = [];
    if (h['server']) stack.push(h['server']);
    if (h['x-powered-by']) stack.push(h['x-powered-by']);
    if (/wordpress/i.test(res.body)) stack.push('WordPress');
    if (/__NEXT_DATA__/.test(res.body)) stack.push('Next.js');
    if (/ng-version=/.test(res.body)) stack.push('Angular');
    if (/data-reactroot|react/i.test(res.body) && /__REACT/.test(res.body)) stack.push('React');

    return { findings, info: { techStack: [...new Set(stack)] } };
  },
};
