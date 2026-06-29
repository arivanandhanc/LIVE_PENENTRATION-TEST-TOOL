// HTTP method checks: dangerous verbs (TRACE/PUT/DELETE) and verbose OPTIONS.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'HTTP Methods';

export default {
  id: 'methods',
  name: 'HTTP Methods',
  category: CAT,
  default: true,
  async run(ctx) {
    const findings = [];

    const opt = await request(ctx.target.url, { method: 'OPTIONS', redirect: 'manual', readBody: false });
    const allow = opt.ok ? opt.headers['allow'] || opt.headers['access-control-allow-methods'] : null;

    if (allow) {
      ctx.info.allowedMethods = allow;
      const dangerous = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT', 'PATCH'].filter((m) =>
        new RegExp(`\\b${m}\\b`, 'i').test(allow)
      );
      if (dangerous.length) {
        findings.push(
          finding({
            module: MOD, category: CAT,
            severity: /TRACE|TRACK/i.test(allow) ? 'medium' : 'low',
            title: `Potentially dangerous HTTP methods advertised: ${dangerous.join(', ')}`,
            description:
              `The server advertises the following methods via OPTIONS: ${allow}. ` +
              'Methods such as TRACE/TRACK enable Cross-Site Tracing, and PUT/DELETE may permit unauthorised content modification if not strictly access-controlled.',
            evidence: `OPTIONS ${ctx.target.path} → Allow: ${allow}`,
            recommendation:
              'Disable unused HTTP methods at the web server/framework. Explicitly deny TRACE/TRACK; restrict write methods (PUT/DELETE/PATCH) to authenticated, authorised contexts.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-650',
          })
        );
      }
    }

    // Active TRACE confirmation (only if advertised or to be thorough — light).
    const trace = await request(ctx.target.url, { method: 'TRACE', redirect: 'manual', readBody: true, maxBytes: 4096 });
    if (trace.ok && trace.status === 200 && /TRACE\s/i.test(trace.body)) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium',
          title: 'HTTP TRACE method enabled (Cross-Site Tracing)',
          description:
            'The server responded to a TRACE request by echoing the request, confirming TRACE is enabled. This can be abused in Cross-Site Tracing (XST) attacks to read sensitive headers.',
          evidence: `TRACE / → ${trace.status}; request echoed in body`,
          recommendation: 'Disable the TRACE method on the web server and any upstream proxies.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-693',
        })
      );
    }

    return { findings };
  },
};
