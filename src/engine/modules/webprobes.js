// Light, non-destructive injection probes: reflected-input canary and
// open-redirect parameter testing. These look for *reflection*, not
// exploitation — a deliberately conservative approach for a hosted scanner.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Injection & Redirect Probes';

const REDIRECT_PARAMS = ['next', 'url', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'dest', 'destination', 'continue', 'r'];

export default {
  id: 'webprobes',
  name: 'Injection & Redirect Probes',
  category: CAT,
  default: true,
  async run(ctx) {
    const findings = [];
    const base = new URL(ctx.target.url);

    // --- Reflected input canary (potential reflected XSS) ---
    const canary = 'xq' + Math.random().toString(36).slice(2, 8) + 'zz';
    const payload = `"'<${canary}>`;
    const u1 = new URL(base);
    u1.searchParams.set('q', payload);
    const r1 = await request(u1.toString(), { redirect: 'manual', maxBytes: 256 * 1024 });
    if (r1.ok && /text\/html/i.test(r1.headers['content-type'] || '') && r1.body.includes(`<${canary}>`)) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium',
          title: 'Reflected user input rendered without encoding',
          description:
            'A unique marker injected via the `q` query parameter was reflected back into the HTML response with angle brackets intact and unescaped. This indicates missing output encoding and a likely reflected cross-site scripting (XSS) vector. Manual confirmation with a script payload is recommended.',
          evidence: `Sent q=${payload}\nReflected unescaped: <${canary}> found in HTML response`,
          recommendation:
            'Context-sensitively encode all user-controlled output (HTML-entity encode for HTML body). Adopt a framework that auto-escapes, and deploy a strong CSP as defence-in-depth.',
          owasp: 'A03:2021 Injection', cwe: 'CWE-79', cvss: 6.1,
        })
      );
      ctx.log('Reflected canary detected (possible XSS).', 'warn');
    }

    // --- Open redirect ---
    const evil = 'https://evil-redirect-probe.example/';
    for (const p of REDIRECT_PARAMS) {
      const u = new URL(base);
      u.searchParams.set(p, evil);
      const r = await request(u.toString(), { redirect: 'manual', readBody: false });
      if (r.ok && r.status >= 300 && r.status < 400 && r.location) {
        let dest;
        try { dest = new URL(r.location, u).toString(); } catch { dest = r.location; }
        if (dest.startsWith(evil) || /evil-redirect-probe\.example/.test(r.location)) {
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'medium',
              title: `Open redirect via "${p}" parameter`,
              description:
                `Supplying an external URL in the \`${p}\` parameter caused the application to issue a redirect (HTTP ${r.status}) to that attacker-controlled destination. Open redirects facilitate phishing and can chain into OAuth token theft or filter bypass.`,
              evidence: `GET ?${p}=${evil}\n→ ${r.status} Location: ${r.location}`,
              recommendation:
                'Validate redirect targets against an allow-list of internal paths/hosts, or use indirect reference tokens instead of full URLs.',
              owasp: 'A01:2021 Broken Access Control', cwe: 'CWE-601', cvss: 6.1,
            })
          );
          ctx.log(`Open redirect via ${p}.`, 'warn');
          break; // one confirmed instance is enough
        }
      }
    }

    return { findings };
  },
};
