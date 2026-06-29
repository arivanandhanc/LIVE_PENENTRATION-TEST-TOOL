// Active reflected-XSS testing. Injects a uniquely-marked breakout payload
// into each discovered parameter and checks whether the markers are reflected
// into the HTML response without encoding. Non-destructive (GET/POST only).
import { sendPayload, selectPoints, pointLabel } from '../inject.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Cross-Site Scripting (Active)';

export default {
  id: 'xss',
  name: 'Cross-Site Scripting (Active)',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const points = selectPoints(surface, ctx.budget?.activePoints || 80);
    if (!points.length) {
      ctx.log('XSS: no parameters discovered to test.');
      return { findings: [] };
    }

    const findings = [];
    const reported = new Set();

    for (const { point, param } of points) {
      const id = 'xq' + Math.random().toString(36).slice(2, 8);
      // Markers let us tell HTML-context reflection from encoded reflection.
      const payload = `'"><svg/onload=${id}>${id}`;
      const res = await sendPayload(point, param, payload, { timeout: 9000 });
      if (!res.ok) continue;
      const ctype = res.headers['content-type'] || '';
      if (!/text\/html/i.test(ctype)) continue;

      const raw = res.body || '';
      const unencoded = raw.includes(`<svg/onload=${id}>`) || raw.includes(`'"><svg/onload=${id}`);
      const encodedOnly = raw.includes(`&lt;svg/onload=${id}`) || raw.includes(`&#`);

      const key = `${point.url}|${param}`;
      if (unencoded && !reported.has(key)) {
        reported.add(key);
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'high', cvss: 6.1, confidence: 'confirmed',
            title: `Reflected XSS in "${param}"`,
            description:
              `A breakout payload injected into the \`${param}\` parameter was reflected into the HTML response with its angle brackets and event handler intact and unencoded. This confirms a reflected cross-site scripting (XSS) vulnerability — an attacker can execute arbitrary JavaScript in a victim's browser session, enabling session hijacking, credential theft, and full client-side compromise.`,
            evidence:
              `${pointLabel(point, param)}\nPayload: ${payload}\nReflected unencoded marker: <svg/onload=${id}>`,
            recommendation:
              'Context-sensitively encode all user-controlled output (HTML-entity encode in HTML body, attribute-encode in attributes, JS-encode in script contexts). Prefer auto-escaping templating, validate input, and deploy a strict Content-Security-Policy as defence-in-depth.',
            owasp: 'A03:2021 Injection', cwe: 'CWE-79',
            references: ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
          })
        );
        ctx.log(`XSS confirmed: ${param} @ ${point.url}`, 'warn');
      } else if (encodedOnly && raw.includes(id) && !reported.has(key)) {
        // Reflected but encoded — informational (input handling visible).
        reported.add(key);
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'info',
            title: `Parameter "${param}" reflects input (encoded)`,
            description: `The \`${param}\` parameter reflects user input into the response but appears to encode HTML metacharacters. No XSS was confirmed; included for completeness as a reflection point worth manual review in other contexts (attribute, JS, URL).`,
            evidence: `${pointLabel(point, param)}\nMarker ${id} reflected in encoded form.`,
            recommendation: 'Verify encoding is correct for every output context; keep CSP enabled.',
            owasp: 'A03:2021 Injection', cwe: 'CWE-79',
          })
        );
      }
    }

    return { findings, info: { xssTested: points.length } };
  },
};
