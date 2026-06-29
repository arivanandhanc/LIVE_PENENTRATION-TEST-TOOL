// Probe for sensitive files/endpoints that are commonly left exposed.
// Each probe only fires a finding when the response strongly indicates the
// real artefact (status + content signature), to minimise false positives.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Exposed Files & Endpoints';

const PROBES = [
  { path: '/.git/config', sev: 'high', sig: /\[core\]|repositoryformatversion/i,
    title: 'Exposed .git repository',
    desc: 'A reachable /.git/config indicates the version-control directory is web-accessible. Attackers can reconstruct full source code (and any committed secrets) from the exposed objects.',
    rec: 'Block access to the .git directory at the web server, or deploy without the VCS metadata.', cwe: 'CWE-538' },
  { path: '/.env', sev: 'critical', sig: /[A-Z_]{3,}=.+/,
    title: 'Exposed .env file',
    desc: 'The application’s .env configuration file is publicly readable. These files routinely contain database credentials, API keys, and secrets, leading directly to full compromise.',
    rec: 'Remove .env from the web root and block it at the server; rotate any exposed secrets immediately.', cwe: 'CWE-538', cvss: 9.1 },
  { path: '/.DS_Store', sev: 'low', sig: /Bud1|\x00/,
    title: 'Exposed .DS_Store file',
    desc: 'A macOS .DS_Store file is accessible and can leak directory/file names, aiding further enumeration.',
    rec: 'Remove .DS_Store files from deployments and block the pattern at the server.', cwe: 'CWE-538' },
  { path: '/server-status', sev: 'medium', sig: /Apache Server Status|Server Version/i,
    title: 'Apache mod_status exposed',
    desc: 'The Apache /server-status page is publicly accessible, disclosing request details, client IPs, and internal vhost information.',
    rec: 'Restrict /server-status to localhost or trusted admin IPs.', cwe: 'CWE-200' },
  { path: '/phpinfo.php', sev: 'medium', sig: /phpinfo\(\)|PHP Version/i,
    title: 'phpinfo() exposed',
    desc: 'A phpinfo() page is reachable, disclosing PHP configuration, loaded modules, paths, and environment details useful for targeting.',
    rec: 'Remove phpinfo pages from production.', cwe: 'CWE-200' },
  { path: '/.well-known/security.txt', sev: 'info', sig: /contact:/i, positive: true,
    title: 'security.txt present (good practice)',
    desc: 'A security.txt policy file is published, giving researchers a clear vulnerability-disclosure channel. This is a positive security control.',
    rec: 'No action required.', cwe: null },
];

async function head404Baseline(ctx) {
  // Fetch a definitely-nonexistent path to learn how the app answers misses
  // (some apps return 200 for everything / SPA fallbacks). Capture the body so
  // we can recognise — and ignore — the catch-all page later.
  const rnd = '/zz-nonexistent-' + Math.random().toString(36).slice(2, 10);
  const res = await request(new URL(rnd, ctx.target.url).toString(), { redirect: 'manual', maxBytes: 32 * 1024 });
  return { status: res.ok ? res.status : 404, body: res.ok ? res.body || '' : '', len: res.ok ? (res.body || '').length : 0 };
}

// Length-ratio similarity; good enough to spot a repeated catch-all page.
function similar(a, b) {
  const max = Math.max(a, b) || 1;
  return 1 - Math.abs(a - b) / max;
}

export default {
  id: 'exposedfiles',
  name: 'Exposed Files & Endpoints',
  category: CAT,
  default: true,
  async run(ctx) {
    const baseline = await head404Baseline(ctx);
    const softFallback = baseline.status === 200; // app returns 200 for everything
    const findings = [];

    for (const p of PROBES) {
      const url = new URL(p.path, ctx.target.url).toString();
      const res = await request(url, { redirect: 'manual', maxBytes: 16 * 1024 });
      if (!res.ok) continue;
      const hit = res.status === 200 && p.sig.test(res.body);
      // When the app soft-404s with 200, a real artefact must look *different*
      // from the catch-all page; otherwise the signature matched the fallback
      // body (e.g. a homepage that happens to contain `KEY=value`) — skip it.
      const looksLikeFallback =
        softFallback && similar(res.body.length, baseline.len) > 0.95 && res.body.slice(0, 200) === baseline.body.slice(0, 200);
      if (hit && !looksLikeFallback) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: p.sev,
            title: p.title, description: p.desc,
            evidence: `GET ${p.path} → ${res.status}\n${res.body.slice(0, 160).replace(/\s+/g, ' ').trim()}`,
            recommendation: p.rec,
            owasp: p.positive ? null : 'A05:2021 Security Misconfiguration',
            cwe: p.cwe, cvss: p.cvss,
          })
        );
        ctx.log(`Exposed: ${p.path} (${res.status})`, p.positive ? 'ok' : 'warn');
      }
    }

    return { findings };
  },
};
