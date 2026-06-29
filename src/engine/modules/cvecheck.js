// Known-vulnerability detection by version signature. Extracts software/version
// from response banners and front-end library references, then matches against
// a curated list of well-known vulnerable version ranges (a lightweight,
// dependency-free nuclei-style check). Findings are flagged for confirmation.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Reconnaissance';
const MOD = 'Known Vulnerable Versions';

// Compare dotted versions: returns -1/0/1.
function cmp(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
const lt = (a, b) => cmp(a, b) < 0;
const gte = (a, b) => cmp(a, b) >= 0;

// Curated signatures. Each: how to extract a version, and a vulnerable predicate.
const SIGNATURES = [
  { product: 'jQuery', sev: 'medium', cwe: 'CWE-79',
    from: 'body', re: /jquery[/-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    vuln: (v) => lt(v, '3.5.0'),
    note: 'jQuery < 3.5.0 is affected by XSS via htmlPrefilter (CVE-2020-11022/11023).',
    fix: 'Upgrade jQuery to 3.5.0 or later.' },
  { product: 'Bootstrap', sev: 'medium', cwe: 'CWE-79',
    from: 'body', re: /bootstrap[/-]?(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)/i,
    vuln: (v) => lt(v, '3.4.1') || (gte(v, '4.0.0') && lt(v, '4.3.1')),
    note: 'Bootstrap < 3.4.1 / < 4.3.1 contains XSS in data-template/data-content (CVE-2019-8331 et al.).',
    fix: 'Upgrade Bootstrap to 3.4.1+ or 4.3.1+.' },
  { product: 'AngularJS', sev: 'medium', cwe: 'CWE-79',
    from: 'body', re: /angular[/-]?(1\.\d+\.\d+)(?:\.min)?\.js/i,
    vuln: (v) => lt(v, '1.8.0'),
    note: 'AngularJS < 1.8.0 has multiple known sandbox-bypass/XSS issues; AngularJS is end-of-life.',
    fix: 'Migrate off AngularJS (EOL) or upgrade to the final 1.8.x and add CSP.' },
  { product: 'Lodash', sev: 'high', cwe: 'CWE-1321',
    from: 'body', re: /lodash[/-]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    vuln: (v) => lt(v, '4.17.21'),
    note: 'Lodash < 4.17.21 is vulnerable to prototype pollution / ReDoS (CVE-2020-8203, CVE-2021-23337).',
    fix: 'Upgrade Lodash to 4.17.21 or later.' },
  { product: 'OpenSSH', sev: 'medium', cwe: 'CWE-noinfo',
    from: 'banner', re: /OpenSSH[_/](\d+\.\d+)/i,
    vuln: (v) => lt(v, '8.5'),
    note: 'Older OpenSSH versions carry multiple CVEs; verify against the vendor advisory for the exact build.',
    fix: 'Update OpenSSH to a current, patched release.' },
  { product: 'nginx', sev: 'low', cwe: 'CWE-noinfo',
    from: 'server', re: /nginx\/(\d+\.\d+\.\d+)/i,
    vuln: (v) => lt(v, '1.21.0'),
    note: 'nginx < 1.21.0 predates several security fixes (e.g. resolver/DNS handling).',
    fix: 'Upgrade nginx to a current stable release.' },
  { product: 'Apache httpd', sev: 'medium', cwe: 'CWE-noinfo',
    from: 'server', re: /Apache\/(\d+\.\d+\.\d+)/i,
    vuln: (v) => lt(v, '2.4.54'),
    note: 'Apache httpd < 2.4.54 is affected by multiple CVEs (incl. mod_proxy SSRF CVE-2021-40438).',
    fix: 'Upgrade Apache httpd to 2.4.54 or later.' },
  { product: 'PHP', sev: 'medium', cwe: 'CWE-noinfo',
    from: 'header:x-powered-by', re: /PHP\/(\d+\.\d+\.\d+)/i,
    vuln: (v) => lt(v, '8.0.0'),
    note: 'PHP < 8.0 is end-of-life and unpatched against newer CVEs.',
    fix: 'Upgrade to a supported PHP release (8.1+).' },
];

export default {
  id: 'cvecheck',
  name: 'Known Vulnerable Versions',
  category: CAT,
  default: true,
  async run(ctx) {
    const res = await request(ctx.target.url, { redirect: 'follow', maxBytes: 512 * 1024 });
    const body = res.ok ? res.body || '' : '';
    const server = res.ok ? res.headers['server'] || '' : '';
    const xpb = res.ok ? res.headers['x-powered-by'] || '' : '';
    const banners = (ctx.info.openPorts || []).map((p) => p.banner).filter(Boolean).join('\n');

    const findings = [];
    const seen = new Set();

    for (const sig of SIGNATURES) {
      let haystack = '';
      if (sig.from === 'body') haystack = body;
      else if (sig.from === 'server') haystack = server;
      else if (sig.from === 'banner') haystack = banners;
      else if (sig.from.startsWith('header:')) haystack = res.ok ? res.headers[sig.from.slice(7)] || '' : '';
      if (!haystack) continue;

      const m = sig.re.exec(haystack);
      if (!m) continue;
      const version = m[1];
      if (!sig.vuln(version)) continue;
      const key = sig.product + version;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push(
        finding({
          module: MOD, category: CAT, severity: sig.sev,
          title: `Outdated ${sig.product} ${version} (known vulnerabilities)`,
          description:
            `${sig.product} version ${version} was detected. ${sig.note} Version-based detection can yield false positives if patches were back-ported — confirm against the vendor advisory.`,
          evidence: `Detected: ${sig.product} ${version}\nSource: ${sig.from}\nMatch: ${m[0]}`,
          recommendation: sig.fix,
          owasp: 'A06:2021 Vulnerable and Outdated Components', cwe: sig.cwe === 'CWE-noinfo' ? null : sig.cwe,
        })
      );
      ctx.log(`Known-vuln version: ${sig.product} ${version}`, 'warn');
    }

    return { findings };
  },
};
