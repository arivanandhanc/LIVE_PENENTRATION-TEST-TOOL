// Content / directory discovery. Probes a curated wordlist of sensitive paths,
// admin panels, backups, and API entry points, using a soft-404 baseline to
// suppress false positives on SPA/catch-all apps.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Content Discovery';

// Curated high-signal paths. (Generic file leaks like .git/.env are handled by
// the Exposed Files module; this focuses on panels, backups, and API surface.)
const WORDLIST = [
  { p: '/admin', t: 'Admin panel', sev: 'low' },
  { p: '/administrator', t: 'Admin panel', sev: 'low' },
  { p: '/login', t: 'Login page', sev: 'info' },
  { p: '/wp-admin/', t: 'WordPress admin', sev: 'low' },
  { p: '/wp-login.php', t: 'WordPress login', sev: 'info' },
  { p: '/phpmyadmin/', t: 'phpMyAdmin', sev: 'medium' },
  { p: '/.git/HEAD', t: 'Git metadata', sev: 'high' },
  { p: '/backup.zip', t: 'Backup archive', sev: 'high' },
  { p: '/backup.sql', t: 'Database backup', sev: 'high' },
  { p: '/db.sql', t: 'Database dump', sev: 'high' },
  { p: '/dump.sql', t: 'Database dump', sev: 'high' },
  { p: '/config.php.bak', t: 'Backup config', sev: 'high' },
  { p: '/web.config', t: 'IIS config', sev: 'medium' },
  { p: '/.htaccess', t: 'Apache config', sev: 'medium' },
  { p: '/.svn/entries', t: 'SVN metadata', sev: 'high' },
  { p: '/api', t: 'API root', sev: 'info' },
  { p: '/api/v1', t: 'API v1', sev: 'info' },
  { p: '/swagger.json', t: 'Swagger/OpenAPI spec', sev: 'low' },
  { p: '/swagger-ui.html', t: 'Swagger UI', sev: 'low' },
  { p: '/openapi.json', t: 'OpenAPI spec', sev: 'low' },
  { p: '/graphql', t: 'GraphQL endpoint', sev: 'low' },
  { p: '/actuator', t: 'Spring Actuator', sev: 'medium' },
  { p: '/actuator/health', t: 'Spring Actuator health', sev: 'low' },
  { p: '/actuator/env', t: 'Spring Actuator env (secrets!)', sev: 'high' },
  { p: '/metrics', t: 'Metrics endpoint', sev: 'low' },
  { p: '/debug', t: 'Debug endpoint', sev: 'medium' },
  { p: '/.aws/credentials', t: 'AWS credentials', sev: 'critical' },
  { p: '/.npmrc', t: 'npm config (tokens)', sev: 'high' },
  { p: '/robots.txt', t: 'robots.txt', sev: 'info' },
  { p: '/sitemap.xml', t: 'sitemap.xml', sev: 'info' },
  { p: '/.well-known/security.txt', t: 'security.txt', sev: 'info' },
  { p: '/console', t: 'Console', sev: 'low' },
  { p: '/server-info', t: 'Apache server-info', sev: 'medium' },
];

async function softBaseline(base) {
  const rnd = '/zz-' + Math.random().toString(36).slice(2, 10);
  const res = await request(new URL(rnd, base).toString(), { redirect: 'manual', maxBytes: 8192 });
  return { status: res.ok ? res.status : 404, len: res.ok ? (res.body || '').length : 0 };
}

export default {
  id: 'discovery',
  name: 'Content Discovery',
  category: CAT,
  default: false,
  async run(ctx) {
    const base = ctx.target.url;
    const baseline = await softBaseline(base);
    const softFallback = baseline.status === 200;

    const found = [];
    const findings = [];

    for (const w of WORDLIST) {
      const url = new URL(w.p, base).toString();
      const res = await request(url, { redirect: 'manual', maxBytes: 16 * 1024 });
      if (!res.ok) continue;
      const exists =
        (res.status === 200 || res.status === 401 || res.status === 403) &&
        !(softFallback && res.status === 200 && Math.abs((res.body || '').length - baseline.len) < 32);
      if (!exists) continue;

      found.push({ ...w, status: res.status });
      if (w.sev !== 'info') {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: w.sev,
            title: `Discovered: ${w.t} (${w.p})`,
            description: `Content discovery found an exposed resource at \`${w.p}\` (HTTP ${res.status}: ${w.t}). Exposed administrative, backup, or debug resources expand the attack surface and may leak sensitive data or grant unintended access.`,
            evidence: `GET ${w.p} → ${res.status}`,
            recommendation: 'Remove or restrict access to this resource. Place admin/debug/backup endpoints behind authentication and network controls; never deploy backups or VCS/config files to the web root.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-200',
          })
        );
      }
    }

    ctx.info.discovered = found.map((f) => `${f.status} ${f.p}`);
    ctx.log(`Content discovery: ${found.length} path(s) found`);
    return { findings };
  },
};
