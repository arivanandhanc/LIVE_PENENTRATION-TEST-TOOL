// Content / directory discovery.
//
// Two kinds of probes:
//   • "file"  — a sensitive file is only reported when the response BODY
//               actually matches that file's format (and is not an HTML page).
//               A bare 200 is never enough: catch-all servers return 200 for
//               everything, so status-only detection produces false positives.
//   • "path"  — an endpoint/panel whose existence is meaningful but cannot be
//               content-proven (e.g. /admin). Reported only when the response
//               clearly differs from the soft-404 baseline, at low confidence.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Content Discovery';

// kind: 'file' requires a content signature; 'path' is status/diff based.
const WORDLIST = [
  // --- Sensitive files: MUST match a content signature to be reported ---
  { p: '/.aws/credentials', t: 'AWS credentials', sev: 'critical', kind: 'file',
    sig: /aws_access_key_id|aws_secret_access_key|\[default\]/i },
  { p: '/.git/HEAD', t: 'Git metadata', sev: 'high', kind: 'file',
    sig: /^ref:\s+refs\/|^[0-9a-f]{40}\b/i },
  { p: '/.svn/entries', t: 'SVN metadata', sev: 'high', kind: 'file',
    sig: /^\d+\s|dir\n|svn:|has-props/i },
  { p: '/.npmrc', t: 'npm config (tokens)', sev: 'high', kind: 'file',
    sig: /_authToken|registry\s*=|\/\/.*:_password/i },
  { p: '/config.php.bak', t: 'PHP config backup', sev: 'high', kind: 'file',
    sig: /<\?php|\$[A-Za-z_]+\s*=|define\(/i },
  { p: '/web.config', t: 'IIS web.config', sev: 'medium', kind: 'file',
    sig: /<configuration\b|<system\.web\b|<\?xml/i },
  { p: '/backup.zip', t: 'Backup archive', sev: 'high', kind: 'file',
    sig: /^PK\x03\x04/, binary: true },
  { p: '/backup.sql', t: 'Database backup', sev: 'high', kind: 'file',
    sig: /INSERT INTO|CREATE TABLE|mysqldump|PostgreSQL database dump/i },
  { p: '/db.sql', t: 'Database dump', sev: 'high', kind: 'file',
    sig: /INSERT INTO|CREATE TABLE|mysqldump/i },
  { p: '/dump.sql', t: 'Database dump', sev: 'high', kind: 'file',
    sig: /INSERT INTO|CREATE TABLE|mysqldump/i },
  { p: '/swagger.json', t: 'Swagger/OpenAPI spec', sev: 'low', kind: 'file',
    sig: /"swagger"\s*:|"openapi"\s*:/i },
  { p: '/openapi.json', t: 'OpenAPI spec', sev: 'low', kind: 'file',
    sig: /"openapi"\s*:|"swagger"\s*:/i },
  { p: '/actuator/env', t: 'Spring Actuator env (secrets!)', sev: 'high', kind: 'file',
    sig: /"propertySources"|"activeProfiles"|"systemProperties"/i },
  { p: '/actuator/health', t: 'Spring Actuator health', sev: 'low', kind: 'file',
    sig: /"status"\s*:\s*"(UP|DOWN)"/i },

  // --- Panels / endpoints: status/diff based, low confidence ---
  { p: '/.git/config', t: 'Git config', sev: 'high', kind: 'file',
    sig: /\[core\]|repositoryformatversion/i },
  { p: '/phpmyadmin/', t: 'phpMyAdmin', sev: 'medium', kind: 'path',
    sig: /phpMyAdmin|pma_/i },
  { p: '/admin', t: 'Admin panel', sev: 'low', kind: 'path' },
  { p: '/administrator', t: 'Admin panel', sev: 'low', kind: 'path' },
  { p: '/wp-admin/', t: 'WordPress admin', sev: 'low', kind: 'path', sig: /wp-admin|wp-login|wordpress/i },
  // (/graphql is covered by the dedicated GraphQL module, which verifies it via
  //  an actual introspection request rather than a weak keyword match.)
  { p: '/actuator', t: 'Spring Actuator', sev: 'medium', kind: 'path', sig: /"_links"|"actuator"/i },
  { p: '/server-info', t: 'Apache server-info', sev: 'medium', kind: 'path', sig: /Apache Server Information/i },
  { p: '/debug', t: 'Debug endpoint', sev: 'medium', kind: 'path' },
];

function isHtml(res) {
  return /text\/html|application\/xhtml/i.test(res.headers['content-type'] || '');
}

async function baseline(base) {
  // Two random misses to learn the "not found" behaviour and its body.
  const make = async () => {
    const rnd = '/zz-' + Math.random().toString(36).slice(2, 12);
    const r = await request(new URL(rnd, base).toString(), { redirect: 'manual', maxBytes: 16 * 1024 });
    return r.ok ? { status: r.status, len: (r.body || '').length, body: (r.body || '').slice(0, 400) } : { status: 404, len: 0, body: '' };
  };
  const a = await make();
  const b = await make();
  return { status: a.status, len: a.len, body: a.body, len2: b.len, soft200: a.status === 200 && b.status === 200 };
}

// Looks like the catch-all "not found" page rather than a real resource.
function looksLikeBaseline(res, base) {
  if (!base.soft200) return false;
  const len = (res.body || '').length;
  const near = (x) => Math.abs(len - x) <= Math.max(40, x * 0.1);
  return (near(base.len) || near(base.len2)) && res.body.slice(0, 200) === base.body.slice(0, 200);
}

export default {
  id: 'discovery',
  name: 'Content Discovery',
  category: CAT,
  default: false,
  async run(ctx) {
    const base = ctx.target.url;
    const bl = await baseline(base);
    const found = [];
    const findings = [];

    for (const w of WORDLIST) {
      const url = new URL(w.p, base).toString();
      const res = await request(url, { redirect: 'manual', maxBytes: 32 * 1024 });
      if (!res.ok || res.status === 404) continue;

      let confirmed = false;
      let confidence = 'tentative';

      if (w.kind === 'file') {
        // A real sensitive file: 200 + content signature match + not an HTML page.
        // (Servers that answer 200 with an HTML page for missing files are
        // exactly the false-positive case we must reject.)
        const sigOk = w.sig ? w.sig.test(res.body || '') : false;
        if (res.status === 200 && sigOk && (w.binary || !isHtml(res))) {
          confirmed = true;
          confidence = 'firm';
        } else {
          continue; // no content proof → not reported
        }
      } else {
        // path/panel: must have a signature match, or a 200/401/403 that is
        // clearly different from the catch-all baseline. Always low confidence.
        if (looksLikeBaseline(res, bl)) continue;
        const statusMeaningful = res.status === 200 || res.status === 401 || res.status === 403;
        const sigOk = w.sig ? w.sig.test(res.body || '') : null;
        if (w.sig && sigOk === false) continue;      // had a signature, didn't match → skip
        if (!statusMeaningful) continue;
        if (res.status === 200 && bl.soft200 && !w.sig) continue; // can't trust 200 on catch-all sites
        confirmed = true;
        confidence = w.sig ? 'firm' : 'tentative';
      }

      if (!confirmed) continue;
      found.push({ ...w, status: res.status });

      const fileVerified = w.kind === 'file';
      findings.push(
        finding({
          module: MOD, category: CAT, severity: w.sev, confidence,
          title: `${fileVerified ? 'Exposed file' : 'Discovered endpoint'}: ${w.t} (${w.p})`,
          description: fileVerified
            ? `A request for \`${w.p}\` returned HTTP ${res.status} and the response body matches the expected format of a ${w.t} file. This indicates a genuinely exposed sensitive file that may leak credentials, source, or configuration.`
            : `The endpoint \`${w.p}\` responded with HTTP ${res.status} and appears to exist (${w.t}). This is reported at ${confidence} confidence — verify manually, as some servers respond to many paths.`,
          evidence: `GET ${w.p} → ${res.status}\nContent-Type: ${res.headers['content-type'] || '—'}\n${fileVerified ? 'Body matched expected file signature.' : (res.body || '').slice(0, 120).replace(/\s+/g, ' ').trim()}`,
          recommendation: 'Remove or restrict access to this resource. Keep admin/debug endpoints behind authentication and network controls; never deploy backups, VCS, or config/credential files to the web root.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-200',
        })
      );
      ctx.log(`Discovery: ${w.p} → ${res.status} (${confidence})`, w.sev === 'critical' || w.sev === 'high' ? 'warn' : 'info');
    }

    ctx.info.discovered = found.map((f) => `${f.status} ${f.p}`);
    ctx.log(`Content discovery: ${found.length} resource(s) verified`);
    return { findings };
  },
};
