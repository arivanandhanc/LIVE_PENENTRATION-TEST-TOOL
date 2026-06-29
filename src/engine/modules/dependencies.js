// Dependency / SBOM vulnerability audit using the OSV.dev API (no key needed).
// Triggered when the user supplies package.json / lockfile content with the scan.
import { finding } from '../finding.js';
import { scoreV3, severityFromScore } from '../../util/cvss.js';

const CAT = 'Dependencies';
const MOD = 'Dependency Audit (OSV)';

/** Parse supplied manifest text into [{name, version, ecosystem}]. */
function parseDeps(opts) {
  const out = [];
  const seen = new Set();
  const add = (name, version) => {
    const v = String(version || '').replace(/^[\^~>=<\s]+/, '').split(/\s/)[0];
    const key = name + '@' + v;
    if (!name || !v || seen.has(key) || /^(?:\*|latest|workspace:|file:|git\+|link:)/.test(v)) return;
    seen.add(key);
    out.push({ name, version: v, ecosystem: 'npm' });
  };

  if (opts.packageJson) {
    try {
      const pkg = typeof opts.packageJson === 'string' ? JSON.parse(opts.packageJson) : opts.packageJson;
      for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        for (const [n, v] of Object.entries(pkg[sec] || {})) add(n, v);
      }
    } catch { /* ignore parse errors; reported by caller */ }
  }

  // package-lock.json (v2/v3 "packages" map).
  if (opts.packageLock) {
    try {
      const lock = typeof opts.packageLock === 'string' ? JSON.parse(opts.packageLock) : opts.packageLock;
      for (const [path, meta] of Object.entries(lock.packages || {})) {
        if (!path || !meta?.version) continue;
        const name = path.replace(/^.*node_modules\//, '');
        if (name) add(name, meta.version);
      }
      for (const [n, meta] of Object.entries(lock.dependencies || {})) {
        if (meta?.version) add(n, meta.version);
      }
    } catch { /* ignore */ }
  }

  return out;
}

async function osvBatch(deps) {
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      queries: deps.map((d) => ({
        version: d.version,
        package: { name: d.name, ecosystem: d.ecosystem === 'npm' ? 'npm' : d.ecosystem },
      })),
    }),
  });
  if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`);
  const json = await res.json();
  return json.results || [];
}

async function osvDetail(id) {
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${id}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function sevFromOsv(detail) {
  // Prefer an accurate CVSS base score computed from the vector; otherwise
  // fall back to the database-specific severity label (e.g. GHSA HIGH).
  const vector = detail?.severity?.find?.((s) => /CVSS/i.test(s.type))?.score;
  const num = scoreV3(vector);
  if (num != null) {
    return { sev: severityFromScore(num) || 'medium', cvss: num };
  }
  const db = (detail?.database_specific?.severity || '').toLowerCase();
  if (db.includes('critical')) return { sev: 'critical' };
  if (db.includes('high')) return { sev: 'high' };
  if (db.includes('moderate') || db.includes('medium')) return { sev: 'medium' };
  if (db.includes('low')) return { sev: 'low' };
  return { sev: 'medium' }; // a known, unscored vuln is at least medium
}

export default {
  id: 'dependencies',
  name: 'Dependency Audit (OSV)',
  category: CAT,
  default: false, // only meaningful when a manifest is supplied
  async run(ctx) {
    const deps = parseDeps(ctx.options);
    if (!deps.length) {
      ctx.log('Dependency audit skipped — no package.json/lockfile supplied.');
      return { findings: [] };
    }
    ctx.log(`Auditing ${deps.length} dependencies against OSV…`);

    let results;
    try {
      results = await osvBatch(deps);
    } catch (e) {
      ctx.log(`OSV query failed: ${e.message}`, 'warn');
      return { findings: [] };
    }

    const findings = [];
    const vulnerable = [];
    for (let i = 0; i < deps.length; i++) {
      const vulns = results[i]?.vulns || [];
      if (vulns.length) vulnerable.push({ dep: deps[i], vulns });
    }

    ctx.info.dependencies = { audited: deps.length, vulnerable: vulnerable.length };

    // Fetch details for up to a sane number to avoid hammering the API.
    let detailBudget = 40;
    for (const { dep, vulns } of vulnerable) {
      const ids = vulns.map((v) => v.id);
      let worstSev = 'low';
      let worstCvss = null;
      const summaries = [];
      for (const id of ids.slice(0, 5)) {
        let sev = { sev: 'medium' };
        let summary = id;
        if (detailBudget-- > 0) {
          const detail = await osvDetail(id);
          if (detail) {
            sev = sevFromOsv(detail);
            summary = `${id}: ${detail.summary || detail.details?.slice(0, 120) || ''}`.trim();
          }
        }
        summaries.push(summary);
        if (rank(sev.sev) > rank(worstSev)) worstSev = sev.sev;
        if (sev.cvss && (!worstCvss || sev.cvss > worstCvss)) worstCvss = sev.cvss;
      }

      findings.push(
        finding({
          module: MOD, category: CAT, severity: worstSev, cvss: worstCvss,
          title: `Vulnerable dependency: ${dep.name}@${dep.version} (${ids.length} ${ids.length > 1 ? 'advisories' : 'advisory'})`,
          description:
            `The dependency \`${dep.name}\` at version ${dep.version} is affected by ${ids.length} known vulnerability advisory(ies) per the OSV database. Vulnerable third-party packages are a leading cause of breaches and are directly exploitable when reachable.`,
          evidence: summaries.join('\n') + (ids.length > 5 ? `\n…and ${ids.length - 5} more` : ''),
          recommendation: `Upgrade \`${dep.name}\` to a patched release (see advisories), or apply the maintainer’s recommended mitigation. Add automated dependency scanning to CI.`,
          owasp: 'A06:2021 Vulnerable and Outdated Components', cwe: 'CWE-1395',
          references: ids.map((id) => `https://osv.dev/vulnerability/${id}`),
        })
      );
    }

    if (!vulnerable.length) {
      ctx.log(`No known vulnerabilities among ${deps.length} dependencies.`, 'ok');
    }

    return { findings };
  },
};

function rank(s) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0;
}
