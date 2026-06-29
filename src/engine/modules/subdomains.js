// Passive subdomain enumeration via Certificate Transparency logs (crt.sh),
// then live resolution to identify active hosts. No brute-force traffic to the
// target — purely OSINT plus DNS lookups.
import dnsp from 'node:dns/promises';
import { finding } from '../finding.js';
import { config } from '../../config.js';

const CAT = 'TLS/DNS';
const MOD = 'Subdomain Enumeration';

async function crtsh(domain) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': config.userAgent, Accept: 'application/json' },
      signal: ctrl.signal,
    });
    if (!res.ok) return [];
    const json = await res.json();
    const names = new Set();
    for (const row of json) {
      for (const n of String(row.name_value || '').split('\n')) {
        const name = n.trim().toLowerCase().replace(/^\*\./, '');
        if (name.endsWith(domain) && !name.includes(' ')) names.add(name);
      }
    }
    return [...names];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export default {
  id: 'subdomains',
  name: 'Subdomain Enumeration',
  category: CAT,
  default: false,
  async run(ctx) {
    if (ctx.target.isIp) return { findings: [] };
    const host = ctx.target.hostname;
    const parts = host.split('.');
    const apex = parts.length > 2 ? parts.slice(-2).join('.') : host;

    const names = await crtsh(apex);
    if (!names.length) {
      ctx.log('Subdomain enum: no CT-log entries found.');
      return { findings: [] };
    }

    // Resolve up to a sane cap to identify live hosts.
    const cap = Math.min(names.length, 120);
    const live = [];
    let i = 0;
    const workers = Array.from({ length: 20 }, async () => {
      while (i < cap) {
        const name = names[i++];
        try {
          const recs = await dnsp.lookup(name, { all: true });
          if (recs.length) live.push({ name, ip: recs[0].address });
        } catch { /* dead/NXDOMAIN */ }
      }
    });
    await Promise.all(workers);
    live.sort((a, b) => a.name.localeCompare(b.name));

    ctx.info.subdomains = { discovered: names.length, live: live.length, hosts: live };
    ctx.log(`Subdomains: ${names.length} from CT logs, ${live.length} live`);

    const findings = [];
    if (live.length) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: live.length > 25 ? 'low' : 'info',
          title: `${live.length} live subdomain(s) for ${apex}`,
          description:
            `Certificate Transparency logs revealed ${names.length} subdomain name(s) for \`${apex}\`, of which ${live.length} currently resolve. A large or stale subdomain footprint increases attack surface and can include forgotten staging/admin hosts or subdomain-takeover candidates.`,
          evidence: live.slice(0, 40).map((h) => `${h.name} → ${h.ip}`).join('\n') + (live.length > 40 ? `\n…and ${live.length - 40} more` : ''),
          recommendation:
            'Inventory all subdomains; decommission unused hosts and dangling DNS records (subdomain-takeover risk). Ensure staging/admin subdomains are not internet-exposed without access controls.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-200',
        })
      );
    }
    return { findings };
  },
};
