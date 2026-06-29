// DNS enumeration and email-security posture (SPF / DMARC / DKIM hints).
import dnsp from 'node:dns/promises';
import { finding } from '../finding.js';

const CAT = 'TLS/DNS';
const MOD = 'DNS & Email Security';

async function safe(fn) {
  try { return await fn(); } catch { return null; }
}

export default {
  id: 'dns',
  name: 'DNS & Email Security',
  category: CAT,
  default: true,
  async run(ctx) {
    const host = ctx.target.hostname;
    if (ctx.target.isIp) return { findings: [] };

    // Use the registrable apex for email records where possible.
    const parts = host.split('.');
    const apex = parts.length > 2 ? parts.slice(-2).join('.') : host;

    const [a, aaaa, mx, ns, txt, dmarcTxt] = await Promise.all([
      safe(() => dnsp.resolve4(host)),
      safe(() => dnsp.resolve6(host)),
      safe(() => dnsp.resolveMx(apex)),
      safe(() => dnsp.resolveNs(apex)),
      safe(() => dnsp.resolveTxt(apex)),
      safe(() => dnsp.resolveTxt(`_dmarc.${apex}`)),
    ]);

    const txtFlat = (txt || []).map((r) => r.join(''));
    const dmarcFlat = (dmarcTxt || []).map((r) => r.join(''));

    ctx.info.dns = {
      a: a || [], aaaa: aaaa || [],
      mx: (mx || []).map((m) => `${m.exchange} (${m.priority})`),
      ns: ns || [], txt: txtFlat,
    };

    const findings = [];
    const hasMx = (mx || []).length > 0;
    const spf = txtFlat.find((t) => /^v=spf1/i.test(t));
    const dmarc = dmarcFlat.find((t) => /^v=DMARC1/i.test(t));

    // Only flag email-security gaps if the domain actually sends/receives mail.
    if (hasMx || spf) {
      if (!spf) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'low',
            title: 'No SPF record published',
            description: `The domain ${apex} has mail infrastructure but publishes no SPF (v=spf1) TXT record. Without SPF, receivers cannot validate which servers may send mail for the domain, easing spoofing.`,
            evidence: `TXT ${apex}: no v=spf1 record found`,
            recommendation: 'Publish an SPF record listing authorised senders, ending in `-all` (hard fail) once validated.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-290',
          })
        );
      } else if (/\+all|~all\s*$/i.test(spf) === false && /-all/i.test(spf) === false) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'info',
            title: 'SPF record present but not strict',
            description: 'An SPF record exists but does not end in a hard-fail (`-all`), reducing spoofing protection.',
            evidence: spf,
            recommendation: 'Tighten SPF to `-all` after confirming all legitimate senders are listed.',
            owasp: 'A05:2021 Security Misconfiguration',
          })
        );
      }

      if (!dmarc) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'low',
            title: 'No DMARC record published',
            description: `No DMARC policy is published at _dmarc.${apex}. DMARC ties SPF/DKIM together and instructs receivers how to handle failures; its absence enables email spoofing and phishing using the domain.`,
            evidence: `TXT _dmarc.${apex}: not found`,
            recommendation: 'Publish a DMARC record, starting at `p=none` for monitoring then progressing to `quarantine`/`reject`.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-290',
          })
        );
      } else if (/p=none/i.test(dmarc)) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'info',
            title: 'DMARC policy set to p=none (monitor only)',
            description: 'A DMARC record exists but is in monitoring mode (p=none), so spoofed mail is not actively blocked.',
            evidence: dmarc,
            recommendation: 'Move to p=quarantine then p=reject once reporting confirms legitimate flows pass.',
            owasp: 'A05:2021 Security Misconfiguration',
          })
        );
      }
    }

    ctx.log(`DNS: A=${(a || []).length} MX=${(mx || []).length} NS=${(ns || []).length} SPF=${spf ? 'yes' : 'no'} DMARC=${dmarc ? 'yes' : 'no'}`);
    return { findings };
  },
};
