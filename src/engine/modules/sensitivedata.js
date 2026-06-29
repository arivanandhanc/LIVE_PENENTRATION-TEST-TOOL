// Passive sensitive-information exposure. Re-fetches a sample of crawled pages
// and inspects responses for stack traces, verbose framework errors, internal
// IPs/hostnames, and other data that should not be exposed to clients.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Sensitive Data Exposure';

const SIGNATURES = [
  { name: 'Stack trace / debug error', sev: 'medium', cwe: 'CWE-209',
    re: /(?:Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|System\.\w+Exception|Microsoft OLE DB|ORA-\d{5}|\bstack trace\b|Whitelabel Error Page|Werkzeug Debugger|Rails\.application|NoMethodError|TypeError:.*\n\s+at )/i,
    desc: 'The response contains a stack trace or verbose error, leaking framework internals, file paths, and code structure useful to an attacker.',
    rec: 'Disable debug mode in production; return generic error pages; log details server-side only.' },
  { name: 'Internal IP / hostname disclosure', sev: 'low', cwe: 'CWE-200',
    re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b|\b[\w-]+\.(?:internal|local|corp|lan)\b/,
    desc: 'An internal/private IP address or internal hostname is disclosed in the response, revealing internal network topology.',
    rec: 'Strip internal addresses/hostnames from responses, error messages, and headers.' },
  { name: 'Email address disclosure', sev: 'info', cwe: 'CWE-200',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
    desc: 'Email addresses are exposed in page content, which can fuel phishing and spam targeting.',
    rec: 'Avoid publishing raw email addresses; use contact forms or obfuscation where appropriate.' },
  { name: 'Possible API/debug data leak', sev: 'low', cwe: 'CWE-200',
    re: /"(?:secret|password|passwd|api[_-]?key|access[_-]?token|private[_-]?key)"\s*:\s*"[^"]{6,}"/i,
    desc: 'A response contains a JSON field named like a secret with a value, suggesting sensitive data is returned to the client.',
    rec: 'Never return secrets to clients; scope API responses to the minimum necessary fields.' },
];

export default {
  id: 'sensitivedata',
  name: 'Sensitive Data Exposure',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    const urls = new Set([ctx.target.url]);
    for (const p of (surface?.pages || []).slice(0, 25)) urls.add(p.url);

    const findings = [];
    const reportedTypes = new Set();

    for (const url of urls) {
      const res = await request(url, { redirect: 'manual', maxBytes: 256 * 1024, timeout: 9000 });
      if (!res.ok || !res.body) continue;
      for (const sig of SIGNATURES) {
        if (reportedTypes.has(sig.name)) continue; // one finding per type
        const m = sig.re.exec(res.body);
        if (m) {
          // Email signature is noisy; only report if several distinct addresses.
          if (sig.name === 'Email address disclosure') {
            const emails = new Set((res.body.match(new RegExp(sig.re, 'g')) || []).slice(0, 10));
            if (emails.size < 2) continue;
          }
          reportedTypes.add(sig.name);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: sig.sev,
              confidence: sig.name === 'Stack trace / debug error' ? 'firm' : 'tentative',
              title: sig.name,
              description: sig.desc,
              evidence: `URL: ${url}\nMatch: ${String(m[0]).slice(0, 160).replace(/\s+/g, ' ').trim()}`,
              recommendation: sig.rec,
              owasp: 'A04:2021 Insecure Design', cwe: sig.cwe,
            })
          );
          ctx.log(`Sensitive data: ${sig.name} @ ${url}`, sig.sev === 'medium' ? 'warn' : 'info');
        }
      }
    }

    return { findings };
  },
};
