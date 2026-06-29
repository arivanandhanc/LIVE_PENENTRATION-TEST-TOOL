// Active OS command injection and Server-Side Template Injection (SSTI).
// SSTI uses a safe arithmetic marker; command injection uses an echo marker,
// with a time-based fallback only in aggressive mode.
import { sendPayload, selectPoints, pointLabel } from '../inject.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Command Injection & SSTI (Active)';

// SSTI probes: each maps a template expression to the expected rendered output.
const SSTI = [
  { payload: '${7*7}', expect: '49', engine: 'JSP EL / Spring' },
  { payload: '{{7*7}}', expect: '49', engine: 'Jinja2 / Twig / Angular' },
  { payload: '<%= 7*7 %>', expect: '49', engine: 'ERB (Ruby)' },
  { payload: '#{7*7}', expect: '49', engine: 'Ruby / Thymeleaf' },
  { payload: '{7*7}', expect: '', engine: '' }, // control: must NOT render
];

export default {
  id: 'cmdinjection',
  name: 'Command Injection & SSTI (Active)',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const aggressive = ctx.profile === 'aggressive';
    const points = selectPoints(surface, ctx.budget?.activePoints || 50);
    if (!points.length) return { findings: [] };

    const findings = [];
    const reported = new Set();

    for (const { point, param } of points) {
      const key = `${point.url}|${param}`;
      if (reported.has(key)) continue;

      // --- SSTI (arithmetic marker) ---
      // Only flag if the unique '49' appears AND the {7*7} control did not,
      // to avoid pages that merely echo input verbatim.
      const uniq = Math.floor(Math.random() * 90 + 10); // 2-digit
      const a = uniq, b = uniq + 1;
      const product = String(a * b);
      let sstiHit = null;
      for (const probe of SSTI) {
        if (!probe.expect) continue;
        const pl = probe.payload.replace('7*7', `${a}*${b}`);
        const res = await sendPayload(point, param, pl, { timeout: 9000 });
        if (res.ok && (res.body || '').includes(product) && !(res.body || '').includes(pl)) {
          sstiHit = { probe, pl };
          break;
        }
      }
      if (sstiHit) {
        reported.add(key);
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'critical', cvss: 9.8,
            title: `Server-Side Template Injection in "${param}"`,
            description:
              `The \`${param}\` parameter evaluated a template expression server-side (\`${sstiHit.pl}\` rendered as ${product}), confirming Server-Side Template Injection (${sstiHit.probe.engine}). SSTI typically escalates to remote code execution on the server.`,
            evidence: `${pointLabel(point, param)}\nPayload: ${sstiHit.pl}\nRendered result: ${product}`,
            recommendation:
              'Never pass user input into template engines as template source. Use logic-less or sandboxed templates, pass user data only as bound variables, and patch the template engine.',
            owasp: 'A03:2021 Injection', cwe: 'CWE-1336',
            references: ['https://portswigger.net/web-security/server-side-template-injection'],
          })
        );
        ctx.log(`SSTI confirmed: ${param} @ ${point.url}`, 'warn');
        continue;
      }

      // --- Command injection (echo marker) ---
      const tag = 'ci' + Math.random().toString(36).slice(2, 8);
      // `expr` style + echo; works across some sh contexts without side effects.
      const echoPayloads = [`;echo ${tag}`, `|echo ${tag}`, `& echo ${tag}`, `$(echo ${tag})`, `\`echo ${tag}\``];
      let cmdHit = null;
      for (const pl of echoPayloads) {
        const res = await sendPayload(point, param, `1${pl}`, { timeout: 9000 });
        if (res.ok && (res.body || '').includes(tag) && !(res.body || '').includes(`echo ${tag}`)) {
          cmdHit = { pl, res }; break;
        }
      }
      if (cmdHit) {
        reported.add(key);
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'critical', cvss: 9.8,
            title: `OS Command Injection in "${param}"`,
            description:
              `A shell command-substitution payload injected into \`${param}\` produced the echoed marker "${tag}" in the response, confirming OS command injection. This allows arbitrary command execution on the host with the privileges of the web application.`,
            evidence: `${pointLabel(point, param)}\nPayload: 1${cmdHit.pl}\nMarker observed: ${tag}`,
            recommendation:
              'Avoid invoking the OS shell with user input. Use language-native APIs, pass arguments as an argv array (never a shell string), and apply strict allow-list validation.',
            owasp: 'A03:2021 Injection', cwe: 'CWE-78',
            references: ['https://owasp.org/www-community/attacks/Command_Injection'],
          })
        );
        ctx.log(`Command injection confirmed: ${param} @ ${point.url}`, 'warn');
        continue;
      }

      // --- Time-based command injection (aggressive only) ---
      if (aggressive) {
        const baseT = 800;
        const sleepPayloads = [`1;sleep 5`, `1|sleep 5`, `1&& sleep 5`, `1$(sleep 5)`, `1& ping -n 6 127.0.0.1`];
        for (const pl of sleepPayloads) {
          const r = await sendPayload(point, param, pl, { timeout: 12000 });
          if (r.ok && r.elapsed >= 4500) {
            reported.add(key);
            findings.push(
              finding({
                module: MOD, category: CAT, severity: 'critical', cvss: 9.8,
                title: `Blind OS Command Injection (time-based) in "${param}"`,
                description: `A time-delay command payload in \`${param}\` delayed the response ~5s, indicating blind OS command injection.`,
                evidence: `${pointLabel(point, param)}\nPayload: ${pl}\nresponse=${r.elapsed}ms`,
                recommendation: 'Do not pass user input to the OS shell; use argv-based execution and strict validation.',
                owasp: 'A03:2021 Injection', cwe: 'CWE-78',
              })
            );
            ctx.log(`Blind command injection: ${param} @ ${point.url}`, 'warn');
            break;
          }
        }
      }
    }

    return { findings };
  },
};
