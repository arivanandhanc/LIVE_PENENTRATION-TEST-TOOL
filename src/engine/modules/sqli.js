// Active SQL-injection testing: error-based, boolean-based, and (in aggressive
// mode) time-based detection against discovered parameters.
import { sendPayload, selectPoints, pointLabel } from '../inject.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'SQL Injection (Active)';

const SQL_ERRORS = [
  /SQL syntax.*?MySQL/i, /Warning.*?\bmysqli?\b/i, /MySqlException/i,
  /valid MySQL result/i, /PostgreSQL.*?ERROR/i, /pg_query\(\)/i,
  /SQLite\/JDBCDriver/i, /SQLite3::/i, /sqlite_/i,
  /Microsoft SQL Server/i, /ODBC SQL Server Driver/i, /OLE DB.*?SQL Server/i,
  /Unclosed quotation mark after the character string/i,
  /ORA-\d{5}/i, /Oracle error/i, /quoted string not properly terminated/i,
  /SQLSTATE\[/i, /System\.Data\.SqlClient\.SqlException/i,
];

function bodyLen(res) {
  return res.ok ? (res.body || '').length : -1;
}
function similar(a, b) {
  if (a < 0 || b < 0) return 0;
  const max = Math.max(a, b) || 1;
  return 1 - Math.abs(a - b) / max;
}

export default {
  id: 'sqli',
  name: 'SQL Injection (Active)',
  category: CAT,
  default: false,
  needsCrawl: true,
  async run(ctx) {
    const surface = ctx.surface;
    if (!surface) return { findings: [] };
    const aggressive = ctx.profile === 'aggressive';
    const points = selectPoints(surface, ctx.budget?.activePoints || 60);
    if (!points.length) {
      ctx.log('SQLi: no parameters discovered to test.');
      return { findings: [] };
    }

    const findings = [];
    const reported = new Set();

    for (const { point, param } of points) {
      const key = `${point.url}|${param}`;
      if (reported.has(key)) continue;

      // --- Error-based ---
      const errRes = await sendPayload(point, param, `'"\`'`, { timeout: 9000 });
      if (errRes.ok) {
        const match = SQL_ERRORS.find((re) => re.test(errRes.body || ''));
        if (match) {
          reported.add(key);
          const snippet = (errRes.body.match(match) || [''])[0].slice(0, 160);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'critical', cvss: 9.8,
              title: `Error-based SQL Injection in "${param}"`,
              description:
                `Injecting SQL metacharacters into the \`${param}\` parameter triggered a database error message in the response, confirming the input is concatenated into a SQL query without proper parameterisation. SQL injection can lead to full database disclosure, authentication bypass, data manipulation, and in many cases remote code execution on the database host.`,
              evidence: `${pointLabel(point, param)}\nPayload: '"\`'\nDB error signature: ${snippet}`,
              recommendation:
                'Use parameterised queries / prepared statements for all database access. Never build SQL by string concatenation. Apply least-privilege DB accounts and validate input types.',
              owasp: 'A03:2021 Injection', cwe: 'CWE-89',
              references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
            })
          );
          ctx.log(`SQLi (error-based) confirmed: ${param} @ ${point.url}`, 'warn');
          continue;
        }
      }

      // --- Boolean-based ---
      const base = await sendPayload(point, param, '1', { timeout: 9000 });
      const tRes = await sendPayload(point, param, `1' AND '1'='1`, { timeout: 9000 });
      const fRes = await sendPayload(point, param, `1' AND '1'='2`, { timeout: 9000 });
      if (base.ok && tRes.ok && fRes.ok) {
        const simTrue = similar(bodyLen(base), bodyLen(tRes));
        const simFalse = similar(bodyLen(base), bodyLen(fRes));
        // TRUE clause mirrors baseline; FALSE clause diverges noticeably.
        if (simTrue > 0.95 && simFalse < 0.9 && Math.abs(bodyLen(tRes) - bodyLen(fRes)) > 40) {
          reported.add(key);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'critical', cvss: 9.1,
              title: `Boolean-based blind SQL Injection in "${param}"`,
              description:
                `The \`${param}\` parameter exhibits boolean-based blind SQL injection: a query that is logically TRUE returns a response matching the baseline, while a logically FALSE variant returns a materially different response. This indicates the parameter alters the SQL WHERE clause and is exploitable to extract data character-by-character.`,
              evidence:
                `${pointLabel(point, param)}\nbaseline len=${bodyLen(base)}  TRUE('1'='1) len=${bodyLen(tRes)}  FALSE('1'='2) len=${bodyLen(fRes)}`,
              recommendation:
                'Use parameterised queries/prepared statements; do not concatenate user input into SQL. Add strict input validation and least-privilege DB accounts.',
              owasp: 'A03:2021 Injection', cwe: 'CWE-89',
              references: ['https://owasp.org/www-community/attacks/Blind_SQL_Injection'],
            })
          );
          ctx.log(`SQLi (boolean blind) confirmed: ${param} @ ${point.url}`, 'warn');
          continue;
        }
      }

      // --- Time-based (aggressive only; slow + intrusive) ---
      if (aggressive) {
        const baseT = base.ok ? base.elapsed : 1000;
        const sleepPayloads = [
          `1' AND SLEEP(5)-- -`,          // MySQL
          `1';SELECT pg_sleep(5)-- -`,    // PostgreSQL
          `1' WAITFOR DELAY '0:0:5'-- -`, // MSSQL
        ];
        let hit = null;
        for (const pl of sleepPayloads) {
          const r = await sendPayload(point, param, pl, { timeout: 12000 });
          if (r.ok && r.elapsed >= 4500 && r.elapsed - baseT >= 3500) { hit = { pl, r }; break; }
        }
        if (hit) {
          reported.add(key);
          findings.push(
            finding({
              module: MOD, category: CAT, severity: 'critical', cvss: 9.1,
              title: `Time-based blind SQL Injection in "${param}"`,
              description:
                `A time-delay SQL payload injected into \`${param}\` caused the response to be delayed by ~5 seconds versus a baseline of ${baseT}ms, confirming time-based blind SQL injection. The database executes attacker-controlled SQL, allowing full data extraction even with no visible output.`,
              evidence: `${pointLabel(point, param)}\nPayload: ${hit.pl}\nbaseline=${baseT}ms  injected=${hit.r.elapsed}ms`,
              recommendation: 'Use parameterised queries/prepared statements; validate input; least-privilege DB accounts.',
              owasp: 'A03:2021 Injection', cwe: 'CWE-89',
            })
          );
          ctx.log(`SQLi (time-based) confirmed: ${param} @ ${point.url}`, 'warn');
        }
      }
    }

    return { findings, info: { sqliTested: points.length } };
  },
};
