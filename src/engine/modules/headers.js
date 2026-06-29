// Security-header analysis: presence, absence, and weak configurations.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'Security Headers';

export default {
  id: 'headers',
  name: 'Security Headers',
  category: CAT,
  default: true,
  async run(ctx) {
    const res = await request(ctx.target.url, { redirect: 'follow' });
    if (!res.ok) {
      ctx.log(`Header check: request failed (${res.error})`, 'warn');
      return { findings: [] };
    }
    const h = res.headers;
    const findings = [];
    const https = ctx.target.protocol === 'https';

    ctx.info.http = {
      status: res.status,
      server: h['server'] || null,
      poweredBy: h['x-powered-by'] || null,
    };

    // --- HSTS ---
    if (https && !h['strict-transport-security']) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium',
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          description:
            'The response does not set the Strict-Transport-Security header. Without HSTS, a user’s first or post-cache request can be downgraded to HTTP and intercepted (SSL-strip), and the browser will not enforce HTTPS on subsequent visits.',
          evidence: 'Strict-Transport-Security: (absent)',
          recommendation:
            'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses and consider HSTS preload submission.',
          owasp: 'A05:2021 Security Misconfiguration',
          cwe: 'CWE-319', references: ['https://owasp.org/www-project-secure-headers/#http-strict-transport-security'],
        })
      );
    } else if (https) {
      const m = /max-age=(\d+)/i.exec(h['strict-transport-security']);
      const age = m ? parseInt(m[1], 10) : 0;
      if (age < 15552000) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'low',
            title: 'Weak HSTS max-age',
            description: `HSTS is enabled but max-age (${age}s) is below the recommended 6 months (15552000s), reducing protection windows.`,
            evidence: `Strict-Transport-Security: ${h['strict-transport-security']}`,
            recommendation: 'Increase max-age to at least 31536000 and add includeSubDomains.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-319',
          })
        );
      }
    }

    // --- CSP ---
    if (!h['content-security-policy']) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium',
          title: 'Missing Content-Security-Policy',
          description:
            'No Content-Security-Policy header is present. A strong CSP is the primary defence-in-depth control against cross-site scripting (XSS) and data-injection by restricting the sources from which scripts, styles and other resources may load.',
          evidence: 'Content-Security-Policy: (absent)',
          recommendation:
            'Deploy a restrictive CSP (e.g. `default-src \'self\'; object-src \'none\'; base-uri \'self\'`), ideally nonce/hash based for scripts. Start in Report-Only mode to tune.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-1021',
          references: ['https://owasp.org/www-project-secure-headers/#content-security-policy'],
        })
      );
    } else if (/unsafe-inline|unsafe-eval/i.test(h['content-security-policy'])) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'low',
          title: 'Content-Security-Policy permits unsafe-inline/unsafe-eval',
          description:
            'The CSP is present but weakened by `unsafe-inline` and/or `unsafe-eval`, which substantially undermines its XSS-mitigation value.',
          evidence: `Content-Security-Policy: ${truncate(h['content-security-policy'])}`,
          recommendation: 'Remove unsafe-inline/unsafe-eval; adopt nonces or hashes for required inline scripts.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-1021',
        })
      );
    }

    // --- X-Frame-Options / frame-ancestors (clickjacking) ---
    const csp = h['content-security-policy'] || '';
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp)) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium',
          title: 'Clickjacking protection missing (no X-Frame-Options / frame-ancestors)',
          description:
            'Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be embedded in an attacker-controlled iframe and used for clickjacking / UI-redress attacks.',
          evidence: 'X-Frame-Options: (absent); CSP frame-ancestors: (absent)',
          recommendation:
            'Set `X-Frame-Options: DENY` (or SAMEORIGIN) and/or `Content-Security-Policy: frame-ancestors \'none\'`.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-1021',
        })
      );
    }

    // --- X-Content-Type-Options ---
    if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'low',
          title: 'Missing X-Content-Type-Options: nosniff',
          description:
            'Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses, enabling certain XSS and content-confusion attacks.',
          evidence: `X-Content-Type-Options: ${h['x-content-type-options'] || '(absent)'}`,
          recommendation: 'Add `X-Content-Type-Options: nosniff` to all responses.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-693',
        })
      );
    }

    // --- Referrer-Policy ---
    if (!h['referrer-policy']) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'info',
          title: 'No Referrer-Policy set',
          description:
            'A Referrer-Policy is not defined; the browser default may leak full URLs (including sensitive path/query data) to third-party destinations.',
          evidence: 'Referrer-Policy: (absent)',
          recommendation: 'Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-200',
        })
      );
    }

    // --- Permissions-Policy ---
    if (!h['permissions-policy']) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'info',
          title: 'No Permissions-Policy set',
          description:
            'A Permissions-Policy header is not defined, so powerful browser features (camera, microphone, geolocation, etc.) are not explicitly restricted.',
          evidence: 'Permissions-Policy: (absent)',
          recommendation: 'Define a least-privilege Permissions-Policy disabling features the app does not use.',
          owasp: 'A05:2021 Security Misconfiguration',
        })
      );
    }

    return { findings };
  },
};

function truncate(s, n = 180) {
  return s && s.length > n ? s.slice(0, n) + '…' : s;
}
