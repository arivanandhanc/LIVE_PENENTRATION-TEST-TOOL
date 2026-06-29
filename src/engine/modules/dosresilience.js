// DoS / abuse-resilience assessment. This is a DEFENSIVE check: it sends a
// small, tightly-capped burst of legitimate requests to determine whether the
// target enforces rate limiting and abuse controls. It deliberately does NOT
// perform a denial-of-service / flood attack — volume is bounded to a few dozen
// requests so the target is never impacted.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Network';
const MOD = 'DoS Resilience & Rate Limiting';

const BURST = 25;            // hard cap — never a flood
const CONCURRENCY = 8;

async function burst(url, n, conc) {
  const results = [];
  let i = 0;
  const runners = Array.from({ length: conc }, async () => {
    while (i < n) {
      i++;
      results.push(await request(url, { redirect: 'manual', readBody: false, timeout: 8000 }));
    }
  });
  await Promise.all(runners);
  return results;
}

export default {
  id: 'dosresilience',
  name: 'DoS Resilience & Rate Limiting',
  category: CAT,
  default: false,
  async run(ctx) {
    const url = ctx.target.url;

    // Baseline single request.
    const base = await request(url, { redirect: 'manual', readBody: false, timeout: 8000 });
    const baseMs = base.ok ? base.elapsed : null;

    ctx.log(`DoS resilience: sending a capped burst of ${BURST} requests…`);
    const res = await burst(url, BURST, CONCURRENCY);

    const ok = res.filter((r) => r.ok);
    const statuses = {};
    let rateLimited = 0;
    let hasRLHeaders = false;
    let retryAfter = false;
    for (const r of ok) {
      statuses[r.status] = (statuses[r.status] || 0) + 1;
      if (r.status === 429 || r.status === 503) rateLimited++;
      const h = r.headers || {};
      if (h['x-ratelimit-limit'] || h['x-rate-limit-limit'] || h['ratelimit-limit'] || h['x-ratelimit-remaining']) hasRLHeaders = true;
      if (h['retry-after']) retryAfter = true;
    }
    const avgMs = ok.length ? Math.round(ok.reduce((s, r) => s + r.elapsed, 0) / ok.length) : null;
    const protected_ = rateLimited > 0 || hasRLHeaders || retryAfter;

    ctx.info.dos = {
      sent: BURST, completed: ok.length, statuses,
      rateLimited, rateLimitHeaders: hasRLHeaders, retryAfter,
      baselineMs: baseMs, avgMs,
    };
    ctx.log(`DoS resilience: ${ok.length}/${BURST} completed; rate-limited=${rateLimited}; RL headers=${hasRLHeaders}`,
      protected_ ? 'ok' : 'warn');

    const findings = [];
    if (protected_) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'info',
          title: 'Rate limiting / abuse controls observed (positive)',
          description:
            `During a small ${BURST}-request burst the application exhibited rate-limiting behaviour (` +
            `${rateLimited ? `${rateLimited} throttled responses; ` : ''}${hasRLHeaders ? 'rate-limit headers present; ' : ''}${retryAfter ? 'Retry-After present' : ''}`.trim().replace(/;\s*$/, '') +
            '). This is a positive control that helps resist brute-force, credential-stuffing, scraping, and application-layer DoS.',
          evidence: `Burst ${BURST} req → statuses ${JSON.stringify(statuses)}; avg ${avgMs}ms (baseline ${baseMs}ms)`,
          recommendation: 'Maintain and tune rate limits across all sensitive endpoints (login, password reset, search, APIs).',
          owasp: null, cwe: null,
        })
      );
    } else {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'low',
          title: 'No rate limiting / abuse controls detected',
          description:
            `A capped ${BURST}-request burst completed with no throttling (no HTTP 429/503, no rate-limit or Retry-After headers). The absence of rate limiting leaves the application exposed to brute-force and credential-stuffing on authentication endpoints, scraping, and application-layer denial-of-service through resource-intensive requests. (This check is non-destructive and does not perform a flood; confirm protections at the edge/CDN where applicable.)`,
          evidence: `Burst ${BURST} req → ${ok.length} completed; statuses ${JSON.stringify(statuses)}; avg ${avgMs}ms (baseline ${baseMs}ms). No 429/503, no rate-limit headers.`,
          recommendation:
            'Implement rate limiting and abuse controls (per-IP and per-account) on authentication and expensive endpoints; deploy CDN/WAF-level DDoS protection; add CAPTCHA/exponential backoff on sensitive flows.',
          owasp: 'A04:2021 Insecure Design', cwe: 'CWE-770',
          references: ['https://owasp.org/www-community/attacks/Denial_of_Service'],
        })
      );
    }
    return { findings };
  },
};
