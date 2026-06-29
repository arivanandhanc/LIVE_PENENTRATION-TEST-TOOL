// GraphQL endpoint discovery + introspection exposure check. Public
// introspection leaks the full API schema and aids attackers in mapping it.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Web Application';
const MOD = 'GraphQL Security';

const ENDPOINTS = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/graphiql', '/api/gql'];
const INTROSPECTION = '{"query":"query{__schema{queryType{name} types{name kind}}}"}';

export default {
  id: 'graphql',
  name: 'GraphQL Security',
  category: CAT,
  default: false,
  async run(ctx) {
    const findings = [];
    const surface = ctx.surface;

    // Candidate endpoints: known paths + any crawled/mined path containing "graphql".
    const candidates = new Set(ENDPOINTS.map((p) => new URL(p, ctx.target.url).toString()));
    for (const pg of surface?.pages || []) if (/graphql|\/gql/i.test(pg.url)) candidates.add(pg.url);
    for (const ep of surface?.minedEndpoints || []) if (/graphql|\/gql/i.test(ep.url)) candidates.add(ep.url);

    for (const url of candidates) {
      const res = await request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: INTROSPECTION,
        redirect: 'manual',
        maxBytes: 256 * 1024,
        timeout: 9000,
      });
      if (!res.ok) continue;
      const body = res.body || '';
      const isGraphQL = /__schema|"data"\s*:|"errors"\s*:|queryType/i.test(body);
      if (!isGraphQL) continue;

      const introspectionOpen = /__schema|queryType|"types"\s*:\s*\[/i.test(body) && !/introspection is disabled|GRAPHQL_VALIDATION_FAILED.*introspection/i.test(body);
      if (introspectionOpen) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'medium', cvss: 5.3,
            title: `GraphQL introspection enabled (${new URL(url).pathname})`,
            description:
              `A GraphQL endpoint at \`${url}\` responded to an introspection query and disclosed its schema. Public introspection hands attackers the complete API surface — types, queries, mutations — accelerating discovery of sensitive or unprotected operations.`,
            evidence: `POST ${new URL(url).pathname} (introspection)\n→ ${res.status}; schema types returned.`,
            recommendation: 'Disable introspection in production, enforce authentication/authorisation on the GraphQL endpoint, add query depth/complexity limits, and disable any GraphiQL/playground UI.',
            owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-200',
            references: ['https://owasp.org/www-project-web-security-testing-guide/'],
          })
        );
        ctx.log(`GraphQL introspection open: ${url}`, 'warn');
      } else {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'info',
            title: `GraphQL endpoint detected (${new URL(url).pathname})`,
            description: `A GraphQL endpoint was identified at \`${url}\`. Introspection appears disabled. Listed for completeness — GraphQL endpoints warrant authorization and rate-limit review.`,
            evidence: `POST ${new URL(url).pathname} → ${res.status} (GraphQL response shape)`,
            recommendation: 'Ensure authorization on all resolvers and apply query depth/complexity limits.',
            owasp: null, cwe: null,
          })
        );
        ctx.log(`GraphQL endpoint detected (introspection off): ${url}`);
      }
      break; // one endpoint is enough
    }

    return { findings };
  },
};
