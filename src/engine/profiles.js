// Scan profiles bundle a module selection, crawl depth, and request budgets
// at a chosen intensity. The UI exposes these; advanced users can still pass an
// explicit module list to override.
export const PROFILES = {
  passive: {
    id: 'passive',
    name: 'Passive Recon',
    description: 'Non-intrusive reconnaissance only. No active injection or crawling. Safe for sensitive/production targets.',
    crawl: { enabled: false },
    modules: ['fingerprint', 'cvecheck', 'headers', 'cookies', 'cors', 'infodisclosure', 'methods', 'tls', 'dns', 'subdomains', 'dependencies'],
    budget: { activePoints: 0 },
  },
  standard: {
    id: 'standard',
    name: 'Standard',
    description: 'Recon, configuration analysis, content discovery, and a light crawl with safe, marker-based active checks. Recommended default.',
    crawl: { enabled: true, maxPages: 40, maxDepth: 2 },
    modules: [
      'fingerprint', 'cvecheck', 'headers', 'cookies', 'cors', 'infodisclosure', 'exposedfiles',
      'methods', 'webprobes', 'discovery', 'secrets', 'sensitivedata', 'graphql', 'csrf',
      'xss', 'sqli', 'ssrf', 'tls', 'dns', 'subdomains', 'dependencies',
    ],
    budget: { activePoints: 60 },
  },
  aggressive: {
    id: 'aggressive',
    name: 'Aggressive (Full)',
    description: 'Deep crawl and the full active test suite including time-based blind injection and OS command injection. Intrusive and slower — authorised, non-production targets only.',
    crawl: { enabled: true, maxPages: 100, maxDepth: 3 },
    modules: [
      'fingerprint', 'cvecheck', 'headers', 'cookies', 'cors', 'infodisclosure', 'exposedfiles',
      'methods', 'webprobes', 'discovery', 'secrets', 'sensitivedata', 'graphql', 'csrf',
      'xss', 'sqli', 'cmdinjection', 'pathtraversal', 'ssrf',
      'tls', 'dns', 'subdomains', 'ports', 'dosresilience', 'dependencies',
    ],
    budget: { activePoints: 120 },
  },
};

export function resolveProfile(name) {
  return PROFILES[name] || PROFILES.standard;
}

export function profileCatalog() {
  return Object.values(PROFILES).map(({ id, name, description }) => ({ id, name, description }));
}
