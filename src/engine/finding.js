// Helper to construct a normalised finding object. Keeping one shape across
// all modules makes the report generator and UI trivial.
let counter = 0;

export function resetFindingCounter() {
  counter = 0;
}

/**
 * @param {object} f
 * @param {string} f.module    e.g. "Security Headers"
 * @param {string} f.category  Web Application | TLS/DNS | Network | Dependencies
 * @param {string} f.title
 * @param {string} f.severity  critical|high|medium|low|info
 * @param {string} f.description
 * @param {string|string[]} [f.evidence]
 * @param {string} [f.recommendation]
 * @param {string[]} [f.references]
 * @param {string} [f.owasp]
 * @param {string} [f.cwe]
 * @param {number} [f.cvss]
 * @param {('confirmed'|'firm'|'tentative')} [f.confidence]
 *   confirmed = actively reproduced (payload sent, exploit verified);
 *   firm      = definitive passive observation (e.g. missing header, expired cert);
 *   tentative = heuristic/pattern match that warrants manual verification.
 */
export function finding(f) {
  counter += 1;
  return {
    ref: `F-${String(counter).padStart(2, '0')}`,
    module: f.module,
    category: f.category,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence ?? 'firm',
    description: f.description,
    evidence: f.evidence ?? null,
    recommendation: f.recommendation ?? null,
    references: f.references ?? [],
    owasp: f.owasp ?? null,
    cwe: f.cwe ?? null,
    cvss: f.cvss ?? null,
  };
}
