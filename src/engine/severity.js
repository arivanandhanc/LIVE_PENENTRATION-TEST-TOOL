// Severity model aligned with the report template (Critical→Info).
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_META = {
  critical: { label: 'Critical', weight: 5, cls: 's-crit', score: 9.5 },
  high: { label: 'High', weight: 4, cls: 's-high', score: 7.5 },
  medium: { label: 'Medium', weight: 3, cls: 's-med', score: 5.0 },
  low: { label: 'Low', weight: 2, cls: 's-low', score: 2.5 },
  info: { label: 'Informational', weight: 1, cls: 's-info', score: 0.0 },
};

/** Build the severity tally + an overall risk rating from a findings array. */
export function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  const total = findings.length;
  const actionable = total - counts.info;

  let posture = 'Strong';
  if (counts.critical > 0) posture = 'Critical';
  else if (counts.high > 0) posture = 'High Risk';
  else if (counts.medium > 0) posture = 'Moderate Risk';
  else if (counts.low > 0) posture = 'Low Risk';

  // Aggregate risk score (0 = clean, 100 = severe). Weighted by severity with
  // diminishing returns so many low-sev items can't outrank a single critical.
  const raw =
    counts.critical * 32 + counts.high * 16 + counts.medium * 6 + counts.low * 2 + counts.info * 0.25;
  const score = Math.min(100, Math.round(raw));
  let grade = 'A';
  if (score >= 80) grade = 'F';
  else if (score >= 55) grade = 'D';
  else if (score >= 30) grade = 'C';
  else if (score >= 12) grade = 'B';
  else if (score > 0) grade = 'A-';

  return { counts, total, actionable, posture, score, grade };
}
