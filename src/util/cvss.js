// Minimal CVSS v3.0/3.1 base-score calculator. Parses a vector string like
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" into a numeric base score.
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
const PR_U = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C = { N: 0.85, L: 0.68, H: 0.5 };
const CIA = { H: 0.56, L: 0.22, N: 0 };

function roundUp1(x) {
  // CVSS 3.1 roundup to one decimal place.
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** @returns {number|null} base score 0–10, or null if the vector is unparseable. */
export function scoreV3(vector) {
  if (!vector || typeof vector !== 'string') return null;
  const m = {};
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (k && v) m[k.toUpperCase()] = v.toUpperCase();
  }
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;

  const changed = m.S === 'C';
  const av = AV[m.AV], ac = AC[m.AC], ui = UI[m.UI];
  const pr = (changed ? PR_C : PR_U)[m.PR];
  const c = CIA[m.C], i = CIA[m.I], a = CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploit = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return 0;
  const base = changed
    ? Math.min(1.08 * (impact + exploit), 10)
    : Math.min(impact + exploit, 10);
  return roundUp1(base);
}

export function severityFromScore(score) {
  if (score == null) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
