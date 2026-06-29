// Shared helpers for sending payloads into discovered injection points
// (query parameters and form fields), used by the active-testing modules.
import { request } from '../util/http.js';

function benign(input) {
  // Plausible benign default so multi-field forms submit cleanly.
  switch (input.type) {
    case 'email': return 'test@example.com';
    case 'number': return '1';
    case 'tel': return '1234567890';
    case 'url': return 'https://example.com';
    case 'password': return 'Passw0rd!1';
    case 'checkbox':
    case 'radio': return input.value || 'on';
    case 'hidden': return input.value || '1';
    default: return input.value || 'test';
  }
}

/** Build a concrete HTTP request for `payload` placed in `targetParam`. */
export function buildRequest(point, targetParam, payload) {
  if (point.where === 'query') {
    const u = new URL(point.url);
    u.searchParams.set(targetParam, payload);
    return { url: u.toString(), method: 'GET' };
  }

  // Form point.
  const fields = {};
  for (const inp of point.inputs || []) {
    if (['submit', 'button', 'image', 'reset', 'file'].includes(inp.type)) continue;
    fields[inp.name] = inp.name === targetParam ? payload : benign(inp);
  }
  if (!(targetParam in fields)) fields[targetParam] = payload;

  if (point.method === 'POST') {
    const body = new URLSearchParams(fields).toString();
    return {
      url: point.url,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    };
  }
  const u = new URL(point.url);
  for (const [k, v] of Object.entries(fields)) u.searchParams.set(k, v);
  return { url: u.toString(), method: 'GET' };
}

/** Send a payload and return the http result (timing included). */
export async function sendPayload(point, targetParam, payload, opts = {}) {
  const req = buildRequest(point, targetParam, payload);
  return request(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
    redirect: 'manual',
    maxBytes: opts.maxBytes || 256 * 1024,
    timeout: opts.timeout,
  });
}

/** A short, human-readable locator for a point (for evidence/logs). */
export function pointLabel(point, param) {
  const loc = point.where === 'query' ? 'query' : `${point.method} form`;
  return `${loc} param "${param}" @ ${point.url}`;
}

/** De-duplicate + cap the set of points to test, to bound request volume. */
export function selectPoints(surface, cap) {
  const pts = [];
  for (const q of surface.queryPoints || []) pts.push({ point: q, params: [q.param] });
  for (const f of surface.formPoints || []) pts.push({ point: f, params: f.params });
  // Flatten to (point, param) pairs.
  const pairs = [];
  for (const { point, params } of pts) {
    for (const p of params) pairs.push({ point, param: p });
  }
  return cap ? pairs.slice(0, cap) : pairs;
}
