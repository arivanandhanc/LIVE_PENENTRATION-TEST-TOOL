// Thin fetch wrapper with timeout, redirect tracking, and safe body capture.
import { AsyncLocalStorage } from 'node:async_hooks';
import { config } from '../config.js';

// Per-scan authentication context. Running a scan inside `runWithAuth` makes
// every request() within that async tree send the configured cookies/headers —
// enabling authenticated scanning without threading auth through every module.
// AsyncLocalStorage keeps this isolated per scan, so concurrent scans don't leak.
const authStore = new AsyncLocalStorage();

export function runWithAuth(auth, fn) {
  return authStore.run(auth || null, fn);
}

function authHeaders() {
  const auth = authStore.getStore();
  if (!auth) return {};
  const h = {};
  if (auth.cookies) h['Cookie'] = auth.cookies;
  if (auth.bearer) h['Authorization'] = `Bearer ${auth.bearer}`;
  if (auth.headers && typeof auth.headers === 'object') Object.assign(h, auth.headers);
  return h;
}

export function hasAuth() {
  return !!authStore.getStore();
}

/**
 * Perform an HTTP request and return a normalised result. Never throws on
 * network errors — failures are returned as { ok:false, error }.
 */
export async function request(url, opts = {}) {
  const controller = new AbortController();
  const timeout = opts.timeout || config.httpTimeout;
  const timer = setTimeout(() => controller.abort(), timeout);
  const started = Date.now();

  try {
    const res = await fetch(url, {
      method: opts.method || 'GET',
      redirect: opts.redirect || 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': config.userAgent,
        Accept: '*/*',
        ...authHeaders(),
        ...(opts.headers || {}),
      },
      body: opts.body,
    });

    let body = '';
    if (opts.readBody !== false) {
      const maxBytes = opts.maxBytes || 256 * 1024;
      const reader = res.body?.getReader?.();
      if (reader) {
        const chunks = [];
        let total = 0;
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          chunks.push(value);
          if (total >= maxBytes) {
            controller.abort();
            break;
          }
        }
        body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
      }
    }

    const headers = {};
    for (const [k, v] of res.headers.entries()) headers[k.toLowerCase()] = v;

    return {
      ok: true,
      url,
      status: res.status,
      statusText: res.statusText,
      headers,
      rawHeaders: res.headers,
      body,
      location: headers.location || null,
      elapsed: Date.now() - started,
    };
  } catch (e) {
    return {
      ok: false,
      url,
      error: e.name === 'AbortError' ? 'timeout' : e.code || e.message,
      elapsed: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Follow up to `max` redirects manually, returning the full chain. */
export async function requestChain(url, opts = {}, max = 5) {
  const chain = [];
  let current = url;
  for (let i = 0; i <= max; i++) {
    const res = await request(current, opts);
    chain.push(res);
    if (!res.ok) break;
    if (res.status >= 300 && res.status < 400 && res.location) {
      try {
        current = new URL(res.location, current).toString();
      } catch {
        break;
      }
    } else {
      break;
    }
  }
  return chain;
}
