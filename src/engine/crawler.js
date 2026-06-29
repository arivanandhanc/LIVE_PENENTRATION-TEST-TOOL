// Same-origin web crawler. Discovers pages, forms, query parameters, and JS
// assets, then derives a set of injection points that the active modules test.
import { request } from '../util/http.js';

const LINK_RE = /<a\b[^>]*?href\s*=\s*["']([^"'#]+)["']/gi;
const SCRIPT_RE = /<script\b[^>]*?src\s*=\s*["']([^"']+)["']/gi;
const FORM_RE = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
const INPUT_RE = /<(?:input|textarea|select)\b[^>]*>/gi;
const ATTR = (tag, name) => {
  const m = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i').exec(tag);
  return m ? m[1] : null;
};

function sameOrigin(a, b) {
  try {
    const x = new URL(a), y = new URL(b);
    return x.protocol === y.protocol && x.host === y.host;
  } catch {
    return false;
  }
}

function parseForms(html, pageUrl) {
  const forms = [];
  let fm;
  FORM_RE.lastIndex = 0;
  while ((fm = FORM_RE.exec(html))) {
    const openTag = fm[0].slice(0, fm[0].indexOf('>') + 1);
    const inner = fm[1];
    let action = ATTR(openTag, 'action');
    const method = (ATTR(openTag, 'method') || 'GET').toUpperCase();
    let actionUrl;
    try {
      actionUrl = new URL(action || '', pageUrl).toString();
    } catch {
      actionUrl = pageUrl;
    }
    const inputs = [];
    let im;
    INPUT_RE.lastIndex = 0;
    while ((im = INPUT_RE.exec(inner))) {
      const name = ATTR(im[0], 'name');
      if (!name) continue;
      inputs.push({
        name,
        type: (ATTR(im[0], 'type') || 'text').toLowerCase(),
        value: ATTR(im[0], 'value') || '',
      });
    }
    if (inputs.length) forms.push({ action: actionUrl, method, inputs, page: pageUrl });
  }
  return forms;
}

/**
 * Crawl the target. Returns a "surface" describing the discovered app.
 * @param {object} opts { startUrl, maxPages, maxDepth, concurrency, onProgress, log }
 */
export async function crawl(opts) {
  const {
    startUrl,
    maxPages = 40,
    maxDepth = 2,
    onProgress = () => {},
    log = () => {},
  } = opts;

  const visited = new Set();
  const queue = [{ url: startUrl, depth: 0 }];

  // Seed from robots.txt + sitemap.xml before crawling links.
  try {
    for (const s of await seedSources(startUrl)) queue.push({ url: s, depth: 1 });
  } catch { /* ignore */ }

  const pages = [];
  const forms = [];
  const jsAssets = new Set();
  const paramPoints = new Map(); // key: url|param -> {url, param, method:'GET'}

  while (queue.length && pages.length < maxPages) {
    const { url, depth } = queue.shift();
    const norm = url.split('#')[0];
    if (visited.has(norm)) continue;
    visited.add(norm);

    const res = await request(norm, { redirect: 'manual', maxBytes: 512 * 1024 });
    if (!res.ok) continue;
    const ctype = res.headers['content-type'] || '';
    const isHtml = /text\/html|application\/xhtml/i.test(ctype);

    pages.push({ url: norm, status: res.status, contentType: ctype, title: titleOf(res.body) });
    onProgress(pages.length, maxPages);

    // Record query parameters on this URL as GET injection points.
    try {
      const u = new URL(norm);
      for (const [p] of u.searchParams) {
        paramPoints.set(`${u.origin}${u.pathname}|${p}`, {
          url: norm, method: 'GET', param: p, where: 'query',
        });
      }
    } catch { /* ignore */ }

    if (!isHtml || res.status >= 400) continue;

    // Forms.
    for (const f of parseForms(res.body, norm)) forms.push(f);

    // JS assets.
    let sm;
    SCRIPT_RE.lastIndex = 0;
    while ((sm = SCRIPT_RE.exec(res.body))) {
      try {
        const js = new URL(sm[1], norm).toString();
        if (sameOrigin(js, startUrl)) jsAssets.add(js);
      } catch { /* ignore */ }
    }

    // Links → enqueue same-origin, bounded by depth.
    if (depth < maxDepth) {
      let lm;
      LINK_RE.lastIndex = 0;
      while ((lm = LINK_RE.exec(res.body))) {
        let href;
        try {
          href = new URL(lm[1], norm).toString();
        } catch {
          continue;
        }
        if (!sameOrigin(href, startUrl)) continue;
        if (/\.(png|jpe?g|gif|svg|webp|ico|css|pdf|zip|woff2?|ttf|mp4|webm)$/i.test(href)) continue;
        const h = href.split('#')[0];
        if (!visited.has(h)) queue.push({ url: h, depth: depth + 1 });
        // capture params on discovered links too
        try {
          const u = new URL(h);
          for (const [p] of u.searchParams) {
            paramPoints.set(`${u.origin}${u.pathname}|${p}`, {
              url: h, method: 'GET', param: p, where: 'query',
            });
          }
        } catch { /* ignore */ }
      }
    }
  }

  // Mine JS assets for hidden endpoints/params and fold them into the surface.
  let mined = { endpoints: [], params: [] };
  try {
    mined = await mineJs([...jsAssets], startUrl, log);
    for (const pp of mined.params) {
      const key = `${new URL(pp.url).origin}${new URL(pp.url).pathname}|${pp.param}`;
      if (!paramPoints.has(key)) paramPoints.set(key, pp);
    }
  } catch { /* ignore */ }

  // Build injection points from forms (each named, non-hidden-only input).
  const formPoints = [];
  for (const f of forms) {
    const testable = f.inputs.filter((i) => !['submit', 'button', 'image', 'file', 'reset'].includes(i.type));
    if (testable.length) {
      formPoints.push({
        url: f.action, method: f.method, where: 'form',
        inputs: f.inputs, params: testable.map((i) => i.name),
      });
    }
  }

  const surface = {
    pages,
    forms,
    jsAssets: [...jsAssets],
    minedEndpoints: mined.endpoints,
    queryPoints: [...paramPoints.values()],
    formPoints,
    stats: {
      pages: pages.length,
      forms: forms.length,
      params: paramPoints.size,
      js: jsAssets.size,
      mined: mined.endpoints.length,
    },
  };
  log(`Crawl complete: ${pages.length} pages, ${forms.length} forms, ${paramPoints.size} params, ${jsAssets.size} JS files`);
  return surface;
}

function titleOf(html) {
  const m = /<title[^>]*>([\s\S]{0,120}?)<\/title>/i.exec(html || '');
  return m ? m[1].trim().replace(/\s+/g, ' ') : '';
}

// --- Seed discovery: robots.txt + sitemap.xml --------------------------------
const ROBOTS_RE = /^(?:dis)?allow:\s*(\S+)/gim;
const SITEMAP_RE = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;

export async function seedSources(startUrl) {
  const seeds = new Set();
  const robots = await request(new URL('/robots.txt', startUrl).toString(), { redirect: 'manual', maxBytes: 32 * 1024 });
  if (robots.ok && robots.status === 200) {
    let m;
    ROBOTS_RE.lastIndex = 0;
    while ((m = ROBOTS_RE.exec(robots.body))) {
      try {
        const u = new URL(m[1].replace(/\*$/, ''), startUrl);
        if (sameOrigin(u.toString(), startUrl)) seeds.add(u.toString());
      } catch { /* ignore */ }
    }
  }
  const sitemap = await request(new URL('/sitemap.xml', startUrl).toString(), { redirect: 'manual', maxBytes: 256 * 1024 });
  if (sitemap.ok && sitemap.status === 200) {
    let m;
    SITEMAP_RE.lastIndex = 0;
    while ((m = SITEMAP_RE.exec(sitemap.body)) && seeds.size < 60) {
      if (sameOrigin(m[1], startUrl)) seeds.add(m[1]);
    }
  }
  return [...seeds];
}

// --- JS endpoint mining (LinkFinder-style) -----------------------------------
// Pull path/URL-looking strings out of JavaScript to reveal API endpoints and
// routes the HTML never linked to.
const ENDPOINT_RE = /["'`]((?:https?:\/\/[^"'`\s]+)|(?:\/[A-Za-z0-9_\-./]+(?:\?[^"'`\s]*)?))["'`]/g;
const STATIC_EXT = /\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|map)(\?|$)/i;

export async function mineJs(jsAssets, startUrl, log = () => {}) {
  const endpoints = new Map(); // path -> {url}
  const params = new Map();
  const cap = Math.min(jsAssets.length, 30);
  for (let i = 0; i < cap; i++) {
    const res = await request(jsAssets[i], { redirect: 'follow', maxBytes: 1024 * 1024, timeout: 9000 });
    if (!res.ok || !res.body) continue;
    let m;
    ENDPOINT_RE.lastIndex = 0;
    while ((m = ENDPOINT_RE.exec(res.body))) {
      let raw = m[1];
      if (raw.length < 2 || raw.length > 200) continue;
      if (STATIC_EXT.test(raw)) continue;
      let abs;
      try {
        abs = new URL(raw, startUrl).toString();
      } catch { continue; }
      if (!sameOrigin(abs, startUrl)) continue;
      const u = new URL(abs);
      endpoints.set(`${u.origin}${u.pathname}`, { url: abs });
      for (const [p] of u.searchParams) {
        params.set(`${u.origin}${u.pathname}|${p}`, { url: abs, method: 'GET', param: p, where: 'query' });
      }
    }
  }
  log(`JS mining: ${cap} file(s) scanned, ${endpoints.size} endpoint(s), ${params.size} param(s) discovered`);
  return { endpoints: [...endpoints.values()], params: [...params.values()] };
}
