// PenTestTool — Express server: REST API, SSE live progress, report export.
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './src/config.js';
import { parseTarget } from './src/util/target.js';
import { createScan, getScan, listScans, persistenceStatus } from './src/store.js';
import { runScan, events } from './src/engine/orchestrator.js';
import { moduleCatalog } from './src/engine/modules/index.js';
import { profileCatalog } from './src/engine/profiles.js';
import { renderReport } from './src/report/generate.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: '4mb' }));

// Clean URLs for the multi-page site (must precede static so /scan → scan.html).
const pages = { '/scan': 'scan.html', '/docs': 'docs.html', '/privacy': 'privacy.html', '/legal': 'legal.html', '/terms': 'legal.html' };
for (const [route, file] of Object.entries(pages)) {
  app.get(route, (_req, res) => res.sendFile(path.join(__dirname, 'public', file)));
}

app.use(express.static(path.join(__dirname, 'public')));

// Normalise supplied authentication into { cookies, bearer, headers } or null.
function normalizeAuth(auth) {
  if (!auth || typeof auth !== 'object') return null;
  const out = {};
  if (typeof auth.cookies === 'string' && auth.cookies.trim()) out.cookies = auth.cookies.trim();
  if (typeof auth.bearer === 'string' && auth.bearer.trim()) out.bearer = auth.bearer.trim().replace(/^Bearer\s+/i, '');
  if (auth.headers && typeof auth.headers === 'object') {
    const h = {};
    for (const [k, v] of Object.entries(auth.headers)) {
      if (typeof k === 'string' && typeof v === 'string' && k.trim()) h[k.trim()] = v;
    }
    if (Object.keys(h).length) out.headers = h;
  }
  // Parse a raw header block (e.g. pasted "Header: value" lines).
  if (typeof auth.raw === 'string' && auth.raw.trim()) {
    const h = out.headers || {};
    for (const line of auth.raw.split('\n')) {
      const m = /^([A-Za-z0-9-]+)\s*:\s*(.+)$/.exec(line.trim());
      if (m) {
        if (/^cookie$/i.test(m[1])) out.cookies = m[2];
        else if (/^authorization$/i.test(m[1])) out.bearer = m[2].replace(/^Bearer\s+/i, '');
        else h[m[1]] = m[2];
      }
    }
    if (Object.keys(h).length) out.headers = h;
  }
  return Object.keys(out).length ? out : null;
}

// --- Catalog of available modules + profiles (for the UI) ---
app.get('/api/modules', (_req, res) => res.json(moduleCatalog()));
app.get('/api/profiles', (_req, res) => res.json(profileCatalog()));

// --- Create + start a scan ---
app.post('/api/scans', (req, res) => {
  const { target, profile, modules, packageJson, packageLock, authorization, auth } = req.body || {};

  // Authorization gate: the requester MUST affirm they are permitted to test.
  if (!authorization?.consent) {
    return res.status(403).json({
      error:
        'Authorization required. You must confirm you own or are explicitly permitted to test this target.',
    });
  }

  let parsed;
  try {
    parsed = parseTarget(target);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const scan = createScan({
    target: { raw: parsed.raw, url: parsed.url, hostname: parsed.hostname, port: parsed.port, protocol: parsed.protocol },
    options: {
      profile: profile || 'standard',
      modules: Array.isArray(modules) && modules.length ? modules : undefined,
      packageJson: packageJson || null,
      packageLock: packageLock || null,
      auth: normalizeAuth(auth),
    },
    authorization: {
      consent: true,
      confirmedBy: authorization.confirmedBy || req.ip,
      acceptedAt: new Date().toISOString(),
    },
  });

  // Fire-and-forget; progress is observable via SSE / polling.
  runScan(scan).catch((e) => console.error('runScan crashed', e));
  res.status(201).json({ id: scan.id, status: scan.status });
});

// --- Scan status (polling fallback) ---
app.get('/api/scans/:id', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

// --- List scans ---
app.get('/api/scans', (_req, res) => res.json(listScans()));

// --- Live progress via Server-Sent Events ---
app.get('/api/scans/:id/stream', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).end();

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(`event: update\ndata: ${JSON.stringify(scan)}\n\n`);

  const onEvent = (payload) => {
    res.write(`event: ${payload.type}\ndata: ${JSON.stringify(payload)}\n\n`);
    if (payload.type === 'done') {
      clearInterval(ka);
      events.off(scan.id, onEvent);
      res.end();
    }
  };
  events.on(scan.id, onEvent);

  // Keep-alive comments so proxies don't drop the connection.
  const ka = setInterval(() => res.write(': ping\n\n'), 15000);

  req.on('close', () => {
    clearInterval(ka);
    events.off(scan.id, onEvent);
  });

  // If the scan already finished before the client connected, close out.
  if (scan.status === 'done' || scan.status === 'error') {
    res.write(`event: done\ndata: ${JSON.stringify({ type: 'done', scan })}\n\n`);
    clearInterval(ka);
    events.off(scan.id, onEvent);
    res.end();
  }
});

// --- HTML report (add ?print=1 to auto-open the print/save-as-PDF dialog) ---
app.get('/api/scans/:id/report', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).send('Scan not found');
  res.type('html').send(renderReport(scan, { print: req.query.print === '1' }));
});

// --- PDF export: serves the print-ready report and auto-triggers Save-as-PDF.
// (Deploy-safe: no headless-browser dependency required on the server.)
app.get('/api/scans/:id/report.pdf', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).send('Scan not found');
  res.type('html').send(renderReport(scan, { print: true }));
});

// --- JSON export ---
app.get('/api/scans/:id/export.json', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.setHeader('Content-Disposition', `attachment; filename="scan-${scan.id}.json"`);
  res.json(scan);
});

// --- Health check (reports persistence status to aid deploy diagnostics) ---
app.get('/api/health', (_req, res) =>
  res.json({ ok: true, version: '1.0.0', persistence: persistenceStatus() })
);

// --- Any unmatched /api/* route returns JSON (never an HTML page) so the
//     frontend always gets parseable responses. ---
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: `No such API route: ${req.method} ${req.path}` });
});

// --- JSON error handler: malformed bodies and unexpected errors return JSON. ---
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON in request body.' });
  }
  console.error('Unhandled error:', err);
  if (req.path.startsWith('/api/')) {
    // Surface the real cause — this is an operator-run security tool, and a
    // generic message makes deploy issues (e.g. read-only filesystem) opaque.
    return res.status(500).json({ error: 'Internal server error.', detail: err && err.message });
  }
  res.status(500).send('Internal server error.');
});

app.listen(config.port, config.host, () => {
  console.log(`PenTestTool listening on http://${config.host}:${config.port}`);
  console.log(`Private-target blocking: ${config.blockPrivateTargets ? 'ON' : 'OFF'}`);
});
