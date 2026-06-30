// In-memory scan registry with JSON-file persistence. Suitable for a single
// Node process (the intended VPS deployment). Swap for Redis/Postgres later.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from './config.js';

const scans = new Map();

// Persistence is best-effort. If the data directory can't be created/written
// (read-only filesystem, missing permissions, hardened container), the tool
// falls back to in-memory operation rather than failing the request.
let persistDisabled = false;

function dataPath(id) {
  return path.join(config.dataDir, `${id}.json`);
}

function ensureDir() {
  if (persistDisabled) return false;
  try {
    fs.mkdirSync(config.dataDir, { recursive: true });
    return true;
  } catch (e) {
    persistDisabled = true;
    console.error(
      `[store] Persistence disabled — cannot use data dir "${config.dataDir}" ` +
        `(${e.code || e.message}). Scans will run in memory only. ` +
        `Set DATA_DIR to a writable path to enable saved results.`
    );
    return false;
  }
}

export function persistenceStatus() {
  return { enabled: !persistDisabled, dir: config.dataDir };
}

export function newId() {
  return crypto.randomBytes(8).toString('hex');
}

export function createScan(meta) {
  ensureDir();
  const id = newId();
  const scan = {
    id,
    status: 'queued', // queued | running | done | error | cancelled
    createdAt: new Date().toISOString(),
    finishedAt: null,
    target: meta.target,
    options: meta.options,
    authorization: meta.authorization,
    progress: { phase: 'queued', percent: 0, message: 'Queued' },
    log: [],
    findings: [],
    info: {}, // module-collected metadata (tech stack, dns, etc.)
    summary: null,
    error: null,
  };
  scans.set(id, scan);
  persist(scan);
  return scan;
}

export function getScan(id) {
  if (scans.has(id)) return scans.get(id);
  // Lazy-load from disk if the process restarted.
  try {
    const raw = fs.readFileSync(dataPath(id), 'utf8');
    const scan = JSON.parse(raw);
    scans.set(id, scan);
    return scan;
  } catch {
    return null;
  }
}

export function listScans() {
  return [...scans.values()]
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map((s) => ({
      id: s.id,
      status: s.status,
      createdAt: s.createdAt,
      target: s.target?.hostname,
      findings: s.findings.length,
      summary: s.summary,
    }));
}

export function persist(scan) {
  if (persistDisabled) return;
  if (!ensureDir()) return;
  try {
    fs.writeFileSync(dataPath(scan.id), JSON.stringify(scan, null, 2));
  } catch (e) {
    // Persistence is best-effort; never crash a scan over a disk error.
    persistDisabled = true;
    console.error('[store] persist failed, disabling persistence:', scan.id, e.message);
  }
}
