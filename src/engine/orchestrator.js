// Runs the selected scan modules against a target, emitting progress events
// so the API can stream live updates over SSE. Handles the crawl pre-phase that
// active modules depend on.
import { EventEmitter } from 'node:events';
import { parseTarget, resolveAndGuard } from '../util/target.js';
import { summarize } from './severity.js';
import { resetFindingCounter } from './finding.js';
import { MODULES } from './modules/index.js';
import { resolveProfile } from './profiles.js';
import { crawl } from './crawler.js';
import { runWithAuth } from '../util/http.js';
import { persist } from '../store.js';

export const events = new EventEmitter();
events.setMaxListeners(0);

function emit(scan, patch) {
  Object.assign(scan, patch);
  events.emit(scan.id, { type: 'update', scan: snapshot(scan) });
  persist(scan);
}

function snapshot(scan) {
  return {
    id: scan.id,
    status: scan.status,
    progress: scan.progress,
    findings: scan.findings,
    summary: scan.summary,
    info: scan.info,
    log: scan.log.slice(-60),
    error: scan.error,
  };
}

function logLine(scan, message, level = 'info') {
  const entry = { t: new Date().toISOString(), level, message };
  scan.log.push(entry);
  events.emit(scan.id, { type: 'log', entry });
}

export async function runScan(scan) {
  // Run the entire scan inside the auth context so every request() within is
  // authenticated when credentials were supplied.
  return runWithAuth(scan.options.auth || null, () => runScanInner(scan));
}

async function runScanInner(scan) {
  resetFindingCounter();

  const profile = resolveProfile(scan.options.profile);
  // Explicit module list (advanced) overrides the profile's selection.
  const moduleIds = scan.options.modules?.length ? scan.options.modules : profile.modules;
  const selected = MODULES.filter((m) => moduleIds.includes(m.id));
  scan.options.resolvedModules = selected.map((m) => m.id);
  scan.options.profileName = profile.name;

  try {
    scan.status = 'running';
    emit(scan, { progress: { phase: 'resolve', percent: 1, message: 'Resolving target' } });

    const target = parseTarget(scan.target.raw);
    const resolved = await resolveAndGuard(target);
    scan.target = { ...scan.target, ...target };
    scan.info.resolved = resolved;
    logLine(scan, `Resolved ${target.hostname} → ${resolved.addresses.join(', ')}`);
    if (scan.options.auth) {
      const modes = [scan.options.auth.cookies && 'cookies', scan.options.auth.bearer && 'bearer', scan.options.auth.headers && 'headers'].filter(Boolean);
      logLine(scan, `🔑 Authenticated scan enabled (${modes.join(', ')})`);
      scan.info.authenticated = true;
    }

    const ctx = {
      target,
      resolved,
      options: scan.options,
      info: scan.info,
      profile: profile.id,
      budget: profile.budget,
      surface: null,
      log: (msg, level) => logLine(scan, msg, level),
    };

    // --- Crawl pre-phase (only if profile enables it and an active module is selected) ---
    const needsCrawl = selected.some((m) => m.needsCrawl);
    if (profile.crawl.enabled && needsCrawl) {
      emit(scan, { progress: { phase: 'crawl', percent: 3, message: 'Crawling application…' } });
      logLine(scan, `▶ Crawling (max ${profile.crawl.maxPages} pages, depth ${profile.crawl.maxDepth})`);
      try {
        ctx.surface = await crawl({
          startUrl: target.url,
          maxPages: profile.crawl.maxPages,
          maxDepth: profile.crawl.maxDepth,
          log: ctx.log,
          onProgress: (n, max) => {
            emit(scan, { progress: { phase: 'crawl', percent: 3 + Math.round((n / max) * 7), message: `Crawling… ${n}/${max} pages` } });
          },
        });
        scan.info.crawl = ctx.surface.stats;
      } catch (e) {
        logLine(scan, `Crawl failed: ${e.message}`, 'warn');
      }
    }

    const findings = [];
    let done = 0;
    const startPct = ctx.surface ? 10 : 5;
    for (const mod of selected) {
      const percent = startPct + Math.round((done / selected.length) * (98 - startPct));
      emit(scan, { progress: { phase: mod.id, percent, message: `Running: ${mod.name}` } });
      logLine(scan, `▶ ${mod.name}`);
      try {
        const result = await mod.run(ctx);
        if (result?.findings?.length) {
          findings.push(...result.findings);
          scan.findings = [...findings];
        }
        if (result?.info) Object.assign(scan.info, result.info);
        logLine(scan, `✓ ${mod.name} — ${result?.findings?.length || 0} finding(s)`, 'ok');
      } catch (e) {
        logLine(scan, `✗ ${mod.name} failed: ${e.message}`, 'warn');
      }
      done += 1;
      scan.summary = summarize(findings);
      emit(scan, {});
    }

    scan.findings = findings;
    scan.summary = summarize(findings);
    scan.status = 'done';
    scan.finishedAt = new Date().toISOString();
    emit(scan, { progress: { phase: 'done', percent: 100, message: 'Scan complete' } });
    events.emit(scan.id, { type: 'done', scan: snapshot(scan) });
  } catch (e) {
    scan.status = 'error';
    scan.error = e.message;
    scan.finishedAt = new Date().toISOString();
    logLine(scan, `Scan aborted: ${e.message}`, 'error');
    emit(scan, { progress: { phase: 'error', percent: 100, message: e.message } });
    events.emit(scan.id, { type: 'done', scan: snapshot(scan) });
  }
}
