// PenTestTool frontend — configures, launches, and live-streams a scan.
const $ = (id) => document.getElementById(id);
const SEV = {
  critical: { b: 'b-crit', c: 'crit', s: 'CRIT' },
  high: { b: 'b-high', c: 'high', s: 'HIGH' },
  medium: { b: 'b-med', c: 'med', s: 'MED' },
  low: { b: 'b-low', c: 'low', s: 'LOW' },
  info: { b: 'b-info', c: 'info', s: 'INFO' },
};
const ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const esc = (s) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

let currentId = null;
let selectedProfile = 'standard';

// ---- Load scan profiles ----
async function loadProfiles() {
  try {
    const profiles = await (await fetch('/api/profiles')).json();
    const el = $('profiles');
    el.innerHTML = '';
    for (const p of profiles) {
      const card = document.createElement('label');
      card.className = 'profile' + (p.id === selectedProfile ? ' sel' : '');
      card.innerHTML = `<input type="radio" name="profile" value="${p.id}" ${p.id === selectedProfile ? 'checked' : ''}>
        <div><div class="pname">${esc(p.name)}</div><div class="pdesc">${esc(p.description)}</div></div>`;
      card.querySelector('input').addEventListener('change', () => {
        selectedProfile = p.id;
        document.querySelectorAll('.profile').forEach((c) => c.classList.remove('sel'));
        card.classList.add('sel');
      });
      el.appendChild(card);
    }
  } catch {
    $('profiles').innerHTML = '<div class="error">Failed to load profiles.</div>';
  }
}

// ---- Load module catalog ----
async function loadModules() {
  try {
    const mods = await (await fetch('/api/modules')).json();
    const byCat = {};
    for (const m of mods) (byCat[m.category] ||= []).push(m);
    const el = $('modules');
    el.innerHTML = '';
    for (const [cat, list] of Object.entries(byCat)) {
      const h = document.createElement('div');
      h.className = 'mod-cat';
      h.textContent = cat;
      el.appendChild(h);
      for (const m of list) {
        const lab = document.createElement('label');
        lab.className = 'mod';
        const tag = m.active ? ' <span class="atag">ACTIVE</span>' : (m.default ? '' : ' <span class="muted">(opt-in)</span>');
        lab.innerHTML = `<input type="checkbox" value="${m.id}">
          <span>${esc(m.name)}${tag}</span>`;
        el.appendChild(lab);
      }
    }
  } catch {
    $('modules').innerHTML = '<div class="error">Failed to load modules.</div>';
  }
}

function selectedModules() {
  return [...document.querySelectorAll('#modules input:checked')].map((i) => i.value);
}

// ---- Enable Start only when target + consent are set ----
function refreshStart() {
  $('start').disabled = !($('target').value.trim() && $('consent').checked);
}
$('target').addEventListener('input', refreshStart);
$('consent').addEventListener('change', refreshStart);

// ---- Start scan ----
$('start').addEventListener('click', async () => {
  $('formError').hidden = true;
  $('start').disabled = true;
  const body = {
    target: $('target').value.trim(),
    profile: selectedProfile,
    modules: selectedModules(), // empty array => use profile
    packageJson: $('packageJson').value.trim() || null,
    packageLock: $('packageLock').value.trim() || null,
    auth: {
      cookies: $('authCookies').value.trim() || null,
      bearer: $('authBearer').value.trim() || null,
      raw: $('authHeaders').value.trim() || null,
    },
    authorization: { consent: $('consent').checked, confirmedBy: 'web-ui' },
  };
  try {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start scan');
    currentId = data.id;
    openResults(body.target);
    stream(currentId);
  } catch (e) {
    $('formError').textContent = e.message;
    $('formError').hidden = false;
  } finally {
    refreshStart();
  }
});

function openResults(target) {
  $('results').hidden = false;
  $('resultTitle').textContent = target;
  $('findings').innerHTML = '';
  $('log').innerHTML = '';
  $('scorecards').innerHTML = '';
  $('recon').hidden = true;
  $('recon').innerHTML = '';
  $('riskBadge').hidden = true;
  $('bar').style.width = '0%';
  $('downloadPdf').disabled = true;
  $('viewReport').disabled = true;
  $('exportJson').disabled = true;
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---- Live stream via SSE ----
function stream(id) {
  const es = new EventSource(`/api/scans/${id}/stream`);
  const apply = (scan) => render(scan);
  es.addEventListener('update', (e) => apply(JSON.parse(e.data).scan || JSON.parse(e.data)));
  es.addEventListener('log', (e) => appendLog(JSON.parse(e.data).entry));
  es.addEventListener('done', (e) => {
    apply(JSON.parse(e.data).scan);
    finish(id);
    es.close();
  });
  es.onerror = () => { es.close(); pollFallback(id); };
}

async function pollFallback(id) {
  // If SSE drops, poll until terminal.
  const tick = async () => {
    const scan = await (await fetch(`/api/scans/${id}`)).json();
    render(scan);
    (scan.log || []).forEach(setLogFull);
    if (scan.status === 'done' || scan.status === 'error') return finish(id);
    setTimeout(tick, 1500);
  };
  tick();
}

const seenFindings = new Set();
const seenLog = new Set();

function render(scan) {
  if (!scan) return;
  const p = scan.progress || {};
  $('bar').style.width = (p.percent || 0) + '%';
  $('phase').textContent = p.message || scan.status;

  // Scorecards
  const c = scan.summary?.counts || {};
  $('scorecards').innerHTML = ORDER.map(
    (s) => `<div class="scard s-${SEV[s].c}"><div class="n">${c[s] || 0}</div><div class="l">${s}</div></div>`
  ).join('');

  // Risk badge
  if (scan.summary?.grade) {
    const score = scan.summary.score || 0;
    const col = score >= 55 ? 'b-crit' : score >= 30 ? 'b-high' : score >= 12 ? 'b-med' : 'b-low';
    const b = $('riskBadge');
    b.hidden = false;
    b.className = `riskBadge ${col}`;
    b.textContent = `Risk ${score}/100 · ${scan.summary.grade}`;
  }

  renderRecon(scan.info || {});

  // Findings (append new ones; keep order by appearance)
  for (const f of scan.findings || []) {
    if (seenFindings.has(f.ref)) continue;
    seenFindings.add(f.ref);
    addFinding(f);
  }
  $('findCount').textContent = (scan.findings || []).length;
}

function renderRecon(info) {
  const chips = [];
  if (info.crawl) chips.push(['Crawl', `${info.crawl.pages}p · ${info.crawl.forms}f · ${info.crawl.params} params`]);
  if (info.fingerprint?.technologies?.length) chips.push(['Tech', info.fingerprint.technologies.join(', ')]);
  if (info.fingerprint?.waf?.length) chips.push(['WAF', info.fingerprint.waf.join(', ')]);
  if (info.subdomains?.live != null) chips.push(['Subdomains', `${info.subdomains.live} live`]);
  if (info.openPorts?.length) chips.push(['Ports', info.openPorts.map((p) => p.port).join(', ')]);
  if (info.discovered?.length) chips.push(['Paths', `${info.discovered.length} found`]);
  if (!chips.length) return;
  const el = $('recon');
  el.hidden = false;
  el.innerHTML = chips.map(([k, v]) => `<div class="chip"><b>${esc(k)}</b> ${esc(v)}</div>`).join('');
}

function addFinding(f) {
  const m = SEV[f.severity] || SEV.info;
  const div = document.createElement('div');
  div.className = `fcard ${m.c}`;
  const meta = [f.module, f.cwe, f.owasp].filter(Boolean).join(' · ');
  div.innerHTML = `
    <div class="fh">
      <span class="ft">${esc(f.ref)} — ${esc(f.title)}</span>
      <span class="badge ${m.b}">${m.s}</span>
    </div>
    <div class="fmeta">${esc(meta)}</div>
    <div class="fdesc">
      <p>${esc(f.description)}</p>
      ${f.evidence ? `<pre>${esc(Array.isArray(f.evidence) ? f.evidence.join('\n') : f.evidence)}</pre>` : ''}
      ${f.recommendation ? `<p><b>Recommendation:</b> ${esc(f.recommendation)}</p>` : ''}
    </div>`;
  div.querySelector('.fh').addEventListener('click', () => div.classList.toggle('open'));
  $('findings').appendChild(div);
}

function appendLog(entry) {
  if (!entry) return;
  const key = entry.t + entry.message;
  if (seenLog.has(key)) return;
  seenLog.add(key);
  const div = document.createElement('div');
  div.className = `ln ${entry.level || ''}`;
  div.textContent = entry.message;
  $('log').appendChild(div);
  $('log').scrollTop = $('log').scrollHeight;
}
const setLogFull = appendLog;

function finish(id) {
  $('downloadPdf').disabled = false;
  $('viewReport').disabled = false;
  $('exportJson').disabled = false;
  $('downloadPdf').onclick = () => window.open(`/api/scans/${id}/report.pdf`, '_blank');
  $('viewReport').onclick = () => window.open(`/api/scans/${id}/report`, '_blank');
  $('exportJson').onclick = () => window.open(`/api/scans/${id}/export.json`, '_blank');
}

loadProfiles();
loadModules();
refreshStart();
