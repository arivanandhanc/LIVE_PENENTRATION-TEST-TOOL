// Renders a scan result into a standalone, print-ready HTML report that
// mirrors the design language of the project's reference pentest-report.html.
import { SEVERITY_META } from '../engine/severity.js';
import { config } from '../config.js';

const esc = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const sevTag = (sev) => {
  const m = SEVERITY_META[sev] || SEVERITY_META.info;
  return `<span class="sev ${m.cls}">${m.label.slice(0, 4).toUpperCase()}</span>`;
};

const CONF_LABEL = { confirmed: 'Confirmed', firm: 'Firm', tentative: 'Tentative' };
const confTag = (c) => {
  const k = c || 'firm';
  return `<span class="conf conf-${k}">${CONF_LABEL[k] || 'Firm'}</span>`;
};

const STYLES = `
:root{
  --navy:#0f2747; --navy2:#1b3a5f; --accent:#b8780a; --accent-soft:#fbe7bd;
  --ink:#1c2431; --muted:#56606e; --line:#d8dee6; --soft:#f4f6f9;
  --crit:#b3261e; --high:#d4691a; --med:#c79a00; --low:#2e7d32; --info:#1565c0;
}
*{box-sizing:border-box;}
@page{ size:A4; margin:18mm 15mm; }
html{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }
body{ font-family:"Segoe UI","Helvetica Neue",Arial,sans-serif; color:var(--ink);
  font-size:10.5pt; line-height:1.55; margin:0; }
h1,h2,h3,h4{ color:var(--navy); font-weight:700; line-height:1.25; }
h1{ font-size:20pt; margin:0 0 6pt; }
h2{ font-size:15pt; margin:22pt 0 8pt; border-bottom:2px solid var(--accent); padding-bottom:4pt; }
h3{ font-size:12pt; margin:14pt 0 5pt; color:var(--navy2); }
h4{ font-size:10.5pt; margin:10pt 0 3pt; color:var(--navy2); }
p{ margin:0 0 8pt; text-align:justify; }
ul,ol{ margin:0 0 8pt; padding-left:18pt; } li{ margin:0 0 4pt; }
a{ color:var(--accent); text-decoration:none; word-break:break-all; }
code,pre{ font-family:"Cascadia Code","Consolas",monospace; font-size:8.7pt; }
code{ background:var(--soft); padding:1px 4px; border-radius:3px; color:#7a3b00; }
pre{ background:#0e1b2c; color:#e8eef6; padding:10pt 12pt; border-radius:5px;
  white-space:pre-wrap; word-break:break-word; line-height:1.45;
  border-left:3px solid var(--accent); margin:6pt 0 10pt; font-size:8.3pt; }
.wrap{ max-width:900px; margin:0 auto; padding:24px; }
table{ width:100%; border-collapse:collapse; margin:6pt 0 12pt; font-size:9pt; }
th,td{ border:1px solid var(--line); padding:5pt 7pt; text-align:left; vertical-align:top; }
th{ background:var(--navy); color:#fff; font-weight:600; }
tr:nth-child(even) td{ background:var(--soft); }
.sev{ color:#fff; font-weight:700; padding:1.5px 7px; border-radius:10px; font-size:8pt;
  white-space:nowrap; display:inline-block; }
.s-crit{ background:var(--crit);} .s-high{ background:var(--high);} .s-med{ background:var(--med);}
.s-low{ background:var(--low);} .s-info{ background:var(--info);}
.pill{ display:inline-block; padding:1.5px 8px; border-radius:10px; font-size:8pt; font-weight:600;
  background:#eef2f8; color:#324a6b; border:1px solid #b9c6da; }
.conf{ display:inline-block; padding:1px 7px; border-radius:10px; font-size:7.5pt; font-weight:700;
  border:1px solid; white-space:nowrap; }
.conf-confirmed{ background:#e3f4e4; color:#1d6b22; border-color:#9fce9f; }
.conf-firm{ background:#eef2f8; color:#324a6b; border-color:#b9c6da; }
.conf-tentative{ background:#fff6ef; color:#a85b13; border-color:#e8c4a3; }
.callout{ border:1px solid var(--line); border-left:4px solid var(--accent); background:#fffaf0;
  padding:8pt 12pt; border-radius:4px; margin:8pt 0; }
.cover{ background:linear-gradient(135deg,var(--navy),var(--navy2)); color:#fff;
  border-radius:10px; padding:40px; margin-bottom:24px; }
.cover h1{ color:#fff; font-size:26pt; }
.cover .sub{ color:var(--accent-soft); font-size:13pt; margin-top:4px; }
.cover .meta{ margin-top:20px; font-size:10pt; color:#cdd8e8; }
.cover .meta b{ color:#fff; }
.scorecards{ display:flex; gap:10px; flex-wrap:wrap; margin:12px 0 4px; }
.card{ flex:1; min-width:90px; text-align:center; border:1px solid var(--line);
  border-radius:8px; padding:12px 8px; background:#fff; }
.card .n{ font-size:22pt; font-weight:800; line-height:1; }
.card .l{ font-size:8pt; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin-top:4px; }
.c-crit .n{ color:var(--crit);} .c-high .n{ color:var(--high);} .c-med .n{ color:var(--med);}
.c-low .n{ color:var(--low);} .c-info .n{ color:var(--info);}
.metarow{ display:flex; flex-wrap:wrap; gap:6px 16px; padding:8px 0; font-size:9pt;
  border-bottom:1px dashed var(--line); margin-bottom:8px; }
.finding{ border:1px solid var(--line); border-radius:8px; padding:14px 16px; margin:14px 0;
  break-inside:avoid; }
.finding-head{ display:flex; justify-content:space-between; align-items:center; gap:10px; }
.finding-head h3{ margin:0; }
.bar{ height:10px; border-radius:6px; overflow:hidden; display:flex; margin:6px 0 2px; background:var(--soft); }
.bar i{ display:block; height:100%; }
.muted{ color:var(--muted); }
.posture{ font-size:13pt; font-weight:800; }
.riskbox{ display:flex; gap:16px; align-items:stretch; margin:10px 0 14px; }
.riskscore{ border:2px solid var(--line); border-radius:12px; padding:10px 18px; text-align:center; min-width:120px;
  display:flex; flex-direction:column; justify-content:center; }
.riskscore .rg{ font-size:30pt; font-weight:800; line-height:1; }
.riskscore .rs{ font-size:8.5pt; color:var(--muted); margin-top:4px; }
.riskbody{ flex:1; display:flex; flex-direction:column; justify-content:center; }
.pagebreak{ break-before:page; }
@media print{ .wrap{ max-width:none; padding:0; } .finding{ box-shadow:none; } .pagebreak{ page-break-before:always; } }
`;

function coverPage(scan) {
  const d = new Date(scan.createdAt);
  return `
  <div class="cover">
    <div class="sub">${esc(config.brand.company)} — Penetration Test Report</div>
    <h1>${esc(scan.target.hostname || scan.target.raw)}</h1>
    <div class="meta">
      <div><b>Target:</b> ${esc(scan.target.url || scan.target.raw)}</div>
      <div><b>Assessment date:</b> ${d.toUTCString()}</div>
      <div><b>Report ID:</b> ${esc(scan.id)}</div>
      <div><b>Generated by:</b> ${esc(config.brand.site)}</div>
    </div>
  </div>`;
}

function confidentiality(scan) {
  return `
  <section class="pagebreak">
  <h2>Confidentiality &amp; Legal Notice</h2>
  <h3>Authorisation &amp; Scope of Testing</h3>
  <p>This penetration test was conducted with the authorisation of the system owner against the target identified
  below. The authorising party confirmed, via the engagement consent gate, that they own or are explicitly
  permitted to test the target. Testing was limited to the agreed scope and performed using non-destructive
  techniques.</p>
  <h3>Limitation of Liability &amp; Point-in-Time Validity</h3>
  <p>The findings in this report reflect the security posture of the target at the time of testing
  (${esc(scan.createdAt)}). Security is not static; subsequent changes to the application, infrastructure, or threat
  landscape may introduce new vulnerabilities. The absence of a finding is not a guarantee that no vulnerability
  exists. Automated assessment complements but does not replace manual penetration testing and code review.</p>
  <h3>Standards Alignment</h3>
  <p>The assessment methodology aligns with industry references including the OWASP Top 10 (2021), the OWASP Web
  Security Testing Guide (WSTG), and CWE classifications. Severity is expressed using a five-tier model
  (Critical → Informational) supported by CVSS v3.1 scoring where applicable.</p>
  <div class="callout"><b>Confidential.</b> This document contains sensitive security information and is intended
  solely for the authorised recipient. Distribution should be limited and controlled.</div>
  </section>`;
}

function documentControl(scan) {
  const d = new Date(scan.createdAt);
  return `
  <section class="pagebreak">
  <h2>Document Control</h2>
  <h3>Engagement Details</h3>
  <table>
    <tr><th style="width:200px;">Field</th><th>Value</th></tr>
    <tr><td>Report title</td><td>Penetration Test Report — ${esc(scan.target.hostname || scan.target.raw)}</td></tr>
    <tr><td>Report reference</td><td>${esc(scan.id)}</td></tr>
    <tr><td>Assessment type</td><td>Automated active web-application assessment (${esc(scan.options?.profileName || 'Standard')} profile)</td></tr>
    <tr><td>Target</td><td>${esc(scan.target.url || scan.target.raw)}</td></tr>
    <tr><td>Date of assessment</td><td>${d.toUTCString()}</td></tr>
    <tr><td>Authentication</td><td>${scan.info?.authenticated ? 'Authenticated (credentials supplied)' : 'Unauthenticated'}</td></tr>
    <tr><td>Prepared by</td><td>${esc(config.brand.company)} — ${esc(config.brand.site)}</td></tr>
    <tr><td>Classification</td><td>Confidential</td></tr>
  </table>
  <h3>Report Conventions</h3>
  <p>Findings are identified as <b>F-NN</b> and ordered by severity. Each finding includes a description, evidence,
  business impact, and remediation guidance, with CWE and OWASP mappings and a CVSS v3.1 base score where
  applicable.</p>
  </section>`;
}

function riskRatingMethodology() {
  const row = (sev, range, desc) => `<tr><td>${sevTag(sev)}</td><td>${range}</td><td>${desc}</td></tr>`;
  return `
  <section class="pagebreak">
  <h2>Risk Rating Methodology</h2>
  <p>Each finding is assigned a severity reflecting the likelihood of exploitation and the potential business
  impact, aligned to CVSS v3.1 base-score bands.</p>
  <table>
    <tr><th style="width:90px;">Severity</th><th style="width:90px;">CVSS band</th><th>Definition</th></tr>
    ${row('critical', '9.0–10.0', 'Trivially exploitable issues causing complete compromise of confidentiality, integrity, or availability. Remediate immediately.')}
    ${row('high', '7.0–8.9', 'Serious issues that are readily exploitable and lead to significant compromise. Prioritise remediation.')}
    ${row('medium', '4.0–6.9', 'Issues requiring specific conditions or offering limited impact; should be remediated in the normal cycle.')}
    ${row('low', '0.1–3.9', 'Minor issues with limited impact, often defence-in-depth hardening opportunities.')}
    ${row('info', '0.0', 'Observations and informational items with no direct security impact; included for awareness.')}
  </table>
  <p class="muted">Note: contextual factors (compensating controls, exposure, data sensitivity) may adjust the
  effective risk relative to the raw CVSS score.</p>
  </section>`;
}

function execSummary(scan) {
  const c = scan.summary?.counts || {};
  const total = scan.summary?.total || 0;
  const posture = scan.summary?.posture || 'Unknown';
  const cards = ['critical', 'high', 'medium', 'low', 'info']
    .map(
      (s) =>
        `<div class="card c-${s.slice(0, 4)}"><div class="n">${c[s] || 0}</div><div class="l">${SEVERITY_META[s].label}</div></div>`
    )
    .join('');

  const tech = scan.info?.techStack?.length ? scan.info.techStack.join(', ') : '—';
  const ips = scan.info?.resolved?.addresses?.join(', ') || '—';

  const score = scan.summary?.score ?? 0;
  const grade = scan.summary?.grade ?? 'A';
  const gradeColor = score >= 55 ? 'var(--crit)' : score >= 30 ? 'var(--high)' : score >= 12 ? 'var(--med)' : 'var(--low)';
  const c2 = scan.summary?.counts || {};
  const barTotal = Math.max(1, total);
  const seg = (s, color) => (c2[s] ? `<i style="width:${(c2[s] / barTotal) * 100}%;background:${color}"></i>` : '');
  const authBadge = scan.info?.authenticated ? '<span class="pill" style="background:#e3f4e4;color:#1d6b22;border-color:#9fce9f;">Authenticated scan</span>' : '';

  return `
  <h2>Executive Summary</h2>
  <div class="riskbox">
    <div class="riskscore" style="border-color:${gradeColor}">
      <div class="rg" style="color:${gradeColor}">${esc(grade)}</div>
      <div class="rs">Risk score <b style="color:${gradeColor}">${score}</b>/100</div>
    </div>
    <div class="riskbody">
      <p style="margin:0 0 6px;">An automated security assessment of <b>${esc(scan.target.hostname)}</b> identified
      <b>${total}</b> finding(s) across ${esc((scan.options?.resolvedModules || []).length)} checks. Overall posture:
      <span class="posture" style="color:${postureColor(posture)}">${esc(posture)}</span>. ${authBadge}</p>
      <div class="bar">${seg('critical', 'var(--crit)')}${seg('high', 'var(--high)')}${seg('medium', 'var(--med)')}${seg('low', 'var(--low)')}${seg('info', 'var(--info)')}</div>
    </div>
  </div>
  <div class="scorecards">${cards}</div>
  <table>
    <tr><th style="width:170px;">Engagement Detail</th><th>Value</th></tr>
    <tr><td>Target host</td><td>${esc(scan.target.hostname)} (${esc(ips)})</td></tr>
    <tr><td>Detected technology</td><td>${esc(tech)}</td></tr>
    <tr><td>TLS</td><td>${scan.info?.tls ? esc(`${scan.info.tls.protocol || ''} · issuer ${scan.info.tls.issuer || '—'} · expires ${scan.info.tls.validTo || '—'}`) : '—'}</td></tr>
    <tr><td>Open ports</td><td>${scan.info?.openPorts?.length ? esc(scan.info.openPorts.map((p) => `${p.port}/${p.service}`).join(', ')) : '—'}</td></tr>
    <tr><td>Modules executed</td><td>${esc((scan.options?.modules || []).join(', ') || 'defaults')}</td></tr>
  </table>`;
}

function postureColor(p) {
  return (
    {
      Critical: 'var(--crit)',
      'High Risk': 'var(--high)',
      'Moderate Risk': 'var(--med)',
      'Low Risk': 'var(--low)',
      Strong: 'var(--low)',
    }[p] || 'var(--navy)'
  );
}

function summaryTable(scan) {
  const rows = scan.findings
    .map(
      (f) => `<tr>
      <td>${esc(f.ref)}</td>
      <td>${esc(f.title)}</td>
      <td>${sevTag(f.severity)}</td>
      <td>${confTag(f.confidence)}</td>
      <td>${esc([f.cwe, f.owasp?.split(' ')[0]].filter(Boolean).join(' / ') || '—')}</td>
    </tr>`
    )
    .join('');
  return `
  <h2>Summary of Findings</h2>
  <p class="muted" style="font-size:9pt;"><b>Confidence key:</b> <b>Confirmed</b> = actively reproduced
  (payload sent and exploit verified); <b>Firm</b> = definitive observation (e.g. missing header, expired
  certificate); <b>Tentative</b> = heuristic/pattern match — verify manually before acting.</p>
  <table>
    <tr><th style="width:48px;">ID</th><th>Title</th><th style="width:58px;">Severity</th><th style="width:74px;">Confidence</th><th style="width:130px;">CWE / OWASP</th></tr>
    ${rows || '<tr><td colspan="5" class="muted">No findings recorded.</td></tr>'}
  </table>`;
}

function detailedFindings(scan) {
  if (!scan.findings.length) return '';
  const blocks = scan.findings
    .map((f) => {
      const meta = [
        `<span><b>Severity:</b> ${sevTag(f.severity)}</span>`,
        `<span><b>Confidence:</b> ${confTag(f.confidence)}</span>`,
        f.cvss != null ? `<span><b>CVSS:</b> ${esc(f.cvss)}</span>` : '',
        f.cwe ? `<span><b>CWE:</b> ${esc(f.cwe)}</span>` : '',
        f.owasp ? `<span><b>OWASP:</b> ${esc(f.owasp)}</span>` : '',
        `<span><b>Module:</b> ${esc(f.module)}</span>`,
      ]
        .filter(Boolean)
        .join('');
      const refs = f.references?.length
        ? `<h4>References</h4><ul>${f.references.map((r) => `<li><a href="${esc(r)}">${esc(r)}</a></li>`).join('')}</ul>`
        : '';
      const evidence = f.evidence
        ? `<h4>Evidence</h4><pre>${esc(Array.isArray(f.evidence) ? f.evidence.join('\n') : f.evidence)}</pre>`
        : '';
      return `
      <div class="finding">
        <div class="finding-head"><h3>${esc(f.ref)} — ${esc(f.title)}</h3>${sevTag(f.severity)}</div>
        <div class="metarow">${meta}</div>
        <h4>Description</h4>
        <p>${esc(f.description)}</p>
        ${evidence}
        ${f.recommendation ? `<h4>Recommendation</h4><p>${esc(f.recommendation)}</p>` : ''}
        ${refs}
      </div>`;
    })
    .join('');
  return `<h2>Detailed Findings</h2>${blocks}`;
}

const OWASP_2021 = [
  ['A01:2021', 'Broken Access Control'],
  ['A02:2021', 'Cryptographic Failures'],
  ['A03:2021', 'Injection'],
  ['A04:2021', 'Insecure Design'],
  ['A05:2021', 'Security Misconfiguration'],
  ['A06:2021', 'Vulnerable and Outdated Components'],
  ['A07:2021', 'Identification and Authentication Failures'],
  ['A08:2021', 'Software and Data Integrity Failures'],
  ['A09:2021', 'Security Logging and Monitoring Failures'],
  ['A10:2021', 'Server-Side Request Forgery (SSRF)'],
];

function owaspCoverage(scan) {
  const byCat = {};
  for (const f of scan.findings) {
    const code = f.owasp?.split(' ')[0];
    if (code) (byCat[code] ||= []).push(f.ref);
  }
  const rows = OWASP_2021.map(([code, name]) => {
    const refs = byCat[code] || [];
    const status = refs.length
      ? `<span class="sev s-high">${refs.length} finding(s)</span>`
      : `<span class="pill">No issues found</span>`;
    return `<tr><td>${esc(code)}</td><td>${esc(name)}</td><td>${status}</td><td>${esc(refs.join(', ') || '—')}</td></tr>`;
  }).join('');
  return `
  <h2>OWASP Top 10 (2021) Coverage</h2>
  <p>The matrix below maps identified findings to the OWASP Top 10 (2021) risk categories assessed during this engagement.</p>
  <table>
    <tr><th style="width:80px;">Category</th><th>Risk</th><th style="width:120px;">Result</th><th style="width:120px;">Findings</th></tr>
    ${rows}
  </table>`;
}

function reconSection(scan) {
  const i = scan.info || {};
  const blocks = [];
  if (i.crawl) blocks.push(`<tr><td>Crawl coverage</td><td>${i.crawl.pages} pages · ${i.crawl.forms} forms · ${i.crawl.params} parameters · ${i.crawl.js} JS assets</td></tr>`);
  if (i.fingerprint?.technologies?.length) blocks.push(`<tr><td>Technologies</td><td>${esc(i.fingerprint.technologies.join(', '))}</td></tr>`);
  if (i.fingerprint?.waf?.length) blocks.push(`<tr><td>WAF / CDN</td><td>${esc(i.fingerprint.waf.join(', '))}</td></tr>`);
  if (i.subdomains?.live) blocks.push(`<tr><td>Subdomains (live)</td><td>${i.subdomains.live} of ${i.subdomains.discovered} from CT logs</td></tr>`);
  if (i.openPorts?.length) blocks.push(`<tr><td>Open ports</td><td>${esc(i.openPorts.map((p) => `${p.port}/${p.service}`).join(', '))}</td></tr>`);
  if (i.discovered?.length) blocks.push(`<tr><td>Discovered paths</td><td>${esc(i.discovered.slice(0, 20).join(', '))}</td></tr>`);
  if (!blocks.length) return '';
  return `
  <h2>Reconnaissance &amp; Attack Surface</h2>
  <table><tr><th style="width:170px;">Item</th><th>Detail</th></tr>${blocks.join('')}</table>
  ${i.subdomains?.hosts?.length ? `<h3>Live subdomains</h3><pre>${esc(i.subdomains.hosts.slice(0, 50).map((h) => `${h.name} → ${h.ip}`).join('\n'))}</pre>` : ''}`;
}

function remediationRoadmap(scan) {
  if (!scan.findings.length) return '';
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const groups = order
    .map((sev) => {
      const items = scan.findings.filter((f) => f.severity === sev);
      if (!items.length) return '';
      const when = { critical: 'Immediate (24–72h)', high: 'Urgent (1–2 weeks)', medium: 'Planned (30–60 days)', low: 'Backlog (90 days)', info: 'Opportunistic' }[sev];
      const li = items.map((f) => `<li><b>${esc(f.ref)}</b> — ${esc(f.title)}</li>`).join('');
      return `<tr><td>${sevTag(sev)}</td><td>${esc(when)}</td><td><ul style="margin:0;">${li}</ul></td></tr>`;
    })
    .join('');
  return `
  <h2>Remediation Roadmap</h2>
  <p>Recommended remediation sequencing by severity. Timeframes are indicative and should be aligned to the organisation's risk appetite.</p>
  <table><tr><th style="width:80px;">Severity</th><th style="width:150px;">Target window</th><th>Items</th></tr>${groups}</table>`;
}

function methodology(scan) {
  return `
  <h2>Methodology &amp; Scope</h2>
  <p>This assessment was performed using the ${esc(config.brand.company)} automated scanning engine against the
  authorised target below. Testing was non-destructive and limited to reconnaissance, configuration analysis,
  and safe, reflection-based probing. The authorising party confirmed they own or are permitted to test the target.</p>
  <table>
    <tr><th style="width:170px;">Item</th><th>Detail</th></tr>
    <tr><td>Authorised target</td><td>${esc(scan.target.url || scan.target.raw)}</td></tr>
    <tr><td>Authorisation</td><td>${esc(scan.authorization?.confirmedBy || 'confirmed via consent gate')} — ${esc(scan.authorization?.acceptedAt || scan.createdAt)}</td></tr>
    <tr><td>Scan started</td><td>${esc(scan.createdAt)}</td></tr>
    <tr><td>Scan finished</td><td>${esc(scan.finishedAt || '—')}</td></tr>
  </table>
  <div class="callout"><b>Limitation &amp; point-in-time validity.</b> Automated scanning complements but does not
  replace manual penetration testing. Findings reflect the target's state at scan time; absence of a finding is not
  proof of absence of a vulnerability.</div>`;
}

export function renderReport(scan, opts = {}) {
  const autoPrint = opts.print
    ? `<script>window.addEventListener('load',function(){setTimeout(function(){window.print();},350);});</script>`
    : '';
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Penetration Test Report — ${esc(scan.target.hostname || scan.target.raw)}</title>
<style>${STYLES}</style>
</head><body><div class="wrap">
${coverPage(scan)}
${confidentiality(scan)}
${documentControl(scan)}
${execSummary(scan)}
${riskRatingMethodology()}
${methodology(scan)}
${reconSection(scan)}
${summaryTable(scan)}
${owaspCoverage(scan)}
${remediationRoadmap(scan)}
${detailedFindings(scan)}
<p class="muted" style="margin-top:24px; font-size:8pt;">Generated by ${esc(config.brand.site)} ·
Report ${esc(scan.id)} · This document is confidential and intended only for the authorised recipient.</p>
</div>${autoPrint}</body></html>`;
}
