# PenTestTool

Active web-application penetration-testing scanner with professional report
generation. Hosted at **pentest.arivanandhan.in**.

> ⚠️ **Authorised testing only.** Only scan systems you own or have explicit
> written permission to test. The UI requires an authorization confirmation
> before any scan runs, and the engine refuses to scan loopback/private hosts
> by default (SSRF protection).

## Scan profiles

Pick a profile (or override with individual modules):

- **Passive Recon** — non-intrusive OSINT/config analysis only. No crawl, no active injection. Safe for production.
- **Standard** (default) — recon + config + content discovery + a light crawl with safe, marker-based active checks (XSS, SQLi error/boolean).
- **Aggressive (Full)** — deep crawl + the full active suite including time-based blind injection, OS command injection, path traversal, and port recon. Intrusive — authorised, non-production targets only.

## Capabilities

The engine first **crawls** the application (pages, forms, parameters, JS assets),
then runs the selected modules — passive checks plus **active injection testing**
against every discovered injection point.

| Area | Module | Notes |
|------|--------|-------|
| Recon | Technology Fingerprint | servers, frameworks, CMS, JS libs, **WAF/CDN** detection |
| Recon | Web Crawler | same-origin spider → pages, forms, params, JS |
| Web | Security Headers | HSTS, CSP, X-Frame-Options, nosniff, Referrer/Permissions-Policy |
| Web | Cookie Security | Secure / HttpOnly / SameSite flags |
| Web | CORS Configuration | wildcard + arbitrary-origin reflection |
| Web | Information Disclosure | server/framework version banners |
| Web | Exposed Files | `.git`, `.env`, `.DS_Store`, `server-status`, `phpinfo` |
| Web | HTTP Methods | dangerous verbs, TRACE/XST |
| Web | Content Discovery | admin panels, backups, API/swagger, actuator, cloud creds |
| Web | Exposed Secrets | AWS/Google/Stripe/GitHub keys, JWTs, private keys in JS/HTML |
| Web | **XSS (Active)** | reflected XSS via breakout payloads on discovered params |
| Web | **SQL Injection (Active)** | error-based, boolean-blind, time-based (aggressive) |
| Web | **Command Injection & SSTI** | echo/arithmetic markers + time-based (aggressive) |
| Web | **Path Traversal / CRLF / Host** | LFI, response splitting, host-header injection |
| Web | **SSRF (Active)** | URL-param probing incl. AWS/Azure/GCP cloud-metadata access |
| Web | **CSRF** | state-changing forms lacking anti-CSRF tokens |
| Web | **GraphQL Security** | endpoint discovery + introspection exposure |
| Web | **Sensitive Data Exposure** | stack traces, internal IPs, verbose errors in responses |
| Web | Injection & Redirect Probes | reflected canary, open redirect |
| Recon | **Known Vulnerable Versions** | jQuery/Bootstrap/Angular/Lodash/nginx/Apache/PHP/OpenSSH CVE bands |
| TLS/DNS | TLS / Certificate | trust, expiry, protocol version |
| TLS/DNS | DNS & Email Security | A/AAAA/MX/NS/TXT, SPF, DMARC |
| TLS/DNS | Subdomain Enumeration | Certificate Transparency (crt.sh) + live resolution |
| Network | Port & Service Recon | TCP connect scan of common ports |
| Network | **DoS Resilience & Rate Limiting** | non-destructive, capped burst to check for rate-limiting/abuse controls |
| Dependencies | Dependency Audit (OSV) | known-vuln check from pasted `package.json`/lockfile |

> **A note on "DoS testing":** this tool does **not** perform denial-of-service /
> flood attacks. The DoS module is a *defensive resilience check* — a tightly
> capped (~25-request) burst that detects whether rate limiting and abuse
> controls exist. It never attempts to overwhelm a target.

### Authenticated scanning

Supply a session and the crawler + all active modules test **behind login**:
- **Cookie** header (e.g. `session=…; csrf=…`)
- **Bearer** token
- Arbitrary **extra headers** (e.g. `X-API-Key`)

Implemented via `AsyncLocalStorage` so credentials are isolated per scan.

### Reports

Executive summary with a **0–100 risk score + A–F grade** and severity chart,
**confidentiality notice**, **document control**, **risk-rating methodology**,
**reconnaissance & attack surface**, findings table, **OWASP Top 10 (2021)
coverage matrix**, **remediation roadmap**, and detailed per-finding write-ups
with CVSS, CWE, evidence, and references. Export as **PDF** (one-click
print-to-PDF, deploy-safe — no headless browser needed) or **JSON**.

## Run locally

```bash
npm install
npm start          # http://localhost:3000
# or: npm run dev  (auto-restart)
```

## Configuration (env vars)

| Var | Default | Purpose |
|-----|---------|---------|
| `PORT` | `3000` | HTTP port |
| `HOST` | `0.0.0.0` | bind address |
| `DATA_DIR` | `data` | where scan JSON is persisted |
| `ALLOW_PRIVATE` | `false` | set `true` to permit scanning private/loopback hosts (self-host only) |
| `HTTP_TIMEOUT` | `12000` | per-request timeout (ms) |
| `PORT_CONCURRENCY` | `60` | parallel TCP probes in port scan |

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/modules` | module catalog |
| `POST` | `/api/scans` | create + start a scan (requires `authorization.consent`) |
| `GET` | `/api/scans/:id` | full scan state |
| `GET` | `/api/scans/:id/stream` | live progress (SSE) |
| `GET` | `/api/scans/:id/report` | HTML report (print to PDF) |
| `GET` | `/api/scans/:id/export.json` | JSON export |

## Deployment (pentest.arivanandhan.in)

Runs as a single persistent Node process — suited to a VPS (not serverless,
because port recon + the burst check need raw TCP sockets and long-lived SSE).

**Plain VPS + systemd + nginx:**
```bash
git clone https://github.com/arivanandhanc/LIVE_PENENTRATION-TEST-TOOL.git /opt/pentesttool
cd /opt/pentesttool && npm ci --omit=dev
cp .env.example .env            # keep ALLOW_PRIVATE=false on the public host
sudo cp deploy/pentesttool.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now pentesttool
sudo cp deploy/pentest.arivanandhan.in.nginx.conf /etc/nginx/sites-available/pentest
sudo ln -s /etc/nginx/sites-available/pentest /etc/nginx/sites-enabled/
sudo certbot --nginx -d pentest.arivanandhan.in   # TLS
sudo systemctl reload nginx
```

**Docker:**
```bash
docker build -t pentesttool .
docker run -d -p 3000:3000 -v $PWD/data:/app/data --name pentesttool pentesttool
```

The nginx config disables proxy buffering so Server-Sent Events (live scan
progress) stream correctly.

## Troubleshooting

**"Unexpected token '<', "<!DOCTYPE"... is not valid JSON" when starting a scan.**
This means the browser called `/api/scans` but got an HTML page instead of JSON —
i.e. the **backend isn't reachable**. This tool is a Node application, not a static
site: serving only the `public/` folder will not work. Check that:

1. The Node server is actually running: `node server.js` (or via the systemd unit / Docker).
2. `GET /api/health` returns `{"ok":true}` from the same origin as the page.
3. If behind nginx/Caddy/Cloudflare, your proxy forwards **`/api`** (and the SSE
   `/api/scans/:id/stream` endpoint, with buffering disabled) to the Node process.

The app now detects this and shows a clear banner plus a readable error instead of
the raw JSON-parse message.

**"Internal server error" when starting a scan.**
Usually the server cannot write the `data/` directory (read-only filesystem,
wrong permissions, or a hardened container). As of v1.0 the tool no longer crashes
on this — it falls back to **in-memory** scans and logs a warning — but to persist
results, point `DATA_DIR` at a writable path and ensure the process can write it:

```bash
DATA_DIR=/var/lib/pentesttool node server.js   # any writable dir
```

`GET /api/health` reports `persistence.enabled`. If it's `false`, the data dir
isn't writable. The systemd unit sets `DATA_DIR=/opt/pentesttool/data` and a
matching `ReadWritePaths`. Docker users should mount a writable volume at
`/app/data` (the provided `Dockerfile` already declares it). API errors now include
a `detail` field with the underlying cause to aid diagnosis.

## Roadmap

- Server-side PDF rendering (Puppeteer) for one-click PDF export
- Authenticated scans (cookie/header injection)
- Persistent DB + multi-user accounts
- Scheduled re-scans and diffing against prior runs
