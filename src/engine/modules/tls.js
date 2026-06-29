// TLS/certificate posture: validity, expiry, hostname match, protocol version.
import tls from 'node:tls';
import { finding } from '../finding.js';
import { config } from '../../config.js';

const CAT = 'TLS/DNS';
const MOD = 'TLS / Certificate';

function connect(host, port, servername, opts = {}) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host, port, servername,
        rejectUnauthorized: false,
        timeout: config.tcpTimeout,
        ...opts,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;
        socket.end();
        resolve({ ok: true, cert, protocol, cipher, authorized, authError });
      }
    );
    socket.on('error', (e) => resolve({ ok: false, error: e.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'timeout' }); });
  });
}

export default {
  id: 'tls',
  name: 'TLS / Certificate',
  category: CAT,
  default: true,
  async run(ctx) {
    if (ctx.target.protocol !== 'https') {
      return {
        findings: [
          finding({
            module: MOD, category: CAT, severity: 'high',
            title: 'Service does not use HTTPS',
            description:
              'The target was reached over plaintext HTTP. All traffic — including credentials and session tokens — is transmitted unencrypted and is trivially interceptable on the network path.',
            evidence: `Scheme: http://${ctx.target.hostname}:${ctx.target.port}`,
            recommendation: 'Serve the application exclusively over HTTPS with a valid certificate and redirect HTTP→HTTPS.',
            owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-319',
          }),
        ],
      };
    }

    const host = ctx.target.hostname;
    const port = ctx.target.port;
    const res = await connect(host, port, host);
    if (!res.ok) {
      ctx.log(`TLS connect failed: ${res.error}`, 'warn');
      return { findings: [] };
    }

    const findings = [];
    const cert = res.cert || {};
    const now = Date.now();
    const validTo = cert.valid_to ? new Date(cert.valid_to).getTime() : null;
    const validFrom = cert.valid_from ? new Date(cert.valid_from).getTime() : null;

    ctx.info.tls = {
      protocol: res.protocol,
      cipher: res.cipher?.name,
      issuer: cert.issuer?.O || cert.issuer?.CN || null,
      subject: cert.subject?.CN || null,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      authorized: res.authorized,
    };

    if (!res.authorized) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'high',
          title: `Certificate not trusted (${res.authError || 'validation failed'})`,
          description:
            `The presented certificate failed validation: ${res.authError || 'unknown error'}. Clients will see security warnings, and the configuration may permit man-in-the-middle attacks if users are trained to click through.`,
          evidence: `authorizationError: ${res.authError}\nSubject CN: ${cert.subject?.CN}\nIssuer: ${cert.issuer?.O || cert.issuer?.CN}`,
          recommendation: 'Install a certificate from a trusted CA with a complete chain that matches the hostname.',
          owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-295',
        })
      );
    }

    if (validTo) {
      const days = Math.round((validTo - now) / 86400000);
      if (days < 0) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'high',
            title: 'TLS certificate has expired',
            description: `The certificate expired ${-days} day(s) ago (${cert.valid_to}). Browsers will block the site with a hard error.`,
            evidence: `valid_to: ${cert.valid_to}`,
            recommendation: 'Renew and deploy a current certificate; automate renewal (e.g. ACME/Let’s Encrypt).',
            owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-298',
          })
        );
      } else if (days < 21) {
        findings.push(
          finding({
            module: MOD, category: CAT, severity: 'medium',
            title: `TLS certificate expires soon (${days} days)`,
            description: `The certificate expires in ${days} day(s) (${cert.valid_to}). Imminent expiry risks an outage.`,
            evidence: `valid_to: ${cert.valid_to}`,
            recommendation: 'Renew promptly and enable automated renewal/monitoring.',
            owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-298',
          })
        );
      }
    }

    // Weak/legacy protocol.
    if (res.protocol && /TLSv1(\.0|\.1)?$/.test(res.protocol)) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'medium',
          title: `Legacy TLS protocol negotiated (${res.protocol})`,
          description: `The server negotiated ${res.protocol}, a deprecated protocol with known weaknesses. Modern baselines require TLS 1.2+ (preferably 1.3).`,
          evidence: `Negotiated protocol: ${res.protocol}; cipher: ${res.cipher?.name}`,
          recommendation: 'Disable TLS 1.0/1.1; require TLS 1.2 minimum and enable TLS 1.3.',
          owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-326',
        })
      );
    }

    if (validFrom && validTo) {
      const lifespanDays = Math.round((validTo - validFrom) / 86400000);
      ctx.log(`TLS: ${res.protocol}, ${res.cipher?.name}, cert valid ${cert.valid_from} → ${cert.valid_to} (${lifespanDays}d)`);
    }

    return { findings };
  },
};
