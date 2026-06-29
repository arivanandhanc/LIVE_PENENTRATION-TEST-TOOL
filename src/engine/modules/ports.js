// TCP connect port scan over a curated common-ports list, with lightweight
// banner grabbing. Connect scans only (no raw sockets / SYN), so it runs
// unprivileged and is safe for authorised assessments.
import net from 'node:net';
import { finding } from '../finding.js';
import { config } from '../../config.js';

const CAT = 'Network';
const MOD = 'Port & Service Recon';

// Common ports with the service + a risk note when exposed to the internet.
const COMMON_PORTS = [
  { p: 21, s: 'FTP', risk: 'medium', note: 'Plaintext file transfer; often allows anonymous or weak auth.' },
  { p: 22, s: 'SSH', risk: 'info', note: 'Remote admin; ensure key-only auth and fail2ban.' },
  { p: 23, s: 'Telnet', risk: 'high', note: 'Plaintext remote admin — should never be internet-exposed.' },
  { p: 25, s: 'SMTP', risk: 'info', note: 'Mail transfer; check for open relay.' },
  { p: 53, s: 'DNS', risk: 'info', note: 'Ensure recursion is not open to the internet.' },
  { p: 110, s: 'POP3', risk: 'low', note: 'Legacy mail retrieval; prefer TLS variants.' },
  { p: 135, s: 'MSRPC', risk: 'high', note: 'Windows RPC — should not be internet-exposed.' },
  { p: 139, s: 'NetBIOS', risk: 'high', note: 'SMB/NetBIOS — should not be internet-exposed.' },
  { p: 143, s: 'IMAP', risk: 'low', note: 'Legacy mail retrieval; prefer TLS variants.' },
  { p: 445, s: 'SMB', risk: 'high', note: 'File sharing — a frequent ransomware/worm vector if exposed.' },
  { p: 1433, s: 'MS SQL', risk: 'high', note: 'Database should not be directly internet-exposed.' },
  { p: 1521, s: 'Oracle DB', risk: 'high', note: 'Database should not be directly internet-exposed.' },
  { p: 2375, s: 'Docker API', risk: 'critical', note: 'Unauthenticated Docker API = host takeover.' },
  { p: 3306, s: 'MySQL', risk: 'high', note: 'Database should not be directly internet-exposed.' },
  { p: 3389, s: 'RDP', risk: 'high', note: 'Remote Desktop — brute-force/exploit target if exposed.' },
  { p: 5432, s: 'PostgreSQL', risk: 'high', note: 'Database should not be directly internet-exposed.' },
  { p: 5601, s: 'Kibana', risk: 'medium', note: 'Often unauthenticated; exposes log data.' },
  { p: 5900, s: 'VNC', risk: 'high', note: 'Remote desktop; frequently weak/no auth.' },
  { p: 6379, s: 'Redis', risk: 'critical', note: 'Default Redis has no auth — full data access/RCE.' },
  { p: 8080, s: 'HTTP-alt', risk: 'info', note: 'Secondary web service / proxy.' },
  { p: 8443, s: 'HTTPS-alt', risk: 'info', note: 'Secondary TLS web service.' },
  { p: 9200, s: 'Elasticsearch', risk: 'critical', note: 'Often unauthenticated — full data exposure.' },
  { p: 11211, s: 'Memcached', risk: 'high', note: 'Unauthenticated; UDP amplification risk.' },
  { p: 27017, s: 'MongoDB', risk: 'critical', note: 'Default MongoDB may allow unauthenticated access.' },
  { p: 80, s: 'HTTP', risk: 'info', note: 'Web service.' },
  { p: 443, s: 'HTTPS', risk: 'info', note: 'Web service.' },
];

function probe(host, port, timeout) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let settled = false;
    const finish = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, open, banner: banner.slice(0, 120).replace(/[^\x20-\x7e]/g, '.').trim() });
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => {
      // Give the service a brief moment to volunteer a banner.
      socket.setTimeout(700);
    });
    socket.once('data', (d) => { banner += d.toString('latin1'); finish(true); });
    socket.once('timeout', () => finish(socket.connecting ? false : true));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function pool(items, size, worker) {
  const results = [];
  let i = 0;
  const runners = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await worker(items[idx]);
    }
  });
  await Promise.all(runners);
  return results;
}

export default {
  id: 'ports',
  name: 'Port & Service Recon',
  category: CAT,
  default: false, // opt-in: heavier and noisier than the web checks
  async run(ctx) {
    const host = ctx.resolved.primary;
    const results = await pool(
      COMMON_PORTS,
      config.portConcurrency,
      (entry) => probe(host, entry.p, config.tcpTimeout)
    );

    const open = [];
    for (let k = 0; k < COMMON_PORTS.length; k++) {
      if (results[k]?.open) open.push({ ...COMMON_PORTS[k], banner: results[k].banner });
    }
    open.sort((a, b) => a.p - b.p);
    ctx.info.openPorts = open.map((o) => ({ port: o.p, service: o.s, banner: o.banner }));
    ctx.log(`Open ports: ${open.map((o) => o.p).join(', ') || 'none'}`);

    const findings = [];
    const risky = open.filter((o) => o.risk !== 'info');

    // One consolidated informational finding listing all open ports.
    if (open.length) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: 'info',
          title: `${open.length} open TCP port(s) discovered`,
          description: 'A TCP connect scan of common ports identified the following reachable services. Each exposed service expands the attack surface and should be justified and hardened.',
          evidence: open.map((o) => `${o.p}/tcp  ${o.s}${o.banner ? `  «${o.banner}»` : ''}`).join('\n'),
          recommendation: 'Confirm each exposed service is required. Place management and database services behind a VPN/firewall; expose only the ports the application genuinely needs.',
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-668',
        })
      );
    }

    // Elevate genuinely risky exposures.
    for (const o of risky) {
      findings.push(
        finding({
          module: MOD, category: CAT, severity: o.risk,
          title: `Sensitive service exposed: ${o.s} (port ${o.p}/tcp)`,
          description: `Port ${o.p} (${o.s}) is reachable from the scanner. ${o.note}`,
          evidence: `${o.p}/tcp open — ${o.s}${o.banner ? `\nBanner: ${o.banner}` : ''}`,
          recommendation: `Restrict access to ${o.s} via firewall/security-group rules; bind to localhost or a private network and require strong authentication.`,
          owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-668',
        })
      );
    }

    return { findings };
  },
};
