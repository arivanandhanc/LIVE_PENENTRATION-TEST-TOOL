// Target parsing, validation, and SSRF-safety checks.
import dns from 'node:dns/promises';
import net from 'node:net';
import { config } from '../config.js';

const PRIVATE_V4 = [
  [/^127\./, 'loopback'],
  [/^10\./, 'private'],
  [/^192\.168\./, 'private'],
  [/^169\.254\./, 'link-local'],
  [/^0\./, 'reserved'],
];

function isPrivateV4(ip) {
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return 'private';
  for (const [re, label] of PRIVATE_V4) if (re.test(ip)) return label;
  return null;
}

function isPrivateV6(ip) {
  const low = ip.toLowerCase();
  if (low === '::1') return 'loopback';
  if (low.startsWith('fe80')) return 'link-local';
  if (low.startsWith('fc') || low.startsWith('fd')) return 'unique-local';
  return null;
}

export function classifyIp(ip) {
  if (net.isIPv4(ip)) return isPrivateV4(ip);
  if (net.isIPv6(ip)) return isPrivateV6(ip);
  return 'invalid';
}

/**
 * Normalise a user-supplied target into a structured object.
 * Accepts: "example.com", "https://example.com:8443/app", "203.0.113.10".
 */
export function parseTarget(raw) {
  if (!raw || typeof raw !== 'string') throw new Error('Target is required.');
  let input = raw.trim();
  if (!/^[a-z]+:\/\//i.test(input)) input = 'https://' + input;

  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`"${raw}" is not a valid URL or hostname.`);
  }

  if (!/^https?:$/.test(url.protocol)) {
    throw new Error('Only http:// and https:// targets are supported.');
  }

  const port = url.port
    ? parseInt(url.port, 10)
    : url.protocol === 'https:'
      ? 443
      : 80;

  return {
    raw,
    url: url.toString(),
    origin: url.origin,
    protocol: url.protocol.replace(':', ''),
    hostname: url.hostname,
    port,
    path: url.pathname || '/',
    isIp: net.isIP(url.hostname) > 0,
  };
}

/**
 * Resolve the hostname and enforce SSRF safety. Returns { addresses, primary }.
 * Throws if the target resolves to a blocked (private/loopback) address.
 */
export async function resolveAndGuard(target) {
  let addresses = [];

  if (target.isIp) {
    addresses = [target.hostname];
  } else {
    try {
      const records = await dns.lookup(target.hostname, { all: true });
      addresses = records.map((r) => r.address);
    } catch (e) {
      throw new Error(`DNS resolution failed for ${target.hostname}: ${e.code || e.message}`);
    }
  }

  if (!addresses.length) throw new Error(`No DNS records for ${target.hostname}.`);

  if (config.blockPrivateTargets) {
    for (const ip of addresses) {
      const cls = classifyIp(ip);
      if (cls && cls !== null && cls !== 'public') {
        throw new Error(
          `Refusing to scan ${target.hostname} → ${ip} (${cls}). ` +
            `Scanning loopback/private/link-local hosts is disabled on the hosted service. ` +
            `Set ALLOW_PRIVATE=true to override on a self-hosted instance.`
        );
      }
    }
  }

  return { addresses, primary: addresses[0] };
}
