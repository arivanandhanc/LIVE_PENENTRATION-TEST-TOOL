// Central registry of scan modules. Order here defines execution order.
import fingerprint from './fingerprint.js';
import cvecheck from './cvecheck.js';
import headers from './headers.js';
import cookies from './cookies.js';
import cors from './cors.js';
import infodisclosure from './infodisclosure.js';
import exposedfiles from './exposedfiles.js';
import methods from './methods.js';
import webprobes from './webprobes.js';
import discovery from './discovery.js';
import secrets from './secrets.js';
import sensitivedata from './sensitivedata.js';
import csrf from './csrf.js';
import graphql from './graphql.js';
import xss from './xss.js';
import sqli from './sqli.js';
import cmdinjection from './cmdinjection.js';
import pathtraversal from './pathtraversal.js';
import ssrf from './ssrf.js';
import tls from './tls.js';
import dns from './dns.js';
import subdomains from './subdomains.js';
import ports from './ports.js';
import dosresilience from './dosresilience.js';
import dependencies from './dependencies.js';

export const MODULES = [
  // Recon
  fingerprint,
  cvecheck,
  // Passive web config
  headers,
  cookies,
  cors,
  infodisclosure,
  exposedfiles,
  methods,
  webprobes,
  // Discovery (needs/uses crawl surface)
  discovery,
  secrets,
  sensitivedata,
  graphql,
  csrf,
  // Active injection (needs crawl surface)
  xss,
  sqli,
  cmdinjection,
  pathtraversal,
  ssrf,
  // Network / infra
  tls,
  dns,
  subdomains,
  ports,
  dosresilience,
  dependencies,
];

/** Public metadata for the UI (without the run function). */
export function moduleCatalog() {
  return MODULES.map(({ id, name, category, default: def, needsCrawl }) => ({
    id, name, category, default: !!def, active: !!needsCrawl,
  }));
}
