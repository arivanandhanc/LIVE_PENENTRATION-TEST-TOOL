// Technology fingerprinting + WAF/CDN detection. Identifies servers, frameworks,
// CMS, JS libraries, analytics, and any web-application firewall in front of the
// target — context that informs the rest of the assessment.
import { request } from '../../util/http.js';
import { finding } from '../finding.js';

const CAT = 'Reconnaissance';
const MOD = 'Technology Fingerprint';

const SIGS = [
  // [label, header-regex|null, body-regex|null]
  ['WordPress', null, /wp-content|wp-includes|<meta name="generator" content="WordPress/i],
  ['Drupal', /x-drupal/i, /Drupal\.settings|sites\/default\/files/i],
  ['Joomla', null, /\/media\/jui\/|Joomla!/i],
  ['Next.js', /x-powered-by:.*next/i, /__NEXT_DATA__|\/_next\//i],
  ['Nuxt.js', null, /__NUXT__|\/_nuxt\//i],
  ['React', null, /data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js/i],
  ['Vue.js', null, /vue(?:\.runtime)?(?:\.min)?\.js|data-v-/i],
  ['Angular', null, /ng-version=|zone\.js/i],
  ['jQuery', null, /jquery[.-]?\d|jquery\.min\.js/i],
  ['Bootstrap', null, /bootstrap(?:\.min)?\.css|class="[^"]*\b(?:col-(?:xs|sm|md|lg)-|navbar-)/i],
  ['Laravel', /set-cookie:.*laravel_session/i, null],
  ['Django', /csrftoken|x-frame-options:.*deny/i, /csrfmiddlewaretoken/i],
  ['Ruby on Rails', /x-runtime|set-cookie:.*_session_id/i, /csrf-param|authenticity_token/i],
  ['ASP.NET', /x-aspnet-version|set-cookie:.*asp\.net_sessionid/i, /__VIEWSTATE/i],
  ['Express', /x-powered-by:.*express/i, null],
  ['PHP', /x-powered-by:.*php|set-cookie:.*phpsessid/i, null],
  ['Cloudflare', /server:.*cloudflare|cf-ray/i, null],
  ['Google Analytics', null, /googletagmanager\.com\/gtag|google-analytics\.com\/analytics/i],
  ['Shopify', /x-shopify/i, /cdn\.shopify\.com/i],
];

const WAF_SIGS = [
  ['Cloudflare', /cf-ray|server:.*cloudflare/i],
  ['AWS WAF / CloudFront', /x-amz-cf-id|x-amzn-/i],
  ['Akamai', /x-akamai|akamaighost/i],
  ['Sucuri', /x-sucuri/i],
  ['Imperva / Incapsula', /x-iinfo|incap_ses|visid_incap/i],
  ['F5 BIG-IP', /x-waf-event|set-cookie:.*bigipserver|x-cnection/i],
  ['Barracuda', /barra_counter_session/i],
  ['Wordfence', /wfwaf/i],
  ['ModSecurity', /mod_security|modsecurity/i],
];

export default {
  id: 'fingerprint',
  name: 'Technology Fingerprint',
  category: CAT,
  default: true,
  async run(ctx) {
    const res = await request(ctx.target.url, { redirect: 'follow', maxBytes: 256 * 1024 });
    if (!res.ok) return { findings: [] };
    const headerBlob = Object.entries(res.headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    const body = res.body || '';

    const tech = new Set();
    if (res.headers['server']) tech.add(res.headers['server']);
    if (res.headers['x-powered-by']) tech.add(res.headers['x-powered-by']);
    for (const [label, hre, bre] of SIGS) {
      if ((hre && hre.test(headerBlob)) || (bre && bre.test(body))) tech.add(label);
    }

    const wafs = [];
    for (const [label, re] of WAF_SIGS) if (re.test(headerBlob)) wafs.push(label);

    ctx.info.fingerprint = { technologies: [...tech], waf: wafs };
    // Merge into techStack so the report's summary table is populated.
    ctx.info.techStack = [...new Set([...(ctx.info.techStack || []), ...tech])];
    ctx.log(`Fingerprint: ${[...tech].join(', ') || 'none'}${wafs.length ? ` | WAF: ${wafs.join(', ')}` : ''}`);

    const findings = [];
    findings.push(
      finding({
        module: MOD, category: CAT, severity: 'info',
        title: `Technology stack identified (${tech.size} component${tech.size === 1 ? '' : 's'})`,
        description: 'Fingerprinting of response headers and page content identified the technologies below. This reconnaissance informs targeted testing and helps confirm patch levels.',
        evidence: ([...tech].map((t) => `• ${t}`).join('\n') || 'No specific technologies identified.') +
          (wafs.length ? `\n\nWAF/CDN detected: ${wafs.join(', ')}` : '\n\nNo WAF/CDN signature detected.'),
        recommendation: 'Keep all identified components patched. Minimise version disclosure. A WAF is a useful defence-in-depth control but not a substitute for fixing underlying issues.',
        owasp: null, cwe: null,
      })
    );
    return { findings };
  },
};
