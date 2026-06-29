// Injects the shared navigation and footer into every page, highlights the
// active link, and wires the mobile menu. Keeps the multi-page site DRY without
// a build step.
(function () {
  const path = location.pathname.replace(/\/index\.html$/, '/').replace(/\.html$/, '');
  const norm = (p) => (p === '' ? '/' : p);
  const here = norm(path);

  const links = [
    { href: '/', label: 'Home' },
    { href: '/scan', label: 'Scanner' },
    { href: '/docs', label: 'Documentation' },
    { href: '/privacy', label: 'Privacy' },
  ];

  const navLinks = links
    .map((l) => `<a href="${l.href}"${norm(l.href) === here ? ' class="active"' : ''}>${l.label}</a>`)
    .join('');

  const nav = `
  <nav class="nav">
    <div class="nav-inner">
      <a class="nav-brand" href="/">
        <span class="mark">⛨</span>
        <span>Arivanandhan SecTools<small>Penetration Testing Suite</small></span>
      </a>
      <button class="nav-toggle" aria-label="Menu">☰</button>
      <div class="nav-links">
        ${navLinks}
        <a href="https://arivanandhan.in" target="_blank" rel="noopener">arivanandhan.in ↗</a>
        <a class="nav-cta" href="/scan">Launch Scanner</a>
      </div>
    </div>
  </nav>`;

  const year = new Date().getFullYear();
  const footer = `
  <footer class="site-footer">
    <div class="container">
      <div class="footer-grid">
        <div class="footer-brand">
          <div class="mark">⛨</div>
          <div style="color:#fff;font-weight:800;font-size:1.05rem;">Arivanandhan SecTools</div>
          <p>An active web-application penetration-testing suite with crawler-driven
          discovery, real exploit verification, and professional reporting.</p>
        </div>
        <div>
          <h4>Product</h4>
          <a href="/scan">Scanner</a>
          <a href="/docs">Documentation</a>
          <a href="/docs#modules">Modules</a>
          <a href="/docs#how">How testing works</a>
        </div>
        <div>
          <h4>Legal</h4>
          <a href="/privacy">Privacy Policy</a>
          <a href="/legal">Terms &amp; Acceptable Use</a>
          <a href="/legal#copyright">Copyright</a>
        </div>
        <div>
          <h4>About</h4>
          <a href="https://arivanandhan.in" target="_blank" rel="noopener">arivanandhan.in ↗</a>
          <a href="https://github.com/arivanandhanc/LIVE_PENENTRATION-TEST-TOOL" target="_blank" rel="noopener">Source ↗</a>
        </div>
      </div>
      <div class="footer-disclaimer">
        ⚠ Authorised testing only. Only scan systems you own or have explicit written permission to test.
        Unauthorised scanning may be unlawful.
      </div>
      <div class="footer-bottom">
        <span>© ${year} Arivanandhan Chitheshwaran. All rights reserved.</span>
        <span>Built by Arivanandhan · sectools.arivanandhan.in</span>
      </div>
    </div>
  </footer>`;

  const navMount = document.getElementById('site-nav');
  const footMount = document.getElementById('site-footer');
  if (navMount) navMount.outerHTML = nav;
  if (footMount) footMount.outerHTML = footer;

  // Mobile menu toggle (re-query after injection).
  const toggle = document.querySelector('.nav-toggle');
  const menu = document.querySelector('.nav-links');
  if (toggle && menu) toggle.addEventListener('click', () => menu.classList.toggle('open'));
})();
