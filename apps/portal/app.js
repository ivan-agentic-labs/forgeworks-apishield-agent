(() => {
  'use strict';
  const IDS = Object.freeze(['apishield-agent','accessfix-ai','specforge-ai','agenttest-lab','datareconcile-ai']);
  const moduleHost = document.getElementById('modules');
  const catalogStatus = document.getElementById('catalog-status');
  const count = document.getElementById('module-count');
  const status = document.getElementById('connection-status');
  const check = document.getElementById('check-connection');

  function isCatalog(products) {
    return Array.isArray(products) && products.length === IDS.length
      && products.every((entry, index) => entry && typeof entry === 'object'
        && Object.keys(entry).sort().join(',') === 'description,domain,id,platform_route,title'
        && entry.id === IDS[index] && entry.platform_route === '/app/' + entry.id
        && ['description','domain','title'].every(k =>
          typeof entry[k] === 'string' && entry[k].trim().length > 0 && entry[k].length <= 256));
  }

  function render(products) {
    if (!isCatalog(products)) throw new Error('INVALID_PORTAL_CATALOG');
    const fragment = document.createDocumentFragment();
    products.forEach((item, index) => {
      const card = document.createElement('article');
      card.className = 'module';
      card.id = item.id;
      const ord = document.createElement('span');
      ord.className = 'ordinal';
      ord.textContent = String(index + 1).padStart(2, '0') + ' / 05';
      const heading = document.createElement('h3');
      heading.textContent = item.title;
      const detail = document.createElement('p');
      detail.textContent = item.description;
      const domain = document.createElement('span');
      domain.className = 'domain';
      domain.textContent = item.domain;
      const gate = document.createElement('span');
      gate.className = 'pending';
      gate.textContent = 'Akses portal belum diaktifkan';
      // Do not create links to reserved /app routes until BFF routing,
      // authentication, and per-service authorization have been verified.
      card.append(ord, heading, detail, domain, gate);
      fragment.append(card);
    });
    moduleHost.replaceChildren(fragment);
    moduleHost.setAttribute('aria-busy','false');
    count.textContent = '05 modul';
    catalogStatus.textContent = 'Katalog ditampilkan; ini bukan bukti kesiapan backend.';
  }

  async function load() {
    try {
      const response = await fetch('./products.json', {cache:'no-store', credentials:'same-origin', redirect:'error'});
      if (!response.ok) throw new Error('CATALOG_UNAVAILABLE');
      const text = await response.text();
      if (text.length > 10000) throw new Error('CATALOG_TOO_LARGE');
      render(JSON.parse(text));
    } catch {
      moduleHost.setAttribute('aria-busy','false');
      catalogStatus.textContent = 'Katalog belum tersedia. Tidak ada produk yang diaktifkan.';
      count.textContent = 'Tidak tersedia';
    }
  }

  check.addEventListener('click', async () => {
    check.disabled = true;
    status.textContent = 'Menghubungi BFF pada origin ini…';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch('/api/platform/status', {
        method:'GET', credentials:'same-origin', cache:'no-store',
        redirect:'error', signal:controller.signal,
        headers:{Accept:'application/json'}
      });
      if (!response.ok) throw new Error('PLATFORM_STATUS_UNAVAILABLE');
      const text = await response.text();
      if (text.length > 4096) throw new Error('PLATFORM_STATUS_TOO_LARGE');
      const payload = JSON.parse(text);
      if (!payload || payload.schema !== 'forgeworks-portal-status-v1'
          || payload.environment !== 'staging' || payload.status !== 'reachable')
        throw new Error('PLATFORM_STATUS_UNRECOGNIZED');
      status.textContent = 'BFF staging merespons. Verifikasi auth dan production acceptance tetap diperlukan.';
    } catch {
      status.textContent = 'BFF belum tersedia atau tidak dapat diverifikasi. Akses produk tetap nonaktif.';
    } finally {
      clearTimeout(timeout);
      check.disabled = false;
    }
  });
  void load();
})();
