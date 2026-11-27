// The Websites list (templates/websites.html, _website_add.html). Reads GET /api/websites once:
//   {success, sites: [{id, name, kind, state, enabled, domain, cert_state, app}],
//    ports: {mode: public|restricted|tunnel, open, sites_enabled, firewall: on|off|unknown},
//    missing: [{key, text, fix_url}], quota: {used, max} | null, php_versions: [..],
//    runtimes: {node: [..]}, apps: [{key, name, version}], hosts: [{id, name}], customers: [{id, name}]}
// (customers only for an administrator; the proxy card's fields come in the same answer for a
// superadmin: js/websites_proxy.js). Each site is a card that taps through to its page. Built with
// textContent only (websites_common.js).
(function () {
  'use strict';
  var WS = window.WS;
  var st = {d: null, kind: 'static', app: '', poll: null, siteId: null};
  var PAGE = WS.el('ws-page');
  var FLAGS = PAGE ? PAGE.dataset : {};

  function portsLine(p) {
    p = p || {};
    if (p.mode === 'tunnel') return {text: WS.T('Tunnel: no port is open; visitors come in through the tunnel.'), cls: 'text-secondary'};
    if (!p.open) return {text: WS.T('Closed: no site is online, so ports 80 and 443 are closed.'), cls: 'text-secondary'};
    var n = p.sites_enabled || 0;
    var key = p.mode === 'restricted'
      ? (n === 1 ? 'Restricted: ports 80 and 443 are open to your listed networks for 1 site.'
        : 'Restricted: ports 80 and 443 are open to your listed networks for {n} sites.')
      : (n === 1 ? 'Public: ports 80 and 443 are open for 1 site.' : 'Public: ports 80 and 443 are open for {n} sites.');
    return {text: WS.TF(key, {n: n}), cls: 'text-warning-emphasis'};
  }
  function renderPorts(p) {
    var e = WS.el('ws-ports');
    if (!e) return;
    // For administrators only: how many sites are online on the host is not a customer's business.
    WS.show(e, FLAGS.admin === '1' && !!p);
    if (FLAGS.admin !== '1' || !p) return;
    var line = portsLine(p);
    e.textContent = line.text;
    e.className = 'small mb-1 ws-ports ' + line.cls;
    if (p.firewall === 'off' && p.mode !== 'tunnel') {
      e.appendChild(WS.node('span', 'd-block text-warning', WS.T('Firewall is off: 80 and 443 are reachable regardless.')));
    }
  }
  function renderQuota(q) {
    var e = WS.el('ws-quota');
    if (!e) return;
    WS.show(e, !!(q && q.max));
    if (q && q.max) e.textContent = WS.TF('{used} of {max} websites used', {used: q.used || 0, max: q.max});
  }
  function lock(cert) {
    var ok = WS.TRUSTED.indexOf(cert) >= 0;
    // The icon is decoration; its meaning is a hidden text node, which the translator reaches.
    var box = WS.node('span', 'ws-lock');
    box.appendChild(WS.icon(ok ? 'lock-fill text-success' : cert === 'failed' ? 'unlock text-danger' : 'hourglass-split text-secondary'));
    box.appendChild(WS.node('span', 'visually-hidden', WS.T(WS.pick(WS.CERT, cert, 'No certificate yet'))));
    return box;
  }
  WS.card = function (s) {
    var a = WS.node('a', 'card ws-card');
    a.href = WS.url(WS.R.page(Number(s.id)));
    var top = WS.node('div', 'ws-card-top');
    top.appendChild(WS.dot(s.state));
    top.appendChild(WS.raw('span', 'ws-card-name', s.name));
    if (s.domain) top.appendChild(lock(s.cert_state));
    a.appendChild(top);
    a.appendChild(s.domain ? WS.raw('div', 'ws-card-domain', s.domain) : WS.node('div', 'ws-card-domain text-secondary', WS.T('No domain yet')));
    var meta = WS.node('div', 'ws-card-meta');
    meta.appendChild(WS.node('span', 'ws-chip', WS.kindLabel(s.kind)));
    meta.appendChild(WS.node('span', 'small text-secondary', WS.stateLabel(s.state)));
    var onCls = s.enabled ? 'small text-success' : 'small text-secondary';
    meta.appendChild(WS.node('span', onCls, WS.T(s.enabled ? 'Online' : 'Offline')));
    a.appendChild(meta);
    return a;
  };
  function renderList(sites) {
    var box = WS.clear(WS.el('ws-list'));
    if (!box) return;
    if (!sites || !sites.length) {
      box.appendChild(WS.node('p', 'small text-secondary mb-0', FLAGS.canAdd === '1'
        ? WS.T('No websites yet. Add one with the button above.') : WS.T('No websites you can see yet. Ask an administrator for access.')));
      return;
    }
    sites.forEach(function (s) { box.appendChild(WS.card(s)); });
  }

  function options(sel, values, labelOf) {
    if (!sel) return;
    WS.clear(sel);
    (values || []).forEach(function (v) {
      var o = WS.node('option', null, labelOf ? labelOf(v) : String(v));
      o.value = typeof v === 'object' ? String(v.id) : String(v);
      sel.appendChild(o);
    });
  }
  function fillAdd(d) {
    options(WS.el('ws-add-php-version'), d.php_versions);
    options(WS.el('ws-add-node-version'), (d.runtimes || {}).node);
    options(WS.el('ws-add-host-id'), d.hosts, function (h) { return h.name; });
    WS.show('ws-add-host', (d.hosts || []).length > 1);
    var cust = WS.el('ws-add-customer-id');
    if (cust) {
      options(cust, [{id: '', name: WS.T('No customer: administrators only')}].concat(d.customers || []), function (c) { return c.name; });
      WS.show('ws-add-customer', true);
    }
    renderAppTiles(d.apps || []);
  }
  function renderAppTiles(apps) {
    var box = WS.clear(WS.el('ws-app-tiles'));
    if (!box) return;
    apps.forEach(function (a, i) {
      var id = 'ws-app-' + i;
      var inp = WS.node('input', 'btn-check');
      inp.type = 'radio';
      inp.name = 'ws-app';
      inp.id = id;
      inp.value = String(a.key);
      inp.setAttribute('data-action', 'wsPickApp');
      inp.setAttribute('data-args', JSON.stringify([String(a.key)]));
      inp.setAttribute('data-on', 'change');
      var lab = WS.node('label', 'ws-tile');
      lab.htmlFor = id;
      lab.appendChild(WS.raw('span', 'ws-tile-name', a.name));
      if (a.version) lab.appendChild(WS.raw('span', 'ws-tile-sub', a.version));
      box.appendChild(inp);
      box.appendChild(lab);
    });
  }

  // The dialog's first line: what is missing, and the one button that fixes it (a superadmin), or
  // who to ask. Create stays on screen, unavailable, with the reason beside it.
  var FIX = {proxy: {label: 'Install the web proxy', action: 'wsProxyInstall', icon: 'download'}};
  WS.renderMissing = function (missing) {
    var box = WS.el('ws-missing');
    var first = (missing || [])[0];
    WS.show(box, !!first);
    var create = WS.el('ws-add-create');
    if (create) create.disabled = !!first;
    if (!first) { WS.say('ws-add-msg', ''); return; }
    WS.el('ws-missing-text').textContent = first.text || WS.T('Something this host needs for websites is missing.');
    var fix = WS.clear(WS.el('ws-missing-fix'));
    var f = WS.pick(FIX, first.key, null);
    var path = WS.safePath(first.fix_url);
    if (FLAGS.super !== '1') {
      fix.appendChild(WS.node('span', 'text-secondary', WS.T('Ask a superadmin to set this up.')));
    } else if (f) {
      fix.appendChild(WS.button(WS.T(f.label), f.icon, f.action, [], 'btn-warning'));
    } else if (path) {
      var a = WS.node('a', 'btn btn-sm btn-warning', WS.T('Fix this'));
      a.href = WS.url(path);
      fix.appendChild(a);
    }
    WS.say('ws-add-msg', WS.T('Create is available once this is fixed.'), 'err');
  };
  window.wsOpenAdd = function () {
    var m = WS.el('ws-add-modal');
    if (!m || !window.bootstrap) return;
    WS.show('ws-add-form', true);
    WS.show('ws-add-footer', true);
    WS.show('ws-progress-wrap', false);
    WS.renderMissing(st.d ? st.d.missing : []);
    window.bootstrap.Modal.getOrCreateInstance(m).show();
  };
  window.wsKind = function (kind) {
    st.kind = kind;
    WS.show('ws-add-php', kind === 'php');
    WS.show('ws-add-node', kind === 'app');
    WS.show('ws-add-apps', kind === 'install');
    WS.show('ws-add-admin', kind === 'install');
  };
  window.wsPickApp = function (key) { st.app = key; };
  // A name from the domain's first label, until the name is typed by hand.
  window.wsDomainTyped = function () {
    var name = WS.el('ws-add-name'), dom = WS.el('ws-add-domain');
    if (!name || !dom || name.dataset.typed === '1') return;
    var label = dom.value.trim().toLowerCase().replace(/^www\./, '').split('.')[0] || '';
    name.value = trimHyphens(label.replace(/[^a-z0-9-]/g, '')).slice(0, 32);
  };
  // `text` without its leading and trailing hyphens (an index scan, not a backtracking pattern).
  function trimHyphens(text) {
    var a = 0, b = text.length;
    while (a < b && text.charAt(a) === '-') a++;
    while (b > a && text.charAt(b - 1) === '-') b--;
    return text.slice(a, b);
  }
  function val(id) { var e = WS.el(id); return e ? e.value.trim() : ''; }
  function addBody() {
    var body = {name: val('ws-add-name'), domain: val('ws-add-domain'), host_id: val('ws-add-host-id') || null,
      customer_id: val('ws-add-customer-id') || null};
    if (st.kind !== 'install') {
      body.kind = st.kind;
      if (st.kind === 'php') body.php_version = val('ws-add-php-version');
      if (st.kind === 'app') { body.runtime = 'node'; body.runtime_version = val('ws-add-node-version'); }
      return body;
    }
    body.app = st.app;
    body.admin_user = val('ws-add-admin-user');
    body.admin_email = val('ws-add-admin-email');
    var pass = WS.el('ws-add-admin-pass');
    body.admin_password = pass ? pass.value : '';
    return body;
  }
  function addProblem(body) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(body.name)) return WS.T('A website name is 1 to 32 lowercase letters, digits and hyphens, and starts and ends with a letter or digit.');
    if (st.kind !== 'install') return '';
    if (!body.app) return WS.T('Choose the app to install.');
    if (!body.domain) return WS.T('An app needs its domain.');
    if (!body.admin_user || !body.admin_email) return WS.T('Enter the app admin username and email.');
    if (body.admin_password && body.admin_password.length < 15) return WS.T('A password you type needs at least 15 characters.');
    return '';
  }
  window.wsAddSubmit = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var body = addBody();
    var problem = addProblem(body);
    if (problem) { WS.say('ws-add-msg', problem, 'err'); return; }
    WS.say('ws-add-msg', WS.T('Creating…'));
    WS.post(st.kind === 'install' ? WS.R.installApp : WS.R.add, body).then(function (d) {
      var pass = WS.el('ws-add-admin-pass');
      if (pass) pass.value = '';
      if (!d || !d.id) { WS.done(d, 'ws-add-msg'); return; }
      startProgress(Number(d.id), d.password || '');
    });
  };

  // After Create: the steps as they run (a job, like an add-on install), then the result.
  function startProgress(id, password) {
    st.siteId = id;
    WS.show('ws-add-form', false);
    WS.show('ws-add-footer', false);
    WS.show('ws-progress-wrap', true);
    WS.clear(WS.el('ws-result'));
    if (password) showPassword(password);
    pollOnce();
  }
  function showPassword(password) {
    var box = WS.el('ws-result');
    var p = WS.node('div', 'alert alert-info py-2 px-2 small mb-2');
    p.appendChild(WS.node('div', 'fw-semibold', WS.T('The app admin password, shown only this once:')));
    var code = WS.raw('code', 'ws-secret user-select-all', password);
    p.appendChild(code);
    box.appendChild(p);
  }
  function pollOnce() {
    WS.get(WS.R.site(st.siteId)).then(function (d) {
      var inst = (d && d.install) || {};
      WS.renderSteps(WS.el('ws-progress'), inst);
      var running = inst.state === 'running' || (d && d.site && d.site.state === 'creating' && inst.state !== 'failed');
      if (running) { st.poll = setTimeout(pollOnce, 2000); return; }
      finish(d || {}, inst);
    });
  }
  function link(text, href, cls) {
    var a = WS.node('a', 'btn btn-sm ' + cls, text);
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    return a;
  }
  function finish(d, inst) {
    var box = WS.el('ws-result');
    var row = WS.node('div', 'd-flex flex-wrap gap-2 align-items-center');
    if (inst.state === 'failed' || (d.site && d.site.state === 'failed')) {
      row.appendChild(WS.node('span', 'text-danger small', inst.error || (d.site && d.site.state_reason) || WS.T('A step failed, and every step done before it was undone.')));
    } else {
      row.appendChild(WS.node('span', 'text-success small', WS.T('Done.')));
      var site = WS.safeUrl(inst.site_url), admin = WS.safeUrl(inst.admin_url);
      if (site) row.appendChild(link(WS.T('Open the site'), site, 'btn-outline-primary'));
      if (admin) row.appendChild(link(WS.T('Open the admin page'), admin, 'btn-outline-primary'));
    }
    var go = WS.node('a', 'btn btn-sm btn-primary', WS.T('Go to the website'));
    go.href = WS.url(WS.R.page(st.siteId));
    row.appendChild(go);
    box.appendChild(row);
    load();
  }

  window.wsProxyInstall = function () {
    WS.stepUp(function () {
      WS.say('ws-add-msg', WS.T('Installing the web proxy…'));
      WS.post('/websites/proxy/install', {host_id: val('ws-add-host-id') || val('wp-host') || null}).then(function (d) {
        WS.done(d);
        load();
      });
    });
  };

  function load() {
    return WS.get(WS.R.list).then(function (d) {
      if (!d || d.success === false) {
        WS.clear(WS.el('ws-list')).appendChild(WS.node('p', 'small text-danger mb-0', (d && d.message) || WS.T('The websites could not be loaded.')));
        return;
      }
      st.d = d;
      renderPorts(d.ports);
      renderQuota(d.quota);
      renderList(d.sites);
      if (WS.el('ws-add-modal')) { fillAdd(d); WS.renderMissing(d.missing); }
      if (WS.customerSites) WS.customerSites(d.sites || []);
      if (window.wsProxyRender) window.wsProxyRender(d);
    });
  }
  WS.loadList = load;
  if (PAGE) load();
})();

// Add a customer (administrators): the sites they get, then a one-time invite link and code, shown once.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.el('wc-form')) return;
  WS.customerSites = function (sites) {
    var box = WS.clear(WS.el('wc-sites'));
    sites.forEach(function (s) {
      var id = 'wc-site-' + Number(s.id);
      var wrap = WS.node('div', 'form-check');
      var cb = WS.node('input', 'form-check-input');
      cb.type = 'checkbox';
      cb.id = id;
      cb.value = String(Number(s.id));
      cb.setAttribute('data-wc-site', '');
      var lab = WS.raw('label', 'form-check-label small', s.name);
      lab.htmlFor = id;
      wrap.appendChild(cb);
      wrap.appendChild(lab);
      box.appendChild(wrap);
    });
    if (!sites.length) box.appendChild(WS.node('span', 'small text-secondary', WS.T('Add a website first.')));
  };
  WS.customerBody = function () {
    var ids = [];
    document.querySelectorAll('[data-wc-site]').forEach(function (cb) { if (cb.checked) ids.push(Number(cb.value)); });
    return {name: WS.el('wc-name').value.trim().toLowerCase(), sites: ids, max_sites: Number(WS.el('wc-max').value) || 3};
  };
  function showInvite(d) {
    var box = WS.clear(WS.el('wc-result'));
    WS.show(box, true);
    var p = WS.node('div', 'alert alert-info py-2 px-2 small mb-0');
    p.appendChild(WS.node('div', 'fw-semibold', WS.T('Send the customer this link and its code. Both are shown only this once:')));
    p.appendChild(WS.raw('code', 'ws-secret user-select-all', d.invite || ''));
    p.appendChild(WS.raw('code', 'ws-secret user-select-all', d.code || ''));
    box.appendChild(p);
  }
  window.wsCustomerAdd = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var body = WS.customerBody();
    if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(body.name)) { WS.say('wc-msg', WS.T('A customer name is 1 to 32 lowercase letters, digits and hyphens.'), 'err'); return; }
    if (!body.sites.length) { WS.say('wc-msg', WS.T('Choose at least one website for the customer.'), 'err'); return; }
    WS.stepUp(function () {
      WS.say('wc-msg', WS.T('Adding…'));
      WS.post('/websites/customers/add', body).then(function (d) {
        if (!WS.done(d, 'wc-msg')) return;
        showInvite(d);
        WS.el('wc-name').value = '';
      });
    });
  };
})();
