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
  // who to ask. An entry that blocks (any entry unless it says blocking: false) keeps Create on screen,
  // unavailable, with the reason beside it; one that does not is a note, and Create stays available, so
  // the line and the button never disagree. An entry with `kinds` concerns only those kinds of site.
  var FIX = {proxy: {label: 'Install the web proxy', action: 'wsProxyInstall', icon: 'download', args: ['add']},
    database: {label: 'Set up databases', action: 'wsDbSetup', icon: 'database-add', host: true},
    'database-stopped': {label: 'Start the database server', action: 'wsDbStart', icon: 'play-circle', host: true}};
  function blocks(m) { return !!m && m.blocking !== false; }
  WS.renderMissing = function (missing) {
    var box = WS.el('ws-missing');
    var mine = (missing || []).filter(function (m) { return !m.kinds || m.kinds.indexOf(st.kind) >= 0; });
    var first = mine.filter(blocks)[0] || mine[0];
    WS.show(box, !!first);
    var create = WS.el('ws-add-create');
    if (create) create.disabled = blocks(first);
    if (!first) { WS.say('ws-add-msg', ''); return; }
    WS.el('ws-missing-text').textContent = first.text || WS.T('Something this host needs for websites is missing.');
    missingFix(WS.clear(WS.el('ws-missing-fix')), first);
    WS.say('ws-add-msg', blocks(first) ? WS.T('Create is available once this is fixed.') : '', 'err');
  };
  // The one button that fixes `m` for a superadmin (or a link to the page that does); "ask" for anyone else.
  function missingFix(fix, m) {
    var f = WS.pick(FIX, m.key, null);
    var path = WS.safePath(m.fix_url);
    if (FLAGS.super !== '1') {
      fix.appendChild(WS.node('span', 'text-secondary', WS.T('Ask a superadmin to set this up.')));
    } else if (f) {
      fix.appendChild(WS.button(WS.T(f.label), f.icon, f.action, f.host ? [Number(m.host_id) || 0] : (f.args || []), 'btn-warning'));
    } else if (path) {
      var a = WS.node('a', 'btn btn-sm btn-warning', WS.T('Fix this'));
      a.href = WS.url(path);
      fix.appendChild(a);
    }
  }
  window.wsOpenAdd = function () {
    var m = WS.el('ws-add-modal');
    if (!m || !window.bootstrap) return;
    WS.show('ws-add-form', true);
    WS.show('ws-add-footer', true);
    WS.show('ws-progress-wrap', false);
    WS.renderMissing(st.d ? st.d.missing : []);
    window.bootstrap.Modal.getOrCreateInstance(m).show();
    refreshMissing(false);
  };
  // The dialog's first line read again from the server, so Create follows what changed since the page loaded (a
  // database server set up meanwhile). With `poll`, asked again every 5 seconds, up to 10 minutes, while a
  // database entry is still there; once it is gone, the dialog says Create works now.
  function refreshMissing(poll, left) {
    clearTimeout(st.dbPoll);
    return WS.get(WS.R.list).then(function (d) {
      if (!d || d.success === false || !st.d) return;
      st.d = Object.assign({}, st.d, {missing: d.missing || []});
      WS.renderMissing(st.d.missing);
      var waiting = st.d.missing.some(function (m) { return String(m.key || '').indexOf('database') === 0; });
      var n = left == null ? 120 : left;
      if (!poll) return;
      if (!waiting) WS.say('ws-add-msg', WS.T('The database server is ready. Create the app now.'), 'ok');
      else if (n > 0) st.dbPoll = setTimeout(function () { refreshMissing(true, n - 1); }, 5000);
    });
  }
  window.wsKind = function (kind) {
    st.kind = kind;
    WS.renderMissing(st.d ? st.d.missing : []);
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
    // In a folder (example.org/forums): the folder's last part names the site.
    var typed = dom.value.trim().toLowerCase(), cut = typed.indexOf('/');
    var folder = cut >= 0 ? typed.slice(cut + 1).split('/').filter(Boolean).pop() || '' : '';
    var label = folder || typed.replace(/^www\./, '').split('.')[0] || '';
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
      if (!d || !d.id) { refused(d); return; }
      startProgress(Number(d.id), d.password || '');
    });
  };

  // Create refused. Before anything was made for a missing precondition (no database server for an app), the
  // answer carries the dialog's entry: its first line then says so, with the button that fixes it.
  function refused(d) {
    var more = (d && d.missing) || [];
    if (more.length && st.d) {
      var key = more[0].key;
      // A copy: the list's own answer is left as the server sent it.
      st.d = Object.assign({}, st.d, {missing: (st.d.missing || []).filter(function (m) { return m.key !== key; }).concat(more)});
      WS.renderMissing(st.d.missing);
    }
    WS.done(d, 'ws-add-msg');
  }

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
  // The generated password, masked like every stored secret (js/secret_field.js): dots until Show, Copy without
  // showing it, hidden again by itself.
  function showPassword(password) {
    var box = WS.el('ws-result');
    var p = WS.node('div', 'alert alert-info py-2 px-2 small mb-2');
    p.appendChild(WS.node('div', 'fw-semibold', WS.T('The app admin password, shown only this once:')));
    p.appendChild(window.secretField({value: password}));
    box.appendChild(p);
  }
  function pollOnce() {
    WS.get(WS.R.site(st.siteId)).then(function (d) {
      if (!d || !d.site) { pollGone(); return; }
      var inst = d.install || {};
      WS.renderSteps(WS.el('ws-progress'), inst);
      var running = inst.state === 'running' || (d.site.state === 'creating' && inst.state !== 'failed');
      if (running) { st.poll = setTimeout(pollOnce, 2000); return; }
      finish(d, inst);
    });
  }
  // The site is gone: an app install that failed undid every step and removed it. Its job still says why
  // (the starter only); without that answer it is still a failure, never "Done."
  function pollGone() {
    WS.get('/websites/install-app/status?id=' + Number(st.siteId)).then(function (j) {
      var inst = (j && j.success && j.install) || {};
      if (inst.state === 'running') { st.poll = setTimeout(pollOnce, 2000); return; }
      WS.renderSteps(WS.el('ws-progress'), inst);
      finish({gone: true}, {state: 'failed', error: inst.error || ''});
    });
  }
  function link(text, href, cls) {
    var a = WS.node('a', 'btn btn-sm ' + cls, text);
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    return a;
  }
  function openLinks(box, inst) {
    var site = WS.safeUrl(inst.site_url), admin = WS.safeUrl(inst.admin_url);
    if (site) box.appendChild(link(WS.T('Open the site'), site, 'btn-outline-primary'));
    if (admin) box.appendChild(link(WS.T('Open the admin page'), admin, 'btn-outline-primary'));
  }
  // A new site starts offline: its links would not open. Its main button is then Put it online (for an
  // administrator of the site), and the links come once it is; anyone else is told who can.
  function offlineRow(row, d, inst) {
    var can = (d.can || {}).admin;
    if (!can) {
      row.appendChild(WS.node('span', 'small text-secondary', WS.T('The website is offline until an administrator of it puts it online.')));
      return;
    }
    var wrap = WS.node('div', 'w-100 d-flex flex-wrap gap-2 align-items-center');
    wrap.id = 'ws-result-online';
    wrap.appendChild(WS.button(WS.T('Put it online'), 'globe', 'wsFinishOnline', [], 'btn-success'));
    wrap.appendChild(WS.node('span', 'small text-secondary', WS.T('This opens ports 80 and 443 to the internet and gets a certificate for its domains. Each domain must point at this host first.')));
    var msg = WS.node('div', 'w-100 small');
    msg.id = 'ws-result-msg';
    msg.setAttribute('role', 'status');
    wrap.appendChild(msg);
    row.appendChild(wrap);
    st.inst = inst;
    var auto = WS.el('ws-add-online');
    if (auto && auto.checked) window.wsFinishOnline();
  }
  window.wsFinishOnline = function () {
    WS.putOnline(st.siteId, 'ws-result-msg', function (ok) {
      var wrap = WS.el('ws-result-online');
      if (!ok || !wrap) return;
      wrap.querySelectorAll('button').forEach(function (b) { b.remove(); });
      openLinks(wrap, st.inst || {});
      load();
    });
  };
  // Nothing of it is left on the host or in the list: no link to a page that is not there.
  function finishGone(box, row, inst) {
    row.appendChild(WS.node('span', 'text-danger small', WS.T('The install failed, and nothing of it was left on the host.')));
    if (inst.error) row.appendChild(WS.raw('span', 'text-danger small w-100', inst.error));
    row.appendChild(WS.button(WS.T('Try again'), 'arrow-counterclockwise', 'wsAddAgain', [], 'btn-primary'));
    box.appendChild(row);
    load();
  }
  function finish(d, inst) {
    var box = WS.el('ws-result');
    var row = WS.node('div', 'd-flex flex-wrap gap-2 align-items-center');
    if (d.gone) { finishGone(box, row, inst); return; }
    if (inst.state === 'failed' || (d.site && d.site.state === 'failed')) {
      row.appendChild(WS.node('span', 'text-danger small', inst.error || (d.site && d.site.state_reason) || WS.T('A step failed, and every step done before it was undone.')));
    } else {
      row.appendChild(WS.node('span', 'text-success small', WS.T('Done.')));
      if (d.site && d.site.enabled) openLinks(row, inst); else offlineRow(row, d, inst);
    }
    var go = WS.node('a', 'btn btn-sm btn-primary', WS.T('Go to the website'));
    go.href = WS.url(WS.R.page(st.siteId));
    row.appendChild(go);
    box.appendChild(row);
    load();
  }

  // MariaDB installed on the host, reached from this machine only (the Databases code's own setup, in the
  // background); the dialog follows it and makes Create available once it is done.
  window.wsDbSetup = function (hostId) {
    WS.stepUp(function () {
      WS.say('ws-add-msg', WS.T('Setting up databases…'));
      WS.post('/api/remote/' + Number(hostId) + '/databases/setup', {}).then(function (d) {
        if (!d || !d.success) { WS.done(d, 'ws-add-msg'); return; }
        WS.say('ws-add-msg', WS.T('Databases are being set up. Create becomes available here when they are ready.'), 'ok');
        refreshMissing(true);
      });
    });
  };

  // The host's database server is installed but stopped: start it (and enable it), then follow the dialog's line.
  window.wsDbStart = function (hostId) {
    WS.stepUp(function () {
      WS.say('ws-add-msg', WS.T('Starting the database server…'));
      WS.post('/api/remote/' + Number(hostId) + '/databases/start', {}).then(function (d) {
        if (!WS.done(d, 'ws-add-msg')) return;
        refreshMissing(true);
      });
    });
  };

  // Back to the form as it was filled in (the typed password is never kept), to change something and Create again.
  window.wsAddAgain = function () {
    clearTimeout(st.poll);
    WS.show('ws-progress-wrap', false);
    WS.show('ws-add-form', true);
    WS.show('ws-add-footer', true);
    WS.clear(WS.el('ws-result'));
    WS.renderMissing(st.d ? st.d.missing : []);
  };

  // From the add dialog's note (`where` 'add'): the dialog's host; from the proxy card: the card's own host.
  window.wsProxyInstall = function (where) {
    var host = where === 'add' ? val('ws-add-host-id') : val('wp-host');
    WS.stepUp(function () {
      WS.say('ws-add-msg', WS.T('Installing the web proxy…'));
      WS.post('/websites/proxy/install', {host_id: host || val('ws-add-host-id') || null}).then(function (d) {
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
      if (WS.customerDefaults) WS.customerDefaults(d);
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
  // A customer gets the sites ticked; only with "They may add their own websites" may they add more, up to the
  // number given (it starts at the superadmin's Sites per customer setting).
  var GRANT = ['view_websites', 'edit_website_files', 'manage_website'];
  WS.customerBody = function () {
    var ids = [];
    document.querySelectorAll('[data-wc-site]').forEach(function (cb) { if (cb.checked) ids.push(Number(cb.value)); });
    var body = {name: WS.el('wc-name').value.trim().toLowerCase(), sites: ids};
    var create = WS.el('wc-create');
    if (create && create.checked) {
      body.permissions = GRANT.concat(['create_websites']);
      body.max_sites = Number(WS.el('wc-max').value) || 1;
    }
    return body;
  };
  window.wsCustomerCreate = function () { var c = WS.el('wc-create'); WS.show('wc-max-wrap', !!(c && c.checked)); };
  WS.customerDefaults = function (d) {
    var max = WS.el('wc-max');
    if (max && d && d.customer_max_sites && max.dataset.typed !== '1') max.value = String(Number(d.customer_max_sites));
  };
  function showInvite(d) {
    var box = WS.clear(WS.el('wc-result'));
    WS.show(box, true);
    var p = WS.node('div', 'alert alert-info py-2 px-2 small mb-0');
    p.appendChild(WS.node('div', 'fw-semibold', WS.T('Send the customer this link and its code. Both are shown only this once:')));
    p.appendChild(WS.raw('code', 'ws-secret user-select-all', d.invite || ''));
    p.appendChild(WS.raw('code', 'ws-secret user-select-all', d.code || ''));
    if (d.invite_note) p.appendChild(WS.node('div', 'mt-1', d.invite_note));
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
