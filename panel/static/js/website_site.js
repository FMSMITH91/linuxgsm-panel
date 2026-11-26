// One website's page (templates/website.html and its _website_*.html panels). Reads
// GET /api/websites/<id> (one probe, cached briefly by the server):
//   {success, site: {id, name, kind, state, state_reason, enabled, open_url, image: {name, version,
//      update_available}, app_version, php_version, runtime_version, last_backup, usage: {mem_mb, disk_mb,
//      cpu_pct}, limits: {mem_mb, cpu_milli, pids, disk_mb, max_body_mb, backup_keep}, access_log,
//      full_egress, customer_note}, install: {state, steps, error, site_url, admin_url},
//    logs: [last lines when failed], domains: [{id, domain, is_primary, dns_state, cert_state,
//      cert_not_after, cert_error}], dns: {a: [..], aaaa: [..]}, databases: [{id, name, user}], ...}
// The PHP, Performance, Rules and App panels (website_tuning.js) and Files (website_files.js) are fed
// from here through WS.onSite. Actions POST to /websites/<id>/<verb>; the page decides nothing the
// server does not check again (websites_access.site_for on every route).
(function () {
  'use strict';
  var WS = window.WS;
  var ROOT = WS.el('ws-site');
  if (!ROOT) return;
  var F = ROOT.dataset;
  var ID = Number(F.siteId);
  var st = {d: null, tab: 'overview', poll: null, hooks: []};
  WS.siteId = ID;
  WS.can = {manage: F.manage === '1', files: F.files === '1', admin: F.admin === '1', sup: F.super === '1'};
  WS.onSite = function (fn) { st.hooks.push(fn); if (st.d) fn(st.d); };
  WS.siteAct = function (verb, body, msgId) {
    return WS.post(WS.R.act(ID, verb), body).then(function (d) { var ok = WS.done(d, msgId); if (ok) WS.reload(); return d; });
  };

  // ── header: state, the main button (never hidden from someone who may use it), Open site ──
  var MAIN = {running: {label: 'Stop', icon: 'stop-fill', cls: 'btn-outline-danger', verb: 'stop'},
    stopped: {label: 'Start', icon: 'play-fill', cls: 'btn-success', verb: 'start'},
    failed: {label: 'Retry', icon: 'arrow-repeat', cls: 'btn-warning', verb: 'start'},
    creating: {label: 'Setting up…', icon: 'hourglass-split', cls: 'btn-secondary', verb: ''},
    removing: {label: 'Removing…', icon: 'hourglass-split', cls: 'btn-secondary', verb: ''}};
  function renderHead(s) {
    var dot = WS.el('ws-dot');
    if (dot) dot.className = WS.dot(s.state).className;
    WS.el('ws-state').textContent = WS.stateLabel(s.state);
    WS.el('ws-online').textContent = WS.T(s.enabled ? 'Online' : 'Offline');
    var open = WS.el('ws-open'), url = WS.safeUrl(s.open_url);
    if (open) { WS.show(open, !!url); if (url) open.href = url; }
    var b = WS.el('ws-main');
    if (!b) return;
    var m = WS.pick(MAIN, s.state, MAIN.creating);
    b.className = 'btn btn-sm ' + m.cls;
    b.disabled = !m.verb;
    b.dataset.verb = m.verb;
    WS.el('ws-main-icon').className = 'bi bi-' + m.icon;
    WS.el('ws-main-label').textContent = WS.T(m.label);
  }
  window.wsMain = function () {
    var b = WS.el('ws-main');
    var verb = b ? b.dataset.verb : 'start';
    if (!verb) return;
    if (verb === 'stop') {
      window.confirmDialog({title: WS.T('Stop this website?'), icon: 'stop-circle', confirmClass: 'btn-danger',
        confirmLabel: WS.T('Stop'), bodyText: WS.T('Visitors see an error until it is started again.'),
        onConfirm: function () { WS.siteAct('stop', {}, 'ws-msg'); }});
      return;
    }
    WS.say('ws-msg', WS.T('Starting…'));
    WS.siteAct(verb, {}, 'ws-msg');
  };
  window.wsRestart = function () { WS.say('ws-msg', WS.T('Restarting…')); WS.siteAct('restart', {}, 'ws-msg'); };
  window.wsUpdateImage = function () {
    WS.stepUp(function () { WS.say('ws-msg', WS.T('Updating…')); WS.siteAct('update-image', {}, 'ws-msg'); });
  };

  // A failed site leads with why, its last log lines and Retry: never an empty page.
  function renderFailed(d) {
    var failed = d.site.state === 'failed';
    WS.show('ws-failed', failed);
    if (!failed) return;
    WS.el('ws-failed-reason').textContent = d.site.state_reason || WS.T('No reason was recorded.');
    WS.el('ws-failed-log').textContent = (d.logs || []).slice(-20).join('\n') || WS.T('No log lines yet.');
  }
  function renderInstall(d) {
    var inst = d.install || {};
    var on = inst.state === 'running' || (d.site.state === 'creating' && (inst.steps || []).length > 0);
    WS.show('ws-install', on);
    if (on) WS.renderSteps(WS.el('ws-install-steps'), inst);
    return on;
  }

  // ── tabs: one panel at a time, picked by ?tab= ──
  window.wsTab = function (name) {
    var known = false;
    document.querySelectorAll('[data-ws-tab]').forEach(function (b) {
      var on = b.getAttribute('data-ws-tab') === name;
      known = known || on;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    if (!known) return window.wsTab('overview');
    st.tab = name;
    document.querySelectorAll('[data-ws-pane]').forEach(function (p) { p.hidden = p.getAttribute('data-ws-pane') !== name; });
    try { history.replaceState(null, '', '?tab=' + encodeURIComponent(name)); } catch (e) { /* the address bar is a nicety */ }
    if (name === 'files' && window.wsFilesOpen) window.wsFilesOpen();
    if (name === 'backups') loadBackups();
    return false;
  };

  // ── overview ──
  function setText(id, text) { var e = WS.el(id); if (e) e.textContent = text == null || text === '' ? '—' : String(text); }
  function meter(id, used, max, text) {
    var m = WS.el(id);
    if (!m) return;
    m.max = max > 0 ? max : 1;
    // Amber from 80 % of the limit and red from 95 %, as the disk warning works.
    m.low = m.max * 0.8;
    m.high = m.max * 0.95;
    m.optimum = 0;
    m.value = Math.max(0, Math.min(used || 0, m.max));
    setText(id + '-text', text);
  }
  function renderOverview(s) {
    setText('ws-ov-kind', WS.kindLabel(s.kind));
    var img = s.image || {};
    setText('ws-ov-image', [img.name, img.version].filter(Boolean).join(' '));
    var ver = s.app_version || s.php_version || s.runtime_version;
    setText('ws-ov-version', ver);
    setText('ws-ov-backup', s.last_backup || WS.T('None yet'));
    WS.show('ws-update', !!img.update_available);
    WS.show('ws-update-note', !!img.update_available);
    var u = s.usage || {}, l = s.limits || {};
    meter('ws-mem', u.mem_mb, l.mem_mb, u.mem_mb != null ? u.mem_mb + ' / ' + l.mem_mb + ' MB' : '');
    meter('ws-disk', u.disk_mb, l.disk_mb, u.disk_mb != null ? u.disk_mb + ' / ' + l.disk_mb + ' MB' : '');
    meter('ws-cpu', u.cpu_pct, 100, u.cpu_pct != null ? u.cpu_pct + ' %' : '');
  }
  window.wsLoadLogs = function () {
    WS.get(WS.R.act(ID, 'logs')).then(function (d) {
      WS.el('ws-logs').textContent = (d && d.lines && d.lines.length) ? d.lines.join('\n') : WS.T('No log lines yet.');
    });
  };

  // ── domains ──
  var DNS = {unchecked: 'DNS not checked yet', matching: 'DNS points here', mismatch: 'DNS points elsewhere',
    private: 'DNS points to a private address', failed: 'DNS check failed'};
  function domainRow(dm) {
    var li = WS.node('li', 'ws-row');
    var top = WS.node('div', 'd-flex flex-wrap gap-2 align-items-baseline');
    top.appendChild(WS.raw('strong', 'text-break', dm.domain));
    if (dm.is_primary) top.appendChild(WS.node('span', 'ws-chip', WS.T('Primary')));
    li.appendChild(top);
    var info = WS.node('div', 'small text-secondary');
    info.appendChild(WS.node('span', dm.dns_state === 'matching' ? 'text-success' : '', WS.T(WS.pick(DNS, dm.dns_state, DNS.unchecked))));
    info.appendChild(document.createTextNode(' · '));
    info.appendChild(WS.node('span', dm.cert_state === 'issued' ? 'text-success' : '', WS.T(WS.pick(WS.CERT, dm.cert_state, 'No certificate yet'))));
    if (dm.cert_not_after) info.appendChild(WS.raw('span', 'ms-1', '(' + dm.cert_not_after + ')'));
    li.appendChild(info);
    if (dm.cert_error) li.appendChild(WS.raw('div', 'small text-danger text-break', dm.cert_error));
    if (WS.can.manage) li.appendChild(domainButtons(dm));
    return li;
  }
  function domainButtons(dm) {
    var row = WS.node('div', 'd-flex flex-wrap gap-2 mt-1');
    row.appendChild(WS.button(WS.T('Check again'), 'arrow-repeat', 'wsDomain', ['check', Number(dm.id)]));
    if (!dm.is_primary) row.appendChild(WS.button(WS.T('Make primary'), 'star', 'wsDomain', ['primary', Number(dm.id)]));
    row.appendChild(WS.button(WS.T('Remove'), 'x-lg', 'wsDomain', ['remove', Number(dm.id)], 'btn-outline-danger'));
    return row;
  }
  function renderDomains(d) {
    var list = WS.clear(WS.el('wd-list'));
    var doms = d.domains || [];
    if (!doms.length) list.appendChild(WS.node('li', 'small text-secondary', WS.T('No domain yet. A site is reached by its domain once one points here.')));
    doms.forEach(function (dm) { list.appendChild(domainRow(dm)); });
    renderRecords(doms, d.dns || {});
  }
  function renderRecords(doms, dns) {
    var body = WS.clear(WS.el('wd-records'));
    var want = doms.filter(function (x) { return x.dns_state !== 'matching'; });
    var rows = [];
    want.forEach(function (x) {
      (dns.a || []).forEach(function (ip) { rows.push(['A', x.domain, ip]); });
      (dns.aaaa || []).forEach(function (ip) { rows.push(['AAAA', x.domain, ip]); });
    });
    WS.show('wd-dns', rows.length > 0);
    rows.forEach(function (r) {
      var tr = WS.node('tr');
      r.forEach(function (c) { tr.appendChild(WS.raw('td', 'text-break font-monospace', c)); });
      body.appendChild(tr);
    });
  }
  window.wsDomainAdd = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var inp = WS.el('wd-domain');
    WS.say('wd-msg', WS.T('Adding…'));
    WS.post(WS.R.act(ID, 'domains/add'), {domain: inp.value.trim()}).then(function (d) {
      if (WS.done(d, 'wd-msg')) { inp.value = ''; WS.reload(); }
    });
  };
  window.wsDomain = function (verb, domainId) {
    var go = function () {
      WS.say('wd-msg', WS.T('Working…'));
      WS.post(WS.R.act(ID, 'domains/' + verb), {id: domainId}).then(function (d) { if (WS.done(d, 'wd-msg')) WS.reload(); });
    };
    if (verb !== 'remove') { go(); return; }
    window.confirmDialog({title: WS.T('Remove this domain?'), icon: 'x-circle', confirmClass: 'btn-danger', confirmLabel: WS.T('Remove'),
      bodyText: WS.T('The site stops answering on it and its certificate is no longer renewed.'), onConfirm: go});
  };

  // ── database ──
  function renderDatabases(d) {
    var list = WS.el('wdb-list');
    if (!list) return;
    WS.clear(list);
    var dbs = d.databases || [];
    if (!dbs.length) list.appendChild(WS.node('li', 'small text-secondary', WS.T('No database yet.')));
    dbs.forEach(function (db) {
      var li = WS.node('li', 'ws-row d-flex flex-wrap gap-2 align-items-center justify-content-between');
      li.appendChild(WS.raw('span', 'fw-semibold text-break', db.name));
      li.appendChild(WS.button(WS.T('Show connection settings'), 'key', 'wsDbReveal', [Number(db.id)]));
      li.appendChild(WS.node('div', 'w-100 small font-monospace ws-db-conn', ''));
      li.lastChild.id = 'wdb-conn-' + Number(db.id);
      list.appendChild(li);
    });
  }
  window.wsDbAdd = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var inp = WS.el('wdb-name');
    WS.say('wdb-msg', WS.T('Creating…'));
    WS.post(WS.R.act(ID, 'databases/add'), {name: inp.value.trim()}).then(function (d) {
      if (WS.done(d, 'wdb-msg')) { inp.value = ''; WS.reload(); }
    });
  };
  window.wsDbReveal = function (dbId) {
    WS.stepUp(function () {
      WS.post(WS.R.act(ID, 'databases/credentials'), {id: dbId}).then(function (d) {
        var box = WS.el('wdb-conn-' + dbId);
        if (!box || !d || !d.success) { WS.done(d, 'wdb-msg'); return; }
        WS.clear(box);
        [['Host', d.host], ['Port', d.port], ['Database', d.name], ['User', d.user], ['Password', d.password]].forEach(function (kv) {
          var line = WS.node('div');
          line.appendChild(WS.node('span', 'text-secondary', WS.T(kv[0]) + ': '));
          line.appendChild(WS.raw('span', 'user-select-all', kv[1] == null ? '' : String(kv[1])));
          box.appendChild(line);
        });
      });
    });
  };

  // ── backups ──
  function backupRow(b) {
    var li = WS.node('li', 'ws-row');
    var top = WS.node('div', 'd-flex flex-wrap gap-2 align-items-baseline justify-content-between');
    top.appendChild(WS.raw('span', 'text-break fw-semibold', b.name));
    top.appendChild(WS.raw('span', 'small text-secondary', [b.when, b.size].filter(Boolean).join(' · ')));
    li.appendChild(top);
    var row = WS.node('div', 'd-flex flex-wrap gap-2 mt-1');
    if (WS.can.files) {
      var a = WS.node('a', 'btn btn-sm btn-outline-secondary');
      a.appendChild(WS.icon('download'));
      a.appendChild(WS.node('span', null, ' ' + WS.T('Download')));
      a.href = WS.url(WS.R.act(ID, 'backups/download') + '?name=' + encodeURIComponent(b.name));
      row.appendChild(a);
      row.appendChild(WS.button(WS.T('Restore'), 'arrow-counterclockwise', 'wsBackup', ['restore', String(b.name)], 'btn-outline-warning'));
    }
    if (WS.can.manage) row.appendChild(WS.button(WS.T('Delete'), 'trash', 'wsBackup', ['delete', String(b.name)], 'btn-outline-danger'));
    li.appendChild(row);
    return li;
  }
  function loadBackups() {
    var list = WS.el('wb-list');
    if (!list) return;
    WS.get(WS.R.act(ID, 'backups/list')).then(function (d) {
      WS.clear(list);
      var rows = (d && d.backups) || [];
      if (d && d.keep) WS.el('wb-keep').textContent = WS.TF('The newest {n} are kept.', {n: d.keep});
      if (!rows.length) list.appendChild(WS.node('li', 'small text-secondary', (d && d.success === false && d.message) || WS.T('No backups yet.')));
      rows.forEach(function (b) { list.appendChild(backupRow(b)); });
    });
  }
  window.wsBackupNow = function () {
    WS.say('wb-msg', WS.T('Backing up…'));
    WS.post(WS.R.act(ID, 'backups/create'), {}).then(function (d) { if (WS.done(d, 'wb-msg')) loadBackups(); });
  };
  var BACKUP_ASK = {
    restore: {title: 'Restore this backup?', body: 'The site stops, a safety backup is taken, then its files and databases are put back as they were.', label: 'Restore', cls: 'btn-warning'},
    'delete': {title: 'Delete this backup?', body: 'It cannot be brought back.', label: 'Delete', cls: 'btn-danger'}};
  window.wsBackup = function (verb, name) {
    var ask = WS.pick(BACKUP_ASK, verb, null);
    if (!ask) return;
    window.confirmDialog({title: WS.T(ask.title), icon: 'archive', confirmClass: ask.cls, confirmLabel: WS.T(ask.label),
      bodyText: WS.T(ask.body), onConfirm: function () {
        WS.stepUp(function () {
          WS.say('wb-msg', WS.T('Working…'));
          WS.post(WS.R.act(ID, 'backups/' + verb), {name: name}).then(function (d) { if (WS.done(d, 'wb-msg')) loadBackups(); });
        });
      }});
  };

  // ── settings (administrators) ──
  function renderSettings(s) {
    var b = WS.el('wset-online');
    if (!b) return;
    b.textContent = WS.T(s.enabled ? 'Take offline' : 'Put online');
    b.dataset.verb = s.enabled ? 'disable' : 'enable';
    WS.el('wset-online-text').textContent = WS.T(s.enabled ? 'This site is online.' : 'This site is offline: the web proxy does not serve it.');
    var l = s.limits || {};
    document.querySelectorAll('[data-limit]').forEach(function (inp) {
      var v = l[inp.getAttribute('data-limit')];
      if (v != null) inp.value = String(v);
    });
    WS.el('wset-log').checked = !!s.access_log;
    WS.el('wset-egress').checked = !!s.full_egress;
    WS.el('wset-note').value = s.customer_note || '';
    window.wsEgressCheck();
  }
  window.wsEgressCheck = function () { var e = WS.el('wset-egress'); WS.show('wset-egress-note', !!(e && e.checked)); };
  window.wsToggleOnline = function () {
    var b = WS.el('wset-online');
    WS.stepUp(function () { WS.siteAct(b.dataset.verb, {}, 'wset-msg'); });
  };
  window.wsSettingsSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var limits = {};
    document.querySelectorAll('[data-limit]').forEach(function (inp) {
      if (inp.value !== '') limits[inp.getAttribute('data-limit')] = Number(inp.value);
    });
    var body = {limits: limits, access_log: WS.el('wset-log').checked, full_egress: WS.el('wset-egress').checked,
      customer_note: WS.el('wset-note').value};
    WS.stepUp(function () { WS.say('wset-msg', WS.T('Saving…')); WS.siteAct('settings', body, 'wset-msg'); });
  };
  window.wsDelete = function () {
    window.confirmDialog({title: WS.T('Delete this website?'), icon: 'trash', confirmClass: 'btn-danger', confirmLabel: WS.T('Delete website'),
      bodyText: WS.T('Its files, backups and account are removed for good. Type the website name to confirm.'),
      requireText: F.name, requireLabel: WS.T('Website name'), onConfirm: function () {
        WS.stepUp(function () {
          WS.post(WS.R.act(ID, 'delete'), {confirm: F.name}).then(function (d) {
            if (WS.done(d, 'wset-msg')) location.href = WS.safePath(F.listUrl) || WS.url('/');
          });
        });
      }});
  };

  // ── load ──
  function render(d) {
    st.d = d;
    var s = d.site || {};
    renderHead(s);
    renderFailed(d);
    var installing = renderInstall(d);
    renderOverview(s);
    renderDomains(d);
    renderDatabases(d);
    renderSettings(s);
    st.hooks.forEach(function (fn) { fn(d); });
    clearTimeout(st.poll);
    if (installing || s.state === 'creating' || s.state === 'removing') st.poll = setTimeout(WS.reload, 3000);
  }
  WS.reload = function () {
    return WS.get(WS.R.site(ID)).then(function (d) {
      if (!d || d.success === false || !d.site) { WS.done(d, 'ws-msg'); return; }
      render(d);
    });
  };
  var q = /[?&]tab=([a-z]+)/.exec(location.search);
  window.wsTab(q ? q[1] : 'overview');
  WS.reload();
})();
