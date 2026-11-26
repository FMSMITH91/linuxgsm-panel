// A website's PHP, Performance, Rules and App panels (templates/_website_php.html, _website_performance.html,
// _website_rules.html, _website_app.html), filled once from the site's first answer (website_site.js,
// WS.onSite) and their own reads:
//   PHP:   GET/POST /websites/<id>/php ({version, versions, values, advanced, effective}; the form's fields
//          by their php.ini names, php_version only from an administrator), POST php/advanced {text}
//   Performance: POST performance {opcache, object_cache, page_cache, page_cache_ttl, static_cache},
//          POST cache/purge; OPcache's memory and interval are php.ini values (POST php)
//   Rules: POST rules {rules: [{type: redirect, from, to, code} | {type: header, name, value} |
//          {type: deny, path}], raw (a superadmin's page only)}
//   App:   POST app/settings (an administrator's page only), GET/POST app/env, POST app/build
// The server validates every value again and has the last word; the checks here only say early what it
// will say. OWASP's PHP values (PHP Configuration Cheat Sheet, "php.ini") are printed beside the fields;
// a value outside one shows a note and is saved anyway.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId) return;
  var ID = WS.siteId;
  var st = {};

  // ── PHP ──
  function bytes(v) {
    var m = /^(-1|\d+)([KMG]?)$/i.exec(String(v || '').trim());
    if (!m) return null;
    if (m[1] === '-1') return Infinity;
    return Number(m[1]) * ({'': 1, K: 1024, M: 1048576, G: 1073741824})[m[2].toUpperCase()];
  }
  WS.phpNotes = function () {
    var notes = [];
    document.querySelectorAll('[data-owasp]').forEach(function (inp) {
      var rec = inp.getAttribute('data-owasp'), v = inp.value;
      if (v === '') return;
      var over = inp.type === 'number' ? Number(v) > Number(rec) : bytes(v) > bytes(rec);
      if (over) notes.push(WS.TF("{key} is above OWASP's {value}. It is still saved.", {key: inp.getAttribute('data-php'), value: rec}));
    });
    var de = WS.el('wphp-display_errors');
    if (de && de.checked) notes.push(WS.T('display_errors is on: visitors can see error details. OWASP recommends Off. It is still saved.'));
    return notes;
  };
  window.wsPhpCheck = function () {
    var box = WS.clear(WS.el('wphp-notes'));
    if (!box) return;
    WS.phpNotes().forEach(function (n) { box.appendChild(WS.node('div', null, n)); });
  };
  window.wsIniCheck = function () {
    var box = WS.clear(WS.el('wphp-ini-problems'));
    var probs = WS.iniProblems(WS.el('wphp-ini').value);
    probs.slice(0, 10).forEach(function (p) {
      box.appendChild(WS.node('li', null, p.line ? WS.TF('Line {n}: {problem}', {n: p.line, problem: WS.T(p.problem)}) : WS.T(p.problem)));
    });
    return probs.length === 0;
  };
  // GET /websites/<id>/php: {version, versions, values, advanced, owasp, owasp_notes, effective}. The
  // version list is only an administrator's to change (the server refuses anyone else); a runner sees it.
  var OPCACHE = {'wperf-op-mem': 'opcache.memory_consumption', 'wperf-op-reval': 'opcache.revalidate_freq'};
  function versionsOf(php) {
    return (php.versions || []).map(function (v) { return String(v && typeof v === 'object' ? v.version : v); });
  }
  function fillValues(values) {
    document.querySelectorAll('[data-php]').forEach(function (inp) {
      var v = values[inp.getAttribute('data-php')];
      if (inp.type === 'checkbox') inp.checked = v === true || v === 'On'; else inp.value = v == null ? '' : String(v);
    });
    Object.keys(OPCACHE).forEach(function (id) {
      var e = WS.el(id), v = values[OPCACHE[id]];
      if (e && v != null && v !== '') e.value = String(v);
    });
  }
  function renderVersion(php) {
    var sel = WS.el('wphp-version');
    if (sel) {
      WS.clear(sel);
      versionsOf(php).forEach(function (v) { var o = WS.node('option', null, v); o.value = v; sel.appendChild(o); });
      sel.value = php.version || '';
    }
    var txt = WS.el('wphp-version-text');
    if (txt) txt.textContent = php.version || '—';
    var eol = WS.el('wphp-eol');
    WS.show(eol, !!php.eol_note);
    if (php.eol_note) eol.textContent = php.eol_note;
  }
  function renderPhp(php) {
    if (!php || !WS.el('wphp-form')) return;
    st.php = php;
    renderVersion(php);
    fillValues(php.settings || php.values || {});
    st.ini = php.custom != null ? php.custom : (php.advanced || '');
    WS.el('wphp-ini').value = st.ini;
    window.wsPhpCheck();
    window.wsIniCheck();
  }
  // The form as the server reads it: each field by its php.ini name, display_errors as On or Off, and
  // the version only when an administrator changed it.
  WS.phpBody = function () {
    var body = {};
    document.querySelectorAll('[data-php]').forEach(function (inp) {
      var v = inp.type === 'checkbox' ? (inp.checked ? 'On' : 'Off') : inp.value.trim();
      if (v !== '') body[inp.getAttribute('data-php')] = v;
    });
    var sel = WS.el('wphp-version');
    if (sel && st.php && sel.value && sel.value !== st.php.version) body.php_version = sel.value;
    return body;
  };
  window.wsPhpSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!window.wsIniCheck()) { WS.say('wphp-msg', WS.T('Fix the Advanced php.ini lines first.'), 'err'); return; }
    var ini = WS.el('wphp-ini').value;
    WS.say('wphp-msg', WS.T('Saving…'));
    WS.post(WS.R.act(ID, 'php'), WS.phpBody()).then(function (d) {
      if (!d || !d.success || ini === st.ini) { WS.done(d, 'wphp-msg'); return; }
      WS.post(WS.R.act(ID, 'php/advanced'), {text: ini}).then(function (d2) { if (WS.done(d2, 'wphp-msg')) st.ini = ini; });
    });
  };
  function showEffective(vals, message) {
    var body = WS.clear(WS.el('wphp-eff-rows'));
    var keys = Object.keys(vals || {}).sort();
    if (!keys.length) {
      var tr0 = WS.node('tr');
      tr0.appendChild(WS.node('td', 'text-secondary', message || WS.T('PHP did not answer. Is the site running?')));
      body.appendChild(tr0);
    }
    keys.forEach(function (k) {
      var tr = WS.node('tr');
      tr.appendChild(WS.raw('td', 'font-monospace', k));
      tr.appendChild(WS.raw('td', 'font-monospace text-break', String(vals[k])));
      body.appendChild(tr);
    });
  }
  // What PHP really uses: read again each time the section is opened (the answer to GET .../php).
  window.wsPhpEffective = function () {
    WS.get(WS.R.act(ID, 'php')).then(function (d) {
      showEffective((d && (d.effective || d.values)) || {}, d && d.success === false ? d.message : '');
    });
  };

  // ── Performance ──
  // The site's switches (opcache, object_cache, page_cache, page_cache_ttl, static_cache) from the
  // site's answer; a field the answer does not carry leaves the control as it is.
  function setPerf(p) {
    if (!p || !WS.el('wperf-page')) return;
    var map = {'wperf-opcache': p.opcache, 'wperf-obj': p.object_cache, 'wperf-page': p.page_cache, 'wperf-static': p.static_cache};
    Object.keys(map).forEach(function (id) { var e = WS.el(id); if (e && map[id] !== undefined) e.checked = !!map[id]; });
    var nums = {'wperf-op-mem': p.opcache_memory_mb, 'wperf-op-reval': p.opcache_revalidate_s, 'wperf-ttl': p.page_cache_ttl};
    Object.keys(nums).forEach(function (id) { var e = WS.el(id); if (e && nums[id] != null) e.value = String(nums[id]); });
    var info = WS.el('wperf-obj-info');
    if (info) {
      WS.clear(info);
      WS.show(info, !!(p.object_cache && p.object_cache_host));
      if (p.object_cache && p.object_cache_host) {
        info.appendChild(WS.node('div', null, WS.T('For WordPress, enter these in its object-cache plugin:')));
        info.appendChild(WS.raw('code', 'user-select-all', p.object_cache_host + ':' + p.object_cache_port));
      }
    }
  }
  function checked(id) { var e = WS.el(id); return e ? e.checked : undefined; }
  function num(id) { var e = WS.el(id); return e && e.value !== '' ? Number(e.value) : undefined; }
  // The switches go to /performance (the object cache only from an administrator's page, which alone
  // has it); OPcache's memory and check interval are php.ini values, so they go to /php.
  WS.perfBodies = function () {
    var perf = {opcache: checked('wperf-opcache'), object_cache: checked('wperf-obj'), page_cache: checked('wperf-page'),
      page_cache_ttl: num('wperf-ttl'), static_cache: checked('wperf-static')};
    Object.keys(perf).forEach(function (k) { if (perf[k] === undefined) delete perf[k]; });
    var php = {};
    Object.keys(OPCACHE).forEach(function (id) { var v = num(id); if (v !== undefined) php[OPCACHE[id]] = String(v); });
    return {perf: perf, php: php};
  };
  window.wsPerfSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var b = WS.perfBodies();
    WS.say('wperf-msg', WS.T('Saving…'));
    WS.post(WS.R.act(ID, 'performance'), b.perf).then(function (d) {
      if (!d || !d.success || !Object.keys(b.php).length) { if (WS.done(d, 'wperf-msg')) WS.reload(); return; }
      WS.post(WS.R.act(ID, 'php'), b.php).then(function (d2) { if (WS.done(d2, 'wperf-msg')) WS.reload(); });
    });
  };
  window.wsPurge = function () {
    WS.say('wperf-msg', WS.T('Purging…'));
    WS.post(WS.R.act(ID, 'cache/purge'), {}).then(function (d) { WS.done(d, 'wperf-msg'); });
  };

  // PHP: the answer's `php`, else its own GET (a PHP site's page only).
  function loadPhp(d) {
    if (d.php) { renderPhp(d.php); return; }
    if (!WS.el('wphp-form')) return;
    WS.get(WS.R.act(ID, 'php')).then(function (php) { if (php && php.success !== false) renderPhp(php); });
  }
  // [flag, what fills the panel from the answer]: each runs once, when the first answer arrives.
  var FILL = [['phpDone', loadPhp], ['perfDone', function (d) { setPerf(d.perf || d.site); }]];
  WS.onSite(function (d) {
    FILL.forEach(function (f) {
      if (!st[f[0]]) { st[f[0]] = true; f[1](d); }
    });
  });
})();

// The Rules and App panels.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId) return;
  var ID = WS.siteId;
  var st = {envNames: [], rules: []};
  function num(id) { var e = WS.el(id); return e && e.value !== '' ? Number(e.value) : undefined; }
  // ── Rules ──
  var RULE = {
    redirect: {title: 'Redirect', fields: [['from', 'From path', '/old-page'], ['to', 'To address or path', '/new-page']]},
    header: {title: 'Response header', fields: [['name', 'Header name', 'X-Frame-Options'], ['value', 'Value', 'SAMEORIGIN']]},
    deny: {title: 'Blocked path', fields: [['path', 'Path', '/private']]}};
  function ruleField(i, key, label, example, value) {
    var wrap = WS.node('div', 'flex-grow-1 minw-0');
    var id = 'wr-' + i + '-' + key;
    var lab = WS.node('label', 'form-label small mb-0', WS.T(label));
    lab.htmlFor = id;
    var inp = WS.node('input', 'form-control form-control-sm font-monospace');
    inp.id = id;
    inp.type = 'text';
    inp.maxLength = 512;
    inp.placeholder = example;
    inp.setAttribute('data-no-i18n', '');
    inp.setAttribute('data-rule', String(i));
    inp.setAttribute('data-key', key);
    inp.value = value == null ? '' : String(value);
    wrap.appendChild(lab);
    wrap.appendChild(inp);
    return wrap;
  }
  function codeSelect(i, value) {
    var sel = WS.node('select', 'form-select form-select-sm fx-9');
    sel.setAttribute('aria-label', WS.T('Redirect code'));
    sel.setAttribute('data-rule', String(i));
    sel.setAttribute('data-key', 'code');
    sel.setAttribute('data-no-i18n', '');
    ['301', '302', '307', '308'].forEach(function (c) { var o = WS.node('option', null, c); o.value = c; sel.appendChild(o); });
    sel.value = String(value || 301);
    return sel;
  }
  function ruleRow(r, i) {
    var spec = WS.pick(RULE, r.type, null);
    if (!spec) return null;
    var row = WS.node('div', 'ws-rule');
    row.appendChild(WS.node('div', 'small fw-semibold', WS.T(spec.title)));
    var fields = WS.node('div', 'd-flex flex-wrap gap-2 align-items-end');
    spec.fields.forEach(function (fd) { fields.appendChild(ruleField(i, fd[0], fd[1], fd[2], r[fd[0]])); });
    if (r.type === 'redirect') fields.appendChild(codeSelect(i, r.code));
    var rm = WS.button('', 'x-lg', 'wsRuleRemove', [i], 'btn-outline-danger');
    rm.setAttribute('aria-label', WS.T('Remove this rule'));
    fields.appendChild(rm);
    row.appendChild(fields);
    return row;
  }
  function readRules() {
    document.querySelectorAll('[data-rule]').forEach(function (inp) {
      var r = st.rules[Number(inp.getAttribute('data-rule'))];
      if (r) r[inp.getAttribute('data-key')] = inp.getAttribute('data-key') === 'code' ? Number(inp.value) : inp.value.trim();
    });
    return st.rules;
  }
  WS.renderRules = function () {
    var box = WS.clear(WS.el('wr-list'));
    if (!box) return;
    st.rules.forEach(function (r, i) { var row = ruleRow(r, i); if (row) box.appendChild(row); });
    WS.show('wr-empty', !st.rules.length);
  };
  window.wsRuleAdd = function (type) {
    readRules();
    st.rules.push({type: type});
    WS.renderRules();
  };
  window.wsRuleRemove = function (i) {
    readRules();
    st.rules.splice(i, 1);
    WS.renderRules();
  };
  window.wsRulesSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var body = {rules: readRules()};
    var raw = WS.el('wr-raw');
    if (raw) body.raw = raw.value;
    WS.say('wr-msg', WS.T('Checking and saving…'));
    WS.post(WS.R.act(ID, 'rules'), body).then(function (d) { WS.done(d, 'wr-msg'); });
  };

  // ── App (Node.js) ──
  function envRow(name, saved) {
    var row = WS.node('div', 'd-flex flex-wrap gap-2 mb-1 ws-env');
    var n = WS.node('input', 'form-control form-control-sm font-monospace fx-12');
    n.type = 'text';
    n.maxLength = 64;
    n.value = name || '';
    n.setAttribute('aria-label', WS.T('Variable name'));
    n.setAttribute('data-env', 'name');
    n.setAttribute('autocomplete', 'off');
    if (saved) { n.readOnly = true; n.setAttribute('data-saved', '1'); }
    var v = WS.node('input', 'form-control form-control-sm font-monospace fx-14');
    v.type = 'password';
    v.setAttribute('aria-label', WS.T('Value'));
    v.setAttribute('data-env', 'value');
    v.setAttribute('autocomplete', 'off');
    v.placeholder = saved ? WS.T('Saved: leave empty to keep') : '';
    var rm = WS.button('', 'x-lg', 'wsEnvRemove', ['@self'], 'btn-outline-danger');
    rm.setAttribute('aria-label', WS.T('Remove this variable'));
    row.appendChild(n);
    row.appendChild(v);
    row.appendChild(rm);
    return row;
  }
  // The app's settings from the site's answer (`app` {versions, version, build, start, port}, or the
  // site's own runtime_version, build_command, start_command, app_port); the variable names from
  // GET /websites/<id>/app/env {names}, never their values.
  function appOf(d) {
    if (d.app) return d.app;
    var s = d.site || {};
    if (s.kind !== 'app') return null;
    return {versions: s.runtime_versions || (s.runtime_version ? [s.runtime_version] : []), version: s.runtime_version,
      build: s.build_command, start: s.start_command, port: s.app_port, env_names: null};
  }
  function renderEnv(names) {
    st.envNames = (names || []).slice();
    var box = WS.clear(WS.el('wapp-env'));
    if (box) st.envNames.forEach(function (n) { box.appendChild(envRow(n, true)); });
  }
  function setIf(id, v) { var e = WS.el(id); if (e && v != null) e.value = String(v); }
  function renderApp(app) {
    if (!app || !WS.el('wapp-form')) return;
    var sel = WS.el('wapp-version');
    if (sel) {
      WS.clear(sel);
      (app.versions || []).forEach(function (v) { var o = WS.node('option', null, String(v)); o.value = String(v); sel.appendChild(o); });
      sel.value = app.version || '';
    }
    setIf('wapp-port', app.port);
    setIf('wapp-build', app.build);
    setIf('wapp-start', app.start);
    if (app.env_names) { renderEnv(app.env_names); return; }
    WS.get(WS.R.act(ID, 'app/env')).then(function (d) { renderEnv((d && d.names) || []); });
  }
  window.wsEnvAdd = function () { WS.el('wapp-env').appendChild(envRow('', false)); };
  window.wsEnvRemove = function (btn) { var row = btn && btn.closest ? btn.closest('.ws-env') : null; if (row) row.remove(); };
  WS.envBody = function () {
    var env = {}, seen = {};
    var box = WS.el('wapp-env');
    Array.prototype.slice.call(box ? box.children : []).forEach(function (row) {
      var name = row.querySelector('[data-env="name"]').value.trim();
      var value = row.querySelector('[data-env="value"]').value;
      if (!name) return;
      seen[name] = 1;
      env[name] = value === '' && row.querySelector('[data-saved]') ? null : value;
    });
    var removed = st.envNames.filter(function (n) { return !seen[n]; });
    return {env: env, env_remove: removed};
  };
  // An administrator's page also has the version, commands and port (POST app/settings); then the
  // variables (POST app/env: a saved one left empty is null, keep it; env_remove drops one) and a build.
  function appSettings() {
    if (!WS.el('wapp-version')) return null;
    return {runtime_version: WS.el('wapp-version').value, app_port: num('wapp-port'), build_command: WS.el('wapp-build').value.trim(),
      start_command: WS.el('wapp-start').value.trim()};
  }
  function step(path, body) {
    return function (prev) {
      if (prev && !prev.success) return prev;
      return body ? WS.post(WS.R.act(ID, path), body) : prev;
    };
  }
  window.wsAppSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    WS.say('wapp-msg', WS.T('Saving and rebuilding…'));
    Promise.resolve(null).then(step('app/settings', appSettings())).then(step('app/env', WS.envBody()))
      .then(step('app/build', {})).then(function (d) {
        Array.prototype.slice.call(document.querySelectorAll('[data-env="value"]')).forEach(function (v) { v.value = ''; });
        if (WS.done(d, 'wapp-msg')) { st.appDone = false; WS.reload(); }
      }).catch(function () { WS.done(null, 'wapp-msg'); });
  };

  // The rules from the answer's `rules` / `raw_rules`, or the site's own custom_rules (JSON text) and
  // raw_proxy_snippet.
  function rulesOf(d) {
    var r = d.rules || (d.site || {}).custom_rules || [];
    if (typeof r === 'string') { try { r = JSON.parse(r); } catch (e) { r = []; } }
    return Array.isArray(r) ? r : [];
  }
  function renderRulesOnce(d) {
    st.rules = rulesOf(d).map(function (r) { return Object.assign({}, r); });
    WS.renderRules();
    var raw = WS.el('wr-raw'), text = d.raw_rules != null ? d.raw_rules : (d.site || {}).raw_proxy_snippet;
    if (raw && text != null) raw.value = text;
  }
  // Each panel is filled once, from the first answer: a status poll while the site starts must not
  // overwrite what is being typed.
  var FILL = [['appDone', function (d) { renderApp(appOf(d)); }], ['rulesDone', function (d) { if (WS.el('wr-list')) renderRulesOnce(d); }]];
  WS.onSite(function (d) {
    FILL.forEach(function (f) {
      if (!st[f[0]]) { st[f[0]] = true; f[1](d); }
    });
  });
})();
