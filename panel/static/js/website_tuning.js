// A website's PHP, Performance, Rules and App panels (templates/_website_php.html, _website_performance.html,
// _website_rules.html, _website_app.html), fed by website_site.js (WS.onSite) from GET /api/websites/<id>:
//   php:  {versions: [{version, eol}], version, settings: {memory_limit, ..., display_errors}, custom}
//   perf: {opcache, opcache_memory_mb, opcache_revalidate_s, object_cache, object_cache_host,
//          object_cache_port, page_cache, page_cache_ttl, static_cache}
//   rules: [{type: redirect, from, to, code} | {type: header, name, value} | {type: deny, path}], raw_rules
//   app:  {versions: [..], version, build, start, port, env_names: [..]}
// and saved to POST /websites/<id>/{php, performance, cache/purge, rules, app}; GET php/effective reads
// what PHP really uses. The server validates every value again and has the last word; the checks here
// only say early what it will say. OWASP's PHP values (PHP Configuration Cheat Sheet, "php.ini") are
// printed beside the fields; a value outside one shows a note and is saved anyway.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId) return;
  var ID = WS.siteId;
  var st = {envNames: [], rules: []};

  // ── PHP ──
  function bytes(v) {
    var m = /^(-1|\d+)([KMG]?)$/i.exec(String(v || '').trim());
    if (!m) return null;
    if (m[1] === '-1') return Infinity;
    return Number(m[1]) * ({'': 1, K: 1024, M: 1048576, G: 1024 * 1024 * 1024})[m[2].toUpperCase()];   // bytes per unit
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
  function renderPhp(php) {
    var sel = WS.el('wphp-version');
    if (!sel || !php) return;
    WS.clear(sel);
    (php.versions || []).forEach(function (v) {
      var o = WS.node('option', null, String(v.version));
      o.value = String(v.version);
      sel.appendChild(o);
    });
    sel.value = php.version || '';
    var eol = WS.el('wphp-eol');
    WS.show(eol, !!php.eol_note);
    if (php.eol_note) eol.textContent = php.eol_note;
    var s = php.settings || {};
    document.querySelectorAll('[data-php]').forEach(function (inp) {
      var v = s[inp.getAttribute('data-php')];
      if (inp.type === 'checkbox') inp.checked = !!v; else inp.value = v == null ? '' : String(v);
    });
    WS.el('wphp-ini').value = php.custom || '';
    window.wsPhpCheck();
    window.wsIniCheck();
  }
  window.wsPhpSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!window.wsIniCheck()) { WS.say('wphp-msg', WS.T('Fix the Advanced php.ini lines first.'), 'err'); return; }
    var settings = {};
    document.querySelectorAll('[data-php]').forEach(function (inp) {
      settings[inp.getAttribute('data-php')] = inp.type === 'checkbox' ? inp.checked : inp.value.trim();
    });
    WS.say('wphp-msg', WS.T('Saving…'));
    WS.post(WS.R.act(ID, 'php'), {version: WS.el('wphp-version').value, settings: settings, custom: WS.el('wphp-ini').value})
      .then(function (d) { WS.done(d, 'wphp-msg'); });
  };
  window.wsPhpEffective = function () {
    WS.get(WS.R.act(ID, 'php/effective')).then(function (d) {
      var body = WS.clear(WS.el('wphp-eff-rows'));
      var vals = (d && d.values) || {};
      var keys = Object.keys(vals).sort();
      if (!keys.length) {
        var tr0 = WS.node('tr');
        tr0.appendChild(WS.node('td', 'text-secondary', (d && d.message) || WS.T('PHP did not answer. Is the site running?')));
        body.appendChild(tr0);
      }
      keys.forEach(function (k) {
        var tr = WS.node('tr');
        tr.appendChild(WS.raw('td', 'font-monospace', k));
        tr.appendChild(WS.raw('td', 'font-monospace text-break', String(vals[k])));
        body.appendChild(tr);
      });
    });
  };

  // ── Performance ──
  function setPerf(p) {
    if (!p || !WS.el('wperf-page')) return;
    var map = {'wperf-opcache': p.opcache, 'wperf-obj': p.object_cache, 'wperf-page': p.page_cache, 'wperf-static': p.static_cache};
    Object.keys(map).forEach(function (id) { var e = WS.el(id); if (e) e.checked = !!map[id]; });
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
  window.wsPerfSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var body = {opcache: checked('wperf-opcache'), opcache_memory_mb: num('wperf-op-mem'), opcache_revalidate_s: num('wperf-op-reval'),
      object_cache: checked('wperf-obj'), page_cache: checked('wperf-page'), page_cache_ttl: num('wperf-ttl'), static_cache: checked('wperf-static')};
    WS.say('wperf-msg', WS.T('Saving…'));
    WS.post(WS.R.act(ID, 'performance'), body).then(function (d) {
      if (WS.done(d, 'wperf-msg')) { st.perfDone = false; WS.reload(); }
    });
  };
  window.wsPurge = function () {
    WS.say('wperf-msg', WS.T('Purging…'));
    WS.post(WS.R.act(ID, 'cache/purge'), {}).then(function (d) { WS.done(d, 'wperf-msg'); });
  };

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
  function renderApp(app) {
    var sel = WS.el('wapp-version');
    if (!sel || !app) return;
    WS.clear(sel);
    (app.versions || []).forEach(function (v) { var o = WS.node('option', null, String(v)); o.value = String(v); sel.appendChild(o); });
    sel.value = app.version || '';
    WS.el('wapp-port').value = app.port == null ? '' : String(app.port);
    WS.el('wapp-build').value = app.build || '';
    WS.el('wapp-start').value = app.start || '';
    st.envNames = (app.env_names || []).slice();
    var box = WS.clear(WS.el('wapp-env'));
    st.envNames.forEach(function (n) { box.appendChild(envRow(n, true)); });
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
  window.wsAppSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var envs = WS.envBody();
    var body = {runtime_version: WS.el('wapp-version').value, app_port: num('wapp-port'), build_command: WS.el('wapp-build').value.trim(),
      start_command: WS.el('wapp-start').value.trim(), env: envs.env, env_remove: envs.env_remove};
    WS.say('wapp-msg', WS.T('Saving and rebuilding…'));
    WS.post(WS.R.act(ID, 'app'), body).then(function (d) {
      Array.prototype.slice.call(document.querySelectorAll('[data-env="value"]')).forEach(function (v) { v.value = ''; });
      if (WS.done(d, 'wapp-msg')) WS.reload();
    });
  };

  // Each panel is filled once, from the first answer: a status poll while the site starts must not
  // overwrite what is being typed.
  function renderRulesOnce(d) {
    st.rules = (d.rules || []).map(function (r) { return Object.assign({}, r); });
    WS.renderRules();
    var raw = WS.el('wr-raw');
    if (raw && d.raw_rules != null) raw.value = d.raw_rules;
  }
  // [flag, the answer's key, what fills the panel]: each runs once its part of the answer is there.
  var FILL = [['phpDone', 'php', renderPhp], ['perfDone', 'perf', setPerf], ['appDone', 'app', renderApp]];
  WS.onSite(function (d) {
    FILL.forEach(function (f) {
      if (!st[f[0]] && d[f[1]]) { f[2](d[f[1]]); st[f[0]] = true; }
    });
    if (WS.el('wr-list') && !st.rulesDone) { renderRulesOnce(d); st.rulesDone = true; }
  });
})();
