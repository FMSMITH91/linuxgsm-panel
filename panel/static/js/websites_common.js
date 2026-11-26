// Shared helpers of the Websites pages (templates/websites.html and website.html): window.WS.
// Every value from the server (a site's name, a domain, a file name, a log line) reaches the page
// through textContent or an attribute, never innerHTML (OWASP Cross Site Scripting Prevention Cheat
// Sheet, "Safe Sinks"), so a hostile name stays text. Element names are constants. Controls carry
// data-action/data-args for panel.js's dispatcher: no inline handler, which the page's nonce-only
// policy would refuse anyway. A link the server hands back (a site's address, an app's admin page) is
// used only when it is http(s), so no javascript: address can become a link.
(function () {
  'use strict';
  var WS = {};
  // The routes the pages call (panel/routes/websites*.py). One place, so a renamed route is one edit.
  WS.R = {
    list: '/api/websites',
    site: function (id) { return '/api/websites/' + id; },
    act: function (id, verb) { return '/websites/' + id + '/' + verb; },
    add: '/websites/add',
    installApp: '/websites/install-app',
    proxyInstall: '/websites/proxy/install',
    proxySettings: '/websites/proxy/settings',
    proxyStatus: function (rid) { return '/websites/proxy/status?remote_id=' + encodeURIComponent(rid); },
    proxyOptions: '/websites/proxy/options',
    page: function (id) { return '/websites/' + id; }
  };
  // A byte count and a Unix time as the lists show them (the host sends numbers, never text).
  WS.size = function (n) {
    n = Number(n);
    if (!isFinite(n) || n < 0) return '';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : String(n)) + ' ' + units[i];
  };
  WS.when = function (t) {
    t = Number(t);
    if (!isFinite(t) || t <= 0) return '';
    var d = new Date(t * 1000), p = function (x) { return (x < 10 ? '0' : '') + x; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  };
  WS.T = function (s) { return window.t ? window.t(s) : s; };
  WS.TF = function (s, v) { return window.tf ? window.tf(s, v) : s; };
  WS.el = function (id) { return document.getElementById(id); };
  WS.url = function (path) { return (window.MOUNT || '') + path; };
  WS.node = function (tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  // A value someone typed or a host reported: text the translator must leave alone.
  WS.raw = function (tag, cls, text) {
    var e = WS.node(tag, cls, text);
    e.setAttribute('data-no-i18n', '');
    return e;
  };
  WS.icon = function (name) {
    var i = WS.node('i', 'bi bi-' + name);
    i.setAttribute('aria-hidden', 'true');
    return i;
  };
  WS.clear = function (e) { while (e && e.firstChild) e.removeChild(e.firstChild); return e; };
  WS.show = function (id, on) { var e = typeof id === 'string' ? WS.el(id) : id; if (e) e.hidden = !on; };
  WS.button = function (text, icon, action, args, cls) {
    var b = WS.node('button', 'btn btn-sm ' + (cls || 'btn-outline-secondary'));
    b.type = 'button';
    if (icon) { b.appendChild(WS.icon(icon)); b.appendChild(document.createTextNode(' ')); }
    b.appendChild(WS.node('span', null, text));
    b.setAttribute('data-action', action);
    if (args && args.length) b.setAttribute('data-args', JSON.stringify(args));
    return b;
  };
  WS.say = function (id, text, kind) {
    var m = WS.el(id);
    if (!m) return;
    m.textContent = text || '';
    m.className = 'small mt-1 ' + (kind === 'ok' ? 'text-success' : kind === 'err' ? 'text-danger' : 'text-secondary');
  };
  WS.safeUrl = function (u) {
    return (typeof u === 'string' && /^https?:\/\/[^\s/]/i.test(u)) ? u : '';
  };
  // A same-origin panel path the server suggests (a fix for a missing precondition): /x, never //x.
  WS.safePath = function (p) {
    return (typeof p === 'string' && /^\/(?![/\\])[\w\-./?=&#]*$/.test(p)) ? p : '';
  };
  function answer(r) {
    return r.json().catch(function () { return {success: false, message: WS.T('The panel sent an answer it could not read.')}; });
  }
  function failed() { return {success: false, message: WS.T('The panel could not be reached. Check the connection and try again.')}; }
  WS.get = function (path) {
    return fetch(WS.url(path), {cache: 'no-store'}).then(answer, failed);
  };
  WS.post = function (path, body) {
    return fetch(WS.url(path), {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body || {})}).then(answer, failed);
  };
  WS.postForm = function (path, fd) {
    return fetch(WS.url(path), {method: 'POST', body: fd}).then(answer, failed);
  };
  // A high-risk action asks for the password again first when the sign-in is old (step_up_form.js).
  WS.stepUp = function (go) { if (window.stepUpThen) window.stepUpThen(go, window.STEP_UP_TOTP === true); else go(); };
  WS.toast = function (msg, kind) { if (window.toast) window.toast(msg, kind || 'info'); };
  WS.done = function (d, msgId) {
    var ok = !!(d && d.success);
    var text = (d && d.message) || (ok ? WS.T('Saved.') : WS.T('That did not work. Nothing was changed.'));
    if (msgId) WS.say(msgId, text, ok ? 'ok' : 'err'); else WS.toast(text, ok ? 'success' : 'danger');
    return ok;
  };

  window.WS = WS;
})();

// The words for states and kinds, the install steps, and the php.ini line check.
(function () {
  'use strict';
  var WS = window.WS;
  WS.STATE = {creating: 'Setting up', running: 'Running', stopped: 'Stopped', failed: 'Failed',
    removing: 'Removing'};
  WS.KIND = {static: 'Plain site', php: 'PHP site', wordpress: 'WordPress', phpbb: 'phpBB forum',
    app: 'Node.js app'};
  WS.PHP_KINDS = {php: 1, wordpress: 1, phpbb: 1};
  WS.CERT = {issued: 'Certificate active', pending: 'Certificate pending', failed: 'Certificate failed'};
  // A map's own entry for a value the server sent, else the fallback ("constructor" is no state).
  WS.pick = function (map, key, fallback) {
    return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : fallback;
  };
  WS.stateLabel = function (s) { return WS.T(WS.pick(WS.STATE, s, 'State unknown')); };
  WS.kindLabel = function (k) { return WS.T(WS.pick(WS.KIND, k, 'Website')); };
  WS.dot = function (state) {
    var cls = state === 'running' ? 'status-online' : (state === 'failed' || state === 'stopped') ? 'status-offline' : 'status-unknown';
    var d = WS.node('span', 'status-dot ' + cls);
    d.setAttribute('aria-hidden', 'true');
    return d;
  };

  // The steps of an app install or a site being set up: one row each, with its state.
  var STEP_ICON = {done: 'check-circle-fill text-success', running: 'arrow-repeat ws-spin', failed: 'x-circle-fill text-danger',
    undone: 'arrow-counterclockwise text-secondary', pending: 'circle text-secondary'};
  var STEP_WORD = {done: 'Done', running: 'Working…', failed: 'Failed', undone: 'Undone', pending: 'Waiting'};
  // The recipe engine's step types (and the setup of a plain site), in plain words; a step the page
  // does not know shows the label the server sent.
  var STEP_LABEL = {account: 'Create the site account', database: 'Create the database',
    download: 'Download and check the app', config: 'Write the app settings', container: 'Start the site container',
    installer: 'Run the app installer', 'web-installer': 'Run the app installer', permissions: 'Set file permissions',
    harden: 'Remove the app installer', https: 'Turn on HTTPS'};
  WS.renderSteps = function (box, install) {
    WS.clear(box);
    var steps = (install && install.steps) || [];
    // A job that reports only where it is: that one step, in its state.
    if (!steps.length && install && install.step) {
      steps = [{key: install.step, state: install.state === 'running' ? 'running' : install.state === 'failed' ? 'failed' : 'done'}];
    }
    var ol = WS.node('ol', 'list-unstyled mb-0 ws-steps');
    steps.forEach(function (s) {
      var st = WS.pick(STEP_ICON, s.state, null) ? s.state : 'pending';
      var li = WS.node('li', 'ws-step ws-step-' + st);
      li.appendChild(WS.icon(STEP_ICON[st]));
      var known = Object.prototype.hasOwnProperty.call(STEP_LABEL, s.key) ? STEP_LABEL[s.key] : '';
      li.appendChild(known ? WS.node('span', 'ws-step-label', WS.T(known)) : WS.raw('span', 'ws-step-label', s.label || s.key || ''));
      li.appendChild(WS.node('span', 'small text-secondary ws-step-state', WS.T(STEP_WORD[st])));
      ol.appendChild(li);
    });
    box.appendChild(ol);
    return ol;
  };

  // The Advanced php.ini box, line by line, as the panel will judge it (the server checks again and
  // has the last word). Returns [{line, problem}] — empty when every line is acceptable.
  var INI_MAX = 8192;
  var INI_REFUSED = {extension: 1, zend_extension: 1, auto_prepend_file: 1, auto_append_file: 1, include_path: 1,
    open_basedir: 1, 'extension_dir': 1, expose_php: 1, allow_url_include: 1, 'sys_temp_dir': 1, 'upload_tmp_dir': 1};
  function iniLine(raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === ';') return '';
    if (line.charAt(0) === '[') return 'Sections are not used here: write key = value lines only.';
    var eq = line.indexOf('=');
    if (eq < 1) return 'Each line is key = value.';
    var key = line.slice(0, eq).trim().toLowerCase();
    if (!/^[a-z][a-z0-9_.]{0,63}$/.test(key)) return 'A setting name is letters, digits, dots and underscores.';
    if (WS.pick(INI_REFUSED, key, 0)) return 'This setting is managed by the panel and cannot be set here.';
    var val = line.slice(eq + 1).trim();
    if (/[\x00-\x1f]/.test(val) || val.length > 512) return 'The value is too long or has control characters.';
    return '';
  }
  WS.iniProblems = function (text) {
    var out = [];
    text = String(text == null ? '' : text);
    if (text.length > INI_MAX) return [{line: 0, problem: 'The box holds at most 8192 characters.'}];
    text.split('\n').forEach(function (raw, i) {
      var p = iniLine(raw);
      if (p) out.push({line: i + 1, problem: p});
    });
    return out;
  };
})();
