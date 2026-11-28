// The web proxy card on the Websites list (templates/_website_proxy.html), superadmin only. Fed by the
// same GET /api/websites answer as the list (websites.js calls wsProxyRender):
//   proxies: [{host_id, host_name, installed, version, exposure_mode, allow_cidrs: [..],
//              allow_presets: [..], tunnel_token_set, last_error}],
//   options: {hsts_max_age, tls_min, acme_contact, acme_staging, hsts_subdomains, hsts_preload, local_certs,
//             cache_build, access_log_default, access_log_days, max_sites, require_2fa, mem_mb, cpu_milli, pids,
//             disk_mb, max_body_mb}
// Saves go to POST /websites/proxy/settings {host_id, exposure: {...}} and /websites/proxy/options {options}. The tunnel
// token is sent only when something was typed, and the page never receives it back (tunnel_token_set).
// OWASP's recommended values are printed beside the fields; a value outside them shows a note and is
// saved anyway: the administrator decides (HTTP Strict Transport Security Cheat Sheet, "Examples";
// Transport Layer Security Cheat Sheet, "Only Support Strong Protocols"; Multifactor Authentication
// Cheat Sheet).
(function () {
  'use strict';
  var WS = window.WS;
  var st = {proxies: [], host: null, presets: []};
  var HSTS_OWASP = 2 * 365 * 24 * 60 * 60;   // OWASP's two years, in seconds

  function cur() {
    for (var i = 0; i < st.proxies.length; i++) if (String(st.proxies[i].host_id) === String(st.host)) return st.proxies[i];
    return st.proxies[0] || {};
  }
  function setMode(mode) {
    ['public', 'restricted', 'tunnel'].forEach(function (m) {
      var r = WS.el('wp-mode-' + m);
      if (r) r.checked = (m === mode);
    });
    WS.show('wp-restricted', mode === 'restricted');
    WS.show('wp-tunnel', mode === 'tunnel');
  }
  // The allow-list presets: each CDN's networks from the signed catalog, its elements (wp-<id>-...) and its source.
  var PRESETS = {
    cloudflare: {id: 'cf', sum: "Cloudflare's networks ({n})",
      src: 'Read from cloudflare.com/ips-v4 and /ips-v6 by a daily check, and updated by themselves with the signed catalog.'},
    fastly: {id: 'fastly', sum: "Fastly's networks ({n})",
      src: 'Read from api.fastly.com/public-ip-list by a daily check, and updated by themselves with the signed catalog. Fastly gives the visitor\'s address only for HTTPS visitors: turn on Force TLS for the service at Fastly.'}
  };
  // A pressed button (aria-pressed, filled) is a CDN whose networks are on the list.
  function renderPresets() {
    Object.keys(PRESETS).forEach(function (name) {
      var pressed = st.presets.indexOf(name) >= 0, b = WS.el('wp-' + PRESETS[name].id);
      if (b) {
        b.setAttribute('aria-pressed', pressed ? 'true' : 'false');
        b.className = 'btn btn-sm ' + (pressed ? 'btn-secondary' : 'btn-outline-secondary');
      }
      renderPresetList(name);
    });
  }
  // Every network a preset admits, from the signed catalog, and where they come from.
  function renderPresetList(name) {
    var p = PRESETS[name], info = (cur().preset_info || {})[name] || {}, ranges = info.ranges || [];
    var sum = WS.el('wp-' + p.id + '-sum');
    if (sum) sum.textContent = WS.TF(p.sum, {n: ranges.length});
    var src = WS.el('wp-' + p.id + '-src');
    if (src) {
      src.textContent = (info.issued ? WS.TF('From the signed catalog of {date}.', {date: info.issued}) : WS.T("From the panel's built-in catalog.")) + ' ' +
        WS.T(p.src);
    }
    var ul = WS.clear(WS.el('wp-' + p.id + '-ranges'));
    if (ul) ranges.forEach(function (r) { ul.appendChild(WS.node('li', null, String(r))); });
  }
  // The list read from an address: its networks, when it was read, and why the last read failed (the old list kept).
  function urlState(p, n) {
    var parts = [];
    if (p.allow_url && p.allow_url_at) parts.push(WS.TF('Read on {date}: {n} networks.', {date: p.allow_url_at, n: n}));
    if (p.allow_url_error) parts.push(WS.TF('The last read failed, so the list read before is kept: {why}', {why: p.allow_url_error}));
    if (p.allow_url && p.allow_url_on === false) parts.push(WS.T('Reading lists from an address is turned off in Settings, Outside services: this list is not read again.'));
    return parts.join(' ');
  }
  function renderUrl(p) {
    var u = WS.el('wp-url'), nets = p.allow_url_nets || [];
    if (u) u.value = p.allow_url || '';
    var sum = WS.el('wp-url-sum');
    if (sum) sum.textContent = p.allow_url ? WS.TF('A list from an address: {n} networks', {n: nets.length}) : WS.T('A list from an address');
    var s = WS.el('wp-url-state');
    if (s) s.textContent = urlState(p, nets.length);
    var ul = WS.clear(WS.el('wp-url-nets'));
    if (ul) nets.forEach(function (n) { ul.appendChild(WS.node('li', null, String(n))); });
  }
  function stateLine(p) {
    var e = WS.el('wp-state');
    if (!e) return;
    WS.show('wp-install', !p.installed);
    if (!p.installed) { e.textContent = WS.T('The web proxy is not installed on this host yet. Sites cannot go online until it is.'); return; }
    e.textContent = WS.TF('Web proxy: Caddy {version}, installed.', {version: p.version || '?'});
    if (p.last_error) e.appendChild(WS.raw('span', 'd-block text-danger', p.last_error));
  }
  var MODE_NAME = {public: 'Public', restricted: 'Restricted', tunnel: 'Tunnel'};
  function renderHost() {
    var p = cur();
    stateLine(p);
    var sum = WS.el('wp-mode-summary');
    if (sum) sum.textContent = WS.TF('How visitors reach your sites: {mode}', {mode: WS.T(WS.pick(MODE_NAME, p.exposure_mode, 'Public'))});
    st.presets = (p.allow_presets || []).slice();
    setMode(p.exposure_mode || 'public');
    renderPresets();
    var c = WS.el('wp-cidrs');
    if (c) c.value = (p.allow_cidrs || []).join('\n');
    renderUrl(p);
    var tr = WS.el('wp-custom-trusted');
    if (tr) tr.checked = !!p.custom_trusted;
    window.wsTrustCheck();
    var tok = WS.el('wp-token');
    if (tok) tok.value = '';
    WS.show('wp-token-state', !!p.tunnel_token_set);
    renderTools(p);
    renderGuard(p.guard || {});
  }
  // ── blocked visitors: the host's numbers, OWASP's words beside them (from the server), a note outside them ──
  var GUARD_FIELDS = {login: 'wp-guard-login', scan: 'wp-guard-scan', findtime: 'wp-guard-findtime',
    bantime: 'wp-guard-bantime', maxtime: 'wp-guard-maxtime'};
  function renderGuard(g) {
    if (!WS.el('wp-guard')) return;
    setVal('wp-guard-on', g.enabled !== false);
    setVal('wp-guard-increment', g.increment !== false);
    Object.keys(GUARD_FIELDS).forEach(function (k) { setVal(GUARD_FIELDS[k], g[k]); });
    Object.keys(g.owasp || {}).forEach(function (k) {
      var e = WS.el('wp-guard-' + k + '-owasp');
      if (e) e.textContent = String(g.owasp[k]);
    });
    var allow = WS.el('wp-guard-allow');
    if (allow) allow.value = (g.allow || []).join('\n');
    WS.show('wp-guard-f2b', g.fail2ban === 'absent');
    window.wsGuardCheck();
  }
  window.wsGuardCheck = function () {
    WS.show('wp-guard-on-note', switchOn('wp-guard-on') === false);
    WS.show('wp-guard-increment-note', switchOn('wp-guard-increment') === false);
    // OWASP's example of a fixed lockout is 10 minutes: a shorter first ban gets the note (it is still saved).
    var ban = WS.el('wp-guard-bantime'), mins = ban ? Number(String(ban.value || '').trim()) : NaN;
    WS.show('wp-guard-bantime-note', Number.isFinite(mins) && mins > 0 && mins < 10);
  };
  window.wsSaveGuard = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var body = {enabled: switchOn('wp-guard-on') === true, increment: switchOn('wp-guard-increment') === true,
      allow: (WS.el('wp-guard-allow').value || '').split('\n').map(function (s) { return s.trim(); }).filter(Boolean)};
    Object.keys(GUARD_FIELDS).forEach(function (k) { body[k] = String(WS.el(GUARD_FIELDS[k]).value || '').trim(); });
    WS.stepUp(function () {
      WS.say('wp-guard-msg', WS.T('Saving…'));
      WS.post('/websites/proxy/settings', {host_id: st.host, guard: body}).then(function (d) {
        if (WS.done(d, 'wp-guard-msg') && WS.loadList) WS.loadList();
      });
    });
  };
  function renderTools(p) {
    var svc = WS.el('wp-tunnel-service');
    if (svc) svc.textContent = p.tunnel_service || '';
    ['wp-check', 'wp-apply'].forEach(function (id) { var b = WS.el(id); if (b) b.disabled = !p.installed; });
  }
  // The proxy's state as the host reports it (version, running, the tunnel connector's state in tunnel mode).
  var ACTIVE = {active: 'running', inactive: 'stopped', failed: 'failed', activating: 'starting'};
  window.wsProxyStatus = function () {
    WS.say('wp-status', WS.T('Checking…'));
    WS.get('/websites/proxy/status?host_id=' + encodeURIComponent(st.host)).then(function (d) {
      if (!d || !d.status_ok) { WS.done(d, 'wp-status'); return; }
      var s = d.status || {}, parts = [WS.TF('Caddy {version}: {state}.', {version: s.version || '?', state: WS.T(WS.pick(ACTIVE, s.active, 'state unknown'))})];
      // A tunnel whose token Cloudflare refuses stays active (cloudflared retries for minutes): its log says so.
      var refused = d.exposure_mode === 'tunnel' && s.tunnel_link === 'refused';
      if (refused) parts.push(WS.T("Tunnel connector: Cloudflare refused its token, so no visitor gets through. Paste the tunnel's token again."));
      else if (d.exposure_mode === 'tunnel') parts.push(WS.TF('Tunnel connector: {state}.', {state: WS.T(WS.pick(ACTIVE, s.tunnel, 'state unknown'))}));
      parts.push(WS.TF('{n} websites online.', {n: d.online_sites || 0}));
      WS.say('wp-status', parts.join(' '), refused ? 'err' : 'ok');
    });
  };
  // Apply the host's configuration again (after a failure the card shows, or a change made on the host).
  window.wsProxyApply = function () {
    WS.say('wp-status', WS.T('Applying…'));
    WS.post('/websites/proxy/apply', {host_id: st.host}).then(function (d) { if (WS.done(d, 'wp-status') && WS.loadList) WS.loadList(); });
  };
  function setVal(id, v) {
    var e = WS.el(id);
    if (!e || v == null) return;
    if (e.type === 'checkbox') e.checked = !!v; else e.value = String(v);
  }
  var OPT_FIELDS = {hsts_max_age: 'wp-hsts', tls_min: 'wp-tls', acme_contact: 'wp-acme-email', acme_staging: 'wp-staging',
    hsts_subdomains: 'wp-hsts-sub', hsts_preload: 'wp-hsts-preload', local_certs: 'wp-local-certs', cache_build: 'wp-cache-build',
    access_log_default: 'wp-log-default', access_log_days: 'wp-log-days', max_sites: 'wp-max-sites', require_2fa: 'wp-2fa',
    mem_mb: 'wp-mem', cpu_milli: 'wp-cpu', pids: 'wp-pids', disk_mb: 'wp-disk', max_body_mb: 'wp-body'};
  window.wsProxyRender = function (d) {
    st.proxies = d.proxies || [];
    var sel = WS.el('wp-host');
    if (sel && !sel.options.length) {
      st.proxies.forEach(function (p) {
        var o = WS.node('option', null, p.host_name || String(p.host_id));
        o.value = String(p.host_id);
        sel.appendChild(o);
      });
    }
    WS.show('wp-host-wrap', st.proxies.length > 1);
    if (st.host == null && st.proxies.length) st.host = st.proxies[0].host_id;
    renderHost();
    var o = d.options || {};
    Object.keys(OPT_FIELDS).forEach(function (k) { setVal(OPT_FIELDS[k], o[k]); });
    window.wsOptCheck();
    foldedSections();
  };
  function foldedSections() {
    var sum = WS.el('wp-opts-sum');
    if (sum) sum.textContent = WS.TF('Security settings: {n} settings', {n: Object.keys(OPT_FIELDS).length});
    // A link to a folded section (from a site's page) opens it, so the setting it points at is in view.
    var hash = String((window.location && window.location.hash) || '');
    if (hash === '#wp-opts-box' || hash === '#wp-mode-box') { var box = WS.el(hash.slice(1)); if (box) box.open = true; }
  };
  window.wsProxyHost = function () { var s = WS.el('wp-host'); st.host = s ? s.value : null; renderHost(); };
  window.wsExposure = function (mode) { setMode(mode); };
  // Trusting the operator's networks lets anyone on them choose the visitor's address the sites see: a note, never a block.
  window.wsTrustCheck = function () { WS.show('wp-custom-trusted-note', switchOn('wp-custom-trusted') === true); };
  window.wsPreset = function (name) {
    if (!PRESETS[name]) return;
    var i = st.presets.indexOf(name);
    if (i >= 0) st.presets.splice(i, 1); else st.presets.push(name);
    renderPresets();
  };
  function mode() {
    var m = 'public';
    ['restricted', 'tunnel'].forEach(function (x) { var r = WS.el('wp-mode-' + x); if (r && r.checked) m = x; });
    return m;
  }
  WS.exposureBody = function () {
    var m = mode();
    var body = {exposure_mode: m};
    if (m === 'restricted') {
      body.allow_presets = st.presets.slice();
      body.allow_cidrs = (WS.el('wp-cidrs').value || '').split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
      body.allow_url = (WS.el('wp-url').value || '').trim();
      body.custom_trusted = switchOn('wp-custom-trusted') === true;
    }
    if (m === 'tunnel') {
      body.tunnel_provider = 'cloudflare';
      var tok = WS.el('wp-token').value.trim();
      if (tok) body.tunnel_token = tok;
    }
    return body;
  };
  function exposureProblem(body) {
    if (body.exposure_mode === 'restricted' && !body.allow_presets.length && !body.allow_cidrs.length && !body.allow_url) {
      return WS.T("List at least one network, or use a CDN's networks.");
    }
    if (body.exposure_mode === 'tunnel' && !body.tunnel_token && !cur().tunnel_token_set) return WS.T('Paste the tunnel token first.');
    return '';
  }
  window.wsSaveExposure = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var body = WS.exposureBody();
    var problem = exposureProblem(body);
    if (problem) { WS.say('wp-msg', problem, 'err'); return; }
    WS.stepUp(function () {
      WS.say('wp-msg', WS.T('Saving…'));
      WS.post('/websites/proxy/settings', {host_id: st.host, exposure: body}).then(function (d) {
        var tok = WS.el('wp-token');
        if (tok) tok.value = '';
        if (WS.done(d, 'wp-msg') && WS.loadList) WS.loadList();
      });
    });
  };
  // The notes beside the OWASP values: shown when a value is outside the recommendation, never a block.
  // A switch's state: true (on), false (off), or null when the card has no such switch.
  function switchOn(id) {
    var e = WS.el(id);
    return e ? !!e.checked : null;
  }
  window.wsOptCheck = function () {
    var h = WS.el('wp-hsts'), tls = WS.el('wp-tls');
    var sub = switchOn('wp-hsts-sub'), pre = switchOn('wp-hsts-preload');
    WS.show('wp-hsts-note', !!(h && h.value !== '' && Number(h.value) < HSTS_OWASP));
    WS.show('wp-tls-note', !!(tls && tls.value === '1.3'));
    WS.show('wp-2fa-note', switchOn('wp-2fa') === false);
    WS.show('wp-hsts-sub-note', sub === false);
    WS.show('wp-hsts-preload-note', pre === false);
    WS.show('wp-hsts-preload-sub', pre === true && sub === false);
    WS.show('wp-local-certs-note', switchOn('wp-local-certs') === true);
  };
  window.wsSaveOptions = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var out = {};
    Object.keys(OPT_FIELDS).forEach(function (k) {
      var el = WS.el(OPT_FIELDS[k]);
      if (!el) return;
      if (el.type === 'checkbox') out[k] = el.checked;
      else if (el.type === 'number') out[k] = el.value === '' ? null : Number(el.value);
      else out[k] = el.value.trim();
    });
    WS.stepUp(function () {
      WS.say('wp-opts-msg', WS.T('Saving…'));
      WS.post('/websites/proxy/options', {options: out}).then(function (d) { WS.done(d, 'wp-opts-msg'); });
    });
  };
})();
