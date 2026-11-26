// The web proxy card on the Websites list (templates/_website_proxy.html), superadmin only. Fed by the
// same GET /api/websites answer as the list (websites.js calls wsProxyRender):
//   proxies: [{host_id, host_name, installed, version, exposure_mode, allow_cidrs: [..],
//              allow_presets: [..], tunnel_token_set, last_error}],
//   options: {hsts_max_age, tls_min, acme_contact, acme_staging, access_log_default, access_log_days,
//             max_sites, require_2fa, mem_mb, cpu_milli, pids, disk_mb, max_body_mb}
// Saves go to POST /websites/proxy/settings as {host_id, exposure: {...}} or {options: {...}}. The tunnel
// token is sent only when something was typed, and the page never receives it back (tunnel_token_set).
// OWASP's recommended values are printed beside the fields; a value outside them shows a note and is
// saved anyway: the administrator decides (HTTP Strict Transport Security Cheat Sheet, "Examples";
// Transport Layer Security Cheat Sheet, "Only Support Strong Protocols"; Multifactor Authentication
// Cheat Sheet).
(function () {
  'use strict';
  var WS = window.WS;
  var st = {proxies: [], host: null, presets: []};
  var HSTS_OWASP = 63072000;

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
  function renderCf() {
    var on = st.presets.indexOf('cloudflare') >= 0;
    var b = WS.el('wp-cf');
    if (b) {
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.className = 'btn btn-sm ' + (on ? 'btn-secondary' : 'btn-outline-secondary');
    }
    var s = WS.el('wp-cf-state');
    if (s) s.textContent = on ? WS.T("Cloudflare's networks are on the list (from the signed catalog). Tap again to remove them.") : '';
  }
  function stateLine(p) {
    var e = WS.el('wp-state');
    if (!e) return;
    WS.show('wp-install', !p.installed);
    if (!p.installed) { e.textContent = WS.T('The web proxy is not installed on this host yet. Sites cannot go online until it is.'); return; }
    e.textContent = WS.TF('Web proxy {version} is installed.', {version: p.version || '?'});
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
    renderCf();
    var c = WS.el('wp-cidrs');
    if (c) c.value = (p.allow_cidrs || []).join('\n');
    var tok = WS.el('wp-token');
    if (tok) tok.value = '';
    WS.show('wp-token-state', !!p.tunnel_token_set);
  }
  function setVal(id, v) {
    var e = WS.el(id);
    if (!e || v == null) return;
    if (e.type === 'checkbox') e.checked = !!v; else e.value = String(v);
  }
  var OPT_FIELDS = {hsts_max_age: 'wp-hsts', tls_min: 'wp-tls', acme_contact: 'wp-acme-email', acme_staging: 'wp-staging',
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
  };
  window.wsProxyHost = function () { var s = WS.el('wp-host'); st.host = s ? s.value : null; renderHost(); };
  window.wsExposure = function (mode) { setMode(mode); };
  window.wsCfPreset = function () {
    var i = st.presets.indexOf('cloudflare');
    if (i >= 0) st.presets.splice(i, 1); else st.presets.push('cloudflare');
    renderCf();
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
    }
    if (m === 'tunnel') {
      body.tunnel_provider = 'cloudflare';
      var tok = WS.el('wp-token').value.trim();
      if (tok) body.tunnel_token = tok;
    }
    return body;
  };
  function exposureProblem(body) {
    if (body.exposure_mode === 'restricted' && !body.allow_presets.length && !body.allow_cidrs.length) {
      return WS.T("List at least one network, or use Cloudflare's networks.");
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
      WS.post(WS.R.proxySettings, {host_id: st.host, exposure: body}).then(function (d) {
        var tok = WS.el('wp-token');
        if (tok) tok.value = '';
        if (WS.done(d, 'wp-msg') && WS.loadList) WS.loadList();
      });
    });
  };
  // The notes beside the OWASP values: shown when a value is outside the recommendation, never a block.
  window.wsOptCheck = function () {
    var h = WS.el('wp-hsts'), tls = WS.el('wp-tls'), mfa = WS.el('wp-2fa');
    WS.show('wp-hsts-note', !!(h && h.value !== '' && Number(h.value) < HSTS_OWASP));
    WS.show('wp-tls-note', !!(tls && tls.value === '1.2'));
    WS.show('wp-2fa-note', !!(mfa && !mfa.checked));
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
      WS.post(WS.R.proxySettings, {options: out}).then(function (d) { WS.done(d, 'wp-opts-msg'); });
    });
  };
})();
