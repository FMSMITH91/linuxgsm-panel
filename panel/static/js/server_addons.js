// The Add-ons tab of a game server's Files & Config page (panel/routes/addons.py,
// templates/_server_addons.html). Loads when the tab is first opened, so the page itself asks nothing
// of the host. Every row is built with textContent: names, states and log lines come from the host.
// Install and remove are step-up routes: a sign-in past the confirmation window confirms the password
// in a dialog first (step_up_form.js's window.stepUpThen).
(function () {
  'use strict';
  var st = {d: null, loaded: false, busy: false, poll: null};
  var STATE = {
    active: 'Running', activating: 'Starting', deactivating: 'Stopping', inactive: 'Stopped',
    failed: 'Failed', reloading: 'Starting', unknown: 'State unknown'
  };

  function T(s) { return window.t ? window.t(s) : s; }
  function TF(s, v) { return window.tf ? window.tf(s, v) : s; }
  function el(id) { return document.getElementById(id); }
  function api(tail) { return MOUNT + '/api/server/' + serverId + '/addons' + (tail || ''); }
  function show(id, on) { var e = el(id); if (e) e.style.display = on ? '' : 'none'; }
  function node(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function say(text, cls) {
    var m = el('ad-msg');
    if (!m) return;
    m.textContent = text || '';
    m.className = 'small mt-1 ' + (cls || 'text-secondary');
  }
  function button(text, icon, action, args, cls) {
    var b = node('button', 'btn btn-sm ' + (cls || 'btn-outline-secondary'));
    b.type = 'button';
    var i = node('i');
    i.className = 'bi ' + icon;
    i.setAttribute('aria-hidden', 'true');
    b.appendChild(i);
    b.appendChild(document.createTextNode(' '));
    b.appendChild(node('span', null, text));
    b.setAttribute('data-action', action);
    b.setAttribute('data-args', JSON.stringify(args));
    return b;
  }
  function postJson(url, body) {
    return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})})
      .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, d: d || {}}; }); });
  }
  function stepUp(go) { if (window.stepUpThen) window.stepUpThen(go, window.STEP_UP_TOTP === true); else go(); }

  // The database select for an add-on that is not installed: this server's databases no other add-on uses.
  function dbSelect(a, dbs) {
    var sel = node('select', 'form-select form-select-sm fx-12');
    sel.id = 'ad-db-' + a.id;
    sel.setAttribute('aria-label', T('Database for the add-on'));
    sel.setAttribute('data-no-i18n', '');
    dbs.filter(function (d) { return !d.used_by; }).forEach(function (d) {
      var o = node('option', null, d.name);
      o.value = String(d.id);
      sel.appendChild(o);
    });
    return sel;
  }

  function installedRow(a, box) {
    if (a.database) box.appendChild(node('div', 'small text-secondary text-break', TF('Database {db}.', {db: a.database})));
    if (a.port) {
      box.appendChild(node('div', 'small text-secondary text-break',
        TF('Its web page: 127.0.0.1:{port} on this host (an SSH tunnel: ssh -L {port}:127.0.0.1:{port} <host>).', {port: a.port})));
    }
    if (a.geolocation_option) {
      box.appendChild(node('div', 'small text-secondary', a.geolocation ? T('Geolocation is on: players\' IP addresses go to ipwho.is.') : T('Geolocation is off.')));
    }
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-1');
    if (a.state === 'active') bar.appendChild(button(T('Stop'), 'bi-stop-circle', 'adAct', [a.id, 'stop']));
    else bar.appendChild(button(T('Start'), 'bi-play-circle', 'adAct', [a.id, 'start']));
    bar.appendChild(button(T('Log'), 'bi-journal-text', 'adLog', [a.id]));
    bar.appendChild(button(T('Remove'), 'bi-trash', 'adRemove', [a.id], 'btn-outline-danger'));
    box.appendChild(bar);
  }

  // The geolocation switch (B3): off unless ticked, with what it sends and to whom.
  function geoSwitch(a, box) {
    var wrap = node('div', 'form-check mt-1');
    var cb = node('input', 'form-check-input');
    cb.type = 'checkbox';
    cb.id = 'ad-geo-' + a.id;
    var lab = node('label', 'form-check-label small', T('Geolocation'));
    lab.htmlFor = cb.id;
    wrap.appendChild(cb);
    wrap.appendChild(lab);
    box.appendChild(wrap);
    box.appendChild(node('div', 'small text-secondary', T('Off unless you tick it. When on, B3 sends each joining player\'s IP address to ipwho.is to find their country and city, and shows them in the game (!locate and the join message).')));
  }

  function installRow(a, d, box) {
    if (a.legacy) {
      box.appendChild(node('div', 'small text-warning', T('Legacy, opt-in: B3 is an older admin bot, kept for Call of Duty, United Offensive and Call of Duty 2. It is built on this host from one pinned version of its source and runs as locked down as every add-on, but it gets fewer fixes than newer tools. Install it only if you want it.')));
    }
    var free = (d.databases || []).filter(function (x) { return !x.used_by; });
    if (a.needs_database && !free.length) {
      box.appendChild(node('div', 'small text-secondary', T('Add a database in the Databases tab first: this add-on needs one of its own.')));
      return;
    }
    if (a.geolocation_option) geoSwitch(a, box);
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-1');
    if (a.needs_database) bar.appendChild(dbSelect(a, d.databases || []));
    var b = button(T('Install'), 'bi-download', 'adInstall', [a.id], 'btn-primary');
    if (d.runtime_error || a.installing) b.disabled = true;
    bar.appendChild(b);
    box.appendChild(bar);
  }

  function addonRow(a, d) {
    var box = node('div', 'ad-row');
    var head = node('div', 'd-flex flex-wrap gap-2 align-items-center');
    var name = node('strong', null, a.name + ' ' + a.version);
    name.setAttribute('data-no-i18n', '');
    head.appendChild(name);
    var state = a.installing ? T('Installing…') : (a.installed ? T(STATE[a.state] || STATE.unknown) : T('Not installed'));
    var badge = a.state === 'active' ? 'badge text-bg-success' : 'badge text-bg-secondary';
    head.appendChild(node('span', badge, state));
    box.appendChild(head);
    if (a.error) box.appendChild(node('div', 'small text-danger', a.error));
    if (a.tail) {
      var pre = node('pre', 'small border rounded p-2 mt-1 mb-0 ad-log', a.tail);
      pre.setAttribute('data-no-i18n', '');
      box.appendChild(pre);
    }
    if (a.installed) installedRow(a, box);
    else if (!a.installing) installRow(a, d, box);
    return box;
  }

  function draw(d) {
    st.d = d;
    show('ad-loading', false);
    var rt = el('ad-runtime');
    rt.textContent = d.runtime_error || '';
    show('ad-runtime', !!d.runtime_error);
    var list = el('ad-list');
    list.textContent = '';
    (d.addons || []).forEach(function (a) { list.appendChild(addonRow(a, d)); });
    var busy = (d.addons || []).some(function (a) { return a.installing; });
    if (busy && !st.poll) {
      var until = Date.now() + 20 * 60000;   // an install's pull and first start finish well inside this
      st.poll = setInterval(function () {
        var still = st.d && (st.d.addons || []).some(function (a) { return a.installing; });
        if (Date.now() > until || !still) { clearInterval(st.poll); st.poll = null; return; }
        void window.adLoad(true);
      }, 5000);
    }
  }

  window.adLoad = function (force) {
    if (!el('ad-card') || (st.loaded && !force)) return Promise.resolve(false);
    st.loaded = true;
    return fetch(api(), {cache: 'no-store'}).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || d.success === false) { show('ad-loading', false); say((d && d.error) || T('Could not load add-ons.'), 'text-danger'); return false; }
      draw(d);
      return true;
    }).catch(function () { show('ad-loading', false); say(T('Could not load add-ons.'), 'text-danger'); return false; });
  };

  function after(res) {
    st.busy = false;
    var ok = res.ok && res.d.success !== false, text = (ok ? '✓ ' : '✗ ') + (res.d.message || res.d.error || T('Failed'));
    say(text, ok ? 'text-success' : 'text-danger');
    return window.adLoad(true).then(function () { say(text, ok ? 'text-success' : 'text-danger'); return ok; });
  }
  function failed() { st.busy = false; say('✗ ' + T('Could not reach the panel. Try again.'), 'text-danger'); return false; }

  function row(id) { return ((st.d && st.d.addons) || []).filter(function (a) { return a.id === id; })[0] || {}; }

  window.adInstall = function (id) {
    var a = row(id), sel = el('ad-db-' + id), geo = el('ad-geo-' + id), body = {};
    if (st.busy || (a.needs_database && (!sel || !sel.value))) return;
    if (a.needs_database) body.database_id = Number.parseInt(sel.value, 10);
    if (geo) body.geolocation = geo.checked === true;
    window.confirmDialog({title: T('Install the add-on'), icon: 'download', confirmClass: 'btn-primary', confirmLabel: T('Install'),
      bodyText: T('This installs Podman on the host if it is not there, readies the server\'s account for containers, and downloads or builds the add-on\'s image. The add-on reads the server\'s RCON password and game log.'),
      onConfirm: function () {
        stepUp(function () {
          st.busy = true;
          say(T('Installing the add-on…'));
          postJson(api('/' + id + '/install'), body).then(after).catch(failed);
        });
      }});
  };

  window.adAct = function (id, action) {
    if (st.busy) return;
    st.busy = true;
    say(action === 'stop' ? T('Stopping the add-on…') : T('Starting the add-on…'));
    postJson(api('/' + id + '/' + action), {}).then(after).catch(failed);
  };

  window.adRemove = function (id) {
    if (st.busy) return;
    window.confirmDialog({title: T('Remove the add-on'), icon: 'trash', confirmClass: 'btn-danger', confirmLabel: T('Remove'),
      bodyText: row(id).data_kept ? T('This stops the add-on and deletes its container, image and files, its settings included. Its database is kept.')
        : T('This stops the add-on and deletes its container, image and files: its settings and its data (players, statistics) too.'),
      onConfirm: function () {
        stepUp(function () {
          st.busy = true;
          say(T('Removing the add-on…'));
          postJson(api('/' + id + '/remove'), {}).then(after).catch(failed);
        });
      }});
  };

  window.adLog = function (id) {
    var pre = el('ad-log');
    say(T('Reading the add-on\'s log…'));
    return fetch(api('/' + id + '/logs'), {cache: 'no-store'}).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || d.success === false) { say((d && d.error) || T('Could not load the log.'), 'text-danger'); return false; }
      pre.textContent = d.log || '';
      show('ad-log', !!d.log);
      say(d.log ? '' : T('The log is empty.'));
      return true;
    }).catch(failed);
  };

  // Load when the tab is first opened (or the page opens on it).
  document.addEventListener('click', function (e) {
    if (e.target && e.target.closest && e.target.closest('[data-sfsub-btn="addons"]')) void window.adLoad(false); });
  window.addEventListener('hashchange', function () { if (location.hash === '#addons') void window.adLoad(false); });
  if (location.hash === '#addons') void window.adLoad(false);
})();
