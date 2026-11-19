// The Add-ons tab of a game server's Files & Config page (panel/routes/addons.py,
// templates/_server_addons.html). Loads when the tab is first opened, so the page itself asks nothing
// of the host. Every row is built with textContent: names, states and log lines come from the host.
// Install and remove are step-up routes: a sign-in past the confirmation window confirms the password
// in a dialog first (step_up_form.js's window.stepUpThen).
(function () {
  'use strict';
  var st = {d: null, loaded: false, busy: false, poll: null, watch: false};
  var STATE = {
    active: 'Running', activating: 'Starting', deactivating: 'Stopping', inactive: 'Stopped',
    failed: 'Failed', reloading: 'Starting', unknown: 'State unknown'
  };
  var JOB = {install: 'Installing…', update: 'Updating…', settings: 'Applying settings…'};

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
    if (a.geolocation_option) geoStatus(a, box);
    if (a.update) {
      box.appendChild(node('div', 'small text-warning', a.update === 'geoip'
        ? T('Update available: a newer month of the country database.') : T('Update available: a newer version of the add-on.')));
    }
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-1');
    if (a.state === 'active') bar.appendChild(button(T('Stop'), 'bi-stop-circle', 'adAct', [a.id, 'stop']));
    else bar.appendChild(button(T('Start'), 'bi-play-circle', 'adAct', [a.id, 'start']));
    if (a.update) bar.appendChild(button(T('Update'), 'bi-arrow-up-circle', 'adUpdate', [a.id], 'btn-outline-primary'));
    bar.appendChild(button(T('Log'), 'bi-journal-text', 'adLog', [a.id]));
    bar.appendChild(button(T('Remove'), 'bi-trash', 'adRemove', [a.id], 'btn-outline-danger'));
    box.appendChild(bar);
    if (a.geolocation_option) settingsFold(a, box);
  }

  var GEO_SAID = {off: 'Geolocation is off.',
    offline: 'Geolocation is offline: each player\'s country, from DB-IP\'s database on this host. No player address leaves the host.',
    online: 'Geolocation is online: players\' IP addresses go to ipwho.is, which answers with their city.'};
  function geoStatus(a, box) {
    box.appendChild(node('div', 'small text-secondary', T(GEO_SAID[a.geolocation] || GEO_SAID.off)));
    if (a.geolocation === 'offline') {
      if (a.geoip_off) box.appendChild(node('div', 'small text-warning', a.geoip_off));
      if (a.geoip) box.appendChild(node('div', 'small text-secondary', TF('Country database: {month}.', {month: a.geoip})));
      creditLine(a, box);
    }
  }
  function creditLine(a, box) {
    var c = node('div', 'small text-secondary', a.credit || '');
    c.setAttribute('data-no-i18n', '');
    box.appendChild(c);
  }

  // The geolocation choice (B3), at install and in its settings: off unless chosen.
  function geoSelect(a, id, value) {
    var wrap = node('div', 'mt-1');
    var lab = node('label', 'form-label small mb-0', T('Geolocation'));
    lab.htmlFor = id;
    var sel = node('select', 'form-select form-select-sm fx-12');
    sel.id = id;
    [['off', T('Off')], ['offline', T('Offline: country')], ['online', T('Online: city')]].forEach(function (o) {
      var opt = node('option', null, o[1]);
      opt.value = o[0];
      if (o[0] === (value || 'off')) opt.selected = true;
      sel.appendChild(opt);
    });
    wrap.appendChild(lab);
    wrap.appendChild(sel);
    wrap.appendChild(node('div', 'small text-secondary', T('Offline looks each player\'s country up in DB-IP\'s free database: the panel\'s host downloads it from db-ip.com once a month, and no player address is sent anywhere. Online sends each joining player\'s IP address to ipwho.is for their city. Either shows it in the game (!locate and the join message).')));
    // Offline with DB-IP's download turned off (Outside services): said here, before it is chosen.
    if (a.geoip_off) wrap.appendChild(node('div', 'small text-warning', a.geoip_off));
    return wrap;
  }

  // B3's settings, folded: geolocation and its plugins. Apply rewrites only those in b3.ini and restarts it.
  function settingsFold(a, box) {
    var fold = node('details', 'mt-2');
    fold.appendChild(node('summary', 'small', T('B3 settings')));
    fold.appendChild(geoSelect(a, 'ad-set-geo-' + a.id, a.geolocation));
    var grid = node('div', 'd-flex flex-wrap gap-2 mt-2');
    var on = a.plugins || [];
    (a.switchable || []).concat(a.geo_switchable || []).forEach(function (p) {
      var w = node('div', 'form-check small');
      var cb = node('input', 'form-check-input');
      cb.type = 'checkbox';
      cb.id = 'ad-plug-' + a.id + '-' + p;
      cb.value = p;
      cb.checked = on.indexOf(p) >= 0;
      cb.setAttribute('data-ad-plugin', a.id);
      var l = node('label', 'form-check-label', p + ((a.geo_switchable || []).indexOf(p) >= 0 ? ' ' + T('(needs geolocation)') : ''));
      l.htmlFor = cb.id;
      w.appendChild(cb);
      w.appendChild(l);
      grid.appendChild(w);
    });
    fold.appendChild(node('div', 'small text-secondary mt-2', T('B3\'s plugins. Admin is always on.')));
    fold.appendChild(grid);
    ownPlugins(a, fold);
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-2');
    bar.appendChild(button(T('Apply and restart'), 'bi-check2-circle', 'adSettings', [a.id], 'btn-primary'));
    fold.appendChild(bar);
    fold.appendChild(node('div', 'small text-secondary mt-1', T('Only these settings are rewritten in b3.ini; your other edits there and in its conf folder are kept.')));
    box.appendChild(fold);
  }

  // The operator's own plugins folder: off unless turned on; the warning sits beside the switch.
  function ownWarn() { return T('A plugin in this folder is someone else\'s code: it runs inside B3\'s container, with B3\'s database and RCON access, and the panel doesn\'t check it. Load only plugins you trust. The folder is mounted read-only, and the container keeps its other limits.'); }
  function ownPlugins(a, fold) {
    var w = node('div', 'form-check small mt-2');
    var cb = node('input', 'form-check-input');
    cb.type = 'checkbox';
    cb.id = 'ad-own-' + a.id;
    cb.checked = !!a.own_plugins;
    var l = node('label', 'form-check-label', TF('Load my own plugins from the add-on\'s {dir} folder', {dir: a.own_plugins_dir || 'Data/extplugins'}));
    l.htmlFor = cb.id;
    w.appendChild(cb);
    w.appendChild(l);
    fold.appendChild(w);
    fold.appendChild(node('div', 'small text-warning', ownWarn()));
  }

  // An add-on that needs a database while the server has none free: Install shows, disabled, with why
  // beside it, and a button to the Databases tab when this viewer has that tab. A host with no
  // database server yet is named, since the Databases tab then offers to set one up first.
  function noDatabaseRow(a, d, box) {
    var bar = node('div', 'd-flex flex-wrap gap-2 align-items-center mt-1');
    var b = button(T('Install'), 'bi-download', 'adInstall', [a.id], 'btn-primary');
    b.disabled = true;
    var why = node('span', 'small text-secondary', d.db_host === 'none'
      ? T('This host has no database server yet. Set one up in the Databases tab, then add a database there: this add-on needs one of its own.')
      : T('Add a database in the Databases tab first: this add-on needs one of its own.'));
    why.id = 'ad-why-' + a.id;
    b.setAttribute('aria-describedby', why.id);
    bar.appendChild(b);
    bar.appendChild(why);
    if (document.querySelector('[data-sfsub-btn="databases"]')) {
      bar.appendChild(button(T('Open Databases'), 'bi-database', 'adOpenDatabases', []));
    }
    box.appendChild(bar);
  }

  // What a row says before Install: the legacy warning and the game's own note.
  function installNotes(a, box) {
    if (a.legacy) {
      box.appendChild(node('div', 'small text-warning', T('Legacy, opt-in: B3 is an older admin bot, kept for Call of Duty, United Offensive, Call of Duty 2, Call of Duty 4, World at War, Soldier of Fortune 2 and Wolfenstein: Enemy Territory. It is built on this host from one pinned version of its source and runs as locked down as every add-on, but it gets fewer fixes than newer tools. Install it only if you want it.')));
    }
    if (a.note) box.appendChild(node('div', 'small text-secondary', a.note));
  }

  function installRow(a, d, box) {
    installNotes(a, box);
    var free = (d.databases || []).filter(function (x) { return !x.used_by; });
    if (a.needs_database && !free.length) { noDatabaseRow(a, d, box); return; }
    if (a.geolocation_option) box.appendChild(geoSelect(a, 'ad-geo-' + a.id, 'off'));
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-1');
    if (a.needs_database) bar.appendChild(dbSelect(a, d.databases || []));
    var b = button(T('Install'), 'bi-download', 'adInstall', [a.id], 'btn-primary');
    if (d.runtime_error || a.installing) b.disabled = true;
    bar.appendChild(b);
    box.appendChild(bar);
  }

  function stateWord(a) {
    if (a.installing) return T(JOB[a.job] || JOB.install);
    return a.installed ? T(STATE[a.state] || STATE.unknown) : T('Not installed');
  }

  function rowHead(a) {
    var head = node('div', 'd-flex flex-wrap gap-2 align-items-center');
    var name = node('strong', null, a.name + ' ' + a.version);
    name.setAttribute('data-no-i18n', '');
    head.appendChild(name);
    head.appendChild(node('span', a.state === 'active' ? 'badge text-bg-success' : 'badge text-bg-secondary', stateWord(a)));
    return head;
  }

  function addonRow(a, d) {
    var box = node('div', 'ad-row');
    box.appendChild(rowHead(a));
    if (a.error) box.appendChild(node('div', 'small text-danger', a.error));
    if (a.tail) {
      var pre = node('pre', 'small border rounded p-2 mt-1 mb-0 ad-log', a.tail);
      pre.setAttribute('data-no-i18n', '');
      box.appendChild(pre);
    }
    if (a.installed && a.note) box.appendChild(node('div', 'small text-secondary', a.note));
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
    // An install this page started has ended: its "Installing the add-on" line goes, and the row says
    // how it went (installed, or the error in red), so no green line stays beside a failure.
    if (st.watch && !busy) { st.watch = false; say(''); }
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
    var started = ok && res.d.started === true;
    st.watch = started;
    say(text, ok ? 'text-success' : 'text-danger');
    return window.adLoad(true).then(function () {
      if (!started || st.watch) say(text, ok ? 'text-success' : 'text-danger');   // unless the install already ended
      return ok;
    });
  }
  function failed() { st.busy = false; say('✗ ' + T('Could not reach the panel. Try again.'), 'text-danger'); return false; }

  function row(id) { return ((st.d && st.d.addons) || []).filter(function (a) { return a.id === id; })[0] || {}; }

  window.adInstall = function (id) {
    var a = row(id), sel = el('ad-db-' + id), geo = el('ad-geo-' + id), body = {};
    if (st.busy || (a.needs_database && (!sel || !sel.value))) return;
    if (a.needs_database) body.database_id = Number.parseInt(sel.value, 10);
    if (geo) body.geolocation = geo.value;
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
      bodyText: row(id).data_kept ? T('This stops the add-on and deletes its container, image and folder: its settings and any plugin settings you edited go with it. Its database is kept in the Databases tab.')
        : T('This stops the add-on and deletes its container, image and files: its settings and its data (players, statistics) too.'),
      onConfirm: function () {
        stepUp(function () {
          st.busy = true;
          say(T('Removing the add-on…'));
          postJson(api('/' + id + '/remove'), {}).then(after).catch(failed);
        });
      }});
  };

  window.adUpdate = function (id) {
    if (st.busy) return;
    window.confirmDialog({title: T('Update the add-on'), icon: 'arrow-up-circle', confirmClass: 'btn-primary', confirmLabel: T('Update'),
      bodyText: T('This downloads or builds the add-on\'s new image and restarts it. Its data, settings and database are kept.'),
      onConfirm: function () {
        stepUp(function () {
          st.busy = true;
          say(T('Updating the add-on…'));
          postJson(api('/' + id + '/update'), {}).then(after).catch(failed);
        });
      }});
  };

  window.adSettings = function (id) {
    var geo = el('ad-set-geo-' + id);
    if (st.busy || !geo) return;
    var plugins = Array.prototype.filter.call(document.querySelectorAll('[data-ad-plugin="' + id + '"]'),
      function (cb) { return cb.checked; }).map(function (cb) { return cb.value; });
    var own = el('ad-own-' + id), ownOn = !!(own && own.checked);
    var go = function () {
      stepUp(function () {
        st.busy = true;
        say(T('Applying the settings…'));
        postJson(api('/' + id + '/settings'), {geolocation: geo.value, plugins: plugins, own_plugins: ownOn}).then(after).catch(failed);
      });
    };
    // Turning the own-plugins folder on is asked once more, with the warning.
    if (ownOn && !row(id).own_plugins) {
      window.confirmDialog({title: T('Load your own B3 plugins'), icon: 'exclamation-triangle', confirmClass: 'btn-warning',
        confirmLabel: T('Turn on and restart'), bodyText: ownWarn(), onConfirm: go});
      return;
    }
    go();
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

  // The Databases tab, opened the way its own button in the page's section nav opens it
  // (server_files.js shows the section; server_databases.js loads it on that click).
  window.adOpenDatabases = function () {
    var b = document.querySelector('[data-sfsub-btn="databases"]');
    if (b) b.click();
    return !!b;
  };

  // Load when the tab is first opened (or the page opens on it). A visit to the Databases tab can add a
  // database or a database server, so the card asks again the next time it is opened.
  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest ? e.target : null;
    if (t && t.closest('[data-sfsub-btn="databases"]')) st.loaded = false;
    if (t && t.closest('[data-sfsub-btn="addons"]')) void window.adLoad(false); });
  window.addEventListener('hashchange', function () { if (location.hash === '#addons') void window.adLoad(false); });
  if (location.hash === '#addons') void window.adLoad(false);
})();
