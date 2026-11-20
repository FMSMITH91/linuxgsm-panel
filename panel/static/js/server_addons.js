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
  var JOB = {install: 'Installing…', update: 'Updating…', settings: 'Applying settings…', start: 'Starting…', remove: 'Removing…'};

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
        TF('Its web page listens on 127.0.0.1:{port} on this host only; Open shows it through the panel.', {port: a.port})));
    }
    if (a.geolocation_option) geoStatus(a, box);
    if (a.eula_url) BM.status(a, box);
    if (a.update) {
      box.appendChild(node('div', 'small text-warning', BM.updateWords(a)));
    } else {
      // Said, not left blank: the card compared the add-on with the panel's own version when it loaded.
      box.appendChild(node('div', 'small text-secondary', T('Up to date (checked just now).')));
    }
    // An install, update, settings change or remove still running: nothing to press until it ends (a
    // start being watched can still be stopped; a Remove meanwhile is refused with the reason).
    if ({install: 1, update: 1, settings: 1, remove: 1}[a.job]) return;
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-1');
    WEB.open(a, bar);
    if (a.state === 'active') bar.appendChild(button(T('Stop'), 'bi-stop-circle', 'adAct', [a.id, 'stop']));
    else bar.appendChild(button(T('Start'), 'bi-play-circle', 'adAct', [a.id, 'start']));
    if (a.update) bar.appendChild(button(T('Update'), 'bi-arrow-up-circle', 'adUpdate', [a.id], 'btn-outline-primary'));
    bar.appendChild(button(T('Log'), 'bi-journal-text', 'adLog', [a.id]));
    bar.appendChild(button(T('Remove'), 'bi-trash', 'adRemove', [a.id], 'btn-outline-danger'));
    box.appendChild(bar);
    if (a.geolocation_option) settingsFold(a, box, bar);
  }

  // BlueMap's parts of the card, in one closure: its lines on an installed row (the Minecraft version it renders,
  // the disk it takes, who accepted Mojang's EULA, its render threads), Mojang's EULA at install (the admin ticks
  // it, never assumed), and its words in the Install, Update and Remove texts.
  var BM = (function () {
    function updateWords(a) {
      if (a.update === 'geoip') return T('Update available: a newer month of the country database.');
      if (a.update === 'game') return TF('Update available: the server now runs Minecraft {version}, and BlueMap needs that version\'s client file.', {version: a.mc_version_now || ''});
      return T('Update available: a newer version of the add-on.');
    }
    function sizeWords(kb) {
      return kb >= 1048576 ? (kb / 1048576).toFixed(1) + ' GB' : Math.max(1, Math.round(kb / 1024)) + ' MB';
    }
    function whenWords(iso) {
      var d = new Date(iso);
      return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
    }
    function status(a, box) {
      var lines = [];
      if (a.mc_version) lines.push(TF('Renders the world as Minecraft {version}.', {version: a.mc_version}));
      if (a.disk_kb != null) lines.push(TF('Disk used: {size}.', {size: sizeWords(a.disk_kb)}));
      if (a.eula_by) lines.push(TF('Mojang\'s EULA accepted by {who} on {when}.', {who: a.eula_by, when: whenWords(a.eula_at)}));
      lines.push(TF('Render threads: {n} (render-thread-count in the add-on\'s config/core.conf; Stop and Start it after a change).', {n: a.render_threads || 1}));
      lines.forEach(function (t) { box.appendChild(node('div', 'small text-secondary text-break', t)); });
    }
    function eula(a, box) {
      var w = node('div', 'form-check small mt-1');
      var cb = node('input', 'form-check-input');
      cb.type = 'checkbox';
      cb.id = 'ad-eula-' + a.id;
      var l = node('label', 'form-check-label', T('I accept Mojang\'s EULA: BlueMap needs Minecraft\'s client file, which this host downloads from Mojang.'));
      l.htmlFor = cb.id;
      w.appendChild(cb);
      w.appendChild(l);
      box.appendChild(w);
      var link = node('a', 'small d-inline-block mb-1', T('Read Mojang\'s EULA'));
      link.href = a.eula_url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      box.appendChild(link);
      box.appendChild(node('div', 'small text-secondary', T('BlueMap shows the world, read-only, as a 3D map on a web page on this host (127.0.0.1). Its first render takes a while and uses CPU and disk, below the game\'s priority.')));
    }
    // Whether Install may go on: for BlueMap, only once the EULA is ticked (else it says so and goes to the box).
    function ticked(a) {
      var cb = el('ad-eula-' + a.id);
      if (!a.eula_url || (cb && cb.checked)) return true;
      say(T('Tick that you accept Mojang\'s EULA first: BlueMap can\'t draw the map without Minecraft\'s client file.'), 'text-danger');
      if (cb) cb.focus();
      return false;
    }
    // The install's body: the database, the geolocation, Mojang's EULA accepted; null when it can't go yet.
    function installBody(a) {
      var sel = el('ad-db-' + a.id), geo = el('ad-geo-' + a.id), body = {};
      if ((a.needs_database && (!sel || !sel.value)) || !ticked(a)) return null;
      if (a.eula_url) body.accept_eula = true;
      if (a.needs_database) body.database_id = Number.parseInt(sel.value, 10);
      if (geo) body.geolocation = geo.value;
      return body;
    }
    function installWords(a) {
      return a.eula_url
        ? T('This installs Podman on the host if it is not there, readies the server\'s account for containers, downloads BlueMap\'s image and Minecraft\'s client file from Mojang, and starts rendering the world, which it reads read-only.')
        : T('This installs Podman on the host if it is not there, readies the server\'s account for containers, and downloads or builds the add-on\'s image. The add-on reads the server\'s RCON password and game log.');
    }
    function removeWords(a) {
      if (a.data_kept) return T('This stops the add-on and deletes its container, image and folder: its settings and any plugin settings you edited go with it. Its database is kept in the Databases tab.');
      if (a.eula_url) return T('This stops BlueMap and deletes its container, image and files: its settings, the rendered map and Minecraft\'s client file. The world itself is not touched.');
      return T('This stops the add-on and deletes its container, image and files: its settings and its data (players, statistics) too.');
    }
    return {updateWords: updateWords, status: status, eula: eula, installBody: installBody, installWords: installWords,
      removeWords: removeWords};
  })();

  // An add-on's web page, opened through the panel (routes/addon_web.py) in a new tab: a form post (CSRF
  // token, no referrer) the panel answers with the page's link. A viewer with View add-on pages alone gets
  // only these rows.
  var WEB = (function () {
    function open(a, bar) {
      if (a.web && a.state === 'active') bar.appendChild(button(T('Open'), 'bi-box-arrow-up-right', 'adOpen', [a.id], 'btn-outline-primary'));
    }
    function go(id) {
      var f = node('form');
      f.method = 'post';
      f.action = api('/' + encodeURIComponent(id) + '/web');
      f.target = '_blank';
      f.rel = 'noopener noreferrer';
      var t = node('input');
      t.type = 'hidden';
      t.name = 'csrf_token';
      t.value = window.CSRF || '';
      f.appendChild(t);
      f.hidden = true;
      document.body.appendChild(f);
      if (window.ensureCsrfFields) window.ensureCsrfFields(f);   // the current token, as panel.js gives every POST form
      f.submit();
      f.remove();
      return true;
    }
    function viewerRows(d, list) {
      if (!(d.addons || []).length) list.appendChild(node('div', 'small text-secondary', T('No add-on with a web page is installed on this server.')));
      (d.addons || []).forEach(function (a) {
        var box = node('div', 'ad-row');
        box.appendChild(rowHead(a));
        var bar = node('div', 'd-flex flex-wrap gap-2 mt-1');
        open(a, bar);
        if (a.state !== 'active') bar.appendChild(node('span', 'small text-secondary', T('Its page opens once the add-on is running.')));
        box.appendChild(bar);
        list.appendChild(box);
      });
    }
    return {open: open, go: go, viewerRows: viewerRows};
  })();
  window.adOpen = WEB.go;

  // B3's own parts of the card (services/b3_control.py): what it says of itself (health.json, or its exit
  // code in words), and in the settings fold the alerts switch for its bans and kicks (saved at once, no
  // Apply) and its service settings (Panel actions, purge_aliases_days). B3's reason is its own English
  // text, shown as it wrote it.
  var B3S = (function () {
    function known(v, yes, no) { return v === true ? T(yes) : (v === false ? T(no) : T('not yet')); }
    function healthLines(h, box) {
      if (h.healthy) box.appendChild(node('div', 'small text-success', T('B3 is healthy.')));
      else {
        var w = node('div', 'small text-warning', T('B3 reports a problem:') + ' ');
        var r = node('span', null, h.reason || '?');   // i18n-ignore: B3's own words
        r.setAttribute('data-no-i18n', '');
        w.appendChild(r);
        box.appendChild(w);
      }
      var parts = [TF('Game log: {s}', {s: known(h.game_log, 'read', 'not read')}),
        TF('RCON: {s}', {s: known(h.rcon, 'working', 'failing')}),
        TF('Database: {s}', {s: known(h.database, 'connected', 'lost')})];
      if (h.humans != null) parts.push(TF('Players: {n} ({bots} bots)', {n: h.humans, bots: h.bots || 0}));
      box.appendChild(node('div', 'small text-secondary', parts.join(' · ')));   // i18n-ignore: a separator
    }
    function alertsSwitch(a, box) {
      var w = node('div', 'form-check small mt-1');
      var cb = node('input', 'form-check-input');
      cb.type = 'checkbox';
      cb.id = 'ad-b3-alerts';
      cb.checked = !!a.alerts;
      cb.setAttribute('data-action', 'adB3Alerts');
      cb.setAttribute('data-on', 'change');
      cb.setAttribute('data-args', JSON.stringify(['@self']));
      var l = node('label', 'form-check-label', T('Alert me when B3 bans, temporarily bans or kicks a player on this server (saved at once)'));
      l.htmlFor = cb.id;
      w.appendChild(cb);
      w.appendChild(l);
      box.appendChild(w);
      box.appendChild(node('div', 'small text-secondary', T('Sent to your alert channels (Settings, Notifications); players\' names only with Include details on.')));
    }
    function status(a, box) {
      if (a.exit_reason) box.appendChild(node('div', 'small text-warning', a.exit_reason));
      if (a.stale) box.appendChild(node('div', 'small text-warning', a.stale));
      if (a.health) healthLines(a.health, box);
    }
    function settings(a, fold) {
      var w = node('div', 'form-check small mt-2');
      var cb = node('input', 'form-check-input');
      cb.type = 'checkbox';
      cb.id = 'ad-actions-' + a.id;
      cb.checked = !!a.actions;
      var l = node('label', 'form-check-label', T('Panel actions: unban, kick and warn from the B3 players section'));
      l.htmlFor = cb.id;
      w.appendChild(cb);
      w.appendChild(l);
      fold.appendChild(w);
      fold.appendChild(node('div', 'small text-secondary', T('Turns on B3\'s control socket: a file in its folder that only the server\'s account can open, no network port. Each action also takes the Ban or Kick players permission, asks for your password when your sign-in is old, and is in the audit log.')));
      var wrap = node('div', 'mt-2');
      var lab = node('label', 'form-label small mb-0', T('Forget earlier names and IP addresses not seen for (days)'));
      lab.htmlFor = 'ad-purge-' + a.id;
      var inp = node('input', 'form-control form-control-sm fx-12');
      inp.type = 'number';
      inp.id = 'ad-purge-' + a.id;
      inp.min = String((a.purge_bounds || [1])[0]);
      inp.max = String((a.purge_bounds || [1, 3650])[1]);
      inp.step = '1';
      inp.placeholder = String(a.purge_example || 365);
      inp.setAttribute('data-no-i18n', '');
      if (a.purge_aliases_days) inp.value = String(a.purge_aliases_days);
      wrap.appendChild(lab);
      wrap.appendChild(inp);
      wrap.appendChild(node('div', 'small text-secondary', TF('Optional; empty keeps them for good. B3 keeps each player\'s last name and address, and their penalties. OWASP\'s Logging Cheat Sheet (Disposal of logs) sets no number of days: keep personal data only as long as you need it ({n} is an example).', {n: a.purge_example || 365})));
      fold.appendChild(wrap);
    }
    // The Apply body's B3 service settings, or null (and why, beside the field) when the days are not a whole number in range.
    function days(inp) {
      var raw = String(inp.value || '').trim(), n = raw === '' ? null : Number(raw);
      return n === null || (Number.isInteger(n) && n >= Number(inp.min) && n <= Number(inp.max)) ? n : undefined;
    }
    function body(id) {
      var cb = el('ad-actions-' + id), inp = el('ad-purge-' + id), n = days(inp);
      if (n === undefined) {
        say(TF('Days: a whole number from {lo} to {hi}, or empty.', {lo: inp.min, hi: inp.max}), 'text-danger');
        if (inp.focus) inp.focus();
        return null;
      }
      return {actions: !!cb.checked, purge_aliases_days: n};
    }
    return {status: status, settings: settings, body: body, alerts: alertsSwitch};
  })();

  window.adB3Alerts = function (cb) {
    var on = !!cb.checked;
    return postJson(api('/b3/alerts'), {enabled: on}).then(function (res) {
      var ok = res.ok && res.d.success !== false;
      if (!ok) cb.checked = !on;
      say((ok ? '✓ ' : '✗ ') + (res.d.message || res.d.error || T('Failed')), ok ? 'text-success' : 'text-danger');
      return ok;
    }).catch(function () { cb.checked = !on; return failed(); });
  };

  function geoStatus(a, box) {
    if (a.b3_card) B3S.status(a, box);   // B3's own lines first: B3 is the add-on with geolocation
    var GEO_SAID = {off: 'Geolocation is off.',
      offline: 'Geolocation is offline: each player\'s country, from DB-IP\'s database on this host. No player address leaves the host.',
      online: 'Geolocation is online: players\' IP addresses go to ipwho.is, which answers with their city.'};
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
  // B3's row also gets Players, before Remove: its players and penalties, read from its database (b3_players.js).
  function settingsFold(a, box, bar) {
    bar.insertBefore(button(T('Players'), 'bi-people', 'b3pOpen', []), bar.lastChild);
    var fold = node('details', 'mt-2');
    fold.appendChild(node('summary', 'small', T('B3 settings')));
    if (a.b3_card) B3S.alerts(a, fold);
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
    if (a.b3_card) B3S.settings(a, fold);
    var bar = node('div', 'd-flex flex-wrap gap-2 mt-2');
    // With a new image pending, Apply would name an image the host doesn't have yet: Update comes first.
    if (a.update === 'image') bar.appendChild(node('div', 'small text-warning', T('Update the add-on first, then apply its settings.')));
    else bar.appendChild(button(T('Apply'), 'bi-check2-circle', 'adSettings', [a.id], 'btn-primary'));
    fold.appendChild(bar);
    fold.appendChild(node('div', 'small text-secondary mt-1', T('Only these settings are rewritten in b3.ini; your other edits there and in its conf folder are kept.')));
    fold.appendChild(node('div', 'small text-secondary', T('B3 checks the new settings before it uses them, and a refusal changes nothing. A change to plugin settings alone is reloaded without a restart; anything else restarts B3.')));
    box.appendChild(fold);
  }

  // The operator's own plugins folder: off unless turned on; the warning sits beside the switch (Apply asks with it).
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
    var warn = node('div', 'small text-warning', T('A plugin in this folder is someone else\'s code: it runs inside B3\'s container, with B3\'s database and RCON access, and the panel doesn\'t check it. Load only plugins you trust. The folder is mounted read-only, and the container keeps its other limits.'));
    warn.id = 'ad-own-warn-' + a.id;
    fold.appendChild(warn);
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
      box.appendChild(node('div', 'small text-warning', T('Legacy, opt-in: B3 is an older admin bot, kept for Call of Duty, United Offensive, Call of Duty 2, Call of Duty 4, World at War, Soldier of Fortune 2, Wolfenstein: Enemy Territory, ET: Legacy and Quake 3 Arena. It is built on this host from one pinned version of its source and runs as locked down as every add-on, but it gets fewer fixes than newer tools. Install it only if you want it.')));
    }
    if (a.note) box.appendChild(node('div', 'small text-secondary', a.note));
  }

  function installRow(a, d, box) {
    installNotes(a, box);
    var free = (d.databases || []).filter(function (x) { return !x.used_by; });
    if (a.needs_database && !free.length) { noDatabaseRow(a, d, box); return; }
    if (a.geolocation_option) box.appendChild(geoSelect(a, 'ad-geo-' + a.id, 'off'));
    if (a.eula_url) BM.eula(a, box);
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
    if (d.manage === false) { WEB.viewerRows(d, list); return; }
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
    var a = row(id), body = st.busy ? null : BM.installBody(a);
    if (!body) return;
    window.confirmDialog({title: T('Install the add-on'), icon: 'download', confirmClass: 'btn-primary', confirmLabel: T('Install'),
      bodyText: BM.installWords(a),
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
      bodyText: BM.removeWords(row(id)),
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
    var svc = el('ad-actions-' + id) ? B3S.body(id) : {};
    if (!svc) return;
    var go = function () {
      stepUp(function () {
        st.busy = true;
        say(T('Applying the settings…'));
        postJson(api('/' + id + '/settings'), Object.assign({geolocation: geo.value, plugins: plugins, own_plugins: ownOn}, svc)).then(after).catch(failed);
      });
    };
    // Turning the own-plugins folder on is asked once more, with the warning.
    if (ownOn && !row(id).own_plugins) {
      window.confirmDialog({title: T('Load your own B3 plugins'), icon: 'exclamation-triangle', confirmClass: 'btn-warning',
        confirmLabel: T('Turn on and restart'), bodyText: el('ad-own-warn-' + id).textContent, onConfirm: go});
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

  // Load when the section is first shown (server_files.js: a click, a #hash, or the section a viewer
  // without VIEW_FILES opens on), or when the page opened on it before this script ran. A visit to
  // the Databases tab can add a database or a database server, so the card asks again the next time.
  document.addEventListener('sfsub:shown', function (e) {
    if (e.detail === 'databases') st.loaded = false;
    if (e.detail === 'addons') void window.adLoad(false); });
  var onView = document.querySelector('[data-sfsub-btn="addons"]');
  if (onView && onView.classList.contains('active')) void window.adLoad(false);
})();
