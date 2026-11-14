// The Mods tab's cards for games with no LinuxGSM mods installer (panel/routes/game_mods.py): Arma 3 /
// DayZ mod folders, Factorio mods, Minecraft datapacks and Bedrock packs. Loaded after server_files.js on those servers' Files & Config page only; it uses that
// file's browse and _uis_sfShow, and the page's serverId, SF_CAN and MOUNT. Rows are built with
// textContent only: folder names come from the server. Buttons that change anything are .fpm-edit, so
// they hide without EDIT_FILES ([data-fpm-ro] on the card).
(function () {
  'use strict';
  function el(id) { return document.getElementById(id); }
  function api(tail) { return MOUNT + '/api/server/' + serverId + tail; }
  function say(id, text, cls) {
    var m = el(id);
    if (!m) return;
    m.textContent = text || '';
    m.className = 'small ' + (cls || 'text-secondary');
  }
  function iconButton(icon, label, action, args, disabled) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm btn-outline-secondary py-0 px-1 fpm-edit';
    b.setAttribute('aria-label', label);
    b.title = label;
    b.disabled = !!disabled;
    var i = document.createElement('i');
    i.className = 'bi ' + icon;
    i.setAttribute('aria-hidden', 'true');
    b.appendChild(i);
    b.setAttribute('data-action', action);
    b.setAttribute('data-args', JSON.stringify(args));
    return b;
  }
  function textButton(text, action, args) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm btn-outline-primary py-0 fpm-edit';
    b.textContent = text;
    b.setAttribute('data-action', action);
    b.setAttribute('data-args', JSON.stringify(args));
    return b;
  }
  // One list row: the name (and a note after it), then the row's buttons.
  function listRow(name, note, buttons) {
    var li = document.createElement('li');
    li.className = 'd-flex flex-wrap align-items-center gap-1 px-2 py-1 border-bottom';
    var span = document.createElement('span');
    span.className = 'text-break';
    span.style.flex = '1 1 8rem';
    span.style.minWidth = '0';
    span.textContent = name;
    if (note) {
      var n = document.createElement('span');
      n.className = 'text-warning ms-1';
      n.textContent = note;
      span.appendChild(n);
    }
    li.appendChild(span);
    buttons.forEach(function (b) { li.appendChild(b); });
    return li;
  }
  function emptyRow(text) {
    var li = document.createElement('li');
    li.className = 'text-secondary px-2 py-1';
    li.textContent = text;
    return li;
  }
  function getJson(url) { return fetch(url).then(function (r) { return r.json(); }); }
  function postJson(url, body) {
    return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
      .then(function (r) { return r.json(); });
  }

  window.gmOpenFolder = function (path, btn) {
    if (btn) btn.blur();
    _uis_sfShow('files');
    browse(path || 'serverfiles');
  };

  // ── Arma 3 / DayZ: the folders in `mods` and `servermods`, in load order ───────────────────────
  var am = {folders: [], mods: [], servermods: [], secrets: [], workshop: false, ready: false, busy: false};

  function amListRows(key) {
    var ul = el('gm-arma-' + key);
    if (!ul) return;
    ul.textContent = '';
    var values = am[key], locked = am.secrets.indexOf(key) >= 0;
    values.forEach(function (v, i) {
      var buttons = locked ? [] : [
        iconButton('bi-arrow-up', _tr('Move up in the list'), 'gmArmaMove', [key, i, -1], i === 0),
        iconButton('bi-arrow-down', _tr('Move down in the list'), 'gmArmaMove', [key, i, 1], i === values.length - 1),
        iconButton('bi-x-lg', _tr('Remove from the list'), 'gmArmaRemove', [key, i])];
      var note = am.folders.indexOf(v) < 0 ? _tr('(folder not found)') : '';
      ul.appendChild(listRow((i + 1) + '. ' + v, note, buttons));
    });
    if (!values.length) ul.appendChild(emptyRow(_tr('None.')));
  }

  function amOtherRows() {
    var ul = el('gm-arma-other');
    if (!ul) return;
    ul.textContent = '';
    var rest = am.folders.filter(function (f) { return am.mods.indexOf(f) < 0 && am.servermods.indexOf(f) < 0; });
    rest.forEach(function (f) {
      var buttons = [];
      if (am.secrets.indexOf('mods') < 0) buttons.push(textButton('+ ' + _tr('Mods'), 'gmArmaAdd', ['mods', f]));
      if (am.secrets.indexOf('servermods') < 0) buttons.push(textButton('+ ' + _tr('Server mods'), 'gmArmaAdd', ['servermods', f]));
      ul.appendChild(listRow(f, '', buttons));
    });
    if (!rest.length) ul.appendChild(emptyRow(am.folders.length ? _tr('Every folder is in a list.') : _tr('No @folders found in serverfiles or serverfiles/mods.')));
  }

  function amNote() {
    var notes = [];
    if (am.secrets.length) notes.push(tf('{keys} is set in the secrets file, so the panel does not change it here.', {keys: am.secrets.join(', ')}));
    if (am.workshop) notes.push(_tr('LinuxGSM adds this server\'s Steam Workshop mods after these when it starts.'));
    var n = el('gm-arma-note');
    if (n) n.textContent = notes.join(' ');
  }

  function amDraw() { amListRows('mods'); amListRows('servermods'); amOtherRows(); amNote(); }

  window.gmArmaLoad = function () {
    if (!el('gm-arma-card')) return Promise.resolve(false);
    say('gm-arma-msg', _tr('Loading mods…'));
    return getJson(api('/mod-folders')).then(function (d) {
      if (!d || d.error) { say('gm-arma-msg', (d && d.error) || _tr('Could not load mods.'), 'text-danger'); return false; }
      am.folders = d.folders || []; am.mods = d.mods || []; am.servermods = d.servermods || [];
      am.secrets = d.secrets || []; am.workshop = !!d.workshop; am.ready = true;
      amDraw(); say('gm-arma-msg', ''); return true;
    }).catch(function () { say('gm-arma-msg', _tr('Could not load mods.'), 'text-danger'); return false; });
  };

  function amChanged() { amDraw(); say('gm-arma-msg', _tr('Not saved yet.')); }

  window.gmArmaAdd = function (key, folder) {
    if (!am.ready || ['mods', 'servermods'].indexOf(key) < 0 || am.folders.indexOf(folder) < 0) return;
    if (am.mods.indexOf(folder) >= 0 || am.servermods.indexOf(folder) >= 0) return;
    am[key].push(folder);
    amChanged();
  };

  window.gmArmaMove = function (key, i, delta) {
    var a = am[key];
    if (!Array.isArray(a) || typeof i !== 'number' || [-1, 1].indexOf(delta) < 0) return;
    var j = i + delta;
    if (i < 0 || j < 0 || i >= a.length || j >= a.length) return;
    var x = a[i]; a[i] = a[j]; a[j] = x;
    amChanged();
  };

  window.gmArmaRemove = function (key, i) {
    var a = am[key];
    if (!Array.isArray(a) || typeof i !== 'number' || i < 0 || i >= a.length) return;
    a.splice(i, 1);
    amChanged();
  };

  window.gmArmaSave = function (btn) {
    if (!am.ready || am.busy) return Promise.resolve(false);
    am.busy = true;
    if (btn) btn.disabled = true;
    say('gm-arma-msg', _tr('Saving…'));
    return postJson(api('/mod-folders'), {mods: am.mods.slice(), servermods: am.servermods.slice()})
      .then(function (d) {
        var ok = !!(d && d.success);
        say('gm-arma-msg', (ok ? '✓ ' : '✗ ') + ((d && d.message) || _tr('Failed')), ok ? 'text-success' : 'text-danger');
        return ok;
      })
      .catch(function () { say('gm-arma-msg', '✗ ' + _tr('Could not save — connection error'), 'text-danger'); return false; })
      .then(function (ok) { am.busy = false; if (btn) btn.disabled = false; return ok; });
  };

  // ── Factorio: each mod on or off in mod-list.json ─────────────────────────────────────────────
  var fm = {busy: false};

  function fmNote(d) {
    if (d.where === 'mod-directory') return _tr('This server\'s start line passes --mod-directory, so the panel does not change its mods here.');
    if (d.mod_list === 'missing') return _tr('Factorio writes mods/mod-list.json the first time the server starts. Start it once, then change mods here.');
    if (d.mod_list === 'bad') return _tr('mods/mod-list.json isn\'t the list Factorio writes, so the panel won\'t change it.');
    return '';
  }

  function fmRow(m, editable) {
    var buttons = [];
    if (editable && !(m.name === 'base')) {
      buttons.push(textButton(m.enabled ? _tr('Turn off') : _tr('Turn on'), 'gmFctrSet', [m.name, !m.enabled]));
    }
    var state = m.enabled ? _tr('On') : _tr('Off');
    var extra = m.builtin ? _tr('built in') : (m.files.length ? m.files.join(', ') : _tr('(file not found)'));
    return listRow(m.name + ' — ' + state + ' · ' + extra, '', buttons);
  }

  function fmDraw(d) {
    var ul = el('gm-fctr-list');
    ul.textContent = '';
    var note = fmNote(d), editable = !note;
    (d.mods || []).forEach(function (m) { ul.appendChild(fmRow(m, editable)); });
    if (!(d.mods || []).length) ul.appendChild(emptyRow(_tr('No mods found.')));
    el('gm-fctr-note').textContent = note;
  }

  window.gmFctrLoad = function () {
    if (!el('gm-fctr-card')) return Promise.resolve(false);
    say('gm-fctr-msg', _tr('Loading mods…'));
    return getJson(api('/factorio-mods')).then(function (d) {
      if (!d || d.error) { say('gm-fctr-msg', (d && d.error) || _tr('Could not load mods.'), 'text-danger'); return false; }
      fmDraw(d); say('gm-fctr-msg', ''); return true;
    }).catch(function () { say('gm-fctr-msg', _tr('Could not load mods.'), 'text-danger'); return false; });
  };

  window.gmFctrSet = function (name, enabled) {
    if (fm.busy || typeof name !== 'string' || typeof enabled !== 'boolean') return Promise.resolve(false);
    fm.busy = true;
    say('gm-fctr-msg', _tr('Saving…'));
    return postJson(api('/factorio-mods'), {name: name, enabled: enabled})
      .then(function (d) {
        var ok = !!(d && d.success);
        say('gm-fctr-msg', (ok ? '✓ ' : '✗ ') + ((d && d.message) || _tr('Failed')), ok ? 'text-success' : 'text-danger');
        fm.busy = false;
        if (ok) return window.gmFctrLoad().then(function () { say('gm-fctr-msg', '✓ ' + d.message, 'text-success'); return true; });
        return false;
      })
      .catch(function () { fm.busy = false; say('gm-fctr-msg', '✗ ' + _tr('Could not save — connection error'), 'text-danger'); return false; });
  };

  // ── Minecraft Java: the world's datapacks, and Modrinth's ──────────────────────────────────────
  var mc = {dir: '', mcVersion: null, busy: false};

  function sizeText(n) {
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    return Math.max(1, Math.round(n / 1024)) + ' KB';
  }

  function mcDraw(d) {
    mc.dir = d.dir || ''; mc.mcVersion = d.mc_version || null;
    var w = el('gm-mc-world');
    if (!d.world) {
      w.textContent = tf('The panel can\'t tell which world folder this server uses: {why}.', {why: d.why || ''});
      w.className = 'small text-warning mb-1 text-break';
    } else {
      var v = d.mc_version ? tf('Minecraft {version}', {version: d.mc_version}) : _tr('Minecraft version unknown');
      w.textContent = tf('World: {world}', {world: d.world}) + ' · ' + v + (d.world_dir ? '' : ' · ' + _tr('not created yet'));
      w.className = 'small text-secondary mb-1 text-break';
    }
    var ul = el('gm-mc-list');
    ul.textContent = '';
    (d.datapacks || []).forEach(function (p) {
      var buttons = p.managed ? [iconButton('bi-trash', _tr('Remove'), 'gmMcRemove', [p.name])] : [];
      ul.appendChild(listRow(p.name + (p.folder ? '/' : ' · ' + sizeText(p.size)), '', buttons));
    });
    if (!(d.datapacks || []).length) ul.appendChild(emptyRow(_tr('No datapacks in this world.')));
  }

  window.gmMcLoad = function () {
    if (!el('gm-mc-card')) return Promise.resolve(false);
    say('gm-mc-msg', _tr('Loading datapacks…'));
    return getJson(api('/mc-packs')).then(function (d) {
      if (!d || d.error) { say('gm-mc-msg', (d && d.error) || _tr('Could not load datapacks.'), 'text-danger'); return false; }
      mcDraw(d); say('gm-mc-msg', ''); return true;
    }).catch(function () { say('gm-mc-msg', _tr('Could not load datapacks.'), 'text-danger'); return false; });
  };

  function mcAfter(d, reload) {
    var ok = !!(d && d.success);
    var text = (ok ? '✓ ' : '✗ ') + ((d && (d.message || d.error)) || _tr('Failed'));
    if (!ok || !reload) { say('gm-mc-msg', text, ok ? 'text-success' : 'text-danger'); return ok; }
    return window.gmMcLoad().then(function () { say('gm-mc-msg', text, 'text-success'); return true; });
  }

  function mcAct(url, body) {
    if (mc.busy) return Promise.resolve(false);
    mc.busy = true;
    say('gm-mc-msg', _tr('Working…'));
    return postJson(url, body).then(function (d) { mc.busy = false; return mcAfter(d, true); })
      .catch(function () { mc.busy = false; say('gm-mc-msg', '✗ ' + _tr('Could not save — connection error'), 'text-danger'); return false; });
  }

  window.gmMcRemove = function (name) {
    if (typeof name !== 'string' || !name) return Promise.resolve(false);
    return new Promise(function (resolve) {
      confirmDialog({title: _tr('Remove datapack'), icon: 'trash', confirmLabel: _tr('Remove datapack'),
                     confirmClass: 'btn-danger', bodyText: tf('Remove the datapack {name} from this world?', {name: name}),
                     onConfirm: function () { resolve(mcAct(api('/mc-packs'), {action: 'remove', name: name})); }});
    });
  };

  window.gmMcInstall = function (projectId) {
    if (typeof projectId !== 'string' || !/^[0-9A-Za-z]{8}$/.test(projectId)) return Promise.resolve(false);
    return mcAct(api('/mc-packs/install'), {project_id: projectId});
  };

  function hitRow(h) {
    var meta = h.author ? ' · ' + h.author : '';
    var li = listRow(h.title + meta, '', [textButton(_tr('Install'), 'gmMcInstall', [h.project_id])]);
    if (h.description) {
      var p = document.createElement('div');
      p.className = 'text-secondary w-100';
      p.textContent = h.description;
      li.appendChild(p);
    }
    return li;
  }

  window.gmMcSearch = function (ev) {
    if (ev) ev.preventDefault();
    var q = String(el('gm-mc-q').value || '').trim();
    var ul = el('gm-mc-hits');
    var url = api('/mc-packs/search?q=' + encodeURIComponent(q) + (mc.mcVersion ? '&mc=' + encodeURIComponent(mc.mcVersion) : ''));
    say('gm-mc-msg', _tr('Searching…'));
    return getJson(url).then(function (d) {
      ul.textContent = '';
      if (!d || !d.success) { say('gm-mc-msg', (d && d.error) || _tr('Search failed.'), 'text-danger'); return false; }
      (d.hits || []).forEach(function (h) { ul.appendChild(hitRow(h)); });
      if (!(d.hits || []).length) ul.appendChild(emptyRow(_tr('No datapacks found.')));
      say('gm-mc-msg', d.verified ? '' : _tr('The server\'s Minecraft version is unknown, so results are for every version.'));
      return true;
    }).catch(function () { say('gm-mc-msg', _tr('Search failed.'), 'text-danger'); return false; });
  };

  window.gmMcOpenFolder = function (btn) { window.gmOpenFolder(mc.dir || 'serverfiles', btn); };

  // ── Minecraft Bedrock: shared packs, on or off for the world ──────────────────────────────────
  var mcb = {busy: false};

  // Why the world's packs cannot be changed, or ''.
  function mcbProblem(d) {
    if (!d.world) return tf('The panel can\'t tell which world folder this server uses: {why}.', {why: d.why || ''});
    if (!d.world_dir) return _tr('The world folder isn\'t there yet: start the server once, then turn packs on here.');
    if ((d.bad_lists || []).length) return _tr('The world\'s pack list isn\'t the list Bedrock writes, so the panel won\'t change it.');
    return '';
  }

  function mcbRow(p, problem) {
    var label = (p.type === 'behavior' ? _tr('Behavior pack') : _tr('Resource pack')) + ': ' + (p.name || p.folder);
    if (p.ok) label += ' ' + p.version.join('.') + ' · ' + (p.enabled ? _tr('On') : _tr('Off'));
    var buttons = p.ok && !problem ? [textButton(p.enabled ? _tr('Turn off') : _tr('Turn on'), 'gmMcbSet', [p.type, p.uuid, !p.enabled])] : [];
    return listRow(label, p.ok ? '' : _tr('(no readable manifest.json)'), buttons);
  }

  function mcbDraw(d) {
    var w = el('gm-mcb-world'), problem = mcbProblem(d);
    w.textContent = problem || tf('World: {world}', {world: d.world});
    w.className = 'small mb-1 text-break ' + (problem ? 'text-warning' : 'text-secondary');
    var ul = el('gm-mcb-list');
    ul.textContent = '';
    (d.packs || []).forEach(function (p) { ul.appendChild(mcbRow(p, problem)); });
    if (!(d.packs || []).length) ul.appendChild(emptyRow(_tr('No packs in behavior_packs or resource_packs.')));
  }

  window.gmMcbLoad = function () {
    if (!el('gm-mcb-card')) return Promise.resolve(false);
    say('gm-mcb-msg', _tr('Loading packs…'));
    return getJson(api('/mc-packs')).then(function (d) {
      if (!d || d.error) { say('gm-mcb-msg', (d && d.error) || _tr('Could not load packs.'), 'text-danger'); return false; }
      mcbDraw(d); say('gm-mcb-msg', ''); return true;
    }).catch(function () { say('gm-mcb-msg', _tr('Could not load packs.'), 'text-danger'); return false; });
  };

  window.gmMcbSet = function (type, uuid, enabled) {
    if (mcb.busy || typeof uuid !== 'string' || typeof enabled !== 'boolean') return Promise.resolve(false);
    mcb.busy = true;
    say('gm-mcb-msg', _tr('Saving…'));
    return postJson(api('/mc-packs'), {type: type, uuid: uuid, enabled: enabled}).then(function (d) {
      mcb.busy = false;
      var ok = !!(d && d.success), text = (ok ? '✓ ' : '✗ ') + ((d && d.message) || _tr('Failed'));
      if (!ok) { say('gm-mcb-msg', text, 'text-danger'); return false; }
      return window.gmMcbLoad().then(function () { say('gm-mcb-msg', text, 'text-success'); return true; });
    }).catch(function () { mcb.busy = false; say('gm-mcb-msg', '✗ ' + _tr('Could not save — connection error'), 'text-danger'); return false; });
  };

  if (SF_CAN.manage) {
    void window.gmArmaLoad();
    void window.gmFctrLoad();
    void window.gmMcLoad();
    void window.gmMcbLoad();
  }
})();
