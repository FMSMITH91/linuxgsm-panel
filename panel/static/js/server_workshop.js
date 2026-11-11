// The server page's Steam Workshop card (server_detail.html #wsc-card), for the games whose Workshop
// list the panel edits (panel/routes/workshop.py). The browser never talks to Steam: titles come
// through the panel. Ids and links are checked here and again on the server; rows are built with
// textContent only, since titles and Mod IDs come from elsewhere.
(function () {
  var ID_RE = /^[0-9]{1,20}$/;
  var MOD_RE = /^\\?[A-Za-z0-9_.\- ]{1,64}$/;
  var MAX = 200;
  var state = {kind: '', items: [], mods: [], titles: {}, found: [], busy: false, ready: false};

  function el(id) { return document.getElementById(id); }
  function url(tail) { return MOUNT + '/api/server/' + serverId + '/workshop' + (tail || ''); }

  function msg(text, cls) {
    var m = el('wsc-msg');
    if (!m) return;
    m.className = 'small mt-1 ' + (cls || '');
    m.textContent = text || '';
  }

  function note(id, text) {
    var n = el(id);
    if (!n) return;
    n.textContent = text || '';
    n.hidden = !text;
  }

  // A Workshop id from what was typed or pasted: the digits, or a steamcommunity.com link's id=.
  // The link is only read, never opened.
  function idFrom(text) {
    var s = String(text || '').trim();
    if (ID_RE.test(s)) return s;
    var u;
    try { u = new URL(s); } catch (e) { return null; }
    if (['https:', 'http:'].indexOf(u.protocol) < 0) return null;
    if (['steamcommunity.com', 'www.steamcommunity.com'].indexOf(u.hostname) < 0) return null;
    var ids = u.searchParams.getAll('id');
    return ids.length === 1 && ID_RE.test(ids[0]) ? ids[0] : null;
  }

  function iconButton(icon, label, action, args, disabled) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm btn-outline-secondary py-0 px-1';
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

  function describe(id) {
    var d = state.titles[id];
    if (!d) return {title: id, meta: ''};
    if (!d.found) return {title: id, meta: t('Not found on Steam, or not public')};
    var meta = d.collection ? tf('Collection of {n} items', {n: d.items}) + ' · ' + id : id;
    return {title: d.title || id, meta: meta};
  }

  function row(list, i, value, count) {
    var li = document.createElement('li');
    li.className = 'd-flex flex-wrap align-items-center gap-1 px-2 py-1 border-bottom';
    var text = document.createElement('div');
    text.className = 'flex-grow-1 text-break';
    text.style.minWidth = '0';
    var title = document.createElement('div');
    var meta = document.createElement('div');
    meta.className = 'text-secondary';
    if (list === 'items') {
      var d = describe(value);
      title.textContent = (i + 1) + '. ' + d.title;
      meta.textContent = d.meta;
    } else {
      title.textContent = value;
    }
    text.appendChild(title);
    if (meta.textContent) text.appendChild(meta);
    li.appendChild(text);
    li.appendChild(iconButton('bi-arrow-up', t('Move up in the list'), 'wscMove', [list, i, -1], i === 0));
    li.appendChild(iconButton('bi-arrow-down', t('Move down in the list'), 'wscMove', [list, i, 1], i === count - 1));
    li.appendChild(iconButton('bi-x-lg', t('Remove from the list'), 'wscRemove', [list, i]));
    return li;
  }

  function drawList(list) {
    var ul = el('wsc-' + list);
    if (!ul) return;
    ul.textContent = '';
    var values = state[list];
    values.forEach(function (v, i) { ul.appendChild(row(list, i, v, values.length)); });
    note('wsc-' + list + '-note', values.length ? '' : (list === 'items' ? t('No Workshop items in the list.') : t('No Mod IDs in the list.')));
  }

  function drawFound() {
    var box = el('wsc-found');
    if (!box) return;
    box.textContent = '';
    var slash = state.mods.some(function (m) { return m.charAt(0) === '\\'; });
    var shown = state.found.filter(function (f) {
      return state.mods.indexOf(f.id) < 0 && state.mods.indexOf('\\' + f.id) < 0;
    });
    shown.forEach(function (f) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn btn-sm btn-outline-success py-0';
      b.textContent = '+ ' + f.id;
      b.title = f.name || f.id;
      b.setAttribute('data-action', 'wscAddFound');
      b.setAttribute('data-args', JSON.stringify([(slash ? '\\' : '') + f.id]));
      box.appendChild(b);
    });
    if (!shown.length) {
      var s = document.createElement('span');
      s.className = 'text-secondary';
      s.textContent = state.found.length ? t('Every Mod ID found is in the list.') : t('None found yet.');
      box.appendChild(s);
    }
  }

  function drawCollection() {
    var info = el('wsc-coll-info');
    if (!info) return;
    var id = state.items[0];
    if (!id) { info.textContent = t('No collection is set.'); return; }
    var d = state.titles[id];
    if (!d) { info.textContent = id; return; }
    if (!d.found) { info.textContent = tf('{id}: not found on Steam, or not public.', {id: id}); return; }
    info.textContent = (d.title || id) + ' · ' + (d.collection ? tf('Collection of {n} items', {n: d.items})
                                                    : t('This is a single item, not a collection.'));
  }

  function drawAll() {
    if (state.kind === 'collection') { drawCollection(); return; }
    drawList('items');
    if (state.kind === 'pz') { drawList('mods'); drawFound(); }
  }

  // Steam's titles for the ids not asked about yet, through the panel.
  function loadTitles() {
    var want = state.items.filter(function (id) { return !(id in state.titles); });
    if (!want.length) { drawAll(); return Promise.resolve(); }
    return fetch(url('/titles?ids=' + want.join(',')))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var got = (d && d.titles) || {};
        Object.keys(got).forEach(function (k) { if (ID_RE.test(k)) state.titles[k] = got[k]; });
        if (!d || !d.complete) msg(t('Titles are unavailable: Steam did not answer. The ids can still be edited.'), 'text-secondary');
        drawAll();
      })
      .catch(function () {
        msg(t('Titles are unavailable: Steam did not answer. The ids can still be edited.'), 'text-secondary');
        drawAll();
      });
  }

  function loadFound() {
    if (state.kind !== 'pz') return Promise.resolve();
    if (!state.items.length) { state.found = []; drawFound(); return Promise.resolve(); }
    return fetch(url('/pz-mods?items=' + state.items.join(',')))
      .then(function (r) { return r.json(); })
      .then(function (d) { state.found = (d && d.success && d.mods) || []; drawFound(); })
      .catch(function () { state.found = []; drawFound(); });
  }

  function failLoad(text) {
    ['wsc-items-note', 'wsc-mods-note'].forEach(function (id) { note(id, text); });
    var info = el('wsc-coll-info');
    if (info) info.textContent = text;
  }

  function load() {
    return fetch(url())
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || d.success === false || d.error) {
          failLoad((d && d.error) || t('The Workshop list could not be read from the server.'));
          return;
        }
        state.kind = d.kind;
        state.items = (d.kind === 'pz' ? d.items : d.ids) || [];
        state.mods = d.mods || [];
        state.ready = true;
        var coll = el('wsc-coll');
        if (coll) coll.value = state.items[0] || '';
        if (d.missing) msg(t('This server has no config file yet: Project Zomboid writes it on the first start.'), 'text-secondary');
        if ((d.ignored || []).length) {
          msg(tf('Not a Workshop id, so it is skipped and is dropped on save: {list}', {list: d.ignored.join(' ')}), 'text-warning');
        }
        drawAll();
        void loadTitles();
        void loadFound();
      })
      .catch(function () { failLoad(t('The Workshop list could not be read from the server.')); });
  }

  function changed() {
    drawAll();
    msg(t('Not saved yet.'), 'text-secondary');
  }

  window.wscAdd = function (list, ev) {
    if (ev) ev.preventDefault();
    if (!state.ready || ['items', 'mods'].indexOf(list) < 0) return false;
    var input = el('wsc-' + list + '-add');
    var value = list === 'items' ? idFrom(input.value) : String(input.value || '').trim();
    if (list === 'items' && !value) {
      msg(t('A Workshop id is 1 to 20 digits, or a steamcommunity.com Workshop link that has one (…?id=123456789).'), 'text-danger');
      return false;
    }
    if (list === 'mods' && !MOD_RE.test(value)) {
      msg(t('A Mod ID is 1 to 64 letters, digits, spaces, dots, dashes or underscores (a leading backslash is kept), with no ; or =.'), 'text-danger');
      return false;
    }
    if (state[list].indexOf(value) >= 0) { msg(t('That is in the list already.'), 'text-warning'); return false; }
    if (state[list].length >= MAX) { msg(t('A list holds at most 200 entries.'), 'text-danger'); return false; }
    state[list].push(value);
    input.value = '';
    changed();
    if (list === 'items') void loadTitles();
    return false;
  };

  window.wscAddFound = function (modId) {
    if (!state.ready || !MOD_RE.test(modId || '') || state.mods.indexOf(modId) >= 0 || state.mods.length >= MAX) return;
    state.mods.push(modId);
    changed();
  };

  window.wscMove = function (list, i, delta) {
    var a = state[list];
    if (!Array.isArray(a) || typeof i !== 'number' || [-1, 1].indexOf(delta) < 0) return;
    var j = i + delta;
    if (i < 0 || j < 0 || i >= a.length || j >= a.length) return;
    var x = a[i]; a[i] = a[j]; a[j] = x;
    changed();
  };

  window.wscRemove = function (list, i) {
    var a = state[list];
    if (!Array.isArray(a) || typeof i !== 'number' || i < 0 || i >= a.length) return;
    a.splice(i, 1);
    changed();
  };

  function post(body) {
    if (state.busy) return Promise.resolve(false);
    state.busy = true;
    msg(t('Saving…'), 'text-secondary');
    return fetch(url(), {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var ok = !!(d && d.success);
        msg((d && (d.message || d.error)) || t('Failed'), ok ? 'text-success' : 'text-danger');
        return ok;
      })
      .catch(function () { msg(t('Failed'), 'text-danger'); return false; })
      .then(function (ok) { state.busy = false; return ok; });
  }

  window.wscSave = function () {
    if (!state.ready || state.kind === 'collection') return;
    var body = state.kind === 'pz' ? {items: state.items.slice(), mods: state.mods.slice()} : {ids: state.items.slice()};
    void post(body).then(function (ok) { if (ok) void loadFound(); });
  };

  window.wscSaveCollection = function (ev) {
    if (ev) ev.preventDefault();
    if (!state.ready) return false;
    var raw = String(el('wsc-coll').value || '').trim();
    var id = raw ? idFrom(raw) : '';
    if (id === null) {
      msg(t('A Workshop id is 1 to 20 digits, or a steamcommunity.com Workshop link that has one (…?id=123456789).'), 'text-danger');
      return false;
    }
    void post({id: id}).then(function (ok) {
      if (!ok) return;
      state.items = id ? [id] : [];
      el('wsc-coll').value = id;
      void loadTitles();
    });
    return false;
  };

  function start() { if (el('wsc-card')) void load(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
