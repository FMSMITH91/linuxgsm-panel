// The server page's Plugins card (server_detail.html #mdr-card, PaperMC servers only).
// Search and install go through the panel (panel/routes/modrinth_plugins.py): the browser never
// talks to Modrinth, and the panel host downloads and checks each file before it reaches the server.
// Rows are built with textContent only: titles, descriptions and file names come from elsewhere.
(function () {
  var NAME_RE = /^[A-Za-z0-9_+-][A-Za-z0-9._+-]{0,127}\.jar(\.disabled)?$/;
  var ID_RE = /^[0-9A-Za-z]{8}$/;
  var state = {mc: null, seq: 0, busy: false};

  function el(id) { return document.getElementById(id); }
  function url(tail) { return MOUNT + '/api/server/' + serverId + '/plugins' + (tail || ''); }

  function msg(text, cls) {
    var m = el('mdr-msg');
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

  function button(label, cls, action, args) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm py-0 ' + cls;
    b.textContent = label;
    b.setAttribute('data-action', action);
    b.setAttribute('data-args', JSON.stringify(args));
    return b;
  }

  function sizeText(n) {
    if (!n) return '';
    return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';
  }

  // One installed jar: its name, its state, and the buttons for what can be done to it.
  function installedRow(p) {
    var li = document.createElement('li');
    li.className = 'd-flex flex-wrap align-items-center gap-2 px-2 py-1 border-bottom';
    var name = document.createElement('span');
    name.className = 'text-break flex-grow-1' + (p.enabled ? '' : ' text-secondary');
    name.style.minWidth = '0';
    name.textContent = p.name;
    var info = document.createElement('span');
    info.className = 'text-secondary';
    info.textContent = (p.enabled ? '' : t('Disabled') + ' · ') + sizeText(p.size);
    li.appendChild(name);
    li.appendChild(info);
    if (p.managed && NAME_RE.test(p.name)) {
      li.appendChild(p.enabled ? button(t('Disable'), 'btn-outline-secondary', 'mdrChange', ['disable', p.name])
                               : button(t('Enable'), 'btn-outline-success', 'mdrChange', ['enable', p.name]));
      li.appendChild(button(t('Remove'), 'btn-outline-danger', 'mdrChange', ['remove', p.name]));
    }
    return li;
  }

  function showVersion() {
    var v = el('mdr-version');
    if (!v) return;
    v.textContent = state.mc
      ? tf('Minecraft {version}: search results are builds for this version.', {version: state.mc})
      : t('The Minecraft version of this server could not be told, so results are not checked against it.');
  }

  function loadInstalled() {
    return fetch(url())
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var list = el('mdr-installed');
        list.textContent = '';
        if (!d || d.success === false || d.error) {
          note('mdr-installed-note', (d && d.error) || t('The plugins folder could not be read from the server, so it is not shown.'));
          return;
        }
        state.mc = d.mc_version || null;
        showVersion();
        (d.plugins || []).forEach(function (p) { list.appendChild(installedRow(p)); });
        note('mdr-installed-note', (d.plugins || []).length ? '' : t('No plugins installed.'));
      })
      .catch(function () { note('mdr-installed-note', t('The plugins folder could not be read from the server, so it is not shown.')); });
  }

  function hitRow(h, verified) {
    var li = document.createElement('li');
    li.className = 'd-flex flex-wrap align-items-start gap-2 px-2 py-1 border-bottom';
    var text = document.createElement('div');
    text.className = 'flex-grow-1 text-break';
    text.style.minWidth = '0';
    var title = document.createElement('div');
    title.className = 'fw-semibold';
    title.textContent = h.title || h.project_id;
    var desc = document.createElement('div');
    desc.className = 'text-secondary';
    desc.textContent = h.description || '';
    var meta = document.createElement('div');
    meta.className = 'text-secondary';
    meta.textContent = tf('{n} downloads', {n: Number(h.downloads || 0).toLocaleString()}) +
      (h.author ? ' · ' + h.author : '') + (verified ? '' : ' · ' + t('not checked against this server'));
    text.appendChild(title); text.appendChild(desc); text.appendChild(meta);
    li.appendChild(text);
    li.appendChild(button(t('Install'), 'btn-outline-primary', 'mdrInstall', [h.project_id, h.title || h.project_id]));
    return li;
  }

  window.mdrSearch = function (ev) {
    if (ev) ev.preventDefault();
    var q = el('mdr-q').value.trim();
    if (q.length > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(q)) {
      msg(t('A search is at most 80 characters, on one line, with no control characters.'), 'text-danger');
      return false;
    }
    var seq = ++state.seq;
    var list = el('mdr-results');
    list.textContent = '';
    note('mdr-results-note', t('Searching…'));
    var qs = '?q=' + encodeURIComponent(q) + (state.mc ? '&mc=' + encodeURIComponent(state.mc) : '');
    fetch(url('/search' + qs))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (seq !== state.seq) return;   // an older search's answer
        if (!d || d.success === false || d.error) {
          note('mdr-results-note', (d && d.error) || t('Failed'));
          return;
        }
        (d.hits || []).forEach(function (h) { if (ID_RE.test(h.project_id || '')) list.appendChild(hitRow(h, d.verified)); });
        note('mdr-results-note', (d.hits || []).length ? '' : t('No plugins found.'));
      })
      .catch(function () { if (seq === state.seq) note('mdr-results-note', t('Failed')); });
    return false;
  };

  function post(tail, body, sending) {
    if (state.busy) return Promise.resolve(false);
    state.busy = true;
    msg(sending, 'text-secondary');
    return fetch(url(tail), {method: 'POST', headers: {'Content-Type': 'application/json'},
                             body: JSON.stringify(body)})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var ok = !!(d && d.success);
        msg((d && (d.message || d.error)) || t('Failed'), ok ? 'text-success' : 'text-danger');
        return ok;
      })
      .catch(function () { msg(t('Failed'), 'text-danger'); return false; })
      .then(function (ok) { state.busy = false; if (ok) loadInstalled(); return ok; });
  }

  window.mdrInstall = function (projectId, title) {
    if (!ID_RE.test(projectId || '')) return;
    void post('/install', {project_id: projectId}, tf('Downloading and checking {name}…', {name: title || projectId}));
  };

  window.mdrChange = function (action, name) {
    if (!NAME_RE.test(name || '') || ['enable', 'disable', 'remove'].indexOf(action) < 0) return;
    var send = function () { void post('/change', {action: action, name: name}, t('Working…')); };
    if (action !== 'remove') { send(); return; }
    // The styled dialog; the name goes in as text (bodyText), never as markup.
    confirmDialog({title: t('Remove plugin'), icon: 'bi-trash', confirmLabel: t('Remove'),
                   confirmClass: 'btn-danger', bodyText: tf('Remove {name} from the plugins folder?', {name: name}),
                   onConfirm: send});
  };

  function start() { if (el('mdr-card')) loadInstalled(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
