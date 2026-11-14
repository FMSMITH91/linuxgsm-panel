// The Databases tab of a game server's Files & Config page (panel/routes/databases.py,
// templates/_server_databases.html). Loads when the tab is first opened, so the page itself asks
// nothing of the host. Every row is built with textContent: names and values come from the server.
// A password is fetched only when the viewer asks to see or copy it (each fetch is audited) and is
// kept in this page's memory only; a connection snippet shows a mask where it goes until then.

// What the tab says about the host's database server: a warning it shows, and a state with no row yet.
var DB_WARN = {
  exposed: 'This database server also listens on the network. The panel won\'t change it: set bind-address = 127.0.0.1 in its config, or block its port in the firewall.',
  skip_networking: 'This database server doesn\'t accept network connections (skip-networking), so games that connect by address can\'t use it.',
  tls_required: 'This database server only accepts encrypted connections (require_secure_transport), which some game plugins can\'t make.'
};
var DB_STATE = {
  setting_up: 'Setting up databases on this host. This takes a minute or two.',
  unsupported: 'This host\'s database server isn\'t one the panel can use: it needs MariaDB 10.4 or later, or MySQL 8.0 or later.',
  unreadable: 'Couldn\'t read the database server on this host: it did not answer. Try again.',
  needs_login: 'A database server is already running here, but the panel can\'t sign in to it yet. A super admin can add its admin login.'
};

// Plain builders the tab's rows are made of (no state of the tab's own).
function dbNode(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function dbIconButton(icon, label, action, args, cls) {
  var b = dbNode('button', 'btn btn-sm btn-outline-secondary db-icon-btn ' + (cls || ''));
  b.type = 'button';
  b.title = label;
  b.setAttribute('aria-label', label);
  var i = dbNode('i');
  i.className = 'bi ' + icon;
  i.setAttribute('aria-hidden', 'true');
  b.appendChild(i);
  b.setAttribute('data-action', action);
  b.setAttribute('data-args', JSON.stringify(args));
  return b;
}
function dbTextButton(text, icon, action, args, cls) {
  var b = dbNode('button', 'btn btn-sm ' + (cls || 'btn-outline-secondary') + ' fpm-edit');
  b.type = 'button';
  if (icon) { var i = dbNode('i'); i.className = 'bi ' + icon; i.setAttribute('aria-hidden', 'true'); b.appendChild(i); b.appendChild(document.createTextNode(' ')); }
  b.appendChild(dbNode('span', null, text));
  b.setAttribute('data-action', action);
  b.setAttribute('data-args', JSON.stringify(args));
  return b;
}
function dbKvRow(label, value, buttons) {
  var r = dbNode('div', 'db-kv');
  r.appendChild(dbNode('span', 'db-k small text-secondary', label));
  var v = dbNode('code', 'db-v', value);
  v.setAttribute('data-no-i18n', '');
  r.appendChild(v);
  buttons.forEach(function (b) { r.appendChild(b); });
  return r;
}
function dbSizeText(b) {
  var GIB = 1024 * 1024 * 1024;   // bytes in one GiB
  if (typeof b !== 'number') return '';
  if (b <= 0) return '0 B';
  if (b < 1024) return '< 1 KB';
  if (b < 1048576) return '≈ ' + Math.max(1, Math.round(b / 1024)) + ' KB';
  if (b < GIB) return '≈ ' + Math.round(b / 1048576) + ' MB';
  return '≈ ' + (b / GIB).toFixed(1) + ' GB';
}

// A superadmin's link after the host line: "Show the panel's admin login" (dbAdminReveal), or
// "Change the admin login" (dbLoginShow).
function dbHostLink(h, text, action) {
  h.appendChild(document.createTextNode(' '));
  var b = dbNode('button', 'btn btn-link btn-sm p-0 align-baseline', text);
  b.type = 'button';
  b.setAttribute('data-action', action);
  b.setAttribute('data-args', JSON.stringify(['@self']));
  h.appendChild(b);
}

(function () {
  'use strict';
  var st = {d: null, pw: {}, kind: {}, open: {}, loaded: false, busy: false, edited: false, poll: null, loginOpen: false};

  var node = dbNode, iconButton = dbIconButton, textButton = dbTextButton, kvRow = dbKvRow;
  function T(s) { return window.t ? window.t(s) : s; }
  function TF(s, v) { return window.tf ? window.tf(s, v) : s; }
  function el(id) { return document.getElementById(id); }
  function api(tail) { return MOUNT + '/api/server/' + serverId + '/databases' + (tail || ''); }
  function show(id, on) { var e = el(id); if (e) e.style.display = on ? '' : 'none'; }
  function say(text, cls) {
    var m = el('db-msg');
    if (!m) return;
    m.textContent = text || '';
    m.className = 'small mt-1 ' + (cls || 'text-secondary');
  }
  function postJson(url, body) {
    return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})})
      .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, d: d || {}}; }); });
  }
  function row(id) {
    var list = (st.d && st.d.databases) || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }

  // ── the host's database server ──────────────────────────────────────────────────────────────
  // A host with no database server row yet: what its state says (a superadmin gets the admin login
  // form for needs_login instead of a line).
  function stateLine(d) {
    var said = DB_STATE[d.state === 'needs_login' && d.can.su ? '' : d.state];
    return {text: said ? T(said) : '', warn: d.state === 'unreadable'};
  }

  function hostLine(d) {
    var h = d.host;
    if (!h) return stateLine(d);
    var ver = /^(\d+\.\d+)/.exec(h.version || ''), name = h.flavor === 'mysql' ? 'MySQL' : 'MariaDB';
    var text = TF('{server} on this host.', {server: name + (ver ? ' ' + ver[1] : '')});
    var bad = (h.warnings || []).filter(function (w) { return DB_WARN[w]; }).map(function (w) { return T(DB_WARN[w]); });
    if (!bad.length) text += ' ' + T('Only reachable from this machine.');
    return {text: [text].concat(bad).join(' ') + loginLine(h, d.can.su), warn: bad.length > 0 || !!h.login_refused};
  }

  // A server the panel signs in to with a stored admin login: say so, and say plainly when the
  // server refused it (every change fails until a super admin replaces or clears it).
  function loginLine(h, su) {
    if (!h.login) return '';
    if (!h.login_refused) return ' ' + T('The panel signs in with a stored admin login.');
    return ' ' + T('The database server refused the panel\'s stored admin login.')
      + (su ? '' : ' ' + T('A super admin can replace or clear it on this tab.'));
  }

  // A superadmin's links after the host line.
  function hostLinks(h, d) {
    if (!d.can.su || !d.host) return;
    if (d.host.installed_by_panel) dbHostLink(h, T('Show the panel\'s admin login'), 'dbAdminReveal');
    if (d.host.login) dbHostLink(h, T('Change the admin login'), 'dbLoginShow');
  }

  // The admin login form: a server the panel can't sign in to yet, or a superadmin replacing or
  // clearing the stored login (opened by its link, or by itself once the server refused it).
  function drawLogin(d) {
    var login = !!(d.host && d.host.login);
    show('db-login', d.can.su && (d.state === 'needs_login' || (login && (d.host.login_refused || st.loginOpen))));
    show('db-login-new', !login);
    show('db-login-old', login);
    show('db-login-clear', login);
  }

  function drawHost(d) {
    var line = hostLine(d), h = el('db-host');
    h.textContent = line.text + (d.setup_error ? (line.text ? ' ' : '') + d.setup_error : '');
    h.className = 'small mb-2 text-break ' + (line.warn || d.setup_error ? 'text-warning' : 'text-secondary');
    show('db-host', !!h.textContent);
    show('db-setup', d.state === 'none');
    show('db-setup-can', d.can.setup);
    show('db-setup-ask', !d.can.setup);
    hostLinks(h, d);
    drawLogin(d);
  }

  function drawAdd(d) {
    var on = d.state === 'ready' && d.can.manage;
    show('db-add', on);
    if (!on) return;
    el('db-prefix').textContent = d.prefix;
    var inp = el('db-name');
    if (!st.edited || !inp.value) { inp.value = d.suggest || ''; st.edited = false; }
    var full = d.used >= d.cap;
    el('db-add-btn').disabled = full;
    el('db-count').textContent = full ? TF('This server has {cap} databases, the most it may have.', {cap: d.cap})
      : TF('{used} of {cap} used', {used: d.used, cap: d.cap});
  }

  // ── one database ────────────────────────────────────────────────────────────────────────────

  // The chosen snippet, with `pw` (else the shown password, else the mask) where the password goes.
  function snippetText(db, pw) {
    var kind = st.kind[db.id] || (db.snippets[0] && db.snippets[0].kind);
    var s = db.snippets.filter(function (x) { return x.kind === kind; })[0] || db.snippets[0];
    pw = pw || st.pw[db.id];
    return s ? (pw ? s.text.split(st.d.pw_mark).join(pw) : s.text) : '';
  }

  function snippetBlock(db) {
    var box = node('div', 'mt-1');
    var bar = node('div', 'd-flex flex-wrap gap-2 align-items-center');
    // The label is the desktop's; a phone keeps the row to the select and its buttons (the select's
    // aria-label says the same).
    var lab = node('label', 'small text-secondary d-none d-md-inline', T('Connection settings for'));
    lab.htmlFor = 'db-kind-' + db.id;
    bar.appendChild(lab);
    var sel = node('select', 'form-select form-select-sm w-auto');
    sel.id = 'db-kind-' + db.id;
    sel.setAttribute('data-no-i18n', '');
    sel.setAttribute('aria-label', T('Connection settings for'));
    db.snippets.forEach(function (s) {
      var o = node('option', null, s.label);
      o.value = s.kind;
      if (s.kind === st.kind[db.id]) o.selected = true;
      sel.appendChild(o);
    });
    sel.setAttribute('data-action', 'dbKind');
    sel.setAttribute('data-on', 'change');
    sel.setAttribute('data-args', JSON.stringify([db.id, '@self']));
    bar.appendChild(sel);
    bar.appendChild(textButton(T('Copy settings'), 'bi-clipboard', 'dbCopySnippet', [db.id]));
    var open = !!st.open[db.id];
    bar.appendChild(iconButton(open ? 'bi-chevron-up' : 'bi-chevron-down', open ? T('Hide the settings') : T('Show the settings'),
                               'dbShowSnippet', [db.id]));
    box.appendChild(bar);
    // Folded until asked for: the copy button needs no look at it, and each one is a dozen lines.
    var pre = node('pre', 'db-snip small border rounded p-2 mb-0', snippetText(db));
    pre.id = 'db-snip-' + db.id;
    pre.style.display = open ? '' : 'none';
    box.appendChild(pre);
    return box;
  }

  function dbCard(db) {
    var card = node('div', 'border rounded p-2');
    var head = node('div', 'd-flex justify-content-between align-items-baseline gap-2 mb-1');
    var title = node('strong', 'text-break', db.name);
    title.setAttribute('data-no-i18n', '');
    head.appendChild(title);
    head.appendChild(node('span', 'small text-secondary text-nowrap', dbSizeText(db.size)));
    card.appendChild(head);
    if (db.old_logins) card.appendChild(node('div', 'small text-warning mb-1', T('This database server only offers newer logins. SourceMod 1.12 and some older plugins can\'t sign in to it.')));
    var kvs = card.appendChild(node('div', 'db-kvs'));
    [['Host', 'host'], ['Port', 'port'], ['Database', 'name'], ['User', 'user']].forEach(function (f) {
      kvs.appendChild(kvRow(T(f[0]), String(db[f[1]]), [iconButton('bi-clipboard', TF('Copy {what}', {what: T(f[0])}), 'dbCopy', [db.id, f[1]])]));
    });
    var pw = st.pw[db.id];
    kvs.appendChild(kvRow(T('Password'), pw || st.d.pw_mark, [
      iconButton(pw ? 'bi-eye-slash' : 'bi-eye', pw ? T('Hide the password') : T('Show the password'), 'dbReveal', [db.id], 'fpm-edit'),
      iconButton('bi-clipboard', T('Copy the password'), 'dbCopy', [db.id, 'password'], 'fpm-edit')]));
    card.appendChild(snippetBlock(db));
    var foot = node('div', 'd-flex flex-wrap gap-1 mt-2 align-items-center');
    foot.appendChild(textButton(T('Reset password'), 'bi-key', 'dbReset', [db.id]));
    // Restore reads the dump in the server's files: offered only while the host says there is one.
    if (db.dumped_at) foot.appendChild(textButton(T('Restore'), 'bi-arrow-counterclockwise', 'dbRestore', [db.id]));
    foot.appendChild(textButton(T('Delete'), 'bi-trash', 'dbDelete', [db.id], 'btn-outline-danger'));
    if (db.dumped_at) foot.appendChild(node('span', 'small text-secondary', TF('Last dump: {when}', {when: new Date(db.dumped_at).toLocaleString()})));
    card.appendChild(foot);
    return card;
  }

  function drawList(d) {
    var list = el('db-list');
    list.textContent = '';
    (d.databases || []).forEach(function (db) { list.appendChild(dbCard(db)); });
    if (!(d.databases || []).length && d.state === 'ready') list.appendChild(node('div', 'small text-secondary', T('No databases yet.')));
  }

  function draw(d) {
    // Setup has ended: its "Setting up…" line is no longer true (the host line says how it went).
    if (st.d && st.d.state === 'setting_up' && d.state !== 'setting_up') say('');
    st.d = d;
    show('db-loading', false);
    drawHost(d);
    drawAdd(d);
    drawList(d);
    if (d.state === 'setting_up' && !st.poll) {
      var until = Date.now() + 15 * 60000;
      st.poll = setInterval(function () {
        if (Date.now() > until || !st.d || st.d.state !== 'setting_up') { clearInterval(st.poll); st.poll = null; return; }
        void window.dbLoad(true);
      }, 5000);
    }
  }

  // `probe`: the Refresh button's, which has the panel look at the host's database server again.
  window.dbLoad = function (force, probe) {
    if (!el('db-card') || (st.loaded && !force)) return Promise.resolve(false);
    st.loaded = true;
    // Refresh starts from what the host says now: an earlier action's line may no longer be true.
    if (probe) say('');
    return fetch(api(probe ? '?refresh=1' : ''), {cache: 'no-store'}).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || d.error || !d.can) { show('db-loading', false); say((d && d.error) || T('Could not load databases.'), 'text-danger'); return false; }
      draw(d);
      return true;
    }).catch(function () { show('db-loading', false); say(T('Could not load databases.'), 'text-danger'); return false; });
  };

  // A change that worked: say so, and draw the tab again from the host's answer.
  function after(res, keepMsg) {
    st.busy = false;
    var ok = res.ok && res.d.success !== false, text = (ok ? '✓ ' : '✗ ') + (res.d.message || res.d.error || T('Failed'));
    say(text, ok ? 'text-success' : 'text-danger');
    if (!ok) return false;
    return window.dbLoad(true).then(function () { if (keepMsg) say(text, 'text-success'); return true; });
  }
  function failed() { st.busy = false; say('✗ ' + T('Could not reach the panel. Try again.'), 'text-danger'); return false; }

  // Form and button handlers: the forms cancel their own submit (ev.preventDefault), so none
  // returns a value for the dispatcher to act on.
  window.dbAdd = function (ev) {
    if (ev) ev.preventDefault();
    if (st.busy) return;
    st.busy = true;
    say(T('Adding the database…'));
    postJson(api(), {name: String(el('db-name').value || '').trim().toLowerCase()})
      .then(function (r) { if (r.ok) st.edited = false; return after(r, true); }).catch(failed);
  };

  window.dbSetup = function (btn) {
    if (st.busy || !st.d) return;
    st.busy = true;
    if (btn) btn.disabled = true;
    postJson(MOUNT + '/api/remote/' + st.d.remote_id + '/databases/setup', {})
      .then(function (r) { if (btn) btn.disabled = false; return after(r, true); }).catch(failed);
  };

  window.dbLogin = function (ev) {
    if (ev) ev.preventDefault();
    if (st.busy || !st.d) return;
    st.busy = true;
    var pw = el('db-login-pw');
    postJson(MOUNT + '/api/remote/' + st.d.remote_id + '/databases/admin-login',
             {user: el('db-login-user').value, password: pw.value})
      .then(function (r) { pw.value = ''; if (r.ok) st.loginOpen = false; return after(r, true); }).catch(failed);
  };

  window.dbLoginShow = function () { st.loginOpen = !st.loginOpen; if (st.d) drawLogin(st.d); };

  // Drop the stored admin login: the panel signs in as root over the socket again, when the server
  // lets it (the route keeps the login otherwise, and says so).
  window.dbLoginClear = function (btn) {
    if (st.busy || !st.d) return;
    st.busy = true;
    if (btn) btn.disabled = true;
    postJson(MOUNT + '/api/remote/' + st.d.remote_id + '/databases/admin-login', {clear: true})
      .then(function (r) { if (btn) btn.disabled = false; if (r.ok) st.loginOpen = false; return after(r, true); })
      .catch(failed);
  };

  // The password, fetched from the panel (audited) unless this page already has it.
  function password(id) {
    if (st.pw[id]) return Promise.resolve(st.pw[id]);
    return postJson(api('/' + id + '/reveal'), {}).then(function (r) {
      if (!r.ok || !r.d.password) throw new Error(r.d.message || r.d.error || T('Failed'));
      return r.d.password;
    });
  }

  // Copy text that may still have to be fetched. A clipboard write after a fetch is refused by some
  // browsers once the click is no longer "now"; a ClipboardItem built from the promise is not.
  function copyLater(promise, label) {
    var cb = navigator.clipboard;
    if (window.ClipboardItem && cb && cb.write) {
      var blob = promise.then(function (text) { return new Blob([text], {type: 'text/plain'}); });
      return cb.write([new window.ClipboardItem({'text/plain': blob})])
        .then(function () { if (window.cursorFlash) window.cursorFlash('✓ ' + label, 'success'); return true; })
        .catch(function (e) { return promise.then(function (text) { window.copyText(text, label); return true; }, function () { say('✗ ' + (e && e.message || T('Failed')), 'text-danger'); return false; }); });
    }
    return promise.then(function (text) { window.copyText(text, label); return true; },
                        function (e) { say('✗ ' + (e && e.message || T('Failed')), 'text-danger'); return false; });
  }

  // One value of a database; the password is fetched first (audited) unless the page already has it.
  window.dbCopy = function (id, field) {
    var db = row(id);
    if (field === 'password') return copyLater(password(id), T('Password copied'));
    if (db && db[field] != null) window.copyText(String(db[field]), T('Copied'));
  };

  // The snippet with the real password goes to the clipboard only: the page keeps showing the mask
  // (the password is fetched for this copy, audited, and not kept) until Show the password is used.
  window.dbCopySnippet = function (id) {
    var db = row(id);
    if (!db) return Promise.resolve(false);
    if (st.pw[id] || !st.d.can.manage) return Promise.resolve(window.copyText(snippetText(db), T('Copied')));
    return copyLater(password(id).then(function (pw) { return snippetText(db, pw); }), T('Copied'));
  };

  function redraw(id) {
    var db = row(id), list = el('db-list');
    if (!db || !list) return;
    var i = st.d.databases.indexOf(db), old = list.children[i];
    if (old) list.replaceChild(dbCard(db), old);
  }

  window.dbReveal = function (id) {
    if (st.pw[id]) { delete st.pw[id]; redraw(id); return Promise.resolve(true); }
    return password(id).then(function (pw) { st.pw[id] = pw; redraw(id); return true; },
                             function (e) { say('✗ ' + e.message, 'text-danger'); return false; });
  };

  window.dbShowSnippet = function (id) { st.open[id] = !st.open[id]; redraw(id); };

  window.dbKind = function (id, sel) {
    st.kind[id] = sel.value;
    var pre = el('db-snip-' + id), db = row(id);
    if (pre && db) pre.textContent = snippetText(db);
  };

  function act(id, tail, body, busyText) {
    if (st.busy) return Promise.resolve(false);
    st.busy = true;
    say(busyText);
    return postJson(api('/' + id + '/' + tail), body).then(function (r) {
      if (tail !== 'restore') delete st.pw[id];
      var done = after(r, true);
      // No dump on the host after all: the row is drawn again without Restore, the answer kept.
      return r.d.no_dump ? window.dbLoad(true).then(function () { return false; }) : done;
    }).catch(failed);
  }

  window.dbReset = function (id) {
    var db = row(id);
    if (!db) return;
    window.confirmDialog({title: T('Reset password'), icon: 'key', confirmClass: 'btn-warning', confirmLabel: T('Reset password'),
      bodyText: T('Anything using the old password stops connecting until you update its config.'),
      onConfirm: function () { void act(id, 'reset-password', {}, T('Setting a new password…')); }});
  };

  window.dbDelete = function (id) {
    var db = row(id);
    if (!db) return;
    window.confirmDialog({title: T('Delete database'), icon: 'trash', confirmClass: 'btn-danger', confirmLabel: T('Delete'),
      bodyText: T('Delete this database and its user? A copy is kept on the host for 30 days.'),
      requireText: db.name, requireLabel: TF('Type the database name ({name}) to confirm:', {name: db.name}),
      onConfirm: function () { void act(id, 'delete', {confirm: db.name}, T('Deleting the database…')); }});
  };

  window.dbRestore = function (id) {
    var db = row(id);
    if (!db) return;
    window.confirmDialog({title: T('Restore from dump'), icon: 'arrow-counterclockwise', confirmClass: 'btn-warning', confirmLabel: T('Restore'),
      bodyText: TF('Replace this database\'s contents with panel-db-dumps/{file} from this server\'s files? Each backup writes that file; a restored backup brings it back.', {file: db.name + '.sql.gz'}),
      requireText: db.name, requireLabel: TF('Type the database name ({name}) to confirm:', {name: db.name}),
      onConfirm: function () { void act(id, 'restore', {confirm: db.name}, T('Restoring the database…')); }});
  };

  window.dbAdminReveal = function (btn) {
    if (!st.d) return Promise.resolve(false);
    return postJson(MOUNT + '/api/remote/' + st.d.remote_id + '/databases/admin-reveal', {}).then(function (r) {
      if (!r.ok || !r.d.password) { say('✗ ' + (r.d.message || T('Failed')), 'text-danger'); return false; }
      var c = node('code', 'ms-1', r.d.user + ' / ' + r.d.password);
      c.setAttribute('data-no-i18n', '');
      if (btn && btn.parentNode) btn.parentNode.replaceChild(c, btn);
      return true;
    }).catch(failed);
  };

  // Typing in the name field keeps what was typed when the tab is drawn again.
  window.dbEdited = function () { st.edited = true; };

  // Load when the tab is first opened (or the page opens on it).
  document.addEventListener('click', function (e) {
    if (e.target && e.target.closest && e.target.closest('[data-sfsub-btn="databases"]')) void window.dbLoad(false); });
  window.addEventListener('hashchange', function () { if (location.hash === '#databases') void window.dbLoad(false); });
  if (location.hash === '#databases') void window.dbLoad(false);
})();
