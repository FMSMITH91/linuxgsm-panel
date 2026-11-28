// The Updates page (templates/updates.html). GET /api/updates:
//   {groups: [{key, title, items: [{kind, ref, name, title (its kind and what it updates), versions: [Installed line,
//     Available line] | [], host, what: [..], notes: [{title, url}], cost, security,
//     safe, auto, auto_editable, when, when_link: {href, title} | null, action: {post, body, step_up, confirm,
//     confirm_title} | {href} | null, link; a game row also: auto_why, backup, backup_post, later: {post, queued}}]}],
//    count, settings: {start, end, can_edit, owasp_auto, off, checking, can_check},
//    history: [{at, at_host (on the clock of the host the row is about), who, action, target, ok, badge, detail}]}
// Every text the server sends is already in the viewer's language. Update now runs the item's own route
// (or opens the card that runs it, with that card's confirmation); nothing here decides what the server allows.
(function () {
  'use strict';
  var ROOT = document.getElementById('upd-page');
  if (!ROOT) return;
  var MOUNT = window.MOUNT || '';
  var T = function (s) { return window.t ? window.t(s) : s; };
  var TF = function (s, v) { return window.tf ? window.tf(s, v) : s; };
  var HISTORY_SHOWN = 10;
  var ACTIONS = {panel_self_update: 'Panel', os_update_run: 'Host system', remote_os_update: 'Host system',
    'update-lgsm_server': 'LinuxGSM', update_server: 'Game update', 'force-update_server': 'Game update',
    update_complete: 'Game update', update_when_empty: 'Game update', update_warned: 'Game update',
    update_left_stopped: 'Game update',
    addon_update: 'Add-on', website_update: 'Website', update_skipped: 'Skipped'};
  var polls = 0;
  var last = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function icon(name) { var i = el('i', 'bi bi-' + name); i.setAttribute('aria-hidden', 'true'); return i; }
  function say(id, text, kind) {
    var m = document.getElementById(id);
    if (!m) return;
    m.className = 'small mb-2 ' + (kind === 'error' ? 'text-danger' : kind === 'ok' ? 'text-success' : 'text-secondary');
    m.textContent = text || '';
  }
  function post(url, body) {
    return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body || {})})
      .then(function (r) { return r.json().catch(function () { return {success: false}; }); });
  }

  function load() {
    return fetch(MOUNT + '/api/updates', {cache: 'no-store'}).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || !d.success) { say('upd-msg', (d && d.message) || T('Couldn\'t read the updates.'), 'error'); return; }
      last = d;
      render(d);
    }).catch(function () { say('upd-msg', T('Couldn\'t read the updates.'), 'error'); });
  }

  function render(d) {
    var list = document.getElementById('upd-list');
    list.textContent = '';
    if (!d.groups.length) list.appendChild(el('p', 'small text-success mb-2', T('Everything is up to date.')));
    d.groups.forEach(function (g) { list.appendChild(groupCard(g)); });
    var safe = 0, off = [];
    d.groups.forEach(function (g) {
      // A game switched off (or off by its family's default) says why on its own row, not in this warning.
      g.items.forEach(function (r) { if (r.safe && r.action && r.action.post) safe++; if (r.auto === false && r.kind !== 'game') off.push(r.name); });
    });
    var b = document.getElementById('upd-safe');
    if (b) { b.disabled = !safe; b.title = safe ? TF('{n} update(s) can run now without kicking players.', {n: safe}) : ''; }
    safeWhy(d.groups, safe);
    renderOff(off);
    renderSettings(d.settings || {});
    renderHistory(d.history || [], false);
    checkButton(d.settings || {});
  }

  // Check now: LinuxGSM's check-update on every game server the viewer may read, one at a time on the server; the
  // list is read again every 10 s while some are left (at most 30 times).
  function checkButton(s) {
    var b = document.getElementById('upd-games-check');
    if (!b) return;
    b.hidden = !s.can_check;
    b.disabled = !!s.checking;
    if (s.checking && polls < 30) { polls++; setTimeout(load, 10000); } else if (!s.checking) polls = 0;
  }
  window.updGamesCheck = function () {
    var b = document.getElementById('upd-games-check');
    if (b) b.disabled = true;
    post(MOUNT + '/api/updates/games/check', {}).then(function (d) {
      say('upd-msg', d.message || '', d.success ? 'ok' : 'error');
      if (d.started) setTimeout(load, 10000); else if (b) b.disabled = false;
    }).catch(function () { say('upd-msg', T('Couldn\'t read the updates.'), 'error'); if (b) b.disabled = false; });
  };

  // A greyed "Update everything safe now" says why beside it (the button stays in its place), by what is listed:
  // nothing at all; a row this viewer may run that kicks players; a row whose Update now opens its own page (the
  // panel's update and the hosts' packages, which can restart services or need a reboot); else rows they may not run.
  function safeWhy(groups, safe) {
    var why = document.getElementById('upd-safe-why');
    if (!why) return;
    var rows = 0, runnable = 0, pages = 0;
    groups.forEach(function (g) {
      g.items.forEach(function (r) {
        rows++;
        if (r.action && r.action.post) runnable++;
        else if (r.action && r.action.href) pages++;
      });
    });
    if (safe) { hideWhy(why); return; }
    var text;
    if (!rows) text = T('Nothing to update now.');
    else if (runnable) text = T('Nothing listed can run now without kicking players or a reboot.');
    else if (pages) text = T('What is listed can restart services or need a reboot: its Update now opens the page that runs it.');
    else text = T('None of these is yours to update now: its administrators or the nightly window update it.');
    why.textContent = text;
    why.hidden = false;
  }
  function hideWhy(why) { why.textContent = ''; why.hidden = true; }

  // Off is a lasting note on the page, never a block (OWASP's recommended value is on).
  function renderOff(off) {
    var box = document.getElementById('upd-off');
    if (!box) return;
    box.hidden = !off.length;
    var text = document.getElementById('upd-off-text');
    text.textContent = off.length ? TF('Automatic updates are off for {n} item(s): {names}. Security updates still install in the nightly window; OWASP recommends leaving automatic updates on.', {n: off.length, names: off.join(', ')}) : '';
    text.setAttribute('data-no-i18n', '');
  }

  function groupCard(g) {
    var card = el('div', 'card mb-2'), head = el('div', 'card-header py-1 small fw-semibold', g.title);
    head.setAttribute('data-no-i18n', '');
    var body = el('div', 'card-body py-1');
    g.items.forEach(function (r) { body.appendChild(row(r)); });
    card.appendChild(head);
    card.appendChild(body);
    return card;
  }

  // A row's first line says, first, what kind of update it is and what it updates ("Game update: PaperMC"); then its
  // name (a link to its page), its host, and the security mark. One line where it fits: less to scroll.
  function rowHead(r) {
    var top = el('div', 'd-flex flex-wrap column-gap-2 align-items-baseline');
    if (r.title) {
      var t = el('span', 'upd-title fw-semibold text-break', r.title);
      t.setAttribute('data-no-i18n', '');
      top.appendChild(t);
    }
    var name = r.link ? el('a', 'text-break', r.name) : el('span', 'text-break', r.name);
    if (r.link) name.href = r.link;
    name.setAttribute('data-no-i18n', '');
    top.appendChild(name);
    if (r.host) { var h = el('span', 'small text-secondary', r.host); h.setAttribute('data-no-i18n', ''); top.appendChild(h); }
    if (r.security) top.appendChild(el('span', 'badge text-bg-danger', T('Security update')));
    return top;
  }
  // What the row says before its cost: the two version lines, what the update changes, and its notes' links.
  function rowBody(r, wrap) {
    if ((r.versions || []).length) wrap.appendChild(versions(r.versions));
    if ((r.what || []).length) wrap.appendChild(lines(r.what));
    if ((r.notes || []).length) wrap.appendChild(notes(r.notes));
  }
  // When it updates by itself, with the link that changes it where there is one.
  function whenLine(r) {
    var when = line('clock', r.when, r.auto === false && !r.security ? 'text-warning-emphasis' : '');
    if (r.when_link && r.when_link.href) {
      var wl = el('a', 'ms-1', r.when_link.title || '');
      wl.href = r.when_link.href;
      wl.setAttribute('data-no-i18n', '');
      when.appendChild(wl);
    }
    return when;
  }
  function row(r) {
    var wrap = el('div', 'upd-row py-2');
    wrap.appendChild(rowHead(r));
    rowBody(r, wrap);
    wrap.appendChild(line('hourglass-split', r.cost, 'text-secondary'));
    var when = whenLine(r);
    wrap.appendChild(when);
    var out = el('div', 'small mt-1');
    out.setAttribute('role', 'status');
    wrap.appendChild(controls(r, out, when));
    if (r.auto_why) wrap.appendChild(line('info-circle', r.auto_why, 'text-secondary'));
    wrap.appendChild(out);
    return wrap;
  }
  // A row's buttons and switches; each answers in `out` (`when`: the row's clock line).
  function controls(r, out, when) {
    var ctl = el('div', 'd-flex flex-wrap gap-2 align-items-center mt-1');
    if (r.action) ctl.appendChild(actionButton(r, out));
    if (r.later) ctl.appendChild(laterButton(r, out, when));
    if (r.auto_editable) ctl.appendChild(autoSwitch(r, out));
    if (r.backup_post && r.auto) ctl.appendChild(backupSwitch(r, out));     // only the nightly window backs up first
    return ctl;
  }
  // Update when empty, or no longer wait: the server's own queue (the due-actions sweep runs it once nobody is on).
  // The row's clock line follows (the server's `when`): a queued update says so before any task or window.
  function laterButton(r, out, when) {
    var b = el('button', 'btn btn-sm btn-outline-secondary');
    b.type = 'button';
    var label = function (queued) {
      b.textContent = '';
      b.appendChild(icon(queued ? 'x-circle' : 'hourglass'));
      b.appendChild(document.createTextNode(' ' + (queued ? T('Don\'t wait') : T('Update when empty'))));
    };
    var queued = !!r.later.queued;
    label(queued);
    b.addEventListener('click', function () {
      b.disabled = true;
      post(r.later.post, {when: queued ? 'cancel' : 'empty'}).then(function (d) {
        b.disabled = false;
        out.className = 'small mt-1 ' + (d.success ? 'text-success' : 'text-danger');
        out.textContent = d.message || '';
        if (d.success) {
          queued = !!d.queued;
          label(queued);
          var said = when && when.querySelector('span');
          if (said && d.when) said.textContent = d.when;
        }
      }).catch(function () { b.disabled = false; });
    });
    return b;
  }
  function backupSwitch(r, out) {
    var box = el('div', 'form-check mb-0');
    var id = 'upd-backup-' + r.ref.replace(/[^a-z0-9]/gi, '-');
    var cb = el('input', 'form-check-input');
    cb.type = 'checkbox'; cb.id = id; cb.checked = !!r.backup;
    var lab = el('label', 'form-check-label small', T('Back up first at night'));
    lab.htmlFor = id;
    cb.addEventListener('change', function () {
      cb.disabled = true;
      post(r.backup_post, {on: cb.checked}).then(function (d) {
        cb.disabled = false;
        if (!d.success) { cb.checked = !cb.checked; out.className = 'small mt-1 text-danger'; out.textContent = d.message || ''; }
      }).catch(function () { cb.disabled = false; cb.checked = !cb.checked; });
    });
    box.appendChild(cb); box.appendChild(lab);
    return box;
  }
  // The version it runs and the one it moves to, one labelled line each (the server's words: "Installed: ...").
  function versions(pair) {
    var box = el('div', 'upd-versions small mb-1');
    box.setAttribute('data-no-i18n', '');
    pair.forEach(function (v, i) {
      var d = el('div', 'text-break' + (i ? ' fw-semibold' : ''));
      d.appendChild(icon(i ? 'arrow-right-circle' : 'box'));
      d.appendChild(el('span', 'ms-1', v));
      box.appendChild(d);
    });
    return box;
  }
  function lines(what) {
    var ul = el('ul', 'small mb-1 ps-3');
    ul.setAttribute('data-no-i18n', '');
    (what || []).forEach(function (w) { ul.appendChild(el('li', 'text-break', w)); });
    return ul;
  }
  function notes(list) {
    var p = el('div', 'small mb-1 d-flex flex-wrap gap-2');
    p.appendChild(el('span', 'text-secondary', T('What\'s new:')));
    list.forEach(function (n) {
      var a = el('a', '', n.title);
      a.href = n.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.setAttribute('data-no-i18n', '');
      p.appendChild(a);
    });
    return p;
  }
  function line(ic, text, cls) {
    var d = el('div', 'small');
    if (cls) d.classList.add(cls);
    d.appendChild(icon(ic));
    var s = el('span', 'ms-1', text || '');
    s.setAttribute('data-no-i18n', '');
    d.appendChild(s);
    return d;
  }

  function actionButton(r, out) {
    if (r.action.href) {
      var a = el('a', 'btn btn-sm btn-primary');
      a.href = r.action.href;
      a.appendChild(icon('download'));
      a.appendChild(document.createTextNode(' ' + T('Update now')));
      return a;
    }
    var b = el('button', 'btn btn-sm btn-primary');
    b.type = 'button';
    b.appendChild(icon('download'));
    b.appendChild(document.createTextNode(' ' + T('Update now')));
    b.addEventListener('click', function () {
      var go = function () { runUpdate(r, b, out); };
      var run = function () { if (r.action.step_up && window.stepUpThen) window.stepUpThen(go, window.STEP_UP_TOTP === true); else go(); };
      // A game update can kick players: asked first, naming the server, with what it costs and whether the players
      // on are warned (the server's words, already in the viewer's language).
      if (r.action.confirm && window.confirmDialog) {
        window.confirmDialog({title: r.action.confirm_title || T('Update now'), icon: 'download', confirmClass: 'btn-primary', confirmLabel: T('Update now'),
          onConfirm: run, bodyText: r.action.confirm});
      } else run();
    });
    return b;
  }
  // The row stays where it is with its result (the button gone): the history, the count and the warnings are read
  // again, the rows are not, so a finished update is not a row that just vanished.
  function runUpdate(r, b, out) {
    b.disabled = true;
    out.className = 'small mt-1 text-secondary';
    out.textContent = T('Updating…');
    post(r.action.post, r.action.body).then(function (d) {
      out.className = 'small mt-1 ' + (d.success ? 'text-success' : 'text-danger');
      out.textContent = d.message || (d.success ? T('Done.') : T('The update failed.'));
      if (!d.success) { b.disabled = false; return; }
      var said = out.textContent;
      out.textContent = '';
      out.appendChild(icon('check-circle-fill'));
      out.appendChild(document.createTextNode(' ' + said));
      b.remove();
      setTimeout(refreshAround, d.started ? 15000 : 1500);
    }).catch(function () { out.className = 'small mt-1 text-danger'; out.textContent = T('The update failed.'); b.disabled = false; });
  }
  function refreshAround() {
    fetch(MOUNT + '/api/updates', {cache: 'no-store'}).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || !d.success) return;
      last = d;
      renderHistory(d.history || [], false);
    }).catch(function () {});
  }

  function autoSwitch(r, out) {
    var box = el('div', 'form-check form-switch mb-0');
    var id = 'upd-auto-' + r.ref.replace(/[^a-z0-9]/gi, '-');
    var cb = el('input', 'form-check-input');
    cb.type = 'checkbox'; cb.id = id; cb.checked = r.auto !== false;
    var lab = el('label', 'form-check-label small', T('Automatic updates'));
    lab.htmlFor = id;
    var rec = el('span', 'small text-secondary ms-1', T('(OWASP recommends: on)'));
    cb.addEventListener('change', function () {
      cb.disabled = true;
      post(MOUNT + '/api/updates/auto', {ref: r.ref, on: cb.checked}).then(function (d) {
        cb.disabled = false;
        if (!d.success) { cb.checked = !cb.checked; out.className = 'small mt-1 text-danger'; out.textContent = d.message || ''; return; }
        out.className = 'small mt-1 text-warning-emphasis';
        out.textContent = d.note || '';
        load().catch(function () {});
      }).catch(function () { cb.disabled = false; cb.checked = !cb.checked; });
    });
    box.appendChild(cb); box.appendChild(lab); box.appendChild(rec);
    return box;
  }

  function renderSettings(s) {
    var a = document.getElementById('upd-start'), b = document.getElementById('upd-end');
    if (a && document.activeElement !== a) a.value = s.start || '04:00';
    if (b && document.activeElement !== b) b.value = s.end || '05:00';
  }
  window.updSaveWindow = function () {
    var a = document.getElementById('upd-start').value, b = document.getElementById('upd-end').value;
    post(MOUNT + '/api/updates/window', {start: a, end: b}).then(function (d) {
      say('upd-window-msg', d.message || '', d.success ? 'ok' : 'error');
    }).catch(function () { say('upd-window-msg', T('Couldn\'t save.'), 'error'); });
  };

  // A History row's mark, from the server's `badge` (done, failed, waited, queued, cancelled).
  function badgeOf(h) {
    switch (h.badge) {
      case 'waited': return ['text-bg-secondary', T('Waited')];
      case 'queued': return ['text-bg-secondary', T('Queued')];
      case 'cancelled': return ['text-bg-secondary', T('No longer queued')];
      default: return h.ok ? ['text-bg-success', T('Done')] : ['text-bg-danger', T('Failed')];
    }
  }
  function historyItem(h) {
    var li = el('li', 'py-1 border-bottom');
    // On the clock of the host the row is about, as the nightly window's times are (the list says so once).
    var t = el('span', 'text-secondary text-nowrap', h.at_host || h.at);
    t.setAttribute('data-no-i18n', '');
    li.appendChild(t);
    var badge = badgeOf(h);
    li.appendChild(el('span', 'ms-2 badge ' + badge[0], badge[1]));
    li.appendChild(el('span', 'ms-2', T(ACTIONS[h.action] || 'Update')));
    var who = el('span', 'ms-2 fw-semibold text-break', h.target);
    who.setAttribute('data-no-i18n', '');
    li.appendChild(who);
    var by = el('span', 'ms-2 text-secondary', h.who === 'automatic' ? T('automatic') : h.who);
    if (h.who !== 'automatic') by.setAttribute('data-no-i18n', '');
    li.appendChild(by);
    if (h.detail) { var d = el('div', 'text-secondary text-break', h.detail); d.setAttribute('data-no-i18n', ''); li.appendChild(d); }
    return li;
  }
  function renderHistory(rows, all) {
    var ul = document.getElementById('upd-history-list');
    if (!ul) return;
    ul.textContent = '';
    if (!rows.length) ul.appendChild(el('li', 'text-secondary', T('Nothing updated yet.')));
    rows.slice(0, all ? rows.length : HISTORY_SHOWN).forEach(function (h) { ul.appendChild(historyItem(h)); });
    var more = document.getElementById('upd-history-more');
    if (more) more.hidden = all || rows.length <= HISTORY_SHOWN;
  }
  window.updHistoryMore = function () { renderHistory((last && last.history) || [], true); };

  window.updSafe = function () {
    var go = function () {
      say('upd-msg', T('Starting…'));
      post(MOUNT + '/api/updates/safe', {}).then(function (d) {
        say('upd-msg', d.message || '', d.success ? 'ok' : 'error');
        if (d.started) setTimeout(load, 20000);
      }).catch(function () { say('upd-msg', T('The update failed.'), 'error'); });
    };
    var run = function () { if (window.stepUpThen) window.stepUpThen(go, window.STEP_UP_TOTP === true); else go(); };
    if (!window.confirmDialog) { run(); return; }
    window.confirmDialog({title: T('Update everything safe now'), icon: 'lightning-charge', confirmClass: 'btn-primary',
      confirmLabel: T('Update now'), onConfirm: run,
      bodyText: T('Websites, add-ons on servers with no players, and LinuxGSM update now, one at a time. Each website is offline for a few seconds; no player is kicked and nothing reboots.')});
  };

  load().catch(function () {});
})();
