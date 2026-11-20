// The Add-ons tab's B3 players section (panel/routes/addons_b3.py, templates/_server_addons.html):
// a search of B3's players, one player's history and B3's latest penalties, read from B3's own
// database. It opens from B3's row (server_addons.js's Players button). Every value is set with
// textContent: names, aliases and reasons are what players and admins typed in the game. The search
// text goes in a POST body, never the address. With B3's Panel actions on, a player's view also offers
// Unban, Kick and Warn (routes/addons_b3_actions.py): B3 itself does them; each confirms first, and a
// sign-in past the confirmation window confirms the password in a dialog (step_up_form.js).
(function () {
  'use strict';
  var st = {mode: '', q: '', after: '', kind: 'all', before: 0, busy: false};
  var TYPE = {Ban: 'Permanent ban', TempBan: 'Temporary ban', Kick: 'Kicked', Warning: 'Warning', Notice: 'Notice'};
  var STATE = {active: 'Active', expired: 'Expired', removed: 'Lifted'};

  function T(s) { return window.t ? window.t(s) : s; }
  function TF(s, v) { return window.tf ? window.tf(s, v) : s; }
  function el(id) { return document.getElementById(id); }
  function show(id, on) { var e = el(id); if (e) e.style.display = on ? '' : 'none'; }
  function api(tail) { return MOUNT + '/api/server/' + serverId + '/addons/b3' + tail; }
  function node(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  // Text a player or an admin typed: never matched against the translation catalogue.
  function typed(tag, cls, text) {
    var e = node(tag, cls, text);
    e.setAttribute('data-no-i18n', '');
    return e;
  }
  function say(text, cls) {
    var m = el('b3p-msg');
    if (!m) return;
    m.textContent = text || '';
    m.className = 'small mb-1 ' + (cls || 'text-secondary');
  }
  function button(text, icon, action, args, cls) {
    var b = node('button', 'btn btn-sm ' + (cls || 'btn-outline-secondary'));
    b.type = 'button';
    var i = node('i', 'bi');
    i.classList.add(icon);
    i.setAttribute('aria-hidden', 'true');
    b.appendChild(i);
    b.appendChild(document.createTextNode(' '));
    b.appendChild(node('span', null, text));
    b.setAttribute('data-action', action);
    b.setAttribute('data-args', JSON.stringify(args));
    return b;
  }
  // Epoch seconds in the viewer's own zone, in the page's language.
  function when(epoch) {
    if (!epoch || epoch < 0) return '—';   // i18n-ignore: a dash
    try {
      var lang = (document.documentElement && document.documentElement.lang) || [];
      return new Date(epoch * 1000).toLocaleString(lang, {year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
    } catch (e) { return ''; }
  }
  function span(m) {
    if (m >= 1440 && m % 1440 === 0) return TF('{n} d', {n: m / 1440});
    if (m >= 60 && m % 60 === 0) return TF('{n} h', {n: m / 60});
    return TF('{n} min', {n: m});
  }
  function getJson(url) {
    return fetch(url, {cache: 'no-store'}).then(function (r) { return r.json().then(function (d) { return d || {}; }); });
  }
  function postJson(url, body) {
    return fetch(url, {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
      .then(function (r) { return r.json().then(function (d) { return d || {}; }); });
  }
  function failed() { st.busy = false; say(T('Could not reach the panel. Try again.'), 'text-danger'); }
  function refused(d) { st.busy = false; say(d.error || T('Failed'), 'text-danger'); return false; }

  // ── lists ─────────────────────────────────────────────────────────────────────────────────────
  function playerRow(p) {
    var row = node('div', 'ad-row d-flex flex-wrap gap-2 align-items-center');
    var who = node('div', 'flex-grow-1 text-break');
    who.appendChild(typed('strong', null, p.name || '—'));   // i18n-ignore: a dash
    who.appendChild(typed('span', 'small text-secondary ms-1', '@' + p.id));
    if (p.group) who.appendChild(typed('span', 'badge text-bg-secondary ms-1', p.group));
    var facts = TF('Last seen {when}, {n} connections.', {when: when(p.last_seen), n: p.connections});
    who.appendChild(node('div', 'small text-secondary', facts));
    if (p.guid) who.appendChild(typed('div', 'small text-secondary text-break', 'GUID ' + p.guid));   // i18n-ignore: a label and a value
    row.appendChild(who);
    row.appendChild(button(T('Open'), 'bi-person-lines-fill', 'b3pPlayer', [p.id]));
    return row;
  }

  function penaltyHead(x) {
    var head = node('div', 'd-flex flex-wrap gap-1 align-items-center');
    head.appendChild(node('span', x.type === 'Ban' || x.type === 'TempBan' ? 'badge text-bg-danger' : 'badge text-bg-secondary',
      T(TYPE[x.type] || x.type || '?')));   // i18n-ignore: the type itself when it is not one of B3's
    if (x.state) head.appendChild(node('span', x.state === 'active' ? 'badge text-bg-warning' : 'badge text-bg-light', T(STATE[x.state])));
    if (x.type === 'TempBan' || x.type === 'Warning') head.appendChild(node('span', 'small text-secondary', span(x.duration)));
    return head;
  }

  // One penalty: what, its state, the reason, who gave it and when; with the player in the latest list.
  function penaltyRow(x, withPlayer) {
    var row = node('div', 'ad-row');
    var head = penaltyHead(x);
    if (withPlayer) {
      var b = button(x.player || ('@' + x.player_id), 'bi-person', 'b3pPlayer', [x.player_id], 'btn-link p-0');
      b.setAttribute('data-no-i18n', '');
      head.insertBefore(b, head.firstChild);
    }
    row.appendChild(head);
    if (x.reason) row.appendChild(typed('div', 'small text-break', x.reason));
    var line = TF('By {admin}, {when}.', {admin: x.admin, when: when(x.time)});
    if (x.expires > 0 && (x.type === 'TempBan' || x.type === 'Warning')) line += ' ' + TF('Until {when}.', {when: when(x.expires)});
    row.appendChild(node('div', 'small text-secondary', line));
    return row;
  }

  function moreButton(box) {
    box.appendChild(button(T('Older'), 'bi-chevron-down', 'b3pMore', [], 'btn-outline-secondary mt-1'));
  }

  function list(rows, emptyText, append) {
    var box = el('b3p-list');
    show('b3p-player', false);
    show('b3p-list', true);
    if (!append) box.textContent = '';
    var old = box.querySelector('[data-action="b3pMore"]');
    if (old) old.remove();
    if (!rows.length && !append) { say(emptyText); return box; }
    say('');
    return box;
  }

  function drawPlayers(d, append) {
    show('b3p-masked', d.masked === true);
    var box = list(d.players || [], T('No player\'s name, alias or GUID starts with that.'), append);
    (d.players || []).forEach(function (p) { box.appendChild(playerRow(p)); });
    st.after = d.after || '';
    if (st.after) moreButton(box);
  }

  function drawPenalties(d, append) {
    var box = list(d.penalties || [], st.kind === 'bans' ? T('B3 has given no bans yet.') : T('B3 has given no penalties yet.'), append);
    (d.penalties || []).forEach(function (x) { box.appendChild(penaltyRow(x, true)); });
    st.before = d.before || 0;
    if (st.before) moreButton(box);
  }

  // ── one player ────────────────────────────────────────────────────────────────────────────────
  function fact(box, label, value) {
    var line = node('div', 'small');
    line.appendChild(node('span', 'text-secondary', label + ' '));
    line.appendChild(typed('span', 'text-break', value));
    box.appendChild(line);
  }

  function section(box, title) {
    box.appendChild(node('div', 'fw-semibold small mt-2', title));
  }

  function aliasRows(p, box) {
    section(box, T('Aliases'));
    if (!(p.aliases || []).length) box.appendChild(node('div', 'small text-secondary', T('No other names.')));
    (p.aliases || []).forEach(function (a) {
      var row = node('div', 'small');
      row.appendChild(typed('span', 'text-break', a.alias + ' '));
      row.appendChild(node('span', 'text-secondary', TF('used {n} times, last {when}', {n: a.used, when: when(a.last)})));
      box.appendChild(row);
    });
    if (p.aliases_more) box.appendChild(node('div', 'small text-secondary', T('Older names are not shown.')));
  }

  function addressRows(p, box) {
    section(box, T('IP addresses'));
    if (p.address_count != null) {
      box.appendChild(node('div', 'small text-secondary', TF('{n} earlier addresses, hidden.', {n: p.address_count})));
      return;
    }
    if (p.ip) fact(box, T('Last:'), p.ip);
    (p.addresses || []).forEach(function (a) {
      var row = node('div', 'small');
      row.appendChild(typed('span', null, a.ip + ' '));
      row.appendChild(node('span', 'text-secondary', TF('used {n} times, last {when}', {n: a.used, when: when(a.last)})));
      box.appendChild(row);
    });
    if (p.addresses_more) box.appendChild(node('div', 'small text-secondary', T('Older addresses are not shown.')));
  }

  function activeBan(p) {
    return (p.penalties || []).some(function (x) { return (x.type === 'Ban' || x.type === 'TempBan') && x.state === 'active'; });
  }

  // Unban (an active ban), Kick and Warn, as this viewer may; with Panel actions off, the line that says where to turn them on.
  function actionBar(p, acts, box) {
    if (!acts || !(acts.unban || acts.kick)) return;
    section(box, T('Actions'));
    if (!acts.on) {
      box.appendChild(node('div', 'small text-secondary', T('Panel actions are off: turn them on in B3 settings on its card to unban, kick or warn from here.')));
      return;
    }
    var reason = node('input', 'form-control form-control-sm fx-12 mb-1');
    reason.id = 'b3p-reason';
    reason.maxLength = 100;
    reason.autocomplete = 'off';
    reason.setAttribute('aria-label', T('Reason, said in the game by B3'));
    reason.placeholder = T('Reason, said in the game by B3');
    box.appendChild(reason);
    var bar = node('div', 'd-flex flex-wrap gap-2');
    if (acts.unban && activeBan(p)) bar.appendChild(button(T('Unban'), 'bi-unlock', 'b3pAct', ['unban', p.id], 'btn-outline-primary'));
    if (acts.kick) {
      bar.appendChild(button(T('Kick'), 'bi-box-arrow-right', 'b3pAct', ['kick', p.id], 'btn-outline-warning'));
      bar.appendChild(button(T('Warn'), 'bi-exclamation-triangle', 'b3pAct', ['warn', p.id], 'btn-outline-warning'));
    }
    box.appendChild(bar);
    box.appendChild(node('div', 'small text-secondary mt-1', T('Kick and Warn reach the player only while they are on the server: the panel finds their slot by name in the game\'s player list.')));
  }

  function drawPlayer(p, masked, acts) {
    var box = el('b3p-player');
    box.textContent = '';
    show('b3p-list', false);
    show('b3p-masked', masked === true);
    var head = node('div', 'd-flex flex-wrap gap-2 align-items-center');
    head.appendChild(typed('strong', 'text-break', p.name || '—'));   // i18n-ignore: a dash
    head.appendChild(typed('span', 'small text-secondary', '@' + p.id));
    if (p.group) head.appendChild(typed('span', 'badge text-bg-secondary', p.group));
    box.appendChild(head);
    fact(box, T('First seen:'), when(p.first_seen));
    fact(box, T('Last seen:'), when(p.last_seen));
    fact(box, T('Connections:'), String(p.connections));
    if (p.guid) fact(box, 'GUID', p.guid);   // i18n-ignore: a label
    aliasRows(p, box);
    addressRows(p, box);
    section(box, T('Penalties'));
    if (!(p.penalties || []).length) box.appendChild(node('div', 'small text-secondary', T('No warnings, kicks or bans.')));
    (p.penalties || []).forEach(function (x) { box.appendChild(penaltyRow(x, false)); });
    if (p.penalties_more) box.appendChild(node('div', 'small text-secondary', T('Older penalties are not shown.')));
    actionBar(p, acts, box);
    if (st.mode) box.appendChild(button(T('Back to the list'), 'bi-arrow-left', 'b3pBack', [], 'btn-outline-secondary mt-2'));
    show('b3p-player', true);
    say('');
    into('b3p');
  }

  // ── actions ───────────────────────────────────────────────────────────────────────────────────
  function search(append) {
    st.busy = true;
    say(T('Searching B3\'s players…'));
    return postJson(api('/players/search'), {q: st.q, after: append ? st.after : ''}).then(function (d) {
      st.busy = false;
      if (d.success === false) return refused(d);
      drawPlayers(d, append);
      return true;
    }).catch(failed);
  }

  function recent(append) {
    st.busy = true;
    say(T('Reading B3\'s latest penalties…'));
    var q = '?kind=' + encodeURIComponent(st.kind) + (append && st.before ? '&before=' + st.before : '');
    return getJson(api('/penalties' + q)).then(function (d) {
      st.busy = false;
      if (d.success === false) return refused(d);
      drawPenalties(d, append);
      return true;
    }).catch(failed);
  }

  // The section sits below every add-on's row: brought into view, so nobody scrolls to find it.
  function into(id) {
    var e = el(id);
    if (e && e.scrollIntoView) e.scrollIntoView({block: 'start', behavior: 'smooth'});
  }

  window.b3pOpen = function () {
    show('b3p', true);
    into('b3p');
    var q = el('b3p-q');
    if (q) q.focus({preventScroll: true});
    if (!st.mode) return window.b3pRecent('all');
    return Promise.resolve(true);
  };

  window.b3pClose = function () { show('b3p', false); };

  window.b3pSearch = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var q = (el('b3p-q').value || '').trim();
    if (st.busy || !q) return Promise.resolve(false);
    st.mode = 'search';
    st.q = q;
    return search(false);
  };

  window.b3pRecent = function (kind) {
    if (st.busy) return Promise.resolve(false);
    st.mode = 'recent';
    st.kind = kind === 'bans' ? 'bans' : 'all';
    return recent(false);
  };

  window.b3pMore = function () {
    if (st.busy) return Promise.resolve(false);
    return st.mode === 'search' ? search(true) : recent(true);
  };

  window.b3pPlayer = function (id) {
    if (st.busy) return Promise.resolve(false);
    st.busy = true;
    say(T('Reading the player\'s history…'));
    return getJson(api('/players/' + Number.parseInt(id, 10))).then(function (d) {
      st.busy = false;
      if (d.success === false) return refused(d);
      drawPlayer(d.player || {}, d.masked, d.actions);
      return true;
    }).catch(failed);
  };

  var ASK = {unban: 'B3 lifts this player\'s active bans.', kick: 'B3 kicks this player from the server now.',
    warn: 'B3 warns this player in the game. Its warnings add up to kicks and temporary bans.'};
  var TITLE = {unban: 'Unban the player', kick: 'Kick the player', warn: 'Warn the player'};

  window.b3pAct = function (action, id) {
    if (st.busy || !ASK[action]) return Promise.resolve(false);
    var r = el('b3p-reason'), reason = r ? r.value.trim() : '', pid = Number.parseInt(id, 10);
    if (action === 'warn' && !reason) {
      say(T('A warning needs a reason.'), 'text-danger');
      if (r) r.focus();
      return Promise.resolve(false);
    }
    return new Promise(function (done) {
      window.confirmDialog({title: T(TITLE[action]), icon: 'person-x', confirmClass: 'btn-warning', confirmLabel: T(TITLE[action]),
        bodyText: T(ASK[action]),
        onConfirm: function () {
          var go = function () {
            st.busy = true;
            say(T('Asking B3…'));
            // Each route written out whole, here where the password was confirmed (the step-up gate reads them).
            var url = action === 'unban' ? api('/players/' + pid + '/unban')
              : (action === 'kick' ? api('/players/' + pid + '/kick') : api('/players/' + pid + '/warn'));
            postJson(url, {reason: reason}).then(function (d) {
              st.busy = false;
              if (d.success === false) { done(refused(d)); return; }
              // The view is read again, so a lifted ban, a kick or a warning shows in it (and Unban is not
              // offered twice); B3's answer is said once it is drawn (also when that read fails: the action was done).
              window.b3pPlayer(pid).then(function () {
                say(d.message || '', d.warning ? 'text-warning' : 'text-success');
                done(true);
              });
            }).catch(function () { failed(); done(false); });
          };
          if (window.stepUpThen) window.stepUpThen(go, window.STEP_UP_TOTP === true); else go();
        }});
    });
  };

  window.b3pBack = function () {
    show('b3p-player', false);
    show('b3p-list', true);
    say('');
  };
})();
