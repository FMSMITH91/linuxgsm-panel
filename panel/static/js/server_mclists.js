// The server page's Player Lists card (server_detail.html #mcl-card, Java Minecraft servers only).
// The lists are read from the server's own files and changed by console command while it runs
// (panel/routes/mc_lists.py); the server rewrites its files, so the list is read again after a change.
// Rows are built with textContent only: names, reasons and addresses come from the server's files.
(function () {
  var LABELS = {
    ops: {placeholder: 'Player name', add: 'Make operator', remove: 'Remove operator'},
    whitelist: {placeholder: 'Player name', add: 'Add to whitelist', remove: 'Remove from whitelist'},
    bans: {placeholder: 'Player name', add: 'Ban', remove: 'Unban'},
    ipbans: {placeholder: 'IPv4 address', add: 'Ban address', remove: 'Unban address'}
  };
  var EMPTY = {ops: 'No operators.', whitelist: 'Nobody is on the whitelist.',
               bans: 'No banned players.', ipbans: 'No banned addresses.'};
  var NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
  var IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  var state = {which: 'ops', running: false, canChange: false, seq: 0};

  function el(id) { return document.getElementById(id); }
  function url(which) { return MOUNT + '/api/server/' + serverId + '/mc-lists/' + which; }

  function note(text) {
    var n = el('mcl-note');
    if (!n) return;
    n.textContent = text || '';
    n.hidden = !text;
  }

  function msg(text, cls) {
    var m = el('mcl-msg');
    if (!m) return;
    m.className = 'small mt-1 ' + (cls || '');
    m.textContent = text || '';
  }

  // The add form and the switch follow what the last read said: changes only while running, and
  // only for an account that may send console commands.
  function setEnabled() {
    var on = state.running && state.canChange;
    ['mcl-value', 'mcl-reason', 'mcl-add', 'mcl-wl-on'].forEach(function (id) {
      var e = el(id);
      if (e) e.disabled = !on;
    });
  }

  function detailOf(which, r) {
    if (which === 'ops') return r.level ? tf('Level {n}', {n: r.level}) : '';
    if (which === 'bans' || which === 'ipbans') return r.reason || '';
    return '';
  }

  function removeButton(which, value) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm btn-outline-danger py-0';
    b.setAttribute('data-action', 'mclRemove');
    b.setAttribute('data-args', JSON.stringify([which, value]));
    b.setAttribute('aria-label', tf('{action}: {name}', {action: t(LABELS[which].remove), name: value}));
    b.title = t(LABELS[which].remove);
    var icon = document.createElement('i');
    icon.className = 'bi bi-x-lg';
    b.appendChild(icon);
    return b;
  }

  function rowFor(which, r) {
    var value = which === 'ipbans' ? r.ip : r.name;
    var tr = document.createElement('tr');
    var who = document.createElement('td');
    who.className = 'text-break';
    who.textContent = value || '';
    var det = document.createElement('td');
    det.className = 'text-secondary text-break';
    det.textContent = detailOf(which, r);
    var act = document.createElement('td');
    act.className = 'text-end';
    act.style.width = '1%';
    if (state.running && state.canChange && value) act.appendChild(removeButton(which, value));
    tr.appendChild(who); tr.appendChild(det); tr.appendChild(act);
    return tr;
  }

  function showRows(which, d) {
    var body = el('mcl-rows');
    body.textContent = '';
    (d.entries || []).forEach(function (r) { body.appendChild(rowFor(which, r)); });
    el('mcl-table').hidden = !(d.entries || []).length;
    var parts = [];
    if (!state.running) parts.push(t('The server is stopped. These lists can be changed while it is running.'));
    if (!(d.entries || []).length) parts.push(t(EMPTY[which]));
    if (d.truncated) parts.push(t('Only the first 1000 entries are shown.'));
    note(parts.join(' '));
  }

  function showWhitelist(which, d) {
    var row = el('mcl-wl-row'), sw = el('mcl-wl-on');
    row.hidden = which !== 'whitelist' || d.whitelist_on === null || d.whitelist_on === undefined;
    if (which === 'whitelist' && sw) sw.checked = !!d.whitelist_on;
  }

  function show(which, seq, d) {
    if (seq !== state.seq || which !== state.which) return;   // an older tab's answer
    if (!d || d.success === false || d.error) {
      el('mcl-table').hidden = true;
      el('mcl-wl-row').hidden = true;
      note((d && d.error) || t('This list could not be read from the server, so it is not shown.'));
      return;
    }
    state.running = !!d.running;
    state.canChange = !!d.can_change && el('mcl-card').getAttribute('data-can-change') === '1';
    setEnabled();
    showWhitelist(which, d);
    showRows(which, d);
  }

  function load(which, after) {
    var seq = ++state.seq;
    fetch(url(which))
      .then(function (r) { return r.json(); })
      .then(function (d) { show(which, seq, d); if (after && seq === state.seq) after(d); })
      .catch(function () { show(which, seq, null); });
  }

  // Whether the list read after a change shows it. A server sends no answer the panel can read for
  // a command it ignores: `op` with a name that is no Minecraft account changes nothing.
  function applied(body, d) {
    if (!d || d.success === false || d.error) return true;   // nothing to judge by
    if (body.action === 'on' || body.action === 'off') {
      return d.whitelist_on === null || d.whitelist_on === undefined || d.whitelist_on === (body.action === 'on');
    }
    var want = String(body.value || '').toLowerCase();
    var there = (d.entries || []).some(function (e) { return String(e.name || e.ip || '').toLowerCase() === want; });
    return there === (body.action === 'add');
  }

  function post(body) {
    var which = state.which;
    msg(t('Sending…'), 'text-secondary');
    return fetch(url(which), {method: 'POST', headers: {'Content-Type': 'application/json'},
                              body: JSON.stringify(body)})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var ok = !!(d && d.success);
        msg((d && d.message) || t('Failed'), ok ? 'text-success' : 'text-danger');
        // The server writes its file when it runs the command, a moment after the send.
        if (ok) {
          setTimeout(function () {
            if (state.which !== which) return;
            load(which, function (after) {
              if (!applied(body, after)) {
                msg(t("The server did not apply this. A player's name must belong to an existing Minecraft account; the console shows the server's reply."), 'text-warning');
              }
            });
          }, 1500);
        }
        return ok;
      })
      .catch(function () { msg(t('Failed'), 'text-danger'); return false; });
  }

  // The same checks the server makes, so a typo is said at once; the server refuses it either way.
  function refusal(which, value, reason) {
    if (which === 'ipbans') {
      if (value.indexOf(':') >= 0) return t("Minecraft's ban-ip cannot take an IPv6 address. Ban the player by name instead.");
      if (!IPV4_RE.test(value)) return t('Enter an IPv4 address, such as 203.0.113.7.');
    } else if (!NAME_RE.test(value)) {
      return t('A player name is 3 to 16 letters, digits or underscores.');
    }
    if (reason.length > 100 || /[\u0000-\u001f\u007f-\u009f]/.test(reason)) {
      return t('A reason is at most 100 characters, on one line, with no control characters.');
    }
    return '';
  }

  window.mclTab = function (which) {
    if (!LABELS[which]) return;
    state.which = which;
    document.querySelectorAll('[data-mcl-tab]').forEach(function (b) {
      var on = b.getAttribute('data-mcl-tab') === which;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
    });
    el('mcl-panel').setAttribute('aria-labelledby', 'mcl-tab-' + which);
    var v = el('mcl-value'), rs = el('mcl-reason'), lbl = el('mcl-add-label');
    if (v) {
      v.placeholder = t(LABELS[which].placeholder);
      v.setAttribute('aria-label', t(LABELS[which].placeholder));
      v.maxLength = which === 'ipbans' ? 15 : 16;
      v.value = '';
    }
    if (rs) { rs.hidden = which !== 'bans' && which !== 'ipbans'; rs.value = ''; }
    if (lbl) lbl.textContent = t(LABELS[which].add);
    msg('');
    el('mcl-table').hidden = true;
    el('mcl-wl-row').hidden = true;
    note(t('Loading…'));
    load(which);
  };

  window.mclAdd = function (ev) {
    if (ev) ev.preventDefault();
    var which = state.which, value = el('mcl-value').value.trim();
    var rs = el('mcl-reason'), reason = (rs && !rs.hidden) ? rs.value.trim() : '';
    var why = refusal(which, value, reason);
    if (why) { msg(why, 'text-danger'); return false; }
    void post({action: 'add', value: value, reason: reason}).then(function (ok) {   // post ends in its own .catch
      if (ok) { el('mcl-value').value = ''; if (rs) rs.value = ''; }
    });
    return false;
  };

  window.mclRemove = function (which, value) {
    if (which !== state.which) return;
    void post({action: 'remove', value: value});   // post ends in its own .catch
  };

  window.mclWhitelistSwitch = function (box) {
    var wanted = box.checked;
    void post({action: wanted ? 'on' : 'off'}).then(function (ok) {   // post ends in its own .catch
      if (!ok) box.checked = !wanted;   // not sent: the switch shows what the server still has
    });
  };

  // Left and Right move between the four tabs, as a tab list does.
  document.addEventListener('keydown', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('[data-mcl-tab]') : null;
    if (!b || (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft')) return;
    var tabs = Array.prototype.slice.call(document.querySelectorAll('[data-mcl-tab]'));
    var i = (tabs.indexOf(b) + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
    e.preventDefault();
    tabs[i].focus();
    window.mclTab(tabs[i].getAttribute('data-mcl-tab'));
  });

  function start() { if (el('mcl-card')) load(state.which); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
