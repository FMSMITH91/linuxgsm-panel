// Warn players first: the Schedule tab's restart, stop or update that sends chat warnings before it
// runs (server_files.html #sch-wrap; composed and checked on the server by
// panel/services/schedule_chains.py). This script only collects the action and the warnings; the
// panel builds the cron line. Loaded only for games whose console chat command the panel knows.
// Rows are built with createElement/textContent: messages are the viewer's own text.
(function () {
  var MAX_STEPS = 5;
  var MAX_MIN = 60;
  var MAX_TEXT = 120;
  var ACTIONS = ['restart', 'stop', 'update'];
  // The default message per action, said with the minutes it is sent at. Plain words; edited freely.
  var DEFAULTS = {
    restart: ['The server restarts in {n} minutes', 'The server restarts in 1 minute'],
    stop: ['The server shuts down in {n} minutes', 'The server shuts down in 1 minute'],
    update: ['The server updates in {n} minutes and may restart', 'The server updates in 1 minute and may restart']
  };
  var LABELS = {restart: 'Restart', stop: 'Stop', update: 'Update'};
  // When the action lands: one whole sentence per action, so each language words it its own way.
  var LEAD = {
    restart: ['The warnings start at the scheduled time; the restart runs {n} minutes later.',
              'Next: warnings from {start}, restart at {end}.'],
    stop: ['The warnings start at the scheduled time; the stop runs {n} minutes later.',
           'Next: warnings from {start}, stop at {end}.'],
    update: ['The warnings start at the scheduled time; the update runs {n} minutes later.',
             'Next: warnings from {start}, update at {end}.']
  };

  function el(id) { return document.getElementById(id); }
  function on() { var c = el('sch-on'); return !!(c && c.checked); }
  function action() {
    var a = el('sch-action');
    return a && ACTIONS.indexOf(a.value) >= 0 ? a.value : 'restart';
  }
  function defaultText(act, n) {
    var d = DEFAULTS[act] || DEFAULTS.restart;
    return n === 1 ? t(d[1]) : tf(d[0], {n: n});
  }
  function rows() {
    var box = el('sch-steps');
    return box ? Array.prototype.slice.call(box.children) : [];
  }
  function parts(row) { return {min: row.children[0], text: row.children[2]}; }

  // A message still showing its default follows the row's minutes and the action; one the viewer
  // typed is left alone.
  function refreshDefaults() {
    rows().forEach(function (row) {
      var p = parts(row), n = parseInt(p.min.value, 10);
      if (p.text.getAttribute('data-auto') === '1' && n >= 1) p.text.value = defaultText(action(), n);
    });
  }

  function makeRow(minutes, text) {
    var row = document.createElement('div');
    row.className = 'd-flex flex-wrap gap-1 align-items-center mb-1';
    var min = document.createElement('input');
    min.type = 'number';
    min.min = '1';
    min.max = String(MAX_MIN);
    min.className = 'form-control form-control-sm sch-min';
    min.value = String(minutes);
    min.setAttribute('aria-label', t('Minutes before the action'));
    var unit = document.createElement('span');
    unit.className = 'small text-secondary';
    unit.textContent = t('min before');
    var msg = document.createElement('input');
    msg.type = 'text';
    msg.maxLength = MAX_TEXT;
    msg.className = 'form-control form-control-sm sch-text';
    msg.setAttribute('aria-label', t('Message to the players'));
    msg.setAttribute('data-no-i18n', '');
    msg.setAttribute('data-auto', text === null ? '1' : '0');
    msg.value = text === null ? defaultText(action(), minutes) : text;
    var del = document.createElement('button');
    del.type = 'button';
    del.className = 'btn btn-sm btn-link text-danger p-0';
    del.title = t('Remove this warning');
    del.setAttribute('aria-label', t('Remove this warning'));
    var icon = document.createElement('i');
    icon.className = 'bi bi-x-lg';
    del.appendChild(icon);
    row.appendChild(min);
    row.appendChild(unit);
    row.appendChild(msg);
    row.appendChild(del);
    return row;
  }

  function addRow(minutes, text) {
    var box = el('sch-steps');
    if (!box || rows().length >= MAX_STEPS) return;
    box.appendChild(makeRow(minutes, text));
    syncAdd();
  }

  function syncAdd() {
    var add = el('sch-add');
    if (add) add.disabled = rows().length >= MAX_STEPS;
  }

  function clearRows() {
    var box = el('sch-steps');
    if (box) box.textContent = '';
  }

  // The longest lead time: the first warning goes out at the scheduled time, the action this long after.
  function lead() {
    var most = 0;
    rows().forEach(function (row) {
      var n = parseInt(parts(row).min.value, 10);
      if (n > most) most = n;
    });
    return most;
  }

  function fmt(dt) {
    return dt.toLocaleString([], {weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit',
                                  minute: '2-digit'});
  }

  function when() {
    var w = el('sch-when');
    if (!w) return;
    var n = lead();
    if (!on() || !n) { w.textContent = ''; return; }
    var say = LEAD[action()], text = tf(say[0], {n: n}), next = window.schNextRun;
    if (next instanceof Date) {
      text += ' ' + tf(say[1], {start: fmt(next), end: fmt(new Date(next.getTime() + n * 60000))});
    }
    w.textContent = text;
  }

  function show(state) {
    var panel = el('sch-panel'), cmd = el('cron-cmd'), box = el('sch-on');
    if (box) box.checked = state;
    if (panel) panel.hidden = !state;
    if (cmd) {
      cmd.disabled = state;
      cmd.required = !state;
    }
    if (state && !rows().length) {
      addRow(5, null);
      addRow(1, null);
    }
    when();
  }

  // What the form posts as `chain`, or null when Warn players first is off. Checked here so the
  // viewer sees the problem at once; the server checks all of it again.
  function body() {
    if (!on()) return null;
    var warnings = rows().map(function (row) {
      var p = parts(row);
      return {minutes: parseInt(p.min.value, 10), message: String(p.text.value || '').trim()};
    });
    return {action: action(), warnings: warnings};
  }

  function problem(chain) {
    if (!chain) return '';
    if (!chain.warnings.length) return t('Add at least one warning, or turn off Warn players first.');
    var last = MAX_MIN + 1;
    for (var i = 0; i < chain.warnings.length; i++) {
      var w = chain.warnings[i];
      if (!(w.minutes >= 1 && w.minutes <= MAX_MIN)) return t('Each warning is 1 to 60 minutes before the action.');
      if (w.minutes >= last) {
        return t('Each warning must come later than the one before it (fewer minutes before the action).');
      }
      if (!w.message || w.message.length > MAX_TEXT) return t('Each warning needs a message of 1 to 120 characters.');
      if (w.message.indexOf(';') >= 0) {
        return t("A warning can't contain ; (game consoles read it as the start of another command).");
      }
      last = w.minutes;
    }
    return '';
  }

  // Editing a listed chain: the form shows its action and warnings as they were saved.
  function fill(chain) {
    clearRows();
    if (!chain) { show(false); syncAdd(); return; }
    var a = el('sch-action');
    if (a) a.value = chain.action;
    (chain.steps || []).forEach(function (s) { addRow(s.minutes, s.message); });
    show(true);
  }

  function reset() {
    clearRows();
    var a = el('sch-action');
    if (a) a.value = 'restart';
    show(false);
    syncAdd();
  }

  // The job list's words for a chain, e.g. "Restart, warnings 5, 1 min before".
  function summary(chain) {
    var mins = (chain.steps || []).map(function (s) { return s.minutes; }).join(', ');
    var key = (chain.steps || []).length === 1 ? '{action}, warning {mins} min before'
                                               : '{action}, warnings {mins} min before';
    return tf(key, {action: t(LABELS[chain.action] || chain.action), mins: mins});
  }

  function wire() {
    var box = el('sch-on'), steps = el('sch-steps'), add = el('sch-add'), act = el('sch-action');
    if (!box) return;
    box.addEventListener('change', function () { show(box.checked); });
    if (act) act.addEventListener('change', function () { refreshDefaults(); when(); });
    if (add) add.addEventListener('click', function () {
      var n = rows().length ? Math.max(1, parseInt(parts(rows()[rows().length - 1]).min.value, 10) - 1) : 5;
      addRow(n, null);
      when();
    });
    if (steps) {
      steps.addEventListener('input', function (ev) {
        if (ev.target.classList.contains('sch-text')) ev.target.setAttribute('data-auto', '0');
        refreshDefaults();
        when();
      });
      steps.addEventListener('click', function (ev) {
        var del = ev.target.closest('button');
        if (!del) return;
        steps.removeChild(del.parentNode);
        syncAdd();
        when();
      });
    }
    // A browser that restored the box as ticked (back/forward) gets the panel it implies.
    show(box.checked);
  }

  window.schChain = {body: body, problem: problem, fill: fill, reset: reset, summary: summary, when: when};
  wire();
})();
