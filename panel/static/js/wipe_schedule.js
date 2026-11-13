// The Schedule tab's scheduled wipe card (server_files.html #wipe-card): Rust's map/full wipe, and the
// world reset of Minecraft Java and Factorio (#wipe-kind is then a hidden input holding "reset").
// The server runs the wipe (panel/routes/wipe_schedule.py): a backup first, no wipe if it failed.
// Times are entered in the viewer's own zone, which is sent with the schedule and kept with it.
(function () {
  var URL_ = function () { return MOUNT + '/api/server/' + serverId + '/wipe-schedule'; };
  function el(id) { return document.getElementById(id); }
  function viewerTz() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; }
  }
  function msg(text, cls) {
    var m = el('wipe-msg');
    if (!m) return;
    m.className = 'small ' + (cls || '');
    m.textContent = text || '';
  }

  // The form takes the stored schedule back, so Save re-saves what is there.
  function showForm(d) {
    var kind = el('wipe-kind');
    if (kind.tagName === 'SELECT') kind.value = d.kind || 'map';   // a world reset has one kind, fixed
    el('wipe-preset').value = d.preset || 'first-thursday';
    if (d.at) el('wipe-at').value = d.at;
    el('wipe-cron').value = d.preset === 'custom' ? (d.cron || '') : '';
    el('wipe-wait').checked = d.wait_empty !== false;
  }

  // When it runs next, how the last run went, and what a due wipe is waiting for.
  function showLast(last) {
    el('wipe-last-row').hidden = !last;
    if (!last) return;
    el('wipe-last').textContent = new Date(last.at * 1000).toLocaleString() + ' — '
      + (last.ok ? '✓ ' : '✗ ') + (last.detail || '');
    el('wipe-last').className = last.ok ? 'text-success' : 'text-danger';
  }

  function showStatus(d, on) {
    var next = on && d.next;
    el('wipe-next-row').hidden = !next;
    if (next) el('wipe-next').textContent = new Date(d.next * 1000).toLocaleString();
    showLast(d.last);
    var waiting = on && d.pending && d.wait;
    el('wipe-wait-row').hidden = !waiting;
    if (waiting) el('wipe-wait-why').textContent = d.wait;
  }

  function show(d) {
    if (!d || !d.success) return;
    var on = !!d.enabled;
    el('wipe-state').textContent = on ? 'On' : 'Off';   // English: the page translator owns it (On/Off share a translation)
    el('wipe-off').hidden = !on;
    if (on) showForm(d);
    window.wipePresetChanged();
    showStatus(d, on);
  }

  function post(body) {
    msg(t('Saving…'), 'text-secondary');
    return fetch(URL_(), {method: 'POST', headers: {'Content-Type': 'application/json'},
                          body: JSON.stringify(body)})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d && d.success) { msg(t('Saved'), 'text-success'); show(d); }
        else msg((d && d.message) || t('Failed'), 'text-danger');
      })
      .catch(function () { msg(t('Failed'), 'text-danger'); });
  }

  window.wipePresetChanged = function () {
    var custom = el('wipe-preset').value === 'custom';
    el('wipe-cron-col').hidden = !custom;
    el('wipe-at-col').hidden = custom;
  };

  // Saving a schedule is the destructive choice, so it is confirmed, naming what will be deleted.
  window.saveWipeSchedule = function (ev) {
    ev.preventDefault();
    var kind = el('wipe-kind').value;
    var body = {enabled: true, kind: kind, preset: el('wipe-preset').value,
                at: el('wipe-at').value, cron: el('wipe-cron').value, tz: viewerTz(),
                wait_empty: el('wipe-wait').checked};
    var said = {
      full: [t('Schedule a full wipe?'), t('On every scheduled run the map, saves, blueprints and player data are deleted. A backup is taken first; if it fails, nothing is wiped.')],
      map: [t('Schedule a map wipe?'), t('On every scheduled run the map and saves are deleted; blueprints are kept. A backup is taken first; if it fails, nothing is wiped.')],
      reset: [t('Schedule a world reset?'), t('On every scheduled run the world is deleted and a new one is created. A backup is taken first; if it fails, nothing is deleted.')]
    }[kind] || [];
    window.confirmDialog({
      title: said[0],
      icon: 'exclamation-triangle-fill', confirmClass: 'btn-danger', confirmLabel: t('Schedule wipe'),
      bodyText: said[1],
      onConfirm: function () { void post(body); }   // post ends in its own .catch
    });
    return false;
  };

  window.turnOffWipeSchedule = function () { void post({enabled: false}); };   // post ends in its own .catch

  document.addEventListener('DOMContentLoaded', function () {
    if (!el('wipe-card')) return;
    fetch(URL_()).then(function (r) { return r.ok ? r.json() : null; }).then(show).catch(function () {});
  });
})();
