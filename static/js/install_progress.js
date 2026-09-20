// ── Install progress, where the server is ─────────────────────────────────────────────────────
// A game-server install runs for five to forty-five minutes. It has to be watchable, and it has
// to be watchable in the place you are already looking:
//
//   * on the dashboard, a row directly UNDER the server it belongs to;
//   * on Install a Server, a panel on the page you just submitted from.
//
// This was a dismissible card in the corner first. Dismissing it lost it for good, which is the
// wrong shape for something you want to keep an eye on — so it is inline now, and it goes away
// when the install does, not when you close it.
//
// Deliberately quiet: no timer runs unless something is actually installing. It asks once on load,
// polls only while a job is live, and the `servers_changed` broadcast the panel already sends
// wakes it for an install started in another tab or by another user.
(function () {
  var POLL_MS = 3000;
  var timer = null, settling = {};

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // The bar + step line, shared by both hosts. Built with DOM calls, never markup: the server
  // name is user-supplied, and the step text comes from the install job.
  function fill(box, job) {
    var step = box.querySelector('.ip-step'), bar = box.querySelector('.ip-bar'),
        meta = box.querySelector('.ip-meta');
    if (!step) {
      step = el('div', 'ip-step');
      var track = el('div', 'ip-track');
      bar = el('div', 'ip-bar');
      track.appendChild(bar);
      meta = el('div', 'ip-meta');
      box.textContent = '';
      box.appendChild(step); box.appendChild(track); box.appendChild(meta);
    }
    step.textContent = job.step_name || 'Working…';
    bar.style.width = (job.percent || 0) + '%';
    meta.textContent = (job.total ? job.step + '/' + job.total + ' · ' : '')
                     + (job.percent || 0) + '% · ' + (job.elapsed || 0) + 's';
  }

  // ── the dashboard: a row under the server ───────────────────────────────────────────────────
  function dashRow(job) {
    var srvRow = document.querySelector('tr[data-server-id="' + job.id + '"]');
    if (!srvRow) return null;
    var row = document.querySelector('tr[data-progress-for="' + job.id + '"]');
    if (!row) {
      row = el('tr', 'install-progress-row');
      row.setAttribute('data-progress-for', String(job.id));
      var td = el('td');
      td.className = 'pt-0';
      td.colSpan = srvRow.children.length;   // span whatever this table actually has
      row.appendChild(td);
      srvRow.parentNode.insertBefore(row, srvRow.nextSibling);
    }
    fill(row.firstChild, job);
    return row;
  }

  function dropDashRow(id) {
    var row = document.querySelector('tr[data-progress-for="' + id + '"]');
    if (row && row.parentNode) row.parentNode.removeChild(row);
  }

  // ── Install a Server: a panel on the page you submitted from ────────────────────────────────
  function pagePanel(jobs) {
    var host = document.getElementById('install-running');
    if (!host) return;
    var card = document.getElementById('install-running-card');
    if (card) card.hidden = !jobs.length;
    if (!jobs.length) { host.textContent = ''; return; }
    jobs.forEach(function (job) {
      var box = host.querySelector('[data-install-id="' + job.id + '"]');
      if (!box) {
        box = el('div', 'install-progress-inline mb-2');
        box.setAttribute('data-install-id', String(job.id));
        var name = el('div', 'ip-name', job.name);
        name.setAttribute('data-no-i18n', '');
        var body = el('div');
        box.appendChild(name); box.appendChild(body);
        host.appendChild(box);
      }
      fill(box.lastChild, job);
    });
    // Anything no longer running leaves the page panel.
    Array.prototype.forEach.call(host.querySelectorAll('[data-install-id]'), function (b) {
      if (!jobs.some(function (j) { return String(j.id) === b.getAttribute('data-install-id'); })) {
        if (b.parentNode) b.parentNode.removeChild(b);
      }
    });
  }

  // An install that has left the live list has finished or failed. The dashboard already re-renders
  // its card region when the failed set changes (that is what brings up the reason and its
  // buttons), so here the row only has to say how it ended and then get out of the way.
  function settle(id) {
    if (settling[id]) return;
    settling[id] = true;
    fetch(MOUNT + '/api/server/' + id + '/install-status')
      .then(function (r) { return r.json(); })
      .then(function (s) {
        var row = document.querySelector('tr[data-progress-for="' + id + '"]');
        if (row) {
          var bad = (s.status === 'failed' || s.status === 'interrupted');
          var td = row.firstChild;
          td.textContent = '';
          var line = el('div', 'ip-step ' + (bad ? 'text-danger' : 'text-success'),
                        s.message || (bad ? 'Install failed' : 'Installed'));
          line.setAttribute('data-no-i18n', '');
          td.appendChild(line);
          // A failure stays until the card region re-renders with the banner that can act on it;
          // a success has nothing left to say.
          if (!bad) setTimeout(function () { dropDashRow(id); }, 8000);
        }
        pagePanel([]);   // the page panel only ever shows what is RUNNING
      })
      .catch(function () { dropDashRow(id); })
      .then(function () { delete settling[id]; });
  }

  function stop() { if (timer) { clearInterval(timer); timer = null; } }

  function apply(jobs) {
    var live = {};
    jobs.forEach(function (j) { live[j.id] = true; dashRow(j); });
    Array.prototype.forEach.call(document.querySelectorAll('tr[data-progress-for]'), function (r) {
      var id = r.getAttribute('data-progress-for');
      if (!live[id]) settle(id);
    });
    pagePanel(jobs);
  }

  function tick() {
    fetch(MOUNT + '/api/installs', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var jobs = d.installs || [];
        apply(jobs);
        if (!jobs.length) stop();
      })
      .catch(function () { stop(); });
  }

  window.watchInstallsNow = function () {
    tick();
    if (!timer) timer = setInterval(tick, POLL_MS);
  };

  document.addEventListener('DOMContentLoaded', function () {
    fetch(MOUNT + '/api/installs', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var jobs = d.installs || [];
        if (jobs.length) { apply(jobs); if (!timer) timer = setInterval(tick, POLL_MS); }
      })
      .catch(function () {});
    if (window.onServersChanged) window.onServersChanged(function () { window.watchInstallsNow(); });
  });
})();
