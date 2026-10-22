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
// Deliberately quiet: no timer runs unless something is actually installing (or the last read
// failed, so nobody knows yet). It asks once on load, polls only while a job is live, and the `servers_changed` broadcast the panel already sends
// wakes it for an install started in another tab or by another user.
(function () {
  var POLL_MS = 3000;
  var timer = null, settling = {};
  // Endings still meant to be on screen, by server id: {kind, message}. The row lives inside
  // #server-cards, which the dashboard swaps wholesale when another server appears or goes or
  // another install fails — and nothing rebuilt it, because /api/installs lists only running jobs.
  // A caveat ("Installed, with a warning") is shown nowhere else, so it vanished undismissed.
  var endings = {};
  // Ids the last answered poll listed as running. An install that ended between a swap (which took
  // its row) and the next poll (which would have rebuilt it) had no row left to settle, so its
  // ending was never read at all.
  var wasLive = {};

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
  function srvRowOf(id) { return document.querySelector('tr[data-server-id="' + id + '"]'); }

  function newDashRow(srvRow, id) {
    var row = el('tr', 'install-progress-row');
    row.setAttribute('data-progress-for', String(id));
    var td = el('td');
    td.className = 'pt-0';
    td.colSpan = srvRow.children.length;   // span whatever this table actually has
    row.appendChild(td);
    srvRow.parentNode.insertBefore(row, srvRow.nextSibling);
    return row;
  }

  function dashRow(job) {
    var srvRow = srvRowOf(job.id);
    if (!srvRow) return null;
    var row = document.querySelector('tr[data-progress-for="' + job.id + '"]');
    if (!row) {
      row = newDashRow(srvRow, job.id);
    } else if (row.hasAttribute('data-settled')) {
      // The same server is installing again (a retry) while its last ending is still on screen.
      // That line has an .ip-step and no bar, so fill() would find the step, skip building, and
      // throw on the missing bar — aborting apply() for every other job on this poll.
      row.removeAttribute('data-settled');
      row.firstChild.textContent = '';
    }
    fill(row.firstChild, job);
    return row;
  }

  function dropDashRow(id) {
    var row = document.querySelector('tr[data-progress-for="' + id + '"]');
    if (row && row.parentNode) row.parentNode.removeChild(row);
  }

  // The delayed removal of a clean ending — which must not take the row with it if that server
  // has started installing again in the meantime and the row is live progress once more.
  function dropSettledRow(id) {
    var row = document.querySelector('tr[data-progress-for="' + id + '"]');
    if (row && row.hasAttribute('data-settled')) dropDashRow(id);
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

  // How an install that has left the live list ENDED, from its /install-status answer. Four
  // answers, not two. A `done` job can carry a caveat (warn: the game took a port another server
  // already uses, or it installed and did not start) that is shown nowhere else. And an answer
  // that is not a finished job at all — `none` once the job was pruned or dismissed, an error
  // body, a non-2xx — says nothing about how it went. Everything that was not failed used to be
  // shown as a green "Installed" and removed after eight seconds, caveats included.
  function outcome(ok, s) {
    if (!ok || !s) return 'unknown';
    if (s.status === 'done') return s.warn ? 'warn' : 'ok';
    if (s.status === 'failed' || s.status === 'interrupted') return 'bad';
    return 'unknown';
  }

  // What each ending looks like. Only a clean success has nothing left to say and removes itself;
  // a failure stays until the card region re-renders with the banner that can act on it, and a
  // caveat stays until the operator dismisses it, because this row is the only place it appears.
  var SETTLED = {
    ok:   { cls: 'text-success', text: 'Installed', drop: 8000, keep: true },
    warn: { cls: 'text-warning', text: 'Installed, with a warning', dismiss: true, keep: true },
    bad:  { cls: 'text-danger', text: 'Install failed' }
  };

  // Write one ending into its row. `keep` endings (a clean one until its timer, a caveat until
  // Dismiss) are remembered in `endings`, so a swap of the card region that took the row does not
  // take the ending: drawEndings() puts it back. A failure is not kept — the swap that takes it is
  // the one that brings up the banner which says the same and can act on it.
  function drawEnding(row, id, end) {
    var view = SETTLED[end.kind], td = row.firstChild;
    td.textContent = '';
    var line = el('div', 'ip-step ' + view.cls, end.message || view.text);
    // Only the job's own text is kept from the translator. The fallback ("Installed",
    // "Install failed") is the panel's, a catalog key, and was left English with it.
    if (end.message) line.setAttribute('data-no-i18n', '');
    td.appendChild(line);
    if (view.dismiss) {
      var btn = el('button', 'btn btn-sm btn-outline-secondary mt-1', 'Dismiss');
      btn.type = 'button';
      btn.addEventListener('click', function () {
        if (endings[id] === end) delete endings[id];
        dropDashRow(id);
      });
      td.appendChild(btn);
    }
  }

  // Put back every kept ending whose row is missing: after the dashboard swapped #server-cards
  // (afterDashRefresh calls this) and on every poll. A server that is gone takes its ending with it.
  function drawEndings() {
    Object.keys(endings).forEach(function (id) {
      if (document.querySelector('tr[data-progress-for="' + id + '"]')) return;
      var srvRow = srvRowOf(id);
      if (!srvRow) { delete endings[id]; return; }
      var row = newDashRow(srvRow, id);
      drawEnding(row, id, endings[id]);
      row.setAttribute('data-settled', endings[id].kind);   // as settle() marks it
    });
  }
  window._r34c_ipRedraw = drawEndings;

  // An install that has left the live list has finished or failed. The dashboard already re-renders
  // its card region when the failed set changes (that is what brings up the reason and its
  // buttons), so here the row only has to say how it ended.
  function settle(id) {
    if (settling[id]) return;
    settling[id] = true;
    var release = function () { delete settling[id]; };
    // One verdict, shown: remembered when it is a kept kind, drawn in its row (rebuilt if a swap
    // took the row while this was being asked), and a clean one removed on its timer.
    function show(res) {
      var row = document.querySelector('tr[data-progress-for="' + id + '"]');
      var view = SETTLED[res.kind];
      if (!view) {
        // No verdict to show, so show none: the card region says what state the server is in.
        if (row) dropDashRow(id);
        return;
      }
      var end = { kind: res.kind, message: res.s.message || '' };
      if (view.keep) endings[id] = end;
      if (!row && view.keep && srvRowOf(id)) row = newDashRow(srvRowOf(id), id);
      if (row) {
        drawEnding(row, id, end);
        // Settled once, for good: the row keeps data-progress-for, so without this every later
        // poll (while any other install keeps the timer alive) fetched install-status again —
        // for a lost job, another SSH probe of the host each time — and rewrote the row.
        row.setAttribute('data-settled', res.kind);
      }
      if (view.drop) {
        setTimeout(function () {
          if (endings[id] === end) delete endings[id];
          dropSettledRow(id);
        }, view.drop);
      }
    }
    fetch(MOUNT + '/api/server/' + id + '/install-status')
      .then(function (r) {
        return r.json().then(function (s) { return { kind: outcome(r.ok, s), s: s || {} }; });
      })
      .then(function (res) {
        show(res);
        pagePanel([]);   // the page panel only ever shows what is RUNNING
      })
      .catch(function () { dropDashRow(id); })
      .then(release, release);   // released even if dropDashRow throws
  }

  function stop() { if (timer) { clearInterval(timer); timer = null; } }

  function apply(jobs) {
    var live = {};
    // A server installing again is live progress, not its last ending.
    jobs.forEach(function (j) { live[j.id] = true; delete endings[j.id]; dashRow(j); });
    Array.prototype.forEach.call(document.querySelectorAll('tr[data-progress-for]'), function (r) {
      var id = r.getAttribute('data-progress-for');
      if (!live[id] && !r.hasAttribute('data-settled')) settle(id);
    });
    // ...and one that was running at the last answer and has no row now (a swap took it). Only
    // where its server's row is: Install a Server has none, and settle() empties its page panel.
    Object.keys(wasLive).forEach(function (id) {
      if (live[id] || !srvRowOf(id)) return;
      var r = document.querySelector('tr[data-progress-for="' + id + '"]');
      if (!r || !r.hasAttribute('data-settled')) settle(id);
    });
    wasLive = live;
    drawEndings();
    pagePanel(jobs);
  }

  // A poll that FAILED is not the same answer as "nothing is installing". This used to call
  // stop() on any error, which clears the interval — and nothing re-arms it: watchInstallsNow is
  // only called from the servers_changed socket event and the install/retry form hooks, and
  // servers_changed fires at the START and END of an install, never per step. So one dropped
  // request ended progress for the rest of the page's life, and the bar stayed on screen showing
  // the last step it happened to receive, which reads as a live measurement of an install the
  // panel is no longer watching.
  var missed = 0;

  // BOTH places progress is shown. This read only the dashboard's rows, so on Install a Server —
  // where the operator who just started it is watching — the box kept the last step, percent and
  // elapsed time it received, frozen and undimmed, exactly the false reading described above.
  // A settled row is excluded: it reports an ending, not a reading that can go stale.
  var PROGRESS_HOSTS = 'tr[data-progress-for]:not([data-settled]), #install-running [data-install-id]';

  function markStale(on) {
    Array.prototype.forEach.call(document.querySelectorAll(PROGRESS_HOSTS),
      function (r) {
        r.classList.toggle('ip-stale', !!on);
        var meta = r.querySelector('.ip-meta');
        if (!meta) return;
        if (on) {
          if (meta.getAttribute('data-was') === null) {
            meta.setAttribute('data-was', meta.textContent);
          }
          meta.textContent = 'Progress unavailable — still trying';
        } else if (meta.getAttribute('data-was') !== null) {
          meta.textContent = meta.getAttribute('data-was');
          meta.removeAttribute('data-was');
        }
      });
  }

  function tick() {
    fetch(MOUNT + '/api/installs', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        // An error reply ({success:false, message, error} from the catch-all) is JSON too, and
        // read as `installs || []` it was "nothing is installing": every live row settled, a
        // still-running install's row was dropped, and stop() ended the poll. A miss, not an answer.
        if (!d || !Array.isArray(d.installs)) throw new Error('not a reading');
        missed = 0;
        markStale(false);
        var jobs = d.installs;
        apply(jobs);
        // Only an ANSWER that says nothing is installing stops the poll.
        if (!jobs.length) stop();
      })
      .catch(function () {
        // Keep the interval. Say so on the second consecutive miss rather than the first, so a
        // single dropped request does not flicker the row.
        missed += 1;
        if (missed >= 2) markStale(true);
      });
  }

  window.watchInstallsNow = function () {
    tick();
    if (!timer) timer = setInterval(tick, POLL_MS);
  };

  document.addEventListener('DOMContentLoaded', function () {
    // The load read goes through the poller. It had its own fetch that armed the interval only on
    // a reply listing jobs, so a failed request or an error reply (a phone just woken, the panel
    // restarting, a 500) armed nothing, and an install already running showed no progress until it
    // ended: the one-dropped-request bug tick's miss path exists to prevent. tick stops on a real
    // answer that nothing is installing, so an idle page still makes one request and keeps no timer.
    window.watchInstallsNow();
    if (window.onServersChanged) window.onServersChanged(function () { window.watchInstallsNow(); });
  });
})();
