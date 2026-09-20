// ── Install progress, from wherever you are ───────────────────────────────────────────────────
// A game-server install runs for five to forty-five minutes. Its progress row lives on the Game
// Servers page, and nowhere else: start an install from "Install a Server" and you got a toast and
// then nothing, and the dashboard showed the server as "installing" with no progress at all. So
// this puts the live step and bar in the corner of every page instead.
//
// It is deliberately quiet: no timer runs unless something is actually installing. The widget asks
// once on page load, then polls only while a job is live, and the `servers_changed` broadcast the
// panel already sends when a server is added wakes it for an install started in another tab or by
// another user.
(function () {
  var POLL_MS = 3000;
  var timer = null, box = null, cards = {}, done = {};

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function ensureBox() {
    if (box) return box;
    box = el('div', 'install-progress-stack');
    box.setAttribute('aria-live', 'polite');
    document.body.appendChild(box);
    return box;
  }

  // One card per install. Built with DOM calls rather than a markup string: the server name is
  // user-supplied and this file has no business concatenating it into HTML.
  function card(job) {
    var c = cards[job.id];
    if (!c) {
      var root = el('div', 'install-progress-card');
      var head = el('div', 'ipc-head');
      var name = el('span', 'ipc-name', job.name);
      name.setAttribute('data-no-i18n', '');   // a server's own name is never a catalog key
      var close = el('button', 'ipc-close');
      close.type = 'button';
      close.setAttribute('aria-label', 'Dismiss');
      close.textContent = '×';
      close.addEventListener('click', function () { dismiss(job.id); });
      head.appendChild(name);
      head.appendChild(close);
      var step = el('div', 'ipc-step');
      var track = el('div', 'ipc-track');
      var bar = el('div', 'ipc-bar');
      track.appendChild(bar);
      var meta = el('div', 'ipc-meta');
      root.appendChild(head);
      root.appendChild(step);
      root.appendChild(track);
      root.appendChild(meta);
      ensureBox().appendChild(root);
      c = cards[job.id] = { root: root, step: step, bar: bar, meta: meta, name: name };
    }
    c.name.textContent = job.name;
    c.step.textContent = job.step_name || 'Working…';
    c.bar.style.width = (job.percent || 0) + '%';
    c.meta.textContent = (job.total ? job.step + '/' + job.total + ' · ' : '')
                       + (job.percent || 0) + '% · ' + (job.elapsed || 0) + 's';
    return c;
  }

  function dismiss(id) {
    var c = cards[id];
    if (c && c.root && c.root.parentNode) c.root.parentNode.removeChild(c.root);
    delete cards[id];
    done[id] = true;          // don't re-open a card the viewer has closed
  }

  // An install that has left the live list has either finished or failed. Say which, using the
  // per-server endpoint that already knows — then fade the card out on its own for a success, and
  // leave a failure up until it is dismissed.
  function settle(id) {
    var c = cards[id];
    if (!c) return;
    fetch(MOUNT + '/api/server/' + id + '/install-status')
      .then(function (r) { return r.json(); })
      .then(function (s) {
        if (!cards[id]) return;
        var bad = (s.status === 'failed' || s.status === 'interrupted');
        var warn = !!s.warn;
        c.bar.style.width = '100%';
        c.root.className = 'install-progress-card ' + (bad ? 'is-bad' : (warn ? 'is-warn' : 'is-ok'));
        c.step.textContent = s.message || (bad ? 'Install failed' : 'Installed');
        c.meta.textContent = '';
        if (!bad) setTimeout(function () { dismiss(id); }, 12000);
      })
      .catch(function () { dismiss(id); });
  }

  function stop() { if (timer) { clearInterval(timer); timer = null; } }

  function tick() {
    fetch(MOUNT + '/api/installs', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var live = {};
        (d.installs || []).forEach(function (j) {
          live[j.id] = true;
          if (!done[j.id]) card(j);
        });
        // Anything we were showing that is no longer live has just ended.
        Object.keys(cards).forEach(function (id) {
          if (!live[id]) settle(id);
        });
        if (!(d.installs || []).length) stop();
      })
      .catch(function () { stop(); });
  }

  window.watchInstallsNow = function () {
    Object.keys(done).forEach(function (k) { delete done[k]; });   // a NEW install re-opens a card
    tick();
    if (!timer) timer = setInterval(tick, POLL_MS);
  };

  document.addEventListener('DOMContentLoaded', function () {
    fetch(MOUNT + '/api/installs', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if ((d.installs || []).length) {
          (d.installs || []).forEach(card);
          if (!timer) timer = setInterval(tick, POLL_MS);
        }
      })
      .catch(function () {});
    // A server added anywhere — including this tab's own install — broadcasts this already.
    if (window.onServersChanged) window.onServersChanged(function () { window.watchInstallsNow(); });
  });
})();
