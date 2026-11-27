// A website's Blocked visitors (templates/_website_rules.html): GET /websites/<id>/blocked lists the addresses the
// host blocks that attacked this site ({entries: [{ip, jail, reason, since, until}], count, guard: {enabled,
// fail2ban}}); POST /websites/<id>/blocked/unban {ip} lifts one. Loaded when the Rules tab opens (website_site.js).
// The reason is the server's sentence, already in the viewer's language; an address is the visitor's, as text.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId) return;
  var ID = WS.siteId;
  function row(e) {
    var li = WS.node('li', 'ws-row');
    var top = WS.node('div', 'd-flex flex-wrap gap-2 align-items-baseline');
    top.appendChild(WS.raw('span', 'font-monospace text-break', String(e.ip || '')));
    top.appendChild(WS.raw('span', 'text-secondary', String(e.reason || '')));
    li.appendChild(top);
    var when = WS.node('div', 'text-secondary');
    when.appendChild(WS.node('span', null, WS.T('until')));
    when.appendChild(WS.raw('span', 'ms-1 text-nowrap', String(e.until || '')));
    li.appendChild(when);
    li.appendChild(WS.button(WS.T('Unblock'), 'unlock', 'wsUnblock', [String(e.ip || '')]));
    return li;
  }
  function stateText(g, n) {
    if (g && g.enabled === false) return WS.T('Blocking is off for this host (the web proxy card, Blocked visitors).');
    if (g && g.fail2ban === 'absent') return WS.T('fail2ban is not installed on this host, so no visitor is blocked.');
    return n ? '' : WS.T('No visitor is blocked.');
  }
  WS.loadBlocked = function () {
    if (!WS.el('wb-list')) return;
    WS.say('wb-msg', WS.T('Loading…'));
    WS.get(WS.R.act(ID, 'blocked')).then(function (d) {
      var list = WS.clear(WS.el('wb-list'));
      if (!d || !d.success) { WS.done(d, 'wb-msg'); return; }
      WS.say('wb-msg', '');
      var entries = d.entries || [];
      var count = WS.el('wb-count');
      if (count) count.textContent = String(entries.length);
      var state = WS.el('wb-state');
      if (state) { state.textContent = stateText(d.guard, entries.length); WS.show(state, !!state.textContent); }
      entries.forEach(function (e) { list.appendChild(row(e)); });
    });
  };
  window.wsBlockedLoad = function () { WS.loadBlocked(); };
  window.wsUnblock = function (ip) {
    WS.say('wb-msg', WS.T('Working…'));
    WS.post(WS.R.act(ID, 'blocked/unban'), {ip: String(ip)}).then(function (d) {
      if (WS.done(d, 'wb-msg')) WS.loadBlocked();
    });
  };
})();
