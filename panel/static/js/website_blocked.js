// A website's Blocked visitors (templates/_website_rules.html): GET /websites/<id>/blocked lists the addresses the
// host blocks that attacked this site ({entries: [{ip, jail, reason, since, until}], count, others, guard: {enabled,
// fail2ban}}; `others` counts the host's other blocked addresses, kept off this site too); POST
// /websites/<id>/blocked/unban {ip} lifts one, and its row goes at once. Loaded when the Rules tab opens (website_site.js).
// The reason is the server's sentence, already in the viewer's language; an address is the visitor's, as text.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId) return;
  var ID = WS.siteId;
  function row(e) {
    var li = WS.node('li', 'ws-row');
    li.setAttribute('data-ip', String(e.ip || ''));
    var top = WS.node('div', 'd-flex flex-wrap gap-2 align-items-baseline');
    top.appendChild(WS.raw('span', 'font-monospace text-break', String(e.ip || '')));
    top.appendChild(WS.raw('span', 'text-secondary', String(e.reason || '')));
    li.appendChild(top);
    var when = WS.node('div', 'text-secondary');
    when.appendChild(WS.node('span', null, WS.T('since')));
    when.appendChild(WS.raw('span', 'ms-1 me-1 text-nowrap', String(e.since || '')));
    when.appendChild(WS.node('span', null, WS.T('until')));
    when.appendChild(WS.raw('span', 'ms-1 text-nowrap', String(e.until || '')));
    li.appendChild(when);
    li.appendChild(WS.button(WS.T('Unblock'), 'unlock', 'wsUnblock', [String(e.ip || '')]));
    return li;
  }
  function stateText(g, n, others) {
    if (g && g.enabled === false) return WS.T('Blocking is off for this host (the web proxy card, Blocked visitors).');
    if (g && g.fail2ban === 'absent') return WS.T('fail2ban is not installed on this host, so no visitor is blocked.');
    // A ban holds for every site of the host: the ones another site's attackers got are kept off this one too.
    if (others) {
      return WS.TF(n ? '{n} more address(es) that attacked another website on this host are blocked from this one too.'
        : 'No visitor that attacked this website is blocked. {n} address(es) that attacked another website on this host are blocked from this one too.', {n: others});
    }
    return n ? '' : WS.T('No visitor is blocked on this host.');
  }
  WS.loadBlocked = function () {
    if (!WS.el('wv-list')) return;
    WS.say('wv-msg', WS.T('Loading…'));
    WS.get(WS.R.act(ID, 'blocked')).then(function (d) {
      var list = WS.clear(WS.el('wv-list'));
      if (!d || !d.success) { WS.done(d, 'wv-msg'); return; }
      WS.say('wv-msg', '');
      var entries = d.entries || [];
      var count = WS.el('wv-count');
      if (count) count.textContent = String(entries.length);
      var state = WS.el('wv-state');
      if (state) { state.textContent = stateText(d.guard, entries.length, d.others || 0); WS.show(state, !!state.textContent); }
      entries.forEach(function (e) { list.appendChild(row(e)); });
    });
  };
  window.wsBlockedLoad = function () { WS.loadBlocked(); };
  // An address lifted leaves the list at once, its answer kept in view (Refresh reads the host's list again).
  function dropRow(ip) {
    var list = WS.el('wv-list');
    if (!list) return;
    Array.prototype.slice.call(list.children).forEach(function (li) { if (li.getAttribute('data-ip') === ip) li.remove(); });
    var count = WS.el('wv-count');
    if (count) count.textContent = String(list.children.length);
  }
  window.wsUnblock = function (ip) {
    WS.say('wv-msg', WS.T('Working…'));
    WS.post(WS.R.act(ID, 'blocked/unban'), {ip: String(ip)}).then(function (d) {
      if (WS.done(d, 'wv-msg')) dropRow(String(ip));
    });
  };
  // Opened straight on the Rules tab (?tab=rules): website_site.js picked the tab before this file was loaded.
  var pane = document.querySelector('[data-ws-pane="rules"]');
  if (pane && !pane.hidden) WS.loadBlocked();
})();
