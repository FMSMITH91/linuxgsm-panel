function titleCase(s){ return s ? s.charAt(0).toUpperCase()+s.slice(1) : ''; }

// Client-side filter of the server list (name / short name / type / connect address).
// Hides remote cards with no matching rows, and shows an empty-state when nothing matches.
// Tag ids currently toggled on in the filter bar. Deliberately not persisted: a filter is a
// momentary lens, and a saved one would leave a user staring at a half-empty dashboard after a
// week away with no memory of why.
var _tagFilter = [];

// Toggle one tag in the filter, then re-run the single filter pass below so tag + text compose.
window.toggleTagFilter = function(tagId, btn){
  var at = _tagFilter.indexOf(tagId);
  if (at === -1) _tagFilter.push(tagId); else _tagFilter.splice(at, 1);
  var on = at === -1;
  btn.classList.toggle('active', on);
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  filterServers();
};

function rowHasEveryTag(tr){
  if (!_tagFilter.length) return true;
  var have = Array.prototype.map.call(tr.querySelectorAll('.tag-chip'),
                                      function(c){ return parseInt(c.getAttribute('data-tag-id'), 10); });
  // AND, not OR: picking "production" + "modded" should narrow to servers that are both, which is
  // what makes the filter useful as a bulk-action selector.
  return _tagFilter.every(function(id){ return have.indexOf(id) !== -1; });
}

function filterServers(){
  var input = document.getElementById('srv-search');
  var q = input ? input.value.trim().toLowerCase() : '', anyVisible = false;
  document.querySelectorAll('.server-remote-card').forEach(function(card){
    var cardHas = false;
    card.querySelectorAll('tbody tr').forEach(function(tr){
      var match = (!q || tr.textContent.toLowerCase().indexOf(q) !== -1) && rowHasEveryTag(tr);
      tr.style.display = match ? '' : 'none';
      if(match) cardHas = true;
    });
    card.style.display = cardHas ? '' : 'none';
    if(cardHas) anyVisible = true;
  });
  var none = document.getElementById('srv-none');
  // Show the empty-state when EITHER lens is active and matched nothing — a tag filter that hides
  // everything used to leave a blank page with no explanation.
  if(none) none.style.display = ((q || _tagFilter.length) && !anyVisible) ? '' : 'none';
}

// Tick every row the current filters leave visible, so "filter by tag, then act on all of them" is
// two clicks. The bulk endpoint still re-checks the action permission and per-server access, so
// this only ever selects rows the user can already see and act on.
window.selectAllShown = function(){
  document.querySelectorAll('.srv-check').forEach(function(cb){
    var tr = cb.closest('tr');
    cb.checked = !!(tr && tr.style.display !== 'none');
  });
  updateBulkBar();
};

// The set of game-server ids currently rendered on this page (sorted, comma-joined),
// so we can detect when another user has added or removed one.
function renderedServerIds() {
  return Array.prototype.map.call(document.querySelectorAll('[id^="status-"]'),
    function(el){ return el.id.slice('status-'.length); }).sort().join(',');
}
var _serverIdsBaseline = null;

// Live status: update the count tiles + each server row's status cell.
function refreshStatus() {
  fetch(MOUNT + '/api/servers')
    .then(r => r.json())
    .then(data => {
      // If the set of servers changed underneath us (another user installed/uninstalled one), the
      // rows are server-rendered — pull the fresh cards into #server-cards in place (no reload).
      var liveIds = data.map(function(s){ return String(s.id); }).sort().join(',');
      if (_serverIdsBaseline !== null && liveIds !== _serverIdsBaseline) {
        _serverIdsBaseline = liveIds;   // adopt now so this doesn't re-fire while the swap is in flight
        window.refreshSection('#server-cards', 'afterDashRefresh');
        return;
      }
      var online = data.filter(s => s.status === 'online').length;
      var offline = data.filter(s => s.status === 'offline').length;
      var oc = document.getElementById('online-count');
      var fc = document.getElementById('offline-count');
      var tc = document.getElementById('total-servers');
      if (oc) oc.innerHTML = '<span class="status-dot status-online"></span> ' + online;
      if (fc) fc.innerHTML = '<span class="status-dot status-offline"></span> ' + offline;
      if (tc) tc.textContent = data.length;
      // Total online / total capacity = sums of the known per-server values (unknowns excluded).
      var totalPlayers = data.reduce(function(a, s){ return a + (typeof s.players === 'number' ? s.players : 0); }, 0);
      var totalMax = data.reduce(function(a, s){ return a + (typeof s.max_players === 'number' ? s.max_players : 0); }, 0);
      var tp = document.getElementById('total-players');
      if (tp) tp.innerHTML = '<i class="bi bi-people-fill text-info"></i> ' + totalPlayers + (totalMax > 0 ? ' / ' + totalMax : '');
      data.forEach(function(s){
        var pcell = document.getElementById('players-' + s.id);
        if (pcell) {
          pcell.innerHTML = (typeof s.players === 'number')
            ? '<i class="bi bi-people-fill text-secondary"></i> ' + s.players + (typeof s.max_players === 'number' && s.max_players > 0 ? ' / ' + s.max_players : '')
            : '<span class="text-secondary">—</span>';
        }
        var cell = document.getElementById('status-' + s.id);
        if (cell && cell.dataset.status !== s.status) {
          cell.dataset.status = s.status;
          var cls = (s.status === 'online' || s.status === 'offline') ? s.status : 'unknown';
          cell.innerHTML = '<span class="status-dot status-' + cls + '"></span> ' + titleCase(s.status);
        }
        var conn = document.getElementById('connect-' + s.id);
        var key = (s.connect || '') + '|' + (s.connect_url || '');
        if (conn && s.connect && conn.dataset.addr !== key) {
          conn.dataset.addr = key;
          // Build via textContent + a listener (NOT innerHTML with the raw address) so a
          // hostile connect address can't inject HTML/script into the dashboard.
          conn.textContent = '';
          var code = document.createElement('code');
          code.className = 'text-info';
          code.style.cssText = 'font-size:.78rem;cursor:pointer;';
          code.title = 'Click to copy';
          code.textContent = s.connect;
          code.addEventListener('click', function(){ copyAddr(s.connect); });
          conn.appendChild(code);
          // One-click join link (steam://connect/…) for games that support it.
          if (s.connect_url) {
            var join = document.createElement('a');
            join.className = 'btn btn-success btn-sm py-0 px-1 ms-2 join-link';
            join.style.fontSize = '.7rem';
            join.rel = 'noopener';
            join.title = 'Launch the game and join (on phones, taps to copy the address)';
            join.href = s.connect_url;   // href property assignment — no HTML parsing
            if (s.connect) join.setAttribute('data-addr', s.connect);  // touch fallback: copy addr
            join.innerHTML = '<i class="bi bi-box-arrow-in-right"></i> Join';
            conn.appendChild(join);
          }
        }
        // In-game server name (the hostname players see), from gamedig. textContent, never innerHTML,
        // so a hostile server name can't inject markup. Keep the old value when none is reported.
        var nm = document.getElementById('game-name-' + s.id);
        if (nm && s.game_name && nm.textContent !== s.game_name) nm.textContent = s.game_name;
        // Keep the row's sort keys in sync with live status/players so a re-sort reflects reality.
        var row = cell ? cell.closest('tr') : null;
        if (row) {
          row.setAttribute('data-status', s.status);
          row.setAttribute('data-players', typeof s.players === 'number' ? s.players : -1);
          // Disable start/restart/stop + console while a server is installing/configuring (or not
          // installed yet), and re-enable them live the moment it's ready — no page reload needed.
          var busy = !s.installed || s.status === 'installing' || s.status === 'configuring';
          row.querySelectorAll('.srv-ctl').forEach(function(b){ b.disabled = busy; });
          var con = row.querySelector('.srv-console');
          if (con) {
            con.classList.toggle('disabled', busy);
            if (busy) { con.setAttribute('tabindex', '-1'); con.setAttribute('aria-disabled', 'true'); }
            else { con.removeAttribute('tabindex'); con.removeAttribute('aria-disabled'); }
          }
        }
      });
    })
    .catch(() => {});
}

// Click-to-sort a single host card's table (the dashboard is already grouped by host into cards, so
// each card sorts its own servers). Toggles asc/desc per column; players numeric, others
// case-insensitive. Rows are moved with appendChild — cells keep their ids so the poller still finds
// them.
window.sortDashCol = function(key, th){
  var table = th.closest('table'); if (!table) return;
  var tb = table.querySelector('tbody'); if (!tb) return;
  var dir = (table.dataset.sortKey === key) ? -(parseInt(table.dataset.sortDir || '1', 10)) : 1;
  table.dataset.sortKey = key; table.dataset.sortDir = String(dir);
  Array.prototype.slice.call(tb.querySelectorAll('tr')).sort(function(a, b){
    if (key === 'players') {
      return ((parseInt(a.getAttribute('data-players'), 10)) - (parseInt(b.getAttribute('data-players'), 10))) * dir;
    }
    return (a.getAttribute('data-' + key) || '').localeCompare(b.getAttribute('data-' + key) || '', undefined, {sensitivity: 'base', numeric: true}) * dir;
  }).forEach(function(r){ tb.appendChild(r); });
  table.querySelectorAll('th[data-sortkey]').forEach(function(h){
    var c = h.querySelector('.dash-caret');
    if (c) c.textContent = (h.getAttribute('data-sortkey') === key) ? (dir > 0 ? ' ▲' : ' ▼') : '';
  });
};
_serverIdsBaseline = renderedServerIds();   // what this page was rendered with
refreshStatus();              // populate status + connect immediately
pollWhenVisible(refreshStatus, 8000);

// Live resource metrics (per-host CPU/RAM/disk in each card header + the summary tile, and per-server
// CPU/RAM/uptime in the Resources column). Heavier than the status feed (an SSH sample per server),
// so it polls on a slower cadence.
function _fmtUptimeShort(s){
  s = Math.max(0, s|0);
  var d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  return d ? (d+'d '+h+'h') : (h ? (h+'h '+m+'m') : (m+'m'));
}
function refreshMetrics(){
  fetch(MOUNT + '/api/dashboard/metrics').then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if(!d) return;
      var hosts = d.hosts || {}, servers = d.servers || {}, summary = null;
      Object.keys(hosts).forEach(function(rid){
        var h = hosts[rid], el = document.getElementById('host-metrics-' + rid);
        if(el) el.textContent = 'CPU ' + h.cpu + '% · RAM ' + h.ram_pct + '% · Disk ' + h.disk_pct + '%';
        if(h.local || summary === null) summary = h;
      });
      var sum = document.getElementById('host-summary');
      if(sum) sum.innerHTML = summary
        ? '<i class="bi bi-cpu text-info"></i> ' + summary.cpu + '% · ' + summary.ram_pct + '%'
        : '<i class="bi bi-cpu text-info"></i> <span class="text-secondary">—</span>';
      Object.keys(servers).forEach(function(sid){
        var s = servers[sid], cell = document.getElementById('res-' + sid);
        if(cell) cell.innerHTML = s.up
          ? ('<i class="bi bi-cpu"></i> ' + s.cpu + '% · ' + s.ram_mb + ' MB'
             + (s.uptime ? ' · <span title="Uptime"><i class="bi bi-clock"></i> ' + _fmtUptimeShort(s.uptime) + '</span>' : ''))
          : '<span class="text-secondary">—</span>';
        var mapEl = document.getElementById('map-' + sid);
        if(mapEl){
          if(s.up && s.map){ mapEl.innerHTML = '<i class="bi bi-geo-alt"></i> ' + s.map; mapEl.classList.remove('d-none'); }
          else { mapEl.classList.add('d-none'); }
        }
      });
    }).catch(function(){});
}
refreshMetrics();
pollWhenVisible(refreshMetrics, 10000);
// Instant reaction when another user adds/removes a server (poll above is the fallback).
if (window.onServersChanged) onServersChanged(refreshStatus);

// After #server-cards is swapped in place (a server appeared/disappeared elsewhere), re-apply the
// search filter and repaint live statuses/connect cells onto the fresh rows — no full-page reload.
// Bind drag to every reorderable region on this page. Same save path as the arrow buttons, so a
// dragged order is server-rendered afterwards exactly like a clicked one.
function bindDragRegions(){
  if (!window.makeSortable) return;
  makeSortable(document.getElementById('dash-tiles'),
               {itemSelector: '[data-panel]', axis: 'x', onDrop: saveHostOrder});
  makeSortable(document.getElementById('server-cards'),
               {itemSelector: '.server-remote-card', axis: 'y', onDrop: saveHostOrder});
  document.querySelectorAll('.server-remote-card tbody').forEach(function(tb){
    makeSortable(tb, {itemSelector: 'tr[data-server-id]', axis: 'y', onDrop: saveHostOrder});
  });
}

window.afterDashRefresh = function(){
  if (typeof filterServers === 'function') filterServers();
  refreshStatus();
  // #server-cards itself survives a refreshSection (only its innerHTML is replaced), so its own
  // listener persists — but the tbody elements inside are new objects and need binding again.
  bindDragRegions();
};

// ── Per-user host-card order ────────────────────────────────────────────────────────────────
// The server renders the saved order, so this only has to (a) move the node for instant feedback
// and (b) persist the new order. #server-cards is swapped wholesale by refreshSection() on a poll
// or another user's install, and the replacement HTML already carries the saved order — which is
// why nothing here needs re-applying afterwards.
var _orderSaveTimer = null;

function hostCards(){
  // #srv-none is a sibling sentinel inside #server-cards — never treat it as a host card.
  return Array.prototype.slice.call(document.querySelectorAll('#server-cards > .server-remote-card'));
}

// Both orders are sent together on any change: they are one layout, the endpoint validates each
// key independently, and sending both keeps them from drifting apart if a save is ever dropped.
// ── Movable panels (the stat tiles today; any [data-region] container tomorrow) ─────────────────
// A region is a container with data-region; its children carry data-panel="<key>". The SERVER
// renders the saved order — this only moves the node for instant feedback and persists the result.
function collectPanels(){
  var panels = {}, hidden = {};
  document.querySelectorAll('[data-region]').forEach(function(region){
    var key = region.getAttribute('data-region');
    panels[key] = Array.prototype.slice.call(region.querySelectorAll(':scope > [data-panel]'))
      .map(function(el){ return el.getAttribute('data-panel'); });
    // Hidden keys live on the restore bar, not in the region — they are not rendered at all.
    var bar = document.getElementById(region.id + '-hidden');
    hidden[key] = bar ? Array.prototype.slice.call(bar.querySelectorAll('[data-action="showPanel"]'))
      .map(function(b){ return JSON.parse(b.getAttribute('data-args'))[1]; }) : [];
  });
  // Every key this page rendered a control for, so the server can keep the ones it did not.
  return {panels: panels, hidden: hidden,
          declared: Object.keys(panels).reduce(function(acc, k){
            acc[k] = panels[k].concat(hidden[k] || []); return acc; }, {})};
}

window.movePanel = function(dir, btn){
  var panel = btn.closest('[data-panel]');
  var region = panel && panel.closest('[data-region]');
  if (!region) return;
  var sibs = Array.prototype.slice.call(region.querySelectorAll(':scope > [data-panel]'));
  var at = sibs.indexOf(panel), to = at + (dir < 0 ? -1 : 1);
  if (at < 0 || to < 0 || to >= sibs.length) return;
  if (dir < 0) region.insertBefore(panel, sibs[to]);
  else region.insertBefore(sibs[to], panel);
  var keep = panel.querySelector('.panel-tools button:not([disabled])');
  if (keep) keep.focus();
  saveHostOrder();
};

// Hiding removes the node and drops a restore chip, so the next server render agrees with what the
// user is looking at right now (the server skips hidden panels entirely).
window.hidePanel = function(btn){
  var panel = btn.closest('[data-panel]');
  var region = panel && panel.closest('[data-region]');
  if (!region) return;
  var key = panel.getAttribute('data-panel');
  var label = (panel.querySelector('.text-secondary.small') || {}).textContent || key;
  var bar = document.getElementById(region.id + '-hidden');
  if (!bar){
    bar = document.createElement('div');
    bar.id = region.id + '-hidden';
    bar.className = 'mb-4 d-flex align-items-center gap-2 flex-wrap';
    var lead = document.createElement('span');
    lead.className = 'text-secondary small';
    lead.textContent = 'Hidden:';
    bar.appendChild(lead);
    region.parentNode.insertBefore(bar, region.nextSibling);
  }
  var chip = document.createElement('button');
  chip.type = 'button';
  chip.className = 'btn btn-sm btn-outline-secondary';
  chip.setAttribute('data-action', 'showPanel');
  chip.setAttribute('data-args', JSON.stringify([region.getAttribute('data-region'), key, '@self']));
  chip.title = 'Show this panel again';
  chip.textContent = label.trim();
  bar.appendChild(chip);
  panel.remove();
  saveHostOrder();
};

// Restoring needs the panel's markup back, which only the server has — so save first, then reload
// once the save is acknowledged. Reloading before it lands would resurrect the old layout.
window.showPanel = function(region, key, btn){
  btn.remove();
  saveHostOrder(function(){ location.reload(); });
};

function collectLayout(){
  var host_order = [], server_order = {};
  hostCards().forEach(function(card){
    var rid = parseInt(card.getAttribute('data-remote-id'), 10);
    if (isNaN(rid)) return;
    host_order.push(rid);
    server_order[rid] = Array.prototype.slice
      .call(card.querySelectorAll('tbody tr[data-server-id]'))
      .map(function(tr){ return parseInt(tr.getAttribute('data-server-id'), 10); })
      .filter(function(n){ return !isNaN(n); });
  });
  var p = collectPanels();
  return {host_order: host_order, server_order: server_order,
          panels: p.panels, hidden: p.hidden, declared: p.declared};
}

// `then` runs only after the server has ACKNOWLEDGED the save — showPanel needs that, because it
// reloads to get the restored panel's markup and a reload before the save lands would undo it.
function saveHostOrder(then){
  clearTimeout(_orderSaveTimer);                 // one request per burst of clicks, not per click
  _orderSaveTimer = setTimeout(function(){
    fetch(MOUNT + '/api/account/ui-order', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},   // the wrapper adds CSRF, not this
      body: JSON.stringify(collectLayout())
    })
      // r.ok first: an expired session answers 302 -> HTML login page and a CSRF failure answers
      // an HTML 400, either of which would explode inside r.json() and look like success.
      .then(function(r){ if(!r.ok) throw 0; return r.json(); })
      .then(function(d){ if(!d || d.success === false) throw 0; if (then) then(); })
      .catch(function(){
        if (window.toast) toast('Could not save your layout — it will revert on reload.', 'danger');
      });
  }, 400);
}

// Move one host card up (dir<0) or down (dir>0). MOVES the existing node rather than rebuilding:
// the cells carry ids the pollers address (status-<id>, res-<id>) and the delegated handlers walk
// up with closest(), both of which survive a move and neither of which survives a re-render.
window.moveHostCard = function(dir, btn){
  var card = btn.closest('.server-remote-card');
  var wrap = document.getElementById('server-cards');
  if (!card || !wrap) return;
  var cards = hostCards(), at = cards.indexOf(card), to = at + (dir < 0 ? -1 : 1);
  if (at < 0 || to < 0 || to >= cards.length) return;         // already at the end: no-op
  if (dir < 0) wrap.insertBefore(card, cards[to]);
  else wrap.insertBefore(cards[to], card);
  // Keep keyboard focus travelling with the card, so repeated arrow presses keep working. Guarded:
  // if a later change disables the end buttons, this must not throw mid-reorder.
  var keep = card.querySelector('.host-move button:not([disabled])');
  if (keep) keep.focus();
  saveHostOrder();
};

// Move one server row within its own host card. Rows hidden by the search filter are SKIPPED, so a
// move always lands where the user can see it — swapping with an invisible neighbour looks like the
// button did nothing.
window.moveServerRow = function(dir, btn){
  var row = btn.closest('tr[data-server-id]');
  if (!row) return;
  var body = row.parentNode;
  var rows = Array.prototype.slice.call(body.querySelectorAll('tr[data-server-id]'))
                  .filter(function(tr){ return tr === row || tr.style.display !== 'none'; });
  var at = rows.indexOf(row), to = at + (dir < 0 ? -1 : 1);
  if (at < 0 || to < 0 || to >= rows.length) return;      // already first/last visible: no-op
  if (dir < 0) body.insertBefore(row, rows[to]);
  else body.insertBefore(rows[to], row);
  var keep = row.querySelector('.srv-move button:not([disabled])');
  if (keep) keep.focus();
  saveHostOrder();
};

function copyAddr(addr) {
  window.copyText(addr, 'Copied');
}

// Inline server actions (no page reload).
function doAction(id, action, btn) {
  var original = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  fetch(MOUNT + '/api/server/' + id + '/action', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ action: action })
  })
  .then(r => r.json())
  .then(d => {
    toast(d.message || (d.success ? ('Server ' + action + ' issued') : 'Action failed'), d.success ? 'success' : 'danger');
    setTimeout(refreshStatus, 1500);
  })
  .catch(() => toast('Action failed', 'danger'))
  .finally(() => { btn.disabled = false; btn.innerHTML = original; });
}

// ── Bulk actions ──────────────────────────────────────────────
// Run one action across every checked server in a single request. The server
// dispatches each in the background, so this returns immediately and the live
// status poll below reflects the outcome per row.
function selectedChecks() {
  return Array.prototype.slice.call(document.querySelectorAll('.srv-check:checked'));
}
function selectedIds() {
  return selectedChecks().map(function (c) { return c.value; });
}
function updateBulkBar() {
  var checks = selectedChecks(), n = checks.length;
  document.querySelectorAll('.bulk-count').forEach(function (el) { el.textContent = n; });
  document.querySelectorAll('.bulk-bar').forEach(function (bar) { bar.style.display = n ? '' : 'none'; });
  // Hide the Update button when NONE of the selected servers support updating (e.g. a lone cod
  // server, which has no LinuxGSM update command) — no point offering an action that can't run.
  var anyUpdatable = checks.some(function (c) { return c.getAttribute('data-supports-update') !== 'false'; });
  document.querySelectorAll('.bulk-update-btn').forEach(function (b) { b.style.display = anyUpdatable ? '' : 'none'; });
}
function toggleAll(cb) {
  var card = cb.closest('.server-remote-card');
  if (!card) return;
  card.querySelectorAll('.srv-check').forEach(function (c) {
    if (c.closest('tr').style.display !== 'none') c.checked = cb.checked;   // visible rows only
  });
  updateBulkBar();
}
function clearSelection() {
  document.querySelectorAll('.srv-check, .srv-check-all').forEach(function (c) { c.checked = false; });
  updateBulkBar();
}
function bulkAction(action) {
  var checks = selectedChecks();
  var ids = checks.map(function (c) { return Number(c.value); });
  if (!ids.length) return;
  var skippedNoUpdate = 0;
  if (action === 'update') {
    // Mixed selection: only update servers whose game has a LinuxGSM update command; skip the
    // rest instead of failing them. The server enforces this too (defence in depth).
    var updatable = checks.filter(function (c) { return c.getAttribute('data-supports-update') !== 'false'; });
    skippedNoUpdate = ids.length - updatable.length;
    ids = updatable.map(function (c) { return Number(c.value); });
    if (!ids.length) { toast('None of the selected servers support updating.', 'warning'); return; }
  }
  var run = function () {
    var btns = document.querySelectorAll('.bulk-bar button');
    btns.forEach(function (b) { b.disabled = true; });
    fetch(MOUNT + '/api/servers/bulk-action', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action, server_ids: ids })
    })
      .then(r => r.json())
      .then(d => {
        var nq = (d.queued || []).length, skip = (d.skipped || []).length + skippedNoUpdate;
        var extra = skip ? ' (' + skip + ' skipped)' : '';
        if (nq) toast(titleCase(action) + ' started on ' + nq + ' server' + (nq === 1 ? '' : 's') + extra, 'success');
        else toast((d.message || 'Nothing to do') + extra, 'warning');
        clearSelection();
        setTimeout(refreshStatus, 1500);
      })
      .catch(() => toast('Bulk action failed', 'danger'))
      .finally(() => { btns.forEach(function (b) { b.disabled = false; }); });
  };
  if (action === 'stop' || action === 'update') {
    confirmDialog({
      title: titleCase(action) + ' ' + ids.length + ' server' + (ids.length === 1 ? '' : 's'),
      icon: 'exclamation-triangle', confirmClass: 'btn-warning', confirmLabel: titleCase(action),
      bodyText: 'Run "' + action + '" on ' + ids.length + ' server' + (ids.length === 1 ? '' : 's') + '?',
      onConfirm: run
    });
  } else {
    run();
  }
}
// Keep the bar's count in sync as individual boxes are toggled.
document.addEventListener('change', function (e) {
  if (e.target && e.target.classList && e.target.classList.contains('srv-check')) updateBulkBar();
});

// makeSortable lives in base.html, whose footer script runs after this block is parsed — so wait.
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindDragRegions);
else bindDragRegions();

// Minimal toast helper.
// Uses the global window.toast (base.html) — one implementation, consistent independent timing.
