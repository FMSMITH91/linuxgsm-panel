// Click a connect address to copy the full ip:port.
document.addEventListener('click', function(ev){
  var el = ev.target.closest('.copy-addr'); if(!el) return;
  if(window.copyText) window.copyText(el.getAttribute('data-copy'), 'Copied ' + el.getAttribute('data-copy'));
});

// Auto-populate a sensible default port when the game changes. This is only a
// hint — after install the panel detects LinuxGSM's real port(s) and opens all of
// them, so it self-corrects even for games not listed here.
var PORTS = {
  "gmod":27015,"cs":27015,"css":27015,"cs2":27015,"csgo":27015,"tf2":27015,
  "hl2dm":27015,"hldm":27015,"hldms":27015,"dods":27015,"ins":27015,"insurgency":27015,
  "nmrih":27015,"l4d":27015,"l4d2":27015,"zps":27015,"fof":27015,"gesource":27015,
  "cscz":27015,"tfc":27015,"ns":27015,"ricochet":27015,"dmc":27015,"sfc":27015,
  "bb2":27015,"unturned":27015,"bt":27015,
  "cod":28960,"coduo":28960,"cod2":28960,"cod4":28960,"codwaw":28960,
  "mc":25565,"pmc":25565,"spigot":25565,"paper":25565,"bukkit":25565,"mcbe":19132,"mcb":19132,
  "rust":28015,"sdtd":26900,"7d2d":26900,"valheim":2456,"vh":2456,"ark":7777,
  "pz":16261,"projectzomboid":16261,"terraria":7777,"tshock":7777,"factorio":34197,
  "avorion":27000,"eco":3000,"vs":42420,
  "arma3":2302,"squad":7787,"mordhau":7777,"kf":7707,"kf2":7777,
  "q2":27910,"q3":27960,"ql":27960,"et":27960,"etl":27960,"rtcw":27960,
  "xonotic":26000,"ut99":7777,"ut2k4":7777,
  "mumble":64738,"ts3":9987,"samp":7777,"mta":22003,"openttd":3979,
};
function updatePort() {
  var select = document.getElementById('game-type-select');
  var port = document.getElementById('port-input');
  if (PORTS[select.value]) {
    port.value = PORTS[select.value];
  }
  // GMod-only: offer to mount CS:S content (it's the one game that needs mounted content).
  var contentOpt = document.getElementById('gmod-content-opt');
  if (contentOpt) contentOpt.style.display = (select.value === 'gmod') ? '' : 'none';
  suggestFreePort();
}
// Once a target host + game are chosen, ask the panel for a free port near the default and bump the
// field if the default is already taken (the install auto-resolves too — this just shows it up front).
function suggestFreePort() {
  var game = (document.getElementById('game-type-select') || {}).value;
  var remote = (document.getElementById('remote-select') || {}).value;
  var portEl = document.getElementById('port-input');
  var hint = document.getElementById('port-hint');
  if (hint) hint.textContent = '';
  if (!game || !remote || !portEl) return;
  var desired = portEl.value || PORTS[game] || 27015;
  fetch(MOUNT + '/api/free-port?remote_id=' + encodeURIComponent(remote)
        + '&game=' + encodeURIComponent(game) + '&desired=' + encodeURIComponent(desired))
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if (!d || !d.port || !hint) return;
      if (d.changed) {
        portEl.value = d.port;
        hint.textContent = 'Port ' + desired + ' is in use — using free port ' + d.port + '.';   // textContent: never treat the port value as HTML
      }
    })
    .catch(function(){});
}

// Live per-server install progress (step-by-step, mirrors the VPS bootstrap).
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.install-progress-row[data-installing="1"]').forEach(function(row) {
    watchInstall(row.id.substring('install-row-'.length));
  });
});

var _instTimers = {};
function watchInstall(id) {
  if (_instTimers[id]) return;
  function tick() {
    fetch(MOUNT + '/api/server/' + id + '/install-status')
      .then(r => r.json())
      .then(s => {
        var row = document.getElementById('install-row-' + id);
        if (!row) return;
        if (s.status === 'none') { row.style.display = 'none'; stopInstall(id); return; }
        row.style.display = '';
        var step = document.getElementById('inst-step-' + id);
        var bar = document.getElementById('inst-bar-' + id);
        var pct = document.getElementById('inst-pct-' + id);
        var badge = document.querySelector('[data-server-id="' + id + '"]');
        if (pct) pct.textContent = (s.total ? s.step + '/' + s.total + ' · ' : '') + s.percent + '% · ' + s.elapsed + 's';
        if (bar) bar.style.width = s.percent + '%';
        if (s.installed) enableServerLinks(id);   // files have landed — Console + Files are usable now
        if (s.status === 'done') {
          // Installed, but with a caveat (warn) — e.g. the files installed yet the server didn't
          // start. Show that as a yellow warning with the reason, not a clean green success.
          var warn = !!s.warn;
          bar.className = 'progress-bar ' + (warn ? 'bg-warning' : 'bg-success'); bar.style.width = '100%';
          step.innerHTML = '<i class="bi bi-' + (warn ? 'exclamation-triangle-fill text-warning' : 'check-circle-fill text-success') + '"></i> ' + (s.message || 'Installed');
          if (badge) { badge.className = 'badge ' + (warn ? 'bg-warning text-dark' : 'bg-success'); badge.textContent = 'Installed'; }
          var dz = document.getElementById('inst-dismiss-' + id); if (dz) dz.style.display = 'inline';
          stopInstall(id);
        } else if (s.status === 'failed') {
          bar.className = 'progress-bar bg-danger';
          step.innerHTML = '<i class="bi bi-x-circle-fill text-danger"></i> ' + (s.message || 'Install failed');
          if (badge) { badge.className = 'badge bg-danger'; badge.textContent = 'Failed'; }
          var df = document.getElementById('inst-dismiss-' + id); if (df) df.style.display = 'inline';
          stopInstall(id);
        } else if (s.status === 'interrupted') {
          if (bar) bar.className = 'progress-bar bg-warning';
          step.innerHTML = '<i class="bi bi-exclamation-triangle-fill text-warning"></i> ' + (s.message || 'Install status unknown');
          if (badge) { badge.className = 'badge bg-warning text-dark'; badge.textContent = 'Unknown'; }
          var di = document.getElementById('inst-dismiss-' + id); if (di) di.style.display = 'inline';
          stopInstall(id);
        } else {
          // Running (steps 1-8). Once the game files land (s.installed), the server IS installed
          // but still finishing config/start — show "Finishing setup…" rather than a premature
          // "Installed", with the bar tracking the remaining steps.
          step.innerHTML = '<i class="bi bi-gear-fill"></i> ' + s.step_name;
          if (badge) {
            badge.className = 'badge bg-info text-dark';
            badge.textContent = s.installed ? 'Finishing setup…' : 'Installing…';
          }
        }
      })
      .catch(function() {});
  }
  tick();
  _instTimers[id] = setInterval(tick, 2500);
}
function stopInstall(id) {
  if (_instTimers[id]) { clearInterval(_instTimers[id]); delete _instTimers[id]; }
  // Install has ended (done/failed/gone) — re-enable its Uninstall button (disabled during install).
  var ub = document.getElementById('uninstall-btn-' + id); if (ub) ub.disabled = false;
}
// Turn the Console + Files links from disabled back into working links once the server is installed.
function enableServerLinks(id) {
  [['console-btn-', 'Console, commands, restart'], ['files-btn-', 'Edit config & browse/upload files']]
    .forEach(function(x) {
      var a = document.getElementById(x[0] + id);
      if (a && a.classList.contains('disabled')) {
        if (a.dataset.href) a.setAttribute('href', a.dataset.href);
        a.classList.remove('disabled'); a.removeAttribute('tabindex'); a.removeAttribute('aria-disabled');
        a.title = x[1];
      }
    });
}
function dismissInstall(id) {
  stopInstall(id);
  var row = document.getElementById('install-row-' + id); if (row) row.style.display = 'none';
  fetch(MOUNT + '/api/server/' + id + '/install-dismiss', { method: 'POST' }).catch(function() {});
}

// ── AJAX uninstall: styled confirm, then remove the row in place — no full-page reload ──────
document.addEventListener('click', function(e){
  var b = e.target.closest && e.target.closest('.uninstall-btn');
  if (!b || b.disabled) return;
  var name = b.getAttribute('data-server-name') || '';
  var short = b.getAttribute('data-server-short') || '';
  confirmDialog({
    title: 'Uninstall server', icon: 'trash', confirmLabel: 'Uninstall', confirmClass: 'btn-danger',
    body: 'Uninstall <strong>' + escapeHtml(name) + '</strong>? This permanently deletes the server, '
        + 'all its files, AND every backup it has — this cannot be undone.',
    requireText: short,
    requireLabel: 'Type the server’s username (' + short + ') to confirm:',
    onConfirm: function(){ doUninstall(b.getAttribute('data-server-id'), name, b); }
  });
});
// Drop a server's rows (main row + its install-progress row) in place, with a short fade — no
// full-page reload. Safe to call twice (getElementById returns null once a row is gone).
function removeServerRow(id){
  var prog = document.getElementById('install-row-' + id); if (prog) prog.remove();
  var row = document.getElementById('server-row-' + id);
  if (row){ row.style.transition = 'opacity .3s'; row.style.opacity = '0';
            setTimeout(function(){ if (row.parentNode) row.remove(); }, 300); }
}
function doUninstall(id, name, btn){
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  // Disable this row's other actions (Console, Files) while it's being torn down — the server is
  // going away, so those shouldn't be clickable. Bootstrap's .disabled kills pointer events on links.
  var row = document.getElementById('server-row-' + id);
  var others = row ? Array.prototype.slice.call(row.querySelectorAll('a.btn, button.btn')).filter(function(el){ return el !== btn; }) : [];
  function setRowDisabled(off){
    others.forEach(function(el){
      if (off){ el.classList.add('disabled'); el.setAttribute('aria-disabled','true'); el.setAttribute('tabindex','-1'); }
      else { el.classList.remove('disabled'); el.removeAttribute('aria-disabled'); el.removeAttribute('tabindex'); }
    });
  }
  setRowDisabled(true);
  if (window.toast) toast('Uninstalling ' + name + '…', 'info');
  fetch(MOUNT + '/servers/' + id + '/delete', { method: 'POST' })
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.success){
        removeServerRow(id);
        _svrBaseline = serverIdsOnPage();   // adopt the reduced set so live-sync doesn't force a reload
        if (window.toast) toast(d.message || 'Uninstalled', 'success');
      } else {
        btn.disabled = false; btn.innerHTML = orig; setRowDisabled(false);
        if (window.toast) toast((d && d.message) || 'Uninstall failed', 'danger');
      }
    })
    .catch(function(){ btn.disabled = false; btn.innerHTML = orig; setRowDisabled(false); if (window.toast) toast('Uninstall request failed', 'danger'); });
}

// Power controls (start/stop/restart) for a row — POST the action, toast the result, then refresh
// the live cells. Mirrors the dashboard's doAction, but refreshes via this page's reconcile poll.
function msrvAction(id, action, btn){
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  fetch(MOUNT + '/api/server/' + id + '/action', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action: action})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(window.toast) toast(d.message || (d.success ? ('Server ' + action + ' issued') : 'Action failed'), d.success ? 'success' : 'danger');
      setTimeout(reconcileServerList, 1500);
    })
    .catch(function(){ if(window.toast) toast('Action failed', 'danger'); })
    .finally(function(){ btn.disabled = false; btn.innerHTML = orig; });
}

// ── Live sync: reflect servers other users add/remove ──────────────────────
// Removed servers are dropped in place (no reload). Added servers need server-rendered markup, so
// those reload — held off while the user is mid-way through the install form (so we don't wipe
// their selection).
function serverIdsOnPage() {
  return Array.prototype.map.call(document.querySelectorAll('[id^="install-row-"]'),
    function(el){ return el.id.slice('install-row-'.length); }).sort().join(',');
}
var _svrBaseline = serverIdsOnPage();
function editingInstallForm() {
  var f = document.getElementById('install-form');
  return f && f.contains(document.activeElement)
    && /^(INPUT|SELECT|TEXTAREA)$/.test((document.activeElement.tagName || ''));
}
function reconcileServerList() {
  fetch(MOUNT + '/api/servers')
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(data){
      if (!data) return;
      // Refresh the live player-count cell for every row on every poll (independent of whether the
      // set of servers changed).
      data.forEach(function(s){
        var pc = document.getElementById('msrv-players-' + s.id);
        if (pc) {
          pc.innerHTML = (typeof s.players === 'number')
            ? '<i class="bi bi-people-fill text-secondary"></i> ' + s.players + (typeof s.max_players === 'number' && s.max_players > 0 ? ' / ' + s.max_players : '')
            : '<span class="text-secondary">—</span>';
        }
      });
      var liveIds = data.map(function(s){ return String(s.id); });
      if (liveIds.slice().sort().join(',') === _svrBaseline) return;
      var baseIds = _svrBaseline ? _svrBaseline.split(',').filter(Boolean) : [];
      // Servers that vanished (uninstalled here or elsewhere) — drop their rows in place, never a
      // full-page reload. This is also what stops our OWN uninstall's servers_changed broadcast
      // from reloading the page out from under us.
      baseIds.filter(function(id){ return liveIds.indexOf(id) === -1; })
             .forEach(function(id){ removeServerRow(id); });
      // Servers that appeared need server-rendered markup we don't have client-side, so those still
      // require a reload — but hold off while the user is filling in the install form.
      var added = liveIds.filter(function(id){ return baseIds.indexOf(id) === -1; });
      if (added.length) {
        if (editingInstallForm()) return;   // don't yank the form out from under the user
        // Pull the freshly server-rendered rows into #servers-list in place (no full reload);
        // afterServerRefresh re-arms install pollers and re-adopts the baseline.
        window.refreshSection('#servers-list', 'afterServerRefresh');
        return;
      }
      _svrBaseline = serverIdsOnPage();   // removals only → adopt the reduced set, no reload
    })
    .catch(function(){});
}
pollWhenVisible(reconcileServerList, 8000);
if (window.onServersChanged) onServersChanged(reconcileServerList);

// Live per-server resources (CPU/RAM/uptime) in the Resources column — a slower, heavier poll (an
// SSH sample per server) than the status reconcile above.
function _fmtUptimeShort(s){
  s = Math.max(0, s|0);
  var d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  return d ? (d+'d '+h+'h') : (h ? (h+'h '+m+'m') : (m+'m'));
}
function refreshMsrvMetrics(){
  fetch(MOUNT + '/api/dashboard/metrics').then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if(!d) return;
      var servers = d.servers || {};
      Object.keys(servers).forEach(function(sid){
        var s = servers[sid], cell = document.getElementById('msrv-res-' + sid);
        if(cell) cell.innerHTML = s.up
          ? ('<i class="bi bi-cpu"></i> ' + s.cpu + '% · ' + s.ram_mb + ' MB'
             + (s.uptime ? ' · <span title="Uptime"><i class="bi bi-clock"></i> ' + _fmtUptimeShort(s.uptime) + '</span>' : ''))
          : '<span class="text-secondary">—</span>';
        var mapEl = document.getElementById('msrv-map-' + sid);
        if(mapEl){
          if(s.up && s.map){ mapEl.innerHTML = '<i class="bi bi-geo-alt"></i> ' + s.map; mapEl.classList.remove('d-none'); }
          else { mapEl.classList.add('d-none'); }
        }
      });
    }).catch(function(){});
}
refreshMsrvMetrics();
pollWhenVisible(refreshMsrvMetrics, 10000);

// After the servers table is swapped in place (AJAX install), re-arm the install-progress pollers
// for any new "installing" rows and adopt the new server set, so the live-sync poller above doesn't
// see a difference and force a full-page reload.
window.afterServerRefresh = function(){
  document.querySelectorAll('.install-progress-row[data-installing="1"]').forEach(function(row){
    watchInstall(row.id.substring('install-row-'.length));
  });
  _svrBaseline = serverIdsOnPage();
  // The refresh rebuilt #servers-list from scratch (flat table) — re-apply the per-host boxes if the
  // "Group by host" switch is on, so they survive another user adding a server.
  if (window.regroupAfterRefresh) window.regroupAfterRefresh();
};
