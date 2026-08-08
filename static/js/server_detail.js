// ── Section tabs (Console / Details): show only the selected group's cards. Actions and the
// pending banner are untagged, so they stay visible on both. The chart + console live in the
// default Console tab, so they initialise visible (no hidden-canvas sizing issues). ──
(function(){
  var nav = document.getElementById('sdtab-nav'); if(!nav) return;
  var TABS = ['console','history','details'];
  function show(tab){
    window._sdTab = tab;
    document.querySelectorAll('[data-mtab]').forEach(function(el){
      el.style.display = (el.getAttribute('data-mtab') === tab) ? '' : 'none';
    });
    nav.querySelectorAll('[data-mtab-btn]').forEach(function(b){
      b.classList.toggle('active', b.getAttribute('data-mtab-btn') === tab);
    });
    try { history.replaceState(null, '', '#' + tab); } catch(e){}
    // The players card is a Console-tab card whose visibility is ALSO driven by the poll — re-apply
    // it so a background refresh can't leave it showing on History/Details.
    if (window.applyPlayersVisibility) window.applyPlayersVisibility();
    if (tab === 'history' && window.loadHistory) window.loadHistory();   // lazy-load the trend charts
  }
  nav.addEventListener('click', function(e){
    var b = e.target.closest('[data-mtab-btn]'); if(b) show(b.getAttribute('data-mtab-btn'));
  });
  var h = (location.hash || '').replace('#','');
  show(TABS.indexOf(h) >= 0 ? h : 'console');
})();

var consoleEl = document.getElementById('console-output');
var wsStatus = document.getElementById('ws-status');

// ── Players + in-game moderation ──────────────────────────────
function plTime(t){
  var n = Number(t); if(!isFinite(n)) return String(t);
  n = Math.floor(n); var h=Math.floor(n/3600), m=Math.floor((n%3600)/60), s=n%60;
  return h>0 ? (h+':'+String(m).padStart(2,'0')) : (m+':'+String(s).padStart(2,'0'));
}
// The automatic poll asks gamedig only (never the console). refreshPlayers() (the button, and the
// re-read after a kick/ban) passes console=1 so a single `status` runs on your explicit action.
function loadPlayers(useConsole){
  if(!document.getElementById('players-card')) return;
  var url = MOUNT+'/api/server/'+serverId+'/playerlist' + (useConsole ? '?console=1' : '');
  fetch(url).then(function(r){return r.json();})
    .then(renderPlayers).catch(function(){ /* transient: keep what's shown */ });
}
function refreshPlayers(){ loadPlayers(true); }
// The players card belongs to the Console tab AND is content-driven (moderators always see it; others
// only when the server is queryable). Keep those two concerns from fighting: renderPlayers records
// whether the content WANTS the card, and applyPlayersVisibility() combines that with the active tab.
window.applyPlayersVisibility = function(){
  var card=document.getElementById('players-card'); if(!card) return;
  card.style.display = (window._sdTab==='console' && window._playersWanted) ? '' : 'none';
};
function renderPlayers(d){
  var card=document.getElementById('players-card'); if(!card||!d) return;
  var caps=d.caps||{}, players=d.players||[], queryable=!!d.queryable;
  // Moderators see the card whenever there's something to do (a list, or the announce box);
  // everyone else only when there's a list or announce to show — but only on the Console tab.
  window._playersWanted = (_CAN_MODERATE || queryable);
  window.applyPlayersVisibility();
  if(card.style.display==='none') return;
  var engine=d.engine||'';
  window._plEngine = engine;   // the ban dialog uses this to decide if "all servers" can apply
  var unsup=document.getElementById('pl-unsupported'), empty=document.getElementById('pl-empty'),
      wrap=document.getElementById('pl-table-wrap'), ann=document.getElementById('pl-announce'),
      cnt=document.getElementById('pl-count'), netonly=document.getElementById('pl-netonly');
  if(ann) ann.style.display = (_CAN_SAY && caps.say) ? 'flex' : 'none';
  if(netonly) netonly.style.display='none';
  if(!queryable){ if(unsup)unsup.style.display=''; if(empty)empty.style.display='none'; if(wrap)wrap.style.display='none'; if(cnt)cnt.textContent=''; return; }
  if(unsup) unsup.style.display='none';
  // gamedig couldn't read the server and the console wasn't run: show the GSLT / load-once hint for
  // a console-capable game, rather than a misleading "no players connected". But if a list is already
  // on screen (e.g. you just loaded it from the console), keep it — an automatic gamedig miss must
  // not blank what you explicitly pulled.
  if(d.unknown){
    var hasRows = wrap && wrap.style.display !== 'none';
    if(!hasRows){
      if(netonly && d.console_capable){ netonly.style.display=''; }
      else if(unsup){ unsup.style.display=''; }
      if(empty)empty.style.display='none';
    }
    return;
  }
  if(cnt) cnt.textContent='('+players.length+')';
  if(!players.length){ if(empty)empty.style.display=''; if(wrap)wrap.style.display='none'; return; }
  if(empty) empty.style.display='none'; if(wrap) wrap.style.display='';
  var rows=players.map(function(p){
    var acts='';
    if(_CAN_MODERATE){
      var sid=p.steamid||'', num=(p.num!=null?String(p.num):'');
      var da='data-name="'+escapeHtml(p.name)+'" data-steamid="'+escapeHtml(sid)+'" data-num="'+escapeHtml(num)+'"';
      if(_CAN_KICK && caps.kick) acts+='<button class="btn btn-sm btn-outline-warning py-0 px-1 me-1" '+da+'' + _da('moderatePlayer', ['@self', 'kick']) + '>Kick</button>';
      if(_CAN_BAN && caps.ban){
        // gamedig lists carry no SteamID (valve) / slot (idTech3), but the backend resolves it from
        // the console when Ban is clicked — so keep the button enabled. A player who genuinely can't
        // be resolved (a bot, or someone who just left) comes back as a clear error toast.
        acts+='<button class="btn btn-sm btn-outline-danger py-0 px-1" '+da
          + _da('moderatePlayer', ['@self', 'ban']) + '>Ban</button>';
      }
    }
    return '<tr><td class="text-truncate" style="max-width:260px;">'+escapeHtml(p.name)+'</td>'
      +'<td class="text-nowrap">'+(p.score!=null?escapeHtml(String(p.score)):'—')+'</td>'
      +'<td class="text-nowrap">'+(p.time!=null?escapeHtml(plTime(p.time)):'—')+'</td>'
      +(_CAN_MODERATE?('<td class="text-nowrap">'+acts+'</td>'):'')+'</tr>';
  }).join('');
  document.getElementById('pl-rows').innerHTML=rows;  // nosemgrep
}
function moderatePlayer(btn, action){
  var name=btn.getAttribute('data-name')||'';
  var steamid=btn.getAttribute('data-steamid')||'';
  var num=btn.getAttribute('data-num')||'';
  if(action==='ban'){ banScopeDialog(btn, name, steamid, num); return; }   // ban asks scope first
  _doModerate(btn, action, name, steamid, num, 'this');
}
function _doModerate(btn, action, name, steamid, num, scope, reason){
  btn.disabled=true;
  fetch(MOUNT+'/api/server/'+serverId+'/moderate',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:action, target:name, steamid:steamid, num:num, scope:scope, reason:reason||''})})
    .then(function(r){return r.json();}).then(function(d){
      window.toast(d.message || (d.success?'Done':'Failed'), d.success?'success':'danger');
      setTimeout(function(){ loadPlayers(true); }, 1200);   // you just moderated — re-read (console ok)
    }).catch(function(){ window.toast('Moderation failed','danger'); btn.disabled=false; });
}
// When banning, ASK: this server only, or all my servers. "All servers" is only offered where the
// identifier ports across servers (SteamID on Valve, name on Minecraft); idTech3 slot bans can't.
function banScopeDialog(btn, name, steamid, num){
  if(window._plEngine!=='valve' && window._plEngine!=='minecraft'){
    confirmDialog({
      title: 'Ban player', icon: 'slash-circle', confirmLabel: 'Ban', confirmClass: 'btn-danger',
      body: 'Ban <strong>' + _esc(name) + '</strong> from <strong>' + _esc(SERVER_NAME) + '</strong>?',
      onConfirm: function(){ _doModerate(btn,'ban',name,steamid,num,'this'); }
    });
    return;
  }
  var ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1080;display:flex;align-items:center;justify-content:center;padding:1rem;';
  ov.innerHTML='<div class="card" style="max-width:440px;width:100%;">'  // nosemgrep
    +'<div class="card-header"><i class="bi bi-slash-circle"></i> Ban '+escapeHtml(name)+'</div>'
    +'<div class="card-body"><p class="small text-secondary mb-2">Ban just on this server, or on '
    +'<strong>all your servers</strong> that can match this player (same SteamID / name)?</p>'
    +'<input type="text" id="ban-reason" class="form-control form-control-sm mb-3" maxlength="200" '
    +'placeholder="Reason (optional) — saved with an all-servers ban">'
    +'<div class="d-grid gap-2">'
    +'<button class="btn btn-danger" data-scope="all"><i class="bi bi-globe2"></i> Ban on ALL my servers</button>'
    +'<button class="btn btn-outline-danger" data-scope="this">Ban on THIS server only</button>'
    +'<button class="btn btn-outline-secondary" data-scope="cancel">Cancel</button>'
    +'</div></div></div>';
  ov.addEventListener('click', function(ev){
    if(ev.target===ov){ ov.remove(); return; }   // click the backdrop = cancel
    var b=ev.target.closest && ev.target.closest('button');
    if(!b) return;
    var scope=b.getAttribute('data-scope');
    var reason=(ov.querySelector('#ban-reason')||{}).value||'';
    ov.remove();
    if(scope==='all'||scope==='this') _doModerate(btn,'ban',name,steamid,num,scope,reason);
  });
  document.body.appendChild(ov);
}
function announceSay(){
  var inp=document.getElementById('pl-say'); if(!inp) return;
  var msg=(inp.value||'').trim(); if(!msg) return;
  fetch(MOUNT+'/api/server/'+serverId+'/moderate',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'say', message:msg})})
    .then(function(r){return r.json();}).then(function(d){
      window.toast(d.message || (d.success?'Announced':'Failed'), d.success?'success':'danger');
      if(d.success) inp.value='';
    }).catch(function(){ window.toast('Announce failed','danger'); });
}

// ── Custom commands (superadmin-defined, handed to this user's group) ──────────
// Delegated so it also covers the argument-input Enter key. The server re-checks every run
// (group assignment + scope + argument validation) — the button list is only a convenience.
function runCustomCommand(wrap, btn){
  var cmdId = wrap.getAttribute('data-cmd-id');
  var hasArg = wrap.getAttribute('data-has-arg')==='1';
  var value = '';
  if(hasArg){
    var inp = wrap.querySelector('.cc-arg');
    value = inp ? (inp.value||'').trim() : '';
    if(!value){ if(inp) inp.focus(); return; }
  }
  var orig = btn.innerHTML; btn.disabled = true;
  btn.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
  fetch(MOUNT+'/api/server/'+serverId+'/custom-command/'+cmdId, {  // nosemgrep
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({value: value})
  }).then(function(r){return r.json();}).then(function(d){
    window.toast(d.message || (d.success?'Done':'Failed'), d.success?'success':'danger');
  }).catch(function(){ window.toast('Command failed','danger'); })
  .finally(function(){ btn.disabled = false; btn.innerHTML = orig; });  // nosemgrep
}
document.addEventListener('click', function(e){
  var btn = e.target.closest && e.target.closest('.cc-run'); if(!btn) return;
  var wrap = btn.closest('.custom-cmd'); if(wrap) runCustomCommand(wrap, btn);
});
document.addEventListener('keydown', function(e){
  if(e.key!=='Enter') return;
  var inp = e.target.closest && e.target.closest('.cc-arg'); if(!inp) return;
  e.preventDefault();
  var wrap = inp.closest('.custom-cmd'); var btn = wrap && wrap.querySelector('.cc-run');
  if(wrap && btn) runCustomCommand(wrap, btn);
});
loadPlayers();
if(window.pollWhenVisible) pollWhenVisible(loadPlayers, 15000);

// "Follow the tail" only while the user is already at the bottom. If they've
// scrolled up to read history, new output must NOT yank them back down.
function consoleAtBottom() {
  return consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 48;
}
function stickConsole() { consoleEl.scrollTop = consoleEl.scrollHeight; }

// Mount prefix (e.g. "/lgsm" when served behind Tailscale Serve). All client-side
// URLs must include it, otherwise requests hit the site root (a different app).

// WebSocket connection for live console streaming. Use the shared window.socket so the
// base-layout pagehide/pageshow handlers close it for bfcache and reconnect it on return —
// the 'connect' handler below re-joins the console room automatically after a reconnect.
var socket = (window.ensureSocket && window.ensureSocket())
  || io({ path: MOUNT + '/socket.io', transports: ['websocket', 'polling'] });

socket.on('connect', function() {
  wsStatus.textContent = '(connected)';
  wsStatus.className = 'text-success small ms-2';
  socket.emit('join_console', { server_id: serverId });
});

socket.on('disconnect', function() {
  wsStatus.textContent = '(disconnected)';
  wsStatus.className = 'text-danger small ms-2';
});

socket.on('console_output', function(data) {
  if (data.server_id === serverId && data.data) {
    appendConsole(data.data);
  }
});

function appendConsole(text) {
  var stick = consoleAtBottom();   // capture BEFORE appending
  var lines = text.split('\n');
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].trim()) {
      var div = document.createElement('div');
      div.className = 'console-line';
      div.textContent = lines[i];
      consoleEl.appendChild(div);
    }
  }
  // Keep console from growing too large
  while (consoleEl.children.length > 500) {
    consoleEl.removeChild(consoleEl.firstChild);
  }
  if (stick) stickConsole();       // only auto-follow if they were at the bottom
}

var _consoleSig = null;
function refreshConsole(forceScroll) {
  // The periodic backup refresh wipes + rebuilds the console; don't yank the user
  // to the bottom unless they were already there (or it's the initial load).
  var stick = forceScroll || consoleAtBottom();
  fetch(MOUNT + '/api/console/' + serverId)
    .then(r => r.json())
    .then(data => {
      var lines = (data.lines || []).filter(function(l) { return l.trim(); });
      // Only rebuild when the log actually changed — otherwise leave the console exactly as
      // it is (no 30s wipe-and-rebuild flicker while a server sits idle).
      var sig = lines.length + ' ' + (lines[lines.length - 1] || '');
      if (sig === _consoleSig && !forceScroll) return;
      _consoleSig = sig;
      consoleEl.innerHTML = '';
      lines.forEach(function(line) {
        var div = document.createElement('div');
        div.className = 'console-line';
        div.textContent = line;
        consoleEl.appendChild(div);
      });
      if (stick) stickConsole();
    })
    .catch(() => {});
}

function clearConsole() {
  consoleEl.innerHTML = '';
}

function sendCommand(ev) {
  ev.preventDefault();
  var input = document.getElementById('command-input');
  var cmd = input.value.trim();
  if (!cmd) return false;
  input.value = '';
  // Echo locally so it feels instant; the real output streams over the websocket.
  var echo = document.createElement('div');
  echo.className = 'console-line';
  echo.style.color = '#58a6ff';
  echo.textContent = '> ' + cmd;
  consoleEl.appendChild(echo);
  consoleEl.scrollTop = consoleEl.scrollHeight;
  fetch(MOUNT + '/api/command/' + serverId, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ command: cmd })
  })
  .then(r => r.json())
  .then(d => { if (d.error) { echo.style.color = '#f85149'; echo.textContent = '> ' + cmd + '  — ' + d.error; } })
  .catch(() => { echo.style.color = '#f85149'; });
  input.focus();
  return false;
}

// Uses the global window.toast (base.html) — one implementation, consistent independent timing.

// Delegates — the old fallback returned the raw string, and String(null) rendered "null".
function _esc(s){ return window.escapeHtml(s); }

// Fire a server action against the JSON endpoint (spinner + toast + banner handling).
function _doServerAction(action, btn, showOutput) {
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  fetch(MOUNT + '/api/server/' + serverId + '/action', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ action: action })
  })
  .then(r => r.json())
  .then(d => {
    // Maintenance/info actions (details, postdetails, monitor, …) return text you want to READ —
    // show it in a dismissible panel, not a toast that disappears before you see it.
    if (showOutput) showActionOutput(action, d.message || (d.success ? 'Done — no output' : 'Failed'), d.success);
    else toast(d.message || (action + ' done'), d.success ? 'success' : 'danger');
    if (d.success && (action === 'restart' || action === 'start' || action === 'stop')) {
      var b = document.getElementById('restart-pending-banner');
      if (b) b.classList.add('d-none');
    }
    setTimeout(pollStats, 1200);
  })
  .catch(() => toast('Action failed — connection error', 'danger'))
  .finally(() => { btn.disabled = false; btn.innerHTML = orig; });  // nosemgrep
}
// Dismissible panel showing a command's full output (for maintenance/info actions). Persists until
// you close it (button / backdrop / Esc), so you can read long output like `details`.
function showActionOutput(title, text, ok) {
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1090;display:flex;align-items:center;justify-content:center;padding:1rem;';
  ov.innerHTML = '<div class="card" style="max-width:760px;width:100%;max-height:85vh;display:flex;flex-direction:column;">'  // nosemgrep
    + '<div class="card-header d-flex justify-content-between align-items-center">'
    + '<span><i class="bi bi-' + (ok ? 'info-circle' : 'x-circle') + '"></i> ' + escapeHtml(title) + '</span>'
    + '<button class="btn btn-sm btn-outline-secondary py-0 px-2" data-close="1">Close</button></div>'
    + '<div class="card-body" style="flex:1 1 auto;min-height:0;overflow-y:auto;">'
    + '<pre style="white-space:pre-wrap;word-break:break-word;margin:0;font-size:.8rem;">' + escapeHtml(text) + '</pre>'
    + '</div></div>';
  function close(){ ov.remove(); document.removeEventListener('keydown', onEsc); }
  function onEsc(e){ if (e.key === 'Escape') close(); }
  ov.addEventListener('click', function(ev){
    if (ev.target === ov || (ev.target.closest && ev.target.closest('[data-close]'))) close();
  });
  document.addEventListener('keydown', onEsc);
  document.body.appendChild(ov);
}

function serverAction(action, btn, confirmFirst, showOutput) {
  // Restart AND stop get a player check first — warn, and offer "when empty".
  if (action === 'restart' || action === 'stop') { return actionWithPlayerCheck(action, btn); }
  if (confirmFirst) {
    var body = _esc(_cap(action)) + ' <strong>' + _esc(SERVER_NAME) + '</strong>?';
    if (action === 'fastdl') {
      body = 'Generate FastDL files for <strong>' + _esc(SERVER_NAME) + '</strong>? '
           + 'This overwrites the existing FastDL directory and can take a while.';
    }
    confirmDialog({ title: _cap(action), body: body, confirmLabel: _cap(action),
                    onConfirm: function(){ _doServerAction(action, btn, showOutput); } });
    return;
  }
  _doServerAction(action, btn, showOutput);
}

function _cap(s){ return s.charAt(0).toUpperCase() + s.slice(1); }

// confirmDialog() is a shared global defined in base.html (window.confirmDialog).

// Restart/Stop confirm for an EMPTY server (or when the player count is unknown) — the
// in-app equivalent of the old native confirm, matching the players-online dialog's look.
function confirmActionDialog(action, btn, note){
  confirmDialog({
    title: _cap(action) + ' server',
    icon: action === 'stop' ? 'stop-fill' : 'arrow-clockwise',
    body: _esc(_cap(action)) + ' <strong>' + _esc(SERVER_NAME) + '</strong>?'
          + (note ? ' <span class="text-secondary">' + _esc(note) + '</span>' : ''),
    confirmLabel: _cap(action),
    confirmClass: action === 'stop' ? 'btn-danger' : 'btn-warning',
    onConfirm: function(){ _doServerAction(action, btn); }
  });
}

function actionWithPlayerCheck(action, btn) {
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  fetch(MOUNT + '/api/server/' + serverId + '/players').then(r => r.json()).then(function(d){
    btn.disabled = false; btn.innerHTML = orig;  // nosemgrep
    var n = (d && d.players) || 0;   // null/unknown -> treat as none (show a plain in-app confirm)
    if (!n) { confirmActionDialog(action, btn); return; }
    actionPlayersDialog(action, n, btn);
  }).catch(function(){
    btn.disabled = false; btn.innerHTML = orig;  // nosemgrep
    confirmActionDialog(action, btn, "(couldn't check who's online)");
  });
}

function actionPlayersDialog(action, n, btn) {
  var verb = _cap(action);                                   // Restart / Stop
  var lower = action;                                        // restart / stop
  var endpoint = action === 'stop' ? 'stop-when-empty' : 'restart-when-empty';
  var nowIcon = action === 'stop' ? 'stop-fill' : 'arrow-clockwise';
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1080;display:flex;align-items:center;justify-content:center;padding:1rem;';
  ov.innerHTML = '<div class="card" style="max-width:540px;width:100%;">'  // nosemgrep
    + '<div class="card-header"><i class="bi bi-people-fill"></i> Players are online</div>'
    + '<div class="card-body">'
    + '<p class="mb-2"><strong>' + n + '</strong> player' + (n===1?' is':'s are') + ' connected to <strong>' + _esc(SERVER_NAME) + '</strong>. ' + verb + 'ping now disconnects ' + (n===1?'them':'everyone') + '.</p>'
    + '<p class="small text-secondary mb-3">Are you sure you want to ' + lower + ' with players on?</p>'
    + '<div class="d-flex flex-column gap-2">'
    + '<button class="btn btn-warning" id="rd-now"><i class="bi bi-' + nowIcon + '"></i> Yes, ' + lower + ' now (disconnect ' + n + ' player' + (n===1?'':'s') + ')</button>'
    + '<button class="btn btn-success" id="rd-wait"><i class="bi bi-hourglass-split"></i> No — ' + lower + ' when the server is empty</button>'
    + '<button class="btn btn-outline-secondary" id="rd-cancel">Cancel</button>'
    + '</div></div></div>';
  document.body.appendChild(ov);
  function close(){ ov.remove(); }
  ov.querySelector('#rd-now').onclick = function(){ close(); _doServerAction(action, btn); };
  ov.querySelector('#rd-wait').onclick = function(){
    close();
    fetch(MOUNT + '/api/server/' + serverId + '/' + endpoint, {method:'POST', headers:{'Content-Type':'application/json'}})
      .then(r => r.json()).then(function(d){
        toast(d.message || ('Queued — will ' + lower + ' once empty.'), d.success ? 'success' : 'danger');
        if (d.success) { showPendingBanner(action); }
      }).catch(function(){ toast('Could not queue the ' + lower, 'danger'); });
  };
  ov.querySelector('#rd-cancel').onclick = close;
  ov.addEventListener('click', function(e){ if (e.target === ov) close(); });
}

// Reflect a queued 'when empty' action (restart|stop) in the banner and show it.
function showPendingBanner(action){
  var b = document.getElementById('restart-pending-banner');
  if (!b) return;
  b.dataset.action = action;
  var v = document.getElementById('rpb-verb'); if (v) v.textContent = action;
  var bt = document.getElementById('rpb-btn'); if (bt) bt.textContent = _cap(action) + ' now';
  b.classList.remove('d-none');
}

// The banner's "do it now" button — runs whichever action is queued (restart|stop).
function bannerDoNow(btn){
  var b = document.getElementById('restart-pending-banner');
  serverAction((b && b.dataset.action) || 'restart', btn);
}

function toggleAutostart(el) {
  el.disabled = true;
  fetch(MOUNT + '/api/server/' + serverId + '/autostart', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enabled: el.checked })
  })
  .then(r => r.json())
  .then(d => { if (!d.success) { el.checked = !el.checked; if(window.toast) toast(d.message || 'Failed to update autostart', 'danger'); } })
  .catch(() => { el.checked = !el.checked; })
  .finally(() => { el.disabled = false; });
}

function toggleDailyRestart(el) {
  el.disabled = true;
  fetch(MOUNT + '/api/server/' + serverId + '/daily-restart', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enabled: el.checked })
  })
  .then(r => r.json())
  .then(d => {
    if (!d.success) { el.checked = !el.checked; if(window.toast) toast(d.message || 'Failed to update daily restart', 'danger'); }
    else if (typeof toast === 'function') { toast(el.checked ? 'Daily restart (when empty) enabled' : 'Daily restart disabled', 'success'); }
  })
  .catch(() => { el.checked = !el.checked; })
  .finally(() => { el.disabled = false; });
}

function toggleNotifyEmpty(el) {
  el.disabled = true;
  fetch(MOUNT + '/api/server/' + serverId + '/notify-empty', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enabled: el.checked })
  })
  .then(r => r.json())
  .then(d => {
    if (!d.success) { el.checked = !el.checked; if(window.toast) toast(d.message || 'Failed to update', 'danger'); }
    else if (typeof toast === 'function') {
      toast(el.checked ? "You'll be alerted once this server is empty (then it turns itself off)"
                       : 'Empty alert cancelled', 'success');
    }
  })
  .catch(() => { el.checked = !el.checked; })
  .finally(() => { el.disabled = false; });
}

// ── Live stats + chart ───────────────────────────────────────
var connectAddr = '';
function copyConnect() {
  var addr = connectAddr || (document.getElementById('connect-addr') || {}).textContent || '';
  addr = addr.trim();
  if (addr && addr !== 'resolving…' && addr !== 'unknown') window.copyText(addr, 'Copied ' + addr);
}
// Sidebar "Connect" code cell — click anywhere on it to copy ip:port.
document.addEventListener('click', function(ev){
  var el = ev.target.closest('.copy-addr'); if(!el) return;
  window.copyText(el.getAttribute('data-copy'), 'Copied ' + el.getAttribute('data-copy'));
});
function fmtGB(b) { return (b / 1073741824).toFixed(1) + ' GB'; }  // NOPMD
function fmtUptime(s) {
  var d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  return d ? d+'d '+h+'h' : (h ? h+'h '+m+'m' : m+'m');
}
function setStatus(status) {
  var badge = document.getElementById('status-badge'), text = document.getElementById('status-text');
  if (!text) return;
  text.textContent = status.charAt(0).toUpperCase() + status.slice(1);
  badge.style.background = status === 'online' ? '#3fb950' : (status === 'offline' ? '#f85149' : '#d29922');
}

var statsChart = null;
function initChart() {
  if (typeof Chart === 'undefined') return;
  // The canvas lives inside the Controls panel, which a user can now HIDE. Without this guard the
  // TypeError aborts the rest of this inline script — including the handlers that undo a hide, so
  // hiding Controls would leave no way to bring it back.
  var canvas = document.getElementById('stats-chart');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var mk = function(label, color) {
    return { label: label, data: [], borderColor: color, backgroundColor: color+'22',
             fill: true, tension: .35, pointRadius: 0, borderWidth: 2 };  // NOPMD
  };
  statsChart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [ mk('Game CPU %', '#3fb950'), mk('Server CPU %', '#58a6ff') ] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { intersect: false, mode: 'index' },
      scales: {
        y: { min: 0, max: 100, ticks: { color: '#8b98a5', maxTicksLimit: 5 }, grid: { color: 'rgba(255,255,255,.05)' } },
        x: { ticks: { color: '#8b98a5', maxTicksLimit: 6, maxRotation: 0 }, grid: { display: false } }
      },
      plugins: { legend: { labels: { color: '#c9d1d9', boxWidth: 12, boxHeight: 12 } } }
    }
  });
}

// Self-scheduling stats poll. A live server gets a snappy refresh so the CPU/RAM graph moves;
// an offline/unreachable one barely changes, so we poll it lazily instead of SSH-ing every few
// seconds. Paused entirely while the tab is hidden (see the visibilitychange catch-up below).
var _lastStatus = '';
var _statsTimer = null;
function _scheduleStats() {
  if (_statsTimer) { clearTimeout(_statsTimer); }
  var delay = (_lastStatus === 'online') ? 8000 : 20000;
  _statsTimer = setTimeout(pollStats, delay);
}
function pollStats() {
  if (document.hidden) { _scheduleStats(); return; }   // don't poll a backgrounded tab; re-check later
  fetch(MOUNT + '/api/server/' + serverId + '/stats')
    .then(r => r.json())
    .then(d => {
      if (d.error) return;
      _lastStatus = d.status || '';
      connectAddr = d.connect || '';
      document.getElementById('connect-addr').textContent = connectAddr || 'unknown';
      // One-click join link (steam://connect/…) for games that support it.
      var join = document.getElementById('connect-join');
      if (join) {
        if (d.connect_url) { join.href = d.connect_url; join.style.display = ''; }
        else { join.removeAttribute('href'); join.style.display = 'none'; }
      }
      setStatus(d.status);
      var m = d.metrics || {};
      // Game-specific tiles
      document.getElementById('stat-gcpu').textContent = (m.game_cpu_percent!=null? m.game_cpu_percent : '–') + '%';
      document.getElementById('stat-gcpu-sub').textContent = 'of ' + (m.cores||1) + '-core server';
      document.getElementById('stat-gram').textContent = (m.game_ram_mb||0) + ' MB';
      document.getElementById('stat-gram-sub').textContent = (m.game_ram_percent!=null? m.game_ram_percent+'% of RAM' : (m.game_procs||0)+' procs');
      document.getElementById('stat-gup').textContent = m.game_procs ? fmtUptime(m.game_uptime_secs||0) : 'stopped';
      document.getElementById('stat-gup-sub').textContent = (m.game_procs||0) + ' process' + ((m.game_procs===1)?'':'es');
      // Whole-server tile
      document.getElementById('stat-scpu').textContent = (m.cpu_percent!=null? m.cpu_percent : '–') + '%';
      document.getElementById('stat-server-sub').textContent = 'RAM ' + (m.ram_percent||0) + '% · disk ' + (m.disk_percent||0) + '%';
      if (statsChart) {
        var t = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
        var L = statsChart.data.labels, A = statsChart.data.datasets[0].data, B = statsChart.data.datasets[1].data;
        L.push(t); A.push(m.game_cpu_percent||0); B.push(m.cpu_percent||0);
        if (L.length > 45) { L.shift(); A.shift(); B.shift(); }
        statsChart.update('none');
      }
    })
    .catch(() => {})
    .finally(_scheduleStats);
}

// ── History charts (persisted CPU/RAM/player trends, lazy-loaded when the History tab opens) ──
var _histRange = '24h';
var _histCharts = {};
var _histTimes = {};   // chart id -> Date[] (one per data point, by category index); refreshed each load
var _histX = { ticks:{color:'#8b98a5', maxTicksLimit:6, maxRotation:0}, grid:{display:false} };
// Date-aware x-axis for the 24h view: a 24h window crosses midnight, so time-only ticks are
// ambiguous about which day they belong to. Chart.js generates labels over the FULL tick set before
// auto-skipping, so a per-point "is this a new day?" check lands the date on the midnight point,
// which auto-skip usually then hides. Instead: the tick callback returns a 2-line [time, date] for
// EVERY tick (so fit() reserves height for the date row), then afterFit — which runs on the actual
// post-auto-skip rendered ticks — demotes repeated dates to time-only. Net: the date shows on the
// first tick and wherever the day changes among the *shown* ticks. Reads _histTimes[id] live so the
// 30s in-place refresh tracks the new timestamps. (If a build ignored the afterFit demotion it would
// harmlessly fall back to date-on-every-tick — never clipped, since fit already reserved two lines.)
function _histXScale(id){
  var fmtT = function(t){ return t.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); };
  var fmtD = function(t){ return t.toLocaleDateString([], {month:'short', day:'numeric'}); };
  return { grid:{display:false},
    afterFit: function(scale){
      var prev = null;
      scale.ticks.forEach(function(tk){
        var t = (_histTimes[id] || [])[tk.value]; if(!t) return;
        var d = fmtD(t);
        tk.label = (d === prev) ? fmtT(t) : [fmtT(t), d];
        prev = d;
      });
    },
    ticks:{ color:'#8b98a5', maxTicksLimit:6, maxRotation:0, autoSkip:true,
      callback: function(value){ var t=(_histTimes[id]||[])[value]; return t ? [fmtT(t), fmtD(t)] : ''; } } };
}
function _histChart(id, labels, datasets, yScales, xScale){
  var el = document.getElementById(id); if(!el || typeof Chart==='undefined') return;
  var existing = _histCharts[id];
  if(existing){
    // Live refresh: update the data in place (no destroy/recreate) so the chart doesn't flash and
    // keeps the tooltip/hover state. The dataset structure is stable per chart id.
    existing.data.labels = labels;
    datasets.forEach(function(ds, i){
      if(existing.data.datasets[i]) existing.data.datasets[i].data = ds.data;
      else existing.data.datasets[i] = ds;
    });
    existing.data.datasets.length = datasets.length;
    existing.update('none');
    return;
  }
  var scales = { x:(xScale||_histX) }; for(var k in yScales){ scales[k]=yScales[k]; }
  _histCharts[id] = new Chart(el.getContext('2d'), {
    type:'line', data:{ labels:labels, datasets:datasets },
    options:{ responsive:true, maintainAspectRatio:false, animation:false,
      interaction:{intersect:false, mode:'index'}, scales:scales,
      plugins:{ legend:{ labels:{color:'#c9d1d9', boxWidth:12, boxHeight:12} } } }
  });
}
function _histLbl(iso){
  // Tooltip title (per point). Both ranges carry the date so a hovered point is never ambiguous
  // about which day it is; the compact date-at-change lives on the x-axis ticks (_histXScale).
  var d = new Date(iso);
  return _histRange==='7d' ? d.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit'})
                           : d.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
}
function _ds(label, data, color, fill){
  return { label:label, data:data, borderColor:color, backgroundColor:color+'22',
           fill:!!fill, tension:.3, pointRadius:0, borderWidth:2, spanGaps:true };  // NOPMD
}
window.loadHistory = function(){
  fetch(MOUNT + '/api/server/' + serverId + '/history?range=' + encodeURIComponent(_histRange))
    .then(function(r){ return r.json(); })
    .then(function(d){
      var s = d.server || [], h = d.host || [];
      var empty = document.getElementById('hist-empty'), charts = document.getElementById('hist-charts');
      if(!s.length && !h.length){ if(empty)empty.style.display=''; if(charts)charts.style.display='none'; return; }
      if(empty)empty.style.display='none'; if(charts)charts.style.display='';
      var sL = s.map(function(p){ return _histLbl(p.t); }), hL = h.map(function(p){ return _histLbl(p.t); });
      // Parsed timestamps for the date-aware 24h axis; refreshed every load so in-place updates stay in sync.
      _histTimes['hist-players'] = _histTimes['hist-server'] = s.map(function(p){ return new Date(p.t); });
      _histTimes['hist-host'] = h.map(function(p){ return new Date(p.t); });
      var _xs = function(id){ return _histRange==='7d' ? _histX : _histXScale(id); };
      var pctY = { y:{ min:0, max:100, ticks:{color:'#8b98a5', maxTicksLimit:5}, grid:{color:'rgba(255,255,255,.05)'} } };
      _histChart('hist-players', sL,
        [ _ds('Players', s.map(function(p){return p.players;}), '#58a6ff', true) ],
        { y:{ min:0, ticks:{color:'#8b98a5', maxTicksLimit:5, precision:0}, grid:{color:'rgba(255,255,255,.05)'} } }, _xs('hist-players'));
      _histChart('hist-server', sL, [
        Object.assign(_ds('CPU %', s.map(function(p){return p.cpu;}), '#3fb950', true), {yAxisID:'y'}),
        Object.assign(_ds('RAM MB', s.map(function(p){return p.ram;}), '#d29922', false), {yAxisID:'y1'})
      ], { y:{ min:0, max:100, position:'left', ticks:{color:'#8b98a5', maxTicksLimit:5}, grid:{color:'rgba(255,255,255,.05)'} },
           y1:{ min:0, position:'right', ticks:{color:'#8b98a5', maxTicksLimit:5}, grid:{display:false} } }, _xs('hist-server'));
      _histChart('hist-host', hL, [
        _ds('CPU %', h.map(function(p){return p.cpu;}), '#58a6ff', false),
        _ds('RAM %', h.map(function(p){return p.ram;}), '#3fb950', false),
        _ds('Disk %', h.map(function(p){return p.disk;}), '#d29922', false)
      ], pctY, _xs('hist-host'));
    }).catch(function(){});
};
document.addEventListener('click', function(e){
  var b = e.target.closest && e.target.closest('[data-hist-range]'); if(!b) return;
  var rng = b.getAttribute('data-hist-range'); if(rng === _histRange) return;
  _histRange = rng;
  if(b.parentNode) b.parentNode.querySelectorAll('[data-hist-range]').forEach(function(x){ x.classList.toggle('active', x===b); });
  // Recreate the charts on range change so the x-axis swaps between the date-aware (24h) and plain
  // (7d) formatter — the live-refresh path deliberately reuses the chart and won't re-apply scales.
  Object.keys(_histCharts).forEach(function(id){ try{ _histCharts[id].destroy(); }catch(err){} delete _histCharts[id]; });
  window.loadHistory();
});
// Keep the History charts live — refresh while its tab is open and the page is visible (a new sample
// lands every minute server-side). Updates in place, so it never flashes or steals focus.
if(window.pollWhenVisible) pollWhenVisible(function(){ if(window._sdTab==='history') window.loadHistory(); }, 30000);

// ── GMod game content: per-server mount (enable/disable) + host install/uninstall ──
function loadGmodContent(){
  var el = document.getElementById('gmod-content-body');
  if(!el) return;
  fetch(MOUNT + '/api/server/' + serverId + '/gmod-content')
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(d.error){ el.innerHTML = '<span class="text-danger">'+_esc(d.error)+'</span>'; return; }  // nosemgrep
      var running = d.job && d.job.status === 'running';
      // Installable games always show; owned/mount-only games only once their content is on the host
      // (or already mounted). Mount-only content that isn't present can't be added by the panel.
      var visible = (d.games||[]).filter(function(g){ return g.downloadable || g.present || g.mounted; });
      var rows = visible.map(function(g){
        var status, act = '';
        if (g.present) {
          status = '<span class="text-success">on host</span>';
          // Any content on the host can be removed to free disk — including owned/mount-only games.
          act = '<button class="btn btn-link btn-sm p-0 text-danger" style="font-size:.72rem;" type="button" '
            + 'data-gmc-uninstall="'+_esc(g.key)+'" data-gmc-label="'+_esc(g.label)+'"'+(running?' disabled':'')+'>Uninstall</button>';
        } else if (g.downloadable) {
          status = '<span class="text-secondary">installs '+_esc(g.size||'')+'</span>';
        } else {
          status = '<span class="text-warning">not on host</span>';
        }
        // Flex row: the label flexes+truncates so the status + Uninstall stay inside the card on
        // narrow (mobile) screens instead of being pushed off the right edge.
        return '<div class="d-flex align-items-center gap-2">'
          + '<input class="form-check-input gmc-box flex-shrink-0 mt-0" type="checkbox" value="'+_esc(g.key)+'" id="gmc-'+_esc(g.key)+'"'
          + (g.mounted?' checked':'') + (running?' disabled':'') + '>'
          + '<label class="small text-truncate" style="flex:1 1 auto;min-width:0;margin:0;cursor:pointer;" for="gmc-'+_esc(g.key)+'">'+_esc(g.label)+'</label>'
          + '<span class="small text-nowrap flex-shrink-0">'+status+'</span>'
          + (act ? '<span class="flex-shrink-0">'+act+'</span>' : '')
          + '</div>';
      }).join('');
      function _gb(b){ return (b/1073741824).toFixed(b >= 10.7e9 ? 0 : 1) + ' GB'; }   // bytes -> GB  // NOPMD
      var disk = (d.disk_free != null && d.disk_total != null)
        ? '<div class="small mb-2"><i class="bi bi-hdd"></i> Host disk: '
          + '<b class="'+(d.disk_free < 5368709120 ? 'text-danger' : 'text-success')+'">'+_gb(d.disk_free)+' free</b>'  // NOPMD
          + ' <span class="text-secondary">of '+_gb(d.disk_total)+'</span></div>'
        : '';
      el.innerHTML =  // nosemgrep
        '<div class="mb-2 text-secondary" style="font-size:.78rem;">'
        + '<b>Tick a game</b> to mount it on <b>this</b> server (enable/disable per server) — a game not '
        + 'yet on the host is installed via LinuxGSM when you Apply, and kept current by a weekly update. '
        + '<b>Uninstall</b> removes the content from the host, freeing disk for <i>every</i> GMod server '
        + 'here. Restart the server to load mount changes.</div>'
        + disk
        + '<div class="d-flex flex-column gap-1 mb-2">' + rows + '</div>'
        + (running
            ? '<div class="text-info small"><span class="spinner-border spinner-border-sm"></span> Working… (install/removal can take a while) '+_esc((d.job&&d.job.msg)||'')+'</div>'
            : '<button class="btn btn-sm btn-primary" type="button" id="gmc-apply"><i class="bi bi-save"></i> Apply mounts</button>'
              + ' <span class="text-secondary small ms-1">Restart the server afterwards to load changes.</span>');
      // Attach handlers programmatically — the strict CSP (no unsafe-inline) blocks inline onclick=.
      var _ap = el.querySelector('#gmc-apply');
      if(_ap) _ap.onclick = function(){ applyGmodContent(_ap); };
      el.querySelectorAll('[data-gmc-uninstall]').forEach(function(b){
        b.onclick = function(){ uninstallGmodContent(b.getAttribute('data-gmc-uninstall'), b.getAttribute('data-gmc-label')); };
      });
      if(running) setTimeout(loadGmodContent, 5000);
    })
    .catch(function(){ el.innerHTML = '<span class="text-danger">Could not load content status.</span>'; });
}
function _gmcPost(bodyObj, okMsg){
  fetch(MOUNT + '/api/server/' + serverId + '/gmod-content', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(bodyObj)
  }).then(function(r){ return r.json(); }).then(function(d){
    if(window.toast) toast(d.message || (d.success?okMsg:'Failed'), d.success?'success':'danger');
    setTimeout(loadGmodContent, 1500);
  }).catch(function(){ if(window.toast) toast('Request failed','danger'); });
}
function applyGmodContent(btn){
  var sel = Array.prototype.map.call(document.querySelectorAll('.gmc-box:checked'), function(b){ return b.value; });
  if(btn){ btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Applying…'; }
  _gmcPost({action:'mount', games: sel}, 'Applying…');
}
function uninstallGmodContent(key, label){
  window.confirmDialog({
    title:'Uninstall '+label+' content', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Uninstall',
    bodyText:'Remove '+label+' content from this host?\n\nThis frees disk but removes it for EVERY GMod server on the host. You can re-install it later from any GMod server.',
    onConfirm:function(){ _gmcPost({action:'uninstall', games:[key]}, 'Removing…'); }
  });
}
loadGmodContent();

// Populate console immediately via AJAX (page render no longer waits on SSH),
// then let the websocket stream take over.
refreshConsole(true);   // initial load: jump to the latest output
// Layout handlers are defined BEFORE the bootstrap calls below on purpose: initChart/pollStats
// touch elements that a user can now hide, and a throw there would otherwise leave movePanel,
// hidePanel and showDetailPanel undefined — i.e. no way to undo the hide that caused it.
// ── Per-user panel order for this page's Console tab ─────────────────────────────────────────────
// Same shape as the dashboard: the SERVER renders the saved order, and these controls move the node
// for instant feedback and persist the result. Scoped to one region, because the tab switcher drives
// display on every [data-mtab] node and mixing tabs into one order would fight it.
function saveDetailLayout(then){
  var region = document.getElementById('detail-console');
  if (!region) return;
  var keys = Array.prototype.slice.call(region.querySelectorAll(':scope > [data-panel]'))
    .map(function(el){ return el.getAttribute('data-panel'); });
  var declared = [];
  try { declared = JSON.parse(region.getAttribute('data-declared') || '[]'); } catch (e) {}
  var bar = document.getElementById('detail-console-hidden');
  var hidden = bar ? Array.prototype.slice.call(bar.querySelectorAll('[data-action="showDetailPanel"]'))
    .map(function(b){ return JSON.parse(b.getAttribute('data-args'))[1]; }) : [];
  fetch(MOUNT + '/api/account/ui-order', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    // `declared` = the keys THIS page could have sent. The server keeps stored keys outside it,
    // so viewing a server without Commands/Game Content cannot erase where you put them elsewhere.
    body: JSON.stringify({panels: {detail_console: keys}, hidden: {detail_console: hidden},
                          declared: {detail_console: declared}})
  })
    .then(function(r){ if(!r.ok) throw 0; return r.json(); })
    .then(function(d){ if(!d || d.success === false) throw 0; if (then) then(); })
    .catch(function(){
      if (window.toast) toast('Could not save your layout — it will revert on reload.', 'danger');
    });
}

// This page reuses the dashboard's action NAMES, so the handlers have to exist here too — they are
// per-page by design (each page knows its own regions and save payload).
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
  saveDetailLayout();
};

window.hidePanel = function(btn){
  var panel = btn.closest('[data-panel]');
  if (!panel) return;
  var key = panel.getAttribute('data-panel');
  var label = (panel.querySelector('.card-header') || {}).textContent || key;
  var bar = document.getElementById('detail-console-hidden');
  if (!bar){
    bar = document.createElement('div');
    bar.id = 'detail-console-hidden';
    bar.className = 'mb-3 d-flex align-items-center gap-2 flex-wrap';
    bar.setAttribute('data-mtab', 'console');   // or it would show on History/Details too
    var lead = document.createElement('span');
    lead.className = 'text-secondary small';
    lead.textContent = 'Hidden:';
    bar.appendChild(lead);
    var region = document.getElementById('detail-console');
    region.parentNode.insertBefore(bar, region.nextSibling);
  }
  var chip = document.createElement('button');
  chip.type = 'button';
  chip.className = 'btn btn-sm btn-outline-secondary';
  chip.setAttribute('data-action', 'showDetailPanel');
  chip.setAttribute('data-args', JSON.stringify(['detail_console', key, '@self']));
  chip.textContent = label.trim().split('\n')[0] || key;
  bar.appendChild(chip);
  panel.remove();
  saveDetailLayout();
};

// A hidden panel is not rendered at all, so restoring needs markup only the server has: save first,
// reload on the acknowledgement.
window.showDetailPanel = function(region, key, btn){
  btn.remove();
  saveDetailLayout(function(){ location.reload(); });
};

if (window.makeSortable) {
  makeSortable(document.getElementById('detail-console'),
               {itemSelector: '[data-panel]', axis: 'y', onDrop: saveDetailLayout});
}

initChart();
pollStats();   // self-schedules: ~8s while online, ~20s while offline, paused while the tab is hidden
// Refocusing the tab catches up immediately (the poll pauses while hidden).
document.addEventListener('visibilitychange', function(){ if (!document.hidden) pollStats(); });
// Backup console refresh (websocket is primary) — respects your scroll position
pollWhenVisible(function(){ refreshConsole(); }, 30000);
