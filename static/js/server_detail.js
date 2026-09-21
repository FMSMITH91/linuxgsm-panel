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
  // DEFERRED to after this file has finished executing. show() guards on
  // window.applyPlayersVisibility and window.loadHistory, and both are ASSIGNED further down this
  // same file (not hoisted function declarations) — so on the initial load both guards were
  // falsy and neither ran. Two visible consequences: the players card, which the template renders
  // hidden and show() unhides, flashed in empty on every load and stayed if the first
  // /playerlist fetch failed; and opening /server/<id>#history — which happens on any reload
  // after clicking History, because show() replaceState's the hash — left three blank canvases
  // until the 30s poll came round.
  //
  // A click on a tab was always fine: by then the whole file has run. Only the FIRST call, made
  // during execution, could see the half-initialised module.
  var _initial = TABS.indexOf(h) >= 0 ? h : 'console';
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { show(_initial); });
  } else {
    setTimeout(function () { show(_initial); }, 0);
  }
})();

var consoleEl = document.getElementById('console-output');

var wsStatus = document.getElementById('ws-status');

function plTime(t){
  var n = Number(t); if(!isFinite(n)) return String(t);
  n = Math.floor(n); var h=Math.floor(n/3600), m=Math.floor((n%3600)/60), s=n%60;
  return h>0 ? (h+':'+String(m).padStart(2,'0')) : (m+':'+String(s).padStart(2,'0'));
}

function loadPlayers(useConsole){
  if(!document.getElementById('players-card')) return;
  var url = MOUNT+'/api/server/'+serverId+'/playerlist' + (useConsole ? '?console=1' : '');
  fetch(url).then(function(r){return r.json();})
    .then(renderPlayers).catch(function(){ /* transient: keep what's shown */ });
}

function refreshPlayers(){ loadPlayers(true); }

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
      // Re-enable on a REFUSAL too, not only when fetch throws. A request that answers
      // {success:false} — no permission, the player already left, console unreachable — left the
      // button dead, and the reload below is not a way back: renderPlayers returns early when the
      // list comes back `unknown`, which is exactly what an unreachable server produces. So the
      // one case where you most want to retry was the one that took the button away.
      if (!d.success) btn.disabled = false;
      setTimeout(function(){ loadPlayers(true); }, 1200);   // you just moderated — re-read (console ok)
    }).catch(function(){ window.toast('Moderation failed','danger'); btn.disabled=false; });
}

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

function consoleAtBottom() {
  return consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 48;
}

function stickConsole() { consoleEl.scrollTop = consoleEl.scrollHeight; }

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
  if (data.server_id !== serverId || !data.data) return;
  var stick = consoleAtBottom();   // capture BEFORE appending
  if (data.rows && data.rows.length) {
    // Per-line rows: a LinuxGSM-stamped line carries the time the GAME wrote it, which beats the
    // moment the poller happened to read it. data.ts is the fallback for lines with no stamp —
    // those the panel did watch arrive, so it is an honest time for them.
    _appendConsoleRows(data.rows.filter(function (r) {
      return r && typeof r.line === 'string' && r.line.trim();
    }), data.ts);
    updateTsNotice();
  } else {
    appendConsole(data.data, data.ts);
  }
  if (stick) stickConsole();
});

// Live output pushed over the websocket. This is the path that actually runs on a busy server, and
// it used to carry its OWN 500-line cap and its own rendering — so however much history the poll
// provided, the next chat message trimmed the console back to 500 lines. It also appended without
// telling the scrollback buffer, which would then let the next poll re-append the same lines as if
// they were new. Both paths go through _appendConsole now: one cap, one buffer, no duplicates.
function appendConsole(text, ts) {
  var stick = consoleAtBottom();   // capture BEFORE appending
  _appendConsole(String(text).split('\n').filter(function(l){ return l.trim(); }), ts);
  updateTsNotice();
  if (stick) stickConsole();       // only auto-follow if they were at the bottom
}

var _consoleSig = null;
// Every line currently on screen, oldest first. The console used to be rebuilt from each poll's
// response — `innerHTML = ''` then re-render — so what you could see was never more than the
// server's tail window, and everything older was dropped on every refresh. This is the scrollback
// instead: each poll only CONTRIBUTES the lines that are new, so history accumulates in the
// browser and the poll stays small.
var _consoleLines = [];
// False until the first poll has replaced the server-rendered seed with its deeper window.
var _consolePrimed = false;
// Beyond this the oldest lines are dropped. A console-line div each, so this is a real DOM cost —
// 5000 is roughly an evening of a busy server and still scrolls smoothly.
var CONSOLE_MAX_LINES = 5000;

// Seed the buffer from what the SERVER already rendered into the page. Without this the first poll
// sees an empty buffer, finds no overlap, and appends its whole window on top of the identical
// lines already on screen — the console would open showing everything twice.
(function seedConsoleBuffer(){
  if (!consoleEl) return;
  _consoleLines = Array.prototype.map.call(consoleEl.querySelectorAll('.console-line'),
                                           function(el){ return el.textContent; });
})();

// How much of `incoming` is genuinely new, given what is already on screen.
//
// The poll returns a SLIDING WINDOW of the log's tail, so consecutive responses overlap heavily —
// appending all of it would duplicate almost everything. Find the longest suffix of what we have
// that is also a prefix of what arrived, and keep only the remainder. When nothing matches, the
// log moved further than one window between polls (a very busy server, a long pause, a rotation),
// and the whole batch is new.
function _eqRange(a, ai, b, bi, n) {
  for (var i = 0; i < n; i++) if (a[ai + i] !== b[bi + i]) return false;
  return true;
}
function _newConsoleLines(have, incoming) {
  if (!incoming.length) return [];
  if (!have.length) return incoming;
  // Find where our last line sits in the incoming window, searching from ITS end so the most
  // recent occurrence wins (log lines repeat — "Player connected" a hundred times a night), then
  // verify the run leading up to it matches what we have. Everything after that point is new.
  //
  // Searching this way covers both shapes in one pass. The window usually CONTINUES from where we
  // are, and our last line lands near the window's start. But it can also reach FURTHER BACK than
  // we do and contain everything we hold — which is what happens on first load, where the page is
  // server-rendered with a short tail and the first poll then asks for a much longer one. Handling
  // only the first shape duplicated every server-rendered line on every page load.
  var lastHave = have[have.length - 1];
  for (var k = incoming.length - 1; k >= 0; k--) {
    if (incoming[k] !== lastHave) continue;
    var n = Math.min(have.length, k + 1);
    if (_eqRange(have, have.length - n, incoming, k + 1 - n, n)) return incoming.slice(k + 1);
  }
  // Nothing in common: the log moved further than a whole window between polls, or it rotated.
  return incoming;
}

// ── Per-line timestamps ──────────────────────────────────────────────────────────────────────
// The time is WHEN THE PANEL SAW THE LINE, and the panel only knows that for lines it watched
// arrive: a push from the console poller (accurate to one poll interval) or a line it wrote
// itself. The window /api/console returns on load is a fresh tail of the log file, which for most
// games carries no per-line time at all — those lines were written at some unknowable point
// before we looked, so their gutter stays BLANK rather than being stamped "now" and putting a
// confident wrong time on a week of history.
//
// Rendered with toLocaleTimeString, so it is the VIEWER's own clock — the same rule the rest of
// the panel follows for stored timestamps (see localizeTimes in panel.js). Two people in
// different timezones each read their own.
var _tsOn = true;
try { _tsOn = localStorage.getItem('sd.consoleTs') !== '0'; } catch (e) { /* private mode */ }

function stampLine(div, ts) {
  var d = new Date(Number(ts) * 1000);
  if (isNaN(d.getTime())) return;
  var g = document.createElement('span');
  g.className = 'console-ts';
  // 24-hour, deliberately, even where the viewer's locale is 12-hour: "7:35:57 PM" is three
  // characters wider than "19:35:57" and overflowed the gutter, and a log column that changes
  // width between noon and midnight cannot align. The tooltip keeps the viewer's own full
  // date-and-time format, so nothing is lost — only the gutter is normalised.
  g.textContent = d.toLocaleTimeString([], {hour12: false});
  g.title = d.toLocaleString();          // the full date, for a console left open overnight
  div.appendChild(g);                    // called before renderAnsi fills the line, so this is first
}

function applyTsVisible() {
  consoleEl.classList.toggle('ts-hidden', !_tsOn);
  var b = document.getElementById('console-ts-toggle');
  if (b) { b.setAttribute('aria-pressed', _tsOn ? 'true' : 'false'); b.classList.toggle('active', _tsOn); }
  updateTsNotice();
}

// An idle server's console is ALL history — a window of a log file that, for most games, records
// no per-line time. Every line is therefore unstamped, correctly, and the result is a console with
// no times on it at all and a "Times" button that appears to do nothing. Reported as exactly that:
// "I still don't see the timestamps in the console."
//
// So when nothing on screen is stamped, say why. It disappears the moment a line arrives with a
// time, which is also the clearest possible demonstration of what the column does.
function updateTsNotice() {
  var n = document.getElementById('console-ts-notice');
  if (!n) return;
  var anyStamped = !!consoleEl.querySelector('.console-line[data-ts]');
  n.hidden = anyStamped || !_tsOn;
}

window.toggleConsoleTs = function () {
  _tsOn = !_tsOn;
  try { localStorage.setItem('sd.consoleTs', _tsOn ? '1' : '0'); } catch (e) { /* private mode */ }
  applyTsVisible();
};

// LinuxGSM colours its output — [  OK  ] green, [ FAIL ] red — and the server now keeps that as
// canonical ESC[<codes>m and nothing else (see panel/core/terminal.py render_colour). So there is
// one trivial pattern to split on here, not a terminal to emulate.
//
// BUILT AS NODES, NEVER innerHTML. This text is the game's console: player names and chat land in
// it verbatim, so it is attacker-authored. textContent per run keeps that inert — the same
// property the line had when it was one textContent assignment, which is why this must not become
// a string of <span>s however much shorter that would read.
var _SGR_RE = /\x1b\[([0-9;]*)m/g;

function _ansiRun(parent, text, codes) {
  if (!text) return;
  // Digits only, from the server's own allowlist — but re-checked here so nothing that reached
  // the payload can ever become part of a class name.
  var cls = (codes || '').split(';')
    .filter(function (c) { return /^[0-9]{1,3}$/.test(c) && c !== '0'; })
    .map(function (c) { return 'ansi-' + c; });
  if (!cls.length) { parent.appendChild(document.createTextNode(text)); return; }
  var span = document.createElement('span');
  span.className = cls.join(' ');
  span.textContent = text;
  parent.appendChild(span);
}

function renderAnsi(el, line) {
  // APPENDS to el; it must never ASSIGN el.textContent. This fast path used to, and it silently
  // wiped the timestamp span that _appendConsole had just put in the gutter — so every line
  // WITHOUT colour lost its time, which is most real console output. Only the coloured lines kept
  // theirs, which made it look like a colour bug rather than what it was.
  if (line.indexOf('\x1b[') < 0) { el.appendChild(document.createTextNode(line)); return; }
  var last = 0, codes = '', m;
  _SGR_RE.lastIndex = 0;
  while ((m = _SGR_RE.exec(line)) !== null) {
    _ansiRun(el, line.slice(last, m.index), codes);
    codes = m[1];
    last = _SGR_RE.lastIndex;
  }
  _ansiRun(el, line.slice(last), codes);
}

// _newConsoleLines returns a SUFFIX of what it was given, so the matching rows are the same-length
// suffix. Keeping the overlap maths on plain text this way leaves that function — and the
// duplicate-detection it exists for — exactly as it was tested.
function _newConsoleRows(haveLines, rows) {
  var fresh = _newConsoleLines(haveLines, rows.map(function (r) { return r.line; }));
  return fresh.length ? rows.slice(rows.length - fresh.length) : [];
}

// Each row may carry its own time (LinuxGSM stamped the log). `fallbackTs` is the panel's clock
// for rows that do not — used only where the caller knows the panel WATCHED them arrive.
function _appendConsoleRows(rows, fallbackTs) {
  if (!rows.length) return;
  var frag = document.createDocumentFragment();
  rows.forEach(function (row) {
    var div = document.createElement('div');
    div.className = 'console-line';
    var ts = row.t || fallbackTs;
    if (ts) { div.dataset.ts = ts; stampLine(div, ts); }
    renderAnsi(div, row.line);
    frag.appendChild(div);
  });
  consoleEl.appendChild(frag);
  _consoleLines = _consoleLines.concat(rows.map(function (r) { return r.line; }));
  _trimConsole();
}

function _appendConsole(lines, ts) {
  if (!lines.length) return;
  var frag = document.createDocumentFragment();
  lines.forEach(function(line) {
    var div = document.createElement('div');
    div.className = 'console-line';
    if (ts) { div.dataset.ts = ts; stampLine(div, ts); }
    renderAnsi(div, line);
    frag.appendChild(div);
  });
  consoleEl.appendChild(frag);
  _consoleLines = _consoleLines.concat(lines);
  _trimConsole();
}

// Trim the DOM and the buffer INDEPENDENTLY, each against its own length. They are deliberately
// not assumed to be in step: sendCommand echoes the typed command straight into the console as a
// line that was never in the log, so a shared counter would remove the wrong number of nodes. The
// buffer is only ever consulted for its tail (overlap detection), so dropping from its front is
// always safe.
function _trimConsole() {
  if (_consoleLines.length > CONSOLE_MAX_LINES) {
    _consoleLines.splice(0, _consoleLines.length - CONSOLE_MAX_LINES);
  }
  while (consoleEl.childElementCount > CONSOLE_MAX_LINES && consoleEl.firstChild) {
    consoleEl.removeChild(consoleEl.firstChild);
  }
}

// What the panel itself pushed into this console — a long action's markers and output. The socket
// only reaches pages that are open at the time, and /api/console rebuilds the console from the
// GAME's console log, which an update never writes to. So reloading after an update used to throw
// away everything the update had said ("when you refresh the page after i did update, those
// messages went away"); the server keeps a bounded backlog and this replays it.
//
// ONCE per page load, guarded by its own flag rather than _consolePrimed: that one stays false
// while the host is unreachable, and an update's output is exactly what you want to still be able
// to read when the server it was updating is down.
var _panelBacklogShown = false;

function showPanelBacklog(panelLines) {
  if (_panelBacklogShown || !panelLines.length) return;
  _panelBacklogShown = true;
  // Appended after the game-log window rather than merged into it. These are a different stream
  // with no shared ordering, and every one of them carries a "[panel]" marker saying so — inventing
  // an interleaving would be guessing. They are also deliberately NOT added to _consoleLines: that
  // buffer exists to find the overlap between successive windows of the log file, and lines that
  // are not in the file would only ever confuse the match.
  var frag = document.createDocumentFragment();
  panelLines.forEach(function (row) {
    var div = document.createElement('div');
    div.className = 'console-line';
    // The backlog is the ONE source that carries a real time for lines you did not watch arrive:
    // the panel wrote them, so it knows exactly when. That is why an update's output still reads
    // with its timestamps after a reload, where the game log's own window cannot.
    if (row && row.t) { div.dataset.ts = row.t; stampLine(div, row.t); }
    renderAnsi(div, (row && row.line) || '');
    frag.appendChild(div);
  });
  consoleEl.appendChild(frag);
}

function refreshConsole(forceScroll, wantLines) {
  // Don't yank the user to the bottom unless they were already there (or it's the initial load).
  var stick = forceScroll || consoleAtBottom();
  fetch(MOUNT + '/api/console/' + serverId + (wantLines ? '?lines=' + wantLines : ''))
    .then(r => r.json())
    .then(data => {
      // Rows now, not strings: each carries LinuxGSM's own per-line time when the log has one.
      var rows = (data.lines || []).filter(function(r) {
        return r && typeof r.line === 'string' && r.line.trim();
      });
      var lines = rows.map(function(r) { return r.line; });
      var panelLines = (data.panel_lines || []).filter(function(r) {
        return r && typeof r.line === 'string' && r.line.trim();
      });
      // Nothing changed since last time — leave the console exactly as it is (no flicker while a
      // server sits idle).
      var sig = lines.length + ' ' + (lines[lines.length - 1] || '');
      if (sig === _consoleSig && !forceScroll) return;
      _consoleSig = sig;
      if (!_consolePrimed && lines.length) {
        // FIRST poll after page load, and it actually returned something. The page was
        // server-rendered with a short tail, and this window reaches much further back — that
        // extra history is exactly what we want on screen, and appending only "what is newer than
        // the seed" would throw it away (the first version of this did, and opened the console
        // showing three lines). The window is the tail of the same file, so it is a superset of
        // the seed: adopt it whole, once.
        //
        // `lines.length` guards the wipe: api_console answers an unreachable host with an EMPTY
        // list, and priming on that would blank the server-rendered console the moment you opened
        // the page of a server that happens to be down. Staying unprimed means the next poll that
        // does return something adopts it instead.
        _consolePrimed = true;
        _consoleLines = [];
        consoleEl.innerHTML = '';
        // The priming window is history, so it gets NO arrival time — but a row that carries
        // LinuxGSM's own stamp keeps it, which is the whole point: that one is a real time for a
        // line written long before the panel looked.
        _appendConsoleRows(rows);
      } else {
        // A poll DELTA is new output the panel just watched arrive — accurate to the poll
        // interval — so it is stamped, exactly like a socket push. Only the priming window above
        // goes unstamped, because that is history written before the panel looked.
        //
        // This is also the path that carries everything when the websocket is unavailable (a
        // proxy that won't upgrade, say). Leaving it unstamped meant that on such an install NO
        // line ever got a time, and the feature looked simply broken.
        _appendConsoleRows(_newConsoleRows(_consoleLines, rows), data.now);
      }
      showPanelBacklog(panelLines);
      updateTsNotice();
      var offEl = document.getElementById('console-ts-off');
      if (offEl) offEl.hidden = !data.log_timestamps;
      if (stick) stickConsole();
    })
    .catch(() => {});
}

// "Load older" — ask for a much bigger tail of the log and show that.
//
// It REPLACES the scrollback rather than trying to splice the deeper window in around what is
// already there. Splicing was the first attempt and it was wrong: the on-screen buffer starts with
// lines the deeper window does not contain (the server-rendered seed, the local command echo), so
// no overlap matched and every line was appended twice — 1022 duplicates in the first test of it.
// A deeper window of the same file is simply a superset of the tail, so showing it as-is is both
// correct and what the button says. The only thing this can drop is a websocket line not yet
// flushed to the log file, which the next poll brings back.
function loadMoreConsole(btn) {
  var orig = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
  fetch(MOUNT + '/api/console/' + serverId + '?lines=2000')
    .then(r => r.json())
    .then(function(data) {
      // ROWS, not strings. /api/console returns lines as [{t, line}] — _console_rows builds
      // them — and this called l.trim() on each, which is `undefined` on an object: a TypeError
      // inside the .then, swallowed by the .catch below, so the button has only ever answered
      // "Could not load more console output". Verified in a browser against the real payload:
      // `TypeError: l.trim is not a function`. refreshConsole, one screen up, has always read
      // the same payload correctly; this call site simply was not updated with the API.
      var older = (data.lines || []).filter(function (r) {
        return r && typeof r.line === 'string' && r.line.trim();
      });
      _consoleLines = [];
      consoleEl.innerHTML = '';
      _appendConsoleRows(older, null);
      _consoleSig = null;   // let the next poll re-evaluate against the new buffer
      if (window.toast) toast('Loaded ' + older.length + ' lines from the log', 'success');
    })
    .catch(function(){ if (window.toast) toast('Could not load more console output', 'danger'); })
    .finally(function(){ if (btn) { btn.disabled = false; btn.innerHTML = orig; } });  // nosemgrep
}

// Ctrl/Cmd+A inside the console selects the CONSOLE, not the whole page.
//
// The console is a plain <div>, so it is not a selection context of its own: the browser hands
// Ctrl+A to the document and you get the entire page — nav, cards, forms — when all you wanted was
// the log. Making it focusable (tabindex) means clicking into it gives it focus, and a keydown
// handler there can scope the selection to its own contents. Native selection with the mouse is
// unaffected; this only redefines "select all" while the console is the thing you are working in.
(function(){
  if (!consoleEl) return;
  consoleEl.setAttribute('tabindex', '0');
  consoleEl.addEventListener('keydown', function(e){
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'a' || e.key === 'A')) {
      e.preventDefault();
      var range = document.createRange();
      range.selectNodeContents(consoleEl);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });
})();

function clearConsole() {
  consoleEl.innerHTML = '';
  _consoleLines = [];
  _consoleSig = null;      // so the next poll repaints rather than deciding nothing changed
  _consolePrimed = false;  // and repaints with a full window, not just what arrived since
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

function bannerDoNow(btn){
  var b = document.getElementById('restart-pending-banner');
  serverAction((b && b.dataset.pendingAction) || 'restart', btn);
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

// ── The daily restart's time, and whose clock it is ──────────────────────────────────────────
// The schedule is a crontab line ON THE HOST, so it fires on the host's clock — which the panel's
// own bootstrap sets to UTC and which is almost never the operator's. "Daily 5am" was therefore a
// number with no meaning attached. The input takes the time in YOUR zone; the server converts it
// to the host's before writing the crontab and tells us both, so the hint underneath can say what
// it actually wrote.
function _viewerTz() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; }
}

// A recurring wall time moved between two IANA zones, done the way the platform already knows how:
// format an instant in the target zone rather than doing offset arithmetic, which gets DST wrong.
function _wallTimeIn(hhmm, fromTz, toTz) {
  if (!fromTz || !toTz || fromTz === toTz) return hhmm;
  var parts = /^(\d{1,2}):(\d{2})$/.exec(hhmm || '');
  if (!parts) return hhmm;
  try {
    // Find the instant that reads as hh:mm in fromTz today, by probing the offset at that wall
    // time. One correction pass is enough: the guess is at most a few hours out.
    var now = new Date();
    var guess = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(),
                                  Number(parts[1]), Number(parts[2])));
    for (var i = 0; i < 2; i++) {
      var shown = _hhmmIn(guess, fromTz);
      var want = Number(parts[1]) * 60 + Number(parts[2]);
      var got = Number(shown.split(':')[0]) * 60 + Number(shown.split(':')[1]);
      var diff = want - got;
      if (diff > 720) { diff -= 1440; } else if (diff < -720) { diff += 1440; }
      if (!diff) break;
      guess = new Date(guess.getTime() + diff * 60000);
    }
    return _hhmmIn(guess, toTz);
  } catch (e) { return hhmm; }
}

function _hhmmIn(date, tz) {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false
  }).format(date);
}

function renderDailyRestart() {
  var el = document.getElementById('dailyrestart-time');
  var hint = document.getElementById('dailyrestart-hosthint');
  if (!el) return;
  var hostTime = el.dataset.hostTime || '05:00';
  var hostTz = el.dataset.hostTz || '';
  var mine = _wallTimeIn(hostTime, hostTz, _viewerTz());
  if ('value' in el && el.tagName === 'INPUT') { el.value = mine; } else { el.textContent = mine; }
  if (!hint) return;
  // Say what is on the host, ALWAYS — including when its zone could not be read, which is a
  // different and more useful statement than showing the host's number as if it were yours.
  // Only the values are set here; the words are in the template so they can be translated.
  var tEl = document.getElementById('drh-time');
  var tzEl = document.getElementById('drh-tz');
  var onEl = document.getElementById('drh-on');
  var unkEl = document.getElementById('drh-on-unknown');
  if (tEl) tEl.textContent = hostTime;
  if (tzEl) tzEl.textContent = hostTz ? '(' + hostTz + ')' : '';
  if (onEl) onEl.hidden = !hostTz;
  if (unkEl) unkEl.hidden = !!hostTz;
  hint.hidden = false;
}

function setDailyRestartTime(el) {
  el.disabled = true;
  fetch(MOUNT + '/api/server/' + serverId + '/daily-restart', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      enabled: (document.getElementById('dailyrestart-toggle') || {}).checked || false,
      time: el.value, tz: _viewerTz()
    })
  })
  .then(r => r.json())
  .then(d => {
    if (!d.success) { if (window.toast) toast(d.message || 'Failed to set the restart time', 'danger'); return; }
    el.dataset.hostTime = d.host_time || el.dataset.hostTime;
    el.dataset.hostTz = d.host_tz || '';
    renderDailyRestart();
    if (window.toast) toast(t('Daily restart time saved'), 'success');
  })
  .catch(() => { if (window.toast) toast('Could not reach the panel', 'danger'); })
  .finally(() => { el.disabled = false; });   // nosemgrep
}

function toggleDailyRestart(el) {
  el.disabled = true;
  fetch(MOUNT + '/api/server/' + serverId + '/daily-restart', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enabled: el.checked, tz: _viewerTz() })
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

var connectAddr = '';

function copyConnect() {
  var addr = connectAddr || (document.getElementById('connect-addr') || {}).textContent || '';
  addr = addr.trim();
  if (addr && addr !== 'resolving…' && addr !== 'unknown') window.copyText(addr, 'Copied ' + addr);
}

document.addEventListener('click', function(ev){
  var el = ev.target.closest('.copy-addr'); if(!el) return;
  window.copyText(el.getAttribute('data-copy'), 'Copied ' + el.getAttribute('data-copy'));
});

function fmtGB(b) { return (b / (1024 * 1024 * 1024)).toFixed(1) + ' GB'; }

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

var _histRange = '24h';

var _histCharts = {};

var _histTimes = {};

var _histX = { ticks:{color:'#8b98a5', maxTicksLimit:6, maxRotation:0}, grid:{display:false} };

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

if(window.pollWhenVisible) pollWhenVisible(function(){ if(window._sdTab==='history') window.loadHistory(); }, 30000);

function loadGmodContent(){
  var el = document.getElementById('gmod-content-body');
  if(!el) return;
  fetch(MOUNT + '/api/server/' + serverId + '/gmod-content')
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(d.error){ el.innerHTML = '<span class="text-danger">'+_esc(d.error)+'</span>'; return; }  // nosemgrep
      // The host did not answer when asked what this server currently mounts. Every checkbox
      // would render unticked — indistinguishable from "mounts nothing" — and Apply rewrites
      // mount.cfg to exactly the ticks, so applying that card unmounts whatever it really had.
      // The route refuses such an apply as well; this is so the card never offers it.
      if(d.mounts_readable === false){
        el.innerHTML =  // nosemgrep
          '<div class="alert alert-warning py-2 px-3 mb-0 small">'
          + '<i class="bi bi-exclamation-triangle"></i> Couldn\'t read what this server currently '
          + 'mounts, so the list isn\'t shown — ticking from a blank card would unmount its '
          + 'existing content. Check the host is reachable, then reload.</div>';
        return;
      }
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

refreshConsole(true);

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

window.showDetailPanel = function(region, key, btn){
  // Same shape, same fix as dashboard.js's showPanel — see the note there.
  var reg = document.querySelector('[data-region="' + region + '"]');
  if (reg){
    var ph = document.createElement('div');
    ph.setAttribute('data-panel', key);
    reg.appendChild(ph);
  }
  btn.remove();
  saveDetailLayout(function(){ location.reload(); });
};

if (window.makeSortable) {
  makeSortable(document.getElementById('detail-console'),
               {itemSelector: '[data-panel]', axis: 'y', onDrop: saveDetailLayout});
}

initChart();

pollStats();

document.addEventListener('visibilitychange', function(){ if (!document.hidden) pollStats(); });

pollWhenVisible(function(){ refreshConsole(); }, 30000);

// Which build of the game is installed. Fetched once, after the page has drawn — the endpoint
// reads the Steam manifest over SSH and queries the running game, which is far too slow to sit on
// either the render path or the stats poll. The element is already in the DOM showing an em dash,
// so filling it in cannot shift the layout; an unreachable host simply leaves the dash.
function loadGameVersion() {
  var el = document.getElementById('game-version');
  if (!el) return;
  fetch(MOUNT + '/api/server/' + serverId + '/version', {cache: 'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (!d || !d.label) return;          // nothing known — leave the placeholder as it is
      el.textContent = d.label;
      if (d.detail) el.title = d.detail;   // where the number came from (build, appid, date)
    })
    .catch(function(){});                  // a version is a nicety; never surface it as an error
}

applyTsVisible();
renderDailyRestart();

loadGameVersion();

// An update changes the answer, so re-read it once the action that ran has finished. The panel's
// own console markers are the signal that it did — they arrive on the same socket as everything
// else, so watch for one rather than polling a build number that changes a few times a year.
// Any marker but the opening one counts, including a failure: an update that died partway has
// still changed the files on disk, and showing the pre-update build would be a lie.
socket.on('console_output', function(data) {
  if (data.server_id !== serverId || typeof data.data !== 'string') return;
  if (data.data.indexOf('[panel] ') >= 0 && data.data.indexOf(' started') < 0) {
    setTimeout(loadGameVersion, 500);
  }
});

// Turn LinuxGSM's `logtimestamp` OFF. There is deliberately no control to turn it ON.
//
// It does what it says — the log really is stamped at write time, which is the only way console
// HISTORY can carry real times — but LinuxGSM builds the capture as
// `cat | gawk '{ print strftime(...), $0 }' >> consolelog`, and gawk writing to a FILE is BLOCK
// buffered: measured at 0 lines reaching the log after 33 lines of input, everything appearing
// only once 4KB had accumulated. On a quiet server that is an apparently frozen console for
// hours. The pipeline lives in command_start.sh, so nothing out here can add an fflush.
//
// The parsing stays: a log that IS stamped (someone set it by hand) is still read correctly.
function disableLogTimestamps(btn) {
  confirmDialog({
    title: t('Stop stamping the console log'),
    body: t('LinuxGSM stamps each line by piping the console through gawk, which buffers in 4KB blocks when writing to a file \u2014 so live output stops appearing until enough has built up. Turning this off restores the live console. It takes effect the next time the server starts.'),
    confirmLabel: t('Turn it off'),
    onConfirm: function () {
      btn.disabled = true;
      fetch(MOUNT + '/api/server/' + serverId + '/log-timestamps', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ enabled: false })
      })
      .then(r => r.json())
      .then(function (d) {
        if (d.error) { toast(d.error, 'danger'); return; }
        toast(t('Stamping is off. Restart the server to restore the live console.'), 'success');
      })
      .catch(function () { toast(t('Could not reach the panel'), 'danger'); })
      .finally(function () { btn.disabled = false; });   // nosemgrep
    }
  });
}
