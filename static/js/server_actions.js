// The server control bar's behaviour, shared by the detail page and Files & Config.
// Needs SERVER_NAME, serverId and MOUNT, which each page assigns inline before loading this.
function _esc(s){ return window.escapeHtml(s); }

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

function showPendingBanner(action){
  var b = document.getElementById('restart-pending-banner');
  if (!b) return;
  b.dataset.action = action;
  var v = document.getElementById('rpb-verb'); if (v) v.textContent = action;
  var bt = document.getElementById('rpb-btn'); if (bt) bt.textContent = _cap(action) + ' now';
  b.classList.remove('d-none');
}
