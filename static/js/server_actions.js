// The server control bar's behaviour, shared by the detail page and Files & Config.
// Needs SERVER_NAME, serverId and MOUNT, which each page assigns inline before loading this.
function _esc(s){ return window.escapeHtml(s); }

// Maintenance/info actions (details, postdetails, monitor, …) return text you want to READ —
// show it in a dismissible panel, not a toast that disappears before you see it.
function _reportActionResult(action, d, showOutput) {
  if (showOutput) showActionOutput(action, d.message || (d.success ? 'Done — no output' : 'Failed'), d.success);
  else toast(d.message || tf('{action} done', {action: action}), d.success ? 'success' : 'danger');
}

// A start, stop or restart that went through supersedes one queued for "when empty".
function _hidePendingBannerAfter(action, d) {
  if (d.success && (action === 'restart' || action === 'start' || action === 'stop')) {
    var b = document.getElementById('restart-pending-banner');
    if (b) b.classList.add('d-none');
  }
}

function _doServerAction(action, btn, showOutput) {
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
  fetch(MOUNT + '/api/server/' + serverId + '/action', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ action: action })
  })
  .then(r => r.json())
  .then(function (d) {
    _reportActionResult(action, d, showOutput);
    _hidePendingBannerAfter(action, d);
    // pollStats lives in server_detail.js. This file is ALSO loaded by Files & Config, which does
    // not load that script — and `setTimeout(pollStats, …)` evaluates the identifier immediately,
    // so on that page it threw ReferenceError before any timer was set. The throw landed in the
    // trailing .catch and was reported as "Action failed — connection error", right after the
    // success toast: two contradictory toasts for one restart that had actually worked.
    if (typeof pollStats === 'function') setTimeout(pollStats, 1200);
  }, function () {
    // Upstream only — the request did not land, or the response was not JSON. Handing this as
    // .then's SECOND argument rather than a trailing .catch is the point: a trailing one also
    // catches whatever the success handler throws, which is how a missing function turned into a
    // connection error the operator had no way to diagnose.
    toast('Action failed — connection error', 'danger');
  })
  .catch(function (err) {
    // A bug in the success handler above. Never reported as a failed action: the request already
    // succeeded, and telling someone their restart failed invites them to run it a second time.
    if (window.console && console.error) console.error('server action: handler error', err);
  })
  .finally(() => { btn.disabled = false; btn.innerHTML = orig; })  // nosemgrep
  .catch(() => { /* failure already reported above; this only stops a throwing cleanup going unhandled */ });
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
  if (action === 'restart' || action === 'stop') { actionWithPlayerCheck(action, btn); return; }
  if (confirmFirst) {
    // Translated whole, the server's name put in after (tfHtml): spliced around the bold name, the
    // question was pieces no catalog key matched.
    var srv = {html: '<strong data-no-i18n>' + _esc(SERVER_NAME) + '</strong>'};
    var body = tfHtml('{action} {name}?', {action: t(_cap(action)), name: srv});
    if (action === 'fastdl') {
      body = tfHtml('Generate FastDL files for {name}? This overwrites the existing FastDL directory and can take a while.', {name: srv});
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
    // The whole title, translated: "Restart server" was a catalog key, "Stop server" was not.
    title: t(action === 'stop' ? 'Stop server' : 'Restart server'),
    icon: action === 'stop' ? 'stop-fill' : 'arrow-clockwise',
    // data-no-i18n: the name is the server's own; one called "Backup" read "Copia de seguridad".
    // One template, as serverAction's: verb + bold name + "?" was three pieces, so Spanish lost its
    // opening "¿" and French its space before "?".
    body: tfHtml('{action} {name}?', {action: t(_cap(action)),
                                      name: {html: '<strong data-no-i18n>' + _esc(SERVER_NAME) + '</strong>'}})
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
    // null is "could not read", not "nobody is on" — the route returns it for a failed query and
    // for a game that cannot be queried at all. Folded into 0 it produced a plain confirm, and a
    // restart that disconnected players the panel had just failed to count. The fetch-failed
    // branch below already says this; the unreadable-answer branch did not.
    var n = (d && typeof d.players === 'number') ? d.players : null;
    if (n === null) { confirmActionDialog(action, btn, "(couldn't check who's online)"); return; }
    if (!n) { confirmActionDialog(action, btn); return; }
    actionPlayersDialog(action, n, btn);
  }).catch(function(){
    btn.disabled = false; btn.innerHTML = orig;  // nosemgrep
    confirmActionDialog(action, btn, "(couldn't check who's online)");
  });
}

// One element with its class and text — textContent, so nothing here is markup.
function _r12c_el(tag, cls, text){
  var el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text != null) el.textContent = text;
  return el;
}

// Built node by node, every fixed piece a WHOLE sentence chosen per action and per count. It was
// one innerHTML string with the count and the server name spliced into the prose, so the page's
// translator met text nodes like " players are connected to " that no catalog key could match:
// a Spanish or French viewer got the whole dialog in English except "Cancel". The count and the
// server's name sit in their own data-no-i18n elements; t() translates each sentence as it is
// built (the walker would too, but this way the dialog is right on its first frame).
function actionPlayersDialog(action, n, btn) {
  var stop = action === 'stop';
  var endpoint = stop ? 'stop-when-empty' : 'restart-when-empty';
  var one = n === 1;
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1080;display:flex;align-items:center;justify-content:center;padding:1rem;';
  var card = _r12c_el('div', 'card');
  card.style.cssText = 'max-width:540px;width:100%;';
  var head = _r12c_el('div', 'card-header');
  head.appendChild(_r12c_el('i', 'bi bi-people-fill'));
  head.appendChild(document.createTextNode(' '));
  head.appendChild(_r12c_el('span', null, t('Players are online')));
  card.appendChild(head);
  var body = _r12c_el('div', 'card-body');
  var who = _r12c_el('p', 'mb-2');
  // One whole sentence with the count and the name as values: split around them ("players are
  // connected to"), the translator had a fragment with nothing to place, and a language that puts
  // the count or the name anywhere else could not be written.
  var lead = _r12c_el('span');
  lead.innerHTML = tfHtml(one ? '{n} player is connected to {name}.' : '{n} players are connected to {name}.',
    {n: {html: '<strong data-no-i18n>' + _esc(String(n)) + '</strong>'},
     name: {html: '<strong data-no-i18n>' + _esc(SERVER_NAME) + '</strong>'}});  // nosemgrep - every value escaped
  who.appendChild(lead);
  who.appendChild(document.createTextNode(' '));
  who.appendChild(_r12c_el('span', null, t(stop ? (one ? 'Stopping now disconnects them.' : 'Stopping now disconnects everyone.')
                                                 : (one ? 'Restarting now disconnects them.' : 'Restarting now disconnects everyone.'))));
  body.appendChild(who);
  body.appendChild(_r12c_el('p', 'small text-secondary mb-3',
                            t(stop ? 'Are you sure you want to stop with players on?'
                                   : 'Are you sure you want to restart with players on?')));
  var btns = _r12c_el('div', 'd-flex flex-column gap-2');
  function button(id, cls, icon, label){
    var b = _r12c_el('button', cls);
    b.id = id;
    if (icon) { b.appendChild(_r12c_el('i', 'bi bi-' + icon)); b.appendChild(document.createTextNode(' ')); }
    b.appendChild(_r12c_el('span', null, label));
    btns.appendChild(b);
    return b;
  }
  var now = button('rd-now', 'btn btn-warning', stop ? 'stop-fill' : 'arrow-clockwise',
                   t(stop ? 'Yes, stop now and disconnect them' : 'Yes, restart now and disconnect them'));
  var wait = button('rd-wait', 'btn btn-success', 'hourglass-split',
                    t(stop ? 'No — stop when the server is empty' : 'No — restart when the server is empty'));
  var cancel = button('rd-cancel', 'btn btn-outline-secondary', null, t('Cancel'));
  body.appendChild(btns);
  card.appendChild(body);
  ov.appendChild(card);
  document.body.appendChild(ov);
  function close(){ ov.remove(); }
  now.onclick = function(){ close(); _doServerAction(action, btn); };
  wait.onclick = function(){
    close();
    fetch(MOUNT + '/api/server/' + serverId + '/' + endpoint, {method:'POST', headers:{'Content-Type':'application/json'}})
      .then(r => r.json()).then(function(d){
        toast(d.message || t(stop ? 'Queued — will stop once empty.' : 'Queued — will restart once empty.'),
              d.success ? 'success' : 'danger');
        if (d.success) { showPendingBanner(action); }
      }).catch(function(){ toast(t(stop ? 'Could not queue the stop' : 'Could not queue the restart'), 'danger'); });
  };
  cancel.onclick = close;
  ov.addEventListener('click', function(e){ if (e.target === ov) close(); });
}

function showPendingBanner(action){
  var b = document.getElementById('restart-pending-banner');
  if (!b) return;
  b.dataset.pendingAction = action;   // see the note on the banner in server_detail.html
  // A whole sentence, not the bare verb: #rpb-verb is one complete clause in the banner so that
  // both halves of it can be translated (see the note on the banner in server_detail.html).
  var v = document.getElementById('rpb-verb');
  if (v) v.textContent = t(action === 'stop' ? 'A stop is queued.' : 'A restart is queued.');
  // The phrase, not a word spliced into one: "Stop now" and "Restart now" are catalog keys, and
  // the banner's template renders each as its own element for exactly that reason. t() here so
  // the button is right immediately instead of waiting for the walker.
  var bt = document.getElementById('rpb-btn');
  if (bt) bt.textContent = t(action === 'stop' ? 'Stop now' : 'Restart now');
  // "Do it now" calls the action endpoint, so it is offered only for an action this viewer may
  // run. The template renders it for either permission and says which on data-can-*; deciding
  // here, per action, is what keeps it right after a switch the page was not rendered for.
  var can = (action === 'stop' ? b.dataset.canStop : b.dataset.canRestart) === '1';
  var doNow = document.getElementById('rpb-do');
  if (doNow) doNow.classList.toggle('d-none', !can);
  var nowCopy = document.getElementById('rpb-now');
  if (nowCopy) nowCopy.classList.toggle('d-none', !can);
  var autoCopy = document.getElementById('rpb-auto');
  if (autoCopy) autoCopy.classList.toggle('d-none', can);
  b.classList.remove('d-none');
}
