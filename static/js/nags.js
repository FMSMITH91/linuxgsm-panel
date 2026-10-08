// Reboot-required and OS-update banners, and the one reboot dialog every reboot button opens.
// window.LOCAL_HOST_ID is set inline above.
//
// ── Rebooting a host: window.rebootHost ──────────────────────────────────────────────────────
// Every way to reboot a host from the page comes here — the Power card's two buttons, the banner's
// two, the palette — and nothing else POSTs a reboot. A reboot stops the host's running game
// servers cleanly first and brings them back after (panel/services/host_reboot.py), so the dialog
// first asks the panel who is on (/players) and what the reboot would do to each server
// (/reboot-plan?preview=1), then offers what fits:
//   idle     -> Reboot now / Cancel
//   players  -> Wait: reboot when everyone has left (primary) / Reboot now: disconnect them / Cancel
//   blocked  -> Wait: reboot when it's finished and everyone has left / Close (Reboot now refused)
// The buttons are a column, so the three of them fit a 375 px screen. A 409 from the POST (someone
// joined since the dialog opened) re-renders it from the answer.
function _rbEl(tag, cls, text){
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function _rbName(text){            // a host or server name: never handed to the translator
  var e = _rbEl('strong', null, text); e.setAttribute('data-no-i18n', ''); return e;
}
function _rbHost(label){           // the panel's own host is called by a phrase, translated; any other by its name
  return label === 'the panel host' ? _rbEl('strong', null, label) : _rbName(label);
}
function _rbRow(name, word){       // "<name> — <word>", the word translatable on its own
  var li = _rbEl('li');
  li.appendChild(_rbName(name));
  li.appendChild(document.createTextNode(' — '));
  li.appendChild(_rbEl('span', null, word));
  return li;
}
function _rbOpen(label){
  var ov = _rbEl('div');
  ov.className = 'rb-overlay';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:11050;display:flex;align-items:center;justify-content:center;padding:1rem;';
  var card = _rbEl('div', 'card'); card.style.cssText = 'max-width:480px;width:100%;max-height:90vh;overflow:auto;';
  card.setAttribute('role', 'dialog'); card.setAttribute('aria-modal', 'true');
  var head = _rbEl('div', 'card-header');
  head.appendChild(_rbEl('i', 'bi bi-power'));
  head.appendChild(document.createTextNode(' '));
  head.appendChild(_rbEl('span', null, 'Reboot'));
  head.appendChild(document.createTextNode(' '));
  head.appendChild(_rbHost(label));
  var body = _rbEl('div', 'card-body');
  body.appendChild(_rbEl('p', 'text-secondary mb-0', 'Checking who is on this host…'));
  card.appendChild(head); card.appendChild(body); ov.appendChild(card);
  document.body.appendChild(ov);
  function close(){ ov.remove(); document.removeEventListener('keydown', onKey); }
  function onKey(e){ if (e.key === 'Escape') close(); }
  document.addEventListener('keydown', onKey);
  ov.addEventListener('click', function(e){ if (e.target === ov) close(); });
  return {ov: ov, body: body, close: close};
}
function _rbButton(text, cls, onClick){
  // text-wrap: panel.css keeps .btn on one line, and these labels are long — in French the Wait
  // button is 434 px of text in a 309 px column at 375 px. Wrapped, every state fits a phone.
  var b = _rbEl('button', 'btn text-wrap ' + cls, text); b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}
function _rbPlayersList(players){
  var ul = _rbEl('ul', 'small mb-2 ps-3');
  ((players && players.busy) || []).forEach(function(b){
    var li = _rbEl('li'); li.appendChild(_rbName(b.name)); li.appendChild(document.createTextNode(' — '));
    var n = _rbEl('span', null, String(Number(b.players) || 0)); n.setAttribute('data-no-i18n', '');
    li.appendChild(n); li.appendChild(document.createTextNode(' '));
    li.appendChild(_rbEl('span', null, Number(b.players) === 1 ? 'player' : 'players'));
    ul.appendChild(li);
  });
  ((players && players.unknown) || []).forEach(function(u){
    ul.appendChild(_rbRow(u.name, u.reason === 'probe_failed' ? 'its state could not be read'
                                                              : 'its player count can’t be read'));
  });
  return ul;
}
function _rbPlanList(plan){
  var ul = _rbEl('ul', 'small mb-2 ps-3');
  ((plan && plan.servers) || []).forEach(function(sv){
    if (sv.text) ul.appendChild(_rbRow(sv.name, sv.text));
  });
  return ul.children.length ? ul : null;
}
function _rbBlockersList(players){
  var ul = _rbEl('ul', 'small mb-2 ps-3');
  ((players && players.blockers) || []).forEach(function(b){
    ul.appendChild(_rbRow(b.name, {install: 'an install is running', backup: 'a backup is running',
      action: 'a LinuxGSM action is running', content: 'a content install is running',
      maintenance: 'LinuxGSM maintenance is running', bootstrap: 'a bootstrap is running',
      dpkg: 'a package install is running', apt: 'a package install is running',
      self_update: 'a panel update is running', restore: 'a restore is running',
      full_backup: 'a full backup is running'}[b.kind] || 'work is running'));
  });
  return ul;
}
function _rbState(players){
  if (!players) return 'unknown';
  return players.state || ((players.busy && players.busy.length) ? 'busy'
                          : (players.unknown && players.unknown.length) ? 'unknown' : 'idle');
}
// One renderer per state: each fills `body` and `actions` and returns nothing.
function _rbUnreachable(ctx){
  ctx.body.appendChild(_rbEl('p', 'mb-0', 'This host is not answering, so it cannot be rebooted from here.'));
  ctx.actions.appendChild(_rbButton('Close', 'btn-outline-secondary', ctx.dlg.close));
}
function _rbBlocked(ctx){
  ctx.body.appendChild(_rbEl('p', 'mb-2', 'Not now: work is running on this host, and a reboot would cut it off.'));
  ctx.body.appendChild(_rbBlockersList(ctx.players));
  ctx.actions.appendChild(_rbButton('Wait: reboot when it’s finished and everyone has left', 'btn-primary', function(){ ctx.post('when_empty'); }));
  ctx.actions.appendChild(_rbButton('Close', 'btn-outline-secondary', ctx.dlg.close));
}
function _rbChoiceButtons(ctx){
  var nowFirst = (ctx.host.opts || {}).prefer === 'now';
  var wait = _rbButton('Wait: reboot when everyone has left', nowFirst ? 'btn-outline-primary' : 'btn-primary', function(){ ctx.post('when_empty'); });
  var now = _rbButton('Reboot now: disconnect them', nowFirst ? 'btn-danger' : 'btn-outline-danger', function(){ ctx.post('now'); });
  ctx.actions.appendChild(nowFirst ? now : wait);
  ctx.actions.appendChild(nowFirst ? wait : now);
  ctx.actions.appendChild(_rbButton('Cancel', 'btn-outline-secondary', ctx.dlg.close));
}
function _rbPlayers(ctx){
  var known = !!ctx.players;
  ctx.body.appendChild(_rbEl('p', 'mb-2 fw-semibold', known ? 'Players are online on this host.' : 'The panel could not check who is on this host.'));
  if (known) ctx.body.appendChild(_rbPlayersList(ctx.players));
  ctx.body.appendChild(_rbEl('p', 'small text-secondary mb-1', 'Waiting reboots it once nobody is on any of its game servers. A server whose count can’t be read holds the wait until it is stopped.'));
  _rbWaitLimit(ctx);
  ctx.body.appendChild(_rbEl('p', 'small text-secondary mb-0', 'Rebooting now warns players in-game first, where the game can show a message, then stops each server cleanly.'));
  _rbChoiceButtons(ctx);
}
function _rbWaitLimit(ctx){         // the limit as Settings has it; nothing when it is not known
  var hours = ctx.plan && ctx.plan.wait_hours;
  if (hours == null) return;
  ctx.body.appendChild(hours > 0
    ? _rbLine(['The wait gives up after', _rbValue(Number(hours) + ' h')])
    : _rbLine(['The wait has no time limit.']));
}
function _rbIdle(ctx){
  ctx.body.appendChild(_rbEl('p', 'mb-2', ctx.host.isLocal
    ? 'Reboot the panel host now? The panel goes down with it for a few minutes.'
    : 'Reboot this host now?'));
  // What comes back is the plan list's to say (After the reboot: …): a setting can keep a server
  // without Autostart stopped, so a blanket 'they come back' would be false there.
  ctx.body.appendChild(_rbEl('p', 'small mb-2', 'Running game servers are stopped cleanly first.'));
  ctx.actions.appendChild(_rbButton('Reboot now', 'btn-warning', function(){ ctx.post('now'); }));
  ctx.actions.appendChild(_rbButton('Cancel', 'btn-outline-secondary', ctx.dlg.close));
}
var _RB_VIEWS = {unreachable: _rbUnreachable, blocked: _rbBlocked, busy: _rbPlayers,
                 unknown: _rbPlayers, idle: _rbIdle};
function _rbPlanNotes(ctx, plan){
  var pl = _rbPlanList(plan);
  if (pl && ctx.state !== 'unreachable') {
    ctx.body.appendChild(_rbEl('div', 'small text-secondary mb-1', 'After the reboot:'));
    ctx.body.appendChild(pl);
  }
  if (plan && plan.warning) ctx.body.appendChild(_rbEl('div', 'alert alert-warning small py-1 px-2 mb-0', plan.warning));
}
function _rbRender(dlg, host, players, plan){
  var ctx = {dlg: dlg, host: host, players: players, plan: plan, state: _rbState(players),
             body: dlg.body, actions: _rbEl('div', 'd-grid gap-2 mt-3'),
             post: function(mode){ _rbPost(dlg, host, mode); }};
  ctx.body.textContent = '';
  (_RB_VIEWS[players ? ctx.state : 'unknown'] || _rbPlayers)(ctx);
  _rbPlanNotes(ctx, plan);
  ctx.body.appendChild(ctx.actions);
  var first = ctx.actions.querySelector('button'); if (first) first.focus();
}
function _rbFailed(dlg, d){
  dlg.body.querySelectorAll('button').forEach(function(b){ b.disabled = false; });
  var err = dlg.body.querySelector('.rb-error') || dlg.body.insertBefore(_rbEl('div', 'rb-error alert alert-danger small py-1 px-2'), dlg.body.firstChild);
  err.textContent = d.message || 'The reboot request failed.';
}
function _rbDone(dlg, host, d){
  dlg.close();
  if (window.toast) toast(d.warning ? d.message + ' ' + d.warning : (d.message || 'Reboot requested'), d.warning ? 'warning' : 'info');
  window.rebootStateRefresh(host.id);
}
function _rbAnswer(dlg, host, res){
  var d = res.d || {};
  if (res.code === 409 && d.needs_choice) { _rbRender(dlg, host, d.players || null, null); return; }
  if (res.code >= 400) { _rbFailed(dlg, d); return; }
  _rbDone(dlg, host, d);
}
function _rbPost(dlg, host, mode){
  dlg.body.querySelectorAll('button').forEach(function(b){ b.disabled = true; });
  fetch(MOUNT+'/api/remote/'+host.id+'/reboot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode})})  // nosemgrep
    .then(function(r){ return r.json().then(function(d){ return {code: r.status, d: d}; }); })
    .then(function(res){ _rbAnswer(dlg, host, res); })
    .catch(function(){
      dlg.close();
      if (window.toast) toast('The reboot request failed.', 'danger');
    });
}
window.rebootHost = function(hostId, label, isLocal, opts){
  var host = {id: hostId, label: label, isLocal: !!isLocal, opts: opts || {}};
  var dlg = _rbOpen(label);
  var get = function(path){ return fetch(MOUNT+'/api/remote/'+hostId+path,{cache:'no-store'}).then(function(r){ return r.ok ? r.json() : null; }).catch(function(){ return null; }); };
  Promise.all([get('/players'), get('/reboot-plan?preview=1')]).then(function(res){
    _rbRender(dlg, host, res[0], res[1]);
  }).catch(function(){ _rbRender(dlg, host, null, null); });
};

// ── What a host's reboot is doing: the Power card's #power-state and the banner ─────────────
// One poll per host while a wait, a job or a restore is in progress (every 10 s); none otherwise.
// On the panel's own host the page goes down with it: when the poll answers again after that, the
// page reloads.
var _rbPolls = {};
function _rbClock(epoch){
  // The date too when it is not today: a 24 h wait gives up at the same clock time it was asked.
  // In the PAGE's language: the browser's own locale put English day names on a Spanish page.
  try {
    var d = new Date(epoch * 1000), opts = {hour: '2-digit', minute: '2-digit'};
    var lang = (document.documentElement && document.documentElement.lang) || [];
    if (d.toDateString() !== new Date().toDateString()) { opts.weekday = 'short'; opts.day = 'numeric'; opts.month = 'short'; }
    return d.toLocaleString(lang, opts);
  } catch (e) { return ''; }
}
function _rbLine(parts){
  var p = _rbEl('div', 'mb-1');
  parts.forEach(function(x){
    if (x == null) return;
    if (typeof x === 'string') p.appendChild(_rbEl('span', null, x));
    else p.appendChild(x);
    p.appendChild(document.createTextNode(' '));
  });
  return p;
}
function _rbValue(text){ var e = _rbEl('span', 'fw-semibold', text); e.setAttribute('data-no-i18n', ''); return e; }
var _RB_PHASE = {preflight: 'Getting ready to reboot…', warning: 'Warning players in-game…',
  stopping: 'Stopping game servers…', arming: 'Waiting for a quiet moment in LinuxGSM’s schedule…',
  rebooting: 'Rebooting; waiting for the host to come back…'};
function _rbWaitState(box, host, w){
  box.appendChild(_rbLine(['Waiting to reboot until everyone has left.']));
  box.appendChild(_rbLine(['Asked at', _rbValue(_rbClock(w.since))]));
  if (w.by) box.appendChild(_rbLine(['Asked by', _rbValue(w.by)]));
  var on = w.waiting_on || {}, busy = on.busy || [], unknown = on.unknown || [];
  if (busy.length + unknown.length) {
    box.appendChild(_rbLine(['Waiting on:']));
    box.appendChild(_rbPlayersList({busy: busy, unknown: unknown}));
  }
  if (w.expires) box.appendChild(_rbLine(['Gives up at', _rbValue(_rbClock(w.expires))]));
  var row = _rbEl('div', 'd-flex gap-2 flex-wrap mt-1');
  row.appendChild(_rbButton('Reboot now instead', 'btn-sm btn-outline-warning', function(){ window.rebootHost(host.id, host.label, host.isLocal, {prefer: 'now'}); }));
  row.appendChild(_rbButton('Cancel', 'btn-sm btn-outline-secondary', function(){ window.rebootCancel(host.id); }));
  box.appendChild(row);
}
function _rbJobNumbers(job){       // the phase's numbers only (2/4, 30 s): the words are the phase's
  if (job.total) return _rbValue((Number(job.done) || 0) + '/' + Number(job.total));
  if (job.left != null) return _rbValue(Number(job.left) + ' s');
  return null;
}
function _rbJobState(box, host, job){
  box.appendChild(_rbLine([_RB_PHASE[job.phase] || 'Rebooting…', _rbJobNumbers(job)]));
  if (!job.sent) {
    box.appendChild(_rbButton('Cancel the reboot', 'btn-sm btn-outline-secondary mt-1', function(){ window.rebootCancel(host.id); }));
  }
}
function _rbRowsState(box, rows){
  var back = rows.filter(function(r){ return r.restore !== 'pending'; }).length;
  box.appendChild(_rbLine(['Coming back:', _rbValue(back + '/' + rows.length)]));
}
function _rbLastState(box, last){
  if (!last || !last.text) return;
  var el = _rbEl('div', last.ok ? 'text-success' : 'text-warning', last.text);
  el.setAttribute('data-no-i18n', '');
  box.appendChild(el);
}
// Fills the Power card's #power-state; true while something is under way (and worth polling).
function _rbRenderState(box, hostId, label, isLocal, st){
  var host = {id: hostId, label: label, isLocal: isLocal}, rows = st.rows || [];
  box.textContent = '';
  if (st.wait) _rbWaitState(box, host, st.wait);
  if (st.job) _rbJobState(box, host, st.job);
  else if (rows.length) _rbRowsState(box, rows);
  var active = !!(st.wait || st.job || rows.length);
  if (!active) _rbLastState(box, st.last);
  return active;
}
window.rebootStateRefresh = function(hostId){
  var p = _rbPolls[hostId]; if (p) p.tick();
  if (window.rebootNagCheck && (hostId === window.LOCAL_HOST_ID || window.REMOTE_ID === hostId)) {
    window.rebootNagCheck(hostId, hostId === window.LOCAL_HOST_ID ? 'the panel host' : (window.REMOTE_NAME || ''));
  }
};
window.rebootStateWatch = function(hostId, label, isLocal){
  var box = document.getElementById('power-state'); if (!box || hostId == null) return;
  var timer = null, wentDown = false;
  function tick(){
    fetch(MOUNT+'/api/remote/'+hostId+'/reboot-plan',{cache:'no-store'})  // nosemgrep
      .then(function(r){ if (!r.ok) throw new Error('status'); return r.json(); })
      .then(function(st){
        if (wentDown && isLocal) { window.location.reload(); return; }
        var active = _rbRenderState(box, hostId, label, isLocal, st);
        if (st.job && st.job.phase === 'rebooting') wentDown = false;
        schedule(active ? 10000 : 0);
      })
      // A failed read polls again for every host: one blip (a phone's network, a 502 while the panel
      // restarts) used to stop a remote's card for good, still "Waiting to reboot…" after the host was
      // back. Only the panel's own host takes a failure as it going down, and reloads once it answers.
      .catch(function(){ if (isLocal) wentDown = true; schedule(10000); });
  }
  function schedule(ms){
    if (timer) { clearTimeout(timer); timer = null; }
    if (ms) timer = setTimeout(function(){ if (document.hidden) schedule(ms); else tick(); }, ms);
  }
  _rbPolls[hostId] = {tick: tick};
  tick();
};
window.rebootCancel = function(hostId){
  fetch(MOUNT+'/api/remote/'+hostId+'/reboot-cancel',{method:'POST'})  // nosemgrep
    .then(function(r){ return r.json(); })
    .then(function(d){ if (window.toast) toast(d.message || 'Canceled', d.success ? 'info' : 'warning'); window.rebootStateRefresh(hostId); })
    .catch(function(){ if (window.toast) toast('Request failed', 'danger'); });
};

// ── "This host needs a reboot" banners ────────────────────────────────────────────
// After an OS update that needs a reboot, Debian/Ubuntu drop /var/run/reboot-required. The banner
// offers the same two choices as the Power card. It also STAYS while a wait or a reboot is under
// way, whether or not a reboot is required: a "reboot when empty" armed on a host that needed none
// was otherwise invisible after its toast, and its Cancel unreachable.
// Generic over a host id — base.html uses it for the panel host; remote_manage for a remote.
window.rebootNagRender = function(el, hostId, label, d){
  var isLocal = hostId === window.LOCAL_HOST_ID;
  el.className = 'alert alert-warning d-flex flex-wrap align-items-center gap-2';
  el.setAttribute('role','alert');
  el.textContent = '';
  el.appendChild(_rbEl('i', 'bi bi-arrow-clockwise fs-5'));
  var text = _rbEl('div', 'flex-grow-1'); text.style.minWidth = '220px';
  var acts = _rbEl('div', 'd-flex gap-2 flex-wrap');
  if (d.job) {
    text.appendChild(_rbEl('span', null, _RB_PHASE[d.job.phase] || 'Rebooting…'));
    text.appendChild(document.createTextNode(' ')); text.appendChild(_rbHost(label));
    if (!d.job.sent) acts.appendChild(_rbButton('Cancel', 'btn-sm btn-outline-secondary', function(){ window.rebootCancel(hostId); }));
  } else if (d.pending_empty) {
    text.appendChild(_rbEl('span', null, 'Auto-reboot scheduled once empty'));
    text.appendChild(document.createTextNode(' — ')); text.appendChild(_rbHost(label));
    acts.appendChild(_rbButton('Reboot now instead', 'btn-sm btn-outline-warning', function(){ window.rebootHost(hostId, label, isLocal, {prefer: 'now'}); }));
    acts.appendChild(_rbButton('Cancel', 'btn-sm btn-outline-secondary', function(){ window.rebootCancel(hostId); }));
  } else {
    text.appendChild(_rbEl('strong', null, 'Reboot needed'));
    text.appendChild(document.createTextNode(' — ')); text.appendChild(_rbHost(label));
    text.appendChild(document.createTextNode(' '));
    text.appendChild(_rbEl('span', null, 'needs to reboot to finish applying system updates.'));
    if (d.packages && d.packages.length) {
      var pk = _rbEl('span', 'text-secondary', ' (' + d.packages.slice(0,6).join(', ') + (d.packages.length>6?', …':'') + ')');
      pk.style.fontSize = '.8rem'; pk.setAttribute('data-no-i18n', '');
      text.appendChild(pk);
    }
    acts.appendChild(_rbButton('Reboot now', 'btn-sm btn-danger', function(){ window.rebootHost(hostId, label, isLocal, {prefer: 'now'}); }));
    acts.appendChild(_rbButton('Reboot when empty', 'btn-sm btn-outline-primary', function(){ window.rebootHost(hostId, label, isLocal, {prefer: 'when_empty'}); }));
  }
  el.appendChild(text); el.appendChild(acts);
};
window.rebootNagCheck = function(hostId, label){
  var box = document.getElementById('reboot-nag'); if(!box || hostId==null) return;
  fetch(MOUNT+'/api/remote/'+hostId+'/reboot-required',{cache:'no-store'})  // nosemgrep
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      var el = document.getElementById('reboot-nag-'+hostId);
      if(!d || !(d.required || d.pending_empty || d.job)){ if(el) el.remove(); return; }
      if(!el){ el = document.createElement('div'); el.id = 'reboot-nag-'+hostId; el.className='mb-2'; box.appendChild(el); }
      window.rebootNagRender(el, hostId, label, d);
    }).catch(function(){});
};
(function(){
  if (window.LOCAL_HOST_ID == null) return;   // only for users who can manage/reboot the host
  function chk(){ window.rebootNagCheck(window.LOCAL_HOST_ID, 'the panel host'); }
  chk();
  if (window.pollWhenVisible) window.pollWhenVisible(chk, 10*60*1000);
})();

// ── "Updates are waiting" banner ──────────────────────────────────────────────────────
// The panel checks every host's OS packages daily and chats you about it; this is the same fact on
// the page, so you see it when you log in rather than only if a chat message survived being
// scrolled past. Served from the panel's memory (/api/os-updates/summary) — it never probes a host,
// so it costs a page load nothing.
//
// Dismissal is per BROWSER SESSION and keyed on what is waiting: close it and it stays closed while
// you work, comes back at your next login, and comes back immediately if a host's list changes
// (a security update landing is not something a dismissal from an hour ago should hide).
function _osNagClear(box){ box.className = ''; box.innerHTML = ''; }   // className too: a stray
//                        mb-2 on an emptied container leaves 8px of blank space where the banner was
window.osUpdatesNagDismiss = function(sig){
  try { sessionStorage.setItem('osUpdatesNagOff', sig); } catch(e){}
  var box = document.getElementById('os-updates-nag'); if(box) _osNagClear(box);
};
window.osUpdatesNagCheck = function(){
  var box = document.getElementById('os-updates-nag'); if(!box) return;
  fetch(MOUNT+'/api/os-updates/summary',{cache:'no-store'})
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      var hosts = (d && d.hosts) || [];
      if(!hosts.length){ _osNagClear(box); return; }
      var sig = hosts.map(function(h){ return h.id+':'+h.count+':'+h.security; }).join('|');
      var off = null; try { off = sessionStorage.getItem('osUpdatesNagOff'); } catch(e){}
      if(off === sig){ _osNagClear(box); return; }
      var sec = hosts.reduce(function(a,h){ return a + (Number(h.security)||0); }, 0);
      // One line per host, so a narrow screen breaks between hosts rather than mid-sentence.
      var rows = hosts.map(function(h){
        // The two counts go into markup unescaped, so they are made numbers HERE. The API sends
        // ints (len() and sum() in _os_update_note), but that was the only thing keeping a string
        // out of this innerHTML; Number() makes the banner's safety this line's, not the server's.
        var n = Number(h.count) || 0, s = Number(h.security) || 0;
        // inline-block + padding: a bare inline link is only as tall as its text (16px), which is
        // an unfair target on a phone. This lifts each one to a 24px row without padding the banner.
        return '<div><a class="alert-link" style="display:inline-block;padding:.25rem 0;"'
             + ' href="' + escapeHtml(h.url) + '#os-updates">'
             + escapeHtml(h.name) + '</a> — ' + n + ' update' + (n===1?'':'s')
             + (s ? ' <span class="badge bg-danger" style="font-weight:normal;">'
                  + s + ' security</span>' : '') + '</div>';
      }).join('');
      // alert-dismissible parks the close button in the corner and reserves room for it; laying it
      // out in the flow instead drops it onto a line of its own at 375px.
      box.className = 'mb-2';
      box.innerHTML = '<div class="alert ' + (sec ? 'alert-warning' : 'alert-info')   // nosemgrep
        + ' alert-dismissible mb-0" role="alert">'
        + '<div class="mb-1"><i class="bi bi-box-arrow-down"></i> <strong>System updates waiting</strong></div>'
        + '<div style="font-size:.9rem;">' + rows + '</div>'
        + '<button type="button" class="btn-close" aria-label="Dismiss updates notice"'
        + _da('osUpdatesNagDismiss', [sig]) + '></button></div>';
    }).catch(function(){});
};
(function(){
  if (window.LOCAL_HOST_ID == null) return;   // same audience as the reboot banner: hosts you manage
  window.osUpdatesNagCheck();
  // Hourly: the underlying check is daily, and the panel's own page actions (a forced check, an
  // install) call osUpdatesNagCheck() directly rather than waiting for this.
  if (window.pollWhenVisible) window.pollWhenVisible(window.osUpdatesNagCheck, 60*60*1000);
})();
