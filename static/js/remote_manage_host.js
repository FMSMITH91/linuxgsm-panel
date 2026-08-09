// SSH/connection, specs, panel-host controls, diagnostics, DB, auto-updates
// Split out of one 86KB file; these load in order and behave as one script.
// ── SSH / connection ──
function retrustHostKey(){
  confirmDialog({title:'Clear pinned host key', icon:'key', confirmClass:'btn-warning', confirmLabel:'Clear host key',
    bodyText:'Clear the pinned SSH host key for this server?\n\nOnly do this if YOU reinstalled or rebuilt the server. The next connection will trust and pin whatever host key the server presents.',
    onConfirm:function(){
      var m=document.getElementById('hostkey-msg'); m.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Clearing…</span>';
      fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/retrust-hostkey',{method:'POST'}).then(r=>r.json())
        .then(d=>{ m.innerHTML='<span class="text-'+(d.success?'success':'danger')+'">'+(d.message||(d.success?'Done — the next connection re-pins the key':'Failed'))+'</span>'; })  // nosemgrep
        .catch(()=>{ m.innerHTML='<span class="text-danger">Request failed.</span>'; });
    }});
}
var SSH_LABELS={allow:'open (allow)',limit:'rate-limited (limit)',off:'disabled — tailnet only'};
function loadSshStatus(){
  var el=document.getElementById('ssh-mode'); if(!el) return;
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/ssh-status').then(r=>r.json())
    .then(d=>{
      el.textContent = d.error?'unknown':(SSH_LABELS[d.mode]||d.mode||'unknown');
      // Reflect the CURRENT public-SSH mode on the buttons: the active mode's button is
      // marked active + disabled (you're already in that state — clicking it is a no-op).
      // Other buttons become clickable again, EXCEPT the "off" button when it's disabled
      // by the lock-out guard (data-lockdown), which must stay disabled.
      document.querySelectorAll('[data-ssh-btn]').forEach(function(b){
        var isCur = !d.error && b.getAttribute('data-ssh-btn') === d.mode;
        b.classList.toggle('active', isCur);
        if (isCur) { b.disabled = true; b.setAttribute('aria-current', 'true'); }
        else if (!b.hasAttribute('data-lockdown')) { b.disabled = false; b.removeAttribute('aria-current'); }
      });
      // "Close public panel port" is a no-op once the port is already closed — disable it.
      var cp = document.getElementById('close-panel-btn');
      if (cp && !cp.hasAttribute('data-hard-disabled')) {
        if (d.panel_port_open === false) {
          cp.disabled = true;
          cp.title = 'The public panel port is already closed — the panel is tailnet-only.';
        } else if (d.panel_port_open === true) {
          cp.disabled = false;
          cp.title = '';
        }
      }
    })
    .catch(()=>{ el.textContent='unknown'; });
}
function sshMode(mode){
  var run = function(){
    var el=document.getElementById('ssh-msg'); el.textContent='Applying…'; el.className='small mt-1 text-secondary';
    fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/ssh-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode})})
      .then(r=>r.json()).then(d=>{ el.textContent=(d.success?'✓ ':'✗ ')+(d.message||''); el.className='small mt-1 '+(d.success?'text-success':'text-danger'); loadSshStatus(); })
      .catch(()=>{ el.textContent='✗ Failed'; el.className='small mt-1 text-danger'; });
  };
  if(mode==='off'){
    confirmDialog({title:'Disable public SSH', icon:'shield-lock', confirmClass:'btn-danger', confirmLabel:'Disable public SSH',
      bodyText:'Disable PUBLIC SSH (port 22)? SSH will only work over Tailscale after this. Make sure Tailscale SSH works first!',
      onConfirm:run});
  } else { run(); }
}
function closePanelPort(){
  confirmDialog({title:'Close public panel port', icon:'shield-lock', confirmClass:'btn-danger', confirmLabel:'Close public port',
    bodyText:'Close the public web port so the panel is reachable ONLY over your tailnet?\n\nMake sure you can already reach the panel at your ts.net URL (Tailscale Serve) — this removes the public way in.',
    onConfirm:function(){
      var m=document.getElementById('panel-port-msg'); m.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Closing…</span>';
      fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/close-panel-port',{method:'POST'}).then(r=>r.json())
        .then(d=>{ m.innerHTML='<span class="text-'+(d.success?'success':'danger')+'">'+(window.escapeHtml?escapeHtml(d.message):(d.message||''))+'</span>'; if(d.success) loadSshStatus(); })  // nosemgrep
        .catch(()=>{ m.innerHTML='<span class="text-danger">Request failed.</span>'; });
    }});
}
function onBindSelect(){
  var sel=document.getElementById('panel-bind-select');
  var wrap=document.getElementById('panel-bind-custom-wrap');
  if(sel && wrap) wrap.style.display = (sel.value === '__custom__') ? '' : 'none';
}
function changePanelBinding(){
  var pinp=document.getElementById('panel-port-input'); if(!pinp) return;
  var p=parseInt(pinp.value,10);
  if(!(p>=1024 && p<=65535)){ if(window.toast) toast('Pick a port between 1024 and 65535.','warning'); return; }
  var sel=document.getElementById('panel-bind-select');
  var bind = sel ? sel.value : '0.0.0.0';
  if(bind === '__custom__'){
    bind = (document.getElementById('panel-bind-custom').value || '').trim();
    if(!bind){ if(window.toast) toast('Enter the IP address to bind to.','warning'); return; }
  }
  var pretty = bind + ':' + p;
  confirmDialog({title:'Change panel binding', icon:'hdd-network', confirmClass:'btn-warning', confirmLabel:'Change binding',
    bodyText:'Change the panel binding to '+pretty+'?\n\nThe panel will briefly restart to apply it. '
      +'Make sure you can still reach it afterward (over Tailscale, or on the new address/port).',
    onConfirm:function(){ _changePanelBinding(p, bind); }});
}
function _changePanelBinding(p, bind){
  var m=document.getElementById('panel-port-change-msg');
  m.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Applying…</span>';
  fetch(MOUNT+'/api/panel/change-port',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({port:p, bind_host:bind})})
    .then(r=>r.json()).then(d=>{
      if(!d.success){ m.innerHTML='<span class="text-danger">'+(window.escapeHtml?escapeHtml(d.message):(d.message||'Failed'))+'</span>'; return; }  // nosemgrep
      // The panel is restarting. Work out where it'll be reachable afterward.
      var target;
      if(d.served_over_tailscale || !location.port){
        target = location.href;                       // same URL (Tailscale Serve / no explicit port)
      } else if(d.port_changed){
        var u=new URL(location.href); u.port=d.new_port; target=u.href;   // direct access → new port
      } else {
        target = location.href;                       // only the bind changed; same URL
      }
      m.innerHTML='<span class="text-success">Panel restarting on '+(window.escapeHtml?escapeHtml(d.new_bind):d.new_bind)+':'+escapeHtml(d.new_port)+'… reconnecting shortly.</span>';  // nosemgrep
      setTimeout(function(){ location.href=target; }, 7000);   // give the service time to rebind
    })
    .catch(function(){
      // The restart may cut the connection before the response arrives.
      m.innerHTML='<span class="text-warning">The panel is restarting — reconnect in a moment'
        + (location.port ? ' on the new address/port' : '') + '.</span>';
    });
}
function changeSshPort(){
  var inp=document.getElementById('ssh-port-input'); if(!inp) return;
  var p=parseInt(inp.value,10);
  if(!(p>=1 && p<=65535)){ if(window.toast) toast('Enter a port between 1 and 65535.','warning'); return; }
  var bindEl=document.getElementById('ssh-bind-input');
  var bind=bindEl ? (bindEl.value||'').trim() : '';
  var bindNote = bind ? (' and bind it to '+bind+' (the panel will roll back if it can\'t reach the host there)') : '';
  confirmDialog({title:'Change SSH port', icon:'door-closed', confirmClass:'btn-primary', confirmLabel:'Change SSH port',
    bodyText:'Move SSH to port '+p+bindNote+'?\n\nLockout-safe: the current binding stays in place as a fallback, and the '
      +'firewall and fail2ban are updated to the new port. Once you\'ve confirmed you can reach SSH on '
      +p+', close the old port from the Firewall page.',
    onConfirm:function(){
      var m=document.getElementById('ssh-port-msg');
      if(m) m.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Applying (opening the port, updating sshd + fail2ban, restarting sshd)…</span>';
      fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/ssh-port',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port:p, bind:bind})})
        .then(function(r){return r.json();}).then(function(d){
          if(m) m.innerHTML='<span class="text-'+(d.success?'success':'danger')+'">'+(window.escapeHtml?escapeHtml(d.message||''):(d.message||''))+'</span>';  // nosemgrep
          if(window.toast) toast(d.message||(d.success?'SSH port changed':'Failed'), d.success?'success':'danger');
        })
        .catch(function(){ if(m) m.innerHTML='<span class="text-danger">Request failed.</span>'; });
    }});
}
function switchToTailscale(){
  confirmDialog({title:'Migrate to Tailscale SSH', icon:'arrow-repeat', confirmClass:'btn-primary', confirmLabel:'Migrate',
    bodyText:'Switch the panel to Tailscale SSH for this server?\n\nThe connection address becomes the Tailscale IP/DNS and auth switches to Tailscale SSH. Requires Tailscale to be running on the remote.',
    onConfirm:_switchToTailscale});
}
function _switchToTailscale(){
  var el=document.getElementById('migrate-msg'); el.textContent='Migrating…'; el.className='small mt-1 text-secondary';
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/tailscale-migrate',{method:'POST'}).then(r=>r.json())
    .then(d=>{ if(d.success){ el.textContent='✓ '+(d.message||'Migrated'); el.className='small mt-1 text-success'; setTimeout(function(){window.refreshSection('#conn-ssh-card');},1200); } else { el.textContent='✗ '+(d.message||'Failed'); el.className='small mt-1 text-danger'; } })
    .catch(()=>{ el.textContent='✗ Migration failed'; el.className='small mt-1 text-danger'; });
}
// ── System specs (static — fetched once) ──
function specEsc(s){ return window.escapeHtml(s); }
function renderSpecs(d, el){
  if(!el) return;
  if(!d || d.error){ el.innerHTML = '<div class="col-12 text-danger small">Specs unavailable'+(d&&d.error?': '+specEsc(d.error):'')+'</div>'; return; }  // nosemgrep
  function tile(label, val, cls){
    if(!val) return '';
    return '<div class="'+(cls||'col-6 col-md-3')+'"><div class="stat-tile h-100"><div class="stat-label">'+label+'</div>'
      +'<div style="font-size:.9rem;font-weight:600;color:var(--text-heading);word-break:break-word;line-height:1.3;">'+specEsc(val)+'</div></div></div>';
  }
  var cpu = d.cpu + (d.cpu_speed ? '  ·  ' + d.cpu_speed : '');
  var html = tile('Operating System', d.os, 'col-12 col-md-6')
    + tile('Processor', cpu, 'col-12 col-md-6')
    + tile('CPU Cores', d.cores, 'col-6 col-md-3')
    + tile('Memory', d.ram, 'col-6 col-md-3')
    + tile('Disk (/)', d.disk, 'col-6 col-md-3')
    + tile('Kernel', d.kernel, 'col-6 col-md-3')
    + tile('Architecture', d.arch, 'col-6 col-md-3')
    + tile('Virtualization', d.virt, 'col-6 col-md-3')
    + tile('Hostname', d.hostname, 'col-6 col-md-3');
  el.innerHTML = html || '<div class="col-12 text-secondary small">No spec data.</div>';  // nosemgrep
}
fetch(MOUNT + '/api/remote/' + REMOTE_ID + '/specs').then(r=>r.json())
  .then(d=>renderSpecs(d, document.getElementById('specs-body')))
  .catch(()=>renderSpecs({error:'request failed'}, document.getElementById('specs-body')));

// Ubuntu Pro card (shared widget from base.html). Pass the persisted status so the card
// paints instantly instead of blanking to "Checking Ubuntu Pro…"; it then refreshes silently.

// ── Panel-host-only controls (Tailscale SSH, UFW-allow, self-update) ──
function tsSshEnable(){
  confirmDialog({title:'Enable Tailscale SSH', icon:'shield-check', confirmClass:'btn-primary', confirmLabel:'Enable',
    bodyText:'Enable Tailscale SSH? This re-authenticates Tailscale with SSH support enabled.',
    onConfirm:function(){
      fetch(MOUNT+'/api/server-management/ts-ssh-enable',{method:'POST'}).then(r=>r.json())
        .then(d=>{ if(window.toast) toast(d.message||(d.success?'Enabled':'Failed'), d.success?'success':'danger'); if(d.success) setTimeout(function(){window.refreshSection('#conn-ssh-card');},800); })
        .catch(()=>{ if(window.toast) toast('Failed to enable Tailscale SSH','danger'); });
    }});
}
function tsSshDisable(){
  confirmDialog({title:'Disable Tailscale SSH', icon:'shield-slash', confirmClass:'btn-danger', confirmLabel:'Disable',
    bodyText:'Disable Tailscale SSH?',
    onConfirm:function(){
      fetch(MOUNT+'/api/server-management/ts-ssh-disable',{method:'POST'}).then(r=>r.json())
        .then(d=>{ if(window.toast) toast(d.message||(d.success?'Disabled':'Failed'), d.success?'success':'danger'); if(d.success) setTimeout(function(){window.refreshSection('#conn-ssh-card');},800); })
        .catch(()=>{ if(window.toast) toast('Failed to disable Tailscale SSH','danger'); });
    }});
}
function ufwAllowTailscale(){
  fetch(MOUNT+'/api/server-management/ufw-allow-tailscale',{method:'POST'}).then(r=>r.json())
    .then(d=>{ if(window.toast) toast(d.message||(d.success?'Allowed':'Failed'), d.success?'success':'danger'); if(d.success) setTimeout(function(){window.refreshSection('#conn-ssh-card');},800); })
    .catch(()=>{ if(window.toast) toast('Failed to configure UFW','danger'); });
}
function renderUpdate(d){
  var st=document.getElementById('pu-status'); if(!st) return;
  var btn=document.getElementById('pu-update-btn'); var changes=document.getElementById('pu-changes');
  var cur=document.getElementById('pu-current'); if(cur) cur.textContent='v'+(d.current_version||'?');
  if(d.git===false){ st.innerHTML='<i class="bi bi-info-circle"></i> '+(d.message||'Self-update unavailable (not a git checkout).'); btn.style.display='none'; changes.style.display='none'; return; }  // nosemgrep
  if(d.fetched===false){ st.innerHTML='<span class="text-secondary"><i class="bi bi-cloud-slash"></i> '+(d.message||'Couldn\'t reach the update source.')+'</span>'; btn.style.display='none'; changes.style.display='none'; return; }  // nosemgrep
  if(d.update_available){
    st.innerHTML='<span class="text-warning"><i class="bi bi-arrow-up-circle-fill"></i> Update available: <strong>v'+(d.remote_version||'?')+'</strong> ('+d.behind+' commit'+(d.behind===1?'':'s')+' behind).</span>';  // nosemgrep
    btn.style.display='';
    var ul=document.getElementById('pu-changes-list'); ul.innerHTML='';
    (d.changes||[]).forEach(function(c){ var li=document.createElement('li'); li.textContent=c; ul.appendChild(li); });
    changes.style.display=(d.changes&&d.changes.length)?'':'none';
  } else {
    // No VERIFIED update ahead — show it as up to date. If a newer commit exists but is still
    // being verified (or failed a check), we deliberately DON'T surface a "being verified"
    // state; the update only appears once a commit has fully passed every check.
    st.innerHTML='<span class="text-success"><i class="bi bi-check-circle"></i> You\'re up to date'+(d.current_sha?' ('+escapeHtml(d.current_sha)+')':'')+'.</span>';  // nosemgrep
    btn.style.display='none'; changes.style.display='none';
  }
}
function checkPanelUpdate(force){
  var st=document.getElementById('pu-status'); if(!st) return;
  st.innerHTML='<i class="bi bi-arrow-repeat"></i> Checking for updates…';
  fetch(MOUNT+'/api/panel/update-status'+(force?'?force=1':'')).then(function(r){return r.json();}).then(renderUpdate)
    .catch(function(){ st.innerHTML='<span class="text-danger">Update check failed.</span>'; });
}
// Render the streamed self-update log with per-line styling (steps / ok / warn / error).
function renderPuLog(lines){
  var body=document.getElementById('pu-log-body'); if(!body) return;
  var atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 30;
  var html=(lines||[]).map(function(ln){
    var cls='text-secondary';
    if(/^\[\d+\/\d+\]/.test(ln)) cls='text-info fw-semibold';
    else if(/^✓|health check passed|update complete|rollback succeeded|is responding|now running version/i.test(ln)) cls='text-success';
    else if(/\[error\]|health check failed|rolling back|could not/i.test(ln)) cls='text-danger';
    else if(/^\[!\]|warn/i.test(ln)) cls='text-warning';
    return '<div class="'+cls+'">'+(window.escapeHtml?escapeHtml(ln):ln)+'</div>';
  }).join('');
  body.innerHTML = html || '<span class="text-secondary">Starting…</span>';  // nosemgrep
  if(atBottom) body.scrollTop = body.scrollHeight;   // stay pinned to the newest line
}
function doPanelUpdate(){
  confirmDialog({title:'Update the panel', icon:'arrow-up-circle', confirmClass:'btn-primary', confirmLabel:'Update now',
    bodyText:'Update the panel to the latest version now?\n\nIt will back up, pull new code, install any new dependencies, and restart — briefly unavailable (a few seconds). Live progress shows below.',
    onConfirm:_doPanelUpdate});
}
function _doPanelUpdate(){
  var msg=document.getElementById('pu-msg'), btn=document.getElementById('pu-update-btn');
  var logWrap=document.getElementById('pu-log'), body=document.getElementById('pu-log-body');
  btn.disabled=true; logWrap.style.display='';
  body.innerHTML='<span class="text-secondary">Starting the updater…</span>';
  msg.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Updating…</span>';
  // Remember THIS process's boot_id — the run is finished once the panel has actually
  // restarted (boot_id changed), not when the git SHA moves (that happens mid-update).
  fetch(MOUNT+'/api/panel/update-status').then(function(r){return r.json();}).then(function(before){
    var beforeBoot=(before&&before.boot_id)||'';
    fetch(MOUNT+'/api/panel/update',{method:'POST'}).then(function(r){return r.json();}).then(function(d){
      if(!d.success){ msg.innerHTML='<span class="text-danger">'+(window.escapeHtml?escapeHtml(d.message||'Update failed'):(d.message||'Update failed'))+'</span>'; btn.disabled=false; return; }  // nosemgrep
      watchPanelRestart(beforeBoot, msg, 'Update complete');
    }).catch(function(){ msg.innerHTML='<span class="text-danger">Update request failed.</span>'; btn.disabled=false; });
  }).catch(function(){ msg.innerHTML='<span class="text-danger">Couldn\'t read the current version.</span>'; btn.disabled=false; });
}

// Watch for the panel restarting after a detached update/branch-switch: stream the installer's
// step log, and finish when boot_id flips (the new process is live), then reload. Shared by the
// "Update now" and "Switch branch" flows since both back up → change code → restart.
function watchPanelRestart(beforeBoot, msg, doneLabel){
  var tries=0, restarted=false, done=false;
  var iv=setInterval(function(){
    tries++;
    fetch(MOUNT+'/api/panel/update-log').then(function(r){ return r.ok?r.json():null; })
      .then(function(l){ if(l && l.lines && l.lines.length) renderPuLog(l.lines); }).catch(function(){});
    fetch(MOUNT+'/api/panel/update-status').then(function(r){ return r.ok?r.json():null; }).then(function(s){
      if(!s){ if(!restarted){ restarted=true; msg.innerHTML='<span class="text-warning"><i class="bi bi-arrow-repeat"></i> Restarting the panel…</span>'; } return; }
      if(s.boot_id && beforeBoot && s.boot_id!==beforeBoot && !done){
        done=true; clearInterval(iv);
        fetch(MOUNT+'/api/panel/update-log').then(function(r){ return r.ok?r.json():null; }).then(function(l){
          if(l && l.lines) renderPuLog(l.lines);
          msg.innerHTML='<span class="text-success"><i class="bi bi-check-circle"></i> '+escapeHtml(doneLabel||'Done')+' — reloading…</span>';  // nosemgrep
          setTimeout(function(){ location.reload(); }, 2500);
        });
      }
    }).catch(function(){ if(!restarted){ restarted=true; msg.innerHTML='<span class="text-warning"><i class="bi bi-arrow-repeat"></i> Restarting the panel…</span>'; } });
    if(tries>120){ clearInterval(iv); msg.innerHTML='<span class="text-warning">Still working — reload the page to check.</span>'; }
  }, 1500);
}
// Populate the branch selector with the remote branches + the currently tracked one.
function loadPanelBranches(){
  var sel=document.getElementById('pu-branch-select'), cur=document.getElementById('pu-branch-current');
  if(!sel) return;
  fetch(MOUNT+'/api/panel/branches').then(function(r){return r.json();}).then(function(d){
    var branches=d.branches||[], current=d.current||'main';
    if(cur) cur.textContent=current;
    sel.innerHTML='';
    branches.forEach(function(b){
      var o=document.createElement('option'); o.value=b; o.textContent=b;
      if(b===current) o.selected=true; sel.appendChild(o);
    });
  }).catch(function(){});
}
function switchPanelBranch(){
  var sel=document.getElementById('pu-branch-select'), msg=document.getElementById('pu-branch-msg');
  var btn=document.getElementById('pu-branch-switch');
  if(!sel||!sel.value){ return; }
  var branch=sel.value;
  var logWrap=document.getElementById('pu-log'), body=document.getElementById('pu-log-body');
  confirmDialog({title:'Switch panel branch', icon:'diagram-3', confirmClass:'btn-danger', confirmLabel:'Switch branch',
    bodyText:'Switch the panel to branch "'+branch+'"?\n\nIt backs up, checks out that branch and restarts. If it fails to boot it rolls back automatically. Non-main branches are unverified code — use for testing.',
    onConfirm:function(){
      btn.disabled=true; if(logWrap) logWrap.style.display='';
      if(body) body.innerHTML='<span class="text-secondary">Starting…</span>';
      msg.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Switching…</span>';
      fetch(MOUNT+'/api/panel/update-status').then(function(r){return r.json();}).then(function(before){
        var beforeBoot=(before&&before.boot_id)||'';
        fetch(MOUNT+'/api/panel/switch-branch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({branch:branch})})
          .then(function(r){return r.json();}).then(function(d){
            if(!d.success){ msg.innerHTML='<span class="text-danger">'+(window.escapeHtml?escapeHtml(d.message||'Switch failed'):(d.message||'Switch failed'))+'</span>'; btn.disabled=false; return; }  // nosemgrep
            watchPanelRestart(beforeBoot, msg, 'Switched to '+branch);
          }).catch(function(){ msg.innerHTML='<span class="text-danger">Switch request failed.</span>'; btn.disabled=false; });
      }).catch(function(){ msg.innerHTML='<span class="text-danger">Couldn\'t read the current version.</span>'; btn.disabled=false; });
    }});
}

// ── Diagnostics & file integrity (panel host only) ──────────────────
var DIAG_BADGE = { ok:'bg-success', warn:'bg-warning text-dark', fail:'bg-danger' };
var DIAG_ICON  = { ok:'bi-check-circle-fill text-success',
                   warn:'bi-exclamation-triangle-fill text-warning',
                   fail:'bi-x-circle-fill text-danger' };

function runDiagnostics(){
  var btn=document.getElementById('diag-run-btn');
  var msg=document.getElementById('diag-msg');
  var list=document.getElementById('diag-list');
  if(btn){ btn.disabled=true; }
  if(msg){ msg.innerHTML='<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Running…</span>'; }
  fetch(MOUNT+'/api/panel/diagnostics').then(function(r){return r.json();}).then(function(d){
    // Build rows with textContent (file details can contain paths) — no innerHTML injection.
    list.textContent='';
    (d.checks||[]).forEach(function(c){
      var row=document.createElement('div');
      row.className='d-flex align-items-start gap-2 py-1';
      var ic=document.createElement('i');
      ic.className='bi '+(DIAG_ICON[c.level]||DIAG_ICON.warn);
      ic.style.marginTop='2px';
      var txt=document.createElement('div');
      var name=document.createElement('strong'); name.textContent=c.name+': ';
      var det=document.createElement('span'); det.className='text-secondary'; det.textContent=c.detail||'';
      txt.appendChild(name); txt.appendChild(det);
      row.appendChild(ic); row.appendChild(txt);
      list.appendChild(row);
    });
    var badge=document.getElementById('diag-summary');
    if(badge){
      var s=d.summary||'fail';
      badge.className='badge '+(DIAG_BADGE[s]||DIAG_BADGE.fail);
      badge.textContent = s==='ok' ? 'all healthy' : (s==='warn' ? (d.warn+' warning(s)') : (d.fail+' problem(s)'));
    }
    if(msg) msg.textContent='';
    loadIntegrity();  // refresh the file list + repair button
    loadDbStats();    // refresh DB size + audit row count
    loadAutoUpd();    // refresh automatic-security-updates status
  }).catch(function(){
    if(msg) msg.innerHTML='<span class="text-danger">Diagnostics failed — check the panel logs.</span>';
  }).finally(function(){ if(btn) btn.disabled=false; });
}

function loadIntegrity(){
  fetch(MOUNT+'/api/panel/integrity').then(function(r){return r.json();}).then(function(d){
    var wrap=document.getElementById('diag-integrity');
    var clean=document.getElementById('diag-integrity-clean');
    var bad=document.getElementById('diag-integrity-bad');
    if(!wrap) return;
    wrap.style.display='';
    if(!d.git){ clean.style.display='none'; bad.style.display='none'; return; }
    if(d.clean){ clean.style.display=''; bad.style.display='none'; return; }
    clean.style.display='none'; bad.style.display='';
    document.getElementById('diag-bad-count').textContent=d.count;
    var ul=document.getElementById('diag-bad-list'); ul.textContent='';
    (d.modified||[]).forEach(function(m){
      var li=document.createElement('li');
      var st=document.createElement('span');
      st.className = m.status==='deleted' ? 'text-danger' : 'text-warning';
      st.textContent='['+m.status+'] ';
      var p=document.createElement('span'); p.textContent=m.path;  // textContent — never innerHTML
      li.appendChild(st); li.appendChild(p);
      ul.appendChild(li);
    });
  }).catch(function(){});
}

function repairPanel(){
  confirmDialog({title:'Restore panel files', icon:'arrow-counterclockwise', confirmClass:'btn-danger', confirmLabel:'Restore files',
    bodyText:'Restore all modified/deleted panel files to their installed version? Your database, keys and config are not affected.',
    onConfirm:_repairPanel});
}
function _repairPanel(){
  var btn=document.getElementById('diag-repair-btn');
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Restoring…'; }
  fetch(MOUNT+'/api/panel/repair',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json();}).then(function(d){
      var msg=document.getElementById('diag-msg');
      if(msg){
        msg.className='small';
        msg.innerHTML = d.success  // nosemgrep
          ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i> '+ (d.message||'Restored.') +'</span>'
          : '<span class="text-danger">'+ (d.message||'Repair failed.') +'</span>';
      }
      loadIntegrity();
      if(d.success) runDiagnostics();
    }).catch(function(){
      var msg=document.getElementById('diag-msg');
      if(msg) msg.innerHTML='<span class="text-danger">Repair request failed.</span>';
    }).finally(function(){
      if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-arrow-counterclockwise"></i> Restore all from installed version'; }
    });
}

// ── Database maintenance (panel host only) ──────────────────────────
function fmtBytes(b){
  if(b == null) return '—';
  if(b >= 1099511627776) return (b/1099511627776).toFixed(2)+' TB';  // NOPMD
  if(b >= 1073741824) return (b/1073741824).toFixed(1)+' GB';  // NOPMD
  if(b >= 1048576) return (b/1048576).toFixed(1)+' MB';
  if(b >= 1024) return Math.max(1, Math.round(b/1024))+' KB';
  return b+' B';
}
function loadDbStats(){
  fetch(MOUNT+'/api/panel/db-stats').then(function(r){return r.json();}).then(function(d){
    var el=document.getElementById('diag-db-stats'); if(!el) return;
    if(d.error){ el.textContent='Could not read database stats.'; return; }
    el.textContent='Size '+fmtBytes(d.size)+' · WAL '+fmtBytes(d.wal_size)+
      ' · audit rows '+(d.audit_rows==null?'?':d.audit_rows);
  }).catch(function(){});
}
function optimizeDb(){
  var btn=document.getElementById('diag-optimize-btn');
  var msg=document.getElementById('diag-db-msg');
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Optimizing…'; }
  fetch(MOUNT+'/api/panel/optimize-db',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json();}).then(function(d){
      if(msg){
        msg.className='small';
        if(d.success){
          var freed=d.freed||0;
          msg.innerHTML='<span class="text-success"><i class="bi bi-check-circle-fill"></i> Optimized'+  // nosemgrep
            (freed>0?(' — reclaimed '+fmtBytes(freed)):'')+'.</span>';
        } else {
          msg.innerHTML='<span class="text-danger">'+(d.message||'Optimize failed.')+'</span>';  // nosemgrep
        }
      }
      loadDbStats();
    }).catch(function(){ if(msg) msg.innerHTML='<span class="text-danger">Optimize request failed.</span>'; })
    .finally(function(){ if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-stars"></i> Optimize database'; } });
}
function checkDbHealth(){
  var btn=document.getElementById('diag-dbhealth-btn');
  var out=document.getElementById('diag-dbhealth-result');
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Checking…'; }
  fetch(MOUNT+'/api/panel/db-health').then(function(r){return r.json();}).then(function(d){
    if(!out) return;
    var rbtn=document.getElementById('diag-repair-btn');
    if(d.healthy===true){
      out.innerHTML='<span class="text-success"><i class="bi bi-check-circle-fill"></i> Database is healthy — integrity check passed.</span>';
      if(rbtn) rbtn.style.display='none';
    } else if(d.healthy===false){
      out.innerHTML='<span class="text-danger"><i class="bi bi-exclamation-triangle-fill"></i> Integrity check flagged a problem: '+escapeHtml(d.detail||'')+'.</span>'+  // nosemgrep
        '<div class="text-secondary" style="font-size:.7rem;">Click <strong>Repair database</strong> — it rebuilds the readable data, or restores the last healthy backup; your data is copied aside first, never deleted. The panel briefly restarts.</div>';
      if(rbtn) rbtn.style.display='';
    } else {
      out.innerHTML='<span class="text-warning">Could not run the health check right now.</span>';
    }
  }).catch(function(){ if(out) out.innerHTML='<span class="text-danger">Health check request failed.</span>'; })
  .finally(function(){ if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-heart-pulse"></i> Check health'; } });
}

// Repair a flagged database on-demand: stops the panel, repairs offline, restarts (~1 min).
function repairDb(){
  confirmDialog({title:'Repair database', icon:'wrench-adjustable', confirmClass:'btn-warning', confirmLabel:'Repair & restart',
    bodyText:'The panel will stop, repair the database offline (your data is copied aside first — never deleted), then restart. This takes about a minute. Continue?',
    onConfirm:function(){
      var rb=document.getElementById('diag-repair-btn'), msg=document.getElementById('diag-db-msg');
      if(rb){ rb.disabled=true; rb.innerHTML='<span class="spinner-border spinner-border-sm"></span> Repairing…'; }
      fetch(MOUNT+'/api/panel/repair-db',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
        .then(function(r){return r.json();}).then(function(d){
          if(msg){ msg.className='small';
            msg.innerHTML = d.success  // nosemgrep
              ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i> '+(window.escapeHtml?escapeHtml(d.message||'Repair started.'):(d.message||'Repair started.'))+'</span>'
              : '<span class="text-danger">'+(window.escapeHtml?escapeHtml(d.message||'Failed.'):(d.message||'Failed.'))+'</span>'; }
        }).catch(function(){ if(msg) msg.innerHTML='<span class="text-danger">Request failed.</span>'; })
        .finally(function(){ if(rb){ rb.disabled=false; rb.innerHTML='<i class="bi bi-wrench-adjustable"></i> Repair database'; } });
    }});
}

// ── Automatic security updates (panel host only) ────────────────────
function loadAutoUpd(){
  fetch(MOUNT+'/api/panel/auto-updates').then(function(r){return r.json();}).then(function(d){
    var el=document.getElementById('diag-autoupd-status');
    var btn=document.getElementById('diag-autoupd-btn');
    if(!el) return;
    if(d.error){ el.textContent='Could not check update status.'; return; }
    el.innerHTML = d.enabled  // nosemgrep
      ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i> '+ (d.detail||'Enabled.') +'</span>'
      : '<span class="text-warning"><i class="bi bi-exclamation-triangle-fill"></i> '+ (d.detail||'Not enabled.') +'</span>';
    if(btn) btn.style.display = d.enabled ? 'none' : '';
  }).catch(function(){});
}
function enableAutoUpdates(){
  confirmDialog({title:'Enable automatic security updates', icon:'shield-check', confirmClass:'btn-primary', confirmLabel:'Enable',
    bodyText:'Install and enable automatic security updates (unattended-upgrades)? This changes the system update settings.',
    onConfirm:_enableAutoUpdates});
}
function _enableAutoUpdates(){
  var btn=document.getElementById('diag-autoupd-btn'), msg=document.getElementById('diag-autoupd-msg');
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Enabling…'; }
  fetch(MOUNT+'/api/panel/enable-auto-updates',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json();}).then(function(d){
      if(msg){
        msg.className='small';
        msg.innerHTML = d.success  // nosemgrep
          ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i> '+escapeHtml(d.message||'Enabled.')+'</span>'
          : '<span class="text-danger">'+escapeHtml(d.message||'Failed.')+'</span>';
      }
      loadAutoUpd();
    }).catch(function(){ if(msg) msg.innerHTML='<span class="text-danger">Request failed.</span>'; })
    .finally(function(){ if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-shield-plus"></i> Enable automatic security updates'; } });
}

// Generate a shareable debug report — show it for review, then let the admin download
// it or open a pre-filled GitHub issue (safe summary; log goes in the download).
function genDebugReport(){
  var btn=document.getElementById('diag-report-btn'), msg=document.getElementById('diag-report-msg');
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Generating…'; }
  fetch(MOUNT+'/api/panel/debug-report').then(function(r){return r.json();}).then(function(d){
    if(d.error){ if(msg) msg.innerHTML='<span class="text-danger">Could not generate the report.</span>'; return; }
    var ta=document.getElementById('diag-report-text');
    ta.value=d.report; ta.style.display='';   // .value (not innerHTML) — nothing to inject
    var dl=document.getElementById('diag-report-dl');
    dl.href=URL.createObjectURL(new Blob([d.report],{type:'text/markdown'}));
    dl.download=d.filename; dl.style.display='';
    var gh=document.getElementById('diag-report-gh');
    var body=d.summary+'\n\n---\n**Describe the problem here.** For the full log, attach the downloaded debug file.\n';
    gh.href=d.issues_url+'?labels=debug&title='+encodeURIComponent('Debug report')+'&body='+encodeURIComponent(body.slice(0,6000));
    gh.style.display='';
    if(msg) msg.innerHTML='<span class="text-success">Report ready — review it below before sharing.</span>';
  }).catch(function(){ if(msg) msg.innerHTML='<span class="text-danger">Request failed.</span>'; })
    .finally(function(){ if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-clipboard2-data"></i> Generate debug report'; } });
}

