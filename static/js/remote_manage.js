// Reboot-required banner for THIS remote (the panel host is shown globally by base.html, so skip it
// here to avoid a duplicate).
if (!IS_LOCAL && window.rebootNagCheck) { window.rebootNagCheck(REMOTE_ID, REMOTE_NAME); }

// ── Section tabs: show only the cards for the selected group (Overview / Host Controls /
// Maintenance). Cards keep their place/markup/JS; we just toggle visibility. The sidebar's
// ── Security tab: fail2ban bans (panel + ssh), recent events, raw logs ──────────
// Panel host hits /api/panel/security/*; a remote hits /api/remote/<id>/security/* (over SSH).
function secBase(){ return IS_LOCAL ? MOUNT+'/api/panel/security' : MOUNT+'/api/remote/'+REMOTE_ID+'/security'; }
function loadSecurity(){ loadSecurityBans(); loadSecurityTopIps(); loadSecurityEvents(); }
function loadSecurityTopIps(){
  var el=document.getElementById('sec-top'); if(!el) return;
  fetch(secBase()+'/top-ips').then(function(r){return r.json();}).then(function(d){
    var tog=document.getElementById('sec-autoblock'); if(tog) tog.checked=!!(d&&d.autoblock);
    var th=document.getElementById('sec-threshold'); if(th && d && d.threshold) th.value=d.threshold;
    renderWhitelist((d&&d.whitelist)||[]);
    var ips=(d&&d.ips)||[];
    if(!ips.length){ el.innerHTML='<div class="small text-secondary">No fail2ban activity logged yet.</div>'; return; }
    var rows=ips.map(function(o,i){
      var badge = o.banned_now ? '<span class="badge bg-danger">banned now</span>'
                : (o.bans>0 ? '<span class="badge bg-secondary" style="font-weight:normal;">'+o.bans+' ban'+(o.bans===1?'':'s')+'</span>' : '');
      var block = o.blocked
        ? '<span class="badge bg-dark border me-1" style="font-weight:normal;"><i class="bi bi-shield-fill-x"></i> blocked</span>'
          +'<button class="btn btn-link btn-sm p-0" style="font-size:.72rem;"'+_da('unblockOffender',[o.ip,'@self'])+'>unblock</button>'
        : '<button class="btn btn-sm btn-outline-danger py-0 px-1" style="font-size:.72rem;"'+_da('blockOffender',[o.ip,'@self'])+'><i class="bi bi-shield-lock"></i> Block</button>';
      // Which fail2ban jail(s) caught this IP (e.g. sshd, recidive, the panel-login jail).
      var jails=(o.jails||[]);
      var jailCell = jails.length
        ? jails.map(function(j){ return '<span class="badge border text-secondary me-1 mb-1" style="font-weight:normal;">'+escapeHtml(j)+'</span>'; }).join('')
        : '<span class="text-secondary">—</span>';
      return '<tr><td class="small text-secondary">'+(i+1)+'</td>'
        +'<td class="small"><code>'+escapeHtml(o.ip)+'</code></td>'
        +'<td class="small text-end">'+(o.attempts||0)+'</td>'
        +'<td class="small text-end">'+(o.bans||0)+'</td>'
        +'<td class="small text-nowrap">'+jailCell+'</td>'
        +'<td class="small">'+badge+'</td>'
        +'<td class="small text-nowrap">'+block+'</td></tr>';
    }).join('');
    el.innerHTML='<div class="table-responsive"><table class="table table-sm align-middle mb-0">'  // nosemgrep
      +'<thead><tr><th class="small">#</th><th class="small">IP</th><th class="small text-end">Attempts</th>'
      +'<th class="small text-end">Bans</th><th class="small">Jail</th><th class="small">Status</th><th class="small">Firewall</th></tr></thead>'
      +'<tbody>'+rows+'</tbody></table></div>';
  }).catch(function(){ el.innerHTML='<div class="small text-danger">Could not load top offenders.</div>'; });
}
function blockOffender(ip, btn){
  confirmDialog({title:'Block IP', icon:'shield-lock', confirmClass:'btn-danger', confirmLabel:'Block (all ports)',
    bodyText:'Firewall-block '+ip+' on ALL ports (UFW)? It won\'t be able to reach SSH, the panel, or any game server on this host until you unblock it.',
    onConfirm:function(){
      if(btn) btn.disabled=true;
      fetch(secBase()+'/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})})
        .then(function(r){return r.json();}).then(function(d){ if(window.toast) toast(d.message||(d.success?'Blocked':'Failed'), d.success?'success':'danger'); loadSecurityTopIps(); })
        .catch(function(){ if(window.toast) toast('Block failed','danger'); if(btn) btn.disabled=false; });
    }});
}
function unblockOffender(ip, btn){
  if(btn) btn.disabled=true;
  fetch(secBase()+'/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip,unblock:true})})
    .then(function(r){return r.json();}).then(function(d){ if(window.toast) toast(d.message||(d.success?'Unblocked':'Failed'), d.success?'success':'info'); loadSecurityTopIps(); })
    .catch(function(){ if(window.toast) toast('Unblock failed','danger'); if(btn) btn.disabled=false; });
}
function toggleAutoblock(cb){
  var on=!!(cb&&cb.checked);
  fetch(secBase()+'/autoblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:on})})
    .then(function(r){return r.json();}).then(function(d){
      if(window.toast) toast(on?'Auto-block on — applying now…':'Auto-block off', on?'success':'info');
      setTimeout(loadSecurityTopIps, on?2500:300);   // give the immediate reconcile a moment
    }).catch(function(){ if(window.toast) toast('Couldn\'t change auto-block','danger'); if(cb) cb.checked=!on; });
}
function saveThreshold(btn){
  var inp=document.getElementById('sec-threshold'); var v=parseInt(inp&&inp.value,10);
  if(!v||v<1){ if(window.toast) toast('Enter a number of attempts (1 or more)','info'); return; }
  var on=!!(document.getElementById('sec-autoblock')||{}).checked;   // preserve the on/off state
  if(btn) btn.disabled=true;
  fetch(secBase()+'/autoblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:on,threshold:v})})
    .then(function(r){return r.json();}).then(function(d){
      if(btn) btn.disabled=false;
      if(window.toast) toast('Threshold saved — auto-blocking IPs with '+(d.threshold||v)+'+ attempts / 7 days.', 'success');
      setTimeout(loadSecurityTopIps, on?2500:300);
    }).catch(function(){ if(btn) btn.disabled=false; if(window.toast) toast('Couldn\'t save the threshold','danger'); });
}
function renderWhitelist(list){
  var el=document.getElementById('sec-wl-list'); if(!el) return;
  if(!list.length){ el.innerHTML='<span class="small text-secondary">Nothing whitelisted. Your Tailscale IPs are always exempt.</span>'; return; }
  el.innerHTML=list.map(function(ip){  // nosemgrep
    return '<span class="badge bg-secondary d-inline-flex align-items-center gap-1" style="font-weight:normal;">'
      +'<code style="color:inherit;">'+escapeHtml(ip)+'</code>'
      +'<button type="button" class="btn btn-link p-0 text-light" style="font-size:.7rem;line-height:1;text-decoration:none;" '
      +_da('removeWhitelist',[ip])+' title="Remove from whitelist">&times;</button></span>';
  }).join('');
}
function addWhitelist(btn){
  var inp=document.getElementById('sec-wl-input'); var ip=((inp&&inp.value)||'').trim();
  if(!ip){ if(window.toast) toast('Enter an IP or CIDR first','info'); return; }
  if(btn) btn.disabled=true;
  fetch(secBase()+'/whitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})})
    .then(function(r){return r.json();}).then(function(d){
      if(btn) btn.disabled=false;
      if(d.success){ if(inp) inp.value=''; renderWhitelist(d.whitelist||[]);
        if(window.toast) toast(d.added+' whitelisted — it won\'t be banned or blocked.', 'success'); loadSecurityTopIps(); }
      else if(window.toast){ toast(d.message||'Could not add it','danger'); }
    }).catch(function(){ if(btn) btn.disabled=false; if(window.toast) toast('Could not add it','danger'); });
}
function removeWhitelist(ip){
  fetch(secBase()+'/whitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip,remove:true})})
    .then(function(r){return r.json();}).then(function(d){
      renderWhitelist(d.whitelist||[]);
      if(window.toast) toast((d.removed||ip)+' removed from the whitelist','info');
    }).catch(function(){ if(window.toast) toast('Could not remove it','danger'); });
}
function loadSecurityBans(){
  var el=document.getElementById('sec-bans'); if(!el) return;
  fetch(secBase()+'/bans').then(function(r){return r.json();}).then(function(d){
    if(!d.installed){ el.innerHTML='<div class="small text-secondary">fail2ban isn\'t installed on this host.</div>'; return; }
    if(!d.jails||!d.jails.length){ el.innerHTML='<div class="small text-secondary">No fail2ban jails found.</div>'; return; }
    el.innerHTML=d.jails.map(function(j){  // nosemgrep
      var head='<div class="small mb-1"><strong>'+escapeHtml(j.jail)+'</strong> '
        +'<span class="badge bg-'+(j.currently_banned?'danger':'secondary')+'">'+j.currently_banned+' banned</span> '
        +'<span class="text-secondary" style="font-size:.7rem;">'+j.total_banned+' total · '+j.total_failed+' failed</span> '
        +'<button class="btn btn-link p-0 ms-1" style="font-size:.7rem;vertical-align:baseline;"'
        +_da('loadSecurityLog',['fail2ban',j.jail])+' title="Show this jail\'s ban/unban activity">view log</button></div>';
      var body=(j.banned_ips&&j.banned_ips.length)
        ? '<div class="d-flex flex-wrap gap-2">'+j.banned_ips.map(function(ip){
            return '<span class="badge border bg-dark" style="font-weight:normal;">'+escapeHtml(ip)
              +' <button class="btn btn-link p-0 ms-1 text-danger" style="font-size:.7rem;vertical-align:baseline;"'
              +_da('unbanIp',[j.jail,ip,'@self'])+' title="Lift this ban">unban</button></span>'; }).join('')+'</div>'
        : '<div class="text-secondary small">No IPs banned right now.</div>';
      return '<div class="mb-3">'+head+body+'</div>';
    }).join('');
  }).catch(function(){ el.innerHTML='<div class="small text-danger">Could not load bans.</div>'; });
}
function unbanIp(jail, ip, btn){
  if(btn) btn.disabled=true;
  fetch(secBase()+'/unban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jail:jail,ip:ip})})
    .then(function(r){return r.json();}).then(function(d){
      if(window.toast) toast(d.message||(d.success?'Unbanned':'Failed'), d.success?'success':'danger');
      loadSecurityBans();
    }).catch(function(){ if(window.toast) toast('Unban request failed','danger'); if(btn) btn.disabled=false; });
}
function loadSecurityEvents(){
  var el=document.getElementById('sec-events'); if(!el) return;
  fetch(MOUNT+'/api/panel/security/events').then(function(r){return r.json();}).then(function(d){
    var ev=d.events||[];
    if(!ev.length){ el.innerHTML='<div class="small text-secondary">No security events yet.</div>'; return; }
    var rows=ev.map(function(e){
      var t=e.time?new Date(e.time).toLocaleString():'';
      var cls=e.action==='fail2ban_ban'?'text-danger':(e.action==='login_blocked'?'text-warning':'text-secondary');
      return '<tr><td class="small text-secondary text-nowrap">'+escapeHtml(t)+'</td>'
        +'<td class="small"><code class="'+cls+'">'+escapeHtml(e.action)+'</code></td>'
        +'<td class="small">'+escapeHtml(e.user||'')+'</td>'
        +'<td class="small text-secondary">'+escapeHtml(e.detail||'')+'</td>'
        +'<td class="small text-secondary">'+escapeHtml(e.ip||e.target||'')+'</td></tr>';
    }).join('');
    el.innerHTML='<table class="table table-sm align-middle mb-0"><thead><tr>'  // nosemgrep
      +'<th class="small">When</th><th class="small">Event</th><th class="small">User</th><th class="small">Detail</th><th class="small">IP</th></tr></thead><tbody>'+rows+'</tbody></table>';
  }).catch(function(){ el.innerHTML='<div class="small text-danger">Could not load events.</div>'; });
}
function loadSecurityLog(which, jail){
  var el=document.getElementById('sec-log'); if(!el) return;
  var hdr=document.getElementById('sec-log-title');
  if(hdr) hdr.textContent = (which==='fail2ban' && jail) ? ('fail2ban activity — '+jail) : '';
  el.textContent='Loading…';
  var url=secBase()+'/log?which='+encodeURIComponent(which);
  if(jail) url += '&jail='+encodeURIComponent(jail);
  fetch(url).then(function(r){return r.json();}).then(function(d){  // nosemgrep
    el.textContent=d.text||'(log is empty)'; el.scrollTop=el.scrollHeight;   // textContent: raw log is never HTML
    if(el.scrollIntoView) el.scrollIntoView({behavior:'smooth',block:'nearest'});
  }).catch(function(){ el.textContent='Could not read the log.'; });
}

// "update available" badge links to #updates, so a hash pointing at a card opens its tab and
// scrolls to it. ──
(function(){
  var nav = document.getElementById('mtab-nav'); if(!nav) return;
  var TABS = ['overview','controls','maintenance','security'];
  var CARD_TAB = {updates:'maintenance', backups:'maintenance', diagnostics:'maintenance'};
  var _secLoaded = false;
  function show(tab){
    document.querySelectorAll('[data-mtab]').forEach(function(el){
      el.style.display = (el.getAttribute('data-mtab') === tab) ? '' : 'none';
    });
    nav.querySelectorAll('[data-mtab-btn]').forEach(function(b){
      b.classList.toggle('active', b.getAttribute('data-mtab-btn') === tab);
    });
    if (tab === 'security' && !_secLoaded && window.loadSecurity) { _secLoaded = true; loadSecurity(); }
    try { history.replaceState(null, '', '#' + tab); } catch(e){}
  }
  nav.addEventListener('click', function(e){
    var b = e.target.closest('[data-mtab-btn]'); if(b) show(b.getAttribute('data-mtab-btn'));
  });
  var h = (location.hash || '').replace('#','');
  if (TABS.indexOf(h) >= 0) { show(h); }
  else if (CARD_TAB[h]) { show(CARD_TAB[h]); var el = document.getElementById(h); if(el) el.scrollIntoView(); }
  else { show('overview'); }
  // Added as an "existing" remote → land on Host Controls and auto-run the LinuxGSM scan.
  try {
    if (new URLSearchParams(location.search).get('scan') === '1') {
      show('controls');
      var sc = document.getElementById('disc-scan-btn'); if (sc) sc.scrollIntoView({block:'center'});
      setTimeout(function(){ if (window.scanExisting) scanExisting(); }, 250);
    }
  } catch(e){}
})();
// Click a game server's connect address to copy the full ip:port.
document.addEventListener('click', function(ev){
  var el = ev.target.closest('.copy-addr'); if(!el) return;
  if(window.copyText) window.copyText(el.getAttribute('data-copy'), 'Copied ' + el.getAttribute('data-copy'));
});
function barColor(p){ if(p>=85) return '#f85149'; if(p>=60) return '#d29922'; return '#3fb950'; }
function fmtGB(b){ return (b/1073741824).toFixed(1)+' GB'; }  // NOPMD

var coresBuilt = 0;
function buildCores(n){
  var w = document.getElementById('cpu-cores'); w.innerHTML='';
  for(var i=0;i<n;i++){
    var r=document.createElement('div'); r.className='core-row';
    r.innerHTML='<span class="core-label">cpu'+i+'</span>'  // nosemgrep
      +'<span class="core-track"><span class="core-fill" id="core-fill-'+i+'"></span></span>'
      +'<span class="core-val" id="core-val-'+i+'">0%</span>';
    w.appendChild(r);
  }
  coresBuilt=n;
}
function pollLive(){
  fetch(MOUNT + '/api/remote/'+REMOTE_ID+'/live').then(r=>r.json()).then(d=>{
    if(d.error) return;
    var ov=d.cpu_overall||0;
    document.getElementById('cpu-overall-val').textContent=ov;
    var ob=document.getElementById('cpu-overall-bar'); ob.style.width=ov+'%'; ob.style.backgroundColor=barColor(ov);
    document.getElementById('cpu-cores-label').textContent=(d.core_count||(d.cpu_cores||[]).length)+' cores';
    var cores=d.cpu_cores||[];
    if(cores.length!==coresBuilt) buildCores(cores.length);
    cores.forEach(function(p,i){
      var f=document.getElementById('core-fill-'+i), v=document.getElementById('core-val-'+i);
      if(f){ f.style.width=p+'%'; f.style.backgroundColor=barColor(p); }
      if(v) v.textContent=p+'%';
    });
    var rp=d.ram_percent||0;
    document.getElementById('ram-val').textContent=rp;
    var rb=document.getElementById('ram-bar'); rb.style.width=rp+'%'; rb.style.backgroundColor=barColor(rp);
    document.getElementById('ram-detail').textContent=fmtGB(d.ram_used||0)+' / '+fmtGB(d.ram_total||0)+' used';
    var sp=d.swap_percent||0;
    document.getElementById('swap-val').textContent=sp;
    var sb=document.getElementById('swap-bar'); sb.style.width=sp+'%'; sb.style.backgroundColor=barColor(sp);
    document.getElementById('swap-detail').textContent=d.swap_total?(fmtGB(d.swap_used||0)+' / '+fmtGB(d.swap_total)+' used'):'No swap configured';
    var dp=d.disk_percent||0;
    document.getElementById('disk-val').textContent=dp;
    var db=document.getElementById('disk-bar'); db.style.width=dp+'%'; db.style.backgroundColor=barColor(dp);
    document.getElementById('disk-detail').textContent=d.disk_total?(fmtGB(d.disk_used||0)+' / '+fmtGB(d.disk_total)+' used'):'—';
  }).catch(function(){});
}
function checkUpdates(){
  var el=document.getElementById('update-info'); el.textContent='Checking…';
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/check-updates').then(r=>r.json())
    .then(d=>{
      var n=d.count||0, pkgs=d.packages||[];
      if(!n){ el.textContent='System is up to date.'; return; }
      var head='<div class="mb-1 text-secondary">'+n+' update'+(n===1?'':'s')+' available:</div>';
      var rows=pkgs.map(function(p){
        var ver = p.from ? (escapeHtml(p.from)+' → <span class="text-success">'+escapeHtml(p.version)+'</span>')
                         : escapeHtml(p.version||'');
        return '<div style="font-family:monospace;font-size:.72rem;line-height:1.5;">'
             + '<span class="text-info">'+escapeHtml(p.name)+'</span> '+ver+'</div>';
      }).join('');
      el.innerHTML=head+'<div style="max-height:200px;overflow:auto;">'+rows+'</div>';  // nosemgrep
    })
    .catch(()=>el.textContent='Check failed');
}
var _osuTimer=null, _osuStale=0;
function runUpdates(){
  confirmDialog({title:'Install updates', icon:'arrow-up-circle', confirmClass:'btn-primary', confirmLabel:'Install updates',
    bodyText:'Install all available updates on this host? You can watch it live in a popup; it runs '
      + 'unattended and answers prompts safely (keeps your config files, assumes yes), so it never '
      + 'gets stuck waiting.',
    onConfirm:_startOsUpdate});
}
function _startOsUpdate(){
  if(_osuTimer){ clearTimeout(_osuTimer); _osuTimer=null; }
  _osuStale=0;
  var logEl=document.getElementById('osu-log'), stEl=document.getElementById('osu-state'),
      spin=document.getElementById('osu-spin');
  if(logEl) logEl.textContent='';
  if(stEl){ stEl.className='small mb-2 text-secondary'; stEl.innerHTML='<i class="bi bi-hourglass-split"></i> Starting…'; }
  if(spin) spin.style.display='';
  var m=document.getElementById('os-update-modal');
  if(m && window.bootstrap) bootstrap.Modal.getOrCreateInstance(m).show();
  var info=document.getElementById('update-info'); if(info) info.textContent='Installing updates… (watch the popup)';
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/os-update/start',{method:'POST'}).then(function(r){return r.json();})
    .then(function(d){
      if(!d.success){ if(spin) spin.style.display='none';
        if(stEl){ stEl.className='small mb-2 text-danger'; stEl.textContent=d.message||'Couldn\'t start.'; } return; }
      _pollOsUpdate();
    }).catch(function(){ if(spin) spin.style.display='none';
      if(stEl){ stEl.className='small mb-2 text-danger'; stEl.textContent='Couldn\'t start the update.'; } });
}
function _pollOsUpdate(){
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/os-update/status').then(function(r){return r.json();})
    .then(function(d){
      var logEl=document.getElementById('osu-log'), stEl=document.getElementById('osu-state'),
          spin=document.getElementById('osu-spin');
      if(logEl){ var atBottom=logEl.scrollTop+logEl.clientHeight >= logEl.scrollHeight-30;
        logEl.textContent=d.log||'';                     // textContent: apt output is never HTML
        if(atBottom) logEl.scrollTop=logEl.scrollHeight; }
      if(d.done){
        if(spin) spin.style.display='none';
        var ok=(d.rc===0);
        if(stEl){ stEl.className='small mb-2 '+(ok?'text-success':'text-danger');
          stEl.innerHTML=ok?'<i class="bi bi-check-circle-fill"></i> Updates installed.'  // nosemgrep
                           :'<i class="bi bi-x-circle-fill"></i> Finished with errors (exit '+d.rc+') — see the log above.'; }
        var info=document.getElementById('update-info');
        if(info) info.innerHTML=ok?'<span class="text-success"><i class="bi bi-check-circle"></i> Updates installed — re-checking…</span>'
                                  :'<span class="text-danger">Update finished with errors — see the popup.</span>';
        // Re-check after a beat so the "installed" note is readable; a full-upgrade should now show 0.
        if(ok && typeof checkUpdates==='function') setTimeout(checkUpdates, 1500);
        if(window.rebootNagCheck){ if(IS_LOCAL && window.LOCAL_HOST_ID!=null) rebootNagCheck(window.LOCAL_HOST_ID,'the panel host');
                                   else if(!IS_LOCAL) rebootNagCheck(REMOTE_ID, REMOTE_NAME); }   // kernel update -> banner
        return;
      }
      _osuStale = d.running ? 0 : (_osuStale+1);
      if(_osuStale>=3){ if(spin) spin.style.display='none';
        if(stEl){ stEl.className='small mb-2 text-warning';
          stEl.innerHTML='<i class="bi bi-exclamation-triangle"></i> The update process ended without a completion marker — check the log.'; }
        return; }
      if(stEl && d.running) stEl.innerHTML='<i class="bi bi-hourglass-split"></i> Installing… (safe to close this popup — it keeps running)';
      _osuTimer=setTimeout(_pollOsUpdate, 1500);
    }).catch(function(){ _osuTimer=setTimeout(_pollOsUpdate, 3000); });
}
function rebootRemote(){
  // Check for players on ANY game server on this host first — a reboot disconnects them all.
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/players').then(r=>r.json()).then(function(d){
    var busy=(d&&d.busy)||[], total=(d&&d.total)||0;
    var base = IS_LOCAL ? 'Reboot the PANEL HOST now? The panel and all its game servers will go down briefly.'
                        : 'Reboot this server now? It will be briefly unreachable.';
    var q = base;
    if(total>0){
      var list = busy.map(function(b){ return b.name+' ('+b.players+')'; }).join(', ');
      q = '⚠ '+total+' player'+(total===1?' is':'s are')+' currently connected across '+busy.length+' server'+(busy.length===1?'':'s')+':\n  '+list
        + '\n\nRebooting will DISCONNECT all of them. '+base+'\n\nAre you sure?';
    }
    _confirmReboot(q);
  }).catch(function(){
    // Couldn't check — fall back to the plain confirm rather than blocking.
    var q = IS_LOCAL ? 'Reboot the PANEL HOST now? The panel and all its game servers will go down briefly.'
                     : 'Reboot this server now? It will be briefly unreachable.';
    _confirmReboot(q);
  });
}
function _confirmReboot(q){
  confirmDialog({title:'Reboot server', icon:'arrow-clockwise', confirmClass:'btn-warning', confirmLabel:'Reboot',
    bodyText:q, onConfirm:doRebootRemote});
}
function doRebootRemote(){
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/reboot',{method:'POST'}).then(r=>r.json())
    .then(d=>{ if(window.toast) toast(d.message||'Reboot requested','info'); }).catch(()=>{ if(window.toast) toast('Reboot failed','danger'); });
}
function rebootRemoteWhenEmpty(){
  // Schedule a reboot once every game server on this host is empty (reuses the shared banner flow).
  if (window.rebootNagWhenEmpty) window.rebootNagWhenEmpty(REMOTE_ID, IS_LOCAL ? 'the panel host' : REMOTE_NAME);
}
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
        msg.innerHTML = d.success
          ? '<span class="text-success"><i class="bi bi-check-circle-fill"></i> '+(d.message||'Enabled.')+'</span>'
          : '<span class="text-danger">'+(d.message||'Failed.')+'</span>';
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

// ── Backups (panel host only) ──
function bkFmtBytes(b){ b=b||0; if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(0)+' KB'; if(b<1073741824)return (b/1048576).toFixed(1)+' MB'; if(b<1099511627776)return (b/1073741824).toFixed(1)+' GB'; return (b/1099511627776).toFixed(2)+' TB'; }  // NOPMD
function bkAgo(epoch){ var s=Math.max(0,Math.floor(Date.now()/1000-epoch)); if(s<60)return 'just now'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
function bkMsg(t,cls){ var m=document.getElementById('bk-msg'); if(m){ m.textContent=t||''; m.className='small '+(cls||'text-secondary'); } }
function loadBackups(){
  fetch(MOUNT+'/api/panel/backups').then(r=>r.json()).then(function(d){
    var s=d.settings||{};
    var en=document.getElementById('bk-enabled'); if(en) en.checked = s.enabled!==false;
    var kp=document.getElementById('bk-keep'); if(kp && s.keep_days) kp.value = String(s.keep_days);
    var tb=document.getElementById('bk-tbody'); if(!tb) return;
    var rows='';
    (d.backups||[]).forEach(function(b){
      var when=new Date(b.created*1000).toLocaleString();
      var kind = b.kind==='daily'?'<span class="badge bg-secondary">daily</span>'
               : b.kind==='prerestore'?'<span class="badge bg-info text-dark">pre-restore</span>'
               : '<span class="badge bg-primary">manual</span>';
      rows += '<tr>'
        + '<td title="'+escapeHtml(when)+'">'+escapeHtml(bkAgo(b.created))+'</td>'
        + '<td>'+kind+'</td>'
        + '<td>'+bkFmtBytes(b.size)+'</td>'
        + '<td class="text-end text-nowrap">'
        + '<a class="btn btn-sm btn-outline-secondary py-0 px-1" href="'+MOUNT+'/api/panel/backup/download/'+encodeURIComponent(b.name)+'" title="Download"><i class="bi bi-download"></i></a> '
        + '<button class="btn btn-sm btn-outline-warning py-0 px-1" title="Restore"' + _da('restoreBackup', [b.name, '@self']) + '><i class="bi bi-arrow-counterclockwise"></i></button> '
        + '<button class="btn btn-sm btn-outline-danger py-0 px-1" title="Delete"' + _da('deleteBackup', [b.name, '@self']) + '><i class="bi bi-trash"></i></button>'
        + '</td></tr>';
    });
    if(!(d.backups||[]).length) rows='<tr><td colspan="4" class="text-secondary text-center py-3">No backups yet.</td></tr>';
    tb.innerHTML=rows;  // nosemgrep
    document.getElementById('bk-loading').style.display='none';
    document.getElementById('bk-table-wrap').style.display='';
    // ── Full (game server files) backup section ──
    var f=d.full||{};
    var autoOn=(f.interval_days||0)>0;
    var fen=document.getElementById('fb-auto-enabled'); if(fen) fen.checked=autoOn;
    var fi=document.getElementById('fb-interval');
    if(fi){ fi.value=String(autoOn?f.interval_days:7); fi.disabled=!autoOn; }
    var fk=document.getElementById('fb-keep'); if(fk) fk.value=String(f.keep||2);
    window._bkDisk=d.disk||{free:0,total:0,backup_bytes:0,est_cycle:0};
    window._bkMultiHost=!!d.multi_host;
    var fdk=document.getElementById('fb-disk');
    if(fdk){
      var dk=window._bkDisk;
      if(window._bkMultiHost){
        // Servers span multiple hosts — a single disk figure would be misleading, so show
        // each server's own host disk on its row below instead.
        fdk.innerHTML='<i class="bi bi-hdd"></i> Your servers are on more than one host — free disk is shown per server below.';
      } else if(dk.total>0){
        var pct=Math.round((dk.total-dk.free)/dk.total*100);
        fdk.innerHTML='<i class="bi bi-hdd"></i> Disk: <strong>'+bkFmtBytes(dk.free)+'</strong> free of '+bkFmtBytes(dk.total)  // nosemgrep
          +' ('+pct+'% used). Game backups currently use '+bkFmtBytes(dk.backup_bytes||0)+'.';
      } else { fdk.textContent=''; }
    }
    fbSummary();
    var fnow=document.getElementById('fb-now'); if(fnow) fnow.disabled = !!d.full_running;
    var fs=document.getElementById('fb-status');
    if(fs){ fs.textContent = d.full_running ? 'Running now…' : (f.last ? ('Last: '+bkAgo(f.last)+(f.summary?' — '+f.summary:'')) : 'Never run'); }
    var fg=document.getElementById('fb-games');
    if(fg){
      var gh='';
      (d.games||[]).forEach(function(g){
        var rows=(g.backups||[])
          // Skip a backup that's still being written — show it only once it's finished.
          .filter(function(b){ return !b.in_progress; })
          .map(function(b){
          return '<tr>'
            + '<td><div style="font-family:monospace;font-size:.72rem;word-break:break-all;">'+escapeHtml(b.name)+'</div>'
            +   '<div class="text-secondary" style="font-size:.68rem;">'+escapeHtml(bkAgo(b.created))+'</div></td>'
            + '<td>'+bkFmtBytes(b.size)+'</td>'
            + '<td class="text-end text-nowrap">'
            + '<a class="btn btn-sm btn-outline-secondary py-0 px-1" href="'+MOUNT+'/backup/game/'+g.id+'/download?name='+encodeURIComponent(b.name)+'" title="Download backup"><i class="bi bi-download"></i></a> '
            + '<button class="btn btn-sm btn-outline-danger py-0 px-1" data-gid="'+g.id+'" data-name="'+escapeHtml(b.name)+'"' + _da('deleteGameBackup', ['@self']) + ' title="Delete backup"><i class="bi bi-trash"></i></button>'
            + '</td></tr>';
        }).join('');
        var table = rows
          ? '<div class="table-responsive mt-1"><table class="table table-sm align-middle mb-0" style="font-size:.8rem;">'
            + '<thead><tr><th>Backup file</th><th>Size</th><th class="text-end">Actions</th></tr></thead>'
            + '<tbody>'+rows+'</tbody></table></div>'
          : '<div class="small text-secondary mt-1">no backups yet</div>';
        var st=g.status, stHtml='';
        if(st){
          if(st.running){ stHtml=' <span class="text-secondary"><i class="bi bi-arrow-repeat"></i> backing up…</span>'; }
          else if(st.busy){
            // Skipped because players were connected — offer a one-click force.
            stHtml=' <span class="text-warning"><i class="bi bi-people-fill"></i> '+escapeHtml(st.msg||'players online — skipped')+'</span>'
              +' <button class="btn btn-sm btn-outline-warning py-0 px-1 ms-1"' + _da('backupOneGame', [g.id, '@self', true]) + '>Back up anyway</button>';
          }
          else if(st.ok===true){ stHtml=' <span class="text-success">✓ '+escapeHtml(st.msg||'backed up')+'</span>'; }
          else if(st.ok===false){ stHtml=' <span class="text-danger">✗ '+escapeHtml(st.msg||'failed')+'</span>'; }
        }
        // Host label disambiguates same-named servers on different machines; per-server disk is
        // that server's OWN host, so the numbers/warnings are right even with multiple hosts.
        var hostHtml = g.host ? ' <span class="text-secondary small">· <i class="bi bi-hdd-network"></i> '+escapeHtml(g.host)+'</span>' : '';
        var dkHtml = '';
        if(g.disk && g.disk.total>0){
          dkHtml = '<div class="small text-secondary"><i class="bi bi-hdd"></i> '+escapeHtml(g.host||'host')+': '+bkFmtBytes(g.disk.free)+' free';
          var eb=g.est_backup||0, keep=(g.schedule&&g.schedule.keep)||2;
          if(eb>0){
            var proj=eb*keep;
            if(proj>g.disk.free) dkHtml += ' <span class="text-danger">— ~'+bkFmtBytes(proj)+' needed for '+keep+' backups, not enough space!</span>';
            else if(proj>g.disk.free*0.5) dkHtml += ' <span class="text-warning">— ~'+bkFmtBytes(proj)+' for '+keep+' backups (over half free)</span>';
          }
          dkHtml += '</div>';
        }
        gh += '<div class="mb-3 border-bottom pb-2">'
            + '<div class="d-flex justify-content-between align-items-center gap-2">'
            + '<span><strong>'+escapeHtml(g.name)+'</strong>'+hostHtml+'</span>'
            + '<button class="btn btn-sm btn-outline-success py-0 px-2" '+(st&&st.running?'disabled':'')
            + '' + _da('backupOneGame', [g.id, '@self']) + '><i class="bi bi-play-circle"></i> Back up now</button>'
            + '</div>'
            + gameSchedule(g)
            + dkHtml
            + (stHtml ? '<div class="small">'+stHtml+'</div>' : '')
            + table
            + '</div>';
      });
      fg.innerHTML = (d.games||[]).length ? gh : '<span class="text-secondary">No installed game servers.</span>';  // nosemgrep
    }
  }).catch(function(){ var l=document.getElementById('bk-loading'); if(l) l.innerHTML='<span class="text-danger">Could not load backups.</span>'; });
}
function createBackup(btn){
  if(btn){ btn.disabled=true; }
  bkMsg('Creating backup…','text-secondary');
  fetch(MOUNT+'/api/panel/backup',{method:'POST'}).then(r=>r.json()).then(function(d){
    bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
    if(btn) btn.disabled=false; loadBackups();
  }).catch(function(){ bkMsg('✗ Backup failed','text-danger'); if(btn) btn.disabled=false; });
}
function onFbAutoToggle(){
  var on=document.getElementById('fb-auto-enabled').checked;
  var fi=document.getElementById('fb-interval'); if(fi) fi.disabled=!on;
  saveBackupSettings();
}
function fbSummary(){
  var el=document.getElementById('fb-summary'); if(!el) return;
  var on=document.getElementById('fb-auto-enabled').checked;
  var keep=parseInt(document.getElementById('fb-keep').value,10)||1;
  var dk=window._bkDisk||{free:0,est_cycle:0};
  var cycle=dk.est_cycle||0;        // size of one full backup run (all servers)
  var free=dk.free||0;
  var projected=cycle*keep;         // rough space the retained backups will occupy
  function fmt(b){ return (typeof bkFmtBytes==='function')?bkFmtBytes(b):(b+' B'); }
  var parts=[];

  if(!on){
    parts.push('<i class="bi bi-info-circle"></i> Automatic backups are <strong>off</strong> — nothing runs on a schedule. '
      +'Use “Back up game servers now” for a one-off; '+(keep===1?'only the latest backup':'the '+keep+' most recent backups')
      +' per server '+(keep===1?'is':'are')+' kept.');
    el.innerHTML=parts.join('<br>'); return;  // nosemgrep
  }

  var days=parseInt(document.getElementById('fb-interval').value,10)||7;
  var every=(days===1?'every day':(days===7?'once a week':(days===14?'once every 2 weeks':'once a month')));
  var s='<i class="bi bi-info-circle"></i> By default, each server is backed up <strong>'+every+'</strong>. '
    +'The <strong>'+keep+'</strong> newest '+(keep===1?'backup is':'backups are')+' kept per server; older ones are deleted automatically. '
    +'(Override per server below.)';
  var multi = !!window._bkMultiHost;
  if(cycle>0 && !multi){ s+=' At the current size that\'s up to <strong>'+fmt(projected)+'</strong> of backups'+(free>0?' ('+fmt(free)+' free now)':'')+'.'; }
  parts.push(s);

  if(days===1){
    parts.push('<span class="text-warning"><i class="bi bi-exclamation-triangle"></i> Daily full backups of game files eat disk fast — keep a low “keep” count unless you have lots of free space.</span>');
  }
  if(multi){
    parts.push('<span class="text-secondary"><i class="bi bi-hdd-network"></i> Disk usage is shown per server below (they\'re on different hosts).</span>');
  }
  if(cycle>0 && free>0 && !multi){
    if(projected>free){
      parts.push('<span class="text-danger"><i class="bi bi-exclamation-octagon"></i> This needs more than your free disk ('+fmt(free)+') — backups will fail once it fills up.</span>');
    } else if(projected>free*0.5){
      parts.push('<span class="text-warning"><i class="bi bi-exclamation-triangle"></i> This would use over half your free disk.</span>');
    }
    var recKeep=Math.max(1, Math.floor(free*0.4/cycle));
    if(recKeep<keep){
      parts.push('<span class="text-secondary"><i class="bi bi-lightbulb"></i> Recommended: keep ≤ <strong>'+recKeep+'</strong> at ~'+fmt(cycle)+' per run (leaves comfortable headroom).</span>');
    }
  } else if(cycle===0){
    parts.push('<span class="text-secondary">Run a backup once and this will estimate the space each cycle uses and recommend a safe “keep”.</span>');
  }
  el.innerHTML=parts.join('<br>');  // nosemgrep
}
function saveBackupSettings(){
  var enabled=document.getElementById('bk-enabled').checked;
  var keep=parseInt(document.getElementById('bk-keep').value,10);
  // Automatic game backups off → send interval 0 (disabled); on → the chosen interval.
  var autoOn=document.getElementById('fb-auto-enabled').checked;
  var fi=autoOn ? (parseInt(document.getElementById('fb-interval').value,10)||7) : 0;
  var fk=parseInt(document.getElementById('fb-keep').value,10);
  fbSummary();
  fetch(MOUNT+'/api/panel/backup/settings',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({enabled:enabled,keep_days:keep,full_interval_days:fi,full_keep:fk})})
    .then(r=>r.json()).then(function(){ bkMsg('✓ Saved','text-success'); }).catch(function(){ bkMsg('✗ Could not save','text-danger'); });
}
function runFullBackup(btn){
  // First check who's online — if any server has players, ask before disconnecting them.
  if(btn){ btn.disabled=true; }
  bkMsg('Checking for players…','text-secondary');
  fetch(MOUNT+'/api/panel/backup/full/precheck').then(r=>r.json()).then(function(d){
    if(btn) btn.disabled=false;
    var busy=(d&&d.busy)||[];
    if(!busy.length){
      bkMsg('','');
      confirmDialog({title:'Back up all servers', icon:'archive', confirmClass:'btn-primary', confirmLabel:'Back up all',
        bodyText:'Back up all installed game servers now?\n\nThis runs LinuxGSM\'s backup on each server — any that are running will be briefly STOPPED and restarted for their backup (a short outage each). It can take a while and use disk space.',
        onConfirm:function(){ fbStart(''); }});
      return;
    }
    fbPlayersDialog(busy);
  }).catch(function(){ if(btn) btn.disabled=false; bkMsg('✗ Could not check players','text-danger'); });
}
function fbStart(mode){
  bkMsg('Starting full backup…','text-secondary');
  fetch(MOUNT+'/api/panel/backup/full',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode})})
    .then(r=>r.json()).then(function(d){
      bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
      [4000,15000,45000,90000,150000].forEach(function(ms){ setTimeout(loadBackups, ms); });   // refresh as it runs
    }).catch(function(){ bkMsg('✗ Could not start','text-danger'); });
}
function fbPlayersDialog(busy){
  var total=busy.reduce(function(s,b){return s+(b.players||0);},0);
  var list=busy.map(function(b){return escapeHtml(b.name)+' ('+b.players+')';}).join(', ');
  var ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1080;display:flex;align-items:center;justify-content:center;padding:1rem;';
  ov.innerHTML='<div class="card" style="max-width:540px;width:100%;">'  // nosemgrep
    +'<div class="card-header"><i class="bi bi-people-fill"></i> Players are online</div>'
    +'<div class="card-body">'
    +'<p class="mb-2"><strong>'+total+'</strong> player'+(total===1?' is':'s are')+' connected to <strong>'+busy.length+'</strong> server'+(busy.length===1?'':'s')+': '+list+'.</p>'
    +'<p class="small text-secondary mb-3">A backup briefly stops each server — this is about the busy ones.</p>'
    +'<div class="d-flex flex-column gap-2">'
    +'<button class="btn btn-warning" id="fbd-now"><i class="bi bi-play-circle"></i> Back up now (disconnects '+total+' player'+(total===1?'':'s')+')</button>'
    +'<button class="btn btn-success" id="fbd-wait"><i class="bi bi-hourglass-split"></i> Wait until they\'re empty, then back up</button>'
    +'<button class="btn btn-outline-secondary" id="fbd-cancel">Cancel</button>'
    +'</div></div></div>';
  document.body.appendChild(ov);
  function close(){ ov.remove(); }
  ov.querySelector('#fbd-now').onclick=function(){ close(); fbStart('now'); };
  ov.querySelector('#fbd-wait').onclick=function(){ close(); fbStart('wait'); };
  ov.querySelector('#fbd-cancel').onclick=function(){ close(); bkMsg('',''); };
  ov.addEventListener('click',function(e){ if(e.target===ov){ close(); bkMsg('',''); } });
}
function backupOneGame(id,btn,force){
  var msg = force
    ? 'Back up NOW and disconnect the players who are currently on?\n\nThe server will be briefly STOPPED and restarted for the backup — anyone playing will be kicked.'
    : 'Back up this game server now?\n\nLinuxGSM archives its files into ~/lgsm/backup. If players are on, the backup will WAIT (it won\'t kick them). If the server is empty it will be briefly STOPPED and restarted for the backup, and the archive can be large.';
  confirmDialog({title:'Back up game server', icon:'archive', confirmClass: force?'btn-warning':'btn-primary', confirmLabel:'Back up',
    bodyText: msg, onConfirm:function(){ _backupOneGame(id, btn, force); }});
}
function _backupOneGame(id,btn,force){
  // Immediate feedback right where the user clicked: spinner on the button.
  var orig = btn ? btn.innerHTML : '';
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Backing up…'; }
  function resetBtn(){ if(btn){ btn.disabled=false; btn.innerHTML=orig || '<i class="bi bi-play-circle"></i> Back up now'; } }  // nosemgrep
  if(window.toast) toast('Starting backup…','info');
  bkMsg('Starting backup…','text-secondary');
  fetch(MOUNT+'/api/panel/backup/game/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({force:!!force})}).then(r=>r.json()).then(function(d){  // nosemgrep
    bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
    // Floating toast so the result is visible even when scrolled down to this server's row.
    if(window.toast) toast((d.success?'✓ ':'✗ ')+(d.message||(d.success?'Backup started':'Could not start backup')), d.success?'success':'danger');
    if(!d.success){ resetBtn(); return; }
    // Refresh soon (so the row's "backing up…" status appears), then keep checking as it runs.
    [600,3000,8000,20000,40000,70000,120000].forEach(function(ms){ setTimeout(loadBackups, ms); });
  }).catch(function(){ bkMsg('✗ Could not start','text-danger'); if(window.toast) toast('✗ Could not start backup — connection error','danger'); resetBtn(); });
}
function schedNote(sc){
  var iv=sc.interval_days, kp=sc.keep;
  var base=(sc.interval_set||sc.keep_set) ? 'Custom — ' : 'Using default — ';
  if(iv<=0) return base+'no automatic backups.';
  var every=(iv===1?'daily':(iv===7?'weekly':(iv===14?'every 2 weeks':(iv===30?'monthly':'every '+iv+' days'))));
  var nextTxt='';
  if(sc.last){ var d=Math.round((sc.last+iv*86400-Date.now()/1000)/86400); nextTxt=' · next '+(d<=0?'due now':'in ~'+d+'d'); }
  return base+every+', keep '+kp+nextTxt+'.';
}
function gameSchedule(g){
  var sc=g.schedule||{interval_days:0,keep:2,interval_set:false,keep_set:false,last:0};
  var ivVal=sc.interval_set?String(sc.interval_days):'default';
  var kpVal=sc.keep_set?String(sc.keep):'default';
  function opt(v,label,cur){ return '<option value="'+v+'"'+(String(v)===cur?' selected':'')+'>'+label+'</option>'; }
  var ivSel='<select class="form-select form-select-sm py-0" style="width:auto;" id="gsi-'+g.id+'"' + _da('setGameSchedule', [g.id], 'change') + '>'
    +opt('default','Default',ivVal)+opt('0','Off',ivVal)+opt('1','Daily',ivVal)+opt('7','Weekly',ivVal)+opt('14','Every 2 weeks',ivVal)+opt('30','Monthly',ivVal)+'</select>';
  var kpSel='<select class="form-select form-select-sm py-0" style="width:auto;" id="gsk-'+g.id+'"' + _da('setGameSchedule', [g.id], 'change') + '>'
    +opt('default','Default',kpVal)+opt('1','1',kpVal)+opt('2','2',kpVal)+opt('3','3',kpVal)+opt('5','5',kpVal)+opt('7','7',kpVal)+opt('14','14',kpVal)+opt('30','30',kpVal)+'</select>';
  return '<div class="d-flex align-items-center gap-2 flex-wrap small my-1">'
    +'<span class="text-secondary"><i class="bi bi-calendar-event"></i> Schedule:</span>'+ivSel
    +'<span class="text-secondary">Keep</span>'+kpSel
    +'<span class="text-secondary" id="gsn-'+g.id+'">'+schedNote(sc)+'</span></div>';
}
function setGameSchedule(id){
  var iv=document.getElementById('gsi-'+id).value, kp=document.getElementById('gsk-'+id).value;
  bkMsg('Saving schedule…','text-secondary');
  fetch(MOUNT+'/api/panel/backup/game/'+id+'/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interval:iv,keep:kp})})
    .then(r=>r.json()).then(function(d){
      bkMsg(d.success?'✓ Schedule saved':'✗ Save failed', d.success?'text-success':'text-danger');
      if(d.success&&d.schedule){ var n=document.getElementById('gsn-'+id); if(n) n.innerHTML=schedNote(d.schedule); }  // nosemgrep
    }).catch(function(){ bkMsg('✗ Could not save schedule','text-danger'); });
}
function deleteGameBackup(btn){
  var name=btn.getAttribute('data-name'), gid=btn.getAttribute('data-gid');
  confirmDialog({title:'Delete backup', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Delete',
    bodyText:'Delete this game-server backup?\n\n'+name,
    onConfirm:function(){
      btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span>';
      bkMsg('Deleting…','text-secondary');
      fetch(MOUNT+'/api/panel/backup/game/'+gid+'/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})})
        .then(r=>r.json()).then(function(d){
          bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
          if(window.toast) toast((d.success?'✓ ':'✗ ')+(d.message||(d.success?'Backup deleted':'Delete failed')), d.success?'success':'danger');
          loadBackups();
        }).catch(function(){ bkMsg('✗ Delete failed','text-danger'); if(window.toast) toast('✗ Delete failed — connection error','danger'); btn.disabled=false; btn.innerHTML='<i class="bi bi-trash"></i>'; });
    }});
}
function deleteBackup(name,btn){
  confirmDialog({title:'Delete backup', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Delete',
    bodyText:'Delete this backup?\n\n'+name,
    onConfirm:function(){
      if(btn) btn.disabled=true;
      fetch(MOUNT+'/api/panel/backup/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})})
        .then(r=>r.json()).then(function(d){ bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger'); loadBackups(); })
        .catch(function(){ bkMsg('✗ Delete failed','text-danger'); if(btn) btn.disabled=false; });
    }});
}
function restoreBackup(name,btn){
  confirmDialog({title:'Restore backup', icon:'arrow-counterclockwise', confirmClass:'btn-danger', confirmLabel:'Restore',
    bodyText:'Restore this backup?\n\n'+name+'\n\nThis OVERWRITES the panel\'s current database, settings and keys, then restarts the panel. A pre-restore safety backup is taken first.',
    onConfirm:function(){
      if(btn) btn.disabled=true;
      bkMsg('Restoring…','text-secondary');
      fetch(MOUNT+'/api/panel/backup/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})})
        .then(r=>r.json()).then(function(d){
          bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
          if(d.success){ setTimeout(function(){ location.reload(); }, 8000); } else if(btn){ btn.disabled=false; }
        })
        .catch(function(){ bkMsg('The panel is restarting — reconnect in a moment.','text-warning'); });
    }});
}

// Uninstall a game server from the list: in-app confirm + type-the-username gate, then submit the
// form (a full POST — this admin page reloads to show the server gone). Delegated so it survives
// any list re-render.
document.addEventListener('click', function(e){
  var b = e.target.closest && e.target.closest('.uninstall-trigger');
  if(!b) return;
  var form = b.closest('form'); if(!form) return;
  var name = form.getAttribute('data-server-name') || '';
  var short = form.getAttribute('data-server-short') || '';
  confirmDialog({
    title:'Uninstall server', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Uninstall',
    body:'Uninstall <strong>'+escapeHtml(name)+'</strong>? This permanently deletes the server, all its files, AND every backup it has — this cannot be undone.',
    requireText: short,
    requireLabel:'Type the server’s username ('+short+') to confirm:',
    onConfirm:function(){ form.submit(); }
  });
});

loadSshStatus();                     // public-SSH controls now exist on both local + remote (no-ops if absent)
if(IS_LOCAL){ checkPanelUpdate(false); loadPanelBranches(); loadIntegrity(); loadDbStats(); loadAutoUpd(); loadBackups(); } // panel-only cards
pollLive();
pollWhenVisible(pollLive, 2000);

// ── Discover + import existing LinuxGSM servers on this host ──────────
function scanExisting(){
  var btn=document.getElementById('disc-scan-btn'), out=document.getElementById('disc-result');
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Scanning…'; }
  if(out) out.innerHTML='<span class="text-secondary small"><i class="bi bi-hourglass-split"></i> Scanning every user account on this host…</span>';
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/discover').then(function(r){return r.json();}).then(function(d){
    if(!out) return;
    if(d.error){ out.innerHTML='<span class="text-danger small">'+escapeHtml(d.error)+'</span>'; return; }  // nosemgrep
    var s=d.servers||[];
    if(!s.length){ out.innerHTML='<span class="text-secondary small"><i class="bi bi-check2"></i> No new LinuxGSM servers found — anything already in the panel is skipped.</span>'; return; }
    var rows=s.map(function(g){
      return '<tr>'
        +'<td><input type="checkbox" class="form-check-input disc-chk" checked data-user="'+escapeHtml(g.user)+'" data-game="'+escapeHtml(g.game_type)+'" data-port="'+(g.port||0)+'" data-autostart="'+(g.autostart?1:0)+'"></td>'
        +'<td class="font-monospace">'+escapeHtml(g.user)+(g.autostart?' <span class="badge bg-success" style="font-size:.58rem;">autostart</span>':'')+'</td>'
        +'<td>'+escapeHtml(g.game_name||g.game_type)+'</td>'
        +'<td>'+(g.port||'—')+'</td>'
        +'<td>'+(g.backups||0)+'</td>'
        +'<td>'+(g.mods||0)+'</td>'
        +'<td>'+(g.cron||0)+'</td></tr>';
    }).join('');
    out.innerHTML='<div class="table-responsive"><table class="table table-sm align-middle mb-2">'  // nosemgrep
      +'<thead><tr><th style="width:1%"><input type="checkbox" class="form-check-input" checked' + _da('discToggleAll', ['@self']) + ' aria-label="Select all"></th><th>User</th><th>Game</th><th>Port</th><th title="LinuxGSM backups on disk">Backups</th><th title="Installed mods">Mods</th><th title="Cron entries for this user">Cron</th></tr></thead>'
      +'<tbody>'+rows+'</tbody></table></div>'
      +'<button class="btn btn-sm btn-primary"' + _da('importExisting', ['@self']) + '><i class="bi bi-plus-circle"></i> Import selected</button> <span id="disc-msg" class="small ms-2"></span>';
  }).catch(function(){ if(out) out.innerHTML='<span class="text-danger small">Scan failed.</span>'; })
  .finally(function(){ if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-search"></i> Scan'; } });
}
function discToggleAll(cb){ document.querySelectorAll('.disc-chk').forEach(function(c){ c.checked=cb.checked; }); }
function importExisting(btn){
  var picks=[], msg=document.getElementById('disc-msg');
  document.querySelectorAll('.disc-chk:checked').forEach(function(c){
    picks.push({user:c.getAttribute('data-user'), game_type:c.getAttribute('data-game'),
                port:parseInt(c.getAttribute('data-port'),10)||0,
                autostart:c.getAttribute('data-autostart')==='1'});
  });
  if(!picks.length){ if(msg) msg.innerHTML='<span class="text-warning">Select at least one.</span>'; return; }
  btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Importing…';
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/import',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({servers:picks})})
    .then(function(r){return r.json();}).then(function(d){
      var n=(d.added||[]).length;
      if(n){ window.toast('Imported '+n+' server'+(n===1?'':'s')+'.', 'success');
             if(msg) msg.innerHTML='<span class="text-success">Imported '+n+' — see the Game Servers list.</span>';  // nosemgrep
             btn.disabled=false; btn.innerHTML='<i class="bi bi-plus-circle"></i> Import selected';
             window.refreshSection('#host-servers-card'); }   // show the new rows in place, no reload
      else { if(msg) msg.innerHTML='<span class="text-danger">'+escapeHtml(d.message||'Nothing imported.')+'</span>';  // nosemgrep
             btn.disabled=false; btn.innerHTML='<i class="bi bi-plus-circle"></i> Import selected'; }
    }).catch(function(){ if(msg) msg.innerHTML='<span class="text-danger">Import failed.</span>';
             btn.disabled=false; btn.innerHTML='<i class="bi bi-plus-circle"></i> Import selected'; });
}
