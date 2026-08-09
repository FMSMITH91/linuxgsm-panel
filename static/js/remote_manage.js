// tab switching and the Security tab (fail2ban, events, logs)
// Split out of one 86KB file; these load in order and behave as one script.
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
