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
// True once the Auto-block toggle shows the host's REAL state. The toggle is rendered unchecked and
// repainted only when /top-ips answers, which comes after several SSH reads (25 s and more on a
// slow host) — and saveThreshold posts the toggle's state back as `enabled`. Saving before that
// answer switched auto-block OFF for the host while the toast said it was blocking at N+.
var _autoblockKnown = false;
function loadSecurity(){ loadSecurityBans(); loadSecurityTopIps(); loadSecurityEvents(); }
function loadSecurityTopIps(){
  var el=document.getElementById('sec-top'); if(!el) return;
  fetch(secBase()+'/top-ips').then(function(r){return r.json();}).then(function(d){
    // Only repaint a control from a value the payload ACTUALLY CARRIED. This was
    // `tog.checked = !!(d && d.autoblock)`, and the error payload has no `autoblock` key — so a
    // failed read showed the Auto-block toggle OFF. saveThreshold then reads that toggle back
    // ("preserve the on/off state"), which turned one failed read plus one Save into
    // auto-blocking being persistently disabled on a host that had it on.
    var tog=document.getElementById('sec-autoblock');
    if(tog && d && 'autoblock' in d){ tog.checked=!!d.autoblock; _autoblockKnown=true; }
    var th=document.getElementById('sec-threshold');
    if(th && d && d.threshold!=null) th.value=d.threshold;
    if(d && 'whitelist' in d) renderWhitelist(d.whitelist||[]);
    var ips=(d&&d.ips)||[];
    // "nothing to report" and "the panel could not read the log" are different answers, and the
    // second one must not read as a clean bill of health on a SECURITY card.
    if(d && (d.error || d.unreadable)){
      el.innerHTML='<div class="small text-danger">'
        +'Could not read this fail2ban log, so recent offenders are unknown.'
        +'</div>';  // nosemgrep - fixed string, no interpolation
      return;
    }
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
  // The on/off state rides along (the endpoint sets both), so it has to be the host's real one:
  // an unpainted toggle reads OFF whatever the host has. Refuse until it has been read.
  if(!_autoblockKnown){ if(window.toast) toast('The auto-block settings are still loading. Save again once they show.','info'); return; }
  var on=!!(document.getElementById('sec-autoblock')||{}).checked;   // preserve the on/off state
  if(btn) btn.disabled=true;
  fetch(secBase()+'/autoblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:on,threshold:v})})
    .then(function(r){return r.json();}).then(function(d){
      if(btn) btn.disabled=false;
      if(window.toast) toast.apply(null, thresholdSaveToast(d, v));
      setTimeout(loadSecurityTopIps, on?2500:300);
    }).catch(function(){ if(btn) btn.disabled=false; if(window.toast) toast('Couldn\'t save the threshold','danger'); });
}
// [message, level] for what the endpoint ACTUALLY did. It answered "Threshold saved" whatever
// happened: the threshold is install-wide, so for anyone but a superadmin the endpoint ignores it
// and still succeeds — and the saved state includes auto-block being on or off for this host.
function thresholdSaveToast(d, asked){
  if(!d || !d.success) return [(d && d.message) || 'Couldn\'t save the threshold', 'danger'];
  var t = Number(d.threshold);
  if(t !== asked) return ['Threshold unchanged at '+t+'+ attempts / 7 days — it applies to every host, so only a superadmin can change it.', 'warning'];
  if(!d.enabled) return ['Threshold saved at '+t+'+ attempts / 7 days — auto-block is off for this host.', 'info'];
  return ['Threshold saved — auto-blocking IPs with '+t+'+ attempts / 7 days.', 'success'];
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
      // A refusal (403 for anyone but a superadmin) has no whitelist in it: rendering `[]` painted
      // "Nothing whitelisted" and the toast said removed, while the address stayed exempt from
      // every ban and auto-block on every host.
      if(!d || !d.success){ if(window.toast) toast((d && d.message)||'Could not remove it','danger'); return; }
      if('whitelist' in d) renderWhitelist(d.whitelist||[]);
      if(window.toast) toast((d.removed||ip)+' removed from the whitelist','info');
    }).catch(function(){ if(window.toast) toast('Could not remove it','danger'); });
}
function loadSecurityBans(){
  var el=document.getElementById('sec-bans'); if(!el) return;
  fetch(secBase()+'/bans').then(function(r){return r.json();}).then(function(d){
    // "could not read" comes FIRST, because both answers below are reassuring and only one of
    // them is a fact. An unreadable host, or one where fail2ban is installed but stopped, used to
    // render as "No fail2ban jails found." — the same thing a healthy host with nothing configured
    // shows.
    // `d.error` belongs in the same branch: both /bans routes answer a raised read with
    // 200 {installed:false, jails:[], error:"…"}. installed:false there is the route's FALLBACK
    // SHAPE, not a measurement, so a host whose SSH session was refused was told, on the page
    // whose job is to say whether it is protected, that it has no brute-force protection
    // installed. The response was already carrying the word that made it honest.
    if(d && (d.unreadable || d.error)){
      el.innerHTML='<div class="small text-danger">'
        +'Could not read fail2ban on this host, so its jails are unknown.'
        +'</div>';  // nosemgrep - fixed string, no interpolation
      return;
    }
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
    // A read that FAILED answers {text:"", error:...}; "(log is empty)" there told an admin an
    // unreachable host had no SSH or ban activity, on the card that exists to show attacks.
    if(!d || d.error){ el.textContent='Could not read the log.'; return; }
    el.textContent=d.text||'(log is empty)'; el.scrollTop=el.scrollHeight;   // textContent: raw log is never HTML
    if(el.scrollIntoView) el.scrollIntoView({behavior:'smooth',block:'nearest'});
  }).catch(function(){ el.textContent='Could not read the log.'; });
}

// "update available" badge links to #updates, so a hash pointing at a card opens its tab and
// scrolls to it. ──
(function(){
  var nav = document.getElementById('mtab-nav'); if(!nav) return;
  var TABS = ['overview','controls','maintenance','security'];
  // Which tab holds a given card is read from the DOM, not from a list kept by hand. There WAS a
  // hand-kept map here, naming four ids; every other card on the page — the whole Security tab
  // among them — fell through it to show('overview'), so a link straight to one opened the wrong
  // tab and scrolled to an element that was display:none. That is how the command palette's
  // Banned IPs / Top offenders / Recent security events entries shipped landing on nothing.
  // The cards already carry data-mtab, so asking the element which section it is in cannot drift
  // the way a second copy of that mapping did.
  function tabOf(id){
    if(!id) return null;
    var el = document.getElementById(id); if(!el) return null;
    var sec = el.closest('[data-mtab]');   // the card itself, or the card an inner div lives in
    return sec ? sec.getAttribute('data-mtab') : null;
  }
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
  function openHash(fallback){
    var h = (location.hash || '').replace('#','');
    // Only a tab this page actually offers: the panel host's Security tab is not rendered for a
    // non-superadmin, and #security would otherwise open an empty tab and fire its 403 reads.
    if (TABS.indexOf(h) >= 0 && nav.querySelector('[data-mtab-btn="' + h + '"]')) { show(h); return; }
    var tab = tabOf(h);
    if (tab) {
      show(tab);
      // AFTER show(): until its tab is open the card is display:none, and scrolling to a hidden
      // element does nothing at all — silently, which is what made this hard to notice.
      var el = document.getElementById(h); if(el) el.scrollIntoView();
      return;
    }
    if (fallback) { show('overview'); }
  }
  openHash(true);
  // Following a #card link while ALREADY on this page changes the hash without reloading, so the
  // banner's link would otherwise do nothing for the host you happen to be looking at.
  window.addEventListener('hashchange', function(){ openHash(false); });
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
    // A read that failed used to arrive as zeros and render an idle-looking host. The route
    // refuses to publish those now, so `error` is what a dead host looks like here — and the
    // card has to SAY so: silently leaving the last good numbers on screen is a live display
    // of a reading nobody took.
    var stale = document.getElementById('live-stale');
    if(d.error){
      if(stale){ stale.textContent = d.unreachable
        ? 'Live figures are paused — the host did not answer. The numbers below are the last reading.'
        : 'Live figures are paused — the last read failed.'; stale.style.display=''; }
      return;
    }
    if(stale){ stale.textContent=''; stale.style.display='none'; }
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
function isSecurityPkg(p){ return ((p.suite||'').indexOf('-security') >= 0); }
// Render one check result into the OS Updates card. `note` is the provenance line — a forced check
// says nothing (you just ran it), a cached one says when it was last asked — so the card can show
// what the host has waiting on page load WITHOUT making the load wait on `apt update`.
function renderUpdates(d, note){
  var el=document.getElementById('update-info'); if(!el) return;
  var n=d.count||0, pkgs=d.packages||[];
  var sec=pkgs.filter(isSecurityPkg).length;
  var head=(n ? '<div class="mb-1"><span class="text-warning"><i class="bi bi-exclamation-triangle-fill"></i> '
                + n + ' update' + (n===1?'':'s') + ' available</span>'
                + (sec ? ' <span class="badge bg-danger" style="font-weight:normal;">'+sec+' security</span>' : '')
                + '</div>'
              : '<div class="text-success"><i class="bi bi-check-circle"></i> System is up to date.</div>')
         + (note ? '<div class="text-secondary" style="font-size:.68rem;">'+escapeHtml(note)+'</div>' : '');
  var rows=!n ? '' : '<div style="max-height:200px;overflow:auto;">' + pkgs.map(function(p){
    var ver = p.from ? (escapeHtml(p.from)+' → <span class="text-success">'+escapeHtml(p.version)+'</span>')
                     : escapeHtml(p.version||'');
    return '<div style="font-family:monospace;font-size:.72rem;line-height:1.5;">'
         + '<span class="'+(isSecurityPkg(p)?'text-danger':'text-info')+'">'
         + escapeHtml(p.name)+'</span> '+ver+'</div>';
  }).join('') + '</div>';
  el.innerHTML=head+rows;   // nosemgrep — head/rows are composed above from escapeHtml()'d values
  // ...and the button follows the count. Offering "Install updates" on a host the panel has just
  // reported as up to date is an action whose only possible outcome is a progress modal that says
  // "0 upgraded, 0 newly installed" — the control should carry what the card already knows.
  setInstallUpdatesState(n > 0 ? 'available' : 'uptodate');
}
// available → enabled. uptodate → disabled, saying why. unknown → enabled, because a check that
// failed is not evidence there is nothing to do, and forcing the upgrade by hand is a legitimate
// way out of exactly that state.
function setInstallUpdatesState(state){
  var b=document.getElementById('btn-install-updates'); if(!b) return;
  b.disabled = (state === 'uptodate');
  b.title = state === 'uptodate' ? 'Nothing to install — the system is up to date.'
          : state === 'unknown'  ? "The last check didn't complete — you can still run the upgrade."
          : 'Install the updates found by the last check.';
}
// Force a fresh check (the Check button): runs `apt update` on the host, so it's the slow path.
var _updatesAsked = false;   // a forced check outranks the cached fill, whichever lands first
function checkUpdates(){
  var el=document.getElementById('update-info'); el.textContent='Checking…';
  _updatesAsked = true;
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/check-updates').then(r=>r.json())
    .then(d=>{
      // A check that FAILED returns an empty list, exactly like a clean host — saying "up to date"
      // there would report a state nobody actually managed to read. Only a positive `ok` is a
      // reading: a host the panel could not reach answers {success:false, unreachable:true} with
      // no `ok` key at all, and `d.ok===false` let that through to a green "System is up to date."
      // with Install disabled as "Nothing to install".
      if(d.ok!==true){
        if(d.unreachable) el.innerHTML='<span class="text-warning"><i class="bi bi-exclamation-triangle"></i> '  // nosemgrep
          + "Couldn't reach the host — its update state is unknown.</span>";
        else el.innerHTML='<span class="text-warning"><i class="bi bi-exclamation-triangle"></i> '  // nosemgrep
          + "Couldn't read the package list — apt may be busy. Try again in a minute.</span>";
        setInstallUpdatesState('unknown'); return; }
      renderUpdates(d, '');
      if(window.osUpdatesNagCheck) window.osUpdatesNagCheck();   // the banner reflects this too
    })
    .catch(function(){ el.textContent='Check failed'; setInstallUpdatesState('unknown'); });
}
// Page load: show what the last check found, from the panel's own memory. No apt, no SSH — the
// daily sweep already asked, and an empty card until you press Check is not an answer.
(function(){
  if(!document.getElementById('update-info')) return;
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/updates-cached').then(function(r){ return r.json(); })
    .then(function(d){
      var el=document.getElementById('update-info'); if(!el || _updatesAsked) return;
      if(!d || !d.known){
        el.innerHTML='<span class="text-secondary">Not checked yet — press Check.</span>';  // nosemgrep
        // Never checked is not "up to date" — leave the button usable rather than disabling it
        // on the strength of a reading nobody has taken.
        setInstallUpdatesState('unknown');
        return;
      }
      renderUpdates(d, 'Last checked '+window.agoText(d.at));
    }).catch(function(){});
})();
var _osuTimer=null, _osuStale=0, _osuMiss=0;
// A status poll that did not READ the host: the route's exception answer (`error`), an unread log
// (`unread`: Tailscale SSH and the panel host return "" rather than raising), or a `done` with no
// sentinel exit code behind it. None of them is the update finishing or stopping.
function _osuPollUnread(d){
  return !!(d.error || d.unread || (d.done && typeof d.rc !== 'number'));
}
function runUpdates(){
  confirmDialog({title:'Install updates', icon:'arrow-up-circle', confirmClass:'btn-primary', confirmLabel:'Install updates',
    bodyText:'Install all available updates on this host? You can watch it live in a popup; it runs '
      + 'unattended and answers prompts safely (keeps your config files, assumes yes), so it never '
      + 'gets stuck waiting.',
    onConfirm:_startOsUpdate});
}
function _startOsUpdate(){
  if(_osuTimer){ clearTimeout(_osuTimer); _osuTimer=null; }
  _osuStale=0; _osuMiss=0;
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
      // One failed read ended the watch: the route's fallback says done:true, rc:null, log:"", so
      // the popup wiped apt's output, announced "Finished with errors (exit null)", offered the
      // reboot banner and stopped polling while dpkg was still unpacking (tailscaled restarting
      // mid-upgrade is enough). An unread poll keeps the last log, is not counted towards the
      // "ended without a marker" verdict, and polls again; only a long silence ends the watch.
      if(_osuPollUnread(d)){
        _osuMiss++;
        if(_osuMiss>=40){ if(spin) spin.style.display='none';
          if(stEl){ stEl.className='small mb-2 text-warning';
            stEl.textContent='Lost contact with the host for two minutes. The update may still be running — reopen this later to check.'; }
          return; }
        if(stEl){ stEl.className='small mb-2 text-warning';
          stEl.textContent='Lost contact with the host — still watching…'; }
        _osuTimer=setTimeout(_pollOsUpdate, 3000);
        return;
      }
      _osuMiss=0;
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
      // Only a definite "apt is not running" counts towards giving up; an unanswered probe
      // (running null) is neither.
      _osuStale = d.running === true ? 0 : d.running === false ? (_osuStale+1) : _osuStale;
      if(_osuStale>=3){ if(spin) spin.style.display='none';
        if(stEl){ stEl.className='small mb-2 text-warning';
          stEl.innerHTML='<i class="bi bi-exclamation-triangle"></i> The update process ended without a completion marker — check the log.'; }
        return; }
      if(stEl && d.running){ stEl.className='small mb-2 text-secondary';
        stEl.innerHTML='<i class="bi bi-hourglass-split"></i> Installing… (safe to close this popup — it keeps running)'; }
      _osuTimer=setTimeout(_pollOsUpdate, 1500);
    }).catch(function(){ _osuTimer=setTimeout(_pollOsUpdate, 3000); });
}
function rebootRemote(){
  // Check for players on ANY game server on this host first — a reboot disconnects them all.
  fetch(MOUNT+'/api/remote/'+REMOTE_ID+'/players').then(r=>r.json()).then(function(d){
    var busy=(d&&d.busy)||[], total=(d&&d.total)||0, unknown=(d&&d.unknown)||[];
    var base = IS_LOCAL ? 'Reboot the PANEL HOST now? The panel and all its game servers will go down briefly.'
                        : 'Reboot this server now? It will be briefly unreachable.';
    var q = base;
    if(total>0){
      var list = busy.map(function(b){ return b.name+' ('+b.players+')'; }).join(', ');
      q = '⚠ '+total+' player'+(total===1?' is':'s are')+' currently connected across '+busy.length+' server'+(busy.length===1?'':'s')+':\n  '+list
        + '\n\nRebooting will DISCONNECT all of them. '+base+'\n\nAre you sure?';
    }
    // A server the panel could not read is NOT an empty one. Saying nothing about it is how a
    // reboot disconnects players it reported as absent — the count came back unknown, and the
    // dialog turned that into silence.
    if(unknown.length){
      var un = unknown.map(function(u){ return u.name + (u.queryable ? '' : ' (not queryable)'); }).join(', ');
      q = (total>0 ? q.replace('\n\nAre you sure?','') : q)
        + '\n\n⚠ The player count could not be read for '+unknown.length+' running server'
        + (unknown.length===1?'':'s')+': '+un
        + '\nAnyone on '+(unknown.length===1?'it':'them')+' will be disconnected without warning.'
        + '\n\nAre you sure?';
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
