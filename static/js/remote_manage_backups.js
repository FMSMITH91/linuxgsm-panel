// backups, and discovering/importing existing LinuxGSM servers
// Split out of one 86KB file; these load in order and behave as one script.
// ── Backups (panel host only) ──
function bkFmtBytes(b){ b=b||0; if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(0)+' KB'; if(b<1073741824)return (b/1048576).toFixed(1)+' MB'; if(b<1099511627776)return (b/1073741824).toFixed(1)+' GB'; return (b/1099511627776).toFixed(2)+' TB'; }  // NOPMD
function bkAgo(epoch){ return window.agoText(epoch); }   // panel.js owns the formatting
function bkMsg(t,cls){ var m=document.getElementById('bk-msg'); if(m){ m.textContent=t||''; m.className='small '+(cls||'text-secondary'); } }
// Retention is TYPED now rather than chosen from a list, so two things the dropdown gave for free
// have to be done explicitly: the field has to carry the server's own bounds, and a value outside
// them has to be reported rather than silently corrected. The server clamps regardless — that is
// the safety net and it stays — but a box that accepts "100" and quietly stores 30 while saying
// "Saved" is worse than the dropdown was.
function bkApplyLimits(lim){
  if(!lim) return;
  [['bk-keep', lim.keep_days], ['fb-keep', lim.full_keep]].forEach(function(pair){
    var el=document.getElementById(pair[0]), b=pair[1];
    if(el && b){ el.min=String(b.min); el.max=String(b.max); el.title='Between '+b.min+' and '+b.max+'.'; }
  });
  window._bkLimits=lim;
}
// Write the value the server ACTUALLY stored back into the box, and say so when it differs from
// what was typed. Returns a note for the status line, or '' when the two agree.
function bkReconcile(id, saved){
  var el=document.getElementById(id);
  if(!el || saved===undefined || saved===null) return '';
  var typed=el.value.trim();
  el.value=String(saved);
  return (typed!=='' && String(saved)!==typed) ? (' — ' + typed + ' is out of range, kept ' + saved) : '';
}
function loadBackups(){
  fetch(MOUNT+'/api/panel/backups').then(r=>r.json()).then(function(d){
    var s=d.settings||{};
    var en=document.getElementById('bk-enabled'); if(en) en.checked = s.enabled!==false;
    // Bounds come from the server, so the number box and the clamp behind it cannot disagree.
    bkApplyLimits(d.limits);
    var kp=document.getElementById('bk-keep'); if(kp && s.keep_days) kp.value = String(s.keep_days);
    bkShowEncState(s.encrypt===true);
    var tb=document.getElementById('bk-tbody'); if(!tb) return;
    var rows='';
    (d.backups||[]).forEach(function(b){
      var when=new Date(b.created*1000).toLocaleString();
      var kind = b.kind==='daily'?'<span class="badge bg-secondary">daily</span>'
               : b.kind==='prerestore'?'<span class="badge bg-info text-dark">pre-restore</span>'
               : '<span class="badge bg-primary">manual</span>';
      // Encrypted rows are marked so a download is not mistaken for a file you can just open —
      // and so it is obvious which archives need the passphrase to restore.
      if(b.encrypted) kind += ' <i class="bi bi-shield-lock-fill text-success" title="Encrypted — needs the passphrase to restore"></i>';
      rows += '<tr>'
        + '<td title="'+escapeHtml(when)+'">'+escapeHtml(bkAgo(b.created))+'</td>'
        + '<td>'+kind+'</td>'
        + '<td>'+bkFmtBytes(b.size)+'</td>'
        + '<td class="text-end text-nowrap">'
        // The archive is panel.db PLUS secret_key and cred_key — the pair that decrypts every
        // stored SSH credential. Downloading it moves that off the 0700 data dir onto whatever
        // machine the browser is on, so the title says so rather than just "Download".
        + '<a class="btn btn-sm btn-outline-secondary py-0 px-1" href="'+MOUNT+'/api/panel/backup/download/'+encodeURIComponent(b.name)+'" title="Download — contains the database AND the encryption keys for every stored SSH credential. Keep it somewhere you would keep those keys."><i class="bi bi-download"></i></a> '
        + '<button class="btn btn-sm btn-outline-warning py-0 px-1" title="Restore"' + _da('restoreBackup', [b.name, !!b.encrypted, '@self']) + '><i class="bi bi-arrow-counterclockwise"></i></button> '
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
          // "no backups yet" and "the host did not answer" are different facts, and only one of
          // them means nothing is protecting this server. The endpoint has reported which it is
          // since #330 (backups_unreadable, from the worker's `return sid, None`) and this page
          // read the field nowhere: every server on an unreachable host rendered "no backups yet",
          // while the SAME server's Files & Config card said the opposite. Same wording as the
          // card (static/js/server_files.js), so the two pages cannot contradict each other.
          : g.backups_unreadable
            ? '<div class="small text-warning mt-1">' + escapeHtml("Couldn't read this server's backups — the host didn't answer. This is not the same as there being none.") + '</div>'
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
  // An EMPTY or non-numeric box must not be sent as NaN — JSON.stringify turns that into null,
  // which the server reads as "don't change this field". That is the right outcome (the value on
  // disk is left alone) and the box is refilled from the response, so a cleared field visibly
  // snaps back to what is actually stored instead of appearing to have saved a blank.
  var keep=parseInt(document.getElementById('bk-keep').value,10);
  if(isNaN(keep)) keep=null;
  // Automatic game backups off → send interval 0 (disabled); on → the chosen interval.
  var autoOn=document.getElementById('fb-auto-enabled').checked;
  var fi=autoOn ? (parseInt(document.getElementById('fb-interval').value,10)||7) : 0;
  var fk=parseInt(document.getElementById('fb-keep').value,10);
  if(isNaN(fk)) fk=null;
  fbSummary();
  fetch(MOUNT+'/api/panel/backup/settings',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({enabled:enabled,keep_days:keep,full_interval_days:fi,full_keep:fk})})
    .then(r=>r.json()).then(function(d){
      var note = bkReconcile('bk-keep', (d.settings||{}).keep_days)
               + bkReconcile('fb-keep', (d.full||{}).keep);
      bkMsg('✓ Saved'+note, note?'text-warning':'text-success');
      fbSummary();   // the disk projection is a function of "keep" — recompute from the SAVED value
      bkRefreshDefaultNotes(d.full);   // ...and so is every row that inherits it
    }).catch(function(){ bkMsg('✗ Could not save','text-danger'); });
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
  // Kept so a change to the GLOBAL default can re-render the rows that inherit it. Without this
  // they keep showing the old number until the page is reloaded, so the screen contradicts itself:
  // "Keep per server 4" above, "Using default — weekly, keep 3" on every row below. Re-rendering
  // from the stored schedule costs nothing; reloading the list would be one SSH per server.
  (window._bkSched || (window._bkSched = {}))[g.id] = sc;
  var ivVal=sc.interval_set?String(sc.interval_days):'default';
  function opt(v,label,cur){ return '<option value="'+v+'"'+(String(v)===cur?' selected':'')+'>'+label+'</option>'; }
  // The same choices Files & Config offers, '3' included, plus one for any other stored interval
  // (the API accepts 0-365). A value with no <option> left the select showing its FIRST entry —
  // "Default" — beside a note saying "Custom — every 3 days", and the next save posted that.
  var ivOpts=[['default','Default'],['0','Off'],['1','Daily'],['3','Every 3 days'],['7','Weekly'],
              ['14','Every 2 weeks'],['30','Monthly']];
  if(!ivOpts.some(function(o){ return o[0]===ivVal; })) ivOpts.push([ivVal, 'Every '+Number(sc.interval_days)+' days']);
  var ivSel='<select class="form-select form-select-sm py-0" style="width:auto;" id="gsi-'+g.id+'"' + _da('setGameSchedule', [g.id], 'change') + '>'
    +ivOpts.map(function(o){ return opt(escapeHtml(o[0]), o[1], ivVal); }).join('')+'</select>';
  // Typed, not picked — the same change as the two global boxes above. A <select> could carry a
  // labelled "Default" option; a number box says it by being EMPTY, so the placeholder has to
  // carry that meaning and the endpoint has to read "" as "inherit".
  var kpLim=(window._bkLimits&&window._bkLimits.full_keep)||{min:1,max:30};
  var kpSel='<input type="number" class="form-control form-control-sm py-0 d-inline-block"'
    +' style="width:5.5rem;" min="'+kpLim.min+'" max="'+kpLim.max+'" step="1" inputmode="numeric"'
    +' placeholder="Default" title="Blank = use the default above. Between '+kpLim.min+' and '+kpLim.max+'."'
    +' value="'+(sc.keep_set?escapeHtml(String(sc.keep)):'')+'" id="gsk-'+g.id+'"'
    + _da('setGameSchedule', [g.id], 'change') + '>';
  return '<div class="d-flex align-items-center gap-2 flex-wrap small my-1">'
    +'<span class="text-secondary"><i class="bi bi-calendar-event"></i> Schedule:</span>'+ivSel
    +'<span class="text-secondary">Keep</span>'+kpSel
    +'<span class="text-secondary" id="gsn-'+g.id+'">'+schedNote(sc)+'</span></div>';
}
// Re-render the note on every row that INHERITS the global schedule, after that global changed.
// A row with its own override is left alone — its note is already correct.
function bkRefreshDefaultNotes(full){
  if(!full || !window._bkSched) return;
  Object.keys(window._bkSched).forEach(function(id){
    var sc=window._bkSched[id];
    if(sc.interval_set && sc.keep_set) return;
    if(!sc.interval_set) sc.interval_days=full.interval_days;
    if(!sc.keep_set) sc.keep=full.keep;
    var n=document.getElementById('gsn-'+id);
    if(n) n.innerHTML=schedNote(sc);  // nosemgrep — schedNote composes from numbers, not user text
  });
}
function setGameSchedule(id){
  var kpEl=document.getElementById('gsk-'+id);
  var iv=document.getElementById('gsi-'+id).value, kp=kpEl.value.trim();   // "" = inherit the default
  // Only the field that CHANGED from what is stored. The select and the box both fire this, and
  // the route leaves an absent field alone; posting both meant a change to one re-sent the other
  // as whatever it happened to read, which for an interval the list had no option for was
  // "Default" — clearing the override the note beside it said was in force.
  var cur=(window._bkSched||{})[id]||{};
  var body={};
  if(iv!=='' && iv!==(cur.interval_set?String(cur.interval_days):'default')) body.interval=iv;
  if(kp!==(cur.keep_set?String(cur.keep):'')) body.keep=kp;
  if(!Object.keys(body).length) return;
  bkMsg('Saving schedule…','text-secondary');
  fetch(MOUNT+'/api/panel/backup/game/'+id+'/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(function(d){
      if(d.success&&d.schedule){
        if(window._bkSched) window._bkSched[id]=d.schedule;
        var n=document.getElementById('gsn-'+id); if(n) n.innerHTML=schedNote(d.schedule);  // nosemgrep
        // Show what was really stored. A typed number outside the bounds is clamped server-side, and
        // an override that was cleared has to empty the box rather than leave the old text sitting
        // in it looking like it still applies.
        var saved=d.schedule.keep_set?String(d.schedule.keep):'';
        var note=(kp!=='' && d.schedule.keep_set && saved!==kp) ? (' — '+kp+' is out of range, kept '+saved) : '';
        kpEl.value=saved;
        bkMsg('✓ Schedule saved'+note, note?'text-warning':'text-success');
      } else {
        bkMsg('✗ Save failed','text-danger');
      }
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
function restoreBackup(name,encrypted,btn){
  confirmDialog({title:'Restore backup', icon:'arrow-counterclockwise', confirmClass:'btn-danger', confirmLabel:'Restore',
    bodyText:'Restore this backup?\n\n'+name+'\n\nThis OVERWRITES the panel\'s current database, settings and keys, then restarts the panel. A pre-restore safety backup is taken first.',
    onConfirm:function(){
      if(btn) btn.disabled=true;
      bkMsg('Restoring…','text-secondary');
      // No passphrase on the first attempt even for an encrypted archive: the server falls back to
      // the configured one, which is the right key for every backup this panel wrote. Only an
      // archive from ANOTHER panel (or from before the passphrase changed) needs to be asked for,
      // so the common case stays one click.
      _bkRestore(name, null, btn, encrypted);
    }});
}
function _bkRestore(name, passphrase, btn, encrypted, skipSafety){
  var body={name:name}; if(passphrase) body.passphrase=passphrase;
  if(skipSafety) body.skip_safety_backup=true;
  return fetch(MOUNT+'/api/panel/backup/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(function(d){
      if(!d.success && encrypted && /passphrase/i.test(d.message||'')){
        if(btn) btn.disabled=false;
        bkMsg('','text-secondary');
        _bkAskPassphrase(name, btn);
        return;
      }
      // The pre-restore safety copy could not be written. The server refuses rather than
      // overwriting the keys with no way back, and this is where the operator says to go ahead —
      // which is the whole point of refusing: the decision reaches a person, before the fact.
      if(!d.success && !skipSafety && /safety copy/i.test(d.message||'')){
        if(btn) btn.disabled=false;
        bkMsg('','text-secondary');
        _bkAskSkipSafety(name, passphrase, btn, encrypted, d.message||'');
        return;
      }
      bkMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
      if(d.success){ setTimeout(function(){ location.reload(); }, 8000); } else if(btn){ btn.disabled=false; }
    })
    .catch(function(){ bkMsg('The panel is restarting — reconnect in a moment.','text-warning'); });
}
function _bkAskSkipSafety(name, passphrase, btn, encrypted, why){
  confirmDialog({title:'No safety copy', icon:'exclamation-triangle',
    confirmLabel:'Restore anyway', confirmClass:'btn-danger',
    bodyText:why,
    onConfirm:function(){
      // A plain confirmDialog has already closed itself by the time this runs (panel.js) — only
      // the requirePassword form leaves it open for the caller.
      if(btn) btn.disabled=true;
      bkMsg('Restoring…','text-secondary');
      _bkRestore(name, passphrase, btn, encrypted, true);
    }});
}
function _bkAskPassphrase(name, btn){
  confirmDialog({title:'Passphrase needed', icon:'shield-lock', confirmLabel:'Restore',
    confirmClass:'btn-danger', requirePassword:true,
    requireLabel:'Backup passphrase',
    requirePlaceholder:'The passphrase this backup was written with',
    bodyText:'This backup is encrypted, and this panel\'s configured passphrase does not open it — it was written by another panel, or before the passphrase was changed.',
    onConfirm:function(val, api){
      fetch(MOUNT+'/api/panel/backup/restore',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({name:name, passphrase:val})})
        .then(r=>r.json()).then(function(d){
          if(d.success){ api.close(); bkMsg('✓ '+(d.message||'Restoring…'),'text-success');
                         setTimeout(function(){ location.reload(); }, 8000); }
          // The passphrase opened the archive, and THEN the safety copy could not be written. That
          // refusal says "Confirm again to restore without one", but pressing Restore here re-posts
          // without skip_safety_backup and gets the same refusal for ever. Hand it to the same
          // dialog _bkRestore uses, carrying the passphrase that worked.
          else if(/safety copy/i.test(d.message||'')){
            api.close();
            _bkAskSkipSafety(name, val, btn, true, d.message||'');
          }
          else api.error(d.message||'Could not restore.');
        })
        .catch(function(){ api.close(); bkMsg('The panel is restarting — reconnect in a moment.','text-warning'); });
    }});
}

function bkShowEncState(on){
  var badge=document.getElementById('bk-enc-status');
  if(badge){ badge.textContent = on?'On':'Off'; badge.className = 'badge '+(on?'bg-success':'bg-secondary'); }
  var off=document.getElementById('bk-pass-off'); if(off) off.style.display = on?'':'none';
  var box=document.getElementById('bk-pass');
  // Never repopulated from the server — it is never sent there. Cleared so a saved passphrase is
  // not left sitting in a form field for the next person at this screen.
  if(box) box.value='';
  if(box) box.placeholder = on ? 'Set a new passphrase to replace the current one'
                               : 'Passphrase — at least 12 characters';
}
function saveBackupPassphrase(btn){
  var box=document.getElementById('bk-pass'); var pass=(box&&box.value)||'';
  if(pass.length<12){ bkMsg('✗ Use at least 12 characters','text-danger'); if(box) box.focus(); return; }
  confirmDialog({title:'Encrypt new backups', icon:'shield-lock', confirmLabel:'Turn on encryption',
    bodyText:'From now on every new backup is encrypted with this passphrase.\n\nWrite it down somewhere other than this machine FIRST. There is no reset and no recovery — if you lose it, every backup written with it is permanently unreadable, including the one you would restore from.',
    onConfirm:function(){
      if(btn) btn.disabled=true;
      fetch(MOUNT+'/api/panel/backup/settings',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({passphrase:pass})})
        .then(r=>r.json()).then(function(d){
          if(btn) btn.disabled=false;
          if(d.success){ bkMsg('✓ New backups will be encrypted','text-success'); loadBackups(); }
          else bkMsg('✗ '+(d.message||'Could not save'),'text-danger');
        }).catch(function(){ if(btn) btn.disabled=false; bkMsg('✗ Could not save','text-danger'); });
    }});
}
function clearBackupPassphrase(btn){
  confirmDialog({title:'Turn off backup encryption', icon:'unlock', confirmClass:'btn-danger',
    confirmLabel:'Turn off',
    bodyText:'New backups will be written unencrypted — database, settings and BOTH encryption keys in one openable file.\n\nArchives already encrypted stay encrypted, and still need their passphrase to restore.',
    onConfirm:function(){
      if(btn) btn.disabled=true;
      fetch(MOUNT+'/api/panel/backup/settings',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({passphrase:''})})
        .then(r=>r.json()).then(function(d){
          if(btn) btn.disabled=false;
          bkMsg(d.success?'✓ Encryption off':'✗ Could not save', d.success?'text-warning':'text-danger');
          loadBackups();
        }).catch(function(){ if(btn) btn.disabled=false; bkMsg('✗ Could not save','text-danger'); });
    }});
}

// The uninstall confirm used to live here. It moved to panel.js so that the SAME gate — type the
// server's username, and the warning that this deletes every backup too — works on the dashboard,
// which is where the servers are. Delegated on document, so both pages get it from one place.

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
    if(!s.length){ out.innerHTML='<span class="text-secondary small"><i class="bi bi-check2"></i> No new LinuxGSM servers found — anything already in the panel is skipped.</span>'; prependContentNotes(out, d.content); return; }
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
    prependContentNotes(out, d.content);
  }).catch(function(){ if(out) out.innerHTML='<span class="text-danger small">Scan failed.</span>'; })
  .finally(function(){ if(btn){ btn.disabled=false; btn.innerHTML='<i class="bi bi-search"></i> Scan'; } });
}
// Say what the scan left out, and why. A GMod content box installs each mountable game through
// LinuxGSM, so the host scan sees every one of them as a server — this table used to show one
// account repeated once per game, none of which could actually be imported. Dropping them
// silently would only move the confusion, so name the account and the games.
//
// Built as DOM nodes rather than concatenated markup: the account name comes off the host's /home
// listing, and textContent cannot be talked into being markup, however it got there. Also keeps
// this out of tests/html_sink_baseline.json, which is meant to shrink.
// Say when something was asked for and not created. The server refuses an account that would
// produce more than one server — a host keys its servers on the Linux user — and reporting only
// the successes made a partial import read as a clean one. Appended as a node for the same reason
// as prependContentNotes: these names came off the host.
function appendSkippedNote(msg, skipped){
  var sk=(skipped||[]).filter(function(u,i,a){ return a.indexOf(u)===i; });
  if(!msg || !sk.length) return;
  var span=document.createElement('span');
  span.className='text-warning ms-1';
  span.textContent='Skipped '+sk.length+': '+sk.join(', ')+'.';
  msg.appendChild(span);
}
// An imported account the helper would not put in the panel's game-account group (it can already
// reach root, or the enrolment failed). On a host where the panel's sudo is limited to its helper,
// the panel cannot control that server, so say so here instead of on every later action.
function appendEnrolNote(msg, notEnrolled){
  if(!msg || !notEnrolled || !notEnrolled.length) return;
  var box=document.createElement('div'); box.className='text-warning small mt-1';
  var head=document.createElement('div');
  head.textContent='Imported, but not added to the panel\u2019s game-account group. Where the panel\u2019s sudo is limited to its helper, it cannot control these servers.';
  box.appendChild(head);
  notEnrolled.forEach(function(n){
    var row=document.createElement('div'); row.className='font-monospace text-break';
    row.setAttribute('data-no-i18n','');
    row.textContent=(n.user||'?')+': '+(n.reason||'');
    box.appendChild(row);
  });
  msg.appendChild(box);
}
function prependContentNotes(out, content){
  if(!out || !content || !content.length) return;
  var frag=document.createDocumentFragment();
  content.forEach(function(c){
    var games=c.games||[], n=games.length;
    var div=document.createElement('div'); div.className='text-secondary small mb-2';
    var icon=document.createElement('i'); icon.className='bi bi-info-circle';
    div.appendChild(icon);
    div.appendChild(document.createTextNode(' Skipped '+n+' GMod content install'+(n===1?'':'s')+' under '));
    var who=document.createElement('span'); who.className='font-monospace'; who.textContent=c.user||'?';
    div.appendChild(who);
    div.appendChild(document.createTextNode(' ('+games.join(', ')+') — mountable content, not servers.'));
    frag.appendChild(div);
  });
  out.insertBefore(frag, out.firstChild);
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
      appendSkippedNote(msg, d.skipped);
      appendEnrolNote(msg, d.not_enrolled);
    }).catch(function(){ if(msg) msg.innerHTML='<span class="text-danger">Import failed.</span>';
             btn.disabled=false; btn.innerHTML='<i class="bi bi-plus-circle"></i> Import selected'; });
}
