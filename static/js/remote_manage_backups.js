// backups, and discovering/importing existing LinuxGSM servers
// Split out of one 86KB file; these load in order and behave as one script.
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
