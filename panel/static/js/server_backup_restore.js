// The Backups card's restore and upload (Files & Config), beside server_files.js: it uses that file's
// MOUNT, serverId, SERVER_NAME, loadBackups and _bkPoll, and renderBackups calls _grsRenderStatus.
// The routes: routes/game_restore (restore) and routes/backup_upload (upload in pieces, panel.js's
// window.backupUpload).
// A restore from a backup (routes/game_restore): what step it is on, then how it ended.
var _GRS_STEPS = {checking: 'Restore: checking the archive…', stopping: 'Restore: stopping the server…',
                  backing_up: 'Restore: backing up the current state first…', restoring: 'Restore: replacing the files…'};
function _grsRenderStatus(r){
  var st=document.getElementById('bk-restore-status');
  if(!st) return !!(r && r.running);
  st.textContent='';
  if(!r) return false;
  var icon=document.createElement('i'), text=document.createElement('span');
  if(r.running){ st.className='small text-info'; icon.className='bi bi-arrow-repeat'; text.textContent=' '+tf(_GRS_STEPS[r.step]||'Restore: running…'); }
  else if(r.ok===true){ st.className='small text-success'; icon.className='bi bi-check-circle'; text.textContent=' '+(r.msg||tf('Restored')); }
  else { st.className='small text-danger'; icon.className='bi bi-x-circle'; text.textContent=' '+(r.msg||tf('Restore failed')); }
  st.appendChild(icon); st.appendChild(text);
  return !!r.running;
}

// Upload a backup of this server (window.backupUpload): it lands in the list, then restores like any other.
function uploadBk(){ var f=document.getElementById('bk-upload-file'); if(f){ f.value=''; f.click(); } }
function uploadBkPicked(el){
  var file = el && el.files && el.files[0];
  if(!file) return;
  var btn=document.getElementById('bk-upload'), st=document.getElementById('bk-restore-status');
  if(btn) btn.disabled=true;
  var say=function(t, cls){ if(st){ st.className='small '+cls; st.textContent=t; } };
  window.backupUpload(file, MOUNT+'/api/panel/backup/game/'+serverId+'/upload', function(sent, total){
    say(tf('Uploading {name}: {pct}%', {name: file.name, pct: total ? Math.floor(sent*100/total) : 100}), 'text-info');
  }).then(function(d){
    say(d.message || (d.success ? tf('Uploaded') : tf('Upload failed')), d.success ? 'text-success' : 'text-danger');
    if(btn) btn.disabled=false; loadBackups();
  }).catch(function(){ say(tf('Upload failed'), 'text-danger'); if(btn) btn.disabled=false; });
}

// Restore the server from one of its backups: the operator types the server's name to confirm.
function restoreBk(btn){
  var name = btn.getAttribute('data-name') || '';
  confirmDialog({title:'Restore from backup', icon:'arrow-counterclockwise', confirmClass:'btn-danger', confirmLabel:'Restore',
    bodyText:tf('Restore {server} from this backup?\n\n{name}\n\nEvery file of the server is replaced with the copy in the archive: its world, configs and LinuxGSM files. The server is stopped first, and a fresh backup of its current state is taken before anything is replaced, so you can go back. A running server is started again afterwards.', {server: SERVER_NAME, name: name}),
    requireText: SERVER_NAME, requireLabel: tf('Type the server name to confirm'),
    onConfirm:function(){
      btn.disabled=true;
      fetch(MOUNT+'/api/panel/backup/game/'+serverId+'/restore',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({name:name, confirm:SERVER_NAME})})
        .then(r=>r.json()).then(function(d){
          window.toast(d.message || (d.success?tf('Restore started'):tf('Restore failed')), d.success?'success':'danger');
          loadBackups();
          if(d.success && !_bkPoll) _bkPoll=setInterval(loadBackups, 4000);
          if(!d.success) btn.disabled=false;
        }).catch(function(){ window.toast(tf('Restore failed'),'danger'); btn.disabled=false; });
    }});
}
