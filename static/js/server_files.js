var curDir = "";        // current browse dir (relative to home)
var curFile = null;     // path of the file open in the editor

// Escapes quotes too (&#39;/&quot;) — config keys/values are interpolated into
// double-quoted HTML attributes below, so a bare " would otherwise break out (XSS).
// Delegates; the old body used (s+'') so esc(null) rendered the literal "null".
function esc(s){ return window.escapeHtml(s); }
function fmtSize(b){ if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(1)+' KB'; return (b/1048576).toFixed(1)+' MB'; }
function fileIcon(name){
  var n=(name||'').toLowerCase();
  if(/\.(cfg|conf|ini|cnf)$/.test(n)) return 'bi-sliders text-info';
  if(/\.(log)$/.test(n)) return 'bi-journal-text text-secondary';
  if(/\.(json|yml|yaml|xml|toml)$/.test(n)) return 'bi-file-earmark-code text-info';
  if(/\.(sh|bash)$/.test(n)) return 'bi-terminal text-success';
  if(/\.(txt|md)$/.test(n)) return 'bi-file-earmark-text';
  if(/\.(zip|gz|tar|bz2|xz|7z|rar)$/.test(n)) return 'bi-file-earmark-zip text-warning';
  if(/\.(jpe?g|png|gif|bmp|svg|webp)$/.test(n)) return 'bi-file-earmark-image text-warning';
  return 'bi-file-earmark';
}

// ── Config tabs ──
var gameCfgLoaded=false, gameCfgRel=null;
document.getElementById('cfg-tabs').addEventListener('click', function(ev){
  var b=ev.target.closest('[data-tab]'); if(!b) return;
  document.querySelectorAll('#cfg-tabs .nav-link').forEach(function(n){ n.classList.remove('active'); });
  b.classList.add('active');
  ['lgsm','game','raw'].forEach(function(t){ document.getElementById('tab-'+t).style.display = (t===b.dataset.tab)?'':'none'; });
  if(b.dataset.tab==='game' && !gameCfgLoaded) loadGameCfg();
});

// ── LinuxGSM settings (grouped) ──
function fieldHtml(s){
  var def = s['default'];
  return '<div class="col-6 col-md-4 col-xl-3 mb-1">'
    + '<label class="form-label mb-1 d-flex align-items-center gap-1" style="font-size:.7rem;">'
    + '<span class="fb-key">'+esc(s.key)+'</span>'
    + '<span class="badge bg-info text-dark cfg-set-badge" style="font-size:.5rem;'+(s.overridden?'':'display:none;')+'">set</span>'
    + '</label>'
    + '<input type="text" class="form-control form-control-sm" data-key="'+esc(s.key)+'" data-orig="'+esc(s.value)+'" value="'+esc(s.value)+'"'
    + (def!==''?' placeholder="'+esc(def)+'"':'') + '>'
    + (def!==''?'<div class="text-secondary text-truncate" style="font-size:.62rem;">default: '
        + '<code class="cfg-copy-default" data-copy="'+esc(def)+'" style="cursor:pointer;" '
        + 'title="default: '+esc(def)+' — click to copy">'+esc(def)+'</code></div>':'')
    + '</div>';
}
// Click any "default: <value>" to copy that value to the clipboard (delegated, so it keeps working
// after the config list re-renders). Uses the shared copyText() helper for the copy + confirmation.
document.addEventListener('click', function(ev){
  var c = ev.target.closest && ev.target.closest('.cfg-copy-default');
  if(!c) return;
  if(window.copyText) window.copyText(c.getAttribute('data-copy') || '', 'Copied default');
});
function loadConfig(){
  fetch(MOUNT+'/api/server/'+serverId+'/config').then(r=>r.json()).then(d=>{
    document.getElementById('cfg-loading').style.display='none';
    if(d.error){ document.getElementById('cfg-loading').style.display=''; document.getElementById('cfg-loading').innerHTML='<span class="text-danger">'+esc(d.error)+'</span>'; return; }  // nosemgrep
    var g=document.getElementById('cfg-groups'); g.innerHTML='';
    (d.groups||[]).forEach(function(grp, idx){
      var open = idx===0; // first group (Game Server Settings) expanded
      var body = '<div class="row g-2">'+grp.settings.map(fieldHtml).join('')+'</div>';
      g.insertAdjacentHTML('beforeend',
        '<div class="mb-2 border rounded overflow-hidden">'  // nosemgrep
        + '<button type="button" class="cfg-acc-header btn btn-sm w-100 text-start d-flex justify-content-between align-items-center px-3 py-2" data-acc="'+idx+'">'
        + '<span class="fw-semibold"><i class="bi bi-caret-'+(open?'down':'right')+'-fill me-1"></i>'+esc(grp.section)+'</span>'
        + '<span class="badge bg-secondary">'+grp.settings.length+'</span></button>'
        + '<div class="p-3" data-accbody="'+idx+'" style="'+(open?'':'display:none;')+'">'+body+'</div></div>');
    });
    if(!(d.groups||[]).length) g.innerHTML='<div class="text-secondary small">No settings detected. Use the raw editor.</div>';
    document.getElementById('cfg-form').style.display='';
    document.getElementById('cfg-raw').value = d.raw||'';
  }).catch(()=>{ document.getElementById('cfg-loading').innerHTML='<span class="text-danger">Failed to load config</span>'; });
}
// Accordion toggle (delegated).
document.getElementById('cfg-groups').addEventListener('click', function(ev){
  var b=ev.target.closest('[data-acc]'); if(!b) return;
  var body=document.querySelector('[data-accbody="'+b.dataset.acc+'"]');
  var ic=b.querySelector('i');
  if(body.style.display==='none'){ body.style.display=''; ic.className='bi bi-caret-down-fill me-1'; }
  else { body.style.display='none'; ic.className='bi bi-caret-right-fill me-1'; }
});
function saveConfig(ev){
  ev.preventDefault();
  var settings={};
  // Only send fields the user actually changed — otherwise every default would be
  // written into the instance override file.
  document.querySelectorAll('#cfg-groups input[data-key]').forEach(function(i){
    if(i.value !== i.getAttribute('data-orig')) settings[i.getAttribute('data-key')]=i.value;
  });
  var msg=document.getElementById('cfg-save-msg');
  if(Object.keys(settings).length===0){ msg.textContent='No changes to save.'; msg.className='small ms-2 text-secondary'; return false; }
  msg.textContent='Saving…'; msg.className='small ms-2 text-secondary';
  fetch(MOUNT+'/api/server/'+serverId+'/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({settings:settings})})
    .then(r=>r.json()).then(d=>{
      msg.textContent = d.success?'✓ Saved — restart the server to apply.':'✗ '+(d.message||'Failed');
      msg.className='small ms-2 '+(d.success?'text-success':'text-danger');
      if(d.success){
        // Mark saved values as the new baseline (preserves accordion state), and show the "set"
        // badge on the fields we just wrote — they're now overrides in the instance .cfg.
        document.querySelectorAll('#cfg-groups input[data-key]').forEach(function(i){
          i.setAttribute('data-orig', i.value);
          if(settings.hasOwnProperty(i.getAttribute('data-key'))){
            var b=i.parentElement.querySelector('.cfg-set-badge'); if(b) b.style.display='';
          }
        });
        // The settings write changed the instance .cfg — refresh the Raw tab so it isn't stale.
        refreshRawConfig();
      }
    }).catch(()=>{ msg.textContent='✗ Save failed'; msg.className='small ms-2 text-danger'; });
  return false;
}
// Re-read just the raw instance cfg and update the Raw tab, WITHOUT re-rendering the settings
// form (which would collapse the accordion). Skipped if the user is actively editing the raw box.
function refreshRawConfig(){
  fetch(MOUNT+'/api/server/'+serverId+'/config').then(r=>r.json()).then(function(d){
    var ta=document.getElementById('cfg-raw');
    if(ta && d && d.raw !== undefined && document.activeElement!==ta) ta.value = d.raw || '';
  }).catch(function(){});
}
// ── Game config file ──
function loadGameCfg(){
  gameCfgLoaded=true;
  fetch(MOUNT+'/api/server/'+serverId+'/game-config').then(r=>r.json()).then(d=>{
    document.getElementById('game-loading').style.display='none';
    if(d.error || !d.rel){
      document.getElementById('game-none').style.display='';
      document.getElementById('game-none').innerHTML='<i class="bi bi-info-circle"></i> '+esc(d.error||'This game has no single editable config file. Use the file browser below.');  // nosemgrep
      return;
    }
    gameCfgRel=d.rel;
    document.getElementById('game-path').textContent=d.rel;
    document.getElementById('game-cfg').value=d.content||'';
    document.getElementById('game-wrap').style.display='';
  }).catch(()=>{ document.getElementById('game-loading').innerHTML='<span class="text-danger">Failed to load game config</span>'; });
}
function saveGameCfg(){
  if(!gameCfgRel) return;
  var msg=document.getElementById('game-msg'); msg.textContent='Saving…'; msg.className='small ms-2 text-secondary';
  fetch(MOUNT+'/api/server/'+serverId+'/file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:gameCfgRel,content:document.getElementById('game-cfg').value})})
    .then(r=>r.json()).then(d=>{ msg.textContent=d.success?'✓ Saved — restart to apply.':'✗ '+(d.message||'Failed'); msg.className='small ms-2 '+(d.success?'text-success':'text-danger'); })
    .catch(()=>{ msg.textContent='✗ Failed'; msg.className='small ms-2 text-danger'; });
}
function saveRaw(){
  var msg=document.getElementById('cfg-raw-msg'); msg.textContent='Saving…'; msg.className='small ms-2 text-secondary';
  fetch(MOUNT+'/api/server/'+serverId+'/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw:document.getElementById('cfg-raw').value})})
    .then(r=>r.json()).then(d=>{ msg.textContent=d.success?'✓ Saved':'✗ '+(d.message||'Failed'); msg.className='small ms-2 '+(d.success?'text-success':'text-danger'); if(d.success) loadConfig(); })
    .catch(()=>{ msg.textContent='✗ Failed'; msg.className='small ms-2 text-danger'; });
}

// ── File browser ──
function renderBreadcrumb(){
  var parts = curDir? curDir.split('/'):[];
  var html='<a href="#" data-nav=""><i class="bi bi-house-door"></i> home</a>';
  var acc='';
  parts.forEach(function(p){ acc = acc?acc+'/'+p:p; html+=' <span class="text-secondary">/</span> <a href="#" data-nav="'+esc(acc)+'">'+esc(p)+'</a>'; });
  document.getElementById('breadcrumb').innerHTML = html;  // nosemgrep
  var dest=document.getElementById('upload-dest'); if(dest) dest.textContent = curDir||'home';
}
function mkRow(opts){
  // opts: {name, path, type: 'dir'|'file'|'up', size, deletable, protected, icon}
  var row=document.createElement('div');
  row.className='list-group-item list-group-item-action d-flex justify-content-between align-items-center';
  row.style.cursor='pointer';
  row.dataset.path=opts.path; row.dataset.type=opts.type;
  var left=document.createElement('span'); left.style.flex='1'; left.style.minWidth='0'; left.style.overflow='hidden'; left.style.textOverflow='ellipsis'; left.style.whiteSpace='nowrap';
  left.innerHTML=opts.icon+' <span style="font-size:.85rem;">'+esc(opts.name)+'</span>';  // nosemgrep
  var right=document.createElement('span'); right.className='d-flex align-items-center gap-2 flex-shrink-0';
  if(opts.size!=null){ var s=document.createElement('span'); s.className='text-secondary'; s.style.fontSize='.68rem'; s.textContent=fmtSize(opts.size); right.appendChild(s); }
  if(opts.protected){ var lk=document.createElement('span'); lk.className='text-secondary'; lk.title='Protected — required by LinuxGSM/the game'; lk.innerHTML='<i class="bi bi-shield-lock"></i>'; right.appendChild(lk); }
  else if(opts.deletable){ var b=document.createElement('button'); b.type='button'; b.className='btn btn-sm btn-link text-danger p-0'; b.title='Delete'; b.dataset.action='delete'; b.innerHTML='<i class="bi bi-trash"></i>'; right.appendChild(b); }
  row.appendChild(left); row.appendChild(right);
  return row;
}
function browse(path){
  curDir = path||'';
  fetch(MOUNT+'/api/server/'+serverId+'/browse?path='+encodeURIComponent(curDir)).then(r=>r.json()).then(d=>{
    var l=document.getElementById('file-list'); l.innerHTML='';
    if(d.error){ l.innerHTML='<div class="text-danger small p-2">'+esc(d.error)+'</div>'; return; }  // nosemgrep
    renderBreadcrumb();
    if(curDir){
      l.appendChild(mkRow({name:'..', path:curDir.split('/').slice(0,-1).join('/'), type:'up', icon:'<i class="bi bi-arrow-90deg-up text-secondary"></i>'}));
    }
    (d.entries||[]).forEach(function(e){
      var p = curDir? curDir+'/'+e.name : e.name;
      l.appendChild(mkRow({
        name:e.name, path:p, type:e.is_dir?'dir':'file', deletable:true, protected:e.protected,
        size: e.is_dir?null:e.size,
        icon: e.is_dir?'<i class="bi bi-folder-fill text-warning"></i>':'<i class="bi '+fileIcon(e.name)+'"></i>'
      }));
    });
    if(!(d.entries||[]).length) l.insertAdjacentHTML('beforeend','<div class="text-secondary small p-3 text-center">(empty folder)</div>');
    // Re-highlight the open file if it's in this directory.
    if(curFile){ var open=l.querySelector('[data-path="'+CSS.escape(curFile)+'"]'); if(open) open.classList.add('active'); }
  }).catch(()=>{});
}
function openFile(path){
  document.getElementById('file-save-msg').textContent='';
  fetch(MOUNT+'/api/server/'+serverId+'/file?path='+encodeURIComponent(path)).then(r=>r.json()).then(d=>{
    if(d.error){ if(window.toast) toast(d.error, 'danger'); return; }
    curFile=path;
    document.getElementById('editor-empty').style.display='none';
    document.getElementById('editor-wrap').style.display='';
    document.getElementById('editor-path').textContent=path;
    document.getElementById('editor').value=d.content||'';
  }).catch(()=>{});
}
function closeEditor(){
  curFile=null;
  document.getElementById('editor-wrap').style.display='none';
  document.getElementById('editor-empty').style.display='';
  document.querySelectorAll('#file-list .list-group-item.active').forEach(function(x){ x.classList.remove('active'); });
}
function saveFile(){
  if(!curFile) return;
  var msg=document.getElementById('file-save-msg'); msg.textContent='Saving…'; msg.className='small text-secondary';
  fetch(MOUNT+'/api/server/'+serverId+'/file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:curFile,content:document.getElementById('editor').value})})
    .then(r=>r.json()).then(d=>{ msg.textContent=d.success?'✓ Saved':'✗ '+(d.message||'Failed'); msg.className='small '+(d.success?'text-success':'text-danger'); })
    .catch(()=>{ msg.textContent='✗ Failed'; msg.className='small text-danger'; });
}
function deletePath(path, isDir){
  confirmDialog({title:'Delete '+(isDir?'directory':'file'), icon:'trash', confirmClass:'btn-danger', confirmLabel:'Delete',
    bodyText:'Delete '+(isDir?'directory (and everything in it)':'file')+':\n'+path+' ?',
    onConfirm:function(){
      fetch(MOUNT+'/api/server/'+serverId+'/delete-path',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})})
        .then(r=>r.json()).then(d=>{
          if(!d.success){ if(window.toast) toast(d.message||'Delete failed','danger'); return; }
          if(curFile===path) closeEditor();
          browse(curDir);
        }).catch(()=>{ if(window.toast) toast('Delete failed','danger'); });
    }});
}
// Upload one or more files to the current dir (used by button + drag-drop).
function uploadFiles(files){
  if(!files || !files.length) return;
  var st=document.getElementById('upload-status');
  var arr=Array.prototype.slice.call(files); var failed=0;
  st.textContent='Uploading '+arr.length+' file(s)…'; st.className='small mt-2 text-secondary';
  function next(i){
    if(i>=arr.length){
      st.textContent=(failed?'⚠ '+failed+' failed, ':'✓ ')+(arr.length-failed)+' uploaded to '+(curDir||'home');
      st.className='small mt-2 '+(failed?'text-warning':'text-success');
      browse(curDir); setTimeout(function(){ st.textContent=''; },4000); return;
    }
    var fd=new FormData(); fd.append('file', arr[i]); fd.append('path', curDir);
    fetch(MOUNT+'/api/server/'+serverId+'/upload',{method:'POST',body:fd}).then(r=>r.json()).then(d=>{ if(!d.success) failed++; }).catch(()=>{failed++;}).finally(()=>{ next(i+1); });
  }
  next(0);
}
function doUpload(ev){
  ev.preventDefault();
  var inp=document.getElementById('upload-input');
  if(inp.files.length){ uploadFiles(inp.files); inp.value=''; }
  return false;
}

// Event delegation for the file list (rows + delete buttons).
document.getElementById('file-list').addEventListener('click', function(ev){
  var del = ev.target.closest('[data-action="delete"]');
  if(del){ ev.stopPropagation(); var r=del.closest('[data-path]'); deletePath(r.dataset.path, r.dataset.type==='dir'); return; }
  var row = ev.target.closest('[data-path]');
  if(!row) return;
  if(row.dataset.type==='file'){
    document.querySelectorAll('#file-list .list-group-item.active').forEach(function(x){ x.classList.remove('active'); });
    row.classList.add('active');
    openFile(row.dataset.path);
  } else browse(row.dataset.path);
});
// Breadcrumb navigation (delegated).
document.getElementById('breadcrumb').addEventListener('click', function(ev){
  var a=ev.target.closest('[data-nav]'); if(a){ ev.preventDefault(); browse(a.getAttribute('data-nav')); }
});
// Drag & drop upload onto the browser (overlay shows while dragging).
(function(){
  var dz=document.getElementById('drop-zone');
  ['dragenter','dragover'].forEach(function(e){ dz.addEventListener(e,function(ev){ ev.preventDefault(); ev.stopPropagation(); dz.classList.add('dragging'); }); });
  ['dragleave','drop'].forEach(function(e){ dz.addEventListener(e,function(ev){ ev.preventDefault(); ev.stopPropagation(); if(e==='drop' || !dz.contains(ev.relatedTarget)) dz.classList.remove('dragging'); }); });
  dz.addEventListener('drop', function(ev){ if(ev.dataTransfer && ev.dataTransfer.files) uploadFiles(ev.dataTransfer.files); });
})();

// ── Scheduled tasks (cron) ──
var cronEditRaw = null;   // when editing: the exact raw line being replaced
// Attribute-safe escape: cron commands routinely contain " and ', which would
// otherwise break the data-* attributes we round-trip the raw line through.
// escA was a no-op wrapper: esc already escapes both quote characters. Kept as an alias so its
// ~call sites need not change, but it adds nothing.
var escA = esc;
function cronMsg(text, cls){ var m=document.getElementById('cron-msg'); m.textContent=text||''; m.className='small '+(cls||'text-secondary'); }
// "3m ago" / "2h ago" / "5d ago" from an epoch (seconds).
function timeAgo(epoch){
  var s = Math.max(0, Math.floor(Date.now()/1000 - epoch));
  if(s < 60) return s+'s ago';
  if(s < 3600) return Math.floor(s/60)+'m ago';
  if(s < 86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
// Last-run cell. Wrapped jobs report an exit status → OK/Failed badge + the error under a
// failure. A managed or legacy job that has not run since the panel re-wrapped it (which
// upgrade_managed_cron_tracking does on every cron GET) has only a run TIME from cron's log → a
// neutral "ran" badge until its next run records a status. No recorded run → "—".
function cronLastRun(j){
  if(!j.last_run){ return '<span class="text-secondary" title="No recorded run yet">—</span>'; }
  var when = new Date(j.last_run*1000).toLocaleString();
  var badge;
  if(j.ok === true){ badge = '<span class="badge bg-success" title="Exit code 0 at '+escA(when)+'">OK</span>'; }
  else if(j.ok === false){ badge = '<span class="badge bg-danger" title="Failed at '+escA(when)+'">Failed</span>'; }
  else { badge = '<span class="badge bg-secondary" title="Ran at '+escA(when)+' — cron doesn\'t record exit status for panel-managed jobs">ran</span>'; }
  var out = badge + ' <span class="text-secondary" title="'+escA(when)+'">'+esc(timeAgo(j.last_run))+'</span>';
  if(j.ok === false && j.error){ out += '<div class="text-danger" style="font-size:.66rem;word-break:break-all;white-space:normal;max-width:22rem;">'+esc(j.error)+'</div>'; }
  return out;
}
function loadCron(){
  fetch(MOUNT+'/api/server/'+serverId+'/cron').then(r=>r.json()).then(d=>{
    var loading=document.getElementById('cron-loading');
    if(d.error){ loading.style.display=''; loading.innerHTML='<span class="text-danger">'+esc(d.error)+'</span>'; return; }  // nosemgrep
    var tb=document.getElementById('cron-tbody'), rows='';
    (d.jobs||[]).forEach(function(j){
      var runBtn = '<button class="btn btn-sm btn-link p-0 me-2" data-cron-run title="Run now"><i class="bi bi-play-circle"></i></button>';
      // Every task is editable + deletable now, including panel-installed ones.
      var actions = runBtn
        + '<button class="btn btn-sm btn-link p-0 me-2" data-cron-edit title="Edit"><i class="bi bi-pencil"></i></button>'
        + '<button class="btn btn-sm btn-link text-danger p-0" data-cron-del title="Delete"><i class="bi bi-trash"></i></button>';
      // Non-blocking label so you can tell what a panel-installed line is (still fully editable).
      var roleTag = j.role
        ? ' <span class="badge bg-secondary align-middle" style="font-weight:normal;font-size:.6rem;" title="Panel-installed: this is your '+esc(j.role)+' line (also on the server-page toggle). You can still reschedule or delete it here.">'+esc(j.role)+'</span>'
        : '';
      rows += '<tr data-raw="'+escA(j.raw)+'" data-sched="'+escA(j.schedule)+'" data-cmd="'+escA(j.command)+'">'
        + '<td data-label="Schedule" class="font-monospace" style="white-space:nowrap;">'+esc(j.schedule)+'</td>'
        + '<td data-label="Command" class="font-monospace cron-cmd">'+esc(j.command)+roleTag+'</td>'
        + '<td data-label="Last run" style="white-space:nowrap;">'+cronLastRun(j)+'</td>'
        + '<td class="text-end" style="white-space:nowrap;">'+actions+'</td></tr>';
    });
    if(!(d.jobs||[]).length) rows='<tr><td colspan="4" class="text-secondary text-center py-3">No scheduled tasks yet.</td></tr>';
    // Only swap in the new list once it has arrived (keep the old rows until then).
    tb.innerHTML=rows;  // nosemgrep
    loading.style.display='none';
    document.getElementById('cron-table-wrap').style.display='';
  }).catch(()=>{ /* keep whatever is shown; transient errors shouldn't blank the list */ });
}
function saveCron(ev){
  ev.preventDefault();
  var sched=document.getElementById('cron-sched').value.trim();
  var cmd=document.getElementById('cron-cmd').value.trim();
  if(!sched || !cmd){ cronMsg('Schedule and command are both required.','text-danger'); return false; }
  var editing = cronEditRaw!==null;
  var url = MOUNT+'/api/server/'+serverId+'/cron'+(editing?'/update':'');
  var body = editing ? {raw:cronEditRaw, schedule:sched, command:cmd} : {schedule:sched, command:cmd};
  cronMsg('Saving…','text-secondary');
  fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(d=>{
      if(d.success){ cronMsg(editing?'✓ Task updated':'✓ Task added','text-success'); cancelCronEdit(); loadCron(); }
      else cronMsg('✗ '+(d.message||'Failed'),'text-danger');
    }).catch(()=>cronMsg('✗ Save failed','text-danger'));
  return false;
}
function cancelCronEdit(){
  cronEditRaw=null;
  document.getElementById('cron-sched').value='';
  document.getElementById('cron-cmd').value='';
  document.getElementById('cron-submit').innerHTML='<i class="bi bi-plus-lg"></i> Add task';
  document.getElementById('cron-cancel').style.display='none';
  updateCronExplain();
}
document.getElementById('cron-tbody').addEventListener('click', function(ev){
  var row=ev.target.closest('tr[data-raw]'); if(!row) return;
  if(ev.target.closest('[data-cron-edit]')){
    cronEditRaw=row.getAttribute('data-raw');
    document.getElementById('cron-sched').value=row.getAttribute('data-sched');
    document.getElementById('cron-cmd').value=row.getAttribute('data-cmd');
    updateCronExplain();
    document.getElementById('cron-submit').innerHTML='<i class="bi bi-save"></i> Save changes';
    document.getElementById('cron-cancel').style.display='';
    cronMsg('Editing an existing task…','text-secondary');
    document.getElementById('cron-sched').focus();
  } else if(ev.target.closest('[data-cron-del]')){
    confirmDialog({title:'Delete scheduled task', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Delete',
      bodyText:'Delete this scheduled task?\n\n'+row.getAttribute('data-sched')+'  '+row.getAttribute('data-cmd'),
      onConfirm:function(){
        fetch(MOUNT+'/api/server/'+serverId+'/cron/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw:row.getAttribute('data-raw')})})
          .then(r=>r.json()).then(d=>{ if(d.success){ cronMsg('✓ Task deleted','text-success'); loadCron(); } else cronMsg('✗ '+(d.message||'Delete failed'),'text-danger'); })
          .catch(()=>cronMsg('✗ Delete failed','text-danger'));
      }});
  } else if(ev.target.closest('[data-cron-run]')){
    var btn=ev.target.closest('[data-cron-run]'); btn.disabled=true;
    cronMsg('Running '+row.getAttribute('data-cmd')+'…','text-secondary');
    fetch(MOUNT+'/api/server/'+serverId+'/cron/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw:row.getAttribute('data-raw')})})
      .then(r=>r.json()).then(d=>{
        cronMsg((d.success?'✓ ':'✗ ')+(d.message||'Done'), d.success?'text-success':'text-danger');
        btn.disabled=false;
        // The run is detached; refresh a few times so the OK/Failed badge lands when it finishes.
        [3000,8000,15000].forEach(function(ms){ setTimeout(loadCron, ms); });
      })
      .catch(()=>{ cronMsg('✗ Run failed','text-danger'); btn.disabled=false; });
  }
});

// ── Live cron explainer (crontab.guru-style: translate + preview next runs) ──
(function(){
  var DOW=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  var MON=['','January','February','March','April','May','June','July','August','September','October','November','December'];
  var NM_DOW={sun:0,mon:1,tue:2,wed:3,thu:4,fri:5,sat:6};
  var NM_MON={jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12};
  var SHORT={'@yearly':'0 0 1 1 *','@annually':'0 0 1 1 *','@monthly':'0 0 1 * *','@weekly':'0 0 * * 0','@daily':'0 0 * * *','@midnight':'0 0 * * *','@hourly':'0 * * * *'};
  // Parse one cron field into a Set of allowed ints (ranges, lists, steps, names). null = invalid.
  function parseField(f,lo,hi,names){
    f=(f||'').trim().toLowerCase(); if(f==='') return null;
    var out=new Set(), parts=f.split(',');
    for(var i=0;i<parts.length;i++){
      var p=parts[i], step=1, range=p, sl=p.indexOf('/');
      if(sl>=0){ step=parseInt(p.slice(sl+1),10); range=p.slice(0,sl); if(!(step>=1)) return null; }
      var a,b;
      if(range==='*'){ a=lo; b=hi; }
      else {
        var seg=range.split('-');
        var mv=function(x){ x=x.trim(); if(names&&names[x]!=null) return names[x]; if(!/^\d+$/.test(x)) return NaN; return parseInt(x,10); };
        a=mv(seg[0]); b=(seg.length>1)?mv(seg[1]):(sl>=0?hi:a);
        if(isNaN(a)||isNaN(b)) return null;
      }
      if(names===NM_DOW){ if(a===7)a=0; if(b===7)b=0; }
      if(a>b || a<lo || b>hi) return null;
      for(var v=a; v<=b; v+=step) out.add(v);
    }
    return out;
  }
  function pad(n){ return (n<10?'0':'')+n; }
  function toArr(s){ return Array.from(s).sort(function(a,b){return a-b;}); }
  function joinList(arr,fmt){ arr=arr.map(fmt); if(arr.length<=1) return arr[0]||''; return arr.slice(0,-1).join(', ')+' and '+arr[arr.length-1]; }
  function contiguous(a){ for(var i=1;i<a.length;i++) if(a[i]!==a[i-1]+1) return false; return a.length>1; }
  function describe(f,sets){
    var mR=f[0],hR=f[1],domR=f[2],monR=f[3],dowR=f[4];
    var mAll=mR==='*', hAll=hR==='*', mOne=/^\d+$/.test(mR), hOne=/^\d+$/.test(hR), stepM=/^\*\/(\d+)$/.exec(mR);
    var time;
    if(mAll&&hAll) time='Every minute';
    else if(stepM&&hAll) time='Every '+stepM[1]+' minutes';
    else if(mOne&&hOne) time='At '+pad(+hR)+':'+pad(+mR);
    else if(mOne&&hAll) time=(+mR===0)?'Every hour, on the hour':'At '+(+mR)+' minutes past every hour';
    else {
      var mp=hAll?'past every hour':'past '+(hOne?('hour '+(+hR)):('hours '+joinList(toArr(sets.hour),String)));
      time=(mAll?'Every minute':'At '+(mOne?('minute '+(+mR)):('minutes '+joinList(toArr(sets.min),String))))+' '+mp;
    }
    var q=[];
    if(domR!=='*') q.push('on day-of-month '+joinList(toArr(sets.dom),String));
    if(dowR!=='*'){ var dw=toArr(sets.dow); q.push((domR!=='*'?'and on ':'on ')+(contiguous(dw)?DOW[dw[0]]+'–'+DOW[dw[dw.length-1]]:joinList(dw,function(x){return DOW[x];}))); }
    if(monR!=='*') q.push('in '+joinList(toArr(sets.mon),function(x){return MON[x];}));
    return time+(q.length?' '+q.join(' '):'');
  }
  function analyze(expr){
    expr=(expr||'').trim().replace(/\s+/g,' ');
    if(expr==='') return {empty:true};
    if(expr.charAt(0)==='@'){
      var k=expr.toLowerCase();
      if(k==='@reboot') return {ok:true,text:'Runs once, at server boot.',reboot:true};
      if(SHORT[k]) expr=SHORT[k]; else return {error:'Unknown shortcut "'+expr+'".'};
    }
    var f=expr.split(' ');
    if(f.length!==5) return {error:'Needs 5 fields (min hour day month weekday) or an @shortcut.'};
    var sets={min:parseField(f[0],0,59),hour:parseField(f[1],0,23),dom:parseField(f[2],1,31),mon:parseField(f[3],1,12,NM_MON),dow:parseField(f[4],0,6,NM_DOW)};
    for(var kk in sets){ if(!sets[kk]||!sets[kk].size) return {error:'Invalid or out-of-range '+kk+' field.'}; }
    sets.domStar=f[2]==='*'; sets.dowStar=f[4]==='*';
    return {ok:true,text:describe(f,sets),sets:sets};
  }
  function nextRuns(sets,count){
    var res=[], d=new Date(); d.setSeconds(0,0); d.setMinutes(d.getMinutes()+1);
    for(var g=0; g<367*24*60 && res.length<count; g++){
      var domOk=sets.dom.has(d.getDate()), dowOk=sets.dow.has(d.getDay()), dayMatch;
      if(sets.domStar&&sets.dowStar) dayMatch=true; else if(sets.domStar) dayMatch=dowOk; else if(sets.dowStar) dayMatch=domOk; else dayMatch=domOk||dowOk;
      if(sets.min.has(d.getMinutes())&&sets.hour.has(d.getHours())&&sets.mon.has(d.getMonth()+1)&&dayMatch) res.push(new Date(d));
      d.setMinutes(d.getMinutes()+1);
    }
    return res;
  }
  function fmtWhen(dt){ return dt.toLocaleString([],{weekday:'short',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}); }
  window.updateCronExplain=function(){
    var el=document.getElementById('cron-desc'), nx=document.getElementById('cron-next');
    if(!el) return;
    var r=analyze(document.getElementById('cron-sched').value);
    if(r.empty){ el.className='text-secondary'; el.innerHTML='<i class="bi bi-magic"></i> Type a schedule (or pick one above) to see what it means.'; nx.textContent=''; return; }
    if(r.error){ el.className='text-danger'; el.textContent='✗ '+r.error; nx.textContent=''; return; }
    el.className='text-info'; el.textContent='“'+r.text+'”';
    if(r.reboot){ nx.textContent='Runs at each boot — no fixed clock time.'; return; }
    var runs=nextRuns(r.sets,3);
    nx.textContent = runs.length ? ('Next: '+runs.map(fmtWhen).join('  ·  ')+'   (your browser’s time — the server may use a different zone)') : 'No upcoming runs within a year.';
  };
})();
document.getElementById('cron-sched').addEventListener('input', updateCronExplain);
document.getElementById('cron-presets').addEventListener('click', function(ev){
  var b=ev.target.closest('[data-cron]'); if(!b) return;
  document.getElementById('cron-sched').value=b.getAttribute('data-cron');
  updateCronExplain();
  document.getElementById('cron-cmd').focus();
});
updateCronExplain();

loadConfig();
browse('');
loadCron();

// ── Alerts & notifications ──
function alertsMsg(t,cls){ var m=document.getElementById('alerts-msg'); if(m){ m.textContent=t||''; m.className='small ms-2 '+(cls||'text-secondary'); } }
function loadAlerts(){
  fetch(MOUNT+'/api/server/'+serverId+'/alerts').then(r=>r.json()).then(function(d){
    var body=document.getElementById('alerts-body'); if(!body) return;
    if(d.error){ document.getElementById('alerts-loading').innerHTML='<span class="text-danger">'+esc(d.error)+'</span>'; return; }  // nosemgrep
    var vals=d.values||{}, html='';
    (d.providers||[]).forEach(function(p){
      var on=String(vals[p.toggle]||'').toLowerCase()==='on';
      html += '<div class="border rounded p-2 mb-2">'
        + '<div class="form-check form-switch mb-1"><input class="form-check-input" type="checkbox" data-alert-toggle="'+escA(p.toggle)+'"'+(on?' checked':'')+'>'
        + '<label class="form-check-label"><strong>'+esc(p.label)+'</strong></label></div>'
        + '<div class="row g-2">';
      (p.fields||[]).forEach(function(f){
        html += '<div class="col-md-6"><label class="form-label small mb-0">'+esc(f.label)+'</label>'
          + '<input type="text" class="form-control form-control-sm font-monospace" data-alert-key="'+escA(f.key)+'" value="'+escA(vals[f.key]||'')+'" spellcheck="false"></div>';
      });
      html += '</div></div>';
    });
    body.innerHTML=html;  // nosemgrep
    document.getElementById('alerts-loading').style.display='none';
    body.style.display='';
  }).catch(function(){ document.getElementById('alerts-loading').innerHTML='<span class="text-danger">Could not load alert settings.</span>'; });
}
function saveAlerts(btn){
  var values={};
  document.querySelectorAll('[data-alert-toggle]').forEach(function(el){ values[el.getAttribute('data-alert-toggle')] = el.checked ? 'on' : 'off'; });
  document.querySelectorAll('[data-alert-key]').forEach(function(el){ values[el.getAttribute('data-alert-key')] = el.value.trim(); });
  if(btn) btn.disabled=true; alertsMsg('Saving…','text-secondary');
  fetch(MOUNT+'/api/server/'+serverId+'/alerts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({values:values})})
    .then(r=>r.json()).then(function(d){ alertsMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger'); if(btn) btn.disabled=false; })
    .catch(function(){ alertsMsg('✗ Save failed','text-danger'); if(btn) btn.disabled=false; });
}
function testAlert(btn){
  if(btn) btn.disabled=true; alertsMsg('Sending a test alert…','text-secondary');
  fetch(MOUNT+'/api/server/'+serverId+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'test-alert'})})
    .then(r=>r.json()).then(function(d){ alertsMsg((d.success?'✓ ':'✗ ')+(d.message||'Sent — check your alert channels.'), d.success?'text-success':'text-danger'); if(btn) btn.disabled=false; })
    .catch(function(){ alertsMsg('✗ Could not send','text-danger'); if(btn) btn.disabled=false; });
}
loadAlerts();

// ── Mods & addons ──
function modsMsg(t,cls){ var m=document.getElementById('mods-msg'); if(m){ m.textContent=t||''; m.className='small '+(cls||'text-secondary'); } }
function modLabel(m){
  // "Name (id)" — id is a safe charset ([A-Za-z0-9._-]) so it's fine inline.
  return esc(m.name||m.id) + ' <span class="text-secondary">('+esc(m.id)+')</span>';
}
function modRow(m, installed){
  // One row per mod: installed → green tick + Remove; not installed → Install. Same place for both.
  var btn = installed
    ? '<button class="btn btn-sm btn-outline-danger"' + _da('modAction', ['remove', m.id, '@self']) + '><i class="bi bi-trash"></i> Remove</button>'
    : '<button class="btn btn-sm btn-outline-primary"' + _da('modAction', ['install', m.id, '@self']) + '><i class="bi bi-download"></i> Install</button>';
  var tick = installed ? '<i class="bi bi-check-circle-fill text-success me-1" title="Installed"></i>' : '';
  return '<div class="d-flex justify-content-between align-items-center border rounded px-2 py-1 gap-2">'
    + '<span class="small"'+(m.desc?' title="'+escA(m.desc)+'"':'')+'>'+tick+modLabel(m)+'</span>'+btn+'</div>';
}
function loadMods(force){
  var load=document.getElementById('mods-loading'), body=document.getElementById('mods-body'),
      uns=document.getElementById('mods-unsupported');
  if(force){ load.style.display=''; body.style.display='none'; uns.style.display='none'; modsMsg(''); }
  fetch(MOUNT+'/api/server/'+serverId+'/mods').then(r=>r.json()).then(function(d){
    if(d.error){ load.innerHTML='<span class="text-danger">'+esc(d.error)+'</span>'; return; }  // nosemgrep
    // This game has no LinuxGSM mods installer (e.g. Call of Duty) — hide the whole card.
    if(d.supported===false){ var card=document.getElementById('mods-card'); if(card) card.style.display='none'; return; }
    var avail=d.available||[], inst=d.installed||[];
    load.style.display='none';
    if(!avail.length && !inst.length){ uns.style.display=''; body.style.display='none'; return; }
    var installedSet={}; inst.forEach(function(m){ installedSet[m.id]=1; });
    // One merged list: the available catalog is the superset; append any installed mod that isn't in
    // the catalog so it stays removable. Each row shows Install or Remove for its current state.
    var byId={}, merged=[];
    avail.concat(inst).forEach(function(m){ if(!byId[m.id]){ byId[m.id]=1; merged.push(m); } });
    document.getElementById('mods-list').innerHTML =  // nosemgrep
      merged.length ? merged.map(function(m){ return modRow(m, !!installedSet[m.id]); }).join('')
      : '<span class="text-secondary small">None available.</span>';
    var n=inst.length;
    document.getElementById('mods-count').textContent =
      n ? (n+' installed · '+merged.length+' available') : (merged.length+' available');
    body.style.display='';
  }).catch(function(){ load.innerHTML='<span class="text-danger">Could not load mods.</span>'; });
}
function modAction(which, id, btn){
  var run = function(){
    var orig=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span>';
    modsMsg((which==='install'?'Installing ':'Removing ')+id+'… this can take a moment.','text-secondary');
    fetch(MOUNT+'/api/server/'+serverId+'/mods',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:which,mod:id})})
      .then(r=>r.json()).then(function(d){
        modsMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
        // The change only loads after a restart. If the panel deferred it (players online / can't
        // confirm empty), offer a one-click force right here.
        if(d.success && d.restart_pending){
          var m=document.getElementById('mods-msg');
          if(m){ m.insertAdjacentHTML('beforeend',
            ' <button class="btn btn-sm btn-warning py-0 px-1 ms-1"' + _da('modRestartNow', ['@self']) + '><i class="bi bi-arrow-clockwise"></i> Restart now</button>'); }
        }
        loadMods(false);
      })
      .catch(function(){ modsMsg('✗ Action failed — connection error','text-danger'); btn.disabled=false; btn.innerHTML=orig; });  // nosemgrep
  };
  if(which==='remove'){
    confirmDialog({title:'Remove mod', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Remove',
      bodyText:'Remove '+id+' from this server?', onConfirm:run});
  } else { run(); }
}
function modRestartNow(btn){
  confirmDialog({title:'Restart server', icon:'arrow-clockwise', confirmClass:'btn-warning', confirmLabel:'Restart now',
    bodyText:'Restart the server now to load the change?\n\nAnyone currently playing will be disconnected.',
    onConfirm:function(){
      btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm"></span> Restarting…';
      fetch(MOUNT+'/api/server/'+serverId+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'restart'})})
        .then(r=>r.json()).then(function(d){
          modsMsg((d.success?'✓ Restarted — the change is now loaded.':'✗ '+(d.message||'Restart failed')), d.success?'text-success':'text-danger');
        })
        .catch(function(){ modsMsg('✗ Restart failed — connection error','text-danger'); });
    }});
}
loadMods(true);

// ── Backups (this server) — superadmin card; reuses the game-backup endpoints ──
function bkFmt(b){ b=b||0; if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(0)+' KB'; if(b<1073741824)return (b/1048576).toFixed(1)+' MB'; if(b<1099511627776)return (b/1073741824).toFixed(1)+' GB'; return (b/1099511627776).toFixed(2)+' TB'; }  // NOPMD
function bkWhen(sec){ try { return new Date(sec*1000).toLocaleString(); } catch(e){ return ''; } }
var _bkPoll = null, _bkDefault = {interval_days:0, keep:2};

function loadBackups(){
  if(!document.getElementById('backup-card')) return;
  fetch(MOUNT+'/api/panel/backup/game/'+serverId+'/info')
    .then(r=>r.json()).then(renderBackups)
    .catch(function(){ /* transient error — keep whatever is already shown */ });
}

function renderBackups(d){
  if(!d || d.error) return;
  var loading=document.getElementById('bk-loading'), wrap=document.getElementById('bk-wrap');
  if(loading) loading.style.display='none';
  if(wrap) wrap.style.display='';
  _bkDefault = d.default || _bkDefault;
  var sc = d.schedule || {interval_days:0, keep:2, interval_set:false, keep_set:false};
  // Don't clobber a select the user is actively changing.
  var iv=document.getElementById('bk-interval'), kp=document.getElementById('bk-keep');
  if(iv && document.activeElement!==iv) iv.value = sc.interval_set ? String(sc.interval_days) : 'default';
  if(kp && document.activeElement!==kp) kp.value = sc.keep_set ? String(sc.keep) : 'default';
  // Disk headroom + a rough projection for the retained set.
  var keepEff=sc.keep, est=d.est_backup||0, disk=d.disk||{free:0,total:0}, parts=[];
  if(disk.total){
    var usedPct=Math.round((disk.total-disk.free)/disk.total*100);
    parts.push('<i class="bi bi-hdd"></i> '+bkFmt(disk.free)+' free of '+bkFmt(disk.total)+' ('+usedPct+'% used)');
    if(est){
      var proj=est*keepEff;
      if(proj>disk.free) parts.push('<span class="text-danger">~'+bkFmt(proj)+' needed to keep '+keepEff+', not enough space</span>');
      else if(proj>disk.free*0.5) parts.push('<span class="text-warning">~'+bkFmt(proj)+' to keep '+keepEff+'</span>');
    }
  }
  var defTxt=(_bkDefault.interval_days>0)?('every '+_bkDefault.interval_days+'d, keep '+_bkDefault.keep):'off';
  parts.push('<span class="text-secondary">Panel default: '+defTxt+'</span>');
  var dk=document.getElementById('bk-disk'); if(dk) dk.innerHTML=parts.join(' &middot; ');  // nosemgrep
  // Live status of any in-flight/last backup.
  var st=document.getElementById('bk-status'), s=d.status;
  if(st){
    if(s && s.running){ st.className='small text-info'; st.innerHTML='<i class="bi bi-arrow-repeat"></i> Backing up…'; }
    else if(s && s.busy){ st.className='small text-warning'; st.innerHTML='<i class="bi bi-people-fill"></i> '+esc(s.msg||'players online — waiting')+' <button class="btn btn-sm btn-outline-warning py-0 px-1 ms-1"' + _da('backupNow', [true]) + '>Back up anyway</button>'; }  // nosemgrep
    else if(s && s.ok===true){ st.className='small text-success'; st.innerHTML='<i class="bi bi-check-circle"></i> '+esc(s.msg||'Backed up'); }  // nosemgrep
    else if(s && s.ok===false){ st.className='small text-danger'; st.innerHTML='<i class="bi bi-x-circle"></i> '+esc(s.msg||'Backup failed'); }  // nosemgrep
    else st.textContent='';
  }
  var nowBtn=document.getElementById('bk-now'); if(nowBtn) nowBtn.disabled=!!(s && s.running);
  // Backup rows.
  var rows=(d.backups||[]).map(function(b){
    var ip=b.in_progress;
    return '<tr>'
      + '<td><span class="font-monospace" style="font-size:.72rem;word-break:break-all;">'+esc(b.name)+'</span>'+(ip?' <span class="badge bg-info">in progress</span>':'')+'</td>'
      + '<td class="text-nowrap">'+bkFmt(b.size)+'</td>'
      + '<td class="text-nowrap" style="font-size:.72rem;">'+esc(bkWhen(b.created))+'</td>'
      + '<td class="text-nowrap">'
      +   (ip?'':('<a class="btn btn-sm btn-outline-secondary py-0 px-1" href="'+MOUNT+'/backup/game/'+serverId+'/download?name='+encodeURIComponent(b.name)+'" title="Download"><i class="bi bi-download"></i></a> '
      +          '<button class="btn btn-sm btn-outline-danger py-0 px-1" title="Delete" data-name="'+esc(b.name)+'"' + _da('deleteBk', ['@self']) + '><i class="bi bi-trash"></i></button>'))
      + '</td></tr>';
  });
  var tb=document.getElementById('bk-rows');
  if(tb) tb.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="4" class="text-secondary text-center py-3">No backups yet.</td></tr>';  // nosemgrep
  // Poll while a backup is running; stop once it finishes.
  var running=s && s.running;
  if(running && !_bkPoll) _bkPoll=setInterval(loadBackups, 4000);
  if(!running && _bkPoll){ clearInterval(_bkPoll); _bkPoll=null; }
}

function saveBkSchedule(){
  var iv=document.getElementById('bk-interval').value, kp=document.getElementById('bk-keep').value;
  fetch(MOUNT+'/api/panel/backup/game/'+serverId+'/schedule',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({interval:iv, keep:kp})})
    .then(r=>r.json()).then(function(d){
      if(d.success){ window.toast('Backup schedule saved','success'); loadBackups(); }
      else window.toast('Could not save schedule','danger');
    }).catch(function(){ window.toast('Could not save schedule','danger'); });
}

function backupNow(force){
  var btn=document.getElementById('bk-now'); if(btn) btn.disabled=true;
  fetch(MOUNT+'/api/panel/backup/game/'+serverId,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({force:!!force})})
    .then(r=>r.json()).then(function(d){
      window.toast(d.message || (d.success?'Backup started':'Could not start backup'), d.success?'success':'warning');
      setTimeout(loadBackups, 800);
      if(!_bkPoll) _bkPoll=setInterval(loadBackups, 4000);   // watch it complete
    })
    .catch(function(){ window.toast('Could not start backup','danger'); if(btn) btn.disabled=false; });
}

function deleteBk(btn){
  var name = btn.getAttribute('data-name') || '';
  confirmDialog({title:'Delete backup', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Delete',
    bodyText:'Delete this backup?\n\n'+name,
    onConfirm:function(){
      btn.disabled=true;
      fetch(MOUNT+'/api/panel/backup/game/'+serverId+'/delete',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({name:name})})
        .then(r=>r.json()).then(function(d){
          window.toast(d.message || (d.success?'Deleted':'Delete failed'), d.success?'success':'danger');
          loadBackups();
        }).catch(function(){ window.toast('Delete failed','danger'); btn.disabled=false; });
    }});
}

loadBackups();
