// A Call of Duty server's Mods tab (panel/services/cod_mods.py, panel/routes/cod_mods.py). Loaded after
// server_files.js on a CoD server's Files & Config page only; it uses that file's esc, _tr, browse and
// _uis_sfShow, and the page's serverId, SF_CAN and MOUNT.
// The server loads the mod folder its startparameters' fs_game names. One row per folder found, plus
// "None"; the active one is marked, the others get Use (.fpm-edit: hidden without EDIT_FILES).
var _codModsUpload = '';   // the folder a mod is uploaded into, from the last listing
function codModsMsg(t,cls){ var m=document.getElementById('codmods-msg'); if(m){ m.textContent=t||''; m.className='small '+(cls||'text-secondary'); } }
function _codModRow(label, value, active, missing){
  var right = active
    ? '<span class="btn btn-sm btn-success disabled" aria-disabled="true">'+esc(_tr('Active'))+'</span>'   // a button's height, so a switch moves no row
    : '<button class="btn btn-sm btn-outline-primary fpm-edit"' + _da('codModUse', [value, '@self']) + '>'+esc(_tr('Use'))+'</button>';
  var note = missing ? ' <span class="text-warning">'+esc(_tr('(folder not found)'))+'</span>' : '';
  return '<div class="d-flex justify-content-between align-items-center border rounded px-2 py-1 gap-2">'
    + '<span class="small text-break" data-no-i18n>'+label+note+'</span>'+right+'</div>';
}
function _codModsRows(d){
  var mods=d.mods||[], active=d.active||'', listed=false, rows=[];
  rows.push(_codModRow(esc(_tr('None (the base game)')), '', !active, false));
  mods.forEach(function(m){
    if(m.value===active) listed=true;
    rows.push(_codModRow(esc(m.value), m.value, m.value===active, false));
  });
  if(active && !listed) rows.push(_codModRow(esc(active), active, true, true));
  return rows.join('');
}
function _codModsWhere(where){
  if(where==='extraparams') return _tr('fs_game is set in extraparams, so the panel does not change it here. Change it in the LinuxGSM config.');
  if(where==='secrets') return _tr('startparameters is set in the secrets file, so the panel does not change it here. Change it there.');
  return '';
}
// Where a mod is uploaded, and the line saying so: serverfiles/mods only once that folder exists.
function _codModsUploadHint(d){
  var sub = d.upload_dir==='serverfiles/mods';
  _codModsUpload = (sub && !d.mods_dir) ? 'serverfiles' : (d.upload_dir||'serverfiles');
  if(!sub) return tf('To add a mod, upload its folder (with its .pk3 files) into {dir}.', {dir: _codModsUpload});
  return d.mods_dir ? tf('To add a mod, upload its folder into {dir}.', {dir: d.upload_dir})
                    : _tr("To add a mod, make a folder named mods in serverfiles and upload the mod's folder into it.");
}
function _codModsDraw(d){
  document.getElementById('codmods-list').innerHTML = _codModsRows(d);  // nosemgrep - every value esc()'d in _codModsRows
  var where=document.getElementById('codmods-where');
  where.textContent = _codModsWhere(d.where);
  where.style.display = d.where ? '' : 'none';
  if(d.where) document.querySelectorAll('#codmods-list .fpm-edit').forEach(function(b){ b.remove(); });
  document.getElementById('codmods-upload').textContent = _codModsUploadHint(d);
}
function loadCodMods(force){
  var load=document.getElementById('codmods-loading'), body=document.getElementById('codmods-body');
  if(!load || !body) return Promise.resolve(false);   // not a Call of Duty server: no card
  if(force){ load.style.display=''; load.textContent=_tr('Loading mods…'); body.style.display='none'; codModsMsg(''); }
  return fetch(MOUNT+'/api/server/'+serverId+'/cod-mods').then(r=>r.json()).then(function(d){
    if(!d || d.error){ load.style.display=''; load.textContent=(d && d.error) || _tr('Could not load mods.'); load.className='small text-danger'; return false; }
    load.style.display='none'; _codModsDraw(d); body.style.display=''; return true;
  }).catch(function(){ load.style.display=''; load.textContent=_tr('Could not load mods.'); load.className='small text-danger'; return false; });
}
function codModUse(value, btn){
  if(btn) btn.disabled=true;
  codModsMsg(_tr('Saving…'), 'text-secondary');
  fetch(MOUNT+'/api/server/'+serverId+'/cod-mods',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mod:value})})
    .then(r=>r.json()).then(function(d){
      codModsMsg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'text-success':'text-danger');
      if(!d.success && btn) btn.disabled=false;
      if(d.success){ loadCodMods(false).catch(function(){ /* loadCodMods never rejects */ }); }
    })
    .catch(function(){ codModsMsg('✗ '+_tr('Could not save — connection error'),'text-danger'); if(btn) btn.disabled=false; });
}
function codModsOpenFolder(btn){
  if(btn) btn.blur();
  _uis_sfShow('files');
  browse(_codModsUpload || 'serverfiles');
}
if (SF_CAN.manage) void loadCodMods(true);
