// Reboot-required and OS-update banners. window.LOCAL_HOST_ID is set inline above.
// ── "This host needs a reboot" banners ────────────────────────────────────────────
// After an OS update that needs a reboot, Debian/Ubuntu drop /var/run/reboot-required. Show a
// banner offering: reboot now, or reboot automatically once every game server on the host is empty.
// Generic over a host id — base.html uses it for the panel host; remote_manage for a remote.
window.rebootNagRender = function(el, hostId, label, d){
  var pkgs = (d.packages && d.packages.length)
    ? ' <span class="text-secondary" style="font-size:.8rem;">('+d.packages.slice(0,6).map(escapeHtml).join(', ')+(d.packages.length>6?', …':'')+')</span>' : '';
  var actions = d.pending_empty
    ? '<span class="text-info me-2" style="font-size:.85rem;"><i class="bi bi-hourglass-split"></i> Auto-reboot scheduled once empty</span>'
      + '<button class="btn btn-sm btn-outline-secondary"'+_da('rebootNagCancel',[hostId,label])+'>Cancel</button>'
    : '<button class="btn btn-sm btn-danger"'+_da('rebootNagNow',[hostId,label])+'><i class="bi bi-power"></i> Reboot now</button>'
      + '<button class="btn btn-sm btn-outline-primary"'+_da('rebootNagWhenEmpty',[hostId,label])+'><i class="bi bi-hourglass-split"></i> Reboot when empty</button>';
  el.className = 'alert alert-warning d-flex flex-wrap align-items-center gap-2';
  el.setAttribute('role','alert');
  el.innerHTML = '<i class="bi bi-arrow-clockwise fs-5"></i>'  // nosemgrep - label is escapeHtml output, pkgs is a .map(escapeHtml), actions is literals plus _da()
    + '<div class="flex-grow-1" style="min-width:220px;"><strong>Reboot needed</strong> — '+escapeHtml(label)
    + ' needs to reboot to finish applying system updates'+pkgs+'.</div>'
    + '<div class="d-flex gap-2 flex-wrap">'+actions+'</div>';
};
window.rebootNagCheck = function(hostId, label){
  var box = document.getElementById('reboot-nag'); if(!box || hostId==null) return;
  fetch(MOUNT+'/api/remote/'+hostId+'/reboot-required',{cache:'no-store'})  // nosemgrep
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      var el = document.getElementById('reboot-nag-'+hostId);
      if(!d || !d.required){ if(el) el.remove(); return; }
      if(!el){ el = document.createElement('div'); el.id = 'reboot-nag-'+hostId; el.className='mb-2'; box.appendChild(el); }
      window.rebootNagRender(el, hostId, label, d);
    }).catch(function(){});
};
window.rebootNagNow = function(hostId, label){
  confirmDialog({title:'Reboot '+label, icon:'power', confirmClass:'btn-danger', confirmLabel:'Reboot now',
    bodyText:'Reboot '+label+' now? It — and any game servers running on it — will go down for about a minute, disconnecting anyone connected.',
    onConfirm:function(){
      fetch(MOUNT+'/api/remote/'+hostId+'/reboot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({when_empty:false})})  // nosemgrep
        .then(function(r){return r.json();}).then(function(d){ if(window.toast) toast(d.message||'Reboot requested','info'); })
        .catch(function(){ if(window.toast) toast('Reboot request failed','danger'); });
    }});
};
window.rebootNagWhenEmpty = function(hostId, label){
  confirmDialog({title:'Reboot when empty', icon:'hourglass-split', confirmClass:'btn-primary', confirmLabel:'Schedule it',
    bodyText:'Reboot '+label+' automatically once every game server on it has no players connected? It keeps running until then, and you can cancel any time.',
    onConfirm:function(){
      fetch(MOUNT+'/api/remote/'+hostId+'/reboot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({when_empty:true})})  // nosemgrep
        .then(function(r){return r.json();}).then(function(d){ if(window.toast) toast(d.message||'Scheduled','success'); window.rebootNagCheck(hostId,label); })
        .catch(function(){ if(window.toast) toast('Request failed','danger'); });
    }});
};
window.rebootNagCancel = function(hostId, label){
  fetch(MOUNT+'/api/remote/'+hostId+'/reboot-cancel',{method:'POST'})  // nosemgrep
    .then(function(r){return r.json();}).then(function(d){ if(window.toast) toast(d.message||'Canceled','info'); window.rebootNagCheck(hostId,label); })
    .catch(function(){ if(window.toast) toast('Request failed','danger'); });
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
      var sec = hosts.reduce(function(a,h){ return a + (h.security||0); }, 0);
      // One line per host, so a narrow screen breaks between hosts rather than mid-sentence.
      var rows = hosts.map(function(h){
        // inline-block + padding: a bare inline link is only as tall as its text (16px), which is
        // an unfair target on a phone. This lifts each one to a 24px row without padding the banner.
        return '<div><a class="alert-link" style="display:inline-block;padding:.25rem 0;"'
             + ' href="' + escapeHtml(h.url) + '#os-updates">'
             + escapeHtml(h.name) + '</a> — ' + h.count + ' update' + (h.count===1?'':'s')
             + (h.security ? ' <span class="badge bg-danger" style="font-weight:normal;">'
                             + h.security + ' security</span>' : '') + '</div>';
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
