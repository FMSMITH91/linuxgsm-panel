// Account page: active-session list and per-session revoke.
// Active Sessions: list this account's login sessions and revoke them individually. Rows are built
// with textContent (never innerHTML) so a spoofed User-Agent can't inject markup. The global fetch
// wrapper adds the CSRF header automatically.
(function(){
  var box = document.getElementById('sessions-list');
  if (!box) return;
  function mp(){ return window.MOUNT || ''; }   // set by base.html, before this file loads
  function rel(iso){
    if(!iso) return '';
    var s = (Date.now() - new Date(iso).getTime())/1000;
    if(s < 60) return 'just now';
    if(s < 3600) return Math.floor(s/60)+' min ago';
    if(s < 86400) return Math.floor(s/3600)+' h ago';
    return Math.floor(s/86400)+' d ago';
  }
  function row(s){
    var wrap = document.createElement('div');
    wrap.className = 'd-flex justify-content-between align-items-center gap-2 border rounded px-2 py-2 mb-2';
    var left = document.createElement('div'); left.style.minWidth = '0';
    var top = document.createElement('div'); top.className = 'small text-truncate';
    var strong = document.createElement('strong'); strong.textContent = s.device || 'Unknown device';
    top.appendChild(strong);
    if(s.current){
      var badge = document.createElement('span'); badge.className = 'badge bg-success ms-2';
      badge.textContent = 'This device'; top.appendChild(badge);
    }
    var sub = document.createElement('div'); sub.className = 'text-secondary text-truncate';
    sub.style.fontSize = '.72rem';
    sub.textContent = (s.ip ? s.ip + ' · ' : '') + 'active ' + rel(s.last_seen);
    left.appendChild(top); left.appendChild(sub); wrap.appendChild(left);
    if(!s.current){
      var btn = document.createElement('button'); btn.type = 'button';
      btn.className = 'btn btn-outline-danger btn-sm text-nowrap'; btn.textContent = 'Revoke';
      btn.addEventListener('click', function(){ revoke(s.id, btn); });
      wrap.appendChild(btn);
    }
    return wrap;
  }
  function load(){
    fetch(mp() + '/api/account/sessions', {cache:'no-store'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        box.textContent = '';
        var list = (d && d.sessions) || [];
        if(!list.length){ box.innerHTML = '<div class="text-secondary small">No active sessions.</div>'; return; }
        list.forEach(function(s){ box.appendChild(row(s)); });
      })
      .catch(function(){ box.innerHTML = '<div class="text-danger small">Couldn\'t load sessions.</div>'; });
  }
  function revoke(id, btn){
    if(btn){ btn.disabled = true; btn.textContent = 'Revoking…'; }
    fetch(mp() + '/api/account/sessions/' + id + '/revoke', {method:'POST', cache:'no-store'})  // nosemgrep
      // Check the STATUS and the envelope. This used to toast "Session revoked" for any parseable
      // body — so a 404 "Session not found" told the user their session had been revoked when it
      // had not. (The route also answered with an `ok` key, which the universal `success === false`
      // guard cannot see; both ends are fixed.)
      .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, d: d || {}}; })
                          .catch(function(){ return {ok: false, d: {}}; }); })
      .then(function(res){
        if(!res.ok || res.d.success === false){
          throw new Error(res.d.message || 'Could not revoke that session');
        }
        if(res.d.current){ location.href = mp() + '/login'; return; }
        if(window.toast) toast('Session revoked', 'success');
        load();
      })
      .catch(function(err){
        if(window.toast) toast(err.message || 'Could not revoke that session', 'danger');
        if(btn){ btn.disabled = false; btn.textContent = 'Revoke'; }
      });
  }
  // Deferred to DOMContentLoaded so the first fetch happens once the page has actually rendered.
  // It used to be deferred because this code was INLINE in the content block, ahead of the
  // window.MOUNT assignment in base.html's footer — that stopped being true when it was extracted
  // into {% block scripts %}, which loads after both MOUNT and panel.js, and a comment describing
  // the old ordering sends the next reader looking for a hazard that is gone.
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', load);
  else load();

})();

// ── Dashboard layout controls ─────────────────────────────────────────────────────────────────
// Their OWN IIFE, not the sessions one above. That block starts with
// `var box = document.getElementById('sessions-list'); if (!box) return;`, so defining these
// inside it made three buttons depend on the sessions list existing on the same page. They happen
// to share account.html today and #sessions-list is unconditional there, so nothing is broken —
// but moving the layout card to a page without the sessions list, or gating that card, would
// silently kill all three with no error anywhere.
(function(){
  function mp(){ return window.MOUNT || ''; }   // set by base.html, before this file loads

// Publish this superadmin's own layout as the panel default. Confirmed because it changes what
// every OTHER account sees on reset (and what new accounts start from).
window.publishDashLayout = function(btn){
  confirmDialog({title:'Publish as the panel default', icon:'broadcast-pin',
    confirmClass:'btn-primary', confirmLabel:'Publish default',
    bodyText:'Make your current dashboard arrangement the default for this panel? New accounts '
           + 'start from it, and anyone who resets their layout returns to it. Users who have '
           + 'arranged their own layout keep theirs.',
    onConfirm:function(){
      fetch(mp() + '/api/settings/ui-default', {method:'POST'})
        .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
        .then(function(res){
          if(!res.ok || !res.d || res.d.success === false) throw new Error((res.d && res.d.message) || '');
          if(window.toast) toast('This is now the panel default.', 'success');
        })
        .catch(function(e){ if(window.toast) toast(e.message || 'Could not publish the default', 'danger'); });
    }});
};

window.clearDashDefault = function(btn){
  confirmDialog({title:'Remove the panel default', icon:'x-circle', confirmClass:'btn-warning',
    confirmLabel:'Remove default',
    bodyText:'Remove this panel’s default layout? Accounts without their own arrangement go '
           + 'back to the built-in order. Nobody’s personal layout is affected.',
    onConfirm:function(){
      fetch(mp() + '/api/settings/ui-default/clear', {method:'POST'})
        .then(function(r){ if(!r.ok) throw 0; return r.json(); })
        .then(function(d){
          if(!d || d.success === false) throw 0;
          if(btn) btn.disabled = true;
          if(window.toast) toast('Panel default removed.', 'success');
        })
        .catch(function(){ if(window.toast) toast('Could not remove the default', 'danger'); });
    }});
};

// Discard this user's saved dashboard order. Confirmed first: it is not recoverable, and on a
// busy install the order may have taken real effort to arrange.
window.resetDashLayout = function(btn){
  confirmDialog({title:'Reset dashboard layout', icon:'arrow-counterclockwise',
    confirmClass:'btn-warning', confirmLabel:'Reset layout',
    bodyText:'Discard your saved panel order and go back to the default? Your other preferences are not affected.',
    onConfirm:function(){
      fetch(mp() + '/api/account/ui-order/reset', {method:'POST'})
        .then(function(r){ if(!r.ok) throw 0; return r.json(); })
        .then(function(d){
          if(!d || d.success === false) throw 0;
          if(btn) btn.disabled = true;
          if(window.toast) toast('Your dashboard is back to the default order.', 'success');
        })
        .catch(function(){ if(window.toast) toast('Could not reset your layout', 'danger'); });
    }});
};
})();
