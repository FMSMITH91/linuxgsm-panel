// ── Server tags ───────────────────────────────────────────────────────────────────────────
// Split out of manage_servers_groupby.js when /servers/manage folded into the dashboard.
// The other half of that file was sortServers/toggleGroupByHost/regroupAfterRefresh, which
// the dashboard does not need: it sorts with sortDashCol and groups by host card natively.
// Those were a second implementation of what the dashboard already did, and they went with
// the page. These two did not — the dashboard filters by tag, so it defines them too.

// ── Tags: install-wide labels, created here and assigned per server ─────────────────────────────
// Every tag name that reaches the DOM goes through textContent, never innerHTML: the names are
// user-authored and this page has no other escaping layer. (window.escapeHtml exists for innerHTML
// sinks, but not building one at all is the stronger guarantee.)
(function(){
  var TAGS = [];                      // last known tag list, from /api/tags

  function mp(){ return window.MOUNT || ''; }

  // Whether a tag mutes alerts, from the authoritative /api/tags list when it has the tag.
  function tagMuted(tag){
    for (var i = 0; i < TAGS.length; i++){
      if (TAGS[i].id === tag.id) return TAGS[i].notify === false;
    }
    return tag.notify === false;
  }

  // Same chip the dashboard renders, muted marker included. It built only the name and colour, and
  // every repaint (opening the tag dialog, even to cancel, and saving) replaced the server-rendered
  // chip — so a server whose alerts a tag mutes stopped showing it.
  function chip(tag){
    var el = document.createElement('span');
    el.className = 'badge tag-chip';
    el.setAttribute('data-tag-id', tag.id);
    el.setAttribute('data-no-i18n', '');
    if (tag.color) el.style.backgroundColor = tag.color;
    el.textContent = tag.name;
    if (tagMuted(tag)){
      el.title = window.t ? window.t('Alerts are muted for this tag') : 'Alerts are muted for this tag';
      var bell = document.createElement('i');
      bell.className = 'bi bi-bell-slash';
      el.appendChild(document.createTextNode(' '));
      el.appendChild(bell);
    }
    return el;
  }

  // One row per tag: chip, how many servers carry it, whether it mutes alerts, and Delete.
  function renderTagList(){
    var box = document.getElementById('tag-list');
    if (!box) return;
    box.textContent = '';
    if (!TAGS.length){
      var empty = document.createElement('span');
      empty.className = 'text-secondary small';
      empty.textContent = 'No tags yet. Add one above, then use the tag button on a server row.';
      box.appendChild(empty);
      return;
    }
    TAGS.forEach(function(tag){
      var row = document.createElement('div');
      row.className = 'd-flex align-items-center gap-2';
      row.appendChild(chip(tag));
      var meta = document.createElement('span');
      meta.className = 'text-secondary small';
      // server_count, not server_ids.length: the ids are only the viewer's servers, and a Delete
      // strips the tag from every server that carries it.
      var count = (typeof tag.server_count === 'number') ? tag.server_count
                                                          : (tag.server_ids || []).length;
      meta.textContent = count + ' server(s)'
                         + (tag.notify ? '' : ' · alerts muted');
      row.appendChild(meta);
      var del = document.createElement('button');
      del.className = 'btn btn-sm btn-link text-danger text-decoration-none ms-auto';
      del.type = 'button';
      del.textContent = 'Delete';
      del.addEventListener('click', function(){ deleteTag(tag); });
      row.appendChild(del);
      box.appendChild(row);
    });
  }

  function loadTags(then){
    fetch(mp() + '/api/tags', {cache: 'no-store'})
      .then(function(r){ if(!r.ok) throw 0; return r.json(); })
      .then(function(d){ TAGS = (d && d.tags) || []; renderTagList(); if (then) then(); })
      .catch(function(){ if (window.toast) toast('Could not load tags', 'danger'); });
  }

  window.createTag = function(btn){
    var nameEl = document.getElementById('tag-name');
    var name = (nameEl.value || '').trim();
    if (!name){ nameEl.focus(); return; }
    btn.disabled = true;
    fetch(mp() + '/api/tags', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: name,
                            color: document.getElementById('tag-color').value,
                            notify: document.getElementById('tag-notify').checked})
    })
      .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, d: d}; }); })
      .then(function(res){
        if (!res.ok || !res.d || res.d.success === false){
          // Surface the server's own message: "already exists" and a rejected name are both
          // things the user can fix, so a generic failure toast would be useless here.
          throw new Error((res.d && res.d.message) || 'Could not create that tag');
        }
        nameEl.value = '';
        loadTags();
        if (window.toast) toast('Tag created', 'success');
      })
      .catch(function(err){ if (window.toast) toast(err.message || 'Could not create that tag', 'danger'); })
      .then(function(){ btn.disabled = false; });
  };

  function deleteTag(tag){
    confirmDialog({title: 'Delete tag', icon: 'tags', confirmClass: 'btn-danger',
      confirmLabel: 'Delete tag',
      bodyText: 'Delete this tag and remove it from every server that carries it? The servers '
                + 'themselves are not touched.',
      onConfirm: function(){
        fetch(mp() + '/api/tags/' + tag.id + '/delete', {method: 'POST'})
          .then(function(r){ if(!r.ok) throw 0; return r.json(); })
          .then(function(d){
            if (!d || d.success === false) throw 0;
            // Drop its chips from every row without a reload.
            document.querySelectorAll('.srv-tags .tag-chip[data-tag-id="' + tag.id + '"]')
              .forEach(function(el){ el.remove(); });
            loadTags();
            if (window.toast) toast('Tag deleted', 'success');
          })
          .catch(function(){ if (window.toast) toast('Could not delete that tag', 'danger'); });
      }});
  }

  // Assignment: a checkbox per tag, current state pre-ticked, saved as the whole set.
  window.editServerTags = function(serverId, btn){
    var row = btn.closest('tr');
    var nameCell = row ? row.querySelector('strong') : null;
    loadTags(function(){
      if (!TAGS.length){
        if (window.toast) toast('Create a tag first — the form is below the server list.', 'info');
        return;
      }
      // Pre-tick from the JUST-FETCHED membership, not from the chips in the row: the row can be
      // stale (another admin tagged this server since page load), and because saving REPLACES the
      // whole set, a stale unticked box would silently delete their change.
      // `msrv-tags-<id>` was the container on the deleted /servers/manage page; the dashboard
      // renders `srv-tags-<id>`. The lookup had been returning null since that page went, so both
      // repaints below were dead code — the row kept its old chips after a save, and the
      // dashboard's tag FILTER reads its truth from those very chips (dashboard.js builds `have`
      // from tr.querySelectorAll('.tag-chip')), so filtering by a tag just added hid the server
      // that now carries it.
      var have = {}, holder = document.getElementById('srv-tags-' + serverId);
      TAGS.forEach(function(tag){
        if ((tag.server_ids || []).indexOf(serverId) !== -1) have[tag.id] = true;
      });
      // Same reason: repaint the row's chips from authoritative data before the dialog opens.
      if (holder){
        holder.textContent = '';
        TAGS.filter(function(t){ return have[t.id]; }).forEach(function(t){ holder.appendChild(chip(t)); });
      }
      var body = document.createElement('div');
      TAGS.forEach(function(tag){
        var line = document.createElement('div');
        line.className = 'form-check';
        var cb = document.createElement('input');
        cb.className = 'form-check-input'; cb.type = 'checkbox';
        cb.id = 'tagcb-' + tag.id; cb.value = tag.id; cb.checked = !!have[tag.id];
        var lab = document.createElement('label');
        lab.className = 'form-check-label'; lab.setAttribute('for', cb.id);
        lab.setAttribute('data-no-i18n', '');
        lab.textContent = tag.name + (tag.notify ? '' : ' (alerts muted)');
        line.appendChild(cb); line.appendChild(lab);
        body.appendChild(line);
      });
      confirmDialog({title: 'Tags for ' + (nameCell ? nameCell.textContent : 'this server'),
        icon: 'tags', confirmClass: 'btn-primary', confirmLabel: 'Save tags', bodyNode: body,
        onConfirm: function(){
          var ids = Array.prototype.slice.call(body.querySelectorAll('input:checked'))
                         .map(function(cb){ return Number(cb.value); });
          fetch(mp() + '/api/server/' + serverId + '/tags', {  // nosemgrep
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({tag_ids: ids})
          })
            .then(function(r){ if(!r.ok) throw 0; return r.json(); })
            .then(function(d){
              if (!d || d.success === false) throw 0;
              if (holder){
                holder.textContent = '';
                (d.tags || []).slice().sort(function(a, b){ return a.name.localeCompare(b.name); })
                  .forEach(function(t){ holder.appendChild(chip(t)); });
              }
              loadTags();
              if (window.toast) toast('Tags saved', 'success');
            })
            .catch(function(){ if (window.toast) toast('Could not save those tags', 'danger'); });
        }});
    });
  };

  // Deferred to DOMContentLoaded so the first fetch waits for the page. (This used to be about
  // window.MOUNT, which base.html's footer set AFTER the inline block this file was extracted
  // from; {% block scripts %} loads after it, so that ordering hazard no longer exists.)
  if (document.getElementById('tag-list')){
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function(){ loadTags(); });
    else loadTags();
  }
})();
