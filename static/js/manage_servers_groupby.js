// Client-side sort + group-by-host for the Installed Game Servers list.
// Client-side sort + group-by-host for the Installed Game Servers list. Flat view = one sortable
// table. Grouped view = ONE CARD (box) PER HOST, each with its own table. Rows are MOVED (never
// cloned), so their ids + live-poll cells + delegated action handlers all keep working; each server's
// hidden install-progress row travels with it.
(function(){
  var list = document.getElementById('servers-list');
  function flatWrap(){ return list ? list.querySelector('.table-responsive.srv-flat') : null; }
  function flatTable(){ var w = flatWrap(); return w ? w.querySelector('table') : null; }
  function flatBody(){ var t = flatTable(); return t ? t.querySelector('tbody') : null; }
  function boxWrap(){ return document.getElementById('srv-host-boxes'); }
  function grpOn(){ var c = document.getElementById('grp-host'); return !!(c && c.checked); }
  // Every data row, wherever it currently lives (flat table OR a host box), with its progress row.
  function pairs(){
    if (!list) return [];
    return Array.prototype.map.call(list.querySelectorAll('tr[data-name]'), function(d){
      return { d: d, p: document.getElementById('install-row-' + d.id.replace('server-row-','')) };
    });
  }
  var curKey = 'host', curDir = 1;

  function cmp(a, b, key){
    if (key === 'players'){ return (parseInt(a.getAttribute('data-players'),10)||0) - (parseInt(b.getAttribute('data-players'),10)||0); }
    return (a.getAttribute('data-'+key)||'').localeCompare(b.getAttribute('data-'+key)||'', undefined, {sensitivity:'base', numeric:true});
  }
  function sortPairs(ps, key){
    ps.sort(function(x, y){
      if (grpOn()){ var h = cmp(x.d, y.d, 'host'); if (h) return h; }   // host stays primary while grouped
      return cmp(x.d, y.d, key) * curDir;
    });
    return ps;
  }
  // A non-interactive copy of the table header (labels only — no sort handlers/carets) for each box.
  function staticHead(){
    var thead = flatTable().querySelector('thead').cloneNode(true);
    thead.querySelectorAll('th').forEach(function(th){
      th.removeAttribute('data-action'); th.removeAttribute('data-args'); th.removeAttribute('data-sortkey');
      th.style.cursor = ''; var c = th.querySelector('.srv-caret'); if (c) c.remove();
    });
    return thead;
  }
  function buildBoxes(){
    var ft = flatTable(); if (!ft) return;
    var box = boxWrap();
    if (!box){ box = document.createElement('div'); box.id = 'srv-host-boxes'; box.className = 'd-flex flex-column gap-3 p-2'; list.appendChild(box); }
    box.textContent = '';
    var order = [], groups = {};
    sortPairs(pairs(), curKey).forEach(function(pr){
      var h = pr.d.getAttribute('data-host') || '—';
      if (!groups[h]){ groups[h] = []; order.push(h); }
      groups[h].push(pr);
    });
    order.forEach(function(h){
      var card = document.createElement('div'); card.className = 'card';
      var hd = document.createElement('div'); hd.className = 'card-header py-2 d-flex align-items-center gap-2';
      var ic = document.createElement('i'); ic.className = 'bi bi-hdd-network';
      var nm = document.createElement('span'); nm.className = 'fw-semibold'; nm.textContent = h;
      var cnt = document.createElement('span'); cnt.className = 'badge bg-secondary'; cnt.style.fontWeight = 'normal';
      cnt.textContent = groups[h].length + (groups[h].length === 1 ? ' server' : ' servers');
      hd.appendChild(ic); hd.appendChild(nm); hd.appendChild(cnt);
      var tw = document.createElement('div'); tw.className = 'table-responsive';
      var tbl = document.createElement('table'); tbl.className = 'table table-hover mb-0';
      tbl.appendChild(staticHead());
      var tb = document.createElement('tbody');
      groups[h].forEach(function(pr){ tb.appendChild(pr.d); if (pr.p) tb.appendChild(pr.p); });
      tbl.appendChild(tb); tw.appendChild(tbl);
      card.appendChild(hd); card.appendChild(tw); box.appendChild(card);
    });
    var fw = flatWrap(); if (fw) fw.style.display = 'none';
    box.style.display = '';
  }
  function showFlat(){
    var tb = flatBody();
    if (tb){ sortPairs(pairs(), curKey).forEach(function(pr){ tb.appendChild(pr.d); if (pr.p) tb.appendChild(pr.p); }); }
    var box = boxWrap(); if (box){ box.textContent = ''; box.style.display = 'none'; }
    var fw = flatWrap(); if (fw) fw.style.display = '';
  }
  function carets(){
    document.querySelectorAll('#servers-list .srv-flat th[data-sortkey]').forEach(function(th){
      var c = th.querySelector('.srv-caret'); if (!c) return;
      c.textContent = (th.getAttribute('data-sortkey') === curKey) ? (curDir > 0 ? ' ▲' : ' ▼') : '';
    });
  }
  window.sortServers = function(key){
    if (curKey === key) curDir = -curDir; else { curKey = key; curDir = 1; }
    if (grpOn()) buildBoxes(); else showFlat();
    carets();
  };
  window.toggleGroupByHost = function(cb){
    if (cb && cb.checked){ curKey = 'host'; curDir = 1; buildBoxes(); } else { showFlat(); }
    carets();
  };
  // Called by afterServerRefresh after a full #servers-list re-render, to re-box if grouping is on.
  window.regroupAfterRefresh = function(){ if (grpOn()) buildBoxes(); };
  carets();   // reflect the server-side default (host order)
})();

// ── Tags: install-wide labels, created here and assigned per server ─────────────────────────────
// Every tag name that reaches the DOM goes through textContent, never innerHTML: the names are
// user-authored and this page has no other escaping layer. (window.escapeHtml exists for innerHTML
// sinks, but not building one at all is the stronger guarantee.)
(function(){
  var TAGS = [];                      // last known tag list, from /api/tags

  function mp(){ return window.MOUNT || ''; }

  function chip(tag){
    var el = document.createElement('span');
    el.className = 'badge tag-chip';
    el.setAttribute('data-tag-id', tag.id);
    el.setAttribute('data-no-i18n', '');
    if (tag.color) el.style.backgroundColor = tag.color;
    el.textContent = tag.name;
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
      meta.textContent = (tag.server_ids || []).length + ' server(s)'
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
      var have = {}, holder = document.getElementById('msrv-tags-' + serverId);
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

  // MOUNT is set by base.html's footer, after this block is parsed.
  if (document.getElementById('tag-list')){
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function(){ loadTags(); });
    else loadTags();
  }
})();
