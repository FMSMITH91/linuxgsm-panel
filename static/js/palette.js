// ── Command palette (Ctrl/⌘+K) ────────────────────────────────────────────────────────────────
// Reaching one game server used to be Dashboard -> Game Servers -> find the row, and there was no
// search anywhere in the panel. This is one box that jumps to any page, host or game server.
//
// WHERE THE INDEX COMES FROM, and why it is two different places:
//
//   Pages and hosts are read out of the SIDEBAR DOM. The sidebar is already rendered per user,
//   already filtered by has_permission(), and already translated by the i18n walker — so scraping
//   it cannot offer a page the user may not open, cannot drift when the nav changes, costs the
//   server nothing, and needs no second translation of the same labels.
//
//   Game servers are not in the sidebar, so they come from /api/palette — fetched ONCE, on first
//   open, and kept. Deliberately not /api/servers: that one refreshes live status with a
//   listening-port scan per remote over SSH, and opening a search box must not reach out to every
//   host the user owns. Fetching lazily also keeps every page render out of it, so the query
//   budget asserted for `/` and /api/servers is untouched.
//
// Rows are built with createElement/textContent rather than innerHTML: a server name is
// user-authored text arriving from an API, and the safe way to put it on the page is to never
// treat it as markup in the first place.
(function () {
  var EL = {};                 // cached element refs, filled on first open
  var servers = null;          // null = not fetched yet; [] = fetched and empty
  var items = [];              // what is currently rendered, in order
  var active = -1;             // index into items, or -1 when the list is empty
  var lastFocus = null;        // what to hand focus back to on close

  function open() {
    var box = document.getElementById('cmdk');
    if (!box) return;
    EL.box = box;
    EL.input = document.getElementById('cmdk-input');
    EL.list = document.getElementById('cmdk-list');
    lastFocus = document.activeElement;
    box.hidden = false;
    EL.input.value = '';
    EL.input.focus();
    render('');
    if (servers === null) loadServers();
  }

  function close() {
    if (!EL.box || EL.box.hidden) return;
    EL.box.hidden = true;
    // Hand focus back to whatever opened the palette, so a keyboard user is not dropped at the
    // top of the document every time they dismiss it.
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) { /* gone */ } }
    lastFocus = null;
  }

  function loadServers() {
    servers = [];   // claim it now: a second open while this is in flight must not re-request
    fetch((window.MOUNT || '') + '/api/palette', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (d) {
        servers = Array.isArray(d) ? d : [];
        if (EL.box && !EL.box.hidden) render(EL.input.value);
      })
      .catch(function () { servers = []; });
  }

  // Every sidebar link, with the section heading above it as its group. Read fresh each time so a
  // nav that changed (a remote added, a permission revoked on reload) is never stale.
  function pages() {
    var out = [];
    var nodes = document.querySelectorAll('.sidebar-nav a[href], .sidebar-user[href]');
    for (var i = 0; i < nodes.length; i++) {
      var a = nodes[i];
      // An explicit title wins over the link's text: the account link reads "Ada Admin · Account"
      // on the page, which is the right thing in a sidebar footer and noise in a result list. Its
      // title ("Account & two-factor auth") is translated by the walker like any other.
      var label = (a.getAttribute('title') || a.textContent || '').replace(/\s+/g, ' ').trim();
      if (!label) continue;
      var icon = a.querySelector('i');
      out.push({
        label: label,
        href: a.getAttribute('href'),
        icon: icon ? icon.className : 'bi bi-arrow-right'
      });
    }
    return out;
  }

  // Rank a candidate against the query. Lower is better; null means "no match at all".
  // A prefix beats a word start beats a bare substring, so typing "se" puts Settings above
  // "Game Servers" above "Users".
  function score(text, q) {
    var t = text.toLowerCase();
    if (!q) return 3;
    var at = t.indexOf(q);
    if (at === 0) return 0;
    if (at > 0) return /[\s\-_/]/.test(t.charAt(at - 1)) ? 1 : 2;
    return null;
  }

  function matches(q) {
    var out = [];
    function consider(entry, haystack, group, order) {
      var s = score(haystack, q);
      if (s === null) return;
      entry.group = group;
      entry.rank = s;
      entry.order = order;
      out.push(entry);
    }
    pages().forEach(function (p, i) { consider(p, p.label, 'pages', i); });
    (servers || []).forEach(function (s, i) {
      consider({
        label: s.name,
        href: (window.MOUNT || '') + '/server/' + s.id,
        icon: 'bi bi-hdd-stack',
        meta: [s.game, s.host].filter(Boolean).join(' · ')
      }, s.name + ' ' + (s.game || '') + ' ' + (s.host || ''), 'servers', i);
    });
    out.sort(function (a, b) {
      if (a.rank !== b.rank) return a.rank - b.rank;
      if (a.group !== b.group) return a.group === 'pages' ? -1 : 1;
      return a.order - b.order;
    });
    return out.slice(0, 40);
  }

  function row(entry, index) {
    var li = document.createElement('li');
    li.className = 'cmdk-item';
    li.id = 'cmdk-opt-' + index;
    li.setAttribute('role', 'option');
    li.setAttribute('aria-selected', 'false');
    li.dataset.href = entry.href;

    var icon = document.createElement('i');
    icon.className = entry.icon;
    icon.setAttribute('aria-hidden', 'true');
    li.appendChild(icon);

    var label = document.createElement('span');
    label.className = 'cmdk-label';
    label.textContent = entry.label;
    // ALWAYS off-limits to the i18n walker, whichever half of the index it came from. A page label
    // was copied out of the sidebar and is already in the user's language; a server name is
    // whatever its owner typed, and the catalogs hold ordinary words like "Online" and "Status",
    // so a server called "Status" would otherwise be renamed on screen.
    label.setAttribute('data-no-i18n', '');
    li.appendChild(label);

    if (entry.meta) {
      var meta = document.createElement('span');
      meta.className = 'cmdk-meta';
      meta.textContent = entry.meta;
      meta.setAttribute('data-no-i18n', '');
      li.appendChild(meta);
    }
    return li;
  }

  function render(q) {
    var found = matches((q || '').toLowerCase().trim());
    EL.list.textContent = '';
    items = [];
    if (!found.length) {
      var empty = document.createElement('li');
      empty.className = 'cmdk-empty';
      empty.textContent = t('Nothing matches that.');
      EL.list.appendChild(empty);
      active = -1;
      EL.input.removeAttribute('aria-activedescendant');
      return;
    }
    var group = null;
    found.forEach(function (entry) {
      if (entry.group !== group) {
        group = entry.group;
        var head = document.createElement('li');
        head.className = 'cmdk-group';
        head.setAttribute('role', 'presentation');
        head.textContent = t(group === 'pages' ? 'Pages' : 'Game servers');
        EL.list.appendChild(head);
      }
      var li = row(entry, items.length);
      EL.list.appendChild(li);
      items.push(li);
    });
    select(0);
  }

  function select(i) {
    if (!items.length) return;
    if (i < 0) i = items.length - 1;
    if (i >= items.length) i = 0;
    if (active >= 0 && items[active]) items[active].setAttribute('aria-selected', 'false');
    active = i;
    items[active].setAttribute('aria-selected', 'true');
    // aria-activedescendant, not focus: the input keeps the caret while a screen reader still
    // announces the row Enter would open.
    EL.input.setAttribute('aria-activedescendant', items[active].id);
    items[active].scrollIntoView({ block: 'nearest' });
  }

  function go() {
    if (active < 0 || !items[active]) return;
    var href = items[active].dataset.href;
    close();
    if (href) window.location.href = href;
  }

  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      var box = document.getElementById('cmdk');
      if (box && !box.hidden) { close(); } else { open(); }
      return;
    }
    if (!EL.box || EL.box.hidden) return;
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); select(active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); select(active - 1); }
    else if (e.key === 'Enter') { e.preventDefault(); go(); }
  });

  document.addEventListener('input', function (e) {
    if (e.target && e.target.id === 'cmdk-input') render(e.target.value);
  });

  document.addEventListener('click', function (e) {
    if (!EL.box || EL.box.hidden) return;
    if (e.target === EL.box) { close(); return; }          // click the backdrop
    var li = e.target.closest ? e.target.closest('.cmdk-item') : null;
    if (li) {
      select(items.indexOf(li));
      go();
    }
  });
  // Keep the pointer and the keyboard agreeing on which row Enter opens.
  document.addEventListener('mousemove', function (e) {
    if (!EL.box || EL.box.hidden || !e.target.closest) return;
    var li = e.target.closest('.cmdk-item');
    if (li && items.indexOf(li) !== active) select(items.indexOf(li));
  });

  // A function EXPRESSION, not `window.openPalette = open`: template_actions_test resolves
  // data-action handlers by scanning for `window.x = function (…)`, and an alias assignment
  // reads to it as an undefined handler.
  window.openPalette = function () { open(); };
})();
