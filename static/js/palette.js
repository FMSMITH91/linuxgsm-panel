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
  var ACTION_LABEL = { start: 'Start', restart: 'Restart', stop: 'Stop' };
  var ACTION_ICON = { start: 'bi bi-play-fill', restart: 'bi bi-arrow-clockwise',
                      stop: 'bi bi-stop-fill' };
  var GROUP_ORDER = { pages: 0, sections: 1, servers: 2, actions: 3 };

  // ── Sections: the places INSIDE a page ────────────────────────────────────────────────────
  // The index was sidebar links plus server names, so typing "2fa", "firewall", "invite" or
  // "api token" found nothing — 13 pages and your servers was the whole of it, and everything
  // else had to be navigated to and then scrolled for.
  //
  // `page` is the sidebar href this section lives on, and a section is offered ONLY when that
  // href is in the scraped sidebar. That is the same permission inheritance pages already get:
  // the sidebar is rendered per user and already filtered by has_permission(), so this cannot
  // surface a section of a page the user may not open, and needs no second permission model to
  // keep in step with the first.
  //
  // `kw` is what people actually TYPE, not what the heading says: "mfa" for two-factor, "colour"
  // for branding, "sign out" for sessions. A section nobody can name is a section nobody finds.
  var SECTIONS = [
    { page: '/account',  hash: 'sec-profile',      label: 'Profile & display name',
      kw: 'profile display name username rename' },
    { page: '/account',  hash: 'sec-password',     label: 'Change your password',
      kw: 'password passphrase change credentials' },
    { page: '/account',  hash: 'sec-2fa',          label: 'Two-factor authentication',
      kw: '2fa two factor totp mfa authenticator otp backup codes' },
    { page: '/account',  hash: 'sec-sessions',     label: 'Active sessions',
      kw: 'sessions devices sign out logout revoke signed in' },
    { page: '/account',  hash: 'sec-api',          label: 'API access & tokens',
      kw: 'api token bearer script bot integration curl' },
    { page: '/account',  hash: 'sec-language',     label: 'Your language',
      kw: 'language translate spanish french espanol francais locale' },
    { page: '/account',  hash: 'sec-layout',       label: 'Dashboard layout',
      kw: 'layout dashboard tiles reorder rearrange panels customise customize' },
    { page: '/settings', hash: 'sec-branding',     label: 'Branding & accent colour',
      kw: 'branding colour color accent logo title tagline theme appearance' },
    { page: '/settings', hash: 'sec-localization', label: 'Default language',
      kw: 'language localization default locale translate' },
    { page: '/settings', hash: 'sec-security',     label: 'Sessions & security',
      kw: 'security session timeout remember proxy https cookie hardening' },
    { page: '/users',    hash: 'sec-invites',      label: 'Invite links',
      kw: 'invite invitation onboard new user link signup join' },
    { page: '/servers/manage', hash: 'install-server', label: 'Install a game server',
      kw: 'install new server add game create setup' },
    { page: '/servers/manage', hash: 'sec-tags',   label: 'Server tags',
      kw: 'tag tags label group colour filter' }
  ];

  // Sections that exist on EVERY host page. The host's own id is not knowable here, so these are
  // expanded against the host links the sidebar already lists — which is also what keeps them
  // permission-filtered, and what makes a host added later appear without touching this table.
  // Labelled with the host's name because a panel with three hosts otherwise offers three
  // identical "Firewall" rows.
  var HOST_SECTIONS = [
    { hash: 'sec-firewall',   label: 'Firewall',
      kw: 'firewall ufw port ports open close allow deny block' },
    { hash: 'sec-osupdates',  label: 'OS updates',
      kw: 'os update updates apt upgrade patch security packages' },
    { hash: 'sec-power',      label: 'Power',
      kw: 'power reboot restart shutdown' },
    { hash: 'sec-specs',      label: 'System specs',
      kw: 'specs cpu ram memory disk hardware storage' },
    { hash: 'sec-connection', label: 'Connection & SSH',
      kw: 'ssh connection port key credentials host key retrust' },
    { hash: 'sec-rawlogs',    label: 'Raw logs',
      kw: 'logs journal syslog raw output' },
    { hash: 'sec-ubuntupro',  label: 'Ubuntu Pro',
      kw: 'ubuntu pro esm livepatch subscription attach' }
  ];
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
    var available = pages();
    available.forEach(function (p, i) { consider(p, p.label, 'pages', i); });
    // A section rides on its page's permission: if the sidebar did not offer the page, the
    // section does not exist for this user either. Compared on PATH, so a panel mounted under a
    // sub-path (Tailscale Serve) still matches — the sidebar href carries MOUNT, the table does
    // not, and hardcoding the bare path here would silently index nothing on such an install.
    // One shape for both section tables: the page-level ones and the per-host ones differ only
    // in where the base href comes from and whether the row is qualified by a host name.
    function addSection(sec, baseHref, order, host) {
      consider({
        label: t(sec.label) + (host ? ' — ' + host : ''),
        href: baseHref + '#' + sec.hash,
        icon: 'bi bi-arrow-return-right',
        meta: host || undefined
      // Searched over the label AND the keyword list, so "mfa" finds Two-factor even though the
      // word appears nowhere on screen.
      }, sec.label + ' ' + sec.kw + (host ? ' ' + host : ''), 'sections', order);
    }
    function pathOf(href) {
      return (href || '').split('?')[0].replace(/\/+$/, '');
    }
    var reachable = {};
    available.forEach(function (p) { reachable[pathOf(p.href)] = true; });
    // One set per host in the sidebar. `hosts` come from the same scrape, so a host the user
    // cannot reach contributes nothing.
    //
    // String comparison rather than a RegExp built from window.MOUNT. A non-literal RegExp is a
    // ReDoS shape whatever the input happens to be today (Opengrep flags it as one), and it also
    // meant escaping MOUNT for regex syntax — a second subtlety for no gain. The only pattern
    // here is a run of digits, and that stays a literal.
    //
    // /remote/<id>/manage — the trailing segment is easy to forget: an earlier version matched
    // '/remote/<id>' with no '/manage', found no host at all, and every per-host section silently
    // vanished from the results with nothing failing.
    var hostPrefix = (window.MOUNT || '') + '/remote/';
    var HOST_SUFFIX = '/manage';
    function hostIdOf(path) {
      if (path.slice(0, hostPrefix.length) !== hostPrefix) return null;
      var rest = path.slice(hostPrefix.length);
      if (rest.slice(-HOST_SUFFIX.length) !== HOST_SUFFIX) return null;
      var id = rest.slice(0, rest.length - HOST_SUFFIX.length);
      return /^[0-9]+$/.test(id) ? id : null;
    }
    available.forEach(function (p, hi) {
      var href = pathOf(p.href);
      if (hostIdOf(href) === null) return;
      HOST_SECTIONS.forEach(function (hs, j) {
        addSection(hs, href, 100 + hi * 10 + j, p.label);
      });
    });
    SECTIONS.forEach(function (sec, i) {
      var full = (window.MOUNT || '') + sec.page;
      if (!reachable[pathOf(full)]) return;
      addSection(sec, full, i);
    });
    (servers || []).forEach(function (s, i) {
      consider({
        label: s.name,
        href: (window.MOUNT || '') + '/server/' + s.id,
        icon: 'bi bi-hdd-stack',
        meta: [s.game, s.host].filter(Boolean).join(' · ')
      }, s.name + ' ' + (s.game || '') + ' ' + (s.host || ''), 'servers', i);
      // ...and the things you can DO to it. The palette used to be a way to reach a page, which
      // left "restart it" as search -> land -> find the button -> click. These rows run.
      //
      // `s.actions` is what the SERVER said this user may run (api_palette computes it with the
      // same check the action endpoint makes). Never a client-side guess: a palette offering an
      // action the user cannot perform is a menu of 403s.
      (s.actions || []).forEach(function (act, j) {
        consider({
          label: ACTION_LABEL[act] + ' ' + s.name,
          act: act, sid: s.id, sname: s.name,
          icon: ACTION_ICON[act] || 'bi bi-play-fill',
          meta: [s.game, s.host].filter(Boolean).join(' · ')
        // Matchable by verb OR by name, so "restart" lists every server you could restart and
        // "cod" lists everything you can do to that one.
        }, act + ' ' + s.name + ' ' + (s.game || '') + ' ' + (s.host || ''),
           'actions', i * 10 + j);
      });
    });
    out.sort(function (a, b) {
      if (a.rank !== b.rank) return a.rank - b.rank;
      if (a.group !== b.group) return GROUP_ORDER[a.group] - GROUP_ORDER[b.group];
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
    if (entry.href) li.dataset.href = entry.href;
    if (entry.act) { li.dataset.act = entry.act; li.dataset.sid = entry.sid;
                     li.dataset.sname = entry.sname; }

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
        head.textContent = t(group === 'pages' ? 'Pages'
                            : group === 'sections' ? 'On a page'
                            : group === 'servers' ? 'Game servers' : 'Actions');
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

  // Stop and restart disconnect whoever is playing. The buttons on the page ask first, and a
  // search box must not be the one place where a keystroke skips that — Enter is easy to hit on
  // a row you did not mean to land on. Start is not destructive and runs straight away.
  function runAction(action, id, name) {
    function fire() {
      // No X-CSRFToken here on purpose: panel.js wraps fetch and adds it to every mutating
      // request. Setting it a second time would just be a second place to keep it right.
      fetch((window.MOUNT || '') + '/api/server/' + encodeURIComponent(id) + '/action', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (window.toast) {
            window.toast(d.message || (d.success ? (ACTION_LABEL[action] + ' issued for ' + name)
                                                 : 'Action failed'),
                         d.success ? 'success' : 'danger');
          }
        })
        .catch(function () { if (window.toast) window.toast('Action failed', 'danger'); });
    }
    if ((action === 'stop' || action === 'restart') && window.confirmDialog) {
      window.confirmDialog({
        title: ACTION_LABEL[action], icon: 'exclamation-triangle',
        confirmLabel: ACTION_LABEL[action], confirmClass: 'btn-danger',
        bodyText: ACTION_LABEL[action] + ' ' + name + '? Anyone playing will be disconnected.',
        onConfirm: fire
      });
      return;
    }
    fire();
  }

  function go() {
    if (active < 0 || !items[active]) return;
    var el = items[active];
    var href = el.dataset.href, act = el.dataset.act;
    close();
    // Closed BEFORE acting either way, so the confirm dialog is not stacked under the palette.
    if (act) { runAction(act, el.dataset.sid, el.dataset.sname); return; }
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
