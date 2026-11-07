// A protected rule's reason in the viewer's language. The server sends the English sentence AND the
// fixed template it was built from with its values (firewall.R14A_REASONS): the catalog translates
// the template, then the values (ports) go in. One pass, so a value is never read as a placeholder.
function _fwReason(g) {
  if (!g || !g.protect_reason_key) return (g && g.protect_reason) || '';
  var p = g.protect_reason_params || {};
  var out = t(g.protect_reason_key).replace(/\{(\w+)\}/g, function(m, k) {
    return Object.prototype.hasOwnProperty.call(p, k) ? String(p[k]) : m;
  });
  return /\{\w+\}/.test(out) ? (g.protect_reason || out) : out;
}

function refreshFirewall() {
  // The settings row is read beside the rules, so every repaint after a change shows both.
  refreshFwSettings();
  fetch(MOUNT + '/api/remote/' + remoteId + '/firewall')
    .then(r => r.json())
    .then(data => {
      var badge = document.getElementById('ufw-badge');
      var listEl = document.getElementById('rules-list');
      // A reply that is not a reading at all: a 500 from the panel's catch-all, a 403/404 denial.
      // Those carry `success:false` and a message, but no `unreachable`, no `installed` and no
      // `groups`, so the branches below read them as a reading: "UFW is not installed on this
      // remote.", badge "Inactive", "No open ports yet." and "0 blocked" — after every block,
      // unblock, open, delete and sync, about a host whose firewall nobody read. A reading always
      // says `installed` (remote_ufw_status's every return does); an unreachable reply says so.
      if (_r23c_fwNotRead(badge, data)) return;
      // A host the panel could not reach has no firewall state to report. The endpoint says so —
      // remote_ufw_status returns unreachable:true rather than claiming UFW is installed, and the
      // ConnectionError branch answers the same shape — and the page's template rendered that carefully:
      // badge "Unknown", plus a line saying the rules can't be read. This refresh then threw all
      // of it away: enabled is absent from that payload, so the badge became "Inactive" and the
      // empty groups list became "No open ports yet." Measured against a down host — the page
      // loaded honest and, one refresh later, reported an inactive firewall with nothing open.
      // On this page that is the most alarming possible way to be wrong.
      // The inactive note beside "Blocking an IP denies it on every port" is true only of an
      // inactive UFW, and only once the firewall has been read.
      var inactive = !data.unreachable && data.installed === true && data.enabled !== true;
      var bin = document.getElementById('blocks-inactive-note');
      if (bin) bin.classList.toggle('d-none', !inactive);
      _fwStatusNote(data, inactive);
      if (data.unreachable) {
        badge.textContent = 'Unknown';
        badge.className = 'badge bg-secondary';
        // BOTH lists, and both counts. Only the rules card was repainted, so the Blocked IPs card
        // went on showing the last good read, "3 blocked" with live Unblock buttons, as the
        // current state of a firewall this refresh could not read. A sudo refusal is flagged
        // unreachable as well, and says so rather than blaming the network.
        _fwUnlisted(_fwUnreadWhy(data));
        return;
      }
      badge.textContent = data.enabled ? 'Active' : 'Inactive';
      badge.className = 'badge ' + (data.enabled ? 'bg-success' : 'bg-secondary');
      if (inactive) {
        // An inactive ufw lists no rules at all, stored ones included, so `groups` is [] here for
        // the same reason it is for a host nothing reached: nothing was listed, and nothing is
        // enforced. "No open ports yet." / "0 blocked" said otherwise.
        _fwUnlisted('UFW is inactive, so its rules are neither listed nor enforced.');
        return;
      }

      var groups = data.groups || [];
      var openGroups = groups.filter(function(g) { return !g.is_block; });
      var blockGroups = groups.filter(function(g) { return g.is_block; });
      _fwRenderRules(listEl, openGroups);
      _fwRenderBlocks(blockGroups);
    })
    // The one fetch chain on this page without a rejection handler — every sibling has one, and
    // openPort's was added with a note about "⟳ Opening..." being stuck on screen forever. This
    // runs after EVERY successful mutation (block, unblock, open, delete, sync), so an unreachable
    // host or an expired session (an HTML login page makes r.json() reject) left the rules table
    // showing the pre-change state: a rule you just deleted still listed, with no error anywhere.
    .catch(function(){
      if (window.toast) toast('Could not refresh the firewall rules — the host may be unreachable.',
                              'danger');
    });
}

// When the reply is no reading, paint that and answer true: badge "Unknown", both lists and counts
// unlisted, the status card and a toast saying why. The inactive note is hidden: nothing says UFW
// is inactive.
function _r23c_fwNotRead(badge, data) {
  if (data && (data.unreachable || typeof data.installed === 'boolean')) return false;
  var why = (data && data.message) || t("The firewall could not be read, so its rules can't be shown.");
  badge.textContent = 'Unknown';
  badge.className = 'badge bg-secondary';
  var bin = document.getElementById('blocks-inactive-note');
  if (bin) bin.classList.toggle('d-none', true);
  _fwUnlisted(why);
  // The card's own painter, handed the sentence as a route's own (any code but the network's).
  _fwStatusNote({unreachable: true, code: 'not_read', message: why}, false);
  if (window.toast) toast(why, 'danger');
  return true;
}

// Why a refresh could not list the rules. A changed host key (the panel refused to connect) and a
// read cut off part-way are flagged unreachable too: `code` says which, and the route's own
// sentence, already in the viewer's language, names the way out ("Re-trust host key").
function _fwUnreadWhy(data) {
  if (data.permission_denied) return "Rules can't be read: sudo refused the firewall read on this host.";
  return _fwHostSaid(data) || "Rules can't be read while this host is unreachable.";
}

// The route's sentence for an unreachable read that the network did not cause, or ''.
function _fwHostSaid(data) {
  var why = data.code;
  return (why && why !== 'host_unreachable' && data.message) ? data.message : '';
}

// The UFW status line under the Firewall heading, from the same read the badge and the lists are painted from. It was
// server-rendered only, so a refresh listed a host's rules under a card still saying the host could
// not be reached, and a changed host key read "can't reach" there under lists saying "Re-trust".
// The same states and sentences the standalone page's template had, in its order; the cards are
// painted only from here now (the Network tab makes no read while the page loads).
function _fwStatusNote(data, inactive) {
  var said = _fwHostSaid(data), n = null;
  if (data.permission_denied) {
    n = ['text-warning', 'bi-lock', "The panel reached this host, but sudo refused the firewall read, so its rules can't be shown. Check the panel's sudoers grant on this host."];
  } else if (data.unreachable) {
    // The key icon for a changed host key only: a read cut off part-way (`command_started`) is
    // not a key problem, and showed one.
    n = said ? ['text-warning', data.code === 'host_key_mismatch' ? 'bi-key' : 'bi-exclamation-triangle', said]
      : ['text-secondary', 'bi-plug', "The panel can't reach this host right now, so its firewall can't be read. Rules below are unavailable until it's back."];
  } else if (data.installed !== true) {
    n = ['text-warning', 'bi-exclamation-triangle', 'UFW is not installed on this remote.'];
  } else if (inactive) {
    n = ['text-warning', 'bi-exclamation-triangle', 'UFW is installed but inactive: nothing on this page is enforced, and ufw does not list its stored rules until it is enabled.'];
  }
  var box = document.getElementById('ufw-status-note');
  if (!box) return;
  box.textContent = '';
  if (!n) return;
  var p = document.createElement('p');
  p.className = n[0] + ' small mb-0';
  var icon = document.createElement('i');
  icon.className = 'bi ' + n[1];
  p.appendChild(icon);
  p.appendChild(document.createTextNode(' ' + n[2]));
  box.appendChild(p);
}

// Add a rule's kind, from the card's Open / One source / Rate-limit / Block switch: that kind's fields shown,
// the others hidden. Nothing typed is cleared, so switching back keeps it. The page renders Open
// shown and the others hidden, which is the switch's checked state, so this only runs on a change.
function fwAddMode(mode) {
  document.querySelectorAll('#fw-add [data-fw-mode]').forEach(function(p) {
    p.hidden = p.getAttribute('data-fw-mode') !== mode;
  });
}

// ── Firewall settings: default policies, logging, on/off ─────────────────────────────────────
// What the last settings read said (firewall.remote_ufw_settings), or null when it said nothing
// usable: then every control is disabled and reads Unknown. A change is decided by the server,
// which refuses one that would lock SSH or the panel out; this only asks first and shows the answer.
var _fwSettings = null;
var _FW_SETTING_KEYS = ['incoming', 'outgoing', 'routed', 'logging'];

function refreshFwSettings() {
  if (!document.getElementById('fw-settings')) return;
  fetch(MOUNT + '/api/remote/' + remoteId + '/firewall/settings')
    .then(function(r) { return r.json(); })
    .then(function(d) { _fwPaintSettings(d); })
    .catch(function() { _fwPaintSettings(null); });
}

// One select set to `v`, or to an added "Unknown" and disabled when `v` is not one of its options.
function _fwSelectValue(sel, v) {
  var known = Array.prototype.some.call(sel.options, function(o) { return o.value === v && v !== ''; });
  var unk = null;
  Array.prototype.forEach.call(sel.options, function(o) { if (o.value === '') unk = o; });
  if (!known) {
    if (!unk) {
      unk = document.createElement('option');
      unk.value = '';
      unk.textContent = t('Unknown');
      sel.insertBefore(unk, sel.firstChild);
    }
    sel.value = '';
    sel.disabled = true;
    return;
  }
  if (unk) unk.remove();
  sel.value = v;
  sel.disabled = false;
}

function _fwPaintSettings(d) {
  _fwSettings = (d && d.read_ok && d.installed) ? d : null;
  _FW_SETTING_KEYS.forEach(function(k) {
    var sel = document.getElementById('fw-set-' + k);
    if (sel) _fwSelectValue(sel, _fwSettings ? _fwSettings[k] : null);
  });
  // Routed only where the host forwards: ufw says "disabled" where it does not.
  var rw = document.getElementById('fw-set-routed-wrap');
  if (rw) rw.hidden = !_fwSettings || _fwSettings.routed === 'disabled';
  var btn = document.getElementById('fw-set-enabled'), lbl = document.getElementById('fw-set-enabled-label');
  if (btn && lbl) {
    var on = !!(_fwSettings && _fwSettings.enabled);
    btn.disabled = !_fwSettings;
    btn.className = 'btn btn-sm w-100 ' + (!_fwSettings ? 'btn-outline-secondary' : (on ? 'btn-outline-danger' : 'btn-outline-success'));
    lbl.textContent = t(on || !_fwSettings ? 'Turn off' : 'Turn on');
  }
}

// What each change does, said before it is made: a whole sentence per choice, so each translates.
var _FW_SETTING_COPY = {
  'incoming:allow': 'Let in every incoming connection that no rule refuses? Every port without a rule becomes open to everyone.',
  'incoming:deny': 'Drop every incoming connection that no rule allows? The panel first checks that SSH and the panel itself stay reachable, and refuses if they would not.',
  'incoming:reject': 'Refuse every incoming connection that no rule allows? The panel first checks that SSH and the panel itself stay reachable, and refuses if they would not.',
  'outgoing:allow': 'Let this host connect out to anywhere a rule does not refuse?',
  'outgoing:deny': 'Drop every outgoing connection that no rule allows? Game server downloads, Steam updates and master-server listings stop unless a rule allows them. The panel refuses unless DNS, HTTP and HTTPS out, and its own SSH connections, are allowed.',
  'outgoing:reject': 'Refuse every outgoing connection that no rule allows? Game server downloads, Steam updates and master-server listings stop unless a rule allows them. The panel refuses unless DNS, HTTP and HTTPS out, and its own SSH connections, are allowed.',
  'routed:allow': 'Let this host forward traffic to other machines when no rule refuses it?',
  'routed:deny': 'Drop traffic this host would forward to other machines when no rule allows it?',
  'routed:reject': 'Refuse traffic this host would forward to other machines when no rule allows it?',
  'logging:off': 'Turn firewall logging off?',
  'logging:low': 'Log blocked connections (low)?',
  'logging:medium': 'Log blocked connections, invalid packets and new allowed connections (medium)?',
  'logging:high': 'Log every packet that is not part of an open connection (high)? This can fill the log quickly.',
  'logging:full': 'Log every packet (full)? This fills the log quickly.'
};

// A settings select changed: put it back to what is in force, ask, and apply only on yes.
function fwSettingChange(name, sel) {
  if (!_fwSettings || !sel) return;
  var v = sel.value, cur = _fwSettings[name];
  sel.value = cur;
  if (!v || v === cur) return;
  var body = _FW_SETTING_COPY[name + ':' + v];
  if (!body) return;
  var risky = (name === 'incoming' || name === 'outgoing') && v !== 'allow';
  confirmDialog({title: 'Firewall settings', icon: 'shield-exclamation',
    confirmClass: risky ? 'btn-danger' : 'btn-primary', confirmLabel: 'Apply', bodyText: t(body),
    onConfirm: function() { _fwPostSetting({setting: name, value: v, confirm: true}); }});
}

// Turn UFW on or off, after a confirmation that says what that means.
function fwToggleEnabled() {
  if (!_fwSettings) return;
  var on = !_fwSettings.enabled;
  confirmDialog(on
    ? {title: 'Turn the firewall on', icon: 'shield-check', confirmClass: 'btn-success', confirmLabel: 'Turn on',
       bodyText: t('Turn the firewall on? Its rules and default policies take effect at once. The panel first checks that SSH and the panel itself stay reachable, and refuses if they would not.'),
       onConfirm: function() { _fwPostSetting({setting: 'enabled', value: true, confirm: true}); }}
    : {title: 'Turn the firewall off', icon: 'shield-x', confirmClass: 'btn-danger', confirmLabel: 'Turn off',
       bodyText: t('Turn the firewall off? This host will then accept every connection on every port: no rule on this page is enforced until you turn it back on.'),
       onConfirm: function() { _fwPostSetting({setting: 'enabled', value: false, confirm: true}); }});
}

function _fwPostSetting(body) {
  var out = document.getElementById('fw-settings-msg');
  if (out) out.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> <span>Applying…</span></span>';
  fetch(MOUNT + '/api/remote/' + remoteId + '/firewall/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    if (out) {
      out.innerHTML = d.success                                                          // nosemgrep
        ? '<span class="text-success">✅ ' + esc(d.message) + '</span>'
        : '<span class="text-danger">❌ ' + esc(d.message) + '</span>';
    }
    if (d.settings) _fwPaintSettings(d.settings);
    if (d.success) refreshFirewall();
  })
  .catch(function() {
    if (out) out.innerHTML = '<span class="text-danger">❌ <span>Request failed.</span></span>';   // nosemgrep
    refreshFwSettings();
  });
}

// The open-ports table, or its empty state, and the rule count beside the card title.
function _fwRenderRules(listEl, openGroups) {
  if (openGroups.length) {
    var html = '<table class="table table-sm table-hover mb-0 align-middle table-pin-actions">'
      + '<thead><tr><th>Port</th><th>Protocol</th><th>For</th><th>Scope</th><th>IP</th><th></th></tr></thead><tbody>';
    openGroups.forEach(function(g) {
      var port = g.is_iface
        ? '<span class="badge bg-info text-dark">' + esc(g.port_num) + '</span>'
        : '<code>' + esc(g.port_num) + '</code>';
      var scope = (g.action !== 'ALLOW' ? '<span class="badge bg-danger me-1">' + esc(g.action) + '</span>' : '') + esc(g.scope);
      html += '<tr><td>' + port + '</td>'
        + '<td>' + protoBadge(g.proto_label) + '</td>'
        + '<td class="small" data-no-i18n>' + esc(g.comment || '—') + '</td>'
        + '<td class="small text-secondary">' + scope + '</td>'
        + '<td><span class="text-secondary" style="font-size:.68rem;">' + esc(g.family_label) + '</span></td>'
        + '<td>' + (g.protected
            ? '<button class="btn btn-outline-secondary btn-sm py-0 px-1" disabled title="' + esc(_fwReason(g)) + '"><i class="bi bi-lock-fill"></i></button>'
            : '<button class="btn btn-outline-danger btn-sm py-0 px-1" title="' + esc(_fwDelTitle(g.nums || [])) + '"'
              + _da('deleteGroup', [g.nums, '@self', !!g.warn, _fwReason(g), (g.key || '')]) + '><i class="bi bi-x"></i></button>')
        + '</td></tr>';
    });
    html += '</tbody></table>';
    listEl.innerHTML = html;  // nosemgrep
  } else {
    listEl.innerHTML = '<div class="p-3 text-center text-secondary small">No open ports yet.</div>';
  }
  // The number and the WORD as separate nodes, as the old page's template rendered them. As one
  // text node the result was "3 rules", which is not a catalog key and never can be — so this
  // repaint replaced a translated count with an English one on every refresh. t() is the same
  // catalog the DOM walker uses, so the word is right immediately rather than after the
  // observer catches up.
  var rc = document.getElementById('rules-count');
  if (rc) {
    rc.textContent = openGroups.length + ' ';
    var rw = document.createElement('span');
    rw.textContent = t(openGroups.length === 1 ? 'rule' : 'rules');
    rc.appendChild(rw);
  }
}

// The x's tooltip (and its only accessible name): the rule NUMBERS it removes, called rules, not
// ports. The standalone page's template wrote it; this repaint drew the button without one.
function _fwDelTitle(nums) {
  return t(nums.length > 1 ? 'Remove this rule (rules %s)' : 'Remove this rule (rule %s)').replace('%s', nums.join(', '));
}

// Blocked IPs (on the Security tab): the table or its empty state, and the count.
function _fwRenderBlocks(blockGroups) {
  var blocksEl = document.getElementById('blocks-list');
  if (blocksEl) {
    if (blockGroups.length) {
      // The same table the old page's template drew (table-pin-actions, an address that may break), and its
      // tooltip one translated sentence: "Unblock " + ip was English in every language.
      var bh = '<table class="table table-sm table-hover mb-0 align-middle table-pin-actions">'
        + '<thead><tr><th>IP address</th><th>Source</th><th>Family</th><th></th></tr></thead><tbody>';
      blockGroups.forEach(function(g) {
        bh += '<tr><td><code class="text-break">' + esc(g.block_ip) + '</code></td>'
          + '<td>' + blockBadge(g.comment) + '</td>'
          + '<td><span class="text-secondary" style="font-size:.68rem;">' + esc(g.family_label) + '</span></td>'
          + '<td><button class="btn btn-outline-warning btn-sm py-0 px-1" title="' + esc(tf('Unblock {ip}', {ip: g.block_ip})) + '"'
          + _da('unblockIp', [g.block_ip, '@self']) + '><i class="bi bi-x"></i></button></td></tr>';
      });
      bh += '</tbody></table>';
      blocksEl.innerHTML = bh;  // nosemgrep
    } else {
      blocksEl.innerHTML = '<div class="p-3 text-center text-secondary small">No IPs are blocked.</div>';
    }
    var bc = document.getElementById('blocks-count');
    if (bc) {
      bc.textContent = blockGroups.length + ' ';
      var bw = document.createElement('span');
      bw.textContent = t('blocked');
      bc.appendChild(bw);
    }
  }
}

// Both lists replaced by one sentence, and both counts by an em dash: the state where the rules
// were not listed, so no count or empty-state line can be printed about them. Built as TEXT, never
// concatenated into innerHTML, which also lets i18n.js's observer translate it like the template.
function _fwUnlisted(message) {
  ['rules-list', 'blocks-list'].forEach(function(id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = '';
    var note = document.createElement('div');
    note.className = 'p-3 text-center text-secondary small';
    note.textContent = message;
    el.appendChild(note);
  });
  ['rules-count', 'blocks-count'].forEach(function(id) {
    var c = document.getElementById(id);
    if (c) c.textContent = '\u2014';
  });
}

function blockBadge(c) {
  if (c === 'panel-autoblock') return '<span class="badge bg-info text-dark">Auto</span>';
  if (c === 'panel-block')     return '<span class="badge bg-secondary">Manual</span>';
  // data-no-i18n: an operator's comment ("Game", "Test") is not the panel's text to translate.
  return c ? '<span class="badge bg-dark" data-no-i18n>' + esc(c) + '</span>' : '<span class="text-secondary">—</span>';
}

function blockIp() {
  var ip = document.getElementById('block-ip').value.trim();
  if (!ip) return;
  var resultEl = document.getElementById('block-result');
  resultEl.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Blocking…</span>';
  fetch(MOUNT + '/api/remote/' + remoteId + '/security/block', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip: ip}),
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      resultEl.innerHTML = '<span class="text-success">✅ ' + esc(data.message) + '</span>';  // nosemgrep
      document.getElementById('block-ip').value = '';
      refreshFirewall();
    } else {
      resultEl.innerHTML = '<span class="text-danger">❌ ' + esc(data.message) + '</span>';  // nosemgrep
    }
  })
  // The words in an element of their own: "❌ Request failed" as one node matched no catalog key.
  .catch(function() { resultEl.innerHTML = '<span class="text-danger">❌ <span>Request failed</span></span>'; });
}

function unblockIp(ip, btn) {
  confirmDialog({title: 'Unblock IP', icon: 'shield-check', confirmClass: 'btn-warning', confirmLabel: 'Unblock',
    bodyText: tf('Remove the firewall block on {ip}?', {ip: ip}),
    onConfirm: function() {
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
      fetch(MOUNT + '/api/remote/' + remoteId + '/security/block', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip: ip, unblock: true}),
      })
      .then(r => r.json())
      .then(function(d) { if (!d.success && window.toast) toast(d.message || 'Failed to unblock', 'danger'); refreshFirewall(); })
      .catch(function() { refreshFirewall(); });
    }});
}

function esc(s){ return window.escapeHtml(s); }

function protoBadge(p) {
  if (p === 'TCP')  return '<span class="badge bg-primary">TCP</span>';
  if (p === 'UDP')  return '<span class="badge bg-warning text-dark">UDP</span>';
  if (p === 'BOTH') return '<span class="badge bg-secondary">Both</span>';
  return '<span class="text-secondary">—</span>';
}

function openPort() {
  var port = document.getElementById('new-port').value.trim();
  var proto = document.getElementById('new-proto').value;
  var comment = document.getElementById('new-comment').value.trim();
  if (!port) return;
  var resultEl = document.getElementById('port-result');
  resultEl.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Opening...</span>';

  fetch(MOUNT + '/api/remote/' + remoteId + '/firewall/open', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({port: Number.parseInt(port, 10), protocol: proto, comment: comment,
                          family: _fwValue('new-family', 'both')}),
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      resultEl.innerHTML = '<span class="text-success">✅ ' + esc(data.message) + '</span>';  // nosemgrep
      document.getElementById('new-port').value = '';
      document.getElementById('new-comment').value = '';
      refreshFirewall();
    } else {
      resultEl.innerHTML = '<span class="text-danger">❌ ' + esc(data.message) + '</span>';  // nosemgrep
    }
  })
  // Its siblings blockIp() and _restrictPost() both have one; this did not, so an unreachable
  // host or an expired session (a non-JSON body makes r.json() reject) left "⟳ Opening..." on
  // screen forever with no way to tell whether the rule had been created.
  .catch(function () {
    // The words in their own span: the page's translator looks up a whole text node. Its mark
    // handling covers ✅/❌ too since #428, so the span is no longer needed for that; it is kept so
    // the mark and the sentence stay separate nodes, as on this file's other result lines.
    resultEl.innerHTML = '<span class="text-danger">❌ <span>The request failed — the host may be '
      + 'unreachable, or your session may have expired. Refresh and check the rules.</span></span>';
  });
}

// ── Restrict a port: to one source, or by rate ────────────────────────────────────────────────
// Both post to routes that validate every argument at the privileged boundary (ipaddress for the
// source, a port/range grammar for the port, a fixed choice for the protocol), so nothing typed
// here can reach a command line as anything but those three shapes.
function _restrictPost(path, body, busy) {
  var out = document.getElementById('restrict-result');
  out.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> ' + esc(busy) + '</span>';  // nosemgrep
  fetch(MOUNT + '/api/remote/' + remoteId + path, {  // nosemgrep - same-origin; path is one of the literals below
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  .then(r => r.json())
  .then(data => {
    out.innerHTML = data.success                                                     // nosemgrep
      ? '<span class="text-success">✅ ' + esc(data.message) + '</span>'
      : '<span class="text-danger">❌ ' + esc(data.message) + '</span>';
    if (data.success) refreshFirewall();
  })
  .catch(function () {
    out.innerHTML = '<span class="text-danger">❌ <span>Request failed.</span></span>';   // nosemgrep
  });
}

function _sourceArgs(allow) {
  var src = document.getElementById('src-cidr').value.trim();
  var port = document.getElementById('src-port').value.trim();
  if (!src || !port) return null;
  return {source: src, port: port, protocol: document.getElementById('src-proto').value,
          allow: allow};
}

function allowFromSource() {
  var a = _sourceArgs(true);
  if (a) _restrictPost('/firewall/allow-from', a, t('Adding…'));
}

function removeAllowFromSource() {
  var a = _sourceArgs(false);
  if (a) _restrictPost('/firewall/allow-from', a, t('Removing…'));
}

function _limitArgs(on) {
  var port = document.getElementById('limit-port').value.trim();
  if (!port) return null;
  return {port: port, protocol: document.getElementById('limit-proto').value, limit: on};
}

function limitPort() {
  var a = _limitArgs(true);
  if (a) _restrictPost('/firewall/limit', a, t('Applying…'));
}

function unlimitPort() {
  var a = _limitArgs(false);
  if (a) _restrictPost('/firewall/limit', a, t('Removing…'));
}

// A select's value, or `dflt` when the page has no such control.
function _fwValue(id, dflt) {
  var el = document.getElementById(id);
  return el ? el.value : dflt;
}

// Block a port or range: deny or reject it at the top of the rule list (firewall.remote_ufw_block_port,
// which refuses SSH's ports, the panel's and Tailscale's).
function blockPort() {
  var port = document.getElementById('block-port').value.trim();
  if (!port) return;
  _restrictPost('/firewall/block-port', {port: port, protocol: _fwValue('block-proto', 'tcp'),
                                         family: _fwValue('block-family', 'both'),
                                         action: _fwValue('block-action', 'deny'),
                                         comment: document.getElementById('block-comment').value.trim()},
                t('Blocking…'));
}

// Delete a whole rule group (its IPv4 + IPv6 entries).
//
// A rule NUMBER is a position, and ufw renumbers every rule below one that is inserted or
// removed. This posted the numbers captured when the table was drawn — and the hourly auto-block
// inserts its denies at position 1 and releases them, as does a Block from another tab — so a
// click could delete whatever had moved into that slot: another game's port, or the deny on an
// attacker's address. So the group is looked up again by its identity (`key`, from the server's
// grouping) before EACH delete, and its CURRENT highest number is the one removed. A group that
// is gone, or has become protected, is not deleted at all.
function deleteGroup(nums, btn, warn, reason, key) {
  if (!nums || !nums.length) return;
  var msg = warn ? ((reason || t('This may affect your access.')) + '\n\n' + t('Remove this rule anyway?'))
                 : 'Remove this firewall rule?';
  function _say(text) { if (window.toast) toast(text, 'danger'); }
  confirmDialog({title:'Remove firewall rule', icon:'shield-exclamation',
    confirmClass: warn ? 'btn-danger' : 'btn-warning', confirmLabel:'Remove', bodyText: msg,
    onConfirm: function(){
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
      if (!key) { _say('This page is out of date — reload it and try again.'); refreshFirewall(); return; }
      var budget = nums.length + 2, first = true;   // bounded: never loops on a rule that will not go
      // The clicked group, found again by its identity in a fresh read — or null, once it has said
      // why and repainted, when the read failed, the group is gone, or it has become protected.
      function _groupToDelete(data) {
        if (!data || data.unreachable || !data.groups) {
          _say("Couldn't re-read the firewall, so the rule was not removed.");
          refreshFirewall(); return null;
        }
        var g = data.groups.filter(function(x) { return x.key === key; })[0];
        if (!g || !g.nums || !g.nums.length) {
          if (first) _say('That rule is no longer in the firewall — the list has been refreshed.');
          refreshFirewall(); return null;
        }
        if (g.protected) { _say(_fwReason(g) || 'This rule protects your access to the host and can\'t be removed here.'); refreshFirewall(); return null; }
        return g;
      }
      (function next() {
        fetch(MOUNT + '/api/remote/' + remoteId + '/firewall')
          .then(r => r.json())
          .then(function(data) {
            var g = _groupToDelete(data);
            if (!g) return null;
            budget -= 1;
            if (budget < 0) { refreshFirewall(); return null; }
            first = false;
            return fetch(MOUNT + '/api/remote/' + remoteId + '/firewall/delete-rule', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              // ...and WHICH rule it is, so the server refuses if that number has moved on in
              // the moment between this read and its delete.
              body: JSON.stringify({num: Math.max.apply(null, g.nums), key: key}),
            })
            .then(r => r.json())
            .then(function(d) {
              if (!d.success) { _say(d.message || 'Failed to delete rule'); refreshFirewall(); return; }
              next();
            });
          })
          .catch(function() { _say('Could not remove the rule — the host may be unreachable.'); refreshFirewall(); });
      })();
    }});
}

function syncPorts(serverId, btn) {
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Detecting…';
  fetch(MOUNT + '/api/server/' + serverId + '/sync-ports', { method: 'POST' })  // nosemgrep
    .then(r => r.json())
    .then(data => {
      if (data.success) { if(window.toast) toast(data.message, 'success'); refreshFirewall(); }
      else if(window.toast) { toast(data.message || 'Failed', 'danger'); }
    })
    .catch(function(){ if(window.toast) toast('Request failed', 'danger'); })
    .finally(function(){ btn.disabled = false; btn.innerHTML = orig; })  // nosemgrep
    .catch(function(){ /* failure already reported above; this only stops a throwing cleanup going unhandled */ });
}

// Enter key opens port
var newPortInput = document.getElementById('new-port');
if (newPortInput) {
  newPortInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') openPort();
  });
}

// Enter key blocks the typed port or range
var blockPortInput = document.getElementById('block-port');
if (blockPortInput) {
  blockPortInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') blockPort();
  });
}

// Enter key blocks the typed IP
var blockIpInput = document.getElementById('block-ip');
if (blockIpInput) {
  blockIpInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') blockIp();
  });
}
