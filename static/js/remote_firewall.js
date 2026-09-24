function refreshFirewall() {
  fetch(MOUNT + '/api/remote/' + remoteId + '/firewall')
    .then(r => r.json())
    .then(data => {
      var badge = document.getElementById('ufw-badge');
      var listEl = document.getElementById('rules-list');
      // A host the panel could not reach has no firewall state to report. The endpoint says so —
      // remote_ufw_status returns unreachable:true rather than claiming UFW is installed, and the
      // ConnectionError branch answers the same shape — and the TEMPLATE renders that carefully:
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
      if (data.unreachable) {
        badge.textContent = 'Unknown';
        badge.className = 'badge bg-secondary';
        // BOTH lists, and both counts. Only the rules card was repainted, so the Blocked IPs card
        // went on showing the last good read, "3 blocked" with live Unblock buttons, as the
        // current state of a firewall this refresh could not read. A sudo refusal is flagged
        // unreachable as well, and says so rather than blaming the network.
        _fwUnlisted(data.permission_denied
          ? "Rules can't be read: sudo refused the firewall read on this host."
          : "Rules can't be read while this host is unreachable.");
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
      if (openGroups.length) {
        var html = '<table class="table table-sm table-hover mb-0 align-middle">'
          + '<thead><tr><th>Port</th><th>Protocol</th><th>For</th><th>Scope</th><th>IP</th><th></th></tr></thead><tbody>';
        openGroups.forEach(function(g) {
          var port = g.is_iface
            ? '<span class="badge bg-info text-dark">' + esc(g.port_num) + '</span>'
            : '<code>' + esc(g.port_num) + '</code>';
          var scope = (g.action !== 'ALLOW' ? '<span class="badge bg-danger me-1">' + esc(g.action) + '</span>' : '') + esc(g.scope);
          html += '<tr><td>' + port + '</td>'
            + '<td>' + protoBadge(g.proto_label) + '</td>'
            + '<td class="small">' + esc(g.comment || '—') + '</td>'
            + '<td class="small text-secondary">' + scope + '</td>'
            + '<td><span class="text-secondary" style="font-size:.68rem;">' + esc(g.family_label) + '</span></td>'
            + '<td>' + (g.protected
                ? '<button class="btn btn-outline-secondary btn-sm py-0 px-1" disabled title="' + esc(g.protect_reason) + '"><i class="bi bi-lock-fill"></i></button>'
                : '<button class="btn btn-outline-danger btn-sm py-0 px-1"' + _da('deleteGroup', [g.nums, '@self', !!g.warn, (g.protect_reason || ''), (g.key || '')]) + '><i class="bi bi-x"></i></button>')
            + '</td></tr>';
        });
        html += '</tbody></table>';
        listEl.innerHTML = html;  // nosemgrep
      } else {
        listEl.innerHTML = '<div class="p-3 text-center text-secondary small">No open ports yet.</div>';
      }
      // The number and the WORD as separate nodes, matching what the template renders. As one
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

      // Blocked IPs (separate card)
      var blocksEl = document.getElementById('blocks-list');
      if (blocksEl) {
        if (blockGroups.length) {
          var bh = '<table class="table table-sm table-hover mb-0 align-middle">'
            + '<thead><tr><th>IP address</th><th>Source</th><th>Family</th><th></th></tr></thead><tbody>';
          blockGroups.forEach(function(g) {
            bh += '<tr><td><code>' + esc(g.block_ip) + '</code></td>'
              + '<td>' + blockBadge(g.comment) + '</td>'
              + '<td><span class="text-secondary" style="font-size:.68rem;">' + esc(g.family_label) + '</span></td>'
              + '<td><button class="btn btn-outline-warning btn-sm py-0 px-1" title="Unblock ' + esc(g.block_ip) + '"'
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
  return c ? '<span class="badge bg-dark">' + esc(c) + '</span>' : '<span class="text-secondary">—</span>';
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
  .catch(function() { resultEl.innerHTML = '<span class="text-danger">❌ Request failed</span>'; });
}

function unblockIp(ip, btn) {
  confirmDialog({title: 'Unblock IP', icon: 'shield-check', confirmClass: 'btn-warning', confirmLabel: 'Unblock',
    bodyText: 'Remove the firewall block on ' + ip + '?',
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
    body: JSON.stringify({port: parseInt(port, 10), protocol: proto, comment: comment}),
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
    resultEl.innerHTML = '<span class="text-danger">❌ The request failed — the host may be '
      + 'unreachable, or your session may have expired. Refresh and check the rules.</span>';
  });
}

// ── Restrict a port: to one source, or by rate ────────────────────────────────────────────────
// Both post to routes that validate every argument at the privileged boundary (ipaddress for the
// source, a port/range grammar for the port, a fixed choice for the protocol), so nothing typed
// here can reach a command line as anything but those three shapes.
function _restrictPost(path, body, busy) {
  var out = document.getElementById('restrict-result');
  out.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> ' + esc(busy) + '</span>';  // nosemgrep
  fetch(MOUNT + '/api/remote/' + remoteId + path, {  // nosemgrep - same-origin; path is one of two literals above
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
    out.innerHTML = '<span class="text-danger">❌ Request failed.</span>';           // nosemgrep
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
  if (a) _restrictPost('/firewall/allow-from', a, 'Adding...');
}

function removeAllowFromSource() {
  var a = _sourceArgs(false);
  if (a) _restrictPost('/firewall/allow-from', a, 'Removing...');
}

function _limitArgs(on) {
  var port = document.getElementById('limit-port').value.trim();
  if (!port) return null;
  return {port: port, protocol: document.getElementById('limit-proto').value, limit: on};
}

function limitPort() {
  var a = _limitArgs(true);
  if (a) _restrictPost('/firewall/limit', a, 'Applying...');
}

function unlimitPort() {
  var a = _limitArgs(false);
  if (a) _restrictPost('/firewall/limit', a, 'Removing...');
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
  var msg = warn ? ((reason || 'This may affect your access.') + '\n\nRemove this rule anyway?')
                 : 'Remove this firewall rule?';
  function _say(text) { if (window.toast) toast(text, 'danger'); }
  confirmDialog({title:'Remove firewall rule', icon:'shield-exclamation',
    confirmClass: warn ? 'btn-danger' : 'btn-warning', confirmLabel:'Remove', bodyText: msg,
    onConfirm: function(){
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
      if (!key) { _say('This page is out of date — reload it and try again.'); refreshFirewall(); return; }
      var budget = nums.length + 2, first = true;   // bounded: never loops on a rule that will not go
      (function next() {
        fetch(MOUNT + '/api/remote/' + remoteId + '/firewall')
          .then(r => r.json())
          .then(function(data) {
            if (!data || data.unreachable || !data.groups) {
              _say("Couldn't re-read the firewall, so the rule was not removed.");
              refreshFirewall(); return;
            }
            var g = data.groups.filter(function(x) { return x.key === key; })[0];
            if (!g || !g.nums || !g.nums.length) {
              if (first) _say('That rule is no longer in the firewall — the list has been refreshed.');
              refreshFirewall(); return;
            }
            if (g.protected) { _say(g.protect_reason || 'This rule protects your access to the host and can\'t be removed here.'); refreshFirewall(); return; }
            if (budget-- <= 0) { refreshFirewall(); return; }
            first = false;
            return fetch(MOUNT + '/api/remote/' + remoteId + '/firewall/delete-rule', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({num: Math.max.apply(null, g.nums)}),
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
    .finally(function(){ btn.disabled = false; btn.innerHTML = orig; });  // nosemgrep
}

// Enter key opens port
document.getElementById('new-port').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') openPort();
});

// Enter key blocks the typed IP
var blockIpInput = document.getElementById('block-ip');
if (blockIpInput) {
  blockIpInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') blockIp();
  });
}
