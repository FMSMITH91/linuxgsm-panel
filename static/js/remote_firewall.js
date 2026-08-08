function refreshFirewall() {
  fetch(MOUNT + '/api/remote/' + remoteId + '/firewall')
    .then(r => r.json())
    .then(data => {
      var badge = document.getElementById('ufw-badge');
      badge.textContent = data.enabled ? 'Active' : 'Inactive';
      badge.className = 'badge ' + (data.enabled ? 'bg-success' : 'bg-secondary');

      var listEl = document.getElementById('rules-list');
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
                : '<button class="btn btn-outline-danger btn-sm py-0 px-1"' + _da('deleteGroup', [g.nums, '@self', !!g.warn, (g.protect_reason || '')]) + '><i class="bi bi-x"></i></button>')
            + '</td></tr>';
        });
        html += '</tbody></table>';
        listEl.innerHTML = html;
      } else {
        listEl.innerHTML = '<div class="p-3 text-center text-secondary small">No open ports yet.</div>';
      }
      document.getElementById('rules-count').textContent = openGroups.length + (openGroups.length === 1 ? ' rule' : ' rules');

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
          blocksEl.innerHTML = bh;
        } else {
          blocksEl.innerHTML = '<div class="p-3 text-center text-secondary small">No IPs are blocked.</div>';
        }
        var bc = document.getElementById('blocks-count');
        if (bc) bc.textContent = blockGroups.length + ' blocked';
      }
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
      resultEl.innerHTML = '<span class="text-success">✅ ' + esc(data.message) + '</span>';
      document.getElementById('block-ip').value = '';
      refreshFirewall();
    } else {
      resultEl.innerHTML = '<span class="text-danger">❌ ' + esc(data.message) + '</span>';
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
    body: JSON.stringify({port: parseInt(port), protocol: proto, comment: comment}),
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      resultEl.innerHTML = '<span class="text-success">✅ ' + esc(data.message) + '</span>';
      document.getElementById('new-port').value = '';
      document.getElementById('new-comment').value = '';
      refreshFirewall();
    } else {
      resultEl.innerHTML = '<span class="text-danger">❌ ' + esc(data.message) + '</span>';
    }
  });
}

// Delete a whole rule group (its IPv4 + IPv6 entries). UFW renumbers rules above a
// deleted one, so delete highest-number-first to keep the remaining indices valid.
function deleteGroup(nums, btn, warn, reason) {
  if (!nums || !nums.length) return;
  var msg = warn ? ((reason || 'This may affect your access.') + '\n\nRemove this rule anyway?')
                 : 'Remove this firewall rule?';
  confirmDialog({title:'Remove firewall rule', icon:'shield-exclamation',
    confirmClass: warn ? 'btn-danger' : 'btn-warning', confirmLabel:'Remove', bodyText: msg,
    onConfirm: function(){
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
      var ordered = nums.slice().sort(function(a, b) { return b - a; });
      (function next(i) {
        if (i >= ordered.length) { refreshFirewall(); return; }
        fetch(MOUNT + '/api/remote/' + remoteId + '/firewall/delete-rule', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({num: ordered[i]}),
        })
        .then(r => r.json())
        .then(function(d) { if (!d.success && window.toast) toast(d.message || 'Failed to delete rule', 'danger'); next(i + 1); })
        .catch(function() { next(i + 1); });
      })(0);
    }});
}

function syncPorts(serverId, btn) {
  var orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Detecting…';
  fetch(MOUNT + '/api/server/' + serverId + '/sync-ports', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      if (data.success) { if(window.toast) toast(data.message, 'success'); refreshFirewall(); }
      else if(window.toast) { toast(data.message || 'Failed', 'danger'); }
    })
    .catch(function(){ if(window.toast) toast('Request failed', 'danger'); })
    .finally(function(){ btn.disabled = false; btn.innerHTML = orig; });
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
