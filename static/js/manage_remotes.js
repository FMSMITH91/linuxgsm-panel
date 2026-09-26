// ── Live stats for each remote card ──────────────────────
// One live tailscale-up poll per host. Its only exit used to be the remote reporting
// running:true, so closing the modal or walking away left it polling — an SSH round trip
// per tick — for the life of the page, and every press of the button added another.
var _tsUpPolls = {};
document.addEventListener('DOMContentLoaded', function() {
  var statEls = document.querySelectorAll('[id^="live-stats-"]');
  statEls.forEach(function(el) {
    var id = el.id.replace('live-stats-', '');
    if (id) loadLiveStats(id);
  });
  // Re-attach to any in-progress bootstrap (persists across page reloads / closing).
  document.querySelectorAll('[id^="bootstrap-card-"]').forEach(function(el) {
    var id = el.id.replace('bootstrap-card-', '');
    if (id) watchBootstrap(id);
  });
});

// ── Persistent bootstrap progress on the card ────────────
var _bsTimers = {};
function watchBootstrap(remoteId) {
  if (_bsTimers[remoteId]) return;
  function tick() {
    fetch(MOUNT + '/api/remote/' + remoteId + '/bootstrap-status')
      .then(r => r.json())
      .then(s => {
        var card = document.getElementById('bootstrap-card-' + remoteId);
        if (!card) return;
        if (s.status === 'none') { card.style.display = 'none'; stopWatch(remoteId); return; }
        card.style.display = 'block';
        var step = document.getElementById('bs-step-' + remoteId);
        var bar = document.getElementById('bs-bar-' + remoteId);
        var pct = document.getElementById('bs-pct-' + remoteId);
        var log = document.getElementById('bs-log-' + remoteId);
        if (pct) pct.textContent = (s.total ? s.step + '/' + s.total + ' · ' : '') + s.percent + '% · ' + s.elapsed + 's';
        if (bar) bar.style.width = s.percent + '%';
        if (log && s.log) { log.textContent = s.log.join('\n'); if (log.style.display !== 'none') log.scrollTop = log.scrollHeight; }
        if (s.status === 'rebooting') {
          bar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-warning';
          step.innerHTML = '<i class="bi bi-arrow-clockwise"></i> ' + escapeHtml(s.step_name);  // nosemgrep
        } else if (s.status === 'done') {
          bar.className = 'progress-bar bg-success'; bar.style.width = '100%';
          step.innerHTML = '<i class="bi bi-check-circle-fill text-success"></i> ' + escapeHtml(s.message || 'Prepared & secured!');  // nosemgrep
          var dz = document.getElementById('bs-dismiss-' + remoteId); if (dz) dz.style.display = 'inline';
          stopWatch(remoteId);
          // Update just this remote's live figures instead of reloading the whole page.
          if (typeof loadLiveStats === 'function') loadLiveStats(remoteId);
        } else if (s.status === 'failed') {
          bar.className = 'progress-bar bg-danger';
          step.innerHTML = '<i class="bi bi-x-circle-fill text-danger"></i> ' + escapeHtml(s.message || 'Bootstrap failed');  // nosemgrep
          var df = document.getElementById('bs-dismiss-' + remoteId); if (df) df.style.display = 'inline';
          stopWatch(remoteId);
        } else {
          step.innerHTML = '<i class="bi bi-gear-fill"></i> ' + escapeHtml(s.step_name);  // nosemgrep
        }
      })
      .catch(function(){});
  }
  tick();
  _bsTimers[remoteId] = setInterval(tick, 3000);
}
function stopWatch(id) { if (_bsTimers[id]) { clearInterval(_bsTimers[id]); delete _bsTimers[id]; } }
function toggleBsLog(id) { var l = document.getElementById('bs-log-' + id); if (l) l.style.display = l.style.display === 'none' ? 'block' : 'none'; }
function dismissBootstrap(id) {
  stopWatch(id);
  var card = document.getElementById('bootstrap-card-' + id);
  if (card) card.style.display = 'none';
  fetch(MOUNT + '/api/remote/' + id + '/bootstrap-dismiss', { method: 'POST' }).catch(function(){});
}

function showAddRemote() {
  var el = document.getElementById('add-remote-form');
  el.style.display = el.style.display === 'none' ? '' : 'none';
}

function loadLiveStats(remoteId) {
  var el = document.getElementById('live-stats-' + remoteId);
  if (!el) return;
  fetch(MOUNT + '/api/remote/' + remoteId + '/live-stats')
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        // escapeHtml, like renderTailscaleStatus above: every one
        // of these is raw output read off the REMOTE host — `uptime` is literally whatever
        // `uptime -p` printed, taken as line[7:] with no tokenising — and a host the panel
        // manages is exactly the thing that may be compromised. The CSP stops it becoming script
        // execution; it does not stop markup.
        el.innerHTML = '<i class="bi bi-cpu"></i> CPU: ' + escapeHtml(String(data.cpu_percent)) + '%'  // nosemgrep
          + ' &middot; <i class="bi bi-memory"></i> RAM: ' + escapeHtml(String(data.memory))
          + ' &middot; <i class="bi bi-hdd"></i> ' + escapeHtml(String(data.disk))
          + ' &middot; ' + escapeHtml(String(data.uptime));
        el.dataset.loaded = '1';
      } else if (el.dataset.loaded !== '1') {
        el.innerHTML = '<span class="text-danger">Stats unavailable</span>';
      }  // else: keep the last good stats on a transient failure
    })
    .catch(function() {
      // A blip shouldn't wipe good numbers — only show "Offline" if we never loaded.
      if (el.dataset.loaded !== '1') el.innerHTML = '<span class="text-danger">Offline</span>';
    });
}

// ── Live refresh local server stats ──────────────────────
pollWhenVisible(function() {
  var statEls = document.querySelectorAll('[id^="live-stats-"]');
  statEls.forEach(function(el) {
    var id = el.id.replace('live-stats-', '');
    if (id) { loadLiveStats(id); }   // update in place; no "Refreshing…" flicker
  });
  // (refreshLocalStats and setBar lived here. Every id they wrote to — cpu-pct, cpu-bar, mem-bar,
  //  cpu-detail, mem-pct, mem-detail, load-1/5/15 — is rendered by no template: they belonged to
  //  the old /server-management page, which now renders remote_manage.html. The `if (cpuEl)` guard
  //  meant no user-visible symptom, but 56 lines that read as live code, named a real endpoint and
  //  would mislead the next reader.)
}, 15000);

function toggleCreds(select) {
  var group = document.getElementById('credential-group');
  var label = document.getElementById('cred-label');
  var input = select.closest('form').querySelector('[name="credential"]');
  if (select.value === 'password') {
    group.style.display = '';
    label.textContent = 'Password';
    input.placeholder = 'Enter SSH password';
    input.value = '';
  } else if (select.value === 'tailscale') {
    group.style.display = 'none';
    input.value = '';
  } else {
    group.style.display = '';
    label.textContent = 'SSH Key Path';
    input.placeholder = '~/.ssh/id_rsa';
    input.value = '~/.ssh/id_rsa';
  }
}
function toggleEditCreds(select, id) {
  var group = document.getElementById('edit-cred-group-' + id);
  var input = select.closest('form').querySelector('[name="credential"]');
  if (select.value === 'tailscale') {
    group.style.display = 'none';
    input.value = '';
  } else {
    group.style.display = '';
    input.placeholder = 'Key path or password';
  }
}

// ── Tailscale Bootstrap ─────────────────────────────────

function checkTailscale(remoteId, name) {
  var safe = escapeHtml(name);   // name comes from a data-attribute; escape at every HTML sink
  var html = '<div class="text-center py-4"><i class="bi bi-arrow-repeat"></i> Checking Tailscale status on ' + safe + '...</div>';
  showModal('Tailscale Setup: ' + safe, html);

  fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-check')  // nosemgrep
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        renderTailscaleStatus(remoteId, name, data);
      } else {
        setModalBody('<div class="text-danger">Error: ' + escapeHtml(data.error || 'Unknown') + '</div>');  // nosemgrep
      }
    })
    .catch(function() {
      setModalBody('<div class="text-danger">Connection failed. Is the remote reachable?</div>');
    });
}

function renderTailscaleStatus(remoteId, name, status) {
  var installed = status.installed;
  var running = status.running;
  var safe = escapeHtml(name);   // name is from a data-attribute — escape at each HTML sink

  var html = '';

  // Status badge
  if (status.unreachable) {
    // The probe did not answer (the Tailscale and local transports return "" rather than raising),
    // so "not installed" — with an Install button — would be a guess stated as a reading.
    html += '<div class="alert alert-warning py-2 small"><i class="bi bi-exclamation-triangle"></i> ' + escapeHtml("Couldn't read Tailscale's state on this host — it did not answer. Try again once it is reachable.") + '</div>';  // nosemgrep
  } else if (installed && running) {
    html += '<div class="alert alert-success py-2 small"><i class="bi bi-check-circle"></i> Tailscale is <strong>installed</strong> and <strong>running</strong> on ' + safe + '.</div>';
    // escapeHtml: tailscale_ip and dns_name are parsed out of `tailscale status --json` run on
    // the REMOTE host, so a compromised or hostile host picks these bytes. They land in innerHTML
    // via setModalBody below.
    if (status.tailscale_ip) html += '<p class="small mb-1"><strong>IP:</strong> <code>' + escapeHtml(status.tailscale_ip) + '</code></p>';
    if (status.dns_name) html += '<p class="small mb-1"><strong>DNS:</strong> <code>' + escapeHtml(status.dns_name) + '</code></p>';
    html += '<hr><button class="btn btn-success btn-sm"' + _da('migrateToTailscale', [remoteId]) + '><i class="bi bi-arrow-repeat"></i> Migrate to Tailscale SSH</button>';
  } else if (installed) {
    html += '<div class="alert alert-warning py-2 small"><i class="bi bi-exclamation-triangle"></i> Tailscale is <strong>installed</strong> but <strong>not running</strong>.</div>';
    html += renderAuthKeyForm(remoteId, name);
  } else {
    html += '<div class="alert alert-info py-2 small"><i class="bi bi-info-circle"></i> Tailscale is <strong>not installed</strong> on ' + safe + '.</div>';
    html += '<button class="btn btn-primary btn-sm mb-2" data-install-ts data-ts-remote="' + Number(remoteId) + '" data-ts-name="' + safe + '"><i class="bi bi-download"></i> Install Tailscale</button>';
    html += '<div id="install-log" class="small mt-2"></div>';
  }

  setModalBody(html);
}

function renderAuthKeyForm(remoteId, name) {
  return '<hr>'
    + '<div class="form-check mb-2">'
    + '<input type="checkbox" id="ts-ssh" class="form-check-input" checked>'
    + '<label class="form-check-label small" for="ts-ssh">Enable Tailscale SSH</label>'
    + '</div>'
    + '<div class="mb-2">'
    + '<label class="form-label small">Advertise Routes (optional)</label>'
    + '<input type="text" id="ts-routes" class="form-control form-control-sm" placeholder="e.g. 192.168.1.0/24">'
    + '</div>'
    // Primary: browser login link (no key needed)
    + '<button class="btn btn-success btn-sm"' + _da('tailscaleUp', [remoteId]) + '><i class="bi bi-box-arrow-up-right"></i> Get login link (recommended)</button>'
    + '<div id="ts-up-result" class="small mt-2"></div>'
    // Fallback: pre-auth key
    + '<div class="mt-3"><a href="#" class="small text-secondary"' + _da('_showTsKeyAdv') + '>Advanced: use a pre-auth key instead</a></div>'
    + '<div id="ts-key-adv" style="display:none;" class="mt-2">'
    + '<label class="form-label small">Auth Key (from <a href="https://login.tailscale.com/admin/keys" target="_blank">Tailscale admin</a>)</label>'
    + '<input type="text" id="ts-auth-key" class="form-control form-control-sm mb-2" placeholder="tskey-auth-...">'
    + '<button class="btn btn-outline-success btn-sm"' + _da('bootstrapTailscale', [remoteId]) + '><i class="bi bi-key"></i> Connect with key</button>'
    + '</div>'
    + '<div id="bootstrap-log" class="small mt-2"></div>';
}

function tailscaleUp(remoteId) {
  var ssh = document.getElementById('ts-ssh').checked;
  var routes = document.getElementById('ts-routes').value.trim();
  var el = document.getElementById('ts-up-result');
  el.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Starting Tailscale… getting your login link (a few seconds)…</span>';
  fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-up', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enable_ssh: ssh, advertise_routes: routes })
  })
  .then(r => r.json())
  .then(d => {
    // escapeHtml: both message and url come from a command run ON THE REMOTE HOST, so they are that
    // host's output, not ours. tailscale.html / setup_tailscale.html escape the same value (tsEsc).
    if (!d.success) { el.innerHTML = '<span class="text-danger">' + escapeHtml(d.message || 'Failed') + '</span>'; return; }  // nosemgrep
    if (d.connected) { el.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> Already connected to your tailnet.</span>'; return; }
    el.innerHTML = '<div class="alert alert-info py-2 small mb-2">'  // nosemgrep
      + '<strong>1.</strong> Open this link in your browser and approve the machine:<br>'
      + '<a href="' + escapeHtml(d.url) + '" target="_blank" rel="noopener" class="d-inline-block my-1" style="word-break:break-all;">' + escapeHtml(d.url) + '</a>'
      + ' <button class="btn btn-sm btn-outline-secondary py-0"' + _da('copyText', [d.url]) + '><i class="bi bi-clipboard"></i></button>'
      + '<br><strong>2.</strong> <span id="ts-wait-' + remoteId + '"><i class="bi bi-hourglass-split"></i> Waiting for you to authorize…</span></div>';
    // Poll for connection — with a deadline and a single live timer per host. Its only exit used
    // to be the remote reporting running:true, so the ordinary path (open the link in another tab
    // and come back later, close the modal, give up) left it polling for the life of the page, and
    // each press of the button added another. /api/remote/<id>/tailscale-check is an SSH round
    // trip to the remote host: measured, three clicks and 13s produced four live intervals and
    // nine requests.
    if (_tsUpPolls[remoteId]) clearInterval(_tsUpPolls[remoteId]);
    var _tsDeadline = Date.now() + 5 * 60 * 1000;
    var t = setInterval(function() {
      if (Date.now() > _tsDeadline) {
        clearInterval(t); delete _tsUpPolls[remoteId];
        var wOut = document.getElementById('ts-wait-' + remoteId);
        if (wOut) wOut.innerHTML = '<span class="text-secondary">Still waiting — press the button '
          + 'again once you have approved the machine.</span>';
        return;
      }
      fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-check').then(r => r.json()).then(s => {
        if (s.running) {
          clearInterval(t); delete _tsUpPolls[remoteId];
          var w = document.getElementById('ts-wait-' + remoteId);
          if (w) w.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> Connected! Finalizing (UFW)…</span>';
          // Always allow the tailscale0 interface in UFW, then offer to switch the
          // panel's connect address to Tailscale and drop public SSH.
          fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-finalize', {method:'POST'})
            .then(r => r.json()).then(f => {
              var ip = ((f.tailscale_ip || s.tailscale_ip || '').split(',')[0] || '').trim();
              // Only when the finalize says it happened. The route answers ufw_allowed=false when UFW
              // was inactive, absent or unreadable (so no allow was issued) — and a refused or
              // unreachable finalize carries no such key at all — yet this sentence printed on all
              // of them, about a firewall nobody had touched.
              var ufwText = f.ufw_allowed === true
                ? 'UFW now allows the tailscale0 interface.'
                : 'UFW was not changed: it is inactive, not installed, or could not be read or updated.';
              if (w) w.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> Connected! IP: <code>' + escapeHtml(ip) + '</code>'  // nosemgrep
                + '<br><span class="small">' + escapeHtml(ufwText) + '</span></span>'
                + '<div class="mt-2"><button class="btn btn-success btn-sm"' + _da('migrateToTailscale', [remoteId]) + '>'
                + '<i class="bi bi-arrow-repeat"></i> Migrate to Tailscale SSH</button></div>';
            })
            // escapeHtml here too: the success path above escapes this exact value, and it is the
            // remote host's `tailscale status --json` output either way — a finalize failure does
            // not make it any more trustworthy.
            .catch(function(){ if (w) w.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> Connected! IP: ' + escapeHtml(s.tailscale_ip || '') + '</span>'; });  // nosemgrep
        }
      }).catch(function(){});
    }, 4000);
    _tsUpPolls[remoteId] = t;   // so the next press replaces this one instead of adding to it
  })
  .catch(function() { el.innerHTML = '<span class="text-danger">Connection failed starting Tailscale.</span>'; });
}

function installTailscale(remoteId, name) {
  var logEl = document.getElementById('install-log');
  logEl.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Installing Tailscale on ' + escapeHtml(name) + '...</span>';  // nosemgrep

  fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-install', {method: 'POST'})  // nosemgrep
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        logEl.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> ' + escapeHtml(data.message) + '</span>';  // nosemgrep
        // Show auth form
        var extra = renderAuthKeyForm(remoteId, name);
        logEl.insertAdjacentHTML('afterend', extra);  // nosemgrep
      } else {
        logEl.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle"></i> ' + escapeHtml(data.message) + '</span>'  // nosemgrep
          + (data.log ? '<pre class="text-secondary small mt-1" style="max-height:200px;overflow-y:auto;">' + escapeHtml(data.log.slice(-2000)) + '</pre>' : '');
      }
    })
    .catch(function() {
      logEl.innerHTML = '<span class="text-danger">Error installing Tailscale</span>';
    });
}

function bootstrapTailscale(remoteId) {
  var key = document.getElementById('ts-auth-key').value.trim();
  var ssh = document.getElementById('ts-ssh').checked;
  var routes = document.getElementById('ts-routes').value.trim();
  var logEl = document.getElementById('bootstrap-log');

  if (!key) {
    logEl.innerHTML = '<span class="text-danger">Auth key is required</span>';
    return;
  }
  logEl.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Authenticating to tailnet...</span>';

  fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-bootstrap', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({auth_key: key, enable_ssh: ssh, advertise_routes: routes}),
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      logEl.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> ' + escapeHtml(data.message) + '</span>'  // nosemgrep
        + '<div class="mt-2"><button class="btn btn-success btn-sm"' + _da('migrateToTailscale', [remoteId]) + '><i class="bi bi-arrow-repeat"></i> Migrate to Tailscale SSH</button></div>';
    } else {
      logEl.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle"></i> ' + escapeHtml(data.message) + '</span>'  // nosemgrep
        + (data.log ? '<pre class="text-secondary small mt-1" style="max-height:200px;overflow-y:auto;">' + escapeHtml(data.log.slice(-2000)) + '</pre>' : '');
    }
  })
  .catch(function() {
    logEl.innerHTML = '<span class="text-danger">Error during bootstrap</span>';
  });
}

function migrateToTailscale(remoteId) {
  confirmDialog({title:'Migrate to Tailscale SSH', icon:'arrow-repeat', confirmClass:'btn-success', confirmLabel:'Migrate',
    bodyText:'Switch this remote to use Tailscale SSH? The connection will be updated to use the Tailscale IP/DNS name.',
    onConfirm:function(){ _migrateToTailscale(remoteId); }});
}
function _migrateToTailscale(remoteId) {
  setModalBody('<div class="text-center py-4"><i class="bi bi-arrow-repeat"></i> Migrating connection...</div>');

  fetch(MOUNT + '/api/remote/' + remoteId + '/tailscale-migrate', {method: 'POST'})
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        setModalBody('<div class="text-success"><i class="bi bi-check-circle"></i> ' + escapeHtml(data.message) + '</div>'
          // Same provenance as renderTailscaleStatus: the addresses come back from the remote.
          + '<p class="small mt-2">Old host: <code>' + escapeHtml(data.old_host || '') + '</code><br>'
          + 'New host: <code>' + escapeHtml(data.new_host || '') + '</code><br>'
          + (data.tailscale_ip ? 'Tailscale IP: <code>' + escapeHtml(data.tailscale_ip) + '</code><br>' : '')
          + (data.dns_name ? 'DNS: <code>' + escapeHtml(data.dns_name) + '</code>' : '')
          + '</p>'
          + '<div class="d-flex gap-2 mt-2">'
          + '<button class="btn btn-primary btn-sm"' + _da('refreshRemotesAndClose') + '><i class="bi bi-check-lg"></i> Done</button>'
          + '<button class="btn btn-danger btn-sm"' + _da('closePort22', [remoteId]) + '><i class="bi bi-shield-lock"></i> Close Port 22 (UFW)</button>'
          + '</div>');
      } else {
        setModalBody('<div class="text-danger"><i class="bi bi-x-circle"></i> ' + escapeHtml(data.message) + '</div>');
      }
    })
    .catch(function() {
      setModalBody('<div class="text-danger">Migration failed</div>');
    });
}

function closePort22(remoteId) {
  confirmDialog({title:'Close port 22', icon:'shield-lock', confirmClass:'btn-danger', confirmLabel:'Close port 22',
    bodyText:'Remove port 22 from UFW? This disables public SSH access. Only do this if Tailscale SSH is working.',
    onConfirm:function(){ _closePort22(remoteId); }});
}
function _closePort22(remoteId) {
  setModalBody('<div class="text-center py-4"><i class="bi bi-arrow-repeat"></i> Removing port 22 rule...</div>');
  fetch(MOUNT + '/api/remote/' + remoteId + '/close-port-22', {method: 'POST'})
    .then(r => r.json())
    .then(data => {
      setModalBody('<div class="' + (data.success ? 'text-success' : 'text-danger') + '"><i class="bi bi-' + (data.success ? 'check-circle' : 'x-circle') + '"></i> ' + escapeHtml(data.message) + '</div>'
        + '<button class="btn btn-primary btn-sm mt-2"' + _da('refreshRemotesAndClose') + '><i class="bi bi-check-lg"></i> Done</button>');
    })
    .catch(function() {
      setModalBody('<div class="text-danger"><i class="bi bi-x-circle"></i> Failed to close port 22</div>');
    });
}

// ── VPS Bootstrap ────────────────────────────────────────

function showBootstrap(remoteId, name) {
  var html = '<p class="small text-secondary mb-3">Configure this VPS with one click: system updates, firewall, security hardening, and essential packages.</p>'
    + '<div class="mb-2">'
    + '<label class="form-label small">Timezone</label>'
    + '<input type="text" id="bootstrap-tz" class="form-control form-control-sm" value="UTC" placeholder="UTC">'
    + '</div>'
    + '<div class="mb-2">'
    + '<label class="form-label small">LinuxGSM User (optional)</label>'
    + '<input type="text" id="bootstrap-user" class="form-control form-control-sm" placeholder="e.g. gmodserver">'
    + '<div class="form-text">Creates a locked system user for LinuxGSM.</div>'
    + '</div>'
    + '<div class="form-check mb-2">'
    + '<input type="checkbox" id="bootstrap-ufw" class="form-check-input" checked>'
    + '<label class="form-check-label small" for="bootstrap-ufw">Configure UFW (deny incoming, allow SSH)</label>'
    + '</div>'
    + '<div class="form-check mb-2">'
    + '<input type="checkbox" id="bootstrap-lgsm" class="form-check-input" checked>'
    + '<label class="form-check-label small" for="bootstrap-lgsm">Install LinuxGSM dependencies (Python, bc, 32-bit libs)</label>'
    + '</div>'
    + '<div class="form-check mb-2">'
        + '<input type="checkbox" id="bootstrap-fail2ban" class="form-check-input" checked>'
        + '<label class="form-check-label small" for="bootstrap-fail2ban">Install and configure fail2ban (SSH brute-force protection)</label>'
        + '</div>'
    + '<div class="form-check mb-2">'
        + '<input type="checkbox" id="bootstrap-reboot" class="form-check-input" checked>'
        + '<label class="form-check-label small" for="bootstrap-reboot">Reboot after updates &amp; wait for the server to come back online</label>'
        + '</div>'
        + '<div class="alert alert-warning small py-2 mb-2"><i class="bi bi-exclamation-triangle"></i> Runs a full apt upgrade and (if enabled) reboots the server. This can take 5-15 minutes — you can watch progress live below.</div>'
        + '<button class="btn btn-primary btn-sm" id="bootstrap-run-btn"' + _da('runBootstrap', [remoteId]) + '><i class="bi bi-rocket-takeoff"></i> Prepare &amp; Secure Server</button>'
    + '<div id="bootstrap-progress-wrap" class="mt-3" style="display:none;">'
        + '<div class="d-flex justify-content-between small mb-1"><span id="bootstrap-step" class="text-info" data-remote="' + escapeHtml(String(remoteId)) + '">Starting…</span><span id="bootstrap-pct" class="text-secondary"></span></div>'
        + '<div class="progress" style="height:18px;"><div id="bootstrap-bar" class="progress-bar progress-bar-striped progress-bar-animated" style="width:0%"></div></div>'
        + '<div id="bootstrap-elapsed" class="text-secondary" style="font-size:.7rem;margin-top:4px;"></div>'
      + '</div>'
    + '<pre id="bootstrap-log" class="small mt-2" style="max-height:260px;overflow-y:auto;font-size:.7rem;display:none;background:#0d1117;padding:8px;border-radius:4px;"></pre>';

  showModal('Prepare & Secure: ' + escapeHtml(name), html);   // name from a data-attribute
}

var _bootstrapPoll = null;

function runBootstrap(remoteId) {
  var tz = document.getElementById('bootstrap-tz').value.trim() || 'UTC';
  var username = document.getElementById('bootstrap-user').value.trim();
  var ufw = document.getElementById('bootstrap-ufw').checked;
  var lgsm = document.getElementById('bootstrap-lgsm').checked;
  var fb = document.getElementById('bootstrap-fail2ban') ? document.getElementById('bootstrap-fail2ban').checked : true;
  var reboot = document.getElementById('bootstrap-reboot') ? document.getElementById('bootstrap-reboot').checked : true;
  var btn = document.getElementById('bootstrap-run-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Running…'; }

  document.getElementById('bootstrap-progress-wrap').style.display = 'block';
  var logEl = document.getElementById('bootstrap-log');
  logEl.style.display = 'block';
  logEl.textContent = '';

  fetch(MOUNT + '/api/remote/' + remoteId + '/bootstrap', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({timezone: tz, enable_ufw: ufw, install_lgsm_deps: lgsm, lgsm_user: username, install_fail2ban: fb, reboot: reboot}),
  })
  .then(r => r.json())
  .then(data => {
    if (!data.success) {
      document.getElementById('bootstrap-step').innerHTML = '<span class="text-danger">' + escapeHtml(data.message || 'Failed to start') + '</span>';  // nosemgrep
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-rocket-takeoff"></i> Prepare &amp; Secure Server'; }
      return;
    }
    pollBootstrap(remoteId, btn);
    watchBootstrap(remoteId);  // also show it on the card so it survives closing the modal
  })
  .catch(function() {
    document.getElementById('bootstrap-step').innerHTML = '<span class="text-danger">Connection failed starting bootstrap</span>';
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-rocket-takeoff"></i> Prepare &amp; Secure Server'; }
  });
}

function pollBootstrap(remoteId, btn) {
  if (_bootstrapPoll) clearInterval(_bootstrapPoll);
  var handle = null;
  // Stops THIS poll only. A fetch already in flight when the next pollBootstrap() started lands
  // after _bootstrapPoll names the new interval, and clearing _bootstrapPoll from here would have
  // stopped that one instead.
  function stop() { clearInterval(handle); if (_bootstrapPoll === handle) _bootstrapPoll = null; }
  function tick() {
    fetch(MOUNT + '/api/remote/' + remoteId + '/bootstrap-status')  // nosemgrep
      .then(r => r.json())
      .then(s => {
        var stepEl = document.getElementById('bootstrap-step');
        var barEl = document.getElementById('bootstrap-bar');
        var pctEl = document.getElementById('bootstrap-pct');
        var logEl = document.getElementById('bootstrap-log');
        var elEl = document.getElementById('bootstrap-elapsed');
        // Clear it, don't just bail. showModal() removes any existing #ts-modal before building a
        // new one, so opening the Tailscale check or Prepare on ANY other host deletes this node —
        // and every `done`/`failed` branch that owns a clearInterval sits BELOW this line. The
        // poll then hit /api/remote/<id>/bootstrap-status every 2.5s, bailed here every time, and
        // ran until the page was closed. watchBootstrap keeps the card's own copy alive, so
        // nothing is lost by stopping this one.
        //
        // And the node being THERE is not enough: Prepare on another host builds the same ids, so
        // this poll found them and painted host A's steps, log and "Server prepared & secured!"
        // into the modal titled "Prepare & Secure: B" — over B's own refusal, when B's start was
        // refused. The modal carries the host it was opened for.
        if (!stepEl || stepEl.getAttribute('data-remote') !== String(remoteId)) { stop(); return; }
        // "none" is the job being gone — the panel restarted, or a finished job expired. It was
        // checked ABOVE the teardown and returned without stopping, so the poll ran for the life
        // of the page and the modal sat on its last step with the button stuck at "Running…".
        if (s.status === 'none') {
          stop();
          stepEl.innerHTML = '<span class="text-warning">' + escapeHtml('The panel is no longer tracking this job — it may have restarted. Check the host before running it again.') + '</span>';  // nosemgrep
          if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-rocket-takeoff"></i> Prepare &amp; Secure Server'; }
          return;
        }
        pctEl.textContent = (s.total ? (s.step + '/' + s.total) : '') + '  ' + s.percent + '%';
        barEl.style.width = s.percent + '%';
        elEl.textContent = 'Elapsed: ' + s.elapsed + 's';
        if (s.log && s.log.length) {
          logEl.textContent = s.log.join('\n');
          logEl.scrollTop = logEl.scrollHeight;
        }
        if (s.status === 'rebooting') {
          barEl.className = 'progress-bar progress-bar-striped progress-bar-animated bg-warning';
          stepEl.innerHTML = '<i class="bi bi-arrow-clockwise"></i> ' + escapeHtml(s.step_name);  // nosemgrep
        } else if (s.status === 'done') {
          stop();
          barEl.className = 'progress-bar bg-success'; barEl.style.width = '100%';
          stepEl.innerHTML = '<i class="bi bi-check-circle-fill text-success"></i> ' + escapeHtml(s.message || 'Server prepared & secured!');  // nosemgrep
          pctEl.textContent = '100%';
          if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-check2"></i> Done — Run Again'; }
        } else if (s.status === 'failed') {
          stop();
          barEl.className = 'progress-bar bg-danger';
          stepEl.innerHTML = '<i class="bi bi-x-circle-fill text-danger"></i> ' + escapeHtml(s.message || 'Bootstrap failed');  // nosemgrep
          if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-rocket-takeoff"></i> Retry'; }
        } else {
          stepEl.innerHTML = '<i class="bi bi-gear-fill"></i> ' + escapeHtml(s.step_name);  // nosemgrep
        }
      })
      .catch(function(){ /* transient poll error, keep going */ });
  }
  handle = _bootstrapPoll = setInterval(tick, 2500);
  tick();
}

// ── Modal helpers ──────────────────────────────────────────

function showModal(title, body) {
  var existing = document.getElementById('ts-modal');
  if (existing) existing.remove();

  var modal = document.createElement('div');
  modal.id = 'ts-modal';
  modal.className = 'modal fade';
  modal.setAttribute('tabindex', '-1');
  modal.innerHTML = '<div class="modal-dialog">'  // nosemgrep
    + '<div class="modal-content">'
    + '<div class="modal-header"><h5 class="modal-title">' + title + '</h5><button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div>'
    + '<div class="modal-body" id="ts-modal-body">' + body + '</div>'
    + '<div class="modal-footer"><button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">Close</button></div>'
    + '</div></div>';
  document.body.appendChild(modal);
  new bootstrap.Modal(modal).show();
}

function setModalBody(html) {
  var el = document.getElementById('ts-modal-body');
  if (el) el.innerHTML = html;  // nosemgrep
}

// Close the action modal and pull the fresh remote list into #remotes-list in place — replaces the
// old "Refresh Page" full reload after a Tailscale migrate / close-port-22.
function refreshRemotesAndClose(){
  var modal = document.getElementById('ts-modal');
  if (modal && window.bootstrap){ var mi = bootstrap.Modal.getInstance(modal); if (mi) mi.hide(); }
  if (window.refreshSection) window.refreshSection('#remotes-list', 'afterRemotesRefresh');
}

// The per-remote Tailscale / Prepare buttons (and the generated "Install Tailscale" button) carry
// their remote id + name in data-attributes instead of an inline onclick — so a remote NAME can
// never break out of an attribute/handler, and there's no Jinja inside a JS-parsed context. The id
// is coerced to a Number here (it's only ever used to build request URLs / handler calls).
document.addEventListener('click', function(e){
  var t = e.target;
  var c = t.closest && t.closest('[data-ts-check]');
  if (c) { checkTailscale(Number(c.getAttribute('data-remote-id')), c.getAttribute('data-remote-name')); return; }
  var b = t.closest && t.closest('[data-ts-bootstrap]');
  if (b) { showBootstrap(Number(b.getAttribute('data-remote-id')), b.getAttribute('data-remote-name')); return; }
  var i = t.closest && t.closest('[data-install-ts]');
  if (i) { installTailscale(Number(i.getAttribute('data-ts-remote')), i.getAttribute('data-ts-name')); return; }
  var rm = t.closest && t.closest('.remove-remote-btn');
  if (rm && !rm.disabled) { removeRemote(rm); return; }
});

// AJAX remove remote — styled confirm, then remove the card in place (no full-page reload).
function removeRemote(btn){
  var id = btn.getAttribute('data-remote-id');
  var name = btn.getAttribute('data-remote-name') || '';
  confirmDialog({
    title: 'Delete remote', icon: 'trash', confirmLabel: 'Delete', confirmClass: 'btn-danger',
    // What stays on the host is said here, before the click: the delete forgets the host and never
    // connects to it, so the gamedig tree and weekly root cron the panel installed there remain.
    // Its own line, one literal, so the whole sentence is one catalog entry. A block <span>, not a
    // <p>: confirmDialog puts the body inside a <p> already, and a <p> in a <p> is closed early by
    // the parser, leaving a stray empty paragraph behind the text.
    body: 'Delete <strong>' + escapeHtml(name) + '</strong>? This removes it and all of its game servers from the panel.'
      + '<span class="d-block small text-muted mt-2">'
      + 'Nothing on the host itself is changed: its game servers keep running, and the gamedig tool and weekly cron the panel installed there stay. The README’s “Removing a host” section says how to remove them.'
      + '</span>',
    requirePassword: true,
    requireLabel: 'Enter your account password to confirm:',
    onConfirm: function(pw, api){
      fetch(MOUNT + '/remotes/' + id + '/delete', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ password: pw })
      })
        .then(function(r){ return r.json().then(function(d){ return { status: r.status, d: d || {} }; }); })
        .then(function(res){
          if (res.status === 200 && res.d.success){
            api.close();
            var card = document.getElementById('remote-card-' + id);
            if (card){ card.style.transition = 'opacity .3s'; card.style.opacity = '0';
                       setTimeout(function(){ card.remove(); }, 300); }
            if (window.toast) toast(res.d.message || 'Deleted', 'success');
          } else if (res.status === 403){
            api.error(res.d.message || 'Incorrect password.');
          } else {
            api.error(res.d.message || 'Delete failed.');
          }
        })
        .catch(function(){ api.error('Delete request failed.'); });
    }
  });
}

// After the remotes list is swapped in place (AJAX add / edit / test), re-arm the per-card
// live-stats pollers and re-attach to any in-progress bootstrap on the fresh DOM nodes.
// (loadLiveStats just fetches; watchBootstrap guards against a duplicate timer — both safe to re-run.)
window.afterRemotesRefresh = function(){
  document.querySelectorAll('[id^="live-stats-"]').forEach(function(el){
    var id = el.id.replace('live-stats-', ''); if (id) loadLiveStats(id);
  });
  document.querySelectorAll('[id^="bootstrap-card-"]').forEach(function(el){
    var id = el.id.replace('bootstrap-card-', ''); if (id) watchBootstrap(id);
  });
};
