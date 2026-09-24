// Tailscale status page.
// Delegates — the old fallback returned the RAW string when the global was missing.
function tsEsc(s){ return window.escapeHtml(s); }

// Shared "bring Tailscale up + show the login link" flow. Used both by the first-time
// install button (not-installed state) and the "Link this machine" button (installed but
// NeedsLogin/Stopped) so a user who skipped the link step can always get a fresh link.
var _tsUpPoll = null;   // only one at a time — see the note inside tsUp
function tsUp(outEl, btn){
  outEl.innerHTML = '<i class="bi bi-arrow-repeat"></i> Starting Tailscale…';
  fetch(MOUNT + '/api/tailscale/up', {method:'POST'}).then(function(r){return r.json();}).then(function(d){
    if(!d.success){ outEl.innerHTML = '<span class="text-danger">' + tsEsc(d.message || 'Failed') + '</span>'; if(btn) btn.disabled = false; return; }  // nosemgrep - tsEsc is window.escapeHtml
    if(d.connected){ outEl.innerHTML = '<span class="text-success"><i class="bi bi-check-circle"></i> Connected!</span>'; setTimeout(function(){ window.refreshSection('#ts-page','wireTsButtons'); }, 900); return; }
    outEl.innerHTML = '<div class="alert alert-info py-2 small mb-0 text-start">'  // nosemgrep - literals plus auth_url, tsEsc-wrapped in both text places and _da()-encoded in the button
      + '<strong>1.</strong> Open this link and approve this machine in your Tailscale account:<br>'
      + '<a href="' + tsEsc(d.auth_url) + '" target="_blank" rel="noopener" style="word-break:break-all;">' + tsEsc(d.auth_url) + '</a>'
      + ' <button type="button" class="btn btn-sm btn-outline-secondary py-0"' + _da('_copyDataU', ['@self']) + ' data-u="' + tsEsc(d.auth_url) + '"><i class="bi bi-clipboard"></i></button><br>'
      + '<strong>2.</strong> <span id="ts-wait"><i class="bi bi-hourglass-split"></i> Waiting for you to authorize…</span></div>';
    // One live poll, with a deadline. Its only exit was the host reporting running:true, so the
    // ordinary path — open the link in another tab, come back later, or give up — left it hitting
    // /api/tailscale every 4s for the life of the page, and every press of the button added
    // another.
    if (_tsUpPoll) clearInterval(_tsUpPoll);
    var _deadline = Date.now() + 5 * 60 * 1000;
    var t = setInterval(function(){
      if (Date.now() > _deadline) {
        clearInterval(t); _tsUpPoll = null;
        var w = document.getElementById('ts-wait');
        if (w) w.innerHTML = '<span class="text-secondary">Still waiting — press the button again '
          + 'once you have approved this machine.</span>';
        return;
      }
      fetch(MOUNT + '/api/tailscale').then(function(r){return r.json();}).then(function(s){
        if(s.running){ clearInterval(t); _tsUpPoll = null;
                       window.refreshSection('#ts-page','wireTsButtons'); }
      }).catch(function(){});
    }, 4000);
    _tsUpPoll = t;
  }).catch(function(){ outEl.innerHTML = '<span class="text-danger">Request failed.</span>'; if(btn) btn.disabled = false; });
}

// Wire the buttons/inputs that use direct listeners (install / connect / peer-check Enter). Called
// on load AND after the page is swapped in place via refreshSection('#ts-page', ...), so the fresh
// elements get their handlers back — the alternative to a full-page reload.
function wireTsButtons(){
  // First-time install button: install Tailscale on the panel host, then bring it up.
  var tsInstallBtn = document.getElementById('ts-install-btn');
  if (tsInstallBtn) {
    var tsInstallOut = document.getElementById('ts-install-out');
    tsInstallBtn.addEventListener('click', function(){
      tsInstallBtn.disabled = true;
      tsInstallOut.innerHTML = '<i class="bi bi-arrow-repeat"></i> Installing Tailscale on the panel host… (up to a minute)';
      fetch(MOUNT + '/api/tailscale/install', {method:'POST'}).then(function(r){return r.json();}).then(function(d){
        if(!d.success){ tsInstallOut.innerHTML = '<span class="text-danger">Install failed: ' + tsEsc((d.log || '').slice(-200)) + '</span>'; tsInstallBtn.disabled = false; return; }  // nosemgrep - the log tail is tsEsc-wrapped
        tsInstallOut.innerHTML = '<span class="text-success">Installed.</span> Starting…';
        tsUp(tsInstallOut, tsInstallBtn);
      }).catch(function(){ tsInstallOut.innerHTML = '<span class="text-danger">Install request failed.</span>'; tsInstallBtn.disabled = false; });
    });
  }
  // "Link this machine" button: Tailscale already installed but not authorized — just bring it up.
  var tsConnectBtn = document.getElementById('ts-connect-btn');
  if (tsConnectBtn) {
    var tsConnectOut = document.getElementById('ts-connect-out');
    tsConnectBtn.addEventListener('click', function(){
      tsConnectBtn.disabled = true;
      tsUp(tsConnectOut, tsConnectBtn);
    });
  }
  // Enter key triggers the peer check (the peer-host input only exists when Tailscale is installed).
  var tsPeerHost = document.getElementById('peer-host');
  if (tsPeerHost) {
    tsPeerHost.addEventListener('keydown', function(e){ if (e.key === 'Enter') checkPeer(); });
  }
}
wireTsButtons();

function checkPeer() {
  var host = document.getElementById('peer-host').value.trim();
  if (!host) return;
  var resultEl = document.getElementById('peer-result');
  resultEl.innerHTML = '<span class="text-secondary"><i class="bi bi-arrow-repeat"></i> Checking...</span>';

  fetch(MOUNT + '/api/tailscale/check-peer', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({host: host}),
  })
  .then(r => r.json())
  .then(data => {
    // host comes from a text field — escape it before it goes into innerHTML (DOM XSS).
    var safeHost = escapeHtml(host);
    if (data.reachable) {
      resultEl.innerHTML = '<span class="text-success">✓ ' + safeHost + ' is reachable'  // nosemgrep - safeHost is escapeHtml output and the latency is a Number()
        + (data.latency_ms ? ' (' + Number(data.latency_ms) + 'ms)' : '')
        + '</span>';
    } else {
      var tsHint = data.is_tailscale_ip ? ' (Tailscale IP)' : '';
      resultEl.innerHTML = '<span class="text-danger">✗ ' + safeHost + tsHint + ' is not responding</span>';  // nosemgrep - safeHost is escapeHtml output and tsHint is one of two literals
    }
  })
  .catch(function() {
    resultEl.innerHTML = '<span class="text-danger">Error checking host</span>';
  });
}

function enableServe(btn) {
  var mount = document.querySelector('[name="mount"]').value || '/';
  var funnel = document.getElementById('funnel-check').checked;
  // `btn` arrives via data-args "@self". It used to be `event.target` off the implicit global,
  // which is the element actually clicked — the <i> icon inside the button as often as the button
  // itself, so `btn.disabled = true` did nothing and the label rewrite ate the icon instead.
  btn.disabled = true;
  btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Configuring...';

  fetch(MOUNT + '/api/tailscale/serve', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'enable', mount: mount, funnel: funnel}),
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      if(window.toast) toast(data.message, 'success');
      setTimeout(function(){ window.refreshSection('#ts-page','wireTsButtons'); }, 800);
    } else {
      if(window.toast) toast(data.message, 'danger');
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-wifi"></i> Enable Serve';
    }
  })
  .catch(function() {
    if(window.toast) toast('Error configuring Tailscale Serve', 'danger');
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-wifi"></i> Enable Serve';
  });
}

function disableServe(btn) {
  // The mount comes from the button's data-mount: the route the host reports proxying the panel.
  var mount = (btn && btn.dataset && btn.dataset.mount) || '/';
  confirmDialog({title:'Disable Tailscale Serve', icon:'exclamation-triangle', confirmClass:'btn-danger', confirmLabel:'Disable',
    bodyText:'Disable Tailscale Serve? The panel will no longer be accessible via the Tailscale URL.',
    onConfirm:function(){
      fetch(MOUNT + '/api/tailscale/serve', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'disable', mount: mount}),
      })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          if (window.toast) toast(data.message, 'success');
          setTimeout(function(){ window.refreshSection('#ts-page','wireTsButtons'); }, 800);
        } else if (window.toast) {
          toast(data.message, 'danger');
        }
      })
      .catch(function() {
        if (window.toast) toast('Error disabling Tailscale Serve', 'danger');
      });
    }});
}

// (peer-host Enter handler now lives in wireTsButtons so it survives an in-place refresh)
