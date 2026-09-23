// ── Live cross-user updates ───────────────────────────────────────────────
// A shared Socket.IO connection (created lazily, reused by the console page) plus a
// helper to subscribe to server-pushed events. Used so that when one user adds or
// removes a game server, every other open session reflects it live.
window.ensureSocket = function(){
  if(!window.socket && window.io){
    try { window.socket = io({ path: MOUNT + '/socket.io', transports: ['websocket', 'polling'] }); }
    catch(e){ window.socket = null; }
  }
  return window.socket;
};
// ── Uninstalling a game server ────────────────────────────────────────────────────────────────
// Lives here, not on the host page, because uninstall was only reachable from Remote Servers ->
// a host -> the Overview tab -> a table far down it. The servers themselves live on the
// dashboard, which offered no way to remove one at all. Delegated on document so any page that
// renders an .uninstall-form gets the same gate, and so it survives a list re-render.
// Uninstall a game server from the list: in-app confirm + type-the-username gate, then submit the
// form (a full POST — this admin page reloads to show the server gone). Delegated so it survives
// any list re-render.
document.addEventListener('click', function(e){
  var b = e.target.closest && e.target.closest('.uninstall-trigger');
  if(!b) return;
  var form = b.closest('form'); if(!form) return;
  var name = form.getAttribute('data-server-name') || '';
  var short = form.getAttribute('data-server-short') || '';
  confirmDialog({
    title:'Uninstall server', icon:'trash', confirmClass:'btn-danger', confirmLabel:'Uninstall',
    body:'Uninstall <strong>'+escapeHtml(name)+'</strong>? This permanently deletes the server, all its files, AND every backup it has — this cannot be undone.',
    requireText: short,
    requireLabel:'Type the server’s username ('+short+') to confirm:',
    // form.submit() is a NATIVE post: no fetch wrapper, so no X-CSRFToken header, so the hidden
    // field is the only token there is — and this list is re-rendered by refreshSection after an
    // import, which brings back the server's markup without it. Belt as well as braces: panel.js
    // re-arms after every swap, and this re-arms the one form about to be submitted.
    onConfirm:function(){ if (window.ensureCsrfFields) window.ensureCsrfFields(form); form.submit(); }
  });
});

window.onServersChanged = function(cb){
  var s = window.ensureSocket();
  if(s){ s.on('servers_changed', cb); }
};
// An open WebSocket makes a page ineligible for the browser's back/forward cache
// (bfcache), which slows down back/forward navigation. Close the socket when the page is
// hidden so it can be cached, and reconnect when it's shown again (incl. restored from
// bfcache). Listeners registered on the socket object survive the disconnect/reconnect.
window.addEventListener('pagehide', function(){
  try { if(window.socket && window.socket.connected) window.socket.disconnect(); } catch(e){}
});
window.addEventListener('pageshow', function(ev){
  if(ev.persisted && window.socket){ try { window.socket.connect(); } catch(e){} }
});

(function(){
  var _fetch = window.fetch.bind(window);

  // ── Session expiry: one place that reacts, for the whole panel ────────────────────────────
  // A page is a snapshot of a moment when you were signed in. The cookie does not ask the page
  // before it expires, so an open tab (or one restored from the back/forward cache) stays fully
  // rendered and completely dead — and every click then hit an endpoint that answered with the
  // login page, which the caller tried to read as JSON. That is where the errors came from. The
  // server now answers those calls 401 + X-Auth-Required; this takes the whole tab to /login.
  function _loginPath(){ return (window.MOUNT || '') + '/login'; }
  function _onLoginPage(){ return location.pathname.indexOf(_loginPath()) === 0; }
  var _expiredHandled = false;
  window.sessionExpired = function(){
    if (_expiredHandled || _onLoginPage()) return;   // in-flight polls all 401 at once: redirect once
    _expiredHandled = true;
    var here = location.pathname + location.search;
    try { if (window.toast) toast('Your session expired — signing you back in.', 'warning'); } catch(e){}
    // Keep where they were, so logging back in lands on the page they were actually using.
    location.replace(_loginPath() + '?next=' + encodeURIComponent(here));
  };

  window.fetch = function(input, init){
    init = init || {};
    var method = (init.method || 'GET').toUpperCase();
    var h = new Headers(init.headers || {});
    if (method !== 'GET' && method !== 'HEAD') {
      if (!h.has('X-CSRFToken')) h.set('X-CSRFToken', window.CSRF);
    }
    // Mark every in-page fetch, GET included. It lets form-POST endpoints answer with JSON
    // (update in place) instead of a full redirect+reload — and it is how the server tells an
    // in-page call from a browser navigation when the session has expired, so it can answer
    // with a 401 a script can act on rather than a login page a script cannot parse.
    if (!h.has('X-Requested-With')) h.set('X-Requested-With', 'XMLHttpRequest');
    init.headers = h;
    return _fetch(input, init).then(function(r){
      if (r.status === 401 && r.headers.get('X-Auth-Required')) window.sessionExpired();
      return r;
    });
  };

  // A tab restored from the back/forward cache never re-asked the server anything — it is the old
  // page, pixel for pixel, cookie or no cookie. Ask once on wake-up; the 401 handler above does
  // the rest. Cheap enough to also do when a long-backgrounded tab is focused again.
  var _lastPing = Date.now();
  function _pingAuth(){
    if (_expiredHandled || _onLoginPage()) return;
    _lastPing = Date.now();
    window.fetch((window.MOUNT || '') + '/api/auth/ping', {cache: 'no-store'}).catch(function(){});
  }
  window.addEventListener('pageshow', function(ev){ if (ev.persisted) _pingAuth(); });
  document.addEventListener('visibilitychange', function(){
    if (!document.hidden && Date.now() - _lastPing > 60000) _pingAuth();
  });
  // Give every POST form under `root` its hidden token. Exported and IDEMPOTENT, because
  // DOMContentLoaded is not the only time a form appears: refreshSection() re-fetches the page and
  // swaps a container's innerHTML, and what comes back is the SERVER-rendered markup — without the
  // field this added to the live DOM. The uninstall form on the host page is inside such a
  // container (importExisting refreshes #host-servers-card) and is submitted with form.submit(),
  // a native POST that carries no header — so after importing servers, Uninstall failed CSRF.
  // Measured in a browser against this file: token present on load, null after the swap.
  //
  // The fetch wrapper above covers everything submitted with fetch(); this covers the rest, and
  // form.submit() fires no 'submit' event, so a delegated listener could not have.
  window.ensureCsrfFields = function(root){
    (root || document).querySelectorAll('form').forEach(function(f){
      var m = (f.getAttribute('method') || 'GET').toUpperCase();
      if (m === 'POST' && !f.querySelector('input[name="csrf_token"]')) {
        var i = document.createElement('input');
        i.type = 'hidden'; i.name = 'csrf_token'; i.value = window.CSRF;
        f.appendChild(i);
      }
    });
  };
  document.addEventListener('DOMContentLoaded', function(){ window.ensureCsrfFields(document); });
})();

// Escape a string for safe interpolation into innerHTML — use this whenever a
// server- or user-provided value goes into markup. Available on every page.
// escapeHtml is defined in <head> so it exists before any page script runs.

// Language picker — one delegated handler for every page's <select data-lang-select>
// (sidebar, login, account, setup wizard; all extend this template). The target URL rides
// in a data-attribute so no Jinja sits in a JS-parsed context, then LANGCODE is swapped for
// the chosen value. Sets the language server-side, then re-renders the sidebar + main content in
// place in the new language (both are plain links / delegated handlers) — no full-page reload.
document.addEventListener('change', function(e){
  var el = e.target;
  if (!el || !el.matches || !el.matches('select[data-lang-select]') || !el.value) return;
  var lang = el.value, tmpl = el.getAttribute('data-lang-url') || '';
  // Save the choice (session + profile) for next load. NOT fire-and-forget: if the profile write
  // fails the language still changes here and now, but it will not follow you to another device —
  // and silently pretending otherwise is how a preference appears to "not stick".
  // POST, because set-language only writes the PROFILE on POST: as a GET it was a state change
  // CSRF could not cover. The wrapper above adds the token; pre-login there is no user row to
  // write, and the session half of the switch works on either method.
  if (tmpl) fetch(tmpl.replace('LANGCODE', encodeURIComponent(lang)) + '?ajax=1',
                  {method: 'POST', cache: 'no-store'})
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if (d && d.success === false && window.toast) toast(d.message || 'Saved for this session only.', 'warning');
    })
    .catch(function(){});
  // …and flip the UI right now: fetch the new language's catalog and re-translate the page in place,
  // no reload (window.setLang reverts every node to its stored English, then applies the new catalog).
  fetch(MOUNT + '/api/i18n/' + encodeURIComponent(lang), {cache: 'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(catalog){
      if (window.setLang) window.setLang(lang, catalog || {});
      document.querySelectorAll('select[data-lang-select]').forEach(function(s){ if (s.value !== lang) s.value = lang; });
    })
    .catch(function(){});
});

// Recurring poll that PAUSES while the tab is hidden and refreshes immediately when it
// becomes visible again. Most of our pollers hit SSH on a remote host every few seconds;
// a dashboard left open in a background tab would keep doing that work for nobody. This
// keeps identical freshness while you're looking at a page and does zero work when you're
// not. Returns the interval id (clearable). Use in place of setInterval for anything that
// fetches live data on a timer.
var _visPolls = {};   // interval id -> its visibilitychange listener, so stopPolling can undo both
window.pollWhenVisible = function(fn, intervalMs){
  // The catch-up on focus is THROTTLED, and the listener can be removed. Unthrottled, the interval
  // argument meant nothing on that path: nags.js registers osUpdatesNagCheck at one hour and
  // rebootNagCheck at ten minutes, and rebootNagCheck hits /api/remote/<id>/reboot-required, which
  // is an SSH command — so alt-tabbing between the panel and a terminal cost one SSH round trip
  // per switch. Measured: ten focus events on a one-HOUR poll ran the work ten times. And the
  // returned id could not stop it, because clearInterval leaves the listener behind and the
  // listener was unreachable; five more focuses still ran after clearInterval.
  var last = 0;
  var gap = Math.min(intervalMs, 60000);
  function run(){ last = Date.now(); try { fn(); } catch(e){} }
  var id = setInterval(function(){ if(!document.hidden) run(); }, intervalMs);
  function onVis(){ if(!document.hidden && Date.now() - last >= gap) run(); }
  document.addEventListener('visibilitychange', onVis);
  // setInterval returns a NUMBER, so the teardown cannot hang off the id — it goes in a registry
  // keyed by it. Existing callers keep passing the id to clearInterval and are unaffected; they
  // just leave the listener behind, which is what stopPolling exists to finish.
  _visPolls[id] = onVis;
  return id;
};

// Stop a pollWhenVisible poll COMPLETELY: the interval and its focus catch-up.
window.stopPolling = function(id){
  clearInterval(id);
  if (_visPolls[id]) { document.removeEventListener('visibilitychange', _visPolls[id]); delete _visPolls[id]; }
};

// "3h ago" for a unix timestamp. Shared: the backups list and the OS Updates card both say when
// something last happened, and a second copy of this would drift from the first.
window.agoText = function(epoch){
  var s = Math.max(0, Math.floor(Date.now()/1000 - epoch));
  if(s < 60) return 'just now';
  if(s < 3600) return Math.floor(s/60)+'m ago';
  if(s < 86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
};

// Render server timestamps (stored UTC, emitted as <span class="localtime" data-utc="…Z">)
// in the VIEWER's own timezone, with the exact UTC value on hover. Idempotent, so it's
// safe to call again after AJAX inserts more. Runs on load.
window.localizeTimes = function(root){
  (root || document).querySelectorAll('.localtime[data-utc]').forEach(function(el){
    if(el.dataset.localized) return;
    var d = new Date(el.getAttribute('data-utc'));
    if(isNaN(d.getTime())) return;
    el.title = el.textContent;                 // keep the UTC value as a tooltip
    el.textContent = d.toLocaleString();       // show local time
    el.dataset.localized = '1';
  });
};
document.addEventListener('DOMContentLoaded', function(){ window.localizeTimes(); });

// Global toast — a notification pops at the TOP-CENTRE (hard to miss on a wide monitor, where a
// bottom-right corner is easy to overlook), then fades. window.toast(message, 'success'|'danger'|'info').
window.toast = function(msg, kind){
  var c = document.getElementById('toast-area');
  if(!c){ c = document.createElement('div'); c.id = 'toast-area';
    c.style.cssText = 'position:fixed;top:1rem;left:50%;transform:translateX(-50%);z-index:11000;'
      + 'display:flex;flex-direction:column;align-items:center;gap:.5rem;max-width:min(92vw,520px);';
    document.body.appendChild(c); }
  // 'warning' is honoured: six call sites already passed it and silently got a blue info toast,
  // so a "this only half-worked" message looked like routine information.
  var KINDS = {success: 'check-circle-fill', danger: 'x-circle-fill',
               warning: 'exclamation-triangle-fill', info: 'info-circle-fill'};
  if (!KINDS[kind]) kind = 'info';
  var icon = KINDS[kind];
  var t = document.createElement('div');
  t.className = 'alert alert-' + kind + ' py-2 px-3 mb-0';
  t.style.cssText = 'font-size:.85rem;box-shadow:0 6px 24px rgba(0,0,0,.55);text-align:center;';
  // nosemgrep - icon is one of four literals from KINDS above; msg goes through escapeHtml.
  t.innerHTML = '<i class="bi bi-' + icon + '"></i> ' + escapeHtml(msg);
  c.appendChild(t);
  // Each toast owns its own timer (captured `t`). Errors linger longer so they're readable before
  // fading; success/info clear quicker.
  setTimeout(function(){ t.style.transition='opacity .4s'; t.style.opacity='0'; setTimeout(function(){ t.remove(); }, 400); },
             kind==='danger' ? 7000 : (kind==='warning' ? 6000 : 4000));
};

// Global styled confirm dialog — replaces the browser's native confirm() so confirmations stay
// in-app and look consistent. opts:
//   {title, icon, body (safe HTML — escape any dynamic text), confirmLabel, confirmClass, onConfirm}
// Extra gates:
//   requireText:  a string the user must TYPE exactly before Confirm enables (type-to-confirm).
//   requirePassword: true -> show a password field; Confirm passes its value to onConfirm and the
//                    dialog STAYS OPEN so the caller can verify server-side, then call api.close()
//                    on success or api.error('…') to re-prompt. onConfirm(value, api).
//   requireLabel: label shown above the input.
//   requirePlaceholder: placeholder for the password field. Defaults to "Your account password",
//                    which is wrong for any gate that is not the account password (e.g. a backup
//                    passphrase), so those pass their own.
//   bodyNode:     a DOM node to place in the body instead of text (interactive dialog content).
//                 NOTE: the overlay is REMOVED before onConfirm runs (see submit() below), so read
//                 any state out of the node you passed in — `body.querySelector(...)` — never via
//                 document.getElementById/querySelectorAll, which by then match nothing. Two
//                 upload dialogs got this wrong and their "Replace existing file" ticks silently
//                 did nothing. A detached node keeps its .checked, so the reference still works.
// Dismiss via Cancel / backdrop / Esc; only Confirm runs onConfirm.
window.confirmDialog = function(opts){
  opts = opts || {};
  var inputHtml = '';
  if (opts.requireText || opts.requirePassword) {
    inputHtml = '<div class="mb-3">'
      + (opts.requireLabel ? '<label class="form-label small" for="cd-input">' + escapeHtml(opts.requireLabel) + '</label>' : '')
      + '<input type="' + (opts.requirePassword ? 'password' : 'text') + '" class="form-control" id="cd-input"'
      + (opts.requirePassword ? ' autocomplete="current-password" placeholder="' + escapeHtml(opts.requirePlaceholder || 'Your account password') + '"' : ' autocomplete="off" autocapitalize="off" spellcheck="false"') + '>'
      + '<div class="small text-danger mt-1" id="cd-err" style="display:none;"></div>'
      + '</div>';
  }
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:11050;display:flex;align-items:center;justify-content:center;padding:1rem;';
  // nosemgrep - static markup; every interpolation is escapeHtml'd, and opts.body is documented
  // as trusted markup (both callers escape their one dynamic value; a test now enforces that).
  ov.innerHTML = '<div class="card" style="max-width:480px;width:100%;">'  // nosemgrep
    + '<div class="card-header"><i class="bi bi-' + escapeHtml(opts.icon || 'question-circle') + '"></i> ' + escapeHtml(opts.title || 'Confirm') + '</div>'
    + '<div class="card-body">'
    + '<p class="mb-3" data-cd-body style="white-space:pre-line;">' + (opts.body || '') + '</p>'
    + inputHtml
    + '<div class="d-flex justify-content-end gap-2">'
    + '<button class="btn btn-outline-secondary" data-cd="cancel">Cancel</button>'
    + '<button class="btn ' + escapeHtml(opts.confirmClass || 'btn-primary') + '" data-cd="ok">' + escapeHtml(opts.confirmLabel || 'Confirm') + '</button>'
    + '</div></div></div>';
  document.body.appendChild(ov);
  // Plain-text body: assign via textContent (never innerHTML) so a caller may pass untrusted
  // text (e.g. a form's data-confirm value) with zero HTML-injection risk.
  if (opts.bodyText != null) { var _cb = ov.querySelector('[data-cd-body]'); if (_cb) _cb.textContent = opts.bodyText; }
  // bodyNode: an already-built DOM node (e.g. a list of checkboxes). Appended, never serialised, so
  // a caller that needs interactive content in the dialog does not have to reach for `body` (raw
  // HTML) and hand-escape user-authored text into it.
  if (opts.bodyNode) {
    var _cn = ov.querySelector('[data-cd-body]');
    if (_cn) {
      _cn.textContent = '';
      // Cap and scroll it: the overlay is a centred fixed flex box, so content taller than the
      // viewport overflows BOTH edges with no scrollbar — putting Confirm out of reach entirely.
      _cn.style.cssText = 'white-space:normal;max-height:50vh;overflow-y:auto;';
      _cn.appendChild(opts.bodyNode);
    }
  }
  var input = ov.querySelector('#cd-input'), okBtn = ov.querySelector('[data-cd="ok"]'),
      errEl = ov.querySelector('#cd-err'), okHtml = okBtn.innerHTML;
  function close(){ ov.remove(); document.removeEventListener('keydown', onKey); }
  function onKey(e){ if(e.key === 'Escape') close(); }
  document.addEventListener('keydown', onKey);
  var api = {
    close: close,
    // nosemgrep - okHtml is this button's OWN markup, captured above; the message uses textContent.
    error: function(m){ if(errEl){ errEl.textContent = m || 'Incorrect.'; errEl.style.display=''; } okBtn.disabled=false; okBtn.innerHTML=okHtml; if(input){ input.value=''; input.focus(); } },
    busy: function(){ okBtn.disabled=true; okBtn.innerHTML='<span class="spinner-border spinner-border-sm"></span>'; }
  };
  if (opts.requireText) {
    okBtn.disabled = true;
    input.addEventListener('input', function(){ okBtn.disabled = (input.value !== opts.requireText); });
  } else if (opts.requirePassword) {
    okBtn.disabled = true;
    input.addEventListener('input', function(){ okBtn.disabled = !input.value; if(errEl) errEl.style.display='none'; });
  }
  function submit(){
    if (okBtn.disabled) return;
    var val = input ? input.value : undefined;
    if (opts.requirePassword) { api.busy(); if(opts.onConfirm) opts.onConfirm(val, api); return; } // caller closes/errors
    close(); if (opts.onConfirm) opts.onConfirm(val, api);
  }
  okBtn.onclick = submit;
  ov.querySelector('[data-cd="cancel"]').onclick = close;
  ov.addEventListener('click', function(e){ if(e.target === ov) close(); });
  if (input) {
    input.addEventListener('keydown', function(e){ if(e.key === 'Enter'){ e.preventDefault(); submit(); } });
    setTimeout(function(){ input.focus(); }, 50);
  }
};

// ── SPA-style forms: submit without a full-page reload ─────────────────────────────────────
// Any <form class="ajax-form"> is submitted via fetch instead of a browser navigation. On success
// it toasts the server's message, closes an enclosing modal, resets the form, and re-renders the
// list section named by data-ajax-refresh (a CSS selector) by re-fetching THIS page and swapping
// just that container — so page scripts/delegated listeners keep working and nothing reloads.
// Optional attributes: data-confirm (+ -title/-icon/-class/-label) shows the styled confirm first;
// data-ajax-after names a window function to run after the section refreshes (e.g. re-arm pollers).
window.refreshSection = function(sel, afterName){
  fetch(location.href, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, cache: 'no-store' })
    .then(function(r){ return r.text(); })
    .then(function(html){
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var fresh = doc.querySelector(sel), cur = document.querySelector(sel);
      // nosemgrep - a fragment of THIS panel's own server-rendered page (Jinja autoescapes),
      // re-parsed same-origin to refresh one region in place.
      if (fresh && cur) cur.innerHTML = fresh.innerHTML;  // nosemgrep
      // The swapped-in markup is what the SERVER rendered, so any POST form in it arrives without
      // the hidden token — see ensureCsrfFields.
      if (cur && window.ensureCsrfFields) window.ensureCsrfFields(cur);
      // nosemgrep - the delegated dispatcher this whole UI is built on: afterName comes from a
      // data- attribute in our own template, and the typeof guard is the contract.
      if (afterName && typeof window[afterName] === 'function') { try { window[afterName](); } catch(e){} }  // nosemgrep
    }).catch(function(){});
};
function _submitAjaxForm(form){
  var btn = form.querySelector('[type="submit"]'), orig = btn ? btn.innerHTML : '';
  // nosemgrep - a static spinner in, and the button's own saved markup back out on restore.
  if (btn){ btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
  var restore = function(){ if (btn){ btn.disabled = false; btn.innerHTML = orig; } };  // nosemgrep
  fetch(form.action || location.href,
        { method: (form.getAttribute('method') || 'POST').toUpperCase(), body: new FormData(form) })
    .then(function(r){
      // A form endpoint that answers with a PAGE — a permission redirect, or the login page after
      // the session expired — is a failure. Parsing that as JSON fails, and the old fallback
      // returned {} … whose `.success !== false` is true, so a refused action rendered a green
      // success toast. Treat a followed redirect or a non-JSON body as the failure it is.
      var ct = r.headers.get('content-type') || '';
      if (r.redirected || ct.indexOf('application/json') === -1) {
        return { status: r.status, d: { success: false,
                 message: r.redirected ? 'Not permitted, or your session expired.'
                                       : 'The server sent an unexpected response.' } };
      }
      return r.json().then(function(d){ return { status: r.status, d: d || {} }; })
                     .catch(function(){ return { status: r.status,
                              d: { success: false, message: 'The server sent an unexpected response.' } }; });
    })
    .then(function(res){
      restore();
      if (res.status >= 200 && res.status < 300 && res.d.success !== false){
        if (window.toast && res.d.message) toast(res.d.message, 'success');
        if (form.getAttribute('data-ajax-reset') !== 'off' && form.reset) form.reset();
        var sel = form.getAttribute('data-ajax-refresh');
        var after = form.getAttribute('data-ajax-after');
        // A response can carry a freshly minted secret (a generated password) for the page to show
        // once. It rides along with the refresh rather than being shown straight away: opening a
        // second modal while the first is still hiding leaves Bootstrap stripping `modal-open` off
        // the body and stranding both backdrops over the new one — the password is on the page,
        // behind two grey sheets, which is the same as losing it.
        var cred = res.d.credential;
        var doRefresh = function(){
          // data-ajax-after runs whether or not there is a section to swap. It used to be handed
          // ONLY to refreshSection, so a form with an after-hook and no data-ajax-refresh — the
          // install form, deliberately, because the list it would refresh lives on another page —
          // quietly never ran it. A data- attribute that is silently ignored in one configuration
          // is a trap, not a feature.
          // nosemgrep - the delegated dispatcher this UI is built on; `after` comes from a data-
          // attribute in our own template and the typeof guard is the contract.
          if (sel) window.refreshSection(sel, after);
          else if (after && typeof window[after] === 'function') { try { window[after](); } catch(e){} }  // nosemgrep
          if (cred && typeof window.showCredential === 'function'){
            try { window.showCredential(cred); } catch(e){}
          }
        };
        var modal = form.closest('.modal');
        if (modal && window.bootstrap){
          // Wait for the modal to FULLY hide (Bootstrap removes its backdrop) before swapping the
          // section DOM — destroying the modal mid-animation would strand a grey backdrop overlay.
          var mi = bootstrap.Modal.getInstance(modal) || bootstrap.Modal.getOrCreateInstance(modal);
          modal.addEventListener('hidden.bs.modal', function _h(){
            modal.removeEventListener('hidden.bs.modal', _h); doRefresh();
          });
          mi.hide();
        } else {
          doRefresh();
        }
      } else if (window.toast) {
        toast(res.d.message || 'Action failed', 'danger');
      }
    })
    .catch(function(){ restore(); if (window.toast) toast('Request failed', 'danger'); });
}
window.ajaxForm = function(form){
  var msg = form.getAttribute('data-confirm');
  if (msg){
    confirmDialog({
      title: form.getAttribute('data-confirm-title') || 'Confirm',
      icon: form.getAttribute('data-confirm-icon') || 'question-circle',
      confirmClass: form.getAttribute('data-confirm-class') || 'btn-primary',
      confirmLabel: form.getAttribute('data-confirm-label') || 'Confirm',
      bodyText: msg,   // data-confirm rendered via textContent — safe for any name, no HTML sink
      onConfirm: function(){ _submitAjaxForm(form); }
    });
  } else {
    _submitAjaxForm(form);
  }
  return false;   // always prevent the native submit
};
// Delegate: any form.ajax-form submits through ajaxForm without needing an inline onsubmit.
document.addEventListener('submit', function(e){
  var f = e.target;
  if (f && f.classList && f.classList.contains('ajax-form')){ e.preventDefault(); window.ajaxForm(f); }
}, true);

// ── CSP-safe event delegation ──────────────────────────────────────────────────────────────
// A strict Content-Security-Policy (script-src has no 'unsafe-inline') blocks inline on* handlers,
// so every handler is declared with data attributes instead and dispatched here:
//   data-action="funcName"   a GLOBAL function to call (comes only from our own templates)
//   data-args='[...]'         optional JSON args; "@self" -> the element, "@event" -> the event
//   data-on="change"          optional event type (default "click")
//   data-prevent (attr)       call event.preventDefault() (e.g. an <a> that shouldn't navigate)
// The call mirrors inline-handler semantics — foo() runs as foo(), foo(this) as foo(element).
// If the function returns false, the default is prevented too (like `onclick="…;return false"`).
window._noop = function(){};                    // for handlers that were only `return false`
// `action` and `on` are literals written in our own templates/scripts; `args` carries VALUES —
// a host name, an IP, a jail, a filename — so it is the half that needs escaping.
//
// & BEFORE ': the attribute is single-quoted, so a literal ' has to become &#39; — but the HTML
// parser decodes entities in attribute values, so a value containing the TEXT "&#39;" decoded to a
// real quote and closed the attribute early, injecting whatever followed as further attributes on
// the tag. Escaping & first (and only then ') means an ampersand in a value round-trips as data
// instead of as the start of an entity. Order matters: & last would re-escape the & of &#39;.
window._da = function(action, args, on){        // build the attributes from JS that generates HTML
  var s = ' data-action="' + action + '"';
  if (args && args.length){
    s += " data-args='"
       + JSON.stringify(args).replace(/&/g, '&amp;').replace(/'/g, '&#39;')
       + "'";
  }
  if (on){ s += ' data-on="' + on + '"'; }
  return s;
};
// Global wrappers so method-calls / statements that used to sit in inline handlers can be reached
// by name from the data-action dispatcher (window[name] must be a function).
window._uproAttach = function(){ if (window.UPro) UPro.attach(); };
window._uproDetach = function(){ if (window.UPro) UPro.detach(); };
window._uproService = function(name, action){ if (window.UPro) UPro.service(name, action); };
window._clickUpload = function(){ var i = document.getElementById('upload-input'); if (i) i.click(); };
window._copyDataU = function(el){ var u = el && el.dataset ? el.dataset.u : ''; if (window.copyText) copyText(u, 'Copied'); else if (navigator.clipboard) navigator.clipboard.writeText(u); };
window._showTsKeyAdv = function(){ var e = document.getElementById('ts-key-adv'); if (e) e.style.display = 'block'; return false; };
window._sayOnEnter = function(e){ if (e && e.key === 'Enter'){ e.preventDefault(); if (window.announceSay) announceSay(); } };
window._acctSignOutAll = function(){
  confirmDialog({title:'Sign out everywhere else', icon:'box-arrow-right', confirmClass:'btn-danger',
    confirmLabel:'Sign out other devices',
    bodyText:'Sign out every OTHER device signed in to this account? This one stays signed in.',
    onConfirm:function(){ var f = document.getElementById('revoke-sessions-form');
      // A native POST: no fetch wrapper, so the hidden field is the only token there is.
      if (f) { window.ensureCsrfFields(f); f.submit(); } }});
};
(function(){
  function fire(el, e){
    var fn = window[el.getAttribute('data-action')];
    if (typeof fn !== 'function') return;
    var args = [];
    var raw = el.getAttribute('data-args');
    if (raw){ try { args = JSON.parse(raw); } catch (_e){ args = []; } }
    args = args.map(function(a){ return a === '@self' ? el : (a === '@event' ? e : a); });
    var ret = fn.apply(null, args);
    if (ret === false || el.hasAttribute('data-prevent')){ if (e.cancelable) e.preventDefault(); }
  }
  ['click', 'change', 'submit', 'input', 'keydown'].forEach(function(type){
    document.addEventListener(type, function(e){
      var el = (e.target && e.target.closest) ? e.target.closest('[data-action]') : null;
      if (!el) return;
      if ((el.getAttribute('data-on') || 'click') !== type) return;
      fire(el, e);
    }, false);
  });
})();

// Copy text to the clipboard and confirm with a toast. Falls back to execCommand
// on non-secure contexts.
// Track the cursor so feedback can pop right where the user clicked (a bottom-right
// toast is easy to miss on big screens).
window._cursor = { x: 0, y: 0 };
document.addEventListener('mousemove', function(e){ window._cursor.x = e.clientX; window._cursor.y = e.clientY; }, { passive: true });

// A small label that pops next to the cursor, floats up, and fades — for quick
// confirmations like "Copied!".
window.cursorFlash = function(msg, kind){
  var bg = kind === 'danger' ? '#f85149' : (kind === 'info' ? '#58a6ff' : '#3fb950');
  var el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = 'position:fixed;z-index:12000;pointer-events:none;white-space:nowrap;'
    + 'left:' + (window._cursor.x + 12) + 'px;top:' + (window._cursor.y - 10) + 'px;'
    + 'background:' + bg + ';color:#0b0f17;font-size:.72rem;font-weight:700;'
    + 'padding:2px 8px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.45);'
    + 'opacity:1;transform:translateY(0);transition:transform .6s ease, opacity .6s ease;';
  document.body.appendChild(el);
  // Hold it fully visible for a beat, THEN float up and fade — so it's not missed.
  setTimeout(function(){ el.style.transform = 'translateY(-18px)'; el.style.opacity = '0'; }, 850);
  setTimeout(function(){ el.remove(); }, 1500);
};

// ── Layout edit mode ────────────────────────────────────────────────────────────────────────────
// Reordering controls are hidden until you ask for them. Kept in sessionStorage because hiding a
// panel and restoring it reloads the page (a hidden panel is not rendered, so only the server has
// its markup) — without this, restoring one would kick you out of edit mode mid-rearrange.
window.layoutEditOn = function(){
  try { return sessionStorage.getItem('layoutEdit') === '1'; } catch (e) { return false; }
};
window.applyLayoutEdit = function(){
  var on = window.layoutEditOn();
  document.body.classList.toggle('layout-edit', on);
  document.querySelectorAll('[data-action="toggleLayoutEdit"]').forEach(function(btn){
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    btn.classList.toggle('active', on);
    var label = btn.querySelector('[data-edit-label]');
    if (label) label.textContent = on ? (window.t ? t('Done') : 'Done')
                                      : (window.t ? t('Customise') : 'Customise');
  });
};
window.toggleLayoutEdit = function(){
  try { sessionStorage.setItem('layoutEdit', window.layoutEditOn() ? '0' : '1'); } catch (e) {}
  window.applyLayoutEdit();
};
document.addEventListener('DOMContentLoaded', function(){ window.applyLayoutEdit(); });

// ── Drag-to-reorder ─────────────────────────────────────────────────────────────────────────────
// POINTER events, not HTML5 drag-and-drop: HTML5 DnD emits nothing at all on touch, and its drop
// targets behave badly inside the horizontally-scrolling .table-responsive wrappers the server lists
// live in. Pointer events are one code path for mouse, touch and pen.
//
// This only reorders the DOM and then calls back — persistence and server-side rendering stay with
// the page, which is what keeps a dragged order surviving the innerHTML swaps that refreshSection
// performs on a poll. The arrow buttons remain the keyboard and screen-reader path; dragging is an
// addition, never the only way to reorder.
//
// makeSortable(container, {itemSelector, handleSelector, axis, onDrop})
window.makeSortable = function(container, opts){
  if (!container || container._sortableBound) return;
  container._sortableBound = true;
  // Marked so NESTED sortables can tell whose gesture a handle belongs to. On the dashboard
  // #server-cards contains each host's tbody, and both are sortable: without this, one pointerdown
  // on a row handle starts BOTH drags — the row reorders and its whole host card moves with it.
  container.setAttribute('data-sortable', '');
  opts = opts || {};
  var ITEM = opts.itemSelector || '[data-panel]';
  var HANDLE = opts.handleSelector || '[data-drag-handle]';
  var horizontal = opts.axis === 'x';
  var dragging = null, startX = 0, startY = 0, moved = false;

  function items(){
    return Array.prototype.slice.call(container.querySelectorAll(':scope > ' + ITEM));
  }

  function onDown(ev){
    // Primary button / single touch only, and only from a handle — so a click on a button inside a
    // panel is never swallowed by the drag.
    if (ev.button !== undefined && ev.button !== 0) return;
    var handle = ev.target.closest(HANDLE);
    if (!handle || !container.contains(handle)) return;
    // The INNERMOST sortable owns the gesture. Without this the outer container also matches,
    // because a row's handle is a descendant of both it and #server-cards.
    if (handle.closest('[data-sortable]') !== container) return;
    var item = handle.closest(ITEM);
    if (!item || item.parentNode !== container) return;
    dragging = item; moved = false;
    startX = ev.clientX; startY = ev.clientY;
    handle.setPointerCapture(ev.pointerId);
    handle._sortRelease = function(){ try { handle.releasePointerCapture(ev.pointerId); } catch (e) {} };
    handle.addEventListener('pointermove', onMove);
    handle.addEventListener('pointerup', onUp);
    handle.addEventListener('pointercancel', onUp);
    ev.preventDefault();          // no text selection / native image drag while reordering
  }

  function onMove(ev){
    if (!dragging) return;
    // A 4px dead zone, so a slightly shaky click is still a click.
    if (!moved && Math.abs(ev.clientX - startX) < 4 && Math.abs(ev.clientY - startY) < 4) return;
    if (!moved){ moved = true; dragging.classList.add('sort-dragging'); document.body.classList.add('sort-active'); }
    // Reorder only when the pointer passes a neighbour's MIDPOINT — a handful of DOM moves per drag
    // rather than one per frame. That matters here: the i18n MutationObserver re-walks every
    // inserted subtree, so moving the node per frame would translate the whole panel each time.
    var sibs = items();
    for (var i = 0; i < sibs.length; i++){
      var el = sibs[i];
      // Skip anything not actually rendered. A display:none sibling (a row hidden by the search or
      // tag filter) reports an ALL-ZERO rect, so its midpoint is 0 and "pointer past it" is true for
      // every position on screen — it would swallow the very first pointermove as a drop target.
      if (el === dragging || !el.getClientRects().length) continue;
      var r = el.getBoundingClientRect();
      // On a wrapping grid (the stat tiles are row-cols-2 on phones) an x-axis compare alone matches
      // tiles on OTHER rows, whose x ranges overlap. Require the pointer to be within this
      // candidate's row before applying the horizontal test.
      if (horizontal && (ev.clientY < r.top || ev.clientY > r.bottom)) continue;
      var mid = horizontal ? r.left + r.width / 2 : r.top + r.height / 2;
      var pos = horizontal ? ev.clientX : ev.clientY;
      var before = sibs.indexOf(dragging) > i;
      if ((before && pos < mid) || (!before && pos > mid)){
        container.insertBefore(dragging, before ? el : el.nextSibling);
        break;
      }
    }
  }

  function onUp(ev){
    var handle = ev.currentTarget;
    handle.removeEventListener('pointermove', onMove);
    handle.removeEventListener('pointerup', onUp);
    handle.removeEventListener('pointercancel', onUp);
    if (handle._sortRelease) handle._sortRelease();
    if (dragging) dragging.classList.remove('sort-dragging');
    document.body.classList.remove('sort-active');
    var didMove = moved;
    dragging = null; moved = false;
    if (didMove && opts.onDrop) opts.onDrop();
  }

  container.addEventListener('pointerdown', onDown);
};

window.copyText = function(text, label){
  function done(){ window.cursorFlash('✓ ' + (label || 'Copied'), 'success'); }
  function fallback(){ try { var ta=document.createElement('textarea'); ta.value=text; ta.style.cssText='position:fixed;opacity:0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); } catch(e){} }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done).catch(function(){ fallback(); done(); });
  } else { fallback(); done(); }
};

// One-click "Join" links use steam://connect/… which launches the game on a
// desktop that has Steam. On a phone there's no client to hand off to, so the
// link silently dies (or pops an ugly "no app found" dialog). On touch devices
// we intercept it, copy the ip:port instead, and tell the user to paste it into
// their game — the phone is for managing, the actual joining happens elsewhere.
// `pointer: coarse` — the POINTER, not the capability. maxTouchPoints > 0 is true on every
// touchscreen Windows laptop, Surface and touch-enabled Chromebook, machines that do have Steam:
// clicking Join with a mouse there never launched steam://connect/…, it copied the address and
// toasted instead, and the href was cancelled so there was no way to get the real link. A hybrid
// device with a mouse reports `pointer: fine` and keeps the hand-off.
window.__isTouch = (window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
  || (!window.matchMedia && (('ontouchstart' in window) || (navigator.maxTouchPoints || 0) > 0));
document.addEventListener('click', function(ev){
  var j = ev.target.closest && ev.target.closest('.join-link');
  if(!j || !window.__isTouch) return;
  var addr = j.getAttribute('data-addr');
  if(!addr) return;
  ev.preventDefault();
  if(window.copyText) window.copyText(addr, 'Copied ' + addr + ' — paste it in your game to join');
});

// ── Ubuntu Pro widget (shared by the Panel Server & Remote Manage pages) ──
// Attaches to a host by its remote id (the panel host uses its own local remote
// id). Renders status, attach form, per-service enable/disable, and detach.
window.UPro = (function(){
  var HOST = null, EL = null;
  function e(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function msg(t, kind){ var m=document.getElementById('upro-msg'); if(m){ m.textContent=t; m.className='small mt-2 '+(kind==='success'?'text-success':(kind==='danger'?'text-danger':'text-secondary')); } }
  function attachForm(){
    return '<div class="input-group input-group-sm" style="max-width:540px;">'
      + '<input type="text" id="upro-token" class="form-control" placeholder="Ubuntu Pro token (e.g. C1a…)" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">'
      + '<button class="btn btn-success"' + _da('_uproAttach') + '><i class="bi bi-shield-check"></i> Attach</button></div>';
  }
  function render(d){
    if(!EL) return;
    // "could not read" before "not attached". The route used to answer a failed read as
    // installed:false, so this branch offered an Attach form and the words "Not attached" about a
    // host nobody had managed to ask — and that answer was persisted and served for a day.
    // `unreachable` belongs in the SAME branch: _unreachable() answers a host that is off or
    // rebooting with 200 {success:false, unreachable:true} — deliberately, so the UI can say so —
    // and that object has no `installed` key at all, so it fell through both tests below and
    // painted "Not attached" plus the attach pitch over a host that may be fully attached. The
    // .catch() eight lines down already says "Could not read Ubuntu Pro status." for a transport
    // that throws; this is the same answer arriving as a 200.
    if(d && (d.unreadable || d.unreachable || d.success === false)){
      EL.innerHTML = '<div class="d-flex align-items-center gap-2 mb-2">'
        + '<span class="badge bg-warning text-dark">Unknown</span></div>'
        + '<p class="small text-secondary mb-2">'
        + 'Could not read Ubuntu Pro status on this host, so it is unknown.'
        + '</p>';  // nosemgrep - fixed string, no interpolation
      return;
    }
    if(!d || d.installed === false){
      // nosemgrep - static literal; attachForm() is fixed markup too.
      EL.innerHTML = '<div class="d-flex align-items-center gap-2 mb-2"><span class="badge bg-secondary">Not attached</span></div>'
        + '<p class="small text-secondary mb-2">Ubuntu Pro is <strong>free for personal use</strong> (up to 5 machines) and adds ~10 years of security updates (ESM) plus kernel <strong>Livepatch</strong>. Get a token at <a href="https://ubuntu.com/pro/dashboard" target="_blank" rel="noopener">ubuntu.com/pro/dashboard</a>. The client will be installed automatically when you attach.</p>'
        + attachForm() + '<div id="upro-msg" class="small mt-2"></div>';
      return;
    }
    if(!d.attached){
      // nosemgrep - static literal; attachForm() is fixed markup too.
      EL.innerHTML = '<div class="d-flex align-items-center gap-2 mb-2"><span class="badge bg-secondary">Not attached</span></div>'
        + '<p class="small text-secondary mb-2">Attach this host to your <strong>free</strong> Ubuntu Pro subscription for ~10 years of security updates (ESM) and kernel <strong>Livepatch</strong>. Get a token at <a href="https://ubuntu.com/pro/dashboard" target="_blank" rel="noopener">ubuntu.com/pro/dashboard</a>.</p>'
        + attachForm() + '<div id="upro-msg" class="small mt-2"></div>';
      return;
    }
    var head = '<div class="d-flex align-items-center gap-2 mb-2 flex-wrap"><span class="badge bg-success">Attached</span>'
      + (d.contract ? '<span class="small text-secondary">'+e(d.contract)+'</span>' : '')
      + (d.account ? '<span class="small text-secondary">· '+e(d.account)+'</span>' : '')
      + (d.expires ? '<span class="small text-secondary">· expires '+e(d.expires.slice(0,10))+'</span>' : '') + '</div>';
    var rows = '';
    (d.services||[]).forEach(function(s){
      var en = s.status === 'enabled';
      var badge = en ? '<span class="badge bg-success">enabled</span>'
        : (s.status === 'disabled' ? '<span class="badge bg-secondary">disabled</span>' : '<span class="badge bg-secondary">'+e(s.status||'—')+'</span>');
      var canToggle = (s.entitled === 'yes');
      var btn = !canToggle ? '<span class="small text-secondary">not entitled</span>'
        : (en ? '<button class="btn btn-outline-secondary btn-sm py-0"' + _da('_uproService', [s.name, 'disable']) + '>Disable</button>'
              : '<button class="btn btn-outline-success btn-sm py-0"' + _da('_uproService', [s.name, 'enable']) + '>Enable</button>');
      rows += '<tr><td class="small"><code>'+e(s.name)+'</code><div class="text-secondary" style="font-size:.68rem;">'+e(s.description||'')+'</div></td><td>'+badge+'</td><td class="text-end">'+btn+'</td></tr>';
    });
    // nosemgrep - head/rows/btn are built above with e() on every value from the server.
    EL.innerHTML = head
      + '<div class="table-responsive"><table class="table table-sm mb-2 align-middle"><tbody>'+rows+'</tbody></table></div>'
      + '<button class="btn btn-outline-danger btn-sm"' + _da('_uproDetach') + '><i class="bi bi-x-circle"></i> Detach</button>'
      + '<div id="upro-msg" class="small mt-2"></div>';
  }
  function refresh(){
    if(!EL) return;
    EL.innerHTML = '<div class="text-secondary small"><i class="bi bi-arrow-repeat"></i> Checking Ubuntu Pro…</div>';
    fetch(MOUNT + '/api/remote/' + HOST + '/pro-status').then(function(r){ return r.json(); })
      .then(render).catch(function(){ EL.innerHTML = '<div class="text-danger small">Could not read Ubuntu Pro status.</div>'; });
  }
  // Quietly re-read without blanking the card — keeps the shown value until the new one lands.
  // "Until the new one lands" means a READING: a payload that says the host could not be read is
  // not one, and overwriting the persisted status with it trades a known value for an unknown.
  // load() passes `initial` precisely so the card never blanks; this used to undo that.
  function quietRefresh(){
    if(!EL) return;
    fetch(MOUNT + '/api/remote/' + HOST + '/pro-status').then(function(r){ return r.json(); })
      .then(function(d){
        if(d && (d.unreadable || d.unreachable || d.success === false)) return;
        render(d);
      }).catch(function(){});
  }
  return {
    // `initial` (the persisted status) paints instantly so the card never blanks to a spinner;
    // it's then refreshed silently in the background. Without it, fall back to the spinner path.
    load: function(hostId, elId, initial){
      HOST = hostId; EL = document.getElementById(elId);
      if(initial){ render(initial); quietRefresh(); } else { refresh(); }
    },
    attach: function(){
      var t = document.getElementById('upro-token'); if(!t) return;
      var token = t.value.trim(); if(!token){ msg('Enter your Ubuntu Pro token first.', 'danger'); return; }
      msg('Attaching… this can take a minute.', 'info');
      fetch(MOUNT + '/api/remote/' + HOST + '/pro-attach', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({token: token})})
        .then(function(r){ return r.json(); }).then(function(d){ msg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'success':'danger'); if(d.success) setTimeout(refresh, 800); })
        .catch(function(){ msg('✗ Request failed', 'danger'); });
    },
    service: function(name, action){
      msg((action==='enable'?'Enabling ':'Disabling ')+name+'… this can take a moment.', 'info');
      fetch(MOUNT + '/api/remote/' + HOST + '/pro-service', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({service:name, action:action})})
        .then(function(r){ return r.json(); }).then(function(d){ msg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'success':'danger'); setTimeout(refresh, 800); })
        .catch(function(){ msg('✗ Request failed', 'danger'); });
    },
    detach: function(){
      confirmDialog({title:'Detach Ubuntu Pro', icon:'shield-slash', confirmClass:'btn-danger', confirmLabel:'Detach',
        bodyText:'Detach this host from Ubuntu Pro? Security (ESM) updates and Livepatch will stop.',
        onConfirm:function(){
          msg('Detaching…', 'info');
          fetch(MOUNT + '/api/remote/' + HOST + '/pro-detach', {method:'POST'})
            .then(function(r){ return r.json(); }).then(function(d){ msg((d.success?'✓ ':'✗ ')+(d.message||''), d.success?'success':'danger'); setTimeout(refresh, 800); })
            .catch(function(){ msg('✗ Request failed', 'danger'); });
        }});
    }
  };
})();
