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
  window.fetch = function(input, init){
    init = init || {};
    var method = (init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      var h = new Headers(init.headers || {});
      if (!h.has('X-CSRFToken')) h.set('X-CSRFToken', window.CSRF);
      // Mark every in-page fetch so form-POST endpoints can answer with JSON (update in place)
      // instead of a full redirect+reload. A real browser form navigation won't have this.
      if (!h.has('X-Requested-With')) h.set('X-Requested-With', 'XMLHttpRequest');
      init.headers = h;
    }
    return _fetch(input, init);
  };
  document.addEventListener('DOMContentLoaded', function(){
    document.querySelectorAll('form').forEach(function(f){
      var m = (f.getAttribute('method') || 'GET').toUpperCase();
      if (m === 'POST' && !f.querySelector('input[name="csrf_token"]')) {
        var i = document.createElement('input');
        i.type = 'hidden'; i.name = 'csrf_token'; i.value = window.CSRF;
        f.appendChild(i);
      }
    });
  });
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
  if (tmpl) fetch(tmpl.replace('LANGCODE', encodeURIComponent(lang)) + '?ajax=1', {cache: 'no-store'})
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
window.pollWhenVisible = function(fn, intervalMs){
  var id = setInterval(function(){ if(!document.hidden){ try { fn(); } catch(e){} } }, intervalMs);
  document.addEventListener('visibilitychange', function(){
    if(!document.hidden){ try { fn(); } catch(e){} }   // catch up the moment the tab is focused
  });
  return id;
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
//   bodyNode:     a DOM node to place in the body instead of text (interactive dialog content).
// Dismiss via Cancel / backdrop / Esc; only Confirm runs onConfirm.
window.confirmDialog = function(opts){
  opts = opts || {};
  var inputHtml = '';
  if (opts.requireText || opts.requirePassword) {
    inputHtml = '<div class="mb-3">'
      + (opts.requireLabel ? '<label class="form-label small" for="cd-input">' + escapeHtml(opts.requireLabel) + '</label>' : '')
      + '<input type="' + (opts.requirePassword ? 'password' : 'text') + '" class="form-control" id="cd-input"'
      + (opts.requirePassword ? ' autocomplete="current-password" placeholder="Your account password"' : ' autocomplete="off" autocapitalize="off" spellcheck="false"') + '>'
      + '<div class="small text-danger mt-1" id="cd-err" style="display:none;"></div>'
      + '</div>';
  }
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:11050;display:flex;align-items:center;justify-content:center;padding:1rem;';
  ov.innerHTML = '<div class="card" style="max-width:480px;width:100%;">'
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
      if (fresh && cur) cur.innerHTML = fresh.innerHTML;
      if (afterName && typeof window[afterName] === 'function') { try { window[afterName](); } catch(e){} }
    }).catch(function(){});
};
function _submitAjaxForm(form){
  var btn = form.querySelector('[type="submit"]'), orig = btn ? btn.innerHTML : '';
  if (btn){ btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
  var restore = function(){ if (btn){ btn.disabled = false; btn.innerHTML = orig; } };
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
        var doRefresh = function(){ if (sel) window.refreshSection(sel, after); };
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
window._da = function(action, args, on){        // build the attributes from JS that generates HTML
  var s = ' data-action="' + action + '"';
  if (args && args.length){ s += " data-args='" + JSON.stringify(args).replace(/'/g, '&#39;') + "'"; }
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
  confirmDialog({title:'Sign out everywhere', icon:'box-arrow-right', confirmClass:'btn-danger',
    confirmLabel:'Sign out everywhere',
    bodyText:'Sign out of ALL sessions, including this one? You will be logged back in fresh.',
    onConfirm:function(){ var f = document.getElementById('revoke-sessions-form'); if (f) f.submit(); }});
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
window.__isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints || 0) > 0;
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
    if(!d || d.installed === false){
      EL.innerHTML = '<div class="d-flex align-items-center gap-2 mb-2"><span class="badge bg-secondary">Not attached</span></div>'
        + '<p class="small text-secondary mb-2">Ubuntu Pro is <strong>free for personal use</strong> (up to 5 machines) and adds ~10 years of security updates (ESM) plus kernel <strong>Livepatch</strong>. Get a token at <a href="https://ubuntu.com/pro/dashboard" target="_blank" rel="noopener">ubuntu.com/pro/dashboard</a>. The client will be installed automatically when you attach.</p>'
        + attachForm() + '<div id="upro-msg" class="small mt-2"></div>';
      return;
    }
    if(!d.attached){
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
  function quietRefresh(){
    if(!EL) return;
    fetch(MOUNT + '/api/remote/' + HOST + '/pro-status').then(function(r){ return r.json(); })
      .then(render).catch(function(){});
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
