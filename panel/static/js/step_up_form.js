// Forms whose POST asks a stale sign-in to confirm the password first (account_guard.step_up_required):
// <form data-step-up data-step-up-totp="1|0">, today Settings and Notifications.
//
// Sent as a plain form, a stale save would be redirected to the confirm page and everything typed
// into it (a new value, a pasted bot token) would be gone. So, just before such a form is sent, ask
// the server whether this sign-in needs confirming (/api/auth/ping?step_up=1). If it does, the
// password (and the 2FA code) is asked for in a dialog ON this page, confirmed with /account/reauth,
// and only then is the form sent, exactly as it was filled in. The server still decides: a form sent
// any other way, or a window that closes between the question and the send, meets the same refusal.
// The same check is window.stepUpThen(go, totp) for a page's own fetch() calls (below).
(function(){
  function mp(){ return window.MOUNT || ''; }
  function send(form){
    form.setAttribute('data-step-up-ok', '1');
    if (window.ensureCsrfFields) window.ensureCsrfFields(form.parentNode || document);   // its token, as panel.js gives every POST form
    // requestSubmit runs the browser's own field checks like a real submit (neither form has a
    // named button to carry); this listener lets it through because of the mark above.
    if (form.requestSubmit) form.requestSubmit(); else form.submit();
  }
  function intro(){
    var wrap = document.createElement('div');
    var p = document.createElement('p'); p.className = 'mb-3';
    p.textContent = t('This change needs your password again because you signed in a while ago. Nothing you typed is lost.');
    wrap.appendChild(p);
    return wrap;
  }
  function withCode(wrap){
    var box = document.createElement('div'); box.className = 'mb-1';
    var label = document.createElement('label'); label.className = 'form-label small'; label.htmlFor = 'su-code';
    label.textContent = 'Authentication code';   // the page's translator swaps it (its translation is shared)
    var code = document.createElement('input'); code.type = 'text'; code.id = 'su-code'; code.className = 'form-control';
    code.inputMode = 'numeric'; code.autocomplete = 'one-time-code'; code.maxLength = 14; code.placeholder = '000000';
    box.appendChild(label); box.appendChild(code); wrap.appendChild(box);
    return code;
  }
  // Ask for the password (and the code when `totp`) in a dialog on this page and confirm it with
  // /account/reauth; then go().
  function confirmThen(go, totp){
    var body = intro();
    var code = totp ? withCode(body) : null;
    window.confirmDialog({title: t('Confirm it is you'), icon: 'shield-lock', bodyNode: body,
      requirePassword: true, requireLabel: t('Password'), confirmLabel: t('Confirm and save'),
      onConfirm: function(password, api){
        var fd = new FormData();
        fd.append('password', password);
        if (code) fd.append('totp_code', code.value.trim());
        fetch(mp() + '/account/reauth', {method: 'POST', body: fd, cache: 'no-store'})
          .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, d: d || {}}; })
                              .catch(function(){ return {ok: false, d: {}}; }); })
          .then(function(res){
            if (res.ok && res.d.success) { api.close(); go(); return; }
            api.error(res.d.message || t('Incorrect.'));
          })
          .catch(function(){ api.error(t('Incorrect.')); });
      }});
  }
  // window.stepUpThen(go, totp): run go() once this sign-in may do a high-risk action, asking for
  // the password in place first when the server says it is needed. For a page's own fetch() to a
  // step_up_required route, so the page (and what was typed in it) stays put; a fetch sent without
  // it still meets the 403 + X-Reauth-Required that panel.js turns into the confirm page.
  window.stepUpThen = function(go, totp){
    fetch(mp() + '/api/auth/ping?step_up=1', {cache: 'no-store'})
      .then(function(r){ return r.ok ? r.json() : {}; })
      // No answer: go on and let the server decide (it refuses a stale request on its own).
      .then(function(d){ if (d && d.step_up === true) confirmThen(go, totp); else go(); })
      .catch(function(){ go(); });
  };
  document.addEventListener('submit', function(e){
    var form = e.target;
    if (!form || !form.hasAttribute || !form.hasAttribute('data-step-up')) return;
    // An .ajax-form is sent by panel.js's window.ajaxForm (its own fetch); handling it here too
    // would send it twice.
    if (form.classList && form.classList.contains('ajax-form')) return;
    if (form.getAttribute('data-step-up-ok') === '1') { form.removeAttribute('data-step-up-ok'); return; }
    e.preventDefault();
    window.stepUpThen(function(){ send(form); }, form.getAttribute('data-step-up-totp') === '1');
  });
})();
