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
    if (window.ensureCsrfFields) window.ensureCsrfFields(form);   // a template's form already has its token
    // requestSubmit runs the browser's own field checks like a real submit (neither form has a
    // named button to carry); this listener lets it through because of the mark above.
    if (form.requestSubmit) form.requestSubmit(); else form.submit();
  }
  // The words follow what is being confirmed: a form's save keeps what was typed into it ("Nothing
  // you typed is lost", "Confirm and save"), but most callers of stepUpThen (a reboot, a delete, a
  // restore, a poll that finishes a Tailscale setup) save nothing typed, and said so for all of them.
  function intro(form){
    var wrap = document.createElement('div');
    var p = document.createElement('p'); p.className = 'mb-3';
    p.textContent = form ? t('This change needs your password again because you signed in a while ago. Nothing you typed is lost.')
                         : t('This action needs your password again because you signed in a while ago.');
    wrap.appendChild(p);
    return wrap;
  }
  function withCode(wrap){
    var box = document.createElement('div'); box.className = 'mb-1';
    var label = document.createElement('label'); label.className = 'form-label small'; label.htmlFor = 'su-code';
    label.textContent = 'Authentication code';   // the page's translator swaps it (its translation is shared)
    var code = document.createElement('input'); code.type = 'text'; code.id = 'su-code'; code.className = 'form-control';
    // No numeric keypad: a backup code (letters and a dash) is taken here too (_reauth_refusal).
    code.autocomplete = 'one-time-code'; code.maxLength = 14; code.placeholder = '000000';
    box.appendChild(label); box.appendChild(code); wrap.appendChild(box);
    return code;
  }
  // Ask for the password (and the code when `totp`) in a dialog on this page and confirm it with
  // /account/reauth; then go(). `cancelled` (optional) runs when the dialog is closed unconfirmed.
  // `form`: the dialog is for a data-step-up form's save (its words, above).
  function confirmThen(go, totp, cancelled, form){
    var body = intro(form);
    var code = totp ? withCode(body) : null;
    // Cancel stays live while the password is checked. Pressed then, the dialog is gone and the
    // caller told it was cancelled, so the check's answer must not run the action after all.
    var gone = false;
    window.confirmDialog({title: t('Confirm it is you'), icon: 'shield-lock', bodyNode: body,
      requirePassword: true, requireLabel: t('Password'), confirmLabel: form ? t('Confirm and save') : t('Confirm'),
      onCancel: function(){ gone = true; if (cancelled) cancelled(); },
      onConfirm: function(password, api){
        var fd = new FormData();
        fd.append('password', password);
        if (code) fd.append('totp_code', code.value.trim());
        fetch(mp() + '/account/reauth', {method: 'POST', body: fd, cache: 'no-store'})
          .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, d: d || {}}; })
                              .catch(function(){ return {ok: false, d: {}}; }); })
          .then(function(res){
            if (gone) return;
            if (res.ok && res.d.success) { api.close(); go(); return; }
            api.error(res.d.message || t('Incorrect.'));
          })
          .catch(function(){ if (!gone) api.error(t('Incorrect.')); });
      }});
  }
  // window.stepUpThen(go, totp, cancelled, form): run go() once this sign-in may do a high-risk action,
  // asking for the password in place first when the server says it is needed. For a page's own
  // fetch() to a step_up_required route, so the page (and what was typed in it) stays put; a fetch
  // sent without it still meets the 403 + X-Reauth-Required that panel.js turns into the confirm
  // page. `cancelled` (optional) runs when the password dialog is closed without confirming, for a
  // control that already shows the unsaved change (a switch) to show the saved state again. `form`
  // (optional, true): go() sends a form's typed fields (panel.js's ajax data-step-up forms), so the
  // dialog uses the form-save words.
  function stepUp(go, totp, cancelled, form){
    fetch(mp() + '/api/auth/ping?step_up=1', {cache: 'no-store'})
      .then(function(r){ return r.ok ? r.json() : {}; })
      // No answer: go on and let the server decide (it refuses a stale request on its own).
      .then(function(d){ if (d && d.step_up === true) confirmThen(go, totp, cancelled, form); else go(); })
      .catch(function(){ go(); });
  }
  window.stepUpThen = function(go, totp, cancelled, form){ stepUp(go, totp, cancelled, form === true); };
  document.addEventListener('submit', function(e){
    var form = e.target;
    if (!form || !form.hasAttribute || !form.hasAttribute('data-step-up')) return;
    // An .ajax-form is sent by panel.js's window.ajaxForm (its own fetch); handling it here too
    // would send it twice.
    if (form.classList && form.classList.contains('ajax-form')) return;
    if (form.getAttribute('data-step-up-ok') === '1') { form.removeAttribute('data-step-up-ok'); return; }
    e.preventDefault();
    stepUp(function(){ send(form); }, form.getAttribute('data-step-up-totp') === '1', null, true);
  });
})();
