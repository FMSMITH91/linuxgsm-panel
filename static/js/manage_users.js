// Populate the one shared edit modal from the #users-data JSON island.
//
// This page used to render a full 2KB edit modal per user — ~210KB of duplicated markup at 100
// accounts, all of it for one dialog you can only have open once. The rows now carry an id and the
// data comes from a single JSON blob, which is ~120 bytes per user.
function _euUsers() {
  var el = document.getElementById('users-data');
  if (!el) return [];
  try {
    return JSON.parse(el.textContent) || [];
  } catch (e) {
    return [];   // a malformed island must not take the page down with it
  }
}

window.openEditUser = function (id) {
  var u = null, all = _euUsers();
  for (var i = 0; i < all.length; i++) {
    if (all[i].id === id) { u = all[i]; break; }
  }
  if (!u) return;

  // Coerce the id to a number before it reaches the form action. It is always an integer from our
  // own database, but it arrives here as text read out of the DOM, and a form action is a URL sink
  // — CodeQL flags that flow (js/xss-through-dom) and is right to. parseInt both proves the value
  // cannot carry meta-characters and rejects a tampered island outright.
  var uid = parseInt(u.id, 10);
  if (!(uid > 0)) return;

  var form = document.getElementById('edit-user-form');
  form.setAttribute('action', (window.MOUNT || '') + '/users/' + uid + '/edit');

  document.getElementById('eu-name').textContent = u.username;   // textContent: never HTML
  // Populated, not left blank: the field posts back as the username, so an unfilled one would
  // submit empty and the route would read "no change" — or, with the browser's `required`, refuse
  // to submit at all with nothing to show for it.
  document.getElementById('eu-username').value = u.username || '';
  document.getElementById('eu-display').value = u.display_name || '';
  document.getElementById('eu-email').value = u.email || '';

  var groups = u.groups || [];
  document.querySelectorAll('.eu-group').forEach(function (cb) {
    cb.checked = groups.indexOf(parseInt(cb.value, 10)) !== -1;
  });

  // The superadmin switch is rendered only for a superadmin — the route refuses the grant from
  // anyone else, so offering it was a control that threw the whole form away. GUARDED, not
  // assumed: an unguarded .checked on the absent element throws, and everything after it here —
  // the active switch, the 2FA reset, the password reset, and the modal's own .show() — would
  // never run, so the Edit dialog simply would not open for a delegated user admin.
  var euSuper = document.getElementById('eu-superadmin');
  if (euSuper) { euSuper.checked = !!u.is_superadmin; }
  document.getElementById('eu-active').checked = !!u.is_active;

  // The 2FA reset only applies to someone who has it on, but the control is SHOWN either way:
  // hiding it meant an admin looking for "reset this person's 2FA" found an empty dialog and no
  // way to tell a missing feature from an inapplicable one. Disabled + a reason instead.
  // It starts unchecked every time so a previous user's toggle can never carry into the next one.
  var box = document.getElementById('eu-reset2fa');
  var help = document.getElementById('eu-2fa-help');
  box.checked = false;
  box.disabled = !u.totp_enabled;
  if (help) {
    help.textContent = u.totp_enabled
      ? "Use this if they've lost their authenticator. They can re-enable it from their Account page."
      : "This account doesn't have two-factor authentication enabled, so there's nothing to reset.";
  }

  // Same reasoning as the 2FA box: a password reset is destructive and must be chosen fresh each
  // time the dialog opens, never inherited from the last user you edited.
  document.getElementById('eu-reset-password').checked = false;

  new bootstrap.Modal(document.getElementById('editUserModal')).show();
};

// Show a one-time password the server just minted. Called by the ajax-form handler the moment the
// response lands (see _submitAjaxForm) — the panel keeps only the hash, so if this is missed the
// password is gone and the account has to be reset again.
//
// Values go in through .value and .textContent, never innerHTML: a username is user-authored text,
// and the generated password contains symbols that are markup if you treat them as markup.
window.showCredential = function(cred){
  if (!cred || !cred.password) return;
  var who = document.getElementById('cred-user'), pw = document.getElementById('cred-pw');
  if (!who || !pw) return;
  who.textContent = cred.username || '';
  pw.value = cred.password;
  new bootstrap.Modal(document.getElementById('credentialModal')).show();
};
window.copyCredential = function(){
  var pw = document.getElementById('cred-pw');
  if (!pw) return;
  if (window.copyText) copyText(pw.value, 'Password copied');
  else if (navigator.clipboard) navigator.clipboard.writeText(pw.value);
};
