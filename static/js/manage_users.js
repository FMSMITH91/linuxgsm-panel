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
  document.getElementById('eu-display').value = u.display_name || '';
  document.getElementById('eu-email').value = u.email || '';
  document.getElementById('eu-password').value = '';             // never prefill a password

  var groups = u.groups || [];
  document.querySelectorAll('.eu-group').forEach(function (cb) {
    cb.checked = groups.indexOf(parseInt(cb.value, 10)) !== -1;
  });

  document.getElementById('eu-superadmin').checked = !!u.is_superadmin;
  document.getElementById('eu-active').checked = !!u.is_active;

  // The 2FA reset only makes sense for someone who has it on; it starts unchecked every time so a
  // previous user's toggle can never carry over into the next one you open.
  var tfa = document.getElementById('eu-2fa-block');
  document.getElementById('eu-reset2fa').checked = false;
  tfa.style.display = u.totp_enabled ? '' : 'none';

  new bootstrap.Modal(document.getElementById('editUserModal')).show();
};
