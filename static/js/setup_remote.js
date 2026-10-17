// Remote-host step of the setup wizard.
document.getElementById('auth-method').addEventListener('change', function() {
  var label = document.getElementById('credential-label');
  var input = document.querySelector('[name="credential"]');
  var field = document.getElementById('credential-field');
  // The one field carries a key PATH or a PASSWORD, so its type follows the method. It stayed
  // type="text" for a password: the remote's root password was shown in clear, and the browser kept
  // it as an ordinary autofill entry for any input named "credential", restored in clear later.
  if (this.value === 'password') {
    field.style.display = '';
    label.textContent = 'SSH Password';
    // t(), and its key named for setLang: the add form's twin of this field is data-no-i18n, and the
    // gate (i18n_scan.guarded_tcall_writes) knows the field by its name only.
    input.setAttribute('data-i18n-placeholder', 'Enter SSH password');
    input.placeholder = t('Enter SSH password');
    input.value = '';
    input.type = 'password';
    input.autocomplete = 'new-password';
  } else if (this.value === 'tailscale') {
    input.removeAttribute('data-i18n-placeholder');
    field.style.display = 'none';
    input.value = '';
    input.type = 'text';
    input.autocomplete = 'off';
  } else {
    field.style.display = '';
    input.type = 'text';
    input.autocomplete = 'off';
    label.textContent = 'SSH Key Path';
    input.removeAttribute('data-i18n-placeholder');   // a path, not a key: a switch leaves it alone
    input.placeholder = '~/.ssh/id_rsa';
    input.value = '~/.ssh/id_rsa';
  }
});

// A browser that restores a form's state on reload or on back/forward (Firefox does, for a select
// with no autocomplete="off") puts the select back on Password or Tailscale SSH without a `change`:
// the field stayed a visible text box labelled for a key path, and the password typed into it showed
// in clear. `pageshow` comes after that restore, so the field is matched to the select then. "SSH
// Key" is the markup's own state: a restored path is left alone.
window.addEventListener('pageshow', function(){
  var sel = document.getElementById('auth-method');
  if (sel && sel.value !== 'key') sel.dispatchEvent(new Event('change'));
});

function toggleSetupCreds() {
  // trigger the same logic from the select's onchange
  document.getElementById('auth-method').dispatchEvent(new Event('change'));
}
