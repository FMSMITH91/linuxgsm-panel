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
    input.placeholder = 'Enter SSH password';
    input.value = '';
    input.type = 'password';
    input.autocomplete = 'new-password';
  } else if (this.value === 'tailscale') {
    field.style.display = 'none';
    input.value = '';
    input.type = 'text';
    input.autocomplete = 'off';
  } else {
    field.style.display = '';
    input.type = 'text';
    input.autocomplete = 'off';
    label.textContent = 'SSH Key Path';
    input.placeholder = '~/.ssh/id_rsa';
    input.value = '~/.ssh/id_rsa';
  }
});

function toggleSetupCreds() {
  // trigger the same logic from the select's onchange
  document.getElementById('auth-method').dispatchEvent(new Event('change'));
}
