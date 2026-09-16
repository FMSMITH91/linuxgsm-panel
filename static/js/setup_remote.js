// Remote-host step of the setup wizard.
document.getElementById('auth-method').addEventListener('change', function() {
  var label = document.getElementById('credential-label');
  var input = document.querySelector('[name="credential"]');
  var field = document.getElementById('credential-field');
  if (this.value === 'password') {
    field.style.display = '';
    label.textContent = 'SSH Password';
    input.placeholder = 'Enter SSH password';
    input.value = '';
  } else if (this.value === 'tailscale') {
    field.style.display = 'none';
    input.value = '';
  } else {
    field.style.display = '';
    label.textContent = 'SSH Key Path';
    input.placeholder = '~/.ssh/id_rsa';
    input.value = '~/.ssh/id_rsa';
  }
});

function toggleSetupCreds() {
  // trigger the same logic from the select's onchange
  document.getElementById('auth-method').dispatchEvent(new Event('change'));
}
