// Backup-codes page. var CODES is set inline above.
function copyCodes(){
  navigator.clipboard.writeText(CODES.join('\n')).then(function(){
    document.getElementById('copy-msg').textContent = 'Copied to clipboard.';
  }, function(){ document.getElementById('copy-msg').textContent = 'Copy failed — select the codes and copy manually.'; });
}
function downloadCodes(){
  var blob = new Blob([CODES.join('\n') + '\n'], {type: 'text/plain'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'linuxgsm-panel-backup-codes.txt';
  document.body.appendChild(a); a.click();
  setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 0);
}
