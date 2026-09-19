// Backup-codes page. var CODES is set inline above.
function copyCodes(){
  // navigator.clipboard is UNDEFINED on an insecure origin, and the panel serves plain HTTP unless
  // HTTPS is turned on — http://<lan-ip>:<port> is the default way in. So the property read threw
  // before any promise existed, the rejection handler that would have said "Copy failed" never
  // ran, and panel.js's dispatcher has no try/catch: the click did nothing at all, silently, on
  // the one page whose whole point is getting the codes out of the browser. panel.js's copyText
  // was written for exactly this and falls back to execCommand.
  var msg = document.getElementById('copy-msg');
  var text = CODES.join('\n');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function(){
      if (msg) msg.textContent = 'Copied to clipboard.';
    }, function(){ fallbackCopy(); });
    return;
  }
  fallbackCopy();

  function fallbackCopy(){
    var ok = false;
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      ok = document.execCommand('copy');
      ta.remove();
    } catch (e) { ok = false; }
    if (msg) {
      msg.textContent = ok ? 'Copied to clipboard.'
                           : 'Copy failed — select the codes and copy manually.';
    }
  }
}
function downloadCodes(){
  var blob = new Blob([CODES.join('\n') + '\n'], {type: 'text/plain'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'linuxgsm-panel-backup-codes.txt';
  document.body.appendChild(a); a.click();
  setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 0);
}
