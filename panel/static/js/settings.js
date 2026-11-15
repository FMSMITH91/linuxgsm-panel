// Settings page.
// Two-way sync between the colour swatch and the hex field. Attached here (not inline oninput=)
// because the strict CSP has no 'unsafe-inline' for scripts.
(function(){
  var pick = document.getElementById('s-accent-picker'), hex = document.getElementById('s-accent');
  if(!pick || !hex) return;
  pick.addEventListener('input', function(){ hex.value = pick.value; });
  hex.addEventListener('input', function(){ try { pick.value = hex.value; } catch(e){} });
})();

// Sessions & Security: the "Longer than OWASP recommends" note under a lifetime field follows the
// value as it is typed (data-owasp-max is OWASP's upper bound). A note, never a refusal.
(function(){
  [['s-idle', 's-idle-note'], ['s-absolute', 's-absolute-note']].forEach(function(pair){
    var field = document.getElementById(pair[0]), note = document.getElementById(pair[1]);
    if(!field || !note) return;
    var max = Number(field.getAttribute('data-owasp-max'));
    function sync(){
      var v = Number(field.value);
      note.classList.toggle('d-none', !(Number.isFinite(v) && v > max));
    }
    field.addEventListener('input', sync);
    sync();
  });
})();
