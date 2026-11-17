// Settings page.
// Two-way sync between the colour swatch and the hex field. Attached here (not inline oninput=)
// because the strict CSP has no 'unsafe-inline' for scripts.
(function(){
  var pick = document.getElementById('s-accent-picker'), hex = document.getElementById('s-accent');
  if(!pick || !hex) return;
  pick.addEventListener('input', function(){ hex.value = pick.value; });
  hex.addEventListener('input', function(){ try { pick.value = hex.value; } catch(e){} });
})();

// Sessions & Security: the "Longer than ... recommends" note under a field follows the value as it
// is typed (data-owasp-max is the recommended upper bound: OWASP's, or NIST's for step-up, where
// OWASP gives none), and so does the step-up field's "Off" note at 0 (data-off-note). Notes, never
// a refusal.
(function(){
  [['s-idle', 's-idle-note'], ['s-absolute', 's-absolute-note'], ['s-stepup', 's-stepup-note']].forEach(function(pair){
    var field = document.getElementById(pair[0]), note = document.getElementById(pair[1]);
    if(!field || !note) return;
    var max = Number(field.getAttribute('data-owasp-max'));
    var off = document.getElementById(field.getAttribute('data-off-note') || '');
    function sync(){
      var v = Number(field.value);
      note.classList.toggle('d-none', !(Number.isFinite(v) && v > max));
      if(off) off.classList.toggle('d-none', !(field.value !== '' && v === 0));
    }
    field.addEventListener('input', sync);
    sync();
  });
})();

// Outside services: a switch with data-confirm-off (the update check, the breached-password check)
// asks before it goes off. It is put back on at once and turned off only on Confirm, so Cancel, the
// Escape key or a click outside the dialog all leave it on. Turning a switch on never asks. Its
// "outside OWASP's recommendation" note (#s-<name>-owasp) follows the switch: a note, never a refusal.
(function(){
  document.querySelectorAll('#sec-outside input[data-confirm-off]').forEach(function(box){
    var note = document.getElementById(box.id + '-owasp');
    function sync(){ if (note) note.classList.toggle('d-none', box.checked); }
    box.addEventListener('change', function(){
      if (box.checked || !window.confirmDialog) { sync(); return; }
      box.checked = true;
      window.confirmDialog({title: t('Outside services'), icon: 'exclamation-triangle', confirmClass: 'btn-warning',
        confirmLabel: t('Turn this service off'), bodyText: box.getAttribute('data-confirm-off'),
        onConfirm: function(){ box.checked = false; sync(); }});
    });
  });
})();
