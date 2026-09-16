// Settings page.
// Two-way sync between the colour swatch and the hex field. Attached here (not inline oninput=)
// because the strict CSP has no 'unsafe-inline' for scripts.
(function(){
  var pick = document.getElementById('s-accent-picker'), hex = document.getElementById('s-accent');
  if(!pick || !hex) return;
  pick.addEventListener('input', function(){ hex.value = pick.value; });
  hex.addEventListener('input', function(){ try { pick.value = hex.value; } catch(e){} });
})();
