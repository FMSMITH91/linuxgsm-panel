// Settings -> Schedules (panel/routes/schedules.py). Times are stored in UTC; here they are shown
// and typed in the viewer's own zone. The form sends that zone (#sch-tz), and the server converts
// what was typed back to UTC. Without this script the fields stay in UTC, the zone stays empty and
// the labels keep saying "(UTC)", so a save still means what it shows.
(function(){
  var tzBox = document.getElementById('sch-tz');
  if (!tzBox) return;
  var zone = '';
  try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { zone = ''; }
  if (!zone) return;
  tzBox.value = zone;
  document.querySelectorAll('#sec-schedules .sch-zone').forEach(function(el){ el.textContent = '(' + zone + ')'; });
  function two(n){ return (n < 10 ? '0' : '') + n; }
  document.querySelectorAll('#sec-schedules input[data-utc-hhmm]').forEach(function(box){
    var m = /^(\d{2}):(\d{2})$/.exec(box.getAttribute('data-utc-hhmm') || '');
    if (!m) return;
    var now = new Date();
    var d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(),
                              Number.parseInt(m[1], 10), Number.parseInt(m[2], 10)));
    box.value = two(d.getHours()) + ':' + two(d.getMinutes());
  });
})();

// The OS update check's switch asks before it goes off, as the Outside services switches do: it is
// put back on at once and turned off only on Confirm. Its "outside OWASP's recommendation" note
// follows it, on load and on pageshow too: a switch the browser restores to its unsaved state (a
// reload in Firefox) fires no change. A note, never a refusal.
(function(){
  var box = document.getElementById('sch-os');
  if (!box) return;
  var note = document.getElementById('sch-os-owasp');
  function sync(){ if (note) note.classList.toggle('d-none', box.checked); }
  window.addEventListener('pageshow', sync);
  sync();
  box.addEventListener('change', function(){
    if (box.checked || !window.confirmDialog) { sync(); return; }
    box.checked = true;
    window.confirmDialog({title: t('Schedules'), icon: 'exclamation-triangle', confirmClass: 'btn-warning',
      confirmLabel: t('Turn the check off'), bodyText: box.getAttribute('data-confirm-off'),
      onConfirm: function(){ box.checked = false; sync(); }});
  });
})();
