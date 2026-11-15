// Sidebar "Sign Out": a browser that has alerts on goes to the sign-out page first, which says its alerts
// keep arriving after sign-out and offers to stop them. Any other browser signs out at once, as before.
// Asked of the browser itself (its push subscription), so no page pays a database query for it.
(function () {
  var form = document.querySelector('form[data-push-signout]');
  if (!form || !window.isSecureContext || !('serviceWorker' in navigator)) return;
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var settled = false;
    function go(hasAlerts) {
      if (settled) return;
      settled = true;
      if (hasAlerts) {
        // The sign-out page's own path, rendered by the server; only ever on this origin.
        var u = new URL(form.getAttribute('data-push-signout') || '/', window.location.href);
        if (u.origin === window.location.origin) { window.location.assign(u.href); return; }
      }
      if (window.ensureCsrfFields) window.ensureCsrfFields(form);
      form.submit();
    }
    // Never hold a sign-out hostage to a slow answer.
    window.setTimeout(function () { go(false); }, 1500);
    navigator.serviceWorker.getRegistration(form.getAttribute('data-push-scope'))
      .then(function (reg) { return reg ? reg.pushManager.getSubscription() : null; })
      .then(function (sub) { go(!!sub); }, function () { go(false); });
  });
})();
