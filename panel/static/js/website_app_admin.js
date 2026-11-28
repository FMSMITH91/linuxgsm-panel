// The site's app administrator (templates/_website_app_admin.html): Reset admin password lists the WordPress
// site's administrators after the password check, then sets the chosen one's new password and, if typed, email.
// A generated password is shown once, masked until Show is pressed (secret_field.js); a typed one is not sent back.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId || !WS.el('wadm-card')) return;
  var ID = WS.siteId;

  function fillUsers(users) {
    var sel = WS.el('wadm-user');
    WS.clear(sel);
    users.forEach(function (u) {
      var o = WS.node('option', null, String(u));
      o.value = String(u);
      sel.appendChild(o);
    });
  }

  window.wsAdminOpen = function () {
    WS.stepUp(function () {
      WS.say('wadm-msg', WS.T('Asking WordPress for its administrators…'));
      WS.post('/websites/' + ID + '/app-admin/users', {}).then(function (d) {
        var users = d && d.success && Array.isArray(d.users) ? d.users : [];
        if (!users.length) { WS.done(d && d.success === false ? d : {success: false, message: WS.T('No administrator was found.')}, 'wadm-msg'); return; }
        fillUsers(users);
        WS.say('wadm-msg', '');
        WS.show('wadm-form', true);
      });
    });
  };

  function showResult(d) {
    var box = WS.el('wadm-result');
    WS.clear(box);
    WS.show(box, true);
    var line = WS.node('div', 'd-flex flex-wrap gap-2 align-items-center');
    line.appendChild(WS.node('span', 'text-secondary', WS.TF('New password for {user}:', {user: String(d.user || '')})));
    line.lastChild.setAttribute('data-no-i18n', '');
    line.appendChild(window.secretField({value: String(d.password)}));
    box.appendChild(line);
    box.appendChild(WS.node('div', 'form-text mt-0', WS.T('Shown once: the panel does not keep it. Copy it into your password manager now.')));
  }

  window.wsAdminReset = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    var pw = WS.el('wadm-pw'), email = WS.el('wadm-email');
    var body = {user: WS.el('wadm-user').value, password: pw.value, email: email.value.trim()};
    WS.show('wadm-result', false);
    WS.stepUp(function () {
      WS.say('wadm-msg', WS.T('Working…'));
      WS.post('/websites/' + ID + '/app-admin/reset', body).then(function (d) {
        pw.value = '';
        if (!WS.done(d, 'wadm-msg')) return;
        email.value = '';
        if (d.generated && d.password) showResult(d);
      });
    });
  };
})();
