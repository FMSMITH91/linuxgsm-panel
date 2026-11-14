// The host page's list of databases whose game server was removed from the panel
// (panel/routes/databases.py). The card stays hidden until the panel lists one. Rows are built with
// textContent: the names come from the server.
(function () {
  'use strict';
  var card = document.getElementById('host-db-card');
  if (!card) return;
  function T(s) { return window.t ? window.t(s) : s; }
  function api(tail) { return MOUNT + '/api/remote/' + REMOTE_ID + '/databases' + (tail || ''); }

  function item(db) {
    var li = document.createElement('li');
    li.className = 'd-flex flex-wrap align-items-center gap-2';
    var name = document.createElement('code');
    name.setAttribute('data-no-i18n', '');
    name.textContent = db.name;
    li.appendChild(name);
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm btn-outline-danger py-0';
    b.textContent = T('Delete');
    b.setAttribute('data-action', 'hostDbDelete');
    b.setAttribute('data-args', JSON.stringify([db.id, db.name]));
    li.appendChild(b);
    return li;
  }

  window.hostDbLoad = function () {
    return fetch(api(), {cache: 'no-store'}).then(function (r) { return r.ok ? r.json() : {}; }).then(function (d) {
      var list = document.getElementById('host-db-list'), dbs = (d && d.databases) || [];
      list.textContent = '';
      dbs.forEach(function (db) { list.appendChild(item(db)); });
      card.classList.toggle('d-none', !dbs.length);
      return dbs.length;
    }).catch(function () { return 0; });
  };

  window.hostDbDelete = function (id, name) {
    window.confirmDialog({title: T('Delete database'), icon: 'trash', confirmClass: 'btn-danger', confirmLabel: T('Delete'),
      bodyText: T('Delete this database and its user? A copy is kept on the host for 30 days.'),
      requireText: name, requireLabel: window.tf('Type the database name ({name}) to confirm:', {name: name}),
      onConfirm: function () {
        fetch(api('/' + id + '/delete'), {method: 'POST', headers: {'Content-Type': 'application/json'},
                                          body: JSON.stringify({confirm: name})})
          .then(function (r) { return r.json(); })
          .then(function (d) { if (window.toast) window.toast((d && d.message) || T('Failed'), d && d.success ? 'success' : 'danger'); return window.hostDbLoad(); })
          .catch(function () { if (window.toast) window.toast(T('Could not reach the panel. Try again.'), 'danger'); });
      }});
  };

  window.hostDbLoad();
})();
