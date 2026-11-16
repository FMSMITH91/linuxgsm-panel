// The panel's alerts service worker: shows a Web Push alert, and opens the panel page it is about.
//
// Scoped to its own folder (static/push/), so it controls no panel page and handles no fetch: all it
// does is receive pushes for this device's subscription, which keeps working when the panel tab is
// closed and when its user is signed out. The payload is encrypted end to end (RFC 8291) by the panel
// and holds only {title, body, url}; `url` is a path under the panel's root, and nothing outside this
// origin and that root is ever opened.
'use strict';

function panelRoot() {
  // The scope is <panel root>/static/push/, under whatever prefix the panel is mounted at.
  return new URL('../../', self.registration.scope);
}

function text(value, max) {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

self.addEventListener('push', function (event) {
  var data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = {};
  }
  var title = text(data.title, 120) || 'LinuxGSM Panel';
  event.waitUntil(self.registration.showNotification(title, {
    body: text(data.body, 300),
    data: {url: text(data.url, 200)}
  }));
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var root = panelRoot();
  var target = root;
  try {
    target = new URL(text(event.notification.data && event.notification.data.url, 200), root);
  } catch (e) {
    target = root;
  }
  if (target.origin !== root.origin || target.pathname.indexOf(root.pathname) !== 0) {
    target = root;
  }
  event.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(function (list) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].url === target.href && 'focus' in list[i]) {
        return list[i].focus();
      }
    }
    return self.clients.openWindow(target.href);
  }));
});
