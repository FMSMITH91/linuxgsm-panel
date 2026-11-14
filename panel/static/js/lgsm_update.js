// LinuxGSM updates on the server page: what's new before updating (the "v26.6.0 available" note) and
// after (update-lgsm's reply). Needs serverId, MOUNT and server_detail.js's _showLgsmVersion.
//
// The release notes are a third party's Markdown. The server sends them as plain-text blocks
// (panel/services/lgsm_releases.py) and everything here goes in through textContent: no markup from
// them ever reaches the page. The one link drawn per release is to its page on GitHub, and only
// when it is one.
(function () {
  var RELEASES = 'https://github.com/GameServerManagers/LinuxGSM/releases';

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function releaseLink(url, label) {
    var a = el('a', 'small', label);
    a.href = (typeof url === 'string' && url.indexOf(RELEASES) === 0) ? url : RELEASES;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    return a;
  }

  // One release: its tag and date, then its blocks (a run of list items is one list).
  function releaseNode(r) {
    var box = el('div', 'mb-3');
    var head = el('div', 'fw-semibold', r.tag + (r.date ? ' · ' + r.date : ''));
    head.setAttribute('data-no-i18n', '');
    box.appendChild(head);
    var list = null;
    (r.blocks || []).forEach(function (b) {
      if (b.k === 'li') {
        if (!list) { list = el('ul', 'small mb-1 ps-3'); box.appendChild(list); }
        list.appendChild(el('li', null, b.t));
        return;
      }
      list = null;
      box.appendChild(el(b.k === 'h' ? 'div' : 'p', b.k === 'h' ? 'small fw-semibold mt-2' : 'small mb-1', b.t));
    });
    box.querySelectorAll('ul, p, div').forEach(function (n) { n.setAttribute('data-no-i18n', ''); });
    if (r.cut) box.appendChild(releaseLink(r.url, t('More in the full release notes')));
    return box;
  }

  // `reading`: the notes are being asked for now (fillNotes), so say so instead of "could not be read".
  function notesNode(notes, reading) {
    var wrap = el('div', 'mt-3');
    wrap.appendChild(el('h6', 'mb-2', t("What's new")));
    if (!notes || !notes.length) {
      wrap.appendChild(el('p', 'small text-secondary mb-1',
                          reading ? t('Reading the release notes…') : t('The release notes could not be read yet.')));
    }
    (notes || []).forEach(function (r) { wrap.appendChild(releaseNode(r)); });
    wrap.appendChild(releaseLink(RELEASES, t('All LinuxGSM release notes on GitHub')));
    return wrap;
  }

  // A dialog that never grows past the screen: the body scrolls, the header and footer stay.
  function dialog(title, ok, bodyNodes, footNodes) {
    var ov = el('div');
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1090;display:flex;'
      + 'align-items:center;justify-content:center;padding:1rem;';
    var card = el('div', 'card');
    card.style.cssText = 'max-width:760px;width:100%;max-height:85vh;display:flex;flex-direction:column;';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    var head = el('div', 'card-header d-flex justify-content-between align-items-center gap-2');
    var h = el('span');
    h.appendChild(el('i', 'bi bi-' + (ok ? 'arrow-up-circle' : 'x-circle')));
    h.appendChild(document.createTextNode(' ' + title));
    head.appendChild(h);
    var close = el('button', 'btn btn-sm btn-outline-secondary py-0 px-2', t('Close'));
    close.type = 'button';
    head.appendChild(close);
    var body = el('div', 'card-body');
    body.style.cssText = 'flex:1 1 auto;min-height:0;overflow-y:auto;';
    bodyNodes.forEach(function (n) { body.appendChild(n); });
    card.appendChild(head);
    card.appendChild(body);
    if (footNodes && footNodes.length) {
      var foot = el('div', 'card-footer d-flex justify-content-end gap-2');
      footNodes.forEach(function (n) { foot.appendChild(n); });
      card.appendChild(foot);
    }
    ov.appendChild(card);
    function shut() { ov.remove(); document.removeEventListener('keydown', onEsc); }
    function onEsc(e) { if (e.key === 'Escape') shut(); }
    close.addEventListener('click', shut);
    ov.addEventListener('click', function (e) { if (e.target === ov) shut(); });
    document.addEventListener('keydown', onEsc);
    document.body.appendChild(ov);
    close.focus();
    return shut;
  }

  // The "v26.6.0 available" note: what's new between this server's release and the latest, and
  // "Update LinuxGSM" for a viewer who may run it (the template says so on #lgsm-behind).
  window.showLgsmUpdate = function (btn) {
    var st = window._lgsmState || {};
    var info = st.info || {};
    if (!info.latest) return;
    var lead = el('p', 'mb-0', tf('This server is on {release}. LinuxGSM {latest} is available.',
                                  {release: info.release || '?', latest: info.latest}));
    var foot = [];
    var holder = document.getElementById('lgsm-behind');
    var shut;
    if (holder && holder.getAttribute('data-can-update') === '1') {
      var go = el('button', 'btn btn-sm btn-warning', t('Update LinuxGSM'));
      go.type = 'button';
      go.addEventListener('click', function () { shut(); _doServerAction('update-lgsm', btn, true); });
      foot.push(go);
    }
    var notes = notesNode(st.notes, !(st.notes && st.notes.length));
    shut = dialog(t('LinuxGSM update available'), true, [lead, notes], foot);
    if (!(st.notes && st.notes.length)) fillNotes(notes);
  };

  // The notes were not read yet when the page asked: ask again now, and put them in the dialog.
  function fillNotes(node) {
    fetch(MOUNT + '/api/server/' + serverId + '/version', {cache: 'no-store'})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var fresh = (d && d.lgsm_notes) || [];
        if (window._lgsmState) window._lgsmState.notes = fresh;
        node.replaceWith(notesNode(fresh, false));
      })
      .catch(function () { node.replaceWith(notesNode([], false)); });
  }

  // update-lgsm's reply: the page's LinuxGSM line now, then what happened and what's new.
  window.lgsmUpdateResult = function (d) {
    var info = d.lgsm || {};
    if (typeof _showLgsmVersion === 'function') _showLgsmVersion(info, []);
    var said = el('p', 'mb-0', d.message || '');
    said.setAttribute('data-no-i18n', '');   // the server translated it; a server's name is in it
    var nodes = [said];
    if (info.notes && info.notes.length) nodes.push(notesNode(info.notes));
    dialog(t('Update LinuxGSM'), !!d.success, nodes, []);
  };
})();
