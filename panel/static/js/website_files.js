// The Files panel of a website (templates/_website_files.html): the site's docroot, as the site's own
// account, through /websites/<id>/files/*:
//   GET  list?path=   -> {success, path, entries: [{name, dir, size, editable}]}
//   GET  read?path=   -> {success, content}       GET download?path= (a link)
//   POST save {path, content} | mkdir {path, name} | rename {path, new_name} | delete {path}
//   POST upload (form: path, file)  | extract (form: path, archive)
// Paths are relative to the docroot; the server normalises them and refuses anything outside it, a
// link out of it, and an archive entry that is absolute, climbs out, or is a link or a device.
(function () {
  'use strict';
  var WS = window.WS;
  if (!WS || !WS.siteId) return;
  var st = {path: '', file: '', loaded: false};
  function f(verb) { return WS.R.act(WS.siteId, 'files/' + verb); }
  function join(dir, name) { return dir ? dir + '/' + name : name; }
  function parent(p) { var i = p.lastIndexOf('/'); return i < 0 ? '' : p.slice(0, i); }

  function entryRow(e) {
    var li = WS.node('li', 'ws-file');
    var p = join(st.path, e.name);
    var name = WS.node('button', 'btn btn-link btn-sm p-0 text-start text-break ws-file-name');
    name.type = 'button';
    name.appendChild(WS.icon(e.dir ? 'folder-fill text-warning' : 'file-earmark'));
    name.appendChild(WS.raw('span', 'ms-1', e.name));
    name.setAttribute('data-action', e.dir ? 'wsFilesGo' : (e.editable ? 'wsFilesEdit' : 'wsFilesDownload'));
    name.setAttribute('data-args', JSON.stringify([p]));
    li.appendChild(name);
    if (!e.dir && e.size != null) li.appendChild(WS.raw('span', 'small text-secondary ws-file-size', String(e.size)));
    var acts = WS.node('span', 'ws-file-acts');
    if (!e.dir) acts.appendChild(iconButton('download', 'Download', 'wsFilesDownload', p));
    acts.appendChild(iconButton('pencil', 'Rename', 'wsFilesRename', p));
    acts.appendChild(iconButton('trash', 'Delete', 'wsFilesDelete', p));
    li.appendChild(acts);
    return li;
  }
  function iconButton(icon, label, action, p) {
    var b = WS.button('', icon, action, [p], 'btn-outline-secondary py-0');
    b.setAttribute('aria-label', WS.T(label));
    b.title = WS.T(label);
    return b;
  }
  function list(path) {
    WS.get(f('list') + '?path=' + encodeURIComponent(path)).then(function (d) {
      var box = WS.clear(WS.el('wf-list'));
      if (!d || !d.success) { WS.done(d, 'wf-msg'); return; }
      st.path = typeof d.path === 'string' ? d.path : path;
      st.loaded = true;
      WS.el('wf-path').textContent = '/' + st.path;
      var rows = d.entries || [];
      if (!rows.length) box.appendChild(WS.node('li', 'small text-secondary', WS.T('This folder is empty.')));
      rows.forEach(function (e) { box.appendChild(entryRow(e)); });
    });
  }
  window.wsFilesOpen = function () { if (!st.loaded) list(''); };
  window.wsFilesGo = function (p) { window.wsFilesClose(); list(p); };
  window.wsFilesUp = function () { window.wsFilesGo(parent(st.path)); };
  window.wsFilesDownload = function (p) { location.href = WS.url(f('download') + '?path=' + encodeURIComponent(p)); };
  window.wsFilesEdit = function (p) {
    WS.get(f('read') + '?path=' + encodeURIComponent(p)).then(function (d) {
      if (!d || !d.success) { WS.done(d, 'wf-msg'); return; }
      st.file = p;
      WS.el('wf-editing').textContent = '/' + p;
      WS.el('wf-text').value = d.content || '';
      WS.show('wf-editor', true);
    });
  };
  window.wsFilesClose = function () { st.file = ''; WS.show('wf-editor', false); };
  window.wsFilesSave = function (e) {
    if (e && e.preventDefault) e.preventDefault();
    WS.post(f('save'), {path: st.file, content: WS.el('wf-text').value}).then(function (d) { WS.done(d, 'wf-msg'); });
  };
  function ask(title, value, go) {
    var inp = nameField(value);
    window.confirmDialog({title: WS.T(title), icon: 'pencil', confirmLabel: WS.T('Save'),
      bodyNode: inp, onConfirm: function () { go(inp.value.trim()); }});
  }
  function nameField(value) {
    var inp = WS.node('input', 'form-control form-control-sm');
    inp.type = 'text';
    inp.maxLength = 255;
    inp.value = value || '';
    inp.setAttribute('aria-label', WS.T('Name'));
    inp.setAttribute('autocomplete', 'off');
    return inp;
  }
  window.wsFilesNew = function (kind) {
    ask(kind === 'dir' ? 'New folder' : 'New file', '', function (name) {
      if (!name) return;
      var req = kind === 'dir' ? WS.post(f('mkdir'), {path: st.path, name: name}) : WS.post(f('save'), {path: join(st.path, name), content: ''});
      req.then(function (d) { if (WS.done(d, 'wf-msg')) list(st.path); });
    });
  };
  window.wsFilesRename = function (p) {
    var old = p.slice(p.lastIndexOf('/') + 1);
    ask('Rename', old, function (name) {
      if (!name || name === old) return;
      WS.post(f('rename'), {path: p, new_name: name}).then(function (d) { if (WS.done(d, 'wf-msg')) list(st.path); });
    });
  };
  window.wsFilesDelete = function (p) {
    window.confirmDialog({title: WS.T('Delete this?'), icon: 'trash', confirmClass: 'btn-danger', confirmLabel: WS.T('Delete'),
      bodyText: '/' + p, onConfirm: function () {
        WS.post(f('delete'), {path: p}).then(function (d) { if (WS.done(d, 'wf-msg')) list(st.path); });
      }});
  };
  window.wsFilesPick = function (id) { var i = WS.el(id); if (i) i.click(); };
  function send(verb, field, file) {
    var fd = new FormData();
    fd.append('path', st.path);
    fd.append(field, file);
    return WS.postForm(f(verb), fd);
  }
  window.wsFilesUpload = function () {
    var inp = WS.el('wf-upload');
    var files = Array.prototype.slice.call(inp.files || []);
    if (!files.length) return;
    WS.say('wf-msg', WS.TF('Uploading {n} files…', {n: files.length}));
    files.reduce(function (p, file) {
      return p.then(function () { return send('upload', 'file', file).then(function (d) { if (!d.success) WS.done(d, 'wf-msg'); }); });
    }, Promise.resolve()).then(function () { inp.value = ''; WS.say('wf-msg', WS.T('Upload finished.'), 'ok'); list(st.path); });
  };
  window.wsFilesExtract = function () {
    var inp = WS.el('wf-archive');
    var file = inp.files && inp.files[0];
    if (!file) return;
    WS.say('wf-msg', WS.T('Uploading and checking the archive…'));
    send('extract', 'archive', file).then(function (d) { inp.value = ''; if (WS.done(d, 'wf-msg')) list(st.path); });
  };
})();
