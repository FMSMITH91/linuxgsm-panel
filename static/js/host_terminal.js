// The host terminal: xterm.js on one side, the panel's single Socket.IO connection on the other.
//
// Flat in static/js/ on purpose. The esprima parse gate and the JS i18n scanner both glob
// static/js/*.js and neither recurses, so a file in static/js/terminal/ would be checked by
// nothing at all.
//
// ES2017-era syntax only — the parse gate runs esprima 4.0.1, which rejects optional chaining,
// nullish coalescing, class fields and ||=. .eslintrc.json says ecmaVersion 2021 and disagrees;
// the gate is the binding one.

var term = null, fitAddonless = true, sock = null, opened = false;

function _sizeFor(el) {
  // No fit addon vendored — one more file to keep in the manifest for arithmetic this simple.
  // 9x18 is xterm's default cell for the 14px monospace stack below; close enough that a resize
  // lands within a row either way, and the server clamps anything silly.
  var w = Math.max(240, el.clientWidth), h = Math.max(120, el.clientHeight);
  return { cols: Math.max(20, Math.floor(w / 9)), rows: Math.max(5, Math.floor(h / 18)) };
}

function _status(msg, kind) {
  var el = document.getElementById('term-status');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'small ' + (kind === 'bad' ? 'text-danger' : kind === 'warn' ? 'text-warning'
                                                            : 'text-secondary');
}

function initTerminal() {
  var host = document.getElementById('terminal');
  if (!host || typeof Terminal === 'undefined') return;

  term = new Terminal({
    convertEol: false,
    cursorBlink: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    fontSize: 14,
    scrollback: 5000,
    theme: { background: '#0d1117', foreground: '#c9d1d9', cursor: '#58a6ff' }
  });
  term.open(host);

  // The panel has ONE socket connection; io() with no URL reuses the same origin and the same
  // authenticated session the console uses. The server's connect handler refuses anonymous ones.
  sock = io();

  var size = _sizeFor(host);
  sock.on('connect', function () {
    if (opened) return;              // a reconnect must not silently open a SECOND shell
    opened = true;
    sock.emit('term_open', { remote_id: REMOTE_ID, cols: size.cols, rows: size.rows });
  });

  sock.on('term_ready', function (d) {
    _status('Connected to ' + ((d && d.host) || 'the host') + '.', 'ok');
    term.focus();
  });

  sock.on('term_output', function (d) { if (d && d.data) term.write(d.data); });

  sock.on('term_error', function (d) {
    var msg = (d && d.message) || 'The terminal could not be opened.';
    _status(msg, 'bad');
    term.write('\r\n\x1b[31m' + msg + '\x1b[0m\r\n');
  });

  sock.on('term_exit', function (d) {
    var why = (d && d.reason) || 'the session ended';
    _status('Session closed — ' + why + '.', 'warn');
    term.write('\r\n\x1b[33m[' + why + ']\x1b[0m\r\n');
    opened = false;
  });

  sock.on('disconnect', function () {
    _status('Disconnected. Reload the page to start a new session.', 'warn');
    opened = false;
  });

  // Keystrokes go straight out and are never stored anywhere, here or on the server: people type
  // passwords into terminals.
  term.onData(function (data) { sock.emit('term_input', { data: data }); });

  var resizeTimer = null;
  window.addEventListener('resize', function () {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      var s = _sizeFor(host);
      term.resize(s.cols, s.rows);
      sock.emit('term_resize', { cols: s.cols, rows: s.rows });
    }, 200);
  });

  // Leaving the page takes the shell with it. The server also closes on disconnect; this just
  // makes the common case immediate rather than waiting for the socket to time out.
  window.addEventListener('beforeunload', function () {
    try { sock.emit('term_close', {}); } catch (e) { /* the socket may already be gone */ }
  });
}

document.addEventListener('DOMContentLoaded', initTerminal);
