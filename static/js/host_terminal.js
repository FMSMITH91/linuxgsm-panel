// The host terminal: xterm.js on one side, the panel's single Socket.IO connection on the other.
//
// Flat in static/js/ on purpose. The esprima parse gate and the JS i18n scanner both glob
// static/js/*.js and neither recurses, so a file in static/js/terminal/ would be checked by
// nothing at all.
//
// ES2017-era syntax only — the parse gate runs esprima 4.0.1, which rejects optional chaining,
// nullish coalescing, class fields and ||=. .eslintrc.json says ecmaVersion 2021 and disagrees;
// the gate is the binding one.

var term = null, sock = null, opened = false, hostLabel = '', sawOutput = false;

function _cellSize() {
  // MEASURED, not assumed. This was hardcoded at 9x18 "close enough that a resize lands within a
  // row either way"; the real cell for this font stack is 8.4x19, so the guess was out by nearly
  // three columns in forty and a row and a half in twenty-five. .xterm-screen is exactly
  // cols x rows cells, so dividing gives the true figure whatever the font resolves to.
  var el = document.querySelector('.xterm-screen');
  if (el && term && term.cols > 0 && term.rows > 0) {
    var r = el.getBoundingClientRect();
    if (r.width > 0 && r.height > 0) return { w: r.width / term.cols, h: r.height / term.rows };
  }
  return { w: 9, h: 18 };       // only before the first render, when nothing is on screen yet
}

function _sizeFor(el) {
  // No fit addon vendored — one more file to keep in the manifest for arithmetic this simple.
  // clientWidth INCLUDES the box's padding, so sizing to it puts two columns of terminal under
  // the padding and back out over the edge. Take the padding off first.
  var cs = window.getComputedStyle(el);
  var padX = (parseFloat(cs.paddingLeft) || 0) + (parseFloat(cs.paddingRight) || 0);
  var padY = (parseFloat(cs.paddingTop) || 0) + (parseFloat(cs.paddingBottom) || 0);
  var cell = _cellSize();
  var w = Math.max(cell.w * 20, el.clientWidth - padX);
  var h = Math.max(cell.h * 5, el.clientHeight - padY);
  return { cols: Math.max(20, Math.floor(w / cell.w)), rows: Math.max(5, Math.floor(h / cell.h)) };
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

  // The panel has ONE socket connection; io() reuses the same origin and the same authenticated
  // session the console uses. The server's connect handler refuses anonymous ones.
  //
  // The PATH has to carry the mount. io() with no options uses socket.io-client's built-in
  // default, "/socket.io" at the site root — so on a panel served under a sub-path (Tailscale
  // Serve with mount /lgsm) the handshake went outside the mount and 404'd: `connect` never
  // fired, term_open was never emitted, and the page sat on "Connecting…" over a blank black box
  // for ever, because term_error and disconnect both need a connection that was never made. Every
  // other socket in the panel already prefixes it — panel.js:7, server_detail.js:232 — and this
  // is the same call they make.
  sock = io({ path: (window.MOUNT || '') + '/socket.io', transports: ['websocket', 'polling'] });

  // Resize the emulator BEFORE telling the server, and tell it the size we actually applied.
  // These were two different numbers: the pty was opened at the computed size while xterm stayed
  // at its 80x24 default, so the shell wrapped at one width and the screen rendered at another —
  // and on a phone the 80-column screen stuck 321px out of a 375px viewport, scrolling the whole
  // page sideways.
  var size = _sizeFor(host);
  term.resize(size.cols, size.rows);
  size = _sizeFor(host);            // the first resize changes the cell metrics we just measured
  term.resize(size.cols, size.rows);
  sock.on('connect', function () {
    if (opened) return;              // a reconnect must not silently open a SECOND shell
    opened = true;
    sock.emit('term_open', { remote_id: REMOTE_ID, cols: term.cols, rows: term.rows });
  });

  // A handshake that never completes has to say so. Every other message on this page is emitted
  // by the SERVER, so a page that never reached the server had nothing at all to show and left
  // "Connecting…" standing indefinitely. Only before the first successful connect: after one,
  // socket.io retries on its own and the disconnect handler owns the status line.
  sock.on('connect_error', function () {
    if (!opened) {
      _status('Could not reach the panel to open a terminal session. Reload the page to try again.', 'bad');
    }
  });

  // term_ready means the session was OPENED, which is not the same as connected. A pty and a
  // paramiko channel are both live by the time it fires, but the tailscale transport is a plain
  // `ssh -tt` that Popen returns from the moment the process starts — so for an unreachable host
  // this said "Connected to <host>." for the seventeen seconds ssh spent dialling, and only then
  // admitted the session had closed. Measured against a host that does not answer.
  //
  // The first byte back is the honest signal, whichever transport it came from, so the label only
  // claims a connection once something has actually arrived. On a reachable host the shell's
  // prompt lands in milliseconds and this is indistinguishable from before.
  sock.on('term_ready', function (d) {
    hostLabel = (d && d.host) || 'the host';
    sawOutput = false;
    _status('Opening a session on ' + hostLabel + '…');
    term.focus();
  });

  sock.on('term_output', function (d) {
    if (!(d && d.data)) return;
    if (!sawOutput) { sawOutput = true; _status('Connected to ' + hostLabel + '.', 'ok'); }
    term.write(d.data);
  });

  sock.on('term_error', function (d) {
    var msg = (d && d.message) || 'The terminal could not be opened.';
    _status(msg, 'bad');
    term.write('\r\n\x1b[31m' + msg + '\x1b[0m\r\n');
  });

  // `opened` is set once and never cleared. It used to be reset in both handlers below, which
  // made the guard on connect dead: socket.io reconnects on its own after a blip, the connect
  // handler fired again, and the page silently opened a SECOND shell — a fresh session with none
  // of the scrollback, while the status line was telling the operator to reload to get one. The
  // message and the behaviour now agree: one page, one session, and a reload to start another.
  sock.on('term_exit', function (d) {
    var why = (d && d.reason) || 'the session ended';
    _status('Session closed — ' + why + '. Reload the page to start another.', 'warn');
    term.write('\r\n\x1b[33m[' + why + ']\x1b[0m\r\n');
  });

  sock.on('disconnect', function () {
    _status('Disconnected. Reload the page to start a new session.', 'warn');
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
      sock.emit('term_resize', { cols: term.cols, rows: term.rows });
    }, 200);
  });

  // Leaving the page takes the shell with it. The server also closes on disconnect; this just
  // makes the common case immediate rather than waiting for the socket to time out.
  window.addEventListener('beforeunload', function () {
    try { sock.emit('term_close', {}); } catch (e) { /* the socket may already be gone */ }
  });
}

document.addEventListener('DOMContentLoaded', initTerminal);
