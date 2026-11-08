// The server page's console command history (server_detail.html), split out of server_detail.js to
// keep that file under the complexity gate's length limit. Loaded BEFORE server_detail.js and after
// the page's inline values (serverId, _CMPA_HIST_SCOPE). Its submit listener reads two names that
// server_detail.js defines (_cmpaLogKind, _cmpaSetView) only when a command is sent, by which time
// that file has run; server_detail.js's cmpaQuickCommand in turn ends browsing through _cmpaHistEnd
// here. Classic scripts share one global scope, so both see the same variables.

// ── Command history: Up/Down in the command box recall what was sent ─────────────────────────────
// Per account and server, the last 50, in localStorage when the browser allows it and in this page
// otherwise. The key names the signed-in account and the server's own row (_CMPA_HIST_SCOPE,
// server_detail.html), not just the server id: another account signed in on this browser must not
// get these commands on Up (they carry rcon and server passwords), and a server deleted and
// re-created takes its old id back (SQLite reuses a deleted row's id) but not its history. panel.js
// drops every sd.cmdHistory.* key on a page drawn signed out (Sign Out, an expired or revoked session).
// Recorded by a listener on the form's own submit, which runs before the delegated sendCommand, so
// the send itself is untouched: same Enter, same echo, same request. Down past the newest brings
// back what was being typed before Up was first pressed.
var _CMPA_HIST_MAX = 50;
var _cmpaHistMem = [];      // the in-page copy, the only one when storage is refused
var _cmpaBrowse = null;     // the list being stepped through, taken when Up is first pressed
var _cmpaHistIdx = -1;      // where in it the box is; -1 = not browsing
var _cmpaDraft = '';        // what was in the box before browsing began

// Ends Up/Down browsing: typing does it (the input listener below), and so does server_detail.js's
// cmpaQuickCommand when a chip fills the box from script, which fires no `input` event.
function _cmpaHistEnd() { _cmpaBrowse = null; _cmpaHistIdx = -1; }

// null without a scope: then the in-page copy only, never a key every account would share.
function _cmpaHistStoreKey() {
  if (typeof _CMPA_HIST_SCOPE !== 'string' || !_CMPA_HIST_SCOPE) return null;
  return 'sd.cmdHistory.' + _CMPA_HIST_SCOPE;   // i18n-ignore: a storage key
}
// The key this history had before it named the account: whoever's it was, it is nobody's now.
try { localStorage.removeItem('sd.cmdHistory.' + serverId); } catch (e) { /* private mode */ }   // i18n-ignore: a storage key

function _cmpaHistLoad() {
  var key = _cmpaHistStoreKey();
  if (!key) return _cmpaHistMem.slice();
  try {
    var raw = localStorage.getItem(key);
    var list = raw ? JSON.parse(raw) : [];
    if (Array.isArray(list)) {
      return list.filter(function (s) { return typeof s === 'string' && s; }).slice(-_CMPA_HIST_MAX);
    }
  } catch (e) { /* private mode, or an entry that is not ours: the in-page copy */ }
  return _cmpaHistMem.slice();
}

function _cmpaHistPush(cmd) {
  var list = _cmpaHistLoad();
  if (list[list.length - 1] !== cmd) list.push(cmd);
  _cmpaHistMem = list.slice(-_CMPA_HIST_MAX);
  var key = _cmpaHistStoreKey();
  if (key) { try { localStorage.setItem(key, JSON.stringify(_cmpaHistMem)); } catch (e) { /* private mode */ } }
  _cmpaBrowse = null; _cmpaHistIdx = -1; _cmpaDraft = '';
}

// The box's next value for an Up (dir -1) or Down (+1), or null to leave the key alone.
function _cmpaHistStep(dir, current) {
  if (_cmpaHistIdx === -1) {
    if (dir > 0) return null;                        // Down while not browsing: nothing to do
    _cmpaBrowse = _cmpaHistLoad();
    if (!_cmpaBrowse.length) return null;
    _cmpaDraft = current;
    _cmpaHistIdx = _cmpaBrowse.length;
  }
  _cmpaHistIdx = Math.max(0, _cmpaHistIdx + dir);
  if (_cmpaHistIdx < _cmpaBrowse.length) return _cmpaBrowse[_cmpaHistIdx];
  _cmpaHistIdx = -1;                                 // past the newest: back to the draft
  return _cmpaDraft;
}

// Whether a keydown is not ours: an IME composing text uses the arrows to pick a candidate, and a
// modified arrow (Shift to select, and the rest) keeps what the browser does with it.
function _cmpaHistLeaves(e) {
  if (e.isComposing || e.keyCode === 229) return true;
  return !!(e.altKey || e.ctrlKey || e.metaKey || e.shiftKey);
}

function _cmpaHistKey(e) {
  if (_cmpaHistLeaves(e) || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return;
  var v = _cmpaHistStep(e.key === 'ArrowUp' ? -1 : 1, e.target.value);
  if (v === null) return;
  e.preventDefault();
  e.target.value = v;
  try { e.target.setSelectionRange(v.length, v.length); } catch (err) { /* not a text box */ }
}

(function () {
  var form = document.getElementById('command-form');
  var input = document.getElementById('command-input');
  if (!form || !input) return;
  input.addEventListener('keydown', _cmpaHistKey);
  // Typing ends browsing: the edited line is the new draft for the next Up.
  input.addEventListener('input', _cmpaHistEnd);
  form.addEventListener('submit', function () {
    var cmd = input.value.trim();
    if (!cmd) return;
    _cmpaHistPush(cmd);
    // A command's echo and reply land in the live console: show it if a log was in its place.
    if (_cmpaLogKind !== 'console') _cmpaSetView('console');
  });
})();
