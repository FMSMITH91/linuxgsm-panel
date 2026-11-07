"""Part 149 of the unit suite: console command history, quick commands, and the script and game logs.

Asked for on 2026-11-06, for the server page:

* Up/Down in the console's command box recall what was sent (per server, the last 50, kept in
  localStorage when the browser allows it), and Down past the newest gives back the draft; an IME
  composing text keeps its arrows, and the send itself (sendCommand) is not touched;
* a few one-tap commands per console dialect, only for people who may send commands; one that takes
  an argument fills the box instead of sending;
* LinuxGSM's script log and the game's own newest log, read-only, through the file browser's
  permission and its refusal for an account that can become root, from paths built off the row.
  A read that failed is "unreadable", never an empty log.
"""
import os
import re as _re_cmpa_
import shutil as _shutil_cmpa_
import subprocess as _sp_cmpa_  # nosec B404 - bash runs the route's own read on a scratch tree
import tempfile as _tempfile_cmpa_
from types import SimpleNamespace as _NS_cmpa_

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_VIEWER, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch,
                         _p9_patch_sm, _p9_restore_all)
from unit.part47 import _cut47, _node47
from panel.ops.ssh_manager import _core as _smc_cmpa_
from panel.routes import _shared as _sh_cmpa_, server_detail as _sd_cmpa_

_TRIP_CMPA_START = len(_P9_TRIPPED)


def _read_cmpa_(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Quick commands: per dialect, and only the ones a game's console has
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _quick_cmpa_(game_type):
    return _sd_cmpa_._cmpa_quick_commands(_NS_cmpa_(game_type=game_type))


check("quick commands: a Source server sends status, and say/changelevel fill the box",
      _quick_cmpa_("csgo") == [("status", False), ("say", True), ("changelevel", True)],
      repr(_quick_cmpa_("csgo")))
check("quick commands: Minecraft lists players and saves; Bedrock, which has no save-all, does not",
      _quick_cmpa_("mc") == [("list", False), ("say", True), ("save-all", False)]
      and _quick_cmpa_("mcb") == [("list", False), ("say", True)], repr((_quick_cmpa_("mc"), _quick_cmpa_("mcb"))))
check("quick commands: a game whose console dialect the panel does not know gets none",
      _quick_cmpa_("vh") == [] and _quick_cmpa_("") == [] and _quick_cmpa_(None) == [])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The read: the route's own shell, run by bash on a scratch home
# ════════════════════════════════════════════════════════════════════════════════════════════════
_GS_CMPA_ = _NS_cmpa_(short_name="u149", lgsm_name="vhserver", game_type="vh")
_HOME_CMPA_ = _tempfile_cmpa_.mkdtemp(prefix="lgsm-unit-cmpa-")


def _bash_cmpa_(kind):
    """(out, rc) of the route's read for `kind`, with /home/u149 pointed at the scratch home."""
    cmd = _sd_cmpa_._cmpa_log_cmd(_GS_CMPA_, kind).replace("/home/u149", _HOME_CMPA_)
    r = _sp_cmpa_.run(["bash", "-c", cmd], capture_output=True, text=True,  # nosec B603 B607 - fixed argv
                      timeout=30, check=False)
    return r.stdout, r.returncode


def _write_cmpa_(rel, text, mtime=None):
    path = os.path.join(_HOME_CMPA_, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


try:
    check("log read: the paths come from the row: the script log by its LinuxGSM name, the game log as "
          "log/server",
          "/home/u149/log/script/vhserver-script.log" in _sd_cmpa_._cmpa_log_cmd(_GS_CMPA_, "script")
          and "D=/home/u149/log/server;" in _sd_cmpa_._cmpa_log_cmd(_GS_CMPA_, "game"))
    _absent_cmpa_ = (_sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("script")),
                     _sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("game")))
    check("log read: a log that is not there is \"missing\", said by a token of its own",
          [a["state"] for a in _absent_cmpa_] == ["missing", "missing"], repr(_absent_cmpa_))
    _write_cmpa_("log/script/vhserver-script.log", "")
    _empty_cmpa_ = _sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("script"))
    check("log read: an empty log that was read is \"ok\" with no lines (not \"unreadable\")",
          _empty_cmpa_ == {"state": "ok", "file": "vhserver-script.log", "lines": []}, repr(_empty_cmpa_))
    _write_cmpa_("log/script/vhserver-script.log",
                 "".join("Nov 06 10:00:%02d.000: vhserver: Monitor: line %d\n" % (i % 60, i)
                         for i in range(500)) + "last line ends in a space \n")
    _script_cmpa_ = _sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("script"))
    check("log read: the script log's last 300 lines, its last line whole (trailing space kept)",
          _script_cmpa_["state"] == "ok" and len(_script_cmpa_["lines"]) == 300
          and _script_cmpa_["lines"][-1] == "last line ends in a space "
          and _script_cmpa_["lines"][0].endswith("Monitor: line 201"),
          repr((_script_cmpa_["state"], len(_script_cmpa_["lines"]), _script_cmpa_["lines"][:1],
                _script_cmpa_["lines"][-1:])))
    _write_cmpa_("log/script/vhserver-script.log", ("x" * 4000 + "\n") * 200)
    _big_cmpa_ = _sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("script"))
    check("log read: bounded in bytes too, and the line the cap cut into is dropped",
          _big_cmpa_["state"] == "ok" and 0 < len(_big_cmpa_["lines"]) < 200
          and all(ln == "x" * 4000 for ln in _big_cmpa_["lines"]),
          repr((_big_cmpa_["state"], len(_big_cmpa_["lines"]), {len(x) for x in _big_cmpa_["lines"]})))

    # The game's directory: the newest plain file, not an archive and not a link out of it.
    _real_cmpa_ = os.path.join(_HOME_CMPA_, "serverfiles", "logs")
    os.makedirs(_real_cmpa_)
    os.makedirs(os.path.join(_HOME_CMPA_, "log"), exist_ok=True)
    os.symlink(_real_cmpa_, os.path.join(_HOME_CMPA_, "log", "server"))
    _write_cmpa_("serverfiles/logs/old.log", "old\n", mtime=1_700_000_000)
    _write_cmpa_("serverfiles/logs/latest.log", "\x1b[32mjoined\x1b[0m\nsaid hi\n", mtime=1_700_000_100)
    _write_cmpa_("serverfiles/logs/2026-11-05-1.log.gz", "\x1f\x8b binary", mtime=1_700_000_200)
    _secret_cmpa_ = _write_cmpa_("secret.txt", "private\n", mtime=1_700_000_300)
    os.symlink(_secret_cmpa_, os.path.join(_real_cmpa_, "zz-link.log"))
    os.utime(os.path.join(_real_cmpa_, "zz-link.log"), (1_700_000_400, 1_700_000_400), follow_symlinks=False)
    _game_cmpa_ = _sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("game"))
    check("log read: the game log is the newest plain file under log/server (LinuxGSM's link to the "
          "game's own log directory), with its colour codes removed",
          _game_cmpa_ == {"state": "ok", "file": "latest.log", "lines": ["joined", "said hi"]}, repr(_game_cmpa_))
    check("log read: neither a rotated archive nor a link inside the directory is chosen, however new",
          "private" not in repr(_game_cmpa_) and ".gz" not in _game_cmpa_.get("file", ""), repr(_game_cmpa_))
    for _f_cmpa_ in ("old.log", "latest.log", "2026-11-05-1.log.gz", "zz-link.log"):
        os.remove(os.path.join(_real_cmpa_, _f_cmpa_))
    _none_cmpa_ = _sd_cmpa_._cmpa_parse_log(*_bash_cmpa_("game"))
    check("log read: a game log directory with no log in it is \"missing\"",
          _none_cmpa_["state"] == "missing", repr(_none_cmpa_))
finally:
    _shutil_cmpa_.rmtree(_HOME_CMPA_, ignore_errors=True)

# ── the reply's parse: a read that did not run is never a log ───────────────────────────────────
_P_CMPA_ = _sd_cmpa_._cmpa_parse_log
check("log parse: an empty reply is \"unreadable\" whatever its rc (a failed SSH read is \"\")",
      _P_CMPA_("", 0)["state"] == "unreadable" and _P_CMPA_("", -1)["state"] == "unreadable"
      and _P_CMPA_(None, 0)["state"] == "unreadable")
check("log parse: a reply cut short (no closing frame) or with a non-zero rc is \"unreadable\"",
      _P_CMPA_("Nx.log\nBsome lines", 0)["state"] == "unreadable"
      and _P_CMPA_("Nx.log\nBline\nE", 1)["state"] == "unreadable"
      and _P_CMPA_("CMPANOFILE", -1)["state"] == "unreadable")
check("log parse: the framed reply is the file's name and its lines (control)",
      _P_CMPA_("Nx.log\nBa\nb\nE", 0) == {"state": "ok", "file": "x.log", "lines": ["a", "b"]})

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The route: who may read, what it reads, and what a failure says
# ════════════════════════════════════════════════════════════════════════════════════════════════
_reads_cmpa_ = []
_R_CMPA_ = {}


def _answer_cmpa_(reply):
    def _read(server, user, sh, timeout=30, selfname=None):
        _reads_cmpa_.append((user, sh, selfname))
        if isinstance(reply, Exception):
            raise reply
        return reply
    _p9_patch_sm("read_as_game_user", _read)


def _get_cmpa_(uid, kind):
    r = _p9_client(uid).get("/api/server/%d/log/%s" % (P9_GS, kind))
    return r.status_code, r.get_json(silent=True) or {}


def _clear_verdicts_cmpa_():
    with _sh_cmpa_._ACCOUNT_VERDICTS_LOCK:
        _sh_cmpa_._ACCOUNT_VERDICTS.clear()


try:
    _p9_arm(who="part149")
    _p9_patch(_sh_cmpa_, "privileged_accounts", lambda remote, users: {})
    _clear_verdicts_cmpa_()
    _answer_cmpa_(("Ncsgoserver-script.log\nBStarting\nStarted\nE", "", 0))
    _R_CMPA_["script"] = _get_cmpa_(P9_ADMIN, "script")
    _R_CMPA_["script_reads"] = list(_reads_cmpa_)
    _reads_cmpa_.clear()
    _R_CMPA_["viewer"] = _get_cmpa_(P9_VIEWER, "script")
    _R_CMPA_["viewer_reads"] = list(_reads_cmpa_)
    _R_CMPA_["other"] = _p9_client(P9_ADMIN).get("/api/server/%d/log/..%%2Fetc" % P9_GS).status_code
    _answer_cmpa_(("", "Command timed out", -1))
    _R_CMPA_["timeout"] = _get_cmpa_(P9_ADMIN, "game")
    _answer_cmpa_(ConnectionError("host down"))
    _R_CMPA_["raised"] = _get_cmpa_(P9_ADMIN, "game")
    _reads_cmpa_.clear()
    _p9_patch(_sh_cmpa_, "privileged_accounts", lambda remote, users: {u: "sudo" for u in users})
    _clear_verdicts_cmpa_()
    _R_CMPA_["root"] = _get_cmpa_(P9_ADMIN, "script")
    _R_CMPA_["root_reads"] = list(_reads_cmpa_)
finally:
    _p9_restore_all()
    _clear_verdicts_cmpa_()

_st_cmpa_, _body_cmpa_ = _R_CMPA_.get("script", (None, {}))
check("log route: the script log reads as the server's account, its path built from the row",
      _st_cmpa_ == 200 and _body_cmpa_ == {"state": "ok", "file": "csgoserver-script.log",
                                            "lines": ["Starting", "Started"], "kind": "script"}
      and len(_R_CMPA_.get("script_reads", [])) == 1
      and _R_CMPA_["script_reads"][0][0] == "csgoserver" and _R_CMPA_["script_reads"][0][2] == "csgoserver"
      and "/home/csgoserver/log/script/csgoserver-script.log" in _R_CMPA_["script_reads"][0][1],
      repr(_R_CMPA_.get("script")) + repr(_R_CMPA_.get("script_reads")))
check("log route: VIEW_CONSOLE alone is refused (403) and nothing is read: the file browser's "
      "permission, MANAGE_SERVERS, not the console's",
      _R_CMPA_.get("viewer", (None,))[0] == 403 and _R_CMPA_.get("viewer_reads") == [],
      repr((_R_CMPA_.get("viewer"), _R_CMPA_.get("viewer_reads"))))
check("log route: only the two logs it knows; any other name is not a route",
      _R_CMPA_.get("other") == 404, repr(_R_CMPA_.get("other")))
check("log route: a read that timed out or raised answers \"unreadable\", never an empty log",
      _R_CMPA_.get("timeout", (0, {}))[1].get("state") == "unreadable"
      and _R_CMPA_.get("raised", (0, {}))[1].get("state") == "unreadable"
      and _R_CMPA_["timeout"][0] == 200 and _R_CMPA_["raised"][0] == 200,
      repr((_R_CMPA_.get("timeout"), _R_CMPA_.get("raised"))))
check("log route: an account that can become root is refused (409) before anything is read, as the "
      "file browser refuses it",
      _R_CMPA_.get("root", (None,))[0] == 409 and _R_CMPA_.get("root_reads") == []
      and _R_CMPA_["root"][1].get("error"), repr((_R_CMPA_.get("root"), _R_CMPA_.get("root_reads"))))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The page: the controls are there for the people they are for
# ════════════════════════════════════════════════════════════════════════════════════════════════
_pages_cmpa_ = {}
try:
    _p9_arm(who="part149")
    _p9_patch(_sd_cmpa_, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd_cmpa_, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc_cmpa_, "run_command", lambda *a, **k: ("", "", 1))
    for _who_cmpa_, _uid_cmpa_ in (("admin", P9_ADMIN), ("viewer", P9_VIEWER)):
        _r_cmpa_ = _p9_client(_uid_cmpa_).get("/server/%d" % P9_GS)
        _pages_cmpa_[_who_cmpa_] = (_r_cmpa_.status_code, _r_cmpa_.get_data(as_text=True))
finally:
    _p9_restore_all()
_adm_cmpa_ = _pages_cmpa_.get("admin", (0, ""))[1]
_vw_cmpa_ = _pages_cmpa_.get("viewer", (0, ""))[1]
_chips_cmpa_ = _re_cmpa_.findall(r'data-action="cmpaQuickCommand" data-args=\'\["@self"\]\' '
                                 r'data-cmd="([^"]+)"\s+data-fill="([01])"', _adm_cmpa_)
check("server page: the command box has its game's quick commands, the ones taking an argument "
      "marked to fill the box",
      _pages_cmpa_.get("admin", (0,))[0] == 200
      and _chips_cmpa_ == [("status", "0"), ("say", "1"), ("changelevel", "1")], repr(_chips_cmpa_))
check("server page: the log menu offers the console, the script log and the game log",
      'id="cmpa-log-select"' in _adm_cmpa_ and '<option value="script">' in _adm_cmpa_
      and '<option value="game">' in _adm_cmpa_ and 'id="cmpa-log-view" hidden' in _adm_cmpa_)
check("server page: a viewer who may not send commands or manage files gets neither (but keeps the console)",
      _pages_cmpa_.get("viewer", (0,))[0] == 200 and 'id="console-output"' in _vw_cmpa_
      and "cmpaQuickCommand" not in _vw_cmpa_ and "cmpa-log-select" not in _vw_cmpa_,
      repr(_pages_cmpa_.get("viewer", (0, ""))[0]))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The page's script, run in node
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SD_CMPA_ = _read_cmpa_("static", "js", "server_detail.js")
_VARS_CMPA_ = "".join(m.group(0) + "\n" for m in _re_cmpa_.finditer(r"^var _(?:cmpa|CMPA)\w+ = [^\n]*;", _SD_CMPA_,
                                                                       _re_cmpa_.M))
_HEADS_CMPA_ = ("function _cmpaHistStoreKey(", "function _cmpaHistLoad(", "function _cmpaHistPush(",
                "function _cmpaHistStep(", "function _cmpaHistKey(", "function cmpaQuickCommand(",
                "function _cmpaLogShown(")
_FORM_IIFE_CMPA_ = "(function () {\n  var form = document.getElementById('command-form');"
_PRELUDE_CMPA_ = (
    "global.window = global; global.serverId = 7; global.t = s => s;\n"
    "let store = {}, storeBroken = false;\n"
    "global.localStorage = {getItem(k){ if (storeBroken) throw new Error('denied'); return k in store ? store[k] : null; },\n"
    "  setItem(k, v){ if (storeBroken) throw new Error('denied'); store[k] = String(v); }};\n"
    "class El { constructor(){ this.value = ''; this.h = {}; this.focused = false; this.attrs = {}; }\n"
    "  addEventListener(t, f){ (this.h[t] = this.h[t] || []).push(f); }\n"
    "  dispatchEvent(e){ (this.h[e.type] || []).forEach(f => f(e)); return true; }\n"
    "  setSelectionRange(){} focus(){ this.focused = true; global.document.activeElement = this; }\n"
    "  blur(){ this.focused = false; global.document.activeElement = null; }\n"
    "  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; } }\n"
    "const form = new El(), input = new El(); let sent = [];\n"
    "global.document = {activeElement: null, getElementById: id => ({'command-form': form, 'command-input': input})[id] || null};\n"
    "global.Event = class { constructor(type){ this.type = type; } };\n"
    "global._cmpaSetView = () => {};\n"
    # sendCommand as the dispatcher runs it: after the form's own listeners, reads the box, clears it
    "form.addEventListener('submit', () => { const c = input.value.trim(); if (c) { sent.push(c); input.value = ''; input.focus(); } });\n"
    "const key = (k, extra) => { const e = Object.assign({key: k, target: input, prevented: false,\n"
    "  preventDefault(){ this.prevented = true; }}, extra || {}); input.dispatchEvent(Object.assign(e, {type: 'keydown'})); return e; };\n"
    "const type = v => { input.value = v; input.dispatchEvent({type: 'input'}); };\n"
    "const submit = v => { type(v); form.dispatchEvent({type: 'submit'}); };\n")


def _node_cmpa_(name, body):
    """The cut functions + the form's listeners + `body` in node: its JSON, or None (skipped)."""
    cuts = "".join((_cut47(_SD_CMPA_, h) if h in _SD_CMPA_ else "/* MISSING %s */" % h) + "\n"
                   for h in _HEADS_CMPA_)
    iife = (_cut47(_SD_CMPA_, _FORM_IIFE_CMPA_) + ")();\n") if _FORM_IIFE_CMPA_ in _SD_CMPA_ else ""
    # The form listener's IIFE runs before the listener standing in for sendCommand: the page's
    # order, where the form's own listener fires before the delegated one on the document.
    prelude = _PRELUDE_CMPA_.replace("form.addEventListener('submit', () =>", iife + "form.addEventListener('submit', () =>", 1)
    out = _node47(prelude.replace("global._cmpaSetView", _VARS_CMPA_ + cuts + "global._cmpaSetView", 1)
                  + body + "\n")
    if out is None:
        skip(name, "node is not installed here")
    return out


_hist_cmpa_ = _node_cmpa_("command history", (
    "submit('status'); submit('say hello'); submit('say hello'); submit('list');\n"
    "type('half typed');\n"
    "const seen = [];\n"
    "for (const k of ['ArrowUp', 'ArrowUp', 'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowDown', 'ArrowDown'])\n"
    "  { const e = key(k); seen.push([input.value, e.prevented]); }\n"
    "const stored = JSON.parse(store['sd.cmdHistory.7'] || '[]');\n"
    "for (let i = 0; i < 60; i++) submit('cmd' + i);\n"
    "const capped = JSON.parse(store['sd.cmdHistory.7'] || '[]');\n"
    "type(''); key('ArrowUp'); const newest = input.value; key('ArrowDown');\n"
    "type('edit'); key('ArrowUp'); const ime = key('ArrowUp', {isComposing: true}); const imeVal = input.value;\n"
    "const shifted = key('ArrowDown', {shiftKey: true});\n"
    "type('');\n"
    "console.log(JSON.stringify({seen, stored, sent: sent.slice(0, 4), capLen: capped.length, first: capped[0],\n"
    "  last: capped[capped.length - 1], newest, after: input.value, imePrevented: ime.prevented, imeVal,\n"
    "  shiftPrevented: shifted.prevented}));\n"))
if _hist_cmpa_ is not None:
    check("command history: Up walks back through what was sent, stopping at the oldest",
          [v for v, _p in _hist_cmpa_.get("seen", [])[:4]] == ["list", "say hello", "status", "status"]
          and all(p for _v, p in _hist_cmpa_.get("seen", [])[:4]), repr(_hist_cmpa_))
    check("command history: Down walks forward, and past the newest gives back the draft being typed",
          [v for v, _p in _hist_cmpa_.get("seen", [])[4:7]] == ["say hello", "list", "half typed"]
          and _hist_cmpa_["seen"][7] == ["half typed", False], repr(_hist_cmpa_.get("seen")))
    check("command history: a command sent twice in a row is kept once; the sends themselves are unchanged",
          _hist_cmpa_.get("stored") == ["status", "say hello", "list"]
          and _hist_cmpa_.get("sent") == ["status", "say hello", "say hello", "list"], repr(_hist_cmpa_))
    check("command history: the last 50, the newest first back",
          _hist_cmpa_.get("capLen") == 50 and _hist_cmpa_.get("first") == "cmd10"
          and _hist_cmpa_.get("last") == "cmd59" and _hist_cmpa_.get("newest") == "cmd59", repr(_hist_cmpa_))
    check("command history: an IME composing text keeps its arrows, and so does Shift+Down",
          _hist_cmpa_.get("imePrevented") is False and _hist_cmpa_.get("imeVal") == "cmd59"
          and _hist_cmpa_.get("shiftPrevented") is False, repr(_hist_cmpa_))

_priv_cmpa_ = _node_cmpa_("command history without storage", (
    "storeBroken = true; submit('status'); submit('list'); type('x');\n"
    "key('ArrowUp'); const a = input.value; key('ArrowUp'); const b = input.value; key('ArrowDown'); key('ArrowDown');\n"
    "console.log(JSON.stringify({a, b, back: input.value, sent}));\n"))
if _priv_cmpa_ is not None:
    check("command history: a browser that refuses storage still recalls this page's commands",
          _priv_cmpa_ == {"a": "list", "b": "status", "back": "x", "sent": ["status", "list"]}, repr(_priv_cmpa_))

_chip_cmpa_ = _node_cmpa_("quick commands", (
    "const chip = (cmd, fill) => { const b = new El(); b.attrs = {'data-cmd': cmd, 'data-fill': fill}; return b; };\n"
    "type('half typed'); input.blur(); cmpaQuickCommand(chip('status', '0'));\n"
    "const afterSend = {value: input.value, focused: input.focused, sent: sent.slice()};\n"
    "type('half typed'); cmpaQuickCommand(chip('say', '1'));\n"
    "console.log(JSON.stringify({afterSend, fill: input.value, fillFocused: input.focused, sentAfterFill: sent.length,\n"
    "  hist: JSON.parse(store['sd.cmdHistory.7'] || '[]')}));\n"))
if _chip_cmpa_ is not None:
    check("quick commands: a chip sends through the box (same send, in the history), then puts back the "
          "half-typed draft and leaves the keyboard closed",
          _chip_cmpa_.get("afterSend") == {"value": "half typed", "focused": False, "sent": ["status"]}
          and _chip_cmpa_.get("hist") == ["status"], repr(_chip_cmpa_))
    check("quick commands: a chip that takes an argument fills the box and sends nothing",
          _chip_cmpa_.get("fill") == "say " and _chip_cmpa_.get("fillFocused") is True
          and _chip_cmpa_.get("sentAfterFill") == 1, repr(_chip_cmpa_))

_shown_cmpa_ = _node_cmpa_("log notes", (
    "console.log(JSON.stringify({\n"
    "  bad: _cmpaLogShown({state: 'unreadable'}, 'script'), none: _cmpaLogShown(null, 'game'),\n"
    "  empty: _cmpaLogShown({state: 'ok', file: 'a.log', lines: []}, 'script'),\n"
    "  ok: _cmpaLogShown({state: 'ok', file: 'a.log', lines: ['x', 'y']}, 'script'),\n"
    "  gone: _cmpaLogShown({state: 'missing'}, 'game'), goneScript: _cmpaLogShown({state: 'missing'}, 'script'),\n"
    "  refused: _cmpaLogShown({error: 'no'}, 'script')}));\n"))
if _shown_cmpa_ is not None:
    _unread_cmpa_ = "Couldn't read this log. The host may not have answered; try Refresh."
    check("log view: a read that failed says it could not be read, never that the log is empty",
          _shown_cmpa_.get("bad", {}).get("note") == _unread_cmpa_
          and _shown_cmpa_.get("none", {}).get("note") == _unread_cmpa_, repr(_shown_cmpa_))
    check("log view: an empty log says so; a log with lines shows them under its file name",
          _shown_cmpa_.get("empty", {}).get("note") == "This log is empty."
          and _shown_cmpa_.get("ok") == {"file": "a.log", "text": "x\ny", "note": ""}, repr(_shown_cmpa_))
    check("log view: a missing log, and a refusal, are said in their own words",
          "No game log found" in _shown_cmpa_.get("gone", {}).get("note", "")
          and _shown_cmpa_.get("goneScript", {}).get("note") == "LinuxGSM has not written this log yet."
          and _shown_cmpa_.get("refused", {}).get("note") == "no", repr(_shown_cmpa_))

check("part149: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP_CMPA_START, repr(_P9_TRIPPED[_TRIP_CMPA_START:]))
