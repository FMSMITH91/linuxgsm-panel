"""Part 63 of the unit suite: the fourth 2026-10-11 review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* routes: a JSON boolean sent into a number field is a 400 (or ignored, as other non-numbers are),
  never 1 or 0 (`{"keep": true}` kept one archive, `{"interval": false}` stopped backups,
  `{"threshold": true}` blocked on one failed attempt, `{"delay": false}` rebooted with no wait);
  a failed update check does not clear the update already announced.
* tools, pages and scripts (bash and node on this part's own fixtures), and the i18n gate's blind
  spots, each shown to catch the shape it missed.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import ast as _ast63
import importlib.util as _ilu63
import json as _json63
import os
import re as _re63
import shutil as _shutil63
import subprocess as _sp63  # nosec B404 - runs this repository's own scripts on scratch fixtures
import sys as _sys63
import tempfile as _tf63
from types import SimpleNamespace as _NS63

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_CFG_PATH, _p9, _p9_client, _p9_patch,
                         _p9_restore_all)
from panel.db.models import db as _db63
from unit.part47 import _SETTLE47 as _SETTLE63, _cut47, _node47
import app as _app63
from panel.ops import backup as _bk63
from panel.ops import system_ops as _so63
from panel.routes import host_terminal as _ht63
from panel.routes import os_updates as _ou63
from panel.routes import remote_vps as _rv63
from panel.security import auth as _auth63
from panel.services import host_reboot as _hr63

_JS63 = os.path.join(_root, "static", "js")
_TPL63 = os.path.join(_root, "templates")
_CFG63_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _read63(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _node63(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _rec63(log, name, result):
    """A stub that records (name, args, kwargs) into `log` and answers `result`."""
    return lambda *a, **k: (log.append((name, a, k)) or result)


_A63 = _p9_client(P9_ADMIN)
try:
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 1. routes
    # ════════════════════════════════════════════════════════════════════════════════════════════

    # ── a JSON boolean is not a number ───────────────────────────────────────────────────────────
    _calls63 = []
    _p9_patch(_bk63, "set_game_schedule", _rec63(_calls63, "schedule", {"interval_days": 1, "keep": 1}))
    _sch63 = "/api/panel/backup/game/%d/schedule" % P9_GS
    _bad63 = [_A63.post(_sch63, json={"keep": True}).status_code,
              _A63.post(_sch63, json={"interval": False}).status_code]
    check("game backup schedule: a JSON boolean for keep or interval is a 400 and nothing is stored "
          "(true kept ONE archive, false read as interval 0, which turns the server's backups off)",
          _bad63 == [400, 400] and _calls63 == [], repr((_bad63, _calls63)))
    _A63.post(_sch63, json={"keep": 3, "interval": ""})
    check("game backup schedule: ...a number and an empty field still save (control)",
          [c[1][1:] for c in _calls63] == [(None, 3)], repr(_calls63))

    # The auto-block threshold is install-wide: true made it 1, a block on one failed attempt.
    _calls63.clear()
    _p9_patch(_app63, "update_config", _rec63(_calls63, "update_config", None))
    for _mod63 in ("remote_security", "host_local"):
        _m63 = __import__("panel.routes." + _mod63, fromlist=["x"])
        _p9_patch(_m63, "_set_autoblock_host", lambda *a, **k: None)
        _p9_patch(_m63, "_run_autoblock_now", lambda *a, **k: None)
    _sec63 = ("/api/remote/%d/security/autoblock" % P9_HOST, "/api/panel/security/autoblock")
    _codes63 = [_A63.post(u, json={"enabled": False, "threshold": True}).status_code for u in _sec63]
    check("auto-block: a JSON boolean threshold is ignored on both hosts, as \"many\" is (true set the "
          "install-wide threshold to 1)", _calls63 == [] and _codes63 == [200, 200],
          repr((_codes63, _calls63)))
    _A63.post(_sec63[1], json={"enabled": False, "threshold": 7})
    _store63 = {}
    if _calls63:
        _calls63[0][1][0](_store63)
    check("auto-block: ...a number is still stored (control)",
          len(_calls63) == 1 and _store63 == {"autoblock_threshold": 7}, repr((_calls63, _store63)))

    # sshd's port: true moved it to port 1.
    _calls63.clear()
    _p9_patch(_rv63, "change_ssh_port", _rec63(_calls63, "change_ssh_port", (False, "stub")))
    _ssh63 = "/api/remote/%d/ssh-port" % P9_HOST
    _bad63 = [_A63.post(_ssh63, json={"port": v}).status_code for v in (True, False, 22.5)]
    check("ssh port: a JSON boolean (or a fractional number) is a 400 and sshd is not moved (true "
          "moved it to port 1)", _bad63 == [400, 400, 400] and _calls63 == [], repr((_bad63, _calls63)))
    _A63.post(_ssh63, json={"port": "2222"})
    _A63.post(_ssh63, json={"port": 2223.0})
    check("ssh port: ...a number, or a number written as text, still moves it (control)",
          [c[1][1] for c in _calls63] == [2222, 2223], repr(_calls63))

    # The panel host's reboot delay: false was 0, a reboot with no wait.
    _calls63.clear()
    _p9_patch(_hr63, "request_reboot", _rec63(_calls63, "request_reboot", (200, {"success": True})))
    _p9_patch(_so63, "server_reboot", _rec63(_calls63, "server_reboot", (True, "ok")))
    _rb63 = "/api/server-management/reboot"
    _bad63 = [_A63.post(_rb63, json={"delay": v, "mode": "now"}).status_code for v in (False, True)]
    check("panel host reboot: a JSON boolean delay is a 400 and nothing reboots (false rebooted with "
          "no wait)", _bad63 == [400, 400] and _calls63 == [], repr((_bad63, _calls63)))
    _A63.post(_rb63, json={"delay": 30, "mode": "now"})
    check("panel host reboot: ...a number of seconds still reboots (control)",
          len(_calls63) == 1, repr(_calls63))

    # The terminal's socket payload: true named host 1, and a one-column terminal.
    _calls63.clear()
    _p9_patch(_ht63, "_may_use_terminal", lambda: True)
    _p9_patch(_ht63, "current_user", _NS63(is_superadmin=False))
    _p9_patch(_auth63, "can_access_remote", _rec63(_calls63, "can_access_remote", False))
    _tt63 = [_ht63._terminal_target({"remote_id": v})[2] for v in (True, 1.5)]
    check("terminal: a JSON boolean (or fractional) remote_id names no host (true asked for host 1)",
          _tt63 == ["No host was named."] * 2 and _calls63 == [], repr((_tt63, _calls63)))
    _tt63 = _ht63._terminal_target({"remote_id": P9_HOST})[2]
    check("terminal: ...a host id goes on to the access check (control)",
          _tt63 == "You don't have access to that host." and len(_calls63) == 1, repr((_tt63, _calls63)))
    _dims63 = [_ht63._term_dim({"cols": v}, "cols", 80) for v in (True, False, 100.5, 120, "132")]
    check("terminal: a JSON boolean or fractional size is the default size, not 1 or 0 columns "
          "(control: a number, or one written as text, is kept)",
          _dims63 == [80, 80, 80, 120, 132], repr(_dims63))

    # ── a failed update check does not clear the announced update ────────────────────────────────
    _written63 = []
    _p9_patch(_ou63, "_remember_announced_update", _written63.append)
    _p9_patch(_ou63, "_announce_panel_update", lambda *a: _written63.append(("SENT",) + a[2:]))
    _failed63 = ({"git": True, "fetched": False, "update_available": False},
                 {"git": True, "fetched": True, "update_available": False, "ci_state": "unknown",
                  "behind": 3},
                 {"git": True, "update_available": False, "update_running": True})
    _kept63 = [_ou63._update_tick(None, st, "X") for st in _failed63]
    check("panel update notice: a check that FAILED (no fetch, CI unreadable, an update running) keeps "
          "the announced commit (each cleared it, and the next good check announced the same commit "
          "again)", _kept63 == ["X"] * 3 and _written63 == [], repr((_kept63, _written63)))
    _cleared63 = [_ou63._update_tick(None, st, "X") for st in
                  ({"git": True, "fetched": True, "update_available": False, "behind": 0},
                   {"git": True, "fetched": True, "update_available": False, "docs_only": True,
                    "behind": 2})]
    check("panel update notice: ...a check that says nothing the panel runs is waiting clears it "
          "(control: up to date, or behind by docs only)",
          _cleared63 == ["", ""] and _written63 == ["", ""], repr((_cleared63, _written63)))
finally:
    _p9_restore_all()
    if _CFG63_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG63_SNAPSHOT)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. tools
# ════════════════════════════════════════════════════════════════════════════════════════════════

# ── smoke-local.sh hands the suite its arguments, and brings a rewritten url_map baseline back ──
# Run as written, in a scratch repository, with a stand-in runner and suite that record their argv.
_sb63 = os.path.realpath(_tf63.mkdtemp(prefix="lgsm-unit-p63-smoke-"))
try:
    os.makedirs(os.path.join(_sb63, "tools"))
    os.makedirs(os.path.join(_sb63, "tests"))
    _shutil63.copy(os.path.join(_root, "tools", "smoke-local.sh"), os.path.join(_sb63, "tools"))
    with open(os.path.join(_sb63, "tools", "nosudo_runner.py"), "w", encoding="utf-8") as _fh63:
        # The stand-in runner: records its argv, then runs the "suite" as the real one does (argv
        # shifted, --allow-egress taken out). The suite writes the baseline on --update, fails on
        # --fail.
        _fh63.write(
            "import json, sys\n"
            "argv = [a for a in sys.argv[1:] if a != '--allow-egress']\n"
            "open('../argv.json', 'w').write(json.dumps(sys.argv[1:]))\n"
            "if '--update' in argv:\n"
            "    open('tests/url_map_baseline.json', 'w').write('NEW\\n')\n"
            "sys.exit(3 if '--fail' in argv else 0)\n")
    with open(os.path.join(_sb63, "tests", "url_map_test.py"), "w", encoding="utf-8") as _fh63:
        _fh63.write("# stand-in\n")
    with open(os.path.join(_sb63, "tests", "url_map_baseline.json"), "w", encoding="utf-8") as _fh63:
        _fh63.write("OLD\n")
    _git63 = _shutil63.which("git")
    _bash63 = _shutil63.which("bash")
    if not (_git63 and _bash63):
        skip("smoke-local: arguments reach the suite", "git or bash is not installed here")
    else:
        _env63 = dict(os.environ, PYTHON=_sys63.executable, TMPDIR=_sb63)
        for _args63 in (["init", "-q"], ["add", "-A"]):
            _sp63.run([_git63, *_args63], cwd=_sb63, check=True, capture_output=True)  # nosec B603

        def _smoke63(*args):
            """Run the copied smoke-local.sh; (rc, argv the runner got, baseline text)."""
            r = _sp63.run([_bash63, "tools/smoke-local.sh", *args], cwd=_sb63, env=_env63,  # nosec B603
                          capture_output=True, text=True, timeout=60, check=False)
            # The runner wrote argv.json one level above the throwaway tree, i.e. into TMPDIR.
            with open(os.path.join(_sb63, "argv.json"), encoding="utf-8") as fh:
                got = _json63.load(fh)
            with open(os.path.join(_sb63, "tests", "url_map_baseline.json"), encoding="utf-8") as fh:
                return r.returncode, got, fh.read()

        _r63 = _smoke63("tests/url_map_test.py", "--update")
        check("smoke-local: arguments after the suite reach it, and a baseline --update rewrote is copied "
              "back into the repository (the documented regeneration command ran the comparison and "
              "wrote nothing)", _r63 == (0, ["tests/url_map_test.py", "--update"], "NEW\n"), repr(_r63))
        with open(os.path.join(_sb63, "tests", "url_map_baseline.json"), "w", encoding="utf-8") as _fh63:
            _fh63.write("OLD\n")
        _r63 = [_smoke63("tests/url_map_test.py", "--allow-egress"),
                _smoke63("tests/url_map_test.py", "--update", "--fail")]
        check("smoke-local: ...without --update, or when the suite failed, the repository's baseline is "
              "left alone (control)",
              _r63[0] == (0, ["tests/url_map_test.py", "--allow-egress"], "OLD\n")
              and _r63[1][0] != 0 and _r63[1][2] == "OLD\n", repr(_r63))
finally:
    _shutil63.rmtree(_sb63, ignore_errors=True)

# ── the harnesses that boot a panel in the real data dir leave no backup behind ─────────────────
_lh63 = _ast63.parse(_read63(_root, "tools", "lhci_serve.py"))
_lh63_src = _read63(_root, "tools", "lhci_serve.py")
_lh63_clean = next(n for n in _lh63.body if isinstance(n, _ast63.FunctionDef) and n.name == "_cleanup")
_lh63_order = [(_ast63.unparse(n)) for n in _lh63.body if isinstance(n, (_ast63.Assign, _ast63.Expr))]
_lh63_off = 'cfg["backup_enabled"] = False'.replace('"', "'")
check("lhci_serve: the throwaway panel's backups are off before it boots (its daily archive, with the "
      "published superadmin and the keys, was left in data/backups)",
      _lh63_off in _lh63_order and "save_config(cfg)" in _lh63_order
      and _lh63_order.index(_lh63_off) < _lh63_order.index("save_config(cfg)"), repr(_lh63_order[:12]))
check("lhci_serve: ...and its cleanup removes a backups directory this run created, only that",
      "_BACKUPS_PREEXISTED" in _ast63.unparse(_lh63_clean) and "rmtree(BACKUP_DIR" in _ast63.unparse(_lh63_clean)
      and "_BACKUPS_PREEXISTED = BACKUP_DIR.exists()" in _lh63_src, _ast63.unparse(_lh63_clean)[-300:])
_lh63_rs = [n for n in _ast63.walk(_lh63) if isinstance(n, _ast63.Call)
            and _ast63.unparse(n.func) == "RemoteServer"]
_lh63_port = [_ast63.unparse(k.value) for n in _lh63_rs for k in n.keywords if k.arg == "port"]
check("lhci_serve: the seeded host is on a port nothing answers, not root@127.0.0.1:22 with the "
      "developer's own SSH keys", _lh63_port == ["1"], repr(_lh63_port))
_pb63 = _ast63.parse(_read63(_root, "tools", "perf_bench.py"))
_pb63_fn = {n.name: _ast63.unparse(n) for n in _pb63.body if isinstance(n, _ast63.FunctionDef)}
check("perf_bench: every size's config has backups off, and cleanup removes a backups directory the "
      "run created", "cfg['backup_enabled'] = False" in _pb63_fn.get("mark_setup_complete", "")
      and "rmtree(BACKUP_DIR" in _pb63_fn.get("cleanup", "")
      and "_BACKUPS_PREEXISTED" in _pb63_fn.get("cleanup", ""), repr(sorted(_pb63_fn)))
_rc63 = _ast63.parse(_read63(_root, "tools", "route_coverage.py"))
_rc63_rep = _ast63.unparse(next(n for n in _rc63.body if isinstance(n, _ast63.FunctionDef)
                                and n.name == "_report"))
check("route_coverage: the app it builds to read the URL map starts no background workers (they ran "
      "outside nosudo_runner, free to reach a real sudo probe)",
      "os.environ[NO_WORKERS_ENV] = '1'" in _rc63_rep
      and _rc63_rep.index("os.environ[NO_WORKERS_ENV]") < _rc63_rep.index("app = create_app()"), _rc63_rep[:400])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. pages (node, against stubs)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SF63 = _read63(_JS63, "server_files.js")

# ── a file created after its field was cancelled shows up; a folder clicked meanwhile is kept ───
_name63 = "file browser: a create answered after Cancel or a folder click"
_out63 = _node63(_name63, (
    "var calls = [], _creating = null, _browseWant = '', curDir = '';\n"
    "function browse(p){ calls.push(['browse', p]); }\n"
    "function openFile(p){ calls.push(['open', p]); }\n"
    "function toast(){}\nfunction _tr(s){ return s; }\nvar window = {toast: toast};\n"
    + _cut47(_SF63, "function _created(") + "\n"
    "function box(){ return {remove: function(){ calls.push(['removed']); }}; }\n"
    "function run(state){ calls = []; _creating = state.open; _browseWant = state.want; curDir = state.cur;\n"
    "  _created(state.r, 'notes.txt'); return calls; }\n"
    "var r1 = {kind: 'file', dir: 'serverfiles', box: box()};\n"
    "var r2 = {kind: 'file', dir: 'serverfiles', box: box()};\n"
    "var r3 = {kind: 'folder', dir: 'serverfiles', box: box()};\n"
    "console.log(JSON.stringify([\n"
    "  run({open: null, want: 'serverfiles', cur: 'serverfiles', r: r1}),\n"
    "  run({open: r2, want: 'other', cur: 'serverfiles', r: r2}),\n"
    "  run({open: r3, want: 'serverfiles', cur: 'serverfiles', r: r3})]));\n"))
if _out63 is not None:
    check("file browser: a create that lands after its field was cancelled refreshes the folder still on "
          "screen (the toast said \"File created\" and the list never showed it)",
          isinstance(_out63, list) and _out63[0] == [["browse", "serverfiles"]], repr(_out63))
    check("file browser: ...one that lands while another folder is loading closes the field and leaves "
          "the user's folder alone (it took the newer browse turn and pulled them back)",
          isinstance(_out63, list) and _out63[1] == [["removed"]], repr(_out63))
    check("file browser: ...and an ordinary create still opens the new folder (control)",
          isinstance(_out63, list) and _out63[2] == [["removed"], ["browse", "serverfiles/notes.txt"]],
          repr(_out63))
check("file browser: browse() records the folder it was asked for before its listing arrives",
      "_browseWant = want;" in _cut47(_SF63, "function browse("), _cut47(_SF63, "function browse(")[:300])

# ── a same-folder refresh keeps an open create or rename field, and what was typed ──────────────
_name63 = "file browser: a refresh keeps the open fields"
_out63 = _node63(_name63, (
    "var _creating = null, _renaming = null, curDir = 'cfg';\n"
    "global.CSS = {escape: function(s){ return s; }};\n"
    "var focused = null; global.document = {get activeElement(){ return focused; }};\n"
    + _cut47(_SF63, "function _r14c_openEditors(") + "\n" + _cut47(_SF63, "function _r14c_restoreEditors(") + "\n"
    "function el(name){ return {name: name, isConnected: true, cls: [], kids: [],\n"
    "  classList: {add: function(c){ this.o.cls.push(c); }},\n"
    "  appendChild: function(k){ this.kids.push(k.name); }, focus: function(){ focused = this; }}; }\n"
    "var cbox = el('cbox'), cinput = el('cinput'), rbox = el('rbox'), rinput = el('rinput'), row = el('row');\n"
    "row.classList.o = row; rinput.closest = function(){ return rbox; };\n"
    "var list = {first: [], firstChild: null, insertBefore: function(k){ this.first.push(k.name); },\n"
    "  querySelector: function(q){ return q === '[data-path=\"cfg/a.cfg\"]' ? row : null; }};\n"
    "_creating = {dir: 'cfg', box: cbox, input: cinput}; _renaming = {path: 'cfg/a.cfg', input: rinput};\n"
    "focused = cinput;\n"
    "var same = _r14c_openEditors('cfg'), other = _r14c_openEditors('maps');\n"
    "_creating = null; _renaming = null; focused = null;\n"
    "_r14c_restoreEditors(same, list);\n"
    "console.log(JSON.stringify([other, list.first, row.kids, row.cls, !!_creating, !!_renaming,\n"
    "  _renaming && _renaming.row === row, focused === cinput]));\n"))
if _out63 is not None:
    check("file browser: a refresh of the same folder (an upload finishing) puts the open create and "
          "rename fields back, focus included (it dropped both, half-typed name and all, with no message)",
          _out63 == [None, ["cbox"], ["rbox"], ["fb-renaming"], True, True, True, True], repr(_out63))
_br63 = _cut47(_SF63, "function browse(")
check("file browser: ...browse() reads the open fields before it clears them and restores them after "
      "the rows are built",
      0 < _br63.find("_r14c_openEditors(want)") < _br63.find("_creating = null;")
      < _br63.find("_r14c_restoreEditors(keep, l)"), _br63[:200])

# ── Clear means the cleared panel lines do not come back ────────────────────────────────────────
_SD63 = _read63(_JS63, "server_detail.js")
_name63 = "console: Clear and the backlog"
_out63 = _node63(_name63, (
    "var consoleEl = {innerHTML: 'x'}, _consoleLines = [1], _consoleSig = 's', _consolePrimed = true;\n"
    "var _panelBacklogShown = false, _returnOwed = false, _lastPanelT = 500;\n"
    + _cut47(_SD63, "function clearConsole(") + "\n" + _cut47(_SD63, "function _panelLinesWiped(") + "\n"
    + _cut47(_SD63, "function _r13c_primeWipesPushes(") + "\n"
    "clearConsole();\nvar wipes = _r13c_primeWipesPushes();\n_panelLinesWiped();\n"
    "console.log(JSON.stringify([wipes, _lastPanelT, consoleEl.innerHTML]));\n"))
if _out63 is not None:
    check("console: after Clear on a page whose backlog was never shown, the re-prime neither resets the "
          "shown-up-to time nor puts back the pushes (the cleared update output came back on the next poll)",
          _out63 == [False, 500, ""], repr(_out63))

# ── the auto-block switch believes the answer, not the click ────────────────────────────────────
_RM63 = _read63(_JS63, "remote_manage.js")
_name63 = "security: the auto-block switch on a refusal"
_out63 = _node63(_name63, (
    _SETTLE63 + "var toasts = [], timers = 0;\n"
    "global.window = global; global.toast = function(m, k){ toasts.push([m, k]); };\n"
    "global.setTimeout = function(){ timers++; };\nfunction secBase(){ return ''; }\n"
    "function loadSecurityTopIps(){}\nvar answer;\n"
    "global.fetch = function(){ return Promise.resolve({json: function(){ return Promise.resolve(answer); }}); };\n"
    + _cut47(_RM63, "function toggleAutoblock(") + "\n"
    "(async function(){\n"
    "  var cb = {checked: true}; answer = {success: false, message: 'No local host record.'};\n"
    "  toggleAutoblock(cb); await settle(); var a = [cb.checked, toasts.slice(), timers];\n"
    "  toasts = []; timers = 0; var cb2 = {checked: true}; answer = {success: true};\n"
    "  toggleAutoblock(cb2); await settle(); var b = [cb2.checked, toasts.slice(), timers];\n"
    "  console.log(JSON.stringify([a, b]));\n})();\n"))
if _out63 is not None:
    check("security: a refused auto-block change says so and puts the switch back (it toasted \"Auto-block "
          "on\" in green and left the switch on)",
          isinstance(_out63, list) and _out63[0] == [False, [["No local host record.", "danger"]], 0], repr(_out63))
    check("security: ...an accepted one keeps the switch and schedules the repaint (control)",
          isinstance(_out63, list) and _out63[1][0] is True and _out63[1][1][0][1] == "success"
          and _out63[1][2] == 1, repr(_out63))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. translations the gate could not see
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Loaded from its file: the runner fails any part that leaves sys.path changed.
_i18n_spec63 = _ilu63.spec_from_file_location("i18n_scan_p63", os.path.join(_root, "tools", "i18n_scan.py"))
_i18n63 = _ilu63.module_from_spec(_i18n_spec63)
_i18n_spec63.loader.exec_module(_i18n63)
_ES63, _FR63 = _i18n63.load_catalog("es"), _i18n63.load_catalog("fr")

# ── each blind spot, shown to catch its shape on a fixture ──────────────────────────────────────
_td63 = os.path.realpath(_tf63.mkdtemp(prefix="lgsm-unit-p63-i18n-"))
try:
    with open(os.path.join(_td63, "t.html"), "w", encoding="utf-8") as _fh63:
        _fh63.write(
            '<button aria-label="Move {{ label }} left" title="{% if a %}Branch one{% else %}Branch two{% endif %}">x</button>\n'
            '<form data-confirm="Delete user “{{ name }}”?" data-confirm-title="Delete Widget"></form>\n'
            '<input placeholder="{{ \'\\u2022\\u2022 (leave blank to keep)\' if h else \'the token from the portal\' }}">\n'
            "<span>{{ host or 'this host' }}</span><b>{{ t('Move %s up')|format(n) }}</b>\n"
            "{% set LABELS = {'k': 'Panel Label'} %}<i>{{ x if y == 'some value' else z }}</i>\n"
            '<p data-no-i18n>A shell on this host, as <code>{{ u }}</code></p>\n'
            '<pre id="p">Pick a log above to see its recent lines.</pre><pre>sudo some-command now</pre>\n'
            '<span>{{ u }}@{{ h }} &middot; Known: {{ m }}</span>\n')
    _tpl63, _dyn63 = _i18n63.scan_template(os.path.join(_td63, "t.html"))
finally:
    _shutil63.rmtree(_td63, ignore_errors=True)
check("i18n scan: static words welded to a {{ }} in a translated attribute are reported as unreachable "
      "(they were skipped as \"per-request text\" and the gate passed)",
      {"Move", "left"} <= set(_dyn63) and _dyn63.get("Move") == {"@aria-label"}, repr(_dyn63))
check("i18n scan: ...each {% if %} branch of an attribute is a whole value to look up",
      {"Branch one", "Branch two"} <= set(_tpl63), repr(sorted(_tpl63)))
check("i18n scan: a form's confirm dialog is read: its title asked for, a name spliced into its body "
      "reported", "Delete Widget" in _tpl63 and "Delete user “" in _dyn63, repr((sorted(_tpl63), sorted(_dyn63))))
check("i18n scan: lower-case words in an expression ('this host', a placeholder after bullets written "
      "as \\u escapes) are asked for, a compared value is not",
      {"•• (leave blank to keep)", "the token from the portal", "this host"} <= set(_tpl63)
      and "some value" not in _tpl63, repr(sorted(_tpl63)))
check("i18n scan: a t() argument is asked for whatever its shape (\"Move %s up\"), and a {% set %} "
      "table's labels too", {"Move %s up", "Panel Label"} <= set(_tpl63), repr(sorted(_tpl63)))
check("i18n scan: prose under data-no-i18n, and a sentence in a <pre>, are reported as unreachable "
      "(control: a command in a <pre> is not)",
      _dyn63.get("A shell on this host, as") == {"guarded"}
      and _dyn63.get("Pick a log above to see its recent lines.") == {"pre"}
      and "sudo some-command now" not in _dyn63, repr(_dyn63))
_pd63 = []
_saved_print63 = _i18n63.__dict__.get("print")
_i18n63.print = lambda *a, **k: _pd63.append(" ".join(str(x) for x in a))
try:
    _i18n63._print_dynamic({"· Known:": {"t.html": {"text"}}}, {"· Known:": "· Conocido:"})
finally:
    if _saved_print63 is None:
        del _i18n63.print
check("i18n scan: a welded fragment is reported even when the catalog has it (\"· Auth:\" was waved "
      "through as \"inert\", and the header stayed English)", "· Known:" in _dyn63
      and _pd63 == ["  DYNAMIC  [t.html] '· Known:'"], repr((_dyn63, _pd63)))

_td63 = os.path.realpath(_tf63.mkdtemp(prefix="lgsm-unit-p63-i18njs-"))
try:
    os.makedirs(os.path.join(_td63, "js"))
    os.makedirs(os.path.join(_td63, "tpl"))
    with open(os.path.join(_td63, "js", "a.js"), "w", encoding="utf-8") as _fh63:
        _fh63.write(
            "el.innerHTML = '<span class=\"badge\">banned now</span><button>unblock</button>';\n"
            "x = '<a href=\"#\"' + _da('f') + '>Advanced: use a key instead</a>';\n"
            "y = '<button' + _da('g') + ' title=\"Show it\">view log</button>';\n"
            "z = '<span class=\"text-danger\">❌ Request went wrong</span><div>(empty list)</div>';\n"
            "w = 'Attach it to your <strong>free</strong> plan <i>every</i> time';\n"
            "v = '<a data-no-i18n><i class=\"bi\"></i> home</a><code>some code</code>';\n")
    _js63 = set(_i18n63.scan_js(os.path.join(_td63, "js")))
    with open(os.path.join(_td63, "tpl", "p.html"), "w", encoding="utf-8") as _fh63:
        _fh63.write('<div id="stale" data-no-i18n></div><input name="cred" data-no-i18n>'
                    '<pre id="log"></pre><div id="free"></div>')
    with open(os.path.join(_td63, "js", "b.js"), "w", encoding="utf-8") as _fh63:
        _fh63.write(
            "function a(){ var s = document.getElementById('stale');\n"
            "  s.textContent = d ? 'The host did not answer in time.' : 'The last read failed.'; }\n"
            "function b(){ var i = f.querySelector('[name=\"cred\"]'); i.placeholder = 'Enter your password'; }\n"
            "function c(){ var l = document.getElementById('log'); l.textContent = t('Loading the log'); }\n"
            "function e(){ var g = document.getElementById('free'); g.textContent = 'Free text goes here'; }\n"
            "function h(){ var lab = document.createElement('label'); lab.setAttribute('data-no-i18n', '');\n"
            "  lab.textContent = tag.name + ' (alerts muted)'; }\n")
    _gw63 = _i18n63.guarded_writes(js_dir=os.path.join(_td63, "js"), template_dir=os.path.join(_td63, "tpl"))
finally:
    _shutil63.rmtree(_td63, ignore_errors=True)
check("i18n scan (JS): a lower-case element text (\"banned now\", \"unblock\", \"(empty list)\") is asked for",
      {"banned now", "unblock", "(empty list)"} <= _js63, repr(sorted(_js63)))
check("i18n scan (JS): ...and an element's text after a splice in its opening tag, and after an emoji",
      {"Advanced: use a key instead", "view log", "❌ Request went wrong"} <= _js63, repr(sorted(_js63)))
check("i18n scan (JS): ...but not a word emphasised inside a sentence, a guarded element's text, or code "
      "(control)", not ({"free", "every", "home", "some code"} & _js63), repr(sorted(_js63)))
check("i18n scan (JS): panel text written into an element the translator skips, not through t(), is "
      "reported: by id, by name, and into one the script guards itself (control: through t(), or into "
      "an unguarded element, is not)",
      sorted(_t for _f, _l, _t in _gw63) == ["(alerts muted)", "Enter your password",
                                               "The host did not answer in time.", "The last read failed."],
      repr(_gw63))

# ── ...and on the real tree, nothing of any of those shapes is left ─────────────────────────────
_found63, _dynr63 = _i18n63.scan_templates(_TPL63)
check("i18n: no template text is welded to a {{ }}, guarded with a name, or written in a <pre> — catalog "
      "entry or not", not _dynr63,
      "; ".join("%r in %s" % (_k, sorted(_v)) for _k, _v in sorted(_dynr63.items())[:6]))
_jsr63 = _i18n63.scan_js(_JS63)
_miss63 = {lang: sorted(k for k in list(_found63) + list(_jsr63) if k not in cat)
           for lang, cat in (("es", _ES63), ("fr", _FR63))}
check("i18n: every string the templates and scripts show is in the French catalog as well as the "
      "Spanish one", not _miss63["es"] and not _miss63["fr"], repr({k: v[:6] for k, v in _miss63.items()}))
_gwr63 = _i18n63.guarded_writes()
check("i18n: no script writes panel text, untranslated, into an element the translator skips",
      not _gwr63, repr(_gwr63[:6]))

# ── labels a route supplies, rendered as whole text nodes ───────────────────────────────────────
from panel.ops import tailscale_integration as _tsi63  # noqa: E402
from panel.ops import terminal_session as _ts63  # noqa: E402
from panel.security.auth import ALL_PERMISSIONS as _PERMS63  # noqa: E402
from panel.services.notifications import EVENTS as _EVENTS63  # noqa: E402
_route63 = ([m[0] for m in _EVENTS63.values()] + list(_PERMS63.values())
            + [_tsi63.SUGGEST_SERVE, _tsi63.SUGGEST_TAILNET_IP, _tsi63.SUGGEST_NOT_LINKED,
               _tsi63.SUGGEST_NO_TAILSCALE]
            + [_ts63.SUDO_HINT_PER_USER, _ts63.SUDO_HINT_SYSTEM])
_rmiss63 = {lang: [k for k in _route63 if k not in cat] for lang, cat in (("es", _ES63), ("fr", _FR63))}
check("i18n: every alert-event label, permission name, Tailscale suggestion and sudo hint is in both "
      "catalogs (all 39 event and permission labels were English on /notifications and /groups)",
      not _rmiss63["es"] and not _rmiss63["fr"], repr({k: v[:4] for k, v in _rmiss63.items()}))
_pct63 = sorted((lang, k) for lang, cat in (("es", _ES63), ("fr", _FR63)) for k, v in cat.items()
                if _re63.findall(r"%[sd%]", k) != _re63.findall(r"%[sd%]", v))
check("i18n: every translation keeps its key's %s placeholders (a |format or a % on one that lost them "
      "is a 500)", not _pct63, repr(_pct63[:6]))
_sd_note63 = _tsi63._direct_suggestion(5000, "https", _tsi63.SUGGEST_NO_TAILSCALE)
check("tailscale page: a suggestion's sentence and its address are separate fields, the sentence a "
      "catalog key (the page showed the f-string, English in every language)",
      _sd_note63.get("note") == _tsi63.SUGGEST_NO_TAILSCALE and _sd_note63.get("note_value") == ""
      and "suggestion.note" in _read63(_TPL63, "tailscale.html"), repr(_sd_note63))
_pwd63 = __import__("pwd")
_saved_pw63, _saved_svc63 = _pwd63.getpwuid, _so63._is_system_service
try:
    _pwd63.getpwuid = lambda uid: _NS63(pw_name="gsmops")
    _so63._is_system_service = lambda: True
    _hint63 = _ts63.sudo_hint(None, True, tr=lambda s: _ES63.get(s, s))
finally:
    _pwd63.getpwuid, _so63._is_system_service = _saved_pw63, _saved_svc63
check("terminal: the sudo hint is translated before the account's name goes in (the name made it one "
      "node no key matched, so it was English in every language)",
      _hint63 == _ES63.get(_ts63.SUDO_HINT_SYSTEM, "?") % ("gsmops", "gsmops"), _hint63[:120])

# ── rendered in Spanish: the attributes and confirms carry the translated sentence ──────────────
from panel.db.models import GameServer as _GS63, User as _User63  # noqa: E402
_c63 = _p9_client(P9_ADMIN)
with _c63.session_transaction() as _s63:
    _s63["lang"] = "es"
# A saved language wins over the session's, so the admin's is cleared for these renders.
with _p9.app_context():
    _gsname63 = _db63.session.get(_GS63, P9_GS).name
    _lang63 = _db63.session.get(_User63, P9_ADMIN).language
    _db63.session.get(_User63, P9_ADMIN).language = None
    _db63.session.commit()
try:
    _dash63 = _c63.get("/").get_data(as_text=True)
    _users63 = _c63.get("/users").get_data(as_text=True)
finally:
    with _p9.app_context():
        _db63.session.get(_User63, P9_ADMIN).language = _lang63
        _db63.session.commit()
check("i18n: the dashboard's row controls are labelled in the viewer's language, with the server's "
      "name verbatim (\"Start <name>\" was English in every language)",
      'aria-label="Iniciar %s"' % _gsname63 in _dash63 and 'aria-label="Start ' not in _dash63,
      repr(_dash63.count("aria-label=")))
check("i18n: ...and /users' delete confirm is the translated sentence (it was English with the name "
      "inside)", "¿Eliminar el usuario “" in _users63 and "Delete user “" not in _users63,
      repr(_users63.count("data-confirm=")))
