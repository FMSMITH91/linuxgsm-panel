"""Part 164 of the unit suite: the twenty-seventh review's console, palette, cron and status fixes (builder C).

Held here, each against the code path the finding named:

* the console's priming read that lands on the OLD log just before LinuxGSM rotates it: the game's
  last lines, pushed while the read was out, were wiped, and the catch-up from the window's end found
  the log moved and could not bring them back. Now kept by their place (inode and offset) and shown
  when the catch-up answers `gap` or cannot answer; dropped when it reads them itself. The page runs
  WHOLE in node, in part38's world (its poller, its rotation, its catch-up answers).
* lines kept from an older log sat directly above a window that may be only a TAIL of the new log,
  with nothing between them. /api/console now says whether its window is the whole log (`whole`),
  and the page puts a notice between the two when it is not.
* cron's journal parser took `int(float(tok))` of a line's first word: `inf` (or 400 digits) raised
  OverflowError and the Scheduled Tasks card 500'd. Now only a plain epoch in column 0 counts.
* `get_server_status` took the state from the first line merely CONTAINING "status:" — a server
  description could decide it. Now only LinuxGSM's own Status line, the last one, as `details` prints
  it (twice, both after the name and description); `_details_started` reads the same way.
* the command palette searched sections and actions by their English words only, while an es/fr page
  shows them translated.
* panel/static/js/.eslintrc.json's globals list missed names used across the scripts and listed dead
  ones; terminal.html's comment claimed remote_manage passes no `status`.
"""
import json as _json164
import os as _os164
import re as _re164
import shutil as _shutil164
import subprocess as _sp164  # nosec B404 - node and bash on this part's own fixtures
import tempfile as _tf164
from types import SimpleNamespace as NS

from panel.ops.ssh_manager import cron as _cron164
from panel.ops.ssh_manager import files as _files164
from panel.ops.ssh_manager import game as _game164
from panel.routes import server_files as _sf164
from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_patch_sm,
                         _p9_restore_all)
from unit.part38 import _HARNESS38, _PANEL38, _SRC38
from unit.part47 import _cut47, _node47
from unit.part158 import _FUNCS158, _SD158
from unit.part161 import _harness161

_TRIP164 = len(_P9_TRIPPED)


def _read164(*parts):
    with open(_os164.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── cron: the journal's first word ───────────────────────────────────────────────────────────────
_MARK164 = "(gm) CMD "
_JOURNAL164 = "\n".join([
    "1700000000.5 host CRON[1]: (gm) CMD (/home/gm/a start)",
    # A message's continuation line, indented, which any local account can fill (its comm set to cron).
    "    inf (gm) CMD (/home/gm/b start)",
    "inf host CRON[2]: (gm) CMD (/home/gm/c start)",
    "9" * 400 + " host CRON[3]: (gm) CMD (/home/gm/d start)",
    "1e5 host CRON[4]: (gm) CMD (/home/gm/e start)",
    "1700000100 host CRON[5]: (gm) CMD (/home/gm/a start)",
])
try:
    _runs164 = _cron164._cron_run_times_from(_JOURNAL164, _MARK164)
except (OverflowError, ValueError) as _e164:
    _runs164 = "raised %s" % type(_e164).__name__
check("cron r39c: a journal line whose first word is inf or a 400-digit number does not raise (OverflowError "
      "500'd the Scheduled Tasks card), and only an entry's own epoch in column 0 gives a last run",
      _runs164 == {"/home/gm/a start": 1700000100}, repr(_runs164))
try:
    _lock164 = _cron164._parse_backup_listing("LOCK\tinf")[1]
    _mt164 = _files164._upload_dir_entries("f\t1\tinf\tname").get("name", {}).get("mtime")
except OverflowError:
    _lock164 = _mt164 = "raised"
check("cron r39c: ...and the backup listing's lock time and the upload check's mtime read `inf` as unreadable "
      "(OverflowError), the same class", _lock164 == 0 and _mt164 == 0, repr((_lock164, _mt164)))


# ── get_server_status: LinuxGSM's own Status line ────────────────────────────────────────────────
def _details164(description, status):
    """`details` as LinuxGSM v26.5.0 prints it (info_messages.sh), with ANSI colours."""
    return ("\x1b[34mServer name:\t\x1b[0mMy server\n"
            "\x1b[34mServer Description:\t\x1b[0m%s\n"
            "\x1b[34mStatus:\t\x1b[32m%s\x1b[0m\n"
            "\x1b[34mQuery Check:\t\x1b[0mhttps://ismygameserver.online/x\n"
            "\x1b[34mDESCRIPTION\tPORT\tPROTOCOL\tLISTEN\x1b[0m\n"
            "\n\x1b[34mStatus:\t\x1b[32m%s\x1b[0m\n\n" % (description, status, status))


_st164 = {}
try:
    _p9_arm(who="part164")     # so the closing "nothing reached a real transport" check can see a trip
    _p9_patch(_game164, "_really_serving", lambda server, gs: True)
    _gs164 = NS(short_name="rustserver", lgsm_name="rustserver")
    for _k164, _desc164, _state164 in (
            ("wipe", "Wipe status: stopped until Thursday", "STARTED"),
            ("newline", "Fresh map\nStatus: STOPPED", "STARTED"),
            ("started-word", "status: started daily at 6", "STOPPED"),
            ("plain", "A server", "STARTED")):
        _text164 = _details164(_desc164, _state164)
        _p9_patch(_game164._core, "run_as_game_user", lambda *a, _t=_text164, **k: (_t, "", 0))
        _st164[_k164] = (_game164.get_server_status(NS(), _gs164),
                         _game164._details_started(_game164.terminal.strip_escapes(_text164)))
finally:
    _p9_restore_all()
check("status r39c: a running server whose description reads 'Wipe status: stopped' is online, not offline "
      "(the first line containing status: decided it)", _st164.get("wipe") == ("online", True), repr(_st164))
check("status r39c: ...and one whose description's newline starts a line 'Status: STOPPED' is still online, "
      "in get_server_status and in _details_started (the first anchored line decided that one)",
      _st164.get("newline") == ("online", True), repr(_st164))
check("status r39c: ...a stopped server whose description says 'status: started' reads offline, and a plain "
      "running one online (control)",
      _st164.get("started-word") == ("offline", False) and _st164.get("plain") == ("online", True), repr(_st164))


# ── the palette: searched in the viewer's language too ───────────────────────────────────────────
_PAL164 = _read164("panel", "static", "js", "palette.js")
_PALPROG164 = (
    "const ES = {'Backups': 'Copias de seguridad', 'Restart': 'Reiniciar', 'Reboot': 'Reiniciar',\n"
    "            'the panel host': 'el host del panel', 'Panel Server': 'Servidor del panel'};\n"
    "global.window = global; window.MOUNT = ''; window.LOCAL_HOST_ID = 5; window.PALETTE_CAN = {};\n"
    "function t(s){ return ES[s] || s; } function _tr(s){ return t(s); }\n"
    "var PALETTE_SECTIONS = [{page: '/backups', hash: 'sec-bk', label: 'Backups', kw: 'archive restore'}];\n"
    "var PALETTE_HOST_SECTIONS = [];\n"
    "var ACTION_LABEL = { start: 'Start', restart: 'Restart', stop: 'Stop' };\n"
    "var ACTION_ICON = {}; var GROUP_ORDER = { pages: 0, sections: 1, servers: 2, actions: 3 };\n"
    "var servers = [{id: 1, name: 'MyServer', game: 'cs2', host: 'h1', actions: ['restart']}];\n"
    "function pages(){ return [{label: 'Copias de seguridad', href: '/backups', icon: ''},\n"
    "  {label: 'Panel', href: '/server-management', icon: ''}, {label: 'Box', href: '/remote/3/manage', icon: ''}]; }\n"
    + _cut47(_PAL164, "function score(") + "\n" + _cut47(_PAL164, "function matches(") + "\n"
    + "const q = s => matches(s).map(e => e.group + ':' + e.label).filter(x => !x.startsWith('pages:'));\n"
    "console.log(JSON.stringify({copias: q('copias'), reiniciar: q('reiniciar'), restart: q('restart'),\n"
    "  archive: q('archive')}));\n")
_pal164 = _node47(_PALPROG164) if "function matches(" in _PAL164 else {"error": "matches() is gone"}
if _pal164 is None:
    skip("palette r39c: sections and actions searched in the viewer's language", "node is not installed here")
else:
    check("palette r39c: on a Spanish page, typing the section's shown name ('copias') finds it (searched in "
          "English only, it found nothing)", "sections:Copias de seguridad" in (_pal164.get("copias") or []),
          repr(_pal164))
    check("palette r39c: ...and the shown verb ('reiniciar') finds the server's Restart and the host reboots",
          set(_pal164.get("reiniciar") or []) >= {"actions:Reiniciar MyServer", "actions:Reiniciar Box…",
                                                  "actions:Reiniciar el host del panel…"}, repr(_pal164))
    check("palette r39c: ...while the English keywords still find them ('restart', 'archive')",
          "actions:Reiniciar MyServer" in (_pal164.get("restart") or [])
          and "sections:Copias de seguridad" in (_pal164.get("archive") or []), repr(_pal164))


# ── .eslintrc.json's globals and terminal.html's comment ─────────────────────────────────────────
_ESL164 = _json164.loads(_read164("panel", "static", "js", ".eslintrc.json"))["globals"]
_SCRIPTS164 = []
for _dir164, _ext164 in ((("panel", "static", "js"), ".js"), (("panel", "templates"), ".html")):
    for _f164 in sorted(_os164.listdir(_os164.path.join(_root, *_dir164))):
        if _f164.endswith(_ext164):
            _SCRIPTS164.append(_read164(*(_dir164 + (_f164,))))
_ALLJS164 = "\n".join(_SCRIPTS164)
_undefined164 = [n for n, how in _ESL164.items() if how == "writable" and not _re164.search(
    r"(?:\bfunction\s+%s\b|\b(?:var|let|const)\s+%s\b|\bwindow\.%s\s*=[^=])" % ((_re164.escape(n),) * 3), _ALLJS164)]
check("eslint r39c: every global .eslintrc.json declares is defined by a script or a template (three were "
      "gone, two more only named in comments)", not _undefined164, repr(_undefined164))
# Read bare by a script that does not define them (ESLint 8 no-undef over panel/static/js, 2026-11-08).
_NEEDED164 = ("tf", "tfHtml", "tfNodes", "tfn", "serverId", "REMOTE_ID", "SERVER_NAME", "IS_LOCAL", "Terminal",
              "_cmpaHistEnd", "refreshFirewall", "_esc", "CODES")
check("eslint r39c: ...and the names the scripts read from another file or a template are declared (no-undef "
      "flagged every call of tf, tfHtml, serverId…)", all(n in _ESL164 for n in _NEEDED164),
      repr([n for n in _NEEDED164 if n not in _ESL164]))
_TERM164 = _read164("panel", "templates", "terminal.html")
check("terminal r39c: the Back-to-host comment no longer says remote_manage renders the panel host with no "
      "status, and remote_manage does pass it",
      "NO `status`" not in _TERM164 and "called only by server_management" not in _TERM164
      and "status=status" in _read164("panel", "routes", "remote_vps.py"), "")


# ── /api/console says whether its window is the whole log ────────────────────────────────────────
_TMP164 = _tf164.mkdtemp(prefix="lgsm-unit-p164-")


def _bash164(remote, user, cmd, timeout=15, selfname=None):
    p = _sp164.run(["bash", "-c", cmd],  # nosec B603 B607 - bash on this part's own command
                   capture_output=True, text=True, timeout=30, check=False)
    return p.stdout, p.stderr, p.returncode


_whole164 = {}
_log164 = _os164.path.join(_TMP164, "console.log")
try:
    _p9_arm(who="part164")
    # /api/console reads the host's timezone first; P9_GS's host has none stored, so unstubbed that
    # started a real lookup on the fixture address.
    _p9_patch(_sf164, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("read_as_game_user", _bash164)
    _gsw164 = NS(console_log=_log164, short_name="gm", lgsm_name="gm")
    for _k164, _text164, _want164 in (("short", "a\nb\nc\n", 50), ("exact", "a\nb\nc\n", 3), ("longer", "a\nb\nc\n", 2),
                                      ("fragment", "a\nb\nc\nd", 3), ("empty", "", 50)):
        with open(_log164, "w", encoding="utf-8") as _fh164:
            _fh164.write(_text164)
        _got164 = _sf164._read_console_window(NS(), _gsw164, _want164, None)
        _whole164[_k164] = (_got164[3], [r["line"] for r in _got164[1]])
    with open(_log164, "w", encoding="utf-8") as _fh164:
        _fh164.write("x" * (_sf164._CATCHUP_REACH + 10) + "\nlast\n")
    _got164 = _sf164._read_console_window(NS(), _gsw164, 50, None)
    _whole164["past-reach"] = (_got164[3], [r["line"] for r in _got164[1]])
    # The caller: /api/console's answer carries it.
    _p9_patch_sm("read_as_game_user", lambda *a, **k: ("@7 6 3\nBa\nb\nc\nE", "", 0))
    _api164 = _p9_json(_p9_client(P9_ADMIN).get("/api/console/%d?lines=50" % P9_GS))
    _p9_patch_sm("read_as_game_user", lambda *a, **k: ("@7 6\nBa\nb\nc\nE", "", 0))
    _api164b = _p9_json(_p9_client(P9_ADMIN).get("/api/console/%d?lines=50" % P9_GS))
finally:
    _p9_restore_all()
check("console r39c: the window says it is the whole log when the log has no more lines than asked for, and "
      "not when it has more, ends mid-line past them, or lies past the catch-up's reach (it never said)",
      _whole164.get("short") == (True, ["a", "b", "c"]) and _whole164.get("exact") == (True, ["a", "b", "c"])
      and _whole164.get("longer") == (False, ["b", "c"]) and _whole164.get("fragment", (None,))[0] is False
      and _whole164.get("empty", (None,))[0] is True and _whole164.get("past-reach") == (False, ["last"]),
      repr(_whole164))
check("console r39c: ...and /api/console's answer carries it, as `whole` (false for a reply with no count)",
      _api164.get("whole") is True and _api164.get("at") == [0, 7, 6] and _api164b.get("whole") is False
      and _api164b.get("at") == [0, 7, 6], repr((_api164, _api164b)))


# ── the page: a notice between an older log's kept lines and a window that is only a tail ────────
_GAPMSG164 = ("Some output from the start of the current console log is not shown. "
              "The server keeps it in its console log files.")
_h164 = _harness161()
_TAILHEADS164 = ("function _r39c_tailGap(", "function _showReturnGap(")
_GAPPROG164 = (
    "(async () => { const out = {};\n"
    "  answer({lines: rows(['a1', 'a2']), at: [0, 11, 20], whole: false}); refreshConsole(true); await settle();\n"
    "  out.first = shown();\n"
    # Clear; the old log's last line, then the new log's first lines, pushed; the re-prime's window is
    # only the new log's tail.
    "  push(['a3'], [1, 11, 30]); clearConsole(); push(['a4'], [1, 11, 40]);\n"
    "  push(['[ INFO ] Restarting', 'b1'], [2, 12, 25]);\n"
    "  refreshConsole(false); answer({lines: rows(['b5', 'b6']), at: [0, 12, 90], whole: false}); await settle();\n"
    "  out.tail = shown(); out.tailCls = consoleEl.children.map(c => c.className);\n"
    "  out.tailLines = _consoleLines.slice();\n"
    # The same, the window the whole new log.
    "  clearConsole(); push(['b7'], [2, 12, 95]); push(['[ INFO ] Restarting', 'c1'], [3, 13, 25]);\n"
    "  refreshConsole(false);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'c1', 'c2']), at: [0, 13, 30], whole: true}); await settle();\n"
    "  out.whole = shown();\n"
    # Load older: the 2000-line window is the new log's tail.
    "  push(['[ INFO ] Restarting', 'd1'], [4, 14, 25]); loadMoreConsole(null);\n"
    "  answer({lines: rows(['d8', 'd9']), at: [0, 14, 99], whole: false}); await settle();\n"
    "  out.older = shown();\n"
    "  console.log(JSON.stringify(out)); })();\n")
if _h164 is None or any(h not in _SD158 for h in _TAILHEADS164):
    check("console r39c: the functions part164 runs are all still in server_detail.js", False,
          [h for h in _FUNCS158 + _TAILHEADS164 if h not in _SD158])
    _gap164 = {}
else:
    _gap164 = _node47(_h164 + "var _gapFromDrop = false;\n" + "\n".join(_cut47(_SD158, h) for h in _TAILHEADS164)
                      + "\n" + _GAPPROG164)
if _gap164 is None:
    skip("console r39c: the notice between an older log's lines and a tail of the new one",
         "node is not installed here")
elif _gap164:
    check("console r39c: after Clear and a Restart, the old log's kept line, then a notice that output is missing, "
          "then the re-prime's window when it is only the new log's tail (they read as neighbours)",
          _gap164.get("tail") == ["a4", _GAPMSG164, "b5", "b6"]
          and "console-gap" in (_gap164.get("tailCls") or ["", ""])[1]
          and _GAPMSG164 not in (_gap164.get("tailLines") or [_GAPMSG164]), _json164.dumps(_gap164))
    check("console r39c: ...no notice when the window is the whole new log, nor on the first window with nothing "
          "kept above it (control)",
          _gap164.get("whole") == ["b7", "[ INFO ] Restarting", "c1", "c2"] and _gap164.get("first") == ["a1", "a2"],
          _json164.dumps(_gap164))
    check("console r39c: ...and Load older whose window is the new log's tail puts the notice between the kept "
          "lines and it",
          _gap164.get("older") == ["b7", "[ INFO ] Restarting", "c1", "c2", _GAPMSG164, "d8", "d9"],
          _json164.dumps(_gap164))


# ── the page, whole, in part38's world: the priming read lands just before the log rotates ──────
_WORLDCHECK164 = r"""
async function checkR39cPrimeRotated(cfg) {
  const cases = [['the poller had pushed up to the window\'s end', false, 0, false],
                 ['the poller\'s push straddles the window\'s end', true, 0, false],
                 ['the catch-up the host cannot answer', false, 3, false],
                 ['the log rotated after the catch-up read it (control)', false, 0, true]];
  for (const [label, straddle, fail, late] of cases) {
    const w = await loadWorld(cfg);
    w.write(20);
    await w.reconnect();
    w.pass();
    await w.reply(w.read(w.pending()[0]));          // the page's first window, caught up from its end
    await w.passAll();
    w.write(2); await w.pass();
    w.page.ctx.clearConsole();
    w.page.ctx.refreshConsole(false);                // the re-prime's read goes out...
    if (straddle) w.write(1);                        // (a line written that the poller has not read yet)
    const rd = w.read(w.pending()[0]);               // ...the host reads the old log...
    w.write(3); await w.pass();                      // ...the game's last lines are pushed...
    const old = w.log().slice();
    if (late) { await w.reply(rd); await w.passAll(); w.rotate(4); }
    else { w.rotate(4); await w.reply(rd); }         // ...a Restart moves the log aside, then the answer lands
    w.failReads = fail;
    for (let i = 0; i < 4; i++) await w.passAll();
    w.write(1); await w.passAll();
    const got = w.pageLog(), want = old.concat(w.log());
    check('r39c: a priming read that lands on the old log just before a Restart rotates it, ' + label
          + ': the old log\'s last lines pushed during the read show once, before the new log, and no notice',
          JSON.stringify(got) === JSON.stringify(want) && w.page.gaps().length === 0 && !w.page.ctx._resync,
          JSON.stringify({got: got.slice(-12), want: want.slice(-12), gaps: w.page.gaps().length}));
  }
}

"""
_ANCHOR164 = "(async () => {\n  const cfg = JSON.parse("
_LIST164 = "for (const fn of [checkLoad,"
if _ANCHOR164 not in _HARNESS38 or _LIST164 not in _HARNESS38:
    check("console r39c: part38's page harness still has the places part164 adds its check at", False, "")
elif not _shutil164.which("node"):
    skip("console r39c: the priming read before a rotation, in part38's world", "node is not installed here")
else:
    _prog164 = _HARNESS38.replace(_ANCHOR164, _WORLDCHECK164 + _ANCHOR164).replace(
        _LIST164, "for (const fn of [checkR39cPrimeRotated, checkLoad,")
    _path164 = _os164.path.join(_TMP164, "harness.js")
    with open(_path164, "w", encoding="utf-8") as _fh164:
        _fh164.write(_prog164)
    _r164 = _sp164.run([_shutil164.which("node"), _path164],  # nosec B603 - node on this part's harness
                       input=_json164.dumps({"src": _SRC38, "panel": _PANEL38, "mode": "checks",
                                             "only": "^checkR39c"}),
                       capture_output=True, text=True, timeout=300, check=False)
    try:
        _world164 = _json164.loads(_r164.stdout)
    except ValueError:
        _world164 = {"error": (_r164.stdout + _r164.stderr)[-1500:]}
    _res164 = _world164.get("results") or []
    check("console r39c: the world check ran, with its four cases",
          _world164.get("ran") == ["checkR39cPrimeRotated"] and len(_res164) == 4, repr(_world164)[:1500])
    for _one164 in _res164:
        check("console " + _one164["name"], _one164["ok"], _one164.get("detail", ""))
_shutil164.rmtree(_TMP164, ignore_errors=True)

check("part164: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP164, repr(_P9_TRIPPED[_TRIP164:]))
