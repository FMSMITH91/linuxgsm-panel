"""Part 198 of the unit suite: Scheduled Tasks' last-run times, read from one account's cron journal.

Held here:
* The helper's journal-cron-account verb: one argument, a validated account name (a flag, a shell
  fragment, a pattern, root or an empty name is refused, by the helper and by the panel's table);
  journalctl's argv is the same in both tables, newest first and bounded by --since, never by -n.
* do_journal_cron_account run for real against a stand-in journalctl: only lines carrying
  `(<account>) CMD ` as a fixed string (not a suffix of another account, not a dot as a pattern),
  only an entry's first line, no over-long line, one line per command (its newest run), and it stops
  after 800 of the account's lines, ending journalctl rather than reading on.
* The remote rendering (journalctl | awk) run under bash against the same stand-in: the same answer.
* The panel's caller, _read_cron_run_times, through the real run_privileged on each transport: the
  helper argv, the remote command run for real, the fallback to journal-cron for a panel-host helper
  that answers "unknown verb" (and no fallback on any other failure), a name the panel refuses, the
  output cap, and the newest time kept whatever the order.
* GET /api/server/<id>/cron on part12's app shows the last-run time from a stubbed read.

HOW IT RUNS. The stand-in journalctl is a bash script in a temp dir printing a fixed journal, then
paced lines for at most 30 s, which only a reader that stopped early does not wait for. The panel's
transports are stubbed or run against that stand-in; part12's tripwire is armed for the route.
"""
import os as _os198
import shutil as _sh198
import subprocess as _sp198  # nosec B404 - bash over this part's own stand-in and the panel's rendering
import tempfile as _tf198
import time as _time198

from unit.part01 import NS, _sm_core, _sm_cron, check, eq
from unit.part05 import _helper, _priv
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _p9_arm, _p9_client, _p9_delete_server, _p9_new_server,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.routes import server_files as _sf198

_TMP198 = _tf198.mkdtemp(prefix="lgsm-unit-p198-")
_MON198 = "/home/codserver/codserver monitor > /dev/null 2>&1"
_L1 = "1788000300.000001 host CRON[9]: (codserver) CMD (%s)" % _MON198
_L5 = "1788000260 host CRON[6]: (codserver) CMD (/home/codserver/codserver update)"
_LDOT = "1788000255 host CRON[12]: (c.d) CMD (/home/c.d/y)"
# Newest first, as `journalctl -r` prints it.
_JOURNAL198 = [
    _L1,
    "1788000290 host CRON[8]: (xcodserver) CMD (/home/x/x start)",       # another account, a suffix
    "1788000285 host CRON[11]: (cxd) CMD (/home/cxd/x)",                   # `.` would match it as a pattern
    "1788000284 host CRON[14]: cxd CMD (/regex)",                          # ...and `(c.d) CMD ` as a regex this
    "    1788000280 (codserver) CMD (/forged continuation)",                # a continuation line
    "1788000270 host CRON[7]: (codserver) CMD (" + "x" * 5000 + ")",       # over-long
    _L5,
    _LDOT,
    "1788000250 host CRON[4]: pam_unix(cron:session): session opened for user codserver(uid=1001) by (uid=0)",
    "1788000000 host CRON[5]: (codserver) CMD (%s)" % _MON198,             # an older run of the first
]
# 3 of the account's lines so far; 797 more makes 800, after which nothing is read.
_JOURNAL198 += ["1787999000 host CRON[5]: (codserver) CMD (%s)" % _MON198] * 797
_JOURNAL198 += ["1787998000 host CRON[13]: (codserver) CMD (/home/codserver/codserver backup)"]
with open(_os198.path.join(_TMP198, "journal"), "w", encoding="utf-8") as _fh198:
    _fh198.write("\n".join(_JOURNAL198) + "\n")
_STAND198 = _os198.path.join(_TMP198, "bin", "journalctl")
_os198.makedirs(_os198.path.dirname(_STAND198))
with open(_STAND198, "w", encoding="utf-8") as _fh198:
    _fh198.write("#!/bin/bash\nprintf '%%s\\n' \"$@\" > %s/argv\ncat %s/journal\n[ -e %s/notail ] && exit 0\n"
                 "i=0; while [ $i -lt 3000 ]; do printf '%%s\\n' '1787990000 host CRON[1]: (codserver) CMD (/late)'; "
                 "i=$((i+1)); sleep 0.01; done\n" % (_TMP198, _TMP198, _TMP198))
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs itself
_os198.chmod(_STAND198, 0o700)  # nosec B103 - a test stand-in in a private temp dir


def _argv198():
    try:
        with open(_os198.path.join(_TMP198, "argv"), encoding="utf-8") as fh:
            return fh.read().splitlines()
    except FileNotFoundError:
        return []


def _refused198(side, args):
    """Does `side` refuse journal-cron-account with `args`?"""
    try:
        if side == "helper":
            _helper.validate("journal-cron-account", list(args))
        else:
            _priv.check_args("journal-cron-account", list(args))
        return False
    except ValueError:
        return True


# ── the verb: its argument and its journalctl argv ───────────────────────────────────────────────
_BAD198 = [[""], ["root"], ["-o"], ["--since=x"], ["a b"], ["$(id)"], ["(x) CMD ("], ["../x"], ["a" * 40],
           ["x*"], [], ["codserver", "codserver"]]
for _side198 in ("helper", "panel"):
    check("cron journal (%s): journal-cron-account refuses a flag, a shell fragment, a pattern, root, a "
          "wrong count" % _side198, all(_refused198(_side198, a) for a in _BAD198),
          repr([a for a in _BAD198 if not _refused198(_side198, a)]))
    check("cron journal (%s): ...and takes an account name (positive control)" % _side198,
          not _refused198(_side198, ["codserver"]) and not _refused198(_side198, ["c.d"]))
_JARGV198 = ["journalctl", "-r", "_COMM=cron", "--since", "-14 days", "-o", "short-unix", "--no-pager"]
eq("cron journal: journalctl reads cron's 14 days NEWEST first, bounded by --since and never by -n "
   "(-n with a match walks the whole journal), the same in the helper and the panel",
   (_helper.cron_journal_account_argv(), _priv.cron_journal_account_argv()), (_JARGV198, _JARGV198))
eq("cron journal: the helper and the panel stop after the same 800 lines and skip the same long lines",
   (_helper.CRON_JOURNAL_MATCHES, _priv.CRON_JOURNAL_MATCHES, _helper.CRON_JOURNAL_LINE_MAX,
    _priv.CRON_JOURNAL_LINE_MAX), (800, 800, 4096, 4096))
check("cron journal: journal-cron-account is a read, ended when its caller gives up",
      "journal-cron-account" in _helper.READ_VERBS)


# ── the helper's read, for real against the stand-in ─────────────────────────────────────────────
def _run_helper198(user):
    """Run do_journal_cron_account(user) with the stand-in as journalctl: (rc, stdout, seconds)."""
    saved = _helper.TOOLS.get("journalctl")
    out_path = _os198.path.join(_TMP198, "helper.out")
    t0 = _time198.monotonic()
    try:
        _helper.TOOLS["journalctl"] = (_STAND198,)
        with open(out_path, "w", encoding="utf-8") as sink:
            real, _helper.sys.stdout = _helper.sys.stdout, sink
            try:
                rc = _helper.do_journal_cron_account([user], "")
            finally:
                _helper.sys.stdout = real
    finally:
        _helper.TOOLS["journalctl"] = saved
    with open(out_path, encoding="utf-8") as fh:
        return rc, fh.read(), _time198.monotonic() - t0


_h198 = _run_helper198("codserver")
eq("cron journal helper: one line per command, its newest, only this account's first lines under the "
   "length limit, and nothing after the 800th of its lines",
   _h198[:2], (0, _L1 + "\n" + _L5 + "\n"))
check("cron journal helper: it ends journalctl at the 800th line instead of reading on (the stand-in "
      "prints for 30 s more)", _h198[2] < 10, "%.1fs" % _h198[2])
eq("cron journal helper: journalctl was run with the fixed argv, nothing of the caller's in it",
   _argv198(), _JARGV198[1:])
# An account that never reaches 800 lines reads the whole window: the stand-in's tail is left off.
open(_os198.path.join(_TMP198, "notail"), "w").close()
eq("cron journal helper: an account name is matched as text, so `c.d` is not a pattern for `cxd`",
   _run_helper198("c.d")[1], _LDOT + "\n")


# ── the remote rendering, run under bash against the same stand-in ───────────────────────────────
def _run_shell198(cmd):
    """Return what `cmd` prints under bash with the stand-in first on PATH."""
    env = {"PATH": _os198.path.dirname(_STAND198) + ":/usr/bin:/bin", "HOME": _TMP198}
    res = _sp198.run(["bash", "-c", cmd], env=env, capture_output=True, text=True,  # nosec B603 B607
                     timeout=60, stdin=_sp198.DEVNULL, check=False)
    return res.stdout


_os198.remove(_os198.path.join(_TMP198, "notail"))
_t198 = _time198.monotonic()
_r198 = _run_shell198(_priv.remote_command("journal-cron-account", ["codserver"]))
eq("cron journal remote: journalctl | awk answers exactly what the helper does",
   _r198, _h198[1])
check("cron journal remote: ...and stops journalctl at the 800th line too",
      _time198.monotonic() - _t198 < 10, "%.1fs" % (_time198.monotonic() - _t198))
open(_os198.path.join(_TMP198, "notail"), "w").close()
eq("cron journal remote: the dotted name is text there as well",
   _run_shell198(_priv.remote_command("journal-cron-account", ["c.d"])), _LDOT + "\n")


# ── the panel's caller, through the real run_privileged ──────────────────────────────────────────
_WANT198 = {_MON198: 1788000300, "/home/codserver/codserver update": 1788000260}
_OLD198 = "\n".join([   # journal-cron's window, oldest first, every account
    "1787000000 host CRON[1]: (codserver) CMD (%s)" % _MON198,
    "1787000100 host CRON[2]: (gmodserver) CMD (/home/gmodserver/gmodserver monitor)",
    "1787000200 host CRON[3]: (codserver) CMD (%s)" % _MON198,
])


def _local198(answers, user="codserver"):
    """Run _read_cron_run_times on the panel host with the helper installed: (its answer, the argv run)."""
    seen = []

    def _exec(argv, timeout=30, stdin_text=None):
        seen.append(list(argv))
        return answers.get(argv[3], ("", "", 1))

    saved = (_sm_core.helper_present, _sm_core._exec_local_argv)
    try:
        _sm_core.helper_present = lambda recheck=False: True
        _sm_core._exec_local_argv = _exec
        return _sm_cron._read_cron_run_times(NS(is_local=True), user), seen
    finally:
        _sm_core.helper_present, _sm_core._exec_local_argv = saved


_got198, _seen198 = _local198({"journal-cron-account": (_h198[1] + "1788000000 host CRON[5]: (codserver) CMD (%s)"
                                                         % _MON198, "", 0)})
eq("cron caller: the panel host asks the helper for this account's lines and reads the newest run of "
   "each command, an older line after it notwithstanding",
   (_got198, _seen198), (_WANT198, [["sudo", "-n", _priv.HELPER_PATH, "journal-cron-account", "codserver"]]))
_got198, _seen198 = _local198({
    "journal-cron-account": ("", "panel-helper: unknown verb 'journal-cron-account'", 2),
    "journal-cron": (_OLD198, "", 0)})
eq("cron caller: a helper older than the verb (unknown verb, rc 2) gets the window read, filtered here",
   (_got198, [a[3] for a in _seen198]), ({_MON198: 1787000200}, ["journal-cron-account", "journal-cron"]))
for _why198, _ans198 in (("a failed read", ("", "panel-helper: journal-cron-account failed (OSError)", 1)),
                         ("a timeout", ("", "timed out", -1)),
                         ("rc 2 without unknown verb", ("", "panel-helper: not a user name", 2))):
    _got198, _seen198 = _local198({"journal-cron-account": _ans198, "journal-cron": (_OLD198, "", 0)})
    eq("cron caller: %s is no times, and does not fall back to the window read" % _why198,
       (_got198, len(_seen198)), ({}, 1))


def _remote198(user):
    """Run _read_cron_run_times on a remote, the command sent run for real under bash: (answer, commands)."""
    sent = []

    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        sent.append(command)
        return _run_shell198(command), "", 0

    saved = _sm_core.run_command
    try:
        _sm_core.run_command = _run
        return _sm_cron._read_cron_run_times(NS(is_local=False, auth_method="key"), user), sent
    finally:
        _sm_core.run_command = saved


_got198, _sent198 = _remote198("codserver")
eq("cron caller: a remote host runs the journalctl | awk form, and its answer is read the same",
   _got198, _WANT198)
check("cron caller: ...the account in it is quoted text for awk's index(), not a pattern",
      len(_sent198) == 1 and "-v m='(codserver) CMD '" in _sent198[0] and "index($0, m)" in _sent198[0],
      repr(_sent198)[:300])
eq("cron caller: a name the panel refuses (root) is no times, and nothing is sent",
   _remote198("root"), ({}, []))
_cap198 = ("1788000000 host CRON[1]: (codserver) CMD (%s)\n" % _MON198) * (_sm_core._MAX_OUTPUT_BYTES // 80)
_got198, _seen198 = _local198({"journal-cron-account": (_cap198[:_sm_core._MAX_OUTPUT_BYTES], "", 0)})
eq("cron caller: an answer cut at the transport's output cap reports no last-run times", _got198, {})


# ── GET /api/server/<id>/cron, end to end on part12's app ───────────────────────────────────────
_CRONLINE198 = "*/5 * * * * /home/p198cs/p198cs monitor > /dev/null 2>&1"
_calls198 = []


def _priv198(server, verb, args=(), **kw):
    _calls198.append((verb, list(args)))
    if verb == "crontab-list":
        return _CRONLINE198 + "\n", "", 0
    if verb == "journal-cron-account":
        return "1788000300 host CRON[9]: (p198cs) CMD (/home/p198cs/p198cs monitor > /dev/null 2>&1)", "", 0
    return "", "", 1


_sid198 = None
_route198 = {}
try:
    _p9_arm(who="part198")
    _trips198 = len(_P9_TRIPPED)
    _sid198 = _p9_new_server(P9_HOST, "p198cs", "cs2", 27098, name="p198-cs2", status="online")
    _p9_patch_sm("run_privileged", _priv198)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("", "", 0))
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: None)
    _p9_patch(_sf198, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sf198, "_sync_toggles_from_cron", lambda gs, jobs: None)
    _resp198 = _p9_client(P9_ADMIN).get("/api/server/%d/cron" % _sid198)
    _route198 = {"status": _resp198.status_code, "json": _resp198.get_json(silent=True) or {},
                 "trips": _P9_TRIPPED[_trips198:]}
finally:
    _p9_restore_all()
    if _sid198 is not None:
        _p9_delete_server(_sid198)
eq("cron route: the Scheduled Tasks listing shows the monitor job's last run from the account's journal read",
   [(j.get("command"), j.get("last_run")) for j in _route198.get("json", {}).get("jobs", [])],
   [("/home/p198cs/p198cs monitor > /dev/null 2>&1", 1788000300)])
check("cron route: ...asked of journal-cron-account for that account, never the every-account window read",
      ("journal-cron-account", ["p198cs"]) in _calls198 and "journal-cron" not in [c[0] for c in _calls198],
      repr(_calls198))
eq("cron route: ...200, and nothing reached a real transport", (_route198.get("status"), _route198.get("trips")),
   (200, []))
_sh198.rmtree(_TMP198, ignore_errors=True)
