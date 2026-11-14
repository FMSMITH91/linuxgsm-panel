"""Part 198 of the unit suite: Scheduled Tasks' last-run times, read from one account's cron journal.

Held here:
* The helper's journal-cron-account verb: a validated account name (a flag, a shell fragment, a
  pattern, root or an empty name is refused, by the helper and by the panel's table) and a span
  (hour, day, fortnight, nothing else); journalctl's argv is the same in both tables, newest first and
  bounded by --since/--until, never by -n.
* do_journal_cron_account run for real against a stand-in journalctl: only lines carrying
  `(<account>) CMD ` as a fixed string (not a suffix of another account, not a dot as a pattern),
  only an entry's first line, no over-long line, one line per command (its newest run), and it stops
  after 800 of the account's lines, ending journalctl rather than reading on, and after 3 s of a
  journalctl that prints nothing.
* The remote rendering (timeout | journalctl | awk) run under bash against the same stand-in: the same
  answer, and the same two stops.
* The panel's caller, _read_cron_run_times, through the real run_privileged on each transport: the
  helper argv, span by span until every wanted command has a time, the remote command run for real,
  the fallback to journal-cron for a panel-host helper that answers "unknown verb" (and no fallback,
  and no wider span, on any other failure), a name the panel refuses, the output cap, and the newest
  time kept whatever the order.
* list_cron_jobs: no read at all for an empty crontab, no journal read when the recorder covers every
  job, and a read reused for the same account and jobs until a crontab write, a different crontab or
  60 s.
* GET /api/server/<id>/cron on part12's app shows the last-run time from a stubbed read, and a second
  load reads no journal.

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
    _fh198.write("#!/bin/bash\nprintf '%%s\\n' \"$@\" > %s/argv\n[ -e %s/silent ] && exec sleep 30\n"
                 "cat %s/journal\n[ -e %s/notail ] && exit 0\n"
                 "i=0; while [ $i -lt 3000 ]; do printf '%%s\\n' '1787990000 host CRON[1]: (codserver) CMD (/late)'; "
                 "i=$((i+1)); sleep 0.01; done\n" % (_TMP198, _TMP198, _TMP198, _TMP198))
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs itself
_os198.chmod(_STAND198, 0o700)  # nosec B103 - a test stand-in in a private temp dir


def _argv198():
    try:
        with open(_os198.path.join(_TMP198, "argv"), encoding="utf-8") as fh:
            return fh.read().splitlines()
    except FileNotFoundError:
        return []


def _flag198(name, on):
    """Set or clear one of the stand-in's modes (notail, silent)."""
    path = _os198.path.join(_TMP198, name)
    if on:
        open(path, "w").close()
    elif _os198.path.exists(path):
        _os198.remove(path)


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


# ── the verb: its arguments and its journalctl argv ──────────────────────────────────────────────
_BAD198 = [[b, "hour"] for b in ("", "root", "-o", "--since=x", "a b", "$(id)", "(x) CMD (", "../x", "a" * 40, "x*")]
_BAD198 += [["codserver", s] for s in ("", "week", "-1h", "--since=-1y", "Hour")]
_BAD198 += [[], ["codserver"], ["codserver", "hour", "hour"]]
for _side198 in ("helper", "panel"):
    check("cron journal (%s): journal-cron-account refuses a flag, a shell fragment, a pattern, root, a span "
          "it does not know, a wrong count" % _side198, all(_refused198(_side198, a) for a in _BAD198),
          repr([a for a in _BAD198 if not _refused198(_side198, a)]))
    check("cron journal (%s): ...and takes an account name and each span (positive control)" % _side198,
          not any(_refused198(_side198, [u, sp]) for u in ("codserver", "c.d") for sp in ("hour", "day", "fortnight")))
_JHEAD198, _JTAIL198 = ["journalctl", "-r", "_COMM=cron", "--since"], ["-o", "short-unix", "--no-pager"]
_JARGV198 = {"hour": _JHEAD198 + ["-1h"] + _JTAIL198,
             "day": _JHEAD198 + ["-24h", "--until", "-1h"] + _JTAIL198,
             "fortnight": _JHEAD198 + ["-14 days", "--until", "-24h"] + _JTAIL198}
eq("cron journal: journalctl reads one span of cron's 14 days NEWEST first, the last hour, the rest of the "
   "day, the rest of the fortnight, bounded by --since/--until and never by -n (-n with a match walks the "
   "whole journal), the same in the helper and the panel",
   [(_helper.cron_journal_account_argv(sp), _priv.cron_journal_account_argv(sp)) for sp in _JARGV198],
   [(v, v) for v in _JARGV198.values()])
eq("cron journal: the helper and the panel stop after the same 800 lines and 3 s, and skip the same long lines",
   (_helper.CRON_JOURNAL_MATCHES, _priv.CRON_JOURNAL_MATCHES, _helper.CRON_JOURNAL_LINE_MAX,
    _priv.CRON_JOURNAL_LINE_MAX, _helper.CRON_JOURNAL_BUDGET, _priv.CRON_JOURNAL_BUDGET), (800, 800, 4096, 4096, 3, 3))
check("cron journal: journal-cron-account is a read, ended when its caller gives up",
      "journal-cron-account" in _helper.READ_VERBS)


# ── the helper's read, for real against the stand-in ─────────────────────────────────────────────
def _run_helper198(user, span="fortnight"):
    """Run do_journal_cron_account(user) with the stand-in as journalctl: (rc, stdout, seconds)."""
    saved = _helper.TOOLS.get("journalctl")
    out_path = _os198.path.join(_TMP198, "helper.out")
    t0 = _time198.monotonic()
    try:
        _helper.TOOLS["journalctl"] = (_STAND198,)
        with open(out_path, "w", encoding="utf-8") as sink:
            real, _helper.sys.stdout = _helper.sys.stdout, sink
            try:
                rc = _helper.do_journal_cron_account([user, span], "")
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
      "prints for 30 s more, and the 3 s budget would end it later)", _h198[2] < 2.5, "%.1fs" % _h198[2])
eq("cron journal helper: journalctl was run with the span's fixed argv, nothing of the caller's in it",
   _argv198(), _JARGV198["fortnight"][1:])
_flag198("silent", True)
_hs198 = _run_helper198("codserver", "day")
_flag198("silent", False)
check("cron journal helper: a journalctl that prints nothing is ended at the 3 s budget, an empty answer",
      _hs198[:2] == (0, "") and 2.5 <= _hs198[2] < 10, repr(_hs198))
# An account that never reaches 800 lines reads the whole span: the stand-in's tail is left off.
_flag198("notail", True)
eq("cron journal helper: an account name is matched as text, so `c.d` is not a pattern for `cxd`",
   _run_helper198("c.d")[1], _LDOT + "\n")


# ── the remote rendering, run under bash against the same stand-in ───────────────────────────────
def _run_shell198(cmd):
    """Return what `cmd` prints under bash with the stand-in first on PATH."""
    env = {"PATH": _os198.path.dirname(_STAND198) + ":/usr/bin:/bin", "HOME": _TMP198}
    res = _sp198.run(["bash", "-c", cmd], env=env, capture_output=True, text=True,  # nosec B603 B607
                     timeout=60, stdin=_sp198.DEVNULL, check=False)
    return res.stdout


_flag198("notail", False)
_t198 = _time198.monotonic()
_r198 = _run_shell198(_priv.remote_command("journal-cron-account", ["codserver", "fortnight"]))
_rt198 = _time198.monotonic() - _t198
eq("cron journal remote: timeout | journalctl | awk answers exactly what the helper does",
   _r198, _h198[1])
check("cron journal remote: ...and stops journalctl at the 800th line too", _rt198 < 2.5, "%.1fs" % _rt198)
_flag198("silent", True)
_t198 = _time198.monotonic()
_rs198 = _run_shell198(_priv.remote_command("journal-cron-account", ["codserver", "hour"]))
_rt198 = _time198.monotonic() - _t198
_flag198("silent", False)
check("cron journal remote: ...and ends a journalctl that prints nothing at the same 3 s",
      _rs198 == "" and 2.5 <= _rt198 < 10, "%r %.1fs" % (_rs198, _rt198))
_flag198("notail", True)
eq("cron journal remote: the dotted name is text there as well",
   _run_shell198(_priv.remote_command("journal-cron-account", ["c.d", "hour"])), _LDOT + "\n")


# ── the panel's caller, through the real run_privileged ──────────────────────────────────────────
_WANT198 = {_MON198: 1788000300, "/home/codserver/codserver update": 1788000260}
_MONCORE198, _UPDCORE198 = "/home/codserver/codserver monitor", "/home/codserver/codserver update"
_OLD198 = "\n".join([   # journal-cron's window, oldest first, every account
    "1787000000 host CRON[1]: (codserver) CMD (%s)" % _MON198,
    "1787000100 host CRON[2]: (gmodserver) CMD (/home/gmodserver/gmodserver monitor)",
    "1787000200 host CRON[3]: (codserver) CMD (%s)" % _MON198,
])
# What each span's read answers: the monitor ran this hour, the update earlier today, and an older
# monitor run sits in the fortnight after a newer one.
_SPANS198 = {"hour": (_L1, "", 0), "day": (_L5, "", 0),
             "fortnight": ("1788000000 host CRON[5]: (codserver) CMD (%s)" % _MON198, "", 0)}


def _local198(answers, user="codserver", wants=None):
    """Run _read_cron_run_times on the panel host with the helper installed: (its answer, the argv run).

    `answers` maps a verb, or (verb, span), to what the helper says.
    """
    seen = []

    def _exec(argv, timeout=30, stdin_text=None):
        seen.append(list(argv))
        return answers.get(tuple(argv[3:4] + argv[5:6]), answers.get(argv[3], ("", "", 1)))

    saved = (_sm_core.helper_present, _sm_core._exec_local_argv)
    try:
        _sm_core.helper_present = lambda recheck=False: True
        _sm_core._exec_local_argv = _exec
        return _sm_cron._read_cron_run_times(NS(is_local=True), user, wants), seen
    finally:
        _sm_core.helper_present, _sm_core._exec_local_argv = saved


_A198 = {("journal-cron-account", sp): v for sp, v in _SPANS198.items()}
_got198, _seen198 = _local198(_A198, wants=[_MONCORE198])
eq("cron caller: the panel host asks the helper for this account's last hour, and stops there when every "
   "wanted job has a time",
   (_got198, _seen198), ({_MON198: 1788000300},
                         [["sudo", "-n", _priv.HELPER_PATH, "journal-cron-account", "codserver", "hour"]]))
_got198, _seen198 = _local198(_A198, wants=[_MONCORE198, _UPDCORE198])
eq("cron caller: ...reads the rest of the day only while a wanted job has no time yet",
   (_got198, [a[5] for a in _seen198]), (_WANT198, ["hour", "day"]))
_got198, _seen198 = _local198(_A198, wants=[_MONCORE198, "/home/codserver/never-ran"])
eq("cron caller: ...and the rest of the fortnight for a job never found, keeping each command's newest run "
   "across the spans", (_got198, [a[5] for a in _seen198]), (_WANT198, ["hour", "day", "fortnight"]))
_got198, _seen198 = _local198(_A198)
eq("cron caller: with no list of wanted jobs it reads every span", [a[5] for a in _seen198],
   ["hour", "day", "fortnight"])
_got198, _seen198 = _local198({
    "journal-cron-account": ("", "panel-helper: unknown verb 'journal-cron-account'", 2),
    "journal-cron": (_OLD198, "", 0)}, wants=["/home/codserver/never-ran"])
eq("cron caller: a helper older than the verb (unknown verb, rc 2) gets the window read once, filtered here",
   (_got198, [a[3] for a in _seen198]), ({_MON198: 1787000200}, ["journal-cron-account", "journal-cron"]))
for _why198, _ans198 in (("a failed read", ("", "panel-helper: journal-cron-account failed (OSError)", 1)),
                         ("a timeout", ("", "timed out", -1)),
                         ("rc 2 without unknown verb", ("", "panel-helper: not a user name", 2))):
    _got198, _seen198 = _local198({"journal-cron-account": _ans198, "journal-cron": (_OLD198, "", 0)})
    eq("cron caller: %s is no times, with no fallback to the window read and no wider span" % _why198,
       (_got198, len(_seen198)), ({}, 1))
_got198, _seen198 = _local198({("journal-cron-account", "hour"): (_L1, "", 0),
                               ("journal-cron-account", "day"): ("", "timed out", -1)})
eq("cron caller: a span that fails keeps what the narrower ones found, and asks for nothing wider",
   (_got198, len(_seen198)), ({_MON198: 1788000300}, 2))


def _remote198(user):
    """Run _read_cron_run_times on a remote, the command sent run for real under bash: (answer, commands)."""
    sent = []

    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        sent.append(command)
        return _run_shell198(command), "", 0

    saved = _sm_core.run_command
    try:
        _sm_core.run_command = _run
        return _sm_cron._read_cron_run_times(NS(is_local=False, auth_method="key"), user, ["x"]), sent
    finally:
        _sm_core.run_command = saved


_got198, _sent198 = _remote198("codserver")
eq("cron caller: a remote host runs the timeout | journalctl | awk form, span by span, and its answer is "
   "read the same", _got198, _WANT198)
check("cron caller: ...the account in it is quoted text for awk's index(), not a pattern",
      len(_sent198) == 3 and all("-v m='(codserver) CMD '" in c and "index($0, m)" in c for c in _sent198),
      repr(_sent198)[:300])
eq("cron caller: a name the panel refuses (root) is no times, and nothing is sent",
   _remote198("root"), ({}, []))
_cap198 = ("1788000000 host CRON[1]: (codserver) CMD (%s)\n" % _MON198) * (_sm_core._MAX_OUTPUT_BYTES // 80)
_got198, _seen198 = _local198({"journal-cron-account": (_cap198[:_sm_core._MAX_OUTPUT_BYTES], "", 0)})
eq("cron caller: an answer cut at the transport's output cap reports no last-run times", _got198, {})


# ── list_cron_jobs: when the journal is read at all, and the read reused ─────────────────────────
_SRV198 = NS(id=919198, is_local=False, auth_method="key")


def _list198(crontab, status=None):
    """list_cron_jobs(_SRV198, "codserver") with every host read stubbed: (rows, the reads made)."""
    reads = []

    def _rp(server, verb, args=(), **kw):
        reads.append((verb,) + tuple(args[1:]))
        if verb == "crontab-list":
            return crontab, "", 0
        return _SPANS198.get(args[1], ("", "", 1)) if verb == "journal-cron-account" else ("", "", 1)

    def _status(server, user):
        reads.append(("status",))
        return dict(status or {})

    saved = (_sm_core.run_privileged, _sm_cron._read_cron_status)
    try:
        _sm_core.run_privileged, _sm_cron._read_cron_status = _rp, _status
        rows = _sm_cron.list_cron_jobs(_SRV198, "codserver")
        return [(r["command"], r["last_run"]) for r in rows or []], reads
    finally:
        _sm_core.run_privileged, _sm_cron._read_cron_status = saved


_TAB198 = "*/5 * * * * %s\n0 5 * * * /home/codserver/codserver update\n" % _MON198
_KEY198 = _sm_core.cron_times_key(_SRV198, "codserver")
_sm_core.CRON_TIMES.pop(_KEY198, None)
eq("cron list: an empty crontab (comments and blank lines only) reads no status and no journal",
   _list198("# nothing here\n\n"), ([], [("crontab-list",)]))
eq("cron list: no journal read when the recorder has a status for every job",
   _list198("*/5 * * * * %s\n" % _MON198, {_sm_cron._cron_job_id(_MON198): {"last_run": 7, "ok": True}}),
   ([(_MON198, 7)], [("crontab-list",), ("status",)]))
eq("cron list: jobs with no recorder status are read from the journal, span by span until each has a time",
   _list198(_TAB198), ([(_MON198, 1788000300), ("/home/codserver/codserver update", 1788000260)],
                       [("crontab-list",), ("status",), ("journal-cron-account", "hour"),
                        ("journal-cron-account", "day")]))
eq("cron list: ...and opened again, the same account and jobs reuse that read",
   _list198(_TAB198), ([(_MON198, 1788000300), ("/home/codserver/codserver update", 1788000260)],
                       [("crontab-list",), ("status",)]))
eq("cron list: a different crontab reads again",
   _list198("*/5 * * * * %s\n" % _MON198)[1][2:], [("journal-cron-account", "hour")])
_list198(_TAB198)
_saved198 = _sm_core.shell_as_game_user
try:
    _sm_core.shell_as_game_user = lambda *a, **k: ("", "", 0)
    _sm_core._rewrite_crontab(_SRV198, "codserver", "", ["0 6 * * * /bin/true"])
finally:
    _sm_core.shell_as_game_user = _saved198
eq("cron list: a crontab write from the panel drops the reused read", _list198(_TAB198)[1][2:],
   [("journal-cron-account", "hour"), ("journal-cron-account", "day")])
_e198 = _sm_core.CRON_TIMES[_KEY198]
_sm_core.CRON_TIMES[_KEY198] = (_e198[0] - 61,) + _e198[1:]
eq("cron list: ...and so does age: a read 61 s old is not reused", _list198(_TAB198)[1][2:],
   [("journal-cron-account", "hour"), ("journal-cron-account", "day")])
eq("cron list: a record with no id is never kept", _sm_core.cron_times_key(NS(is_local=True), "codserver"), None)
_sm_core.CRON_TIMES.pop(_KEY198, None)


# ── GET /api/server/<id>/cron, end to end on part12's app ───────────────────────────────────────
_CRONLINE198 = "*/5 * * * * /home/p198cs/p198cs monitor > /dev/null 2>&1"
_calls198 = []


def _priv198(server, verb, args=(), **kw):
    _calls198.append((verb, list(args)))
    if verb == "crontab-list":
        return _CRONLINE198 + "\n", "", 0
    if verb == "journal-cron-account" and list(args) == ["p198cs", "hour"]:
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
    _first198 = list(_calls198)
    _again198 = _p9_client(P9_ADMIN).get("/api/server/%d/cron" % _sid198)
    _route198 = {"status": (_resp198.status_code, _again198.status_code),
                 "json": _resp198.get_json(silent=True) or {}, "again": _again198.get_json(silent=True) or {},
                 "trips": _P9_TRIPPED[_trips198:], "second": _calls198[len(_first198):], "first": _first198}
finally:
    _p9_restore_all()
    _sm_core.CRON_TIMES.clear()
    if _sid198 is not None:
        _p9_delete_server(_sid198)
eq("cron route: the Scheduled Tasks listing shows the monitor job's last run from the account's journal read",
   [(j.get("command"), j.get("last_run")) for j in _route198.get("json", {}).get("jobs", [])],
   [("/home/p198cs/p198cs monitor > /dev/null 2>&1", 1788000300)])
eq("cron route: ...asked of journal-cron-account for that account's last hour, never the every-account "
   "window read", _route198.get("first"), [("crontab-list", ["p198cs"]), ("journal-cron-account", ["p198cs", "hour"])])
eq("cron route: a second load shows the same time and reads no journal",
   ([(j.get("command"), j.get("last_run")) for j in _route198.get("again", {}).get("jobs", [])],
    _route198.get("second")),
   ([("/home/p198cs/p198cs monitor > /dev/null 2>&1", 1788000300)], [("crontab-list", ["p198cs"])]))
eq("cron route: ...200 both times, and nothing reached a real transport",
   (_route198.get("status"), _route198.get("trips")), ((200, 200), []))
_sh198.rmtree(_TMP198, ignore_errors=True)
