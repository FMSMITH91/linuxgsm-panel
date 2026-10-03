"""Part 39 of the unit suite: the report's journal read is bounded; a dropped call ends as root.

The debug report's journal read is bounded, and a privileged call the panel gives up on leaves
nothing running as root.

Both came from the test VPS (1.9 GB of journal, 105 files). The report's filtered read, `journal
panel-own 5000`, asked journalctl for the panel unit's own output by field matches with `-n 5000`.
Only 1683 entries matched in the whole journal, so journalctl walked all of it: still running as
root at 315 s, the report's 10 s budget gone, the plain fallback left 0.5 s, and the report showed
no journal. And when the panel gave up it SIGKILLed the process group it had started -- sudo, which
died without relaying anything -- so the root helper and its journalctl ran on, parented to init,
for about 5.5 minutes of a core. Each check below fails on the code before these fixes, or holds
a property they rely on against the one change that would break it (a writer watched for a lost
parent, a streamed download given the deadline, a writer slipped into READ_VERBS):

* A. the field-match sources read a fixed window FORWARD (`--since=<window> --lines=+N`), never
     `-n N`, the same in the helper and the panel; every OR'd branch of the panel's own read has a
     term that is sparse on its own (or journalctl re-walks the branch once per line printed), and
     the stdout identifier among them is the one install.sh's unit gives; a real journalctl accepts
     the argv; and on a real journal (built with systemd-journal-remote, where it is installed) the
     read returns nothing from outside its window, where `-n` reached the oldest match there was,
     and prints a traceback's continuation lines indented;
* B. the report's read gives a filtered read at most half the time left, so the plain read after
     it always has the rest; a filtered read that came back FULL -- counted in ENTRIES, not lines
     -- gives way to the plain read of the newest N, and when that has nothing is the answer,
     marked cut, which both sections say; the per-user and unprivileged reads are windowed the
     same way; and the report names the window;
* C. the helper, run for real under a stand-in sudo with a stand-in journalctl that forks a
     grandchild: a read's whole tree ends on a relayed SIGTERM, on the loss of its parent (sudo
     SIGKILLed), and at its deadline, a grandchild that ignores SIGTERM after its parent died of it
     included; lgsm-command is a read for LinuxGSM's reporting actions; a verb that CHANGES the
     host runs to its end through a SIGTERM and through the loss of its sudo, follow-up included;
     a streamed download has no deadline; READ_VERBS is an explicit set; main()'s own bound on a
     read's tool; and no panel call waits on a read as long as its deadline;
* D. the panel stops a command SIGTERM first: through a stand-in sudo that relays (and one that is
     slow to), the stand-in root command ends; a member of the group that ignores SIGTERM still
     gets SIGKILL; and end to end, system_ops._run_verb's helper path leaves no process behind.

HOW IT RUNS. The stand-ins are Python scripts in this part's temp dir; each records its pid in the
directory it lives in. The stand-in sudo runs its command in a session of its own, so a signal to
the panel's process group cannot reach it -- as a root command under real sudo cannot be reached
from the panel's account -- and relays SIGTERM/SIGHUP to the command's pid only, as classic sudo
(exec_nopty.c) and sudo-rs (exec/no_pty.rs) do. Nothing here runs real sudo: the shell-form check
passes sudo=False, the helper path's argv is this part's own, and system_ops.os is geteuid-less
there (part16's _Os16(None)), so the shell branch could not prefix sudo either.
"""
import ast as _ast39
import os
import shlex
import shutil as _shutil39
import signal
import subprocess as _sp39  # nosec B404 - runs this part's own stand-in scripts
import sys
import tempfile as _tf39
import time as _time39
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part05 import _helper, _root
from unit.part20 import _patch, _patched
from panel.ops import system_ops as _so39
from panel.ops.debug_report import _src_journal as _sj39
from panel.ops.ssh_manager import _core as _core39
from panel.security import privileged as _priv39

_TMP39 = _tf39.mkdtemp(prefix="lgsm-unit-p39-")
_PY39 = sys.executable
_HELPER39 = os.path.join(_root, "tools", "panel-helper")
_SVC39 = "linuxgsm-panel.service"
# Read with a default throughout, so the code before this part's fixes FAILS the checks rather than
# crashing the run before the tally.
_SINCE39 = getattr(_priv39, "JOURNAL_SINCE", {})

# ── the stand-ins ────────────────────────────────────────────────────────────────────────────────
_FAKE_SUDO39 = '''
import os, signal, subprocess, sys, time
here = os.path.dirname(os.path.abspath(__file__))
open(os.path.join(here, "sudo.pid"), "w").write(str(os.getpid()))
delay = float(open(os.path.join(here, "relay_delay")).read()) if os.path.exists(
    os.path.join(here, "relay_delay")) else 0.0
p = subprocess.Popen(sys.argv[1:], start_new_session=True)
def relay(sig, _frame):
    time.sleep(delay)
    try:
        os.kill(p.pid, sig)
    except OSError:
        pass
signal.signal(signal.SIGTERM, relay)
signal.signal(signal.SIGHUP, relay)
rc = p.wait()
sys.exit(rc if rc >= 0 else 128 - rc)
'''
# A silent, long read (journalctl walking a big journal): records its pid, forks a grandchild
# unless --flat, ignores SIGTERM with --ignore-term (the grandchild alone with --gc-ignore-term),
# and waits. With --work it is a verb that CHANGES something instead: it finishes after a second
# and a half, says so, and leaves a marker.
_STANDIN39 = '''
import os, signal, sys, time
here = os.path.dirname(os.path.abspath(__file__))
if "--work" in sys.argv:
    open(os.path.join(here, "child.pid"), "w").write(str(os.getpid()))
    time.sleep(1.5)
    open(os.path.join(here, "work.done"), "w").write("done")
    print("restarted")
    sys.exit(0)
if "--ignore-term" in sys.argv:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if "--flat" not in sys.argv and os.fork() == 0:
    if "--gc-ignore-term" in sys.argv:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open(os.path.join(here, "grandchild.pid"), "w").write(str(os.getpid()))
    while True:
        time.sleep(0.05)
open(os.path.join(here, "child.pid"), "w").write(str(os.getpid()))
while True:
    time.sleep(0.05)
'''
# The real panel-helper, its run() as __main__ calls it, with the tools this verb resolves pointed
# at the stand-in and, when a `deadline` file says so, a shorter READ_DEADLINE (and
# LGSM_READ_DEADLINE). With an `actions` file, the actions it names (a streamed download) and
# lgsm-command's dropped half run the stand-in instead, with no argument checks: the real ones
# need a game account and root.
_HELPER_WRAP39 = '''
import importlib.machinery as m, importlib.util as u, os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
standin = os.path.join(here, "standin")
spec = u.spec_from_loader("ph39", m.SourceFileLoader("ph39", %r))
h = u.module_from_spec(spec)
spec.loader.exec_module(h)
for tool in ("journalctl", "systemctl"):
    h.TOOLS[tool] = (standin,)
if os.path.exists(os.path.join(here, "deadline")):
    h.READ_DEADLINE = h.LGSM_READ_DEADLINE = float(open(os.path.join(here, "deadline")).read())
if os.path.exists(os.path.join(here, "actions")):
    h.validate = lambda verb, args: list(args)
    for verb in open(os.path.join(here, "actions")).read().split():
        h.ACTIONS[verb] = lambda checked, content: subprocess.call([standin])
    def lgsm_child(*_a):
        open(os.path.join(here, "lgsmchild.pid"), "w").write(str(os.getpid()))
        return subprocess.call([standin])
    h._lgsm_child = lgsm_child
open(os.path.join(here, "helper.pid"), "w").write(str(os.getpid()))
sys.exit(getattr(h, "run", h.main)(["panel-helper"] + sys.argv[1:]))
'''


def _scenario39(name, standin_args=(), relay_delay=None, deadline=None, actions=()):
    """A fresh directory holding the stand-ins; returns it."""
    d = os.path.join(_TMP39, name)
    os.makedirs(d)
    with open(os.path.join(d, "fake_sudo.py"), "w") as fh:
        fh.write(_FAKE_SUDO39)
    with open(os.path.join(d, "helper_wrap.py"), "w") as fh:
        fh.write(_HELPER_WRAP39 % _HELPER39)
    standin = os.path.join(d, "standin")
    with open(standin, "w") as fh:
        # The helper hands the tool a fixed argv, so the stand-in's own switches are baked in.
        fh.write("#!%s\nimport sys\nsys.argv += %r\n%s" % (_PY39, list(standin_args), _STANDIN39))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(standin, 0o700)
    if relay_delay is not None:
        with open(os.path.join(d, "relay_delay"), "w") as fh:
            fh.write(str(relay_delay))
    if deadline is not None:
        with open(os.path.join(d, "deadline"), "w") as fh:
            fh.write(str(deadline))
    if actions:
        with open(os.path.join(d, "actions"), "w") as fh:
            fh.write(" ".join(actions))
    return d


_NAMES39 = ("sudo", "helper", "lgsmchild", "child", "grandchild")


def _pids39(d, names=_NAMES39):
    out = {}
    for n in names:
        try:
            with open(os.path.join(d, n + ".pid")) as fh:
                out[n] = int(fh.read())
        except (OSError, ValueError):
            pass
    return out


def _alive39(pid):
    """Running, and not a zombie waiting to be collected."""
    try:
        with open("/proc/%d/stat" % pid) as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def _until39(cond, timeout):
    end = _time39.monotonic() + timeout
    while _time39.monotonic() < end:
        if cond():
            return True
        _time39.sleep(0.05)
    return cond()


def _left39(d, names=_NAMES39, wait=4.0):
    """The scenario's processes still running after up to `wait` seconds: {name: pid}."""
    _until39(lambda: not any(_alive39(p) for p in _pids39(d, names).values()), wait)
    return {n: p for n, p in _pids39(d, names).items() if _alive39(p)}


def _sweep39(d):
    """SIGKILL whatever a scenario left running, so a failing check leaves no stand-in behind."""
    for pid in _pids39(d).values():
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _start39(d, verb_args):
    """Start the stand-in sudo -> the real helper -> the stand-in tool, as the panel starts it."""
    out = open(os.path.join(d, "out"), "wb")
    err = open(os.path.join(d, "err"), "wb")
    try:
        argv = [_PY39, os.path.join(d, "fake_sudo.py"), _PY39, os.path.join(d, "helper_wrap.py")]
        p = _sp39.Popen(argv + list(verb_args),  # nosec B603 - this part's own scripts
                        stdin=_sp39.DEVNULL, stdout=out, stderr=err, start_new_session=True)
    finally:
        out.close()
        err.close()
    return p


def _read39(d, name):
    try:
        with open(os.path.join(d, name), "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


# ════════════════════════════════════════════════════════════════════════════════════════════════
# A. the field-match sources read a fixed window forward
def _section_argv39():
    rows = []
    for src in ("panel-own", "panel-sudo"):
        helper = _helper.VERBS["journal"][1](_helper.validate("journal", [src, "5000"]))
        panel = _priv39.journal_argv(src, "5000")
        first_match = min([i for i, t in enumerate(panel) if "=" in t and not t.startswith("--")]
                          or [len(panel)])
        rows.append((src, helper == panel, "-n" not in panel,
                     ("--since=" + _SINCE39.get(src, "?")) in panel[:first_match],
                     "--lines=+5000" in panel[:first_match]))
    check("A journal: the field-match sources read a fixed window FORWARD (--since=<window> "
          "--lines=+N, options before the matches), never `-n N`, which walked the whole journal "
          "back when it held fewer than N matches; the helper and the panel build the same argv",
          rows and all(all(r[1:]) for r in rows), repr(rows))
    check("A journal: the windows are the panel's own output over 24 h and its sudo lines over 1 h",
          _SINCE39 == {"panel-own": "-24h", "panel-sudo": "-1h"}
          and getattr(_helper, "JOURNAL_SINCE", None) == _SINCE39, repr(_SINCE39))
    _section_sparse39()
    _section_argv_real39()


# Terms that are sparse ON THEIR OWN on any host: the panel's stdout identifier, the fields that
# name this unit or a coredump of it, and PRIORITY at critical or worse (err and warning are every
# public host's sshd and ufw noise).
_SPARSE39 = frozenset(["SYSLOG_IDENTIFIER=python", "PRIORITY=0", "PRIORITY=1", "PRIORITY=2",
                       "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1"]
                      + ["%s=%s" % (f, _SVC39) for f in (
                          "COREDUMP_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT", "USER_UNIT",
                          "COREDUMP_USER_UNIT", "OBJECT_SYSTEMD_USER_UNIT")])


def _dense_branches39(matches):
    """The OR'd branches of a journalctl match list with no field whose every value is sparse."""
    branches, cur = [], []
    for term in list(matches) + ["+"]:
        if term == "+":
            branches.append(cur)
            cur = []
        else:
            cur.append(term)
    bad = []
    for branch in branches:
        fields = {}
        for term in branch:
            fields.setdefault(term.split("=", 1)[0], set()).add(term)
        if not any(values <= _SPARSE39 for values in fields.values()):
            bad.append(branch)
    return bad


def _unit_programs39():
    """(the program of every unit install.sh writes, whether one sets SyslogIdentifier)."""
    with open(os.path.join(_root, "install.sh"), encoding="utf-8") as fh:
        text = fh.read()
    body = text[text.index("render_service_unit() {"):]
    body = body[:body.index("\n}\n")]
    progs = [ln.split("=", 1)[1].split()[0] for ln in body.splitlines() if ln.startswith("ExecStart=")]
    return progs, "SyslogIdentifier" in body


def _section_sparse39():
    sources = {"helper": _helper.JOURNAL_MATCHES["panel-own"],
               "privileged": _priv39.JOURNAL_MATCHES["panel-own"],
               "user unit": _sj39.user_unit_matches(1000)}
    bad = {k: _dense_branches39(v) for k, v in sources.items()}
    check("A journal: every OR'd branch of the panel's own read has a term that is sparse on its own "
          "-- the panel's stdout identifier, PRIORITY 0-2, a field naming the unit -- or journalctl "
          "re-walks that branch across the window once per line printed (2.6 s for one busy day's "
          "2,400 lines, 0.01 s with these terms)",
          not any(bad.values()) and all(len(v) >= 3 for v in sources.values()), repr(bad))
    progs, ident_set = _unit_programs39()
    ident = getattr(_priv39, "PANEL_IDENT", None)
    check("A journal: that identifier is what systemd names the panel unit's stdout lines -- the "
          "basename of the program in install.sh's ExecStart, for both unit layouts, none of which "
          "sets SyslogIdentifier -- and the helper and the panel agree on it",
          all((len(progs) == 2, ident is not None, getattr(_helper, "PANEL_IDENT", None) == ident,
               all(os.path.basename(pr) == ident for pr in progs), not ident_set)),
          repr((progs, ident, ident_set)))


def _section_argv_real39():
    jctl = _shutil39.which("journalctl")
    if not jctl:
        skip("A journal: a real journalctl accepts both sources' argv", "no journalctl here")
        return
    empty = os.path.join(_TMP39, "empty-journal")
    os.makedirs(empty)
    bad = []
    for src in ("panel-own", "panel-sudo"):
        argv = _priv39.journal_argv(src, "5000")
        r = _sp39.run([jctl, "--directory=" + empty] + argv[1:],  # nosec B603 - fixed argv
                      capture_output=True, text=True,
                      timeout=30, stdin=_sp39.DEVNULL)
        if r.returncode != 0 or "Failed" in r.stderr:
            bad.append((src, r.returncode, r.stderr.strip()[:200]))
    check("A journal: a real journalctl accepts both sources' argv (no 'Failed to parse')", not bad,
          repr(bad))
    _section_argv_journal39(jctl)


_REMOTE39 = "/usr/lib/systemd/systemd-journal-remote"


def _export39(entries):
    """Render (age seconds, fields) entries in journald's EXPORT format, oldest first (bytes).

    A value with a newline in it takes the format's binary form: the name, a newline, its length
    as 64-bit little-endian, the bytes, a newline.
    """
    now = _time39.time()
    out = []
    for i, (age, fields) in enumerate(sorted(entries, key=lambda e: -e[0])):
        out.append(("__REALTIME_TIMESTAMP=%d\n__MONOTONIC_TIMESTAMP=%d\n_BOOT_ID=%s\n"
                    "_MACHINE_ID=%s\n_HOSTNAME=p39\n" % (int((now - age) * 1e6), 1000000 + i,
                                                        "1" * 32, "2" * 32)).encode())
        for name, value in fields:
            data = value.encode()
            out.append(name.encode() + b"\n" + len(data).to_bytes(8, "little") + data + b"\n"
                       if b"\n" in data else b"%s=%s\n" % (name.encode(), data))
        out.append(b"\n")
    return b"".join(out)


def _own39(tag, unit=_SVC39):
    return [("_SYSTEMD_UNIT", unit), ("_TRANSPORT", "stdout"), ("SYSLOG_IDENTIFIER", "python"),
            ("PRIORITY", "6"), ("MESSAGE", "own line " + tag)]


def _sudo39(tag, priority="5", message="lgsmpanel : PWD=/ ; USER=root ; COMMAND=/x "):
    return [("_SYSTEMD_UNIT", _SVC39), ("_TRANSPORT", "syslog"), ("SYSLOG_IDENTIFIER", "sudo"),
            ("PRIORITY", priority), ("MESSAGE", message + tag)]


def _section_argv_journal39(jctl):
    if not os.access(_REMOTE39, os.X_OK):
        skip("A journal: on a real journal the windowed read returns nothing from outside its "
             "window, where `-n 5000` reached the oldest match there was",
             "no systemd-journal-remote here to build one")
        return
    d = os.path.join(_TMP39, "journal")
    os.makedirs(d)
    entries = [(30 * 86400, _own39("thirty-days")), (3 * 86400, _own39("three-days")),
               (7200, _own39("two-hours")), (600, _own39("ten-minutes")),
               (1800, _own39("tb\nTraceback (most recent call last):\n  File \"x.py\", line 1\n"
                             "ValueError: boom")),
               (1700, _own39("other unit", unit="hub.service")),
               (900, _sudo39("", "1", "lgsmpanel : a password is required ; USER=root ; COMMAND=/x")),
               (950, _sudo39("", "3", "pam_unix(sudo:auth): conversation failed"))]
    entries += [(age, _sudo39("s%d" % age)) for age in range(60, 40 * 86400, 3 * 3600)]
    r = _sp39.run([_REMOTE39, "-o", os.path.join(d, "p39.journal"), "-"],  # nosec B603 - fixed
                  input=_export39(entries), capture_output=True, timeout=60)

    def read(argv):
        return _sp39.run([jctl, "--directory=" + d] + argv[1:],  # nosec B603 - fixed argv
                         capture_output=True, text=True, timeout=30, stdin=_sp39.DEVNULL).stdout

    def lines(argv):
        return [ln.rsplit("own line ", 1)[-1] for ln in read(argv).splitlines() if "own line " in ln]
    own = _priv39.journal_argv("panel-own", "5000")
    walked = lines(["journalctl", "--no-pager", "-q", "-n", "5000"]
                   + list(_priv39.JOURNAL_MATCHES["panel-own"]))
    windowed = lines(own)
    full = lines(_priv39.journal_argv("panel-own", "1"))
    check("A journal: on a real journal the windowed read returns nothing from outside its window, "
          "where `-n 5000` reached the oldest match there was (it walks the whole journal back)",
          all((r.returncode == 0, walked == ["thirty-days", "three-days", "two-hours", "tb",
                                             "ten-minutes"],
               windowed == ["two-hours", "tb", "ten-minutes"])),
          repr((r.returncode, r.stderr[-200:], walked, windowed)))
    check("A journal: ...and `--lines=+N` keeps the OLDEST N of the window, which is why a read that "
          "comes back full gives way to the newest-N read", full == ["two-hours"], repr(full))
    _section_journal_terms39(read(own))


def _section_journal_terms39(out):
    got = _sj39.content_lines(out)
    continued = [ln for ln in got if ln[:1].isspace()]
    check("A journal: on a real journal the panel's own read keeps its stdout (a traceback's "
          "continuation lines printed indented, so entry_count counts 4 entries in 7 lines) and a "
          "refused sudo (alert), and leaves out the unit's err-level pam line and another unit's "
          "'python' stdout",
          all((len(got) == 7, _sj39.entry_count(got) == 4, len(continued) == 3,
               any("a password is required" in ln for ln in got),
               not any("conversation failed" in ln or "other unit" in ln for ln in got))),
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# B. the report's read: budget, a full window, the per-user and unprivileged reads, the wording
class _Clock39(object):
    """time for _src_journal, on a clock the stand-in reads advance by the time they were given."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def _helper_read39(answer):
    """Run _src_journal.read on a system install: (result, [(source, timeout)]).

    The helper is present and the user journal empty; every helper read is answered by
    answer(src, timeout, clock) -> (out, err, rc).
    """
    clock, calls = _Clock39(), []

    def _verb(verb, args=(), timeout=30, merge_stderr=True):
        calls.append((list(args)[0], round(timeout, 2)))
        return answer(list(args)[0], timeout, clock)
    with _patched():
        _patch(_sj39, "time", clock)
        _patch(_so39, "_debug_run", lambda argv, timeout=5, cap=None: ("", "No journal files were found.", 1))
        _patch(_so39, "_helper_present", lambda: True)
        _patch(_so39, "_run_verb", _verb)
        got = _sj39.read(5000, timeout=10)
    return got, calls


def _stamped39(prefix, n):
    return "\n".join("Oct 03 08:%02d:%02d h python[1]: %s %05d" % (i // 60 % 60, i % 60, prefix, i)
                     for i in range(n)) + "\n"


def _answer39(own, plain):
    """A helper stand-in: panel-own answers own(timeout, clock), panel `plain`, panel-sudo 3 lines."""
    def answer(src, timeout, clock):
        if src == "panel-own":
            return own(timeout, clock)
        return plain if src == "panel" else (_stamped39("sudo", 3), "", 0)
    return answer


def _spends_it_all39(timeout, clock):
    clock.now += timeout                           # it spends every second it is given
    return "", "Command timed out", -1


def _section_budget39():
    got, calls = _helper_read39(_answer39(_spends_it_all39, (_stamped39("plain", 10), "", 0)))
    own_t = [t for s, t in calls if s == "panel-own"]
    plain_t = [t for s, t in calls if s == "panel"]
    check("B budget: a filtered read that spends all it is given gets at most HALF the time left, so "
          "the plain read after it still has the rest (the VPS report's filtered read took the whole "
          "10 s, the plain read got 0.5 s, and the report had no journal)",
          all((own_t and own_t[0] <= 5.0, plain_t and plain_t[0] >= 4.5, got.get("source") == "helper",
               len(got.get("lines") or []) == 10)), repr(calls))

    _section_full39()


def _section_full39():
    oldest = (lambda timeout, clock: (_stamped39("oldest", 5000), "", 0))
    got, calls = _helper_read39(_answer39(oldest, (_stamped39("newest", 5000), "", 0)))
    check("B full: a filtered read that came back FULL (the oldest 5000 of its window, so the newest "
          "are past them) gives way to the plain read of the newest 5000",
          all((got.get("filtered") is False, (got.get("lines") or [""])[0].endswith("newest 00000"),
               [s for s, _ in calls][:2] == ["panel-own", "panel"])), repr((got.get("filtered"), calls)))

    got, _calls = _helper_read39(_answer39(oldest, ("", "", 1)))
    check("B full: ...and is still the answer when the plain read has nothing, marked cut (the "
          "window's oldest 5000, not its newest)",
          got.get("filtered") is True and len(got.get("lines") or []) == 5000 and got.get("cut") is True,
          repr((got.get("why"), got.get("cut"))))

    tracebacks = (lambda timeout, clock: (_tracebacks39(1500), "", 0))
    got, calls = _helper_read39(_answer39(tracebacks, (_stamped39("newest", 5000), "", 0)))
    check("B full: FULL counts ENTRIES, not lines: a window of 1500 entries, each a traceback that "
          "journalctl prints as 4 lines (6000 lines), is complete and stays the answer -- counted by "
          "lines it was taken for full and swapped for the newest 5000 lines, mostly sudo noise, on "
          "exactly the day the panel was logging errors",
          all((got.get("filtered") is True, len(got.get("lines") or []) == 6000,
               got.get("cut") is False, [s for s, _ in calls] == ["panel-own", "panel-sudo"])),
          repr((got.get("filtered"), len(got.get("lines") or []), calls)))


def _tracebacks39(n):
    """`n` journal entries as journalctl's short output prints them.

    Each is a 4-line traceback, its continuation lines indented under the message.
    """
    out = []
    for i in range(n):
        out.append("Oct 03 08:%02d:%02d h python[1]: ERROR own %05d" % (i // 60 % 60, i % 60, i))
        out.extend(" " * 32 + t for t in ("Traceback (most recent call last):",
                                          '  File "x.py", line 1, in f', "ValueError: boom"))
    return "\n".join(out) + "\n"


class _Os39(object):
    """os for _src_journal, as a non-root account (so no read here can reach sudo)."""

    def __getattr__(self, name):
        if name in ("geteuid", "getuid"):
            return lambda: 1000
        return getattr(os, name)


def _section_user_reads39():
    seen = []

    def _run(argv, timeout=5, cap=None):
        seen.append(list(argv))
        return "", "", 1                             # nothing anywhere: every read is tried
    with _patched():
        _patch(_so39, "_debug_run", _run)
        _patch(_so39, "_helper_present", lambda: False)
        _patch(_so39, "os", _Os39())
        _sj39.read(5000, timeout=10)
    filtered = [a for a in seen if "_TRANSPORT=stdout" in a]
    plain = [a for a in seen if "_TRANSPORT=stdout" not in a]
    check("B user reads: the per-user and the unprivileged system read are windowed the same way "
          "(--since=-24h --lines=+5000, no -n), and the plain reads after them keep -n 5000",
          len(filtered) == 2 and all(_windowed39(a, "-24h") for a in filtered)
          and len(plain) == 2 and all(_plain39(a) for a in plain), repr(seen))
    _section_user_sudo39()


def _windowed39(argv, since):
    return "--since=" + since in argv and "--lines=+5000" in argv and "-n" not in argv


def _plain39(argv):
    return "-n" in argv and argv[argv.index("-n") + 1] == "5000"


def _section_user_sudo39():
    sudo_seen = []

    def _run_sudo(argv, timeout=5, cap=None):
        sudo_seen.append(list(argv))
        if "SYSLOG_IDENTIFIER=sudo" in argv:
            return _stamped39("sudo", 3), "", 0
        return (_stamped39("own", 4), "", 0) if "--user" in argv else ("", "", 1)
    with _patched():
        _patch(_so39, "_debug_run", _run_sudo)
        _patch(_so39, "_helper_present", lambda: False)
        _patch(_so39, "os", _Os39())
        got = _sj39.read(5000, timeout=10)
    sudo_argv = [a for a in sudo_seen if "SYSLOG_IDENTIFIER=sudo" in a]
    check("B user reads: ...and the sudo read is the last hour's (--since=-1h --lines=+5000)",
          got.get("filtered") is True and len(sudo_argv) == 1 and _windowed39(sudo_argv[0], "-1h"),
          repr(sudo_argv))


def _report39(own, sudo, plain=None):
    """A whole debug report whose user-journal reads answer `own` and its sudo read `sudo`.

    The plain `--user -u` read answers `plain` when it is given, else `own` too. It is
    part34's _report34, on this part's own database: part34 removes its temp dir when it ends.
    """
    from flask import Flask
    from panel.db.models import db
    from unit.part20 import _env

    def _run(argv, timeout=5, cap=None):
        if "SYSLOG_IDENTIFIER=sudo" in argv:
            return sudo, "", 0
        if "--user" in argv:
            return (own if plain is None or "_TRANSPORT=stdout" in argv else plain), "", 0
        return ("yes\n", "", 0) if "timedatectl" in argv else ("", "", 1)
    app = Flask("p39-report")
    app.config.update(SECRET_KEY="p39r", SQLALCHEMY_TRACK_MODIFICATIONS=False,  # nosec B106 - test app
                      SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP39, "rep.db"))
    db.init_app(app)
    with _patched():
        _env(journal=own)
        _patch(_so39, "_debug_run", _run)
        with app.app_context():
            db.create_all()
            return _so39.generate_debug_report()["report"]


def _section_wording39():
    own = "\n".join(["Oct 03 08:%02d:00 livebox7731 python3[1]: panel line %s" % (i, chr(97 + i) * 3)
                     for i in range(20)]) + "\n"
    sudo = "\n".join("Oct 03 05:%02d:01 livebox7731 sudo[%d]:   ubuntu : PWD=/home/ubuntu ; USER=root ; "
                     "COMMAND=/usr/local/lib/linuxgsm-panel/panel-helper restart-flags" % (i, 3000 + i)
                     for i in range(3))
    rep = _report39(own, sudo)
    digest = rep.split("### Errors in the journal", 1)[-1].split("### Recent log", 1)[0]
    check("B wording: the report names the window it read — the panel's own output from the last 24 "
          "hours, its sudo lines from the last hour — and no longer calls them 'the last N lines'",
          all(("20 lines of the panel's own output from the last 24 hours" in digest,
               "sudo lines of the panel's unit from the last hour" in digest,
               "the newest" not in digest, "cut off" not in rep)), digest[:700])
    full = "\n".join("Oct 03 %02d:%02d:%02d livebox7731 python3[1]: panel line %05d"
                     % (i // 3600, i // 60 % 60, i % 60, i) for i in range(5000)) + "\n"
    rep = _report39(full, sudo, plain="")
    digest = rep.split("### Errors in the journal", 1)[-1].split("### Recent log", 1)[0]
    recent = rep.split("### Recent log", 1)[-1]
    words = "the oldest 5000 entries of the panel's own output from the last 24 hours (cut off"
    check("B wording: a window cut off at 5000 entries (the plain read had nothing) says so in both "
          "sections: its lines are the OLDEST of the last 24 hours, not the newest, so neither the "
          "Window line nor the Recent log may read as the panel's latest output",
          all((words in digest, words in recent.split("```", 1)[0],
               "5000 lines of the panel's own output" not in digest)),
          repr((digest[:500], recent[:500])))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# C. the helper ends a read's whole tree; a verb that changes the host runs to its end
def _helper_tree39(name, act, standin_args=(), deadline=None,
                   verb_args=("journal", "panel-own", "5000"), actions=()):
    """Start the tree (sudo, helper, tool, its child), wait for it, act(p): (left, d, p)."""
    d = _scenario39(name, standin_args, deadline=deadline, actions=actions)
    p = _start39(d, verb_args)
    # The stand-in sudo and the helper are waited for too: a tree started without its sudo still
    # passes the SIGTERM check (the signal then reaches the helper directly) and proves nothing.
    want = ("sudo", "helper", "child") + (
        () if "--flat" in standin_args or "--work" in standin_args else ("grandchild",)) + (
        ("lgsmchild",) if verb_args[0] == "lgsm-command" else ())
    try:
        up = _until39(lambda: all(n in _pids39(d) for n in want), 15)
        if up:
            act(p)
        left = _left39(d, wait=6.0) if up else {"tree": "never came up: " + _read39(d, "err")[-300:]}
        try:
            p.wait(timeout=10)
        except _sp39.TimeoutExpired:
            pass
        return left, d, p
    finally:
        _sweep39(d)
        if p.poll() is None:
            p.kill()
            p.wait()


def _section_helper_stop39():
    left, d, p = _helper_tree39("c-term", lambda p: os.kill(p.pid, signal.SIGTERM))
    check("C helper: a read whose caller gave up (SIGTERM to sudo, relayed to the helper) ends with "
          "its whole tree — the tool and the tool's own child — and says so in fixed words",
          all((left == {}, p.returncode == 143,
               "journal was stopped (signal 15): its caller gave up on it" in _read39(d, "err"))),
          repr((left, p.returncode, _read39(d, "err")[-300:])))
    left, d, p = _helper_tree39("c-kill", lambda p: os.kill(p.pid, signal.SIGKILL))
    check("C helper: a read whose sudo was SIGKILLed (nothing relayed: an older panel, or the "
          "panel's grace ran out) notices it lost its parent and ends its whole tree",
          left == {} and "journal lost its caller" in _read39(d, "err"),
          repr((left, _read39(d, "err")[-300:])))
    t0 = _time39.monotonic()
    left, d, p = _helper_tree39("c-deadline", lambda p: None, deadline=1.5)
    check("C helper: a read nobody signals still ends, tree and all, at its deadline (rc 124)",
          all((left == {}, p.returncode == 124, _time39.monotonic() - t0 < 12,
               "ran past its" in _read39(d, "err"))),
          repr((left, p.returncode, _read39(d, "err")[-300:])))
    left, d, p = _helper_tree39("c-gc-ignore", lambda p: os.kill(p.pid, signal.SIGTERM),
                                standin_args=("--gc-ignore-term",))
    check("C helper: a grandchild that ignores SIGTERM while its parent dies of it still gets "
          "SIGKILL -- by then it has been reparented away from the helper, so a fresh walk of the "
          "helper's tree no longer finds it, and it ran on as root",
          all((left == {}, p.returncode == 143)), repr((left, p.returncode, _read39(d, "err")[-300:])))
    _section_helper_lgsm39()
    _section_helper_work39()


def _section_helper_lgsm39():
    me = __import__("pwd").getpwuid(os.getuid()).pw_name
    left, d, p = _helper_tree39("c-lgsm-read", lambda p: os.kill(p.pid, signal.SIGTERM),
                                verb_args=("lgsm-command", me, "gmodserver", "details", "-", "no"),
                                actions=("lgsm-child",))
    check("C helper: lgsm-command with a LinuxGSM action that only reports (details) is a read: a "
          "relayed SIGTERM ends it and everything it started -- the child it forked to drop to the "
          "game account, LinuxGSM, and LinuxGSM's own children -- where the helper used to sit in "
          "an unbounded waitpid as root",
          all((left == {}, p.returncode == 143,
               "lgsm-command was stopped (signal 15)" in _read39(d, "err"))),
          repr((left, p.returncode, _read39(d, "err")[-300:])))
    left, d, p = _helper_tree39("c-lgsm-work", lambda p: os.kill(p.pid, signal.SIGTERM),
                                standin_args=("--work",),
                                verb_args=("lgsm-command", me, "gmodserver", "start", "-", "no"),
                                actions=("lgsm-child",))
    check("C helper: ...and with an action that changes something (start) it runs to its end",
          all((left == {}, p.returncode == 0, _read39(d, "work.done") == "done")),
          repr((left, p.returncode, _read39(d, "err")[-300:])))
    check("C helper: the LinuxGSM reads are exactly details, check-update and postdetails (not "
          "monitor, which restarts a crashed server), and their deadline outlasts every panel wait "
          "for one (the sync action's 60 s)",
          all((getattr(_helper, "LGSM_READ_ACTIONS", None) == {"details", "check-update", "postdetails"},
               getattr(_helper, "LGSM_READ_DEADLINE", 0) > max(_sync_action_timeouts39() or [999]))),
          repr((getattr(_helper, "LGSM_READ_ACTIONS", None), _sync_action_timeouts39())))


def _sync_action_timeouts39():
    """Every number server_detail._run_sync_action assigns to `timeout`: what it waits for one."""
    with open(os.path.join(_root, "panel", "routes", "server_detail.py"), encoding="utf-8") as fh:
        tree = _ast39.parse(fh.read())
    fns = [n for n in tree.body if getattr(n, "name", "") == "_run_sync_action"]
    sets = [a for fn in fns for a in _ast39.walk(fn) if _sets_timeout39(a)]
    return [c.value for a in sets for c in _ast39.walk(a.value) if _number39(c)]


def _sets_timeout39(node):
    """Whether `node` is an assignment to a name `timeout`."""
    targets = getattr(node, "targets", None) if isinstance(node, _ast39.Assign) else None
    return any(getattr(t, "id", "") == "timeout" for t in targets or ())


def _number39(node):
    return isinstance(node, _ast39.Constant) and isinstance(node.value, (int, float))


def _kill_sudo_later39(delay):
    """act(p): the panel's stop when the helper outlives its grace.

    SIGTERM to the stand-in sudo, then SIGKILL `delay` s later, so the helper loses its parent
    while its tool still runs.
    """
    def act(p):
        os.kill(p.pid, signal.SIGTERM)
        _time39.sleep(delay)
        os.kill(p.pid, signal.SIGKILL)
    return act


def _section_helper_work39():
    left, d, p = _helper_tree39("c-work", lambda p: os.kill(p.pid, signal.SIGTERM),
                                standin_args=("--work",), verb_args=("service-restart", "ssh"))
    check("C helper: a verb that CHANGES the host is not stopped by a SIGTERM: it runs to its end, "
          "its tool finishes, and its own answer still comes back (dying of the signal would have "
          "skipped any step after the tool)",
          all((left == {}, p.returncode == 0, _read39(d, "work.done") == "done",
               "restarted" in _read39(d, "out"))),
          repr((left, p.returncode, _read39(d, "out")[-200:], _read39(d, "err")[-300:])))
    left, d, p = _helper_tree39("c-work-orphan", _kill_sudo_later39(0.4), standin_args=("--work",),
                                verb_args=("service-restart", "ssh"))
    check("C helper: ...and keeps running when the sudo above it is SIGKILLed as well (the panel's "
          "stop once its grace runs out, for every writer that outlives it): its tool finishes and "
          "it never reports losing its caller -- a watch for a lost parent is for reads alone",
          all((left == {}, _read39(d, "work.done") == "done",
               "lost its caller" not in _read39(d, "err"))),
          repr((left, _read39(d, "err")[-300:])))
    _section_helper_sets39()


# The verbs that only read, by name: adding one to READ_VERBS (so it is ended when its caller gives
# up) has to be a decision made here as well, not a side effect.
_READ_VERBS39 = frozenset({
    "apt-any-running", "apt-upgrade-running", "content-game-present", "content-scan",
    "content-script-present", "crontab-list", "disk-free", "dpkg-lock-held", "f2b-log-lines",
    "f2b-status", "f2b-status-jail", "game-backup-read", "game-dir-tar", "game-file-read",
    "gmod-mount-read", "journal", "journal-cron", "lgsm-discover", "listening-sockets",
    "listening-sockets-owner", "log-tail", "os-update-log", "pro-status", "restart-flags",
    "sshd-effective-config", "sshd-socket-active", "sshd-validate", "ufw-status",
})


def _section_helper_sets39():
    reads = getattr(_helper, "READ_VERBS", frozenset())
    streamed = getattr(_helper, "STREAMED_READS", frozenset({""}))
    check("C helper: READ_VERBS is exactly the verbs that only read -- every other verb, everything "
          "that changes the host, runs to its end when its caller leaves -- all of them exist, and "
          "the streamed downloads are among them",
          all((reads == _READ_VERBS39, reads <= set(_helper.VERBS), streamed <= reads,
               streamed == {"game-backup-read", "game-dir-tar", "game-file-read"})),
          repr((sorted(reads ^ _READ_VERBS39), sorted(streamed))))
    left, d, p = _helper_tree39("c-stream", lambda p: None, standin_args=("--work",), deadline=0.2,
                                verb_args=("game-file-read", "gmodserver", "f"),
                                actions=("game-file-read",))
    check("C helper: a streamed download has NO deadline: it runs on past READ_DEADLINE to its end "
          "(a backup or a directory download takes as long as it takes; cut at the deadline it "
          "would answer 124, which the panel reads as a failed stream)",
          all((left == {}, p.returncode == 0, _read39(d, "work.done") == "done",
               "ran past" not in _read39(d, "err"))),
          repr((left, p.returncode, _read39(d, "err")[-300:])))
    _section_helper_main39()


def _section_helper_main39():
    seen = []

    class _Sp(object):
        TimeoutExpired = _sp39.TimeoutExpired

        @staticmethod
        def run(argv, **kw):
            seen.append((argv[1:2], kw.get("timeout")))
            return NS(stdout="", stderr="", returncode=0)
    with _patched():
        _patch(_helper, "subprocess", _Sp)
        _patch(_helper, "resolve", lambda prog: "/bin/true")
        _helper.main(["panel-helper", "journal", "panel", "5"])
        _helper.main(["panel-helper", "apt-update"])
    check("C helper: main() bounds a read's tool by READ_DEADLINE too (a few seconds after run()'s "
          "watch), and leaves a verb that changes the host its 30 minutes",
          [t for _a, t in seen] == [getattr(_helper, "READ_DEADLINE", 0) + 5, 1800], repr(seen))
    check("C helper: what sudo runs is run(), the stop rules around main() — the checks above call "
          "run() themselves, so this is what ties them to the installed entry point",
          _main_calls39() == ["_scrub_environ", "run"], repr(_main_calls39()))
    _section_read_timeouts39()


def _py_files39(top):
    for dirpath, _dirs, files in os.walk(top):
        yield from (os.path.join(dirpath, n) for n in files if n.endswith(".py"))


def _literal_timeout39(call):
    """A call's `timeout=` when it is a number written out, else None."""
    for k in call.keywords:
        if k.arg == "timeout" and isinstance(k.value, _ast39.Constant):
            return k.value.value if isinstance(k.value.value, (int, float)) else None
    return None


def _named_in39(call, names):
    """The string constants among `names` anywhere in a call's positional arguments."""
    return {c.value for a in call.args for c in _ast39.walk(a)
            if isinstance(c, _ast39.Constant) and c.value in names}


def _read_timeouts39():
    """(name, timeout, file, deadline) for every panel call that names a read with a literal timeout.

    A read is a READ verb or a LinuxGSM read action; `deadline` is what the helper gives it.
    """
    reads = getattr(_helper, "READ_VERBS", frozenset()) - getattr(_helper, "STREAMED_READS", frozenset())
    lgsm = getattr(_helper, "LGSM_READ_ACTIONS", frozenset())
    found = []
    for path in _py_files39(os.path.join(_root, "panel")):
        with open(path, encoding="utf-8") as fh:
            tree = _ast39.parse(fh.read())
        for call in (n for n in _ast39.walk(tree) if isinstance(n, _ast39.Call)):
            limit = _literal_timeout39(call)
            if limit is None:
                continue
            for name in _named_in39(call, reads | lgsm):
                found.append((name, limit, os.path.basename(path),
                              getattr(_helper, "LGSM_READ_DEADLINE" if name in lgsm
                                      else "READ_DEADLINE", 0)))
    return found


def _section_read_timeouts39():
    found = _read_timeouts39()
    over = [f for f in found if f[1] >= f[3]]
    check("C helper: no panel call waits on a read as long as the helper's deadline for it "
          "(READ_DEADLINE, or LGSM_READ_DEADLINE for a LinuxGSM read), so a read the helper ends at "
          "its deadline has no reader left (the helper's comment says so; this holds it)",
          len(found) >= 12 and not over and any(f[0] == "lgsm-discover" for f in found)
          and any(f[0] == "details" for f in found),
          repr((len(found), over)))


def _main_calls39():
    """The functions the helper's `if __name__ == "__main__":` block calls, in order."""
    with open(_HELPER39) as fh:
        tree = _ast39.parse(fh.read())
    for node in tree.body:
        if (isinstance(node, _ast39.If) and isinstance(node.test, _ast39.Compare)
                and getattr(node.test.left, "id", "") == "__name__"):
            return [c.func.id for c in _ast39.walk(node) if isinstance(c, _ast39.Call)
                    and isinstance(c.func, _ast39.Name)]
    return []


# ════════════════════════════════════════════════════════════════════════════════════════════════
# D. the panel stops a command SIGTERM first
def _shell_stop39(name, standin_args, relay_delay=None, via_sudo=True, chain=False, timeout=1):
    """Run the stand-in sudo -> stand-in, or the stand-in alone, through system_ops' shell form.

    sudo=False: nothing real is escalated. `chain` adds a second command, so the shell forks
    instead of exec'ing and is the process the panel started, with sudo below it in its group.
    """
    d = _scenario39(name, standin_args, relay_delay=relay_delay)
    argv = ([_PY39, os.path.join(d, "fake_sudo.py")] if via_sudo else []) + [os.path.join(d, "standin")]
    cmd = " ".join(shlex.quote(a) for a in argv) + ("; true" if chain else "")
    t0 = _time39.monotonic()
    try:
        res = _so39._run_verb_shell(cmd, timeout=timeout, sudo=False)
        took = _time39.monotonic() - t0
        return res, took, _left39(d, ("sudo", "child"), wait=4.0), d
    finally:
        _sweep39(d)


def _section_panel_stop39():
    res, took, left, _d = _shell_stop39("d-shell", ("--flat",))
    check("D panel: a command it gives up on gets SIGTERM first, which sudo relays, so the root "
          "command under it ends (a SIGKILL to sudo's group reached sudo alone and orphaned it)",
          all((res == ("", "Command timed out", -1), left == {})), repr((res, round(took, 2), left)))
    res, took, left, _d = _shell_stop39("d-slow-relay", ("--flat",), relay_delay=0.6, chain=True)
    check("D panel: ...and it waits for the GROUP, not just the shell it started: a sudo slow to "
          "relay is not SIGKILLed the moment the shell above it exits",
          left == {}, repr((res, round(took, 2), left)))
    res, took, left, _d = _shell_stop39("d-ignore", ("--flat", "--ignore-term"), via_sudo=False)
    check("D panel: a process of its own that ignores SIGTERM still gets SIGKILL, and the answer "
          "comes within the timeout plus the two graces",
          all((res[2] == -1, left == {},
               took < 1 + getattr(_core39, "_TERM_GRACE", 2.0) + _core39._KILL_GRACE + 2.5)),
          repr((res, round(took, 2), left)))
    _section_panel_paths39()


def _section_panel_paths39():
    d = _scenario39("d-tpool", ("--flat",))
    try:
        res = _core39._exec_local_argv([_PY39, os.path.join(d, "fake_sudo.py"),
                                        os.path.join(d, "standin")], timeout=1)
        left = _left39(d, ("sudo", "child"), wait=4.0)
    finally:
        _sweep39(d)
    check("D panel: the same through the native-thread path (ssh_manager's local argv runner)",
          res[2] == -1 and left == {}, repr((res, left)))
    green = _sp39.Popen([_PY39, "-c", "pass"])  # nosec B603 - a no-op child of this interpreter
    green.wait()
    real = _core39._real_subprocess.Popen([_PY39, "-c", "pass"])  # nosec B603 - the same
    real.wait()
    real_cls = getattr(_core39, "_REAL_POPEN", None)
    patched = real_cls is not None and green.__class__ is not real_cls
    pause = getattr(_core39, "_pause_for", lambda p: None)
    real_sleep = getattr(getattr(_core39, "_real_time", None), "sleep", None)
    check("D panel: the stop's pause yields to the hub beside eventlet's Popen and sleeps the thread "
          "beside the unpatched one (tpool), never the other way round",
          all((real_sleep is not None, real.__class__ is real_cls, pause(real) is real_sleep,
               (pause(green) is _core39.time.sleep and pause(green) is not real_sleep)
               if patched else True)),
          repr((patched, type(green), type(real), pause(green), pause(real))))
    _section_end_to_end39()


class _NoEuid39(object):
    """os without geteuid (part16's _Os16(None)).

    system_ops._run_verb's shell branch then never prefixes `sudo`, so a check that reaches it by
    mistake cannot run the real one.
    """

    def __getattr__(self, name):
        if name == "geteuid":
            raise AttributeError(name)
        return getattr(os, name)


def _section_end_to_end39():
    d = _scenario39("d-e2e", ())
    wrap = [_PY39, os.path.join(d, "fake_sudo.py"), _PY39, os.path.join(d, "helper_wrap.py")]
    guarded = []

    def _argv(verb, args):
        guarded.append(not hasattr(_so39.os, "geteuid"))
        return wrap + [verb] + list(args)
    try:
        with _patched():
            _patch(_so39, "os", _NoEuid39())
            _patch(_so39, "_helper_present", lambda: True)
            _patch(_priv39, "helper_argv", _argv)
            res = _so39._run_verb("journal", ["panel-own", "5000"], timeout=1, merge_stderr=False)
        left = _left39(d, wait=6.0)
        seen = _pids39(d)
    finally:
        _sweep39(d)
    check("D end to end: system_ops._run_verb's helper path, given up on after 1 s, leaves no process "
          "behind — not sudo, not the helper, not its journalctl, not that one's child",
          all((res == ("", "Command timed out", -1), left == {},
               set(seen) == {"sudo", "helper", "child", "grandchild"})), repr((res, seen, left)))
    check("D end to end: ...run with system_ops.os stubbed geteuid-less, so had the helper patch "
          "missed, the shell branch it fell into could never have prefixed a real sudo",
          guarded == [True], repr(guarded))


def _guarded39(section):
    """Run one section; one that raises fails a check of its own instead of ending the run.

    The code before these fixes lacks names the sections read, and an exception would end the run
    before the tally.
    """
    try:
        section()
    except Exception as e:  # noqa: BLE001 - recorded as a failure, never swallowed
        check("part39: %s ran to its end" % section.__name__, False, "%s: %s" % (type(e).__name__, e))


try:
    for _section39 in (_section_argv39, _section_budget39, _section_user_reads39, _section_wording39,
                       _section_helper_stop39, _section_panel_stop39):
        _guarded39(_section39)
finally:
    _shutil39.rmtree(_TMP39, ignore_errors=True)
