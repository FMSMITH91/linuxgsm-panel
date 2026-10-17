#!/usr/bin/env python3
"""Fast unit tests for the pure-logic helpers — no network, no SSH, no live DB.

This file is the RUNNER. The checks live in tests/unit/part*.py, imported in _PARTS order;
each part is ordinary module-level code that records results as it is imported, exactly as it did
when this was one 6,966-line file. No check and no ordering changed: the parts were cut at
top-level statement boundaries, and the chunks were proved to reconstruct the original
byte-for-byte before anything moved.

WHY THE PARTS IMPORT FROM EACH OTHER. The suite is a narrative — earlier sections build fixtures
later ones use (`check` and `results` themselves, the scanned module lists, the privileged helper).
Each part imports what it needs from the parts before it, nothing imports backwards, so the import
order below IS the execution order, and it is the order the single file had.

WHY THE TALLY IS HERE AND NOT IN A PART. `passed` must be counted after every part has run. Left
in the last part it would have counted only the checks recorded up to that point — a smaller total,
still exiting 0. A suite quietly reporting fewer checks than it has is the exact failure this suite
exists to catch, so it is not allowed to be the shape of the suite itself.

    python tests/unit_test.py      # exits 0 if all pass, 1 otherwise
"""
import functools
import glob
import importlib
import os
import re
import sys

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
# tests/ on the path too, so `unit.partNN` resolves whichever directory this is run from.
sys.path.insert(0, os.path.join(_root, "tests"))

# ── nothing in this suite may read or write the machine's own config.json (or its keys) ─────────
# DATA_DIR is a fixed path inside the checkout, so a unit check that reached panel.core.config
# without redirecting it first read — or wrote — the data/ of whatever panel runs from this
# checkout. The gate that was meant to stop that read each part's TEXT: it counted only direct
# load_config()/save_config() calls and exempted a whole file that mentioned `CONFIG_FILE =`
# anywhere, so part01 rewrote data/config.json seven times BEFORE its redirect and was exempt
# because of it, and 26 other lines read it through panel helpers (_ssh_connect_timeout,
# create_backup, the PrefixMiddleware...) with no direct call at all. Green, the whole time, on a
# suite whose answers depended on the machine it ran on.
#
# So both halves are done at RUNTIME, here, before any part or panel module is imported:
#   1. the three paths are pointed at a throwaway dir for the whole run — every indirect read now
#      sees a fresh install's absent config, the same on a dev box as in CI; and
#   2. every entry point is wrapped (a module that does `from panel.core.config import
#      load_config` then holds the wrapper too), and a call made while a path resolves to the
#      checkout's own file — a check that pointed it back, or a runner that lost step 1 — is
#      recorded with the test line that led to it, and fails the run below.
import shlex  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402

# ── every temp dir or file a part makes with tempfile goes at the end of the run ─────────────────
# Parts make them by the hundred, and dozens were never removed (review 1011e: one run left ~20 in
# /tmp, part24's holding audit rows with addresses). Fixing each by hand is the fixed-list shape
# the gates here keep being burnt by, so the runner records every mkdtemp()/mkstemp() a part makes
# and removes what is left once the tally is printed. Recorded, not relocated: a private TMPDIR
# would change ownership and modes under checks that run tools as other accounts on CI's root leg.
_r15d_made_tmp = []
_r15d_mkdtemp, _r15d_mkstemp = tempfile.mkdtemp, tempfile.mkstemp


@functools.wraps(_r15d_mkdtemp)
def _r15d_tracked_mkdtemp(*a, **k):
    _p = _r15d_mkdtemp(*a, **k)
    _r15d_made_tmp.append(_p)
    return _p


@functools.wraps(_r15d_mkstemp)
def _r15d_tracked_mkstemp(*a, **k):
    _fd, _p = _r15d_mkstemp(*a, **k)
    # mkstemp makes its file through _mkstemp_inner, which is tracked below and has recorded it
    # already: recorded once, so the "N of M left" count is of paths, not of records.
    if not _r15d_made_tmp or _r15d_made_tmp[-1] != _p:
        _r15d_made_tmp.append(_p)
    return _fd, _p


# NamedTemporaryFile(delete=False) makes its file through tempfile's private _mkstemp_inner, not
# mkstemp, so its leftovers went unrecorded (review 1012a): that is recorded too. A shell `mktemp`
# in a script a part runs is outside all of this; those parts point TMPDIR at their own sandbox.
_r16d_mkstemp_inner = tempfile._mkstemp_inner


@functools.wraps(_r16d_mkstemp_inner)
def _r16d_tracked_mkstemp_inner(*a, **k):
    _fd, _p = _r16d_mkstemp_inner(*a, **k)
    _r15d_made_tmp.append(_p)
    return _fd, _p


tempfile.mkdtemp, tempfile.mkstemp = _r15d_tracked_mkdtemp, _r15d_tracked_mkstemp
tempfile._mkstemp_inner = _r16d_tracked_mkstemp_inner


def _r15d_remove_made_tmp():
    """Remove what is left of every recorded temp path; the paths that would not go."""
    return _r16d_remove_paths(_r15d_made_tmp)


def _r16d_remove_paths(paths):
    """Remove each of `paths` (a directory with all it holds); the paths that would not go."""
    for _p in paths:
        if os.path.isdir(_p) and not os.path.islink(_p):
            # A check that made a directory unwritable (to test a refusal) would stop rmtree. That
            # includes the recorded directory itself: part06's TMPDIR stand-in is mode 0o200, which
            # os.walk cannot list, so it never reaches the loop below.
            # 0o700 is owner-only, on the suite's own temp dir, so rmtree can enter it.
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(_p, 0o700)
            for _dp, _dns, _fns in os.walk(_p):
                for _d in _dns:
                    if not os.path.islink(os.path.join(_dp, _d)):
                        # 0o700 is owner-only, on the suite's own temp dir, so rmtree can enter it.
                        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                        os.chmod(os.path.join(_dp, _d), 0o700)
            shutil.rmtree(_p, ignore_errors=True)   # what would not go is named below
        elif os.path.lexists(_p):
            os.unlink(_p)
    return [_p for _p in paths if os.path.lexists(_p)]


import unit as _unit_pkg  # noqa: E402
from panel.core import config as _cfg_live  # noqa: E402

_WATCHED = {"CONFIG_FILE": ("load_config", "save_config", "update_config", "config_unreadable"),
            "SECRET_FILE": ("get_secret_key",),
            "CRED_KEY_FILE": ("_cred_fernet",)}
# The checkout's own paths, for the one part01 check that asserts where they resolve.
_unit_pkg.LIVE_PATHS = {_n: getattr(_cfg_live, _n) for _n in _WATCHED}
_LIVE_REAL = {_n: os.path.realpath(str(_p)) for _n, _p in _unit_pkg.LIVE_PATHS.items()}
_RUN_DATA = tempfile.mkdtemp(prefix="lgsm-unit-data-")
for _n, _p in _unit_pkg.LIVE_PATHS.items():
    setattr(_cfg_live, _n, type(_p)(_RUN_DATA) / _p.name)
_TESTS_DIR = os.path.join(_root, "tests") + os.sep
_config_touches = []


def _watch(attr, fn):
    @functools.wraps(fn)
    def _watched(*a, **k):
        if os.path.realpath(str(getattr(_cfg_live, attr))) == _LIVE_REAL[attr]:
            f = sys._getframe(1)
            while f is not None and not f.f_code.co_filename.startswith(_TESTS_DIR):
                f = f.f_back
            _config_touches.append("%s from %s" % (
                fn.__name__, "%s:%d" % (os.path.relpath(f.f_code.co_filename, _root), f.f_lineno)
                if f is not None else "outside tests/"))
        return fn(*a, **k)
    return _watched


for _attr, _fns in _WATCHED.items():
    for _fn in _fns:
        setattr(_cfg_live, _fn, _watch(_attr, getattr(_cfg_live, _fn)))

# ── nothing in this suite runs the machine's own `tailscale` ─────────────────────────────────────
# Every page render reads Tailscale state for the nav (inject_globals), and a cold or 15 s-old
# cache runs `tailscale version/status/debug prefs/serve status`. CI's runner has no tailscale, so
# there those fail "not found"; a dev box that has it read its real node into the renders of six
# parts (review 1011e), checks passing on what that node said. So the run answers the system
# binary exactly as CI does — not installed — while a part's own stand-in `tailscale` on a PATH it
# set (part32's fake, part54) still runs.
# Three handles reach it, not one: tailscale_integration's argv calls; system_ops' shell `_run`
# (`tailscale status --json`, `debug prefs`, and `set --ssh`, a WRITE to the node, behind every
# /server-management render); and _core's local transport, whose bash runs `tailscale status`
# and `which tailscale` for the panel host. A shell can set its own PATH before it calls tailscale
# (part05's secret rendering puts a stand-in first), so a shell is not judged from outside: a
# `tailscale` and a `which` make the same call at the moment of use. In the shell it was given,
# from a shim directory first on its PATH (_R26D_SHIM); under bash with them as functions where
# the shim cannot hold (a shell behind a wrapper, a script that sets its own PATH).
# Imported here, before any part, so its handle is wrapped before anything can call it.
importlib.import_module("panel.ops.tailscale_integration")

# What a part's own stand-in IS, rather than where the machine's might be (review 1012d): a list of
# system directories had to grow by one home-relative path a round (~/.local/bin, ~/.linuxbrew), and
# a CLI copied to ~/bin (first on Ubuntu's default PATH) or `go install`ed to ~/go/bin still ran for
# real. Every stand-in a part writes is in this run's temp area (mkdtemp) or under tests/, so a
# `tailscale` found AND resolved under one of those is a stand-in, and anything else is the
# machine's. Both spellings of each root, since a found path is judged before it is resolved.
_R19D_STAND_IN_ROOTS = tuple(sorted({_p + os.sep for _d in (tempfile.gettempdir(), _TESTS_DIR)
                                     for _p in (os.path.abspath(_d), os.path.realpath(_d))}))
# Where a command that clears or resets PATH (`env -i`, sudo's secure_path) looks for a program.
_R19D_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
# A shell that may BUILD the name (`T=tail; ${T}scale`) but does not name it keeps the shell it was
# given, and gets this directory first on its PATH instead: a `tailscale` and a `which` that make
# the functions' found-and-resolved test at the moment of use, in any shell (review 1016c: such a
# script was rerouted to bash for the functions, so nearly every `$`-holding system_ops command ran
# under bash where production runs it under /bin/sh, and a bashism in one would have passed here).
# A `command -v` of a built name finds the shim, as the bash route's finds the function. A shell
# behind a wrapper (env -i, sudo, runuser) keeps the bash route: its PATH is the wrapper's to set.
_R26D_SHIM = tempfile.mkdtemp(prefix="lgsm-unit-ts-shim-")
# What keeps a script off the shim route: PATH set, appended, exported, unset or defaulted by the
# script itself, `command -p`, and `hash`, which can point the name at any file.
_R28D_PATH_OWN = re.compile(r"(?<![\w${])PATH\b|\$\{PATH:?=|\bcommand\s+(?:-\w+\s+)*-\w*p|\bhash\b")
# A login shell: its profile sets PATH (Debian's /etc/profile resets it, ~/.profile prepends ~/bin).
# An interactive one (`bash -ic`) reads ~/.bashrc, which can set it as well; an option's value
# (`bash -O extglob -l`) is skipped, and `exec -l` hands any shell a login name (review 1017a).
_R29D_LOGIN = re.compile(r"(?:^|[\s;&|(`/'\"])(?:ba|da|z|k|mk)?sh\s+(?:[-+][oO]\s+\w+\s+|[-+]\w+\s+)*"
                         r"(?:-[a-zA-Z]*[il][a-zA-Z]*|--login|--interactive)\b"
                         r"|\bexec\s+(?:-a\s+\S+\s+|-\w+\s+)*-\w*l\w*\s")
# The `.` builtin, where a command starts (review 1017a: any ` . ` word counted, so `find . -name x`
# read as sourcing a file, moved its script off the shell production runs it under, and a wrapper
# handed `find . …` was judged as possibly running the binary).
_R30D_SOURCE_DOT = (r"(?:^|[;&|(){!\n]|\b(?:then|do|else|if|elif|while|until|time|builtin|command))"
                    r"[ \t]*\.[ \t]+[^\s;&|]")
# A sourced or eval'd text, which can set any name the script reads.
_R30D_SETS_ANY = re.compile(r"\beval\b|\bsource\b|" + _R30D_SOURCE_DOT)
# ...and what else can set it unseen (review 1016f): a sourced or eval'd text, a nested login shell.
_R29D_SHIM_OFF = re.compile(_R30D_SETS_ANY.pattern + "|" + _R29D_LOGIN.pattern)
# A nested shell, bash too, handed a -c script (review 1017a: `bash -c "${P}TH=<d>; tailscale"`
# builds the name PATH only when the inner shell runs, where no reader of the outer text sees it).
_R30D_NESTED_C = re.compile(r"(?:^|[\s;&|(`/'\"])(?:(?:ba|da|z|k|mk)?sh|busybox\s+sh)\s+(?:[-+]\w+\s+)*"
                            r"-\w*c\w*\s+('[^']*'|\"[^\"]*\"|[^\s;&|]+)")
# Builtins that take a variable NAME as a word (`export 'PATH=…'`, `read ${P}TH`): one handed a
# quoted or built name may be setting PATH. printf names it only after -v.
_R29D_NAME_BUILTINS = ("export", "declare", "typeset", "readonly", "local", "read", "mapfile", "readarray",
                       "getopts", "unset")
_R26D_SHIM_JUDGE = r'''
_r26d_standin() {
  case "$1" in /*) _r26d_f=$1;; *) _r26d_f=$PWD/$1;; esac
  _r26d_r=$(readlink -f "$_r26d_f" 2>/dev/null) || return 1
  _r26d_a=; _r26d_b=; _r26d_ifs=$IFS; IFS=:; set -f
  for _r26d_x in $R26D_TS_ROOTS; do
    case "$_r26d_f" in "$_r26d_x"*) _r26d_a=1;; esac
    case "$_r26d_r" in "$_r26d_x"*) _r26d_b=1;; esac
  done
  IFS=$_r26d_ifs; set +f
  [ -n "$_r26d_a" ] && [ -n "$_r26d_b" ]
}
_r26d_path() {
  _r26d_p=; _r26d_ifs=$IFS; IFS=:; set -f
  for _r26d_x in $PATH; do [ "$_r26d_x" = "@SHIM@" ] || _r26d_p=${_r26d_p:+$_r26d_p:}$_r26d_x; done
  IFS=$_r26d_ifs; set +f
}
_r26d_first() {
  _r26d_path; _r26d_ifs=$IFS; IFS=:; set -f
  for _r26d_x in $_r26d_p; do
    [ -n "$_r26d_x" ] || _r26d_x=.
    if [ -f "$_r26d_x/tailscale" ] && [ -x "$_r26d_x/tailscale" ]; then echo "$_r26d_x/tailscale"; return 0; fi
  done
  return 1
}
'''.replace("@SHIM@", _R26D_SHIM)
_R26D_SHIM_FILES = {
    "tailscale": ('_r26d_t=$(_r26d_first) && _r26d_standin "$_r26d_t" && exec "$_r26d_t" "$@"\n'
                  'echo "tailscale: command not found" >&2\nexit 127\n'),
    "which": ('_r26d_path\n'
              'case " $* " in *" tailscale "*)\n'
              '  if _r26d_t=$(_r26d_first) && ! _r26d_standin "$_r26d_t"; then exit 1; fi\n'
              '  _r26d_o=$(PATH=$_r26d_p; export PATH; which "$@"); _r26d_s=$?\n'
              '  [ -n "$_r26d_o" ] && printf "%s\\n" "$_r26d_o" | while IFS= read -r _r26d_w; do\n'
              '    case "$_r26d_w" in */tailscale) ! _r26d_standin "$_r26d_w" || echo "$_r26d_w";;'
              ' *) echo "$_r26d_w";; esac\n'
              '  done\n  exit "$_r26d_s";;\nesac\n'
              'PATH=$_r26d_p; export PATH; exec which "$@"\n')}
for _r26d_n, _r26d_body in _R26D_SHIM_FILES.items():
    with open(os.path.join(_R26D_SHIM, _r26d_n), "w", encoding="utf-8") as _r26d_fh:
        _r26d_fh.write("#!/bin/sh\n# The unit suite's tailscale guard (tests/unit_test.py, _R26D_SHIM).\n"
                       + _R26D_SHIM_JUDGE + _r26d_body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this runner runs itself
    os.chmod(os.path.join(_R26D_SHIM, _r26d_n), 0o700)  # nosec B103 - a stand-in in a private temp dir
# The machine's own tailscale, looked up before any part has planted a stand-in: if a root holds it
# (TMPDIR=~/.local puts ~/.local/bin/tailscale under one), it reads as a stand-in and runs. Holding
# a home or a system directory was gated; a root inside the home that holds a PATH directory was
# not (review 1015a).
_r21d_ts_at_start = [shutil.which("tailscale", path=_p)
                     for _p in (os.environ.get("PATH", os.defpath), _R19D_DEFAULT_PATH)]
_r15d_ts_refused = []
# What would really start a process. A part that stands in for subprocess.run itself (part44's
# TimeoutExpired raiser) is answered by its stand-in, not by this: it starts nothing. The green
# Popen counts as real: eventlet.monkey_patch() (part01's app import) puts it on the module, and
# comparing against the pre-patch class alone let every Popen through from part01 on.
_R15D_SP_REAL = {"run": sys.modules["subprocess"].run, "Popen": sys.modules["subprocess"].Popen}


def _r16d_real_spawners(how):
    """Every object that, called as subprocess.<how>, really starts a process in this run."""
    _reals = {_R15D_SP_REAL[how]}
    for _m in ("eventlet.green.subprocess", "__original_module_subprocess"):
        _reals.add(getattr(sys.modules.get(_m), how, None))
    _reals.discard(None)
    return _reals


def _r16d_shell_text(cmd, kw):
    """The shell source `cmd` runs, or None when it is not a shell command."""
    if kw.get("shell"):
        # A list with shell=True runs its first item as the script (review 1012b: it was not read).
        _first = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else cmd
        return _first if isinstance(_first, str) else None
    return _r17d_dash_c_script(cmd) if isinstance(cmd, (list, tuple)) else None


def _r17d_dash_c_script(argv):
    """The script of `[sh|bash|dash, -c, script]`; -c grouped with other letters (`bash -lc`) too."""
    return _r18d_dash_c(argv)[1]


def _r18d_dash_c(argv):
    """(index of the shell word, its -c script) for an argv that runs a shell script, else (None, None).

    -c was read only as argv[1] (review 1012c): `bash -e -c s`, `bash -o pipefail -c s` and
    `env bash -c s` ran their script with no guard. Options are read as the shell reads them: the
    script is the first word that is not an option, -o/-O and --rcfile/--init-file take a value,
    and the shell may come after wrapper commands (_r19d_unwrap).
    """
    _i = _r18d_shell_word(argv)
    if _i is None:
        return None, None
    _c, _j = _r18d_shell_opts(argv, _i + 1)
    if _c and _j < len(argv) and isinstance(argv[_j], str):
        return _i, argv[_j]
    return None, None


def _r18d_shell_word(argv):
    """Index of the shell word: argv[0], or the word after the wrapper commands in front of it.

    Under every reading of the long options that only prefix a value-taking one (_r25d_readings;
    review 1016b: only "each takes a value" was tried, so `setsid --f bash -c …`, --f being
    setsid's --fork and a prefix of --format, hid the shell and it ran without the functions).
    """
    for _pv in _r25d_readings(argv):
        _i = _r19d_unwrap(argv, None, _pv)[0]
        if _i < len(argv) and os.path.basename(str(argv[_i])) in ("sh", "bash", "dash"):
            return _i
    return None


def _r25d_readings(argv):
    """Each way to read argv's ambiguous long options: the set of their indices that take a value.

    An ambiguous one is a prefix of a value-taking name (`--f` of --format) that may be a flag of
    the wrapper it follows (setsid's --fork, timeout's --foreground). Reading them all one way or
    all the other missed an argv needing both (review 1016b: `timeout --f --sig KILL 5 tailscale`
    and `xargs --in --arg /dev/null tailscale` were judged as running nothing). Few enough to try
    every combination; past eight, the two uniform readings.
    """
    _amb = [_k for _k, _a in enumerate(argv) if isinstance(_a, str) and "=" not in _a
            and _a not in _R19D_LONG_VALUE and _r23d_long_prefix(_a, _R19D_LONG_VALUE)]
    if len(_amb) > 8:
        return [frozenset(_amb), frozenset()]
    return [frozenset(_k for _b, _k in enumerate(_amb) if _n >> _b & 1) for _n in range(2 ** len(_amb))]


# Commands that run the rest of their argv as a command: (short options taking a value, operands
# before the command). Only `env VAR=x` was read (review 1012d): `env -i bash -c …`, `timeout 5
# tailscale …`, `nice`, `setsid` and `sudo` hid the shell or the binary from the guard.
# The argv form knew 8 of them while the script form's pattern named 20 (review 1013a: `taskset 1
# tailscale`, `flock /x tailscale` and `xargs bash -c …` ran the machine's binary), so the script
# pattern is now built from this table plus the shell-only words, and the two cannot disagree.
_R19D_WRAPPERS = {"env": ("uCSa", 0), "timeout": ("sk", 1), "nice": ("n", 0), "nohup": ("", 0),
                  "setsid": ("", 0), "stdbuf": ("ioe", 0), "ionice": ("cnpPu", 0),
                  "sudo": ("ugCDhprtTU", 0), "doas": ("aCu", 0), "runuser": ("ugGcsw", 0),
                  "su": ("cgGsw", 0), "xargs": ("adEILnPs", 0), "chrt": ("TPD", 1), "taskset": ("", 1),
                  "flock": ("wEc", 1), "time": ("fo", 0), "watch": ("n", 0)}
# Wrappers that reset PATH for the command they run: it is found on the default PATH.
_R20D_PATH_RESETS = ("sudo", "doas", "runuser", "su")
# Words only a script has (shell builtins, a nested shell that does not read bash's exported
# functions, and commands that run another): judged in a script, never an argv wrapper.
_R20D_SCRIPT_ONLY = ("command", "exec", "builtin", "type", "hash", "whereis", "sh", "dash", "zsh", "ksh",
                     "mksh", "busybox", "awk", "find")
# Long options of those that take their value as the next word.
_R19D_LONG_VALUE = {"--unset", "--chdir", "--argv0", "--split-string", "--signal", "--kill-after", "--adjustment",
                    "--input", "--output", "--error", "--class", "--classdata", "--pid", "--pgid", "--uid",
                    "--user", "--group", "--close-from", "--chroot", "--host", "--prompt", "--role",
                    "--type", "--other-user", "--command-timeout", "--command", "--shell", "--supp-group",
                    "--whitelist-environment", "--arg-file", "--delimiter", "--eof", "--replace",
                    "--max-lines", "--max-args", "--max-procs", "--max-chars", "--timeout",
                    "--conflict-exit-code", "--format", "--interval", "--sched-runtime", "--sched-period",
                    "--sched-deadline"}
# Options whose VALUE is a command line (`env -S 'tailscale up'`, `su -c`, `runuser -c`, `flock
# -c`): the program inside is never the next argv word, so such a value is judged by the words it
# names (review 1013a).
# The short letters of those, read anywhere in a cluster and with the value attached or in the next
# word, as getopt reads them (review 1015a: only the exact words above were, so `env -Stailscale`,
# `env -vS tailscale`, `zsh -ec tailscale` and `su -lc tailscale` ran the machine's binary).
_R21D_CMDLINE_LETTERS = "Sc"
# The long ones, read as getopt_long reads them: also by an unambiguous prefix (`--split-str=`,
# `--comm x`), and su/runuser's --session-command (review 1015c: only the exact `--split-string=`
# and `--command=` were, so `env --split-str=tailscale` ran the machine's binary).
_R22D_CMDLINE_LONG = ("--split-string", "--command", "--session-command")


def _r19d_unwrap(argv, path, prefix_value=True):
    """(index of the word the wrapper commands in front leave to run, the PATH it is found on).

    The PATH is None when a wrapper clears or resets it: `env -i`, `env -u PATH`, sudo.
    `prefix_value` is how a long option that is only a PREFIX of a value-taking one is read
    (_r19d_opt_word): True or False for all of them, or the set of their argv indices that take
    one; the guard judges the argv every way (_r25d_readings).
    """
    _i = 0
    while (_i < len(argv) and isinstance(argv[_i], str)
           and os.path.basename(argv[_i]) in _R19D_WRAPPERS):
        _w = os.path.basename(argv[_i])
        _i, path = _r19d_wrapper_opts(_w, argv, _i + 1, None if _w in _R20D_PATH_RESETS else path,
                                      prefix_value)
        _i += _R19D_WRAPPERS[_w][1]
    return _i, path


def _r19d_wrapper_opts(word, argv, _i, path, prefix_value=True):
    """(index of the first operand after `word`'s options from argv[_i], the PATH its command sees)."""
    while _i < len(argv) and isinstance(argv[_i], str) and argv[_i] != "--":
        _step = _r19d_opt_word(word, argv, _i, prefix_value)
        if _step is None:
            return _i, path
        path = _r19d_path_after(word, _step[1], path)
        _i += _step[0]
    # A tuple argv is as runnable as a list (review 1013a: comparing its slice with ["--"] was
    # never true, so `("env", "--", "tailscale")` read "--" as the program).
    return _i + (1 if tuple(argv[_i:_i + 1]) == ("--",) else 0), path


def _r23d_long_prefix(name, full):
    """Is `name` (`--x`, no `=`) one of `full` (a long option or a collection of them) by getopt_long's prefix rule?"""
    _full = (full,) if isinstance(full, str) else full
    return len(name) > 2 and name.startswith("--") and any(_o.startswith(name) for _o in _full)


def _r19d_opt_word(word, argv, _i, prefix_value=True):
    """(words used, [(option, value)]) for the option word argv[_i] of `word`, or None at its operand.

    A variable set by env or sudo reads as ("=", "NAME=value"): any word holding "=" sets one,
    the guard's own BASH_FUNC_x%%=… included.
    A long option is read as getopt_long reads it, also by an unambiguous prefix (review 1015d:
    only the exact names were, so `env --ch /x tailscale` and `timeout --sig KILL 5 tailscale`
    took the option's value for the program and ran the machine's binary). The table spans every
    wrapper, so a prefix of a value-taking name may be a flag of this one (env's `--i` is
    --ignore-environment, stdbuf's takes a value): `prefix_value` says which reading this pass takes.
    """
    _a = argv[_i]
    if word in ("env", "sudo") and re.fullmatch(r"[^=-][^=]*=.*", _a, re.S):
        return 1, [("=", _a)]
    if _a == "-" and word == "env":
        return 1, [("-i", "")]
    if _a.startswith("--"):
        return _r23d_long_opt(argv, _i, prefix_value)
    if re.fullmatch(r"-[A-Za-z0-9]+", _a):
        return _r19d_short_opts(word, argv, _i)
    return None


def _r23d_long_opt(argv, _i, prefix_value):
    """(words used, [(option, value)]) for the long option word argv[_i] (see _r19d_opt_word)."""
    _name, _eq, _val = argv[_i].partition("=")
    _pv = _i in prefix_value if isinstance(prefix_value, frozenset) else prefix_value
    if not _eq and (_name in _R19D_LONG_VALUE or (_pv and _r23d_long_prefix(_name, _R19D_LONG_VALUE))):
        return 2, [(_name, _r19d_next(argv, _i))]
    return 1, [(_name, _val)]


def _r19d_next(argv, _i):
    return argv[_i + 1] if _i + 1 < len(argv) else ""


def _r19d_short_opts(word, argv, _i):
    """(words used, [(option, value)]) for the short-option cluster argv[_i] of `word`."""
    _a, _opts = argv[_i], []
    for _k, _ch in enumerate(_a[1:], 1):
        if _ch in _R19D_WRAPPERS[word][0]:
            _rest = _a[_k + 1:]
            _opts.append(("-" + _ch, _rest or _r19d_next(argv, _i)))
            return (1 if _rest else 2), _opts
        _opts.append(("-" + _ch, ""))
    return 1, _opts


def _r19d_path_after(word, opts, path):
    """The PATH after options `opts`: set by PATH=, cleared by env -i and env -u PATH.

    Their long names count by a prefix too (`--ignore-e`, `--unse PATH`, review 1015d); an
    ambiguous one (`--ig`) reads as clearing, which judges both PATHs (_r20d_argv_programs).
    """
    for _name, _val in opts:
        # sudo's own PATH= does not choose where sudo looks: secure_path does (review 1013a).
        if _name == "=" and _val.startswith("PATH=") and word not in _R20D_PATH_RESETS:
            path = _val[len("PATH="):]
        elif word == "env" and _r23d_env_clears_path(_name, _val):
            path = None
    return path


def _r23d_env_clears_path(name, val):
    """Does env's option `name` (with value `val`) clear PATH: -i, -u PATH, or their long names by a prefix?"""
    if name == "-i" or _r23d_long_prefix(name, "--ignore-environment"):
        return True
    return (name == "-u" or _r23d_long_prefix(name, "--unset")) and val == "PATH"


def _r18d_shell_opts(argv, _j):
    """(whether -c was given, index of the first operand) for the shell options from argv[_j]."""
    _c = False
    while _j < len(argv) and isinstance(argv[_j], str):
        _a = argv[_j]
        if _a in ("-", "--"):
            return _c, _j + 1
        if _a.startswith("--"):
            _j += 2 if _a in ("--rcfile", "--init-file") else 1
        elif re.fullmatch(r"[-+][A-Za-z]+", _a):
            _c = _c or (_a[0] == "-" and "c" in _a)
            _j += 2 if re.search("[oO]", _a) else 1
        else:
            break
    return _c, _j


def _r19d_stand_in(path):
    """Whether the `tailscale` at `path` is a part's own stand-in: found AND resolved under a root.

    The guard's own shim (_R26D_SHIM) counts as one: it judges what it finds past itself.
    """
    return ((os.path.abspath(path).startswith(_R19D_STAND_IN_ROOTS)
             and os.path.realpath(path).startswith(_R19D_STAND_IN_ROOTS))
            or os.path.realpath(path) == os.path.join(os.path.realpath(_R26D_SHIM), "tailscale"))


def _r16d_ts_shell_funcs():
    """Bash functions `tailscale` and `which` that answer the machine's tailscale as missing.

    Each resolves `tailscale` on the shell's PATH as it is when called; one that is not a part's
    stand-in (_r19d_stand_in) is "command not found" (127) and `which tailscale` finds nothing.
    """
    _roots = "|".join('"%s"*' % _d for _d in _R19D_STAND_IN_ROOTS)
    # The found path is judged as found AND as resolved: a link in a stand-in's directory to the
    # machine's binary is the machine's, and so is a link elsewhere to a stand-in (review 1012c/d).
    _is_sys = ('_r16d_p=$(type -P tailscale); _r16d_q=$(readlink -f "$_r16d_p" 2>/dev/null); '
               'case "$_r16d_p" in "") false;; %s) case "$_r16d_q" in %s) false;; *) true;; esac;; '
               '*) true;; esac' % (_roots, _roots))
    return {"BASH_FUNC_tailscale%%": "() { if %s; then echo 'tailscale: command not found' >&2; "
                                     "return 127; fi; command tailscale \"$@\"; }" % _is_sys,
            # Any `which` that names tailscale among its words, options included (review 1013a:
            # `which -a tailscale` was answered by the real which, and `$t` then ran its path).
            # Past a stand-in first on PATH, `which -a` still listed the machine's after it, and
            # `| tail -n1` handed that to the script (review 1016b): only stand-ins are printed.
            # The answer is which's own exit status, not the filter loop's (review 1016c: the
            # loop's 0 made `which tailscale` succeed with no tailscale anywhere, CI's case).
            "BASH_FUNC_which%%": ('() { case " $* " in *" tailscale "*) if { %s; }; then return 1; fi; '
                                  'local _r26d_o _r26d_s; _r26d_o=$(command which "$@"); _r26d_s=$?; '
                                  '[ -n "$_r26d_o" ] && printf "%%s\\n" "$_r26d_o" | '
                                  'while IFS= read -r _r25d_w; do case "$_r25d_w" in '
                                  '*/tailscale) _r25d_q=$(readlink -f "$_r25d_w" 2>/dev/null); '
                                  'case "$_r25d_w" in %s) case "$_r25d_q" in %s) echo "$_r25d_w";; esac;; esac;; '
                                  '*) echo "$_r25d_w";; esac; done; return "$_r26d_s";; esac; '
                                  'command which "$@"; }' % (_is_sys, _roots, _roots))}


def _r16d_ts_shell_env(env):
    """`env` plus _r16d_ts_shell_funcs' functions."""
    return dict(env, **_r16d_ts_shell_funcs())


def _r18d_ts_program(cmd, kw, prefix_value=True):
    """(program word, PATH it is found on or None) of a shell-less `tailscale` run, else (None, None).

    A bare string without a shell is a program name on POSIX, and an argv may name the binary by
    its path: both ran unjudged (review 1012c), as did one behind `timeout`, `env -i` or `nice`.
    """
    if isinstance(cmd, str) and not kw.get("shell"):
        cmd = [cmd]
    if not isinstance(cmd, (list, tuple)) or kw.get("shell"):
        return None, None
    _i, _path = _r19d_unwrap(cmd, _r20d_run_env(kw).get("PATH", os.defpath), prefix_value)
    if _i < len(cmd) and isinstance(cmd[_i], str) and os.path.basename(cmd[_i]) == "tailscale":
        return cmd[_i], _path
    return None, None


def _r20d_run_env(kw):
    """The environment a run gets: an explicit `env={}` is an empty one, not "inherit" (review 1013a)."""
    return os.environ if kw.get("env") is None else kw["env"]


def _r20d_cmdline_values(cmd):
    """Each argv word that is a command line in itself.

    That is an option value of `-S`/`--split-string`/`-c`/`--command` (a short one also grouped or attached:
    _r21d_cluster_value), or a word with whitespace in it (a script handed to a shell the guard
    does not read, zsh -c …).
    """
    _out = []
    for _k, _a in enumerate(cmd):
        if not isinstance(_a, str):
            continue
        if _r21d_whole_cmdline(cmd, _k):
            _out.append(_a.partition("=")[2] if _a.startswith("--") and "=" in _a else _a)
        _val = _r21d_cluster_value(cmd, _k)
        if _val is not None:
            _out.append(_val)
    return _out


def _r25d_option_cmdlines(cmd):
    """The argv words that are an option's command line (-S/-c/--command/--split-string), not merely spaced."""
    _out = []
    for _k, _a in enumerate(cmd):
        if not isinstance(_a, str):
            continue
        _prev = cmd[_k - 1] if _k else None
        if _r22d_cmdline_long(_prev) and "=" not in _prev:
            _out.append(_a)
        elif _r22d_cmdline_long(_a) and "=" in _a:
            _out.append(_a.partition("=")[2])
        _val = _r21d_cluster_value(cmd, _k)
        if _val is not None:
            _out.append(_val)
    return _out


def _r22d_cmdline_long(word):
    """Is `word` (`--x` or `--x=…`) a long option whose value is a command line, by its name or a prefix?"""
    _name = word.partition("=")[0] if isinstance(word, str) else ""
    return len(_name) > 2 and _name.startswith("--") and any(_o.startswith(_name) for _o in _R22D_CMDLINE_LONG)


def _r21d_whole_cmdline(cmd, k):
    """Is cmd[k] a command line by its long option (`--command x`, `--split-str=x`) or its whitespace?"""
    _a, _prev = cmd[k], cmd[k - 1] if k else None
    return ((_r22d_cmdline_long(_prev) and "=" not in _prev) or (_r22d_cmdline_long(_a) and "=" in _a)
            or bool(re.search(r"\s", _a)))


def _r21d_cluster_value(cmd, k):
    """The value a short-option word cmd[k] gives -S or -c, wherever it sits in its cluster, or None.

    Attached (`-Stailscale`, `-ctailscale`) or the next word (`-S x`, `-vS x`, `-lc x`).
    """
    _a = cmd[k]
    if not re.match(r"-[A-Za-z0-9]", _a):
        return None
    for _j, _ch in enumerate(_a[1:], 1):
        if _ch in _R21D_CMDLINE_LETTERS:
            _nxt = cmd[k + 1] if k + 1 < len(cmd) else None
            return _a[_j + 1:] or (_nxt if isinstance(_nxt, str) else None)
        if not _ch.isalnum():
            return None
    return None


def _r20d_cmdline_candidates(cmd, kw):
    """The tailscale a shell-less argv could run through a command line it carries as one word.

    Such a value runs under a shell or `env -S`, which the shell functions never reach, so it is
    judged as a script would be: on the PATH the run starts with, and the default one too when
    something may reset PATH.
    """
    if not isinstance(cmd, (list, tuple)) or kw.get("shell"):
        return []
    _vals = _r20d_cmdline_values(cmd)
    # A value that names the binary by a path runs that path, whatever PATH finds first (review
    # 1015a: `env -S '<dir>/tailscale up'` with a stand-in first on PATH was judged by the stand-in).
    _named = [_h for _v in _vals for _h in _r19d_script_candidates(_v, kw)]
    if not _r25d_may_name(cmd, _vals, _r20d_run_env(kw)):
        return _named
    _paths = [_r20d_run_env(kw).get("PATH", os.defpath)]
    if _r20d_may_reset_path(cmd):
        _paths.append(_R19D_DEFAULT_PATH)
    return _named + [shutil.which("tailscale", path=_p) for _p in _paths]


def _r25d_may_name(cmd, vals, env):
    """Might one of argv `cmd`'s command lines `vals` name `tailscale`?

    One that names it in its words, or an option's command line that can build a word
    (_r25d_builds), which may name it however it is spelled. A plain word with whitespace is only
    read by its words: it is an operand (ssh's remote command), not a command line run here.
    """
    return (any(_r25d_builds(_v) for _v in _r25d_option_cmdlines(cmd))
            or any(_r20d_names_tailscale(_v, env) for _v in vals))


# A variable a shell or env -S expands: $NAME, ${NAME}, and ${NAME[:]-word}, [:]=, [:]+ and [:]?.
_R23D_SHELL_VAR = re.compile(r"\$(?:\{(\w+)(?:(:?)([-=+?])([^}]*))?\}|(\w+))")


def _r23d_expand_vars(text, env):
    """`text` with each variable expanded as a shell or env -S expands it against `env`.

    As the shell reads the operators (review 1016b: `${X-w}` with X set but empty gave w, where the
    shell gives "", and `${X:+w}` was not read at all): without the colon only an UNSET name takes
    the default, with it an empty one does too, and `+` gives the word only when that does not hold.
    """
    def _one(_m):
        _name, _colon, _op, _word = _m.group(1) or _m.group(5), _m.group(2), _m.group(3), _m.group(4) or ""
        _v = env.get(_name)
        _missing = _v is None or (bool(_colon) and _v == "")
        if _op in ("-", "="):
            return _word if _missing else _v
        if _op == "+":
            return "" if _missing else _word
        return _v or ""
    return _R23D_SHELL_VAR.sub(_one, text)


# What lets a command line build a word at run time: an expansion, a quote-free escape, brace
# expansion, eval or a sourced file. Its letters are not its words then, so a line holding one
# is judged as one that may name `tailscale` (review 1016b: `T=tail; ${T}scale`, `tail$(:)scale`,
# `$'tail\x73cale'` and `tail${X:+scale}` each ran the machine's binary under a shell the guard
# reads statically; a fifth spelling would always remain, so the construct is what is judged).
_R25D_BUILDS = re.compile(r"[$`\\{]|\beval\b|\bsource\b|(?:^|[\s;&|(])\.\s")


def _r25d_builds(text):
    """Can command line `text` build a word at run time (_R25D_BUILDS), outside its '…' strings?

    A single-quoted string is literal to the shell: awk's `'$1 >= c'` builds nothing, and read as
    if it did, the f2b readers' scripts were refused. `$'…'` keeps its `$`, so it still counts.
    """
    return bool(_R25D_BUILDS.search(_r26d_strip_single(text)))


def _r26d_strip_single(text):
    """`text` with each '…' string the shell reads literally emptied to '', and only those.

    An apostrophe inside "…" or after a backslash opens nothing (review 1016c: `echo "it's"` read
    as opening a string up to the next apostrophe hid the `${T}scale` between them). Nor does one
    in a `#` comment, which is dropped to its line's end, or in a here-document's body, which is
    kept as text with its apostrophes taken out (review 1016e: `# it's` and a body line `it's`
    opened a string up to the next apostrophe, and the built word between read as nothing).
    A comment is kept the same way, not dropped (review 1016f: a `#` bash reads as part of a word,
    an escaped space before it or `$(:)#`, dropped the rest of its line, and a wrapper or a PATH= on it with it).
    A `#` is a comment only where bash starts a word (review 1017a: after an escaped blank it was
    taken for one, so a quote it opened was never seen and the reader's quoting ran inverted from
    there). After a `)` it may be either (`(cd x)#…` starts a word, `$(:)#…` does not), so both
    readings are returned, joined: a caller searching the text sees what either one holds.
    """
    _as_comment = _r30d_strip_once(text, True)
    _as_code = _r30d_strip_once(text, False)
    return _as_comment if _as_comment == _as_code else _as_comment + "\n" + _as_code


def _r30d_strip_once(text, paren_comment):
    """_r26d_strip_single under one reading of a `#` right after a `)` (a comment when `paren_comment`)."""
    out, i, dq, bodies, esc_end = [], 0, False, [], -1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            out.append(text[i:i + 2])
            i += 2
            esc_end = i
            continue
        _j = None if dq else _r28d_unquoted_step(text, i, out, bodies, _r30d_word_start(text, i, esc_end, paren_comment))
        if _j is not None:
            i = _j
            continue
        if ch == "'" and not dq:
            j = text.find("'", i + 1)
            if j < 0:
                out.append(text[i:])
                break
            out.append("''")
            i = j + 1
            continue
        dq = dq != (ch == '"')
        out.append(ch)
        i += 1
    return "".join(out)


def _r30d_word_start(text, i, esc_end, paren_comment):
    """Does a word start at text[i] (unquoted), as bash decides whether a `#` there opens a comment?

    At the start, or after an unescaped blank or operator character; after a `)` only under the
    reading `paren_comment` takes.
    """
    if i == 0:
        return True
    if i == esc_end:
        return False        # the character before was escaped: the word goes on
    return text[i - 1] in " \t\n;&|(<>" or (paren_comment and text[i - 1] == ")")


# A here-document's operator: `<<WORD`, `<<-WORD`, the delimiter one shell word quoted any way
# (`<<'EOF'`, `<<\\EOF`, `<<E"OF"`), and not `<<<`, a here-string (review 1016f: a backslash or a
# part-quoted delimiter was no here-document, and `<<< END` matched at its second `<`).
_R28D_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*((?:\\.|'[^'\n]*'|\"[^\"\n]*\"|[^\s;&|<>()'\"\\])+)")


def _r28d_unquoted_step(text, i, out, bodies, word_start):
    """Past a `#` comment, a here-document operator or the bodies due at a newline, at text[i] (unquoted).

    The index after it, with what it leaves appended to `out`, or None when text[i] is none of them.
    `bodies` holds the here-documents whose bodies start at the next newline; `word_start`, whether
    a word starts at text[i] (_r30d_word_start), which a `#` needs to open a comment.
    """
    if text[i] == "\n" and bodies:
        out.append("\n")
        _j = _r28d_heredoc_bodies(text, i + 1, bodies, out)
        bodies.clear()
        return _j
    if text[i] == "#" and word_start:
        _e = text.find("\n", i)
        _e = len(text) if _e < 0 else _e
        out.append(text[i:_e].replace("'", ""))
        return _e
    _hd = _R28D_HEREDOC.match(text, i)
    if _hd:
        bodies.append((_hd.group(1) == "-", re.sub(r"['\"\\]", "", _hd.group(2))))
        out.append(_hd.group(0))
        return _hd.end()
    return None


def _r28d_heredoc_bodies(text, i, bodies, out):
    """Append the bodies of the here-documents `bodies` that start at text[i] to `out`; where they end.

    Each body runs to the line that is its delimiter (after leading tabs for `<<-`). A delimiter
    with no such line (`$((1<<2))`, which only looks like one) takes nothing, so no text is hidden.
    """
    for _tabs, _delim in bodies:
        j = i
        while j < len(text):
            _e = text.find("\n", j)
            _e = len(text) if _e < 0 else _e
            if (text[j:_e].lstrip("\t") if _tabs else text[j:_e]) == _delim:
                out.append(text[i:j].replace("'", ""))
                i = j
                break
            j = _e + 1
    return i


# What a static reading cannot resolve: a command's output, eval or a sourced file, an escape or a
# brace expansion that joins letters, and the shell's own parameters.
# Also any `${…}` _R23D_SHELL_VAR does not take whole (review 1016e: `${T%x}`, `${T/X/tail}`,
# `${T:0:4}`, `${T^^}` and `${A[0]}` were left as text, so the word read as spelling nothing),
# and a `declare -n` nameref, which makes one name another's.
_R26D_UNRESOLVED = re.compile(r"\$\(|`|\beval\b|\bsource\b|" + _R30D_SOURCE_DOT + r"|\\|\{[^}\s]*(?:,|\.\.)|"
                              r"\$'|\$\{?[!#@*0-9?$-]|\$\{(?!\w+(?::?[-=+?][^}$`]*)?\})|"
                              r"\b(?:declare|typeset|local)\s+(?:[-+]\w+\s+)*-\w*n")
# How a script sets a name other than by a plain `NAME=value` that _r25d_script_env reads (%s is the
# name): a loop, read, getopts, an append, an element or an array, printf -v, mapfile, a declare
# with options (-u, -l change the value), and the assigning defaults ${NAME=…} and ${NAME:=…}
# (review 1016e: each left the name unset to the reader, so `T+=scale`, `printf -v T tail` and
# `: ${T:=tail}` ahead of `timeout 5 ${T}scale` read as `timeout 5 scale`).
_R28D_SET_OTHERWISE = (r"\b(?:for|select)\s+%(n)s\b|\bread\b[^;&|\n]*\b%(n)s\b|\bgetopts\s+\S+\s+%(n)s\b"
                       r"|(?:^|[\s;&|(])%(n)s(?:\+=|\[|=\()|\bprintf\s+(?:-\S+\s+)*-v\s*%(n)s\b"
                       r"|\b(?:mapfile|readarray)\b[^;&|\n]*\b%(n)s\b"
                       r"|\b(?:declare|typeset|local|readonly|export)\s+(?:[-+]\w+\s+)+(?:\w+(?:=\S*)?\s+)*%(n)s\b"
                       r"|\$\{%(n)s:?=")


def _r26d_may_spell(text, script, env):
    """Can the command line `text` (a part of `script`) spell `tailscale` when it runs?

    Only what stays unresolved (_R26D_UNRESOLVED, a name `script` sets other than plainly
    (_R28D_SET_OTHERWISE) or from another expansion) or what expands to the word (review 1016c:
    any wrapper followed by a `$` was judged as possibly running it, so `exec 3<"$L"`, `timeout 5
    cat "$HOME/x"` and the console reads were refused on a machine with tailscale on PATH and ran
    on CI). A name nothing sets is empty, as the shell reads it.
    """
    _text = _r26d_strip_single(text)
    if _R26D_UNRESOLVED.search(_text):
        return True
    _env = _r25d_script_env(script, env)
    for _m in _R23D_SHELL_VAR.finditer(_text):
        _name = _m.group(1) or _m.group(5)
        # A sourced or eval'd text can set any name (review 1017a: `. <file>; timeout 5 ${T}scale`
        # with T=tail in the file read T as unset).
        if (_R30D_SETS_ANY.search(script) or re.search(_R28D_SET_OTHERWISE % {"n": re.escape(_name)}, script)
                or re.search(r"[$`]", _env.get(_name) or "")):
            return True
    return _r20d_names_tailscale(_r23d_expand_vars(_text, _env), _env)


def _r20d_names_tailscale(text, env=None):
    """Does a command line held in one word name `tailscale` as one of its words?

    Also once unquoted, as a shell or env -S reads it, with env -S's backslash-underscore as a space
    (review 1015c: `tail'scale' version`, and tailscale joined to `version` by that escape, ran the
    machine's binary), and with its variables expanded against the run's environment (review
    1015d: `env -S 'tail${NOPE}scale'` and `zsh -c 'tail$NOPE"scale"'` ran it).
    """
    _words = []
    for _t in {text, _r23d_expand_vars(text, env or {})}:
        _words += re.split(r"[\s;&|()`'\"$=]+", _t)
        try:
            _words += [_x for _w in shlex.split(_t.replace("\\_", " ")) for _x in re.split(r"[\s;&|()`$=]+", _w)]
        except ValueError:
            pass    # unbalanced quotes: a shell refuses it, and the split above still reads its words
    return any(os.path.basename(_w) == "tailscale" for _w in _words)


def _r20d_may_reset_path(cmd):
    """Might argv `cmd` clear or reset PATH before what it runs looks the program up?"""
    return bool(_R19D_SCRIPT_RESETS.search(" ".join(str(_a) for _a in cmd))) or any(
        isinstance(_a, str) and os.path.basename(_a) in _R20D_PATH_RESETS for _a in cmd)


# A script that reaches tailscale past the shell's function, through a command that execs it from
# PATH itself (`timeout 5 tailscale`, `command tailscale`, `xargs tailscale`), is judged on the PATH
# it starts with, and on the default PATH too when it may clear or reset PATH first.
# Built from the argv table, so the two forms name the same wrappers (review 1013a). A wrapper
# named by its path (`/usr/bin/env tailscale`) counts as well: it execs from PATH all the same.
# `type -P tailscale` hands the binary's path to the script, past the function, and a nested
# `sh -c` runs under dash, which never reads the exported functions.
_R19D_SCRIPT_WRAPPED = re.compile(
    r"(?:^|[\s;&|(`/])(?:%s)\s[^;&|\n]*?\btailscale\b"
    % "|".join(sorted(set(_R19D_WRAPPERS) | set(_R20D_SCRIPT_ONLY))))
# ...and one of those commands given a word the script builds at run time (`command ${T}scale`,
# `exec $(printf …)`): the function cannot see it, and the word may be the binary (review 1016b).
_R25D_SCRIPT_WRAPPED_BUILT = re.compile(
    r"(?:^|[\s;&|(`/])(?:%s)\s[^;&|\n]*?(?:[$`]|\beval\b)"
    % "|".join(sorted(set(_R19D_WRAPPERS) | set(_R20D_SCRIPT_ONLY))))
# A shell the functions never reach (dash, zsh, …) handed a quoted script of its own: that script
# is judged by what it can build, not by the quotes that make it literal to the outer shell.
_R25D_NESTED_SHELL = re.compile(r"(?:^|[\s;&|(`/])(?:sh|dash|zsh|ksh|mksh|busybox)\s+(?:busybox\s+)?"
                                r"(?:[-+]\w+\s+)*-\w*c\w*\s+('[^']*'|\"[^\"]*\")")
# env's clearing options anywhere among its options, and by a long name's prefix (review 1015d:
# only one right after `env` was read, so `env -v -i x`, `env -u PATH x` and `env --unse PATH x`
# were judged on the PATH the script started with).
# An option that takes its value as the next word is skipped with it (review 1016b: the scan
# stopped at the value of `env -u X -i` and `env --chdir /x -i`, and both were judged on the PATH
# the script started with).
# Read word by word, not by one regex (CodeQL py/redos, review 1016b twice): a pattern with a repeated
# option group followed by an option alternative could split a run of `-C! ` or `-- ` words more
# than one way, and a failing search backtracked exponentially. One pass over the words has one
# reading. -S/--split-string hands env a string it splits into more options (a -i among them), so
# it counts as a reset outright, as it was effectively read.
_R25J_RESET_WORDS = re.compile(r"\b(?:sudo|doas|runuser|su)\b|\bPATH=")
_R25J_ENV_WORD = re.compile(r"\benv\b")


def _r25j_long(w, nxt):
    """(resets PATH?, words consumed) for one `--name[=value]` option of env.

    By its first letter, which is how getopt_long takes an unambiguous prefix: --unset, --chdir and
    --argv0 take a value (review 1016c: --argv0's was read as env's command).
    """
    name, eq, val = w[2:].partition("=")
    # --ignore-signal (coreutils 9) is not --ignore-environment; a shorter --i still reads as it,
    # which older env takes it for (review 1016e lead: every --i… counted, an over-strict reading).
    if name[:1] == "s" or (name[:1] == "i" and not name.startswith("ignore-s")):
        return True, 1
    if name[:1] not in ("u", "c", "a"):
        return False, 1
    value = val if eq else nxt
    return name[0] == "u" and value == "PATH", (1 if eq else 2)


def _r25j_short(cl, nxt):
    """(resets PATH?, words consumed) for one `-cluster` option of env (cl is without the dash).

    Letter by letter, as getopt reads it: -i or -S resets; the first of -u, -C or -a takes the rest
    of the cluster as its value, or the next word when nothing follows it (review 1016c: only a
    cluster STARTING with u or C was read that way, so `env -vu X -i` stopped at X).
    """
    for _k, _ch in enumerate(cl):
        if _ch in "iS":
            return True, 1
        if _ch in "uCa":
            rest = cl[_k + 1:]
            return _ch == "u" and (rest or nxt) == "PATH", (1 if rest else 2)
    return False, 1


def _r25j_env_resets(words):
    """Whether env's options (the words after `env`) clear or replace the PATH it searches."""
    i = 0
    while i < len(words):
        w = words[i]
        nxt = words[i + 1] if i + 1 < len(words) else ""
        if w == "-":
            return True
        if w.startswith("-"):
            reset, step = _r25j_long(w, nxt) if w.startswith("--") else _r25j_short(w[1:], nxt)
            if reset:
                return True
            i += step
        elif "=" in w and not w.startswith("="):
            i += 1
        else:
            return False
    return False


class _R25JResets:
    """`.search(text)` like the regex it replaced: a reset word anywhere, or an env that resets."""

    @staticmethod
    def search(text):
        if _R25J_RESET_WORDS.search(text):
            return True
        return any(_r25j_env_resets(text[m.end():].split()) for m in _R25J_ENV_WORD.finditer(text))


_R19D_SCRIPT_RESETS = _R25JResets()
# Commands that find a program somewhere other than PATH: `whereis` searches the system's own
# directories whatever PATH says, and `find` walks them (review 1015a: with a part's stand-in first
# on PATH, `whereis -b tailscale` handed the script the machine's binary and was judged on PATH).
# `command -p` searches the shell's default PATH whatever $PATH holds (review 1016e).
_R21D_SCRIPT_SEARCHES = re.compile(r"\b(?:whereis|find)\b|\bcommand\s+(?:-\w+\s+)*-\w*p")
# ...and one that names the binary by a path is judged by that path: ~, $VAR and a relative path
# are read against the run's environment and directory.
_R19D_SCRIPT_PATH = re.compile(r"(?<![\w.~$/:-])((?:~|\$\{?\w+\}?|\.{1,2})?[\w./~-]*/tailscale)(?![\w.-])")


def _r19d_script_candidates(script, kw, cmd=None):
    """The tailscale binaries a script could run past the shell's `tailscale` function.

    `cmd`, the argv that runs a `-c` script, adds what its wrappers set for the shell
    (_r28d_argv_env).
    """
    _env, _extra = _r28d_argv_env(cmd, _r20d_run_env(kw))
    _found = (_r19d_wrapped_candidates(script, _env, _extra)
              + _r19d_path_candidates(script, _env, kw.get("cwd")))
    # A login shell's profile sets the PATH its script searches, past the shim (review 1016f):
    # one that may name or build the word (in any of its quotes: the login shell reads them) is
    # judged on the PATHs a profile gives it.
    if (_r29d_login(cmd if isinstance(cmd, (list, tuple)) else script)
            and (_r20d_names_tailscale(script, _env) or _R25D_BUILDS.search(script))):
        _found += [shutil.which("tailscale", path=_p) for _p in _r29d_login_paths(_env)]
    return [_f for _f in _found if _f is not None]


def _r29d_login(cmd):
    """Does `cmd` (a script, or an argv) start a login shell (_R29D_LOGIN)?"""
    return bool(_R29D_LOGIN.search(cmd if isinstance(cmd, str) else " ".join(str(_a) for _a in cmd)))


def _r29d_login_paths(env):
    """The PATHs a login shell's profile gives it: the default one, and the home's bin directories."""
    _home = env.get("HOME") or os.path.expanduser("~")
    return [_R19D_DEFAULT_PATH, os.pathsep.join(os.path.join(_home, _b) for _b in (".local/bin", "bin"))]


def _r28d_argv_env(cmd, env):
    """(`env` plus the NAME=value words the wrappers in front of argv `cmd`'s shell set, more PATHs).

    Review 1016e: `env T=tailscale bash -c 'timeout 5 $T version'` read $T as unset, and a shell
    behind `env PATH=<dir>` or sudo was judged only on the PATH the run started with, while what
    its script execs from PATH is found on the wrapper's. The extra PATHs: the one a wrapper sets,
    and the default one behind a wrapper that resets it, under every reading of its options.
    """
    if not isinstance(cmd, (list, tuple)):
        return env, []
    _i = _r18d_dash_c(cmd)[0]
    if not _i:
        return env, []
    _env, _extra = dict(env), []
    for _w in cmd[:_i]:
        _m = re.fullmatch(r"([A-Za-z_]\w*)=(.*)", _w, re.S) if isinstance(_w, str) else None
        if _m and _m.group(1) != "PATH":
            _env[_m.group(1)] = _m.group(2)
    for _pv in _r25d_readings(cmd):
        _p = _r19d_unwrap(cmd, env.get("PATH", os.defpath), _pv)[1]
        _extra.append(_R19D_DEFAULT_PATH if _p is None else _p)
    return _env, _extra


def _r28d_no_shim(path):
    """`path` without the guard's own shim directory: what the script searches past it."""
    return os.pathsep.join(_d for _d in path.split(os.pathsep) if _d != _R26D_SHIM)


def _r19d_wrapped_candidates(script, env, extra=()):
    """The tailscale a wrapper in `script` could exec from PATH: the starting one, and the default.

    A wrapper given a built word, or a nested shell given a building script, counts only when what
    it builds may spell the binary (_r26d_may_spell), judged over that command up to its end.
    Also every PATH the script assigns, read against the one it starts with (review 1016e:
    `PATH=<dir>:$PATH; timeout 5 ${T}scale` was judged on the starting PATH, never on <dir>), and
    the starting one without the shim, which counts as a stand-in and would answer for any PATH.
    """
    if not (_R19D_SCRIPT_WRAPPED.search(script) or _r26d_runs_built(script, env)
            or _R19D_SCRIPT_WRAPPED.search(_r23d_expand_vars(script, _r25d_script_env(script, env)))):
        return []
    return [shutil.which("tailscale", path=_p) for _p in _r29d_script_paths(script, env, extra)]


def _r29d_script_paths(script, env, extra):
    """The PATHs a wrapper in `script` may search (_r19d_wrapped_candidates)."""
    _start = _r28d_no_shim(env.get("PATH", os.defpath))
    _bare = _r29d_unquoted(script)
    _paths = [_start] + list(extra)
    if (_R19D_SCRIPT_RESETS.search(script) or _R19D_SCRIPT_RESETS.search(_bare)
            or _R21D_SCRIPT_SEARCHES.search(script)):
        _paths.append(_R19D_DEFAULT_PATH)
    # A login shell searches what its profile sets.
    if _r29d_login(script):
        _paths += _r29d_login_paths(env)
    # Each PATH the script assigns, quoted or not, read with the script's own names (review 1016f:
    # `D=<d>; sh -c "PATH=$D:…"` expanded $D against the run's environment, and <d> was never judged).
    _senv = dict(_r25d_script_env(script, env), PATH=_start)
    return _paths + [_r23d_expand_vars(_r29d_unquote(_v), _senv)
                     for _t in (script, _bare) for _v in re.findall(r"(?<![\w$])PATH\+?=" + _R29D_VALUE, _t)]


def _r26d_runs_built(script, env):
    """Does `script` hand a wrapper, or a nested shell, a word it builds that may spell the binary?"""
    _bare = _r26d_strip_single(script)
    return (any(_r26d_may_spell(_c, script, env) for _c in _r26d_built_commands(_bare))
            or any(_r25d_builds(_n) and _r26d_may_spell(_n, _n + "\n" + script, env)
                   for _n in (_q.strip("'\"") for _q in _R25D_NESTED_SHELL.findall(script))))


def _r26d_built_commands(bare):
    """Each command in `bare` (a script, its '…' strings emptied) where a wrapper is given a built word.

    From the wrapper to the end of its command, so what it is handed is read whole.
    """
    return [bare[_m.start():_m.end()] + re.split(r"[;&|\n]", bare[_m.end():], maxsplit=1)[0]
            for _m in _R25D_SCRIPT_WRAPPED_BUILT.finditer(bare)]


# An assigned value as the shell takes it: quoted pieces and bare ones, up to the first unquoted break.
_R29D_VALUE = r"((?:'[^']*'|\"[^\"]*\"|[^\s;&|)'\"])*)"


def _r29d_unquote(word):
    """`word` with its quotes and escapes removed, as the shell removes them; `word` itself if unbalanced."""
    try:
        return "".join(shlex.split(word))
    except ValueError:
        return word.strip("'\"")


def _r29d_unquoted(text):
    """`text` with every quote and backslash dropped: `export 'PATH=…'` and `"PA"TH=` read as PATH=."""
    return re.sub(r"['\"\\]", "", text)


def _r29d_named(words, k):
    """The variable NAMES the builtin at words[k] is handed (printf: only -v's), else []."""
    if words[k] == "printf":
        return [words[_j + 1] if words[_j] == "-v" and _j + 1 < len(words) else words[_j][2:]
                for _j in range(k + 1, len(words)) if words[_j].startswith("-v")]
    if words[k] not in _R29D_NAME_BUILTINS:
        return []
    return [_x for _j, _x in enumerate(words[k + 1:], k + 1)
            if not _x.startswith(("-", "+", "<", ">")) and words[_j - 1] not in ("<", ">", "<<<")]


def _r29d_names_built(script):
    """Does `script` hand a name-taking builtin (_R29D_NAME_BUILTINS, printf -v) a quoted or built name?"""
    return any(re.search(r"[$'\"\\`]", _n.split("=", 1)[0])
               for _w in (_seg.split() for _seg in re.split(r"[;&|\n]", script))
               for _k in range(len(_w)) for _n in _r29d_named(_w, _k))


def _r25d_script_env(script, env):
    """`env` plus the plain assignments `script` makes (`T=tail`, `T='tail'`), as its later words see them.

    A value quoted in part (`T=ta"il"`) is unquoted as the shell does (review 1016f: its quotes were
    kept, so `${T}scale` read as `ta"ilscale` and `env -i ${T}scale` was not judged).
    """
    _env = dict(env)
    for _name, _val in re.findall(r"(?:^|[\s;&|(])(\w+)=" + _R29D_VALUE, script):
        _env[_name] = _r29d_unquote(_val)
    return _env


def _r29d_may_set_path(script):
    """Can `script` change the PATH its commands search, read past every quote (review 1016f)?

    `_R28D_PATH_OWN` on the script as written, as the stripped reader sees it, and with its quotes
    dropped; a sourced or eval'd text, a login shell, or a builtin handed a built name. A script
    that may is kept off the shim, which holds only while it is first on the PATH searched:
    `bash -c 'PATH=<d>:$PATH; tailscale'`, `export 'PATH=<d>'` and `. file` each stepped past it.
    """
    return (any(_R28D_PATH_OWN.search(_t) for _t in (script, _r26d_strip_single(script), _r29d_unquoted(script)))
            or bool(_R29D_SHIM_OFF.search(script)) or _r29d_names_built(script)
            # A nested shell's -c script that builds a word may build PATH= itself (review 1017a).
            or any(_r25d_builds(_a.strip("'\"")) for _a in _R30D_NESTED_C.findall(script)))


def _r19d_path_candidates(script, env, cwd):
    """Each tailscale `script` names by a path that exists, read against `env` and `cwd`.

    Also once its variables are expanded, the script's own assignments included (review 1016b:
    `d=/usr/bin; t=tail; $d/${t}scale` named no path the pattern could see), and once its quotes are
    dropped, as the shell drops them (review 1017a: `"<d>"/tailscale`, `<d>/tail'scale'` and
    `"$D"/${T%x}` were read as `/tailscale` or as no path at all). A directory the reader cannot
    resolve (`"$(…)"/tailscale`, `D=$(…); $D/tailscale`), or a relative path after a `cd` it cannot
    follow, may be any directory: the default PATH's and the run PATH's tailscale are judged, as
    _r29d_cd_bases judges an unresolved `cd`.
    """
    _out = []
    _senv = _r25d_script_env(script, env)
    _lits, _open = _r30d_path_literals(script, env, _senv)
    _bases, _cd_open = _r29d_cd_bases(script, _senv, env, cwd or os.getcwd())
    for _lit in _lits:
        # An unset variable is empty, as the shell reads it (review 1013a: `$PREFIX/bin/tailscale`
        # with PREFIX unset runs /bin/tailscale, and was read as a path that does not exist); a set
        # one is read with the script's own names (review 1017a: only the run's were).
        _lit = re.sub(r"\$\{?(\w+)\}?", lambda _m: _senv.get(_m.group(1), ""), os.path.expanduser(_lit))
        _open = _open or bool(re.search(r"[$`]", _lit)) or (_cd_open and not _lit.startswith("/"))
        for _base in _bases:
            _p = os.path.join(_base, _lit)
            _out.append(_p if os.path.exists(_p) else None)
    if _open:
        _out += [shutil.which("tailscale", path=_p)
                 for _p in (_R19D_DEFAULT_PATH, _r28d_no_shim(env.get("PATH", os.defpath)))]
    return _out


def _r30d_path_literals(script, env, senv):
    """(each `…/tailscale` literal `script` names, as written and unquoted, expanded or not; whether one is open).

    Open: joined to what goes before it (`$(…)/tailscale`, `` `…`/tailscale ``), so no directory was read.
    """
    _lits, _open = set(), False
    for _t in (script, _r29d_unquoted(script)):
        for _x in (_t, _r23d_expand_vars(_t, senv)):
            for _m in _R19D_SCRIPT_PATH.finditer(_x):
                _lits.add(_m.group(1))
                _open = _open or (_m.start() > 0 and _x[_m.start() - 1] not in " \t\n;&|(<>='\"")
        _lits |= _r29d_built_last(_t, env)
    return _lits, _open


# A directory change a script makes, and its target if it names one (after `--`, review 1017a: the
# `--` was read as the target, so `cd -- <d> && ./tailscale` was judged against `<start>/--`).
_R29D_CD = re.compile(r"(?:^|[\s;&|(])(?:cd|pushd)\b(?:[ \t]+(?:-[LPe@]+[ \t]+)*(?:--(?=[\s;&|)]|$)[ \t]*)?"
                      r"([^\s;&|)]+))?")
# A path whose last word the script builds (`<d>/tail$(:)scale`, `<d>/${T%x}`): judged as `<d>/tailscale`.
_R29D_BUILT_LAST = re.compile(r"(?<![\w.~$/:-])((?:~|\$\{?\w+\}?|\.{1,2})?[\w./~-]*)/([^\s/;&|<>]+)")


def _r29d_built_last(script, env):
    """`<dir>/tailscale` for each `<dir>/<word>` in `script` whose last word is built and may spell it."""
    _senv = _r25d_script_env(script, env)
    return {_r23d_expand_vars(_d, _senv) + "/tailscale"
            for _d, _w in _R29D_BUILT_LAST.findall(_r26d_strip_single(script))
            if _r25d_builds(_w) and _r26d_may_spell(_w, script, env)}


def _r30d_cd_unresolved(target, cdpath):
    """Is the (expanded) `cd` target one the reader cannot resolve: `-`, built, or relative under CDPATH?"""
    return (target == "-" or bool(_R26D_UNRESOLVED.search(target)) or "$" in target
            or (cdpath and not target.startswith(("/", "~"))))


def _r29d_cd_bases(script, senv, env, start):
    """(the directories a relative path in `script` may be read against, whether one is unresolved).

    `start`, then each `cd`'s. Review 1016f: `cd <d> && ./tailscale` was read against the run's
    directory only. A target the reader cannot resolve (`cd "$(…)"`, `cd -`) may be any directory,
    so the default PATH's and the run PATH's directories, where the machine's binary would be, are
    judged as well, and the caller judges any relative path's binary on those PATHs (review 1017a:
    `cd "$(echo /usr)" && ./bin/tailscale` was joined to each of them, and found nowhere). So is a
    relative target under CDPATH, which `cd` searches before the current directory.
    """
    _bases, _cur, _unresolved = [start], start, False
    _cdpath = "CDPATH" in script or bool(env.get("CDPATH"))
    for _m in _R29D_CD.finditer(script):
        _t = _r23d_expand_vars(_r29d_unquote(_m.group(1) or "~"), senv)
        if _r30d_cd_unresolved(_t, _cdpath):
            _bases += (_R19D_DEFAULT_PATH + os.pathsep + _r28d_no_shim(env.get("PATH", os.defpath))).split(os.pathsep)
            _unresolved = True
            continue
        _t = (senv.get("HOME") or os.path.expanduser("~")) + _t[1:] if _t.startswith("~") else _t
        _cur = os.path.join(_cur, _t)
        _bases += [_cur, os.path.join(start, _t)]
    return list(dict.fromkeys(_bases)), _unresolved


def _r20d_argv_programs(cmd, kw):
    """The tailscale binaries a shell-less argv may run as its program (past any wrappers).

    Behind a wrapper that may reset PATH, both the PATH it was given and the default one: sudo
    with no secure_path (Arch's default sudoers), and runuser or su without -l, keep the caller's
    (review 1015a: only the default PATH was judged, so a tailscale found on the run's PATH alone
    went through).
    """
    _out = []
    # A long option that is only a prefix of a value-taking one is read every way (_r25d_readings).
    _readings = _r25d_readings(cmd) if isinstance(cmd, (list, tuple)) else [True]
    for _prog, _path in {_r18d_ts_program(cmd, kw, _pv) for _pv in _readings}:
        if _prog is None:
            continue
        if os.sep in _prog:
            _out.append(_prog)
            continue
        _paths = [_R19D_DEFAULT_PATH, _r20d_run_env(kw).get("PATH", os.defpath)] if _path is None else [_path]
        _out += [shutil.which("tailscale", path=_p) for _p in _paths]
    return _out


class _R15dNoSystemTailscale:
    """A module's subprocess handle, refusing a `tailscale` that is not a part's own stand-in."""

    def __init__(self, real, src="subprocess"):
        self._real = real
        # The sys.modules entry whose run/Popen tells a stand-in from the real. Not `real`'s own:
        # from part05 on, `real` is nosudo_runner's shim, which forwards to the real spawner, and
        # judged by its own run it read as a stand-in and let the machine's tailscale run.
        self._src = src

    def __getattr__(self, name):
        return getattr(self._real, name)

    def _system_tailscale(self, cmd, kw, how="run"):
        if getattr(sys.modules.get(self._src), how, None) not in _r16d_real_spawners(how):
            return False
        _sh = _r16d_shell_text(cmd, kw)
        if _sh is not None:
            _hits = _r19d_script_candidates(_sh, kw, None if kw.get("shell") else cmd)
            return any(not _r19d_stand_in(_h) for _h in _hits)
        _hits = _r20d_cmdline_candidates(cmd, kw) + _r20d_argv_programs(cmd, kw)
        return any(_h is not None and not _r19d_stand_in(_h) for _h in _hits)

    def _guard_shell(self, cmd, kw, how):
        """(cmd, kw) for a shell that may name tailscale: under bash, with _r16d_ts_shell_env's functions.

        One that may is one that names it, or builds a word at run time (_r25d_builds; review
        1016b: only the literal word was, so `T=tail; ${T}scale version` ran the machine's binary
        with no function to stop it). The functions judge the word as the shell has built it.
        """
        _sh = _r16d_shell_text(cmd, kw)
        if _sh is None or getattr(sys.modules.get(self._src), how, None) not in _r16d_real_spawners(how):
            return cmd, kw
        # Named, also once unquoted or expanded (review 1016c: `tail'scale' version` and
        # `tail"scale"` named it with no literal word), or only built: the shell it was given,
        # behind the shim (_R26D_SHIM), as production runs it (review 1016e: a named one ran under
        # bash, so a bashism in system_ops' `tailscale status --json || echo '{}'` would pass here
        # and fail under /bin/sh). Bash and the functions where the shim cannot hold (_r26d_shim).
        if ("tailscale" not in _sh and not _r20d_names_tailscale(_sh, _r20d_run_env(kw))
                and not _r25d_builds(_sh)):
            return cmd, kw
        _shimmed = self._r26d_shim(cmd, kw)
        if _shimmed is not None:
            return _shimmed
        kw = dict(kw, env=_r16d_ts_shell_env(_r20d_run_env(kw)))
        if kw.get("shell"):
            kw["executable"] = "/bin/bash"      # only bash reads exported functions; dash does not
        else:
            # The shell word, after any wrappers; the functions go on its own `env`, so a wrapper
            # that clears the environment (`env -i`, sudo) in front of it cannot drop them.
            _i = _r18d_dash_c(cmd)[0]
            cmd = (list(cmd[:_i]) + ["/usr/bin/env"]
                   + ["%s=%s" % _f for _f in _r16d_ts_shell_funcs().items()] + ["/bin/bash"]
                   + list(cmd[_i + 1:]))
        return cmd, kw

    @staticmethod
    def _r26d_shim(cmd, kw):
        """(cmd, kw) for a shell that may name tailscale: its own shell, with _R26D_SHIM first on PATH.

        On the run's own environment, so only for a shell=True run or a shell that is the argv's
        first word: behind a wrapper (env -i, sudo, runuser) the PATH it would search is that
        wrapper's to set, so such a shell keeps the bash route (None).
        """
        if not kw.get("shell") and _r18d_dash_c(cmd)[0] != 0:
            return None
        # ...and a script that sets PATH itself or looks the name up past it: the shim is found
        # only while it is first on the PATH searched (review 1016e: `PATH=<dir>:$PATH; ${T}scale`,
        # `export PATH=…` and `command -p ${T}scale` ran the machine's binary). The functions
        # answer a name whatever PATH holds.
        if _r29d_may_set_path(_r16d_shell_text(cmd, kw)) or (not kw.get("shell") and _r29d_login(cmd)):
            return None
        _env = _r20d_run_env(kw)
        return cmd, dict(kw, env=dict(_env, PATH=_R26D_SHIM + os.pathsep + _env.get("PATH", os.defpath),
                                      R26D_TS_ROOTS=os.pathsep.join(_R19D_STAND_IN_ROOTS)))

    def _r20d_judged(self, name, how, cmd, a, kw):
        """Run subprocess.`name` (which starts its process through `how`) unless it is the machine's tailscale."""
        cmd, kw = self._guard_shell(cmd, kw, how)
        if self._system_tailscale(cmd, kw, how):
            _r15d_ts_refused.append(cmd if isinstance(cmd, str) else " ".join(map(str, cmd)))
            raise FileNotFoundError(2, "No such file or directory (the unit suite answers the "
                                       "machine's own tailscale as CI's runner does)", "tailscale")
        return getattr(self._real, name)(cmd, *a, **kw)

    def run(self, cmd, *a, **kw):
        return self._r20d_judged("run", "run", cmd, a, kw)

    def Popen(self, cmd, *a, **kw):  # noqa: N802 - subprocess's own name
        return self._r20d_judged("Popen", "Popen", cmd, a, kw)

    # The real module's own helpers start their process through its run/Popen, past this wrapper,
    # so __getattr__ handing them over let them run the machine's tailscale unjudged (review 1013a).
    def check_output(self, cmd, *a, **kw):
        return self._r20d_judged("check_output", "run", cmd, a, kw)

    def call(self, cmd, *a, **kw):
        return self._r20d_judged("call", "Popen", cmd, a, kw)

    def check_call(self, cmd, *a, **kw):
        return self._r20d_judged("check_call", "Popen", cmd, a, kw)

    # getoutput/getstatusoutput call the real module's check_output, past this wrapper, so they
    # are rebuilt on the judged one, as the stdlib writes them (review 1015a).
    def getstatusoutput(self, cmd, *, encoding=None, errors=None):
        try:
            _data, _rc = self.check_output(cmd, shell=True, text=True, stderr=self._real.STDOUT,  # nosec B604 - the stdlib's own getoutput, judged
                                           encoding=encoding, errors=errors), 0
        except Exception as _ex:  # noqa: BLE001 - CalledProcessError, from whichever subprocess raised it
            # Monkey-patched, check_output may raise the ORIGINAL module's class, not this one's.
            if type(_ex).__name__ != "CalledProcessError":
                raise
            _data, _rc = _ex.output, _ex.returncode
        return _rc, _data[:-1] if _data[-1:] == "\n" else _data

    def getoutput(self, cmd, *, encoding=None, errors=None):
        return self.getstatusoutput(cmd, encoding=encoding, errors=errors)[1]


# (module, attribute holding its subprocess, the sys.modules entry that attribute stands for).
# Wrapped as soon as each module is loaded and again before every part: part05 reinstalls
# nosudo_runner's shim over every module's subprocess, which replaced this answer for the rest of
# the run. _core is not imported here: under a bare `python tests/unit_test.py` (CI)
# eventlet.monkey_patch() has to come first, and part01's app import is what does it. system_ops
# is (tailscale_integration imports it), and is wrapped below; monkey_patch later patches the same
# subprocess module object the wrapper holds, in place.
_R16D_TS_HANDLES = (("panel.ops.tailscale_integration", "subprocess", "subprocess"),
                    ("panel.ops.system_ops", "subprocess", "subprocess"),
                    ("panel.ops.ssh_manager._core", "_real_subprocess", "__original_module_subprocess"))


def _r16d_wrap_ts_handles():
    """Wrap each loaded module's handle that is not wrapped already; the modules still unloaded."""
    _unloaded = []
    for _mod, _attr, _src in _R16D_TS_HANDLES:
        _m = sys.modules.get(_mod)
        if _m is None:
            _unloaded.append(_mod)
        elif not isinstance(getattr(_m, _attr, None), _R15dNoSystemTailscale):
            setattr(_m, _attr, _R15dNoSystemTailscale(getattr(_m, _attr), _src))
    return _unloaded


# A module's helper cache, pinned: it records a read that finds it unread while the module's `os`
# is the real one, which is the machine's disk answering (review 1016e: part03 reset the cache to
# None, and the rest of the part asked the disk; on a machine without the helper that read cached
# False, so "what each part left" alone could not see it). A part that stubs the module's os to
# drive the read itself (part10) is not recorded.
_r28d_disk_reads = []      # (part, module) whose pinned cache answered from the disk
_r28d_part = [None]        # the part running now


def _r28d_pinned_state(modname, value):
    """A `_HELPER_STATE` dict for module `modname` holding `value`, recording disk reads (above)."""
    class _R28dPinned(dict):
        def __getitem__(self, key):
            _v = dict.__getitem__(self, key)
            if key == "present" and _v is None and getattr(sys.modules.get(modname), "os", None) is os:
                _r28d_disk_reads.append((_r28d_part[0], modname))
            return _v
    return _R28dPinned(present=value)


def _r28d_pin(module):
    """Pin `module`'s helper cache as absent, in a recording dict (_r28d_pinned_state)."""
    if type(module._HELPER_STATE).__name__ != "_R28dPinned":
        module._HELPER_STATE = _r28d_pinned_state(module.__name__, False)
    module._HELPER_STATE["present"] = False


class _R16dWrapOnLoad:
    """Wraps a handle the moment its module finishes loading, so no part runs before it."""

    def find_spec(self, name, path=None, target=None):
        if name not in {_m for _m, _a, _s in _R16D_TS_HANDLES}:
            return None
        for _f in sys.meta_path:
            _spec = None if _f is self else getattr(_f, "find_spec", lambda *_a: None)(name, path, target)
            if _spec is not None and _spec.loader is not None:
                break
        else:
            return None
        _exec = _spec.loader.exec_module

        def _exec_then_wrap(module):
            _exec(module)
            _r16d_wrap_ts_handles()
            # _core is first loaded inside part01, after that part's pin: pinned here too, or part01
            # ran with its helper cache unread and the first read asked the disk (review 1016e).
            if isinstance(getattr(module, "_HELPER_STATE", None), dict):
                _r28d_pin(module)
        _spec.loader.exec_module = _exec_then_wrap
        return _spec


sys.meta_path.insert(0, _R16dWrapOnLoad())
_r16d_wrap_ts_handles()

# The parts, in order: each runs its checks as it is imported. Named, never globbed, so that the
# gate below can tell a part left off this list from one that ran.
# part16 to part19 run BEFORE part15, which must stay last: it ends the run with a look for
# threads left running, and that look has to come after every part that could have started one.
# part19 comes right after part18, whose app, client and row helpers it imports. part20 (the debug
# report) builds its own app and imports only part01. part21 to part23 are the debug report's other
# sections; part21 imports part01 and part12, the latter for one route check. part24 runs the cross-builder contracts as
# real producer-consumer pairs. part29 reads the CI workflows, and imports only part01 and part06;
# part30 reads them too (the review's fuzz and CodeQL-trigger fixes), importing part01, 05, 06 and 29.
# part40 (renaming in the file browser) drives routes on part12's app, importing part01 and part12.
# part42 (zizmor and Harden-Runner) reads the workflows as text, importing part01, 03, 05, 06, 29 and 30.
# part43 (the port an import stores) drives the import route on part12's app, importing part01 and 12.
# part44 (system_ops and debug-report fixes from the 2026-10-08 review) imports part01, 02, 10 and 20.
# part47 (small page behaviours from the 2026-10-08 review, run in node) imports part01, 05 and 12.
# part49 (raw-cfg logtimestamp and failed-backup partial archives) drives part12's app; imports part01, 12.
# part50 (documentation-only pull requests skip the heavy checks) reads the workflows and runs
# .github/scripts/pr_scope.py; imports part01, 05 and 29.
# part51 (review 1011: the recovery CLI's workers, system_ops, ssh core and reboot fixes) imports
# part01, 02, 05 and 20.
# part52 (fixes from the 2026-10-11 review: game files, debug report, helper, routes) drives part12's
# app in a real bash over a throwaway home; imports part01, 05 and 12.
# part53 (the 2026-10-11 review's routes, installer, tools and page fixes) drives part12's app and
# runs node/bash on its own fixtures; imports part01, 05, 12 and 47.
# part54 (review 1011b: core, system_ops, ssh-core and Tailscale Funnel fixes) runs part32's fake
# tailscale on its own PATH; imports part01, 02, 12, 20 and 51 (part12's app for two page renders).
# part55 (the second 2026-10-11 review: game files, debug report, helper, routes) drives part12's
# app in a real bash over a throwaway home, and node on one page function; imports part01, 05, 12, 47.
# part56 (the 2026-10-11 second review's routes, tools and page fixes) drives part12's app and runs
# node on its own fixtures; imports part01, 05, 12 and 47.
# part57 (review 1011c: core, system_ops, ssh-core and reboot fixes) drives part12's app; imports
# part01, 02, 10, 12 and 20.
# part58 (the third 2026-10-11 review: game files, bots, debug report, helper, routes) drives
# part12's app in a real bash over a throwaway home, with stand-in tools; imports part01, 05, 12.
# part59 (the 2026-10-11 third review's routes, tools and page fixes) drives part12's app and runs
# node on its own fixtures; imports part01, 05, 12, 47 and 56 (the js_coverage module part56 holds).
# part60 (New file / New folder in the file browser) drives part12's app in a real bash over a
# throwaway home, as part40 does for rename; imports part01, 12 and 40.
# part61 (review 1011d: system_ops, Tailscale Serve, ssh-core and notify fixes) drives part12's app
# for two routes; imports part01, 02, 12, 20 and 47.
# part62 (the fourth 2026-10-11 review: game files, debug report, helper, routes) drives part12's
# app in a real bash with stand-in tools; imports part01, 05 and 12.
# part63 (the fourth 2026-10-11 review's routes, tools, page and i18n fixes, builder C) drives
# part12's app and runs node and bash on its own fixtures; imports part01, 05, 12 and 47.
# part64 (review 1011e: core, backup, ssh-core and reboot fixes, builder A) drives part12's app and
# database with stand-ins, and node on one page function; imports part01, 02, 12, 20, 47 and 61
# (part61's transport tripwire).
# part65 (the fifth 2026-10-11 review: game files, debug report, helper, routes, builder B) drives
# part12's app, the capture in a real bash with a stand-in tmux; imports part01, 05 and 12.
# part66 (the fifth 2026-10-11 review's routes, tools, page and i18n fixes, builder C) drives
# part12's app and runs node on its own fixtures; imports part01, 05, 11, 12, 20, 47 and 61 (part61's
# close-panel-port helpers, part11's transport stand-in).
# part67 (review 1012a: core, backup, ssh-core and reboot fixes, builder A) drives part12's app and
# database with stand-ins, and node and bash on its own fixtures; imports part01, 02, 12, 14, 20, 47,
# 61 and 64 (part14's update-status stand-in, part61's transport tripwire, part64's firewall stand-in).
# part68 (review 1012a: cron, game files, helper and routes, builder B) drives part12's app with
# stand-ins, and the crontab pipeline in a real bash; imports part01, 05 and 12.
# part69 (the sixth review's routes, tools, page and i18n fixes, builder C) drives part12's app and
# runs node on its own fixtures; imports part01, 05, 12 and 47.
# part70 (review 1012b: core, backup, ssh-core and reboot fixes, builder A) drives part12's app and
# database with stand-ins, and node on its own fixtures; imports part01, 12, 20 and 47.
# part71 (review 1012b: game files, debug report, helper and routes, builder B) drives part12's app
# with stand-ins, and node on the GMod Content card; imports part01, 05, 12 and 47.
# part72 (the seventh review's routes, tools, page and i18n fixes, builder C) drives part12's app
# and runs node on its own fixtures; imports part01, 05, 12, 47 and 69 (part69's @media reader).
# part73 (review 1012c: core, backup, ssh-core and reboot fixes, builder A) drives part12's app and
# database with stand-ins, and node on its own fixtures; imports part01, 12, 20, 47 and 51.
# part74 (review 1012c: game files, debug report, helper and routes, builder B) drives part12's app
# with stand-ins, and the remote restart-flags form in a real bash; imports part01, 05 and 12.
# part75 (the eighth review's routes, tools, page and i18n fixes, builder C) drives part12's app
# and runs node on its own fixtures; imports part01, 05, 12, 16 and 47.
# part76 (review 1012d: core, ssh-core, system and reboot fixes, builder A) drives part12's app and
# database with stand-ins, and a real bash over its own stand-in programs; imports part01, 12, 20.
# part77 (review 1012d: moderation, console sends, system_ops, debug report and routes, builder B)
# drives part12's app with stand-ins; imports part01 and 12.
# part78 (the ninth review's routes, tools, page and i18n fixes, builder C) drives part12's app
# and runs node and bash on its own fixtures; imports part01, 05, 12, 47 and 72 (part72's DOM).
# part79 (the tenth review's core, ssh-core, system and locale fixes, builder A) drives part12's
# stubs and runs bash on install.sh's own text and stand-in sudo/ufw; imports part01, 05 and 12.
# part80 (review 1013a: gamedig ports, port resync, audits of raised host calls, the local
# C.UTF-8 locale, builder B) drives part12's app with stand-ins, and `env` for real; imports part01
# and 12.
# part81 (the tenth review's routes, tools, page and i18n fixes, builder C) drives part12's app
# and runs node and bash on its own fixtures; imports part01, 05, 12, 47 and 72 (part72's DOM).
# part82 (the eleventh review's core, system and helper fixes, builder A) drives part12's app with
# stand-ins and runs node on the page scripts; imports part01, 05, 12 and 47.
# part83 (review 1015a: ufw limit read-back, bracketed hosts, file guards, audits, builder B) drives
# part12's app with stand-ins, and bash over its own fixture tree; imports part01 and 12.
# part84 (the eleventh review's routes, tools, page and i18n fixes, builder C) drives part12's app
# and runs node on its own fixtures; imports part01, 05, 12, 47 and 72 (part72's DOM).
# part85 (the twelfth review's install, test-runner, core and report fixes, builder A) runs bash over
# install.sh's and run-tests.sh's own functions in throwaway dirs, and part18's app on its own
# database file; imports part01, 05 and 18.
# part86 (review 1015c: bracketed wizard hosts, saves through a symlink, every sudo asked, unreachable
# catch-alls, builder B) drives part12's app with stand-ins, bash over its own fixture tree and
# stand-in sudo, and node on panel.js; imports part01, 05, 12, 47 and 83.
# part87 (the twelfth review's page, script and i18n-tool fixes, builder C) drives part12's app and
# its socket, and runs node on its own fixtures; imports part01, 05, 12 and 47.
# part88 (review 1015d: helper, install, test runner, system_ops, prefs and docs, builder A) runs the
# helper's and system_ops' functions on stand-ins, bash over install.sh's and run-tests.sh's own
# functions in throwaway dirs, and part12's app; imports part01, 05 and 12.
# part89 (review 1015d: Close Port 22 and every ufw close read back, the console log refused to the
# file writers, a chunked save's leftovers, builder B) drives part12's app with stand-ins and bash
# over its own fixture tree; imports part01 and 12.
# part90 (the thirteenth review's page and script fixes, builder C) drives part12's app and runs node
# on its own fixtures; imports part01, 05, 12, 47 and 87 (part87's DOM).
# part91 (Tailscale on the panel's host through the helper, never the panel account as operator,
# builder T) runs the helper and the Tailscale code on stand-ins, and bash over install.sh's and
# uninstall.sh's own functions with a stand-in tailscale; imports part01 and 05.
# part92 (decisions 1016a: the debug report's security posture on the panel's page only, never the
# downloaded file, builder R) runs the report's network and access sections and its assembler on
# stand-ins, and node on the page's script; imports part01, 05, 47 and 87 (part87's DOM).
# part93 (review 1016b: Tailscale SSH on the panel host only by the owner's choice at install, the
# helper's restore and self-update targets, the debug report, monitoring, install and uninstall,
# builder A) runs the helper and the panel's modules on stand-ins, part12's app, and bash over
# install.sh's and uninstall.sh's own functions in throwaway dirs, and the debug report's
# assembler through part92's fixture; imports part01, 05, 12 and 92.
# part94 (review 1016b: an SSH port move on a Tailscale-SSH host, a v6 LIMIT kept, reads without
# sudo, an adopted account's uninstall, the config writers and the console log, builder B) drives
# part12's app with stand-ins and bash over its own fixture tree; imports part01, 10, 12 and 89.
# part95 (the fourteenth review's page and script fixes, builder C) drives part12's app and runs node
# on its own fixtures; imports part01, 05, 12, 47 and 87 (part87's DOM).
# part96 (review 1016b, the integrator: Tailscale Serve and Funnel publish only the panel's own port,
# recorded root-side) runs the helper on stand-in socket tables, install.sh's functions under bash,
# and part12's app for change-port and the setup wizard; imports part01, 05 and 12.
# part97 (review 1016c: the snapshot prune and an operator's link, the helper's data/ link chain,
# one port reader, the monitor's reachability without sudo, builder A) runs install.sh's functions
# under bash in throwaway dirs, the helper and the panel's modules on stand-ins, and part12's app;
# imports part01, 05 and 12.
# part98 (review 1016c: sshd's ports on a socket-activated Tailscale-SSH host, the SSH port card, and
# the route and ssh_manager fixes of builder B) drives part12's app with stand-ins; imports part01
# and 12.
# part99 (the fifteenth review's page and script fixes, builder C) drives part12's app and runs node
# on its own fixtures; imports part01, 05, 12, 47 and 87 (part87's DOM).
# part100 (Ubuntu's phased updates respected, never forced) runs bash over its own stand-ins, drives
# part12's app with every host call stubbed, and node for the card; imports part01, 05, 12 and 47.
# part101 (review 1016e: the helper's DB repair walks data/ itself, a hard-linked root symlink is no
# operator's link, install's port picker and uninstall's port reader, the monitor's maintenance probe
# without sudo, builder A) runs the helper on stand-ins and install.sh/uninstall.sh text under bash;
# imports part01, 05 and 12.
# part102 (review 1016e: GMod content never written under a panel server's account, the backup
# prune beside a running backup, SSH ports, builder B) drives part12's app with stand-ins; imports
# part01 and 12.
# part103 (the sixteenth review's page and script fixes, builder C) drives part12's app and runs node
# on part87's DOM; imports part01, 05, 12, 47 and 87.
# part104 (review 1016f: discovery's installed-mods read bounded on both forms and nothing read as
# root for a home with no account, the remote mount.cfg read's rc, a whitelist string, gamedig's
# check as nobody, install.sh's apt through sudo, the legacy OS update detached, builder A) runs
# the helper and the scan in their own processes, shell text under bash on stand-ins; imports
# part01, 05, 12 and 43.
# part105 (review 1016f: the stale backup lock swept before the headroom prune, an unread GMod content
# scan is not "no content", every live invite revocable, builder B) drives part12's app with
# stand-ins and runs bash and node; imports part01, 12 and 71.
# part106 (the seventeenth review's page and script fixes, builder C) drives part12's app and runs
# node on part87's DOM; imports part01, 05, 12, 47 and 87.
# part107 (review 1017a: a hand-edited whitelist entry removable, the OS-update guard sees the
# panel's own job, install.sh's every apt-get non-interactive, the privilege model page-only in the
# debug report, builder A) drives part12's app with stand-ins, real pgrep over stand-in processes,
# install.sh under bash, and part92's report harness; imports part01, 05, 12, 43 and 92.
# part108 (review 1017a: a remote root write creates its directory and change_ssh_port reads its rc,
# GMod content held by a server's account named on any ordering, a failed panel restart keeps the
# old port reachable, the unread-firewall close refusal audited, builder B) runs the rendered write
# in bash under a temp root and drives part12's app with stand-ins; imports part01 and 12.
# part109 (the eighteenth review's page and script fixes, builder C) drives part12's app and runs
# node through part106's harness; imports part01, 12 and 106.
_PARTS = ("part01", "part02", "part03", "part04", "part05", "part06", "part07", "part08", "part09",
          "part10", "part11", "part12", "part13", "part14", "part16", "part17", "part18", "part19",
          "part20", "part21", "part22", "part23", "part24", "part25", "part26", "part27",
          "part28", "part29", "part30", "part31", "part32", "part33", "part34", "part35", "part36", "part37",
          "part38", "part39", "part40", "part41", "part42", "part43", "part44", "part47", "part49",
          "part50", "part51", "part52", "part53", "part54", "part55", "part56", "part57", "part58",
          "part59", "part60", "part61", "part62", "part63", "part64", "part65", "part66",
          "part67", "part68", "part69", "part70", "part71", "part72", "part73", "part74",
          "part75", "part76", "part77", "part78", "part79", "part80", "part81", "part82", "part83",
          "part84", "part85", "part86", "part87", "part88", "part89", "part90", "part91",
          "part92", "part93", "part94", "part95", "part96", "part97", "part98", "part99", "part100",
          "part101", "part102", "part103", "part104", "part105", "part106", "part107", "part108",
          "part109",
          "part15")


# ── what each part leaves in the eventlet hub ────────────────────────────────────────────────────
# Between two parts nothing of the suite's is waiting on anything, so the hub should hold exactly
# one listener: eventlet tpool's own socket. Anything else was left by the part just run — a
# listener a failed wait never removed, an IOClosed still queued to be thrown into whatever waits
# next, or a greenthread still blocked on a socket. part01's check() sweeps for the first two at
# every check (a leak and its victim can sit inside one part, where this cannot see them); this
# catches what outlives a part, a stuck greenthread included, and never touches it.
def _hub_leftovers():
    """What the hub holds besides tpool's socket, as text; None when there is no hub to read."""
    hubs = sys.modules.get("eventlet.hubs")
    hub = getattr(getattr(hubs, "_threadlocal", None), "hub", None)
    if hub is None:
        return None
    rsock = getattr(sys.modules.get("eventlet.tpool"), "_rsock", None)
    tpool_fd = rsock.fileno() if rsock is not None else None

    def _whose(ls):
        g = ls.greenlet
        if g.dead or g.parent is None:
            return "a dead greenlet" if g.dead else "the suite's own greenlet"
        # A started greenlet has no `run` left to name; its outermost frame is what it was spawned
        # with — for an eventlet GreenThread, GreenThread.main, holding the spawned `function`.
        f = g.gr_frame
        while f is not None and f.f_back is not None:
            f = f.f_back
        fn = f.f_locals.get("function") if f is not None else None
        code = getattr(f, "f_code", None)
        return "a greenthread running %s" % (
            getattr(fn, "__qualname__", None) or getattr(code, "co_qualname", None)
            or getattr(code, "co_name", "?"))
    left =["%s listener on fd %d, for %s" % (ev, fd, _whose(ls))
            for ev, bucket in hub.listeners.items() for fd, ls in bucket.items() if fd != tpool_fd]
    left += ["%s secondary listener on fd %d, for %s" % (ev, fd, _whose(ls))
             for ev, bucket in hub.secondaries.items() for fd, waiting in bucket.items()
             for ls in waiting]
    left += ["IOClosed queued for fd %d, for %s" % (ls.fileno, _whose(ls)) for ls in hub.closed]
    return left


_hub_after = []
# The temp tracking must still be the module's after every part: a stub restored to a value saved
# before the tracking went in, or a reload of tempfile, would make every later temp path go
# unrecorded and unremoved, while the gate below, counting the runner's own dirs, still passed.
_r16d_tmp_swapped = []
_r16d_tmp_runner_made = len(_r15d_made_tmp)
_path_moved = []           # (part, what it added to / took off sys.path)
# Every part runs as on CI's runner, which has no root helper: the cached "is it installed?" and
# the panel.conf beside it are pinned before each one (review 1016c: #436's boot step and the port
# change read the machine's real helper and panel.conf; the cache starts unread, so the first
# read decided for the whole run, and on a host with the panel installed parts 22, 54, 75 and 91
# took the helper's branch and ran its verbs). A part that wants the helper's branch patches it.
# The panel.conf pinned is system_ops' (_R25A_PANEL_CONF, which the port and boot paths act on).
# The debug report's two readers of it (install.panel_conf_text, root_pieces._panel_conf_line)
# find it beside the helper's path, and only print yes/no from it: a check that asserts on that
# line passes its own path or patches _root_dir (part21, part22).
# Read from sys.modules, not imported: importing ssh_manager here, before part01, would change
# what is loaded ahead of eventlet's patching.
_R26D_NO_CONF = os.path.join(_RUN_DATA, "no-helper", "panel.conf")
_r26d_pins = []            # (part, the cache it found, what it holds once pinned)


def _r26d_pin_helper(part):
    """Pin the helper as absent for `part` in each loaded module; record what the part before left."""
    _mods = [sys.modules.get(_m) for _m in ("panel.ops.system_ops", "panel.ops.ssh_manager._core")]
    _found = tuple(getattr(_m, "_HELPER_STATE", {}).get("present", "not loaded") for _m in _mods)
    _r28d_part[0] = part
    for _m in _mods:
        if _m is not None:
            _r28d_pin(_m)
    if _mods[0] is not None:
        _mods[0]._R25A_PANEL_CONF = _R26D_NO_CONF
    _r26d_pins.append((part, _found, tuple(getattr(_m, "_HELPER_STATE", {}).get("present", False)
                                            for _m in _mods), getattr(_mods[0], "_R25A_PANEL_CONF", None)))


for _part in _PARTS:
    _path_before = list(sys.path)
    _r26d_pin_helper(_part)
    # Again before each part: part05 reinstalls nosudo_runner's shim over every module's subprocess,
    # and that replaced this answer for the rest of the run.
    _r16d_wrap_ts_handles()
    importlib.import_module("unit." + _part)
    _hub_after.append((_part, _hub_leftovers()))
    if (tempfile.mkdtemp is not _r15d_tracked_mkdtemp or tempfile.mkstemp is not _r15d_tracked_mkstemp
            or tempfile._mkstemp_inner is not _r16d_tracked_mkstemp_inner):
        _r16d_tmp_swapped.append(_part)
        tempfile.mkdtemp, tempfile.mkstemp = _r15d_tracked_mkdtemp, _r15d_tracked_mkstemp
        tempfile._mkstemp_inner = _r16d_tracked_mkstemp_inner
    # An entry added or taken off, or a tools/ directory moved AHEAD of the repository root. Not
    # the plain order: part01 puts the root (already on it) first, which shadows nothing. But
    # tools/ is on sys.path already when the suite runs under tools/nosudo_runner.py, BEHIND the
    # root, so a leaked insert(0, tools) only reorders — and puts tools/run.py, serve.py and the
    # rest ahead of every top-level name the panel and the parts import.
    _ahead = [_p for _p in sys.path[:sys.path.index(_root) if _root in sys.path else len(sys.path)]
              if os.path.realpath(_p).startswith(os.path.join(os.path.realpath(_root), "tools"))]
    if set(sys.path) != set(_path_before) or _ahead:
        _path_moved.append((_part, sorted(set(sys.path) ^ set(_path_before)) or _ahead))
# What the LAST part left, which no pin after it reads (review 1016f lead).
_r29d_last_left = tuple(getattr(sys.modules.get(_m), "_HELPER_STATE", {}).get("present", "not loaded")
                        for _m in ("panel.ops.system_ops", "panel.ops.ssh_manager._core"))
# Counted HERE, before the controls below make temp dirs of their own: the tailscale control's dir
# was recorded after the loop, so "no part's path was recorded" could never be true (review 1012b).
_r16d_tmp_parts_made = len(_r15d_made_tmp) - _r16d_tmp_runner_made
from unit.part01 import check, results, hub_leaks, hub_swept  # noqa: E402

# A part that leaves a directory on sys.path (tools/, tools/js_coverage) hands every later import of
# a top-level name in it — `run`, `walk`, `flows`, `serve` — that directory's file. part14, part53
# and part56 each put it back and say so; this names any part, present or future, that does not.
# ...and what each part LEFT is held too, not only what the pin wrote (review 1016e: the check
# read the values set one line before it, so part03 resetting the cache to "unread" mid-part, and
# answering the rest of its checks from the machine's real helper, passed). What part N left is
# what the pin before part N+1 found: still False in both modules, as a part that saved and
# restored the pinned value leaves it.
_r28d_left = [(_PARTS[_i - 1], _p[1]) for _i, _p in enumerate(_r26d_pins) if _i and _p[1] != (False, False)]
_r28d_left += [(_PARTS[-1], _r29d_last_left)] if _r29d_last_left != (False, False) else []
check("unit suite: every part ran as on a machine without the root helper, and left the cache as "
      "pinned; the run started with the cache unread, which the disk would have answered (control)",
      all(_p[2] == (False, False) and _p[3] in (None, _R26D_NO_CONF) for _p in _r26d_pins)
      and len(_r26d_pins) == len(_PARTS) and _r26d_pins[-1][3] == _R26D_NO_CONF
      and _r26d_pins[0][1][0] is None and not _r28d_left and not _r28d_disk_reads,
      "parts that left the helper cache other than pinned (system_ops, _core): %r; parts whose "
      "cache was read from the disk: %r" % (_r28d_left[:6], sorted(set(_r28d_disk_reads))[:6]))
check("unit suite: no part leaves sys.path changed for the parts after it",
      not _path_moved, "; ".join("%s: %s" % _pm for _pm in _path_moved))

# The env-reset reader against a run of value-taking options: it backtracked exponentially there
# (CodeQL py/redos), so 40 `-C!` words would not finish. Run in a child with a time limit, so a
# pattern that backtracks fails this check by name rather than stall the suite (review 1016c: the
# comment said so while both searches ran in-process, unbounded). The child runs this file's own
# reader, cut out by name, and answers the rows below too, so it is shown to be the same reader.
import json as _r26d_json  # noqa: E402 - only this check needs it

_R26D_READER = ("_R25J_RESET_WORDS", "_R25J_ENV_WORD", "_r25j_long", "_r25j_short", "_r25j_env_resets",
                "_R25JResets", "_R19D_SCRIPT_RESETS")
_R26D_ROWS = (
    "env -i x", "env -v -i x", "env -u PATH x", "env --unse PATH x", "env -u X -i y",
    "env --chdir /x -i y", "env -C! -i x", "env -uPATH x", "env -S x", "env --split-string=x",
    # A value letter inside a cluster takes the next word, and -a/--argv0 takes one (review 1016c).
    "env -vu X -i y", "env -vC /x -i y", "env -0u X -i y", "env -vuPATH y", "env -a x -i y",
    "env --argv0 x -i y", "env --arg x -i y", "env -va x -i y",
    # --ig is --ignore-environment to an env older than --ignore-signal (coreutils 9), and refused
    # as ambiguous by a newer one; --ignore-signal itself resets nothing (review 1016e).
    "env --ig x",
    "env -u X y", "env -C /x y", "env --debug x", "env FOO=1 x", "env -u -u PATH x", "env -vu X y",
    "env -a x y", "env -vC /x y", "env -va -i y", "env --ignore-signal x", "env --ignore-s=INT x")
_R26D_RESETTING = 19     # the rows above `env -u X y` reset; the rest do not


def _r26d_reader_child(timeout=10):
    """(finished in time?, the child's row answers) for this file's reader run in a child process."""
    import ast as _ast
    with open(os.path.abspath(__file__), encoding="utf-8") as _fh:
        _src = _fh.read()
    _defs = [_n for _n in _ast.parse(_src).body
             if getattr(_n, "name", None) in _R26D_READER
             or (isinstance(_n, _ast.Assign)
                 and any(getattr(_t, "id", None) in _R26D_READER for _t in _n.targets))]
    _code = "\n".join(["import json, re, sys"] + [_ast.get_source_segment(_src, _n) for _n in _defs] + [
        'R = _R19D_SCRIPT_RESETS',
        'R.search("env" + " -C!" * 4000 + " x")',
        'R.search("env" + " --" * 4000 + " x")',
        'print(json.dumps([bool(R.search(c)) for c in json.loads(sys.argv[1])]))'])
    try:
        # The real run the runner captured: this file's own reader, in this interpreter.
        _p = _R15D_SP_REAL["run"]([sys.executable, "-c", _code, _r26d_json.dumps(_R26D_ROWS)],  # nosec B603
                                  capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as _ex:  # noqa: BLE001 - TimeoutExpired, of whichever subprocess module ran it
        if type(_ex).__name__ != "TimeoutExpired":
            raise
        return False, None
    return _p.returncode == 0, (_r26d_json.loads(_p.stdout) if _p.returncode == 0 else _p.stderr[-300:])


_redos_ok, _child_rows = _r26d_reader_child()
_resets_rows = {c: bool(_R19D_SCRIPT_RESETS.search(c)) for c in _R26D_ROWS}
check("unit suite: the env-reset reader answers 4000 `-C!` or `--` options at once in a child with a "
      "time limit (no exponential backtracking), still finds -i, -u PATH, -S, a value letter inside a "
      "cluster and an option's value skipped, and not a plain env",
      _redos_ok and _child_rows == list(_resets_rows.values())
      and all(_resets_rows[c] for c in _R26D_ROWS[:_R26D_RESETTING])
      and not any(_resets_rows[c] for c in _R26D_ROWS[_R26D_RESETTING:]),
      repr((_redos_ok, _child_rows, _resets_rows)))


# ── the ordering notes above _PARTS name what each part imports ─────────────────────────────────
# They are the stated contract for where a part may move: a part imported out of order runs
# inside the importing part's import, silently. Corrected by hand twice (part54, then part30, 43,
# 51 and 57), so now read: every note that lists a part's imports must list exactly its
# `from unit.partNN import` lines.
def _r14d_noted_imports(text):
    """{part: set of the numbers its note says it imports}, from the comment block's text.

    Two digits or more (review 1016e: a reader of exactly two digits never matched part100, so its
    note was folded into part99's and never compared, nor named unreadable).
    """
    _re = re
    flat = " ".join(_ln.lstrip("#").strip() for _ln in text.splitlines())
    # A note starts at a part named at a sentence (or clause) start; "part12's app" mid-sentence
    # is not one.
    out = {}
    for _seg in _re.split(r"(?:^|(?<=[.;])\s+)(?=part\d{2,}\b)", flat):
        _m = _re.match(r"(part\d{2,})\b", _seg)
        _l = _re.search(r"\bimport(?:s|ing)\s+(?:only\s+)?(part\d{2,}(?:(?:\s*,\s*|\s+and\s+|,\s+and\s+)"
                        r"(?:part)?\d{2,})*)", _seg)
        if _m and _l:
            out[_m.group(1)] = set(_re.findall(r"\d{2,}", _l.group(1)))
        elif _m and _re.search(r"\bimport(?:s|ing)\b[^.;]*?(?<!\d)\d{2,}\b", _seg):
            # A note that names imports in a wording the reader does not take ("imports parts 01
            # and 12") was dropped silently, not judged (review 1011e): named instead. The digits
            # may follow "part" ("imports from part01"): a word boundary before them read only
            # the bare-number wording (review 1012a).
            out[_m.group(1)] = {"unreadable: " + _seg[:80]}
    return out


def _r17d_imported_modules(node):
    """The modules an import statement names (none for any other node).

    `from unit import idreuse_support` (part16, part18) names the module after `import`: it was not
    followed, so a part import added to such a shared module went unseen (review 1012b).
    """
    import ast as _ast
    if isinstance(node, _ast.Import):
        return [_a.name for _a in node.names]
    if not isinstance(node, _ast.ImportFrom):
        return []
    # Relative, from inside tests/unit: `from .part01 import x` and `from . import part01` name
    # unit.* modules (review 1012c: they were read as top-level, or not at all).
    _mod = ("unit" + ("." + node.module if node.module else "")) if node.level == 1 else node.module
    if not _mod:
        return []
    return [_mod] + (["unit." + _a.name for _a in node.names] if _mod == "unit" else [])


def _r14d_real_imports(part):
    with open(os.path.join(_root, "tests", "unit", part + ".py"), encoding="utf-8") as _fh:
        return _r18d_parts_imported(_fh.read())


def _r18d_parts_imported(text):
    """{two-digit part number} a part's source imports directly, in any spelling.

    Only `from unit.partNN import` was read (review 1012c): `from unit import part05` and a
    relative `from .part01 import x`, both of which the order check below follows or should, could
    be left out of a note with this check green.
    """
    import ast as _ast
    return {_m[len("unit.part"):] for _n in _ast.walk(_ast.parse(text))
            for _m in _r17d_imported_modules(_n)
            if _m.startswith("unit.part") and _m[len("unit.part"):].isdecimal()}


with open(os.path.abspath(__file__), encoding="utf-8") as _fh_r14d:
    _src_r14d = _fh_r14d.read()
_notes_r14d = _r14d_noted_imports(
    _src_r14d[_src_r14d.index("# The parts, in order:"):_src_r14d.index("\n_PARTS = (")])
_wrong_r14d = sorted("%s: note says %s, imports %s" % (_p, sorted(_n), sorted(_r14d_real_imports(_p)))
                     for _p, _n in _notes_r14d.items() if _n != _r14d_real_imports(_p))
check("unit suite: every ordering note that lists a part's imports lists exactly them",
      len(_notes_r14d) >= 20 and not _wrong_r14d,
      "%d notes read; %s" % (len(_notes_r14d), _wrong_r14d))
_ctl_r14d = _r14d_noted_imports("# part57 (x: y) drives part12's app; imports\n# part01, 12 and 20.\n"
                                "# part19 comes after part18. part20 builds and imports only part01.")
check("unit suite: ...the note reader takes a list across lines, and not a part named mid-sentence "
      "(control)", _ctl_r14d == {"part57": {"01", "12", "20"}, "part20": {"01"}}, repr(_ctl_r14d))
_ctl2_r14d = _r14d_noted_imports("# part70 (x) imports parts 01 and 12. part71 comes after part70, "
                                 "whose app it imports. part72 (x) imports from part01 and part12. "
                                 "part73 (x) imports nothing but part01.")
check("unit suite: ...and a note listing imports in a wording it cannot read is named, not dropped "
      "(control)", sorted(_ctl2_r14d) == ["part70", "part72", "part73"]
      and all(next(iter(_v)).startswith("unreadable") for _v in _ctl2_r14d.values()), repr(_ctl2_r14d))
_ctl4_r14d = _r14d_noted_imports("# part99 (x) imports part01 and 87.\n# part100 (x) imports part01, 99 "
                                 "and 100.\n# part101 (x) imports from part100.")
check("unit suite: ...a three-digit part's note is read, and lists a three-digit import, as a "
      "two-digit one's is (control)",
      _ctl4_r14d.get("part99") == {"01", "87"} and _ctl4_r14d.get("part100") == {"01", "99", "100"}
      and next(iter(_ctl4_r14d.get("part101", {""}))).startswith("unreadable")
      and "part100" in _notes_r14d, repr((_ctl4_r14d, sorted(_notes_r14d)[-3:])))
_ctl3_r18d = _r18d_parts_imported("from unit.part12 import a\nfrom unit import part05, idreuse_support\n"
                                  "from .part01 import b\nfrom . import part20\nimport unit.part30\n"
                                  "from unit.part61_ufw import c\n")
check("unit suite: ...a part's imports are read in every spelling: from unit import partNN, relative, "
      "and import unit.partNN (control)", _ctl3_r18d == {"12", "05", "01", "20", "30"}, repr(_ctl3_r18d))

# ...and the imports are held to the ORDER, which is what the notes are for: "nothing imports
# backwards, so the import order below IS the execution order" was stated, never checked. A part
# moved ahead of one it imports runs that part inside its own import, silently (review 1011e).
# Through a shared module too: part41 reaches part01 and part20 by importing unit.reboot41_fixtures,
# and only direct `from unit.partNN` imports were read (review 1012a), so part41 moved ahead of
# part20 would have run part20 inside that import with this check green.
def _r16d_unit_imports(module):
    """The unit.* modules `module` (unit.<name>) imports, or none when it has no file."""
    import ast as _ast
    _path = os.path.join(_root, "tests", *module.split(".")) + ".py"
    if not os.path.isfile(_path):
        return set()
    with open(_path, encoding="utf-8") as _fh:
        _tree = _ast.parse(_fh.read())
    return {_m for _n in _ast.walk(_tree) for _m in _r17d_imported_modules(_n) if _m.startswith("unit.")}


def _r16d_parts_reached(module, seen=None):
    """{two-digit part number} `module` (unit.<name>) imports, directly or through non-part modules."""
    seen = set() if seen is None else seen
    if module in seen:
        return set()
    seen.add(module)
    out = set()
    for _m in _r16d_unit_imports(module):
        if _m.startswith("unit.part") and _m[len("unit.part"):].isdecimal():
            out.add(_m[len("unit.part"):])
        else:
            out |= _r16d_parts_reached(_m, seen)
    return out


_r15d_backward = sorted("%s imports %s, which runs after it" % (_p, _i)
                        for _p in _PARTS for _i in _r16d_parts_reached("unit." + _p)
                        if ("part" + _i) in _PARTS
                        and _PARTS.index("part" + _i) >= _PARTS.index(_p))
check("unit suite: ...the order check follows imports through shared modules: unit.reboot41_d names "
      "no part, and reaches part01 and part20 through unit.reboot41_fixtures (control)",
      {"01", "20"} <= _r16d_parts_reached("unit.reboot41_d"),
      repr(sorted(_r16d_parts_reached("unit.reboot41_d"))))
check("unit suite: ...and through `from unit import <module>`: part16 reaches unit.idreuse_support "
      "that way (control)", "unit.idreuse_support" in _r16d_unit_imports("unit.part16"),
      repr(sorted(_r16d_unit_imports("unit.part16"))))
_r15d_imports_read = sum(len(_r14d_real_imports(_p)) for _p in _PARTS)
check("unit suite: no part imports a part that runs at or after it in _PARTS",
      _r15d_imports_read >= 100 and not _r15d_backward,
      "%d imports read; %s" % (_r15d_imports_read, _r15d_backward))

# ...and every part20 patch is undone. _patch pushes onto part20's list and only _patched() (or
# part20's own _restore_all, long finished) pops it: one made outside a _patched() block by any of
# the thirteen parts that import them stayed stubbed for every part after, unseen.
_r15d_saved20 = getattr(sys.modules.get("unit.part20"), "_SAVED20", None)
check("unit suite: every part20 _patch was undone by the end of the run",
      _r15d_saved20 == [], "not imported" if _r15d_saved20 is None else repr(
          [(getattr(_o, "__name__", type(_o).__name__), _n) for _o, _n, _v in _r15d_saved20[:6]]))

_hub_first_after = {}      # each leftover once, with the part it first outlived
for _part, _left in _hub_after:
    for _item in (["no eventlet hub to read (is the suite still monkey-patched?)"]
                  if _left is None else _left):
        _hub_first_after.setdefault(_item, _part)
check("unit suite: every part leaves the eventlet hub holding only tpool's own socket",
      all(left == [] for _, left in _hub_after),
      "; ".join("%s, first after %s" % kv for kv in _hub_first_after.items()))
check("unit suite: no check leaves the eventlet hub a listener or IOClosed for a greenlet not "
      "waiting on it",
      hub_swept[0] > 0 and not hub_leaks,
      "no check() found an eventlet hub to sweep" if not hub_swept[0]
      else "%d found, first at: %s" % (len(hub_leaks), "; ".join(hub_leaks[:5])))

# The answer above, against the machine's binary and a part's stand-in (control): a wrapper that
# refused nothing, or everything, would read the same as one that works. The machine's side is
# planted, not read off the machine: CI has no tailscale, so a control that asked the host compared
# False with False there and passed whatever the wrapper did. For one look, the stand-in roots are
# planted directories, and every shape each handle sees must be refused without the planted
# "machine's" binary having run (it leaves a mark when it does).
_r15d_ts_ctl_dir = tempfile.mkdtemp(prefix="lgsm-unit-ts-ctl-")
_r16d_ts_mark = os.path.join(_r15d_ts_ctl_dir, "ran")
# The machine's binary, in a directory that is on no list at all (review 1012d: ~/bin and ~/go/bin
# were not on the old one, and the planted "system" dirs could not show a location it omitted).
_r17d_ts_sys = os.path.join(_r15d_ts_ctl_dir, "sys")
os.makedirs(_r17d_ts_sys)
with open(os.path.join(_r17d_ts_sys, "tailscale"), "w", encoding="utf-8") as _fh_ts:
    _fh_ts.write("#!/bin/sh\necho stand-in\n: > '%s'\n" % _r16d_ts_mark)
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this runner runs itself
os.chmod(os.path.join(_r17d_ts_sys, "tailscale"), 0o700)  # nosec B103 - a stand-in in a private temp dir
# Each half of "found AND resolved" with a shape only it refuses (review 1012d: a found-only or a
# resolved-only judge passed the old control). sysl/tailscale is found outside the roots and
# resolves into one (tgt/, a copy of the script); lnk/tailscale is found in a root (lnk/) and
# resolves out of every root, to sys/.
_r18d_ts_sysl = os.path.join(_r15d_ts_ctl_dir, "sysl")
_r19d_ts_lnk = os.path.join(_r15d_ts_ctl_dir, "lnk")
for _r19d_d in (_r18d_ts_sysl, _r19d_ts_lnk, os.path.join(_r15d_ts_ctl_dir, "tgt")):
    os.makedirs(_r19d_d)
shutil.copy(os.path.join(_r17d_ts_sys, "tailscale"), os.path.join(_r15d_ts_ctl_dir, "tgt", "tailscale"))
os.symlink(os.path.join(_r15d_ts_ctl_dir, "tgt", "tailscale"), os.path.join(_r18d_ts_sysl, "tailscale"))
os.symlink(os.path.join(_r17d_ts_sys, "tailscale"), os.path.join(_r19d_ts_lnk, "tailscale"))
_r16d_ts_env = dict(os.environ, PATH=_r17d_ts_sys + os.pathsep + os.environ.get("PATH", ""))
os.makedirs(os.path.join(_r15d_ts_ctl_dir, "own"))
with open(os.path.join(_r15d_ts_ctl_dir, "own", "tailscale"), "w", encoding="utf-8") as _fh_ts:
    _fh_ts.write("#!/bin/sh\necho own stand-in\n")
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this runner runs itself
os.chmod(os.path.join(_r15d_ts_ctl_dir, "own", "tailscale"), 0o700)  # nosec B103 - a stand-in in a private temp dir
_r16d_ts_wraps = [getattr(sys.modules.get(_m), _a, None) for _m, _a, _s in _R16D_TS_HANDLES]


_r21d_own_first = dict(os.environ, PATH=os.path.join(_r15d_ts_ctl_dir, "own") + os.pathsep + "/usr/bin:/bin")


def _r19d_ts_shapes(d):
    """Every shape a handle sees, with the binary found in directory `d`.

    A shape that brings its own `env` keeps it; every other one starts with `d` first on PATH.
    """
    _ts, _p = os.path.join(d, "tailscale"), "PATH=%s:/usr/bin:/bin" % d
    return (("run", (["tailscale", "version"],), {}),
            ("Popen", (["tailscale", "status"],), {}),
            ("run", ("tailscale status --json 2>/dev/null || echo '{}'",), {"shell": True}),
            ("run", ("tailscale set --ssh 2>&1",), {"shell": True}),
            # WHICH-FOUND: `which` letting the binary's path through is a let-through too (the
            # path has no "stand-in" in it, review 1012b).
            ("Popen", (["/bin/bash", "-c", "which tailscale && echo WHICH-FOUND; tailscale version"],), {}),
            # An option before -c, an `env` prefix, a bare string with no shell and the binary
            # named by its path ran unjudged (review 1012c).
            ("run", (["/bin/bash", "-e", "-c", "tailscale version"],), {}),
            ("run", (["/usr/bin/env", "X=1", "sh", "-o", "errexit", "-c", "tailscale version"],), {}),
            ("run", ("tailscale",), {}),
            ("run", ([_ts, "version"],), {}),
            # Behind wrapper commands, and past the shell's function by a wrapper or a path, it
            # ran unjudged too (review 1012d); `env -i` drops the exported functions.
            ("run", (["timeout", "5", "tailscale", "version"],), {}),
            ("run", (["nice", "-n", "5", "/usr/bin/env", "-i", _p, "tailscale"],), {}),
            ("run", (["env", "-i", _p, "bash", "-c", "tailscale version"],), {}),
            ("run", (["setsid", "env", "-u", "X", "sh", "-c", "tailscale version"],), {}),
            ("run", ("timeout 5 tailscale version",), {"shell": True}),
            ("run", ("command tailscale version",), {"shell": True}),
            ("run", (["/bin/bash", "-c", "%s version" % _ts],), {}),
            # Behind a wrapper only the script form knew, as a command line held in one option
            # value, as a tuple, through check_output/call, and past the function by `type -P`, a
            # nested sh, a wrapper named by its path or an unset variable (review 1013a).
            ("run", (["taskset", "1", "tailscale", "version"],), {}),
            ("run", (["flock", "-w", "5", d, "tailscale"],), {}),
            ("run", (["chrt", "-o", "0", "tailscale"],), {}),
            ("run", (["/usr/bin/time", "-o", "/dev/null", "tailscale"],), {}),
            ("run", (["xargs", "-a", "/dev/null", "tailscale"],), {}),
            ("run", (["xargs", "-a", "/dev/null", "bash", "-c", "tailscale version"],), {}),
            ("run", (["env", "-S", "tailscale version"],), {}),
            ("run", (["env", "--split-string=tailscale version"],), {}),
            # A long option by its prefix, as getopt_long takes it (review 1015c).
            ("run", (["env", "--split-str=tailscale version"],), {}),
            ("run", (["env", "--spl=tailscale"],), {}),
            ("run", (["env", "-S", "tail'scale' version"],), {}),
            ("run", (["env", "-Stailscale\\_version"],), {}),
            ("run", (["zsh", "-c", "tailscale version"],), {}),
            ("run", (("env", "--", "tailscale", "version"),), {}),
            ("run", (("env", "--", "bash", "-c", "tailscale version"),), {}),
            ("check_output", (["tailscale", "version"],), {}),
            ("call", (["tailscale", "version"],), {}),
            ("run", ('"$(type -P tailscale)" version',), {"shell": True}),
            ("run", ("sh -c 'tailscale version'",), {"shell": True}),
            ("run", ("/usr/bin/env tailscale version",), {"shell": True}),
            ("run", ("$R20D_UNSET%s version" % _ts,), {"shell": True}),
            ("run", ('t=$(which -a tailscale | head -n 1); [ -n "$t" ] && "$t" version',), {"shell": True}),
            ("run", ('t=$(whereis -b tailscale | cut -d" " -f2); [ -x "$t" ] && "$t" version',), {"shell": True}),
            # -S/-c grouped or attached, and a command line naming the binary by its path while a
            # part's own stand-in is first on PATH (review 1015a).
            ("run", (["env", "-Stailscale version"],), {}),
            ("run", (["env", "-vS", "tailscale version"],), {}),
            ("run", (["zsh", "-ec", "tailscale"],), {}),
            ("run", (["env", "-S", "%s version" % _ts],), {"env": _r21d_own_first}),
            ("run", (["zsh", "-c", "%s version" % _ts],), {"env": _r21d_own_first})) + _r23d_ts_shapes(d)


def _r23d_ts_shapes(d):
    """_r19d_ts_shapes' long-option and variable shapes (review 1015d)."""
    return (
        # flock reads -c/--command only as the word after the lock file, and by its value in
        # the next word: `--comm=x` was refused by flock itself, so it could not fail; this one
        # runs the binary unless the separate-word reading judges it.
        ("run", (["flock", d, "--command", "tailscale"],), {}),
        ("run", (["env", "--spl", "tailscale\\_version"],), {}),
        # A value-taking long option by its prefix: its value is not the program.
        ("run", (["env", "--ch", d, "tailscale", "version"],), {}),
        ("run", (["timeout", "--sig", "TERM", "5", "tailscale", "version"],), {}),
        ("run", (["xargs", "--arg", "/dev/null", "tailscale"],), {}),
        # A variable env -S or a shell expands to nothing, unset or empty.
        ("run", (["env", "-S", "tail${R23D_UNSET}scale version"],), {}),
        ("run", (["zsh", "-c", "tail$R23D_UNSET'scale' version"],), {})) + _r25d_ts_shapes(d)


def _r25d_ts_shapes(d):
    """_r19d_ts_shapes' mixed-reading, built-word and which -a shapes (review 1016b)."""
    _own_then_d = dict(os.environ, PATH=os.pathsep.join((os.path.join(_r15d_ts_ctl_dir, "own"), d, "/usr/bin:/bin")))
    return (
        # --f is timeout's --foreground (a flag) and a prefix of --format; --sig needs its value.
        ("run", (["timeout", "--f", "--sig", "KILL", "5", "tailscale", "version"],), {}),
        # A name the script builds: bash, sh and a shell-less shell the guard reads statically.
        ("run", (["bash", "-c", "T=tail; ${T}scale version"],), {}),
        ("run", ("T=tail; ${T}scale version",), {"shell": True}),
        ("run", (["sh", "-c", "T=tail; ${T}scale version"],), {}),
        ("run", (["zsh", "-c", "T=tail; ${T}scale version"],), {}),
        ("run", (["zsh", "-c", "tail${HOME:+scale} version"],), {}),
        ("run", (["zsh", "-c", "tail$(:)scale version"],), {}),
        # ...past the function: a wrapper given the built word, and a path the script builds.
        ("run", ("T=tail; command ${T}scale version",), {"shell": True}),
        ("run", ("sh -c 'T=tail; ${T}scale version'",), {"shell": True}),
        ("run", ('p=%s; t=tail; "$p/${t}scale" version' % d,), {"shell": True}),
        # `which -a` past a part's stand-in first on PATH listed the machine's binary after it.
        ("run", ('t=$(which -a tailscale | grep -v /own/ | head -n 1); [ -n "$t" ] && "$t" version',),
         {"shell": True, "env": _own_then_d})) + _r26d_ts_shapes(d)


def _r26d_ts_shapes(d):
    """_r19d_ts_shapes' quoted-name, apostrophe and argv0 shapes, and built words behind the shim (review 1016c)."""
    _apos = 'echo "it\'s" >/dev/null; T=tail; ${T}scale version; echo "don\'t" >/dev/null'
    return (
        # An apostrophe inside "…" opened no string, but was read as one hiding the built word.
        ("run", (_apos,), {"shell": True}),
        ("run", (["bash", "-c", _apos],), {}),
        ("run", (["zsh", "-c", _apos],), {}),
        # The name spelled with quotes: no literal word, so no function was handed over.
        ("run", (["bash", "-c", "tail'scale' version"],), {}),
        ("run", ('tail"scale" version',), {"shell": True}),
        ("run", (["sh", "-c", "ta''ilscale version"],), {}),
        # env's -a/--argv0 takes a value, which was read as the program.
        ("run", (["env", "-a", "x", "tailscale", "version"],), {}),
        ("run", (["env", "--argv0", "x", "tailscale", "version"],), {}),
        # A built word a wrapper execs from PATH, and one `which` finds, in the shell it was given.
        ("run", ("T=tail; timeout 5 ${T}scale version",), {"shell": True}),
        ("run", (["sh", "-c", "T=tail; command ${T}scale version"],), {}),
        ("run", ('T=tail; t=$(which ${T}scale) && "$t" version',), {"shell": True}),
        ("run", (["sh", "-c", 'T=tail; t=$(which -a ${T}scale | tail -n 1) && "$t" version'],), {})
    ) + _r28d_ts_shapes(d)


def _r28d_ts_shapes(d):
    """_r19d_ts_shapes' PATH-setting, comment, here-document and set-otherwise shapes (review 1016e).

    Each puts the planted "machine's" directory `d` where the script searches, never the real
    default PATH: a shape that escaped would otherwise run this machine's own binary.
    """
    _hd = "cat >/dev/null <<EOF\nit's\nEOF\nT=tail; ${T}scale version\necho 'x'"
    return (
        # A script that only builds the name and sets its own PATH stepped past the shim.
        ("run", ("PATH=%s:$PATH; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", ("export PATH=%s:$PATH; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", (["sh", "-c", "PATH=%s:$PATH; T=tail; ${T}scale version" % d],), {}),
        ("run", ("T=tail; PATH=%s ${T}scale version" % d,), {"shell": True}),
        # ...and a wrapper execs from the PATH the script gives it, which was never judged.
        ("run", ("T=tail; env PATH=%s ${T}scale version" % d,), {"shell": True}),
        ("run", ("T=tail; PATH=%s:$PATH; timeout 5 ${T}scale version" % d,), {"shell": True}),
        ("run", (["env", "PATH=%s:/usr/bin:/bin" % d, "bash", "-c", "T=tail; timeout 5 ${T}scale version"],), {}),
        # An expansion the reader cannot model, behind a wrapper given a PATH.
        ("run", ("T=tailx; env PATH=%s ${T%%x}scale version" % d,), {"shell": True}),
        ("run", ("T=X; env PATH=%s ${T/X/tail}scale version" % d,), {"shell": True}),
        ("run", ("A=(tail); env PATH=%s ${A[0]}scale version" % d,), {"shell": True}),
        ("run", ("T=xtailscale; env -i PATH=%s:/usr/bin:/bin ${T#x} version" % d,), {"shell": True}),
        # A name set other than by a plain NAME=, under the bash route (the script names the word).
        ("run", (["bash", "-c", "echo tailscale >/dev/null; printf -v T tail; timeout 5 ${T}scale version"],), {}),
        ("run", (["bash", "-c", "echo tailscale >/dev/null; : ${T:=tail}; timeout 5 ${T}scale version"],), {}),
        ("run", (["bash", "-c", "echo tailscale >/dev/null; T=tail; T+=scale; timeout 5 $T version"],), {}),
        ("run", (["env", "T=tailscale", "bash", "-c", "timeout 5 $T version"],), {}),
        # An apostrophe in a comment or a here-document's body opened no string.
        ("run", ("# it's a comment\nT=tail; ${T}scale version\necho 'x'",), {"shell": True}),
        ("run", (_hd,), {"shell": True}),
        ("run", (["sh", "-c", _hd],), {})) + _r29d_ts_shapes(d)


def _r29d_ts_shapes(d):
    """_r19d_ts_shapes' PATH set past the reader, cd-relative and built-path shapes (review 1016f).

    Each reached the planted "machine's" binary in `d` through every handle: a PATH the stripped
    reader could not see (single-quoted inside a nested bash, a quoted or built name, a sourced or
    eval'd text, hidden by `$'…'`, a `#` inside a word or a here-document it did not know), a path
    read against the run's directory instead of the script's `cd`, a path whose last word is built,
    and a value quoted in part.
    """
    _src = os.path.join(_r15d_ts_ctl_dir, "r29d-path-%s.sh" % os.path.basename(d))
    with open(_src, "w", encoding="utf-8") as _fh:
        _fh.write("PATH=%s:$PATH\n" % d)
    _tail = "T=$(echo tail); PATH=%s:$PATH; timeout 5 ${T}scale version; echo 'x'" % d
    return (
        ("run", ("bash -c 'PATH=%s:$PATH; tailscale version'" % d,), {"shell": True}),
        ("run", ("bash -c 'export PATH=%s; tailscale version'" % d,), {"shell": True}),
        ("run", ("export 'PATH=%s:/usr/bin:/bin'; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", (["bash", "-c", "declare -x 'PATH=%s:/usr/bin'; T=tail; ${T}scale version" % d],), {}),
        ("run", ("T=tail; export 'PATH=%s'; tailscale version" % d,), {"shell": True}),
        ("run", ("P=PA; export ${P}TH=%s; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", (". %s; T=tail; ${T}scale version" % _src,), {"shell": True}),
        ("run", (["sh", "-c", ". %s; T=tail; ${T}scale version" % _src],), {}),
        ("run", ('eval "PA""TH=%s:$PATH"; T=tail; ${T}scale version' % d,), {"shell": True}),
        ("run", (["bash", "-c", "x=$'it\\'s'; PATH=%s:$PATH; T=tail; ${T}scale version; echo 'y'" % d],), {}),
        ("run", ("T=tailscalex; echo \\ #; env -i PATH=%s ${T%%x} version" % d,), {"shell": True}),
        ("run", ("T=tailscalex; : $(:)#; env -i PATH=%s ${T%%x} version" % d,), {"shell": True}),
        ("run", ("T=tailscalex; echo a\\\n#; env -i PATH=%s ${T%%x} version" % d,), {"shell": True}),
        ("run", ("echo \\ #; PATH=%s; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", ("cat >/dev/null <<\\EOF\nit's\nEOF\n" + _tail,), {"shell": True}),
        ("run", ('cat >/dev/null <<E"OF"\nit\'s\nEOF\n' + _tail,), {"shell": True}),
        ("run", (["bash", "-c", "T=tail; cat <<< END\necho 'abc\nEND\ndef' ; ${T}scale version; echo 'z'\n"],), {}),
        ("run", ("cd %s && ./tailscale version" % d,), {"shell": True}),
        ("run", ("cd %s; T=tail; ./${T}scale version" % d,), {"shell": True}),
        ("run", (["sh", "-c", "cd %s; T=tail; ./${T}scale version" % d],), {}),
        ("run", ("%s/tail$(:)scale version" % d,), {"shell": True}),
        ("run", ("T=tailscalex; %s/${T%%x} version" % d,), {"shell": True}),
        ("run", ('T=ta"il"; env -i PATH=%s ${T}scale version' % d,), {"shell": True}),
        ("run", ("T=ta'il'; env -i PATH=%s ${T}scale version" % d,), {"shell": True})) + _r30d_ts_shapes(d)


def _r30d_ts_shapes(d):
    """_r19d_ts_shapes' quoted-path, unresolved-directory, CDPATH, nested-PATH and `#` shapes (review 1017a).

    Each reached the planted "machine's" binary in `d`: a path whose directory or last word is
    quoted or cannot be resolved, a `cd` under CDPATH, past `--` or to a directory the reader cannot
    name, a nested bash building the name PATH, a `#` that only looks like a comment opening a
    quote the reader never saw, and a name set in a sourced file.
    """
    _up, _base = os.path.dirname(d), os.path.basename(d)
    _src = os.path.join(_r15d_ts_ctl_dir, "r30d-env-%s.sh" % _base)
    with open(_src, "w", encoding="utf-8") as _fh:
        _fh.write("T=tail\n")
    _nested = 'P=PA; bash -c "${P}TH=%s; tailscale version"' % d
    return (
        ("run", ("CDPATH=%s; cd %s && ./tailscale version" % (_up, _base),), {"shell": True}),
        ("run", ("export CDPATH=%s; cd %s >/dev/null && ./tailscale version" % (_up, _base),), {"shell": True}),
        ("run", ('cd "$(echo %s)" && ./%s/tailscale version' % (_up, _base),), {"shell": True}),
        ("run", ("cd -- %s && ./tailscale version" % d,), {"shell": True}),
        ("run", ("cd -P -- %s; ./tailscale version" % d,), {"shell": True}),
        ("run", ("%s/tail'scale' version" % d,), {"shell": True}),
        ("run", ('%s/tail""scale version' % d,), {"shell": True}),
        ("run", ('cd %s && ./tail""scale version' % d,), {"shell": True}),
        ("run", ('T=tailscalex; "%s"/${T%%x} version' % d,), {"shell": True}),
        ("run", ("T=tailscalex; '%s'/${T%%x} version" % d,), {"shell": True}),
        ("run", ('D=%s; T=tailscalex; "$D"/${T%%x} version' % d,), {"shell": True}),
        ("run", ('"%s"/tailscale version' % d,), {"shell": True}),
        ("run", ('D=%s; "$D"/tailscale version' % d,), {"shell": True}),
        ("run", ('"$(echo %s)"/tailscale version' % d,), {"shell": True}),
        ("run", ("D=$(echo %s); $D/tailscale version" % d,), {"shell": True}),
        ("run", (["sh", "-c", 'D=$(echo %s); "$D/tailscale" version' % d],), {}),
        ("run", (_nested,), {"shell": True}),
        ("run", (["sh", "-c", _nested],), {}),
        ("run", (["bash", "-c", _nested],), {}),
        ("run", ('echo \\ #"\n"; echo "x\'"; T=tailscalex; env -i PATH=%s ${T%%x} version; echo "\'"' % d,),
         {"shell": True}),
        ("run", ('T=tailscalex; : $(:)#"\n"; echo "x\'"; env -i PATH=%s ${T%%x} version; echo "\'"' % d,),
         {"shell": True}),
        ("run", ("x=$(:)#'\n'\nPATH=%s:$PATH; timeout 5 tail$(:)scale version; echo 'y'" % d,), {"shell": True}),
        ("run", ("echo a\\ #'\n'\nPATH=%s:$PATH; timeout 5 tail$(:)scale version; echo 'y'" % d,),
         {"shell": True}),
        ("run", (". %s; timeout 5 ${T}scale version" % _src,), {"shell": True}),
        ("run", (["sh", "-c", "source %s; timeout 5 ${T}scale version" % _src],), {}))


def _r21d_spawn(how):
    """The subprocess function a handle's `how` starts its process through."""
    return {"check_output": "run", "call": "Popen"}.get(how, how)


def _r21d_unrun_judged(w, how, args, kw):
    """Whether a shape whose wrapper program this machine lacks would still be stopped by the guard.

    Nothing ran, so the run proves nothing (review 1015a: the missing program's FileNotFoundError
    was counted as the guard's refusal, and with `time` taken off the wrapper table the
    `/usr/bin/time` shape still passed here, as `zsh` does on CI's image). It is judged without
    running: refused outright, or a shell the guard hands its functions to.
    """
    _cmd, _kw = w._guard_shell(args[0], kw, _r21d_spawn(how))
    return _cmd is not args[0] or _kw is not kw or w._system_tailscale(_cmd, _kw, _r21d_spawn(how))


def _r20d_ts_drive(w, how, args, kw):
    """What a shape printed, run through handle `w`'s `how` with stdout captured where it can be."""
    if how == "check_output":
        return w.check_output(*args, stderr=-3, **kw)
    if how == "call":
        w.call(*args, stdout=-3, stderr=-3, **kw)     # the mark file, not the output, shows a run
        return b""
    _p = getattr(w, how)(*args, stdout=-1, stderr=-1, **kw)
    return (_p.communicate(timeout=10) if how == "Popen" else (_p.stdout, _p.stderr))[0]


_r16d_ts_let = []      # the shapes that ran the planted machine's binary


def _r28d_guarded(cmd, kw):
    """Whether handle 0 refuses `cmd` as a run does: the guard's rewrite first, then the judge."""
    _c, _k = _r16d_ts_wraps[0]._guard_shell(cmd, kw, "run")
    return _r16d_ts_wraps[0]._system_tailscale(_c, _k, "run")


_r19d_ts_saved_roots = _R19D_STAND_IN_ROOTS
_R19D_STAND_IN_ROOTS = tuple(os.path.join(_r15d_ts_ctl_dir, _d) + os.sep for _d in ("own", "tgt", "lnk"))
try:
    for _w in _r16d_ts_wraps:
        for _r19d_d in (_r17d_ts_sys, _r18d_ts_sysl, _r19d_ts_lnk):
            for _how, _args, _kw in _r19d_ts_shapes(_r19d_d):
                _kw = dict(_kw, env=_kw.get("env") or dict(
                    os.environ, PATH=_r19d_d + os.pathsep + os.environ.get("PATH", "")))
                _r21d_n = len(_r15d_ts_refused)
                _r21d_shape = "%s.%s %r %s" % (type(_w).__name__, _how, _args[0], os.path.basename(_r19d_d))
                try:
                    _out = _r20d_ts_drive(_w, _how, _args, _kw)
                    if b"stand-in" in (_out or b"") or b"WHICH-FOUND" in (_out or b""):
                        _r16d_ts_let.append(_r21d_shape)
                except FileNotFoundError:
                    # The guard's refusal is recorded; anything else is this machine lacking the
                    # wrapper program, and that shape is judged without being run.
                    if len(_r15d_ts_refused) == _r21d_n and not _r21d_unrun_judged(_w, _how, _args, _kw):
                        _r16d_ts_let.append(_r21d_shape + " (not run here, and not judged)")
    # Not a tailscale command: the grep's pattern and an echo's word are text, and run.
    _r16d_ts_text = _r16d_ts_wraps[1].run(  # nosec B604 - a fixed command, through the wrapper under test
        "echo tailscale | grep -c tailscale", shell=True, env=_r16d_ts_env, capture_output=True,
        text=True).stdout
    # A shell that puts its own stand-in first on PATH still runs it (part05's secret rendering):
    # the shell is judged by the PATH it calls tailscale with, not the one it was started with.
    # Started inside the planted window, on a PATH whose first tailscale is the planted machine's,
    # so a judge of the starting PATH refuses it here on any machine (outside, CI's PATH resolved
    # no tailscale at all and such a judge passed, review 1012b).
    _r16d_ts_own = _r16d_ts_wraps[2].run(["/bin/bash", "-c", "export PATH=%s:\"$PATH\"; tailscale" % (
        os.path.join(_r15d_ts_ctl_dir, "own"))], env=_r16d_ts_env, capture_output=True, text=True).stdout
    # A stand-in behind a wrapper, or named by its path in a script, still runs (review 1012d).
    _r19d_ts_own_env = dict(os.environ, PATH=os.path.join(_r15d_ts_ctl_dir, "own") + os.pathsep
                            + os.environ.get("PATH", ""))
    _r19d_ts_own_wrapped = (
        _r16d_ts_wraps[0].run(["timeout", "5", "tailscale"], env=_r19d_ts_own_env, capture_output=True,
                              text=True).stdout,
        _r16d_ts_wraps[1].run(  # nosec B604 - a fixed command, through the wrapper under test
            os.path.join(_r15d_ts_ctl_dir, "own", "tailscale"), shell=True, env=_r16d_ts_env,
            capture_output=True, text=True).stdout)
    # Judged without running what a machine may lack or a run may not do (review 1015a): sudo
    # keeping the caller's PATH, whereis finding a system binary past a stand-in first on PATH,
    # and getoutput, which ran through the real module's check_output. The default PATH is
    # pointed at a planted directory for it, so the answer is the same on any machine.
    _r21d_saved_default = _R19D_DEFAULT_PATH
    _r21d_none = os.path.join(_r15d_ts_ctl_dir, "none")
    os.makedirs(_r21d_none)
    try:
        _R19D_DEFAULT_PATH = _r21d_none
        _r21d_static = [_r16d_ts_wraps[0]._system_tailscale(["sudo", "tailscale"], {"env": dict(
            os.environ, PATH=_r17d_ts_sys)}), _r16d_ts_wraps[0]._system_tailscale(
                ["runuser", "-u", "x", "tailscale"], {"env": dict(os.environ, PATH=_r17d_ts_sys)})]
        _R19D_DEFAULT_PATH = _r17d_ts_sys
        _r21d_static.append(_r16d_ts_wraps[0]._system_tailscale(
            't=$(whereis -b tailscale | cut -d" " -f2); "$t" version', {"shell": True, "env": _r21d_own_first}))
        # env clearing PATH past another option, or by -u / a long prefix (review 1015d).
        _r21d_static += [_r16d_ts_wraps[0]._system_tailscale(_x, {"shell": True, "env": _r21d_own_first})
                         for _x in ("env -v -i tailscale version", "env -u PATH tailscale version",
                                    "env --unse PATH tailscale version",
                                    # ...past an option's own value (review 1016b).
                                    "env -u X -i tailscale version", "env -C /tmp -i tailscale version",
                                    "env --chdir /tmp --ignore-environment tailscale version")]
        # ...and an argv needing both readings of its ambiguous options, which a machine without
        # xargs' --interactive tty cannot run here (review 1016b).
        _r21d_static.append(_r16d_ts_wraps[0]._system_tailscale(
            ["xargs", "--in", "--arg", "/dev/null", "tailscale"], {"env": dict(os.environ, PATH=_r17d_ts_sys)}))
        # Through the guard, as a run is: `command -p` and a wrapper behind sudo search the default
        # PATH, and the shim first on the run's PATH answered for every PATH (review 1016e).
        _r28d_static = [_r28d_guarded(_x, {"shell": True, "env": dict(os.environ, PATH=_r21d_none)})
                        for _x in ("T=tail; command -p ${T}scale version",
                                   "T=tail; command -pv ${T}scale >/dev/null && echo x")]
        _r28d_static.append(_r28d_guarded(["sudo", "bash", "-c", "T=tail; timeout 5 ${T}scale version"],
                                          {"env": dict(os.environ, PATH=_r21d_none)}))
        # A login shell searches its profile's PATH (here the planted default), and a PATH a nested
        # shell is handed is read with the script's own names; beside forms that name no tailscale
        # by a path or a built word, and a cd the reader cannot follow with no path after it
        # (review 1016f).
        _r29d_env = dict(os.environ, PATH=_r21d_none, HOME=_r21d_none)
        # (The nested shell's PATH with the default one empty: a PATH= also has the default judged,
        # which would answer for it.)
        _R19D_DEFAULT_PATH = _r21d_none
        _r29d_static = [_r28d_guarded('D=%s; sh -c "PATH=$D:\\$PATH; tailscale version"' % _r17d_ts_sys,
                                      {"shell": True, "env": _r29d_env})]
        _R19D_DEFAULT_PATH = _r17d_ts_sys
        _r29d_static += [_r28d_guarded(_x, {"shell": True, "env": _r29d_env}) for _x in (
            "sh -lc 'tailscale version'", "T=tail; bash --login -c 'timeout 5 ${T}scale version'",
            'cd "$(mktemp -u)" && ./tailscale version', "cd -; ./tailscale version",
            "cd /x && ./x version", 'cd "$(mktemp -u)" && ls', 'T=ta"il"; env -i ${T}x version',
            'D=/x; echo "$D/$(date)"', 'export X="$HOME"; timeout 5 cat "$X"')]
        _r29d_static += [_r28d_guarded(_x, {"env": _r29d_env}) for _x in (
            ["sh", "-lc", "tailscale version"], ["sh", "-l", "-c", "T=tail; ${T}scale version"],
            ["sh", "-c", "tailscale version"])]
        # An interactive shell or a login one past an option's value reads a profile too, and a
        # directory the reader cannot resolve may be the default PATH's; beside a quoted directory
        # that resolves to no tailscale, a `cd --` to one, and a `#` mid-word naming nothing
        # (review 1017a).
        _r30d_static = [_r28d_guarded(_x, {"shell": True, "env": _r29d_env}) for _x in (
            "bash -ic 'tailscale version'", "bash -O extglob -lc 'tailscale version'",
            '"$(mktemp -u)"/tailscale version', 'D=$(mktemp -u); "$D/tailscale" version',
            'cd "$(mktemp -u)" && ./x/tailscale version', "CDPATH=/x; cd y && ./tailscale version",
            'D=/x; "$D"/y version', "cd -- /x && ./x version", "x=$(:)#'\n'\necho 'y'",
            'cd "$(mktemp -u)" && /x/tailscale version')]
    finally:
        _R19D_DEFAULT_PATH = _r21d_saved_default
    # A wrapper handed a word that cannot spell the binary is not judged as running it, and one
    # that can still is (review 1016c: any `$` after a wrapper was, so on a machine with
    # tailscale on PATH the console reads were refused, where CI ran them).
    _r26d_static = [_r16d_ts_wraps[0]._system_tailscale(_x, {"shell": True, "env": dict(
        os.environ, PATH=_r17d_ts_sys + os.pathsep + "/usr/bin:/bin", HOME="/home/x")}) for _x in (
            'L=/x/log; exec 3<"$L" 2>/dev/null || exit 1', 'timeout 5 cat "$HOME/x"',
            'find "$NOPE26D" -name x', 'nice -n 5 echo "it\'s"; timeout 5 cat "$HOME"',
            "T=tail; timeout 5 ${T}scale version", "for t in tail; do timeout 5 ${t}scale; done",
            'timeout 5 "$(printf tail)scale"', "sh -c 'T=tail; ${T}scale version'")]
    # ...and what can spell it however the script sets or shapes the name (review 1016e), with the
    # misreads that hid one (a comment, a here-document) beside forms that still spell nothing.
    _r28d_env = dict(os.environ, PATH=_r17d_ts_sys + os.pathsep + "/usr/bin:/bin", HOME="/home/x")
    _r28d_static += [_r28d_guarded(_x, {"shell": True, "env": _r28d_env}) for _x in (
        "cat <<EOF\nit's $HOME\nEOF\ntimeout 5 cat \"$HOME/x\"", "# don't\nT=x; timeout 5 cat \"$T\"",
        "n=$((1<<2)); timeout 5 cat \"$HOME\"", "D=/x; timeout 5 cat \"${D}/y\"",
        "T=tailscalex; env -i ${T%x} version", "T=xailscale; env -i ${T/x/t} version",
        "T=tailscalexx; env -i ${T:0:9} version", "T=tail; T+=scale; env -i $T version",
        "printf -v T %s tail; timeout 5 ${T}scale version", ": ${T:=tail}; timeout 5 ${T}scale version",
        "T[0]=tail; timeout 5 ${T}scale version", "declare -l T=TAIL; timeout 5 ${T}scale version",
        "mapfile -t T <<<tail; timeout 5 ${T}scale version",
        "# it's\nT=tail; timeout 5 ${T}scale version; echo 'x'",
        "cat <<EOF\nit's\nEOF\nT=tail; timeout 5 ${T}scale version; echo 'x'")]
    _r28d_static += [_r28d_guarded(_x, {"env": _r28d_env}) for _x in (
        ["env", "T=tailscale", "bash", "-c", "timeout 5 $T version"],
        ["env", "X=1", "bash", "-c", "T=tail; T+=scale; timeout 5 $T version"],
        ["bash", "-c", "printf -v T %s tail; env -i ${T}scale version"])]
    _r21d_saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = _r17d_ts_sys + os.pathsep + _r21d_saved_path
    try:
        _r21d_static.append(_r16d_ts_wraps[1].getoutput("tailscale version"))
        _r21d_static.append(_r16d_ts_wraps[1].getstatusoutput("tailscale version")[1])
    finally:
        os.environ["PATH"] = _r21d_saved_path
finally:
    _R19D_STAND_IN_ROOTS = _r19d_ts_saved_roots
_r16d_ts_ran_refused = os.path.exists(_r16d_ts_mark)
# The green Popen counts as a real spawner: compared with the pre-patch class alone, every Popen
# passed from part01 on in CI's bare run (here, under smoke-local, eventlet was patched first and
# the runner captured the green one, so the planted shapes above cannot show it).
_r16d_green = sys.modules.get("eventlet.green.subprocess")
_r16d_ts_green = _r16d_green is None or _r16d_green.Popen in _r16d_real_spawners("Popen")
# Outside the planted window the control directory is in the run's temp area, a real stand-in root.
_r15d_ts_ctl = (_r16d_ts_let, _r16d_ts_ran_refused, _r16d_ts_text, _r16d_ts_own, _r19d_ts_own_wrapped,
                _r16d_ts_green, _r16d_ts_wraps[0].run(["tailscale"], capture_output=True, text=True,
                                                      env=_r16d_ts_env).stdout)
check("unit suite: the machine's own tailscale is answered 'not installed' through every handle that "
      "runs it, and a part's stand-in on its own PATH still runs (control)",
      all(isinstance(_w, _R15dNoSystemTailscale) for _w in _r16d_ts_wraps)
      and _r15d_ts_ctl == ([], False, "1\n", "own stand-in\n", ("own stand-in\n", "own stand-in\n"),
                           True, "stand-in\n"),
      repr(([type(_w).__name__ for _w in _r16d_ts_wraps], _r15d_ts_ctl, _r15d_ts_refused[:3])))

check("unit suite: a wrapper handed a word that cannot spell tailscale is not judged as running it "
      "(the console read, a file under $HOME, an unset name), and one that can still is (control)",
      _r26d_static == [False] * 4 + [True] * 4, repr(_r26d_static))
check("unit suite: a login shell is judged on its profile's PATH, a nested shell's PATH with the script's "
      "own names, and a relative path after a cd the reader cannot follow; a cd, a built word or a "
      "quoted value that names no tailscale is not (control)",
      _r29d_static == [True] * 5 + [False] * 5 + [True] * 2 + [False], repr(_r29d_static))
check("unit suite: ...an interactive shell, a login one past an option's value, a directory the reader "
      "cannot resolve and a relative path after an unresolved or CDPATH cd are judged; a quoted directory, "
      "`cd --` and a `#` mid-word that name no tailscale are not (control)",
      _r30d_static == [True] * 6 + [False] * 4, repr(_r30d_static))
# What keeps a script off the shim (review 1016f): any PATH it may set, read past every quote, and
# none of the everyday shapes that set nothing (each keeps the shell production runs it under).
_r29d_owns = [_r29d_may_set_path(_x) for _x in (
    "bash -c 'PATH=/x:$PATH; tailscale'", "export 'PATH=/x'", "declare -x 'PATH=/x'", "P=PA; export ${P}TH=/x",
    ". /x/env", "source /x/env", 'eval "PA""TH=/x"', "x=$'it\\'s'; PATH=/x; echo 'y'", "echo \\ #; PATH=/x",
    "cat <<\\EOF\nit's\nEOF\nPATH=/x; echo 'y'", "read ${P}TH </x", "printf -v \"${P}TH\" /x", "sh -lc x",
    "tailscale status --json 2>/dev/null || echo '{}'", 'L=/x/log; exec 3<"$L" 2>/dev/null || exit 1',
    "awk '{print $1}' /x", 'read -r a b < "$f"', 'export X="$HOME"; local y="$1"', "printf '%s\\n' \"$x\"",
    'cd "$D" && ls ./x', "echo '#'; T=tail")]
check("unit suite: a script that may set PATH however it spells it is kept off the shim, and one that "
      "does not keeps the shell it was given (control)",
      _r29d_owns == [True] * 13 + [False] * 8, repr(_r29d_owns))
# ...and (review 1017a) a nested bash building the name, an interactive shell, a login shell behind an
# option's value or `exec -l`, and a `.` where a command starts, beside a `.` that is only a word.
_r30d_owns = [_r29d_may_set_path(_x) for _x in (
    'P=PA; bash -c "${P}TH=/x; tailscale"', "P=PA; sh -c '${P}TH=/x; tailscale'", "bash -ic x",
    "bash -O extglob -l -c x", "exec -l bash", "if . /x/env; then :; fi", "x; . /x/env",
    'find . -name "$x"', "cp a . && echo \"$T\"", 'bash -c "echo hi"', 'sh -c "ls ."',
    "OS=$(. /etc/os-release; printf '%s' \"$PRETTY_NAME\")")]
check("unit suite: ...a nested shell building PATH, an interactive or `exec -l` shell and a `.` where a "
      "command starts are kept off the shim; `find .`, `cp a .` and a nested shell building nothing are not "
      "(control)", _r30d_owns == [True] * 7 + [False] * 4 + [True], repr(_r30d_owns))
check("unit suite: ...nor past a comment, a here-document or a shift that only looks like one, while "
      "`command -p`, sudo, an expansion the reader cannot model, a name set other than by NAME=, and "
      "a wrapper's own NAME= are judged (control)",
      _r28d_static == [True] * 3 + [False] * 4 + [True] * 14, repr(_r28d_static))

# What the guard hands a shell must not change what the shell answers (review 1016c): `which
# tailscale` with no tailscale anywhere fails, as on CI, through the functions and the shim; a
# script that only builds words keeps the shell it was given (`$0`), so a bashism still fails under
# dash; and a part's stand-in first on PATH still runs behind the shim.
_r26d_nots = tempfile.mkdtemp(prefix="lgsm-unit-nots-")
for _r26d_tool in ("which", "readlink"):
    if shutil.which(_r26d_tool):
        os.symlink(shutil.which(_r26d_tool), os.path.join(_r26d_nots, _r26d_tool))
_r26d_nots_env = dict(os.environ, PATH=_r26d_nots)
_r26d_own_env = dict(os.environ, PATH=os.path.join(_r15d_ts_ctl_dir, "own") + os.pathsep + "/usr/bin:/bin")
_r26d_answers = [
    _r16d_ts_wraps[1].run(_x, shell=True, env=_r26d_nots_env,  # nosec B604 - fixed commands, through the wrapper under test
                          capture_output=True, text=True).stdout for _x in (
        "which tailscale >/dev/null 2>&1 && echo INSTALLED || echo NOTINSTALLED",
        "T=tail; which ${T}scale >/dev/null 2>&1 && echo INSTALLED || echo NOTINSTALLED")]
_r26d_answers += [_r16d_ts_wraps[1].run(  # nosec B604 - a fixed command, through the wrapper under test
    'echo "$0"', shell=True, capture_output=True, text=True).stdout,
    # ...and so does one that names the binary (review 1016e: it ran under bash for the functions).
    _r16d_ts_wraps[0].run(["sh", "-c", 'tailscale version >/dev/null 2>&1; echo "$0"'],
                          capture_output=True, text=True).stdout,
    _r16d_ts_wraps[0].run(["sh", "-c", 'echo "$0"'], capture_output=True, text=True).stdout,
    _r16d_ts_wraps[1].run(  # nosec B604 - a fixed command, through the wrapper under test
        "T=tail; ${T}scale", shell=True, env=_r26d_own_env, capture_output=True, text=True).stdout,
    _r16d_ts_wraps[0].run(["sh", "-c", "T=tail; timeout 5 ${T}scale"], env=_r26d_own_env,
                          capture_output=True, text=True).stdout]
check("unit suite: the guard's `which` fails with no tailscale anywhere, a script that builds or "
      "names the word keeps its own shell, and a stand-in first on PATH still runs behind the shim (control)",
      _r26d_answers == ["NOTINSTALLED\n", "NOTINSTALLED\n", "/bin/sh\n", "sh\n", "sh\n", "own stand-in\n",
                        "own stand-in\n"], repr(_r26d_answers))

# The shapes a shell comes in (control, review 1012b): a grouped `-lc` and a list run with
# shell=True are shells too, so the guard's functions reach them.
_r16d_sh_read = [_r16d_shell_text(*_c) for _c in (
    (["bash", "-lc", "tailscale status"], {}), (["sh", "-ec", "tailscale up"], {}),
    (["tailscale status --json"], {"shell": True}), (["bash", "--login", "x"], {}),
    (["tailscale", "-c", "x"], {}),
    # Options before -c, and an `env` that only sets variables (review 1012c); -o's value is not
    # a -c.
    (["bash", "-o", "pipefail", "-c", "a"], {}), (["sh", "--norc", "-e", "-c", "b"], {}),
    (["/usr/bin/env", "X=1", "bash", "-c", "c"], {}), (["bash", "-o", "c", "x"], {}),
    (["bash", "--rcfile", "-c", "x"], {}),
    # Wrapper commands with options and values of their own (review 1012d); a wrapper's option
    # value is not the command, and `timeout`'s duration is not either.
    (["env", "-i", "-u", "bash", "dash", "-c", "d"], {}), (["timeout", "-s", "KILL", "5", "sh", "-c", "e"], {}),
    (["nice", "-n5", "setsid", "-w", "nohup", "bash", "-c", "f"], {}), (["env", "-C", "bash", "x"], {}),
    (["sudo", "-u", "bash", "X=1", "--", "bash", "-c", "g"], {}), (["timeout", "bash", "-c", "x"], {}),
    (["env", "--unset", "sh", "--chdir=/", "-", "sh", "-c", "h"], {}),
    # The wrappers only the script form knew, and a tuple behind `env --` (review 1013a).
    (["xargs", "-a", "/dev/null", "bash", "-c", "i"], {}), (["taskset", "1", "sh", "-c", "j"], {}),
    (("env", "--", "bash", "-c", "k"), {}), (["flock", "-w", "1", "/l", "dash", "-c", "m"], {}),
    # A flag that only prefixes a value-taking option, alone and beside one that takes its value
    # (review 1016b).
    (["setsid", "--f", "bash", "-c", "n"], {}), (["timeout", "--f", "--sig", "KILL", "5", "bash", "-c", "o"], {}))]
check("unit suite: ...behind a sudo that keeps PATH, through whereis, an env clearing PATH past another "
      "option's value, both readings of ambiguous options and through getoutput, the machine's "
      "tailscale is refused too (control)",
      _r21d_static[:10] == [True] * 10
      and not any("stand-in" in _o for _o in _r21d_static[10:]),
      repr(_r21d_static))

check("unit suite: ...a grouped -lc, a list with shell=True, options before -c and wrapper commands "
      "in front are read as shells (control)",
      _r16d_sh_read == ["tailscale status", "tailscale up", "tailscale status --json", None, None,
                        "a", "b", "c", None, None, "d", "e", "f", None, "g", None, "h",
                        "i", "j", "k", "m", "n", "o"],
      repr(_r16d_sh_read))
# A variable's operators, as the shell reads them (review 1016b): without a colon only an unset
# name takes the default, `+` gives the word only for a set one.
_r25d_expanded = [_r23d_expand_vars(_t, _e) for _t, _e in (
    ("tail${X-junk}scale", {"X": ""}), ("tail${X:-scale}", {"X": ""}), ("tail${X:+scale}", {"X": "1"}),
    ("tail${X:+junk}scale", {}), ("tail${X+scale}", {"X": ""}), ("tail${X=scale}", {}))]
check("unit suite: ...a variable with a default, an alternate or an assignment is expanded as the shell "
      "expands it (control)", _r25d_expanded == ["tailscale"] * 6, repr(_r25d_expanded))
# ...and the PATH a wrapped program is found on: a clearing `env` or sudo resets it (None).
_r19d_unwrapped = [_r19d_unwrap(*_c) for _c in (
    (["env", "-i", "tailscale"], "/p"), (["env", "-iv", "PATH=/q", "tailscale"], "/p"),
    (["env", "-uPATH", "tailscale"], "/p"), (["env", "--unset=PATH", "x"], "/p"),
    (["env", "-u", "X", "tailscale"], "/p"), (["sudo", "-E", "tailscale"], "/p"),
    (["timeout", "--signal", "TERM", "1", "x"], "/p"), (["tailscale"], "/p"),
    # sudo's PATH= does not move where it looks, and a tuple's `--` is skipped (review 1013a).
    (["sudo", "PATH=/x", "tailscale"], "/p"), (("env", "--", "tailscale"), "/p"),
    (["doas", "-u", "u", "tailscale"], "/p"),
    # Long options by an unambiguous prefix, as getopt_long reads them (review 1015d).
    (["env", "--ch", "/x", "tailscale"], "/p"), (["timeout", "--sig", "KILL", "5", "x"], "/p"),
    (["env", "--unse", "PATH", "tailscale"], "/p"), (["env", "--ignore-e", "tailscale"], "/p"))]
check("unit suite: ...a wrapped program is found on the PATH its wrappers leave it (control)",
      _r19d_unwrapped == [(2, None), (3, "/q"), (2, None), (2, None), (3, "/p"), (2, None), (4, "/p"),
                          (0, "/p"), (2, None), (2, "/p"), (3, None),
                          (3, "/p"), (4, "/p"), (3, None), (2, None)],
      repr(_r19d_unwrapped))
# An explicit empty environment is empty: the program is found on os.defpath, as Popen finds it,
# and a shell gets the guard's functions, or its shim before os.defpath, in an otherwise empty
# environment (review 1013a; the shim since review 1016e routes a named script there too).
_r20d_empty_env = (_r18d_ts_program(["tailscale"], {"env": {}}),
                   sorted(_R15dNoSystemTailscale(sys.modules["subprocess"])._guard_shell(
                       "PATH=/x; tailscale up", {"shell": True, "env": {}}, "run")[1]["env"]),
                   _R15dNoSystemTailscale(sys.modules["subprocess"])._guard_shell(
                       "tailscale up", {"shell": True, "env": {}}, "run")[1]["env"])
check("unit suite: ...an explicit empty environment is judged as empty, not as the runner's own (control)",
      _r20d_empty_env == (("tailscale", os.defpath), ["BASH_FUNC_tailscale%%", "BASH_FUNC_which%%"],
                          {"PATH": _R26D_SHIM + os.pathsep + os.defpath,
                           "R26D_TS_ROOTS": os.pathsep.join(_R19D_STAND_IN_ROOTS)}),
      repr(_r20d_empty_env))


def _r20d_unsafe_roots(roots, home):
    """The stand-in roots that hold a home or a system program directory.

    Under such a root the machine's own tailscale (~/bin, ~/go/bin, /usr/bin) reads as a part's
    stand-in: a run with TMPDIR=$HOME made every one of them a root (review 1013a).
    """
    _held = [_h.rstrip(os.sep) + os.sep for _h in [home] + _R19D_DEFAULT_PATH.split(os.pathsep) if _h]
    return [_r for _r in roots if any(_h.startswith(_r) for _h in _held)]


def _r22d_ts_held(found):
    """The machine's own tailscale binaries in `found` that a stand-in root holds (each would run)."""
    return [_f for _f in found if _f and _r19d_stand_in(_f)]


_r20d_roots_ctl = _r20d_unsafe_roots(("/", "/home/u/", "/home/u/x/", "/usr/", "/srv/u/"), "/home/u")
# ...and the start-of-run half has a control of its own (review 1015c: on CI, with no tailscale, it
# read [None, None], so nothing showed it could fail).
_r22d_held_ctl = _r22d_ts_held([os.path.join(_TESTS_DIR, "tailscale"), "/usr/bin/tailscale", None])
_r21d_misread_ctl = [_r19d_stand_in(_f) for _f in (os.path.join(_TESTS_DIR, "tailscale"), "/usr/bin/tailscale")]
check("unit suite: no stand-in root holds a home, a system program directory or the machine's own "
      "tailscale (with its control)",
      not _r20d_unsafe_roots(_R19D_STAND_IN_ROOTS, os.path.expanduser("~"))
      and not _r22d_ts_held(_r21d_ts_at_start)
      and _r20d_roots_ctl == ["/", "/home/u/", "/usr/"] and _r21d_misread_ctl == [True, False]
      and _r22d_held_ctl == [os.path.join(_TESTS_DIR, "tailscale")],
      repr((_R19D_STAND_IN_ROOTS, _r20d_roots_ctl, _r21d_ts_at_start, _r21d_misread_ctl, _r22d_held_ctl)))

# The cleanup, against unlistable directories, in BOTH of shutil.rmtree's modes. Which one a run gets
# depends on import order: eventlet.monkey_patch() replaces os.open with a function not in
# os.supports_dir_fd, so shutil imported AFTER it (under tools/smoke-local.sh, whose runner patches
# first) removes by path, and an empty mode-0o200 directory goes with a plain rmdir; imported
# BEFORE it (CI's bare run) it removes by descriptor, cannot open that directory, and leaves it.
# part06's TMPDIR stand-in failed the leak gate on all three CI legs and never on a local run for
# exactly that reason (review 1012a). Both modes are driven here, so a local run sees CI's.
# Python 3.14 picks the mode once, at import, into shutil._rmtree_impl, and never reads
# _use_fd_functions again: flipping the flag alone ran one mode twice (review 1012b). So the
# implementation is swapped too where there is one, and each mode's own function records that it
# ran, so a toggle that changes nothing fails by name.
_r16d_rm_modes = {}
_r16d_rm_ran = []
_r16d_rm_fns = {True: "_rmtree_safe_fd", False: "_rmtree_unsafe"}


def _r16d_rm_recorder(fd, fn):
    @functools.wraps(fn)
    def _rec(*a, **k):
        _r16d_rm_ran.append(fd)
        return fn(*a, **k)
    return _rec


for _r16d_fd in (True, False):
    _r16d_rm = _r15d_mkdtemp(prefix="lgsm-unit-rm-ctl-")     # not recorded: removed here, or named
    os.makedirs(os.path.join(_r16d_rm, "sub", "deeper"))
    os.chmod(os.path.join(_r16d_rm, "sub"), 0o200)
    os.chmod(_r16d_rm, 0o200)
    _r16d_fd_was = getattr(shutil, "_use_fd_functions", None)
    _r16d_saved_fns = {_n: getattr(shutil, _n) for _n in ("_rmtree_impl", *_r16d_rm_fns.values())
                       if hasattr(shutil, _n)}
    shutil._use_fd_functions = _r16d_fd
    for _r16d_k, _r16d_n in _r16d_rm_fns.items():
        setattr(shutil, _r16d_n, _r16d_rm_recorder(_r16d_k, _r16d_saved_fns[_r16d_n]))
    if "_rmtree_impl" in _r16d_saved_fns:
        shutil._rmtree_impl = getattr(shutil, _r16d_rm_fns[_r16d_fd])
    del _r16d_rm_ran[:]
    try:
        _r16d_rm_modes[_r16d_fd] = (_r16d_remove_paths([_r16d_rm]), sorted(set(_r16d_rm_ran)))
    finally:
        shutil._use_fd_functions = _r16d_fd_was
        for _r16d_n, _r16d_f in _r16d_saved_fns.items():
            setattr(shutil, _r16d_n, _r16d_f)
        if os.path.lexists(_r16d_rm):
            # 0o700 is owner-only, on this check's own temp dir, so rmtree can enter it.
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(_r16d_rm, 0o700)
            for _r16d_dp, _r16d_dns, _r16d_fns in os.walk(_r16d_rm):
                for _r16d_dn in _r16d_dns:
                    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                    os.chmod(os.path.join(_r16d_dp, _r16d_dn), 0o700)
            shutil.rmtree(_r16d_rm)
check("unit suite: the temp cleanup removes a directory it cannot list, and one inside it, whether "
      "shutil removes by descriptor (CI's bare run) or by path (a run under tools/smoke-local.sh)",
      _r16d_rm_modes == {True: ([], [True]), False: ([], [False])},
      repr(_r16d_rm_modes))

check("suites: no unit check reads or writes the machine's own config.json or keys",
      not _config_touches,
      "%d call(s): %s" % (len(_config_touches), "; ".join(sorted(set(_config_touches)))))

# part05 installs tools/nosudo_runner's shim for the rest of the run (it answers any sudo with "a
# password is required", as an unprivileged host would), and nothing read what it refused: a check
# that reached an escalation got a canned rc=1, tested the "could not escalate" branch under
# another name, and the run said nothing. What the shim refused is named here.
_nsr_blocked = getattr(sys.modules.get("unit.part05"), "_nsr_ns", {}).get("BLOCKED")
check("unit suite: no check reached sudo or the network through part05's no-sudo shim",
      _nsr_blocked == [],
      "the shim is not installed" if _nsr_blocked is None
      else "%d refused, first: %s" % (len(_nsr_blocked), "; ".join(
          "%s: %s" % _b for _b in _nsr_blocked[:4])))

# Every part file ran. Checked HERE, after the imports, because a gate inside a part cannot see
# that part being dropped: the old one lived in part06 and matched part names as substrings of this
# file's text (the docstring says "part01..part06"), so removing `part06` from the import line took
# its ~5,000 checks — and the gate — with it, and the tally still exited 0.
_parts_on_disk = sorted(os.path.basename(p)[:-3]
                        for p in glob.glob(os.path.join(_root, "tests", "unit", "part*.py")))
check("unit suite: every tests/unit/part*.py was imported and ran",
      bool(_parts_on_disk) and all("unit." + p in sys.modules for p in _parts_on_disk),
      "never ran: %s" % [p for p in _parts_on_disk if "unit." + p not in sys.modules])


# ok is True (pass), False (fail) or None (skipped — the check did not run; see part01.skip).
passed = sum(1 for ok, _, _ in results if ok is True)
failed = sum(1 for ok, _, _ in results if ok is False)
skipped = [(name, detail) for ok, name, detail in results if ok is None]
for ok, name, detail in results:
    line = ("PASS" if ok is True else "FAIL" if ok is False else "SKIP") + "  " + name
    if detail and ok is not True:
        line += "   [%s]" % (detail,)   # (detail,) not detail: a multi-element TUPLE detail made
        #     THIS line raise ('not all arguments converted'), so a
        #     FAILING check printed a traceback instead of its name
        #     and killed the tally and cleanup. Lists and ints are fine
        #     here; the concat-style printer elsewhere breaks on those.
    print(line)
print("\n%d / %d checks passed" % (passed, len(results) - len(skipped)))
# Loud, and after the tally, because a skip is a hole in the run rather than a result in it. It
# does not fail the suite (the environment is not the code's fault) but it must never be mistaken
# for a pass — the whole point of counting it apart.
if skipped:
    print("\n%d CHECK(S) DID NOT RUN:" % len(skipped))
    for name, detail in skipped:
        print("  SKIP  %s   [%s]" % (name, detail))
shutil.rmtree(_RUN_DATA, ignore_errors=True)
_r15d_left = _r15d_remove_made_tmp()
# After the tally, so it is printed on its own; it fails the run like any check would.
# The parts' own paths, not the runner's: the runner makes one before any part runs and more after
# the last, so "some were recorded" could not tell tracking that the parts went around from tracking
# that worked; the count taken right after the part loop can.
if _r16d_tmp_parts_made <= 0 or _r15d_left or _r16d_tmp_swapped:
    print("\nFAIL  unit suite: every temp dir and file the parts made is removed at the end   [%s]"
          % ("tempfile.mkdtemp/mkstemp was swapped back by %s, so what came after went unrecorded"
             % _r16d_tmp_swapped if _r16d_tmp_swapped
             else "no part's mkdtemp()/mkstemp() was recorded: the tracking is not installed"
             if _r16d_tmp_parts_made <= 0
             else "%d of %d left: %s" % (len(_r15d_left), len(_r15d_made_tmp), _r15d_left[:5])))
    failed += 1
sys.exit(0 if results and failed == 0 else 1)
