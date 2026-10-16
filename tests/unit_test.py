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
# (part05's secret rendering puts a stand-in first), so a shell is not judged from outside: it runs
# under bash with `tailscale` and `which` as functions that make the same call at the moment of use.
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
    """Index of the shell word: argv[0], or the word after the wrapper commands in front of it."""
    _i = _r19d_unwrap(argv, None)[0]
    if _i >= len(argv) or os.path.basename(str(argv[_i])) not in ("sh", "bash", "dash"):
        return None
    return _i


# Commands that run the rest of their argv as a command: (short options taking a value, operands
# before the command). Only `env VAR=x` was read (review 1012d): `env -i bash -c …`, `timeout 5
# tailscale …`, `nice`, `setsid` and `sudo` hid the shell or the binary from the guard.
# The argv form knew 8 of them while the script form's pattern named 20 (review 1013a: `taskset 1
# tailscale`, `flock /x tailscale` and `xargs bash -c …` ran the machine's binary), so the script
# pattern is now built from this table plus the shell-only words, and the two cannot disagree.
_R19D_WRAPPERS = {"env": ("uCS", 0), "timeout": ("sk", 1), "nice": ("n", 0), "nohup": ("", 0),
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
_R19D_LONG_VALUE = {"--unset", "--chdir", "--split-string", "--signal", "--kill-after", "--adjustment",
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


def _r19d_unwrap(argv, path):
    """(index of the word the wrapper commands in front leave to run, the PATH it is found on).

    The PATH is None when a wrapper clears or resets it: `env -i`, `env -u PATH`, sudo.
    """
    _i = 0
    while (_i < len(argv) and isinstance(argv[_i], str)
           and os.path.basename(argv[_i]) in _R19D_WRAPPERS):
        _w = os.path.basename(argv[_i])
        _i, path = _r19d_wrapper_opts(_w, argv, _i + 1, None if _w in _R20D_PATH_RESETS else path)
        _i += _R19D_WRAPPERS[_w][1]
    return _i, path


def _r19d_wrapper_opts(word, argv, _i, path):
    """(index of the first operand after `word`'s options from argv[_i], the PATH its command sees)."""
    while _i < len(argv) and isinstance(argv[_i], str) and argv[_i] != "--":
        _step = _r19d_opt_word(word, argv, _i)
        if _step is None:
            return _i, path
        path = _r19d_path_after(word, _step[1], path)
        _i += _step[0]
    # A tuple argv is as runnable as a list (review 1013a: comparing its slice with ["--"] was
    # never true, so `("env", "--", "tailscale")` read "--" as the program).
    return _i + (1 if tuple(argv[_i:_i + 1]) == ("--",) else 0), path


def _r19d_opt_word(word, argv, _i):
    """(words used, [(option, value)]) for the option word argv[_i] of `word`, or None at its operand.

    A variable set by env or sudo reads as ("=", "NAME=value"): any word holding "=" sets one,
    the guard's own BASH_FUNC_x%%=… included.
    """
    _a = argv[_i]
    if word in ("env", "sudo") and re.fullmatch(r"[^=-][^=]*=.*", _a, re.S):
        return 1, [("=", _a)]
    if _a == "-" and word == "env":
        return 1, [("-i", "")]
    if _a.startswith("--"):
        _name, _eq, _val = _a.partition("=")
        if not _eq and _name in _R19D_LONG_VALUE:
            return 2, [(_name, _r19d_next(argv, _i))]
        return 1, [(_name, _val)]
    if re.fullmatch(r"-[A-Za-z0-9]+", _a):
        return _r19d_short_opts(word, argv, _i)
    return None


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
    """The PATH after options `opts`: set by PATH=, cleared by env -i and env -u PATH."""
    for _name, _val in opts:
        # sudo's own PATH= does not choose where sudo looks: secure_path does (review 1013a).
        if _name == "=" and _val.startswith("PATH=") and word not in _R20D_PATH_RESETS:
            path = _val[len("PATH="):]
        elif word == "env" and (_name in ("-i", "--ignore-environment")
                                or (_name in ("-u", "--unset") and _val == "PATH")):
            path = None
    return path


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
    """Whether the `tailscale` at `path` is a part's own stand-in: found AND resolved under a root."""
    return (os.path.abspath(path).startswith(_R19D_STAND_IN_ROOTS)
            and os.path.realpath(path).startswith(_R19D_STAND_IN_ROOTS))


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
            "BASH_FUNC_which%%": '() { case " $* " in *" tailscale "*) if { %s; }; then return 1; fi;; esac; '
                                 'command which "$@"; }' % _is_sys}


def _r16d_ts_shell_env(env):
    """`env` plus _r16d_ts_shell_funcs' functions."""
    return dict(env, **_r16d_ts_shell_funcs())


def _r18d_ts_program(cmd, kw):
    """(program word, PATH it is found on or None) of a shell-less `tailscale` run, else (None, None).

    A bare string without a shell is a program name on POSIX, and an argv may name the binary by
    its path: both ran unjudged (review 1012c), as did one behind `timeout`, `env -i` or `nice`.
    """
    if isinstance(cmd, str) and not kw.get("shell"):
        cmd = [cmd]
    if not isinstance(cmd, (list, tuple)) or kw.get("shell"):
        return None, None
    _i, _path = _r19d_unwrap(cmd, _r20d_run_env(kw).get("PATH", os.defpath))
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
    if not any(_r20d_names_tailscale(_v) for _v in _vals):
        return _named
    _paths = [_r20d_run_env(kw).get("PATH", os.defpath)]
    if _r20d_may_reset_path(cmd):
        _paths.append(_R19D_DEFAULT_PATH)
    return _named + [shutil.which("tailscale", path=_p) for _p in _paths]


def _r20d_names_tailscale(text):
    """Does a command line held in one word name `tailscale` as one of its words?

    Also once unquoted, as a shell or env -S reads it, with env -S's backslash-underscore as a space
    (review 1015c: `tail'scale' version`, and tailscale joined to `version` by that escape, ran the
    machine's binary).
    """
    _words = re.split(r"[\s;&|()`'\"$=]+", text)
    try:
        _words += [_x for _w in shlex.split(text.replace("\\_", " ")) for _x in re.split(r"[\s;&|()`$=]+", _w)]
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
_R19D_SCRIPT_RESETS = re.compile(r"\benv\s+(?:-\w*i|-\s|--ignore)|\b(?:sudo|doas|runuser|su)\b|\bPATH=")
# Commands that find a program somewhere other than PATH: `whereis` searches the system's own
# directories whatever PATH says, and `find` walks them (review 1015a: with a part's stand-in first
# on PATH, `whereis -b tailscale` handed the script the machine's binary and was judged on PATH).
_R21D_SCRIPT_SEARCHES = re.compile(r"\b(?:whereis|find)\b")
# ...and one that names the binary by a path is judged by that path: ~, $VAR and a relative path
# are read against the run's environment and directory.
_R19D_SCRIPT_PATH = re.compile(r"(?<![\w.~$/:-])((?:~|\$\{?\w+\}?|\.{1,2})?[\w./~-]*/tailscale)(?![\w.-])")


def _r19d_script_candidates(script, kw):
    """The tailscale binaries a script could run past the shell's `tailscale` function."""
    _env = _r20d_run_env(kw)
    _found = _r19d_wrapped_candidates(script, _env) + _r19d_path_candidates(script, _env, kw.get("cwd"))
    return [_f for _f in _found if _f is not None]


def _r19d_wrapped_candidates(script, env):
    """The tailscale a wrapper in `script` could exec from PATH: the starting one, and the default."""
    if not _R19D_SCRIPT_WRAPPED.search(script):
        return []
    _paths = [env.get("PATH", os.defpath)] + ([_R19D_DEFAULT_PATH] if _R19D_SCRIPT_RESETS.search(script)
                                              or _R21D_SCRIPT_SEARCHES.search(script) else [])
    return [shutil.which("tailscale", path=_p) for _p in _paths]


def _r19d_path_candidates(script, env, cwd):
    """Each tailscale `script` names by a path that exists, read against `env` and `cwd`."""
    _out = []
    for _lit in _R19D_SCRIPT_PATH.findall(script):
        # An unset variable is empty, as the shell reads it (review 1013a: `$PREFIX/bin/tailscale`
        # with PREFIX unset runs /bin/tailscale, and was read as a path that does not exist).
        _lit = re.sub(r"\$\{?(\w+)\}?", lambda _m: env.get(_m.group(1), ""), os.path.expanduser(_lit))
        _lit = os.path.join(cwd or os.getcwd(), _lit)
        _out.append(_lit if os.path.exists(_lit) else None)
    return _out


def _r20d_argv_programs(cmd, kw):
    """The tailscale binaries a shell-less argv may run as its program (past any wrappers).

    Behind a wrapper that may reset PATH, both the PATH it was given and the default one: sudo
    with no secure_path (Arch's default sudoers), and runuser or su without -l, keep the caller's
    (review 1015a: only the default PATH was judged, so a tailscale found on the run's PATH alone
    went through).
    """
    _prog, _path = _r18d_ts_program(cmd, kw)
    if _prog is None:
        return []
    if os.sep in _prog:
        return [_prog]
    _paths = [_R19D_DEFAULT_PATH, _r20d_run_env(kw).get("PATH", os.defpath)] if _path is None else [_path]
    return [shutil.which("tailscale", path=_p) for _p in _paths]


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
            _hits = _r19d_script_candidates(_sh, kw)
            return any(not _r19d_stand_in(_h) for _h in _hits)
        _hits = _r20d_cmdline_candidates(cmd, kw) + _r20d_argv_programs(cmd, kw)
        return any(_h is not None and not _r19d_stand_in(_h) for _h in _hits)

    def _guard_shell(self, cmd, kw, how):
        """(cmd, kw) for a shell that names tailscale: under bash, with _r16d_ts_shell_env's functions."""
        _sh = _r16d_shell_text(cmd, kw)
        if (_sh is None or "tailscale" not in _sh
                or getattr(sys.modules.get(self._src), how, None) not in _r16d_real_spawners(how)):
            return cmd, kw
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
_PARTS = ("part01", "part02", "part03", "part04", "part05", "part06", "part07", "part08", "part09",
          "part10", "part11", "part12", "part13", "part14", "part16", "part17", "part18", "part19",
          "part20", "part21", "part22", "part23", "part24", "part25", "part26", "part27",
          "part28", "part29", "part30", "part31", "part32", "part33", "part34", "part35", "part36", "part37",
          "part38", "part39", "part40", "part41", "part42", "part43", "part44", "part47", "part49",
          "part50", "part51", "part52", "part53", "part54", "part55", "part56", "part57", "part58",
          "part59", "part60", "part61", "part62", "part63", "part64", "part65", "part66",
          "part67", "part68", "part69", "part70", "part71", "part72", "part73", "part74",
          "part75", "part76", "part77", "part78", "part79", "part80", "part81", "part82", "part83",
          "part84", "part85", "part86", "part87", "part15")


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
for _part in _PARTS:
    _path_before = list(sys.path)
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
# Counted HERE, before the controls below make temp dirs of their own: the tailscale control's dir
# was recorded after the loop, so "no part's path was recorded" could never be true (review 1012b).
_r16d_tmp_parts_made = len(_r15d_made_tmp) - _r16d_tmp_runner_made
from unit.part01 import check, results, hub_leaks, hub_swept  # noqa: E402

# A part that leaves a directory on sys.path (tools/, tools/js_coverage) hands every later import of
# a top-level name in it — `run`, `walk`, `flows`, `serve` — that directory's file. part14, part53
# and part56 each put it back and say so; this names any part, present or future, that does not.
check("unit suite: no part leaves sys.path changed for the parts after it",
      not _path_moved, "; ".join("%s: %s" % _pm for _pm in _path_moved))


# ── the ordering notes above _PARTS name what each part imports ─────────────────────────────────
# They are the stated contract for where a part may move: a part imported out of order runs
# inside the importing part's import, silently. Corrected by hand twice (part54, then part30, 43,
# 51 and 57), so now read: every note that lists a part's imports must list exactly its
# `from unit.partNN import` lines.
def _r14d_noted_imports(text):
    """{part: set of two-digit numbers its note says it imports}, from the comment block's text."""
    _re = re
    flat = " ".join(_ln.lstrip("#").strip() for _ln in text.splitlines())
    # A note starts at a part named at a sentence (or clause) start; "part12's app" mid-sentence
    # is not one.
    out = {}
    for _seg in _re.split(r"(?:^|(?<=[.;])\s+)(?=part\d\d\b)", flat):
        _m = _re.match(r"(part\d\d)\b", _seg)
        _l = _re.search(r"\bimport(?:s|ing)\s+(?:only\s+)?(part\d\d(?:(?:\s*,\s*|\s+and\s+|,\s+and\s+)"
                        r"(?:part)?\d\d)*)", _seg)
        if _m and _l:
            out[_m.group(1)] = set(_re.findall(r"\d\d", _l.group(1)))
        elif _m and _re.search(r"\bimport(?:s|ing)\b[^.;]*?(?<!\d)\d\d\b", _seg):
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
            ("run", (["flock", d, "--comm=tailscale"],), {}),
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
            ("run", (["zsh", "-c", "%s version" % _ts],), {"env": _r21d_own_first}))


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
    finally:
        _R19D_DEFAULT_PATH = _r21d_saved_default
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
    (("env", "--", "bash", "-c", "k"), {}), (["flock", "-w", "1", "/l", "dash", "-c", "m"], {}))]
check("unit suite: ...behind a sudo that keeps PATH, through whereis and through getoutput, the machine's "
      "tailscale is refused too (control)",
      _r21d_static[:3] == [True, True, True]
      and not any("stand-in" in _o for _o in _r21d_static[3:]),
      repr(_r21d_static))

check("unit suite: ...a grouped -lc, a list with shell=True, options before -c and wrapper commands "
      "in front are read as shells (control)",
      _r16d_sh_read == ["tailscale status", "tailscale up", "tailscale status --json", None, None,
                        "a", "b", "c", None, None, "d", "e", "f", None, "g", None, "h",
                        "i", "j", "k", "m"],
      repr(_r16d_sh_read))
# ...and the PATH a wrapped program is found on: a clearing `env` or sudo resets it (None).
_r19d_unwrapped = [_r19d_unwrap(*_c) for _c in (
    (["env", "-i", "tailscale"], "/p"), (["env", "-iv", "PATH=/q", "tailscale"], "/p"),
    (["env", "-uPATH", "tailscale"], "/p"), (["env", "--unset=PATH", "x"], "/p"),
    (["env", "-u", "X", "tailscale"], "/p"), (["sudo", "-E", "tailscale"], "/p"),
    (["timeout", "--signal", "TERM", "1", "x"], "/p"), (["tailscale"], "/p"),
    # sudo's PATH= does not move where it looks, and a tuple's `--` is skipped (review 1013a).
    (["sudo", "PATH=/x", "tailscale"], "/p"), (("env", "--", "tailscale"), "/p"),
    (["doas", "-u", "u", "tailscale"], "/p"))]
check("unit suite: ...a wrapped program is found on the PATH its wrappers leave it (control)",
      _r19d_unwrapped == [(2, None), (3, "/q"), (2, None), (2, None), (3, "/p"), (2, None), (4, "/p"),
                          (0, "/p"), (2, None), (2, "/p"), (3, None)],
      repr(_r19d_unwrapped))
# An explicit empty environment is empty: the program is found on os.defpath, as Popen finds it,
# and a shell gets the guard's functions in an otherwise empty environment (review 1013a).
_r20d_empty_env = (_r18d_ts_program(["tailscale"], {"env": {}}),
                   sorted(_R15dNoSystemTailscale(sys.modules["subprocess"])._guard_shell(
                       "tailscale up", {"shell": True, "env": {}}, "run")[1]["env"]))
check("unit suite: ...an explicit empty environment is judged as empty, not as the runner's own (control)",
      _r20d_empty_env == (("tailscale", os.defpath), ["BASH_FUNC_tailscale%%", "BASH_FUNC_which%%"]),
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
