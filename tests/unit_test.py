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

_R15D_SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/opt/", "/snap/", "/nix/")
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
    if isinstance(cmd, str) and kw.get("shell"):
        return cmd
    # A list with shell=True runs its first item as the script (review 1012b: it was not read).
    if isinstance(cmd, (list, tuple)) and cmd and isinstance(cmd[0], str) and kw.get("shell"):
        return cmd[0]
    # `-c` grouped with other one-letter options (`bash -lc`, `sh -ec`) is still -c.
    if (isinstance(cmd, (list, tuple)) and len(cmd) >= 3 and isinstance(cmd[2], str)
            and os.path.basename(str(cmd[0])) in ("sh", "bash", "dash")
            and isinstance(cmd[1], str) and re.fullmatch(r"-[a-z]*c[a-z]*", cmd[1])):
        return cmd[2]
    return None


def _r16d_ts_shell_env(env):
    """`env` plus bash functions `tailscale` and `which` that answer a system tailscale as missing.

    Each resolves `tailscale` on the shell's PATH as it is when called; one under a system
    directory is "command not found" (127) and `which tailscale` finds nothing, anything else runs.
    """
    _sys = "|".join('"%s"*' % _d for _d in _R15D_SYSTEM_DIRS)
    _is_sys = ('_r16d_p=$(type -P tailscale); _r16d_p=$(readlink -f "$_r16d_p" 2>/dev/null); '
               'case "$_r16d_p" in "") false;; %s) true;; *) false;; esac' % _sys)
    return dict(env, **{
        "BASH_FUNC_tailscale%%": "() { if %s; then echo 'tailscale: command not found' >&2; return 127; "
                                 "fi; command tailscale \"$@\"; }" % _is_sys,
        "BASH_FUNC_which%%": '() { if [ "$*" = tailscale ] && { %s; }; then return 1; fi; '
                             'command which "$@"; }' % _is_sys})


class _R15dNoSystemTailscale:
    """A module's subprocess handle, refusing a `tailscale` that resolves to the system's."""

    def __init__(self, real):
        # What run/Popen of `real` itself are tells a stand-in from the real: a part that left a
        # stand-in module on the attribute (unrestored) is wrapped by the next part's pass, and
        # judged by the module it named in sys.modules, that stand-in's calls were rewritten to
        # run under /bin/bash although it spawns nothing (review 1012b).
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def _system_tailscale(self, cmd, kw, how="run"):
        if not (isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "tailscale"):
            return False
        if getattr(self._real, how, None) not in _r16d_real_spawners(how):
            return False
        _path = (kw.get("env") or os.environ).get("PATH", os.defpath)
        _hit = shutil.which("tailscale", path=_path)
        return _hit is not None and os.path.realpath(_hit).startswith(_R15D_SYSTEM_DIRS)

    def _guard_shell(self, cmd, kw, how):
        """(cmd, kw) for a shell that names tailscale: under bash, with _r16d_ts_shell_env's functions."""
        _sh = _r16d_shell_text(cmd, kw)
        if (_sh is None or "tailscale" not in _sh
                or getattr(self._real, how, None) not in _r16d_real_spawners(how)):
            return cmd, kw
        kw = dict(kw, env=_r16d_ts_shell_env(kw.get("env") or os.environ))
        if kw.get("shell"):
            kw["executable"] = "/bin/bash"      # only bash reads exported functions; dash does not
        elif os.path.basename(str(cmd[0])) != "bash":
            cmd = ["/bin/bash"] + list(cmd[1:])
        return cmd, kw

    def run(self, cmd, *a, **kw):
        cmd, kw = self._guard_shell(cmd, kw, "run")
        if self._system_tailscale(cmd, kw):
            _r15d_ts_refused.append(cmd if isinstance(cmd, str) else " ".join(map(str, cmd)))
            raise FileNotFoundError(2, "No such file or directory (the unit suite answers the "
                                       "machine's own tailscale as CI's runner does)", "tailscale")
        return self._real.run(cmd, *a, **kw)

    def Popen(self, cmd, *a, **kw):  # noqa: N802 - subprocess's own name
        cmd, kw = self._guard_shell(cmd, kw, "Popen")
        if self._system_tailscale(cmd, kw, "Popen"):
            _r15d_ts_refused.append(cmd if isinstance(cmd, str) else " ".join(map(str, cmd)))
            raise FileNotFoundError(2, "No such file or directory", "tailscale")
        return self._real.Popen(cmd, *a, **kw)


# (module, attribute holding its subprocess).
# Wrapped as soon as each module is loaded and again before every part: part05 reinstalls
# nosudo_runner's shim over every module's subprocess, which replaced this answer for the rest of
# the run. _core is not imported here: under a bare `python tests/unit_test.py` (CI)
# eventlet.monkey_patch() has to come first, and part01's app import is what does it. system_ops
# is (tailscale_integration imports it), and is wrapped below; monkey_patch later patches the same
# subprocess module object the wrapper holds, in place.
_R16D_TS_HANDLES = (("panel.ops.tailscale_integration", "subprocess"),
                    ("panel.ops.system_ops", "subprocess"),
                    ("panel.ops.ssh_manager._core", "_real_subprocess"))


def _r16d_wrap_ts_handles():
    """Wrap each loaded module's handle that is not wrapped already; the modules still unloaded."""
    _unloaded = []
    for _mod, _attr in _R16D_TS_HANDLES:
        _m = sys.modules.get(_mod)
        if _m is None:
            _unloaded.append(_mod)
        elif not isinstance(getattr(_m, _attr, None), _R15dNoSystemTailscale):
            setattr(_m, _attr, _R15dNoSystemTailscale(getattr(_m, _attr)))
    return _unloaded


class _R16dWrapOnLoad:
    """Wraps a handle the moment its module finishes loading, so no part runs before it."""

    def find_spec(self, name, path=None, target=None):
        if name not in {_m for _m, _a in _R16D_TS_HANDLES}:
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
# part01, 02, 12 and 20.
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
# database with stand-ins, and node and bash on its own fixtures; imports part01, 02, 12, 14, 20, 47
# and 64 (part14's update-status stand-in, part64's firewall stand-in).
# part68 (review 1012a: cron, game files, helper and routes, builder B) drives part12's app with
# stand-ins, and the crontab pipeline in a real bash; imports part01, 05 and 12.
# part69 (the sixth review's routes, tools, page and i18n fixes, builder C) drives part12's app and
# runs node on its own fixtures; imports part01, 05, 12 and 47.
_PARTS = ("part01", "part02", "part03", "part04", "part05", "part06", "part07", "part08", "part09",
          "part10", "part11", "part12", "part13", "part14", "part16", "part17", "part18", "part19",
          "part20", "part21", "part22", "part23", "part24", "part25", "part26", "part27",
          "part28", "part29", "part30", "part31", "part32", "part33", "part34", "part35", "part36", "part37",
          "part38", "part39", "part40", "part41", "part42", "part43", "part44", "part47", "part49",
          "part50", "part51", "part52", "part53", "part54", "part55", "part56", "part57", "part58",
          "part59", "part60", "part61", "part62", "part63", "part64", "part65", "part66",
          "part67", "part68", "part69", "part15")


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
    import re as _re
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


def _r14d_real_imports(part):
    import ast as _ast
    with open(os.path.join(_root, "tests", "unit", part + ".py"), encoding="utf-8") as _fh:
        _tree = _ast.parse(_fh.read())
    return {_n.module[len("unit.part"):] for _n in _ast.walk(_tree)
            if isinstance(_n, _ast.ImportFrom) and (_n.module or "").startswith("unit.part")}


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
    _mods = {_n.module for _n in _ast.walk(_tree) if isinstance(_n, _ast.ImportFrom) and _n.module}
    _mods |= {_a.name for _n in _ast.walk(_tree) if isinstance(_n, _ast.Import) for _a in _n.names}
    # `from unit import idreuse_support` (part16, part18) names the module after `import`: it was
    # not followed, so a part import added to such a shared module went unseen (review 1012b).
    _mods |= {"unit." + _a.name for _n in _ast.walk(_tree)
              if isinstance(_n, _ast.ImportFrom) and _n.module == "unit" for _a in _n.names}
    return {_m for _m in _mods if _m.startswith("unit.")}


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

# The answer above, against a system path and a part's stand-in (control): a wrapper that refused
# nothing, or everything, would read the same as one that works. The "system" side is planted, not
# read off the machine: CI has no tailscale, so a control that asked the host compared False with
# False there and passed whatever the wrapper did. For one look, the stand-in's own directory
# counts as a system directory, and every shape each handle sees must be refused without the
# stand-in having run (it leaves a mark when it does).
_r15d_ts_ctl_dir = tempfile.mkdtemp(prefix="lgsm-unit-ts-ctl-")
_r16d_ts_mark = os.path.join(_r15d_ts_ctl_dir, "ran")
with open(os.path.join(_r15d_ts_ctl_dir, "tailscale"), "w", encoding="utf-8") as _fh_ts:
    _fh_ts.write("#!/bin/sh\necho stand-in\n: > '%s'\n" % _r16d_ts_mark)
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this runner runs itself
os.chmod(os.path.join(_r15d_ts_ctl_dir, "tailscale"), 0o700)  # nosec B103 - a stand-in in a private temp dir
_r16d_ts_env = dict(os.environ, PATH=_r15d_ts_ctl_dir + os.pathsep + os.environ.get("PATH", ""))
os.makedirs(os.path.join(_r15d_ts_ctl_dir, "own"))
with open(os.path.join(_r15d_ts_ctl_dir, "own", "tailscale"), "w", encoding="utf-8") as _fh_ts:
    _fh_ts.write("#!/bin/sh\necho own stand-in\n")
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this runner runs itself
os.chmod(os.path.join(_r15d_ts_ctl_dir, "own", "tailscale"), 0o700)  # nosec B103 - a stand-in in a private temp dir
_r16d_ts_wraps = [getattr(sys.modules.get(_m), _a, None) for _m, _a in _R16D_TS_HANDLES]
_r16d_ts_shapes = (("run", (["tailscale", "version"],), {}),
                   ("Popen", (["tailscale", "status"],), {}),
                   ("run", ("tailscale status --json 2>/dev/null || echo '{}'",), {"shell": True}),
                   ("run", ("tailscale set --ssh 2>&1",), {"shell": True}),
                   # WHICH-FOUND: `which` letting the stand-in's path through is a let-through
                   # too (the stand-in's path has no "stand-in" in it, review 1012b).
                   ("Popen", (["/bin/bash", "-c", "which tailscale && echo WHICH-FOUND; tailscale version"],),
                    {}))
_r16d_ts_let = []      # the shapes that ran the stand-in while it counted as the system's
_r16d_ts_saved_dirs = _R15D_SYSTEM_DIRS
_R15D_SYSTEM_DIRS = (os.path.realpath(_r15d_ts_ctl_dir) + os.sep,)
try:
    for _w in _r16d_ts_wraps:
        for _how, _args, _kw in _r16d_ts_shapes:
            try:
                _p = getattr(_w, _how)(*_args, env=_r16d_ts_env, stdout=-1, stderr=-1, **_kw)
                _out = (_p.communicate(timeout=10) if _how == "Popen" else (_p.stdout, _p.stderr))[0]
                if b"stand-in" in (_out or b"") or b"WHICH-FOUND" in (_out or b""):
                    _r16d_ts_let.append("%s.%s %r" % (type(_w).__name__, _how, _args[0]))
            except FileNotFoundError:
                pass    # no such program on this machine: nothing ran, so nothing got through
    # Not a tailscale command: the grep's pattern and an echo's word are text, and run.
    _r16d_ts_text = _r16d_ts_wraps[1].run(  # nosec B604 - a fixed command, through the wrapper under test
        "echo tailscale | grep -c tailscale", shell=True, env=_r16d_ts_env, capture_output=True,
        text=True).stdout
    # A shell that puts its own stand-in first on PATH still runs it (part05's secret rendering):
    # the shell is judged by the PATH it calls tailscale with, not the one it was started with.
    # Started inside the planted window, on a PATH whose first tailscale is the planted "system"
    # one, so a judge of the starting PATH refuses it here on any machine (outside, CI's PATH
    # resolved no tailscale at all and such a judge passed, review 1012b).
    _r16d_ts_own = _r16d_ts_wraps[2].run(["/bin/bash", "-c", "export PATH=%s:\"$PATH\"; tailscale" % (
        os.path.join(_r15d_ts_ctl_dir, "own"))], env=_r16d_ts_env, capture_output=True, text=True).stdout
finally:
    _R15D_SYSTEM_DIRS = _r16d_ts_saved_dirs
_r16d_ts_ran_refused = os.path.exists(_r16d_ts_mark)
# The green Popen counts as a real spawner: compared with the pre-patch class alone, every Popen
# passed from part01 on in CI's bare run (here, under smoke-local, eventlet was patched first and
# the runner captured the green one, so the planted shapes above cannot show it).
_r16d_green = sys.modules.get("eventlet.green.subprocess")
_r16d_ts_green = _r16d_green is None or _r16d_green.Popen in _r16d_real_spawners("Popen")
_r15d_ts_ctl = (_r16d_ts_let, _r16d_ts_ran_refused, _r16d_ts_text, _r16d_ts_own, _r16d_ts_green,
                _r16d_ts_wraps[0].run(["tailscale"], capture_output=True, text=True,
                                      env=_r16d_ts_env).stdout)
check("unit suite: the machine's own tailscale is answered 'not installed' through every handle that "
      "runs it, and a part's stand-in on its own PATH still runs (control)",
      all(isinstance(_w, _R15dNoSystemTailscale) for _w in _r16d_ts_wraps)
      and _r15d_ts_ctl == ([], False, "1\n", "own stand-in\n", True, "stand-in\n"),
      repr(([type(_w).__name__ for _w in _r16d_ts_wraps], _r15d_ts_ctl, _r15d_ts_refused[:3])))

# The shapes a shell comes in, and a stand-in module left on a handle (control, review 1012b): a
# grouped `-lc` and a list run with shell=True are shells too; a wrapped stand-in module is passed
# its call untouched, since it spawns nothing (judged by sys.modules' real subprocess, it was
# rewritten to /bin/bash all the same).
_r16d_sh_read = [_r16d_shell_text(*_c) for _c in (
    (["bash", "-lc", "tailscale status"], {}), (["sh", "-ec", "tailscale up"], {}),
    (["tailscale status --json"], {"shell": True}), (["bash", "--login", "x"], {}),
    (["tailscale", "-c", "x"], {}))]
_r16d_fake_calls = []


class _R16dStandInModule:
    """A part's stand-in for a subprocess module: records each call, starts nothing."""

    @staticmethod
    def run(cmd, *a, **kw):
        _r16d_fake_calls.append((cmd, sorted(kw)))


_R15dNoSystemTailscale(_R16dStandInModule).run("tailscale status --json", shell=True)
check("unit suite: ...a grouped -lc and a list with shell=True are read as shells, and a stand-in "
      "module left on a handle gets its call as made (control)",
      _r16d_sh_read == ["tailscale status", "tailscale up", "tailscale status --json", None, None]
      and _r16d_fake_calls == [("tailscale status --json", ["shell"])],
      repr((_r16d_sh_read, _r16d_fake_calls)))

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
