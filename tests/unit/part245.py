"""Part 245 of the unit suite: the helper runs from root's bytecode, and ban-watch reads fail2ban on change.

* install.sh's install_helper_code, run by bash on a scratch directory, places the helper's code,
  its checked-hash bytecode and the entry (tools/panel_helper_entry.py) at the path sudo runs; the
  entry then runs the helper from that bytecode with the same output as the helper run whole, and
  as the __main__ module with the path sudo ran as its __file__.
* The entry falls back to compiling the code file for every bytecode it must not trust: stale,
  unchecked or timestamp-based, another magic number, a symbolic link, a pyc others may write; files
  of another owner are refused (part284 covers the refusals through the entry).
* Root's readers of the helper's functions (can_already_sudo, enrolment_refusal) load the code file
  when the helper is split, and the Diagnostics comparison follows both layouts.
* app._ban_watch_tick reads the panel jail only when fail2ban's files or the panel's auth.log
  changed, on the tick after a change, while anything is banned, after a failed read or stat, and
  every F2B_FORCED_READ seconds; a ban and its expiry are still recorded within one tick.

Nothing reaches a host, sudo, fail2ban or data/.
"""
import os
import py_compile as _pyc245
import shutil as _sh245
import stat as _st245
import subprocess as _sp245  # nosec B404 - bash and the system python over this part's own scratch files
import sys as _sys245
import tempfile as _tf245
import time as _time245
from importlib import machinery as _mach245, util as _iu245
from types import SimpleNamespace as _NS245

from unit.part01 import check, eq
from unit.part05 import _root
import app as _app245
from panel.ops import system_ops as _so245
from panel.ops.debug_report import network as _nw245, root_pieces as _rp245
from panel.security import banlist as _bl245, privileged as _priv245

_T245 = _tf245.mkdtemp(prefix="lgsm-unit-p245-")
_PY245 = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else _sys245.executable
_HELPER245 = os.path.join(_root, "tools", "panel-helper")
_ENTRY_SRC245 = os.path.join(_root, "tools", "panel_helper_entry.py")
_UID245 = os.geteuid()
with open(os.path.join(_root, "install.sh"), encoding="utf-8") as _fh245:
    _INS245 = _fh245.read()


def _entry_module():
    loader = _mach245.SourceFileLoader("panel_helper_entry245", _ENTRY_SRC245)
    mod = _iu245.module_from_spec(_iu245.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


_E245 = _entry_module()


def _fn245(name):
    """The text of install.sh's shell function `name`."""
    i = _INS245.find("\n%s() {" % name)
    return _INS245[i + 1:_INS245.index("\n}\n", i) + 3] if i >= 0 else "%s() { exit 97; }\n" % name


# `install` without chown (a non-root run cannot give files to root), honouring -m; H_SUDO empty; info echoes.
_SHIM245 = ('H_SUDO=""\ninfo() { echo "$*"; }\ninstall() { local m=0755; while [[ "$1" == -* ]]; do case "$1" in -m) m="$2"; shift 2 ;; '
            '-o|-g) shift 2 ;; *) shift ;; esac; done; cp -- "$1" "$2" && chmod "$m" "$2"; }\n')


def _bash245(script):
    p = _sp245.run(["bash", "-c", script], capture_output=True, text=True, timeout=120, check=False,
                   stdin=_sp245.DEVNULL)  # nosec B603 B607 - bash over install.sh's own functions
    return p.returncode, p.stdout + p.stderr


def _tree245(name):
    """A fresh top/lib pair owned by this account, writable by nobody else (umask); returns (top, lib)."""
    top = os.path.join(_T245, name)
    lib = os.path.join(top, "lib")
    os.makedirs(lib)
    return top, lib


def _install245(lib, helper=_HELPER245):
    """install.sh's install_helper_code into `lib`, from staged copies as install_root_tools passes them."""
    _sh245.copy(helper, os.path.join(lib, ".stage-panel-helper"))
    _sh245.copy(_ENTRY_SRC245, os.path.join(lib, ".stage-panel-helper-entry"))
    script = ('%sHELPER_DIR=%s\nHELPER_TRUST_TOP=%s\nHELPER_DST="${HELPER_DIR}/panel-helper"\nHELPER_CODE="${HELPER_DIR}/panel-helper-code.py"\n'
              '%s\ninstall_helper_code "${HELPER_DIR}/.stage-panel-helper" '
              '"${HELPER_DIR}/.stage-panel-helper-entry"; echo "rc=$?"'
              % (_SHIM245, lib, os.path.dirname(lib), _fn245("install_helper_code").replace(
                  "/usr/bin/python3", _PY245)))
    return _bash245(script)


def _mode245(path):
    return _st245.S_IMODE(os.stat(path).st_mode)


def _run_entry245(lib, top, *argv):
    """The entry's load + run_code against `lib`, in a fresh -I interpreter: (rc, stdout, stderr)."""
    wrapper = (
        "import importlib.machinery as m, importlib.util as u, sys\n"
        "l = m.SourceFileLoader('e', sys.argv[1]); e = u.module_from_spec(u.spec_from_loader('e', l))\n"
        "l.exec_module(e)\n"
        "code, hit = e.load(sys.argv[2], int(sys.argv[3]), sys.argv[4])\n"
        "entry = sys.argv[2] + '/panel-helper'\n"
        "sys.argv = [entry] + sys.argv[5:]\n"
        "try:\n    e.run_code(code, entry)\n"
        "finally:\n"
        "    g = sys.modules['__main__']\n"
        "    sys.stderr.write('\\nHIT=%s FILE=%s RUN=%s\\n' % (hit, g.__file__, callable(getattr(g, 'run', None))))\n")
    p = _sp245.run([_PY245, "-I", "-c", wrapper, _ENTRY_SRC245, lib, str(_UID245), top] + list(argv),
                   capture_output=True, text=True, timeout=60, check=False,
                   stdin=_sp245.DEVNULL)  # nosec B603 - the system python over this part's own files
    return p.returncode, p.stdout, p.stderr


def _section_install_and_run245():
    top, lib = _tree245("good")
    _rc, out = _install245(lib)
    code, pyc, dst = (os.path.join(lib, n) for n in ("panel-helper-code.py", "panel-helper-code.pyc", "panel-helper"))
    eq("helper code: install_helper_code places the code 0644, its bytecode 0644 and the entry 0755 at the "
       "path sudo runs, and leaves no staged pyc", (out.strip().splitlines()[-1:],
                                                    [_mode245(p) if os.path.exists(p) else None for p in (code, pyc, dst)],
                                                    os.path.exists(os.path.join(lib, ".stage-panel-helper-code.pyc"))),
       (["rc=0"], [0o644, 0o644, 0o755], False))
    with open(pyc, "rb") as fh:
        head = fh.read(16)
    with open(code, "rb") as fh, open(_HELPER245, "rb") as fh2, open(dst, "rb") as fh3, open(_ENTRY_SRC245, "rb") as fh4:
        same = (fh.read() == fh2.read(), fh3.read() == fh4.read())
    eq("helper code: the code file is tools/panel-helper byte for byte, the entry is tools/panel_helper_entry.py, "
       "and the pyc is a checked-hash pyc (PEP 552 flags 0b11) of the code", (same, int.from_bytes(head[4:8], "little")),
       ((True, True), 3))
    eq("helper code: the entry loads that bytecode", _E245.load(lib, _UID245, top)[1], True)
    direct = _sp245.run([_PY245, "-I", _HELPER245, "--list-verbs"], capture_output=True, text=True, timeout=60,
                        check=False, stdin=_sp245.DEVNULL)  # nosec B603 - the repo's own helper, read-only verb
    rc2, out2, err2 = _run_entry245(lib, top, "--list-verbs")
    check("helper code: run through the entry from bytecode, --list-verbs prints what the helper run whole "
          "prints, with the same exit status",
          (rc2, out2) == (direct.returncode, direct.stdout) and direct.stdout.strip() != "" and "HIT=True" in err2,
          repr((rc2, direct.returncode, len(out2), len(direct.stdout), err2[-300:])))
    check("helper code: the helper runs as __main__ with the entry's path as __file__, so its own re-exec "
          "(systemd-run ... --job) comes back through the path sudo runs",
          "FILE=%s/panel-helper RUN=True" % lib in err2, err2[-300:])
    return top, lib


def _variant245(name, mutate):
    """A good tree, `mutate(lib)` applied: whether the entry used the bytecode, and whether it got the helper's code."""
    top, lib = _tree245(name)
    _install245(lib)
    mutate(lib)
    code, hit = _E245.load(lib, _UID245, top)
    return hit, "validate" in code.co_names and "run" in code.co_names   # the helper's own module code


def _chmod245(rel, add):
    """A mutation that adds the write bit `add` ("g+w" / "o+w") to `rel` in lib (lib itself for "")."""
    return lambda lib: _sp245.run(["chmod", add, os.path.join(lib, rel) if rel else lib], check=True,
                                  timeout=10, stdin=_sp245.DEVNULL)  # nosec B603 B607 - this part's scratch file


def _recompile245(mode):
    def mutate(lib):
        src, pyc = os.path.join(lib, "panel-helper-code.py"), os.path.join(lib, "panel-helper-code.pyc")
        os.remove(pyc)
        _pyc245.compile(src, cfile=pyc, doraise=True, invalidation_mode=mode)
    return mutate


def _stale245(lib):
    with open(os.path.join(lib, "panel-helper-code.py"), "a", encoding="utf-8") as fh:
        fh.write("\nSTALE245 = 1\n")


def _magic245(lib):
    pyc = os.path.join(lib, "panel-helper-code.pyc")
    with open(pyc, "r+b") as fh:
        fh.write(b"\x00\x00\x00\x00")


def _symlink245(lib):
    pyc = os.path.join(lib, "panel-helper-code.pyc")
    os.rename(pyc, pyc + ".real")
    os.symlink(pyc + ".real", pyc)


def _section_fallbacks245():
    cases = (("a code file changed after its pyc was compiled", _stale245),
             ("a timestamp-based pyc", _recompile245(_pyc245.PycInvalidationMode.TIMESTAMP)),
             ("an unchecked-hash pyc", _recompile245(_pyc245.PycInvalidationMode.UNCHECKED_HASH)),
             ("another interpreter's magic number", _magic245),
             ("a pyc that is a symbolic link", _symlink245),
             ("a pyc others may write", _chmod245("panel-helper-code.pyc", "o+w")),
             ("a pyc its group may write", _chmod245("panel-helper-code.pyc", "g+w")))
    got = {why: _variant245("v%d" % i, fn) for i, (why, fn) in enumerate(cases)}
    eq("helper code: the entry compiles the code file instead of trusting the bytecode for every case it "
       "must not trust, and the helper still loads", got, {why: (False, True) for why, _fn in cases})
    top, lib = _tree245("owner")
    _install245(lib)
    raised = []
    try:
        _E245.load(lib, _UID245 + 1, top)
    except _E245.Untrusted:
        raised.append("Untrusted")
    eq("helper code: files owned by another account than the one the entry expects (root) are refused",
       raised, ["Untrusted"])
    raised = []
    try:
        _E245.open_dir(lib, _UID245, os.path.join(top, "lib", "elsewhere"))
    except _E245.Untrusted:
        raised.append("Untrusted")
    except OSError as e:
        raised.append(type(e).__name__)
    os.remove(os.path.join(lib, "panel-helper-code.py"))
    try:
        _E245.load(lib, _UID245, top)
    except OSError as e:
        raised.append(type(e).__name__)
    eq("helper code: a directory outside the checked top is refused, and a missing code file is an error "
       "(the entry exits 1 with a message), never an empty helper", raised, ["Untrusted", "FileNotFoundError"])


def _section_constants245():
    with open(_ENTRY_SRC245, encoding="utf-8") as fh:
        text = fh.read()
    eq("helper code: the entry's fixed values are the production ones (root's directory, uid 0, checked from /), "
       "its code file is the one install.sh and Diagnostics name, and it runs under the isolated system python",
       (_E245.LIB_DIR, _E245.ROOT_UID, _E245.TOP, _E245.CODE, _E245.BYTECODE, text.splitlines()[0]),
       (os.path.dirname(_priv245.HELPER_PATH), 0, "/", _so245._HELPER_CODE, _so245._HELPER_CODE + "c",
        "#!/usr/bin/python3 -I"))
    check("helper code: install.sh's HELPER_CODE sits beside the helper under the entry's file name",
          'HELPER_CODE="${HELPER_DIR}/%s"' % _E245.CODE in _INS245, "")
    check("helper code: the entry reads nothing from the environment or its arguments before the helper's "
          "code does (sudo's environment is the caller's to shape)",
          not any(w in text for w in ("os.environ", "getenv", "sys.argv", "input(")), "")
    irt = _fn245("install_root_tools")
    i_split, i_whole = irt.find("install_helper_code"), irt.find('-m 0755 "${_stage}" "${HELPER_DST}"')
    check("helper code: install_root_tools tries the split helper first and, when that fails, places the "
          "helper whole as before and removes the code file (so every reader sees the whole one)",
          0 < i_split < i_whole and 'rm -f "${HELPER_CODE}" "${HELPER_CODE}c"' in irt[i_whole:], irt[:200])


def _section_failed_install245():
    _top, lib = _tree245("bad")
    bad = os.path.join(_T245, "broken-helper")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("def broken(:\n")
    with open(os.path.join(lib, "panel-helper"), "w", encoding="utf-8") as fh:
        fh.write("OLD HELPER\n")
    _rc, out = _install245(lib, bad)
    with open(os.path.join(lib, "panel-helper"), encoding="utf-8") as fh:
        kept = fh.read()
    eq("helper code: a code file that does not compile fails install_helper_code before anything is placed: "
       "the helper at the path sudo runs is untouched", (out.strip().splitlines()[-1:], kept,
                                                         os.path.exists(os.path.join(lib, "panel-helper-code.py"))),
       (["rc=1"], "OLD HELPER\n", False))


def _section_readers245():
    _top, lib = _tree245("readers")
    with open(os.path.join(lib, "panel-helper"), "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/python3 -I\n# an entry: defines nothing\n")
    pre = 'HELPER_DIR=%s\n%s%s' % (lib, _fn245("can_already_sudo"), _fn245("enrolment_refusal"))
    probe = 'can_already_sudo nosuchuser245; enrolment_refusal nosuchuser245; echo "end"'
    _rc, whole = _bash245(pre + probe)
    with open(os.path.join(lib, "panel-helper-code.py"), "w", encoding="utf-8") as fh:
        fh.write("def _escalation_verdict(u):\n    return ('no', '')\n\n\ndef _enrolment_refusal(u):\n    return ''\n")
    _rc, split = _bash245(pre + probe)
    eq("helper code: root's two readers of the helper's functions load the code file when the helper is split "
       "(an entry defines neither function)", (whole.split(), split.split()),
       (["unknown", "the", "helper", "could", "not", "check", "it", "end"], ["no", "end"]))


def _section_pieces245():
    rdir = os.path.join(_T245, "pieces")
    os.makedirs(rdir)
    for name, data in (("panel-helper", b"entry\n"), ("panel-helper-code.py", b"code\n")):
        with open(os.path.join(rdir, name), "wb") as fh:
            fh.write(data)
    blob = _so245._git_blob_id
    head = {"tools/panel-helper": blob(os.path.join(rdir, "panel-helper-code.py")),
            "tools/panel_helper_entry.py": blob(os.path.join(rdir, "panel-helper"))}
    saved = (_so245._root_dir, _so245._head_blobs)
    try:
        _so245._root_dir, _so245._head_blobs = (lambda: rdir), (lambda: dict(head))
        split = {k: v["state"] for k, v in _so245.root_piece_state(force=True).items()}
        os.remove(os.path.join(rdir, "panel-helper-code.py"))
        head["tools/panel-helper"] = blob(os.path.join(rdir, "panel-helper"))
        whole = {k: v["state"] for k, v in _so245.root_piece_state(force=True).items()}
    finally:
        _so245._root_dir, _so245._head_blobs = saved
        _so245._root_pieces_cache.update(at=0.0, res=None)
    eq("helper code: Diagnostics compares the code file with tools/panel-helper and the entry with "
       "tools/panel_helper_entry.py when split, the whole helper with tools/panel-helper otherwise",
       ({k: split[k] for k in ("panel-helper", "panel-helper entry")},
        {k: whole[k] for k in ("panel-helper", "panel-helper entry")}),
       ({"panel-helper": "same", "panel-helper entry": "same"},
        {"panel-helper": "same", "panel-helper entry": "unused"}))
    eq("helper code: the report words an unused entry", _rp245._piece_line("panel-helper entry", {"state": "unused"}, None),
       "not used (the helper is installed whole)")


# ── ban-watch ────────────────────────────────────────────────────────────────────────────────────
class _F2bRig245:
    """fail2ban's log and database and the panel's auth.log as scratch files, a clock, a counted read."""

    def __init__(self):
        d = os.path.join(_T245, "f2b")
        os.makedirs(d)
        self.log, self.db, self.auth = (os.path.join(d, n) for n in ("fail2ban.log", "fail2ban.sqlite3", "auth.log"))
        for p in (self.log, self.db, self.auth):
            self.touch(p)
        self.clock = {"t": _time245.monotonic() + 200000.0}
        self.reads, self.answer, self.events = 0, set(), []
        self.state = {"seen": None}

    @staticmethod
    def touch(path):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("x\n")

    def read(self):
        self.reads += 1
        return None if self.answer is None else set(self.answer)

    def tick(self, dt=90):
        """One app._ban_watch_tick; whether it read the jail."""
        before = self.reads
        self.clock["t"] += dt
        _app245._ban_watch_tick(None, self.state)   # the app is only for _f2b_record_events, stubbed
        return self.reads > before


def _f2b_scenario245(rig):
    first = [rig.tick() for _ in range(3)]
    rig.touch(rig.auth)                           # five failed logins written...
    on_line = rig.tick()
    rig.answer = {"203.0.113.45"}                 # ...and the ban lands after that read, nothing else written
    settled = rig.tick()
    banned = [rig.tick() for _ in range(2)]
    rig.answer = set()                            # expired, wherever fail2ban logs it
    expired = rig.tick()
    quiet = [rig.tick() for _ in range(2)]
    rig.touch(rig.log)                            # fail2ban-client set ... banip, by hand
    rig.answer = {"198.51.100.45"}
    by_hand = rig.tick()
    return first, on_line, settled, banned, expired, quiet, by_hand


def _section_banwatch245():
    rig = _F2bRig245()
    saved_gate = dict(_bl245._f2b_gate)
    saved = [(_bl245, "F2B_STATE_FILES"), (_bl245, "_panel_auth_log"), (_bl245, "time"), (_bl245, "watch_ufw"),
             (_bl245, "_allow"),
             (_so245, "panel_fail2ban_banned_ips"), (_app245, "_f2b_record_events"), (_bl245, "set_f2b")]
    saved = [(o, n, getattr(o, n)) for o, n in saved]
    try:
        _bl245.F2B_STATE_FILES = (rig.log, rig.db)
        _bl245._panel_auth_log = lambda: rig.auth
        _bl245.time = _NS245(monotonic=lambda: rig.clock["t"], time=_time245.time)
        _bl245.watch_ufw = lambda read: False
        _bl245.set_f2b = lambda ips, taken=None: None
        _so245.panel_fail2ban_banned_ips = rig.read
        _app245._f2b_record_events = lambda app, new, gone: (new or gone) and rig.events.append((new, gone))
        _bl245._f2b_gate.update(key=None, read_at=float("-inf"), checked_at=float("-inf"), skipped=0,
                                last_skipped=False, settling=True)
        first, on_line, settled, banned, expired, quiet, by_hand = _f2b_scenario245(rig)
        eq("ban-watch: the first tick reads, the tick after it reads once more, then ticks with nothing "
           "changed and nothing banned skip the privileged read", first, [True, True, False])
        eq("ban-watch: the tick after the panel's auth.log changed reads, and so does the next, which finds "
           "the ban that landed after the first read (no fail2ban file needed to change)",
           (on_line, settled), (True, True))
        eq("ban-watch: while anything is banned every tick reads, so the expiry is recorded on the tick it "
           "happens; then reads stop again", (banned, expired, quiet), ([True, True], True, [False, False]))
        eq("ban-watch: a ban made by hand (fail2ban's log written) is read on the next tick",
           by_hand, True)
        eq("ban-watch: each ban and its expiry was recorded exactly once, on the tick it was read",
           rig.events, [(("203.0.113.45",), ()), ((), ("203.0.113.45",)), (("198.51.100.45",), ())])
        _banwatch_rest245(rig)
    finally:
        for o, n, v in saved:
            setattr(o, n, v)
        _bl245._f2b_gate.clear()
        _bl245._f2b_gate.update(saved_gate)


def _banwatch_rest245(rig):
    """The forced read, the report line, and the reads after a failed read or stat."""
    rig.answer = set()
    for _ in range(4):
        rig.tick()
    skipped = rig.tick()
    forced = rig.tick(_bl245.F2B_FORCED_READ)
    eq("ban-watch: an unchanged, empty jail is still read every F2B_FORCED_READ seconds",
       (skipped, forced), (False, True))
    line = _bangate245_after_skip(rig)
    check("ban-watch: the report's ban-gate line says fail2ban's files were checked after a skip",
          "fail2ban's files unchanged, checked" in line, line)
    rig.touch(rig.log)
    rig.answer = None
    failed = [rig.tick(), rig.tick(), rig.tick()]
    rig.answer = set()
    _bl245.F2B_STATE_FILES = (rig.log, os.path.join(rig.log, "not-a-dir"))
    unstat = [rig.tick(), rig.tick(), rig.tick()]
    eq("ban-watch: a failed read (None) reads again every tick until one succeeds, and so does a stat "
       "that fails", (failed, unstat), ([True, True, True], [True, True, True]))


def _bangate245():
    lines = []
    _nw245._bangate_line(_NS245(posture=lines.append, posture_find=lambda *a, **k: None))
    return lines


def _bangate245_after_skip(rig):
    for _ in range(3):
        rig.tick()
    return "".join(_bangate245())


try:
    _section_install_and_run245()
    _section_fallbacks245()
    _section_constants245()
    _section_failed_install245()
    _section_readers245()
    _section_pieces245()
    _section_banwatch245()
finally:
    _sh245.rmtree(_T245, ignore_errors=True)
