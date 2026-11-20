"""Part 284 of the unit suite: the helper's entry fails securely.

1. A code file or a directory on the way that someone other than root could have changed is refused:
   the entry exits 1 with a message saying to re-run install.sh as root, and runs nothing.
2. The pyc is optional: without one, or with a stale or forged one, the entry runs the code it read
   through the checked descriptor, and never reads the code file again by its path.
3. install.sh's install_helper_code places the entry only where the entry's own check passes, so a
   host whose directories fail it gets the helper whole, not an entry that refuses every call.

Each tree is this account's own, with this account standing in for root (the entry's uid and top
parameters). Nothing reaches a host, sudo or data/.
"""
import os
import py_compile as _pyc284
import shutil as _sh284
import subprocess as _sp284  # nosec B404 - the system python and bash over this part's own scratch files
import tempfile as _tf284

from unit.part01 import check, eq
from unit.part245 import _ENTRY_SRC245, _PY245, _install245

_T284 = _tf284.mkdtemp(prefix="lgsm-unit-p284-")
_UID284 = os.geteuid()

# The entry's start(), run in a fresh isolated interpreter against a scratch tree. With "noopen",
# builtins.open raises from then on: the entry must not read the code file by its path.
_RUN284 = (
    "import builtins, importlib.machinery as m, importlib.util as u, sys\n"
    "l = m.SourceFileLoader('e', sys.argv[1]); e = u.module_from_spec(u.spec_from_loader('e', l))\n"
    "l.exec_module(e)\n"
    "if sys.argv[5] == 'noopen':\n"
    "    def _no(*a, **k):\n"
    "        raise RuntimeError('read by path: %r' % (a[:1],))\n"
    "    builtins.open = _no\n"
    "e.start(sys.argv[2] + '/panel-helper', sys.argv[2], int(sys.argv[3]), sys.argv[4])\n")


def _code284(marker, word):
    """A stand-in helper: it creates `marker` (without open) and prints `word`."""
    return ("import os\nos.close(os.open(%r, os.O_CREAT | os.O_WRONLY, 0o600))\nprint(%r)\n"
            % (marker, word))


def _tree284(name, loose=False):
    """A tree installed by install_helper_code with a stand-in helper; (top, lib, marker, install output).

    With `loose`, the top directory is group-writable before the install.
    """
    top = os.path.join(_T284, name)
    lib = os.path.join(top, "lib")
    os.makedirs(lib)
    if loose:
        _chmod284(top, "g+w")
    marker = os.path.join(top, "ran")
    helper = os.path.join(top, "stand-in-helper")
    with open(helper, "w", encoding="utf-8") as fh:
        fh.write(_code284(marker, "RAN284"))
    return top, lib, marker, _install245(lib, helper)[1]


def _entry284(top, lib, mode="open"):
    p = _sp284.run([_PY245, "-I", "-c", _RUN284, _ENTRY_SRC245, lib, str(_UID284), top, mode],
                   capture_output=True, text=True, timeout=60, check=False,
                   stdin=_sp284.DEVNULL)  # nosec B603 - the system python over this part's own files
    return p.returncode, p.stdout, p.stderr


def _chmod284(path, add):
    _sp284.run(["chmod", add, path], check=True, timeout=10,
               stdin=_sp284.DEVNULL)  # nosec B603 B607 - this part's scratch file


def _refused284(name, target, add):
    """Install, add the write bit to `target` (a path relative to lib, "" for lib), run the entry."""
    top, lib, marker, _out = _tree284(name)
    _chmod284(os.path.join(lib, target) if target else lib, add)
    rc, out, err = _entry284(top, lib)
    return (rc, "RAN284" in out, os.path.exists(marker), "refusing to run" in err,
            "re-run install.sh as root" in err), err[-300:]


def _section_refusals284():
    got, err = _refused284("code", "panel-helper-code.py", "o+w")
    eq("helper entry: a code file others may write is refused, exit 1 with a message to re-run "
       "install.sh as root, and the code is not run", got, (1, False, False, True, True))
    check("helper entry: the refusal names the code file", "panel-helper-code.py" in err, err)
    got, err = _refused284("dir", "", "g+w")
    eq("helper entry: a directory on the way its group may write is refused and nothing runs",
       got, (1, False, False, True, True))


def _section_optional_pyc284():
    top, lib, marker, _out = _tree284("nopyc")
    os.remove(os.path.join(lib, "panel-helper-code.pyc"))
    rc, out, err = _entry284(top, lib, "noopen")
    eq("helper entry: with no pyc the code read through the checked descriptor runs, and the code file "
       "is not read again by its path", (rc, out.strip(), os.path.exists(marker)), (0, "RAN284", True))
    check("helper entry: no traceback when the pyc is missing", "Traceback" not in err, err[-300:])

    top, lib, marker, _out = _tree284("forged")
    forged_src = os.path.join(top, "forged.py")
    with open(forged_src, "w", encoding="utf-8") as fh:
        fh.write(_code284(os.path.join(top, "forged-ran"), "FORGED284"))
    pyc = os.path.join(lib, "panel-helper-code.pyc")
    os.remove(pyc)
    _pyc284.compile(forged_src, cfile=pyc, doraise=True,
                    invalidation_mode=_pyc284.PycInvalidationMode.CHECKED_HASH)
    rc, out, _err = _entry284(top, lib, "noopen")
    eq("helper entry: a checked-hash pyc of other code (forged or stale) is not run; the checked "
       "source is", (rc, out.strip(), os.path.exists(os.path.join(top, "forged-ran"))),
       (0, "RAN284", False))

    top, lib, marker, _out = _tree284("stale")
    with open(os.path.join(lib, "panel-helper-code.py"), "a", encoding="utf-8") as fh:
        fh.write("print('STALE284')\n")
    rc, out, _err = _entry284(top, lib, "noopen")
    eq("helper entry: a pyc older than the code file falls back to the code as read now",
       (rc, out.split()), (0, ["RAN284", "STALE284"]))


def _section_installer284():
    top, lib, _marker, out = _tree284("good")
    rc, run, _err = _entry284(top, lib)
    eq("helper entry: on a correct tree install_helper_code places the entry, which runs the code",
       (out.strip().splitlines()[-1:], os.path.exists(os.path.join(lib, "panel-helper")), rc, run.strip()),
       (["rc=0"], True, 0, "RAN284"))
    top, lib, _marker, out = _tree284("loose", loose=True)
    eq("helper entry: install_helper_code fails (so install_root_tools places the helper whole) and "
       "places no entry when a directory above the helper's fails the entry's check",
       (out.strip().splitlines()[-1:], os.path.exists(os.path.join(lib, "panel-helper"))),
       (["rc=1"], False))
    check("helper entry: install_helper_code says why the helper is placed whole",
          "is not root's alone, so the helper is placed whole" in out, out[-300:])


try:
    _section_refusals284()
    _section_optional_pyc284()
    _section_installer284()
finally:
    _sh284.rmtree(_T284, ignore_errors=True)
