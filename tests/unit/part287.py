"""Part 287 of the unit suite: the installer's file modes, core dumps, old crontabs, the B3 image, image scans.

1. Update snapshots (data/.backups/<stamp>/code.tgz, data.tgz) are written owner-only: the folder
   0700 and each archive 0600, under umask 077 inside the owner's own shell (sudo's PAM session
   gives an account with its own group umask 0002). ensure_tree_modes takes group and world write
   off everything in the tree and every permission but the owner's off the snapshots, as the tree's
   owner and only on what that account owns, on a fresh install, an update, an up-to-date run and
   both rollbacks.
2. The panel marks its own process not dumpable (prctl PR_SET_DUMPABLE 0) before it reads the Flask
   secret or the key ring, so no core dump holds them; a program it starts afterwards is dumpable as
   before (the flag does not survive execve, unlike a LimitCORE=0 every child would inherit).
3. An update (and an install, and an up-to-date run) removes the crontab of a game account that no
   longer exists when every job in it is one the panel writes for that account; a file holding any
   other job, a live account's crontab, crontab(1)'s temporary file and a link are left alone.
4. The threat model says why the panel's unit has no systemd sandboxing (everything it starts, the root
   helper and the game servers, would inherit it).
5. B3's image leaves out pip, setuptools and wheel (and ensurepip's pip wheel) once B3's packages are in.
6. The "Add-on images" workflow: daily and on a pull request touching an image or a pin, a read-only
   token, scanner images by digest; its script scans what the add-on catalog pins and what the panel
   builds, refuses a Containerfile default that is not the catalog's, and gates Trivy on fixable High/Critical
   findings; every accepted finding has a reason and an expiry date.

HOW IT RUNS. install.sh's own text, cut out and run under bash over this part's scratch trees (a
stand-in cron spool among them); `id` and `sudo` are stand-ins where a check needs a root run. The
core-dump probe is a fresh interpreter that points panel.core.config's key files at scratch paths.
The scan script is loaded from .github/scripts and planned over scratch fixtures; nothing runs docker.
Nothing here runs as another account, or reads or writes /etc, the real cron spool, or data/.
"""
import atexit as _atexit287
import importlib.util as _ilu287
import json as _json287
import os
import pwd as _pwd287
import re as _re287
import shutil as _sh287
import subprocess as _sp287  # nosec B404 - bash over the repo's own install.sh text, in a scratch dir
import sys as _sys287
import tempfile as _tf287
from shlex import quote as _q287

from unit.part01 import _root, check
from unit.part06 import _inst, _inst_shfn

_TMP287 = _tf287.mkdtemp(prefix="p287-")
_atexit287.register(_sh287.rmtree, _TMP287, True)


def _bash287(script, timeout=60):
    """Run `script` under bash; its stdout and stderr together."""
    p = _sp287.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout,  # nosec B603 B607
                   check=False)
    return p.stdout + p.stderr


def _mode287(path):
    """The permission bits of `path` (not following a link) as an octal string, or "gone"."""
    try:
        return oct(os.lstat(path).st_mode & 0o777)
    except OSError:
        return "gone"


def _write287(path, text, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)


# The loose modes are made by the shell, as a umask-0002 update makes them (umask, then each file).
_LOOSE_SH287 = r"""set -eu
umask 0002
cd "$1"
mkdir -p linuxgsm-panel/panel linuxgsm-panel/data/.backups/20260101-000000
echo '# app' > linuxgsm-panel/panel/app.py
printf '#!/bin/sh\n' > linuxgsm-panel/install.sh && chmod u+x,g+x,o+x linuxgsm-panel/install.sh
(umask 077 && echo '{}' > linuxgsm-panel/data/config.json)
echo k > linuxgsm-panel/data/.backups/20260101-000000/data.tgz
echo c > linuxgsm-panel/data/.backups/20260101-000000/code.tgz
(umask 0 && echo o > outside.txt)
ln -s "$1/outside.txt" linuxgsm-panel/panel/link
"""


def _loose_tree287():
    """A panel tree as a umask-0002 update leaves it: (panel dir, a file outside it a link names)."""
    top = _tf287.mkdtemp(prefix="tree-", dir=_TMP287)
    _sp287.run(["bash", "-c", _LOOSE_SH287, "loose", top], check=False, timeout=30)  # nosec B603 B607 - own script
    return os.path.join(top, "linuxgsm-panel"), os.path.join(top, "outside.txt")


# `id` answers as a non-root account, so the run is the same whoever runs the suite (CI runs it as root).
_NOT_ROOT287 = 'id() { case "${1:-}" in -u) echo 4242 ;; *) command id "$@" ;; esac; }\n'


def _tree_modes_run287(pd, prelude=""):
    script = ("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\nPANEL_DIR=%s\n" % _q287(pd) + prelude
              + _inst_shfn("ensure_tree_modes") + "ensure_tree_modes; echo RC=$?\n")
    return _bash287(script)


def _s287_tree_modes():
    pd, outside = _loose_tree287()
    out = _tree_modes_run287(pd, _NOT_ROOT287)
    stamp = os.path.join(pd, "data", ".backups", "20260101-000000")
    got = {rel: _mode287(os.path.join(pd, rel)) for rel in (
        "", "panel", "panel/app.py", "install.sh", "data/config.json", "data/.backups",
        "data/.backups/20260101-000000", "data/.backups/20260101-000000/data.tgz")}
    check("install.sh: ensure_tree_modes takes group and world write off the code tree (files 644, folders 755)",
          got[""] == got["panel"] == "0o755" and got["panel/app.py"] == "0o644" and "RC=0" in out,
          repr((got, out)))
    check("install.sh: ...and leaves every permission but the owner's off the update snapshots (0700, 0600)",
          got["data/.backups"] == got["data/.backups/20260101-000000"] == "0o700"
          and got["data/.backups/20260101-000000/data.tgz"] == _mode287(os.path.join(stamp, "code.tgz")) == "0o600",
          repr(got))
    # Controls: the owner keeps what it had, and a file a link in the tree names is not touched.
    check("install.sh: ...the owner keeps its own bits (a script stays executable, a 0600 file stays 0600)",
          os.stat(os.path.join(pd, "install.sh")).st_mode & 0o700 == 0o700 and got["data/config.json"] == "0o600",
          repr(got))
    check("install.sh: ...and a link in the tree is not followed (the file it names keeps its mode)",
          _mode287(outside) == "0o666" and "WARN" not in out, repr((_mode287(outside), out)))


def _s287_tree_modes_owner():
    """A root run changes modes AS the tree's owner (sudo -u), never as root; a root-owned tree, as root."""
    log = os.path.join(_TMP287, "sudo.log")
    stub = ('id() { case "${1:-}" in -u) echo 0 ;; *) command id "$@" ;; esac; }\n'
            'sudo() { echo "AS $2" >> %s; shift 2; "$@"; }\n' % _q287(log))
    pd, _ = _loose_tree287()
    _tree_modes_run287(pd, stub + "_r42i_tree_owner() { echo nobody; }\n")
    try:
        with open(log, encoding="utf-8") as fh:
            as_owner = fh.read().split("\n")
        os.unlink(log)
    except OSError:
        as_owner = []
    pd2, _ = _loose_tree287()
    out = _tree_modes_run287(pd2, stub + "_r42i_tree_owner() { echo root; }\n")
    check("install.sh: ensure_tree_modes, run as root over the panel user's tree, works as that account",
          as_owner.count("AS nobody") == 2, repr(as_owner))
    check("install.sh: ...and over a tree root owns (a fresh install before the chown), as root itself",
          not os.path.exists(log) and "RC=0" in out, out)


def _snapshot_lines287():
    """install.sh's [1/6] folder line and both archive lines, cut from install.sh as written."""
    mk = _section287('    info "[1/6] Snapshotting', "    # Compressor").split("\n", 1)[-1]
    lines = [ln for ln in _inst.splitlines() if "TREE_SUDO" in ln and "tar -C" in ln]
    code = [ln for ln in lines if "--exclude=./venv --exclude=./data -cf - ." in ln] + ["exit 97"]
    data = [ln for ln in lines if "--exclude=./.backups" in ln] + ["exit 97"]
    return mk, code[0], data[0]


def _s287_snapshot_modes():
    pd, _ = _loose_tree287()
    backup = os.path.join(pd, "data", ".backups", "20991231-235959")
    _sh287.rmtree(os.path.join(pd, "data", ".backups"))
    mk, code, data = _snapshot_lines287()
    script = "\n".join(["set -euo pipefail", "umask 0002", "TREE_SUDO=''", "SNAP_GZ='gzip -1'",
                        "info() { :; }", "PANEL_DIR=%s" % _q287(pd), "BACKUP=%s" % _q287(backup),
                        mk, code, data, "echo SNAPPED"])
    out = _bash287(script)
    got = (_mode287(os.path.dirname(backup)), _mode287(backup), _mode287(os.path.join(backup, "code.tgz")),
           _mode287(os.path.join(backup, "data.tgz")))
    check("install.sh: [1/6] makes data/.backups and the snapshot's folder 0700, under a 0002 umask",
          got[:2] == ("0o700", "0o700") and "SNAPPED" in out, repr((got, out)))
    check("install.sh: ...and writes code.tgz and data.tgz 0600 (they hold the database and its key)",
          got[2:] == ("0o600", "0o600") and os.path.getsize(os.path.join(backup, "data.tgz")) > 0, repr((got, out)))


def _section287(start, end):
    i = _inst.find(start)
    j = _inst.find(end, i) if i >= 0 else -1
    return _inst[i:j] if j >= 0 else ""


def _code_lines287(text):
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _s287_tree_modes_callers():
    fresh = _code_lines287(_section287('info "[3/4] Registering the service', 'info "[4/4] Verifying'))
    full = _code_lines287(_section287('    info "[4/6] Installing dependencies', '    info "[5/6] Starting'))
    noop = _code_lines287(_section287("        install_gamedig\n        # The breached-password list",
                                      "        update_noop_line\n        exit 0"))
    abort = _code_lines287(_section287("    _update_window_abort() {", "\n    }\n"))
    rollback = _code_lines287(_section287("Rolling back to ${FROM_VER}", "if health_check; then"))
    after_chown = [part.split("_chown_panel_tree", 1)[-1] for part in (fresh, full, abort, rollback)]
    check("install.sh: ensure_tree_modes runs on a fresh install, an update, an up-to-date run and both rollbacks",
          all("ensure_tree_modes" in part for part in (fresh, full, noop, abort, rollback)),
          repr([("ensure_tree_modes" in p) for p in (fresh, full, noop, abort, rollback)]))
    check("install.sh: ...each time after the chown (an account's modes are changed once the tree is its own)",
          all("ensure_tree_modes" in part for part in after_chown), repr([("ensure_tree_modes" in p) for p in after_chown]))


# ── 2. Core dumps ────────────────────────────────────────────────────────────────────────────────
# A fresh interpreter each, so the flag starts as the kernel sets it (the suite's own process has
# long since read keys). PR_GET_DUMPABLE is 3; a child started after the key read reports its own.
_DUMP_PROBE287 = r'''
import ctypes, os, resource, subprocess, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from panel.core import config
get = lambda: ctypes.CDLL(None).prctl(3, 0, 0, 0, 0)
before, core = get(), resource.getrlimit(resource.RLIMIT_CORE)[0]
setattr(config, sys.argv[2], Path(sys.argv[3]))
getattr(config, sys.argv[4])()
kid = "import ctypes, resource; print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0), resource.getrlimit(resource.RLIMIT_CORE)[0])"
child = subprocess.run([sys.executable, "-c", kid], capture_output=True, text=True, check=False).stdout.split()
print("DUMPABLE", before, get(), child[0] if child else "none", "same-limit" if child[1:] == [str(core)] else "other-limit")
'''


def _dump_probe287(attr, reader):
    key = os.path.join(_tf287.mkdtemp(prefix="keys-", dir=_TMP287), "key")
    p = _sp287.run([_sys287.executable, "-c", _DUMP_PROBE287, _root, attr, key, reader],  # nosec B603 - own probe
                   capture_output=True, text=True, timeout=60, check=False)
    line = [ln for ln in p.stdout.splitlines() if ln.startswith("DUMPABLE ")]
    return (line[-1].split()[1:] if line else []), p.stdout + p.stderr


def _s287_core_dumps():
    secret, out = _dump_probe287("SECRET_FILE", "get_secret_key")
    check("core dumps: reading the Flask secret leaves the panel's process not dumpable (it was before)",
          secret[:2] == ["1", "0"], out)
    ring, out = _dump_probe287("CRED_KEY_FILE", "_cred_keyring")
    check("core dumps: ...and so does reading the key ring that decrypts stored credentials",
          ring[:2] == ["1", "0"], out)
    check("core dumps: ...while a program it starts afterwards (the helper, a game) is dumpable as before",
          secret[2:] == ring[2:] == ["1", "same-limit"], repr((secret, ring)))


# ── 3. Crontabs of removed game accounts ────────────────────────────────────────────────────────────
_ME287 = _pwd287.getpwuid(os.getuid()).pw_name
_HEADER287 = ("# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
              "# (/tmp/crontab.x installed on Mon Jul  6 10:00:00 2026)\n")


def _panel_jobs287(u):
    """Every form of job the panel writes into account u's crontab."""
    return ("*/5 * * * * cd /home/%s && ./csserver monitor\n" % u
            + "15 5 * * * /home/%s/csserver update > /dev/null 2>&1\n" % u
            + "@reboot mkdir -p /home/%s/.lgsm-cron && cd /home/%s && ./csserver monitor > "
              "/home/%s/.lgsm-cron/0a1b2c.log 2>&1; R=$?; T=$(date +\\%%s); echo \"$R $T $T\" > "
              "/home/%s/.lgsm-cron/0a1b2c.status\n" % (u, u, u, u)
            + "0 6 * * * /home/%s/.lgsm-cron/run 3d4e5f ZWNobyBoaQ==\n" % u
            + "0 4 * * * touch /home/%s/.restart-pending\n" % u)


def _sweep287(spool, uid):
    """Run install.sh's ensure_no_orphan_crontabs over `spool`, with `id -u` answering `uid`."""
    script = ("set -euo pipefail\nok() { echo \"OK $*\"; }\nwarn() { echo \"WARN $*\"; }\n"
              'id() { case "${1:-}" in -u) echo %s ;; *) command id "$@" ;; esac; }\n' % uid
              + "CRON_SPOOL=%s\n" % _q287(spool) + _inst_shfn("ensure_no_orphan_crontabs")
              + "ensure_no_orphan_crontabs; echo RC=$?\n")
    return _bash287(script)


def _spool287(outside):
    """A stand-in cron spool: each case's file, and a link to `outside` under an orphan's name."""
    spool = _tf287.mkdtemp(prefix="spool-", dir=_TMP287)
    files = {
        "p287gone": _HEADER287 + _panel_jobs287("p287gone"),          # removed
        "p287mixed": _panel_jobs287("p287mixed") + "0 1 * * * /usr/local/bin/own-backup\n",
        # Only the recorder's forms, naming another account's home: the account's name is what matches.
        "p287other": "".join(ln + "\n" for ln in _panel_jobs287("csserver").splitlines() if ".lgsm-cron" in ln),
        _ME287: _panel_jobs287(_ME287),                                # a live account
        "tmp.ab12cd": _panel_jobs287("tmp.ab12cd"),                    # crontab(1) mid-write
        "p287empty": _HEADER287,                                       # no job at all
    }
    for name, text in files.items():
        _write287(os.path.join(spool, name), text, 0o600)
    _write287(outside, _panel_jobs287("p287link"), 0o600)
    os.symlink(outside, os.path.join(spool, "p287link"))
    return spool


def _s287_orphan_crontabs():
    outside = os.path.join(_TMP287, "outside-crontab")
    spool = _spool287(outside)
    as_user = _sweep287(spool, 4242)
    left_user = sorted(os.listdir(spool))
    out = _sweep287(spool, 0)
    left = set(os.listdir(spool))
    check("crontabs: a removed account's crontab holding only the panel's jobs is removed, and said",
          "p287gone" not in left and "OK Removed the crontabs left by uninstalled game servers: p287gone" in out
          and "RC=0" in out, repr((sorted(left), out)))
    check("crontabs: ...one that also holds a job the panel did not write is left whole",
          "p287mixed" in left, repr(sorted(left)))
    check("crontabs: ...and so is one whose jobs name another account's home, or that holds no job",
          {"p287other", "p287empty"} <= left, repr(sorted(left)))
    check("crontabs: ...a live account's crontab, crontab's own temporary file and a link are never touched",
          {_ME287, "tmp.ab12cd", "p287link"} <= left and os.path.exists(outside), repr(sorted(left)))
    check("crontabs: ...and a run that is not root reads nothing (the spool is root's)",
          "p287gone" in left_user and "RC=0" in as_user and "WARN" not in as_user, repr((left_user, as_user)))


def _s287_orphan_callers():
    full = _code_lines287(_section287('    info "[6/6] Verifying the panel', 'ok "Update complete'))
    noop = _code_lines287(_section287("        install_gamedig\n        # The breached-password list",
                                      "        update_noop_line\n        exit 0"))
    fresh = _code_lines287(_section287('info "[1/4] Fetching the panel', 'info "[3/4] Registering'))
    check("crontabs: the sweep runs after a successful update, on an up-to-date run and on a fresh install",
          all("ensure_no_orphan_crontabs" in part for part in (full, noop, fresh)),
          repr([("ensure_no_orphan_crontabs" in p) for p in (full, noop, fresh)]))


# ── 4. The threat model: no sandboxing in the unit, and why ─────────────────────────────────────────
def _s287_threat_model():
    with open(os.path.join(_root, "docs", "THREAT-MODEL.md"), encoding="utf-8") as fh:
        tm = fh.read()
    rows = [ln for ln in tm.splitlines() if ln.startswith("| The panel's systemd unit has no sandboxing")]
    row = rows[0] if rows else ""
    check("threat model: a residual-risk row says why the panel's unit has no systemd sandboxing (the helper "
          "and the game servers it starts would inherit it), and names its authority",
          len(rows) == 1 and tm.index(row) > tm.index("## Residual risks") and "| Accept |" in row
          and all(w in row for w in ("root helper", "game server", "NoNewPrivileges", "systemd.exec(5)")), row)


# ── 5. B3's image without its installer ─────────────────────────────────────────────────────────────
def _s287_b3_no_pip():
    with open(os.path.join(_root, "panel", "addon_images", "b3", "Containerfile"), encoding="utf-8") as fh:
        text = fh.read()
    final = _code_lines287(text[text.rindex("\nFROM "):]).replace("\\\n", " ")
    runs = [ln for ln in final.splitlines() if ln.startswith("RUN ")]
    install = [r for r in runs if "pip install" in r]
    step = install[0] if len(install) == 1 else ""
    check("B3 image: the RUN that installs B3's packages then uninstalls pip, setuptools and wheel, in the same layer",
          _re287.search(r"pip install .*&& python -m pip uninstall --yes [^&]*\bpip setuptools wheel\b", step)
          is not None, step)
    check("B3 image: ...takes out ensurepip's bundled wheels, and fails the build if pip can still be imported",
          "ensurepip" in step and "os.remove" in step and step.rstrip().endswith('! python -c "import pip" 2>/dev/null'),
          step)


# ── 6. The add-on image scan ────────────────────────────────────────────────────────────────────────
_AI_PATH287 = os.path.join(_root, ".github", "scripts", "addon_images.py")
_ai_spec287 = _ilu287.spec_from_file_location("addon_images_p287", _AI_PATH287)
_AI287 = _ilu287.module_from_spec(_ai_spec287)
_ai_spec287.loader.exec_module(_AI287)


def _read287(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _wf_parts287():
    """(the workflow's code lines, the part above `jobs:`, the jobs) of addon-images.yml."""
    wf = _code_lines287(_read287(".github", "workflows", "addon-images.yml"))
    head, _, jobs = wf.partition("\njobs:")
    return wf, head, jobs


def _s287_scan_workflow():
    _, head, jobs = _wf_parts287()
    cron = _re287.findall(r'cron: "([^"]+)"', head)
    # Every pull request (its job is a required check); the scope step lists what it scans.
    paths = _re287.findall(r"^              '([^']+)'$", jobs, _re287.M)
    check("image scan: the workflow runs daily, by hand, and on every pull request, scanning one that changes "
          "an image, a pin, a linted Dockerfile or the scan's own files",
          len(cron) == 1 and _re287.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", cron[0]) is not None
          and "workflow_dispatch:" in head and "pull_request:" in head and "paths" not in head
          and {"panel/addon_images/**", "panel/services/addons.py", ".github/workflows/addon-images.yml",
               ".github/scripts/addon_images.py", ".github/trivyignore.yaml", ".github/hadolint.yaml",
               ".clusterfuzzlite/Dockerfile"} <= set(paths),
          repr((cron, paths)))


def _s287_scan_token():
    wf, head, jobs = _wf_parts287()
    perms = _re287.findall(r"^\s+permissions:(.*(?:\n\s{6,}\S.*)*)", jobs, _re287.M)
    check("image scan: ...holds a read-only token and no secret, and runs the script's plan, then its scan",
          "permissions: {}" in head and len(perms) == 1
          and _re287.sub(r"#.*", "", perms[0]).split() == ["contents:", "read", "pull-requests:", "read"]
          and "secrets." not in wf and "addon_images.py plan" in jobs
          and jobs.index("addon_images.py plan") < jobs.index("addon_images.py scan"), repr(perms))


def _s287_scan_images_pinned():
    pins = _re287.findall(r"# renovate: datasource=docker\n\s+([A-Z_]+IMAGE): '([^']+)'", _read287(
        ".github", "workflows", "addon-images.yml"))
    check("image scan: ...with Trivy and hadolint by tag and digest, in the form Renovate keeps current",
          sorted(n for n, _ in pins) == ["HADOLINT_IMAGE", "TRIVY_IMAGE"]
          and all(_re287.fullmatch(r"[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}", v) for _, v in pins),
          repr(pins))


def _s287_scan_images_from_file():
    real = _AI287.scanner_images()
    wf = _tf287.mkdtemp(prefix="ai-wf-", dir=_TMP287)
    loose = os.path.join(wf, "loose.yml")
    _write287(loose, "    env:\n      TRIVY_IMAGE: 'aquasec/trivy:0.76.2'\n"
                     "      HADOLINT_IMAGE: 'hadolint/hadolint:v2.15.1@sha256:%s'\n" % ("a" * 64), 0o600)
    check("image scan: the script reads the two scanner images from the workflow file by digest, not from the "
          "job's environment, and a pin without a digest is no image",
          real[0] and real[0].startswith("aquasec/trivy:") and real[1] and real[1].startswith("hadolint/hadolint:")
          and _AI287.scanner_images(loose) == (None, "hadolint/hadolint:v2.15.1@sha256:" + "a" * 64)
          and "os.environ.get(\"TRIVY_IMAGE" not in _read287(".github", "scripts", "addon_images.py"),
          repr((real, _AI287.scanner_images(loose))))


def _addons_fixture287(addons, containerfile):
    d = _tf287.mkdtemp(prefix="ai-", dir=_TMP287)
    _write287(os.path.join(d, "catalog.json"), _json287.dumps({"schema": 1, "addons": addons}), 0o600)
    _write287(os.path.join(d, "images", "x", "Containerfile"), containerfile, 0o600)
    return _AI287.plan(os.path.join(d, "catalog.json"), os.path.join(d, "images"))


def _s287_scan_plan():
    real = _AI287.plan()
    check("image scan: on this tree it scans BlueMap's pinned image and builds B3, with nothing wrong",
          "bluemap" in real["upstream"] and "b3" in real["builds"] and not real["problems"], repr(real))
    good = {"a": {"image": "ghcr.io/o/a@sha256:" + "1" * 64}, "x": {"base": "docker.io/library/p@sha256:" + "2" * 64}}
    ok = _addons_fixture287(good, "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
    bad = _addons_fixture287(good, "ARG BASE_IMAGE=docker.io/library/p@sha256:%s\nFROM ${BASE_IMAGE}\n" % ("2" * 64))
    loose = _addons_fixture287(dict(good, a={"image": "ghcr.io/o/b:latest"}), "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
    check("image scan: ...an image the catalog pins by digest is scanned, a build gets the catalog's values as build "
          "arguments, and one pinned by tag stops the scan",
          ok["upstream"] == {"a": "ghcr.io/o/a@sha256:" + "1" * 64}
          and ok["builds"] == {"x": [("BASE_IMAGE", "docker.io/library/p@sha256:" + "2" * 64)]}
          and not ok["problems"] and any("not pinned by digest" in p for p in loose["problems"]), repr((ok, loose)))
    check("image scan: ...and a Containerfile ARG with a default stops the scan, even one equal to the catalog's (a "
          "second copy of a pin, which makes a catalog update a panel update)",
          bad["problems"] and "ARG BASE_IMAGE has a default" in bad["problems"][0], repr(bad))
    argv = _AI287.trivy_argv("t@sha256:" + "0" * 64, "/c", "/s", "x.tar")
    gate = " ".join(argv)
    check("image scan: Trivy fails on a fixable High or Critical vulnerability or a secret, reads the accepted "
          "findings, and takes its databases from GitHub's registry",
          all(f in gate for f in ("--severity HIGH,CRITICAL", "--ignore-unfixed", "--exit-code 1",
                                  "--scanners vuln,secret", "--ignorefile /trivyignore.yaml",
                                  "--db-repository ghcr.io/", "--java-db-repository ghcr.io/"))
          and argv[:3] == ["docker", "run", "--rm"], gate)


def _s287_scan_lint():
    lint = _AI287.lint_targets(_AI287.plan())
    check("image scan: hadolint lints every build's Containerfile and ClusterFuzzLite's build image, which "
          "nothing else lints",
          ("b3 Containerfile", os.path.join(_root, "panel", "addon_images", "b3", "Containerfile")) in lint
          and (".clusterfuzzlite/Dockerfile", os.path.join(_root, ".clusterfuzzlite", "Dockerfile")) in lint
          and all(os.path.isfile(p) for _, p in lint), repr(lint))


def _s287_scan_accepted():
    text = _read287(".github", "trivyignore.yaml")
    entries = _re287.split(r"(?m)^  - id: ", _code_lines287(text))[1:]
    dates = [_re287.search(r"(?m)^    expired_at: (\d{4}-\d{2}-\d{2})$", e) for e in entries]
    check("image scan: every accepted finding names its packages, says why and expires",
          entries and all(d for d in dates)
          and all(_re287.search(r"(?m)^    statement: \"[^\"]{20,}\"$", e) and "    purls:\n      - \"pkg:" in e
                  for e in entries), repr(entries))
    hl = _code_lines287(_read287(".github", "hadolint.yaml"))
    check("image scan: hadolint turns off DL3008 alone, and says why",
          _re287.findall(r"(?m)^  - (\S+)$", hl) == ["DL3008"] and "DL3008" in _read287(".github", "hadolint.yaml")
          .split("- DL3008")[0], hl)


for _fn287 in (_s287_tree_modes, _s287_tree_modes_owner, _s287_snapshot_modes, _s287_tree_modes_callers,
               _s287_core_dumps, _s287_orphan_crontabs, _s287_orphan_callers, _s287_threat_model, _s287_b3_no_pip,
               _s287_scan_workflow, _s287_scan_token, _s287_scan_images_pinned, _s287_scan_images_from_file,
               _s287_scan_plan, _s287_scan_lint, _s287_scan_accepted):
    try:
        _fn287()
    except Exception as _e287:  # a crash names its section instead of taking the suite down
        check("part287: %s ran to the end" % _fn287.__name__, False, repr(_e287))
