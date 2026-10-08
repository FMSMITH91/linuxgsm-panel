"""Debug-report section(s): install.

Owner: builder B3. install model and privilege verdict (R16), which sudo (R26).

Accounts are printed as ROLES with a uid (the installer's service account, a login account, root),
never by name; paths as yes/no or '<panel>/...'; groups only from a fixed list. Passwordless sudo is
read from system_ops' cached probe only: _check_sudo() is never called from here, because every
real probe that fails counts toward pam_faillock.
"""
import os
import re
import shutil
import subprocess  # nosec B404 - `sudo --version`, a fixed argv, no shell
import sys
import time

from panel.ops import system_ops as so
from panel.ops.debug_report._base import Result, ago, unread_line
from panel.security import privileged as _priv

AREA = "Install & privilege"
# install.sh's SERVICE_USER: the account a root install creates for the panel. A role, not a name
# printed: it is the installer's own constant, the same on every host.
SERVICE_ACCOUNT = "lgsmpanel"
ETC_GROUP = "/etc/group"
NSSWITCH = "/etc/nsswitch.conf"
SUDO_WS = "/usr/bin/sudo.ws"
_NSS_SOURCES = frozenset(("files", "sss", "ldap", "nis", "db", "compat", "systemd", "winbind"))
_SUDO_VER_RE = re.compile(r"(sudo-rs|Sudo version|sudo) ?v?(\d[\w.]{0,20})")


def _groups():
    """Fixed-list group names this process is in: the panel's own group, sudo, admin, wheel."""
    wanted = {_priv.GAME_GROUP, "sudo", "admin", "wheel"}
    mine = set(os.getgroups()) | {os.getegid()}
    out = []
    with open(ETC_GROUP, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split(":")
            if len(parts) >= 3 and parts[0] in wanted and parts[2].isdigit() \
                    and int(parts[2]) in mine:
                out.append(parts[0])
    return sorted(out)


def _role(scope):
    """'the installer's service account (uid 998)' / 'a login account (uid 1000)' / 'root'."""
    import pwd
    uid = os.geteuid()
    if uid == 0:
        return "root"
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        return "an account with no passwd entry (uid %d)" % uid
    if name == SERVICE_ACCOUNT:
        return "the installer's service account (uid %d)" % uid
    if scope == "user":
        return "a login account (uid %d)" % uid
    return "another account (uid %d)" % uid


def _model():
    """(scope, the Install model line)."""
    if so._is_system_service():
        scope, text = "system", "system service"
    elif os.path.exists(os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")):
        scope, text = "user", "per-user (systemd --user)"
    else:
        scope, text = None, "no unit file (started by hand?)"
    return scope, "%s as %s" % (text, _role(scope))


def _sudo_probe():
    """(ok: True/False/None, age in seconds or None) from system_ops' cache. Never probes."""
    probe = getattr(so, "_SUDO_PROBE", None) or {}
    ok = probe.get("ok")
    at = probe.get("at") or 0
    return ok, (time.time() - at) if ok is not None and at else None


def verdict_text(euid, helper, sudo_ok):
    """The privilege verdict: what can reach root on this install, in one fixed sentence."""
    if euid == 0:
        return "the panel runs as root, so nothing constrains its privileged actions"
    if sudo_ok:
        return ("passwordless sudo works for this account, so the helper boundary does not "
                "constrain this panel")
    if helper:
        if sudo_ok is None:
            return ("helper installed; whether general passwordless sudo also works was not "
                    "probed in this process")
        return "narrow grant in force, so root is reachable only through the helper"
    if sudo_ok is None:
        return "no helper installed; passwordless sudo not probed in this process"
    return ("no helper and no passwordless sudo, so every privileged action will be refused")


def _privilege_lines(res, facts):
    helper = bool(so._helper_present())
    ok, age = _sudo_probe()
    facts["verdict"] = verdict_text(os.geteuid(), helper, ok)
    res.add("- **Verdict**: " + facts["verdict"])
    res.add("- **Privileged helper installed**: %s" % ("yes" if helper else "no"))
    res.add("- **Passwordless `sudo -n true`**: %s" % (
        "not probed in this process" if ok is None
        else "%s (cached, probed %s ago)" % ("works" if ok else "refused", ago(age))))
    if os.geteuid() != 0 and not helper and ok is False:
        res.find("fail", AREA, "no helper and no passwordless sudo: privileged actions are refused")


def _interpreter():
    """'<panel>/venv/bin/python3, Python 3.12.3 · pyvenv.cfg 3.12, same · sys.prefix is the venv: yes'."""
    import platform
    venv = os.path.realpath(os.path.join(so.PANEL_DIR, "venv"))
    # The path the interpreter was STARTED as, not its realpath: install.sh's venv
    # (`python3 -m venv`) makes venv/bin/python3 a symlink to /usr/bin/python3, so the resolved
    # path is always the system one. The venv dir itself may be reached through a symlink.
    exe = os.path.abspath(sys.executable or "")
    venvs = {venv, os.path.abspath(os.path.join(so.PANEL_DIR, "venv"))}
    if any(exe.startswith(v + os.sep) for v in venvs):
        where = "<panel>/venv/bin/" + os.path.basename(sys.executable or "python")
    elif sys.prefix != sys.base_prefix:
        # Checked before the realpath: a virtualenv's python is a symlink to the system one, so
        # resolving it named every OTHER virtualenv "system python".
        where = "a virtualenv outside this checkout"
    elif os.path.realpath(exe).startswith(("/usr/bin/", "/usr/local/bin/")):
        where = "system python"
    else:
        where = "other path"
    text = "%s, Python %s" % (where, platform.python_version())
    text += " · " + _pyvenv_text(venv)
    return text + " · sys.prefix is the venv: %s" % (
        "yes" if os.path.realpath(sys.prefix) == venv else "no")


def _pyvenv_text(venv):
    cfg = {}
    try:
        with open(os.path.join(venv, "pyvenv.cfg"), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, sep, value = line.partition("=")
                if sep:
                    cfg[key.strip()] = value.strip()
    except FileNotFoundError:
        return "pyvenv.cfg absent"
    except OSError as exc:
        return "pyvenv.cfg unreadable (%s)" % type(exc).__name__
    ver = cfg.get("version") or cfg.get("version_info") or ""
    m = re.match(r"(\d+)\.(\d+)", ver)
    if not m:
        return "pyvenv.cfg has no version"
    same = (int(m.group(1)), int(m.group(2))) == sys.version_info[:2]
    return "pyvenv.cfg %s.%s, %s" % (m.group(1), m.group(2), "same" if same else "DIFFERENT")


def _stdin_kind():
    try:
        target = os.readlink("/proc/self/fd/0")
    except OSError:
        return "stdin closed"
    if target == "/dev/null":
        return "stdin /dev/null"
    if target.startswith(("/dev/pts/", "/dev/tty")):
        return "stdin a terminal"
    return "stdin a pipe" if target.startswith("pipe:") else "stdin other"


def _under_unit():
    """'yes (cgroup is the panel's unit; stdin /dev/null; INVOCATION_ID set)'. Never the path."""
    try:
        with open("/proc/self/cgroup", encoding="ascii", errors="replace") as fh:
            in_unit = "/linuxgsm-panel.service" in fh.read()
    except OSError:
        in_unit = None
    head = "unknown (cgroup unreadable)" if in_unit is None else "yes" if in_unit else "no"
    return "%s (%s; INVOCATION_ID %s)" % (
        head, _stdin_kind(), "set" if os.environ.get("INVOCATION_ID") else "not set")


def panel_conf_text(path=None):
    """'points at this checkout: yes · data dir: yes · database: yes', or why it cannot say."""
    from panel.core import config as _cfg
    path = path or os.path.join(os.path.dirname(_priv.HELPER_PATH), "panel.conf")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            conf = {k.strip(): v.strip() for k, _, v in
                    (line.partition("=") for line in fh if "=" in line and not line.startswith("#"))}
    except FileNotFoundError:
        return "absent (helper not installed)"
    except OSError as exc:
        return "unreadable (%s)" % type(exc).__name__

    def same(key, want):
        have = conf.get(key)
        return "not set" if not have else "yes" if os.path.realpath(have) == os.path.realpath(
            str(want)) else "NO"
    return "points at this checkout: %s · data dir: %s · database: %s" % (
        same("panel_dir", so.PANEL_DIR), same("data_dir", _cfg.DATA_DIR),
        same("db_path", _cfg.DB_PATH))


def _identity_lines(res, facts):
    scope, model = _model()
    res.add("- **Install model**: " + model)
    res.add("- **Interpreter**: " + _interpreter())
    res.add("- **Under the unit**: " + _under_unit())
    conf = panel_conf_text()
    res.add("- **Helper panel.conf**: " + conf)
    if "NO" in conf.split():
        res.find("warn", AREA, "the helper's panel.conf points at a different install")
    try:
        res.add("- **Groups (of the panel's fixed list)**: %s" % (", ".join(_groups()) or "none"))
    except OSError as exc:
        res.add(unread_line("Groups", exc))
    facts["scope"] = scope


# ── R26: which sudo answers ──────────────────────────────────────────────────────────────────────
def run_version(path, timeout=5):
    """The FIRST line of `<sudo> --version`, or raise.

    The rest is dropped at once: run as root, classic sudo goes on to print the host's addresses. A
    module function, so the tests can stand in for it.
    """
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = subprocess.run([path, "--version"], stdin=subprocess.DEVNULL,  # nosec B603 - fixed argv
                       capture_output=True, text=True, timeout=timeout, check=False,
                       env=dict(os.environ, LC_ALL="C"))
    first = (r.stdout or "").split("\n", 1)[0]
    del r
    return first


def _sudo_version(path):
    try:
        first = run_version(path)
    except (OSError, subprocess.SubprocessError) + so._SOPS_TIMEOUTS as exc:
        # + the eventlet-original TimeoutExpired, which is not a green SubprocessError.
        return "version unreadable (%s)" % type(exc).__name__
    m = _SUDO_VER_RE.search(first)
    if not m:
        return "version unreadable"
    return "%s %s" % ("sudo-rs" if m.group(1) == "sudo-rs" else "sudo", m.group(2))


def nss_sudoers():
    """The sources on /etc/nsswitch.conf's 'sudoers:' line, as fixed tokens; [] if there is none."""
    with open(NSSWITCH, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip().startswith("sudoers:"):
                return [t if t in _NSS_SOURCES else "other"
                        for t in re.findall(r"[a-z_]+", line.split(":", 1)[1].split("#")[0])]
    return []


def _nss_text():
    """' · nsswitch sudoers: files sss (sudo-rs ignores the sss rules)', for sudo-rs only."""
    try:
        srcs = nss_sudoers()
    except OSError as exc:
        return " · nsswitch unreadable (%s)" % type(exc).__name__
    text = " · nsswitch sudoers: %s" % (" ".join(srcs) or "not set")
    ignored = [s for s in srcs if s in ("sss", "ldap")]
    if ignored:
        text += " (sudo-rs ignores the %s rules)" % "/".join(ignored)
    return text


def _sudo_line(res, _facts=None):
    """R26: realpath of sudo, its first version line, sudo.ws, and nsswitch when sudo-rs answers."""
    found = shutil.which("sudo")
    if not found:
        res.add("- **sudo**: not installed")
        return
    real = os.path.realpath(found)
    rs = "sudo-rs" in real or "/cargo/" in real
    text = "%s → %s · %s" % ("/usr/bin/sudo" if found == "/usr/bin/sudo" else "sudo",
                             "sudo-rs" if rs else "classic sudo", _sudo_version(found))
    if os.path.exists(SUDO_WS):
        text += " · classic sudo also present as sudo.ws (%s)" % _sudo_version(SUDO_WS)
    res.add("- **sudo**: " + text + (_nss_text() if rs else ""))


def section_install(ctx):
    """R16 and R26. Every part says why when it cannot read something."""
    res, facts = Result(), {}
    for title, part in (("Install model", _identity_lines), ("Privilege", _privilege_lines),
                        ("sudo", _sudo_line)):
        try:
            part(res, facts)
        except Exception as exc:  # noqa: BLE001 - one part's failure is printed, not fatal
            res.add(unread_line(title, exc))
            res.find("unread", AREA, "%s could not be read" % title.lower())
    res.verdict = "Privilege: " + facts.get("verdict", "could not be read")
    return res
