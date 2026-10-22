"""Part 107 of the unit suite: the eighteenth review's fixes by builder A (review 1017a).

The helper, the installer, the app core and the debug report. Held here, each against the code
path the finding named:

* a whitelist entry stored in a non-canonical form ("10.0.0.5/24", "2001:DB8::1", " 203.0.113.5",
  as a hand edit leaves it) is removed by its own × button; it stayed in force while the panel
  answered and audited it as removed. Text on no list is answered as such, in the viewer's language.
* apt-upgrade-running (the "an update is already running" guard before os-update-run) sees the
  panel's own OS-update job: apt-get with its options first, the helper's job process, and the shell
  form's script. It matched only `apt-get upgrade…`, so a second Install updates started a second job.
* install.sh runs EVERY apt-get with its non-interactive settings (_r30a_apt_ni): through sudo on
  the command line, and as root on apt-get's environment. #443 did it for the OS upgrade only, and
  the Node.js, npm, fail2ban, … installs (output to /dev/null) could wait on an unseen dialog. The
  prerequisites fall back to plain apt-get under a sudo that allows only apt-get.
* the downloadable debug report states the privilege model nowhere: the installer's "sudo grant:
  WIDE (NOPASSWD:ALL)" and "pre-helper path" lines, "system service as root", the journal source
  "(the panel runs as root)", the `sudo systemd-run` launcher and the via-shell/via-root counts are
  on the in-panel page only (#443 moved only the verdict's own sentences).
* (from the reports' leads) the install-reconcile pass settles every row though one raises; a
  restore or a self-update is refused while a database repair this panel launched is starting; the
  remote mount.cfg read is bounded (a FIFO there blocked it past its caller), and the helper's file
  reads judge what they opened (a FIFO swapped in after the check).

HOW IT RUNS. The whitelist through part12's Flask app and client (part12 has run), every stub
through _p9_patch and undone in the finally. The pgrep pattern through the real pgrep, against
stand-in processes (a sleeping python whose command line is the job's), judged by their own pids.
install.sh's own text under bash, with sudo, id and apt-get as stand-ins (functions).
The debug report through part92's assemble harness, with the real sections' own functions.
"""
import os
import re as _re107
import shlex as _shlex107
import shutil as _shutil107
import subprocess as _sp107  # nosec B404 - the verb's own pgrep argv, and sleeping stand-ins
import sys as _sys107
import tempfile as _tf107
import time as _time107
from types import SimpleNamespace as _NS107

from unit.part01 import check
from unit.part05 import _helper as _helper107, _root
from unit.part43 import _run_bounded43
from unit.part92 import _TMP92, _r24r_assemble, _r24r_patched
from unit.part12 import (_P9_TRIPPED, _p9, _p9_app, _p9_arm, _p9_client, _p9_drain, _p9_json,
                         _p9_patch, _p9_restore_all)
from panel.core import runtime_stats as _rs107
from panel.db import models as _models107
from panel.db.models import AuditLog, GameServer, RemoteServer, RowReplaced, User, db
from panel.ops import backup as _bk107
from panel.ops import system_ops as _so107
from panel.ops.debug_report import _base as _b107
from panel.ops.debug_report import install as _in107
from panel.ops.debug_report import logs as _lg107
from panel.ops.debug_report import root_pieces as _rp107
from panel.ops.debug_report import updates as _up107
from panel.routes import _shared as _sh107
from panel.security import auth as _auth107
from panel.security import privileged as _priv107

_TRIP107_START = len(_P9_TRIPPED)
_mine107 = {"users": [], "servers": [], "hosts": []}


def _setup107():
    """Two superadmins: one reading English, one Spanish. Their ids."""
    ids = []
    with _p9.app_context():
        for name, lang in (("p107_admin", "en"), ("p107_admin_es", "es")):
            u = User(username=name, password_hash=_auth107.hash_password("Str0ng!passw0rd-" + name),
                     display_name=name, is_superadmin=True, is_active=True, language=lang)
            db.session.add(u)
            db.session.commit()
            ids.append(u.id)
    _mine107["users"].extend(ids)
    return ids


def _cleanup107():
    with _p9.app_context():
        AuditLog.query.filter(AuditLog.username.like("p107%")).delete(synchronize_session=False)
        for model, key in ((GameServer, "servers"), (RemoteServer, "hosts"), (User, "users")):
            for i in _mine107[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
        db.session.commit()


def _audits107(action):
    with _p9.app_context():
        return [(r.target, r.success) for r in AuditLog.query.filter_by(action=action, username="p107_admin")
                .order_by(AuditLog.id)]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A whitelist entry is removed by its own text, however it was stored
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _whitelist107(client, client_es):
    """Run the whitelist checks, with the list put back as found however they end.

    It was emptied, and only when they finished.
    """
    _was = list(_p9_app.load_config().get("security_whitelist", []) or [])
    try:
        _r35d_whitelist107(client, client_es)
    finally:
        _p9_app.update_config(_whitelist_as107(_was))


def _whitelist_as107(was):
    """Return update_config's mutator that puts the whitelist back to `was`.

    Made here, not in the finally: CodeQL's py/exit-from-finally reads a lambda's implicit return
    there as a 'return' in it.
    """
    return lambda cfg: cfg.update(security_whitelist=was)


def _r35d_whitelist107(client, client_es):
    _p9_patch(_sh107, "_apply_whitelist_everywhere", lambda app, unban=None: None)
    _p9_patch(_sh107._banlist, "refresh_soon", lambda *a, **k: None)   # a real fail2ban/ufw read
    _p9_app.update_config(lambda cfg: cfg.update(security_whitelist=[
        "10.0.0.5/24", "2001:DB8::1", " 203.0.113.5", "198.51.100.7"]))
    said = []
    # Each × button posts the entry exactly as the Security tab lists it, as stored.
    for stored in ("10.0.0.5/24", "2001:DB8::1", " 203.0.113.5"):
        d = _p9_json(client.post("/api/panel/security/whitelist", json={"ip": stored, "remove": True}))
        _p9_drain()
        said.append((d.get("success"), d.get("removed")))
    left = _p9_app._security_whitelist()
    check("whitelist remove: an entry stored non-canonically (a hand edit) is taken off by its own button "
          "— it stayed in force, exempting that network from every ban, while the panel said removed",
          left == ["198.51.100.7"]
          and said == [(True, "10.0.0.0/24"), (True, "2001:db8::1"), (True, "203.0.113.5")],
          repr((left, said)))
    check("whitelist remove: ...and each removal is audited once, as the address it was read as",
          _audits107("whitelist_remove") == [("10.0.0.0/24", True), ("2001:db8::1", True),
                                             ("203.0.113.5", True)], repr(_audits107("whitelist_remove")))
    # An entry typed differently from how it is stored reads as the same network: also taken off.
    _p9_app.update_config(lambda cfg: cfg.update(security_whitelist=["10.0.0.5/24", "198.51.100.7"]))
    client.post("/api/panel/security/whitelist", json={"ip": "10.0.0.0/24", "remove": True})
    _p9_drain()
    check("whitelist remove: the canonical form of a network removes the hand-edited form of it too",
          _p9_app._security_whitelist() == ["198.51.100.7"], repr(_p9_app._security_whitelist()))
    # Nothing on the list is that address: refused, nothing audited, the list sent back as it is.
    n_before = len(_audits107("whitelist_remove"))
    r = client.post("/api/panel/security/whitelist", json={"ip": "192.0.2.44", "remove": True})
    d = _p9_json(r)
    _p9_drain()
    check("whitelist remove: an address on no list is not answered or audited as removed",
          d.get("success") is False and d.get("code") == "not_whitelisted" and "removed" not in d
          and d.get("whitelist") == ["198.51.100.7"] and len(_audits107("whitelist_remove")) == n_before,
          repr(d))
    d_es = _p9_json(client_es.post("/api/panel/security/whitelist", json={"ip": "192.0.2.44", "remove": True}))
    check("whitelist remove: ...said in the viewer's language (es)",
          d_es.get("code") == "not_whitelisted" and d_es.get("message") == "Esa entrada no está en la lista blanca.",
          repr(d_es))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. "An update is already running" sees the panel's own OS-update job
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _shell_job_script107():
    """The script the shell form of os-update-run runs under `setsid bash -c`: its command line."""
    words = _shlex107.split(_priv107.remote_command("os-update-run", []))
    return words[words.index("-c") + 1]


# (what the process is, its command line after the sleeper's own words, whether it is an update)
_PROCS107 = (
    ("the helper's job: apt-get with its options first",
     ["/usr/bin/apt-get", "-y"] + _priv107.APT_CONFOLD + ["full-upgrade"], True),
    ("apt-full-upgrade's own order", ["apt-get", "full-upgrade", "-y"] + _priv107.APT_CONFOLD, True),
    ("an operator's apt-get upgrade", ["apt-get", "upgrade"], True),
    ("the helper's job unit, still on apt-get update",
     [_priv107.HELPER_PATH, "--job", "os-update-run"], True),
    ("the helper's forked job (no systemd)", [_priv107.HELPER_PATH, "os-update-run"], True),
    ("the shell form's script", ["bash", "-c", _shell_job_script107()], True),
    ("the update check's simulation",
     ["apt-get", "-s", "-o", "Debug::NoLocking=1", "full-upgrade"], False),
    ("the keep step's simulation, under its time bound (review 1022a)",
     ["timeout", "600", "apt-get", "-s", "-o", "Debug::NoLocking=1", "full-upgrade"], False),
    ("the update check's apt-get update", ["apt-get", "update", "-qq"], False),
    ("an install of unattended-upgrades", ["apt-get", "install", "-y", "unattended-upgrades"], False),
    ("the helper answering this very probe", [_priv107.HELPER_PATH, "apt-upgrade-running"], False),
)


def _pgrep107(argv):
    """The pids pgrep with `argv` (the verb's own) names, as ints."""
    r = _sp107.run(argv, capture_output=True, text=True, timeout=20, check=False)  # nosec B603
    return {int(x) for x in r.stdout.split() if x.isdigit()}


def _probe107(argv):
    """(the stand-ins' pids, what pgrep named, the remote form's own shell pid, what it named)."""
    procs = []
    try:
        for _what, words, _want in _PROCS107:
            procs.append(_sp107.Popen(  # nosec B603 - a sleeping stand-in; its words are only argv
                [_sys107.executable, "-c", "import time; time.sleep(60)"] + words,
                stdout=_sp107.DEVNULL, stderr=_sp107.DEVNULL))
        seen = _pgrep107(argv)
        # The rendered remote form, run as a remote's sudo runs it: a bash -c that stays the parent
        # (`; true`), whose own command line holds the pattern. It must not name itself.
        r = _sp107.run(["bash", "-c", "echo $$; %s; true" % _priv107.remote_command(  # nosec B603 B607
            "apt-upgrade-running", [], merge_stderr=False)], capture_output=True, text=True, timeout=20)
        own = [int(x) for x in r.stdout.split() if x.isdigit()] or [0]
    finally:
        for p in procs:
            p.kill()
            p.wait()
    return [p.pid for p in procs], seen, own[0], set(own[1:])


def _upgrade_running107():
    argv = _priv107.tool_argv("apt-upgrade-running", [])
    check("apt-upgrade-running: the helper's table builds the panel's argv (held equal)",
          _helper107.VERBS["apt-upgrade-running"][1]([]) == argv, repr(argv))
    pids, seen, shell, remote_seen = _probe107(argv)
    want = [(what, wanted) for what, _w, wanted in _PROCS107]
    got = [(what, pid in seen) for (what, _w, _x), pid in zip(_PROCS107, pids)]
    remote = [(what, pid in remote_seen) for (what, _w, _x), pid in zip(_PROCS107, pids)]
    check("apt-upgrade-running: the panel's own OS-update job reads as running (apt-get with its options "
          "first, the helper's job, the shell form's script); a simulation, an apt-get update or an "
          "install does not", got == want, repr([g for g, w in zip(got, want) if g != w]))
    check("apt-upgrade-running: ...the remote's rendered form finds the same, and never its own shell",
          remote == want and shell and shell not in remote_seen, repr((shell, sorted(remote_seen))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. install.sh: every apt-get is non-interactive, through sudo and as root
# ════════════════════════════════════════════════════════════════════════════════════════════════
with open(os.path.join(_root, "install.sh"), encoding="utf-8") as _fh107:
    _INS107 = _fh107.read()


def _ins_block107(start, end):
    """install.sh from `start` through `end`; a command that fails when either is missing."""
    i = _INS107.find(start)
    j = _INS107.find(end, i + 1) if i >= 0 else -1
    return _INS107[i:j + len(end)] if j >= 0 else "exit 97\n"


# apt-get run as a command (not `command -v apt-get`, not a message naming it), in code lines.
_RUNS_APT107 = _re107.compile(r"(?<![\w/-])apt-get\b(?! reported)")
# The only places apt-get may be run by name: the shared function's two branches, the
# prerequisites' fallback, tzdata's own env line (its continuation), and the read-only simulations.
_APT_ALLOWED107 = [
    '"${s}" env "${APT_NI_ENV[@]}" apt-get "$@"',
    '( export "${APT_NI_ENV[@]}"; apt-get "$@" )',
    # _r34a_keep_installed's read-only plan (review 1022a), in the C locale it is read by.
    "elif ! env -u LANGUAGE LC_ALL=C.UTF-8 timeout 600 apt-get -s -o Debug::NoLocking=1 full-upgrade \\",
    '${SUDO} apt-get "$@"',
    "apt-get install -y --no-upgrade tzdata || true",
    "if [[ \"$(${UPG_SUDO} apt-get -s full-upgrade 2>/dev/null | grep -c '^Inst ')\" -gt 0 ]]; then",
]


def _apt_lines107():
    return [ln.strip() for ln in _INS107.splitlines()
            if not ln.lstrip().startswith("#") and "command -v apt-get" not in ln
            and _RUNS_APT107.search(ln)]


# The settings install.sh's apt calls carry, which these checks read as apt-get and the script see them.
# GitHub's runners export DEBIAN_FRONTEND=noninteractive in the job environment, so inherited, "they do
# not leak into the script" read the runner's own variable as a leak on every Ubuntu leg.
_APT_VARS107 = ("DEBIAN_FRONTEND", "NEEDRESTART_MODE")


def _bash107(script):
    """`script`'s stdout under bash, started without the apt settings the caller's environment may hold."""
    env = {k: v for k, v in os.environ.items() if k not in _APT_VARS107}
    r = _sp107.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, env=env)  # nosec B603 B607
    return r.stdout


_SHIM107 = ("info() { :; }\nok() { :; }\nwarn() { :; }\n_venv_works() { return 1; }\n"
            "command() { [ \"$2\" = apt-get ]; }\n"
            # apt-get as a stand-in: what it was given, and the two settings as IT sees them. On fd 3,
            # since install.sh sends most of these to /dev/null.
            "exec 3>&1\n"
            "apt-get() { echo \"APT fe=${DEBIAN_FRONTEND:-} nr=${NEEDRESTART_MODE:-} $*\" >&3; }\n")
# sudo as a stand-in, as a sudo that allows anything, or apt-get and nothing else.
_SUDO_ANY107 = 'id() { echo 1000; }\nsudo() { echo "SUDO $*" >&3; }\n'
_SUDO_APT_ONLY107 = 'id() { echo 1000; }\nsudo() { [ "$1" = apt-get ] || return 1; echo "SUDO $*" >&3; }\n'


def _install_sh107():
    lines = _apt_lines107()
    check("install.sh: no apt-get is run without _r30a_apt_ni's non-interactive settings (needrestart's "
          "hook ran after the Node.js/npm/fail2ban installs, whose output goes to /dev/null), but its own "
          "two branches, the prerequisites' fallback, tzdata's env line and the simulation",
          lines == _APT_ALLOWED107, repr([ln for ln in lines if ln not in _APT_ALLOWED107]))
    funcs = _ins_block107("APT_NI_ENV=(", "\n}\n")
    pre = _ins_block107("# If anything's missing, install it automatically", "\nfi\n")
    any_sudo = _bash107(_SHIM107 + _SUDO_ANY107 + pre)
    ni = "SUDO env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get "
    pkgs = "install -y python3-venv python3-pip git curl wget cron ufw"
    check("install.sh: a per-user install's prerequisites are installed through sudo with the settings on "
          "apt-get's command line", any_sudo.splitlines() == [ni + "update -qq", ni + pkgs], repr(any_sudo))
    apt_only = _bash107(_SHIM107 + _SUDO_APT_ONLY107 + pre)
    check("install.sh: ...and a sudo that allows only apt-get (it refuses `env`) still installs them, as "
          "plain apt-get", apt_only.splitlines() == ["SUDO apt-get update -qq", "SUDO apt-get " + pkgs],
          repr(apt_only))
    # As root, on the update path: ensure_fail2ban and ensure_nodejs's npm run before any export.
    root = _bash107(_SHIM107 + "id() { echo 0; }\n" + funcs
                    + _ins_block107("\nensure_fail2ban() {", "\n}\n")
                    + "command() { [ \"$2\" = apt-get ]; }\nensure_fail2ban\n"
                    + "_r30a_apt_ni '' install -y npm\necho \"after fe=${DEBIAN_FRONTEND:-}\"\n")
    check("install.sh: as root, apt-get itself sees the settings (an install on the update path runs before "
          "any export), and they do not leak into the script",
          root.splitlines() == ["APT fe=noninteractive nr=a install -y fail2ban",
                                "APT fe=noninteractive nr=a install -y npm", "after fe="], repr(root))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The downloadable debug report states the privilege model nowhere
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A self-update on a host left on the wide grant, as install.sh words it (warn/ok, ANSI gone).
_LOG107 = ["=== self-update ===", "✓ Code updated (abc1234)",
           "[!] sudo grant: WIDE (NOPASSWD:ALL) — the root-owned helper pieces are not all installed",
           "[!]   The panel falls back to the pre-helper path, which needs the wide grant to work.",
           "✓ Panel restarted"]
# The sections' own lines, which must reach the file or the page without the backstop's help.
_OWN107 = ("**Install model**", "**Runs as**", "**Privileged calls", "**A self-update here runs**",
           "**Source**")
# What must not be in the file, the summary or the issue body in any form.
_PRIVMODEL107 = ("sudo grant", "NOPASSWD", "pre-helper", "as root", "runs as root", "via shell",
                 "via root", "sudo systemd-run", "**Runs as**")


def _r30a_sections107():
    """{key: Result}: the real parts that printed the privilege model, on a root, no-helper host."""
    out = {"updates": _b107.Result(), "install": _b107.Result(), "root_pieces": _b107.Result(),
           "recent_log": _b107.Result()}
    _up107._tail_lines(out["updates"], {"lines": list(_LOG107)}, "canonical-https")
    with _r24r_patched(_so107, _is_system_service=lambda: True, _helper_present=lambda: False), \
            _r24r_patched(_in107, os=_NS107(geteuid=lambda: 0, path=os.path, getgroups=os.getgroups,
                                            getegid=os.getegid),
                          _interpreter=lambda: "fixture", _under_unit=lambda: "fixture",
                          panel_conf_text=lambda: "fixture", _groups=lambda: []):
        _in107._identity_lines(out["install"], {})
    with _r24r_patched(_rs107, snapshot=lambda group: {"ufw-status|ok": 3, "via|shell": 2, "via|root": 1}), \
            _r24r_patched(_so107, _is_system_service=lambda: True, _helper_present=lambda: False,
                          root_piece_state=lambda: {}, _ROOT_PIECES=()), \
            _r24r_patched(_rp107, _panel_conf_line=lambda: "fixture", _floor_line=lambda: "fixture",
                          _tip_line=lambda: "fixture"):
        _rp107._privileged_lines(out["root_pieces"])
        _rp107._pieces_lines(out["root_pieces"])
    out["recent_log"].add("- **Source**: %s, 3 lines" % _lg107._SOURCE_LABEL["root"])
    # The digest's count of the panel's sudo calls: two a shell as root, one a helper verb.
    j = {"lines": [_SUDO107 % (1, "/usr/bin/bash -c 'id'"), _SUDO107 % (2, "/usr/bin/bash -c 'ls'"),
                   _SUDO107 % (3, _helper_cmd107("ufw-status"))],
         "sudo": None, "filtered": False, "cut": False, "why": ""}
    with _r24r_patched(_lg107, _journal=lambda ctx: j):
        out["journal_digest"] = _lg107.section_journal_digest(_b107.Ctx(app=None, deadline_s=20.0))
    return out


_SUDO107 = "Oct 03 02:59:5%d vps sudo[3001]: lgsmpanel : PWD=/home/x ; USER=root ; COMMAND=%s"


def _helper_cmd107(verb):
    return "%s %s" % (_priv107.HELPER_PATH, verb)


def _report107():
    """(part92's assemble over the sections above, or {}; the harness's error, or "")."""
    # part92's harness writes its fixture files into its temp dir, which part92 removed when done.
    os.makedirs(_TMP92, exist_ok=True)
    try:
        secs = _r30a_sections107()
        return _r24r_assemble(extra={k: ("ok", 0.01, r) for k, r in secs.items()})[0], ""
    except Exception as exc:  # noqa: BLE001 - a harness failure fails by name below
        return {}, "%s: %s" % (type(exc).__name__, exc)
    finally:
        _shutil107.rmtree(_TMP92, ignore_errors=True)


_PAGE107 = ("NOPASSWD", "pre-helper path", "**Runs as**: root", "via root 1 · via shell 2", "sudo systemd-run",
            "shell as root ×2")
# What stays in the file, from the sections' own lines.
_KEPT107 = ("- **Install model**: system service\n", "- **Privileged calls since start**: ok 3 · refused by sudo 0",
            "- **Source**: system journal, 3 lines",
            "- **Privileged calls (left out below)**: 1 successful sudo call in this window (ufw-status ×1) · ")


def _absent107(words, text):
    return [w for w in words if w not in text]


def _present107(words, text):
    return [w for w in words if w in text]


def _debug_report107():
    rep, err = _report107()
    shared = "\n".join(str(rep.get(k, "")) for k in ("report", "summary", "issue_body"))
    page, report = str(rep.get("posture", "")), str(rep.get("report", ""))
    # What the backstop held back: the sections' own lines must not be there (each kept its posture
    # apart itself); only the installer's log lines, which the Updates section prints as written.
    held = page.partition("### Held back from the file")[2]
    leaked = _present107(_PRIVMODEL107, shared)
    missing = _absent107(_PAGE107, page)
    lost = _absent107(_KEPT107, report) + _present107(_OWN107, held)
    check("debug report: the downloadable file, summary and issue body state the privilege model "
          "nowhere (the installer's WIDE grant lines, 'as root', the pre-helper launcher, via shell)",
          bool(rep) and not leaked, err + repr(leaked))
    check("debug report: ...and the in-panel page shows each of them", bool(rep) and not missing,
          err + repr(missing))
    check("debug report: ...while the diagnosis in those lines stays in the file, each section having "
          "kept the posture apart itself (install model, call outcomes, journal source)",
          bool(rep) and not lost, err + repr(lost))


def _ins_warn107(start):
    """install.sh's `warn "<start>..."` text, as the self-update log prints it ("[!] ..."); "" if gone."""
    m = _re107.search(r'warn "(%s[^"]*)"' % _re107.escape(start), _INS107)
    return "[!] " + m.group(1) if m else ""


def _r9_detail107():
    """Privileged helper's real detail on a host without the helper, as section_diagnostics prints it."""
    from panel.ops.ssh_manager import _core as _smc107
    with _r24r_patched(_so107, _helper_present=lambda: False), \
            _r24r_patched(_smc107, helper_on_disk=lambda: False):
        level, detail = _so107._diag_privileged_helper()
    return "- [%s] **Privileged helper**: %s" % (level, detail)


_DIAG_SAID107 = ("**Privileged helper**: Not installed — privileged actions fall back to the pre-helper path",
                 "pre-helper repair path until you re-run this as root",
                 "visudo rejected the grant line: p107 ALL=(root) NOPASSWD:")
_MODEL_SAID107 = ("sudo grant: WIDE (NOPASSWD:", "falls back to the pre-helper path, which needs the wide grant",
                  "once the helper can be placed to narrow it again")


def _diag_report107(diag, model):
    """(part92's assemble, or {}; the harness's error, or "").

    `diag[0]` is the Diagnostics section's line; the rest are a self-update log's lines.
    """
    os.makedirs(_TMP92, exist_ok=True)
    try:
        up, dg = _b107.Result(), _b107.Result(lines=[diag[0]])
        _up107._tail_lines(up, {"lines": ["=== self-update ==="] + diag[1:] + model}, "canonical-https")
        return _r24r_assemble(extra={"updates": ("ok", 0.01, up), "diagnostics": ("ok", 0.01, dg)})[0], ""
    except Exception as exc:  # noqa: BLE001 - a harness failure fails by name below
        return {}, "%s: %s" % (type(exc).__name__, exc)
    finally:
        _shutil107.rmtree(_TMP92, ignore_errors=True)


def _diagnosis_kept107():
    """The privilege model is held back by its own lines, never by a word that diagnosis shares (F3, #444).

    A bare `pre-helper` or `NOPASSWD` in POSTURE_RE also held back the Privileged helper check's "Not
    installed — privileged actions fall back to the pre-helper path", install.sh's db_maintenance warning
    and a sudoers error naming its grant: the lines that explain a host's failing privileged actions.
    """
    diag = [_r9_detail107(), _ins_warn107("The panel falls back to the pre-helper repair path"),
            "[ERROR] visudo rejected the grant line: p107 ALL=(root) NOPASSWD: /p107/panel-helper"]
    model = [_ins_warn107("sudo grant: ${SUDO_SCOPE}").replace("${SUDO_SCOPE}", "WIDE (NOPASSWD:ALL)"),
             _ins_warn107("  The panel falls back to the pre-helper path"),
             _ins_warn107("  Re-run this installer as root once the helper can be placed")]
    rep, err = _diag_report107(diag, model)
    # The file, and the page's held-back block (empty when the harness failed, which then fails below).
    report, held = str(rep.get("report", "")), str(rep.get("posture", "")).partition("### Held back from the file")[2]
    found = all(diag + model)
    # By words each line holds that the report's redaction leaves alone (it rewrites a path or a token).
    lost = [t for t in _DIAG_SAID107 if t not in report or t in held]
    leaked = [t for t in _MODEL_SAID107 if t in report or t not in held]
    check("debug report: diagnosis that names the pre-helper path or NOPASSWD stays in the downloadable file "
          "(Privileged helper's 'Not installed', install.sh's db_maintenance warning, a sudoers error)",
          found and not lost, err + repr((lost, diag)))
    check("debug report: ...while install.sh's three grant-block lines are still held back from the file and "
          "shown on the in-panel page",
          found and not leaked, err + repr((leaked, model)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. One raising row does not end the install-reconcile pass
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _reconcile107():
    with _p9.app_context():
        host = RemoteServer(name="p107-host", host="p107.example.invalid", port=22, username="admin",
                            auth_method="key", auth_credential="", is_online=True)
        db.session.add(host)
        db.session.commit()
        _mine107["hosts"].append(host.id)
        ids = []
        for short in ("p107gone", "p107kept"):
            gs = GameServer(remote_id=host.id, name=short, short_name=short, game_type="gmodserver",
                            port=27107 + len(ids), installed=False, status="failed")
            db.session.add(gs)
            db.session.commit()
            ids.append(gs.id)
        _mine107["servers"].extend(ids)
    gone, kept = ids
    seen = []

    def held(gs):
        if gs.id == gone:
            raise RowReplaced("p107: deleted and its id taken during an earlier row's round trip")
        return True
    _p9_patch(_models107, "still_held", held)
    _p9_patch(_p9_app, "_reconcile_stranded_install", lambda app, gs: seen.append(gs.id))
    raised = ""
    with _p9.app_context():
        try:
            _p9_app._r30a_reconcile_pass(_p9)
        except Exception as exc:  # noqa: BLE001 - the old pass raised out; fails by name below
            raised = type(exc).__name__
    check("install reconcile: a row that raises (RowReplaced) is skipped and the rows after it are still "
          "settled in the same pass (it ended the pass, so they waited ten minutes)",
          kept in seen and gone not in seen and not raised, repr((seen, raised)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. A restore or self-update is refused while a repair this panel launched is starting
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _repair_env107(base, verb_rc, restored):
    """A checkout at `base` the repair can launch from, through the helper; the restore's swap recorded."""
    os.makedirs(os.path.join(base, "venv", "bin"))
    for rel in (("venv", "bin", "python3"), ("db_maintenance.py",), ("install.sh",)):
        open(os.path.join(base, *rel), "w").close()
    _p9_patch(_so107, "PANEL_DIR", base)
    _p9_patch(_so107, "_is_system_service", lambda: True)
    _p9_patch(_so107, "_helper_present", lambda: True)
    _p9_patch(_so107, "_update_in_progress", lambda: False)
    _p9_patch(_so107, "_run_verb", lambda verb, args, *a, **k: ("", "", verb_rc[0]))
    _p9_patch(_bk107, "_restore_backup_locked", lambda *a, **k: (restored.append(a) or (True, "ok")))


def _repair_race107():
    base = _tf107.mkdtemp(prefix="p107-panel-")
    verb_rc, restored = [0], []
    try:
        _repair_env107(base, verb_rc, restored)
        _so107._r30a_repair_launched.update(ts=0.0, dir="")
        repair = _so107.panel_repair_database()
        restore = _bk107.restore_backup("p107.tar.gz")
        update = _so107._launch_installer(target_ref="a" * 40, branch="main")
        got = (repair[0], restore, update, list(restored))
        check("db repair: once this panel launched one, a restore and a self-update are refused until the "
              "panel stops for it (each replaces panel.db; the repair only asked, so a click in those "
              "seconds ran beside it)",
              got == (True, (False, _so107.R30A_REPAIR_STARTING_RESTORE),
                      (False, _so107.R30A_REPAIR_STARTING_UPDATE), []), repr(got))
        # A repair that is refused, or whose launch fails, takes its record back.
        _so107._r30a_repair_launched.update(ts=0.0, dir="")
        _p9_patch(_so107, "_r29a_repair_refusal", lambda: "p107 refused")
        refused = _so107.panel_repair_database()
        after_refused = _bk107.restore_backup("p107.tar.gz")
        _p9_patch(_so107, "_r29a_repair_refusal", lambda: None)
        verb_rc[0] = 1
        failed = _so107.panel_repair_database()
        after_failed = _bk107.restore_backup("p107.tar.gz")
        got = (refused, failed[0], after_refused, after_failed, len(restored))
        check("db repair: ...and one refused, or whose launch failed, refuses nothing (control)",
              got == ((False, "p107 refused"), False, (True, "ok"), (True, "ok"), 2), repr(got))
    finally:
        _so107._r30a_repair_launched.update(ts=0.0, dir="")
        _shutil107.rmtree(base, ignore_errors=True)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. A FIFO at mount.cfg ends the read: the remote form's timeout, the helper's open
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RUNUSER107 = '#!/bin/bash\n[ "$1" = -u ] && [ "$3" = -- ] || exit 125\nshift 3\nexec "$@"\n'
# The helper's _emit_file in its own process (a blocked open cannot hang the suite), with the
# isfile check answering "regular file" for a FIFO: the name swapped between the check and the open.
_EMIT107 = """
import importlib.machinery, importlib.util, io, os, sys
spec = importlib.util.spec_from_loader("ph", importlib.machinery.SourceFileLoader("ph", sys.argv[1]))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
class _Path:
    def __getattr__(self, name):
        return getattr(os.path, name)
    @staticmethod
    def isfile(p):
        return True
class _Os:
    path = _Path()
    def __getattr__(self, name):
        return getattr(os, name)
mod.os = _Os()
try:
    mod._emit_file(sys.argv[2], io.BytesIO())
    print("READ")
except ValueError:
    print("REFUSED")
"""


def _fifo_reads107():
    d = _tf107.mkdtemp(prefix="p107-fifo-")
    cfg = os.path.join(d, "gm", "serverfiles", "garrysmod", "cfg", "mount.cfg")
    try:
        stub = os.path.join(d, "stub")
        os.makedirs(stub)
        with open(os.path.join(stub, "runuser"), "w", encoding="utf-8") as fh:
            fh.write(_RUNUSER107)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in program in this test's temp dir
        os.chmod(os.path.join(stub, "runuser"), 0o700)  # nosec B103 - a stand-in program in this test's temp dir
        home = os.path.join(d, "gm")
        os.makedirs(os.path.dirname(cfg))
        os.mkfifo(cfg)
        _p9_patch(_priv107, "_R30A_MOUNT_READ_S", 1)
        cmd = _priv107.remote_command("gmod-mount-read", ["gm"]).replace("/home/gm", home)
        t0 = _time107.monotonic()
        # part43's runner: its own session, the whole group killed at its deadline (a cat blocked on
        # the fifo would otherwise outlive the shell).
        _o, err, rc = _run_bounded43(["bash", "-c", "PATH=%s:$PATH; %s" % (_shlex107.quote(stub), cmd)])
        got = ("blocked" if err == "timed out" and rc == -1 else rc, round(_time107.monotonic() - t0))
        check("gmod mount read (remote): a FIFO at mount.cfg ends the read within its bound, as a failed "
              "read ('unknown'), instead of blocking past the caller and leaving the process on the host",
              got[0] not in (0, "blocked") and got[1] <= 5, repr(got))
        _o, err, rc = _run_bounded43([_sys107.executable, "-I", "-c", _EMIT107,
                                      os.path.join(_root, "tools", "panel-helper"), cfg])
        said = "blocked" if err == "timed out" and rc == -1 else (_o.strip() or err.strip()[-200:])
        check("helper _emit_file: a FIFO swapped in after the regular-file check is refused at once, by "
              "what was opened (the open blocked with no end)", said == "REFUSED", said)
    finally:
        _release_fifo107(cfg)
        _shutil107.rmtree(d, ignore_errors=True)


def _release_fifo107(path):
    """Open the FIFO's write end and close it: a reader a reverted guard left blocked gets EOF and ends."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass  # ENXIO: no reader is waiting, or the FIFO was never made; nothing to release


try:
    _p9_arm(who="part107")
    _ADMIN107, _ADMIN_ES107 = _setup107()
    _whitelist107(_p9_client(_ADMIN107), _p9_client(_ADMIN_ES107))
    _reconcile107()
    _repair_race107()
    _fifo_reads107()
finally:
    _p9_restore_all()
    _cleanup107()
_upgrade_running107()
_install_sh107()
_debug_report107()
_diagnosis_kept107()

check("part107: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP107_START, repr(_P9_TRIPPED[_TRIP107_START:][:6]))
