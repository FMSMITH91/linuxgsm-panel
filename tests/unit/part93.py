"""Part 93 of the unit suite: the fourteenth review's fixes by builder A (review 1016b).

Helper, install, uninstall, Tailscale, monitoring and the debug report. Held here, each against the
code path the finding named:

* Tailscale SSH on the panel's host only where the owner chose it at install (the owner's decision
  of 2026-10-16): the helper refuses `--ssh` on both joins and `tailscale-ssh on` without panel.conf's
  `tailscale_ssh=yes`, and still joins without SSH and turns SSH off; install.sh records the choice
  (an env answer, else the one recorded, else "yes" for a host already running Tailscale SSH, else
  no unless someone at a terminal says yes); the panel's Connect leaves --ssh off, its Enable
  refuses with a stable code in the viewer's language, and the System page shows Enable read-only.

HOW IT RUNS. The helper and the panel's modules with stand-ins, undone in a finally; part12's app
for the routes and the page; install.sh's own functions run under bash in a throwaway directory
with a stand-in `tailscale`. Nothing reaches this machine's tailscale, sudo, or the checkout's data/.
"""
import atexit as _atexit93
import io as _io93
import json as _json93
import os
import shutil as _shutil93
import subprocess as _sp93  # nosec B404 - bash over the repo's own scripts, in a throwaway dir
import sys
import tempfile as _tf93
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _helper93, _root
from unit.part12 import P9_ADMIN, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import validation as _val93
from panel.db.models import User as _U93, db as _db93
from panel.ops import system_ops as _so93
from panel.ops import tailscale_integration as _ts93
from panel.routes import remotes as _rem93

_TMP93 = _tf93.mkdtemp(prefix="p93-")
_atexit93.register(_shutil93.rmtree, _TMP93, True)


def _read93(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _fn93(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Tailscale SSH on the panel's host only where the owner chose it at install
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Run93:
    """subprocess for the helper, answering `status --json` as a node that has never joined.

    The rest is recorded (run) or started (Popen) and succeeds.
    """

    TimeoutExpired = _sp93.TimeoutExpired
    DEVNULL = _sp93.DEVNULL
    STDOUT = _sp93.STDOUT
    PIPE = _sp93.PIPE

    def __init__(self):
        self.ran, self.popen = [], []

    def run(self, argv, **_kw):
        if list(argv[1:]) == ["status", "--json"]:
            return _sp93.CompletedProcess(argv, 0, '{"BackendState": "NeedsLogin", '
                                                   '"HaveNodeKey": false}', "")
        if list(argv[1:]) == ["debug", "prefs"]:
            # The helper's read for an unrecorded choice (_r25a_ssh_record_running): SSH is off.
            return _sp93.CompletedProcess(argv, 0, '{"RunSSH": false}', "")
        self.ran.append(list(argv[1:]))
        return _sp93.CompletedProcess(argv, 0, "", "")

    def Popen(self, argv, **_kw):  # noqa: N802 - subprocess's own name
        self.popen.append(list(argv[1:]))
        return NS(pid=1)


def _r25a_helper(conf, argv, stdin=""):
    """(rc, what ran, stderr) of the helper's main(argv) with panel.conf answering `conf`."""
    fake = _Run93()
    saved = (_helper93.subprocess, _helper93.resolve, _helper93.panel_conf, _helper93.TS_UP_LOG,
             _helper93.TS_UP_POLL_SECONDS, sys.stdin, sys.stdout, sys.stderr)
    _helper93.subprocess, _helper93.resolve = fake, (lambda n: "/usr/bin/" + n)
    _helper93.panel_conf = lambda: dict(conf)
    _helper93.TS_UP_LOG = os.path.join(_tf93.mkdtemp(dir=_TMP93), "tsup.log")
    _helper93.TS_UP_POLL_SECONDS = 0
    sys.stdin, sys.stdout, sys.stderr = _io93.StringIO(stdin), _io93.StringIO(), _io93.StringIO()
    try:
        rc = _helper93.main(["panel-helper"] + list(argv))
        return rc, fake.ran + fake.popen, sys.stderr.getvalue()
    finally:
        (_helper93.subprocess, _helper93.resolve, _helper93.panel_conf, _helper93.TS_UP_LOG,
         _helper93.TS_UP_POLL_SECONDS, sys.stdin, sys.stdout, sys.stderr) = saved


_KEY93 = "tskey-auth-" + "p93" + "Wd4Lq8"
_VERBS93 = {"login, SSH": (["tailscale-up-login", "yes", "-"], ""),
            "login, no SSH": (["tailscale-up-login", "no", "-"], ""),
            "key, SSH": (["tailscale-up-key", "yes", "-", "-"], _KEY93 + "\n"),
            "key, no SSH": (["tailscale-up-key", "no", "-", "-"], _KEY93 + "\n"),
            "SSH on": (["tailscale-ssh", "on"], ""),
            "SSH off": (["tailscale-ssh", "off"], "")}


def _ssh_flag93(ran):
    return [("--ssh" in c) if c[:1] == ["up"] else " ".join(c) for c in ran]


_optin93 = {}
for _conf_label93, _conf93 in (("not chosen", {}), ("chosen", {"tailscale_ssh": "yes"}),
                               ("recorded no", {"tailscale_ssh": "no"}),
                               ("YES", {"tailscale_ssh": "YES"}), ("1", {"tailscale_ssh": "1"})):
    for _vl93, (_argv93, _in93) in _VERBS93.items():
        _rc93, _ran93, _err93 = _r25a_helper(_conf93, _argv93, _in93)
        _optin93[(_conf_label93, _vl93)] = (_rc93, _ssh_flag93(_ran93))
_refused93 = [(c, v) for c in ("not chosen", "recorded no", "YES", "1")
              for v in ("login, SSH", "key, SSH", "SSH on")]
check("panel-helper: without `tailscale_ssh=yes` in panel.conf (none, \"no\", or another spelling), "
      "an `up --ssh` (login link or key) and `tailscale-ssh on` are refused and run nothing: "
      "whoever opens a Connect link picks the tailnet that would get root logins here",
      all(_optin93[k] == (1, []) for k in _refused93), repr({k: _optin93[k] for k in _refused93}))
check("panel-helper: ...while a join without SSH and `tailscale-ssh off` still run there "
      "(Connect works; turning SSH off is always allowed)",
      all(_optin93[(c, "login, no SSH")] == (0, [False])
          and _optin93[(c, "key, no SSH")] == (0, [False])
          and _optin93[(c, "SSH off")] == (0, ["set --ssh=false"])
          for c in ("not chosen", "recorded no")), repr(_optin93))
check("panel-helper: ...and with `tailscale_ssh=yes` the SSH join and `tailscale-ssh on` run as "
      "before (control)",
      _optin93[("chosen", "login, SSH")] == (0, [True])
      and _optin93[("chosen", "key, SSH")] == (0, [True])
      and _optin93[("chosen", "SSH on")] == (0, ["set --ssh=true"]),
      repr({k: v for k, v in _optin93.items() if k[0] == "chosen"}))
_rc93, _ran93, _err93 = _r25a_helper({}, ["tailscale-up-login", "yes", "-"])
check("panel-helper: the refusal says how to allow it (re-run the installer with "
      "PANEL_TAILSCALE_SSH=1), in fixed words", "PANEL_TAILSCALE_SSH=1" in _err93, _err93)

# ── install.sh records the choice ──────────────────────────────────────────────────────────────
_INS93 = _read93("install.sh")


def _r25a_choice(env_val=None, record=None, run_ssh=False, ts_reads=True, self_update=False):
    """What install.sh's _r25a_tailscale_ssh_choice prints, run under bash with no terminal.

    The stand-in `tailscale` is first on PATH whatever this machine has installed; with `ts_reads`
    False it fails, as on a host where tailscale is absent or its daemon is not answering.
    """
    d = _tf93.mkdtemp(dir=_TMP93)
    conf = os.path.join(d, "panel.conf")
    if record is not None:
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("db_path=/x/data/panel.db\n%s" % record)
    stand = os.path.join(d, "tailscale")
    with open(stand, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nexit 1\n" if not ts_reads else
                 "#!/bin/sh\nif [ \"$1 $2\" = \"debug prefs\" ]; then printf '%%s' '%s'; fi\n"
                 "exit 0\n" % _json93.dumps({"RunSSH": run_ssh, "OperatorUser": ""}))
    os.chmod(stand, 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
    script = ("set -euo pipefail\n%s\n_r25a_tailscale_ssh_choice '%s'\n"
              % (_fn93(_INS93, "_r25a_tailscale_ssh_choice"), conf))
    env = {k: v for k, v in os.environ.items() if k not in ("PANEL_TAILSCALE_SSH", "PANEL_SELF_UPDATE")}
    if self_update:
        env["PANEL_SELF_UPDATE"] = "1"
    env["PATH"] = d + os.pathsep + env.get("PATH", "")
    if env_val is not None:
        env["PANEL_TAILSCALE_SSH"] = env_val
    # No terminal: stdin, stdout and stderr are all pipes, and a new session has no /dev/tty.
    r = _sp93.run(["bash", "-c", script], cwd=d, capture_output=True, text=True,  # nosec B603 B607
                  stdin=_sp93.DEVNULL, timeout=60, env=env, start_new_session=True)
    return r.returncode, r.stdout.strip()


_choice93 = {
    "env 1": _r25a_choice("1"), "env 0 over a recorded yes": _r25a_choice("0", "tailscale_ssh=yes\n"),
    "recorded yes": _r25a_choice(None, "tailscale_ssh=yes\n"),
    "recorded no, SSH running": _r25a_choice(None, "tailscale_ssh=no\n", run_ssh=True),
    "no record, SSH running": _r25a_choice(None, "panel_dir=/x\n", run_ssh=True),
    "no record, SSH off": _r25a_choice(None, "panel_dir=/x\n"),
    "no panel.conf, tailscale unreadable": _r25a_choice(None, None, ts_reads=False),
    "a record that is not yes|no": _r25a_choice(None, "tailscale_ssh=maybe\n"),
    "env 1 on a run the panel started": _r25a_choice("1", "tailscale_ssh=no\n", self_update=True),
}
check("install.sh: the Tailscale SSH choice is PANEL_TAILSCALE_SSH when set; else the one panel.conf "
      "recorded (an update never changes it); else yes for a host already running Tailscale SSH (it "
      "keeps working); else no when nobody is at a terminal to ask; and a run the panel started "
      "(a self-update) never takes the answer from the environment",
      _choice93 == {"env 1": (0, "yes env"), "env 0 over a recorded yes": (0, "no env"),
                    "recorded yes": (0, "yes kept"), "recorded no, SSH running": (0, "no kept"),
                    "no record, SSH running": (0, "yes running"),
                    "no record, SSH off": (0, "no default"),
                    "no panel.conf, tailscale unreadable": (0, "no default"),
                    "a record that is not yes|no": (0, "no default"),
                    "env 1 on a run the panel started": (0, "no kept")}, repr(_choice93))
_irt93 = _fn93(_INS93, "install_root_tools")
_rd93, _wr93 = _irt93.find("_r25a_tailscale_ssh_choice"), _irt93.find('tee "${PANEL_CONF}"')
check("install.sh: install_root_tools reads the choice BEFORE it rewrites panel.conf, and writes it "
      "as `tailscale_ssh=` (the line the helper reads)",
      0 <= _rd93 < _wr93 and "\\ntailscale_ssh=%s\\n" in _irt93
      and '"${TS_SSH_CHOICE}"' in _irt93[_rd93:_wr93], repr((_rd93, _wr93)))
check("panel-helper and install.sh name the same panel.conf key",
      _helper93.R25A_SSH_CONF_KEY == "tailscale_ssh"
      and "sed -n 's/^tailscale_ssh=//p'" in _fn93(_INS93, "_r25a_tailscale_ssh_choice"),
      _helper93.R25A_SSH_CONF_KEY)

# ── the panel: Connect without --ssh, Enable refused, the page read-only ──────────────────────
_CONF93 = os.path.join(_TMP93, "helper-panel.conf")


def _conf93(text):
    with open(_CONF93, "w", encoding="utf-8") as fh:
        fh.write(text)


_allowed93 = {}
_saved_conf93 = (_so93._R25A_PANEL_CONF, _so93._helper_present, _so93.tailscale_ssh_status)
try:
    _so93._R25A_PANEL_CONF = _CONF93
    _so93._helper_present = lambda: True
    # An unrecorded choice reads whether SSH is on now (part96 covers it on): off here.
    _so93.tailscale_ssh_status = lambda: {"enabled": False, "running": True}
    for _l93, _t93 in (("yes", "db_path=/x\ntailscale_ssh=yes\n"), ("no", "tailscale_ssh=no\n"),
                       ("no key (an older installer)", "db_path=/x\n"),
                       ("commented", "# tailscale_ssh=yes\n"), ("Yes", "tailscale_ssh=Yes\n")):
        _conf93(_t93)
        _allowed93[_l93] = _so93.tailscale_ssh_allowed()
    os.unlink(_CONF93)
    _allowed93["no panel.conf"] = _so93.tailscale_ssh_allowed()
    _so93._helper_present = lambda: False
    _allowed93["no helper"] = _so93.tailscale_ssh_allowed()
finally:
    _so93._R25A_PANEL_CONF, _so93._helper_present, _so93.tailscale_ssh_status = _saved_conf93
check("system_ops.tailscale_ssh_allowed: true only for panel.conf's exact `tailscale_ssh=yes` where "
      "the helper is installed; and true with no helper (the panel's grant is the old wide one there, "
      "and nothing changes)",
      _allowed93 == {"yes": True, "no": False, "no key (an older installer)": False,
                     "commented": False, "Yes": False, "no panel.conf": False, "no helper": True},
      repr(_allowed93))

_flows93 = {}
_verbs93 = []
try:
    _p9_arm(_p9_patch, who="part93")
    _p9_patch(_so93, "_run_verb", lambda verb, args=(), **kw: (
        _verbs93.append((verb, list(args))), ("https://login.tailscale.com/a/p93x", "", 0))[1])
    for _l93, _ok93 in (("not chosen", False), ("chosen", True)):
        _p9_patch(_so93, "tailscale_ssh_allowed", lambda _v=_ok93: _v)
        del _verbs93[:]
        _ts93.tailscale_up_local(enable_ssh=True)
        _flows93[("Connect", _l93)] = list(_verbs93)
        del _verbs93[:]
        _flows93[("SSH on", _l93)] = (_so93.tailscale_ssh_enable()[0], list(_verbs93))
    with _p9.app_context():
        _lang_was93 = _db93.session.get(_U93, P9_ADMIN).language
        _db93.session.get(_U93, P9_ADMIN).language = "es"
        _db93.session.commit()
    try:
        _p9_patch(_so93, "tailscale_ssh_allowed", lambda: False)
        del _verbs93[:]
        _resp93 = _p9_client(P9_ADMIN).post("/api/server-management/ts-ssh-enable")
        _flows93["route, es viewer"] = (_resp93.status_code, _p9_json(_resp93).get("code"),
                                        _p9_json(_resp93).get("message", ""), list(_verbs93))
    finally:
        with _p9.app_context():
            _db93.session.get(_U93, P9_ADMIN).language = _lang_was93
            _db93.session.commit()
finally:
    _p9_restore_all()
check("panel: Connect asks the helper for a join WITHOUT SSH where the owner did not choose it at "
      "install, and with it where they did (control)",
      _flows93[("Connect", "not chosen")] == [("tailscale-up-login", ["no", "-"])]
      and _flows93[("Connect", "chosen")] == [("tailscale-up-login", ["yes", "-"])], repr(_flows93))
check("panel: Enable Tailscale SSH is refused before any verb runs where it was not chosen, and runs "
      "`tailscale-ssh on` where it was (control)",
      _flows93[("SSH on", "not chosen")] == (False, [])
      and _flows93[("SSH on", "chosen")] == (True, [("tailscale-ssh", ["on"])]), repr(_flows93))
_ES93 = _json93.loads(_read93("translations", "es", "r25j.json"))
check("panel: ...its route answers 403 with the stable code tailscale_ssh_not_chosen and the "
      "sentence in the viewer's language (es)",
      _flows93["route, es viewer"][:2] == (403, "tailscale_ssh_not_chosen")
      and _flows93["route, es viewer"][2] == _ES93[str(_so93.TS_SSH_NOT_CHOSEN)]
      and _flows93["route, es viewer"][3] == [], repr(_flows93["route, es viewer"]))


def _page93(allowed, enabled=False):
    """The System page's Tailscale SSH block for a connected panel host."""
    status = {"has_sudo": True, "ufw": {"enabled": False, "rules": []},
              "tailscale_ssh": {"enabled": enabled, "running": True},
              "tailscale_ssh_allowed": allowed, "tailscale_interface": "tailscale0",
              "tailscale_ufw_allowed": True, "updates": {}, "uptime": ""}
    try:
        _p9_arm(_p9_patch, who="part93")
        _p9_patch(_so93, "get_server_status", lambda force=False: status)
        _p9_patch(_ts93, "panel_funnel_facts", lambda cfg: {})
        resp = _p9_client(P9_ADMIN).get("/server-management")
        body = resp.get_data(as_text=True)
    finally:
        _p9_restore_all()
    i = body.find('id="ts-ssh-badge"')
    block = body[i:body.find("Tailscale interface (UFW)", i)] if i >= 0 else ""
    return resp.status_code, block


_pg_no93, _pg_yes93, _pg_on93 = _page93(False), _page93(True), _page93(False, enabled=True)
check("System page: where Tailscale SSH was not chosen at install, Enable is shown read-only "
      "(disabled, no action) with why and how to allow it",
      _pg_no93[0] == 200 and 'data-action="tsSshEnable"' not in _pg_no93[1]
      and "disabled" in _pg_no93[1] and "PANEL_TAILSCALE_SSH=1" in _pg_no93[1], repr(_pg_no93))
check("System page: ...where it was, Enable works (control); and SSH already on offers Disable "
      "either way", 'data-action="tsSshEnable"' in _pg_yes93[1]
      and "PANEL_TAILSCALE_SSH=1" not in _pg_yes93[1]
      and 'data-action="tsSshDisable"' in _pg_on93[1], repr((_pg_yes93, _pg_on93)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A data/ that is a link root made: restore and self-update act on the real directory
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A root-made link cannot be made here without root, so _r26a_link_root_made (which tells a
# root-made link from the panel user's by its owner) answers "root made it" for this one path; the
# walk, the pinned opens and the copies are the real ones.
def _r25a_linked_data(root_made=True):
    """(restore target, members copied, stage left behind, self-update target, log written)."""
    base = _tf93.mkdtemp(dir=_TMP93)
    disk = os.path.join(base, "disk", "data")          # data/ "moved to another disk"
    stage = os.path.join(disk, _helper93.RESTORE_STAGE)
    os.makedirs(stage)
    for name, text in (("config.json", "{\"restored\": true}"), ("secret_key", "k")):
        with open(os.path.join(stage, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    with open(os.path.join(disk, "config.json"), "w", encoding="utf-8") as fh:
        fh.write("{}")
    panel = os.path.join(base, "panel")
    os.makedirs(panel)
    data = os.path.join(panel, "data")
    os.symlink(disk, data)
    installer = os.path.join(base, "install.sh")
    with open(installer, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n")
    real_link = _helper93._r26a_link_root_made
    try:
        _p9_patch(_helper93, "panel_conf", lambda: {"data_dir": data, "panel_dir": panel})
        _p9_patch(_helper93, "INSTALLER_PATH", installer)
        _p9_patch(_helper93, "resolve", lambda name: "/bin/true")
        _p9_patch(_helper93, "subprocess", NS(run=lambda *a, **k: NS(returncode=0),
                                             STDOUT=_sp93.STDOUT, TimeoutExpired=_sp93.TimeoutExpired))
        if root_made:
            _p9_patch(_helper93, "_r26a_link_root_made",
                      lambda p: p == data or real_link(p))
        target = _helper93._restore_target()
        if target is not None:
            _helper93._restore_run(target)
        su = _helper93._self_update_target()
        if su is not None:
            _helper93._self_update_run(su[0], su[1], "-", "-")
    finally:
        _p9_restore_all()
    with open(os.path.join(disk, "config.json"), encoding="utf-8") as fh:
        restored = fh.read() == "{\"restored\": true}"
    return (target, restored, os.path.isdir(stage), su and su[1],
            os.path.isfile(os.path.join(disk, _helper93.SELF_UPDATE_LOG)), disk)


_ld93 = _r25a_linked_data()
check("panel-helper: a restore through a data/ link root made copies the staged files into the real "
      "directory and removes the staging directory (a plaintext database and both keys); it used to "
      "say RESTORE_STARTED and do nothing",
      _ld93[0] == os.path.realpath(_ld93[5]) and _ld93[1] is True and _ld93[2] is False,
      repr(_ld93))
check("panel-helper: ...and a self-update through it writes its log in the real directory (it used "
      "to say UPDATE_STARTED and never run the installer)",
      _ld93[3] == os.path.realpath(_ld93[5]) and _ld93[4] is True, repr(_ld93))
_ldu93 = _r25a_linked_data(root_made=False)
check("panel-helper: a data/ link the panel user made is still refused by both, and nothing is "
      "restored or logged there",
      _ldu93[0] is None and _ldu93[3] is None and _ldu93[1] is False and _ldu93[2] is True
      and _ldu93[4] is False, repr(_ldu93))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The debug report: "fail2ban ignores proxied clients" is posture, page-only
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _r25a_proxied_report():
    """The assembled report for a proxied request the panel keyed as loopback (no trusted proxy)."""
    from flask import Flask as _Flask93
    from panel.ops.debug_report import _base as _b93
    from panel.ops.debug_report import network as _nw93
    from unit import part92 as _p92
    app = _Flask93("p93req")
    app.config.update(BOOT_PORT=5000, BOOT_BIND="127.0.0.1", BOOT_TLS=False, _TRUST_PROXY=False)
    net = _b93.Result()
    with app.test_request_context("/", headers={"X-Forwarded-For": "192.0.2.93"},
                                  environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        _nw93._request_lines(net, app.config)
    planted = _b93.Result(lines=["- the throttle is shared, and fail2ban ignores them (planted-p93)"])
    # part92's fixture writes into its own temp dir, which it removes when it ends: lend it one.
    was = _p92._TMP92
    _p92._TMP92 = _tf93.mkdtemp(dir=_TMP93)
    try:
        rep = _p92._r24r_assemble(extra={"network": ("ok", 0.01, net)})[0]
        prep = _p92._r24r_assemble(extra={"planted93": ("ok", 0.01, planted)},
                                   sections=(("planted93", "Planted", "header", "request", "full"),))[0]
    finally:
        _p92._TMP92 = was
    return net, rep, prep


_FIND93 = "fail2ban ignores them"
_rq93 = {}
try:
    _rq93["net"], _rq93["rep"], _rq93["prep"] = _r25a_proxied_report()
except Exception as _e93:  # noqa: BLE001 - a harness failure fails by name below
    _rq93["error"] = "%s: %s" % (type(_e93).__name__, _e93)
_rqfile93 = "\n".join((_rq93.get("rep") or {}).get(k) or "" for k in ("report", "summary", "issue_body"))
_rqpage93 = (_rq93.get("rep") or {}).get("posture") or ""
check("debug report posture: a proxied request keyed as loopback (the throttle shared, fail2ban "
      "ignoring every proxied client) is a finding on the page, and in none of the file, summary, "
      "At a glance or issue body",
      "rep" in _rq93 and _FIND93 in _rqpage93 and _FIND93 not in _rqfile93
      and "- **This request**: from a" in _rqfile93,
      repr(_rq93.get("error") or (_FIND93 in _rqpage93, _rqfile93[-1200:])))
_pfile93 = "\n".join((_rq93.get("prep") or {}).get(k) or "" for k in ("report", "summary", "issue_body"))
check("debug report posture gate: ...and the backstop withholds that wording printed by any "
      "section with add()",
      "prep" in _rq93 and "planted-p93" not in _pfile93
      and "planted-p93" in ((_rq93.get("prep") or {}).get("posture") or ""),
      repr(_rq93.get("error") or _pfile93[-800:]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The auto-block reconcile releases only an address that is still its own
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _r25a_reconcile(is_local, later):
    """(result, the undeny calls) for one reconcile whose later firewall reads answer `later`.

    Its first read shows 192.0.2.93 as the panel's auto-block (its count is now under the
    threshold); `later` is what a superadmin's Block, pressed while the reconcile worked through its
    new blocks, left.
    """
    from panel.services import monitoring as _mon93
    ip = "192.0.2.93"
    reads = [{ip: _mon93._AUTOBLOCK_TAG}]
    undenied = []

    def read(*_a):
        return reads.pop(0) if reads else later

    remote = NS(is_local=is_local, name="p93", id=None if is_local else 9393, host="h93", port=22)
    try:
        _p9_patch(_mon93, "_autoblock_threshold", lambda: 5)
        _p9_patch(_mon93, "tailnet_exempt_ips", lambda r, ips: set())
        _p9_patch(_mon93, "_whitelist_networks", lambda: [])
        if is_local:
            _p9_patch(_so93, "fail2ban_attempt_counts", lambda days=7: {ip: 1})
            _p9_patch(_so93, "ufw_blocked_ips", read)
            _p9_patch(_so93, "ufw_undeny_ip", lambda a: (undenied.append(a), (True, "ok"))[1])
        else:
            _p9_patch(_mon93, "remote_fail2ban_attempt_counts", lambda r, days=7: {ip: 1})
            _p9_patch(_mon93, "remote_ufw_blocked_ips", read)
            _p9_patch(_mon93, "remote_ufw_undeny_ip",
                      lambda r, a: (undenied.append(a), (True, "ok"))[1])
        out = _mon93._autoblock_reconcile(remote)
    finally:
        _p9_restore_all()
    return out, undenied


_rc93 = {(h, k): _r25a_reconcile(h, later) for h in (True, False)
         for k, later in (("re-tagged manual", {"192.0.2.93": "panel-block"}),
                          ("still ours", {"192.0.2.93": "panel-autoblock"}),
                          ("unreadable", None))}
check("monitor autoblock: an address a superadmin blocked by hand while the reconcile ran (its rule "
      "re-tagged from auto-block) is not released, on the panel host and on a remote; it used to "
      "delete the manual block from the reconcile's stale read",
      all(_rc93[(h, "re-tagged manual")] == ((0, 0), []) for h in (True, False)), repr(_rc93))
check("monitor autoblock: ...a firewall that cannot be read again releases nothing either, and one "
      "still tagged as the auto-block is released (control)",
      all(_rc93[(h, "unreadable")] == ((0, 0), []) for h in (True, False))
      and all(_rc93[(h, "still ours")] == ((0, 1), ["192.0.2.93"]) for h in (True, False)),
      repr(_rc93))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The boot's operator release falls back to the self-clear when the helper call fails
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _r25a_release(verb_answer, self_rc=0):
    """(release_operator's answer, the verbs it ran, what it ran as its own account)."""
    verbs, own = [], []
    try:
        _p9_patch(_ts93, "_current_os_user", lambda: "lgsmpanel")
        _p9_patch(_ts93, "_read_prefs_json", lambda: {"OperatorUser": "lgsmpanel"})
        _p9_patch(_so93, "_helper_present", lambda: True)
        _p9_patch(_so93, "_is_system_service", lambda: True)
        _p9_patch(_so93, "_run_verb", lambda verb, args=(), **kw: (verbs.append(verb), verb_answer)[1])
        _p9_patch(_ts93, "_run_ts", lambda args, timeout=5: (own.append(list(args)), ("", "", self_rc))[1])
        return _ts93.release_operator(), verbs, own
    finally:
        _p9_restore_all()


_SUDO93 = ("", "sudo: a password is required", 1)
_rel93 = {"sudo refused the helper": _r25a_release(_SUDO93),
          "timed out": _r25a_release(("", "Command timed out", -1)),
          "...and the self-clear failed too": _r25a_release(_SUDO93, self_rc=1),
          "the helper released it": _r25a_release(("released", "", 0))}
check("release_operator: when the helper call fails (sudo wants a password, a timeout) the panel's "
      "account clears the operator role itself, which needs no privilege; it used to keep the role "
      "at every boot",
      _rel93["sudo refused the helper"] == ("released", ["tailscale-release-operator"],
                                            [["set", "--operator="]])
      and _rel93["timed out"][0] == "released", repr(_rel93))
check("release_operator: ...a self-clear that fails too answers failed, and a helper that released "
      "it runs no self-clear (control)",
      _rel93["...and the self-clear failed too"][0] == "failed"
      and _rel93["the helper released it"] == ("released", ["tailscale-release-operator"], []),
      repr(_rel93))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. uninstall.sh: the sudo note is never read as a Serve route
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UN93 = _read93("uninstall.sh")
_SERVE93 = _json93.dumps({"TCP": {"443": {"HTTPS": True}}, "Web": {"h93.ts.net:443": {"Handlers": {
    "/lgsm": {"Proxy": "http://127.0.0.1:5000"}}}}})


def _r25a_uninstall_routes(plain_refused, after_first=False):
    """(the parent's output, stderr, rc) for a per-user uninstall reading the panel's Serve routes.

    Its plain `tailscale serve status` is refused (an older Tailscale answers it only to root); with
    `after_first`, refused only from the second plain read on, past the parent's own probe.
    """
    d = _tf93.mkdtemp(dir=_TMP93)
    serve = os.path.join(d, "serve.json")
    with open(serve, "w", encoding="utf-8") as fh:
        fh.write(_SERVE93)
    stand = os.path.join(d, "tailscale")
    with open(stand, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n[ \"$1 $2\" = \"serve status\" ] || exit 1\n"
                 "if [ -z \"$P93_AS_ROOT\" ] && [ -n \"$P93_REFUSE\" ]; then\n"
                 "  if [ -n \"$P93_AFTER\" ] && [ ! -e '%s.n' ]; then : > '%s.n'; else exit 1; fi\n"
                 "fi\ncat '%s'\n" % (serve, serve, serve))
    sudo = os.path.join(d, "fakesudo")
    with open(sudo, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nP93_AS_ROOT=1 exec \"$@\"\n")
    for f in (stand, sudo):
        os.chmod(f, 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
    i = _UN93.index("\n_TS_ROUTES_PY='")
    routes_py = _UN93[i + 1:_UN93.index("\n'\n", i) + 2]
    script = ("set -euo pipefail\nRED='' GREEN='' YELLOW='' CYAN='' NC=''\n"
              "info()  { echo -e \"${CYAN}$*${NC}\"; }\nU_SUDO=%s\n_SUDO_NOTE_SHOWN=0\n%s%s\n%s%s%s"
              "if _ts_sudo_note_first && _TS_ROUTES=\"$(_ts_panel_routes 5000 routes)\"; then\n"
              "    printf 'ROUTES<%%s>\\n' \"${_TS_ROUTES}\"\n"
              "    _again=\"$(_ts_panel_routes 5000 routes)\"; printf 'AGAIN<%%s>\\n' \"${_again}\"\nfi\n"
              % (sudo, _fn93(_UN93, "sudo_note"), routes_py, _fn93(_UN93, "_ts_panel_routes"),
                 _fn93(_UN93, "_ts_sudo_note_first"), ""))
    env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    if plain_refused:
        env["P93_REFUSE"] = "1"
    if after_first:
        env["P93_AFTER"] = "1"
    r = _sp93.run(["bash", "-c", script], cwd=d, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60, env=env)
    return r.stdout, r.stderr, r.returncode


_un93 = {k: _r25a_uninstall_routes(k) for k in (True, False)}
_un93["later"] = _r25a_uninstall_routes(True, after_first=True)
_ROUTE93 = "--https=443 /lgsm 0"
check("uninstall.sh: a per-user uninstall whose plain Serve read is refused reads it again under "
      "sudo and captures ONLY route lines (the sudo note used to be captured as a route, and its "
      "words handed to `tailscale serve ... off`), the re-read too",
      all("ROUTES<%s>" % _ROUTE93 in _un93[k][0] and "AGAIN<%s>" % _ROUTE93 in _un93[k][0]
          for k in (True, "later")), repr((_un93[True], _un93["later"])))
check("uninstall.sh: ...and shows the sudo note once, in its own output before the read that "
      "asks sudo; with the plain read allowed, no note at all (control)",
      _un93[True][0].count("need sudo to remove") == 1
      and _un93[True][0].index("need sudo to remove") < _un93[True][0].index("ROUTES<")
      and "need sudo" not in _un93[False][0] + _un93[False][1]
      and "ROUTES<%s>" % _ROUTE93 in _un93[False][0], repr(_un93))
# The harness above calls the probe as uninstall.sh's own first read does: hold that call site.
check("uninstall.sh: its first Serve read is the one behind the parent's sudo-note probe",
      'elif _ts_sudo_note_first && ! _TS_ROUTES="$(_ts_panel_routes "${PANEL_PORT}" routes)"; then'
      in _UN93, "the first _ts_panel_routes call site changed")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. install.sh: the snapshot prune's expected path is not read through PANEL_DIR
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STAMPS93 = ["20260101-00000%d" % i for i in range(5)]
# The hooks stand in for the panel user swapping PANEL_DIR (a real directory) for a link to <other>
# at one moment of the prune: at its first `cd`, its first `readlink`, or never. Where `rootlink`
# asks for a link root made, `stat` answers "root" (0) for it until the swap replaces it. The prune
# runs as root (`id -u` answers 0), with the test's own directories beyond the panel user's reach.
_PRUNE_HOOKS93 = r'''
id() { if [ "$*" = "-u" ]; then echo 0; else command id "$@"; fi; }
_panel_ids() { _PR_UID=4242; }
_panel_cannot_write() { return 0; }
_p93_swap() { [ -e "$P93/swapped" ] && return 0; : > "$P93/swapped"
              mv -- "$PANEL_DIR" "$P93/moved"; ln -s -- "$P93/other" "$PANEL_DIR"; }
cd() { [ "$P93_AT" = cd ] && _p93_swap; builtin cd "$@"; }
readlink() { [ "$P93_AT" = readlink ] && _p93_swap; command readlink "$@"; }
stat() { if [ -n "$P93_ROOTLINK" ] && [ ! -e "$P93/swapped" ]; then echo 0 1;
         else command stat "$@"; fi; }
'''


def _r25a_prune(at, rootlink=False):
    """(rc, stamps left in <other>, stamps left in the real tree, output) for one prune."""
    base = _tf93.mkdtemp(dir=_TMP93)
    real, other = os.path.join(base, "real"), os.path.join(base, "other")
    for t in (real, other):
        for s in _STAMPS93:
            os.makedirs(os.path.join(t, "data", ".backups", s))
    panel = os.path.join(base, "linuxgsm-panel")
    if rootlink:
        os.symlink(real, panel)      # "root made it": stat answers 0 for its first look
    else:
        os.rename(real, panel)
        real = os.path.join(base, "moved") if at else panel
    script = ("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\nKEEP_BACKUPS=3\nP93=%s\nP93_AT=%s\n"
              "P93_ROOTLINK=%s\nPANEL_DIR=%s\n%s\n%s%s%s_r22a_prune_snapshots\n"
              % (base, at, "1" if rootlink else "", panel, _PRUNE_HOOKS93,
                 _fn93(_INS93, "_r26a_link_trusted"), _fn93(_INS93, "_r26a_fixed_target"),
                 _fn93(_INS93, "_r22a_prune_snapshots")))
    r = _sp93.run(["bash", "-c", script], cwd=base, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60)

    def left(t):
        p = os.path.join(t, "data", ".backups")
        return sorted(os.listdir(p)) if os.path.isdir(p) else None
    return r.returncode, left(other), left(real), r.stdout + r.stderr


_pr93 = {"swapped at its first cd": _r25a_prune("cd"),
         "never swapped": _r25a_prune(""),
         "root-made link": _r25a_prune("", rootlink=True),
         "root-made link swapped before its readlink": _r25a_prune("readlink", rootlink=True)}
check("install.sh: a PANEL_DIR swapped for the panel user's link after the prune's link check "
      "(between it and the cd that used to compute both sides) prunes nothing at the link's target",
      _pr93["swapped at its first cd"][1] == _STAMPS93 and "WARN" in _pr93["swapped at its first cd"][3],
      repr(_pr93["swapped at its first cd"]))
check("install.sh: ...nor when a link root made is swapped for the panel user's before it is read "
      "(checked again once inside)",
      _pr93["root-made link swapped before its readlink"][1] == _STAMPS93
      and "WARN" in _pr93["root-made link swapped before its readlink"][3],
      repr(_pr93["root-made link swapped before its readlink"]))
check("install.sh: ...while a real PANEL_DIR, and a link root made, are still pruned to KEEP_BACKUPS "
      "(controls)",
      _pr93["never swapped"][2] == _STAMPS93[2:] and _pr93["root-made link"][2] == _STAMPS93[2:]
      and _pr93["never swapped"][1] == _STAMPS93, repr(_pr93))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. Leads confirmed in review 1016b's A01: the boot's port, and a malformed saved order
# ════════════════════════════════════════════════════════════════════════════════════════════════
_APP93 = _read93("app.py")
_boot93 = [ln.strip() for ln in _APP93[_APP93.find('\nif __name__ == "__main__":'):].splitlines()
           if ln.strip().startswith("port = ")]
_bootvals93 = {repr(v): _val93._port_or(v, 5000) for v in (0, 70000, 5000.7, "5000", 5001, True, -1)}
check("app.py: the boot reads config.json's port as a PORT (a hand-edited 0 bound an ephemeral port, "
      "70000 never started the service, 5000.7 read as 5000), and a quoted one still binds",
      _boot93 == ['port = _port_or(cfg.get("port", 5000), 5000)']
      and _bootvals93 == {"0": 5000, "70000": 5000, "5000.7": 5000, "'5000'": 5000, "5001": 5001,
                          "True": 5000, "-1": 5000}, repr((_boot93, _bootvals93)))

_ord93 = {}
for _l93, _prefs93 in (("server_order a dict of non-lists", {"server_order": {"3": 7, "4": [1, 2]}}),
                       ("server_order a list", {"server_order": [1, 2]}),
                       ("host_order a number", {"host_order": 7}),
                       ("host_order a dict", {"host_order": {"9": 1}})):
    try:
        _ord93[_l93] = (_rem93._host_order_without(_prefs93, 9),
                        _rem93._server_order_without(_prefs93, 9, {2}))
    except Exception as _e93:  # noqa: BLE001 - the defect is exactly a raise; named below
        _ord93[_l93] = type(_e93).__name__
_ordok93 = (_rem93._host_order_without({"host_order": [9, 4]}, 9),
            _rem93._server_order_without({"server_order": {"9": [1], "4": [2, 3]}}, 9, {2}))
check("remote delete: a user's saved order that is not the shape the panel writes is skipped, not a "
      "TypeError (whose rollback dropped every other user's clean-up for that delete too)",
      _ord93 == {"server_order a dict of non-lists": (None, {"3": 7, "4": [1]}),
                 "server_order a list": (None, None), "host_order a number": (None, None),
                 "host_order a dict": (None, None)}, repr(_ord93))
check("remote delete: ...and a well-formed order still loses the deleted host and its servers "
      "(control)", _ordok93 == ([4], {"4": [3]}), repr(_ordok93))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. uninstall.sh takes the Tailscale operator role back from the dedicated account it deletes
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _r25a_uninstall_operator(operator):
    """The `tailscale set` calls uninstall.sh's release made, for tailscaled's OperatorUser."""
    d = _tf93.mkdtemp(dir=_TMP93)
    log = os.path.join(d, "calls")
    stand = os.path.join(d, "tailscale")
    with open(stand, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho \"$*\" >> '%s'\nif [ \"$1 $2\" = \"debug prefs\" ]; then "
                 "printf '%%s' '%s'; fi\nexit 0\n" % (log, _json93.dumps({"OperatorUser": operator})))
    os.chmod(stand, 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
    script = ("set -euo pipefail\nok() { echo \"OK $*\"; }\nwarn() { echo \"WARN $*\"; }\n"
              "PANEL_USER=lgsmpanel\n%s_r25a_release_ts_operator\necho REACHED\n"
              % _fn93(_UN93, "_r25a_release_ts_operator"))
    env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    r = _sp93.run(["bash", "-c", script], cwd=d, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60, env=env)
    calls = open(log, encoding="utf-8").read().split("\n") if os.path.exists(log) else []
    return r.returncode, "REACHED" in r.stdout, [c for c in calls if c.startswith("set")]


_unop93 = {k: _r25a_uninstall_operator(v) for k, v in (("the panel's account", "lgsmpanel"),
                                                      ("someone else's", "alice"), ("none", ""))}
_blk93 = _UN93[_UN93.find('if [[ "${PANEL_USER}" = "${SERVICE_USER}" ]] && id'):]
check("uninstall.sh: a system uninstall takes the Tailscale operator role back from the dedicated "
      "account before deleting it (a pre-#435 panel gave it; a later account of that name inherited "
      "it), leaves anyone else's, and never stops the uninstall",
      _unop93 == {"the panel's account": (0, True, ["set --operator="]),
                  "someone else's": (0, True, []), "none": (0, True, [])}
      and 0 <= _blk93.find("_r25a_release_ts_operator") < _blk93.find("userdel"), repr(_unop93))
