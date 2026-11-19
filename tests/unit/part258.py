"""Part 258 of the unit suite: B3's later games, its own-plugins folder, DB-IP's page, the start limit, /tmp at uninstall.

1. The host page: get_server_status (and /api/server-management) asks sudo nothing when the helper or root
   answers; only the shell path runs `sudo -n true`.
2. DB-IP: the SHA1 is read from the MMDB's own block above its link (the live page's layout, the CSV's block
   first); it is the unpacked database's; a page with no link and sum says so; with the Outside services
   switch off no month update is offered and the card says the switch is off.
3. The start limit: an operator's start, Apply or Update clears it first; a start that still hits it says so.
4. Uninstall: the account's tmux and JVM folders in /tmp go (helper and remote form), only real folders it owns.
5. B3's later games (q3, csgo, ins): off by default; switched on, the probe, the refusals (SourceMod,
   console.log), the TCP RCON forward and b3.ini.
6. The own-plugins folder: off by default; on, a read-only mount and external_plugins_dir; the card asks again.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a recorder.
Shells run under bash in a throwaway folder; nothing reaches a host or db-ip.com.
"""
import contextlib as _ctx258
import gzip as _gzip258
import io as _io258
import json as _json258
import os
import pathlib as _pl258
import re as _re258
import shutil as _shutil258
import subprocess as _sp258  # nosec B404 - bash and node over this part's own throwaway files
import tempfile as _tf258
import types as _types258

from unit.part01 import _root, check, eq
from unit.part05 import _helper as _h258
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_threading,
                         _P9Thread)
from unit.part257 import _HARNESS257
from panel.core import outside_services as _os258
from panel.core.config import encrypt_secret as _enc258
from panel.db.models import AuditLog as _AL258, GameDatabase as _GD258, db as _db258
from panel.ops import system_ops as _so258
from panel.routes import addons as _ra258, addons_change as _ch258
from panel.security import journal_forget_sh as _jf258, privileged as _pv258
from panel.services import addons as _ad258, geoip as _geo258

_trips258 = len(_P9_TRIPPED)
_TMP258 = _tf258.mkdtemp(prefix="p258-")
_RC258 = "p258-rcon-" + "value"            # the game's RCON password in these checks
_DBV258 = "Dbv258" + "abcdefghijklmnopq"   # a database's password in these checks
_MONTH258 = "2026-11"
# The folder the clean-up shells name; every check rewrites it into this part's own throwaway folder.
_SHELL_TMP258 = "/tmp/"  # nosec B108 - only replaced, never used as a path


def _bash258(sh, path_first=None, timeout=30):
    path = "/usr/bin:/bin" if path_first is None else path_first + ":/usr/bin:/bin"
    return _sp258.run(["bash", "-c", sh], capture_output=True, text=True, timeout=timeout,  # nosec B603 B607
                      check=False, env={"PATH": path, "HOME": _TMP258})


# ── 1. the host page's sudo probe ───────────────────────────────────────────────────────────────
class _OsAs258:
    """The os module as system_ops sees it, with geteuid answering `euid` (no stdlib module is patched)."""

    def __init__(self, euid):
        self._euid = euid

    def geteuid(self):
        """The effective uid this check runs as."""
        return self._euid

    def __getattr__(self, name):
        return getattr(os, name)


def _status_cmds258(helper, euid, sudo_ok=False):
    """(has_sudo from get_server_status, has_sudo from /api/server-management, the sudo probes run)."""
    ran = []

    def run(cmd, *a, **k):
        ran.append(cmd)
        return ("OK" if sudo_ok and "sudo -n true" in cmd else "NOPASS"), "", 0
    _p9_patch(_so258, "_run", run)
    _p9_patch(_so258, "_helper_present", lambda: helper)
    _p9_patch(_so258, "os", _OsAs258(euid))
    for name in ("ufw_status", "tailscale_ssh_status"):
        _p9_patch(_so258, name, lambda: {"enabled": False, "installed": True, "rules": [], "running": False})
    _p9_patch(_so258, "tailscale_ssh_choice", lambda: "unrecorded")
    _p9_patch(_so258, "server_uptime", lambda: "1 day")
    _p9_patch(_so258, "detect_tailscale_interface", lambda: "")
    was = dict(_so258._SUDO_PROBE)
    try:
        _so258._SUDO_PROBE.update(at=0.0, ok=None)
        direct = _so258.get_server_status(force=True)["has_sudo"]
        _so258._status_cache["data"] = None
        _so258._SUDO_PROBE.update(at=0.0, ok=None)
        via = (_p9_client(P9_ADMIN).get("/api/server-management").get_json() or {}).get("has_sudo")
    finally:
        _so258._status_cache["data"] = None
        _so258._SUDO_PROBE.update(was)
        _p9_restore_all()
    return direct, via, len([c for c in ran if "sudo -n true" in c])


def _sudo258():
    eq("host page: with the helper installed it asks sudo nothing and can escalate (the narrow grant refuses "
       "`sudo -n true`, and sudo logged each refusal)", _status_cmds258(True, 1000), (True, True, 0))
    eq("host page: as root it asks sudo nothing", _status_cmds258(False, 0), (True, True, 0))
    eq("host page: with neither, the cached probe answers (refused, then allowed)",
       [_status_cmds258(False, 1000), _status_cmds258(False, 1000, sudo_ok=True)],
       [(False, False, 2), (True, True, 2)])


# ── 2. DB-IP ────────────────────────────────────────────────────────────────────────────────────
_DB258 = b"\x00" * 64 + _geo258.MMDB_MARKER + b"\xe1\x00metadata"
_GZ258 = _gzip258.compress(_DB258)
_SHA_DB258 = _geo258.sha1_hex(_DB258)
_URL258 = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz" % _MONTH258
_CARD258 = """    <div class="col-6">
      <div class="card">
        <dl class="card-body">
          <dt>Format</dt>
          <dd>%s</dd>
          <dt>Release</dt>
          <dd>November 2026</dd>
          <dt>MD5SUM</dt>
          <dd class="small">%s</dd>
          <dt>SHA1SUM</dt>
          <dd class="small">%s</dd>
        </dl>
        <div class="px-1 mb-1">
          <a href='https://download.db-ip.com/free/dbip-country-lite-%s.%s.gz'
           class='btn btn-block icon-txt download free_download_link'>Download IP to Country Lite %s</a>
        </div>
      </div>
    </div>
"""


def _page258(mmdb_sha, csv_sha="c" * 40):
    """DB-IP's download page as it is laid out live (2026-11-18).

    The CSV's block, then the MMDB's, each with its MD5SUM and SHA1SUM above its link.
    """
    return ("<html><body><h1>IP to Country Lite</h1><div class=\"row\">\n"
            + _CARD258 % ("CSV", "a" * 32, csv_sha, _MONTH258, "csv", "CSV")
            + _CARD258 % ("MMDB", "b" * 32, mmdb_sha, _MONTH258, "mmdb", "MMDB")
            + "</div><h2>Commercial versions</h2></body></html>")


def _geo_stub258(gets, switch=True):
    asked = []

    def get(url, cap):
        asked.append(url)
        return gets.get(url, (None, "unreachable"))
    _p9_patch(_geo258, "_get", get)
    _p9_patch(_geo258, "CACHE_DIR", _pl258.Path(_TMP258) / ("geo-%d" % len(os.listdir(_TMP258))))
    _p9_patch(_geo258, "month_now", lambda: _MONTH258)
    _p9_patch(_os258, "enabled", lambda key: switch if key == _os258.DBIP else True)
    return asked


def _dbip258():
    page = _page258(_SHA_DB258)
    eq("DB-IP (live layout): the MMDB's link, month and the SHA1 in its own block above the link, never the CSV's",
       (_geo258.parse_page(page), (_geo258.parse_page(_page258("d" * 40, csv_sha=_SHA_DB258)) or ("", "", ""))[2]),
       ((_URL258, _MONTH258, _SHA_DB258), "d" * 40))
    eq("DB-IP: a page whose MMDB block has no SHA1SUM gives nothing (the CSV's sum is not borrowed)",
       _geo258.parse_page(page.replace("SHA1SUM</dt>\n\t\t\t\t\t<dd class=\"small\">%s" % _SHA_DB258, "x</dt>", 1)
                          .replace(_SHA_DB258, "")), None)
    eq("DB-IP: the published SHA1 is the unpacked database's; the .gz's own sum is not accepted",
       [_geo258.unpack(_GZ258, _SHA_DB258) == _DB258, _geo258.unpack(_GZ258, _geo258.sha1_hex(_GZ258))],
       [True, None])
    asked = _geo_stub258({_geo258.PAGE: (page.encode(), None), _URL258: (_GZ258, None)})
    got = _geo258.latest()
    eq("DB-IP: latest() downloads the page, then the file, and keeps the database",
       (got[1:], got[0] is not None and got[0].read_bytes() == _DB258, asked),
       ((_MONTH258, ""), True, [_geo258.PAGE, _URL258]))
    _geo_stub258({_geo258.PAGE: (b"<html>no links</html>", None)})
    unreadable = _geo258.latest()[2]
    _geo_stub258({})
    eq("DB-IP: a page that came but holds no link and sum says so; a page that did not come says it couldn't "
       "download", (unreadable, _geo258.latest()[2]), (_geo258.UNREADABLE, _geo258.UNREACHABLE))
    _p9_restore_all()


def _geo_off258():
    meta = {"image": _ad258.CATALOG["b3"]["image"], "geolocation": "offline", "geoip": "2026-10"}
    _p9_patch(_os258, "enabled", lambda key: key != _os258.DBIP)
    off = _ch258.update_reason("b3", meta, _MONTH258)
    _p9_patch(_os258, "enabled", lambda key: True)
    eq("DB-IP switch off: no update is offered for the database month (it could fetch nothing); on, it is",
       (off, _ch258.update_reason("b3", meta, _MONTH258)), ("", "geoip"))
    _p9_restore_all()


# ── 3. the start limit ──────────────────────────────────────────────────────────────────────────
_SYSTEMCTL258 = """#!/bin/bash
echo "$*" >> "%s/systemctl.log"
case "$*" in
  *"show -p Result"*) echo start-limit-hit ;;
  *" start "*|*" restart "*) exit 1 ;;
esac
exit 0
"""


def _limit_sh258():
    bindir = os.path.join(_TMP258, "bin")
    os.makedirs(bindir, exist_ok=True)
    with open(os.path.join(bindir, "systemctl"), "w", encoding="utf-8") as fh:
        fh.write(_SYSTEMCTL258 % _TMP258)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(os.path.join(bindir, "systemctl"), 0o700)  # nosec B103 - this part's own stub, its owner only
    sh = _ad258.action_sh("b3", "start").replace('cd "$HOME"', "cd %s" % _TMP258)
    r = _bash258(sh, path_first=bindir)
    try:
        with open(os.path.join(_TMP258, "systemctl.log"), encoding="utf-8") as fh:
            log = fh.read().split("\n")
    except OSError:
        log = []    # systemctl never ran: the check below says so
    eq("start (bash): the start limit is cleared before the start; a start refused for the limit prints "
       "ADDON_START_LIMIT and keeps the start's failure status",
       (log[:2], "ADDON_START_LIMIT" in r.stdout, r.returncode != 0),
       (["--user reset-failed lgsm-addon-b3.service", "--user start lgsm-addon-b3.service"], True, True))
    restart = _ad258.reconfigure_sh("u258", "b3", "UNIT", "{}")
    install = _ad258.install_sh("u258", "b3", "UNIT", "{}")
    eq("Apply/Update and install: reset-failed comes right before their restart and start",
       ["systemctl --user reset-failed lgsm-addon-b3.service 2>/dev/null; systemctl --user restart" in restart,
        "systemctl --user reset-failed lgsm-addon-b3.service 2>/dev/null; systemctl --user start" in install],
       [True, True])
    eq("a change or install that hit the limit is said in its own words, not \"its log says why\"",
       _ad258.install_outcome("ADDON_START_LIMIT\nADDON_START_FAILED\n", 25)[1], _ad258.START_LIMIT)


def _limit_route258(sid):
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, **_k: ("ADDON_START_LIMIT\n", "", 1))
    _p9_patch(_ra258, "game_account_write_refusal", lambda remote, user, reading=False: None)
    refused = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/start" % sid).get_json() or {}
    with _ra258._JOBS_LOCK:
        _ra258._JOBS[(sid, "b3")] = {"running": False, "why": "an earlier failure", "tail": "", "kind": "settings"}
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, **_k: ("", "", 0))
    ok = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/start" % sid).get_json() or {}
    with _ra258._JOBS_LOCK:
        left = (sid, "b3") in _ra258._JOBS
    eq("Start (route): a start refused for the limit says so; a start that works clears an earlier job's error",
       ("more than 5 times in 10 minutes" in (refused.get("error") or ""), ok.get("success"), left),
       (True, True, False))


# ── 4. /tmp at uninstall ────────────────────────────────────────────────────────────────────────
def _tmp_tree258(name, tmux):
    base = os.path.join(_TMP258, name)
    _shutil258.rmtree(base, ignore_errors=True)
    os.makedirs(os.path.join(base, tmux, "default-sock"))
    os.makedirs(os.path.join(base, "hsperfdata_acct258"))
    os.makedirs(os.path.join(base, "elsewhere"))
    with open(os.path.join(base, "elsewhere", "keep"), "w", encoding="utf-8") as fh:
        fh.write("x")
    os.symlink(os.path.join(base, "elsewhere"), os.path.join(base, "hsperfdata_linked258"))
    with open(os.path.join(base, "hsperfdata_file258"), "w", encoding="utf-8") as fh:
        fh.write("x")
    return base


def _helper_tmp258():
    base = _tmp_tree258("helper-tmp", "tmux-%d-acct258" % os.getuid())
    saved = {k: getattr(_h258, k) for k in ("ACCOUNT_TMP_DIRS", "ADDON_FORGET_MIN_UID")}
    uid = os.getuid()
    try:
        # The tmux folder named by the account too here, so each call below has only its own folders.
        _h258.ACCOUNT_TMP_DIRS = (base + "/tmux-%(uid)d-%(user)s", base + "/hsperfdata_%(user)s")
        _h258.ADDON_FORGET_MIN_UID = 0
        linked = _h258._forget_account_tmp("linked258", uid)
        a_file = _h258._forget_account_tmp("file258", uid)
        other = _h258._forget_account_tmp("acct258", uid + 1)
        _h258.ADDON_FORGET_MIN_UID = uid + 1
        low = _h258._forget_account_tmp("acct258", uid)
        _h258.ADDON_FORGET_MIN_UID = 0
        mine = _h258._forget_account_tmp("acct258", uid)
    finally:
        for k, v in saved.items():
            setattr(_h258, k, v)
    eq("forget (helper): the account's tmux and JVM folders go when they are real folders it owns; a link (and its "
       "target), a file, another uid's and a uid below the floor are left",
       ([linked, a_file, other, low, mine], sorted(os.listdir(base)), os.listdir(os.path.join(base, "elsewhere"))),
       ([0, 0, 0, 0, 2], ["elsewhere", "hsperfdata_file258", "hsperfdata_linked258"], ["keep"]))


def _helper_release258():
    """do_addon_account_release: the /tmp folders go with `forget` (an uninstall) only."""
    seen = []
    saved = {k: getattr(_h258, k) for k in ("pwd", "subprocess", "resolve", "_addon_forget_account",
                                             "_forget_account_tmp")}
    try:
        _h258.pwd = _types258.SimpleNamespace(getpwnam=lambda u: _types258.SimpleNamespace(pw_uid=5000))
        _h258.subprocess = _types258.SimpleNamespace(
            run=lambda argv, **_k: _types258.SimpleNamespace(returncode=0, stderr=b""),
            TimeoutExpired=_sp258.TimeoutExpired)
        _h258.resolve = lambda prog: prog
        _h258._addon_forget_account = lambda uid, forget: 1
        _h258._forget_account_tmp = lambda user, uid: seen.append((user, uid)) or 2
        outs = []
        for how in ("forget", "keep"):
            buf = _io258.StringIO()
            with _ctx258.redirect_stdout(buf):
                _h258.do_addon_account_release(["acct258", how], None)
            outs.append(buf.getvalue().strip().split("\n")[-1])
    finally:
        for k, v in saved.items():
            setattr(_h258, k, v)
    eq("release (helper): an uninstall (forget) removes the account's /tmp folders; keep leaves them",
       (outs, seen), (["forgotten=3", "forgotten=1"], [("acct258", 5000)]))


def _remote_tmp258():
    base = _tmp_tree258("remote-tmp", "tmux-%d" % os.getuid())
    uid = os.getuid()
    sh = ("u=acct258; uid=%d; n=0; " % uid + _jf258.account_tmp_sh().replace(_SHELL_TMP258, base + "/")
          + 'echo "n=$n"; u=linked258; n=0; ' + _jf258.account_tmp_sh().replace(_SHELL_TMP258, base + "/")
          + 'echo "n=$n"')
    r = _bash258(sh)
    release = _pv258._addon_release_remote(["acct258", "forget"])
    eq("forget (remote, bash): the account's tmux and JVM folders go; a link is left with its target; the shell runs "
       "only with forget, inside the uid >= 1000 test",
       (r.stdout.split(), sorted(os.listdir(base)), os.listdir(os.path.join(base, "elsewhere")),
        _jf258.account_tmp_sh() in release, _jf258.account_tmp_sh() in _pv258._addon_release_remote(["acct258", "keep"]),
        0 <= release.find("-ge 1000") < release.find(_SHELL_TMP258 + "tmux-")),
       (["n=2", "n=0"], ["elsewhere", "hsperfdata_file258", "hsperfdata_linked258"], ["keep"], True, False, True))


# ── 5. B3's later games ─────────────────────────────────────────────────────────────────────────
def _later_games258():
    eq("later games: q3, csgo and ins have their parsers but are off until switched on",
       (_ad258.B3_LATER_GAMES, [_ad258.offered(g) for g in ("q3", "csgo", "ins", "etl", "arma3", "cmw")]),
       ((("q3", "q3", False), ("csgo", "csgo", False), ("ins", "insurgency", False)), [[], [], [], [], [], []]))
    eq("later games: RCON settings, logs, TCP RCON and SourceMod folders",
       ([_ad258.RCON_SETTING[g] for g in ("q3", "csgo", "ins")], [_ad258.game_log_name(g) for g in ("q3", "csgo")],
        _ad258.RCON_TCP_GAMES, sorted(_ad258.SOURCEMOD_DIR)),
       (["rconpassword", "rcon_password", "rcon_password"], ["games.log", "console.log"], ("csgo", "ins"),
        ["csgo", "ins"]))
    eq("RCON: a Source config line has no `set` and is read; a comment is not",
       [_ad258.rcon_password('// rcon_password "old"\nrcon_password "%s"\n' % _RC258),
        _ad258.game_rcon("csgo", 'hostname "x"\nrcon_password "%s"' % _RC258)],
       [_RC258, (_RC258, "")])
    eq("network: a Source game's RCON is forwarded as TCP, the others' as UDP",
       [_ad258.network(27015, None, [], True, True), _ad258.network(28960, None, [], True)],
       ["pasta:--splice-only,-T,27015", "pasta:--splice-only,-U,28960"])


def _probe_q3_258():
    home = os.path.join(_TMP258, "q3-home")
    for d in ("serverfiles/baseq3", ".q3a/baseq3"):
        os.makedirs(os.path.join(home, d), exist_ok=True)
    with open(os.path.join(home, "serverfiles", "baseq3", "q3server.cfg"), "w", encoding="utf-8") as fh:
        fh.write('set rconpassword "%s"\n' % _RC258)
    open(os.path.join(home, ".q3a", "baseq3", "games.log"), "w").close()
    p = _ad258.parse_probe(_bash258(_ad258.probe_sh("b3", "q3server", 7, "q3", 0)
                                    .replace('cd "$HOME"', "cd %s" % home)).stdout)
    eq("probe (bash): Quake 3's games.log under ~/.q3a/baseq3, its rconpassword from serverfiles/baseq3",
       (p["logdir"], _ad258.game_rcon("q3", p["rcon_lines"])), (".q3a/baseq3", (_RC258, "")))


def _probe_csgo258():
    home = os.path.join(_TMP258, "csgo-home")
    os.makedirs(os.path.join(home, "serverfiles", "csgo", "cfg"), exist_ok=True)
    with open(os.path.join(home, "serverfiles", "csgo", "cfg", "csgoserver.cfg"), "w", encoding="utf-8") as fh:
        fh.write('hostname "p258"\nrcon_password "%s"\n' % _RC258)
    open(os.path.join(home, "serverfiles", "csgo", "console.log"), "w").close()
    sh = _ad258.probe_sh("b3", "csgoserver", 7, "csgo", 0).replace('cd "$HOME"', "cd %s" % home)
    before = _ad258.parse_probe(_bash258(sh).stdout)
    os.makedirs(os.path.join(home, "serverfiles", "csgo", "addons", "sourcemod"))
    after = _ad258.parse_probe(_bash258(sh).stdout)
    eq("probe (bash): CS:GO's console.log in its game folder, its rcon_password (no set), and SourceMod's folder",
       (after["logdir"], _ad258.game_rcon("csgo", after["rcon_lines"]), before["sourcemod"], after["sourcemod"]),
       ("serverfiles/csgo", (_RC258, ""), False, True))


_CSPROBE258 = ("os=24.04\npodman=podman version 4.9.3\nuid=1004\ngid=1005\nlogdir=%s\nrcon.b64=%s\n"
               "ports= 21050 21051 21052\nudp=27015 27020\n%s")


def _host258(answer):
    calls = []

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append(("sh", sh, stdin_text))
        return answer(sh), "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **_k: calls.append(("verb", verb, list(args)))
                 or ("", "", 0))
    _p9_patch_sm("enrol_game_user", lambda server, user: None)
    _p9_patch(_ra258, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ch258, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ra258, "step_up_needed", lambda: False)
    _p9_patch(_ra258, "game_account_write_refusal", lambda remote, user, reading=False: None)
    return calls


def _csgo_try258(ids, logdir, sm):
    """One CS:GO B3 install with this probe answer -> (status, the audit's detail, the install shell or None)."""
    probe = _CSPROBE258 % (logdir, _ad258._b64('rcon_password "%s"' % _RC258), sm)
    calls = _host258(lambda sh: probe if "-maxdepth 3 -type f -name" in sh else "ADDON_INSTALLED\n")
    code = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/install" % ids["csgo"],
                                     json={"database_id": ids["db"], "geolocation": "off"}).status_code
    _p9_drain()
    inst = next((c for c in calls if c[0] == "sh" and "podman build" in c[1]), None)
    _p9_restore_all()
    _p9_arm(who="part258")
    return code, _p9_audit("addon_install").detail, inst


def _install_csgo258(ids):
    games = _ad258.CATALOG["b3"]["games"]
    games["csgo"] = "csgo"
    try:
        said = [_csgo_try258(ids, logdir, sm) for logdir, sm in (("serverfiles/csgo", ""), ("", "sourcemod=1\n"),
                                                                  ("serverfiles/csgo", "sourcemod=1\n"))]
    finally:
        games.pop("csgo", None)
    (_c1, no_sm, inst1), (_c2, no_log, inst2), (code3, _d3, inst3) = said
    stdin = (inst3 or ("", "", ""))[2] or ""
    unit = next((t for p, t in _puts258((inst3 or ("", ""))[1]).items() if p.endswith(".container")), "")
    eq("install (CS:GO, switched on): refused without SourceMod, then without console.log (each says what to do); "
       "with both, RCON over TCP on 27015, B3's csgo parser and console.log",
       ("SourceMod" in no_sm, "-condebug" in no_log, inst1, inst2, code3, "Network=pasta:-4,-o,127.0.0.1,-T,27015" in unit,
        "parser: csgo\n" in stdin, "game_log: /gamelog/console.log\n" in stdin, "rcon_password: %s\n" % _RC258 in stdin),
       (True, True, None, None, 202, True, True, True, True))


# ── 6. the own-plugins folder ───────────────────────────────────────────────────────────────────
_B3INI258 = ("[b3]\nparser: cod2\nexternal_plugins_dir: @b3/extplugins\n\n[server]\nrcon_password: %s\n\n"
             "[plugins]\nadmin: @conf/conf/plugin_admin.ini\nmine: @conf/extplugins/plugin_mine.ini\n" % _RC258)
_PROBE258 = ("os=24.04\npodman=podman version 4.9.3\nuid=1004\ngid=1005\nlogdir=.callofduty2/main\n"
             "rcon.b64=%s\nports= 21030 21031 21032\n" % _ad258._b64('set rcon_password "%s"' % _RC258))


def _own_answer258(meta):
    def answer(sh):
        if "b3ini.b64" in sh:
            return _PROBE258 + "installed=1\nmeta.b3=%s\nstate.b3=active\nb3ini.b64=%s\ngeoini.b64=\n" % (
                _ad258._b64(_json258.dumps(meta)), _ad258._b64(_B3INI258))
        if "restart lgsm-addon-b3" in sh:
            return "ADDON_INSTALLED\n"
        return "os=24.04\npodman=podman version 4.9.3\nmeta.b3=%s\nstate.b3=active\n" % _ad258._b64(_json258.dumps(meta))
    return answer


def _own_post258(sid, meta, own):
    calls = _host258(_own_answer258(meta))
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % sid,
                                  json={"geolocation": "off", "plugins": ["tk"], "own_plugins": own})
    _p9_drain()
    re_ = next((c for c in calls if c[0] == "sh" and "restart lgsm-addon-b3" in c[1]), None) or ("", "", "")
    return r.status_code, re_[1], re_[2] or "", _audits258("addon_settings")


def _own258(ids):
    meta = {"kind": "b3", "image": _ad258.CATALOG["b3"]["image"], "commit": _ad258.B3_COMMIT, "geolocation": "off",
            "plugins": ["tk"], "database": "gs%d_b3" % ids["cod2"], "port": None}
    vol = "Volume=/home/cod2p258/panel-addons/b3/Data/extplugins:/data/extplugins:ro"
    code, sh, ini, audits = _own_post258(ids["cod2"], meta, True)
    unit = next((t for p, t in _puts258(sh).items() if p.endswith(".container")), "")
    eq("own plugins on: the folder is made and mounted read-only over /data/extplugins, b3.ini loads from it "
       "(the operator's plugin line kept), the record and the audit say so, a restart",
       (code, vol in unit, "/panel-addons/b3/Data/extplugins" in sh.split("printf")[0],
        "external_plugins_dir: @conf/extplugins\n" in ini, "mine: @conf/extplugins/plugin_mine.ini" in ini,
        _record258(sh).get("own_plugins"), any("own plugins on" in d for d in audits)),
       (202, True, True, True, True, True, True))
    code, sh, ini, _a = _own_post258(ids["cod2"], dict(meta, own_plugins=True), False)
    unit = next((t for p, t in _puts258(sh).items() if p.endswith(".container")), "")
    eq("own plugins off: the mount is gone and B3 looks in its own folder again",
       (code, bool(unit), vol in unit, "external_plugins_dir: @b3/extplugins\n" in ini), (202, True, False, True))
    _p9_restore_all()
    _p9_arm(who="part258")
    _host258(_own_answer258(meta))
    bad = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % ids["cod2"],
                                    json={"geolocation": "off", "plugins": [], "own_plugins": "yes"})
    eq("own plugins: anything but true or false is refused", bad.status_code, 400)
    eq("install: the own-plugins folder is off (no mount, B3's own folder)",
       ("extplugins:ro" in _ad258.quadlet("u", "b3", "/home/u/l", "pasta:", None),
        "external_plugins_dir: @b3/extplugins\n" in _ad258.b3_ini("cod2", 28960, _RC258, "d", _DBV258, "off")),
       (False, True))


def _puts258(sh):
    """The files an install or change shell writes, {path: text} (from its base64 lines)."""
    return {path: _ad258._unb64(b64.strip("'"))
            for b64, path in _re258.findall(r"printf %s (\S+) \| base64 -d > (\S+)\.new", sh or "")}


def _record258(sh):
    """The record (addon.json) a change shell writes, as a dict ({} when there is none)."""
    text = next((t for p, t in _puts258(sh).items() if p.endswith("/addon.json")), "")
    try:
        return _json258.loads(text) if text else {}
    except ValueError:
        return {}


def _audits258(action):
    """Every audit row's detail for `action`, oldest first."""
    with _p9.app_context():
        return [r.detail or "" for r in _AL258.query.filter_by(action=action).order_by(_AL258.id).all()]


def _card258(row_extra, tick_own):
    node = _shutil258.which("node")
    if not node:
        return {"error": "node is not installed"}
    js = _HARNESS257.replace("ctx.window.adRemove('b3');",
                             "const own = els.filter(function (e) { return e.id === 'ad-own-b3'; })[0]; "
                             "res.own = own ? own.checked : null; if (own) own.checked = %s;" % (
                                 "true" if tick_own else "false"))
    path = os.path.join(_TMP258, "harness.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(js)
    row = dict({"id": "b3", "name": "B3", "version": "x", "installed": True, "state": "active", "legacy": True,
                "needs_database": True, "data_kept": True, "database": "gs7_b3", "geolocation_option": True,
                "geolocation": "offline", "geoip": "2026-11", "credit": _geo258.CREDIT, "plugins": ["stats"],
                "switchable": list(_ad258.B3_SWITCHABLE), "geo_switchable": [], "update": "", "note": "",
                "own_plugins": False, "own_plugins_dir": _ad258.B3_OWN_PLUGINS, "geoip_off": ""}, **row_extra)
    cfg = {"src": os.path.join(_root, "panel", "static", "js", "server_addons.js"),
           "data": {"success": True, "addons": [row], "databases": []}}
    r = _sp258.run([node, path], input=_json258.dumps(cfg),  # nosec B603 - node on this part's harness
                   capture_output=True, text=True, timeout=120, check=False)
    try:
        return _json258.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _card_checks258():
    turning_on = _card258({}, True)
    already = _card258({"own_plugins": True}, True)
    off = _card258({"geoip_off": _geo258.OFF}, False)
    warn = "someone else's code"
    eq("card: the own-plugins switch is off with its warning beside it; turning it on asks again (the warning) "
       "and posts nothing until confirmed",
       (turning_on.get("own"), warn in turning_on.get("text", ""), [warn in d for d in turning_on.get("dialogs") or []],
        turning_on.get("posts")), (False, True, [True], []))
    eq("card: with it already on, Apply posts own_plugins with the rest and asks nothing more",
       (already.get("own"), already.get("posts"), already.get("dialogs")),
       (True, [["/api/server/7/addons/b3/settings", {"geolocation": "offline", "plugins": ["afk"],
                                                     "own_plugins": True}]], []))
    eq("card: with DB-IP's download off, an offline B3 and the geolocation chooser say so",
       off.get("text", "").count(_geo258.OFF), 2)


def _row_geo_off258(ids):
    meta = {"kind": "b3", "image": _ad258.CATALOG["b3"]["image"], "geolocation": "offline", "geoip": "2026-10",
            "plugins": ["tk"], "database": "gs%d_b3" % ids["cod2"]}
    _host258(_own_answer258(meta))
    _p9_patch(_geo258, "month_now", lambda: _MONTH258)
    _p9_patch(_os258, "enabled", lambda key: key != _os258.DBIP)
    off = next((r for r in (_p9_client(P9_ADMIN).get("/api/server/%d/addons" % ids["cod2"]).get_json() or {})
                .get("addons") or [] if r["id"] == "b3"), {})
    _p9_patch(_os258, "enabled", lambda key: True)
    on = next((r for r in (_p9_client(P9_ADMIN).get("/api/server/%d/addons" % ids["cod2"]).get_json() or {})
               .get("addons") or [] if r["id"] == "b3"), {})
    eq("add-ons list (route): with DB-IP's download off the B3 row says so and offers no month update; on, it "
       "offers it and says nothing",
       ((off.get("geoip_off"), off.get("update")), (on.get("geoip_off"), on.get("update"))),
       ((_geo258.OFF, ""), ("", "geoip")))


# ── the fixture ─────────────────────────────────────────────────────────────────────────────────
def _fixture258():
    ids = {"cod2": _p9_new_server(P9_HOST, "cod2p258", "cod2", 28965, name="p258-cod2"),
           "csgo": _p9_new_server(P9_HOST, "csgop258", "csgo", 27015, name="p258-csgo")}
    with _p9.app_context():
        for key, db_key in (("cod2", "cod2db"), ("csgo", "db")):
            row = _GD258(remote_id=P9_HOST, game_server_id=ids[key], name="gs%d_b3" % ids[key], secret=_enc258(_DBV258))
            _db258.session.add(row)
            _db258.session.commit()
            ids[db_key] = row.id
    return ids


def _drop258(ids):
    with _p9.app_context():
        for key in ("cod2", "csgo"):
            _GD258.query.filter_by(game_server_id=ids[key]).delete()
        _db258.session.commit()
    for key in ("cod2", "csgo"):
        _p9_delete_server(ids[key])
    with _ra258._JOBS_LOCK:
        for key in ("cod2", "csgo"):
            _ra258._JOBS.pop((ids[key], "b3"), None)


try:
    _sudo258()
    _dbip258()
    _geo_off258()
    _limit_sh258()
    _helper_tmp258()
    _helper_release258()
    _remote_tmp258()
    _later_games258()
    _probe_q3_258()
    _probe_csgo258()
    _card_checks258()
    _ids258 = _fixture258()
    try:
        for _step258 in (lambda ids: _limit_route258(ids["cod2"]), _row_geo_off258, _install_csgo258, _own258):
            _p9_restore_all()
            _p9_arm(who="part258")
            _step258(_ids258)
    finally:
        _p9_restore_all()
        _drop258(_ids258)
finally:
    _p9_restore_all()
check("part258: no check reached a real host", len(_P9_TRIPPED) == _trips258, repr(_P9_TRIPPED[_trips258:][:4]))
_shutil258.rmtree(_TMP258, ignore_errors=True)
