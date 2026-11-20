"""Part 278 of the unit suite: the B3 add-on's service interface (services/b3_control.py, b3_events.py).

1. The pin and the unit: the pinned commit in addons.py and the Containerfile, B3_COMMIT kept in the
   running image, and no restart on B3's exit codes 222 and 230 (but on 233).
2. The card: health.json read into lines, "not answering" past two health intervals on the host's
   clock, an unreadable file shown as nothing, an exit code in words, the version B3 says it runs.
3. Settings Apply: B3's --check-config in a locked-down container on the new files before anything is
   moved into place (run under bash against a stand-in podman), a refusal said with B3's first ERROR
   line and the passwords masked, a plugin-only change reloaded (SIGHUP or the control socket) instead
   of a restart, and the new service settings (Panel actions, purge_aliases_days) validated and written.
4. The control socket's actions (routes/addons_b3_actions.py) through the app: permissions, step-up,
   the request on stdin with the actor, the slot found in the game's list, B3's answers, the audit.
   The socket client itself against a real Unix socket.
5. The table layout check on every read of B3's database.
6. events.jsonl alerts: where the read left off across growth, a cut line, rotation and a shrink
   (bash on real files), alerts through the monitor's sweep, names only in the alert's body.
7. The page: the card's lines and switches and the player view's actions, in node.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the host is a recorder.
"""
import base64 as _b64_278
import json as _json278
import os
import re as _re278
import shutil as _shutil278
import socket as _sk278
import subprocess as _sp278  # nosec B404 - bash, node and python on this part's own fixtures
import sys
import tempfile as _tf278
import threading as _th278

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part221 import _node221
from unit.part47 import _cut47
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all,
                         _p9_threading, _P9Thread)
from unit.part257 import _B3INI257, _DBV257, _HARNESS257, _PROBE257, _RC257, _meta257
from unit.part273 import _drop273, _user273, _xml273
from panel.core.config import encrypt_secret as _enc278
from panel.db import models as _m278
from panel.ops.ssh_manager import db_data as _dd278
from panel.routes import addons as _ra278, addons_b3_actions as _act278, addons_change as _ch278
from panel.routes import databases as _dbr278
from panel.security import auth as _auth278
from panel.services import addons as _ad278, b3_control as _b3c278, b3_events as _ev278, b3_players as _b3p278
from panel.services import chat_privacy as _cp278, monitoring as _mon278, notifications as _nt278

_trips278 = len(_P9_TRIPPED)
_TMP278 = _tf278.mkdtemp(prefix="p278-")
_PIN278 = "7c3bbe8c2fc3e9e75673ceb58c98e54cfc48170f"


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The pin and the unit
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _pin278():
    with open(os.path.join(_root, "panel", "addon_images", "b3", "Containerfile"), encoding="utf-8") as fh:
        cf = fh.read()
    stage2 = cf.split("\nFROM ${BASE_IMAGE}\n", 1)[-1]
    eq("b3 pin: addons.py and the Containerfile build the same commit, labelled 2.0.2 with its short commit",
       (_ad278.B3_COMMIT, _re278.findall(r"^ARG B3_COMMIT=(\S+)", cf, _re278.M), _ad278.CATALOG["b3"]["version"]),
       (_PIN278, [_PIN278], "2.0.2 (7c3bbe8c)"))
    check("b3 pin: the running image keeps the commit (ENV B3_COMMIT in the second stage, after its ARG), so "
          "--version and health.json name it",
          _re278.search(r"^ARG B3_COMMIT\n(?:.*\n)*?ENV B3_COMMIT=\$\{B3_COMMIT\}$", stage2, _re278.M) is not None, stage2[:300])
    unit = _ad278.quadlet("u278", "b3", "logs", "pasta", None, ids=(1004, 1005))
    other = _ad278.quadlet("u278", "iw4madmin", "logs", "pasta", 21001, ids=(1004, 1005))
    eq("b3 unit: no restart after B3's !die (222) or invalid settings (230); a database not reached at start (233) "
       "still restarts; another add-on's unit has no such line",
       (_re278.findall(r"^RestartPreventExitStatus=.*$", unit, _re278.M), "233" in unit,
        "RestartPreventExitStatus" in other, "Restart=always" in unit),
       (["RestartPreventExitStatus=222 230"], False, False, True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The card
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WRITTEN278 = 1763572000                     # 2025-11-19T17:06:40Z
_ISO278 = "2025-11-19T17:06:40Z"


def _health278(**kw):
    doc = {"schema": 1, "written_at": _ISO278, "healthy": False, "reason": "RCON: Bad rconpassword.\x07",
           "state": "running", "b3": {"version": "2.0.2dev", "commit": _PIN278, "parser": "cod4"},
           "game_log": {"ok": True}, "rcon": {"ok": None}, "database": {"ok": True},
           "players": {"humans": 3, "bots": 1}}
    doc.update(kw)
    return _json278.dumps(doc, indent=1)


def _st278(health, now, exit_code="0", ini=""):
    kv = {"b3health.b64": _ad278._b64(health) if health is not None else "", "b3exit": exit_code,
          "b3svc.b64": _ad278._b64(ini), "b3now": str(now)}
    return _b3c278.parse_status(kv, _ad278._unb64)


def _card278():
    fresh = _b3c278.card(_st278(_health278(), _WRITTEN278 + 119), "active")
    eq("b3 card: health.json read into lines (B3's own reason without its control character, RCON not known yet, "
       "players), and the version B3 runs (the pinned commit: the release's label)",
       (fresh["health"], fresh["version"], fresh["stale_minutes"]),
       ({"healthy": False, "reason": "RCON: Bad rconpassword.", "game_log": True, "rcon": None, "database": True,
         "humans": 3, "bots": 1}, "2.0.2 (7c3bbe8c)", None))
    late = _b3c278.card(_st278(_health278(), _WRITTEN278 + 121), "active")
    slow = _b3c278.card(_st278(_health278(), _WRITTEN278 + 121, ini="[b3]\nhealth_interval: 90\n"), "active")
    eq("b3 card: past two health intervals on the host's clock B3 is not answering (no health line); with "
       "health_interval 90 in b3.ini the same age is fine",
       (late["stale_minutes"], late["health"], slow["stale_minutes"], slow["health"] is not None), (2, None, None, True))
    blind = [_b3c278.card(_st278(h, _WRITTEN278 + 9999), "active") for h in (None, "", "not json", '{"schema": 2}', "[1]")]
    eq("b3 card: no file, an empty or failed read, or a file that isn't B3's schema 1 is no measurement: neither a "
       "health line nor \"not answering\", and the pin's version",
       [(c["health"], c["stale_minutes"], c.get("version", _ad278.CATALOG["b3"]["version"])) for c in blind],
       [(None, None, "2.0.2 (7c3bbe8c)")] * 5)
    stopped = _b3c278.card(_st278(_health278(), _WRITTEN278 + 9999, exit_code="230"), "failed")
    eq("b3 card: a stopped B3 says its exit code in words (230: invalid settings) and is not called \"not "
       "answering\"; a running one, or an exit code B3 doesn't define, says none",
       (stopped["exit_reason"] == _b3c278.EXIT_REASONS[230], stopped["stale_minutes"], stopped["health"],
        _b3c278.card(_st278(None, 1, "230"), "active")["exit_reason"], _b3c278.card(_st278(None, 1, "1"), "failed")["exit_reason"],
        sorted(_b3c278.EXIT_REASONS)),
       (True, None, None, "", "", [220, 221, 222, 223, 230, 231, 232, 233]))
    bad = _health278(b3={"version": "x; rm -rf", "commit": "zz"})
    eq("b3 card: a version or commit that isn't one is not shown (the row keeps the installed image's version)",
       _b3c278.card(_st278(bad, _WRITTEN278), "active").get("version"), None)


def _service278():
    ini = "[b3]\nparser: cod4\ncontrol_socket: off\n\n[plugins]\nadmin: @conf/conf/plugin_admin.ini\n"
    on = _ad278.b3_ini_apply(ini, "off", [], service={"actions": True, "purge": 365})
    off = _ad278.b3_ini_apply(on, "off", [], service={"actions": False, "purge": None})
    eq("b3.ini: Panel actions on writes control_socket @conf/b3.sock under [b3] (and purge_aliases_days when set); off "
       "removes both lines; read back as the card shows them",
       (sorted(_re278.findall(r"^(control_socket|purge_aliases_days): (.*)$", on.split("[plugins]")[0], _re278.M)),
        "control_socket" in off or "purge_aliases_days" in off, "parser: cod4" in off,
        _b3c278.service_settings(on), _b3c278.service_settings(off)),
       ([("control_socket", "@conf/b3.sock"), ("purge_aliases_days", "365")], False, True,
        {"actions": True, "purge": 365, "health_interval": 60}, {"actions": False, "purge": None, "health_interval": 60}))
    ok = {"geolocation": "off", "plugins": []}
    eq("settings post: Panel actions is true or false, purge_aliases_days a whole number from 1 to 3650 or null; "
       "anything else is refused (a bool is not a number)",
       [_ch278.settings_choice(dict(ok, **extra)) for extra in (
           {}, {"actions": True, "purge_aliases_days": 365}, {"purge_aliases_days": 3650}, {"purge_aliases_days": 0},
           {"purge_aliases_days": 3651}, {"purge_aliases_days": "365"}, {"purge_aliases_days": True},
           {"purge_aliases_days": 1.5}, {"actions": "yes"})],
       [("off", [], False, False, None), ("off", [], False, True, 365), ("off", [], False, False, 3650), None, None,
        None, None, None, None])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Settings Apply: the check, the reload
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PODMAN278 = r"""#!/bin/bash
echo "$*" >> "%(d)s/podman.log"
mode=$(cat "%(d)s/mode")
if [ "$1" = run ]; then
  for a in "$@"; do case "$a" in *:/data:ro) src=${a%%:/data:ro};; esac; done
  cp "$src/b3.ini" "%(d)s/seen.ini" 2>/dev/null; cp "$src/conf/plugin_geolocation.ini" "%(d)s/seen.geo" 2>/dev/null
  [ -d "$src/.b3" ] && touch "%(d)s/seen.home"
  case "$mode" in
    invalid) echo "Loading..."; echo "ERROR: cannot read /data/b3.ini: [line 3]: 'rcon_password = %(rc)s x'"; echo "ERROR: 2nd"; exit 230;;
    ok) echo "OK: /data/b3.ini"; exit 0;;
    *) echo "Error: no such image"; exit 125;;
  esac
fi
if [ "$1" = kill ]; then : > "%(d)s/hup"; exit 0; fi
if [ "$1" = exec ]; then cat > "%(d)s/socket.in"; echo '{"id": 1, "ok": true, "result": {"failed": {"stats": "ValueError: x"}, "reloaded": []}}'; exit 0; fi
exit 0
"""
# B3 answers a SIGHUP a moment later: its config_reload line lands at the second second of the wait.
_SLEEP278 = r"""#!/bin/bash
[ -e "%(d)s/hup" ] || exit 0
echo x >> "%(d)s/hup"
[ "$(wc -l < "%(d)s/hup")" -ge 2 ] || exit 0
rm -f "%(d)s/hup"
printf '%%s\n' '{"event": "config_reload", "failed": {}, "reloaded": ["admin"], "schema": 1, "time": "t2"}' >> "%(ev)s"
"""
_SYSTEMCTL278 = r"""#!/bin/bash
case "$*" in
  *is-active*) [ "$(cat "%(d)s/active")" = yes ];;
  *ExecMainStartTimestamp*) echo "@$(cat "%(d)s/started")";;
  *) exit 0;;
esac
"""


def _bin278():
    """A folder of stand-ins (podman, systemctl, sleep) and the add-on folder they act on."""
    d = os.path.join(_TMP278, "host")
    data = os.path.join(d, "b3", "Data")
    os.makedirs(os.path.join(data, "conf"), exist_ok=True)
    os.makedirs(os.path.join(d, "b3", "geoip"), exist_ok=True)
    os.makedirs(os.path.join(d, "bin"), exist_ok=True)
    for name, text in (("podman", _PODMAN278 % {"d": d, "rc": _RC257, "ev": os.path.join(data, "events.jsonl")}),
                       ("systemctl", _SYSTEMCTL278 % {"d": d}),
                       ("sleep", _SLEEP278 % {"d": d, "ev": os.path.join(data, "events.jsonl")})):
        with open(os.path.join(d, "bin", name), "w", encoding="utf-8") as fh:
            fh.write(text)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(os.path.join(d, "bin", name), 0o700)  # nosec B103 - this part's own stand-in, its owner only
    return d


def _bash278(d, sh, mode="ok", stdin=None):
    with open(os.path.join(d, "mode"), "w", encoding="utf-8") as fh:
        fh.write(mode)
    # A fixed environment, not this process's: the script sees only the stand-ins and the system's tools.
    env = {"PATH": os.path.join(d, "bin") + ":/usr/local/bin:/usr/bin:/bin", "HOME": d, "LC_ALL": "C.UTF-8"}
    r = _sp278.run(["bash", "-c", sh + "echo SHELL_WENT_ON"], input=stdin, capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, env=env, check=False)
    return r.stdout, r.returncode


def _write278(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read278(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _check_sh278(d):
    data = os.path.join(d, "b3", "Data")
    _write278(os.path.join(data, "b3.ini"), "OLD\n")
    _write278(os.path.join(data, "b3.ini.new"), "NEW\n")
    sh = _b3c278.check_sh("u278", (1004, 1005), "[settings]\ngeolocators: mmdb\n", False)
    out, rc = _bash278(d, sh, "invalid")
    kv = _ad278.kv_lines(out)
    eq("settings check (bash): exit 230 refuses with B3's first ERROR line, removes b3.ini.new, keeps b3.ini, and the "
       "shell goes no further; the check saw the new b3.ini, the new geolocation file and a home folder for B3 (it "
       "makes ~/.b3 at import, and /data is read-only there)",
       ("ADDON_CONFIG_INVALID" in out, _ad278._unb64(kv.get("err.b64", "")).startswith("ERROR: cannot read"),
        "2nd" in _ad278._unb64(kv.get("err.b64", "")), rc, "SHELL_WENT_ON" in out,
        os.path.exists(os.path.join(data, "b3.ini.new")), _read278(os.path.join(data, "b3.ini")),
        _read278(os.path.join(d, "seen.ini")), _read278(os.path.join(d, "seen.geo")),
        os.path.exists(os.path.join(d, "b3", "check")), os.path.exists(os.path.join(d, "seen.home"))),
       (True, True, False, 27, False, False, "OLD\n", "NEW\n", "[settings]\ngeolocators: mmdb\n", False, True))
    args = (_read278(os.path.join(d, "podman.log")) or "").splitlines()[-1:] or [""]
    for flag in ("--network=none", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
                 "--userns=keep-id", "--user 1004:1005", "--pull=never", "/check:/data:ro", "/geoip:/geoip:ro",
                 "--entrypoint python %s /opt/b3/b3_run.py --check-config -c /data/b3.ini" % _ad278.CATALOG["b3"]["image"]):
        check("settings check (bash): the check's container: %s" % flag, flag in args[0], args[0])
    _write278(os.path.join(data, "b3.ini.new"), "NEW\n")
    out, rc = _bash278(d, sh, "ok")
    eq("settings check (bash): a passed check goes on with b3.ini.new in place for the move (and its own folder gone)",
       ("SHELL_WENT_ON" in out, "ADDON_" in out, os.path.exists(os.path.join(data, "b3.ini.new")),
        os.path.exists(os.path.join(d, "b3", "check"))), (True, False, True, False))
    out, rc = _bash278(d, sh, "broken")
    eq("settings check (bash): a check that could not run (Podman's 125) changes nothing either: ADDON_CHECK_FAILED "
       "and its output", ("ADDON_CHECK_FAILED" in out, rc, os.path.exists(os.path.join(data, "b3.ini.new")),
                          "no such image" in _ad278._unb64(_ad278.kv_lines(out).get("tail.b64", ""))),
       (True, 28, False, True))
    _bash278(d, _b3c278.check_sh("u278", (1004, 1005), None, True), "ok")
    last = (_read278(os.path.join(d, "podman.log")) or "").splitlines()[-1]
    eq("settings check (bash): without a new b3.ini the current one is checked; the own-plugins folder is mounted "
       "read-only when it is on", (_read278(os.path.join(d, "seen.ini")), "/Data/extplugins:/data/extplugins:ro" in last),
       ("OLD\n", True))


def _reload_sh278(d):
    data = os.path.join(d, "b3", "Data")
    ev = os.path.join(data, "events.jsonl")
    _write278(ev, '{"event": "config_reload", "failed": {}, "reloaded": [], "schema": 1, "time": "t1"}\n')
    _write278(os.path.join(data, "b3.ini"), "[b3]\nparser: cod4\n")
    mtime = int(os.stat(os.path.join(data, "b3.ini")).st_mtime)
    _write278(os.path.join(d, "active"), "yes")
    _write278(os.path.join(d, "started"), str(mtime + 60))
    sh = _b3c278.reload_sh("u278", "admin")
    out, rc = _bash278(d, sh)
    line = _ad278._unb64(_ad278.kv_lines(out).get("reload.b64", ""))
    eq("reload (bash): without the control socket, SIGHUP, then the config_reload line B3 wrote after it (not the "
       "one before); the shell ends there (no restart)",
       ("ADDON_RELOADED" in out, '"t2"' in line, "SHELL_WENT_ON" in out, rc,
        "kill --signal HUP lgsm-addon-b3" in (_read278(os.path.join(d, "podman.log")) or "")), (True, True, False, 0, True))
    _write278(os.path.join(data, "b3.ini"), "[b3]\ncontrol_socket: @conf/b3.sock\n")
    os.utime(os.path.join(data, "b3.ini"), (mtime, mtime))
    out, _rc = _bash278(d, sh)
    sent = _json278.loads(_read278(os.path.join(d, "socket.in")) or "{}")
    eq("reload (bash): with the control socket, reload_plugins through it with the actor (its answer is read back)",
       (sent.get("cmd"), sent.get("actor"), '"stats"' in _ad278._unb64(_ad278.kv_lines(out).get("reload.b64", ""))),
       ("reload_plugins", "panel:admin", True))
    _write278(os.path.join(d, "started"), str(mtime - 60))
    newer = _bash278(d, sh)[0]
    _write278(os.path.join(d, "started"), str(mtime + 60))
    _write278(os.path.join(d, "active"), "no")
    down = _bash278(d, sh)[0]
    eq("reload (bash): b3.ini edited after B3 started, or B3 not running: no reload, the shell goes on to the restart",
       [("ADDON_RELOADED" in o, "SHELL_WENT_ON" in o) for o in (newer, down)], [(False, True), (False, True)])


def _outcomes278():
    secrets = [_RC257]
    err = _ad278._b64("ERROR: cannot read /data/b3.ini: 'rcon_password = %s x'" % _RC257)
    why, tail = _b3c278.change_outcome("ADDON_CONFIG_INVALID\nerr.b64=%s\n" % err, 27, secrets)[1:]
    check("apply outcome: B3's refusal is said, with its first ERROR line below (without \"ERROR: \"), the RCON "
          "password masked", why == _b3c278.S_INVALID and tail.startswith("cannot read /data/b3.ini")
          and _RC257 not in tail, repr((why, tail)))
    kept = _b3c278.change_outcome("ADDON_RELOADED\nreload.b64=%s\n" % _ad278._b64(
        '{"id": 1, "ok": true, "result": {"reloaded": ["admin"], "failed": {"geolocation": "ValueError: bad"}}}'), 0, [])
    clean = _b3c278.change_outcome("ADDON_RELOADED\nreload.b64=%s\n" % _ad278._b64(
        '{"event": "config_reload", "reloaded": ["admin"], "failed": {}}'), 0, [])
    silent = _b3c278.change_outcome("ADDON_RELOADED\nreload.b64=\n", 0, [])
    eq("apply outcome: a reload that kept a plugin's old settings names it (B3 still running); a clean one is "
       "success; no answer is said; an ordinary restart's output is left to install_outcome",
       ("geolocation" in str(kept[1]), kept[2], clean, silent[1] == _b3c278.S_RELOAD_SILENT,
        _b3c278.change_outcome("ADDON_INSTALLED\n", 0, [])),
       (True, "geolocation: ValueError: bad", (True, "", ""), True, (False, "", "")))


def _apply_host278(meta, b3ini, outcome):
    """Record the host calls of an Apply; the change's own shell answers `outcome` (stdout, rc)."""
    calls = []
    status = _PROBE257 + "installed=1\nmeta.b3=%s\nstate.b3=active\nb3ini.b64=%s\ngeoini.b64=\n" % (
        _ad278._b64(_json278.dumps(meta)), _ad278._b64(b3ini))

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append((sh, stdin_text))
        return (status, "", 0) if "b3ini.b64" in sh else (outcome[0], "", outcome[1])
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch(_ra278, "game_account_write_refusal", lambda remote, user, reading=False: None)
    _p9_patch(_ra278, "step_up_needed", lambda: False)
    _p9_patch(_ch278, "threading", _p9_threading(_P9Thread))
    return calls


def _apply278(sid, body, b3ini, outcome=("ADDON_INSTALLED\n", 0)):
    meta = _meta257(database="gs%d_b3" % sid, plugins=["stats"])
    calls = _apply_host278(meta, b3ini, outcome)
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % sid, json=body)
    _p9_drain()
    with _ra278._JOBS_LOCK:
        job = dict(_ra278._JOBS.get((sid, "b3")) or {})
    change = [c for c in calls if "b3ini.b64" not in c[0]]
    return r.status_code, job, (change[0] if change else ("", None))


def _apply_routes278(sid):
    same = {"geolocation": "off", "plugins": ["stats"]}
    ini = _ad278.b3_ini_apply(_B3INI257, "off", ["stats"], service={"actions": False, "purge": None})
    st, job, (sh, stdin) = _apply278(sid, same, ini)
    at = [sh.find(v) for v in ("--check-config", "kill --signal HUP", ".container.new")]
    eq("apply route: a change to plugin settings only (b3.ini as it is) is checked, then reloaded before the unit "
       "or the relays are touched, with nothing on stdin",
       (st, job.get("why"), -1 < at[0] < at[1] < at[2], stdin, "lgsm-addon-b3.container" in sh),
       (202, "", True, None, True))
    st, job, (sh, stdin) = _apply278(sid, dict(same, actions=True, purge_aliases_days=365), ini)
    eq("apply route: Panel actions turned on rewrites b3.ini (control_socket, purge_aliases_days on stdin), checks "
       "it before it is moved into place, and restarts (no reload)",
       (st, "control_socket: @conf/b3.sock" in (stdin or ""), "purge_aliases_days: 365" in (stdin or ""),
        -1 < sh.find("--check-config") < sh.find("mv -f -T /home/"), "kill --signal HUP" in sh,
        "restart lgsm-addon-b3" in sh), (202, True, True, True, False, True))
    _apply_refusals278(sid, same, ini)


def _apply_refusals278(sid, same, ini):
    refusal = "ADDON_CONFIG_INVALID\nerr.b64=%s\n" % _ad278._b64("ERROR: plugin stats: rcon_password %s" % _RC257)
    job = _apply278(sid, dict(same, actions=True), ini, (refusal, 27))[1]
    a = _p9_audit("addon_settings")
    check("apply route: B3's refusal is the job's answer on the card (its ERROR line below it, the password masked) "
          "and the audit row says not done", job.get("why") == _b3c278.S_INVALID and "plugin stats" in job.get("tail", "")
          and _RC257 not in job.get("tail", "") and a.success is False and _RC257 not in a.detail, repr((job, a)))
    calls = _apply_host278(_meta257(database="gs%d_b3" % sid), ini, ("", 0))
    bad = [_p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % sid, json=dict(same, **x)).status_code
           for x in ({"purge_aliases_days": 0}, {"purge_aliases_days": "30"}, {"actions": 1})]
    eq("apply route: a purge outside 1-3650, as text, or Panel actions not a boolean is refused (400) before the host "
       "is asked", (bad, calls), ([400, 400, 400], []))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The control socket: the client, the actions
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _client_run278(path, line):
    code = _b3c278._CLIENT.replace(repr(_b3c278.SOCKET_PATH), repr(path))
    r = _sp278.run([sys.executable, "-I", "-c", code], input=line.encode(), capture_output=True,  # nosec B603
                   timeout=30, check=False)
    return r.stdout.decode("utf-8", "replace"), r.returncode


def _socket278():
    path = os.path.join(_TMP278, "b3.sock")
    got = []
    srv = _sk278.socket(_sk278.AF_UNIX, _sk278.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
            got.append(data)
            conn.sendall(b'{"id": 1, "ok": true, "result": {"client_id": 12, "bans_lifted": 1}}\n')
    t = _th278.Thread(target=serve, daemon=True)
    t.start()
    req = _b3c278.request("unban", {"client_id": 12, "reason": "appeal"}, "admin\x07")
    out, rc = _client_run278(path, req)
    t.join(10)
    srv.close()
    eq("socket client: one request line, as sent (the actor cleaned of control characters), and B3's reply read back",
       (got, _b3c278.reply(out, rc)),
       ([req.encode()], ("ok", {"client_id": 12, "bans_lifted": 1})))
    out, rc = _client_run278(os.path.join(_TMP278, "none.sock"), req)
    eq("socket client: no socket to connect to is \"off\" (Panel actions off), never a crash or \"down\"",
       (_b3c278.reply(out, rc), rc), (("off", None), 3))
    eq("socket replies: a refusal, a stopped container (125, no JSON) and garbage each read as what they are",
       [_b3c278.reply('{"id":1,"ok":false,"error":"not_found","message":"no client\\u0007"}', 0)[0:2],
        _b3c278.reply("Error: container state improper", 125), _b3c278.reply("{}", 0)],
       [("error", ("not_found", "no client")), ("down", None), ("down", None)])
    eq("reasons: at most 100 characters, no control character, line break or colour code; a warning needs one",
       [_b3c278.clean_reason(x, required=r) for x, r in (("  appeal ", False), ("", False), ("", True), ("x" * 101, False),
                                                        ("a\nb", False), ("^1red", False), ("a\u2028b", False),
                                                        ("Ünïcode ok", True), (5, False))],
       ["appeal", "", None, None, None, None, None, "Ünïcode ok", None])


def _socket_stub278(reply, resolve=None, name="Snake", namesakes=()):
    """Stub the host: the socket call answers `reply`; the player list `resolve`; B3's database one name row.

    `namesakes` are the other stored names B3's database answers for the identity check.
    """
    seen = {"socket": [], "resolve": []}

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        if "podman exec -i lgsm-addon-b3 python -c" in sh:
            seen["socket"].append((sh, stdin_text))
            return reply, "", (3 if "B3SOCK_NONE" in reply else 0)
        meta = _ad278._b64(_json278.dumps({"database": "gs_b3_278"}))
        return "os=24.04\npodman=podman version 5.0\nmeta.b3=%s\nstate.b3=active\n" % meta, "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("_resolve_from_console", lambda server, user, gt, n, selfname: seen["resolve"].append(n) or resolve)
    _p9_patch(_ra278, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_act278, "step_up_needed", lambda: False)
    _p9_patch(_dbr278, "_restore_target", lambda gs, r: type("T", (), {"flavor": "mariadb", "port": 3306, "address": ""})())
    sets = [(("name",), [(name,)]), (("name",), [(n,) for n in namesakes])]
    _p9_patch(_dd278, "run", lambda *a, **k: dict(_dd278.parse(_xml273(sets)), rc=0))
    return seen


def _post278(uid, sid, action, body, cid=12):
    r = _p9_client(uid).post("/api/server/%d/addons/b3/players/%d/%s" % (sid, cid, action), json=body,
                             headers={"Accept": "application/json"})
    return r.status_code, r.get_json(silent=True) or {}


def _unban278(sid):
    seen = _socket_stub278('{"id": 1, "ok": true, "result": {"client_id": 12, "bans_lifted": 2}}\n')
    st, d = _post278(P9_ADMIN, sid, "unban", {"reason": "appeal ok"})
    sh, stdin = seen["socket"][0] if seen["socket"] else ("", "")
    req = _json278.loads(stdin or "{}")
    with _p9.app_context():
        who = _m278.db.session.get(_m278.User, P9_ADMIN).username
    eq("b3 unban: B3 lifts the bans through its socket; the request (actor, client_id, reason) is on stdin, never on "
       "the command line", (st, d.get("message"), req.get("cmd"), req.get("args"), req.get("actor"), "appeal" in sh),
       (200, "B3 lifted the player's bans (2).", "unban", {"client_id": 12, "reason": "appeal ok"}, "panel:" + who, False))
    a = _p9_audit("b3_unban")
    check("b3 unban: audited with the server and the player's B3 id, never the reason", a.success and "@12" in a.detail
          and "appeal" not in a.detail and "2 bans lifted" in a.detail, repr(a))
    _socket_stub278("B3SOCK_NONE\n")
    st, d = _post278(P9_ADMIN, sid, "unban", {})
    eq("b3 unban: with Panel actions off (no socket) it says where to turn them on (409), audited as refused",
       (st, d.get("error"), _p9_audit("b3_unban").success), (409, _act278.S_ACTIONS_OFF, False))


def _kick278(sid):
    seen = _socket_stub278('{"id": 1, "ok": true, "result": {"cid": "3", "client_id": 12}}\n', {"name": "Snake", "num": 3},
                           name="^1Snake")
    st, d = _post278(P9_ADMIN, sid, "kick", {"reason": "camping"})
    req = _json278.loads(seen["socket"][0][1] if seen["socket"] else "{}")
    eq("b3 kick: the slot is found by B3's stored name (colour codes out) in the game's own list, and B3 kicks that slot",
       (st, d.get("message"), seen["resolve"], req.get("args")), (200, "B3 kicked the player.", ["Snake"],
                                                                 {"cid": "3", "reason": "camping"}))
    check("b3 kick: audited with the B3 id and the slot, never the name or the reason",
          "@12, slot 3: done" in _p9_audit("b3_kick").detail and "Snake" not in _p9_audit("b3_kick").detail
          and "camping" not in _p9_audit("b3_kick").detail, repr(_p9_audit("b3_kick")))
    _socket_stub278('{"id": 1, "ok": true, "result": {"cid": "3", "client_id": 40}}\n', {"name": "Snake", "num": 3})
    st, d = _post278(P9_ADMIN, sid, "warn", {"reason": "language"})
    check("b3 warn: B3 acting on another player than asked (the slot changed hands) is said and audited as such",
          st == 200 and d.get("warning") is True and "@40" in d.get("message", "") and "instead" in _p9_audit("b3_warn").detail,
          repr(d))
    seen = _socket_stub278("{}", None)
    st, d = _post278(P9_ADMIN, sid, "kick", {})
    eq("b3 kick: a player not in the game's list (or two of that name) is refused before B3 is asked",
       (st, d.get("error"), seen["socket"]), (409, _act278.S_NOT_ONLINE, []))


def _action_refusals278(sid):
    seen = _socket_stub278("{}", {"name": "Snake", "num": 3})
    bad = [_post278(P9_ADMIN, sid, a, b)[0] for a, b in (("warn", {}), ("warn", {"reason": "^1x"}),
                                                         ("kick", {"reason": "a\nb"}), ("kick", {"reason": 5}),
                                                         ("unban", {"reason": "x" * 101}), ("ban", {}))]
    eq("b3 actions: a warning without a reason, a reason with a colour code, a line break, not text or too long, or "
       "an action that isn't one, is refused before the host is asked", (bad, seen["socket"], seen["resolve"]),
       ([400, 400, 400, 400, 400, 404], [], []))
    _p9_patch(_act278, "step_up_needed", lambda: True)
    st, d = _post278(P9_ADMIN, sid, "unban", {})
    _p9_patch(_act278, "step_up_needed", lambda: False)
    eq("b3 actions: a sign-in past the confirmation window confirms the password first (step-up), nothing sent",
       (st, d.get("error"), seen["socket"]), (403, "reauth_required", []))
    big = _post278(P9_ADMIN, sid, "unban", {}, cid=_b3c278.CLIENT_ID_MAX + 1)[0]
    eq("b3 actions: a B3 id past B3's range is no player (404), unasked", (big, seen["socket"]), (404, []))


def _action_perms278(sid):
    users = {}
    try:
        for name, perms in (("p278addons", [_auth278.MANAGE_ADDONS]),
                            ("p278kick", [_auth278.MANAGE_ADDONS, _auth278.KICK_PLAYER]),
                            ("p278mod", [_auth278.MODERATE_SERVER])):
            users[name] = _user273(perms, name)
        seen = _socket_stub278('{"id": 1, "ok": true, "result": {"client_id": 12, "bans_lifted": 0}}\n',
                               {"name": "Snake", "num": 3})
        got = [_post278(users[u][0], sid, a, {"reason": "r"})[0] for u, a in (
            ("p278addons", "unban"), ("p278addons", "kick"), ("p278kick", "unban"), ("p278mod", "unban"))]
        eq("b3 actions: Manage add-ons alone acts on no one; Kick players adds kick and warn, not unban; the moderation "
           "umbrella without Manage add-ons none: each refused (403) with nothing sent",
           (got, seen["socket"]), ([403, 403, 403, 403], []))
        ok = _post278(users["p278kick"][0], sid, "warn", {"reason": "r"})[0]
        check("b3 actions: ...Manage add-ons with Kick players warns (control)", ok == 200 and len(seen["socket"]) == 1,
              repr((ok, seen["socket"])))
    finally:
        for uid, gid in users.values():
            _drop273((_m278.User, uid), (_m278.Group, gid))


def _alerts_route278(sid):
    c = _p9_client(P9_ADMIN)
    on = c.post("/api/server/%d/addons/b3/alerts" % sid, json={"enabled": True})
    bad = c.post("/api/server/%d/addons/b3/alerts" % sid, json={"enabled": "yes"})
    with _p9.app_context():
        flag = _m278.db.session.get(_m278.GameServer, sid).b3_alerts
    eq("b3 alerts switch: on is stored on the server and audited; anything but true or false is refused",
       (on.status_code, flag, bad.status_code, _p9_audit("b3_alerts_set").detail),
       (200, True, 400, "alerts for B3's bans and kicks on"))
    uid, gid = _user273([], "p278none")
    try:
        denied = _p9_client(uid).post("/api/server/%d/addons/b3/alerts" % sid, json={"enabled": False}).status_code
    finally:
        _drop273((_m278.User, uid), (_m278.Group, gid))
    eq("b3 alerts switch: without Manage add-ons it is refused (403)", denied, 403)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The table layout
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _layout278(sid):
    said = []
    for layout in (None, "2", "1"):
        _socket_stub278("{}")
        _p9_patch(_dd278, "run", lambda *a, _l=layout, **k: dict(_dd278.parse(_xml273(
            [(("id", "name", "connections", "time_add", "time_edit", "grp"), [])], layout=_l)), rc=0))
        r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/players/search" % sid, json={"q": "a"})
        d = r.get_json(silent=True) or {}
        said.append((r.status_code, d.get("error") or d.get("players")))
    eq("b3 table layout: a database that doesn't say its layout, or says another than 1, is refused with a sentence; "
       "layout 1 is read (control)", said,
       [(200, "B3's database doesn't say which table layout it has: B3 2.0.2 or newer writes it when it starts. Update "
              "B3 on its card and start it, then open Players again."),
        (200, "B3's database has table layout 2, which this panel doesn't read (it reads layout 1). Update the panel."),
        (200, [])])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. events.jsonl
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _line278(event, n):
    return _json278.dumps({"schema": 1, "event": event, "time": "t", "target": {"id": n, "cid": "1", "name": "P%d" % n},
                           "admin": {"id": 1, "cid": "0", "name": "Boss"} if n % 2 else None, "reason": "r%d" % n,
                           "duration_minutes": 30 if event == "tempban" else None}) + "\n"


def _look278(d, state):
    out, _rc = _bash278(d, _ev278.read_sh("u278", state))
    return _ev278.parse_read(out, state)


def _append278(path, text):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def _events_bash278(d):
    ev = os.path.join(d, "b3", "Data", "events.jsonl")
    for p in (ev, ev + ".1"):
        if os.path.exists(p):
            os.remove(p)
    s0, none = _look278(d, None)
    _append278(ev, _line278("ban", 1))
    s1, first = _look278(d, s0)
    again = _look278(d, None)[1]
    _append278(ev, _line278("kick", 2) + '{"schema": 1, "event": "ban", "tar')
    s2, grown = _look278(d, s1)
    _append278(ev, 'get": null}\n')
    os.rename(ev, ev + ".1")
    _append278(ev + ".1", _line278("tempban", 3))
    _append278(ev, _line278("kick", 4))
    s3, rotated = _look278(d, s2)
    _write278(ev, _line278("ban", 5))
    s4, cut = _look278(d, (s3[0], s3[1] + 500))
    names = [[_json278.loads(x).get("target", {}) and (_json278.loads(x).get("target") or {}).get("name") for x in lines]
             for lines in (none, first, again, grown, rotated, cut)]
    eq("events (bash): a file that isn't there yet is read from its start once it is; a first look after the panel "
       "starts notes the end only; a cut line waits; a rotation reads the rest of events.jsonl.1, then the new file; "
       "a file shorter than where the read was is read from its start",
       (names, s4[1] == os.path.getsize(ev)),
       ([[], ["P1"], [], ["P2"], [None, "P3", "P4"], ["P5"]], True))


def _sweep278(sid):
    sent = []
    _p9_patch(_nt278, "notify", lambda key, title, body="", server=None, remote=None: sent.append((key, title, body)))
    _p9_patch(_nt278, "alerts_muted", lambda gs: False)
    _p9_patch(_ra278, "game_account_write_refusal", lambda *a, **k: None)
    from panel.routes import _shared as _sh278
    _p9_patch(_sh278, "game_account_write_refusal", lambda *a, **k: None)
    data = {"st": "st=11 0\n"}
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, **k: (data["st"], "", 0))
    _ev278.forget(sid)
    _p9_patch(_mon278, "_probe_hosts", lambda remotes, flag_hosts=None: {P9_HOST: {"reachable": True}})
    _p9_patch(_mon278, "_monitor_host", lambda remote, probe, th, servers: False)
    with _p9.app_context():
        _mon278._monitor_pass()
        lines = _line278("ban", 7) + _line278("tempban", 8) + _line278("unban", 9)
        data["st"] = "st=11 %d\nnew.b64=%s\n" % (len(lines), _b64_278.b64encode(lines.encode()).decode())
        _mon278._monitor_pass()
        many = "".join(_line278("kick", n) for n in range(10, 15))
        data["st"] = "st=11 %d\nnew.b64=%s\n" % (len(lines) + len(many), _b64_278.b64encode(many.encode()).decode())
        _mon278._monitor_pass()
    eq("events: the monitor's sweep reads a B3 with alerts on (first a baseline), alerts on its ban and tempban "
       "(not the unban), the title naming no one, the body the player and the admin; five at once come as one count",
       sent, [("b3_penalty", "B3 banned a player on p278-cod2", "P7 (@7) was banned by Boss (@1): r7"),
              ("b3_penalty", "B3 temporarily banned a player on p278-cod2", "P8 (@8) was banned for 30 minutes by B3: r8"),
              ("b3_penalty", "B3 gave 5 penalties on p278-cod2", "0 bans, 0 temporary bans and 5 kicks since the last look.")])
    eq("events: names are personal data in the alert channels: the body is replaced unless Include details is on",
       (_cp278.chat_body({"include_details": False}, "b3_penalty", "P7 was banned"),
        _cp278.chat_body({"include_details": True}, "b3_penalty", "P7 was banned")),
       (_cp278.BRIEF_BODY, "P7 was banned"))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The page
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _card_js278(row):
    node = _shutil278.which("node")
    if not node:
        from unit.part01 import skip
        skip("b3 card (node)", "no node on this machine")
        return None
    path = os.path.join(_TMP278, "harness.js")
    # The page's own tf(): the card's lines are read with their values in.
    _write278(path, _HARNESS257.replace("ctx.window = ctx;", "ctx.window = ctx; ctx.tf = function (s, v) { return "
                                        "s.replace(/\\{(\\w+)\\}/g, function (m, k) { return k in v ? String(v[k]) : m; }); };"))
    base = {"id": "b3", "name": "B3", "version": "2.0.2 (7c3bbe8c)", "installed": True, "state": "active",
            "legacy": True, "needs_database": True, "data_kept": True, "database": "gs7_b3", "geolocation_option": True,
            "geolocation": "off", "plugins": ["stats"], "switchable": list(_ad278.B3_SWITCHABLE),
            "geo_switchable": list(_ad278.B3_GEO_SWITCHABLE), "update": "", "b3_card": True, "alerts": True,
            "actions": True, "purge_aliases_days": 400, "purge_example": 365, "purge_bounds": [1, 3650]}
    base.update(row)
    cfg = {"src": os.path.join(_root, "panel", "static", "js", "server_addons.js"),
           "data": {"success": True, "addons": [base], "databases": []}}
    r = _sp278.run([node, path], input=_json278.dumps(cfg), capture_output=True, text=True,  # nosec B603
                   timeout=120, check=False)
    try:
        return _json278.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _page278():
    got = _card_js278({"health": {"healthy": False, "reason": "RCON: Bad rconpassword.", "game_log": True,
                                  "rcon": False, "database": None, "humans": 2, "bots": 1}})
    if got is None:
        return
    text = got.get("text", "")
    check("b3 card (node): B3's reason as it wrote it, and its game log, RCON, database and players",
          all(x in text for x in ("B3 reports a problem: RCON: Bad rconpassword.", "Game log: read", "RCON: failing",
                                  "Database: not yet", "Players: 2 (1 bots)", "Alert me when B3 bans")), text[:600])
    posts = [p for p in got.get("posts", []) if p[0].endswith("/settings")]
    eq("b3 card (node): Apply sends Panel actions and purge_aliases_days with the other settings",
       [(p[1].get("actions"), p[1].get("purge_aliases_days")) for p in posts], [(True, 400)])
    _page_bad278()


def _page_bad278():
    bad = _card_js278({"purge_aliases_days": 99999, "stale": "B3 is not answering: x.",
                       "exit_reason": "B3's settings are invalid (exit code 230)."}) or {}
    check("b3 card (node): days out of range are refused on the page (no post); the not-answering and exit lines show",
          not [p for p in bad.get("posts", []) if p[0].endswith("/settings")]
          and "B3 is not answering: x." in bad.get("text", "") and "exit code 230" in bad.get("text", ""), repr(bad)[:400])


def _player_actions_js278():
    src = open(os.path.join(_root, "panel", "static", "js", "b3_players.js"), encoding="utf-8").read()
    prog = ("function T(s){ return s; }\nvar made = [];\n"
            "function node(t, c, x){ var e = {t: t, text: x, kids: [], setAttribute: function(){}, appendChild: "
            "function(k){ this.kids.push(k); return k; }}; return e; }\n"
            "function section(){}\nfunction button(label, icon, act, args){ made.push(act + ':' + args[0]); return {}; }\n"
            + _cut47(src, "function activeBan(") + "\n" + _cut47(src, "function actionBar(") + "\n"
            "var ban = {id: 4, penalties: [{type: 'Ban', state: 'active'}]}, none = {id: 4, penalties: [{type: 'Ban', state: 'removed'}]};\n"
            "var out = [];\n"
            "[[ban, {on: true, unban: true, kick: true}], [none, {on: true, unban: true, kick: true}],"
            " [ban, {on: true, unban: false, kick: true}], [ban, {on: false, unban: true, kick: true}],"
            " [ban, {on: true, unban: false, kick: false}]].forEach(function (c) {"
            " made = []; var box = node('div'); actionBar(c[0], c[1], box); out.push(made.join(',')); });\n"
            "console.log(JSON.stringify(out));\n")
    got = _node221("b3 player view: actions", prog)
    if got is not None:
        eq("b3 player view (node): Unban only for an active ban and Unban permission; Kick and Warn with Kick players; "
           "none with Panel actions off or no permission",
           got, ["b3pAct:unban,b3pAct:kick,b3pAct:warn", "b3pAct:kick,b3pAct:warn", "b3pAct:kick,b3pAct:warn", "", ""])


# ════════════════════════════════════════════════════════════════════════════════════════════════
def _fixture278():
    sid = _p9_new_server(P9_HOST, "cod2p278", "cod2", 28970, name="p278-cod2")
    with _p9.app_context():
        _m278.db.session.add(_m278.GameDatabase(remote_id=P9_HOST, game_server_id=sid, name="gs_b3_278",
                                                secret=_enc278(_DBV257)))
        _m278.db.session.add(_m278.GameDatabase(remote_id=P9_HOST, game_server_id=sid, name="gs%d_b3" % sid,
                                                secret=_enc278(_DBV257)))
        gs = _m278.db.session.get(_m278.GameServer, sid)
        gs.b3_alerts = True
        _m278.db.session.commit()
    return sid


def _routes278():
    sid = _fixture278()
    try:
        _apply_routes278(sid)
        _unban278(sid)
        _kick278(sid)
        _action_refusals278(sid)
        _action_perms278(sid)
        _layout278(sid)
        _sweep278(sid)
        _alerts_route278(sid)
    finally:
        _b3p278.forget(sid)
        _ev278.forget(sid)
        with _p9.app_context():
            _m278.GameDatabase.query.filter_by(game_server_id=sid).delete()
            _m278.db.session.commit()
        _p9_delete_server(sid)


def _bash_parts278():
    d = _bin278()
    real = _ad278.addon_dir
    _ad278.addon_dir = lambda user, addon_id: os.path.join(d, addon_id)
    try:
        _check_sh278(d)
        _reload_sh278(d)
        _events_bash278(d)
    finally:
        _ad278.addon_dir = real


def _main278():
    _pin278()
    _card278()
    _service278()
    _outcomes278()
    _socket278()
    _bash_parts278()
    _p9_arm(_p9_patch, who="part278")
    try:
        _routes278()
    finally:
        _p9_restore_all()
    _page278()
    _player_actions_js278()
    check("part278: no check reached a real transport", len(_P9_TRIPPED) == _trips278,
          repr(_P9_TRIPPED[_trips278:][:4]))


try:
    _main278()
finally:
    _shutil278.rmtree(_TMP278, ignore_errors=True)
