"""Part 117 of the unit suite: the twentieth review's integration fixes (review 1017c, integrator J).

* The debug report's Hosts section no longer says, in the downloadable file, whether the panel logs
  in to each remote as root: that is the privilege model on that host, page-only like every other
  privilege line (owner, 2026-10-16). The file is the same whichever account a remote uses.
* The setup wizard's Serve step and finish, while a port the welcome step saved waits for its
  restart, keep the panel's own route that reaches the port this process serves (the boot moves it
  to the new port) instead of pointing it where nothing listens yet, or publishing a second one at
  /lgsm beside it; with no such route they publish the stored port, as before.
* Create and rename refuse a NEW name that is the console's log path once links are resolved, in
  every state: a home whose `log` link dangles (a stopped server) took a file at the link's target,
  which stops LinuxGSM making its log folders on the next start, as a file at `log` does.

HOW IT RUNS. On part12's Flask app and stand-ins, part12's transport tripwire re-armed for this
part's duration, every stub undone in its finally. The file browser's host-side commands run under
bash over this part's own fixture home. Nothing reaches a host, sudo, tmux or the checkout's data/.
"""
import os
import shutil as _shutil117
import subprocess as _sp117  # nosec B404 - bash over this part's own fixture home, fixed argv
import tempfile as _tf117
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client, _p9_core, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_ts)
from panel.ops.debug_report import _base as _base117
from panel.ops.debug_report import hosts as _dh117
from panel.ops.ssh_manager import files as _f117
from panel.routes import route_helpers as _rh117

_TRIP117_START = len(_P9_TRIPPED)
_TMP117 = _tf117.mkdtemp(prefix="lgsm-unit-p117-")


# ── 1. the Hosts section's login class is on the page only ─────────────────────────────────────────
def _hosts_report117(login):
    """(file lines, page lines) of the real Hosts section, with every remote logging in as `login`."""
    rows = [{"id": 1, "transport": "local", "port": 22, "sudo": False, "is_online": True},
            {"id": 2, "transport": "key", "port": 22, "sudo": True, "is_online": True},
            {"id": 3, "transport": "tailscale", "port": 2222, "sudo": False, "is_online": False}]
    det = {r["id"]: {"addr": "private IPv4", "login": login, "hostkey": "pinned", "cred": None}
           for r in rows}
    _p9_patch(_dh117, "_read_host_cols", lambda: [dict(r) for r in rows])
    _p9_patch(_dh117, "key_present", lambda: True)
    _p9_patch(_dh117, "_read_host_details", lambda: det)
    _p9_patch(_dh117, "peers_by_host", lambda ctx, res: {})
    with _p9.app_context():
        res = _dh117.section_hosts(_base117.Ctx(app=None, deadline_s=20.0))
    return "\n".join(res.lines), "\n".join(res.page_lines)


def _hosts117():
    files, pages = {}, {}
    for login in ("root", "non-root"):
        files[login], pages[login] = _hosts_report117(login)
    check("debug report: the Hosts section's downloadable lines are the SAME whether the panel logs in to its "
          "remotes as root or not (each host's line said 'login root')",
          files["root"] == files["non-root"] and "- host 2 · key" in files["root"]
          and not _base117.POSTURE_RE.search(files["root"]), files["root"][:600])
    check("debug report: ...and each remote's login class is on the page only, never for the panel host",
          "**Host 2 login**: root" in pages["root"] and "**Host 3 login**: non-root" in pages["non-root"]
          and "Host 1 login" not in pages["root"], repr(pages))
    held = [_base117.POSTURE_RE.search(s) is not None for s in (
        "- host 2 · key (paramiko, pooled) · port 22 · sudo yes · address private IPv4 · login root · host key "
        "pinned", "address public IPv4 · login non-root ·", "- host 2 · address private IPv4 · host key pinned")]
    check("debug report: the posture backstop withholds a host line still naming its login class, not one "
          "without it", held == [True, True, False], repr(held))


# ── 2. create/rename never put a file where a dangling `log` link points ───────────────────────────
_HOME117 = os.path.join(_TMP117, "home", "p117u")
_SELF117 = "p117srv"


def _home_tree117():
    """A stopped server's home: `log -> disk/logs`, which does not exist yet, and a plain file."""
    _shutil117.rmtree(os.path.join(_TMP117, "home"), ignore_errors=True)
    os.makedirs(os.path.join(_HOME117, "disk"))
    os.symlink("disk/logs", os.path.join(_HOME117, "log"))
    with open(os.path.join(_HOME117, "disk", "notes.txt"), "w", encoding="utf-8") as fh:
        fh.write("n")


def _shell117(server, user, cmd, timeout=30, selfname=None):
    """shell_as_game_user over the fixture home: the command's /home/p117u is the temp tree's."""
    r = _sp117.run(["/bin/bash", "-c", cmd.replace("/home/p117u", _HOME117)],  # nosec B603 - own text
                   capture_output=True, text=True, timeout=30,
                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"})
    return r.stdout, r.stderr, r.returncode


def _dangling117():
    _p9_patch(_p9_core, "shell_as_game_user", _shell117)
    got = {}
    for case, call, made in (
            ("create file", lambda: _f117.create_path(None, "p117u", "disk", "logs", "file", _SELF117),
             "disk/logs"),
            ("create beside", lambda: _f117.create_path(None, "p117u", "", "dsk", "file", _SELF117), None),
            ("rename onto", lambda: _f117.rename_path(None, "p117u", "disk/notes.txt", "logs", _SELF117),
             "disk/logs"),
            ("create elsewhere", lambda: _f117.create_path(None, "p117u", "disk", "other", "file", _SELF117),
             "disk/other"),
            ("rename elsewhere", lambda: _f117.rename_path(None, "p117u", "disk/notes.txt", "n2", _SELF117),
             "disk/n2")):
        _home_tree117()
        ok, msg = call()
        got[case] = (ok, msg, os.path.lexists(os.path.join(_HOME117, made)) if made else None)
    want_ref = (False, _f117.CREATE_RESERVED, False)
    check("files: on a stopped server whose `log -> disk/logs` link dangles, Create of a file at disk/logs and a "
          "Rename onto it are refused as reserved and make nothing (a file there stops LinuxGSM making its log "
          "folders, as one at `log` does)",
          got["create file"] == want_ref and got["rename onto"] == want_ref, repr(got))
    check("files: ...and a name off the console's path is still created and renamed (controls)",
          got["create elsewhere"] == (True, "Created", True) and got["rename elsewhere"][0] is True
          and got["rename elsewhere"][2] is True and got["create beside"][0] is True, repr(got))


# ── 3. the wizard's Serve keeps the working route while a port change waits ───────────────────────
def _serve_table117(routes):
    """A parsed `tailscale serve status` whose :443 holds `routes` ({mount: loopback port})."""
    text = "https://h.tail.ts.net (tailnet only)\n" + "".join(
        "|-- %s proxy http://127.0.0.1:%d\n" % (m, p) for m, p in routes.items())
    return _p9_ts._parse_serve_status(text) if routes else {"services": []}


def _wizard_case117(client, bound, stored, routes, finish):
    """(Serve writes, stored mount, setup done, answer) of the Serve step, or of the finish."""
    writes = []
    info = NS(installed=True, running=True, dns_name="h.tail.ts.net", serve_unreadable=False,
              serve_config=_serve_table117(routes))
    _p9_patch(_p9_ts, "get_tailscale_info", lambda force_refresh=False: info)
    _p9_patch(_p9_ts, "setup_tailscale_serve",
              lambda port=5000, mount="/", **k: writes.append((port, mount)) or (True, "Serve on"))
    _p9_patch(_p9_ts, "remove_stale_panel_routes", lambda port, mount: ("none", [], None))
    _p9_patch(_rh117, "_setup_ts_ok", lambda: True)   # the route's gate is the wizard's state, not this
    cfg = dict(_CFG117, port=stored, setup_complete=False, tailscale_setup_done=False, tailscale_mount="/",
               tailscale_auto_setup=True)
    _p9_cfg.save_config(cfg)
    _p9.config["BOOT_PORT"] = bound
    if finish:
        with _p9.test_request_context("/setup"):
            _rh117._auto_tailscale_serve(_p9_cfg.load_config())
        said = ""
    else:
        said = _p9_json(client.post("/api/setup/tailscale/serve")).get("message", "")
    now = _p9_cfg.load_config()
    return writes, now.get("tailscale_mount"), now.get("tailscale_setup_done"), said


def _wizard117(client):
    had = ("BOOT_PORT" in _p9.config, _p9.config.get("BOOT_PORT"))
    got = {}
    try:
        for finish in (False, True):
            step = "finish" if finish else "step"
            got[step + " kept"] = _wizard_case117(client, 5000, 5100, {"/": 5000}, finish)
            got[step + " none yet"] = _wizard_case117(client, 5000, 5100, {}, finish)
            got[step + " no change"] = _wizard_case117(client, 5100, 5100, {"/": 5100}, finish)
    finally:
        _p9.config.pop("BOOT_PORT", None)
        if had[0]:
            _p9.config["BOOT_PORT"] = had[1]
    kept = [got[k][:3] for k in ("step kept", "finish kept")]
    check("setup wizard: with a saved port change waiting for its restart, the Serve step and the finish keep "
          "the panel's '/' route to the port it serves now, mark Serve set up there, and write nothing (it was "
          "pointed at the new port where nothing listens yet, or a second route went up at /lgsm)",
          kept == [([], "/", True)] * 2 and "moves to port 5100" in got["step kept"][3], repr(got))
    check("setup wizard: ...with no route to the panel yet it publishes the stored port, and with no port change "
          "it writes as before (controls)",
          [got[k][:3] for k in ("step none yet", "finish none yet", "step no change", "finish no change")]
          == [([(5100, "/")], "/", True)] * 2 + [([(5100, "/")], "/", True)] * 2, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
_CFG117 = _p9_cfg.load_config()
try:
    _p9_arm(who="part117")
    _wizard117(_p9_client(P9_ADMIN))
    _p9_restore_all()
    _p9_arm(who="part117")
    for _fn117 in (_hosts117, _dangling117):
        _fn117()
        _p9_restore_all()
        _p9_arm(who="part117")
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG117)
    _shutil117.rmtree(_TMP117, ignore_errors=True)

check("part117: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP117_START, repr(_P9_TRIPPED[_TRIP117_START:][:6]))
