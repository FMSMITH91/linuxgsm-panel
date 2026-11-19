"""Part 267 of the unit suite: SFTP sign-in failures, the service's answer pools, add-on and uninstall guards.

1. SFTP: a key whose signature does not verify is one failed sign-in, counted at once, and the
   unsigned "would this key do?" query is never counted; a key check the panel never answered (or
   answered "busy") is not charged to the client; the panel answers file requests with "busy" when
   their pool is full, and sign-ins keep a pool of their own; a write into an existing file cut off
   by a disconnect is audited as a change, not as refused; an empty ~/.config can be made.
2. Add-ons: a Remove is a job while it runs (install, update and start refused with its own
   sentence; the card offers no button); Remove also deletes the image the unit runs; an Update or
   Apply refused for a missing log says "try again"; nothing that changes an add-on starts while
   the host's clean reboot holds the server.
3. The uninstall registers itself for the wipe's and the restore's checks and refuses beside a
   scheduled wipe or an add-on job; the Databases tab holds a reset or delete while an add-on job
   runs; a game backup upload whose finish is still running is not forgotten.
4. GMod content cron remove failure, a duplicate JSON key the form never shows, server.properties
   continuation lines read in linear time, and pieces answered "busy" waited for (backups, dumps).

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a stub.
The SFTP pieces run over socket pairs in this process: a real paramiko client against the service's
own transport code, with the panel's answers stubbed.
"""
import io as _io267
import os
import socket as _socket267
import subprocess as _sp267  # nosec B404 - bash over this part's own throwaway files
import tempfile as _tf267
import threading as _th267
import time as _time267
import types as _types267

import paramiko as _pm267
from cryptography.hazmat.primitives import serialization as _ser267
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed267

from unit.part01 import SO as _so267, check, eq
from unit.part06 import _inst_shfn as _shfn267
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part221 import _node221
from unit.part249 import _DOM249, _SETTLE249, _cut249, _js249, _run249
from unit.part255 import _stand_ins255
from unit.part261 import _UPCASES261
from unit.part47 import _cut47
from unit.part263 import _db_row263, _db_stubs263, _gmod_cron263, _write_handle263
from panel.core import i18n as _i18n267
from panel.core.panel_state import r36j_route_job as _rj267
from panel.db.models import GameServer as _GS267, db as _db267
from panel.ops.ssh_manager import files as _files267
from panel.routes import addons as _ra267, addons_change as _ch267, backup_upload as _bup267
from panel.routes import game_restore as _grs267, manage_servers as _ms267, wipe_schedule as _ws267
from panel.services import addons as _ad267, game_config_form as _gcf267, host_reboot as _hr267
from panel.services import sftp_broker as _br267, sftp_files as _sf267, sftp_server as _ss267
from panel.services import world_reset as _wr267

_trips267 = len(_P9_TRIPPED)
_TMP267 = _tf267.mkdtemp(prefix="p267-")
_NS267 = _types267.SimpleNamespace
_XHR267 = {"X-Requested-With": "XMLHttpRequest"}


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. SFTP
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _key267():
    pem = _ed267.Ed25519PrivateKey.generate().private_bytes(
        _ser267.Encoding.PEM, _ser267.PrivateFormat.OpenSSH, _ser267.NoEncryption()).decode()
    return _pm267.Ed25519Key.from_private_key(_io267.StringIO(pem))


_HOST_KEY267 = _key267()


class _Panel267:
    """The panel as the service sees it: records each request; `auth_key` answers what the case says."""

    def __init__(self, key_answer):
        """A panel answering key checks with `key_answer`."""
        self.asked, self.key_answer = [], key_answer

    def ask(self, req, timeout=60):
        """One request: recorded, then answered."""
        self.asked.append(dict(req))
        if req["op"] == "auth_key":
            return dict(self.key_answer)
        return {"ok": True}


# The service settings' password sign-in switch (a yes/no, not a secret).
_PWSWITCH267 = "password"
_ACCEPTED267 = {"ok": True, "uid": 1, "epoch": 0, "name": "u267", "fp": "SHA256:k267"}


def _service267(panel):
    svc = object.__new__(_ss267.Service)
    svc.panel, svc.cfg, svc.host_key = panel, {_PWSWITCH267: False}, _HOST_KEY267
    svc._lock, svc._conns, svc._unauth, svc._db_app = _th267.Lock(), 0, {}, None
    return svc


def _sign_in267(key_answer, wrong_signature):
    """A paramiko client signs in with a key over a socket pair -> (signed in, the panel's requests)."""
    panel = _Panel267(key_answer)
    ours, theirs = _socket267.socketpair()
    runner = _th267.Thread(target=_service267(panel)._run_transport, args=(ours, "192.0.2.64"), daemon=True)
    runner.start()
    key = _key267()
    if wrong_signature:
        key.sign_ssh_data = _key267().sign_ssh_data      # the registered key's blob, another key's signature
    t = _pm267.Transport(theirs)
    ok = False
    try:
        t.connect()
        t.auth_publickey("u267", key)
        ok = t.is_authenticated()
    except _pm267.AuthenticationException:
        ok = False
    finally:
        t.close()
        runner.join(15)
        ours.close()
        theirs.close()
    return ok, panel.asked


def _fails267(asked):
    return [a.get("why") for a in asked if a["op"] == "auth_fail"]


def _sftp_signature267():
    ok, asked = _sign_in267(_ACCEPTED267, wrong_signature=True)
    eq("sftp sign-in: a registered key with a signature that does not verify is one failed sign-in (audited and "
       "counted), named as a bad signature for that key, and the connection's own end does not count it again",
       (ok, _fails267(asked)), (False, ["the signature did not verify for key SHA256:k267"]))
    ok, asked = _sign_in267(_ACCEPTED267, wrong_signature=False)
    eq("sftp sign-in: ...a good signature signs in and counts nothing, also when the client leaves at once (a closed "
       "transport reads as not signed in, and such a sign-in was audited as failed)", (ok, _fails267(asked)), (True, []))
    conn = _ss267.Connection(_service267(_Panel267(_ACCEPTED267)), "192.0.2.64")
    key = _pm267.Ed25519Key(data=_key267().asbytes())     # a public key, as paramiko makes it from the request
    queried = conn.check_auth_publickey("u267", key)
    after_query = _fails267(conn.service.panel.asked)
    verified = key.verify_ssh_sig(b"session blob", _pm267.Message(_key267().sign_ssh_data(b"session blob").asbytes()))
    eq("sftp sign-in: the unsigned \"would this key do?\" query is accepted and counted nowhere; only the signed "
       "request's failed verification is",
       (queried, after_query, verified, len(_fails267(conn.service.panel.asked))),
       (_pm267.AUTH_SUCCESSFUL, [], False, 1))


def _sftp_unanswered267():
    ok, asked = _sign_in267({}, wrong_signature=False)
    busy_ok, busy = _sign_in267({"ok": False, "busy": True, "reason": _br267.BUSY}, wrong_signature=False)
    refused_ok, refused = _sign_in267({"ok": False, "why": "key not registered for this account"}, False)
    eq("sftp sign-in: a key check the panel never answered, or answered busy, refuses the sign-in but charges the "
       "client nothing (no address throttle count, no fail2ban line); a refusal the panel did answer still counts",
       (ok, _fails267(asked), busy_ok, _fails267(busy), refused_ok, _fails267(refused)),
       (False, [], False, [], False, ["key not registered for this account"]))


def _broker_line267(rf):
    import json as _json
    return _json.loads(rf.readline() or b"{}")


def _broker_pools267():
    """HANDLER_SLOTS=1: a slow file request, a second one, then a sign-in failure -> the answers' (id, busy) order."""
    ours, theirs = _socket267.socketpair()
    theirs.settimeout(5)
    release = _th267.Event()

    def slow(_app, _req, _spawn):
        release.wait(8)
        return {"ok": True}
    _p9_patch(_br267, "HANDLER_SLOTS", 1)
    _p9_patch(_br267, "_HANDLERS", dict(_br267._HANDLERS, slow267=slow,
                                        auth_fail=lambda _a, _r, _s: {"ok": True, "counted": True}))
    runner = _th267.Thread(target=_br267.serve, args=(_p9, ours, {}), daemon=True)
    runner.start()
    rf = theirs.makefile("rb")
    got = []
    try:
        for rid, op in ((1, "slow267"), (2, "slow267"), (3, "auth_fail")):
            theirs.sendall(('{"op": "%s", "id": %d}\n' % (op, rid)).encode())
        for _ in range(2):
            a = _broker_line267(rf)
            got.append((a.get("id"), bool(a.get("busy")), a.get("reason") == _br267.BUSY))
        release.set()
        got.append(_broker_line267(rf).get("id"))
    except OSError as exc:
        got.append(type(exc).__name__)
    finally:
        release.set()
        rf.close()
        theirs.close()
        runner.join(5)
        ours.close()
        _p9_restore_all()
    eq("sftp panel: with every file-request slot taken (a host that stopped answering), the next file request is "
       "answered busy at once, a sign-in failure is still answered from its own pool, and the slow one ends later; "
       "the reader used to wait for a slot, holding every user's sign-in", got,
       [(2, True, True), (3, False, False), 1])
    reply = {"ok": False, "busy": True, "reason": _br267.BUSY}
    vfs = object.__new__(_ss267.VirtualSftp)
    vfs.conn = _NS267(signed_in=lambda: {"uid": 1, "epoch": 0, "fp": ""}, ip="192.0.2.64")
    vfs.service = _NS267(panel=_NS267(ask=lambda req, timeout=60: dict(reply)))
    try:
        vfs.ask_folder("p267", False)
        said = None
    except _sf267.Refused as r:
        said = r.answer()
    eq("sftp service: a busy answer reaches the client as a failure saying so, not as permission denied",
       said, (_pm267.SFTP_FAILURE, _br267.BUSY))


def _sftp_in_place267():
    wh, vfs = _write_handle267_in_place()[:2]
    wh.write(0, b"x" * 64)
    srv = object.__new__(_ss267.PanelSftpServer)
    srv.server = vfs
    srv.file_table, srv.folder_table = {b"1": wh}, {}
    srv._SubsystemHandler__channel = _NS267(close=lambda: None)
    srv.finish_subsystem()
    eq("sftp service: a write into an existing file (no staged copy) cut off by a disconnect is audited as the "
       "change it made (its bytes are in the file), not as a refused upload",
       vfs.audits, [("upload_file", "lgsm/config-lgsm/x/common.txt (64 bytes, %s)" % _sf267.CUT_OFF_IN_PLACE, True)])
    wh, vfs = _write_handle263("maps/big.bsp")[:2]
    wh.write(0, b"x" * 64)
    wh.failed = _sf267.CUT_OFF
    wh.close()
    eq("sftp service: ...a staged upload cut off is still audited as refused (its copy is removed) (control)",
       [a[2] for a in vfs.audits], [False])


def _write_handle267_in_place():
    return _write_handle263("lgsm/config-lgsm/x/common.txt", staged=False)


class _MkVfs267:
    """A session for Files.change: `resolve` maps /P267/<rel> to the account's home; records calls."""

    def __init__(self):
        """Nothing made yet."""
        self.audits, self.made = [], []
        self.target = _NS267(user="p267u", selfname="p267srv", sid=267)
        self.backend = _NS267(mkdir=lambda real, attrs: self.made.append(real))

    @staticmethod
    def split(path):
        """The folder and the rest of `path`."""
        parts = path.strip("/").split("/", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""

    def resolve(self, path, write=False, follow=True):
        """(target, backend, real, rel) for `path`."""
        rel = self.split(path)[1]
        return self.target, self.backend, "/home/p267u/" + rel, rel

    def audit(self, target, action, detail, success=True):
        """One audit row."""
        self.audits.append((action, detail, bool(success)))


def _login_above267():
    vfs = _MkVfs267()
    files = _sf267.Files({"cap_mb": 1})
    attr = _pm267.SFTPAttributes()
    made = [files.change(vfs, "mkdir", "/P267/" + rel, None, attr) for rel in (".config", ".config/unity3d")]
    refused = [files.change(vfs, "mkdir", "/P267/.config/systemd", None, attr),
               files.change(vfs, "rename", "/P267/units", "/P267/.config")]
    eq("sign-in paths: an SFTP client may make an empty ~/.config and a game's folder in it (a Unity game's upload "
       "starts with mkdir .config), while a unit folder, or a folder renamed onto ~/.config, is still refused",
       (made, vfs.made, [r[1] if isinstance(r, tuple) else r for r in refused]),
       ([_pm267.SFTP_OK] * 2, ["/home/p267u/.config", "/home/p267u/.config/unity3d"],
        [_files267.LOGIN_FILE_REFUSED] * 2))
    eq("sign-in paths: the file browser's New folder makes ~/.config and ~/.local/share too; a FILE named .config, "
       "a systemd folder in it and a rename onto it are still refused",
       [_files267.create_refusal("p267u", "", ".config", "folder"),
        _files267.create_refusal("p267u", ".local", "share", "folder"),
        _files267.create_refusal("p267u", "", ".config", "file"),
        _files267.create_refusal("p267u", ".config", "systemd", "folder"),
        _files267.rename_refusal("p267u", "units", ".config")],
       [None, None] + [_files267.LOGIN_FILE_REFUSED] * 3)


def _sftp267():
    _sftp_signature267()
    _sftp_unanswered267()
    _broker_pools267()
    _sftp_in_place267()
    _login_above267()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Add-ons
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _addon_remove_job267(sid):
    seen = []

    def shell(*a, **k):
        with _ra267._JOBS_LOCK:
            seen.append(dict(_ra267._JOBS.get((sid, "b3")) or {}))
        seen.append(_ra267.job_running(sid))
        return "removed=1\nothers=1\nADDON_REMOVED\n", "", 0
    _p9_arm(who="part267")
    _p9_patch(_ra267, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 0))
    c = _p9_client(P9_ADMIN)
    try:
        r = c.post("/api/server/%d/addons/b3/remove" % sid)
        with _ra267._JOBS_LOCK:
            after = (sid, "b3") in _ra267._JOBS
            _ra267._JOBS[(sid, "b3")] = {"running": True, "why": "", "tail": "", "kind": "remove"}
        upd = c.post("/api/server/%d/addons/b3/update" % sid)
        start = c.post("/api/server/%d/addons/b3/start" % sid)
        again = c.post("/api/server/%d/addons/b3/remove" % sid)
    finally:
        with _ra267._JOBS_LOCK:
            _ra267._JOBS.pop((sid, "b3"), None)
        _p9_restore_all()
    eq("add-ons: a Remove is a job while remove_sh runs (the reboot census counts it) and is cleared after",
       (r.status_code, seen[0].get("kind"), seen[0].get("running"), seen[1], after),
       (200, "remove", True, True, False))
    eq("add-ons: ...so an Update, a Start or a second Remove begun meanwhile is refused with the remove's own "
       "sentence (an update wrote the unit back after remove_sh, an install lost its folder to rm -rf)",
       [(x.status_code, (x.get_json(silent=True) or {}).get("message")) for x in (upd, start, again)],
       [(409, _ra267._BUSY_REMOVING)] * 3)
    eq("add-ons: the remove's and the add-on job's busy sentences are translated (es, fr)",
       [bool(_i18n267.catalog(lang).get(s)) for lang in ("es", "fr") for s in (_ra267._BUSY_REMOVING, _ra267.ADDON_BUSY)],
       [True] * 4)


def _addon_card267():
    src = open(os.path.join(os.path.dirname(_ra267.__file__), "..", "static", "js", "server_addons.js"),
               encoding="utf-8").read()
    prog = ("var made = [];\n"
            "function node(t, c, x){ return {appendChild: function(){}}; }\n"
            "function button(label, icon, act){ made.push(act); return {}; }\n"
            "function T(s){ return s; } function TF(s){ return s; } function geoStatus(){} function settingsFold(){}\n"
            + _cut47(src, "var JOB = {") + "\n" + _cut47(src, "function installedRow(") + "\n"
            "function acts(a){ made = []; installedRow(a, node()); return made; }\n"
            "console.log(JSON.stringify({remove: acts({id: 'b3', state: 'active', installing: true, job: 'remove'}),"
            " word: JOB.remove || null}));\n")
    got = _node221("add-ons card: no buttons while a remove runs", prog)
    if got is not None:
        eq("add-ons card: while a Remove runs the row offers no button and says Removing…", got,
           {"remove": [], "word": "Removing…"})


def _run_remove267(image_line):
    home = os.path.join(_TMP267, "rm-%d" % len(os.listdir(_TMP267)))
    quadlet = os.path.join(home, _ad267.QUADLET_DIR)
    for d in ("panel-addons/b3/Data", "panel-addons/iw4madmin", _ad267.QUADLET_DIR):
        os.makedirs(os.path.join(home, d), exist_ok=True)
    with open(os.path.join(quadlet, _ad267.unit_name(_ad267.B3) + ".container"), "w", encoding="utf-8") as fh:
        fh.write("[Container]\n%s\nContainerName=x\n" % image_line)
    log, bindir = os.path.join(home, "tools.log"), os.path.join(_TMP267, "bin")
    _stand_ins255(bindir)
    sh = _ad267.remove_sh("u267", _ad267.B3).replace("/home/u267", home)
    r = _sp267.run(["bash", "-c", sh], capture_output=True, text=True, timeout=60, check=False,  # nosec B603 B607
                   env={"PATH": bindir + ":/usr/bin:/bin", "S255_LOG": log, "S255_UNIT": "/nonexistent"})
    tools = open(log, encoding="utf-8").read() if os.path.exists(log) else ""
    return r.returncode, [ln for ln in tools.splitlines() if ln.startswith("podman rmi")]


def _addon_remove_image267():
    rc, rmis = _run_remove267("Image=localhost/lgsm-addon-b3:old267")
    eq("add-ons: Remove deletes the image the unit runs (an add-on not updated since the catalog's image changed) "
       "as well as the catalog's, so the old image does not stay while another add-on is left",
       (rc, rmis), (0, ["podman rmi %s" % _ad267.CATALOG[_ad267.B3]["image"], "podman rmi -- localhost/lgsm-addon-b3:old267"]))
    rc, rmis = _run_remove267("Image=--all")
    eq("add-ons: ...an Image= line that starts with a dash is never handed to podman (control)",
       (rc, rmis), (0, ["podman rmi %s" % _ad267.CATALOG[_ad267.B3]["image"]]))


def _addon_change_words267(sid):
    probe = {"meta": {"database": "", "port": 0}, "ports": [], "udp": [], "ids": (1000, 1000), "logdir": "log",
             "log_found": False, "log_name": "games_mp.log", "splice": False, "rcon_lines": ""}
    with _p9.app_context():
        gs = _db267.session.get(_GS267, sid)
        plain = _ch267._unit_refusal(gs, dict(probe))
        gs.game_type = "csgo"
        named = _ch267._unit_refusal(gs, dict(probe, log_name="console.log"))
        _db267.session.rollback()
    eq("add-ons: an Update or Apply refused for a missing game log says to try again, not to install again (Remove "
       "is the only way to install again, and it deletes the add-on's data)",
       [str(plain), "then try again." in str(named), "install again" in str(plain) + str(named)],
       [_ra267._AGAIN[_ra267._NO_LOG], True, False])
    eq("add-ons: ...and every new ending is translated (es, fr)",
       [k for k in _ra267._AGAIN.values() for lang in ("es", "fr") if not _i18n267.catalog(lang).get(k)], [])


def _addon_reboot267(sid):
    shells = []
    _p9_arm(who="part267")
    _p9_patch(_ra267, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: shells.append(a[2]) or ("", "", 1))
    _p9_patch(_hr267, "reboot_busy", lambda rid: rid == P9_HOST)
    c = _p9_client(P9_ADMIN)
    try:
        said = [c.post("/api/server/%d/addons/b3/%s" % (sid, verb)) for verb in ("update", "settings", "start", "stop")]
        refused_shells = list(shells)
        c.get("/api/server/%d/addons" % sid)
    finally:
        _p9_restore_all()
    eq("add-ons: an update, settings change, start or stop is refused (409, the reboot's sentence) while the host's "
       "clean reboot is stopping its servers, and nothing runs on the host; the card can still be read",
       ([x.status_code for x in said], [" is being rebooted" in ((x.get_json(silent=True) or {}).get("message") or "")
                                        for x in said], refused_shells, len(shells)),
       ([409] * 4, [True] * 4, [], 1))


def _addons267(sid):
    _addon_remove_job267(sid)
    _addon_card267()
    _addon_remove_image267()
    _addon_change_words267(sid)
    _addon_reboot267(sid)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Uninstall, databases, backup uploads
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _uninstall267(sid):
    ran = []

    def claimed(app, gs, remote, server_id, name):
        ran.append((_grs267._grs_other_work(gs), _ws267._r39a_other_work(server_id)))
        return _ms267._index_reply("removed", True, "success")
    _p9_arm(who="part267")
    _p9_patch(_ms267, "_r25b_uninstall_claimed", claimed)
    c = _p9_client(P9_ADMIN)
    try:
        with _rj267(sid, "wipe"):
            wipe = c.post("/servers/%d/delete" % sid, headers=_XHR267)
        with _ra267._JOBS_LOCK:
            _ra267._JOBS[(sid, "b3")] = {"running": True, "why": "", "tail": "", "kind": "install"}
        addon = c.post("/servers/%d/delete" % sid, headers=_XHR267)
        with _ra267._JOBS_LOCK:
            _ra267._JOBS.pop((sid, "b3"), None)
        held = list(ran)
        ok = c.post("/servers/%d/delete" % sid, headers=_XHR267)
    finally:
        with _ra267._JOBS_LOCK:
            _ra267._JOBS.pop((sid, "b3"), None)
        _p9_restore_all()
    eq("uninstall: refused (409) while a scheduled wipe of the server runs (its LinuxGSM run was killed and its "
       "alert sent about a removed server), and while an add-on install runs; nothing is removed",
       [(x.status_code, (x.get_json(silent=True) or {}).get("message", "")[:30]) for x in (wipe, addon)] + [held],
       [(409, "A scheduled wipe of 'p267-cod4'"[:30]), (409, _ra267.ADDON_BUSY[:30]), []])
    eq("uninstall: ...and while it runs, a restore from a backup and a scheduled wipe that fall due see it and "
       "refuse (they read only the route registrations, and the uninstall registered none)",
       (ok.status_code, len(ran), ran[0][0] is not None, ran[0][1] if ran else None), (200, 1, True, True))


def _db_addon_job267(sid):
    rid = _db_row263(sid, "gs%d_b3" % sid)
    calls = _db_stubs263("gs1_unrelated")
    try:
        with _ra267._JOBS_LOCK:
            _ra267._JOBS[(sid, "b3")] = {"running": True, "why": "", "tail": "", "kind": "install"}
        c = _p9_client(P9_ADMIN)
        reset = c.post("/api/server/%d/databases/%d/reset-password" % (sid, rid), json={})
        delete = c.post("/api/server/%d/databases/%d/delete" % (sid, rid), json={"confirm": "gs%d_b3" % sid})
        held = list(calls)
        with _ra267._JOBS_LOCK:
            _ra267._JOBS.pop((sid, "b3"), None)
        reset2 = c.post("/api/server/%d/databases/%d/reset-password" % (sid, rid), json={})
    finally:
        with _ra267._JOBS_LOCK:
            _ra267._JOBS.pop((sid, "b3"), None)
        _p9_restore_all()
        with _p9.app_context():
            from panel.db.models import GameDatabase as _GD
            row = _db267.session.get(_GD, rid)
            if row is not None:
                _db267.session.delete(row)
                _db267.session.commit()
    eq("databases: a password reset and a delete are refused while an add-on install on the server runs (it has "
       "chosen its database but written no record yet), and nothing changes on the database server",
       [(x.status_code, (x.get_json(silent=True) or {}).get("message")) for x in (reset, delete)] + [held],
       [(409, _ra267.ADDON_BUSY)] * 2 + [[]])
    eq("databases: ...with no job running the reset goes ahead (control)", (reset2.status_code, calls),
       (200, ["set_password"]))


def _bup_prune267():
    old = _time267.time() - _bup267._UPLOAD_IDLE - 60
    with _bup267._uploads_lock:
        saved = dict(_bup267._uploads)
        _bup267._uploads.clear()
        _bup267._uploads.update({
            "f267": {"uid": "f267", "kind": "game", "sid": 26701, "user": 1, "size": 1, "got": 0, "ts": old, "busy": 1},
            "q267": {"uid": "q267", "kind": "game", "sid": 26702, "user": 1, "size": 1, "got": 0, "ts": old}})
        try:
            free = _bup267._bup_take_target("game", 26703, _time267.time())
            left = sorted(_bup267._uploads)
        finally:
            _bup267._uploads.clear()
            _bup267._uploads.update(saved)
    eq("backup upload: an upload whose finish is still running past the idle time is kept (a new upload to the "
       "server was accepted and its start deleted the part file the finish was checking); a quiet one is forgotten",
       (free, left), ((True, None), ["f267"]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. GMod cron, JSON form, server.properties, busy pieces
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _gmod_remove267():
    _p9_patch(_hr267, "reboot_busy", _hr267.reboot_busy)       # nothing: keeps _p9_restore_all's list non-empty
    from panel.ops.ssh_manager import _core as _core267, gmod as _gmod267
    written = {}
    crontab = "30 2 * * 0 /home/gmodcontent/cssserver update\n30 2 * * 0 /home/gmodcontent/tf2server update\n"
    _p9_patch(_core267, "run_privileged", lambda server, verb, args=(), **k: (crontab, "", 0)
              if verb == "crontab-list" else ("", "denied", 1))
    _p9_patch(_core267, "write_content_cron", lambda s, u, body, **k: written.setdefault("body", body) and ("", "", 0))
    _p9_patch(_gmod267, "_installed_content_lgsm_names", lambda s, u: ["cssserver", "tf2server"])
    try:
        failed = _gmod267.ensure_content_update_cron(object(), "gmodcontent")
    finally:
        _p9_restore_all()
    ok, _body = _gmod_cron263("30 2 * * 0 /home/gmodcontent/cssserver update\n"
                              "30 2 * * 0 /home/gmodcontent/tf2server update\n")
    eq("gmod content cron: when every game is updated by the account's own crontab and removing the panel's cron "
       "fails, it reports the cron as not matching (False), not done; a remove that works is True (control)",
       (failed, written, ok), (False, {}, True))


def _gcf_deep267():
    arr = _gcf267.build("serverfiles/server-settings.json",
                        '{"max_players": 8, "admins": [{"name": "a", "name": "b"}], "x": {"y": {"z": 1, "z": 2}}}\n')
    top = _gcf267.build("serverfiles/server-settings.json", '{"max_players": 8, "s": {"a": 1, "a": 2}}\n')
    eq("game config form: a key repeated inside an array or below the form's depth leaves the form (no field shows "
       "it); a repeat of a field the form shows still gets the raw editor only",
       (arr is not None, top is None), (True, True))


def _wwr_old267(props):
    """The logical lines as the code read them before (the reference for the joined-once version)."""
    import re as _re
    phys = _re.split(r"\r\n|\r|\n", props)
    out, i = [], 0
    while i < len(phys):
        line, i = phys[i].lstrip(" \t\f"), i + 1
        if not line or line[0] in "#!":
            continue
        while (len(line) - len(line.rstrip("\\"))) % 2 == 1 and i < len(phys):
            line, i = line[:-1] + phys[i].lstrip(" \t\f"), i + 1
        out.append(line)
    return out


def _wwr_lines267():
    cases = ["level-name=a\\\n  b\nx=1", "k=v\\\\\nz=2", "k=a\\\\\\\n\\\nnext\nq=1", "k=a\\\n\nm=3",
             "k=a\\\n\\\\\nm=4", "# c\\\nk=1", "k=a\\", "k=a\\\r\n b\r c=1", "k=\\\n\\\n\\\nend"]
    eq("world reset: server.properties continuation lines read exactly as before (odd/even backslashes, blank and "
       "backslash-only parts, comments, CR and CRLF)",
       [_wr267._wwr_logical_lines(c) for c in cases], [_wwr_old267(c) for c in cases])
    seen = []
    real = _wr267._wwr_continues
    _p9_patch(_wr267, "_wwr_continues", lambda line: seen.append(len(line)) or real(line))
    try:
        joined = _wr267._wwr_logical_lines("k=" + "a\\\n" * 2000 + "end\n")
    finally:
        _p9_restore_all()
    eq("world reset: 2000 continued lines are judged one physical line at a time (each check reads a few "
       "characters, not the whole line grown so far: quadratic on a 1 MiB file, in the wipe ticker)",
       (len(joined), len(joined[0]), max(seen)), (1, 2 + 2000 + 3, 4))


_BUSYCASE267 = r"""
cases.busyLong = Array(8).fill({status: 409, body: {success: false, busy: true}})
  .concat([{status: 200, body: {success: true, received: 8}}]);
cases.busyForever = Array(200).fill({status: 409, body: {success: false, busy: true}});
let clock = 0; Date.now = () => (clock += 20000);
"""


def _busy_pieces267():
    prog = (_SETTLE249 + _UPCASES261 + _BUSYCASE267 + r"""
global.window = global; global.setTimeout = (f) => setImmediate(f);
let sent = [], plan = [];
function reply(status, body){ return Promise.resolve({ok: status < 400, status, json: () => Promise.resolve(body)}); }
window.fetch = function(url){
  sent.push(String(url));
  if (/cancel$/.test(url)) return reply(200, {success: true});
  if (/finish$/.test(url)) return reply(200, {success: true, name: 'a.tar.gz'});
  const m = /offset=(\d+)/.exec(url);
  if (m && Number(m[1]) === 4 && plan.length) { const p = plan.shift(); return reply(p.status, p.body); }
  if (m) return reply(200, {success: true, received: Math.min(Number(m[1]) + 4, 10)});
  return reply(200, {success: true, id: 'u1', chunk: 4});
};
""" + _cut249(_js249("panel.js"), "window.backupUpload = function(") + r"""
const file = {size: 10, slice: (a, b) => 'x'.repeat(b - a)};
(async () => {
  const out = {};
  for (const k of ['busyLong', 'busyForever']) {
    sent = []; plan = cases[k].slice(); clock = 0; let res = null;
    try { res = await window.backupUpload(file, '/x/upload', null); } catch (e) { res = null; }
    out[k] = {ok: !!(res && res.success), at4: sent.filter(u => /offset=4$/.test(u)).length,
              cancel: sent.some(u => /cancel$/.test(u))};
  }
  console.log(JSON.stringify(out));
})();
""")
    got = _run249("backup upload (node): busy pieces", prog)
    if got is not None:
        eq("backup upload (node): a piece answered busy (the first copy still writing, up to the server's 300 s) "
           "is asked again without spending the four lost-answer retries, and the upload goes on; past the busy "
           "allowance it falls back to them and is cancelled",
           got, {"busyLong": {"ok": True, "at4": 9, "cancel": False},
                 "busyForever": {"ok": False, "at4": 21, "cancel": True}})
    prog = (_SETTLE249 + _DOM249 + _UPCASES261 + _BUSYCASE267 + r"""
global.setTimeout = (f) => setImmediate(f); window.MOUNT = '';
let sent = [], plan = [];
function reply(status, body){ return Promise.resolve({ok: status < 400, status, json: () => Promise.resolve(body)}); }
window.confirmDialog = o => o.onConfirm();
window.fetch = function(url, init){
  sent.push(String(url));
  if (/cancel$/.test(url)) return reply(200, {success: true});
  if (/finish$/.test(url)) return reply(200, {success: true, message: 'restored'});
  const m = /offset=(\d+)/.exec(url);
  if (m && Number(m[1]) === 4 && plan.length) { const p = plan.shift(); return reply(p.status, p.body); }
  if (m) return reply(200, {success: true, received: Math.min(Number(m[1]) + 4, 10)});
  if (/\/upload$/.test(url)) return reply(200, {success: true, id: 'ab', chunk: 4});
  return reply(200, {success: true});
};
""" + _js249("databases_manager.js") + r"""
(async () => {
  const out = {};
  for (const k of ['busyLong', 'busyForever']) {
    sent = []; plan = cases[k].slice(); clock = 0; dbmCtx.st.busy = false;
    dbmOpen(5, 7, 'gs5_db', '127.0.0.1', 3306);
    document.getElementById('dbm-upload-file').files = [{name: 'd.sql', size: 10, slice: (a, b) => 'x'.repeat(b - a)}];
    dbmUpload(); for (let i = 0; i < 8; i++) await settle();
    out[k] = {at4: sent.filter(u => /offset=4$/.test(u)).length, finish: sent.some(u => /finish$/.test(u)),
              cancel: sent.some(u => /cancel$/.test(u))};
  }
  console.log(JSON.stringify(out));
})();
""")
    got = _run249("database dump upload (node): busy pieces", prog)
    if got is not None:
        eq("database dump upload (node): a piece answered busy is asked again without spending the lost-answer "
           "pauses and the restore goes on; past the busy allowance the upload fails and is cancelled", got,
           {"busyLong": {"at4": 9, "finish": True, "cancel": False},
            "busyForever": {"at4": 21, "finish": False, "cancel": True}})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The release name of a commit signed without one (CI or tooling only)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DAY267 = 1795046400          # 2026-11-19 00:00 UTC
_GIT_ENV267 = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git267(repo, *args, **env):
    r = _sp267.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False,  # nosec B603 B607
                   env=dict(os.environ, **_GIT_ENV267, **env))
    return r.stdout.strip()


def _commit267(repo, msg, at):
    _git267(repo, "commit", "-q", "--allow-empty", "-m", msg, GIT_COMMITTER_DATE="@%d +0000" % at,
            GIT_AUTHOR_DATE="@%d +0000" % at)
    return _git267(repo, "rev-parse", "HEAD")


def _names267(repo, names):
    """Save main/<sha>.name for each (sha, name) on the signatures ref, as tools/sign-release.sh does."""
    idx = os.path.join(_TMP267, "sig-index")
    for sha, name in names:
        blob = _sp267.run(["git", "-C", repo, "hash-object", "-w", "--stdin"], input=name + "\n", text=True,  # nosec B603 B607
                          capture_output=True, check=False, env=dict(os.environ, **_GIT_ENV267)).stdout.strip()
        _git267(repo, "update-index", "--add", "--cacheinfo", "100644,%s,main/%s.name" % (blob, sha), GIT_INDEX_FILE=idx)
    tree = _git267(repo, "write-tree", GIT_INDEX_FILE=idx)
    _git267(repo, "update-ref", _so267._RELEASE_SIG_REF, _git267(repo, "commit-tree", tree, "-m", "signatures"))


def _installer_label267(repo):
    prog = "set -euo pipefail\n" + "".join(_shfn267(n) for n in (
        "_gitc", "_epoch_version", "_r42i_tree_owner", "_owner_read", "_version_file", "_release_name",
        "panel_version")) + "panel_version\n"
    r = _sp267.run(["bash", "-c", prog], capture_output=True, text=True, check=False, timeout=60,  # nosec B603 B607
                   env=dict(os.environ, PANEL_DIR=repo, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                            GIT_CEILING_DIRECTORIES=_TMP267))
    return r.stdout.strip().split(" · ")[0]


def _release_names267():
    repo = os.path.join(_TMP267, "rel")
    _sp267.run(["git", "init", "-q", "-b", "main", repo], capture_output=True, check=False)  # nosec B603 B607
    older = _commit267(repo, "the day before", _DAY267 - 3600)
    third = _commit267(repo, "release 2026.11.19.3", _DAY267 + 3600)
    fourth = _commit267(repo, "release 2026.11.19.4", _DAY267 + 7200)
    tooling = _commit267(repo, "CI only", _DAY267 + 9000)
    tooling2 = _commit267(repo, "tooling only", _DAY267 + 9600)
    _names267(repo, [(older, "2026.11.18.2"), (third, "2026.11.19.3"), (fourth, "2026.11.19.4")])
    saved_dir = _so267.PANEL_DIR
    _so267.PANEL_DIR = repo
    try:
        labels = [_so267.version_for_commit(c) for c in (tooling2, tooling, fourth, third)]
        installer = _installer_label267(repo)
        nextday = _commit267(repo, "tooling the next day", _DAY267 + 86400 + 60)
        _names267(repo, [(older, "2026.11.18.2"), (third, "2026.11.19.3"), (fourth, "2026.11.19.4")])
        lone = _so267.version_for_commit(nextday)
        installer_lone = _installer_label267(repo)
    finally:
        _so267.PANEL_DIR = saved_dir
    eq("release name: a commit signed with no name (CI or tooling only) is labelled with the nearest named release "
       "before it on the same day (2026.11.19.4, the first one met), as the update card, What's new and the bots read "
       "it; the named commits keep their own", labels, ["2026.11.19.4", "2026.11.19.4", "2026.11.19.4", "2026.11.19.3"])
    eq("release name: ...install.sh's \"Update complete\" label follows the same rule", installer, "2026.11.19.4")
    eq("release name: a commit whose day has no named release before it shows the date (another day's name is never "
       "borrowed)", (lone, installer_lone), ("2026.11.20", "2026.11.20"))


def _main267():
    sid = _p9_new_server(P9_HOST, "cod4p267", "cod4", 28960, name="p267-cod4")
    try:
        _sftp267()
        _addons267(sid)
        _uninstall267(sid)
        _db_addon_job267(sid)
    finally:
        _p9_delete_server(sid)
        _p9_restore_all()
    _bup_prune267()
    _gmod_remove267()
    _gcf_deep267()
    _wwr_lines267()
    _busy_pieces267()
    _release_names267()
    check("part267: no check reached a real transport", len(_P9_TRIPPED) == _trips267,
          repr(_P9_TRIPPED[_trips267:][:4]))


try:
    _main267()
finally:
    import shutil as _shutil267
    _shutil267.rmtree(_TMP267, ignore_errors=True)
