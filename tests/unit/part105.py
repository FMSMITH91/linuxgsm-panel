"""Part 105 of the unit suite: the seventeenth review's ssh_manager and route fixes (review 1016f, builder B).

* Backups: an orphaned backup.lock is swept BEFORE the headroom prune, so a lock the sweep removes
  no longer stops the prune (a tight disk then refused the backup for space, for up to an hour);
  a fresh lock still does (#439).
* GMod content: a content scan that did not answer is not "no content here". Remove refuses
  instead of unmounting the game and reporting "Removed from host: (none)"; the card says it could
  not read the host instead of showing every game as not on it; a server-only admin's mount is
  refused as unread, not as "not on this host yet"; no content account is prepared on top of an
  unread scan; the remote scan exits 0 when it ran.
* Downloads: a file whose size stat could not read is no answer, not an empty 200 file.
* Users: every live invite is listed with its Revoke button (the 26th had none for up to 30 days), and
  minting stops at Invite.MAX_LIVE live ones so that list stays bounded (integrator).

HOW IT RUNS. Stand-ins behind ssh_manager's _core and cron, and routes on part12's app with
recorders; the remote scan is run in bash over this part's own stand-in `id`/`runuser` and home.
Nothing reaches a host, sudo or the checkout's data/.
"""
import os
import shutil as _shutil105
import subprocess as _sp105  # nosec B404 - runs bash on this part's own rendered verb
import tempfile as _tf105
from datetime import timedelta as _td105
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part12 import (_P9_TRIPPED, _P9Thread, _p9, _p9_arm, _p9_client, _p9_core, _p9_drain, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_sf, _p9_threading)
from unit.part71 import _card71
from panel.core.clock import utcnow as _now105
from panel.db.models import AuditLog, GameServer, Invite, RemoteServer, User, db
from panel.ops.ssh_manager import cron as _cron105, files as _files105, game as _game105, gmod as _gmod105
from panel.security import auth as _auth105
from panel.security import privileged as _priv105

_TRIP105_START = len(_P9_TRIPPED)
_mine105 = {"hosts": [], "servers": [], "users": [], "invites": []}


def _setup105():
    with _p9.app_context():
        host = RemoteServer(name="p105-host", host="p105.example.invalid", port=22, username="admin",
                            auth_method="key", auth_credential="", is_online=True)
        admin = User(username="p105_admin", password_hash=_auth105.hash_password("Str0ng!passw0rd-p105"),
                     display_name="p105 admin", is_superadmin=True, is_active=True)
        db.session.add_all([host, admin])
        db.session.commit()
        _mine105["hosts"].append(host.id)
        _mine105["users"].append(admin.id)
        return host.id, admin.id


def _new_server105(rid, short, game_type, **kw):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name=kw.pop("name", short), short_name=short, game_type=game_type,
                        port=kw.pop("port", 27105), installed=True, status="offline", **kw)
        db.session.add(gs)
        db.session.commit()
        _mine105["servers"].append(gs.id)
        return gs.id


def _cleanup105():
    with _p9.app_context():
        if _mine105["invites"]:
            Invite.query.filter(Invite.id.in_(_mine105["invites"])).delete(synchronize_session=False)
        for i in _mine105["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
            _p9_sf._gmod_content_apply_state.pop(i, None)
        for i in _mine105["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p105%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine105[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
        db.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. An orphaned backup.lock is swept before the headroom prune
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _backup105(lock):
    """run_game_backup on a tight disk with `lock` ("orphaned", "fresh" or None) on the host.

    -> (archives deleted, the answer's message, whether LinuxGSM's backup was started).
    """
    host = {"lock": lock, "free": 50,
            "backups": [{"name": "b%d.tar.zst" % i, "size": 100} for i in range(4)]}   # newest first
    gone, ran = [], []

    def _list(server, user, locks=None):
        if locks is not None and host["lock"]:
            locks.append(0)
        return [dict(b) for b in host["backups"]]

    def _delete(server, user, name):
        host["backups"] = [b for b in host["backups"] if b["name"] != name]
        host["free"] += 100
        gone.append(name)
        return True

    def _as_user(server, user, sh, timeout=30, **k):
        # The sweep, as the host runs it: no tar as the account, so a lock past 5 minutes goes.
        if _game105._stale_backup_lock_sweep(user) in sh and host["lock"] == "orphaned":
            host["lock"] = None
        return "", "", 0
    _p9_patch(_cron105, "list_game_backups", _list)
    _p9_patch(_cron105, "backup_disk_info", lambda server, user: {"free": host["free"], "total": 10 ** 9})
    _p9_patch(_cron105, "delete_game_backup", _delete)
    _p9_patch(_p9_core, "shell_as_game_user", _as_user)
    _p9_patch(_p9_core, "run_as_game_user", lambda *a, **k: ran.append(a[2]) or ("", "backup failed", 1))
    _p9_patch(_game105, "_bkpart_listing", lambda server, user: [])
    _p9_patch(_game105, "_bkpart_cleanup", lambda *a, **k: "")
    _ok, msg, _skipped = _game105.run_game_backup(NS(id=-10501), "p105u", "p105srv", keep=2, force=True)
    return gone, str(msg), bool(ran)


def _orphan_lock105():
    orphan, fresh, none = _backup105("orphaned"), _backup105("fresh"), _backup105(None)
    check("backup headroom: an ORPHANED backup.lock (past 5 minutes, no tar running) no longer stops the "
          "prune — the stale-lock sweep runs first, so the oldest backup is pruned and LinuxGSM's backup "
          "starts (it skipped the prune, then refused the backup for disk space, 'lower keep', for up to "
          "an hour)",
          orphan[0] == ["b3.tar.zst"] and orphan[2] and "Not enough disk space" not in orphan[1], repr(orphan))
    check("backup headroom: ...a FRESH lock the sweep keeps still stops the prune (#439: another backup "
          "is running), and with no lock the prune runs as before (controls)",
          fresh[0] == [] and not fresh[2] and "Not enough disk space" in fresh[1]
          and none[0] == ["b3.tar.zst"] and none[2], repr((fresh, none)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. GMod content: a content scan that did not answer is not "no content here"
# ════════════════════════════════════════════════════════════════════════════════════════════════
# content: user -> games; scan: "ok", "empty-rc" (a transport that answers ("", …, -1)), "raise"
# (paramiko), or "second" (the first scan answers, the next does not).
_HOST105 = {"content": {}, "scan": "ok", "scans": 0, "calls": [], "mounts": "", "written": None}


def _scan105(args):
    _HOST105["scans"] += 1
    mode = _HOST105["scan"]
    if mode == "raise":
        raise OSError("p105: the session dropped")
    if mode == "empty-rc" or (mode == "second" and _HOST105["scans"] > 1):
        return "", "", -1
    return "".join("HIT|%s|%s\n" % (u, g) for u, gs in _HOST105["content"].items()
                   for g in sorted(gs) if g in args), "", 0


def _remove105(args):
    _HOST105["content"].get(args[0], set()).discard(args[1])
    return "", "", 0


# The privileged verbs the content code runs, answered from _HOST105; any other answers ("", "", 0).
_VERBS105 = {
    "content-scan": _scan105,
    "content-game-remove": _remove105,
    "content-game-present": lambda args: ("", "", 0 if args[1] in _HOST105["content"].get(args[0], ()) else 1),
    "gmod-mount-read": lambda args: (_HOST105["mounts"], "", 0),
    "crontab-list": lambda args: ("", "no crontab for %s" % args[0], 1),
}


def _gmod_host105():
    calls = _HOST105["calls"]

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        args = list(args)
        calls.append((verb, tuple(args)))
        answer = _VERBS105.get(verb)
        return answer(args) if answer else ("", "", 0)

    def _cmd(server, cmd, timeout=30, sudo=None, stdin_text=None):
        calls.append(("cmd", cmd[:40]))
        if cmd.startswith("id -gn "):
            return cmd.split()[2].strip("'") + "\n", "", 0
        return "Y\n", "", 0

    def _as_user(server, user, sh, timeout=30, selfname=None, scope=False):
        if "linuxgsm.sh" in sh:
            calls.append(("install-as", user))
            return "", "", 0
        if "mount.cfg" in sh:
            calls.append(("mount-write", user))
            _HOST105["written"] = sh
            return "__OK__\n", "", 0
        return "NO_SESSION\n", "", 3

    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", _cmd)
    _p9_patch(_p9_core, "shell_as_game_user", _as_user)
    _p9_patch(_p9_core, "write_content_cron",
              lambda server, user, body, timeout=15: calls.append(("write-content-cron", user)) or ("", "", 0))
    _p9_patch(_p9_core, "create_game_user",
              lambda server, user, timeout=30: calls.append(("create-user", user)) or ("", "", 0))
    _p9_patch(_p9_sf, "threading", _p9_threading(_P9Thread))
    _p9_patch(_p9_sf, "path_disk_free", lambda remote, path: (50 * 2 ** 30, 100 * 2 ** 30))


def _gmod_job105(client, gid, rid, action, games, content, scan):
    """One content-card job: (job state, the host writes it made)."""
    _HOST105.update(content=content, scan=scan, scans=0, written=None,
                    mounts='"mountcfg"\n{\n\t"cstrike"\t"/home/p105box/serverfiles/cstrike"\n}\n')
    del _HOST105["calls"][:]
    _p9_sf._release_gmod_content_host(rid)
    _p9_sf._gmod_content_apply_state.pop(gid, None)
    client.post("/api/server/%d/gmod-content" % gid, json={"action": action, "games": games})
    _p9_drain()
    st = dict(_p9_sf._gmod_job_state(gid) or {})
    writes = [c for c in _HOST105["calls"]
              if c[0] in ("content-game-remove", "mount-write", "install-as", "create-user", "write-content-cron")]
    return st, writes


def _gmod_remove105(client, gid, rid):
    got = {mode: _gmod_job105(client, gid, rid, "uninstall", ["cstrike"], {"p105box": {"cstrike"}}, mode)
           for mode in ("empty-rc", "raise")}
    # The content is in the panel CS:S server's account only: the first scan (servers skipped) finds
    # nobody, and the second (servers_too, to name that server in the refusal) does not answer.
    got["owner scan"] = _gmod_job105(client, gid, rid, "uninstall", ["cstrike"], {"p105css": {"cstrike"}},
                                     "second")
    check("GMod content removal: a content scan that did not answer (a transport returning ('', …, -1), "
          "or one raising) is not read as 'no content here' — Remove refuses, saying the host did not "
          "answer, and unmounts nothing (it rewrote mount.cfg without the game and reported 'Removed "
          "from host: (none)' with 13 GB still on disk)",
          all(st.get("status") == "error" and "Couldn't read what content is on this host" in str(st.get("msg"))
              and w == [] for st, w in got.values()), repr(got))
    done, d_writes = _gmod_job105(client, gid, rid, "uninstall", ["cstrike"], {"p105box": {"cstrike"}}, "ok")
    check("GMod content removal: ...a scan that answered still removes and unmounts as before (control)",
          done.get("status") == "done" and ("content-game-remove", ("p105box", "cstrike", "cssserver")) in d_writes
          and ("mount-write", "p105gm") in d_writes, repr((done, d_writes)))
    with _p9.app_context():
        db.session.get(User, _mine105["users"][0]).language = "es"
        db.session.commit()
    try:
        _gmod_job105(client, gid, rid, "uninstall", ["cstrike"], {"p105box": {"cstrike"}}, "empty-rc")
        card = _p9_json(client.get("/api/server/%d/gmod-content" % gid))
    finally:
        with _p9.app_context():
            db.session.get(User, _mine105["users"][0]).language = "en"
            db.session.commit()
    check("GMod content removal: ...and an es viewer reads that refusal in Spanish on the card",
          (card.get("job") or {}).get("msg", "").startswith("No se pudo leer qué contenido hay en este host"),
          repr(card.get("job")))


def _gmod_status105(client, gid, rid):
    _HOST105.update(content={"p105box": {"cstrike"}}, mounts="")
    cards = {}
    for mode in ("empty-rc", "ok"):
        _HOST105.update(scan=mode, scans=0)
        _p9_sf._gmod_content_apply_state.pop(gid, None)
        cards[mode] = _p9_json(client.get("/api/server/%d/gmod-content" % gid))
    check("GMod content card: the status answer says when the content scan was not read "
          "(content_readable false), where it painted every game 'not on the host'; a read scan says "
          "true and shows CS:S present (control)",
          cards["empty-rc"].get("content_readable") is False and cards["ok"].get("content_readable") is True
          and any(g.get("key") == "cstrike" and g.get("present") for g in cards["ok"].get("games", [])),
          repr(cards))
    _gmod_card105()


def _gmod_card105():
    games = [{"key": "cstrike", "label": "Counter-Strike: Source", "size": "13 GB", "present": False,
              "mounted": False, "downloadable": True}]
    base = {"games": games, "mounted": [], "mounts_readable": True, "disk_free": 50 * 2 ** 30,
            "disk_total": 100 * 2 ** 30, "job": None}
    unread, read = _card71(dict(base, content_readable=False)), _card71(dict(base, content_readable=True))
    if unread is None or read is None:
        skip("GMod content card: an unread content scan is said, not drawn as 'installs 13 GB'",
             "node is not installed here")
        return
    u_html, r_html = unread.get("html", ""), read.get("html", "")
    check("GMod content card: ...and the card says it could not read the host's content, drawing no game "
          "list and no Apply (it read 'installs 13 GB' for content on the disk); a read scan draws the "
          "list (control)",
          all(("Couldn't read what content is on this host" in u_html, 'id="gmc-apply"' not in u_html,
               "installs" not in u_html, 'id="gmc-apply"' in r_html)), repr((unread, r_html[:200])))


def _refusal105(gs, host, content, scan):
    """The server-only admin's mount refusal on `content` and `scan`: (status, message) or None."""
    _HOST105.update(content=content, scan=scan, scans=0)
    r = _p9_sf._sf_gmod_host_refusal(gs, host, "mount", ["cstrike"])
    return (r[1], (r[0].get_json() or {}).get("message")) if r else None


def _said105(got, status, text):
    """Whether a refusal from _refusal105 is `status` and its message holds `text`."""
    return got is not None and got[0] == status and text in (got[1] or "")


def _gmod_gate105(rid):
    """The server-only admin's mount gate, and ensure_content_user, on an unread scan."""
    gs = NS(remote_id=rid, name="p105 GMod")
    _p9_patch(_p9_sf, "current_user", NS(is_superadmin=False))
    _p9_patch(_p9_sf, "can_access_remote", lambda user, remote_id: False)
    with _p9.test_request_context("/"), _p9.app_context():
        host = db.session.get(RemoteServer, rid)
        got = {"unread": _refusal105(gs, host, {"p105box": {"tf"}}, "empty-rc"),
               "read": _refusal105(gs, host, {"p105box": {"tf"}}, "ok"),
               # The content is on the host, but only in the panel CS:S server's own account.
               "server held": _refusal105(gs, host, {"p105css": {"cstrike"}}, "ok")}
        _HOST105.update(content={"p105box": {"cstrike"}}, scan="empty-rc", scans=0)
        del _HOST105["calls"][:]
        cu = _gmod105.ensure_content_user(host)
        prepared = [c for c in _HOST105["calls"] if c[0] in ("create-user", "content-dir-create")]
    check("GMod content: a server-only admin's mount on a host whose scan did not answer is refused as "
          "unread — not 'Not on this host yet: Counter-Strike: Source' (it may well be); a read scan "
          "missing the game still says so (control)",
          _said105(got["unread"], 403, "Couldn't read what content is on this host")
          and _said105(got["read"], 403, "Not on this host yet"), repr(got))
    check("GMod content: ...and content held only in a panel server's own account is refused saying so, "
          "not as 'Not on this host yet' (it is on the host; the panel never mounts from a server's account)",
          _said105(got["server held"], 403,
                   "Only a panel server's own account on this host holds Counter-Strike: Source"),
          repr(got.get("server held")))
    check("GMod content: ensure_content_user prepares no content account on top of an unread scan "
          "(it set up the panel's own and downloaded beside content another account holds)",
          cu is None and prepared == [], repr((cu, prepared)))


def _remote_scan105():
    """The remote content-scan, run in bash: its exit status when it ran."""
    root = os.path.realpath(_tf105.mkdtemp(prefix="lgsm-unit-p105-"))
    try:
        bindir, home = os.path.join(root, "bin"), os.path.join(root, "home")
        os.makedirs(os.path.join(home, "gm", "serverfiles"))      # an account holding no content
        for name, body in (("id", "echo 1000\n"), ("runuser", 'shift 3; exec "$@"\n')):
            path = os.path.join(bindir, name)
            os.makedirs(bindir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/bash\n" + body)
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in tool this part runs
            os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in this part's own temp dir
        sh = _priv105.remote_command("content-scan", ["cstrike"]).replace(_priv105.HOME_ROOT, home)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
        p = _sp105.run(["bash", "-c", sh], env=env, capture_output=True, text=True,  # nosec B603 B607 - bash on the rendered verb
                       timeout=30, check=False)
        os.makedirs(os.path.join(home, "gm", "serverfiles", "cstrike"))
        hit = _sp105.run(["bash", "-c", sh], env=env, capture_output=True, text=True,  # nosec B603 B607 - bash on the rendered verb
                         timeout=30, check=False)
    finally:
        _shutil105.rmtree(root, ignore_errors=True)
    check("remote content-scan: a scan that ran exits 0 even when its last account holds no content (it "
          "exited with that last `test`'s 1, which the panel now reads as a scan that did not run); a hit "
          "is still printed (control)",
          (p.returncode, p.stdout, hit.returncode, hit.stdout.strip()) == (0, "", 0, "HIT|gm|cstrike"),
          repr((p.returncode, p.stdout, p.stderr[-200:], hit.returncode, hit.stdout)))


def _gmod_all105(client, rid):
    gid = _new_server105(rid, "p105gm", "gmod", name="p105 GMod")
    _new_server105(rid, "p105css", "css", name="p105 CSS")
    _gmod_host105()
    _gmod_remove105(client, gid, rid)
    _gmod_status105(client, gid, rid)
    _gmod_gate105(rid)
    _remote_scan105()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2b. A download whose size stat could not read is no answer, not an empty file
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _stat105(client, rid):
    gid = _new_server105(rid, "p105dl", "css", name="p105 DL")
    answers = {}
    for tag, out in (("no size", "f\n"), ("sized", "f 4096\n"), ("dir", "d 0\n")):
        _p9_patch(_p9_core, "shell_as_game_user", lambda server, user, sh, timeout=30, _o=out, **k: (_o, "", 0))
        answers[tag] = _files105.stat_path(NS(id=-10502), "p105dl", "cfg/server.cfg")
    _p9_patch(_p9_core, "shell_as_game_user", lambda server, user, sh, timeout=30, **k: ("f\n", "", 0))
    _p9_patch(_p9_sf, "stream_path", lambda *a, **k: iter([b""]))
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)   # as part62 drives it
    resp = client.get("/server/%d/download?path=cfg/server.cfg" % gid)
    # ...and the same route with a size the stat did read serves the file, so the 302 above is that
    # refusal and not any other (review 1017a: the part kept no route-level control).
    _p9_patch(_p9_core, "shell_as_game_user", lambda server, user, sh, timeout=30, **k: ("f 4\n", "", 0))
    _p9_patch(_p9_sf, "stream_path", lambda *a, **k: iter([b"abcd"]))
    _p9_patch(_p9_sf, "log_action", lambda *a, **k: None)   # this part's viewer is a stand-in with no id
    resp_ok = client.get("/server/%d/download?path=cfg/server.cfg" % gid)
    check("file download: a file whose size stat could not read is no answer (the route redirects back "
          "saying the host did not return it), never a 200 with an EMPTY file under the real name; a "
          "sized file and a folder still answer (controls)",
          answers["no size"] is None and resp.status_code == 302
          and resp_ok.status_code == 200 and resp_ok.get_data() == b"abcd"
          and (answers["sized"] or {}).get("size") == 4096 and (answers["dir"] or {}).get("type") == "d",
          repr((answers, resp.status_code, resp_ok.status_code)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Every live invite has its Revoke button
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _invites105(client, admin_id):
    with _p9.app_context():
        admin = db.session.get(User, admin_id)
        for n in range(30):
            inv, _tok = Invite.mint(admin, hours=720, note="p105-live-%02d" % n)
            inv.created_at = _now105() - _td105(minutes=60 - n)    # p105-live-00 is the oldest
            db.session.add(inv)
            db.session.flush()
            _mine105["invites"].append(inv.id)
        db.session.commit()
    page = client.get("/users").get_data(as_text=True)
    missing = [i for i in _mine105["invites"] if ("/users/invite/%d/revoke" % i) not in page]
    check("invite list: every live invite is listed with its Revoke button — 30 of them, the oldest "
          "included (the list stopped at the 25 newest, and the 26th could not be revoked for up to "
          "30 days)", missing == [] and "p105-live-00" in page, repr(missing))
    _mint_bound105(client, admin_id)


def _live105():
    with _p9.app_context():
        return Invite.query.filter(Invite.used_at.is_(None), Invite.revoked_at.is_(None),
                                   Invite.expires_at > _now105()).count()


def _mint_bound105(client, admin_id):
    """Integrator, review 1016f: with every live invite listed, the number of live ones bounds the page.

    Nothing did: minting has no rate limit and a link lives up to 30 days. At Invite.MAX_LIVE a mint
    is refused (409, nothing minted); one revoked, the next mint works.
    """
    with _p9.app_context():
        admin = db.session.get(User, admin_id)
        for n in range(max(0, 100 - _live105())):
            inv, _tok = Invite.mint(admin, hours=720, note="p105-fill-%03d" % n)
            db.session.add(inv)
            db.session.flush()
            _mine105["invites"].append(inv.id)
        db.session.commit()
    at = _live105()
    hdr = {"X-Requested-With": "XMLHttpRequest"}
    r = client.post("/users/invite", data={"hours": "1", "note": "p105-mint-over"}, headers=hdr)
    refused = (r.status_code, _p9_json(r), _live105())
    with _p9.app_context():
        one = db.session.get(Invite, _mine105["invites"][-1])
        one.revoked_at = _now105()
        db.session.commit()
    r = client.post("/users/invite", data={"hours": "1", "note": "p105-mint-after"}, headers=hdr)
    after = (r.status_code, (_p9_json(r) or {}).get("success"), _live105())
    with _p9.app_context():
        _mine105["invites"] += [i.id for i in Invite.query.filter(Invite.note.like("p105-mint-%")).all()]
    _mint_checks105(at, refused, after)


def _mint_checks105(at, refused, after):
    """_mint_bound105's two checks, on what it saw."""
    check("invite mint: with 100 links that still work, another is refused (409, nothing minted, the "
          "message says why) — so the Users page, which lists every live one, stays bounded",
          at == 100 and refused[0] == 409 and (refused[1] or {}).get("success") is False
          and "100" in ((refused[1] or {}).get("message") or "") and refused[2] == 100,
          repr((at, refused)))
    check("invite mint: ...and once one is revoked, the next mint works (control)",
          after == (200, True, 100), repr(after))


try:
    _p9_arm(who="part105")
    _HOSTID105, _ADMIN105 = _setup105()
    _A105 = _p9_client(_ADMIN105)
    _orphan_lock105()
    _gmod_all105(_A105, _HOSTID105)
    _stat105(_A105, _HOSTID105)
    _invites105(_A105, _ADMIN105)
finally:
    _p9_restore_all()
    _cleanup105()

check("part105: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP105_START, repr(_P9_TRIPPED[_TRIP105_START:][:6]))
