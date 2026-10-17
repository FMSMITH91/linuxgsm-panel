"""Part 102 of the unit suite: the sixteenth review's ssh_manager and route fixes (review 1016e, builder B).

* GMod content: a panel-managed server's own account is never the content user: not installed
  into, removed from, given an update cron (Remove deleted a CS:S server's game files, script and
  config) or even mounted from (the read grant joins its group, which reads its configs); the
  panel's own content account is used instead.
* The backup headroom prune does not run while another backup is being written.
* An SSH move back onto a socket-activated host's ignored `sshd -T` port opens it in UFW.
* ssh-status gives sshd's real ports for every host; a move's audit row names sshd's old ports.
* A retry that created the account forgets the kept "found an account" record at once.
* Public SSH "off" / Close port 22 refuse a host the panel itself reaches on public port 22.
* Editing a scheduled task re-syncs the Autostart / Daily-restart switches.

HOW IT RUNS. Stand-ins behind ssh_manager's _core (run_privileged, run_command, shell_as_game_user,
write_content_cron), and routes on part12's app with recorders. Nothing reaches a host, sudo or
the checkout's data/.
"""
import base64 as _b64_102
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _P9Thread, _p9, _p9_arm, _p9_client, _p9_core, _p9_drain, _p9_json,
                         _p9_ms, _p9_patch, _p9_restore_all, _p9_sf, _p9_state, _p9_threading)
from panel.core import i18n as _i18n102
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import cron as _cron102, gmod as _gmod102, hosts as _hosts102
from panel.routes import api as _api102, close_port22 as _cp102, remote_vps as _rv102
from panel.security import auth as _auth102

_TRIP102_START = len(_P9_TRIPPED)
_LIST_BACKUPS102 = _cron102.list_game_backups
_mine102 = {"hosts": [], "servers": [], "users": []}


def _setup102():
    with _p9.app_context():
        host = RemoteServer(name="p102-host", host="p102.example.invalid", port=22, username="admin",
                            auth_method="key", auth_credential="", is_online=True)
        ts = RemoteServer(name="p102-ts", host="p102-ts.example.invalid", port=22, username="admin",
                          auth_method="tailscale", auth_credential="", is_online=True)
        admin = User(username="p102_admin", password_hash=_auth102.hash_password("Str0ng!passw0rd-p102"),
                     display_name="p102 admin", is_superadmin=True, is_active=True)
        db.session.add_all([host, ts, admin])
        db.session.commit()
        _mine102["hosts"] += [host.id, ts.id]
        _mine102["users"].append(admin.id)
        local = RemoteServer.query.filter_by(is_local=True).first()
        if local is None:
            local = RemoteServer(name="p102-local", host="localhost", port=22, username="local",
                                 auth_method="local", auth_credential="", is_online=True, is_local=True)
            db.session.add(local)
            db.session.commit()
            _mine102["hosts"].append(local.id)
        return host.id, ts.id, local.id, admin.id


def _new_server102(rid, short, game_type, **kw):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name=kw.pop("name", short), short_name=short, game_type=game_type,
                        port=kw.pop("port", 27102), installed=kw.pop("installed", True),
                        status=kw.pop("status", "offline"), **kw)
        db.session.add(gs)
        db.session.commit()
        _mine102["servers"].append(gs.id)
        return gs.id


def _cleanup102():
    with _p9.app_context():
        for i in _mine102["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
            _p9_sf._gmod_content_apply_state.pop(i, None)
        for i in _mine102["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p102%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine102[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
        db.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. GMod content never writes under a panel-managed server's account
# ════════════════════════════════════════════════════════════════════════════════════════════════
# What the host holds: user -> content games present in its ~/serverfiles.
_HOST102 = {"content": {}, "calls": [], "mounts": "", "written": None}

# What counts as writing under an account: removing its games, installing into it (a LinuxGSM run
# as it), its update cron.
_WRITES102 = ("content-game-remove", "content-cron-remove", "write-content-cron", "install-as")


def _gmod_host102():
    """Stand-ins for every host call the content code makes, recording each."""
    calls = _HOST102["calls"]

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        args = list(args)
        calls.append((verb, tuple(args)))
        if verb == "content-scan":
            return "".join("HIT|%s|%s\n" % (u, g) for u, gs in _HOST102["content"].items() for g in sorted(gs)
                           if g in args), "", 0
        if verb == "content-game-remove":
            _HOST102["content"].get(args[0], set()).discard(args[1])
        if verb == "content-game-present":
            return "", "", 0 if args[1] in _HOST102["content"].get(args[0], ()) else 1
        if verb == "gmod-mount-read":
            return _HOST102["mounts"], "", 0
        if verb == "crontab-list":
            return "", "no crontab for %s" % args[0], 1
        return "", "", 0

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
            _HOST102["written"] = _b64_102.b64decode(sh.split("echo ", 2)[1].split()[0]).decode()
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


def _gmod_job102(client, gid, rid, action, games, content):
    """Run one content-card job against `content`: (job state, writes, every recorded call)."""
    _HOST102["content"] = content
    del _HOST102["calls"][:]
    _p9_sf._release_gmod_content_host(rid)
    _p9_sf._gmod_content_apply_state.pop(gid, None)
    client.post("/api/server/%d/gmod-content" % gid, json={"action": action, "games": games})
    _p9_drain()
    st = dict(_p9_sf._gmod_job_state(gid) or {})
    calls = list(_HOST102["calls"])
    writes = [c for c in calls if c[0] in _WRITES102]
    return st, writes, calls


def _gmod_owner102(client, rid):
    gid = _new_server102(rid, "p102gm", "gmod", name="p102 GMod")
    _new_server102(rid, "p102css", "css", name="p102 CSS")
    _gmod_host102()
    _gmod_remove102(client, gid, rid)
    _gmod_apply102(client, gid, rid)
    _gmod_step102(rid)
    _gmod_mounted102(client, gid, rid)
    _gmod_named102(rid)
    _gmod_es102(client, gid, rid)
    _gmod_mixed102(client, gid, rid)


def _says102(state, *parts):
    """Whether a job state's message holds every one of `parts`."""
    return all(p in str(state.get("msg")) for p in parts)


def _removes102(writes):
    """The content-game-remove calls among recorded writes, by their arguments."""
    return [w[1] for w in writes if w[0] == "content-game-remove"]


def _gmod_remove102(client, gid, rid):
    refused, r_writes, r_calls = _gmod_job102(client, gid, rid, "uninstall", ["cstrike"],
                                              {"p102css": {"cstrike"}})
    box, b_writes, _b = _gmod_job102(client, gid, rid, "uninstall", ["cstrike"], {"p102box": {"cstrike"}})
    both, both_writes, _c = _gmod_job102(client, gid, rid, "uninstall", ["cstrike"],
                                         {"p102css": {"cstrike", "tf"}, "p102box": {"cstrike"}})
    check("GMod content removal: when the only content on the host is in a panel server's own account "
          "(a managed CS:S server's `p102css`), Remove deletes nothing there, writes no cron and leaves "
          "the GMod server's mounts alone, and the refusal names the server it protected (it ran "
          "content-game-remove on that server's game files, script and config)",
          (refused.get("status"), _says102(refused, "p102 CSS", "Nothing was removed"), r_writes,
           [c for c in r_calls if c[0] in ("gmod-mount-read", "content-grant-read", "mount-write")])
          == ("error", True, [], []), repr((refused, r_writes, r_calls)))
    check("GMod content removal: ...a content box that is no panel server's is removed from as before, "
          "and is preferred over a server's account holding MORE content (controls)",
          (box.get("status"), both.get("status"), _removes102(b_writes), _removes102(both_writes))
          == ("done", "done", [("p102box", "cstrike", "cssserver")], [("p102box", "cstrike", "cssserver")])
          and not any("p102css" in str(w) for w in both_writes),
          repr((box, b_writes, both, both_writes)))


def _gmod_mixed102(client, gid, rid):
    # A host set up before a server's account was refused: GMod mounts CS:S from the panel CS:S
    # server's account, while the panel's `gmodcontent` holds TF2. Removing TF2 must leave the CS:S
    # line as it stood (it re-pointed it at /home/gmodcontent, where there is no CS:S).
    got = {}
    for k, content, cs_from in (("mixed", {"p102css": {"cstrike"}, "gmodcontent": {"tf"}}, "p102css"),
                                ("all held", {"gmodcontent": {"tf", "cstrike"}}, "gmodcontent")):
        _HOST102["mounts"] = ('"mountcfg"\n{\n\t"cstrike"\t"/home/%s/serverfiles/cstrike"\n'
                              '\t"tf"\t"/home/gmodcontent/serverfiles/tf"\n}\n' % cs_from)
        _HOST102["written"] = None
        st, writes, calls = _gmod_job102(client, gid, rid, "uninstall", ["tf"], content)
        got[k] = (st.get("status"), str(st.get("msg")), _removes102(writes), _HOST102["written"],
                  [c[1] for c in calls if c[0] == "content-grant-read"])
    _HOST102["mounts"] = ""
    mixed, held = got["mixed"], got["all held"]
    m_cfg, h_cfg = mixed[3] or "", held[3] or ""
    check("GMod content removal: on a host whose GMod server mounts CS:S from a panel server's account "
          "while `gmodcontent` holds TF2, removing TF2 keeps the CS:S mount line as it stood and grants "
          "nothing for it (it rewrote it to /home/gmodcontent/serverfiles/cstrike, where there is no "
          "CS:S, and reported success: adversarial F2); the TF2 line goes",
          all([mixed[:3] == ("done", "Removed from host: tf", [("gmodcontent", "tf", "tf2server")]),
               '"cstrike"\t"/home/p102css/serverfiles/cstrike"' in m_cfg,
               "gmodcontent/serverfiles/cstrike" not in m_cfg, '"tf"' not in m_cfg, mixed[4] == []]),
          repr(mixed))
    check("GMod content removal: ...when the content account holds every remaining game, they are mounted "
          "from it and read granted as before (control)",
          all([held[0] == "done", '"cstrike"\t"/home/gmodcontent/serverfiles/cstrike"' in h_cfg,
               '"tf"' not in h_cfg, [a[3:] for a in held[4]] == [("cstrike",)]]), repr(held))


def _no_server_account102(calls):
    """Whether no recorded host call names the managed CS:S server's account at all."""
    return not any("p102css" in repr(c) for c in calls)


def _gmod_apply102(client, gid, rid):
    applied, a_writes, a_calls = _gmod_job102(client, gid, rid, "mount", ["cstrike", "tf"],
                                              {"p102css": {"cstrike"}})
    check("GMod content apply: content found only in a panel server's account is not used, not even "
          "mounted read-only (the read grant joins the GMod account to that server's group, which reads "
          "its configs, RCON password included): the games go into the panel's own content account",
          ("install-as", "gmodcontent") in a_writes and _no_server_account102(a_calls),
          repr((applied, a_writes, a_calls)))
    installed, i_writes, _i = _gmod_job102(client, gid, rid, "mount", ["cstrike", "tf"],
                                           {"p102box": {"cstrike"}})
    check("GMod content apply: ...a content box that is no panel server's still gets the missing game "
          "installed into it and its update cron written (control)",
          ("install-as", "p102box") in i_writes and ("write-content-cron", "p102box") in i_writes,
          repr((installed, i_writes)))


def _gmod_step102(rid):
    # The install job's own content step (a new GMod server with content picked).
    _HOST102["content"] = {"p102css": {"cstrike"}}
    del _HOST102["calls"][:]
    with _p9.app_context():
        _p9_ms._r12b_gmod_content_step(db.session.get(RemoteServer, rid), "p102gm", ["cstrike", "tf"],
                                       lambda *a, **k: None)
    calls = list(_HOST102["calls"])
    check("GMod install step: a new GMod server's content step neither installs into, writes a cron "
          "for nor mounts from a panel server's account; it uses the panel's own content account",
          ("install-as", "gmodcontent") in calls and _no_server_account102(calls), repr(calls))


def _gmod_mounted102(client, gid, rid):
    # A host set up before the rule: this GMod server's mount.cfg already points into the CS:S
    # server's account. The card shows it mounted but not on the host (the panel's content is
    # elsewhere), and Remove refuses and names the server (part of _gmod_remove102).
    _HOST102["content"] = {"p102css": {"cstrike"}}
    _HOST102["mounts"] = '"mountcfg"\n{\n\t"cstrike"\t"/home/p102css/serverfiles/cstrike"\n}\n'
    try:
        _p9_sf._gmod_content_apply_state.pop(gid, None)
        card = _p9_json(client.get("/api/server/%d/gmod-content" % gid))
    finally:
        _HOST102["mounts"] = ""
    cs = [g for g in card.get("games", []) if g.get("key") == "cstrike"]
    check("GMod content card: a mount that already points into a panel server's account shows as "
          "mounted but not on the host, so the card never offers that account's content as the panel's",
          cs and cs[0].get("mounted") is True and cs[0].get("present") is False, repr(card))


def _gmod_named102(rid):
    # A panel server running under the content account's own name: that account is not the panel's.
    sid = _new_server102(rid, "gmodcontent", "css", name="p102 named")
    _HOST102["content"] = {}
    del _HOST102["calls"][:]
    try:
        with _p9.app_context():
            cu = _gmod102.ensure_content_user(db.session.get(RemoteServer, rid))
    finally:
        with _p9.app_context():
            db.session.delete(db.session.get(GameServer, sid))
            db.session.commit()
        _mine102["servers"].remove(sid)
    check("GMod content: a panel server whose account is called `gmodcontent` is not taken as the "
          "panel's content account (no content storage instead)", cu is None, repr((cu, _HOST102["calls"])))


def _gmod_es102(client, gid, rid):
    with _p9.app_context():
        db.session.get(User, _mine102["users"][0]).language = "es"
        db.session.commit()
    try:
        _gmod_job102(client, gid, rid, "uninstall", ["cstrike"], {"p102css": {"cstrike"}})
        card = _p9_json(client.get("/api/server/%d/gmod-content" % gid))
    finally:
        with _p9.app_context():
            db.session.get(User, _mine102["users"][0]).language = "en"
            db.session.commit()
    check("GMod content removal: ...and an es viewer reads that refusal in Spanish on the card",
          (card.get("job") or {}).get("msg", "").startswith(
              "El contenido de este host está en la cuenta del servidor del panel p102 CSS"), repr(card))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The backup headroom prune waits for a backup that is still being written
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _headroom102(backups):
    gone = []
    _p9_patch(_cron102, "list_game_backups", lambda server, user, **k: [dict(b) for b in backups])
    _p9_patch(_cron102, "backup_disk_info", lambda server, user: {"free": 10, "total": 10 ** 9})
    _p9_patch(_cron102, "delete_game_backup", lambda server, user, name: gone.append(name) or True)
    note = _cron102._ensure_backup_headroom(NS(id=-10201), "p102u", 2)
    return gone, note


def _prune_running102():
    finished = [{"name": "b2.tar.zst", "size": 500, "created": 200},
                {"name": "b1.tar.zst", "size": 500, "created": 100}]
    running = {"name": "new.tar.zst", "size": 300, "created": 300, "in_progress": True}
    got = {"growing": _headroom102([running] + finished),
           "none running": _headroom102(finished)}
    _p9_patch(_cron102, "delete_game_backup", lambda server, user, name: got.setdefault("direct", []).append(name)
              or True)
    _cron102._prune_for_headroom(NS(id=-10202), "p102u", [running] + finished, 2, 0, 10 ** 9)
    check("backup headroom: while another backup's archive is still being written (past 0 bytes), the "
          "prune deletes nothing (it took a protected slot as the newest valid backup, and every "
          "finished one went); with none running the oldest goes as before (control); the archive "
          "being written is never counted as a kept backup",
          got["growing"] == ([], "") and got["none running"][0] == ["b1.tar.zst"]
          and got["direct"] == ["b1.tar.zst"], repr(got))
    _prune_locked102()


def _prune_locked102():
    # LinuxGSM's own order: take backup.lock, stop the server (a graceful stop, tens of seconds),
    # only then write the archive. In that window the lock exists and no archive is newer than it.
    # The real listing runs on a game-user shell stand-in; the disk is tight; four finished backups.
    sent = []

    def _listing(lock):
        def _as_user(server, user, sh, timeout=30, **k):
            sent.append(sh)
            out = "".join("F\tb%d.tar.zst\t500\t%d\n" % (i, 1000 + i) for i in range(4))
            return out + ("LOCK\t%s\n" % lock if lock else "") + _cron102._BACKUP_LIST_DONE + "\n", "", 0
        return _as_user
    gone = []
    _p9_patch(_cron102, "list_game_backups", _LIST_BACKUPS102)   # the real one: _headroom102 stubbed it
    _p9_patch(_cron102, "backup_disk_info", lambda server, user: {"free": 10, "total": 10 ** 9})
    _p9_patch(_cron102, "delete_game_backup", lambda server, user, name: gone.append(name) or True)
    got = {}
    for k, lock in (("lock, no archive yet", "2000.5"), ("lock time unreadable", "?"), ("no lock", None)):
        del gone[:]
        _p9_patch(_p9_core, "shell_as_game_user", _listing(lock))
        note = _cron102._ensure_backup_headroom(NS(id=-10204), "p102u", 2)
        got[k] = (list(gone), note)
    check("backup headroom: while LinuxGSM holds a fresh backup.lock and has not created its archive yet "
          "(it is still stopping the server), the prune deletes nothing (it removed finished backups, "
          "then failed on the lock: adversarial F3); with no lock it frees space as before (control)",
          got["lock, no archive yet"] == ([], "") and got["lock time unreadable"] == ([], "")
          and got["no lock"][0][:1] == ["b0.tar.zst"], repr(got))
    check("backup listing: a lock counts as stale exactly when LinuxGSM's fn_backup_check_lockfile says so "
          "(`find backup.lock -mmin +60`), so the listing reads every lock that test keeps",
          bool(sent) and all('-name "*backup.lock" ! -mmin +60 ' in sh for sh in sent), repr(sent[:1]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A move back onto a socket-activated host's ignored `sshd -T` port opens it
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TJ102 = "%-27s%-12s%s"
_DROPIN102, _CLOSED102 = [], []
_UFW_HEAD102 = ("Status: active\n\n     To                         Action      From\n"
                "     --                         ------      ----\n")


def _move102(socket_show, ufw_rules, new_port=22, stored=2222, **opt):
    """Move sshd to `new_port`; stops at sshd -t. -> (opened, free-port checked, refusal or None).

    An open adds its rule to `ufw_rules` (a later status read lists it) unless `opens` is False:
    ufw answered 0 and the rule is not there. The drop-in written is kept in _DROPIN102 and the ports
    closed again (the revert at the stop, or a refused open) in _CLOSED102. `opt`: socket_mode (True),
    auth ("key"), bind (""), opens (True), listening (`ss` showing 2222), local (False: the panel host).
    A bind address is one of the host's own (`ip -o addr show` lists it).
    """
    socket_mode, opens = opt.get("socket_mode", True), opt.get("opens", True)
    listening = opt.get("listening", "LISTEN 0 4096 0.0.0.0:2222 0.0.0.0:*\n")
    state = {"opened": [], "listed": 0}
    ufw_rules = list(ufw_rules)

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb == "sshd-socket-active":
            return ("active\n", "", 0) if socket_mode else ("inactive\n", "", 3)
        if verb == "sshd-effective-config":
            return "port 22\nport 2222\n" if not socket_mode else "port 22\n", "", 0
        if verb == "listening-sockets":
            state["listed"] += 1
            return listening, "", 0
        if verb == "ufw-status":
            return _UFW_HEAD102 + "".join("[%2d] %s\n" % (i + 1, r) for i, r in enumerate(ufw_rules)), "", 0
        if verb == "sshd-validate":
            return "", "p102 stops here", 1
        return "", "", 0

    def _cmd(server, cmd, **k):
        if "systemctl show ssh.socket" in cmd:
            return socket_show
        if "ip -o addr show" in cmd and opt.get("bind"):
            return "2: eth0    inet %s/24 brd + scope global eth0\n" % opt["bind"], "", 0
        return "", "p102: unexpected command", 1
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", _cmd)

    def _open(server, port, proto, comment=""):
        state["opened"].append(port)
        if opens:
            ufw_rules.append(_TJ102 % ("%s/tcp" % port, "ALLOW IN", "Anywhere"))
        return True, "opened"
    _DROPIN102[:] = []
    _CLOSED102[:] = []
    _p9_patch(_p9_core, "write_root_file", lambda server, target, body, **k: _DROPIN102.append(body) or ("", "", 0))
    _p9_patch(_hosts102, "_restart_ssh_listener", lambda *a, **k: None)
    _p9_patch(_hosts102, "remote_ufw_open_port", _open)
    _p9_patch(_hosts102, "remote_ufw_close_port",
              lambda server, port, proto=None, force=False: _CLOSED102.append(int(port)) or (True, ""))
    _ok, msg = _hosts102.change_ssh_port(NS(id=-10203, name="p102", host="p102.example.invalid", port=stored,
                                           is_local=opt.get("local", False), auth_method=opt.get("auth", "key")),
                                        new_port,
                                        opt.get("bind", ""))
    refused = (str(msg) if "blocked by the firewall rule" in str(msg) or "did not show port" in str(msg)
               else None)
    return state["opened"], state["listed"] > 0, refused


def _socket_move_back102():
    sock_2222 = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n", "", 0)
    sock_both = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=0.0.0.0:22 (Stream)\n", "", 0)
    allow_2222 = ["2222/tcp                   ALLOW IN    Anywhere"]
    got = {
        # sshd_config says 22, systemd serves 2222 only, and 22/tcp was closed after the first move.
        "socket 2222, 22 closed": _move102(sock_2222, allow_2222),
        "socket unread, 22 closed": _move102(("", "Failed to connect to bus", 1), allow_2222),
        "socket 2222, 22 denied": _move102(sock_2222, ["22/tcp                     DENY IN     Anywhere"]
                                           + allow_2222),
        # Ways in that must still count: a LIMIT already there, and a port systemd really serves.
        "socket 2222, 22 limited": _move102(sock_2222, ["22/tcp                     LIMIT IN    Anywhere"]
                                            + allow_2222),
        "socket serves 22": _move102(sock_both, allow_2222),
        "sshd_config serves 2222": _move102(("", "", 1), allow_2222, new_port=2222, stored=22, socket_mode=False),
    }
    check("ssh port: on a socket-activated host, a move back onto sshd_config's ignored port 22 (after "
          "22/tcp was closed) opens 22/tcp and checks it is free, also when ssh.socket cannot be read "
          "(it skipped both, and the route pointed the panel at a port UFW drops); a DENY for it now "
          "refuses the move",
          got["socket 2222, 22 closed"] == ([22], True, None)
          and got["socket unread, 22 closed"] == ([22], True, None)
          and got["socket 2222, 22 denied"][0] == [] and got["socket 2222, 22 denied"][2] is not None,
          repr(got))
    check("ssh port: ...a LIMIT for the port already lets it in (nothing added over it), and a port "
          "sshd really serves (ssh.socket's, or `sshd -T`'s without the socket) is neither opened "
          "again nor free-port checked (controls)",
          got["socket 2222, 22 limited"] == ([], True, None)
          and got["sshd_config serves 2222"] == ([], False, None), repr(got))
    check("ssh port: a move back onto a port ssh.socket still listens on, with no firewall rule letting it in, "
          "opens it and skips only the free-port check (review 1016e integration: listening said nothing "
          "about the firewall, and the move opened nothing)",
          got["socket serves 22"] == ([22], False, None), repr(got))


def _vps_sequence102():
    # The test VPS's exact sequence (24.04, ssh.socket on 22, sshd_config Port 22): the panel's own
    # 22 -> 2222 move, then the operator closes 22/tcp as the move advises, then the move back to 22.
    sock_22 = ("ActiveState=active\nListen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n", "", 0)
    first = _move102(sock_22, [_TJ102 % ("22/tcp", "ALLOW IN", "Anywhere")], new_port=2222, stored=22,
                     listening="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n")
    dropin = "".join(_DROPIN102)
    sock_after = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n"
                  "Listen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n", "", 0)
    back = _move102(sock_after, ["2222/tcp                   ALLOW IN    Anywhere"], new_port=22, stored=2222)
    check("ssh port: the panel's own 22 -> 2222 move keeps 22 in the ssh.socket drop-in, and after 22/tcp is "
          "closed the move back to 22 issues the allow for 22 (it opened nothing, and the route pointed the "
          "panel at a port UFW drops)",
          first[0] == [2222] and "0.0.0.0:22\n" in dropin and "0.0.0.0:2222\n" in dropin
          and back == ([22], False, None), repr((first, dropin, back)))


_SOCK_BOTH102 = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=0.0.0.0:22 (Stream)\n", "", 0)
_A2222_102 = _TJ102 % ("2222/tcp", "ALLOW IN", "Anywhere")


def _ufw_table102():
    # Both directions: rules that ARE a public way in to 22/tcp (nothing added) and rules that are not
    # (the allow goes in), on the move back to 22 with ssh.socket still serving it.
    sock_both, a2222 = _SOCK_BOTH102, _A2222_102
    way_in = {"allow": ("22/tcp", "ALLOW IN", "Anywhere"), "limit": ("22/tcp", "LIMIT IN", "Anywhere"),
              "bare 22": ("22", "ALLOW IN", "Anywhere"), "range": ("20:30/tcp", "ALLOW IN", "Anywhere")}
    not_in = {"on lo": ("22/tcp on lo", "ALLOW IN", "Anywhere"),
              "on docker0": ("22/tcp on docker0", "ALLOW IN", "Anywhere"),
              "from 127.0.0.1": ("22/tcp", "ALLOW IN", "127.0.0.1"), "from ::1": ("22/tcp (v6)", "ALLOW IN", "::1"),
              "udp": ("22/udp", "ALLOW IN", "Anywhere"), "out": ("22/tcp", "ALLOW OUT", "Anywhere"),
              "fwd": ("22/tcp", "ALLOW FWD", "Anywhere")}
    got_in = {k: _move102(sock_both, [_TJ102 % r, a2222]) for k, r in way_in.items()}
    got_not = {k: _move102(sock_both, [_TJ102 % r, a2222]) for k, r in not_in.items()}
    denied = _move102(sock_both, [_TJ102 % ("22/tcp", "DENY IN", "Anywhere"),
                                  _TJ102 % ("22/tcp", "ALLOW IN", "Anywhere"), a2222])
    check("ssh port: an ALLOW, LIMIT, bare 22 or a range covering 22/tcp is a way in, so the move back adds "
          "nothing over it (controls)", all(v == ([], False, None) for v in got_in.values()), repr(got_in))
    check("ssh port: a rule on lo or docker0, from 127.0.0.1 or ::1, for UDP, OUT or FWD is no way in, so the "
          "move back still adds 22/tcp; a DENY above an ALLOW refuses the move",
          all(v == ([22], False, None) for v in got_not.values())
          and denied[0] == [] and denied[2] is not None, repr((got_not, denied)))
    _ufw_reread102()


def _ufw_reread102():
    sock_both, a2222 = _SOCK_BOTH102, _A2222_102
    unconfirmed = _move102(sock_both, [a2222], opens=False)
    check("ssh port: an open ufw answered but the re-read does not show refuses the move and takes back "
          "what it added (it went on, and the panel was pointed at a port the firewall drops)",
          unconfirmed[0] == [22] and _CLOSED102 == [22] and "did not show port 22/tcp open" in str(unconfirmed[2])
          and not _DROPIN102, repr((unconfirmed, _CLOSED102, _DROPIN102)))
    # Only the port the panel's own SSH connection uses is left as it is: a bind change on it (a key
    # row stored on 22, reached through some rule that is not a public 22/tcp) opens nothing, while a
    # Tailscale-SSH row (its way in is tailscaled) or a move away from the stored port reads the rules.
    sock_22 = ("ActiveState=active\nListen=0.0.0.0:22 (Stream)\n", "", 0)
    keep = _move102(sock_22, [a2222], new_port=22, stored=22, bind="192.0.2.10")
    ts = _move102(sock_both, [a2222], new_port=22, stored=22, auth="tailscale")
    check("ssh port: the port the panel's own key/password connection uses is not opened again; a "
          "Tailscale-SSH row's sshd port is decided by the rules (controls)",
          keep[0] == [] and ts[0] == [22], repr((keep, ts)))
    _bind_only102()


def _bind_only102():
    # Public SSH "off" on a Tailscale-SSH row and on the panel host: only `on tailscale0` lets SSH in,
    # no public 22 rule. A bind change on 22 (sshd serves it) must add no allow; a move onto 22 that
    # sshd does not serve yet is still decided by the rules (control, the VPS sequence's direction).
    from panel.ops import system_ops as _so102
    _p9_patch(_so102, "host_has_ip", lambda addr: True)
    off = [_TJ102 % ("Anywhere on tailscale0", "ALLOW IN", "Anywhere"),
           _TJ102 % ("Anywhere (v6) on tailscale0", "ALLOW IN", "Anywhere (v6)")]
    sock_22 = ("ActiveState=active\nListen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n", "", 0)
    got = {
        "ts sshd_config": _move102(("", "", 1), off, new_port=22, stored=22, auth="tailscale", bind="192.0.2.10",
                                   socket_mode=False),
        "ts socket": _move102(sock_22, off, new_port=22, stored=22, auth="tailscale", bind="192.0.2.10"),
        "local sshd_config": _move102(("", "", 1), off, new_port=22, stored=22, auth="local", local=True,
                                      bind="192.0.2.10", socket_mode=False),
        "local socket": _move102(sock_22, off, new_port=22, stored=22, auth="local", local=True,
                                 bind="192.0.2.10"),
        "ts move onto 2222": _move102(sock_22, off, new_port=2222, stored=22, auth="tailscale",
                                      listening="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"),
    }
    check("ssh port: with public SSH off (only tailscale0 allowed), a bind change on the port sshd already "
          "serves adds no firewall rule on a Tailscale-SSH row or the panel host, socket-activated or not "
          "(it added `allow 22/tcp` and left public SSH back on, adversarial F1); a move onto a port sshd "
          "does not serve still opens it (control)",
          all(got[k][0] == [] and got[k][2] is None for k in ("ts sshd_config", "ts socket", "local sshd_config",
                                                              "local socket"))
          and got["ts move onto 2222"][0] == [2222], repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. ssh-status names sshd's real ports for every host; a move's audit row names sshd's old ones
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SHOW102 = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n"
            "Listen=0.0.0.0:22 (Stream)\n", "", 0)


def _ssh_reads102(socket_show):
    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb == "ufw-status":
            return ("Status: active\n\nTo                         Action      From\n--                         "
                    "------      ----\n22/tcp                     LIMIT       Anywhere\n", "", 0)
        if verb == "sshd-effective-config":
            return "port 22\n", "", 0
        return "", "", 0
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: socket_show)


def _ssh_status102(client, key_rid, ts_rid, local_rid):
    _p9_patch(_rv102, "remote_public_ssh_status", lambda remote, panel_port=None: {"mode": "limit"})
    _ssh_reads102(_SHOW102)
    got = {name: _p9_json(client.get("/api/remote/%d/ssh-status" % rid)).get("sshd_ports")
           for name, rid in (("local", local_rid), ("key", key_rid), ("tailscale", ts_rid))}
    _ssh_reads102(("", "", 1))
    got["local, socket unused"] = _p9_json(client.get("/api/remote/%d/ssh-status" % local_rid)).get("sshd_ports")
    _p9_patch(_p9_core, "run_privileged", lambda *a, **k: ("", "sudo: a password is required", 1))
    got["local, unread"] = _p9_json(client.get("/api/remote/%d/ssh-status" % local_rid)).get("sshd_ports")
    check("ssh port card: ssh-status carries `sshd_ports`, the ports sshd really listens on, for the "
          "panel host (its row's 22 is a placeholder never read from sshd, and the card showed it as "
          "\"the port sshd listens on\"), a key host and a Tailscale-SSH host alike; [] when unread",
          got == {"local": [2222, 22], "key": [2222, 22], "tailscale": [2222, 22],
                  "local, socket unused": [22], "local, unread": []}, repr(got))


def _ssh_audit102(client, key_rid, ts_rid, local_rid):
    _p9_patch(_rv102, "change_ssh_port", lambda remote, port, bind="": (True, "moved"))
    _ssh_reads102(_SHOW102)
    for rid in (key_rid, ts_rid, local_rid):
        client.post("/api/remote/%d/ssh-port" % rid, json={"port": 3333})
    _p9_patch(_p9_core, "run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    client.post("/api/remote/%d/ssh-port" % ts_rid, json={"port": 4444})
    with _p9.app_context():
        rows = {rid: [a.detail for a in AuditLog.query.filter_by(remote_id=rid, action="change_ssh_port")
                      .order_by(AuditLog.id)] for rid in (key_rid, ts_rid, local_rid)}
        db.session.get(RemoteServer, key_rid).port = 22
        db.session.get(RemoteServer, local_rid).port = 22
        db.session.commit()
    check("ssh port move: the audit row names the ports sshd served before the move on a Tailscale-SSH "
          "host and the panel host, whose row port is not sshd's (\"22 -> 3333\" recorded a move from "
          "2222), and \"unknown\" when they cannot be read; a key host's row port is its sshd port "
          "(control)",
          rows == {key_rid: ["22 -> 3333"], ts_rid: ["2222,22 -> 3333", "unknown -> 4444"],
                   local_rid: ["2222,22 -> 3333"]}, repr(rows))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A retry that created the account drops step 1's "found an account" record at once
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Restart102(Exception):
    """Where the stand-in for step 2 stops the job, like a panel restart would."""


def _found_row102(rid, short):
    sid = _new_server102(rid, short, "css", installed=False, status="installing")
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        why = _i18n102.Sentence(_p9_ms._R25B_FOUND_UNCONFIRMED, name=short)
        _p9_ms.record_install_failure(gs, "Preparing user account", why, True)
        gs.status = "installing"
        db.session.commit()
    return sid


def _retry_created102(rid, short, creates):
    sid = _found_row102(rid, short)
    seen = {}

    def _prepare(remote, remote_id, short_name, fresh):
        if creates:
            with _p9_state._install_lock:
                _p9_ms._accounts_created.add((remote_id, short_name))
        return True, "", True

    def _deps(job, remote):
        seen["left"] = _p9_ms._r25b_left_account(db.session.get(GameServer, sid))
        raise _p9_ms._InstallAbandoned("p102: the panel restarted here")
    _p9_patch(_p9_ms, "prepare_install_account", _prepare)
    _p9_patch(_p9_ms, "_install_dependencies", _deps)
    # The job's thread is queued and run by the drain below, so it has ended before the "restart"
    # (review 1016f: part12's finally gives the route modules their real threading back, the job
    # ran on a real thread, and the drain ran nothing; a yield before step 2 would have raced it).
    _p9_patch(_p9_ms, "threading", _p9_threading(_P9Thread))
    with _p9.app_context():
        _p9_ms._queue_install_job(db.session.get(GameServer, sid), [])
    _p9_ms._install_job_runner(_p9)(sid, rid, short, "css", "cssserver", 27102, [], fresh=False)
    _drained = _p9_drain()
    # The restart: the job, and this process's memory of the accounts it made, are gone.
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(sid, None)
        _p9_ms._accounts_created.discard((rid, short))
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        gs.status = "failed"            # what the restart reconcilers write, and nothing else
        db.session.commit()
        return seen.get("left"), _p9_ms._r25b_left_account(db.session.get(GameServer, sid)), _drained >= 1


def _retry_restart102(rid):
    got = {"created": _retry_created102(rid, "p102made", True),
           "reused": _retry_created102(rid, "p102kept", False)}
    sid = _found_row102(rid, "p102done")
    _p9_patch(_api102, "_looks_installed", lambda app, remote, short, lgsm: True)
    with _p9.test_request_context("/"):
        gs = db.session.get(GameServer, sid)
        _api102._settle_lost_install(_p9, gs)
        settled = (gs.installed, gs.install_error_i18n, gs.install_error)
    check("install retry: a retry whose step 1 created the account forgets step 1's old \"found an "
          "account, left it alone\" record as soon as it did, so a restart mid-install no longer "
          "brings it back (Remove then kept the panel's own account and said it had not made it); "
          "a retry that reused the account keeps it (control)",
          got == {"created": (False, False, True), "reused": (True, True, True)}, repr(got))
    check("install status: a lost install the host shows as installed clears the recorded failure, as "
          "the reconcile ticker does (the kept record came back once the row read uninstalled)",
          settled == (True, None, ""), repr(settled))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Public SSH "off" / Close port 22 never cuts the panel's own connection
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _off102(host, auth="key", port=22, local=False, resolves=()):
    """remote_set_public_ssh(off) on one host: (ok, ufw deletes run, refused for the panel's way in)."""
    ran = []
    _p9_patch(_hosts102, "_tailnet_ssh_state", lambda server: (True, True, True))
    _p9_patch(_hosts102, "_r28b_resolve", lambda name: list(resolves))
    _p9_patch(_hosts102, "remote_public_ssh_status", lambda server, panel_port=None: {"active": True, "mode": "off"})
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: ran.append(verb) or ("", "", 0))
    ok, msg = _hosts102.remote_set_public_ssh(NS(id=-10206, name="p102", host=host, port=port, is_local=local,
                                                 auth_method="local" if local else auth), "off")
    return ok, bool(ran), "connects to this host at" in str(msg)


def _public_off102(client, key_rid):
    cut = {"public IP": _off102("203.0.113.7"),
           "public v6": _off102("2001:db8::7"),
           "name, public": _off102("vps.example.com", resolves=("203.0.113.7",)),
           "name, mixed": _off102("vps.example.com", resolves=("100.64.0.7", "203.0.113.7")),
           "name, unresolved": _off102("vps.example.invalid")}
    kept = {"tailnet IP": _off102("100.64.0.7"), "tailnet v6": _off102("fd7a:115c:a1e0::7"),
            "MagicDNS FQDN": _off102("vps.tail1234.ts.net"),
            "name, tailnet": _off102("vps", resolves=("100.101.102.103",)),
            "Tailscale SSH": _off102("203.0.113.7", auth="tailscale"),
            "other port": _off102("203.0.113.7", port=2222),
            "panel host": _off102("127.0.0.1", local=True)}
    check("public SSH off: a host the panel itself reaches over public SSH on port 22 (a public "
          "address, or a name that resolves to one, or does not resolve) is refused before any rule "
          "is removed — the operator's Tailscale way back passed the gate, and the panel's next "
          "connection was dropped",
          all(v == (False, False, True) for v in cut.values()), repr(cut))
    check("public SSH off: ...while a host the panel reaches over the tailnet (address, MagicDNS name, "
          "a name resolving there), over Tailscale SSH, on another port, or the panel host itself "
          "goes ahead as before (controls)",
          all(v == (True, True, False) for v in kept.values()), repr(kept))
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: ("", "", 0))
    _p9_patch(_hosts102, "_r28b_resolve", lambda name: ["203.0.113.8"])
    _p9_patch(_cp102, "_tailnet_ssh_state", lambda server: (True, True, True))
    deleted = []
    _p9_patch(_hosts102, "_r15c_delete_port_22", lambda server: deleted.append(server.id))
    d = _p9_json(client.post("/api/remote/%d/close-port-22" % key_rid))
    check("close port 22: ...and the Close Port 22 button refuses the same host the same way, removing "
          "nothing", d.get("success") is False and "connects to this host at" in (d.get("message") or "")
          and deleted == [], repr((d, deleted)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. Editing a scheduled task re-syncs the Autostart / Daily-restart switches
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cron_edit102(client, rid):
    sid = _new_server102(rid, "p102cron", "css", autostart=True)
    _p9_patch(_p9_sf, "_write_refused", lambda gs, action, detail="": None)
    _p9_patch(_cron102, "list_cron_jobs", lambda server, user, selfname=None: [])   # `monitor` edited away
    got = {}
    for name, ok in (("refused", False), ("edited", True)):
        _p9_patch(_p9_sf, "update_cron_job", lambda *a, **k: (ok, ""))
        client.post("/api/server/%d/cron/update" % sid, json={"raw": "*/5 * * * * /home/p102cron/cssserver monitor",
                                                              "schedule": "0 4 * * *", "command": "details"})
        with _p9.app_context():
            got[name] = db.session.get(GameServer, sid).autostart
    check("scheduled tasks: editing the `monitor` line into something else turns Autostart off, as "
          "deleting it does (it stayed On until the card was listed again); an edit the host refused "
          "changes nothing (control)", got == {"refused": True, "edited": False}, repr(got))


try:
    _p9_arm(who="part102")
    _HOSTID102, _TSID102, _LOCALID102, _ADMIN102 = _setup102()
    _A102 = _p9_client(_ADMIN102)
    _gmod_owner102(_A102, _HOSTID102)
    _prune_running102()
    _socket_move_back102()
    _vps_sequence102()
    _ufw_table102()
    _ssh_status102(_A102, _HOSTID102, _TSID102, _LOCALID102)
    _ssh_audit102(_A102, _HOSTID102, _TSID102, _LOCALID102)
    _retry_restart102(_HOSTID102)
    _public_off102(_A102, _HOSTID102)
    _cron_edit102(_A102, _HOSTID102)
finally:
    _p9_restore_all()
    _cleanup102()

check("part102: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP102_START, repr(_P9_TRIPPED[_TRIP102_START:][:6]))
