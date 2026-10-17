"""Part 94 of the unit suite: the fourteenth review's ssh_manager and route fixes (review 1016b, builder B).

* Moving sshd's port on a host the panel reaches over Tailscale SSH keeps the row on port 22:
  tailscaled answers 22 on the tailnet whatever sshd listens on, and storing the new port sent
  every later command to plain sshd there, which wants a key the panel does not hold.

* Moving SSH onto a port an IPv6-only LIMIT already covers adds only the IPv4 rule (ufw rewrote
  the operator's LIMIT into an ALLOW), and the revert deletes exactly that rule.

* Closing a port whose delete matched no rule, with the firewall unreadable after, is not "closed".

* The world-readable polls (uptime, live metrics, timezone, gamedig's address, disk and load, ...)
  run without sudo, so a remote whose sudo wants a password still answers them.

* A LinuxGSM `querytype` starting with `-` never reaches gamedig as an option.

* Uninstalling a server whose install stopped at step 1, refusing an account it found on the host,
  deletes the row and touches nothing on the host (it ran `userdel -r -f` on that account).

* The config editor's save and every lgsm_write_config write refuse the live console's log.

* Leads: a scheduled backup's mark is not left "running" under the id of a server deleted before
  it went in; a TLS cert the panel does not serve pages nobody; an action or a console command
  whose audit row cannot be written is not reported as failed, and never as a 500.

HOW IT RUNS. Stand-ins behind run_privileged/run_command (a ufw table with ufw's own rewrite and
per-family delete), bash for real over this part's own fixture tree (no sudo, no host), and
routes on part12's app with recorders. Nothing reaches a host, sudo or the checkout's data/.
"""
import os
import shutil as _shutil94
import subprocess as _sp94  # nosec B404 - runs bash over this part's own fixture tree
import tempfile as _tempfile94
import time as _time94
from functools import partial as _partial94
from types import SimpleNamespace as NS

from sqlalchemy.exc import OperationalError as _OpErr94

from unit.part01 import check
from unit.part10 import _Over
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_flashes, _p9_json,
                         _p9_ms, _p9_patch, _p9_restore_all, _p9_rv, _p9_sd, _p9_sf, _p9_sh, _p9_patch_sm)
from unit.part89 import _HEAD89 as _HEAD89_94, _Ufw89
from panel.core import i18n as _i18n94
from panel.core.panel_state import _game_backup_status as _gbs94
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db, row_birth
from panel.ops.ssh_manager import (_core as _core94, cron as _cron94, files as _files94,
                                   gmod as _gmod94, hosts as _hosts94)
from panel.routes import os_updates as _osu94, panel_backup as _pb94
from panel.security import auth as _auth94
from panel.services import certs as _certs94, monitoring as _mon94

_TRIP94_START = len(_P9_TRIPPED)
_mine94 = {"hosts": [], "servers": [], "users": []}
_TMP94 = _tempfile94.mkdtemp(prefix="p94-")


def _setup94():
    with _p9.app_context():
        ts = RemoteServer(name="p94-ts", host="p94-ts.example.invalid", port=22, username="admin",
                          auth_method="tailscale", auth_credential="", is_online=True)
        key = RemoteServer(name="p94-key", host="p94-key.example.invalid", port=22, username="admin",
                           auth_method="key", auth_credential="", is_online=True)
        admin = User(username="p94_admin", password_hash=_auth94.hash_password("Str0ng!passw0rd-p94"),
                     display_name="p94 admin", is_superadmin=True, is_active=True)
        db.session.add_all([ts, key, admin])
        db.session.commit()
        _mine94["hosts"] += [ts.id, key.id]
        _mine94["users"].append(admin.id)
        return ts.id, key.id, admin.id


def _new_server94(rid, short, **kw):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name=kw.pop("name", short), short_name=short, game_type="css",
                        port=kw.pop("port", 27094), installed=kw.pop("installed", True),
                        status=kw.pop("status", "offline"), **kw)
        db.session.add(gs)
        db.session.commit()
        _mine94["servers"].append(gs.id)
        return gs.id


def _exists94(model, i):
    with _p9.app_context():
        return db.session.get(model, i) is not None


def _cleanup94():
    with _p9.app_context():
        for i in _mine94["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        for i in _mine94["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p94%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine94[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
        db.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. An SSH port move on a Tailscale-SSH host keeps the row on port 22
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ssh_port94(client, ts_rid, key_rid):
    moved = []
    _p9_patch(_p9_rv, "change_ssh_port", lambda remote, port, bind="": moved.append(remote.id) or (True, "moved"))
    # The audit row reads a Tailscale-SSH host's sshd ports before the move (review 1016e).
    _p9_patch(_p9_rv, "_r26b_sshd_ports", lambda remote: [])
    d_ts = _p9_json(client.post("/api/remote/%d/ssh-port" % ts_rid, json={"port": 2222}))
    d_key = _p9_json(client.post("/api/remote/%d/ssh-port" % key_rid, json={"port": 2222}))
    with _p9.app_context():
        ports = {"tailscale": db.session.get(RemoteServer, ts_rid).port,
                 "key": db.session.get(RemoteServer, key_rid).port}
    check("ssh port: moving sshd on a host the panel reaches over Tailscale SSH keeps the row on "
          "port 22 and says so (the new port went on the row, every later command went to plain "
          "sshd on it, and the host was lost); a key-auth host still stores the new port (control)",
          moved == [ts_rid, key_rid] and ports == {"tailscale": 22, "key": 2222}
          and d_ts.get("success") is True and "Tailscale SSH on port 22" in (d_ts.get("message") or "")
          and d_key.get("message") == "moved", repr((moved, ports, d_ts, d_key)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. ufw: a move onto a port an IPv6-only LIMIT covers, and its revert
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Ufw94(_Ufw89):
    """_Ufw89 plus the allows: ufw rewrites a same-spec rule's action in place, per family."""

    def _put(self, to, fams):
        for fam in fams:
            hit = [r for r in self.rules if r[0] == to and r[2] == "Anywhere" and r[fam]
                   and r[1].endswith(" IN")]
            if hit:
                hit[0][1] = "ALLOW IN"
            else:
                self.rules.append([to, "ALLOW IN", "Anywhere", fam == 3, fam == 4])
        return "Rule added", "", 0

    def run(self, server, verb, args=(), timeout=30, **k):
        a = list(args)
        if verb == "ufw-allow-proto-port":
            self.verbs.append((verb, a))
            return self._put("%s/%s" % (a[1], a[0]), (3, 4))
        if verb in ("ufw-allow-from-port", "ufw-delete-allow-from-port"):
            self.verbs.append((verb, a))
            fam = 3 if a[0] == _hosts94._R25B_V4_ANYWHERE else 4
            to = "%s/%s" % (a[1], a[2])
            if verb == "ufw-allow-from-port":
                return self._put(to, (fam,))
            hit = self._delete_family(fam, to, "ALLOW IN")
            self.rules = [r for r in self.rules if r[3] or r[4]]
            return ("Rule deleted" if hit else "Could not delete non-existent rule"), "", 0
        return super().run(server, verb, args, timeout, **k)


def _move94(*rows):
    """change_ssh_port 22 -> 2222 over `rows`, failing at sshd-validate: (answer, rules after, verbs)."""
    ufw = _Ufw94(*rows)

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb.startswith("ufw-"):
            return ufw.run(server, verb, args)
        if verb == "listening-sockets":
            return ("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "", 0)
        if verb == "sshd-validate":
            return ("", "bad config", 1)
        return ("", "", 0)
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "write_root_file", lambda *a, **k: ("", "", 0))
    _p9_patch(_hosts94, "_sshd_socket_activated", lambda s: False)
    _p9_patch(_hosts94, "_sshd_current_ports", lambda s: ["22"])
    _p9_patch(_hosts94, "_restart_ssh_listener", lambda *a, **k: None)
    res = _hosts94.change_ssh_port(NS(id=-9401, name="p94", host="p94.example.invalid", port=22,
                                      is_local=False, auth_method="key"), 2222)
    return res, sorted(tuple(r) for r in ufw.rules), [v for v, _a in ufw.verbs if v != "ufw-status"]


# No public way in to TCP 2222 over IPv6: none may be read as the operator's exact v6 rule.
_HARMLESS94 = [("2222/tcp on lo", "ALLOW IN", "Anywhere", False, True),
               ("2222/tcp on docker0", "ALLOW IN", "Anywhere", False, True),
               ("2222/tcp", "ALLOW IN", "::1", False, True),
               ("2222/udp", "ALLOW IN", "Anywhere", False, True),
               ("2222/tcp", "ALLOW OUT", "Anywhere", False, True),
               ("2222/tcp", "ALLOW FWD", "Anywhere", False, True),
               ("2222/tcp", "ALLOW IN", "127.0.0.1", True, False)]


_V6_LIMIT94 = ("2222/tcp", "LIMIT IN", "Anywhere", False, True)
_V6_ALLOW94 = ("2222/tcp", "ALLOW IN", "Anywhere", False, True)


def _v6_limit_move94():
    v6_limit, v6_allow = _V6_LIMIT94, _V6_ALLOW94
    got = {name: _move94(*rows) for name, rows in (
        ("v6 LIMIT", [v6_limit]), ("v6 ALLOW", [v6_allow]), ("v6 LIMIT + harmless", [v6_limit] + _HARMLESS94),
        ("harmless only", _HARMLESS94), ("nothing", []))}
    ends = {k: v[1] for k, v in got.items()}
    check("ssh port move: onto a port an IPv6-only LIMIT or ALLOW covers, only the IPv4 rule goes in "
          "and the revert removes exactly it — the operator's v6 rule ends as it began (ufw rewrote the "
          "LIMIT into an ALLOW, and the panel's own v4 ALLOW stayed public for a port nothing served)",
          ends["v6 LIMIT"] == [v6_limit] and ends["v6 ALLOW"] == [v6_allow]
          and ends["v6 LIMIT + harmless"] == sorted([v6_limit] + _HARMLESS94)
          and got["v6 LIMIT"][2] == ["ufw-allow-from-port", "ufw-delete-allow-from-port"]
          and all(not v[0][0] for v in got.values()), repr(got))
    _v6_harmless_check94(got, ends)


def _v6_harmless_check94(got, ends):
    check("ssh port move: an IPv6 rule on lo or docker0, from ::1, for UDP, OUT or FWD (and a v4 one "
          "from 127.0.0.1) is not the operator's v6 rule: the panel adds and removes its own rule for "
          "both families, and those rules are left as they were",
          ends["harmless only"] == sorted(_HARMLESS94) and ends["nothing"] == []
          and got["harmless only"][2][0] == "ufw-allow-proto-port"
          and "ufw-allow-from-port" not in got["harmless only"][2], repr(got))


def _v6_deny_move94():
    v6_allow = _V6_ALLOW94
    res, end, verbs = _move94(("2222/tcp", "DENY IN", "Anywhere", False, True), v6_allow)
    check("ssh port move: a v6 DENY met first still refuses the move, with nothing opened (control)",
          res[0] is False and "blocked by the firewall rule" in str(res[1]) and verbs == []
          and end == sorted([("2222/tcp", "DENY IN", "Anywhere", False, True), v6_allow]),
          repr((res, end, verbs)))


def _close_unread94():
    """Close a port whose delete matched nothing, with the read-back failing or not."""
    def close(delete_out, status):
        def _priv(server, verb, args=(), timeout=30, **k):
            if verb == "ufw-status":
                return status
            return delete_out, "", 0
        _p9_patch(_p9_core, "run_privileged", _priv)
        return _hosts94.remote_ufw_close_port(NS(id=-9405, name="p94"), 27094, "tcp", force=True)[0]
    nothing = "Could not delete non-existent rule\nCould not delete non-existent rule (v6)"
    unread, listed = ("", "ufw: permission denied", 1), (_HEAD89_94, "", 0)
    got = {"nothing removed, unread": close(nothing, unread),
           "removed, unread": close("Rule deleted\nRule deleted (v6)", unread),
           "nothing removed, read and closed": close(nothing, listed)}
    check("close port: a delete that matched no rule, with the firewall unreadable afterwards, is not "
          "\"Port N closed\" (nothing confirmed it, and nothing was removed); a delete that removed a "
          "rule, or a read-back that shows the port closed, still is (controls)",
          got == {"nothing removed, unread": False, "removed, unread": True,
                  "nothing removed, read and closed": True}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. World-readable polls run without sudo
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _sudo_reads94():
    asked, cur = [], ["?"]

    def _rc(server, cmd, timeout=30, sudo="(not passed)", stdin_text=None):
        asked.append((cur[0], sudo))
        if "reboot-required &&" in cmd:
            return "YES\n", "", 0
        return "", "", 0
    _p9_patch(_core94, "run_command", _rc)
    _p9_patch(_mon94, "run_command", _rc)
    srv = NS(id=-9402, name="p94", host="p94.example.invalid", port=22, is_local=False,
             auth_method="key", sudo_enabled=True, username="admin")
    _core94._gamedig_host_cache.pop(srv.id, None)
    # Each bound to its own arguments here (functools.partial), not one `fn(srv, *args)` call
    # site: that read to CodeQL as every function called with the longest tuple
    # (py/call/wrong-arguments), though each got its own.
    calls = (("host_timezone", _partial94(_hosts94.host_timezone, srv)),
             ("remote_uptime", _partial94(_hosts94.remote_uptime, srv, True)),
             ("remote_live_metrics", _partial94(_core94.remote_live_metrics, srv)),
             ("_gamedig_host", _partial94(_core94._gamedig_host, srv)),
             ("remote_public_ip", _partial94(_core94.remote_public_ip, srv)),
             ("_host_disk_pct", _partial94(_mon94._host_disk_pct, srv)),
             ("_host_load_mem", _partial94(_mon94._host_load_mem, srv)),
             ("host_os_slug", _partial94(_hosts94.host_os_slug, srv)),
             ("remote_reboot_required", _partial94(_hosts94.remote_reboot_required, srv)),
             ("host_boot_identity", _partial94(_hosts94.host_boot_identity, srv)),
             ("_tsiface_names", _partial94(_hosts94._tsiface_names, srv)),
             ("_user_primary_group", _partial94(_gmod94._user_primary_group, srv, "p94u")))
    for name, fn in calls:
        cur[0] = name
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - recorded: a raise is a finding of its own here
            asked.append((name, "raised %s" % type(e).__name__))
    _core94._gamedig_host_cache.pop(srv.id, None)
    bad = [a for a in asked if a[1] is not False]
    check("reads: the world-readable polls (uptime, live metrics, timezone, gamedig's address, the "
          "public IP, disk and load, os-release, reboot-required, boot id, interfaces, a group) pass "
          "sudo=False, so a sudo-enabled remote whose sudo wants a password still answers them",
          not bad and {n for n, _s in asked} == {c[0] for c in calls}, repr(asked))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. LinuxGSM's querytype never reaches gamedig as an option
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _lgsm_qtype94():
    sent, vals = [], {}
    _p9_patch(_files94, "lgsm_get_values", lambda server, user, selfname, keys: dict(vals))
    _p9_patch(_core94, "_gamedig_host", lambda server: "gd.example.invalid")
    _p9_patch(_core94, "shell_as_game_user",
              lambda server, user, cmd, timeout=30, **k: sent.append(cmd) or ('{"c":3,"ok":true}', "", 0))
    got = {}
    for qt in ("--debug", "-h", "_x", "--", "csgo"):
        vals.clear()
        vals.update({"querymode": "2", "querytype": qt, "queryport": "27094", "port": ""})
        del sent[:]
        n = _cron94.player_count_via_lgsm_query(NS(id=-9403), "p94u", "p94srv")
        got[qt] = (n, sent[0].split(" gd.example")[0] if sent else None)
    check("gamedig: a LinuxGSM querytype starting with - or _ (the cfg is the game account's to "
          "write) reaches gamedig as a type, never an option, and one that is nothing else asks nothing",
          got == {"--debug": (3, "gamedig --type debug"), "-h": (3, "gamedig --type h"),
                  "_x": (3, "gamedig --type x"), "--": (None, None), "csgo": (3, "gamedig --type csgo")},
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Uninstalling a server whose install refused an account it found on the host
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _refused_row94(rid, short, fresh):
    """A failed row recorded exactly as the install's step 1 records its refusal."""
    sid = _new_server94(rid, short, installed=False, status="failed")
    _p9_patch_sm("read_as_game_user", lambda *a, **k: ("NOTEXISTS\n", "", 0))
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        ok, why, retry = _p9_ms._existing_account_verdict(gs.remote, (rid, short), fresh)
        _p9_ms.record_install_failure(gs, "Preparing user account", why, retry)
        db.session.commit()
    return sid, ok


def _old_row94(rid, short):
    """A row recorded before the refusal was reworded (the template a live panel.db holds)."""
    old = next(t for t in _p9_ms._R25B_FOUND_TEMPLATES
               if t.startswith("An account") and t != _p9_ms._R25B_FOUND_FRESH)
    sid = _new_server94(rid, short, installed=False, status="failed")
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        _p9_ms.record_install_failure(gs, "Preparing user account", _i18n94.Sentence(old, name=short), False)
        db.session.commit()
    return sid


def _uninstall94(client, rid):
    host = []
    _p9_patch(_p9_ms, "privileged_accounts", lambda remote, users: host.append(("probe", list(users))) or {})
    _p9_patch(_p9_ms, "_stop_game_processes", lambda *a, **k: host.append(("stop",)))
    _p9_patch(_p9_ms, "_close_game_firewall", lambda remote, gs: host.append(("firewall",)) or ([], False))
    _p9_patch(_p9_ms, "_remove_account_crontab", lambda *a, **k: host.append(("crontab",)))
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **k: host.append((verb,)) or ("", "", 0))
    rows = {"fresh": _refused_row94(rid, "p94fresh", True), "unconfirmed": _refused_row94(rid, "p94unc", False),
            "old wording": (_old_row94(rid, "p94old"), False)}
    xhr = {"X-Requested-With": "XMLHttpRequest"}
    got = {}
    for name, (sid, _ok) in rows.items():
        del host[:]
        d = _p9_json(client.post("/servers/%d/delete" % sid, headers=xhr))
        got[name] = (d.get("success"), d.get("warn"), _exists94(GameServer, sid), list(host))
    check("uninstall: a server whose install stopped at step 1, refusing an account it found on the "
          "host (fresh, unconfirmed, or recorded before the reword), is removed from the panel with "
          "nothing run on the host (Remove ran `userdel -r -f` on exactly that account)",
          all(v == (True, True, False, []) for v in got.values())
          and not any(ok for _s, ok in rows.values()), repr(got))
    ctl = _new_server94(rid, "p94ctl", installed=False, status="failed")
    with _p9.app_context():
        gs = db.session.get(GameServer, ctl)
        _p9_ms.record_install_failure(gs, "Downloading game files", "steamcmd failed", True)
        db.session.commit()
    del host[:]
    d = _p9_json(client.post("/servers/%d/delete" % ctl, headers=xhr))
    check("uninstall: ...while any other failed install still stops, closes and deletes its account "
          "(control)", d.get("success") is True and ("user-delete-force",) in host
          and host[0] == ("probe", ["p94ctl"]), repr((d, host)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The config editor and lgsm_write_config refuse the live console's log
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HOME94 = os.path.join(_TMP94, "home", "p94cfg")


def _bash94(script):
    r = _sp94.run(["/bin/bash", "-c", script], capture_output=True, text=True,  # nosec B603 - own text
                  timeout=30)
    return r.stdout, r.stderr, r.returncode


def _fshell94(server, user, script, timeout=30, **k):
    return _bash94(script.replace("/home/p94cfg", _HOME94))


def _console_cfg94(client, rid):
    sid = _new_server94(rid, "p94cfg")
    with _p9.app_context():
        lgsm = db.session.get(GameServer, sid).lgsm_name
    log_rel = "log/console/%s-console.log" % lgsm
    cfg_dir = os.path.join(_HOME94, "lgsm", "config-lgsm", lgsm)
    os.makedirs(cfg_dir)
    os.makedirs(os.path.join(_HOME94, "log", "console"))
    with open(os.path.join(_HOME94, log_rel), "wb") as fh:
        fh.write(b"line 1\n")
    os.symlink("../../../" + log_rel, os.path.join(cfg_dir, lgsm + ".cfg"))
    ino = os.stat(os.path.join(_HOME94, log_rel)).st_ino
    _p9_patch(_p9_core, "shell_as_game_user", _fshell94)
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_files94, "_read_instance_cfg_lines", lambda *a, **k: ['port="27094"'])
    want = str(_files94.WRITE_CONSOLE)
    got = {
        "raw save": _p9_json(client.post("/api/server/%d/config" % sid, json={"raw": "port=\"1\"\n"})),
        "settings save": _p9_json(client.post("/api/server/%d/config" % sid,
                                              json={"settings": {"maxplayers": "8"}})),
        "alerts save": _p9_json(client.post("/api/server/%d/alerts" % sid,
                                            json={"values": {"discordalert": "on"}})),
    }
    direct = _files94.lgsm_write_config(NS(), "p94cfg", lgsm, {"maxplayers": "9"})
    with open(os.path.join(_HOME94, log_rel), "rb") as fh:
        body = fh.read()
    check("config: the config editor's raw and settings saves, an alerts save and lgsm_write_config "
          "itself refuse an instance cfg that is a link to the live console's log, which keeps its "
          "inode and text (the replace through the link silenced the console under \"Saved\")",
          all(d.get("success") is False and d.get("message") == want for d in got.values())
          and direct == (False, _files94.WRITE_CONSOLE)
          and os.stat(os.path.join(_HOME94, log_rel)).st_ino == ino and body == b"line 1\n",
          repr((got, direct, body)))
    os.unlink(os.path.join(cfg_dir, lgsm + ".cfg"))
    ok = _files94.lgsm_write_config(NS(), "p94cfg", lgsm, {"maxplayers": "9"})
    with open(os.path.join(cfg_dir, lgsm + ".cfg"), "rb") as fh:
        cfg = fh.read()
    check("config: ...while a plain instance cfg still saves (control)",
          ok == (True, "") and b'maxplayers="9"' in cfg, repr((ok, cfg)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. Leads: backup marks, a leftover cert, rows that cannot be written
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _delete_row94(sid):
    """Delete the row as an uninstall elsewhere would, without forget_rows (the mark went in after)."""
    with _p9.app_context():
        GameServer.query.filter_by(id=sid).delete()
        db.session.commit()


def _backup_marks94(rid):
    left = {}
    with _p9.app_context():
        # The full run: the server goes while it is being archived.
        sid = _new_server94(rid, "p94bk1")
        gs = db.session.get(GameServer, sid)
        tally = NS(keep_unread=False)
        _p9_patch(_pb94, "run_game_backup", lambda *a, **k: _delete_row94(sid) or (True, "", False))
        _pb94._full_backup_server(_p9, gs, (False, False), tally)
        left["full run"] = _gbs94.pop(sid, None)
        # The queued sweep.
        sid2 = _new_server94(rid, "p94bk2", backup_pending=True)
        gs2 = db.session.get(GameServer, sid2)
        _p9_patch(_p9_sh, "run_game_backup", lambda *a, **k: _delete_row94(sid2) or (True, "", False))
        _p9_sh._back_up_queued(_p9, gs2)
        left["queued"] = _gbs94.pop(sid2, None)
        # The scheduled ticker, and a raise.
        sid3 = _new_server94(rid, "p94bk3")
        gs3 = db.session.get(GameServer, sid3)
        target = (sid3, gs3.remote, gs3.short_name, gs3.lgsm_name, gs3.name, gs3.game_type, gs3.port,
                  gs3.query_type, row_birth(gs3))
        _p9_patch(_p9_sh, "bk", _Over(_p9_sh.bk, get_game_schedule=lambda s: {"interval_days": 1, "keep": 3,
                                                                                "last": 1.0},
                                      game_backup_due=lambda s: True))

        def _gone_raise(*a, **k):
            _delete_row94(sid3)
            raise RuntimeError("p94")
        _p9_patch(_p9_sh, "run_game_backup", _gone_raise)
        try:
            _p9_sh._back_up_if_due(_p9, target)
        except RuntimeError:
            pass  # the raise is the scenario; what it left behind is the check
        left["scheduled, raised"] = _gbs94.pop(sid3, None)
    mark = {}
    _p9_sh._marked_backup(-9404, runner=lambda: (True, "", False), held=lambda: True)
    mark["held"] = (_gbs94.pop(-9404, None) or {}).get("running")
    check("backup: a run whose server was deleted before its mark went in (so forget_rows had nothing "
          "to drop) leaves no \"running\" entry under the id — the full run, the queued sweep, and a "
          "scheduled run that raised; a server still there keeps its mark for the caller (control)",
          left == {"full run": None, "queued": None, "scheduled, raised": None} and mark == {"held": True},
          repr((left, mark)))


def _leftover_cert94():
    said = []
    _p9_patch(_certs94.notifications, "notify", lambda kind, title, body: said.append(kind))
    _p9_patch(_certs94, "DATA_DIR", _certs94.DATA_DIR.__class__(_TMP94))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime as _dt94
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "p94")])
    now = _dt94.datetime.now(_dt94.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - _dt94.timedelta(days=80))
            .not_valid_after(now + _dt94.timedelta(days=5)).sign(key, hashes.SHA256()))
    os.makedirs(os.path.join(_TMP94, "ssl"), exist_ok=True)
    with open(os.path.join(_TMP94, "ssl", "cert.pem"), "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    got = {}
    for label, boot in (("plain HTTP", {"BOOT_TLS": False, "BOOT_TLS_ERROR": None}),
                        ("serving TLS", {"BOOT_TLS": True, "BOOT_TLS_ERROR": None}),
                        ("TLS failed", {"BOOT_TLS": False, "BOOT_TLS_ERROR": "SSLError"}),
                        ("no record", None)):
        del said[:]
        _certs94._CERT_ALERTED["at"] = 0
        _certs94._maybe_alert_cert_expiring(boot)
        got[label] = bool(said)
    _certs94._CERT_ALERTED["at"] = 0
    seen, boot = _cert_ticker94()
    check("TLS expiry: a certificate left in data/ssl while the panel serves plain HTTP on purpose "
          "pages nobody (\"renew it\" for a cert nothing served); serving it, a TLS start that "
          "failed and no boot record still alert; the ticker passes the boot record",
          got == {"plain HTTP": False, "serving TLS": True, "TLS failed": True, "no record": True}
          and seen == [boot], repr((got, seen)))


def _cert_ticker94():
    """One pass of the update-check ticker, everything else stubbed: (what the cert check got, boot)."""
    seen, ticker = [], []

    class _Stop94(Exception):
        """Ends the ticker's endless loop after one pass."""

    def _sleep(s):
        if s >= 1800:
            raise _Stop94()
    boot = {"BOOT_TLS": False, "BOOT_TLS_ERROR": None}
    fake = NS(config=boot, logger=NS(debug=lambda *a, **k: None))
    _p9_patch(_osu94, "time", _Over(_time94, sleep=_sleep))
    _p9_patch(_osu94, "runtime_stats", NS(loop_started=lambda *a: None, beat=lambda *a: None,
                                          bump=lambda *a: None))
    _p9_patch(_osu94, "so", NS(panel_update_status=lambda force=False: {}))
    _p9_patch(_osu94, "_update_tick", lambda app, st, last: last)
    _p9_patch(_osu94, "_announced_update", lambda: None)
    _p9_patch(_osu94, "_maybe_alert_cert_expiring", lambda b=None: seen.append(b))
    saved_run = _osu94._os_update_state["last_run"]
    _osu94._os_update_state["last_run"] = _time94.time()   # the daily OS check returns at once
    try:
        _osu94.register(fake, lambda name, fn: ticker.append(fn))
        try:
            ticker[0]()
        except _Stop94:
            pass  # one pass done
    finally:
        _osu94._os_update_state["last_run"] = saved_run
    return seen, boot


def _unwritable_audit94(client, rid):
    sid = _new_server94(rid, "p94aud", status="online")

    def _locked(*a, **k):
        raise _OpErr94("INSERT INTO audit_log", {}, Exception("database is locked"))
    _p9_patch(_p9_sd, "log_action", _locked)
    _p9_patch(_p9_sd, "send_console_command", lambda *a, **k: ("", "", 0))
    r = client.post("/server/%d/command" % sid, data={"command": "say p94"})
    sent = (r.status_code, _p9_flashes(client))
    _p9_patch(_p9_sd, "_run_action", _locked)
    r = client.post("/server/%d/action" % sid, data={"action": "details"})
    action = (r.status_code, _p9_flashes(client))
    check("audit: a console command whose audit row cannot be written (the database locked) still "
          "says it was sent, and that the row is missing — it said the send failed, for a command the "
          "game already had",
          sent[0] == 302 and "Command sent: say p94" in sent[1]
          and _p9_sd._R25B_AUDIT_UNWRITTEN in sent[1]
          and not any("Failed to send" in m for m in sent[1]), repr(sent))
    check("audit: an action that met a database error answers its redirect saying it may have run, "
          "and its failure row raising too is no 500", action[0] == 302
          and action[1] == [_p9_sd._R25B_ACTION_UNSURE], repr(action))


try:
    _p9_arm(who="part94")
    _TS94, _KEY94, _ADMIN94 = _setup94()
    _A94 = _p9_client(_ADMIN94)
    _ssh_port94(_A94, _TS94, _KEY94)
    _v6_limit_move94()
    _v6_deny_move94()
    _close_unread94()
    _sudo_reads94()
    _lgsm_qtype94()
    _uninstall94(_A94, _KEY94)
    _console_cfg94(_A94, _KEY94)
    _backup_marks94(_KEY94)
    _leftover_cert94()
    _unwritable_audit94(_A94, _KEY94)
finally:
    _p9_restore_all()
    _cleanup94()
    _shutil94.rmtree(_TMP94, ignore_errors=True)

check("part94: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP94_START, repr(_P9_TRIPPED[_TRIP94_START:][:6]))
