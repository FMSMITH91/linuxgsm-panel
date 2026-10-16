"""Part 83 of the unit suite: the eleventh review's fixes (review 1015a, builder B).

ssh_manager, the game and file modules, and the first half of the routes:

* Rate limit on a port: success only when the LIMIT is the first rule a connection meets. An ALLOW
  above it written as the OpenSSH profile, a port list, a destination before the port or no port
  at all was skipped by the reader, so the port was reported limited and nothing was throttled.
  The Network card's public-SSH reading shares that reader now (a `22,80/tcp` allow read "off").

* A Tailscale join refuses what `tailscale up` refuses BEFORE IP forwarding is switched on: a
  route with host bits or no prefix, and an auth key the verb's validator refuses.

* A host typed in brackets (`[2001:db8::5]`, how the panel prints an IPv6 login) is stored and
  dialled without them, every spelling of an address is one text, and the debug report matches a
  Tailscale peer by that text.

* The file browser's host-side guards: a name that ENDS in a newline is the file asked for (a
  download read, and a delete removed, the sibling without it), and a host whose /home is a
  symlink is not "outside the home" for everything. Real bash over this part's own fixture tree.

* Audits: a short action's raise is one row, not two; a crontab write that worked is audited even
  when its read-back raises; Autostart and the daily restart audit a refusal and a raise; a queued
  action's raise counts toward its attempts. A malformed Ubuntu Pro token is refused, not a 500.

HOW IT RUNS. On part12's Flask app and stubs, as part80 does; the file guards run `bash` for real
on a tree under this part's own temporary directory (no sudo, no host).
"""
import os
import shutil as _shutil83
import subprocess as _sp83  # nosec B404 - runs bash over this part's own fixture tree
import tempfile as _tempfile83
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_core, _p9_patch, _p9_restore_all, _p9_sd, _p9_sf, _p9_sh)
from panel.core import validation as _val83
from panel.db import models as _m83
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops import ssh_manager as _sm83
from panel.ops.debug_report import hosts as _dbh83
from panel.ops.ssh_manager import files as _files83, game as _game83, hosts as _hosts83
from panel.security import auth as _auth83
from panel.security import privileged as _priv83

_TRIP83_START = len(_P9_TRIPPED)
_mine83 = {"hosts": [], "servers": [], "users": []}


def _setup83():
    with _p9.app_context():
        r = RemoteServer(name="p83-host", host="p83.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p83-css", short_name="p83css", game_type="css",
                        port=27083, installed=True, status="online")
        admin = User(username="p83_admin", password_hash=_auth83.hash_password("Str0ng!passw0rd-p83"),
                     display_name="p83 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine83["hosts"].append(r.id)
        _mine83["servers"].append(gs.id)
        _mine83["users"].append(admin.id)
        return r.id, gs.id, admin.id


def _cleanup83():
    with _p9.app_context():
        for i in _mine83["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
            _p9_sh._queued_action_failures.pop(i, None)
        for i in _mine83["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p83%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine83[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Rate limit: success only when the LIMIT is what a connection meets first
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UFW_HEAD83 = ("Status: active\n\n     To                         Action      From\n"
               "     --                         ------      ----\n")


class _Ufw83:
    """`ufw status numbered` over a list of rule rows; `ufw limit` appends its LIMIT, as ufw does."""

    def __init__(self, *rows):
        self.rows = list(rows)
        self.verbs = []

    def status(self):
        return _UFW_HEAD83 + "".join("[%2d] %s\n" % (i + 1, r) for i, r in enumerate(self.rows))

    def plain(self):
        return _UFW_HEAD83 + "".join(r + "\n" for r in self.rows)

    def run(self, server, verb, args=(), timeout=30, **k):
        self.verbs.append(verb)
        if verb == "ufw-status":
            return self.status(), "", 0
        if verb == "ufw-limit-port":
            # Both families, as ufw does with IPv6 on: the (v6) twin is listed after the v4 rules.
            self.rows.append("%-27sLIMIT IN    Anywhere" % args[0])
            self.rows.append("%-27sLIMIT IN    Anywhere (v6)" % (args[0] + " (v6)"))
        return "", "", 0


def _limit83(port, *rows, proto="tcp"):
    ufw = _Ufw83(*rows)
    _p9_patch(_p9_core, "run_privileged", ufw.run)
    ok, msg = _hosts83.remote_ufw_limit_port(NS(id=-83, name="p83"), port, proto)
    return ok, str(msg)


_ALLOW_ROW83 = "%-27sALLOW IN    Anywhere"


def _limit_shadowed83():
    shadows = {
        "OpenSSH profile": (22, _ALLOW_ROW83 % "OpenSSH"),
        "port list": (27015, _ALLOW_ROW83 % "27015,27016/tcp"),
        "destination": (22, _ALLOW_ROW83 % "203.0.113.5 22/tcp"),
        "every port": (22, _ALLOW_ROW83 % "Anywhere"),
        "range": (27015, _ALLOW_ROW83 % "27000:27030/tcp"),
        "DENY above": (22, "%-27sDENY IN     Anywhere" % "22/tcp"),
        # IPv6 is its own chain: a (v6) allow above the (v6) LIMIT leaves every IPv6 client
        # unthrottled (review 1015c; this was listed below as a harmless "v6 twin").
        "v6 profile above": (22, "%-27sALLOW IN    Anywhere (v6)" % "OpenSSH (v6)"),
        "v6 port above": (22, "%-27sALLOW IN    Anywhere (v6)" % "22/tcp (v6)"),
    }
    got = {k: _limit83(port, row) for k, (port, row) in shadows.items()}
    check("ufw limit: a LIMIT appended below an ALLOW it never reaches — the OpenSSH profile, a "
          "port list, a destination before the port, an every-port allow, a range, a DENY above it, or "
          "a (v6) allow above the (v6) LIMIT — is NOT reported rate limited; the answer names the rule matched first",
          all(not ok and "is still matched first by" in msg for ok, msg in got.values()),
          repr({k: v for k, v in got.items() if v[0] or "is still matched first by" not in v[1]}))
    prof = _limit83(443, _ALLOW_ROW83 % "Nginx Full")
    check("ufw limit: ...and an app profile whose ports the panel cannot read is 'cannot confirm', "
          "never success", not prof[0] and "application profile" in prof[1], repr(prof))


def _limit_reached83():
    # Rules that must NOT count as matching first: none admits a public TCP connection to the port.
    harmless = {
        "loopback iface": (22, "%-27sALLOW IN    Anywhere" % "22/tcp on lo"),
        "docker iface": (22, "%-27sALLOW IN    Anywhere" % "22/tcp on docker0"),
        "tailscale iface": (22, "%-27sALLOW IN    Anywhere" % "22/tcp on tailscale0"),
        "loopback source": (22, "%-27sALLOW IN    127.0.0.1" % "22/tcp"),
        "one source": (22, "%-27sALLOW IN    198.51.100.7" % "22/tcp"),
        "UDP only": (22, _ALLOW_ROW83 % "22/udp"),
        "UDP list": (27015, _ALLOW_ROW83 % "27015,27016/udp"),
        "OUT": (22, "%-27sALLOW OUT   Anywhere" % "22/tcp"),
        "FWD": (22, "%-27sALLOW FWD   Anywhere" % "22/tcp"),
        "v6 on lo": (22, "%-27sALLOW IN    Anywhere (v6)" % "22/tcp (v6) on lo"),
        "v6 one source": (22, "%-27sALLOW IN    2001:db8::7" % "22/tcp (v6)"),
        "multicast": (22, _ALLOW_ROW83 % "224.0.0.251"),
        "UDP every port": (22, "%-27sALLOW IN    Anywhere/udp" % "Anywhere"),
        "profile, other port": (27015, _ALLOW_ROW83 % "OpenSSH"),
        "other port": (22, _ALLOW_ROW83 % "2222/tcp"),
    }
    got = {k: _limit83(port, row) for k, (port, row) in harmless.items()}
    check("ufw limit: ...while a rule no public TCP connection to the port matches (loopback, "
          "docker or tailscale interface, a loopback or single source, UDP, OUT, FWD, a v6 rule on lo or "
          "for one v6 source, "
          "multicast, another port) still lets the limit count as reached",
          all(ok for ok, _m in got.values()), repr({k: v for k, v in got.items() if not v[0]}))
    check("ufw limit: ...and a host with no rule for the port at all is limited (control)",
          _limit83(22)[0] is True, repr(_limit83(22)))


def _public_ssh83():
    def mode(*rows):
        ufw = _Ufw83(*rows)
        _p9_patch(_p9_core, "run_privileged", lambda s, v, a=(), **k: (ufw.plain(), "", 0))
        return _hosts83.remote_public_ssh_status(NS(id=-83)).get("mode")
    got = {
        "list": mode(_ALLOW_ROW83 % "22,80/tcp"),
        "destination": mode(_ALLOW_ROW83 % "203.0.113.5 22/tcp"),
        "profile then limit": mode(_ALLOW_ROW83 % "OpenSSH", "%-27sLIMIT IN    Anywhere" % "22/tcp"),
        "limit": mode("%-27sLIMIT IN    Anywhere" % "22/tcp"),
        "nothing": mode(_ALLOW_ROW83 % "80/tcp"),
        "port 2222": mode(_ALLOW_ROW83 % "2222/tcp"),
    }
    check("public ssh: a host whose 22 is open through a port list or a destination reads 'allow', "
          "not 'off' (\"reachable over the tailnet only\"), and the OpenSSH profile above a LIMIT "
          "reads 'allow'; a plain LIMIT, no rule and port 2222 read as before",
          got == {"list": "allow", "destination": "allow", "profile then limit": "allow",
                  "limit": "limit", "nothing": "off", "port 2222": "off"}, repr(got))


def _ssh_move83():
    def opened(*rows):
        ufw, asked = _Ufw83(*rows), []
        _p9_patch(_p9_core, "run_privileged", ufw.run)
        _p9_patch(_hosts83, "remote_ufw_open_port", lambda s, p, proto, comment="": asked.append(p) or (True, ""))
        res = _hosts83._open_ssh_port_rule(NS(id=-83, name="p83"), 2222, ["22"])
        return res, asked
    got = {
        "to one address": opened(_ALLOW_ROW83 % "203.0.113.5 2222/tcp"),
        "list": opened(_ALLOW_ROW83 % "2222,2223/tcp"),
        "every port": opened(_ALLOW_ROW83 % "Anywhere"),
        "nothing": opened(),
        "DENY": opened("%-27sDENY IN     Anywhere" % "2222/tcp")[1],
    }
    check("ssh port move: an allow to ONE destination address does not count as the new port being "
          "open (the host's other addresses still meet the default deny), while a port list or an "
          "every-port allow does; no rule opens it, and a DENY opens nothing",
          got == {"to one address": ((True, None), [2222]), "list": ((False, None), []),
                  "every port": ((False, None), []), "nothing": ((True, None), [2222]), "DENY": []},
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Tailscale join: what `tailscale up` refuses is refused before forwarding is switched on
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ts_join83():
    routes = {r: _hosts83._r20a_routes_or_none(r)
              for r in ("192.168.1.5/24", "10.0.0.1", "192.168.1.0/24, 10.0.0.0/8", "", "-")}
    check("tailscale routes: a prefix with host bits (a gateway typed for its LAN) and a bare "
          "address are refused, as tailscale's CalcAdvertiseRoutes refuses them; networks pass",
          routes == {"192.168.1.5/24": None, "10.0.0.1": None,
                     "192.168.1.0/24, 10.0.0.0/8": "192.168.1.0/24,10.0.0.0/8", "": "", "-": ""},
          repr(routes))
    seen = []
    # Answered from the start: a join that went on past a refusal (the defect) must reach this
    # stand-in and be seen, not the tripwire, whose raise would end the part instead of the check.
    _p9_patch(_hosts83, "remote_check_tailscale", lambda s: {"running": True, "tailscale_ip": "x",
                                                              "dns_name": "y"})
    _p9_patch(_p9_core, "write_root_file", lambda s, t, c, timeout=15: seen.append(("write", t)) or ("", "", 0))
    _p9_patch(_p9_core, "run_privileged", lambda s, v, a=(), **k: seen.append((v,)) or ("", "", 0))
    try:
        _hosts83.remote_bootstrap_tailscale(NS(id=-83), auth_key="bad'key", advertise_routes="10.0.0.0/8")
        out = "returned"
    except _priv83.VerbError:
        out = "VerbError"
    except Exception as exc:  # noqa: BLE001 - reported by class in the check below
        out = type(exc).__name__
    check("tailscale join: an auth key the verb refuses is refused BEFORE IP forwarding is written "
          "and loaded (it was left forwarding with nothing joined), and still raises the VerbError "
          "the route answers 400 for", (out, seen) == ("VerbError", []), repr((out, seen)))
    try:
        ok = _hosts83.remote_tailscale_up_url(NS(id=-83), advertise_routes="192.168.1.5/24")
    except Exception as exc:  # noqa: BLE001 - reported by class in the check below
        ok = ("raised", type(exc).__name__)
    check("tailscale join: ...and the login-link flow refuses a host-bits route before any write",
          ok[0] is False and seen == [], repr((ok, seen)))
    del seen[:]
    _hosts83.remote_bootstrap_tailscale(NS(id=-83), auth_key="p83" + "k" * 12,   # built: no key literal
                                        advertise_routes="10.0.0.0/8")
    check("tailscale join: ...while a usable key with a network route still writes forwarding "
          "first and joins (control)",
          seen[:2] == [("write", "sysctl-tailscale"), ("sysctl-reload",)]
          and ("tailscale-up-key",) in seen, repr(seen))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A bracketed or non-canonical IPv6 host: one canonical text, every reader
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Client83:
    def __init__(self):
        self.hosts = []

    def connect(self, host, **k):
        self.hosts.append(host)


def _brackets83(client, rid):
    canon = [_val83.canonical_host(h) for h in ("[2001:db8::5]", "fd7a:115c:a1e0:0:0:0:0:1",
                                               "fd7a:115c:a1e0:ab12:4843:cd96:6258:0b01",
                                               "vps.example", "[vps.example]", "fe80::1%eth0")]
    check("host: canonical_host drops the brackets around an address and spells it canonically; a "
          "name, a bracketed name and a zone id are left for HOST_RE to judge",
          canon == ["2001:db8::5", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0:ab12:4843:cd96:6258:b01",
                    "vps.example", "[vps.example]", "fe80::1%eth0"], repr(canon))
    check("host: HOST_RE refuses brackets (`[x]` is no host ssh or paramiko resolves)",
          not _val83.HOST_RE.match("[vps.example]") and not _val83.HOST_RE.match("[2001:db8::5]")
          and _val83.HOST_RE.match("2001:db8::5"), "")
    with _p9.app_context():
        assigned = RemoteServer(name="p83-probe", host="[2001:db8::5]", username="admin").host
    check("host: the model stores an assignment canonical, whatever wrote it (the add and edit "
          "forms, the Tailscale move, a restore)", assigned == "2001:db8::5", repr(assigned))
    r = client.post("/remotes/%d/edit" % rid, data={"host": "[2001:db8::83]", "ssh_port": "22"})
    with _p9.app_context():
        stored = db.session.get(RemoteServer, rid).host
    check("host: the edit form stores `[2001:db8::83]` as the address it names (it stored the "
          "brackets, and every command to the host failed)",
          r.status_code in (200, 302) and stored == "2001:db8::83", repr((r.status_code, stored)))
    _stored_brackets83(rid)


def _stored_brackets83(rid):
    with _p9.app_context():
        tbl = RemoteServer.__table__
        db.session.execute(tbl.update().where(tbl.c.id == rid).values(host="[fd7a:115c:a1e0::83]"))
        db.session.commit()
        db.session.expire_all()
        _m83._r21b_canonical_remote_hosts()
        db.session.commit()
        db.session.expire_all()
        migrated = db.session.get(RemoteServer, rid).host
        db.session.execute(tbl.update().where(tbl.c.id == rid).values(host="p83.example.invalid"))
        db.session.commit()
    check("host: data migration 2 brings a row stored with brackets into canonical form",
          migrated == "fd7a:115c:a1e0::83", repr(migrated))
    dialled = []
    for method in ("key", "password"):
        c = _Client83()
        _p9_core._connect_by_auth_method(c, NS(auth_method=method, host="[2001:db8::5]", port=22,
                                               username="admin"), "cred", 5)
        dialled += c.hosts
    dialled.append(_p9_core._resolve_ts_host(NS(host="[fd7a:115c:a1e0::1234]")))
    check("host: ...and a row not migrated yet is dialled without them, on the key, password and "
          "tailscale paths", dialled == ["2001:db8::5", "2001:db8::5", "fd7a:115c:a1e0::1234"],
          repr(dialled))


def _peers83():
    peers = [{"ips": ["100.101.1.2", "fd7a:115c:a1e0::1"], "dns_name": "vps-one.tail1.ts.net."}]
    found = {h: bool(_dbh83.match_peer(h, peers))
             for h in ("fd7a:115c:a1e0:0:0:0:0:1", "[fd7a:115c:a1e0::1]", "FD7A:115C:A1E0::0001",
                       "vps-one", "fd7a:115c:a1e0::2")}
    check("debug report: a Tailscale host stored in any spelling of its peer's IPv6 address, or in "
          "brackets, matches that peer; a name still does, and another address does not",
          found == {"fd7a:115c:a1e0:0:0:0:0:1": True, "[fd7a:115c:a1e0::1]": True,
                    "FD7A:115C:A1E0::0001": True, "vps-one": True, "fd7a:115c:a1e0::2": False},
          repr(found))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The file guards, in real bash: a trailing newline, and a symlinked /home
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TREE83 = _tempfile83.mkdtemp(prefix="p83-")


def _tree83(linked):
    """A fixture home for p83u: `foo/bar/f` and `foo<LF>/bar`, `cfg` and `cfg<LF>`, a link out."""
    _shutil83.rmtree(_TREE83)
    os.makedirs(_TREE83)
    home = os.path.join(_TREE83, "data/home/p83u" if linked else "home/p83u")
    os.makedirs(os.path.join(home, "foo", "bar"))
    os.makedirs(os.path.join(home, "foo\n"))
    os.makedirs(os.path.join(_TREE83, "elsewhere"))
    with open(os.path.join(home, "foo\n", "bar"), "w", encoding="utf-8") as fh:
        fh.write("nl")
    for name, text in (("cfg", "plain-cfg"), ("cfg\n", "nl-cfg"), ("ren", "r")):
        with open(os.path.join(home, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    os.symlink(os.path.join(_TREE83, "elsewhere"), os.path.join(home, "out"))
    if linked:
        os.symlink(os.path.join(_TREE83, "data/home"), os.path.join(_TREE83, "home"))


def _bash83(script, stdin=None):
    script = script.replace("/home/p83u", _TREE83 + "/home/p83u")
    r = _sp83.run(["/bin/bash", "-c", script], input=stdin,  # nosec B603 - this part's own text
                  capture_output=True, text=True, timeout=30)
    return r.stdout, r.returncode


def _guards83(linked):
    _tree83(linked)
    home = "/home/p83u"
    out = {
        "guard": _bash83(_files83._guarded("p83u", home + "/cfg", "echo IN"))[0].strip(),
        "guard link out": _bash83(_files83._guarded("p83u", home + "/out", "echo IN"))[0].strip(),
        "delete": _bash83(_files83._protected_resolved("p83u", home + "/foo\n/bar", "x",
                                                       'printf "[%s]" "${t#"$h"/}"'))[0],
        "rename": _bash83(_files83._protected_resolved(
            "p83u", home + "/ren", "x", _files83._rename_inner(home + "/ren", "ren2", "p83u", "x")))[0].strip(),
        "create": _bash83(_files83._protected_resolved(
            "p83u", home + "/new", "x", _files83._create_inner(home + "/new", "file", "p83u", "x")))[0].strip(),
        "download nl": _bash83(_files83._remote_read_command("p83u", False), stdin="cfg\n")[0],
        "download": _bash83(_files83._remote_read_command("p83u", False), stdin="cfg")[0],
        "tar": _bash83(_files83._remote_read_command("p83u", True) + " | tar tzf -", stdin="foo\n")[0],
    }
    return out


def _files83_checks():
    _p9_patch(_p9_core, "game_user_cmd", lambda user, inner, selfname=None: inner)
    want = {"guard": "IN", "guard link out": _files83._OUTSIDE_HOME, "delete": "[foo\n/bar]",
            "rename": _files83._RENAME_DONE, "create": _files83._CREATE_DONE,
            "download nl": "nl-cfg", "download": "plain-cfg", "tar": "foo\\n/\nfoo\\n/bar\n"}
    plain = _guards83(False)
    check("files: a name ending in a newline is the file the guards act on — a download of "
          "`cfg<LF>` reads it (not `cfg`), its folder's tar holds it, and a delete of `foo<LF>/bar` "
          "removes that one, not `foo/bar`",
          {k: plain[k] for k in ("delete", "download nl", "download", "tar")}
          == {k: want[k] for k in ("delete", "download nl", "download", "tar")}, repr(plain))
    check("files: ...and on a plain /home the guards, rename and create work, and a link out of the "
          "home is still outside it (control)", plain == want, repr(plain))
    linked = _guards83(True)
    check("files: on a host whose /home is a symlink, the home is not 'outside the home': browse, "
          "delete, rename, create and download all work there",
          {k: v for k, v in linked.items() if k != "guard link out"}
          == {k: v for k, v in want.items() if k != "guard link out"}, repr(linked))
    check("files: ...while a link from that home to somewhere else is still refused as outside it",
          linked["guard link out"] == _files83._OUTSIDE_HOME, repr(linked["guard link out"]))
    _shutil83.rmtree(_TREE83, ignore_errors=True)


def _game_config83():
    said = ("__LGSMP_REAL_HOME__=/data/home/p83u\n  Config file: /data/home/p83u/serverfiles/cfg/server.cfg\n"
            + _files83._DETAILS_DONE)
    _p9_patch(_p9_core, "shell_as_game_user", lambda *a, **k: (said, "", 0))
    _p9_patch(_files83, "read_file", lambda s, u, rel: ("hostname x", None))
    got = _files83.lgsm_game_config(NS(id=-83), "p83u", "p83server")
    check("files: on a host whose /home is a symlink, the game config LinuxGSM reports under the "
          "real home is found (it read \"no editable game config\")",
          got.get("rel") == "serverfiles/cfg/server.cfg", repr(got))
    said = ("__LGSMP_REAL_HOME__=/home/p83u\n  Config file: /srv/other/server.cfg\n" + _files83._DETAILS_DONE)
    got = _files83.lgsm_game_config(NS(id=-83), "p83u", "p83server")
    check("files: ...and a path under neither home is still no editable config (control)",
          got.get("rel") is None, repr(got))


def _serving83():
    scans = []
    _p9_patch(_game83.portscan, "_remote_listening_ports", lambda s: scans.append(1) or {27015})
    got = (_game83._really_serving(NS(), NS(port=float("inf"))),
           _game83._really_serving(NS(), NS(port=27016)))
    check("status: a port stored as REAL infinity is 'no port', so LinuxGSM's STARTED stands (it "
          "read offline), while a real port that is not listening is still offline (control)",
          got == (True, False) and len(scans) == 1, repr((got, scans)))


def _discover83():
    script = _p9_core._discover_scan_script()
    check("discover: each LinuxGSM config read is bounded by `timeout` where the host has it, so a "
          "file swapped for a FIFO after its regular-file test cannot hold root's scan to its 45 s "
          "timeout", 'T=; command -v timeout >/dev/null 2>&1 && T="timeout 5"; ' in script
          and '$T head -c ' in script, script[:200])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Audits, and the Ubuntu Pro token
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _down83(*a, **k):
    raise ConnectionError("Connection to p83.example.invalid:22 timed out.")


def _action_once83(client, sid):
    _p9_patch(_sm83, "run_as_game_user", _down83)
    _p9_patch(_p9_sd, "_after_power_action", lambda *a, **k: None)
    _p9_patch(_p9_sd, "_noop_power_refusal", lambda *a, **k: None)
    n = _p9_audit_count("details_server")
    client.post("/server/%d/action" % sid, data={"action": "details"})
    check("audit: a short action posted to the form route whose SSH raised is ONE failed row (the "
          "wrapper's), not two", _p9_audit_count("details_server") - n == 1,
          repr(_p9_audit_count("details_server") - n))
    _p9_patch(_p9_sd, "_run_action", _down83)
    n = _p9_audit_count("start_server")
    client.post("/server/%d/action" % sid, data={"action": "start"})
    check("audit: ...while a raise from outside that wrapper is still audited by the route (control)",
          _p9_audit_count("start_server") - n == 1, repr(_p9_audit_count("start_server") - n))


def _cron_readback83(client, sid):
    _p9_patch(_p9_sf, "_write_refused", lambda *a, **k: None)
    _p9_patch(_p9_sf, "add_cron_job", lambda *a, **k: (True, "Added"))
    _p9_patch(_sm83, "list_cron_jobs", _down83)
    _p9_patch(_sm83, "delete_cron_job", lambda *a, **k: (True, "Deleted"))
    got = {}
    for act, url, body in (("cron_add", "/api/server/%d/cron" % sid, {"schedule": "0 4 * * *", "command": "x"}),
                           ("cron_delete", "/api/server/%d/cron/delete" % sid, {"raw": "0 4 * * * x"})):
        n = _p9_audit_count(act)
        r = client.post(url, json=body)
        got[act] = (r.status_code, (r.get_json() or {}).get("success"), _p9_audit_count(act) - n,
                    _p9_audit(act).success)
    check("audit: a crontab add and delete that WORKED are audited, and answered as done, when the "
          "read-back after them raises (no row, and \"request failed\")",
          got == {"cron_add": (200, True, 1, True), "cron_delete": (200, True, 1, True)}, repr(got))


def _toggles83(client, sid):
    got = {}
    for act, url, name, body in (
            ("set_autostart", "/api/server/%d/autostart" % sid, "set_autostart", {"enabled": True}),
            ("set_daily_restart", "/api/server/%d/daily-restart" % sid, "set_daily_restart",
             {"enabled": True, "time": "05:00", "tz": "Etc/UTC"})):
        _p9_patch(_p9_sd, "_host_timezone_cached", lambda remote: "Etc/UTC")
        _p9_patch(_p9_sd, "_autostart_reboot_gate", lambda *a, **k: None)
        _p9_patch(_p9_sd, name, lambda *a, **k: (False, "p83: crontab refused"))
        n = _p9_audit_count(act)
        r = client.post(url, json=body)
        refused = (r.status_code, _p9_audit_count(act) - n, _p9_audit(act).success)
        _p9_patch(_p9_sd, name, _down83)
        n = _p9_audit_count(act)
        try:
            code = client.post(url, json=body).status_code
        except ConnectionError:
            code = "raised"
        got[act] = (refused, (code, _p9_audit_count(act) - n, _p9_audit(act).success))
    check("audit: Autostart and the daily restart audit a crontab write the host refused, and one "
          "that raised, as failed (neither left a row on any transport)",
          got == {"set_autostart": ((500, 1, False), (500, 1, False)),
                  "set_daily_restart": ((500, 1, False), (500, 1, False))}, repr(got))


def _queued83(sid):
    _p9_patch(_sm83, "run_as_game_user", _down83)
    _p9_patch(_p9_sh, "_mark_expected_offline", lambda *a, **k: None)
    _p9_sh._queued_action_failures.pop(sid, None)
    seen = []
    with _p9.app_context():
        for _ in range(_p9_sh._QUEUED_ACTION_ATTEMPTS):
            gs = db.session.get(GameServer, sid)
            if not gs.stop_pending:
                gs.stop_pending = True
                db.session.commit()
            try:
                _p9_sh._run_queued_action(_p9, gs)
            except ConnectionError:
                pass  # the raise goes on to the sweep; what is checked is the count it left
            gs = db.session.get(GameServer, sid)
            seen.append((_p9_sh._queued_action_failures.get(sid), gs.stop_pending))
    want = [(i, True) for i in range(1, _p9_sh._QUEUED_ACTION_ATTEMPTS)] + [(None, False)]
    check("queued action: a queued stop whose run RAISES counts as an attempt, and the last one "
          "clears the queue (the raise left before the counter, so it ran again every tick)",
          seen == want, repr(seen))


def _pro83(client, rid):
    ran = []
    _p9_patch(_p9_core, "run_privileged", lambda s, v, a=(), **k: ran.append(v) or ("", "", 0))
    # Built at run time: no token-shaped literal in the tree (Gitleaks reads every commit).
    good = "C" + "1a2b" * 4
    r = client.post("/api/remote/%d/pro-attach" % rid, json={"token": good[:6] + "-" + good[6:]})
    body = r.get_json() or {}
    check("ubuntu pro: a token the verb refuses is answered with a refusal, not \"Something went "
          "wrong\" and a traceback, and nothing runs on the host",
          (r.status_code, body.get("success"), ran) == (200, False, [])
          and "valid Ubuntu Pro token" in (body.get("message") or ""), repr((r.status_code, body, ran)))
    client.post("/api/remote/%d/pro-attach" % rid, json={"token": good})
    check("ubuntu pro: ...while a well-formed token still reaches the attach verb (control)",
          "pro-attach" in ran, repr(ran))


try:
    _p9_arm(who="part83")
    _RID83, _GS83, _ADMIN83 = _setup83()
    _A83 = _p9_client(_ADMIN83)
    _limit_shadowed83()
    _limit_reached83()
    _public_ssh83()
    _ssh_move83()
    _ts_join83()
    _brackets83(_A83, _RID83)
    _peers83()
    _files83_checks()
    _game_config83()
    _serving83()
    _discover83()
    _action_once83(_A83, _GS83)
    _cron_readback83(_A83, _GS83)
    _toggles83(_A83, _GS83)
    _queued83(_GS83)
    _pro83(_A83, _RID83)
finally:
    _p9_restore_all()
    _cleanup83()
    _shutil83.rmtree(_TREE83, ignore_errors=True)

check("part83: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP83_START, repr(_P9_TRIPPED[_TRIP83_START:][:6]))
