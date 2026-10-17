"""Part 89 of the unit suite: the thirteenth review's ssh_manager and route fixes (review 1015d, builder B).

* "Close Port 22" decides from a read-back, not from the delete's exit code. ufw exits 0 deleting
  a rule that is not there ("Could not delete non-existent rule", measured on the test VPS), and
  every host the panel bootstrapped holds SSH open with `22/tcp LIMIT`, which `delete allow` never
  matched: the button said "Port 22 rule removed from UFW" with port 22 open to the internet. It
  now removes every shape the panel knows (ALLOW, LIMIT, the OpenSSH profile, a bare 22) and names
  the rule left when port 22 is still open. The Tailscale migration's close removes the same set.

* Closing any port reads back too (a bare allow or a LIMIT left the port open under "closed"), and
  removing an "allow from" rule that was never there is no longer "removed".

* Moving SSH to a port that an IPv6-only allow already opens does not count the panel's v4 rule
  as its own to delete: ufw takes the operator's v6 rule over, and the revert removed it.

* The file editor's save and an upload over the live console's log are refused (the replace gave
  the log a new inode, and tmux kept writing to the old one: the console went silent until a
  restart), by name and through a link; a chunked save whose finish fails leaves no
  `<name>.paneltmp` behind.

HOW IT RUNS. Stand-in ufw tables behind run_privileged (both families, ufw's own delete-by-spec
matching and its real rc 0 for an absent rule); the file writers run `bash` for real over this
part's own fixture tree (no sudo, no host); one route on part12's app with a recorder.
"""
import os
import shutil as _shutil89
import subprocess as _sp89  # nosec B404 - runs bash over this part's own fixture tree
import tempfile as _tempfile89
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_patch, _p9_restore_all,
                         _p9_sd, _p9_sf)
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import files as _files89, hosts as _hosts89
from panel.security import auth as _auth89

_TRIP89_START = len(_P9_TRIPPED)
_mine89 = {"hosts": [], "servers": [], "users": []}
_TMP89 = _tempfile89.mkdtemp(prefix="p89-")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. ufw: a stand-in with both families and ufw's own delete-by-spec answers
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HEAD89 = ("Status: active\n\n     To                         Action      From\n"
           "     --                         ------      ----\n")


class _Ufw89:
    """`ufw status` over a rule table; deletes as ufw does them.

    A rule is (to, action, src, v4, v6): `src` "Anywhere" or an address, `to` may carry " on <if>",
    action "ALLOW IN" / "LIMIT IN" / "DENY IN" / "ALLOW OUT" / "ALLOW FWD". A delete by spec removes
    the public inbound rule with exactly that To and action, in each family that has it, answering
    per family and exiting 0 whether or not anything matched (backend_iptables.set_rule).
    """

    def __init__(self, *rules):
        self.rules = [list(r) for r in rules]
        self.verbs = []

    @staticmethod
    def _v6_row(to, act, src):
        """One rule's IPv6 row: ufw puts (v6) after the port, before any interface."""
        base, _sep, iface = to.partition(" on ")
        to = base + " (v6)" + ((" on " + iface) if iface else "")
        return "%-27s%-12s%s" % (to, act, src + " (v6)" if src == "Anywhere" else src)

    def status(self):
        rows = ["%-27s%-12s%s" % (r[0], r[1], r[2]) for r in self.rules if r[3]]
        rows += [self._v6_row(*r[:3]) for r in self.rules if r[4]]
        return _HEAD89 + "".join(r + "\n" for r in rows)

    def _delete_family(self, i, to, act):
        """Remove the family-`i` half of every public `act` rule for exactly `to`; True if any."""
        hit = [r for r in self.rules if r[:3] == [to, act, "Anywhere"] and r[i]]
        for r in hit:
            r[i] = False
        return bool(hit)

    def _delete(self, to, act):
        said = [("Rule deleted" if self._delete_family(i, to, act) else "Could not delete non-existent rule")
                + fam for i, fam in ((3, ""), (4, " (v6)"))]
        self.rules = [r for r in self.rules if r[3] or r[4]]
        return "\n".join(said), "", 0

    def run(self, server, verb, args=(), timeout=30, **k):
        a = list(args)
        self.verbs.append((verb, a))
        if verb == "ufw-status":
            return self.status(), "", 0
        if verb in ("ufw-delete-allow-port", "ufw-delete-allow-app"):
            return self._delete(a[0], "ALLOW IN")
        if verb == "ufw-delete-limit-port":
            return self._delete(a[0], "LIMIT IN")
        if verb == "ufw-delete-allow-proto-port":
            return self._delete("%s/%s" % (a[1], a[0]), "ALLOW IN")
        if verb == "ufw-allow-from-port" and a[0] == "0.0.0.0/0":   # NOSONAR(S1313) - ufw's IPv4 "any"
            # ufw lists an IPv4-only allow from 0.0.0.0/0 as "Anywhere", in the v4 family only.
            self.rules.append(["%s/%s" % (a[1], a[2]), "ALLOW IN", "Anywhere", True, False])
        return "", "", 0

    def left(self):
        return [r[0] + " " + r[1].split()[0] for r in self.rules]


def _both89(to, act="ALLOW IN", src="Anywhere"):
    return (to, act, src, True, True)


# Rules that are no public way in to TCP port `p`: they must neither count as open nor be deleted.
def _harmless89(p):
    return [("%d/tcp on lo" % p, "ALLOW IN", "Anywhere", True, True),
            ("%d/tcp on docker0" % p, "ALLOW IN", "Anywhere", True, False),
            ("%d/tcp on tailscale0" % p, "ALLOW IN", "Anywhere", True, True),
            ("%d/tcp" % p, "ALLOW IN", "127.0.0.1", True, False),
            ("%d/tcp" % p, "ALLOW IN", "::1", False, True),
            ("%d/udp" % p, "ALLOW IN", "Anywhere", True, True),
            ("%d/tcp" % p, "ALLOW OUT", "Anywhere", True, True),
            ("%d/tcp" % p, "ALLOW FWD", "Anywhere", True, False)]


def _close22_89(*rules):
    ufw = _Ufw89(*rules)
    _p9_patch(_p9_core, "run_privileged", ufw.run)
    ok, msg = _hosts89.remote_ufw_close_port_22(NS(id=-89, name="p89"))
    return ok, str(msg), ufw


def _close22_checks89():
    closes = {
        "bootstrap LIMIT": [_both89("22/tcp", "LIMIT IN")],
        "22/tcp ALLOW": [_both89("22/tcp")],
        "OpenSSH profile": [_both89("OpenSSH")],
        "bare 22": [_both89("22")],
        "all four": [_both89("OpenSSH"), _both89("22"), _both89("22/tcp", "LIMIT IN")],
        "v6-only LIMIT": [("22/tcp", "LIMIT IN", "Anywhere", False, True)],
        "with harmless rules": [_both89("22/tcp", "LIMIT IN")] + _harmless89(22),
        "DENY above a list": [_both89("22/tcp", "DENY IN"), _both89("22,80/tcp")],
    }
    got = {k: _close22_left89(*rules) for k, rules in closes.items()}
    check("close port 22: every shape that opens 22/tcp to the public goes and the read-back says "
          "closed — the bootstrap's 22/tcp LIMIT (it said \"removed\" and left it), an ALLOW, the "
          "OpenSSH profile, a bare 22, a v6-only LIMIT — while loopback/docker/tailscale interfaces, "
          "loopback sources, UDP, OUT, FWD and a DENY above everything stay and still read closed",
          all(v == (True, []) for v in got.values()), repr({k: v for k, v in got.items() if v != (True, [])}))
    _close22_kept89()
    _close22_refused89()


def _close22_left89(*rules):
    """(ok, the public 22 rules of the panel's shapes left) after Close Port 22 over `rules`."""
    ok, _msg, ufw = _close22_89(*rules)
    return ok, [r for r in ufw.rules if r[0] in ("22/tcp", "22", "OpenSSH")
                and r[1] in ("ALLOW IN", "LIMIT IN") and r[2] == "Anywhere"]


def _close22_kept89():
    _ok, _m, ufw = _close22_89(*([_both89("22/tcp", "LIMIT IN")] + _harmless89(22)))
    check("close port 22: ...and the rules that are no public way in are left exactly as they were",
          sorted(ufw.left()) == sorted(r[0] + " " + r[1].split()[0] for r in _harmless89(22)), repr(ufw.left()))


def _close22_refused89():
    left = {
        "port list": [_both89("22,80/tcp")],
        "destination": [("203.0.113.5 22/tcp", "ALLOW IN", "Anywhere", True, False)],
        "every port": [_both89("Anywhere")],
        "v6 list only": [("22,80/tcp", "ALLOW IN", "Anywhere", False, True)],
        "range": [_both89("20:30/tcp", "LIMIT IN")],
    }
    got = {k: _close22_89(*rules)[:2] for k, rules in left.items()}
    check("close port 22: a rule the panel does not remove that still opens 22 (a port list, a "
          "destination, an every-port allow, a v6-only list, a range LIMIT) is a failure naming it, "
          "never \"Port 22 rule removed from UFW\"",
          all(not ok and "Port 22 is still open to the public" in msg and "`" in msg for ok, msg in got.values()),
          repr({k: v for k, v in got.items() if v[0] or "still open" not in v[1]}))


def _migration89():
    ufw = _Ufw89(_both89("22/tcp", "LIMIT IN"), _both89("OpenSSH"))
    _p9_patch(_p9_core, "run_privileged", ufw.run)
    _hosts89._r15c_delete_port_22(NS(id=-89))
    check("tailscale migration: its close removes the bootstrap's 22/tcp LIMIT and the OpenSSH "
          "profile too (it deleted only `allow 22/tcp`, and the public door stayed)",
          ufw.left() == [], repr((ufw.left(), ufw.verbs)))


def _close_port89():
    def close(port, proto, *rules):
        ufw = _Ufw89(*rules)
        _p9_patch(_p9_core, "run_privileged", ufw.run)
        ok, msg = _hosts89.remote_ufw_close_port(NS(id=-89, name="p89"), port, proto, force=True)
        return ok, str(msg)
    still = {
        "bare allow, tcp closed": close(27015, "tcp", _both89("27015")),
        "LIMIT": close(27015, "tcp", _both89("27015/tcp", "LIMIT IN")),
        "v6-only bare": close(27015, "both", ("27015", "LIMIT IN", "Anywhere", False, True)),
        "list": close(27015, "udp", _both89("27015,27016/udp")),
    }
    check("ufw close: a port still open after the delete — a bare allow under a tcp close, a LIMIT, "
          "a v6-only LIMIT, a list — is not \"closed\" (ufw answered rc 0 for nothing deleted)",
          all(not ok and "is still open" in msg for ok, msg in still.values()), repr(still))
    closed = {
        "its rule": close(27015, "tcp", _both89("27015/tcp")),
        "nothing there": close(27015, "tcp"),
        "harmless only": close(27015, "tcp", *_harmless89(27015)),
        "bare, both": close(27015, "both", _both89("27015")),
        "DENY above": close(27015, "tcp", _both89("27015/tcp", "DENY IN"), _both89("27000:27030/tcp")),
    }
    check("ufw close: ...while a port nothing public lets in any more is closed (its own rule gone, "
          "never there, only interface/loopback/UDP/OUT/FWD rules, or a DENY first)",
          all(ok for ok, _m in closed.values()), repr({k: v for k, v in closed.items() if not v[0]}))


def _allow_from89():
    ufw = _Ufw89()
    _p9_patch(_hosts89.firewall, "remote_ufw_status", lambda s: {"installed": True, "groups": []})
    _p9_patch(_p9_core, "run_privileged", lambda s, v, a=(), **k: (
        ("Could not delete non-existent rule", "", 0) if v == "ufw-delete-allow-from-port" else ufw.run(s, v, a)))
    ok, msg = _hosts89.remote_ufw_allow_from(NS(id=-89, name="p89"), "198.51.100.7", 22, allow=False)
    check("ufw allow-from: removing a rule that is not there (ufw: rc 0, \"Could not delete "
          "non-existent rule\") is not reported removed", not ok and "nothing was removed" in str(msg),
          repr((ok, msg)))


def _undeny89():
    def unblock(*rows, read_rc=0,
                deleted="Could not delete non-existent rule\nCould not delete non-existent rule (v6)"):
        verbs = []

        def run(server, verb, args=(), timeout=30, **k):
            verbs.append(verb)
            if verb == "ufw-delete-deny-ip":
                return deleted, "", 0
            if verb == "ufw-status":
                return (_HEAD89 + "".join("%-27s%-12s%s\n" % r for r in rows)), "", read_rc
            return "", "", 0
        _p9_patch(_p9_core, "run_privileged", run)
        ok, msg = _hosts89.remote_ufw_undeny_ip(NS(id=-89, name="p89"), "198.51.100.7")
        return ok, str(msg), verbs
    still = unblock(("Anywhere", "REJECT IN", "198.51.100.7"))
    check("ufw unblock on a remote: a delete that matched no rule (ufw: rc 0, \"Could not delete "
          "non-existent rule\") while a REJECT still blocks the address is not \"Unblocked\"",
          not still[0] and "still blocked" in still[1]
          and still[2] == ["ufw-delete-deny-ip", "ufw-status"], repr(still))
    gone = {"unlisted": unblock(("22/tcp", "LIMIT IN", "Anywhere")),
            "read failed": unblock(("Anywhere", "REJECT IN", "198.51.100.7"), read_rc=1,
                                   deleted="Rule deleted\nRule deleted (v6)")}
    check("ufw unblock on a remote: ...an address the read-back no longer lists, or a read-back that "
          "fails after a delete that removed a rule (the delete's answer stands), is reported "
          "unblocked (control; part98 holds the delete that removed nothing)",
          all(v[0] and v[1] == "Unblocked 198.51.100.7." for v in gone.values()), repr(gone))


def _ssh_move89():
    def opened(*rows):
        ufw, asked = _Ufw89(*rows), []
        _p9_patch(_p9_core, "run_privileged", ufw.run)
        # The allow lands in the table, as ufw's does: step 1 re-reads it to confirm the open.
        _p9_patch(_hosts89, "remote_ufw_open_port", lambda s, p, proto, comment="": asked.append(p) or ufw.rules.append(
            ["%s/%s" % (p, proto), "ALLOW IN", "Anywhere", True, True]) or (True, ""))
        return _hosts89._open_ssh_port_rule(NS(id=-89, name="p89"), 2222, ["22"]), asked
    got = {
        "v6-only allow": opened(("2222/tcp", "ALLOW IN", "Anywhere", False, True)),
        "v6-only LIMIT": opened(("2222/tcp", "LIMIT IN", "Anywhere", False, True)),
        "nothing": opened(),
        "v6 list": opened(("2222,2223/tcp", "ALLOW IN", "Anywhere", False, True)),
        "v6 on lo": opened(("2222/tcp on lo", "ALLOW IN", "Anywhere", False, True)),
    }
    check("ssh port move: an IPv6-only allow or LIMIT for exactly the new port gets only the v4 rule "
          "(review 1016b: `allow port/tcp` rewrote it), counted as the v4 rule's own to delete (the "
          "revert's `delete allow` took the operator's v6 rule with it); no rule, a v6 list or a v6 "
          "rule on lo still count as added",
          got == {"v6-only allow": ((_hosts89._R25B_V4_ADDED, None), []),
                  "v6-only LIMIT": ((_hosts89._R25B_V4_ADDED, None), []),
                  "nothing": ((True, None), [2222]), "v6 list": ((True, None), [2222]),
                  "v6 on lo": ((True, None), [2222])}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The file writers: the console log, and a chunked finish that fails
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HOME89 = os.path.join(_TMP89, "home", "p89u")
_CONSOLE89 = "log/console/p89srv-console.log"


def _bash89(script):
    r = _sp89.run(["/bin/bash", "-c", script], capture_output=True, text=True,  # nosec B603 - own text
                  timeout=30)
    return r.stdout, r.stderr, r.returncode


def _fshell89(server, user, script, timeout=30, **k):
    return _bash89(script.replace("/home/p89u", _HOME89))


def _put89(rel, data):
    path = os.path.join(_HOME89, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _tree89():
    _shutil89.rmtree(os.path.join(_TMP89, "home"), ignore_errors=True)
    _put89(_CONSOLE89, b"line 1\n")
    _put89("log/console/other.log", b"old\n")
    os.symlink(_CONSOLE89, os.path.join(_HOME89, "mylog.txt"))
    # A link whose target's folder is a FILE: the finish's mkdir fails, root or not.
    _put89("data", b"not a folder")
    os.symlink("data/big.cfg", os.path.join(_HOME89, "big.cfg"))


def _console_writes89():
    _p9_patch(_p9_core, "shell_as_game_user", _fshell89)
    _tree89()
    log = os.path.join(_HOME89, _CONSOLE89)
    ino = os.stat(log).st_ino
    big = b"B" * (70 * 1024)          # past _ONE_SHOT_B64: the chunked path
    want = _files89.WRITE_CONSOLE
    got = {
        "save by name": _files89.write_file(NS(), "p89u", _CONSOLE89, "", selfname="p89srv"),
        "save through a link": _files89.write_file(NS(), "p89u", "mylog.txt", "", selfname="p89srv"),
        "chunked through a link": _files89.write_file(NS(), "p89u", "mylog.txt", big.decode(),
                                                      selfname="p89srv"),
        "upload over it": _files89.upload_file(NS(), "p89u", "log/console", "p89srv-console.log", b"x",
                                               overwrite=True, selfname="p89srv"),
    }
    with open(log, "rb") as fh:
        body = fh.read()
    check("files: saving or uploading over the live console's log — by name, through a link, "
          "one-shot or chunked — is refused, and the log keeps its inode and its text (a rename over "
          "it gave it a new inode, and tmux went on writing to the old one)",
          all(v == (False, want) for v in got.values()) and os.stat(log).st_ino == ino
          and body == b"line 1\n" and not [n for n in os.listdir(_HOME89) if n.endswith(".paneltmp")],
          repr((got, body, os.listdir(_HOME89))))
    ok = _files89.write_file(NS(), "p89u", "log/console/other.log", "new\n", selfname="p89srv")
    with open(os.path.join(_HOME89, "log/console/other.log"), "rb") as fh:
        other = fh.read()
    check("files: ...while another file in the same folder still saves (control)",
          ok == (True, "") and other == b"new\n", repr((ok, other)))


def _chunk_leftover89():
    _p9_patch(_p9_core, "shell_as_game_user", _fshell89)
    _tree89()
    big = b"C" * (70 * 1024)
    ok, _msg = _files89._write_file_as_user(NS(), "p89u", "/home/p89u/big.cfg", big)
    check("files: a chunked save whose finish fails (the target's folder cannot be made) is a "
          "failure and leaves no `<name>.paneltmp` with the whole payload in the user's folder",
          not ok and not os.path.exists(os.path.join(_HOME89, "big.cfg.paneltmp")),
          repr((ok, sorted(os.listdir(_HOME89)))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The routes hand the writers the script name the console log is named after
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _setup89():
    with _p9.app_context():
        r = RemoteServer(name="p89-host", host="p89.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p89-css", short_name="p89css", game_type="css",
                        port=27089, installed=True, status="online")
        admin = User(username="p89_admin", password_hash=_auth89.hash_password("Str0ng!passw0rd-p89"),
                     display_name="p89 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine89["hosts"].append(r.id)
        _mine89["servers"].append(gs.id)
        _mine89["users"].append(admin.id)
        return r.id, gs.id, admin.id, gs.lgsm_name


def _cleanup89():
    with _p9.app_context():
        for i in _mine89["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        for i in _mine89["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p89%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine89[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
        db.session.commit()


def _routes89(client, sid, lgsm):
    import io as _io89
    seen = []
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_p9_sf, "write_file", lambda *a, **k: seen.append(("save", k.get("selfname"))) or (True, ""))
    _p9_patch(_p9_sf, "upload_file", lambda *a, **k: seen.append(("upload", k.get("selfname"))) or (True, ""))
    client.post("/api/server/%d/file" % sid, json={"path": "log/console/x.log", "content": "x"})
    client.post("/api/server/%d/upload" % sid, content_type="multipart/form-data",
                data={"path": "log/console", "overwrite": "1", "file": (_io89.BytesIO(b"x"), "x.log")})
    check("routes: the editor's save and an upload pass the server's script name, so the writer can "
          "refuse the live console's log", seen == [("save", lgsm), ("upload", lgsm)] and bool(lgsm),
          repr((seen, lgsm)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Leads: rows written after a raise, figures that are not numbers, a type that is an option
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _break_session89(*a, **k):
    """Leave the session refusing every write, as a commit that raised does, and raise."""
    db.session.add(User(username=None, display_name="p89 broken"))
    db.session.flush()


def _audited89(sid, action):
    with _p9.app_context():
        return [r.success for r in AuditLog.query.filter_by(game_server_id=sid, action=action).all()]


def _rollback_routes89(client, sid):
    from panel.ops import ssh_manager as _sm89
    _p9_patch(_p9_sd, "_run_action", _break_session89)
    _p9_patch(_p9_sd, "send_console_command", _break_session89)
    _p9_patch(_sm89, "list_server_commands", _break_session89)
    got = {
        "action": client.post("/server/%d/action" % sid, data={"action": "details"}).status_code,
        "command": client.post("/server/%d/command" % sid, data={"command": "say p89"}).status_code,
        "refresh": client.post("/server/%d/refresh-commands" % sid).status_code,
    }
    rows = {k: _audited89(sid, a) for k, a in (("action", "details_server"), ("command", "send_command"),
                                                ("refresh", "refresh_commands"))}
    check("routes: an action, a console command and a command-list refresh whose own commit raised "
          "answer their redirect and write the failure row (the session was not rolled back, so the "
          "row raised PendingRollbackError and the reply was a 500)",
          got == {"action": 302, "command": 302, "refresh": 302}
          and all(v == [False] for v in rows.values()), repr((got, rows)))


def _leads89():
    from panel.ops.ssh_manager import _core as _c89, cron as _cron89, game as _game89
    m = {}
    try:
        for line in ("MEM - -", "DISK 100 -", "MEM 2048 1024"):
            f = line.split()
            {"MEM": _c89._put_mem, "DISK": _c89._put_disk}[f[0]](f, m)
        raised = None
    except ValueError as e:
        raised = e
    check("metrics: a MEM or DISK line whose figures are not numbers is skipped like every other "
          "malformed line (it raised out of the live metrics); a good one still reads",
          raised is None and m == {"ram_total": 2048, "ram_used": 1024}, repr((raised, m)))
    qt = {q: _cron89._gamedig_type("cod", q) for q in ("-x", "--debug", "_a", "cod4mw")}
    check("gamedig type: a stored override starting with - or _ (which the route refuses) never "
          "reaches gamedig as an option",
          qt == {"-x": "x", "--debug": "debug", "_a": "a", "cod4mw": "cod4mw"}, repr(qt))
    _version89(_game89)
    _backup_mark89()


def _version89(_game89):
    try:
        d = _game89._version_detail({"build": "123", "updated": 10 ** 20})
    except (OverflowError, OSError, ValueError) as e:
        d = e
    check("version: an appmanifest date past time_t is left out of the hover text, which still names "
          "the build (it raised, and the version route lost the whole reading)",
          d == "Steam build 123", repr(d))


def _backup_mark89():
    from panel.routes import _shared as _sh89
    sid = -8901

    def _swap(*a, **k):
        # The server was deleted mid-backup (forget_rows dropped its entry) and a new one took the
        # id and wrote its own status.
        _sh89._game_backup_status[sid] = {"running": False, "ok": True, "msg": "new server"}
        raise RuntimeError("p89")
    try:
        _sh89._marked_backup(sid, runner=_swap)
    except RuntimeError:
        pass  # the raise is the scenario; what matters is what it left behind
    left = dict(_sh89._game_backup_status.get(sid) or {})
    try:
        _sh89._marked_backup(sid, runner=lambda: (_ for _ in ()).throw(RuntimeError("p89")))
    except RuntimeError:
        pass  # as above
    own = dict(_sh89._game_backup_status.pop(sid, None) or {})
    check("backup: a raise after the server's entry was replaced does not file \"backup error\" over "
          "the new server's status; a raise over its own mark still does (control)",
          left.get("msg") == "new server" and own.get("msg") == "backup error (RuntimeError)",
          repr((left, own)))


try:
    _p9_arm(who="part89")
    _close22_checks89()
    _migration89()
    _close_port89()
    _allow_from89()
    _undeny89()
    _ssh_move89()
    _console_writes89()
    _chunk_leftover89()
    _RID89, _GS89, _ADMIN89, _LGSM89 = _setup89()
    _A89 = _p9_client(_ADMIN89)
    _routes89(_A89, _GS89, _LGSM89)
    _rollback_routes89(_A89, _GS89)
    _leads89()
finally:
    _p9_restore_all()
    _cleanup89()
    _shutil89.rmtree(_TMP89, ignore_errors=True)

check("part89: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP89_START, repr(_P9_TRIPPED[_TRIP89_START:][:6]))
