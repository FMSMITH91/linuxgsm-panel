"""Part 86 of the unit suite: the twelfth review's ssh_manager and route fixes (review 1015c, builder B).

* The setup wizard accepts a bracketed IPv6 host (`[fd7a:115c:a1e0::1]`), as the Hosts page has
  since #430: one canonicalisation (validation.canonical_host) before the shared host check.

* The file editor's save writes THROUGH a symlink to a file in the home (it replaced the link with
  a regular file, so the game kept reading the old config while the panel said "Saved"); the read
  calls a file of blank lines text and an unreadable file unreadable, not "Binary file".

* The root-capable-account probe asks every sudo on a remote, classic sudo.ws beside sudo-rs
  (Ubuntu 26.04), and so does install.sh's fallback when the helper is missing.

* A host that is down, or presents a changed key, is _unreachable's answer from the routes that
  caught it in a catch-all (ssh-port, os-update/start, sync-ports, security/block, a game backup
  delete), and every other catch-all now says the unreachable sentence, not "Internal server error".

* Leads: a loopback-destination ufw rule is no public way in; public SSH names the rule in its
  way; an IPv6 Internet IP line does not give the game port; a fractional REAL port is not
  queried; the crontab read-back never raises from its own except; Autostart and the daily
  restart are audited before the column commit; Ubuntu Pro shows the re-trust sentence; the
  OS-updates banner knows the panel host by its transport too.

HOW IT RUNS. Routes on part12's Flask app and stubs (every stub through _p9_patch, undone in the
finally); the file guards and both sudo probes run `bash` for real over this part's own fixture
tree and stand-ins (no sudo, no host); the page script in node.
"""
import os
import shutil as _shutil86
import subprocess as _sp86  # nosec B404 - runs bash over this part's own fixture tree
import tempfile as _tempfile86
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _node47
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_core, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_rs,
                         _p9_rv, _p9_sd, _p9_sf, _p9_sh)
from unit.part83 import _ALLOW_ROW83, _limit83
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import cron as _cron86, files as _files86, game as _game86, hosts as _hosts86
from panel.routes import panel_backup as _pb86, route_helpers as _rh86
from panel.security import auth as _auth86
from sqlalchemy import text as _text86

_TRIP86_START = len(_P9_TRIPPED)
_mine86 = {"hosts": [], "servers": [], "users": []}
_TMP86 = _tempfile86.mkdtemp(prefix="p86-")


def _setup86():
    with _p9.app_context():
        r = RemoteServer(name="p86-host", host="p86.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p86-css", short_name="p86css", game_type="css",
                        port=27086, installed=True, status="online")
        admin = User(username="p86_admin", password_hash=_auth86.hash_password("Str0ng!passw0rd-p86"),
                     display_name="p86 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine86["hosts"].append(r.id)
        _mine86["servers"].append(gs.id)
        _mine86["users"].append(admin.id)
        return r.id, gs.id, admin.id


def _cleanup86():
    with _p9.app_context():
        for i in _mine86["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        for i in _mine86["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p86%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine86[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()


def _down86(*a, **k):
    raise ConnectionError("Connection to p86.example.invalid:22 timed out.")


def _bash86(script, stdin=None, env=None):
    r = _sp86.run(["/bin/bash", "-c", script], input=stdin, env=env,  # nosec B603 - this part's own text
                  capture_output=True, text=True, timeout=30)
    return r.stdout, r.stderr, r.returncode


def _standin86(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n" + body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(path, 0o700)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The setup wizard and a bracketed IPv6 host
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _wizard86():
    tried = []
    _p9_patch(_rh86, "ssh_test_connection",
              lambda host, *a, **k: tried.append(host) or (False, "p86: no connection made"))
    with _p9.test_request_context("/setup", method="POST", data={
            "name": "p86-wiz", "host": "[fd7a:115c:a1e0:0:0:0:0:1]", "ssh_user": "root",
            "ssh_port": "22", "auth_method": "password", "credential": "x"}):
        _rh86._setup_add_remote(NS(data="{}"), {})
    check("setup wizard: a host typed in brackets, as the panel prints an IPv6 login, reaches the "
          "connection test in its canonical text (it was refused as not a hostname or IP)",
          tried == ["fd7a:115c:a1e0::1"], repr(tried))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The file editor: save through a symlink, and what a read calls binary
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HOME86 = os.path.join(_TMP86, "home", "p86u")


def _fshell86(server, user, script, timeout=30, **k):
    out, err, rc = _bash86(script.replace("/home/p86u", _HOME86))
    return out, err, rc


def _put86(rel, data):
    path = os.path.join(_HOME86, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _tree86():
    _shutil86.rmtree(os.path.join(_TMP86, "home"), ignore_errors=True)
    _shutil86.rmtree(os.path.join(_TMP86, "elsewhere"), ignore_errors=True)
    os.makedirs(os.path.join(_TMP86, "elsewhere"))
    for name in ("one", "big"):
        _put86("serverfiles/cfg/%s.cfg" % name, b"old")
        os.symlink("serverfiles/cfg/%s.cfg" % name, os.path.join(_HOME86, "%s.cfg" % name))
    _put86("plain.cfg", b"old")
    with open(os.path.join(_TMP86, "elsewhere", "x.cfg"), "wb") as fh:
        fh.write(b"outside")
    os.symlink(os.path.join(_TMP86, "elsewhere", "x.cfg"), os.path.join(_HOME86, "out.cfg"))
    os.symlink("later/new.cfg", os.path.join(_HOME86, "dangling.cfg"))


def _read86(rel):
    with open(os.path.join(_HOME86, rel), "rb") as fh:
        return fh.read()


def _symlink_save86():
    _p9_patch(_p9_core, "shell_as_game_user", _fshell86)
    _tree86()
    big = b"B" * (70 * 1024)          # past _ONE_SHOT_B64: the chunked path
    got = {}
    for rel, data in (("one.cfg", b"new"), ("big.cfg", big)):
        ok, _msg = _files86._write_file_as_user(NS(), "p86u", "/home/p86u/" + rel, data)
        got[rel] = (ok, os.path.islink(os.path.join(_HOME86, rel)),
                    _read86("serverfiles/cfg/" + rel) == data)
    check("files: saving a file that is a symlink to another file in the home writes the file it "
          "points at and keeps the link, one-shot and chunked (it replaced the link with a copy and "
          "the game read the old config)",
          got == {"one.cfg": (True, True, True), "big.cfg": (True, True, True)}, repr(got))
    ok_p, _ = _files86._write_file_as_user(NS(), "p86u", "/home/p86u/plain.cfg", b"new")
    ok_d, _ = _files86._write_file_as_user(NS(), "p86u", "/home/p86u/dangling.cfg", b"made")
    made = os.path.join(_HOME86, "later", "new.cfg")
    check("files: ...a plain file is still saved, and a link to a file not created yet creates it "
          "(control)",
          ok_p and _read86("plain.cfg") == b"new" and ok_d and os.path.isfile(made)
          and os.path.islink(os.path.join(_HOME86, "dangling.cfg")), repr((ok_p, ok_d)))
    out = {}
    for rel, data in (("out.cfg", b"x"), ("out.cfg", big)):
        ok, msg = _files86._write_file_as_user(NS(), "p86u", "/home/p86u/" + rel, data)
        out[len(data)] = (ok, msg)
    with open(os.path.join(_TMP86, "elsewhere", "x.cfg"), "rb") as fh:
        outside = fh.read()
    check("files: ...while a link out of the home is still refused, by both paths, and nothing "
          "outside it is written",
          all(v == (False, "Invalid path") for v in out.values()) and outside == b"outside"
          and sorted(os.listdir(os.path.join(_TMP86, "elsewhere"))) == ["x.cfg"], repr((out, outside)))


def _binary86():
    _p9_patch(_p9_core, "shell_as_game_user", _fshell86)
    _tree86()
    _put86("blank.cfg", b"\n\n")
    _put86("text.cfg", b"hostname x\n")
    _put86("nul.bin", b"ab\x00cd\n")
    got = {rel: _files86.read_file(NS(), "p86u", rel) for rel in ("blank.cfg", "text.cfg", "nul.bin")}
    check("files: a file of blank lines opens in the editor as text (it was refused as a binary "
          "file), and a file with a NUL in it is still binary (control)",
          got == {"blank.cfg": ("\n\n", None), "text.cfg": ("hostname x\n", None),
                  "nul.bin": (None, _files86._READ_REFUSALS["__BINARY__"])}, repr(got))
    name = "files: a file the game account cannot read says so, not \"Binary file\""
    if os.geteuid() == 0:
        skip(name, "running as root, which reads a 0000 file")
        return
    path = _put86("locked.cfg", b"secret\n")
    os.chmod(path, 0)
    try:
        got = _files86.read_file(NS(), "p86u", "locked.cfg")
    finally:
        os.chmod(path, 0o600)
    check(name, got == (None, _files86._READ_REFUSALS["__UNREADABLE__"]), repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The root-capable-account probe asks every sudo (sudo-rs and sudo.ws)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SUDO_YES86 = 'echo "User deploy may run the following commands on h:"\n'
_SUDO_NO86 = 'echo "User deploy is not allowed to run sudo on h."\n'


def _shims86(sudo, ws):
    """A stand-in dir: `id` (root asking about a plain `deploy`), `sudo`, and sudo.ws at `ws`."""
    d = os.path.join(_TMP86, "shims")
    _shutil86.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    _standin86(os.path.join(d, "id"), 'case "$*" in "-u") echo 0 ;; "-u deploy") echo 1086 ;; '
                                      '"-Gn deploy") echo "deploy games" ;; *) exit 1 ;; esac\n')
    _standin86(os.path.join(d, "sudo"), sudo)
    if ws is not None:
        _standin86(os.path.join(d, "sudo.ws"), ws)
    return d


def _probe86(sudo, ws):
    d = _shims86(sudo, ws)
    _p9_patch(_p9_sh, "_R22B_SUDO_WS", os.path.join(d, "sudo.ws"))
    out, _e, _rc = _bash86(_p9_sh._account_probe_cmd(["deploy"]),
                           env={"PATH": d + ":/usr/bin:/bin", "LC_ALL": "C"})
    return (_p9_sh._parse_account_probe(out, ["deploy"]) or {}).get("deploy")


def _cas86(sudo, ws):
    txt = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
    i = txt.index("can_already_sudo() {")
    fn = txt[i:txt.index("\n}\n", i) + 3]
    d = _shims86(sudo, ws)
    script = ("set -uo pipefail\nHELPER_DIR=%s\nSUDO_WS=%s\n" % (os.path.join(_TMP86, "no-helper"),
                                                                 os.path.join(d, "sudo.ws"))
              + "id() { echo 'x games'; }\n" + fn + "can_already_sudo deploy\n")
    out, _e, _rc = _bash86(script, env={"PATH": d + ":/usr/bin:/bin", "LC_ALL": "C"})
    return (out.strip().splitlines() or [""])[-1]


def _sudo_ws86():
    got = {
        "ws grants, sudo-rs not": _probe86(_SUDO_NO86, _SUDO_YES86),
        "sudo grants, no ws": _probe86(_SUDO_YES86, None),
        "neither": _probe86(_SUDO_NO86, _SUDO_NO86),
        "no ws, sudo not": _probe86(_SUDO_NO86, None),
    }
    rules = "it has sudo rules of its own"
    check("account probe: on a remote whose `sudo` is sudo-rs, an account classic sudo (sudo.ws) "
          "lists rules for is refused as root-capable (sudo-rs said \"not allowed\" and it passed)",
          got["ws grants, sudo-rs not"] == rules, repr(got))
    check("account probe: ...sudo alone still decides where there is no sudo.ws, and an account "
          "neither lists is a plain account (controls)",
          (got["sudo grants, no ws"], got["neither"], got["no ws, sudo not"]) == (rules, "ok", "ok"),
          repr(got))
    cas = {
        "ws grants": _cas86(_SUDO_NO86, _SUDO_YES86),
        "both no": _cas86(_SUDO_NO86, _SUDO_NO86),
        "ws unclear": _cas86(_SUDO_NO86, 'echo "sudo: something else"\n'),
        "no ws": _cas86(_SUDO_NO86, None),
        "sudo grants": _cas86(_SUDO_YES86, None),
    }
    check("install.sh: with no helper, the enrolment guard asks sudo.ws too — yes when it lists "
          "rules, no only when every sudo says no, unknown when one is unclear",
          cas == {"ws grants": "yes", "both no": "no", "ws unclear": "unknown", "no ws": "no",
                  "sudo grants": "yes"}, repr(cas))


def _r25d_home86(getent_row):
    """The probe's verdict for `deploy` whose account row (getent's output) is `getent_row`.

    Named for what it is, an account row with no password in it ("x": the hash is in shadow): the
    old name made CodeQL read it as a password stored in clear text (py/clear-text-storage).
    """
    d = _shims86(_SUDO_NO86, None)
    _standin86(os.path.join(d, "getent"), 'echo "%s"\n' % getent_row)
    _p9_patch(_p9_sh, "_R22B_SUDO_WS", os.path.join(d, "sudo.ws"))
    out, _e, _rc = _bash86(_p9_sh._account_probe_cmd(["deploy"]),
                           env={"PATH": d + ":/usr/bin:/bin", "LC_ALL": "C"})
    return str((_p9_sh._parse_account_probe(out, ["deploy"]) or {}).get("deploy"))


def _r25d_probe_home86():
    # The probe's HOME line, read from passwd's sixth field by the real text: no other check ran the
    # command against an account whose home IS /home/<name>, so a probe reading another field (the
    # shell, -f7) refused every game account on every remote with every gate green (review 1016b).
    got = (_r25d_home86("deploy:x:1086:1086::/home/deploy:/bin/bash"),
           _r25d_home86("deploy:x:1086:1086::/srv/x:/home/deploy"))
    check("account probe (real text): an account whose passwd home is /home/<name> is a plain "
          "account, and one whose home is elsewhere is refused for it even when another field "
          "says /home/<name>",
          got[0] == "ok" and "home" in got[1] and "/srv/x" in got[1], repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. A host that is down: _unreachable's answer, never "Internal server error"
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _hostkey86(*a, **k):
    raise _p9_core.HostKeyMismatch("p86: the host's key changed")


def _unreachable_routes86(client, rid, sid):
    _p9_patch(_p9_rv, "change_ssh_port", _down86)
    _p9_patch(_p9_rv, "remote_os_update_start", _hostkey86)
    _p9_patch(_p9_rv, "detect_game_ports", _down86)
    _p9_patch(_p9_rs, "tailnet_exempt_ips", lambda *a, **k: set())
    _p9_patch(_p9_rs, "remote_ufw_deny_ip", _down86)
    _p9_patch(_pb86, "list_game_backups", lambda *a, **k: [{"name": "p86.tar.zst"}])
    _p9_patch(_pb86, "delete_game_backup", _down86)
    calls = {
        "ssh-port": ("/api/remote/%d/ssh-port" % rid, {"port": 2286}, "host_unreachable"),
        "os-update/start": ("/api/remote/%d/os-update/start" % rid, {}, "host_key_mismatch"),
        "sync-ports": ("/api/server/%d/sync-ports" % sid, {}, "host_unreachable"),
        "security/block": ("/api/remote/%d/security/block" % rid, {"ip": "203.0.113.86"},
                           "host_unreachable"),
        "game backup delete": ("/api/panel/backup/game/%d/delete" % sid, {"name": "p86.tar.zst"},
                               "host_unreachable"),
    }
    bad = {}
    for name, (url, body, code) in calls.items():
        r = client.post(url, json=body)
        j = r.get_json(silent=True) or {}
        if (r.status_code, j.get("unreachable"), j.get("code")) != (200, True, code):
            bad[name] = (r.status_code, j)
    check("routes: a host that is down (or presents a changed key) is _unreachable's answer from "
          "ssh-port, os-update/start, sync-ports, security/block and a game backup delete — 200, "
          "`unreachable` and a `code` — not \"Internal server error\"", not bad, repr(bad)[:600])
    _p9_patch(_p9_sd, "_autostart_reboot_gate", lambda *a, **k: None)
    said = {}
    for raiser, want in ((_down86, "Host unreachable"), (_hostkey86, "Re-trust host key")):
        _p9_patch(_p9_sd, "set_autostart", raiser)
        said[want] = (client.post("/api/server/%d/autostart" % sid, json={"enabled": True})
                      .get_json(silent=True) or {}).get("message", "")
    check("routes: ...and every other catch-all says what happened to the host — \"Host "
          "unreachable\", or the re-trust remedy for a changed key — not \"Internal server error\"",
          all(want in got for want, got in said.items()), repr(said))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Leads: firewall readers, the details port, the batch port, audits, Ubuntu Pro, the banner
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UFW_HEAD86 = ("Status: active\n\n     To                         Action      From\n"
               "     --                         ------      ----\n")


def _public_mode86(*rows):
    out = _UFW_HEAD86 + "".join(r + "\n" for r in rows)
    _p9_patch(_p9_core, "run_privileged", lambda *a, **k: (out, "", 0))
    return _hosts86.remote_public_ssh_status(NS(id=-86, name="p86")).get("mode")


def _loopback86():
    way_in = {
        "22/tcp": _ALLOW_ROW83 % "22/tcp",
        "a public destination": _ALLOW_ROW83 % "203.0.113.5 22/tcp",
        "every address": _ALLOW_ROW83 % "0.0.0.0/0 22/tcp",
        "OpenSSH": _ALLOW_ROW83 % "OpenSSH",
    }
    not_in = {
        "loopback destination": _ALLOW_ROW83 % "127.0.0.1 22/tcp",
        "loopback network": _ALLOW_ROW83 % "127.0.0.0/8 22/tcp",
        "loopback source": "%-27sALLOW IN    127.0.0.1" % "22/tcp",
        "on lo": "%-27sALLOW IN    Anywhere" % "22/tcp on lo",
        "docker bridge": "%-27sALLOW IN    Anywhere" % "22/tcp on docker0",
        "udp": _ALLOW_ROW83 % "22/udp",
        "out": "%-27sALLOW OUT   Anywhere" % "22/tcp",
        "fwd": "%-27sALLOW FWD   Anywhere" % "22/tcp",
    }
    got_in = {k: _public_mode86(r) for k, r in way_in.items()}
    got_not = {k: _public_mode86(r) for k, r in not_in.items()}
    check("public ssh: a rule for a loopback destination (`127.0.0.1 22/tcp`) is no public way in "
          "(it read as \"open (allow)\", so \"off\" could never succeed)",
          set(got_not.values()) == {"off"}, repr(got_not))
    check("public ssh: ...while 22/tcp, a public destination, every address and OpenSSH still are, "
          "and a DENY above an ALLOW is what a connection meets (controls)",
          set(got_in.values()) == {"allow"}
          and _public_mode86("%-27sDENY IN     Anywhere" % "22/tcp", _ALLOW_ROW83 % "22/tcp") == "off",
          repr(got_in))
    ok, msg = _limit83(22, _ALLOW_ROW83 % "127.0.0.1 22/tcp")
    check("ufw limit: a loopback-destination ALLOW above the LIMIT does not shadow it", ok, msg)


_V6ROW86 = "%-27s%-12sAnywhere (v6)"


def _v6_86():
    v4_limit = "%-27sLIMIT IN    Anywhere" % "22/tcp"
    got = {
        "v6 allow above": _public_mode86(v4_limit, _V6ROW86 % ("22/tcp (v6)", "ALLOW IN"),
                                         _V6ROW86 % ("22/tcp (v6)", "LIMIT IN")),
        "v6 only allow": _public_mode86(_V6ROW86 % ("OpenSSH (v6)", "ALLOW IN")),
        "both limit": _public_mode86(v4_limit, _V6ROW86 % ("22/tcp (v6)", "LIMIT IN")),
        "no v6 rule": _public_mode86(v4_limit),
    }
    check("public ssh: IPv6 is read on its own — a (v6) ALLOW above the (v6) LIMIT, or a v6-only "
          "allow, is public SSH open (it read \"rate-limited\" / \"off\" from the IPv4 list alone); "
          "LIMIT in both, or no v6 rule at all, is still limited (controls)",
          got == {"v6 allow above": "allow", "v6 only allow": "allow", "both limit": "limit",
                  "no v6 rule": "limit"}, repr(got))

    def _ufw_listing86(rows, opened):
        # Each case gets its own listing (a factory, not a list default argument).
        def _run86(*a, **kw):
            # The IPv4-only allow lands in the listing, as ufw's does: step 1 re-reads it.
            if a[1] == "ufw-allow-from-port":
                opened.append(a[1])
                rows.insert(0, _ALLOW_ROW83 % ("%s/%s" % (a[2][1], a[2][2])))
            return _UFW_HEAD86 + "".join(r + "\n" for r in rows), "", 0
        return _run86

    opened = []
    _p9_patch(_hosts86, "remote_ufw_open_port", lambda *a, **k: opened.append(a[1]) or (True, ""))
    res = {}
    for k, rows in (("v6 deny", (_ALLOW_ROW83 % "2286/tcp", _V6ROW86 % ("2286/tcp (v6)", "DENY IN"))),
                    ("v4 allow only", (_ALLOW_ROW83 % "2286/tcp",)),
                    ("v6 allow only", (_V6ROW86 % ("2286/tcp (v6)", "ALLOW IN"),))):
        _p9_patch(_p9_core, "run_privileged", _ufw_listing86(list(rows), opened))
        del opened[:]
        _added, refusal = _hosts86._open_ssh_port_rule(NS(id=-86, name="p86"), 2286, ["22"])
        res[k] = (bool(refusal), list(opened))
    check("ssh port move: a (v6) DENY first for the new port refuses the move; an IPv4 allow with "
          "no v6 rule needs nothing opened; a v6-only allow still opens it for IPv4 (that family's rule "
          "alone since review 1016b)",
          res == {"v6 deny": (True, []), "v4 allow only": (False, []),
                  "v6 allow only": (False, ["ufw-allow-from-port"])},
          repr(res))


def _v6_split86():
    before = [_ALLOW_ROW83 % "27015", _V6ROW86 % ("27015 (v6)", "ALLOW IN")]
    after = [_ALLOW_ROW83 % "27015/udp", "%-27sLIMIT IN    Anywhere" % "27015/tcp",
             _V6ROW86 % ("27015/tcp (v6)", "LIMIT IN")]
    got = {}
    for k, extra in (("v6 udp closed", []), ("v6 udp kept", [_V6ROW86 % ("27015/udp (v6)", "ALLOW IN")])):
        reads = [before, after + extra]

        def _run(server, verb, args=(), timeout=30, **kw):
            if verb == "ufw-status":
                rows = reads.pop(0) if len(reads) > 1 else reads[0]
                return _UFW_HEAD86 + "".join(r + "\n" for r in rows), "", 0
            return "", "", 0
        _p9_patch(_p9_core, "run_privileged", _run)
        ok, msg = _hosts86.remote_ufw_limit_port(NS(id=-86, name="p86"), 27015, "tcp")
        got[k] = (ok, "is no longer open" in str(msg))
    check("ufw limit: splitting a bare game-port allow that closed its other protocol for IPv6 only "
          "is reported (the check read the IPv4 list alone); kept in both, it is rate limited (control)",
          got == {"v6 udp closed": (False, True), "v6 udp kept": (True, False)}, repr(got))


def _named_rule86():
    out = _UFW_HEAD86 + _ALLOW_ROW83 % "22,80/tcp" + "\n"
    _p9_patch(_p9_core, "run_privileged", lambda *a, **k: (out, "", 0))
    _p9_patch(_hosts86, "_tailnet_ssh_state", lambda s: (True, True, True))
    ok, msg = _hosts86.remote_set_public_ssh(NS(id=-86, name="p86", host="100.64.0.86", port=22, auth_method="key",
                                                is_local=False), "off")
    check("public ssh: a change that cannot take names the rule connections meet first (it said "
          "only that the firewall still reports it open)",
          not ok and "meet `22,80/tcp" in str(msg), str(msg))


def _details_port86():
    said = {"ipv6": "Internet IP: [2001:db8::1234]:27015\n",
            "ipv4": "Server IP: 0.0.0.0:0\nInternet IP: 198.51.100.4:27016\n"}
    got = {}
    for k, text in said.items():
        _p9_patch(_p9_core, "run_as_game_user", lambda *a, _t=text, **kw: (_t, "", 0))
        got[k] = _game86.detect_game_ports(NS(), "p86u").get("game_port")
    check("details: an IPv6 Internet IP line gives the port that ends it, not a group of the "
          "address (it read 1234), and an IPv4 line still reads as before (control)",
          got == {"ipv6": 27015, "ipv4": 27016}, repr(got))


def _batch_port86():
    gd = _cron86._gamedig_type("css", None)
    got = _cron86._batch_queries([(1, "css", 27015.5, None), (2, "css", 27016.0, None),
                                  (3, "css", float("inf"), None)])
    check("player poll: a fractional REAL port is no port to query (it queried the neighbouring "
          "integer as this server); a whole one still is",
          gd is not None and got == [(2, gd, 27016)], repr((gd, got)))


def _cron_readback86():
    with _p9.app_context():
        gs = GameServer(remote_id=_mine86["hosts"][0], name="p86-gone", short_name="p86gone",
                        game_type="css", port=27186, installed=True, status="offline")
        db.session.add(gs)
        db.session.commit()
        sid = gs.id

        def _gone(*a, **k):
            # The row goes while the read-back runs: deleted on its own connection, then the raise.
            with db.engine.begin() as conn:
                conn.execute(_text86("DELETE FROM game_server WHERE id = :i"), {"i": sid})
            raise ConnectionError("p86: dropped")
        _p9_patch_sm("list_cron_jobs", _gone)
        try:
            _p9_sf._r21b_sync_after_cron_write(gs)
            raised = None
        except Exception as e:  # noqa: BLE001 - what is checked is that nothing escapes
            raised = type(e).__name__
        db.session.rollback()
    check("cron: the read-back after a crontab write never raises, even when the server's row went "
          "while it ran (its except reloaded the expired row)", raised is None, repr(raised))


# server_detail's `db` with a commit that raises (a locked database).
_CommitFails86 = NS(session=NS(commit=lambda: (_ for _ in ()).throw(RuntimeError("p86: database is locked")),
                               rollback=lambda: None))


def _toggle_audit86(client, sid):
    _p9_patch(_p9_sd, "_autostart_reboot_gate", lambda *a, **k: None)
    _p9_patch(_p9_sd, "_host_timezone_cached", lambda remote: "Etc/UTC")
    _p9_patch(_p9_sd, "set_autostart", lambda *a, **k: (True, ""))
    _p9_patch(_p9_sd, "set_daily_restart", lambda *a, **k: (True, ""))
    _p9_patch(_p9_sd, "db", _CommitFails86)
    got = {}
    for act, url, body in (("set_autostart", "/api/server/%d/autostart" % sid, {"enabled": True}),
                           ("set_daily_restart", "/api/server/%d/daily-restart" % sid,
                            {"enabled": True, "time": "05:00", "tz": "Etc/UTC"})):
        n = _p9_audit_count(act)
        r = client.post(url, json=body)
        got[act] = (r.status_code, _p9_audit_count(act) - n, _p9_audit(act).success)
    check("audit: Autostart and the daily restart audit a crontab write that worked even when the "
          "commit of the column after it raises (the crontab changed with no row)",
          got == {"set_autostart": (500, 1, True), "set_daily_restart": (500, 1, True)}, repr(got))


def _upro86():
    src = open(os.path.join(_root, "static", "js", "panel.js"), encoding="utf-8").read()
    i = src.find("window.UPro = (function(){")
    j = src.find("\n})();", i)
    body = src[i:j + 6] if i >= 0 and j > i else "/* MISSING window.UPro */"
    prog = (
        "var els = {}; function mk(id){ return els[id] || (els[id] = {id: id, innerHTML: '', "
        "textContent: '', setAttribute: function(){}, className: ''}); }\n"
        "var document = {getElementById: mk, querySelectorAll: function(){ return []; }};\n"
        "var window = {}; var MOUNT = ''; function t(s){ return s; } function tf(s){ return s; }\n"
        "function tfHtml(s){ return s; } function _da(){ return ''; }\n"
        "function escapeHtml(s){ return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;'); }\n"
        "var fetch = function(){ return new Promise(function(){}); };\n"
        + body + "\n"
        "window.UPro.load(1, 'upro', {success: false, unreachable: true, code: 'host_key_mismatch', "
        "message: 'P86 re-trust <b>'});\n"
        "var key = els.upro.innerHTML;\n"
        "window.UPro.load(1, 'upro', {success: false, unreachable: true, code: 'host_unreachable', "
        "message: 'P86 down'});\n"
        "console.log(JSON.stringify({key: key, down: els.upro.innerHTML}));\n")
    name = ("ubuntu pro: a changed host key shows the route's re-trust sentence, escaped (the card "
            "said only \"could not read\"), and a host that is down keeps that sentence")
    got = _node47(prog)
    if got is None:
        skip(name, "node is not installed here")
        return
    check(name, "P86 re-trust &lt;b>" in got.get("key", "") and "Could not read" not in got.get("key", "")
          and "Could not read Ubuntu Pro status" in got.get("down", "") and "P86 down" not in got.get("down", ""),
          repr(got)[:400])


def _banner86():
    with _p9.app_context():
        r = RemoteServer(name="p86-localish", host="p86-local.example.invalid", port=22,
                         username="local", auth_method="local", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        _mine86["hosts"].append(r.id)
        rid = r.id
        local_id = _p9_rv._current_os_updates({rid: {}})[1]
    check("os updates banner: a row that is the panel host by its transport alone is the panel host "
          "(is_local alone kept it in a delegate's banner)", local_id == rid, repr((local_id, rid)))


try:
    _p9_arm(who="part86")
    _RID86, _GS86, _ADMIN86 = _setup86()
    _A86 = _p9_client(_ADMIN86)
    _wizard86()
    _symlink_save86()
    _binary86()
    _sudo_ws86()
    _r25d_probe_home86()
    _unreachable_routes86(_A86, _RID86, _GS86)
    _p9_restore_all()
    _p9_arm(who="part86")
    _loopback86()
    _v6_86()
    _v6_split86()
    _named_rule86()
    _details_port86()
    _batch_port86()
    _toggle_audit86(_A86, _GS86)
    _p9_restore_all()
    _p9_arm(who="part86")
    _upro86()
    _banner86()
    _cron_readback86()
finally:
    _p9_restore_all()
    _cleanup86()
    _shutil86.rmtree(_TMP86, ignore_errors=True)

check("part86: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP86_START, repr(_P9_TRIPPED[_TRIP86_START:][:6]))
