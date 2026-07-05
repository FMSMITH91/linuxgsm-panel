"""Fast unit tests for the pure-logic helpers — no network, no SSH, no live DB.

These lock in the behaviour of the parsing/classification code where subtle bugs
tend to hide: firewall rule grouping + lock-out protection, game-port selection,
password policy, safe int parsing, and secret encryption. Several of these would
have caught real regressions (wrong protocol split, opening non-essential ports,
deleting the last SSH rule, a non-numeric port 500).

    python tests/unit_test.py      # exits 0 if all pass, 1 otherwise
"""
import os
import sys
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import ssh_manager as sm
from app import password_problem, _int_or
from auth import can_access_remote, client_ip

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


# ── password policy ───────────────────────────────────────────
check("weak: too short", password_problem("Ab1!") is not None)
check("weak: no upper", password_problem("test1234!@") is not None)
check("weak: no lower", password_problem("TEST1234!@") is not None)
check("weak: no digit", password_problem("TestTest!@") is not None)
check("weak: no symbol", password_problem("TestTest12") is not None)
check("strong password accepted", password_problem("Test1234!@") is None)

# ── safe int parsing (a non-numeric port must not raise) ──────
eq("_int_or valid", _int_or("2222", 22), 2222)
eq("_int_or blank -> default", _int_or("", 22), 22)
eq("_int_or junk -> default", _int_or("abc", 22), 22)
eq("_int_or None -> default", _int_or(None, 5000), 5000)
eq("_int_or whitespace", _int_or("  80 ", 1), 80)

# ── cron manager (pure logic; no crontab touched) ─────────────
# schedule validation
check("cron: 5-field ok", sm._validate_cron("*/5 * * * *", "/bin/true")[0])
check("cron: @daily ok", sm._validate_cron("@daily", "/home/gm/backup.sh")[0])
check("cron: @reboot ok", sm._validate_cron("@reboot", "echo hi")[0])
check("cron: ranges/steps ok", sm._validate_cron("0-30/2 1,3 * * mon-fri", "x")[0])
check("cron: normalises inner ws", sm._validate_cron("0   5  *  *  *", "x")[2] == "0 5 * * * x")
check("cron: 4 fields rejected", not sm._validate_cron("* * * *", "x")[0])
check("cron: bad @shortcut rejected", not sm._validate_cron("@sometimes", "x")[0])
check("cron: empty command rejected", not sm._validate_cron("@daily", "")[0])
check("cron: newline in command rejected", not sm._validate_cron("@daily", "a\nb")[0])
check("cron: embedded CR rejected", not sm._validate_cron("@daily", "a\rb")[0])
check("cron: embedded CR in schedule rejected", not sm._validate_cron("0 5 *\r* *", "x")[0])
check("cron: shell metachars allowed in command", sm._validate_cron("@daily", "a && b | c")[0])
# managed-line detection (must never let the generic editor touch panel entries)
check("cron: autostart is managed",
      sm._cron_line_managed("@reboot /home/gm/gmodserver start > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: maintenance update is managed",
      sm._cron_line_managed("15 5 * * * /home/gm/gmodserver update > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: update-lgsm is managed",
      sm._cron_line_managed("30 5 * * 0 /home/gm/gmodserver update-lgsm > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: daily-restart flag is managed",
      sm._cron_line_managed("0 5 * * * touch /home/gm/.restart-pending", "gm", "gmodserver"))
check("cron: user backup line is NOT managed",
      not sm._cron_line_managed("0 3 * * * /home/gm/backup.sh", "gm", "gmodserver"))
# update/delete must REFUSE a panel-managed line before touching SSH (server=None
# proves no connection is attempted — the guard returns first). This is the security
# invariant that the generic editor can't tamper with autostart/maintenance/restart.
_up = sm.update_cron_job(None, "gm", "@reboot /home/gm/gmodserver start > /dev/null 2>&1",
                         "@daily", "/home/gm/x.sh", "gmodserver")
check("cron: update refuses a managed line (no SSH)", _up[0] is False and "managed" in _up[1])
_dl = sm.delete_cron_job(None, "gm", "0 5 * * * touch /home/gm/.restart-pending", "gmodserver")
check("cron: delete refuses a managed line (no SSH)", _dl[0] is False and "managed" in _dl[1])
# a bad schedule is rejected by update before any SSH too
_bad = sm.update_cron_job(None, "gm", "0 3 * * * /home/gm/backup.sh", "not-a-schedule", "x", "gmodserver")
check("cron: update rejects a bad schedule (no SSH)", _bad[0] is False)
# line splitting
eq("cron: split 5-field", sm._split_cron_line("0 3 * * * /home/gm/b.sh a"), ("0 3 * * *", "/home/gm/b.sh a"))
eq("cron: split @shortcut", sm._split_cron_line("@reboot /home/gm/x start"), ("@reboot", "/home/gm/x start"))
eq("cron: split rejects short line", sm._split_cron_line("0 3 * *"), (None, None))

# ── anti-lockout: disabling public SSH must be refused with no Tailscale path back in ──
_orig_rc = sm.run_command
def _rc_no_tailnet(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Stopped"}', "", 0)   # Tailscale not running
    return ("", "", 0)
sm.run_command = _rc_no_tailnet
_ok, _msg = sm.remote_set_public_ssh(object(), "off")
check("ssh off REFUSED when no Tailscale path (anti-lockout)", _ok is False and "lock you out" in _msg.lower())

def _rc_ts_ssh(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Running"}', "", 0)
    if "debug prefs" in cmd:
        return ('{"RunSSH": true}', "", 0)                # Tailscale SSH enabled
    return ("", "", 0)
sm.run_command = _rc_ts_ssh
check("ssh off ALLOWED when Tailscale SSH enabled", sm.remote_set_public_ssh(object(), "off")[0] is True)

def _rc_iface(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Running"}', "", 0)
    if "debug prefs" in cmd:
        return ('{"RunSSH": false}', "", 0)
    if "ufw status" in cmd:
        return ("Anywhere on tailscale0     ALLOW IN    Anywhere", "", 0)  # tailscale0 allowed
    return ("", "", 0)
sm.run_command = _rc_iface
check("ssh off ALLOWED when tailscale0 allowed in UFW", sm.remote_set_public_ssh(object(), "off")[0] is True)

sm.run_command = lambda *a, **k: ("", "", 0)
check("ssh allow is never lockout-guarded", sm.remote_set_public_ssh(object(), "allow")[0] is True)
check("ssh limit is never lockout-guarded", sm.remote_set_public_ssh(object(), "limit")[0] is True)
sm.run_command = _orig_rc

# ── secret encryption round-trip ──────────────────────────────
_pre = {p for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE)
        if os.path.exists(p)}
enc = config.encrypt_secret("hunter2")
check("encrypt adds enc: prefix", enc.startswith("enc:v1:"))
check("is_encrypted true for ciphertext", config.is_encrypted(enc))
eq("decrypt round-trips", config.decrypt_secret(enc), "hunter2")
eq("encrypt empty -> empty", config.encrypt_secret(""), "")
eq("decrypt legacy plaintext passthrough", config.decrypt_secret("plainpw"), "plainpw")

# ── UFW rule grouping: port / protocol split ──────────────────
def _rules(rs):
    return [{"num": str(i + 1), "detail": d} for i, d in enumerate(rs)]


groups = sm._group_ufw_rules(_rules([
    "22/tcp  ALLOW IN  Anywhere",
    "22/tcp (v6)  ALLOW IN  Anywhere (v6)",
    "5000/tcp  ALLOW IN  Anywhere",
    "28960  ALLOW IN  Anywhere  # codserver",
    "27015/udp  ALLOW IN  Anywhere",
]))
by_port = {g["port_num"]: g for g in groups}
eq("22 -> TCP", by_port["22"]["proto_label"], "TCP")
eq("22 merges v4+v6", by_port["22"]["family_label"], "IPv4 + IPv6")
eq("bare port -> BOTH", by_port["28960"]["proto_label"], "BOTH")
eq("bare port keeps comment", by_port["28960"]["comment"], "codserver")
eq("udp suffix -> UDP", by_port["27015"]["proto_label"], "UDP")

# ── firewall lock-out protection ──────────────────────────────
def protect(server, rules, enabled=True, cfg=None, is_local=False, tailscale=(False, False)):
    sm.is_local_server = lambda s: is_local
    sm._tailscale_conn_state = lambda s: tailscale   # (running, ssh_enabled) — deterministic in tests
    if cfg is not None:
        config.load_config = lambda: cfg
    return sm._annotate_firewall_protection(server, enabled, sm._group_ufw_rules(_rules(rules)))


# SSH-only: port 22 is the last way in -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("SSH-only: 22 protected", gp["22"]["protected"])
check("SSH-only: game port not protected", not gp["28960"]["protected"])

# A rate-limited SSH rule (`ufw limit`, action LIMIT — now the default) is still SSH access,
# and the only way in here -> protected. Regression: LIMIT != ALLOW was letting it be deleted.
g = protect(NS(port=22), ["22/tcp LIMIT IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("LIMIT SSH rule recognised as SSH", gp["22"]["is_ssh"])
check("LIMIT SSH rule protected as the only way in", gp["22"]["protected"])

# Custom SSH port + a tailscale0 rule, WITH Tailscale actually running -> two real ways in
# -> the SSH rule can be removed (warn); custom port recognised as SSH.
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"], tailscale=(True, False))
gp = {x["port_num"]: x for x in g}
check("custom 2222 recognised as SSH", gp["2222"]["is_ssh"])
check("2222 warn when Tailscale is up (another way in)", gp["2222"]["warn"] and not gp["2222"]["protected"])

# Same rules but Tailscale is DOWN -> the tailscale0 rule is no real route -> 2222 is the only
# way in and must be PROTECTED (the reported bug: don't let me delete SSH with no tailnet path).
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"], tailscale=(False, False))
gp = {x["port_num"]: x for x in g}
check("2222 protected when Tailscale is down (no real fallback)", gp["2222"]["protected"])

# Tailscale SSH enabled -> a guaranteed way in -> the sole SSH rule can be removed (warn).
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere"], tailscale=(True, True))
gp = {x["port_num"]: x for x in g}
check("SSH rule removable when Tailscale SSH is enabled", gp["22"]["warn"] and not gp["22"]["protected"])

# Tailscale-only: the tailscale rule is the last way in -> protected.
g = protect(NS(port=22), ["Anywhere ALLOW IN Anywhere on tailscale0",
                          "28960 ALLOW IN Anywhere"])
ts = next(x for x in g if x["is_tailscale"])
check("tailscale-only: protected", ts["protected"])

# `allow in on tailscale0` + `allow out on tailscale0` (the pair ufw adds), no SSH: only the
# IN rule is a "way in", so it's the last route and must be protected. The OUT rule must NOT
# count as access, or the protection would think there are two routes and let you delete the
# real (in) one.
g = protect(NS(port=22), ["Anywhere ALLOW IN Anywhere on tailscale0",
                          "Anywhere ALLOW OUT Anywhere on tailscale0"])
ins = [x for x in g if x["is_tailscale"]]
check("tailscale in+out: only the IN rule counts as access", len(ins) == 1)
check("tailscale in+out: the last-way-in IN rule is protected", bool(ins) and ins[0]["protected"])

# UFW disabled -> nothing protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere"], enabled=False)
check("ufw disabled: nothing protected", not any(x["protected"] for x in g))

# Panel web port on the LOCAL host, no Tailscale -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"],
            cfg={"port": 5000}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local, no tailscale: panel 5000 protected", gp["5000"]["protected"] and gp["5000"]["is_panel"])

# Panel web port with a tailscale0 rule but Serve NOT set up -> STILL protected. The
# tailscale interface only provides SSH recovery, not panel-UI access, so the public web
# port is still the only way into the panel.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local + tailscale0 but no Serve: panel 5000 STILL protected", gp["5000"]["protected"])

# Once Tailscale Serve is configured, the panel IS reachable over the tailnet -> the public
# port is no longer the only way in -> NOT protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local + Serve set up: panel 5000 NOT protected", not gp["5000"]["protected"])

# On a REMOTE host the panel port is never protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"],
            cfg={"port": 5000}, is_local=False)
gp = {x["port_num"]: x for x in g}
check("remote host: panel 5000 not protected", not gp["5000"]["protected"])

# ── game-port selection: open only what's needed ──────────────
_GMOD_DETAILS = """\
Some header text
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Client 27005 udp
SourceTV 27020 udp
"""
sm.run_as_game_user = lambda *a, **k: (_GMOD_DETAILS, "", 0)
res = sm.detect_game_ports(NS(), "gmodserver")
eq("gmod game_port", res["game_port"], 27015)
eq("gmod opens ONLY 27015 (no SourceTV/Client)", res["open_ports"], [27015])

_SRC_DETAILS = """\
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Query 27016 udp
RCON 27015 tcp
SourceTV 27020 udp
Client 27005 udp
"""
sm.run_as_game_user = lambda *a, **k: (_SRC_DETAILS, "", 0)
res = sm.detect_game_ports(NS(), "srv")
eq("source: opens game + query only", res["open_ports"], [27015, 27016])

# ── per-remote access control (fix: MANAGE_REMOTES alone must NOT grant every host) ──
def _user(is_admin, *group_remote_ids):
    return NS(is_superadmin=is_admin,
              groups=[NS(servers=[NS(id=i) for i in group_remote_ids])])


check("remote access: granted host allowed", can_access_remote(_user(False, 1, 2), 1))
check("remote access: non-granted host DENIED", not can_access_remote(_user(False, 1, 2), 3))
check("remote access: superadmin allowed anywhere", can_access_remote(_user(True), 999))
check("remote access: string id handled", can_access_remote(_user(False, 5), "5"))
check("remote access: junk id denied", not can_access_remote(_user(False, 5), "abc"))

# ── client_ip: trust X-Forwarded-For ONLY from the loopback proxy ─────
from flask import Flask as _Flask
_app = _Flask(__name__)
with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                               environ_base={"REMOTE_ADDR": "127.0.0.1"}):
    eq("loopback proxy: trust XFF", client_ip(), "1.2.3.4")
with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                               environ_base={"REMOTE_ADDR": "203.0.113.9"}):
    eq("direct connection: ignore spoofed XFF, use socket", client_ip(), "203.0.113.9")

# ── TOTP (2FA) ────────────────────────────────────────────────
from auth import generate_totp_secret, verify_totp
import pyotp as _pyotp
_sec = generate_totp_secret()
check("verify_totp accepts the current code", verify_totp(_sec, _pyotp.TOTP(_sec).now()))
check("verify_totp accepts a spaced code", verify_totp(_sec, " " + _pyotp.TOTP(_sec).now() + " "))
check("verify_totp rejects a wrong code", not verify_totp(_sec, "000000"))
check("verify_totp rejects empty", not verify_totp(_sec, ""))

# ── password check robustness (a bad stored hash must never raise) ───
from auth import check_password, hash_password, dummy_password_check
_h = hash_password("Test1234!@")
check("check_password: correct password -> True", check_password("Test1234!@", _h))
check("check_password: wrong password -> False", not check_password("nope", _h))
check("check_password: empty stored hash -> False (no raise)", not check_password("x", ""))
check("check_password: None stored hash -> False (no raise)", not check_password("x", None))
check("check_password: garbage stored hash -> False (no raise)", not check_password("x", "not-a-bcrypt-hash"))
check("dummy_password_check always returns False", dummy_password_check("anything") is False)

# ── login-throttle map must not grow unbounded (prune stale/empty IP buckets) ──
# _LOGIN_FAILS is the same dict object app.py mutates, so in-place edits here are seen
# by _prune_login_fails. (Single import style — CodeQL flags mixing import/from-import.)
from app import _prune_login_fails, _LOGIN_FAILS
_now = 1_000_000.0
_LOGIN_FAILS.clear()
_LOGIN_FAILS["fresh"] = [_now - 10]     # last failure within the window
_LOGIN_FAILS["stale"] = [_now - 9999]   # last failure aged out
_LOGIN_FAILS["empty"] = []              # bucket emptied by trimming
_prune_login_fails(_now)
check("login-throttle prune keeps a recently-active IP", "fresh" in _LOGIN_FAILS)
check("login-throttle prune drops an aged-out IP", "stale" not in _LOGIN_FAILS)
check("login-throttle prune drops an empty bucket", "empty" not in _LOGIN_FAILS)
_LOGIN_FAILS.clear()

# ── 2FA backup codes ──────────────────────────────────────────
from auth import generate_backup_codes
from models import User as _User
_codes = generate_backup_codes()
check("backup: generates 10 codes", len(_codes) == 10)
check("backup: codes are unique", len(set(_codes)) == 10)
check("backup: xxxxx-xxxxx format", all(len(c) == 11 and c[5] == "-" for c in _codes))
check("backup: unambiguous alphabet (no 0/o/1/l/i)",
      all(ch in "23456789abcdefghjkmnpqrstuvwxyz-" for c in _codes for ch in c))
_u = _User()
_u.set_backup_codes(_codes)
check("backup: 10 remaining after set", _u.backup_codes_remaining == 10)
check("backup: wrong code rejected", not _u.use_backup_code("00000-00000"))
check("backup: valid code accepted (ignores case + dashes)",
      _u.use_backup_code(_codes[0].upper().replace("-", "")))
check("backup: remaining drops to 9 after use", _u.backup_codes_remaining == 9)
check("backup: a used code can't be reused (one-time)", not _u.use_backup_code(_codes[0]))
check("backup: a different code still works", _u.use_backup_code(_codes[1]))
check("backup: no codes set is handled", not _User().use_backup_code("whatever"))

# ── one-click connect URI (steam://connect for Source/GoldSrc) ─
from models import GameServer as _GS
_steam = _GS(game_type="gmod", port=27015)
eq("connect: steam game -> steam://connect", _steam.connect_uri("1.2.3.4"),
   "steam://connect/1.2.3.4:27015")
_cs16 = _GS(game_type="cs", port=27015)
eq("connect: goldsrc game -> steam://connect", _cs16.connect_uri("host.example"),
   "steam://connect/host.example:27015")
_cod = _GS(game_type="cod", port=28960)
eq("connect: non-steam game (cod) -> no URI", _cod.connect_uri("1.2.3.4"), "")
_mc = _GS(game_type="mc", port=25565)
eq("connect: minecraft -> no URI", _mc.connect_uri("1.2.3.4"), "")
eq("connect: no host -> no URI", _steam.connect_uri(""), "")

# ── panel file integrity + repair (git-based) ─────────────────
import system_ops as _so
_so._is_git_checkout = lambda: True
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"]
    else ("M\tapp.py\nD\ttemplates/base.html\n", "", 0) if list(args) == ["diff", "--name-status", "HEAD"]
    else ("", "", 0))
_intg = _so.panel_integrity()
check("integrity: reports git checkout", _intg["git"] is True)
eq("integrity: counts tampered files", _intg["count"], 2)
check("integrity: not clean when files differ", _intg["clean"] is False)
check("integrity: parses modified status",
      {"path": "app.py", "status": "modified"} in _intg["modified"])
check("integrity: parses deleted status",
      {"path": "templates/base.html", "status": "deleted"} in _intg["modified"])

# Repair must ONLY ever check out files git itself reported as changed — a caller
# can't smuggle in an arbitrary path (path-traversal / arbitrary checkout).
_co = {}
def _repair_git(args, timeout=45):
    a = list(args)
    if a[:1] == ["checkout"]:
        _co["args"] = a
        return ("", "", 0)
    if a == ["rev-parse", "--short", "HEAD"]:
        return ("abc1234\n", "", 0)
    if a == ["diff", "--name-status", "HEAD"]:
        return ("M\tapp.py\n", "", 0)
    return ("", "", 0)
_so._git = _repair_git
_ok, _msg, _restored = _so.panel_repair(["app.py", "/etc/passwd", "../../secret"])
check("repair: restores only git-reported files", _restored == ["app.py"])
check("repair: rejects paths not in tampered set",
      "/etc/passwd" not in _co.get("args", []) and "../../secret" not in _co.get("args", []))
check("repair: uses HEAD + '--' path guard", _co["args"][:3] == ["checkout", "HEAD", "--"])

_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "", 0))
_ok2, _msg2, _ = _so.panel_repair()
check("repair: no-op when nothing is tampered", _ok2 is True and "Nothing to repair" in _msg2)

# Fail-safe: if git itself errors we must NOT claim the files are verified-clean.
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "fatal", 1))
_intgf = _so.panel_integrity()
check("integrity: fail-safe when git errors (not verified)",
      _intgf.get("verified") is False and _intgf["clean"] is True)
_okf, _msgf, _ = _so.panel_repair()
check("repair: refuses when integrity can't be verified", _okf is False)

_so._is_git_checkout = lambda: False
check("integrity: handles non-git checkout", _so.panel_integrity()["git"] is False)
_ok3, _msg3, _ = _so.panel_repair()
check("repair: refuses when not a git checkout", _ok3 is False)

# ── shell-identifier validation (the core injection defense) ──
from models import _validate_shell_ident as _vsi
for _bad in ("a;b", "a b", "a`b", "a$(x)", "a|b", "../x", "a&b", "a>b", "x'y", 'x"y', "a\nb", "a/b"):
    _rej = False
    try:
        _vsi("field", _bad)
    except ValueError:
        _rej = True
    check("shell-ident rejects %r" % _bad, _rej)
for _good in ("gmodserver", "cod", "my-server_1", "a.b", ""):
    _acc = True
    try:
        _vsi("field", _good)
    except ValueError:
        _acc = False
    check("shell-ident accepts %r" % _good, _acc)

# ── _quote() single-quoting neutralizes shell metacharacters ──
eq("_quote wraps a plain string in single quotes", sm._quote("abc"), "'abc'")
eq("_quote escapes an embedded single quote", sm._quote("a'b"), "'a'\\''b'")
_q = sm._quote("; rm -rf / #")
check("_quote fully single-quotes a metachar payload", _q[0] == "'" and _q[-1] == "'")
check("_quote leaves no unescaped quote to break out",
      _q.count("'") % 2 == 0)  # every quote is balanced/escaped

# ── cron builders generate correct + safe crontab lines ───────
# Capture what would be written instead of touching a real crontab.
_cron = {}
def _cap_rewrite(server, user, grep_args, add_lines, extra_pre=""):
    _cron.update(grep=grep_args, add=list(add_lines), pre=extra_pre)
    return True, "ok"
sm._rewrite_crontab = _cap_rewrite

sm.set_autostart(None, "gmodserver", True)
eq("autostart(on): @reboot start line", _cron["add"],
   ["@reboot /home/gmodserver/gmodserver start > /dev/null 2>&1"])
sm.set_autostart(None, "gmodserver", False)
eq("autostart(off): removes line, adds none", _cron["add"], [])

sm.install_game_cron(None, "gmodserver", supported={"monitor", "update-lgsm"})
check("install_game_cron: monitor every 5 min",
      "*/5 * * * * /home/gmodserver/gmodserver monitor > /dev/null 2>&1" in _cron["add"])
check("install_game_cron: weekly update-lgsm",
      "30 5 * * 0 /home/gmodserver/gmodserver update-lgsm > /dev/null 2>&1" in _cron["add"])
eq("install_game_cron: only supported commands scheduled", len(_cron["add"]), 2)

sm.set_daily_restart(None, "gmodserver", game_type="gmod", port=27015, enabled=True)
eq("daily_restart(mapped): sets pending flag at 05:00", _cron["add"][0],
   "0 5 * * * touch /home/gmodserver/.restart-pending")
check("daily_restart(mapped): queries gamedig for player count",
      "gamedig --type garrysmod 127.0.0.1:27015" in _cron["add"][1])
sm.set_daily_restart(None, "codserver", game_type="cod", port=28960, enabled=True)
check("daily_restart(unmapped game): skips gamedig, no player query",
      "gamedig" not in _cron["add"][1] and "P=; " in _cron["add"][1])
sm.set_daily_restart(None, "gmodserver", enabled=False)
check("daily_restart(disable): adds nothing and clears the flag",
      _cron["add"] == [] and "rm -f" in _cron["pre"])

# ── server_live_metrics parses SSH output into a numeric dict ──
_METRICS_OUT = "\n".join([
    "cpu 100 0 100 800 0 0 0", "GJA 1000",
    "cpu 110 0 110 880 0 0 0", "GJB 1100",
    "MEM 8000000000 4000000000", "LOAD 0.5 0.4 0.3",
    "DISK 100000000000 33000000000", "CORES 4", "UPTIME 123456",
    "GAMERAM 524288 3", "GUP 3600", "PORT 1",
])
sm.run_command = lambda server, cmd, timeout=30, sudo=None: (_METRICS_OUT, "", 0)
_m = sm.server_live_metrics(None, "gmodserver", 27015)
eq("metrics: ram_total parsed", _m["ram_total"], 8000000000)
eq("metrics: ram_percent computed", _m["ram_percent"], 50.0)
eq("metrics: disk_percent computed", _m["disk_percent"], 33.0)
eq("metrics: cores parsed", _m["cores"], 4)
eq("metrics: uptime parsed", _m["uptime_secs"], 123456)
eq("metrics: game_ram_mb parsed", _m["game_ram_mb"], 512)
eq("metrics: game_procs parsed", _m["game_procs"], 3)
check("metrics: port_open true when a socket is listening", _m["port_open"] is True)
eq("metrics: cpu_percent from the /proc/stat delta", _m["cpu_percent"], 20.0)
eq("metrics: game_cpu_percent from the jiffie delta", _m["game_cpu_percent"], 100.0)

# ── config save/load round-trips (guards the atomic-write path) ─
_cfg_backup = config.CONFIG_FILE.read_text() if config.CONFIG_FILE.exists() else None
try:
    _c = config.load_config()
    _c["_roundtrip_probe"] = "value-123"
    config.save_config(_c)
    check("config: value survives a save/load round-trip",
          config.load_config().get("_roundtrip_probe") == "value-123")
    check("config: file exists after atomic save", config.CONFIG_FILE.exists())
finally:
    if _cfg_backup is not None:
        config.CONFIG_FILE.write_text(_cfg_backup)

# ── cleanup: remove key/config files this run created ─────────
for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE):
    if p not in _pre and os.path.exists(p):
        try:
            p.unlink()
        except OSError:
            pass

passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if results and passed == len(results) else 1)
