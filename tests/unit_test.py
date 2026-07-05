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
# line splitting
eq("cron: split 5-field", sm._split_cron_line("0 3 * * * /home/gm/b.sh a"), ("0 3 * * *", "/home/gm/b.sh a"))
eq("cron: split @shortcut", sm._split_cron_line("@reboot /home/gm/x start"), ("@reboot", "/home/gm/x start"))
eq("cron: split rejects short line", sm._split_cron_line("0 3 * *"), (None, None))

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
def protect(server, rules, enabled=True, cfg=None, is_local=False):
    sm.is_local_server = lambda s: is_local
    if cfg is not None:
        config.load_config = lambda: cfg
    return sm._annotate_firewall_protection(server, enabled, sm._group_ufw_rules(_rules(rules)))


# SSH-only: port 22 is the last way in -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("SSH-only: 22 protected", gp["22"]["protected"])
check("SSH-only: game port not protected", not gp["28960"]["protected"])

# Custom SSH port + Tailscale: two ways in -> warn, not blocked; custom port recognised.
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"])
gp = {x["port_num"]: x for x in g}
check("custom 2222 recognised as SSH", gp["2222"]["is_ssh"])
check("2222 warn (another way in)", gp["2222"]["warn"] and not gp["2222"]["protected"])

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
