"""Part 259 of the unit suite: the panel's SFTP service (services/sftp_*, routes/sftp_settings).

1. Settings: off by default; each address choice binds what it says (Tailscale, 127.0.0.1, every
   address with :: only when the host has IPv6) and never 0.0.0.0 or :: otherwise; password sign-in
   is off by default under every choice; the "all addresses" warning; the card's save, its refusals
   and its audit row; the fail2ban jail and filter follow an SFTP service on every address.
2. Keys: the Account page adds (Ed25519, ECDSA, RSA of 3072 bits or more; smaller RSA refused),
   refuses duplicates, removes only the owner's own, and audits each.
3. The service end to end: a real paramiko SSH client against the real service process, the panel
   side answered by sftp_broker in this process, and the files reached through this machine's own
   sftp-server as the account running the suite. Sign-in by key and by password with an
   authenticator code; refusals (no 2FA, deactivated, a paused name's password, wrong key, a replayed
   code; a paused name's key still signs in); the top folder lists only the servers the user may
   edit; a permission removed mid-session; paths that try to leave a server's folder (.., absolute,
   a link inside pointing out); the panel's file-name rules; the size cap; the audit rows; and
   nothing listening once it is off.
4. The card shows an IPv6 listener as [addr]:port; the fail2ban jail is rewritten on every start and
   save, so the SFTP port leaves it with "all addresses".
5. Key TEXT pasted into a host's key PATH field (Remotes > Add and Edit, the setup wizard, a row
   already holding it, the Test button, every connection) is refused with a fixed sentence and never
   reaches a log record, traceback, flash or response (OWASP Logging Cheat Sheet, "Data to exclude").

HOW IT RUNS. Routes on part12's app. The service is started as it is in production (sftp_broker.
run_once: `python -m panel.services.sftp_server` with a socket pair), bound to 127.0.0.1 on a free
port. Game servers are rows on part12's panel-host row whose account is the one running the suite,
each with a throwaway home (sftp_broker.home_of is pointed there), so sftp-server runs without sudo.
Run as root (the CI's root lane) the end-to-end block is skipped by name: root is never a game
account.
"""
import base64 as _b64_259
import io as _io259
import ipaddress as _ipaddress259
import logging as _logging259
import os
import pwd as _pwd259
import shutil as _shutil259
import socket as _socket259
import tempfile as _tf259
import threading as _th259
import time as _time259

import paramiko as _pk259

from unit.part01 import check, eq, skip
from unit.part12 import P9_ADMIN, P9_LOCAL, _p9, _p9_client, _p9_patch, _p9_restore_all
from panel.core import config as _cfg259
from panel.db.models import AuditLog as _AL259, Group as _Grp259, GameServer as _GS259
from panel.db.models import SftpKey as _Key259, User as _User259, db as _db259
from panel.ops import system_ops as _so259
from panel.routes import _shared as _sh259
from panel.security import account_guard as _ag259, auth as _auth259
from panel.services import sftp_backend as _bk259, sftp_broker as _br259, sftp_common as _sc259

_TMP259 = _tf259.mkdtemp(prefix="p259-")
_PW259 = "p259-Pass" + "word-long-enough-1"     # the test accounts' password, never a real one
_CFG_SNAP259 = _cfg259.CONFIG_FILE.read_bytes() if _cfg259.CONFIG_FILE.exists() else None


def _put_cfg259(**changes):
    _cfg259.update_config(lambda c: c.update(changes))


def _drop_cfg259(*keys):
    _cfg259.update_config(lambda c: [c.pop(k, None) for k in keys])


def _ed25519_259():
    """A new Ed25519 private key (paramiko) and its public line."""
    k = _sc259.host_key_from_text(_sc259.new_host_key_text())
    return k, "%s %s p259" % (k.get_name(), k.get_base64())


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Settings: defaults, binds, the warning, the save
# ════════════════════════════════════════════════════════════════════════════════════════════════
_def259 = _sc259.settings({})
eq("sftp settings: off by default, keys only, the default port and the recommended cap",
   (_def259["enabled"], _def259["password"], _def259["port"], _def259["cap_mb"], _def259["bind"]),
   (False, False, 2222, _sc259.RECOMMENDED_CAP_MB, None))
eq("sftp settings: the absolute limit is the web sign-in's own until set (8 h, or what Settings holds), 1-168 h",
   (_def259["absolute_h"], _sc259.settings({"session_absolute_hours": 6})["absolute_h"],
    _sc259.settings({"session_absolute_hours": 6, "sftp_absolute_hours": 3})["absolute_h"],
    _sc259.absolute_or("0", 8), _sc259.absolute_or(169, 8), _sc259.absolute_or("x", 8),
    [_sc259.absolute_past_owasp(h) for h in (4, 8, 9)], _sc259.ABSOLUTE_GRACE_MINUTES),
   (8, 6, 3, 8, 8, 8, [False, False, True], 60))
eq("sftp settings: an idle session is closed after 15 minutes by default (OWASP's 15-30 for most applications)",
   (_def259["idle_min"], _sc259.idle_or("abc", 15), _sc259.idle_or(-1, 15), _sc259.idle_or(1441, 15),
    [_sc259.idle_outside_owasp(m) for m in (0, 2, 15, 30, 31)]),
   (15, 15, 15, 15, [True, False, False, False, True]))
eq("sftp settings: the first choice offered is Tailscale when it is up, else 127.0.0.1",
   (_sc259.default_bind(True), _sc259.default_bind(False)), ("tailscale", "loopback"))
_TS259 = ["100.101.102.103", "fd7a:115c:a1e0::1", "192.0.2.7"]
eq("sftp binds: tailscale is this host's tailnet addresses only (IPv4 first), never 0.0.0.0 or ::",
   _sc259.bind_addresses("tailscale", _TS259, True), ["100.101.102.103", "fd7a:115c:a1e0::1"])
eq("sftp binds: loopback is 127.0.0.1 only, with or without IPv6",
   (_sc259.bind_addresses("loopback", _TS259, True), _sc259.bind_addresses("loopback", [], False)),
   (["127.0.0.1"], ["127.0.0.1"]))
eq("sftp binds: all is 0.0.0.0, and :: only when the host has IPv6",
   (_sc259.bind_addresses("all", [], True), _sc259.bind_addresses("all", [], False)),
   (["0.0.0.0", "::"], ["0.0.0.0"]))  # nosec B104 - compared, never bound here
eq("sftp binds: no Tailscale address means nothing to listen on yet (never a fallback to all)",
   (_sc259.bind_addresses("tailscale", [], True), _sc259.bind_addresses("tailscale", ["192.0.2.7"], True),
    _sc259.bind_addresses("bogus", _TS259, True)), ([], [], []))
_WILD259 = (str(_ipaddress259.IPv4Address(0)), "::")   # the wildcard addresses this check says are never bound
_wild259 = [a for c in ("tailscale", "loopback") for ips in (_TS259, [], list(_WILD259))
            for a in _sc259.bind_addresses(c, ips, True) if a in _WILD259]
eq("sftp binds: no choice but all ever yields 0.0.0.0 or :: (not even from a hostile address list)",
   _wild259, [])

_if6 = os.path.join(_TMP259, "if_inet6")
with open(_if6, "w", encoding="ascii") as _f259:
    _f259.write("00000000000000000000000000000001 01 80 10 80       lo\n")
_lo_only259 = _sc259.host_has_ipv6(_if6)
with open(_if6, "a", encoding="ascii") as _f259:
    _f259.write("20010db8000000000000000000000001 02 40 00 80     eth0\n")
eq("sftp binds: IPv6 counts only on an interface other than lo (::1 alone is no IPv6)",
   (_lo_only259, _sc259.host_has_ipv6(_if6), _sc259.host_has_ipv6(os.path.join(_TMP259, "none"))),
   (False, True, False))


def _spawn259(cfg_changes, ts_ips, ipv6):
    """spawn_config's answer with the config, Tailscale addresses and IPv6 given."""
    _put_cfg259(**cfg_changes)
    saved = (_br259.tailscale_ips, _sc259.host_has_ipv6)
    _br259.tailscale_ips = lambda: list(ts_ips)
    _sc259.host_has_ipv6 = lambda *_a: ipv6
    try:
        return _br259.spawn_config(_p9)
    finally:
        _br259.tailscale_ips, _sc259.host_has_ipv6 = saved


try:
    _off259 = _spawn259({"sftp_enabled": False}, _TS259, True)
    _a259 = _spawn259({"sftp_enabled": True, "sftp_bind": "all"}, [], True)[0]
    _a4_259 = _spawn259({"sftp_enabled": True, "sftp_bind": "all"}, [], False)[0]
    _l259 = _spawn259({"sftp_enabled": True, "sftp_bind": "loopback"}, _TS259, True)[0]
    _t259 = _spawn259({"sftp_enabled": True, "sftp_bind": "tailscale"}, _TS259, True)[0]
    _tw259 = _spawn259({"sftp_enabled": True, "sftp_bind": "tailscale"}, [], True)
    _u259 = _spawn259({"sftp_enabled": True, "sftp_bind": None}, [], False)[0]
    _u_ts259 = _spawn259({"sftp_enabled": True, "sftp_bind": None}, _TS259, False)[0]
except Exception as _e259:  # noqa: BLE001 - a crash is this block's failure, not the suite's
    _off259 = _a259 = _a4_259 = _l259 = _t259 = _u259 = _u_ts259 = {}
    _tw259 = (None, repr(_e259))
eq("sftp service: off in Settings starts nothing (and waits for nothing)", _off259, (None, None))
eq("sftp service: all addresses binds 0.0.0.0 and ::, or 0.0.0.0 alone without IPv6",
   ((_a259 or {}).get("binds"), (_a4_259 or {}).get("binds")), (["0.0.0.0", "::"], ["0.0.0.0"]))  # nosec B104
eq("sftp service: loopback binds 127.0.0.1 even with Tailscale up", (_l259 or {}).get("binds"), ["127.0.0.1"])
eq("sftp service: tailscale binds the tailnet addresses", (_t259 or {}).get("binds"),
   ["100.101.102.103", "fd7a:115c:a1e0::1"])
eq("sftp service: tailscale chosen but down waits, binding nothing", _tw259,
   (None, "Waiting for this host's Tailscale address."))
eq("sftp service: no choice saved is 127.0.0.1 without Tailscale, the tailnet with it",
   ((_u259 or {}).get("binds"), (_u_ts259 or {}).get("binds")),
   (["127.0.0.1"], ["100.101.102.103", "fd7a:115c:a1e0::1"]))
eq("sftp service: the service is started with the idle timeout in force", (_l259 or {}).get("idle_min"), 15)
eq("sftp service: ...and the absolute limit and the grace for an open transfer",
   ((_l259 or {}).get("absolute_h"), (_l259 or {}).get("absolute_grace_min")), (8, 60))
eq("sftp service: password sign-in stays off under every choice unless switched on (keys only)",
   [(s or {}).get("password") for s in (_a259, _a4_259, _l259, _t259, _u259)], [False] * 5)
check("sftp service: the host key is Ed25519, made once and kept encrypted in config.json",
      (_a259 or {}).get("host_key", "").startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
      and (_a259 or {}).get("host_key") == (_l259 or {}).get("host_key")
      and _cfg259.is_encrypted(_cfg259.load_config().get("sftp_host_key", ""))
      and _sc259.host_key_from_text((_a259 or {}).get("host_key", "")).get_name() == "ssh-ed25519",
      repr(_cfg259.load_config().get("sftp_host_key", ""))[:40])


class _Conn259:
    """A stand-in service for Connection.get_allowed_auths: only the settings it reads."""

    def __init__(self, cfg):
        self.cfg = cfg


from panel.services import sftp_server as _ss259   # noqa: E402 - after the settings checks above
# The sign-in switch's key in the service's settings (a yes/no, not a secret).
_PWSWITCH259 = "password"
eq("sftp sign-in: keys only under every choice by default; the password and code only when allowed",
   [_ss259.Connection(_Conn259(s or {}), "192.0.2.9").get_allowed_auths("x") for s in (_a259, _l259, _t259)]
   + [_ss259.Connection(_Conn259({_PWSWITCH259: True}), "192.0.2.9").get_allowed_auths("x")],
   ["publickey", "publickey", "publickey", "publickey,keyboard-interactive"])

# The Settings card: each choice saved, Tailscale refused while it is down, the warning, the audit row.
_restarts259 = []
_REAL_RESTART259 = _br259.restart
_p9_patch(_br259, "restart", lambda: _restarts259.append(1))
# The jail rewrite runs the root helper: recorded here, and the real one checked in section 4 with
# the app's jail writer stubbed.
_follows259 = []
_REAL_F2B_FOLLOW259 = _br259.f2b_follow
_p9_patch(_br259, "f2b_follow", lambda app: _follows259.append(app is not None))
_p9_patch(_br259, "tailscale_ips", lambda: [])
_A259 = _p9_client(P9_ADMIN)


def _save259(**form):
    base = {"sftp_enabled": "on", "sftp_bind": "loopback", "sftp_port": "2222", "sftp_max_upload_mb": "4096",
            "sftp_idle_minutes": "15", "sftp_absolute_hours": "8"}
    base.update(form)
    return _A259.post("/settings/sftp", data={k: v for k, v in base.items() if v is not None})


def _flashed259():
    with _A259.session_transaction() as s:
        msgs = [m for _c, m in s.get("_flashes", [])]
        s.pop("_flashes", None)
    return msgs


_r259 = _save259(sftp_bind="all")
_f259 = _flashed259()
eq("sftp card: saving 'all addresses' stores it, restarts the service, and warns plainly",
   (_r259.status_code, _sc259.settings(_cfg259.load_config())["bind"], len(_restarts259),
    any("reachable from the internet" in m for m in _f259)), (302, "all", 1, True))
check("sftp card: the warning names the firewall as the operator's to open, and keys as the default",
      "does not open the port in the firewall" in " ".join(_f259)
      and "limited to SSH keys" in " ".join(_f259), repr(_f259))
_save259(sftp_bind="loopback")
eq("sftp card: no warning for 127.0.0.1", any("reachable from the internet" in m for m in _flashed259()), False)
_r259 = _save259(sftp_bind="tailscale")
eq("sftp card: the Tailscale address is refused while Tailscale is down (nothing saved)",
   (_r259.status_code, _sc259.settings(_cfg259.load_config())["bind"],
    any("Choose where" in m for m in _flashed259())),
   (302, "loopback", True))
_save259(sftp_port="0")
_save259(sftp_port="70000")
_save259(sftp_max_upload_mb="0")
eq("sftp card: a port or cap out of range is refused, not changed into one that passes",
   (_sc259.settings(_cfg259.load_config())["port"], _sc259.settings(_cfg259.load_config())["cap_mb"]),
   (2222, 4096))
_flashed259()
_save259(**{"sftp_max_upload_mb": "9000", "sftp_" + _PWSWITCH259 + "_auth": "on"})  # the checkbox, ticked
_f259 = _flashed259()
check("sftp card: above the recommended cap and password sign-in on are saved, each with a note",
      _sc259.settings(_cfg259.load_config())["cap_mb"] == 9000 and _sc259.settings(_cfg259.load_config())["password"]
      and any("above the recommended" in m for m in _f259) and any("SSH keys only" in m for m in _f259), repr(_f259))
with _p9.app_context():
    _row259 = _AL259.query.filter_by(action="settings_update").order_by(_AL259.id.desc()).first()
check("sftp card: each save is audited with what changed", _row259 is not None
      and "SFTP upload limit MiB 4096 -> 9000" in (_row259.detail or "")
      and "password and code sign-in allowed" in (_row259.detail or ""), getattr(_row259, "detail", None))
_flashed259()
_save259(sftp_idle_minutes="45")
_f45 = _flashed259()
_save259(sftp_idle_minutes="0")
_f0 = _flashed259()
_save259(sftp_idle_minutes="20")
_f20 = _flashed259()
_save259(sftp_idle_minutes="1441")
_fbad = _flashed259()
eq("sftp card: the idle timeout saves inside and outside OWASP's range, a note only outside, never a refusal",
   (_sc259.settings(_cfg259.load_config())["idle_min"], any("longer than the 30 minutes" in m for m in _f45),
    any("never closed" in m for m in _f0), any("OWASP" in m and "idle" in m.lower() for m in _f20),
    any("whole number of minutes" in m for m in _fbad)),
   (20, True, True, False, True))
_save259(sftp_absolute_hours="12")
_fa12 = _flashed259()
_save259(sftp_absolute_hours="169")
_fa169 = _flashed259()
_save259(sftp_absolute_hours="8", sftp_idle_minutes="600")
_fa_idle = _flashed259()
_abs_now259 = _sc259.settings(_cfg259.load_config())["absolute_h"]
_save259(sftp_absolute_hours="6")
_fa6 = _flashed259()
eq("sftp card: the absolute limit saves past OWASP's 8 h with a note, refuses 169 h and an idle longer than it",
   (_abs_now259, any("longer than the 8 hours OWASP" in m for m in _fa12), any("from 1 to 168" in m for m in _fa169),
    any("idle timeout cannot be longer than the absolute" in m for m in _fa_idle),
    _sc259.settings(_cfg259.load_config())["absolute_h"], any("8 hours OWASP" in m for m in _fa6)),
   (12, True, True, True, 6, False))
_save259(sftp_absolute_hours="12")
_html_abs259 = _A259.get("/settings").get_data(as_text=True)
check("sftp card: the absolute field shows the value in force, OWASP's 4-8 hours and the note past it",
      'name="sftp_absolute_hours"' in _html_abs259 and 'value="12"' in _html_abs259
      and "OWASP: 4–8 hours." in _html_abs259 and 'id="sftp-absolute-note"' in _html_abs259, _html_abs259[:0])
_save259(sftp_absolute_hours="8")
eq("sftp card: ...and no absolute note at 8 hours",
   'id="sftp-absolute-note"' in _A259.get("/settings").get_data(as_text=True), False)
_save259(sftp_idle_minutes="45")
_html_idle259 = _A259.get("/settings").get_data(as_text=True)
check("sftp card: the field shows the value in force, the recommended 15 minutes and OWASP's range beside it",
      'name="sftp_idle_minutes"' in _html_idle259 and 'value="45"' in _html_idle259
      and "OWASP recommends 15 to 30 minutes without activity" in _html_idle259
      and 'id="sftp-idle-note"' in _html_idle259, _html_idle259[:0])
_save259(sftp_idle_minutes="15")
eq("sftp card: ...and no note at the recommended value",
   'id="sftp-idle-note"' in _A259.get("/settings").get_data(as_text=True), False)
_html259 = _A259.get("/settings").get_data(as_text=True)
check("sftp card: the Settings page shows the card, the three choices and the warning",
      'id="sec-sftp"' in _html259 and 'value="tailscale"' in _html259 and 'value="all"' in _html259
      and "reachable from the internet" in _html259 and 'id="sftp-bind-ts"' in _html259, _html259[:0])
_saved_auth259 = _p9_client(P9_ADMIN)
with _saved_auth259.session_transaction() as _s259:
    _s259["_auth_at"] = _time259.time() - 86400
_cap_before259 = _sc259.settings(_cfg259.load_config())["cap_mb"]
eq("sftp card: a stale sign-in confirms its password before saving (step-up)",
   _saved_auth259.post("/settings/sftp", data={"sftp_bind": "loopback", "sftp_port": "2222", "sftp_idle_minutes": "15",
                                                "sftp_max_upload_mb": "1"}).status_code, 302)
eq("sftp card: ...and the stale post (a valid form) changed nothing",
   (_cap_before259 != 1, _sc259.settings(_cfg259.load_config())["cap_mb"]), (True, _cap_before259))

# The fail2ban jail: the SFTP port is banned on too, only while it listens on every address.
_put_cfg259(sftp_enabled=True, sftp_bind="all", sftp_port=2201)
_jall259 = _so259._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
_put_cfg259(sftp_bind="loopback")
_jlo259 = _so259._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
_put_cfg259(sftp_enabled=False, sftp_bind="all")
_joff259 = _so259._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
eq("sftp fail2ban: the jail bans on the SFTP port too only while it is on and on every address",
   ["port = 5000,2201" in _jall259, "port = 5000\n" in _jlo259, "port = 5000\n" in _joff259], [True] * 3)
_flt259 = next(ln.split("=", 1)[1].strip() for ln in _so259._panel_f2b_filter_body().splitlines()
               if ln.startswith("failregex"))
import re as _re259   # noqa: E402
_hit259 = _re259.search(_flt259.replace("<HOST>", r"(?P<host>\S+)"), "panel sftp login failed from 198.51.100.4")
eq("sftp fail2ban: the jail's filter counts a failed SFTP sign-in's auth.log line",
   _hit259.group("host") if _hit259 else None, "198.51.100.4")
_put_cfg259(sftp_enabled=True, sftp_bind="all", sftp_port=2201)
_jail_file259 = os.path.join(_TMP259, "jail.local")
with open(_jail_file259, "w", encoding="ascii") as _f259:
    _f259.write(_so259._panel_f2b_jail_body("/x/auth.log", 5000, [], False).replace("5000,2201", "5000"))
_p9_patch(_so259, "_F2B_PANEL_JAIL", _jail_file259)
eq("sftp fail2ban: a jail without the SFTP port reads as needing a rewrite (the boot self-heal)",
   (_so259._panel_f2b_jail_port(), _so259._panel_f2b_jail_sftp_ok(5000)), (5000, False))
_put_cfg259(sftp_enabled=False)
eq("sftp fail2ban: ...and the same jail is healthy once SFTP is off again", _so259._panel_f2b_jail_sftp_ok(5000), True)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Keys on the Account page
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _keygen259(kind, bits=None):
    """A public key line made by this machine's ssh-keygen-free path: (private paramiko key, line)."""
    if kind == "ecdsa":
        k = _pk259.ECDSAKey.generate(bits=bits or 256)
        return k, "%s %s p259-ecdsa" % (k.get_name(), k.get_base64())
    if kind == "rsa":
        k = _pk259.RSAKey.generate(bits)
        return k, "ssh-rsa %s p259-rsa" % k.get_base64()
    return _ed25519_259()


_KED259, _LED259 = _ed25519_259()
_KEC259, _LEC259 = _keygen259("ecdsa", 384)
_KRS259, _LRS259 = _keygen259("rsa", 3072)
_KRS2K259, _LRS2K259 = _keygen259("rsa", 2048)
_parsed259 = [_sc259.parse_public_key(x)[1] for x in (_LED259, _LEC259, _LRS259)]
eq("sftp keys: Ed25519, ECDSA and RSA-3072 are accepted", _parsed259, [None, None, None])
check("sftp keys: RSA below 3072 bits is refused, naming the size (NIST SP 800-57's 128-bit level)",
      "3072 bits" in (_sc259.parse_public_key(_LRS2K259)[1] or ""), _sc259.parse_public_key(_LRS2K259)[1])
eq("sftp keys: a DSA key, two lines, a type that is not the key's, or junk is refused",
   [_sc259.parse_public_key(x)[0] is None for x in (
       "ssh-dss AAAAB3NzaC1kc3MAAACBAP p", _LED259 + "\n" + _LEC259,
       "ecdsa-sha2-nistp256 " + _LED259.split()[1], "ssh-ed25519 !!!", "")], [True] * 5)
eq("sftp keys: the fingerprint is OpenSSH's SHA256 form",
   _sc259.parse_public_key(_LED259)[0].fingerprint,
   _sc259.fingerprint(_b64_259.b64decode(_LED259.split()[1])))

with _p9.app_context():
    _owner259 = _User259(username="p259_keys", password_hash=_auth259.hash_password(_PW259), is_active=True)
    _other259 = _User259(username="p259_other", password_hash=_owner259.password_hash, is_active=True)
    _db259.session.add_all([_owner259, _other259])
    _db259.session.commit()
    _OWNER259, _OTHER259 = _owner259.id, _other259.id
_O259 = _p9_client(_OWNER259)
_add259 = _O259.post("/account/sftp-keys/add", data={"public_key": _LED259, "label": "laptop", "password": _PW259})
_dup259 = _O259.post("/account/sftp-keys/add", data={"public_key": _LED259, "password": _PW259})
_small259 = _O259.post("/account/sftp-keys/add", data={"public_key": _LRS2K259, "password": _PW259})
with _p9.app_context():
    _keys259 = [(k.label, k.key_type, k.user_id) for k in _Key259.query.filter_by(user_id=_OWNER259)]
    _kadd259 = [(r.success, r.detail) for r in _AL259.query.filter_by(action="sftp_key_add", user_id=_OWNER259)]
    _kid259 = _Key259.query.filter_by(user_id=_OWNER259).first().id if _keys259 else 0
eq("sftp keys: the Account page adds a key once (a duplicate and a 2048-bit RSA are refused)",
   (_add259.status_code, _dup259.status_code, _small259.status_code, _keys259),
   (302, 302, 302, [("laptop", "ssh-ed25519", _OWNER259)]))
check("sftp keys: every add is audited, refusals as failures",
      [s for s, _d in _kadd259] == [True, False, False] and "SHA256:" in _kadd259[0][1], repr(_kadd259))
_stale259 = _p9_client(_OWNER259)
with _stale259.session_transaction() as _s259:
    _s259["_auth_at"] = _time259.time() - 86400
# r31: the password on the form every time, as the API token's mint (a fresh sign-in is not enough).
_nopw_add259 = _O259.post("/account/sftp-keys/add", data={"public_key": _LEC259})
_badpw_add259 = _O259.post("/account/sftp-keys/add", data={"public_key": _LEC259, "password": _PW259 + "x"})
with _p9.app_context():
    _n_after259 = _Key259.query.filter_by(user_id=_OWNER259).count()
    _why259 = [r.detail for r in _AL259.query.filter_by(action="sftp_key_add", user_id=_OWNER259, success=False)
               .order_by(_AL259.id.desc()).limit(2)]
eq("sftp keys r31: adding a key needs the account password on the form, even in a fresh session (none, or a "
   "wrong one, adds nothing and is audited as refused)",
   (_nopw_add259.status_code, _badpw_add259.status_code, _n_after259, _why259),
   (302, 302, 1, ["refused: wrong password", "refused: wrong password"]))
_stale_add259 = _stale259.post("/account/sftp-keys/add", data={"public_key": _LEC259, "password": _PW259})
with _p9.app_context():
    _n_stale259 = _Key259.query.filter_by(user_id=_OWNER259).count()
    _Key259.query.filter_by(user_id=_OWNER259, key_type=_sc259.parse_public_key(_LEC259)[0].key_type).delete()
    _db259.session.commit()
eq("sftp keys r31: ...and with it, a sign-in past the step-up window adds one (the password is the proof)",
   (_stale_add259.status_code, _n_stale259), (302, 2))
_x259 = _p9_client(_OTHER259).post("/account/sftp-keys/%d/remove" % _kid259)
with _p9.app_context():
    _still259 = _Key259.query.filter_by(id=_kid259).count()
eq("sftp keys: another account cannot remove a key that is not theirs", (_x259.status_code, _still259), (404, 1))
_acct_resp259 = _O259.get("/account")
_acct259 = _acct_resp259.get_data(as_text=True)
_card259 = _acct259[_acct259.find('id="sec-sftp"'):][:3000]
check("sftp keys: the Account page lists the key with its fingerprint and label",
      'id="sec-sftp"' in _acct259 and "laptop" in _card259 and _sc259.parse_public_key(_LED259)[0].fingerprint
      in _card259, "%s %s" % (_acct_resp259.status_code, _card259[:1500] or _acct259[:600]))
_rm259 = _O259.post("/account/sftp-keys/%d/remove" % _kid259)
with _p9.app_context():
    _gone259 = _Key259.query.filter_by(id=_kid259).count()
    _krm259 = _AL259.query.filter_by(action="sftp_key_remove", user_id=_OWNER259).count()
eq("sftp keys: the owner removes it, audited", (_rm259.status_code, _gone259, _krm259), (200, 0, 1))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The service end to end
# ════════════════════════════════════════════════════════════════════════════════════════════════
_ME259 = _pwd259.getpwuid(os.getuid()).pw_name
_E2E = os.geteuid() != 0 and _bk259.local_sftp_server() is not None
_why_skip259 = "run as root (root is never a game account)" if os.geteuid() == 0 else "no sftp-server here"


def _free_port259():
    s = _socket259.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _E2E259:
    """The service running for this block: its port, the audit capture, and the homes."""

    port = 0
    idle_port = 0
    abs_port = 0
    homes = {}
    log_lines = []


class _Capture259(_logging259.Handler):
    """The panel.auth (data/auth.log) lines written while this block runs."""

    handler = None

    def emit(self, record):
        """Keep the line."""
        _E2E259.log_lines.append(record.getMessage())


_Capture259.handler = _Capture259()


def _audits259(action, since):
    with _p9.app_context():
        return [(r.username, r.success, r.detail, r.ip_address, r.game_server_id)
                for r in _AL259.query.filter(_AL259.action == action, _AL259.id > since).order_by(_AL259.id)]


def _last_audit_id259():
    with _p9.app_context():
        r = _AL259.query.order_by(_AL259.id.desc()).first()
        return r.id if r else 0


def _connect259(user, pkey=None, kbd=None, host_key=None):
    """A paramiko SFTP client signed in as `user`, or the exception that refused it."""
    client = _pk259.SSHClient()
    client.get_host_keys().add("[127.0.0.1]:%d" % _E2E259.port, host_key.get_name(), host_key)
    try:
        if kbd is not None:
            t = _pk259.Transport(("127.0.0.1", _E2E259.port))
            t.connect(hostkey=host_key)
            t.auth_interactive(user, lambda _t, _i, prompts: list(kbd)[:len(prompts)])
            return t, _pk259.SFTPClient.from_transport(t)
        client.connect("127.0.0.1", _E2E259.port, username=user, pkey=pkey, look_for_keys=False,
                       allow_agent=False, timeout=15, banner_timeout=15, auth_timeout=15)
        return client, client.open_sftp()
    except Exception as exc:  # noqa: BLE001 - the refusal IS the result here
        client.close()
        return None, exc


def _close259(pair):
    conn, sftp = pair
    for x in (sftp, conn):
        try:
            x.close()
        except Exception:  # noqa: BLE001 - already gone is fine
            _logging259.getLogger("p259").debug("close", exc_info=True)


def _listening259(port):
    """The local addresses listening on TCP `port`, read from /proc/net/tcp and tcp6 (no socket is opened)."""
    out = []
    for table, width in (("/proc/net/tcp", 8), ("/proc/net/tcp6", 32)):
        try:
            with open(table, encoding="ascii") as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            cols = row.split()
            addr, _sep, hexport = cols[1].partition(":")
            if cols[3] != "0A" or int(hexport, 16) != port or len(addr) != width:
                continue
            raw = bytes.fromhex(addr)
            # Each 32-bit word is in host (little-endian) order.
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            out.append(str(_ipaddress259.ip_address(raw)))
    return sorted(out)


def _until259(cond, limit=10.0):
    """Wait (at most `limit` seconds) for `cond()` to hold; whether it did."""
    end = _time259.monotonic() + limit
    while not cond():
        if _time259.monotonic() > end:
            return False
        _time259.sleep(0.1)
    return True


def _sftp_listing259(sftp, path):
    """sorted(sftp.listdir(path)), or the error's class name."""
    try:
        return sorted(sftp.listdir(path))
    except Exception as exc:  # noqa: BLE001 - the error is the result
        return type(exc).__name__


def _read259(path):
    """The bytes of a file the service wrote, or None when it is not there."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def _sftp_err259(fn, *a):
    """The errno-ish answer of an SFTP call: 'ok', or the exception class and text."""
    try:
        fn(*a)
        return "ok"
    except Exception as exc:  # noqa: BLE001 - the error is the result
        return "%s: %s" % (type(exc).__name__, exc)


_runner259 = None
_E2E_UP259 = False
_s = None
if not _E2E:
    skip("sftp end to end: the service, signed in by key and by password and code", _why_skip259)
else:
    try:
        import pyotp as _otp259
        from panel.core.config import encrypt_secret as _enc259

        # Two servers on the panel host whose account is this one, each with its own home.
        _HOME_A = os.path.join(_TMP259, "homeA")
        _HOME_B = os.path.join(_TMP259, "homeB")
        _OUTSIDE = os.path.join(_TMP259, "outside")
        for _d in (_HOME_A, _HOME_B, _OUTSIDE, os.path.join(_HOME_A, "serverfiles"), os.path.join(_HOME_A, ".ssh"),
                   os.path.join(_HOME_A, "log", "console"), os.path.join(_HOME_A, "lgsm", "config-lgsm", "p259server")):
            os.makedirs(_d, exist_ok=True)
        with open(os.path.join(_OUTSIDE, "secret.txt"), "w", encoding="ascii") as _f259:
            _f259.write("outside the home")
        with open(os.path.join(_HOME_A, "server.cfg"), "w", encoding="ascii") as _f259:
            _f259.write("hostname p259\n")
        os.symlink(_OUTSIDE, os.path.join(_HOME_A, "escape"))
        os.symlink(os.path.join(_OUTSIDE, "secret.txt"), os.path.join(_HOME_A, "escape.txt"))
        os.symlink(os.path.join(_HOME_A, "server.cfg"), os.path.join(_HOME_A, "inside-link.cfg"))

        with _p9.app_context():
            _gsa = _GS259(remote_id=P9_LOCAL, name="Alpha One", short_name=_ME259, game_type="p259",
                          port=29001, installed=True, status="offline")
            _gsb = _GS259(remote_id=P9_LOCAL, name="Bravo", short_name=_ME259, game_type="p259b",
                          port=29002, installed=True, status="offline")
            _db259.session.add_all([_gsa, _gsb])
            _db259.session.flush()
            _grp = _Grp259(name="p259_edit", description="", is_default=False)
            _grp.set_permissions([_auth259.VIEW_FILES, _auth259.EDIT_FILES])
            _grp.game_servers.append(_gsa)
            _db259.session.add(_grp)
            _db259.session.flush()
            _secret259 = _otp259.random_base32()
            _ed_user = _User259(username="p259_ed", password_hash=_auth259.hash_password(_PW259), is_active=True)
            _ed_user.groups.append(_grp)
            _tf_user = _User259(username="p259_2fa", password_hash=_ed_user.password_hash, is_active=True,
                                totp_secret=_enc259(_secret259), totp_enabled=True)
            _tf_user.groups.append(_grp)
            _grp_nv = _Grp259(name="p259_editonly", description="", is_default=False)
            _grp_nv.set_permissions([_auth259.EDIT_FILES])
            _grp_nv.game_servers.append(_gsa)
            _db259.session.add(_grp_nv)
            _nv_user = _User259(username="p259_noview", password_hash=_ed_user.password_hash, is_active=True)
            _nv_user.groups.append(_grp_nv)
            _db259.session.add(_nv_user)
            _nofa_user = _User259(username="p259_nofa", password_hash=_ed_user.password_hash, is_active=True)
            _nofa_user.groups.append(_grp)
            _off_user = _User259(username="p259_off", password_hash=_ed_user.password_hash, is_active=False)
            _off_user.groups.append(_grp)
            _db259.session.add_all([_ed_user, _tf_user, _nofa_user, _off_user])
            _db259.session.flush()
            _K1, _L1 = _ed25519_259()
            _K2, _L2 = _ed25519_259()
            _KX, _LX = _ed25519_259()      # registered to nobody
            for _uid, _line in ((_ed_user.id, _L1), (_off_user.id, _L2), (_nofa_user.id, _L2), (_nv_user.id, _L2)):
                _pk = _sc259.parse_public_key(_line)[0]
                _db259.session.add(_Key259(user_id=_uid, label="k", key_type=_pk.key_type, key_blob=_pk.blob_b64,
                                           fingerprint=_pk.fingerprint))
            _db259.session.commit()
            _GSA, _GSB, _GRP, _ED, _TF = _gsa.id, _gsb.id, _grp.id, _ed_user.id, _tf_user.id
        _E2E259.homes = {_GSA: _HOME_A, _GSB: _HOME_B}
        _p9_patch(_br259, "home_of", lambda gs: _E2E259.homes[gs.id])
        _p9_patch(_sh259, "game_account_write_refusal", lambda *a, **k: None)
        _logging259.getLogger("panel.auth").addHandler(_Capture259.handler)

        _host_text259 = _sc259.new_host_key_text()
        _HK259 = _sc259.host_key_from_text(_host_text259)
        _E2E259.port = _free_port259()
        _SPAWN259 = {"ok": True, "binds": ["127.0.0.1"], "port": _E2E259.port, _PWSWITCH259: True, "cap_mb": 1,
                     "host_key": _host_text259, "choice": "loopback"}
        _ag259.reset_throttle()
        _runner259 = _th259.Thread(target=_br259.run_once, args=(_p9, _SPAWN259), daemon=True)
        _runner259.start()
        _deadline259 = _time259.monotonic() + 30
        while _br259.status()["state"] != "running" and _time259.monotonic() < _deadline259:
            _time259.sleep(0.1)
        eq("sftp end to end: the service starts and listens on 127.0.0.1 only",
           (_br259.status()["state"], _br259.status()["bound"]), ("running", [["127.0.0.1", _E2E259.port]]))
        eq("sftp end to end: the kernel lists exactly one listener on the port, 127.0.0.1 (never 0.0.0.0 or ::)",
           _listening259(_E2E259.port), ["127.0.0.1"])
        _since259 = _last_audit_id259()
        _E2E_UP259 = True
    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the setup ran to its end", False, repr(_exc259))


if _E2E_UP259:
    try:
        # ── sign-in by key ──
        _p1 = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        _top259 = sorted(_p1[1].listdir("/")) if _p1[0] else repr(_p1[1])
        eq("sftp end to end: a key signs in; the top folder lists only the server the user may edit",
           _top259, ["Alpha One"])
        eq("sftp end to end: the folder is the game account's home", sorted(_p1[1].listdir("/Alpha One"))
           if _p1[0] else None, sorted(os.listdir(_HOME_A)))
        _sl259 = _audits259("sftp_login", _since259)
        check("sftp end to end: the sign-in is audited with the key and the address",
              len(_sl259) == 1 and _sl259[0][0] == "p259_ed" and "key" in _sl259[0][2] and _sl259[0][3] == "127.0.0.1",
              repr(_sl259))
        _s = _p1[1] if _p1[0] else None
    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the sign-in by key ran to their end", False, repr(_exc259))


if _E2E_UP259 and _s is not None:
    try:
        # ── paths that try to leave the folder ──
        eq("sftp paths: .. cannot climb above the top folder or out of a server's folder",
           (_sftp_listing259(_s, "/Alpha One/../.."), _sftp_listing259(_s, "/Alpha One/serverfiles/../../..")),
           (["Alpha One"], ["Alpha One"]))
        check("sftp paths: an absolute host path is not reachable (it names no server's folder)",
              _sftp_err259(_s.listdir, _OUTSIDE).startswith(("FileNotFoundError", "PermissionError", "IOError")),
              _sftp_err259(_s.listdir, _OUTSIDE))
        eq("sftp paths: a server the user may not edit is not reachable by name",
           _sftp_err259(_s.listdir, "/Bravo")[:17], "FileNotFoundError")
        check("sftp paths: a link inside the folder that leads out is refused (folder and file)",
              _sftp_err259(_s.listdir, "/Alpha One/escape").startswith("PermissionError")
              and _sftp_err259(lambda p: _s.open(p).read(), "/Alpha One/escape.txt").startswith("PermissionError"),
              _sftp_err259(_s.listdir, "/Alpha One/escape") + " | "
              + _sftp_err259(lambda p: _s.open(p).read(), "/Alpha One/escape.txt"))
        _bio = _io259.BytesIO()
        eq("sftp paths: a link that stays inside the folder still works",
           _sftp_err259(_s.getfo, "/Alpha One/inside-link.cfg", _bio) + " " + _bio.getvalue().decode(), "ok hostname p259\n")
        _rl = {}
        for _k, _p in (("inside", "/Alpha One/inside-link.cfg"), ("outward", "/Alpha One/escape.txt"),
                       ("not a link", "/Alpha One/server.cfg")):
            try:
                _rl[_k] = _s.readlink(_p)
            except Exception as _e:  # noqa: BLE001 - the error is the result
                _rl[_k] = type(_e).__name__
        eq("sftp paths: readlink names an inside link's target in the tree, refuses an outward one and a non-link",
           _rl, {"inside": "/Alpha One/server.cfg", "outward": "PermissionError", "not a link": "OSError"})
        eq("sftp paths: no link can be made over SFTP", _sftp_err259(_s.symlink, "/etc", "/Alpha One/l")[:13],
           "OSError: Link")
        check("sftp paths: writing through an outward link is refused and nothing lands outside",
              _sftp_err259(_s.putfo, _io259.BytesIO(b"x"), "/Alpha One/escape/new.txt").startswith("PermissionError")
              and not os.path.exists(os.path.join(_OUTSIDE, "new.txt")), os.listdir(_OUTSIDE))

    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the path checks ran to their end", False, repr(_exc259))


if _E2E_UP259 and _s is not None:
    try:
        # ── the file manager's rules ──
        _rules259 = {
            "delete serverfiles (an empty folder)": _sftp_err259(_s.rmdir, "/Alpha One/serverfiles"),
            "rename the LinuxGSM tree away": _sftp_err259(_s.rename, "/Alpha One/lgsm", "/Alpha One/lgsm2"),
            "write ~/.ssh/authorized_keys": _sftp_err259(_s.putfo, _io259.BytesIO(b"k"),
                                                         "/Alpha One/.ssh/authorized_keys"),
            "write ~/.bashrc": _sftp_err259(_s.putfo, _io259.BytesIO(b"k"), "/Alpha One/.bashrc"),
            "a name with a control character": _sftp_err259(_s.mkdir, "/Alpha One/bad\x07name"),
            "a name ending in a space": _sftp_err259(_s.putfo, _io259.BytesIO(b"k"), "/Alpha One/x.cfg "),
            "write at the top level": _sftp_err259(_s.putfo, _io259.BytesIO(b"k"), "/top.txt"),
            "the console log": _sftp_err259(_s.putfo, _io259.BytesIO(b"k"), "/Alpha One/log/console/p259server-console.log"),
        }
        eq("sftp rules: the web file manager's refusals hold over SFTP",
           sorted(k for k, v in _rules259.items() if v == "ok"), [])
        _chmods = (_sftp_err259(_s.chmod, "/Alpha One/lgsm", 0o700), _sftp_err259(_s.chmod, "/Alpha One/server.cfg", 0o4755),
                   _sftp_err259(_s.chown, "/Alpha One/server.cfg", 0, 0))
        eq("sftp rules: a protected folder's permissions are not changed; setuid is dropped; the owner never changes",
           (_chmods[0][:15], _chmods[1], os.stat(os.path.join(_HOME_A, "server.cfg")).st_mode & 0o7777,
            _chmods[2][:15], os.stat(os.path.join(_HOME_A, "lgsm")).st_mode & 0o777 != 0o700),
           ("PermissionError", "ok", 0o755, "PermissionError", True))
        _cfg_path = "/Alpha One/lgsm/config-lgsm/p259server/p259server.cfg"
        _cfg_disk = os.path.join(_HOME_A, "lgsm", "config-lgsm", "p259server", "p259server.cfg")
        _lts = _sftp_err259(_s.putfo, _io259.BytesIO(b'logtimestamp="on"\n'), _cfg_path)
        eq("sftp rules: a LinuxGSM config that turns logtimestamp on is refused whole (nothing written)",
           (_lts != "ok", os.path.exists(_cfg_disk)), (True, False))
        eq("sftp rules: ...and one that does not is written (a new file in lgsm/ is an upload, not a reserved name)",
           (_sftp_err259(_s.putfo, _io259.BytesIO(b'maxplayers="8"\n'), _cfg_path), _read259(_cfg_disk)),
           ("ok", b'maxplayers="8"\n'))
        _lts2 = _sftp_err259(_s.putfo, _io259.BytesIO(b'logtimestamp="on"\n'), _cfg_path)
        eq("sftp rules: ...and overwriting it with logtimestamp on leaves it exactly as it was",
           (_lts2 != "ok", _read259(_cfg_disk)), (True, b'maxplayers="8"\n'))

    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the file-name rules ran to their end", False, repr(_exc259))


if _E2E_UP259 and _s is not None:
    try:
        # ── writes, the cap, and their audit rows ──
        _since_w = _last_audit_id259()
        _data = os.urandom(300 * 1024)
        _put = _sftp_err259(_s.putfo, _io259.BytesIO(_data), "/Alpha One/upload.bin")
        eq("sftp writes: an upload lands as the game account's file, byte for byte",
           (_put, _read259(os.path.join(_HOME_A, "upload.bin")) == _data), ("ok", True))
        _bio = _io259.BytesIO()
        _s.getfo("/Alpha One/upload.bin", _bio)
        eq("sftp writes: ...and reads back the same", _bio.getvalue() == _data, True)
        _big = _sftp_err259(_s.putfo, _io259.BytesIO(b"\0" * (1024 * 1024 + 1)), "/Alpha One/big.bin")
        _over = _sftp_err259(_s.putfo, _io259.BytesIO(b"\1" * (1024 * 1024 + 1)), "/Alpha One/upload.bin")
        eq("sftp writes: an upload past the size limit (1 MiB here) is refused and leaves nothing behind",
           (_big != "ok", os.path.exists(os.path.join(_HOME_A, "big.bin")),
            sorted(n for n in os.listdir(_HOME_A) if "panel-sftp" in n)), (True, False, []))
        eq("sftp writes: a refused overwrite leaves the old file exactly as it was",
           (_over != "ok", _read259(os.path.join(_HOME_A, "upload.bin")) == _data), (True, True))
        # r31: a file opened for APPEND. sftp-server writes such a handle's data at the end whatever offset
        # is sent, so writes "at offset 0" over and over grew the file past the cap and the free space,
        # which were judged on the offsets. 100 KiB to start, then twelve writes of 100 KiB at offset 0.
        with open(os.path.join(_HOME_A, "grow.bin"), "wb") as _fh259:
            _fh259.write(b"g" * 102400)
        _app_errs259 = []
        _app259 = _s.open("/Alpha One/grow.bin", "a")
        try:
            for _ in range(12):
                _w259 = _sftp_err259(lambda: (_app259.seek(0), _app259.write(b"a" * 102400), _app259.flush()))
                if _w259 != "ok":
                    _app_errs259.append(_w259)
                    break
        finally:
            _sftp_err259(_app259.close)
        _grow_size259 = os.path.getsize(os.path.join(_HOME_A, "grow.bin"))
        check("sftp writes r31: a file opened for append is held to the size limit by what is written, not by the "
              "offsets sent (writes at offset 0 again and again stop at 1 MiB)",
              bool(_app_errs259) and _grow_size259 <= 1024 * 1024,
              "errors=%r size=%d" % (_app_errs259, _grow_size259))
        _sftp_err259(_s.remove, "/Alpha One/grow.bin")
        eq("sftp writes: mkdir, rename and delete work in the folder",
           [_sftp_err259(_s.mkdir, "/Alpha One/maps"), _sftp_err259(_s.rename, "/Alpha One/upload.bin",
                                                                     "/Alpha One/maps/u.bin"),
            _sftp_err259(_s.remove, "/Alpha One/maps/u.bin"), _sftp_err259(_s.rmdir, "/Alpha One/maps")],
           ["ok"] * 4)
        eq("sftp writes: rename never replaces a file that is there",
           (_sftp_err259(_s.rename, "/Alpha One/inside-link.cfg", "/Alpha One/server.cfg")[:7],
            _read259(os.path.join(_HOME_A, "server.cfg"))), ("OSError", b"hostname p259\n"))
        _rows = {a: _audits259(a, _since_w) for a in ("upload_file", "create_folder", "rename_file", "delete_file")}
        check("sftp writes: each upload, mkdir, rename and delete is audited, about the server, from the address",
              all(r and all(x[4] == _GSA and x[3] == "127.0.0.1" and x[2].startswith("SFTP: ") for x in r)
                  for r in _rows.values())
              and any("upload.bin (307200 bytes)" in x[2] and x[1] for x in _rows["upload_file"])
              and any("big.bin" in x[2] and "size limit" in x[2] and not x[1] for x in _rows["upload_file"])
              and any("upload.bin -> maps/u.bin" in x[2] for x in _rows["rename_file"]), repr(_rows))
        eq("sftp writes: a read is not audited", _audits259("read_file", _since_w), [])
        _refused_up259 = [x[2] for x in _rows["upload_file"] if not x[1]]
        eq("sftp writes: a refused upload's audit row never says it overwrote the file (the overwrite was refused)",
           (any("upload.bin" in x for x in _refused_up259), [x for x in _refused_up259 if "(overwrote)" in x]),
           (True, []))

    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the write checks ran to their end", False, repr(_exc259))


if _E2E_UP259 and _s is not None:
    try:
        # ── a permission removed mid-session ──
        _held = _s.open("/Alpha One/server.cfg", "r")
        with _p9.app_context():
            _g = _db259.session.get(_Grp259, _GRP)
            _g.set_permissions([_auth259.VIEW_FILES])
            _db259.session.commit()
        eq("sftp authz: with edit_files taken away, the next listing shows no folder",
           _s.listdir("/"), [])
        _time259.sleep(1.2)
        check("sftp authz: ...and a file already open stops reading",
              _sftp_err259(_held.read, 4).startswith("PermissionError"), _sftp_err259(_held.read, 4))
        with _p9.app_context():
            _g = _db259.session.get(_Grp259, _GRP)
            _g.set_permissions([_auth259.VIEW_FILES, _auth259.EDIT_FILES])
            _db259.session.commit()
        eq("sftp authz: given back, the folder is there again", _s.listdir("/"), ["Alpha One"])
        with _p9.app_context():
            _u = _db259.session.get(_User259, _ED)
            _u.auth_epoch = (_u.auth_epoch or 0) + 1      # "sign out everywhere"
            _db259.session.commit()
        check("sftp authz: signing out everywhere ends the SFTP session's access at once",
              _sftp_err259(_s.listdir, "/").startswith("PermissionError"), _sftp_err259(_s.listdir, "/"))
        _close259(_p1)
    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the permission checks ran to their end", False, repr(_exc259))


if _E2E_UP259:
    try:
        # ── edit_files without view_files ──
        _pnv = _connect259("p259_noview", pkey=_K2, host_key=_HK259)
        if _pnv[0]:
            eq("sftp authz: edit_files alone shows the folder, but reading it needs view_files too",
               (_pnv[1].listdir("/"), _sftp_err259(_pnv[1].listdir, "/Alpha One")[:15],
                _sftp_err259(lambda p: _pnv[1].putfo(_io259.BytesIO(b"w"), p, confirm=False), "/Alpha One/write-only.txt"),
                _read259(os.path.join(_HOME_A, "write-only.txt"))),
               (["Alpha One"], "PermissionError", "ok", b"w"))
        else:
            check("sftp authz: edit_files alone shows the folder, but reading it needs view_files too", False,
                  repr(_pnv[1]))
        _close259(_pnv)

        # ── sign-in by password and code ──
        _since_k = _last_audit_id259()
        _code = _otp259.TOTP(_secret259).now()
        _p2 = _connect259("p259_2fa", kbd=(_PW259, _code), host_key=_HK259)
        eq("sftp sign-in: the password with an authenticator code signs in (2FA account)",
           sorted(_p2[1].listdir("/")) if _p2[0] else repr(_p2[1]), ["Alpha One"])
        _close259(_p2)
        _p3 = _connect259("p259_2fa", kbd=(_PW259, _code), host_key=_HK259)
        eq("sftp sign-in: the same code a second time is refused (single use)", _p3[0], None)
        _close259(_p3) if _p3[0] else None
        _refusals259 = {
            "no 2FA": _connect259("p259_nofa", kbd=(_PW259, "000000"), host_key=_HK259),
            "wrong password": _connect259("p259_2fa", kbd=("wrong-" + _PW259, _code), host_key=_HK259),
            "deactivated": _connect259("p259_off", pkey=_K2, host_key=_HK259),
            "unknown key": _connect259("p259_ed", pkey=_KX, host_key=_HK259),
            "no such user": _connect259("p259_nobody", pkey=_K1, host_key=_HK259),
        }
        eq("sftp sign-in: refused without 2FA, with a wrong password, deactivated, an unknown key, no such user",
           sorted(k for k, v in _refusals259.items() if v[0] is not None), [])
        for _v in _refusals259.values():
            if _v[0] is not None:
                _close259(_v)
        # A key refusal is reported when the connection ends, a moment after the client gave up.
        _until259(lambda: len(_audits259("sftp_login_failed", _since_k)) >= 6)
        _fails259 = _audits259("sftp_login_failed", _since_k)
        check("sftp sign-in: every refusal is audited with its reason and the address",
              all(x[3] == "127.0.0.1" and not x[1] for x in _fails259)
              and any("authenticator code already used" in x[2] for x in _fails259)
              and any("needs two-factor" in x[2] for x in _fails259)
              and any("wrong password" in x[2] for x in _fails259)
              and any("account disabled" in x[2] for x in _fails259)
              and any("key not registered" in x[2] for x in _fails259), repr(_fails259))
        check("sftp sign-in: each failure writes the auth.log line the fail2ban jail counts",
              sum(1 for m in _E2E259.log_lines if m == "panel sftp login failed from 127.0.0.1") >= 5,
              repr(_E2E259.log_lines[-8:]))

        # ── a paused name, and the address throttle ──
        _ag259.reset_throttle()
        import app as _app259
        _app259._LOGIN_FAILS.clear()
        _now259 = _time259.time()
        for _ in range(_ag259.ACCOUNT_SOFT_FAILS):
            _ag259.account_reserve("p259_ed", _now259)
            _ag259.account_reserve("p259_2fa", _now259)
        _p4 = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        eq("sftp sign-in: a name paused after repeated wrong passwords still signs in with its key (not a guess)",
           sorted(_p4[1].listdir("/")) if _p4[0] else repr(_p4[1]), ["Alpha One"])
        _close259(_p4) if _p4[0] else None
        _since_p259 = _last_audit_id259()
        _p4b = _connect259("p259_2fa", kbd=(_PW259, "000000"), host_key=_HK259)
        _close259(_p4b) if _p4b[0] else None
        check("sftp sign-in: ...while a paused name's password sign-in is refused as paused",
              _p4b[0] is None and any("paused" in x[2] for x in _audits259("sftp_login_failed", _since_p259)),
              repr(_audits259("sftp_login_failed", _since_p259)))
        _ag259.reset_throttle()
        _app259._LOGIN_FAILS.clear()
        _app259._LOGIN_FAILS[_auth259.throttle_key("127.0.0.1")] = [_time259.time()] * _app259.LOGIN_MAX_FAILS
        _raw259 = _socket259.create_connection(("127.0.0.1", _E2E259.port), timeout=10)
        _raw259.settimeout(10)
        try:
            _banner259 = _raw259.recv(64)
        except OSError:
            _banner259 = b""
        _raw259.close()
        eq("sftp sign-in: an address over the sign-in throttle is closed before the SSH banner",
           _banner259.startswith(b"SSH-"), False)
        _p5 = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        eq("sftp sign-in: an address over the sign-in throttle is turned away before it signs in", _p5[0], None)
        _close259(_p5) if _p5[0] else None
        _app259._LOGIN_FAILS.clear()
        _ag259.reset_throttle()
    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the sign-in checks ran to their end", False, repr(_exc259))


# ── the idle timeout, on a second service whose limit is three seconds ──
if _E2E_UP259:
    try:
        _REAL_RESTART259()
        _until259(lambda: not _runner259.is_alive(), 15)
        _E2E259.idle_port = _free_port259()
        _spawn_idle259 = dict(_SPAWN259, port=_E2E259.idle_port, idle_min=0.05)
        _runner_idle259 = _th259.Thread(target=_br259.run_once, args=(_p9, _spawn_idle259), daemon=True)
        _runner_idle259.start()
        _until259(lambda: _br259.status()["bound"] == [["127.0.0.1", _E2E259.idle_port]], 30)
        _since_i = _last_audit_id259()
        _E2E259.port = _E2E259.idle_port
        _busy = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        _idle = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        for _ in range(9):                   # a request every half second, for 4.5 s
            _sftp_listing259(_busy[1], "/")
            _time259.sleep(0.5)
        _busy_alive = bool(_busy[0]) and _busy[0].get_transport().is_active()
        _idle_closed = bool(_idle[0]) and _until259(lambda: not _idle[0].get_transport().is_active(), 6)
        eq("sftp idle: a session with no SFTP request past the timeout is closed; one making requests is not",
           (_idle_closed, _busy_alive), (True, True))
        _closed_rows = _audits259("sftp_session_closed", _since_i)
        check("sftp idle: the close is audited, with the user, the address and why",
              len(_closed_rows) == 1 and _closed_rows[0][0] == "p259_ed" and _closed_rows[0][3] == "127.0.0.1"
              and "no SFTP request" in _closed_rows[0][2], repr(_closed_rows))
        _close259(_busy)
        _close259(_idle)
        _REAL_RESTART259()
        _until259(lambda: not _runner_idle259.is_alive(), 15)
    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the idle checks ran to their end", False, repr(_exc259))


# ── the absolute limit, on a third service: 5.4 s, and a 3 s grace for a file still open ──
if _E2E_UP259:
    try:
        _E2E259.abs_port = _free_port259()
        _spawn_abs259 = dict(_SPAWN259, port=_E2E259.abs_port, idle_min=0, absolute_h=0.0015,
                             absolute_grace_min=0.05)
        _runner_abs259 = _th259.Thread(target=_br259.run_once, args=(_p9, _spawn_abs259), daemon=True)
        _runner_abs259.start()
        _until259(lambda: _br259.status()["bound"] == [["127.0.0.1", _E2E259.abs_port]], 30)
        _since_a = _last_audit_id259()
        _E2E259.port = _E2E259.abs_port
        _plain = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        _xfer = _connect259("p259_ed", pkey=_K1, host_key=_HK259)
        _t_signed = _time259.monotonic()
        _slow = _xfer[1].open("/Alpha One/slow.bin", "w", bufsize=0)   # each write sent and answered
        _late = {}
        while _time259.monotonic() - _t_signed < 7.0:          # a write every half second, past the limit
            _late["write"] = _sftp_err259(_slow.write, b"x" * 1024)
            if _time259.monotonic() - _t_signed > 6.0 and "list" not in _late:
                _late["list"] = _sftp_err259(_xfer[1].listdir, "/")[:15]
                _late["open"] = _sftp_err259(lambda p: _xfer[1].open(p, "w").close(), "/Alpha One/new.bin")[:15]
            _time259.sleep(0.5)
        _plain_closed = not _plain[0].get_transport().is_active() if _plain[0] else None
        eq("sftp absolute: past the limit a session opens and lists nothing new, while its open file still writes",
           (_late.get("list"), _late.get("open"), _late.get("write")), ("PermissionError", "PermissionError", "ok"))
        eq("sftp absolute: a session with nothing open is closed at the limit", _plain_closed, True)
        _xfer_open_at_limit = _xfer[0].get_transport().is_active() if _xfer[0] else None
        _xfer_closed = bool(_xfer[0]) and _until259(lambda: not _xfer[0].get_transport().is_active(), 6)
        eq("sftp absolute: ...one with a file open goes on past it, and is closed when the grace runs out",
           (_xfer_open_at_limit, _xfer_closed), (True, True))
        _abs_rows = sorted(r[2] for r in _audits259("sftp_session_closed", _since_a))
        check("sftp absolute: both closes are audited as the absolute limit, the cut one with its open transfer",
              len(_abs_rows) == 2 and all("absolute limit" in r for r in _abs_rows)
              and sum("transfer still open" in r for r in _abs_rows) == 1, repr(_abs_rows))
        _close259(_plain)
        _close259(_xfer)
        _REAL_RESTART259()
        _until259(lambda: not _runner_abs259.is_alive(), 15)
    except Exception as _exc259:  # noqa: BLE001 - a crash is this block's failure
        check("sftp end to end: the absolute-limit checks ran to their end", False, repr(_exc259))


if _E2E:
    # ── off: nothing listens ──
    _REAL_RESTART259()
    if _runner259 is not None:
        _until259(lambda: not _runner259.is_alive(), 15)
        _alive259 = _runner259.is_alive()
        _listeners259 = _listening259(_E2E259.port)
        if _alive259 and _br259._STATE.get("proc") is not None:
            _br259._STATE["proc"].kill()          # a stop that did not stop: end it, so the run goes on
            _until259(lambda: not _runner259.is_alive(), 15)
        eq("sftp service: stopped, nothing listens on its port any more (and its loop ended)",
           (_listeners259, _alive259), ([], False))
    _logging259.getLogger("panel.auth").removeHandler(_Capture259.handler)
    with _p9.app_context():
        for _row in _GS259.query.filter(_GS259.game_type.in_(("p259", "p259b"))).all():
            _db259.session.delete(_row)
        for _row in _Grp259.query.filter(_Grp259.name.in_(("p259_edit", "p259_editonly"))).all():
            _db259.session.delete(_row)
        for _row in _User259.query.filter(_User259.username.in_(("p259_ed", "p259_2fa", "p259_nofa",
                                                                 "p259_off", "p259_noview"))).all():
            _db259.session.delete(_row)
        _db259.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Part 2: the card's IPv6 listener, the jail on every bind change
# ════════════════════════════════════════════════════════════════════════════════════════════════
eq("sftp card: an IPv6 listener is shown in brackets, an IPv4 one as it is",
   [_sc259.listen_text("::", 2222), _sc259.listen_text("2001:db8::10", 2201), _sc259.listen_text("127.0.0.1", 2222)],
   ["[::]:2222", "[2001:db8::10]:2201", "127.0.0.1:2222"])
_put_cfg259(sftp_enabled=True, sftp_bind="all", sftp_port=2222)
_p9_patch(_br259, "status", lambda: {"state": "running", "bound": [["0.0.0.0", 2222], ["::", 2222]],  # nosec B104
                                      "error": "", "detail": "", "since": 0.0})
_html_v6_259 = _A259.get("/settings").get_data(as_text=True)
_state_v6_259 = _html_v6_259.split('id="sftp-state"', 1)[-1].split("</div>", 1)[0]
eq("sftp card: ...and the Settings page says so (`[::]:2222`, never `:::2222`)",
   ("<code data-no-i18n>[::]:2222</code>" in _state_v6_259, ":::2222" in _state_v6_259,
    "<code data-no-i18n>0.0.0.0:2222</code>" in _state_v6_259), (True, False, True))

# Every save rewrites the jail, whichever address it chose: leaving "all addresses" has to take the
# SFTP port out again (it stayed listed until something else rewrote the jail).
_follows259.clear()
_save259(sftp_bind="loopback")
_flashed259()
eq("sftp fail2ban: a save that leaves every address rewrites the jail too", _follows259, [True])
_jail_calls259 = []
import app as _app259   # noqa: E402 - the module the broker imports the jail writer from
_p9_patch(_app259, "_apply_whitelist_to_fail2ban", lambda: _jail_calls259.append(_sc259.settings(
    _cfg259.load_config())["bind"]) or (True, "jail ok"))
_put_cfg259(sftp_enabled=True, sftp_bind="loopback")
_REAL_F2B_FOLLOW259(_p9).join(15)
_put_cfg259(sftp_enabled=False, sftp_bind="all")
_REAL_F2B_FOLLOW259(_p9).join(15)
eq("sftp fail2ban: the jail is rewritten on a start or save under every choice, off included (not only 'all')",
   _jail_calls259, ["loopback", "all"])
_follows259.clear()
_br259._h_ready(_p9, {"bound": [["127.0.0.1", 2222]]}, {})
eq("sftp fail2ban: ...and a start on 127.0.0.1 asks for it", _follows259, [True])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Key TEXT in a host's key PATH field never reaches a log line, a traceback, a flash or a response
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Remotes > Add takes the PATH of a key file. Pasted key text used to reach paramiko as a file name,
# and the FileNotFoundError naming it, the whole private key, was logged with its traceback.
# OWASP Logging Cheat Sheet, "Data to exclude": encryption keys and other primary secrets.
import traceback as _tb259   # noqa: E402
from types import SimpleNamespace as _NS259   # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser259   # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed259   # noqa: E402
from panel.core import validation as _val259   # noqa: E402
from panel.db.models import RemoteServer as _RS259   # noqa: E402
from panel.ops.ssh_manager import _core as _core259, hosts as _hosts259   # noqa: E402
from panel.routes import route_helpers as _rh259   # noqa: E402

_KEY_TEXT259 = _ed259.Ed25519PrivateKey.generate().private_bytes(
    _ser259.Encoding.PEM, _ser259.PrivateFormat.OpenSSH, _ser259.NoEncryption()).decode("ascii").strip()
_KEY_BODY259 = [ln for ln in _KEY_TEXT259.splitlines() if not ln.startswith("-----")]
# What would give the key away: every 12 characters of its body, on any line or across them.
_KEY_FLAT259 = "".join(_KEY_BODY259)
_KEY_BITS259 = [_KEY_FLAT259[i:i + 12] for i in range(0, len(_KEY_FLAT259) - 12, 6)]
_KEY_ONE_LINE259 = _KEY_TEXT259.replace("\n", "")   # what a browser's one-line text box keeps of a paste


def _leaks259(*texts):
    """The key fragments found in `texts` (none is the answer wanted)."""
    blob = "\n".join(t if isinstance(t, str) else repr(t) for t in texts)
    flat = blob.replace("\n", "").replace("\\n", "")
    return [b for b in _KEY_BITS259 if b in blob or b in flat]


class _Records259(_logging259.Handler):
    """Every record, formatted with its traceback, as the journal would get it."""

    def __init__(self):
        """Every level, the lowest included."""
        super().__init__(level=1)
        self.lines = []

    def emit(self, record):
        """Keep the record as one formatted text, its traceback included."""
        self.lines.append(_logging259.Formatter("%(name)s %(levelname)s %(message)s").format(record))


_rec259 = _Records259()
_root259 = _logging259.getLogger()
_root_level259 = _root259.level
_root259.addHandler(_rec259)
_root259.setLevel(1)
try:
    eq("key text: the check refuses a pasted key (header, line breaks, one line), and a path or password passes",
       [_val259.key_text_problem("key", _KEY_TEXT259) is not None,
        _val259.key_text_problem("key", _KEY_ONE_LINE259) is not None,
        _val259.key_text_problem("key", "/srv/keys/id\ned25519") is not None,
        _val259.key_text_problem("key", "/srv/" + "k" * 256) is not None,
        _val259.key_text_problem("key", "/home/panel/.ssh/id_ed25519"),
        _val259.key_text_problem("key", ""),
        _val259.key_text_problem("password", "-----BEGIN pass\nword")],
       [True, True, True, True, None, None, None])

    _add_form259 = {"name": "p259-keytext", "host": "192.0.2.59", "ssh_user": "root", "ssh_port": "22",
                    "auth_method": "key", "lgsm_user": "", "host_key_fingerprint": ""}
    _rows_before259 = None
    with _p9.app_context():
        _rows_before259 = _RS259.query.count()
    _answers259 = []
    for _cred259 in (_KEY_TEXT259, _KEY_ONE_LINE259):
        _r = _A259.post("/remotes/add", data=dict(_add_form259, credential=_cred259),
                        headers={"X-Requested-With": "XMLHttpRequest"})
        _answers259.append((_r.status_code, (_r.get_json() or {}).get("message"), _r.get_data(as_text=True)))
    _r = _A259.post("/remotes/add", data=dict(_add_form259, credential=_KEY_TEXT259))
    _flash_add259 = _flashed259()
    with _p9.app_context():
        _rows_after259 = _RS259.query.count()
    eq("key text: Remotes > Add refuses it (as typed and as one line) before anything connects, and stores nothing",
       ([(c, m) for c, m, _t in _answers259], _r.status_code, _flash_add259, _rows_after259 == _rows_before259),
       ([(400, _val259.KEY_TEXT_REFUSED)] * 2, 302, [_val259.KEY_TEXT_REFUSED], True))

    with _p9.app_context():
        _host259 = _RS259.query.filter_by(name="p9-host").first()
        _host_id259, _cred_before259 = _host259.id, _host259.auth_credential
    _r = _A259.post("/remotes/%d/edit" % _host_id259,
                    data={"name": "", "host": "", "ssh_user": "", "ssh_port": "22", "auth_method": "key",
                          "credential": _KEY_TEXT259, "host_key_fingerprint": ""},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    _edit_answer259 = _r.get_data(as_text=True)
    with _p9.app_context():
        _cred_after259 = _db259.session.get(_RS259, _host_id259).auth_credential
    eq("key text: editing a host refuses it too, and its stored credential is left as it was",
       (_r.status_code, (_r.get_json() or {}).get("message"), _cred_after259 == _cred_before259),
       (400, _val259.KEY_TEXT_REFUSED, True))

    with _p9.test_request_context("/setup", method="POST", data=dict(_add_form259, credential=_KEY_TEXT259)):
        _rh259._setup_add_remote(None, {})
        from flask import get_flashed_messages as _gfm259
        _wizard_flash259 = _gfm259()
    eq("key text: the setup wizard's host step refuses it the same way", _wizard_flash259,
       [_val259.KEY_TEXT_REFUSED])

    # A row that already holds key text (stored before the forms refused it): the Test button and every
    # connection refuse to open it, with a fixed sentence.
    from panel.core.config import encrypt_secret as _enc259   # noqa: E402
    with _p9.app_context():
        _kt_row259 = _RS259(name="p259-keyrow", host="192.0.2.60", port=22, username="root", auth_method="key",
                            auth_credential=_enc259(_KEY_TEXT259), is_online=True)
        _db259.session.add(_kt_row259)
        _db259.session.commit()
        _kt_id259 = _kt_row259.id
    _r = _A259.post("/remotes/%d/test" % _kt_id259, headers={"X-Requested-With": "XMLHttpRequest"})
    _test_answer259 = _r.get_data(as_text=True)
    eq("key text: a stored one is refused by the Test button with the panel's own sentence",
       "holds key text, not a path" in ((_r.get_json() or {}).get("message") or ""), True)
    _conn_err259 = None
    with _p9.app_context():
        try:
            _core259._connect_client(_pk259.SSHClient(), _db259.session.get(_RS259, _kt_id259))
        except ConnectionError as _e259:
            _conn_err259 = _e259
    _conn_text259 = "".join(_tb259.format_exception(_conn_err259)) if _conn_err259 else ""
    eq("key text: ...and by every connection (get_connection's connect), whose error and traceback hold none of it",
       ("holds key text, not a path" in str(_conn_err259), _leaks259(_conn_text259)), (True, []))
    with _p9.app_context():
        _db259.session.delete(_db259.session.get(_RS259, _kt_id259))
        _db259.session.commit()

    # Whatever OSError a key file raises, its file name (the "path") reaches no log line or answer.
    _fnf259 = FileNotFoundError(2, "No such file or directory", _KEY_ONE_LINE259)
    _said259 = _hosts259._ssh_test_failure(_fnf259, "192.0.2.61", 22)
    _REAL_CBA259 = _core259._connect_by_auth_method
    _p9_patch(_core259, "_connect_by_auth_method", lambda *a, **k: (_ for _ in ()).throw(
        FileNotFoundError(2, "No such file or directory", _KEY_ONE_LINE259)))
    _osr259 = None
    try:
        _core259._connect_client(None, _NS259(auth_credential="", auth_method="key", host="192.0.2.62", port=22))
    except ConnectionError as _e259:
        _osr259 = _e259
    _p9_patch(_core259, "_connect_by_auth_method", _REAL_CBA259)
    eq("key text: a key file's OSError is said without its file name, in the answer, the log and the traceback",
       (_leaks259(_said259), "key file could not be read (No such file or directory)" in str(_osr259),
        _leaks259("".join(_tb259.format_exception(_osr259)) if _osr259 else "")),
       ([], True, []))
    eq("key text: nothing of the key reached any log record, response, flash or traceback above",
       _leaks259(_rec259.lines, [a[2] for a in _answers259], _flash_add259, _edit_answer259, _wizard_flash259,
                 _test_answer259), [])
    eq("key text: ...and the failure that was logged is a fixed sentence and the class",
       any(ln.endswith("ssh_test_connection failed: FileNotFoundError (ENOENT)") for ln in _rec259.lines), True)
finally:
    _root259.removeHandler(_rec259)
    _root259.setLevel(_root_level259)


# ── put everything back ──
_p9_restore_all()
_ag259.reset_throttle()
with _p9.app_context():
    for _name in ("p259_keys", "p259_other"):
        _row = _User259.query.filter_by(username=_name).first()
        if _row is not None:
            _db259.session.delete(_row)
    _db259.session.commit()
if _CFG_SNAP259 is None:
    _cfg259.CONFIG_FILE.unlink(missing_ok=True)
else:
    _cfg259.CONFIG_FILE.write_bytes(_CFG_SNAP259)
_cfg259._cfg_cache["key"] = None
_shutil259.rmtree(_TMP259, ignore_errors=True)
