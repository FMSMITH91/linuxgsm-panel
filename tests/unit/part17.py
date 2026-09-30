"""Part 16 of the unit suite: an IPv6 zone id is never an address. Imported for its side effects.

ipaddress accepts a zone id (the scope after '%') on any IPv6 literal and keeps its text verbatim:
spaces, `$(...)`, ';', a newline, a second address. The panel took str(ipaddress.ip_address(x)),
"the canonical form", as its safety check, so that text reached data/auth.log (where fail2ban
banned the second address), admin alerts, the audit trail, the root helper's argv, a remote host's
sshd drop-in, and a login-throttle key that was new on every attempt.

Every entry point that takes an address from outside is fed each payload below and must refuse
it. The few that must key or judge the address instead (a socket peer, a client address a proxy
reports, a throttle bucket, a refuse-only ban check, a value an older version stored) must answer
with the address, never the text. Each block has a positive
control: ordinary IPv4, IPv6, IPv4-mapped, CIDRs and Tailscale's ranges still pass.

Runs before part15, which must stay last: it ends the run with a look for threads left running.
Nothing here reaches a host: the transports are stubbed at their definition sites and restored in
a `finally`.
"""
import ipaddress as _zi
import logging as _zlog

from flask import Flask as _ZFlask

import app as _zapp
from panel.core import config as _zcfgmod
from panel.core import validation as _zv
from panel.db import models as _zmodels
from panel.ops import tailscale_integration as _zts
from panel.routes import remote_security as _zrs
from panel.security import auth as _zauth
from panel.security import banlist as _zbl
from panel.services import monitoring as _zmon
from unit.part01 import NS, SO, _privmod, _sm_core, _sm_hosts, check, eq
from unit.part05 import _helper as _zhelper

# Each is a zone id ipaddress ACCEPTS, so each is a test of the refusal and not of the parser.
_Z_PAYLOADS = (
    "fe80::1%x y",                                          # a space
    "fe80::1%$(id)",                                        # command substitution
    "fe80::1%x;reboot",                                     # a command separator
    "fe80::1%x\n2026-09-29 00:00:00 panel login failed from 203.0.113.9",   # a newline
    "fe80::1%x panel login failed from 203.0.113.9",       # a second address for fail2ban
    "2001:db8::%x y",                                       # host bits zero: kept through a /64
    "::1%lo",                                               # loopback, with a real interface
    "fd7a:115c:a1e0::1%tailscale0",                         # a tailnet address
)
_Z_GOOD_IPS = ("203.0.113.9", "2001:db8::1", "::ffff:203.0.113.9", "100.101.102.103",
               "fd7a:115c:a1e0::5", " 198.51.100.7 ")
_Z_GOOD_NETS = ("10.0.0.0/8", "10.0.0.5/24", "2001:db8::/32", "100.64.0.0/10", "fd7a:115c:a1e0::/48")

check("zone id: every payload really is accepted by ipaddress, text kept (so each check below "
      "tests a refusal, not the parser)",
      all(str(_zi.ip_address(_p)) == _p for _p in _Z_PAYLOADS))


def _z_not_refused(fn, refused=lambda got: got is None, values=_Z_PAYLOADS):
    """The payloads `fn` let through, as 'payload -> answer' strings; [] when it refused them all."""
    out = []
    for _p in values:
        try:
            got = fn(_p)
        except ValueError:
            continue                  # a validator that RAISES has refused
        if not refused(got):
            out.append("%r -> %r" % (_p, got))
    return out


# ── the validators themselves, and every wrapper of them ─────────────────────────────────────────
for _zname, _zfn in (("validation.ip_address_or_none", _zv.ip_address_or_none),
                     ("validation.ip_network_or_none", _zv.ip_network_or_none),
                     ("validation.canonical_ip", _zv.canonical_ip),
                     ("validation.canonical_ip_or_network", _zv.canonical_ip_or_network),
                     ("auth._ip_or_none (client_ip's fallthrough)", _zauth._ip_or_none),
                     ("app._valid_ip_or_cidr (the whitelist's)", _zapp._valid_ip_or_cidr),
                     ("hosts._canonical_ip", _sm_hosts._canonical_ip)):
    _zlet = _z_not_refused(_zfn)
    check("zone id: %s refuses every zone-id payload" % _zname, not _zlet, "; ".join(_zlet))

eq("zone id: ...and still canonicalises ordinary addresses (positive control)",
   [_zv.canonical_ip(g) for g in _Z_GOOD_IPS] + [_zauth._ip_or_none("[2001:DB8::1]:443"),
                                                 _sm_hosts._canonical_ip(" 2001:0DB8::0001 ")],
   [str(_zi.ip_address(g.strip())) for g in _Z_GOOD_IPS] + ["2001:db8::1", "2001:db8::1"])
eq("zone id: ...and networks, masked, with a bare address kept an address (positive control)",
   [_zv.canonical_ip_or_network(n) for n in _Z_GOOD_NETS + ("203.0.113.9",)]
   + [str(_zv.ip_network_or_none("fd7a:115c:a1e0::5"))],
   ["10.0.0.0/8", "10.0.0.0/24", "2001:db8::/32", "100.64.0.0/10", "fd7a:115c:a1e0::/48",
    "203.0.113.9", "fd7a:115c:a1e0::5/128"])

_zlet = _z_not_refused(_zapp._log_ip, refused=lambda got: got == "unknown")
check("zone id: app._log_ip writes 'unknown' to auth.log for every payload, never its text",
      not _zlet, "; ".join(_zlet))
eq("zone id: ...and writes an ordinary address canonically (positive control)",
   [_zapp._log_ip("2001:DB8::1"), _zapp._log_ip(" 203.0.113.9 ")], ["2001:db8::1", "203.0.113.9"])
_zlet = _z_not_refused(_sm_hosts._valid_ip, refused=lambda got: got is False)
check("zone id: hosts._valid_ip answers False for every payload", not _zlet, "; ".join(_zlet))

# The ones that KEEP the address and drop the zone, each for a reason its docstring gives.
eq("zone id: unzoned_ip_address_or_none keeps the ADDRESS and drops the zone (socket peers, keys)",
   [str(_zv.unzoned_ip_address_or_none(_p)) for _p in _Z_PAYLOADS],
   [str(_zi.ip_address(_p.split("%", 1)[0])) for _p in _Z_PAYLOADS])
eq("zone id: ...but an IPv4 address never has a zone, so '1.2.3.4%x' is nothing",
   _zv.unzoned_ip_address_or_none("1.2.3.4%x"), None)
eq("zone id: auth._peer_or_none keys a zoned socket peer as its address",
   [_zauth._peer_or_none(v) for v in ("fe80::1%eth0", "fe80::1%x y", "203.0.113.9", "junk")],
   ["fe80::1", "fe80::1", "203.0.113.9", None])
# throttle_key: '2001:db8::%<text>' with the host bits zero kept the zone through the /64, so a
# client choosing the forwarded address had a new bucket on every attempt.
_zkeys = {_zauth.throttle_key("2001:db8::%%z%d panel" % _i) for _i in range(6)}
eq("zone id: throttle_key puts every zone on one address in ONE bucket, its /64",
   sorted(_zkeys), ["2001:db8::/64"])
eq("zone id: ...and still keys ordinary clients as before (positive control)",
   [_zauth.throttle_key(v) for v in ("2001:db8::1", "203.0.113.9", "::ffff:203.0.113.9", "junk")],
   ["2001:db8::/64", "203.0.113.9", "203.0.113.9", "junk"])

# ── bind addresses: the wizard, the entry point, and the change-port route ───────────────────────
_zlet = _z_not_refused(_zv.bind_host_error, refused=lambda got: got is not None)
check("zone id: bind_host_error refuses every payload as a bind address", not _zlet,
      "; ".join(_zlet))
_zlet = _z_not_refused(lambda p: _zv.bind_host_error(p, _zv.can_bind_address),
                       refused=lambda got: got is not None)
check("zone id: ...including with the wizard's local-address check (a zone made the bind raise "
      "gaierror, which that check read as 'could not tell' and let through)", not _zlet,
      "; ".join(_zlet))
_zlet = _z_not_refused(_zv.can_bind_address, refused=lambda got: got is False)
check("zone id: can_bind_address answers no for every payload", not _zlet, "; ".join(_zlet))
# nosec B104 - the wildcard is a VALUE handed to the validator under test, not a bind.
_Z_WILDCARD = "0.0.0.0"  # nosec B104
eq("zone id: ...while a real local address still binds and passes (positive control)",
   (_zv.can_bind_address("127.0.0.1"), _zv.bind_host_error("127.0.0.1", _zv.can_bind_address),
    _zv.bind_host_error(_Z_WILDCARD)), (True, None, None))
eq("zone id: _bind_is_loopback is False for a zoned loopback ('::1%x' is loopback to ipaddress)",
   [_zapp._bind_is_loopback(v) for v in ("::1%lo", "::1%x y", "::1", "127.0.0.2")],
   [False, False, True, True])
_zlet = _z_not_refused(lambda p: _zrs._bind_refusal(False, p), refused=lambda got: got is not None)
check("zone id: the change-port route's _bind_refusal refuses every payload", not _zlet,
      "; ".join(_zlet))
eq("zone id: _panel_bind_is_public keeps the port open for a zoned bind (unknown = public)",
   [_zrs._panel_bind_is_public(v) for v in ("::1%lo", "fd7a:115c:a1e0::1%x", "::1",
                                            "fd7a:115c:a1e0::1", "203.0.113.9")],
   [True, True, False, False, True])

# ── display flags, the anonymiser ────────────────────────────────────────────────────────────────
eq("zone id: is_tailscale_ip is False for a zoned tailnet address, True for the plain one",
   [_zts.is_tailscale_ip(v) for v in ("fd7a:115c:a1e0::1%tailscale0", "fd7a:115c:a1e0::1",
                                      "100.101.102.103")], [False, True, True])
# An older version stored zoned client addresses (a proxy's link-local client) and reduced some
# with the zone kept ('2001:db8::%<text>/64'). Ageing keeps the network and drops the text.
_zanon = {_p: _zmodels._anonymise_ip(_p) for _p in _Z_PAYLOADS + ("2001:db8::%x y/64",)}
_zanon_want = {_p: str(_zi.ip_network(_p.split("%", 1)[0] + "/64", strict=False)) for _p in _zanon}
check("zone id: _anonymise_ip reduces a stored zoned value to its address's /64 — no '%', no zone "
      "text, the network kept", _zanon == _zanon_want
      and not any("%" in v or "203.0.113" in v or " " in v for v in _zanon.values()),
      "; ".join("%r -> %r" % kv for kv in _zanon.items() if kv[1] != _zanon_want[kv[0]]))
eq("zone id: ...and an IPv4 address with a '%' is still nothing ('' — IPv4 has no zones)",
   _zmodels._anonymise_ip("203.0.113.9%x y"), "")
eq("zone id: ...and still reduces an ordinary address to its network (positive control)",
   [_zmodels._anonymise_ip(v) for v in ("203.0.113.77", "2001:db8::1")],
   ["203.0.113.0/24", "2001:db8::/64"])

# ── the whitelist, as the auto-block and the ban gate read it ────────────────────────────────────
_zwl_nets = [_zi.ip_network(n) for n in ("fe80::/10", "2001:db8::/32", "::1/128",
                                         "fd7a:115c:a1e0::/48")]
_zlet = _z_not_refused(lambda p: _zmon._whitelisted(p, _zwl_nets), refused=lambda got: got is False)
check("zone id: monitoring._whitelisted covers no payload (membership ignored the zone)",
      not _zlet, "; ".join(_zlet))
check("zone id: ...while the plain address is covered (positive control)",
      _zmon._whitelisted("2001:db8::5", _zwl_nets) is True)
# A whitelist entry stored with a zone before the add refused one: the Settings page lists it as
# active, and before the refusal the auto-block honoured it — so it must still exempt its address.
_zmon_saved = (_zmon.load_config, _zmon.tailnet_exempt_ips)
try:
    _zmon.load_config = lambda: {"security_whitelist": [
        "2001:db8::1%x y", "2001:db8:5::%eth0/48", "1.2.3.4%x", "10.0.0.0/8"]}
    eq("zone id: _whitelist_networks reads a stored zoned entry as the address or network it names "
       "(an IPv4 '%' is still nothing), and keeps the good one",
       [str(n) for n in _zmon._whitelist_networks()],
       ["2001:db8::1/128", "2001:db8:5::/48", "10.0.0.0/8"])
    _zmon.tailnet_exempt_ips = lambda remote, ips: set()
    eq("zone id: ...so the auto-block still spares the address of a stored zoned entry (the "
       "caller)",
       sorted(_zmon._autoblock_offenders(NS(id=1, is_local=True),
                                         {"2001:db8::1": 50, "2001:db8:5::9": 50,
                                          "198.51.100.7": 50}, 5)), ["198.51.100.7"])
finally:
    _zmon.load_config, _zmon.tailnet_exempt_ips = _zmon_saved

# ── proxy trust, client_ip, and what the ignored-proxy warning logs ──────────────────────────────
_zapplog = _zlog.getLogger("panel.app")


class _ZLines(_zlog.Handler):
    """Every message logged through it, as the text a log file would get."""

    def __init__(self):
        """Start with no lines."""
        super().__init__()
        self.lines = []

    def emit(self, record):
        """Keep the formatted message."""
        self.lines.append(record.getMessage())


_zh = _ZLines()
_zapplog_saved = (_zapplog.disabled, _zapplog.level)
_zapplog.addHandler(_zh)
_zapplog.disabled = False
_zapplog.setLevel(_zlog.WARNING)
try:
    _znets = _zauth._trusted_proxy_networks(["::1%x y", "fe80::1%x;id", "192.0.2.10"])
    eq("zone id: trusted_proxies ignores a zoned entry, keeps the plain one",
       [str(n) for n in _znets], ["192.0.2.10/32"])
    check("zone id: ...and says so, once per ignored entry",
          len([ln for ln in _zh.lines if ln.startswith("trusted_proxies:")]) == 2, repr(_zh.lines))

    _zfl = _ZFlask("zoneid")
    _zfl.config.update(_TRUST_PROXY=True, _TRUSTED_PROXIES=_znets,
                       _TRUSTED_PROXY_UIDS=frozenset({0}))

    def _z_client_ip(headers, peer="192.0.2.10"):
        with _zfl.test_request_context(headers=headers, environ_overrides={"REMOTE_ADDR": peer}):
            return _zauth.client_ip()

    # Apache's mod_proxy and Go's httputil.ReverseProxy write a link-local client into
    # X-Forwarded-For WITH its zone. Refused, that client was keyed as the proxy that connected, so
    # its failed logins were written as the proxy's and fail2ban banned the proxy — everyone behind
    # it. The zone is dropped instead, and only the parsed address comes back.
    _z_zoned_hops = [
        ({"X-Forwarded-For": "fe80::1c2d:3e4f:5a6b:7c8d%eth0"}, "fe80::1c2d:3e4f:5a6b:7c8d"),
        ({"X-Forwarded-For": "198.51.100.1, fe80::1%x panel login failed from 203.0.113.9"},
         "fe80::1"),
        ({"X-Forwarded-For": "[fe80::1%eth0]:8443"}, "fe80::1"),
        ({"X-Real-IP": "fe80::1%realip, commas survive here from 203.0.113.77"}, "fe80::1"),
        ({"X-Forwarded-For": "2001:db8::%x y"}, "2001:db8::"),
        ({"X-Forwarded-For": "fe80::1%x y", "X-Real-IP": "198.51.100.44"}, "fe80::1"),
    ]
    _z_got = [_z_client_ip(h) for h, _ in _z_zoned_hops]
    eq("zone id: client_ip keys a zoned last X-Forwarded-For hop, and a zoned X-Real-IP, from a "
       "trusted proxy as the CLIENT's address — never as the proxy that connected",
       _z_got, [w for _, w in _z_zoned_hops])
    check("zone id: ...and a zone full of text contributes nothing: no '%', space or second "
          "address",
          not any("%" in g or " " in g or "203.0.113" in g for g in _z_got), repr(_z_got))
    eq("zone id: ...while a hop that is no address still falls back to X-Real-IP, then the proxy, "
       "an IPv4 '%' is no address, and a plain hop is taken (controls)",
       [_z_client_ip({"X-Forwarded-For": "bogus x y", "X-Real-IP": "198.51.100.44"}),
        _z_client_ip({"X-Forwarded-For": "203.0.113.9%x"}),
        _z_client_ip({"X-Forwarded-For": "198.51.100.1, 203.0.113.9"})],
       ["198.51.100.44", "192.0.2.10", "203.0.113.9"])
    eq("zone id: ...and throttle_key buckets a zoned forwarded client with its own /64",
       sorted({_zauth.throttle_key(_z_client_ip({"X-Forwarded-For": "2001:db8:7::1%%z%d" % _i}))
               for _i in range(4)}), ["2001:db8:7::/64"])
    # The fallthrough names the proxy that connected — its socket address, which for a link-local
    # proxy the kernel may report with its interface. That is keyed as the address, not the text.
    _zfl.config["_TRUSTED_PROXIES"] = _zauth._trusted_proxy_networks(["fe80::/64"])
    eq("zone id: ...and a zoned link-local PROXY in that fallback is keyed as its address",
       _z_client_ip({"X-Forwarded-For": "bogus x y"}, peer="fe80::5%eth0"), "fe80::5")
    _zfl.config["_TRUSTED_PROXIES"] = _znets

    _zfl.config["_TRUST_PROXY"] = False
    eq("zone id: a DIRECT link-local socket peer is keyed as its address, not its raw text",
       [_z_client_ip({}, peer="fe80::1%eth0"), _z_client_ip({}, peer="203.0.113.9")],
       ["fe80::1", "203.0.113.9"])

    # The two warning lines CodeQL flagged (py/log-injection): they logged the raw socket peer.
    _zfl.config["_TRUST_PROXY"] = True
    _zauth._ignored_proxy_warned.clear()
    _zh.lines.clear()
    _z_client_ip({"X-Forwarded-For": "203.0.113.9"}, peer="2001:db8::7%x y\nFAKE")
    _zfl.config["_TRUSTED_PROXIES"] = _zauth._trusted_proxy_networks(None)   # loopback
    _z_client_ip({"X-Forwarded-For": "203.0.113.9"}, peer="::1%x y\nFAKE")
    _zignored = [ln for ln in _zh.lines if ln.startswith("ignoring X-Forwarded-For")]
    eq("zone id: the ignored-proxy warnings log the peer's ADDRESS, never its text — both lines",
       [ln.split(" from ", 1)[1].split(" ", 1)[0].rstrip(";") for ln in _zignored],
       ["2001:db8::7", "::1"])
    check("zone id: ...one line each, no newline in either", len(_zignored) == 2
          and not any("\n" in ln or "FAKE" in ln for ln in _zignored), repr(_zignored))
finally:
    _zapplog.removeHandler(_zh)
    _zapplog.disabled, _zapplog.level = _zapplog_saved
    _zauth._ignored_proxy_warned.clear()

# ── the ban gate: a zone is DROPPED here, because every caller only refuses ──────────────────────
_zbl_saved = (_zbl._f2b, _zbl._ufw, _zbl._allow, _zbl._by_len, dict(_zbl._taken))
try:
    _zbl.set_f2b(["2001:db8::1", "203.0.113.9"])
    _zbl.set_ufw([])
    _zbl.set_whitelist([])
    _zfc = _zbl.forwarded_client("198.51.100.1, 2001:db8::1%x y")
    eq("zone id: forwarded_client judges a zoned hop as its address",
       [str(_zfc), str(_zbl.forwarded_client("fe80::1%eth0")), _zbl.forwarded_client("1.2.3.4%x")],
       ["2001:db8::1", "fe80::1", None])
    check("zone id: ...so a banned address with a zone is banned as the firewall judges it too "
          "(widen=False missed it: ipaddress counts the zone in equality)",
          _zbl.is_banned(_zfc, widen=False) and _zbl.is_banned(_zfc))
    _zbl.set_whitelist(["2001:db8::1%x y"])
    check("zone id: a stored zoned whitelist entry still exempts its address from the ban gate, as "
          "it did before the whitelist refused zones",
          not _zbl.is_banned(_zi.ip_address("2001:db8::1"))
          and not any("%" in str(n) for n in _zbl._allow), repr(_zbl._allow))
    _zbl.set_whitelist(["1.2.3.4%x", "junk"])
    check("zone id: ...while an entry that is no address at all exempts nothing (control)",
          _zbl.is_banned(_zi.ip_address("2001:db8::1")) and _zbl._allow == (), repr(_zbl._allow))
    # Through the ban gate's own reader, refresh(), which takes the whitelist from config.json.
    _zbl_cfg_saved = (_zcfgmod.load_config, SO.panel_fail2ban_banned_ips, SO.ufw_blocked_ips)
    try:
        _zcfgmod.load_config = lambda: {"security_whitelist": ["2001:db8::1%eth0"]}
        SO.panel_fail2ban_banned_ips = lambda: ["2001:db8::1", "203.0.113.9"]
        SO.ufw_blocked_ips = lambda: []
        _zbl.refresh()
        check("zone id: ...and refresh() reads a stored zoned entry from config.json the same way",
              not _zbl.is_banned(_zi.ip_address("2001:db8::1"))
              and _zbl.is_banned(_zi.ip_address("203.0.113.9")), repr((_zbl._allow, _zbl._f2b)))
    finally:
        _zcfgmod.load_config, SO.panel_fail2ban_banned_ips, SO.ufw_blocked_ips = _zbl_cfg_saved
finally:
    (_zbl._f2b, _zbl._ufw, _zbl._allow, _zbl._by_len, _zbl_taken0) = _zbl_saved
    _zbl._taken.clear()
    _zbl._taken.update(_zbl_taken0)

# ── the root boundary: privileged.py and tools/panel-helper, every IP verb, both sides ───────────
# (args, index of the address) per verb, panel side then helper side — tailscale-up-key's secret
# goes to the helper on stdin, so the helper is handed one argument fewer.
_Z_IP_VERBS = {
    "f2b-unban": ((["sshd", None], 1), (["sshd", None], 1)),
    "ufw-deny-ip": (([None, "panel-block"], 0), ([None, "panel-block"], 0)),
    "ufw-delete-deny-ip": (([None], 0), ([None], 0)),
    "ufw-allow-from-port": (([None, "22", "tcp", "c"], 0), ([None, "22", "tcp", "c"], 0)),
    "ufw-delete-allow-from-port": (([None, "22", "tcp"], 0), ([None, "22", "tcp"], 0)),
    "tailscale-up-login": ((["yes", None], 1), (["yes", None], 1)),
    "tailscale-up-key": ((["tskey-auth-abc123def", "yes", None, "tag:server"], 2),
                         (["yes", None, "tag:server"], 1)),
}


def _z_with(spec, value):
    args, i = spec
    args = list(args)
    args[i] = value
    return args


_Z_ROUTE_SMUGGLE = ("10.0.0.0/8,fe80::1%x y",)       # a zone after a good route, in one list
for _zverb, (_zpanel, _zhelp) in sorted(_Z_IP_VERBS.items()):
    _zvals = _Z_PAYLOADS + (_Z_ROUTE_SMUGGLE if "tailscale" in _zverb else ())
    _zlet = []
    for _p in _zvals:
        for _side, _run in (("panel", lambda p: _privmod.check_args(_zverb, _z_with(_zpanel, p))),
                            ("remote", lambda p: _privmod.remote_command(_zverb, _z_with(_zpanel, p))),
                            ("helper", lambda p: _zhelper.validate(_zverb, _z_with(_zhelp, p)))):
            try:
                _run(_p)
            except ValueError:
                continue
            _zlet.append("%s accepted %r" % (_side, _p))
    check("zone id: verb %s refuses every payload — panel, remote rendering and root helper"
          % _zverb, not _zlet, "; ".join(_zlet[:4]))

# The helper hands the tool its OWN parse, never the input, so both sides must spell it the same.
_Z_CANON = {
    "ufw-deny-ip": (["2001:0DB8:0000::0005", "panel-block"], ["2001:db8::5", "panel-block"]),
    "ufw-allow-from-port": (["2001:DB8::1/64", "22", "tcp", "c"], ["2001:db8::1/64", "22", "tcp", "c"]),
    "f2b-unban": (["sshd", "2001:0db8::0001"], ["sshd", "2001:db8::1"]),
    "tailscale-up-login": (["yes", "10.0.0.5/255.0.0.0,2001:DB8::/32"],
                           ["yes", "10.0.0.5/8,2001:db8::/32"]),
}
_zdrift = []
for _zverb, (_zin, _zwant) in sorted(_Z_CANON.items()):
    _zp, _zh2 = _privmod.check_args(_zverb, _zin), _zhelper.validate(_zverb, _zin)
    if not (_zp == _zh2 == _zwant):
        _zdrift.append("%s: panel=%r helper=%r want=%r" % (_zverb, _zp, _zh2, _zwant))
check("zone id: panel and helper return the SAME canonical spelling of an address, prefix and "
      "route list — the parsed value, not the input (host bits kept)", not _zdrift,
      "; ".join(_zdrift))
_Z_MAPPED = "::ffff:203.0.113.9"      # spelled differently by Python before 3.13
eq("zone id: ...and still take every ordinary address and route (positive control)",
   [_privmod.canonical_cidr(v) for v in _Z_GOOD_NETS + ("203.0.113.9", _Z_MAPPED)]
   + [_zhelper.v_routes("0.0.0.0/0,::/0"), _zhelper.v_routes("-")],
   ["10.0.0.0/8", "10.0.0.5/24", "2001:db8::/32", "100.64.0.0/10", "fd7a:115c:a1e0::/48",
    "203.0.113.9", str(_zi.ip_address(_Z_MAPPED)), "0.0.0.0/0,::/0", "-"])

# ── the panel host's firewall and fail2ban: refused before any verb is sent ──────────────────────
_zso_saved = {n: getattr(SO, n) for n in ("_run_verb", "_run", "_fail2ban_jails", "fail2ban_overview")}
_zso_calls = []
try:
    def _zso_verb(verb, args=(), timeout=30, merge_stderr=True):
        _zso_calls.append((verb, list(args)))
        return "", "", 0
    SO._run_verb = _zso_verb
    SO._fail2ban_jails = lambda: ["sshd"]
    SO.fail2ban_overview = lambda: {"jails": [{"jail": "sshd", "banned_ips": []}]}
    SO._run = lambda cmd, timeout=30, sudo=False, text=True: ("fe80::1\n::1\n203.0.113.9\n", "", 0)
    for _zname, _zfn in (("ufw_deny_ip", SO.ufw_deny_ip), ("ufw_undeny_ip", SO.ufw_undeny_ip),
                         ("fail2ban_unban", lambda p: SO.fail2ban_unban("sshd", p)),
                         ("fail2ban_unban_ip_everywhere", SO.fail2ban_unban_ip_everywhere)):
        del _zso_calls[:]
        _zlet = _z_not_refused(_zfn, refused=lambda got: got == (False, "Invalid IP address."))
        check("zone id: system_ops.%s refuses every payload, sending nothing" % _zname,
              not _zlet and not _zso_calls, "; ".join(_zlet) + " calls=%r" % _zso_calls[:3])
    del _zso_calls[:]
    _zok = SO.ufw_deny_ip("2001:0DB8::0005")
    check("zone id: ...while an ordinary address is blocked, sent in canonical form (control)",
          _zok[0] is True and ("ufw-deny-ip", ["2001:db8::5", "panel-block"]) in _zso_calls,
          repr((_zok, _zso_calls)))
    eq("zone id: host_has_ip is False for a zoned copy of an address the host HAS",
       [SO.host_has_ip(v) for v in ("fe80::1%eth0", "::1%lo", "fe80::1", "::1")],
       [False, False, True, True])
finally:
    for _n, _v in _zso_saved.items():
        setattr(SO, _n, _v)

# ── remote hosts: every host verb refuses before the transport is touched ────────────────────────
_zcore_saved = {n: getattr(_sm_core, n) for n in ("run_privileged", "run_command", "write_root_file")}
_zhost_saved = {n: getattr(_sm_hosts, n) for n in ("_tcp_reachable",)}
_zcalls = []


def _zrec_priv(answers):
    def _run(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
        _zcalls.append(("verb", verb, list(args)))
        return answers.get(verb, ("", "", 0))
    return _run


_zsrv = NS(id=990016, name="vps", host="203.0.113.10", port=22, username="root",
           auth_method="tailscale", auth_credential="", host_key="", is_local=False,
           sudo_enabled=True)
try:
    _sm_core.run_command = lambda *a, **k: _zcalls.append(("cmd",) + a[1:2]) or ("", "", 0)
    _sm_core.write_root_file = lambda s, target, content, timeout=15: (
        _zcalls.append(("write", target, content)) or ("", "", 0))
    _sm_hosts._tcp_reachable = lambda host, port, timeout=8: False
    _sm_core.run_privileged = _zrec_priv({"f2b-status": ("Jail list:\tsshd\n", "", 0),
                                          "f2b-status-jail": ("Currently banned: 0\n", "", 0)})
    for _zname, _zfn, _zmsg in (
            ("remote_ufw_deny_ip", lambda p: _sm_hosts.remote_ufw_deny_ip(_zsrv, p),
             "Invalid IP address."),
            ("remote_ufw_undeny_ip", lambda p: _sm_hosts.remote_ufw_undeny_ip(_zsrv, p),
             "Invalid IP address."),
            ("remote_ufw_allow_from", lambda p: _sm_hosts.remote_ufw_allow_from(_zsrv, p, "22", "tcp"),
             "Source must be an IP address or network (e.g. 10.0.0.0/24)"),
            ("remote_ufw_allow_from (remove)",
             lambda p: _sm_hosts.remote_ufw_allow_from(_zsrv, p, "22", "tcp", allow=False),
             "Source must be an IP address or network (e.g. 10.0.0.0/24)"),
            ("change_ssh_port (the bind address)",
             lambda p: _sm_hosts.change_ssh_port(_zsrv, 2222, p),
             "Bind address must be a valid IP address, or blank for all interfaces.")):
        del _zcalls[:]
        _zlet = _z_not_refused(_zfn, refused=lambda got, m=_zmsg: got == (False, m))
        check("zone id: hosts.%s refuses every payload before touching the host" % _zname,
              not _zlet and not _zcalls, "; ".join(_zlet[:3]) + " calls=%r" % _zcalls[:3])
    del _zcalls[:]
    _zlet = _z_not_refused(lambda p: _sm_hosts.remote_fail2ban_unban(_zsrv, "sshd", p),
                           refused=lambda got: got == (False, "Invalid IP address."))
    check("zone id: hosts.remote_fail2ban_unban refuses every payload, and no unban is sent",
          not _zlet and not [c for c in _zcalls if c[1] == "f2b-unban"],
          "; ".join(_zlet[:3]) + " calls=%r" % [c for c in _zcalls if c[1] == "f2b-unban"][:3])
    eq("zone id: tailnet_exempt_ips exempts no zoned address",
       _sm_hosts.tailnet_exempt_ips(_zsrv, set(_Z_PAYLOADS)), set())

    # Positive controls: an ordinary value reaches the host, in canonical spelling.
    del _zcalls[:]
    _zok = _sm_hosts.remote_ufw_allow_from(_zsrv, "2001:DB8::1/64", "22", "tcp")
    check("zone id: allow-from still sends an ordinary source, canonical, and reports it (control)",
          _zok == (True, "Port 22/tcp open from 2001:db8::1/64")
          and ("verb", "ufw-allow-from-port", ["2001:db8::1/64", "22", "tcp", ""]) in _zcalls,
          repr((_zok, _zcalls)))
    del _zcalls[:]
    _sm_core.run_privileged = _zrec_priv({
        "sshd-socket-active": ("inactive", "", 3), "sshd-effective-config": ("port 22\n", "", 0),
        "listening-sockets": ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "", 0)})
    _zcp = _sm_hosts.change_ssh_port(_zsrv, 2222, "2001:DB8::5")
    _zdrop = [c[2] for c in _zcalls if c[0] == "write" and c[1] == "sshd-port-dropin"]
    check("zone id: a plain bind still reaches the drop-in, bracketed and canonical (control)",
          _zdrop and "ListenAddress [2001:db8::5]:2222\n" in _zdrop[0]
          and all(ln == "" or ln.startswith(("#", "ListenAddress [2001:db8::5]:"))
                  for ln in _zdrop[0].split("\n")), repr((_zcp, _zdrop)))
finally:
    for _n, _v in _zcore_saved.items():
        setattr(_sm_core, _n, _v)
    for _n, _v in _zhost_saved.items():
        setattr(_sm_hosts, _n, _v)


# ═══ Second-pass review: background jobs, host-local routes, groups ═══════════════════════════════
# Each block drives the function that was wrong. Nothing reaches a host: the one collaborator that
# would (_shared._looks_installed) is stubbed on its definition site and put back in a `finally`,
# and the database is a throwaway SQLite file.
import os as _rv2os                                                                 # noqa: E402
import tempfile as _rv2tmp                                                          # noqa: E402

from panel.core import panel_state as _rv2state                                     # noqa: E402
from panel.routes import _shared as _rv2shared                                      # noqa: E402
from panel.routes import api as _rv2api                                             # noqa: E402
from panel.routes import groups as _rv2groups                                       # noqa: E402
from panel.routes import os_updates as _rv2osu                                      # noqa: E402

_rv2_dir = _rv2tmp.mkdtemp(prefix="lgsm-unit-p17-rv2-")
_rv2_app = _ZFlask("p17_second_pass")
_rv2_app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + _rv2os.path.join(_rv2_dir, "p.db"),
                       SQLALCHEMY_TRACK_MODIFICATIONS=False,
                       SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 5}})
_rv2_app.logger.disabled = True
_zmodels.db.init_app(_rv2_app)
_rv2_db = _zmodels.db
# api.py binds both names at import, so the stub goes on that module as well as on _shared.
_rv2_saved = {(m, n): getattr(m, n) for m in (_rv2shared, _rv2api)
              for n in ("_looks_installed", "_notify_servers_changed")}
_rv2_calls = []


def _rv2_stub(name, fn):
    """Put `fn` in place of `name` wherever the reconcile code reaches it."""
    for m in (_rv2shared, _rv2api):
        setattr(m, name, fn)


def _rv2_row(status, installed=False, name="rv2srv"):
    """A fresh host and one game server on it, as the reconcile ticker's query would load it."""
    r = _zmodels.RemoteServer(name="rv2host", host="192.0.2.61", username="root",
                              auth_method="password", auth_credential="")
    _rv2_db.session.add(r)
    _rv2_db.session.flush()
    gs = _zmodels.GameServer(remote_id=r.id, name=name, short_name=name, game_type="gmod",
                             port=27015, status=status, installed=installed)
    _rv2_db.session.add(gs)
    _rv2_db.session.commit()
    return gs


def _rv2_stored(gid):
    """(status, installed) as the database holds them now, past this session's identity map."""
    with _rv2_db.engine.connect() as conn:
        row = conn.exec_driver_sql("SELECT status, installed FROM game_server WHERE id = ?",
                                   (gid,)).fetchone()
    return (row[0], bool(row[1])) if row else None


def _rv2_retry_during_read(gid, verdict):
    """A _looks_installed that answers `verdict` after Retry started a new install mid-read."""
    def _looks(app, remote, short, lgsm):
        _rv2_calls.append(("looks", short))
        with _rv2_db.engine.begin() as conn:          # retry_install's own commit, elsewhere
            conn.exec_driver_sql("UPDATE game_server SET status = 'installing' WHERE id = ?",
                                 (gid,))
        with _rv2state._install_lock:                 # ...and its queued job
            _rv2state._install_jobs[gid] = {"status": "running", "step": 0, "total": 8,
                                            "started": 0, "updated": 0, "log": []}
        return verdict
    return _looks


try:
    _rv2_stub("_notify_servers_changed", lambda app: _rv2_calls.append(("notify",)))
    with _rv2_app.app_context():
        _rv2_db.create_all()

        # ── the reconcile ticker must not settle an install that was restarted during its read ──
        for _rv2v in (False, True):
            _rv2gs = _rv2_row("failed", installed=True, name="rv2retry%d" % int(_rv2v))
            del _rv2_calls[:]
            _rv2_stub("_looks_installed", _rv2_retry_during_read(_rv2gs.id, _rv2v))
            _zapp._reconcile_stranded_install(_rv2_app, _rv2gs)
            eq("install reconcile: a Retry started while the host was being asked is left alone "
               "(verdict %s): the row stays 'installing', installed untouched" % _rv2v,
               _rv2_stored(_rv2gs.id), ("installing", True))
            check("install reconcile: ...and nothing was broadcast about it (verdict %s)" % _rv2v,
                  ("notify",) not in _rv2_calls, repr(_rv2_calls))
            with _rv2state._install_lock:
                _rv2state._install_jobs.pop(_rv2gs.id, None)
            _rv2_db.session.rollback()

        # Control: with nothing started meanwhile, the verdict still lands exactly as before.
        _rv2gs = _rv2_row("failed", installed=True, name="rv2plain")
        del _rv2_calls[:]
        _rv2_stub("_looks_installed", lambda app, remote, short, lgsm: (
            _rv2_calls.append(("looks", short)) or False))
        _zapp._reconcile_stranded_install(_rv2_app, _rv2gs)
        eq("install reconcile: an undisturbed 'not installed' verdict still settles the row "
           "(control)", _rv2_stored(_rv2gs.id), ("failed", False))
        check("install reconcile: ...and broadcasts it (control)", ("notify",) in _rv2_calls)

        # ── one host check per server at a time, shared by the ticker and the status poll ───────
        _rv2gs = _rv2_row("installing", installed=False, name="rv2busy")
        del _rv2_calls[:]
        check("install reconcile: a server's host check can be claimed",
              _zapp._begin_install_reconcile(_rv2gs.id))
        try:
            check("install reconcile: ...but not twice",
                  not _zapp._begin_install_reconcile(_rv2gs.id))
            _zapp._reconcile_stranded_install(_rv2_app, _rv2gs)
            with _rv2_app.test_request_context():
                _rv2d = _rv2api._reconcile_lost_install(_rv2_app, _rv2gs).get_json()
            check("install reconcile: while one check runs, the ticker and the status poll do not "
                  "ask the host again", not [c for c in _rv2_calls if c[0] == "looks"],
                  repr(_rv2_calls))
            eq("install reconcile: ...and the poll is told the install is still being checked, so "
               "it keeps polling", (_rv2d.get("status"), _rv2_stored(_rv2gs.id)),
               ("running", ("installing", False)))
        finally:
            _zapp._end_install_reconcile(_rv2gs.id)
        with _rv2_app.test_request_context():
            _rv2d = _rv2api._reconcile_lost_install(_rv2_app, _rv2gs).get_json()
        eq("install reconcile: once released, the poll asks the host and settles it (control)",
           (_rv2d.get("status"), _rv2_stored(_rv2gs.id)), ("failed", ("failed", False)))
        check("install reconcile: ...and releases the check when it is done",
              _zapp._begin_install_reconcile(_rv2gs.id))
        _zapp._end_install_reconcile(_rv2gs.id)

        # ── the status poll must not write a verdict onto a row deleted during the read ─────────
        _rv2gs = _rv2_row("installing", installed=False, name="rv2gone")
        _rv2gid = _rv2gs.id

        def _rv2_deleted_during_read(app, remote, short, lgsm):
            with _rv2_db.engine.begin() as conn:
                conn.exec_driver_sql("DELETE FROM game_server WHERE id = ?", (_rv2gid,))
            return False
        _rv2_stub("_looks_installed", _rv2_deleted_during_read)
        del _rv2_calls[:]
        try:
            with _rv2_app.test_request_context():
                _rv2d = _rv2api._reconcile_lost_install(_rv2_app, _rv2gs).get_json()
            _rv2err = None
        except Exception as _rv2e:              # StaleDataError: a 500 to the poll
            _rv2err = _rv2e
            _rv2_db.session.rollback()
            _rv2d = {}
        check("install status: a row deleted while the host was asked answers 'none', not a 500",
              _rv2err is None and _rv2d.get("status") == "none" and ("notify",) not in _rv2_calls,
              repr((_rv2err, _rv2d, _rv2_calls)))
        check("install status: ...and its host check was released even so",
              _zapp._begin_install_reconcile(_rv2gid))
        _zapp._end_install_reconcile(_rv2gid)

        # ── /groups: an id field that is not an id is skipped, never a 500 ──────────────────────
        with _rv2_app.test_request_context(method="POST", data={
                "servers": ["9" * 5000, str(2 ** 64), "٣", "12", " 7", "-3", "", "5"]}):
            try:
                _rv2ids = _rv2groups._posted_ids("servers")
            except Exception as _rv2e:
                _rv2ids = _rv2e
        eq("groups: _posted_ids keeps only ASCII ids that fit SQLite's INTEGER (5,000 digits, "
           "2**64 and an Arabic-Indic digit are skipped instead of raising or being misread)",
           _rv2ids, {12, 5})
        with _rv2_app.test_request_context(method="POST", data={"servers": [str(2 ** 63 - 1)]}):
            eq("groups: ...the largest id a row can have still counts (control)",
               _rv2groups._posted_ids("servers"), {2 ** 63 - 1})
finally:
    for (_rv2m, _rv2n), _rv2f in _rv2_saved.items():
        setattr(_rv2m, _rv2n, _rv2f)
    with _rv2state._install_lock:
        for _rv2k in [k for k, j in _rv2state._install_jobs.items() if j.get("started") == 0]:
            _rv2state._install_jobs.pop(_rv2k, None)
    with _rv2_app.app_context():
        _rv2_db.session.remove()
        _rv2_db.engine.dispose()

# ── a JSON number is not always finite ───────────────────────────────────────────────────────────
# json reads `Infinity` and `1e400` as float('inf'); int() of that raises OverflowError, which the
# reboot delay and the auto-block threshold did not catch — a 500 for a malformed body.
_rv2_esc = SO._can_escalate
try:
    SO._can_escalate = lambda: True
    try:
        _rv2rb = SO.server_reboot(float("inf"))
    except Exception as _rv2e:
        _rv2rb = _rv2e
    eq("server_reboot: an infinite delay is refused with the delay message, not raised (and no "
       "reboot is scheduled)", _rv2rb,
       (False, "The reboot delay must be a number of seconds (0-300)."))
finally:
    SO._can_escalate = _rv2_esc

_rv2_cfg_path = _zcfgmod.CONFIG_FILE
_rv2_cfg_snap = _rv2_cfg_path.read_bytes() if _rv2_cfg_path.exists() else None
try:
    if _rv2_cfg_path.exists():
        _rv2_cfg_path.unlink()                    # a fresh install's config for what follows
    _rv2_thr_before = _zmon._autoblock_threshold()
    try:
        _rv2thr = _zapp._maybe_set_threshold({"threshold": float("inf")})
    except Exception as _rv2e:
        _rv2thr = _rv2e
    eq("autoblock threshold: an infinite value is ignored like any other non-number, not raised",
       _rv2thr, _rv2_thr_before)

    # ── the panel-update notification is sent once per commit, not once per process ─────────────
    _rv2_sent = []
    _rv2_ann = _rv2osu._announce_panel_update
    _rv2osu._announce_panel_update = lambda app, st, tgt: _rv2_sent.append(tgt)
    try:
        _rv2st = {"update_available": True, "target_sha": "abc1234def"}
        _rv2last = _rv2osu._announced_update()          # a first boot: nothing announced yet
        _rv2last = _rv2osu._update_tick(None, _rv2st, _rv2last)
        _rv2last = _rv2osu._update_tick(None, _rv2st, _rv2last)
        eq("update check: a newly available commit is announced once within a process",
           _rv2_sent, ["abc1234def"])
        # A restart: the loop's own copy starts again from what config.json holds.
        _rv2osu._update_tick(None, _rv2st, _rv2osu._announced_update())
        eq("update check: ...and NOT again after a restart, for the same commit",
           _rv2_sent, ["abc1234def"])
        _rv2osu._update_tick(None, {"update_available": True, "target_sha": "fff0000aaa"},
                             _rv2osu._announced_update())
        eq("update check: a different commit is still announced (control)",
           _rv2_sent, ["abc1234def", "fff0000aaa"])
        _rv2osu._update_tick(None, {"update_available": False}, _rv2osu._announced_update())
        _rv2osu._update_tick(None, _rv2st, _rv2osu._announced_update())
        eq("update check: once up to date, a later update is announced again, restart or not",
           _rv2_sent, ["abc1234def", "fff0000aaa", "abc1234def"])
    finally:
        _rv2osu._announce_panel_update = _rv2_ann
finally:
    if _rv2_cfg_snap is None:
        if _rv2_cfg_path.exists():
            _rv2_cfg_path.unlink()
    else:
        _rv2_cfg_path.write_bytes(_rv2_cfg_snap)

# ── Codacy splits: the legs of _create_key_once and _set_corrupt_db_aside no other check reaches ──
# A filesystem without hard links takes _create_key_once's O_EXCL fallback; and a second corrupt
# copy in the same second must not reuse the first one's aside name (or its -wal/-shm).
import time as _ck17time                                                            # noqa: E402

_ck17_dir = _rv2tmp.mkdtemp()
_ck17_link = _rv2os.link


def _ck17_no_link(*_a, **_k):
    raise PermissionError(1, "Operation not permitted")


try:
    _ck17_kp = _rv2os.path.join(_ck17_dir, "k")
    _rv2os.link = _ck17_no_link
    try:
        _zcfgmod._create_key_once(_ck17_kp, lambda: b"FIRST")
        _zcfgmod._create_key_once(_ck17_kp, lambda: b"SECOND")
    finally:
        _rv2os.link = _ck17_link
    with open(_ck17_kp, "rb") as _ck17f:
        eq("key file, no hard links: created once with its bytes, never overwritten",
           _ck17f.read(), b"FIRST")
    eq("key file, no hard links: 0600", _rv2os.stat(_ck17_kp).st_mode & 0o777, 0o600)
    eq("key file, no hard links: no temp file is left behind",
       [n for n in _rv2os.listdir(_ck17_dir) if n.startswith(".key-")], [])

    _ck17_db = _rv2os.path.join(_ck17_dir, "p.db")
    _ck17_now = int(_ck17time.time())
    for _ck17s in range(_ck17_now, _ck17_now + 6):
        open("%s.corrupt-%d-wal" % (_ck17_db, _ck17s), "w").close()
    _ck17_aside = _zmodels._db_aside_name(_ck17_db)
    check("corrupt aside: a name whose -wal is taken gets a -1 suffix, not the taken name",
          any(_ck17_aside == "%s.corrupt-%d-1" % (_ck17_db, _s)
              for _s in range(_ck17_now, _ck17_now + 6)), repr(_ck17_aside))
finally:
    _rv2os.link = _ck17_link
    __import__("shutil").rmtree(_ck17_dir, ignore_errors=True)


# ── the config editor's write, and GMod's host-wide content gate, pinned branch by branch ─────────
# Both were lifted out of their route bodies into module helpers (Codacy CCN). Neither branch set
# was pinned: the smoke sweep only asks that a wrong-shaped config body is not a 500, and nothing
# drove the refusal a server-only admin gets for content that is host-wide. Driven directly on a
# bare app with the collaborators stubbed at panel.routes.server_files and restored in the finally.
from types import SimpleNamespace as _sf17NS  # noqa: E402

from panel.routes import server_files as _sf17  # noqa: E402

_sf17_app = _ZFlask("p17-server-files")
_sf17_app.logger.disabled = True
_sf17_names = ("write_file", "lgsm_write_config", "log_action", "current_user", "can_access_remote",
               "detect_content_user")
_sf17_saved = {_sf17n: getattr(_sf17, _sf17n) for _sf17n in _sf17_names}
_sf17_calls = []


def _sf17_out(resp):
    """(status, json) of a view's return value, bare or (response, status)."""
    body, code = resp if isinstance(resp, tuple) else (resp, 200)
    return code, body.get_json()


def _sf17_raise(*_a, **_k):
    raise RuntimeError("write path fell over")


try:
    _sf17.write_file = lambda remote, short, rel, raw: (
        _sf17_calls.append(("write", rel, raw)), (True, ""))[1]
    _sf17.lgsm_write_config = lambda remote, short, lgsm, settings: (
        _sf17_calls.append(("settings", dict(settings))), (False, ""))[1]
    _sf17.log_action = lambda user, action, **kw: _sf17_calls.append(
        ("audit", action, kw.get("target"), kw.get("success")))
    _sf17_gs = _sf17NS(remote="R", short_name="sf17srv", lgsm_name="gmodserver", name="sf17",
                       remote_id=7)
    with _sf17_app.test_request_context():
        # config: the two wrong shapes are refused with their reason, and nothing is written
        for _sf17_body, _sf17_msg in (({"raw": 5}, "The file contents must be text."),
                                      ({"settings": [1]}, "Settings must be a map of names to values.")):
            del _sf17_calls[:]
            eq("config write: %r is a 400 with its reason, nothing written or audited" % _sf17_body,
               (_sf17_out(_sf17._sf_config_write(_sf17_gs, _sf17_body)), _sf17_calls),
               ((400, {"success": False, "message": _sf17_msg}), []))
        # ...raw text goes to the instance's own .cfg and is audited; "Saved" when the writer is silent
        del _sf17_calls[:]
        eq("config write: raw text is written to the instance's own LinuxGSM cfg, and audited",
           (_sf17_out(_sf17._sf_config_write(_sf17_gs, {"raw": "a=\"1\"\n"})), _sf17_calls),
           ((200, {"success": True, "message": "Saved"}),
            [("write", "lgsm/config-lgsm/gmodserver/gmodserver.cfg", "a=\"1\"\n"),
             ("audit", "edit_config", "sf17", True)]))
        # ...no raw goes through the config writer, an absent map as {}; "Failed" on a silent no
        del _sf17_calls[:]
        eq("config write: no raw and no settings writes an empty map, and a silent failure says so",
           (_sf17_out(_sf17._sf_config_write(_sf17_gs, {})), _sf17_calls),
           ((200, {"success": False, "message": "Failed"}),
            [("settings", {}), ("audit", "edit_config", "sf17", False)]))
        _sf17.write_file = _sf17_raise
        eq("config write: a writer that raises is a generic 500, never its text",
           _sf17_out(_sf17._sf_config_write(_sf17_gs, {"raw": "x"})),
           (500, {"success": False, "message": "Internal server error"}))

        # gmod: host-wide content needs the host, for anyone who is not a superadmin
        _sf17_access = []
        _sf17.can_access_remote = lambda user, rid: (_sf17_access.append(rid), user.host)[1]
        _sf17.detect_content_user = lambda remote, games: {"user": "gmc", "present": {"cstrike": 1}}
        _sf17.current_user = _sf17NS(is_superadmin=False, host=False)
        _sf17_r = _sf17._sf_gmod_host_refusal(_sf17_gs, "R", "uninstall", ["cstrike"])
        eq("gmod content: a server-only admin may not uninstall host-wide content",
           (_sf17_out(_sf17_r), _sf17_access),
           ((403, {"success": False, "message": (
               "Removing content affects every Garry's Mod server on this host, so it needs "
               "access to the host, not just this server.")}), [7]))
        _sf17_r = _sf17._sf_gmod_host_refusal(_sf17_gs, "R", "mount", ["cstrike", "tf", "hl2mp"])
        eq("gmod content: ...nor mount content the host does not have yet, named by label",
           _sf17_out(_sf17_r),
           (403, {"success": False, "message": (
               "Not on this host yet: Team Fortress 2, Half-Life 2: Deathmatch. Downloading "
               "content for every Garry's Mod server here needs access to the host — ask its "
               "admin to install it, then mount it here.")}))
        eq("gmod content: ...while mounting what the host already has stays theirs",
           _sf17._sf_gmod_host_refusal(_sf17_gs, "R", "mount", ["cstrike"]), None)
        _sf17.detect_content_user = lambda remote, games: None
        eq("gmod content: ...and an unreadable content account counts as nothing present",
           _sf17_out(_sf17._sf_gmod_host_refusal(_sf17_gs, "R", "mount", ["cstrike"]))[0], 403)
        _sf17.current_user = _sf17NS(is_superadmin=False, host=True)
        eq("gmod content: host access lifts the gate (uninstall)",
           _sf17._sf_gmod_host_refusal(_sf17_gs, "R", "uninstall", ["cstrike"]), None)
        del _sf17_access[:]
        _sf17.current_user = _sf17NS(is_superadmin=True, host=False)
        eq("gmod content: ...and so does being a superadmin, without asking about the host",
           (_sf17._sf_gmod_host_refusal(_sf17_gs, "R", "mount", ["tf"]), _sf17_access), (None, []))
finally:
    for _sf17n, _sf17v in _sf17_saved.items():
        setattr(_sf17, _sf17n, _sf17v)
