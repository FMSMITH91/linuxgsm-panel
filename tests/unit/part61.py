"""Part 61 of the unit suite: review 1011d's system_ops, Tailscale Serve, ssh-core and notify fixes.

Held here, each against the code path the finding named:

* a panel route on a Tailscale Service's listener ("(svc:<name>)") is never removed with the node's
  own `serve --https=443 ... off`, which took down another app at that mount on the node;
* a Serve handler the CLI prints with no kind (a Redirect) still holds its mount;
* a firewall rule that admits only this machine (on lo or a container bridge, from or to loopback)
  or only UDP (the protocol printed in the From column) is no way in, so the host's only public
  `22/tcp` stays protected; one admitting every port on tailscale0 in any spelling is a way in;
* a rate-limited (LIMIT) panel port reads as open on the Network card;
* a numeric chat_id / channel_id / ntfy topic in config.json no longer raises from the Test
  button or stops ntfy alerts; a hand-edited `Infinity` wait does not raise; a non-string
  bind_host does not 500 the change-port form;
* JSON inside a JSON string has its secret redacted.

HOW IT RUNS. Pure functions with their outside calls stood in for (part20's _patch / _patched,
undone at the end of each block), and one route on part12's Flask app and client. Nothing touches
the network, sudo, a real host or the checkout's data/.
"""
import types as _types61

from unit.part01 import check
from unit.part02 import protect as _protect61
from unit.part12 import P9_ADMIN, _P9_CFG_PATH, _p9, _p9_cfg, _p9_client, _p9_json
from unit.part20 import _patch, _patched

from panel.ops import system_ops as _so61  # noqa: E402
from panel.ops import tailscale_integration as _ts61  # noqa: E402
from panel.ops.ssh_manager import _core as _smc61  # noqa: E402
from panel.ops.ssh_manager import hosts as _smh61  # noqa: E402
from panel.routes import tailscale as _rts61  # noqa: E402
from panel.services import host_reboot as _hr61  # noqa: E402
from panel.services import notifications as _nt61  # noqa: E402

NS = _types61.SimpleNamespace
# Addresses built from their parts, so no address literal is added: loopback, a documentation
# address (TEST-NET-2), a private LAN range, Tailscale's CGNAT range and one tailnet address.
_LB61 = ".".join(["127", "0", "0", "1"])
_ADMIN61 = ".".join(["198", "51", "100", "7"])
_LAN61 = ".".join(["192", "168", "1", "0"]) + "/24"
_CGNAT61 = ".".join(["100", "64", "0", "0"]) + "/10"
_TSIP61 = ".".join(["100", "64", "0", "9"])
_CFG61_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _try61(fn, *a, **k):
    """Return fn's answer, or the NAME of the exception it raised (so a revert fails by name)."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - which class arrives IS the check
        return type(exc).__name__


# ── A02: a Tailscale Service's route is never removed through the node's own :443 listener ──────
_SVC61 = ("https://node.tail.ts.net (tailnet only)\n"
          "|-- /     proxy http://%s:3000\n"
          "|-- /lgsm proxy http://%s:5000\n"
          "https://web.tail.ts.net (tailnet only) (svc:web)\n"
          "|-- /     proxy http://%s:5000\n") % (_LB61, _LB61, _LB61)
_svc61 = _ts61._parse_serve_status(_SVC61)
_offs61 = []


def _ts_run61(args, timeout=5):
    """The `tailscale` CLI: every `off` is recorded and succeeds; nothing else is asked here."""
    if args and args[-1] == "off":
        _offs61.append(list(args))
    return "", "", 0


def _with_svc61(fn, *a):
    """Run fn against the node+Service status above; returns (answer, the `off`s sent)."""
    del _offs61[:]
    with _patched():
        _patch(_ts61, "get_tailscale_info", lambda force_refresh=False: NS(
            installed=True, serve_unreadable=False, serve_config=_svc61))
        _patch(_ts61, "_run_ts", _ts_run61)
        _patch(_ts61, "ensure_operator", lambda: None)
        got = _try61(fn, *a)
    return got, list(_offs61)


_NODE_ROOT_OFF61 = ["serve", "--https=443", "--set-path=/", "off"]
_stale61, _soffs61 = _with_svc61(_ts61.remove_stale_panel_routes, 5000, "/lgsm")
check("serve: boot's leftover sweep leaves a panel route on a Tailscale Service alone (its `off` "
      "named the node's own :443 and removed the other app at /)",
      _stale61 == ("none", [], "") and _soffs61 == [], repr((_stale61, _soffs61)))
_dis61, _doffs61 = _with_svc61(_ts61.disable_tailscale_serve, "/lgsm", 5000)
check("serve: Disable removes only the node's own panel route and says the Service still publishes "
      "the panel (it sent `--set-path=/ off` too, taking the other app's / off the node)",
      _NODE_ROOT_OFF61 not in _doffs61
      and _doffs61 == [["serve", "--https=443", "--set-path=/lgsm", "off"]]
      and isinstance(_dis61, tuple) and _dis61[0] is True and "svc:web" in _dis61[1],
      repr((_dis61, _doffs61)))
_svcr61 = [r for r in _ts61.panel_serve_routes(_svc61, 5000) if r.get("svc")]
_rm61, _roffs61 = _with_svc61(_ts61.remove_panel_route, _svcr61[0] if _svcr61 else {}, 5000)
check("serve: removing a Service route by hand answers failed and runs nothing",
      isinstance(_rm61, tuple) and _rm61[0] == "failed" and "svc:web" in _rm61[1]
      and _roffs61 == [], repr((_rm61, _roffs61)))
_nodr61 = [r for r in _ts61.panel_serve_routes(_svc61, 5000) if not r.get("svc")]
_rmn61, _rnoffs61 = _with_svc61(_ts61.remove_panel_route, _nodr61[0] if _nodr61 else {}, 5000)
check("serve: ...while a node route to the panel is still removed with its own mount (control)",
      _rmn61 == ("removed", "") and _rnoffs61 == [["serve", "--https=443", "--set-path=/lgsm", "off"]],
      repr((_rmn61, _rnoffs61)))
_msvc61 = {"url": "https://web.tail.ts.net", "mount": "/lgsm", "svc": "svc:web",
           "target": "http://%s:5000" % _LB61}
_mcfg61 = {"tailscale_setup_done": True, "tailscale_mount": "/lgsm"}
check("serve: a Service route at tailscale_mount is not the route the panel manages",
      _ts61.is_managed_route(_msvc61, _mcfg61) is False
      and _ts61.is_managed_route(dict(_msvc61, svc=""), _mcfg61) is True, repr(_msvc61))
with _patched():
    _patch(_rts61.ts, "get_tailscale_info", lambda force_refresh=False: NS(
        installed=True, serve_unreadable=False, serve_config=_svc61))
    _patch(_rts61, "load_config", lambda: dict(_mcfg61))
    with _p9.test_request_context():
        _lr61 = _try61(_rts61._leftover_route, 5000, "https://web.tail.ts.net", "/")
        # (None, (response, status)) is a refusal; (route, None) would go on to remove it.
        _lr61 = ((_lr61[1][1], _p9_json(_lr61[1][0]).get("message", ""))
                 if isinstance(_lr61, tuple) and _lr61[1] else _lr61)
check("serve: the page's Remove refuses a Service route (400) before anything runs",
      isinstance(_lr61, tuple) and _lr61[0] == 400 and "svc:web" in _lr61[1], repr(_lr61))

_bare61 = _ts61._parse_serve_status("https://h.tail.ts.net (tailnet only)\n|-- /\n"
                                    "|-- /lgsm proxy http://%s:5000\n" % _LB61)
check("serve status: a handler printed with no kind (a Redirect, set with `serve set-raw`) holds its "
      "mount, so the wizard does not publish the panel over it",
      [r["mount"] for s in _bare61["services"] for r in s["routes"]] == ["/", "/lgsm"]
      and _ts61.free_panel_mount(_bare61, 5000, "/") == "/lgsm", repr(_bare61["services"]))

# ── A02 lead: JSON inside a JSON string is redacted ─────────────────────────────────────────────
_red61 = _so61._redact('body={\\"password\\": \\"hunter2 x\\", \\"user\\": \\"bob\\"}')
check("redact: a secret in escaped JSON (`{\\\"password\\\": \\\"hunter2 x\\\"}`) is redacted whole and the "
      "next key kept", _red61 == 'body={\\"password\\": [redacted], \\"user\\": \\"bob\\"}', repr(_red61))

# ── A03: what is, and is not, another way in past the host's one public SSH rule ────────────────


def _fw61(rules, **kw):
    """{To column + scope: group} of `rules` on a remote whose sshd serves 22."""
    return {(x["port_label"], x["scope"]): x
            for x in _protect61(NS(port=22), rules, sshd_ports=(22,), **kw)}


def _ssh22_61(rules, **kw):
    """(the extra rule's is_ssh, 22/tcp protected, 22/tcp warn) with `rules` beside `22/tcp ALLOW`."""
    g = _fw61(["22/tcp ALLOW IN Anywhere"] + rules, **kw)
    extra = [v for k, v in g.items() if k != ("22/tcp", "Any address")]
    ssh = g[("22/tcp", "Any address")]
    return (any(x["is_ssh"] for x in extra), ssh["protected"], ssh["warn"])


_WAY_IN61 = {
    "from an admin address": ["Anywhere ALLOW IN %s" % _ADMIN61],
    "from an admin address over tcp": ["Anywhere ALLOW IN %s/tcp" % _ADMIN61],
    "on eth0": ["Anywhere on eth0 ALLOW IN Anywhere"],
    "on br0 (an uplink bridge)": ["Anywhere on br0 ALLOW IN Anywhere"],
    "from a LAN range": ["Anywhere ALLOW IN %s" % _LAN61],
    "every tcp port": ["Anywhere/tcp ALLOW IN Anywhere"],
}
_NOT_IN61 = {
    "on lo": ["Anywhere on lo ALLOW IN Anywhere", "Anywhere (v6) on lo ALLOW IN Anywhere (v6)"],
    "on docker0": ["Anywhere on docker0 ALLOW IN Anywhere"],
    "on a docker network bridge": ["Anywhere on br-0123456789ab ALLOW IN Anywhere"],
    "on virbr0": ["Anywhere on virbr0 ALLOW IN Anywhere"],
    "from v4 loopback": ["Anywhere ALLOW IN %s" % _LB61],
    "from ::1": ["Anywhere (v6) ALLOW IN ::1"],
    "to v4 loopback": ["%s ALLOW IN Anywhere" % _LB61],
    "22/tcp on lo": ["22/tcp on lo ALLOW IN Anywhere"],
    "22 from the loopback /8": ["22 ALLOW IN %s/8" % ".".join(["127", "0", "0", "0"])],
    "udp from an address (From column)": ["Anywhere ALLOW IN %s/udp" % _ADMIN61],
    "every udp port": ["Anywhere/udp ALLOW IN Anywhere"],
    "OUT": ["Anywhere ALLOW OUT Anywhere on eth0"],
    "FWD": ["Anywhere on eth0 ALLOW FWD Anywhere"],
    "a DENY from an address": ["Anywhere DENY IN %s" % _ADMIN61],
}
_way61 = {k: _ssh22_61(v) for k, v in _WAY_IN61.items()}
check("firewall: an inbound rule admitting every port from another machine is another way in, so "
      "the public 22/tcp only warns (control: admin address, eth0, br0, a LAN range)",
      set(_way61.values()) == {(True, False, True)}, repr(_way61))
_not61 = {k: _ssh22_61(v) for k, v in _NOT_IN61.items()}
check("firewall: a rule admitting only this machine (lo, docker0, a docker or libvirt bridge, from or "
      "to loopback), only UDP (either column), OUT, FWD or a DENY is no way in: the only public "
      "22/tcp stays protected (lo and docker0 made it deletable)",
      {k: v for k, v in _not61.items() if v != (False, True, False)} == {}, repr(_not61))

_TS_RUN61 = {"tailscale": (True, False)}
_tsr61 = {}
for _k61, _rule61 in (("Anywhere/tcp", "Anywhere/tcp on tailscale0 ALLOW IN Anywhere"),
                      ("an address", "%s on tailscale0 ALLOW IN Anywhere" % _TSIP61)):
    _g61 = list(_fw61([_rule61], **_TS_RUN61).values())[0]
    _tsr61[_k61] = (_g61["is_tailscale"], _g61["protected"])
check("firewall: a tailnet-only host's one way in written `allow in on tailscale0 proto tcp` or `... to "
      "<addr>` is a Tailscale access rule and protected (an ordinary delete × before)",
      set(_tsr61.values()) == {(True, True)}, repr(_tsr61))
_g61 = _fw61(["Anywhere/tcp on tailscale0 DENY IN Anywhere", "Anywhere on tailscale0 ALLOW IN Anywhere",
              "22/tcp ALLOW IN Anywhere"], **_TS_RUN61)[("22/tcp", "Any address")]
check("firewall: a tcp DENY on tailscale0 above its allow wins (first match), so the tailnet is no "
      "way in and the public 22/tcp is protected", _g61["protected"] and not _g61["warn"],
      repr((_g61["protected"], _g61["warn"])))
_g61 = _fw61(["Anywhere on tailscale0 ALLOW IN %s/udp" % _CGNAT61, "22/tcp ALLOW IN Anywhere"],
             **_TS_RUN61)
_tsu61 = [(v["is_tailscale"], v["protected"]) for k, v in sorted(_g61.items())]
check("firewall: a UDP-only allow on tailscale0 (the protocol in the From column) is no tailnet way "
      "in: the public 22/tcp stays protected",
      _g61[("22/tcp", "Any address")]["protected"]
      and not any(v["is_tailscale"] for v in _g61.values()), repr(_tsu61))
_TSIF61 = {"to": "Anywhere on tailscale0", "action": "ALLOW", "direction": "IN"}
check("firewall: the panel host's tailnet-only lockdown is not offered on a UDP-only tailscale0 allow "
      "(ufw_allows_iface_in), and is on a plain one (control)",
      _so61.ufw_allows_iface_in([dict(_TSIF61, **{"from": _CGNAT61 + "/udp"})], "tailscale0") is False
      and _so61.ufw_allows_iface_in([dict(_TSIF61, **{"from": "Anywhere"})], "tailscale0") is True)

_UFW_HEAD61 = "\n".join(["Status: active", "", "To" + " " * 25 + "Action      From",
                         "--" + " " * 25 + "------      ----", ""])


def _panel_open61(*rows):
    with _patched():
        _patch(_smc61, "run_privileged", lambda server, verb, args, timeout=None: (
            _UFW_HEAD61 + "".join(r + "\n" for r in rows), "", 0))
        got = _try61(_smh61.remote_public_ssh_status, NS(port=22), panel_port=5000)
    return got.get("panel_port_open") if isinstance(got, dict) else got


_po61 = {k: _panel_open61(*v) for k, v in (
    ("limit", ("5000/tcp                   LIMIT       Anywhere",)),
    ("allow", ("5000/tcp                   ALLOW       Anywhere",)),
    ("v6 only", ("5000/tcp (v6)              ALLOW       Anywhere (v6)",)),
    ("tailscale comment", ("5000/tcp                   ALLOW       Anywhere    # tailscale fallback",)),
    ("tailscale0 only", ("5000/tcp on tailscale0     ALLOW       Anywhere",
                         "Anywhere on tailscale0     ALLOW       Anywhere")),
    ("deny", ("5000/tcp                   DENY        Anywhere",)),
    ("out", ("5000/tcp                   ALLOW OUT   Anywhere",)),
    ("another port", ("15000/tcp                  ALLOW       Anywhere",)))}
check("network card: a rate-limited (LIMIT) public panel port reads as open (it read closed and the "
      "card called the panel tailnet-only)", _po61["limit"] is True, repr(_po61))
check("network card: ...an IPv6-only allow and one whose comment says tailscale are open too; ALLOW is "
      "open (control); a tailscale0 rule, a DENY, an OUT rule and another port are not",
      (_po61["v6 only"], _po61["tailscale comment"], _po61["allow"], _po61["tailscale0 only"],
       _po61["deny"], _po61["out"], _po61["another port"])
      == (True, True, True, False, False, False, False), repr(_po61))

# ── A05: a numeric id saved in config.json; a hand-edited Infinity; a non-string bind_host ──────
_sent61 = []
with _patched():
    _patch(_nt61, "send_telegram", lambda tok, chat, text: (_sent61.append(("tg", chat)), (True, ""))[1])
    _patch(_nt61, "discord_bot_send", lambda tok, chan, text: (_sent61.append(("dc", chan)), (True, ""))[1])
    _patch(_nt61, "send_ntfy", lambda srv, top, tok, text: (_sent61.append(("nt", top)), (True, ""))[1])
    _tg61 = _try61(_nt61._test_send_telegram, {"telegram": {"chat_id": 123456789}},
                   "123456:" + "A" * 35, None, "t")
    _dc61 = _try61(_nt61._test_send_discord_bot, {"discord": {"channel_id": 112233445566778899}},
                   "x" * 24 + "." + "y" * 6 + "." + "z" * 27, None, "t")
    _ntt61 = _try61(_nt61._test_send_ntfy, {"ntfy": {"topic": 4242}}, None, None, None, "t")
check("notify test: Test with the Chat ID field cleared and a NUMERIC chat_id saved sends to it (a "
      "bare 500: AttributeError on int.strip)",
      _tg61 == (True, "Test message sent — check Telegram.") and ("tg", "123456789") in _sent61,
      repr((_tg61, _sent61)))
check("notify test: ...the same for a numeric Discord channel_id and a numeric ntfy topic",
      isinstance(_dc61, tuple) and _dc61[0] is True and ("dc", "112233445566778899") in _sent61
      and isinstance(_ntt61, tuple) and _ntt61[0] is True and ("nt", "4242") in _sent61,
      repr((_dc61, _ntt61, _sent61)))
_nurl61 = _try61(_nt61._ntfy_url, None, 4242)
check("notify: a numeric ntfy topic builds its URL in the alert path (it raised inside the sender's "
      "catch-all, so every ntfy alert stopped unseen)",
      _nurl61 == _nt61.NTFY_DEFAULT_SERVER.rstrip("/") + "/4242", repr(_nurl61))
with _patched():
    _patch(_hr61, "load_config", lambda: {_hr61._SETTING_WAIT_HOURS: float("inf")})
    _wm61 = _try61(_hr61.wait_max_hours)
check("reboot: a hand-edited `reboot_wait_max_hours: Infinity` reads as the default (OverflowError "
      "out of the Settings page, the wait and startup)", _wm61 == _hr61.DEFAULT_WAIT_HOURS, repr(_wm61))

try:
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), bind_host=5))
    _cur61 = int(_p9_cfg.load_config().get("port", 5000))
    _rb61 = _p9_client(P9_ADMIN).post("/api/panel/change-port",
                                      json={"port": _cur61, "bind_host": ".".join(["0"] * 4)})
    check("change-port: a non-string bind_host in config.json reads as unset (the form answered a bare "
          "500); asked for the binding it already has, it says so",
          _rb61.status_code == 400 and "already the panel's binding" in _p9_json(_rb61).get("message", ""),
          repr((_rb61.status_code, _p9_json(_rb61))))
finally:
    if _CFG61_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG61_SNAPSHOT)
