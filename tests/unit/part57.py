"""Part 57 of the unit suite: review 1011c's core, system_ops, ssh-core and reboot fixes (builder A).

Held here, each against the code path the finding named:

* a non-string text setting hand-edited into config.json (accent_color, login_tagline,
  tailscale_mount, site_domain, bind_host, a socketio_cors_origins entry) reads as unset; it took
  down every page, the console's handshake, or the boot.
* (further sections are added below, one per finding)

HOW IT RUNS. Pages on part12's Flask app and client (part12 has run); every other outside call is a
stand-in (part20's _patch / _patched, undone at the end of each block). Nothing touches the
network, sudo, a real host or the checkout's data/.
"""
import types as _types57

from unit.part01 import check
from unit.part12 import _P9_CFG_PATH, _P9_TRIPPED, _p9, _p9_cfg, _p9_Over, _p9_trip
from unit.part20 import _patch, _patched

import app as _app57  # noqa: E402
from panel.core import config as _cfg57  # noqa: E402
from panel.core import middleware as _mw57  # noqa: E402
from panel.core import origins as _or57  # noqa: E402
from panel.core.validation import _valid_hex_color as _hex57  # noqa: E402
from panel.ops import system_ops as _so57  # noqa: E402
from panel.ops.debug_report import process as _drp57  # noqa: E402
from panel.routes import route_helpers as _rh57  # noqa: E402

NS = _types57.SimpleNamespace
# Addresses built from their parts, so no address literal is added: a tailnet (CGNAT) address and
# the any-address a panel binds.
_TSIP57 = ".".join(["100", "64", "0", "9"])
_ANY57 = ".".join(["0"] * 4)
_CFG57_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _try57(fn, *a, **k):
    """Return fn's answer, or the NAME of the exception it raised.

    So a reverted fix fails its check by name instead of ending the part.
    """
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - which class arrives IS the check
        return type(exc).__name__


# ── A01: a non-string text setting in config.json reads as unset ───────────────────────────────
try:
    _hexes57 = [_try57(_hex57, v) for v in (5, ["#aabbcc"], True)]
    check("config text: accent_color 5 / a list / true is no colour, not an AttributeError on every "
          "render", _hexes57 == ["", "", ""], repr(_hexes57))
    check("config text: ...and a real colour still reads (control)", _hex57("AABBCC") == "#aabbcc")

    _p9_cfg.save_config(dict(_p9_cfg.load_config(), accent_color=5, login_tagline=5))
    # A render reads Tailscale state for the nav (inject_globals), and with a cold cache that ran
    # the real `tailscale` CLI on a box that has it (review 1011e). Answered here, and the CLI
    # tripwired so a call that slips past the answer is counted below.
    from panel.ops import tailscale_integration as _ts57   # noqa: E402
    _trip57_start = len(_P9_TRIPPED)
    with _patched():
        _patch(_ts57, "get_tailscale_info",
               lambda force_refresh=False: _types57.SimpleNamespace(
                   dns_name=None, serve_config={}, serve_unreadable=False))
        _patch(_ts57, "subprocess", _p9_Over(
            _ts57.subprocess,
            Popen=_p9_trip("tailscale.subprocess.Popen", exc=OSError("refused by part57's tripwire")),
            run=_p9_trip("tailscale.subprocess.run", exc=OSError("refused by part57's tripwire"))))
        _r57 = _p9.test_client().get("/login")
    check("config text: /login renders with accent_color 5 and login_tagline 5 hand-edited in (every "
          "page answered 500, with no way back in through the UI)",
          _r57.status_code == 200 and b"Sign in to manage your game servers" in _r57.data,
          repr(_r57.status_code))
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), accent_color="#123abc", login_tagline="  Hi there "))
    with _patched():
        _patch(_ts57, "get_tailscale_info",
               lambda force_refresh=False: _types57.SimpleNamespace(
                   dns_name=None, serve_config={}, serve_unreadable=False))
        _patch(_ts57, "subprocess", _p9_Over(
            _ts57.subprocess,
            Popen=_p9_trip("tailscale.subprocess.Popen", exc=OSError("refused by part57's tripwire")),
            run=_p9_trip("tailscale.subprocess.run", exc=OSError("refused by part57's tripwire"))))
        _r57 = _p9.test_client().get("/login")
    check("config text: ...and real text values still render (control)",
          _r57.status_code == 200 and b"Hi there" in _r57.data and b"#123abc" in _r57.data,
          repr(_r57.status_code))
    check("config text: the /login renders ran no real tailscale CLI",
          len(_P9_TRIPPED) == _trip57_start, repr(_P9_TRIPPED[_trip57_start:][:4]))

    def _mw57_run(mount):
        seen = {}

        def inner(environ, start_response):
            seen["script"] = environ.get("SCRIPT_NAME")
            start_response("200 OK", [])
            return [b""]
        with _patched():
            _patch(_mw57, "load_config", lambda: {"tailscale_mount": mount})
            raised = _try57(_mw57.PrefixMiddleware(inner), {"PATH_INFO": "/lgsm/x", "REQUEST_METHOD": "GET"},
                            lambda *a, **k: None)
        return raised if isinstance(raised, str) else seen.get("script")
    check("config text: tailscale_mount 5 serves the request with no prefix (prefix.rstrip raised on "
          "every request, static files and the Socket.IO handshake included)", _mw57_run(5) == "",
          repr(_mw57_run(5)))
    check("config text: ...and a real mount still prefixes (control)", _mw57_run("/lgsm") == "/lgsm")

    _socket57 = {k: _try57(_app57._explicit_socket_origins, v) for k, v in
                 (("none", [None]), ("zero", [0]), ("mixed", [None, "https://a.example"]))}
    check("config text: socketio_cors_origins [null] / [0] lists no origin (str(None) is 'None', "
          "which made the list truthy and refused every handshake)",
          _socket57 == {"none": [], "zero": [], "mixed": ["https://a.example"]}, repr(_socket57))
    with _patched():
        _patch(_app57, "load_config", lambda: {"socketio_cors_origins": [None], "site_domain": 5})
        _hs57 = _try57(_app57._socket_origin_allowed, "https://panel.example:5000",
                       {"HTTP_HOST": "panel.example:5000"})
    check("config text: the console handshake from the panel's own page is allowed with "
          "socketio_cors_origins [null] and site_domain 5 hand-edited in", _hs57 is True, repr(_hs57))
    _oc57 = _try57(_or57._origin_candidates, {"HTTP_HOST": "h:1"}, {"site_domain": 5})
    check("config text: site_domain 5 is no candidate host (it raised inside engineio's CORS "
          "callback)", _oc57 == ["h:1"], repr(_oc57))

    with _patched():
        _patch(_app57.ts, "suggest_best_bind", lambda port: {"bind_host": _TSIP57})
        _app57._RESOLVED_BIND.pop(59157, None)
        _rb57 = _try57(_app57._resolved_bind, {"bind_host": 5, "port": 59157})
        _app57._RESOLVED_BIND.pop(59157, None)
    check("config text: bind_host 5 resolves as unset at boot (the boot raised: no panel at all)",
          _rb57 == _TSIP57, repr(_rb57))
    with _patched():
        _patch(_rh57, "current_app", NS(config={"_BOOT_BIND": _ANY57}))
        _rp57 = _try57(_rh57._rebind_pending, {"bind_host": 5})
    check("config text: the Tailscale page's rebind test reads bind_host 5 as unset", _rp57 is False,
          repr(_rp57))
    with _patched():
        _patch(_cfg57, "load_config", lambda: {"bind_host": 5})
        _px57 = _try57(_so57._panel_login_proxied)
    check("config text: the fail2ban jail's proxied test reads bind_host 5 as unset", _px57 is False,
          repr(_px57))
    check("config text: the debug report reads bind_host 5 as unset (control: the helper it uses)",
          _drp57._cfg_text({"bind_host": 5}, "bind_host") == "" and _drp57._cfg_text(
              {"bind_host": "::1"}, "bind_host") == "::1")
    # The report's own read, driven (review 1011d): the helper above stays green with
    # _listen_lines reverted to `(cfg.get("bind_host") or "").strip()`, which raises on a 5.
    _ll57 = []
    _res57 = _types57.SimpleNamespace(add=_ll57.append, find=lambda *a, **k: None)
    _ctx57 = _types57.SimpleNamespace(app=_types57.SimpleNamespace(config={"BOOT_PORT": 5000}),
                                      memo=lambda key, fn: [])
    with _patched():
        _patch(_drp57, "_load_cfg", lambda: ({"bind_host": 5, "port": 5000}, True))
        _ll57_err = _try57(_drp57._listen_lines, _ctx57, _res57, {})
    check("config text: the debug report's network section reads bind_host 5 as unset (config auto)",
          _ll57_err is None and any(_l.startswith("- **Bind**: config auto ·") for _l in _ll57),
          repr((_ll57_err, _ll57)))
finally:
    if _CFG57_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG57_SNAPSHOT)

# ── A02: every Serve handler type is another app; a Tailscale Service's listener is not the node's ─
from panel.ops import serve_upkeep as _su57  # noqa: E402
from panel.ops import tailscale_integration as _ts57  # noqa: E402

_LB57 = ".".join(["127", "0", "0", "1"])    # loopback, built so no address literal is added
_P57 = "http://%s:5000" % _LB57
_SHARE57 = ("https://h.tail.ts.net (%s)\n|-- /     path  /srv/share\n|-- /lgsm proxy " + _P57
            + "\n|-- /t    text  \"hello world\"\n")
_svc57 = _ts57._parse_serve_status(_SHARE57 % "tailnet only")
_types57 = [(r["mount"], r.get("type")) for s in _svc57["services"] for r in s["routes"]]
check("serve status: a path (file share) and a text handler are parsed as routes beside the proxy "
      "(only `proxy` lines were kept, so another app's file share was invisible)",
      _types57 == [("/", "path"), ("/lgsm", "proxy"), ("/t", "text")], repr(_types57))
_lf57 = _ts57._r12a_listener_funnel(_svc57, 5000)
check("serve status: the shared :443 listener counts the file share and the text handler as other "
      "apps", _lf57 == (False, ["/", "/t"]), repr(_lf57))
_only57 = _ts57._parse_serve_status("https://h.tail.ts.net (tailnet only)\n|-- / path /srv/share\n")
check("serve status: the wizard does not publish the panel over a file share at / (it replaced it: "
      "the CLI overwrites a mount without asking)",
      _ts57.free_panel_mount(_only57, 5000, "/") == "/lgsm"
      and _ts57.free_panel_mount(_svc57, 5000, "/") == "/lgsm", repr(_only57["services"]))
# Not a guard of its own: a path is absolute and a text is quoted, so route_targets_port reads no
# loopback host in either. Held so a later change to that parse cannot make one the panel's.
check("serve status: a path or text route is never the panel's (control)",
      _ts57.panel_serve_routes(_ts57._parse_serve_status(
          "https://h.tail.ts.net (tailnet only)\n|-- / text \"%s:5000\"\n|-- /x path /%s:5000\n"
          % (_LB57, _LB57)), 5000) == [])
with _patched():
    _patch(_ts57, "get_tailscale_info", lambda force_refresh=False: NS(serve_unreadable=False,
                                                                       serve_config=_svc57))
    _verb57 = _ts57._r12a_serve_verb(5000, "/lgsm", True, False)
check("serve: publishing the panel WITH Funnel beside a tailnet-only file share is refused (it put "
      "the share on the public internet: Funnel is per listener)",
      _verb57[0] is None and "the app at /" in _verb57[1], repr(_verb57))

_TSVC57 = "https://web.tail.ts.net (tailnet only) (svc:web)\n|-- / proxy http://%s:8080\n" % _LB57
_sv57 = _ts57._parse_serve_status(_TSVC57)
check("serve status: a Tailscale Service's listener ((svc:name)) is not read as the node's :443 "
      "listener the panel writes",
      _sv57["services"][0].get("svc") == "svc:web"
      and _ts57._r12a_listener_funnel(_sv57, 5000) == (False, [])
      and _ts57.free_panel_mount(_sv57, 5000, "/") == "/", repr(_sv57["services"]))
_psvc57 = _ts57._parse_serve_status("https://p.tail.ts.net (tailnet only) (svc:p)\n|-- /lgsm proxy %s\n"
                                    % _P57)
check("serve status: a panel route on a Tailscale Service is not 'the panel on the node's :443' (the "
      "boot's keep-Funnel and the shared-Funnel note read it as one)",
      not _ts57._r12a_panel_on_443(_psvc57, 5000, "/lgsm")
      and not _ts57._r13a_panel_on_listener(_psvc57, 5000), repr(_psvc57["services"]))
_both57 = _ts57._parse_serve_status(_TSVC57 + (_SHARE57 % "Funnel on"))
check("serve status: ...and with both, the node's own listener is the one read (control)",
      _ts57._r12a_listener_funnel(_both57, 5000) == (True, ["/", "/t"]), repr(_both57["services"]))

_calls57 = []
with _patched():
    _patch(_ts57, "ensure_operator", lambda: _calls57.append("operator"))
    _patch(_ts57, "allow_tailscale_ufw", lambda: _calls57.append("ufw"))
    _patch(_ts57, "_r12a_serve_verb", lambda *a: (None, "refused. Nothing was changed."))
    _patch(_ts57, "_apply_serve", lambda *a: _calls57.append("apply") or (True, ""))
    _refused57 = _ts57.setup_tailscale_serve(port=5000, mount="/lgsm", funnel=True)
    _refused_calls57 = list(_calls57)
    del _calls57[:]
    _patch(_ts57, "_r12a_serve_verb", lambda *a: ("serve", ""))
    _done57 = _ts57.setup_tailscale_serve(port=5000, mount="/lgsm")
check("serve: a refused write opens no tailscale0 UFW rule (the refusal says 'Nothing was changed', "
      "and every port stayed open to the tailnet)",
      _refused57[0] is False and _refused_calls57 == ["operator"], repr((_refused57, _refused_calls57)))
check("serve: ...while a write that goes ahead still allows tailscale0 first (control)",
      _done57[0] is True and _calls57 == ["operator", "ufw", "apply"], repr((_done57, _calls57)))

_aud57 = []
with _patched():
    _patch(_ts57, "get_tailscale_info", lambda force_refresh=False: NS(
        serve_unreadable=False, serve_config=_ts57._parse_serve_status(_SHARE57 % "tailnet only")))
    _su57._boot_shared_funnel(NS(), {"tailscale_use_funnel": True}, 5000,
                              lambda app, detail, ok, action="": _aud57.append(detail))
    _su57._boot_shared_funnel(NS(), {"tailscale_use_funnel": False}, 5000,
                              lambda app, detail, ok, action="": _aud57.append(detail))
check("boot: the panel kept tailnet-only against its own Funnel setting, by a shared listener, is "
      "put on record (only the opposite case was), and nothing when the setting is off",
      len(_aud57) == 1 and "tailnet-only, although its own Funnel setting is on" in _aud57[0]
      and "the app at /" in _aud57[0], repr(_aud57))

# ── A02: a quoted secret is redacted whole, escaped quotes and over-long values included ─────────
_red57 = {k: _so57._redact(v) for k, v in (
    ("escaped", '{"password": "ab\\"c de fg"} tail'),
    ("long", "token: \"" + "a b " * 400 + "\" end"),
    ("single", "token='a\\'b c' ok"),
    ("plain", "password=hunter2 next"),
    ("two", '{"password": "correct horse", "user": "bob"}'))}
check("redact: a quoted value with an escaped quote is redacted whole (`c de fg\"` was printed)",
      _red57["escaped"] == '{"password": [redacted]} tail', repr(_red57["escaped"]))
check("redact: a quoted value past the bound is redacted to the end of the line (the `\\S+` fallback "
      "printed everything after its first blank)",
      _red57["long"] == "token: [redacted]", repr(_red57["long"][:80]))
check("redact: ...the same for a single-quoted value with an escaped quote, and a plain or a short "
      "quoted value is redacted exactly as before (control)",
      (_red57["single"], _red57["plain"], _red57["two"])
      == ("token=[redacted] ok", "password=[redacted] next", '{"password": [redacted], "user": "bob"}'),
      repr(_red57))

# ── A03: a rule admitting every port reaches sshd; a UDP rule does not; the tailnet needs sshd ───
from unit.part02 import protect as _protect57  # noqa: E402

_ADMIN57 = ".".join(["198", "51", "100", "7"])    # documentation addresses (TEST-NET-2/3)
_DEST57 = ".".join(["203", "0", "113", "57"])


def _fw57(rules, **kw):
    """{To column: group} of `rules` on a remote whose sshd serves 22."""
    return {x["port_label"]: x for x in _protect57(NS(port=22), rules, sshd_ports=(22,), **kw)}


_every57 = {}
for _rule57, _key57 in (("Anywhere ALLOW IN %s" % _ADMIN57, "Anywhere"),
                        ("Anywhere on eth0 ALLOW IN Anywhere", "All ports"),
                        ("%s ALLOW IN Anywhere" % _DEST57, _DEST57)):
    _g57 = _fw57([_rule57, "28960 ALLOW IN Anywhere"])[_key57]
    _every57[_key57] = (_g57["is_ssh"], _g57["protected"], "every port" in _g57["protect_reason"])
check("firewall: the host's only way in written as an all-ports rule (`ufw allow from <admin ip>`, "
      "`ufw allow in on eth0`, `ufw allow to <addr>`) is protected, not an ordinary delete",
      set(_every57.values()) == {(True, True, True)}, repr(_every57))
_g57 = _fw57(["Apache ALLOW IN Anywhere", "Anywhere DENY IN %s" % _ADMIN57, "22/tcp ALLOW IN Anywhere"])
check("firewall: ...while an app profile that is not SSH, and a DENY from an address, are not SSH "
      "rules, and 22/tcp is still the only way in (control)",
      not _g57["Apache"]["is_ssh"] and not _g57["Anywhere"]["is_ssh"] and _g57["22/tcp"]["protected"],
      repr({k: (v["is_ssh"], v["protected"]) for k, v in _g57.items()}))

_udp57 = {}
for _u57 in ("1:1024/udp", "22/udp", "10,22,53/udp"):
    _g57 = _fw57(["22/tcp ALLOW IN Anywhere", _u57 + " ALLOW IN Anywhere"])
    _udp57[_u57] = (_g57[_u57]["is_ssh"], _g57["22/tcp"]["protected"], _g57["22/tcp"]["warn"])
check("firewall: a UDP rule naming sshd's port is not a second way in, so the only `22/tcp` stays "
      "protected (it read 'Another way in exists')",
      set(_udp57.values()) == {(False, True, False)}, repr(_udp57))
_g57 = _fw57(["22/tcp ALLOW IN Anywhere", "22 ALLOW IN %s" % _ADMIN57])
check("firewall: ...while a both-protocols rule on 22 is still a second way in (control)",
      _g57["22/tcp"]["warn"] and not _g57["22/tcp"]["protected"], repr(_g57["22/tcp"]))

_TSR57 = ["22/tcp ALLOW IN Anywhere", "Anywhere on tailscale0 ALLOW IN Anywhere"]
_tsn57 = {k: _fw57(_TSR57, tailscale=(True, False), **kw)["22/tcp"]
          for k, kw in (("ok", {}), ("off", {"sshd_off_tailnet": True}), ("noiface", {"tsifaces": ()}))}
check("firewall: with sshd listening off the tailnet (the panel's own bind change), or no Tailscale "
      "interface (userspace networking), the tailscale0 rule is no way in: the only public SSH rule "
      "is protected",
      _tsn57["off"]["protected"] and _tsn57["noiface"]["protected"],
      repr({k: (v["protected"], v["warn"]) for k, v in _tsn57.items()}))
check("firewall: ...and with both it is still another way in, so the rule only warns (control)",
      _tsn57["ok"]["warn"] and not _tsn57["ok"]["protected"], repr(_tsn57["ok"]))

# ── A05: the bare-reboot text never calls an owner-"none" server one "to start again" ───────────
from panel.services import reboot_summary as _rs57  # noqa: E402

_bt57 = _rs57._bare_rebooted_text(NS(id=9157, display_name="p57-host"), {"servers": [
    {"name": "a", "owner": "panel", "stop": "still_running"},
    {"name": "b", "owner": "none", "stop": "stopped"}], "sent": None}, None)
check("reboot: a bare job whose plan held an owner-none server does not say it was 'to start again'",
      "to start again" not in _bt57 and "the 2 game servers in its plan (it stopped 1 of them)" in _bt57,
      _bt57)

# ── A05 lead: telegram_get_updates never raises on a reply that is not an object ───────────────
from panel.services import notifications as _nt57  # noqa: E402


class _Resp57:
    def __init__(self, body):
        self.body = body

    def read(self, n=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_tg57 = {}
with _patched():
    _patch(_nt57, "_tg_api_url", lambda token, method: "https://api.telegram.org/bot/x")
    for _k57, _body57 in (("list", b"[1, 2]"), ("num", b"5"), ("dictres", b'{"ok": true, "result": {"a": 1}}'),
                          ("ok", b'{"ok": true, "result": [{"update_id": 3}]}')):
        _patch(_nt57, "_OPENER", NS(open=lambda req, timeout=None, b=_body57: _Resp57(b)))
        _tg57[_k57] = _try57(_nt57.telegram_get_updates, "t", offset=1, timeout=0)
check("telegram: a getUpdates reply that is a list or a number answers None (it raised "
      "AttributeError, against 'never raises'), and a non-list result is no updates",
      _tg57["list"] is None and _tg57["num"] is None and _tg57["dictres"] == [], repr(_tg57))
check("telegram: ...and an ordinary reply still returns its updates (control)",
      _tg57["ok"] == [{"update_id": 3}], repr(_tg57["ok"]))

# ── A01 class: a chat / channel id hand-edited in as a JSON number is read as its text ───────────
from panel.services.bots import discord as _dc57  # noqa: E402
from panel.services.bots import telegram as _tgb57  # noqa: E402

_NOTOK57 = str()    # no bot token: these read the ids, and nothing is sent
_ids57 = {}
with _patched():
    _patch(_nt57, "_cfg", lambda: {"telegram": {"enabled": True, "accept_commands": True, "token": _NOTOK57,
                                                "chat_id": 12345}})
    _ids57["tg_settings"] = _try57(_tgb57._tg_settings)
_ids57["tg_gate"] = _try57(_tgb57._tg_chat_still_authorised,
                           {"enabled": True, "accept_commands": True, "chat_id": 12345}, 12345)
_ids57["dc_gate"] = _try57(_dc57._dc_gate_channel, {"enabled": True, "accept_commands": True,
                                                    "channel_id": 987}, "987", "!status")
_ids57["dc_still"] = _try57(_dc57._dc_channel_still_authorised,
                            {"enabled": True, "accept_commands": True, "channel_id": 987}, "987")
_sent57 = []
with _patched():
    _patch(_nt57, "send_telegram", lambda token, chat, text: _sent57.append(chat) or (True, ""))
    _tgs57 = _nt57._channel_senders({"enabled": True, "token": _NOTOK57, "chat_id": 12345}, {}, {}, "hi")[0]
    _ids57["tg_send"] = _try57(_tgs57[2])
check("bots: a numeric chat_id / channel_id (Telegram and Discord ids are numbers) is read as its "
      "text, not an AttributeError that stopped the command watch and every alert to that chat",
      _ids57 == {"tg_settings": ("", "12345", "unconfigured"), "tg_gate": True, "dc_gate": "987",
                 "dc_still": True, "tg_send": (True, "")} and _sent57 == ["12345"], repr((_ids57, _sent57)))
