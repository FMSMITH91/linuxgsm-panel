"""Part 307 of the unit suite: SFTP on one specific address, and CI's artifact retention and job order.

1. SFTP "A specific address" (services/sftp_common, sftp_broker, routes/sftp_settings, ops/system_ops):
   the card lists the panel host's own addresses read with `ip -o addr` in the C locale, marks a public
   one and warns beside it; saving stores the address, refuses one the host does not have, and keeps a
   saved one the host lost; the service binds that address alone; an address that is gone stops the
   service (the running one within a check interval), says why on the card and in the audit log once,
   and never falls back to other addresses; it starts again when the address is back; the fail2ban
   jail bans on the SFTP port for a public address and not for a private one.
2. CI: every actions/upload-artifact step in every workflow and local action keeps its artifact for an
   explicit number of days: 7 for a run's own reports, 30 for a fuzz crash reproducer.
3. CI: the js coverage parts are queued behind the short gamedig lockfile legs, so the unit shards (the
   longest required jobs) are queued first at the 20-job cap; they still run when a leg fails.

HOW IT RUNS. Routes on part12's app with the host's address list stood in (the broker's own reader is
driven once through a stand-in `ip`); the running service's watcher is driven through run_once with a
stand-in child process; the workflows are read as text.
"""
import os
import re as _re307
import sys as _sys307
import threading as _th307
import time as _time307

from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _P9_PATCHED, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from panel.core import config as _cfg307
from panel.db.models import AuditLog as _AL307
from panel.ops import system_ops as _so307
from panel.ops.ssh_manager import ufweval as _uf307
from panel.services import sftp_broker as _br307, sftp_common as _sc307

_ROOT307 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_CFG_SNAP307 = _cfg307.CONFIG_FILE.read_bytes() if _cfg307.CONFIG_FILE.exists() else None
# Documentation and private ranges only (RFC 5737 TEST-NET, RFC 3849, RFC 1918, Tailscale's CGNAT range).
_PUB307, _LAN307, _V6_307, _TSA307 = "9.9.9.9", "192.168.1.20", "2620:fe::fe", "100.101.102.103"
_ELSEWHERE307 = "149.112.112.112"
_IP_OUT307 = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
    "1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever\n"
    "2: eth0    inet 9.9.9.9/24 scope global secondary eth0\\       valid_lft forever\n"
    "2: eth0    inet6 2620:fe::fe/64 scope global \\       valid_lft forever preferred_lft forever\n"
    "2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever\n"
    "3: tailscale0    inet 100.101.102.103/32 scope global tailscale0\\       valid_lft forever\n")
_ROWS307 = {"rows": _uf307.parse_ip_addr(_IP_OUT307)}
_ALL_ROWS307 = _ROWS307["rows"]


def _put307(**changes):
    _cfg307.update_config(lambda c: c.update(changes))


def _rows_without307(*gone):
    return [r for r in _ALL_ROWS307 if str(r[1]) not in gone]


def _audits307(action):
    with _p9.app_context():
        return [r.detail or "" for r in _AL307.query.filter_by(action=action).order_by(_AL307.id).all()]


def _settings307():
    return _sc307.settings(_cfg307.load_config())


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. SFTP on one specific address
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The broker's own reader, as it was before part12's tripwire answered it (every render of Settings reads it).
_REAL_ROWS307 = _P9_PATCHED.get((_br307, "host_address_rows"), _br307.host_address_rows)
_TRIP307 = len(_P9_TRIPPED)
_p9_arm()
_restarts307 = []
_p9_patch(_br307, "restart", lambda: _restarts307.append(1))
_p9_patch(_br307, "f2b_follow", lambda app: None)
_p9_patch(_br307, "tailscale_ips", lambda: [])
_p9_patch(_br307, "host_address_rows", lambda: _ROWS307["rows"])
_A307 = _p9_client(P9_ADMIN)

# The broker's own reader: `ip -o addr show` in the C locale (a translated listing is never parsed).
_ran307 = []


def _fake_run307(cmd, *_a, **_k):
    _ran307.append(cmd)
    return _IP_OUT307, "", 0


_p9_patch(_so307, "_run", _fake_run307)
_read307 = _REAL_ROWS307()
check("sftp address: the host's addresses are read with `ip -o addr show` in the C locale",
      len(_ran307) == 1 and "LC_ALL=C" in _ran307[0] and "ip -o addr show" in _ran307[0] and _read307 == _ALL_ROWS307,
      repr(_ran307))
_offer307 = _sc307.host_addresses(_read307)
eq("sftp address: the list is the host's own addresses (IPv4 first), never loopback or IPv6 link-local, each once",
   [a["addr"] for a in _offer307], [_LAN307, _PUB307, _TSA307, _V6_307])
eq("sftp address: public is any address not private, CGNAT (Tailscale's too), loopback, link-local or ULA",
   [a["public"] for a in _offer307] + [_sc307.is_public(x) for x in ("10.1.2.3", "172.20.0.1", "fd00::1",
                                                                       "fd7a:115c:a1e0::1", "169.254.1.1", "::1",
                                                                       _ELSEWHERE307, "bogus")],
   [False, True, False, True] + [False] * 5 + [False, True, False])
eq("sftp address: documentation, CGNAT, unique-local and reserved addresses are not public; real public ones are",
   [_sc307.is_public(x) for x in ("203.0.113.5", "198.51.100.7", "2001:db8::5", "100.64.0.1", "fc00::1", "240.0.0.1",
                                  "9.9.9.9", "2620:fe::fe")],
   [False] * 6 + [True, True])
eq("sftp address: the stored address is never an every-address form, multicast, IPv6 link-local or junk",
   [_sc307.address_or(x) for x in ("0.0.0.0", "::", "224.0.0.1", "fe80::1", "x", "", None, " 9.9.9.9 ",
                                   "2620:FE::FE")],  # nosec B104 - refused here, never bound
   [""] * 7 + [_PUB307, _V6_307])
eq("sftp address: the choice binds that address alone, and nothing at all without one (never 0.0.0.0 or ::)",
   [_sc307.bind_addresses("address", [_TSA307], True, a) for a in (_PUB307, "", "0.0.0.0", "::")],  # nosec B104
   [[_PUB307], [], [], []])
eq("sftp address: (control) the other choices bind as before", [_sc307.bind_addresses(c, [_TSA307], True)
                                                                 for c in ("tailscale", "loopback", "all")],
   [[_TSA307], ["127.0.0.1"], ["0.0.0.0", "::"]])  # nosec B104 - compared, never bound here


def _save307(**form):
    base = {"sftp_enabled": "on", "sftp_bind": "loopback", "sftp_port": "2222", "sftp_max_upload_mb": "4096",
            "sftp_idle_minutes": "15", "sftp_absolute_hours": "8"}
    base.update(form)
    return _A307.post("/settings/sftp", data={k: v for k, v in base.items() if v is not None})


def _flashed307():
    with _A307.session_transaction() as s:
        msgs = [m for _c, m in s.get("_flashes", [])]
        s.pop("_flashes", None)
    return msgs


def _option307(html, addr):
    m = _re307.search(r'<option value="%s"[^>]*>([^<]*)</option>' % _re307.escape(addr), html)
    return " ".join(m.group(1).split()) if m else None


_save307(sftp_enabled=None)
_flashed307()
_html307 = _A307.get("/settings").get_data(as_text=True)
check("sftp card: a 4th choice, A specific address, lists every address with its interface",
      'id="sftp-bind-addr"' in _html307 and 'value="address"' in _html307
      and all(_option307(_html307, a) is not None for a in (_LAN307, _PUB307, _TSA307, _V6_307))
      and _option307(_html307, _LAN307).startswith("192.168.1.20 (eth0)"), _option307(_html307, _LAN307))
eq("sftp card: the public address is marked public beside it, a private one is not",
   ["public: reachable from the internet" in (_option307(_html307, a) or "") for a in (_PUB307, _LAN307, _TSA307)],
   [True, False, False])

_n307 = len(_restarts307)
_r307 = _save307(sftp_bind="address", sftp_bind_address=_PUB307)
_f307 = _flashed307()
eq("sftp card: saving a public address stores that address, restarts the service, and warns plainly",
   (_r307.status_code, _settings307()["bind"], _settings307()["address"], len(_restarts307) - _n307,
    any("Public address:" in m and "OWASP" in m for m in _f307)),
   (302, "address", _PUB307, 1, True))
_html307 = _A307.get("/settings").get_data(as_text=True)
check("sftp card: ...and the card shows it chosen, with the public warning beside the field",
      _re307.search(r'<option value="9\.9\.9\.9" selected>', _html307) is not None
      and 'id="sftp-public-warning"' in _html307 and "reachable from the internet" in _html307, _html307[:0])
with _p9.app_context():
    _row307 = _AL307.query.filter_by(action="settings_update").order_by(_AL307.id.desc()).first()
check("sftp card: the save's audit row names the address", _row307 is not None
      and "SFTP specific address (none) -> 9.9.9.9" in (_row307.detail or ""), getattr(_row307, "detail", None))

_save307(sftp_bind="address", sftp_bind_address=_LAN307)
_f307 = _flashed307()
eq("sftp card: a private address saves with no public warning, on the card or flashed",
   (_settings307()["address"], any("public address" in m for m in _f307),
    'id="sftp-public-warning"' in _A307.get("/settings").get_data(as_text=True)), (_LAN307, False, False))
_save307(sftp_bind="address", sftp_bind_address=_ELSEWHERE307)
_f_else307 = _flashed307()
_save307(sftp_bind="address", sftp_bind_address=None)
_f_none307 = _flashed307()
_save307(sftp_bind="address", sftp_bind_address="0.0.0.0")  # nosec B104 - refused, never bound
_f_wild307 = _flashed307()
eq("sftp card: an address the host does not have, none, or 0.0.0.0 is refused and nothing changes",
   (_settings307()["address"], ["Choose one of this host's addresses" in " ".join(f)
                                for f in (_f_else307, _f_none307, _f_wild307)]), (_LAN307, [True] * 3))

_ROWS307["rows"] = _rows_without307(_LAN307)
_save307(sftp_bind="address", sftp_bind_address=_LAN307, sftp_port="2233")
_f_kept307 = _flashed307()
eq("sftp card: a saved address the host lost is kept, so other changes still save (the service waits)",
   (_settings307()["address"], _settings307()["port"], any("Choose one" in m for m in _f_kept307)),
   (_LAN307, 2233, False))
_html307 = _A307.get("/settings").get_data(as_text=True)
check("sftp card: ...and the list still shows it, marked as not on this host now",
      "not on this host now" in (_option307(_html307, _LAN307) or ""), _option307(_html307, _LAN307))
_ROWS307["rows"] = None
_html307 = _A307.get("/settings").get_data(as_text=True)
check("sftp card: an address list that cannot be read says so, and the saved address is offered but not called gone",
      "This host's addresses could not be read." in _html307 and _option307(_html307, _LAN307) == _LAN307
      and _re307.search(r'id="sftp-bind-addr" value="address"\s+checked\s*>', _html307) is not None,
      repr(_option307(_html307, _LAN307)))
_ROWS307["rows"] = _rows_without307(_LAN307)
_save307(sftp_bind="loopback")
_save307(sftp_bind="address", sftp_bind_address=_LAN307)
_f_new307 = _flashed307()
eq("sftp card: ...but it is refused as a NEW choice for a service that is on",
   (_settings307()["bind"], any("Choose one of this host's addresses" in m for m in _f_new307)), ("loopback", True))
_save307(sftp_enabled=None, sftp_bind="address", sftp_bind_address=_LAN307)
eq("sftp card: ...and saved with the service off", (_settings307()["bind"], _settings307()["address"]),
   ("address", _LAN307))
_ROWS307["rows"] = _ALL_ROWS307
_save307(sftp_bind="loopback")
eq("sftp card: (control) the other choices still save, and the address is not in force for them",
   (_settings307()["bind"], _settings307()["address"]), ("loopback", ""))

# The service: spawn_config binds that address alone, waits when it is gone, and audits each change once.
_put307(sftp_enabled=True, sftp_bind="address", sftp_bind_address=_PUB307)
_br307._STATE.pop("address_gone", None)
_gone0_307, _back0_307 = len(_audits307("sftp_address_gone")), len(_audits307("sftp_address_back"))
_sp307, _why307 = _br307.spawn_config(_p9)
eq("sftp service: the chosen address is the only one listened on",
   ((_sp307 or {}).get("binds"), (_sp307 or {}).get("choice"), _why307), ([_PUB307], "address", None))
_ROWS307["rows"] = _rows_without307(_PUB307)
_waits307 = [_br307.spawn_config(_p9) for _i in range(3)]
_detail307 = _br307._STATE.pop("wait_detail", None)
eq("sftp service: the address gone, it waits (binding nothing) and says why, the address as the detail",
   (_waits307[0], _detail307), ((None, _br307.ADDRESS_GONE), _PUB307))
_gone307 = _audits307("sftp_address_gone")[_gone0_307:]
check("sftp service: ...audited once in plain words, however often it is asked again",
      len(_gone307) == 1 and _PUB307 in _gone307[0] and "listens nowhere else" in _gone307[0]
      and all(w == (None, _br307.ADDRESS_GONE) for w in _waits307), repr((_gone307, _waits307)))
_ROWS307["rows"] = None
eq("sftp service: an address list that cannot be read waits too, and is not counted as gone",
   (_br307.spawn_config(_p9), len(_audits307("sftp_address_gone")) - _gone0_307), ((None, _br307.ADDRESS_UNREAD), 1))
_ROWS307["rows"] = _ALL_ROWS307
_sp_back307, _ = _br307.spawn_config(_p9)
_back307 = _audits307("sftp_address_back")[_back0_307:]
check("sftp service: the address back, it listens on it again and the audit log says so once",
      (_sp_back307 or {}).get("binds") == [_PUB307] and len(_back307) == 1 and _PUB307 in _back307[0]
      and _br307.spawn_config(_p9)[0] is not None and len(_audits307("sftp_address_back")) - _back0_307 == 1,
      repr((_sp_back307 and _sp_back307.get("binds"), _back307)))

# The running service: its watcher stops it once the address leaves the host, and not before.
_p9_patch(_br307, "ADDRESS_CHECK_SECONDS", 0.1)
_runs307 = []
_child307 = [_sys307.executable, "-c", "import sys; sys.stdin.read()"]
_t307 = _th307.Thread(target=lambda: _runs307.append(_br307.run_once(_p9, dict(_sp_back307), _child307)),
                      name="p307-run-once", daemon=True)
_t307.start()
_time307.sleep(0.6)
_alive_with307 = _t307.is_alive() and _br307._STATE.get("proc") is not None
_ROWS307["rows"] = _rows_without307(_PUB307)


def _wait_ended307(thread, seconds):
    """Wait up to `seconds` for `thread` to end. Not join(timeout): eventlet's raises its Timeout instead."""
    deadline = _time307.monotonic() + seconds
    while thread.is_alive() and _time307.monotonic() < deadline:
        _time307.sleep(0.1)


_wait_ended307(_t307, 15)
_st307, _left307, _proc_left307 = _br307.status(), _t307.is_alive(), _br307._STATE.get("proc")
if _left307:    # nothing stopped it: end the stand-in service here, so the suite goes on to say so
    _br307._stop_child()
    _wait_ended307(_t307, 15)
check("sftp service: running on the address, it is left running while the host has it",
      _alive_with307, repr(_br307.status()))
eq("sftp service: ...and stopped once the host loses it, the card's state saying why with the address",
   (_left307, _st307["state"], _st307["error"], _st307["detail"], _proc_left307),
   (False, "waiting", _br307.ADDRESS_GONE, _PUB307, None))
_html307 = _A307.get("/settings").get_data(as_text=True)
check("sftp card: the waiting state reads the plain reason and the address on the Settings page",
      "Waiting" in _html307 and "never listens on another address instead" in _html307
      and "<code" in _html307 and _PUB307 in _html307.split('id="sftp-state"', 1)[-1][:1200], _html307[:0])
_ROWS307["rows"] = _ALL_ROWS307
_br307._STATE.pop("address_gone", None)
_br307._set_status("off")

# The fail2ban jail bans on the SFTP port for a public address, as for every address, and not for a private one.
_put307(sftp_enabled=True, sftp_bind="address", sftp_bind_address=_PUB307, sftp_port=2207)
_j_pub307 = _so307._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
_put307(sftp_bind_address=_LAN307)
_j_lan307 = _so307._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
_put307(sftp_bind="all")
_j_all307 = _so307._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
_put307(sftp_bind="address", sftp_bind_address=_PUB307, sftp_enabled=False)
_j_off307 = _so307._panel_f2b_jail_body("/x/auth.log", 5000, [], False)
eq("sftp fail2ban: the jail bans on the SFTP port for a public address and every address, not a private one or off",
   ["port = 5000,2207\n" in _j_pub307, "port = 5000\n" in _j_lan307, "port = 5000,2207\n" in _j_all307,
    "port = 5000\n" in _j_off307], [True] * 4)

eq("part307: no check reached a real transport", _P9_TRIPPED[_TRIP307:], [])

# ── put everything back ──
_p9_restore_all()
_br307._STATE.pop("address_gone", None)
_br307._STATE.pop("wait_detail", None)
_br307._set_status("off")
if _CFG_SNAP307 is None:
    _cfg307.CONFIG_FILE.unlink(missing_ok=True)
else:
    _cfg307.CONFIG_FILE.write_bytes(_CFG_SNAP307)
_cfg307._cfg_cache["key"] = None


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. CI: every uploaded artifact has an explicit retention
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _step_body307(lines, col):
    """The lines of one step after its `uses:` line (at column `col`): up to the next step or a shallower line."""
    body = []
    for nxt in lines:
        indent = len(nxt) - len(nxt.lstrip(" "))
        if nxt.strip() and (indent < col or (nxt.lstrip().startswith("- ") and indent <= col)):
            break
        body.append(nxt)
    return body


def _key307(body, key):
    """The value of `key:` in a step's lines (its comment cut), or None."""
    return next((b.split(":", 1)[1].split("#")[0].strip() for b in body if b.strip().startswith(key + ":")), None)


def _upload_steps307(text):
    """[(artifact name, retention-days text or None)] for each actions/upload-artifact step in `text`."""
    lines, out = text.splitlines(), []
    for i, ln in enumerate(lines):
        m = _re307.match(r"^(\s*)(- )?uses: actions/upload-artifact@", ln)
        if m:
            body = _step_body307(lines[i + 1:], len(m.group(1)) + len(m.group(2) or ""))
            out.append((_key307(body, "name") or "?", _key307(body, "retention-days")))
    return out


_CTL_WF307 = ("    steps:\n      - name: a\n        uses: actions/upload-artifact@" + "a" * 40 + " # v7\n"
              "        with:\n          name: kept\n          # why\n          retention-days: 7\n"
              "      - uses: actions/upload-artifact@" + "b" * 40 + " # v7\n        with:\n          name: forever\n"
              "          path: x\n      - name: next step\n        retention-days: 3\n")
eq("ci artifacts: (control) the reader finds each upload step and its own retention, not the next step's",
   _upload_steps307(_CTL_WF307), [("kept", "7"), ("forever", None)])
_uploads307 = {}
for _dir307 in (os.path.join(_ROOT307, ".github", "workflows"), os.path.join(_ROOT307, ".github", "actions")):
    for _base307, _dirs307, _files307 in os.walk(_dir307):
        for _fn307 in sorted(_files307):
            if _fn307.endswith((".yml", ".yaml")):
                with open(os.path.join(_base307, _fn307), encoding="utf-8") as _fh307:
                    _found307 = _upload_steps307(_fh307.read())
                if _found307:
                    _uploads307[os.path.relpath(os.path.join(_base307, _fn307), _ROOT307)] = _found307
_bad307 = {f: [s for s in steps if s[1] not in ("7", "30") or (s[1] == "30") != s[0].startswith("fuzz-crash-")]
           for f, steps in _uploads307.items()}
check("ci artifacts: every upload-artifact step keeps its artifact 7 days (a run's report) or 30 (a fuzz crash), "
      "never GitHub's 90-day default",
      sum(len(s) for s in _uploads307.values()) >= 7 and not any(_bad307.values()), repr(_uploads307))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. CI: the unit shards are queued ahead of the js coverage parts
# ════════════════════════════════════════════════════════════════════════════════════════════════
with open(os.path.join(_ROOT307, ".github", "workflows", "ci.yml"), encoding="utf-8") as _fh307:
    _ci307 = _fh307.read()


def _job307(job):
    m = _re307.search(r"^  %s:[ \t]*$" % _re307.escape(job), _ci307, _re307.M)
    if m is None:
        return ""
    nxt = _re307.search(r"^  [A-Za-z_]", _ci307[m.end():], _re307.M)
    return _ci307[m.start():m.end() + nxt.start()] if nxt else _ci307[m.start():]


_js307 = _job307("js-coverage")
check("ci order: the js coverage parts wait for the gamedig lockfile legs, and run whatever those did",
      "\n    needs: gamedig-lockfile\n" in _js307 and "\n    if: ${{ !cancelled() }}\n" in _js307, _js307[:400])
eq("ci order: the unit shards, coverage and the gamedig legs need nothing, so they are queued at once",
   ["\n    needs:" in _job307(j) for j in ("checks", "coverage", "gamedig-lockfile")], [False] * 3)
