"""Part 2 of the smoke suite. Imported for its side effects: see tests/smoke_test.py.

Two markers here are about the split, not the checks. `# pylint: disable=reimported`: each section
imports what it uses under an alias of its own, as it did in the single-file suite, whose one try
hid those imports from Pylint's reimport rule. `# noqa: MC0001` (mccabe): a block whose branches
mccabe counted, until the split, as part of that one try, already reported as too complex.
"""
from smoke.part01 import (_lgsm_tempfile, _sm_core, _sm_hosts, _smoke_banlist, _smoke_ms,
                          _smoke_priv_real, _SUITE_FILE, app, auth, bk, check, client_as, db,
                          GameServer, Group, load_config, os, RemoteServer, save_config,
                          SetupState, sys, User)

# ── Fixtures: a superadmin, one remote host, one game server on it ──
with app.app_context():
    db.session.add(SetupState(step="complete", complete=True))
    admin = User(username="smoke_admin",
                 password_hash=auth.hash_password("Str0ng!passw0rd"),
                 display_name="Smoke Admin", is_superadmin=True, is_active=True)
    db.session.add(admin)
    remote = RemoteServer(name="smoke-host", host="127.0.0.1", port=22,
                          username="root", auth_method="key", auth_credential="")
    remote2 = RemoteServer(name="smoke-host-2", host="127.0.0.1", port=22,
                           username="root", auth_method="key", auth_credential="")
    db.session.add_all([remote, remote2])
    db.session.flush()
    gs = GameServer(remote_id=remote.id, name="smoke-cs", short_name="csgoserver",
                    game_type="csgo", port=27015, installed=True, status="offline")
    db.session.add(gs)
    # A non-superadmin with MANAGE_REMOTES but access to remote #1 ONLY, to prove
    # remote management is scoped per host (not global with the permission).
    mrg = Group(name="smoke_mr", description="", is_default=False)
    mrg.set_permissions([auth.MANAGE_REMOTES])
    mrg.servers.append(remote)
    db.session.add(mrg)
    db.session.flush()
    mru = User(username="smoke_mr", password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name="MR", is_superadmin=False, is_active=True)
    mru.groups.append(mrg)
    db.session.add(mru)
    # A 2FA-enabled user with known backup codes, to exercise backup-code login.
    from panel.core.config import encrypt_secret
    tfa = User(username="smoke_2fa", password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name="2FA", is_superadmin=True, is_active=True, totp_enabled=True,
               totp_secret=encrypt_secret(auth.generate_totp_secret()))
    bc_codes = auth.generate_backup_codes()
    tfa.set_backup_codes(bc_codes)
    db.session.add(tfa)
    # A delegated admin: MANAGE_USERS + MANAGE_GROUPS but NOT superadmin — used to prove
    # they can't escalate to superadmin via user/group management.
    dg = Group(name="smoke_deleg", description="", is_default=False)
    dg.set_permissions([auth.MANAGE_USERS, auth.MANAGE_GROUPS])
    db.session.add(dg)
    db.session.flush()
    deleg = User(username="smoke_deleg", password_hash=auth.hash_password("Str0ng!passw0rd"),
                 display_name="Deleg", is_superadmin=False, is_active=True)
    deleg.groups.append(dg)
    db.session.add(deleg)
    db.session.commit()
    admin_id, remote_id = admin.id, remote.id
    remote2_id, mru_id = remote2.id, mru.id
    gs_id = gs.id
    bc_code = bc_codes[0]
    deleg_id, admin2_id = deleg.id, tfa.id

c = client_as(admin_id)

# ── Every main page must RENDER (200) — not 500, and not a silent redirect
#    to /setup or /login (which would mean the check isn't really exercising
#    the page). We skip pages that shell out to host-only tooling
#    (/server-management runs ufw/systemctl), so the test stays portable.
for path in ["/", "/users", "/groups", "/logs", "/remotes", "/tailscale", "/account",
             "/notifications", "/settings"]:
    code = c.get(path).status_code
    check("GET %s renders (200)" % path, code == 200, "got %d" % code)

# ── /tailscale's Disable takes down the PANEL's Serve mapping, not the first one listed ──
# The button sent services[0].routes[0].mount, and Tailscale lists "/" first — on a node where
# another app holds "/" and the panel sits at /lgsm, that was the other app. And the removal
# ran `tailscale serve --bg --remove`, which no Tailscale accepts (--remove was the 1.34-1.36
# alpha CLI's, which had no --bg), so it never worked.
import panel.ops.tailscale_integration as _tsd
from panel.core.config import load_config as _tsd_load, save_config as _tsd_save
_tsd_saved = (_tsd.get_tailscale_info, _tsd._run_ts, _tsd.ensure_operator)
_tsd_cfg0 = dict(_tsd_load())
_tsd_port = _tsd_cfg0.get("port", 5000)
_tsd_ran = []
_tsd_info = _tsd.TailscaleInfo(
    installed=True, running=True, backend_state="Running", dns_name="node.example.ts.net",
    tailscale_ips=["100.64.0.9"],
    serve_config={"services": [{"url": "https://node.example.ts.net", "funnel": True, "routes": [
        {"mount": "/", "target": "http://127.0.0.1:3000"},
        {"mount": "/lgsm", "target": "http://127.0.0.1:%d" % _tsd_port}]}], "raw": "x"})
try:
    _tsd.get_tailscale_info = lambda force_refresh=False: _tsd_info
    _tsd._run_ts = lambda args, timeout=5: (_tsd_ran.append(list(args)), ("", "", 0))[1]
    _tsd.ensure_operator = lambda: (True, "panel")
    _tsd_c = _tsd_load()
    # No stored mount: the button's mount has to come from the host's routes, which only the
    # route supplies — a stored "/lgsm" would let a route that passed nothing pass this too.
    # bind_host 0.0.0.0: the panel is reachable without Serve, so disabling it strands nothing
    # (the loopback case, where it does, is refused below).
    _tsd_c.update(tailscale_setup_done=True, tailscale_use_funnel=True, tailscale_mount="",
                  bind_host="0.0.0.0")
    _tsd_save(_tsd_c)
    _tsd_html = c.get("/tailscale").get_data(as_text=True)
    check("tailscale page: Disable targets the panel's own mount, not another app's '/'",
          'data-mount="/lgsm"' in _tsd_html and 'data-mount="/"' not in _tsd_html,
          repr([ln.strip() for ln in _tsd_html.splitlines() if "data-mount" in ln][:3]))
    _tsd_r = c.post("/api/tailscale/serve", json={"action": "disable", "mount": "/"})
    check("tailscale serve: disabling at another app's mount removes nothing and keeps the config",
          _tsd_r.status_code != 200 and _tsd_ran == []
          and _tsd_load().get("tailscale_setup_done") is True,
          "%d %r ran=%r" % (_tsd_r.status_code, _tsd_r.get_json(), _tsd_ran))
    # A loopback-bound panel is reached ONLY through Serve. Removing it ended the admin's session
    # and nothing could reach the process again — a restart re-binds 127.0.0.1 and no longer
    # re-applies Serve — so getting back in took host SSH. change-port refuses to create that
    # state; Disable created it with one click. Both a stored 127.0.0.1 and an unset bind that
    # boot resolved to 127.0.0.1 are that state.
    _tsd_app = sys.modules["app"]   # loaded by `from app import` above
    _tsd_rb = dict(_tsd_app._RESOLVED_BIND)
    try:
        for _tsd_label, _tsd_bind, _tsd_resolved in (
                ("a stored 127.0.0.1 bind", "127.0.0.1", None),
                ("an unset bind that boot resolved to 127.0.0.1", "", "127.0.0.1")):
            _tsd_app._RESOLVED_BIND.clear()
            if _tsd_resolved:
                _tsd_app._RESOLVED_BIND[_tsd_port] = _tsd_resolved
            _tsd_lb = _tsd_load()
            _tsd_lb["bind_host"] = _tsd_bind
            _tsd_save(_tsd_lb)
            _tsd_r = c.post("/api/tailscale/serve", json={"action": "disable", "mount": "/lgsm"})
            check("tailscale serve: Disable is refused with %s (it would lock the admin out)"
                  % _tsd_label,
                  _tsd_r.status_code == 400 and _tsd_ran == []
                  and _tsd_load().get("tailscale_setup_done") is True
                  and "0.0.0.0" in ((_tsd_r.get_json() or {}).get("message") or ""),
                  "%d %r ran=%r" % (_tsd_r.status_code, _tsd_r.get_json(), _tsd_ran))
    finally:
        _tsd_app._RESOLVED_BIND.clear()
        _tsd_app._RESOLVED_BIND.update(_tsd_rb)
    # The same POST with the panel reachable without Serve goes through: the control that the
    # refusal above is about the bind, not about Disable.
    _tsd_lb = _tsd_load()
    _tsd_lb["bind_host"] = "0.0.0.0"
    _tsd_save(_tsd_lb)
    _tsd_r = c.post("/api/tailscale/serve", json={"action": "disable", "mount": "/lgsm"})
    check("tailscale serve: disabling the panel's mount runs the CLI's `serve ... off` removal",
          _tsd_r.status_code == 200
          and _tsd_ran == [["serve", "--https=443", "--set-path=/lgsm", "off"]],
          "%d %r ran=%r" % (_tsd_r.status_code, _tsd_r.get_json(), _tsd_ran))
    check("tailscale serve: ...and the boot path will no longer re-apply it (control)",
          _tsd_load().get("tailscale_setup_done") is False
          and not _tsd_load().get("tailscale_use_funnel"))
finally:
    _tsd.get_tailscale_info, _tsd._run_ts, _tsd.ensure_operator = _tsd_saved
    _tsd._cache["info"] = None
    _tsd_save(_tsd_cfg0)
# ── window.MOUNT follows the LIVE mount, like url_for does ────────────────────────────────
# It was the mount as it stood at boot, while PrefixMiddleware applies the live one to every
# request: after Serve was enabled (or moved) at runtime the pages rendered with correct links,
# and every fetch() and the console socket went to the old mount until a restart.
_mt_saved = load_config()
try:
    _mt_cfg = dict(_mt_saved)
    _mt_cfg["tailscale_mount"] = "/lgsm"
    save_config(_mt_cfg)
    _mt_r = c.get("/lgsm/account")
    _mt_html = _mt_r.get_data(as_text=True)
    check("mount: (control) the page is served under a mount set at runtime",
          _mt_r.status_code == 200 and 'href="/lgsm/' in _mt_html, "got %d" % _mt_r.status_code)
    check("mount: a mount set at runtime reaches window.MOUNT (not the boot-time one)",
          'window.MOUNT = "/lgsm";' in _mt_html,
          "fetch() and the socket would still use the boot-time mount")
finally:
    save_config(_mt_saved)
check("mount: ...and with no mount, window.MOUNT is empty again",
      'window.MOUNT = "";' in c.get("/account").get_data(as_text=True))

# ── a banned client arriving through Tailscale Funnel (or a reverse proxy) is refused ──────
# Funnel delivers every public client from 127.0.0.1 — the client's own connection ends at
# Tailscale's relay — so fail2ban's and the auto-block's firewall bans never touch it: a banned
# client carried on at 8 guesses per 5 minutes while the panel announced it banned. The gate is
# the OUTERMOST WSGI layer, because the Socket.IO handshake and the static files never reach
# Flask's request hooks. Driven through the real app stack.
from panel.security import banlist as _gb
_gb_saved = (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, dict(_gb._taken))
try:
    _gb.set_f2b(["203.0.113.77", "100.101.102.103"])
    _gb.set_ufw({"198.51.100.0/24": "panel-autoblock"})
    _gb.set_whitelist([])
    _gb_c = app.test_client()
    _gb_ban = {"X-Forwarded-For": "203.0.113.77"}
    _gb_r = {"login": _gb_c.get("/login", headers=_gb_ban),
             "socket": _gb_c.get("/socket.io/?EIO=4&transport=polling", headers=_gb_ban),
             "static": _gb_c.get("/static/css/panel.css", headers=_gb_ban),
             "ufw-net": _gb_c.get("/login", headers={"X-Forwarded-For": "198.51.100.40"})}
    check("funnel gate: a banned forwarded client is refused on a page, the Socket.IO handshake, "
          "a static file, and from a banned UFW network",
          all(r.status_code == 403 and r.get_data() == b"Forbidden\n" for r in _gb_r.values()),
          {k: r.status_code for k, r in _gb_r.items()})
    _gb_ok = {"other": _gb_c.get("/login", headers={"X-Forwarded-For": "192.0.2.10"}),
              "banned-first-hop": _gb_c.get("/login",
                                            headers={"X-Forwarded-For": "203.0.113.77, 192.0.2.10"}),
              "no-header": _gb_c.get("/login"),
              "socket-other": _gb_c.get("/socket.io/?EIO=4&transport=polling",
                                        headers={"X-Forwarded-For": "192.0.2.10"}),
              # A tailnet peer the jail banned (web port only) keeps its Serve access.
              "tailnet": _gb_c.get("/login", headers={"X-Forwarded-For": "100.101.102.103"})}
    check("funnel gate: ...while any other client, a banned address that is not the LAST hop, "
          "a request with no forwarded address, and a banned TAILNET peer go through",
          all(r.status_code != 403 for r in _gb_ok.values())
          and _gb_ok["socket-other"].get_data(as_text=True).startswith("0{"),
          {k: r.status_code for k, r in _gb_ok.items()})
    _gb.set_whitelist(["203.0.113.77"])
    _gb_wl = _gb_c.get("/login", headers=_gb_ban).status_code
    _gb.set_whitelist([])
    _gb.set_f2b([])
    _gb.set_ufw([])
    _gb_lift = _gb_c.get("/login", headers=_gb_ban).status_code
    check("funnel gate: ...a whitelisted address is never refused, and a lifted ban lets it in",
          _gb_wl != 403 and _gb_lift != 403, "whitelisted=%s lifted=%s" % (_gb_wl, _gb_lift))
finally:
    (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, _gb_t0) = _gb_saved
    _gb._taken.clear()
    _gb._taken.update(_gb_t0)

# The set is kept current between the ban-watcher's 90 s ticks: a failed login that came
# through a proxy (it may be the one fail2ban bans for), and an admin's Block / Unban /
# Whitelist, each ask for one refresh. Recorded, not run — a refresh reads the firewall.
_gb_calls = []
_gb_rs = _gb.refresh_soon
_gb_cfg0 = load_config()
try:
    _gb.refresh_soon = lambda delay=3.0: _gb_calls.append(delay)
    for _proxied in (True, False):
        _gb_calls.clear()
        app.test_client().post("/login", data={"username": "nobody-here", "password": "x"},
                               headers={"X-Forwarded-For": "192.0.2.77"} if _proxied else {})
        check("funnel gate: a failed login %s a refresh (%s)"
              % ("asks for" if _proxied else "does not ask for",
                 "it came through a proxy" if _proxied else "it came straight in"),
              bool(_gb_calls) is _proxied, repr(_gb_calls))
    from panel.ops import system_ops as _gb_so
    _gb_deny = _gb_so.ufw_deny_ip
    try:
        _gb_so.ufw_deny_ip = lambda ip: (True, "blocked")
        _gb_calls.clear()
        c.post("/api/panel/security/block", json={"ip": "203.0.113.200"})
        _gb_blk = list(_gb_calls)
    finally:
        _gb_so.ufw_deny_ip = _gb_deny
    check("funnel gate: an admin's Block IP refreshes the set at once", _gb_blk == [0],
          repr(_gb_blk))
finally:
    _gb.refresh_soon = _gb_rs
    save_config(_gb_cfg0)
_gb_app_src = open(os.path.join(os.path.dirname(os.path.abspath(_SUITE_FILE)), "..", "app.py"),
                   encoding="utf-8").read()
# The loop runs _ban_watch_tick; the tick feeds the set from the fail2ban reading it takes, and
# UFW's through banlist.watch_ufw (which reads it when ufw's rule files changed; unit part34).
_gb_watch = _gb_app_src[_gb_app_src.index("def _f2b_ban_watch"):]
_gb_watch = _gb_watch[:_gb_watch.index("time.sleep(90)")]
_gb_tick = _gb_app_src[_gb_app_src.index("def _ban_watch_tick"):]
_gb_tick = _gb_tick[:_gb_tick.index("\ndef ")]
check("funnel gate: the 90 s ban-watcher feeds the set from the reading it already takes",
      "_ban_watch_tick(app, state)" in _gb_watch
      and "_banlist.set_f2b(reading, _taken)" in _gb_tick
      and "_banlist.watch_ufw(so.ufw_blocked_ips)" in _gb_tick)

# ── a socket opened BEFORE its client was banned is dropped when the ban lands ─────────────
# A ban refuses new connections — the gate above, or the firewall — and nothing re-asked about
# one already open: a live console or a root terminal opened by an address fail2ban then banned
# kept streaming for as long as the browser stayed. Driven through the real socket stack.
from panel.routes import server_files as _bs_sf
_bs_saved = (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, dict(_gb._taken))
_bs_socks = []


def _bs_open(xff):
    _s = app.socketio.test_client(app, flask_test_client=client_as(admin_id),
                                  headers={"X-Forwarded-For": xff})
    _bs_socks.append(_s)
    return _s


try:
    _gb.set_f2b([])
    _gb.set_ufw([])
    _gb.set_whitelist(["203.0.113.99"])
    _bs = {"banned": _bs_open("203.0.113.88"), "other": _bs_open("192.0.2.88"),
           "tailnet": _bs_open("100.101.102.104"), "whitelisted": _bs_open("203.0.113.99")}
    check("ban sweep: (control) every socket connects and is recorded by its address",
          all(_s.is_connected() for _s in _bs.values()) and len(_bs_sf._socket_addrs) >= 4,
          {k: _s.is_connected() for k, _s in _bs.items()})
    _gb.set_f2b(["203.0.113.88", "100.101.102.104", "203.0.113.99"])
    check("ban sweep: a fail2ban ban drops the open socket of the address it names",
          not _bs["banned"].is_connected())
    check("ban sweep: ...and leaves another client, a tailnet peer and a whitelisted address "
          "connected", all(_bs[k].is_connected() for k in ("other", "tailnet", "whitelisted")),
          {k: _s.is_connected() for k, _s in _bs.items()})
    _gb.set_ufw({"192.0.2.0/24": ""})
    check("ban sweep: a UFW deny of a whole network drops a socket inside it",
          not _bs["other"].is_connected())
    check("ban sweep: a dropped socket leaves no address behind (the disconnect handler ran)",
          not any(a[1] is not None and str(a[1]) in ("203.0.113.88", "192.0.2.88")
                  for a in _bs_sf._socket_addrs.values()), repr(_bs_sf._socket_addrs))
    check("ban sweep: a banned address cannot open a new socket either",
          not _bs_open("203.0.113.88").is_connected())
    # A socket is refused where a new request would be. A direct client meets the host
    # firewall, which bans the ADDRESS; a forwarded one meets the gate, which widens an IPv6
    # ban to its /64 (the throttle's unit). Judging the peer by the /64 cost a household
    # neighbour its console while every page still loaded.
    import ipaddress as _bs_ip
    _gb.set_f2b(["2001:db8:1:2::10"])
    _bs_n = _bs_ip.ip_address("2001:db8:1:2::11")
    _bs_v6 = [_bs_sf._addrs_banned((_bs_ip.ip_address("2001:db8:1:2::10"), None)),
              _bs_sf._addrs_banned((_bs_n, None)), _bs_sf._addrs_banned((None, _bs_n))]
    check("ban sweep: an IPv6 ban drops the banned PEER but not a /64 neighbour the firewall "
          "still admits, while a FORWARDED neighbour is judged by its /64 as the gate judges it",
          _bs_v6 == [True, False, True], repr(_bs_v6))
finally:
    for _s in _bs_socks:
        try:
            if _s.is_connected():
                _s.disconnect()
        except Exception:
            pass
    (_gb._f2b, _gb._ufw, _gb._allow, _gb._by_len, _bs_t0) = _bs_saved
    _gb._taken.clear()
    _gb._taken.update(_bs_t0)
# panel.js arms its auth ping and session-expired redirect only where SIGNED_IN is true. They
# ran on signed-out pages too, and threw an invitee (or the first-run admin) off a half-filled
# form to /login with "Your session expired" — about a session that never existed.
check("session: (control) a page rendered for a signed-in user says so",
      "window.SIGNED_IN = true;" in c.get("/account").get_data(as_text=True))
check("session: a signed-out page does not claim a session panel.js could 'expire'",
      "window.SIGNED_IN = false;" in app.test_client().get("/login").get_data(as_text=True))

# ── The notifications page must actually OFFER each channel ───────────────────────────────
# "/notifications renders 200" passes just as well with a channel's whole card missing, which
# is how a half-wired provider ships: the backend supports it and nobody can reach it.
_nt_html = c.get("/notifications").get_data(as_text=True)
for _field in ("ntfy_enabled", "ntfy_topic", "ntfy_server", "ntfy_token"):
    check("notifications page: the ntfy form offers %s" % _field,
          ('name="%s"' % _field) in _nt_html)
check("notifications page: ntfy has a Send test button wired to the dispatcher",
      'data-args=\'["ntfy", "@self"]\'' in _nt_html)
check("notifications page: the stored ntfy token is NOT sent to the browser",
      "TESTONLY" not in _nt_html)

# ── Sidebar active-state must use request.endpoint, NOT request.path == url_for(...) — the
#    latter breaks under a URL mount prefix (e.g. /lgsm), where url_for includes the prefix but
#    request.path doesn't, so nothing highlights. Exactly the current page's link is active. ──
import re as _nre


def _active_navs(html):
    return [m.strip() for m in _nre.findall(r'class="active">\s*<i[^>]*></i>\s*([^<]+?)\s*</a>', html)]


check("nav active: Dashboard on /", _active_navs(c.get("/").get_data(as_text=True)) == ["Dashboard"],
      _active_navs(c.get("/").get_data(as_text=True)))
check("nav active: Users on /users", _active_navs(c.get("/users").get_data(as_text=True)) == ["Users"])
check("nav active: Settings on /settings",
      _active_navs(c.get("/settings").get_data(as_text=True)) == ["Settings"])

# ── The footer's version: the commit's date, beside the commit it is the date of ──────────────
# Every commit of a day shares the date, so the footer only answers "what is deployed" with the
# commit next to it. Rendered with known values: this suite's copy of the panel may have no
# .git, and then its own version reads "unknown" with no commit at all.
_fv_app = sys.modules["app"]   # loaded by `from app import` above
_fv_saved = (_fv_app.PANEL_VERSION, _fv_app.PANEL_COMMIT)
try:
    _fv_app.PANEL_VERSION, _fv_app.PANEL_COMMIT = "2026.9.26", "a1b2c3d"
    _fv_html = c.get("/").get_data(as_text=True)
finally:
    _fv_app.PANEL_VERSION, _fv_app.PANEL_COMMIT = _fv_saved
_fv_m = _nre.search(r'<span id="panel-version">([^<]*)</span>\s*<(a|span) id="panel-commit"'
                    r'([^>]*)>([^<]*)<', _fv_html)
check("footer: the version is the date, as it is, followed by the running commit",
      _fv_m is not None and _fv_m.group(1) == "2026.9.26"
      and _fv_m.group(4).strip() == "· a1b2c3d",
      repr(_fv_m.groups() if _fv_m else _fv_html[_fv_html.find("panel-version") - 20:][:300]))
check("footer: ...and the commit links to that commit on GitHub",
      _fv_m is not None and _fv_m.group(2) == "a" and "/commit/a1b2c3d\"" in _fv_m.group(3),
      repr(_fv_m.group(3) if _fv_m else None))

# ── Audit-log filters/sort must be injection-safe: a junk sort column, bad
#    direction/status, and hostile filter values are allowlisted/parameterized,
#    so the page still renders 200 rather than 500. ──
r = c.get("/logs?sort=id%3BDROP+TABLE&dir=nonsense&status=xyz"
          "&q=%27%22%3B--&action=whatever&user=nobody")
check("GET /logs with junk filter/sort params -> 200 (allowlisted)",
      r.status_code == 200, "got %d" % r.status_code)

# ── The audit log shows a detail's END, not just its first 100 characters ──
# Start/stop/restart store the LAST 400 characters of LinuxGSM's output on purpose — the
# [ OK ]/[FAIL] line and its reason are at the end — and the viewer cut every detail at 100
# characters, so the part kept on purpose was never visible anywhere in the panel.
from panel.db.models import AuditLog as _dtl_AL
_dtl_head = "DTLHEAD" + "x" * 150
_dtl_tail = "DTLTAIL_FAIL_REASON"
with app.app_context():
    db.session.add(_dtl_AL(username="admin", action="server_start", target="dtl-probe",
                           detail=_dtl_head + " ... " + _dtl_tail, success=False))
    db.session.commit()
_dtl_html = c.get("/logs?q=DTLHEAD").get_data(as_text=True)
check("audit log: (control) the long entry is on the page at all",
      "DTLHEAD" in _dtl_html, "the probe row did not render — the check below proves nothing")
check("audit log: a long detail's tail (where the outcome is) is rendered, not cut at 100 chars",
      _dtl_tail in _dtl_html, "the FAIL reason stored at the end of the detail is not on /logs")
# ...and the search leaves out what does not match it. Ignoring `q` (in _filtered_audit_query
# since view_logs was split) left every suite green: every search here only looked for the row
# it expected, and a newer, unrelated row is on page one either way.
with app.app_context():
    db.session.add(_dtl_AL(username="admin", action="server_start", target="dtl-other",
                           detail="DTLOTHER_UNRELATED", success=True))
    db.session.commit()
_dtl_q = c.get("/logs?q=DTLHEAD").get_data(as_text=True)
check("audit log: a search shows only the rows that match it",
      "DTLHEAD" in _dtl_q and "DTLOTHER_UNRELATED" not in _dtl_q,
      "an unrelated row is on the page a search for DTLHEAD returned")

# The Files & Config page (config editor + file browser + cron manager) must render.
check("GET /server/<id>/files renders (200)",
      c.get("/server/%d/files" % gs_id).status_code == 200)

# An un-installed (still-installing) server has no console/files yet — those routes must redirect
# away, not render, so you can't reach them before the install finishes.
with app.app_context():
    _inst = GameServer(remote_id=remote.id, name="smoke-installing", short_name="instserver",
                       game_type="gmod", port=27099, installed=False, status="installing")
    db.session.add(_inst); db.session.commit()
    _inst_id = _inst.id
_inst_r = c.get("/server/%d" % _inst_id)
check("console of an installing server redirects (not 200)",
      _inst_r.status_code in (302, 303))
check("files of an installing server redirects (not 200)",
      c.get("/server/%d/files" % _inst_id).status_code in (302, 303))
# ...and it must redirect somewhere the VIEWER can enter. It sent them to manage_servers,
# which is @permission_required(MANAGE_SERVERS, INSTALL_SERVER) and whose whole body is
# `redirect(url_for("index"))`. A VIEW_CONSOLE-only member failed that gate on a page they
# never asked for, so the hop added a red "You do not have permission to do that." beside the
# blue "still installing" notice — a false statement about their own rights — and landed them
# on the dashboard anyway. Asserted on the LOCATION, not on the flash: a superadmin passes the
# gate, so the extra hop is invisible to this client and only the target shows it.
check("installing server: the redirect skips the permission-gated manage_servers hop",
      "/servers/manage" not in (_inst_r.headers.get("Location") or ""),
      "Location: %r — a viewer without MANAGE_SERVERS is told they lack a permission they "
      "never asked for" % (_inst_r.headers.get("Location"),))
check("installing server: ...and goes straight to the dashboard (positive control)",
      (_inst_r.headers.get("Location") or "x").split("?")[0].endswith("/"),
      "Location: %r — expected the dashboard" % (_inst_r.headers.get("Location"),))

# ── an install must not call a slow first boot a failure ────────────────────────────────────
# The install started the server, then polled ~15s for its port and, if it wasn't up, finished
# with "installed, but it didn't start". Measured while installing the LinuxGSM catalogue on
# the test host: most games bind immediately, Nuclear Dawn took 20s and Insurgency 40s, and the
# heavier Unreal/Unity titles are slower again. All of those ended an otherwise perfect install
# with the one sentence that sends an operator hunting a fault that isn't there.
#
# Two things had to change together, so both are pinned: the window, and the fact that a start
# LinuxGSM did not complain about is not a failed start.
_ms_src2 = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(_SUITE_FILE))),
                             "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
check("install: the post-start port poll waits ~90s, not 15",
      "for _ in range(30):" in _ms_src2 and "for _ in range(5):" not in _ms_src2,
      "still polling 5 times")
check("install: a start LinuxGSM did not complain about is reported as still coming up",
      "if reason or s_rc != 0:" in _ms_src2 and "installed and starting" in _ms_src2,
      "the didn't-start wording is still unconditional")
check("install: ...and a start that DID report a problem still says it didn't start",
      "installed, but it didn't start" in _ms_src2)

# ── a FAILED install must not be a dead end ─────────────────────────────────────────────────
# The Game Servers page offers a failed row both "Console & stats" and "Files and config", and
# both routes redirected away saying the server was "still installing". It was not: the install
# had failed, and step 2 (`./linuxgsm.sh <game>`) had already written the whole
# lgsm/config-lgsm/<game>/ tree — including the `steamuser="username"` line that the most common
# failure tells you to change. So the panel pointed at a setting and then locked the door.
#
# Verified in a rendered panel before this was written: both links present, both dead.
with app.app_context():
    _fi = GameServer(remote_id=db.session.get(GameServer, gs_id).remote_id,
                     name="failed-install", short_name="bsserver", game_type="bs",
                     port=27045, installed=False, status="failed")
    db.session.add(_fi); db.session.commit()
    _fi_id = _fi.id
_ffr = c.get("/server/%d/files" % _fi_id)
check("failed install: the Files & Config page OPENS (its LinuxGSM config is what survives)",
      _ffr.status_code == 200, _ffr.status_code)
_ffh = _ffr.get_data(as_text=True)
check("failed install: ...and says the game files never downloaded",
      "the game files never downloaded" in _ffh)
# Nothing to browse, back up or install a mod into until the files exist.
check("failed install: the file browser is not rendered over a directory that isn't there",
      'id="file-browser"' not in _ffh)
check("failed install: nor the mods card, which installs INTO serverfiles",
      'id="mods-card"' not in _ffh)
# The config editor is the whole point of the page in this state.
check("failed install: the LinuxGSM config editor IS there", 'id="cfg-tabs"' in _ffh)
# The console genuinely has nothing to show, but it must not claim the install is still running
# — and it should hand the operator to the page that can fix it.
_fdr = c.get("/server/%d" % _fi_id)
check("failed install: the console redirects to Files & Config, not to a 'still installing' wait",
      _fdr.status_code in (302, 303)
      and ("/files" in (_fdr.headers.get("Location") or "")), _fdr.headers.get("Location"))
# A server still genuinely installing keeps the old behaviour.
with app.app_context():
    _fi2 = db.session.get(GameServer, _fi_id)
    _fi2.status = "installing"; db.session.commit()
check("failed install: a server that really IS installing still gets the wait message",
      c.get("/server/%d/files" % _fi_id).status_code in (302, 303))
# And the reconciler has to be looking at failed rows, or files that arrive after a repair
# (the control bar's Update re-runs SteamCMD) are never adopted and the row stays unusable.
_app_src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(_SUITE_FILE))),
                             "app.py"), encoding="utf-8").read()
check("failed install: the reconcile ticker re-checks failed rows, so a repair is noticed",
      '("installing", "configuring", "failed")' in _app_src)
with app.app_context():
    _d = db.session.get(GameServer, _fi_id)
    db.session.delete(_d); db.session.commit()

# ── /api/server/<id> must never write a status it could not READ ────────────────────────────
# get_server_status answers "unknown" when the host did not answer. That is not a third kind of
# server, and this endpoint used to commit it. It arrives more easily than it looks: the read
# runs LinuxGSM `details`, which does a full `du` of serverfiles — measured at 13s on a 6.5GB
# server against a 30s timeout — and a timed-out command does not raise here, it returns
# ("", "timed out", -1). So a big server wrote "unknown" over a perfectly good "online", and
# the dashboard, the chat bots' /servers and _query_server_slots all repeated it.
_stat_saved = _sm_core.run_as_game_user
try:
    with app.app_context():
        _sg = db.session.get(GameServer, gs_id)
        _sg.installed, _sg.status = True, "online"
        db.session.commit()
    # THE BUG: the host did not answer. No raise, no output.
    _sm_core.run_as_game_user = lambda *a, **k: ("", "SSH command timed out", -1)
    _sr = c.get("/api/server/%d" % gs_id)
    check("status endpoint: an unreadable host reports unknown",
          (_sr.get_json() or {}).get("status") == "unknown", _sr.get_json())
    with app.app_context():
        check("status endpoint: ...and does NOT write it over the last known status",
              db.session.get(GameServer, gs_id).status == "online",
              db.session.get(GameServer, gs_id).status)
    # A status it really did read still lands, or the guard above would just freeze the column.
    _sm_core.run_as_game_user = lambda *a, **k: ("Status: STOPPED", "", 0)
    c.get("/api/server/%d" % gs_id)
    with app.app_context():
        check("status endpoint: a status it DID read is still persisted",
              db.session.get(GameServer, gs_id).status == "offline",
              db.session.get(GameServer, gs_id).status)
finally:
    _sm_core.run_as_game_user = _stat_saved

# ── /api/server/<id>/stats tells the page whether it actually READ anything ───────────────
# This route already computes the ram_total sentinel — it uses it to refuse to PERSIST a
# guess ("report what we last knew") — and then shipped `metrics` without it, so the detail
# page painted a confident 0% CPU / 0 MB RAM for a host nobody could read and pushed those
# zeros into the live chart as a dip that never happened. The route had no test at all.
_st_saved = _sm_core.server_live_metrics
try:
    _sm_core.server_live_metrics = lambda *a, **k: {
        "cpu_percent": 12.0, "ram_percent": 40, "ram_total": 8, "disk_percent": 20,
        "cores": 4, "game_procs": 2, "game_cpu_percent": 5.0, "game_ram_mb": 1024,
        "game_uptime_secs": 60, "port_open": True}
    _sj = (c.get("/api/server/%d/stats" % gs_id).get_json() or {})
    check("server stats: a real read is reported as readable",
          _sj.get("metrics_readable") is True, str(_sj)[:140])
    # ...and the all-zero dict, which is what the non-raising transports produce.
    _sm_core.server_live_metrics = lambda *a, **k: {
        "cpu_percent": 0.0, "ram_percent": 0, "ram_total": 0, "disk_percent": 0,
        "cores": 1, "game_procs": 0, "game_cpu_percent": 0.0, "game_ram_mb": 0,
        "game_uptime_secs": 0, "port_open": False}
    # The row says online going in, so "offline" can only come from the port the sample never
    # read. Reporting that (in _persisted_stats_status since api_server_stats was split) left
    # every suite green: the persist guard held, so only the ANSWER was wrong, and only the
    # source-text checks in part02 looked at this route.
    with app.app_context():
        _st_before = db.session.get(GameServer, gs_id).status
        db.session.get(GameServer, gs_id).status = "online"
        db.session.commit()
    _sj2 = (c.get("/api/server/%d/stats" % gs_id).get_json() or {})
    check("server stats: an all-zero sample is reported as NOT readable",
          _sj2.get("metrics_readable") is False, str(_sj2)[:140])
    with app.app_context():
        _st_row = db.session.get(GameServer, gs_id).status
        db.session.get(GameServer, gs_id).status = _st_before
        db.session.commit()
    check("server stats: ...and reports the status it last KNEW, not 'offline' off a port it "
          "never read", _sj2.get("status") == "online" and _st_row == "online",
          "reported %r, row now %r" % (_sj2.get("status"), _st_row))
finally:
    _sm_core.server_live_metrics = _st_saved

# Alerts endpoint: GET returns the provider list; POST filters to known keys and never 500s
# (the config write to the game host fails on the test box, but returns gracefully).
#
# The GET needs a config read that SUCCEEDS now, and that is the point of the check below it.
# This used to run against the test box's unreachable game host and still assert a rendered
# provider list, because the route answered an unreadable config with `values: {}`. The card
# paints those values into its inputs and Save posts every input back, so a blank form was one
# click away from writing "" over the operator's real Discord/Telegram credentials.
_al_saved = _sm_core.run_command
try:
    from panel.ops.ssh_manager import files as _sm_files_al
    _sm_core.run_command = lambda s, cmd, **k: (
        'discordalert="on"\ndiscordwebhook="https://real/hook"\n' + _sm_files_al._READ_END, "", 0)
    al = c.get("/api/server/%d/alerts" % gs_id)
    check("alerts: GET returns the provider list",
          al.status_code == 200 and isinstance((al.get_json() or {}).get("providers"), list))
    check("alerts: GET returns the values it read",
          ((al.get_json() or {}).get("values") or {}).get("discordwebhook") == "https://real/hook",
          str(al.get_json())[:160])
    # ...and a read that did NOT happen is reported, not rendered as "nothing configured".
    # run_command does not raise on the tailscale/local transports, so this tuple — not an
    # exception — is what an unreachable host really produces.
    _sm_core.run_command = lambda s, cmd, **k: ("", "SSH command timed out", -1)
    alf = c.get("/api/server/%d/alerts" % gs_id)
    _alfj = alf.get_json() or {}
    check("alerts: an unreadable config is an error, not a blank form",
          bool(_alfj.get("error")) and "values" not in _alfj, str(_alfj)[:160])
finally:
    _sm_core.run_command = _al_saved
# `al` deliberately stays bound to the SUCCESSFUL read above: the provider cross-checks below
# compare the GET's advertised providers against the POST's accepted keys, and they need a
# response that actually carries a provider list.
alp = c.post("/api/server/%d/alerts" % gs_id, json={"values": {"discordalert": "on", "notakey": "x"}})
check("alerts: POST returns a JSON result (no 500)", "success" in (alp.get_json() or {}))

# Every provider the endpoint advertises must be one the WRITE path will actually store. A
# provider present in the GET but filtered out of the POST would render, accept input and
# silently drop it \u2014 the read and write sides derive from the same list, and this is what
# holds them together end to end.
_al_provs = (al.get_json() or {}).get("providers") or []
check("alerts: ntfy is offered to the per-server UI",
      any(_p.get("id") == "ntfy" for _p in _al_provs),
      str(sorted(_p.get("id") for _p in _al_provs)))
# Asserted against the write path's OWN key set, not against the response: this endpoint
# answers {"success": ...} whether or not it silently dropped a key, so a status-only check
# would pass for a provider whose fields never get written.
from panel.routes.server_files import _ALERT_KEY_SET as _AKS_SMOKE
_al_keys = [k for _p in _al_provs for k in [_p["toggle"]] + [f["key"] for f in _p["fields"]]]
_al_dropped = [k for k in _al_keys if k not in _AKS_SMOKE]
check("alerts: POST accepts every key the GET advertises (no provider is write-only-in-name)",
      not _al_dropped, "the write path would silently drop: %s" % _al_dropped)

# ── uninstall never stops, kills or deletes an account that is root on the host ───────────
# A row for the host's own sudo-capable login (which import used to adopt) made this route run
# `userdel -r -f` on it. The real privileged_accounts runs here; the host's reply is scripted,
# and run_privileged is trapped so nothing a check drives reaches a host.
from panel.db.models import GameServer as _UPGS
_smoke_ms.privileged_accounts = _smoke_priv_real
_up_saved = (_sm_core.run_command, _sm_core.run_privileged)
_up_verbs = []
_up_reply = ["ACCT upadmin 1000 upadmin adm sudo\nLGSM_ACCT_PROBE_DONE\n"]
try:
    _sm_core.run_command = lambda _s, cmd, **_k: (
        (_up_reply[0], "", 0) if "LGSM_ACCT_PROBE_DONE" in cmd else ("", "", 0))
    _sm_core.run_privileged = lambda *a, **k: (_up_verbs.append(a[1:2]), ("", "", 0))[1]
    with app.app_context():
        _up_rm = RemoteServer.query.first()
        _up = _UPGS(remote_id=_up_rm.id, name="upadmin", short_name="upadmin",
                    game_type="gmod", port=28940, installed=True, status="offline")
        _up_down = _UPGS(remote_id=_up_rm.id, name="updown", short_name="updown",
                         game_type="gmod", port=28945, installed=True, status="offline")
        db.session.add_all([_up, _up_down])
        db.session.commit()
        _up_id, _up_down_id = _up.id, _up_down.id
    _up_r = c.post("/servers/%d/delete" % _up_id, json={},
                   headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    _up_reply[0] = ""                      # the host stops answering
    _up_d = c.post("/servers/%d/delete" % _up_down_id, json={},
                   headers={"X-Requested-With": "XMLHttpRequest"})
finally:
    _sm_core.run_command, _sm_core.run_privileged = _up_saved
    _smoke_ms.privileged_accounts = lambda _remote, _users: {}
with app.app_context():
    _up_gone = db.session.get(_UPGS, _up_id) is None
    _up_down_kept = db.session.get(_UPGS, _up_down_id) is not None
    if _up_down_kept:
        db.session.delete(db.session.get(_UPGS, _up_down_id))
        db.session.commit()
check("uninstall: a sudo-group account is NOT stopped, killed or deleted on the host",
      _up_verbs == [], "verbs sent: %r" % (_up_verbs,))
check("uninstall: ...its row is removed from the panel, with a warning that says so",
      _up_gone and _up_r.get("success") is True and _up_r.get("warn") is True
      and "NOT deleted" in (_up_r.get("message") or ""), str(_up_r)[:200])
check("uninstall: a host that cannot answer the check keeps the row and touches nothing (409)",
      _up_d.status_code == 409 and _up_down_kept and _up_verbs == [],
      "got %d kept=%s" % (_up_d.status_code, _up_down_kept))

# ── uninstall: a FAILED userdel must not delete the panel's row ───────────────────────────
# This endpoint used to capture run_privileged's rc, hand it to log_action, and then delete the
# row and answer {"success": true} no matter what it was. A userdel that failed therefore left
# the account, its home and every game file on the host with no row left to manage them from —
# firewall rules already removed, next install of that game colliding with the surviving user,
# and the operator told it had worked. run_privileged RETURNS rc; it never raises, so nothing
# else caught it.
#
# Driven through the real endpoint with run_privileged stubbed per exit code, because the bug
# was in the branch AFTER the call, not in the call.
from panel.db.models import GameServer as _UGS  # pylint: disable=reimported
_uapp = sys.modules["app"]      # _appmod is not bound until later in this file
_u_orig = _sm_core.run_privileged
try:
    for _rc, _expect_gone, _label in ((1, False, "generic failure"),
                                      (4, False, "unexpected code"),
                                      (0, True, "removed"),
                                      (6, True, "no such user"),
                                      (12, True, "removed, home left")):
        with app.app_context():
            _rm = RemoteServer.query.first()
            _tmp = _UGS(remote_id=_rm.id, name="uninst%d" % _rc, short_name="uninst%d" % _rc,
                        game_type="gmod", port=28900 + _rc, installed=True, status="offline")
            db.session.add(_tmp); db.session.commit()
            _tid = _tmp.id
        _sm_core.run_privileged = (lambda rc: (lambda *a, **k: ("", "userdel: boom", rc)))(_rc)
        # X-Requested-With is what the page's fetch wrapper sends, and what _wants_json()
        # keys on — without it this endpoint answers with a flash+redirect instead.
        _resp = c.post("/servers/%d/delete" % _tid, json={},
                       headers={"X-Requested-With": "XMLHttpRequest"})
        with app.app_context():
            _still = _UGS.query.get(_tid) is not None
        check("uninstall: rc=%d (%s) -> row %s" % (_rc, _label, "deleted" if _expect_gone else "KEPT"),
              _still != _expect_gone, "row %s" % ("survived" if _still else "was deleted"))
        if not _expect_gone:
            check("uninstall: rc=%d reports failure, not success" % _rc,
                  (_resp.get_json() or {}).get("success") is False,
                  "got %r" % ((_resp.get_json() or {}).get("success"),))
        with app.app_context():   # clean up whatever survived
            _left = _UGS.query.get(_tid)
            if _left: db.session.delete(_left); db.session.commit()
finally:
    _sm_core.run_privileged = _u_orig


# ── uninstall removes THIS server's firewall rules, and nobody else's (Aikido 745379215) ────
# After the server's tagged rules it ran `ufw delete allow <port>` and the proto tcp/udp pair
# with no comment — and ufw removes a rule matching all but its comment when the delete has
# none. So every ALLOW on the port went, whoever's: another service's, an operator's own SSH
# allow, with no lockout guard in the way. The host below is a rule table answering the verbs
# with ufw's own matching; the route, the cleanup and the status parser are all real.
class _UfwTable:
    def __init__(self, *rules):
        self.rules = [list(r) for r in rules]

    def priv(self, server, verb, args=(), *a, **k):
        args = [str(x) for x in args]
        if verb == "ufw-status":
            return ("Status: active\n\n" + "".join(
                "[%2d] %-26s %-5s IN    Anywhere%s\n" % (
                    i, t, act, ("                   # " + cm) if cm else "")
                for i, (t, act, cm) in enumerate(self.rules, 1)), "", 0)
        if verb == "ufw-delete-num":
            del self.rules[int(args[0]) - 1]
            return ("Rule deleted", "", 0)
        if verb == "ufw-delete-num-if":      # the host's own re-check, then the delete
            rows = self.priv(server, "ufw-status")[0].splitlines()
            got = [" ".join(r.split("]", 1)[1].split()) for r in rows
                   if r.startswith("[") and int(r[1:r.index("]")]) == int(args[0])]
            if got != [args[1]]:
                return ("ufw-delete-num-if: rule moved", "", 3)
            del self.rules[int(args[0]) - 1]
            return ("Rule deleted", "", 0)
        if verb in ("ufw-delete-allow-port", "ufw-delete-allow-proto-port"):
            to = args[0] if verb == "ufw-delete-allow-port" else "%s/%s" % (args[1], args[0])
            self.rules = [r for r in self.rules if not (r[0] == to and r[1] == "ALLOW")]
            return ("Rule deleted", "", 0)
        return ("", "", 0)


_uf_saved = (_sm_core.run_privileged, _sm_core.run_command, _sm_core.run_as_game_user)
try:
    _sm_core.run_command = lambda *a, **k: ("", "", 0)
    _sm_core.run_as_game_user = lambda *a, **k: ("", "", 0)
    # The third: rules that CARRY the server's name but are not what the panel makes — a DENY,
    # a LIMIT, and a `22` allow the old "Open all ports" takeover could leave tagged with a
    # server. The name cleanup took every one of them; they stay now, and are named.
    for _uf_name, _uf_port, _uf_rules, _uf_keep, _uf_gone in (
            ("fwsshsrv", 22,
             (("22/tcp", "ALLOW", "operator"), ("22", "ALLOW", ""), ("27041", "ALLOW", "fwsshsrv")),
             [("22/tcp", "ALLOW", "operator"), ("22", "ALLOW", "")], ["27041"]),
            ("fwforeign", 27042,
             (("22/tcp", "LIMIT", ""), ("27042", "ALLOW", "fwforeign"),
              ("27042/udp", "ALLOW", "voicebridge"), ("27042/tcp", "ALLOW", "")),
             [("22/tcp", "LIMIT", ""), ("27042/udp", "ALLOW", "voicebridge")],
             ["27042", "27042/tcp"]),
            ("fwmixed", 27045,
             (("22/tcp", "ALLOW", "operator"), ("27045", "ALLOW", "fwmixed"),
              ("27046", "DENY", "fwmixed"), ("27047/tcp", "LIMIT", "fwmixed"),
              ("22", "ALLOW", "fwmixed")),
             [("22/tcp", "ALLOW", "operator"), ("27046", "DENY", "fwmixed"),
              ("27047/tcp", "LIMIT", "fwmixed"), ("22", "ALLOW", "fwmixed")], ["27045"])):
        _uf = _UfwTable(*_uf_rules)
        _sm_core.run_privileged = _uf.priv
        with app.app_context():
            _rm = RemoteServer.query.first()
            _tmp = _UGS(remote_id=_rm.id, name=_uf_name, short_name=_uf_name, game_type="gmod",
                        port=_uf_port, installed=True, status="offline")
            db.session.add(_tmp); db.session.commit()
            _tid = _tmp.id
        _resp = c.post("/servers/%d/delete" % _tid, json={},
                       headers={"X-Requested-With": "XMLHttpRequest"})
        _uf_left = [tuple(r) for r in _uf.rules]
        check("uninstall %s (port %d): every rule that is not this server's survives — an "
              "operator's SSH allow, another service's tag, a LIMIT" % (_uf_name, _uf_port),
              (_resp.get_json() or {}).get("success") is True
              and all(k in _uf_left for k in _uf_keep), "left=%r" % (_uf_left,))
        check("uninstall %s: ...while its own tagged rule and an untagged legacy allow on a port "
              "no one else holds still go (positive control)" % _uf_name,
              not any(r[0] in _uf_gone for r in _uf_left), "left=%r" % (_uf_left,))
        if _uf_name == "fwmixed":
            _uf_msg = (_resp.get_json() or {}).get("message", "")
            check("uninstall fwmixed: ...and the rules carrying its name that it left are named "
                  "in the answer",
                  "27046 DENY, 27047/tcp LIMIT" in _uf_msg and "own port: 22." in _uf_msg,
                  "message=%r" % (_uf_msg,))
            check("uninstall fwmixed: ...and the answer is a WARNING, not a green 'done'",
                  (_resp.get_json() or {}).get("warn") is True, repr(_resp.get_json()))
        else:
            check("uninstall %s: a clean firewall cleanup is no warning (control)" % _uf_name,
                  (_resp.get_json() or {}).get("warn") is False, repr(_resp.get_json()))
        with app.app_context():
            _left = _UGS.query.get(_tid)
            if _left: db.session.delete(_left); db.session.commit()
finally:
    _sm_core.run_privileged, _sm_core.run_command, _sm_core.run_as_game_user = _uf_saved


# ── uninstall names a rule with no name on it that is still on the server's own ports ─────
# The Firewall page's rate limit writes an UNTAGGED `N/tcp LIMIT` (ufw-limit-port takes no
# comment) and moves the server's other protocol onto a tagged `N/udp` allow. Uninstall took
# the udp allow and answered a clean "uninstalled": the port stayed open, rate limited, and
# nobody was told. The host below prints `ufw status numbered` as ufw 0.36.2 did on the test
# VPS (each public rule twice, its (v6) twin in a second block, one numbering); the route, both
# cleanups and the status parser are real.
class _Ufw36Table:
    HDR = ("Status: active\n\n     To                         Action      From\n"
           "     --                         ------      ----\n")

    def __init__(self, *rules):
        self.v4 = [list(r) for r in rules]
        self.v6 = [list(r) for r in rules]

    def rows(self):
        return (["%-26s %-11s %-26s%s" % (t, a + " IN", "Anywhere", " # " + c if c else "")
                 for t, a, c in self.v4]
                + ["%-26s %-11s %-26s%s" % (t + " (v6)", a + " IN", "Anywhere (v6)",
                                            " # " + c if c else "") for t, a, c in self.v6])

    def priv(self, server, verb, args=(), *a, **k):
        if verb == "ufw-status":
            return (self.HDR + "".join("[%2d] %s\n" % (i, r)
                                       for i, r in enumerate(self.rows(), 1)), "", 0)
        if verb in ("ufw-delete-num", "ufw-delete-num-if"):
            n = int(args[0])
            rows = self.rows()
            if verb == "ufw-delete-num-if" and not (
                    1 <= n <= len(rows) and " ".join(rows[n - 1].split()) == args[1]):
                return ("ufw-delete-num-if: rule moved", "", 3)   # the host's own re-check
            fam, i = (self.v4, n - 1) if n <= len(self.v4) else (self.v6, n - 1 - len(self.v4))
            del fam[i]
            return ("Rule deleted", "", 0)
        return ("", "", 0)

    def left(self):
        return [tuple(r) for r in self.v4 + self.v6]


_ul_saved = (_sm_core.run_privileged, _sm_core.run_command, _sm_core.run_as_game_user)
try:
    _sm_core.run_command = lambda *a, **k: ("", "", 0)
    _sm_core.run_as_game_user = lambda *a, **k: ("", "", 0)
    _UL_BASE = (("28960", "ALLOW", "codserver"), ("27015", "ALLOW", "gmodserver"),
                ("22/tcp", "ALLOW", "SSH panel"))
    # (name, game, port, a sibling (name, game, port) or None, rules, the sentence expected
    # in the answer or None for a clean uninstall, text that must NOT be in the answer)
    for _ul_name, _ul_game, _ul_port, _ul_sib, _ul_rules, _ul_named, _ul_not in (
            # What remote_ufw_limit_port leaves on the server's tagged bare allow, and another
            # port's untagged limit. The legacy sweep runs (no one else holds 27060).
            ("fwlimit", "gmod", 27060, None,
             (("27060/tcp", "LIMIT", ""), ("27060/udp", "ALLOW", "fwlimit"),
              ("27062/tcp", "LIMIT", "")),
             "Left in place on its port: 27060/tcp LIMIT.", "27062"),
            # ...and on a legacy UNTAGGED bare allow: its udp half is the sweep's to take, so
            # it goes and is not named; only the LIMIT is.
            ("fwlegacy", "gmod", 27074, None,
             (("27074/tcp", "LIMIT", ""), ("27074/udp", "ALLOW", "")),
             "Left in place on its port: 27074/tcp LIMIT.", "27074/udp"),
            ("fwclean", "gmod", 27064, None,
             (("27064", "ALLOW", "fwclean"), ("27066/tcp", "LIMIT", "")), None, "27066"),
            # 27068 is still in fwsib's block: a limit there is fwsib's concern, not left.
            ("fwshared", "gmod", 27068, ("fwsib", "rust", 27067),
             (("27068", "ALLOW", "fwshared"), ("27068/tcp", "LIMIT", "")), None, "27068"),
            # No legacy sweep (fwsib2 holds 27070), so the name cleanup names the block's
            # other port, and not the one fwsib2 still holds.
            ("fwq", "rust", 27070, ("fwsib2", "gmod", 27070),
             (("27070", "ALLOW", "fwq"), ("27071", "ALLOW", "fwq"), ("27070/tcp", "LIMIT", ""),
              ("27071/tcp", "LIMIT", "")),
             "Left in place on its port: 27071/tcp LIMIT.", "27070/tcp"),
            # A port its own tagged allow was on is its own too, outside the game's span: the
            # install tags LinuxGSM's Query port, and Rust's (28017) is beyond the 2-port span.
            # The legacy sweep names what is left, so the name cleanup hands the port on.
            ("fwrq", "rust", 27080, None,
             (("27080", "ALLOW", "fwrq"), ("27082/udp", "ALLOW", "fwrq"),
              ("27082/tcp", "LIMIT", ""), ("27084/tcp", "LIMIT", "")),
             "Left in place on its ports: 27082/tcp LIMIT.", "27084"),
            # ...but not one another server holds: the allocator reserves only the span, so the
            # next Rust server can be given the first one's tagged Query port as its game port.
            ("fwrh", "rust", 27086, ("fwsib3", "rust", 27088),
             (("27086", "ALLOW", "fwrh"), ("27088/udp", "ALLOW", "fwrh"),
              ("27088/tcp", "LIMIT", "")), None, "27088"),
            # The same with no sweep (fwsib4 holds 27092): the name cleanup names it, less what
            # fwsib4 holds.
            ("fwrn", "rust", 27092, ("fwsib4", "gmod", 27092),
             (("27092", "ALLOW", "fwrn"), ("27094/udp", "ALLOW", "fwrn"),
              ("27094/tcp", "LIMIT", ""), ("27092/tcp", "LIMIT", "")),
             "Left in place on its ports: 27094/tcp LIMIT.", "27092/tcp")):
        _ul = _Ufw36Table(*(_UL_BASE + _ul_rules))
        _sm_core.run_privileged = _ul.priv
        with app.app_context():
            _rm = RemoteServer.query.first()
            _tmp = _UGS(remote_id=_rm.id, name=_ul_name, short_name=_ul_name,
                        game_type=_ul_game, port=_ul_port, installed=True, status="offline")
            _sib = (_UGS(remote_id=_rm.id, name=_ul_sib[0], short_name=_ul_sib[0],
                         game_type=_ul_sib[1], port=_ul_sib[2], installed=True,
                         status="offline") if _ul_sib else None)
            db.session.add_all([_tmp] + ([_sib] if _sib else [])); db.session.commit()
            _tid, _sid = _tmp.id, (_sib.id if _sib else None)
        _uj = c.post("/servers/%d/delete" % _tid, json={},
                     headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
        _um = _uj.get("message", "")
        if _ul_named:
            check("uninstall %s: an untagged rule left on its own port is named in the answer, "
                  "and the answer warns" % _ul_name,
                  _uj.get("success") is True and _um.count(_ul_named) == 1
                  and _uj.get("warn") is True, repr(_uj))
        else:
            check("uninstall %s: a clean uninstall still does not warn" % _ul_name,
                  _uj.get("success") is True and _uj.get("warn") is False
                  and "Left in place" not in _um, repr(_uj))
        check("uninstall %s: ...a rule on another port, or on one another server still "
              "holds, is not named" % _ul_name,
              _ul_not not in _um, repr(_um))
        check("uninstall %s: ...every LIMIT stays — named, never deleted" % _ul_name,
              all(r in _ul.left() for r in _ul_rules if r[1] == "LIMIT")
              and not any(r[2] == _ul_name for r in _ul.left()), repr(_ul.left()))
        with app.app_context():
            for _x in (_tid, _sid):
                _left = _UGS.query.get(_x) if _x else None
                if _left: db.session.delete(_left); db.session.commit()
finally:
    _sm_core.run_privileged, _sm_core.run_command, _sm_core.run_as_game_user = _ul_saved

# ── a queued "stop/restart when empty" must not be thrown away ────────────────────────────
# The deferred sweep asks get_server_status and treats "offline" as "already stopped, nothing
# to do" — clearing BOTH flags. Once the port cross-check began answering "offline" for a
# server whose session is alive but not serving, that swallowed the operator's request: a
# "stop when empty" aimed at a crashed server (the exact state the cross-check detects) was
# cleared without ever being performed, and so was one that landed in the seconds between a
# restart and the port binding.
#
# Driven through the real sweep with the status stubbed, because the bug was in the CALLER:
# the helper answers correctly when asked correctly, and the sweep was not asking.
import panel.routes._shared as _shmod
_sh_gss = _shmod.get_server_status
try:
    with app.app_context():
        _rm = RemoteServer.query.first()
        _q = _UGS(remote_id=_rm.id, name="queued-stop", short_name="queuedstop",
                  game_type="gmod", port=28960, installed=True, status="online")
        _q.stop_pending = True
        db.session.add(_q); db.session.commit()
        _q_id = _q.id

    # A session that is alive but not serving. The stub answers the FOLDED word unless the
    # caller asks the finer question — so the flag surviving proves the sweep asked.
    _shmod.get_server_status = (lambda srv, gs, distinguish_unresponsive=False:
                                "unresponsive" if distinguish_unresponsive else "offline")
    _shmod._run_due_restarts(app)
    with app.app_context():
        _still_queued = bool(db.session.get(_UGS, _q_id).stop_pending)
    check("queued stop: a server whose session is alive but not serving keeps the request",
          _still_queued,
          "the sweep cleared stop_pending without ever stopping anything")

    # ...and a genuinely stopped server still clears it — that is what 'idle' is for, and
    # this is the control that stops the fix above from being 'never clear anything'.
    _shmod.get_server_status = lambda srv, gs, distinguish_unresponsive=False: "offline"
    _shmod._run_due_restarts(app)
    with app.app_context():
        _cleared = not db.session.get(_UGS, _q_id).stop_pending
    check("queued stop: ...while a genuinely stopped server still clears it", _cleared,
          "a stopped server should not keep a pending stop for ever")
finally:
    _shmod.get_server_status = _sh_gss
    with app.app_context():
        _l = db.session.get(_UGS, _q_id)
        if _l is not None:
            db.session.delete(_l); db.session.commit()

# ── a queued stop that FAILED must stay queued, and the sweep must count with the override ─
# The sweep discarded run_as_game_user's (out, err, rc) and cleared both flags whatever
# happened. That call does not raise on the tailscale/local transports: a timeout comes back as
# rc=-1, so a stop that never happened left the queue and nobody retried. It also counted
# players without the server's gamedig override, so a Project Zomboid/ARK server read as None
# ("unknown") on every tick and its queued restart never fired.
from panel.db.models import AuditLog as _QAL  # pylint: disable=reimported
_qa_saved = (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
             _sm_core.set_game_priority)
_qa_pc_args, _qa_rc = [], [-1]
_qa_id = None
try:
    with app.app_context():
        _rm = RemoteServer.query.first()
        _qa = _UGS(remote_id=_rm.id, name="queued-stop-rc", short_name="queuedstoprc",
                   game_type="pz", port=16261, installed=True, status="online")
        _qa.stop_pending = True
        _qa.query_type = "projectzomboid"
        db.session.add(_qa); db.session.commit()
        _qa_id = _qa.id
        _QAL.query.filter_by(target="queued-stop-rc").delete(); db.session.commit()
    _shmod.get_server_status = lambda srv, gs, distinguish_unresponsive=False: "online"

    def _qa_pc(*a, **k):
        if a[1] == "queuedstoprc":
            _qa_pc_args.append((a, k))
        return 0
    _shmod.sm_player_count = _qa_pc
    _sm_core.run_as_game_user = lambda *a, **k: (("", "SSH command timed out", _qa_rc[0])
                                                 if a[1] == "queuedstoprc" else ("", "", 0))
    _sm_core.set_game_priority = lambda *a, **k: None

    def _qa_state():
        with app.app_context():
            _g = db.session.get(_UGS, _qa_id)
            _rows = (_QAL.query.filter_by(target="queued-stop-rc", action="stop_server")
                     .order_by(_QAL.id).all())
            return bool(_g.stop_pending), [(r.success, r.detail) for r in _rows]

    _shmod._run_due_restarts(app)
    _qa_qt = [k.get("query_type", a[4] if len(a) > 4 else None) for a, k in _qa_pc_args]
    check("queued stop: the sweep counts players with the server's gamedig override",
          _qa_qt == ["projectzomboid"],
          "player_count got query_type %r — without it an overridden game reads as unknown "
          "and its queued action never fires" % (_qa_qt,))
    _qa_pend, _qa_rows = _qa_state()
    check("queued stop: a stop that timed out (rc=-1) stays queued for the next tick",
          _qa_pend is True, "stop_pending was cleared although the stop never happened")
    check("queued stop: ...and the failed attempt is audited as a failure",
          len(_qa_rows) == 1 and _qa_rows[0][0] is False and "still queued" in (_qa_rows[0][1] or ""),
          "audit rows %r" % (_qa_rows,))
    # The failure count belongs to the queued action: cancel it, and a later re-queue starts
    # from zero instead of being given up on early with the old attempts.
    _qa_count_before = _shmod._queued_action_failures.get(_qa_id)
    with app.app_context():
        db.session.get(_UGS, _qa_id).stop_pending = False
        db.session.commit()
    _shmod._run_due_restarts(app)
    _qa_count_after = _shmod._queued_action_failures.get(_qa_id)
    with app.app_context():
        db.session.get(_UGS, _qa_id).stop_pending = True
        db.session.commit()
        _QAL.query.filter_by(target="queued-stop-rc").delete(); db.session.commit()
    check("queued stop: cancelling the queue drops its failure count",
          _qa_count_before == 1 and _qa_count_after is None,
          "count %r before the cancel, %r after" % (_qa_count_before, _qa_count_after))
    # Bounded: a queued action that keeps failing is given up on, not retried for ever (a
    # restart LinuxGSM answers non-zero would otherwise bounce the server on every tick).
    _shmod._run_due_restarts(app)
    _shmod._run_due_restarts(app)
    _shmod._run_due_restarts(app)
    _qa_pend, _qa_rows = _qa_state()
    check("queued stop: ...and is given up on after %d failed attempts, saying so"
          % _shmod._QUEUED_ACTION_ATTEMPTS,
          _qa_pend is False and len(_qa_rows) == _shmod._QUEUED_ACTION_ATTEMPTS
          and "no longer queued" in (_qa_rows[-1][1] or ""),
          "pending=%r rows=%r" % (_qa_pend, _qa_rows))
    # Positive control: a stop that WORKED clears the queue at once and is audited as a success.
    with app.app_context():
        db.session.get(_UGS, _qa_id).stop_pending = True
        db.session.commit()
        _QAL.query.filter_by(target="queued-stop-rc").delete(); db.session.commit()
    _qa_rc[0] = 0
    # While the maintenance menu's Backup button is archiving the server, the queued stop
    # waits: that long action holds no flag the sweep used to read.
    from panel.core.panel_state import _action_output as _qa_ao
    _qa_ao[_qa_id] = {"action": "backup", "path": "/dev/null", "user": "queuedstoprc", "pos": 0}
    try:
        _shmod._run_due_restarts(app)
    finally:
        _qa_ao.pop(_qa_id, None)
    _qa_pend, _qa_rows = _qa_state()
    check("queued stop: ...waits while a Backup-button run is archiving the server",
          _qa_pend is True and not _qa_rows, "pending=%r rows=%r" % (_qa_pend, _qa_rows))
    _shmod._run_due_restarts(app)
    _qa_pend, _qa_rows = _qa_state()
    check("queued stop: one that exits 0 clears the queue and is audited as a success",
          _qa_pend is False and [r[0] for r in _qa_rows] == [True],
          "pending=%r rows=%r" % (_qa_pend, _qa_rows))
finally:
    (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
     _sm_core.set_game_priority) = _qa_saved
    _shmod._queued_action_failures.pop(_qa_id, None)
    with app.app_context():
        _l = db.session.get(_UGS, _qa_id) if _qa_id else None
        if _l is not None:
            db.session.delete(_l); db.session.commit()

# ── a queued restart LinuxGSM answers non-zero ran, and must not run again ─────────────────
# Every rc but 0 read as "did not happen" and the restart was retried on each tick, up to the
# attempt limit. But LinuxGSM's exit code is whatever its last log line set: a failed status
# alert after a good restart ends it at 1. The next tick finds the server online and empty —
# the very trigger — so it was restarted up to three times. Only a missing exit status (the
# transport's -1, or ssh's own 255) may be retried; a stop still retries on LinuxGSM's
# non-zero, because the next tick asks the server first and clears a stopped one.
_qr_saved = (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
             _sm_core.set_game_priority)
_qr_calls, _qr_rc, _qr_status = [], [1], ["online"]
_qr_id = None
try:
    with app.app_context():
        _rm = RemoteServer.query.first()
        _qr = _UGS(remote_id=_rm.id, name="queued-restart-rc", short_name="queuedrestartrc",
                   game_type="pz", port=16261, installed=True, status="online")
        _qr.restart_pending = True
        db.session.add(_qr); db.session.commit()
        _qr_id = _qr.id
        _QAL.query.filter_by(target="queued-restart-rc").delete(); db.session.commit()
    _shmod.get_server_status = lambda srv, gs, distinguish_unresponsive=False: _qr_status[0]
    _shmod.sm_player_count = lambda *a, **k: 0

    def _qr_run(*a, **k):
        if a[1] != "queuedrestartrc":
            return "", "", 0
        _qr_calls.append(a[2])
        return "Started queuedrestartrc\nSending Discord alert: FAIL", "", _qr_rc[0]
    _sm_core.run_as_game_user = _qr_run
    _sm_core.set_game_priority = lambda *a, **k: None

    def _qr_state():
        with app.app_context():
            _g = db.session.get(_UGS, _qr_id)
            _rows = (_QAL.query.filter(_QAL.target == "queued-restart-rc")
                     .order_by(_QAL.id).all())
            return (bool(_g.restart_pending), bool(_g.stop_pending),
                    [(r.action, r.success, r.detail) for r in _rows])

    def _qr_reset(restart=False, stop=False, rc=1):
        with app.app_context():
            _g = db.session.get(_UGS, _qr_id)
            _g.restart_pending, _g.stop_pending = restart, stop
            db.session.commit()
            _QAL.query.filter_by(target="queued-restart-rc").delete(); db.session.commit()
        _shmod._queued_action_failures.pop(_qr_id, None)
        _qr_calls[:] = []
        _qr_rc[0] = rc
        _qr_status[0] = "online"

    _shmod._run_due_restarts(app)
    _shmod._run_due_restarts(app)   # still online and empty: a retry would restart it again
    _qr_rp, _qr_sp, _qr_rows = _qr_state()
    check("queued restart: LinuxGSM exiting 1 after it ran restarts the server ONCE",
          _qr_calls == ["restart"] and _qr_rp is False,
          "calls=%r restart_pending=%r" % (_qr_calls, _qr_rp))
    check("queued restart: ...and the audit row gives the exit code and its line, unqueued",
          len(_qr_rows) == 1 and _qr_rows[0][1] is False
          and "exited 1: " in (_qr_rows[0][2] or "")
          and "no longer queued" in (_qr_rows[0][2] or "")
          and "Discord alert: FAIL" in (_qr_rows[0][2] or ""),
          "rows %r" % (_qr_rows,))
    # Positive controls: no exit status at all is still retried — the hole the retry closed.
    for _qr_code in (-1, 255):
        _qr_reset(restart=True, rc=_qr_code)
        _shmod._run_due_restarts(app)
        _qr_rp, _qr_sp, _qr_rows = _qr_state()
        check("queued restart: one with no answer (rc=%d) stays queued for the next tick" % _qr_code,
              _qr_calls == ["restart"] and _qr_rp is True
              and len(_qr_rows) == 1 and "still queued" in (_qr_rows[0][2] or ""),
              "calls=%r pending=%r rows=%r" % (_qr_calls, _qr_rp, _qr_rows))
    # A stop LinuxGSM answers non-zero stays queued without calling itself a failure, and is
    # cleared, not repeated, once the next tick sees the server stopped.
    _qr_reset(stop=True, rc=2)
    _shmod._run_due_restarts(app)
    _qr_rp, _qr_sp, _qr_rows = _qr_state()
    check("queued stop: LinuxGSM exiting 2 stays queued until the server is seen stopped",
          _qr_sp is True and len(_qr_rows) == 1
          and "exited 2" in (_qr_rows[0][2] or "") and "failed" not in (_qr_rows[0][2] or ""),
          "stop_pending=%r rows=%r" % (_qr_sp, _qr_rows))
    _qr_status[0] = "offline"
    _shmod._run_due_restarts(app)
    _qr_rp, _qr_sp, _qr_rows = _qr_state()
    check("queued stop: ...and a stopped server clears it without a second stop",
          _qr_sp is False and _qr_calls == ["stop"],
          "stop_pending=%r calls=%r" % (_qr_sp, _qr_calls))
finally:
    (_shmod.get_server_status, _shmod.sm_player_count, _sm_core.run_as_game_user,
     _sm_core.set_game_priority) = _qr_saved
    _shmod._queued_action_failures.pop(_qr_id, None)
    with app.app_context():
        _l = db.session.get(_UGS, _qr_id) if _qr_id else None
        if _l is not None:
            db.session.delete(_l); db.session.commit()
        _QAL.query.filter_by(target="queued-restart-rc").delete(); db.session.commit()

# ── an install that dies EARLY must still leave a row you can act on ──────────────────────
# Only the step-4 path wrote status="failed". Every earlier exit — a bad game type, an
# unreachable host during LinuxGSM setup, an unhandled exception — wrote the REASON and left
# the row saying "installing". The whole recovery design is keyed on status == "failed": no
# banner, so the reason it had just written was never shown; no Retry; no Remove; and /delete
# refused it outright with "still installing". The only exit was editing the database.
#
# Driven through record_install_failure, the one writer, because the closure that used to hold
# this is unreachable from a test and re-implementing it here would pass with the fix deleted.
from panel.routes.manage_servers import record_install_failure as _rif


class _FakeRow(object):
    pass


_fr = _FakeRow(); _fr.installed, _fr.status = True, "installing"
_fr_reason = _rif(_fr, "LinuxGSM setup failed", "ssh: connect to host timed out")
check("early install failure: the row is marked failed, not left saying 'installing'",
      _fr.status == "failed", "status=%r" % _fr.status)
check("early install failure: ...and no longer claims to be installed",
      _fr.installed is False, "installed=%r" % _fr.installed)
check("early install failure: ...and carries the reason and the retry verdict",
      "timed out" in _fr.install_error and _fr.install_retryable is True,
      "%r / %r" % (_fr.install_error, _fr.install_retryable))
_fr2 = _FakeRow(); _fr2.installed, _fr2.status = True, "installing"
_rif(_fr2, "The whole explanation.", "a noisy tool tail", retryable=False, explained=True)
check("early install failure: an explained reason does not get the tool's tail appended",
      _fr2.install_error == "The whole explanation." and _fr2.install_retryable is False,
      _fr2.install_error)

# ...and the row is removable. A panel restart mid-install strands one of these every time:
# the worker thread dies with the process while the row keeps saying installing, and there is
# no cancel route. /delete used to refuse on the STATUS COLUMN, so that row was undeletable.
_u_orig2 = _sm_core.run_privileged
try:
    _sm_core.run_privileged = lambda *a, **k: ("", "", 0)
    with app.app_context():
        _rm = RemoteServer.query.first()
        _st = _UGS(remote_id=_rm.id, name="stranded", short_name="stranded",
                   game_type="gmod", port=28950, installed=False, status="installing")
        db.session.add(_st); db.session.commit()
        _st_id = _st.id
    _sresp = c.post("/servers/%d/delete" % _st_id, json={},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    with app.app_context():
        _st_left = _UGS.query.get(_st_id) is not None
    check("stranded install: a row stuck at 'installing' with no live job CAN be removed",
          not _st_left,
          "still there — %r" % ((_sresp.get_json() or {}).get("message"),))
    with app.app_context():
        _l = _UGS.query.get(_st_id)
        if _l: db.session.delete(_l); db.session.commit()
finally:
    _sm_core.run_privileged = _u_orig2

# Liveness probe: unauthenticated, returns 200 + {"status":"ok"}, works pre-login.
hz = app.test_client().get("/healthz")
check("GET /healthz -> 200 ok (unauthenticated)",
      hz.status_code == 200 and (hz.get_json() or {}).get("status") == "ok",
      "got %d" % hz.status_code)

# The login page (unauthenticated) offers a language switcher so the UI language can be
# changed before signing in — set-language works pre-login (session-scoped).
lg = app.test_client().get("/login")
check("GET /login renders with a language switcher",
      lg.status_code == 200 and b"/set-language/" in lg.data and b"bi-translate" in lg.data,
      "got %d" % lg.status_code)

# Panel self-update live-log endpoint renders (no update running -> exists:false).
ul = c.get("/api/panel/update-log")
check("GET /api/panel/update-log -> 200 (superadmin)",
      ul.status_code == 200 and "lines" in (ul.get_json() or {}), "got %d" % ul.status_code)
# ...and it says how a finished run ENDED, and which process answered. An update that stops
# before the panel restarts never flips boot_id, so the card reads this to stop spinning — only
# while the boot_id here is still the one it started with. A throwaway log, never data/'s.
import panel.ops.system_ops as _ul_so
from panel.routes import host_local as _ul_hl
_ul_dir = _lgsm_tempfile.mkdtemp(prefix="smoke-updlog-")
_ul_path = os.path.join(_ul_dir, "self-update.log")
with open(_ul_path, "w", encoding="utf-8") as _ul_fh:
    _ul_fh.write("=== panel self-update ===\n\033[0;31m[ERROR]\033[0m Couldn't reach the update "
                 "source (offline, or a private repo without credentials).\n     Nothing was "
                 "changed.\n=== installer exit 1 ===\n")
_ul_saved = _ul_so._update_log_path
try:
    _ul_so._update_log_path = lambda: _ul_path
    _ulj = c.get("/api/panel/update-log").get_json() or {}
    # The report's Updates section, which reads the run's outcome (debug_report/updates.py).
    from panel.ops.debug_report import updates as _ul_upd
    from panel.ops.debug_report._base import Ctx as _UlCtx

    def _ul_gdr():
        return {"report": "\n".join(_ul_upd.section_updates(_UlCtx(app=app)).lines)}
    with app.app_context():
        _ul_rep = _ul_gdr()["report"]
    # ...and a hold (exit 0, install.sh's "Not updated" line), which is not "unknown" either.
    with open(_ul_path, "w", encoding="utf-8") as _ul_fh:
        _ul_fh.write("=== panel self-update ===\n\033[1;33m[!]\033[0m Not updated: held at "
                     "0123456789, because the pinned commit could not be verified on main. The "
                     "panel was left running.\n=== installer exit 0 ===\n")
    with app.app_context():
        _ul_rep_held = _ul_gdr()["report"]
    # ...an up-to-date run (exit 0 on install.sh's "Already up to date"), and a stop and a hold
    # whose text looks secret: the outcome line is log text, redacted like the tail under it.
    _ul_reps = {}
    for _ul_k, _ul_body in (
            ("current", "\033[0;32m✓\033[0m Already up to date (version 9.9.9) — no snapshot "
                        "taken, panel left running.\n=== installer exit 0 ===\n"),
            ("failed", "\033[0;31m[ERROR]\033[0m Couldn't fetch as ops@example.com with "
                       "token=s3cr3tvalue123.\n=== installer exit 1 ===\n"),
            ("held", "\033[1;33m[!]\033[0m Not updated: held at 0123456789, because "
                     "ops@example.com set token=s3cr3tvalue123. The panel was left running.\n"
                     "=== installer exit 0 ===\n")):
        with open(_ul_path, "w", encoding="utf-8") as _ul_fh:
            _ul_fh.write("=== panel self-update ===\n" + _ul_body)
        with app.app_context():
            _ul_reps[_ul_k] = _ul_gdr()["report"]
finally:
    _ul_so._update_log_path = _ul_saved
    import shutil as _ul_sh
    _ul_sh.rmtree(_ul_dir, ignore_errors=True)
check("GET /api/panel/update-log: a run that stopped early reads as failed, with its reason and "
      "the answering process's boot_id",
      _ulj.get("finished") is True and _ulj.get("outcome") == "failed" and _ulj.get("exit_code") == 1
      and _ulj.get("reason") == ("Couldn't reach the update source (offline, or a private repo "
                                 "without credentials). Nothing was changed.")
      and _ulj.get("boot_id") == _ul_hl._BOOT_ID,
      repr({k: _ulj.get(k) for k in ("finished", "outcome", "exit_code", "reason", "boot_id")}))
check("debug report: a self-update that stopped before the panel restarted is reported as FAILED "
      "with its reason, not 'unknown (in progress…)'",
      "- **Outcome**: FAILED — the installer stopped (exit 1): Couldn't reach the update source" in _ul_rep,
      _ul_rep[_ul_rep.find("- **Outcome**"):][:300])
check("debug report: ...an up-to-date run as nothing to install, not 'unknown (in progress…)'",
      "- **Outcome**: nothing to install — Already up to date (version 9.9.9)"
      in _ul_reps.get("current", ""),
      _ul_reps.get("current", "")[_ul_reps.get("current", "").find("- **Outcome**"):][:300])
check("debug report: ...and the reason in a stop's or a hold's outcome is redacted like the log",
      all("s3cr3tvalue123" not in _ul_reps.get(_k, "s3cr3tvalue123")
          and "ops@example.com" not in _ul_reps.get(_k, "ops@example.com") for _k in ("failed", "held"))
      and "- **Outcome**: FAILED — the installer stopped (exit 1): Couldn't fetch as [email] with "
          "token=[redacted]" in _ul_reps.get("failed", "")
      and "- **Outcome**: NOT UPDATED — Not updated: held at 0123456789, because [email] set "
          "token=[redacted]" in _ul_reps.get("held", ""),
      repr({_k: _v[_v.find("- **Outcome**"):][:160] for _k, _v in _ul_reps.items()}))
check("debug report: ...and a hold as NOT UPDATED, with install.sh's reason",
      "- **Outcome**: NOT UPDATED — Not updated: held at 0123456789, because the pinned commit "
      "could not be verified on main." in _ul_rep_held,
      _ul_rep_held[_ul_rep_held.find("- **Outcome**"):][:300])

# change-port validation: out-of-range ports are refused BEFORE any save/restart, so
# these are side-effect-free. (A valid port would restart the panel — not exercised here.)
cp1 = c.post("/api/panel/change-port", json={"port": 80})
check("change-port refuses a privileged port (<1024)",
      cp1.status_code == 400 and not (cp1.get_json() or {}).get("success"))
cp2 = c.post("/api/panel/change-port", json={"port": 99999})
check("change-port refuses an out-of-range port (>65535)",
      cp2.status_code == 400 and not (cp2.get_json() or {}).get("success"))
# Bind-address validation: a non-IP is rejected by ipaddress parsing before any save or
# restart, so this is env-independent and side-effect-free.
cp3 = c.post("/api/panel/change-port", json={"port": 5000, "bind_host": "not-an-ip"})
check("change-port refuses a non-IP bind address",
      cp3.status_code == 400 and not (cp3.get_json() or {}).get("success"))
# ...and a port a game server on the panel's own host already holds, by the server's name.
# Deleting that clash check (in _port_refusal since api_panel_change_port was split) left
# every suite green — only the range and bind refusals above were driven — and the panel then
# saves and restarts onto the game's port. port_in_use is stubbed so the clash is the only thing
# that can refuse, and restart_panel so a regression cannot restart anything.
import panel.routes.remote_security as _cp_rs
with app.app_context():
    _cp_local = RemoteServer.query.filter_by(is_local=True).first()
    _cp_made = _cp_local is None
    if _cp_made:
        _cp_local = RemoteServer(name="smoke-cp-local", host="127.0.0.1", port=22,
                                 username="panel", auth_method="local", auth_credential="",
                                 is_local=True)
        db.session.add(_cp_local)
        db.session.flush()
    _cp_gs = GameServer(remote_id=_cp_local.id, name="cp-clash", short_name="cpclash",
                        game_type="csgo", port=5099, installed=True, status="offline")
    db.session.add(_cp_gs)
    db.session.commit()
    _cp_ids = (_cp_local.id, _cp_gs.id)
_cp_saved = (_cp_rs.so.port_in_use, _cp_rs.so.restart_panel)
try:
    _cp_rs.so.port_in_use = lambda _p: False
    _cp_rs.so.restart_panel = lambda: (False, "stubbed by smoke_test")
    cp4 = c.post("/api/panel/change-port", json={"port": 5099})
finally:
    _cp_rs.so.port_in_use, _cp_rs.so.restart_panel = _cp_saved
    with app.app_context():
        db.session.delete(db.session.get(GameServer, _cp_ids[1]))
        if _cp_made:
            db.session.delete(db.session.get(RemoteServer, _cp_ids[0]))
        db.session.commit()
check("change-port refuses a port a game server on the panel's host already uses",
      cp4.status_code == 400
      and "is used by game server 'cp-clash'" in ((cp4.get_json() or {}).get("message") or ""),
      str(cp4.get_json())[:160])

# ── Backups: list + settings + name validation (no real backup/restart triggered) ──
bl = c.get("/api/panel/backups")
_blj = bl.get_json() or {}
check("backups: list endpoint returns backups + settings",
      bl.status_code == 200 and "settings" in _blj and "backups" in _blj)
check("backups: response includes full-backup settings + per-server games",
      "full" in _blj and "games" in _blj)
bset = c.post("/api/panel/backup/settings", json={"enabled": True, "keep_days": 7,
                                                  "full_interval_days": 7, "full_keep": 2})
check("backups: settings save round-trips keep_days + full settings",
      (bset.get_json() or {}).get("settings", {}).get("keep_days") == 7
      and (bset.get_json() or {}).get("full", {}).get("interval_days") == 7)
# Retention is TYPED in the UI now rather than picked from a list, which changes two things the
# API has to hold up: the browser needs the server's own bounds (it cannot invent them and stay
# in step), and an out-of-range number has to come back CLAMPED in the response so the page can
# show what was really stored instead of echoing what was typed.
check("backups: the response carries the retention bounds the UI enforces",
      isinstance(_blj.get("limits"), dict)
      and _blj["limits"].get("full_keep", {}).get("max") == bk.MAX_FULL_KEEP
      and _blj["limits"].get("keep_days", {}).get("max") == bk.MAX_KEEP_DAYS,
      str(_blj.get("limits"))[:80])
_over = c.post("/api/panel/backup/settings",
               json={"enabled": True, "keep_days": 99999, "full_interval_days": 7,
                     "full_keep": 999}).get_json() or {}
check("backups: an out-of-range keep comes back clamped, not echoed",
      _over.get("settings", {}).get("keep_days") == bk.MAX_KEEP_DAYS
      and _over.get("full", {}).get("keep") == bk.MAX_FULL_KEEP,
      "%s / %s" % (_over.get("settings"), _over.get("full")))
c.post("/api/panel/backup/settings", json={"enabled": True, "keep_days": 7,
                                           "full_interval_days": 7, "full_keep": 2})

# A per-server override is set by typing a number and CLEARED by emptying the box. A <select>
# could carry a labelled "Default" option; a number input says it by being empty, so "" has to
# mean the same thing to the endpoint as the old "default" did.
_sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
              json={"interval": "default", "keep": "5"}).get_json() or {}
check("backups: a typed per-server keep sets an override",
      _sch.get("schedule", {}).get("keep") == 5 and _sch["schedule"].get("keep_set") is True,
      str(_sch.get("schedule")))
_sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
              json={"interval": "default", "keep": "999"}).get_json() or {}
check("backups: a per-server keep over the maximum is clamped",
      _sch.get("schedule", {}).get("keep") == bk.MAX_FULL_KEEP, str(_sch.get("schedule")))
_sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
              json={"interval": "default", "keep": ""}).get_json() or {}
check("backups: an EMPTY per-server keep clears the override (inherits the default)",
      _sch.get("schedule", {}).get("keep_set") is False, str(_sch.get("schedule")))
# A field LEFT OUT is left alone. Both pages posted both fields on a change to either, and
# Files & Config's keep <select> has no option for 14, so it read '' and an interval change
# cleared the keep override: the next backup pruned to the global 2 and deleted 12 archives.
c.post("/api/panel/backup/game/%d/schedule" % gs_id, json={"interval": "7", "keep": "14"})
_sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
              json={"interval": "1"}).get_json() or {}
check("backups: changing only the interval leaves the keep override where it was",
      _sch.get("schedule", {}).get("keep") == 14 and _sch["schedule"].get("keep_set") is True
      and _sch["schedule"].get("interval_days") == 1,
      str(_sch.get("schedule")))
_sch = c.post("/api/panel/backup/game/%d/schedule" % gs_id,
              json={"keep": "4"}).get_json() or {}
check("backups: ...and changing only keep leaves the interval override (both directions)",
      _sch.get("schedule", {}).get("interval_days") == 1
      and _sch["schedule"].get("interval_set") is True and _sch["schedule"].get("keep") == 4,
      str(_sch.get("schedule")))
c.post("/api/panel/backup/game/%d/schedule" % gs_id, json={"interval": "", "keep": ""})

bdel = c.post("/api/panel/backup/delete", json={"name": "../../etc/passwd"})
check("backups: delete rejects a traversal name", not (bdel.get_json() or {}).get("success"))
bres = c.post("/api/panel/backup/restore", json={"name": "nope.tar.gz"})
check("backups: restore rejects an invalid name", not (bres.get_json() or {}).get("success"))
check("backups: download 404s on a bad name", c.get("/api/panel/backup/download/..%2f..%2fetc%2fpasswd").status_code in (400, 404))

# ── Privilege-escalation guards: a delegated admin (MANAGE_USERS + MANAGE_GROUPS,
#    NOT superadmin) must not be able to become / create a superadmin. ──
dc = client_as(deleg_id)
dc.post("/users/add", data={"username": "esc_user", "password": "Str0ng!passw0rd",
                            "is_superadmin": "on"})
with app.app_context():
    eu = User.query.filter_by(username="esc_user").first()
    check("MANAGE_USERS user can't create a superadmin", eu is None or not eu.is_superadmin)
# reset_password=on is the real reset path now (the password is generated, never posted), so
# this has to drive THAT to still be testing the superadmin guard rather than an ignored field.
dc.post("/users/%d/edit" % admin2_id,
        data={"is_superadmin": "on", "is_active": "on", "reset_password": "on"})
with app.app_context():
    a2 = User.query.get(admin2_id)
    check("MANAGE_USERS user can't reset a superadmin's password",
          a2.is_superadmin and auth.check_password("Str0ng!passw0rd", a2.password_hash))
dc.post("/groups/add", data={"name": "esc_group", "permissions": ["super_admin", "manage_users"]})
with app.app_context():
    eg = Group.query.filter_by(name="esc_group").first()
    check("MANAGE_GROUPS user can't grant super_admin to a group",
          eg is not None and "super_admin" not in eg.get_permissions())

# ── Aikido 745379084: a name an admin types cannot carry terminal controls ───────────────
# The recovery CLI (`sudo linuxgsm-panel-recover`, manage.py) prints stored usernames and
# group names to the operator's terminal. username_problem refused only whitespace, and group
# names had no format check at all, so a delegate with MANAGE_USERS or MANAGE_GROUPS could store
# ESC sequences (cursor moves, erase-line, OSC 52 clipboard writes) and a newline (a forged row).
import panel.core.validation as _valmod
_unp = _valmod.username_problem
_gnp = getattr(_valmod, "group_name_problem", lambda _n: None)   # absent before the fix
for _nm in ("a\x1bb", "a\u202eb", "a\x9bb", "a\x07b", "ab\u200bc", "a\x00b"):
    check("username: %r (a control or format character) is refused" % _nm,
          _unp(_nm) is not None, "accepted")
for _nm in ("José", "dan_the-man.2", "Łukasz", "用户名"):
    check("username: %r is still accepted (control)" % _nm, _unp(_nm) is None, _unp(_nm))
for _nm in ("a\nb", "a\x1bb", "a\tb", "a\u2028b", "a\u202eb", "", "x" * 81):
    check("group name: %r is refused" % _nm, _gnp(_nm) is not None, "accepted")
check("group name: an ordinary name with spaces is still accepted (control)",
      _gnp("Game Admins") is None, _gnp("Game Admins"))
_xhr = {"X-Requested-With": "XMLHttpRequest"}
_inj_user = "\x1b[1A\x1b[2K\x1b]52;c;ZWNobyBoaQ==\x07zz"
_iu = dc.post("/users/add", data={"username": _inj_user, "display_name": "x"}, headers=_xhr)
with app.app_context():
    check("users/add: a delegate cannot store a username carrying ESC sequences",
          User.query.filter_by(username=_inj_user).first() is None and _iu.status_code == 400,
          "status=%d" % _iu.status_code)
for _gn in ("ops\nforged", "ops\x1b[2Kteam"):
    _ig = dc.post("/groups/add", data={"name": _gn}, headers=_xhr)
    with app.app_context():
        check("groups/add: a delegate cannot store the group name %r" % _gn,
              Group.query.filter_by(name=_gn).first() is None and _ig.status_code == 400,
              "status=%d" % _ig.status_code)
with app.app_context():
    _eg_id = Group.query.filter_by(name="esc_group").first().id
_ie = dc.post("/groups/%d/edit" % _eg_id, data={"name": "esc\x1b]52;c;eA==\x07"}, headers=_xhr)
with app.app_context():
    check("groups/edit: ...nor rename one to it",
          db.session.get(Group, _eg_id).name == "esc_group" and _ie.status_code == 400,
          "status=%d name=%r" % (_ie.status_code, db.session.get(Group, _eg_id).name))
_ok_g = dc.post("/groups/add", data={"name": "Esc Ops Team"}, headers=_xhr)
with app.app_context():
    _okg = Group.query.filter_by(name="Esc Ops Team").first()
    check("groups/add: an ordinary name with a space is still created (control)",
          _okg is not None, "status=%d" % _ok_g.status_code)
    if _okg is not None:
        db.session.delete(_okg)
        db.session.commit()

# ── Group create via the real route WITH a host selected. This is the exact
#    regression that 500'd: the route assigned GameServer objects to
#    Group.servers, which is a RemoteServer collection. ──
import secrets as _secrets
gtag = "smokegrp_" + _secrets.token_hex(3)
r = c.post("/groups/add", data={"name": gtag,
                                "permissions": auth.VIEW_SERVERS,
                                "servers": str(remote_id)})
check("POST /groups/add with a host selected -> not 5xx", r.status_code < 500,
      "got %d" % r.status_code)
with app.app_context():
    g = Group.query.filter_by(name=gtag).first()
    gid = g.id if g else None
    check("add_group persisted host access",
          g is not None and any(rs.id == remote_id for rs in g.servers))

# ── Group edit, including deliberately malformed/unknown server ids: must
#    not 5xx and must keep only the valid host. ──
if gid:
    r = c.post("/groups/%d/edit" % gid,
               data={"name": gtag, "permissions": auth.VIEW_SERVERS,
                     "servers": ["not-a-number", "999999", str(remote_id)]})
    check("POST /groups/<id>/edit tolerates bad ids -> not 5xx",
          r.status_code < 500, "got %d" % r.status_code)
    with app.app_context():
        g = Group.query.get(gid)
        check("edit_group kept only the valid host",
              g is not None and [rs.id for rs in g.servers] == [remote_id])
    # ...and ids no row can have: 5,000 digits (int() refuses past 4,300) and 2**64 (SQLite's
    # driver refuses past 2**63-1) each answered a 500 from both routes.
    for _hid in ("9" * 5000, str(2 ** 64)):
        r = c.post("/groups/%d/edit" % gid,
                   data={"name": gtag, "permissions": auth.VIEW_SERVERS,
                         "servers": [_hid, str(remote_id)], "game_servers": [_hid]})
        check("POST /groups/<id>/edit with an id of %d digits -> not 5xx" % len(_hid),
              r.status_code < 500, "got %d" % r.status_code)
        r = c.post("/groups/add", data={"name": gtag + "_h%d" % len(_hid),
                                        "servers": [_hid], "game_servers": [_hid]})
        check("POST /groups/add with an id of %d digits -> not 5xx" % len(_hid),
              r.status_code < 500, "got %d" % r.status_code)
    with app.app_context():
        g = Group.query.get(gid)
        check("edit_group with oversized ids still kept the valid host",
              g is not None and [rs.id for rs in g.servers] == [remote_id])
        for _hg in Group.query.filter(Group.name.like(gtag + "_h%")).all():
            db.session.delete(_hg)
        db.session.commit()

# ── A non-numeric port must not 5xx the settings/remote forms ──
r = c.post("/remotes/%d/edit" % remote_id,
           data={"name": "smoke-host", "host": "127.0.0.1", "ssh_port": "abc",
                 "ssh_user": "root", "auth_method": "key"})
check("POST /remotes/<id>/edit with non-numeric port -> not 5xx",
      r.status_code < 500, "got %d" % r.status_code)


# ── Editing a host must drop its pooled SSH client ────────────────────────────────────────
# A pooled client is valid only while the row it was opened from still names the same host and
# the same credential. edit_remote rewrote username/host/port/auth_method/auth_credential and
# committed without closing anything, so: a ROTATED CREDENTIAL kept authenticating with the old
# one for as long as the 30s keepalive held the socket open, and a REPOINTED host orphaned its
# cache entry for the life of the process (close_connection builds the key from the row's
# CURRENT values, so the old key was no longer spellable). Asserted through the real route, not
# the listener, because the route is what regressed.
class _FakePooled:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _pool_one(rid):
    """Put a fake client in the pool under the key that host currently spells."""
    with app.app_context():
        _r = db.session.get(RemoteServer, rid)
        _k = _sm_core._conn_key(_r.username, _r.host, _r.port)
    _c = _FakePooled()
    _sm_core._connections[_k] = _c
    _sm_core._remote_conn_keys[rid] = _k
    return _k, _c


_ek, _ec = _pool_one(remote2_id)
c.post("/remotes/%d/edit" % remote2_id,
       data={"name": "smoke-host-2", "host": "127.0.0.1", "ssh_port": "22",
             "ssh_user": "root", "auth_method": "password", "credential": "rotated-secret"})
check("edit_remote: rotating the credential closes the pooled SSH client", _ec.closed)
check("edit_remote: ...and drops it from the pool", _ek not in _sm_core._connections)

_ek2, _ec2 = _pool_one(remote2_id)
c.post("/remotes/%d/edit" % remote2_id,
       data={"name": "smoke-host-2", "host": "127.0.0.2", "ssh_port": "22",
             "ssh_user": "root", "auth_method": "password"})
check("edit_remote: repointing the host closes the client opened under the OLD key", _ec2.closed)
check("edit_remote: ...leaving no entry under a key nothing can name again",
      _ek2 not in _sm_core._connections)

_ek3, _ec3 = _pool_one(remote2_id)
c.post("/remotes/%d/edit" % remote2_id,
       data={"name": "renamed-only", "host": "127.0.0.2", "ssh_port": "22",
             "ssh_user": "root", "auth_method": "password"})
check("edit_remote: a rename alone does NOT churn the pool",
      not _ec3.closed and _ek3 in _sm_core._connections)
_sm_core._connections.pop(_ek3, None)
_sm_core._remote_conn_keys.pop(remote2_id, None)

# ── Remote management is scoped per host: a MANAGE_REMOTES user can reach the
#    remote their group grants, but a NON-granted remote id returns 403 (no
#    remote-level IDOR). The 403 is enforced in get_remote before any SSH. ──
mrc = client_as(mru_id)
check("MANAGE_REMOTES user: /remotes renders (200)",
      mrc.get("/remotes").status_code == 200)
# ...and the sidebar, on every page, lists only the hosts their groups grant. It listed every
# remote's name and id to anyone holding the permission, undoing the per-host scoping above.
_nav_html = mrc.get("/account").get_data(as_text=True)
check("sidebar: (control) a host admin's sidebar links the host they are granted",
      ("/remote/%d/manage" % remote_id) in _nav_html, "no granted-host link — the check below is vacuous")
check("sidebar: ...and does not name a host they are not granted",
      ("/remote/%d/manage" % remote2_id) not in _nav_html and "smoke-host-2" not in _nav_html,
      "the Infrastructure sidebar lists an ungranted host")
# manage_remotes.html carries no is_local branch any more — six of them tested a flag that is
# False for every row this route can hand it, including a "This Machine" badge and a "Runs
# locally on this server" line no visitor was ever shown. That is only true while the route
# keeps filtering, so the filter is pinned here rather than left as a comment: the panel's own
# host is managed under System -> Panel Server, and listing it here would offer Test, Tailscale
# and Prepare against the machine the panel is running on.
# Seeded HERE and removed again, not added to the fixture: an is_local host changes the host
# card count, the per-host groups and the dashboard's own tables, and this is the only check
# that needs one.
with app.app_context():
    _lh = RemoteServer(name="smoke-localhost", host="127.0.0.1", port=22,
                       username="root", auth_method="key", is_local=True)
    db.session.add(_lh)
    db.session.commit()
    _lh_id = _lh.id
_rl = c.get("/remotes")
_rlh = _rl.get_data(as_text=True)
check("remotes: the page still renders with a local host in the table",
      _rl.status_code == 200 and "smoke-host" in _rlh,
      "status=%d — an empty body would pass the next check vacuously" % _rl.status_code)
check("remotes: ...and it is not listed",
      "smoke-localhost" not in _rlh and ("/remote/%d/manage" % _lh_id) not in _rlh,
      "the local host is on a page whose template no longer has a branch for it")
with app.app_context():
    db.session.delete(db.session.get(RemoteServer, _lh_id))
    db.session.commit()

# ── the Edit form must not offer a transport this panel cannot run ───────────────────────
# The Add form gates "Tailscale SSH" behind tailscale_installed; the per-remote Edit form
# offered it unconditionally. edit_remote accepts the value and answers "Remote '…' updated."
# — and every later command for that host then goes through `ssh 100.x.y.z`, which without
# tailscaled returns ("", …, -1) WITHOUT raising, so the firewall page, the backups card and
# ufw status read the host as reachable-but-empty rather than unreachable.
import panel.routes.remotes as _ts_mod
_ts_save = _ts_mod.ts


class _FakeTsInfo:
    def __init__(self, installed):
        self.installed = installed


class _FakeTs:
    def __init__(self, installed):
        self._installed = installed

    def get_tailscale_info(self):
        return _FakeTsInfo(self._installed)


with app.app_context():
    _tsr_was = db.session.get(RemoteServer, remote2_id).auth_method
try:
    _ts_mod.ts = _FakeTs(False)
    _rno = c.get("/remotes").get_data(as_text=True)
    check("remotes: the page renders with Tailscale absent",
          "smoke-host" in _rno,
          "an empty body would pass the next check having rendered nothing")
    check("remotes: no form offers Tailscale SSH when the panel has no Tailscale",
          _rno.count('value="tailscale"') == 0,
          "%d tailscale options on a host with no tailscaled" % _rno.count('value="tailscale"'))
    # A remote ALREADY on that transport keeps the option: hiding it there makes the select
    # submit "key" on the next save and silently repoints a working host.
    with app.app_context():
        _tsr = db.session.get(RemoteServer, remote2_id)
        _tsr.auth_method = "tailscale"
        db.session.commit()
    _rno2 = c.get("/remotes").get_data(as_text=True)
    check("remotes: ...but a remote already on Tailscale SSH keeps its own option",
          _rno2.count('value="tailscale"') == 1 and 'value="tailscale" selected' in _rno2,
          "%d options, selected=%s" % (_rno2.count('value="tailscale"'),
                                       'value="tailscale" selected' in _rno2))
    with app.app_context():
        _tsr = db.session.get(RemoteServer, remote2_id)
        _tsr.auth_method = _tsr_was
        db.session.commit()
    # POSITIVE CONTROL: with Tailscale installed the option is back on every form — the gate
    # is the panel's tailscaled, not a transport that was removed from the UI.
    _ts_mod.ts = _FakeTs(True)
    _rny = c.get("/remotes").get_data(as_text=True)
    check("remotes: ...and every form offers it again once Tailscale is installed",
          _rny.count('value="tailscale"') >= 2,
          "%d tailscale options" % _rny.count('value="tailscale"'))
finally:
    _ts_mod.ts = _ts_save
    with app.app_context():
        _tsr = db.session.get(RemoteServer, remote2_id)
        if _tsr is not None and _tsr.auth_method != _tsr_was:
            _tsr.auth_method = _tsr_was
            db.session.commit()

check("MANAGE_REMOTES user: non-granted remote -> 403",
      mrc.get("/api/remote/%d/firewall" % remote2_id).status_code == 403)
check("MANAGE_REMOTES user: non-granted remote reboot -> 403",
      mrc.post("/api/remote/%d/reboot" % remote2_id).status_code == 403)

# ── the host page offers a host operator only what their rights can do ──────────────────
# remote_manage needs MANAGE_REMOTES alone. It offered this operator the game table's
# Uninstall (a typed-name confirm, then refused) and Files & Config, the install-wide threshold
# Save and whitelist Add/× (the endpoints ignore or 403 them, and the page said "saved" /
# "removed"), and top-ips handed them the whole install's whitelist.
import panel.routes.remote_security as _hp_rs  # pylint: disable=reimported
_hp_saved = (_hp_rs.remote_fail2ban_top_ips, _hp_rs.remote_security_log)
_hp_lid = None
try:
    _hp_rs.remote_fail2ban_top_ips = lambda *a, **k: []
    _hp_rem = mrc.get("/remote/%d/manage" % remote_id).get_data(as_text=True)
    _hp_adm = c.get("/remote/%d/manage" % remote_id).get_data(as_text=True)
    _hp_files = "/server/%d/files" % gs_id
    check("host page: a MANAGE_REMOTES-only operator is not offered Uninstall or Files & Config",
          "smoke-cs" in _hp_rem and "uninstall-form" not in _hp_rem and _hp_files not in _hp_rem,
          "the game row offers controls whose routes refuse this user")
    check("host page: ...while a superadmin still is (positive control)",
          "uninstall-form" in _hp_adm and _hp_files in _hp_adm, "the gate hides them from everyone")
    check("host page: the install-wide threshold Save and whitelist Add are superadmin-only",
          'data-action="saveThreshold"' not in _hp_rem and 'data-action="addWhitelist"' not in _hp_rem
          and 'id="sec-wl-readonly"' in _hp_rem, "an operator is offered writes that are refused")
    check("host page: ...and a superadmin keeps them (positive control)",
          'data-action="saveThreshold"' in _hp_adm and 'data-action="addWhitelist"' in _hp_adm,
          "the superadmin lost the threshold/whitelist controls")
    _hp_ti = mrc.get("/api/remote/%d/security/top-ips" % remote_id).get_json(silent=True) or {}
    _hp_ta = c.get("/api/remote/%d/security/top-ips" % remote_id).get_json(silent=True) or {}
    check("top-ips: a host operator is not sent the install-wide whitelist",
          "whitelist" not in _hp_ti and "autoblock" in _hp_ti, repr(_hp_ti)[:200])
    check("top-ips: ...a superadmin is (positive control)", "whitelist" in _hp_ta, repr(_hp_ta)[:200])
    # An unanswered log read is not an empty log.
    _hp_rs.remote_security_log = lambda *a, **k: None
    _hp_lg = c.get("/api/remote/%d/security/log?which=ssh" % remote_id).get_json(silent=True) or {}
    check("security log: a read no host answered comes back as an error, not empty text",
          _hp_lg.get("error") and _hp_lg.get("text") == "", repr(_hp_lg))
    _hp_rs.remote_security_log = lambda *a, **k: ""
    _hp_lg = c.get("/api/remote/%d/security/log?which=ssh" % remote_id).get_json(silent=True) or {}
    check("security log: ...while an answered empty log is still just empty (positive control)",
          "error" not in _hp_lg and _hp_lg.get("text") == "", repr(_hp_lg))
    # The PANEL HOST's page, granted to the same operator (Groups offers it as a checkbox). Its
    # Security endpoints are all superadmin-only, and its Connection card's else-branch spoke
    # of an SSH login, a Migrate button and a pinned host key the panel host does not have.
    with app.app_context():
        _hp_l = RemoteServer(name="smoke-hp-local", host="127.0.0.1", port=22, username="local",
                             auth_method="local", auth_credential="", is_local=True)
        db.session.add(_hp_l)
        db.session.flush()
        _hp_g = Group.query.filter_by(name="smoke_mr").first()   # held: a chained append
        _hp_g.servers.append(_hp_l)                              # loses it to the GC
        db.session.commit()
        _hp_lid = _hp_l.id
    _hp_loc = mrc.get("/remote/%d/manage" % _hp_lid).get_data(as_text=True)
    # Nor the Connection & SSH card (its public-SSH and SSH-port rows): ssh-status, ssh-mode and
    # ssh-port all go through get_host_remote, so on the panel host they 403 this operator too.
    check("panel host page: a non-superadmin is not shown the Security tab its endpoints refuse",
          'id="ssh-port-input"' not in _hp_loc and 'id="conn-ssh-card"' not in _hp_loc
          and 'data-mtab-btn="security"' not in _hp_loc
          and 'id="sec-bans"' not in _hp_loc, "the tab renders 403s as an all-clear")
    check("panel host page: ...nor an SSH login, Migrate button or host key it does not have",
          "Migrate to Tailscale SSH" not in _hp_loc and "Panel connects via" not in _hp_loc
          and "Pinned SSH host key" not in _hp_loc, "remote-only copy on the panel host")
    # Migrate is superadmin-only (the route refuses everyone else), so on a remote the operator
    # is told who can, and the superadmin's page has the button.
    check("host page: ...while a REMOTE's page keeps all of them (positive control)",
          'data-mtab-btn="security"' in _hp_rem and 'id="ssh-port-input"' in _hp_rem
          and "A superadmin can switch the panel" in _hp_rem
          and "Migrate to Tailscale SSH" in _hp_adm
          and "Pinned SSH host key" in _hp_rem, "the gate hides them on every host")
    # A block or unban on the PANEL host through its row id is followed in the panel's own ban
    # gate at once, as host_local's twins are; on a remote there is nothing of the panel's to
    # refresh. Before, the gate kept serving a just-blocked address until its 90 s tick.
    _hp_refresh = []
    _hp_rs_saved = (_hp_rs.remote_ufw_deny_ip, _hp_rs.remote_fail2ban_unban,
                    _hp_rs.tailnet_exempt_ips, _smoke_banlist.refresh_soon)
    try:
        _hp_rs.remote_ufw_deny_ip = lambda _r, _ip: (True, "blocked")
        _hp_rs.remote_fail2ban_unban = lambda _r, _j, _ip: (True, "unbanned")
        _hp_rs.tailnet_exempt_ips = lambda _r, _ips: set()
        _smoke_banlist.refresh_soon = lambda *a, **k: _hp_refresh.append(a)
        c.post("/api/remote/%d/security/block" % _hp_lid, json={"ip": "203.0.113.77"})
        c.post("/api/remote/%d/security/unban" % _hp_lid,
               json={"jail": "sshd", "ip": "203.0.113.77"})
        _hp_refresh_local = len(_hp_refresh)
        c.post("/api/remote/%d/security/block" % remote_id, json={"ip": "203.0.113.78"})
    finally:
        (_hp_rs.remote_ufw_deny_ip, _hp_rs.remote_fail2ban_unban,
         _hp_rs.tailnet_exempt_ips, _smoke_banlist.refresh_soon) = _hp_rs_saved
    check("panel host security: block and unban refresh the panel's own ban gate at once",
          _hp_refresh_local == 2, "refreshes=%r" % (_hp_refresh,))
    check("panel host security: ...a block on a remote does not (it is not the panel's gate)",
          len(_hp_refresh) == 2, "refreshes=%r" % (_hp_refresh,))
    # The panel host's firewall is superadmin-only (get_host_remote) — the two game-port
    # writes were still open to a delegated MANAGE_REMOTES admin whose group covered it.
    import panel.routes.remote_vps as _hp_vps
    _hp_fw = []
    _hp_vps_saved = (_hp_vps.remote_ufw_allow_game_port, _hp_vps.remote_ufw_allow_game_ports,
                     _hp_vps.detect_game_ports)
    with app.app_context():
        _hp_gs = GameServer(remote_id=_hp_lid, name="hpgame", short_name="hpgame",
                            game_type="csgo", port=27990, installed=True, status="offline")
        db.session.add(_hp_gs)
        db.session.commit()
        _hp_gsid = _hp_gs.id
    try:
        _hp_vps.remote_ufw_allow_game_port = lambda *a, **k: (_hp_fw.append("open"), (1, "x"))[1]
        _hp_vps.remote_ufw_allow_game_ports = lambda *a, **k: (_hp_fw.append("sync"), ([], "x"))[1]
        _hp_vps.detect_game_ports = lambda *a, **k: {"game_port": 27990, "open_ports": [27990],
                                                     "ports": []}
        _hp_go = mrc.post("/api/remote/%d/game-port/27990/open" % _hp_lid)
        _hp_sy = mrc.post("/api/server/%d/sync-ports" % _hp_gsid)
    finally:
        (_hp_vps.remote_ufw_allow_game_port, _hp_vps.remote_ufw_allow_game_ports,
         _hp_vps.detect_game_ports) = _hp_vps_saved
        with app.app_context():
            db.session.delete(db.session.get(GameServer, _hp_gsid))
            db.session.commit()
    # Rebooting the panel host goes through the clean reboot's gate (host_reboot), as Reboot now
    # on a remote does: here its one server cannot be read (this machine refuses the sudo -u
    # the probe needs), so the answer is the choice — never a reboot. Nothing is marked and
    # the plain reboot underneath is never called. tests/unit/part41 drives the rest.
    from panel.ops import system_ops as _hp_so  # pylint: disable=reimported
    from panel.core.panel_state import _expected_offline as _hp_expected
    with app.app_context():
        _hp_first_local = RemoteServer.query.filter_by(is_local=True).first().id
        _hp_rg = GameServer(remote_id=_hp_first_local, name="hpreboot", short_name="hpreboot",
                            game_type="csgo", port=27995, installed=True, status="online")
        db.session.add(_hp_rg)
        db.session.commit()
        _hp_rgid = _hp_rg.id
    _hp_so_saved = _hp_so.server_reboot
    _hp_expected.pop(_hp_rgid, None)
    _hp_plain = []
    try:
        _hp_so.server_reboot = lambda d: (_hp_plain.append(d), (True, "Server will reboot"))[1]
        _hp_rb = c.post("/api/server-management/reboot", json={"delay": 10})
        _hp_body = _hp_rb.get_json() or {}
        _hp_bad = c.post("/api/server-management/reboot", json={"mode": "later"})
    finally:
        _hp_so.server_reboot = _hp_so_saved
        with app.app_context():
            db.session.delete(db.session.get(GameServer, _hp_rgid))
            db.session.commit()
    check("panel host reboot: a server whose state cannot be read gets the choice (409), not a "
          "reboot — nothing marked, the plain reboot never called",
          _hp_rb.status_code == 409 and _hp_body.get("needs_choice") is True
          and _hp_rgid not in _hp_expected and _hp_plain == [],
          "status=%d body=%r plain=%r" % (_hp_rb.status_code, _hp_body, _hp_plain))
    check("panel host reboot: ...and a mode it does not know is a 400", _hp_bad.status_code == 400)
    check("panel host firewall: a delegated admin cannot open a game port on it, nor sync one",
          _hp_go.status_code == 403 and _hp_sy.status_code == 403 and _hp_fw == [],
          "open=%d sync=%d calls=%r" % (_hp_go.status_code, _hp_sy.status_code, _hp_fw))
    # Known version and commit (see the footer's check) for the Updates card's header.
    _hp_app = sys.modules["app"]   # loaded by `from app import` above
    _hp_vsaved = (_hp_app.PANEL_VERSION, _hp_app.PANEL_COMMIT)
    try:
        _hp_app.PANEL_VERSION, _hp_app.PANEL_COMMIT = "2026.9.26", "a1b2c3d"
        _hp_loc_a = c.get("/remote/%d/manage" % _hp_lid).get_data(as_text=True)
    finally:
        _hp_app.PANEL_VERSION, _hp_app.PANEL_COMMIT = _hp_vsaved
    check("panel host page: the Updates card names the running version beside its commit",
          '<strong id="pu-current">2026.9.26 · a1b2c3d</strong>' in _hp_loc_a,
          _hp_loc_a[_hp_loc_a.find('id="pu-current"') - 10:][:120])
    check("panel host page: ...and a superadmin still gets the Security tab there (positive control)",
          'data-mtab-btn="security"' in _hp_loc_a and 'id="sec-bans"' in _hp_loc_a,
          "the Security tab is gone for the superadmin too")
finally:
    _hp_rs.remote_fail2ban_top_ips, _hp_rs.remote_security_log = _hp_saved
    if _hp_lid is not None:
        with app.app_context():
            _hp_row = db.session.get(RemoteServer, _hp_lid)
            if _hp_row is not None:
                _hp_row.groups = []
                db.session.delete(_hp_row)
                db.session.commit()

# ── a host you add has to be a host you can then reach ───────────────────────────────────
# add_remote committed the row and granted it to nothing. Access is purely group-derived, so
# for a non-superadmin creator the host was invisible on /remotes and answered 403 from its
# manage page, its edit and its delete — while the panel held its SSH credential, the sweep
# polled it, and on the "fresh" path a root bootstrap (apt full-upgrade, sshd_config rewrite,
# reboot) was already running with no way to watch or stop it. The success copy compounded it:
# "watch the progress on its card" about a card that never appears, and a redirect straight
# into a 403.
import panel.routes.remotes as _ar_mod  # pylint: disable=reimported
_ar_ssh = _ar_mod.ssh_test_connection
_ar_new_id = None
try:
    _ar_mod.ssh_test_connection = lambda *a, **k: (True, "ok")
    _ar = mrc.post("/remotes/add",
                   data={"name": "smoke-added-by-mr", "host": "198.51.100.44",
                         "ssh_user": "root", "ssh_port": "22", "auth_method": "password",
                         "credential": "s3cret", "setup_type": "existing"},
                   follow_redirects=False)
    with app.app_context():
        _ar_row = RemoteServer.query.filter_by(name="smoke-added-by-mr").first()
        _ar_new_id = _ar_row.id if _ar_row else None
    check("add_remote: the row is created (the checks below need it)",
          _ar_new_id is not None, "no RemoteServer row was written")
    if _ar_new_id is not None:
        check("add_remote: a non-superadmin creator can reach the host they just added",
              mrc.get("/remote/%d/manage" % _ar_new_id).status_code != 403,
              "the creator is 403'd from their own new host")
        check("add_remote: ...and it is listed on the page the flash sends them to",
              b"smoke-added-by-mr" in mrc.get("/remotes").data,
              "the card the success message points at does not exist")
        check("add_remote: ...and the redirect goes to a page they can open",
              _ar.status_code in (301, 302, 303)
              and ("/remote/%d/manage" % _ar_new_id) in (_ar.headers.get("Location") or ""),
              "Location: %r" % (_ar.headers.get("Location"),))
        # POSITIVE CONTROL: the grant is scoped to the row that was just created, not a
        # blanket widening — the host this user was never granted is still refused.
        check("add_remote: ...while a host they were never granted is still 403",
              mrc.get("/api/remote/%d/firewall" % remote2_id).status_code == 403,
              "the new grant widened access to hosts it should not have touched")
finally:
    _ar_mod.ssh_test_connection = _ar_ssh
    if _ar_new_id is not None:
        with app.app_context():
            _ar_row = db.session.get(RemoteServer, _ar_new_id)
            if _ar_row is not None:
                _ar_row.groups = []
                db.session.delete(_ar_row)
                db.session.commit()

# ── the host key an enrolment login saw is PINNED with the row ───────────────────────────
# add_remote and the setup wizard tested the login, threw the key it saw away and committed the
# row unpinned, so the pin came from whichever connection happened next — for a wizard-added
# host, a background worker. The REAL ssh_test_connection runs here against a fake SSH client
# that shows a chosen key; then the next connection, shown a different key, has to refuse.
import paramiko as _enr_paramiko
import types as _enr_types
from cryptography.fernet import Fernet as _EnrFernet
from sqlalchemy import text as _enr_text
from panel.core.config import encrypt_secret as _enr_encrypt
import panel.routes.route_helpers as _enr_rh


class _EnrSSH:
    presents = ("ssh-ed25519", "AAAAENROLLED")
    made = []

    def __init__(self):
        self.policy, self.kw, self.closed = None, None, 0
        _EnrSSH.made.append(self)

    def set_missing_host_key_policy(self, p):
        self.policy = p

    def connect(self, host, **kw):
        self.kw = dict(kw, host=host)
        _kt, _kb = _EnrSSH.presents
        self.policy.missing_host_key(self, host, _enr_types.SimpleNamespace(
            get_name=lambda: _kt, get_base64=lambda: _kb))

    def get_transport(self):
        return None

    def close(self):
        self.closed += 1


def _enr_next_connection(rid):
    """What the panel's next fresh connection to row `rid` does: 'refused', 'accepted', or why."""
    with app.app_context():
        _row = db.session.get(RemoteServer, rid)
        _sm_core.close_connection(_row)
        try:
            _sm_core.get_connection(_row, force_new=True, pooled=False)
            return "accepted"
        except _sm_core.HostKeyMismatch:
            return "refused"
        except Exception as _e:
            return repr(_e)


_enr_fake = _enr_types.SimpleNamespace(SSHClient=_EnrSSH,
                                       AuthenticationException=_enr_paramiko.AuthenticationException)
_enr_saved = (_sm_hosts.paramiko, _sm_core.paramiko)
_enr_names = ("smoke-enrol-pin", "smoke-wizard-pin", "smoke-test-unpinned", "smoke-test-unreadable",
              "smoke-worker-pin")
try:
    _sm_hosts.paramiko = _sm_core.paramiko = _enr_fake
    _EnrSSH.presents = ("ssh-ed25519", "AAAAENROLLED")
    c.post("/remotes/add", data={"name": "smoke-enrol-pin", "host": "198.51.100.60",
                                 "ssh_user": "root", "ssh_port": "22", "auth_method": "password",
                                 "credential": "s3cret", "setup_type": "existing"})
    with app.app_context():
        _er = RemoteServer.query.filter_by(name="smoke-enrol-pin").first()
        _er_id, _er_key = (_er.id, _er.host_key) if _er else (None, None)
    check("add_remote: the host key its test login saw is pinned with the new row",
          _er_key == "ssh-ed25519 AAAAENROLLED", repr(_er_key))
    _EnrSSH.presents = ("ssh-ed25519", "AAAADIFFERENT")
    check("add_remote: ...so the next connection, shown a DIFFERENT key, is refused",
          _er_id is not None and _enr_next_connection(_er_id) == "refused",
          _er_id and _enr_next_connection(_er_id))

    # The setup wizard's remote_server step, the path that makes no connection of its own after.
    _EnrSSH.presents = ("ssh-ed25519", "AAAAWIZARD")
    with app.test_request_context("/setup", method="POST", data={
            "name": "smoke-wizard-pin", "host": "198.51.100.61", "ssh_user": "root",
            "ssh_port": "22", "auth_method": "password", "credential": "s3cret"}):
        _wz_data = {}
        _enr_rh._setup_add_remote(_enr_types.SimpleNamespace(data="{}"), _wz_data)
        _wz = RemoteServer.query.filter_by(name="smoke-wizard-pin").first()
        _wz_id, _wz_key = (_wz.id, _wz.host_key) if _wz else (None, None)
    check("setup wizard: the host key its test login saw is pinned with the new row",
          _wz_data.get("remote_added") is True and _wz_key == "ssh-ed25519 AAAAWIZARD",
          repr((_wz_data, _wz_key)))
    _EnrSSH.presents = ("ssh-ed25519", "AAAADIFFERENT")
    check("setup wizard: ...so the next connection, shown a DIFFERENT key, is refused",
          _wz_id is not None and _enr_next_connection(_wz_id) == "refused",
          _wz_id and _enr_next_connection(_wz_id))

    # The Test button: an UNPINNED host is pinned by the login (it is first contact, like the
    # next connection would be), and an UNREADABLE pin refuses before any credential is sent.
    with app.app_context():
        _tu = RemoteServer(name="smoke-test-unpinned", host="198.51.100.63", port=22,
                           username="root", auth_method="password",
                           auth_credential=_enr_encrypt("s3cret"))
        _tr = RemoteServer(name="smoke-test-unreadable", host="198.51.100.64", port=22,
                           username="root", auth_method="password",
                           auth_credential=_enr_encrypt("s3cret"), is_online=False)
        db.session.add_all([_tu, _tr])
        db.session.commit()
        _tu_id, _tr_id = _tu.id, _tr.id
        db.session.execute(_enr_text("UPDATE remote_server SET host_key = :k WHERE id = :i"),
                           {"k": "enc:v1:" + _EnrFernet(_EnrFernet.generate_key()).encrypt(
                               b"ssh-ed25519 AAAAREAL").decode(), "i": _tr_id})
        db.session.commit()
    _EnrSSH.presents = ("ssh-ed25519", "AAAATESTED")
    c.post("/remotes/%d/test" % _tu_id)
    with app.app_context():
        _tu_key = db.session.get(RemoteServer, _tu_id).host_key
    check("remote test: an unpinned host is pinned to the key the Test login saw",
          _tu_key == "ssh-ed25519 AAAATESTED", repr(_tu_key))
    _EnrSSH.presents = ("ssh-ed25519", "AAAAMITM")
    _made_before = len(_EnrSSH.made)
    _tr_resp = c.post("/remotes/%d/test" % _tr_id, headers={"Accept": "application/json"})
    with app.app_context():
        _tr_row = db.session.get(RemoteServer, _tr_id)
        _tr_after = (type(_tr_row.host_key).__name__, _tr_row.is_online)
    _tr_sent = [m.kw for m in _EnrSSH.made[_made_before:] if m.kw]
    check("remote test: an UNREADABLE pin refuses the Test login before the password is sent",
          _tr_sent == [] and _tr_after == ("UnreadableSecret", False),
          "connect calls=%r row=%r status=%s" % (_tr_sent, _tr_after, _tr_resp.status_code))

    # create_app registers the app the pin is stored with from a WORKER thread (no app
    # context): the monitor's probes and the /api/servers port scan make most first contacts.
    import concurrent.futures as _enr_cf
    with app.app_context():
        _wp = RemoteServer(name="smoke-worker-pin", host="198.51.100.65", port=22,
                           username="root", auth_method="key", auth_credential="")
        db.session.add(_wp)
        db.session.commit()
        _wp_id = _wp.id
        _wp_obj = db.session.get(RemoteServer, _wp_id)
    with _enr_cf.ThreadPoolExecutor(max_workers=1) as _enr_ex:
        _wp_ok = _enr_ex.submit(_sm_core._persist_host_key, _wp_obj,
                                "ssh-ed25519 AAAAWORKER").result(timeout=30)
    with app.app_context():
        _wp_key = db.session.get(RemoteServer, _wp_id).host_key
    check("host key: create_app lets a worker thread with no app context store a pin",
          _wp_ok is True and _wp_key == "ssh-ed25519 AAAAWORKER", repr((_wp_ok, _wp_key)))
finally:
    _sm_hosts.paramiko, _sm_core.paramiko = _enr_saved
    with app.app_context():
        for _n in _enr_names:
            for _row in RemoteServer.query.filter_by(name=_n).all():
                _sm_core.close_connection(_row)
                _row.groups = []
                db.session.delete(_row)
        db.session.commit()

# ── ...but only with a credential the delegated admin SUPPLIED ───────────────────────────
# add_remote decided a host was the creator's to have by logging in to it, then granted it to
# their MANAGE_REMOTES groups. With auth_method=key the credential is a PATH on the panel host
# (blank -> the panel user's ~/.ssh/id_rsa, and paramiko tries the agent and every ~/.ssh key
# besides), and tailscale is the panel node's own tailnet identity: the login proved the PANEL
# could reach the address, not the requester. edit_remote let the same user repoint a granted
# row anywhere on those credentials. A password is the one method that proves the requester.
_ar2_calls = []
_ar2_ids = []
_ar2_ssh = _ar_mod.ssh_test_connection
_jh = {"Accept": "application/json"}
with app.app_context():
    _ed_row = db.session.get(RemoteServer, remote_id)
    _ed_before = (_ed_row.name, _ed_row.host, _ed_row.port, _ed_row.username,
                  _ed_row.auth_method, _ed_row.auth_credential, _ed_row.sudo_enabled)
try:
    _ar_mod.ssh_test_connection = lambda *a, **k: (_ar2_calls.append(a), (True, "ok"))[1]
    for _am in ("key", "tailscale"):
        _before_n = len(_ar2_calls)
        _r2 = mrc.post("/remotes/add", headers=_jh,
                       data={"name": "smoke-deleg-%s" % _am, "host": "198.51.100.45",
                             "ssh_user": "root", "ssh_port": "22", "auth_method": _am,
                             "credential": "", "setup_type": "existing"})
        with app.app_context():
            _made = RemoteServer.query.filter_by(name="smoke-deleg-%s" % _am).first()
            if _made is not None:
                _ar2_ids.append(_made.id)
        check("add_remote: a delegated admin cannot add a host that signs in with the panel's "
              "own %s" % _am,
              _r2.status_code == 403 and _made is None and len(_ar2_calls) == _before_n,
              "status=%d row=%s logins=%d — the panel's credential was used to prove the "
              "requester's claim" % (_r2.status_code, _made is not None,
                                     len(_ar2_calls) - _before_n))
    # ...nor register the panel's own machine: that row is superadmin-only everywhere else
    # (host_local), and from here it landed outside every group the creator is in.
    _r2 = mrc.post("/remotes/add", headers=_jh,
                   data={"name": "smoke-deleg-local", "is_local": "1", "ssh_port": "22"})
    with app.app_context():
        _made = RemoteServer.query.filter_by(name="smoke-deleg-local").first()
        if _made is not None:
            _ar2_ids.append(_made.id)
    check("add_remote: ...nor register the panel's own machine as a host",
          _r2.status_code == 403 and _made is None,
          "status=%d row=%s" % (_r2.status_code, _made is not None))
    # POSITIVE CONTROL: a superadmin still adds a key-auth host (the refusal is scoped).
    _r2 = client_as(admin_id).post("/remotes/add", headers=_jh,
                                   data={"name": "smoke-sa-key", "host": "198.51.100.46",
                                         "ssh_user": "root", "ssh_port": "22",
                                         "auth_method": "key", "credential": "",
                                         "setup_type": "existing"})
    with app.app_context():
        _made = RemoteServer.query.filter_by(name="smoke-sa-key").first()
        if _made is not None:
            _ar2_ids.append(_made.id)
    check("add_remote: ...while a superadmin still adds a key-auth host (positive control)",
          _made is not None, "status=%d" % _r2.status_code)

    # edit_remote: the delegated admin's own granted row, repointed on the panel's key.
    def _ed(**f):
        d = {"name": _ed_before[0], "host": _ed_before[1], "ssh_port": str(_ed_before[2]),
             "ssh_user": _ed_before[3], "auth_method": _ed_before[4], "credential": ""}
        d.update(f)
        return mrc.post("/remotes/%d/edit" % remote_id, headers=_jh, data=d)

    def _ed_now():
        with app.app_context():
            _x = db.session.get(RemoteServer, remote_id)
            return (_x.host, _x.port, _x.username, _x.auth_method)

    _e = _ed(host="198.51.100.99")
    check("edit_remote: a delegated admin cannot repoint a key-auth host to another address",
          _e.status_code == 403 and _ed_now()[0] == _ed_before[1],
          "status=%d now=%r" % (_e.status_code, _ed_now()))
    _e = _ed(auth_method="tailscale")
    check("edit_remote: ...nor switch it to the panel's tailnet identity",
          _e.status_code == 403 and _ed_now()[3] == _ed_before[4],
          "status=%d now=%r" % (_e.status_code, _ed_now()))
    _e = _ed(ssh_user="admin")
    check("edit_remote: ...nor change the SSH user the panel's key signs in as",
          _e.status_code == 403 and _ed_now()[2] == _ed_before[3],
          "status=%d now=%r" % (_e.status_code, _ed_now()))
    _e = _ed(credential="/home/panel/.ssh/other_key")
    check("edit_remote: ...nor point it at a different key file on the panel host",
          _e.status_code == 403, "status=%d" % _e.status_code)
    # POSITIVE CONTROLS: a rename is not a retarget, and a repoint that brings its own
    # password is the requester's credential, not the panel's.
    _e = _ed(name="smoke-host-renamed")
    with app.app_context():
        _nm = db.session.get(RemoteServer, remote_id).name
    check("edit_remote: ...while a rename still saves (positive control)",
          _e.status_code == 200 and _nm == "smoke-host-renamed",
          "status=%d name=%r" % (_e.status_code, _nm))
    _e = _ed(host="198.51.100.98", auth_method="password", credential="their-own-pw")
    check("edit_remote: ...and a repoint WITH a password they supply is theirs to make",
          _e.status_code == 200 and _ed_now()[0] == "198.51.100.98"
          and _ed_now()[3] == "password",
          "status=%d now=%r" % (_e.status_code, _ed_now()))
finally:
    _ar_mod.ssh_test_connection = _ar2_ssh
    with app.app_context():
        _x = db.session.get(RemoteServer, remote_id)
        (_x.name, _x.host, _x.port, _x.username, _x.auth_method, _x.auth_credential,
         _x.sudo_enabled) = _ed_before
        for _rid in _ar2_ids:
            _row = db.session.get(RemoteServer, _rid)
            if _row is not None:
                _row.groups = []
                db.session.delete(_row)
        db.session.commit()

# ── The firewall PAGE survives a host it cannot reach ────────────────────────────────────
# A down / rebooting host makes remote_ufw_status() raise ConnectionError. The API route has
# always caught that and answered "unreachable"; the page route called the same function bare
# and rendered a 500 — so the one page whose job is managing a remote broke precisely when
# that remote had a problem. Stub the raise rather than depending on a host being down, and
# restore it in finally: this file is a flat script, so a leaked stub changes every later check.
import panel.routes.remote_vps as _rvps
_real_ufw = _rvps.remote_ufw_status
try:
    def _refuse(_server):
        raise ConnectionError("smoke: host is down")
    _rvps.remote_ufw_status = _refuse
    _fw = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
    check("firewall page: an unreachable host renders, not 500",
          _fw.status_code == 200, "got %d" % _fw.status_code)
    check("firewall page: ...and says it couldn't read the firewall, not that UFW is missing",
          b"can't reach this host" in _fw.data and b"UFW is not installed" not in _fw.data,
          "the unreachable banner is what should render")
    # The Blocked IPs card shipped with no unreachable branch at all: block_groups is derived
    # from status.groups, which is [] on every unreachable path, so the same screen that said
    # "can't reach this host" went on to state "0 blocked" and "No IPs are blocked." An
    # operator checking whether an abusive address is still denied was told it is not, about a
    # firewall nothing read.
    check("firewall page: ...and does not state 'No IPs are blocked' about a host it never read",
          b"No IPs are blocked." not in _fw.data,
          "the Blocked IPs card contradicts the banner above it")
    check("firewall page: ...and neither count is an arithmetic claim about that host",
          b'id="rules-count">&mdash;<' in _fw.data and b'id="blocks-count">&mdash;<' in _fw.data,
          "a count is still printed for a firewall nothing read")
    # Positive control: a host that ANSWERS and genuinely has nothing must still say so, with
    # real counts — otherwise the three checks above pass by the page refusing to answer ever.
    def _empty(_server):
        return {"installed": True, "enabled": True, "rules": [], "groups": []}
    _rvps.remote_ufw_status = _empty
    _fw_ok = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
    check("firewall page: a REACHABLE host with nothing blocked still says so",
          _fw_ok.status_code == 200 and b"No IPs are blocked." in _fw_ok.data
          and b"No firewall rules yet." in _fw_ok.data,
          "status=%d — the empty states were lost" % _fw_ok.status_code)
    check("firewall page: ...and still counts, rather than dashing everything",
          b'id="blocks-count">0 <' in _fw_ok.data and b"&mdash;" not in _fw_ok.data,
          "the real empty case no longer reports a count")
    check("firewall page: ...and an ACTIVE firewall does not show the inactive note",
          b'class="text-warning d-none">While UFW is inactive' in _fw_ok.data
          and b"installed but inactive" not in _fw_ok.data, "the inactive copy shows on an active host")
    # An INACTIVE ufw (stock Ubuntu) prints only its Status line — stored rules are neither
    # listed nor enforced — so groups is [] and the page said "0 rules", "No firewall rules
    # yet." and "No IPs are blocked." over a block that denies nothing.
    def _inactive(_server):
        return {"installed": True, "enabled": False, "rules": [], "groups": []}
    _rvps.remote_ufw_status = _inactive
    _fw_in = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
    check("firewall page: an INACTIVE ufw is said to be inactive and unenforced",
          _fw_in.status_code == 200 and b"installed but inactive" in _fw_in.data
          and b"neither listed nor enforced" in _fw_in.data,
          "status=%d" % _fw_in.status_code)
    check("firewall page: ...with no rule or block count, and no 'none blocked' claim",
          b'id="rules-count">&mdash;<' in _fw_in.data and b'id="blocks-count">&mdash;<' in _fw_in.data
          and b"No IPs are blocked." not in _fw_in.data and b"No firewall rules yet." not in _fw_in.data,
          "an inactive firewall's empty listing is still counted")
    check("firewall page: ...and says a block there denies nothing",
          b'class="text-warning">While UFW is inactive' in _fw_in.data, "the block copy is unqualified")
    # A sudo refusal comes back as unreachable + permission_denied; the page blamed the network.
    def _sudo_refused(_server):
        return {"installed": False, "enabled": False, "rules": [], "groups": [],
                "unreachable": True, "permission_denied": True}
    _rvps.remote_ufw_status = _sudo_refused
    _fw_pd = client_as(admin_id).get("/remote/%d/firewall" % remote_id)
    check("firewall page: a sudo refusal names sudo, not an unreachable host",
          _fw_pd.status_code == 200 and b"sudo refused the firewall read" in _fw_pd.data
          and b"can't reach this host" not in _fw_pd.data
          and b"while this host is unreachable" not in _fw_pd.data,
          "status=%d" % _fw_pd.status_code)
finally:
    _rvps.remote_ufw_status = _real_ufw

# ── tailscale-finalize must report the UFW change it actually made ───────────────────────
# The route's whole job is "allow tailscale0 in UFW", and it audited success=status["running"]
# — tailscaled's BackendState, which says nothing about the firewall. remote_tailscale_finalize
# only issues the allow when `ufw-status` came back ACTIVE; rc 127 (ufw absent, the normal case
# for setup_type="existing") and the tailscale transport's silent ("", "…timed out", -1) both
# make _ufw_is_active("") false, so the allow is skipped and `log` comes back empty. The route
# received that empty log, forwarded it, and never looked at it — recording a successful
# firewall change that never happened.
import panel.routes.remote_tailscale as _rts
from panel.db.models import AuditLog as _TSAudit  # pylint: disable=reimported
_real_fin = _rts.remote_tailscale_finalize
try:
    _rts.remote_tailscale_finalize = lambda _s: ({"running": True, "tailscale_ip": "100.1.2.3",
                                                  "dns_name": "h.ts.net"}, "")
    _tf = client_as(admin_id).post("/api/remote/%d/tailscale-finalize" % remote_id)
    _tfj = _tf.get_json() or {}
    check("tailscale-finalize: a skipped UFW allow is not reported as one that happened",
          _tfj.get("ufw_allowed") is False, "answered %r" % (_tfj,))
    with app.app_context():
        _tfa = (_TSAudit.query.filter_by(action="remote_tailscale_finalize")
                .order_by(_TSAudit.id.desc()).first())
    check("tailscale-finalize: ...and the audit row does not record a firewall change",
          _tfa is not None and not _tfa.success,
          "audit row: %r" % (getattr(_tfa, "success", "no row"),))
    # POSITIVE CONTROL: when the allow really was issued, both say so.
    _rts.remote_tailscale_finalize = lambda _s: ({"running": True, "tailscale_ip": "100.1.2.3",
                                                  "dns_name": "h.ts.net"},
                                                 "UFW: allowed tailscale0 interface (in)")
    _tf2 = client_as(admin_id).post("/api/remote/%d/tailscale-finalize" % remote_id)
    _tfj2 = _tf2.get_json() or {}
    check("tailscale-finalize: a UFW allow that DID happen is reported and audited",
          _tfj2.get("ufw_allowed") is True and _tfj2.get("running") is True,
          "answered %r" % (_tfj2,))
    with app.app_context():
        _tfa2 = (_TSAudit.query.filter_by(action="remote_tailscale_finalize")
                 .order_by(_TSAudit.id.desc()).first())
    check("tailscale-finalize: ...with a success row, so the gate is not refusing everything",
          _tfa2 is not None and _tfa2.success,
          "audit row: %r" % (getattr(_tfa2, "success", "no row"),))
finally:
    _rts.remote_tailscale_finalize = _real_fin

# ── Scheduled-tasks (cron) endpoints need MANAGE_SERVERS (same gate as the file
#    editor). The MANAGE_REMOTES user CAN reach this server (its group grants the
#    host) but lacks MANAGE_SERVERS, so every cron verb is refused with 403 — and
#    the refusal happens before any SSH, so the check stays offline/portable. ──
check("cron list without MANAGE_SERVERS -> 403",
      mrc.get("/api/server/%d/cron" % gs_id).status_code == 403)
check("cron add without MANAGE_SERVERS -> 403",
      mrc.post("/api/server/%d/cron" % gs_id,
               json={"schedule": "@daily", "command": "/bin/true"}).status_code == 403)
check("cron delete without MANAGE_SERVERS -> 403",
      mrc.post("/api/server/%d/cron/delete" % gs_id, json={"raw": "x"}).status_code == 403)

from panel.core.panel_state import (_install_jobs as _install_jobs_sm,
                                    _install_lock as _install_lock_sm)
# ── the recorded reason must be READABLE ────────────────────────────────────────────────────
# LinuxGSM and SteamCMD colour their output, and the last 300 bytes of a failed install is
# nearly all escape sequences. That is what the corner card showed, verbatim:
#
#   info...\x1b[0mOK \x1b[0mERROR! Failed to install app '222860' (Invalid platform)
#   \x1b[0mUnloading Steam API...\x1b[0mOK \x1b[0m\x1b[31mFailure!\x1b[0m Installing l4d2server…
#
# The panel has had strip_escapes since the console was written; this path never called it.
_raw_tail = ("info...\x1b[0mOK \x1b[0mERROR! Failed to install app '222860' (Invalid "
             "platform)\r\n   \x1b[0m\x1b[31mFailure!\x1b[0m Installing l4d2server")
# The PANEL'S function, not a copy of it rebuilt here. These three used to assert properties
# of a local `" ".join(strip_escapes(raw).split())` the test wrote itself, so they passed with
# the production line deleted — they were testing the test.
from panel.routes.manage_servers import readable_reason as _clean_fn
_clean = _clean_fn(_raw_tail)
check("install failure: the recorded reason carries no ANSI escapes",
      "\x1b" not in _clean and "[0m" not in _clean, repr(_clean)[:120])
check("install failure: ...and is one line, not the raw column padding",
      "\r" not in _clean and "\n" not in _clean and "   " not in _clean, repr(_clean)[:120])
check("install failure: ...with the actual message still in it",
      "Invalid platform" in _clean and "l4d2server" in _clean, repr(_clean)[:120])
_ms_esc = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(_SUITE_FILE))),
                            "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
# ...and _fail routes through it, so every caller benefits rather than just this one.
check("install failure: _fail strips before recording, so every caller benefits",
      "detail = readable_reason(detail)" in _ms_esc)

# A CLASSIFIED reason stands alone on the row. The raw tail is the tool's own last word, and
# the tool is sometimes wrong: LinuxGSM ends an "Invalid platform" failure with "Check
# steamcmdforcewindows setting and system architecture", which points at the host — and the
# host is not the problem (the app publishes no Linux launch configuration; proven on the test
# box, where forcing the platform fails identically). Appending that after the correct sentence
# undoes it, so the row gets the explanation and the live job keeps the unabridged output.
# Driven, not grepped: this used to assert that a particular line of source existed, which
# says nothing about what the line does and broke the moment the logic moved into a function.
from panel.routes.manage_servers import record_install_failure as _rif_tail  # pylint: disable=reimported


class _TailRow(object):
    pass


def _reason(name, detail, explained):
    _r = _TailRow(); _r.installed, _r.status = True, "installing"
    _rif_tail(_r, name, detail, True, explained)
    return _r.install_error


check("install failure: a classified reason is not followed by the tool's own wrong hint",
      _reason("SteamCMD refused this game — a known SteamCMD bug.",
              "Check steamcmdforcewindows setting and system architecture", True)
      == "SteamCMD refused this game — a known SteamCMD bug.",
      "the raw tail is still appended to a classified reason")
check("install failure: ...while an UNclassified one still carries its tail, which is all it has",
      _reason("Downloading game server files", "mirror unreachable", False)
      == "Downloading game server files: mirror unreachable")
check("install failure: ...and the classified call site is the one that asks for that",
      "explained=bool(why)" in _ms_esc,
      "step 4 no longer tells the recorder the reason is self-contained")

# ── the install must not point two servers at one port ──────────────────────────────────────
# resolve_free_port picks a genuinely free port at request time — it unions the host's live
# listening ports with every panel server's reserved block. Step 6 then adopts whatever port
# LinuxGSM REPORTS, because auto-install uses the game's default rather than the port the panel
# wrote. That adoption had no conflict check.
#
# A game that ignores the panel's port key reports its own default there. Reproduced on the
# test box with a Velocity proxy (it reads velocity.toml, not the LinuxGSM key): it reported
# 25565, the host's Minecraft server already had it, and the proxy logged
#
#     [ERROR]: Can't bind to /0.0.0.0:25565
#     bind(..) failed with error(-98): Address already in use
#
# while LinuxGSM still said STARTED. And the panel would then call that proxy ONLINE, because
# something IS listening on 25565 — a port check cannot tell whose socket it is. So the clash
# must not be created in the first place.
# The first version of this checked for substrings in manage_servers.py, which says only that
# some text is present. The decision is now its own function, so drive it: the panel's table,
# a foreign listener, and a scan that could not answer are three different results.
from panel.routes.manage_servers import decide_port_adoption as _dpa

_scans = []


def _live(value):
    def f():
        _scans.append(1)
        return value
    return f


check("install: a reported port nobody holds is adopted",
      _dpa(25565, 25566, {}, _live({22, 80})) == (True, None, False))
check("install: ...but not one another PANEL server on the host has",
      _dpa(25565, 25566, {25565: "mc"}, _live(set()))[0] is False)
check("install: ...nor one a NON-panel process is already listening on",
      _dpa(25565, 25566, {}, _live({25565}))[0] is False,
      "adopting a foreign socket makes every status answer read that process, so a server "
      "that never bound anything is reported online for ever")
check("install: ...nor when the port scan could not answer at all",
      _dpa(25565, 25566, {}, _live(None))[0] is False,
      "a failed scan is not an empty one — 'could not look' must not read as 'free'")
check("install: ...and each refusal says which of the three it was",
      len({_dpa(25565, 25566, {25565: "mc"}, _live(set()))[1:],
           _dpa(25565, 25566, {}, _live({25565}))[1:],
           _dpa(25565, 25566, {}, _live(None))[1:]}) == 3,
      "two of the three reasons reach the user as the same sentence")
# The third answer has to be distinguishable BY THE CALLER, not only by its wording. It used
# to be carried in taken_by as the phrase "something the panel could not check for", so the
# caller could not tell it from a real holder and printed "it wants port 25565, which
# something the panel could not check for already uses" — plus a matching
# `install_complete success=False ... clashes with` audit entry — about a port that is very
# often free. So: a failed scan names NOBODY, and flags itself.
_dpa_unread = _dpa(25565, 25566, {}, _live(None))
check("install: ...and a scan that FAILED names no holder at all",
      _dpa_unread[1] is None and _dpa_unread[2] is True,
      "%r — a phrase here is spliced into 'which %%s already uses', a fact about the host "
      "that this very branch established it could not read" % (_dpa_unread,))
check("install: ...while an observed holder is still named, and not flagged unreadable",
      _dpa(25565, 25566, {}, _live({25565}))[1] == "another process on this host"
      and _dpa(25565, 25566, {}, _live({25565}))[2] is False,
      repr(_dpa(25565, 25566, {}, _live({25565}))))
_scans.clear()
_dpa(25565, 25565, {}, _live(set()))
_dpa(25565, 25566, {25565: "mc"}, _live(set()))
check("install: ...without an SSH round trip the table could have answered",
      not _scans, "the host is scanned even when the panel already knows the port is taken")

# ── SCP: Secret Laboratory asks two questions nobody can answer ─────────────────────────────
# Found while walking the LinuxGSM catalogue: scpsl installed, LinuxGSM reported STARTED, and
# the game never launched. Its launcher stops and asks, inside a tmux session with no input:
#
#   1. "Before starting please read and accept the SCP:SL EULA. Do you accept? [yes/no]"
#   2. "Do you want to edit that configuration? [edit/keep]"
#
# The second is the subtle one: LocalAdmin keeps its config PER PORT, under
# config/<port>/, and asks whenever a port has no config yet. The panel assigns a FREE port
# rather than the game's default, so it walks into that on every install.
#
# The panel already writes Minecraft's eula.txt at the same step, so accepting is the
# established pattern here rather than a new decision. Proven end to end through the panel's
# own routes on the test host: SCPSL.x86_64 running, console at "Level loaded. Creating
# match...", and the panel reporting the server online.
_ms_sl = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(_SUITE_FILE))),
                           "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
# Assert what is actually SENT. These were whole-file substring greps, and every string they
# looked for — "EulaAccepted", "config_localadmin.txt" — also appears in the COMMENTS that
# explain the code, so all four passed with the EULA write deleted. The ordering one was worse:
# .index() finds the FIRST occurrence, which is the comment, so it measured where a comment sat.
from panel.routes.manage_servers import (scpsl_eula_payload as _sl_eula,
                                         scpsl_seed_config_payload as _sl_seed)
_eula_cmd, _seed_cmd = _sl_eula(), _sl_seed(27031)
check("scpsl: the EULA is accepted the way Minecraft's already is",
      "d['EulaAccepted']" in _eula_cmd and "localadmin_internal_data.json" in _eula_cmd,
      "the install still stops at the EULA prompt with nothing to answer it")
check("scpsl: ...and the per-port config is seeded, or LocalAdmin asks about it instead",
      "config/27031" in _seed_cmd and "config_localadmin.txt" in _seed_cmd, _seed_cmd[:120])
check("scpsl: ...into the directory named after THAT port, not a fixed one",
      "config/27032" in _sl_seed(27032), _sl_seed(27032)[:120])
check("scpsl: ...and an existing config is left alone",
      '[ -f "$d/config_localadmin.txt" ] ||' in _seed_cmd,
      "it would overwrite a config the operator had edited")
# AFTER step 6, not at step 5: the port is only final once step 6 has decided whether to adopt
# the one LinuxGSM reports, and seeding the wrong directory helps nobody. Measured on the CALL,
# which appears once, rather than on a string the comments also contain.
check("scpsl: ...seeded once the port is final, not before step 6 can change it",
      _ms_sl.index("scpsl_seed_config_payload(gs.port)")
      > _ms_sl.index("# 6. Sync to LinuxGSM's real port"),
      "the per-port config is written before the port is settled")

# ── the install works around SteamCMD's "Invalid platform" bug itself ───────────────────────
# Left 4 Dead 2 refuses to install with "ERROR! Failed to install app '222860' (Invalid
# platform)". It is not a missing Linux build — the app has a Linux depot (222863) — it is a
# SteamCMD bug, and LinuxGSM's maintainer published the way through it in
# GameServerManagers/LinuxGSM#4754: install with steamcmdforcewindows=yes (which gets SteamCMD
# past its own refusal by pulling the Windows depot), unset it, then validate, which pulls the
# Linux binaries.
#
# Proven on the test host before this was written: both steps reported "Success! App '222860'
# fully installed", srcds_linux came out an ELF 32-bit LSB executable, and the server started
# and listened on its port with VAC active. Telling an operator to go and read a GitHub thread
# is the opposite of what this panel is for, so the install does it.
_ms_w = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(_SUITE_FILE))),
                          "panel", "routes", "manage_servers.py"), encoding="utf-8").read()
check("install: an Invalid-platform failure primes with the Windows depot instead of giving up",
      'why[0] == "steam_platform" and not primed_windows' in _ms_w
      and '{"steamcmdforcewindows": "yes"}' in _ms_w)
check("install: ...then unsets the flag and validates, which is what pulls the Linux binaries",
      '{"steamcmdforcewindows": "no"}' in _ms_w and '"validate"' in _ms_w)
check("install: ...and does it at most once, so a workaround that misses cannot loop",
      "primed_windows = True" in _ms_w and "primed_windows = False" in _ms_w)

# ── a failed install has to say WHY, and offer the two things you can actually do ───────────
# The row said "Failed" and nothing else. The reason lived in the install job's memory until
# the panel restarted; Retry did not exist; and Remove was on the host page, a different page
# from the one showing the failure. Worse, `busy = not installed` greyed out Files & Config on
# exactly that row — the config the failure usually asks you to change.
with app.app_context():
    _rf = db.session.get(GameServer, gs_id)
    _rf_before = (_rf.status, _rf.installed, _rf.install_error, _rf.install_retryable)
    _rf.status, _rf.installed = "failed", False
    _rf.install_error = "Downloading game server files: the mirror was unreachable."
    _rf.install_retryable = True
    db.session.commit()
try:
    _dash = c.get("/").get_data(as_text=True)
    check("failed install: the dashboard says WHY it failed",
          "the mirror was unreachable" in _dash)
    check("failed install: ...and offers Retry when a retry could help",
          ("/servers/%d/retry-install" % gs_id) in _dash)
    check("failed install: ...and Remove, which used to live on another page entirely",
          ("/servers/%d/delete" % gs_id) in _dash)
    # The Files link is what #282 made reachable; greying it out here made that unreachable
    # from the one page that shows the failure.
    #
    # Find it by its CLASS, not by its href. There are TWO links to /server/<id>/files on this
    # page — the banner's "Edit its config" above the table, and the row's own button — and the
    # banner's comes first in the document and is never disabled. A check that took the first
    # href therefore passed whatever the row button did, which is no check at all. Only the row
    # button carries `srv-files`.
    _fi = _dash.find("srv-files")
    _ftag = _dash[_dash.rfind("<a", 0, _fi):_dash.find(">", _fi) + 1] if _fi != -1 else ""
    check("failed install: ...and Files & Config is NOT greyed out on a failed row",
          _fi != -1 and "disabled" not in _ftag,
          _ftag[:200] or "no srv-files button at all")
    check("failed install: ...and the banner offers the same page in words",
          'href="/server/%d/files"' % gs_id in _dash and "Edit its config" in _dash)

    # The retry itself. The real job runs in a background thread and its first step is an SSH
    # round trip to a host this suite does not run, so it fails — what is being checked here
    # is the ROUTE's contract: accepted, row back to installing, reason cleared.
    #
    # HELD at that first SSH call while the contract is read, and drained before the next
    # scenario is written. The crash path records the failure ON THE ROW now (it could not
    # before — the `with _app.app_context():` had already exited by the time the handler ran,
    # so db.session raised "Working outside of application context" into a debug log), and a
    # worker that reaches the row a few milliseconds after this POST returns would both race
    # this check and overwrite the scenario set up after it.
    import contextlib as _rt_ctx
    import threading as _rt_thr
    import time as _rt_time

    def _live_install_workers():
        """The threads still inside an install job's _run(), identified by their target.

        manage_servers spawns them as bare `threading.Thread(target=_run, daemon=True)` — no
        name, no handle kept — so the target function is the only thing there is to match on.
        """
        _out = []
        for _t in _rt_thr.enumerate():
            _tgt = getattr(_t, "_target", None)
            if (_tgt is not None and _t.is_alive()
                    and getattr(_tgt, "__module__", "") == "panel.routes.manage_servers"
                    and getattr(_tgt, "__qualname__", "").endswith("._run")):
                _out.append(_t)
        return _out

    @_rt_ctx.contextmanager
    def _install_seam_closed(_what):
        """Hold every install worker at its first SSH call, and keep the transport closed
        until all of them have finished.

        Two separate things go wrong without this, and only the first is obvious.

        The obvious one: these jobs run in a background thread whose first step is an SSH
        round trip, and no suite has a host to answer it. Letting that reach the real
        transport costs a full TCP timeout per call on a CI runner — and with a key
        configured it does not even get that far ("No such file: /home/runner/.ssh/id_rsa").
        run_command is not enough on its own; get_connection is the one door all three
        transports go through, so closing it is what makes an unaccounted call fail here
        instead of dialling out.

        The one that actually broke CI: a worker that outlives the block that started it.
        The content-capture POST below starts a job, then deletes its row and pops its job
        dict — but the THREAD keeps running. SQLite hands the next INSERT the id it just
        freed, so the install-job block's own row is created with the SAME id, and the
        abandoned worker's _fail() writes "Install failed unexpectedly: SSH connection
        failed: ... id_rsa" into that row and that job dict. Four install-job checks then
        failed on a job that was walking through its steps perfectly well. It passed locally
        because the worker reached its SSH call before the next block began; on a slower
        runner it did not. This is the hazard _ij_wait's docstring describes, arriving
        through the id rather than through the stubs.

        So the seam does not reopen on a timer or on one row's status — it reopens when
        there is no install worker left alive, and says so loudly if that never happens.
        """
        _gate = _rt_thr.Event()
        _saved_rc, _saved_gc = _sm_core.run_command, _sm_core.get_connection

        def _blocked(*a, **k):
            _gate.wait(30)
            raise ConnectionError("no SSH host in this suite")
        _sm_core.run_command = _blocked
        _sm_core.get_connection = _blocked
        try:
            yield
        finally:
            _gate.set()
            for _ in range(3600):                 # 180s, as _ij_wait allows
                if not _live_install_workers():
                    break
                _rt_time.sleep(0.05)
            _sm_core.run_command = _saved_rc
            _sm_core.get_connection = _saved_gc
            _left = len(_live_install_workers())
            check("install seam: no worker outlives the %s block that started it" % _what,
                  _left == 0,
                  "%d still running after 180s — whatever it fails on next lands on the row "
                  "the NEXT block creates, which may hold this one's recycled id" % _left)

    def _retry_under_gate():
        with _install_seam_closed("retry"):
            _resp = c.post("/servers/%d/retry-install" % gs_id)
            with app.app_context():
                _row = db.session.get(GameServer, gs_id)
                return _resp, (_row.status, _row.install_error)

    _rr, _rr_state = _retry_under_gate()
    check("failed install: retry is accepted for a retryable failure",
          _rr.status_code in (200, 302), _rr.status_code)
    check("failed install: ...and the row goes back to installing, with the reason cleared",
          _rr_state[0] == "installing" and not _rr_state[1],
          "status=%s error=%r" % _rr_state)
    # ...and the job that then crashes leaves the row RECOVERABLE. The outer handler's own
    # comment promised "a reason on the row, status failed, and the dashboard told"; what it
    # did was set the in-memory job only, because the application context was already gone.
    # The two diverged, and the divergence is what hid it: the corner widget said failed while
    # the row said installing for ever — no reason, no Retry, and /delete refusing to remove
    # it, since /delete will not touch a row that says it is installing.
    with app.app_context():
        _cr = db.session.get(GameServer, gs_id)
        _cr_state = (_cr.status, _cr.install_error, _cr.install_retryable, _cr.installed)
    with _install_lock_sm:
        _cr_job = dict(_install_jobs_sm.get(gs_id) or {})
    check("failed install: a job that dies mid-install writes the failure to the ROW",
          _cr_state[0] == "failed" and bool(_cr_state[1]),
          "status=%r error=%r — the row is stranded at 'installing' with no reason, which "
          "/delete also refuses" % (_cr_state[0], _cr_state[1]))
    check("failed install: ...and offers a retry, since a dropped SSH is worth trying again",
          _cr_state[2] is True and _cr_state[3] is False, repr(_cr_state))
    check("failed install: ...the in-memory job agreeing with it, not instead of it",
          _cr_job.get("status") == "failed", repr(_cr_job.get("status")))
    # The row that actually reaches this state most often. Step 4 commits
    # installed=True/status="configuring"; a panel restart during steps 5-8 kills the worker,
    # and api.py's install-status poll reconciles it by writing status="failed" and leaving
    # installed alone. The dashboard's card is keyed on status ALONE, so it draws the Retry
    # button for that row — and the guard, which also demanded `not gs.installed`, answered
    # "That server's install didn't fail, so there's nothing to retry." to the button it had
    # just drawn. Remove was the only way out, which is the dead end this flow exists to end.
    with app.app_context():
        _ri = db.session.get(GameServer, gs_id)
        _ri.status, _ri.installed = "failed", True
        _ri.install_error = "Interrupted by a panel restart during setup."
        _ri.install_retryable = True
        db.session.commit()
    with _install_lock_sm:
        _install_jobs_sm.pop(gs_id, None)
    _dash_ri = c.get("/").get_data(as_text=True)
    check("failed install: a failed row still marked installed is offered Retry",
          ("/servers/%d/retry-install" % gs_id) in _dash_ri,
          "the card is keyed on status alone, so this is the row the guard has to accept")
    _rr_i, _rr_i_state = _retry_under_gate()
    check("failed install: ...and the route accepts it instead of answering its own button",
          _rr_i.status_code in (200, 302) and _rr_i_state[0] == "installing",
          "status=%r http=%r — 'that server's install didn't fail' on a row that says failed"
          % (_rr_i_state[0], _rr_i.status_code))
    with app.app_context():
        _after = db.session.get(GameServer, gs_id)
        # put it back to failed, this time with a cause no retry can fix
        _after.status, _after.installed = "failed", False
        _after.install_error = "This game is not downloadable with an anonymous Steam login."
        _after.install_retryable = False
        db.session.commit()
    with _install_lock_sm:
        _install_jobs_sm.pop(gs_id, None)
    _dash2 = c.get("/").get_data(as_text=True)
    check("failed install: a cause no retry can fix does NOT offer Retry",
          ("/servers/%d/retry-install" % gs_id) not in _dash2)
    check("failed install: ...and says so, instead of leaving you to guess",
          "Trying again won" in _dash2)
    _rr2 = c.post("/servers/%d/retry-install" % gs_id)
    with app.app_context():
        check("failed install: ...and the route refuses it too, not just the button",
              db.session.get(GameServer, gs_id).status == "failed", _rr2.status_code)
finally:
    with _install_lock_sm:
        _install_jobs_sm.pop(gs_id, None)
    with app.app_context():
        _rf = db.session.get(GameServer, gs_id)
        (_rf.status, _rf.installed, _rf.install_error, _rf.install_retryable) = _rf_before
        db.session.commit()

# ── a retry must reproduce the install it is retrying ─────────────────────────────────────
# The mounted-content games for a GMod server arrive on the install FORM and were never stored,
# so retry_install re-ran the job with no seventh argument: `if content_games and game_type ==
# "gmod"` was false, the content step was skipped, no mount.cfg was written, and the server
# came back missing the maps and props that were asked for — with nothing on screen saying so.
# The retry's progress bar also hardcoded 8 steps while the original derived 9 for these.
with app.app_context():
    _cg = db.session.get(GameServer, gs_id)
    _cg_before = (_cg.content_games, _cg.status, _cg.installed,
                  _cg.install_error, _cg.install_retryable, _cg.game_type)
    _cg_remote_id = _cg.remote_id
    _cg.content_games = "cstrike,tf"          # real GMOD_CONTENT_GAMES keys
    _cg.game_type, _cg.status, _cg.installed = "gmod", "failed", False
    _cg.install_error, _cg.install_retryable = "mirror unreachable", True
    db.session.commit()
try:
    # Gated, like the retries above: the crash path records the failure ON THE ROW now, so a
    # worker still running here writes status="failed" over whatever the `finally` below puts
    # back — and gs_id is the row the rest of this suite goes on using. The job dict survives
    # the drain, so `total` is still there to read.
    _retry_under_gate()
    with _install_lock_sm:
        _cgj = dict(_install_jobs_sm.get(gs_id) or {})
    check("retry: a GMod retry counts the content step the original did",
          _cgj.get("total") == 9,
          "total=%r — the progress bar is short by the content step" % (_cgj.get("total"),))
    with app.app_context():
        check("retry: ...and the selection survived on the row to be replayed",
              (db.session.get(GameServer, gs_id).content_games or "") == "cstrike,tf",
              db.session.get(GameServer, gs_id).content_games)
    # ...and it gets there from the FORM. Writing the column by hand above tests the replay
    # but not the capture, and the capture is the half that was missing: the selection arrived
    # on this POST and was dropped on the floor.
    # The route refuses when it cannot read the host's ports ("Can't reach ... right now"), and
    # this suite's remote is a 127.0.0.1 nothing answers on. Stub the scan for this POST only.
    _appmod_cg = sys.modules["app"]
    _cg_rlp = _appmod_cg._remote_listening_ports
    _appmod_cg._remote_listening_ports = lambda r: {22}
    # ...and the route now also asks the host whether the account already exists (an existing
    # one is someone else's, not a leftover), which the same dead host cannot answer either.
    import panel.routes.manage_servers as _cg_msmod
    _cg_has = _cg_msmod.host_account_state
    _cg_msmod.host_account_state = lambda r, n: "absent"
    # Under the seam, and drained before the row goes: this POST starts a real install thread,
    # and the row it belongs to is deleted a few lines down. SQLite then hands that freed id
    # to the next INSERT — the install-job block's row — and this worker, still running, wrote
    # its SSH failure onto it. See _install_seam_closed.
    with _install_seam_closed("content-capture"):
        _add = c.post("/servers/add", data={
            "remote_id": str(_cg_remote_id), "game_type": "gmod",
            "server_name": "cgcapture", "port": "28980",
            "content_games": ["cstrike", "tf"],
        }, follow_redirects=True)
    _appmod_cg._remote_listening_ports = _cg_rlp
    _cg_msmod.host_account_state = _cg_has
    with app.app_context():
        _new = GameServer.query.filter_by(short_name="cgcapture").first()
        _captured = (_new.content_games or "") if _new is not None else "<no row>"
        _new_id = _new.id if _new is not None else None
    check("retry: the content selection is captured from the install form in the first place",
          _captured == "cstrike,tf",
          "row stored %r (POST -> %s)" % (_captured, _add.status_code))
    if _new_id is not None:
        with app.app_context():
            _n = db.session.get(GameServer, _new_id)
            if _n is not None:
                db.session.delete(_n); db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_new_id, None)
finally:
    with app.app_context():
        # Restore what it WAS, including game_type — putting back a hardcoded "gmod" left
        # the row lying about itself and failed four unrelated checks further down the suite.
        _cg = db.session.get(GameServer, gs_id)
        (_cg.content_games, _cg.status, _cg.installed,
         _cg.install_error, _cg.install_retryable, _cg.game_type) = _cg_before
        db.session.commit()
    with _install_lock_sm:
        _install_jobs_sm.pop(gs_id, None)

# ── the install JOB itself, executed end to end ───────────────────────────────────────────
# Coverage said manage_servers.py was 49% and named the gap: lines 499-948, which is the whole
# of _run() — steps 2 through 8. Every suite's host is unreachable, so /servers/add started the
# thread and it died at step 2; the panel's most consequential code path was held only by
# source-level gates. Those gates read the file. This runs it.
#
# The host is stubbed to SUCCEED so the job walks the whole way: dependencies, download,
# config, port adoption, firewall, autostart, start, and the post-start liveness poll.
import panel.routes.manage_servers as _msmod
import time as _ijw_time
# Stub at the DEFINITION SITE, never on the package. panel/ops/ssh_manager/__init__.py exposes
# these through __getattr__ precisely so there is one stub target, and its docstring says not
# to bind names on it. Setting them on the package shadows the forwarding — and "restoring"
# them afterwards makes that shadow permanent, so every later stub on _core stops being seen.
# That is not hypothetical: doing it here broke six power-action checks further down the file.
from panel.ops.ssh_manager import game as _ij_game, portscan as _ij_ps


def _ij_wait(gid, secs=180):
    """Wait until the install job for `gid` is genuinely FINISHED.

    Both halves matter. The job dict can stop saying "running" while the worker still has work
    left, and the worker only touches the row at the end — so waiting on either one alone lets
    the block finish, restore its stubs, and leave a thread still running against whatever the
    NEXT block installs. That is not hypothetical: CI logged the first job adopting the second
    scenario's ports, because the first block had already handed the stubs back.
    """
    # int(), and a floor of one pass: a fractional or zero `secs` made range() empty, so the
    # loop never ran and the return below referenced an unbound name — the guard crashed the
    # suite instead of reporting the stall it exists to report. Found by mutating it.
    _row_status = "unread"
    _deadline = max(1, int(secs * 10))
    for _ in range(_deadline):
        with _install_lock_sm:
            j = dict(_install_jobs_sm.get(gid) or {})
        with app.app_context():
            _r = db.session.get(GameServer, gid)
            _row_status = _r.status if _r is not None else "gone"
        if j.get("status") not in ("running", None) and _row_status != "installing":
            return j, _row_status, True
        _ijw_time.sleep(0.1)
    with _install_lock_sm:
        j = dict(_install_jobs_sm.get(gid) or {})
    return j, _row_status, False


_ij_saved, _ij_calls, _ij_state = {}, [], {"started": False}
_ij_verbs = []


def _ij_priv(server, verb, args=(), *a, **k):
    _ij_verbs.append((verb, list(args)))
    return ("freed=0 held=0 slots=10", "", 0)


def _ij_stub(mod, name, fn):
    _ij_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


def _ij_ports(_remote):
    # Before the server starts, nothing of ours is listening — which is what makes the port
    # step 6 wants to adopt look free. After `start`, the port answers.
    return {28991} if _ij_state["started"] else set()


def _ij_run_as(remote, user, action, **k):
    if action == "start":
        _ij_state["started"] = True
    _ij_calls.append(("run_as_game_user", action))
    return ("", "", 0)


try:
    # Close the SSH seam outright. The stubs below cover every function this job is KNOWN to
    # call, and CI still reached paramiko — "SSH connection failed: Error reading SSH protocol
    # banner" / "No such file: /home/runner/.ssh/id_rsa" — on a runner where a real connect
    # gets further than it does here, which is why it reproduced there and not locally. It only
    # became visible when the install job's last-resort _fail() gained the app context it needs
    # to record anything: before that the failure was swallowed and the job kept its earlier
    # values, so the checks below passed on a job that had crashed.
    #
    # get_connection is the one door all three transports go through, so stubbing it makes any
    # call this block has NOT accounted for fail loudly and locally instead of dialling out.
    _ij_stub(_sm_core, "get_connection",
             lambda *a, **k: (_ for _ in ()).throw(
                 AssertionError("the install job opened a real SSH connection — a call this "
                                "block does not stub reached the transport")))
    _ij_stub(_sm_core, "read_as_game_user", lambda *a, **k: ("", "", 0))
    _ij_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
    _ij_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
    _ij_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
    _ij_stub(_sm_core, "run_as_game_user", _ij_run_as)
    _ij_stub(_sm_core, "run_privileged", _ij_priv)
    _ij_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop", "monitor"])
    _ij_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
    _ij_stub(_msmod, "_looks_installed", lambda *a, **k: True)
    _ij_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
    _ij_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
    _ij_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
    _ij_stub(_msmod, "install_game_cron", lambda *a, **k: None)
    _ij_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
    _ij_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
    _ij_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
    # remote_ufw_close_game_port is left REAL: the adoption below leaves 28990, and what it
    # sends the host for that is checked verb by verb.
    _ij_stub(_msmod, "_remote_listening_ports", _ij_ports)
    _ij_stub(_msmod, "remote_ufw_allow_game_ports",
             lambda r, ports, name: _ij_calls.append(("ufw_allow", tuple(sorted(ports)))))
    # LinuxGSM reports a port other than the one the panel allocated — the ordinary case for a
    # game that reads its own config — and nothing else holds it, so step 6 adopts it.
    _ij_stub(_msmod, "detect_game_ports",
             lambda *a, **k: {"game_port": 28991, "open_ports": [28991, 28992]})
    _appmod_ij = sys.modules["app"]
    _ij_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
    _appmod_ij._remote_listening_ports = lambda r: {22}

    _ij_resp = c.post("/servers/add", data={
        "remote_id": str(_cg_remote_id), "game_type": "gmod",
        "server_name": "jobwalk", "port": "28990"}, follow_redirects=True)
    with app.app_context():
        _ij_row = GameServer.query.filter_by(short_name="jobwalk").first()
        _ij_id = _ij_row.id if _ij_row else None
    check("install job: the POST created a row to run the job against", _ij_id is not None,
          "no row — the job never started (POST %s)" % _ij_resp.status_code)

    if _ij_id is not None:
        _job, _row_st, _ij_settled = _ij_wait(_ij_id)
        _st = _job.get("status")
        # What the job itself said, so a failure here names the step it stopped on instead of
        # only the end state. CI failed this where the machine running it passed, and "status
        # is still installing" on its own does not say which stub the job walked past.
        _why_job = "job=%r step=%r/%r name=%r msg=%r" % (
            _st, _job.get("step"), _job.get("total"), _job.get("step_name"),
            (_job.get("message") or "")[:200])
        with app.app_context():
            _ij_done = db.session.get(GameServer, _ij_id)
            _ij_final = (_ij_done.status, _ij_done.installed, _ij_done.port,
                         _ij_done.install_error)
        check("install job: it runs to completion instead of dying at step 2",
              _ij_settled, _why_job)
        check("install job: ...and the server ends up installed and online",
              _ij_final[0] == "online" and _ij_final[1] is True,
              "status=%r installed=%r error=%r | %s" % (_ij_final[0], _ij_final[1], _ij_final[3], _why_job))
        check("install job: ...having adopted the port LinuxGSM reported",
              _ij_final[2] == 28991, "port=%r | %s" % (_ij_final[2], _why_job))
        check("install job: ...and started the server, not just installed it",
              ("run_as_game_user", "start") in _ij_calls,
              "calls: %s | %s" % (_ij_calls[:8], _why_job))
        _ij_opened = [c2 for c2 in _ij_calls if c2[0] == "ufw_allow"]
        check("install job: ...and opened the reported ports in the firewall",
              any(28991 in c2[1] for c2 in _ij_opened), "ufw calls: %s | %s" % (_ij_opened, _why_job))
        # Aikido 745379215. Leaving 28990 ran `ufw delete allow 28990` and the proto tcp/udp
        # pair with no comment — every ALLOW on the port, whoever's — on a port that, this
        # early in a FRESH install, cannot hold a rule of this server's yet.
        _ij_deletes = [v for v in _ij_verbs if v[0].startswith("ufw-delete")]
        check("install job: ...and leaving the allocated port deleted NO firewall rule — "
              "nothing on it was this new server's",
              _ij_deletes == [], "delete verbs: %r | %s" % (_ij_deletes, _why_job))
        with app.app_context():
            _d = db.session.get(GameServer, _ij_id)
            if _d is not None:
                db.session.delete(_d); db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_ij_id, None)
finally:
    for (_m, _n), _v in _ij_saved.items():
        setattr(_m, _n, _v)
