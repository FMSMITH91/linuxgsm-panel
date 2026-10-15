"""Part 64 of the unit suite: review 1011e's core, backup, ssh-core and reboot fixes (builder A).

Held here, each against the code path the finding named:

* a row deleted while a background pass is under way no longer ends the pass from inside the
  `except` that logs it (the log line's own read raised a second time);
* the host page's threshold box refuses more than the 100000 the endpoint clamps to (a superadmin
  was told the threshold was unchanged and that only a superadmin could change it);
* an admin's password reset, and a legacy cookie's sign-out (both bump auth_epoch), clear the
  account's session rows too: left, the revoked devices listed as live sessions;
* (further sections are added below, one per finding)

HOW IT RUNS. Pure functions and part12's Flask app and database, with every outside call stood in
for (part20's _patch / _patched, undone at the end of each block). Nothing touches the network,
sudo, a real host or the checkout's data/.
"""
import os as _os64
import types as _types64

from unit.part01 import check, skip
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_client
from unit.part20 import _patch, _patched
from unit.part47 import _cut47, _node47
from unit.part61 import _r15d_arm61

# The route blocks below run with part61's transport tripwire armed, and the part ends by reading
# what it recorded (review 1012a): each stubs only the leaf it names, so a host call on a passing
# path would have run a real local shell (as root on CI's root leg) with the part green.
_TRIP64_START = len(_P9_TRIPPED)

import app as _app64  # noqa: E402
from panel.db.models import GameServer, RemoteServer, User, UserSession, db  # noqa: E402
from panel.security import auth as _auth64  # noqa: E402
from panel.services import game_ports as _gp64  # noqa: E402
from panel.routes import _shared as _sh64  # noqa: E402

NS = _types64.SimpleNamespace
# A documentation address (TEST-NET-1), built from its parts so no address literal is added.
_DOC64 = ".".join(["192", "0", "2", "64"])
_ROOT64 = _os64.path.dirname(_os64.path.dirname(_os64.path.dirname(_os64.path.abspath(__file__))))


def _try64(fn, *a, **k):
    """Return fn's answer, or the NAME of the exception it raised (so a revert fails by name)."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - which class arrives IS the check
        return type(exc).__name__


def _host64(name):
    r = RemoteServer(name=name, host=_DOC64, port=22, username="admin", auth_method="key",
                     auth_credential="", is_online=True)
    db.session.add(r)
    db.session.commit()
    return r


def _gone64(row):
    """Delete `row` behind the session's back (another session's commit), then expire it.

    As the pin-store commit inside the SSH call does: its next read raises ObjectDeletedError.
    """
    tbl = row.__table__
    with db.engine.begin() as conn:
        conn.execute(tbl.delete().where(tbl.c.id == row.id))
    db.session.expire(row)


def _drop64(*names):
    with _p9.app_context():
        for model in (GameServer, RemoteServer):
            for row in model.query.filter(model.name.in_(names)).all():
                db.session.delete(row)
        db.session.commit()


# ── A01: a row deleted mid-pass is logged, and the pass goes on to the next one ──────────────────
_N64 = ("p64-wl-a", "p64-wl-b", "p64-nt-a", "p64-nt-b")
try:
    with _p9.app_context():
        for _n64 in _N64:
            _host64(_n64)
        _gsh64 = RemoteServer.query.filter_by(name="p64-nt-a").first()
        for _s64 in ("p64gsa", "p64gsb", "p64gsc"):
            db.session.add(GameServer(remote_id=_gsh64.id, name=_s64, short_name=_s64,
                                      game_type="csgo", port=27064, installed=True, status="offline"))
        db.session.commit()
    _seen64 = []

    def _wl64(remote, wl, unban_ip=None):
        name = remote.name
        _seen64.append(name)
        if name == "p64-wl-a":
            _gone64(remote)
            raise RuntimeError("stand-in: the SSH call failed")

    with _patched():
        _r15d_arm61()       # a host loop over the shared database: tripwired too (review 1015a)
        _patch(_app64, "remote_set_fail2ban_ignoreip", _wl64)
        _wlr64 = _try64(_app64._apply_whitelist_to_remotes, _p9)
    check("whitelist push: a remote deleted mid-pass is logged and the next remote still gets the "
          "whitelist (the except's own `remote.id` raised ObjectDeletedError and ended the thread)",
          _wlr64 is None and "p64-wl-b" in _seen64 and _seen64.index("p64-wl-b") > _seen64.index("p64-wl-a"),
          repr((_wlr64, _seen64)))

    _nt64, _up64 = [], []

    def _ntc64(r):
        name = r.name
        _nt64.append(name)
        if name == "p64-nt-a":
            raise RuntimeError("stand-in: the gamedig install failed")
        if name == "p64-wl-b":
            _gone64(r)
            raise RuntimeError("stand-in: deleted during its own install")

    def _upg64(remote, short_name, lgsm_name, game_type=None, port=None, query_type=None):
        _up64.append(short_name)
        if short_name == "p64gsa":
            _gone64(db.session.get(GameServer, _gsa64))
            raise RuntimeError("stand-in: deleted during its cron upgrade")

    with _p9.app_context():
        _gsa64 = GameServer.query.filter_by(short_name="p64gsa").first().id
    with _patched():
        _r15d_arm61()
        _patch(_app64, "ensure_node_tools_cron", _ntc64)
        _patch(_app64._sm, "upgrade_managed_cron_tracking", _upg64)
        # The pass asks game_account_write_refusal before each rewrite (review 1012d), a host round
        # trip stood in for here as a plain game account.
        _patch(_sh64, "game_account_write_refusal", lambda *a, **k: None)
        _ntr64 = _try64(_app64._node_tools_cron_pass, _p9)
    check("node-tools pass: a host deleted during its own install is logged and the hosts after it, "
          "and every game server's cron upgrade, still run (`r.name` in the except ended the pass)",
          # ...hosts AFTER it: rows come back in rowid order today, so this held only by that order
          # (review 1012a); the deleted host has to have been reached before one that still ran.
          _ntr64 is None and "p64-nt-a" in _nt64 and "p64-nt-b" in _nt64 and "p64-wl-b" in _nt64
          and max(_nt64.index("p64-nt-a"), _nt64.index("p64-nt-b")) > _nt64.index("p64-wl-b"),
          repr((_ntr64, _nt64)))
    check("node-tools pass: ...and a game server deleted during its cron upgrade does not stop the "
          "next one's (`gs.name` in the except)",
          _ntr64 is None and _up64.index("p64gsb") > _up64.index("p64gsa") if "p64gsb" in _up64 else False,
          repr((_ntr64, _up64)))

    _rc64 = []

    def _rrow64(host, row, reading, rules):
        _rc64.append(reading)
        if reading == "first":
            _gone64(row)
            raise RuntimeError("stand-in: the re-read failed")
        return None

    with _p9.app_context():
        _rows64 = [(GameServer.query.filter_by(short_name=n).first(), t)
                   for n, t in (("p64gsb", "first"), ("p64gsc", "second"))]
        with _patched():
            _patch(_gp64, "_reconcile_row", _rrow64)
            _rr64 = _try64(_gp64._reconcile_rows, None, _rows64, None)
    check("startup port re-read: a server deleted while its host's rows are re-read is logged and the "
          "host's next server is still re-read (`row.name` after the rollback raised)",
          _rr64 == [] and _rc64 == ["first", "second"], repr((_rr64, _rc64)))
finally:
    _drop64(*_N64, "p64gsa", "p64gsb", "p64gsc")


# ── A01: a threshold above the endpoint's 100000 cap is refused on the host page ─────────────────
with open(_os64.path.join(_ROOT64, "static", "js", "remote_manage.js"), encoding="utf-8") as _fh64:
    _rmjs64 = _fh64.read()
with open(_os64.path.join(_ROOT64, "templates", "remote_manage.html"), encoding="utf-8") as _fh64:
    _rmhtml64 = _fh64.read()
_th64 = _node47("global.window = global; let toasts = [], posts = [];\n"
                "global.toast = (m, l) => toasts.push([m, l]);\n"
                "global.fetch = (u, o) => { posts.push(o.body); return new Promise(() => {}); };\n"
                "let _autoblockKnown = true; const secBase = () => '';\n"
                "const box = {value: ''};\n"
                "global.document = {getElementById: id => id === 'sec-threshold' ? box : {checked: true}};\n"
                "%s\nconst out = [];\n"
                "for (const v of ['150000', '100000', '0']) { toasts = []; posts = []; box.value = v;\n"
                "  saveThreshold(null); out.push([v, posts.length, toasts.map(t => t[0])]); }\n"
                "console.log(JSON.stringify(out));" % (_cut47(_rmjs64, "function _r15aThresholdOk") + "\n"
                                                        + _cut47(_rmjs64, "function saveThreshold")))
_THNAME64 = ("threshold: the host page refuses 150000 before posting it (the endpoint clamped it to 100000, "
             "and the toast told a superadmin only a superadmin could change it), sends 100000, refuses 0")
if _th64 is None:
    skip(_THNAME64, "node is not installed")
else:
    check(_THNAME64, _th64 == [["150000", 0, ["Enter a number of attempts from 1 to 100000"]],
                               ["100000", 1, []],
                               ["0", 0, ["Enter a number of attempts from 1 to 100000"]]], repr(_th64))
check("threshold: ...and both of the host page's threshold inputs carry max=\"100000\", as Settings' does",
      _rmhtml64.count('min="1" max="100000" class="form-control" id="sec-threshold"') == 2
      and _rmhtml64.count('id="sec-threshold"') == 2)


# ── A01: a password reset clears the account's session rows, as deactivating does ───────────────
def _user64(name):
    u = User(username=name, password_hash=_auth64.hash_password("Str0ng!passw0rd-p64"),
             display_name=name, is_superadmin=False, is_active=True)
    db.session.add(u)
    db.session.commit()
    for k in range(2):
        db.session.add(UserSession(user_id=u.id, sid="p64-%s-%d" % (name, k)))
    db.session.commit()
    return u.id


def _sess64(uid):
    with _p9.app_context():
        u = db.session.get(User, uid)
        return UserSession.query.filter_by(user_id=uid).count(), (u.auth_epoch or 0) if u else None


try:
    with _p9.app_context():
        _rp64, _lo64 = _user64("p64_reset"), _user64("p64_logout")
    with _patched():
        _r15d_arm61()
        _rpr64 = _p9_client(P9_ADMIN).post("/users/%d/edit" % _rp64, data={
            "display_name": "p64_reset", "is_active": "on", "reset_password": "on"})  # nosec B105 - a checkbox value
    check("reset: an admin's password reset on /users clears the account's session rows (they listed "
          "as live sessions, revoked devices among them, until they idled out)",
          _rpr64.status_code in (200, 302) and _sess64(_rp64) == (0, 1),
          repr((_rpr64.status_code, _sess64(_rp64))))
    # A cookie with no sid (the legacy shape _p9_client signs in with) is signed out by the global
    # epoch bump; every device goes with it, so every row must too.
    with _patched():
        _r15d_arm61()
        _lor64 = _p9_client(_lo64).post("/logout")
    check("logout: a legacy cookie's sign-out (the epoch bump: every device) clears every session row",
          _lor64.status_code in (200, 302) and _sess64(_lo64) == (0, 1),
          repr((_lor64.status_code, _sess64(_lo64))))
finally:
    with _p9.app_context():
        for _u64 in User.query.filter(User.username.in_(("p64_reset", "p64_logout"))).all():
            UserSession.query.filter_by(user_id=_u64.id).delete()
            db.session.delete(_u64)
        db.session.commit()


# ── A02/A05: a hand-edited Infinity or true in config.json reads as the default ─────────────────
from unit.part12 import _P9_CFG_PATH, _p9_cfg  # noqa: E402
from panel.ops import backup as _bk64  # noqa: E402
from panel.services import host_reboot as _hr64  # noqa: E402
from panel.services import monitoring as _mon64  # noqa: E402

_CFG64_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
_INF64 = float("inf")
_BAD64 = {"backup_keep_days": _INF64, "full_backup_interval_days": _INF64, "full_backup_keep": _INF64,
          "full_backup_last": _INF64, "autoblock_threshold": _INF64, "reboot_wait_max_hours": _INF64,
          "game_schedules": {"64": {"interval_days": True, "keep": True}}}
_TRUE64 = {"backup_keep_days": True, "autoblock_threshold": True, "reboot_wait_max_hours": True,
           "full_backup_interval_days": True, "game_schedules": {"64": {"interval_days": True, "keep": True}}}


def _read64(cfg):
    """Every reader under test, against `cfg`; each answer, or the name of what it raised."""
    with _patched():
        for _m in (_bk64, _hr64, _mon64):
            _patch(_m, "load_config", lambda: dict(cfg))
        _patch(_bk64, "list_backups", lambda: [])
        gs = _try64(_bk64.game_schedule_from, cfg, 64)
        st = _try64(_bk64.get_settings)
        return {"settings_keep": st if isinstance(st, str) else st.get("keep_days"),
                "full": _try64(_bk64.full_settings_from, cfg),
                "game": gs if isinstance(gs, str) else (gs["interval_days"], gs["keep"]),
                "prune": _try64(_bk64.prune_backups),
                "threshold": _try64(_mon64._autoblock_threshold),
                "wait": _try64(_hr64.wait_max_hours)}


_inf64 = _read64(_BAD64)
_full64 = {"interval_days": _bk64.DEFAULT_FULL_INTERVAL, "keep": _bk64.DEFAULT_FULL_KEEP, "last": 0}
check("config Infinity: the Backups settings, the full-backup defaults, a server's schedule and the daily "
      "prune read the defaults (each raised OverflowError: the Backups page 500'd, old archives never "
      "pruned)",
      _inf64["settings_keep"] == _bk64.DEFAULT_KEEP_DAYS and _inf64["prune"] == 0
      and isinstance(_inf64["full"], dict)
      and {k: _inf64["full"].get(k) for k in _full64} == _full64
      and _inf64["game"] == (_bk64.DEFAULT_FULL_INTERVAL, _bk64.DEFAULT_FULL_KEEP), repr(_inf64))
check("config Infinity: the auto-block threshold and the reboot wait read the defaults (the threshold "
      "raised out of /settings, both Security cards and the auto-block pass)",
      _inf64["threshold"] == _mon64._AUTOBLOCK_DEFAULT_THRESHOLD
      and _inf64["wait"] == _hr64.DEFAULT_WAIT_HOURS, repr(_inf64))
_tru64 = _read64(_TRUE64)
check("config true: a JSON boolean is no number (int(True) is 1: a one-attempt auto-block threshold, a "
      "one-hour reboot wait, a one-day backup retention, a one-day per-server interval)",
      _tru64["threshold"] == _mon64._AUTOBLOCK_DEFAULT_THRESHOLD and _tru64["wait"] == _hr64.DEFAULT_WAIT_HOURS
      and _tru64["settings_keep"] == _bk64.DEFAULT_KEEP_DAYS
      and isinstance(_tru64["full"], dict) and _tru64["full"].get("interval_days") == _bk64.DEFAULT_FULL_INTERVAL
      and _tru64["game"] == (_bk64.DEFAULT_FULL_INTERVAL, _bk64.DEFAULT_FULL_KEEP), repr(_tru64))
_ok64 = _read64({"backup_keep_days": 30, "autoblock_threshold": 7, "reboot_wait_max_hours": 5,
                 "full_backup_interval_days": 3, "game_schedules": {"64": {"interval_days": 4, "keep": 5}}})
check("config numbers: ...and a real number still reads (control)",
      _ok64["settings_keep"] == 30 and _ok64["threshold"] == 7 and _ok64["wait"] == 5
      and _ok64["full"]["interval_days"] == 3 and _ok64["game"] == (4, 5), repr(_ok64))
try:
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), autoblock_threshold=_INF64, session_lifetime_hours=_INF64,
                             remember_days="abc", reboot_wait_max_hours=_INF64))
    with _patched():
        _r15d_arm61()
        _set64 = _p9_client(P9_ADMIN).get("/settings")
    _sbody64 = _set64.get_data(as_text=True)
    check("config Infinity: /settings renders with Infinity / \"abc\" hand-edited into the threshold, the "
          "session lifetime, remember-me and the reboot wait (it answered 500)",
          _set64.status_code == 200 and 'id="s-autoblock"' in _sbody64, repr(_set64.status_code))
finally:
    if _CFG64_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG64_SNAPSHOT)


# ── A03: Remove under "Allow from source" and /firewall/close answer to the lockout guard ───────
from unit.part02 import protect as _protect64  # noqa: E402
from panel.ops.ssh_manager import _core as _smc64  # noqa: E402
from panel.ops.ssh_manager import hosts as _smh64  # noqa: E402

_ADMIN64 = ".".join(["203", "0", "113", "5"])
_S64 = NS(id=-64, host="p64-fw", port=22)
_ONLY_FROM64 = ["22/tcp ALLOW IN %s" % _ADMIN64]
_ONLY_PUBLIC64 = ["22/tcp ALLOW IN Anywhere", "27015/udp ALLOW IN Anywhere"]
_BOTH64 = ["22/tcp ALLOW IN Anywhere", "22/tcp ALLOW IN %s" % _ADMIN64]


def _fwrun64(rules, fn, *a, status=None, **k):
    """fn(*a, **k) against a host whose firewall is `rules` (sshd on 22, no Tailscale).

    -> (answer, the privileged verbs it ran). `status` replaces the read (an unreachable host).
    """
    st = status if status is not None else {
        "installed": True, "enabled": True, "groups": _protect64(NS(port=22), rules, sshd_ports=(22,))}
    ran = []

    def _priv(server, verb, args, **kw):
        ran.append(verb)
        return "", "", 0
    with _patched():
        _patch(_smc64, "run_privileged", _priv)
        _patch(_smc64, "is_local_server", lambda s: False)
        _patch(_smh64.firewall, "remote_ufw_status", lambda s: st)
        got = _try64(fn, *a, **k)
    return got, ran


_fr64 = _fwrun64(_ONLY_FROM64, _smh64.remote_ufw_allow_from, _S64, _ADMIN64, "22", "tcp", allow=False)
check("firewall: Remove under \"Allow from source\" refuses the host's only SSH rule (22/tcp from the "
      "admin's address) and runs no delete (it deleted it: the x beside the same rule refuses)",
      isinstance(_fr64[0], tuple) and _fr64[0][0] is False and "lock you out" in _fr64[0][1]
      and _fr64[1] == [], repr(_fr64))
_fr32_64 = _fwrun64(_ONLY_FROM64, _smh64.remote_ufw_allow_from, _S64, _ADMIN64 + "/32", "22", "tcp",
                    allow=False)
check("firewall: ...and so it does when the source is typed as a /32",
      isinstance(_fr32_64[0], tuple) and _fr32_64[0][0] is False and _fr32_64[1] == [], repr(_fr32_64))
_cp64 = _fwrun64(_ONLY_PUBLIC64, _smh64.remote_ufw_close_port, _S64, 22, "tcp")
check("firewall: POST /firewall/close for 22/tcp refuses the host's only SSH rule, and runs nothing",
      isinstance(_cp64[0], tuple) and _cp64[0][0] is False and "lock you out" in _cp64[0][1]
      and _cp64[1] == [], repr(_cp64))
_ok64 = {"from, with another SSH rule": _fwrun64(_BOTH64, _smh64.remote_ufw_allow_from, _S64, _ADMIN64,
                                                 "22", "tcp", allow=False),
         "close a game port": _fwrun64(_ONLY_PUBLIC64, _smh64.remote_ufw_close_port, _S64, 27015, "udp"),
         "close 22/udp (no such rule)": _fwrun64(_ONLY_PUBLIC64, _smh64.remote_ufw_close_port, _S64, 22, "udp"),
         "force": _fwrun64(_ONLY_PUBLIC64, _smh64.remote_ufw_close_port, _S64, 22, "tcp", force=True)}
check("firewall: ...while a rule that is not the only way in, another port, another protocol and the "
      "panel's own forced moves still delete (control)",
      all(isinstance(v[0], tuple) and v[0][0] is True and len(v[1]) == 1 for v in _ok64.values()),
      repr(_ok64))
_un64 = {"from": _fwrun64(_ONLY_FROM64, _smh64.remote_ufw_allow_from, _S64, _ADMIN64, "22", "tcp",
                          allow=False, status={"installed": False, "unreachable": True}),
         "close": _fwrun64(_ONLY_PUBLIC64, _smh64.remote_ufw_close_port, _S64, 27015, "udp",
                           status={"installed": False, "unreachable": True})}
check("firewall: a by-spec delete on a host whose firewall cannot be read refuses, as the numbered "
      "delete does (\"I could not check\" is not \"it is safe\")",
      all(isinstance(v[0], tuple) and v[0][0] is False and v[1] == [] for v in _un64.values()), repr(_un64))
with open(_os64.path.join(_ROOT64, "panel", "routes", "remote_security.py"), encoding="utf-8") as _fh64:
    _rsec64 = _fh64.read()
with open(_os64.path.join(_ROOT64, "panel", "ops", "ssh_manager", "hosts.py"), encoding="utf-8") as _fh64:
    _hsrc64 = _fh64.read()
check("firewall: the panel's own port moves (change-port's two closes, the SSH port change's revert) "
      "pass force, so the guard does not refuse closing the port the config just stopped naming",
      _rsec64.count('remote_ufw_close_port(local, new_port, "tcp", force=True)') == 1
      and _rsec64.count('remote_ufw_close_port(local, cur_port, "tcp", force=True)') == 1
      and _rsec64.count("remote_ufw_close_port(") == 2
      and _hsrc64.count('remote_ufw_close_port(server, new_port, "tcp", force=True)') == 1)


# ── A03: a rule for a protocol that cannot carry TCP (ufw's portless ones) is no way in ─────────
from panel.ops import system_ops as _so64  # noqa: E402

_PEER64 = ".".join(["198", "51", "100", "64"])
_LB64 = ".".join(["127", "0", "0", "1"])


def _ssh22_64(rules):
    """(the extra rules' is_ssh, 22/tcp protected, 22/tcp warn) beside the one `22/tcp ALLOW IN Anywhere`."""
    gs = _protect64(NS(port=22), ["22/tcp ALLOW IN Anywhere"] + rules, sshd_ports=(22,))
    ssh = [g for g in gs if g["port_label"] == "22/tcp" and g["scope"] == "Any address"][0]
    extra = [g for g in gs if g is not ssh]
    return (any(g["is_ssh"] for g in extra), ssh["protected"], ssh["warn"])


_NOT_TCP64 = {p: ["Anywhere ALLOW IN %s/%s" % (_PEER64, p)]
              for p in ("gre", "esp", "ah", "vrrp", "ipv6", "igmp", "udp", "GRE")}
_NOT_TCP64.update({
    "vrrp on eth0": ["Anywhere on eth0 ALLOW IN %s/vrrp" % _PEER64],
    "on lo": ["Anywhere on lo ALLOW IN Anywhere"],
    "on docker0": ["Anywhere on docker0 ALLOW IN Anywhere"],
    "from loopback": ["Anywhere ALLOW IN %s" % _LB64],
    "OUT": ["Anywhere ALLOW OUT Anywhere on eth0"],
    "FWD": ["Anywhere on eth0 ALLOW FWD Anywhere"],
    "a DENY above the allow": ["Anywhere DENY IN %s" % _PEER64, "Anywhere ALLOW IN %s" % _PEER64],
})
_IN64 = {"from a peer": ["Anywhere ALLOW IN %s" % _PEER64],
         "from a peer over tcp": ["Anywhere ALLOW IN %s/tcp" % _PEER64],
         "on eth0": ["Anywhere on eth0 ALLOW IN Anywhere"]}
_nt64 = {k: _ssh22_64(v) for k, v in _NOT_TCP64.items()}
check("firewall: a source rule for a protocol that cannot carry TCP (gre, esp, ah, vrrp, ipv6, igmp, "
      "udp) is no way in, so the only public 22/tcp stays protected (a GRE, 6in4 or IPsec peer's allow "
      "made it deletable); lo, docker0, loopback, OUT, FWD and a DENY above an allow likewise",
      # The shadowed allow under the DENY is still an SSH rule (is_ssh); what matters is that 22/tcp
      # stays protected with no warning.
      {k: v for k, v in _nt64.items()
       if v[1:] != (True, False) or (v[0] and k != "a DENY above the allow")} == {}, repr(_nt64))
_in64 = {k: _ssh22_64(v) for k, v in _IN64.items()}
check("firewall: ...while an every-port allow from a peer (any protocol, or tcp) or on eth0 is still a "
      "way in, so the public 22/tcp only warns (control)",
      set(_in64.values()) == {(True, False, True)}, repr(_in64))
_TSIF64 = {"to": "Anywhere on tailscale0", "action": "ALLOW", "direction": "IN"}
_tsif64 = {p: _so64.ufw_allows_iface_in([dict(_TSIF64, **{"from": _PEER64 + p})], "tailscale0")
           for p in ("/gre", "/esp", "/ipv6", "/vrrp", "/udp", "/tcp", "")}
check("tailnet lockdown: a whole-tailscale0 allow for gre / esp / ipv6 / vrrp / udp does not read as "
      "letting everything in (it unlocked the tailnet-only lockdown); one for tcp or every protocol does",
      _tsif64 == {"/gre": False, "/esp": False, "/ipv6": False, "/vrrp": False, "/udp": False,
                  "/tcp": True, "": True}, repr(_tsif64))


# ── A03: a rule comment saying "not installed" does not make UFW read as absent ─────────────────
def _pss64(out, rc):
    def _priv(server, verb, args, **kw):
        return (out, "", rc) if verb == "ufw-status" else ("", "", 0)
    with _patched():
        _patch(_smc64, "run_privileged", _priv)
        got = _try64(_smh64.remote_public_ssh_status, _S64, panel_port=5000)
    return got if isinstance(got, str) else {k: got.get(k) for k in ("active", "mode", "installed",
                                                                     "panel_port_open")}


_UFW64 = ("Status: active\n\nTo                         Action      From\n"
          "--                         ------      ----\n"
          "22/tcp                     LIMIT       Anywhere\n"
          "5000/tcp                   ALLOW       Anywhere\n")
_pss_c64 = {c: _pss64(_UFW64 + "27015                      ALLOW       Anywhere                   # %s\n" % c, 0)
            for c in ("plex not installed yet", "map not found")}
check("public SSH card: an active firewall with a rule commented \"plex not installed yet\" or \"map not "
      "found\" still reads active, rate-limited, panel port open (it read as no UFW at all)",
      all(v == {"active": True, "mode": "limit", "installed": None, "panel_port_open": True}
          for v in _pss_c64.values()), repr(_pss_c64))
_pss_m64 = _pss64("", 127)
check("public SSH card: ...and a missing ufw (rc 127) still reads as not installed (control)",
      _pss_m64 == {"active": False, "mode": "unknown", "installed": False, "panel_port_open": False},
      repr(_pss_m64))


# ── A05: a stays-stopped server's row is done only once its moved-aside lock is confirmed gone ──
_GS64 = NS(short_name="p64game", lgsm_name="p64srv", id=-64)


def _none64(confirmed, rollback_=False, queued=True):
    """_act_one for an owner-'none' row whose aside-file drop is (or is not) confirmed."""
    asked = []

    def _plb(remote, user, entries):
        asked.append(list(entries))
        return {"p64srv"} if confirmed else set()
    with _patched():
        _patch(_hr64, "put_locks_back", _plb)
        _patch(_hr64, "_act_panel", lambda *a, **k: ("done", "started"))
        got = _try64(_hr64._act_one, None, _GS64, {"owner": "none", "stop": "stopped", "queued": queued},
                     1000.0, rollback_)
    return got, asked


_nr64 = {"unconfirmed": _none64(False), "confirmed": _none64(True),
         "rollback, unconfirmed": _none64(False, True, False), "rollback, confirmed": _none64(True, True, False)}
check("reboot: a stays-stopped server whose aside lock could not be dropped stays pending (it was "
      "reported done and the file left, which the host's next panel reboot re-armed as a live lock)",
      _nr64["unconfirmed"][0] is None and _nr64["unconfirmed"][1] == [[("p64srv", "none")]]
      and _nr64["rollback, unconfirmed"][0] is None, repr(_nr64))
check("reboot: ...and once the drop is confirmed it is done, stopped (or, in a rollback of a stop "
      "that was not queued, started again) (control)",
      _nr64["confirmed"][0] == ("done", "stopped") and _nr64["rollback, confirmed"][0] == ("done", "started"),
      repr(_nr64))


# ── A03 lead: a console command that starts with "-" is typed, not read as a send-keys flag ─────
import shlex as _shlex64  # noqa: E402


def _tmux_positionals64(script):
    """What tmux's send-keys would type, from the script's send-keys words, parsed as tmux parses.

    tmux's args_parse (arguments.c) reads flags until a word that does not start with "-", or a
    "--" (consumed); -t takes the next word as its value. Every word after that is a key to send.
    """
    words = _shlex64.split(script[script.index("send-keys") + len("send-keys"):])
    i, flags = 0, []
    while i < len(words) and words[i].startswith("-") and words[i] != "-":
        if words[i] == "--":
            i += 1
            break
        if words[i] == "-t":
            i += 2
            continue
        flags.append(words[i])
        i += 1
    return flags, words[i:]


_sent64 = {}
for _cmd64 in ("-R", "-X cancel", "say hello"):
    with _patched():
        _patch(_smc64, "shell_as_game_user", lambda s, u, inner, **k: (inner, "", 0))
        _out64 = _try64(_smc64.send_console_command, _S64, "p64game", _cmd64, selfname="p64srv")
    _sent64[_cmd64] = (_tmux_positionals64(_out64[0]) if isinstance(_out64, tuple)
                       and "send-keys" in str(_out64[0]) else _out64)
check("console send: a command starting with \"-\" (-R, -X cancel) is typed into the console, not taken "
      "as send-keys' own flag (no `--` ended tmux's option parsing)",
      # -l (typed as characters, part67), then Enter in a second send-keys of the same tmux command.
      _sent64 == {c: (["-l"], [c, ";", "send-keys", "-t", "p64srv", "Enter"]) for c in ("-R", "-X cancel", "say hello")},
      repr(_sent64))


# ── A03 lead: a multicast / broadcast destination takes no TCP, so it is no way in ──────────────
_MC64 = {"to mDNS multicast": ["%s ALLOW IN Anywhere" % ".".join(["224", "0", "0", "251"])],
         "to an IPv6 multicast group": ["ff02::fb ALLOW IN Anywhere"],
         "to the limited broadcast": ["%s ALLOW IN Anywhere" % ".".join(["255"] * 4)]}
_mc64 = {k: _ssh22_64(v) for k, v in _MC64.items()}
_uc64 = _ssh22_64(["%s ALLOW IN Anywhere" % _PEER64])
check("firewall: an allow to a multicast group or the limited broadcast (TCP never arrives there) is no "
      "way in, so the only public 22/tcp stays protected; one to a unicast address is (control)",
      set(_mc64.values()) == {(False, True, False)} and _uc64 == (True, False, True), repr((_mc64, _uc64)))
check("part64: nothing its routes and host loops drove reached a real transport (every host call was "
      "stubbed)",
      len(_P9_TRIPPED) == _TRIP64_START, repr(_P9_TRIPPED[_TRIP64_START:][:6]))
