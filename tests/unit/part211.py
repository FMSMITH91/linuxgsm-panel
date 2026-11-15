"""Part 211 of the unit suite: databases on another machine (Tailscale), the firewall, the narrow grant.

* The probe reads the host's ufw (one ufw-status, only for a server listening beyond loopback and the
  tailnet): blocked -> no exposed warning, allowed from anywhere / inactive / default allow -> exposed,
  unreadable -> "couldn't check", never exposed.
* The narrow grant the tab offers: what SHOW GRANTS prints for it reads 'scoped' in the helper, its
  privileged.py twin and the remote shell; any one line missing reads 'lacks_grants'; MySQL's
  partial_revokes turns it down; the existence check needs only mysql.user's User column.
* The verbs: a sign-in at a tailnet address only (both twins refuse every other), TLS off only there,
  an account for one game-host address (never localhost, 127.0.0.1 or a wildcard), no secret on argv.
* The routes through part12's app with the host side recorded: only a superadmin chooses the server,
  a new database is kept only after its account signs in from the game host, the dump, restore,
  move and host removal go where they must, and the read-only overview page shows each viewer only
  the servers they can see.
Nothing reaches a host or data/.
"""
import subprocess as _sp211  # nosec B404 - bash over the renderings this part checks
from types import SimpleNamespace as _NS211

from unit.part01 import check, eq
from unit.part05 import _helper
from unit.part12 import (P9_ADMIN, P9_HOST, P9_HOST2, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_new_server, _p9_delete_server, _p9_patch, _p9_restore_all)
from panel.core.config import encrypt_secret as _enc211
from panel.db.models import (AuditLog as _AL211, DatabaseEndpoint as _EP211, EndpointClient as _EC211,
                             GameDatabase as _GD211, Group as _G211, HostDatabaseServer as _HD211,
                             RemoteServer as _RS211, User as _U211, db as _db211)
from panel.ops.ssh_manager import _core as _core211, databases as _dbs211
from panel.routes import databases as _dbr211, databases_net as _net211
from panel.security import auth as _auth211, privileged as _priv211

_trips211 = len(_P9_TRIPPED)
_R211 = {}

# ── 1. the firewall: is a server that listens on the network reachable from other machines? ──────
_UFW_HEAD211 = ("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
                "New profiles: skip\n\nTo                         Action      From\n"
                "--                         ------      ----\n")
# A CloudPanel host as found: MySQL on every address, ufw deny by default, tailscale0, games, the web.
_CLOUDPANEL211 = (_UFW_HEAD211 + "Anywhere on tailscale0     ALLOW IN    Anywhere\n"
                  "27015/udp                  ALLOW IN    Anywhere\n80/tcp                     ALLOW IN    Anywhere\n"
                  "443/tcp                    ALLOW IN    Anywhere\n"
                  "Anywhere (v6) on tailscale0 ALLOW IN    Anywhere (v6)\n80/tcp (v6)                ALLOW IN    Anywhere (v6)\n")
_LISTEN_ALL211 = ("pkg=mysql-server\t8.4.11\nactive.mysql=active\nlisten=*:3306\nsocket_root=ok\n"
                  "var.version=8.4.11-0ubuntu1\nvar.bind_address=*\nvar.port=3306\nvar.native=ACTIVE\n")
_UFW211 = {
    "cloudpanel: listening, ufw lets only tailscale0 in": ((_CLOUDPANEL211, "", 0), ["firewalled"]),
    "3306 allowed from Anywhere": ((_CLOUDPANEL211 + "3306/tcp                   ALLOW IN    Anywhere\n", "", 0),
                                   ["exposed"]),
    "33060 (X protocol) allowed from a LAN": ((_CLOUDPANEL211 + "33060                      ALLOW IN    "
                                               "192.0.2.0/24\n", "", 0), ["exposed"]),
    "3306 allowed on tailscale0 only": ((_UFW_HEAD211 + "3306/tcp on tailscale0     ALLOW IN    Anywhere\n", "", 0),
                                        ["firewalled"]),
    "a port range holding 3306": ((_UFW_HEAD211 + "3000:4000/tcp              ALLOW IN    Anywhere\n", "", 0),
                                  ["exposed"]),
    "ufw inactive": (("Status: inactive\n", "", 0), ["exposed"]),
    "ufw not installed": (("", "", 127), ["exposed"]),
    "default incoming allow": ((_UFW_HEAD211.replace("deny (incoming)", "allow (incoming)"), "", 0), ["exposed"]),
    "ufw-status failed": (("", "sudo: a password is required", 1), ["firewall_unknown"]),
    "ufw-status empty": (("", "", 0), ["firewall_unknown"]),
}
_RP211 = []
_ANS211 = {}


def _fake_rp211(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, secrets=None):
    _RP211.append((verb, list(args), secrets))
    ans = _ANS211.get(verb, ("", "", 0))
    return ans(args) if callable(ans) else ans


_rp_saved211 = _core211.run_privileged
_core211.run_privileged = _fake_rp211
try:
    _wrong211 = []
    for _k211, (_ufw211, _want211) in _UFW211.items():
        _ANS211.clear()
        _ANS211.update({"db-probe": (_LISTEN_ALL211, "", 0), "ufw-status": _ufw211})
        _got211 = _dbs211.probe(_NS211(id=1))["warnings"]
        if _got211 != _want211:
            _wrong211.append("%s: %r" % (_k211, _got211))
    eq("databases firewall: a server listening on every address is exposed only when the host's ufw lets "
       "another machine reach 3306/33060 (or is off, missing, or allows by default); a firewall that could "
       "not be read says so instead", _wrong211, [])
    _ANS211.clear()
    _RP211.clear()
    _ANS211["db-probe"] = (_LISTEN_ALL211.replace("*:3306", "127.0.0.1:3306").replace("=*", "=127.0.0.1"), "", 0)
    _p211 = _dbs211.probe(_NS211(id=1))
    _R211["loopback"] = (_p211["warnings"], [c[0] for c in _RP211])
    _RP211.clear()
    _ANS211["db-probe"] = (_LISTEN_ALL211.replace("*:3306", "100.64.7.9:3306").replace("=*", "=100.64.7.9"), "", 0)
    _p211 = _dbs211.probe(_NS211(id=1))
    _R211["tailnet"] = (_p211["warnings"], [c[0] for c in _RP211])
    _RP211.clear()
    _ANS211.update({"db-probe": (_LISTEN_ALL211, "", 0), "ufw-status": (_CLOUDPANEL211, "", 0)})
    _dbs211.probe(_NS211(id=1))
    _R211["ufw_call"] = [(c[0], c[1]) for c in _RP211]
finally:
    _core211.run_privileged = _rp_saved211
check("databases firewall: a server on loopback only is not exposed, and its firewall is not read (no extra call)",
      _R211.get("loopback") == ([], ["db-probe"]), repr(_R211.get("loopback")))
check("databases firewall: a server on a tailnet address only reads as reachable over Tailscale, no firewall read",
      _R211.get("tailnet") == (["tailnet"], ["db-probe"]), repr(_R211.get("tailnet")))
check("databases firewall: the firewall is read with the Network tab's own read-only verb, once",
      _R211.get("ufw_call") == [("db-probe", []), ("ufw-status", ["verbose"])], repr(_R211.get("ufw_call")))
_hl211 = _dbs211.with_login_facts({"listeners": ["*:3306"], "firewall": "blocked", "port": 3306},
                                  {"version": "8.4.11", "bind_address": "*", "native": "ACTIVE"})
check("databases firewall: a probe completed through a stored login keeps the firewall's verdict",
      _hl211["warnings"] == ["firewalled"], repr(_hl211["warnings"]))
_js_tab211 = open("panel/static/js/server_databases.js", encoding="utf-8").read()
check("databases firewall: the tab explains every reach key (exposed and couldn't-check as warnings, "
      "firewalled and tailnet as plain lines)",
      all(k + ":" in _js_tab211 for k in ("exposed", "firewall_unknown", "firewalled", "tailnet")),
      "a key without words in server_databases.js")

# ── 2. the narrow grant for a dedicated panel login ──────────────────────────────────────────────
_SQL211 = _dbs211.scoped_grant_sql("Pw211")
# What SHOW GRANTS prints for those statements on MySQL 8 (backquoted columns) and MariaDB (bare).
_SHOW_MY211 = ("GRANT USAGE ON *.* TO `linuxgsm_panel`@`127.0.0.1`\n"
               "GRANT CREATE USER ON *.* TO `linuxgsm_panel`@`127.0.0.1`\n"
               "GRANT SELECT (`Host`, `User`) ON `mysql`.`user` TO `linuxgsm_panel`@`127.0.0.1`\n"
               "GRANT ALL PRIVILEGES ON `gs%`.* TO `linuxgsm_panel`@`127.0.0.1` WITH GRANT OPTION\n")
_SHOW_MA211 = ("GRANT CREATE USER ON *.* TO `linuxgsm_panel`@`127.0.0.1` IDENTIFIED BY PASSWORD '*0A1B'\n"
               "GRANT SELECT (Host, User) ON `mysql`.`user` TO `linuxgsm_panel`@`127.0.0.1`\n"
               "GRANT ALL PRIVILEGES ON `gs%`.* TO `linuxgsm_panel`@`127.0.0.1` WITH GRANT OPTION\n")
eq("databases grant: the statements the tab offers make exactly the narrow grant",
   _SQL211.splitlines(),
   ["CREATE USER 'linuxgsm_panel'@'127.0.0.1' IDENTIFIED BY 'Pw211';",
    "GRANT CREATE USER ON *.* TO 'linuxgsm_panel'@'127.0.0.1';",
    "GRANT SELECT (User, Host) ON mysql.user TO 'linuxgsm_panel'@'127.0.0.1';",
    "GRANT ALL PRIVILEGES ON `gs%`.* TO 'linuxgsm_panel'@'127.0.0.1' WITH GRANT OPTION;"])


def _shell_verdict211(text):
    """The remote shell's verdict on SHOW GRANTS `text` (bash over _db_scoped_sh)."""
    # bash over the panel's own fixed rendering; `text` is an argument ($1), never part of the script.
    r = _sp211.run(["bash", "-c", 'o=$1; if %s; then echo scoped; else echo no; fi' % _priv211._db_scoped_sh(),  # nosec B603 B607
                    "_", text], capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


_drops211 = [_SHOW_MY211.replace(line + "\n", "") for line in _SHOW_MY211.splitlines()[1:]]
_drops211.append(_SHOW_MY211.replace(" WITH GRANT OPTION", ""))
eq("databases grant: MySQL's and MariaDB's SHOW GRANTS for it read 'scoped' in the helper, privileged.py and the "
   "remote shell",
   [(_helper.db_grants_verdict(t), _priv211.db_grants_verdict(t), _shell_verdict211(t)) for t in (_SHOW_MY211, _SHOW_MA211)],
   [("scoped", "scoped", "scoped")] * 2)
eq("databases grant: ...and with any one of its lines (or the GRANT OPTION) missing, it does not",
   [(_helper.db_grants_verdict(t), _priv211.db_grants_verdict(t), _shell_verdict211(t)) for t in _drops211],
   [("lacks_grants", "lacks_grants", "no")] * 4)
check("databases grant: whether a name is free is read from mysql.user's User column only (the narrow grant's "
      "column privilege), in both twins",
      "COUNT(User) FROM mysql.user" in _priv211.db_sql_exists("gs1_a")
      and _helper.db_sql_exists("gs1_a") == _priv211.db_sql_exists("gs1_a"), _priv211.db_sql_exists("gs1_a"))
check("databases grant: the probe asks partial_revokes in both twins (the narrow grant's gs% is literal with it on)",
      "'partial_revokes'" in _priv211.DB_SQL_PROBE and _helper.DB_SQL_PROBE == _priv211.DB_SQL_PROBE)
_rp_saved211 = _core211.run_privileged
_core211.run_privileged = _fake_rp211
try:
    _vrd211 = []
    for _pr211 in ("OFF", "ON", ""):
        _ANS211["db-admin-check"] = ("scoped\nvar.version=8.0.46\nvar.partial_revokes=%s\n" % _pr211, "", 0)
        _vrd211.append(_dbs211.admin_check(_NS211(id=1), 3306, "linuxgsm_panel", "Pw211x")[0])
    _R211["scoped_verdicts"] = _vrd211
finally:
    _core211.run_privileged = _rp_saved211
eq("databases grant: the service takes the narrow grant as a working login, unless partial_revokes is ON",
   _R211.get("scoped_verdicts"), ["ok", "partial_revokes", "ok"])

# ── 3. the verbs: a tailnet address only, TLS off only there, one account host ───────────────────
_AUTHS211 = ["tcp3306@100.64.0.5", "tcp3306@100.127.255.254", "tcp3306@fd7a:115c:a1e0::5",
             "tcp3306@10.0.0.5", "tcp3306@192.168.1.2", "tcp3306@203.0.113.9", "tcp3306@127.0.0.1",
             "tcp3306@100.128.0.1", "tcp3306@100.064.0.5", "tcp3306@db.example.net", "tcp3306@%",
             "tcp3306@100.64.0.5 ", "tcp3306@"]


def _verdicts211(fn, values, err):
    out = []
    for v in values:
        try:
            fn(v)
            out.append("ok")
        except err:
            out.append("no")
    return out


eq("databases verbs: a sign-in at another machine is a tailnet address only, in both twins alike",
   (_verdicts211(_helper.v_db_auth, _AUTHS211, ValueError), _verdicts211(_priv211._db_auth, _AUTHS211, _priv211.VerbError)),
   (["ok"] * 3 + ["no"] * 10, ["ok"] * 3 + ["no"] * 10))
_HOSTS211 = ["100.70.1.2", "%", "100.70.1.%", "localhost", "127.0.0.1", "10.0.0.2", "100.70.1.2/32", "::1", ""]
eq("databases verbs: an account is made for one tailnet address, never a wildcard, a range or this machine",
   (_verdicts211(_helper.db_client_host, _HOSTS211, ValueError),
    _verdicts211(_priv211.db_client_host, _HOSTS211, _priv211.VerbError)),
   (["ok"] + ["no"] * 8, ["ok"] + ["no"] * 8))
_C211 = _priv211.db_sql_create("mysql", "gs12_lp", "native", 30, "A" * 24, "100.70.1.2")
check("databases verbs: a database for a game host on another machine gets ONE account, at that host's address "
      "(no localhost, no 127.0.0.1, no %), in both twins byte for byte",
      _C211.count("CREATE USER") == 1 and "'gs12_lp'@'100.70.1.2'" in _C211 and "localhost" not in _C211
      and "127.0.0.1" not in _C211 and "'%'" not in _C211
      and _helper.db_sql_create("mysql", "gs12_lp", "native", 30, "A" * 24, "100.70.1.2") == _C211, _C211)
check("databases verbs: a password change and a drop name that one account only; a local database still has its two",
      _priv211.db_sql_password("mysql", "gs12_lp", "native", "A" * 24, "100.70.1.2").count("ALTER USER") == 1
      and _priv211.db_sql_drop("gs12_lp", "100.70.1.2").count("DROP USER") == 1
      and _priv211.db_sql_drop("gs12_lp").count("DROP USER") == 2
      and _helper.db_sql_drop("gs12_lp", "100.70.1.2") == _priv211.db_sql_drop("gs12_lp", "100.70.1.2"))
eq("databases verbs: moving an account is RENAME USER between two tailnet addresses, in both twins",
   (_priv211.db_sql_rehost("gs12_lp", "100.70.1.2", "100.70.1.3"),
    _helper.db_sql_rehost("gs12_lp", "100.70.1.2", "100.70.1.3")),
   ("RENAME USER 'gs12_lp'@'100.70.1.2' TO 'gs12_lp'@'100.70.1.3';\n",) * 2)
check("databases verbs: TLS is turned off only for a server at a tailnet address (WireGuard carries it), never "
      "for 127.0.0.1, in both twins",
      "--loose-skip-ssl" in _priv211._db_conn_sh("tcp3306@100.64.0.5")
      and "ssl" not in _priv211._db_conn_sh("tcp3306") and "ssl" not in _priv211._db_conn_sh("socket")
      and _helper.db_conn_net("tcp3306@100.64.0.5") == _priv211.db_conn_net("tcp3306@100.64.0.5")
      and not any("ssl" in a for a in _helper.db_conn_net("tcp3306")))
_imp211 = _priv211.remote_command("db-import", ["mariadb", "3306@100.64.0.5", "pmcserver", "gs12_lp"])
check("databases verbs: a restore from another machine connects to the server's tailnet address, TLS off; a local "
      "one to 127.0.0.1 without",
      _imp211.rstrip().endswith("3306 \"$C\" 100.64.0.5 --loose-skip-ssl --loose-ssl-mode=DISABLED")
      and _priv211.remote_command("db-import", ["mariadb", "3306", "pmcserver", "gs12_lp"])
      .rstrip().endswith("3306 \"$C\" 127.0.0.1"), _imp211[-160:])
_PW211, _APW211 = "Zremote211" + "q" * 20, "Zadmin211" + "w" * 12
_argv_leaks211 = []
for _verb211, _args211, _sec211 in (
        ("db-create", ["mysql", "tcp3306@100.64.0.5", "gs12_lp", "native", "30", "100.70.1.2"],
         {"admin": ("panel", _APW211), "pw": _PW211}),
        ("db-password", ["mysql", "tcp3306@100.64.0.5", "gs12_lp", "native", "100.70.1.2"],
         {"admin": ("panel", _APW211), "pw": _PW211}),
        ("db-rehost", ["mysql", "tcp3306@100.64.0.5", "gs12_lp", "100.70.1.2", "100.70.1.3"], {"admin": ("panel", _APW211)}),
        ("db-dump", ["mysql", "tcp3306@100.64.0.5", "game", "pmcserver", "gs12_lp"], {"admin": ("gs12_lp", _PW211)})):
    _cmd211 = _priv211.remote_command(_verb211, _args211) + " ".join(_priv211.helper_argv(_verb211, _args211))
    _stdin211 = _priv211.remote_stdin(_verb211, _args211, _sec211) + _priv211.helper_stdin(_verb211, _args211, _sec211)
    if _PW211 in _cmd211 or _APW211 in _cmd211 or not (_PW211 in _stdin211 or _APW211 in _stdin211):
        _argv_leaks211.append(_verb211)
eq("databases verbs: no password of a remote database or its admin login is ever on a command line (stdin only)",
   _argv_leaks211, [])
check("databases verbs: db-rehost is a stdin verb in the helper (its sign-in arrives there)",
      "db-rehost" in _helper.STDIN_VERBS and "db-rehost" in _helper.ACTIONS and "db-rehost" in _priv211.DB_VERBS)

# ── 4. the routes, with the host side recorded ──────────────────────────────────────────────────
_CALLS211 = []
_ANSW211 = {}
_TS211 = {}


def _rec211(name, result_key=None):
    def f(*a, **k):
        _CALLS211.append((name,) + a)
        return _ANSW211.get(result_key or name)
    return f


def _target211(remote, hostdb):
    """What a call was aimed at: (host id, sign-in, account host, admin user)."""
    return (getattr(remote, "id", None), _dbs211._auth(hostdb), getattr(hostdb, "client", None),
            getattr(hostdb, "admin_user", None))


def _user211(tag, perms, hosts):
    with _p9.app_context():
        g = _G211(name="p211_" + tag, description="", is_default=False)
        g.set_permissions(perms)
        g.servers.extend(_db211.session.get(_RS211, h) for h in hosts)
        u = _U211(username="p211_" + tag, password_hash=_auth211.hash_password("Str0ng!passw0rd-p211"),
                  display_name="p211", is_superadmin=False, is_active=True)
        u.groups.append(g)
        _db211.session.add_all([g, u])
        _db211.session.commit()
        return u.id, g.id


def _rows211(sid):
    with _p9.app_context():
        return [(r.name, r.endpoint_id, r.account_host) for r in _GD211.query.filter_by(game_server_id=sid).all()]


_MINE211, _SID211, _SID2_211 = [], None, None
try:
    _p9_arm(who="part211")
    for _n211 in ("create", "set_password", "drop", "dump", "restore", "rehost"):
        _p9_patch(_dbs211, _n211, (lambda name: lambda remote, hostdb, *a: (
            _CALLS211.append((name, _target211(remote, hostdb)) + a), _ANSW211.get(name, (True, "")))[1])(_n211))
    _p9_patch(_dbs211, "sizes", lambda remote, hostdb, account, names: (
        _CALLS211.append(("sizes", _target211(remote, hostdb), account, list(names))),
        {"sizes": {n: 1 for n in names}, "dumps": {}})[1])
    _p9_patch(_dbs211, "sign_in_check", lambda remote, ep, name, pw: (
        _CALLS211.append(("sign_in", getattr(remote, "id", None), ep.address, name)), _ANSW211.get("sign_in", ("ok", "")))[1])
    _p9_patch(_dbs211, "endpoint_check", lambda remote, address, port, user, pw: (
        _CALLS211.append(("endpoint_check", getattr(remote, "id", None), address, port, user)),
        _ANSW211.get("endpoint_check", ("ok", {"version": "10.11.14-MariaDB", "native": "ACTIVE", "seen": "100.70.1.2"})))[1])
    _p9_patch(_dbs211, "probe", lambda remote: (
        _CALLS211.append(("probe", getattr(remote, "id", None))),
        dict(_ANSW211.get("probe") or {"state": "ready", "flavor": "mariadb", "listeners": ["0.0.0.0:3306"],
                                       "socket_root": "ok", "warnings": []}))[1])
    _p9_patch(_dbs211, "install_client", lambda remote, flavor: (_CALLS211.append(("install_client", remote.id)), True)[1])
    _p9_patch(_net211, "tailnet_ip", lambda remote, force=False: _TS211.get(remote.id, ""))
    _p9_patch(_dbr211, "game_account_write_refusal", lambda remote, user, **k: None)
    _SID211 = _p9_new_server(P9_HOST, "p211u", "pmc", 25565, name="p211 paper")
    _SID2_211 = _p9_new_server(P9_HOST2, "p211v", "pmc", 25566, name="p211 other")
    _MGR211 = _user211("mgr", ["manage_databases", "view_servers", "view_files"], [P9_HOST])
    _OP211 = _user211("op", ["manage_databases", "manage_remotes", "view_servers"], [P9_HOST, P9_HOST2])
    _NONE211 = _user211("none", ["view_files"], [P9_HOST])
    _MINE211 = [_MGR211, _OP211, _NONE211]
    _A211, _M211 = _p9_client(P9_ADMIN), _p9_client(_MGR211[0])
    _ep_api211 = "/api/remote/%d/databases/endpoint" % P9_HOST
    _api211 = "/api/server/%d/databases" % _SID211
    _TS211.update({P9_HOST: "100.70.1.2", P9_HOST2: "100.80.0.9"})
    _EXT211 = {"kind": "external", "address": "100.90.0.4", "port": 3306, "user": "panel", "password": _APW211}

    # 4a. who may choose the server, and what an address may be
    _R211["choose_op"] = _p9_client(_OP211[0]).post(_ep_api211, json=_EXT211).status_code
    _CALLS211.clear()
    _R211["choose_lan"] = (_A211.post(_ep_api211, json=dict(_EXT211, address="10.0.0.4")).status_code,
                           [c[0] for c in _CALLS211])
    _CALLS211.clear()
    _r211 = _A211.post(_ep_api211, json=_EXT211)
    _R211["choose_ext"] = (_r211.status_code, [c for c in _CALLS211 if c[0] == "endpoint_check"])
    with _p9.app_context():
        _e211 = _EP211.query.filter_by(kind="external", address="100.90.0.4").first()
        _c211 = _EC211.query.filter_by(remote_id=P9_HOST).first()
        _R211["ext_row"] = (None if _e211 is None else (_e211.admin_user, _APW211 in (_e211.admin_secret or ""),
                                                        bool(_e211.admin_secret)),
                            None if _c211 is None else _c211.seen_addr)
        _R211["ext_audit"] = [(a.action, a.detail) for a in _AL211.query.filter_by(action="db_endpoint_allow").all()]

    # 4b. a database there: made from the game host for its address, kept only once it signs in
    _CALLS211.clear()
    _r211 = _M211.post(_api211, json={"name": "lp"})
    _R211["add_ext"] = (_r211.status_code, [c for c in _CALLS211 if c[0] in ("create", "sign_in")], _rows211(_SID211))
    _CALLS211.clear()
    _ANSW211["sign_in"] = ("unreachable", "")
    _r211 = _M211.post(_api211, json={"name": "core"})
    _R211["add_unreach"] = (_r211.status_code, [c[0] for c in _CALLS211], _p9_json(_r211).get("message", ""),
                            [r[0] for r in _rows211(_SID211)])
    _ANSW211["sign_in"] = ("denied", "100.70.9.9")
    _r211 = _M211.post(_api211, json={"name": "plan"})
    _R211["add_seen"] = (_r211.status_code, _p9_json(_r211).get("message", ""))
    _ANSW211.pop("sign_in")

    # 4c. the list names the server's address; sizes asked where the accounts are
    _CALLS211.clear()
    _lst211 = _p9_json(_M211.get(_api211))
    _R211["list"] = ([(d["host"], d["account_host"], "100.90.0.4:3306" in d["snippets"][0]["text"])
                      for d in _lst211.get("databases", [])], (_lst211.get("endpoint") or {}).get("address"),
                     [c[:3] for c in _CALLS211 if c[0] == "sizes"])
    _R211["grant_mgr"] = _lst211.get("grant")
    _R211["grant_su"] = (_p9_json(_A211.get(_api211)).get("grant") or {}).get("sql", "")
    with _p9.app_context():
        _db_row211 = _GD211.query.filter_by(game_server_id=_SID211, name="gs%d_lp" % _SID211).first()
        _dbid211 = _db_row211.id if _db_row211 is not None else -1

    # 4d. a backup's dump and a restore run on the game host, as the database's own account
    _CALLS211.clear()
    with _p9.app_context():
        _R211["dump_note"] = _dbr211.dump_for_backup(_SID211, _db211.session.get(_RS211, P9_HOST), "p211u")
    _R211["dump"] = [c for c in _CALLS211 if c[0] == "dump"]
    _CALLS211.clear()
    _M211.post("%s/%d/restore" % (_api211, _dbid211), json={"confirm": "gs%d_lp" % _SID211})
    _R211["restore"] = [c[:2] for c in _CALLS211 if c[0] == "restore"]
    _CALLS211.clear()
    _M211.post("%s/%d/reset-password" % (_api211, _dbid211))
    _R211["reset"] = [c[:2] for c in _CALLS211 if c[0] == "set_password"]

    # 4e. the game host's address changed: the list says so, and Move renames the account
    _TS211[P9_HOST] = "100.70.1.3"
    _lst211 = _p9_json(_M211.get(_api211))
    _R211["moved"] = (_lst211.get("moved_to"), [d.get("moved") for d in _lst211.get("databases", [])])
    _CALLS211.clear()
    _r211 = _M211.post("%s/%d/move" % (_api211, _dbid211))
    _R211["move"] = (_r211.status_code, [c for c in _CALLS211 if c[0] in ("rehost", "sign_in")], _rows211(_SID211))
    _R211["move_viewer"] = _p9_client(_NONE211[0]).post("%s/%d/move" % (_api211, _dbid211)).status_code

    # 4f. a managed host's server: the accounts are made there, as its own row says
    with _p9.app_context():
        _db211.session.add(_HD211(remote_id=P9_HOST2, flavor="mariadb", version="10.11.14-MariaDB",
                                  auth_mode="socket", port=3306))
        _db211.session.commit()
    _ANSW211["probe"] = {"state": "ready", "flavor": "mariadb", "listeners": ["127.0.0.1:3306"], "socket_root": "ok"}
    _r211 = _A211.post(_ep_api211, json={"kind": "managed", "db_remote_id": P9_HOST2})
    _R211["managed_loopback"] = (_r211.status_code, _p9_json(_r211).get("message", ""))
    _ANSW211["probe"] = {"state": "ready", "flavor": "mariadb", "listeners": ["100.80.0.9:3306", "127.0.0.1:3306"],
                         "socket_root": "ok"}
    _R211["managed"] = _A211.post(_ep_api211, json={"kind": "managed", "db_remote_id": P9_HOST2}).status_code
    _CALLS211.clear()
    _M211.post(_api211, json={"name": "mg"})
    _R211["add_managed"] = [c[:2] for c in _CALLS211 if c[0] in ("create", "sign_in")]
    _R211["rows_before_forget"] = sorted(r[1] is not None for r in _rows211(_SID211))
    with _p9.app_context():
        _ep_m211 = _EP211.query.filter_by(kind="managed", remote_id=P9_HOST2).first()
        _ep_m_id211 = _ep_m211.id if _ep_m211 is not None else -1
        _dbr211.forget_remote(P9_HOST2)
        _db211.session.commit()
        _R211["forget"] = (_EP211.query.filter_by(kind="managed", remote_id=P9_HOST2).count(),
                           _GD211.query.filter_by(endpoint_id=_ep_m_id211).count(),
                           _EC211.query.filter_by(endpoint_id=_ep_m_id211).count())

    # 4g. the overview page: a viewer sees only the servers they can see
    with _p9.app_context():
        _db211.session.add(_GD211(remote_id=P9_HOST2, game_server_id=_SID2_211, name="gs%d_far" % _SID2_211,
                                  secret=_enc211(_PW211)))
        _db211.session.commit()
    _ov211 = _M211.get("/databases")
    _R211["overview_mgr"] = (_ov211.status_code, "gs%d_lp" % _SID211 in _ov211.get_data(as_text=True),
                             "gs%d_far" % _SID2_211 in _ov211.get_data(as_text=True),
                             _PW211 in _ov211.get_data(as_text=True))
    _R211["overview_none"] = _p9_client(_NONE211[0]).get("/databases").status_code
    _ov211 = _A211.get("/databases").get_data(as_text=True)
    _R211["overview_su"] = ("gs%d_far" % _SID2_211 in _ov211, 'href="/databases"' in _ov211)
    _R211["nav_none"] = 'href="/databases"' in _p9_client(_NONE211[0]).get("/account").get_data(as_text=True)

    # 4h. back to the host's own server
    _R211["clear_su"] = _A211.post(_ep_api211, json={"clear": True}).status_code
    with _p9.app_context():
        _R211["clear_row"] = _EC211.query.filter_by(remote_id=P9_HOST).count()
finally:
    _p9_restore_all()
    _net211._TS_IPS.clear()
    with _p9.app_context():
        for _sid211 in (_SID211, _SID2_211):
            if _sid211 is not None:
                _GD211.query.filter_by(game_server_id=_sid211).delete()
        _GD211.query.filter(_GD211.remote_id.in_([P9_HOST, P9_HOST2])).delete()
        _EC211.query.filter(_EC211.remote_id.in_([P9_HOST, P9_HOST2])).delete()
        _EP211.query.delete()
        _HD211.query.filter(_HD211.remote_id.in_([P9_HOST, P9_HOST2])).delete()
        for _uid211, _gid211 in _MINE211:
            for _mdl211, _i211 in ((_U211, _uid211), (_G211, _gid211)):
                _row211 = _db211.session.get(_mdl211, _i211)
                if _row211 is not None:
                    _db211.session.delete(_row211)
        _db211.session.commit()
    for _sid211 in (_SID211, _SID2_211):
        if _sid211 is not None:
            _p9_delete_server(_sid211)

_lp211 = "gs%d_lp" % (_SID211 or 0)
check("databases remote: only a superadmin chooses the server a host's databases go to (403 for MANAGE_DATABASES "
      "+ MANAGE_REMOTES)", _R211.get("choose_op") == 403, repr(_R211.get("choose_op")))
check("databases remote: a LAN address is refused before anything is asked of a host (Tailscale only for now)",
      _R211.get("choose_lan") == (400, []), repr(_R211.get("choose_lan")))
check("databases remote: an external server's admin login is checked from the game host at its tailnet address",
      _R211.get("choose_ext", (0, []))[0] == 200
      and _R211.get("choose_ext", (0, []))[1] == [("endpoint_check", P9_HOST, "100.90.0.4", 3306, "panel")],
      repr(_R211.get("choose_ext")))
check("databases remote: the admin login is stored encrypted (no plaintext), and the game host is recorded with "
      "the address the server saw it from", _R211.get("ext_row") == (("panel", False, True), "100.70.1.2"),
      repr(_R211.get("ext_row")))
check("databases remote: the choice is audited with the server and the account host, never the password",
      any(a == "db_endpoint_allow" and "100.70.1.2" in (d or "") for a, d in _R211.get("ext_audit", []))
      and not any(_APW211 in (d or "") for _a, d in _R211.get("ext_audit", [])), repr(_R211.get("ext_audit")))
_ok_add211 = _R211.get("add_ext", (0, [], []))
check("databases remote: a new database is made from the game host on the server for the host's address only, then "
      "its own account signs in from the game host before it is kept",
      _ok_add211[0] == 200
      and [c[:2] for c in _ok_add211[1]] == [("create", (P9_HOST, "tcp3306@100.90.0.4", "100.70.1.2", "panel")),
                                            ("sign_in", P9_HOST)]
      and (_lp211, True, "100.70.1.2") in [(n, e is not None, h) for n, e, h in _ok_add211[2]], repr(_ok_add211))
check("databases remote: a new account that can't sign in from the game host is dropped again, nothing kept, and "
      "the answer names the host",
      _R211.get("add_unreach", (0,))[0] == 502 and _R211["add_unreach"][1] == ["create", "sign_in", "drop"]
      and not any(n.endswith("_core") for n in _R211["add_unreach"][3])
      and "can't reach" in _R211["add_unreach"][2], repr(_R211.get("add_unreach")))
check("databases remote: a refused sign-in says which address the server saw instead",
      _R211.get("add_seen", (0, ""))[0] == 502 and "100.70.9.9" in _R211.get("add_seen", (0, ""))[1],
      repr(_R211.get("add_seen")))
check("databases remote: the list gives the game the server's tailnet address (also in the snippets) and the "
      "account's host, and asks the sizes there with the stored login",
      _R211.get("list", ([], None, []))[0] == [("100.90.0.4", "100.70.1.2", True)]
      and _R211["list"][1] == "100.90.0.4"
      and _R211["list"][2] == [("sizes", (P9_HOST, "tcp3306@100.90.0.4", "100.70.1.2", "panel"), "p211u")],
      repr(_R211.get("list")))
check("databases grant: the narrow grant's statements reach a superadmin's tab only",
      _R211.get("grant_mgr") is None and "GRANT CREATE USER ON *.*" in _R211.get("grant_su", ""),
      repr((_R211.get("grant_mgr"), _R211.get("grant_su", "")[:60])))
check("databases remote: a backup dumps it on the game host, signed in as the database's own account (not the admin)",
      [c[1] for c in _R211.get("dump", [])] == [(P9_HOST, "tcp3306@100.90.0.4", None, _lp211)]
      and [c[2:] for c in _R211.get("dump", [])] == [("game", "p211u", [_lp211])] and _R211.get("dump_note") is None,
      repr((_R211.get("dump"), _R211.get("dump_note"))))
check("databases remote: a restore runs on the game host at the server's address; a password reset where the "
      "accounts are made, for the one account host",
      _R211.get("restore") == [("restore", (P9_HOST, "tcp3306@100.90.0.4", None, _lp211))]
      and _R211.get("reset") == [("set_password", (P9_HOST, "tcp3306@100.90.0.4", "100.70.1.2", "panel"))],
      repr((_R211.get("restore"), _R211.get("reset"))))
check("databases remote: a game host whose tailnet address changed is told so on the row",
      _R211.get("moved") == ("100.70.1.3", [True]), repr(_R211.get("moved")))
check("databases remote: Move renames the account to the new address and proves it signs in, and the row follows; "
      "a viewer without MANAGE_DATABASES is refused",
      _R211.get("move", (0,))[0] == 200
      and [c[0] for c in _R211["move"][1]] == ["rehost", "sign_in"]
      and _R211["move"][1][0][2:] == (_lp211, "100.70.1.2", "100.70.1.3")
      and (_lp211, "100.70.1.3") in [(n, h) for n, _e, h in _R211["move"][2]]
      and _R211.get("move_viewer") == 403, repr((_R211.get("move"), _R211.get("move_viewer"))))
check("databases remote: a managed host's server that listens on loopback only is refused with what to change, "
      "and nothing is changed", _R211.get("managed_loopback", (0, ""))[0] == 409
      and "bind-address" in _R211["managed_loopback"][1] and "won't change" in _R211["managed_loopback"][1],
      repr(_R211.get("managed_loopback")))
check("databases remote: a managed host's server is used where it listens on its tailnet address; the accounts are "
      "made THERE (as root over its socket), for the game host's address",
      _R211.get("managed") == 200
      and _R211.get("add_managed") == [("create", (P9_HOST2, "socket", "100.70.1.3", "")), ("sign_in", P9_HOST)],
      repr((_R211.get("managed"), _R211.get("add_managed"))))
check("databases remote: removing the database host takes its endpoint, the rows of the databases on it and every "
      "host's choice of it", _R211.get("forget") == (0, 0, 0)
      and _R211.get("rows_before_forget") == [True, True], repr((_R211.get("forget"), _R211.get("rows_before_forget"))))
check("databases overview: a viewer sees their own servers' databases and not another host's, and no password",
      _R211.get("overview_mgr") == (200, True, False, False), repr(_R211.get("overview_mgr")))
check("databases overview: a user with neither view_servers nor manage_databases is refused, and has no link",
      _R211.get("overview_none") == 403 and _R211.get("nav_none") is False,
      repr((_R211.get("overview_none"), _R211.get("nav_none"))))
check("databases overview: a superadmin sees every server's databases, and the sidebar links the page",
      _R211.get("overview_su") == (True, True), repr(_R211.get("overview_su")))
check("databases remote: a superadmin can send the host's new databases back to its own server",
      _R211.get("clear_su") == 200 and _R211.get("clear_row") == 0, repr((_R211.get("clear_su"), _R211.get("clear_row"))))
check("part211: nothing reached a real transport", len(_P9_TRIPPED) == _trips211, repr(_P9_TRIPPED[_trips211:][:4]))
_lst211 = [_net211._listens_on({"listeners": [a]}, "100.64.7.8")
           for a in ("0.0.0.0:3306", "[::]:3306", "*:3306", "100.64.7.8:3306", "127.0.0.1:3306", "[::1]:3306",
                     "100.64.7.9:3306", "not-an-address:3306")]
eq("databases remote: a server listening on every address (0.0.0.0, ::, *) or on the tailnet address itself "
   "is reachable there; loopback, another address or an unparsable listener is not",
   _lst211, [True, True, True, True, False, False, False, False])

# ── 5. the test box's findings: a dead address, MySQL 8 passwords, routines, definers ─────────────
_NET211 = "tcp3306@100.64.0.5"
check("databases verbs: a tailnet sign-in gives up after 10 s (--connect-timeout), asks a MySQL 8 server for its "
      "key, and keeps TLS off; a sign-in on 127.0.0.1 gets none of them; both twins alike",
      all(o in _priv211.db_conn_net(_NET211) for o in ("--connect-timeout=10", "--loose-get-server-public-key",
                                                         "--loose-skip-ssl"))
      and not any(o.startswith(("--connect-timeout", "--loose")) for o in _priv211.db_conn_net("tcp3306"))
      and _helper.db_conn_net(_NET211) == _priv211.db_conn_net(_NET211)
      and _helper.db_conn_net("tcp3306") == _priv211.db_conn_net("tcp3306"), repr(_priv211.db_conn_net(_NET211)))
check("databases verbs: the remote rendering's tailnet sign-in carries the timeout and the key option too",
      all(o in _priv211._db_conn_sh(_NET211) for o in ("--connect-timeout=10", "--loose-get-server-public-key"))
      and "connect-timeout" not in _priv211._db_conn_sh("tcp3306"), _priv211._db_conn_sh(_NET211))
_E2061 = ("ERROR 2061 (HY000): Authentication plugin 'caching_sha2_password' reported error: Authentication "
          "requires secure connection.")
eq("databases verbs: ERROR 2061 (a caching_sha2 password without TLS or the server's key) is its own answer, not "
   "'did not answer', in the helper, privileged.py and the remote shell",
   (_helper.db_failed_word(_E2061), _priv211.db_failed_word(_E2061),
    '*"ERROR 2061"*) echo keyauth; exit 1;;' in _priv211.remote_command("db-admin-check", ["mysql", _NET211]),
    _dbs211._net_kind(1, _E2061)), ("keyauth", "keyauth", True, "keyauth"))
eq("databases verbs: a database is dropped before its accounts (MySQL 8 won't drop an event's definer first), in "
   "both twins", [_priv211.db_sql_drop("gs12_lp").splitlines()[0], _helper.db_sql_drop("gs12_lp", "100.70.1.2")
                  == _priv211.db_sql_drop("gs12_lp", "100.70.1.2")], ["DROP DATABASE IF EXISTS `gs12_lp`;", True])
_kept_sh211 = _priv211.remote_command("db-drop", ["mysql", "tcp3306", "gs12_lp", "kept"])
_full_sh211 = _priv211.remote_command("db-drop", ["mysql", "tcp3306", "gs12_lp"])
_hd_calls211 = []
_saved_h211 = (_helper._db_dump_archive, _helper._db_run)
try:
    _helper._db_dump_archive = lambda sess, names: (_hd_calls211.append(("archive", list(names))), 0)[1]
    _helper._db_run = lambda sess, sql: (_hd_calls211.append(("sql", sql.split()[0:2])), (0, "", ""))[1]
    _sess211 = {"secrets": [], "flavor": "mysql"}
    _helper._db_drop(_sess211, ["mysql", "tcp3306", "gs12_lp", "kept"])
    _R211["helper_kept"] = list(_hd_calls211)
    _hd_calls211.clear()
    _helper._db_drop(_sess211, ["mysql", "tcp3306", "gs12_lp", "100.70.1.2"])
    _R211["helper_full"] = list(_hd_calls211)
finally:
    _helper._db_dump_archive, _helper._db_run = _saved_h211
check("databases verbs: db-drop told the copy is kept makes no dump of its own (helper and remote rendering), and "
      "without it still dumps first",
      _R211.get("helper_kept") == [("sql", ["DROP", "DATABASE"])]
      and _R211.get("helper_full") == [("archive", ["gs12_lp"]), ("sql", ["DROP", "DATABASE"])]
      and "dump1" not in _kept_sh211 and "dump1" in _full_sh211,
      repr((_R211.get("helper_kept"), _R211.get("helper_full"))))
_rp_saved211 = _core211.run_privileged
_core211.run_privileged = _fake_rp211
try:
    _ANS211["db-rehost"] = ("ERROR 4006 (HY000): Operation RENAME USER failed for 'gs1_lp'@'100.70.1.2' as it is "
                            "referenced as a definer account in an event.", "", 1)
    _rh211 = _dbs211.rehost(_NS211(id=1), _NS211(flavor="mysql", auth_mode="socket", port=3306, native_ok=True),
                            "gs1_lp", "100.70.1.2", "100.70.1.3")
    _ANS211["db-admin-check"] = ("keyauth\n", "", 1)
    _R211["ep_key"] = _dbs211.endpoint_check(_NS211(id=1), "100.64.0.5", 3306, "panel", "Pw211x")[0]
finally:
    _core211.run_privileged = _rp_saved211
check("databases remote: MySQL refusing to move a definer account (4006) is said as such, nothing changed",
      _rh211[0] is False and "4006" in str(_rh211[1]) and "Nothing was changed" in str(_rh211[1]), repr(_rh211))
check("databases remote: an endpoint check answered keyauth reads keyauth, and the choice route words it",
      _R211.get("ep_key") == "keyauth" and "2061" in _net211._VERDICTS.get("keyauth", ""), repr(_R211.get("ep_key")))

# The copy before a delete, and a backup's dumps, with a stored admin login: each database's own account.
_C5 = []
_SID5_211 = None
try:
    _p9_arm(who="part211")
    for _n211 in ("dump", "drop"):
        _p9_patch(_dbs211, _n211, (lambda name: lambda remote, hostdb, *a: (
            _C5.append((name, getattr(remote, "id", None), _dbs211._auth(hostdb), getattr(hostdb, "admin_user", None),
                        bool(getattr(hostdb, "copy_kept", False))) + a), (True, ""))[1])(_n211))
    _p9_patch(_dbr211, "game_account_write_refusal", lambda remote, user, **k: None)
    _SID5_211 = _p9_new_server(P9_HOST, "p211w", "pmc", 25567, name="p211 login")
    with _p9.app_context():
        _db211.session.add(_HD211(remote_id=P9_HOST, flavor="mysql", version="8.0.46", auth_mode="login", port=3306,
                                  admin_user="linuxgsm_panel", admin_secret=_enc211("Zscoped211pw")))
        _db211.session.add_all([_GD211(remote_id=P9_HOST, game_server_id=_SID5_211, name="gs%d_a" % _SID5_211,
                                       secret=_enc211(_PW211)),
                                _GD211(remote_id=P9_HOST, game_server_id=_SID5_211, name="gs%d_b" % _SID5_211,
                                       secret=_enc211(_PW211))])
        _db211.session.commit()
        _R211["login_backup_note"] = _dbr211.dump_for_backup(_SID5_211, _db211.session.get(_RS211, P9_HOST), "p211w")
        _ida211 = _GD211.query.filter_by(name="gs%d_a" % _SID5_211).first().id
    _R211["login_backup"] = [c for c in _C5 if c[0] == "dump"]
    _C5.clear()
    _r211 = _p9_client(P9_ADMIN).post("/api/server/%d/databases/%d/delete" % (_SID5_211, _ida211),
                                      json={"confirm": "gs%d_a" % _SID5_211})
    _R211["login_delete"] = (_r211.status_code, list(_C5))
finally:
    _p9_restore_all()
    with _p9.app_context():
        if _SID5_211 is not None:
            _GD211.query.filter_by(game_server_id=_SID5_211).delete()
        _HD211.query.filter_by(remote_id=P9_HOST).delete()
        _db211.session.commit()
    if _SID5_211 is not None:
        _p9_delete_server(_SID5_211)
_a5, _b5 = "gs%d_a" % (_SID5_211 or 0), "gs%d_b" % (_SID5_211 or 0)
eq("databases login mode: a backup dumps each database signed in as its own account (a narrow admin login can't "
   "read another account's routines), one call each",
   [c[1:] for c in _R211.get("login_backup", [])],
   [(P9_HOST, "tcp3306", _a5, False, "game", "p211w", [_a5]), (P9_HOST, "tcp3306", _b5, False, "game", "p211w", [_b5])])
eq("databases login mode: a delete keeps the copy first as the database's own account, then the admin login drops "
   "it without dumping again",
   (_R211.get("login_delete", (0, []))[0], [c[:5] + c[5:6] for c in _R211.get("login_delete", (0, []))[1]]),
   (200, [("dump", P9_HOST, "tcp3306", _a5, False, "archive"), ("drop", P9_HOST, "tcp3306", "linuxgsm_panel", True, "p211w")]))
check("part211: section 5 reached no real transport", len(_P9_TRIPPED) == _trips211, repr(_P9_TRIPPED[_trips211:][:4]))
