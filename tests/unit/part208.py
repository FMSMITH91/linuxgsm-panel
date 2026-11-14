"""Part 208 of the unit suite: the Databases tab (routes/databases.py, services/db_snippets.py).

* Snippets: each kind's exact text with sentinel values, and which kinds and name each game gets.
* The routes through part12's app, with the host side (ssh_manager.databases) replaced by a recorder
  that keeps §2.3's signatures: the permission matrix (the view permission sees, MANAGE_DATABASES
  changes, MANAGE_DATABASES + MANAGE_REMOTES sets a host up, a superadmin alone handles the admin
  login), the cap and a bad name refused before the host is asked, a password never in a list, an
  audit row or a log record, reveal POST-only and no-store, delete and restore confirmed by the
  name, restore behind the root-capable-account refusal.
* The hooks: a backup dumps the server's databases first in one call (none when it has none; a
  failed or refused dump is said and the backup still runs), an uninstall drops them, a server
  removed from the panel only leaves them listed on its host, a deleted host takes its rows.
* The Files page carries the tab for the view permission only; the debug report prints no secret;
  the tab's script in node.

The host side's functions are replaced, on ssh_manager.databases itself, by stand-ins that take the
same arguments (checked here) and record each call; part207 drives that module against the helper.
Nothing reaches a host or data/.
"""
import inspect as _insp208
import json as _js208
import logging as _lg208
import types as _ty208
from types import SimpleNamespace as _NS208

from unit.part01 import check, eq
from unit.part99 import _js99, _read99
from unit.part12 import (P9_ADMIN, P9_HOST, P9_HOST2, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_exists, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.core import config as _cfg208
from panel.db import models as _m208
from panel.db.models import AuditLog as _AL208, Group as _G208, RemoteServer as _RS208, User as _U208, db as _db208
from panel.ops.ssh_manager import databases as _dbs208
from panel.routes import _shared as _sh208, databases as _dbr, manage_servers as _ms208
from panel.security import auth as _auth208
from panel.services import db_snippets as _sn208

_trips208 = len(_P9_TRIPPED)
_R208 = {}

# ── 1. snippets ─────────────────────────────────────────────────────────────────────────────────
_PW208 = "Zsnip" + "q" * 27
_SN208 = {k: _sn208.render(k, "mariadb", 3307, "gs9_lp", _PW208) for k in _sn208.LABELS}
eq("snippets: LuckPerms, storage-method mariadb on a MariaDB server, address host:port",
   _SN208["luckperms"], "storage-method: mariadb\ndata:\n  address: '127.0.0.1:3307'\n  database: 'gs9_lp'\n"
   "  username: 'gs9_lp'\n  password: '%s'\n" % _PW208)
eq("snippets: LuckPerms on a MySQL server says storage-method mysql, and the JDBC URL says mysql",
   [_sn208.render("luckperms", "mysql", 3306, "gs9_lp", "w").splitlines()[0],
    _sn208.render("generic", "mysql", 3306, "gs9_lp", "w").splitlines()[5]],
   ["storage-method: mysql", "JDBC: jdbc:mysql://127.0.0.1:3306/gs9_lp"])
eq("snippets: CoreProtect, both its database-type and its older use-mysql switch",
   _SN208["coreprotect"], "use-mysql: true\ndatabase-type: mysql\ntable-prefix: co_\nmysql-host: 127.0.0.1\n"
   "mysql-port: 3307\nmysql-database: gs9_lp\nmysql-username: gs9_lp\nmysql-password: %s\n" % _PW208)
eq("snippets: Plan, Database.Type MySQL and its MySQL keys",
   _SN208["plan"], "Database:\n  Type: MySQL\n  MySQL:\n    Host: 127.0.0.1\n    Port: 3307\n    User: gs9_lp\n"
   "    Password: %s\n    Database: gs9_lp\n" % _PW208)
eq("snippets: FiveM's oxmysql connection string",
   _SN208["fivem"], 'set mysql_connection_string "mysql://gs9_lp:%s@127.0.0.1:3307/gs9_lp?charset=utf8mb4"\n' % _PW208)
eq("snippets: SourceMod's databases.cfg entry (named sourcebans for a database called that)",
   [_SN208["sourcemod"], _sn208.render("sourcemod", "mariadb", 3306, "gs9_sourcebans", "w").splitlines()[0]],
   ['"default"\n{\n\t"driver"\t"default"\n\t"host"\t"127.0.0.1"\n\t"database"\t"gs9_lp"\n\t"user"\t"gs9_lp"\n'
    '\t"pass"\t"%s"\n\t"port"\t"3307"\n}\n' % _PW208, '"sourcebans"'])
eq("snippets: extDB3's section, MySQLOO's connect call",
   [_SN208["extdb3"], _SN208["mysqloo"]],
   ["[gs9_lp]\nIP = 127.0.0.1\nPort = 3307\nUsername = gs9_lp\nPassword = %s\nDatabase = gs9_lp\n" % _PW208,
    'local db = mysqloo.connect("127.0.0.1", "gs9_lp", "%s", "gs9_lp", 3307)\ndb:connect()\n' % _PW208])
eq("snippets: the generic one, five values, a JDBC URL and a mysql:// URI",
   _SN208["generic"], "Host: 127.0.0.1\nPort: 3307\nDatabase: gs9_lp\nUser: gs9_lp\nPassword: %s\n"
   "JDBC: jdbc:mariadb://127.0.0.1:3307/gs9_lp\nURI: mysql://gs9_lp:%s@127.0.0.1:3307/gs9_lp\n" % (_PW208, _PW208))
eq("snippets: each game's own kinds first, then generic",
   [_sn208.kinds_for(g) for g in ("pmc", "vpmc", "fivem", "tf2", "gmod", "arma3", "rust", "MC")],
   [["luckperms", "coreprotect", "plan", "generic"], ["luckperms", "plan", "generic"], ["fivem", "generic"],
    ["sourcemod", "generic"], ["mysqloo", "generic"], ["extdb3", "generic"], ["generic"],
    ["luckperms", "coreprotect", "plan", "generic"]])
eq("snippets: the suggested name is the game's usual one, then data, data2... once taken",
   [_sn208.suggest_slug("pmc", []), _sn208.suggest_slug("css", []), _sn208.suggest_slug("pmc", ["luckperms"]),
    _sn208.suggest_slug("pmc", ["luckperms", "data"]), _sn208.suggest_slug("ark", [])],
   ["luckperms", "sourcebans", "data", "data2", "data"])


# ── 2. the tables ──────────────────────────────────────────────────────────────────────────────
_GD208, _HD208 = _m208.GameDatabase, _m208.HostDatabaseServer


# ── 3. the host side, recorded ──────────────────────────────────────────────────────────────────
class _Svc208:
    """What ssh_manager.databases is asked, and what it answers (each test sets `ans`)."""

    def __init__(self):
        self.calls, self.n = [], 0
        self.ans = {}

    def reset(self, **ans):
        self.calls.clear()
        self.ans = dict({"probe": {"state": "ready", "flavor": "mariadb", "version": "10.11.14-MariaDB",
                                   "port": 3306, "native_ok": True, "warnings": []},
                         "ok": (True, ""), "admin": "ok"}, **ans)

    def secret(self):
        self.n += 1
        return "Zsecret208%s%s" % ("x" * 20, self.n)


_S208 = _Svc208()


def _stub_module208():
    m = _ty208.ModuleType("p208_databases")

    def db_name(server_id, slug):
        return "gs%d_%s" % (server_id, slug)

    def new_password():
        return _S208.secret()

    def probe(remote):
        _S208.calls.append(("probe",))
        return dict(_S208.ans["probe"])

    def plugin_for(hostdb):
        return "native" if hostdb.native_ok else "sha2"

    def install_mariadb(remote):
        _S208.calls.append(("install",))
        return True, "", "Zadmin208" + "y" * 20

    def check_admin_login(remote, port, user, pw):
        _S208.calls.append(("admin", port, user, pw))
        return _S208.ans["admin"]

    def create(remote, hostdb, name, pw, maxconn):
        _S208.calls.append(("create", name, pw, maxconn))
        return _S208.ans["ok"]

    def set_password(remote, hostdb, name, pw):
        _S208.calls.append(("password", name, pw))
        return _S208.ans["ok"]

    def sizes(remote, hostdb, names):
        _S208.calls.append(("sizes", list(names)))
        return {n: 12 * 1048576 for n in names}

    def dump(remote, hostdb, dest, account, names):
        _S208.calls.append(("dump", dest, account, list(names)))
        return _S208.ans.get("dump", (True, ""))

    def restore(remote, hostdb, account, name, pw):
        _S208.calls.append(("restore", account, name, pw))
        return _S208.ans["ok"]

    def drop(remote, hostdb, account, name):
        _S208.calls.append(("drop", account, name))
        return _S208.ans.get("drop", (True, ""))

    for f in (db_name, new_password, probe, plugin_for, install_mariadb, check_admin_login, create, set_password,
              sizes, dump, restore, drop):
        setattr(m, f.__name__, f)
    return m


_STUB208 = _stub_module208()
_NAMES208 = sorted(n for n in vars(_STUB208) if not n.startswith("_"))
_sig208 = {n: (list(_insp208.signature(getattr(_dbs208, n, None) or (lambda: None)).parameters),
               list(_insp208.signature(getattr(_STUB208, n)).parameters)) for n in _NAMES208}
check("databases: ssh_manager.databases takes the arguments the routes pass (the stand-ins below take the same)",
      len(_sig208) == 12 and all(a == b for a, b in _sig208.values()),
      repr({n: v for n, v in _sig208.items() if v[0] != v[1]}))


def _stub_in208():
    """The recorder's functions in place of ssh_manager.databases' own, undone by _p9_restore_all."""
    for _n in _NAMES208:
        _p9_patch(_dbs208, _n, getattr(_STUB208, _n))


def _user208(tag, perms, hosts):
    with _p9.app_context():
        g = _G208(name="p208_" + tag, description="", is_default=False)
        g.set_permissions(perms)
        g.servers.extend(_db208.session.get(_RS208, h) for h in hosts)
        u = _U208(username="p208_" + tag, password_hash=_auth208.hash_password("Str0ng!passw0rd-p208"),
                  display_name="p208", is_superadmin=False, is_active=True)
        u.groups.append(g)
        _db208.session.add_all([g, u])
        _db208.session.commit()
        return u.id, g.id


def _rows208(**filt):
    with _p9.app_context():
        return [_NS208(id=r.id, name=r.name, gs=r.game_server_id, secret=r.secret, plugin=r.auth_plugin,
                       remote=r.remote_id, dumped=r.dumped_at) for r in _GD208.query.filter_by(**filt).all()]


def _audits208(prefix="db_"):
    with _p9.app_context():
        return [(a.action, a.detail or "", a.success) for a in
                _AL208.query.filter(_AL208.action.like(prefix + "%")).order_by(_AL208.id).all()]


class _Logs208(_lg208.Handler):
    def __init__(self):
        super().__init__(_lg208.DEBUG)
        self.text = []

    def emit(self, record):
        try:
            self.text.append(record.getMessage())
        except Exception:  # nosec B110 - a record that cannot be formatted is not text a check can read
            pass


_SID208 = _OTHER208 = None
_MINE208 = []
_LOG208 = _Logs208()
_lg208.getLogger().addHandler(_LOG208)
try:
    _p9_arm(who="part208")
    _stub_in208()
    _p9_patch(_dbr, "game_account_write_refusal", lambda remote, user, **k: None)
    _SID208 = _p9_new_server(P9_HOST, "p208u", "pmc", 25565, name="p208 paper")
    _OTHER208 = _p9_new_server(P9_HOST, "p208v", "pmc", 25566, name="p208 other")
    _MGR208 = _user208("mgr", ["manage_databases", "view_servers", "view_files"], [P9_HOST])
    _VIEW208 = _user208("view", ["view_servers", "view_files"], [P9_HOST])
    _FILES208 = _user208("files", ["view_files"], [P9_HOST])
    _FAR208 = _user208("far", ["manage_databases", "view_servers"], [P9_HOST2])
    _HOSTOP208 = _user208("hostop", ["manage_databases", "manage_remotes", "view_servers"], [P9_HOST])
    _MINE208 = [_MGR208, _VIEW208, _FILES208, _FAR208, _HOSTOP208]
    _A208, _M208, _V208 = _p9_client(P9_ADMIN), _p9_client(_MGR208[0]), _p9_client(_VIEW208[0])
    _api208 = "/api/server/%d/databases" % _SID208

    # ── 4a. a host that did not answer is asked again on the next look, not taken as down ────────
    _FARSID208 = _p9_new_server(P9_HOST2, "p208w", "pmc", 25568, name="p208 far")
    _S208.reset(probe={"state": "unreadable"})
    _R208["unread"] = [_p9_json(_A208.get("/api/server/%d/databases" % _FARSID208)).get("state") for _ in (1, 2)]
    _R208["unread_probes"] = [c[0] for c in _S208.calls]
    _p9_delete_server(_FARSID208)

    # ── 4. a host with no database server: nothing can be added; setting it up ───────────────────
    _S208.reset(probe={"state": "none"})
    _R208["none_get"] = _p9_json(_M208.get(_api208))
    _R208["none_add"] = (_M208.post(_api208, json={"name": "lp"}).status_code, list(_S208.calls))
    _S208.reset(probe={"state": "none"})
    _R208["setup_mgr"] = _M208.post("/api/remote/%d/databases/setup" % P9_HOST).status_code
    _R208["setup_mgr_calls"] = list(_S208.calls)
    _ran208 = []
    _p9_patch(_dbr, "threading", _NS208(Lock=_dbr.threading.Lock, Thread=lambda target, args, daemon: _NS208(
        start=lambda: _ran208.append((target, args)))))
    _S208.reset(probe={"state": "none"})
    _r208 = _p9_client(_HOSTOP208[0]).post("/api/remote/%d/databases/setup" % P9_HOST)
    _R208["setup_hostop"] = (_r208.status_code, len(_ran208))
    _R208["setup_running"] = _p9_json(_M208.get(_api208)).get("state")
    for _t208, _a208 in _ran208:
        _t208(*_a208)
    _R208["setup_calls"] = [c[0] for c in _S208.calls]
    with _p9.app_context():
        _h208 = _HD208.query.filter_by(remote_id=P9_HOST).first()
        _R208["setup_row"] = (None if _h208 is None else
                              (_h208.installed_by_panel, _h208.auth_mode, bool(_h208.panel_admin_secret),
                               "Zadmin208" in (_h208.panel_admin_secret or "")))
    _R208["setup_again"] = _p9_client(_HOSTOP208[0]).post("/api/remote/%d/databases/setup" % P9_HOST).status_code
    _R208["admin_reveal_mgr"] = _M208.post("/api/remote/%d/databases/admin-reveal" % P9_HOST).status_code
    _r208 = _A208.post("/api/remote/%d/databases/admin-reveal" % P9_HOST)
    _R208["admin_reveal_su"] = (_r208.status_code, _p9_json(_r208).get("password", "")[:9],
                                _r208.headers.get("Cache-Control"))
    _R208["admin_login_mgr"] = _M208.post("/api/remote/%d/databases/admin-login" % P9_HOST,
                                          json={"user": "root", "password": "x"}).status_code

    # ── 5. adding: a bad name and a full server refused before the host is asked ─────────────────
    _S208.reset()
    _R208["add_bad"] = (_M208.post(_api208, json={"name": "a-b"}).status_code,
                        _M208.post(_api208, json={"name": "x" * 17}).status_code, list(_S208.calls))
    _R208["add_viewer"] = (_V208.post(_api208, json={"name": "lp"}).status_code, list(_S208.calls))
    _R208["add_far"] = _p9_client(_FAR208[0]).post(_api208, json={"name": "lp"}).status_code
    _r208 = _M208.post(_api208, json={"name": "LuckPerms"})
    _R208["add"] = (_r208.status_code, _p9_json(_r208), [c for c in _S208.calls if c[0] == "create"])
    _R208["add_text"] = _r208.get_data(as_text=True)
    _p9_patch(_dbr, "load_config", lambda: dict(_cfg208.DEFAULT_CONFIG, db_max_per_server=1))
    _S208.reset()
    _R208["add_full"] = (_M208.post(_api208, json={"name": "data"}).status_code, list(_S208.calls))
    _p9_patch(_dbr, "load_config", _cfg208.load_config)
    _R208["add_dupe"] = (_M208.post(_api208, json={"name": "luckperms"}).status_code, list(_S208.calls))
    _S208.reset(ok=(False, "the host said no"))
    _R208["add_failed"] = (_M208.post(_api208, json={"name": "core"}).status_code, len(_rows208(game_server_id=_SID208)))

    # ── 6. the list: never a password, sizes asked once a minute ─────────────────────────────────
    _S208.reset()
    _r208 = _M208.get(_api208)
    _R208["list"], _R208["list_text"] = _p9_json(_r208), _r208.get_data(as_text=True)
    _R208["list_calls"] = list(_S208.calls)
    _S208.reset()
    _M208.get(_api208)
    _R208["list_again_calls"] = list(_S208.calls)
    _S208.reset()
    _M208.get(_api208 + "?refresh=1")
    _R208["refresh_calls"] = [c[0] for c in _S208.calls]
    _V208.get(_api208 + "?refresh=1")
    _R208["refresh_viewer_calls"] = [c[0] for c in _S208.calls]
    _r208 = _V208.get(_api208)
    _R208["list_viewer"] = (_r208.status_code, _p9_json(_r208).get("can"), _r208.get_data(as_text=True))
    _R208["list_far"] = _p9_client(_FAR208[0]).get(_api208).status_code
    _R208["names"] = _p9_json(_V208.get(_api208 + "?names=1"))
    _DB208 = (_rows208(game_server_id=_SID208) or [_NS208(id=-1, name="", secret="")])[0]
    _row_api208 = "%s/%d" % (_api208, _DB208.id)

    # ── 7. reveal, reset ────────────────────────────────────────────────────────────────────────
    _R208["reveal_get"] = _M208.get(_row_api208 + "/reveal").status_code
    _R208["reveal_viewer"] = _V208.post(_row_api208 + "/reveal").status_code
    _R208["reveal_other"] = _M208.post("/api/server/%d/databases/%d/reveal" % (_OTHER208, _DB208.id)).status_code
    _r208 = _M208.post(_row_api208 + "/reveal")
    _R208["reveal"] = (_r208.status_code, _p9_json(_r208).get("password"), _r208.headers.get("Cache-Control"))
    _S208.reset()
    _r208 = _M208.post(_row_api208 + "/reset-password")
    _R208["reset"] = (_r208.status_code, _r208.get_data(as_text=True), [c for c in _S208.calls if c[0] == "password"])
    _R208["reset_row"] = _rows208(id=_DB208.id)[0].secret if _rows208(id=_DB208.id) else ""

    # ── 8. restore: confirmed by name, refused for a root-capable account ─────────────────────────
    _S208.reset()
    _R208["restore_noconfirm"] = (_M208.post(_row_api208 + "/restore", json={"confirm": "x"}).status_code,
                                  list(_S208.calls))
    _p9_patch(_dbr, "game_account_write_refusal", lambda remote, user, **k: "p208u can become root")
    _R208["restore_root"] = (_M208.post(_row_api208 + "/restore", json={"confirm": _DB208.name}).status_code,
                             list(_S208.calls))
    _p9_patch(_dbr, "game_account_write_refusal", lambda remote, user, **k: None)
    _R208["restore"] = (_M208.post(_row_api208 + "/restore", json={"confirm": _DB208.name}).status_code,
                        [c for c in _S208.calls if c[0] == "restore"])

    # ── 9. the backup hook, through _marked_backup ────────────────────────────────────────────────
    def _backup208(sid, short):
        order = []
        _S208.calls.clear()

        def runner(*a, **k):
            order.append("runner:%s" % ",".join(c[0] for c in _S208.calls))
            return True, "", False
        with _p9.app_context():
            remote = _db208.session.get(_RS208, P9_HOST)
            res = _sh208._marked_backup(sid, remote, short, short, 3, runner=runner)
        return order, [c for c in _S208.calls if c[0] == "dump"], res

    _S208.reset()
    _R208["bk"] = _backup208(_SID208, "p208u")
    _R208["bk_dumped"] = _rows208(id=_DB208.id)[0].dumped if _rows208(id=_DB208.id) else None
    _R208["bk_none"] = _backup208(_OTHER208, "p208v")
    _S208.reset(dump=(False, "mariadb-dump failed"))
    _R208["bk_fail"] = _backup208(_SID208, "p208u")
    _p9_patch(_dbr, "game_account_write_refusal", lambda remote, user, **k: "p208u can become root")
    _S208.reset()
    _R208["bk_root"] = _backup208(_SID208, "p208u")
    _p9_patch(_dbr, "game_account_write_refusal", lambda remote, user, **k: None)

    # ── 10. delete: confirmed by name ─────────────────────────────────────────────────────────────
    _S208.reset()
    _R208["del_noconfirm"] = (_M208.post(_row_api208 + "/delete", json={"confirm": "nope"}).status_code,
                              list(_S208.calls))
    _r208 = _M208.post(_row_api208 + "/delete", json={"confirm": _DB208.name})
    _R208["del"] = (_r208.status_code, [c for c in _S208.calls if c[0] == "drop"], _rows208(id=_DB208.id))

    # ── 11. uninstall drops them; removed from the panel only keeps them, listed on the host ──────
    for _sl208 in ("data", "core"):
        _M208.post(_api208, json={"name": _sl208})
    _p9_patch(_ms208, "_stop_game_processes", lambda *a, **k: None)
    _p9_patch(_ms208, "_close_game_firewall", lambda remote, gs: ([], False))
    _p9_patch(_ms208, "_remove_account_crontab", lambda *a, **k: None)
    _p9_patch(_ms208, "privileged_accounts", lambda remote, users: {})
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 0))
    _S208.reset()
    _r208 = _A208.post("/servers/%d/delete" % _SID208, headers={"X-Requested-With": "XMLHttpRequest"})
    _R208["uninstall"] = (_r208.status_code, _p9_exists(_SID208), [c for c in _S208.calls if c[0] == "drop"],
                          _rows208(remote_id=P9_HOST))
    _M208.post("/api/server/%d/databases" % _OTHER208, json={"name": "kept"})
    _p9_patch(_ms208, "privileged_accounts", lambda remote, users: {"p208v": "it can become root"})
    _r208 = _A208.post("/servers/%d/delete" % _OTHER208, headers={"X-Requested-With": "XMLHttpRequest"})
    _R208["row_only"] = (_r208.status_code, _p9_exists(_OTHER208), [(r.name, r.gs) for r in _rows208(remote_id=P9_HOST)])
    _R208["orphans"] = _p9_json(_M208.get("/api/remote/%d/databases" % P9_HOST))
    _R208["orphans_viewer"] = _V208.get("/api/remote/%d/databases" % P9_HOST).status_code
    _orph208 = (_R208["orphans"].get("databases") or [{"id": -1, "name": ""}])[0]
    _S208.reset()
    _r208 = _M208.post("/api/remote/%d/databases/%d/delete" % (P9_HOST, _orph208["id"]),
                       json={"confirm": _orph208["name"]})
    _R208["orphan_del"] = (_r208.status_code, [c for c in _S208.calls if c[0] == "drop"], _rows208(remote_id=P9_HOST))

    # ── 12. a deleted host takes its rows ───────────────────────────────────────────────────────
    with _p9.app_context():
        _db208.session.add(_GD208(remote_id=99208, game_server_id=None, name="gs1_gone", secret="x"))
        _db208.session.add(_HD208(remote_id=99208, flavor="mariadb"))
        _db208.session.commit()
        _dbr.forget_remote(99208)
        _db208.session.commit()
        _R208["forget_remote"] = (_GD208.query.filter_by(remote_id=99208).count(),
                                  _HD208.query.filter_by(remote_id=99208).count())
    _R208["audits"] = _audits208()
finally:
    _p9_restore_all()
    _lg208.getLogger().removeHandler(_LOG208)
    _dbr._PROBES.clear()
    _dbr._SETUP.clear()
    for _sid208 in (_SID208, _OTHER208):
        _sh208._game_backup_status.pop(_sid208, None)
    with _p9.app_context():
        _GD208.query.filter(_GD208.remote_id.in_([P9_HOST, 99208])).delete()
        _HD208.query.filter(_HD208.remote_id.in_([P9_HOST, 99208])).delete()
        for _uid208, _gid208 in _MINE208:
            for _mdl208, _i208 in ((_U208, _uid208), (_G208, _gid208)):
                _row208 = _db208.session.get(_mdl208, _i208)
                if _row208 is not None:
                    _db208.session.delete(_row208)
        _db208.session.commit()

_SECRETS208 = ["Zsecret208"]

# ── checks: setting up a host ───────────────────────────────────────────────────────────────────
check("databases tab: a host with no database server answers state none, and adding is refused (409) without "
      "asking the host to create anything",
      _R208.get("none_get", {}).get("state") == "none" and _R208.get("none_add", (0, []))[0] == 409
      and not any(c[0] == "create" for c in _R208.get("none_add", (0, []))[1]), repr(_R208.get("none_add")))
check("databases setup: MANAGE_DATABASES without MANAGE_REMOTES is refused (403) before the host is asked",
      _R208.get("setup_mgr") == 403 and not _R208.get("setup_mgr_calls"), repr(_R208.get("setup_mgr")))
check("databases setup: with both permissions it starts in the background (202), and the tab reads setting_up",
      _R208.get("setup_hostop") == (202, 1) and _R208.get("setup_running") == "setting_up",
      repr((_R208.get("setup_hostop"), _R208.get("setup_running"))))
check("databases setup: the worker probes first, installs, probes again, and records a panel-installed "
      "socket-login server with its admin password encrypted",
      _R208.get("setup_calls") == ["probe", "install", "probe"]
      and _R208.get("setup_row") == (True, "socket", True, False), repr((_R208.get("setup_calls"), _R208.get("setup_row"))))
check("databases setup: a host already set up is refused (409)", _R208.get("setup_again") == 409,
      repr(_R208.get("setup_again")))
check("databases admin: the panel's admin password and an admin login are superadmin only (403), and the "
      "superadmin's reveal is no-store",
      _R208.get("admin_reveal_mgr") == 403 and _R208.get("admin_login_mgr") == 403
      and _R208.get("admin_reveal_su") == (200, "Zadmin208", "no-store"),
      repr((_R208.get("admin_reveal_mgr"), _R208.get("admin_login_mgr"), _R208.get("admin_reveal_su"))))

# ── checks: adding ──────────────────────────────────────────────────────────────────────────────
check("databases add: a name that is not 1-16 lower-case letters and digits is a 400, and the host is not asked",
      _R208.get("add_bad", (0, 0, [1]))[:2] == (400, 400) and not _R208["add_bad"][2], repr(_R208.get("add_bad")))
check("databases add: the view permission alone cannot add (403), nor MANAGE_DATABASES on another host's grant",
      _R208.get("add_viewer", (0, [1]))[0] == 403 and not _R208["add_viewer"][1]
      and _R208.get("add_far") in (403, 404), repr((_R208.get("add_viewer"), _R208.get("add_far"))))
_add208 = _R208.get("add", (0, {}, []))
check("databases add: the name is lower-cased and prefixed gs<id>_, the host creates it with 30 connections, "
      "and the answer carries no password",
      _add208[0] == 200 and _add208[1].get("success") is True
      and [(c[1], c[3]) for c in _add208[2]] == [("gs%s_luckperms" % _SID208, 30)]
      and not any(s in _R208.get("add_text", "") for s in _SECRETS208), repr(_add208))
check("databases add: at the cap (config db_max_per_server) a 409, and the host is not asked",
      _R208.get("add_full", (0, [1]))[0] == 409 and not any(c[0] == "create" for c in _R208["add_full"][1]),
      repr(_R208.get("add_full")))
check("databases add: a name this server already has is a 409 without a create",
      _R208.get("add_dupe", (0, [1]))[0] == 409 and not any(c[0] == "create" for c in _R208["add_dupe"][1]),
      repr(_R208.get("add_dupe")))
check("databases add: a create the host refused stores no row", _R208.get("add_failed") == (502, 1),
      repr(_R208.get("add_failed")))

# ── checks: the list, reveal, reset ─────────────────────────────────────────────────────────────
_list208 = _R208.get("list", {})
_one208 = (_list208.get("databases") or [{}])[0]
check("databases list: each database's host, port, name, user, size and snippets, the password masked",
      _one208.get("name") == "gs%s_luckperms" % _SID208 and _one208.get("user") == _one208.get("name")
      and _one208.get("host") == "127.0.0.1" and _one208.get("port") == 3306 and _one208.get("size") == 12 * 1048576
      and [s["kind"] for s in _one208.get("snippets", [])] == ["luckperms", "coreprotect", "plan", "generic"]
      and _dbr.PW_MARK in _one208["snippets"][0]["text"] and _list208.get("used") == 1 and _list208.get("cap") == 5,
      repr(_one208)[:600])
check("databases list: no password in the list, for the manager or the viewer",
      not any(s in _R208.get("list_text", "") + _R208.get("list_viewer", (0, {}, ""))[2] for s in _SECRETS208)
      and "password" not in _one208, _R208.get("list_text", "")[:300])
check("databases list: sizes are asked once for all databases, then not again inside a minute; a fresh host row "
      "is not probed again",
      [c[0] for c in _R208.get("list_calls", [])] == ["sizes"] and not _R208.get("list_again_calls"),
      repr((_R208.get("list_calls"), _R208.get("list_again_calls"))))
check("databases list: Refresh probes the host again now (a manager's; a viewer's reads what is stored), and a "
      "host that did not answer is asked again on the next look, not cached as down",
      _R208.get("refresh_calls") == ["probe"] and _R208.get("refresh_viewer_calls") == ["probe"]
      and _R208.get("unread") == ["unreadable", "unreadable"] and _R208.get("unread_probes") == ["probe", "probe"],
      repr((_R208.get("refresh_calls"), _R208.get("refresh_viewer_calls"), _R208.get("unread"), _R208.get("unread_probes"))))
check("databases list: the view permission sees the list without the controls; a grant on another host does not",
      _R208.get("list_viewer", (0, {}))[:2] == (200, {"manage": False, "setup": False, "su": False})
      and _R208.get("list_far") in (403, 404), repr((_R208.get("list_viewer", (0,))[:2], _R208.get("list_far"))))
check("databases: the uninstall dialog's name list reads only the panel", _R208.get("names") ==
      {"names": ["gs%s_luckperms" % _SID208]}, repr(_R208.get("names")))
check("databases reveal: POST only (GET 405), MANAGE_DATABASES only, and only this server's database",
      _R208.get("reveal_get") == 405 and _R208.get("reveal_viewer") == 403 and _R208.get("reveal_other") == 404,
      repr((_R208.get("reveal_get"), _R208.get("reveal_viewer"), _R208.get("reveal_other"))))
_rv208 = _R208.get("reveal", (0, "", ""))
check("databases reveal: the stored password, decrypted, with Cache-Control no-store",
      _rv208[0] == 200 and str(_rv208[1]).startswith("Zsecret208") and _rv208[2] == "no-store", repr(_rv208))
_rs208 = _R208.get("reset", (0, "", []))
check("databases reset: a new password set on the host and stored encrypted, none in the answer",
      _rs208[0] == 200 and len(_rs208[2]) == 1 and _rs208[2][0][2] != _rv208[1]
      and "Zsecret208" not in _rs208[1] and _R208.get("reset_row", "").startswith("enc:")
      and _cfg208.decrypt_secret(_R208.get("reset_row", "")) == _rs208[2][0][2], repr(_rs208))
check("databases restore: a wrong confirmation is a 400, a root-capable game account a 409, neither asks the host",
      _R208.get("restore_noconfirm", (0, [1]))[0] == 400 and not _R208["restore_noconfirm"][1]
      and _R208.get("restore_root", (0, [1]))[0] == 409 and not _R208["restore_root"][1],
      repr((_R208.get("restore_noconfirm"), _R208.get("restore_root"))))
check("databases restore: confirmed, the dump is loaded as the game account with the database's own password",
      _R208.get("restore", (0, []))[0] == 200
      and [c[1:3] for c in _R208["restore"][1]] == [("p208u", "gs%s_luckperms" % _SID208)]
      and _R208["restore"][1][0][3] == _rs208[2][0][2] if _rs208[2] else False, repr(_R208.get("restore")))

# ── checks: the backup hook ─────────────────────────────────────────────────────────────────────
_bk208 = _R208.get("bk", ([], [], None))
check("backup: a server with databases has them dumped into its files in ONE call before LinuxGSM's backup runs",
      _bk208[0] == ["runner:dump"] and [(c[1], c[2], c[3]) for c in _bk208[1]]
      == [("game", "p208u", ["gs%s_luckperms" % _SID208])] and _bk208[2] == (True, "", False)
      and _R208.get("bk_dumped") is not None, repr(_bk208))
check("backup: a server with no databases asks the host nothing more", _R208.get("bk_none", ([0], [1], None))[:2]
      == (["runner:"], []), repr(_R208.get("bk_none")))
_bkf208 = _R208.get("bk_fail", ([], [], (None, "", None)))
check("backup: a dump that fails still runs the backup, and its outcome says the databases were not included",
      _bkf208[0] == ["runner:dump"] and _bkf208[2][0] is True
      and "Databases were not included: mariadb-dump failed" in str(_bkf208[2][1]), repr(_bkf208))
_bkr208 = _R208.get("bk_root", ([], [1], (None, "", None)))
check("backup: a root-capable game account gets no dump (it is written as that account), and the outcome says why",
      _bkr208[0] == ["runner:"] and not _bkr208[1] and "p208u can become root" in str(_bkr208[2][1]), repr(_bkr208))

# ── checks: delete, uninstall, removal, a deleted host ─────────────────────────────────────────
check("databases delete: a wrong confirmation is a 400 and drops nothing",
      _R208.get("del_noconfirm", (0, [1]))[0] == 400 and not _R208["del_noconfirm"][1], repr(_R208.get("del_noconfirm")))
check("databases delete: confirmed by name, the host drops it (its archive first) and the row goes",
      _R208.get("del", (0, [], [1]))[0] == 200 and [c[2] for c in _R208["del"][1]] == ["gs%s_luckperms" % _SID208]
      and _R208["del"][2] == [], repr(_R208.get("del")))
_un208 = _R208.get("uninstall", (0, True, [], [1]))
check("uninstall: the server's databases are dropped on the host and their rows go with the server",
      _un208[0] == 200 and not _un208[1] and sorted(c[2] for c in _un208[2])
      == sorted(["gs%s_data" % _SID208, "gs%s_core" % _SID208]) and _un208[3] == [], repr(_un208))
check("removed from the panel only: the database stays, kept with no server, and the host lists it",
      _R208.get("row_only", (0, True, []))[:2] == (200, False)
      and _R208["row_only"][2] == [("gs%s_kept" % _OTHER208, None)]
      and [d["name"] for d in _R208.get("orphans", {}).get("databases", [])] == ["gs%s_kept" % _OTHER208]
      and _R208.get("orphans_viewer") == 403, repr((_R208.get("row_only"), _R208.get("orphans"))))
check("host page: a database with no server is deleted through the host's route (account unknown: None)",
      _R208.get("orphan_del", (0, [], [1]))[0] == 200 and [c[1:] for c in _R208["orphan_del"][1]]
      == [(None, "gs%s_kept" % _OTHER208)] and _R208["orphan_del"][2] == [], repr(_R208.get("orphan_del")))
check("remote delete: a deleted host's database rows go with it", _R208.get("forget_remote") == (0, 0),
      repr(_R208.get("forget_remote")))

# ── checks: audit rows and logs never hold a password ──────────────────────────────────────────
_aud208 = _R208.get("audits", [])
_acts208 = {a[0] for a in _aud208}
check("databases: create, reveal, reset, restore, delete and setup are each audited",
      {"db_create", "db_reveal", "db_password", "db_restore", "db_delete", "db_setup"} <= _acts208, repr(sorted(_acts208)))
check("databases: no password in any audit row or log record",
      not any(s in d for _a, d, _s in _aud208 for s in _SECRETS208 + ["Zadmin208"])
      and not any(s in t for t in _LOG208.text for s in _SECRETS208 + ["Zadmin208"]),
      repr([d for _a, d, _s in _aud208][:6]))
check("databases: the routes reached no host transport", len(_P9_TRIPPED) == _trips208,
      repr(_P9_TRIPPED[_trips208:][:3]))

# ── the remote-delete hook is in delete_remote, and the uninstall hook in the uninstall ─────────
_rem208 = _read99("panel", "routes", "remotes.py")
check("remote delete: delete_remote clears the host's database rows (routes/databases.forget_remote)",
      "_dbr.forget_remote(remote_id)" in _rem208[_rem208.index("def delete_remote"):], "")


# ── 13. the Files page: the tab for the view permission, no host read on render ─────────────────
def _page208():
    out = {}
    sid = _p9_new_server(P9_HOST, "p208p", "pmc", 25567, name="p208 page")
    users = [_user208("pv", ["view_servers", "view_files"], [P9_HOST]), _user208("pf", ["view_files"], [P9_HOST])]
    _S208.reset()
    trips = len(_P9_TRIPPED)
    try:
        _p9_arm(who="part208")
        _stub_in208()
        _p9_patch_sm("list_server_commands", lambda *a, **k: [])
        from panel.routes import server_files as _sf208
        _p9_patch(_sf208, "_host_timezone_cached", lambda *a, **k: "")   # the page's background read
        for key, uid in (("view", users[0][0]), ("files", users[1][0])):
            out[key] = _p9_client(uid).get("/server/%d/files" % sid).get_data(as_text=True)
        out["calls"] = list(_S208.calls)
        out["trips"] = len(_P9_TRIPPED) - trips
    finally:
        _p9_restore_all()
        with _p9.app_context():
            for uid, gid in users:
                for mdl, i in ((_U208, uid), (_G208, gid)):
                    r = _db208.session.get(mdl, i)
                    if r is not None:
                        _db208.session.delete(r)
            _db208.session.commit()
    return out


_pg208 = _page208()
check("files page: the view permission gets the Databases tab, its card (read-only) and its script",
      'data-sfsub-btn="databases"' in _pg208.get("view", "") and 'id="db-card"' in _pg208.get("view", "")
      and "server_databases.js" in _pg208.get("view", "") and "data-fpm-ro" in
      _pg208.get("view", "").split('id="db-card"', 1)[-1][:120], _pg208.get("view", "")[:200])
check("files page: the render reached no host transport", _pg208.get("trips") == 0, repr(_P9_TRIPPED[-2:]))
check("files page: without the view permission no tab, card or script; rendering asked the host nothing",
      'data-sfsub-btn="databases"' not in _pg208.get("files", "x") and "server_databases.js" not in _pg208.get("files", "x")
      and _pg208.get("calls") == [], repr(_pg208.get("calls")))


# ── 14. the debug report prints no database secret ──────────────────────────────────────────────
def _report208():
    from unit.part20 import _env, _generate, _patched
    ct = _cfg208.encrypt_secret("Zreport208secret")
    with _p9.app_context():
        _db208.session.add(_GD208(remote_id=P9_HOST2, game_server_id=None, name="gs1_report", secret=ct))
        _db208.session.add(_HD208(remote_id=P9_HOST2, flavor="mariadb", admin_user="Zreport208user",
                                  admin_secret=ct, panel_admin_secret=ct))
        _db208.session.commit()
    try:
        with _patched():
            _env()
            rep = _generate(_p9)
        return ct, "\n".join(str(rep.get(k, "")) for k in ("report", "summary", "issue_body"))
    finally:
        with _p9.app_context():
            _GD208.query.filter_by(remote_id=P9_HOST2).delete()
            _HD208.query.filter_by(remote_id=P9_HOST2).delete()
            _db208.session.commit()


_ct208, _rep208 = _report208()
check("debug report: no database password, admin login or their ciphertext in the report",
      len(_rep208) > 1000 and not any(s in _rep208 for s in ("Zreport208", _ct208, _ct208[4:40])), _rep208[:200])

# ── 15. the tab's script, in node ───────────────────────────────────────────────────────────────
_JS208 = _read99("panel", "static", "js", "server_databases.js")
_LIST208 = {"state": "ready", "remote_id": 3, "host": {"flavor": "mariadb", "version": "10.11.14-MariaDB", "port": 3306,
                                                         "installed_by_panel": False, "login": False, "warnings": []},
            "probe_warnings": [], "setup_error": "", "can": {"manage": True, "setup": True, "su": False},
            "prefix": "gs7_", "suggest": "luckperms", "cap": 5, "used": 1, "pw_mark": "MASK",
            "databases": [{"id": 4, "name": "gs7_lp", "user": "gs7_lp", "host": "127.0.0.1", "port": 3306,
                           "size": 3 * 1048576, "dumped_at": None, "old_logins": True,
                           "snippets": [{"kind": "luckperms", "label": "LuckPerms", "text": "pw: MASK\n"},
                                        {"kind": "generic", "label": "Generic", "text": "Password: MASK\n"}]}]}
_out208 = _js99("databases tab script", (
    "global.serverId = 7; global.location = {hash: ''}; global.addEventListener = () => {};\n"
    "document.addEventListener = () => {}; global.confirmDialog = o => o.onConfirm();\n"
    "let copied = []; global.copyText = (s) => copied.push(s);\n"
    "E87.prototype.replaceChild = function (n, o) { const i = this.children.indexOf(o); if (i >= 0) this.children[i] = n; return o; };\n"
    + _JS208 + "\n"), (), (
    "  const out = {}, txt = id => document.getElementById(id).textContent;\n"
    "  const walk = (e, f) => { f(e); (e.children || []).forEach(c => walk(c, f)); };\n"
    "  const find = (id, tag) => { const r = []; walk(document.getElementById(id), e => { if (e.tagName === tag) r.push(e); }); return r; };\n"
    "  reply(" + _js208.dumps(_LIST208) + "); out.loaded = await dbLoad(true);\n"
    "  out.preHidden = find('db-list', 'pre').map(p => p.style.display);\n"
    "  out.host = txt('db-host'); out.prefix = txt('db-prefix'); out.name = document.getElementById('db-name').value;\n"
    "  out.count = txt('db-count'); out.list = txt('db-list'); out.pre = find('db-list', 'pre').map(p => p.textContent);\n"
    "  reply({success: true, password: 'REALPW'}); sent = []; await dbReveal(4); await settle();\n"
    "  out.revealSent = sent.map(s => s[0]); out.preAfter = find('db-list', 'pre').map(p => p.textContent);\n"
    "  out.listAfter = txt('db-list').includes('REALPW');\n"
    "  sent = []; await dbCopySnippet(4); out.copySent = sent.length; out.copied = copied.slice();\n"
    "  sent = []; reply({success: true, message: 'ok'}); document.getElementById('db-name').value = ' Core ';\n"
    "  dbAdd(null); await settle(); out.addSent = sent[0];\n"
    "  const full = Object.assign({}, " + _js208.dumps(_LIST208) + ", {used: 5});\n"
    "  reply(full); await dbLoad(true); out.fullDisabled = document.getElementById('db-add-btn').disabled;\n"
    "  out.fullCount = txt('db-count');\n"
    "  sent = []; reply({success: true}); dbDelete(4); await settle(); out.delSent = sent[0];\n"
    "  const none = Object.assign({}, " + _js208.dumps(_LIST208) + ", {state: 'none', host: null, databases: []});\n"
    "  reply(none); await dbLoad(true); out.setupShown = document.getElementById('db-setup').style.display;\n"
    "  out.addShown = document.getElementById('db-add').style.display;\n"
    "  console.log(JSON.stringify(out));\n"), "")
if _out208 is not None:
    check("databases script: the host line, the prefix and the suggested name, the count, and each database with "
          "its old-logins note and the password masked in the snippet",
          _out208.get("loaded") is True and _out208.get("host", "").startswith("MariaDB 10.11 on this host.")
          and _out208.get("prefix") == "gs7_" and _out208.get("name") == "luckperms"
          and _out208.get("count") == "1 of 5 used" and "gs7_lp" in _out208.get("list", "")
          and "only offers newer logins" in _out208.get("list", "") and _out208.get("pre") == ["pw: MASK\n"]
          and _out208.get("preHidden") == ["none"],
          repr(_out208)[:900])
    check("databases script: Show password asks the reveal route once and puts it in the field and the snippet",
          _out208.get("revealSent") == ["/api/server/7/databases/4/reveal"] and _out208.get("preAfter") == ["pw: REALPW\n"]
          and _out208.get("listAfter") is True, repr(_out208)[:900])
    check("databases script: Copy settings copies the snippet with the real password (no second reveal)",
          _out208.get("copySent") == 0 and _out208.get("copied") == ["pw: REALPW\n"], repr(_out208.get("copied")))
    check("databases script: Add posts the name trimmed and lower-cased; at the cap the button is off and says why",
          _out208.get("addSent") == ["/api/server/7/databases", {"name": "core"}] and _out208.get("fullDisabled") is True
          and _out208.get("fullCount") == "This server has 5 databases, the most it may have.", repr(_out208)[:900])
    check("databases script: Delete posts the typed name; a host with no server shows the setup card, not Add",
          _out208.get("delSent") == ["/api/server/7/databases/4/delete", {"confirm": "gs7_lp"}]
          and _out208.get("setupShown") == "" and _out208.get("addShown") == "none", repr(_out208)[:900])
