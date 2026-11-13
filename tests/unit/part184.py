"""Part 184 of the unit suite: a server's files and its backups, each behind its own permission.

Held here:
* The four permissions: grantable, described on the Groups page (a deleted backup is said to be gone
  for good) beside manage_servers, in Spanish and French too.
* Data migration 3: every group holding manage_servers is given view_files and edit_files, once,
  and no group is given a backup permission; a group an administrator takes them from afterwards
  keeps that.
* The routes, through the app: VIEW_FILES reads, EDIT_FILES writes, MANAGE_SERVERS alone reaches
  neither; DOWNLOAD_BACKUP downloads and DELETE_BACKUP deletes a game backup, each on its own, while
  taking one stays superadmin-only. A refused write reaches no host stub and writes no audit row.
* The pages: the Files & Config tabs and controls each viewer's permissions cover, and the secrets
  in LinuxGSM's output unmasked for whoever can read the configs they are kept in.

HOW IT RUNS. The migration on a throwaway database through part18's app; the routes on part12's app
with its transport tripwire armed and every host call stubbed. Nothing reaches a host or data/.
"""
import json as _json184
import os as _os184
import sqlite3 as _sq184
import tempfile as _tf184
import shutil as _shutil184

from types import SimpleNamespace as _NS184

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_VIEWER, _p9, _p9_arm, _p9_audit_count, _p9_client,
                         _p9_patch, _p9_restore_all)
from unit.part18 import _app18
from panel.core import i18n as _i18n184
from panel.db import models as _m184
from panel.routes import panel_backup as _pb184, server_detail as _sd184, server_files as _sf184
from panel.security import auth as _auth184

_NEW184 = (_auth184.VIEW_FILES, _auth184.EDIT_FILES, _auth184.DOWNLOAD_BACKUP, _auth184.DELETE_BACKUP)

# ── 1. the permissions ──────────────────────────────────────────────────────────────────────────
_keys184 = list(_auth184.ALL_PERMISSIONS)
_at184 = _keys184.index(_auth184.MANAGE_SERVERS)
eq("permissions: view_files, edit_files, download_backup and delete_backup are grantable, listed right "
   "after manage_servers on the Groups page",
   _keys184[_at184 + 1:_at184 + 5], list(_NEW184))
check("permissions: delete_backup's description says a deleted backup is gone for good",
      "gone for good" in _auth184.ALL_PERMISSIONS[_auth184.DELETE_BACKUP], "")
_untranslated184 = [(_l, _p) for _l in ("es", "fr") for _p in _NEW184
                    if _i18n184.translate(_l, _auth184.ALL_PERMISSIONS[_p]) == _auth184.ALL_PERMISSIONS[_p]]
check("permissions: each new description reads in Spanish and French", not _untranslated184,
      repr(_untranslated184))

# ── 2. data migration 3 ─────────────────────────────────────────────────────────────────────────
_tmp184 = _tf184.mkdtemp(prefix="p184-")
_mig184 = {}
try:
    _path184 = _os184.path.join(_tmp184, "m.db")
    _app_m184 = _app18(_path184)
    with _app_m184.app_context():
        _m184.db.create_all()
        _G184 = _m184.Group
        for _n, _perms in (("p184_ms", '["view_servers", "manage_servers"]'),
                           ("p184_view", '["view_servers", "view_console"]'),
                           ("p184_half", '["manage_servers", "view_files"]'),
                           ("p184_broken", "not json")):
            _m184.db.session.add(_G184(name=_n, description="", permissions=_perms))
        _m184.db.session.commit()
    _con184 = _sq184.connect(_path184)
    _con184.execute("PRAGMA user_version = 2")      # an install that ran data migrations 1 and 2
    _con184.commit()
    _con184.close()

    def _groups184():
        with _app_m184.app_context():
            out = {g.name: g.permissions for g in _G184.query.all()}
            _m184.db.session.remove()
        return out

    def _version184():
        con = _sq184.connect(_path184)
        try:
            return con.execute("PRAGMA user_version").fetchone()[0]
        finally:
            con.close()

    with _app_m184.app_context():
        _m184._run_data_migrations()
        _m184.db.session.remove()
    _mig184["first"], _mig184["v1"] = _groups184(), _version184()
    # An administrator takes the file permissions back from the group afterwards...
    with _app_m184.app_context():
        _g = _G184.query.filter_by(name="p184_ms").one()
        _g.set_permissions(["view_servers", "manage_servers"])
        _m184.db.session.commit()
        _m184._run_data_migrations()                 # ...and the panel starts again
        _m184.db.session.remove()
    _mig184["second"], _mig184["v2"] = _groups184(), _version184()
    # Repeated by hand (a salvaged database starts its count again): only adds, never twice.
    with _app_m184.app_context():
        _m184._fpm_grant_file_permissions()
        _m184._fpm_grant_file_permissions()
        _m184.db.session.commit()
        _m184.db.session.remove()
    _mig184["repeat"] = _groups184()
finally:
    _shutil184.rmtree(_tmp184, ignore_errors=True)


def _perms184(stage, name):
    try:
        return sorted(_json184.loads(_mig184[stage][name]))
    except (KeyError, TypeError, ValueError):
        return None


eq("data migration 3: a group holding manage_servers is given view_files and edit_files, keeping the rest",
   _perms184("first", "p184_ms"), ["edit_files", "manage_servers", "view_files", "view_servers"])
eq("data migration 3: ...one that already held view_files gets edit_files, each permission once",
   _perms184("first", "p184_half"), ["edit_files", "manage_servers", "view_files"])
eq("data migration 3: a group without manage_servers is left as it was (no file or backup permission)",
   _mig184.get("first", {}).get("p184_view"), '["view_servers", "view_console"]')
eq("data migration 3: a group whose list cannot be read is left as it was, not rewritten",
   _mig184.get("first", {}).get("p184_broken"), "not json")
check("data migration 3: no group is given download_backup or delete_backup",
      not [_n for _n, _p in _mig184.get("first", {}).items()
           if "download_backup" in str(_p) or "delete_backup" in str(_p)], repr(_mig184.get("first")))
eq("data migration 3: counted (user_version 3)", _mig184.get("v1"), 3)
eq("data migration 3: ...ONCE: the next start leaves a group the file permissions were taken from alone",
   (_perms184("second", "p184_ms"), _mig184.get("v2")), (["manage_servers", "view_servers"], 3))
eq("data migration 3: run again by hand it only adds, and adds each permission once",
   _perms184("repeat", "p184_ms"), ["edit_files", "manage_servers", "view_files", "view_servers"])

# ── 3. the routes ───────────────────────────────────────────────────────────────────────────────
_NO_LOGIN184 = "!"      # not a hash any password produces: these accounts cannot sign in
_uids184 = {}
with _p9.app_context():
    from panel.db.models import Group as _PG184, RemoteServer as _PRS184, User as _PU184, db as _pdb184
    for _suffix, _perms in (("view", [_auth184.VIEW_FILES]), ("edit", [_auth184.EDIT_FILES]),
                            ("manage", [_auth184.MANAGE_SERVERS]), ("dl", [_auth184.DOWNLOAD_BACKUP]),
                            ("rm", [_auth184.DELETE_BACKUP])):
        _g = _PG184(name="p184_" + _suffix, description="", is_default=False)
        _g.set_permissions([_auth184.VIEW_SERVERS] + _perms)
        _g.servers.append(_pdb184.session.get(_PRS184, P9_HOST))
        _pdb184.session.add(_g)
        _pdb184.session.flush()
        _u = _PU184(username="p184_" + _suffix, password_hash=_NO_LOGIN184, display_name=_suffix,
                    is_superadmin=False, is_active=True)
        _u.groups.append(_g)
        _pdb184.session.add(_u)
        _pdb184.session.commit()
        _uids184[_suffix] = _u.id

_calls184 = []


def _rec184(name, result):
    def _f(*a, **k):
        _calls184.append(name)
        return result
    return _f


_BK184 = [{"name": "p184-a.tar.zst", "size": 3, "created": 0}]
_url184 = "/api/server/%d" % P9_GS
_r184 = {}
try:
    _p9_arm(who="part184")
    _p9_patch(_sf184, "_read_refused", lambda *a, **k: None)
    _p9_patch(_sf184, "_write_refused", lambda *a, **k: None)
    _p9_patch(_sf184, "read_file", _rec184("read_file", ("hostname x\n", None)))
    _p9_patch(_sf184, "write_file", _rec184("write_file", (True, "")))
    _p9_patch(_sf184, "delete_path", _rec184("delete_path", (True, "")))
    _p9_patch(_sf184, "browse_dir", _rec184("browse_dir", {"path": "", "entries": []}))
    _p9_patch(_pb184, "list_game_backups", _rec184("list_game_backups", _BK184))
    _p9_patch(_pb184, "stream_game_backup", lambda *a, **k: iter([b"abc"]))
    _p9_patch(_pb184, "delete_game_backup", _rec184("delete_game_backup", True))
    _p9_patch(_pb184, "backup_disk_info", lambda *a, **k: {"free": 1, "total": 2})
    _C184 = {_k: _p9_client(_v) for _k, _v in _uids184.items()}
    _C184["admin"], _C184["viewer"] = _p9_client(P9_ADMIN), _p9_client(P9_VIEWER)

    def _probe184(who, method, url, **kw):
        """(status, the host stubs it reached, audit rows it wrote) for one request."""
        del _calls184[:]
        before = _p9_audit_count("edit_file") + _p9_audit_count("delete_file")
        resp = getattr(_C184[who], method)(url, **kw)
        after = _p9_audit_count("edit_file") + _p9_audit_count("delete_file")
        return resp.status_code, list(_calls184), after - before

    _save184 = {"path": "server.cfg", "content": "hostname y\n"}
    for _who in ("view", "edit", "manage", "admin"):
        _r184[_who] = {
            "read": _probe184(_who, "get", _url184 + "/file?path=server.cfg"),
            "browse": _probe184(_who, "get", _url184 + "/browse?path="),
            "save": _probe184(_who, "post", _url184 + "/file", json=_save184),
            "delete": _probe184(_who, "post", _url184 + "/delete-path", json={"path": "old.cfg"}),
        }
    for _who in ("view", "manage"):
        _r184[_who]["upload"] = _probe184(_who, "post", _url184 + "/upload", data={"path": ""})[0]
        _r184[_who]["config"] = _probe184(_who, "post", _url184 + "/config", json={"raw": "x"})[0]
        _r184[_who]["gcf"] = _probe184(_who, "post", _url184 + "/game-config/form", json={})[0]
        _r184[_who]["workshop"] = _probe184(_who, "post", _url184 + "/workshop", json={})[0]
        _r184[_who]["plugins"] = _probe184(_who, "post", _url184 + "/plugins/change", json={})[0]
        _r184[_who]["pz"] = _probe184(_who, "post", _url184 + "/pz-admin-password", json={})[0]
        _r184[_who]["logts"] = _probe184(_who, "post", _url184 + "/log-timestamps", json={"enabled": False})[0]

    _bk_dl184 = "/backup/game/%d/download?name=p184-a.tar.zst" % P9_GS
    _bk_rm184 = "/api/panel/backup/game/%d/delete" % P9_GS
    _bk_info184 = "/api/panel/backup/game/%d/info" % P9_GS
    for _who in ("dl", "rm", "manage", "admin"):
        _d = _C184[_who].get(_bk_dl184)
        del _calls184[:]
        _x = _C184[_who].post(_bk_rm184, json={"name": "p184-a.tar.zst"})
        _r184["bk_" + _who] = {
            "dl": (_d.status_code, _d.get_data() if _d.status_code == 200 else b""),
            "rm": (_x.status_code, "delete_game_backup" in _calls184),
            "info": _C184[_who].get(_bk_info184).status_code,
        }
    for _who in ("dl", "rm"):     # never as the superadmin: that one would start a backup
        _r184["bk_" + _who]["take"] = _C184[_who].post("/api/panel/backup/game/%d" % P9_GS,
                                                       json={"force": False}).status_code

    # The pages.
    _html184 = {_w: _C184[_w].get("/server/%d/files" % P9_GS) for _w in ("view", "edit", "manage", "dl", "viewer")}
    with _p9.test_request_context():
        _fa184 = {_w: _auth184.files_access(_NS184(is_superadmin=False,
                                                    groups=[_NS184(get_permissions=lambda p=_p: set(p))]))
                  for _w, _p in (("view", {"view_files"}), ("manage", {"manage_servers"}),
                                 ("dl", {"download_backup"}), ("none", {"view_console"}))}
    with _p9.app_context():
        _sees184 = {_w: _sd184._dtl_sees_secrets(_pdb184.session.get(_PU184, _uids184[_w]))
                    for _w in ("view", "manage")}
        _sees184["superadmin"] = _sd184._dtl_sees_secrets(_pdb184.session.get(_PU184, P9_ADMIN))
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _u in _PU184.query.filter(_PU184.username.like("p184_%")).all():
            _pdb184.session.delete(_u)
        for _g in _PG184.query.filter(_PG184.name.like("p184_%")).all():
            _pdb184.session.delete(_g)
        _pdb184.session.commit()

# VIEW_FILES reads, EDIT_FILES writes.
eq("files: VIEW_FILES reads and browses (the host read reached), and its save and delete are refused "
   "before the host, with no audit row",
   _r184["view"], {"read": (200, ["read_file"], 0), "browse": (200, ["browse_dir"], 0),
                   "save": (403, [], 0), "delete": (403, [], 0)})
eq("files: EDIT_FILES saves and deletes (the host write reached, audited), and cannot read or browse",
   _r184["edit"], {"read": (403, [], 0), "browse": (403, [], 0),
                   "save": (200, ["write_file"], 1), "delete": (200, ["delete_path"], 1)})
eq("files: MANAGE_SERVERS alone no longer reaches a server's files, read or write",
   _r184["manage"], {"read": (403, [], 0), "browse": (403, [], 0), "save": (403, [], 0),
                     "delete": (403, [], 0)})
eq("files: a superadmin reads, browses, saves and deletes (control)",
   [_v[0] for _v in _r184["admin"].values()], [200, 200, 200, 200])
eq("files: without EDIT_FILES every other write is refused: upload, the LinuxGSM config, the game "
   "config form, the Workshop list, a plugin change, the PZ admin password, log stamping off",
   [_r184[_w][_k] for _w in ("view", "manage")
    for _k in ("upload", "config", "gcf", "workshop", "plugins", "pz", "logts")], [403] * 14)

# Backups.
eq("backups: DOWNLOAD_BACKUP downloads the archive, and its delete is refused before the host",
   (_r184["bk_dl"]["dl"], _r184["bk_dl"]["rm"]), ((200, b"abc"), (403, False)))
eq("backups: DELETE_BACKUP deletes it (the host delete reached), and its download is refused (sent home)",
   (_r184["bk_rm"]["rm"], _r184["bk_rm"]["dl"][0]), ((200, True), 302))
eq("backups: MANAGE_SERVERS reaches neither, nor the listing",
   (_r184["bk_manage"]["dl"][0], _r184["bk_manage"]["rm"], _r184["bk_manage"]["info"]), (302, (403, False), 403))
eq("backups: either backup permission opens the listing; taking a backup stays superadmin-only",
   [(_r184["bk_" + _w]["info"], _r184["bk_" + _w]["take"]) for _w in ("dl", "rm")], [(200, 403), (200, 403)])
eq("backups: a superadmin downloads and deletes (control)",
   (_r184["bk_admin"]["dl"][0], _r184["bk_admin"]["rm"]), (200, (200, True)))


def _tabs184(resp):
    body = resp.get_data(as_text=True)
    return resp.status_code, [_t for _t in ("config", "files", "backups", "schedule", "alerts", "mods")
                              if 'data-sfsub-btn="%s"' % _t in body]


eq("page: Files & Config shows each viewer the tabs their permissions cover, and none to a console viewer",
   {_w: _tabs184(_r) for _w, _r in _html184.items()},
   {"view": (200, ["config", "files"]), "edit": (302, []), "manage": (200, ["schedule", "alerts", "mods"]),
    "dl": (200, ["backups"]), "viewer": (302, [])})
_vb184 = _html184["view"].get_data(as_text=True)
check("page: without EDIT_FILES the config editor and the file browser are drawn read-only",
      'data-sfsub="config" data-fpm-ro' in _vb184 and 'data-sfsub="files" style="display:none;" data-fpm-ro' in _vb184,
      "")
_db184 = _html184["dl"].get_data(as_text=True)
check("page: a download-only viewer's Backups card hides the schedule, Back up now and delete",
      "data-fpm-nosu" in _db184 and "data-fpm-nodel" in _db184 and "data-fpm-nodl" not in _db184, "")
eq("page: who may open Files & Config (auth.files_access)",
   {_w: _f["page"] for _w, _f in _fa184.items()}, {"view": True, "manage": True, "dl": True, "none": False})
eq("secrets: LinuxGSM's output is unmasked for whoever can read the configs (VIEW_FILES), not for "
   "MANAGE_SERVERS alone",
   _sees184, {"view": True, "manage": False, "superadmin": True})
