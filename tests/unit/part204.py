"""Part 204 of the unit suite: the Mods tab, and a Call of Duty server's mod folder switch.

Held here:
* Which games get which Mods card (services/cod_mods.mods_kind): LinuxGSM's installer only for the
  games LinuxGSM's core_getopt.sh gives mods-install, the fs_game switch for the five CoD games, and
  no Mods tab at all for the rest; every key is a LinuxGSM shortname.
* The mod folder listing (cod_mods.list_sh) run by bash in a temp home: a CoD1 folder holding a .pk3,
  CoD4's mods/<name>, never the base game's folder, a hidden or oddly named folder, a link out of the
  home, or anything at all when serverfiles itself leads out of the home.
* The callers: /api/server/<id>/cod-mods read and switch through the app, with the account's shell
  run by bash against a temp home: the switch writes fs_game into the instance cfg's start line and
  back to "none" restores the file byte for byte; a folder that is not listed, a root-capable account,
  a viewer without EDIT_FILES, fs_game held in extraparams, and a game that is not CoD are each
  refused with the cfg untouched; each switch is audited with the folder before and after.
* The Files & Config page: a CoD server's Mods tab holds the CoD card, not LinuxGSM's installer, and
  a game with neither has no Mods tab.
* The card's drawing (server_files.js _codModsDraw) in node.

HOW IT RUNS. Shell text runs under bash in temp folders; everything else drives part12's app with its
transport tripwire armed. Nothing reaches a host or data/.
"""
import os as _os204
import shutil as _shutil204
import subprocess as _sp204  # nosec B404 - bash over the commands this part builds, in a temp folder
import tempfile as _tf204

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_NO_AUDIT, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part99 import _SF99, _js99
from panel.db.models import Group as _G204, RemoteServer as _RS204, User as _U204, db as _db204
from panel.routes import server_files as _sf204
from panel.security import auth as _auth204
from panel.services import cod_mods as _cm204

_trips204 = len(_P9_TRIPPED)
_U = "p204u"

# ── 1. which games get which card ───────────────────────────────────────────────────────────────
with open(_os204.path.join(_root, "tests", "unit", "lgsm_shortnames.txt"), encoding="utf-8") as _fh204:
    _SHORT204 = {ln.strip() for ln in _fh204 if ln.strip() and not ln.startswith("#")}
check("mods tab: every game the panel offers a Mods card for is a LinuxGSM shortname",
      not ((_cm204.LGSM_MODS_GAMES | _cm204.COD_GAMES) - _SHORT204),
      sorted((_cm204.LGSM_MODS_GAMES | _cm204.COD_GAMES) - _SHORT204))
eq("mods tab: LinuxGSM's installer for source-engine and core_getopt's named games, the fs_game switch "
   "for CoD, nothing for a game with neither",
   [_cm204.mods_kind(g) for g in ("csgo", "gmod", "rust", "vh", "cs", "cod", "coduo", "cod2", "cod4", "codwaw",
                                  "mc", "ark", "q3", "")],
   ["lgsm"] * 5 + ["cod"] * 5 + [""] * 4)
eq("mods tab: 30 source-engine games plus cs2, rust, sdtd, cs, dod, tfc, ns, ts, hldm and vh",
   len(_cm204.LGSM_MODS_GAMES), 40)
eq("mods tab: where a mod is uploaded: serverfiles for CoD1/UO (a folder beside main), serverfiles/mods "
   "for CoD2, CoD4 and WaW",
   [_cm204.upload_dir(g) for g in ("cod", "coduo", "cod2", "cod4", "codwaw")],
   ["serverfiles", "serverfiles", "serverfiles/mods", "serverfiles/mods", "serverfiles/mods"])

# ── 2. the listing, run by bash in a temp home ──────────────────────────────────────────────────


def _touch204(path, text=""):
    _os204.makedirs(_os204.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _home204(tmp):
    """A CoD home under `tmp`: base folders, two mods of each layout, and the folders never listed."""
    home = _os204.path.join(tmp, "home")
    sf = _os204.path.join(home, "serverfiles")
    for f in ("main/pak0.pk3", "uo/pakuo00.pk3", "awe/zzz_awe.PK3", "bad name/a.pk3", ".hid/a.pk3",
              "Logs/games_mp.log", "mods/promod/mod.ff", "mods/.x/mod.ff", "pb/pbsv.so"):
        _touch204(_os204.path.join(sf, f))
    _os204.makedirs(_os204.path.join(sf, "mods", "ok2"))
    _touch204(_os204.path.join(tmp, "outside", "evil", "a.pk3"))
    _os204.symlink(_os204.path.join(tmp, "outside", "evil"), _os204.path.join(sf, "linked"))
    _os204.symlink(_os204.path.join(tmp, "outside"), _os204.path.join(sf, "mods", "lnk"))
    return home


def _bash204(sh, home):
    """(stdout, stderr, rc) of `sh` with /home/p204u pointing at `home`."""
    r = _sp204.run(["bash", "-c", sh.replace("/home/" + _U, home)], capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, check=False)
    return r.stdout, r.stderr, r.returncode


def _listed204(game, prep=None):
    tmp = _tf204.mkdtemp(prefix="p204-")
    try:
        home = _home204(tmp)
        if prep:
            prep(tmp, home)
        out = _bash204(_cm204.list_sh(_U, game), home)[0]
        got = _cm204._parse_listing(out)
        return None if got is None else ([m["value"] for m in got[0]], got[1])
    finally:
        _shutil204.rmtree(tmp, ignore_errors=True)


def _sf_out204(tmp, home):
    """serverfiles moved out of the home and linked back in."""
    _shutil204.move(_os204.path.join(home, "serverfiles"), _os204.path.join(tmp, "sf-out"))
    _os204.symlink(_os204.path.join(tmp, "sf-out"), _os204.path.join(home, "serverfiles"))


eq("cod mods list: CoD1 lists a folder beside main holding a .pk3 (any case), never main, uo, a hidden or "
   "oddly named folder, or a link out of the home",
   _listed204("cod"), (["awe"], False))
eq("cod mods list: CoD4 lists mods/<name> folders only, not a hidden one or a link out of the home",
   _listed204("cod4"), (["mods/ok2", "mods/promod"], True))
eq("cod mods list: CoD2 lists both forms (no .iwd in a top folder here)",
   _listed204("cod2"), (["mods/ok2", "mods/promod"], True))
eq("cod mods list: serverfiles that leads out of the home lists nothing",
   (_listed204("cod", _sf_out204), _listed204("cod4", _sf_out204)), (([], False), ([], False)))
eq("cod mods list: an answer without the listing's frame is no answer, not an empty list",
   _cm204._parse_listing("T awe\n"), None)

# ── 3. the routes, through the app, with the account's shell run against a temp home ───────────
_DEFAULT204 = ('##### Game Server Settings #####\nstartparameters="+set sv_punkbuster 0 +set fs_basepath '
               '${serverfiles} +set dedicated 2 +set net_ip ${ip} +set net_port ${port} +exec ${servercfg}"\n'
               'extraparams=""\n')
_INST204 = '##### Instance Configuration #####\n# Settings added here override _default.cfg.\nport="28960"\n'
_R204 = {}


def _cfgdir204(home):
    return _os204.path.join(home, "lgsm", "config-lgsm", "codserver")


def _inst_text204(home):
    with open(_os204.path.join(_cfgdir204(home), "codserver.cfg"), encoding="utf-8") as fh:
        return fh.read()


def _shell204(home):
    def _run(server, user, sh, **k):
        out, err, rc = _bash204(sh, home)
        return out.strip(), err, rc
    return _run


def _post204(c, sid, mod):
    r = c.post("/api/server/%d/cod-mods" % sid, json={"mod": mod})
    return r.status_code, _p9_json(r)


def _get204(c, sid):
    r = c.get("/api/server/%d/cod-mods" % sid)
    return r.status_code, _p9_json(r)


def _ro_user204():
    """A user with the Mods tab (MANAGE_SERVERS) and VIEW_FILES, but no EDIT_FILES."""
    with _p9.app_context():
        g = _G204(name="p204_ro", description="", is_default=False)
        g.set_permissions([_auth204.MANAGE_SERVERS, _auth204.VIEW_FILES])
        g.servers.append(_db204.session.get(_RS204, P9_HOST))
        u = _U204(username="p204_ro", password_hash=_auth204.hash_password("Str0ng!passw0rd-p204"),
                  display_name="p204", is_superadmin=False, is_active=True)
        u.groups.append(g)
        _db204.session.add_all([g, u])
        _db204.session.commit()
        return u.id, g.id


def _drop_user204(uid, gid):
    with _p9.app_context():
        for model, i in ((_U204, uid), (_G204, gid)):
            row = _db204.session.get(model, i)
            if row is not None:
                _db204.session.delete(row)
        _db204.session.commit()


def _route_cases204(sid, home, admin):
    """Every route case against one CoD server; results into _R204."""
    _R204["get"] = _get204(admin, sid)
    _R204["use"] = _post204(admin, sid, "awe")
    _R204["audit_use"] = _p9_audit("mods_select")
    _R204["inst_use"] = _inst_text204(home)
    _R204["get_after"] = _get204(admin, sid)
    _R204["none"] = _post204(admin, sid, "")
    _R204["audit_none"] = _p9_audit("mods_select")
    _R204["inst_none"] = _inst_text204(home)
    _R204["again"] = _post204(admin, sid, "")
    _R204["inst_again"] = _inst_text204(home)
    _R204["bad"] = [_post204(admin, sid, m)[1].get("success") for m in ("../awe", "main", "linked", "mods/x", "a b")]
    _R204["inst_bad"] = _inst_text204(home)


def _refusal_cases204(sid, home, admin):
    """The switch refused by the account check, the permission and extraparams; results into _R204."""
    uid, gid = _ro_user204()
    try:
        ro = _p9_client(uid)
        _R204["ro_get"] = _get204(ro, sid)[0]
        _R204["ro_post"] = _post204(ro, sid, "awe")[0]
    finally:
        _drop_user204(uid, gid)
    _p9_patch(_sf204, "game_account_write_refusal", lambda *a, **k: "Refused: p204 is root-capable")
    _R204["root"] = _post204(admin, sid, "awe")
    _p9_patch(_sf204, "game_account_write_refusal", lambda *a, **k: None)
    _touch204(_os204.path.join(_cfgdir204(home), "common.cfg"), 'extraparams="+set fs_game awe"\n')
    _R204["extra_get"] = _get204(admin, sid)[1]
    _R204["extra"] = _post204(admin, sid, "")
    _R204["inst_refused"] = _inst_text204(home)
    _R204["csgo"] = _get204(admin, P9_GS)[0]


_tmp204 = _tf204.mkdtemp(prefix="p204-")
_sid204 = None
try:
    _home204v = _home204(_tmp204)
    _touch204(_os204.path.join(_cfgdir204(_home204v), "_default.cfg"), _DEFAULT204)
    _touch204(_os204.path.join(_cfgdir204(_home204v), "codserver.cfg"), _INST204)
    _sid204 = _p9_new_server(P9_HOST, _U, "cod", 28960)
    _p9_arm(who="part204")
    _p9_patch_sm("shell_as_game_user", _shell204(_home204v))
    _p9_patch(_sf204, "game_account_write_refusal", lambda *a, **k: None)
    _admin204 = _p9_client(P9_ADMIN)
    _route_cases204(_sid204, _home204v, _admin204)
    _refusal_cases204(_sid204, _home204v, _admin204)
    _R204["page"] = _admin204.get("/server/%d/files" % _sid204).get_data(as_text=True)
    _mc204 = _p9_new_server(P9_HOST, "p204mc", "mc", 25565)
    _R204["page_mc"] = _admin204.get("/server/%d/files" % _mc204).get_data(as_text=True)
    _p9_delete_server(_mc204)
finally:
    _p9_restore_all()
    if _sid204 is not None:
        _p9_delete_server(_sid204)
    _shutil204.rmtree(_tmp204, ignore_errors=True)

_g204 = _R204.get("get", (0, {}))
eq("cod mods route: GET lists the server's mod folders, no active mod, where to upload",
   (_g204[0], [m.get("value") for m in _g204[1].get("mods", [])], _g204[1].get("active"),
    _g204[1].get("upload_dir"), _g204[1].get("where")),
   (200, ["awe"], "", "serverfiles", ""))
check("cod mods route: Use writes `+set fs_game awe` into the instance cfg's start line, from LinuxGSM's "
      "own start line in _default.cfg, and says a restart applies it",
      _R204.get("use", (0, {}))[1].get("changed") is True
      and _R204.get("inst_use") == _INST204 + 'startparameters="+set fs_game awe +set sv_punkbuster 0 +set '
      'fs_basepath ${serverfiles} +set dedicated 2 +set net_ip ${ip} +set net_port ${port} +exec ${servercfg}"\n'
      and "Restart" in _R204["use"][1].get("message", ""), repr((_R204.get("use"), _R204.get("inst_use"))))
eq("cod mods route: ...and the read then names awe as the active mod",
   _R204.get("get_after", (0, {}))[1].get("active"), "awe")
eq("cod mods route: back to None restores the instance cfg byte for byte",
   (_R204.get("none", (0, {}))[1].get("changed"), _R204.get("inst_none") == _INST204), (True, True))
eq("cod mods route: None again changes nothing and writes nothing",
   (_R204.get("again", (0, {}))[1].get("changed"), _R204.get("inst_again") == _INST204), (False, True))
eq("cod mods route: each switch is audited with the folder before and after",
   (_R204.get("audit_use", _P9_NO_AUDIT).detail, _R204.get("audit_use", _P9_NO_AUDIT).success,
    _R204.get("audit_none", _P9_NO_AUDIT).detail, _R204.get("audit_none", _P9_NO_AUDIT).success),
   ("(none) -> awe", True, "awe -> (none)", True))
eq("cod mods route: a path, the base game's folder, a link out of the home, a folder not there and a bad "
   "name are each refused with the cfg untouched",
   (_R204.get("bad"), _R204.get("inst_bad") == _INST204), ([False] * 5, True))
eq("cod mods route: without EDIT_FILES the list reads but a switch is refused (403)",
   (_R204.get("ro_get"), _R204.get("ro_post")), (200, 403))
eq("cod mods route: a root-capable account is refused (409) before the host is asked",
   (_R204.get("root", (0, {}))[0], _R204.get("root", (0, {}))[1].get("success")), (409, False))
check("cod mods route: fs_game held in extraparams is shown, and a switch is refused with the cfg untouched",
      _R204.get("extra_get", {}).get("where") == "extraparams" and _R204.get("extra_get", {}).get("active") == "awe"
      and _R204.get("extra", (0, {}))[1].get("message") == _cm204.IN_EXTRAPARAMS
      and _R204.get("inst_refused") == _INST204, repr((_R204.get("extra_get"), _R204.get("extra"))))
eq("cod mods route: a server that is not Call of Duty has no CoD mods (404)", _R204.get("csgo"), 404)
_pg204 = _R204.get("page", "")
check("files page: a CoD server's Mods tab holds the CoD card, not LinuxGSM's installer",
      'data-sfsub-btn="mods"' in _pg204 and 'id="codmods-card"' in _pg204 and 'id="mods-card"' not in _pg204,
      _pg204[:200])
check("files page: a game with no mods the panel can manage has no Mods tab and no mods card",
      'data-sfsub-btn="mods"' not in _R204.get("page_mc", "x") and 'mods-card' not in _R204.get("page_mc", "x")
      and "Files" in _R204.get("page_mc", ""))
eq("cod mods: nothing reached a real transport", _P9_TRIPPED[_trips204:], [])

# ── 4. the card's drawing, in node ──────────────────────────────────────────────────────────────
_out204 = _js99("cod mods card", (
    "var serverId = 1; function _tr(s){ return s; } function esc(s){ return escapeHtml(s); }\n"
    "document.querySelectorAll = () => [];\n"), ("function codModsMsg(", "function _codModRow(",
                                                 "function _codModsDraw(", "function loadCodMods("), (
    "  const out = {};\n"
    "  for (const [k, d] of [['top', {mods: [{value: 'awe', name: 'awe'}], active: 'gone', where: '',\n"
    "                                upload_dir: 'serverfiles', mods_dir: false}],\n"
    "                        ['sub', {mods: [{value: 'mods/p<b>', name: 'p<b>'}], active: '', where: 'extraparams',\n"
    "                                upload_dir: 'serverfiles/mods', mods_dir: false}]]) {\n"
    "    answer(d); const drew = await loadCodMods(true);\n"
    "    out[k] = {drew, list: document.getElementById('codmods-list').innerHTML,\n"
    "              where: document.getElementById('codmods-where').style.display,\n"
    "              up: document.getElementById('codmods-upload').textContent, dir: _codModsUpload}; }\n"
    "  console.log(JSON.stringify(out));\n"), _SF99)
if _out204 is not None:
    _top204, _sub204 = _out204.get("top", {}), _out204.get("sub", {})
    check("cod mods card: None and each folder get a row, the active one missing from disk is marked as not "
          "found, and Use is offered for the rest",
          _top204.get("drew") is True and "None (the base game)" in _top204.get("list", "")
          and "(folder not found)" in _top204.get("list", "") and _top204.get("list", "").count("fpm-edit") == 2
          and _top204.get("dir") == "serverfiles", repr(_top204))
    check("cod mods card: a folder name is escaped, fs_game held in extraparams is said, and with no mods "
          "folder the upload goes to serverfiles with how to make it",
          "p&lt;b&gt;" in _sub204.get("list", "") and "<b>" not in _sub204.get("list", "")
          and _sub204.get("where") == "" and "make a folder named mods" in _sub204.get("up", "")
          and _sub204.get("dir") == "serverfiles", repr(_sub204))
