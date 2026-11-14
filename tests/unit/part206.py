r"""Part 206 of the unit suite: Mods cards for Arma 3 / DayZ folders, NS2: Combat, Factorio and Minecraft.

* Which games get which Mods card (cod_mods.mods_kind): arma3 and dayz the folder lists, and the
  Workshop card's kind for ns2c (workshop.workshop_kind).
* Arma 3 / DayZ (services/arma_mods, routes/game_mods): the @folder listing run by bash in a temp
  home (real folders only, never serverfiles/workshop, a link or an odd name), then the route through
  the app: GET lists the folders and both lists, POST writes `mods` / `servermods` joined by `\;` into
  the instance cfg (every other line kept), a folder not listed is refused, a key the secrets file
  sets is refused, without EDIT_FILES a save is 403, a root-capable account 409, each save audited.
* ns2c (routes/workshop): the hex mod ids in `mods` read as Workshop ids and saved back as hex.

Every route check drives part12's app with the account's shell run by bash against a temp home and
the transport tripwire armed. Nothing reaches a host or data/.
"""
import hashlib as _hl206
import json as _js206
import os as _os206
import shutil as _shutil206
import subprocess as _sp206  # nosec B404 - bash over the commands this part builds, in a temp folder
import tempfile as _tf206
import zipfile as _zf206

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part99 import _js99, _read99
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_NO_AUDIT, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.db.models import Group as _G206, RemoteServer as _RS206, User as _U206, db as _db206
from panel.routes import server_files as _sf206, workshop as _wsr206
from panel.security import auth as _auth206
from panel.services import (arma_mods as _am206, cod_mods as _cm206, fctr_mods as _fm206, mc_packs as _mp206,
                            modrinth as _mr206)

_trips206 = len(_P9_TRIPPED)
_U = "p206u"
_R206 = {}

# ── 1. which games get which card ───────────────────────────────────────────────────────────────
eq("mods tab: arma3 and dayz get the mod folder card, fctr the Factorio card, mc and pmc datapacks, mcb packs",
   [_cm206.mods_kind(g) for g in ("arma3", "dayz", "ARMA3", "fctr", "mc", "pmc", "mcb", "ns2")],
   ["arma", "arma", "arma", "fctr", "mc", "mc", "mcb", ""])
with open(_os206.path.join(_root, "tests", "unit", "lgsm_shortnames.txt"), encoding="utf-8") as _fh206:
    _SHORT206 = {ln.strip() for ln in _fh206 if ln.strip() and not ln.startswith("#")}
eq("mods tab: every game given a card of its own is a LinuxGSM shortname",
   sorted(set(_cm206.OTHER_KINDS) | _wsr206.NS2_GAMES) == sorted((set(_cm206.OTHER_KINDS) | _wsr206.NS2_GAMES)
                                                                 & _SHORT206), True)
eq("workshop card: ns2c's mods list is a Workshop list of its own kind",
   [_wsr206.workshop_kind(g) for g in ("ns2c", "ns2", "arma3")], ["ns2", None, "mods"])


def _touch206(path, text=""):
    _os206.makedirs(_os206.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _bash206(sh, home):
    """(stdout, stderr, rc) of `sh` with /home/p206u pointing at `home`."""
    r = _sp206.run(["bash", "-c", sh.replace("/home/" + _U, home)], capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, check=False)
    return r.stdout, r.stderr, r.returncode


def _shell206(home):
    def _run(server, user, sh, **k):
        out, err, rc = _bash206(sh, home)
        return out.strip(), err, rc
    return _run


def _read206(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _ro_user206():
    """A user with the Mods tab (MANAGE_SERVERS) and VIEW_FILES, but no EDIT_FILES."""
    with _p9.app_context():
        g = _G206(name="p206_ro", description="", is_default=False)
        g.set_permissions([_auth206.MANAGE_SERVERS, _auth206.VIEW_FILES])
        g.servers.append(_db206.session.get(_RS206, P9_HOST))
        u = _U206(username="p206_ro", password_hash=_auth206.hash_password("Str0ng!passw0rd-p206"),
                  display_name="p206", is_superadmin=False, is_active=True)
        u.groups.append(g)
        _db206.session.add_all([g, u])
        _db206.session.commit()
        return u.id, g.id


def _drop_user206(uid, gid):
    with _p9.app_context():
        for model, i in ((_U206, uid), (_G206, gid)):
            row = _db206.session.get(model, i)
            if row is not None:
                _db206.session.delete(row)
        _db206.session.commit()


# ── 2. Arma 3 / DayZ: the listing, by bash in a temp home ───────────────────────────────────────
def _arma_home206(tmp):
    """An Arma 3 home: @folders at the top and in mods/, Workshop items, and folders never listed."""
    home = _os206.path.join(tmp, "home")
    sf = _os206.path.join(home, "serverfiles")
    for f in ("@CBA_A3/addons/cba.pbo", "mods/@ace/addons/ace.pbo", "mods/@acex/meta.cpp", "workshop/@450814997/x",
              "@bad name/x", "keys/a.bikey", "mods/plain/x", ".@hid/x"):
        _touch206(_os206.path.join(sf, f))
    _touch206(_os206.path.join(tmp, "outside", "@evil", "x"))
    _os206.symlink(_os206.path.join(tmp, "outside", "@evil"), _os206.path.join(sf, "@evil"))
    return home


def _arma_listed206(prep=None):
    tmp = _tf206.mkdtemp(prefix="p206-")
    try:
        home = _arma_home206(tmp)
        if prep:
            prep(tmp, home)
        return _am206.parse_listing(_bash206(_am206.list_sh(_U), home)[0])
    finally:
        _shutil206.rmtree(tmp, ignore_errors=True)


def _mods_link_out206(tmp, home):
    """serverfiles/mods made a link out of the home."""
    sf = _os206.path.join(home, "serverfiles")
    _shutil206.move(_os206.path.join(sf, "mods"), _os206.path.join(tmp, "mods-out"))
    _os206.symlink(_os206.path.join(tmp, "mods-out"), _os206.path.join(sf, "mods"))


eq("arma mods list: real @folders in serverfiles and serverfiles/mods; never workshop/, a link, an odd or "
   "hidden name, or a folder without the @",
   _arma_listed206(), ["@CBA_A3", "mods/@ace", "mods/@acex"])
eq("arma mods list: a mods folder that is a link is not looked in", _arma_listed206(_mods_link_out206), ["@CBA_A3"])
eq("arma mods list: an answer without the listing's frame is no answer", _am206.parse_listing("T @x\n"), None)
eq("arma mods value: split at \\; or a bare ;, and joined with \\;",
   (_am206.split_value("mods/@ace\\;@CBA_A3; ;@x"), _am206.join_value(["@a", "mods/@b"])),
   (["mods/@ace", "@CBA_A3", "@x"], "@a\\;mods/@b"))

# ── 3. Arma 3 / DayZ: the route through the app ─────────────────────────────────────────────────
_ARMA_DEFAULT206 = ('mods=""\nservermods=""\nworkshopmods=""\nstartparameters="-ip=${ip} -port=${port} '
                    '-mod=${mods} -servermod=${servermods} -autoinit"\n')
_ARMA_INST206 = '# Instance\nport="2302"\nmods="mods/@ace\\;@gone"\n'


def _arma_cfg206(home, name="arma3server.cfg"):
    return _os206.path.join(home, "lgsm", "config-lgsm", "arma3server", name)


def _arma_get206(c, sid):
    r = c.get("/api/server/%d/mod-folders" % sid)
    return r.status_code, _p9_json(r)


def _arma_post206(c, sid, body):
    r = c.post("/api/server/%d/mod-folders" % sid, json=body)
    return r.status_code, _p9_json(r)


def _arma_cases206(sid, home, admin):
    _R206["a_get"] = _arma_get206(admin, sid)
    _R206["a_save"] = _arma_post206(admin, sid, {"mods": ["@CBA_A3", "mods/@ace", "@gone"],
                                                 "servermods": ["mods/@acex"]})
    _R206["a_audit"] = _p9_audit("mods_folders_save")
    _R206["a_inst"] = _read206(_arma_cfg206(home))
    _R206["a_get2"] = _arma_get206(admin, sid)
    _R206["a_same"] = _arma_post206(admin, sid, {"mods": ["@CBA_A3", "mods/@ace", "@gone"],
                                                 "servermods": ["mods/@acex"]})
    _R206["a_bad"] = [_arma_post206(admin, sid, b)[1].get("message") for b in (
        {"mods": ["@evil"]}, {"mods": ["../x"]}, {"mods": ["workshop/@450814997"]},
        {"mods": ["@CBA_A3", "@CBA_A3"]}, {"mods": ["@CBA_A3"], "servermods": ["@CBA_A3"]}, {"mods": "@CBA_A3"})]
    _R206["a_inst_bad"] = _read206(_arma_cfg206(home))


def _arma_refusals206(sid, home, admin):
    uid, gid = _ro_user206()
    try:
        ro = _p9_client(uid)
        _R206["a_ro"] = (_arma_get206(ro, sid)[0], _arma_post206(ro, sid, {"mods": []})[0])
    finally:
        _drop_user206(uid, gid)
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: "Refused: p206 is root-capable")
    _R206["a_root"] = _arma_post206(admin, sid, {"mods": []})
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    _touch206(_arma_cfg206(home, "secrets-arma3server.cfg"), 'servermods="@x"\n')
    _R206["a_secrets_get"] = _arma_get206(admin, sid)[1]
    _R206["a_secrets"] = _arma_post206(admin, sid, {"mods": [], "servermods": []})
    _R206["a_inst_secrets"] = _read206(_arma_cfg206(home))


_tmp206 = _tf206.mkdtemp(prefix="p206-")
_sid206 = None
try:
    _home206 = _arma_home206(_tmp206)
    _touch206(_arma_cfg206(_home206, "_default.cfg"), _ARMA_DEFAULT206)
    _touch206(_arma_cfg206(_home206), _ARMA_INST206)
    _sid206 = _p9_new_server(P9_HOST, _U, "arma3", 2302)
    _p9_arm(who="part206")
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])   # the files page's background read
    _p9_patch_sm("shell_as_game_user", _shell206(_home206))
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    _admin206 = _p9_client(P9_ADMIN)
    _arma_cases206(_sid206, _home206, _admin206)
    _arma_refusals206(_sid206, _home206, _admin206)
    _R206["a_page"] = _admin206.get("/server/%d/files" % _sid206).get_data(as_text=True)
finally:
    _p9_restore_all()
    if _sid206 is not None:
        _p9_delete_server(_sid206)
    _shutil206.rmtree(_tmp206, ignore_errors=True)

_ag206 = _R206.get("a_get", (0, {}))
eq("arma mods route: GET lists the folders and the current lists, a value whose folder is gone kept in place",
   (_ag206[0], _ag206[1].get("folders"), _ag206[1].get("mods"), _ag206[1].get("servermods"),
    _ag206[1].get("secrets"), _ag206[1].get("workshop")),
   (200, ["@CBA_A3", "mods/@ace", "mods/@acex"], ["mods/@ace", "@gone"], [], [], False))
check("arma mods route: a save writes mods and servermods joined by \\; into the instance cfg, every other line "
      "kept, and says a restart applies it",
      _R206.get("a_inst") == '# Instance\nport="2302"\nmods="@CBA_A3\\\\;mods/@ace\\\\;@gone"\n'
                             'servermods="mods/@acex"\n'
      and _R206.get("a_save", (0, {}))[1].get("changed") is True
      and "Restart" in _R206["a_save"][1].get("message", ""), repr((_R206.get("a_save"), _R206.get("a_inst"))))
eq("arma mods route: ...LinuxGSM's sourcing of that line reads back the same lists",
   (_R206.get("a_get2", (0, {}))[1].get("mods"), _R206.get("a_get2", (0, {}))[1].get("servermods")),
   (["@CBA_A3", "mods/@ace", "@gone"], ["mods/@acex"]))
eq("arma mods route: the save is audited with each list before and after",
   (_R206.get("a_audit", _P9_NO_AUDIT).detail, _R206.get("a_audit", _P9_NO_AUDIT).success),
   ("mods: mods/@ace;@gone -> @CBA_A3;mods/@ace;@gone; servermods: (none) -> mods/@acex", True))
eq("arma mods route: the same lists again change nothing",
   _R206.get("a_same", (0, {}))[1].get("changed"), False)
eq("arma mods route: a link, a path, a Workshop folder, a duplicate, one folder in both lists and a list that is "
   "not a list are each refused with the cfg untouched",
   (_R206.get("a_bad"), _R206.get("a_inst_bad") == _R206.get("a_inst")),
   ([_am206.NOT_A_FOLDER] * 3 + [_am206.DUPLICATE, _am206.BOTH_LISTS, _am206.NOT_A_FOLDER], True))
eq("arma mods route: without EDIT_FILES the lists read but a save is refused (403)", _R206.get("a_ro"), (200, 403))
eq("arma mods route: a root-capable account is refused (409) before the host is asked",
   (_R206.get("a_root", (0, {}))[0], _R206.get("a_root", (0, {}))[1].get("success")), (409, False))
check("arma mods route: a list the secrets file sets is shown as locked, and changing it is refused, cfg untouched",
      _R206.get("a_secrets_get", {}).get("secrets") == ["servermods"]
      and _R206.get("a_secrets", (0, {}))[1].get("message") == _am206.IN_SECRETS
      and _R206.get("a_inst_secrets") == _R206.get("a_inst"), repr((_R206.get("a_secrets_get"), _R206.get("a_secrets"))))
check("files page: an Arma 3 server's Mods tab holds the mod folder card and its script",
      'data-sfsub-btn="mods"' in _R206.get("a_page", "") and 'id="gm-arma-card"' in _R206.get("a_page", "")
      and "server_game_mods.js" in _R206.get("a_page", "") and 'id="mods-card"' not in _R206.get("a_page", ""))

# ── 4. ns2c: hex mod ids through the Workshop card ──────────────────────────────────────────────
eq("ns2c mods: hex mod ids read as Workshop ids (Shine's 706d242 is 117887554); other words are ignored",
   _wsr206.ns2_ids("706d242 5F35045 706d242 zz -x"), (["117887554", "99831877"], ["zz", "-x"]))
eq("ns2c mods: Workshop ids are written as lower-case hex, space separated",
   _wsr206.ns2_value(["117887554", "99831877"]), "706d242 5f35045")


def _ns2_cfg206(home, name="ns2cserver.cfg"):
    return _os206.path.join(home, "lgsm", "config-lgsm", "ns2cserver", name)


_tmp206n = _tf206.mkdtemp(prefix="p206-")
_sid206n = None
try:
    _touch206(_ns2_cfg206(_tmp206n, "_default.cfg"), 'mods=""\n')
    _touch206(_ns2_cfg206(_tmp206n), 'port="27015"\nmods="706d242"\n')
    _sid206n = _p9_new_server(P9_HOST, _U, "ns2c", 27015)
    _p9_arm(who="part206")
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])   # the files page's background read
    _p9_patch_sm("shell_as_game_user", _shell206(_tmp206n))
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    _c206n = _p9_client(P9_ADMIN)
    _R206["n_get"] = _p9_json(_c206n.get("/api/server/%d/workshop" % _sid206n))
    _R206["n_save"] = _p9_json(_c206n.post("/api/server/%d/workshop" % _sid206n,
                                           json={"ids": ["99831877", "117887554"]}))
    _R206["n_inst"] = _read206(_ns2_cfg206(_tmp206n))
    _R206["n_audit"] = _p9_audit("workshop_save")
finally:
    _p9_restore_all()
    if _sid206n is not None:
        _p9_delete_server(_sid206n)
    _shutil206.rmtree(_tmp206n, ignore_errors=True)

eq("ns2c workshop route: GET shows the mods value's hex ids as Workshop ids",
   (_R206.get("n_get", {}).get("kind"), _R206.get("n_get", {}).get("ids")), ("ns2", ["117887554"]))
check("ns2c workshop route: a save writes the ids into mods as hex, in order, and audits them as Workshop ids",
      _R206.get("n_save", {}).get("success") is True
      and _R206.get("n_inst") == 'port="27015"\nmods="5f35045 706d242"\n'
      and _R206.get("n_audit", _P9_NO_AUDIT).detail == "mods: 117887554 -> 99831877 117887554",
      repr((_R206.get("n_save"), _R206.get("n_inst"), _R206.get("n_audit", _P9_NO_AUDIT).detail)))
_tpl206 = open(_os206.path.join(_root, "panel", "templates", "server_detail.html"), encoding="utf-8").read()
_ns2b206 = _tpl206[_tpl206.find("{% if _wsc_kind == 'ns2' %}"):]
check("ns2c Workshop card: its own note says the ids are written as hex, and Download now is only for workshopmods",
      "as the hex mod ids the game takes" in _ns2b206[:400] and "{% if _wsc_kind == 'mods' and _wsc_dl %}" in _tpl206,
      _ns2b206[:200])

# ── 5. Factorio: the listing and mod-list.json, through the app ─────────────────────────────────
_FCTR_LIST206 = ('{"mods": [{"name": "base", "enabled": true}, {"name": "space-age", "enabled": true}, '
                 '{"name": "krastorio2", "enabled": false, "x": 1}], "extra": true}')


def _fctr_home206(tmp):
    home = _os206.path.join(tmp, "home")
    md = _os206.path.join(home, "serverfiles", "mods")
    for f in ("krastorio2_1.3.24.zip", "Squeak-Through_1.8.2.zip", "even-distribution/info.json", "notes.txt",
              "bad name_1.0.0.zip", "noversion.zip", ".hidden_1.0.0.zip"):
        _touch206(_os206.path.join(md, f))
    _touch206(_os206.path.join(md, "mod-list.json"), _FCTR_LIST206)
    _touch206(_os206.path.join(tmp, "outside", "linked_1.0.0.zip"))
    _os206.symlink(_os206.path.join(tmp, "outside", "linked_1.0.0.zip"), _os206.path.join(md, "linked_1.0.0.zip"))
    cfg = _os206.path.join(home, "lgsm", "config-lgsm", "fctrserver")
    _touch206(_os206.path.join(cfg, "_default.cfg"), 'startparameters="--start-server-load-latest"\nextraparams=""\n')
    _touch206(_os206.path.join(cfg, "fctrserver.cfg"), 'port="34197"\n')
    return home


def _fctr_post206(c, sid, name, enabled):
    r = c.post("/api/server/%d/factorio-mods" % sid, json={"name": name, "enabled": enabled})
    return r.status_code, _p9_json(r)


def _fctr_list_json206(home):
    try:
        return _js206.loads(_read206(_os206.path.join(home, "serverfiles", "mods", "mod-list.json")) or "null")
    except ValueError:
        return None


def _fctr_cases206(sid, home, admin):
    _R206["f_get"] = _p9_json(admin.get("/api/server/%d/factorio-mods" % sid))
    _R206["f_on"] = _fctr_post206(admin, sid, "krastorio2", True)
    _R206["f_on_audit"] = _p9_audit("mods_factorio_enable")
    _R206["f_off"] = _fctr_post206(admin, sid, "Squeak-Through", False)
    _R206["f_off_audit"] = _p9_audit("mods_factorio_disable")
    _R206["f_list"] = _fctr_list_json206(home)
    _R206["f_again"] = _fctr_post206(admin, sid, "krastorio2", True)
    _R206["f_bad"] = [_fctr_post206(admin, sid, n, e)[1].get("message") for n, e in (
        ("base", False), ("nope", True), ("../x", True), ("linked", True), ("notes", True))]
    _R206["f_list_bad"] = _fctr_list_json206(home)


def _fctr_running206(sid, home, admin):
    """GET and POST while a process of the account runs serverfiles/bin/x64/factorio (a copy of python)."""
    import sys as _sys206
    exe = _os206.path.join(home, "serverfiles", "bin", "x64", "factorio")
    _os206.makedirs(_os206.path.dirname(exe), exist_ok=True)
    _shutil206.copy2(_os206.path.realpath(_sys206.executable), exe)
    path = _os206.path.join(home, "serverfiles", "mods", "mod-list.json")
    before = _read206(path)
    proc = _sp206.Popen([exe, "-S", "-c", "import time; time.sleep(60)"],  # nosec B603 - a stand-in game in a temp home
                        stdout=_sp206.DEVNULL, stderr=_sp206.DEVNULL)
    try:
        running = _p9_json(admin.get("/api/server/%d/factorio-mods" % sid)).get("running")
        post = _fctr_post206(admin, sid, "krastorio2", False)[1]
    finally:
        proc.kill()
        proc.wait()
    stopped = _p9_json(admin.get("/api/server/%d/factorio-mods" % sid)).get("running")
    return running, post.get("success"), post.get("message", ""), _read206(path) == before, stopped


def _fctr_refusals206(sid, home, admin):
    uid, gid = _ro_user206()
    try:
        ro = _p9_client(uid)
        _R206["f_ro"] = (ro.get("/api/server/%d/factorio-mods" % sid).status_code,
                         _fctr_post206(ro, sid, "krastorio2", False)[0])
    finally:
        _drop_user206(uid, gid)
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: "Refused: p206 is root-capable")
    _R206["f_root"] = _fctr_post206(admin, sid, "krastorio2", False)
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    cfg = _os206.path.join(home, "lgsm", "config-lgsm", "fctrserver", "fctrserver.cfg")
    _touch206(cfg, 'port="34197"\nextraparams="--mod-directory /srv/mods"\n')
    _R206["f_where"] = _p9_json(admin.get("/api/server/%d/factorio-mods" % sid)).get("where")
    _R206["f_elsewhere"] = _fctr_post206(admin, sid, "krastorio2", False)[1].get("message")
    _touch206(cfg, 'port="34197"\n')
    _R206["f_running"] = _fctr_running206(sid, home, admin)
    _os206.remove(_os206.path.join(home, "serverfiles", "mods", "mod-list.json"))
    _R206["f_missing"] = (_p9_json(admin.get("/api/server/%d/factorio-mods" % sid)).get("mod_list"),
                          _fctr_post206(admin, sid, "krastorio2", False)[1].get("message"))


_tmp206f = _tf206.mkdtemp(prefix="p206-")
_sid206f = None
try:
    _home206f = _fctr_home206(_tmp206f)
    _sid206f = _p9_new_server(P9_HOST, _U, "fctr", 34197)
    _p9_arm(who="part206")
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])   # the files page's background read
    _p9_patch_sm("shell_as_game_user", _shell206(_home206f))
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    _c206f = _p9_client(P9_ADMIN)
    _fctr_cases206(_sid206f, _home206f, _c206f)
    _fctr_refusals206(_sid206f, _home206f, _c206f)
    _R206["f_page"] = _c206f.get("/server/%d/files" % _sid206f).get_data(as_text=True)
finally:
    _p9_restore_all()
    if _sid206f is not None:
        _p9_delete_server(_sid206f)
    _shutil206.rmtree(_tmp206f, ignore_errors=True)

_fg206 = _R206.get("f_get", {})
eq("factorio mods route: GET lists the built-in mods first, then each zip or folder mod by name, on or off as "
   "mod-list.json says (a mod not in it yet is on); a link, an odd name or a zip with no version is not a mod",
   [(m.get("name"), m.get("enabled"), m.get("builtin"), m.get("files")) for m in _fg206.get("mods", [])],
   [("base", True, True, []), ("space-age", True, True, []), ("even-distribution", True, False, ["even-distribution"]),
    ("krastorio2", False, False, ["krastorio2_1.3.24.zip"]), ("Squeak-Through", True, False, ["Squeak-Through_1.8.2.zip"])])
eq("factorio mods route: ...with the list's state and where to upload",
   (_fg206.get("mod_list"), _fg206.get("where"), _fg206.get("dir")), ("ok", "", "serverfiles/mods"))
_fl206 = _R206.get("f_list") or {}
check("factorio mods route: turning one on sets its entry, turning a new one off appends it, and every other key "
      "and entry is kept in order",
      _fl206.get("mods") == [{"name": "base", "enabled": True}, {"name": "space-age", "enabled": True},
                             {"name": "krastorio2", "enabled": True, "x": 1},
                             {"name": "Squeak-Through", "enabled": False}] and _fl206.get("extra") is True
      and _R206.get("f_on", (0, {}))[1].get("changed") is True and "Restart" in _R206["f_on"][1].get("message", ""),
      repr((_R206.get("f_on"), _fl206)))
eq("factorio mods route: each change is audited with the mod and what it became",
   (_R206.get("f_on_audit", _P9_NO_AUDIT).detail, _R206.get("f_off_audit", _P9_NO_AUDIT).detail,
    _R206.get("f_on_audit", _P9_NO_AUDIT).success), ("krastorio2: on", "Squeak-Through: off", True))
eq("factorio mods route: the same state again changes nothing", _R206.get("f_again", (0, {}))[1].get("changed"), False)
eq("factorio mods route: base off, a mod not there, a path, a link and a file that is not a mod are refused, the "
   "list untouched",
   (_R206.get("f_bad"), _R206.get("f_list_bad") == _R206.get("f_list")),
   ([_fm206.BASE_ON] + [_fm206.NOT_A_MOD] * 4, True))
eq("factorio mods route: without EDIT_FILES the mods read but a change is refused (403)", _R206.get("f_ro"), (200, 403))
eq("factorio mods route: a root-capable account is refused (409) before the host is asked",
   _R206.get("f_root", (0, {}))[0], 409)
eq("factorio mods route: a start line passing --mod-directory is shown and not edited",
   (_R206.get("f_where"), _R206.get("f_elsewhere")), ("mod-directory", _fm206.ELSEWHERE))
eq("factorio mods route: before the first start (no mod-list.json) nothing is written",
   _R206.get("f_missing"), ("missing", _fm206.NO_LIST))
check("files page: a Factorio server's Mods tab holds the Factorio card and says the mod portal is not used",
      'id="gm-fctr-card"' in _R206.get("f_page", "") and "Factorio mod portal" in _R206.get("f_page", ""))

# ── 6. Minecraft Java: datapacks, and Modrinth's, through the app ───────────────────────────────

_MCDEF206 = ('startparameters="nogui"\nextraparams=""\nexecutabledir="${serverfiles}"\n'
             'executable="./minecraft_server.jar"\npreexecutable="java -Xmx${javaram}M -jar"\n')
_DP_BODY206 = b"PK-terralith-bytes"
_DP_SHA206 = _hl206.sha512(_DP_BODY206).hexdigest()
_DP_CDN206 = "https://cdn.modrinth.com/data/AbCdEf12/versions/VvVvVv12/Terralith_1.21_v2.5.8.zip"


def _mc_home206(tmp):
    home = _os206.path.join(tmp, "home")
    sf = _os206.path.join(home, "serverfiles")
    _touch206(_os206.path.join(sf, "server.properties"), "#Minecraft server properties\nlevel-name=world\n")
    _touch206(_os206.path.join(sf, "world", "datapacks", "VanillaTweaks (1).zip"), "x" * 2048)
    _touch206(_os206.path.join(sf, "world", "datapacks", "vt", "pack.mcmeta"), "{}")
    _touch206(_os206.path.join(sf, "plugins", "x.jar"))
    with _zf206.ZipFile(_os206.path.join(sf, "minecraft_server.jar"), "w") as z:
        z.writestr("version.json", '{"id": "1.21.4", "name": "1.21.4"}')
    _touch206(_os206.path.join(home, "lgsm", "config-lgsm", "mcserver", "_default.cfg"), _MCDEF206)
    return home


def _modrinth206(asked, body=_DP_BODY206):
    """A stand-in for Modrinth: search, the project, its datapack versions, and the file."""
    def _get(url, cap, hosts, timeout=None):
        asked.append(url)
        if "/search?" in url:
            return _js206.dumps({"hits": [{"project_id": "AbCdEf12", "title": "Terralith", "description": "d",
                                           "author": "a", "downloads": 9}]}).encode(), None
        if url.endswith("/project/AbCdEf12"):
            return _js206.dumps({"title": "Terralith"}).encode(), None
        if "/project/AbCdEf12/version" in url:
            return _js206.dumps([{"id": "VvVvVv12", "project_id": "AbCdEf12", "version_type": "release",
                                  "version_number": "2.5.8", "loaders": ["datapack"],
                                  "files": [{"url": _DP_CDN206, "filename": "Terralith_1.21_v2.5.8.zip", "primary": True,
                                             "size": len(body), "hashes": {"sha512": _DP_SHA206}}]}]).encode(), None
        if url == _DP_CDN206:
            return body, None
        return None, "unexpected"
    return _get


def _mc_cases206(sid, home, admin):
    dp = _os206.path.join(home, "serverfiles", "world", "datapacks")
    asked = []
    _p9_patch(_mr206, "_mdr_http_get", _modrinth206(asked))
    _R206["m_get"] = _p9_json(admin.get("/api/server/%d/mc-packs" % sid))
    _R206["m_search"] = _p9_json(admin.get("/api/server/%d/mc-packs/search?q=terra&mc=1.21.4" % sid))
    _R206["m_search_url"] = asked[-1] if asked else ""
    _R206["m_install"] = _p9_json(admin.post("/api/server/%d/mc-packs/install" % sid, json={"project_id": "AbCdEf12"}))
    _R206["m_install_audit"] = _p9_audit("mods_datapack_install")
    _R206["m_version_url"] = next((u for u in asked if "/version?" in u), "")
    _R206["m_file"] = open(_os206.path.join(dp, "Terralith_1.21_v2.5.8.zip"), "rb").read() \
        if _os206.path.exists(_os206.path.join(dp, "Terralith_1.21_v2.5.8.zip")) else None
    r = admin.post("/api/server/%d/mc-packs/install" % sid, json={"project_id": "AbCdEf12"})
    _R206["m_again"] = (r.status_code, _p9_json(r).get("success"))
    _p9_patch(_mr206, "_mdr_http_get", _modrinth206([], body=b"tampered"))
    _os206.remove(_os206.path.join(dp, "Terralith_1.21_v2.5.8.zip"))
    _R206["m_badhash"] = (_p9_json(admin.post("/api/server/%d/mc-packs/install" % sid,
                                              json={"project_id": "AbCdEf12"})).get("message"),
                          _os206.path.exists(_os206.path.join(dp, "Terralith_1.21_v2.5.8.zip")))
    _R206["m_remove"] = _p9_json(admin.post("/api/server/%d/mc-packs" % sid, json={"action": "remove", "name": "vt"}))
    _R206["m_remove_audit"] = _p9_audit("mods_datapack_remove")
    _R206["m_vt_gone"] = not _os206.path.exists(_os206.path.join(dp, "vt"))
    _R206["m_bad"] = [_p9_json(admin.post("/api/server/%d/mc-packs" % sid, json={"action": "remove", "name": n}))
                      .get("message") for n in ("../server.properties", "plugins", "nope.zip")]
    _R206["m_props_kept"] = _os206.path.exists(_os206.path.join(home, "serverfiles", "server.properties"))


def _mc_refusals206(sid, home, admin):
    uid, gid = _ro_user206()
    try:
        ro = _p9_client(uid)
        _R206["m_ro"] = (ro.get("/api/server/%d/mc-packs" % sid).status_code,
                         ro.post("/api/server/%d/mc-packs/install" % sid, json={"project_id": "AbCdEf12"}).status_code,
                         ro.post("/api/server/%d/mc-packs" % sid, json={"action": "remove", "name": "x"}).status_code)
    finally:
        _drop_user206(uid, gid)
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: "Refused: p206 is root-capable")
    _R206["m_root"] = admin.post("/api/server/%d/mc-packs" % sid,
                                 json={"action": "remove", "name": "VanillaTweaks (1).zip"}).status_code
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    cfg = _os206.path.join(home, "lgsm", "config-lgsm", "mcserver", "mcserver.cfg")
    _touch206(cfg, 'startparameters="nogui --world other"\n')
    _R206["m_moved"] = _p9_json(admin.get("/api/server/%d/mc-packs" % sid))
    _R206["m_moved_install"] = admin.post("/api/server/%d/mc-packs/install" % sid,
                                          json={"project_id": "AbCdEf12"}).status_code


_tmp206m = _tf206.mkdtemp(prefix="p206-")
_sid206m = None
try:
    _home206m = _mc_home206(_tmp206m)
    _sid206m = _p9_new_server(P9_HOST, _U, "mc", 25565)
    _p9_arm(who="part206")
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])   # the files page's background read
    _p9_patch_sm("shell_as_game_user", _shell206(_home206m))
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    _c206m = _p9_client(P9_ADMIN)
    _mc_cases206(_sid206m, _home206m, _c206m)
    _mc_refusals206(_sid206m, _home206m, _c206m)
    _R206["m_page"] = _c206m.get("/server/%d/files" % _sid206m).get_data(as_text=True)
    _R206["m_cod"] = _c206m.get("/api/server/%d/cod-mods" % _sid206m).status_code
finally:
    _p9_restore_all()
    if _sid206m is not None:
        _p9_delete_server(_sid206m)
    _shutil206.rmtree(_tmp206m, ignore_errors=True)

_mg206 = _R206.get("m_get", {})
eq("datapacks route: GET finds the world level-name names, its datapacks (files and folders) and the Minecraft "
   "version in minecraft_server.jar",
   (_mg206.get("world"), [(p.get("name"), p.get("folder"), p.get("managed")) for p in _mg206.get("datapacks", [])],
    _mg206.get("mc_version"), _mg206.get("dir"), _mg206.get("kind")),
   ("world", [("VanillaTweaks (1).zip", False, True), ("vt", True, True)],
    "1.21.4" if _shutil206.which("unzip") else None, "serverfiles/world/datapacks", "java"))
check("datapacks route: search asks Modrinth for datapacks on the server's version",
      _R206.get("m_search", {}).get("hits", [{}])[0].get("project_id") == "AbCdEf12"
      and "project_type%3Adatapack" in _R206.get("m_search_url", "") and "versions%3A1.21.4" in _R206.get("m_search_url", ""),
      _R206.get("m_search_url", ""))
check("datapacks route: install takes Modrinth's datapack build, checks its sha512 and writes the .zip into the "
      "world's datapacks folder",
      _R206.get("m_install", {}).get("success") is True and _R206.get("m_file") == _DP_BODY206
      and "datapack" in _R206.get("m_version_url", "") and "Terralith" in _R206.get("m_install_audit", _P9_NO_AUDIT).detail
      and _R206.get("m_install_audit", _P9_NO_AUDIT).detail.endswith("-> world"),
      repr((_R206.get("m_install"), _R206.get("m_version_url"), _R206.get("m_install_audit", _P9_NO_AUDIT).detail)))
eq("datapacks route: a second install of the same file is refused (409), never written over",
   _R206.get("m_again"), (409, False))
eq("datapacks route: a file that does not match Modrinth's checksum is not installed",
   _R206.get("m_badhash"), (_mr206.BAD_HASH, False))
check("datapacks route: remove deletes one datapack of the world and is audited",
      _R206.get("m_remove", {}).get("success") is True and _R206.get("m_vt_gone") is True
      and _R206.get("m_remove_audit", _P9_NO_AUDIT).detail == "world/vt", repr(_R206.get("m_remove")))
eq("datapacks route: a path, a folder beside the world and a pack not there are refused, nothing deleted",
   (_R206.get("m_bad"), _R206.get("m_props_kept")), ([_mp206.NOT_A_PACK] * 3, True))
eq("datapacks route: without EDIT_FILES the list reads but install and remove are refused (403)",
   _R206.get("m_ro"), (200, 403, 403))
eq("datapacks route: a root-capable account is refused (409)", _R206.get("m_root"), 409)
check("datapacks route: a start line that picks another world shows why and installs nothing",
      _R206.get("m_moved", {}).get("world") is None and _R206.get("m_moved", {}).get("why")
      and _R206.get("m_moved_install") == 409, repr(_R206.get("m_moved")))
check("files page: a Minecraft server's Mods tab holds the datapack card; the CoD route says it is not CoD",
      'id="gm-mc-card"' in _R206.get("m_page", "") and _R206.get("m_cod") == 404)

# ── 7. Minecraft Bedrock: shared packs on or off for the world ──────────────────────────────────
_BP206 = "0aba1b58-2cdc-4d31-9cee-4dc5e2c39bf6"
_RP206 = "11111111-2222-3333-4444-555555555555"
_OTHER206 = {"pack_id": "99999999-2222-3333-4444-555555555555", "version": [1, 0, 0], "extra": 1}


def _mcb_home206(tmp):
    home = _os206.path.join(tmp, "home")
    sf = _os206.path.join(home, "serverfiles")
    _touch206(_os206.path.join(sf, "server.properties"), "server-name=x\nlevel-name=Bedrock level\n")
    _touch206(_os206.path.join(sf, "behavior_packs", "bp1", "manifest.json"),
              _js206.dumps({"format_version": 2, "header": {"name": "BP One", "uuid": _BP206.upper(),
                                                            "version": [1, 0, 0]}}))
    _touch206(_os206.path.join(sf, "behavior_packs", "broken", "manifest.json"), "{not json")
    _touch206(_os206.path.join(sf, "resource_packs", "rp1", "manifest.json"),
              _js206.dumps({"header": {"name": "RP", "uuid": _RP206, "version": [2, 1, 0]}}))
    _touch206(_os206.path.join(tmp, "outside", "evil", "manifest.json"),
              _js206.dumps({"header": {"name": "E", "uuid": _RP206.replace("1", "7"), "version": [1, 0, 0]}}))
    _os206.symlink(_os206.path.join(tmp, "outside", "evil"), _os206.path.join(sf, "behavior_packs", "evil"))
    _touch206(_os206.path.join(sf, "worlds", "Bedrock level", "world_behavior_packs.json"), _js206.dumps([_OTHER206]))
    _touch206(_os206.path.join(home, "lgsm", "config-lgsm", "mcbserver", "_default.cfg"),
              'startparameters=""\nextraparams=""\nexecutabledir="${serverfiles}"\npreexecutable=""\n')
    return home


def _mcb_post206(c, sid, t, uuid, on):
    r = c.post("/api/server/%d/mc-packs" % sid, json={"type": t, "uuid": uuid, "enabled": on})
    return r.status_code, _p9_json(r)


def _mcb_world_json206(home, t):
    text = _read206(_os206.path.join(home, "serverfiles", "worlds", "Bedrock level", "world_%s_packs.json" % t))
    try:
        return None if text is None else _js206.loads(text)
    except ValueError:
        return "bad"


def _mcb_cases206(sid, home, admin):
    _R206["b_get"] = _p9_json(admin.get("/api/server/%d/mc-packs" % sid))
    _R206["b_on"] = _mcb_post206(admin, sid, "behavior", _BP206, True)
    _R206["b_on_audit"] = _p9_audit("mods_bedrock_enable")
    _R206["b_rp_on"] = _mcb_post206(admin, sid, "resource", _RP206, True)
    _R206["b_lists_on"] = (_mcb_world_json206(home, "behavior"), _mcb_world_json206(home, "resource"))
    _R206["b_get_on"] = _p9_json(admin.get("/api/server/%d/mc-packs" % sid))
    _R206["b_again"] = _mcb_post206(admin, sid, "behavior", _BP206, True)[1].get("changed")
    _R206["b_off"] = _mcb_post206(admin, sid, "behavior", _BP206, False)
    _R206["b_off_audit"] = _p9_audit("mods_bedrock_disable")
    _R206["b_list_off"] = _mcb_world_json206(home, "behavior")
    _R206["b_bad"] = [_mcb_post206(admin, sid, t, u, True)[1].get("message") for t, u in (
        ("behavior", "not-a-uuid"), ("resource", _BP206), ("skin", _BP206), ("behavior", _RP206.replace("1", "7")))]
    _touch206(_os206.path.join(home, "serverfiles", "server.properties"), "level-name=New world\n")
    _R206["b_nodir"] = _mcb_post206(admin, sid, "behavior", _BP206, True)[1].get("message")
    _R206["b_nodir_made"] = _os206.path.exists(_os206.path.join(home, "serverfiles", "worlds", "New world"))


_tmp206b = _tf206.mkdtemp(prefix="p206-")
_sid206b = None
try:
    _home206b = _mcb_home206(_tmp206b)
    _sid206b = _p9_new_server(P9_HOST, _U, "mcb", 19132)
    _p9_arm(who="part206")
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])   # the files page's background read
    _p9_patch_sm("shell_as_game_user", _shell206(_home206b))
    _p9_patch(_sf206, "game_account_write_refusal", lambda *a, **k: None)
    _c206b = _p9_client(P9_ADMIN)
    _mcb_cases206(_sid206b, _home206b, _c206b)
    _R206["b_search"] = _c206b.get("/api/server/%d/mc-packs/search?q=x" % _sid206b).status_code
    _R206["b_page"] = _c206b.get("/server/%d/files" % _sid206b).get_data(as_text=True)
finally:
    _p9_restore_all()
    if _sid206b is not None:
        _p9_delete_server(_sid206b)
    _shutil206.rmtree(_tmp206b, ignore_errors=True)

_bg206 = _R206.get("b_get", {})
eq("bedrock packs route: GET lists each shared pack from its manifest (a link is not followed, a manifest that "
   "does not read is shown and not offered) and whether the world turns it on",
   (_bg206.get("world"), _bg206.get("world_dir"),
    [(p.get("type"), p.get("folder"), p.get("uuid"), p.get("version"), p.get("ok"), p.get("enabled"))
     for p in _bg206.get("packs", [])]),
   ("Bedrock level", True, [("behavior", "bp1", _BP206, [1, 0, 0], True, False),
                            ("behavior", "broken", "", [], False, False),
                            ("resource", "rp1", _RP206, [2, 1, 0], True, False)]))
eq("bedrock packs route: turning packs on adds {pack_id, version} to the world's lists, every other entry kept, "
   "and a list not there yet is made",
   _R206.get("b_lists_on"), ([_OTHER206, {"pack_id": _BP206, "version": [1, 0, 0]}],
                             [{"pack_id": _RP206, "version": [2, 1, 0]}]))
eq("bedrock packs route: ...the read then shows both on, and the same change again changes nothing",
   ([p.get("enabled") for p in _R206.get("b_get_on", {}).get("packs", [])], _R206.get("b_again")),
   ([True, False, True], False))
eq("bedrock packs route: turning one off removes its entry only",
   _R206.get("b_list_off"), [_OTHER206])
eq("bedrock packs route: each change is audited with the pack and what it became",
   (_R206.get("b_on_audit", _P9_NO_AUDIT).detail, _R206.get("b_off_audit", _P9_NO_AUDIT).detail),
   ("behavior bp1 (%s): on" % _BP206, "behavior bp1 (%s): off" % _BP206))
eq("bedrock packs route: a bad uuid, a pack of the other type, an unknown type and a linked pack are refused",
   _R206.get("b_bad"), [_mp206.NOT_A_PACK] * 4)
eq("bedrock packs route: a world folder not made yet is refused and not created",
   (_R206.get("b_nodir"), _R206.get("b_nodir_made")), (_mp206.NO_WORLD_DIR, False))
eq("bedrock packs route: Bedrock gets no Modrinth datapack search", _R206.get("b_search"), 404)
check("files page: a Bedrock server's Mods tab holds the packs card", 'id="gm-mcb-card"' in _R206.get("b_page", ""))

# ── 8. the cards' script, in node ───────────────────────────────────────────────────────────────
_GMJS206 = _read99("panel", "static", "js", "server_game_mods.js")
_out206 = _js99("game mods cards", (
    "global.serverId = 1; global.SF_CAN = {manage: false}; global._tr = s => s; global.browse = () => {};\n"
    "global._uis_sfShow = () => {}; global.confirmDialog = o => o.onConfirm();\n" + _GMJS206 + "\n"), (), (
    "  const out = {}, txt = id => document.getElementById(id).textContent;\n"
    "  const btns = id => { const r = []; const walk = e => { if (e.attrs && e.attrs['data-action']) r.push(\n"
    "    e.attrs['data-action'] + ' ' + e.attrs['data-args']); (e.children || []).forEach(walk); };\n"
    "    walk(document.getElementById(id)); return r; };\n"
    "  reply({folders: ['@CBA_A3', 'mods/@ace'], mods: ['mods/@ace', '@gone'], servermods: [],\n"
    "         secrets: ['servermods'], workshop: true});\n"
    "  out.armaLoaded = await gmArmaLoad();\n"
    "  out.armaMods = txt('gm-arma-mods'); out.armaOther = btns('gm-arma-other'); out.armaNote = txt('gm-arma-note');\n"
    "  gmArmaAdd('mods', '@CBA_A3'); gmArmaMove('mods', 2, -1); gmArmaAdd('servermods', 'mods/@ace');\n"
    "  reply({success: true, message: 'Saved.'}); sent = []; await gmArmaSave(null); out.armaSent = sent.slice();\n"
    "  reply({mods: [{name: 'base', enabled: true, builtin: true, files: []},\n"
    "                {name: 'k2', enabled: false, builtin: false, files: ['k2_1.0.0.zip']}], mod_list: 'ok', where: ''});\n"
    "  await gmFctrLoad(); out.fctr = btns('gm-fctr-list'); out.fctrText = txt('gm-fctr-list');\n"
    "  reply({mods: [], mod_list: 'missing', where: ''}); await gmFctrLoad(); out.fctrNote = txt('gm-fctr-note');\n"
    "  reply({world: 'w', why: '', world_dir: false, bad_lists: [], packs: [{type: 'behavior', folder: 'bp',\n"
    "         uuid: 'u', version: [1, 0, 0], name: 'BP', enabled: false, ok: true}]});\n"
    "  await gmMcbLoad(); out.mcbNoDir = btns('gm-mcb-list'); out.mcbWorld = txt('gm-mcb-world');\n"
    "  reply({world: 'w', why: '', world_dir: true, bad_lists: [], packs: [{type: 'behavior', folder: 'bp',\n"
    "         uuid: 'u', version: [1, 0, 0], name: 'BP', enabled: false, ok: true}]});\n"
    "  await gmMcbLoad(); out.mcb = btns('gm-mcb-list');\n"
    "  reply({world: null, why: 'it is empty', datapacks: [], mc_version: null, dir: ''}); await gmMcLoad();\n"
    "  out.mcWorld = txt('gm-mc-world');\n"
    "  console.log(JSON.stringify(out));\n"), "")
if _out206 is not None:
    check("arma card: each list in order with a gone folder marked, a list the secrets file holds offered no "
          "add, and the Workshop note",
          _out206.get("armaLoaded") is True and "2. @gone(folder not found)" in _out206.get("armaMods", "")
          and _out206.get("armaOther") == ['gmArmaAdd ["mods","@CBA_A3"]'] and "Workshop" in _out206.get("armaNote", ""),
          repr(_out206))
    eq("arma card: Add, Move and Save post the new lists (a folder already in a list is not added twice)",
       _out206.get("armaSent"), [["/api/server/1/mod-folders", {"mods": ["mods/@ace", "@CBA_A3", "@gone"],
                                                                "servermods": []}]])
    check("factorio card: base has no switch, another mod is offered Turn on; no mod-list.json says why",
          _out206.get("fctr") == ['gmFctrSet ["k2",true]'] and "k2_1.0.0.zip" in _out206.get("fctrText", "")
          and "first time the server starts" in _out206.get("fctrNote", ""), repr(_out206))
    check("bedrock card: before the world folder exists nothing is offered and it says why; then Turn on is",
          _out206.get("mcbNoDir") == [] and "start the server once" in _out206.get("mcbWorld", "")
          and _out206.get("mcb") == ['gmMcbSet ["behavior","u",true]'], repr(_out206))
    check("datapack card: a world the panel cannot tell says why",
          "can't tell which world folder" in _out206.get("mcWorld", "") and "it is empty" in _out206.get("mcWorld", ""),
          repr(_out206))
eq("game mods: nothing reached a real transport", _P9_TRIPPED[_trips206:], [])

_fr206 = _R206.get("f_running") or (None,) * 5
check("factorio mods: while the game runs (a process of the account running serverfiles/bin/*/factorio) the card "
      "says so and a change is refused, the list untouched (Factorio writes it back when it stops); stopped, it is not",
      _fr206[0] is True and _fr206[1] is False and "Stop the server first" in _fr206[2] and _fr206[3] is True
      and _fr206[4] is False, repr(_fr206))
check("datapack card: a Paper build that writes no version_history.json is read from paper.jar's version.json, "
      "version_history.json still first",
      _mp206.java_mc_version({"paper": None, "paperjar": '{"id": "26.3"}'}, "pmc") == "26.3"
      and _mp206.java_mc_version({"paper": '{"currentVersion": "1.21.4-212-abc (MC: 1.21.4)"}',
                                  "paperjar": '{"id": "26.3"}'}, "pmc") == "1.21.4"
      and _mp206.java_mc_version({"paper": None, "paperjar": None}, "pmc") is None
      and 'unzip -p "$sf/paper.jar" version.json' in _mp206.java_sh("p206u"))
