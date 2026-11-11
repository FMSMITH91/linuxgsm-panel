"""Part 173 of the unit suite: a server's Steam Workshop list (panel/routes/workshop.py).

Held here:
* Which games have the card, and which kind: LinuxGSM's workshopmods games, the wscollectionid pair
  (gmod, csgo) and Project Zomboid's ini.
* What is checked before anything is written: ids of 1-20 digits (or a steamcommunity.com link's
  id=, never fetched), at most 200, each once; Mod IDs that cannot break the ini line.
* Project Zomboid's ini keeps every byte but the WorkshopItems= and Mods= lines.
* Steam's titles: both methods POSTed to the fixed host in batches of at most 100, cached, and a
  Steam that does not answer leaves the ids bare instead of failing.
* The routes: the Settings tab's permission, the file browser's refusals, the writes through the
  Settings tab's and the file editor's helpers as the game account (never csgo's wsapikey), and an
  audit row per save with the ids before and after.
* The page and the card's script in node: titles drawn as text, links reduced to their id, nothing
  posted that the server would refuse.

HOW IT RUNS. The network is never touched: panel/services/steam_workshop._wsc_http_post is replaced
by canned answers. Routes run on part12's app with its transport tripwire armed and every host call
stubbed; the script in node through part75's runner.
"""
import json as _json173
import os as _os173

from unit.part01 import _root, check, eq
from unit.part12 import (P9_ADMIN, P9_FILES, P9_HOST, P9_VIEWER, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_set)
from unit.part75 import _run_js75
from panel.ops.ssh_manager import _core as _smc173
from panel.routes import server_detail as _sd173, server_files as _sf173, workshop as _wk173
from panel.services import steam_workshop as _ws173

# ── 1. which games ──────────────────────────────────────────────────────────────────────────────
eq("workshop: the workshopmods games, gmod/csgo's one collection and Project Zomboid; no other game",
   [_wk173.workshop_kind(g) for g in ("arma3", "DAYZ", "squad", "squad44", "ohd", "bt", "hw", "col", "st",
                                      "l4d2", "sb", "sol", "gmod", "csgo", "pz", "cs2", "rust", "mc", "", None)],
   ["mods"] * 12 + ["collection", "collection", "pz", None, None, None, None, None])

# ── 2. what is checked ──────────────────────────────────────────────────────────────────────────
eq("workshop: an id is 1-20 digits, or a steamcommunity.com link's single id=; anything else is refused",
   [_ws173.normalize_id(v) for v in (
       "450814997", " 450814997 ", "1" * 20, "1" * 21, "", "12a", "-1", "١٢٣",
       "https://steamcommunity.com/sharedfiles/filedetails/?id=450814997",
       "https://steamcommunity.com/workshop/filedetails/?id=123&searchtext=x",
       "https://evil.example/?id=123", "https://steamcommunity.com.evil.example/?id=1",
       "https://steamcommunity.com/?id=1&id=2", "https://steamcommunity.com/?id=1;rm",
       "ftp://steamcommunity.com/?id=1",
       None, 450814997)],
   ["450814997", "450814997", "1" * 20, None, None, None, None, None, "450814997", "123",
    None, None, None, None, None, None, None])
eq("workshop: a list keeps its order, takes links, and refuses a duplicate, a bad id, a non-list and over 200",
   [_ws173.check_ids(v) for v in (
       ["3", "1", "https://steamcommunity.com/sharedfiles/filedetails/?id=2"], [], ["1", "1"], ["1", "x"],
       "1 2", [str(i) for i in range(201)], [1])],
   [(["3", "1", "2"], None), ([], None), (None, _ws173.DUPLICATE), (None, _ws173.BAD_ID), (None, _ws173.BAD_ID),
    (None, _ws173.TOO_MANY), (None, _ws173.BAD_ID)])
eq("workshop: workshopmods splits as LinuxGSM's does (blanks, commas, semicolons) and names what it skips",
   [_ws173.split_ids(v) for v in ("450814997 463939057,333;444", "  ", "12 @ace 7x", "", None)],
   [(["450814997", "463939057", "333", "444"], []), ([], []), (["12"], ["@ace", "7x"]), ([], []), ([], [])])
eq("workshop: a Mod ID cannot hold ; = or a line break, nor start or end with a blank; a leading \\ is kept",
   [_wk173.check_mod_ids(v) for v in (
       ["Hydrocraft", "tsarslib", "\\ModB42", "Mod With Space", "a.b-c_d"], ["a;b"], ["a=b"], ["a\nb"],
       [" a"], ["a "], [""], ["x" * 65], ["a", "a"], "a", [5], ["\\"], ["a\\b"])],
   [(["Hydrocraft", "tsarslib", "\\ModB42", "Mod With Space", "a.b-c_d"], None)]
   + [(None, _wk173.BAD_MOD_ID)] * 7 + [(None, _ws173.DUPLICATE)] + [(None, _wk173.BAD_MOD_ID)] * 4)
_ini173 = ("# Project Zomboid server settings\r\nPVP=true\r\n#WorkshopItems=999\r\nWorkshopItems=111;222\r\n"
           "PublicName=My ; Server = x\r\nMods=ModA;ModB\r\nMaxPlayers=32")
eq("workshop: the ini's lists read from the last uncommented key line, split on ; with blanks dropped",
   [_wk173.ini_list(_ini173, "WorkshopItems"), _wk173.ini_list(_ini173, "Mods"),
    _wk173.ini_list("Mods= a ; ;b\nMods=c", "Mods"), _wk173.ini_list("", "Mods"), _wk173.ini_list(None, "Mods"),
    _wk173.ini_list("ModsX=1\n Mods = q", "Mods")],
   [["111", "222"], ["ModA", "ModB"], ["c"], [], [], ["q"]])
eq("workshop: saving the ini changes only the two key lines; comments, other lines and CRLF stay byte-identical",
   _wk173.ini_set(_ini173, {"WorkshopItems": "333;111", "Mods": "\\ModC"}),
   "# Project Zomboid server settings\r\nPVP=true\r\n#WorkshopItems=999\r\nWorkshopItems=333;111\r\n"
   "PublicName=My ; Server = x\r\nMods=\\ModC\r\nMaxPlayers=32")
eq("workshop: a key the ini lacks is added at the end with the file's line ending; a last line without one is "
   "ended first",
   [_wk173.ini_set("A=1\nB=2\n", {"Mods": "x"}), _wk173.ini_set("A=1\r\nB=2", {"WorkshopItems": "1"}),
    _wk173.ini_set("", {"Mods": ""})],
   ["A=1\nB=2\nMods=x\n", "A=1\r\nB=2\r\nWorkshopItems=1\r\n", "Mods=\n"])
eq("workshop: a mod.info's id is its Mod ID when valid; its name is kept; a bad or missing id is no mod",
   [_wk173._wsc_mod_info(t) for t in (
       "name=Hydrocraft Mod\nid=Hydrocraft\nposter=p.png", "id=a;b", "name=x", "id=\\x", "", None)],
   [("Hydrocraft", "Hydrocraft Mod"), None, None, None, None, None])

# ── 3. Steam's titles, the network replaced ─────────────────────────────────────────────────────
_net173 = {"calls": [], "down": False}


def _post173(method, form):
    _net173["calls"].append((method, dict(form)))
    if _net173["down"]:
        return None, "URLError"
    ids = [form[k] for k in sorted(form, key=lambda k: (len(k), k)) if k.startswith("publishedfileids[")]
    if method == "GetPublishedFileDetails":
        rows = [{"publishedfileid": i, "result": 9} if i == "404" else
                {"publishedfileid": i, "result": 1, "title": ("<b>T%s</b>" % i) + ("x" * 300 if i == "7" else "")}
                for i in ids]
        return _json173.dumps({"response": {"result": 1, "publishedfiledetails": rows}}).encode(), None
    rows = [{"publishedfileid": i, "result": 1, "children": [{"publishedfileid": "1", "filetype": 0}] * 3}
            if i == "500" else {"publishedfileid": i, "result": 9} for i in ids]
    return _json173.dumps({"response": {"result": 1, "collectiondetails": rows}}).encode(), None


_s173 = {}
try:
    _p9_patch(_ws173, "_wsc_http_post", _post173)
    _p9_patch(_ws173, "_wsc_cache", {})
    _s173["first"] = _ws173.details(["500", "7", "404", "x", "500"])
    _s173["first_calls"] = list(_net173["calls"])
    _net173["calls"] = []
    _s173["cached"] = _ws173.details(["7", "500"])
    _s173["cached_calls"] = len(_net173["calls"])
    _many173 = [str(1000 + i) for i in range(150)]
    _s173["many"] = _ws173.details(_many173)
    _s173["many_calls"] = [(m, f.get("itemcount") or f.get("collectioncount"), len(f) - 1)
                           for m, f in _net173["calls"]]
    _net173["calls"], _net173["down"] = [], True
    _s173["down"] = _ws173.details(["8", "7"])
    _net173["down"] = False
finally:
    _p9_restore_all()

_f173 = _s173["first"][0]
check("workshop titles: Steam's title, whether it is a collection and how many items it holds; an id Steam does "
      "not know is 'not found'; a bad id is never asked",
      _s173["first"][1] is True and sorted(_f173) == ["404", "500", "7"]
      and _f173["500"] == {"title": "<b>T500</b>", "found": True, "collection": True, "items": 3}
      and _f173["404"]["found"] is False and _f173["404"]["title"] == ""
      and _f173["7"]["collection"] is False and len(_f173["7"]["title"]) == _ws173._WSC_TITLE_MAX, repr(_f173))
check("workshop titles: both methods are asked once, each with its count field and the ids in order",
      [(m, f) for m, f in _s173["first_calls"]] == [
          ("GetPublishedFileDetails", {"itemcount": "3", "publishedfileids[0]": "500", "publishedfileids[1]": "7",
                                       "publishedfileids[2]": "404"}),
          ("GetCollectionDetails", {"collectioncount": "3", "publishedfileids[0]": "500",
                                    "publishedfileids[1]": "7", "publishedfileids[2]": "404"})],
      repr(_s173["first_calls"]))
check("workshop titles: ids asked a moment ago come from the cache, not from Steam",
      _s173["cached_calls"] == 0 and sorted(_s173["cached"][0]) == ["500", "7"], repr(_s173["cached_calls"]))
check("workshop titles: at most 100 ids go in one request (150 ids are two of each method)",
      _s173["many_calls"] == [("GetPublishedFileDetails", "100", 100), ("GetCollectionDetails", "100", 100),
                              ("GetPublishedFileDetails", "50", 50), ("GetCollectionDetails", "50", 50)]
      and len(_s173["many"][0]) == 150, repr(_s173["many_calls"]))
check("workshop titles: when Steam does not answer, the uncached ids are left out and the answer says so",
      _s173["down"][1] is False and list(_s173["down"][0]) == ["7"], repr(_s173["down"]))
check("workshop titles: only the two ISteamRemoteStorage methods are ever posted to",
      _ws173._wsc_http_post("GetUserFiles", {}) == (None, "not an allowed method")
      and _ws173._wsc_http_post("../../evil", {}) == (None, "not an allowed method")
      and _ws173._WSC_BASE == "https://api.steampowered.com/ISteamRemoteStorage/")
check("workshop titles: a redirect is refused (the URL asked for is the only host)",
      _ws173._WscNoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example/") is None)

# ── 4. the routes ───────────────────────────────────────────────────────────────────────────────
_arma173 = _p9_new_server(P9_HOST, "arma3server", "arma3", 2302, name="p173-arma", status="online")
_gmod173 = _p9_new_server(P9_HOST, "gmodserver", "gmod", 27015, name="p173-gmod", status="online")
_pz173 = _p9_new_server(P9_HOST, "pzserver", "pz", 16261, name="p173-pz", status="online")
_mc173 = _p9_new_server(P9_HOST, "p173mc", "mc", 25565, name="p173-mc", status="online")
_cfg173 = {"workshopmods": "450814997 @bad,463939057", "wscollectionid": "500"}
_cfg_reads173, _cfg_writes173, _file_writes173 = [], [], []
_files173 = {"Zomboid/Server/pzserver.ini": (_ini173, None)}
_listing173 = {}
_cfg_answer173 = {"v": (True, "")}
_write_refusal173 = {"on": False}
_refused173 = []


def _get_values173(server, user, selfname, keys):
    _cfg_reads173.append((user, selfname, list(keys)))
    return None if _cfg173.get("_fail") else {k: _cfg173.get(k, "") for k in keys}


def _write_config173(server, user, selfname, updates):
    _cfg_writes173.append((user, selfname, dict(updates)))
    return _cfg_answer173["v"]


def _read173(server, user, relpath, max_bytes=1048576):
    return _files173.get(relpath, (None, "File not found"))


def _write_file173(server, user, relpath, content, selfname=None):
    _file_writes173.append((user, relpath, content, selfname))
    return True, ""


def _browse173(server, user, relpath="", selfname=None):
    return _listing173.get(relpath, {"path": relpath, "entries": [], "unreadable": True})


def _wrefuse173(gs, action, detail=""):
    if not _write_refusal173["on"]:
        return None
    _refused173.append((action, detail))
    from flask import jsonify
    return jsonify({"success": False, "message": "refused"}), 409


def _j173(r):
    return r.get_json(silent=True) or {}


_r173 = {}
_u173 = "/api/server/%d/workshop"
try:
    _p9_arm(who="part173")
    _p9_patch(_ws173, "_wsc_http_post", _post173)
    _p9_patch(_ws173, "_wsc_cache", {})
    _p9_patch_sm("lgsm_get_values", _get_values173)
    _p9_patch_sm("lgsm_write_config", _write_config173)
    _p9_patch_sm("read_file", _read173)
    _p9_patch_sm("write_file", _write_file173)
    _p9_patch_sm("browse_dir", _browse173)
    _p9_patch(_sf173, "_write_refused", _wrefuse173)
    _p9_patch(_sf173, "_read_refused", lambda *a, **k: None)
    _A173, _F173, _V173 = _p9_client(P9_ADMIN), _p9_client(P9_FILES), _p9_client(P9_VIEWER)

    _r173["mods"] = _A173.get(_u173 % _arma173)
    _r173["mods_files"] = _F173.get(_u173 % _arma173)
    _r173["mods_viewer"] = _V173.get(_u173 % _arma173)
    _r173["mc"] = _A173.get(_u173 % _mc173)
    _cfg173["_fail"] = True
    _r173["mods_unread"] = _A173.get(_u173 % _arma173)
    _r173["save_unread"] = _A173.post(_u173 % _arma173, json={"ids": ["1"]})
    _r173["save_unread_writes"] = len(_cfg_writes173)
    del _cfg173["_fail"]

    _r173["save"] = _A173.post(_u173 % _arma173, json={"ids": [
        "463939057", "https://steamcommunity.com/sharedfiles/filedetails/?id=500", "450814997"]})
    _r173["save_audit"] = _p9_audit("workshop_save")
    _r173["save_writes"] = list(_cfg_writes173)
    _n173 = (len(_cfg_writes173), _p9_audit_count("workshop_save"))
    _r173["save_bad"] = [_A173.post(_u173 % _arma173, json=b).status_code for b in (
        {"ids": ["1", "1"]}, {"ids": ["1; rm -rf ~"]}, {"ids": "1 2"}, {"ids": [str(i) for i in range(201)]},
        {"ids": ["https://evil.example/?id=1"]}, {})]
    _r173["save_bad_writes"] = len(_cfg_writes173) - _n173[0]
    _r173["save_bad_audits"] = _p9_audit_count("workshop_save") - _n173[1]
    _r173["save_bad_audit"] = _p9_audit("workshop_save")
    _r173["save_files"] = _F173.post(_u173 % _arma173, json={"ids": []})
    _r173["save_viewer"] = _V173.post(_u173 % _arma173, json={"ids": []})
    _r173["save_mc"] = _A173.post(_u173 % _mc173, json={"ids": []})
    _cfg_answer173["v"] = (False, "bash: host text\nsecret")
    _r173["save_failed"] = _A173.post(_u173 % _arma173, json={"ids": ["1"]})
    _r173["save_failed_audit"] = _p9_audit("workshop_save")
    _cfg_answer173["v"] = (True, "")
    _write_refusal173["on"] = True
    _n173 = len(_cfg_writes173), len(_file_writes173)
    _r173["save_refused"] = _A173.post(_u173 % _arma173, json={"ids": ["1"]})
    _r173["pz_refused"] = _A173.post(_u173 % _pz173, json={"items": [], "mods": []})
    _r173["refused_writes"] = (len(_cfg_writes173) - _n173[0], len(_file_writes173) - _n173[1])
    _write_refusal173["on"] = False

    _cfg_reads173.clear()
    _cfg_writes173.clear()
    _r173["coll"] = _A173.get(_u173 % _gmod173)
    _r173["coll_save"] = _A173.post(_u173 % _gmod173, json={
        "id": "https://steamcommunity.com/sharedfiles/filedetails/?id=123456"})
    _r173["coll_clear"] = _A173.post(_u173 % _gmod173, json={"id": ""})
    _r173["coll_bad"] = [_A173.post(_u173 % _gmod173, json=b).status_code for b in (
        {"id": "1 2"}, {"id": ["1", "2"]}, {"id": "x"})]
    _r173["coll_reads"] = list(_cfg_reads173)
    _r173["coll_writes"] = list(_cfg_writes173)
    _r173["coll_audit"] = _p9_audit("workshop_save")

    _r173["pz"] = _A173.get(_u173 % _pz173)
    _r173["pz_save"] = _A173.post(_u173 % _pz173, json={"items": ["222", "333"], "mods": ["ModB", "\\ModC"]})
    _r173["pz_audit"] = _p9_audit("workshop_save")
    _r173["pz_writes"] = list(_file_writes173)
    _n173 = len(_file_writes173)
    _r173["pz_bad"] = [_A173.post(_u173 % _pz173, json=b).status_code for b in (
        {"items": ["1"], "mods": ["a;b"]}, {"items": ["1"], "mods": ["a\nWorkshopItems=9"]},
        {"items": ["x"], "mods": []}, {"items": ["1"]}, {"mods": []})]
    _saved_ini173 = _files173.pop("Zomboid/Server/pzserver.ini")
    _r173["pz_missing"] = _A173.get(_u173 % _pz173)
    _r173["pz_missing_save"] = _A173.post(_u173 % _pz173, json={"items": ["1"], "mods": []})
    _files173["Zomboid/Server/pzserver.ini"] = _saved_ini173
    _r173["pz_bad_writes"] = len(_file_writes173) - _n173
    _r173["pz_on_arma"] = _A173.get(_u173 % _arma173 + "/pz-mods?items=1")

    _base173 = "serverfiles/steamapps/workshop/content/108600"
    _listing173.update({
        _base173 + "/111/mods": {"entries": [{"name": "ModA", "is_dir": True}, {"name": "ModB42", "is_dir": True},
                                             {"name": "readme.txt", "is_dir": False},
                                             {"name": "../x", "is_dir": True}]},
        _base173 + "/222/mods": {"entries": [{"name": "ModA", "is_dir": True}]}})
    _files173.update({_base173 + "/111/mods/ModA/mod.info": ("name=Mod A\nid=ModA\n", None),
                      _base173 + "/111/mods/ModB42/42/mod.info": ("id=ModB42\nname=B", None),
                      _base173 + "/222/mods/ModA/mod.info": ("id=ModA", None)})
    _r173["found"] = _A173.get(_u173 % _pz173 + "/pz-mods?items=111,222,999")
    _reads173 = []
    _p9_patch_sm("read_file", lambda s, u, rel, max_bytes=0: (_reads173.append((rel, max_bytes)), (None, "x"))[1])
    _p9_patch_sm("browse_dir", lambda s, u, rel="", selfname=None: {"entries": [
        {"name": "M%d" % i, "is_dir": True} for i in range(50)]})
    _r173["found_bounded"] = _A173.get(_u173 % _pz173 + "/pz-mods?items=" + ",".join(str(i) for i in range(1, 60)))
    _r173["found_reads"] = list(_reads173)
    _r173["found_bad"] = _A173.get(_u173 % _pz173 + "/pz-mods?items=1,../2")
    _r173["found_viewer"] = _V173.get(_u173 % _pz173 + "/pz-mods?items=1")

    _net173["calls"] = []
    _r173["titles"] = _A173.get(_u173 % _arma173 + "/titles?ids=500,abc,7,1;2")
    _r173["titles_calls"] = list(_net173["calls"])
    _net173["down"] = True
    _r173["titles_down"] = _A173.get(_u173 % _arma173 + "/titles?ids=31337")
    _net173["down"] = False
    _r173["titles_viewer"] = _V173.get(_u173 % _arma173 + "/titles?ids=1")
finally:
    _p9_restore_all()
    _p9_delete_server(_mc173)

_jm173 = _j173(_r173["mods"])
check("workshop read: workshopmods' ids in order, and the entry LinuxGSM skips named, for the Settings tab's "
      "permission",
      _jm173.get("success") is True and _jm173.get("kind") == "mods"
      and _jm173.get("ids") == ["450814997", "463939057"] and _jm173.get("ignored") == ["@bad"]
      and _r173["mods_files"].status_code == 200, repr(_jm173))
check("workshop read: a console viewer is refused, a game with no Workshop list is a 400, an unread config is "
      "said, never an empty list",
      _r173["mods_viewer"].status_code == 403 and _r173["mc"].status_code == 400
      and _j173(_r173["mods_unread"]).get("success") is False and "ids" not in _j173(_r173["mods_unread"]),
      repr([_r173[k].status_code for k in ("mods_viewer", "mc", "mods_unread")]))
check("workshop save: workshopmods is written through the Settings tab's writer as the game account, in the "
      "order given, links reduced to their id",
      _j173(_r173["save"]).get("success") is True
      and _r173["save_writes"] == [("arma3server", "arma3server", {"workshopmods": "463939057 500 450814997"})],
      repr(_r173["save_writes"]))
check("workshop save: the audit row names the ids before and after, against the server",
      _r173["save_audit"].success is True and _r173["save_audit"].target == "p173-arma"
      and _r173["save_audit"].detail == "workshopmods: 450814997 463939057 -> 463939057 500 450814997",
      repr(_r173["save_audit"]))
check("workshop save: a duplicate, a bad id, a non-list, over 200, a foreign link or no list is a 400 that writes "
      "nothing and is audited as refused",
      _r173["save_bad"] == [400] * 6 and _r173["save_bad_writes"] == 0 and _r173["save_bad_audits"] == 6
      and _r173["save_bad_audit"].success is False and "(refused:" in _r173["save_bad_audit"].detail,
      repr((_r173["save_bad"], _r173["save_bad_writes"], _r173["save_bad_audit"])))
check("workshop save: a config that could not be read first is refused, nothing written",
      _r173["save_unread"].status_code == 409 and _r173["save_unread_writes"] == 0,
      repr(_r173["save_unread"].status_code))
check("workshop save: the Settings tab's permission saves; a console viewer and a game with no list are refused",
      _j173(_r173["save_files"]).get("success") is True and _r173["save_viewer"].status_code == 403
      and _r173["save_mc"].status_code == 400,
      repr([_r173[k].status_code for k in ("save_files", "save_viewer", "save_mc")]))
check("workshop save: a failed write shows no host text and is audited as failed",
      _j173(_r173["save_failed"]).get("success") is False
      and "host text" not in _j173(_r173["save_failed"]).get("message", "host text")
      and _r173["save_failed_audit"].success is False and "host text" not in _r173["save_failed_audit"].detail,
      repr((_j173(_r173["save_failed"]), _r173["save_failed_audit"])))
check("workshop save: the file browser's root-account refusal comes before any write, for the cfg and the ini",
      _r173["save_refused"].status_code == 409 and _r173["pz_refused"].status_code == 409
      and _r173["refused_writes"] == (0, 0)
      and _refused173 == [("workshop_save", ""), ("workshop_save", "Zomboid/Server/pzserver.ini")],
      repr((_r173["refused_writes"], _refused173)))
check("workshop collection: wscollectionid is read and written alone (never wsapikey), a link reduced to its id, "
      "an empty field clearing it",
      _j173(_r173["coll"]).get("ids") == ["500"] and _j173(_r173["coll"]).get("kind") == "collection"
      and _r173["coll_writes"] == [("gmodserver", "gmodserver", {"wscollectionid": "123456"}),
                                   ("gmodserver", "gmodserver", {"wscollectionid": ""})]
      and all(keys == ["wscollectionid"] for _u, _s, keys in _r173["coll_reads"]) and _r173["coll_reads"],
      repr((_r173["coll_reads"], _r173["coll_writes"])))
check("workshop collection: two ids, a list or a non-id are each a 400",
      _r173["coll_bad"] == [400] * 3 and _r173["coll_audit"].success is False, repr(_r173["coll_bad"]))
_jp173 = _j173(_r173["pz"])
check("workshop pz: WorkshopItems and Mods are read from Zomboid/Server/pzserver.ini",
      _jp173.get("kind") == "pz" and _jp173.get("items") == ["111", "222"] and _jp173.get("mods") == ["ModA", "ModB"]
      and _jp173.get("missing") is False, repr(_jp173))
check("workshop pz: the save rewrites only the two lines through the file editor's writer as the game account",
      _r173["pz_writes"] == [("pzserver", "Zomboid/Server/pzserver.ini",
                              _ini173.replace("WorkshopItems=111;222", "WorkshopItems=222;333")
                              .replace("Mods=ModA;ModB", "Mods=ModB;\\ModC"), "pzserver")],
      repr(_r173["pz_writes"]))
check("workshop pz: the audit row names both lists before and after",
      _r173["pz_audit"].detail == "WorkshopItems: 111 222 -> 222 333; Mods: ModA ModB -> ModB \\ModC"
      and _r173["pz_audit"].success is True, repr(_r173["pz_audit"]))
check("workshop pz: a Mod ID with ; or a line break, a bad id or a missing list is a 400; an ini not written yet "
      "is said on read and refused on save; nothing is written",
      _r173["pz_bad"] == [400] * 5 and _j173(_r173["pz_missing"]).get("missing") is True
      and _r173["pz_missing_save"].status_code == 409
      and "first time the server starts" in _j173(_r173["pz_missing_save"]).get("message", "")
      and _r173["pz_bad_writes"] == 0, repr((_r173["pz_bad"], _j173(_r173["pz_missing_save"]))))
check("workshop pz mods: the Mod IDs in downloaded items, Build 41 and 42 layouts, each once; an odd folder "
      "name is not read",
      _j173(_r173["found"]).get("mods") == [{"id": "ModA", "name": "Mod A", "item": "111"},
                                            {"id": "ModB42", "name": "B", "item": "111"}],
      repr(_j173(_r173["found"])))
check("workshop pz mods: the search is bounded (60 small reads at most, however many items and folders)",
      len(_r173["found_reads"]) == _wk173._WSC_PZ_READS == 60
      and all(m == _wk173._WSC_MODINFO_MAX for _r, m in _r173["found_reads"])
      and _j173(_r173["found_bounded"]).get("mods") == [], repr(len(_r173["found_reads"])))
check("workshop pz mods: a bad item id is a 400; a viewer is refused; a non-pz server is refused",
      _r173["found_bad"].status_code == 400 and _r173["found_viewer"].status_code == 403
      and _r173["pz_on_arma"].status_code == 400,
      repr([_r173[k].status_code for k in ("found_bad", "found_viewer", "pz_on_arma")]))
check("workshop titles route: only valid ids go to Steam; Steam not answering says incomplete, not an error",
      sorted(_j173(_r173["titles"]).get("titles", {})) == ["500", "7"]
      and all(sorted(v for k, v in f.items() if k.startswith("publishedfileids")) == ["500", "7"]
              for _m, f in _r173["titles_calls"])
      and _j173(_r173["titles_down"]).get("complete") is False
      and _j173(_r173["titles_down"]).get("titles") == {} and _r173["titles_viewer"].status_code == 403,
      repr((_r173["titles_calls"], _j173(_r173["titles_down"]))))

# ── 5. the server page ──────────────────────────────────────────────────────────────────────────
_pages173 = {}
_cmds173 = _json173.dumps([{"cmd": "workshop-update", "desc": "Update Workshop mods"},
                           {"cmd": "start", "desc": "Start"}])
try:
    _p9_arm(who="part173")
    for _sid173 in (_arma173, _pz173):
        _p9_set(_sid173, commands=_cmds173)
    _p9_patch(_sd173, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd173, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc173, "run_command", lambda *a, **k: ("", "", 1))
    for _k173, _uid173, _sid173 in (("admin", P9_ADMIN, _arma173), ("files", P9_FILES, _arma173),
                                    ("viewer", P9_VIEWER, _arma173), ("pz", P9_ADMIN, _pz173),
                                    ("gmod", P9_ADMIN, _gmod173)):
        _rp173 = _p9_client(_uid173).get("/server/%d" % _sid173)
        _pages173[_k173] = (_rp173.status_code, _rp173.get_data(as_text=True))
finally:
    _p9_restore_all()
    for _sid173 in (_arma173, _gmod173, _pz173):
        _p9_delete_server(_sid173)
_pa173, _pf173, _pv173, _pp173, _pg173 = (_pages173.get(k, (0, ""))[1] for k in ("admin", "files", "viewer", "pz",
                                                                                 "gmod"))
_dl173 = 'data-args=\'["workshop-update","@self",true,true]\''
check("server page: a workshopmods game shows the card, its script, and Download now (the existing "
      "workshop-update action) to whom may run it",
      _pages173.get("admin", (0,))[0] == 200 and 'id="wsc-card"' in _pa173 and 'data-kind="mods"' in _pa173
      and "js/server_workshop.js" in _pa173 and _dl173 in _pa173 and '"workshop"' in _pa173, _pa173[:200])
check("server page: the Settings tab's permission without UPDATE_SERVER gets the card but no Download now",
      'id="wsc-card"' in _pf173 and _dl173 not in _pf173, repr(_pages173.get("files", (0,))[0]))
check("server page: a console viewer gets no card and no script",
      'id="wsc-card"' not in _pv173 and "server_workshop.js" not in _pv173, repr(_pages173.get("viewer", (0,))[0]))
check("server page: Project Zomboid gets both lists and the found-Mod-ID box, no Download now; gmod the one "
      "collection field",
      'data-kind="pz"' in _pp173 and 'id="wsc-mods"' in _pp173 and 'id="wsc-found"' in _pp173
      and _dl173 not in _pp173 and 'data-kind="collection"' in _pg173 and 'id="wsc-coll"' in _pg173
      and 'id="wsc-items"' not in _pg173, repr([_pages173.get(k, (0,))[0] for k in ("pz", "gmod")]))

# ── 6. the card's script, in node ───────────────────────────────────────────────────────────────
with open(_os173.path.join(_root, "panel", "static", "js", "server_workshop.js"), encoding="utf-8") as _fh173:
    _js173 = _fh173.read()


def _node173(name, view, steps):
    """Run the card's script against a stand-in page whose GET answers `view`; `steps` drive it."""
    return _run_js75(name, (
        "const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)); };\n"
        "global.window = global; global.MOUNT = ''; global.serverId = 9; global.t = s => s;\n"
        "global.tf = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => v[k]);\n"
        "function node(tag) { const n = {tag, children: [], attrs: {}, hidden: false, disabled: false, value: '',\n"
        "  className: '', style: {}, title: '', _t: '',\n"
        "  appendChild(c) { this.children.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = String(v); },\n"
        "  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }};\n"
        "  Object.defineProperty(n, 'textContent', {get() { return this._t + this.children.map(c => c.textContent)\n"
        "    .join(''); }, set(v) { this._t = String(v); this.children = []; }});\n"
        "  Object.defineProperty(n, 'innerHTML', {set() { throw new Error('innerHTML used'); }}); return n; }\n"
        "const els = {}; const mk = id => (els[id] = els[id] || node('div'));\n"
        "global.document = {getElementById: mk, readyState: 'complete', addEventListener: () => 0,\n"
        "  createElement: node};\n"
        "const posts = [], gets = [];\n"
        "const view = " + _json173.dumps(view) + ";\n"
        "const titles = {success: true, complete: true, titles: {'500': {title: '<img src=x onerror=alert(1)>',\n"
        "  found: true, collection: true, items: 4}, '7': {title: 'Seven', found: true, collection: false,\n"
        "  items: 0}}};\n"
        "const found = {success: true, mods: [{id: 'ModA', name: 'A', item: '111'}, {id: 'ModZ', name: 'Z'}]};\n"
        "global.fetch = (u, o) => {\n"
        "  if (o && o.method === 'POST') posts.push(JSON.parse(o.body)); else gets.push(u);\n"
        "  const d = o ? {success: true, message: 'Saved.'} : (u.indexOf('/titles') >= 0 ? titles :\n"
        "    (u.indexOf('/pz-mods') >= 0 ? found : view));\n"
        "  return Promise.resolve({json: () => Promise.resolve(d)}); };\n"
        "const ev = {preventDefault() {}};\n"
        + _js173 + "\n"
        "(async () => { await settle(); const out = {};\n"
        "  const rows = id => els[id].children.map(li => li.children[0].children.map(c => c.textContent));\n"
        + steps + "\n"
        "  out.posts = posts; out.gets = gets; console.log(JSON.stringify(out)); })();\n"))


_mods_steps173 = (
    "  out.first = rows('wsc-items');\n"
    "  mk('wsc-items-add').value = 'https://steamcommunity.com/sharedfiles/filedetails/?id=42&x=1';\n"
    "  window.wscAdd('items', ev); await settle();\n"
    "  mk('wsc-items-add').value = 'https://evil.example/?id=43'; window.wscAdd('items', ev);\n"
    "  out.badMsg = els['wsc-msg'].textContent;\n"
    "  mk('wsc-items-add').value = '7'; window.wscAdd('items', ev); out.dupMsg = els['wsc-msg'].textContent;\n"
    "  window.wscMove('items', 2, -1); window.wscMove('items', 0, -1); window.wscMove('items', 2, 1);\n"
    "  window.wscMove('items', 0, 5); out.moved = rows('wsc-items').map(r => r[0]);\n"
    "  window.wscRemove('items', 0); window.wscRemove('items', 9);\n"
    "  out.after = rows('wsc-items');\n"
    "  window.wscSave(); await settle();\n")
_mods_js173 = _node173("workshop card: draws Steam's titles as text, reduces links to ids, posts the list in order",
                       {"success": True, "kind": "mods", "ids": ["500", "7"], "ignored": []}, _mods_steps173)
if _mods_js173 is not None:
    check("workshop card: a Steam title is drawn as text with its collection size; rows are numbered in load order",
          _mods_js173.get("first") == [["1. <img src=x onerror=alert(1)>", "Collection of 4 items · 500"],
                                       ["2. Seven", "7"]], repr(_mods_js173))
    check("workshop card: a steamcommunity.com link adds its id; a foreign link or a duplicate adds nothing and "
          "says why",
          "1 to 20 digits" in _mods_js173.get("badMsg", "")
          and _mods_js173.get("dupMsg") == "That is in the list already."
          and any("/titles?ids=42" in g for g in _mods_js173.get("gets", [])), repr(_mods_js173))
    check("workshop card: move and remove reorder the list (out-of-range moves do nothing) and Save posts the ids "
          "in that order",
          _mods_js173.get("moved") == ["1. <img src=x onerror=alert(1)>", "2. 42", "3. Seven"]
          and _mods_js173.get("posts") == [{"ids": ["42", "7"]}]
          and [r[0] for r in _mods_js173.get("after", [])] == ["1. 42", "2. Seven"], repr(_mods_js173))

_pz_steps173 = (
    "  out.found = els['wsc-found'].children.map(b => [b.textContent, b.attrs['data-args']]);\n"
    "  out.gotFound = gets.filter(g => g.indexOf('/pz-mods?items=111') >= 0).length;\n"
    "  mk('wsc-mods-add').value = 'a;b'; window.wscAdd('mods', ev); out.badMod = els['wsc-msg'].textContent;\n"
    "  window.wscAddFound('ModZ;x'); window.wscAddFound('\\\\ModA'); await settle();\n"
    "  out.foundAfter = els['wsc-found'].children.map(b => b.textContent);\n"
    "  window.wscSave(); await settle();\n")
_pz_js173 = _node173("workshop card: Project Zomboid's Mod IDs, the found ones offered, both lists posted",
                     {"success": True, "kind": "pz", "items": ["111"], "mods": ["\\ModB"], "missing": False},
                     _pz_steps173)
if _pz_js173 is not None:
    check("workshop card (pz): Mod IDs found in downloaded items are offered as one-tap adds, in the list's own "
          "backslash style",
          _pz_js173.get("gotFound") == 1
          and _pz_js173.get("found") == [["+ ModA", '["\\\\ModA"]'], ["+ ModZ", '["\\\\ModZ"]']], repr(_pz_js173))
    check("workshop card (pz): a Mod ID with ; is refused with the rule; a tapped one leaves the offers and both "
          "lists are posted",
          "no ; or =" in _pz_js173.get("badMod", "") and _pz_js173.get("foundAfter") == ["+ ModZ"]
          and _pz_js173.get("posts") == [{"items": ["111"], "mods": ["\\ModB", "\\ModA"]}], repr(_pz_js173))

_coll_steps173 = (
    "  out.info = els['wsc-coll-info'].textContent; out.value = els['wsc-coll'].value;\n"
    "  els['wsc-coll'].value = 'https://steamcommunity.com/sharedfiles/filedetails/?id=7';\n"
    "  window.wscSaveCollection(ev); await settle(); out.info2 = els['wsc-coll-info'].textContent;\n"
    "  els['wsc-coll'].value = 'not an id'; window.wscSaveCollection(ev); await settle();\n"
    "  els['wsc-coll'].value = ''; window.wscSaveCollection(ev); await settle();\n")
_coll_js173 = _node173("workshop card: one collection field, a link reduced to its id, cleared with an empty field",
                       {"success": True, "kind": "collection", "ids": ["500"], "ignored": []}, _coll_steps173)
if _coll_js173 is not None:
    check("workshop card (collection): the collection's title and item count; a link saves its id, junk posts "
          "nothing, an empty field clears it",
          _coll_js173.get("value") == "500"
          and _coll_js173.get("info") == "<img src=x onerror=alert(1)> · Collection of 4 items"
          and _coll_js173.get("info2") == "Seven · This is a single item, not a collection."
          and _coll_js173.get("posts") == [{"id": "7"}, {"id": ""}], repr(_coll_js173))
