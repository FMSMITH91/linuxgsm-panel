"""Part 171 of the unit suite: a PaperMC server's plugins from Modrinth (panel/routes/modrinth_plugins.py).

Held here:
* Which games have the card: pmcserver (PaperMC) only.
* What reaches Modrinth and the server is checked first: project ids by Modrinth's eight-character
  base62 format, a capped printable search, a file URL that is https on Modrinth's CDN, a 128-hex
  sha512, a size within the cap, and a file name reduced to [A-Za-z0-9._+-] ending .jar.
* A download whose sha512 is not the API's is dropped before anything is written.
* The routes: the file manager's permission on each, the file browser's root-account refusal before
  any write, the install through upload_file as the game account without overwrite, enable/disable
  as a rename and remove as a delete, each audited against the server with the plugin's name.
* The page: the card and its script for a PaperMC server and the file manager's permission only; the
  card's script, run in node, drawing Modrinth's text as text and posting only checked values.

HOW IT RUNS. The network is never touched: panel/services/modrinth._mdr_http_get is replaced by a
table of canned answers, and the one check of the real function replaces urllib's opener. Routes run
on part12's app with its transport tripwire armed and every host call stubbed; the script in node
through part75's runner.
"""
import hashlib as _hl171
import json as _json171
import os as _os171
import urllib.parse as _up171

from unit.part01 import _root, check, eq
from unit.part12 import (P9_ADMIN, P9_FILES, P9_HOST, P9_VIEWER, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part75 import _run_js75
from panel.ops.ssh_manager import _core as _smc171, files as _smf171
from panel.routes import modrinth_plugins as _mp171, server_detail as _sd171, server_files as _sf171
from panel.services import modrinth as _mr171

# ── 1. which games ──────────────────────────────────────────────────────────────────────────────
eq("plugins: only a PaperMC server (pmcserver) has the card; vanilla, Bedrock and the proxies do not",
   [_mp171.plugins_supported(g) for g in ("pmc", "PMC", "mc", "mcb", "vpmc", "wmc", "css", "", None)],
   [True, True, False, False, False, False, False, False, False])

# ── 2. what is checked ──────────────────────────────────────────────────────────────────────────
eq("plugins: a Modrinth id is eight base62 characters; a slug, a path, a short or long id is not",
   [_mr171.valid_id(v) for v in ("AABBCC12", "P7dR8mSH", "luckperms", "AABBCC1", "AABBCC123", "../AABBC",
                                 "AABB-C12", "AABBCC1\n", 12345678, None, "AABBCC١٢")],
   [True, True, False, False, False, False, False, False, False, False, False])
eq("plugins: a search is printable, at most 80 characters; an empty search is allowed (most downloaded)",
   [_mr171.query_problem(q) for q in ("luckperms", "", "x" * 80, "x" * 81, "a\nb", "a\x00", "a\u202e", 5)],
   [None, None, None] + [_mr171.BAD_QUERY] * 5)
eq("plugins: a Minecraft version reads as N.N or N.N.N only",
   [_mr171.valid_mc_version(v) for v in ("1.21", "1.21.4", "1.21.4-pre1", "1", "1.21 ", "x", None)],
   [True, True, False, False, False, False, False])
eq("plugins: the Minecraft version comes from Paper's version_history.json currentVersion, else None",
   [_mr171.paper_mc_version(t) for t in (
       '{"currentVersion": "1.21.4-212-abc1234 (MC: 1.21.4)"}', '{"currentVersion": "git-Paper-196 (MC: 1.20)"}',
       '{"currentVersion": "1.21.4-212"}', '{"currentVersion": 5}', "[]", "not json", "", None)],
   ["1.21.4", "1.20", None, None, None, None, None, None])
eq("plugins: a file name is the basename, reduced to [A-Za-z0-9._+-], and must end .jar",
   [_mr171.safe_filename(n) for n in (
       "LuckPerms-Bukkit-5.4.jar", "../../.bashrc.jar", "a/b\\Essentials X.JAR", "evil.jar\n.sh", "x.zip",
       ".jar", "...jar", "plugin.jar.disabled", "Ünïcode+1.jar", None)],
   ["LuckPerms-Bukkit-5.4.jar", "bashrc.jar", "Essentials_X.jar", None, None, None, None, None,
    "_n_code+1.jar", None])
eq("plugins: enable needs a .jar.disabled, disable a .jar; remove takes either; anything else is refused",
   [_mp171.change_target(a, n) for a, n in (
       ("disable", "Foo-1.0.jar"), ("enable", "Foo-1.0.jar.disabled"), ("remove", "Foo-1.0.jar"),
       ("remove", "Foo.jar.disabled"), ("enable", "Foo.jar"), ("disable", "Foo.jar.disabled"),
       ("remove", "../server.properties.jar"), ("remove", "sub/Foo.jar"), ("remove", "Foo.txt"),
       ("remove", ".hidden.jar"), ("remove", "Foo bar.jar"), ("delete", "Foo.jar"), ("remove", ""))],
   [("Foo-1.0.jar.disabled", None), ("Foo-1.0.jar", None), (None, None), (None, None),
    (None, _mp171._MDR_BAD_ACTION), (None, _mp171._MDR_BAD_ACTION)] + [(None, _mp171._MDR_BAD_FILE)] * 5
   + [(None, _mp171._MDR_BAD_ACTION), (None, _mp171._MDR_BAD_FILE)])
eq("plugins: only https on the allowlisted host, default port, no credentials, is fetched",
   [_mr171._mdr_allowed(u, _mr171._MDR_CDN_HOSTS) for u in (
       "https://cdn.modrinth.com/data/AABBCC12/versions/x/a.jar", "http://cdn.modrinth.com/a.jar",
       "https://cdn.modrinth.com.evil.example/a.jar", "https://evil.example/a.jar",
       "https://cdn.modrinth.com:8443/a.jar", "https://u:p@cdn.modrinth.com/a.jar", "https://api.modrinth.com/a")],
   [True, False, False, False, False, False, False])

# ── 3. the Modrinth client, its network replaced ────────────────────────────────────────────────
_BODY171 = b"PK\x03\x04 a plugin jar"
_SHA171 = _hl171.sha512(_BODY171).hexdigest()
_CDN171 = "https://cdn.modrinth.com/data/AABBCC12/versions/VVVVVV01/Good-Plugin-1.2.jar"


def _ver171(vid, vtype="release", url=_CDN171, sha=_SHA171, name="Good Plugin-1.2.jar", size=None, pid="AABBCC12"):
    return {"id": vid, "project_id": pid, "version_number": "1.2", "version_type": vtype,
            "files": [{"url": "https://cdn.modrinth.com/x/sources.jar", "filename": "src.jar", "primary": False,
                       "hashes": {"sha512": "0" * 128}, "size": 3},
                      {"url": url, "filename": name, "primary": True, "hashes": {"sha512": sha},
                       "size": len(_BODY171) if size is None else size}]}


_net171 = {"calls": [], "answers": {}}


def _net_get171(url, cap, hosts, timeout=15):
    _net171["calls"].append((url, cap, tuple(sorted(hosts))))
    for prefix, answer in _net171["answers"].items():
        if url.startswith(prefix):
            return answer
    return None, "no canned answer"


def _api171(versions, project=None):
    return {"https://api.modrinth.com/v2/project/AABBCC12/version":
            (_json171.dumps(versions).encode(), None),
            "https://api.modrinth.com/v2/project/AABBCC12": (
                _json171.dumps(project or {"title": "Good Plugin"}).encode(), None),
            "https://cdn.modrinth.com/": (_BODY171, None)}


_svc171 = {}
try:
    _p9_patch(_mr171, "_mdr_http_get", _net_get171)
    _net171["answers"] = {"https://api.modrinth.com/v2/search": (_json171.dumps({"hits": [
        {"project_id": "AABBCC12", "title": "Good", "description": "d" * 400, "downloads": 12, "author": "a"},
        {"project_id": "../x", "title": "bad id"}, "not an object",
        {"project_id": "DDEEFF34", "title": ["x"], "downloads": True}]}).encode(), None)}
    _svc171["search"] = _mr171.search("perms", "1.21.4")
    _svc171["search_url"] = _net171["calls"][-1][0]
    _svc171["search_nov"] = _mr171.search("", None)
    _svc171["search_nov_url"] = _net171["calls"][-1][0]
    _n_before171 = len(_net171["calls"])
    _svc171["search_bad"] = _mr171.search("a\nb")
    _svc171["search_bad_calls"] = len(_net171["calls"]) - _n_before171
    _net171["answers"] = {}
    _svc171["search_down"] = _mr171.search("x")
    _net171["answers"] = _api171([_ver171("BETA0001", "beta"), _ver171("VVVVVV01"), _ver171("OLDREL01")])
    _svc171["resolve"] = _mr171.resolve("AABBCC12", "1.21.4")
    _svc171["resolve_urls"] = [c[0] for c in _net171["calls"][-2:]]
    _svc171["download"] = _mr171.download(_svc171["resolve"][0]["plan"])
    _svc171["download_call"] = _net171["calls"][-1]
    _net171["answers"] = _api171([_ver171("BETA0001", "beta")])
    _svc171["only_beta"] = _mr171.resolve("AABBCC12")
    _svc171["only_beta_url"] = _net171["calls"][-1][0]
    _svc171["off_cdn"] = []
    for _bad171 in ({"url": "https://evil.example/Good.jar"}, {"url": "http://cdn.modrinth.com/Good.jar"},
                    {"sha": "ab" * 32}, {"name": "Good.zip"}):
        _net171["answers"] = _api171([_ver171("VVVVVV01", **_bad171)])
        _svc171["off_cdn"].append(_mr171.resolve("AABBCC12")[1])
    _net171["answers"] = _api171([_ver171("VVVVVV01", size=_mr171.FILE_CAP + 1)])
    _svc171["too_big"] = _mr171.resolve("AABBCC12")
    _net171["answers"] = _api171([_ver171("VVVVVV01", pid="ZZZZZZ99"), {"id": "../x", "project_id": "AABBCC12"}])
    _svc171["other_project"] = _mr171.resolve("AABBCC12")
    _net171["answers"] = _api171([])
    _svc171["none"] = _mr171.resolve("AABBCC12")
    _n_before171 = len(_net171["calls"])
    _svc171["bad_id"] = _mr171.resolve("../etc/x")
    _svc171["bad_id_calls"] = len(_net171["calls"]) - _n_before171
    _net171["answers"] = {"https://cdn.modrinth.com/": (_BODY171 + b"tampered", None)}
    _svc171["tampered"] = _mr171.download({"url": _CDN171, "sha512": _SHA171})
finally:
    _p9_restore_all()

_hits171 = (_svc171["search"][0] or [])
check("plugins search: Modrinth's hits become rows with a valid id; a bad id or a non-object is dropped, long "
      "text capped, a non-text field blank",
      [h["project_id"] for h in _hits171] == ["AABBCC12", "DDEEFF34"] and len(_hits171[0]["description"]) == 300
      and _hits171[1]["title"] == "" and _hits171[1]["downloads"] == 0, repr(_hits171))
_facets171 = _json171.loads(_up171.parse_qs(_svc171["search_url"].split("?", 1)[1])["facets"][0]) \
    if "?" in _svc171.get("search_url", "") else None
check("plugins search: the query asks api.modrinth.com for plugins on Paper, Spigot or Bukkit, on the server's "
      "version when known and on every version when not",
      _facets171 == [["project_type:plugin"], ["categories:paper", "categories:spigot", "categories:bukkit"],
                     ["versions:1.21.4"]]
      and "versions%3A" not in _svc171["search_nov_url"] and "index=downloads" in _svc171["search_nov_url"],
      repr((_facets171, _svc171.get("search_nov_url"))))
check("plugins search: a refused query asks Modrinth nothing; Modrinth not answering is said, not an empty list",
      _svc171["search_bad"] == (None, _mr171.BAD_QUERY) and _svc171["search_bad_calls"] == 0
      and _svc171["search_down"] == (None, _mr171.UNAVAILABLE), repr(_svc171))
_res171 = _svc171["resolve"][0] or {}
check("plugins install: the newest RELEASE build is chosen over a newer beta, with its primary file, its name "
      "sanitized",
      _res171.get("version_id") == "VVVVVV01" and _res171.get("title") == "Good Plugin"
      and _res171.get("plan") == {"url": _CDN171, "filename": "Good_Plugin-1.2.jar", "sha512": _SHA171,
                                  "size": len(_BODY171)}, repr(_svc171["resolve"]))
check("plugins install: the versions are asked for the Paper loaders and the server's version, and a server "
      "whose version is unknown asks without one",
      "loaders=%5B%22paper%22%2C+%22spigot%22%2C+%22bukkit%22%5D" in _svc171["resolve_urls"][1]
      and "game_versions=%5B%221.21.4%22%5D" in _svc171["resolve_urls"][1]
      and "game_versions" not in _svc171["only_beta_url"]
      and (_svc171["only_beta"][0] or {}).get("version_id") == "BETA0001", repr(_svc171["resolve_urls"]))
check("plugins install: the file is fetched from the CDN only, capped at the upload limit, and kept when its "
      "sha512 matches",
      _svc171["download"] == (_BODY171, None)
      and _svc171["download_call"] == (_CDN171, _mr171.FILE_CAP, ("cdn.modrinth.com",)),
      repr(_svc171["download_call"]))
check("plugins install: a file off Modrinth's CDN, over http, without a sha512 or not a .jar is refused",
      _svc171["off_cdn"] == [_mr171.NO_FILE] * 4, repr(_svc171["off_cdn"]))
check("plugins install: a file over the cap is refused from the API's size, before any download",
      _svc171["too_big"] == (None, _mr171.TOO_LARGE), repr(_svc171["too_big"]))
check("plugins install: a build of another project, or with a bad id, is never chosen; none left is said",
      _svc171["other_project"] == (None, _mr171.NO_VERSION) and _svc171["none"] == (None, _mr171.NO_VERSION),
      repr((_svc171["other_project"], _svc171["none"])))
check("plugins install: a bad project id asks Modrinth nothing",
      _svc171["bad_id"] == (None, _mr171.BAD_ID) and _svc171["bad_id_calls"] == 0, repr(_svc171["bad_id"]))
check("plugins install: a download whose sha512 is not the API's is dropped",
      _svc171["tampered"] == (None, _mr171.BAD_HASH), repr(_svc171["tampered"]))

# The real fetcher: a URL off the allowlist is refused before any opener is built (nothing here can open one:
# the suites refuse connections, and a refusal that went on to open would answer with an error class name).
_real171 = [_mr171._mdr_http_get(u, 100, {"api.modrinth.com"}) for u in (
    "http://api.modrinth.com/v2/search", "https://api.modrinth.com.evil.example/v2", "https://evil.example/",
    "https://api.modrinth.com:444/v2", "https://u@api.modrinth.com/v2", "file:///etc/passwd", "not a url")]
check("plugins fetch: a URL that is not https on the allowed host, port 443, without credentials, never opens",
      _real171 == [(None, "not an allowed URL")] * 7, repr(_real171))
check("plugins fetch: a redirect is refused (the allowlist is the URL asked for)",
      _mr171._MdrNoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example/") is None)

# ── 4. the routes ───────────────────────────────────────────────────────────────────────────────
_pmc171 = _p9_new_server(P9_HOST, "pmcserver", "pmc", 25565, name="p171-pmc", status="online")
_mc171 = _p9_new_server(P9_HOST, "p171mc", "mc", 25566, name="p171-mc", status="online")
_listing171 = {"serverfiles/plugins": {"path": "serverfiles/plugins", "entries": [
    {"name": "cache", "is_dir": True, "size": 0}, {"name": "LuckPerms-5.4.jar", "is_dir": False, "size": 2048},
    {"name": "Old-1.0.jar.disabled", "is_dir": False, "size": 10}, {"name": "config.yml", "is_dir": False},
    {"name": "Odd name.jar", "is_dir": False, "size": 5}]}}
_files171 = {"serverfiles/version_history.json": ('{"currentVersion": "1.21.4-212-abc (MC: 1.21.4)"}', None)}
_uploads171, _renames171, _deletes171 = [], [], []
_upload_answer171 = {"v": (True, "Uploaded")}
_write_refusal171 = {"on": False}
_refused171 = []


def _browse171(server, user, relpath="", selfname=None):
    return _listing171.get(relpath, {"path": relpath, "entries": [], "unreadable": True})


def _read171(server, user, relpath, max_bytes=1048576):
    return _files171.get(relpath, (None, "File not found"))


def _upload171(server, user, reldir, filename, data, overwrite=True, selfname=None):
    _uploads171.append((user, reldir, filename, data, overwrite, selfname))
    return _upload_answer171["v"]


def _rename171(server, user, relpath, new_name, selfname=None):
    _renames171.append((user, relpath, new_name, selfname))
    return True, "Renamed"


def _delete171(server, user, relpath, selfname=None):
    _deletes171.append((user, relpath, selfname))
    return False, "rm: cannot remove: host text"


def _wrefuse171(gs, action, detail=""):
    if not _write_refusal171["on"]:
        return None
    _refused171.append((action, detail))
    from flask import jsonify
    return jsonify({"success": False, "message": "refused"}), 409


_r171 = {}
_url171 = "/api/server/%d/plugins" % _pmc171
try:
    _p9_arm(who="part171")
    _p9_patch(_mr171, "_mdr_http_get", _net_get171)
    _p9_patch_sm("browse_dir", _browse171)
    _p9_patch_sm("read_file", _read171)
    _p9_patch_sm("upload_file", _upload171)
    _p9_patch_sm("rename_path", _rename171)
    _p9_patch_sm("delete_path", _delete171)
    _p9_patch(_sf171, "_write_refused", _wrefuse171)
    _p9_patch(_sf171, "_read_refused", lambda *a, **k: None)
    _A171, _F171, _V171 = _p9_client(P9_ADMIN), _p9_client(P9_FILES), _p9_client(P9_VIEWER)

    _r171["list"] = _A171.get(_url171)
    _r171["list_files"] = _F171.get(_url171)
    _r171["list_viewer"] = _V171.get(_url171)
    _r171["list_mc"] = _A171.get("/api/server/%d/plugins" % _mc171)
    _listing171["serverfiles"] = {"path": "serverfiles", "entries": [{"name": "server.jar", "is_dir": False}]}
    _saved171 = _listing171.pop("serverfiles/plugins")
    _r171["list_nofolder"] = _A171.get(_url171)
    _listing171["serverfiles"]["entries"].append({"name": "plugins", "is_dir": True})
    _r171["list_unreadable"] = _A171.get(_url171)
    _listing171["serverfiles/plugins"] = _saved171

    _net171["answers"] = {"https://api.modrinth.com/v2/search": (b'{"hits": []}', None)}
    _net171["calls"] = []
    _r171["search"] = _A171.get(_url171 + "/search?q=perms&mc=1.21.4")
    _r171["search_badmc"] = _A171.get(_url171 + "/search?q=perms&mc=1.21%22%5D")
    _r171["search_calls"] = [c[0] for c in _net171["calls"]]
    _r171["search_badq"] = _A171.get(_url171 + "/search?q=" + "x" * 81)
    _r171["search_viewer"] = _V171.get(_url171 + "/search?q=x")

    _net171["answers"] = _api171([_ver171("VVVVVV01")])
    _net171["calls"] = []
    _r171["install"] = _A171.post(_url171 + "/install", json={"project_id": "AABBCC12"})
    _r171["install_audit"] = _p9_audit("plugin_install")
    _r171["install_calls"] = [c[0] for c in _net171["calls"]]
    _ok_uploads171 = list(_uploads171)
    _net171["calls"] = []
    _r171["install_badid"] = [_A171.post(_url171 + "/install", json=b).status_code for b in (
        {"project_id": "../x"}, {"project_id": ["AABBCC12"]}, {}, {"project_id": "AABBCC1!"})]
    _r171["install_badid_audit"] = _p9_audit("plugin_install")
    _r171["install_badid_calls"] = len(_net171["calls"])
    _r171["install_viewer"] = _V171.post(_url171 + "/install", json={"project_id": "AABBCC12"})
    _r171["install_mc"] = _A171.post("/api/server/%d/plugins/install" % _mc171, json={"project_id": "AABBCC12"})
    _r171["install_files"] = _F171.post(_url171 + "/install", json={"project_id": "AABBCC12"})
    _uploads_after_ok171 = list(_uploads171)
    _net171["answers"]["https://cdn.modrinth.com/"] = (_BODY171 + b"!", None)
    _r171["install_tampered"] = _A171.post(_url171 + "/install", json={"project_id": "AABBCC12"})
    _r171["install_tampered_audit"] = _p9_audit("plugin_install")
    _r171["uploads_after_tamper"] = len(_uploads171) - len(_uploads_after_ok171)
    _net171["answers"]["https://cdn.modrinth.com/"] = (_BODY171, None)
    _upload_answer171["v"] = (False, _smf171.UPLOAD_EXISTS)
    _r171["install_taken"] = _A171.post(_url171 + "/install", json={"project_id": "AABBCC12"})
    _r171["install_taken_audit"] = _p9_audit("plugin_install")
    _upload_answer171["v"] = (True, "Uploaded")
    _write_refusal171["on"] = True
    _net171["calls"] = []
    _n_up171 = len(_uploads171)
    _r171["install_refused"] = _A171.post(_url171 + "/install", json={"project_id": "AABBCC12"})
    _r171["install_refused_calls"] = (len(_net171["calls"]), len(_uploads171) - _n_up171)
    _r171["change_refused"] = _A171.post(_url171 + "/change", json={"action": "remove", "name": "LuckPerms-5.4.jar"})
    _write_refusal171["on"] = False

    _r171["disable"] = _A171.post(_url171 + "/change", json={"action": "disable", "name": "LuckPerms-5.4.jar"})
    _r171["disable_audit"] = _p9_audit("plugin_disable")
    _r171["enable"] = _F171.post(_url171 + "/change", json={"action": "enable", "name": "Old-1.0.jar.disabled"})
    _r171["enable_audit"] = _p9_audit("plugin_enable")
    _r171["remove"] = _A171.post(_url171 + "/change", json={"action": "remove", "name": "Old-1.0.jar.disabled"})
    _r171["remove_audit"] = _p9_audit("plugin_remove")
    _n_ch171 = (len(_renames171), len(_deletes171))
    _r171["change_bad"] = [_A171.post(_url171 + "/change", json=b).status_code for b in (
        {"action": "remove", "name": "../../.ssh/authorized_keys"}, {"action": "remove", "name": "x/../a.jar"},
        {"action": "remove", "name": "server.properties"}, {"action": "enable", "name": "a.jar"},
        {"action": "rm", "name": "a.jar"}, {"action": "remove", "name": ["a.jar"]})]
    _r171["change_bad_audit"] = _p9_audit("plugin_remove")
    _r171["change_bad_calls"] = (len(_renames171) - _n_ch171[0], len(_deletes171) - _n_ch171[1])
    _r171["change_viewer"] = _V171.post(_url171 + "/change", json={"action": "remove", "name": "a.jar"})
finally:
    _p9_restore_all()
    _p9_delete_server(_mc171)


def _j171(r):
    return r.get_json(silent=True) or {}


_jl171 = _j171(_r171["list"])
check("plugins list: the .jar and .jar.disabled files of serverfiles/plugins, with the server's Minecraft "
      "version; folders and other files are left out, an odd name listed but not managed",
      _jl171.get("success") is True and _jl171.get("mc_version") == "1.21.4"
      and [(p["name"], p["enabled"], p["managed"]) for p in _jl171.get("plugins", [])]
      == [("LuckPerms-5.4.jar", True, True), ("Old-1.0.jar.disabled", False, True), ("Odd name.jar", True, False)],
      repr(_jl171))
check("plugins list: the file manager's permission reads it; a console viewer is refused; a vanilla server "
      "is refused",
      _r171["list_files"].status_code == 200 and _r171["list_viewer"].status_code == 403
      and _r171["list_mc"].status_code == 400,
      repr([_r171[k].status_code for k in ("list_files", "list_viewer", "list_mc")]))
check("plugins list: no plugins folder yet (made by the first start) is an empty list; one that is there but "
      "could not be read is said, never empty",
      _j171(_r171["list_nofolder"]).get("plugins") == [] and _j171(_r171["list_unreadable"]).get("success") is False
      and _j171(_r171["list_unreadable"]).get("error") == _mp171.UNREADABLE,
      repr((_j171(_r171["list_nofolder"]), _j171(_r171["list_unreadable"]))))
check("plugins search route: a version that is not N.N.N is dropped (search everything, marked unverified); an "
      "over-long query is a 400; a console viewer is refused",
      _j171(_r171["search"]).get("verified") is True and _j171(_r171["search_badmc"]).get("verified") is False
      and len(_r171["search_calls"]) == 2 and "versions%3A1.21.4" in _r171["search_calls"][0]
      and "versions%3A" not in _r171["search_calls"][1]
      and _r171["search_badq"].status_code == 400 and _r171["search_viewer"].status_code == 403,
      repr((_r171["search_calls"], _r171["search_badq"].status_code)))
_ja171 = _j171(_r171["install"])
check("plugins install route: the verified jar is written through upload_file into serverfiles/plugins as the "
      "game account, never over a file already there",
      _ja171.get("success") is True and _ja171.get("name") == "Good_Plugin-1.2.jar"
      and _ok_uploads171 == [("pmcserver", "serverfiles/plugins", "Good_Plugin-1.2.jar", _BODY171, False,
                              "pmcserver")], repr((_ja171, _ok_uploads171)))
check("plugins install route: the server's own version picks the build, and the audit row names the plugin, "
      "its version and file, against the server",
      any("game_versions=%5B%221.21.4%22%5D" in u for u in _r171["install_calls"])
      and _r171["install_audit"].success is True and _r171["install_audit"].target == "p171-pmc"
      and _r171["install_audit"].detail == "Good Plugin 1.2 (Good_Plugin-1.2.jar, AABBCC12/VVVVVV01)",
      repr((_r171["install_calls"], _r171["install_audit"])))
check("plugins install route: a bad or missing project id is a 400 that asks Modrinth nothing, audited as refused",
      _r171["install_badid"] == [400] * 4 and _r171["install_badid_calls"] == 0
      and _r171["install_badid_audit"].success is False
      and _r171["install_badid_audit"].detail.startswith("? (refused:"),
      repr((_r171["install_badid"], _r171["install_badid_audit"])))
check("plugins install route: the file manager's permission installs; a console viewer and a vanilla server "
      "are refused",
      _r171["install_viewer"].status_code == 403 and _r171["install_mc"].status_code == 400
      and _j171(_r171["install_files"]).get("success") is True,
      repr([_r171[k].status_code for k in ("install_viewer", "install_mc", "install_files")]))
check("plugins install route: a download that fails its sha512 writes nothing and is audited as failed",
      _r171["install_tampered"].status_code == 502 and _j171(_r171["install_tampered"]).get("message")
      == _mr171.BAD_HASH and _r171["uploads_after_tamper"] == 0 and _r171["install_tampered_audit"].success is False,
      repr((_j171(_r171["install_tampered"]), _r171["install_tampered_audit"])))
check("plugins install route: a name already in the folder is a 409 that says so, audited as name taken",
      _r171["install_taken"].status_code == 409
      and "already in the plugins folder" in _j171(_r171["install_taken"]).get("message", "")
      and "(name taken)" in _r171["install_taken_audit"].detail, repr(_j171(_r171["install_taken"])))
check("plugins install/change: the file browser's root-account refusal is asked before Modrinth or the host",
      _r171["install_refused"].status_code == 409 and _r171["install_refused_calls"] == (0, 0)
      and _r171["change_refused"].status_code == 409
      and _refused171 == [("plugin_install", "serverfiles/plugins"),
                          ("plugin_remove", "serverfiles/plugins/LuckPerms-5.4.jar")],
      repr((_r171["install_refused_calls"], _refused171)))
check("plugins change route: disable and enable rename in place as the game account, remove deletes; each is "
      "audited with the file name against the server",
      _renames171 == [("pmcserver", "serverfiles/plugins/LuckPerms-5.4.jar", "LuckPerms-5.4.jar.disabled",
                       "pmcserver"),
                      ("pmcserver", "serverfiles/plugins/Old-1.0.jar.disabled", "Old-1.0.jar", "pmcserver")]
      and _deletes171 == [("pmcserver", "serverfiles/plugins/Old-1.0.jar.disabled", "pmcserver")]
      and _r171["disable_audit"].detail == "LuckPerms-5.4.jar -> LuckPerms-5.4.jar.disabled"
      and _r171["enable_audit"].success is True and _r171["disable_audit"].target == "p171-pmc"
      and _r171["remove_audit"].detail == "Old-1.0.jar.disabled" and _r171["remove_audit"].success is False,
      repr((_renames171, _deletes171, _r171["disable_audit"], _r171["remove_audit"])))
check("plugins change route: a failed delete shows no host text, only a fixed answer",
      "host text" not in _j171(_r171["remove"]).get("message", "x")
      and _j171(_r171["remove"]).get("success") is False,
      repr(_j171(_r171["remove"])))
check("plugins change route: a path, a non-plugin file, an action that does not fit, an unknown action and a "
      "list are each a 400 that touches nothing; a console viewer is refused",
      _r171["change_bad"] == [400] * 6 and _r171["change_bad_calls"] == (0, 0)
      and _r171["change_bad_audit"].success is False and _r171["change_viewer"].status_code == 403,
      repr((_r171["change_bad"], _r171["change_bad_calls"])))

# ── 5. the server page ──────────────────────────────────────────────────────────────────────────
_pages171 = {}
_mc2_171 = _p9_new_server(P9_HOST, "p171mc2", "mc", 25567, name="p171-mc2", status="online")
try:
    _p9_arm(who="part171")
    _p9_patch(_sd171, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd171, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc171, "run_command", lambda *a, **k: ("", "", 1))
    for _k171, _uid171, _sid171 in (("admin", P9_ADMIN, _pmc171), ("files", P9_FILES, _pmc171),
                                    ("viewer", P9_VIEWER, _pmc171), ("vanilla", P9_ADMIN, _mc2_171)):
        _rp171 = _p9_client(_uid171).get("/server/%d" % _sid171)
        _pages171[_k171] = (_rp171.status_code, _rp171.get_data(as_text=True))
finally:
    _p9_restore_all()
    _p9_delete_server(_pmc171)
    _p9_delete_server(_mc2_171)
_pa171, _pf171, _pv171, _pn171 = (_pages171.get(k, (0, ""))[1] for k in ("admin", "files", "viewer", "vanilla"))
check("server page: a PaperMC server shows the Plugins card and its script to a superadmin and a file manager",
      _pages171.get("admin", (0,))[0] == 200 and 'id="mdr-card"' in _pa171 and "js/server_plugins.js" in _pa171
      and 'id="mdr-card"' in _pf171 and "js/server_plugins.js" in _pf171, _pa171[:200])
check("server page: a console viewer and a vanilla server get no Plugins card and no script",
      'id="mdr-card"' not in _pv171 and "server_plugins.js" not in _pv171
      and 'id="mdr-card"' not in _pn171 and "server_plugins.js" not in _pn171,
      repr([_pages171.get(k, (0,))[0] for k in ("viewer", "vanilla")]))

# ── 6. the card's script, in node ───────────────────────────────────────────────────────────────
with open(_os171.path.join(_root, "panel", "static", "js", "server_plugins.js"), encoding="utf-8") as _fh171:
    _js171 = _fh171.read()
_name_js171 = "plugins card: draws Modrinth's text as text, posts only checked ids and names"
_out171 = _run_js75(_name_js171, (
    "const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 9; global.t = s => s;\n"
    "global.tf = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => v[k]);\n"
    "function node(tag) { const n = {tag, children: [], attrs: {}, hidden: false, disabled: false, value: '',\n"
    "  textContent: '', className: '', style: {},\n"
    "  appendChild(c) { this.children.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = String(v); },\n"
    "  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }};\n"
    "  Object.defineProperty(n, 'innerHTML', {set() { throw new Error('innerHTML used'); }}); return n; }\n"
    "const els = {}; const mk = id => (els[id] = els[id] || node('div'));\n"
    "global.document = {getElementById: mk, readyState: 'complete', addEventListener: () => 0,\n"
    "  createElement: node};\n"
    "const posts = [], gets = []; const confirms = [];\n"
    "global.confirmDialog = o => { confirms.push(o.bodyText); o.onConfirm(); };\n"
    "const list = {success: true, mc_version: '1.21.4', plugins: [\n"
    "  {name: '<b>x</b>.jar', enabled: true, managed: false, size: 10},\n"
    "  {name: 'Good-1.0.jar', enabled: true, managed: true, size: 2048}]};\n"
    "const hits = {success: true, verified: false, hits: [\n"
    "  {project_id: 'AABBCC12', title: '<img src=x onerror=alert(1)>', description: 'd', downloads: 5},\n"
    "  {project_id: '../evil', title: 'bad id'}]};\n"
    "global.fetch = (u, o) => {\n"
    "  if (o && o.method === 'POST') posts.push([u, JSON.parse(o.body)]); else gets.push(u);\n"
    "  const d = o ? {success: true, message: 'ok'} : (u.indexOf('/search') >= 0 ? hits : list);\n"
    "  return Promise.resolve({json: () => Promise.resolve(d)}); };\n"
    + _js171 + "\n"
    "(async () => { await settle(); const out = {};\n"
    "  const inst = els['mdr-installed'].children;\n"
    "  out.installed = inst.map(li => li.children.length); out.firstName = inst[0].children[0].textContent;\n"
    "  out.version = els['mdr-version'].textContent;\n"
    "  mk('mdr-q').value = 'a\\u0007b'; window.mdrSearch({preventDefault() {}}); await settle();\n"
    "  out.badQueryGets = gets.length; out.badQueryMsg = els['mdr-msg'].textContent;\n"
    "  els['mdr-q'].value = ' perms '; window.mdrSearch({preventDefault() {}}); await settle();\n"
    "  out.searchUrl = gets[gets.length - 1];\n"
    "  const res = els['mdr-results'].children; out.results = res.length;\n"
    "  out.title = res[0].children[0].children[0].textContent;\n"
    "  out.meta = res[0].children[0].children[2].textContent;\n"
    "  out.installArgs = res[0].children[1].attrs['data-args'];\n"
    "  window.mdrInstall('../evil', 'x'); window.mdrChange('remove', '../../x.jar');\n"
    "  window.mdrChange('rm', 'a.jar');\n"
    "  await settle(); out.badPosts = posts.length;\n"
    "  window.mdrInstall('AABBCC12', 'Good'); await settle();\n"
    "  window.mdrChange('remove', 'Good-1.0.jar'); await settle();\n"
    "  out.posts = posts; out.confirms = confirms; console.log(JSON.stringify(out)); })();\n"))
if _out171 is not None:
    check("plugins card: installed names are text; an odd name gets no buttons, a managed one Disable and Remove",
          _out171.get("installed") == [2, 4] and _out171.get("firstName") == "<b>x</b>.jar"
          and _out171.get("version", "").startswith("Minecraft 1.21.4"), repr(_out171))
    check("plugins card: a query with a control character asks nothing and says the rule; a good one is trimmed "
          "and sent with the server's version",
          _out171.get("badQueryGets") == 1 and _out171.get("badQueryMsg") == _mr171.BAD_QUERY
          and _out171.get("searchUrl") == "/api/server/9/plugins/search?q=perms&mc=1.21.4", repr(_out171))
    check("plugins card: a Modrinth title is drawn as text, a hit with a bad id is dropped, and an unverified "
          "result says so",
          _out171.get("results") == 1 and _out171.get("title") == "<img src=x onerror=alert(1)>"
          and "not checked against this server" in _out171.get("meta", "")
          and _out171.get("installArgs") == '["AABBCC12","<img src=x onerror=alert(1)>"]', repr(_out171))
    check("plugins card: a bad id, a path or an unknown action posts nothing; install posts the id and remove "
          "asks first, then posts the name",
          _out171.get("badPosts") == 0
          and _out171.get("posts") == [
              ["/api/server/9/plugins/install", {"project_id": "AABBCC12"}],
              ["/api/server/9/plugins/change", {"action": "remove", "name": "Good-1.0.jar"}]]
          and _out171.get("confirms") == ["Remove Good-1.0.jar from the plugins folder?"], repr(_out171))
