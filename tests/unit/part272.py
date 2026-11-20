"""Part 272 of the unit suite: the BlueMap add-on (services/addons_bluemap.py, its parts of routes/addons*.py).

1. The pieces: the world read from the probe (level-name as Java reads it, a plain folder name only, Paper's
   nether and end beside it), the read-only mounts, the unit (no game log, no forward, its command and
   priority, the loopback page), the config files (the EULA's acceptance, no usage report, no access log),
   Mojang's version list read only from piston-meta with the detail's and the jar's SHA-1 checked, the
   status read (disk and version), and the client file's shell under bash with a stand-in curl.
2. The routes: an install without Mojang's EULA ticked is refused before the host is asked anything; with
   it, the install reads the world, fetches the client file's address, writes core.conf over stdin with
   who accepted it, mounts the world read-only and audits the acceptance; a missing world or an unreachable
   Mojang stops it before anything is written; the list offers BlueMap on vanilla and Paper only, with the
   EULA's link, and an Update once the game logged another version; that Update fetches the new version's
   client file.
3. The card (node over server_addons.js): Install posts nothing until the EULA is ticked, then posts it;
   the installed row says who accepted it, the version, the disk used and the update.
4. The text: every new sentence in Spanish and French.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call a recorder;
Mojang's answers are fixtures. The client file's shell runs under bash in a throwaway folder with a
stand-in curl on PATH. Nothing reaches a host, Mojang, /etc or data/.
"""
import atexit as _atexit272
import json as _json272
import os
import re as _re272
import shutil as _shutil272
import subprocess as _sp272  # nosec B404 - bash and node over the panel's own files, in a throwaway dir
import tempfile as _tf272

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_quiet_lookups, _p9_restore_all,
                         _p9_threading, _P9Thread)
from unit.part257 import _HARNESS257
from panel.core import i18n as _i18n272
from panel.routes import addons as _ra272, addons_change as _ch272
from panel.services import addons as _ad272, addons_bluemap as _bm272, geoip as _geo272

_trips272 = len(_P9_TRIPPED)
_TMP272 = _tf272.mkdtemp(prefix="p272-")
_atexit272.register(_shutil272.rmtree, _TMP272, True)
_ROOT272 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_JAR272 = b"p272 client jar bytes"
_JAR_SHA272 = _geo272.sha1_hex(_JAR272)   # the stand-in jar's own SHA-1


def _mojang272(version="1.21.4", jar_sha=_JAR_SHA272, detail_sha=None, client_host="piston-data.mojang.com"):
    """(version list, detail) bytes as Mojang serves them, for one version and its client jar."""
    detail = _json272.dumps({"id": version, "downloads": {"client": {
        "url": "https://%s/v1/objects/%s/client.jar" % (client_host, jar_sha), "sha1": jar_sha, "size": 21}}}).encode()
    dsha = detail_sha or _geo272.sha1_hex(detail)
    manifest = _json272.dumps({"latest": {"release": version}, "versions": [
        {"id": "1.20.1", "url": "https://piston-meta.mojang.com/v1/packages/%s/1.20.1.json" % ("a" * 40),
         "sha1": "a" * 40},
        {"id": version, "url": "https://piston-meta.mojang.com/v1/packages/%s/%s.json" % (dsha, version),
         "sha1": dsha}]}).encode()
    return manifest, detail


def _getter272(manifest, detail, asked=None):
    """A stand-in for addons_bluemap._get: the list for MANIFEST, the detail for a piston-meta package URL."""
    def get(url, cap):
        if asked is not None:
            asked.append(url)
        if not _bm272._allowed(url):
            return None
        return manifest if url == _bm272.MANIFEST else detail
    return get


def _kv272(level="world", dirs=("world", "logs"), version="1.21.4"):
    props = "" if level is None else "#Minecraft server properties\nlevel-seed=\nlevel-name=%s\nlevel-type=normal\n" % level
    return {"props.b64": _ad272._b64(props), "dirs.b64": _ad272._b64("\n".join(dirs)), "mcver": version}


# ── 1. the pieces ─────────────────────────────────────────────────────────────────────────────────
def _world272():
    plain = _bm272.parse_world(_kv272(), _ad272._unb64)
    paper = _bm272.parse_world(_kv272("survival", ("survival", "survival_nether", "survival_the_end")), _ad272._unb64)
    unset = _bm272.parse_world(_kv272(None), _ad272._unb64)
    eq("world: level-name read as Java reads it, `world` when unset, Paper's nether and end found beside it",
       [(w["level"], w["nether"], w["end"], w["version"], str(w["why"])) for w in (plain, paper, unset)],
       [("world", False, False, "1.21.4", ""), ("survival", True, True, "1.21.4", ""), ("world", False, False, "1.21.4", "")])
    bad = [_bm272.parse_world(_kv272(name, (name,)), _ad272._unb64) for name in ("my world", "a%h", "-x", "..")]
    check("world: a level-name that is not one plain folder name is refused (blank, %, leading dash, ..)",
          all(w["level"] == "" and str(w["why"]).startswith("BlueMap can't use this world's name") for w in bad),
          repr([str(w["why"])[:60] for w in bad]))
    gone = _bm272.parse_world(_kv272("world", ("logs",)), _ad272._unb64)
    nover = _bm272.parse_world(_kv272(version="1.21 4;rm"), _ad272._unb64)
    eq("world: no world folder, or no plain version in the log, stops it with the step to take",
       [gone["why"].template, nover["why"]], [_bm272.NO_WORLD, _bm272.NO_VERSION])
    w = _bm272.world("mcp", paper)
    eq("world: every world folder is mounted read-only, the nether and end only when the server keeps them beside it",
       (w.mounts, w.version, _bm272.world("mcp", plain).mounts),
       (("/home/mcp/serverfiles/survival:/app/world:ro", "/home/mcp/serverfiles/survival_nether:/app/world_nether:ro",
         "/home/mcp/serverfiles/survival_the_end:/app/world_the_end:ro"), "1.21.4",
        ("/home/mcp/serverfiles/world:/app/world:ro",)))
    return paper


def _unit272(paper):
    net = _ad272.network(None, None, [], True)
    unit = _ad272.quadlet("mcp", "bluemap", _bm272.world("mcp", paper), net, 21004, (), (1001, 1001))
    want = ("Network=pasta:--splice-only", "PublishPort=127.0.0.1:21004:8100", "Exec=-r -u -w -v 1.21.4",
            "Volume=/home/mcp/serverfiles/survival:/app/world:ro", "Nice=10", "SuccessExitStatus=143",
            "ReadOnly=true", "DropCapability=all", "NoNewPrivileges=true", "UserNS=keep-id", "User=1001",
            "Image=ghcr.io/bluemap-minecraft/bluemap@sha256:", "--dns=none", "Volume=/home/mcp/panel-addons/bluemap/data:/app/data")
    eq("unit: BlueMap's hardening, its pinned image, the world read-only, its command and lower priority, the "
       "page on loopback", [x for x in want if x not in unit], [])
    check("unit: no game log, no forward to the game (-U/-T), no RCON, no host network or added capability",
          not any(x in unit for x in ("/gamelog", "-U,", "-T,", "Network=host", "AddCapability", "--privileged")),
          unit[:300])
    other = _ad272.quadlet("u", "iw4madmin", "/home/u/serverfiles/main", _ad272.network(28960, None, [], True), 21001)
    check("unit: the log add-ons keep their game log mount and no Exec= or Nice=",
          "Volume=/home/u/serverfiles/main:/gamelog:ro" in other and "Exec=" not in other and "Nice=" not in other,
          other[:200])


def _configs272(paper):
    core = _bm272.core_conf("adm272", "2026-11-19T10:00:00+00:00")
    eq("core.conf: the EULA accepted (who, when, the link), one render thread, no usage report, no debug log",
       [x in core for x in ("accept-download: true", "render-thread-count: 1", "metrics: false", "adm272",
                            "2026-11-19T10:00:00+00:00", _bm272.EULA_URL)] + ["log:" in core, "file:" in core],
       [True] * 6 + [False, False])
    files = _bm272.config_files(paper)
    web = files["config/webserver.conf"]
    check("webserver.conf: port 8100 on the container's own network, no access log (no visitor address kept), "
          "nosniff and no referrer", "port: 8100" in web and "log" not in web.replace("logs", "")
          and '"X-Content-Type-Options": "nosniff"' in web and '"Referrer-Policy": "no-referrer"' in web, web)
    vanilla = _bm272.config_files({"nether": False, "end": False})
    eq("maps: the nether and end read Paper's folders beside the world, else the world itself; the nether's ceiling "
       "is cut away", (_re272.findall(r'world: "([^"]+)"', files["config/maps/nether.conf"] + files["config/maps/end.conf"]),
                       _re272.findall(r'world: "([^"]+)"', vanilla["config/maps/nether.conf"] + vanilla["config/maps/end.conf"]),
                       "subtract: true" in files["config/maps/nether.conf"], "subtract" in files["config/maps/end.conf"]),
       (["/app/world_nether", "/app/world_the_end"], ["/app/world", "/app/world"], True, False))


def _mojang_reads272():
    manifest, detail = _mojang272()
    picked = _bm272.pick_version(manifest, "1.21.4")
    eq("Mojang: the version's detail URL and SHA-1 are read from the list; a version it lacks is None",
       (bool(picked) and picked[0].startswith("https://piston-meta.mojang.com/v1/packages/"),
        _bm272.pick_version(manifest, "9.9.9"), _bm272.pick_version(b"not json", "1.21.4")), (True, None, None))
    eq("Mojang: the client jar's URL and SHA-1, only when the detail matches the list's SHA-1",
       (_bm272.pick_client(detail, picked[1]), _bm272.pick_client(detail + b" ", picked[1])),
       (("https://piston-data.mojang.com/v1/objects/%s/client.jar" % _JAR_SHA272, _JAR_SHA272), None))
    _m2, other_host = _mojang272(client_host="evil.example")
    _m3, wrong_sha = _mojang272(jar_sha="b" * 40)
    wrong_sha = wrong_sha.replace(b'"sha1": "' + b"b" * 40, b'"sha1": "' + b"c" * 40)
    eq("Mojang: a client URL off piston-data, or one whose object hash is not the detail's SHA-1, is refused",
       [_bm272.pick_client(d, _geo272.sha1_hex(d)) for d in (other_host, wrong_sha)],
       [None, None])
    eq("Mojang: only https on piston-meta is fetched (no other host, no http, no user info)",
       [_bm272._allowed(u) for u in ("https://piston-meta.mojang.com/x", "http://piston-meta.mojang.com/x",
                                     "https://piston-meta.mojang.com.evil.example/x", "https://u:p@piston-meta.mojang.com/x",
                                     "https://piston-data.mojang.com/x")],
       [True, False, False, False, False])
    asked = []
    _p9_patch(_bm272, "_get", _getter272(manifest, detail, asked))
    url, sha1, why = _bm272.client_download("1.21.4")
    eq("Mojang: client_download reads the list, then the detail it names, and gives the jar's address",
       (url and url.endswith("/%s/client.jar" % _JAR_SHA272), sha1, why, len(asked)), (True, _JAR_SHA272, "", 2))
    _p9_patch(_bm272, "_get", lambda url, cap: None)
    eq("Mojang: unreachable is said with the version", str(_bm272.client_download("1.21.4")[2]),
       "Couldn't read Mojang's version list for Minecraft 1.21.4. Try again later.")


def _status272():
    meta = _ad272._b64(_json272.dumps({"kind": "bluemap", "mc_version": "1.21.4"}))
    st = _ad272.parse_status("os=24.04\nmeta.bluemap=%s\nstate.bluemap=active\ndisk.bluemap=2048\nmcver.bluemap=1.21.5\n"
                             "meta.b3=%s\nstate.b3=active\n" % (meta, _ad272._b64("{}")))
    eq("status: BlueMap's disk use and the game's logged version are read; another add-on's disk is None",
       (st["addons"]["bluemap"]["disk_kb"], st["addons"]["bluemap"]["mc_version"], st["addons"]["b3"]["disk_kb"]),
       (2048, "1.21.5", None))
    sh = _ad272.status_sh()
    check("status: the disk read is bounded (timeout, low priority) and asked for BlueMap only",
          sh.count("du -sk") == 1 and "timeout 5 nice -n 19 du" in sh and "disk.bluemap=" in sh, sh[-400:])
    probe = _ad272.probe_sh("bluemap", "mcserver", 4, "mc", 1)
    check("probe: BlueMap's reads the world and the version, not the game's log or RCON lines",
          "props.b64=" in probe and "mcver=" in probe and "rcon.b64" not in probe and "games_mp.log" not in probe,
          probe[:300])


# A stand-in curl, as a bash function (it runs before any curl on PATH): it logs its arguments and writes
# $S272_BODY to its -o file, or fails like curl with $S272_FAIL set.
_CURL272 = ('curl() { echo "curl $*" >> "$S272_LOG"; local out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && '
            '{ out="$2"; shift; }; shift; done; [ -n "$S272_FAIL" ] && return 22; printf %s "$S272_BODY" > "$out"; }; ')


def _client_run272(body, fail=False, keep=None):
    """Run client_sh under bash in a fresh folder: (exit status, output, files in data/, curl's calls)."""
    base = os.path.join(_TMP272, "client")
    _shutil272.rmtree(base, ignore_errors=True)
    data = os.path.join(base, "addon", "data")
    os.makedirs(os.path.join(base, "addon", "web"))
    os.makedirs(data)
    with open(os.path.join(data, "minecraft-client-1.20.1.jar"), "wb") as fh:
        fh.write(b"old")
    with open(os.path.join(base, "addon", "web", "index.html"), "w", encoding="utf-8") as fh:
        fh.write("old page")
    if keep is not None:
        with open(os.path.join(data, "minecraft-client-1.21.4.jar"), "wb") as fh:
            fh.write(keep)
    sh = _bm272.client_sh(os.path.join(base, "addon"), "1.21.4",
                          "https://piston-data.mojang.com/v1/objects/%s/client.jar" % _JAR_SHA272, _JAR_SHA272,
                          fresh_webapp=True)
    env = dict(os.environ, S272_LOG=os.path.join(base, "log"), S272_BODY=body.decode(), S272_FAIL="1" if fail else "")
    r = _sp272.run(["bash", "-c", _CURL272 + sh + "echo DONE272"], env=env, capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, check=False)
    log = open(env["S272_LOG"], encoding="utf-8").read() if os.path.exists(env["S272_LOG"]) else ""
    return r.returncode, r.stdout, sorted(os.listdir(data)), log, os.path.exists(os.path.join(base, "addon", "web",
                                                                                             "index.html"))


def _client_sh272():
    rc, out, files, log, page = _client_run272(_JAR272)
    eq("client file (bash): fetched over https only, checked, kept under its version's name; the other version's "
       "jar and the old page go", (rc, "DONE272" in out, files, "--proto =https" in log, page),
       (0, True, ["minecraft-client-1.21.4.jar"], True, False))
    rc, out, files, _log, _page = _client_run272(b"tampered bytes")
    eq("client file (bash): a download whose SHA-1 is not Mojang's is refused and removed (exit 27)",
       (rc, "ADDON_CLIENT_FAILED" in out, files), (27, True, ["minecraft-client-1.20.1.jar"]))
    rc, out, files, _log, _page = _client_run272(_JAR272, fail=True)
    eq("client file (bash): a failed download stops the install", (rc, "ADDON_CLIENT_FAILED" in out), (27, True))
    rc, _out, files, log, _page = _client_run272(b"unused", keep=_JAR272)
    eq("client file (bash): a file already there with Mojang's SHA-1 is kept, nothing downloaded",
       (rc, files, log), (0, ["minecraft-client-1.21.4.jar"], ""))


# ── 2. the routes ─────────────────────────────────────────────────────────────────────────────────
def _probe_out272(level="world", dirs=("world", "logs"), version="1.21.4", meta=None, now=None):
    out = ("os=24.04\npodman=podman version 4.9.3\nuid=1001\ngid=1001\nports= 21008\nsplice=1\n"
           + "".join("%s=%s\n" % kv for kv in _kv272(level, dirs, version).items()))
    if meta is not None:
        out += "meta.bluemap=%s\nstate.bluemap=active\ndisk.bluemap=4096\nmcver.bluemap=%s\n" % (
            _ad272._b64(_json272.dumps(meta)), now or version)
    return out


def _host272(probe, install_out="ADDON_INSTALLED\n"):
    calls = []

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append(("sh", sh, stdin_text))
        if "systemctl --user daemon-reload" in sh:
            return install_out, "", 0
        return probe, "", 0

    def priv(server, verb, args=(), **_kw):
        calls.append(("verb", verb, list(args)))
        return "", "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", priv)
    _p9_patch(_ra272, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ch272, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ra272, "step_up_needed", lambda: False)
    _p9_patch(_ra272, "game_account_write_refusal", lambda remote, user, reading=False: None)
    manifest, detail = _mojang272()
    _p9_patch(_bm272, "_get", _getter272(manifest, detail))
    return calls


def _writes272(calls):
    """The install or change shell the host was given, and its stdin."""
    return next(((c[1], c[2]) for c in calls if c[0] == "sh" and "systemctl --user daemon-reload" in c[1]), ("", None))


def _puts272(sh):
    return {path: _ad272._unb64(b64.strip("'"))
            for b64, path in _re272.findall(r"printf %s (\S+) \| base64 -d > (\S+)\.new", sh or "")}


def _no_eula272(sid):
    calls = _host272(_probe_out272())
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/install" % sid, json={"accept_eula": "yes"})
    _p9_drain()
    eq("install: without Mojang's EULA ticked (exactly true) it is refused, and the host is asked nothing",
       (r.status_code, (r.get_json(silent=True) or {}).get("error"), calls), (400, _bm272.NO_EULA, []))


def _named272(puts, end):
    """The text of the one file `puts` writes whose path ends with `end` ("" when none)."""
    return next((t for p, t in puts.items() if p.endswith(end)), "")


def _install272(sid):
    calls = _host272(_probe_out272())
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/install" % sid, json={"accept_eula": True})
    start = _p9_audit("addon_install")
    _p9_drain()
    sh, stdin = _writes272(calls)
    puts = _puts272(sh)
    eq("install: 202, its start audited with Mojang's EULA (and its link) accepted by the admin, then installed",
       (r.status_code, "Mojang's EULA (%s) accepted" % _bm272.EULA_URL in start.detail, start.username,
        _p9_audit("addon_install").success), (202, True, "p9_admin", True))
    _install_texts272(sh, stdin or "", puts)
    verbs = [c[1] for c in calls if c[0] == "verb"]
    eq("install: the account is readied as for every add-on (prepare last)", verbs[-1:], ["addon-account-prepare"])


def _install_texts272(sh, stdin, puts):
    meta = _json272.loads(_named272(puts, "/addon.json") or "{}")
    unit = _named272(puts, ".container")
    eq("install: core.conf on stdin says the EULA is accepted, by whom; the record keeps who, when, the world, the "
       "version", (["accept-download: true" in stdin, "by p9_admin" in stdin], meta.get("eula_accepted_by"),
                   meta.get("mc_version"), meta.get("world"), bool(meta.get("eula_accepted_at"))),
       ([True, True], "p9_admin", "1.21.4", "world", True))
    eq("install: the host fetches the client jar Mojang names, checks its SHA-1, before the image",
       (("piston-data.mojang.com/v1/objects/%s/client.jar" % _JAR_SHA272) in sh, sh.count(_JAR_SHA272) >= 3,
        -1 < sh.find("curl -fsS") < sh.find("podman pull")), (True, True, True))
    eq("install: the unit mounts the world read-only, starts with that version, and has no game log; the maps are "
       "written", [x in unit for x in ("Volume=/home/mcp272/serverfiles/world:/app/world:ro", "Exec=-r -u -w -v 1.21.4",
                                      "/gamelog")] + ["config/maps/overworld.conf" in " ".join(puts)],
       [True, True, False, True])


def _install_refused272(sid):
    for probe, stub, want in ((_probe_out272(dirs=("logs",)), None, "Couldn't find the world folder"),
                              (_probe_out272(), lambda url, cap: None, "Couldn't read Mojang's version list")):
        calls = _host272(probe)
        if stub is not None:
            _p9_patch(_bm272, "_get", stub)
        _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/install" % sid, json={"accept_eula": True})
        _p9_drain()
        row = _p9_audit("addon_install")
        check("install refused (%s): audited as failed, nothing written on the host" % want,
              row.success is False and want in row.detail and _writes272(calls)[0] == "", repr(row.detail))


def _bluemap_row272(sid):
    got = (_p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid).get_json(silent=True) or {}).get("addons") or []
    return next((a for a in got if a["id"] == "bluemap"), {})


def _rows272(ids):
    meta = {"kind": "bluemap", "image": _ad272.BLUEMAP_IMAGE, "mc_version": "1.21.4", "port": 21008,
            "eula_accepted_by": "admin", "eula_accepted_at": "2026-11-19T10:00:00+00:00"}
    _host272(_probe_out272(meta=meta, now="1.21.5"))
    row = _bluemap_row272(ids["mc"])
    eq("list: BlueMap's row says who accepted Mojang's EULA, the version, the disk, and offers Update for the "
       "game's new version", [row.get(k) for k in ("eula_by", "mc_version", "disk_kb", "update", "mc_version_now", "port")],
       ["admin", "1.21.4", 4096, "game", "1.21.5", 21008])
    _host272(_probe_out272(meta=meta))
    eq("list: the same version offers no update", _bluemap_row272(ids["mc"]).get("update"), "")
    eq("offered: vanilla and Paper, not the proxies or Bedrock",
       [("bluemap" in _ad272.offered(g)) for g in ("mc", "pmc", "vpmc", "wmc", "mcb")], [True, True, False, False, False])
    _host272(_probe_out272())
    fresh = _bluemap_row272(ids["pmc"])
    eq("list: an uninstalled BlueMap carries the EULA's link for the install", (fresh.get("installed"), fresh.get("eula_url")),
       (False, _bm272.EULA_URL))
    return meta


def _update272(ids, meta):
    calls = _host272(_probe_out272(meta=dict(meta, image="ghcr.io/bluemap-minecraft/bluemap@sha256:" + "0" * 64),
                                   version="1.21.5"))
    manifest, detail = _mojang272("1.21.5")
    _p9_patch(_bm272, "_get", _getter272(manifest, detail))
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/update" % ids["mc"])
    _p9_drain()
    sh, _stdin = _writes272(calls)
    rec = _json272.loads(next((t for p, t in _puts272(sh).items() if p.endswith("/addon.json")), "{}"))
    unit = next((t for p, t in _puts272(sh).items() if p.endswith(".container")), "")
    eq("update: the new version's client file, the unit with it, the page written again after a new image, the "
       "record moved on; the EULA's record and the configs are kept",
       (r.status_code, "minecraft-client-1.21.5.jar" in sh, "Exec=-r -u -w -v 1.21.5" in unit, "web/index.html" in sh,
        rec.get("mc_version"), rec.get("eula_accepted_by"), rec.get("image"), "core.conf" in sh, _p9_audit("addon_update").success),
       (202, True, True, True, "1.21.5", "admin", _ad272.BLUEMAP_IMAGE, False, True))


def _update_refused272(ids, meta):
    calls = _host272(_probe_out272(dirs=("logs",), meta=meta))
    _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/update" % ids["mc"])
    _p9_drain()
    row = _p9_audit("addon_update")
    eq("update refused (no world folder): audited as not done, worded to try again (not to install again, which "
       "would mean Remove), nothing written", (row.success, "then try again" in row.detail, _writes272(calls)[0]),
       (False, True, ""))


def _tab272(ids):
    _host272(_probe_out272())
    _p9_quiet_lookups()
    page = _p9_client(P9_ADMIN).get("/server/%d/files" % ids["mc"]).get_data(as_text=True)
    check("tab: a Minecraft server's Files & Config page has the Add-ons tab", 'data-sfsub-btn="addons"' in page, "")


# ── 3. the card ───────────────────────────────────────────────────────────────────────────────────
_TAIL272 = """  const eula = els.filter(function (e) { return e.id === 'ad-eula-bluemap'; })[0];
  const link = els.filter(function (e) { return e.tagName === 'A'; })[0] || {};
  res.eula = eula ? eula.checked : null; res.link = [link.href, link.target, link.rel];
  if (cfg.install) {
    ctx.window.adInstall('bluemap');
    res.first = [posts.length, dialogs.length, fixed['ad-msg'].textContent];
    if (eula) eula.checked = true;
    ctx.window.adInstall('bluemap');
  }
"""


def _card272(row, install):
    node = _shutil272.which("node")
    if not node:
        return {"error": "node is not installed"}
    js = _HARNESS257.replace("confirmDialog: function (o) { dialogs.push(o.bodyText); }",
                             "confirmDialog: function (o) { dialogs.push(o.bodyText); o.onConfirm(); }")
    js = js.replace("  ctx.window.adRemove('b3');\n  ctx.window.adSettings('b3');\n", _TAIL272)
    js = js.replace("function walk(", "El.prototype.focus = function () {};\nfunction walk(")
    # The page's window.tf (i18n.js) fills {name} from its values; the harness has none.
    js = js.replace("ctx.window = ctx;", "ctx.window = ctx; ctx.tf = function (s, v) { return s.replace(/\\{(\\w+)\\}/g, "
                    "function (m, k) { return k in v ? String(v[k]) : m; }); };")
    path = os.path.join(_TMP272, "harness.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(js)
    cfg = {"src": os.path.join(_ROOT272, "panel", "static", "js", "server_addons.js"), "install": install,
           "data": {"success": True, "addons": [dict({"id": "bluemap", "name": "BlueMap", "version": "v5 x",
                                                      "legacy": False, "needs_database": False, "data_kept": False,
                                                      "geolocation_option": False, "eula_url": _bm272.EULA_URL,
                                                      "render_threads": 1, "update": "", "note": ""}, **row)],
                    "databases": []}}
    r = _sp272.run([node, path], input=_json272.dumps(cfg),  # nosec B603 - node on this part's harness
                   capture_output=True, text=True, timeout=120, check=False)
    try:
        return _json272.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _cards272():
    fresh = _card272({"installed": False, "state": ""}, True)
    first = fresh.get("first") or [None, None, ""]
    eq("card: Install posts nothing until Mojang's EULA is ticked (it says so), then asks and posts accept_eula",
       (fresh.get("eula"), first[:2], "Tick that you accept Mojang's EULA first" in first[2], fresh.get("posts"),
        ["BlueMap's image and Minecraft's client file" in d for d in fresh.get("dialogs") or []]),
       (False, [0, 0], True, [["/api/server/7/addons/bluemap/install", {"accept_eula": True}]], [True]))
    eq("card: the EULA's link opens Mojang's page in a new tab without an opener",
       fresh.get("link"), [_bm272.EULA_URL, "_blank", "noopener noreferrer"])
    done = _card272({"installed": True, "state": "active", "port": 21008, "eula_by": "admin272",
                     "eula_at": "2026-11-19T10:00:00+00:00", "mc_version": "1.21.4", "disk_kb": 3 * 1048576,
                     "update": "game", "mc_version_now": "1.21.5"}, False)
    text = done.get("text", "")
    eq("card: the installed row says who accepted the EULA, the version, the disk, the threads and the update",
       [x in text for x in ("accepted by admin272", "Minecraft 1.21.4", "3.0 GB", "render-thread-count",
                            "now runs Minecraft 1.21.5", "127.0.0.1:21008")], [True] * 6)


# ── 4. the text ───────────────────────────────────────────────────────────────────────────────────
def _said_module272():
    """The sentences addons_bluemap shows: its public string constants that read as a sentence."""
    said = set()
    for k, v in vars(_bm272).items():
        if k.isupper() and not k.startswith("_") and isinstance(v, str) and " " in v and not v.startswith("http"):
            said.add(v)
    return said | set(_bm272.AGAIN.values())


def _said_page272():
    """The BlueMap sentences in the card's script (T and TF) and the tab's template."""
    js = open(os.path.join(_ROOT272, "panel", "static", "js", "server_addons.js"), encoding="utf-8").read()
    words = ("BlueMap", "Mojang", "Minecraft", "Render threads", "Disk used")
    said = {m.replace("\\'", "'") for m in _re272.findall(r"\bTF?\('((?:[^'\\]|\\.)*)'", js)}
    html = open(os.path.join(_ROOT272, "panel", "templates", "_server_addons.html"), encoding="utf-8").read()
    said |= {m.strip() for m in _re272.findall(r"<li>([^<]+)</li>", html)}
    return {x for x in said if any(w in x for w in words)}


def _text272():
    said = _said_module272() | _said_page272() | {_ad272._FAIL_MARKS["ADDON_CLIENT_FAILED"]}
    missing = [(lang, x) for lang in ("es", "fr") for x in sorted(said) if x not in _i18n272.catalog(lang)]
    check("text: the check found BlueMap's sentences", len(said) >= 18, repr(len(said)))
    eq("text: every BlueMap sentence has a Spanish and a French translation", missing[:4], [])


def _fixture272():
    return {"mc": _p9_new_server(P9_HOST, "mcp272", "mc", 25565, name="p272-mc"),
            "pmc": _p9_new_server(P9_HOST, "pmcp272", "pmc", 25566, name="p272-pmc")}


def _drop272(ids):
    for sid in ids.values():
        with _ra272._JOBS_LOCK:
            _ra272._JOBS.pop((sid, "bluemap"), None)
        _p9_delete_server(sid)


try:
    _paper272 = _world272()
    _unit272(_paper272)
    _configs272(_paper272)
    _p9_arm(who="part272")
    _mojang_reads272()
    _p9_restore_all()
    _status272()
    _client_sh272()
    _cards272()
    _ids272 = _fixture272()
    try:
        for _step272 in (lambda ids: _no_eula272(ids["mc"]), lambda ids: _install272(ids["mc"]),
                         lambda ids: _install_refused272(ids["mc"]), lambda ids: _update272(ids, _rows272(ids)),
                         lambda ids: _update_refused272(ids, {"kind": "bluemap", "image": _ad272.BLUEMAP_IMAGE,
                                                             "mc_version": "1.21.4", "port": 21008}),
                         _tab272):
            _p9_restore_all()
            _p9_arm(who="part272")
            _step272(_ids272)
    finally:
        _p9_restore_all()
        _drop272(_ids272)
    _text272()
finally:
    _p9_restore_all()
check("part272: no check reached a real host", len(_P9_TRIPPED) == _trips272, repr(_P9_TRIPPED[_trips272:][:4]))
