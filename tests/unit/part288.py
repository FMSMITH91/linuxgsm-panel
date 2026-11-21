"""Part 288 of the unit suite: IW4MAdmin built on the host on a patched .NET runtime.

1. The pins: the catalog's IW4MAdmin image is built from panel/addon_images/iw4madmin (never pulled), named by
   its release and build id, with the three build arguments addons.py records; the Containerfile's ARG defaults
   are the same values; BlueMap is still pulled by digest.
2. The archive step: the source stage's download, run under sh with a stand-in curl and unzip, fetches the release
   archive by the tag's URL, and a tampered archive stops the build before anything in it is unpacked.
3. The image: the final stage installs nothing, runs as a user that is not root, starts the panel's entrypoint,
   which is readable, and keeps the release's defaults for the mounted folders.
4. The entrypoint, under sh over a throwaway /app: refuses to start without its settings, fills empty folders
   from the defaults, never overwrites the operator's files, then starts IW4MAdmin.
5. The routes: an install writes the build folder and builds the image before the unit; an add-on installed from
   the earlier published image is offered the update, which builds the new image, keeps the settings file (not
   written), removes the old image, records the new one and is audited.
6. Renovate: the release tag and its archive's sha256 come from a custom datasource over GitHub's releases API.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a recorder. Shells run
under sh in a throwaway folder; nothing reaches a host, a registry or GitHub.
"""
import hashlib as _hash288
import json as _json288
import os
import re as _re288
import shutil as _shutil288
import subprocess as _sp288  # nosec B404 - sh over this part's own throwaway files
import tempfile as _tf288

from unit.part01 import _root, check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_threading,
                         _P9Thread)
from panel.routes import addons as _ra288, addons_change as _ch288
from panel.services import addons as _ad288

_trips288 = len(_P9_TRIPPED)
_TMP288 = _tf288.mkdtemp(prefix="p288-")
_RC288 = "p288-rcon-" + "value"            # the game's RCON password in these checks
_OLD288 = "ghcr.io/raidmax/iw4madmin@sha256:72ccf1b33983cdc64071b77fca8acac49943093aa74d41ae35ffbb89d8b15a46"
_DIR288 = os.path.join(_root, "panel", "addon_images", "iw4madmin")
_PUT288 = _re288.compile(r"printf %s (\S+) \| base64 -d > (\S+)\.new")


def _read288(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _instructions288(text):
    """The Containerfile's instructions as [(stage index, KEYWORD, rest)], comments dropped, continuations joined."""
    out, stage, buf = [], -1, ""
    for line in text.splitlines():
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        more = line.rstrip().endswith("\\")
        buf += (line.rstrip()[:-1].strip() + " ") if more else line.strip()
        if more:
            continue
        word, _sp, rest = buf.partition(" ")
        stage += word.upper() == "FROM"
        out.append((stage, word.upper(), rest.strip()))
        buf = ""
    return out


def _text288(path):
    """A file's text, or "" when it is not there (a stand-in that never ran wrote no log)."""
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


_CF288 = _read288("panel", "addon_images", "iw4madmin", "Containerfile")
_INS288 = _instructions288(_CF288)


# ── 1. the pins ─────────────────────────────────────────────────────────────────────────────────
def _pins288():
    a = _ad288.CATALOG[_ad288.IW4MADMIN]
    sh = _ad288._image_sh(_ad288.IW4MADMIN, "/d")
    args = _re288.findall(r"--build-arg ([A-Z0-9_]+)=(\S+)", sh)
    eq("IW4MAdmin: built on the host from addon_images/iw4madmin, never pulled, tagged by its release and build id, "
       "with the base, release tag and archive sha256 addons.py records",
       (a["build"], a["image"].startswith("localhost/lgsm-addon-iw4madmin:%s-" % _ad288.IW4MADMIN_VERSION),
        "podman build" in sh and "podman pull" not in sh, "-t %s " % a["image"] in sh, args, a["version"]),
       ("iw4madmin", True, True, True, [("BASE_IMAGE", _ad288.IW4MADMIN_BASE), ("IW4MADMIN_TAG", _ad288.IW4MADMIN_TAG),
                                        ("IW4MADMIN_SHA256", _ad288.IW4MADMIN_SHA256)], "2026.2.4.1"))
    eq("IW4MAdmin: the base is ASP.NET Core 10 by digest, the release a tag whose archive is checked by sha256",
       [bool(_re288.fullmatch(r"mcr\.microsoft\.com/dotnet/aspnet@sha256:[0-9a-f]{64}", _ad288.IW4MADMIN_BASE)),
        bool(_re288.fullmatch(r"[0-9a-f]{64}", _ad288.IW4MADMIN_SHA256)), _ad288.IW4MADMIN_TAG],
       [True, True, "2026.2.4.1-prerelease"])
    defaults = dict(_re288.findall(r"(?m)^ARG ([A-Z0-9_]+)=(\S+)$", _CF288))
    eq("IW4MAdmin: the Containerfile's ARG defaults are addons.py's pins, so a build by hand is the panel's build",
       defaults, {"BASE_IMAGE": _ad288.IW4MADMIN_BASE, "IW4MADMIN_TAG": _ad288.IW4MADMIN_TAG,
                  "IW4MADMIN_SHA256": _ad288.IW4MADMIN_SHA256})
    eq("IW4MAdmin: its build files are the Containerfile and the entrypoint, read from the repository",
       _ad288.build_files(_ad288.IW4MADMIN), {"build/Containerfile": _CF288,
                                              "build/entrypoint.sh": _read288("panel", "addon_images", "iw4madmin",
                                                                              "entrypoint.sh")})
    bm = _ad288._image_sh(_ad288.BLUEMAP, "/d")
    check("IW4MAdmin (control): BlueMap is still pulled by its digest", "podman pull -q %s " % _ad288.BLUEMAP_IMAGE in bm,
          bm[:120])
    other = _ad288.build_id(_DIR288, _ad288.IW4MADMIN_BASE.split("@")[0] + "@sha256:" + "0" * 64,
                            _ad288.BUILD_FILES["iw4madmin"])
    now = _ad288.build_id(_DIR288, _ad288.IW4MADMIN_BASE, _ad288.BUILD_FILES["iw4madmin"])
    check("IW4MAdmin: another runtime digest is another image tag, so the card offers the new runtime as an update",
          other != now and a["image"].endswith("-" + now), a["image"])


# ── 2. the archive step ─────────────────────────────────────────────────────────────────────────
_STANDINS288 = r"""
curl() { out=""; url=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; -*) ;; *) url="$1";; esac; shift; done
  echo "curl $url" >> "$P288_LOG"; cp "$P288_ZIP" "$out"; }
unzip() { echo "unzip $*" >> "$P288_LOG"; mkdir -p app; }
"""


def _fetch_run288():
    """The source stage's RUN that downloads the archive (the one naming curl), as text."""
    runs = [r for s, w, r in _INS288 if s == 0 and w == "RUN" and "curl " in r and "apt-get" not in r]
    return runs[0] if len(runs) == 1 else ""


def _run_fetch288(name, data, sha):
    """The archive RUN under sh with stand-ins: (rc, the stand-ins' log)."""
    work = os.path.join(_TMP288, "fetch-" + name)
    os.makedirs(work, exist_ok=True)
    zipf, log = os.path.join(work, "src.zip"), os.path.join(work, "tools.log")
    with open(zipf, "wb") as fh:
        fh.write(data)
    sh = _STANDINS288 + "IW4MADMIN_TAG=%s\nIW4MADMIN_SHA256=%s\n%s\n" % (_ad288.IW4MADMIN_TAG, sha, _fetch_run288())
    r = _sp288.run(["sh", "-c", sh], cwd=work, capture_output=True, text=True, timeout=60, check=False,  # nosec B603 B607
                   env={"PATH": "/usr/bin:/bin", "P288_LOG": log, "P288_ZIP": zipf})
    return r.returncode, _text288(log)


def _fetch288():
    if not _fetch_run288() or _shutil288.which("sha256sum") is None:
        check("archive: the source stage has one download step and sha256sum is here to run it", False,
              repr(_fetch_run288()[:80]))
        return
    good = b"PK\x03\x04 the release archive p288"
    rc, log = _run_fetch288("good", good, _hash288.sha256(good).hexdigest())
    url = "https://github.com/RaidMax/IW4M-Admin/releases/download/2026.2.4.1-prerelease/IW4MAdmin-2026.2.4.1.zip"
    eq("archive: the release's archive is fetched by its tag's download URL and unpacked when its sha256 matches",
       (rc, log.splitlines()[:1], "unzip -q iw4madmin.zip -d app" in log), (0, ["curl " + url], True))
    rc, log = _run_fetch288("bad", good + b" tampered", _hash288.sha256(good).hexdigest())
    eq("archive: an archive whose sha256 is not the pinned one stops the build before anything in it is unpacked",
       (rc != 0, "curl " in log, "unzip" in log), (True, True, False))


# ── 3. the image ────────────────────────────────────────────────────────────────────────────────
def _final_stage288():
    """{KEYWORD: [its arguments]} of the Containerfile's last stage."""
    final = max(s for s, _w, _r in _INS288)
    out = {}
    for stage, word, rest in _INS288:
        if stage == final:
            out.setdefault(word, []).append(rest)
    return out


def _image288():
    last = _final_stage288()
    runs, users, entry, copies = (last.get(w, []) for w in ("RUN", "USER", "ENTRYPOINT", "COPY"))
    froms = [r for _s, w, r in _INS288 if w == "FROM"]
    eq("image: two stages on the pinned base; the final one installs nothing (curl and unzip stay in the first)",
       (froms, [r for r in runs if _re288.search(r"apt|curl|unzip|wget", r)]),
       (["${BASE_IMAGE} AS source", "${BASE_IMAGE}"], []))
    eq("image: it runs as a user that is not root, the panel's entrypoint, made readable after its 0600 copy",
       (users, entry, runs), (["$APP_UID"], ['["/bin/sh", "/app/entrypoint.sh"]'], ["chmod 0755 /app/entrypoint.sh"]))
    eq("image: the release's files, and its settings, plugins and translations kept as defaults for the mounted folders",
       copies, ["--from=source /src/app /app", "--from=source /src/app/Configuration /app_defaults/Configuration",
                "--from=source /src/app/Plugins /app_defaults/Plugins",
                "--from=source /src/app/Localization /app_defaults/Localization", "entrypoint.sh /app/entrypoint.sh"])
    eq("image: the folders the unit mounts are the image's own (/app/Configuration, Plugins, Localization, "
       "Database, Log and /data)", [at for _d, at in _ad288.CATALOG[_ad288.IW4MADMIN]["mounts"]],
       ["/app/Configuration", "/app/Plugins", "/app/Localization", "/app/Database", "/app/Log", "/data"])


# ── 4. the entrypoint ───────────────────────────────────────────────────────────────────────────
def _entry_run288(name, files):
    """The entrypoint under sh over a throwaway /app with `files` there: (rc, stderr, dotnet's log, the app dir)."""
    base = os.path.join(_TMP288, "entry-" + name)
    app, dflt, bindir = os.path.join(base, "app"), os.path.join(base, "defaults"), os.path.join(base, "bin")
    for d in ("Configuration", "Plugins", "Localization"):
        os.makedirs(os.path.join(app, d), exist_ok=True)
    os.makedirs(bindir, exist_ok=True)
    for rel, text in {"Configuration/LoggingConfiguration.json": "release logging\n", "Plugins/Stats.dll": "stats\n",
                      "Plugins/Welcome.dll": "welcome\n", "Localization/IW4MAdmin.en-US.json": "en\n"}.items():
        os.makedirs(os.path.dirname(os.path.join(dflt, rel)), exist_ok=True)
        with open(os.path.join(dflt, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    for rel, text in files.items():
        with open(os.path.join(app, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    for tool, text in (("dotnet", 'echo "dotnet $* in $(pwd)" >> "$P288_LOG"\n'), ("sleep", "exit 0\n")):
        path = os.path.join(bindir, tool)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n" + text)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in the part's own temp dir
    script = _read288("panel", "addon_images", "iw4madmin", "entrypoint.sh")
    script = script.replace("/app_defaults", dflt).replace("cd /app\n", "cd %s\n" % app)
    log = os.path.join(base, "dotnet.log")
    r = _sp288.run(["sh", "-c", script], capture_output=True, text=True, timeout=60, check=False,  # nosec B603 B607
                   env={"PATH": bindir + ":/usr/bin:/bin", "P288_LOG": log})
    return r.returncode, r.stderr, _text288(log), app


def _entry288():
    rc, err, ran, _app = _entry_run288("nosettings", {})
    eq("entrypoint: without its settings file it stops with a reason and IW4MAdmin is not started",
       (rc, "IW4MAdminSettings.json not found" in err, ran), (1, True, ""))
    rc, _err, ran, app = _entry_run288("fresh", {"Configuration/IW4MAdminSettings.json": "{}\n"})
    eq("entrypoint: empty folders get the release's defaults, then IW4MAdmin starts from /app",
       (rc, [os.path.exists(os.path.join(app, x))
             for x in ("Configuration/LoggingConfiguration.json", "Plugins/Stats.dll", "Localization/IW4MAdmin.en-US.json")],
        ran), (0, [True] * 3, "dotnet Lib/IW4MAdmin.dll in %s\n" % app))
    rc, _err, ran, app = _entry_run288("kept", {"Configuration/IW4MAdminSettings.json": "{\"mine\": 1}\n",
                                                "Configuration/LoggingConfiguration.json": "operator logging\n",
                                                "Plugins/Stats.dll": "operator stats\n"})
    logging = _text288(os.path.join(app, "Configuration", "LoggingConfiguration.json"))
    stats = _text288(os.path.join(app, "Plugins", "Stats.dll"))
    eq("entrypoint: the operator's settings and plugins already there are never overwritten",
       (rc, logging, stats, os.path.exists(os.path.join(app, "Plugins", "Welcome.dll")), bool(ran)),
       (0, "operator logging\n", "operator stats\n", False, True))


# ── 5. the routes ───────────────────────────────────────────────────────────────────────────────
def _probe288():
    return ("os=24.04\npodman=podman version 4.9.3\nuid=1004\ngid=1005\nlogdir=serverfiles/main\nrcon.b64=%s\n"
            "ports= 21003 21004 21005\n" % _ad288._b64('set rcon_password "%s"' % _RC288))


def _host288(meta):
    """Recorders for the host calls [(sh, stdin)]: the probe, a status read with `meta`, an install or update."""
    calls = []

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append((sh, stdin_text))
        if "podman build" in sh or "podman pull" in sh or "restart lgsm-addon-iw4madmin" in sh:
            return "ADDON_INSTALLED\n", "", 0
        status = ("installed=1\nmeta.iw4madmin=%s\nstate.iw4madmin=active\n" % _ad288._b64(_json288.dumps(meta))
                  if meta else "")
        return _probe288() + status, "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **_k: ("", "", 0))
    _p9_patch_sm("enrol_game_user", lambda server, user: None)
    for mod in (_ra288, _ch288):
        _p9_patch(mod, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ra288, "step_up_needed", lambda: False)
    _p9_patch(_ra288, "game_account_write_refusal", lambda remote, user, reading=False: None)
    return calls


def _puts288(sh):
    return {path: _ad288._unb64(b64) for b64, path in _PUT288.findall(sh)}


def _shell288(calls, *marks):
    """(the first recorded shell holding every one of `marks`, its stdin), or ("", None)."""
    return next((c for c in calls if all(m in c[0] for m in marks)), ("", None))


def _built288(puts):
    """{file name: text} of the build folder files a shell writes."""
    return {os.path.basename(p): t for p, t in puts.items() if "/panel-addons/iw4madmin/build/" in p}


def _record288(puts):
    """The addon.json a shell writes, parsed ({} when it writes none)."""
    return _json288.loads(next((t for p, t in puts.items() if p.endswith("/addon.json")), "{}"))


def _install288(sid):
    calls = _host288(None)
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    sh, stdin = _shell288(calls, "lgsm-addon-iw4madmin.container", "ADDON_INSTALLED")
    puts = _puts288(sh)
    eq("install (route): the build folder is written and the image built from it before the unit is written",
       (r.status_code, _built288(puts), "podman build" in sh and "podman pull" not in sh,
        0 <= sh.find("podman build") < sh.find("lgsm-addon-iw4madmin.container.new")),
       (202, {"Containerfile": _CF288, "entrypoint.sh": _read288("panel", "addon_images", "iw4madmin", "entrypoint.sh")},
        True, True))
    rec = _record288(puts)
    eq("install (route): the record names the built image and its release, the settings go on stdin, audited",
       (rec.get("image"), rec.get("version"), '"DatabaseProvider": "sqlite"' in (stdin or ""), _RC288 in sh,
        _p9_audit("addon_install").success),
       (_ad288.CATALOG["iw4madmin"]["image"], "2026.2.4.1", True, False, True))


def _update288(sid):
    meta = {"kind": "iw4madmin", "image": _OLD288, "version": "latest 72ccf1b33983", "port": 21003, "game_port": 28960}
    calls = _host288(meta)
    rows = _p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid).get_json(silent=True) or {}
    row = next((x for x in rows.get("addons") or [] if x.get("id") == "iw4madmin"), {})
    eq("update (route): an IW4MAdmin installed from the published image is offered the built one, named by release",
       (row.get("update"), row.get("version"), row.get("version_new")), ("image", "latest 72ccf1b33983", "2026.2.4.1"))
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/update" % sid, json={})
    _p9_drain()
    sh, stdin = _shell288(calls, "restart lgsm-addon-iw4madmin")
    puts = _puts288(sh)
    rec = _record288(puts)
    wiped = _re288.search(r"\brm -[a-z]*r[a-z]* [^;|&]*panel-addons/iw4madmin", sh) is not None
    eq("update (route): it builds the new image from the build folder, records it, removes the old image, and leaves "
       "the settings file and the database alone, audited",
       (r.status_code, "podman build" in sh and "-t %s " % _ad288.CATALOG["iw4madmin"]["image"] in sh,
        sorted(_built288(puts)), (rec.get("image"), rec.get("version")),
        "podman rmi %s" % _OLD288 in sh, "IW4MAdminSettings.json" in sh, stdin, wiped, _p9_audit("addon_update").success),
       (202, True, ["Containerfile", "entrypoint.sh"], (_ad288.CATALOG["iw4madmin"]["image"], "2026.2.4.1"), True,
        False, None, False, True))


# ── 6. Renovate ─────────────────────────────────────────────────────────────────────────────────
def _release_hits288(mgr):
    """[(file, tag, sha256)] the managers `mgr` match in addons.py and the IW4MAdmin Containerfile (JS regexes as Python's)."""
    found = []
    for pat in [p for m in mgr for p in m.get("matchStrings") or []]:
        rx = _re288.compile(_re288.sub(r"\(\?<(?=[A-Za-z])", "(?P<", pat))
        for path in ("panel/services/addons.py", "panel/addon_images/iw4madmin/Containerfile"):
            found += [(path, x.group("currentValue"), x.group("currentDigest")) for x in rx.finditer(_read288(path))]
    return found


def _renovate288():
    cfg = _json288.loads(_read288(".github", "renovate.json"))
    ds = (cfg.get("customDatasources") or {}).get("iw4madmin-release") or {}
    mgr = [m for m in cfg.get("customManagers") or [] if m.get("datasourceTemplate") == "custom.iw4madmin-release"]
    found = _release_hits288(mgr)
    pin = (_ad288.IW4MADMIN_TAG, _ad288.IW4MADMIN_SHA256)
    eq("renovate: the IW4MAdmin release and its archive's sha256 are matched once each in addons.py and the "
       "Containerfile, from a custom datasource over RaidMax/IW4M-Admin's releases that keeps each archive's sha256",
       (sorted(found), len(mgr), ds.get("defaultRegistryUrlTemplate", "").startswith(
           "https://api.github.com/repos/RaidMax/IW4M-Admin/releases"),
        ["IW4MAdmin-[0-9.]+" in t and '"digest": $d' in t and "sha256:" in t for t in ds.get("transformTemplates") or []]),
       (sorted([("panel/addon_images/iw4madmin/Containerfile",) + pin, ("panel/services/addons.py",) + pin]), 1, True,
        [True]))


# ── run ─────────────────────────────────────────────────────────────────────────────────────────
for _step288 in (_pins288, _fetch288, _image288, _renovate288):
    _step288()
if _shutil288.which("sh") is None:
    skip("entrypoint: sh present to run IW4MAdmin's start script", "no sh on this runner")
else:
    _entry288()
_sid288 = _p9_new_server(P9_HOST, "cod4p288", "cod4", 28960, name="p288-cod4")
try:
    for _route288 in (_install288, _update288):
        _p9_restore_all()
        _p9_arm(who="part288")
        _route288(_sid288)
finally:
    _p9_restore_all()
    _p9_delete_server(_sid288)
check("part288: no check reached a real host", len(_P9_TRIPPED) == _trips288, repr(_P9_TRIPPED[_trips288:][:4]))
_shutil288.rmtree(_TMP288, ignore_errors=True)
