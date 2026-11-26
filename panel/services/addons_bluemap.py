"""BlueMap, the add-on that draws a live 3D web map of a Minecraft Java world (services/addons.py runs it).

WHAT RUNS
    The CLI build BlueMap's author publishes as an image (ghcr.io/bluemap-minecraft/bluemap, its
    Dockerfile's `java -jar cli.jar`), pinned by digest (addons.BLUEMAP_IMAGE), started with
    `-r -u -w -v <version>`: render the maps, keep watching the world for changes, serve the web page,
    and use that Minecraft version's client file. One CLI jar reads worlds of Minecraft 1.13.2 to 26.3
    (the 5.29 release's notes), so the image needs no build per game version. Its folders: config/,
    web/ (the page and the rendered map) and data/ (render progress, the client file) in the add-on's
    folder; the world is mounted READ-ONLY.

THE WORLD (Minecraft Wiki "server.properties"; world_reset's notes on LinuxGSM's mcserver and pmcserver)
    The server runs in serverfiles and its world is the folder server.properties' level-name names
    (default `world`). Vanilla keeps the nether and the end inside it (DIM-1 and DIM1, or
    dimensions/minecraft/<name> in current releases); Paper and other Bukkit servers keep them beside it
    as <level-name>_nether and <level-name>_the_end, mounted too when they are there. BlueMap looks in
    both layouts by itself (MCAWorld.resolveDimensionFolder). The level-name must be a plain folder
    name here: it goes into the unit file, where `%` is a specifier and a blank could split a value.

MOJANG'S CLIENT FILE AND ITS LICENCE
    BlueMap textures the map from the Minecraft client jar of the world's version, which it may
    download only once core.conf's accept-download says the operator accepts Mojang's EULA. The panel
    never sets that silently: the install asks the admin to tick it, and refuses without it. The
    container cannot reach the internet (services/addons.py THE NETWORK), so the panel does the download
    for it: its own host reads Mojang's version list and that version's details from piston-meta
    (the detail checked against the list's SHA-1), and the game's host fetches the client jar from
    piston-data with curl and checks the SHA-1 Mojang publishes for it, as BlueMap itself would. BlueMap
    then runs with -v <version>: when it cannot reach Mojang it uses data/minecraft-client-<version>.jar
    (MinecraftVersion.load). OWASP's cheat sheets have no rule for a downloaded data file; this follows
    the Top 10's A08 advice: a trusted source over TLS and an integrity check before use.

THE VERSION, AND A GAME UPDATE
    The world's version is the one the server logged at its last start (serverfiles/logs/latest.log,
    "Starting minecraft server version X"). That log is replaced at each start and by a rotation, and a
    fresh one may not hold the line yet, so version_sh then reads the server jar's own version.json
    (Mojang's server jar and its bundler carry one, "id"), and last the newest rotated logs
    (logs/*.log.gz). LinuxGSM keeps no record of the version it installed that the panel could read.
    After the game is updated, the version read names a newer one than the add-on's record, and the
    card offers Update: the new client file, the unit with the new -v.

PRIVACY
    BlueMap's CLI has no connection to the game, so its map shows no players and no addresses. Its
    web server keeps no access log (webserver.conf has no log section), and its usage report to
    bluemap.bluecolored.de is off (metrics: false), though the container could not send it anyway.
"""
import json
import re
import shlex
import urllib.parse
import urllib.request
from collections import namedtuple

from panel.core import i18n
from panel.services import geoip as _geoip, world_reset as _wr

# Mojang's EULA, which accept-download stands for (BlueMap's core.conf names account.mojang.com's old
# address of it, which redirects here).
EULA_URL = "https://www.minecraft.net/eula"
# BlueMap's own default, and the most a host shared with the game should give a first render by default.
RENDER_THREADS = 1
# The page's port inside the container (BlueMap's default, webserver.conf).
WEB_PORT = 8100
# Mojang's hosts: the version list and details (piston-meta), the client jar (piston-data).
MANIFEST = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
_META_HOST = "piston-meta.mojang.com"
_DETAIL_RE = re.compile(r"https://piston-meta\.mojang\.com/v1/packages/([0-9a-f]{40})/[A-Za-z0-9._-]{1,64}\.json")
_CLIENT_RE = re.compile(r"https://piston-data\.mojang\.com/v1/objects/([0-9a-f]{40})/client\.jar")
MANIFEST_CAP = 8 * 1024 * 1024
DETAIL_CAP = 1024 * 1024
# A client jar is about 30 MB (26.x); curl stops past this.
CLIENT_CAP = 512 * 1024 * 1024
TIMEOUT = 60
_UA = "linuxgsm-panel (BlueMap add-on)"
# A Minecraft version id as the server logs it (1.21.4, 26.1, 25w14a, 1.20-pre1): plain, so it can go on
# BlueMap's command line in the unit and into a file name.
_VERSION_RE = re.compile(r"[0-9][0-9A-Za-z._-]{0,31}")
# A level-name the unit can carry: one plain folder name.
_LEVEL_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]{0,63}")
_PROPS = "serverfiles/server.properties"
_LATEST_LOG = "serverfiles/logs/latest.log"
_STARTING = "Starting minecraft server version "
# The server jars version_sh reads version.json from, in this order: LinuxGSM's Minecraft (vanilla) jar,
# the name Mojang's download has, then any other jar in serverfiles (Paper, Purpur, Fabric's launcher).
_JARS = ("serverfiles/minecraft_server.jar", "serverfiles/server.jar", "serverfiles/*.jar")
# The rotated logs read last (newest first), at most this many: each is decompressed until its first line.
_ROTATED_MAX = 5
# version.json out of a jar, by unzip, else Python's zipfile (a host may have either).
_ZIP_READ = ("import sys,zipfile; "
             "sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read('version.json')[:4000].decode('utf-8','replace'))")

NO_WORLD = ("Couldn't find the world folder ({world}). Start the Minecraft server once so it creates its world, "
            "then install again.")
NO_VERSION = ("Couldn't read the world's Minecraft version from the server's logs (serverfiles/logs) or its server "
              "jar. Start the Minecraft server once, then install again.")
BAD_LEVEL = ("BlueMap can't use this world's name (level-name in server.properties: {why}). Use letters, digits and "
             ". _ + - only, then install again.")
BAD_LEVEL_CHARS = "it holds a character other than letters, digits and . _ + -"
# The same steps for an Update of an installed BlueMap, where "install again" would mean Remove, which deletes
# the rendered map: the update is simply tried again.
AGAIN = {
    NO_WORLD: ("Couldn't find the world folder ({world}). Start the Minecraft server once so it creates its world, "
               "then try again."),
    NO_VERSION: ("Couldn't read the world's Minecraft version from the server's logs (serverfiles/logs) or its "
                 "server jar. Start the Minecraft server once, then try again."),
    BAD_LEVEL: ("BlueMap can't use this world's name (level-name in server.properties: {why}). Use letters, digits "
                "and . _ + - only, then try again."),
}
NO_EULA = ("BlueMap needs Minecraft's client file from Mojang to draw the map. Tick that you accept Mojang's EULA, then "
           "install again.")
NO_MOJANG = "Couldn't read Mojang's version list for Minecraft {version}. Try again later."
NOT_AT_MOJANG = "Mojang's version list has no Minecraft {version}, so BlueMap has no client file for it."

# What the unit needs from the probe: its world mounts (Volume= values) and the Minecraft version.
World = namedtuple("World", "mounts version")


# ── reading the host ─────────────────────────────────────────────────────────────────────────────
def world_sh():
    """The probe's lines for BlueMap: props.b64= (server.properties' level-name lines), dirs.b64=, mcver=.

    props.b64 holds only the lines that mention "level" (server.properties also holds the RCON password);
    a level-name continued on a next line then ends in a backslash, which level_name refuses. dirs.b64
    is the names of serverfiles' folders (the world and a Bukkit server's _nether/_the_end); mcver the
    world's Minecraft version (version_sh).
    """
    return ('echo "props.b64=$(grep -ai level %s 2>/dev/null | head -c 4000 | base64 -w0)"; '
            'echo "dirs.b64=$(find serverfiles -mindepth 1 -maxdepth 1 -type d -printf "%%f\\n" 2>/dev/null '
            '| head -c 16000 | base64 -w0)"; %s'
            % (shlex.quote(_PROPS), version_sh()))


def version_sh(key="mcver"):
    """Shell printing `<key>=` and the world's Minecraft version ("" when none could be read).

    In order: the line the server logged at its last start (latest.log); the server jar's version.json
    "id" (_JARS; unzip, else python3, 5 seconds each); the newest rotated logs (_ROTATED_MAX). Every read
    is the game account's own file, bounded, and the caller keeps only a plain version (mc_version).
    """
    line = shlex.quote(_STARTING + "[0-9A-Za-z._-]+")
    jar = ('{ timeout 5 unzip -p "$j" version.json 2>/dev/null || timeout 5 python3 -c %s "$j" 2>/dev/null; } '
           '| head -c 4000 | grep -m1 -oE \'"id"[[:space:]]*:[[:space:]]*"[^"]{1,32}"\' | sed -E \'s/.*"([^"]*)"$/\\1/\''
           % shlex.quote(_ZIP_READ))
    rotated = ("ls -t serverfiles/logs/ 2>/dev/null | grep -E '^[0-9A-Za-z._-]+\\.log\\.gz$' | head -n %d"
               % _ROTATED_MAX)
    return ('_mcv=$(grep -m1 -aoE %s %s 2>/dev/null | head -n 1 | sed "s/.* //"); '
            '[ -n "$_mcv" ] || for j in %s; do [ -f "$j" ] || continue; _mcv=$(%s); [ -n "$_mcv" ] && break; done; '
            '[ -n "$_mcv" ] || for g in $(%s); do _mcv=$(timeout 5 zcat -- "serverfiles/logs/$g" 2>/dev/null '
            '| grep -m1 -aoE %s | sed "s/.* //"); [ -n "$_mcv" ] && break; done; echo "%s=$_mcv"; '
            % (line, shlex.quote(_LATEST_LOG), " ".join(_JARS), jar, rotated, line, key))


def mc_version(text):
    """A version id the probe read, if it is plain (_VERSION_RE), else ""."""
    text = (text or "").strip()
    return text if _VERSION_RE.fullmatch(text) else ""


def parse_world(kv, unb64):
    """What the probe found: {level, why, nether, end, version} (why: an English sentence, "" when usable).

    `kv` is the probe's key=value lines, `unb64` addons._unb64. The level-name is read as Java reads
    server.properties (world_reset.level_name: the last line wins, `world` when none), and must be a
    plain folder name; the world folder must be there; the version must be plain.
    """
    dirs = set(unb64(kv.get("dirs.b64", "")).splitlines())
    name, why = _wr.level_name(unb64(kv.get("props.b64", "")))
    got = {"level": "", "why": "", "nether": False, "end": False, "version": mc_version(kv.get("mcver"))}
    if name is None or not _LEVEL_RE.fullmatch(name):
        got["why"] = i18n.Sentence(BAD_LEVEL, why=why or i18n.Sentence(BAD_LEVEL_CHARS))
        return got
    got.update(level=name, nether=name + "_nether" in dirs, end=name + "_the_end" in dirs)
    if name not in dirs:
        got["why"] = i18n.Sentence(NO_WORLD, world="serverfiles/" + name)
    elif not got["version"]:
        got["why"] = NO_VERSION
    return got


def again(why):
    """A world refusal (parse_world's) worded for an Update: "then try again" instead of "then install again"."""
    if isinstance(why, i18n.Sentence) and why.template in AGAIN:
        return i18n.Sentence(AGAIN[why.template], **why.vals)
    return AGAIN.get(why, why)


def world(user, found):
    """The unit's World: each world folder read-only at /app/<world|world_nether|world_the_end>, and the version."""
    base = "/home/%s/serverfiles/%s" % (user, found["level"])
    mounts = ["%s:/app/world:ro" % base]
    mounts += ["%s_nether:/app/world_nether:ro" % base] if found["nether"] else []
    mounts += ["%s_the_end:/app/world_the_end:ro" % base] if found["end"] else []
    return World(tuple(mounts), found["version"])


# ── what the install writes ──────────────────────────────────────────────────────────────────────
def core_conf(who, when):
    """The core.conf BlueMap reads: the EULA accepted (by `who`, at `when`), one render thread, no usage report or debug log."""
    return ("# Written by linuxgsm-panel at the BlueMap add-on's install. BlueMap reads it at each start; edit it, then\n"
            "# Stop and Start the add-on on its card.\n"
            "# Mojang's EULA (%s) was accepted on the add-on's install by %s at %s, so BlueMap may\n"
            "# use Minecraft's client file (the panel downloads it: the container reaches no network).\n"
            "accept-download: true\n"
            "data: \"data\"\n"
            "# Render threads: BlueMap's default. A higher value renders faster but takes more of the host's CPU,\n"
            "# which the game shares; keep it at or below the host's cores.\n"
            "render-thread-count: %d\n"
            "update-cooldown: 60\n"
            "full-update-interval: 1440\n"
            "region-file-check-interval: 5\n"
            "scan-for-mod-resources: true\n"
            "metrics: false\n" % (EULA_URL, who, when, RENDER_THREADS))


_HEADERS = ('additional-headers: {\n'
            '  "Cache-Control": "public, max-age=86400, stale-if-error=604800"\n'
            '  "X-Content-Type-Options": "nosniff"\n'
            '  "Referrer-Policy": "no-referrer"\n'
            '  "X-Frame-Options": "DENY"\n'
            '  "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), '
            'microphone=(), payment=(), usb=()"\n'
            '}\n')

# Each map: (id, its world folder in the container when the server keeps one beside the world, the dimension,
# the name, sorting, sky colour, void colour, ambient light, remove-caves-below-y), BlueMap's own templates'.
_MAPS = (("overworld", "", "minecraft:overworld", "Overworld", 0, "#7dabff", "#000000", "0.1", "55"),
         ("nether", "world_nether", "minecraft:the_nether", "Nether", 100, "#290000", "#150000", "0.6", "-10000"),
         ("end", "world_the_end", "minecraft:the_end", "End", 200, "#080010", "#080010", "0.6", "-10000"))
# The nether's ceiling, cut away as BlueMap's own nether template does.
_NETHER_MASK = "render-mask: [\n  {\n    subtract: true\n    min-y: 90\n    max-y: 127\n  }\n]\n"


def config_files(found):
    """The config files beside core.conf ({path in the add-on's folder: text}): the web server and the three maps.

    The web server listens on every address of the container's own network (the host publishes it on
    127.0.0.1), keeps no access log, and sends the security headers BlueMap's template lists. A map's
    world is the folder beside the world when the server keeps one (Bukkit), else the world itself.
    """
    files = {"config/webserver.conf": ("# Written by linuxgsm-panel. The host publishes this page on 127.0.0.1 only.\n"
                                       "enabled: true\nwebroot: \"web\"\nip: \"0.0.0.0\"\nport: %d\nsse-enabled: true\n"
                                       % WEB_PORT) + _HEADERS}
    beside = {"world_nether": found["nether"], "world_the_end": found["end"]}
    for mid, folder, dim, name, sort, sky, void, ambient, caves in _MAPS:
        files["config/maps/%s.conf" % mid] = (
            "# Written by linuxgsm-panel. Changes here need a re-render (see BlueMap's documentation).\n"
            "world: \"/app/%s\"\ndimension: \"%s\"\nname: \"%s\"\nsorting: %d\nsky-color: \"%s\"\nvoid-color: \"%s\"\n"
            "ambient-light: %s\nremove-caves-below-y: %s\nstorage: \"file\"\n%s"
            % (folder if beside.get(folder) else "world", dim, name, sort, sky, void, ambient, caves,
               _NETHER_MASK if mid == "nether" else ""))
    return files


def client_file(version):
    """The client jar's file name in the add-on's data folder, as BlueMap looks for it."""
    return "minecraft-client-%s.jar" % version


def client_sh(addon_dir, version, url, sha1, fresh_webapp=False, tidy=True):
    """Shell, as the account: the client jar for `version` into data/, checked against `sha1`; other versions' go.

    Kept when the file there already has that SHA-1. Downloaded beside and renamed once it matches, so
    BlueMap never reads half a file. Prints ADDON_CLIENT_FAILED and exits 27 when it can't. Then, with
    `tidy`, client_tidy_sh. An update passes tidy=False and runs that tidy-up after the new image is
    there instead: the old jar (and page) are what the running BlueMap still uses if the pull fails.
    """
    f = shlex.quote("%s/data/%s" % (addon_dir, client_file(version)))
    return ("{ [ \"$(sha1sum %s 2>/dev/null | cut -d' ' -f1)\" = %s ] || { "
            "curl -fsS --proto =https --tlsv1.2 --max-time 900 --max-filesize %d -o %s.part %s "
            "&& [ \"$(sha1sum %s.part | cut -d' ' -f1)\" = %s ] && mv -f -T %s.part %s; }; } "
            "|| { rm -f %s.part; echo ADDON_CLIENT_FAILED; exit 27; }; %s"
            % (f, sha1, CLIENT_CAP, f, shlex.quote(url), f, sha1, f, f, f,
               client_tidy_sh(addon_dir, version, fresh_webapp) if tidy else ""))


def client_tidy_sh(addon_dir, version, fresh_webapp=False):
    """Shell, as the account: other versions' client jars removed; with `fresh_webapp`, web/index.html too.

    The page goes so a new BlueMap writes its own again (its release notes ask for that on an update).
    """
    d = shlex.quote(addon_dir + "/data")
    f = shlex.quote("%s/data/%s" % (addon_dir, client_file(version)))
    page = "rm -f %s; " % shlex.quote(addon_dir + "/web/index.html") if fresh_webapp else ""
    return "for j in %s/minecraft-client-*.jar; do [ \"$j\" = %s ] || rm -f -- \"$j\"; done; %s" % (d, f, page)


# ── Mojang's version list (read by the panel's host) ─────────────────────────────────────────────
def _allowed(url):
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return (p.scheme == "https" and p.hostname == _META_HOST and p.port in (None, 443)
            and not p.username and not p.password)


class _AllowedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an https URL on piston-meta."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse (None) a redirect off piston-meta; follow one on it."""
        if not _allowed(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url, cap):
    """GET `url` from piston-meta: the body's bytes, or None. Never raises."""
    if not _allowed(url):
        return None
    opener = urllib.request.build_opener(_AllowedRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with opener.open(req, timeout=TIMEOUT) as resp:  # nosec B310 - https on piston-meta only, checked above
            body = resp.read(cap + 1) if getattr(resp, "status", 200) == 200 else None
    except Exception:  # noqa: BLE001 - every failure is "could not be read"
        return None
    return body if body is not None and len(body) <= cap else None


def pick_version(manifest, version):
    """(detail URL, its SHA-1) for `version` from Mojang's version list (bytes), or None when it has none."""
    row = _version_row(manifest, version)
    if row is None:
        return None
    m = _DETAIL_RE.fullmatch(str(row.get("url") or ""))
    sha1 = str(row.get("sha1") or "")
    return (m.group(0), sha1) if m and re.fullmatch(r"[0-9a-f]{40}", sha1) else None


def _version_row(manifest, version):
    """The version list's entry (a dict) for `version`, or None (none, or not the list's shape)."""
    try:
        doc = json.loads(manifest)
    except ValueError:
        return None
    rows = doc.get("versions") if isinstance(doc, dict) else None
    return next((r for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict) and r.get("id") == version),
                None)


def pick_client(detail, sha1):
    """(client jar URL, its SHA-1) from a version's detail (bytes), once the detail matches `sha1`; else None.

    The URL must be piston-data's object address, which carries the file's own SHA-1, and that must be
    the one the detail gives for the client.
    """
    if _geoip.sha1_hex(detail) != sha1:     # Mojang publishes SHA-1 only; see geoip.sha1_hex on what it guards
        return None
    try:
        client = ((json.loads(detail).get("downloads") or {}).get("client") or {})
    except (ValueError, AttributeError):
        return None
    m = _CLIENT_RE.fullmatch(str(client.get("url") or "")) if isinstance(client, dict) else None
    return (m.group(0), m.group(1)) if m and m.group(1) == client.get("sha1") else None


def client_download(version):
    """(client jar URL, its SHA-1, "") for Minecraft `version`, or (None, None, why) with an i18n sentence."""
    manifest = _get(MANIFEST, MANIFEST_CAP)
    if manifest is None:
        return None, None, i18n.Sentence(NO_MOJANG, version=version)
    picked = pick_version(manifest, version)
    if picked is None:
        return None, None, i18n.Sentence(NOT_AT_MOJANG, version=version)
    detail = _get(picked[0], DETAIL_CAP)
    client = pick_client(detail, picked[1]) if detail is not None else None
    if client is None:
        return None, None, i18n.Sentence(NO_MOJANG, version=version)
    return client[0], client[1], ""
