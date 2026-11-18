"""Add-ons: admin tools that run beside a game server, each in a rootless Podman container.

WHAT RUNS WHERE
    Each add-on is a container of the game server's OWN account, run by Podman in rootless mode: no
    root daemon, no Docker socket, and the container's root is that account (its other users map
    onto the account's subordinate ids). The account's user manager starts it, from a Quadlet unit
    in ~/.config/containers/systemd/, so it comes back at boot. Root is needed twice, through the
    helper's verbs: installing Podman (`apt-install podman uidmap passt`) and readying the account
    (`addon-account-prepare`: subordinate ids and lingering). Everything else runs as the account.

THE CONTAINER (OWASP Docker Security Cheat Sheet)
    Rootless (rule 11), no added capability and every default one dropped (rule 3), no new
    privileges (rule 4), a read-only root filesystem with tmpfs where it writes (rule 8), a memory
    and process cap and a restart limit (rule 7), the image pinned (rule 13: by digest, or built
    here from a pinned commit with hashed dependencies). The game's log folder is mounted read-only.

THE NETWORK (pasta(1), podman-run(1); the cheat sheet has no rule for a container's outbound traffic)
    The container has its own network namespace, and reaches only what network() forwards to the
    host's loopback: the game's RCON port (UDP) and, for an add-on with a database, that database
    (TCP; a database on another machine through a relay on this host, see relays()). Its web page,
    if it has one, is published on 127.0.0.1 only. Nothing else:
      - where pasta has --splice-only (passt 2026_01_20 and later: Ubuntu 26.04), the namespace has
        no interface but loopback, so the forwards are ALL it can reach;
      - where it has not (Ubuntu 24.04's passt 2024_02_20), its outbound connections are bound to
        127.0.0.1 (-o) and IPv6 is off (-4): the kernel refuses a loopback source towards another
        machine, so the internet, the tailnet and the LAN are out of reach. A service listening on
        one of THIS host's own other addresses (its Tailscale address, say) is still reachable:
        pasta has no option that closes that on this release.

THE ADD-ONS
    IW4MAdmin (cod4, codwaw): the image RaidMax's own release workflow builds and pushes to
    ghcr.io/raidmax/iw4madmin (its build_application.yml), pinned by digest. Its settings are
    written by the panel before the first start, so its interactive first-run setup never runs: one
    server (this one, on 127.0.0.1), the RCON password read from the game's config, the game log,
    and its built-in SQLite database in its own folder (its MySQL migrations fail on MariaDB). The
    two plugin questions its first start would ask are answered in their own files.
    B3 (cod, coduo, cod2): legacy, opt-in. Built on the host from addon_images/b3 (a Containerfile:
    FMSMITH91/big-brother-bot at one commit, its dependencies by hash), with one of this server's
    databases from the Databases tab (never one another add-on uses). Its geolocation, which sends
    each player's IP address to ipwho.is and ipapi.co, is off unless chosen at install.

The host keeps the state: ~/panel-addons/<id>/addon.json says what the panel installed. Nothing is
installed until someone with Manage add-ons installs an add-on.
"""
import base64
import json
import os
import re
import shlex

# ── the catalog ─────────────────────────────────────────────────────────────────────────────────
IW4MADMIN = "iw4madmin"
B3 = "b3"
# FMSMITH91/big-brother-bot master on 2026-11-15 (the merge of its PR #17): the B3 the add-on builds.
B3_COMMIT = "4ef524d9e991d94a685290d6b6c6a5cf023e3218"
# python:3.12-slim (Debian 13) on 2026-11-18, by its multi-arch index digest: the build's base.
B3_BASE = "docker.io/library/python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
CATALOG = {
    IW4MADMIN: {
        "name": "IW4MAdmin",
        # RaidMax/IW4M-Admin release 2026.2.4.1 (prerelease channel), the `latest` tag on
        # 2026-11-18: org.opencontainers.image.revision 80bf102b, linux/amd64.
        "image": "ghcr.io/raidmax/iw4madmin@sha256:72ccf1b33983cdc64071b77fca8acac49943093aa74d41ae35ffbb89d8b15a46",
        "version": "2026.2.4.1",
        "source": "https://github.com/RaidMax/IW4M-Admin",
        # game type -> the parser IW4MAdmin matches by name (its Plugins/ScriptPlugins/Parser*.cs).
        # LinuxGSM's cod4server runs CoD4x (executable cod4x18_dedrun).
        "games": {"cod4": "CoD4x Parser", "codwaw": "Call of Duty 5: World at War Parser"},
        # (folder in the add-on's home, where the container sees it): its image's mounts (its
        # Dockerfile and entrypoint.sh), and /data for HOME.
        "mounts": (("Configuration", "/app/Configuration"), ("Plugins", "/app/Plugins"),
                   ("Localization", "/app/Localization"), ("Database", "/app/Database"),
                   ("Log", "/app/Log"), ("Data", "/data")),
        "env": ("PUID=0", "PGID=0", "TZ=Etc/UTC", "HOME=/data"),
        # The file holding the secrets (written from stdin), relative to the add-on's folder.
        "settings": "Configuration/IW4MAdminSettings.json",
        "web_port": 1624,
        # It stops gracefully on SIGINT (Application/Main.cs: Console.CancelKeyPress); on SIGTERM
        # its synchronous ProcessExit shutdown outlasted Podman's wait and it was killed (137).
        "stop_signal": "SIGINT",
        "database": False, "build": None, "legacy": False, "log_file": None,
        "data_kept": False,
    },
    B3: {
        "name": "B3 (Big Brother Bot)",
        "image": "localhost/lgsm-addon-b3:" + B3_COMMIT[:12],
        "version": "2.0.0dev " + B3_COMMIT[:8],
        "source": "https://github.com/FMSMITH91/big-brother-bot",
        # game type -> B3's parser. United Offensive is CoD1's engine and log: B3's cod parser.
        "games": {"cod": "cod", "coduo": "cod", "cod2": "cod2"},
        "mounts": (("Data", "/data"),),
        "env": ("TZ=Etc/UTC", "HOME=/data"),
        "settings": "Data/b3.ini",
        "web_port": None,
        # B3 shuts down on SIGTERM and exits 0 (b3/__init__.py term_signal_handler).
        "stop_signal": "SIGTERM",
        "database": True, "build": "b3", "legacy": True, "log_file": "Data/b3.log",
        "data_kept": True,
    },
}
ADDON_IDS = tuple(sorted(CATALOG))

# Where an add-on lives in the account's home, and the name of its unit and container.
HOME_DIR = "panel-addons"
QUADLET_DIR = ".config/containers/systemd"
USER_UNIT_DIR = ".config/systemd/user"
UNIT_PREFIX = "lgsm-addon-"
META_FILE = "addon.json"
BUILD_DIR = "build"
# The packages the runtime needs on Ubuntu (all in universe): Podman, newuidmap/newgidmap for the
# user namespace, and pasta for the container's own network. Ubuntu 24.04 ships Podman 4.9 (Quadlet
# and pasta), 26.04 ships 5.7; 22.04's 3.4 has neither, so it is refused.
PACKAGES = ("podman", "uidmap", "passt")
MIN_PODMAN = (4, 9)
MIN_UBUNTU = (24, 4)
# The container's caps: its memory, processes, how often systemd restarts it, and how long a stop
# waits for it before Podman kills it.
MEMORY = "1g"
PIDS = 512
RESTART_BURST = 5
RESTART_WINDOW = 600
STOP_TIMEOUT = 30
# After the first start, how long the install watches the add-on before calling it running. On the
# test box IW4MAdmin died 10 s after a start that systemd had reported done (and exited 0, so no
# restart showed it): three times that.
SETTLE_SECONDS = 30
# The longest the install's pull or build and first start may take, and a status or action read.
INSTALL_TIMEOUT = 1200
ACTION_TIMEOUT = 120
LOG_LINES = 200
LOG_BYTES = 60000
TAIL_LINES = 15
# Host ports: an add-on's page and its relays take the first free ones from PORT_BASE + server id.
PORT_BASE = 21000
_PORT_TRIES = 40
# systemd's TCP relay (systemd-socket-proxyd(8)), run as the account for a relay() it needs.
SOCKET_PROXYD = "/usr/lib/systemd/systemd-socket-proxyd"
# The services B3's geolocation asks (b3/plugins/geolocation/geolocators.py), each on its own
# loopback address inside the container, relayed to HTTPS on the internet.
B3_GEOLOCATORS = (("ipwho.is", "127.0.0.2"), ("ipapi.co", "127.0.0.3"))
# The plugins a B3 install turns on (the distribution's own list, less adv: it reads an RSS feed
# from the internet; censor: it punishes words on its own; punkbuster: off on these games).
B3_PLUGINS = ("admin", "cmdmanager", "pingwatch", "pluginmanager", "spamcontrol", "stats", "status", "tk",
              "welcome")
# Geolocation's, when chosen: the lookup itself and the location plugin (!locate, join message).
B3_GEO_PLUGINS = ("geolocation", "location")
# A plugin with no settings file of its own (b3.ini names it with an empty value).
_B3_NO_FILE = ("geolocation",)
# The config folder a game's RCON password is read from, by game type (LinuxGSM's servercfgdir:
# serverfiles/main, serverfiles/uo for United Offensive).
_CFG_DIR = {"coduo": "uo"}

# What the host prints, read by the parsers below.
_MARK_INSTALLED = "ADDON_INSTALLED"
_MARK_REMOVED = "ADDON_REMOVED"
_FAIL_MARKS = {
    "ADDON_NO_USER_MANAGER": "The account's user manager didn't start, so the add-on can't run as it.",
    "ADDON_PULL_FAILED": "Couldn't download the add-on's image. Check that this host can reach its registry.",
    "ADDON_BUILD_FAILED": "Couldn't build the add-on's image on this host. Its log says why.",
    "ADDON_START_FAILED": "The add-on was installed but didn't start. Its log says why.",
    "ADDON_DIED": "The add-on was installed but stopped again within 30 seconds, so it was left stopped. "
                  "Its last log lines are below.",
    "ADDON_WRITE_FAILED": "Couldn't write the add-on's files in the server's home folder.",
}
_B3_RCON_REFUSAL = ("B3 can't use this RCON password: it has a space at either end, or a space before a ';'. "
                    "Change it, then install again.")
_RCON_RE = re.compile(r'^[ \t]*seta?[ \t]+rcon_?password[ \t]+(?:"([^"\r\n]*)"|(\S+))', re.I | re.M)
_KV_RE = re.compile(r"([a-z][a-z0-9_.]{0,40})=(.*)")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)")
_STATES = ("active", "activating", "deactivating", "inactive", "failed", "reloading")


def addon(addon_id):
    """The catalog entry for `addon_id`, or None."""
    return CATALOG.get(addon_id) if isinstance(addon_id, str) else None


def offered(game_type):
    """The add-on ids a game server of `game_type` can run (its game is in the add-on's list)."""
    gt = (game_type or "").lower()
    return [k for k in ADDON_IDS if gt in CATALOG[k]["games"]]


def unit_name(addon_id):
    """The Quadlet unit's (and the container's) name for `addon_id`."""
    return UNIT_PREFIX + addon_id


def addon_dir(user, addon_id):
    """The add-on's folder in the account's home."""
    return "/home/%s/%s/%s" % (user, HOME_DIR, addon_id)


def _version(text):
    m = _VERSION_RE.search(text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def runtime_refusal(os_version, podman_version):
    """Why this host can't run add-ons (an English sentence), or "".

    `os_version` is /etc/os-release's VERSION_ID; `podman_version` what `podman --version` printed,
    "" when Podman is not installed yet (then only the Ubuntu release is asked).
    """
    osv = _version(os_version)
    if osv is None or osv < MIN_UBUNTU:
        return "Add-ons need Ubuntu 24.04 or newer on the game's host."
    pv = _version(podman_version)
    if podman_version and (pv is None or pv < MIN_PODMAN):
        return "Add-ons need Podman 4.9 or newer, and this host has an older one."
    return ""


# ── reading the host ──────────────────────────────────────────────────────────────────────────
def kv_lines(out):
    """The key=value lines a probe printed, as a dict (later lines win)."""
    got = {}
    for line in (out or "").splitlines():
        m = _KV_RE.match(line.strip())
        if m:
            got[m.group(1)] = m.group(2).strip()
    return got


def rcon_password(cfg_text):
    """The last RCON password a CoD server config sets (rcon_password or rconpassword), or ""."""
    found = ""
    for m in _RCON_RE.finditer(cfg_text or ""):
        found = m.group(1) if m.group(1) is not None else m.group(2)
    return found


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _unb64(text):
    try:
        return base64.b64decode((text or "").encode("ascii"), validate=True).decode("utf-8", "replace")
    except (ValueError, UnicodeEncodeError):
        return ""


# Every game-account body starts here: the user manager's runtime folder (sudo does not set it),
# the account's own home, and a working folder it can enter.
_ENV = ('export XDG_RUNTIME_DIR="/run/user/$(id -u)"; '
        'HOME=$(getent passwd "$(id -un)" | cut -d: -f6); export HOME; cd "$HOME" || exit 1; ')


def probe_sh(addon_id, selfname, server_id, game_type, nports):
    """The install's first read, as the account: the host, the game's log folder, RCON, free ports.

    Prints os=, podman=, splice=1 (pasta has --splice-only), logdir= (the folder of the newest
    games_mp.log under serverfiles or ~/.callofduty*), rcon.b64= (the config's RCON password line,
    base64), ports= (the first `nports` free host ports from PORT_BASE + the server id) and
    installed=1 when the add-on is already there.
    """
    cfg = "serverfiles/%s/%s.cfg" % (_CFG_DIR.get(game_type, "main"), selfname)
    ports = " ".join(str(PORT_BASE + int(server_id) + i) for i in range(_PORT_TRIES))
    return (_ENV + '. /etc/os-release 2>/dev/null; echo "os=${VERSION_ID:-}"; '
            'echo "podman=$(podman --version 2>/dev/null | head -n 1)"; '
            'pasta --help 2>&1 | grep -q -- "--splice-only" && echo splice=1; '
            'l=$(find serverfiles .callofduty* -maxdepth 3 -type f -name games_mp.log -printf "%%T@ %%h\\n" '
            '2>/dev/null | sort -nr | head -n 1 | cut -d" " -f2-); echo "logdir=$l"; '
            'echo "rcon.b64=$(grep -iE "^[[:space:]]*seta?[[:space:]]+rcon_?password" %s 2>/dev/null '
            '| tail -n 1 | head -c 400 | base64 -w0)"; '
            'f=""; n=0; for p in %s; do [ $n -ge %d ] && break; '
            'if ! ss -Htln "sport = :$p" 2>/dev/null | grep -q .; then f="$f $p"; n=$((n + 1)); fi; done; '
            'echo "ports=$f"; [ -f %s ] && echo installed=1; true'
            % (shlex.quote(cfg), ports, int(nports), shlex.quote("%s/%s/%s" % (HOME_DIR, addon_id, META_FILE))))


# The game's log folder as the probe prints it, relative to the home: plain path words only, since it
# goes into the unit file (where `%` is a specifier and a line break a new key). A segment may start
# with one dot (CoD1's ~/.callofduty/main), never be `..`.
_LOGDIR_RE = re.compile(r"\.?[A-Za-z0-9_+-][A-Za-z0-9._+-]*(?:/\.?[A-Za-z0-9_+-][A-Za-z0-9._+-]*){0,3}")


def log_dir(user, rel):
    """The game log's folder as an absolute path in the account's home, or "" when `rel` is not plain."""
    if not _LOGDIR_RE.fullmatch(rel or "") or ".." in rel.split("/"):
        return ""
    return "/home/%s/%s" % (user, rel)


def parse_probe(out):
    """What probe_sh found: {os, podman, splice, logdir, rcon, ports, installed} (rcon decoded and parsed)."""
    kv = kv_lines(out)
    return {"os": kv.get("os", ""), "podman": kv.get("podman", ""), "splice": kv.get("splice") == "1",
            "logdir": kv.get("logdir", ""), "rcon": rcon_password(_unb64(kv.get("rcon.b64", ""))),
            "ports": [int(p) for p in kv.get("ports", "").split() if p.isdecimal()],
            "installed": kv.get("installed") == "1"}


def status_sh():
    """One read of every add-on of this account: os=, podman=, and per add-on meta.<id>= and state.<id>=."""
    rows = []
    for k in ADDON_IDS:
        meta = shlex.quote("%s/%s/%s" % (HOME_DIR, k, META_FILE))
        rows.append('[ -f %s ] && { echo "meta.%s=$(head -c 4000 %s | base64 -w0)"; '
                    'echo "state.%s=$(systemctl --user is-active %s.service 2>/dev/null | head -n 1)"; }; '
                    % (meta, k, meta, k, unit_name(k)))
    return (_ENV + '. /etc/os-release 2>/dev/null; echo "os=${VERSION_ID:-}"; '
            'echo "podman=$(podman --version 2>/dev/null | head -n 1)"; ' + "".join(rows) + "true")


def parse_status(out):
    """What status_sh found: {os, podman, addons: {id: {meta dict, state}}} for the installed ones."""
    kv = kv_lines(out)
    found = {}
    for k in ADDON_IDS:
        if "meta." + k not in kv:
            continue
        try:
            meta = json.loads(_unb64(kv["meta." + k]) or "{}")
        except ValueError:
            meta = {}
        state = kv.get("state." + k, "")
        found[k] = {"meta": meta if isinstance(meta, dict) else {},
                    "state": state if state in _STATES else "unknown"}
    return {"os": kv.get("os", ""), "podman": kv.get("podman", ""), "addons": found}


# ── what the install writes ───────────────────────────────────────────────────────────────────
def iw4madmin_settings(game_type, game_port, rcon):
    """IW4MAdminSettings.json for one server, as text: enough that its first-run setup never runs.

    IW4MAdmin runs its setup only when the file has no Servers and no Id (ApplicationManager), and
    its validator asks for a bind URL, a database provider, AutoMessagePeriod >= 60, and per server
    a port and an RCON password. The database is its built-in SQLite one (Database/Database.db in
    the add-on's folder). Its translations are the image's own files (no download). The page
    listens on every address of the container's own network; the host publishes it on 127.0.0.1.
    """
    parser = CATALOG[IW4MADMIN]["games"][game_type]
    # Where IW4MAdmin listens inside its own container network; the host publishes it on 127.0.0.1.
    bind = "http://0.0.0.0:%d" % CATALOG[IW4MADMIN]["web_port"]  # NOSONAR(S5332) - a listen address, not a request
    doc = {
        "Webfront": {"Enabled": True, "BindUrl": bind},
        "DatabaseProvider": "sqlite",
        "UseLocalTranslations": True,
        "AutoMessagePeriod": 60,
        "AutoMessages": [], "GlobalRules": [], "DisallowedClientNames": [],
        "Servers": [{
            "IPAddress": "127.0.0.1", "Port": int(game_port), "Password": rcon,
            "ManualLogPath": "/gamelog/games_mp.log",
            "RConParserVersion": parser, "EventParserVersion": parser,
            "AutoMessages": [], "Rules": [], "ReservedSlotNumber": 0,
        }],
    }
    return json.dumps(doc, indent=2) + "\n"


def iw4madmin_files():
    """The two plugin settings files IW4MAdmin's first start would otherwise ask about on its console.

    Stats asks whether to turn on its anti-cheat (it checks IW4 and T6 only, not these games) and
    ProfanityDeterment whether to warn and kick players for words on its list: both off. Every
    other setting keeps the plugin's own default (a value left out of the file is its default).
    """
    stats = {"AnticheatConfiguration": {"Enable": False}, "TopPlayersMinPlayTime": 10800, "StoreClientKills": False}
    profanity = {"EnableProfanityDeterment": False, "OffensiveWords": [], "KickAfterInfringementCount": 2,
                 "KickOnInfringingName": False}
    return {"Configuration/StatsPluginSettings.json": json.dumps(stats, indent=2) + "\n",
            "Configuration/ProfanityDetermentSettings.json": json.dumps(profanity, indent=2) + "\n"}


def b3_ini_refusal(rcon):
    """Why B3's ini can't hold this RCON password ("" when it can).

    B3 reads b3.ini with ConfigParser: a value loses its leading and trailing blanks, and a `;`
    after a blank starts a comment (b3/config.py, inline_comment_prefixes).
    """
    return _B3_RCON_REFUSAL if rcon != rcon.strip() or re.search(r"\s;", rcon) else ""


def b3_ini(game_type, game_port, rcon, db_name, db_secret, geolocation):
    """b3.ini for one server, as text (it holds the RCON and database passwords).

    The database is reached at 127.0.0.1:3306 inside the container, which network() forwards. The
    panel's database names and passwords are letters, digits and - _ . only
    (ssh_manager/databases.new_password), so they need no quoting in the URL.
    """
    plugins = B3_PLUGINS + (B3_GEO_PLUGINS if geolocation else ())
    lines = [
        "; Written by linuxgsm-panel: the B3 add-on of this game server. Reinstalling rewrites it.",
        "[b3]", "parser: %s" % CATALOG[B3]["games"][game_type],
        "database: mysql://%s:%s@127.0.0.1:3306/%s" % (db_name, db_secret, db_name),
        "bot_name: b3", "bot_prefix: ^0(^2b3^0)^7:", "time_format: %I:%M%p %Z %m/%d/%y", "time_zone: UTC",
        "log_level: 20", "logfile: @conf/b3.log", "disabled_plugins:", "external_plugins_dir: @b3/extplugins",
        "", "[server]", "rcon_password: %s" % rcon, "port: %d" % int(game_port),
        "game_log: /gamelog/games_mp.log", "public_ip: 127.0.0.1", "rcon_ip: 127.0.0.1", "punkbuster: off",
        "delay: 0.33", "lines_per_second: 50",
        "", "[update]", "channel: skip",
        "", "[messages]",
        "kicked_by: $clientname^7 was kicked by $adminname^7 $reason",
        "kicked: $clientname^7 was kicked $reason",
        "banned_by: $clientname^7 was banned by $adminname^7 $reason",
        "banned: $clientname^7 was banned $reason",
        "temp_banned_by: $clientname^7 was temp banned by $adminname^7 for $banduration^7 $reason",
        "temp_banned: $clientname^7 was temp banned for $banduration^7 $reason",
        "unbanned_by: $clientname^7 was un-banned by $adminname^7 $reason",
        "unbanned: $clientname^7 was un-banned^7 $reason",
        "", "[plugins]",
    ] + ["%s:%s" % (p, "" if p in _B3_NO_FILE else " @conf/conf/plugin_%s.ini" % p) for p in plugins]
    return "\n".join(lines) + "\n"


def build_files(addon_id):
    """The files an add-on built on the host needs ({path in its folder: text}), from panel/addon_images/<build>/."""
    build = CATALOG[addon_id]["build"]
    if not build:
        return {}
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addon_images", build)
    got = {}
    for name in ("Containerfile", "requirements.txt", "entrypoint.sh"):
        with open(os.path.join(base, name), encoding="utf-8") as fh:
            got["%s/%s" % (BUILD_DIR, name)] = fh.read()
    return got


def relays(addon_id, db_host, db_port, geolocation, ports):
    """The TCP relays the add-on needs on this host.

    Each is (name, address in the container, port there, host port, target "host:port"). A database
    on this host needs none (network() forwards its port straight). One on another machine, and each
    geolocation service when chosen, gets a relay: systemd-socket-proxyd as the account, listening
    on one of `ports` (free host ports on 127.0.0.1) and connecting to that one
    target only, so the container never needs a route to anywhere.
    """
    want = []
    if CATALOG[addon_id]["database"] and db_host and db_host != "127.0.0.1":
        want.append(("db", "127.0.0.1", 3306, "%s:%d" % (db_host, int(db_port))))
    if addon_id == B3 and geolocation:
        want += [("geo%d" % i, addr, 443, "%s:443" % name) for i, (name, addr) in enumerate(B3_GEOLOCATORS, 1)]
    return [(n, addr, cport, hport, target) for (n, addr, cport, target), hport in zip(want, ports)]


def relay_units(addon_id, relay_list):
    """The user units ({file name: text}) for `relay_list`: a socket on 127.0.0.1 and its proxy."""
    units = {}
    for name, _addr, _cport, hport, target in relay_list:
        base = "%s%s-%s" % (UNIT_PREFIX, addon_id, name)
        units[base + ".socket"] = ("# Written by linuxgsm-panel: a relay of the %s add-on.\n[Unit]\n"
                                   "Description=linuxgsm-panel add-on relay to %s\n\n[Socket]\n"
                                   "ListenStream=127.0.0.1:%d\n" % (addon_id, target, int(hport)))
        units[base + ".service"] = ("# Written by linuxgsm-panel: a relay of the %s add-on.\n[Unit]\n"
                                    "Description=linuxgsm-panel add-on relay to %s\nRequires=%s.socket\n"
                                    "After=%s.socket\n\n[Service]\nExecStart=%s --exit-idle-time=5min %s\n"
                                    % (addon_id, target, base, base, SOCKET_PROXYD, target))
    return units


def network(game_port, db_port, relay_list, splice):
    """The container's Network= value: pasta, reaching only what it forwards to the host's loopback.

    -U the game's RCON port (UDP). -T the database's port (TCP) when the database is on this host
    (`db_port`, seen at 3306 inside), and each relay's (`relay_list`, from relays()). Then the lock:
    --splice-only where pasta has it, else -4 and -o 127.0.0.1 (see the module's NETWORK note).
    """
    opts = ["--splice-only"] if splice else ["-4", "-o", "127.0.0.1"]
    opts += ["-U", str(int(game_port))]
    if db_port:
        opts += ["-T", "3306:%d" % int(db_port)]
    for _name, addr, cport, hport, _target in relay_list:
        spec = "%d:%d" % (int(cport), int(hport))
        opts += ["-T", spec if addr == "127.0.0.1" else "%s/%s" % (addr, spec)]
    return "pasta:" + ",".join(opts)


def _podman_args(addon_id, relay_list):
    a = CATALOG[addon_id]
    args = ["--memory=%s" % MEMORY, "--stop-timeout=%d" % STOP_TIMEOUT, "--dns=none"]
    if a["stop_signal"] != "SIGTERM":
        args.append("--stop-signal=%s" % a["stop_signal"])
    args += ["--add-host=%s:%s" % (name, addr) for name, addr in B3_GEOLOCATORS
             if any(r[4] == "%s:443" % name for r in relay_list)]
    return "PodmanArgs=" + " ".join(args)


def quadlet(user, addon_id, logdir, net, port, relay_list=()):
    """The add-on's Quadlet unit text (~/.config/containers/systemd/<unit>.container)."""
    a = CATALOG[addon_id]
    base = addon_dir(user, addon_id)
    needs = ["%s%s-%s.socket" % (UNIT_PREFIX, addon_id, r[0]) for r in relay_list]
    vols = ["Volume=%s/%s:%s" % (base, d, at) for d, at in a["mounts"]] + ["Volume=%s:/gamelog:ro" % logdir]
    lines = [
        "# Written by linuxgsm-panel: the %s add-on of this game server. The panel rewrites it." % a["name"],
        "[Unit]", "Description=%s (linuxgsm-panel add-on)" % a["name"],
        "StartLimitIntervalSec=%d" % RESTART_WINDOW, "StartLimitBurst=%d" % RESTART_BURST,
    ] + ["Requires=%s" % n for n in needs] + ["After=%s" % n for n in needs] + [
        "", "[Container]", "Image=%s" % a["image"], "ContainerName=%s" % unit_name(addon_id), "Pull=never",
        "Network=%s" % net,
    ] + (["PublishPort=127.0.0.1:%d:%d" % (port, a["web_port"])] if a["web_port"] else []) + [
        "Environment=%s" % e for e in a["env"]] + vols + [
        # keep-id: the add-on runs as the game account's own uid inside the container, not as root
        # there (podman-run(1): keep-id runs the process as the user's UID and overrides the image's
        # USER), so the files it writes in its folder belong to the account.
        "UserNS=keep-id",
        "ReadOnly=true", "DropCapability=all", "NoNewPrivileges=true", "PidsLimit=%d" % PIDS,
        "HealthCmd=none", _podman_args(addon_id, relay_list),
        # always: an add-on that quits, even with status 0, is started again (IW4MAdmin exits 0 on a
        # fatal error); the start limit above stops a loop, and a stop from the panel never restarts.
        "", "[Service]", "Restart=always", "RestartSec=30", "TimeoutStartSec=300",
        "", "[Install]", "WantedBy=default.target", "",
    ]
    return "\n".join(lines)


def _put_sh(path, text):
    """Shell writing `text` (no secret: it travels base64 on the command line) to `path`, atomically."""
    q = shlex.quote(path)
    return "printf %%s %s | base64 -d > %s.new && mv -f -T %s.new %s" % (shlex.quote(_b64(text)), q, q, q)


def _image_sh(addon_id, d):
    """Shell that gets the add-on's image: a pull by digest, or a build from its own folder."""
    a = CATALOG[addon_id]
    if not a["build"]:
        return "podman pull -q %s >/dev/null || { echo ADDON_PULL_FAILED; exit 23; }; " % shlex.quote(a["image"])
    return ("podman build -q --network=host --pull=missing --build-arg BASE_IMAGE=%s --build-arg B3_COMMIT=%s "
            "-t %s -f %s/%s/Containerfile %s/%s >/dev/null 2>%s/%s/build.log "
            "|| { echo ADDON_BUILD_FAILED; tail -n %d %s/%s/build.log | base64 -w0 | sed 's/^/tail.b64=/'; echo; "
            "exit 24; }; podman image prune -f >/dev/null 2>&1; "
            % (shlex.quote(B3_BASE), B3_COMMIT, shlex.quote(a["image"]), d, BUILD_DIR, d, BUILD_DIR, d, BUILD_DIR,
               TAIL_LINES, d, BUILD_DIR))


def _tail_sh(user, addon_id):
    """Shell printing the add-on's last TAIL_LINES log lines: its own log file if it keeps one, else its journal."""
    a = CATALOG[addon_id]
    if a["log_file"]:
        return "tail -n %d %s 2>/dev/null" % (TAIL_LINES, shlex.quote("%s/%s" % (addon_dir(user, addon_id), a["log_file"])))
    return "journalctl --user -u %s.service -n %d --no-pager -o cat 2>/dev/null" % (unit_name(addon_id), TAIL_LINES)


def _settle_sh(user, addon_id):
    """Shell that watches the started unit for SETTLE_SECONDS: active the whole time and never restarted.

    Otherwise it stops the unit (so it does not restart in a loop), prints ADDON_DIED and the last
    TAIL_LINES of its log (base64), and exits 26.
    """
    unit = unit_name(addon_id)
    return ("i=0; while [ $i -lt %d ]; do sleep 2; i=$((i + 2)); "
            "s=$(systemctl --user is-active %s.service 2>/dev/null); "
            "r=$(systemctl --user show -p NRestarts --value %s.service 2>/dev/null); "
            "if [ \"$s\" != active ] || [ \"${r:-0}\" != 0 ]; then systemctl --user stop %s.service 2>/dev/null; "
            "echo ADDON_DIED; %s | tail -c 4000 | base64 -w0 | sed 's/^/tail.b64=/'; echo; exit 26; fi; done; "
            % (SETTLE_SECONDS, unit, unit, unit, _tail_sh(user, addon_id)))


def install_sh(user, addon_id, unit_text, meta_text, files=None, units=None):
    """The install's second step, as the account: write the files, get the image, start, watch.

    The settings (which hold the passwords) arrive on stdin, never on a command line; the unit, the
    relays' units (`units`), the plugin or build files (`files`, relative to the add-on's folder)
    and the panel's record are base64 here (they hold no secret). Every file is 0600 and every
    folder 0700. Ends with ADDON_INSTALLED, or one of _FAIL_MARKS.
    """
    a = CATALOG[addon_id]
    d = addon_dir(user, addon_id)
    q = "/home/%s/%s" % (user, QUADLET_DIR)
    uu = "/home/%s/%s" % (user, USER_UNIT_DIR)
    unit = unit_name(addon_id)
    dirs = " ".join(shlex.quote("%s/%s" % (d, m)) for m in [m for m, _at in a["mounts"]] + [BUILD_DIR])
    puts = [_put_sh("%s/%s.container" % (q, unit), unit_text), _put_sh("%s/%s" % (d, META_FILE), meta_text)]
    puts += [_put_sh("%s/%s" % (d, rel), text) for rel, text in sorted((files or {}).items())]
    puts += [_put_sh("%s/%s" % (uu, name), text) for name, text in sorted((units or {}).items())]
    secret = shlex.quote("%s/%s" % (d, a["settings"]))
    return (_ENV + "umask 077; mkdir -p %s %s %s || { echo ADDON_WRITE_FAILED; exit 20; }; "
            "cat > %s.new && mv -f -T %s.new %s && %s || { echo ADDON_WRITE_FAILED; exit 21; }; "
            "i=0; while [ ! -S \"$XDG_RUNTIME_DIR/bus\" ] && [ $i -lt 20 ]; do sleep 1; i=$((i + 1)); done; "
            "[ -S \"$XDG_RUNTIME_DIR/bus\" ] || { echo ADDON_NO_USER_MANAGER; exit 22; }; "
            "podman system migrate >/dev/null 2>&1; %s"
            "systemctl --user daemon-reload && systemctl --user start %s.service "
            "|| { echo ADDON_START_FAILED; %s | tail -c 4000 | base64 -w0 | sed 's/^/tail.b64=/'; echo; exit 25; }; "
            "%secho %s"
            % (dirs, shlex.quote(q), shlex.quote(uu), secret, secret, secret, " && ".join(puts),
               _image_sh(addon_id, shlex.quote(d)), unit, _tail_sh(user, addon_id), _settle_sh(user, addon_id),
               _MARK_INSTALLED))


def install_outcome(out, rc):
    """(ok, English sentence or "", log tail or "") from what install_sh printed and its exit status."""
    tail = _unb64(kv_lines(out).get("tail.b64", ""))
    if rc == 0 and _MARK_INSTALLED in (out or ""):
        return True, "", ""
    for mark, said in _FAIL_MARKS.items():
        if mark in (out or ""):
            return False, said, tail
    return False, "The install didn't finish on the host.", tail


def action_sh(addon_id, action):
    """Start or stop the add-on's unit, as the account (`action` is "start" or "stop")."""
    if action not in ("start", "stop"):
        raise ValueError("unknown add-on action")
    return _ENV + "systemctl --user %s %s.service" % (action, unit_name(addon_id))


def logs_sh(user, addon_id):
    """The add-on's last LOG_LINES lines.

    Its own log file if it keeps one (B3's b3.log), else its unit's journal, else the newest file in
    its Log folder.
    """
    a = CATALOG[addon_id]
    own = shlex.quote("%s/%s" % (addon_dir(user, addon_id), a["log_file"])) if a["log_file"] else "''"
    log_dir = shlex.quote(addon_dir(user, addon_id) + "/Log")
    return (_ENV + "if [ -n %s ] && [ -f %s ]; then tail -n %d %s; else "
            "o=$(journalctl --user -u %s.service -n %d --no-pager -o short-iso 2>/dev/null "
            "| grep -v '^-- No entries --$'); "
            "if [ -n \"$o\" ]; then printf '%%s\\n' \"$o\"; else "
            "f=$(ls -1t %s 2>/dev/null | head -n 1); [ -n \"$f\" ] && tail -n %d %s/\"$f\"; fi; fi "
            "| tail -c %d; true"
            % (own, own, LOG_LINES, own, unit_name(addon_id), LOG_LINES, log_dir, LOG_LINES, log_dir, LOG_BYTES))


def remove_sh(user, addon_id):
    """Stop and remove the add-on, its relays, its image, its unit and its folder, as the account.

    The folder goes through `podman unshare`, so a file the container made as one of its own users
    (a subordinate id) goes too. A built image's leftover build layers go with `podman image prune`.
    Prints ADDON_REMOVED and others=0/1 (whether another add-on is left).
    """
    unit = unit_name(addon_id)
    d = shlex.quote(addon_dir(user, addon_id))
    home = shlex.quote("/home/%s/%s" % (user, HOME_DIR))
    relay_glob = "/home/%s/%s/%s%s-*" % (user, USER_UNIT_DIR, UNIT_PREFIX, addon_id)
    return (_ENV + "systemctl --user stop %s.service 2>/dev/null; rm -f %s; "
            "for f in %s; do [ -e \"$f\" ] || continue; systemctl --user stop \"${f##*/}\" 2>/dev/null; rm -f \"$f\"; "
            "done; systemctl --user daemon-reload 2>/dev/null; podman rm -f --ignore %s >/dev/null 2>&1; "
            "podman rmi %s >/dev/null 2>&1; podman image prune -f >/dev/null 2>&1; "
            "podman unshare rm -rf -- %s 2>/dev/null || rm -rf -- %s; "
            "[ -e %s ] && exit 30; rmdir %s 2>/dev/null; "
            "if [ -d %s ]; then echo others=1; else echo others=0; fi; echo %s"
            % (unit, shlex.quote("/home/%s/%s/%s.container" % (user, QUADLET_DIR, unit)), relay_glob, unit,
               shlex.quote(CATALOG[addon_id]["image"]), d, d, d, home, home, _MARK_REMOVED))


def remove_outcome(out, rc):
    """(removed, another add-on left) from what remove_sh printed."""
    kv = kv_lines(out)
    return (rc == 0 and _MARK_REMOVED in (out or "")), kv.get("others") == "1"


def scrub(text, secrets):
    """`text` with every secret in `secrets` (non-empty) replaced by a mask."""
    for s in secrets:
        if s:
            text = text.replace(s, "•" * 8)
    return text
