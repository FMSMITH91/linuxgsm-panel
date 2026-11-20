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
    host's loopback: the game's RCON port (UDP; TCP for a Source game) and, for an add-on with a database, that database
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
    B3 (cod, coduo, cod2, cod4, codwaw, sof2, wet, q3, etl; csgo and ins built in, each behind its
    own switch: B3_LATER_GAMES): legacy, opt-in. Built on
    the host from addon_images/b3 (a Containerfile: FMSMITH91/big-brother-bot at one commit, its
    dependencies by hash), with one of this server's databases from the Databases tab (never one
    another add-on uses). Its geolocation is off unless chosen: offline (a country, from DB-IP's
    database in the add-on's folder, see services/geoip.py; no player address leaves the host) or
    online (a city, from ipwho.is through a relay: each player's IP address goes there).
    BlueMap (mc, pmc): a live 3D web map of the Minecraft world, the image its author publishes
    (ghcr.io/bluemap-minecraft/bluemap), pinned by digest. It reads the world READ-ONLY (no game log,
    no RCON) and reaches nothing at all; Minecraft's client file it textures the map from is fetched
    for it before its start, once the admin has accepted Mojang's EULA (services/addons_bluemap.py).

The host keeps the state: ~/panel-addons/<id>/addon.json says what the panel installed. Nothing is
installed until someone with Manage add-ons installs an add-on.
"""
import base64
import hashlib
import json
import os
import re
import shlex

# ── the catalog ─────────────────────────────────────────────────────────────────────────────────
IW4MADMIN = "iw4madmin"
B3 = "b3"
BLUEMAP = "bluemap"
# Games whose LinuxGSM start command passes no port, so the port in the game's config may not be the one
# it listens on (Wolfenstein: Enemy Territory binds 0.0.0.0:27960 unless the instance's startparameters set
# net_port: vps-b3 round 3). An add-on for one needs the server running at install, to read the real port.
# LinuxGSM's ET: Legacy start passes no port either (its server.cfg sets net_port, which the engine reads
# only after its socket is open, as Enemy Territory's does).
LIVE_PORT_GAMES = ("wet", "etl")
# More B3 games, built in and each switched on after its own test against LinuxGSM's server (the
# vps checklist): Quake 3 Arena (q3server, the id 1.32c build), ET: Legacy (etlserver: B3's et parser, which
# reads its status rows and chat since B3_COMMIT; it writes a game log only once the operator sets g_log:
# G_LOG_DIR), Counter-Strike: Global Offensive and Insurgency (Source engine: B3 needs SourceMod on the
# server and its console.log from -condebug, and speaks RCON over TCP). Not offered, each for its reason
# in docs/addons.md: Arma 3 and Chivalry: Medieval Warfare (their RCON is not set up by LinuxGSM's
# configs, so nothing on the host says where B3 would reach it). Switching one on also adds its name to
# the card's legacy warning (server_addons.js installNotes, and its es/fr text).
# Wolfenstein: Enemy Territory, ET: Legacy and Quake 3: B3 at 1b96587f asked `dumpuser <slot>` for a
# player's cl_guid, and these Quake 3 engines' dumpuser takes only a player's name (ET: Legacy's sv_ccmds.c
# SV_DumpUser_f -> SV_GetPlayerByName), so no human player was ever authorized there (VPS round D, F-D1).
# B3_COMMIT has the fork's fix (its PR #25), and VPS round E saw real protocol-client joins authorized at it
# on all three (colour-coded names and names with spaces too), so they are on. CS:GO and Insurgency were
# never tested on the VPS and stay off.
B3_WET = True
B3_Q3 = True
B3_ETL = True
B3_CSGO = False
B3_INS = False
# Each one's B3 parser (b3/parsers/<name>.py at B3_COMMIT), and whether it is offered.
B3_LATER_GAMES = (("wet", "et", B3_WET), ("q3", "q3", B3_Q3), ("etl", "et", B3_ETL), ("csgo", "csgo", B3_CSGO),
                  ("ins", "insurgency", B3_INS))
# Games whose RCON is TCP on the game port (Source's), forwarded with -T; the others' is UDP (-U).
RCON_TCP_GAMES = ("csgo", "ins")
# Source games B3 refuses to run on without SourceMod (its csgo and insurgency parsers exit 220): the
# folder LinuxGSM's mods-install puts it in.
SOURCEMOD_DIR = {"csgo": "serverfiles/csgo/addons/sourcemod", "ins": "serverfiles/insurgency/addons/sourcemod"}
# FMSMITH91/big-brother-bot master on 2026-11-19: v2.0.1 (the Quake 3 engine parsers asking `dumpuser` by
# the slot's name, ET: Legacy's status and chat, CoD4x and vanilla ET, commands refused to a player B3 has
# not authenticated, geolocation) and the service interface the panel uses on top of it: `--check-config`
# (exit 230), `--version` with the commit (from the image's B3_COMMIT), fixed exit codes 220-223 and
# 230-233 (b3/exitcodes.py), health.json, the `data` table's b3_schema_version, purge_aliases_days,
# events.jsonl, the control socket (with `actor`) and the plugin reload (SIGHUP / reload_plugins): the B3
# the add-on builds. Renovate proposes the branch's newest commit (.github/renovate.json), in this line and
# the Containerfile's ARG together.
B3_COMMIT = "7da5ac8685c34665cb10670810656a3bf99fcf91"
# A development commit after v2.0.1: a 2.0.2 tag is planned on it. The card shows this label beside the
# short commit until B3 itself says what runs (its health.json). Only a label: the build checks the
# commit, not a tag, and the image's tag is the commit and build id, so a new label alone offers no update.
B3_RELEASE = "2.0.2dev"
# RaidMax/IW4M-Admin's `latest` image (its release 2026.2.4.1 on 2026-11-18, org.opencontainers.image.revision
# 80bf102b, linux/amd64), by digest. Renovate proposes the tag's new digest.
IW4MADMIN_IMAGE = "ghcr.io/raidmax/iw4madmin@sha256:72ccf1b33983cdc64071b77fca8acac49943093aa74d41ae35ffbb89d8b15a46"
# BlueMap's `v5` image (its release 5.29 on 2026-10-10, org.opencontainers.image.revision a61e143f; the same
# digest as its v5.29 and latest tags then), by its multi-arch index digest. Renovate proposes the v5 tag's new
# digest, so a new 5.x release is offered and a major release with new configs is not.
BLUEMAP_IMAGE = "ghcr.io/bluemap-minecraft/bluemap@sha256:bb49bfdef996c6fd9cf68c8c6a2b79189e6711fa90ae4d43cf22d81a6811301e"
# python:3.12-slim (Debian 13) on 2026-11-18, by its multi-arch index digest: the build's base. Renovate
# proposes the tag's new digest here and in the Containerfile's ARG BASE_IMAGE together (.github/renovate.json).
B3_BASE = "docker.io/library/python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
# The files of an add-on's build folder (panel/addon_images/<build>/) that go to the host.
BUILD_FILES = ("Containerfile", "requirements.txt", "entrypoint.sh")
_IMAGES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addon_images")


def build_id(folder, base):
    """A short id of what an image built on the host is made of: its base image and its build folder's files.

    Part of the image's tag beside the source commit, so a new base digest, a new lock of its Python
    packages or a changed Containerfile (the automatic update pull requests among them) is offered as
    an update to every host still running the image built before, as a new commit is.
    """
    h = hashlib.sha256(base.encode("utf-8"))
    for name in BUILD_FILES:
        h.update(b"\0" + name.encode("ascii") + b"\0")
        try:
            with open(os.path.join(folder, name), "rb") as fh:
                h.update(fh.read())
        except OSError:
            h.update(b"\0missing")      # read at import: a missing file fails the build, never the panel's start
    return h.hexdigest()[:8]


CATALOG = {
    IW4MADMIN: {
        "name": "IW4MAdmin",
        "image": IW4MADMIN_IMAGE,
        # The tag and the digest's start: a digest Renovate moves has no release name beside it.
        "version": "latest " + IW4MADMIN_IMAGE.rsplit(":", 1)[1][:12],
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
        "stop_signal": "SIGINT", "stop_timeout": 30, "success_exit": None,
        "database": False, "build": None, "legacy": False, "log_file": None,
        "data_kept": False, "reads": "log", "command": (), "nice": 0, "no_restart": None,
    },
    B3: {
        "name": "B3 (Big Brother Bot)",
        "image": "localhost/lgsm-addon-b3:%s-%s" % (B3_COMMIT[:12], build_id(os.path.join(_IMAGES_DIR, "b3"), B3_BASE)),
        "version": "%s (%s)" % (B3_RELEASE, B3_COMMIT[:8]),
        "source": "https://github.com/FMSMITH91/big-brother-bot",
        # game type -> B3's parser (each tested against LinuxGSM's server, work/batch-1115 vps-b3 rounds 3
        # and 3b). United Offensive is CoD1's engine and log: B3's cod parser. World at War is cod5.
        "games": dict({"cod": "cod", "coduo": "cod", "cod2": "cod2", "cod4": "cod4", "codwaw": "cod5", "sof2": "sof2"},
                      **{g: parser for g, parser, on in B3_LATER_GAMES if on}),
        # geoip: DB-IP's country database, put there by the panel (services/geoip.py), read-only inside.
        "mounts": (("Data", "/data"), ("geoip", "/geoip:ro")),
        "env": ("TZ=Etc/UTC", "HOME=/data"),
        "settings": "Data/b3.ini",
        "web_port": None,
        # B3 shuts down on SIGTERM and exits 0. Before b8e98400 its player-authentication retry
        # timers were not daemon threads and held the exit after it had read a log line, so Podman
        # killed it (137); that fork commit made them daemon, so no exit status is excused here.
        "stop_signal": "SIGTERM", "stop_timeout": 30, "success_exit": None,
        "database": True, "build": "b3", "legacy": True, "log_file": "Data/b3.log",
        "data_kept": True, "reads": "log", "command": (), "nice": 0,
        # B3's exit codes (b3/exitcodes.py) that a restart can't mend: 222 an admin's !die in the game,
        # 230 invalid settings. Not 233 (the database not reached at start): that one may come back.
        "no_restart": "222 230",
    },
    BLUEMAP: {
        "name": "BlueMap",
        "image": BLUEMAP_IMAGE,
        "version": "v5 " + BLUEMAP_IMAGE.rsplit(":", 1)[1][:12],
        "source": "https://github.com/BlueMap-Minecraft/BlueMap",
        # LinuxGSM's Java servers with a world: vanilla (mcserver) and Paper (pmcserver). Not its proxies
        # (Velocity, Waterfall: no world) nor Bedrock (BlueMap reads Java worlds only).
        "games": {"mc": "Minecraft", "pmc": "Paper"},
        # Its image's folders (the installation page's Docker volumes); the worlds are mounted read-only
        # beside them (quadlet's `logdir` is then a World: services/addons_bluemap.py).
        "mounts": (("config", "/app/config"), ("web", "/app/web"), ("data", "/app/data")),
        # The JVM's heap: 60% of the memory cap (Java's default, 25%, is too little to render).
        "env": ("TZ=Etc/UTC", "HOME=/app/data", "JAVA_TOOL_OPTIONS=-XX:MaxRAMPercentage=60"),
        "settings": "config/core.conf",
        "web_port": 8100,
        # The JVM runs its shutdown hook on SIGTERM (BlueMap saves the maps' state) and exits 143.
        "stop_signal": "SIGTERM", "stop_timeout": 30, "success_exit": "143",
        "database": False, "build": None, "legacy": False, "log_file": None,
        "data_kept": False, "reads": "world",
        # The image's `java -jar cli.jar` takes these, then the Minecraft version: render, watch, serve.
        "command": ("-r", "-u", "-w", "-v"),
        # Rendering is CPU heavy and the game shares the host: below the game's priority.
        "nice": 10, "no_restart": None,
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
# The service B3's geolocation asks first (b3/plugins/geolocation/geolocators.py), on port 443 of
# the container's loopback, relayed to HTTPS on the internet. Only one fits: pasta's -T takes no
# address, on either release (conf.c conf_ports: an address is for -t/-u only), so a second service
# on 443 has nowhere to go. Its other one (ipapi.co) is left out: it can't resolve inside.
B3_GEOLOCATORS = (("ipwho.is", "127.0.0.1"),)
# The plugins a B3 install turns on (the distribution's own list, less adv: it reads an RSS feed
# from the internet; censor: it punishes words on its own; punkbuster: off on these games).
B3_PLUGINS = ("admin", "cmdmanager", "pingwatch", "pluginmanager", "spamcontrol", "stats", "status", "tk",
              "welcome")
# The plugins the card switches on and off (b3/conf at B3_COMMIT, each a plugin for any game): admin is
# always on (the commands themselves). Never offered: adv (an RSS feed from the internet), censor
# (punishes words on its own), punkbuster (not on these games), translator (Google's service); nor
# what cannot work here: banlist, ftpytail and sftpytail (fetch from other machines; the container
# reaches none), poweradmin*, callvote, censorurt, jumper, spawnkill, urtserversidedemo (other games'
# parsers). geolocation and location follow the Geolocation setting; countryfilter and geowelcome
# need it on.
B3_SWITCHABLE = ("afk", "chatlogger", "cmdmanager", "customcommands", "firstkill", "ipban", "login", "makeroom",
                 "netblocker", "nickreg", "pingwatch", "pluginmanager", "scheduler", "spamcontrol", "spree",
                 "stats", "status", "tk", "welcome", "xlrstats")
B3_GEO_SWITCHABLE = ("countryfilter", "geowelcome")
# Geolocation's, when chosen: the lookup itself and the location plugin (!locate, join message).
B3_GEO_PLUGINS = ("geolocation", "location")
# A plugin whose settings file in b3/conf is XML.
_B3_XML = ("scheduler",)
# Geolocation: off, offline (a country, from DB-IP's database: services/geoip.py) or online (a city,
# from ipwho.is through a relay). An older install's record holds true/false: online/off.
GEO_OFF, GEO_OFFLINE, GEO_ONLINE = "off", "offline", "online"
GEO_MODES = (GEO_OFF, GEO_OFFLINE, GEO_ONLINE)
# Each mode's [settings] geolocators in plugin_geolocation.ini (the plugin's own service names).
_GEOLOCATORS = {GEO_OFFLINE: "mmdb", GEO_ONLINE: "ipwho.is"}
B3_GEO_INI = "Data/conf/plugin_geolocation.ini"
# The operator's own B3 plugins (off unless turned on in B3's settings): this folder of the add-on's
# Data, mounted read-only over its place in /data, is then b3.ini's external_plugins_dir. Off, B3 looks
# in its own (empty) extplugins folder in the image, and the folder is not mounted.
B3_OWN_PLUGINS = "Data/extplugins"
_B3_EXT_DIR = {False: "@b3/extplugins", True: "@conf/extplugins"}
# The config folder a game's RCON password is read from, by game type (LinuxGSM's servercfgdir:
# serverfiles/main; uo for United Offensive, base for SoF2, etmain for ET).
_CFG_DIR = {"coduo": "uo", "sof2": "base", "wet": "etmain", "etl": "etmain", "q3": "baseq3", "csgo": "csgo/cfg",
            "ins": "insurgency/cfg"}
# The game's log file and where to look for it, by game type (default: games_mp.log, which every CoD
# writes under its own folder in the home, or under serverfiles for cod4server). SoF2 1.02a/1.03 takes
# LinuxGSM's `g_log "date"` as a file name (~/.sof2/base/date); ET's is serverfiles/etmain/etserver.log.
# Quake 3 1.32c writes g_log's default, games.log, under its home path (~/.q3a/baseq3: LinuxGSM sets
# only fs_basepath). A Source game's is console.log in its game folder, written with -condebug.
_GAME_LOG = {"sof2": (".sof2", "date"), "wet": ("serverfiles", "etserver.log"), "q3": (".q3a", "games.log"),
             "csgo": ("serverfiles/csgo", "console.log"), "ins": ("serverfiles/insurgency", "console.log")}
_LOG_DEFAULT = ("serverfiles .callofduty* .cod*", "games_mp.log")
# Games whose log is the file g_log names, which their default configs leave empty: the folder it is
# written to. ET: Legacy writes it under fs_homepath/fs_game: LinuxGSM's start sets fs_homepath to
# serverfiles, and fs_game defaults to legacy (LinuxGSM's own gamelogdir for etlserver). The panel
# never sets g_log itself: the install says what to add to the operator's config (etl_g_log).
G_LOG_DIR = {"etl": "serverfiles/legacy"}
# The probe's lines for etl_g_log: the server's config's g_log lines and its `exec legacy.cfg`, then this
# line, then legacy.cfg's own g_log lines (ET: Legacy ships it with g_log "", and LinuxGSM's server.cfg
# execs it near its end).
_LEGACY_MARK = "//legacy.cfg"
_G_LOG_GREP = r'^[[:space:]]*((set[asu]?[[:space:]]+)?g_log[[:space:]]|exec[[:space:]]+"?legacy(\.cfg)?"?([[:space:]]|$))'
_G_LOG_RE = re.compile(r'^[ \t]*(?:set[asu]?[ \t]+)?g_log[ \t]+(?:"([^"\r\n]*)|([^ \t\r\n]*))', re.I)
_EXEC_LEGACY_RE = re.compile(r'^[ \t]*exec[ \t]+"?legacy(?:\.cfg)?"?(?:[ \t]|$)', re.I)
# A g_log the add-on reads: a plain file name in G_LOG_DIR's folder (it goes into b3.ini's game_log).
_LOG_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")

# What the host prints, read by the parsers below.
_MARK_INSTALLED = "ADDON_INSTALLED"
_MARK_REMOVED = "ADDON_REMOVED"
_MARK_STARTED = "ADDON_STARTED"
# The line logs_sh prints between a log file's tail and the journal's newer lines (split_journal).
JOURNAL_MARK = "ADDON_JOURNAL"
_FAIL_MARKS = {
    "ADDON_NO_USER_MANAGER": "The account's user manager didn't start, so the add-on can't run as it.",
    "ADDON_PULL_FAILED": "Couldn't download the add-on's image. Check that this host can reach its registry.",
    "ADDON_BUILD_FAILED": "Couldn't build the add-on's image on this host. Its log says why.",
    # Before ADDON_START_FAILED, which is printed with it: the first mark found is the one said.
    "ADDON_START_LIMIT": "systemd refused to start the add-on: it was started more than 5 times in 10 minutes, its "
                         "limit against a crash loop. Wait a few minutes, then start it.",
    "ADDON_START_FAILED": "The add-on was installed but didn't start. Its log says why.",
    "ADDON_DIED": "The add-on was installed but stopped again within 30 seconds, so it was left stopped. "
                  "Its last log lines are below.",
    "ADDON_WRITE_FAILED": "Couldn't write the add-on's files in the server's home folder.",
    "ADDON_CLIENT_FAILED": "Couldn't download Minecraft's client file from Mojang on this host, or it didn't match "
                           "the checksum Mojang publishes. Check that this host can reach piston-data.mojang.com.",
}
START_LIMIT = _FAIL_MARKS["ADDON_START_LIMIT"]
_B3_RCON_REFUSAL = ("B3 can't use this RCON password: it has a space at either end, or a space before a ';'. "
                    "Change it, then install again.")
# `set` is optional: a config line is a console command, and Source's server.cfg has none.
_RCON_RE = {name: re.compile(r'^[ \t]*(?:seta?[ \t]+)?%s[ \t]+(?:"([^"\r\n]*)"|(\S+))' % name, re.I | re.M)
            for name in ("rcon_password", "rconpassword")}
# The RCON password setting each game reads. CoD4 and World at War read rcon_password only: World at
# War answers "The server must set 'rcon_password'" when only rconpassword is set (test box,
# 2026-11-18), though LinuxGSM's own codwaw config sets rconpassword. CoD1 reads rconpassword (B3's
# RCON test passed on LinuxGSM's codserver config, which sets only that) and United Offensive is
# CoD1's engine; CoD2 is taken as rcon_password like the later engines (not yet seen on a box).
RCON_SETTING = {"cod": "rconpassword", "coduo": "rconpassword", "cod2": "rcon_password", "cod4": "rcon_password",
                "codwaw": "rcon_password", "sof2": "rconpassword", "wet": "rconpassword", "etl": "rconpassword",
                "q3": "rconpassword", "csgo": "rcon_password", "ins": "rcon_password"}
_START_FIRST = ("Start the game server first: its start command sets no port, so the add-on reads the port it really "
                "listens on, then install again.")
_RCON_RENAME = ("This game ignores rconpassword. In the server's config, rename it to rcon_password, restart the "
                "server, then install again.")
_KV_RE = re.compile(r"([a-z][a-z0-9_.]{0,40})=(.*)")
_VERSION_RE = re.compile(r"(?<!\d)(\d{1,9})\.(\d{1,9})")
_STATES = ("active", "activating", "deactivating", "inactive", "failed", "reloading")


def game_log_name(game_type):
    """The game log's file name B3 or IW4MAdmin reads, by game type (games_mp.log unless _GAME_LOG says)."""
    return _GAME_LOG.get(game_type, _LOG_DEFAULT)[1]


def game_cfg(game_type, selfname):
    """The game's own config as LinuxGSM installs it, relative to the home (where its RCON password is read)."""
    return "serverfiles/%s/%s.cfg" % (_CFG_DIR.get(game_type, "main"), selfname)


def etl_g_log(lines):
    """The g_log ET: Legacy's server ends up with, from the probe's lines ("" when the server writes no game log).

    The lines are the server's config's g_log and `exec legacy.cfg` lines in their order, then
    _LEGACY_MARK, then legacy.cfg's own g_log lines. A config runs top to bottom, legacy.cfg's lines
    run where it is exec'd, and the last value set wins: a g_log above LinuxGSM's `exec legacy.cfg`
    is cleared again by the g_log "" that ET: Legacy's legacy.cfg ships with.
    """
    rows = (lines or "").splitlines()
    cut = rows.index(_LEGACY_MARK) if _LEGACY_MARK in rows else len(rows)
    legacy = _g_log_set(rows[cut + 1:], None)
    value = ""
    for row in rows[:cut]:
        if _EXEC_LEGACY_RE.match(row):
            value = value if legacy is None else legacy
        else:
            value = _g_log_set([row], value)
    return value


def _g_log_set(rows, value):
    """The value the last g_log line of `rows` sets, else `value`."""
    for row in rows:
        m = _G_LOG_RE.match(row)
        if m:
            value = m.group(1) if m.group(1) is not None else m.group(2)
    return value


def plain_log_name(name):
    """Whether a g_log value is a plain file name the add-on can read (no folder, no leading dot)."""
    return bool(_LOG_NAME_RE.fullmatch(name or ""))


def game_port(game_type, configured, udp):
    """(the port the add-on reaches the game on, or None, and why not) from the UDP ports the account listens on.

    `udp` is what probe_sh read (the account's own listening sockets). The configured port when the game
    listens there, or when nothing of the account's is listening (a game that is stopped). When the game
    listens elsewhere on exactly one port, that one: LinuxGSM's ET start passes no port, so its config's
    port can be ignored. A LIVE_PORT_GAMES game must be running, since nothing else says its real port.
    """
    if configured in udp or (not udp and game_type not in LIVE_PORT_GAMES):
        return configured, ""
    if len(udp) == 1:
        return udp[0], ""
    return (configured, "") if udp else (None, _START_FIRST)


def geo_mode(value):
    """A geolocation setting as one of GEO_MODES: a record's older true/false is online/off; anything else off."""
    if value is True:
        return GEO_ONLINE
    return value if value in GEO_MODES else GEO_OFF


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


def rcon_password(cfg_text, name="rcon_password"):
    """The last value a CoD server config sets for `name` (rcon_password or rconpassword), or ""."""
    found = ""
    for m in _RCON_RE[name].finditer(cfg_text or ""):
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


def _log_sh(game_type, cfg):
    """The probe's lines that find the game's log (see probe_sh): logdir=, or a G_LOG_DIR game's glog.b64= and logs.b64=.

    For a G_LOG_DIR game: its config's g_log and `exec legacy.cfg` lines, _LEGACY_MARK, then the g_log
    lines of the legacy.cfg the game runs (its fs_game folder's first, as the game looks there first,
    else the one beside the config), and the file names in G_LOG_DIR's folder.
    """
    if game_type not in G_LOG_DIR:
        where, name = _GAME_LOG.get(game_type, _LOG_DEFAULT)
        return ('l=$(find %s -maxdepth 3 -type f -name %s -printf "%%T@ %%h\\n" '
                '2>/dev/null | sort -nr | head -n 1 | cut -d" " -f2-); echo "logdir=$l"; ' % (where, shlex.quote(name)))
    folder, grep = G_LOG_DIR[game_type], shlex.quote(_G_LOG_GREP)
    legacy = " ".join(shlex.quote(d + "/legacy.cfg") for d in (folder, cfg.rsplit("/", 1)[0]))
    return ('echo "glog.b64=$({ grep -iE %s %s; echo %s; for f in %s; do [ -f "$f" ] && { grep -iE %s "$f"; break; }; '
            'done; } 2>/dev/null | head -c 4000 | base64 -w0)"; '
            'echo "logs.b64=$(find %s -maxdepth 1 -type f -printf "%%f\\n" 2>/dev/null | head -c 8000 | base64 -w0)"; '
            % (grep, shlex.quote(cfg), shlex.quote(_LEGACY_MARK), legacy, grep, shlex.quote(folder)))


# The game config's RCON password lines (either name, with or without set/seta), at most 4000 bytes, base64.
_RCON_LINES_SH = ('grep -iE "^[[:space:]]*(seta?[[:space:]]+)?rcon_?password[[:space:]]" %s 2>/dev/null '
                  '| head -c 4000 | base64 -w0')


def probe_sh(addon_id, selfname, server_id, game_type, nports):
    """The install's first read, as the account: the host, the game's log folder, RCON, free ports.

    Prints os=, podman=, splice=1 (pasta has --splice-only), uid= and gid= (the account's, for the
    unit's User= and Group=), udp= (the UDP ports the account's own processes listen on: game_port),
    logdir= (the folder of the newest game log, game_log_name: games_mp.log
    under serverfiles, or the game's own folder in the home: LinuxGSM sets fs_homepath only for
    cod4server, so CoD1 and United Offensive write under ~/.callofduty, CoD2 under ~/.callofduty2 and
    World at War under ~/.codwaw; SoF2's under ~/.sof2, ET's under serverfiles; for ET: Legacy, whose
    log g_log names, glog.b64= and logs.b64= instead: _log_sh), rcon.b64= (the config's rcon_password and rconpassword lines, base64:
    game_rcon picks the game's own), ports= (the first `nports` free host ports from PORT_BASE + the
    server id), installed=1 when the add-on is already there, and for a Source game sourcemod=1 when
    SourceMod is installed (SOURCEMOD_DIR). An add-on that reads the world (BlueMap) reads no log and no
    RCON password: its lines are addons_bluemap.world_sh's instead.
    """
    ports = " ".join(str(PORT_BASE + int(server_id) + i) for i in range(_PORT_TRIES))
    return (_ENV + '. /etc/os-release 2>/dev/null; echo "os=${VERSION_ID:-}"; '
            'echo "podman=$(podman --version 2>/dev/null | head -n 1)"; '
            'pasta --help 2>&1 | grep -q -- "--splice-only" && echo splice=1; echo "uid=$(id -u)"; echo "gid=$(id -g)"; '
            + _game_reads_sh(addon_id, game_type, selfname) +
            'f=""; n=0; for p in %s; do [ $n -ge %d ] && break; '
            'if ! ss -Htln "sport = :$p" 2>/dev/null | grep -q .; then f="$f $p"; n=$((n + 1)); fi; done; '
            'echo "ports=$f"; echo "udp=$(ss -Hulnp 2>/dev/null | grep -F "users:((" | awk \'{print $4}\' '
            '| sed "s/.*://" | sort -un | tr "\\n" " ")"; [ -f %s ] && echo installed=1; %strue'
            % (ports, int(nports), shlex.quote("%s/%s/%s" % (HOME_DIR, addon_id, META_FILE)),
               "[ -d %s ] && echo sourcemod=1; " % shlex.quote(SOURCEMOD_DIR[game_type])
               if game_type in SOURCEMOD_DIR else ""))


def _game_reads_sh(addon_id, game_type, selfname):
    """The probe's lines on what the add-on reads of the game: its log and RCON lines, or (BlueMap) its world."""
    if CATALOG[addon_id]["reads"] == "world":
        from panel.services import addons_bluemap as _bm     # it imports world_reset, which needs ssh_manager
        return _bm.world_sh()
    cfg = game_cfg(game_type, selfname)
    return _log_sh(game_type, cfg) + 'echo "rcon.b64=$(%s)"; ' % (_RCON_LINES_SH % shlex.quote(cfg))


# The game's log folder as the probe prints it, relative to the home: plain path words only, since it
# goes into the unit file (where `%` is a specifier and a line break a new key). A segment may start
# with one dot (CoD1's ~/.callofduty/main), never be `..`.
_LOGDIR_RE = re.compile(r"\.?[A-Za-z0-9_+-][A-Za-z0-9._+-]*(?:/\.?[A-Za-z0-9_+-][A-Za-z0-9._+-]*){0,3}")


def log_dir(user, rel):
    """The game log's folder as an absolute path in the account's home, or "" when `rel` is not plain."""
    if not _LOGDIR_RE.fullmatch(rel or "") or ".." in rel.split("/"):
        return ""
    return "/home/%s/%s" % (user, rel)


def _probe_log(kv, game_type):
    """(the game log's folder, its file name, whether it is there) from the probe's lines (see parse_probe)."""
    if game_type not in G_LOG_DIR:
        return kv.get("logdir", ""), game_log_name(game_type), bool(kv.get("logdir"))
    name = etl_g_log(_unb64(kv.get("glog.b64", "")))
    return G_LOG_DIR[game_type], name, plain_log_name(name) and name in _unb64(kv.get("logs.b64", "")).splitlines()


def parse_probe(out, game_type=""):
    """What probe_sh found for `game_type`: {os, podman, splice, ids, logdir, log_name, log_found, rcon_lines, ...}.

    ids is (uid, gid), or None unless both are plain numbers above 0. logdir is the game log's folder
    (relative to the home), log_name its file name (B3's game_log), log_found whether it is there. For
    a G_LOG_DIR game the folder is fixed, and the name is the g_log the server ends up with (etl_g_log):
    found when it is a plain file name and that file is in the folder.
    """
    kv = kv_lines(out)
    ids = (kv.get("uid", ""), kv.get("gid", ""))
    ids = (int(ids[0]), int(ids[1])) if all(x.isdecimal() and 0 < int(x) < 2 ** 31 for x in ids) else None
    logdir, name, found = _probe_log(kv, game_type)
    return {"os": kv.get("os", ""), "podman": kv.get("podman", ""), "splice": kv.get("splice") == "1", "ids": ids,
            "logdir": logdir, "log_name": name, "log_found": found, "rcon_lines": _unb64(kv.get("rcon.b64", "")),
            "ports": [int(p) for p in kv.get("ports", "").split() if p.isdecimal()],
            "udp": [int(p) for p in kv.get("udp", "").split() if p.isdecimal() and 0 < int(p) < 65536],
            "installed": kv.get("installed") == "1", "sourcemod": kv.get("sourcemod") == "1"}


def status_sh():
    """One read of every add-on of this account: os=, podman=, and per add-on meta.<id>= and state.<id>=.

    For an installed add-on that reads the world (BlueMap) also disk.<id>= (its folder's size in KiB, given
    5 seconds at low priority, "" past them) and mcver.<id>= (the version the game logged at its last
    start: a newer one than its record's offers Update).
    """
    rows = []
    for k in ADDON_IDS:
        meta = shlex.quote("%s/%s/%s" % (HOME_DIR, k, META_FILE))
        rows.append('[ -f %s ] && { echo "meta.%s=$(head -c 4000 %s | base64 -w0)"; '
                    'echo "state.%s=$(systemctl --user is-active %s.service 2>/dev/null | head -n 1)"; %s}; '
                    % (meta, k, meta, k, unit_name(k), _world_status_sh(k) + _b3_status_sh(k)))
    return (_ENV + '. /etc/os-release 2>/dev/null; echo "os=${VERSION_ID:-}"; '
            'echo "podman=$(podman --version 2>/dev/null | head -n 1)"; ' + "".join(rows) + "true")


def _world_status_sh(k):
    """status_sh's extra lines for add-on `k` when it reads the world: its folder's size and the game's version."""
    if CATALOG[k]["reads"] != "world":
        return ""
    from panel.services import addons_bluemap as _bm     # it imports world_reset, which needs ssh_manager
    return ('echo "disk.%s=$(timeout 5 nice -n 19 du -sk --one-file-system -- %s 2>/dev/null | cut -f1)"; %s'
            % (k, shlex.quote("%s/%s" % (HOME_DIR, k)), _bm.version_sh("mcver." + k)))


def _b3_status_sh(k):
    """status_sh's extra lines for B3: its health file, its last exit status and its service settings (b3_control)."""
    if k != B3:
        return ""
    from panel.services import b3_control as _b3c     # it imports this module
    return _b3c.status_sh("%s/%s" % (HOME_DIR, k))


def parse_status(out):
    """What status_sh found: {os, podman, addons: {id: {meta dict, state, disk_kb, mc_version}}} for the installed ones.

    disk_kb is None when it was not read (an add-on that does not read the world, or a slow du). An
    installed B3 also has "b3": b3_control.parse_status's {health, exit, svc, now}.
    """
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
        disk = kv.get("disk." + k, "")
        found[k] = {"meta": meta if isinstance(meta, dict) else {},
                    "state": state if state in _STATES else "unknown",
                    "disk_kb": int(disk) if disk.isdecimal() and len(disk) < 16 else None,
                    "mc_version": kv.get("mcver." + k, "")}
    if B3 in found:
        from panel.services import b3_control as _b3c     # it imports this module
        found[B3]["b3"] = _b3c.parse_status(kv, _unb64)
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


def game_rcon(game_type, rcon_lines):
    """(the RCON password the game reads, or "", and why not: _RCON_RENAME or "") from the config's lines.

    Only the game's own setting (RCON_SETTING) counts. A config that sets only the other name, which
    the game ignores, gets the sentence that says to rename it.
    """
    name = RCON_SETTING.get(game_type, "rcon_password")
    value = rcon_password(rcon_lines, name)
    if value or name != "rcon_password":
        return value, ""
    return "", _RCON_RENAME if rcon_password(rcon_lines, "rconpassword") else ""


def b3_ini_refusal(rcon):
    """Why B3's ini can't hold this RCON password ("" when it can).

    B3 reads b3.ini with ConfigParser: a value loses its leading and trailing blanks, and a `;`
    after a blank starts a comment (b3/config.py, inline_comment_prefixes).
    """
    return _B3_RCON_REFUSAL if rcon != rcon.strip() or re.search(r"\s;", rcon) else ""


def b3_plugin_line(name):
    """The b3.ini [plugins] line for plugin `name`, with its settings file in the add-on's conf folder."""
    return "%s: @conf/conf/plugin_%s.%s" % (name, name, "xml" if name in _B3_XML else "ini")


def b3_plugins(geolocation, chosen=B3_PLUGINS):
    """The plugins b3.ini turns on: admin, the `chosen` switchable ones, and geolocation's when it is on."""
    on = geo_mode(geolocation) != GEO_OFF
    geo = B3_GEO_PLUGINS + tuple(p for p in B3_GEO_SWITCHABLE if p in chosen) if on else ()
    return ("admin",) + tuple(p for p in B3_SWITCHABLE if p in chosen) + geo     # geolocation before what needs it


def b3_ini(game_type, game_port, rcon, db_name, db_secret, geolocation, chosen=B3_PLUGINS, log_name=None):
    """b3.ini for one server, as text (it holds the RCON and database passwords).

    `log_name` is the game log's file name when the probe read it (parse_probe), else game_log_name's.

    The database is reached at 127.0.0.1:3306 inside the container, which network() forwards. The
    panel's database names and passwords are letters, digits and - _ . only
    (ssh_manager/databases.new_password), so they need no quoting in the URL.
    """
    lines = [
        "; Written by linuxgsm-panel: the B3 add-on of this game server. Reinstalling rewrites it.",
        "[b3]", "parser: %s" % CATALOG[B3]["games"][game_type],
        "database: mysql://%s:%s@127.0.0.1:3306/%s" % (db_name, db_secret, db_name),
        "bot_name: b3", "bot_prefix: ^0(^2b3^0)^7:", "time_format: %I:%M%p %Z %m/%d/%y", "time_zone: UTC",
        "log_level: 20", "logfile: @conf/b3.log", "disabled_plugins:", "external_plugins_dir: %s" % _B3_EXT_DIR[False],
        "", "[server]", "rcon_password: %s" % rcon, "port: %d" % int(game_port),
        "game_log: /gamelog/%s" % (log_name or game_log_name(game_type)), "public_ip: 127.0.0.1", "rcon_ip: 127.0.0.1",
        "punkbuster: off",
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
    ] + [b3_plugin_line(p) for p in b3_plugins(geolocation, chosen)]
    return "\n".join(lines) + "\n"


# The [plugins] lines the panel owns in b3.ini: every plugin the card can turn on or off, and admin.
_B3_OWNED = frozenset(("admin",) + B3_SWITCHABLE + B3_GEO_SWITCHABLE + B3_GEO_PLUGINS)
_INI_KEY_RE = re.compile(r"^[ \t]*([A-Za-z0-9_.-]+)[ \t]*[:=]")
_INI_SECTION_RE = re.compile(r"^[ \t]*\[([^\]]+)\]")


def _ini_lines(text):
    """An ini file's lines, without the empty string a final newline leaves."""
    lines = (text or "").split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def _sections(lines):
    """Each line's section (lower case; "" before the first header), in order."""
    out, section = [], ""
    for line in lines:
        m = _INI_SECTION_RE.match(line)
        if m:
            section = m.group(1).strip().lower()
        out.append(section)
    return out


def _ini_key(line):
    """The key a `key: value` (or `key = value`) line sets, lower case; "" for any other line."""
    k = _INI_KEY_RE.match(line)
    return k.group(1).lower() if k else ""


def _header_at(lines, name):
    """The index of section `name`'s first header line, or None."""
    for i, line in enumerate(lines):
        m = _INI_SECTION_RE.match(line)
        if m and m.group(1).strip().lower() == name:
            return i
    return None


def _section_end(lines, at):
    """The index after the last line of the section headed at `at` that is not blank."""
    end = at + 1
    while end < len(lines) and not _INI_SECTION_RE.match(lines[end]):
        end += 1
    while end > at + 1 and not lines[end - 1].strip():
        end -= 1
    return end


def _into_section(lines, name, new, at_end):
    """`lines` with `new` put in section `name`: after its header, or (`at_end`) after its last line that is not blank.

    The section is added at the end when the file has none.
    """
    at = _header_at(lines, name)
    if at is None:
        return lines + ([""] if lines else []) + ["[%s]" % name] + new
    end = _section_end(lines, at) if at_end else at + 1
    return lines[:end] + new + lines[end:]


def b3_ini_apply(text, geolocation, chosen, own_plugins=False, service=None):
    """`text` (b3.ini) with the [plugins] lines the panel owns set to `chosen` and the geolocation mode.

    Every other line is kept as it was: the passwords, the operator's own settings, comments, and the
    [plugins] lines of plugins the panel does not offer (an operator's external plugin). The owned lines
    are dropped where they were and the ones turned on are written at the end of [plugins], which is
    added when the file has none. [b3] external_plugins_dir is the panel's too: the own-plugins folder
    with `own_plugins`, else B3's own. With `service` ({actions, purge}), [b3] control_socket is written
    only while Panel actions is on (else removed: B3 then opens no socket) and purge_aliases_days only
    when it is set (else removed: B3 keeps aliases for good, its default).
    """
    lines = _ini_lines(text)
    keep = [ln for ln, sec in zip(lines, _sections(lines)) if not (sec == "plugins" and _ini_key(ln) in _B3_OWNED)]
    want = {"external_plugins_dir": _B3_EXT_DIR[bool(own_plugins)]}
    if service is not None:
        keep = _b3_service(keep, service, want)
    keep = _ini_set(keep, "b3", want)
    return "\n".join(_into_section(keep, "plugins", [b3_plugin_line(p) for p in b3_plugins(geolocation, chosen)],
                                   at_end=True)) + "\n"


def _b3_service(lines, service, want):
    """`lines` without [b3]'s control_socket / purge_aliases_days while off; `want` gets them while on."""
    from panel.services import b3_control as _b3c     # it imports this module
    on = {"control_socket": _b3c.SOCKET_LINE if service.get("actions") else None,
          "purge_aliases_days": int(service["purge"]) if service.get("purge") else None}
    want.update({k: v for k, v in on.items() if v is not None})
    return [ln for ln, sec in zip(lines, _sections(lines)) if not (sec == "b3" and on.get(_ini_key(ln), 1) is None)]


def _ini_set(lines, section, want):
    """`lines` with each key of `want` set in `section`: its first line rewritten, a repeat dropped, a missing one added.

    A missing key goes right after the section's header (the section is added when there is none).
    """
    out, done = [], set()
    for line, sec in zip(lines, _sections(lines)):
        key = _ini_key(line)
        if sec == section and key in want:
            if key not in done:
                out.append("%s: %s" % (key, want[key]))
                done.add(key)
            continue
        out.append(line)
    return _into_section(out, section, ["%s: %s" % (k, v) for k, v in want.items() if k not in done], at_end=False)


def b3_ini_plugins(text):
    """The owned plugins b3.ini turns on (its [plugins] keys among those the panel offers), in order."""
    on, section = [], ""
    for line in (text or "").split("\n"):
        m = _INI_SECTION_RE.match(line)
        if m:
            section = m.group(1).strip().lower()
            continue
        k = _INI_KEY_RE.match(line)
        if section == "plugins" and k and k.group(1).lower() in _B3_OWNED and k.group(1).lower() not in on:
            on.append(k.group(1).lower())
    return on


def geolocation_ini(text, geolocation):
    """plugin_geolocation.ini with [settings] geolocators and mmdb_file set for `geolocation`.

    The two keys are the panel's; the rest of an existing file (the operator's comments and anything
    else) is kept. Offline asks only the database in the add-on's geoip folder, online only ipwho.is
    (the service the relay reaches). Off leaves the file as it is (the plugin is not loaded).
    """
    mode = geo_mode(geolocation)
    if mode == GEO_OFF:
        return text
    want = {"geolocators": _GEOLOCATORS[mode], "mmdb_file": "/geoip/dbip-country-lite.mmdb"}
    return "\n".join(_ini_set(_ini_lines(text), "settings", want)) + "\n"


def build_files(addon_id):
    """The files an add-on built on the host needs ({path in its folder: text}), from panel/addon_images/<build>/."""
    build = CATALOG[addon_id]["build"]
    if not build:
        return {}
    base = os.path.join(_IMAGES_DIR, build)
    got = {}
    for name in BUILD_FILES:
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
    if addon_id == B3 and geo_mode(geolocation) == GEO_ONLINE:
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


def network(game_port, db_port, relay_list, splice, rcon_tcp=False):
    """The container's Network= value: pasta, reaching only what it forwards to the host's loopback.

    -U the game's RCON port (UDP), or -T with `rcon_tcp` (a Source game: RCON_TCP_GAMES); none when `game_port` is
    None (BlueMap reaches nothing of the game). -T the database's port (TCP) when the database is on this host
    (`db_port`, seen at 3306 inside), and each relay's (`relay_list`, from relays()). Then the lock:
    --splice-only where pasta has it, else -4 and -o 127.0.0.1 (see the module's NETWORK note).
    """
    opts = ["--splice-only"] if splice else ["-4", "-o", "127.0.0.1"]
    if game_port is not None:
        opts += ["-T" if rcon_tcp else "-U", str(int(game_port))]
    if db_port:
        opts += ["-T", "3306:%d" % int(db_port)]
    for _name, _addr, cport, hport, _target in relay_list:
        opts += ["-T", "%d:%d" % (int(cport), int(hport))]     # no address: -T takes none
    return "pasta:" + ",".join(opts)


def _podman_args(addon_id, relay_list):
    a = CATALOG[addon_id]
    args = ["--memory=%s" % MEMORY, "--stop-timeout=%d" % a["stop_timeout"], "--dns=none"]
    if a["stop_signal"] != "SIGTERM":
        args.append("--stop-signal=%s" % a["stop_signal"])
    args += ["--add-host=%s:%s" % (name, addr) for name, addr in B3_GEOLOCATORS
             if any(r[4] == "%s:443" % name for r in relay_list)]
    return "PodmanArgs=" + " ".join(args)


def _volumes(user, addon_id, logdir, own_plugins):
    """The unit's Volume= lines: the add-on's folders, the game log (or BlueMap's worlds) read-only, B3's own plugins read-only."""
    base = addon_dir(user, addon_id)
    vols = ["Volume=%s/%s:%s" % (base, d, at) for d, at in CATALOG[addon_id]["mounts"]]
    if CATALOG[addon_id]["reads"] == "world":
        vols += ["Volume=%s" % m for m in logdir.mounts]
    else:
        vols.append("Volume=%s:/gamelog:ro" % logdir)
    if own_plugins and addon_id == B3:
        vols.append("Volume=%s/%s:/data/extplugins:ro" % (base, B3_OWN_PLUGINS))
    return vols


def quadlet(user, addon_id, logdir, net, port, relay_list=(), ids=None, own_plugins=False):
    """The add-on's Quadlet unit text (~/.config/containers/systemd/<unit>.container).

    `ids` is the account's (uid, gid): with keep-id they are the process's user inside, set
    explicitly because on Podman 4.9 an image's own USER wins over keep-id's default. With
    `own_plugins` (B3), the own-plugins folder is mounted read-only over its place in /data, so B3
    cannot change the code it runs from there. For an add-on that reads the world (BlueMap), `logdir`
    is an addons_bluemap.World: its worlds' read-only mounts, and the Minecraft version its command ends with.
    """
    a = CATALOG[addon_id]
    needs = ["%s%s-%s.socket" % (UNIT_PREFIX, addon_id, r[0]) for r in relay_list]
    vols = _volumes(user, addon_id, logdir, own_plugins)
    lines = [
        "# Written by linuxgsm-panel: the %s add-on of this game server. The panel rewrites it." % a["name"],
        "[Unit]", "Description=%s (linuxgsm-panel add-on)" % a["name"],
        "StartLimitIntervalSec=%d" % RESTART_WINDOW, "StartLimitBurst=%d" % RESTART_BURST,
    ] + ["Requires=%s" % n for n in needs] + ["After=%s" % n for n in needs] + [
        "", "[Container]", "Image=%s" % a["image"], "ContainerName=%s" % unit_name(addon_id), "Pull=never",
        "Network=%s" % net,
    ] + (["PublishPort=127.0.0.1:%d:%d" % (port, a["web_port"])] if a["web_port"] else []) + [
        "Environment=%s" % e for e in a["env"]] + vols + [
        # keep-id maps the game account's own uid into the container, and User=/Group= run the add-on
        # as it (not as root there), so the files it writes in its folder belong to the account. Both
        # are needed: on Podman 4.9.3 an image's own USER (B3's 65534) wins over keep-id's default.
        "UserNS=keep-id",
    ] + (["User=%d" % ids[0], "Group=%d" % ids[1]] if ids else []) + [
        "ReadOnly=true", "DropCapability=all", "NoNewPrivileges=true", "PidsLimit=%d" % PIDS,
        "HealthCmd=none", _podman_args(addon_id, relay_list),
    ] + _exec_lines(a, logdir) + [
        # always: an add-on that quits, even with status 0, is started again (IW4MAdmin exits 0 on a
        # fatal error); the start limit above stops a loop, and a stop from the panel never restarts.
        "", "[Service]", "Restart=always", "RestartSec=30", "TimeoutStartSec=300",
    ] + _service_extra(a) + [
        "", "[Install]", "WantedBy=default.target", "",
    ]
    return "\n".join(lines)


def _exec_lines(a, logdir):
    """The unit's Exec= line: the add-on's command (the image's own entrypoint takes it), then the World's version."""
    if not a["command"]:
        return []
    return ["Exec=%s" % " ".join(a["command"] + ((logdir.version,) if a["reads"] == "world" else ()))]


def _service_extra(a):
    """The [Service] lines an add-on adds: the exit status its stop ends with, a lower CPU priority, no restart on some exits.

    RestartPreventExitStatus= keeps Restart=always from starting again an add-on that exited with a code
    no restart can mend (B3's invalid settings, or its !die): the unit stays failed with that code, which
    the card says in words, instead of five restarts into the start limit.
    """
    return ((["SuccessExitStatus=%s" % a["success_exit"]] if a["success_exit"] else [])
            + (["Nice=%d" % a["nice"]] if a["nice"] else [])
            + (["RestartPreventExitStatus=%s" % a["no_restart"]] if a.get("no_restart") else []))


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


def _fresh_start_sh(addon_id, verb):
    """Shell for a start or restart the operator asked for: the unit's start limit cleared first.

    The unit's StartLimitBurst counts every start in RESTART_WINDOW, the operator's too, so the sixth
    Apply or Update within it left the add-on down (`start-limit-hit`). `reset-failed` clears that
    count (systemctl(1)), so the limit is left for Restart=always's crash loops. A start that still
    hits it prints ADDON_START_LIMIT, so the card says so instead of pointing at a clean log.
    Sets t0 to the time just before the start, so a failure's tail (_tail_sh) shows this start's lines.
    """
    unit = unit_name(addon_id)
    return ("t0=$(date +%%s); systemctl --user reset-failed %s.service 2>/dev/null; systemctl --user %s %s.service "
            "|| { rc=$?; "
            "[ \"$(systemctl --user show -p Result --value %s.service 2>/dev/null)\" = start-limit-hit ] "
            "&& echo ADDON_START_LIMIT; (exit $rc); }" % (unit, verb, unit, unit))


# A line Podman itself logs into the unit's journal (an event: "container died <id> (image=...)"),
# which buries the add-on's own lines; matched with or without journalctl's short-iso prefix.
_PODMAN_EVENT_ERE = "(^|: )(container|image|pod|volume|network) [a-z_-]+ [0-9a-f]{12,64}( |$)"


def _journal_sh(addon_id, lines, fmt, since=False):
    """Shell printing the add-on's own last `lines` journal lines (its container's output).

    The lines its container wrote (CONTAINER_NAME, set by Podman's journald log driver); when there
    are none, the unit's journal without Podman's own event lines. With `since`, only the lines
    from $t0 on (the epoch second _fresh_start_sh took before the start). Fails when it printed none.
    """
    unit = unit_name(addon_id)
    after = " --since \"@$t0\"" if since else ""
    return ("o=$(journalctl --user CONTAINER_NAME=%s%s -n %d --no-pager -o %s 2>/dev/null "
            "| grep -v '^-- No entries --$'); "
            "[ -n \"$o\" ] || o=$(journalctl --user -u %s.service%s -n %d --no-pager -o %s 2>/dev/null "
            "| grep -vE '%s' | grep -v '^-- No entries --$' | tail -n %d); [ -n \"$o\" ] && printf '%%s\\n' \"$o\""
            % (unit, after, lines, fmt, unit, after, lines * 4, fmt, _PODMAN_EVENT_ERE, lines))


def _tail_sh(user, addon_id):
    """Shell printing the last log lines of the start that just failed (at most TAIL_LINES from each source).

    After a start (t0 set by _fresh_start_sh): its own log file's tail if this start wrote to it, then
    the journal's lines since the start. A B3 that dies checking b3.ini writes only to the journal, and
    its b3.log still ends with the last clean shutdown, so that file alone pointed at a clean log (VPS
    round D, O-D1). With neither, or no t0: the log file's tail if it has one, else the journal's.
    """
    a = CATALOG[addon_id]
    journal = _journal_sh(addon_id, TAIL_LINES, "cat")
    fresh = _journal_sh(addon_id, TAIL_LINES, "cat", since=True)
    if not a["log_file"]:
        return "{ { [ -n \"${t0:-}\" ] && { %s; }; } || { %s; }; }" % (fresh, journal)
    own = shlex.quote("%s/%s" % (addon_dir(user, addon_id), a["log_file"]))
    return ("{ n=; if [ -n \"${t0:-}\" ]; then "
            "if [ -s %s ] && [ \"$(stat -c %%Y %s 2>/dev/null || echo 0)\" -ge \"$t0\" ]; then tail -n %d %s; n=1; fi; "
            "{ %s; } && n=1; fi; "
            "[ -n \"$n\" ] || { { [ -s %s ] && tail -n %d %s; } || { %s; }; }; }"
            % (own, own, TAIL_LINES, own, fresh, own, TAIL_LINES, own, journal))


def _settle_sh(user, addon_id):
    """Shell that watches the started unit for SETTLE_SECONDS: active the whole time and never restarted.

    Otherwise it stops the unit (so it does not restart in a loop), prints ADDON_DIED and the last
    TAIL_LINES of its log (base64), and exits 26.
    """
    unit = unit_name(addon_id)
    # systemd counts NRestarts from the last start it was told to make (a start that is not an automatic
    # restart resets it: src/core/service.c service_start), so after the install's start or a change's restart any restart at all is the add-on failing.
    return ("i=0; while [ $i -lt %d ]; do sleep 2; i=$((i + 2)); "
            "s=$(systemctl --user is-active %s.service 2>/dev/null); "
            "r=$(systemctl --user show -p NRestarts --value %s.service 2>/dev/null); "
            "if [ \"$s\" != active ] || [ \"${r:-0}\" != 0 ]; then systemctl --user stop %s.service 2>/dev/null; "
            "echo ADDON_DIED; %s | tail -c 4000 | base64 -w0 | sed 's/^/tail.b64=/'; echo; exit 26; fi; done; "
            % (SETTLE_SECONDS, unit, unit, unit, _tail_sh(user, addon_id)))


def install_sh(user, addon_id, unit_text, meta_text, files=None, units=None, extra=""):
    """The install's second step, as the account: write the files, get the image, start, watch.

    The settings (which hold the passwords) arrive on stdin, never on a command line; the unit, the
    relays' units (`units`), the plugin or build files (`files`, relative to the add-on's folder)
    and the panel's record are base64 here (they hold no secret). Every file is 0600 and every
    folder 0700. `extra` is shell run before the image is fetched (BlueMap's client file:
    addons_bluemap.client_sh). Ends with ADDON_INSTALLED, or one of _FAIL_MARKS.
    """
    a = CATALOG[addon_id]
    d = addon_dir(user, addon_id)
    q = "/home/%s/%s" % (user, QUADLET_DIR)
    uu = "/home/%s/%s" % (user, USER_UNIT_DIR)
    unit = unit_name(addon_id)
    dirs = _dirs(d, a, files)
    early = [_put_sh("%s/%s" % (d, META_FILE), meta_text)]
    early += [_put_sh("%s/%s" % (d, rel), text) for rel, text in sorted((files or {}).items())]
    # The units are written only once the image exists: a user manager that comes up meanwhile
    # (lingering was just turned on) would start the unit through default.target and fail on an
    # image it doesn't have yet.
    late = [_put_sh("%s/%s.container" % (q, unit), unit_text)]
    late += [_put_sh("%s/%s" % (uu, name), text) for name, text in sorted((units or {}).items())]
    secret = shlex.quote("%s/%s" % (d, a["settings"]))
    return (_ENV + "umask 077; mkdir -p %s %s %s || { echo ADDON_WRITE_FAILED; exit 20; }; "
            "cat > %s.new && mv -f -T %s.new %s && %s || { echo ADDON_WRITE_FAILED; exit 21; }; "
            "i=0; while [ ! -S \"$XDG_RUNTIME_DIR/bus\" ] && [ $i -lt 20 ]; do sleep 1; i=$((i + 1)); done; "
            "[ -S \"$XDG_RUNTIME_DIR/bus\" ] || { echo ADDON_NO_USER_MANAGER; exit 22; }; "
            "podman system migrate >/dev/null 2>&1; %s%s"
            "%s || { echo ADDON_WRITE_FAILED; exit 21; }; "
            "systemctl --user daemon-reload && { %s; } "
            "|| { systemctl --user stop %s.service 2>/dev/null; echo ADDON_START_FAILED; "
            "%s | tail -c 4000 | base64 -w0 | sed 's/^/tail.b64=/'; echo; exit 25; }; "
            "%secho %s"
            % (dirs, shlex.quote(q), shlex.quote(uu), secret, secret, secret, " && ".join(early), extra,
               _image_sh(addon_id, shlex.quote(d)), " && ".join(late), _fresh_start_sh(addon_id, "start"), unit,
               _tail_sh(user, addon_id),
               _settle_sh(user, addon_id), _MARK_INSTALLED))


def _dirs(d, a, files, extra=()):
    """The add-on's folders to make, quoted: its mounts', the build folder, each file's own, and `extra`."""
    rels = ([m for m, _at in a["mounts"]] + [BUILD_DIR] + sorted({os.path.dirname(r) for r in (files or {})} - {""})
            + list(extra))
    return " ".join(shlex.quote("%s/%s" % (d, r)) for r in rels)


def _relays_gone_sh(user, addon_id):
    """Shell stopping and removing the add-on's relay units (a settings change or an update writes its own)."""
    return ("for f in /home/%s/%s/%s%s-*; do [ -e \"$f\" ] || continue; systemctl --user stop \"${f##*/}\" "
            "2>/dev/null; rm -f \"$f\"; done; " % (user, USER_UNIT_DIR, UNIT_PREFIX, addon_id))


def reconfigure_sh(user, addon_id, unit_text, meta_text, files=None, units=None, how=None):
    """A settings change or an update, as the account: rewrite, restart, watch. Ends like install_sh.

    Writes the record, `files` and, with how["settings"], the settings file from stdin (b3.ini holds the
    passwords); with how["rebuild"], pulls or builds the image again. The relay units are replaced by
    `units` and the unit by `unit_text`, then the add-on restarts and is watched as an install is.
    how["dirs"] are more folders of the add-on to make (B3's own-plugins folder, when it is mounted).
    how["extra"] is shell run before the image (BlueMap's client file: addons_bluemap.client_sh).
    Its data, settings and database stay. how["old_image"], when the update moved it, is removed afterwards.
    how["check"] (B3's settings check, b3_control.check_sh) runs after the new settings file is written
    beside the old one and before anything is moved into place; it exits on a refusal. how["reload"]
    (b3_control.reload_sh) runs once the files are in place and, when B3 can take them without a restart,
    reloads it and exits before the unit is touched.
    """
    how = how or {}
    rebuild, settings, old_image = how.get("rebuild", False), how.get("settings", False), how.get("old_image", "")
    a = CATALOG[addon_id]
    d = addon_dir(user, addon_id)
    folders = _dirs(d, a, files, how.get("dirs", ()))
    unit = unit_name(addon_id)
    q = "/home/%s/%s" % (user, QUADLET_DIR)
    uu = "/home/%s/%s" % (user, USER_UNIT_DIR)
    secret = shlex.quote("%s/%s" % (d, a["settings"]))
    early = [_put_sh("%s/%s" % (d, META_FILE), meta_text)]
    early += [_put_sh("%s/%s" % (d, rel), text) for rel, text in sorted((files or {}).items())]
    late = [_put_sh("%s/%s.container" % (q, unit), unit_text)]
    late += [_put_sh("%s/%s" % (uu, name), text) for name, text in sorted((units or {}).items())]
    stdin, move = _settings_io(secret, settings)
    drop = ("podman rmi %s >/dev/null 2>&1; " % shlex.quote(old_image)) if old_image and old_image != a["image"] else ""
    # The user manager first: B3's check runs Podman, which needs it, before anything is written.
    return (_ENV + "umask 077; mkdir -p %s %s %s || { echo ADDON_WRITE_FAILED; exit 20; }; "
            "[ -S \"$XDG_RUNTIME_DIR/bus\" ] || { echo ADDON_NO_USER_MANAGER; exit 22; }; "
            "%s%s%s%s || { echo ADDON_WRITE_FAILED; exit 21; }; %s%s%s"
            "%s%s || { echo ADDON_WRITE_FAILED; exit 21; }; "
            "systemctl --user daemon-reload && { %s; } "
            "|| { systemctl --user stop %s.service 2>/dev/null; echo ADDON_START_FAILED; "
            "%s | tail -c 4000 | base64 -w0 | sed 's/^/tail.b64=/'; echo; exit 25; }; "
            "%s%secho %s"
            % (folders, shlex.quote(q), shlex.quote(uu), stdin, how.get("check", ""), move, " && ".join(early),
               how.get("reload", ""), how.get("extra", ""),
               _image_sh(addon_id, shlex.quote(d)) if rebuild else "", _relays_gone_sh(user, addon_id),
               " && ".join(late), _fresh_start_sh(addon_id, "restart"), unit, _tail_sh(user, addon_id),
               _settle_sh(user, addon_id), drop,
               _MARK_INSTALLED))


def _settings_io(secret, settings):
    """(the shell writing the settings file from stdin beside the old one, the shell moving it into place); ("", "") without."""
    if not settings:
        return "", ""
    return ("cat > %s.new || { echo ADDON_WRITE_FAILED; exit 21; }; " % secret,
            "mv -f -T %s.new %s && " % (secret, secret))


def b3_conf_read_sh(user):
    """Shell printing B3's b3.ini and plugin_geolocation.ini, base64, as b3ini.b64= and geoini.b64= lines."""
    d = addon_dir(user, B3)
    return ('echo "b3ini.b64=$(head -c 200000 %s 2>/dev/null | base64 -w0)"; '
            'echo "geoini.b64=$(head -c 200000 %s 2>/dev/null | base64 -w0)"; '
            % (shlex.quote("%s/%s" % (d, CATALOG[B3]["settings"])), shlex.quote("%s/%s" % (d, B3_GEO_INI))))


def geoip_put_sh(user, addon_id):
    """Shell, as the account, writing the country database from stdin (base64) into the add-on's geoip folder.

    Prints GEOIP_PUT once it is in place; written beside and renamed, so a reader never sees half a file.
    """
    f = shlex.quote("%s/geoip/%s" % (addon_dir(user, addon_id), "dbip-country-lite.mmdb"))
    g = shlex.quote("%s/geoip" % addon_dir(user, addon_id))
    return (_ENV + "umask 077; mkdir -p %s && base64 -d > %s.new && mv -f -T %s.new %s && echo GEOIP_PUT"
            % (g, f, f, f))


def install_outcome(out, rc):
    """(ok, English sentence or "", log tail or "") from what install_sh printed and its exit status."""
    tail = _unb64(kv_lines(out).get("tail.b64", ""))
    if rc == 0 and _MARK_INSTALLED in (out or ""):
        return True, "", ""
    for mark, said in _FAIL_MARKS.items():
        if mark in (out or ""):
            return False, said, tail
    return False, "The install didn't finish on the host.", tail


def start_sh(user, addon_id, cfg=""):
    """The card's Start, as the account: the start limit cleared, the start, then the install's watch (_settle_sh).

    Its first line is secrets_sh's (`cfg`: the game's config, game_cfg), so a failure's tail is masked
    without another read. Ends with ADDON_STARTED. A start systemd refuses prints ADDON_START_FAILED (with ADDON_START_LIMIT
    when its start limit refused it) and the log's tail; one that stops or restarts within
    SETTLE_SECONDS is stopped, and prints ADDON_DIED and the tail. Without the watch, a crash loop it
    set off ended as a bare "failed": systemd's last result there is exit-code, not start-limit-hit.
    """
    return (_ENV + secrets_sh(user, addon_id, cfg)
            + "{ %s; } || { echo ADDON_START_FAILED; %s | tail -c 4000 | base64 -w0 | sed 's/^/tail.b64=/'; "
            "echo; exit 25; }; %secho %s"
            % (_fresh_start_sh(addon_id, "start"), _tail_sh(user, addon_id), _settle_sh(user, addon_id), _MARK_STARTED))


def start_outcome(out, rc):
    """(ok, the mark that says why not: ADDON_START_LIMIT, ADDON_DIED or "", log tail) from what start_sh printed."""
    tail = _unb64(kv_lines(out).get("tail.b64", ""))
    if rc == 0 and _MARK_STARTED in (out or ""):
        return True, "", ""
    return False, next((m for m in ("ADDON_START_LIMIT", "ADDON_DIED") if m in (out or "")), ""), tail


def action_sh(addon_id, action):
    """Start or stop the add-on's unit, as the account (`action` is "start" or "stop").

    A start is the operator's, so the unit's start limit is cleared first (_fresh_start_sh).
    """
    if action not in ("start", "stop"):
        raise ValueError("unknown add-on action")
    if action == "start":
        return _ENV + _fresh_start_sh(addon_id, "start")
    return _ENV + "systemctl --user stop %s.service" % unit_name(addon_id)


def logs_sh(user, addon_id, cfg=""):
    """The add-on's last LOG_LINES lines, after secrets_sh's line (`cfg`: the game's config, game_cfg).

    Its own log file if it keeps one (B3's b3.log), then, after a JOURNAL_MARK line, its journal's
    lines from after that file's last write (split_journal); else its own journal lines (without
    Podman's event lines), else the newest file in its Log folder. A B3 that dies checking b3.ini
    writes only to the journal, so b3.log alone still ended with the last clean shutdown (VPS round
    E, O-E1). The journal's lines start a second after the file's last write, so a line written to
    both at once is not shown twice.
    """
    a = CATALOG[addon_id]
    own = shlex.quote("%s/%s" % (addon_dir(user, addon_id), a["log_file"])) if a["log_file"] else "''"
    log_dir = shlex.quote(addon_dir(user, addon_id) + "/Log")
    newer = ("m=$(stat -c %%Y %s 2>/dev/null) && j=$(t0=$((m + 1)); %s) && printf '\\n%s\\n%%s\\n' \"$j\"; "
             % (own, _journal_sh(addon_id, LOG_LINES, "short-iso", since=True), JOURNAL_MARK))
    return (_ENV + secrets_sh(user, addon_id, cfg) + "{ if [ -n %s ] && [ -f %s ]; then tail -n %d %s; %selse "
            "%s || { f=$(ls -1t %s 2>/dev/null | head -n 1); [ -n \"$f\" ] && tail -n %d %s/\"$f\"; }; fi; } "
            "| tail -c %d; true"
            % (own, own, LOG_LINES, own, newer, _journal_sh(addon_id, LOG_LINES, "short-iso"), log_dir, LOG_LINES,
               log_dir, LOG_BYTES))


def split_journal(log):
    """(the log file's text, the journal's newer lines or "") from what logs_sh printed after secrets_sh's line."""
    head, mark, journal = (log or "").rpartition("\n%s\n" % JOURNAL_MARK)
    return (head.rstrip("\n"), journal.rstrip("\n")) if mark else (log or "", "")


def remove_sh(user, addon_id):
    """Stop and remove the add-on, its relays, its image, its unit and its folder, as the account.

    The folder goes through `podman unshare`, so a file the container made as one of its own users
    (a subordinate id) goes too. A built image's leftover build layers go with `podman image prune`.
    When it was the account's last add-on, Podman's own storage and files go too (`podman system
    reset`, then what it leaves: see _podman_purge_sh).
    Prints ADDON_REMOVED and others=0/1 (whether another add-on is left).
    The image the unit runs goes as well as the catalog's: an add-on not updated since the catalog's
    image changed runs an older one, which would otherwise stay while another add-on is left.
    """
    unit = unit_name(addon_id)
    d = shlex.quote(addon_dir(user, addon_id))
    home = shlex.quote("/home/%s/%s" % (user, HOME_DIR))
    quadlet = shlex.quote("/home/%s/%s/%s.container" % (user, QUADLET_DIR, unit))
    relay_glob = "/home/%s/%s/%s%s-*" % (user, USER_UNIT_DIR, UNIT_PREFIX, addon_id)
    return (_ENV + "img=$(sed -n 's/^Image=//p' %s 2>/dev/null | head -n 1); "
            "systemctl --user stop %s.service 2>/dev/null; rm -f %s; "
            "for f in %s; do [ -e \"$f\" ] || continue; systemctl --user stop \"${f##*/}\" 2>/dev/null; rm -f \"$f\"; "
            "done; systemctl --user daemon-reload 2>/dev/null; podman rm -f --ignore %s >/dev/null 2>&1; "
            "podman rmi %s >/dev/null 2>&1; "
            "case \"$img\" in ''|-*) ;; *) podman rmi -- \"$img\" >/dev/null 2>&1 ;; esac; "
            "podman image prune -f >/dev/null 2>&1; "
            "podman unshare rm -rf -- %s 2>/dev/null || rm -rf -- %s; "
            "[ -e %s ] && exit 30; rmdir %s 2>/dev/null; "
            "if [ -d %s ]; then echo others=1; else %secho others=0; fi; echo %s"
            % (quadlet, unit, quadlet, relay_glob, unit,
               shlex.quote(CATALOG[addon_id]["image"]), d, d, d, home, home, _podman_purge_sh(user), _MARK_REMOVED))


def _podman_purge_sh(user):
    """Shell removing the account's Podman storage and files once it runs no add-on (best effort).

    `podman system reset` removes images, layers and state but leaves a skeleton (a lock, empty
    store folders, a cache database) and its config folders: those, and its cache, then go whole,
    each only when it is a real folder (not a link) owned by the account, and rm never crosses into
    another file system. The unit folders go when empty.
    """
    h = "/home/%s" % user
    owned = " ".join(shlex.quote(h + "/" + d) for d in (".local/share/containers", ".config/containers", ".config/cni",
                                                         ".cache/containers"))
    return ("podman system reset -f >/dev/null 2>&1; "
            "for p in %s; do if [ -d \"$p\" ] && [ ! -L \"$p\" ] && [ \"$(stat -c %%u \"$p\")\" = \"$(id -u)\" ]; "
            "then rm -rf --one-file-system -- \"$p\"; fi; done; rmdir -- %s %s 2>/dev/null; "
            % (owned, shlex.quote(h + "/" + USER_UNIT_DIR), shlex.quote(h + "/.config/systemd")))


def remove_outcome(out, rc):
    """(removed, another add-on left) from what remove_sh printed."""
    kv = kv_lines(out)
    return (rc == 0 and _MARK_REMOVED in (out or "")), kv.get("others") == "1"


# Shown in place of a secret.
_MASK = "\u2022" * 8
# An RCON password setting and its value, as a config, b3.ini, a JSON file or a command line writes it:
# `rcon_password: v`, `rconpassword=v`, `"rcon_password": "v"`, `set rconpassword "v w"`, `+set rcon_password v`.
_RCON_SET_RE = re.compile(r'(rcon_?password"?[ \t]*[:=][ \t]*|\bseta?[ \t]+"?rcon_?password"?[ \t]+)'
                          r'("[^"\r\n]*"|[^\s"]+)', re.I)
# b3.ini's RCON password lines (ConfigParser: `key: value` or `key = value`).
_INI_RCON_RE = re.compile(r"^[ \t]*rcon_?password[ \t]*[:=]([^\r\n]*)", re.I | re.M)
_SECRETS_MARK = "ADDON_SECRETS"


def scrub(text, secrets):
    """`text` with every secret in `secrets` (non-empty) replaced by a mask, and every RCON setting's value.

    The second pass (_RCON_SET_RE) masks a value written as an RCON password setting even when the
    value itself was not read (a failed read, or a setting the panel did not know of).
    """
    for s in sorted({x for x in secrets if x}, key=len, reverse=True):
        text = text.replace(s, _MASK)
    return _RCON_SET_RE.sub(lambda m: m.group(1) + _MASK, text)


def secrets_sh(user, addon_id, cfg):
    """Shell printing, as one first line, the RCON passwords a log of this add-on may echo (read_secrets).

    `ADDON_SECRETS rcon.b64=<the game config's RCON lines> b3rcon.b64=<b3.ini's>`, base64: the config's
    lines as the install's probe reads them (`cfg`, relative to the home; none when empty), and for
    B3 its b3.ini's, which the operator may have changed. Read on the shell the Start or Log runs.
    """
    game = _RCON_LINES_SH % shlex.quote(cfg) if cfg else "true"
    ini = ('grep -iE "^[[:space:]]*rcon_?password[[:space:]]*[:=]" %s 2>/dev/null | head -c 4000 | base64 -w0'
           % shlex.quote("%s/%s" % (addon_dir(user, B3), CATALOG[B3]["settings"])) if addon_id == B3 else "true")
    return "printf '%s rcon.b64=%%s b3rcon.b64=%%s\\n' \"$(%s)\" \"$(%s)\"; " % (_SECRETS_MARK, game, ini)


def rcon_values(cfg_lines, ini_text=""):
    """Every RCON password value the game config's lines and b3.ini's text set (either setting name).

    A b3.ini value is taken whole and as B3 reads it (ConfigParser ends it at a `;` after a blank).
    """
    found = [m.group(1) if m.group(1) is not None else m.group(2)
             for name in ("rcon_password", "rconpassword") for m in _RCON_RE[name].finditer(cfg_lines or "")]
    for m in _INI_RCON_RE.finditer(ini_text or ""):
        value = m.group(1).strip()
        found += [value, re.split(r"\s;", value)[0].rstrip()]
    return [v for v in dict.fromkeys(found) if v]


def read_secrets(out):
    """(the RCON passwords secrets_sh's first line names, the rest of `out`).

    Without that line as the first one (the read failed), nothing is taken out and the whole of
    `out` is the rest: scrub's second pass still masks a value written as an RCON setting.
    """
    first, _nl, rest = (out or "").partition("\n")
    words = first.strip().split(" ")
    if words[0] != _SECRETS_MARK:
        return [], out or ""
    kv = dict(w.split("=", 1) for w in words[1:] if "=" in w)
    return rcon_values(_unb64(kv.get("rcon.b64", "")), _unb64(kv.get("b3rcon.b64", ""))), rest
