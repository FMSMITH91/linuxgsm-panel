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
    and process cap and a restart limit (rule 7), the image pinned by digest. Its network is its own
    (pasta): the only ports it reaches on the host are the game's RCON port (UDP) and the local
    database's port (TCP), forwarded to the host's loopback, and its web page is published on
    127.0.0.1 only. The game's log folder is mounted read-only.

THE ADD-ONS
    IW4MAdmin (cod4, codwaw): the image RaidMax's own release workflow builds and pushes to
    ghcr.io/raidmax/iw4madmin (its build_application.yml), pinned by digest. Its settings are
    written by the panel before the first start, so its interactive first-run setup never runs: one
    server (this one, on 127.0.0.1), the RCON password read from the game's config, the game log,
    and one of this server's databases from the Databases tab (MySQL provider), never one another
    add-on uses.

The host keeps the state: ~/panel-addons/<id>/addon.json says what the panel installed. Nothing is
installed until someone with Manage add-ons installs an add-on.
"""
import base64
import json
import re
import shlex

# ── the catalog ─────────────────────────────────────────────────────────────────────────────────
IW4MADMIN = "iw4madmin"
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
        # The folders its image mounts (its Dockerfile and entrypoint.sh), and /data for HOME.
        "mounts": ("Configuration", "Plugins", "Localization", "Database", "Log"),
        "web_port": 1624,
        # The host port its page is published on: PORT_BASE + the server's id, or the next free one.
        "port_base": 21000,
        "legacy": False,
    },
}
ADDON_IDS = tuple(sorted(CATALOG))

# Where an add-on lives in the account's home, and the name of its unit and container.
HOME_DIR = "panel-addons"
QUADLET_DIR = ".config/containers/systemd"
UNIT_PREFIX = "lgsm-addon-"
META_FILE = "addon.json"
# The packages the runtime needs on Ubuntu (all in universe): Podman, newuidmap/newgidmap for the
# user namespace, and pasta for the container's own network. Ubuntu 24.04 ships Podman 4.9 (Quadlet
# and pasta), 26.04 ships 5.7; 22.04's 3.4 has neither, so it is refused.
PACKAGES = ("podman", "uidmap", "passt")
MIN_PODMAN = (4, 9)
MIN_UBUNTU = (24, 4)
# The container's caps: its memory, processes, and how often systemd restarts a failing one.
MEMORY = "1g"
PIDS = 512
RESTART_BURST = 5
RESTART_WINDOW = 600
# The longest the install's pull and first start may take, and a status or action read.
INSTALL_TIMEOUT = 900
ACTION_TIMEOUT = 120
LOG_LINES = 200
LOG_BYTES = 60000
_PORT_TRIES = 20

# What the host prints, read by the parsers below.
_MARK_INSTALLED = "ADDON_INSTALLED"
_MARK_REMOVED = "ADDON_REMOVED"
_FAIL_MARKS = {
    "ADDON_NO_USER_MANAGER": "The account's user manager didn't start, so the add-on can't run as it.",
    "ADDON_PULL_FAILED": "Couldn't download the add-on's image. Check that this host can reach ghcr.io.",
    "ADDON_START_FAILED": "The add-on was installed but didn't start. Its log says why.",
    "ADDON_WRITE_FAILED": "Couldn't write the add-on's files in the server's home folder.",
}
_RCON_RE = re.compile(r'^\s*seta?\s+rcon_password\s+(?:"([^"\r\n]*)"|(\S+))', re.I | re.M)
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


def host_port(server_id, addon_id, offset=0):
    """The host port the add-on's page is published on: its base + the server id (+ offset)."""
    return CATALOG[addon_id]["port_base"] + int(server_id) + offset


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
    """The last rcon_password a CoD server config sets, or "" (no line, or an empty value)."""
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


def probe_sh(addon_id, selfname, server_id):
    """The install's first read, as the account: the host, the game's log folder, RCON, a free port.

    Prints os=, podman=, logdir= (the folder of the newest games_mp.log under serverfiles or
    ~/.callofduty*), rcon.b64= (the config's rcon_password line, base64), port= (the first free host
    port from the add-on's own), installed= (1 when the add-on is already there).
    """
    cfg = "serverfiles/main/%s.cfg" % selfname
    ports = " ".join(str(host_port(server_id, addon_id, i)) for i in range(_PORT_TRIES))
    return (_ENV + '. /etc/os-release 2>/dev/null; echo "os=${VERSION_ID:-}"; '
            'echo "podman=$(podman --version 2>/dev/null | head -n 1)"; '
            'l=$(find serverfiles .callofduty* -maxdepth 3 -type f -name games_mp.log -printf "%%T@ %%h\\n" '
            '2>/dev/null | sort -nr | head -n 1 | cut -d" " -f2-); echo "logdir=$l"; '
            'echo "rcon.b64=$(grep -iE "^[[:space:]]*seta?[[:space:]]+rcon_password" %s 2>/dev/null '
            '| tail -n 1 | head -c 400 | base64 -w0)"; '
            'for p in %s; do if ! ss -Htln "sport = :$p" 2>/dev/null | grep -q .; then echo "port=$p"; break; fi; done; '
            '[ -f %s ] && echo installed=1; true'
            % (shlex.quote(cfg), ports, shlex.quote("%s/%s/%s" % (HOME_DIR, addon_id, META_FILE))))


# The game's log folder as the probe prints it, relative to the home: plain path words only, since it
# goes into the unit file (where `%` is a specifier and a line break a new key).
_LOGDIR_RE = re.compile(r"[A-Za-z0-9_+-][A-Za-z0-9._+-]*(?:/[A-Za-z0-9_+-][A-Za-z0-9._+-]*){0,3}")


def log_dir(user, rel):
    """The game log's folder as an absolute path in the account's home, or "" when `rel` is not plain."""
    if not _LOGDIR_RE.fullmatch(rel or "") or ".." in rel.split("/"):
        return ""
    return "/home/%s/%s" % (user, rel)


def parse_probe(out):
    """What probe_sh found: {os, podman, logdir, rcon, port, installed} (rcon decoded and parsed)."""
    kv = kv_lines(out)
    port = kv.get("port", "")
    return {"os": kv.get("os", ""), "podman": kv.get("podman", ""), "logdir": kv.get("logdir", ""),
            "rcon": rcon_password(_unb64(kv.get("rcon.b64", ""))),
            "port": int(port) if port.isdecimal() else None, "installed": kv.get("installed") == "1"}


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
def connection_string(host, port, name, secret):
    """IW4MAdmin's MySQL connection string (MySqlConnector's keys) for one of the server's databases.

    The panel's database names and passwords hold no `;` or `=` (databases.new_password), so no
    value needs quoting.
    """
    return "Server=%s;Port=%d;Database=%s;User ID=%s;Password=%s" % (host, int(port), name, name, secret)


def iw4madmin_settings(game_type, game_port, rcon, conn):
    """IW4MAdminSettings.json for one server, as text: enough that its first-run setup never runs.

    IW4MAdmin runs its setup only when the file has no Servers and no Id (ApplicationManager), and
    its validator asks for a bind URL, a database provider (with a connection string for mysql),
    AutoMessagePeriod >= 60, and per server a port and an RCON password. The page listens on every
    address of the container's own network; the host publishes it on 127.0.0.1 only.
    """
    parser = CATALOG[IW4MADMIN]["games"][game_type]
    doc = {
        "Webfront": {"Enabled": True, "BindUrl": "http://0.0.0.0:%d" % CATALOG[IW4MADMIN]["web_port"]},
        "DatabaseProvider": "mysql",
        "ConnectionString": conn,
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


def network(game_port, db_host, db_port):
    """The container's Network= value: pasta, forwarding to the host's loopback only what it needs.

    -U the game's RCON port (UDP); -T the database's port when the database is on this host
    (127.0.0.1). A database on another machine (over Tailscale) is reached through pasta's own
    outbound connections, with no forward.
    """
    opts = ["-U", str(int(game_port))]
    if db_host == "127.0.0.1":
        opts += ["-T", str(int(db_port))]
    return "pasta:" + ",".join(opts)


def quadlet(user, addon_id, logdir, net, port):
    """The add-on's Quadlet unit text (~/.config/containers/systemd/<unit>.container)."""
    a = CATALOG[addon_id]
    base = addon_dir(user, addon_id)
    vols = ["Volume=%s/%s:/app/%s" % (base, m, m) for m in a["mounts"]]
    vols += ["Volume=%s/Data:/data" % base, "Volume=%s:/gamelog:ro" % logdir]
    lines = [
        "# Written by linuxgsm-panel: the %s add-on of this game server. The panel rewrites it." % a["name"],
        "[Unit]", "Description=%s (linuxgsm-panel add-on)" % a["name"],
        "StartLimitIntervalSec=%d" % RESTART_WINDOW, "StartLimitBurst=%d" % RESTART_BURST,
        "", "[Container]", "Image=%s" % a["image"], "ContainerName=%s" % unit_name(addon_id), "Pull=never",
        "Network=%s" % net, "PublishPort=127.0.0.1:%d:%d" % (port, a["web_port"]),
        "Environment=PUID=0", "Environment=PGID=0", "Environment=TZ=Etc/UTC", "Environment=HOME=/data",
    ] + vols + [
        "ReadOnly=true", "DropCapability=all", "NoNewPrivileges=true", "PidsLimit=%d" % PIDS,
        "HealthCmd=none", "PodmanArgs=--memory=%s" % MEMORY,
        "", "[Service]", "Restart=on-failure", "RestartSec=30", "TimeoutStartSec=300",
        "", "[Install]", "WantedBy=default.target", "",
    ]
    return "\n".join(lines)


def install_sh(user, addon_id, unit_text, meta_text):
    """The install's second step, as the account: write the files, pull the image, start the unit.

    The settings (which hold the RCON and database passwords) arrive on stdin, never on a command
    line; the unit and the panel's record are base64 here (they hold no secret). Every file is
    0600 and every folder 0700. Ends with ADDON_INSTALLED, or one of _FAIL_MARKS.
    """
    a = CATALOG[addon_id]
    d = shlex.quote(addon_dir(user, addon_id))
    q = shlex.quote("/home/%s/%s" % (user, QUADLET_DIR))
    unit = unit_name(addon_id)
    dirs = " ".join("%s/%s" % (d, m) for m in a["mounts"] + ("Data",))
    return (_ENV + "umask 077; d=%s; q=%s; "
            "mkdir -p %s \"$q\" || { echo ADDON_WRITE_FAILED; exit 20; }; "
            "cat > \"$d/Configuration/IW4MAdminSettings.json.new\" "
            "&& mv -f -T \"$d/Configuration/IW4MAdminSettings.json.new\" \"$d/Configuration/IW4MAdminSettings.json\" "
            "&& printf %%s %s | base64 -d > \"$q/%s.container.new\" "
            "&& mv -f -T \"$q/%s.container.new\" \"$q/%s.container\" "
            "&& printf %%s %s | base64 -d > \"$d/%s\" || { echo ADDON_WRITE_FAILED; exit 21; }; "
            "i=0; while [ ! -S \"$XDG_RUNTIME_DIR/bus\" ] && [ $i -lt 20 ]; do sleep 1; i=$((i + 1)); done; "
            "[ -S \"$XDG_RUNTIME_DIR/bus\" ] || { echo ADDON_NO_USER_MANAGER; exit 22; }; "
            "podman system migrate >/dev/null 2>&1; "
            "podman pull -q %s >/dev/null || { echo ADDON_PULL_FAILED; exit 23; }; "
            "systemctl --user daemon-reload && systemctl --user start %s.service "
            "|| { echo ADDON_START_FAILED; exit 25; }; echo %s"
            % (d, q, dirs, shlex.quote(_b64(unit_text)), unit, unit, unit, shlex.quote(_b64(meta_text)),
               META_FILE, shlex.quote(a["image"]), unit, _MARK_INSTALLED))


def install_outcome(out, rc):
    """(ok, English sentence or "") from what install_sh printed and its exit status."""
    if rc == 0 and _MARK_INSTALLED in (out or ""):
        return True, ""
    for mark, said in _FAIL_MARKS.items():
        if mark in (out or ""):
            return False, said
    return False, "The install didn't finish on the host."


def action_sh(addon_id, action):
    """Start or stop the add-on's unit, as the account (`action` is "start" or "stop")."""
    if action not in ("start", "stop"):
        raise ValueError("unknown add-on action")
    return _ENV + "systemctl --user %s %s.service" % (action, unit_name(addon_id))


def logs_sh(user, addon_id):
    """The add-on's last LOG_LINES lines: its unit's journal, else its own newest log file."""
    log_dir = shlex.quote(addon_dir(user, addon_id) + "/Log")
    return (_ENV + "o=$(journalctl --user -u %s.service -n %d --no-pager -o short-iso 2>/dev/null "
            "| grep -v '^-- No entries --$'); "
            "if [ -n \"$o\" ]; then printf '%%s\\n' \"$o\"; else "
            "f=$(ls -1t %s 2>/dev/null | head -n 1); [ -n \"$f\" ] && tail -n %d %s/\"$f\"; fi "
            "| tail -c %d; true"
            % (unit_name(addon_id), LOG_LINES, log_dir, LOG_LINES, log_dir, LOG_BYTES))


def remove_sh(user, addon_id):
    """Stop and remove the add-on, its image, its unit and its folder, as the account.

    The folder goes through `podman unshare`, so a file the container made as one of its own users
    (a subordinate id) goes too. Prints ADDON_REMOVED and others=0/1 (whether another add-on is left).
    """
    unit = unit_name(addon_id)
    return (_ENV + "systemctl --user stop %s.service 2>/dev/null; rm -f %s; "
            "systemctl --user daemon-reload 2>/dev/null; podman rm -f --ignore %s >/dev/null 2>&1; "
            "podman rmi %s >/dev/null 2>&1; "
            "podman unshare rm -rf -- %s 2>/dev/null || rm -rf -- %s; "
            "[ -e %s ] && exit 30; rmdir %s 2>/dev/null; "
            "if [ -d %s ]; then echo others=1; else echo others=0; fi; echo %s"
            % (unit, shlex.quote("/home/%s/%s/%s.container" % (user, QUADLET_DIR, unit)), unit,
               shlex.quote(CATALOG[addon_id]["image"]),
               shlex.quote(addon_dir(user, addon_id)), shlex.quote(addon_dir(user, addon_id)),
               shlex.quote(addon_dir(user, addon_id)), shlex.quote("/home/%s/%s" % (user, HOME_DIR)),
               shlex.quote("/home/%s/%s" % (user, HOME_DIR)), _MARK_REMOVED))


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
