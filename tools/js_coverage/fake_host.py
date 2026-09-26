"""The hosts tools/js_coverage/serve.py pretends to have: what each command the panel runs answers.

A lookup table, not a simulation. Each entry matches what a command IS — the tool it runs, a file
it reads, a sentinel it prints — never how a builder spells its arguments (which `sudo -u` wrapper,
which quoting), so rewriting a command builder does not silently lose its answer. A command nothing
here matches succeeds with no output, which every caller in the panel already reads as "nothing
there"; `jscov-commands.log` in the throwaway tree lists every command, for finding the ones a page
needed and got nothing for.

The world: the panel's own host (local) runs mcserver and gmodserver, vps-one runs rustserver and
cs2server, vps-two runs vhserver. Numbers are plausible, not measured.
"""
import base64
import json
import re
import threading
import time

_T0 = time.time()
_lock = threading.Lock()
_tick = [0]

# The parts of the world a walk can change as it goes (driver.world() writes this file, serve.py
# says where it is): a page that renders differently for a host without Tailscale, or one waiting
# to be linked, is only reached by making the host that way.
WORLD_FILE = ""
_WORLD_DEFAULTS = {"tailscale": "running"}     # running | stopped | absent


def world(key):
    """Return the current value of `key` in the walk's world."""
    try:
        with open(WORLD_FILE, encoding="utf-8") as fh:
            return json.load(fh).get(key, _WORLD_DEFAULTS[key])
    except (OSError, ValueError):
        return _WORLD_DEFAULTS[key]


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _users_in(command):
    return re.findall(r"/home/([a-z0-9_]+server)\b", command)


# ── the console log, growing ────────────────────────────────────────────────────────────────────
# One log for every server: what the page does with lines does not depend on whose they are. It
# grows by a line every couple of seconds, so the console poller sees a file that changes and
# pushes the new lines over the socket — the path a live server's console actually takes.
_LOG_HEAD = [
    "[2026-09-26 10:00:01] [  OK  ] Starting mcserver: LinuxGSM",
    "\x1b[32m[ INFO ]\x1b[0m Server started on port 25565",
    "\x1b[1;33mWARN\x1b[0m Can't keep up! Is the server overloaded?",
    "Steve joined the game",
    "<Steve> hello world",
    "\x1b[31mERROR\x1b[0m Failed to load chunk (-3, 7)",
    "Alex joined the game",
    "[Server thread/INFO]: Done (4.203s)! For help, type \"help\"",
]


def _log_text():
    n = int((time.time() - _T0) / 2)
    lines = list(_LOG_HEAD) + ["[Server thread/INFO]: tick %d, 2 players online" % i
                               for i in range(n)]
    return "\n".join(lines) + "\n"


def _console(command):
    text = _log_text()
    m = re.search(r"tail -c \+(\d+)\b.*?head -c (\d+)", command)
    if m:
        start, n = int(m.group(1)) - 1, int(m.group(2))
        data = text.encode()[start:start + n].decode(errors="replace")
        return "B" + data + "E"
    m = re.search(r"tail -(\d+) ", command)
    if m:
        want = int(m.group(1))
        return "B" + "\n".join(text.splitlines()[-want:]) + "\nE"
    return None


# ── game servers' files ─────────────────────────────────────────────────────────────────────────
_TREE = {
    "": [("d", 0, "serverfiles"), ("d", 0, "lgsm"), ("d", 0, "log"),
         ("f", 18213, "mcserver"), ("f", 412, "notes.txt"), ("f", 2048, "server.cfg")],
    "serverfiles": [("d", 0, "world"), ("f", 1024, "server.properties"),
                    ("f", 52428800, "server.jar"), ("f", 900, "ops.json"), ("f", 12, "eula.txt")],
    "log": [("d", 0, "console"), ("f", 20480, "latest.log")],
}
_FILES = {
    "notes.txt": "Remember to update the whitelist.\n",
    "server.cfg": "hostname \"My Server\"\nsv_maxclients 24\n",
    "serverfiles/server.properties": "motd=A Minecraft Server\nmax-players=20\npvp=true\n",
    "serverfiles/eula.txt": "eula=true\n",
    "serverfiles/ops.json": "[]\n",
}
_DEFAULT_CFG = (
    "#### Game Server Settings ####\n"
    "ip=\"0.0.0.0\"\nport=\"25565\"\nmaxplayers=\"20\"\n"
    "#### LinuxGSM Settings ####\n"
    "## Notification Alerts\n"
    "discordalert=\"off\"\ndiscordwebhook=\"webhook\"\ntelegramalert=\"off\"\n"
    "telegramtoken=\"token\"\ntelegramchatid=\"\"\n"
    "#### Backup Settings ####\n"
    "maxbackups=\"4\"\nmaxbackupdays=\"30\"\nstoponbackup=\"on\"\n"
    "#### Logging ####\n"
    "consolelogging=\"on\"\nlogdays=\"7\"\n"
)
_INSTANCE_CFG = "maxplayers=\"24\"\ndiscordalert=\"on\"\ndiscordwebhook=\"https://discord.example/x\"\n"


def _browse(command):
    m = re.search(r"find '?/home/[a-z0-9_]+server/?([^' ]*)'? -maxdepth 1", command)
    if not m:
        return None
    rel = m.group(1).strip("/")
    entries = _TREE.get(rel, [("f", 10, "readme.txt")])
    if "%T@" in command:        # the upload pre-check also asks for each entry's mtime
        return "\n".join("%s\t%d\t%d.5\t%s" % (t, n, time.time() - 3600, f) for t, n, f in entries)
    return "\n".join("%s\t%d\t%s" % e for e in entries)


def _read_file(command):
    m = re.search(r"/home/[a-z0-9_]+server/([^' ]+)", command)
    rel = m.group(1) if m else ""
    content = _FILES.get(rel, "# %s\nkey=value\n" % rel)
    return "__LGSMP_FILE_BEGIN__" + _b64(content) + "__LGSMP_FILE_END__"


def _lgsm_frames(command):
    return ("__LGSMP_DEFAULT_B__" + _b64(_DEFAULT_CFG) + "__LGSMP_DEFAULT_E__"
            "__LGSMP_COMMON_B__" + _b64("") + "__LGSMP_COMMON_E__"
            "__LGSMP_INSTANCE_B__" + _b64(_INSTANCE_CFG) + "__LGSMP_INSTANCE_E__")


_LGSM_COMMANDS = """Usage: ./mcserver [option]

LinuxGSM - Minecraft - Version v25.1.0
https://linuxgsm.com/mc

Commands
start         st   | Start the server.
stop          sp   | Stop the server.
restart       r    | Restart the server.
monitor       m    | Check server status and restart if crashed.
test-alert    ta   | Send a test alert.
details       dt   | Display server information.
postdetails   pd   | Post details to termbin.com (removing passwords).
backup        b    | Create backup archives of the server.
update-lgsm   ul   | Check and apply any LinuxGSM updates.
update        u    | Check and apply any server updates.
force-update  fu   | Apply server updates bypassing check.
validate      v    | Validate server files with SteamCMD.
console       c    | Access server console.
debug         d    | Start server directly in your terminal.
"""

_MODS_AVAILABLE = """Installing Mods
=================================
Installed addons/mods
 * ulib
Available addons/mods
ULib - Complete framework for Garry's Mod - https://example.org/ulib
 * ulib
ULX - Admin mod - https://example.org/ulx
 * ulx
Sourcemod - Admin framework - https://example.org/sm
 * sourcemod
"""
_MODS_INSTALLED = """Removing Mods
=================================
ulib - ULib - Complete framework for Garry's Mod
"""


# LinuxGSM's `details`: what get_server_status reads the Status line from, and what
# lgsm_game_config reads the game's own config path from (it adds a DONE sentinel after it).
_RUNNING = {"mcserver", "gmodserver", "cs2server"}


def _details(command):
    user = (_users_in(command) or ["mcserver"])[0]
    text = ("\x1b[34mServer name:\x1b[0m     %s\n"
            "Status:          %s\n"
            "Config file:     /home/%s/server.cfg\n"
            "ismygameserver.online check: https://ismygameserver.online/\n"
            % (user, "\x1b[32mSTARTED\x1b[0m" if user in _RUNNING else "\x1b[31mSTOPPED\x1b[0m",
               user))
    if "__LGSMP_DETAILS_DONE__" in command:
        text += "__LGSMP_DETAILS_DONE__"
    return text


def _players_json(_command):
    return json.dumps([{"name": "Steve", "score": 12, "time": 3725.4},
                       {"name": "Alex", "score": 3, "time": 118.0},
                       {"name": "Admin", "score": None, "time": None}])


# ── host figures ────────────────────────────────────────────────────────────────────────────────
def _cpu_lines(k):
    base = 100000 + k * 400
    return ["cpu  %d 0 %d %d 100 0 50 0" % (base, base // 3, base * 4),
            "cpu0 %d 0 %d %d 50 0 20 0" % (base // 2, base // 6, base * 2),
            "cpu1 %d 0 %d %d 50 0 30 0" % (base // 2, base // 6, base * 2 + 90)]


def _metrics(command):
    with _lock:
        _tick[0] += 1
        k = _tick[0]
    a, b = _cpu_lines(k * 2), _cpu_lines(k * 2 + 1)
    users = ["mcserver", "gmodserver", "rustserver", "cs2server", "vhserver"]
    out = [a[0]]
    host_form = "ps -eo user:32=,rss=" in command
    if host_form:
        out += ["GJA %s %d" % (u, 5000 + 7 * k) for u in users]
    else:
        out.append("GJA %d" % (5000 + 7 * k))
    out.append(b[0])
    if host_form:
        out += ["GJB %s %d" % (u, 5100 + 7 * k + i * 9) for i, u in enumerate(users)]
    else:
        out.append("GJB %d" % (5160 + 7 * k))
    out += ["MEM 8294967296 3221225472", "LOAD 0.42 0.37 0.30",
            "DISK 85899345920 32212254720", "CORES 4", "UPTIME 312480"]
    if host_form:
        out += ["GAMERAM %s %d 3" % (u, 1500000 + i * 200000) for i, u in enumerate(users)]
        out += ["GUP %s %d" % (u, 86400 + i * 3600) for i, u in enumerate(users)]
        out += ["PORT %d" % p for p in (22, 25565, 27015, 28015, 27016, 2456, 5000)]
    else:
        out += ["GAMERAM 1843200 3", "GUP 86400", "PORT 1"]
    return "\n".join(out)


def _live(command):
    with _lock:
        _tick[0] += 1
        k = _tick[0]
    a, b = _cpu_lines(k * 2), _cpu_lines(k * 2 + 1)
    return "\n".join(["===A"] + a + ["===B"] + b + [
        "===MEM", "MemTotal:        8100000 kB", "MemAvailable:    5000000 kB",
        "SwapTotal:       2097148 kB", "SwapFree:        2000000 kB",
        "===DISK", "Filesystem 1B-blocks Used Available Use% Mounted",
        "/dev/sda1 85899345920 32212254720 53687091200 38% /"])


_SPECS = ("OS\tUbuntu 24.04.1 LTS\nKERNEL\t6.8.0-45-generic\nARCH\tx86_64\nHOST\tvps-one\n"
          "CPU\tAMD EPYC 7B13\nCORES\t4\nMAXMHZ\t3500.0\nMEM\t7.7\nDISK\t80G\nVIRT\tkvm\n")

_UFW_NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 25565/tcp                  ALLOW IN    Anywhere                   # mcserver
[ 3] 27015                      ALLOW IN    Anywhere                   # gmodserver
[ 4] 5000/tcp                   ALLOW IN    100.64.0.0/10
[ 5] Anywhere                   DENY IN     198.51.100.7               # panel-block
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 7] 25565/tcp (v6)             ALLOW IN    Anywhere (v6)              # mcserver
"""
_UFW_VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
25565/tcp                  ALLOW IN    Anywhere                   # mcserver
Anywhere                   DENY IN     198.51.100.7               # panel-block
"""
_F2B_STATUS = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, linuxgsm-panel\n"
_F2B_JAIL = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t1\n"
             "|  |- Total failed:\t57\n|  `- File list:\t/var/log/auth.log\n`- Actions\n"
             "   |- Currently banned:\t2\n   |- Total banned:\t9\n"
             "   `- Banned IP list:\t198.51.100.7 203.0.113.99\n")


def _f2b_log(_command):
    day = time.strftime("%Y-%m-%d")
    rows = []
    for i, ip in enumerate(["198.51.100.7", "198.51.100.7", "203.0.113.99", "192.0.2.200"]):
        rows.append("%s 10:%02d:01,123 fail2ban.filter [812]: INFO [sshd] Found %s - %s 10:%02d:01"
                    % (day, i, ip, day, i))
    rows.append("%s 10:09:01,500 fail2ban.actions [812]: NOTICE [sshd] Ban 198.51.100.7" % day)
    rows.append("%s 10:12:44,900 fail2ban.actions [812]: NOTICE [sshd] Ban 203.0.113.99" % day)
    return "\n".join(rows)


_AUTH_LOG = "\n".join([
    "Sep 26 10:00:01 vps-one sshd[1201]: Failed password for root from 198.51.100.7 port 51234 ssh2",
    "Sep 26 10:00:05 vps-one sshd[1201]: Accepted publickey for root from 192.0.2.1 port 50000 ssh2",
    "Sep 26 10:01:07 vps-one sshd[1210]: Invalid user admin from 203.0.113.99 port 40000",
])

_APT_UPGRADABLE = """Listing...
openssl/noble-updates 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.3]
nginx/noble-security 1.24.0-2ubuntu7.1 amd64 [upgradable from: 1.24.0-2ubuntu7]
tzdata/noble-updates 2026a-0ubuntu0.24.04 all [upgradable from: 2025b-0ubuntu0.24.04]
"""

_PRO_STATUS = json.dumps({
    "attached": False, "contract": {"name": ""},
    "services": [{"name": "esm-infra", "status": "disabled", "entitled": "yes",
                  "description": "Expanded Security Maintenance for Infrastructure"},
                 {"name": "livepatch", "status": "n/a", "entitled": "yes",
                  "description": "Canonical Livepatch service"}]})

_TS_STATUS = json.dumps({
    "BackendState": "Running", "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"],
    "Self": {"HostName": "panel-host", "DNSName": "panel-host.tail1234.ts.net.",
             "TailscaleIPs": ["100.101.102.103"], "OS": "linux", "Online": True},
    "Peer": {
        "nodekey:1": {"HostName": "vps-one", "DNSName": "vps-one.tail1234.ts.net.",
                      "TailscaleIPs": ["100.101.102.104"], "OS": "linux", "Online": True,
                      "LastSeen": "2026-09-26T10:00:00Z", "Relay": "lhr"},
        "nodekey:2": {"HostName": "laptop", "DNSName": "laptop.tail1234.ts.net.",
                      "TailscaleIPs": ["100.101.102.105"], "OS": "macOS", "Online": False,
                      "LastSeen": "2026-09-20T08:00:00Z", "Relay": ""}}})

_TS_NEEDS_LOGIN = json.dumps({"BackendState": "NeedsLogin", "AuthURL":
                               "https://login.tailscale.com/a/jscov", "Self": None,
                               "Peer": None, "TailscaleIPs": None})
_TS_AUTH = "\nTo authenticate, visit:\n\n\thttps://login.tailscale.com/a/jscov\n\n"


def _ts(when_running, when_stopped=None, when_absent=""):
    """Answer by the host's Tailscale: running, installed but not linked, or absent."""
    def answer(_command):
        state = world("tailscale")
        if state == "absent":
            return when_absent
        if state == "stopped" and when_stopped is not None:
            return when_stopped
        return when_running
    return answer


_CRONTAB = ("# m h dom mon dow command\n"
            "@reboot /home/%(u)s/%(u)s start > /dev/null 2>&1\n"
            "*/5 * * * * /home/%(u)s/%(u)s monitor > /dev/null 2>&1\n"
            "0 4 * * 1 /home/%(u)s/%(u)s update-lgsm > /dev/null 2>&1\n"
            "30 3 * * * /home/%(u)s/%(u)s backup > /dev/null 2>&1\n")


def _crontab(command):
    u = (_users_in(command) or re.findall(r"crontab -u ([a-z0-9_]+)", command) or ["mcserver"])[0]
    return _CRONTAB % {"u": u}


def _backups(command):
    now = int(time.time())
    return ("F\tmcserver-2026-09-25-0330.tar.zst\t734003200\t%d\n"
            "F\tmcserver-2026-09-24-0330.tar.zst\t713031680\t%d\n"
            "__LGSMP_BK_DONE__" % (now - 86400, now - 2 * 86400))


def _discover(command):
    return ("FOUND|mcserver|mcserver|25565|2|0|3|1\n"
            "FOUND|arkserver|arkserver|7777|0|1|0|0\n")


# (pattern, answer): answer is text, or a callable taking the command. First match wins.
_TABLE = [
    (r"tail -c \+\d+|printf B; tail -\d+", _console),
    (r"stat -c '?%i %s'?", lambda c: "4242 %d" % len(_log_text().encode())),
    (r"-maxdepth 1 -mindepth 1 -printf", _browse),
    (r"__LGSMP_FILE_BEGIN__", _read_file),
    (r"__LGSMP_DEFAULT_B__", _lgsm_frames),
    (r"\./[a-z0-9_]+ details\b", _details),
    (r"_default\.cfg.*common\.cfg.*__LGSMP_FILE_END__",
     lambda c: _DEFAULT_CFG + "\n" + _INSTANCE_CFG + "\n__LGSMP_FILE_END__"),
    (r"lgsm/backup/\*\.tar", _backups),
    (r"\.lgsm-cron.*\.status",
     lambda c: "abc123\t1\t%d\t%d\t%s\n" % (time.time() - 90, time.time() - 60,
                                            _b64("backup failed: disk full\n"))),
    (r"crontab -u [a-z0-9_]+ -l|crontab-list", _crontab),
    (r"mods-install", _MODS_AVAILABLE),
    (r"mods-remove", _MODS_INSTALLED),
    (r"gamedig .*\.players\[\] \| \{name", _players_json),
    (r"gamedig .*\.players\|length", '{"c":3,"ok":true}'),
    (r"gamedig .*\.version", "1.21.4"),
    (r"gamedig .*maxplayers", "20"),
    (r"gamedig .*\.map", "de_dust2"),
    (r"appmanifest_", "appid=740\nbuild=15234567\nupdated=1758337200\n"),
    (r"cd /home/([a-z0-9_]+) && \./[a-z0-9_]+'?\s*$", _LGSM_COMMANDS),
    (r"ps -eo user:32=,rss=|grep '\^cpu ' /proc/stat", _metrics),
    (r"echo ===A", _live),
    (r"^OS=\$\(\. /etc/os-release", _SPECS),
    (r"\$\{ID\}-\$\{VERSION_ID\}", "ubuntu-24.04"),
    (r"ss -H -lntu", "0.0.0.0:22\n0.0.0.0:25565\n0.0.0.0:27015\n0.0.0.0:28015\n"
                     "0.0.0.0:27016\n0.0.0.0:2456\n127.0.0.1:5000"),
    (r"reboot-required", "YES"),
    (r"ip route get", "10.0.0.5"),
    (r"ufw[ -]status\b.*numbered", _UFW_NUMBERED),
    (r"ufw[ -]status\b.*verbose", _UFW_VERBOSE),
    (r"ufw[ -]status", "Status: active\n"),
    (r"fail2ban-client status [a-z]|f2b-status-jail", _F2B_JAIL),
    (r"fail2ban-client status|f2b-status", _F2B_STATUS),
    (r"command -v fail2ban-client", "yes"),
    (r"fail2ban\.log", _f2b_log),
    (r"auth\.log|journalctl -u ssh", _AUTH_LOG),
    (r"journalctl -u fail2ban", "Sep 26 10:00:00 vps-one fail2ban-server[812]: Server ready"),
    (r"journalctl .*linuxgsm-panel", "Sep 26 10:00:00 panel-host python[900]: panel started"),
    (r"apt list --upgradable|apt-check", _APT_UPGRADABLE),
    (r"apt-config dump APT::Periodic::Unattended-Upgrade", 'APT::Periodic::Unattended-Upgrade "1";'),
    (r"pro status --format json|pro-status", _PRO_STATUS),
    (r"which tailscale 2>/dev/null && echo 'INSTALLED'",
     _ts("/usr/bin/tailscale\nINSTALLED", when_absent="NOTINSTALLED")),
    (r"which tailscale && tailscale version", _ts("/usr/bin/tailscale\n1.84.0")),
    (r"tailscale (--)?version", _ts("1.84.0\n  tailscale commit: 0123456789ab\n")),
    (r"tailscale status --json", _ts(_TS_STATUS, _TS_NEEDS_LOGIN, "{}")),
    (r"tailscale up\b", _ts("", _TS_AUTH)),
    (r"tailscale serve status", _ts("https://panel-host.tail1234.ts.net (tailnet only)\n"
                                    "|-- / proxy http://127.0.0.1:5000\n", "No serve config\n")),
    (r"tailscale debug prefs", json.dumps({"RouteAll": False})),
    (r"ip link show tailscale\d", "NOTFOUND"),
    (r"uptime -p", "up 3 days, 14 hours, 8 minutes"),
    (r"timedatectl|/etc/timezone", "Europe/London"),
    (r"uname -r", "6.8.0-45-generic"),
    (r"df -PB1 /home", "Filesystem 1B-blocks Used Available Use% Mounted on\n"
                       "/dev/sda1 85899345920 32212254720 53687091200 38% /"),
    (r"free -h \| grep Mem", "3.0G/7.7G"),
    (r"free \| grep Mem", "38.8"),
    (r"df -h / \| tail -1", "30G/80G (38%)"),
    (r"/proc/loadavg", "0.42 0.37 0.30"),
    (r"echo UPTIME", "UPTIME up 3 days\nLOAD 0.42 0.37 0.30\nDISK 30G/80G\nMEM 3.0G/7.7G"),
    (r"for u in \$\(ls -1 /home/|lgsm-discover", _discover),
    (r"\.panel-update\.log", "120\nUpdating mcserver\n[ OK ] Update complete\n"),
    (r"^echo (\S+)$", lambda c: c.split(" ", 1)[1]),
]
_COMPILED = [(re.compile(p, re.S | re.M), a) for p, a in _TABLE]
_SENTINEL = re.compile(r"printf (?:%s|\"%s\\\\n\"|'%s\\\\n') '?(__[A-Z0-9_]+__)'?\s*$")


def answer(command):
    """(stdout, stderr, rc) for one command, as the host would have answered it."""
    text = command if isinstance(command, str) else " ".join(str(c) for c in command)
    for rx, ans in _COMPILED:
        if rx.search(text):
            try:
                out = ans(text) if callable(ans) else ans
            except Exception:   # a broken answer must say so, not look like an unanswered host
                import traceback
                traceback.print_exc()
                raise
            if out is None:
                continue
            return out, "", 0
    # A command that ends by printing a DONE sentinel ran to the end: say so, with nothing before.
    m = _SENTINEL.search(text.rstrip("'\" "))
    return (m.group(1) if m else ""), "", 0
