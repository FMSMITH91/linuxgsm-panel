"""Privileged operations, expressed as verbs instead of shell strings.

THE PROBLEM THIS IS SOLVING
    The panel escalates local work as `sudo bash -c '<command>'`. A sudoers rule that permits
    /bin/bash is exactly as powerful as NOPASSWD:ALL, so the grant on the panel's own host could
    not be narrowed by editing sudoers — any list containing bash reads as scoped while granting
    identical power. Narrowing it for real means the shell string has to stop crossing the
    privilege boundary at all.

    So each privileged operation is named here, once, as a verb plus already-separated arguments.
    Nothing composes a command string from user input any more; the arguments are passed as argv.

TWO TRANSPORTS, ONE DEFINITION
    A verb has to work against the panel's own host AND against a remote host over SSH, because the
    same call sites serve both:

      local   ->  sudo -n /usr/local/lib/linuxgsm-panel/panel-helper <verb> <args...>
                  No shell. The helper is root-owned, re-validates every argument against its own
                  table, and execs a fixed argv. See tools/panel-helper.

      remote  ->  the same argv, shell-quoted, run over the existing SSH path. A remote host has no
                  helper installed and its sudoers is the operator's business, not the panel's —
                  what this buys there is that the command is built from validated pieces rather
                  than interpolated text.

    The argv is built once, in `_ARGV`, and used for both. The helper keeps its own independent copy
    of the same table on purpose: it must not import panel code (root running panel-writable code
    would defeat the point). tests/unit_test.py asserts the two agree, so they cannot drift.

STATUS
    Conversion is in progress — the ufw family first. Until EVERY privileged call site routes
    through a verb, /etc/sudoers.d/linuxgsm-panel still grants NOPASSWD:ALL and this reduces
    nothing: a boundary with a hole in it is not a boundary. SECURITY.md says so too.
"""
import ipaddress
import re
import shlex

# Root-owned, outside the panel's git checkout. The checkout belongs to the panel user and is
# rewritten by `git pull` on every self-update, so a helper living there would be panel-writable
# by design — and a boundary the untrusted side can edit is not a boundary.
HELPER_PATH = "/usr/local/lib/linuxgsm-panel/panel-helper"

# The bare tool NAME. The helper resolves it to an absolute path from its own fixed
# list; the remote rendering leaves it bare, exactly as the SSH path has always sent it.
UFW = "ufw"
F2B = "fail2ban-client"
SYSTEMCTL = "systemctl"

# The services the panel is allowed to touch, named exhaustively — see tools/panel-helper.
UNITS = ("ssh", "sshd", "fail2ban", "whoopsie", "cups", "modemmanager",
         "unattended-upgrades")

APT = "apt-get"
# dpkg's conflict answers, fixed rather than passed in: keep a config file the operator has edited,
# take the package default for one they have not — see tools/panel-helper.
APT_CONFOLD = ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
# Verbs that need DEBIAN_FRONTEND=noninteractive so apt never blocks on a prompt nobody can answer.
NONINTERACTIVE = {"apt-full-upgrade", "apt-upgrade", "apt-install"}
REPOS = ("universe",)

# Log sources. The panel reads exactly these, so they are named here and the caller passes a NAME —
# never a unit and never a path.
JOURNAL_UNITS = {
    "ssh": ("ssh", "sshd"),       # Debian/Ubuntu call it ssh, others sshd; the panel wants both
    "fail2ban": ("fail2ban",),
    "panel": ("linuxgsm-panel",),
}
JOURNAL_SOURCES = tuple(sorted(JOURNAL_UNITS))
LOG_FILES = {
    "fail2ban": "/var/log/fail2ban.log",
    "auth": "/var/log/auth.log",
}
OS_UPDATE_LOG = "/run/panel-os-update.log"

# Linux user names the panel may act on. Deliberately narrower than useradd itself accepts: it must
# start with a letter or underscore and hold only [A-Za-z0-9._-], so it can never be an option
# (-o, --system), a path fragment (., ..), or empty. This one validator is what makes the home
# directory safe to CONSTRUCT below rather than accept.
USERNAME_RE = r"[A-Za-z_][A-Za-z0-9._-]{0,31}"
HOME_ROOT = "/home"

# The sshd drop-in the panel manages, and the snapshot kept beside it during a port change. The
# snapshot deliberately does not end in ".conf" — sshd_config.d is included as "*.conf", so a
# "….conf.bak" sitting next to it is inert.
SSHD_DROPIN = "/etc/ssh/sshd_config.d/99-panel-sshport.conf"
SSHD_DROPIN_BAK = SSHD_DROPIN + ".bak"

# Root-owned files the panel writes, by NAME. The content arrives on stdin and the path is looked
# up here — so a caller names a destination, it never supplies one. This is the whole reason the
# write verb is safe: there is no argument that could become a path.
#
# The sshd drop-in is deliberately NOT here. Getting an sshd config write wrong locks the operator
# out of their own host, so it keeps its current path until it gets a change of its own.
WRITE_TARGETS = {
    "apt-auto-upgrades": ("/etc/apt/apt.conf.d/20auto-upgrades", 0o644),
    "fail2ban-jail-local": ("/etc/fail2ban/jail.local", 0o644),
    "fail2ban-panel-whitelist": ("/etc/fail2ban/jail.d/zz-panel-whitelist.local", 0o644),
    "fail2ban-panel-filter": ("/etc/fail2ban/filter.d/linuxgsm-panel.conf", 0o644),
    "fail2ban-panel-jail": ("/etc/fail2ban/jail.d/linuxgsm-panel.conf", 0o644),
    "node-tools-cron": ("/etc/cron.d/lgsm-node-tools", 0o644),
    "sysctl-tailscale": ("/etc/sysctl.d/99-tailscale.conf", 0o644),
    # Added deliberately alongside the sshd verbs — see tools/panel-helper.
    "sshd-port-dropin": (SSHD_DROPIN, 0o644),
}





class VerbError(ValueError):
    """An argument did not pass validation. Never contains the rejected value: this text can reach
    the panel UI, and echoing attacker-controlled input back into a page is a reflection."""


# ── Validators ────────────────────────────────────────────────────────────────────────────────
# Deliberately strict. A rejected argument is a bug to fix at the call site, not a reason to fall
# back to something looser.

def _portspec(s):
    m = re.fullmatch(r"(\d{1,5})(?::(\d{1,5}))?(?:/(tcp|udp))?", str(s))
    if not m:
        raise VerbError("not a port specification")
    for p in (m.group(1), m.group(2)):
        if p is not None and not (1 <= int(p) <= 65535):
            raise VerbError("port out of range")
    if m.group(2) is not None and int(m.group(2)) < int(m.group(1)):
        raise VerbError("reversed port range")
    return str(s)


def _iface(s):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", str(s)):
        raise VerbError("not an interface name")
    return str(s)


def _cidr(s):
    try:
        ipaddress.ip_network(str(s), strict=False)
    except ValueError:
        raise VerbError("not an IP address or network")
    return str(s)


def _comment(s):
    s = "" if s is None else str(s)
    if not re.fullmatch(r"[A-Za-z0-9 _.-]{0,60}", s):
        raise VerbError("comment outside [A-Za-z0-9 _.-] or over 60 characters")
    return s


def _jail(s):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(s)):
        raise VerbError("not a jail name")
    return str(s)


def _username(s):
    """A Linux user name the panel is allowed to manage — see tools/panel-helper."""
    if not re.fullmatch(USERNAME_RE, str(s)):
        raise VerbError("not a user name")
    return str(s)


def home_of(user):
    """The home directory for a validated user name — built, never accepted. See the helper."""
    path = HOME_ROOT + "/" + _username(user)
    if not path.startswith(HOME_ROOT + "/") or len(path) <= len(HOME_ROOT) + 1 or ".." in path:
        raise VerbError("refusing to build that home path")
    return path


def _linecount(s):
    """A number of log lines, bounded so a caller cannot ask for the whole journal."""
    if not re.fullmatch(r"[1-9][0-9]{0,4}", str(s)) or int(s) > 20000:
        raise VerbError("not a line count in 1..20000")
    return str(s)


def _portlist(s):
    """A comma-separated port list for a fail2ban jail — see tools/panel-helper."""
    parts = str(s).split(",")
    if not (1 <= len(parts) <= 10):
        raise VerbError("expected 1..10 ports")
    for p in parts:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", p) or not (1 <= int(p) <= 65535):
            raise VerbError("not a port list")
    return str(s)


def _package(s):
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,60}(?::[a-z0-9]{1,10})?", str(s)):
        raise VerbError("not a package name")
    return str(s)


class Rest:
    """A validator that consumes every remaining argument — see tools/panel-helper."""

    def __init__(self, check, minimum=1, maximum=64):
        self.check, self.minimum, self.maximum = check, minimum, maximum


def _rulenum(s):
    if not re.fullmatch(r"[1-9]\d{0,3}", str(s)):
        raise VerbError("not a rule number")
    return str(s)


def _choice(*allowed):
    def check(s):
        if str(s) not in allowed:
            raise VerbError("expected one of: " + ", ".join(allowed))
        return str(s)
    return check


# ── The verb table ────────────────────────────────────────────────────────────────────────────
# verb -> (validators, build(args) -> argv of the real tool, stdin or None)
#
# This mirrors tools/panel-helper's VERBS. Keep them identical — a unit test compares every verb's
# argv for a set of sample arguments and fails if they disagree.

_ARGV = {
    "ufw-status": ([_choice("plain", "numbered", "verbose")],
                   lambda a: [UFW, "status"] if a[0] == "plain" else [UFW, "status", a[0]], None),
    "ufw-enable": ([], lambda a: [UFW, "--force", "enable"], None),
    "ufw-default": ([_choice("allow", "deny", "reject"), _choice("incoming", "outgoing")],
                    lambda a: [UFW, "default", a[0], a[1]], None),
    "ufw-allow-port": ([_portspec, _comment],
                       lambda a: [UFW, "allow", a[0]] + (["comment", a[1]] if a[1] else []), None),
    "ufw-allow-proto-port": ([_choice("tcp", "udp"), _portspec, _comment],
                             lambda a: [UFW, "allow", "proto", a[0], "to", "any", "port", a[1]]
                             + (["comment", a[2]] if a[2] else []), None),
    "ufw-delete-allow-proto-port": ([_choice("tcp", "udp"), _portspec],
                                    lambda a: [UFW, "delete", "allow", "proto", a[0], "to", "any",
                                               "port", a[1]], None),
    # ── fail2ban ──
    "f2b-status": ([], lambda a: [F2B, "status"], None),
    "f2b-status-jail": ([_jail], lambda a: [F2B, "status", a[0]], None),
    "f2b-unban": ([_jail, _cidr], lambda a: [F2B, "set", a[0], "unbanip", a[1]], None),
    "f2b-reload": ([], lambda a: [F2B, "reload"], None),

    # ── systemd units, from a fixed list ──
    "service-restart": ([_choice(*UNITS)], lambda a: [SYSTEMCTL, "restart", a[0]], None),
    "service-reload": ([_choice(*UNITS)], lambda a: [SYSTEMCTL, "reload", a[0]], None),
    "service-enable-now": ([_choice(*UNITS)], lambda a: [SYSTEMCTL, "enable", "--now", a[0]], None),
    "service-disable-now": ([_choice(*UNITS)], lambda a: [SYSTEMCTL, "disable", "--now", a[0]], None),

    # sysctl -p on one of the panel's own drop-ins. The NAME maps to the same path the write verb
    # uses, so the two cannot point at different files.
    "sysctl-reload": ([_choice("tailscale")],
                      lambda a: ["sysctl", "-p", WRITE_TARGETS["sysctl-" + a[0]][0]], None),

    # ── root-owned file writes ──
    # The content travels on stdin, so the argv is only the destination NAME. Locally the helper
    # does the write itself; remotely it is still `base64 -d > path`, because a remote host has no
    # helper — but the path comes from this table rather than from a call site either way.
    "write-file": ([_choice(*sorted(WRITE_TARGETS))], lambda a: [], None),

    # ── sshd port changes ──
    "sshd-backup-dropin": ([], lambda a: [], None),
    "sshd-restore-dropin": ([], lambda a: [], None),
    "sshd-discard-backup": ([], lambda a: [], None),
    "f2b-set-sshd-ports": ([_portlist], lambda a: [], None),
    "sshd-validate": ([], lambda a: ["sshd", "-t"], None),
    "listening-sockets": ([], lambda a: ["ss", "-lnt"], None),
    "reboot-delayed": ([], lambda a: [], None),

    # ── cron and user accounts ──
    "crontab-list": ([_username], lambda a: ["crontab", "-u", a[0], "-l"], None),
    "user-create": ([_username], lambda a: ["useradd", "-m", "-s", "/bin/bash", a[0]], None),
    "user-lock-password": ([_username], lambda a: ["passwd", "-l", a[0]], None),
    "user-delete": ([_username], lambda a: ["userdel", "-r", a[0]], None),
    "user-delete-force": ([_username], lambda a: ["userdel", "-r", "-f", a[0]], None),
    "user-kill-processes": ([_username], lambda a: ["pkill", "-9", "-u", a[0]], None),
    # rm -rf as root: the path is CONSTRUCTED from a validated name, never passed in.
    "user-remove-home": ([_username], lambda a: ["rm", "-rf", "--", home_of(a[0])], None),

    # ── log reads ──
    # Neither journalctl nor tail is ever handed a caller's target: the SOURCE is a name from a
    # fixed set and this table maps it to units or to a path, so no path crosses the boundary.
    "journal": ([_choice(*JOURNAL_SOURCES), _linecount],
                lambda a: ["journalctl"]
                + [x for u in JOURNAL_UNITS[a[0]] for x in ("-u", u)]
                + ["--no-pager", "-n", a[1]], None),
    "log-tail": ([_choice(*LOG_FILES), _linecount],
                 lambda a: ["tail", "-n", a[1], LOG_FILES[a[0]]], None),
    "os-update-log": ([], lambda a: ["tail", "-c", "20000", OS_UPDATE_LOG], None),

    # ── apt / dpkg ──
    "apt-update": ([], lambda a: [APT, "update", "-qq"], None),
    "apt-full-upgrade": ([_choice("phased", "standard")],
                         lambda a: [APT, "full-upgrade", "-y"]
                         + (["-o", "APT::Get::Always-Include-Phased-Updates=true"]
                            if a[0] == "phased" else []) + APT_CONFOLD, None),
    "apt-upgrade": ([], lambda a: [APT, "upgrade", "-y"] + APT_CONFOLD, None),
    "apt-autoremove": ([], lambda a: [APT, "autoremove", "-y"], None),
    "apt-install": ([Rest(_package)], lambda a: [APT, "install", "-y"] + a, None),
    "apt-add-repo": ([_choice(*REPOS)], lambda a: ["add-apt-repository", "-y", a[0]], None),
    "dpkg-add-arch": ([_choice("i386")], lambda a: ["dpkg", "--add-architecture", a[0]], None),
    # Fixed pgrep patterns: pgrep takes a regex, so it is written here and never comes from a caller.
    "apt-any-running": ([], lambda a: ["pgrep", "-f", "apt-get"], None),
    "apt-upgrade-running": ([], lambda a: ["pgrep", "-f",
                                           "apt-get (upgrade|dist-upgrade|full-upgrade)"], None),
    "dpkg-lock-held": ([], lambda a: ["fuser", "/var/lib/dpkg/lock-frontend"], None),
    "reboot": ([], lambda a: ["reboot"], None),

    "ufw-delete-limit-port": ([_portspec], lambda a: [UFW, "delete", "limit", a[0]], None),
    # Only OpenSSH: the panel deletes exactly this one UFW application profile, so the validator is
    # the literal rather than an app-name pattern — the narrowest thing that still works.
    "ufw-delete-allow-app": ([_choice("OpenSSH")], lambda a: [UFW, "delete", "allow", a[0]], None),
    "ufw-limit-port": ([_portspec], lambda a: [UFW, "limit", a[0]], None),
    "ufw-allow-iface": ([_iface], lambda a: [UFW, "allow", "in", "on", a[0]], None),
    "ufw-delete-allow-port": ([_portspec], lambda a: [UFW, "delete", "allow", a[0]], None),
    "ufw-deny-ip": ([_cidr, _comment],
                    lambda a: [UFW, "insert", "1", "deny", "from", a[0]]
                    + (["comment", a[1]] if a[1] else []), None),
    "ufw-delete-deny-ip": ([_cidr], lambda a: [UFW, "delete", "deny", "from", a[0]], None),
    "ufw-delete-num": ([_rulenum], lambda a: [UFW, "delete", a[0]], "y\n"),
}



# Verbs the helper implements itself, with no tool to run. A REMOTE host has no helper, so each one
# needs the shell form it has always been sent — kept here, beside the verb, so the two renderings
# cannot drift. These are byte-identical to what the call sites used to build inline.
_REMOTE_ACTIONS = {
    "sshd-backup-dropin": lambda a: "[ -f %s ] && cp -f %s %s || true"
                          % (shlex.quote(SSHD_DROPIN), shlex.quote(SSHD_DROPIN),
                             shlex.quote(SSHD_DROPIN_BAK)),
    "sshd-restore-dropin": lambda a: "if [ -f %s ]; then mv -f %s %s; else rm -f %s; fi"
                           % (shlex.quote(SSHD_DROPIN_BAK), shlex.quote(SSHD_DROPIN_BAK),
                              shlex.quote(SSHD_DROPIN), shlex.quote(SSHD_DROPIN)),
    "sshd-discard-backup": lambda a: "rm -f %s" % shlex.quote(SSHD_DROPIN_BAK),
    "f2b-set-sshd-ports": lambda a: (
        "if [ -f /etc/fail2ban/jail.local ]; then "
        "sed -i '/^\\[sshd\\]/,/^\\[/{s/^port *=.*/port = %s/}' /etc/fail2ban/jail.local; "
        "systemctl restart fail2ban 2>&1 || true; fi" % a[0]),
    # The subshell is the point: it backgrounds the sleep so this command returns and the SSH
    # connection can close before the host goes down.
    "reboot-delayed": lambda a: "( sleep 2 ; reboot ) >/dev/null 2>&1 & echo scheduled",
}


def is_action(verb):
    """True when the helper performs this verb itself rather than running a tool."""
    return verb in _REMOTE_ACTIONS or verb == "write-file"


def check_args(verb, args):
    """Validated arguments for `verb`, as strings. Raises VerbError on anything unexpected."""
    spec = _ARGV.get(verb)
    if spec is None:
        raise VerbError("unknown verb")
    validators = spec[0]
    args = list(args)
    rest = validators[-1] if validators and isinstance(validators[-1], Rest) else None
    fixed = validators[:-1] if rest else validators
    if rest is None:
        if len(args) != len(fixed):
            raise VerbError("%s takes %d argument(s), got %d" % (verb, len(fixed), len(args)))
        checks = list(fixed)
    else:
        low, high = len(fixed) + rest.minimum, len(fixed) + rest.maximum
        if not low <= len(args) <= high:
            raise VerbError("%s takes %d..%d argument(s), got %d" % (verb, low, high, len(args)))
        checks = list(fixed) + [rest.check] * (len(args) - len(fixed))
    return [check(v) for v, check in zip(args, checks)]


def tool_argv(verb, args):
    """The real tool's argument vector for `verb` — e.g. ['/usr/sbin/ufw', 'status', 'numbered']."""
    return _ARGV[verb][1](check_args(verb, args))


def stdin_for(verb):
    """Text to feed the tool on stdin, or None. `ufw delete <n>` prompts; answering it here is what
    replaces the old `yes | ufw delete n`, and with it the pipe and the shell."""
    return _ARGV[verb][2]


def helper_argv(verb, args):
    """The argv that runs `verb` locally through the root-owned helper."""
    return ["sudo", "-n", HELPER_PATH, verb] + list(check_args(verb, args))


def remote_command(verb, args, merge_stderr=True):
    """The shell command that runs `verb` on a REMOTE host over SSH.

    Shell-quoted from the same validated argv, so the remote string is a rendering of the verb
    rather than a separately-maintained command. `2>&1` is kept because the existing callers read
    tool errors out of stdout; dropping it would silently change which stream messages land in."""
    checked = check_args(verb, args)
    if verb in _REMOTE_ACTIONS:
        # No tool to run — the helper does this one itself. A remote gets the shell form.
        return _REMOTE_ACTIONS[verb](checked)
    cmd = shlex.join(tool_argv(verb, args))
    if verb in NONINTERACTIVE:
        # The helper sets this on the child's environment; over SSH there is a shell, so the
        # familiar prefix is what goes on the wire — the same thing these commands always sent.
        cmd = "DEBIAN_FRONTEND=noninteractive " + cmd
    if stdin_for(verb) is not None:
        # No helper on the far side to feed stdin, so the prompt is answered the old way.
        cmd = "yes | " + cmd
    return cmd + (" 2>&1" if merge_stderr else "")


def write_target(name):
    """(path, mode) for a named root-owned destination. Raises VerbError on an unknown name."""
    if name not in WRITE_TARGETS:
        raise VerbError("unknown write target")
    return WRITE_TARGETS[name]


def remote_write_command(name, content):
    """The shell command that writes `content` to a named destination on a REMOTE host.

    A remote has no helper, so this is still `base64 -d > path` — but the path comes from
    WRITE_TARGETS rather than from a call site, and base64 keeps every byte of the content inert on
    the way through the shell."""
    import base64
    path, mode = write_target(name)
    b64 = base64.b64encode(content.encode()).decode()
    return ("echo %s | base64 -d > %s && chmod %o %s"
            % (shlex.quote(b64), shlex.quote(path), mode, shlex.quote(path)))


def verbs():
    """Every verb this module knows, for tests and for the operator-facing docs."""
    return sorted(_ARGV)
