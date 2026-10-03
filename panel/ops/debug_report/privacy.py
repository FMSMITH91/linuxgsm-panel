"""The report's privacy pass: pseudonymise known names, classify IPs, normalise paths (R72, R73).

Owner: builder B1. Sections are written never to print identifying values (see _base.py); this runs
over the finished text anyway, because log lines, installer output and other sections' detail are
free text.

prepare(ctx)              builds the in-memory name map once per report (request greenlet: DB reads).
scrub(ctx, text) -> text  applied by the assembler to the whole report and the summary.
scrub_lines(ctx, lines)   the same for a list of log lines, or None when the pass failed and the
                          lines must be withheld.
footer(ctx) -> [lines]    what was pseudonymised and what was kept, stated truthfully.
findings(ctx)             At-a-glance findings when the pass ran incompletely.

The order inside scrub: the checkout, data dir, virtualenv and home paths are normalised first (so a
traceback frame keeps its module and loses the account), then the syslog host field, then the known
names (longest first, case-insensitive, never inside a longer word), then the generic patterns that
need no names (*.ts.net, login URLs, URL userinfo, IP addresses by class, long ids, SteamIDs,
'@github' logins, SQLAlchemy bound parameters), and last system_ops._redact. The map is never
logged or printed: only the tokens and counts are.
"""
import ipaddress
import os
import re
import sys
import threading

from panel.ops.debug_report._base import finding

_MIN_NAME = 3
# Names that are words of the report or of the platform. Pseudonymising them would mangle the
# report ("Ubuntu 24.04" -> "[account-1] 24.04") and hide nothing: they identify no one.
_STOP_WORDS = frozenset((
    "root", "admin", "admins", "administrator", "ubuntu", "debian", "user", "users", "panel",
    "server", "servers", "game", "games", "host", "hosts", "local", "localhost", "linuxgsm",
    "linuxgsm-panel", "lgsmpanel", "lgsm", "lgsmpanel-games", "python", "python3", "systemd",
    "sudo", "kernel", "default", "main", "test", "none", "null", "true", "false", "www-data",
    "nobody", "daemon", "steam", "docker", "the", "and", "error", "warning", "info", "debug",
    "status", "online", "offline", "running", "started", "stopped", "update", "updates",
    "backup", "backups", "tailscale", "console", "database", "config", "network", "service",
    "unknown", "system", "journal", "helper", "privileged", "operator", "everyone",
    # generic first labels of a host's FQDN, which is mapped by its first label too: these name no
    # one, and "home" would turn every /home/[user] path into a token
    "www", "mail", "vps", "srv", "node", "box", "web", "app", "api", "home", "data", "dev",
    "prod", "cloud", "gateway", "router", "remote",
))
ETC_PASSWD = "/etc/passwd"  # nosec B105 - a file path, not a password
ETC_GROUP = "/etc/group"
_TAILNET_NETS = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))

# A journal line's host field, by position: after the timestamp (journalctl's short or short-iso
# form) and before the "ident[pid]:" tag. The tag is required, so a log line that merely starts
# with a date and a word is not taken for one.
_SYSLOG_HOST_RE = re.compile(
    r"^((?:[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]+[\d:]{5,8}|\d{4}-\d\d-\d\dT[\d:.]{5,15}"
    r"(?:[+-]\d\d:?\d\d|Z)?)[ \t]+)(\S{1,255})([ \t]+[\w./@-]{1,64}(?:\[\d{1,10}\])?:)", re.M)
_HOME_RE = re.compile(r"(/(?:home|srv|opt|var/home|Users))/(?!\[user\])[^/\s\"':;,)\]]{1,64}")
_VENV_RE = re.compile(r"(?:/[^\s/\"':]{1,255}){0,32}/(?:site|dist)-packages(?=/)")
_GENERIC = (
    (re.compile(r"\[parameters: [^\n]*"), "[parameters: withheld]", "sql-params"),
    # up to the LAST '@' before the path: userinfo can itself hold an unencoded '@'
    (re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{0,15}://)[^/\s]{1,256}@"), r"\1[redacted]@", "url"),
    (re.compile(r"(?:https?://)?login\.tailscale\.com[^\s)\"'>\]]*"), "[tailscale-url]", "url"),
    (re.compile(r"(?<![\w.-])[\w-]{1,63}(?:\.[\w-]{1,63}){0,8}\.ts\.net\b"), "[ts-name]", "ts-name"),
    (re.compile(r"(?<![\w.-])[\w.-]{1,64}@github\b"), "[login]", "login"),
    (re.compile(r"STEAM_[0-5]:[01]:\d{1,12}|\[U:1:\d{1,12}\]"), "[steamid]", "steamid"),
)
_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d])")
# Not preceded by a hex digit, ':' or '.', so a match starts at the first character an address can
# start at, even when a word is glued to it ('src2a01:...'); up to 45 characters, so a full-form
# address with a ':port' after it is one candidate. _ip_sub validates every candidate, and trims a
# trailing ':' or ':port' and a glued prefix before it gives up.
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:.%])[0-9A-Fa-f:]{2,45}(?:(?<=:)\d{1,3}(?:\.\d{1,3}){3})?"
                      r"(?:%[\w.-]{1,32})?")
# An address carried inside a provider's reverse-DNS name, dotted (static.77.13.2.81.clients...,
# often reversed) or dashed (ec2-81-2-13-77..., ip-51-38-12-34...): four octets between hostname
# labels. Each octet is checked to be 0-255 before it is replaced.
_IP_DOTTED_NAME_RE = re.compile(r"(?<=[A-Za-z]\.)()(\d{1,3}(?:\.\d{1,3}){3})(?=\.[A-Za-z])")
_IP_DASHED_NAME_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]{0,15}-)(\d{1,3}(?:-\d{1,3}){3})"
                                r"(?=\.[A-Za-z]|[^\w-]|\Z)")
_LONG_ID_RE = re.compile(r"(?<!\d)\d{15,}(?!\d)")
_WITHHELD = "_(withheld: pseudonymisation unavailable)_"


class _State(object):
    """One report's name map, what it replaced (for the footer), and what failed."""

    def __init__(self):
        """Start empty: no names, nothing replaced, nothing failed."""
        self.names = {}            # lowercased name -> token
        self.kinds = {}            # lowercased name -> kind, for the footer's counts
        self.counters = {}         # kind -> next sequential number (for names with no DB id)
        self.stats = {}            # kind -> set of what was replaced (never printed)
        self.source_errors = []    # (source, fixed reason or exception class)
        self.pattern_error = None  # exception class when the generic pass itself failed
        self.cred_key_missing = False
        self.ts_done = False
        self.lock = threading.Lock()

    def add(self, name, kind, ident=None):
        """Map `name` to a typed token; ident is a DB id when the name belongs to a row.

        Keyed by _name_key (folded case, single spaces). A name whose full case folding differs
        ('Straße' -> 'strasse') is mapped under that spelling too, to the same token.
        """
        if not isinstance(name, str):
            return
        key = _name_key(name)
        with self.lock:
            if not _usable_name(key) or key in self.names:
                return
            if ident is None:
                ident = self.counters.get(kind, 0) + 1
                self.counters[kind] = ident
            token = "[%s-%s]" % (kind, ident) if ident != "" else "[%s]" % kind
            for variant in (key, _name_key(name.casefold())):
                if variant not in self.names and _usable_name(variant):
                    self.names[variant], self.kinds[variant] = token, kind

    def snapshot(self):
        """A copy of the map, safe to iterate while another thread adds a name."""
        with self.lock:
            return dict(self.names), dict(self.kinds)

    def hit(self, kind, value):
        """Record that `value` of `kind` was replaced."""
        self.stats.setdefault(kind, set()).add(value)


def _fold(text):
    """`text` lower-cased one character for one.

    A match found in it is then at the same offset in `text` ('İ'.lower() is two characters; its
    first is the simple lower case 'i').
    """
    low = text.lower()
    return low if len(low) == len(text) else "".join(ch.lower()[:1] or ch for ch in text)


def _name_key(name):
    """A name as the map keys it: folded, its whitespace runs single spaces."""
    return " ".join(_fold(name).split())


def _usable_name(key):
    """Whether a lowercased name is long enough, not a common word, and not an address."""
    if len(key) < _MIN_NAME or key in _STOP_WORDS or "\n" in key:
        return False
    try:
        ipaddress.ip_address(key)
        return False                       # the IP rule classifies addresses
    except ValueError:
        return True


# ── the name map ────────────────────────────────────────────────────────────────────────────────
def prepare(ctx):
    """The report's privacy state, built once (DB, OS and config names). Never raises."""
    try:
        return ctx.memo("privacy", lambda: _build(ctx))
    except Exception as exc:  # noqa: BLE001 - an empty map, said in the footer and At a glance
        name = type(exc).__name__
        return ctx.memo("privacy_fallback", lambda: _failed_state(name))


def _failed_state(name):
    st = _State()
    st.source_errors.append(("the name map", name))
    return st


def _build(ctx):
    st = _State()
    for source, fn in (("database names", _names_db), ("OS names", _names_os),
                       ("config names", _names_config)):
        try:
            fn(ctx, st)
        except Exception as exc:  # noqa: BLE001 - one source missing is said, never fatal
            st.source_errors.append((source, type(exc).__name__))
    return st


class NoAppContext(LookupError):
    """There is no Flask app to read the database through (a CLI or test caller)."""


def _in_app(ctx, fn):
    """fn() inside an app context: the current one, else ctx.app's; raises without either."""
    from flask import has_app_context
    if has_app_context():
        return fn()
    if ctx.app is None:
        raise NoAppContext("no app")
    with ctx.app.app_context():
        return fn()


def _names_db(ctx, st):
    from panel.core import config as cfgmod
    st.cred_key_missing = not cfgmod.CRED_KEY_FILE.exists()
    _in_app(ctx, lambda: _read_db_names(st))
    if st.cred_key_missing:
        st.source_errors.append(("host addresses and accounts", "cred_key missing"))


def _read_db_names(st):
    from panel.db.models import Group, ServerTag, User, db
    _read_host_names(st)
    _read_server_names(st)
    for model, col, kind in ((User, User.username, "user"), (ServerTag, ServerTag.name, "tag"),
                             (Group, Group.name, "group")):
        for ident, name in db.session.query(model.id, col):
            st.add(name, kind, ident)


def _read_host_names(st):
    from panel.db.models import RemoteServer, db
    if st.cred_key_missing:
        # Reading the encrypted columns would call decrypt_secret, which CREATES a new cred_key
        # when it is missing. Only the plain name column is read; the generic rules still apply.
        for rid, name in db.session.query(RemoteServer.id, RemoteServer.name):
            st.add(name, "host", rid)
        return
    for row in db.session.query(RemoteServer.id, RemoteServer.name, RemoteServer.host,
                                RemoteServer.public_ip, RemoteServer.username,
                                RemoteServer.linuxgsm_user):
        for value in row[1:4]:
            st.add(value, "host", row[0])
            st.add(_first_label(value), "host", row[0])
        for value in row[4:]:
            st.add(value, "account")


def _first_label(value):
    """A host name's first label ('zephyr' of 'zephyr.example.org'); '' for an address.

    Also '' for a name with no dot. Logs often print a host by its short name.
    """
    value = str(value or "").strip()
    if "." not in value:
        return ""
    try:
        ipaddress.ip_address(value)
        return ""
    except ValueError:
        label = value.split(".", 1)[0]
        return "" if label.isdigit() else label


def _read_server_names(st):
    """Game-server names; a short name that is LinuxGSM's own ('<game>server') is vocabulary."""
    from panel.db.models import GameServer, db
    for sid, name, short, gtype in db.session.query(GameServer.id, GameServer.name,
                                                     GameServer.short_name, GameServer.game_type):
        common = {(gtype or "").lower(), (gtype or "").lower() + "server"}
        for value in (name, short):
            if (value or "").strip().lower() not in common:
                st.add(value, "server", sid)


def _names_os(_ctx, st):
    import socket
    host = socket.gethostname() or ""
    for value in (host, _first_label(host)):
        st.add(value, "panel-host", "")
    for value in _etc_hosts_names(host):
        st.add(value, "panel-host", "")
    for value in _os_accounts():
        st.add(value, "account")


def _etc_hosts_names(host):
    """The other names /etc/hosts gives this machine (on a line naming it, or on 127.0.1.1)."""
    out = []
    try:
        with open("/etc/hosts", encoding="utf-8", errors="replace") as f:
            lines = f.read(65536).splitlines()
    except OSError:
        return out
    for line in lines:
        parts = line.split("#", 1)[0].split()
        if len(parts) > 1 and (parts[0] == "127.0.1.1" or host in parts[1:]):
            out.extend(parts[1:])
    return out


def _os_accounts():
    """The panel's own account, every login account (uid 1000+), and the game-account group.

    Parsed from /etc/passwd and /etc/group, never pwd.getpwall()/grp.getgrnam(): those are NSS
    calls that can fall through to LDAP/SSSD, native calls that block the eventlet hub, and this
    runs in the request greenlet. Only getpwuid(own uid) is asked of NSS.
    """
    import pwd
    names = [pwd.getpwuid(os.getuid()).pw_name]
    for parts in _etc_rows(ETC_PASSWD):
        if len(parts) > 2 and parts[2].isdigit() and 1000 <= int(parts[2]) < 65534:
            names.append(parts[0])
    for parts in _etc_rows(ETC_GROUP):
        if len(parts) > 3 and parts[0] == "lgsmpanel-games":
            names += [m for m in parts[3].split(",") if m]
    return names


def _etc_rows(path):
    """The ':'-split rows of a local account file; [] when it cannot be read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [line.rstrip("\n").split(":") for line in fh.read(4 * 1024 * 1024).splitlines()
                    if line and not line.startswith("#")]
    except OSError:
        return []


def _names_config(_ctx, st):
    from panel.core import config as cfgmod
    cfg = cfgmod.load_config()
    if cfgmod.is_unreadable(cfg):
        raise ValueError("config.json unreadable")
    if (cfg.get("site_title") or "") != cfgmod.DEFAULT_CONFIG.get("site_title"):
        st.add(cfg.get("site_title"), "site-title", "")
    st.add(cfg.get("site_domain"), "site-domain", "")
    _names_origins(st, cfg)
    _names_notifications(st, cfg.get("notifications") or {})


def _names_origins(st, cfg):
    """Map the host names an operator configured for the panel to be reached by.

    A reverse proxy's domain in socketio_cors_origins, a bind_host given as a name: engineio logs
    a refused origin verbatim at ERROR, and the panel logs its bind at start.
    """
    from urllib.parse import urlsplit
    origins = cfg.get("socketio_cors_origins")
    origins = [origins] if isinstance(origins, str) else list(origins or [])
    names = []
    for origin in origins:
        try:
            names.append(urlsplit(str(origin)).hostname or "")
        except ValueError:
            continue                        # not a URL: the generic rules still apply
    names.append(str(cfg.get("bind_host") or ""))
    for name in names:
        st.add(name, "site-domain", "")
        st.add(_first_label(name), "site-domain", "")


def _ids(value):
    """A list of ids from a config value that is a list, or a comma/space separated string."""
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [v for v in re.split(r"[\s,]+", str(value or "")) if v]


def _names_bot(st, conf, key):
    if not isinstance(conf, dict):
        return
    for value in [conf.get(key)] + _ids(conf.get("command_users")):
        st.add(str(value or ""), "id")
        # a group's chat id is negative; logs and API errors often print it without the sign
        st.add(str(value or "").strip().lstrip("-"), "id")
    for secret in ("token", "bot_token", "webhook"):
        st.add(str(conf.get(secret) or ""), "secret", "")


def _names_ntfy(st, ntfy):
    from urllib.parse import urlsplit
    if not isinstance(ntfy, dict):
        return
    st.add(str(ntfy.get("topic") or ""), "ntfy-topic", "")
    st.add(str(ntfy.get("token") or ""), "secret", "")
    try:
        st.add(urlsplit(str(ntfy.get("server") or "")).hostname or "", "ntfy-host", "")
    except ValueError:
        pass                            # not a URL: the generic rules still apply


def _names_notifications(st, notif):
    if not isinstance(notif, dict):
        return
    _names_bot(st, notif.get("telegram"), "chat_id")
    _names_bot(st, notif.get("discord"), "channel_id")
    _names_ntfy(st, notif.get("ntfy"))


# Keys of tailscale data whose string values name a node, a person or the tailnet.
_TS_KEYS = re.compile(r"(?i)name|host|dns|login|display|tailnet|suffix|user|domain|node|peer|owner")


def _names_tailscale(info, st, key="", depth=0):
    """Walk _src_tailscale.info()'s dict and map every identity-looking string in it."""
    if depth > 6:
        return
    if isinstance(info, dict):
        for k, v in list(info.items())[:2000]:
            _names_tailscale(v, st, str(k), depth + 1)
    elif isinstance(info, (list, tuple)):
        for v in list(info)[:2000]:
            _names_tailscale(v, st, key, depth + 1)
    elif isinstance(info, str) and _TS_KEYS.search(key):
        value = info.strip().rstrip(".")
        st.add(value, "tailnet-name")
        st.add(value.split(".")[0], "tailnet-name")
        if "@" in value:                    # a login's handle prints on its own too
            st.add(value.split("@", 1)[0], "tailnet-name")


def _tailscale_names(ctx, st, wait):
    """Add Tailscale's names, from the report's one read when a section already made it.

    The read is never forced here: when no section has made it, it runs in a thread waited on for
    at most `wait` seconds, so a cold Tailscale cache cannot hold the report past its budget.
    """
    with st.lock:
        if st.ts_done:
            return
        st.ts_done = True
    from panel.ops.debug_report import _src_tailscale
    box, done = {}, threading.Event()

    def _read():
        # shared_read, not shared_info: info() answers None both for "not installed" and for a
        # status that could not be read, and only the second leaves names unmapped.
        try:
            state, val = _src_tailscale.shared_read(ctx, wait=wait)
            if state == "error":
                box["error"] = str(val)
            elif state == "ok":
                box["info"] = val
        except Exception as exc:  # noqa: BLE001 - reported as a source error below
            box["error"] = type(exc).__name__
        finally:
            done.set()

    threading.Thread(target=_read, name="debug-report-tailscale-names", daemon=True).start()
    if not done.wait(max(0.1, wait)):
        st.source_errors.append(("tailscale names", "timed out"))
    elif "error" in box:
        st.source_errors.append(("tailscale names", box["error"]))
    elif box.get("info") is not None:
        _names_tailscale(box["info"], st)


# ── the pass ────────────────────────────────────────────────────────────────────────────────────
def _paths(text, st):
    """The data dir, the virtualenv, the checkout and home directories as fixed placeholders."""
    from panel.core import config as cfgmod
    from panel.ops import system_ops as so
    text = _replace_dir(text, str(cfgmod.DATA_DIR), "<data>")
    if "-packages/" in text:
        text = _VENV_RE.sub("<venv>", text)
    if sys.prefix != sys.base_prefix:      # a virtualenv's own root (bin/python and the like)
        text = _replace_dir(text, sys.prefix, "<venv>")
    text = _replace_dir(text, so.PANEL_DIR, "<panel>")

    def _home(m):
        st.hit("home", m.group(0))
        return m.group(1) + "/[user]"
    return _HOME_RE.sub(_home, text)


def _replace_dir(text, path, token):
    """`text` with `path` (as given and as resolved) replaced by `token`, longest first."""
    for variant in sorted({path, os.path.realpath(path)}, key=len, reverse=True):
        if len(variant) > 1:
            text = text.replace(variant, token)
    return text


def _syslog_hosts(text, st):
    """The journal's host field rewritten by position.

    The name is also MAPPED, so the same name later in the message ('unable to resolve host <old
    name>') is caught by the known-name pass: an old hostname is in no other source.
    """
    def _host(m):
        if m.group(2).startswith("["):
            return m.group(0)
        st.hit("panel-host", m.group(2).lower())
        st.add(m.group(2), "panel-host", "")
        return m.group(1) + "[panel-host]" + m.group(3)
    return _SYSLOG_HOST_RE.sub(_host, text)


def _is_heading(line):
    """Whether `line` is one of the assembler's own headings (fixed text).

    Those are never pseudonymised, and are kept when bodies are withheld. Any other line starting
    with '#' is content, a log line.
    """
    if not line.startswith(("## ", "### ")):
        return False
    from panel.ops.debug_report import SECTIONS
    rest = line.split(" ", 1)[1]
    titles = [sec[1] for sec in SECTIONS] + list(_OWN_HEADINGS)
    return any(rest == t or rest.startswith((t + " _(", t + ": ", t + " (")) for t in titles)


_OWN_HEADINGS = ("LinuxGSM Panel debug report", "At a glance", "Verdicts", "All findings",
                 "Privacy")


def _name_rx(key):
    """The pattern for one map key: its words with any run of whitespace between them."""
    return r"\s+".join(map(re.escape, key.split(" ")))


def _known_names(text, st):
    """Every known name in `text` replaced by its token. Headings are fixed text and skipped.

    Matched over each run of non-heading lines, so a name split across a line break is still
    one match; the token keeps the line breaks it replaced, so the line count never changes.
    """
    names, kinds = st.snapshot()
    low = _fold(text)
    present = [n for n in names if n.split(" ", 1)[0] in low]
    if not present:
        return text
    present.sort(key=len, reverse=True)
    rx = re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % "|".join(map(_name_rx, present)),
                    re.I)

    def _sub(m):
        key = _name_key(m.group(0))
        st.hit(kinds.get(key, "name"), key)
        return names.get(key, "[name]") + "\n" * m.group(0).count("\n")

    out, run = [], []
    for line in text.split("\n"):
        if _is_heading(line):
            if run:
                out.append(rx.sub(_sub, "\n".join(run)))
                run = []
            out.append(line)
        else:
            run.append(line)
    if run:
        out.append(rx.sub(_sub, "\n".join(run)))
    return "\n".join(out)


def _ip_class(ip):
    """The class an address prints as, or None for one kept as it is (loopback, unspecified)."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return None
    if any(ip.version == n.version and ip in n for n in _TAILNET_NETS):
        return "tailnet"
    for attr, cls in (("is_link_local", "link-local"), ("is_private", "private"),
                      ("is_multicast", "multicast")):
        if getattr(ip, attr):
            return cls
    return "public"


def _v4(raw):
    """An IPv4 address written with zero-padded octets ('081.002.013.077'), or None."""
    parts = raw.split(".")
    if len(parts) != 4 or not all(p.isdigit() and int(p) <= 255 for p in parts):
        return None
    return ipaddress.ip_address(".".join(str(int(p)) for p in parts))


def _ip_candidates(raw):
    """(prefix, address, suffix) readings of a candidate, most literal first."""
    yield "", raw, ""
    yield "", raw.split("%", 1)[0], ""               # its zone (an interface name) dropped
    if ":" not in raw:
        return
    stripped = raw.rstrip(":")
    if stripped != raw:                              # 'addr: message'
        yield "", stripped, raw[len(stripped):]
    port = re.match(r"(.+):(\d{1,5})\Z", stripped)
    if port:                                         # a full-form address and its ':port'
        yield "", port.group(1), raw[len(port.group(1)):]
    if stripped.count(":") >= 3:                     # a word glued in front of it ('src2a01:...')
        for cut in range(1, 5):
            yield raw[:cut], stripped[cut:], raw[len(stripped):]


def _ip_parse(raw):
    """(prefix, ipaddress object, suffix) for the first reading that is an address, or None."""
    for prefix, addr, suffix in _ip_candidates(raw):
        try:
            return prefix, ipaddress.ip_address(addr), suffix
        except ValueError:
            ip = _v4(addr) if "." in addr and ":" not in addr else None
            if ip is not None:
                return prefix, ip, suffix
    return None


def _v6_skip(m):
    """Whether an IPv6 candidate is not one to read.

    A word glued to fewer than three colons ('Type::bad'), or the '::ffff:' left in front of an
    IPv4 address already replaced.
    """
    text, start, end = m.string, m.start(), m.end()
    glued = start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_")
    return (glued and m.group(0).count(":") < 3) or text[end:end + 1] == "["


def _ip_sub(st):
    def _sub(m):
        raw = m.group(0)
        if ":" in raw and _v6_skip(m):
            return raw
        got = _ip_parse(raw)
        if got is None:
            return raw
        prefix, ip, suffix = got
        cls = _ip_class(ip)
        if cls is None:
            return raw
        st.hit("ip:" + cls, str(ip))
        return "%s[ip:%s]%s" % (prefix, cls, suffix)
    return _sub


def _ip_in_name(st):
    def _sub(m):
        octets = re.split(r"[.-]", m.group(2))
        if not all(int(o) <= 255 for o in octets):
            return m.group(0)
        st.hit("ip:in-hostname", ".".join(octets))
        return m.group(1) + "[ip:in-hostname]"
    return _sub


def _generic(text, st):
    for rx, repl, kind in _GENERIC:
        if kind != "sql-params" and rx.search(text):
            for m in rx.finditer(text):
                st.hit(kind, m.group(0).lower())
        text = rx.sub(repl, text)
    sub = _ip_sub(st)
    for rx in (_IP_DOTTED_NAME_RE, _IP_DASHED_NAME_RE):
        text = rx.sub(_ip_in_name(st), text)
    text = _IPV4_RE.sub(sub, text)
    if ":" in text:
        text = _IPV6_RE.sub(lambda m: sub(m) if m.group(0).count(":") >= 2 else m.group(0), text)

    def _long(m):
        st.hit("id", m.group(0))
        return "[id]"
    return _LONG_ID_RE.sub(_long, text)


def scrub(ctx, text):
    """`text` pseudonymised; when the pattern pass itself fails, every body is withheld."""
    from panel.ops import system_ops as so
    st = prepare(ctx)
    try:
        text = _paths(text, st)
        text = _syslog_hosts(text, st)
    except Exception as exc:  # noqa: BLE001 - nothing pattern-only is printed after this
        st.pattern_error = type(exc).__name__
        return _withhold(text)
    try:
        text = _known_names(text, st)
    except Exception as exc:  # noqa: BLE001 - the generic rules below still run
        st.source_errors.append(("name matching", type(exc).__name__))
    try:
        return so._redact(_generic(text, st))
    except Exception as exc:  # noqa: BLE001 - withhold rather than print pattern-free text
        st.pattern_error = type(exc).__name__
        return _withhold(text)


def scrub_lines(ctx, lines):
    """`lines` scrubbed one for one, or None when they must be withheld (the pass failed)."""
    out = scrub(ctx, "\n".join(lines)).split("\n")
    if prepare(ctx).pattern_error or len(out) != len(lines):
        return None
    return out


def scrub_text(ctx, text):
    """One piece of free text scrubbed before a section cuts it.

    '(withheld)' when the pass failed: the assembler then withholds every body anyway.
    """
    out = scrub(ctx, text)
    return "(withheld)" if prepare(ctx).pattern_error else out


def _withhold(text):
    """Headings kept, every other line replaced by one 'withheld' line per section."""
    out = []
    for line in text.split("\n"):
        if _is_heading(line):
            out.extend([line, _WITHHELD])
    return "\n".join(out) + "\n"


def finish(ctx, wait):
    """Before the final pass: add Tailscale's names (waiting at most `wait` s for them)."""
    try:
        _tailscale_names(ctx, prepare(ctx), wait)
    except Exception as exc:  # noqa: BLE001 - reported in the footer
        prepare(ctx).source_errors.append(("tailscale names", type(exc).__name__))


# ── what the reader is told ─────────────────────────────────────────────────────────────────────
def findings(ctx):
    """At-a-glance findings for a pass that did not fully run."""
    st = prepare(ctx)
    out = []
    if st.pattern_error:
        out.append(finding("fail", "Privacy", "pattern redaction failed; section bodies withheld"))
    if st.source_errors:
        out.append(finding("warn", "Privacy", "some known names could not be read; only pattern "
                                              "redaction covers them; review names before posting"))
    return out


_FOOTER_KINDS = (("host", "host"), ("server", "game server"), ("user", "panel user"),
                 ("account", "OS or SSH account"), ("tag", "tag"), ("group", "group"),
                 ("panel-host", "panel hostname"), ("tailnet-name", "Tailscale name"),
                 ("ts-name", "*.ts.net name"), ("login", "@github login"),
                 ("site-title", "site title"), ("site-domain", "site domain"),
                 ("ntfy-topic", "ntfy topic"), ("ntfy-host", "ntfy server"),
                 ("id", "long id"), ("steamid", "SteamID"), ("url", "URL credential or login link"),
                 ("secret", "configured secret"), ("home", "home-directory path"))


def _counts(st):
    parts = []
    for kind, label in _FOOTER_KINDS:
        n = len(st.stats.get(kind, ()))
        if n:
            parts.append("%d %s%s" % (n, label, "" if n == 1 else "s"))
    ips = {k[3:]: len(v) for k, v in st.stats.items() if k.startswith("ip:")}
    if ips:
        parts.append("%d IPs (%s)" % (sum(ips.values()), ", ".join(
            "%d %s" % (n, cls) for cls, n in sorted(ips.items(), key=lambda kv: -kv[1]))))
    return parts


def footer(ctx):
    """The Privacy section: what the pass replaced and kept, and what it could not cover."""
    st = prepare(ctx)
    parts = _counts(st)
    lines = ["### Privacy",
             "- **Pseudonymised**: %s. Loopback and unspecified addresses (0.0.0.0, ::) kept."
             % ("; ".join(parts) if parts else "nothing matched a known name or pattern"),
             "- Paths: the checkout prints as <panel>, the data directory as <data>, the "
             "virtualenv as <venv>, home directories as /home/[user]. Tokens are the same in "
             "every section; [host-N], [server-N], [user-N], [tag-N] and [group-N] carry the "
             "row's database id."]
    if st.pattern_error:
        lines.append("- **Pattern redaction FAILED** (%s): every section body was withheld."
                     % st.pattern_error)
    for source, why in st.source_errors:
        lines.append("- **Known-name pseudonymisation incomplete**: %s unavailable (%s); only "
                     "pattern redaction covers them. Review host and server names before posting."
                     % (source, why))
    lines.append("- Not covered: names under %d characters, common words, and names deleted "
                 "since (an IP address is still caught by the IP rule; a host NAME deleted since "
                 "is not). This is a best-effort pass: review the report before posting it."
                 % _MIN_NAME)
    return lines
