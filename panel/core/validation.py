"""Input validation the panel applies BEFORE a value reaches a model, a shell or a page.

WHY THIS IS ITS OWN MODULE. These are pure functions and compiled patterns with no dependency on
the Flask app, the database or any panel state — and they were defined in app.py, which every
route module then had to reach back into (`from app import SAFE_LABEL_RE, _port_or, ...`). app.py
imports the route modules; the route modules imported app.py. That is not a cycle at RUNTIME (the
route imports are lazy, inside register_routes) but it is one to a static analyser, and CodeQL
cannot follow a use across it — which is how seven names in app.py came back as
py/unused-global-variable while their equivalents in panel/core/ did not. See panel/routes/__init__.

Living here, the arrow points one way: panel.core knows nothing about app.py, and app.py and every
route module import from it. Nothing about a route changes — no endpoint is renamed, no decorator
moves — because this holds no routes.

The values themselves are MOVED VERBATIM from app.py, comments and all, so the diff reads as a move.
"""
import ipaddress
import os
import re
import secrets as _secrets
import unicodedata
from urllib.parse import quote

from panel.core import i18n


# ── Strict input validation ───────────────────────────────────────────────
# These values become LinuxGSM shortnames, Linux usernames, home-directory paths and
# arguments to shell commands run as root during install. LinuxGSM shortnames are
# lowercase alphanumeric; a game-server instance name becomes a Linux user. Rejecting
# anything outside a safe charset here is what prevents shell/command injection into
# the install pipeline (a user with INSTALL_SERVER must NOT be able to run arbitrary
# root commands on a host).
GAME_TYPE_RE = re.compile(r"^[a-z0-9]{1,32}\Z")
INSTANCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}\Z")   # valid Linux username shape
LINUX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\Z")     # for linuxgsm_user / ssh user
# Hostname / IPv4 / IPv6 / Tailscale MagicDNS — no HTML or shell metacharacters, so a
# stored host can't inject markup where it's shown (e.g. the dashboard connect address).
# Never a leading dash: the host is an ARGUMENT to the system ssh client (the Tailscale transport,
# the terminal, the download streams), and ssh reads an argument that begins with `-` as an
# option — `-oProxyCommand=…` runs a command. No hostname, IPv4 or IPv6 address starts with one.
# ssh_manager._core.ssh_destination holds every stored host to this again before it is used,
# because a row LOADED from the database never passed through the route that checks it here.
# No brackets: `[2001:db8::5]` (how the panel itself PRINTS an IPv6 login) passed, was stored, and
# was handed to ssh and paramiko as typed — neither strips them, so nothing resolved and every
# command to that host failed. canonical_host drops them before this is asked.
HOST_RE = re.compile(r"^[A-Za-z0-9._:][A-Za-z0-9._:-]{0,254}\Z")
# An SSH host key fingerprint as `ssh-keygen -lf` prints it (SHA256 is its default hash): "SHA256:" and the
# digest in base64, whose 32 bytes are 43 characters without the padding OpenSSH leaves off.
_HOST_KEY_FP_RE = re.compile(r"(?:^|\s)(SHA256:[A-Za-z0-9+/]{43})=?(?:\s|\Z)")
# Free-text display labels (e.g. a remote's name): allow spaces/punctuation but reject the
# characters that would let a stored label break out of HTML or a JS string when it's shown
# in the UI's client-side rendering. Defense-in-depth alongside output encoding.
SAFE_LABEL_RE = re.compile(r"""^[^<>"'`\r\n\\]{1,120}\Z""")

# The auth methods a REMOTE may be set to from a form. RemoteServer.auth_method also has a fourth
# value, "local", and that one is deliberately absent: it is not a credential choice but a
# transport choice — _core.is_local_server() treats `auth_method == "local"` as "this record is
# this machine" — so accepting it from a form would let a remote's commands be redirected onto the
# panel host. The panel's own row is created with it by host_local.py and is identified by
# `is_local`, never by an edit.
EDITABLE_AUTH_METHODS = ("key", "password", "tailscale")

# A KEY login's credential is the PATH of a private key file on the panel host, never the key's
# text. Pasting the key itself is an easy mistake, and it used to reach paramiko as a file name:
# open() failed, and the FileNotFoundError, whose message is the "path", i.e. the whole private
# key, was logged with its traceback into the system journal. OWASP Logging Cheat Sheet, "Data to
# exclude": encryption keys and other primary secrets are not recorded. So text that cannot be a
# path is refused before anything opens it, and the refusal never repeats it.
_PATH_MAX = 4096    # Linux PATH_MAX, terminating NUL included
_NAME_MAX = 255     # Linux NAME_MAX: the longest single path component
KEY_TEXT_REFUSED = ("The key field takes the path of a private key file on the panel host (for "
                    "example /home/panel/.ssh/id_ed25519), not the key itself. Nothing was sent or "
                    "saved. Put the key in a file the panel's account can read and enter its path.")


def key_text_problem(auth_method, credential):
    """KEY_TEXT_REFUSED when a key login's credential looks like key text, not a path; else None.

    Key text: a PEM or OpenSSH header (`-----BEGIN`), a line break or any other control character,
    or a length no file name can have. A password is not judged here: any text may be one.
    """
    if auth_method != "key" or not credential:
        return None
    if "-----BEGIN" in credential or any(ord(c) < 32 or ord(c) == 127 for c in credential):
        return KEY_TEXT_REFUSED
    if len(credential) >= _PATH_MAX or any(len(p) > _NAME_MAX for p in credential.split("/")):
        return KEY_TEXT_REFUSED
    return None

# ── IP addresses and networks ─────────────────────────────────────────────
# ipaddress parses an IPv6 ZONE ID (the scope after '%') and keeps it VERBATIM. 'fe80::1%x y',
# 'fe80::1%$(id)' and 'fe80::1%' + a newline + 'FAKE' all parse, and str() hands the text back with
# its spaces and newlines. So "it parsed as an address" never meant "it is only an address", and
# every check that took str(ipaddress.ip_address(x)) as its canonical, safe form let free text
# through: into data/auth.log (which fail2ban reads), admin alerts, the audit trail, the root
# helper's argv and a remote host's sshd drop-in.
#
# A client, ban, whitelist, firewall or bind address never legitimately carries a zone. A zone
# names an interface of the machine that holds the address, and means nothing to a ban list, a
# firewall rule, a log line or another host. So these REFUSE one outright, and with it refused
# the canonical text is built by ipaddress from the parsed number: hex digits, ':' and '.' only.
# The one exception is unzoned_ip_address_or_none, for the few callers that must key a real
# address rather than refuse it; its docstring says which.


# What an audit row records as the address of a block or unban whose address did not parse: a
# fixed text, never the request's own.
NOT_AN_IP = "(not an IP address)"


def _ip_text(value):
    """The stripped text of `value`, or None when it is empty or holds a zone id ('%')."""
    text = "" if value is None else str(value).strip()
    return text if text and "%" not in text else None


def ip_address_or_none(value):
    """Parse `value` as exactly one IP address; None for anything else, a zone id included.

    str() of the result is the canonical form: what fail2ban and ufw store, and what two
    spellings of one address ("2001:0DB8::0001", "2001:db8::1") compare equal as.
    """
    text = _ip_text(value)
    if text is None:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def ip_network_or_none(value):
    """Parse `value` as an IP network, host bits masked; None for anything else, a zone id included.

    A bare address is its own /32 or /128. 'fe80::/64%x' was already refused, but ipaddress
    accepts 'fe80::1%x y' as a network and keeps the zone at /128 — and at any prefix when the
    host bits are zero ('2001:db8::%x y/64').
    """
    text = _ip_text(value)
    if text is None:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def canonical_ip(value):
    """The canonical text of `value` as one IP address, or None (see ip_address_or_none)."""
    addr = ip_address_or_none(value)
    return None if addr is None else str(addr)


def canonical_host(value):
    """A host as the panel stores and dials it: an IP literal in its canonical text, brackets gone.

    `[2001:db8::5]` -> `2001:db8::5`, and every spelling of one address the same text
    (`fd7a:115c:a1e0:0:0:0:0:1` and `fd7a:115c:a1e0::1`), which is how Tailscale lists a peer's
    address. A name, or anything else that is not one address, comes back unchanged for HOST_RE to
    judge. The ONE canonicalisation every reader of RemoteServer.host goes through: the model's
    validator, the stored-row migration, the transports and the debug report's peer match.
    """
    if not isinstance(value, str):
        return value
    inner = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    addr = ip_address_or_none(inner)
    return value if addr is None else str(addr)


def canonical_ip_or_network(value):
    """An address as its canonical address, 'a/n' as its canonical NETWORK; None otherwise.

    '10.0.0.5/24' -> '10.0.0.0/24'. The form the security whitelist is stored and compared in.
    """
    text = _ip_text(value)
    if text is not None and "/" in text:
        net = ip_network_or_none(text)
        return None if net is None else str(net)
    return canonical_ip(text)


def global_ipv4(text):
    """Return `text` as a public (globally routable) IPv4 address, else ""."""
    try:
        addr = ipaddress.IPv4Address(str(text or "").strip())
    except ValueError:
        return ""
    return str(addr) if addr.is_global else ""


def unzoned_ip_address_or_none(value):
    """Parse `value` as one IP address with any IPv6 zone id DROPPED rather than refused.

    Only for a value that must still be keyed or judged as the address it names:

      * the SOCKET PEER. The kernel can hand a link-local client over with its interface as the
        zone (fe80::1%eth0); eventlet reports one without it, but a WSGI server is free to write
        it. That is one real client, and refusing it would key it as raw text or skip its ban;
      * the client address a PROXY reports. Apache's mod_proxy and Go's httputil.ReverseProxy
        write a link-local client into X-Forwarded-For with its zone. Refusing it keyed that
        client as the proxy, so its failed logins reached auth.log as the proxy's, and fail2ban
        banned the proxy and everyone behind it;
      * a throttle KEY, which must stay one bucket per address whatever text follows the '%';
      * a refuse-only ban check, where reading the address a zone is attached to can only refuse
        more — refusing the value instead let '2001:db8::1%x' past a ban on 2001:db8::1;
      * a value an older version already STORED with a zone (a whitelist entry, an audit row's
        address), which is read as the address it was stored for.

    What such a caller records, logs or hands on is str() of the result: the parsed number, with
    no zone. Never the input text, and never the value itself where refusing it is the check (a
    ban, a firewall rule, a bind address): use ip_address_or_none there.
    Only IPv6 has zones, so '1.2.3.4%x' is not an address at all.
    """
    text = "" if value is None else str(value).strip()
    addr = ip_address_or_none(text.split("%", 1)[0])
    if addr is not None and "%" in text and addr.version != 6:
        return None
    return addr


def unzoned_ip_or_network(value):
    """A STORED whitelist entry as canonical text, an IPv6 zone id dropped; None if it is neither.

    For entries written before the whitelist refused a zone (the add refuses one now, so only an
    older config holds one). Before that refusal the auto-block and the ban gate honoured such an
    entry as the address or network it named, and the Settings page still lists it as active, so
    it is read that way again rather than silently exempting nothing. A bare address stays an
    address ('fe80::1%eth0' -> 'fe80::1'); 'a%zone/n' is the network the old parse gave
    ('2001:db8::%eth0/64' -> '2001:db8::/64'). Both are rebuilt from the parsed number, so no
    zone text survives. An entry without a zone reads exactly as canonical_ip_or_network does.
    Also what a whitelist removal is audited as: the entry it takes out, read the same way.
    """
    text = "" if value is None else str(value).strip()
    if "/" not in text:
        addr = unzoned_ip_address_or_none(text)
        return None if addr is None else str(addr)
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    # From the integer, through the network's own class: an int alone would read ::1 as IPv4.
    return str(type(net)((int(net.network_address), net.prefixlen)))


# A candidate IP address inside free text (an audit entry, a console line): an IPv6 address, whose last
# 32 bits may be written as IPv4 (::ffff:203.0.113.9 is one address), or an IPv4 one. Not one glued to a
# word or a dot before it: "v1.2.3.4" and "build7.1.2.3.4" are version numbers. A bare 1.40.2.4 is a valid
# address and counts as one. Each candidate is parsed before anything is replaced, so a clock time stays.
_TEXT_V4 = r"\d{1,3}(?:\.\d{1,3}){3}(?![\d.]*\d)"
_TEXT_IP = (r"(?<![0-9A-Za-z_.])(?:(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?P<tail>" + _TEXT_V4
            + r")|[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:]))|" + _TEXT_V4 + ")")
_TEXT_IP_RE = re.compile(_TEXT_IP)
_TEXT_IP_NOT_NET_RE = re.compile(_TEXT_IP + r"(?!/\d)")    # not one followed by "/<digits>": a network


def replace_text_ips(text, repl, networks=True):
    """Return `text` with each IP address in it replaced by repl(address), `address` an ipaddress object.

    An IPv4-mapped IPv6 address (::ffff:203.0.113.9) is one address. With networks=False an address
    followed by "/<digits>" (a network, such as one this already reduced) is left as it is.
    """
    pattern = _TEXT_IP_RE if networks else _TEXT_IP_NOT_NET_RE

    def _one(m):
        cand = m.group(0)
        addr = ip_address_or_none(cand)
        if addr is None:
            tail = m.group("tail")
            # "12:00:203.0.113.9" is no IPv6 address, but its IPv4 tail still is an address.
            return cand[:-len(tail)] + replace_text_ips(tail, repl, networks) if tail else cand
        return repl(addr)
    return pattern.sub(_one, "" if text is None else str(text))


def same_whitelist_entry(stored, requested):
    """Whether a STORED whitelist entry is the one a removal request names.

    Its text equals the request's, or it reads as the same address or network (unzoned_ip_or_network
    on both sides). The canonical form alone left a hand-edited entry (a network written with a
    host's address, upper-case IPv6, surrounding spaces) in force while the panel answered and
    audited it as removed. The raw text still matches on its own, so an entry stored before the
    add refused it (a zone id) can be taken out.
    """
    raw = "" if requested is None else str(requested).strip()
    target = unzoned_ip_or_network(raw)
    return str(stored).strip() == raw or (target is not None and unzoned_ip_or_network(stored) == target)


def whitelist_without(listed, requested, removed):
    """`listed` without every entry same_whitelist_entry matches to `requested`.

    Each one taken is appended to `removed`, so the caller can say what was taken (nothing, for
    text on no list).
    """
    removed.extend(w for w in (listed or []) if same_whitelist_entry(w, requested))
    return [w for w in (listed or []) if w not in removed]


# nosec B104 - the set of wildcard addresses to RECOGNISE, so callers can tell "listening
# everywhere" from loopback. Naming a value is not binding to it.
BIND_WILDCARD = frozenset({"0.0.0.0", "::"})  # nosec B104
BIND_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def bind_host_error(value, host_has_ip=None):
    """None if `value` is an address this panel could actually bind to, else why not.

    `bind_host` is written to config.json and read back by the entry point as the address to
    listen on, so a value that cannot be bound produces a panel that does not come up on its next
    boot — recoverable only with linuxgsm-panel-recover or by editing the file by hand. It is the
    same hazard as `port`.

    It lives here because the wizard wrote it UNCHECKED under a comment saying
    "api_panel_change_port validates whatever they choose" — a different route, which the wizard
    never calls. Its ONE caller is the wizard. /api/panel/change-port (remote_security.py) keeps
    its own inline copy of these rules plus two more (the address must be on this host, and a
    loopback bind needs Tailscale Serve); this docstring used to claim both writers shared it.

    `host_has_ip` is passed in rather than imported: this module is the low-level validation layer
    and must not depend on panel.ops. When it is None the local-address check is skipped. The wizard
    passes can_bind_address below: a well-formed IP that is not on this host passes the parse and
    the wildcard/loopback rules, and then fails to bind at the next start.
    """
    text = (value or "").strip()
    if not text:
        return "Pick a bind address — e.g. 0.0.0.0 (all interfaces) or 127.0.0.1 (localhost)."
    if text in BIND_WILDCARD:
        return None
    if text in BIND_LOOPBACK and text != "localhost":
        return None
    # A zone id is refused with everything else that is not an address. It used to parse, and then
    # can_bind_address's bind raised gaierror rather than EADDRNOTAVAIL — "could not tell" — so any
    # address the host does not have got past the local-address check by growing a '%x'.
    if ip_address_or_none(text) is None:
        return ("Bind address must be an IP — e.g. 0.0.0.0 (all interfaces), 127.0.0.1 "
                "(localhost), or this host's Tailscale IP.")
    if host_has_ip is not None and not host_has_ip(text):
        # A Sentence: English for anything that records it, whole for tr() to show translated.
        return i18n.Sentence("{address} isn't an address on this host — the panel couldn't bind to it.",
                             address=text)
    return None


def can_bind_address(ip):
    """Whether this process can listen on `ip` — asked of the kernel, by binding port 0 on it.

    The exact question the next start will ask: it follows interface addresses, IPv6, and even
    net.ipv4.ip_nonlocal_bind, with no command output to parse (an empty read from a missing `ip`
    binary would read as "not on this host"). Only EADDRNOTAVAIL means no; any other error is
    "could not tell" and does not block the operator.
    """
    import errno
    import socket
    addr = ip_address_or_none(ip)
    if addr is None:
        return False
    # A wildcard is not an address this host HAS: binding 0.0.0.0 or :: always succeeds, which would
    # answer yes for every host. Callers that accept a wildcard bind test for it themselves.
    if addr.is_unspecified:
        return False
    fam = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as sock:
            sock.bind((str(addr), 0))
        return True
    except OSError as exc:
        return exc.errno != errno.EADDRNOTAVAIL


# Filenames reach a Content-Disposition header, whose WSGI value is latin-1 — see
# _attachment_header. Anything outside this set is replaced rather than quoted, because a name is
# attacker-influenceable (anyone who can upload a file picks it) and a raw CR here is header
# injection.
_ASCII_FILENAME_STRIP = re.compile(r"[^A-Za-z0-9._ ()+,\[\]-]")


def _attachment_header(name):
    """A Content-Disposition value that survives a real game-server filename.

    These names are written by mod authors, map packers and Windows tooling — spaces, brackets,
    apostrophes, accents and the occasional control character are all ordinary. WSGI header values
    are latin-1, so a UTF-8 name cannot go in `filename=` at all: the exact name goes in RFC 5987's
    `filename*` (percent-encoded, which every current browser prefers), and a scrubbed ASCII
    version stays in `filename=` for anything that ignores it. Scrubbed, not just quoted, because
    a name is attacker-influenceable — anyone who can upload a file picks it — and a raw CR here
    would be header injection.
    """
    base = os.path.basename(name or "") or "download"
    ascii_name = _ASCII_FILENAME_STRIP.sub("_", base).strip() or "download"
    return "attachment; filename=\"%s\"; filename*=UTF-8\'\'%s" % (
        ascii_name, quote(base, safe=""))


# OWASP Authentication Cheat Sheet, "Implement Proper Password Strength Controls" (read 2026-11-15):
# "Password Length" — under 15 characters is weak without MFA, 8 is the floor with it, and the
# maximum should be at least 64 (the panel's is MAX_PASSWORD_BYTES, 1 MB); "There should be no
# password composition rules limiting the type of characters permitted", so any character counts,
# spaces and every script included; and common or breached passwords are refused (common_passwords).
MIN_PASSWORD_LEN = 15
MIN_PASSWORD_LEN_MFA = 8


# The username column is String(80) and the creation form asked only for >= 3 characters, so a
# longer name reached the database and was silently truncated (or errored, depending on the
# driver). Both places that set a username now go through this, so create and rename cannot drift
# apart on what they accept.
MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 80


def username_problem(name):
    """Return a human error if the username is unusable, else None.

    FORMAT only — uniqueness needs the database and stays with the caller, which is also the only
    place that knows whether a clash with the user's OWN current name should count.
    """
    name = (name or "").strip()
    # i18n-ignore on these length lines: the number is a module constant, so each is ONE fixed
    # sentence, a catalog key exactly as written (part66 calls these and finds them in es and fr).
    if len(name) < MIN_USERNAME_LEN:
        return f"Username must be at least {MIN_USERNAME_LEN} characters."  # i18n-ignore
    if len(name) > MAX_USERNAME_LEN:
        return f"Username must be at most {MAX_USERNAME_LEN} characters."  # i18n-ignore
    if any(c.isspace() for c in name):
        # It is typed into a login box and read off a screen; an interior space (or a tab pasted in
        # from a spreadsheet) is invisible there and makes the account unloggable-into.
        return "Username cannot contain spaces."
    if _has_control_or_format(name):
        return "Username can only contain printable characters."
    return None


def _has_control_or_format(text):
    """Whether `text` holds a character of Unicode category C.

    That is a control (ESC, BEL, the C1 CSI), a format character (bidi overrides such as U+202E,
    zero-width joiners and spaces), a surrogate, a private-use or an unassigned code point.

    A stored name is printed to a TERMINAL by the recovery CLI (manage.py, run as root), where an
    ESC sequence moves the cursor, erases the line or writes the clipboard (OSC 52), and a bidi
    override reorders what is shown. It is also nothing anyone can type into a login box. The UI
    ships English, Spanish and French, none of which needs ZWJ/ZWNJ. (Line and paragraph
    separators are Z, not C; the whitespace checks refuse those.) Aikido 745379084.
    """
    return any(unicodedata.category(c)[0] == "C" for c in text)


# Group.name is String(80) too, and had no format check at all: a newline and ESC both passed,
# and manage.py list-users prints each user's groups beside the name.
MAX_GROUP_NAME_LEN = 80


def group_name_problem(name):
    """Return a human error if a permission group's name is unusable, else None (FORMAT only)."""
    name = (name or "").strip()
    if not name:
        return "Group name is required."
    if len(name) > MAX_GROUP_NAME_LEN:
        return f"Group name must be at most {MAX_GROUP_NAME_LEN} characters."  # i18n-ignore: as username_problem's
    # A plain space is fine ("Game Admins"); a newline, tab or line separator is a second row in
    # every listing the name is printed in.
    if any(c.isspace() and c != " " for c in name):
        return "Group name cannot contain line breaks or tabs."
    if _has_control_or_format(name):
        return "Group name can only contain printable characters."
    return None


def password_problem(pw, has_mfa=False, avoid=()):
    """Return a human error if the password is too weak, else None.

    At least MIN_PASSWORD_LEN characters, or MIN_PASSWORD_LEN_MFA for an account with two-factor
    authentication on (`has_mfa`); not containing any of `avoid` (the username) of three or more
    characters; not a common password (common_passwords, offline); and not a breached one
    (breached_passwords: the downloaded list, then Pwned Passwords when that setting is on). No
    composition rules. Applied when a password is set or changed: a password set before keeps working.
    """
    floor = MIN_PASSWORD_LEN_MFA if has_mfa else MIN_PASSWORD_LEN
    if not pw or len(pw) < floor:
        if has_mfa:
            return "Password must be at least 8 characters."
        return "Password must be at least 15 characters, or 8 with two-factor authentication on."
    folded = pw.casefold()
    if any(len(w.strip()) >= 3 and w.strip().casefold() in folded for w in avoid if isinstance(w, str)):
        return "Password must not contain your username."
    return _listed_problem(pw)


def _listed_problem(pw):
    """The message for a common password, then for a breached one (asked only if it is not common), or None."""
    from panel.core.breached_passwords import is_breached
    from panel.core.common_passwords import is_common
    if is_common(pw):
        return ("That password is too common or too easy to guess. A few unrelated words make a long "
                "password that is easy to remember.")
    if is_breached(pw):
        return ("That password has appeared in a data breach, so attackers try it first. Choose "
                "one you have not used anywhere else.")
    return None


# Characters a person has to read off one screen and type into another without getting it wrong, so
# the pairs that look alike are gone: no O/0, no I/l/1, no S/5, no B/8, no Z/2. The symbols are the
# ones that survive being pasted into a chat message or a terminal unquoted — no quotes, no
# backslash, no backtick, nothing a shell would eat.
_GEN_LOWER = "abcdefghijkmnpqrstuvwxyz"
_GEN_UPPER = "ACDEFGHJKLMNPQRTUVWXY"
_GEN_DIGIT = "34679"
_GEN_SYMBOL = "!@#$%^&*+-=?"
_GEN_ALL = _GEN_LOWER + _GEN_UPPER + _GEN_DIGIT + _GEN_SYMBOL
GENERATED_PASSWORD_LEN = 16


def generate_password(length=GENERATED_PASSWORD_LEN):
    """A random password that always satisfies password_problem().

    Built by construction rather than by rejection sampling: one character from each required class
    first, the rest from the full alphabet, then shuffled. "Generate and retry until it passes" has
    no bound on how long it runs, and a generator for a login credential is not the place to find
    out how unlucky a machine can get.

    16 characters from a ~62-character alphabet is ~95 bits — far past anything the login throttle
    would ever let an attacker reach, and still short enough to read aloud. Uses secrets, not
    random: this is a credential, and random's Mersenne Twister is reconstructible from its output.
    """
    length = max(MIN_PASSWORD_LEN, int(length))   # 16 by default: past the non-2FA floor
    pools = (_GEN_LOWER, _GEN_UPPER, _GEN_DIGIT, _GEN_SYMBOL)
    chars = [_secrets.choice(p) for p in pools]
    chars += [_secrets.choice(_GEN_ALL) for _ in range(length - len(pools))]
    # Shuffled, or the class of each position would be predictable. SystemRandom draws from
    # os.urandom, not the Mersenne Twister, so the order is as unguessable as the characters.
    _secrets.SystemRandom().shuffle(chars)  # NOSONAR - SystemRandom is os.urandom's CSPRNG
    return "".join(chars)


def _int_or(value, default):
    """Parse an int from untrusted form input, falling back to default instead of raising.

    A bad value like an empty or non-numeric port must not 500 the page.

    NOT FOR PORTS — use _port_or. This guarantees "an int" and nothing else, which is exactly
    how a port of 0, -5 or 99999 reached a database row; see the note there.
    """
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# The range every port in the panel must land in. 0 is not bindable and 65536 does not exist, so a
# value outside this is a typo or an attack — never a server that could work.
MIN_PORT = 1
MAX_PORT = 65535
# Ports below 1024 need root to bind. The panel's own listener refuses them (it does not run as
# root); a GAME server may legitimately want one, so this is a separate, narrower floor that only
# the panel-port callers apply.
MIN_UNPRIVILEGED_PORT = 1024


# A leading + or - is what int() itself accepts, so it is accepted here too and then judged on
# range — "+2302" is port 2302, "-1" is out of range.
_ASCII_INT_RE = re.compile(r"^[+-]?[0-9]+$")


def _port_or(value, default, lo=MIN_PORT, hi=MAX_PORT):
    """Parse a PORT from untrusted input, falling back to `default` when it is unusable.

    Pass default=None to make an out-of-range value REFUSABLE rather than silently corrected —
    the caller then gets None and can return an error instead of storing a guess.

    WHY THIS EXISTS SEPARATELY FROM _int_or. A port has a range, and "parse an int" does not carry
    it. Four call sites took a port from a request; two grew their own inline bounds check
    (/api/panel/change-port, change_ssh_port) and two did not — the game-server install form and
    the setup wizard — so `int(port)` from a form became a stored port of 0 or 99999 and an
    unbootable panel. Keeping the bound with the parse is what stops the fifth call site
    repeating it.
    """
    s = str(value if value is not None else "").strip()
    # ASCII digits only. int() happily accepts every Unicode decimal form, so "\u0661\u0662\u0663"
    # parsed as 123 and was stored as a port — a value nobody typed, on a field that ends up in a
    # LinuxGSM config, a UFW rule and a connect address. A port is ASCII; say so.
    if not _ASCII_INT_RE.match(s):
        return default
    try:
        n = int(s)
    except (TypeError, ValueError):     # unreachable via the pattern; kept so this cannot raise
        return default
    return n if lo <= n <= hi else default


_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}\Z")


def _valid_hex_color(value):
    """Return a normalised #rrggbb string if `value` is a 6-digit hex colour, else "".

    The accent colour is emitted into a CSS custom property, so it must be a strict
    colour literal — never arbitrary text that could carry `}` / `<` and break out.
    """
    # Not a string (a hand-edited config.json): no colour. `(5 or "").strip()` raised on every
    # template render, /login included, so every page answered 500.
    v = value.strip() if isinstance(value, str) else ""
    if not v.startswith("#"):
        v = "#" + v
    return v.lower() if _HEX_COLOR_RE.match(v) else ""


def host_key_fingerprint_arg(text):
    """The SHA256 host key fingerprint in `text`, "" for a blank field, or None when it holds none.

    Takes the whole line `ssh-keygen -lf <key>.pub` prints ("256 SHA256:... root@host (ED25519)") as
    well as the fingerprint alone, so it can be pasted as it comes. An MD5 fingerprint, a
    truncated one or anything over 512 characters is None.
    """
    text = (text or "").strip()
    if not text:
        return ""
    if len(text) > 512:
        return None
    m = _HOST_KEY_FP_RE.search(text)
    return m.group(1) if m else None


def host_key_sha256(keystr):
    """The OpenSSH SHA256 fingerprint ("SHA256:...", unpadded) of a "keytype base64" key, or ""."""
    import base64
    import hashlib
    parts = (keystr or "").split()
    try:
        raw = base64.b64decode(parts[-1], validate=True) if parts else b""
    except ValueError:
        return ""
    if not raw:
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
