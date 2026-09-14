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
import os
import re
from urllib.parse import quote


# ── Strict input validation ───────────────────────────────────────────────
# These values become LinuxGSM shortnames, Linux usernames, home-directory paths and
# arguments to shell commands run as root during install. LinuxGSM shortnames are
# lowercase alphanumeric; a game-server instance name becomes a Linux user. Rejecting
# anything outside a safe charset here is what prevents shell/command injection into
# the install pipeline (a user with INSTALL_SERVER must NOT be able to run arbitrary
# root commands on a host).
GAME_TYPE_RE = re.compile(r"^[a-z0-9]{1,32}$")
INSTANCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")   # valid Linux username shape
LINUX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")     # for linuxgsm_user / ssh user
# Hostname / IPv4 / IPv6 / Tailscale MagicDNS — no HTML or shell metacharacters, so a
# stored host can't inject markup where it's shown (e.g. the dashboard connect address).
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,255}$")
# Free-text display labels (e.g. a remote's name): allow spaces/punctuation but reject the
# characters that would let a stored label break out of HTML or a JS string when it's shown
# in the UI's client-side rendering. Defense-in-depth alongside output encoding.
SAFE_LABEL_RE = re.compile(r"""^[^<>"'`\r\n\\]{1,120}$""")


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

MIN_PASSWORD_LEN = 10
import string as _string
_PW_SYMBOLS = set(_string.punctuation)


def password_problem(pw):
    """Return a human error if the password is too weak, else None.
    Requires: length, lower, upper, digit, and a symbol."""
    if not pw or len(pw) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if not any(c.islower() for c in pw):
        return "Password must include a lowercase letter."
    if not any(c.isupper() for c in pw):
        return "Password must include an uppercase letter."
    if not any(c.isdecimal() for c in pw):
        return "Password must include a number."
    if not any(c in _PW_SYMBOLS for c in pw):
        return "Password must include a symbol (e.g. !@#$%)."
    return None


def _int_or(value, default):
    """Parse an int from untrusted form input, falling back to default instead of
    raising (a bad value like an empty or non-numeric port must not 500 the page).

    NOT FOR PORTS — use _port_or. This guarantees "an int" and nothing else, which is exactly
    how a port of 0, -5 or 99999 reached a database row; see the note there."""
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
    repeating it."""
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



_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _valid_hex_color(value):
    """Return a normalised #rrggbb string if `value` is a 6-digit hex colour, else "".
    The accent colour is emitted into a CSS custom property, so it must be a strict
    colour literal — never arbitrary text that could carry `}` / `<` and break out."""
    v = (value or "").strip()
    if not v.startswith("#"):
        v = "#" + v
    return v.lower() if _HEX_COLOR_RE.match(v) else ""
