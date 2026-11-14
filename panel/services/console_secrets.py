"""Game secrets masked out of console text before a browser or a chat bot is sent it.

A game's console echoes what it was started with, and some games print their own passwords: Project
Zomboid starts as `-servername <name> -adminpassword <password>` (LinuxGSM's pzserver _default.cfg
startparameters) and writes that line into the console log and the tmux pane. The panel's console
reaches anyone who may view a server's console (VIEW_CONSOLE), which is less than reading its
configs (VIEW_FILES), so every console text path runs its text through mask() first:

* the live stream (the poller's pushes), the page's window read (/api/console), its read from a
  place (?place=1) and the catch-up on return: server_files._console_shown_text;
* the panel's own lines in the console and their replay (`panel_lines`): _shared._console_push;
* the chat bots' /console and !console tail: bots.commands._console_text.

Masked for every viewer, the superadmin too. The stream is one push to a room, and the page stitches
the push and the window together by their exact text, so two viewers cannot be shown two versions of
a line. Whoever may read the configs reads the values there.

Two kinds of masking, applied to the text as it is shown (after its colour is rendered):

1. The VALUES of this server's secret LinuxGSM settings, wherever they appear: the settings LinuxGSM
   itself masks for every command but `details` (LGSM_MASKED_KEYS), any setting named like one
   (_SECRET_NAME_RE: steampass, a webhook, an alert token), and every setting kept in
   secrets-common.cfg or secrets-<instance>.cfg, the files LinuxGSM gives for secrets
   (lgsm/config-default/config-lgsm/secrets-*-template.cfg). Read with the panel's own config read
   (ssh_manager.lgsm_cfg_texts: the five files in one round trip), cached per server for _TTL
   seconds, never once per line.
2. The value after a flag or key named like a secret (_ARG_RE): `-adminpassword X`, `+rcon_password
   "X"`, `+sv_setsteamaccount X`, `?ServerAdminPassword=X`, `rcon.password=X`. For what the panel
   cannot read, or has not read yet: a config read that failed, a value changed since the cache.

Both are deterministic for a given cache, so the poller's push and the page's window of the same
line are the same text, and the stitching between them still matches.
"""
import re
import time

from panel.core.panel_state import register_server_state
from panel.ops import ssh_manager as _sm

MASK = "********"

# LinuxGSM v26.6.0 (master 98be8a98, 2026-11-13), lgsm/modules/info_messages.sh,
# fn_info_messages_password_strip: the settings LinuxGSM replaces with ******** in every command's
# output except `details`.
LGSM_MASKED_KEYS = frozenset((
    "serverpassword", "rconpassword", "adminpassword", "statspassword", "httppassword",
    "telnetpassword", "wsapikey", "gslt", "betapassword", "authtoken", "usertoken", "apikey",
    "gspassword", "eosclientsecret"))
# Any other setting named like a secret: steampass (SteamCMD's login), the alert webhooks and tokens,
# a game's own *password. Matched against the lower-cased key.
_SECRET_NAME_RE = re.compile(r"pass(?:word|wd|phrase)?\Z|password|token|secret|apikey|gslt|webhook")
# Indices into lgsm_cfg_texts' list (_core.LGSM_CFG_ORDER) of secrets-common.cfg and
# secrets-<instance>.cfg: every setting in them is a secret.
_SECRETS_FILES = (2, 4)
# Values that are not secrets, whatever their setting is called: unset, switches, the mask itself.
_NOT_SECRET = frozenset(("", "true", "false", "on", "off", "yes", "no", "none", "null", "not set",
                         MASK.lower()))
# Shorter values are not masked by value: a two-letter password would mask those letters all
# through the console (`details`' own masking keeps the same floor). The flag form still masks it.
_MIN_VALUE = 3
# How long a server's values are trusted, and how soon a read that failed is tried again.
_TTL = 120.0
_RETRY = 30.0

# The word in a flag or key that makes the value after it a secret.
_KEY_NAME_WORDS = (r"(?:password|passwd|passwort|passphrase|pass(?![a-z])|pwd?(?![a-z])|secret|token"
                   r"|api_?key|auth_?key|gslt|setsteamaccount)")
# A flag (`-adminpassword X`, `+rcon_password X`) takes the next token after blanks, or after SGR
# colour codes the console kept; a key (`ServerPassword=X`, `password: X`) only after `=` or `:`.
# Either starts a word, or follows a colour code (render_colour writes them as ESC[Nm, ESC[NNm and
# ESC[N;NNm).
# Every repeat is bounded and no two repeats overlap on the same characters, so a hostile line
# costs a constant per position: no catastrophic backtracking.
_ARG_RE = re.compile(
    r"(?:(?<![\w.+-])|(?<=\x1b\[\dm)|(?<=\x1b\[\d\dm)|(?<=\x1b\[\d;\d\dm))(?P<key>(?P<flag>[-+]{1,2})?[\w.]{0,40}?" + _KEY_NAME_WORDS + r"[\w.]{0,40})"
    r"(?P<sep>[ \t]{0,8}[=:][ \t]{0,8}|(?(flag)(?:[ \t]|\x1b\[[0-9;]{0,32}m){1,16}|(?!)))"
    r"(?P<value>\"[^\"\n]{0,256}\"|'[^'\n]{0,256}'|[^\s\"'?&;,\x1b]{1,256})",
    re.IGNORECASE)

# server id -> (monotonic time it is good until, frozenset of values). Registered, so a deleted
# server's values are dropped rather than applied to whichever server takes its id.
_values = register_server_state({})


def _is_secret_key(key, in_secrets_file):
    """Whether a LinuxGSM setting holds a secret: in a secrets file, LinuxGSM's own list, or by its name."""
    low = key.lower()
    return in_secrets_file or low in LGSM_MASKED_KEYS or bool(_SECRET_NAME_RE.search(low))


def _maskable(value):
    """Whether a secret setting's value is masked wherever it appears in the console.

    Not an unexpanded reference (rconpassword="${adminpassword}" is never printed as written; the
    value it names is masked on its own), a switch, or a value shorter than _MIN_VALUE.
    """
    return len(value) >= _MIN_VALUE and value.strip().lower() not in _NOT_SECRET and "${" not in value


def secret_values(texts):
    """The secret values in an instance's LinuxGSM config texts (lgsm_cfg_texts' list), as a set."""
    return {value for i, text in enumerate(texts or ())
            for key, value in _sm._parse_cfg(text).items()
            if _is_secret_key(key, i in _SECRETS_FILES) and _maskable(value)}


def refresh(gs, now=None):
    """Return the server's cached secret values, read from its LinuxGSM config when the cache is stale.

    At most one read per _TTL per server (a failed one is tried again after _RETRY and keeps what
    was known). A row with no id is never read for. Never raises.
    """
    sid = getattr(gs, "id", None)
    if sid is None:
        return frozenset()
    now = time.monotonic() if now is None else now
    got = _values.get(sid)
    if got is not None and got[0] > now:
        return got[1]
    try:
        texts = _sm.lgsm_cfg_texts(gs.remote, gs.short_name, gs.lgsm_name or gs.short_name,
                                   read_only=True)
    except Exception:
        texts = None
    if texts is None:
        keep = got[1] if got is not None else frozenset()
        _values[sid] = (now + _RETRY, keep)
        return keep
    vals = frozenset(secret_values(texts))
    _values[sid] = (now + _TTL, vals)
    return vals


def forget(server_id):
    """Drop a server's cached values, so its next console text reads them again."""
    _values.pop(server_id, None)


def _arg_mask(m):
    """_ARG_RE's replacement: the flag or key kept, its value masked (not a switch or a next flag)."""
    value = m.group("value")
    bare = value.strip("\"'").strip()
    if bare.lower() in _NOT_SECRET or bare.lower() == "not":
        return m.group(0)
    if m.group("flag") and "=" not in m.group("sep") and ":" not in m.group("sep") and value[0] in "-+":
        return m.group(0)       # `-password -port 27015`: an empty password, and the next flag
    return m.group("key") + m.group("sep") + MASK


def mask_text(text, values=()):
    """`text` with each of `values` masked (longest first) and every secret flag's or key's value."""
    if not text:
        return text
    for value in sorted(values, key=len, reverse=True):
        if value in text:
            text = text.replace(value, MASK)
    return _ARG_RE.sub(_arg_mask, text)


def mask(server_id, text):
    """`text` masked with whatever this server's cache holds; never reads the config."""
    got = _values.get(server_id)
    return mask_text(text, got[1] if got is not None else ())


def mask_for(gs, text):
    """`text` masked for this server, its config read first when the cache is stale (refresh)."""
    if not text:
        return text
    return mask_text(text, refresh(gs))
