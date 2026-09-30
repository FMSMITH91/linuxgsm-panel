"""Proactive admin notifications to Telegram, Discord and/or ntfy.

The panel already lets you configure a game's own LinuxGSM alerts; this is the panel telling YOU, the
admin, when something needs attention — a server dropped, a host went unreachable, a backup failed, a
super admin signed in, an IP was banned, a disk is filling up.

Best-effort and non-blocking: a send happens on a background thread and a failure is logged and
swallowed, never propagated to the caller (an alert must never break the action that triggered it).
Secrets (the bot token, the webhook URL, an ntfy access token) are Fernet-encrypted at rest via
config.encrypt_secret.
"""
import json
import logging
import queue
import re
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from panel.core.config import load_config, update_config, encrypt_secret, decrypt_secret

_log = logging.getLogger("notifications")

# Events an admin can toggle, in display order: key -> (label, default_on).
EVENTS = {
    "server_down":        ("A game server goes offline unexpectedly", True),
    "server_up":          ("A game server comes back online", False),
    "server_empty":       ("A server you flagged has emptied (per-server, set on its page)", True),
    "server_full":        ("A game server hits its player cap", False),
    "server_peak":        ("A game server sets a new player-count record", False),
    "remote_unreachable": ("A remote host becomes unreachable", True),
    "remote_recovered":   ("A remote host comes back", True),
    "high_load":          ("A host's CPU or memory is sustained high", True),
    "disk_low":           ("A host's disk is running low", True),
    "auto_reboot":        ("A host auto-reboots once empty (reboot-when-empty)", True),
    "backup_failed":      ("A backup fails", True),
    "update_available":   ("A panel update is available", True),
    "os_updates":         ("A host has OS package updates waiting (security ones called out)", True),
    "cert_expiring":      ("The panel's TLS certificate is expiring soon", True),
    "admin_login":        ("A super admin signs in", True),
    "admin_bruteforce":   ("A super admin account is being brute-forced", True),
    "account_change":     ("A user is created or a group's permissions change", True),
    "ip_banned":          ("fail2ban bans an IP on the panel login", False),
    "ban_spike":          ("A burst of fail2ban bans (attack wave)", True),
}

# A Discord webhook MUST live on Discord — never let an admin-set (or tampered) URL become an SSRF
# probe into internal services. Telegram uses the fixed api.telegram.org host, so it needs no such
# host check, but its token is format-validated so it can't rewrite the request path.
# A Discord webhook is parsed into its <id>/<token> and the request URL is then rebuilt from a
# CONSTANT host, so the host the panel connects to is never taken from user input (no SSRF). The id
# and token are charset-bounded, so the path can't traverse either.
_DISCORD_WEBHOOK_RE = re.compile(
    r"^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d{5,25})/([\w-]{1,120})\Z")
_TG_TOKEN_RE = re.compile(r"^(\d{5,}):([A-Za-z0-9_-]{20,})\Z")   # (bot id):(secret) — captured for the URL rebuild
# A Discord *bot* token (for the Gateway command bot). It only ever goes into an `Authorization: Bot`
# HTTP header, never a URL — the charset here forbids whitespace/control chars so it can't inject a
# header, and it's deliberately loose on the internal `.`-separated shape so future token formats still
# validate. A Discord channel id is a snowflake (digits only) and lands only in a charset-checked path.
_DISCORD_BOT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]{40,120}\Z")
_DISCORD_CHANNEL_RE = re.compile(r"^\d{5,25}\Z")

# ── Who may run the command bots' state-changing commands ───────────────────────────────────────
# The bots used to authorise by CHAT only: any member of the configured Telegram group, or anyone
# who could post in the Discord channel, could /stop a server, /update (self-update and restart)
# the panel, read /console and /say things in-game — and the audit row named them only by a
# username they can change at will. A chat is not an identity. What the transport DOES vouch for
# is the sender's numeric user id (Telegram `from.id`, Discord `author.id`): the sender cannot
# choose it, and it survives a rename. So each bot keeps a list of those ids, and a command that
# changes anything runs only for a sender on it (bots.commands.command_refusal).
#
# Digits only, no leading zero, at most 20 of them (a Discord snowflake is a 64-bit integer, a
# Telegram id at most 52 bits), and at most _COMMAND_USERS_MAX entries: the list is read on every
# command, and no chat has a legitimate need for a hundred operators.
_COMMAND_USER_RE = re.compile(r"^[1-9]\d{0,19}\Z")
_COMMAND_USERS_MAX = 50

# ── ntfy ───────────────────────────────────────────────────────────────────────────────────────
# ntfy is the one provider whose SERVER is chosen by the operator: the public ntfy.sh, or their own
# instance — and a self-hosted one is typically on a LAN or tailnet address, which is exactly what
# the allow-list in _post() exists to refuse. Supporting only ntfy.sh would exclude most of ntfy's
# users, so this is a DELIBERATE, NARROW exception, and it is enforced at the sink rather than by
# trusting the caller (see _post's allow_configured_host).
#
# What keeps it narrow: https only (no http, no other scheme), a hostname charset that cannot
# express userinfo (`@`), a query, a fragment or a second path segment, and exactly one path
# component which must be a valid topic. So the most an operator can do is point the panel at a
# host of their choosing — which, on a panel that already SSHes into hosts they nominate, is a
# power they hold several times over. What they cannot do is smuggle a path, a redirect target or
# credentials through it, and _post still returns only fixed reason words, so nothing read back
# from the response can be exfiltrated.
_NTFY_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\Z")
_NTFY_URL_RE = re.compile(r"^https://[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
                          r"(?::\d{1,5})?/[A-Za-z0-9_-]{1,64}\Z")
NTFY_DEFAULT_SERVER = "https://ntfy.sh"


# ── config read/write ──────────────────────────────────────────
def _cfg():
    return load_config().get("notifications") or {}


def event_enabled(cfg, key):
    events = cfg.get("events") or {}
    return bool(events.get(key, EVENTS.get(key, ("", False))[1]))


_DEFAULT_THRESHOLDS = {"disk_pct": 90, "load_pct": 200, "mem_pct": 90, "load_mins": 5}
# Per-key clamp ranges. disk % and mem % are real percentages (<=99). CPU 'load' is the 1-minute load
# average per core x100, so it legitimately exceeds 100% (100% = one core fully busy) and gets a much
# higher ceiling. load_mins is how long CPU/RAM must STAY over the line before it pages you (minutes).
_THRESHOLD_BOUNDS = {"disk_pct": (50, 99), "load_pct": (50, 800), "mem_pct": (50, 99), "load_mins": (1, 120)}


def get_thresholds():
    """Configured alert thresholds, each clamped to its own range, falling back to the defaults.

    The ranges: disk % and mem % (50-99), CPU load-average per-core % (50-800, so it can be >100),
    and load_mins — the minutes CPU/RAM must stay high before alerting. The monitor reads these for
    disk_low / high_load.
    """
    t = _cfg().get("thresholds") or {}
    out = {}
    for k, dflt in _DEFAULT_THRESHOLDS.items():
        lo, hi = _THRESHOLD_BOUNDS[k]
        try:
            out[k] = min(hi, max(lo, int(t.get(k, dflt))))
        except (TypeError, ValueError, OverflowError):
            out[k] = dflt
    return out


def settings_for_form():
    """Current settings with secrets masked (so the token/webhook are never re-sent to the browser)."""
    cfg = _cfg()
    tg = cfg.get("telegram") or {}
    dc = cfg.get("discord") or {}
    nt = cfg.get("ntfy") or {}
    return {
        "telegram": {"enabled": bool(tg.get("enabled")), "chat_id": tg.get("chat_id") or "",
                     "has_token": bool(tg.get("token")), "accept_commands": bool(tg.get("accept_commands")),
                     "command_users": ", ".join(sorted(command_users(tg)))},
        "discord": {"enabled": bool(dc.get("enabled")), "has_webhook": bool(dc.get("webhook")),
                    "has_bot_token": bool(dc.get("bot_token")), "channel_id": dc.get("channel_id") or "",
                    "accept_commands": bool(dc.get("accept_commands")),
                    "command_users": ", ".join(sorted(command_users(dc))),
                    # Why the command bot is not connected, when Discord told us — see
                    # discord_gateway_problem. "" when there is nothing to report.
                    "gateway_problem": discord_gateway_problem()},
        "ntfy": {"enabled": bool(nt.get("enabled")),
                 "server": nt.get("server") or NTFY_DEFAULT_SERVER,
                 "topic": nt.get("topic") or "", "has_token": bool(nt.get("token"))},
        "events": {k: event_enabled(cfg, k) for k in EVENTS},
        "thresholds": get_thresholds(),
    }


def parse_command_users(value):
    """Split a submitted list of user ids into (accepted, rejected).

    `value` is the form's text (ids separated by commas, spaces or new lines) or an already-split
    list. `accepted` is the valid ids in the order given, without repeats and at most
    _COMMAND_USERS_MAX of them. `rejected` is every entry that is not a plain numeric id, cut to 24
    characters, plus a note when the list hit the cap: the form shows it back, so a typo is never
    the silent reason someone cannot run anything.
    """
    if isinstance(value, (list, tuple)):
        raw = [str(v) for v in value]
    else:
        raw = re.split(r"[\s,;]+", str(value or "")[:4000])
    accepted, rejected = [], []
    for item in raw:
        item = item.strip()
        if not item:
            continue
        if not _COMMAND_USER_RE.match(item):
            rejected.append(item[:24])
        elif item not in accepted:
            if len(accepted) >= _COMMAND_USERS_MAX:
                rejected.append("(more than %d ids)" % _COMMAND_USERS_MAX)
                break
            accepted.append(item)
    return accepted, rejected


def command_users(platform_cfg):
    """The allowed user ids stored for one bot, as a frozenset of digit strings.

    Re-validated on READ, not only on save: the config file can be edited by hand or restored from
    a backup, and what this returns is an authorisation decision.
    """
    stored = (platform_cfg or {}).get("command_users") or []
    if not isinstance(stored, (list, tuple)):
        return frozenset()
    return frozenset(parse_command_users(stored)[0])


def _submitted_command_users(form, stored):
    """The ids to store: the stored list when the form did not send the field (None), else parsed.

    None means "this caller does not manage the list" — the rule the secrets follow — so a caller
    that omits the key cannot wipe who may run commands.
    """
    value = form.get("command_users")
    if value is None:
        return sorted(command_users(stored))
    return parse_command_users(value)[0]


def _kept_or_encrypted(submitted, stored, key):
    """Return the secret to store: `stored[key]` when the form sent None ('keep'), else it encrypted.

    `stored` is only read when the form asked to keep the value.
    """
    return stored.get(key) if submitted is None else encrypt_secret(submitted)


def _submitted_thresholds(thresholds):
    """Return the current/default thresholds with each submitted numeric field clamped into range."""
    th = get_thresholds()   # start from current/defaults; only overwrite fields that were submitted
    for k in _DEFAULT_THRESHOLDS:
        if thresholds and thresholds.get(k) not in (None, ""):
            lo, hi = _THRESHOLD_BOUNDS[k]
            try:
                th[k] = min(hi, max(lo, int(thresholds[k])))
            except (TypeError, ValueError, OverflowError):
                _log.debug("ignoring non-numeric threshold %r; keeping %r", k, th[k])
    return th


def _telegram_record(form, token, stored=None):
    """Build the stored Telegram settings from the form and the already-resolved token."""
    return {"enabled": bool(form.get("enabled")),
            "chat_id": (form.get("chat_id") or "").strip()[:64], "token": token or "",
            "accept_commands": bool(form.get("accept_commands")),
            "command_users": _submitted_command_users(form, stored or {})}


def _discord_record(form, webhook, bot_token, stored=None):
    """Build the stored Discord settings from the form and the already-resolved secrets."""
    return {"enabled": bool(form.get("enabled")), "webhook": webhook or "",
            "bot_token": bot_token or "",
            "channel_id": (form.get("channel_id") or "").strip()[:32],
            "accept_commands": bool(form.get("accept_commands")),
            "command_users": _submitted_command_users(form, stored or {})}


def _ntfy_record(form, token):
    """Build the stored ntfy settings from the form and the already-resolved access token."""
    return {"enabled": bool(form.get("enabled")),
            "server": (form.get("server") or "").strip()[:253] or NTFY_DEFAULT_SERVER,
            "topic": (form.get("topic") or "").strip()[:64], "token": token or ""}


def save_settings(*, telegram, discord, events, thresholds=None, ntfy=None):
    """Persist settings, encrypting secrets.

    `telegram`/`discord` secrets that come in as None mean 'keep the stored value' (the form never
    round-trips the real secret back). There is no global master switch — a channel's own enable
    toggle is what turns its alerts on/off.
    """
    _discord_saves[0] += 1
    cur = _cfg()
    cur_tg = cur.get("telegram") or {}
    cur_dc = cur.get("discord") or {}
    cur_nt = cur.get("ntfy") or {}
    tg_token = _kept_or_encrypted(telegram.get("token"), cur_tg, "token")
    dc_webhook = _kept_or_encrypted(discord.get("webhook"), cur_dc, "webhook")
    dc_bot_token = _kept_or_encrypted(discord.get("bot_token"), cur_dc, "bot_token")
    # ntfy=None means "this caller doesn't manage ntfy" — keep whatever is stored, rather than
    # wiping a configured channel because an older caller omitted the argument.
    ntfy = cur_nt if ntfy is None else ntfy
    nt_token = _kept_or_encrypted(ntfy.get("token"), cur_nt, "token")
    th = _submitted_thresholds(thresholds)
    notif = {
        "telegram": _telegram_record(telegram, tg_token, cur_tg),
        "discord": _discord_record(discord, dc_webhook, dc_bot_token, cur_dc),
        "ntfy": _ntfy_record(ntfy, nt_token),
        "events": {k: bool(events.get(k, EVENTS[k][1])) for k in EVENTS},
        "thresholds": th,
    }
    # update_config: this can race with the Telegram poller thread's pending-update write.
    update_config(lambda cfg: cfg.update({"notifications": notif}))


def _drop_master_switch(notif):
    """Pure, in-place migration of a notifications-config dict off the removed master switch.

    The global 'enabled' master switch was removed. If it was explicitly OFF that meant 'no
    notifications' — preserve that by disabling both channels (so dropping the gate can't start
    sending), then remove the key. Returns True if the old key was present (i.e. something changed).
    """
    if not isinstance(notif, dict) or "enabled" not in notif:
        return False
    if notif.get("enabled") is False:
        for ch in ("telegram", "discord"):
            if isinstance(notif.get(ch), dict):
                notif[ch]["enabled"] = False
    notif.pop("enabled", None)
    return True


def migrate_master_switch():
    """One-time on startup: strip the removed global 'enabled' master switch from the stored config.

    A muted state is preserved via the channel toggles. No-op once the key is gone.
    """
    if "enabled" not in _cfg():
        return
    update_config(lambda cfg: _drop_master_switch(cfg.get("notifications")) if isinstance(cfg.get("notifications"), dict) else None)


# ── senders ────────────────────────────────────────────────────
# Every request URL the panel builds uses one of these CONSTANT-host prefixes (Telegram's is a fixed
# literal; Discord webhook + bot-API URLs are rebuilt onto the discord.com host below). _post re-checks
# the URL against them right before the request as an SSRF barrier — no user/admin-supplied value
# decides the host. The Discord prefix covers both /api/webhooks/… (alerts) and /api/v10/channels/…
# (the command bot's replies); both are on the same constant host with charset-checked path parts.
_ALLOWED_PREFIXES = ("https://api.telegram.org/", "https://discord.com/api/")


def _discord_api_url(webhook):
    """Canonical https://discord.com/api/webhooks/<id>/<token> rebuilt from a validated webhook URL.

    None if it isn't one. The host is a constant literal and the id/token are charset-checked, so
    nothing user-supplied controls where the request goes.
    """
    m = _DISCORD_WEBHOOK_RE.match(webhook or "")
    return "https://discord.com/api/webhooks/%s/%s" % (m.group(1), m.group(2)) if m else None


def _valid_discord_webhook(url):
    return _DISCORD_WEBHOOK_RE.match(url or "") is not None


# The only Bot API methods the panel calls — pinning `method` to this set makes the URL path
# provably not user-controlled (add here to use a new one).
_TG_METHODS = ("sendMessage", "getUpdates", "setMyCommands", "getMe")


def _tg_api_url(token, method):
    """A Telegram Bot API URL on the CONSTANT api.telegram.org host, or None.

    The bot token is REBUILT from its regex-captured id/secret groups and `method` restricted to
    _TG_METHODS — so no request-tainted value reaches the request path. Same shape as the
    (un-flagged) Discord builder: token + fixed method only. A query string is a separate concern
    appended by the one caller that needs it — it is deliberately NOT a parameter here, so this
    function's return can't be tainted by one. None if the token is malformed or the method is
    unknown.
    """
    m = _TG_TOKEN_RE.match(token or "")
    if not m or method not in _TG_METHODS:
        return None
    return "https://api.telegram.org/bot%s:%s/%s" % (m.group(1), m.group(2), method)


def _ntfy_url(server, topic):
    """https://<host>[:port]/<topic> for a configured ntfy server, or None if either part is unusable.

    The topic is charset-checked and the whole result must satisfy _NTFY_URL_RE, so a server value
    carrying a path, query, credentials or a non-https scheme yields None rather than a request. A
    trailing slash on the server is tolerated because operators type it.
    """
    topic = (topic or "").strip()
    server = (server or "").strip().rstrip("/") or NTFY_DEFAULT_SERVER
    if not _NTFY_TOPIC_RE.match(topic):
        return None
    url = "%s/%s" % (server, topic)
    return url if _NTFY_URL_RE.match(url) else None


def _valid_ntfy_server(server):
    """Whether `server` can host a topic at all.

    Used by the form so a bad server is reported when it is typed, not silently as a failed send
    later.
    """
    return _ntfy_url(server, "probe") is not None


# The only values `provider` is ever called with, as literals. See the log line inside _post.
_PROVIDER_LABELS = {"telegram": "telegram", "discord": "discord", "ntfy": "ntfy"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx.

    Returning None from redirect_request makes http_error_302 (which 301, 303, 307 and 308 all
    alias) fall through to HTTPDefaultErrorHandler, so the 3xx surfaces as an HTTPError — which
    _post already reads as 'rejected' and LOGS.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# _post used the default global opener, which has urllib's HTTPRedirectHandler in it: a 301/302/303
# was FOLLOWED, to a host no allow-list ever saw. CPython's redirect_request strips only
# content-length and content-type, so `Authorization: Bearer <ntfy access token>` was carried
# verbatim onto the new address, and http_error_302 permits http:// there. An ntfy instance that
# started answering `302 Location: http://169.254.169.254/…` would therefore have handed the
# operator's token to whoever controlled the redirect and turned the panel into a request proxy
# onto exactly the addresses _NTFY_URL_RE exists to refuse — while _post still returned only the
# word 'sent', so the admin saw alerts "working".
#
# A dedicated opener rather than install_opener(): that is global, and system_ops and lgsm_data
# call urlopen for their own reasons. None of the three providers needs a redirect followed —
# Telegram and Discord answer directly, and an ntfy server that 302s is the case to refuse. This
# is also what finally makes two claims already written here true: the ntfy comment above
# ("cannot smuggle ... a redirect target through it") and send_ntfy's docstring ("it cannot leak
# via a redirect").
_OPENER = urllib.request.build_opener(_NoRedirect)


def _post(url, data, headers, allow_configured_host=False, provider="?"):
    """POST to a validated https URL. Returns (ok, reason): ok is True on a 2xx.

    `reason` is a FIXED word describing the outcome — 'sent' / 'rejected' (the provider answered
    with an error status) / 'unreachable' (couldn't connect) / 'blocked' (host not allow-listed).
    It carries no data read back from the response, so this can never become an SSRF exfiltration
    sink. Never raises.
    """
    # SSRF barrier at the sink: the URL must start with one of our known-provider prefixes, so a
    # user/admin-supplied URL can never make this request hit an internal or arbitrary host. Every
    # caller builds `url` on a CONSTANT host with the id/token rebuilt from regex-captured groups
    # (_tg_api_url / _discord_api_url), so no request-tainted value reaches the host OR the path.
    # allow_configured_host is ONLY for ntfy, whose server the operator chooses. The check stays
    # HERE rather than in the caller: a sink that trusts "my caller already validated it" is one
    # refactor away from trusting a caller that doesn't. _NTFY_URL_RE admits nothing but
    # https://<host>[:port]/<single-topic-segment>.
    if allow_configured_host:
        if not _NTFY_URL_RE.match(url or ""):
            return False, "blocked"
    elif not (url or "").startswith(_ALLOWED_PREFIXES):
        return False, "blocked"
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": "linuxgsm-panel", **headers})
    try:
        # _OPENER, not urlopen: the allow-list above is only worth as much as the request that
        # follows it, and the default opener follows redirects off the allow-listed host.
        with _OPENER.open(req, timeout=8) as resp:  # nosec B310 - https, host-allowlisted, no redirects
            return (200 <= resp.getcode() < 300), "sent"
    except urllib.error.HTTPError as e:      # the provider answered with a 4xx/5xx
        # LOGGED, at WARNING. This is how alerting stops: a rotated bot token, a deleted webhook,
        # a bot removed from the channel. The module docstring says "a failure is logged and
        # swallowed" — it was only swallowed, and the panel configures no logging at all, so even
        # the _log.debug below the unreachable case never printed. There was nothing in the
        # journal, nothing in the UI and nothing in the audit log to say alerts had stopped; the
        # only way to find out was to open the settings page and press Test.
        # `provider` is a LITERAL passed by the caller, not anything taken off the URL. A
        # scrubbed hostname read the same to a person and not to CodeQL — py/log-injection kept
        # flagging the flow, and the answer to a gate that will not be convinced is to give it
        # nothing to trace, not to dismiss it.
        # The status as an INT. `e.code` is set from the provider's own response, so a string
        # there could carry a newline and forge a second log line; an int cannot. Same reasoning
        # as `provider` above — give the tracker nothing, rather than argue with it.
        try:
            _code = int(getattr(e, "code", 0) or 0)
        except (TypeError, ValueError):
            _code = 0
        # ...and the provider through a fixed table, so the string that reaches the log is a
        # module-level literal rather than a parameter. Every caller already passes one of these
        # three words; the lookup just makes that visible to a reader and to the scanner.
        _log.warning("notification rejected by %s: HTTP %d",
                     _PROVIDER_LABELS.get(provider, "?"), _code)
        return False, "rejected"
    except (urllib.error.URLError, OSError, ValueError) as e:
        # The exception TYPE, not exc_info. A URLError renders the URL into its message and the
        # traceback, and for ntfy that URL carries an operator-chosen host and topic — so
        # exc_info=True put a value from outside this module into the log verbatim. The class
        # name is a stdlib literal and says the same thing at this level (cannot resolve /
        # refused / timed out / TLS), which is all a debug line here needs.
        _log.debug("notification POST failed (%s)", e.__class__.__name__)
        return False, "unreachable"


def send_telegram(token, chat_id, text):
    """Send a Telegram message. Returns (ok, detail).

    The token is format-validated so it can't rewrite the request path; chat_id + text are
    urlencoded into the body.
    """
    url = _tg_api_url(token, "sendMessage")
    if not url:
        return False, "the bot token is missing or malformed"
    if not chat_id:
        return False, "the chat ID is missing"
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:4000],
                                   "disable_web_page_preview": "true"}).encode()
    ok, reason = _post(url, body, {"Content-Type": "application/x-www-form-urlencoded"},
                       provider="telegram")
    if ok:
        return True, ""
    if reason == "unreachable":
        return False, "couldn't reach api.telegram.org — check the host's outbound network / firewall."
    return False, ("Telegram rejected it — the bot token or chat ID is wrong, or you haven't messaged "
                   "the bot yet. Re-copy the token from @BotFather, use your numeric ID from "
                   "@userinfobot, and press Start in the bot's chat.")


def telegram_get_updates(token, offset=None, timeout=25):
    """Long-poll Telegram for incoming messages (bot command input).

    Returns a list of update dicts (possibly empty) or None on error/timeout/conflict. SSRF-safe:
    the URL is built by _tg_api_url on the constant api.telegram.org host with the token rebuilt
    from its regex-captured groups, so nothing user-supplied reaches the request path — only the
    JSON `result` array is read back. Never raises.
    """
    params = {"timeout": int(timeout)}
    if offset is not None:
        params["offset"] = int(offset)
    url = _tg_api_url(token, "getUpdates")
    if not url:
        return None
    url += "?" + urllib.parse.urlencode(params)   # only int-coerced params; kept out of _tg_api_url
    req = urllib.request.Request(url, headers={"User-Agent": "linuxgsm-panel"})
    try:
        # _tg_api_url builds the URL on the fixed api.telegram.org host.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        # _OPENER, as _post uses: the default urlopen FOLLOWS a 3xx, off api.telegram.org to
        # wherever it points (http:// included), with the bot token in the path of the URL that
        # asked — the one thing _post's comment above says no provider needs. A 3xx is now an
        # HTTPError, a URLError, so this answers None like any other failed poll.
        with _OPENER.open(req, timeout=timeout + 10) as resp:  # nosec B310 - https, host-literal, no redirects
            data = json.loads(resp.read(2_000_000).decode("utf-8", "replace"))
        return (data.get("result") or []) if data.get("ok") else None
    except (urllib.error.URLError, OSError, ValueError) as e:
        # The class, not exc_info: a URLError renders the URL, and this one carries the bot token.
        _log.debug("telegram getUpdates failed (%s)", e.__class__.__name__)
        return None


def telegram_get_me(token):
    """Return this bot's own @username (getMe), or None when it could not be read.

    Same SSRF-safe URL builder as the other Telegram calls. Never raises.
    """
    url = _tg_api_url(token, "getMe")
    if not url:
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "linuxgsm-panel"})
    try:
        # _tg_api_url builds the URL on the fixed api.telegram.org host.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with _OPENER.open(req, timeout=15) as resp:  # nosec B310 - https, host-literal, no redirects
            data = json.loads(resp.read(200_000).decode("utf-8", "replace"))
        name = (data.get("result") or {}).get("username") if data.get("ok") else None
        return str(name) if name else None
    except (urllib.error.URLError, OSError, ValueError, AttributeError) as e:
        # _OPENER and the class name for the reasons telegram_get_updates gives.
        _log.debug("telegram getMe failed (%s)", e.__class__.__name__)
        return None


# The bot's command menu — what Telegram shows when you type '/'. Keep in sync with the commands
# _handle_telegram_command actually handles.
TG_COMMANDS = [
    ("status", "Panel version + server counts"),
    ("servers", "List servers with player counts"),
    ("hosts", "List hosts and their status"),
    ("players", "Who's on a server: /players <name>"),
    ("console", "Last 20 console lines: /console <name>"),
    ("connect", "The address to give players: /connect <name>"),
    ("say", "Announce in-game: /say <name> <message>"),
    ("start", "Start a server: /start <name>"),
    ("stop", "Stop a server: /stop <name>"),
    ("restart", "Restart a server: /restart <name>"),
    ("backup", "Back a server up: /backup <name>"),
    ("update", "Update the panel — or one server: /update <name>"),
    ("help", "Show the command list"),
]


def telegram_set_commands(token, clear=False):
    """Register the bot's command list with Telegram (setMyCommands), or clear it.

    Registered, typing '/' pops the command menu; `clear` empties it when commands are turned off.
    Best-effort; returns True on success. SSRF-safe: the URL is built by _tg_api_url (constant
    host, token rebuilt from its regex groups).
    """
    url = _tg_api_url(token, "setMyCommands")
    if not url:
        return False
    cmds = [] if clear else [{"command": c, "description": d} for c, d in TG_COMMANDS]
    body = json.dumps({"commands": cmds}).encode()
    ok, _reason = _post(url, body, {"Content-Type": "application/json"},
                        provider="telegram")
    return ok


# Discord parses every mention in `content` by default, and this content is not ours: it carries
# player names (`!players`), the tail of the live console — which on most engines includes in-game
# chat — and package names from a remote host's apt output. Anyone who can join a public game
# server could pick a name that mass-pings the operator's Discord every time an admin ran
# `!players`. An empty `parse` turns every mention in the body into inert text.
_DISCORD_NO_MENTIONS = {"parse": []}


def send_discord(webhook, text):
    """Send a Discord webhook message. Returns (ok, detail).

    The URL is rebuilt onto a constant host from the validated webhook id/token, so the request
    can only ever go to Discord.
    """
    url = _discord_api_url(webhook)
    if not url:
        return False, "that isn't a valid discord.com webhook URL"
    ok, reason = _post(url, json.dumps({"content": text[:1900],
                                        "allowed_mentions": _DISCORD_NO_MENTIONS}).encode(),
                       {"Content-Type": "application/json"}, provider="discord")
    if ok:
        return True, ""
    if reason == "unreachable":
        return False, "couldn't reach discord.com — check the host's outbound network."
    return False, "Discord rejected it — the webhook URL is wrong or was deleted."


def send_ntfy(server, topic, token, text):
    """Publish a message to an ntfy topic. Returns (ok, detail).

    The body is the message; the title goes in an X-Title header because ntfy renders it as the
    notification's heading. An access token is optional — ntfy.sh topics are public by default,
    but a self-hosted instance (or a reserved topic) can require one, and it travels in an
    Authorization header, never in the URL, so it cannot leak via a redirect or a proxy log.
    """
    url = _ntfy_url(server, topic)
    if not url:
        return False, ("that isn't a usable ntfy server + topic — the server must be https with no "
                       "path, and the topic may use letters, digits, - and _ only.")
    headers = {"Content-Type": "text/plain; charset=utf-8",
               "X-Title": "LinuxGSM Panel"}
    token = (token or "").strip()
    if token:
        # \Z, not $. `$` also matches BEFORE a trailing newline, which is the one thing this
        # check exists to stop — "a pasted value carrying a newline can never split the header"
        # is what the anchor has to deliver, and `$` does not. The .strip() above happens to
        # remove it first, so nothing was exploitable; the anchor was still the wrong one, and
        # the repo's anchor gate could not see it because it walks module-level re.compile
        # assignments and this is an inline re.match.
        if not re.match(r"^[A-Za-z0-9_.\-]{1,256}\Z", token):
            return False, "that access token has characters ntfy tokens don't use."
        headers["Authorization"] = "Bearer %s" % token
    ok, reason = _post(url, text[:3800].encode("utf-8"), headers,
                       allow_configured_host=True, provider="ntfy")
    if ok:
        return True, ""
    if reason == "unreachable":
        return False, "couldn't reach that ntfy server — check the URL and the host's outbound network."
    if reason == "blocked":
        return False, "that ntfy URL was refused before sending — https and a plain topic only."
    return False, ("ntfy rejected it — the topic may be reserved, or the access token is wrong "
                   "or missing.")


# ── Discord command bot (Gateway) ──────────────────────────────
# Discord offers no outbound long-poll like Telegram's getUpdates, so the two-way command bot keeps a
# persistent Gateway WebSocket open (in a background greenlet) and posts replies over the bot REST API.
# The Gateway host is a fixed literal; replies go to /channels/<id>/messages on the constant discord.com
# host with a digits-only channel id — so, like the webhook sender, nothing user-supplied picks the host.
DISCORD_GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"
# GUILD_MESSAGES (1<<9) | DIRECT_MESSAGES (1<<12) | MESSAGE_CONTENT (1<<15). MESSAGE_CONTENT is a
# privileged intent the bot owner must enable in the Discord Developer Portal to read command text.
_DISCORD_INTENTS = (1 << 9) | (1 << 12) | (1 << 15)
_ws_warned = [False]   # so a missing websocket-client dep is logged once, not every reconnect tick

# WebSocket frame opcodes (RFC 6455 §5.2), for reading a close frame's status code.
_WS_OP_TEXT, _WS_OP_BINARY, _WS_OP_CLOSE = 0x1, 0x2, 0x8

# Why the command bot is not connected, in words for the settings page ("" when nothing is wrong).
# Written by the watcher in bots/discord.py, which is the only thing that knows; a one-element
# holder so it is shared without a `global`.
_gateway_problem = [""]
# Bumped by every save of the notification settings. The Discord bot's hold after a fatal close is
# keyed on it as well as on the token: the page tells the admin to fix the intent in the Portal and
# then turn "Accept commands" off and on, and a quick untick-save-tick-save inside one 15-second
# poll never showed the loop an "off" config — so the hold stayed for its full six hours.
_discord_saves = [0]


def discord_settings_generation():
    """How many times the notification settings have been saved in this process."""
    return _discord_saves[0]


def set_discord_gateway_problem(text):
    """Record (or, with "", clear) why the Discord command bot is not connected."""
    _gateway_problem[0] = str(text or "")[:300]


def discord_gateway_problem():
    """Why the Discord command bot is not connected, or "" — shown on the Notifications page."""
    return _gateway_problem[0]


def _valid_discord_bot_token(token):
    return _DISCORD_BOT_TOKEN_RE.match(token or "") is not None


def _discord_bot_message_url(channel_id):
    """Canonical https://discord.com/api/v10/channels/<id>/messages, or None.

    None when the channel id isn't a plain snowflake. Constant host + digits-only id, so the
    request path is never user-controlled.
    """
    return ("https://discord.com/api/v10/channels/%s/messages" % channel_id
            if _DISCORD_CHANNEL_RE.match(channel_id or "") else None)


def discord_bot_send(bot_token, channel_id, text):
    """Post a message to a channel as the bot (the command bot's reply path). Returns (ok, detail).

    The token rides only in the Authorization header; the URL is built on the constant discord.com
    host with a charset-checked channel id, so this can't become an SSRF sink.
    """
    url = _discord_bot_message_url((channel_id or "").strip())
    if not url:
        return False, "the channel ID is missing or malformed"
    if not _valid_discord_bot_token(bot_token):
        return False, "the bot token is missing or malformed"
    body = json.dumps({"content": text[:1900],
                       "allowed_mentions": _DISCORD_NO_MENTIONS}).encode()
    ok, reason = _post(url, body, {"Content-Type": "application/json",
                                   "Authorization": "Bot %s" % bot_token}, provider="discord")
    if ok:
        return True, ""
    if reason == "unreachable":
        return False, "couldn't reach discord.com — check the host's outbound network."
    return False, ("Discord rejected it — check the bot token, that the bot is in the server, and that "
                   "it can see/send in that channel.")


def _gateway_connector():
    """Return the real Gateway connector, or None when websocket-client isn't installed.

    A missing dependency is warned about once, not on every reconnect tick.
    """
    try:
        import websocket  # optional dependency; command bot is off if it's absent
    except Exception:
        if not _ws_warned[0]:   # warn once, not every reconnect tick, if the dep is missing
            _ws_warned[0] = True
            _log.warning("discord command bot: the 'websocket-client' package isn't installed — "
                         "skipping (webhook alerts are unaffected).")
        return None

    def _connect():
        return websocket.create_connection(DISCORD_GATEWAY_URL, timeout=40, enable_multithread=True)
    return _connect


def _gateway_heartbeat(ws, interval, state, stop):
    """Send the session's heartbeat every `interval` seconds until `stop` is set.

    Zombied-connection guard: if the previous heartbeat wasn't ACKed (op 11) by the next tick, the
    link is dead — close it so the session's recv() unblocks and the caller reconnects.
    """
    while not stop["v"]:
        time.sleep(interval)
        if stop["v"]:
            break
        if not state["acked"]:
            try:
                ws.close()
            except Exception:
                _log.debug("discord heartbeat close failed", exc_info=True)
            break
        state["acked"] = False
        try:
            ws.send(json.dumps({"op": 1, "d": state["seq"]}))
        except Exception:
            break


def _gateway_message(d, on_message):
    """Hand one MESSAGE_CREATE payload to `on_message`; a handler that raises is logged, not fatal."""
    author = d.get("author") or {}
    try:
        # `author` is passed through, not just its bot flag: a command that stops a
        # game server or updates the panel needs to be attributable to whoever sent it,
        # and the audit log had no way to record that.
        on_message(str(d.get("channel_id") or ""), bool(author.get("bot")),
                   d.get("content") or "", author)
    except Exception:
        _log.debug("discord on_message handler failed", exc_info=True)


def _gateway_frame(ws, data, state, on_message):
    """Handle one decoded Gateway frame. Returns False when the session has to end."""
    if data.get("s") is not None:
        state["seq"] = data["s"]
    op = data.get("op")
    if op == 11:                       # heartbeat ACK
        state["acked"] = True
    elif op == 1:                      # server demands an immediate heartbeat (don't touch the
        ws.send(json.dumps({"op": 1, "d": state["seq"]}))   # periodic ACK tracking → no races
    elif op in (7, 9):                 # reconnect / invalid-session → drop and re-identify
        return False
    elif op == 0 and data.get("t") == "MESSAGE_CREATE":
        _gateway_message(data.get("d") or {}, on_message)
    return True


def _gateway_recv(ws, closed):
    """Read one Gateway frame's text; "" when the far end closed, with its status in closed["code"].

    recv() cannot be used for this: websocket-client answers a close frame by returning "" and
    discarding the frame, and its two-byte status code with it. That code is the only place
    Discord says WHY a session ended — 4004 "authentication failed", 4014 "disallowed intents" —
    and without it every session end looked alike, so the watcher retried a revoked token or a
    missing Message Content intent every 15 seconds for ever (see bots/discord.py).

    A socket without recv_data (websocket-client always has it) is read with plain recv(), and
    then no code is known.
    """
    recv_data = getattr(ws, "recv_data", None)
    if recv_data is None:
        return ws.recv()
    opcode, data = recv_data()
    if opcode == _WS_OP_CLOSE:
        if isinstance(data, (bytes, bytearray)) and len(data) >= 2:
            closed["code"] = struct.unpack("!H", bytes(data[:2]))[0]
        return ""
    if opcode in (_WS_OP_TEXT, _WS_OP_BINARY):
        return data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else data
    return ""


def _gateway_close(ws):
    """Close the session's socket if it got one; a close that fails is logged, not raised."""
    try:
        if ws is not None:
            ws.close()
    except Exception:
        _log.debug("discord gateway close failed", exc_info=True)


def discord_gateway_run(bot_token, on_message, _connect=None):
    """Open ONE Discord Gateway session and pump MESSAGE_CREATE events to `on_message`.

    Each event reaches `on_message(channel_id, author_is_bot, content, author)` until the socket
    drops; then this returns so the caller can reconnect after a backoff. A fresh IDENTIFY each time
    (no RESUME) means anything sent while we were down is skipped — the same 'no backlog replay' the
    Telegram poller gets, so the /update that restarted us is never re-run. Degrades to a no-op
    (logged) if websocket-client isn't installed. Never raises.

    Returns the close code Discord ended the session with, or None when it did not send one (the
    socket dropped, the heartbeat closed a zombie link, or op 7/9 asked for a reconnect). The
    caller needs it to tell "try again" from "this can never work until someone fixes the
    settings" — see bots/discord.py's _DC_FATAL_CLOSE.

    `_connect` is a seam for tests to inject a fake socket; production leaves it None.
    """
    if _connect is None:
        _connect = _gateway_connector()
        if _connect is None:
            return None
    ws = None
    stop = {"v": False}
    closed = {"code": None}
    try:
        ws = _connect()
        hello = json.loads(_gateway_recv(ws, closed))
        interval = float((hello.get("d") or {}).get("heartbeat_interval", 41250)) / 1000.0
        # The 40s given to create_connection is ALSO the timeout of every later recv(), and a
        # quiet guild sends nothing but heartbeat ACKs — the first of which comes a full interval
        # (~41s) after IDENTIFY. So recv() timed out before the first heartbeat was even sent, the
        # session "ended", and the watcher identified again ~56s later, around the clock: ~1500
        # IDENTIFYs a day against Discord's 1000, which gets the bot token reset. recv() now has
        # room for two intervals; a dead link is still caught by the unACKed-heartbeat check below,
        # which closes the socket and so unblocks recv().
        ws.settimeout(interval * 2 + 10)
        ws.send(json.dumps({"op": 2, "d": {
            "token": bot_token, "intents": _DISCORD_INTENTS,
            "properties": {"os": "linux", "browser": "linuxgsm-panel", "device": "linuxgsm-panel"},
        }}))
        state = {"seq": None, "acked": True}
        # The heartbeat runs beside the receive loop, on its own thread, until `stop` is set.
        threading.Thread(target=lambda: _gateway_heartbeat(ws, interval, state, stop),
                         daemon=True).start()

        while True:
            raw = _gateway_recv(ws, closed)
            if not raw or not _gateway_frame(ws, json.loads(raw), state, on_message):
                break
    except Exception:
        _log.debug("discord gateway session ended", exc_info=True)
    finally:
        stop["v"] = True
        _gateway_close(ws)
    return closed["code"]


# ── public API ─────────────────────────────────────────────────
def _channel_senders(tg, dc, nt, text):
    """Return (name, enabled, send) for each channel; `send()` decrypts and sends only when called."""
    return (("telegram", tg.get("enabled"),
             lambda: send_telegram(decrypt_secret(tg.get("token") or ""),
                                   (tg.get("chat_id") or "").strip(), text)),
            ("discord", dc.get("enabled"),
             lambda: send_discord(decrypt_secret(dc.get("webhook") or ""), text)),
            ("ntfy", nt.get("enabled"),
             lambda: send_ntfy(nt.get("server") or NTFY_DEFAULT_SERVER,
                               nt.get("topic") or "",
                               decrypt_secret(nt.get("token") or ""), text)))


# ── Alert delivery: one bounded queue, one sender, bursts folded into one message ──────────────
# notify() used to start a NEW THREAD PER ALERT, each sending on its own. Nothing bounded that:
# a host with fifty game servers coming back after an outage produced fifty "back online" alerts
# in one monitor pass, i.e. fifty concurrent threads, each making a request to every channel at
# once. Telegram allows a bot about one message a second into a chat (twenty a minute into a
# group) and answers the rest 429 — so most of the burst was refused and LOGGED as a failure,
# while the operator's phone buzzed for the ones that got through.
#
# Now alerts go on a bounded queue and ONE sender thread drains it. Whatever has piled up by the
# time the sender comes back for more is sent as a single message listing each alert, so a burst
# costs a couple of requests per channel rather than one per alert. The sender is started when
# there is work and exits when the queue is empty (no idle thread on a panel with alerts off), and
# a queue that is full drops the alert with a WARNING instead of growing without bound behind a
# provider that stopped answering.
_ALERT_QUEUE_MAX = 200
_ALERT_BATCH_MAX = 25          # alerts folded into one message at most
_ALERT_TEXT_MAX = 1800         # under the smallest provider cap (Discord's 1900 in send_discord)
_ALERT_LINE_MAX = 300          # one alert's line inside a folded message
_alert_queue = queue.Queue(maxsize=_ALERT_QUEUE_MAX)
_alert_lock = threading.Lock()
_alert_sender = [False]        # True while a sender thread owns the queue


def _alert_text(items):
    """The message for one or more queued (event_key, title, body) alerts.

    One alert reads exactly as it always has; several become one message with a line each.
    """
    if len(items) == 1:
        _key, title, body = items[0]
        return "🎮 LinuxGSM Panel — %s" % title + (("\n%s" % body) if body else "")
    lines = ["🎮 LinuxGSM Panel — %d alerts" % len(items)]
    for _key, title, body in items:
        lines.append(("• %s%s" % (title, (": " + body) if body else ""))[:_ALERT_LINE_MAX])
    return "\n".join(lines)


def _alert_messages(items):
    """Split `items` into messages that each fit _ALERT_TEXT_MAX: [(event keys, text)]."""
    out, chunk = [], []
    for item in items:
        if chunk and len(_alert_text(chunk + [item])) > _ALERT_TEXT_MAX:
            out.append(chunk)
            chunk = []
        chunk.append(item)
    if chunk:
        out.append(chunk)
    return [(", ".join(sorted({k for k, _t, _b in c})), _alert_text(c)) for c in out]


def _deliver_alerts(items):
    """Send queued alerts to every enabled channel, CHECKING each result. Never raises.

    The channel settings are read here, at send time: an alert queued a moment before a channel
    was switched off is not sent to it.
    """
    cfg = _cfg()
    tg = cfg.get("telegram") or {}
    dc = cfg.get("discord") or {}
    nt = cfg.get("ntfy") or {}
    for keys, text in _alert_messages(items):
        for _name, _enabled, _send in _channel_senders(tg, dc, nt, text):
            if not _enabled:
                continue
            # Each result is CHECKED. They were called as bare statements, so a provider that
            # refused every message left no trace at all — see _post's HTTPError branch. And each
            # channel on its own: one sender that raises no longer stops the others.
            try:
                _ok, _why = _send()
            except Exception:
                _log.debug("notify send to %s failed", _name, exc_info=True)
                continue
            if not _ok:
                _log.warning("notification to %s failed (%s): %s", _name, keys, _why)


def _next_alert_batch():
    """Take up to _ALERT_BATCH_MAX queued alerts; [] (and the sender stands down) when none.

    The empty check and the stand-down happen under the same lock _queue_alert takes to decide
    whether to start a sender, so an alert queued at that instant is never left without one.
    """
    with _alert_lock:
        items = []
        while len(items) < _ALERT_BATCH_MAX:
            try:
                items.append(_alert_queue.get_nowait())
            except queue.Empty:
                break
        if not items:
            _alert_sender[0] = False
        return items


def _drain_alerts():
    """The sender thread: deliver batches until the queue is empty, then exit."""
    while True:
        items = _next_alert_batch()
        if not items:
            return
        try:
            _deliver_alerts(items)
        except Exception:
            # Never let one batch end the sender while it still owns the queue: the flag would
            # stay set and no alert would ever be sent again.
            _log.debug("notify delivery failed", exc_info=True)


def _queue_alert(item):
    """Queue one alert, starting the sender if none is running. Dropped (and logged) when full."""
    try:
        _alert_queue.put_nowait(item)
    except queue.Full:
        _log.warning("notification queue is full (%d waiting); an alert was dropped",
                     _ALERT_QUEUE_MAX)
        return
    with _alert_lock:
        if _alert_sender[0]:
            return
        _alert_sender[0] = True
    try:
        threading.Thread(target=_drain_alerts, daemon=True, name="notifications").start()
    except Exception:
        with _alert_lock:
            _alert_sender[0] = False
        _log.debug("notify could not start its sender", exc_info=True)


def notify(event_key, title, body=""):
    """Queue an alert for `event_key` to every enabled channel; it is sent in the background.

    No-op when notifications (or this event) are off, or no channel is configured. Never raises.
    """
    try:
        cfg = _cfg()
        if not event_enabled(cfg, event_key):
            return
        _queue_alert((event_key, str(title or ""), str(body or "")))
    except Exception:
        _log.debug("notify failed to dispatch", exc_info=True)


def _form_or_saved(value, saved, key, default=""):
    """Return the value typed into the form, else `saved[key]` (read only then), else `default`."""
    return (value or "").strip() or (saved.get(key) or default)


def _form_or_saved_secret(value, saved, key):
    """Return the secret typed into the form, else `saved[key]` decrypted (read only then)."""
    return (value or "").strip() or decrypt_secret(saved.get(key) or "")


def _test_send_telegram(cfg, token, chat_id, text):
    """test_send for Telegram: check the token and chat id, then send."""
    tg = cfg.get("telegram") or {}
    tok = _form_or_saved_secret(token, tg, "token")
    chat = _form_or_saved(chat_id, tg, "chat_id").strip()
    if not tok:
        return False, "Enter the bot token first."
    if not _TG_TOKEN_RE.match(tok):
        return False, "That bot token isn't in the expected format (like 123456789:AA…)."
    if not chat:
        return False, "Enter the chat ID first. Message your bot once, then use your numeric chat ID."
    ok, detail = send_telegram(tok, chat, text)
    return (True, "Test message sent — check Telegram.") if ok \
        else (False, "Telegram error: %s" % (detail or "unknown"))


def _test_send_discord(cfg, webhook, text):
    """test_send for a Discord webhook: check the URL, then send."""
    wh = (webhook or "").strip() or decrypt_secret((cfg.get("discord") or {}).get("webhook") or "")
    if not wh:
        return False, "Enter the webhook URL first."
    if not _valid_discord_webhook(wh):
        return False, "That doesn't look like a Discord webhook URL."
    ok, detail = send_discord(wh, text)
    return (True, "Test message sent — check Discord.") if ok \
        else (False, "Discord error: %s" % (detail or "unknown"))


def _test_send_discord_bot(cfg, token, chat_id, text):
    """test_send for the Discord command bot: check the bot token and channel id, then send."""
    dc = cfg.get("discord") or {}
    tok = _form_or_saved_secret(token, dc, "bot_token")
    chan = _form_or_saved(chat_id, dc, "channel_id").strip()
    if not tok:
        return False, "Enter the bot token first."
    if not _valid_discord_bot_token(tok):
        return False, "That bot token isn't in the expected format."
    if not _DISCORD_CHANNEL_RE.match(chan):
        return False, "Enter the numeric channel ID first (right-click the channel → Copy Channel ID)."
    ok, detail = discord_bot_send(tok, chan, text)
    return (True, "Test message sent — check the Discord channel.") if ok \
        else (False, "Discord error: %s" % (detail or "unknown"))


def _test_send_ntfy(cfg, token, server, topic, text):
    """test_send for ntfy: check the topic and server, then publish."""
    nt = cfg.get("ntfy") or {}
    srv = _form_or_saved(server, nt, "server", NTFY_DEFAULT_SERVER)
    top = _form_or_saved(topic, nt, "topic")
    tok = _form_or_saved_secret(token, nt, "token")
    if not top:
        return False, "Enter the topic first — it is the name you subscribed to in the ntfy app."
    if not _NTFY_TOPIC_RE.match(top):
        return False, "A topic may use letters, digits, - and _ only (no spaces or slashes)."
    if not _valid_ntfy_server(srv):
        return False, ("That server isn't usable — give the base URL only, https and no path "
                       "(for example https://ntfy.sh).")
    ok, detail = send_ntfy(srv, top, tok, text)
    return (True, "Test message sent — check the ntfy app.") if ok \
        else (False, "ntfy error: %s" % (detail or "unknown"))


def test_send(kind, token=None, chat_id=None, webhook=None, server=None, topic=None):
    """Synchronously send a test message to one channel. Returns (ok, message).

    Uses the values passed from the form when given (so you can test BEFORE saving), else the saved
    config. The message carries the provider's actual error on failure.
    """
    cfg = _cfg()
    text = "🎮 LinuxGSM Panel — test alert. If you can read this, notifications are working."
    if kind == "telegram":
        return _test_send_telegram(cfg, token, chat_id, text)
    if kind == "discord":
        return _test_send_discord(cfg, webhook, text)
    if kind == "discord_bot":
        return _test_send_discord_bot(cfg, token, chat_id, text)
    if kind == "ntfy":
        return _test_send_ntfy(cfg, token, server, topic, text)
    return False, "Unknown channel."


def alerts_muted(gs):
    """True when one of this server's tags is marked "don't alert" (ServerTag.notify=False).

    That is how a tag like "test" or "staging" keeps a noisy box out of the alert channel without
    turning the event off globally for the real servers. Any muting tag wins: opting a server out
    is the conservative outcome, and being wrong the other way means paging someone at 3am.

    Fails OPEN (returns False) on any error: an alert we can't decide about should still be sent.
    Runs in poller threads, so it must never raise.

    Lives here rather than in app.py because it is an alerting decision, and because app.py is not
    importable from the modules that need it: the background jobs being pulled out of
    register_routes use it, and a jobs module importing app would be a cycle. This module imports
    nothing but config, so everything can reach it.
    """
    try:
        return any(not tag.notify for tag in (gs.tags or []))
    except Exception:
        _log.debug("tag mute check failed for %s", _server_log_name(gs), exc_info=True)
        return False


def _server_log_name(gs):
    """gs.short_name for alerts_muted's log line, or "?" when even that read raises.

    getattr's default answers AttributeError only. A server another row took the id of raises
    models.RowReplaced from every read, the one in the handler as well, and alerts_muted promises
    never to raise (models.row_label, which this module does not import: see alerts_muted).
    """
    try:
        return gs.short_name
    except Exception:
        return "?"
