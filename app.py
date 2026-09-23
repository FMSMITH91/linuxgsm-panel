"""LinuxGSM Panel - Full Game Server Administration Panel.

Routes:
  GET  /                    -> Dashboard (server overview)
  GET  /login               -> Login page
  GET  /setup               -> Initial setup wizard (multi-step)
  POST /setup               -> Process setup steps
  GET  /server/<id>         -> Single server detail + console
  POST /server/<id>/action  -> Execute server action (start/stop/restart/update)
  POST /server/<id>/command -> Send console command
  GET  /servers/manage      -> Redirects to the dashboard (the list folded into it)
  GET  /servers/install     -> The install form
  POST /servers/add         -> Install a new game server
  POST /servers/<id>/delete -> Uninstall a game server
  GET  /remotes             -> Manage remote VPS connections
  POST /remotes/add         -> Add a remote VPS
  POST /remotes/<id>/edit   -> Edit remote VPS
  POST /remotes/<id>/delete -> Remove remote VPS
  POST /remotes/<id>/test   -> Test remote VPS connection
  GET  /users               -> User management (admin)
  POST /users/add           -> Add user
  POST /users/<id>/edit     -> Edit user
  POST /users/<id>/delete   -> Delete user
  GET  /groups              -> Group management (admin)
  POST /groups/add          -> Add group
  POST /groups/<id>/edit    -> Edit group (permissions + server access)
  POST /groups/<id>/delete  -> Delete group
  GET  /logs                -> Audit log viewer
  GET  /api/servers         -> JSON server list
  GET  /api/server/<id>     -> JSON server status
  GET  /api/console/<id>    -> JSON console log (recent lines)
  POST /api/command/<id>    -> JSON send command
  socket.io join_console    -> Live console streaming (events, not a route:
                               connect / join_console / leave_console / disconnect)
"""
import logging
import os
import re
import threading
import time
import gzip as _gzip
from datetime import timedelta

# eventlet announces its own deprecation on import — upstream's words, not a nit: "Eventlet is
# deprecated ... we strongly recommend against using it for new projects ... we recommend migrating
# to a different framework." Migrating off it is tracked separately; the banner is silenced here so
# it does not print on every start.
#
# Silenced by MESSAGE, and only around the import. What used to be here was
# `filterwarnings("ignore", category=DeprecationWarning)` — process-wide, permanent, and it never
# matched this warning at all, because EventletDeprecationWarning subclasses Warning rather than
# DeprecationWarning. So the banner printed anyway while every REAL DeprecationWarning in the panel
# was silenced for the life of the process. `datetime.utcnow()` was deprecated in 3.12 and scheduled
# for removal, and the panel called it 22 times without ever saying so.
#
# catch_warnings() restores the previous filter state on exit, so nothing leaks past this block.
import warnings as _w
with _w.catch_warnings():
    _w.filterwarnings("ignore", message=r"\s*Eventlet is deprecated")
    import eventlet
    eventlet.monkey_patch()

del _w

# Panel imports live AFTER the patch, all of them. terminal/clock used to sit above it and got
# away with it only because neither pulls in anything eventlet needs to green — a latent trap for
# whichever of them grows a dependency first. tests/unit asserts this ordering now.
from panel.core import terminal
from panel.core.clock import utcnow

import secrets
from flask import (Flask, abort, current_app, g, jsonify, redirect, request, session, url_for)
from markupsafe import Markup
from panel.core import i18n
from flask_login import (current_user)
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

from panel.security.auth import (ALL_PERMISSIONS, client_ip, get_user_permissions, init_auth,
    log_action, strip_legacy_superadmin_grants)
from panel.core.config import (
    DATA_DIR, DB_PATH, get_secret_key, load_config, save_config, update_config,
    encrypt_secret, is_encrypted, harden_data_permissions,
)
from panel.services import notifications
# The two chat bots. They import nothing from app.py — every dependency they have comes from
# the module that owns it — so unlike panel.routes.* this needs no lazy import to break a cycle.
from panel.services.bots.discord import (_discord_command_watch, _report_dc_pending_update)
from panel.services.bots.telegram import (_report_tg_pending_update, _telegram_command_watch)
from panel.services.certs import (_ensure_self_signed_cert)
from panel.db.prefs import (_effective_prefs, _panel_layout)
from panel.core.middleware import PrefixMiddleware
# The pure layers, now that they live outside this module. app.py used to DEFINE these and every
# route module imported them back out of it — app.py imports the route modules, so the arrow went
# both ways. It points one way now: panel.core knows nothing about app.py, and app.py and the route
# modules each import what they use. Deliberately NOT a re-export of the whole surface: a name
# app.py does not use has no reason to be reachable through app.py, and leaving it importable from
# here is what let the cycle grow in the first place. See the docstrings in panel/core/validation.py
# and panel/core/http.py.
from panel.core.validation import MAX_PORT, MIN_PORT, _valid_hex_color
from panel.services.monitoring import (_METRIC_RETENTION_DAYS, _METRIC_SAMPLE_SECONDS,
    _MONITOR_SECONDS, _PLAYER_POLL_SECONDS, _autoblock_reconcile, _autoblock_threshold,
    _host_reachable, _monitor_pass, _reboot_when_empty_watch, _record_metric_samples,
    _refresh_player_counts)
from panel.core.panel_state import (_expected_offline, _install_jobs, _install_lock,
    _last_sample_prune, _monitor_state, _os_update_seen, _player_counts)
from panel.db.models import (AuditLog, GameServer, Group, RemoteServer, SetupState, User, db,
    init_db, CUSTOM_ARG_PLACEHOLDER, GlobalBan, MetricSample, HostSample)
from panel.ops.ssh_manager import (_remote_listening_ports, is_local_server, get_server_status,
    game_engine, console_steamid_ban, pro_status, list_game_backups, game_engine as
    sm_game_engine, set_game_priority_bulk, lgsm_get_values, remote_set_fail2ban_ignoreip,
    ensure_node_tools_cron, ensure_persistent_bans)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.ops import tailscale_integration as ts
from panel.ops import system_ops as so
from panel.ops import backup as bk
from panel.services import lgsm_data

_log = logging.getLogger("panel.app")

# Dedicated failed-login logger. Writes to data/auth.log (set up in create_app) in a fixed,
# fail2ban-parseable format so the optional panel-login fail2ban jail can ban repeat offenders.
_authlog = logging.getLogger("panel.auth")
AUTH_LOG_PATH = os.path.join(str(DATA_DIR), "auth.log")


def _log_ip(ip):
    """Only a valid IP literal is written to auth.log (fail2ban bans IPs anyway); anything else
    becomes 'unknown'. CR/LF are stripped explicitly first, so a forged header value can never
    inject a second line into the log fail2ban parses."""
    import ipaddress
    s = str(ip or "").replace("\r", "").replace("\n", "").strip()
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return "unknown"


def _session_label(ua):
    """A short, human device/browser label from a session's User-Agent (best-effort, display only)."""
    ua = ua or ""
    br = ("Edge" if "Edg/" in ua else
          "Opera" if ("OPR/" in ua or "Opera" in ua) else
          "Chrome" if ("Chrome" in ua and "Chromium" not in ua) else
          "Firefox" if "Firefox" in ua else
          "Safari" if "Safari" in ua else "")
    os_ = ("Windows" if "Windows" in ua else
           "Android" if "Android" in ua else
           "iPhone" if "iPhone" in ua else
           "iPad" if "iPad" in ua else
           "macOS" if ("Macintosh" in ua or "Mac OS" in ua) else
           "Linux" if "Linux" in ua else "")
    if br and os_:
        return "%s on %s" % (br, os_)
    return br or os_ or "Unknown device"


def _has_remember_cookie():
    """True when the browser is still sending flask-login's "remember me" cookie.

    Only presence matters here — the cookie's VALUE is never trusted at this point (the user
    loader is what validates it); this answers "does this login outlive the session cookie?" so a
    UserSession row can be given the right expiry window.

    Written as a comparison rather than bool() on request data deliberately. That is what the
    question actually is, and bool()/float() over request data is a pattern the security scanners
    flag on sight — correctly for float() and complex(), where a hostile string becomes NaN. Not
    worth an exception entry for a test that reads better spelled out.
    """
    name = current_app.config.get("REMEMBER_COOKIE_NAME", "remember_token")
    return (request.cookies.get(name) or "") != ""


def _register_session(user, remember=None):
    """Record a server-side row for this login and tag `user` with its sid so User.get_id embeds it
    (letting load_user validate it and the account page revoke it individually). Also drops this
    user's expired sessions. `remember` records which cookie keeps this login alive, which is what
    decides when the row expires — a plain login dies with the session cookie (hours), a "remember
    me" one with the remember cookie (days). Returns the sid, or None on failure — login still
    proceeds either way, the cookie just falls back to epoch-only (not individually revocable)."""
    from panel.db.models import UserSession, prune_expired_sessions
    sid = secrets.token_urlsafe(24)
    if remember is None:
        # Not told (adopting a login that predates this bookkeeping) — ask the browser. If it is
        # still sending a remember cookie, this login outlives the session cookie, and recording it
        # as a plain one would expire the row hours before the login itself actually dies.
        remember = _has_remember_cookie()
    prune_expired_sessions(user.id)   # commits (or rolls back) on its own
    try:
        db.session.add(UserSession(user_id=user.id, sid=sid, remember=bool(remember),
                                   ip=(client_ip() or "")[:64],
                                   user_agent=(request.headers.get("User-Agent", "") or "")[:300]))
        db.session.commit()
    except Exception:
        db.session.rollback()
        return None
    user._sid = sid
    return sid


def _setup_auth_log():
    """Attach a small rotating file handler to _authlog once, so failed logins land in
    data/auth.log for fail2ban to tail. Best-effort — a logging failure must never block a login."""
    if any(getattr(h, "_panel_auth", False) for h in _authlog.handlers):
        return
    try:
        from logging.handlers import RotatingFileHandler
        h = RotatingFileHandler(AUTH_LOG_PATH, maxBytes=512 * 1024, backupCount=3)
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        h._panel_auth = True
        _authlog.addHandler(h)
        _authlog.setLevel(logging.INFO)
        _authlog.propagate = False   # keep these lines out of the main app log / journal
    except Exception:
        _log.debug("auth-log setup failed", exc_info=True)


def _read_version():
    """Panel version from the VERSION file next to this module (bumped per release)."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")) as f:
            return f.read().strip() or "0.0.0"
    except Exception:
        return "0.0.0"


PANEL_VERSION = _read_version()
# The exact git commit this process is running. Computed once (it can't change until a restart,
# and a self-update restarts the process). "" when not a git checkout.
try:
    PANEL_COMMIT = so.panel_commit()
except Exception:
    PANEL_COMMIT = ""
# Same reasoning: a checkout's origin cannot change under a running process. Derived from the
# remote rather than hardcoded, so a fork's panel links to the fork -- the same rule the
# "report an issue" URL already follows.
try:
    PANEL_REPO_URL = so.github_repo_url()
except Exception:
    PANEL_REPO_URL = ""


# Largest file the browser upload accepts (enforced in the upload route AND as the app-wide
# MAX_CONTENT_LENGTH, so an oversized body is rejected before it's read).
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024

# Short-lived cache of each remote's listening ports (the dashboard status poll). Keyed by
# remote id -> (expiry_epoch, set_of_ports). Collapses the thundering herd: a servers_changed
# broadcast makes EVERY open dashboard call /api/servers at once, and without this each one
# would run its own `ss` scan per remote. Invalidated on start/stop/restart so status stays
# accurate right after an action. TTL is short — status only ever lags by a couple of seconds.

# How many CONTIGUOUS ports one server of a game occupies, for auto-picking a non-colliding
# port at install. Most LinuxGSM games answer queries on the game port itself, so a server needs
# just ONE port (default 1) — that's why two Call of Duty servers should sit on 28960 and 28961,
# not 28960 and 28962. A few games spread game + query/steam/voice across an ADJACENT block; those
# reserve the whole block so two of them can't overlap. Anything not listed defaults to 1. This is
# only a hint for STOPPED servers — resolve_free_port also unions in the host's live listening
# ports, so a running server's real footprint is always respected regardless of this table.
_PORT_SPAN = {
    "rust": 2,                       # game 28015 + query 28016
    "valheim": 3, "vh": 3,           # 2456–2458
    "sdtd": 3, "7d2d": 3,            # 26900–26902 (game + query)
    "arma3": 5,                      # 2302 + steam query/voice 2303–2306
    "ark": 2,                        # 7777 game + 7778 raw
    "squad": 2,                      # game 7787 + query 7788
    "unturned": 2,                   # game 27015 + steam query 27016
}


# Characters a filename may keep in the plain `filename=` parameter: everything else is replaced.
# Quotes and backslashes would end the quoted string early, and CR/LF would split the header.




def _port_span(game_type):
    """Contiguous ports one server of `game_type` reserves (default 1)."""
    return _PORT_SPAN.get((game_type or "").lower(), 1)


def _first_free_block(desired, span, occupied, limit=400):
    """Lowest start port >= `desired` whose `span` contiguous ports are all clear of `occupied`,
    or None when there is no such block within `limit` tries or before the port range runs out.

    RETURNS None RATHER THAN A BEST GUESS. It used to return the last candidate after exhausting
    `limit` — a port that is occupied by definition — so the caller was handed a colliding port
    AND told the search had succeeded. The install then died on the host with srcds's own
    "Port N was unavailable", which points at the game rather than at the allocator. The same walk
    could also run past 65535 and hand back a port that does not exist. A caller that cannot be
    given a free block has to be told so; there is no useful port to invent here."""
    p = max(int(desired), MIN_PORT)
    for _ in range(limit):
        if p + span - 1 > MAX_PORT:
            return None
        if all((p + k) not in occupied for k in range(span)):
            return p
        p += 1
    return None




_PRO_MAX_AGE = 86400   # only auto-run the slow `pro status` client if the stored value is >1 day old
_CUSTOM_CMD_ENGINES = {"valve": "Valve / Source & GoldSrc",
                       "idtech3": "idTech3 / Quake3 (CoD family)",
                       "minecraft": "Minecraft"}


# Source (srcds) instances bind a SourceTV port and a client port besides the game port, and LinuxGSM
# starts them with `-strictportbind`, which makes srcds QUIT if ANY of those is already taken. So a
# 2nd Source server on one host must de-conflict all of them — de-conflicting only the game port (as
# resolve_free_port does) still leaves SourceTV/client at their shared defaults (27020/27005) and the
# second server dies with "Port 27020 was unavailable". These keys live in the LinuxGSM config.
_SOURCE_AUX_PORT_KEYS = ("clientport", "sourcetvport")


def _dedupe_aux_ports(have, occupied):
    """Pure port picker. `have` = {config_key: current_port_int}; `occupied` = ports already in use
    on the host. Return {config_key: new_port} ONLY for keys whose current port collides and must
    move — each is bumped to the next free port scanning upward, reserving it so two keys can't land
    on the same port. Free ports keep their value (and are reserved) and are omitted from the result.
    Deterministic (iterates `have` in insertion order) so it can be tested directly."""
    updates = {}
    occ = set(occupied)
    for key, p in have.items():
        if p in occ:
            np = p + 1
            while np in occ and np <= 65535:
                np += 1
            if np > 65535:
                continue                 # nothing free above it — leave as-is rather than pick junk
            updates[key] = np
            occ.add(np)
        else:
            occ.add(p)
    return updates


def _add_sibling_ports(occupied, remote, remote_id, skip_short_name=None):
    """Union into `occupied` every panel game server's reserved port block on this remote, plus
    every OTHER valve server's CONFIGURED SourceTV/client ports. Returns `occupied`.

    The aux ports belong in that set for the same reason the game-port block does: the panel wrote
    them into that sibling's config, so they are authoritative even when it is STOPPED and so not
    listening for _remote_listening_ports to find. This walk used to exist only here, and
    resolve_free_port had the block half alone — while _PORT_SPAN has no entry for any valve game,
    so each Source server reserved exactly one port. Five stopped Source servers on 27015-27019
    therefore left 27020 (the first one's sourcetvport) looking free, and a sixth install took it.
    The install succeeded; the cost landed later, on whoever started the older server and got
    "Port 27020 was unavailable" out of a server nobody had touched. One walk now, so the two
    cannot drift apart again.

    `skip_short_name` is the instance being resolved: its own aux ports are the values being
    moved, not a constraint on them."""
    for e in GameServer.query.filter_by(remote_id=remote_id).all():
        for k in range(_port_span(e.game_type)):
            occupied.add(e.port + k)
        if e.short_name == skip_short_name or sm_game_engine(e.game_type) != "valve":
            continue
        try:
            sib = lgsm_get_values(remote, e.short_name, e.lgsm_name, _SOURCE_AUX_PORT_KEYS) or {}
            for v in sib.values():
                if str(v).strip().isdecimal():
                    occupied.add(int(str(v).strip()))
        except Exception:
            _log.debug("aux-port: sibling servercfg read failed", exc_info=True)
    return occupied


def _resolve_source_aux_ports(remote, remote_id, short_name, lgsm_name, main_port):
    """Config updates that move THIS instance's SourceTV/client ports off any already taken on the
    host, so a 2nd Source server can start under -strictportbind. Reads the instance's effective
    clientport/sourcetvport (absent/blank => not a Source game => returns {}); the 'occupied' set is
    the host's live listening ports, every panel server's reserved game-port block, this instance's
    own game port, and every OTHER valve server's configured aux ports (authoritative even when that
    sibling is stopped and so not listening). Best-effort — returns {} on any read failure."""
    try:
        cur = lgsm_get_values(remote, short_name, lgsm_name, _SOURCE_AUX_PORT_KEYS)
    except Exception:
        return {}
    if cur is None:
        return {}                        # config unreadable — same best-effort answer as a raise
    have = {k: int(str(cur.get(k, "")).strip())
            for k in _SOURCE_AUX_PORT_KEYS if str(cur.get(k, "")).strip().isdecimal()}
    if not have:
        return {}                        # game has no SourceTV/client ports — nothing to do
    # `or ()`: None means the scan failed. Treating that as 'no ports occupied' can suggest
    # a port that is actually taken — the install then fails with a clear error, which is
    # the same outcome this had before the scanner learned to say 'I could not read'.
    occupied = set(_remote_listening_ports(remote) or ())
    occupied.add(int(main_port))
    _add_sibling_ports(occupied, remote, remote_id, skip_short_name=short_name)
    return {k: str(v) for k, v in _dedupe_aux_ports(have, occupied).items()}


# Known, actionable failure lines from a game's start log (srcds/LinuxGSM), most specific first — so a
# failed auto-start can tell the admin WHY instead of a bare "offline". ANSI colour is stripped first.
_START_ERROR_PATTERNS = (
    r"Port\s+\d+\s+was unavailable[^\n]*",              # -strictportbind: a needed port is taken
    r"Host_Error:[^\n]*",
    r"(?:Couldn't|Could not|Failed to)\s+(?:open|load|find|bind|allocate|mount)[^\n]*",
    r"FATAL[^\n]*",
)


def _extract_start_error(out):
    """A short, human-meaningful reason from a start log, or "" when nothing clear stands out (so the
    caller can fall back to a generic message rather than surfacing srcds boot noise). Never raises."""
    text = terminal.strip_escapes(out or "")
    for pat in _START_ERROR_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            # Collapse whitespace and drop angle brackets: this game-generated text is surfaced in
            # the install job message, which the progress UI inserts via innerHTML, so keep it inert.
            return re.sub(r"\s+", " ", m.group(0)).replace("<", "").replace(">", "").strip()[:200]
    return ""


# ── What each host's last OS-update check found ─────────────


def _is_security_pkg(p):
    """An apt suite ending in "-security" ("jammy-security") is what marks a security update."""
    return "-security" in ((p or {}).get("suite") or "")


def _os_update_note(remote, result):
    """Record one host's check result. A check that FAILED is dropped rather than stored: apt
    produces no output when it fails, which is exactly what a clean host produces, so recording it
    would clear a real banner and tell you the host is up to date when nobody ever asked it."""
    if not result or not result.get("ok"):
        return
    pkgs = result.get("packages") or []
    _os_update_seen[remote.id] = {
        "name": remote.display_name,
        "count": len(pkgs),
        "security": sum(1 for p in pkgs if _is_security_pkg(p)),
        "packages": pkgs,
        "at": time.time(),
    }


# ── Live player-count cache ────────────────────────────────


def _cached_player_max(server_id):
    """Last known max-player capacity for a server (int), or None when unknown / not polled yet."""
    entry = _player_counts.get(server_id)
    return entry.get("max") if entry else None


def _cached_player_name(server_id):
    """Last known in-game server name (the hostname players see in the browser) for a server, or None
    when unknown / not gamedig-queryable."""
    entry = _player_counts.get(server_id)
    return entry.get("name") if entry else None


def _player_count_watch(app):
    """Keep _player_counts fresh in the background so the dashboard and Game Servers page can show
    live per-server counts (and a total) without a query on the request path."""
    while True:
        try:
            _refresh_player_counts(app)
        except Exception:
            _log.debug("player-count poller pass failed", exc_info=True)
        time.sleep(_PLAYER_POLL_SECONDS)


def _prune_metric_samples(app):
    """Drop samples older than the retention window — at most every 30 min so it isn't per-pass churn."""
    if time.time() - _last_sample_prune[0] < 1800:
        return
    _last_sample_prune[0] = time.time()
    with app.app_context():
        cutoff = utcnow() - timedelta(days=_METRIC_RETENTION_DAYS)
        MetricSample.query.filter(MetricSample.ts < cutoff).delete(synchronize_session=False)
        HostSample.query.filter(HostSample.ts < cutoff).delete(synchronize_session=False)
        db.session.commit()


def _metrics_history_watch(app):
    """Background loop: sample metrics into history every _METRIC_SAMPLE_SECONDS, then prune old rows."""
    while True:
        try:
            _record_metric_samples(app)
        except Exception:
            _log.debug("metrics-history sampler pass failed", exc_info=True)
        try:
            _prune_metric_samples(app)
        except Exception:
            _log.debug("metrics-history prune failed", exc_info=True)
        time.sleep(_METRIC_SAMPLE_SECONDS)


def _node_tools_cron_watch(app):
    """Once at startup and daily after, make sure every host has the weekly npm+gamedig auto-update
    cron — so hosts that predate it (or a remote added without the 'Prepare & Secure' bootstrap) still
    keep their player-query tools current, without a manual re-bootstrap. Idempotent + best-effort."""
    while True:
        try:
            with app.app_context():
                for r in RemoteServer.query.all():   # includes the local/panel host
                    try:
                        ensure_node_tools_cron(r)
                    except Exception:
                        _log.debug("node-tools cron ensure failed for %s", r.name, exc_info=True)
        except Exception:
            _log.debug("node-tools cron watch pass failed", exc_info=True)
        time.sleep(86400)   # daily


# ── Power actions: is this game actually running? ──────────────


def _live_run_state(gs, remote):
    """Is ANY trace of this server alive right now? True/False, or None when that can't be read.

    A listening game port OR a live process owned by the game user. That is deliberately WIDER
    than the panel's `status` column, which means "a player could connect" and is the listening
    port alone. The two used to be the same predicate, and the narrow question is the wrong one
    here: this exists only to refuse a power action that would be a no-op, and a server whose game
    has crashed inside a surviving srcds_run reads offline in the status column while its tmux
    session is still there to be cleared. Refusing that Stop would leave no way out of the panel.

    Reads through server_live_metrics' 2s cache, which an open dashboard is usually filling
    anyway. An SSH blip returns the all-zero default dict; ram_total is 0 only in that case
    (`free -b` never fails on a reachable host), so it is the sentinel for "don't claim to know"."""
    try:
        m = _sm.server_live_metrics(remote, gs.short_name, gs.port)
    except Exception:
        _log.debug("live run-state check failed", exc_info=True)
        return None
    if not m or not m.get("ram_total"):
        return None
    return bool(m.get("port_open") or m.get("game_procs"))


# ── Proactive monitor → admin notifications ────────────────────


def _mark_expected_offline(server_id):
    """Record that the PANEL just took a server offline, so the monitor won't alert on an
    intentional stop/restart."""
    _expected_offline[server_id] = time.time()


def _monitor_watch(app):
    """Background monitor loop that feeds the admin notifications (server down, host unreachable,
    disk low)."""
    while True:
        time.sleep(_MONITOR_SECONDS)
        try:
            with app.app_context():
                _monitor_pass()
        except Exception:
            _log.debug("monitor pass failed", exc_info=True)


# ── Rolling auto-block: keep the top-20 offenders (last 7 days) UFW-blocked, releasing an IP once it
# ── ages out of that window. Which hosts have it on is stored in the panel config (a list of remote
# ── ids). Only rules the panel itself tagged 'panel-autoblock' are ever added/removed here — manual
# ── blocks and any other UFW rules are left untouched.


def _autoblock_hosts():
    return set(load_config().get("autoblock_hosts", []) or [])


def _set_autoblock_host(remote_id, enabled):
    def _mut(cfg):   # read-modify-write under the config lock (toggled alongside threshold/whitelist)
        hosts = set(cfg.get("autoblock_hosts", []) or [])
        hosts.add(remote_id) if enabled else hosts.discard(remote_id)
        cfg["autoblock_hosts"] = sorted(hosts)
    update_config(_mut)


# ── Auto-block threshold: an IP earns an all-ports UFW block once its failed-login count over the
# ── rolling 7-day window reaches this many. Ranking (old "top 20") let a patient attacker who spaced
# ── attempts wider than fail2ban's findtime slip through; a cumulative count over 7 days can't be
# ── dodged that way, and a still-active attacker stays blocked instead of aging out at rank 21.


# ── Login-security whitelist: IPs / CIDRs that are NEVER fail2ban-banned or UFW auto-blocked (global,
# ── on top of the automatic tailnet exemption). Stored as validated canonical strings in the config.
def _valid_ip_or_cidr(value):
    """Canonical 'ip' or 'cidr' string for a user-entered value, or None if it isn't a real one."""
    import ipaddress
    s = (str(value) or "").strip()
    try:
        return str(ipaddress.ip_network(s, strict=False)) if "/" in s else str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _security_whitelist():
    return list(load_config().get("security_whitelist", []) or [])


def _security_whitelist_add(value):
    canon = _valid_ip_or_cidr(value)
    if not canon:
        return None

    def _mut(cfg):   # read-modify-write under the config lock so a concurrent write can't clobber it
        cfg["security_whitelist"] = sorted(set(cfg.get("security_whitelist", []) or []) | {canon})
    update_config(_mut)
    return canon


def _security_whitelist_remove(value):
    canon = _valid_ip_or_cidr(value) or (str(value) or "").strip()
    update_config(lambda cfg: cfg.update(
        {"security_whitelist": [w for w in (cfg.get("security_whitelist", []) or []) if w != canon]}))
    return canon


def _apply_whitelist_to_fail2ban():
    """Rewrite the panel-login jail so its ignoreip matches the current whitelist (no-op if the jail
    is already correct). Best-effort and panel-host-only — for remotes see _apply_whitelist_to_remotes."""
    try:
        return so.ensure_panel_fail2ban(AUTH_LOG_PATH, load_config().get("port", 5000), _security_whitelist())
    except Exception:
        _log.debug("applying whitelist to fail2ban failed", exc_info=True)
        return False, "could not update fail2ban"


def _apply_whitelist_to_remotes(app, unban_ip=None):
    """Push the whitelist into every remote host's fail2ban over SSH, so a whitelisted IP is never
    banned on a remote either (parity with the panel host). Best-effort and backgrounded — one SSH
    round-trip per remote. Needs its own app context (runs from a background thread)."""
    with app.app_context():
        wl = _security_whitelist()
        for remote in RemoteServer.query.filter_by(is_local=False).all():
            try:
                remote_set_fail2ban_ignoreip(remote, wl, unban_ip=unban_ip)
            except Exception:
                _log.debug("remote fail2ban ignoreip failed for remote %s", remote.id, exc_info=True)


def _apply_whitelist_everywhere(app, unban_ip=None):
    """Apply the whitelist to fail2ban on the panel host AND every remote. Run in a background thread
    (SSH per remote) so the request that changed the whitelist returns immediately."""
    _apply_whitelist_to_fail2ban()                     # panel-login jail (local)
    if unban_ip:
        try:
            so.fail2ban_unban_ip_everywhere(unban_ip)  # lift a current local ban immediately
        except Exception:
            _log.debug("whitelist: local unban-everywhere failed", exc_info=True)
    _apply_whitelist_to_remotes(app, unban_ip=unban_ip)


# ── Global ban list: one SteamID banned on every Source/GoldSrc server across every host ─────────
def _valve_game_servers():
    """Every installed valve-engine (Source/GoldSrc) game server — the only engine with SteamID bans."""
    return [gs for gs in GameServer.query.filter_by(installed=True).all()
            if game_engine(gs.game_type) == "valve"]


def _fan_out_global_ban(app, steamid, unban=False):
    """Apply (or lift) one SteamID on every valve server across all hosts, and RECORD what happened.

    Backgrounded, so the flash that started it cannot report the result — which is exactly why the
    result has to land in the audit log. console_steamid_ban already computes a precise outcome
    ('banned' / 'unbanned' / 'offline' / 'failed'); this used to call it for effect and throw that
    away, while the page said "Banned <id> across all Source servers" and the audit row — written
    BEFORE this thread starts, with log_action's default success=True — asserted a success nobody
    had checked. A server that was stopped, mid-restart, or on an unreachable host simply did not
    get the ban, and nothing anywhere said so.

    The old docstring claimed "a stopped server picks the ban up from writeid/banned_user.cfg or
    the next Sync". It cannot: banid/writeid run THROUGH the console, so no console means no write
    to banned_user.cfg, and _sync_global_bans takes the identical path — a server down at ban time
    and at sync time never receives it at all. The tally below is what makes that visible.

    ensure_persistent_bans runs first, because a ban the engine drops on the next map change is not
    a ban. It was only ever called on the INSTALL path, so every IMPORTED valve server was missing
    the `exec banned_user.cfg` line. It is idempotent and cheap (a grep, then an append only when
    absent), and this is the one place that knows a ban is about to be applied to this server."""
    done, offline, failed = [], [], []
    with app.app_context():
        for gs in _valve_game_servers():
            try:
                ensure_persistent_bans(gs.remote, gs.short_name, gs.lgsm_name)
                ok, why = console_steamid_ban(gs.remote, gs.short_name, gs.lgsm_name, steamid,
                                              unban=unban)
                (done if ok else (offline if why == "offline" else failed)).append(gs.short_name)
            except Exception:
                failed.append(getattr(gs, "short_name", "?"))
                _log.debug("global-ban fan-out failed for %s", getattr(gs, "short_name", "?"), exc_info=True)
        _log_ban_fanout("global_ban_apply" if not unban else "global_ban_lift",
                        steamid, done, offline, failed)


def _log_ban_fanout(action, steamid, done, offline, failed):
    """One audit row saying what a ban fan-out actually achieved. success=False when any server
    missed it, so /logs shows the difference between "applied everywhere" and "applied where it
    could" — which is the whole point of collecting the outcomes."""
    bits = ["%d applied" % len(done)]
    if offline:
        bits.append("%d not running (%s)" % (len(offline), ", ".join(sorted(offline)[:6])))
    if failed:
        bits.append("%d failed (%s)" % (len(failed), ", ".join(sorted(failed)[:6])))
    try:
        log_action(None, action, target=steamid, detail="; ".join(bits),
                   success=not (offline or failed))
    except Exception:
        _log.debug("could not record the ban fan-out outcome", exc_info=True)


def _sync_global_bans(app):
    """Re-apply the WHOLE global ban list to every valve server (covers newly added servers and any
    whose native ban list was reset), and record the outcome — same reasoning as
    _fan_out_global_ban: this runs in the background, so the audit row is the only place the result
    can appear."""
    with app.app_context():
        bans = [b.steamid for b in GlobalBan.query.all()]
        done, offline, failed = [], [], []
        for gs in _valve_game_servers():
            try:
                ensure_persistent_bans(gs.remote, gs.short_name, gs.lgsm_name)
            except Exception:
                _log.debug("persistent-ban setup failed for %s", getattr(gs, "short_name", "?"),
                           exc_info=True)
            for sid in bans:
                try:
                    ok, why = console_steamid_ban(gs.remote, gs.short_name, gs.lgsm_name, sid)
                    (done if ok else (offline if why == "offline" else failed)).append(
                        "%s/%s" % (gs.short_name, sid))
                except Exception:
                    failed.append("%s/%s" % (getattr(gs, "short_name", "?"), sid))
                    _log.debug("global-ban sync failed for %s", getattr(gs, "short_name", "?"), exc_info=True)
        if bans:
            _log_ban_fanout("global_ban_sync", "%d ban(s)" % len(bans), done, offline, failed)


def _local_remote_id():
    r = RemoteServer.query.filter_by(is_local=True).first()
    return r.id if r else None


def _run_autoblock_now(app, remote_id):
    """Reconcile one host's auto-block immediately (in the background), so toggling it on takes effect
    without waiting for the hourly tick."""
    def _go():
        with app.app_context():
            try:
                remote = RemoteServer.query.get(remote_id)
                if remote:
                    _autoblock_reconcile(remote)
            except Exception:
                _log.debug("immediate autoblock reconcile failed for %s", remote_id, exc_info=True)
    threading.Thread(target=_go, daemon=True).start()


def _autoblock_watch(app):
    """Reconcile every auto-block host hourly, so the block list rolls with the 7-day window."""
    while True:
        time.sleep(3600)
        host_ids = _autoblock_hosts()
        if not host_ids:
            continue
        with app.test_request_context():
            for rid in host_ids:
                try:
                    remote = RemoteServer.query.get(rid)
                    if remote:
                        a, r = _autoblock_reconcile(remote)
                        if a or r:
                            log_action(None, "autoblock_reconcile", target=remote.name,
                                       detail="+%d blocked, -%d released" % (a, r), actor="system")
                except Exception:
                    _log.debug("autoblock tick failed for remote %s", rid, exc_info=True)


def _prune_jobs(registry, lock, max_age=7200):
    """Drop job entries whose last update is older than max_age seconds (default 2h).

    Finished jobs are normally removed when their status is polled, but a job whose
    result is never polled would otherwise linger forever — this bounds the registry so
    it can't grow without limit over a long-running process. Called when a new job starts."""
    now = time.time()
    with lock:
        stale = [k for k, j in registry.items()
                 if now - (j.get("updated") or j.get("started") or 0) > max_age]
        for k in stale:
            registry.pop(k, None)

# LinuxGSM commands the panel is willing to run from a button. Each only appears for a game whose
# LinuxGSM command list actually includes it, so fastdl shows only for Source games. fastdl asks a
# few yes/no questions (all default Y) and loops forever on EOF, so it's fed answers in _bg_action.
# The wipe variants were dropped: they're destructive and their non-interactive behaviour couldn't
# be verified without a live Rust server (fastdl proved these commands DO prompt-loop). Genuinely
# interactive/foreground commands (console, debug, send, install, auto-install, skeleton, developer,
# sponsor, and the mods-install/mods-remove pickers, which are handled by the dedicated mods UI)
# are excluded — they can't be driven by a blind one-click button.
RUNNABLE_ACTIONS = {
    "start", "stop", "restart", "monitor", "update", "validate", "backup",
    "details", "check-update", "force-update", "update-lgsm", "mods-update",
    "postdetails", "test-alert", "fastdl",
}
# Long-running ones run in the background so the HTTP request returns immediately.
LONG_ACTIONS = {"update", "validate", "backup", "force-update", "mods-update", "fastdl"}
# Read-only ones: show their output back to the user.

# LinuxGSM alert providers: a toggle key (on/off) + the fields each needs. Exposed as a
# friendly per-server "Alerts" editor that writes straight into the LinuxGSM config.
ALERT_PROVIDERS = [
    {"id": "discord", "label": "Discord", "toggle": "discordalert",
     "fields": [{"key": "discordwebhook", "label": "Webhook URL"}]},
    {"id": "telegram", "label": "Telegram", "toggle": "telegramalert",
     "fields": [{"key": "telegramtoken", "label": "Bot token"},
                {"key": "telegramchatid", "label": "Chat ID"}]},
    {"id": "email", "label": "Email", "toggle": "emailalert",
     "fields": [{"key": "email", "label": "To address"},
                {"key": "emailfrom", "label": "From (optional)"}]},
    {"id": "pushover", "label": "Pushover", "toggle": "pushoveralert",
     "fields": [{"key": "pushovertoken", "label": "App token"},
                {"key": "pushoveruserkey", "label": "User key"}]},
    {"id": "pushbullet", "label": "Pushbullet", "toggle": "pushbulletalert",
     "fields": [{"key": "pushbullettoken", "label": "Access token"}]},
    {"id": "slack", "label": "Slack", "toggle": "slackalert",
     "fields": [{"key": "slacktoken", "label": "Webhook / token"}]},
    {"id": "gotify", "label": "Gotify", "toggle": "gotifyalert",
     "fields": [{"key": "gotifywebhook", "label": "Server URL"},
                {"key": "gotifytoken", "label": "App token"}]},
    # Key names are LinuxGSM's own (lgsm/config-default/config-lgsm/*/_default.cfg), not ours — the
    # panel writes them straight into the server's config, so a name we invented would be written
    # and then silently ignored by every alert run. ntfy's server is exposed because self-hosting is
    # the common case; blank means LinuxGSM's own default of https://ntfy.sh. The token is only
    # needed for a reserved or private topic.
    {"id": "ntfy", "label": "ntfy", "toggle": "ntfyalert",
     "fields": [{"key": "ntfytopic", "label": "Topic"},
                {"key": "ntfyserver", "label": "Server (blank = ntfy.sh)"},
                {"key": "ntfytoken", "label": "Access token (optional)"}]},
    {"id": "ifttt", "label": "IFTTT", "toggle": "iftttalert",
     "fields": [{"key": "iftttmakerapi", "label": "Maker API key"},
                {"key": "iftttevent", "label": "Event name"}]},
]

# The game dropdown is built from LinuxGSM's own serverlist.csv (every supported
# game). For all entries the server name is exactly "{shortname}server", so the
# install just uses that — no per-game mapping needed.
_GAME_LIST_CACHE = {"games": None}


def game_os_unsupported(game_os, host_os):
    """True when LinuxGSM says this game tops out at an OLDER release than the host runs.

    Both are LinuxGSM's own slugs ("ubuntu-24.04"). Only the four games that declare an older
    release are ever affected — bf1942 and bfv (22.04), btl and onset (20.04) — but on a 24.04
    host those four fail every time, and nothing told the operator before the install did.

    Unknown or unparseable on either side answers False: a game whose OS we cannot read is not
    evidence of a problem, and hiding a game that would have worked is worse than letting it try.
    A game declaring a NEWER release than the host is left alone too — that is LinuxGSM being
    ahead of this box, not a refusal.
    """
    def _parse(slug):
        parts = (slug or "").strip().lower().split("-")
        if len(parts) != 2 or not parts[0]:
            return None
        try:
            return (parts[0], tuple(int(x) for x in parts[1].split(".")))
        except ValueError:
            return None
    g, h = _parse(game_os), _parse(host_os)
    if not g or not h or g[0] != h[0]:
        return False
    return g[1] < h[1]


def load_game_list():
    """All LinuxGSM-supported games, from LinuxGSM's own serverlist.csv.

    That file is fetched and cached rather than committed here — see lgsm_data — so a game
    LinuxGSM adds shows up without waiting for a panel release. An empty list means the data
    could not be had; `lgsm_data.status()` says why, and the install page surfaces it rather than
    rendering an empty menu.
    """
    if _GAME_LIST_CACHE["games"] is not None:
        return _GAME_LIST_CACHE["games"]
    games = []
    for row in lgsm_data.serverlist():
        sn = (row.get("shortname") or "").strip()
        name = (row.get("gamename") or "").strip()
        if sn and name:
            # LinuxGSM's serverlist declares the newest OS it supports each game on, and that
            # column was parsed and thrown away — so the picker offered every game on every host
            # and four of them could only ever fail at install time, with LinuxGSM's own
            # "not supported on Ubuntu 24.04.5" arriving minutes in. Carry it through; the caller
            # compares it against the host.
            games.append({"shortname": sn, "name": name,
                          "os": (row.get("os") or "").strip()})
    # Mark the games LinuxGSM tops out at an OLDER release than the rest of the catalogue. Only
    # four do, and the picker cannot know which host is about to be chosen — so state the game's
    # OWN limit rather than guess. That is true whatever the target, and it is the fact the
    # operator needs before spending an install on it.
    newest = max((row.get("os") or "" for row in games), default="")
    for row in games:
        row["legacy_os"] = (row.get("os") or "") if (row.get("os") and newest
                                                     and game_os_unsupported(row["os"], newest)) \
            else ""
    games.sort(key=lambda row: row["name"].lower())
    # Only memoise a real answer: caching [] would make one failed fetch permanent for the life
    # of the process, so a later retry (or the background warm) could never take effect.
    if games:
        _GAME_LIST_CACHE["games"] = games
    return games


_LGSM_NAME_MAP = {"data": None}


def lgsm_name_to_game_type(lgsm_name):
    """Map a LinuxGSM 'gameservername' (e.g. 'gmodserver') to the panel's game_type / shortname
    (e.g. 'gmod'), from LinuxGSM's serverlist. Used when importing servers discovered on a host.
    Returns None for a game the panel doesn't know."""
    if _LGSM_NAME_MAP["data"] is None:
        m = {}
        for row in lgsm_data.serverlist():
            gsn = (row.get("gameservername") or "").strip()
            sn = (row.get("shortname") or "").strip()
            if gsn and sn:
                m[gsn] = sn
        if m:                      # same reasoning as load_game_list: never memoise a failure
            _LGSM_NAME_MAP["data"] = m
        return m.get(lgsm_name)
    return _LGSM_NAME_MAP["data"].get(lgsm_name)

# ─── App Factory ──────────────────────────────────────────────


# Lightweight in-memory login throttle (single-process eventlet app). Blocks an IP
# after too many failed logins within the window — a basic brute-force speed bump.
_LOGIN_FAILS = {}
_LOGIN_FAILS_LOCK = threading.Lock()
# IPs whose rate-limit block we've already written to the audit log this window, so a client that
# keeps hammering after being blocked adds ONE "login_blocked" entry, not one per request.
_LOGIN_BLOCK_LOGGED = {}
LOGIN_MAX_FAILS = 8
LOGIN_WINDOW = 300  # seconds
# Notify when a SUPER ADMIN username is under a failed-login attack: >= this many fails against it
# within the window fires the "admin_bruteforce" alert, at most once per window per admin.
_ADMIN_BF_THRESHOLD = 5
_ADMIN_BF_NOTIFIED = {}   # admin username -> ts we last alerted (dedup)


def _prune_login_fails(now):
    """Drop IPs whose failures have all aged out of the window. Without this the map
    grows one entry per client IP that ever failed a login (a public login page gets
    hit by scanners from countless IPs), leaking memory. Call under _LOGIN_FAILS_LOCK."""
    for ip in [k for k, v in _LOGIN_FAILS.items() if not v or now - v[-1] >= LOGIN_WINDOW]:
        del _LOGIN_FAILS[ip]
    for ip in [k for k, t in _LOGIN_BLOCK_LOGGED.items() if now - t >= LOGIN_WINDOW]:
        del _LOGIN_BLOCK_LOGGED[ip]
    for u in [k for k, t in _ADMIN_BF_NOTIFIED.items() if now - t >= LOGIN_WINDOW]:
        del _ADMIN_BF_NOTIFIED[u]


def _maybe_alert_admin_bruteforce(who, ip, now):
    """Fire the admin_bruteforce notification when the ATTEMPTED username belongs to an existing
    super admin AND it has failed to log in enough times within the window. Once per window per
    admin. Best-effort — never breaks the login response."""
    try:
        if not who or who == "(blank)":
            return
        target = User.query.filter_by(username=who).first()
        if not target or not target.is_superadmin:
            return
        since = utcnow() - timedelta(seconds=LOGIN_WINDOW)
        fails = AuditLog.query.filter(AuditLog.action == "login_failed",
                                      AuditLog.username == who,
                                      AuditLog.timestamp >= since).count()
        if fails < _ADMIN_BF_THRESHOLD:
            return
        with _LOGIN_FAILS_LOCK:
            fire = (now - _ADMIN_BF_NOTIFIED.get(who, 0)) >= LOGIN_WINDOW
            if fire:
                _ADMIN_BF_NOTIFIED[who] = now
        if fire:
            notifications.notify(
                "admin_bruteforce", "Admin account under attack",
                "%d failed logins for super admin '%s' from %s in the last %d min."
                % (fails, who, ip, LOGIN_WINDOW // 60))
    except Exception:
        _log.debug("admin-bruteforce alert check failed", exc_info=True)


# A burst of this many NEW fail2ban bans in one watch cycle looks like an active attack wave.
_BAN_SPIKE_THRESHOLD = 3








# Terminal control noise that "fancy" game consoles write into their log. Minecraft/Paper run a
# JLine console that emits ANSI escapes (colour, and \x1b[K "erase to end of line" — which shows up
# as a literal "[K" once the ESC byte is dropped), carriage returns to redraw the input line, and a
# bare "> " prompt line after every message. Plain-text consoles (Source/CoD/GMod) have none of it.
_CONSOLE_PROMPT_RE = re.compile(r"^>\s*$")
# The prompt test runs on the line with its colour REMOVED. JLine wraps its prompt in SGR, and
# once render_colour started keeping those, "\x1b[0m> \x1b[0m" stopped matching "^>\s*$" — so
# every prompt line the panel has been dropping for a year would have come back at once.
_sgr_bare = re.compile(r"\x1b\[[0-9;]*m")


def _clean_console_text(text):
    """Console-log text rendered the way a terminal would show it, then with JLine's bare '> ' prompt
    lines dropped. A no-op for plain-text game consoles. Never drops a real message: only lines that
    are *just* the prompt are removed, so an echoed command like '> list' is kept."""
    if not text:
        return text
    return "\n".join(ln for ln in terminal.render_colour(text).split("\n")
                      if not _CONSOLE_PROMPT_RE.match(_sgr_bare.sub("", ln)))


def create_app():
    app = Flask(__name__)
    cfg = load_config()

    # One-time nudge for installs still sitting on the previous, longer session defaults
    # (12h idle / 14d remember) → the tighter 8h / 3d. Only touches values left at the old
    # default, so a deliberately-customized value is never overwritten. Runs once: after
    # the bump the condition is false, so it won't fire again.
    _cfg_changed = False
    if cfg.get("session_lifetime_hours") == 12:
        cfg["session_lifetime_hours"] = 8
        _cfg_changed = True
    if cfg.get("remember_days") == 14:
        cfg["remember_days"] = 3
        _cfg_changed = True
    if _cfg_changed:
        save_config(cfg)

    app.config["SECRET_KEY"] = get_secret_key()
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # Wait up to 15s for a locked SQLite DB instead of failing immediately with
    # "database is locked" — the eventlet workers can briefly contend on writes.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"timeout": 15}}
    app.config["SESSION_COOKIE_NAME"] = "lgpanel_session"
    # Idle session timeout (sliding — refreshed on each request). 8h by default so a
    # forgotten browser doesn't stay logged in overnight; configurable.
    app.config["PERMANENT_SESSION_LIFETIME"] = cfg.get("session_lifetime_hours", 8) * 3600

    # Cookie path must cover the mount point — always use root to be safe
    # since we don't know the final mount until after setup
    app.config["SESSION_COOKIE_PATH"] = "/"

    # Session-cookie hardening. HttpOnly keeps JS from reading it; Secure keeps it to
    # HTTPS (the panel is served over HTTPS via Tailscale Serve); SameSite=Lax stops a
    # cross-site page from sending the cookie on a POST, which mitigates CSRF on the
    # form endpoints (the JSON API additionally requires an application/json body).
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Secure defaults ON once the panel is REACHED over HTTPS — whether it terminates TLS
    # itself, or something in front does. Override with cookie_secure.
    #
    # This used to mirror _effective_https's Tailscale case and not its PROXY case, so the
    # deployment the README recommends — `trust_proxy: true` behind nginx/Caddy — issued the
    # session cookie and the 3-day remember-me token with no Secure flag, and both then travel in
    # cleartext on any http:// request to the same host (a typo'd link, the first visit before
    # HSTS pins, a downgrade). A captured remember token is a working login for remember_days.
    # _security_headers already emits HSTS on those requests, so the rest of the code knew.
    #
    # site_domain is NOT evidence of TLS — it is a hostname typed into the setup wizard — and
    # counting it was the mirror mistake: `use_https: false` plus a domain marked the cookies
    # Secure while the panel served plain HTTP, which a browser answers by dropping them. The
    # password is right, the cookie never comes back, and / bounces to /login forever.
    app.config["SESSION_COOKIE_SECURE"] = cfg.get("cookie_secure", _https_ready(cfg))

    # "Remember me" cookie (flask-login). Capped at the configured remember_days (default 3,
    # max 90 — see settings.html) instead of
    # flask-login's 365-day default — a stolen remember-token shouldn't be valid for a
    # year — and give it the same hardening as the session cookie.
    app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=int(cfg.get("remember_days", 3)))
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]

    # flask-login session protection. "strong" rejects a session cookie replayed from a
    # different client (IP+User-Agent binding); set "basic" if users roam between IPs a
    # lot, or None to disable. Cookie theft is also recoverable via "sign out everywhere".
    app.config["SESSION_PROTECTION"] = cfg.get("session_protection", "strong")


    # Store mount prefix in app config so templates can access it
    app.config["_MOUNT_PREFIX"] = cfg.get("tailscale_mount", "/")

    # Initialize extensions
    init_auth(app)
    init_db(app)
    # One-time: drop the removed global notifications master switch from the stored config
    # (preserves a muted state via the channel toggles). No-op once the key is gone.
    try:
        notifications.migrate_master_switch()
    except Exception:
        _log.debug("notifications master-switch migration skipped", exc_info=True)
    # One-time: strip a stored "super_admin" group permission from when it was grantable. It is no
    # longer consulted anywhere, so this grants and revokes nothing — it clears a string the Groups
    # UI can no longer show or untick, and which a future has_permission(user, SUPER_ADMIN) would
    # otherwise silently start honouring again.
    try:
        with app.app_context():
            _stripped = strip_legacy_superadmin_grants()
        if _stripped:
            _log.info("removed the legacy super_admin permission from %d group(s)", _stripped)
    except Exception:
        _log.debug("legacy super_admin cleanup skipped", exc_info=True)
    # Lock down data/ (0700) and the sensitive files inside (DB, keys, config → 0600) now that the
    # DB exists — keeps them unreachable by other local users. Idempotent; tightens old installs too.
    harden_data_permissions()
    _setup_auth_log()   # failed logins → data/auth.log for the optional fail2ban jail

    # CSRF protection for every state-changing request. Forms carry a hidden token
    # (auto-injected in base.html); the JSON API sends it as an X-CSRFToken header
    # (a global fetch wrapper adds it). Defense-in-depth on top of the SameSite=Lax
    # session cookie. Tests disable it via WTF_CSRF_ENABLED=False.
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)  # token valid for the session
    # Protect per-request (below) instead of automatically, so we can skip CSRF for API-token
    # (Bearer) requests — those carry no session cookie, so CSRF (a cookie-riding attack) can't
    # apply, and an invalid token is still rejected by @login_required.
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    csrf = CSRFProtect(app)

    @app.before_request
    def _csrf_protect_unless_bearer():
        # csrf.protect() (called directly) does NOT itself honour WTF_CSRF_ENABLED — that check
        # normally lives in flask-wtf's auto before_request, which WTF_CSRF_CHECK_DEFAULT=False turns
        # off — so replicate it here (tests set WTF_CSRF_ENABLED=False).
        if not app.config.get("WTF_CSRF_ENABLED", True):
            return
        # The Bearer exemption is justified by "an API-token request carries no cookie, so there is
        # nothing for a cross-site page to ride" — so TEST THAT, rather than testing only for the
        # header. Exempting on the header alone meant a request that sent BOTH a Bearer header and
        # a session cookie skipped CSRF while flask-login authenticated it from the cookie: the
        # stated reason no longer held, and the code could not tell. Not reachable from a browser
        # today (a custom header forces a CORS preflight, and the SameSite=Lax cookie is not sent
        # cross-site anyway), which is why this is a narrowing and not a patch — but an exemption
        # should rest on the condition it claims.
        # EVERY cookie flask-login would authenticate from, not just the session one. The
        # remember cookie is the other: flask-login's _load_user tries it BEFORE the request
        # loader, so a login whose session cookie has expired is still authenticated by it — and
        # such a request is not "cookie-less". Measured: drop only the session cookie, keep
        # remember_token, POST /logout with no CSRF token and an INVALID Bearer header, and the
        # UserSession row was deleted. For up to remember_days that made every mutating endpoint
        # reachable cross-site by adding one header. A custom header does force a CORS preflight
        # the panel does not answer, which is the same reasoning the comment above already rates
        # as not good enough on its own: an exemption should rest on the condition it claims.
        _auth_cookies = (app.config["SESSION_COOKIE_NAME"],
                         app.config.get("REMEMBER_COOKIE_NAME", "remember_token"))
        if (request.headers.get("Authorization", "").startswith("Bearer ")
                and not any(request.cookies.get(_c) for _c in _auth_cookies)):
            return   # genuinely cookie-less API-token request: CSRF cannot apply
        csrf.protect()   # session/cookie request: full CSRF enforcement (no-op on safe methods)

    # ── An unhandled exception on a JSON endpoint must answer JSON ───────────────────────────
    # There was no errorhandler anywhere in this project, so an exception in a route came back as
    # Werkzeug's HTML 500 page. Every mutating endpoint here is called with
    # `.then(r => r.json())`, which then fails to parse it — so the user sees a generic "failed"
    # instead of the reason, and the panel log fills with tracebacks that look like the panel is
    # broken. The ordinary trigger is not a bug in the panel at all: run_privileged raises
    # ConnectionError for a host that is down and VerbError for an argument a verb refuses, and
    # nothing between the ops layer and the browser catches either.
    #
    # Only requests that ASKED for JSON are converted. Anything else re-raises, so a page render
    # keeps whatever behaviour it has today (including propagating under TESTING).
    @app.errorhandler(Exception)
    def _json_for_api_errors(e):
        wants_json = (request.path.startswith("/api/")
                      or request.headers.get("X-Requested-With") == "XMLHttpRequest")
        if not wants_json:
            # RETURN an HTTPException, do not re-raise it: Flask renders a returned one as its
            # normal page, while a raised one propagates — and under TESTING that means
            # `GET /logout` (405) stops being a 405 and becomes a crash in the caller.
            if isinstance(e, HTTPException):
                return e
            raise e             # a page render keeps whatever behaviour it has today
        if isinstance(e, HTTPException):
            # abort(404) from get_or_404, a 405, flask-wtf's CSRF 400 — all of them rendered
            # Werkzeug's HTML page, which is the same unparseable body as the 500 below. 401 is
            # the exception: panel.js's session-expired handling reads the status and the
            # X-Auth-Required header off it, and that contract is not ours to reshape here.
            if e.code == 401:
                return e
            return jsonify({"success": False,
                            "message": e.description or e.name}), (e.code or 500)
        # The endpoint name taken from app.view_functions, not off the request. Werkzeug only ever
        # matches a request to one of the app's own rules, so the two are the same string — but
        # py/log-injection traces every value reached through `request`, and this repo's answer to
        # a gate that will not be convinced is to give it nothing to trace rather than to dismiss
        # it (see the note in notifications._post). The string logged is now literally one of the
        # app's own dict keys.
        _rule = request.url_rule
        _ep = next((n for n in app.view_functions
                    if _rule is not None and n == _rule.endpoint), "?")
        _log.exception("unhandled error serving %s", _ep)
        return jsonify({"success": False,
                        "message": "Something went wrong — see the panel log."}), 500

    # Cap the total request body so an oversized upload can't be spooled to disk / read into memory
    # before the per-file size check runs. Werkzeug already bounds in-memory form fields, but NOT
    # multipart file parts; this rejects anything past the file limit (plus a little envelope
    # headroom) with a 413 up front. Keep it in step with _MAX_UPLOAD_BYTES.
    app.config["MAX_CONTENT_LENGTH"] = _MAX_UPLOAD_BYTES + 2 * 1024 * 1024

    # A fresh CSP nonce per request. Every one of our own <script> blocks carries it
    # (nonce="{{ csp_nonce }}"), so the Content-Security-Policy can drop 'unsafe-inline' from
    # script-src — an injected <script> without the (unguessable, per-request) nonce won't run.
    # Registered before check_setup so it's set even on the redirect-to-setup response.
    @app.before_request
    def _make_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    # ── Forced password change ───────────────────────────────────────────────────────────────
    # An account whose password was set by an ADMIN (created, or reset) holds a credential two
    # people know, that has been read off a screen and relayed through chat or spoken aloud. Until
    # the holder replaces it with one only they know, it is a handover token, not a password — so
    # the account can do exactly one thing: replace it.
    #
    # A before_request, not a decorator on each view. A decorator is a list of places to remember,
    # and the one that gets forgotten is the hole: 200-odd routes, an API that authenticates with a
    # bearer token, and any route added later would each have to opt in. This opts everything OUT by
    # default and names the handful that must stay reachable.
    _PW_GATE_OPEN = frozenset((
        "force_password_change",     # the page itself
        "account_change_password",   # …and the form it posts to
        "logout",                    # never trap someone in a session they want to leave
        "set_language", "api_i18n_catalog",   # the page's own language switcher
        "healthz", "static",
    ))

    @app.before_request
    def _require_password_change():
        if not getattr(current_user, "is_authenticated", False):
            return None
        if not getattr(current_user, "must_change_password", False):
            return None
        if (request.endpoint or "") in _PW_GATE_OPEN:
            return None
        # An in-page fetch or an API client cannot be redirected — it would follow the redirect and
        # try to read an HTML page as JSON. Same contract as the expired-session 401: a status the
        # caller can act on, plus the header the page's fetch wrapper watches for.
        from panel.security.auth import _denial_wants_json
        if _denial_wants_json():
            resp = jsonify({"success": False, "error": "password_change_required",
                            "message": "Set your own password before using the panel."})
            resp.status_code = 403
            resp.headers["X-Password-Change-Required"] = "1"
            return resp
        return redirect(url_for("force_password_change"))

    # ── Security response headers ──
    # STRICT script-src: 'self' + a per-request nonce, NO 'unsafe-inline'. Every one of our own
    # <script> blocks carries nonce="{{ csp_nonce }}"; all event handlers are attached via the
    # delegated dispatcher in base.html (data-action), never inline on* attributes. So an injected
    # <script>/handler without the nonce simply won't execute.
    # style-src keeps 'unsafe-inline': the UI uses inline style="…" attributes throughout, and CSP
    # can't nonce inline STYLE attributes (only <style> blocks). Style injection is far lower risk
    # than script injection, so this is the standard, deliberate split.
    # All assets are self-hosted, so no external origins are allowed.
    def _csp():
        nonce = getattr(g, "csp_nonce", "")
        return (
            "default-src 'self'; "
            "script-src 'self' 'nonce-%s'; " % nonce +
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; base-uri 'self'; object-src 'none'"
        )

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        # The panel uses none of these powerful browser features, so deny them outright —
        # a defence-in-depth limit on what any injected/compromised script could reach for.
        resp.headers.setdefault("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), usb=(), "
                                "payment=(), interest-cohort=()")
        resp.headers.setdefault("Content-Security-Policy", _csp())
        # Keep the admin panel out of search engines. This header covers EVERY
        # response (crawlers can't miss it), and /robots.txt asks nicely too — a
        # private management UI has no business being indexed.
        resp.headers.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive")
        # Don't advertise the framework/version to scanners/fingerprinters (the WSGI
        # server would otherwise send "Werkzeug/x Python/y"). Override, not setdefault.
        resp.headers["Server"] = "LinuxGSM Panel"
        # Advertise HSTS only for HTTPS backed by a TRUSTED cert — via a proxy that sets
        # X-Forwarded-Proto, or Tailscale. NOT for our own self-signed TLS: HSTS turns the
        # one-time "not private" warning into a hard, un-clickable-through block on a named
        # host, which would lock the user out of their own panel.
        self_tls = _effective_https(cfg)
        if (request.headers.get("X-Forwarded-Proto", "") == "https"
                or (request.is_secure and not self_tls)):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    # Compressible content types worth gzipping (skip already-compressed images/fonts/archives).
    _GZIP_TYPES = {"text/html", "text/css", "text/plain", "text/javascript",
                   "application/javascript", "application/json", "image/svg+xml",
                   "application/manifest+json", "application/xml"}
    _static_prefix = (app.static_url_path or "/static") + "/"

    @app.after_request
    def _compress_and_cache(resp):
        # 1) Cache the vendored static assets (bootstrap/icons/socketio). They ship WITH the panel
        #    version, so a long cache is safe — a panel update restarts the process and the user
        #    reloads. This stops the browser revalidating ~600KB of assets on every page load.
        try:
            if request.path.startswith(_static_prefix):
                resp.headers["Cache-Control"] = "public, max-age=604800"   # 1 week
            elif "Cache-Control" not in resp.headers:
                # 1b) Every signed-in page is private and must be revalidated before it is shown
                #     again. Without this, Back (or reopening the tab) after the cookie expired
                #     could paint the old dashboard from the disk cache — fully rendered and
                #     completely dead, so every button on it failed instead of taking you to the
                #     login screen. `no-cache` means "ask first", and the ask is what redirects.
                #     Deliberately NOT `no-store`, which would also evict the page from the
                #     back/forward cache and undo the bfcache work in panel.js; the JS side covers
                #     a bfcache restore by pinging /api/auth/ping on pageshow.
                resp.headers["Cache-Control"] = "no-cache, private"
        except Exception:  # nosec B110 - a cache header is an optimisation, never correctness:
            pass           # if request.path is unavailable the response still goes out, unchanged.
        # 2) gzip text responses (HTML ~10x, JSON ~17x smaller) when the client accepts it — the
        #    biggest win for page loads and the every-few-seconds status polls, especially remote.
        try:
            if ("gzip" in request.headers.get("Accept-Encoding", "").lower()
                    and resp.status_code == 200
                    and "Content-Encoding" not in resp.headers
                    and (resp.content_type or "").split(";")[0].strip() in _GZIP_TYPES):
                resp.direct_passthrough = False
                data = resp.get_data()
                if len(data) >= 500:   # not worth the CPU/overhead below this
                    # Level 4, not the default 6: profiling showed 6 shaves only ~7% more bytes
                    # off our HTML/JSON but costs ~50% more CPU per response. Since responses are
                    # CPU-serialized on eventlet's single hub and the byte difference is trivial on
                    # the wire, 4 is the better balance (near-max compression, much less CPU).
                    resp.set_data(_gzip.compress(data, 4))
                    resp.headers["Content-Encoding"] = "gzip"
                    _vary = resp.headers.get("Vary")
                    if not _vary:
                        resp.headers["Vary"] = "Accept-Encoding"
                    elif "accept-encoding" not in _vary.lower():
                        resp.headers["Vary"] = _vary + ", Accept-Encoding"
        except Exception:
            app.logger.debug("response gzip skipped", exc_info=True)
        return resp

    # One-time: encrypt any legacy plaintext secrets/PII already in the DB
    # (remote SSH credentials, and user email addresses).
    with app.app_context():
        try:
            from panel.db.models import RemoteServer, User
            changed = False
            for r in RemoteServer.query.all():
                if r.auth_credential and not is_encrypted(r.auth_credential) \
                        and r.auth_method in ("password", "key"):
                    r.auth_credential = encrypt_secret(r.auth_credential)
                    changed = True
            for u in User.query.all():
                if u.email and not is_encrypted(u.email):
                    u.email = encrypt_secret(u.email)
                    changed = True
            if changed:
                db.session.commit()
        except Exception:
            db.session.rollback()

    # One-time (idempotent): encrypt the columns that became EncryptedString — hostnames, SSH
    # usernames, public IPs, pinned host keys, and per-session IP/user-agent — so an existing
    # install stops leaving a map of its machines in plain sight inside panel.db.
    with app.app_context():
        try:
            from panel.db.models import encrypt_at_rest_columns
            _touched = encrypt_at_rest_columns()
            if _touched:
                app.logger.info("encrypted at-rest columns on %d row(s)", _touched)
        except Exception:
            db.session.rollback()
            app.logger.exception("at-rest column encryption migration failed")

    # Optional audit-log retention. Off by default (keep everything — audit history
    # shouldn't vanish by surprise). Set "audit_log_retention_days" in config.json to a
    # positive number to prune older entries on startup so the table can't grow forever.
    with app.app_context():
        try:
            days = int(cfg.get("audit_log_retention_days", 0) or 0)
            if days > 0:
                from panel.db.models import AuditLog
                cutoff = utcnow() - timedelta(days=days)
                deleted = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
                if deleted:
                    db.session.commit()
                    # A plain DELETE leaves the freed pages in the file. After a
                    # meaningful prune, reclaim the space + refresh stats so enabling
                    # retention actually shrinks the DB (cheap on a small file).
                    if deleted >= 100:
                        from panel.db.models import optimize_database
                        optimize_database()
        except Exception:
            db.session.rollback()

    # Audit IPs age out into network prefixes. Separate from audit_log_retention_days above,
    # which DELETES rows: the history is the reason the log exists, so the default reduces the
    # identifying part and keeps the entry rather than discarding both.
    with app.app_context():
        try:
            from panel.db.models import anonymise_audit_ips
            _anon = anonymise_audit_ips(cfg.get("audit_ip_retention_days", 90))
            if _anon:
                app.logger.info("reduced the IP on %d audit entries to a network prefix", _anon)
        except Exception:
            db.session.rollback()
            app.logger.exception("audit IP anonymisation failed")

    # Register blueprints/routes
    register_routes(app)
    register_template_filters(app)
    register_context_processors(app)

    # Always apply the prefix middleware. It resolves the mount per-request from the
    # X-Forwarded-Prefix header (sent by Tailscale Serve) or the config, and is a no-op
    # when there is no prefix. Applying it unconditionally means a sub-path mount like
    # /lgsm works immediately — including during first-run setup — without needing a
    # restart after the config is written.
    app.wsgi_app = PrefixMiddleware(app.wsgi_app)

    # Behind a reverse proxy (Caddy/nginx/Cloudflare Tunnel), trust ONE hop of
    # X-Forwarded-* so request.is_secure/scheme + client IP reflect the real client.
    # Off by default — only enable when actually behind a trusted proxy, or these
    # headers become spoofable. (client_ip() also only trusts XFF from loopback.)
    # Recorded in app.config so client_ip() can ask it without re-reading config.json on every
    # request — it has to know, because ProxyFix below rewrites remote_addr from the very header
    # client_ip is deciding whether to trust.
    app.config["_TRUST_PROXY"] = bool(cfg.get("trust_proxy"))
    if cfg.get("trust_proxy"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    return app


# ─── Template Filters ─────────────────────────────────────────

def register_template_filters(app):
    @app.template_filter("datetime")
    def format_datetime(dt):
        # Timestamps are stored as naive UTC. Emit the UTC value (ISO with a trailing Z)
        # plus a readable UTC fallback, wrapped so the browser can render it in the
        # viewer's own timezone (see base.html localizeTimes()). No user input, so the
        # Markup is safe.
        if not dt:
            return "Never"
        iso = dt.replace(microsecond=0).isoformat() + "Z"
        return Markup(  # nosec B704 - both interpolations are datetime-derived, never user input
            '<span class="localtime" data-utc="%s">%s UTC</span>'
            % (iso, dt.strftime("%Y-%m-%d %H:%M:%S")))

    @app.template_filter("permlabel")
    def permission_label(perm):
        return ALL_PERMISSIONS.get(perm, perm)


# ─── Context Processors ───────────────────────────────────────









def _new_user_language(cfg, known):
    """The UI language a newly-created account starts in: whatever Settings → Localization is set
    to, or English.

    The setting is always a concrete language code. It used to allow a blank "creator's language"
    value, which was both confusing to read on the settings page and (before it was fixed) did
    nothing at all — so the option is gone and a blank left over from an older install simply reads
    as English. Validated against the supported-language map, so a language retired in a later
    version cannot be assigned. Pure, for testability."""
    # str() first: config.json is a file a human can hand-edit, and a non-string here would raise
    # on .strip() while creating a user — a 500 on account creation over a cosmetic setting.
    configured = str((cfg or {}).get("default_language") or "").strip()
    return configured if configured in known else "en"


def _current_lang():
    """Active UI language: the logged-in user's saved preference, else the session choice, else en."""
    lang = None
    try:
        if getattr(current_user, "is_authenticated", False):
            lang = getattr(current_user, "language", None)
    except Exception:
        lang = None
    if not lang:
        try:
            lang = session.get("lang")
        except Exception:
            lang = None
    return i18n.normalize_lang(lang)


# Content hash per static file, computed once per process. Cheap enough to do lazily and it must
# never be a per-request stat: these are on every page render.
_ASSET_HASHES = {}


def _asset_url(app, filename):
    """url_for('static', ...) with a content hash appended.

    The panel serves /static with `Cache-Control: public, max-age=604800`, so without this a
    browser would keep a week-old panel.js after an update. With it the URL changes the moment the
    bytes do, and not a moment sooner — which is what makes a long cache safe rather than a trap."""
    ver = _ASSET_HASHES.get(filename)
    if ver is None:
        try:
            import hashlib
            with open(os.path.join(app.static_folder, filename), "rb") as fh:
                ver = hashlib.sha256(fh.read()).hexdigest()[:12]
        except OSError:
            ver = ""      # missing file: still emit a usable URL and let the 404 speak for itself
        _ASSET_HASHES[filename] = ver
    url = url_for("static", filename=filename)
    return "%s?v=%s" % (url, ver) if ver else url


def register_context_processors(app):
    app.jinja_env.globals["asset_url"] = lambda filename: _asset_url(app, filename)
    # RemoteServer.is_online defaults to False, so between a fresh install (or a panel restart)
    # and the first monitor pass, EVERY host reads as unreachable although nothing has been asked
    # yet. Rendering that as "Unreachable" states something false; "Checking…" states what is
    # actually true. _monitor_state["remotes"] holds an entry only once a host has really been
    # probed, so it is the exact signal — not a proxy like last_seen, which stays null for a host
    # that has been probed and genuinely never answered.
    app.jinja_env.globals["host_probed"] = lambda rid: rid in _monitor_state["remotes"]

    @app.context_processor
    def inject_globals():
        cfg = load_config()
        # Get Tailscale info for URL injection
        tailscale_url = None
        try:
            ts_info = ts.get_tailscale_info()
            if ts_info.dns_name:
                tailscale_url = f"https://{ts_info.dns_name}"
        except Exception:
            _log.debug("inject_globals: ignored non-fatal error", exc_info=True)
        # Non-local remotes for the SYSTEM nav (one management link per remote VPS).
        nav_remotes = []
        try:
            if getattr(current_user, "is_authenticated", False) and (
                current_user.is_superadmin or "manage_remotes" in get_user_permissions(current_user)
            ):
                nav_remotes = (RemoteServer.query.filter_by(is_local=False)
                               .order_by(RemoteServer.name).all())
        except Exception:
            nav_remotes = []
        # The panel host's own remote-row id, so any page can render its "reboot required" banner
        # (the panel host is just a remote with is_local=True). Only for users who could act on it.
        local_remote_id = None
        try:
            if getattr(current_user, "is_authenticated", False) and (
                current_user.is_superadmin or "manage_remotes" in get_user_permissions(current_user)
            ):
                _lr = RemoteServer.query.filter_by(is_local=True).first()
                local_remote_id = _lr.id if _lr else None
        except Exception:
            local_remote_id = None
        lang = _current_lang()
        return {
            "site_title": cfg.get("site_title", "LinuxGSM Panel"),
            "login_tagline": (cfg.get("login_tagline") or "").strip(),
            "accent_color": _valid_hex_color(cfg.get("accent_color")),
            # Templates ask for their own panel order: panel_layout(region, default_keys) ->
            # (visible, hidden). Passed as a callable so a page declares the panels IT emitted and
            # nothing stored can add one — see _panel_layout.
            "panel_layout": (lambda region, keys: _panel_layout(
                _effective_prefs(current_user, cfg), region, keys)),
            # Whether a superadmin has published a house layout — the Account page's controls need it,
            # and it is rendered from two routes, so it belongs here rather than in either of them.
            "install_default_layout": bool(cfg.get("default_ui_prefs")),
            "current_year": utcnow().year,
            "tailscale_url": tailscale_url,
            "mount_prefix": app.config.get("_MOUNT_PREFIX", "/"),
            "panel_version": PANEL_VERSION,
            "panel_commit": PANEL_COMMIT,
            "panel_repo_url": PANEL_REPO_URL,
            "csp_nonce": getattr(g, "csp_nonce", ""),
            "nav_remotes": nav_remotes,
            "local_remote_id": local_remote_id,
            # Whether to render the signed-in chrome — sidebar, topbar, nag banners and the
            # background pollers that come with them. Normally "are they signed in", but an account
            # that still has to replace a handed-over password is signed in and cannot use any of
            # it: every one of those links and polls is refused by the gate in create_app. Deciding
            # it HERE, once, means a page added to that chrome later is covered without anyone
            # remembering to cover it.
            "show_app_chrome": (getattr(current_user, "is_authenticated", False)
                                and not getattr(current_user, "must_change_password", False)),
            # i18n: `t()` translates a string for the active language (falls back to English);
            # the catalog is also handed to the browser so client JS can translate too.
            "t": lambda s: i18n.translate(lang, s),
            "current_lang": lang,
            "languages": i18n.LANGUAGES,
            "i18n_catalog": i18n.catalog(lang),
            "has_permission": lambda perm: (
                current_user.is_superadmin
                or perm in get_user_permissions(current_user)
            ) if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated else False,
        }


# ─── Routes ───────────────────────────────────────────────────


# ─── Route helpers ────────────────────────────────────────────────────────────────────
# These were defined INSIDE register_routes(), which made them closures over its scope and
# meant no view using one could be moved out of that 6,570-line function. None of them
# actually needed anything from that scope — they are plain helpers — so they live at module
# level now. Behaviour is unchanged: a view calling one resolves it as a global instead of a
# closure cell, which is the same function. Hoisting them is the precondition for splitting
# the route table into modules, and it makes them directly testable and stubbable besides.

def resolve_free_port(remote, remote_id, desired, game_type):
    """Find a free contiguous port block at/after `desired` on a remote for a `game_type`
    server. A block of _port_span(game_type) ports must clear (a) the ports other panel
    game servers on this remote reserve — each per its own game's span — (b) whatever is
    actually listening on the host right now, and (c) the SourceTV/client ports the panel
    configured on this remote's valve servers, which no span covers and which a stopped server
    still owns. Returns (start_port, changed), or (None, False)
    when no free block exists near `desired` — see _first_free_block on why that is not a port.

    The span makes the increment game-correct: single-port games (most, incl. Call of Duty and
    Source) pack sequentially (28960, 28961, …) instead of wastefully skipping every other
    port, while multi-port games (Rust, Valheim, …) still reserve their whole adjacent block."""
    span = _port_span(game_type)
    # Whatever is currently listening on the host (cached scan) — covers running servers'
    # FULL real footprint (game + query + rcon + …) and any non-panel service, so we never
    # land on one even if a game's span table entry is imperfect.
    # `or ()`: None means the scan failed. Treating that as 'no ports occupied' can suggest
    # a port that is actually taken — the install then fails with a clear error, which is
    # the same outcome this had before the scanner learned to say 'I could not read'.
    occupied = set(_remote_listening_ports(remote) or ())
    # Plus every panel server's reserved block (covers STOPPED servers, which aren't listening) —
    # AND every valve sibling's configured SourceTV/client ports, which are reserved for exactly
    # the same reason and were missing here. See _add_sibling_ports for what that cost.
    _add_sibling_ports(occupied, remote, remote_id)
    p = _first_free_block(desired, span, occupied)
    if p is None:
        return None, False      # nothing free nearby — the caller must refuse, not guess
    return p, (p != desired)

# ── Setup Wizard ────────────────────────────────────────
def is_setup_complete():
    """Check if setup wizard has been completed."""
    state = SetupState.query.filter_by(complete=True).first()
    cfg = load_config()
    return state is not None and cfg.get("setup_complete", False)

# ── Setup-only Tailscale endpoints ─────────────────────────
# No login exists yet during setup, so these are unauthenticated BUT usable ONLY
# while setup is unfinished (they're a no-op/forbidden once complete, same as the
# wizard itself). They operate on THIS host only.
def _setup_open():
    # The SAME DB-row-only lock the wizard uses, and for the same reason — see the long
    # comment on setup_wizard() above, which describes this exact failure and then only
    # defended /setup with it.
    #
    # These four were gated on `not is_setup_complete()`, which is (DB row AND config flag).
    # The config half fails OPEN: load_config() swallows JSONDecodeError/OSError and returns
    # DEFAULT_CONFIG, where setup_complete is False. So on a fully configured install, a
    # data/config.json that was deleted, truncated by a full disk, or hand-edited into invalid
    # JSON made is_setup_complete() False and reopened all four to unauthenticated callers:
    # /install runs the Tailscale installer as root; /up returns an auth URL that joins THIS
    # HOST to whoever called it, with Tailscale SSH enabled; /serve rewrites bind_host and
    # site_domain. A missing config file should degrade the panel, not hand it over.
    #
    # state.complete is the one signal that is false for the whole wizard and true only once
    # it has finished, and it lives in the DB rather than in a file that falls back to
    # defaults. Gating on it is strictly more restrictive than what was here: during a genuine
    # first run no completed row exists, so the wizard's own endpoints behave identically.
    return SetupState.query.filter_by(complete=True).first() is None

# ── Account / Two-factor auth ───────────────────────────
def _qr_svg(data):
    """Render `data` as an inline SVG QR code (no PIL needed)."""
    import io
    import qrcode
    import qrcode.image.svg
    qr = qrcode.QRCode(box_size=9, border=2, image_factory=qrcode.image.svg.SvgPathImage)
    qr.add_data(data)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image().save(buf)
    return buf.getvalue().decode()

def _tag_json(tag):
    return {"id": tag.id, "name": tag.name, "color": tag.color or "", "notify": bool(tag.notify),
            "server_ids": sorted(gs.id for gs in tag.servers)}

def _apply_mod_restart(gs, remote):
    """A mod install/remove/update only takes effect after the server restarts — but we NEVER
    restart automatically. Auto-restarting would disconnect whoever's playing out from under the
    admin, so instead we just report whether a manual restart is needed and let them press
    'Restart now' when they're ready. A stopped server needs nothing (the change loads on next
    start). Returns (state, message) with state in {'needed','idle'}."""
    try:
        status = get_server_status(remote, gs)
    except Exception:
        status = "unknown"
    if status == "offline":
        if gs.restart_pending:              # clear any stale flag; nothing auto-restarts it now
            gs.restart_pending = False
            db.session.commit()
        return "idle", "The server is stopped — the change will load when you next start it."
    # Running: a restart is needed to load the change, but we do NOT do it or queue it — the admin
    # decides. (We deliberately don't set restart_pending, so the empty-ticker won't restart it
    # either — no surprise restarts from installing a mod.)
    return "needed", ("Restart the server to load the change — use Restart now when you're ready "
                      "(nobody is disconnected until you do).")

def _selected_remotes(server_ids):
    """Resolve submitted remote ids to RemoteServer rows, skipping anything
    malformed or unknown. A group grants access per *remote* (host), which
    covers every game server on it — see auth.can_access_server."""
    out = []
    seen = set()
    for sid in server_ids:
        try:
            rid = int(sid)
        except (TypeError, ValueError):
            continue
        if rid in seen:
            continue
        rs = db.session.get(RemoteServer, rid)
        if rs:
            seen.add(rid)
            out.append(rs)
    return out

def _selected_game_servers(ids):
    """Resolve submitted game-server ids to GameServer rows (individual per-server grants,
    finer than the whole-host grants from _selected_remotes). Skips malformed/unknown ids."""
    out = []
    seen = set()
    for sid in ids:
        try:
            gid = int(sid)
        except (TypeError, ValueError):
            continue
        if gid in seen:
            continue
        g = db.session.get(GameServer, gid)
        if g:
            seen.add(gid)
            out.append(g)
    return out

def _custom_cmd_form(cmd=None):
    """Read + validate the custom-command form. Returns (fields, error). `fields` is a dict
    ready to assign onto a CustomCommand; `error` is a user-facing string or None."""
    name = (request.form.get("name") or "").strip()
    template = (request.form.get("command_template") or "").strip()
    arg_label = (request.form.get("argument_label") or "").strip()
    arg_pattern = (request.form.get("argument_pattern") or "").strip()
    # Scope arrives as a single "<type>|<value>" field (e.g. "all|", "engine|idtech3", "game|cod2").
    scope_raw = (request.form.get("scope") or "all").strip()
    scope_type, _, scope_value = scope_raw.partition("|")
    scope_type = scope_type.strip()
    scope_value = scope_value.strip()
    enabled = request.form.get("enabled") is not None
    if not name or not template:
        return None, "A label and a command template are required."
    if template.count(CUSTOM_ARG_PLACEHOLDER) > 1:
        return None, "The template may contain at most one {} placeholder."
    # The template is sent to tmux as a console line — forbid control chars / newlines so it
    # can't smuggle a second keystroke sequence. Normal console punctuation is allowed.
    if any(ord(c) < 32 for c in template):
        return None, "The command template can't contain control characters or newlines."
    if scope_type not in ("all", "engine", "game"):
        scope_type = "all"
    if scope_type == "engine" and scope_value not in _CUSTOM_CMD_ENGINES:
        return None, "Pick a valid engine for the engine scope."
    if scope_type == "game" and scope_value not in {g["shortname"] for g in load_game_list()}:
        return None, "Pick a valid game for the game scope."
    if scope_type == "all":
        scope_value = ""
    # A custom pattern must compile; otherwise fall back to the safe default (blank stores default).
    if arg_pattern:
        try:
            re.compile(arg_pattern)
        except re.error:
            return None, "The argument validation pattern isn't a valid regular expression."
    # ...and it must FIT, checked here rather than by slicing it into the column below. The
    # pattern was compiled in full and then stored as arg_pattern[:200], so a longer one was
    # validated as one regex and saved as a different one. A cut does not always break a regex —
    # an alternation sliced after a `|` leaves a trailing empty branch that matches ANYTHING — so
    # the failure mode is a validation rule that silently accepts more than the superadmin who
    # wrote it intended, for everyone allowed to run the command. Refuse instead of truncating.
    if len(arg_pattern) > 200:
        return None, ("The argument validation pattern is too long (%d characters, limit 200). "
                      "Shorten it — truncating it here could silently widen what it accepts."
                      % len(arg_pattern))
    # The template is the command itself; a cut changes what runs (a lost closing quote, a lost
    # argument). Same reasoning, same answer.
    if len(template) > 500:
        return None, ("The command template is too long (%d characters, limit 500)."
                      % len(template))
    return {"name": name[:80], "command_template": template,
            "argument_label": arg_label[:80], "argument_pattern": arg_pattern,
            "scope_type": scope_type, "scope_value": scope_value[:64],
            "enabled": enabled}, None

def _assign_command_groups(cmd):
    """Set which groups may run this command from the submitted checkboxes."""
    ids = set()
    for gid in request.form.getlist("groups"):
        try:
            ids.add(int(gid))
        except (TypeError, ValueError):
            continue
    cmd.groups = Group.query.filter(Group.id.in_(list(ids))).all() if ids else []

# ── Security tab (panel host): fail2ban bans, recent security events, raw logs ──
def _maybe_set_threshold(body):
    """If the request carries a 'threshold', validate + persist it. Returns the effective value."""
    if body.get("threshold") is not None:
        try:
            val = max(1, min(int(body.get("threshold")), 100000))
            update_config(lambda cfg: cfg.update({"autoblock_threshold": val}))
            log_action(current_user, "autoblock_threshold", target="all hosts", detail="%d attempts / 7d" % val)
        except (TypeError, ValueError):
            _log.debug("ignoring a non-numeric autoblock threshold", exc_info=True)
    return _autoblock_threshold()

def _find_game_backup(gs, name):
    """Return the backup dict whose name matches `name` from the server's real backup list, or
    None. Validating against the listing (not building a path from user input) keeps this
    path-injection safe."""
    listing = list_game_backups(gs.remote, gs.short_name)
    # None is "the host could not be READ", which list_game_backups was deliberately taught to say
    # apart from [] ("this server has no backups"). Iterating it raised TypeError: on the download
    # route — a plain navigation, so the JSON error handler re-raises — that was Werkzeug's HTML
    # 500 page, and on delete the generic "Something went wrong". Collapsing it into the callers'
    # falsy check would be worse still: both answer "Backup not found." / 404, which tells the
    # operator their archive is gone when the panel simply never reached the host. Both callers
    # turn an HTTPException into their own shape, so say which failure this is.
    if listing is None:
        abort(503, description="Couldn't reach this server's host to read its backups, so the "
                               "panel can't tell whether that archive is still there. Check the "
                               "host is reachable and try again.")
    for b in listing:
        if b["name"] == name:
            return b
    return None

def _pro_status_cached(remote, force=False):
    """Ubuntu Pro status, served from the persisted value so a page visit (even right after a
    panel restart) never re-spawns the slow client. Only refreshes on an explicit force or when
    the stored value is genuinely stale — the attach/detach/service actions refresh it directly,
    so it's otherwise set-and-forget. Returns the status dict."""
    cached = remote.cached_pro
    if cached and not force and (time.time() - cached.get("ts", 0)) < _PRO_MAX_AGE:
        return cached["data"]
    data = pro_status(remote, force=force)
    # Never persist a read that did not happen. This cache is served for _PRO_MAX_AGE — a day —
    # and survives restarts, so storing an unreadable result pins "Ubuntu Pro is not installed"
    # onto a host nobody managed to ask. The helper's own reader refuses to cache a failed read
    # for the same reason; this is the database half of it.
    if not data.get("unreadable"):
        try:
            remote.update_pro_cache(data)
            db.session.commit()
        except Exception:
            db.session.rollback()
    elif cached:
        # Something was known before. Hand that back rather than a blank — with the flag, so the
        # page can say the figure is the last one read rather than the current truth.
        return dict(cached["data"], unreadable=True, stale=True)
    return data

def _refuse_on_panel_host(remote, what):
    """A JSON 400 when a VPS-PREPARATION action is aimed at the panel's own host, else None.

    get_remote() already enforces WHICH hosts a user may touch. This is the other axis: WHICH
    KIND. Bootstrap, Tailscale-install and Tailscale-join prepare a fresh VPS — they apt
    full-upgrade the machine, rewrite its sshd config, pipe an installer into a root shell, and
    reboot it. Aimed at the host the panel runs on, that reboots the panel out from under the
    request, and can change the tailnet identity of the very machine the operator is reaching
    it through.

    manage_remotes.html already hides all three for the local host. This is the server-side
    half of that: a UI-only restriction on a destructive privileged action is not a
    restriction — the route still accepted a POST with the local host's id."""
    if not is_local_server(remote):
        return None
    _log.warning("refused %s aimed at the panel's own host (remote_id=%s)", what, remote.id)
    return jsonify({
        "success": False,
        "message": ("%s prepares a REMOTE VPS and can't target the panel's own host — it "
                    "would reboot the panel mid-request. Use the panel's own pages for "
                    "updates, firewall and Tailscale." % what),
    }), 400

# ── Scheduled tasks (cron) for the game user ──
# Same privilege gate as the file editor: a cron entry runs an arbitrary command
# as the (unprivileged) game user, exactly as file editing writes arbitrary
# content. The panel's own managed entries (autostart / maintenance / daily restart) are
# editable here too — nothing is locked in the generic editor any more (see
# ssh_manager._cron_managed_patterns, which now returns []). This comment previously claimed
# they were read-only, which read as a security guarantee that the code does not make.
def _sync_toggles_from_cron(gs, jobs):
    """Make the crontab the source of truth for the Autostart / Daily-restart switches.

    Both switches are stored as columns, but what they really mean is "is this line in the
    crontab". Three paths wrote the line without touching the column — install_game_cron() at
    install time, an import that adopted an existing setup, and deleting the line by hand in
    Scheduled Tasks (whose own help text promised that deleting `monitor` turns Autostart off).
    So the Details page could show Off while `*/5 * * * * ... monitor` was scheduled and
    running. Reconciles on every read or write of the cron list; returns True if it changed
    anything.

    `jobs` of None means the crontab could not be READ, and is refused. This function writes
    columns from an ABSENCE — "the monitor line is not in this list" — so a failed read fed to
    it as [] is not a no-op, it is a wipe: both switches go off, the host's crontab keeps
    running the lines, and nothing ever turns them back on. That is what an unreachable host
    did to a server whose Files & Config page you merely OPENED. `or []` would restore exactly
    that, which is why the guard is on `is None` and the comprehension no longer carries one."""
    if jobs is None:
        return False
    roles = {j.get("role") for j in jobs}
    changed = False
    for field, role in (("autostart", "autostart"), ("daily_restart", "daily-restart")):
        live = role in roles
        if bool(getattr(gs, field)) != live:
            setattr(gs, field, live)
            changed = True
    if changed:
        db.session.commit()
    return changed

# ── WebSocket Console ───────────────────────────────────
def _socketio_cors():
    """Origins allowed to open the console WebSocket. Explicit config wins; else,
    once the panel has a domain (served via Tailscale Serve/nginx), lock to that
    origin instead of "*". Falls back to "*" only for plain IP:port access, where
    there's no fixed origin to pin to. (join_console also requires an authenticated
    session, and the SameSite=Lax cookie stops a cross-site page carrying it.)"""
    cfg = load_config()
    explicit = cfg.get("socketio_cors_origins")
    if explicit:
        return explicit
    dom = (cfg.get("site_domain") or "").strip()
    if dom:
        return ["https://%s" % dom, "http://%s" % dom]
    return "*"

def _os_updates_for(remote):
    """One host's check result dict, or None if it could not be checked.

    Runs on a pool thread, so it touches no session and reads only already-loaded columns of
    `remote` — the same contract as _probe_host. Never raises."""
    try:
        if not _host_reachable(remote):
            return None       # an unreachable host is the monitor's alert to raise, not this one's
        if remote.is_local:
            res = so.os_update_available(refresh=True)
        else:
            res = _sm.remote_os_check_updates(remote) or {}
        # A failed check returns no packages, exactly like a clean host. Without this the state
        # would re-arm on the failure and re-announce the identical list on the next success.
        if not res.get("ok"):
            return None
        return res
    except Exception:
        _log.debug("os-update check failed for %s", getattr(remote, "name", "?"), exc_info=True)
        return None


# ─── Error responses shared by the route table ───────────────────────────────────────
# Hoisted out of register_routes for the same reason as the helpers above. `app.logger`
# becomes `current_app.logger`, which inside a request is the SAME logger object on the SAME
# channel — so no log line changes and not one of the 79 call sites needed touching. Every
# caller of both is a route view, so the request context they need is guaranteed.



def register_routes(app):
    # Lazy, like every other panel.routes import here: those modules do
    # `from app import ...` at their top, so they can only be imported once
    # this module's own body has finished.
    from panel.routes._shared import (_looks_installed, _notify_servers_changed,
        _run_due_game_backups, _run_due_restarts, _run_pending_backups)

    # ── Helpers ─────────────────────────────────────────────




    from panel.routes import route_helpers as _r_route_helpers
    _r_route_helpers.register(app)

    # ── Authentication Routes ──────────────────────────────
    from panel.routes import auth_routes as _r_auth_routes
    _r_auth_routes.register(app)

    # ── Server tags: install-wide labels for grouping, bulk actions and alert routing ──────────


    from panel.routes import tags as _r_tags
    _r_tags.register(app)

    # ── Dashboard ──────────────────────────────────────────
    from panel.routes import dashboard as _r_dashboard
    _r_dashboard.register(app)

    # ── Server Detail + Console ────────────────────────────

    from panel.routes import server_detail as _r_server_detail
    _r_server_detail.register(app)

    # ── Manage Game Servers ────────────────────────────────
    from panel.routes import manage_servers as _r_manage_servers
    _r_manage_servers.register(app)

    # ── Remote Server Management ───────────────────────────
    from panel.routes import remotes as _r_remotes
    _r_remotes.register(app)

    # ── Discover + import LinuxGSM servers already installed on a host ──
    from panel.routes import discover as _r_discover
    _r_discover.register(app)

    # ── User Management ────────────────────────────────────
    from panel.routes import users as _r_users
    _r_users.register(app)

    # ── Admin notifications (Telegram / Discord) ──────────────
    from panel.routes import admin_notifications as _r_admin_notifications
    _r_admin_notifications.register(app)

    # ── Group Management ───────────────────────────────────
    from panel.routes import groups as _r_groups
    _r_groups.register(app)

    # ── Custom Commands (superadmin-defined game commands handed to groups) ──
    # A dict of engine value -> label for the scope selector. Kept here (not a new ssh_manager
    # export) so the admin UI stays self-contained.



    from panel.routes import custom_commands as _r_custom_commands
    _r_custom_commands.register(app)

    # ── Audit Logs ──────────────────────────────────────────
    from panel.routes import audit as _r_audit
    _r_audit.register(app)

    # ── Tailscale Integration ───────────────────────────────
    from panel.routes import tailscale as _r_tailscale
    _r_tailscale.register(app)

    # ── Server Management (local) ──────────────────────────
    from panel.routes import host_local as _r_host_local
    _r_host_local.register(app)

    # ── Security tab for REMOTE hosts (fail2ban + SSH logs over SSH) ──
    from panel.routes import remote_security as _r_remote_security
    _r_remote_security.register(app)

    # ── Panel backup & restore (superadmin) ──────────────────────
    from panel.routes import panel_backup as _r_panel_backup
    _r_panel_backup.register(app)

    # ── Remote VPS Management (port/OS) ────────────────────
    from panel.routes import remote_vps as _r_remote_vps
    _r_remote_vps.register(app)

    # ── Ubuntu Pro (works for the panel host too, via its local remote id) ──


    from panel.routes import ubuntu_pro as _r_ubuntu_pro
    _r_ubuntu_pro.register(app)

    # ── Remote Tailscale Bootstrap Routes ──────────────────
    from panel.routes import remote_tailscale as _r_remote_tailscale
    _r_remote_tailscale.register(app)

    # ── Close port 22 after Tailscale ───────────────────────
    from panel.routes import close_port22 as _r_close_port22
    _r_close_port22.register(app)

    # ── Remote VPS Bootstrap Route (async, with live progress) ──
    from panel.routes import remote_bootstrap as _r_remote_bootstrap
    _r_remote_bootstrap.register(app)

    # ── API Routes ──────────────────────────────────────────
    from panel.routes import api as _r_api
    _r_api.register(app)

    # ── Config editor + file browser (per game server) ─────────



    # Defined before its first use: server_files takes the supervisor for the console
    # poller, and the tickers below all go through it.
    # _supervise and the priority keeper are the background layer, not file-browser code —
    # they only travelled with server_files because they sat inside that section's line
    # span. They belong beside the other tickers, which is here.
    # Start the console poller under a tiny supervisor: it has an inner try/except so it
    # shouldn't die, but if it ever exits we log and respawn it — console streaming
    # self-heals instead of silently staying dead until the next full restart.
    def _supervise(name, target):
        def _runner():
            while True:
                t = threading.Thread(target=target, daemon=True)
                t.start()
                t.join()   # only returns if the worker exited unexpectedly
                app.logger.error("%s thread exited — respawning in 5s", name)
                time.sleep(5)
        threading.Thread(target=_runner, daemon=True).start()

    from panel.routes import server_files as _r_server_files
    socketio = _r_server_files.register(app, _supervise)
    # AFTER socketio exists, and handed it: there is exactly one SocketIO in this app and the
    # terminal's events live on its DEFAULT namespace so the connect-time auth gate above applies
    # to them too. A second SocketIO(app) would collide on /socket.io/.
    from panel.routes import host_terminal as _r_terminal
    _r_terminal.register(app, socketio, _supervise)
    # Daily automatic backups: check hourly; daily_backup_tick() takes one only when the last
    # daily backup is ~a day old (and enabled), then prunes past the retention window.
    def backup_ticker():
        # Wait before the FIRST tick so a restart (e.g. a panel self-update) doesn't immediately
        # fire this batch — which can start a due backup, archiving a server on top of the cold-start
        # and pinning the CPU. Hourly cadence is unchanged; the first run is just shifted ~2 min.
        time.sleep(120)
        while True:
            try:
                bk.daily_backup_tick()
                _run_due_game_backups(app)   # per-server schedules (each records its own last-run)
                _run_pending_backups(app)    # 'wait until empty' full-backup queue
            except Exception:
                app.logger.debug("backup tick failed", exc_info=True)
            time.sleep(3600)
    _supervise("backup-ticker", backup_ticker)
    # "Restart/stop when empty" needs to act PROMPTLY once the last player leaves — an hourly check
    # would leave the server up for up to an hour after it emptied. Run the deferred-action sweep on
    # a short cadence instead; it only does anything for servers that actually have a queued action.
    def due_actions_ticker():
        time.sleep(45)
        while True:
            try:
                _run_due_restarts(app)   # apply queued 'restart/stop when empty' once a server empties
            except Exception:
                app.logger.debug("due-actions tick failed", exc_info=True)
            time.sleep(90)
    _supervise("due-actions", due_actions_ticker)
    # Self-heal installs stranded in "installing" with no live job — the panel restarting
    # mid-install (a deploy/self-update) loses the in-memory progress, and the status poller
    # SKIPS anything "installing"/"configuring", so such a server would sit stuck forever. On boot
    # (and periodically, to also catch a host that was unreachable earlier) reconcile each against
    # the real server: verified-installed → offline (metrics flip it online), clearly-not → failed.
    #
    # "failed" is in that list for the same reason, in the other direction. An install that failed
    # for a fixable reason — a game needing a Steam account that owns it is the common one — is
    # recoverable IN THE PANEL: its LinuxGSM config survives (the download is what failed, not the
    # setup), the Files & Config page now opens on it, and the control bar's Update runs SteamCMD
    # again. Without this the files would land and nothing would notice: installed stayed False,
    # the row stayed "failed", and the server the operator had just repaired remained unusable.
    # A row that is genuinely dead costs one `details` per 10 minutes, against an empty
    # serverfiles, which is the cheap case.
    def install_reconcile_ticker():
        time.sleep(20)   # let boot settle; the per-server check is an SSH round trip
        while True:
            try:
                with app.app_context():
                    for gs in GameServer.query.filter(
                            GameServer.status.in_(("installing", "configuring", "failed"))).all():
                        with _install_lock:
                            live = (gs.id in _install_jobs
                                    and _install_jobs[gs.id].get("status") == "running")
                        if live:
                            continue   # a genuinely in-progress install — leave it alone
                        try:
                            verdict = _looks_installed(app, gs.remote, gs.short_name, gs.lgsm_name)
                        except Exception:
                            verdict = None
                        if verdict is True:
                            gs.installed = True
                            gs.status = "offline"   # live metrics flip it to online if running
                            db.session.commit()
                            _notify_servers_changed(app)
                            app.logger.info("reconciled stranded install '%s' -> installed", gs.short_name)
                        elif verdict is False:
                            # Only when something ACTUALLY changed. "failed" is itself in the
                            # query's filter set (deliberately — see above), so unlike the True
                            # branch this row comes back every tick, and writing the two values it
                            # already holds re-fired a `servers_changed` broadcast to every open
                            # dashboard — each one then re-requesting /api/servers and restarting
                            # its install-progress poller — and logged "reconciled stranded install
                            # 'X' -> failed" 144 times a day about a reconciliation that did not
                            # happen. _sync_toggles_from_cron compares before it commits for the
                            # same reason.
                            if gs.installed or gs.status != "failed":
                                gs.installed = False
                                gs.status = "failed"
                                db.session.commit()
                                _notify_servers_changed(app)
                                app.logger.info("reconciled stranded install '%s' -> failed", gs.short_name)
                        # None (host unreachable): leave it; the next tick retries.
            except Exception:
                app.logger.debug("install-reconcile tick failed", exc_info=True)
            time.sleep(600)
    _supervise("install-reconcile", install_reconcile_ticker)

    # Keep game processes at their slight CPU-priority edge (nice -1). The panel boosts a game on
    # its own start/restart, but the LinuxGSM monitor cron restarts a crashed server AS the game
    # user — which can't set a negative nice — so it falls back to nice 0. Re-apply the boost on a
    # slow cadence so every game, however it (re)started, settles at the intended priority. One
    # batched `renice` per host; users with no running processes are a no-op.
    def priority_keeper():
        time.sleep(60)
        while True:
            try:
                with app.app_context():
                    by_remote = {}   # remote_id -> (remote, {short_name, …})
                    for gs in GameServer.query.filter_by(installed=True).all():
                        if not gs.remote_id:
                            continue
                        by_remote.setdefault(gs.remote_id, (gs.remote, set()))[1].add(gs.short_name)
                    for remote, users in by_remote.values():
                        try:
                            set_game_priority_bulk(remote, sorted(users))
                        except Exception:
                            app.logger.debug("priority keeper: renice failed", exc_info=True)
            except Exception:
                app.logger.debug("priority keeper tick failed", exc_info=True)
            time.sleep(120)

    _supervise("priority-keeper", priority_keeper)

    # ── OS package updates, per host ───────────────────────────────────────────────────────────
    # Checked once a day, not on the monitor's 60s tick: each check runs `apt update`, which is a
    # network fetch on every host. It rides the existing update-check ticker rather than adding
    # another thread.
    #
    # Alerts on the TRANSITION (nothing waiting -> something waiting) and re-arms once the host is
    # clean again, the same shape as the disk-low alert. Telling you every day that the same twelve
    # packages are still there is how an alert becomes noise you filter out.


    from panel.routes import os_updates as _r_os_updates
    _r_os_updates.register(app, _supervise)

    # Make socketio accessible from app
    app.socketio = socketio
    return app


# ─── Main Entry Point ──────────────────────────────────────────

def _https_ready(cfg):
    """Is the panel REACHED over HTTPS — whether it terminates TLS itself or something in front
    does? This is what decides the Secure flag on the session and remember-me cookies.

    A named function so a test can ask it the question the cookie asks, rather than restating the
    expression and then proving its own restatement right. See the note at the call site for what
    it used to get wrong in both directions."""
    return bool(_effective_https(cfg)
                or cfg.get("tailscale_setup_done", False)
                or cfg.get("trust_proxy", False))


def _effective_https(cfg):
    """Should the panel terminate TLS itself with the built-in self-signed cert?

    Self-signed HTTPS is the default so a fresh public install is encrypted out of the
    box. But when Tailscale Serve or a reverse proxy is in front, THAT layer terminates
    TLS (with a real cert) and forwards plain HTTP to us on loopback — serving HTTPS
    underneath would just break their http:// upstream. So we stand down in those cases
    and let them do it. This keeps existing Tailscale installs serving HTTP exactly as
    before (zero change on upgrade)."""
    if not cfg.get("use_https", True):
        return False
    if cfg.get("tailscale_setup_done", False):
        return False
    if cfg.get("trust_proxy", False):
        return False
    return True


def _f2b_ban_events(seen, cur):
    """One ban-watcher tick, as a decision: (new_seen, new_bans, unbans).

    Pure, and module level, because this is where the bug was and a `while True` with a
    time.sleep() in it cannot be driven by a test. The loop below does the I/O and the logging;
    what to CONCLUDE from two readings is here.

    `cur is None` means the jail could not be read. That is not "nothing is banned": the watcher
    diffs consecutive readings, so answering set() invents an unban for every live ban now, and a
    ban plus a notification for each of them on the next good tick. The reading is discarded and
    `seen` is handed back untouched.

    `seen is None` is the first successful reading — adopt it silently, so bans that already
    existed when the panel started are not announced as new.
    """
    if cur is None:
        return seen, (), ()
    if seen is None:
        return cur, (), ()
    if cur == seen:
        return seen, (), ()
    return cur, tuple(sorted(cur - seen)), tuple(sorted(seen - cur))


def _f2b_record_events(app, new_bans, unbans):
    """Write the audit rows and fire the notifications for one ban-watcher tick.

    Separated from the loop for the same reason _f2b_ban_events is: the false NOTIFICATIONS were
    half of what the unreadable-jail bug produced — an "IP banned on the panel login" message per
    live ban, and a "Login attack in progress" alert once three arrived together — so what this
    emits, and at what threshold, is behaviour worth driving directly rather than reaching through
    a daemon thread.

    Takes the events rather than deciding them, so it cannot re-introduce the judgement it is
    paired with."""
    if not new_bans and not unbans:
        return
    with app.test_request_context():   # gives log_action an (empty) request/DB context
        for _ip in new_bans:
            log_action(None, "fail2ban_ban", target=_ip,
                       detail="banned after 5 failed panel logins in 10 min (1-hour ban)",
                       success=False)
            notifications.notify("ip_banned", "IP banned on the panel login",
                                 "%s was banned by fail2ban (5 failed logins in 10 min)" % _ip)
        for _ip in unbans:
            log_action(None, "fail2ban_unban", target=_ip, detail="ban expired or lifted")
    if len(new_bans) >= _BAN_SPIKE_THRESHOLD:   # a burst of bans at once = an attack wave
        notifications.notify("ban_spike", "Login attack in progress",
                             "%d IPs were just banned from the panel login at once." % len(new_bans))


def _ts_backend_scheme(cfg):
    """Loopback scheme Tailscale Serve must use to reach us — has to match how the panel
    is actually listening right now, or Serve 502s. When we're terminating self-signed
    TLS ourselves, Serve talks https+insecure to us; otherwise plain http."""
    return "https+insecure" if _effective_https(cfg) else "http"


if __name__ == "__main__":
    app = create_app()
    cfg = load_config()
    port = cfg.get("port", 5000)

    # Make sure the fail2ban panel-login jail is up and pointed at the current port. fail2ban is
    # installed by the panel installer; this self-heals the jail on every boot (and after a port
    # change) so it's protected by default — no manual "enable" click. Backgrounded so it never
    # delays startup, and idempotent so a healthy jail just costs a quick status read.
    def _f2b_autostart():
        try:
            _ok, _msg = so.ensure_panel_fail2ban(AUTH_LOG_PATH, port, _security_whitelist())
            _log.info("panel fail2ban: %s", _msg)
        except Exception:
            _log.debug("panel fail2ban autostart failed", exc_info=True)
        # Re-sync the whitelist into every remote's fail2ban too, so a remote that was offline or
        # newly added during a whitelist change catches up. Only when there's something to apply.
        if _security_whitelist():
            try:
                _apply_whitelist_to_remotes(app)
            except Exception:
                _log.debug("remote fail2ban whitelist sync failed", exc_info=True)
    threading.Thread(target=_f2b_autostart, daemon=True).start()

    # Record fail2ban bans/unbans of the panel-login jail in the audit log, so the activity is
    # visible even though the jail runs automatically with no management UI. Seeds from the current
    # bans on start (so existing bans aren't re-logged) and polls for changes.
    def _f2b_ban_watch():
        seen = None
        while True:
            try:
                seen, new_bans, unbans = _f2b_ban_events(
                    seen, so.panel_fail2ban_banned_ips())
                _f2b_record_events(app, new_bans, unbans)
            except Exception:
                _log.debug("fail2ban ban-watch tick failed", exc_info=True)
            time.sleep(90)
    if os.name == "posix":
        threading.Thread(target=_f2b_ban_watch, daemon=True).start()

    # Fire any "reboot when empty" requests once a host has no players left.
    threading.Thread(target=lambda: _reboot_when_empty_watch(app), daemon=True).start()

    # Keep each auto-block host's rolling top-20 (7-day) UFW block list in sync.
    threading.Thread(target=lambda: _autoblock_watch(app), daemon=True).start()

    # Keep live per-server player counts fresh for the dashboard / Game Servers page.
    threading.Thread(target=lambda: _player_count_watch(app), daemon=True).start()

    # Record CPU/RAM/player samples into history (for the trend charts on the server page).
    threading.Thread(target=lambda: _metrics_history_watch(app), daemon=True).start()

    # Keep the npm + gamedig player-query tools auto-updating on every host (weekly cron; this ensures
    # the cron exists on hosts that predate it).
    threading.Thread(target=lambda: _node_tools_cron_watch(app), daemon=True).start()

    # Proactive monitor: server-down / host-unreachable / disk-low admin notifications.
    threading.Thread(target=lambda: _monitor_watch(app), daemon=True).start()

    # Telegram command bot (/update, /status, …) — opt-in, locked to the configured chat.
    threading.Thread(target=lambda: _telegram_command_watch(app), daemon=True).start()

    # Discord command bot (!update, !status, …) — opt-in, locked to the configured channel. Holds a
    # persistent Gateway WebSocket; a no-op until a bot token + channel are configured with commands on.
    threading.Thread(target=lambda: _discord_command_watch(app), daemon=True).start()

    # If a Telegram/Discord-triggered self-update just restarted us, tell the chat/channel it's back
    # (after a short settle so "back online" is true). No-op when there's no pending update.
    def _bot_update_report():
        time.sleep(8)
        for fn in (_report_tg_pending_update, _report_dc_pending_update):
            try:
                fn()
            except Exception:
                _log.debug("bot pending-update report failed", exc_info=True)
    threading.Thread(target=_bot_update_report, daemon=True).start()

    host = (cfg.get("bind_host") or "").strip()
    if not host:
        # Not explicitly configured: bind where the panel is actually reachable —
        # 127.0.0.1 if Tailscale Serve is up to proxy to it, otherwise 0.0.0.0 so the
        # first-run setup wizard is reachable over the network on a plain VPS.
        try:
            host = ts.suggest_best_bind(port).get("bind_host") or "0.0.0.0"
        except Exception:
            host = "0.0.0.0"
    _scheme = "https" if _effective_https(cfg) else "http"
    print(f"LinuxGSM Panel starting on {host}:{port}")
    print(f"Open {_scheme}://{host}:{port} in your browser")

    # Show Tailscale URL if available
    try:
        ts_info = ts.get_tailscale_info()
        if ts_info.dns_name:
            print(f"\n  🌐 Tailscale: https://{ts_info.dns_name}")
            if ts_info.funnel_enabled:
                print(f"  🌍 Funnel (public): https://{ts_info.dns_name}")
        elif ts_info.tailscale_ips:
            print(f"\n  🌐 Tailscale IP: http://{ts_info.tailscale_ips[0]}:{port}")
    except Exception:
        _log.debug("ignored non-fatal error", exc_info=True)

    # Optional built-in HTTPS with a self-signed cert (for public, no-domain, no-proxy
    # setups). Browsers will warn about the self-signed cert — that's expected.
    ssl_args = {}
    if _effective_https(cfg):
        cert_path = str(DATA_DIR / "ssl" / "cert.pem")
        key_path = str(DATA_DIR / "ssl" / "key.pem")
        try:
            _ensure_self_signed_cert(cert_path, key_path, cfg.get("site_domain") or host)
            ssl_args = {"certfile": cert_path, "keyfile": key_path}
            print(f"  🔒 HTTPS enabled (self-signed) — https://{host}:{port}")
            print("     Browsers will show a certificate warning; click through to proceed.")
        except Exception as e:
            print(f"  [!] Could not enable HTTPS ({e}); serving plain HTTP instead.")

    # Self-heal Tailscale Serve's upstream scheme. If we flipped between self-signed HTTPS
    # and plain HTTP since Serve was configured (e.g. HTTPS during first-run setup, then
    # HTTP once Tailscale took over TLS on the next restart), re-point Serve at the scheme
    # we're actually listening on now. Idempotent when already correct; best-effort.
    if cfg.get("tailscale_setup_done"):
        try:
            ts.setup_tailscale_serve(
                port=port,
                mount=cfg.get("tailscale_mount", "/") or "/",
                funnel=cfg.get("tailscale_use_funnel", False),
                backend_scheme=_ts_backend_scheme(cfg),
            )
        except Exception:
            _log.debug("ignored non-fatal error", exc_info=True)

    app.socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True, **ssl_args)
