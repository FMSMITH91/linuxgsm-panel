"""LinuxGSM Panel - Full Game Server Administration Panel.

Routes:
  GET  /                    -> Dashboard (server overview)
  GET  /login               -> Login page
  GET  /setup               -> Initial setup wizard (multi-step)
  POST /setup               -> Process setup steps
  GET  /server/<id>         -> Single server detail + console
  POST /server/<id>/action  -> Execute server action (start/stop/restart/update)
  POST /server/<id>/command -> Send console command
  GET  /servers/manage      -> Manage game servers on a remote
  POST /servers/install     -> Install a new game server
  POST /servers/uninstall   -> Uninstall a game server
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
  WebSocket /console/<id>   -> Live console streaming
"""
import logging
import concurrent.futures
import os
import re
from panel.core import terminal
import threading
import time
import gzip as _gzip
from datetime import timedelta
from panel.core.clock import utcnow
from urllib.parse import quote

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

import secrets
from flask import (Flask, Response, current_app, flash, g, jsonify, redirect, render_template,
    request, session, url_for)
from markupsafe import Markup
from panel.core import i18n
from flask_login import (current_user, login_required)
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect

from panel.security.auth import (ALL_PERMISSIONS, can_access_server, get_remote, get_game,
    _can_manage_files, can_access_remote, accessible_remote_ids, check_password, client_ip,
    get_user_permissions, get_user_servers, has_permission, init_auth, log_action,
    permission_required, server_access_required, superadmin_required,
    strip_legacy_superadmin_grants, INSTALL_SERVER, UNINSTALL_SERVER, MANAGE_SERVERS,
    MANAGE_REMOTES, VIEW_CONSOLE, SEND_COMMAND, RESTART_SERVER, START_SERVER, STOP_SERVER,
    UPDATE_SERVER)
from panel.core.config import (
    DATA_DIR, DB_PATH, get_secret_key, load_config, save_config, update_config,
    encrypt_secret, decrypt_secret, is_encrypted, harden_data_permissions,
)
from panel.services import notifications
from panel.services.certs import (_ensure_self_signed_cert)
from panel.db.prefs import (_apply_user_server_order, _effective_prefs, _panel_layout)
from panel.core.middleware import PrefixMiddleware
from panel.services.monitoring import (_METRIC_RETENTION_DAYS, _METRIC_SAMPLE_SECONDS,
    _MONITOR_SECONDS, _PLAYER_POLL_SECONDS, _PLAYER_POLL_WORKERS, _autoblock_reconcile,
    _autoblock_threshold, _cached_player_count, _host_reachable, _metrics_work, _monitor_pass,
    _query_server_metrics, _reboot_when_empty_watch, _record_metric_samples,
    _refresh_player_counts, _whitelisted)
from panel.core.panel_state import (_expected_offline, _game_backup_status, _install_jobs,
    _install_lock, _last_sample_prune, _monitor_state, _os_update_seen, _player_counts)
from panel.db.models import (AuditLog, GameServer, Group, RemoteServer, SetupState, User, db,
    init_db, CUSTOM_ARG_PLACEHOLDER, GlobalBan, MetricSample, HostSample)
from panel.ops.ssh_manager import (_remote_listening_ports, _invalidate_port_scan,
    close_connection, is_local_server, run_command, run_privileged, ssh_test_connection,
    get_server_status, run_as_game_user, send_console_command, capture_console,
    list_server_commands, server_live_metrics, discover_linuxgsm_servers, player_list, moderate,
    game_engine, console_steamid_ban, ensure_persistent_bans, pro_status, set_autostart,
    install_game_cron, list_cron_jobs, add_cron_job, update_cron_job, delete_cron_job,
    upgrade_managed_cron_tracking, run_cron_job_now, list_game_backups, mods_available,
    mods_installed, mods_action, game_engine as sm_game_engine, set_game_priority_bulk,
    install_game_dependencies, parse_missing_deps, detect_game_ports, lgsm_read_config,
    GMOD_CONTENT_GAMES, GMOD_CONTENT_SIZES, ensure_content_user, install_gmod_content,
    gmod_mount_setup, gmod_current_mounts, detect_content_user, uninstall_gmod_content,
    path_disk_free, lgsm_write_config, lgsm_game_config, lgsm_get_values, browse_dir, read_file,
    write_file, upload_file, stat_upload_targets, UPLOAD_EXISTS, delete_path, stat_path,
    stream_path, remote_ufw_open_port, remote_ufw_close_port, remote_ufw_close_game_port,
    remote_ufw_allow_game_ports, remote_ufw_close_by_name, remote_os_check_updates,
    remote_fail2ban_overview, remote_fail2ban_unban, remote_security_log,
    remote_fail2ban_top_ips, remote_set_fail2ban_ignoreip, remote_ufw_deny_ip,
    remote_ufw_undeny_ip, tailnet_exempt_ips, ensure_node_tools_cron)
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


def _register_session(user):
    """Record a server-side row for this login and tag `user` with its sid so User.get_id embeds it
    (letting load_user validate it and the account page revoke it individually). Also prunes this
    user's long-dead sessions. Returns the sid, or None on failure — login still proceeds either way,
    the cookie just falls back to epoch-only (not individually revocable)."""
    from datetime import timedelta
    from panel.db.models import UserSession
    sid = secrets.token_urlsafe(24)
    try:
        cutoff = utcnow() - timedelta(days=45)   # forget sessions untouched for ~6 weeks
        UserSession.query.filter(UserSession.user_id == user.id,
                                 UserSession.last_seen < cutoff).delete(synchronize_session=False)
        db.session.add(UserSession(user_id=user.id, sid=sid,
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

# In-memory registry of running/finished VPS bootstrap jobs, keyed by remote_id.
# Populated by the async bootstrap runner and read by the status endpoint. Both
# live in the same (single) panel process, so a plain dict + lock is sufficient.
_bootstrap_jobs = {}
_bootstrap_lock = threading.Lock()

# Serializes the install "slot" allocation (pick a free port → reject a duplicate name → create the
# row). resolve_free_port yields on an SSH scan, so without this two concurrent installs on the same
# remote could both pick the same port or both pass the duplicate-name check before either commits.
_install_alloc_lock = threading.Lock()

# Largest file the browser upload accepts (enforced in the upload route AND as the app-wide
# MAX_CONTENT_LENGTH, so an oversized body is rejected before it's read).
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024

# Console log window. The default is what each poll pulls back; the browser stitches successive
# windows into a much longer scrollback of its own, so this is sized to cover the gap between two
# polls rather than to be the whole history. The ceiling bounds an explicit ?lines= request — the
# "load more" control asks for it once, and it is still only a `tail`.
_CONSOLE_LINES = 250
_CONSOLE_LINES_MAX = 2000

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
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (
        ascii_name, quote(base, safe=""))


def _port_span(game_type):
    """Contiguous ports one server of `game_type` reserves (default 1)."""
    return _PORT_SPAN.get((game_type or "").lower(), 1)


def _first_free_block(desired, span, occupied, limit=400):
    """Lowest start port >= `desired` whose `span` contiguous ports are all clear of `occupied`."""
    p = desired
    for _ in range(limit):
        if all((p + k) not in occupied for k in range(span)):
            return p
        p += 1
    return p


# A token unique to THIS panel process — it changes only when the panel actually restarts.
# The self-update UI polls for this to flip, rather than the git SHA: install.sh moves HEAD
# the instant it resets, before the new process is serving, so a SHA change doesn't mean the
# update is live — a boot-id change does.
_BOOT_ID = "%.6f" % time.time()


# ── State that used to live inside register_routes() ──────────────────────────────────────────
# These were assigned in the body of register_routes, which made them closure cells: reachable
# only from the functions defined alongside them. Nothing outside could see them — including the
# tests, which had to dig state out of `_maybe_alert_os_updates.__code__.co_freevars` and
# `__closure__` to assert on it. Module level is where module state belongs; every one of these is
# process-wide anyway, none is per-app, and no nested function rebinds any of them (they are read,
# or mutated in place), so hoisting needs no `global` anywhere.
#
# `socketio` deliberately stays inside register_routes: it is constructed FROM the app and is the
# one genuinely per-app object in that set.
_cmd_fetch_attempts = {}       # server_id -> last background command-fetch time (rate-limits lazy refetch)
_pubip_resolve_attempts = {}   # remote_id -> last background public-IP resolve time
_gmod_content_apply_state = {}  # server_id -> {"status": running|done|error, "msg", "ts"}
_console_viewers = {}          # server_id -> set of socket session ids
_viewers_lock = threading.Lock()
_OS_UPDATE_EVERY = 24 * 3600
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
    have = {k: int(str(cur.get(k, "")).strip())
            for k in _SOURCE_AUX_PORT_KEYS if str(cur.get(k, "")).strip().isdecimal()}
    if not have:
        return {}                        # game has no SourceTV/client ports — nothing to do
    occupied = set(_remote_listening_ports(remote))
    occupied.add(int(main_port))
    for e in GameServer.query.filter_by(remote_id=remote_id).all():
        for k in range(_port_span(e.game_type)):
            occupied.add(e.port + k)
        if e.short_name == short_name or sm_game_engine(e.game_type) != "valve":
            continue
        try:
            sib = lgsm_get_values(remote, e.short_name, e.lgsm_name, _SOURCE_AUX_PORT_KEYS)
            for v in sib.values():
                if str(v).strip().isdecimal():
                    occupied.add(int(str(v).strip()))
        except Exception:
            _log.debug("aux-port: sibling servercfg read failed", exc_info=True)
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


# ── Telegram command bot ───────────────────────────────────────────────────────────────────────
# Drive the panel from the configured Telegram chat: /update, /status, /servers, /help. Opt-in
# (Notifications → Telegram → "Accept commands") and locked to the saved chat_id — no other chat is
# honoured. Discord webhooks are send-only, so this is Telegram-only. Long-polls getUpdates.
_TG_CMD_BACKOFF = 15


def _tg_panel_label():
    """A short identifier for THIS panel so replies are unambiguous when someone runs several panels:
    '<site title> (<hostname>)'."""
    import socket
    title = (load_config().get("site_title") or "LinuxGSM Panel").strip()
    try:
        host = socket.gethostname()
    except Exception:
        host = ""
    return "🎮 %s (%s)" % (title, host) if host else "🎮 %s" % title


def _tg_reply(token, chat_id, text):
    notifications.send_telegram(token, chat_id, "%s\n%s" % (_tg_panel_label(), text))


def _parse_tg_command(text):
    """Normalise a Telegram command: '/Update@MyBot foo' -> 'update'. '' if it isn't a command."""
    text = (text or "").strip()
    if not text.startswith("/"):
        return ""
    return text.split()[0].split("@")[0].lstrip("/").lower()


def _telegram_command_watch(app):
    """Long-poll loop: honour commands from the authorised chat only. Skips any backlog on (re)start
    so a command sent while we were down — including the /update that caused our own restart — is
    never replayed."""
    offset, primed, registered = None, False, False
    while True:
        try:
            cfg = notifications._cfg()
            tg = cfg.get("telegram") or {}
            token = decrypt_secret(tg.get("token") or "")
            if not (tg.get("enabled") and tg.get("accept_commands")):
                if registered and token:
                    notifications.telegram_set_commands(token, clear=True)   # drop the '/' menu
                    registered = False
                time.sleep(_TG_CMD_BACKOFF)
                offset, primed = None, False   # re-prime (skip backlog) when it's re-enabled
                continue
            authorized = (tg.get("chat_id") or "").strip()
            if not token or not authorized:
                time.sleep(_TG_CMD_BACKOFF)
                continue
            if not registered:
                # Populate Telegram's '/' autocomplete menu with the bot's commands.
                registered = bool(notifications.telegram_set_commands(token))
            if not primed:
                latest = notifications.telegram_get_updates(token, offset=-1, timeout=0)
                if latest:
                    offset = latest[-1].get("update_id", 0) + 1
                primed = True
                continue
            updates = notifications.telegram_get_updates(token, offset=offset, timeout=25)
            if updates is None:
                time.sleep(_TG_CMD_BACKOFF)   # error / 409 conflict (a second poller) → back off
                continue
            for upd in updates:
                offset = upd.get("update_id", 0) + 1
                msg = upd.get("message") or upd.get("edited_message") or {}
                text = (msg.get("text") or "").strip()
                chat = str((msg.get("chat") or {}).get("id") or "")
                if not text.startswith("/"):
                    continue
                if chat != authorized:
                    _log.info("telegram: ignoring a command from unauthorised chat %s", chat[:32])
                    continue
                _handle_telegram_command(app, token, authorized, text, msg.get("from"))
        except Exception:
            _log.debug("telegram command-watch tick failed", exc_info=True)
            time.sleep(_TG_CMD_BACKOFF)


def _tg_command_arg(text):
    """The text after the command word: '/restart my server' -> 'my server'."""
    parts = (text or "").strip().split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def _tg_help_text():
    return ("Commands:\n"
            "/status — panel version + server counts\n"
            "/servers — servers with player counts\n"
            "/hosts — hosts and their status\n"
            "/players <name> — who's on a server\n"
            "/console <name> — the last 20 console lines\n"
            "/connect <name> — the address to give players\n"
            "/say <name> <message> — announce it in-game\n"
            "/start <name> — start a server\n"
            "/stop <name> — stop a server\n"
            "/restart <name> — restart a server\n"
            "/backup <name> — back a server up\n"
            "/update — update the panel itself\n"
            "/update <name> — update that ONE game server instead\n"
            "/help — this message")


def _tg_find_server(arg):
    """Resolve a GameServer from a name/short_name argument (case-insensitive). Returns (gs, error):
    an exact short_name/name match wins, else a unique partial name match, else (None, message)."""
    arg = (arg or "").strip()
    if not arg:
        return None, "Which server? Send /servers to see the names."
    servers = GameServer.query.filter_by(installed=True).all()
    low = arg.lower()
    exact = [g for g in servers if g.short_name.lower() == low or g.name.lower() == low]
    if len(exact) == 1:
        return exact[0], None
    if len(exact) > 1:
        return None, "That matches several — use the exact short name: %s" % ", ".join(g.short_name for g in exact)
    partial = [g for g in servers if low in g.name.lower() or low in g.short_name.lower()]
    if len(partial) == 1:
        return partial[0], None
    if len(partial) > 1:
        return None, "Matches several: %s — be more specific." % ", ".join(g.name for g in partial[:8])
    return None, "No server matches '%s'. Send /servers for the list." % arg[:40]


def _tg_server_action(app, token, chat_id, action, arg, sender=None):
    run_action = getattr(app, "_run_action", None)
    with app.app_context():
        gs, err = _tg_find_server(arg)
        if err:
            _tg_reply(token, chat_id, err)
            return
        if not run_action:
            _tg_reply(token, chat_id, "That action isn't available right now.")
            return
        try:
            # origin, not actor=None: this is attributable to a chat message, and the audit
            # log should say so rather than filing it under "system".
            ok, msg = run_action(gs, gs.remote, action, None,
                                 origin=_bot_origin("telegram", sender))
        except Exception:
            _log.debug("telegram server action failed", exc_info=True)
            ok, msg = False, "the action failed"
        _tg_reply(token, chat_id, "%s %s — %s" % ("✅" if ok else "⚠️", gs.name, msg))


def _tg_players_text(app, arg):
    with app.app_context():
        gs, err = _tg_find_server(arg)
        if err:
            return err
        try:
            # An explicit /players you typed — allowed to fall back to one console `status` if the
            # server can't be read over the network (unlike the panel's automatic polling).
            players = player_list(gs.remote, gs.short_name, gs.game_type, port=gs.port,
                                  query_type=gs.query_type, selfname=gs.lgsm_name, allow_console=True)
        except Exception:
            players = None
        if players is None:
            return "%s — couldn't read the player list (is it running?)." % gs.name
        if not players:
            return "%s — no players connected." % gs.name
        names = [str(p.get("name") or "?") for p in players]
        return "%s — %d player(s):\n%s" % (gs.name, len(names), "\n".join("• " + n for n in names[:40]))


# A chat reply has to fit in one message on BOTH transports — Telegram truncates at 4000 chars,
# Discord's bot REST send at 1900. Cap the variable-length bodies below that so the label and the
# last line of a console tail are never the part that gets cut.
_BOT_BODY_MAX = 1500


def _tg_console_text(app, arg, lines=20):
    """The tail of a server's live console.

    The missing half of the power commands: start/stop/restart run in the background and their
    output is discarded, so when a start fails the bot can say that it failed but never why. This
    is that answer, without opening the panel."""
    with app.app_context():
        gs, err = _tg_find_server(arg)
        if err:
            return err
        try:
            out, _, rc = capture_console(gs.remote, gs.short_name, selfname=gs.lgsm_name, lines=lines)
        except Exception:
            _log.debug("telegram console tail failed", exc_info=True)
            return "%s — couldn't read the console." % gs.name
        # rc 3 + NO_SESSION is capture_console's "the server isn't running", not an error.
        text = terminal.strip_escapes(out or "")
        rows = [r.rstrip() for r in text.splitlines() if r.strip()][-lines:]
        if not rows:
            return "%s — no console output (is it running?)." % gs.name
        body = "\n".join(rows)
        if len(body) > _BOT_BODY_MAX:      # keep the END: the newest lines are the useful ones
            body = "…" + body[-_BOT_BODY_MAX:]
        return "%s — last %d console line(s):\n%s" % (gs.name, len(rows), body)


def _tg_say_text(app, arg):
    """Announce a message in a server's chat: '<server> <message>'.

    The server is the FIRST word (a short name never contains a space), everything after it is the
    message — otherwise there is no way to tell where one ends and the other begins. moderate()
    sanitizes the text, so a message can't smuggle a second console command."""
    name, _, message = (arg or "").strip().partition(" ")
    if not name:
        return "Usage: say <server> <message>"
    with app.app_context():
        gs, err = _tg_find_server(name)
        if err:
            return err
        if not message.strip():
            return "%s — what should I announce? Usage: say <server> <message>" % gs.name
        try:
            ok, msg = moderate(gs.remote, gs.short_name, gs.game_type, "say",
                               message=message, selfname=gs.lgsm_name)
        except Exception:
            _log.debug("telegram say failed", exc_info=True)
            ok, msg = False, "the announcement failed"
        return "%s %s — %s" % ("✅" if ok else "⚠️", gs.name, msg or ("announced" if ok else "failed"))


def _tg_connect_text(app, arg):
    """A server's joinable address, ready to paste to players."""
    with app.app_context():
        gs, err = _tg_find_server(arg)
        if err:
            return err
        r = gs.remote
        host = (r.public_ip if r else "") or (r.host if (r and not r.is_local) else "")
        if not host:
            return ("%s — no public address known for its host yet. Open the panel once so it can "
                    "resolve one." % gs.name)
        uri = gs.connect_uri(host)
        return "%s\n%s:%s%s" % (gs.name, host, gs.port, ("\n" + uri) if uri else "")


def _tg_hosts_text(app):
    with app.app_context():
        rows = []
        # One grouped COUNT for every host, rather than one COUNT per host inside the loop. The
        # /hosts command is not hot, but the shape was N+1 and the fix is a single query.
        _counts = dict(db.session.query(GameServer.remote_id, db.func.count(GameServer.id))
                       .filter_by(installed=True).group_by(GameServer.remote_id).all())
        for r in RemoteServer.query.order_by(RemoteServer.name).all():
            n_srv = _counts.get(r.id, 0)
            dot = "🟢" if r.is_online else "🔴"
            local = " (this panel)" if r.is_local else ""
            rows.append("%s %s%s — %d server%s" % (dot, r.display_name, local, n_srv, "" if n_srv == 1 else "s"))
    return "\n".join(rows) if rows else "No hosts configured."


def _bot_origin(platform, sender):
    """Audit-log actor string for a command that arrived over a chat bot.

    A bot command can stop a game server or update the panel, and until now every one was recorded
    with actor=None — i.e. as "system". The log showed that a server restarted but not that a chat
    message caused it, let alone which account sent it. Chat bots have no panel identity to map to,
    so the next best thing is to record the origin verbatim and let a human follow it up.
    """
    sender = sender or {}
    who = str(sender.get("username") or sender.get("id") or "unknown")
    return ("%s:%s" % (platform, who))[:64]


def _handle_telegram_command(app, token, chat_id, text, sender=None):
    cmd = _parse_tg_command(text)
    arg = _tg_command_arg(text)
    # A BARE /start is Telegram's own "open the chat" command and should answer with help — but
    # `/start <server>` is the documented way to start a server (it is in TG_COMMANDS, so Telegram
    # puts it in the '/' menu, and _tg_help_text lists it). Matching on the word alone swallowed
    # every one of those: the branch below never saw "start", so the bot answered a start request
    # with its help text. Discord's equivalent matches "help" only and has always worked.
    if cmd == "help" or (cmd == "start" and not arg):
        _tg_reply(token, chat_id, _tg_help_text())
    elif cmd == "status":
        _tg_reply(token, chat_id, _tg_status_text(app))
    elif cmd == "servers":
        _tg_reply(token, chat_id, _tg_servers_text(app))
    elif cmd == "hosts":
        _tg_reply(token, chat_id, _tg_hosts_text(app))
    elif cmd == "players":
        _tg_reply(token, chat_id, _tg_players_text(app, arg))
    elif cmd == "console":
        _tg_reply(token, chat_id, _tg_console_text(app, arg))
    elif cmd == "say":
        _tg_reply(token, chat_id, _tg_say_text(app, arg))
    elif cmd == "connect":
        _tg_reply(token, chat_id, _tg_connect_text(app, arg))
    elif cmd in ("restart", "start", "stop", "backup"):
        _tg_server_action(app, token, chat_id, cmd, arg, sender)
    elif cmd in ("update", "upgrade"):
        # An argument names a SERVER here, the way it does for every other command that takes one
        # (/start, /stop, /restart, /players). The argument used to be parsed and then dropped, so
        # "/update codserver" — asking for a LinuxGSM update of one game server — silently updated
        # the panel itself and restarted it instead.
        if arg:
            _tg_server_action(app, token, chat_id, "update", arg, sender)
        else:
            _telegram_do_update(app, token, chat_id)
    else:
        _tg_reply(token, chat_id, "Unknown command '%s'. Send /help." % cmd[:24])


def _tg_status_text(app):
    with app.app_context():
        installed = GameServer.query.filter_by(installed=True).all()
        online = sum(1 for gs in installed if gs.status == "online")
        players = sum((_player_counts.get(gs.id) or {}).get("count") or 0
                      for gs in installed if isinstance((_player_counts.get(gs.id) or {}).get("count"), int))
    return ("Version %s\nServers: %d online / %d installed\nPlayers online: %d"
            % (_panel_ver_label(), online, len(installed), players))


def _tg_servers_text(app):
    with app.app_context():
        rows = []
        for gs in GameServer.query.filter_by(installed=True).order_by(GameServer.name).all():
            slot = _player_counts.get(gs.id) or {}
            count = slot.get("count")
            pc = ("%s/%s" % (count, slot.get("max"))) if isinstance(count, int) else "?"
            rows.append("%s %s — %s (%s players)"
                        % ("🟢" if gs.status == "online" else "⚪", gs.name, gs.status, pc))
    return "\n".join(rows) if rows else "No servers installed."


def _panel_ver_label():
    """Human-friendly version for messages: '<VERSION> (<short-commit>)'. The VERSION file rarely
    changes between commits, so the commit is what tells you an update actually landed."""
    ver = so.panel_version()
    commit = so.panel_commit()
    return "%s (%s)" % (ver, commit) if commit else ver


def _telegram_do_update(app, token, chat_id):
    try:
        st = so.panel_update_status(force=True)
    except Exception:
        st = {}
    if st.get("git") and not st.get("update_available"):
        _tg_reply(token, chat_id, "✅ Already up to date — %s." % _panel_ver_label())
        return
    ok, msg = so.panel_self_update()   # detached + CI-gated; returns immediately, then restarts us
    if not ok:
        _tg_reply(token, chat_id, "⚠️ Update not started: %s" % msg)
        return
    # Store the COMMIT (not the VERSION string, which rarely changes) so the post-restart check can
    # tell whether the update actually landed.
    _set_tg_pending_update(chat_id, so.panel_commit())
    target = (st.get("target_sha") or "")[:7] or "the newest verified commit"
    _tg_reply(token, chat_id, "🔄 Update started: %s → %s. I'll message you here once I'm back."
              % (_panel_ver_label(), target))


def _set_tg_pending_update(chat_id, from_commit):
    # update_config: this runs in the Telegram poller thread, so a plain load+save could clobber a
    # concurrent whitelist/threshold write from an HTTP handler.
    update_config(lambda cfg: cfg.update(
        {"telegram_pending_update": {"chat_id": chat_id, "from_commit": from_commit, "ts": time.time()}}))


def _report_tg_pending_update():
    """After a restart, if a Telegram-triggered update was pending, tell the chat how it went — by
    comparing the git commit before/after (the VERSION string usually doesn't move between commits)."""
    cfg = load_config()
    pend = cfg.get("telegram_pending_update")
    if not pend:
        return
    update_config(lambda c: c.pop("telegram_pending_update", None))   # clear the marker atomically
    tg = (cfg.get("notifications") or {}).get("telegram") or {}
    token = decrypt_secret(tg.get("token") or "")
    chat = pend.get("chat_id") or ""
    if not (token and chat):
        return
    now = so.panel_commit()
    frm = pend.get("from_commit") or pend.get("from_version")   # from_version: older pending markers
    if now and frm and now != frm:
        _tg_reply(token, chat, "✅ Update complete — now on %s (was %s). Back online." % (_panel_ver_label(), frm))
    else:
        _tg_reply(token, chat, "ℹ️ Update finished — no new commit landed (already current, or it "
                               "rolled back). Still on %s." % _panel_ver_label())


# ── Discord command bot (Gateway) ──────────────────────────────
# Two-way control over Discord. Unlike Telegram (outbound long-poll), Discord needs a persistent Gateway
# WebSocket, so this keeps one open in a background greenlet and posts replies over the bot REST API. The
# command SET, auth model (only the configured channel), and per-command text are shared with the
# Telegram bot — only the transport (reply send / update-pending marker) differs.
_DC_CMD_BACKOFF = 15


def _dc_reply(bot_token, channel_id, text):
    notifications.discord_bot_send(bot_token, channel_id, "%s\n%s" % (_tg_panel_label(), text))


def _parse_dc_command(text):
    """Normalise a Discord command word: '!Restart foo' or '/status' -> 'restart'/'status'. Accepts a
    '!' or '/' prefix — Discord reserves '/' for its own slash-command picker, so '!' is the one that
    types cleanly. '' if it isn't a command."""
    text = (text or "").strip()
    if not text or text[0] not in "!/":
        return ""
    parts = text[1:].split()
    return parts[0].split("@")[0].lower() if parts else ""


def _discord_command_watch(app):
    """Keep a Discord Gateway session open and honour commands from the authorised channel only.
    Mirrors _telegram_command_watch: reconnect-with-backoff, each command routed to the same
    channel-agnostic text builders the Telegram bot uses. A dropped socket just reconnects (a fresh
    IDENTIFY skips any backlog, so the /update that restarted us is never replayed)."""
    while True:
        try:
            cfg = notifications._cfg()
            dc = cfg.get("discord") or {}
            bot_token = decrypt_secret(dc.get("bot_token") or "")
            channel = (dc.get("channel_id") or "").strip()
            if not (dc.get("enabled") and dc.get("accept_commands") and bot_token and channel):
                time.sleep(_DC_CMD_BACKOFF)
                continue

            def _on_message(msg_channel, author_is_bot, content, author=None, _tok=bot_token, _chan=channel):
                # Ignore our own (and every other bot's) messages; only the configured channel counts.
                if author_is_bot or msg_channel != _chan:
                    return
                if (content or "")[:1] not in ("!", "/"):
                    return
                _handle_discord_command(app, _tok, _chan, content.strip(), author)

            notifications.discord_gateway_run(bot_token, _on_message)   # returns when the socket drops
        except Exception:
            _log.debug("discord command-watch tick failed", exc_info=True)
        time.sleep(_DC_CMD_BACKOFF)


def _dc_help_text():
    return ("Commands (type `!cmd`, or `/cmd`):\n"
            "`!status` — panel version + server counts\n"
            "`!servers` — servers with player counts\n"
            "`!hosts` — hosts and their status\n"
            "`!players <name>` — who's on a server\n"
            "`!console <name>` — the last 20 console lines\n"
            "`!connect <name>` — the address to give players\n"
            "`!say <name> <message>` — announce it in-game\n"
            "`!start <name>` — start a server\n"
            "`!stop <name>` — stop a server\n"
            "`!restart <name>` — restart a server\n"
            "`!backup <name>` — back a server up\n"
            "`!update` — update the panel itself\n"
            "`!update <name>` — update that ONE game server instead\n"
            "`!help` — this message")


def _dc_server_action(app, bot_token, channel_id, action, arg, sender=None):
    run_action = getattr(app, "_run_action", None)
    with app.app_context():
        gs, err = _tg_find_server(arg)
        if err:
            _dc_reply(bot_token, channel_id, err)
            return
        if not run_action:
            _dc_reply(bot_token, channel_id, "That action isn't available right now.")
            return
        try:
            # origin, not actor=None: this is attributable to a chat message, and the audit
            # log should say so rather than filing it under "system".
            ok, msg = run_action(gs, gs.remote, action, None,
                                 origin=_bot_origin("discord", sender))
        except Exception:
            _log.debug("discord server action failed", exc_info=True)
            ok, msg = False, "the action failed"
        _dc_reply(bot_token, channel_id, "%s %s — %s" % ("✅" if ok else "⚠️", gs.name, msg))


def _handle_discord_command(app, bot_token, channel_id, text, sender=None):
    cmd = _parse_dc_command(text)
    arg = _tg_command_arg(text)
    if cmd == "help":
        _dc_reply(bot_token, channel_id, _dc_help_text())
    elif cmd == "status":
        _dc_reply(bot_token, channel_id, _tg_status_text(app))
    elif cmd == "servers":
        _dc_reply(bot_token, channel_id, _tg_servers_text(app))
    elif cmd == "hosts":
        _dc_reply(bot_token, channel_id, _tg_hosts_text(app))
    elif cmd == "players":
        _dc_reply(bot_token, channel_id, _tg_players_text(app, arg))
    elif cmd == "console":
        _dc_reply(bot_token, channel_id, _tg_console_text(app, arg))
    elif cmd == "say":
        _dc_reply(bot_token, channel_id, _tg_say_text(app, arg))
    elif cmd == "connect":
        _dc_reply(bot_token, channel_id, _tg_connect_text(app, arg))
    elif cmd in ("restart", "start", "stop", "backup"):
        _dc_server_action(app, bot_token, channel_id, cmd, arg, sender)
    elif cmd in ("update", "upgrade"):
        # Same rule as Telegram: an argument names a server, not the panel. (See the note there.)
        if arg:
            _dc_server_action(app, bot_token, channel_id, "update", arg, sender)
        else:
            _discord_do_update(app, bot_token, channel_id)
    elif cmd:
        _dc_reply(bot_token, channel_id, "Unknown command '%s'. Send !help." % cmd[:24])


def _discord_do_update(app, bot_token, channel_id):
    try:
        st = so.panel_update_status(force=True)
    except Exception:
        st = {}
    if st.get("git") and not st.get("update_available"):
        _dc_reply(bot_token, channel_id, "✅ Already up to date — %s." % _panel_ver_label())
        return
    ok, msg = so.panel_self_update()   # detached + CI-gated; returns immediately, then restarts us
    if not ok:
        _dc_reply(bot_token, channel_id, "⚠️ Update not started: %s" % msg)
        return
    _set_dc_pending_update(channel_id, so.panel_commit())
    target = (st.get("target_sha") or "")[:7] or "the newest verified commit"
    _dc_reply(bot_token, channel_id, "🔄 Update started: %s → %s. I'll message you here once I'm back."
              % (_panel_ver_label(), target))


def _set_dc_pending_update(channel_id, from_commit):
    # update_config: runs in the Discord watcher greenlet, so use the atomic mutator (not load+save) to
    # avoid clobbering a concurrent config write from an HTTP handler.
    update_config(lambda cfg: cfg.update(
        {"discord_pending_update": {"channel_id": channel_id, "from_commit": from_commit, "ts": time.time()}}))


def _report_dc_pending_update():
    """After a restart, if a Discord-triggered update was pending, tell the channel how it went — by
    comparing the git commit before/after."""
    cfg = load_config()
    pend = cfg.get("discord_pending_update")
    if not pend:
        return
    update_config(lambda c: c.pop("discord_pending_update", None))   # clear the marker atomically
    dc = (cfg.get("notifications") or {}).get("discord") or {}
    bot_token = decrypt_secret(dc.get("bot_token") or "")
    channel = pend.get("channel_id") or ""
    if not (bot_token and channel):
        return
    now = so.panel_commit()
    frm = pend.get("from_commit") or ""
    if now and frm and now != frm:
        _dc_reply(bot_token, channel, "✅ Update complete — now on %s (was %s). Back online."
                  % (_panel_ver_label(), frm))
    else:
        _dc_reply(bot_token, channel, "ℹ️ Update finished — no new commit landed (already current, or "
                                      "it rolled back). Still on %s." % _panel_ver_label())


# ── Power actions: is this game actually running? ──────────────


def _live_run_state(gs, remote):
    """Is this game genuinely running right now? True/False, or None when that can't be read.

    Deliberately the SAME predicate /api/server/<id>/stats uses to set gs.status — a listening game
    port OR a live process owned by the game user — so a refusal built on this always agrees with
    what the dashboard and the chat bots' /servers are showing. Reads through server_live_metrics'
    2s cache, which an open dashboard is usually filling anyway. An SSH blip returns the all-zero
    default dict; ram_total is 0 only in that case (`free -b` never fails on a reachable host), so
    it is the sentinel for "don't claim to know"."""
    try:
        m = server_live_metrics(remote, gs.short_name, gs.port)
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
    """Apply (or lift) one SteamID on every running valve server across all hosts. Best-effort and
    backgrounded — a stopped server picks the ban up from writeid/banned_user.cfg or the next Sync."""
    with app.app_context():
        for gs in _valve_game_servers():
            try:
                console_steamid_ban(gs.remote, gs.short_name, gs.lgsm_name, steamid, unban=unban)
            except Exception:
                _log.debug("global-ban fan-out failed for %s", getattr(gs, "short_name", "?"), exc_info=True)


def _sync_global_bans(app):
    """Re-apply the WHOLE global ban list to every running valve server (covers newly added servers
    and any whose native ban list was reset). Best-effort, backgrounded."""
    with app.app_context():
        bans = [b.steamid for b in GlobalBan.query.all()]
        for gs in _valve_game_servers():
            for sid in bans:
                try:
                    console_steamid_ban(gs.remote, gs.short_name, gs.lgsm_name, sid)
                except Exception:
                    _log.debug("global-ban sync failed for %s", getattr(gs, "short_name", "?"), exc_info=True)


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
    {"id": "ifttt", "label": "IFTTT", "toggle": "iftttalert",
     "fields": [{"key": "iftttmakerapi", "label": "Maker API key"},
                {"key": "iftttevent", "label": "Event name"}]},
]
_ALERT_KEYS = [p["toggle"] for p in ALERT_PROVIDERS] + [f["key"] for p in ALERT_PROVIDERS for f in p["fields"]]
_ALERT_KEY_SET = set(_ALERT_KEYS)

# The game dropdown is built from LinuxGSM's own serverlist.csv (every supported
# game). For all entries the server name is exactly "{shortname}server", so the
# install just uses that — no per-game mapping needed.
_GAME_LIST_CACHE = {"games": None}


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
            games.append({"shortname": sn, "name": name})
    games.sort(key=lambda g: g["name"].lower())
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
    raising (a bad value like an empty or non-numeric port must not 500 the page)."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _valid_hex_color(value):
    """Return a normalised #rrggbb string if `value` is a 6-digit hex colour, else "".
    The accent colour is emitted into a CSS custom property, so it must be a strict
    colour literal — never arbitrary text that could carry `}` / `<` and break out."""
    v = (value or "").strip()
    if not v.startswith("#"):
        v = "#" + v
    return v.lower() if _HEX_COLOR_RE.match(v) else ""


# Terminal control noise that "fancy" game consoles write into their log. Minecraft/Paper run a
# JLine console that emits ANSI escapes (colour, and \x1b[K "erase to end of line" — which shows up
# as a literal "[K" once the ESC byte is dropped), carriage returns to redraw the input line, and a
# bare "> " prompt line after every message. Plain-text consoles (Source/CoD/GMod) have none of it.
_CONSOLE_PROMPT_RE = re.compile(r"^>\s*$")


def _clean_console_text(text):
    """Console-log text rendered the way a terminal would show it, then with JLine's bare '> ' prompt
    lines dropped. A no-op for plain-text game consoles. Never drops a real message: only lines that
    are *just* the prompt are removed, so an echoed command like '> list' is kept."""
    if not text:
        return text
    return "\n".join(ln for ln in terminal.render(text).split("\n")
                      if not _CONSOLE_PROMPT_RE.match(ln))


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
    # Secure defaults ON once the panel is served over HTTPS — via built-in self-signed
    # TLS, Tailscale Serve, or a reverse proxy once a site_domain is configured. Only OFF
    # if HTTPS is explicitly disabled AND there's no proxy in front. Override cookie_secure.
    _https_ready = (_effective_https(cfg)
                    or bool(cfg.get("tailscale_setup_done", False))
                    or bool((cfg.get("site_domain") or "").strip()))
    app.config["SESSION_COOKIE_SECURE"] = cfg.get("cookie_secure", _https_ready)

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
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return   # API-token request: no cookie to forge, so CSRF doesn't apply
        csrf.protect()   # session/cookie request: full CSRF enforcement (no-op on safe methods)

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

def _json_body():
    """Request JSON coerced to a dict — {} for a missing, non-object (array/scalar), or malformed
    body. Guards every endpoint's `.get(...)` from crashing on a hostile/buggy request body."""
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def _wants_json():
    """True when the caller is an in-page fetch() (so form-POST endpoints can answer with JSON and
    let the page update in place instead of doing a full redirect+reload). The global fetch wrapper
    in base.html sets X-Requested-With; a real browser form navigation does not."""
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or ""))


def _form_ok(message, endpoint, **values):
    """Success result for an action form: JSON for an in-page fetch (so the page updates in place),
    else the classic flash + redirect for a plain browser submit."""
    if _wants_json():
        return jsonify({"success": True, "message": message})
    flash(message, "success")
    return redirect(url_for(endpoint, **values))


def _form_err(message, endpoint, code=400, category="danger", **values):
    """Failure result for an action form: JSON (+ status) for a fetch, else flash + redirect."""
    if _wants_json():
        return jsonify({"success": False, "message": message}), code
    flash(message, category)
    return redirect(url_for(endpoint, **values))


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
            "csp_nonce": getattr(g, "csp_nonce", ""),
            "nav_remotes": nav_remotes,
            "local_remote_id": local_remote_id,
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
    server. A block of _port_span(game_type) ports must clear both (a) the ports other panel
    game servers on this remote reserve — each per its own game's span — and (b) whatever is
    actually listening on the host right now. Returns (start_port, changed).

    The span makes the increment game-correct: single-port games (most, incl. Call of Duty and
    Source) pack sequentially (28960, 28961, …) instead of wastefully skipping every other
    port, while multi-port games (Rust, Valheim, …) still reserve their whole adjacent block."""
    span = _port_span(game_type)
    # Whatever is currently listening on the host (cached scan) — covers running servers'
    # FULL real footprint (game + query + rcon + …) and any non-panel service, so we never
    # land on one even if a game's span table entry is imperfect.
    occupied = set(_remote_listening_ports(remote))
    # Plus every panel server's reserved block (covers STOPPED servers, which aren't listening).
    for e in GameServer.query.filter_by(remote_id=remote_id).all():
        for k in range(_port_span(e.game_type)):
            occupied.add(e.port + k)
    p = _first_free_block(desired, span, occupied)
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
    return {"name": name[:80], "command_template": template[:500],
            "argument_label": arg_label[:80], "argument_pattern": arg_pattern[:200],
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
    for b in list_game_backups(gs.remote, gs.short_name):
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
    try:
        remote.update_pro_cache(data)
        db.session.commit()
    except Exception:
        db.session.rollback()
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
    anything."""
    roles = {j.get("role") for j in (jobs or [])}
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
            res = remote_os_check_updates(remote) or {}
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

def _log_and_generic(context):
    """Record the real exception in the server log and return a generic string,
    so raw exception text is never sent to the client (CodeQL
    py/stack-trace-exposure). Admins read the detail in the panel logs."""
    current_app.logger.exception(context)
    return "Internal server error"

def _unreachable(context):
    """A remote host that cannot be reached is a NORMAL condition for this panel, not a fault
    in it — hosts go down, networks blip, a VPS reboots. Answer 200 with an error field so the
    UI can say "host unreachable" instead of the browser logging a 500, and so 5xx alerting
    stays a signal that the PANEL is broken.

    ssh_manager raises ConnectionError for exactly this (auth failed / timed out / cannot
    resolve), which is what makes it separable from a genuine bug. Anything that is not a
    ConnectionError still returns 500, deliberately: those are ours.

    api_remote_live_stats already did this and said why in a comment; six sibling endpoints
    did not, and every one of them 500s on a host that is simply switched off."""
    current_app.logger.warning("%s: host unreachable", context)
    return jsonify({"success": False, "unreachable": True,
                    "error": "Host unreachable"}), 200

def register_routes(app):
    # Lazy, like every other panel.routes import here: those modules do
    # `from app import ...` at their top, so they can only be imported once
    # this module's own body has finished.
    from panel.routes._shared import (_begin_bootstrap, _bg_cache_commands, _maybe_resolve_public_ip, _run_due_game_backups, _run_due_restarts, _run_pending_backups, _server_action_buttons, _whitelist_mutate)

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
    @app.route("/servers/manage")
    @login_required
    @permission_required(MANAGE_SERVERS, INSTALL_SERVER)
    def manage_servers():
        remotes = RemoteServer.query.all()
        # Default to grouped-by-host order (host name, then server name); the page also lets you
        # re-sort by any column and toggle a grouped view client-side.
        from panel.db.models import ServerTag
        from sqlalchemy.orm import selectinload
        # selectinload the tags: they render per row, and this page has no per-server query budget
        # only because nothing here is lazy — keep it that way.
        all_servers = (GameServer.query.outerjoin(RemoteServer, GameServer.remote_id == RemoteServer.id)
                       .options(selectinload(GameServer.tags))
                       .order_by(RemoteServer.name.asc(), GameServer.name.asc()).all())
        all_tags = ServerTag.query.order_by(ServerTag.name).all()
        player_counts = {gs.id: _cached_player_count(gs.id) for gs in all_servers}
        player_max = {gs.id: _cached_player_max(gs.id) for gs in all_servers}
        server_names = {gs.id: _cached_player_name(gs.id) for gs in all_servers}
        can_control = current_user.is_superadmin or bool(
            {START_SERVER, STOP_SERVER, RESTART_SERVER} & get_user_permissions(current_user))
        # Only downloadable games on the install form — the target host isn't chosen yet, so we can't
        # know what mount-only (owned) content is already present. Those show on the server's own page.
        gmod_games = [{"key": k, "label": v[0], "size": GMOD_CONTENT_SIZES.get(k, "")}
                      for k, v in GMOD_CONTENT_GAMES.items() if v[1] is not None]
        return render_template("manage_servers.html", remotes=remotes,
                               all_servers=all_servers, games=load_game_list(),
                               can_control=can_control, gmod_games=gmod_games,
                               player_counts=player_counts, player_max=player_max,
                               server_names=server_names, all_tags=all_tags,
                               can_edit_tags=(current_user.is_superadmin
                                              or has_permission(current_user, MANAGE_SERVERS)))

    def _notify_servers_changed():
        """Best-effort broadcast to every connected browser that the game-server set
        changed (one was added or removed), so open dashboards / Game Servers pages
        reconcile live instead of waiting for a manual refresh. A dropped broadcast must
        never affect the actual install/uninstall, so this is fully swallowed."""
        try:
            sio = getattr(app, "socketio", None)
            if sio is not None:
                sio.emit("servers_changed", {})
        except Exception:
            _log.debug("UI-nicety broadcast only — never let it affect the install/uninstall", exc_info=True)

    @app.route("/servers/add", methods=["POST"])
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def install_game_server():
        remote_id = request.form.get("remote_id", type=int)
        game_type = request.form.get("game_type", "").strip().lower()
        server_name = request.form.get("server_name", "").strip()
        port = request.form.get("port", "27015").strip()
        remote = get_remote(remote_id)

        # SECURITY: game_type and server_name become Linux users / paths / root shell
        # arguments during install — validate strictly to prevent command injection.
        if not GAME_TYPE_RE.match(game_type) or game_type not in {g["shortname"] for g in load_game_list()}:
            return _form_err("Invalid or unknown game type.", "manage_servers")
        if server_name:
            server_name = server_name.lower()
            if not INSTANCE_NAME_RE.match(server_name):
                return _form_err("Server name must be lowercase letters, numbers, - or _ and start with "
                                 "a letter (it becomes a Linux user on the host).", "manage_servers")

        # Canonical LinuxGSM server name — always "{shortname}server".
        lgsm_name = f"{game_type}server"
        short_name = server_name or lgsm_name

        # Best-effort default port per game for the install form. This is only a
        # pre-install HINT — after install the panel reads LinuxGSM's real port(s)
        # via `details` and opens every one, so an imperfect default self-corrects.
        KNOWN_PORTS = {
            # Source engine — default 27015
            "gmod": 27015, "cs": 27015, "css": 27015, "cs2": 27015, "csgo": 27015,
            "tf2": 27015, "hl2dm": 27015, "hldm": 27015, "hldms": 27015, "dods": 27015,
            "ins": 27015, "insurgency": 27015, "nmrih": 27015, "l4d": 27015, "l4d2": 27015,
            "zps": 27015, "fof": 27015, "gesource": 27015, "cscz": 27015, "tfc": 27015,
            "ns": 27015, "ricochet": 27015, "dmc": 27015, "sfc": 27015, "bb2": 27015,
            "unturned": 27015, "bt": 27015,
            # Call of Duty — 28960
            "cod": 28960, "coduo": 28960, "cod2": 28960, "cod4": 28960, "codwaw": 28960,
            # Minecraft family
            "mc": 25565, "pmc": 25565, "spigot": 25565, "paper": 25565, "bukkit": 25565,
            "mcbe": 19132, "mcb": 19132,
            # Survival / sandbox
            "rust": 28015, "sdtd": 26900, "7d2d": 26900, "valheim": 2456, "vh": 2456,
            "ark": 7777, "pz": 16261, "projectzomboid": 16261, "terraria": 7777,
            "tshock": 7777, "factorio": 34197, "avorion": 27000, "eco": 3000, "vs": 42420,
            # Mil-sim / shooters
            "arma3": 2302, "squad": 7787, "mordhau": 7777, "kf": 7707, "kf2": 7777,
            "q2": 27910, "q3": 27960, "ql": 27960, "et": 27960, "etl": 27960, "rtcw": 27960,
            "xonotic": 26000, "ut99": 7777, "ut2k4": 7777,
            # Voice / misc
            "mumble": 64738, "ts3": 9987, "samp": 7777, "mta": 22003, "openttd": 3979,
        }
        if not port or port == "27015":
            port = str(KNOWN_PORTS.get(game_type, 27015))
        try:
            desired_port = int(port)
        except (TypeError, ValueError):
            desired_port = KNOWN_PORTS.get(game_type, 27015)

        # Allocate the install "slot" atomically: pick a free port, reject a duplicate name and
        # create the row under one lock. resolve_free_port yields on an SSH scan, so without the
        # lock two concurrent installs on the same remote could pick the same port or both clear the
        # duplicate-name check before either committed.
        with _install_alloc_lock:
            # Port-conflict handling: auto-pick the next free port if taken.
            final_port, port_changed = resolve_free_port(remote, remote_id, desired_port, game_type)

            # Name conflict: if the user TYPED the name it's a real conflict; if they left it blank
            # (using the "{game}server" default), auto-suffix a number so leaving it blank always
            # works — the same courtesy the port gets above.
            def _name_taken(n):
                return GameServer.query.filter_by(short_name=n, remote_id=remote_id).first() is not None
            name_changed = False
            if _name_taken(short_name):
                if server_name:
                    return _form_err(f"A server named '{short_name}' already exists on this remote — "
                                     f"pick a different name.", "manage_servers")
                _n = 2
                while _name_taken(f"{lgsm_name}{_n}") and _n < 100:
                    _n += 1
                short_name = f"{lgsm_name}{_n}"
                name_changed = True

            # Create the DB row up-front in the "installing" state, then run the WHOLE
            # install in a background job with live step-by-step progress (polled by the
            # Game Servers page — mirrors the VPS bootstrap progress). The route returns
            # immediately so the browser never waits on the long download.
            gs = GameServer(
                remote_id=remote_id, name=server_name or short_name, short_name=short_name,
                game_type=game_type, game_display=game_type, port=final_port,
                installed=False, status="installing",
            )
            db.session.add(gs)
            db.session.commit()
        # Start the server's scheduled-backup clock now, so a brand-new install isn't seen as
        # immediately "due" and backed up mid-install (its first scheduled backup is one interval
        # out). Without this, last=0 makes game_backup_due() true the moment installed flips True.
        bk.record_game_backup(gs.id)

        # GMod is the one game that needs mounted content to render maps/props — offer the picked
        # games (validated against the known set). This adds a content step to the install job.
        content_games = ([g for g in request.form.getlist("content_games") if g in GMOD_CONTENT_GAMES]
                         if game_type == "gmod" else [])
        _prune_jobs(_install_jobs, _install_lock)
        with _install_lock:
            _install_jobs[gs.id] = {
                "status": "running", "step": 0, "total": (9 if content_games else 8),
                "step_name": "Queued",
                "message": "", "log": [], "started": time.time(), "updated": time.time(),
                "name": gs.name,
            }
        _run_install_job(gs.id, remote_id, short_name, game_type, lgsm_name, final_port, content_games)
        _notify_servers_changed()   # new "installing" row → appears live on other sessions

        log_action(current_user, "install_server", target=gs.name,
                   detail=f"Type: {game_type}, port: {final_port}")
        port_note = (f" (port {desired_port} was busy — using {final_port})" if port_changed else "")
        name_note = (f" (the default name was taken — using '{short_name}')" if name_changed else "")
        return _form_ok(f"Installing {short_name} on port {final_port}{port_note}{name_note}. "
                        f"Progress is shown live below.", "manage_servers")

    def _run_install_job(gs_id, remote_id, short_name, game_type, lgsm_name, final_port, content_games=None):
        """Full game-server install as a tracked background job with step progress.
        Steps (8, or 9 for GMod-with-content): user → LinuxGSM → deps → game files → config →
        port/firewall → autostart → [GMod content] → start. Progress → _install_jobs[gs_id]."""
        content_games = content_games or []
        _app = app

        def _p(step, name, status="running", message=""):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                if j is None:
                    return
                j["step"], j["step_name"], j["status"], j["updated"] = step, name, status, time.time()
                if message:
                    j["message"] = message
                j["log"].append(f"[{step}/{j['total']}] {name}")

        def _fail(name, detail=""):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                cur = j["step"] if j else 0
            _p(cur, name, status="failed", message=detail)

        def _finish(msg, warn=False):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                if j is not None:
                    j["status"], j["step"] = "done", j["total"]
                    j["step_name"], j["message"], j["updated"] = "Complete", msg, time.time()
                    j["warn"] = bool(warn)   # done, but with a caveat (e.g. installed yet didn't start)

        def _run():
            try:
                from panel.db.models import db, RemoteServer, GameServer
                with _app.app_context():
                    remote = db.session.get(RemoteServer, remote_id)
                    gs = db.session.get(GameServer, gs_id)
                    if not remote or not gs:
                        return
                    # Hard stop before any destructive root command below: an empty short_name
                    # would turn `rm -rf /home/{short_name}` into `rm -rf /home/` (every home dir).
                    # It's always set upstream (server_name or lgsm_name), but never trust that here.
                    if not short_name:
                        _fail("Preparing user account", "internal error: missing instance name")
                        return

                    # 1. User account (clean any half-finished leftover first).
                    _p(1, "Preparing user account")
                    chk, _, _ = run_command(remote, f"test -x /home/{short_name}/linuxgsm.sh && echo EXISTS || echo NOTEXISTS", timeout=10)
                    if "NOTEXISTS" in chk:
                        # Was one root shell running `userdel -r X; rm -rf /home/X`. Two verbs
                        # now, and the home path is built by the helper from the validated name
                        # rather than interpolated into an `rm -rf`.
                        run_privileged(remote, "user-delete", [short_name], timeout=15,
                                       merge_stderr=False)
                        run_privileged(remote, "user-remove-home", [short_name], timeout=15,
                                       merge_stderr=False)
                    idout, _, _ = run_command(remote, f"id {short_name} 2>/dev/null && echo EXISTS || echo NOTEXISTS", timeout=10)
                    if "NOTEXISTS" in idout:
                        run_privileged(remote, "user-create", [short_name], timeout=15)
                        time.sleep(0.3)

                    # 2. Download & set up LinuxGSM (canonical script name).
                    _p(2, "Downloading LinuxGSM")
                    install_cmd = (f"sudo -u {short_name} bash -c 'cd /home/{short_name} && "
                                   f"wget -q -O linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh && "
                                   f"bash linuxgsm.sh {lgsm_name}' 2>&1")
                    out = err = ""; rc = -1
                    for attempt in range(10):
                        out, err, rc = run_command(remote, install_cmd, timeout=300, sudo=False)
                        if "unknown user" not in (out + err):
                            break
                        time.sleep(0.5 * (attempt + 1))
                    if "Unknown game server" in out:
                        _fail("Invalid game type", f"'{game_type}' is not a valid LinuxGSM shortname."); return
                    if rc != 0:
                        _fail("LinuxGSM setup failed", (out or err)[-300:]); return

                    # 3. System dependencies (as root — the game user has no sudo).
                    _p(3, "Installing dependencies")
                    try:
                        install_game_dependencies(remote, game_type)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 4. Download the game server files (the long step). A truncated / corrupt archive
                    #    can leave LinuxGSM "done" — even with exit code 0 — but with NO game files
                    #    (exactly how a bad cod2 download failed silently). So DON'T trust the exit
                    #    code: after each attempt verify the files actually landed (_looks_installed),
                    #    and on failure wipe LinuxGSM's cached download and retry from scratch.
                    auto = f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} auto-install' 2>&1"
                    installed_ok = False
                    last_out = ""
                    for attempt in range(3):
                        _p(4, "Downloading game server files (this can take a while)"
                              + ("" if attempt == 0 else " — retry %d" % attempt))
                        out, err, rc = run_command(remote, auto, timeout=1800, sudo=False)
                        last_out = out or err or last_out
                        missing = parse_missing_deps((out or "") + "\n" + (err or ""))
                        if missing:
                            try:
                                install_game_dependencies(remote, game_type, extra=" ".join(missing))
                                out, err, rc = run_command(remote, auto, timeout=1800, sudo=False)
                                last_out = out or err or last_out
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                        # The real test — did the game files actually install? rc alone lies on a
                        # corrupt/truncated download.
                        if _looks_installed(remote, short_name, lgsm_name) is True:
                            installed_ok = True
                            break
                        # Not really installed: wipe LinuxGSM's cached (likely corrupt) archive so the
                        # next attempt re-downloads fresh instead of reusing the bad file.
                        try:
                            run_command(remote, f"sudo -u {short_name} bash -c "
                                        f"'rm -rf /home/{short_name}/lgsm/tmp/* 2>/dev/null; echo cleared'",
                                        timeout=30, sudo=False)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)
                    if not installed_ok:
                        gs.installed = False; gs.status = "failed"; db.session.commit()
                        _fail("Game files didn't install after 3 tries — the download may be corrupt or "
                              "the mirror unreachable. Try again shortly.", last_out[-300:]); return
                    # Files have landed — the server IS installed, but it still needs configuring
                    # and starting (steps 5-8). Use a distinct "configuring" status (NOT "installing")
                    # so the state model is honest: the status poller skips it just like "installing"
                    # (it isn't fully up yet), and if the panel restarts before step 8 the reconciler
                    # heals it instead of it sitting stuck.
                    gs.installed = True; gs.status = "configuring"; db.session.commit()

                    # 5. Configure: cache command list + maintenance cron + Minecraft EULA.
                    _p(5, "Configuring server")

                    # Make LinuxGSM actually use the free port we reserved at request time
                    # (resolve_free_port already skipped ports taken by another server or listening
                    # on the host). auto-install used the game's DEFAULT port, which can collide with
                    # another server — so write our port into the instance config. Step 6 then reads
                    # it back via `details` and opens it, instead of overwriting with the default.
                    try:
                        lgsm_write_config(remote, short_name, lgsm_name, {"port": final_port})
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)
                    # Source games also bind a SourceTV + client port; if a sibling Source server
                    # already holds the defaults (27020/27005), -strictportbind makes this one QUIT
                    # on start. Move ours to free ports before the first start so it can come up.
                    try:
                        aux = _resolve_source_aux_ports(remote, remote_id, short_name, lgsm_name, final_port)
                        if aux:
                            lgsm_write_config(remote, short_name, lgsm_name, aux)
                            _log.info("install %s: reassigned Source aux ports %s", short_name, aux)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)
                    try:
                        cmds = list_server_commands(remote, short_name, gs.lgsm_name)
                        if cmds:
                            gs.set_commands(cmds); db.session.commit()
                            try:
                                supported = {c["cmd"] for c in cmds}
                                install_game_cron(remote, short_name, gs.lgsm_name, supported)
                                # install_game_cron schedules `monitor` when the game has it, and
                                # that line IS the Autostart switch — record it, or the Details
                                # page shows Off while monitor is scheduled and running.
                                if "monitor" in supported and not gs.autostart:
                                    gs.autostart = True
                                    db.session.commit()
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)
                    if gs.game_type in ("mc", "mcbe", "pmc", "spigot", "paper"):
                        try:
                            run_command(remote, f"sudo -u {short_name} bash -c \"echo 'eula=true' > /home/{short_name}/serverfiles/eula.txt 2>/dev/null; true\"", timeout=15, sudo=False)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)
                    # Source/GoldSrc: make the server reload its ban list on every start, so a banid
                    # ban actually survives a restart (without this the engine drops it on reboot and
                    # the player rejoins). Best-effort.
                    if sm_game_engine(gs.game_type) == "valve":
                        try:
                            ensure_persistent_bans(remote, short_name, lgsm_name)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 6. Sync to LinuxGSM's real port(s) and open ALL of them (many
                    #    games need game+query+rcon+etc., not just the main port).
                    _p(6, "Detecting ports & opening firewall")
                    try:
                        info = detect_game_ports(remote, short_name, gs.lgsm_name)
                        real_port = info.get("game_port")
                        if real_port and real_port != gs.port:
                            old_port = gs.port; gs.port = real_port; db.session.commit()
                            try:
                                remote_ufw_close_game_port(remote, old_port)
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                        to_open = info.get("open_ports") or ([gs.port] if gs.port else [])
                        remote_ufw_allow_game_ports(remote, to_open, short_name)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 7. Enable autostart by default (the LinuxGSM monitor cron; install_game_cron
                    #    above already adds it when supported — this ensures it either way).
                    _p(7, "Enabling autostart (monitor)")
                    try:
                        set_autostart(remote, short_name, True, gs.lgsm_name)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 8 (GMod only, if requested). Mountable content: reuse an existing content user's
                    # games or download them (SteamCMD), grant read access, and write GMod's mount.cfg —
                    # BEFORE start, so the server comes up with content already mounted and the content
                    # group in effect. Best-effort: a content failure never fails the install.
                    start_step = 8
                    if content_games and game_type == "gmod":
                        start_step = 9
                        labels = ", ".join(GMOD_CONTENT_GAMES[g][0]
                                           for g in content_games if g in GMOD_CONTENT_GAMES)
                        _p(8, "Installing GMod content (%s)" % (labels or "content"))
                        try:
                            cu = ensure_content_user(remote)
                            if cu:
                                install_gmod_content(remote, cu["user"], content_games,
                                                     on_progress=lambda m: _p(8, m))
                                ok_m, msg_m = gmod_mount_setup(remote, short_name, cu["user"], content_games)
                                if not ok_m:
                                    _log.warning("gmod content mount for %s: %s", short_name, msg_m)
                            else:
                                _log.warning("gmod content: no content user could be prepared on %s", remote.name)
                        except Exception:
                            _log.warning("gmod content setup failed for %s", short_name, exc_info=True)

                    # Start the server — then VERIFY it actually came up. LinuxGSM's `start` exit
                    # code alone can lie: a port taken under -strictportbind, or a crash-on-boot, can
                    # still exit 0 or just flap. So capture the start log and confirm the game port is
                    # really listening a few seconds later; if it isn't, mark it offline and surface
                    # the reason from the log instead of a bare "offline".
                    _p(start_step, "Starting server")
                    start_out = ""
                    try:
                        start_out, _, s_rc = run_as_game_user(remote, short_name, "start 2>&1", timeout=120, selfname=gs.lgsm_name)
                    except Exception:
                        s_rc = 1
                        _log.debug("_run: start command failed", exc_info=True)
                    really_up = False
                    try:
                        for _ in range(5):                    # poll ~15s: give a heavy first boot time to bind
                            time.sleep(3)
                            _invalidate_port_scan(remote.id)  # force a fresh scan each try
                            if gs.port and gs.port in _remote_listening_ports(remote):
                                really_up = True
                                break
                    except Exception:
                        really_up = (s_rc == 0)               # host unreachable — fall back to the exit code
                    gs.status = "online" if really_up else "offline"
                    db.session.commit()

                    # Now that it's actually run once, re-read the ports and open any that only
                    # become visible at runtime. A no-op for the static-config majority (step 6 already
                    # opened them before start); future-proofs a game whose effective ports settle on
                    # first start. Best-effort — ufw allow is idempotent.
                    try:
                        info2 = detect_game_ports(remote, short_name, gs.lgsm_name)
                        extra = info2.get("open_ports") or []
                        if extra:
                            remote_ufw_allow_game_ports(remote, extra, short_name)
                    except Exception:
                        _log.debug("_run: post-start port re-detect failed", exc_info=True)

                    if really_up:
                        _finish(f"{short_name} installed and started")
                        log_action(None, "install_complete", target=gs.name, success=True)
                    else:
                        reason = _extract_start_error(start_out)
                        note = f"{short_name} installed, but it didn't start"
                        note += (" — " + reason) if reason else " — check the console for the reason."
                        _finish(note, warn=True)
                        log_action(None, "install_complete", target=gs.name, success=False,
                                   detail=(("start failed: " + reason) if reason else "start failed")[:300])
            except Exception as e:
                with _install_lock:
                    j = _install_jobs.get(gs_id)
                    if j is not None:
                        j["status"], j["message"], j["updated"] = "failed", str(e), time.time()
                app.logger.exception("install job failed")

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/servers/<int:server_id>/delete", methods=["POST"])
    @login_required
    @permission_required(UNINSTALL_SERVER)
    @server_access_required   # get_game() does NOT check access; the permission alone is not enough
    def uninstall_server(server_id):
        gs = get_game(server_id)
        name = gs.name   # capture before the row is deleted (used in the success/error message)
        # Refuse to uninstall while an install is in progress — deleting the user/files out from
        # under the running install job corrupts it (and can orphan processes). The UI disables the
        # button too, but guard the endpoint as well (belt and suspenders).
        with _install_lock:
            _installing = (server_id in _install_jobs
                           and _install_jobs[server_id].get("status") == "running")
        if _installing or (gs.status == "installing" and not gs.installed):
            _m = "'%s' is still installing — wait for it to finish before uninstalling." % name
            if _wants_json():
                return jsonify({"success": False, "message": _m}), 409
            flash(_m, "warning")
            return redirect(url_for("manage_servers"))
        remote = gs.remote
        short_name = gs.short_name
        game_port = gs.port
        selfname = gs.lgsm_name

        try:
            # Stop the game server and kill any lingering processes BEFORE deleting the user.
            # Otherwise userdel removes the user + home while the game process is still running —
            # leaving it orphaned under a now-deleted uid: not manageable from the panel, and still
            # eating CPU/RAM and holding its port. Graceful LinuxGSM stop first, then a hard kill of
            # anything left, then delete.
            try:
                run_as_game_user(remote, short_name, "stop 2>&1", timeout=60, selfname=selfname)
            except Exception:
                _log.debug("uninstall: graceful stop failed; force-killing next", exc_info=True)
            try:
                run_privileged(remote, "user-kill-processes", [short_name], timeout=20,
                               merge_stderr=False)
                time.sleep(1)   # the `; sleep 1` that used to ride along inside the root shell
            except Exception:
                _log.debug("uninstall: pkill failed; proceeding to userdel", exc_info=True)

            # Close ALL of this server's firewall rules (multi-port games tag every
            # rule with the server name), then also the legacy single-port cleanup.
            fw_note = ""
            try:
                count, _ = remote_ufw_close_by_name(remote, short_name)
                remote_ufw_close_game_port(remote, game_port)
                if count > 0:
                    fw_note = f" {count} firewall rule(s) removed."
            except Exception:
                _log.debug("uninstall_server: ignored non-fatal error", exc_info=True)

            # Remove LinuxGSM user and home.
            #
            # THE EXIT CODE DECIDES WHETHER THE ROW GOES. run_privileged RETURNS rc rather than
            # raising, and this used to feed it to log_action and nothing else — so a userdel that
            # FAILED still deleted the panel's row and still answered "Server 'x' uninstalled."
            # The account, its home and every game file stayed on the host, now with no row to
            # manage them from, the firewall rules already removed, and the next install of that
            # game colliding with the surviving user. The audit log was the only trace.
            #
            # userdel's codes, which is why this is not a bare `rc == 0`:
            #   0   removed
            #   6   no such user — already gone, so there is nothing to orphan and the row SHOULD go
            #   12  the account was removed but its home could not be — partial, worth saying out loud
            #   *   the account is still there; keeping the row is what lets the operator retry
            out, err, rc = run_privileged(remote, "user-delete-force", [short_name], timeout=30)
            _gone = rc in (0, 6, 12)
            log_action(current_user, "uninstall_server", target=gs.name, success=_gone)
            if not _gone:
                _em = ("Could not remove the '%s' account on %s, so '%s' has been left in place — "
                       "nothing was deleted from the panel. %s"
                       % (short_name, remote.display_name, name,
                          (err or out or "userdel exited %d" % rc).strip()[:200]))
                if _wants_json():
                    return jsonify({"success": False, "message": _em}), 500
                flash(_em, "danger")
                return redirect(url_for("manage_servers"))
            if rc == 12:
                fw_note += (" The account was removed but its home directory could not be — "
                            "check /home/%s on the host." % short_name)

            # Remove from DB
            db.session.delete(gs)
            db.session.commit()
            # Clean up this server's per-server backup schedule + status so nothing is orphaned
            # (and can't be inherited if SQLite reuses the row id for a future server).
            try:
                bk.remove_game_schedule(server_id)
                _game_backup_status.pop(server_id, None)
            except Exception:
                _log.debug("uninstall: schedule cleanup failed", exc_info=True)
            _notify_servers_changed()   # row disappears live on other sessions
            _m = f"Server '{name}' uninstalled.{fw_note}"
            if _wants_json():
                return jsonify({"success": True, "message": _m})
            flash(_m, "success")
            return redirect(url_for("manage_servers"))

        except Exception:
            _em = _log_and_generic("uninstall failed")
            log_action(current_user, "uninstall_server", target=name, success=False)
            if _wants_json():
                return jsonify({"success": False, "message": _em}), 500
            flash(_em, "danger")
            return redirect(url_for("manage_servers"))

    @app.route("/servers/<int:server_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    @server_access_required   # same: MANAGE_SERVERS is not a grant for EVERY server
    def edit_server(server_id):
        """Rename a game server's DISPLAY labels. Nothing here touches the host.

        Two things were wrong with the previous version, and both only ever showed up through a
        direct API call — no template or script references this route.

        `name` and `game_display` were written straight from the form. Every other label the panel
        stores goes through SAFE_LABEL_RE first (add_remote / edit_remote do), and SQLite does not
        enforce VARCHAR length, so this was the one write that accepted any bytes at any size.

        `port` was worse: it moved the panel's RECORD of the port and nothing else. The firewall
        rule stays on the old port, LinuxGSM keeps listening there, and the monitor — which decides
        a server is up by `gs.port in <listening ports>` — then reports it permanently offline. A
        port really does change in three places at once, which is what the install flow and the
        Firewall page's "Open all ports" (sync-ports) do together. So this refuses rather than
        silently desyncing: a refusal names the right mechanism, a silent write hides it.
        """
        gs = get_game(server_id)
        new_port = (request.form.get("port") or "").strip()
        if new_port and _int_or(new_port, gs.port) != gs.port:
            return _form_err(
                "The port can't be changed here — it would only move the panel's record, leaving "
                "the game server and the firewall on the old port. Change it in the server's "
                "LinuxGSM config, then use 'Open all ports' on the Firewall page.",
                "manage_servers")
        name = (request.form.get("name") or gs.name or "").strip() or gs.name
        game_display = (request.form.get("game_display") or gs.game_display or "").strip()
        for _label, _value in (("Name", name), ("Game", game_display)):
            if _value and not SAFE_LABEL_RE.match(_value):
                return _form_err("%s can't be empty, longer than 120 characters, or contain "
                                 "< > \" ' ` or backslashes." % _label, "manage_servers")
        gs.name = name
        gs.game_display = game_display
        db.session.commit()
        log_action(current_user, "edit_server", target=gs.name)
        return _form_ok(f"Server '{gs.name}' updated.", "manage_servers")

    # ── Remote Server Management ───────────────────────────
    @app.route("/remotes")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def manage_remotes():
        # Only actual remote VPSes — the panel's own host is managed under
        # System → Panel Server, not here. Non-superadmins only see remotes their
        # groups grant (consistent with the per-host access enforced in get_remote).
        remotes = RemoteServer.query.filter_by(is_local=False).order_by(RemoteServer.name).all()
        if not current_user.is_superadmin:
            allowed = accessible_remote_ids(current_user)
            remotes = [r for r in remotes if r.id in allowed]
        return render_template("manage_remotes.html", remotes=remotes,
                               tailscale_installed=ts.get_tailscale_info().installed)

    @app.route("/remotes/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def add_remote():
        name = request.form.get("name", "").strip()
        host = request.form.get("host", "").strip()
        ssh_user = request.form.get("ssh_user", "root").strip()
        ssh_port = _int_or(request.form.get("ssh_port"), 22)
        auth_method = request.form.get("auth_method", "key")
        credential = request.form.get("credential", "").strip()
        sudo_enabled = request.form.get("sudo_enabled") == "on"
        lgsm_user = request.form.get("lgsm_user", "").strip()
        is_local = request.form.get("is_local") == "1"

        if not name or not SAFE_LABEL_RE.match(name):
            return _form_err("Name is required and cannot contain < > \" ' ` or backslashes.", "manage_remotes")

        # SECURITY: these reach `sudo -u <user>` / SSH command construction — validate
        # to a safe Linux-username charset so they can't inject shell commands.
        if lgsm_user and not LINUX_USER_RE.match(lgsm_user):
            return _form_err("LinuxGSM user must be a valid Linux username (lowercase letters, numbers, - or _).",
                             "manage_remotes")
        if ssh_user and not LINUX_USER_RE.match(ssh_user):
            return _form_err("SSH user must be a valid Linux username.", "manage_remotes")
        if not is_local and (not host or not HOST_RE.match(host)):
            return _form_err("Host must be a valid hostname or IP address.", "manage_remotes")

        if is_local:
            remote = RemoteServer(
                name=name, host="127.0.0.1", port=22,
                username="local", auth_method="local",
                auth_credential="", sudo_enabled=True,
                linuxgsm_user=lgsm_user,
                is_local=True, is_online=True,
                last_seen=utcnow(),
            )
            db.session.add(remote)
            db.session.commit()
            log_action(current_user, "add_local_remote", target=name)
            return _form_ok(f"Local server '{name}' added! You can now install game servers on this machine.",
                            "manage_remotes")

        # (host presence + charset already validated above for non-local remotes)
        success, msg = ssh_test_connection(host, ssh_port, ssh_user, auth_method, credential)
        if not success:
            return _form_err(f"Connection test failed: {msg}", "manage_remotes")

        remote = RemoteServer(
            name=name, host=host, port=ssh_port,
            username=ssh_user, auth_method=auth_method,
            auth_credential=encrypt_secret(credential),
            sudo_enabled=sudo_enabled, linuxgsm_user=lgsm_user,
            is_online=True, last_seen=utcnow(),
        )
        db.session.add(remote)
        db.session.commit()
        log_action(current_user, "add_remote", target=name, detail=f"{ssh_user}@{host}")

        # Setup type. "fresh" runs the full Prepare & Secure bootstrap (updates, UFW, SSH hardening,
        # fail2ban, deps, then reboot) for a brand-new VPS. "existing" leaves the host untouched and
        # jumps straight to scanning it for LinuxGSM servers already installed. (The old auto_bootstrap
        # checkbox is honoured as a fallback so older/cached forms still work.)
        setup_type = request.form.get("setup_type", "").strip().lower()
        if setup_type not in ("fresh", "existing"):
            setup_type = "fresh" if request.form.get("auto_bootstrap", "on") == "on" else "existing"
        if setup_type == "existing":
            flash(f"Remote '{name}' added — scanning it for existing LinuxGSM servers…", "success")
            return redirect(url_for("remote_manage", remote_id=remote.id) + "?scan=1")

        opts = {
            "set_timezone": request.form.get("timezone", "UTC") or "UTC",
            "enable_ufw": True, "install_lgsm_deps": True,
            "username": lgsm_user, "install_fail2ban": True, "do_reboot": True,
        }
        started, _ = _begin_bootstrap(app, remote.id, opts, current_user.id)
        _m = (f"Remote '{name}' added. Preparing & securing it now — watch the progress on its card."
              if started else f"Remote '{name}' added.")
        return _form_ok(_m, "manage_remotes")

    @app.route("/remotes/<int:remote_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def edit_remote(remote_id):
        remote = get_remote(remote_id)
        new_user = request.form.get("ssh_user", remote.username)
        new_lgsm = request.form.get("lgsm_user", remote.linuxgsm_user)
        # SECURITY: validate the username fields (reach `sudo -u <user>` / SSH commands).
        if new_user and not LINUX_USER_RE.match(new_user):
            return _form_err("SSH user must be a valid Linux username.", "manage_remotes")
        if new_lgsm and not LINUX_USER_RE.match(new_lgsm):
            return _form_err("LinuxGSM user must be a valid Linux username.", "manage_remotes")
        new_name = request.form.get("name", remote.name)
        if new_name and not SAFE_LABEL_RE.match(new_name):
            return _form_err("Name cannot contain < > \" ' ` or backslashes.", "manage_remotes")
        remote.name = new_name
        new_host = request.form.get("host", remote.host)
        if not remote.is_local and new_host and not HOST_RE.match(new_host):
            return _form_err("Host must be a valid hostname or IP address.", "manage_remotes")
        new_port = _int_or(request.form.get("ssh_port"), remote.port)
        # Repointing to a different host/port means the pinned key no longer applies —
        # clear it so the new target is re-pinned (TOFU) instead of failing as a mismatch.
        if (new_host, new_port) != (remote.host, remote.port):
            remote.host_key = ""
        remote.host = new_host
        remote.port = new_port
        remote.username = new_user
        remote.auth_method = request.form.get("auth_method", remote.auth_method)
        # Credential: the edit form leaves it blank to keep the current one; a new
        # value is (re)encrypted before storage.
        new_cred = request.form.get("credential", "").strip()
        if new_cred:
            remote.auth_credential = encrypt_secret(new_cred)
        remote.sudo_enabled = request.form.get("sudo_enabled") == "on"
        remote.linuxgsm_user = new_lgsm
        db.session.commit()
        log_action(current_user, "edit_remote", target=remote.name)
        return _form_ok(f"Remote '{remote.name}' updated.", "manage_remotes")

    @app.route("/remotes/<int:remote_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def delete_remote(remote_id):
        remote = get_remote(remote_id)
        name = remote.name
        # Re-authenticate: deleting a remote (and ALL its game servers) is destructive, so require
        # the operator to re-enter their own account password — a guard against an accidental or
        # hijacked click. Verified constant-time via bcrypt (check_password).
        if not check_password(_json_body().get("password", ""), current_user.password_hash):
            if _wants_json():
                return jsonify({"success": False, "message": "Incorrect password."}), 403
            flash("Incorrect password.", "danger")
            return redirect(url_for("manage_remotes"))
        # Delete associated game servers. This is a BULK delete, which bypasses the ORM entirely —
        # so every association row keyed on those game_server ids has to go by hand. This app never
        # sets PRAGMA foreign_keys, so nothing removes them for us, and SQLite reuses rowids: an
        # orphan here is later inherited by a completely unrelated server.
        _doomed_ids = [gid for (gid,) in db.session.query(GameServer.id)
                       .filter_by(remote_id=remote_id).all()]
        GameServer.query.filter_by(remote_id=remote_id).delete()
        if _doomed_ids:
            from panel.db.models import game_server_tags
            db.session.execute(game_server_tags.delete()
                               .where(game_server_tags.c.game_server_id.in_(_doomed_ids)))
            # Same shape of orphan, pre-existing: per-server group grants are keyed the same way.
            _ggs = db.Table("group_game_servers", db.metadata, autoload_with=db.engine)
            db.session.execute(_ggs.delete().where(_ggs.c.game_server_id.in_(_doomed_ids)))
        # Delete group associations
        group_servers_table = db.Table(
            "group_servers", db.metadata, autoload_with=db.engine
        )
        db.session.execute(
            group_servers_table.delete().where(
                group_servers_table.c.server_id == remote_id
            )
        )
        db.session.delete(remote)
        db.session.commit()
        close_connection(remote)
        log_action(current_user, "delete_remote", target=name)
        _m = f"Remote '{name}' deleted."
        if _wants_json():
            return jsonify({"success": True, "message": _m})
        flash(_m, "success")
        return redirect(url_for("manage_remotes"))

    @app.route("/remotes/<int:remote_id>/test", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def test_remote(remote_id):
        remote = get_remote(remote_id)
        success, msg = ssh_test_connection(
            remote.host, remote.port, remote.username,
            remote.auth_method, decrypt_secret(remote.auth_credential)
        )
        remote.is_online = bool(success)
        remote.last_seen = utcnow()
        db.session.commit()
        if success:
            return _form_ok(f"Connection to {remote.name} successful!", "manage_remotes")
        return _form_err(f"Connection failed: {msg}", "manage_remotes")

    # ── Discover + import LinuxGSM servers already installed on a host ──
    @app.route("/api/remote/<int:remote_id>/discover")
    @login_required
    @permission_required(MANAGE_SERVERS)
    def api_remote_discover(remote_id):
        """Scan a host for LinuxGSM servers already installed under any user account and return
        the ones NOT yet in the panel, mapped to a known game. Read-only — imports nothing."""
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"error": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        try:
            found = discover_linuxgsm_servers(remote)
        except Exception:
            return jsonify({"error": _log_and_generic("server discovery failed")}), 200
        existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
        games = {g["shortname"]: g["name"] for g in load_game_list()}
        out = []
        for f in found:
            user = f.get("user") or ""
            if user in existing:
                continue   # already in the panel
            gt = lgsm_name_to_game_type(f.get("lgsm_name") or "")
            if not gt or gt not in games:
                continue   # a game the panel doesn't support — don't offer a broken import
            out.append({"user": user, "game_type": gt, "game_name": games.get(gt, gt),
                        "port": f.get("port") or 0,
                        "backups": f.get("backups", 0), "mods": f.get("mods", 0),
                        "cron": f.get("cron", 0), "autostart": bool(f.get("autostart"))})
        return jsonify({"servers": out})

    @app.route("/api/remote/<int:remote_id>/import", methods=["POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    def api_remote_import(remote_id):
        """Create panel records for selected discovered servers. Each user/game_type is validated
        with the SAME strict rules as a fresh install (so an imported short_name can never carry
        shell metacharacters), and duplicates/unknowns are skipped."""
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"error": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        items = _json_body().get("servers") or []
        if not isinstance(items, list) or not items:
            return jsonify({"success": False, "message": "Nothing selected."}), 400
        existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
        game_names = {g["shortname"]: g["name"] for g in load_game_list()}
        valid_games = set(game_names)
        added, skipped = [], []
        for it in items[:100]:
            user = (it.get("user") or "").strip()
            gt = (it.get("game_type") or "").strip().lower()
            if not INSTANCE_NAME_RE.match(user) or gt not in valid_games or user in existing:
                skipped.append(user or "?")
                continue
            try:
                port = int(it.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            # Import NEVER starts or reconfigures a discovered server — it's left exactly as it
            # is (its own cron/backups/mods are read live by the panel once imported). Autostart
            # is off until you enable it here, which is what sets up the panel's monitor cron, so
            # the panel never takes over a server you didn't ask it to manage.
            db.session.add(GameServer(
                remote_id=remote_id, name=user, short_name=user, game_type=gt,
                game_display=game_names.get(gt, ""),
                port=(port if 1 <= port <= 65535 else 27015), installed=True, status="offline",
                autostart=False))
            existing.add(user)
            added.append(user)
        if added:
            db.session.commit()
            log_action(current_user, "import_servers", target=remote.name,
                       detail="added=%s" % ",".join(added))
            # Populate the imported servers' command lists so "Supported Commands" is ready
            # without a manual refresh (install caches these; import didn't).
            new_ids = [gs.id for gs in GameServer.query.filter(
                GameServer.remote_id == remote_id,
                GameServer.short_name.in_(added)).all()]
            _bg_cache_commands(app, new_ids)
        return jsonify({"success": bool(added), "added": added, "skipped": skipped})

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
    @app.route("/api/remote/<int:remote_id>/security/bans")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_bans(remote_id):
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_fail2ban_overview(remote))
        except Exception:
            return jsonify({"installed": False, "jails": [], "error": _log_and_generic("ban list failed")}), 200

    @app.route("/api/remote/<int:remote_id>/security/top-ips")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_top_ips(remote_id):
        """Top offending IPs on a remote host (last 7 days), aggregated from its fail2ban log."""
        remote = get_remote(remote_id)
        try:
            return jsonify({"ips": remote_fail2ban_top_ips(remote, 100, days=7),
                            "autoblock": remote_id in _autoblock_hosts(),
                            "threshold": _autoblock_threshold(),
                            "whitelist": _security_whitelist()})
        except Exception:
            return jsonify({"ips": [], "error": _log_and_generic("top-ips failed")}), 200

    @app.route("/api/remote/<int:remote_id>/security/block", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_block(remote_id):
        """UFW-block (all ports, permanent) an IP on a remote host."""
        remote = get_remote(remote_id)
        ip = (_json_body().get("ip") or "").strip()
        unblock = bool(_json_body().get("unblock"))
        if not unblock and tailnet_exempt_ips(remote, {ip}):
            return jsonify({"success": False, "message":
                            "%s is a Tailscale address — blocking it would cut off tailnet access." % ip})
        if not unblock and _whitelisted(ip):
            return jsonify({"success": False, "message":
                            "%s is on the security whitelist — remove it there first to block it." % ip})
        try:
            ok, msg = (remote_ufw_undeny_ip(remote, ip) if unblock else remote_ufw_deny_ip(remote, ip))
            log_action(current_user, "ufw_unblock" if unblock else "ufw_block",
                       target=ip, detail=remote.name, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("block failed")}), 500

    @app.route("/api/remote/<int:remote_id>/security/autoblock", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_autoblock(remote_id):
        """Turn the rolling auto-block (attempts >= threshold over 7 days) on/off for a remote host,
        and optionally update the shared threshold."""
        remote = get_remote(remote_id)
        enabled = bool(_json_body().get("enabled"))
        _maybe_set_threshold(_json_body())
        _set_autoblock_host(remote_id, enabled)
        log_action(current_user, "autoblock_toggle", target=remote.name, detail="on" if enabled else "off")
        if enabled:
            _run_autoblock_now(app, remote_id)
        return jsonify({"success": True, "enabled": enabled, "threshold": _autoblock_threshold()})

    @app.route("/api/remote/<int:remote_id>/security/whitelist", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_whitelist(remote_id):
        """Add/remove a global security-whitelist entry from a remote host's page (the whitelist is
        global; the panel-jail ignoreip it feeds is applied on the panel host)."""
        get_remote(remote_id)
        return _whitelist_mutate(app, _json_body())

    @app.route("/api/remote/<int:remote_id>/security/unban", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_unban(remote_id):
        remote = get_remote(remote_id)
        d = _json_body()
        jail, banned_ip = (d.get("jail") or "").strip(), (d.get("ip") or "").strip()
        try:
            ok, msg = remote_fail2ban_unban(remote, jail, banned_ip)
            log_action(current_user, "fail2ban_unban", target=banned_ip,
                       detail="%s on %s — %s" % (jail, remote.name, msg), success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("unban failed")}), 500

    @app.route("/api/remote/<int:remote_id>/security/log")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_log(remote_id):
        remote = get_remote(remote_id)
        which = request.args.get("which", "ssh")
        if which not in ("fail2ban", "ssh"):
            return jsonify({"text": "", "error": "unknown log"}), 400
        jail = (request.args.get("jail") or "").strip() or None   # only meaningful for which=fail2ban
        try:
            return jsonify({"text": remote_security_log(remote, which, 300, jail=jail)})
        except Exception:
            return jsonify({"text": "", "error": _log_and_generic("log read failed")}), 200

    @app.route("/api/panel/change-port", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_change_port():
        """Change where the panel's web server listens: its bind address and/or port. Saves the
        new binding, brings the firewall in line (a publicly-bound panel needs its port open; a
        loopback/tailnet-bound one doesn't, and a changed port's old rule is removed), then
        restarts the panel so it rebinds (on restart it re-points Tailscale Serve at the current
        port). Refuses anything that would leave the panel unreachable: a port outside 1024-65535
        / already in use / used by a local game server, a bind address that isn't a valid IP or
        isn't on this host, or a loopback-only bind without Tailscale Serve to proxy to it."""
        import ipaddress
        data = _json_body()
        cfg = load_config()
        cur_port = int(cfg.get("port", 5000))
        cur_bind = (cfg.get("bind_host") or "0.0.0.0").strip()
        new_port = _int_or(data.get("port"), cur_port)
        new_bind = str(data.get("bind_host") or cur_bind).strip()

        local = RemoteServer.query.filter_by(is_local=True).first()
        wildcard = {"0.0.0.0", "::"}
        loopback = {"127.0.0.1", "::1", "localhost"}

        # ── Validate the port ──
        if not (1024 <= new_port <= 65535):
            return jsonify({"success": False, "message": "Pick a port between 1024 and 65535."}), 400
        if new_port != cur_port:
            clash = GameServer.query.filter_by(remote_id=local.id, port=new_port).first() if local else None
            if clash:
                return jsonify({"success": False,
                                "message": f"Port {new_port} is used by game server "
                                           f"'{clash.name}'. Pick another."}), 400
            if so.port_in_use(new_port):
                return jsonify({"success": False,
                                "message": f"Port {new_port} is already in use on this host."}), 400

        # ── Validate the bind address ──
        served = bool(cfg.get("tailscale_setup_done"))
        if new_bind not in wildcard:
            try:
                ipaddress.ip_address(new_bind)
            except ValueError:
                return jsonify({"success": False,
                                "message": "Bind address must be an IP — e.g. 0.0.0.0 (all "
                                           "interfaces), 127.0.0.1 (localhost), or this host's "
                                           "Tailscale IP."}), 400
            if new_bind not in loopback:
                # A specific IP: with Tailscale Serve (which proxies to localhost) this would
                # break Serve and lock you out; without Serve it must at least be a real local IP.
                if served:
                    return jsonify({"success": False,
                                    "message": "Tailscale Serve reaches the panel on localhost, so "
                                               "bind to 0.0.0.0 (all) or 127.0.0.1 (localhost). A "
                                               "specific IP would break Serve and lock you out."}), 400
                if not so.host_has_ip(new_bind):
                    return jsonify({"success": False,
                                    "message": f"{new_bind} isn't an address on this host — the "
                                               "panel couldn't bind to it."}), 400
        if new_bind in loopback and not served:
            return jsonify({"success": False,
                            "message": "Binding to localhost only would lock you out unless "
                                       "Tailscale Serve is set up to reach the panel. Set up "
                                       "Serve first."}), 400
        if new_port == cur_port and new_bind == cur_bind:
            return jsonify({"success": False, "message": "That's already the panel's binding."}), 400

        # ── Save the new binding ──
        cfg["port"] = new_port
        cfg["bind_host"] = new_bind
        save_config(cfg)

        # ── Bring the firewall in line with the resulting exposure ──
        # Publicly bound (0.0.0.0/::) → the port must be open. Loopback/specific-IP bound → the
        # public port rule isn't needed, so close it. A changed port also gets its old rule gone.
        now_public = new_bind in wildcard
        fw_note = ""
        if local:
            try:
                if now_public:
                    remote_ufw_open_port(local, new_port, "tcp", "LinuxGSM Panel")
                    fw_note = f" Firewall: opened {new_port}."
                else:
                    remote_ufw_close_port(local, new_port, "tcp")
                    fw_note = f" Firewall: {new_port} kept tailnet-only."
                if new_port != cur_port:
                    remote_ufw_close_port(local, cur_port, "tcp")
                    fw_note += f" Removed the old rule for {cur_port}."
            except Exception:
                app.logger.warning("change-port: firewall update failed", exc_info=True)

        # Keep the fail2ban panel-login jail pointed at the new port so brute-force protection
        # follows the move. Idempotent + best-effort; a no-op if the jail isn't set up.
        if new_port != cur_port:
            try:
                # _security_whitelist() is NOT optional here: ensure_panel_fail2ban REWRITES the
                # jail whenever the port changes, and an omitted ignore_ips writes an ignoreip of
                # localhost only — silently dropping every whitelisted IP/CIDR until the next boot
                # re-applies it (or indefinitely, if the restart below fails).
                so.ensure_panel_fail2ban(AUTH_LOG_PATH, new_port, _security_whitelist())
            except Exception:
                app.logger.warning("change-port: fail2ban port update failed", exc_info=True)

        log_action(current_user, "panel_change_binding",
                   detail=f"{cur_bind}:{cur_port} -> {new_bind}:{new_port}", success=True)
        ok, _ = so.restart_panel()
        if not ok:
            return jsonify({"success": False,
                            "message": "Saved the new binding, but couldn't restart the panel "
                                       "automatically — restart it (or reboot the host) to apply."}), 200
        return jsonify({"success": True, "new_port": new_port, "old_port": cur_port,
                        "new_bind": new_bind, "port_changed": new_port != cur_port,
                        "served_over_tailscale": bool(cfg.get("tailscale_setup_done")),
                        "message": f"Panel binding to {new_bind}:{new_port}. Restarting…{fw_note}"})

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
    @app.route("/api/dashboard/metrics")
    @login_required
    def api_dashboard_metrics():
        """Live resource metrics for the dashboard / manage pages: per-server game CPU%/RAM/uptime,
        and per-host whole-VPS CPU%/RAM%/disk%/uptime. Each server is one cached SSH sample, taken in
        parallel; polled on a slower cadence than the status feed so it stays cheap."""
        servers = get_user_servers(current_user)
        # One pass over the rows already in hand: the hosts are joinedloaded, so naming them and
        # answering "is this host local?" below costs no further queries.
        remote_by_id = {gs.remote_id: gs.remote for gs in servers if gs.remote_id and gs.remote}
        work = _metrics_work(servers)
        out_servers, hosts = {}, {}
        if work:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(work))) as ex:
                for sid, m, rid, mp in ex.map(_query_server_metrics, work):
                    if not m:
                        continue
                    out_servers[str(sid)] = {
                        "cpu": round(m.get("game_cpu_percent") or 0, 1),
                        "ram_mb": int(m.get("game_ram_mb") or 0),
                        "uptime": int(m.get("game_uptime_secs") or 0),
                        "up": bool(m.get("game_procs")),   # a live game process, not just a listening port
                        "map": mp or "",
                    }
                    if rid is not None and str(rid) not in hosts:
                        rt, dt = m.get("ram_total") or 0, m.get("disk_total") or 0
                        _rem = remote_by_id.get(rid)
                        hosts[str(rid)] = {
                            "name": getattr(_rem, "display_name", "") or "",
                            "local": bool(getattr(_rem, "is_local", False)),
                            "cpu": round(m.get("cpu_percent") or 0, 1),
                            "ram_pct": round(100.0 * (m.get("ram_used") or 0) / rt, 1) if rt else 0,
                            "disk_pct": round(100.0 * (m.get("disk_used") or 0) / dt, 1) if dt else 0,
                            "uptime": int(m.get("uptime_secs") or 0),
                            "cores": int(m.get("cores") or 1),
                        }
        return jsonify({"servers": out_servers, "hosts": hosts})

    @app.route("/api/server/<int:server_id>/history")
    @login_required
    @server_access_required
    def api_server_history(server_id):
        """Down-sampled CPU/RAM/player time series for the history charts (range=24h|7d), plus the
        host's CPU/RAM/disk over the same window. Capped to ~240 points so the chart stays light."""
        gs = get_game(server_id)
        rng = "7d" if request.args.get("range") == "7d" else "24h"
        since = utcnow() - timedelta(hours=(168 if rng == "7d" else 24))
        # with_entities, not the mapped class: the 7-day window is ~10k samples, of which at most
        # 240 survive down-sampling. Building a full ORM instance (and an identity-map entry) for
        # every discarded row was ~80% of this endpoint's time. Rows are plain named tuples.
        srows = (db.session.query(MetricSample.ts, MetricSample.cpu, MetricSample.ram_mb,
                                  MetricSample.players)
                 .filter(MetricSample.server_id == server_id, MetricSample.ts >= since)
                 .order_by(MetricSample.ts.asc()).all())
        sstep = max(1, len(srows) // 240)
        # Players is a spiky, low-integer metric: plain decimation (every sstep-th sample) silently
        # drops peaks that land on discarded samples — and 24h vs 7d use different steps, so they drop
        # DIFFERENT sessions and disagree. Take the MAX players over each point's window so no peak or
        # session is lost. CPU/RAM stay point-sampled (a level metric reads fine decimated).
        server = []
        for i in range(0, len(srows), sstep):
            r = srows[i]
            pv = [w.players for w in srows[i:i + sstep] if w.players is not None]
            server.append({"t": r.ts.isoformat() + "Z", "cpu": r.cpu, "ram": r.ram_mb,
                           "players": max(pv) if pv else None})
        host = []
        if gs.remote_id:
            hrows = (db.session.query(HostSample.ts, HostSample.cpu, HostSample.ram_pct,
                                      HostSample.disk_pct)
                     .filter(HostSample.remote_id == gs.remote_id, HostSample.ts >= since)
                     .order_by(HostSample.ts.asc()).all())
            hstep = max(1, len(hrows) // 240)
            host = [{"t": r.ts.isoformat() + "Z", "cpu": r.cpu, "ram": r.ram_pct, "disk": r.disk_pct}
                    for r in hrows[::hstep]]
        return jsonify({"server": server, "host": host, "range": rng})

    @app.route("/api/free-port")
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def api_free_port():
        """Suggest a non-colliding port for installing <game> on <remote_id> near <desired>, so the
        install form can show a free port up front (the install resolves one anyway). Read-only."""
        try:
            remote_id = int(request.args.get("remote_id") or 0)
            desired = int(request.args.get("desired") or 0)
        except (TypeError, ValueError):
            return jsonify({"port": None})
        game = re.sub(r"[^a-z0-9]", "", (request.args.get("game") or "").lower())[:40]
        # get_remote(), not a bare lookup: this scans listening ports on the host, so it must be
        # a host the caller may see (see get_remote's "every remote-scoped route" contract).
        remote = get_remote(remote_id) if remote_id else None
        if not remote or not game or not (1 <= desired <= 65535):
            return jsonify({"port": None})
        try:
            port, changed = resolve_free_port(remote, remote_id, desired, game)
        except Exception:
            return jsonify({"port": None})
        return jsonify({"port": port, "changed": bool(changed)})

    @app.route("/api/servers")
    @login_required
    def api_servers():
        # Same per-user order as the dashboard. This payload is keyed by id client-side, so order
        # is not load-bearing here — but any future consumer that iterates it should see the user's
        # order rather than a second, different one.
        servers = _apply_user_server_order(get_user_servers(current_user),
                                           _effective_prefs(current_user))
        # Refresh live status efficiently: one listening-port scan per remote,
        # then match each game server's port (instead of an SSH call per server).
        by_remote = {}
        for gs in servers:
            if gs.remote_id:
                by_remote.setdefault(gs.remote_id, []).append(gs)
        changed = False
        for gslist in by_remote.values():
            remote = gslist[0].remote
            try:
                ports = _remote_listening_ports(remote)
                for gs in gslist:
                    # NEVER overwrite an in-progress install's status. This poller only reflects
                    # running/stopped, and a not-yet-running install would otherwise get flipped
                    # "installing" -> "offline" (it isn't listening on its port yet) — which made the
                    # progress row vanish and show "Not installed" the moment you navigated back.
                    if not gs.installed or gs.status in ("installing", "configuring"):
                        continue
                    st = "online" if gs.port in ports else "offline"
                    if gs.status != st:
                        gs.status = st
                        changed = True
                # Resolve+cache the remote's public IP for the connect address in the background
                # (non-blocking) — the connect address falls back to remote.host until it's cached,
                # so a slow/unreachable remote never stalls this polled endpoint.
                if not remote.public_ip:
                    _maybe_resolve_public_ip(app, remote.id)
            except Exception:
                _log.debug("api_servers: ignored non-fatal error", exc_info=True)
        if changed:
            db.session.commit()

        data = []
        for gs in servers:
            r = gs.remote
            host = (r.public_ip if r else "") or (r.host if (r and not r.is_local) else "")
            data.append({
                "id": gs.id,
                "name": gs.name,
                "short_name": gs.short_name,
                "game_type": gs.game_type,
                "port": gs.port,
                "status": gs.status,
                "installed": gs.installed,
                "remote_name": r.name if r else "",
                "connect": f"{host}:{gs.port}" if host else "",
                "connect_url": gs.connect_uri(host),
                "players": _cached_player_count(gs.id),
                "max_players": _cached_player_max(gs.id),
                "game_name": _cached_player_name(gs.id),
            })
        return jsonify(data)

    @app.route("/api/server/<int:server_id>")
    @login_required
    @server_access_required
    def api_server_status(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        try:
            status = get_server_status(remote, gs)
            # Don't clobber an in-progress install's status (see /api/servers) — only persist
            # running/stopped for a server that's actually installed and not mid-install/config.
            if gs.installed and gs.status not in ("installing", "configuring"):
                gs.status = status
                db.session.commit()
        except Exception:
            status = "error"

        # The player counts come from the SAME cache /api/servers reads, kept fresh by the
        # background poller (gamedig, with the console and LinuxGSM-query fallbacks).
        #
        # This used to run `cat <console_log> | grep -c '...'` over SSH and then scan the result for
        # a line containing both "players" and "has". `grep -c` prints a bare number, so that loop
        # could never match: the endpoint reported 0/0 for every server, always — while paying for a
        # round trip that `cat`s the whole console log across the network on each call. None (not 0)
        # is what "we could not read it" means everywhere else in the API, so it is what this
        # answers now too.
        player_count = _cached_player_count(gs.id)
        max_players = _cached_player_max(gs.id)

        return jsonify({
            "id": gs.id,
            "name": gs.name,
            "short_name": gs.short_name,
            "game_type": gs.game_type,
            "port": gs.port,
            "status": status,
            "installed": gs.installed,
            "player_count": player_count,
            "max_players": max_players,
            "remote": gs.remote.name if gs.remote else "",
        })

    @app.route("/api/server/<int:server_id>/stats")
    @login_required
    @server_access_required
    def api_server_stats(server_id):
        """Fast live metrics for polling: VPS CPU/RAM/disk/uptime + the game's RAM
        and a port-based online check + the public connect address."""
        gs = get_game(server_id)
        remote = gs.remote
        try:
            m = server_live_metrics(remote, gs.short_name, gs.port)
        except Exception:
            # An unreachable host is an expected condition, not a server error — return
            # 200 with an error field (the poller handles it) so it doesn't log a console
            # 500 on every poll of an offline server.
            return jsonify({"error": _log_and_generic("server stats failed")}), 200

        status = "online" if (m.get("port_open") or m.get("game_procs")) else "offline"
        changed = False
        if gs.status != status:
            gs.status = status
            changed = True
        # Resolve + cache the remote's public IP (for the connect address) in the background —
        # non-blocking, so this polled endpoint never stalls on a slow/unreachable remote.
        if not remote.public_ip:
            _maybe_resolve_public_ip(app, remote.id)
        if changed:
            db.session.commit()

        host = remote.public_ip or (remote.host if not remote.is_local else "")
        return jsonify({
            "status": status,
            "connect": f"{host}:{gs.port}" if host else f":{gs.port}",
            "connect_url": gs.connect_uri(host),
            "public_ip": remote.public_ip,
            "port": gs.port,
            "metrics": m,
        })

    def _looks_installed(remote, short_name, lgsm_name):
        """Best-effort check of whether a game server is actually installed on the remote — used
        to reconcile an install whose live progress was lost (e.g. the panel restarted mid-install).
        Returns True (installed), False (clearly not), or None (couldn't tell)."""
        try:
            out, err, _ = run_command(
                remote,
                f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} details 2>&1'",
                timeout=30, sudo=False)
            low = terminal.strip_escapes((out or "") + "\n" + (err or "")).lower()
            if re.search(r"not installed|please run .*install|serverfiles.*(missing|not found)|no such file", low):
                return False
            if "status:" in low or "server ip:" in low:
                return True
            # Fallback: real content in serverfiles means the download completed.
            out2, _, _ = run_command(
                remote,
                f"sudo -u {short_name} bash -c 'du -sm /home/{short_name}/serverfiles 2>/dev/null | cut -f1'",
                timeout=20, sudo=False)
            try:
                return int((out2 or "0").strip() or "0") > 50
            except ValueError:
                return None
        except Exception:
            app.logger.debug("install reconcile check failed", exc_info=True)
            return None

    @app.route("/api/server/<int:server_id>/install-status")
    @login_required
    @server_access_required
    def api_server_install_status(server_id):
        """Live step-by-step progress of a game-server install (mirrors bootstrap)."""
        gs = db.session.get(GameServer, server_id)
        installed_flag = bool(gs and gs.installed)
        with _install_lock:
            j = _install_jobs.get(server_id)
        if not j:
            # No live job. If the DB still says "installing", the in-memory progress was lost —
            # almost always because the panel restarted mid-install (e.g. a deploy). Reconcile
            # against the real server so the user gets a definite answer instead of a vanished row.
            # Covers both "installing" (steps 1-4) and "configuring" (steps 5-8, installed=True): a
            # restart in either phase strands a status the poller skips forever, so both reconcile.
            if gs and gs.status in ("installing", "configuring"):
                verdict = _looks_installed(gs.remote, gs.short_name, gs.lgsm_name)
                if verdict is True:
                    gs.installed = True
                    gs.status = "offline"   # live metrics will flip it to online if it's running
                    db.session.commit()
                    _notify_servers_changed()
                    return jsonify({"status": "done", "step": 8, "total": 8, "percent": 100,
                                    "step_name": "Complete",
                                    "message": "Install finished — verified after the panel restarted.",
                                    "log": [], "elapsed": 0})
                if verdict is False:
                    gs.status = "failed"
                    db.session.commit()
                    _notify_servers_changed()
                    return jsonify({"status": "failed", "step": 0, "total": 8, "percent": 0,
                                    "step_name": "Interrupted",
                                    "message": "The panel restarted before this install finished, so it "
                                               "didn't complete. Uninstall it, then install again.",
                                    "log": [], "elapsed": 0})
                # Couldn't reach the host to check — report an interrupted-but-unknown state.
                return jsonify({"status": "interrupted", "step": 0, "total": 8, "percent": 0,
                                "step_name": "Unknown", "log": [], "elapsed": 0,
                                "message": "Install progress was lost (the panel may have restarted) and "
                                           "the server couldn't be reached to confirm. Try refreshing."})
            return jsonify({"status": "none"})
        with _install_lock:
            j = _install_jobs.get(server_id)
            if not j:
                return jsonify({"status": "none"})
            if j["status"] in ("done", "failed") and (time.time() - j.get("updated", j["started"])) > 900:
                _install_jobs.pop(server_id, None)
                return jsonify({"status": "none"})
            pct = int(j["step"] / j["total"] * 100) if j.get("total") else 0
            return jsonify({
                "status": j["status"], "step": j["step"], "total": j["total"], "percent": pct,
                "step_name": j["step_name"], "message": j.get("message", ""),
                "warn": bool(j.get("warn")),   # done, but with a caveat (installed yet didn't start)
                "log": j["log"][-100:], "elapsed": int(time.time() - j["started"]),
                # installed flips True after the game files download (step 4), several steps before
                # the job's final "done" (config → ports → autostart → start). Surface it so the live
                # view can show "Finishing setup…" during those steps (server is installed but not yet
                # fully up) instead of a premature "Installed".
                "installed": installed_flag,
            })

    @app.route("/api/server/<int:server_id>/install-dismiss", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_install_dismiss(server_id):
        """Clear a finished install job so its progress card goes away."""
        with _install_lock:
            j = _install_jobs.get(server_id)
            if j and j["status"] in ("done", "failed"):
                _install_jobs.pop(server_id, None)
        return jsonify({"success": True})

    # ── Config editor + file browser (per game server) ─────────



    @app.route("/server/<int:server_id>/files")
    @login_required
    @server_access_required
    def server_files(server_id):
        """Config editor + live file browser for a game server."""
        gs = get_game(server_id)
        if not gs.installed:   # files don't exist yet while it's still installing (or after a failure)
            flash("That server is still installing — its files aren't available until it's done.", "info")
            return redirect(url_for("manage_servers"))
        if not _can_manage_files():
            flash("You don't have permission to manage server files.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        # Same control bar as the detail page — this page tells you to restart to apply a
        # change, so it has to offer the button.
        actions, maintenance, _all_cmds, _sup = _server_action_buttons(app, gs)
        return render_template("server_files.html", server=gs, remote=gs.remote,
                               actions=actions, maintenance=maintenance)

    @app.route("/api/server/<int:server_id>/config", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_config(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                return jsonify(lgsm_read_config(gs.remote, gs.short_name, gs.lgsm_name))
            except Exception:
                return jsonify({"error": _log_and_generic("request failed")}), 500
        data = _json_body()
        try:
            if data.get("raw") is not None:
                rel = f"lgsm/config-lgsm/{gs.lgsm_name}/{gs.lgsm_name}.cfg"
                ok, msg = write_file(gs.remote, gs.short_name, rel, data["raw"])
            else:
                ok, msg = lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name, data.get("settings") or {})
            log_action(current_user, "edit_config", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/game-config")
    @login_required
    @server_access_required
    def api_server_game_config(server_id):
        """The game's own server config file (detected via LinuxGSM details)."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            return jsonify(lgsm_game_config(gs.remote, gs.short_name, gs.lgsm_name))
        except Exception:
            return jsonify({"error": _log_and_generic("game config read failed")}), 200

    @app.route("/api/server/<int:server_id>/alerts", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_alerts(server_id):
        """Read/write the server's LinuxGSM alert settings (Discord/Telegram/email/…). Writes
        straight into the LinuxGSM config so the game server itself sends the notifications."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                vals = lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, _ALERT_KEYS)
            except Exception:
                vals = {}   # host unreachable — still return the static provider list so it renders
                app.logger.debug("alerts read failed", exc_info=True)
            return jsonify({"providers": ALERT_PROVIDERS, "values": vals})
        # POST: only the known alert keys; toggles coerced to on/off.
        data = _json_body().get("values") or {}
        updates = {}
        for k, v in data.items():
            if k not in _ALERT_KEY_SET:
                continue
            if k.endswith("alert"):
                v = "on" if str(v).lower() in ("on", "true", "1", "yes") else "off"
            updates[k] = v
        try:
            ok, msg = lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name, updates)
            log_action(current_user, "server_alerts_save", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("alerts save failed")}), 200

    @app.route("/api/server/<int:server_id>/mods", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_mods(server_id):
        """List / install / remove LinuxGSM mods (SourceMod, MetaMod, Oxide, …). Listing
        drives LinuxGSM's mods menus; install/remove feed the chosen mod id. Install/remove
        modify the install, so they need UPDATE_SERVER."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            available, installed, supported = [], [], True
            try:
                available, av_ok = mods_available(gs.remote, gs.short_name, gs.lgsm_name)
                installed, in_ok = mods_installed(gs.remote, gs.short_name, gs.lgsm_name)
                supported = av_ok and in_ok   # this game has a LinuxGSM mods installer
            except Exception:
                app.logger.debug("mods list failed", exc_info=True)  # unreachable host — return empties
            return jsonify({"available": available, "installed": installed, "supported": supported})
        # POST: install or remove a mod by its LinuxGSM id (e.g. "sourcemod").
        if not (current_user.is_superadmin or has_permission(current_user, UPDATE_SERVER)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        data = _json_body()
        which = "install" if data.get("action") == "install" else ("remove" if data.get("action") == "remove" else "")
        mod_id = str(data.get("mod") or "").strip()   # str() so a numeric/other type can't crash .strip()
        if not which or not re.match(r"^[A-Za-z0-9._-]+$", mod_id):
            return jsonify({"success": False, "message": "Pick a valid mod to " + (which or "act on") + "."}), 400
        try:
            out, err, rc = mods_action(gs.remote, gs.short_name, gs.lgsm_name, which, mod_id)
            clean = terminal.strip_escapes(((out or "") + "\n" + (err or ""))).strip()
            log_action(current_user, f"mods_{which}", target=gs.name, success=(rc == 0), detail=clean[-400:])
            ok = rc == 0
            tail = ""
            for line in reversed(clean.splitlines()):
                if line.strip():
                    tail = line.strip()
                    break
            msg = (f"Mod {which} finished." if ok
                   else f"Mod {which} reported an error: {tail[:200] or 'check the console'}")
            restart_pending = False
            if ok:
                # A mod change only loads on restart — we never restart automatically; just tell the
                # admin a restart is needed so the UI can offer "Restart now".
                state, rmsg = _apply_mod_restart(gs, gs.remote)
                restart_pending = (state == "needed")   # drives the "Restart now" button in the UI
                if rmsg:
                    msg = msg + " " + rmsg
            return jsonify({"success": ok, "message": msg, "restart_pending": restart_pending})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("mods action failed")}), 200

    @app.route("/api/server/<int:server_id>/browse")
    @login_required
    @server_access_required
    def api_server_browse(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            result = browse_dir(gs.remote, gs.short_name, request.args.get("path", ""), gs.lgsm_name)
            if result is None:
                return jsonify({"error": "Invalid path"}), 400
            return jsonify(result)
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/file", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_file(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            content, err = read_file(gs.remote, gs.short_name, request.args.get("path", ""))
            if err:
                return jsonify({"error": err}), 400
            return jsonify({"content": content, "path": request.args.get("path", "")})
        data = _json_body()
        rel = data.get("path", "")
        try:
            ok, msg = write_file(gs.remote, gs.short_name, rel, data.get("content", ""))
            log_action(current_user, "edit_file", target=gs.name, detail=rel, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/delete-path", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_delete_path(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        rel = _json_body().get("path", "")
        try:
            ok, msg = delete_path(gs.remote, gs.short_name, rel, gs.lgsm_name)
            log_action(current_user, "delete_file", target=gs.name, detail=rel, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("delete_path failed")}), 500


    @app.route("/server/<int:server_id>/download")
    @login_required
    @server_access_required
    def server_file_download(server_id):
        """Download one file from the game server, or a .tar.gz of one directory.

        Not an /api route and not JSON: this is a plain GET the browser navigates to, so the file
        lands in the download manager with a name and a progress bar instead of being buffered
        through fetch() as a blob. A 4 GB map pack would not survive that.

        The editor's read (api_server_file) is text-only, capped at 1 MB and refuses a binary —
        which is right for an editor and useless for a download, so this streams instead. Same
        permission as the rest of the file browser: if you may edit and delete these files, you
        may take a copy of one.
        """
        gs = get_game(server_id)
        if not _can_manage_files():
            flash("You don't have permission to manage server files.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        rel = request.args.get("path", "")
        # Every failure below ends in a flash and a redirect rather than an abort(), because this
        # is a LINK the browser follows: an error page would replace the file browser with a bare
        # 404, whereas a redirect back to the page says what went wrong and leaves the admin where
        # they were. A download that succeeds never navigates at all.
        def _refuse(message, category="warning"):
            flash(message, category)
            return redirect(url_for("server_files", server_id=server_id))

        try:
            info = stat_path(gs.remote, gs.short_name, rel)
        except Exception:
            _log.debug("download: could not stat the path", exc_info=True)
            return _refuse("Couldn't reach %s to read that file." % gs.name, "danger")
        if not info:
            return _refuse("That file or folder isn't there any more.")
        if info["rel"] in (".", ""):
            # The home directory itself — by an empty ?path=, or by any spelling that resolves
            # back to it ("." , "/", "cfg/.."). stream_path refuses it too; this is the half that
            # can still explain why, instead of sending a 0-byte archive named after the user.
            return _refuse("Pick a file or a folder to download, not the whole home directory.")
        is_dir = info["type"] == "d"
        name = info["name"] + (".tar.gz" if is_dir else "")
        log_action(current_user, "download_file", target=gs.name,
                   detail=rel + (" (as .tar.gz)" if is_dir else ""))
        resp = Response(stream_path(gs.remote, gs.short_name, rel, as_tar=is_dir,
                                    limit=None if is_dir else info["size"]),
                        mimetype="application/gzip" if is_dir else "application/octet-stream")
        if not is_dir:
            # A directory archive is generated as it streams, so its length is not knowable in
            # advance — the browser shows an indeterminate download for those. A file's is, and
            # the same number caps the stream: a console log the game is still writing to would
            # otherwise hand back more bytes than this header promises.
            resp.headers["Content-Length"] = str(info["size"])
        resp.headers["Content-Disposition"] = _attachment_header(name)
        return resp

    @app.route("/api/lgsm-data/refresh", methods=["POST"])
    @login_required
    @superadmin_required
    def api_lgsm_data_refresh():
        """Re-fetch LinuxGSM's serverlist/deps now.

        The install form offers this when it has no games to show, which means the fetch failed and
        nothing was cached — almost always a host with no outbound access to GitHub. Superadmin
        because it makes an outbound request and replaces install-wide data.
        """
        try:
            ok = lgsm_data.refresh()
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("lgsm data refresh failed")}), 200
        # Drop the module-level memos too, or the page would re-render the old (empty) answer.
        _GAME_LIST_CACHE["games"] = None
        _LGSM_NAME_MAP["data"] = None
        games = len(load_game_list())
        log_action(current_user, "lgsm_data_refresh", success=ok, detail="%d games" % games)
        return jsonify({"success": bool(ok and games), "games": games,
                        "message": ("Loaded %d games." % games) if games
                                   else "Could not reach LinuxGSM — check this host's outbound access."})

    @app.route("/api/server/<int:server_id>/cron", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_cron(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                # One-time, in-place upgrade so pre-existing managed jobs start reporting
                # success/error (idempotent + state-preserving; never blocks the listing).
                try:
                    upgrade_managed_cron_tracking(gs.remote, gs.short_name, gs.lgsm_name)
                except Exception:
                    app.logger.debug("cron tracking upgrade skipped", exc_info=True)
                jobs = list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name)
                _sync_toggles_from_cron(gs, jobs)
                return jsonify({"jobs": jobs})
            except Exception:
                return jsonify({"error": _log_and_generic("list_cron_jobs failed")}), 500
        data = _json_body()
        try:
            ok, msg = add_cron_job(gs.remote, gs.short_name, data.get("schedule"),
                                   data.get("command"), gs.lgsm_name)
            if ok:
                _sync_toggles_from_cron(gs, list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name))
            log_action(current_user, "cron_add", target=gs.name, success=ok,
                       detail=(data.get("schedule") or "")[:120])
            return jsonify({"success": ok, "message": msg or ("Added" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("add_cron_job failed")}), 500

    @app.route("/api/server/<int:server_id>/cron/update", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_cron_update(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        data = _json_body()
        try:
            ok, msg = update_cron_job(gs.remote, gs.short_name, data.get("raw") or "",
                                      data.get("schedule"), data.get("command"), gs.lgsm_name)
            log_action(current_user, "cron_update", target=gs.name, success=ok,
                       detail=(data.get("schedule") or "")[:120])
            return jsonify({"success": ok, "message": msg or ("Updated" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("update_cron_job failed")}), 500

    @app.route("/api/server/<int:server_id>/cron/delete", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_cron_delete(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        data = _json_body()
        try:
            ok, msg = delete_cron_job(gs.remote, gs.short_name, data.get("raw") or "", gs.lgsm_name)
            if ok:
                # The card's own help text promises that deleting `monitor` turns Autostart off.
                _sync_toggles_from_cron(gs, list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name))
            log_action(current_user, "cron_delete", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Deleted" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("delete_cron_job failed")}), 500

    @app.route("/api/server/<int:server_id>/cron/run", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_cron_run(server_id):
        """Run a scheduled task on demand (records its exit code + output so Last-run updates)."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        raw = _json_body().get("raw") or ""
        try:
            ok, msg = run_cron_job_now(gs.remote, gs.short_name, raw, gs.lgsm_name)
            log_action(current_user, "cron_run_now", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("cron run failed")}), 200


    def _bg_gmod_content_apply(server_id, remote_id, gmod_user, games):
        """Apply a GMod content selection in the background (a download can take many minutes): ensure
        a content user, fetch any missing games, then rewrite the server's mount.cfg to exactly the
        selection. An empty selection unmounts everything. Result is stashed for the status poll."""
        _app = app
        _gmod_content_apply_state[server_id] = {"status": "running", "msg": "", "ts": time.time()}

        def _run():
            with _app.app_context():
                try:
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    if games:
                        cu = ensure_content_user(remote)
                        if not cu:
                            _gmod_content_apply_state[server_id] = {
                                "status": "error", "msg": "No content storage could be prepared on the host.",
                                "ts": time.time()}
                            return
                        install_gmod_content(remote, cu["user"], games)
                        ok, msg = gmod_mount_setup(remote, gmod_user, cu["user"], games)
                    else:
                        ok, msg = gmod_mount_setup(remote, gmod_user, "", [])
                    _gmod_content_apply_state[server_id] = {
                        "status": "done" if ok else "error", "msg": msg, "ts": time.time()}
                except Exception:
                    _log.warning("gmod content apply failed for %s", gmod_user, exc_info=True)
                    _gmod_content_apply_state[server_id] = {
                        "status": "error", "msg": "Content setup failed — check the server logs.",
                        "ts": time.time()}

        threading.Thread(target=_run, daemon=True).start()

    def _bg_gmod_content_uninstall(server_id, remote_id, gmod_user, games):
        """Uninstall content from the host (host-wide) in the background, then drop the removed games
        from THIS server's mounts. Result is stashed for the status poll."""
        _app = app
        _gmod_content_apply_state[server_id] = {"status": "running", "msg": "", "ts": time.time()}

        def _run():
            with _app.app_context():
                try:
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    cu = detect_content_user(remote, tuple(GMOD_CONTENT_GAMES))
                    removed = []
                    if cu:
                        _, removed, _m = uninstall_gmod_content(remote, cu["user"], games)
                    # Drop the removed games from THIS server's mount.cfg (other servers just skip the
                    # now-missing mount). Best-effort.
                    remaining = [g for g in gmod_current_mounts(remote, gmod_user) if g not in games]
                    gmod_mount_setup(remote, gmod_user, (cu or {}).get("user", ""), remaining)
                    _gmod_content_apply_state[server_id] = {
                        "status": "done", "msg": "Removed from host: " + (", ".join(removed) or "(none)"),
                        "ts": time.time()}
                except Exception:
                    _log.warning("gmod content uninstall failed for %s", gmod_user, exc_info=True)
                    _gmod_content_apply_state[server_id] = {
                        "status": "error", "msg": "Uninstall failed — check the server logs.",
                        "ts": time.time()}

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/api/server/<int:server_id>/gmod-content", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_gmod_content(server_id):
        # Gate BOTH methods, like every other file-editor route: mount status exposes what content
        # exists on the host. The POST branch used to carry its own inline copy of this check, which
        # is what left the GET ungated.
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        gs = get_game(server_id)
        if gs.game_type != "gmod":
            return jsonify({"error": "Content mounting is available for Garry's Mod only."}), 400
        remote = gs.remote
        if request.method == "GET":
            try:
                mounted = gmod_current_mounts(remote, gs.short_name)
                cu = detect_content_user(remote, tuple(GMOD_CONTENT_GAMES))
                present = set((cu or {}).get("present", {}))
                games = [{"key": k, "label": GMOD_CONTENT_GAMES[k][0], "size": GMOD_CONTENT_SIZES.get(k, ""),
                          "present": (k in present), "mounted": (k in mounted),
                          "downloadable": GMOD_CONTENT_GAMES[k][1] is not None} for k in GMOD_CONTENT_GAMES]
                st = _gmod_content_apply_state.get(server_id)
                # Free disk on the filesystem where content is stored — so nobody starts a 13GB
                # install without room. Uses the content user's serverfiles if one exists, else /home.
                content_path = ("/home/%s/serverfiles" % cu["user"]) if cu else "/home"
                disk_free, disk_total = path_disk_free(remote, content_path)
                return jsonify({"games": games, "mounted": mounted,
                                "disk_free": disk_free, "disk_total": disk_total,
                                "job": st if (st and st.get("status") == "running") else None})
            except Exception:
                return jsonify({"error": _log_and_generic("gmod content status failed"), "games": []}), 200
        # POST: apply a selection (mutating). The MANAGE_SERVERS gate is at the top of the route.
        body = _json_body()
        action = body.get("action") or "mount"
        sel = [g for g in (body.get("games") or []) if g in GMOD_CONTENT_GAMES]
        if action == "uninstall":
            _bg_gmod_content_uninstall(gs.id, remote.id, gs.short_name, sel)
            log_action(current_user, "gmod_content_uninstall", target=gs.name, detail=",".join(sel))
            return jsonify({"success": True, "games": sel,
                            "message": "Removing content from the host — this frees disk for every GMod "
                                       "server here. Restart affected servers afterwards."})
        _bg_gmod_content_apply(gs.id, remote.id, gs.short_name, sel)
        log_action(current_user, "gmod_content", target=gs.name, detail=(",".join(sel) or "(none)"))
        return jsonify({"success": True, "games": sel,
                        "message": "Applying mount changes — a download can take a while for large games. "
                                   "Restart the server afterwards to load the changes."})

    @app.route("/api/server/<int:server_id>/upload", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_upload(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        reldir = request.form.get("path", "")
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify({"success": False, "message": "No file provided"}), 400
        data = f.read(_MAX_UPLOAD_BYTES + 1)   # bounded read: never pull more than the limit into memory
        if len(data) > _MAX_UPLOAD_BYTES:
            return jsonify({"success": False, "message": "File too large (max 50 MB)"}), 400
        # Overwriting is opt-in per request: the browser asks the user first (showing both files'
        # size and date), and only then sends overwrite=1. Anything else — an older client, a
        # direct API call, or a file that appeared between the check and this write — gets a 409
        # conflict rather than silently replacing someone's config.
        overwrite = request.form.get("overwrite") == "1"
        try:
            ok, msg = upload_file(gs.remote, gs.short_name, reldir, f.filename, data,
                                  overwrite=overwrite)
            if not ok and msg == UPLOAD_EXISTS:
                return jsonify({"success": False, "conflict": True, "name": f.filename,
                                "message": "A file with that name already exists."}), 409
            log_action(current_user, "upload_file", target=gs.name,
                       detail="%s/%s%s" % (reldir, f.filename, " (overwrote)" if overwrite else ""),
                       success=ok)
            return jsonify({"success": ok, "message": msg or ("Uploaded" if ok else "Failed"), "name": f.filename})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/upload-check", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_upload_check(server_id):
        """Which of these names already exist in the target directory, with size + mtime.

        Lets the browser show old-vs-new and ask before overwriting, without uploading the bytes
        twice. Advisory only — the upload route re-checks, so a file that appears in between is
        still refused rather than clobbered."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        body = _json_body()
        names = body.get("names")
        if not isinstance(names, list) or len(names) > 500:
            return jsonify({"error": "Invalid request"}), 400
        try:
            hits = stat_upload_targets(gs.remote, gs.short_name, body.get("path", ""), names)
            if hits is None:
                return jsonify({"error": "Invalid path"}), 400
            return jsonify({"existing": hits, "checked": True})
        except Exception:
            # An unreachable host is the ordinary case here, not a bug, and it must not answer
            # "nothing exists" — that reads as "no conflicts" and is exactly the false clear this
            # endpoint exists to prevent. checked=false lets the UI say it could not look; the
            # upload route's own refusal stays the backstop either way.
            _log.debug("upload-check: could not list the target directory", exc_info=True)
            return jsonify({"existing": [], "checked": False})

    @app.route("/api/console/<int:server_id>")
    @login_required
    @server_access_required
    def api_console(server_id):
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, VIEW_CONSOLE):
            return jsonify({"error": "Permission denied", "lines": []}), 403
        remote = gs.remote
        # How much of the log to return. This was a hard `tail -100`, which is where "the console
        # clears out a lot of the old console" came from: 100 lines is a minute or two of chat and
        # connects on a busy server, and the poll returns a SLIDING WINDOW, so anything older had
        # already fallen off before the browser ever saw it. The browser keeps its own scrollback
        # now (it appends what is new instead of re-rendering), so this window only has to be big
        # enough that a gap between two polls is still covered — and the FIRST load has some
        # history to show. Clamped because it is a caller-supplied number that sizes a read.
        try:
            want = int(request.args.get("lines") or _CONSOLE_LINES)
        except (TypeError, ValueError):
            want = _CONSOLE_LINES
        want = max(50, min(want, _CONSOLE_LINES_MAX))
        try:
            log_path = gs.console_log
            out, err, rc = run_command(remote, f"tail -{want} {log_path} 2>/dev/null", timeout=15)
            lines = _clean_console_text(out).split("\n") if rc == 0 else []
        except Exception:
            lines = []
        return jsonify({"lines": lines})

    @app.route("/api/command/<int:server_id>", methods=["POST"])
    @login_required
    @server_access_required
    def api_send_command(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        data = _json_body()
        cmd_text = data.get("command", "").strip()

        if not cmd_text:
            return jsonify({"error": "No command provided"}), 400

        if not current_user.is_superadmin and not has_permission(current_user, SEND_COMMAND):
            return jsonify({"error": "Permission denied"}), 403

        try:
            out, err, rc = send_console_command(remote, gs.short_name, cmd_text, timeout=10, selfname=gs.lgsm_name)
            log_action(current_user, "send_command", target=gs.name, detail=cmd_text, success=(rc == 0))
            if rc != 0:
                return jsonify({"error": "Console (tmux) not accessible. Is the server running?"}), 502
            return jsonify({"success": True, "command": cmd_text})
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500


    socketio = SocketIO(app, cors_allowed_origins=_socketio_cors(), async_mode="eventlet")

    # Track which sockets are viewing which server console, so the poller only
    # polls consoles that someone is actually watching (idle = ~0% CPU).

    @socketio.on("connect")
    def on_socket_connect():
        # Defence in depth: only authenticated sessions get a socket at all. Anonymous or
        # cross-site handshakes (which, thanks to SameSite=Lax, won't carry the session
        # cookie) are refused here — so no client can hold a connection or receive any
        # broadcast (e.g. servers_changed) without being logged in. Returning False rejects
        # the connection. Per-event checks (join_console) still apply on top of this.
        if not current_user.is_authenticated:
            return False
        return True   # authenticated → accept the socket

    @socketio.on("join_console")
    def on_join_console(data):
        server_id = data.get("server_id")
        if not server_id:
            return
        # Enforce the SAME access control as the HTTP console routes: the socket must
        # belong to a logged-in user who has access to this specific server AND holds
        # VIEW_CONSOLE. Without this, any socket could stream any server's console.
        if (not current_user.is_authenticated
                or not can_access_server(current_user, server_id)
                or not (current_user.is_superadmin or has_permission(current_user, VIEW_CONSOLE))):
            emit("console_output", {"server_id": server_id,
                                    "data": "[access denied — you don't have permission to view this console]"})
            return
        join_room(f"console_{server_id}")
        with _viewers_lock:
            _console_viewers.setdefault(server_id, set()).add(request.sid)

    @socketio.on("leave_console")
    def on_leave_console(data):
        server_id = data.get("server_id")
        if server_id:
            leave_room(f"console_{server_id}")
            with _viewers_lock:
                if server_id in _console_viewers:
                    _console_viewers[server_id].discard(request.sid)
                    if not _console_viewers[server_id]:
                        del _console_viewers[server_id]

    @socketio.on("disconnect")
    def on_console_disconnect():
        # A browser that closed without leave_console must still stop the poller.
        with _viewers_lock:
            for sid_set in list(_console_viewers.values()):
                sid_set.discard(request.sid)
            for k in [k for k, v in _console_viewers.items() if not v]:
                del _console_viewers[k]

    # Console polling thread — streams new console output to WebSocket viewers.
    def console_poller():
        last_positions = {}
        while True:
            try:
                with _viewers_lock:
                    active_ids = list(_console_viewers.keys())
                if active_ids:
                    with app.app_context():
                        for server_id in active_ids:
                            gs = db.session.get(GameServer, server_id)
                            if not gs or not gs.remote:
                                continue
                            remote = gs.remote
                            try:
                                log_path = gs.console_log
                                size_out, _, _ = run_command(
                                    remote, f"stat -c%s {log_path} 2>/dev/null || echo 0", timeout=5
                                )
                                try:
                                    current_size = int(size_out.strip())
                                except ValueError:
                                    continue
                                last_pos = last_positions.get(server_id, 0)
                                if current_size < last_pos:  # log rotated/truncated
                                    last_pos = 0
                                if current_size > last_pos:
                                    if last_pos == 0:
                                        last_positions[server_id] = current_size
                                        continue
                                    diff = min(current_size - last_pos, 65536)  # cap 64KB/poll
                                    # tail -c +N | head -c diff: two reads, not one-per-byte.
                                    out, _, _ = run_command(
                                        remote,
                                        f"tail -c +{last_pos + 1} {log_path} 2>/dev/null | head -c {diff}",
                                        timeout=5,
                                    )
                                    if out:
                                        out = _clean_console_text(out)
                                    if out:
                                        socketio.emit("console_output",
                                                      {"server_id": server_id, "data": out},
                                                      room=f"console_{server_id}")
                                    last_positions[server_id] = current_size
                            except Exception:
                                continue   # skip this server; keep polling the rest
            except Exception:
                app.logger.debug("console poller iteration failed", exc_info=True)
            time.sleep(2)

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

    _supervise("console-poller", console_poller)

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
    def install_reconcile_ticker():
        time.sleep(20)   # let boot settle; the per-server check is an SSH round trip
        while True:
            try:
                with app.app_context():
                    for gs in GameServer.query.filter(
                            GameServer.status.in_(("installing", "configuring"))).all():
                        with _install_lock:
                            live = (gs.id in _install_jobs
                                    and _install_jobs[gs.id].get("status") == "running")
                        if live:
                            continue   # a genuinely in-progress install — leave it alone
                        try:
                            verdict = _looks_installed(gs.remote, gs.short_name, gs.lgsm_name)
                        except Exception:
                            verdict = None
                        if verdict is True:
                            gs.installed = True
                            gs.status = "offline"   # live metrics flip it to online if running
                            db.session.commit()
                            _notify_servers_changed()
                            app.logger.info("reconciled stranded install '%s' -> installed", gs.short_name)
                        elif verdict is False:
                            gs.installed = False
                            gs.status = "failed"
                            db.session.commit()
                            _notify_servers_changed()
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
                cur = so.panel_fail2ban_banned_ips()
                if seen is None:
                    seen = cur
                elif cur != seen:
                    new_bans = cur - seen
                    with app.test_request_context():   # gives log_action an (empty) request/DB context
                        for _ip in sorted(new_bans):
                            log_action(None, "fail2ban_ban", target=_ip,
                                       detail="banned after 5 failed panel logins in 10 min (1-hour ban)",
                                       success=False)
                            notifications.notify("ip_banned", "IP banned on the panel login",
                                                 "%s was banned by fail2ban (5 failed logins in 10 min)" % _ip)
                        for _ip in sorted(seen - cur):
                            log_action(None, "fail2ban_unban", target=_ip, detail="ban expired or lifted")
                    if len(new_bans) >= _BAN_SPIKE_THRESHOLD:   # a burst of bans at once = an attack wave
                        notifications.notify("ban_spike", "Login attack in progress",
                                             "%d IPs were just banned from the panel login at once." % len(new_bans))
                    seen = cur
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
