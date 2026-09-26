"""The per-server config editor, file browser and the live console socket.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (Response, flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from flask_socketio import (SocketIO, emit, join_room, leave_room)
from panel.core import (terminal)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops.ssh_manager import (GMOD_CONTENT_GAMES, GMOD_CONTENT_SIZES, UPLOAD_EXISTS,
    add_cron_job, browse_dir, delete_path, detect_content_user, ensure_content_user,
    gmod_current_mounts, gmod_mount_setup, install_gmod_content, lgsm_game_config,
    lgsm_get_values, lgsm_read_config, lgsm_write_config, mods_action, mods_available,
    mods_installed, path_disk_free, read_file, run_cron_job_now, send_console_command,
    stat_path, stat_upload_targets, stream_path, uninstall_gmod_content, update_cron_job,
    upload_file, write_file)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.ops import socket_hooks as _socket_hooks
from panel.security.auth import (SEND_COMMAND, UPDATE_SERVER, VIEW_CONSOLE, _can_manage_files,
    can_access_server, get_game, has_permission, log_action, server_access_required,
    superadmin_required)
from panel.services import (lgsm_data)
import re
import threading
import time
from panel.core.http import (_json_body, _json_str, _log_and_generic, _unreachable)
from panel.core.validation import (_attachment_header)
from app import (ALERT_PROVIDERS, _GAME_LIST_CACHE, _LGSM_NAME_MAP, _MAX_UPLOAD_BYTES,
    _apply_mod_restart, _clean_console_text, _log, _socketio_cors, _sync_toggles_from_cron,
    load_game_list)
from panel.core.panel_state import (_console_backlog, _console_offsets, _console_partial,
    register_server_state)
from panel.routes._shared import (_console_rows, _drain_action_output,
    _host_timezone_cached, _server_action_buttons)

# ── State and constants this module OWNS ───────────────────────────────────────────────────────
# These lived in app.py until the split left it as their only definition and this file as their
# only reader. A module-private name (leading underscore) that nothing in its own module touches
# is dead code as far as CodeQL is concerned — `from app import _x` does not count as a use — so
# seven of them came back as py/unused-global-variable. Keeping mutable state next to the single
# module that mutates it is the right shape anyway; the alert was just what pointed at it.

# Every LinuxGSM alert config key, flattened from the provider table, plus a set for membership
# tests. Derived here rather than imported so ALERT_PROVIDERS stays the single source of truth.
_ALERT_KEYS = [p["toggle"] for p in ALERT_PROVIDERS] + [f["key"] for p in ALERT_PROVIDERS for f in p["fields"]]
_ALERT_KEY_SET = set(_ALERT_KEYS)

# Console log window. The default is what each poll pulls back; the browser stitches successive
# windows into a much longer scrollback of its own, so this is sized to cover the gap between two
# polls rather than to be the whole history. The ceiling bounds an explicit ?lines= request — the
# "load more" control asks for it once, and it is still only a `tail`.
_CONSOLE_LINES = 250
_CONSOLE_LINES_MAX = 2000

# Registered, not a bare dict: it is keyed by GameServer.id and read to render the server's page,
# so a deleted server's id — which SQLite hands straight to the next INSERT — would show the NEW
# server a content install frozen at "running". See panel_state.register_server_state.
_gmod_content_apply_state = register_server_state({})   # server_id -> {"status", "msg", "ts"}
# How long a FINISHED content job stays visible to the status poll. Same 900s remote_bootstrap's
# job poll gives its done/failed card, and for the same reason: without an expiry a failure from
# last month reappears on every later visit to the server page.
_GMOD_JOB_TTL = 900

# Hosts (remote ids) with a GMod content job in flight. Content is HOST-wide — one content user,
# one ~/serverfiles, shared by every GMod server there — but job state is kept per game server, so
# nothing stopped a second job on the same host: two SteamCMD installs writing one content
# directory, or an uninstall `rm`-ing content another server's job was still downloading and
# mounting. One job per host; a second is refused (409) until the first finishes.
_gmod_content_busy_hosts = set()
_gmod_content_busy_lock = threading.Lock()


def _claim_gmod_content_host(remote_id):
    """True, and the host is now held, when no content job is running on it; False otherwise."""
    with _gmod_content_busy_lock:
        if remote_id in _gmod_content_busy_hosts:
            return False
        _gmod_content_busy_hosts.add(remote_id)
        return True


def _release_gmod_content_host(remote_id):
    with _gmod_content_busy_lock:
        _gmod_content_busy_hosts.discard(remote_id)


def _publish_gmod_job(server_id, remote_id, state):
    """A content worker's last step: release the host, THEN publish the job's terminal state.

    In that order so a poller that sees the job finish can start the next one at once — the other
    way round left a moment where the card said "done" and the next apply was refused as busy.
    `state` None means the worker left without recording one (its host was deleted mid-job), which
    used to leave the card spinning on "running" for ever."""
    _release_gmod_content_host(remote_id)
    _gmod_content_apply_state[server_id] = state or {
        "status": "error", "msg": "The host is no longer registered with the panel.",
        "ts": time.time()}


def _gmod_job_state(server_id):
    """What the GMod content status poll should report: a running job, or a TERMINAL result the
    card has not had time to show yet.

    The poll used to answer `st if st.get("status") == "running" else None`, which discarded every
    outcome the two workers take care to record — "No content storage could be prepared on the
    host.", "Content setup failed — check the server logs.", gmod_mount_setup's "Couldn't read
    <user>'s group, so the content mount was not granted", and the removal list the uninstall
    worker builds. Their docstrings say the result is "stashed for the status poll"; the status
    poll could not see it, so a job that ended in error was indistinguishable from no job at all:
    the spinner vanished, nothing was said, and the operator restarted the server as instructed
    into ERROR textures. A content install can run for up to two hours, and every one of its
    failure modes behaved this way.

    Module level so a test can drive the expiry without sleeping through it."""
    st = _gmod_content_apply_state.get(server_id)
    if not st:
        return None
    if st.get("status") == "running":
        return st
    if (time.time() - (st.get("ts") or 0)) > _GMOD_JOB_TTL:
        _gmod_content_apply_state.pop(server_id, None)
        return None
    return st


def _gmod_removal_result(asked, removed):
    """The (status, msg) the uninstall worker stashes: what the host CONFIRMED is gone, and what it
    would not answer about.

    uninstall_gmod_content re-probes every game after the rm and deliberately keeps out of
    `removed` any game whose probe did not answer — that list is evidence, and the gap between it
    and what was asked for is not. This used to be rendered as `", ".join(removed) or "(none)"`
    with status "done", so a host that stopped answering during the 120s removal told the operator
    "Removed from host: (none)", which reads as "there was nothing to remove" — the one thing it
    does not mean. The disk may still be full and the content may or may not still be there. The
    three-state probe added in ssh_manager/gmod.py stops at that module's boundary unless this says
    what it found, and a job that could not confirm its own work is not "done"."""
    _done = [g for g in asked if g in (removed or [])]
    _unconfirmed = [g for g in asked if g not in _done]
    if not _unconfirmed:
        # "(none)" belongs to THIS branch only: nothing was asked of the host, or everything asked
        # came back confirmed. It is the one case where "nothing was removed" is a reading.
        return "done", "Removed from host: " + (", ".join(_done) or "(none)")
    _tail = ("Couldn't confirm the removal of " + ", ".join(_unconfirmed)
             + " — the host stopped answering, so that content may still be on disk. Check the "
               "host is reachable, then run the removal again.")
    return "error", (("Removed from host: " + ", ".join(_done) + ". " + _tail) if _done else _tail)


# server_id -> {socket session id: the user id that joined on it}.
#
# It was a set of sids. The user id is here because authorization on this stream was a ONE-TIME
# question asked in the join handler, and the poller then streamed to the room for as long as the
# socket stayed open — so revoking a group, removing a permission, or deactivating an account did
# not stop the console output already flowing to that browser. The poller re-asks the question
# each tick, and it needs to know whose socket it is asking about.
_console_viewers = {}
_viewers_lock = threading.Lock()

# socket sid -> (login id, token digest or None): the CREDENTIAL a console socket joined with, not
# only whose it is. The per-tick re-check used to ask only about the user ROW, and none of the
# panel's revocation controls change the row's answers: logout and a device revoke delete a
# UserSession row, "sign out everywhere" and a password change bump auth_epoch, revoking an API
# token clears its hash, and idle expiry lives on the session. load_user enforces every one of
# those — on each socket EVENT — but the console is push-only: after join_console the client sends
# nothing, so a stolen cookie that had been signed out everywhere kept receiving RCON replies,
# admin commands and player IPs every two seconds for as long as it stayed connected. Guarded by
# _viewers_lock, and cleared on disconnect.
_viewer_creds = {}

# socket sid -> (socket peer, X-Forwarded-For's last hop or None), as ip_address objects: the two
# addresses a ban can name, recorded at connect. For _drop_banned_sockets. Guarded by
# _viewers_lock, and cleared on disconnect.
_socket_addrs = {}


def _handshake_addrs():
    """The socket peer and the forwarded client of the current socket's handshake — what the
    firewall and ProxiedBanGate each judge a client by. The ORIGINAL peer, since ProxyFix may have
    rewritten remote_addr from the header. Request context only."""
    from panel.security import banlist
    env = request.environ
    peer = ((env.get("werkzeug.proxy_fix.orig") or {}).get("REMOTE_ADDR")
            or env.get("REMOTE_ADDR") or "")
    xff = request.headers.get("X-Forwarded-For")
    # forwarded_client parses a bare address as a one-hop header, unmapping ::ffff:a.b.c.d.
    return banlist.forwarded_client(peer), (banlist.forwarded_client(xff) if xff else None)


def _addrs_banned(addrs):
    """Whether a ban names this socket's client. The peer is judged as the host firewall judges a
    direct connection (the address itself); the forwarded client as ProxiedBanGate judges it (an
    IPv6 ban covering its /64) — so a socket is refused exactly where a new request would be."""
    from panel.security import banlist
    peer, fwd = addrs
    return ((peer is not None and banlist.is_banned(peer, widen=False))
            or (fwd is not None and banlist.is_banned(fwd)))


def _drop_banned_sockets(app, socketio):
    """Disconnect every open socket whose client the current ban set names. Returns how many.

    A ban refuses NEW connections — at the firewall, or at ProxiedBanGate for a client behind
    Funnel — and a socket accepted before it is not a new connection: a console or a root
    terminal opened by an address fail2ban then banned went on streaming, under Funnel for as long
    as the browser stayed, and under a UFW deny too (ufw passes ESTABLISHED traffic before its own
    rules). Disconnecting runs THE disconnect handler, so the terminal's hook closes its shell."""
    from panel.security import banlist
    if not banlist.active():
        return 0
    with _viewers_lock:
        doomed = [sid for sid, addrs in _socket_addrs.items() if _addrs_banned(addrs)]
    for sid in doomed:
        try:
            socketio.server.disconnect(sid, namespace="/")
        except Exception:
            app.logger.debug("ban sweep: could not disconnect %s", sid, exc_info=True)
    if doomed:
        app.logger.info("ban sweep: dropped %d socket(s) from a banned address", len(doomed))
    return len(doomed)


def _viewer_credential():
    """What join_console records for this socket: (current_user's login id, bearer digest).

    The login id is the string the session cookie carries ("<uid>:<epoch>[:<session sid>]"), so
    running it back through _login_id_still_accepted later asks what a page load asks. The
    digest is recorded only when this socket authenticated with a bearer token that is the
    current user's: revoking a token changes neither the epoch nor any session row, so the token
    itself has to be compared. Request context only."""
    import hashlib
    digest = None
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        d = hashlib.sha256(hdr[7:].strip().encode()).hexdigest()
        if getattr(current_user, "api_token", None) == d:
            digest = d
    return current_user.get_id(), digest


def _login_id_still_accepted(login_id):
    """The User a recorded login id still names, or None: load_user's verdict without its writes.

    For the console poller, which holds each viewer's login id ("<uid>:<epoch>[:<sid>]",
    User.get_id) outside any request and re-asks every tick whether the panel would still accept
    it. It asks load_user's questions (the epoch still matches, the account is active, the
    per-device UserSession row still exists and has not idled out) and nothing else, because
    load_user is a REQUEST hook and two of its side effects are wrong here. It writes last_seen
    every ~5 minutes, and idle expiry is measured from last_seen, so a poller calling it kept a
    login alive for as long as a console socket stayed open (a stolen remember cookie included).
    And it turns a database error into None ("deny this request"), which the poller read as
    "revoked" and evicted a legitimate viewer on a transient lock.

    So this writes and deletes nothing, and RAISES when it cannot look (after a rollback, so the
    next viewer's query is not refused by a session left mid-failure). The per-request client
    binding (_session_binding_ok) is not asked: there is no request. Keep it in step with
    auth.load_user: smoke_test drives both over the same login ids."""
    from panel.core.clock import utcnow
    from panel.db.models import User, UserSession
    s = str(login_id)
    try:
        if ":" not in s:      # legacy cookie from before epochs: load_user accepts the plain id
            user = db.session.get(User, int(s)) if s.isdecimal() else None
            return user if user is not None and user.is_active else None
        parts = s.split(":")
        uid, epoch = parts[0], parts[1]
        sid = parts[2] if len(parts) > 2 and parts[2] else None
        if not uid.isdecimal():
            return None
        user = db.session.get(User, int(uid))
        if user is None or str(user.auth_epoch or 0) != epoch or not user.is_active:
            return None
        if sid:
            sess = UserSession.query.filter_by(sid=sid, user_id=user.id).first()
            if sess is None or sess.is_expired(utcnow()):
                return None
        return user
    except Exception:
        db.session.rollback()
        raise


def _credential_still_valid(uid, cred):
    """Is the credential a viewer joined with still one the panel would accept? cred is what
    _viewer_credential recorded, or None for a viewer registered without one (nothing to check).
    A revoked device, a bumped auth_epoch, an idle-expired session and a deactivated account all
    fail here as they fail a page load.

    It asks _login_id_still_accepted, NOT the app's user_loader: load_user refreshed last_seen
    from this poller (so an open console socket kept its login from ever idling out) and answered
    a database error with None (so a transient lock evicted a legitimate viewer as "revoked").
    _login_id_still_accepted writes nothing and RAISES when it cannot look, and
    _evict_unauthorized_viewers keeps a viewer it could not check."""
    if cred is None:
        return True
    login_id, digest = cred
    user = _login_id_still_accepted(login_id)
    if user is None or user.id != uid:
        return False
    return digest is None or getattr(user, "api_token", None) == digest


def _console_whole_lines(server_id, raw):
    """The COMPLETE lines in a byte-cut chunk; the trailing fragment is held for the next read.

    Returns None when the chunk did not arrive framed, i.e. the read never ran — which is a
    different thing from "" (it ran and held back a partial line), and the caller must treat it so.

    The poller reads the console log by byte range, so a chunk almost always ends mid-line. Emit
    that half and the console shows one line as two — seen in the wild as a bare "[20" where a
    LinuxGSM timestamp had been sliced across a 64KB read boundary.

    `raw` arrives FRAMED — a 'B' before the byte range and an 'E' after it — because run_command
    `.strip()`s what it returns, and strip() takes BOTH ends (_core.py: `out.strip()` on the
    paramiko path, `r.stdout.strip()` on the ssh-CLI one, `(out or "").strip()` on the local one).
    Only the trailing 'E' was here at first, which covered exactly half the problem: without it the
    chunk's own final newline is eaten and a line that was complete looks partial. The LEADING half
    had no sentinel at all, so when a byte-range chunk began with the newline that terminated the
    previous chunk's last line, that newline was deleted in transit and the held fragment was
    concatenated straight onto the next line's text — two real log lines reaching the screen as one
    with a timestamp welded into the middle of it, which also defeats _console_rows' stamp parsing.
    The same strip also ate a chunk's first line's indentation (Lua stack traces, LinuxGSM's own
    indented output) and any leading blank line.

    The frame is also the POSITIVE TOKEN for "the read actually ran": on the non-raising transports
    (tailscale and local) a failed or timed-out read returns ("", "…timed out", -1), and "" is
    indistinguishable from a chunk that held no complete line. Return None for that, so the caller
    can refuse to advance its offset over bytes the host never sent — the absence of a token must
    never read as success. The held fragment is deliberately NOT consumed on that path, so the next
    tick can re-read the same range and reassemble it.

    Extracted rather than inlined so it can be driven directly by a test. It was inline first, and
    the test reimplemented the arithmetic instead of calling it — which passed happily with the
    carry deleted from the code it was supposed to be guarding."""
    if not (raw and raw.startswith("B") and raw.endswith("E")):
        return None
    raw = raw[1:-1]
    chunk = _console_partial.pop(server_id, "") + raw
    whole, nl, rest = chunk.rpartition("\n")
    # A fragment is held only while it could still be finished. A game that writes without ever
    # ending the line (a progress bar redrawn with \r, a binary blob) grew the held text by a
    # whole read every tick with no bound, and it was re-concatenated and re-scanned each time.
    # Past the cap it is shown as a line of its own rather than held forever.
    if len(rest if nl else chunk) > _CONSOLE_PARTIAL_MAX:
        return chunk
    if nl:
        _console_partial[server_id] = rest
        return whole
    _console_partial[server_id] = chunk
    return ""


_CONSOLE_READ_CAP = 65536   # bytes per server per tick; a bigger backlog drains over later ticks
_CONSOLE_PARTIAL_MAX = 65536   # longest unterminated line held back waiting for its end


def _console_tick(app, socketio, gs, server_id):
    """One poll of one server's console log: push whatever is new to its viewers.

    Module level, and handed everything it touches, so a test can drive it against a fake host.
    It was the body of a `while True` inside a closure, which is why every earlier check of it had
    to read its SOURCE — and a source gate cannot tell a rotation it handles from one it misses.

    Offsets live in _console_offsets as {"ino", "pos"}, and the three cases are kept apart:

    * FIRST SIGHT (no entry): record the end and read nothing. History is /api/console's job — the
      page primed itself from it — and pushing the whole file here would print it twice.
    * ROTATED (the inode changed, or the file shrank): read the NEW log from byte 0. This is a
      server that has just started, and its boot output is exactly what someone is watching for.
      Offset 0 used to mean both "first sight" and "rotated", so a rotation skipped the new log's
      first chunk; and rotation was detected only by shrinking, so a new log that outgrew the old
      offset before the next tick was read from the OLD offset — the boot never shown, and the
      first line pushed began mid-line ('l:joml:1.10.9) to libraries/…' on the test VPS).
    * GROWN: read from where we were, at most _CONSOLE_READ_CAP bytes, and advance by what was
      READ — never to the file's size, which discarded everything past the cap.

    A read that did not run leaves the offset alone so the next tick re-reads the same range."""
    log_path = gs.console_log
    remote = gs.remote
    # Inode and size in one round trip. MISSING is its own answer, not a size of 0: between
    # LinuxGSM's `mv` and its `touch` there is briefly no file, and calling that "empty" would
    # record a bogus rotation. An unparseable reply (a failed read on a non-raising transport
    # comes back as "") is not a measurement either — try again next tick.
    st_out, _, _ = _sm.read_as_game_user(
        remote, gs.short_name,
        f"stat -c '%i %s' {log_path} 2>/dev/null || echo MISSING", timeout=5)
    parts = (st_out or "").split()
    if len(parts) != 2 or not (parts[0].isdigit() and parts[1].isdigit()):
        return
    ino, size = int(parts[0]), int(parts[1])
    state = _console_offsets.get(server_id)
    if state is None:
        _console_offsets[server_id] = {"ino": ino, "pos": size}
        return
    pos = state["pos"]
    if ino != state["ino"] or size < pos:
        # Rotated (LinuxGSM's start mv's the log to a dated name) or truncated. Persist the reset
        # BEFORE reading, so a read that fails below retries from 0 of the NEW file next tick
        # rather than detecting the same rotation again. Drop the half-line held from the OLD
        # file — gluing it onto the new one's first line is a line that never existed.
        pos = 0
        state["ino"], state["pos"] = ino, 0
        _console_partial.pop(server_id, None)
    if size <= pos:
        return
    diff = min(size - pos, _CONSOLE_READ_CAP)
    # tail -c +N | head -c diff: two reads, not one-per-byte. 'B' and 'E' are SENTINELS, not
    # decoration: run_command `.strip()`s what it returns, and strip() takes BOTH ends — the
    # trailing one would eat the chunk's own final newline and make a COMPLETE last line look
    # partial, the leading one eats the newline a chunk starts with and glues two real log lines
    # into one. See _console_whole_lines.
    out, _, rc = _sm.read_as_game_user(
        remote, gs.short_name,
        f"printf B; {{ tail -c +{pos + 1} {log_path} 2>/dev/null | head -c {diff}; }}; printf E",
        timeout=5,
    )
    # The frame is the POSITIVE TOKEN that this read ran at all. tailscale and local do not
    # raise: a 64KB read that exceeds the 5s timeout returns ("", "SSH command timed out", -1)
    # while the 20-byte stat in the same tick succeeded, so advancing here would jump `diff` bytes
    # over output the host never sent. Re-read the same range next tick instead — the guard
    # _drain_action_output makes in routes/_shared.py for the same reason.
    out = _console_whole_lines(server_id, out) if rc == 0 else None
    if out is None:
        return
    if out:
        out = _clean_console_text(out)
    if out:
        # Parsed per line: a LinuxGSM-stamped line carries its OWN time, which is more accurate
        # than the moment the poller happened to read it. `ts` is when the panel READ these
        # bytes, alongside the payload rather than inside it (see _console_push).
        rows = _console_rows(out.split("\n"), _host_timezone_cached(remote))
        socketio.emit("console_output",
                      {"server_id": server_id, "data": out, "rows": rows, "ts": time.time()},
                      room=f"console_{server_id}")
    # Advance by what was ACTUALLY READ. `head -c diff` emits exactly diff bytes (diff is clamped
    # to what the file holds), and this line is reached only past the frame check above.
    state["pos"] = pos + diff


def _forget_unwatched_consoles(watched_ids):
    """Drop poll state for every server nobody is watching.

    The offsets used to outlive the last viewer. Close a console, let the server write for an
    hour, open it again, and the poller resumed from where it had stopped — replaying the hour at
    64KB a tick, as if it were live, ahead of anything actually happening now. The page had
    already primed itself from /api/console, so every one of those lines was also a duplicate."""
    watched = set(watched_ids)
    for sid in [k for k in list(_console_offsets) if k not in watched]:
        _console_offsets.pop(sid, None)
        _console_partial.pop(sid, None)


def _evict_unauthorized_viewers(app, socketio, server_id):
    """Drop any viewer of this console whose access no longer allows it. Returns how many.

    Module level, and handed `app`/`socketio` rather than closing over them, so a test can
    drive it directly — the behaviour it guards is an authorization boundary, and one that
    only ran inside a background thread would be tested by watching the thread.

    Asks the SAME questions the join handler asks, of what was stored at join rather than of a
    request, because there is no request here: the row still exists and is active, it is not held
    at a forced password change, it reaches this server and holds VIEW_CONSOLE — and the
    CREDENTIAL the socket joined with is still accepted (_credential_still_valid: the session row,
    its epoch and idle expiry via _login_id_still_accepted, and a bearer token's hash).

    The socket is removed from the ROOM, not merely from the viewer map: the map governs
    whether the panel POLLS the host, while the room governs who receives what it already
    read. Dropping only the map entry would stop the reads and still deliver anything another
    viewer's poll produced. Caller holds no lock; this takes it.

    Must run inside an app context (the poller's). Never raises — a console that cannot
    answer the question keeps its viewers rather than dropping everyone on a transient error,
    and says so in the log."""
    from panel.db.models import User
    with _viewers_lock:
        watchers = dict(_console_viewers.get(server_id) or {})
        creds = {sid: _viewer_creds.get(sid) for sid in watchers}
    if not watchers:
        return 0
    dropped = 0
    for sid, uid in watchers.items():
        try:
            user = db.session.get(User, uid) if uid is not None else None
            allowed = bool(
                user is not None
                and getattr(user, "is_active", False)
                and not getattr(user, "must_change_password", False)
                and can_access_server(user, server_id)
                and (user.is_superadmin or has_permission(user, VIEW_CONSOLE))
                and _credential_still_valid(uid, creds.get(sid)))
        except Exception:
            app.logger.debug("console: could not re-check viewer %s", sid, exc_info=True)
            continue          # unknown is not "revoked" — leave them be and try next tick
        if allowed:
            continue
        with _viewers_lock:
            if server_id in _console_viewers:
                _console_viewers[server_id].pop(sid, None)
                if not _console_viewers[server_id]:
                    del _console_viewers[server_id]
        try:
            socketio.emit("console_output",
                          {"server_id": server_id,
                           "data": "[access to this console was revoked]"}, to=sid)
            socketio.server.leave_room(sid, f"console_{server_id}", namespace="/")
        except Exception:
            app.logger.debug("console: could not evict %s", sid, exc_info=True)
        dropped += 1
    return dropped


def register(app, supervise):
    """Register the file/config routes and the console socket. RETURNS the SocketIO instance.

    console_poller stays here too: it pushes through this socket, so it belongs beside the
    handlers that read from it. The supervisor is passed in for it, the way os_updates takes one.

    socketio is CONSTRUCTED here rather than handed in: this is where the console handlers live
    and it is the app's only SocketIO instance, so panel/routes/host_terminal.py is handed THIS one
    rather than making a second that would collide on /socket.io/. It is
    returned because register_routes still needs it — the console-poller ticker pushes through
    it, and app.socketio is what the entry point calls .run() on.
    """
    @app.route("/server/<int:server_id>/files")
    @login_required
    @server_access_required
    def server_files(server_id):
        """Config editor + live file browser for a game server."""
        gs = get_game(server_id)
        # A FAILED install is not "still installing", and it is the one state that most needs this
        # page. Step 2 of the install runs `./linuxgsm.sh <game>`, which writes the whole
        # lgsm/config-lgsm/<game>/ tree; it is step 4, the download, that fails. So the config the
        # failure message tells you to edit — `steamuser`, most often — is sitting there, editable,
        # while this route sent you to a list of servers and said the install was still running.
        #
        # The Game Servers page OFFERS this link on a failed row ("Files and config for <name>"),
        # which made it a dead end you were invited to walk into. Verified in a rendered panel: the
        # link is there, and both it and the Console link bounced back with "still installing".
        failed = (gs.status == "failed")
        if not gs.installed and not failed:
            flash("That server is still installing — its files aren't available until it's done.", "info")
            return redirect(url_for("manage_servers"))
        if not _can_manage_files():
            flash("You don't have permission to manage server files.", "danger")
            # The console is the right place to land — but only when there IS one. For a failed
            # install server_detail redirects back HERE, and the pair loops until the browser
            # gives up. Send those to the dashboard, which renders for anyone logged in.
            return redirect(url_for("server_detail", server_id=server_id)
                            if gs.installed else url_for("index"))
        # Same control bar as the detail page — this page tells you to restart to apply a
        # change, so it has to offer the button.
        actions, maintenance, _all_cmds, _sup = _server_action_buttons(app, gs)
        return render_template("server_files.html", server=gs, remote=gs.remote,
                               actions=actions, maintenance=maintenance,
                               # The game files never landed, so the browser has nothing to show
                               # and the page says why instead of rendering an empty tree.
                               install_failed=failed,
                               # Every cron line on this page fires on the HOST's clock. Without
                               # saying which clock that is, "Daily 5am" is a number with no
                               # meaning — and the panel's own bootstrap sets new hosts to UTC.
                               host_timezone=_host_timezone_cached(gs.remote, app))

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
                # A file's contents must be a STRING. A number or a list reached write_file and
                # died on .encode() — deep in the write path, reported as a 500.
                if not isinstance(data["raw"], str):
                    return jsonify({"success": False,
                                    "message": "The file contents must be text."}), 400
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
            # A read that FAILED must not render as a form, and this is not a cosmetic point.
            # The card paints `vals` straight into the inputs, and Save posts every input back
            # through lgsm_write_config — so a blank form is not "nothing configured", it is a
            # loaded gun: one failed read followed by one Save replaced the operator's real
            # Discord/Telegram webhooks and tokens with empty strings and reported success.
            # lgsm_get_values now answers None for "could not read"; the front end already has an
            # error path (server_files.js loadAlerts: `if(d.error)`) that shows the message and
            # never builds the inputs, so there is nothing to save back.
            try:
                vals = lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, _ALERT_KEYS)
            except Exception:
                vals = None
                app.logger.debug("alerts read failed", exc_info=True)
            if vals is None:
                return jsonify({"error": "Could not read this server's LinuxGSM config, so the "
                                         "current alert settings are unknown. Nothing has been "
                                         "changed — try again when the host answers."}), 200
            return jsonify({"providers": ALERT_PROVIDERS, "values": vals})
        # POST: only the known alert keys; toggles coerced to on/off.
        # isinstance, not `or {}`: a non-empty non-dict (a number, a list) passes the `or` and
        # then .items() raises AttributeError — a 500 for a bad request body.
        data = _json_body().get("values")
        data = data if isinstance(data, dict) else {}
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
        mod_id = _json_str(data, "mod")   # coerces, so a numeric/other type cannot crash .strip()
        if not which or not re.match(r"^[A-Za-z0-9._-]+\Z", mod_id):
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
        # The contents must be present and be TEXT, as api_server_config's `raw` must. This was
        # data.get("content", ""), and write_file encodes (content or ""), so a missing key (an API
        # script's typo) or a null/0/false/[] truncated the file to nothing and answered "Saved".
        # An intentionally empty file is "", which is text, and still saves.
        if not isinstance(data.get("content"), str):
            return jsonify({"success": False, "message": "The file contents must be text."}), 400
        try:
            ok, msg = write_file(gs.remote, gs.short_name, rel, data["content"])
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
            # stat_path answers None for THREE different things: a path that escapes the home
            # directory, a path that is not there, and a read that never ran — on the non-raising
            # transports (tailscale, local) a failed read returns ("", "…timed out", -1), so its
            # `parts` is empty and it returns None exactly as it does for a deleted file. The
            # "Couldn't reach" branch two lines up is only reachable from paramiko, the transport
            # the panel steers people away from. This line used to state deletion as fact: an
            # operator whose link flapped while downloading server.cfg was told the file was gone,
            # and went looking for what deleted it — or restored a backup over a newer copy. Until
            # stat_path grows the third answer browse_dir already has (`unreadable`, because "rc is
            # the only thing that tells them apart"), say only what was actually checked.
            return _refuse("%s didn't return that file. It may have been moved or deleted — or the "
                           "host didn't answer. Reload the file browser to check." % gs.name)
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
        # `ok` is the FETCH; `games` is what the page can show. They disagree when the fetch failed
        # and a cached list is still on disk — which used to read as "Loaded 30 games." because the
        # message only looked at the count, on the one button an operator presses BECAUSE a game is
        # missing. Name the real error when there is one.
        why = (lgsm_data.status().get("reason") or "").strip()
        if ok:
            message = "Loaded %d games." % games
        elif games:
            message = ("Could not reach LinuxGSM — still showing the cached list of %d games%s."
                       % (games, (" (%s)" % why) if why else ""))
        else:
            message = ("Could not reach LinuxGSM — check this host's outbound access%s."
                       % ((" (%s)" % why) if why else ""))
        return jsonify({"success": bool(ok and games), "games": games, "message": message})

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
                # Given the server's game type and port so a restart-when-empty line is healed
                # to what set_daily_restart writes for THIS server. Through the module (the seam).
                try:
                    _sm.upgrade_managed_cron_tracking(gs.remote, gs.short_name, gs.lgsm_name,
                                                      game_type=gs.game_type, port=gs.port)
                except Exception:
                    app.logger.debug("cron tracking upgrade skipped", exc_info=True)
                jobs = _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name)
                # The same distinction the file browser two cards up already makes, for the
                # same reason: a read that FAILED and an account with no jobs both used to
                # arrive here as [], and the page said "No scheduled tasks yet." about a
                # crontab it had never reached. _sync_toggles_from_cron refuses None as
                # well — this is the caller that made an unreadable crontab destructive
                # rather than merely misleading.
                if jobs is None:
                    return jsonify({"error": "Couldn't read the scheduled tasks — %s didn't "
                                             "answer. This is not the same as there being none."
                                             % (gs.remote.display_name if gs.remote
                                                else "the host")})
                _sync_toggles_from_cron(gs, jobs)
                return jsonify({"jobs": jobs})
            except Exception:
                return jsonify({"error": _log_and_generic("list_cron_jobs failed")}), 500
        data = _json_body()
        try:
            ok, msg = add_cron_job(gs.remote, gs.short_name, data.get("schedule"),
                                   data.get("command"), gs.lgsm_name)
            if ok:
                _sync_toggles_from_cron(gs, _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name))
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
            ok, msg = _sm.delete_cron_job(gs.remote, gs.short_name, data.get("raw") or "", gs.lgsm_name)
            if ok:
                # The card's own help text promises that deleting `monitor` turns Autostart off.
                _sync_toggles_from_cron(gs, _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name))
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

        _result = [None]   # the terminal state, published only once the host is released

        def _run():
            with _app.app_context():
                try:
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    if games:
                        cu = ensure_content_user(remote)
                        if not cu:
                            _result[0] = {
                                "status": "error", "msg": "No content storage could be prepared on the host.",
                                "ts": time.time()}
                            return
                        # KEEP the result. `installed` is the games install_gmod_content verified
                        # are on disk afterwards (it re-runs content_present after SteamCMD), and
                        # throwing it away meant the mount was written for every game the operator
                        # ticked whether or not its content existed: a 13GB CS:S install that ran
                        # out of disk still produced mount.cfg pointing at a directory that is not
                        # there, a stored result of "Mounted: Counter-Strike: Source — restart the
                        # server to apply", and purple ERROR textures on every map for an operator
                        # who had been told the content was mounted. The uninstall worker below
                        # already reports what it actually removed rather than what was asked.
                        _ok_i, installed, _imsg = install_gmod_content(remote, cu["user"], games)
                        # Already on the host before this ran (ensure_content_user's scan), plus
                        # whatever this run put there. Anything else is not on disk, so mounting it
                        # would be the claim this card exists to make true.
                        _on_disk = set(cu.get("present") or {}) | set(installed or [])
                        _mountable = [g for g in games if g in _on_disk]
                        _missing = [g for g in games if g not in _on_disk]
                        ok, msg = gmod_mount_setup(remote, gmod_user, cu["user"], _mountable)
                        if _missing:
                            _labels = ", ".join(GMOD_CONTENT_GAMES[g][0] for g in _missing)
                            _result[0] = {
                                "status": "error",
                                "msg": ("Not installed, so not mounted: %s. Check free disk on "
                                        "the host, then try again. %s" % (_labels, msg or "")).strip(),
                                "ts": time.time()}
                            return
                    else:
                        ok, msg = gmod_mount_setup(remote, gmod_user, "", [])
                    _result[0] = {
                        "status": "done" if ok else "error", "msg": msg, "ts": time.time()}
                except Exception:
                    _log.warning("gmod content apply failed for %s", gmod_user, exc_info=True)
                    _result[0] = {
                        "status": "error", "msg": "Content setup failed — check the server logs.",
                        "ts": time.time()}
                finally:
                    _publish_gmod_job(server_id, remote_id, _result[0])

        _start_gmod_content_worker(remote_id, _run)

    def _bg_gmod_content_uninstall(server_id, remote_id, gmod_user, games):
        """Uninstall content from the host (host-wide) in the background, then drop the removed games
        from THIS server's mounts. Result is stashed for the status poll."""
        _app = app
        _gmod_content_apply_state[server_id] = {"status": "running", "msg": "", "ts": time.time()}

        _result = [None]

        def _run():
            with _app.app_context():
                try:
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    cu = detect_content_user(remote, tuple(GMOD_CONTENT_GAMES))
                    # No content user at all: nothing was asked of the host, so there is nothing
                    # this could have failed to confirm — `asked` stays empty rather than turning
                    # every game into an unconfirmed removal.
                    _asked, removed = [], []
                    if cu:
                        _asked = list(games)
                        _, removed, _m = uninstall_gmod_content(remote, cu["user"], games)
                    # Drop the removed games from THIS server's mount.cfg (other servers just skip the
                    # now-missing mount). Best-effort — but NOT when the current mounts could not be
                    # read: `remaining` would be [], and writing that back unmounts everything the
                    # server had, including games nobody asked to remove.
                    _cur = gmod_current_mounts(remote, gmod_user)
                    if _cur is None:
                        _log.warning("gmod content uninstall: mounts unreadable for %s — leaving "
                                     "mount.cfg alone", gmod_user)
                    else:
                        gmod_mount_setup(remote, gmod_user, (cu or {}).get("user", ""),
                                         [g for g in _cur if g not in games])
                    _st, _msg = _gmod_removal_result(_asked, removed)
                    _result[0] = {
                        "status": _st, "msg": _msg, "ts": time.time()}
                except Exception:
                    _log.warning("gmod content uninstall failed for %s", gmod_user, exc_info=True)
                    _result[0] = {
                        "status": "error", "msg": "Uninstall failed — check the server logs.",
                        "ts": time.time()}
                finally:
                    _publish_gmod_job(server_id, remote_id, _result[0])

        _start_gmod_content_worker(remote_id, _run)

    def _start_gmod_content_worker(remote_id, run):
        """Start a content worker; the host the route claimed is released by the worker's own
        finally — or here, if the thread never starts, so a failed start cannot wedge the host."""
        try:
            threading.Thread(target=run, daemon=True).start()
        except Exception:
            _release_gmod_content_host(remote_id)
            raise

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
                # `or []` collapsed the THIRD answer into the second. gmod_current_mounts
                # returns a list, [] for "mounts nothing", and None for "the mount state could
                # not be read" — its docstring calls that distinction the whole point. Collapsed,
                # a failed read painted every checkbox unticked, i.e. "this server mounts
                # nothing"; applying that card writes exactly the visible selection, so an empty
                # one unmounts everything. The uninstall worker 33 lines above already guards the
                # same call for the same reason.
                _mounts = gmod_current_mounts(remote, gs.short_name)
                mounted = _mounts or []
                cu = detect_content_user(remote, tuple(GMOD_CONTENT_GAMES))
                present = set((cu or {}).get("present", {}))
                games = [{"key": k, "label": GMOD_CONTENT_GAMES[k][0], "size": GMOD_CONTENT_SIZES.get(k, ""),
                          "present": (k in present), "mounted": (k in mounted),
                          "downloadable": GMOD_CONTENT_GAMES[k][1] is not None} for k in GMOD_CONTENT_GAMES]
                # The job, INCLUDING a terminal one the card has not shown yet — see
                # _gmod_job_state for what filtering to "running" cost.
                st = _gmod_job_state(server_id)
                # Free disk on the filesystem where content is stored — so nobody starts a 13GB
                # install without room. Uses the content user's serverfiles if one exists, else /home.
                content_path = ("/home/%s/serverfiles" % cu["user"]) if cu else "/home"
                disk_free, disk_total = path_disk_free(remote, content_path)
                return jsonify({"games": games, "mounted": mounted,
                                # False = the host did not answer. The card must not offer an
                                # Apply built on ticks it could not read.
                                "mounts_readable": _mounts is not None,
                                "disk_free": disk_free, "disk_total": disk_total,
                                "job": st})
            except Exception:
                return jsonify({"error": _log_and_generic("gmod content status failed"), "games": []}), 200
        # POST: apply a selection (mutating). The MANAGE_SERVERS gate is at the top of the route.
        body = _json_body()
        action = body.get("action") or "mount"
        sel = [g for g in (body.get("games") or []) if g in GMOD_CONTENT_GAMES]
        _busy = jsonify({"success": False, "message": (
            "A Garry's Mod content job is already running on this host. Content is shared by every "
            "GMod server here, so wait for that one to finish, then try again.")}), 409
        if action == "uninstall":
            if not _claim_gmod_content_host(remote.id):
                return _busy
            _bg_gmod_content_uninstall(gs.id, remote.id, gs.short_name, sel)
            log_action(current_user, "gmod_content_uninstall", target=gs.name, detail=",".join(sel))
            return jsonify({"success": True, "games": sel,
                            "message": "Removing content from the host — this frees disk for every GMod "
                                       "server here. Restart affected servers afterwards."})
        # Refuse the write when the CURRENT mounts cannot be read, whatever the page sent.
        # gmod_mount_setup rewrites mount.cfg to exactly this selection, so applying a card that
        # was built from an unreadable state silently unmounts whatever the server really had.
        # Guarding here and not only in the UI: this is the request that does the damage.
        if gmod_current_mounts(remote, gs.short_name) is None:
            return jsonify({"success": False, "message": (
                "Couldn't read this server's current mounts, so the panel won't rewrite them — "
                "applying now could unmount content the server already has. Check the host is "
                "reachable and reload this card.")}), 409
        if not _claim_gmod_content_host(remote.id):
            return _busy
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
        host_tz = _host_timezone_cached(remote, app)
        # Whether the log was actually READ, kept separate from what it held. The route knew this
        # and threw it away: a host that did not answer, a `tail -2000` that timed out on a slow
        # link, a log that does not exist and a genuinely empty log all left here as 200 with the
        # same `lines: []`, and nothing in the payload told them apart. The browser's "Load older"
        # believed it, emptied its own scrollback — the only copy, since the poller emits a sliding
        # window and keeps nothing — and toasted "Loaded 0 lines from the log" about a log it never
        # opened. Same answer api_server_upload_check gives with `checked`, for the same reason.
        readable = False
        try:
            log_path = gs.console_log
            # AS THE GAME USER, not as root: the log sits inside a 0750 home. See
            # _core.read_as_game_user for why this was a root read and what that cost.
            # FRAMED, like the poller's reads, and for the same reason: run_command strips the
            # output, so the window's LAST line lost its trailing whitespace and its FIRST line its
            # indentation. The browser de-duplicates this window against lines the poller pushed,
            # by exact string — and the pushed copies were not stripped. Minecraft's "There are 0
            # of a max of 20 players online: " ends in a space, so after every `list` the page
            # found no overlap and appended the whole window again beneath the reply: the
            # "console stops responding until I press Load older" report.
            out, err, rc = _sm.read_as_game_user(
                remote, gs.short_name,
                # tail's OWN status is the answer, not printf's: without `exit $r` a log that does
                # not exist (LinuxGSM's start is `mv` then `touch`) came back framed, rc 0, empty —
                # "readable, and nothing in it" — and Load older wiped the console on that.
                f"printf B; tail -{want} {log_path} 2>/dev/null; r=$?; printf E; exit $r",
                timeout=15)
            framed = rc == 0 and (out or "").startswith("B") and (out or "").endswith("E")
            readable = framed
            body = out[1:-1] if framed else ""
            if body.endswith("\n"):
                body = body[:-1]     # the file's own final newline, not an empty last line
            lines = _console_rows(_clean_console_text(body).split("\n"), host_tz) if framed else []
        except Exception:
            lines = []
        # What the PANEL pushed into this console (a long action's markers and output) — its own
        # field, not spliced into `lines`. Two reasons: the browser de-duplicates `lines` by
        # matching the overlap between successive windows, and a block that is stable at the end
        # of every response would defeat that; and these did not come from the file being tailed,
        # so a caller that wants the game log verbatim still gets exactly it.
        # Each row is {t, line}. `t` is set ONLY where the line carries LinuxGSM's own timestamp,
        # written into the log at write time and converted here from the host's clock to an epoch
        # — the one way a line written while nobody was watching can have a real time. Everything
        # else has t=null: the panel is seeing those now but they were written at some unknowable
        # point before that, and dating them "now" would put a confident wrong time on a week of
        # history.
        #
        # `now` is the panel's clock at the moment it read this window, for the browser to stamp
        # the lines that are NEW since its last poll — those it did watch arrive. Sent from the
        # server rather than taken from Date.now() so every console time shares one clock.
        return jsonify({"lines": lines, "now": time.time(),
                        # False = the console was not read, so `lines` is not a measurement of
                        # what the log holds. A caller must not redraw a scrollback from it.
                        "readable": readable,
                        "log_timestamps": any(r.get("t") for r in lines),
                        "panel_lines": list(_console_backlog.get(server_id, []))})

    @app.route("/api/server/<int:server_id>/log-timestamps", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_log_timestamps(server_id):
        """Read LinuxGSM's own `logtimestamp`, or turn it OFF. It stamps the console log AT WRITE TIME.

        This is the only way a line written while nobody was watching can carry a real time — the
        panel tails the file, so on its own it can date only what it saw arrive, and an idle
        server's whole history is therefore blank. With this on, LinuxGSM pipes the tmux capture
        through `gawk strftime` and every line arrives already dated.

        It edits the instance's LinuxGSM config, so it needs the same permission as the rest of
        the config editor, and it only takes effect on the server's next START — `pipe-pane` is
        wired up in command_start.sh. Both facts are reported rather than assumed away."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            if request.method == "POST":
                # OFF only. The page withdrew its "turn on" control once it was measured that
                # LinuxGSM's stamping pipeline (`cat | gawk strftime >> consolelog`) block-buffers
                # to the file and freezes the live console for as long as 4KB takes to accumulate
                # — but this endpoint still accepted `enabled: true`, so anyone with the config
                # permission could still freeze every viewer's console with one request. The
                # reading side stays: a log someone stamped by hand is still parsed.
                if _json_body().get("enabled"):
                    return jsonify({"error": "Turning LinuxGSM's log timestamps on freezes the "
                                             "live console, so the panel only turns them off."}), 400
                want = "off"
                ok, msg = lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name,
                                            {"logtimestamp": want})
                if not ok:
                    return jsonify({"error": msg or "Could not write the LinuxGSM config"}), 502
                log_action(current_user, "set_log_timestamps", target=gs.name, detail=want)
                return jsonify({"success": True, "enabled": want == "on",
                                "needs_restart": True})
            vals = lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, ["logtimestamp"])
            if vals is None:
                # "enabled": False would be a claim about a config we could not read, and the
                # toggle renders from it — say so instead, like the write path above.
                return jsonify({"error": "Could not read the LinuxGSM config on this host."}), 502
            return jsonify({"enabled": _json_str(vals, "logtimestamp").strip('"') == "on"})
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500

    @app.route("/api/command/<int:server_id>", methods=["POST"])
    @login_required
    @server_access_required
    def api_send_command(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        data = _json_body()
        cmd_text = _json_str(data, "command")

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
        # A host that is switched off is a normal condition, not a fault in the panel — the same
        # distinction api_remote_live_stats draws. Anything that is NOT a ConnectionError stays a
        # 500 on purpose: those are ours.
        except ConnectionError:
            return _unreachable("send console command")
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500


    # A per-request check (app._socket_origin_allowed): same origin including the port, or
    # site_domain, or the operator's explicit list. See _socketio_cors.
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
        # ...and not an account still holding a handed-over temporary password. That gate is an
        # @app.before_request (app.py), and a before_request NEVER runs for a Socket.IO event —
        # flask-socketio's middleware takes /socket.io/ ahead of the Flask app — so the whole
        # socket surface sat outside it. Every HTTP route answered 403 password_change_required
        # while a client on the same cookie could emit join_console and be streamed a live console:
        # RCON output, admin commands, player names and connect lines, to a session the panel had
        # decided may not use the panel yet. host_terminal's _may_use_terminal asks this for
        # exactly this reason; this is THE connect handler for the namespace, so asking here covers
        # every event on it.
        if getattr(current_user, "must_change_password", False):
            return False
        # Recorded for the ban sweep. A handshake from an address already banned is refused here
        # too: ProxiedBanGate refuses it first on every path it sees, and this costs one lookup.
        _addrs = _handshake_addrs()
        if _addrs_banned(_addrs):
            return False
        with _viewers_lock:
            _socket_addrs[request.sid] = _addrs
        return True   # authenticated, password their own → accept the socket

    from panel.security import banlist as _banlist

    @_banlist.on_change
    def _ban_sweep():
        _drop_banned_sockets(app, socketio)

    @socketio.on("join_console")
    def on_join_console(data):
        # int(), because the ROOM NAME is built from this value and the console poller emits to
        # f"console_{gs.id}" with a real int. A client that sent "3" passed the access check
        # (SQLAlchemy coerces the lookup) and then joined "console_3" as a string-derived room the
        # poller never pushes to — an authorised viewer with a permanently silent console.
        try:
            server_id = int(data.get("server_id"))
        except (TypeError, ValueError):
            return
        if server_id <= 0:
            return
        # Enforce the SAME access control as the HTTP console routes: the socket must
        # belong to a logged-in user who has access to this specific server AND holds
        # VIEW_CONSOLE. Without this, any socket could stream any server's console.
        # must_change_password is asked again here, not only in the connect handler: a socket
        # opened BEFORE an admin reset that account's password is already connected, and connect
        # does not run a second time.
        if (not current_user.is_authenticated
                or getattr(current_user, "must_change_password", False)
                or not can_access_server(current_user, server_id)
                or not (current_user.is_superadmin or has_permission(current_user, VIEW_CONSOLE))):
            emit("console_output", {"server_id": server_id,
                                    "data": "[access denied — you don't have permission to view this console]"})
            return
        join_room(f"console_{server_id}")
        _cred = _viewer_credential()
        with _viewers_lock:
            _console_viewers.setdefault(server_id, {})[request.sid] = current_user.id
            _viewer_creds[request.sid] = _cred

    @socketio.on("leave_console")
    def on_leave_console(data):
        # int(), for the same reason join does it: _console_viewers is keyed by the int the join
        # handler put there, so a client that sent "3" here left the ROOM (the f-string spells the
        # same name either way) and then looked its sid up under a key that does not exist. The
        # entry survived, and the console poller went on paying an SSH round trip every two
        # seconds for a console nobody was watching — until the socket itself dropped, which is
        # the only other thing that clears it.
        try:
            server_id = int(data.get("server_id"))
        except (TypeError, ValueError):
            return
        leave_room(f"console_{server_id}")
        with _viewers_lock:
            if server_id in _console_viewers:
                _console_viewers[server_id].pop(request.sid, None)
                if not _console_viewers[server_id]:
                    del _console_viewers[server_id]

    @socketio.on("disconnect")
    def on_console_disconnect():
        # THE disconnect handler for the whole app. flask-socketio keeps one handler per event per
        # namespace and a second registration replaces this one outright, so everything else that
        # cleans up per-socket state goes through socket_hooks instead of adding its own.
        sid = request.sid
        # A browser that closed without leave_console must still stop the poller.
        with _viewers_lock:
            for watchers in list(_console_viewers.values()):
                watchers.pop(sid, None)
            for k in [k for k, v in _console_viewers.items() if not v]:
                del _console_viewers[k]
            _viewer_creds.pop(sid, None)
            _socket_addrs.pop(sid, None)
        _socket_hooks.run_disconnect_hooks(sid)

    # Console polling thread — streams new console output to WebSocket viewers.
    def console_poller():
        while True:
            try:
                with _viewers_lock:
                    active_ids = list(_console_viewers.keys())
                # Before the early-out: a console whose last viewer just left must lose its offset
                # now, or reopening it replays everything written in between as if it were live.
                _forget_unwatched_consoles(active_ids)
                if active_ids:
                    with app.app_context():
                        for server_id in active_ids:
                            gs = db.session.get(GameServer, server_id)
                            if not gs or not gs.remote:
                                continue
                            # RE-ASK who may watch this, every tick. The join handler's check is a
                            # one-time question, and the answer can change while the socket stays
                            # open: a group removed, a permission dropped, the account
                            # deactivated. Evicting from the ROOM is what actually stops the
                            # stream; dropping the viewer entry alone would only stop the polling.
                            _evicted = _evict_unauthorized_viewers(app, socketio, server_id)
                            if _evicted:
                                app.logger.info(
                                    "console: dropped %d viewer(s) of server %s whose access no "
                                    "longer permits it", _evicted, server_id)
                            with _viewers_lock:
                                if not _console_viewers.get(server_id):
                                    continue      # nobody left who may see it — do not read
                            try:
                                # A long panel action (update/validate/backup/…) writes its output
                                # to its own file on the host, NOT to the game's console log — so
                                # tail that too while one is running. Without this the console
                                # stayed silent for the whole of an update the panel had just told
                                # the operator to watch it for.
                                _drain_action_output(app, gs.remote, server_id)
                                _console_tick(app, socketio, gs, server_id)
                            except Exception:  # nosec B112 - try/except/continue is the point:
                                # one unreadable console must not stop the poll for every OTHER
                                # server. The next tick retries this one; the failure is visible
                                # as a console that stops updating, not as a dead poller.
                                continue
            except Exception:
                app.logger.debug("console poller iteration failed", exc_info=True)
            time.sleep(2)


    supervise("console-poller", console_poller)





    return socketio
