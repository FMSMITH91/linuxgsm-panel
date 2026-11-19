"""The panel's side of the SFTP service: start and stop it, and answer every question it asks.

The service (sftp_server.py) runs as a child process of the panel. This module, in the panel:

* starts it when Settings turns it on, with the addresses, port and host key it is to use; stops
  it when Settings turns it off or changes it, and starts it again; starts it again after a crash
  (a supervised loop, app._make_supervisor), and it ends with the panel (its stdin is the panel's);
* answers its questions over a socket pair, one JSON line each way, read by ONE greenlet that owns
  the socket (memory one-greenlet-per-descriptor), each answered in a greenlet of its own: may
  this address connect; is this key, or this password and code, a sign-in for this name; which
  servers may this user's files be edited on; may this request go ahead; and the audit rows.

The answers use what the web sign-in uses, in this process where its state lives:
* the address throttle (app._LOGIN_FAILS: 8 failures in 5 minutes, and account_guard's day limit
  per address), the per-account pause (account_guard), the ban list (security/banlist), and
  data/auth.log, whose "panel sftp login failed from <ip>" lines the panel's fail2ban jail counts
  (OWASP Authentication Cheat Sheet, "Login Throttling", "Account Lockout"; "Logging and
  Monitoring": every failure and every lockout logged);
* the password (Argon2id, checked off the hub) and the authenticator code, single use (OWASP
  Multifactor Authentication Cheat Sheet 5.3.2: "Reject a code that has already been accepted");
* a deactivated account, one that must change its password, and one Settings requires 2FA of that
  has none, are refused (MFA Cheat Sheet 4 and 5.2: when several sign-in paths exist they "should
  all require MFA, or have other protections implemented");
* the same permission and server-access checks as the web file manager, on every request (OWASP
  Authorization Cheat Sheet, "Validate the Permissions on Every Request"), and the same refusals of
  a game account that can become root (routes/_shared.game_account_write_refusal) and of writes
  while the server is being restored.
The SSH client only ever sees "authentication failed": which check refused is in the audit row
(OWASP Authentication Cheat Sheet, "Authentication and Error Messages").
"""
import json
import logging
import os
import socket
import subprocess  # nosec B404 - one fixed argv: this interpreter and the service's module
import sys
import threading
import time

from panel.services import sftp_common as sc

_log = logging.getLogger("panel.sftp")

_STATUS = {"state": "off", "bound": [], "error": "", "detail": "", "since": 0.0}
_STATE = {"proc": None, "spawn": None}
_WAKE = threading.Event()
_LOCK = threading.Lock()
RETRY_SECONDS = 30
AUDIT_ACTIONS = frozenset({"upload_file", "delete_file", "rename_file", "create_folder", "edit_file"})


def home_of(gs):
    """The home of `gs`'s game account, as the web file manager reaches it (ssh_manager/files.py)."""
    return "/home/%s" % gs.short_name


# ── state the Settings card shows ──────────────────────────────────────────────────────────────
def status():
    """A copy of the service's state: {state, bound, error, detail, since}."""
    with _LOCK:
        return dict(_STATUS, bound=list(_STATUS["bound"]))


def _set_status(state, bound=(), error="", detail=""):
    """Record the service's state: `error` is a fixed sentence (translated), `detail` the host's own text."""
    with _LOCK:
        _STATUS.update(state=state, bound=[list(b) for b in bound], error=error, detail=str(detail)[:300],
                       since=time.time())


# ── starting and stopping ──────────────────────────────────────────────────────────────────────
def start_supervisor(app):
    """Run the service loop under the panel's supervisor (named, respawned, never in the recovery CLI)."""
    from app import _make_supervisor   # lazily: app imports the routes that call this while loading
    _make_supervisor(app)("sftp-service", lambda: run_loop(app))


def restart():
    """Stop the service so the loop starts it again with the settings as they are now (or leaves it off)."""
    _WAKE.set()
    _stop_child()


def _stop_child():
    proc = _STATE.get("proc")
    if proc is None:
        return
    try:
        if proc.stdin:
            proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        try:
            proc.kill()
        except OSError:
            _log.debug("SFTP service already gone", exc_info=True)


def run_loop(app):
    """Keep the service in the state Settings asks for, for the life of the panel."""
    while True:
        _WAKE.clear()
        spawn, why = spawn_config(app)
        if spawn is None:
            _set_status("off" if why is None else "waiting", error=why or "")
            _WAKE.wait(None if why is None else RETRY_SECONDS)
            continue
        ended_ok = run_once(app, spawn)
        if not _WAKE.is_set():
            _WAKE.wait(5 if ended_ok else RETRY_SECONDS)


def spawn_config(app):
    """(what the service is started with, None), or (None, None) when off, or (None, why it waits)."""
    from panel.core.config import decrypt_secret, encrypt_secret, load_config, update_config, is_unreadable
    cfg = load_config()
    if is_unreadable(cfg):
        return None, "config.json could not be read."
    s = sc.settings(cfg)
    if not s["enabled"]:
        return None, None
    ts_ips = tailscale_ips()
    choice = s["bind"] or sc.default_bind(bool(ts_ips))
    binds = sc.bind_addresses(choice, ts_ips, sc.host_has_ipv6())
    if not binds:
        return None, "Waiting for this host's Tailscale address."
    key = sc.ensure_host_key(update_config, load_config, encrypt_secret, decrypt_secret)
    return {"ok": True, "binds": binds, "port": s["port"], "password": s["password"],
            "cap_mb": s["cap_mb"], "idle_min": s["idle_min"], "absolute_h": s["absolute_h"],
            "absolute_grace_min": sc.ABSOLUTE_GRACE_MINUTES, "host_key": key, "choice": choice}, None


def tailscale_ips():
    """The Tailscale addresses of this host while Tailscale is up, else []."""
    try:
        from panel.ops import tailscale_integration as ts
        info = ts.get_tailscale_info()
        return list(getattr(info, "tailscale_ips", None) or []) if getattr(info, "running", False) else []
    except Exception:  # noqa: BLE001 - no Tailscale is an answer
        _log.debug("tailscale info unavailable", exc_info=True)
        return []


def run_once(app, spawn, argv=None):
    """Start the service, answer it until it ends, and return whether it had been listening."""
    from panel import REPO_ROOT
    ours, theirs = socket.socketpair()
    env = dict(os.environ, **{sc.IPC_FD_ENV: str(theirs.fileno())})
    _set_status("starting")
    try:
        proc = subprocess.Popen(argv or [sys.executable, "-m", "panel.services.sftp_server"],  # nosec B603
                                cwd=str(REPO_ROOT), env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, pass_fds=(theirs.fileno(),))
    except OSError as exc:
        theirs.close()
        ours.close()
        _set_status("error", error="The SFTP service could not be started.", detail=type(exc).__name__)
        return False
    theirs.close()
    _STATE.update(proc=proc, spawn=spawn)
    listening = False
    try:
        listening = serve(app, ours, spawn)
    finally:
        ours.close()
        _stop_child()
        _STATE["proc"] = None
        if _STATUS["state"] in ("running", "starting"):
            _set_status("error" if not _WAKE.is_set() else "off",
                        error="" if _WAKE.is_set() else "The SFTP service stopped; starting it again.")
    return listening


HANDLER_SLOTS = 16          # requests answered at once; one more waits for a slot


def serve(app, sock, spawn):
    """Answer the service's requests until its socket closes. -> whether it reported listening.

    This greenlet alone reads the socket (a second reader of one descriptor fails); each request is
    answered in a thread (a greenlet in the panel) of its own, so one slow answer (a host that does
    not answer the permission check, which can take minutes) never holds every other user's
    sign-in, listing and transfer. The answer carries the request's id, which is how the service
    matches it. "hello" and "ready" are answered here, in order: the start depends on them.
    """
    rf = sock.makefile("rb")
    link = {"sock": sock, "lock": threading.Lock(), "open": True,
            "slots": threading.BoundedSemaphore(HANDLER_SLOTS)}
    listening = False
    try:
        while True:
            line = rf.readline(1024 * 1024)
            if not line:
                return listening
            try:
                req = json.loads(line)
            except ValueError:
                continue
            if not isinstance(req, dict):
                continue
            if req.get("op") in ("hello", "ready"):
                listening = listening or bool(req.get("op") == "ready" and req.get("bound"))
                _answer(app, link, req, spawn)
                continue
            link["slots"].acquire()
            threading.Thread(target=_answer_in_slot, args=(app, link, req, spawn), name="sftp-answer",
                             daemon=True).start()
    finally:
        with link["lock"]:
            link["open"] = False        # an answer still being worked out is not sent on a closed socket


def _answer_in_slot(app, link, req, spawn):
    try:
        _answer(app, link, req, spawn)
    finally:
        link["slots"].release()


def _answer(app, link, req, spawn):
    """Work out one answer and send it, unless the service's socket has gone meanwhile."""
    data = json.dumps(dict(handle(app, req, spawn), id=req.get("id"))).encode("utf-8") + b"\n"
    with link["lock"]:
        if not link["open"]:
            return
        try:
            link["sock"].sendall(data)
        except OSError:
            _log.debug("the SFTP service's socket closed before an answer", exc_info=True)


def handle(app, req, spawn):
    """The answer to one request (a dict); never raises."""
    op = req.get("op")
    fn = _HANDLERS.get(op)
    if fn is None:
        return {"ok": False}
    try:
        with app.app_context():
            return fn(app, req, spawn)
    except Exception:  # noqa: BLE001 - a failed answer is a refusal, never a crashed loop
        _log.exception("SFTP request %s failed", op)
        return {"ok": False}


# ── the answers ────────────────────────────────────────────────────────────────────────────────
def _h_hello(_app, req, spawn):
    return dict(spawn)


def _h_ready(app, req, spawn):
    bound = req.get("bound") or []
    if bound:
        _set_status("running", bound=bound, detail=req.get("error") or "")
        f2b_follow(app)
    else:
        _set_status("error", error="The SFTP service could not listen on its address.", detail=req.get("error") or "")
    return {"ok": True}


def f2b_follow(app):
    """Rewrite the panel's fail2ban jail for the SFTP settings as saved (in a thread; best-effort).

    On every start and every Settings save, not only for "all addresses": the jail lists the SFTP
    port only while that is the choice (system_ops._panel_f2b_sftp_port), so leaving it, or turning
    the service off, has to rewrite the jail too. Only "all" used to: the port stayed listed until
    something else rewrote the jail. An unchanged jail is left as it is (ensure_panel_fail2ban).
    Returns the started thread.
    """
    def _run():
        try:
            from app import _apply_whitelist_to_fail2ban
            with app.app_context():
                _apply_whitelist_to_fail2ban()
        except Exception:  # noqa: BLE001 - the jail is best-effort, as at boot
            _log.debug("fail2ban update for SFTP failed", exc_info=True)
    worker = threading.Thread(target=_run, name="sftp-f2b", daemon=True)
    worker.start()
    return worker


def _ip(req):
    from panel.core.validation import canonical_ip
    return canonical_ip(str(req.get("ip") or "")) or "unknown"


def _throttled(ip, now):
    """Whether this address may not try to sign in now (the web sign-in's address limits)."""
    from app import LOGIN_MAX_FAILS, LOGIN_WINDOW, _LOGIN_FAILS, _LOGIN_FAILS_LOCK, _prune_login_fails
    from panel.security import account_guard
    from panel.security.auth import throttle_key
    tk = throttle_key(ip)
    with _LOGIN_FAILS_LOCK:
        _prune_login_fails(now)
        fails = [t for t in _LOGIN_FAILS.get(tk, []) if now - t < LOGIN_WINDOW]
    return len(fails) >= LOGIN_MAX_FAILS or account_guard.ip_day_blocked(tk, now)


def _count_failure(ip, now):
    """Count one failed sign-in from `ip` for the address throttle and its day limit."""
    from app import _LOGIN_FAILS, _LOGIN_FAILS_LOCK
    from panel.security import account_guard
    from panel.security.auth import throttle_key
    tk = throttle_key(ip)
    with _LOGIN_FAILS_LOCK:
        _LOGIN_FAILS.setdefault(tk, []).append(now)
    account_guard.ip_day_note(tk, now)


def _authlog(ip, what="failed"):
    """The data/auth.log line the panel's fail2ban jail counts."""
    from app import _authlog as log, _log_ip
    log.warning("panel sftp login %s from %s", what, _log_ip(ip))


def _as_request(ip):
    """A request context whose client address is `ip`: log_action and the lockout read it there."""
    from flask import current_app
    return current_app.test_request_context("/", environ_base={"REMOTE_ADDR": ip if ip != "unknown" else ""})


def _sftp_audit(ip, user, action, target="", detail="", success=True, actor=None, server=None):
    """log_action, with the client's address as the row's address."""
    from panel.security.auth import log_action
    with _as_request(ip):
        log_action(user, action, target=target, detail=detail, success=success, actor=actor, server=server)


def _h_conn(_app, req, _spawn):
    import ipaddress
    from panel.security import banlist
    ip = _ip(req)
    try:
        banned = banlist.is_banned(ipaddress.ip_address(ip))
    except ValueError:
        banned = False
    if banned:
        return {"ok": False}
    if _throttled(ip, time.time()):
        _authlog(ip, "blocked")
        return {"ok": False}
    return {"ok": True}


def user_refusal(user):
    """Why `user` may not use SFTP now (for the audit row), or None. A None user is no such user."""
    from panel.security import account_guard
    if user is None:
        return "no such user"
    if not user.is_active:
        return "account disabled"
    if user.must_change_password:
        return "must change the password first"
    if account_guard.twofa_required(user):
        return "two-factor authentication is required and not set up"
    # The name's pause is not asked here: it is for guessed passwords (account_reserve, in the
    # password sign-in). A key cannot be guessed, so a pause that wrong passwords sent by anyone can
    # keep up must not shut a user's key sign-in or end their open session (OWASP Authentication
    # Cheat Sheet, "Account Lockout": a lockout must not become a denial of service).
    return None


def _named(username):
    from panel.core.validation import MAX_USERNAME_LEN
    from panel.db.models import User
    name = str(username or "").strip()[:MAX_USERNAME_LEN]
    return name, (User.query.filter_by(username=name).first() if name else None)


def _h_auth_key(_app, req, _spawn):
    import base64
    from panel.db.models import SftpKey
    ip, now = _ip(req), time.time()
    if _throttled(ip, now):
        return {"ok": False, "why": "address rate-limited"}
    _name, user = _named(req.get("username"))
    why = user_refusal(user)
    if why:
        return {"ok": False, "why": why}
    try:
        blob = base64.b64decode(str(req.get("blob") or ""), validate=True)
    except ValueError:
        return {"ok": False, "why": "malformed key"}
    fp = sc.fingerprint(blob)
    row = SftpKey.query.filter_by(user_id=user.id, fingerprint=fp).first()
    if row is None or not sc.key_matches(row.key_type, row.key_blob, str(req.get("type") or ""), blob):
        return {"ok": False, "why": "key not registered for this account"}
    # Not "last used" yet: paramiko asks this before it checks the signature (and for a client's
    # unsigned "would this key do?"), so anyone holding the public key gets this far. auth_done
    # stamps it once the session has really started.
    return {"ok": True, "uid": user.id, "epoch": user.auth_epoch or 0, "name": user.username, "fp": fp,
            "detail": "key %s (%s)" % (row.label or sc.KEY_TYPES.get(row.key_type, row.key_type), fp)}


def _h_auth_kbd(_app, req, spawn):
    from panel.security import account_guard
    ip, now = _ip(req), time.time()
    if not (spawn or {}).get("password"):
        return {"ok": False}
    if _throttled(ip, now):
        _authlog(ip, "blocked")
        return {"ok": False}
    _count_failure(ip, now)              # reserved now, given back only on a sign-in (as /login does)
    name, user = _named(req.get("username"))
    slot, _left = account_guard.account_reserve(name, now)
    if slot is None:
        return _kbd_fail(ip, name, now, None, "sign-ins for this name are paused after repeated failures")
    why = _kbd_refusal(user, req)
    if why:
        return _kbd_fail(ip, name, now, slot, why)
    account_guard.account_release(slot)
    _release_failure(ip, now)
    return {"ok": True, "uid": user.id, "epoch": user.auth_epoch or 0, "name": user.username}


def _kbd_refusal(user, req):
    """Why this password and code do not sign `user` in (for the audit row), or None when they do."""
    from panel.security.auth import check_password, dummy_password_check
    password = req.get("password") if isinstance(req.get("password"), str) else ""
    why = user_refusal(user) if user is not None else None
    if user is None or not user.is_active:
        dummy_password_check(password)          # the same time spent whether the name exists or not
        return why or "no such user"
    if not check_password(password, user.password_hash):
        return "wrong password"
    return why or _code_refusal(user, req.get("code"))


def _code_refusal(user, code):
    """Why the second factor is refused, or None once its time step is spent (single use)."""
    from panel.db.models import db
    from panel.routes._shared import spend_totp_step
    from panel.security.auth import verify_totp_step
    if not user.totp_enabled:
        return "password sign-in over SFTP needs two-factor authentication on the account"
    step = verify_totp_step(user.totp_secret_plain, str(code or ""))
    if step is None:
        return "wrong authenticator code"
    if step <= (user.last_totp_step or 0) or not spend_totp_step(user, step):
        db.session.rollback()
        return "authenticator code already used"
    db.session.commit()
    return None


def _release_failure(ip, now):
    """Give back the address slot _count_failure took, for an attempt that signed in."""
    from app import _LOGIN_FAILS, _LOGIN_FAILS_LOCK
    from panel.security.auth import throttle_key
    tk = throttle_key(ip)
    with _LOGIN_FAILS_LOCK:
        fails = _LOGIN_FAILS.get(tk)
        if fails and now in fails:
            fails.remove(now)
            if not fails:
                _LOGIN_FAILS.pop(tk, None)


def _kbd_fail(ip, name, now, slot, why):
    """Log, audit and (once per pause) alert one failed password sign-in; the refusal answer."""
    from flask import g
    from panel.routes.auth_routes import _note_lockout
    _authlog(ip)
    who = name or "(blank)"
    _sftp_audit(ip, None, "sftp_login_failed", target=who, actor=who, detail="password: %s" % why, success=False)
    with _as_request(ip):
        g._login_slot = slot
        _note_lockout(who, ip, now)
    return {"ok": False}


def _h_auth_fail(_app, req, _spawn):
    ip, now = _ip(req), time.time()
    name, _user = _named(req.get("username"))
    _count_failure(ip, now)
    _authlog(ip)
    who = name or "(blank)"
    reason = str(req.get("why") or "no accepted key")[:200]
    _sftp_audit(ip, None, "sftp_login_failed", target=who, actor=who, detail="key: %s" % reason, success=False)
    return {"ok": True}


def _h_auth_done(_app, req, _spawn):
    from panel.core.clock import utcnow
    from panel.db.models import User, db
    user = db.session.get(User, int(req.get("uid") or 0))
    if user is None:
        return {"ok": False}
    row = _session_key(user, req)
    if row is not None:
        row.last_used = utcnow()
        db.session.commit()
    method = "key" if req.get("method") == "publickey" else "password and code"
    _sftp_audit(_ip(req), user, "sftp_login", target=user.username,
           detail="%s: %s" % (method, str(req.get("detail") or "")[:300]))
    return {"ok": True}


def _h_session_end(_app, req, _spawn):
    from panel.db.models import User, db
    user = db.session.get(User, int(req.get("uid") or 0))
    if user is None:
        return {"ok": False}
    _sftp_audit(_ip(req), user, "sftp_session_closed", target=user.username,
                detail=str(req.get("why") or "")[:200])
    return {"ok": True}


def _session_key(user, req):
    """The SftpKey row a key session signed in with (its fingerprint `fp`), or None (gone, or no key)."""
    from panel.db.models import SftpKey
    fp = str(req.get("fp") or "")
    return SftpKey.query.filter_by(user_id=user.id, fingerprint=fp).first() if fp else None


def _session_user(req):
    """(the user a signed-in SFTP session belongs to, None), or (None, why) when it may not go on.

    A session signed in with a key ends once that key is removed from the Account page: removing a
    key someone else holds must cut them off, not leave them until the idle or absolute limit.
    """
    from panel.db.models import User, db
    user = db.session.get(User, int(req.get("uid") or 0))
    if user is None or (user.auth_epoch or 0) != req.get("epoch"):
        return None, "signed out"
    if req.get("fp") and _session_key(user, req) is None:
        return None, "the key it signed in with was removed"
    why = user_refusal(user)
    return (None, why) if why else (user, None)


def editable(user):
    """{folder name: GameServer} of the servers `user` may edit files on (edit_files and access)."""
    from panel.security.auth import EDIT_FILES, get_user_permissions, get_user_servers
    if not (user.is_superadmin or EDIT_FILES in get_user_permissions(user)):
        return {}
    servers = {gs.id: gs for gs in get_user_servers(user)}
    return {name: servers[sid] for name, sid in sc.folder_names((gs.id, gs.name) for gs in servers.values()).items()}


def _h_servers(_app, req, _spawn):
    user, why = _session_user(req)
    if user is None:
        return {"ok": False, "reason": "Your SFTP session has ended (%s)." % why}
    return {"ok": True, "folders": sorted(editable(user))}


def _h_authz(_app, req, _spawn):
    from panel.security.auth import VIEW_FILES, get_user_permissions
    user, why = _session_user(req)
    if user is None:
        return {"ok": False, "reason": "Your SFTP session has ended (%s)." % why}
    gs = editable(user).get(str(req.get("folder") or ""))
    if gs is None:
        return {"ok": False, "gone": True}
    if not req.get("write") and not (user.is_superadmin or VIEW_FILES in get_user_permissions(user)):
        return {"ok": False, "reason": "Reading files needs the view_files permission too."}
    refusal = account_refusal(gs, bool(req.get("write")))
    if refusal:
        return {"ok": False, "reason": refusal}
    return dict(ok=True, **describe(gs))


def account_refusal(gs, write):
    """The web file manager's refusal for this server's account (root-capable, restore running), or None."""
    from panel.routes._shared import game_account_write_refusal, grs_or_account_refusal
    if write:
        why = grs_or_account_refusal(gs, game_account_write_refusal)
    else:
        why = game_account_write_refusal(gs.remote, gs.short_name, reading=True)
    return str(why) if why else None


def describe(gs):
    """How the service reaches `gs`'s files: the account, its home and the host's transport."""
    from panel.ops.ssh_manager import _core
    remote = gs.remote
    if _core.is_local_server(remote):
        transport = "local"
    elif getattr(remote, "auth_method", "") == "tailscale":
        transport = "tailscale"
    else:
        transport = "paramiko"
    return {"sid": gs.id, "name": gs.name, "user": gs.short_name, "selfname": gs.lgsm_name,
            "home": home_of(gs), "transport": transport, "remote_id": gs.remote_id}


def _h_audit(_app, req, _spawn):
    from panel.db.models import GameServer, User, db
    from panel.routes.server_files import _audit_safe
    action = req.get("action")
    if action not in AUDIT_ACTIONS:
        return {"ok": False}
    user = db.session.get(User, int(req.get("uid") or 0))
    gs = db.session.get(GameServer, int(req.get("sid") or 0))
    if user is None or gs is None:
        return {"ok": False}
    _sftp_audit(_ip(req), user, action, target=gs.name, detail=_audit_safe(str(req.get("detail") or ""), 2000),
           success=bool(req.get("success")), server=gs)
    return {"ok": True}


_HANDLERS = {"hello": _h_hello, "ready": _h_ready, "conn": _h_conn, "auth_key": _h_auth_key,
             "auth_kbd": _h_auth_kbd, "auth_fail": _h_auth_fail, "auth_done": _h_auth_done,
             "servers": _h_servers, "authz": _h_authz, "audit": _h_audit, "session_end": _h_session_end}
