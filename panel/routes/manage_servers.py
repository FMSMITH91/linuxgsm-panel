"""Adding, installing, editing and uninstalling game servers.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core.panel_state import (_game_backup_status, _install_jobs, _install_lock)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import (backup as bk)
from panel.services import (lgsm_data)
from panel.ops.ssh_manager import (GMOD_CONTENT_GAMES, GMOD_CONTENT_SIZES,
    _remote_listening_ports, detect_game_ports, ensure_content_user, ensure_persistent_bans,
    game_engine as sm_game_engine, gmod_mount_setup, install_game_cron,
    INSTALL_FAILURE_FINAL, classify_install_failure, install_game_dependencies,
    install_gmod_content,
    lgsm_write_config, parse_missing_deps,
    remote_ufw_allow_game_ports, remote_ufw_close_by_name, remote_ufw_close_game_port,
    set_autostart)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security.auth import (INSTALL_SERVER, MANAGE_SERVERS, UNINSTALL_SERVER,
    accessible_remote_ids, get_game, get_remote, log_action, permission_required,
    server_access_required)
import shlex
import threading
import time
from panel.core.http import (_form_err, _form_ok, _log_and_generic, _wants_json)
from panel.core import terminal
from panel.core.validation import (GAME_TYPE_RE, INSTANCE_NAME_RE, MAX_PORT, MIN_PORT,
    SAFE_LABEL_RE, _port_or)
from app import (_extract_start_error, _log, _prune_jobs,
    _resolve_source_aux_ports, load_game_list, resolve_free_port)
from panel.routes._shared import (_looks_installed, _notify_servers_changed)

# Serializes the install "slot" allocation (pick a free port → reject a duplicate name → create the
# row). resolve_free_port yields on an SSH scan, so without this two concurrent installs on the same
# remote could both pick the same port or both pass the duplicate-name check before either commits.
#
# Defined here, not in app.py: this module is the only thing that takes it, and a module-private
# name with no use inside its OWN module reads as dead to CodeQL however many other modules import
# it (py/unused-global-variable). The lock is only correct as a single shared object, so there is
# exactly one definition and no one else may make another.
_install_alloc_lock = threading.Lock()


def record_install_failure(row, name, detail="", retryable=True, explained=False):
    """Write a failed install onto `row`: the reason, whether a retry can help, AND the status.

    All three together, because the UI reads them together. Only the step-4 path used to set the
    status, so an install that died earlier — a bad game type, an unreachable host during LinuxGSM
    setup, an unhandled exception — left the row at "installing" with a reason beside it that
    nothing would ever show. The banner, Retry, Remove, the console redirect and Files & Config
    are ALL keyed on status == "failed", and /delete refuses a row that says it is installing, so
    that row could not even be removed. A comment here used to claim the status poll would flip
    it; it does not — api.py skips "installing" and "configuring" rows precisely so that a poll
    cannot end a live install early.

    `explained` means `name` IS the whole explanation, so the raw tail is not appended: the tail is
    the tool's own last word and the tool is sometimes wrong (LinuxGSM ends an "Invalid platform"
    failure by pointing at the host, which is not the problem).

    Returns the reason written, so the caller can log it.
    """
    reason = (name if (explained or not detail) else "%s: %s" % (name, detail))[:1000]
    row.install_error = reason
    row.install_retryable = bool(retryable)
    row.installed = False
    row.status = "failed"
    return reason


def decide_port_adoption(real_port, cur_port, panel_ports, live_ports):
    """Should the install adopt the port LinuxGSM reports? -> (adopt, taken_by).

    `taken_by` is a phrase for the user when the answer is no and the reason is worth saying;
    (False, None) just means there is nothing to adopt.

    The panel's own table is only HALF of "is this port free". The other half is what is actually
    listening on the host — a hand-installed server, a container, anything never imported through
    /discover. Asking only the table turns a lookup MISS into the measured fact "nobody has it",
    and adopting a foreign process's port makes every status answer read ITS socket: a server that
    never bound anything is then reported online, permanently.

    Nothing of OURS can be listening when this runs — the first start comes later in the install —
    so anything holding real_port at that moment is someone else.

    Three answers, not two, because a scan that FAILED is not an empty one:

        live_ports() is None   could not look -> keep the port the panel allocated, the only one
                               it knows to be free
        real_port in it        taken by something that is not us
        otherwise              free, adopt it

    `live_ports` is a callable so the SSH round trip only happens when the table cannot answer.
    `panel_ports` maps port -> name for the OTHER servers on this host.
    """
    if not real_port or real_port == cur_port:
        return False, None
    other = panel_ports.get(real_port)
    if other:
        return False, "'%s' on this host" % other
    live = live_ports()
    if live is None:
        return False, "something the panel could not check for"
    if real_port in live:
        return False, "another process on this host"
    return True, None


def register(app):
    @app.route("/servers/manage")
    @login_required
    @permission_required(MANAGE_SERVERS, INSTALL_SERVER)
    def manage_servers():
        """Kept as a REDIRECT, not deleted.

        The server list folded into the dashboard: the two pages showed seven of the same eight
        columns and shared no code at all — doAction vs msrvAction, sortDashCol vs sortServers —
        so one of them was a second implementation of the other, drifting on its own.

        The route stays because the URL is in people's bookmarks, in the sidebar's muscle memory,
        and in any link anyone has shared. A 302 costs nothing; a 404 is a support question.
        """
        return redirect(url_for("index"))

    @app.route("/servers/install")
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def install_server_page():
        """The install form, on its own page.

        It used to sit on /servers/manage above the list of servers you already have — 631px of
        mostly-empty selects for a thing you do once, ahead of the thing you came for. Same
        permission pair as the POST it submits to, so reaching the form and using it are one
        decision rather than two that can drift.
        """
        _my = accessible_remote_ids(current_user)
        remotes = [r for r in RemoteServer.query.all() if r.id in _my]
        # Only downloadable games: the target host is not chosen yet, so mount-only content that
        # may already be present cannot be known here. Same reasoning as the old inline form.
        gmod_games = [{"key": k, "label": v[0], "size": GMOD_CONTENT_SIZES.get(k, "")}
                      for k, v in GMOD_CONTENT_GAMES.items() if v[1] is not None]
        # lgsm_status so the "no games" warning can say WHY rather than guessing at GitHub —
        # a DNS failure, an HTTP 403, a response that was not a CSV and a read-only data/ all
        # look identical from the template otherwise.
        return render_template("install_server.html", remotes=remotes,
                               games=load_game_list(), gmod_games=gmod_games,
                               lgsm_status=lgsm_data.status())

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
        # _port_or, not int(): a port has a RANGE, and `int(port)` carried none — so 0, -5 and
        # 99999 all reached the row below, the firewall verbs that take it, and the LinuxGSM
        # config written from it. A typo is corrected to the game's default; nothing out of range
        # is stored. (/api/free-port next door has always range-checked its input; this is the
        # endpoint that actually writes a server.)
        desired_port = _port_or(port, None)
        if desired_port is None:
            return _form_err("Port must be a number between %d and %d." % (MIN_PORT, MAX_PORT),
                             "manage_servers")

        # Allocate the install "slot" atomically: pick a free port, reject a duplicate name and
        # create the row under one lock. resolve_free_port yields on an SSH scan, so without the
        # lock two concurrent installs on the same remote could pick the same port or both clear the
        # duplicate-name check before either committed.
        with _install_alloc_lock:
            # Port-conflict handling: auto-pick the next free port if taken.
            # resolve_free_port SCANS the host's listening ports over SSH, so it raises when the
            # host is simply switched off — and that propagated as a 500. A host being unreachable
            # is a normal condition for this panel, not a fault in it (see _unreachable's docstring,
            # which lists the sibling endpoints this was already true of); it just needs the form
            # shape rather than the JSON one. Caught here, before any row exists.
            try:
                final_port, port_changed = resolve_free_port(remote, remote_id, desired_port,
                                                             game_type)
            except (ConnectionError, OSError):
                _log.warning("install: host %s unreachable while picking a port", remote.name)
                return _form_err("Can't reach %s right now, so the panel can't check which ports "
                                 "are free. Check the host is up and try again." % remote.name,
                                 "manage_servers")
            # None = the allocator found nothing free near the requested port. Refusing names the
            # real problem; storing its old best-guess handed the install a port already in use and
            # let it fail later as the GAME's error.
            if final_port is None:
                return _form_err("No free port near %d on this host — every port in the search "
                                 "range is taken. Pick a different port." % desired_port,
                                 "manage_servers")

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
        _notify_servers_changed(app)   # new "installing" row → appears live on other sessions

        log_action(current_user, "install_server", target=gs.name,
                   detail=f"Type: {game_type}, port: {final_port}")
        port_note = (f" (port {desired_port} was busy — using {final_port})" if port_changed else "")
        name_note = (f" (the default name was taken — using '{short_name}')" if name_changed else "")
        # "Progress is shown live below" was not true here. This route is submitted from the
        # Install a Server page, whose only progress row is on a DIFFERENT page — so the install
        # produced a toast pointing at nothing, and the dashboard then showed the server as
        # "installing" with no progress of any kind. The corner widget (install_progress.js) is
        # what makes the sentence true now, on whatever page you happen to be on.
        return _form_ok(f"Installing {short_name} on port {final_port}{port_note}{name_note}. "
                        f"Progress is shown in the corner while it runs.", "manage_servers")

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

        def _fail(name, detail="", retryable=True, explained=False):
            """Record a failed install — in the live job AND on the row.

            The job dict is in memory, so until now the reason existed only until the panel
            restarted or the operator navigated away, and the Game Servers row said "Failed" and
            nothing else. That is the state the user is left in: no reason, no retry, nothing to
            act on. Persisting it is what lets the row say why and offer the right next step.

            `retryable` is False only for a cause nothing about trying again changes — today
            that is a game LinuxGSM caps at an older Ubuntu than the host runs. The row then
            offers Remove instead of Retry. A cause the operator can act on (free a dump slot,
            add a Steam account, let the Windows-prime workaround run) stays retryable: its
            message tells them what to do, and Retry is how they do it. See
            INSTALL_FAILURE_FINAL.

            `explained` means `name` IS the whole explanation, so the raw tail is not appended to
            it on the row. It matters because the tail is the tool's own last word, and the tool
            is sometimes wrong: LinuxGSM ends an "Invalid platform" failure with "Check
            steamcmdforcewindows setting and system architecture", which points at the host, and
            the host is not the problem (the app publishes no Linux launch configuration — proven
            on the test box). Appending that after the correct sentence undoes it. The tail still
            goes to the live job, which is where the unabridged output belongs.
            """
            # Strip the ANSI before it goes anywhere. LinuxGSM and SteamCMD colour their output,
            # and the last 300 bytes of a failed install is nearly all escape sequences — which is
            # what the operator was shown, verbatim:
            #
            #   info...\x1b[0mOK \x1b[0mERROR! Failed to install app '222860' (Invalid platform)
            #   \x1b[0mUnloading Steam API...\x1b[0mOK \x1b[0m\x1b[31mFailure!\x1b[0m Installing…
            #
            # The panel has had strip_escapes since the console was written; this path just never
            # called it. Collapse the whitespace too: the raw tail arrives full of \r and column
            # padding that turns one sentence into five ragged lines in a corner card.
            detail = " ".join(terminal.strip_escapes(detail or "").split())
            with _install_lock:
                j = _install_jobs.get(gs_id)
                cur = j["step"] if j else 0
            _p(cur, name, status="failed", message=detail)
            try:
                from panel.db.models import db as _db, GameServer as _GS
                _row = _db.session.get(_GS, gs_id)
                if _row is not None:
                    record_install_failure(_row, name, detail, retryable, explained)
                    _db.session.commit()
            except Exception:
                _log.debug("could not record the install failure on the row", exc_info=True)
            # Tell every open dashboard immediately, rather than leaving the explanation to appear
            # whenever someone happens to reload.
            _notify_servers_changed(app)

        def _finish(msg, warn=False):
            # A install that got here worked, whatever happened on an earlier attempt — clear the
            # recorded reason, or a retried server keeps showing the failure it recovered from.
            try:
                from panel.db.models import db as _db, GameServer as _GS
                _row = _db.session.get(_GS, gs_id)
                if _row is not None and (_row.install_error or not _row.install_retryable):
                    _row.install_error, _row.install_retryable = "", True
                    _db.session.commit()
            except Exception:
                _log.debug("could not clear the install failure on the row", exc_info=True)
            _notify_servers_changed(app)   # a finished install clears a banner as surely as one appears
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
                    # ORDER MATTERS, and the old order was a loaded gun. This asked whether
                    # /home/<n>/linuxgsm.sh was executable and, on "no", ran user-delete +
                    # user-remove-home — `userdel -r` and an rm of that home. The probe went out
                    # with no `sudo=`, so it inherited the host row's sudo_enabled and ran as
                    # ROOT, which is the only reason it could read a 0750 home at all. Unprivileged
                    # it answers EACCES, `test -x` fails, and the shell prints the literal
                    # NOTEXISTS — "cannot look" rendered as "nothing there", immediately before
                    # the destructive branch.
                    #
                    # So ask about the ACCOUNT first: `id` needs no privilege and answers
                    # definitively. Only if it exists is there anything to clean up, and only then
                    # is the script probed — AS THAT USER, which is both what can read the home and
                    # what the narrow grant permits. A probe that FAILS (rc != 0) is not evidence
                    # of a half-finished install, so it cleans up nothing.
                    idout, _, _ = _sm.run_command(
                        remote, f"id {short_name} >/dev/null 2>&1 && echo EXISTS || echo NOTEXISTS",
                        timeout=10)
                    user_exists = "NOTEXISTS" not in idout and "EXISTS" in idout
                    if user_exists:
                        chk, _, chk_rc = _sm.read_as_game_user(
                            remote, short_name,
                            f"test -x /home/{short_name}/linuxgsm.sh && echo EXISTS "
                            f"|| echo NOTEXISTS", timeout=10)
                        if chk_rc == 0 and "NOTEXISTS" in chk:
                            # A genuine half-finished leftover: the account is there, the script
                            # is not. Was one root shell running `userdel -r X; rm -rf /home/X`.
                            # Two verbs now, and the home path is built by the helper from the
                            # validated name rather than interpolated into an `rm -rf`.
                            _sm.run_privileged(remote, "user-delete", [short_name], timeout=15,
                                               merge_stderr=False)
                            _sm.run_privileged(remote, "user-remove-home", [short_name], timeout=15,
                                               merge_stderr=False)
                            user_exists = False
                    if not user_exists:
                        _sm.create_game_user(remote, short_name, timeout=15)
                        time.sleep(0.3)

                    # 2. Download & set up LinuxGSM (canonical script name).
                    _p(2, "Downloading LinuxGSM")
                    install_cmd = (f"sudo -u {short_name} bash -c 'cd /home/{short_name} && "
                                   f"wget -q -O linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh && "
                                   f"bash linuxgsm.sh {lgsm_name}' 2>&1")
                    out = err = ""; rc = -1
                    for attempt in range(10):
                        out, err, rc = _sm.run_command(remote, install_cmd, timeout=300, sudo=False)
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
                        deps_ok, deps_msg = install_game_dependencies(remote, game_type)
                    except Exception:
                        deps_ok, deps_msg = False, "the dependency step raised"
                        _log.debug("_run: install_game_dependencies raised", exc_info=True)
                    if not deps_ok:
                        # Deliberately NOT fatal: LinuxGSM re-reports what is missing at step 4 and
                        # this runs again with those exact names, and plenty of games install fine
                        # without the optional ones. But it has to be VISIBLE. This was a bare
                        # `except` logging at debug level, and the function returned success
                        # regardless (its pipeline ended in `echo deps-done`) — so on a host where
                        # the whole step was REFUSED by sudo, nothing was written anywhere and the
                        # install carried on to fail later looking like a bad download.
                        _p(3, "Installing dependencies", message=(
                            "Some dependencies did not install — continuing; step 4 reports "
                            "anything still missing. %s" % (deps_msg or "")[-200:]))
                        _log.warning("install %s: dependency step failed: %s",
                                     short_name, (deps_msg or "")[:300])

                    # 4. Download the game server files (the long step). A truncated / corrupt archive
                    #    can leave LinuxGSM "done" — even with exit code 0 — but with NO game files
                    #    (exactly how a bad cod2 download failed silently). So DON'T trust the exit
                    #    code: after each attempt verify the files actually landed (_looks_installed),
                    #    and on failure wipe LinuxGSM's cached download and retry from scratch.
                    auto = f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} auto-install' 2>&1"
                    # Free any Steam crash-dump slot left behind by a deleted game account. Steam
                    # has ten, one per account, and a full table stops SteamCMD dead on a host
                    # whose servers were all working — see do_steam_dumps_sweep. Best-effort: a
                    # host that has never run out has nothing to free.
                    try:
                        _sm.run_privileged(remote, "steam-dumps-sweep", [short_name], timeout=20)
                    except Exception:
                        _log.debug("_run: steam dumps sweep failed", exc_info=True)
                    installed_ok = False
                    last_out = ""
                    why = None
                    primed_windows = False
                    for attempt in range(3):
                        _p(4, "Downloading game server files (this can take a while)"
                              + ("" if attempt == 0 else " — retry %d" % attempt))
                        out, err, rc = _sm.run_command(remote, auto, timeout=1800, sudo=False)
                        last_out = out or err or last_out
                        missing = parse_missing_deps((out or "") + "\n" + (err or ""))
                        if missing:
                            try:
                                _r_ok, _r_msg = install_game_dependencies(
                                    remote, game_type, extra=" ".join(missing))
                                if not _r_ok:
                                    _log.warning("install %s: retry of the dependency step failed: "
                                                 "%s", short_name, (_r_msg or "")[:300])
                                out, err, rc = _sm.run_command(remote, auto, timeout=1800, sudo=False)
                                last_out = out or err or last_out
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                        # The real test — did the game files actually install? rc alone lies on a
                        # corrupt/truncated download.
                        if _looks_installed(app, remote, short_name, lgsm_name) is True:
                            installed_ok = True
                            break
                        # Some failures a second download cannot fix: no Steam licence, no crash-dump
                        # slot, a game LinuxGSM does not support on this release. Retrying those
                        # costs up to an hour and ends with the same wrong "may be corrupt" advice.
                        why = classify_install_failure(last_out)
                        # ...except "Invalid platform", which CAN be fixed — it is a SteamCMD bug,
                        # and LinuxGSM's maintainer found the way through it in
                        # GameServerManagers/LinuxGSM#4754 (still open): set steamcmdforcewindows,
                        # install (which pulls the Windows depot and gets SteamCMD past its own
                        # refusal), unset it, then validate, which pulls the Linux binaries.
                        #
                        # The panel does that ITSELF. The alternative is telling an operator to go
                        # and read a GitHub thread, which is the opposite of what this is for.
                        # Once per install: if priming does not take, the next pass reports it
                        # rather than looping.
                        if why and why[0] == "steam_platform" and not primed_windows:
                            primed_windows = True
                            try:
                                _p(4, "Working around a SteamCMD bug (priming with the Windows "
                                      "depot — this downloads twice, so it takes a while)")
                                lgsm_write_config(remote, short_name, lgsm_name,
                                                  {"steamcmdforcewindows": "yes"})
                                # try/finally, because leaving this key set is WORSE than the
                                # failure that would leave it. It is written to the instance
                                # config, which outlives the install: with it still "yes" every
                                # later update and validate for this server fetches the WINDOWS
                                # depot, so a server that installed fine breaks the first time it
                                # is updated, months later, for a reason nothing on screen
                                # connects to this install. The download raising — an SSH drop, a
                                # timeout — used to skip the reset entirely.
                                try:
                                    out, err, rc = _sm.run_command(remote, auto, timeout=2700,
                                                                   sudo=False)
                                    last_out = out or err or last_out
                                finally:
                                    # "no", not a delete: LinuxGSM tests `== "yes"`, and
                                    # lgsm_write_config replaces a key in place rather than
                                    # removing one, so this is the same thing through the safe
                                    # writer. It RETURNS (ok, message) and does not raise, so a
                                    # failed reset is only visible if the result is read — try
                                    # once more, then say plainly what is left behind.
                                    _unset_ok = False
                                    for _try in range(2):
                                        _unset_ok = bool(lgsm_write_config(
                                            remote, short_name, lgsm_name,
                                            {"steamcmdforcewindows": "no"})[0])
                                        if _unset_ok:
                                            break
                                    if not _unset_ok:
                                        _log.warning(
                                            "install %s: could not clear steamcmdforcewindows on "
                                            "%s — it is still 'yes', so this server's future "
                                            "updates will fetch the Windows depot until it is "
                                            "changed in Files & Config",
                                            short_name, lgsm_name)
                                _p(4, "Fetching the Linux server binaries")
                                _sm.run_as_game_user(remote, short_name, "validate",
                                                     timeout=2700, selfname=gs.lgsm_name)
                            except Exception:
                                _log.warning("install %s: the Invalid-platform workaround failed",
                                             short_name, exc_info=True)
                            why = None          # judge it on what the next pass finds
                            continue
                        if why:
                            break
                        # Not really installed: wipe LinuxGSM's cached (likely corrupt) archive so the
                        # next attempt re-downloads fresh instead of reusing the bad file.
                        try:
                            _sm.run_command(remote, f"sudo -u {short_name} bash -c "
                                        f"'rm -rf /home/{short_name}/lgsm/tmp/* 2>/dev/null; echo cleared'",
                                        timeout=30, sudo=False)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)
                    if not installed_ok:
                        # (_fail writes installed/status/reason together — see above.)
                        # Being classified is not the same as being hopeless. Three of the four
                        # causes are "do this, then try again" and their messages say exactly
                        # that, so taking Retry away contradicts the sentence above the button.
                        # Only INSTALL_FAILURE_FINAL is beyond a retry.
                        _fail(why[1] if why else
                              ("Game files didn't install after 3 tries — the download may be corrupt "
                               "or the mirror unreachable. Try again shortly."),
                              last_out[-300:],
                              retryable=not (why and why[0] in INSTALL_FAILURE_FINAL),
                              explained=bool(why)); return
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
                        cmds = _sm.list_server_commands(remote, short_name, gs.lgsm_name)
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
                            _sm.run_command(remote, f"sudo -u {short_name} bash -c \"echo 'eula=true' > /home/{short_name}/serverfiles/eula.txt 2>/dev/null; true\"", timeout=15, sudo=False)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)
                    # SCP: Secret Laboratory has the same problem Minecraft has, in a form that is
                    # harder to see. Its launcher stops and ASKS:
                    #
                    #   Before starting please read and accept the SCP:SL EULA.
                    #   Do you accept the EULA? [yes/no]
                    #
                    # Nothing is there to answer it, so LocalAdmin sits at the prompt for ever.
                    # LinuxGSM reports STARTED (a tmux session exists), the game itself never
                    # launches, and no port is ever opened — found while installing the LinuxGSM
                    # catalogue, where it looked like a server that ran and served nobody.
                    #
                    # LocalAdmin records the answer in its own config, so write it there, exactly
                    # as the line above writes Minecraft's eula.txt. Proven on the test host: with
                    # EulaAccepted set, SCPSL.x86_64 launches and the console reaches "Waiting for
                    # players...". Best-effort and idempotent — an existing file is edited, not
                    # replaced, so nothing else in it is lost.
                    if gs.game_type in ("scpsl", "scpslsm"):
                        _eula_py = (
                            "import json,io,os,datetime;"
                            "p=os.path.expanduser('~/.config/SCP Secret Laboratory/config/"
                            "localadmin_internal_data.json');"
                            "os.makedirs(os.path.dirname(p),exist_ok=True);"
                            "d=json.load(io.open(p,encoding='utf-8-sig')) if os.path.exists(p) else {};"
                            "d['EulaAccepted']=datetime.datetime.now(datetime.timezone.utc)"
                            ".strftime('%Y-%m-%dT%H:%M:%S.%f0Z');"
                            "io.open(p,'w',encoding='utf-8').write(json.dumps(d))"
                        )
                        try:
                            _sm.run_command(remote,
                                            "sudo -u %s python3 -c %s"
                                            % (shlex.quote(short_name), shlex.quote(_eula_py)),
                                            timeout=20, sudo=False)
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
                    port_conflict = None
                    try:
                        info = detect_game_ports(remote, short_name, gs.lgsm_name)
                        real_port = info.get("game_port")
                        # Adopt the port LinuxGSM reports — but NOT one another server on this host
                        # already reserves. resolve_free_port picked a genuinely free port at
                        # request time; this step exists because auto-install uses the game's
                        # default instead, so the panel has to follow reality. A game that ignores
                        # the port the panel wrote into its LinuxGSM config reports its own default
                        # here, and adopting that blindly points TWO panel servers at one port.
                        #
                        # Reproduced on the test box with a Velocity proxy, which reads
                        # velocity.toml and not the LinuxGSM key: it reported 25565, the host's
                        # Minecraft server already had it, and the proxy logged
                        #
                        #     [ERROR]: Can't bind to /0.0.0.0:25565
                        #     bind(..) failed with error(-98): Address already in use
                        #
                        # while LinuxGSM still said STARTED. Worse, the panel would then call that
                        # proxy ONLINE, because something IS listening on 25565 — a port check
                        # cannot tell whose socket it is. Not adopting the port is what stops the
                        # panel manufacturing that state.
                        # See decide_port_adoption for why this is three answers and not two.
                        _panel_ports = {e.port: e.name
                                        for e in GameServer.query.filter_by(
                                            remote_id=remote.id).all()
                                        if e.id != gs.id and e.port}
                        _adopt, _taken_by = decide_port_adoption(
                            real_port, gs.port, _panel_ports,
                            lambda: _remote_listening_ports(remote))
                        if _adopt:
                            old_port = gs.port; gs.port = real_port; db.session.commit()
                            try:
                                remote_ufw_close_game_port(remote, old_port)
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                        elif _taken_by is not None:
                            port_conflict = (real_port, _taken_by)
                            _log.warning("install %s: %s reports port %s, which %s already has "
                                         "— keeping %s and not adopting it",
                                         short_name, lgsm_name, real_port, _taken_by, gs.port)
                        # Only open what this server is actually entitled to. On the conflict
                        # branch the panel has just REFUSED the reported port, so opening
                        # info["open_ports"] — which contains it — would hand a hole in the
                        # firewall to the other process, attributed to this server.
                        if port_conflict:
                            to_open = [gs.port] if gs.port else []
                        else:
                            to_open = info.get("open_ports") or ([gs.port] if gs.port else [])
                        remote_ufw_allow_game_ports(remote, to_open, short_name)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # SCP:SL keeps its config PER PORT — ~/.config/SCP Secret Laboratory/config/<port>/
                    # — and when a port has no config yet, LocalAdmin prints its settings and asks
                    #
                    #     Do you want to edit that configuration? [edit/keep]:
                    #
                    # which nothing answers inside a tmux session, so the start hangs there for
                    # ever. The panel assigns a free port rather than the game's default, so it
                    # walks into this on EVERY install. Seeding the directory from the config
                    # LinuxGSM already ships is what stops it being asked. Proven on the test host:
                    # with config/<port>/config_localadmin.txt in place the same start reaches
                    # "Waiting for players..." instead of the prompt.
                    #
                    # HERE, not at step 5: the port is only final once step 6 has decided whether
                    # to adopt the one LinuxGSM reports.
                    if gs.game_type in ("scpsl", "scpslsm") and gs.port:
                        _sl_sh = (
                            'd="$HOME/.config/SCP Secret Laboratory/config/%d"; mkdir -p "$d"; '
                            '[ -f "$d/config_localadmin.txt" ] || '
                            'cp "$HOME/lgsm/config-default/config-game/config_localadmin.txt" '
                            '"$d/config_localadmin.txt" 2>/dev/null; true' % int(gs.port)
                        )
                        try:
                            _sm.run_command(remote,
                                            "sudo -u %s bash -c %s"
                                            % (shlex.quote(short_name), shlex.quote(_sl_sh)),
                                            timeout=20, sudo=False)
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
                        start_out, _, s_rc = _sm.run_as_game_user(remote, short_name, "start", timeout=120, selfname=gs.lgsm_name)
                    except Exception:
                        s_rc = 1
                        _log.debug("_run: start command failed", exc_info=True)
                    # Poll up to 90s, not 15. Measured on the test host while installing the
                    # LinuxGSM catalogue: most games bind immediately, but Nuclear Dawn took 20s
                    # and Insurgency 40s, and the heavier Unreal/Unity titles are slower again.
                    # At 15s those all finished the install with "installed, but it didn't start"
                    # on a server that was simply still booting — the one sentence that makes an
                    # operator go looking for a fault that isn't there.
                    #
                    # This is a background job, so the wait costs the browser nothing; the progress
                    # row already says "Starting server" while it runs.
                    really_up = False
                    try:
                        for _ in range(30):                   # ~90s
                            time.sleep(3)
                            _sm._invalidate_port_scan(remote.id)  # force a fresh scan each try
                            if gs.port and gs.port in (_remote_listening_ports(remote)
                                                       or set()):
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
                        if port_conflict:
                            # Step 6 refused this port precisely so the panel would not open it in
                            # front of someone else's process. detect_game_ports re-reads the same
                            # unchanged config and always folds game_port back into open_ports, so
                            # without this filter the next statement undid that decision — and
                            # worse than "opened it again": `ufw allow <port> comment <name>`
                            # REPLACES an existing rule that differs only by comment (verified on
                            # the test host — two allows for one port leave one rule carrying the
                            # second name). So this re-opened the other server's port under THIS
                            # server's name, and uninstalling this one would then delete the rule
                            # protecting the other, still-running server.
                            extra = [p for p in extra if p != port_conflict[0]]
                        if extra:
                            remote_ufw_allow_game_ports(remote, extra, short_name)
                    except Exception:
                        _log.debug("_run: post-start port re-detect failed", exc_info=True)

                    if port_conflict:
                        # The files are there and LinuxGSM will keep reporting STARTED, so this is
                        # not a failed install — but the server cannot serve anyone until the
                        # clash is resolved, and saying nothing would leave someone staring at a
                        # server that looks fine and answers nobody.
                        _finish(f"{short_name} installed, but it wants port {port_conflict[0]}, "
                                f"which {port_conflict[1]} already uses. This game ignores the "
                                f"port the panel sets, so change it in the game's own config "
                                f"(Files & Config), or free that port on the host.", warn=True)
                        log_action(None, "install_complete", target=gs.name, success=False,
                                   detail=("port %s clashes with %s"
                                           % (port_conflict[0], port_conflict[1]))[:300])
                    elif really_up:
                        _finish(f"{short_name} installed and started")
                        log_action(None, "install_complete", target=gs.name, success=True)
                    else:
                        # Two different outcomes shared one sentence. If LinuxGSM's own `start`
                        # REPORTED a problem, say it didn't start — that is a fault, and the reason
                        # is in the log. If start succeeded and only the port hasn't appeared yet,
                        # the install worked and the server is still coming up: say THAT, and don't
                        # dress it as a failure. Slow-booting games (ARK, Rust, the Unreal titles)
                        # are the normal case for this, and the monitor flips the status to online
                        # by itself the moment the port opens.
                        reason = _extract_start_error(start_out)
                        if reason or s_rc != 0:
                            note = f"{short_name} installed, but it didn't start"
                            note += (" — " + reason) if reason else " — check the console for the reason."
                            _detail = ("start failed: " + reason) if reason else "start failed"
                        else:
                            note = (f"{short_name} installed and starting — it hasn't opened port "
                                    f"{gs.port} yet, which some games take a few minutes to do. "
                                    f"It will show as online on its own once it does.")
                            _detail = "started; port %s not open after 90s" % gs.port
                        _finish(note, warn=True)
                        log_action(None, "install_complete", target=gs.name, success=False,
                                   detail=_detail[:300])
            except Exception as e:
                # Go through _fail so an unexpected crash leaves the same recoverable state as
                # every other failure: a reason on the row, status "failed", and the dashboard
                # told. Setting only the in-memory job left the row saying "installing" for ever
                # — no reason, no Retry, and /delete refusing to remove it.
                app.logger.exception("install job failed")
                try:
                    _fail("Install failed unexpectedly", str(e))
                except Exception:
                    _log.debug("could not record the unexpected install failure", exc_info=True)
                    with _install_lock:
                        j = _install_jobs.get(gs_id)
                        if j is not None:
                            j["status"], j["message"], j["updated"] = "failed", str(e), time.time()

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/servers/<int:server_id>/retry-install", methods=["POST"])
    @login_required
    # The SAME pair /servers/install and /servers/add accept. This ran the same install job behind
    # a narrower permission, so someone with MANAGE_SERVERS could install a server but not retry
    # the one that failed — and the dashboard's can_install flag (that pair) rendered the Retry
    # button for them anyway, so the button was there and answered "You do not have permission".
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    @server_access_required
    def retry_install(server_id):
        """Run the install again for a row whose install failed.

        A failed install was a dead end: the row said "Failed", the reason lived in memory until
        the panel restarted, and the only way forward was to delete the server and start over —
        which also throws away the LinuxGSM config the failure usually asks you to change. The
        install job is re-entrant by construction (step 1 keeps an account whose linuxgsm.sh is
        there and rebuilds one whose isn't), so this simply runs it again on the same row.

        Refused for a cause a retry cannot fix. install_retryable is False when the failure was
        classified — a game needing a Steam account that owns it, one LinuxGSM caps at an older
        Ubuntu, one SteamCMD has no build of for this platform — and spending another half hour
        arriving at the same line is not a service to anyone. Changing the config that caused it
        (a steamuser, say) clears the flag, because that IS a change worth retrying on.
        """
        gs = get_game(server_id)
        if gs.status not in ("failed",) or gs.installed:
            return _form_err("That server's install didn't fail, so there's nothing to retry.",
                             "manage_servers")
        with _install_lock:
            live = (gs.id in _install_jobs
                    and _install_jobs[gs.id].get("status") == "running")
        if live:
            return _form_err("That install is already running.", "manage_servers")
        if not gs.install_retryable:
            return _form_err(
                "Trying again won't change this one — " + (gs.install_error or "see the reason on "
                "the row") + " Fix the cause first, or remove the server.", "manage_servers")
        remote = gs.remote
        if remote is None:
            return _form_err("That server's host is gone.", "manage_servers")
        gs.status = "installing"
        gs.install_error, gs.install_retryable = "", True
        db.session.commit()
        with _install_lock:
            _install_jobs[gs.id] = {
                "status": "running", "step": 0, "total": 8, "step_name": "Queued",
                "message": "", "log": [], "started": time.time(), "updated": time.time(),
                "name": gs.name,
            }
        _run_install_job(gs.id, remote.id, gs.short_name, gs.game_type, gs.lgsm_name, gs.port)
        _notify_servers_changed(app)   # the corner progress widget picks it up from here
        log_action(current_user, "retry_install", target=gs.name)
        return _form_ok(f"Installing {gs.short_name} again. "
                        f"Progress is shown in the corner while it runs.", "manage_servers")

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
        # A LIVE job is the only safe "still installing" signal. The status column was part of
        # this test, which made any row stranded at "installing" permanently undeletable — and the
        # panel restarting mid-install strands one every time, because the worker thread dies with
        # the process while the row keeps saying installing. There is no cancel route, so that row
        # could only be removed by editing the database. _install_jobs is the authority on whether
        # a thread is running: _prune_jobs only drops an entry after two hours with no progress
        # update, and every download attempt reports progress, so an absent entry means a dead job.
        if _installing:
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
                _sm.run_as_game_user(remote, short_name, "stop", timeout=60, selfname=selfname)
            except Exception:
                _log.debug("uninstall: graceful stop failed; force-killing next", exc_info=True)
            try:
                _sm.run_privileged(remote, "user-kill-processes", [short_name], timeout=20,
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
            # Free this account's Steam crash-dump slot while its name still resolves. Steam has
            # ten of them per host and `userdel` leaves the directory behind, so without this each
            # uninstall permanently costs the host one slot — and at ten, SteamCMD stops working
            # for every server on it, installed or not.
            try:
                _sm.run_privileged(remote, "steam-dumps-sweep", [short_name], timeout=20)
            except Exception:
                _log.debug("uninstall: steam dumps sweep failed", exc_info=True)
            out, err, rc = _sm.run_privileged(remote, "user-delete-force", [short_name], timeout=30)
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
                # ...and this server's install job. Same reason as the schedule beside it: the row
                # id is handed to the next server created, and /install-status would answer for it
                # with THIS one's outcome. The monitor sweep also prunes it, one pass later.
                with _install_lock:
                    _install_jobs.pop(server_id, None)
            except Exception:
                _log.debug("uninstall: schedule cleanup failed", exc_info=True)
            _notify_servers_changed(app)   # row disappears live on other sessions
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
        # Compared as TEXT. Parsing it first meant an unparseable value read as "unchanged" and
        # was silently ignored rather than refused — and it put a port through _int_or, the parser
        # that carries no range. Any submitted port that is not exactly the stored one is refused.
        if new_port and new_port != str(gs.port):
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
