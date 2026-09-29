"""The panel tools/js_coverage/run.py drives: seeded, with every way out of the process stubbed.

Run ONLY by run.py, inside the throwaway copy of the tree it makes, through tools/nosudo_runner.py:

    python tools/nosudo_runner.py tools/js_coverage/serve.py <port>

It refuses to start anywhere else. DATA_DIR is a fixed path inside the checkout with no override,
so the only data directory this can write is the copy's own; the marker file run.py leaves at the
copy's root is what says the tree is disposable, and a real checkout never has one.

WHAT IS STUBBED, AND WHY AT THESE POINTS. run.py clicks through every page the way a person would,
Stop and Delete included, so nothing the panel does may leave this process:
  * every command the panel runs on a host — ssh_manager._core's exec primitives, for local and
    remote hosts alike — is answered by fake_host.answer(), never by a shell or a socket;
  * the panel host's own commands (system_ops._run) and the tailscale CLI (tailscale_integration.
    _run_ts) are answered the same way;
  * any subprocess a panel module still starts itself is refused (a deny-all shim, over
    nosudo_runner's refusal of sudo), and so is any URL that is not this panel's own (on top of
    nosudo_runner's refusal of every non-loopback connection);
  * the host terminal's local shell is a two-line echo loop, not the account's login shell.
The answers are realistic enough that pages render their full content — a console with lines, a
file browser with files, a firewall with rules — because the code that renders content is most of
the JavaScript being measured. They are not a test of that code: nothing here asserts anything.
"""
import os
import secrets
import sys
import threading
import time
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MARKER = ".js-coverage-throwaway"
if not os.path.isfile(os.path.join(ROOT, MARKER)):
    print("refusing: %s is not a throwaway copy made by tools/js_coverage/run.py (no %s)"
          % (ROOT, MARKER))
    sys.exit(2)

from panel.core.config import DB_PATH  # noqa: E402

if not str(DB_PATH).startswith(ROOT + os.sep) or DB_PATH.exists():
    print("refusing: the database %s is not a fresh one inside %s" % (DB_PATH, ROOT))
    sys.exit(2)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5099
USER = os.environ.get("JS_COVERAGE_USER", "")
PASSWORD = os.environ.get("JS_COVERAGE_PASSWORD", "")
if not USER or len(PASSWORD) < 16:
    print("refusing: JS_COVERAGE_USER / JS_COVERAGE_PASSWORD are run.py's to set")
    sys.exit(2)

import fake_host  # noqa: E402

fake_host.WORLD_FILE = os.path.join(ROOT, "jscov-world.json")

_LOG = os.path.join(ROOT, "jscov-commands.log")
_log_lock = threading.Lock()


def _answer(command):
    """Answer one command the panel runs, and log it.

    Every command the panel asked for goes in the log, one line each, so a run can be read back to
    see what a page needed and got no answer to (run.py --keep leaves the tree in place).
    """
    text = command if isinstance(command, str) else " ".join(str(c) for c in command)
    with _log_lock, open(_LOG, "a", encoding="utf-8") as fh:
        fh.write(" ".join(text.split())[:400] + "\n")
    return fake_host.answer(text)


def _stub_commands():
    """Route every command the panel runs on a host — local or remote — to the fake host."""
    from panel.ops import system_ops as so
    from panel.ops import tailscale_integration as ts
    from panel.ops.ssh_manager import _core

    def no_connection(*_a, **_k):
        raise ConnectionError("js_coverage: no SSH from this harness")

    _core.run_command = lambda server, command, timeout=30, sudo=None, stdin_text=None: \
        _answer(command)
    _core._exec_local_argv = lambda cmd, timeout=30, stdin_text=None, **_kw: _answer(cmd)
    _core._exec_local_shell = lambda cmd, timeout=30, stdin_text=None, **_kw: _answer(cmd)
    _core._run_local = lambda cmd, timeout=30, sudo=False, stdin_text=None, **_kw: _answer(cmd)
    _core.get_connection = no_connection
    so._run = lambda cmd, timeout=30, sudo=False, text=True: _answer(cmd)
    so._check_sudo = lambda force=False: True
    ts._run_ts = lambda args, timeout=5: _answer(["tailscale"] + list(args))


def _stub_urlopen():
    """Refuse any URL that is not this panel's own."""
    import urllib.request
    real = urllib.request.urlopen

    def urlopen(url, *a, **k):
        target = url if isinstance(url, str) else getattr(url, "full_url", "")
        if not target.startswith("http://127.0.0.1:%d/" % PORT):
            raise OSError("js_coverage: no outbound request to %s" % target[:80])
        return real(url, *a, **k)
    urllib.request.urlopen = urlopen


def _stub_terminal():
    """Give the host terminal a two-line echo loop for a shell, not an account's login shell.

    The page still gets real output over a real pty. Returns the script's path.
    """
    from panel.ops import terminal_session as term
    fake_shell = os.path.join(ROOT, "jscov-shell")
    # Created owner-only and executable in one step: no window in which it is anyone else's.
    fd = os.open(fake_shell, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho 'js-coverage terminal'\n"
                 "while IFS= read -r l; do printf '%s\\n' \"$l\"; done\n")
    term._login_shell = lambda: fake_shell
    return fake_shell


class _Deny:
    """What a panel module that still reaches for subprocess itself gets: a refusal."""

    def __init__(self, allowed):
        """Refuse everything except starting `allowed` (the terminal's echo loop)."""
        import subprocess  # nosec B404 - held only to refuse it (and start the echo loop)
        self._sp, self._allowed = subprocess, allowed

    def __getattr__(self, name):
        """Constants and exception types pass through."""
        return getattr(self._sp, name)

    def run(self, cmd, *_a, **_k):
        """Refuse: a failed run."""
        return self._sp.CompletedProcess(cmd, 1, "", "refused by js_coverage")

    def Popen(self, cmd, *a, **k):  # noqa: N802 - the name subprocess gives it
        """Start the echo loop; anything else starts /bin/false."""
        if isinstance(cmd, list) and cmd[:1] == [self._allowed]:
            return self._sp.Popen(cmd, *a, **k)  # nosec B603 - the echo loop _stub_terminal wrote
        return self._sp.Popen(["/bin/false"], *a, **k)  # nosec B603 - fixed literal

    def check_output(self, cmd, *_a, **_k):
        """Refuse: a failed command."""
        raise self._sp.CalledProcessError(1, cmd)


def _stub_subprocess(fake_shell):
    """Replace subprocess, in every panel module that imports it, with a refusal."""
    import db_maintenance
    from panel.ops import backup
    from panel.ops import system_ops as so
    from panel.ops import tailscale_integration as ts
    from panel.ops import terminal_session as term
    from panel.ops.ssh_manager import _core, cron, files
    deny = _Deny(fake_shell)
    for mod in (so, ts, term, backup, db_maintenance, _core, cron, files):
        if getattr(mod, "subprocess", None) is not None:
            mod.subprocess = deny
    if getattr(_core, "_real_subprocess", None) is not None:
        _core._real_subprocess = deny


_stub_commands()
_stub_urlopen()
_stub_subprocess(_stub_terminal())

from app import create_app  # noqa: E402
from panel.core.clock import utcnow  # noqa: E402
from panel.core.panel_state import _install_jobs, _install_lock  # noqa: E402
from panel.db.models import (AuditLog, CustomCommand, GameServer, GlobalBan, Group,  # noqa: E402
                             HostSample, MetricSample, RemoteServer, ServerTag, SetupState, User,
                             db)
from panel.security import auth  # noqa: E402

INSTALLING_ID = 6
# (host, name, account, game, port, status, installed) — hosts by index into _seed_hosts().
GAMES = [
    (0, "Survival MC", "mcserver", "mc", 25565, "online", True),
    (0, "Garry's Mod", "gmodserver", "gmod", 27015, "online", True),
    (1, "Rust Main", "rustserver", "rust", 28015, "offline", True),
    (1, "CS2 Pug", "cs2server", "cs2", 27016, "online", True),
    (2, "Valheim", "vhserver", "vh", 2456, "offline", True),
    (1, "ARK Island", "arkserver", "ark", 7777, "installing", False),
    (2, "Broken Install", "ut2k4server", "ut2k4", 7778, "failed", False),
]


def _seed_users(now):
    """Add the signed-in admin, an operator in a group, and a deactivated account."""
    db.session.add(User(username=USER, password_hash=auth.hash_password(PASSWORD),
                        display_name="Coverage Admin", is_superadmin=True, is_active=True))
    other = User(username="operator", password_hash=auth.hash_password(secrets.token_hex(16)),
                 display_name="Operator", email="op@example.com", is_superadmin=False,
                 is_active=True, last_login=now - timedelta(days=2))
    spare = User(username="retired", password_hash=auth.hash_password(secrets.token_hex(16)),
                 display_name="Retired", is_superadmin=False, is_active=False)
    db.session.add_all([other, spare])
    return other


def _seed_hosts(now):
    """Add the panel's own host, a reachable VPS and one that is down: TEST-NET addresses.

    RFC 5737: nothing is ever reached, and nothing may be.
    """
    hosts = [
        RemoteServer(name="panel-host", host="127.0.0.1", port=22, username="panel",
                     auth_method="local", auth_credential="", is_local=True, sudo_enabled=True,
                     is_online=True, last_seen=now, timezone="Europe/London"),
        RemoteServer(name="vps-one", host="192.0.2.10", port=22, username="root",
                     auth_method="key", auth_credential="", public_ip="203.0.113.10",
                     sudo_enabled=True, is_online=True, last_seen=now),
        RemoteServer(name="vps-two", host="192.0.2.20", port=2222, username="root",
                     auth_method="password", auth_credential="x", is_online=False,
                     last_seen=now - timedelta(hours=3)),
    ]
    db.session.add_all(hosts)
    db.session.flush()
    return hosts


def _seed_games(hosts, tags):
    """Add the game servers of GAMES, tagged in turn, one mid-install and one failed."""
    rows = []
    for i, (h, name, short, gtype, port, status, installed) in enumerate(GAMES):
        gs = GameServer(remote_id=hosts[h].id, name=name, short_name=short, game_type=gtype,
                        port=port, installed=installed, status=status,
                        daily_restart=(i == 0), restart_pending=(i == 1),
                        peak_players=(8 if i == 0 else 0))
        if status == "failed":
            gs.install_error = "SteamCMD could not download the server files."
        if i % 2 == 0:
            gs.tags.append(tags[(i // 2) % len(tags)])
        db.session.add(gs)
        rows.append(gs)
    db.session.flush()
    return rows


def _seed_groups_and_commands(operator, vps):
    """Add a group with a member and a host, a default group, two commands and a ban."""
    grp = Group(name="moderators", description="Start and stop", is_default=False)
    grp.set_permissions([auth.VIEW_SERVERS, auth.START_SERVER, auth.STOP_SERVER])
    grp.servers.append(vps)
    grp.users.append(operator)
    db.session.add(grp)
    db.session.add(Group(name="viewers", description="Look, don't touch", is_default=True))
    db.session.add_all([
        CustomCommand(name="Say hello", command_template="say Hello from the panel",
                      scope_type="all", enabled=True, created_by=USER),
        CustomCommand(name="Change map", command_template="changelevel {}",
                      argument_label="Map", argument_pattern="^[a-z0-9_]+$",
                      scope_type="all", enabled=True, created_by=USER),
    ])
    db.session.add(GlobalBan(steamid="STEAM_0:1:12345", player_name="cheater",
                             reason="aimbot", created_by=USER))


def _seed_history(now, game, hosts):
    """Add three pages of audit log, and a day of samples at the sampler's cadence."""
    kinds = [("server_start", "Survival MC", True), ("login", "", True),
             ("login_failed", "", False), ("server_stop", "Rust Main", True)]
    db.session.add_all([
        AuditLog(user_id=None, username=USER, action=a, target=t, detail="seeded",
                 ip_address="127.0.0.1", timestamp=now - timedelta(minutes=5 * k), success=ok)
        for k, (a, t, ok) in enumerate(kinds * 30)])
    db.session.add_all([
        MetricSample(server_id=game.id, ts=now - timedelta(minutes=10 * k),
                     cpu=float(10 + (k * 7) % 60), ram_mb=1500 + (k * 13) % 400,
                     players=(k * 3) % 9) for k in range(144)])
    db.session.add_all([
        HostSample(remote_id=r.id, ts=now - timedelta(minutes=10 * k),
                   cpu=float(5 + (k * 11) % 70), ram_pct=40.0 + (k % 20),
                   disk_pct=38.0) for r in hosts[:2] for k in range(144)])


def seed(app):
    """Fill the fresh database: the wizard, accounts, hosts, servers, groups and history."""
    now = utcnow()
    with app.app_context():
        # The wizard is left at its Tailscale step, with the admin already made: walk.py finishes
        # it (the last two pages of it are only ever rendered before setup is done).
        db.session.add(SetupState(step="tailscale", complete=False, data="{}"))
        operator = _seed_users(now)
        tags = [ServerTag(name="survival", color="#3ba55d", notify=True),
                ServerTag(name="events", color="#d29922", notify=False),
                ServerTag(name="staging", color="", notify=True)]
        db.session.add_all(tags)
        hosts = _seed_hosts(now)
        games = _seed_games(hosts, tags)
        _seed_groups_and_commands(operator, hosts[1])
        _seed_history(now, games[0], hosts)
        db.session.commit()


_STEPS = ["Queued", "Creating user", "Dependencies", "Downloading LinuxGSM",
          "Installing server files", "Config", "Firewall", "Starting"]


def _install_job(k):
    """Return the install job at tick `k` of a 12-tick cycle: 8 steps, done, a retry, failed."""
    phase = k % 12
    job = {"status": "running", "step": phase % 8, "total": 8, "step_name": _STEPS[phase % 8],
           "message": "", "log": ["line %d of the install" % i for i in range(phase % 8 + 1)],
           "started": time.time() - 60 - k * 3, "updated": time.time(), "name": "ARK Island"}
    if phase == 8:
        job.update(status="done", message="Installed.", warn=(k // 12) % 2 == 1)
    elif phase == 11:
        job.update(status="failed", message="SteamCMD could not download the server files.")
    return job


def _installing():
    """Keep a server installing, for the corner progress widget: a new tick every few seconds.

    Its install finishes, is retried and fails in turn, so the widget sees each ending.
    """
    k = 0
    while True:
        with _install_lock:
            _install_jobs[INSTALLING_ID] = _install_job(k)
        k += 1
        time.sleep(3)


app = create_app()
seed(app)
threading.Thread(target=_installing, daemon=True).start()
print("js_coverage panel: seeded, serving on 127.0.0.1:%d" % PORT, flush=True)
app.socketio.run(app, host="127.0.0.1", port=PORT, debug=False, allow_unsafe_werkzeug=True)
