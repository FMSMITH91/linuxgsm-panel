"""Part 197 of the unit suite: every game-account shell starts in `/`.

sudo keeps the caller's working directory: the panel unit's WorkingDirectory on its own host, the
SSH login's home on a remote, and both sit under a home a game account cannot enter. GNU find
saves the directory it starts in and goes back to it before exiting; when it cannot, it exits 1
after a complete listing. The file browser read that rc as "unreadable" and the upload check as
"could not look", about folders that had just been listed.

Held here:
* The command shell_as_game_user builds (local host, remote host, local with the user scope) has
  `cd / || exit; ` at the head of the game account's shell body, exactly once.
* The file browser route and the upload check route, run in a REAL bash on the local transport
  from a working directory nobody can enter, list the folder.
* The backup listing still lists from there (a control: its exit status is printf's, not find's).

HOW IT RUNS. On part12's Flask app and stubs. run_command is replaced by one that strips the
`sudo -u <account> ` in front of a game-account command, points /home/<account> at a throwaway
home, and hands the rest to the panel's real local shell transport from a 0000 directory. As root
nothing is unreadable, so the two real-shell checks skip by name there.
"""
import os
import shlex as _shlex197
import shutil as _shutil197
import tempfile as _tf197
from types import SimpleNamespace as _NS197

from unit.part01 import check, skip
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_sh)
from panel.db.models import GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import cron as _cron197
from panel.security import auth as _auth197

_TRIP197_START = len(_P9_TRIPPED)
_USER197 = "gucwd197"
# The panel's real local shell transport, taken before _p9_arm puts a tripwire in its place.
_REAL_SHELL197 = _p9_core._exec_local_shell
_HOME197 = os.path.realpath(_tf197.mkdtemp(prefix="lgsm-unit-p197-home-"))
_LOCKED197 = os.path.realpath(_tf197.mkdtemp(prefix="lgsm-unit-p197-cwd-"))
_SEEN197 = []
_mine197 = {"hosts": [], "servers": [], "users": []}


def _locked_shell197(text, timeout, stdin_text):
    """`text` through the real local transport, started in a directory nobody but root can enter."""
    here = os.getcwd()
    os.chdir(_LOCKED197)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0000: closes this test's own temp dir
    os.chmod(_LOCKED197, 0)  # nosec B103 - closes the directory: no bits at all
    try:
        return _REAL_SHELL197(text, timeout=timeout, stdin_text=stdin_text)
    finally:
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: owner-only, as mkdtemp made it
        os.chmod(_LOCKED197, 0o700)  # nosec B103 - owner-only, as mkdtemp made it
        os.chdir(here)


def _run197(server, cmd, timeout=30, sudo=False, stdin_text=None, **_kw):
    """run_command: a game-account command runs for real (see the module docstring); others fail."""
    _SEEN197.append((getattr(server, "name", ""), cmd, sudo))
    prefix = "sudo -u %s " % _USER197
    if sudo or not cmd.startswith(prefix):
        return "", "not a game-account command", 1
    return _locked_shell197(cmd[len(prefix):].replace("/home/" + _USER197, _HOME197), timeout, stdin_text)


def _write197(rel, text=""):
    path = os.path.join(_HOME197, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _arm197():
    _p9_arm(who="part197")
    _p9_patch(_p9_core, "run_command", _run197)
    _p9_patch(_p9_core, "user_scope_argv", lambda: list(_p9_core.USER_SCOPE_ARGV))
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()


def _setup197():
    with _p9.app_context():
        r = RemoteServer(name="p197-host", host="192.0.2.197", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p197-" + _USER197, short_name=_USER197, game_type="csgo",
                        port=27197, installed=True, status="offline")
        admin = User(username="p197_admin", password_hash=_auth197.hash_password("Str0ng!passw0rd-p197"),
                     display_name="p197 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine197["hosts"].append(r.id)
        _mine197["servers"].append(gs.id)
        _mine197["users"].append(admin.id)
        return gs.id, admin.id


def _cleanup197():
    with _p9.app_context():
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine197[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    for path in (_LOCKED197, _HOME197):
        try:
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: owner-only, a cut-short run left it 0000
            os.chmod(path, 0o700)  # nosec B103 - owner-only; a run cut short may have left it 0000
        except OSError:
            # Already gone (a clean earlier run, or another cleanup): nothing to make removable.
            pass
        _shutil197.rmtree(path, ignore_errors=True)


# ── 1. the built command ─────────────────────────────────────────────────────────────────────────
def _body197(cmd):
    """The shell body `bash -c` is handed in `cmd`, or "" when there is none."""
    words = _shlex197.split(cmd)
    return words[words.index("-c") + 1] if "-c" in words else ""


def _built197():
    hosts = {"local": _NS197(name="local", is_local=True, auth_method="local"),
             "remote": _NS197(name="remote", is_local=False, auth_method="key")}
    got = {}
    for label, scope in (("local", False), ("remote", False), ("local", True)):
        del _SEEN197[:]
        _p9_core.shell_as_game_user(hosts[label], _USER197, "find /tmp -maxdepth 0", scope=scope)
        cmd = _SEEN197[0][1] if _SEEN197 else ""
        body = _body197(cmd)
        got[label + ("+scope" if scope else "")] = (body.startswith("cd / || exit; find /tmp"),
                                                    cmd.count("cd / "), "sudo -u %s bash -c " % _USER197 in cmd)
    check("game shell: the command run as a game account (panel host, remote host, panel host in the "
          "user scope) starts its shell body in / exactly once",
          got == {k: (True, 1, True) for k in ("local", "remote", "local+scope")}, repr(got))


# ── 2. the file browser and the upload check, from a directory the account cannot enter ──────────
_LOCKED_NAMES197 = (
    "game shell: the file browser lists a folder when the panel's working directory is one the game "
    "account cannot enter",
    "game shell: the upload check finds an existing file when the panel's working directory is one the "
    "game account cannot enter",
    "game shell: the backup listing lists the archives when the panel's working directory is one the "
    "game account cannot enter (control)")


def _names197(entries):
    return sorted(e.get("name") for e in entries or [])


def _browse_route197(client, sid):
    r = client.get("/api/server/%d/browse?path=" % sid)
    body = _p9_json(r)
    ok = (r.status_code == 200 and not body.get("unreadable")
          and _names197(body.get("entries")) == ["a.cfg", "lgsm", "serverfiles"])
    check(_LOCKED_NAMES197[0], ok, repr((r.status_code, body)))


def _upload_check197(client, sid):
    r = client.post("/api/server/%d/upload-check" % sid, json={"path": "", "names": ["a.cfg", "new.cfg"]})
    body = _p9_json(r)
    ok = r.status_code == 200 and body.get("checked") is True and _names197(body.get("existing")) == ["a.cfg"]
    check(_LOCKED_NAMES197[1], ok, repr((r.status_code, body)))


def _backups197():
    listing = _cron197.list_game_backups(_NS197(name="local", is_local=True), _USER197)
    check(_LOCKED_NAMES197[2], _names197(listing) == ["csgoserver-2026-11-14-120000.tar.zst"], repr(listing))


def _browse197(client, sid):
    if os.geteuid() == 0:
        for name in _LOCKED_NAMES197:
            skip(name, "root enters every directory, so the working directory cannot be made unreadable")
        return
    _write197("a.cfg", "x\n")
    _write197("serverfiles/b.cfg", "y\n")
    _write197("lgsm/backup/csgoserver-2026-11-14-120000.tar.zst", "z")
    _browse_route197(client, sid)
    _upload_check197(client, sid)
    _backups197()


try:
    _arm197()
    _built197()
    _S197, _ADMIN197 = _setup197()
    _browse197(_p9_client(_ADMIN197), _S197)
finally:
    _p9_restore_all()
    _cleanup197()

check("part197: nothing it drove reached a real transport beyond the local shell it hands each "
      "game-account command (every other host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP197_START, repr(_P9_TRIPPED[_TRIP197_START:][:6]))
