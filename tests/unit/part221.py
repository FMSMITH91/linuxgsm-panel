"""Part 221 of the unit suite: the pen test's file-browser, error-page, step-up and outbound-URL findings.

* The file browser never writes, uploads, creates or renames onto a path that decides who can sign
  in to the game account (~/.ssh, the shell start-up files, .pam_environment, .rhosts/.shosts,
  .k5login): by name in Python, and for a write on the path the HOST resolves, so a link to ~/.ssh
  is refused too. Real bash over this part's own fixture tree; the routes on part12's app.

HOW IT RUNS. On part12's Flask app with its transport tripwire armed for each section, every stub
undone in its finally. Bash runs only over this part's temporary tree; nothing reaches a host, sudo or
the checkout's data/.
"""
import io as _io221
import os as _os221
import shutil as _shutil221
import subprocess as _sp221  # nosec B404 - runs bash over this part's own fixture tree
import tempfile as _tempfile221
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_sf)
from panel.db.models import GameServer as _GS221, RemoteServer as _RS221, db as _db221
from panel.ops.ssh_manager import files as _files221

_trips221 = len(_P9_TRIPPED)
_TREE221 = _tempfile221.mkdtemp(prefix="lgsm-unit-p221-")
_HOME221 = "/home/p221u"
_ROWS221 = {"remotes": [], "servers": []}


def _setup221():
    """A host row and one game server on it; the server's id."""
    with _p9.app_context():
        r = _RS221(name="p221-host", host="p221.example.invalid", port=22, username="admin",
                   auth_method="key", auth_credential="", is_online=True)
        _db221.session.add(r)
        _db221.session.commit()
        gs = _GS221(remote_id=r.id, name="p221-css", short_name="p221u", game_type="css", port=27221,
                    installed=True, status="offline")
        _db221.session.add(gs)
        _db221.session.commit()
        _ROWS221["remotes"].append(r.id)
        _ROWS221["servers"].append(gs.id)
        return gs.id


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Sign-in paths in the game account's home (M2)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _fixture221():
    """The fixture home: ~/.ssh, serverfiles/, and `keys -> .ssh` (a link a mod or the game could plant)."""
    home = _TREE221 + _HOME221
    _shutil221.rmtree(home, ignore_errors=True)
    _os221.makedirs(home + "/.ssh")
    _os221.makedirs(home + "/serverfiles")
    _os221.symlink(".ssh", home + "/keys")
    return home


def _bash221(server, user, sh, timeout=30, selfname=None):
    """shell_as_game_user, run by real bash with the home moved under this part's tree."""
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp221.run(["bash", "-c", sh.replace(_HOME221, _TREE221 + _HOME221)],  # nosec B603 B607
                   capture_output=True, text=True, timeout=timeout, check=False)
    return r.stdout, r.stderr, r.returncode


def _m2_host221():
    """A write whose target RESOLVES to ~/.ssh is refused on the host before a byte is staged."""
    home = _fixture221()
    _p9_patch(_p9_core, "shell_as_game_user", _bash221)
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP221 planted\n"
    got = {"link": _files221.write_file(NS(id=-221), "p221u", "keys/authorized_keys", key),
           "link big": _files221.upload_file(NS(id=-221), "p221u", "keys", "authorized_keys2", b"k" * 90000),
           "plain": _files221.write_file(NS(id=-221), "p221u", "serverfiles/server.cfg", "hostname x\n")}
    left = sorted(_os221.listdir(home + "/.ssh"))
    eq("file browser (real bash): a save and a chunked upload through a link to ~/.ssh are refused on the "
       "host with the sign-in sentence, and nothing is left in ~/.ssh; a plain file still saves (control)",
       (got["link"], got["link big"], got["plain"][0], left,
        open(home + "/serverfiles/server.cfg", encoding="utf-8").read()),
       ((False, _files221.LOGIN_FILE_REFUSED), (False, _files221.LOGIN_FILE_REFUSED), True, [], "hostname x\n"))
    reads = _bash221(None, None, _files221._guarded("p221u", _HOME221 + "/keys/x", "echo READ"))[0].strip()
    eq("file browser (real bash): the read guard is unchanged: a read through the same link still runs",
       reads, "READ")


def _m2_names221():
    """By name, before any round trip: each sign-in path, for each of the four ways to write."""
    names = (".ssh/authorized_keys", ".ssh", ".ssh/rc", ".bashrc", ".profile", ".bash_profile",
             ".bash_login", ".bash_logout", ".pam_environment", ".rhosts", ".shosts", ".k5login",
             "./.ssh/../.ssh/authorized_keys")
    hits = [n for n in names if not _files221._is_login_path(n)]
    eq("file browser: every sign-in path is one by name, written however", hits, [])
    eq("file browser: game files with similar names are not sign-in paths (controls)",
       [_files221._is_login_path(n) for n in (".bashrc.bak", "serverfiles/.ssh", "cfg/.profile", "sshkeys")],
       [False] * 4)
    eq("file browser: rename onto, or out of, a sign-in path, and create in ~/.ssh or as .bash_profile, are "
       "refused with the sign-in sentence",
       [_files221.rename_refusal("p221u", "notes.txt", ".bash_login"),
        _files221.rename_refusal("p221u", ".ssh/authorized_keys2", "authorized_keys"),
        _files221.create_refusal("p221u", ".ssh", "authorized_keys", "file"),
        _files221.create_refusal("p221u", "", ".bash_profile", "file")],
       [_files221.LOGIN_FILE_REFUSED] * 4)
    eq("file browser: the refusal is one an audit row may carry", _files221.write_failure_reason(
        _files221.LOGIN_FILE_REFUSED), _files221.LOGIN_FILE_REFUSED)


def _m2_routes221():
    """The four routes answer the refusal and never reach the host; a plain save still does."""
    gid = _setup221()
    sent = []
    _p9_patch(_p9_core, "shell_as_game_user", lambda server, user, sh, timeout=30, **k: sent.append(sh) or ("", "", 0))
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    c = _p9_client(P9_ADMIN)
    base = "/api/server/%d/" % gid
    answers = [
        _p9_json(c.post(base + "file", json={"path": ".bashrc", "content": "curl x | sh\n"})),
        _p9_json(c.post(base + "file", json={"path": ".ssh/authorized_keys", "content": "ssh-ed25519 A\n"})),
        _p9_json(c.post(base + "upload", content_type="multipart/form-data",
                        data={"path": ".ssh", "overwrite": "1",
                              "file": (_io221.BytesIO(b"ssh-ed25519 A\n"), "authorized_keys")})),
        _p9_json(c.post(base + "rename-path", json={"path": "notes.txt", "new_name": ".bash_login"})),
        _p9_json(c.post(base + "create-path", json={"dir": ".ssh", "name": "authorized_keys", "kind": "file"})),
    ]
    refused = [(a.get("success"), a.get("message")) for a in answers]
    blocked = list(sent)
    ok = _p9_json(c.post(base + "file", json={"path": "serverfiles/server.cfg", "content": "hostname x\n"}))
    eq("file routes: save, upload, rename and create onto a sign-in path answer the sign-in sentence and "
       "send nothing to the host; a plain save still reaches it (control)",
       (refused, blocked, ok.get("success"), len(sent) > 0),
       ([(False, _files221.LOGIN_FILE_REFUSED)] * 5, [], True, True))


def _cleanup221():
    with _p9.app_context():
        for sid in _ROWS221["servers"]:
            row = _db221.session.get(_GS221, sid)
            if row is not None:
                _db221.session.delete(row)
        for rid in _ROWS221["remotes"]:
            row = _db221.session.get(_RS221, rid)
            if row is not None:
                _db221.session.delete(row)
        _db221.session.commit()
    _shutil221.rmtree(_TREE221, ignore_errors=True)


try:
    for _fn221 in (_m2_host221, _m2_names221, _m2_routes221):
        _p9_arm(who="part221")
        try:
            _fn221()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _cleanup221()

check("part221: nothing reached a real transport", len(_P9_TRIPPED) == _trips221, repr(_P9_TRIPPED[_trips221:]))
