"""Part 291 of the unit suite: secrets off the command line, login timing, host findings.

1. File writes: a file the panel writes as a game account (the file editor, the config form, uploads) travels on
   the command's stdin as base64, never in the command, on every transport (local, Tailscale SSH, direct SSH).

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; each transport is a recorder.
"""
import base64 as _b64_291

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, RemoteServer, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all, db)
from panel.ops.ssh_manager import _core as _core291, files as _files291
from panel.routes import server_files as _sf291

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A written file's bytes are on no command line
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A config the panel writes carries RCON and admin passwords, a steampass and alert tokens. The
# command is an argv every local account reads in /proc/<pid>/cmdline and sudo logs as COMMAND=; the
# bytes went there as base64. They now go on stdin, which neither shows.
_SECRET291 = "p291-rcon-" + "Zx81Qw"
_BODY291 = 'rconpassword="%s"\nport="27015"\n' % _SECRET291
_seen291 = []


def _rec291(kind):
    """A transport stand-in recording (kind, command, stdin as bytes) and answering success."""
    def run(*a, **k):
        command = a[1] if kind != "local" else a[0]
        stdin = k.get("stdin_text") if kind != "paramiko" else a[4]
        if stdin is not None and not isinstance(stdin, (str, bytes)):
            stdin = b"".join(stdin)
        _seen291.append((kind, command, stdin.encode() if isinstance(stdin, str) else stdin))
        return "", "", 0
    return run


def _save291(kind):
    """POST the file editor's save on P9_GS with `kind` as the host's transport: its JSON reply."""
    _p9_patch(_core291, "is_local_server", lambda s: kind == "local")
    for name, k in (("_run_local", "local"), ("_run_via_ssh_cli", "tailscale"), ("_run_via_paramiko", "paramiko")):
        _p9_patch(_core291, name, _rec291(k))
    with _p9.app_context():
        db.session.get(RemoteServer, P9_HOST).auth_method = "tailscale" if kind == "tailscale" else "key"
        db.session.commit()
    return _p9_json(_p9_client(P9_ADMIN).post("/api/server/%d/file" % P9_GS, json={
        "path": "serverfiles/csgo/cfg/p291.cfg", "content": _BODY291}))


_replies291 = {}
try:
    _p9_arm(who="part291")
    _p9_patch(_sf291, "_write_refused", lambda gs, action, detail="": None)
    for _kind291 in ("local", "tailscale", "paramiko"):
        _replies291[_kind291] = _save291(_kind291)
finally:
    _p9_restore_all()
    with _p9.app_context():
        db.session.get(RemoteServer, P9_HOST).auth_method = "key"
        db.session.commit()

_writes291 = [(k, c, i) for k, c, i in _seen291 if ".paneltmp" in c]
_b64_291s = _b64_291.b64encode(_BODY291.encode()).decode()
check("file write: the file editor's save went out once on each transport (local, Tailscale SSH, direct SSH)",
      all(r.get("success") is True for r in _replies291.values())
      and [k for k, _c, _i in _writes291] == ["local", "tailscale", "paramiko"],
      repr((_replies291, [(k, c[-120:]) for k, c, _i in _writes291])))
check("file write: no command carries the file, as text or base64, on any transport (it went in the "
      "argv every local account reads and sudo logs)",
      _writes291 and not [k for k, c, _i in _writes291 if _SECRET291 in c or _b64_291s[:40] in c],
      repr([(k, c[-160:]) for k, c, _i in _writes291]))
check("file write: ...each command gets the file on its stdin, as base64 that decodes to it (control)",
      _writes291 and all(_i is not None and _b64_291.b64decode(_i) == _BODY291.encode() for _k, _c, _i in _writes291),
      repr([(k, (_i or b"")[:60]) for k, _c, _i in _writes291]))

# A large file (an upload) is one command too, its stdin sent in slices that join to the whole.
_big291 = bytes(range(256)) * 400 + b"tail"
_seen291.clear()
_files291_saved = _core291.run_command
try:
    _core291.run_command = lambda s, c, **k: _rec291("tailscale")(s, c, **k)
    _okb291 = _files291._write_file_as_user(object(), "csgoserver", "/home/csgoserver/big.bin", _big291)
finally:
    _core291.run_command = _files291_saved
check("file write: a large file is one command, its bytes on stdin only",
      _okb291 == (True, "") and len(_seen291) == 1 and _b64_291.b64decode(_seen291[0][2]) == _big291
      and _b64_291.b64encode(_big291[:3000]).decode()[:40] not in _seen291[0][1],
      repr((_okb291, len(_seen291), [len(c) for _k, c, _i in _seen291])))

