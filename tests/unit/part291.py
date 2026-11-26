"""Part 291 of the unit suite: secrets off the command line, login timing, host findings.

1. File writes: a file the panel writes as a game account (the file editor, the config form, uploads) travels on
   the command's stdin as base64, never in the command, on every transport (local, Tailscale SSH, direct SSH).
2. Sign-in: POST /login and the SFTP service spend the same hashing work for an unknown name as for any account
   while bcrypt-era hashes remain; the upgrade layers those hashes in Argon2id, and a sign-in re-encodes them.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; each transport is a recorder.
"""
import base64 as _b64_291
import json as _json291

import bcrypt as _bcrypt291
from sqlalchemy import text as _text291

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, RemoteServer, User, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_patch, _p9_restore_all, db)
from panel.db import models as _models291
from panel.ops.ssh_manager import _core as _core291, files as _files291
from panel.routes import server_files as _sf291
from panel.security import account_guard as _ag291, auth as _auth291
from panel.services import sftp_broker as _broker291

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

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Sign-in spends the same hashing work for every name; bcrypt-era hashes are layered at upgrade
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The decoy for an unknown or inactive name was one Argon2id verify (about 13 ms) while an account
# still holding a bcrypt-era hash cost a bcrypt (hundreds of ms): one timed POST /login said the
# account existed. Each path's hashing is counted here (run_off_hub is the one door to every hash).
_K291 = "harbour violet stepping " + "stones"     # the fixtures' password (no real credential)
_work291 = []
_run_off291 = _auth291.run_off_hub


def _count291(fn, *args):
    _work291.append("bcrypt" if fn in (_bcrypt291.checkpw, _bcrypt291.hashpw) else
                    "argon2" if fn is _auth291._argon2_verify else getattr(fn, "__name__", "?"))
    return _run_off291(fn, *args)


def _user291(name, password_hash, active=True):
    with _p9.app_context():
        u = User(username=name, password_hash=password_hash, display_name=name, is_superadmin=False,
                 is_active=active)
        db.session.add(u)
        db.session.commit()
        return u.id


def _bcrypt_era291(password):
    """A `sha256$` bcrypt hash of `password`, as the panel stored before Argon2id (low cost: counted, not timed)."""
    return "sha256$" + _bcrypt291.hashpw(_auth291._prehash(password), _bcrypt291.gensalt(4)).decode()


def _login291(n, name, password):
    """POST /login from its own address: (status, the hashing it ran, sorted)."""
    _ag291.reset_denials()
    del _work291[:]
    r = _p9.test_client().post("/login", data={"username": name, "password": password},
                               environ_base={"REMOTE_ADDR": "198.51.100.%d" % n})
    return r.status_code, sorted(_work291)


def _hash_of291(uid):
    with _p9.app_context():
        return db.session.get(User, uid).password_hash


_U291 = {"argon": _user291("p291_argon", _auth291.hash_password(_K291)),
         "legacy": _user291("p291_legacy", _bcrypt_era291(_K291)),
         "layered": _user291("p291_layered", _bcrypt_era291(_K291)),
         "off": _user291("p291_off", _bcrypt_era291(_K291), active=False)}
with _p9.app_context():
    _hist291 = db.session.get(User, _U291["argon"])
    _hist291.password_history = _json291.dumps([_bcrypt_era291("old " + _K291)])
    db.session.commit()

# The upgrade's data migration 4, through the startup's runner: every bcrypt-era hash layered.
with _p9.app_context():
    db.session.execute(_text291("PRAGMA user_version = 3"))
    db.session.commit()
    for _uid291 in (_U291["legacy"], _U291["off"]):     # these two stay bcrypt-era for the timing checks
        db.session.get(User, _uid291).password_hash = "p291-hold"
    db.session.commit()
    _models291._run_data_migrations()
    _ver291 = db.session.execute(_text291("PRAGMA user_version")).scalar()
    _hist_after291 = _json291.loads(db.session.get(User, _U291["argon"]).password_history)
_layered291 = _hash_of291(_U291["layered"])
with _p9.app_context():
    db.session.get(User, _U291["legacy"]).password_hash = _bcrypt_era291(_K291)
    db.session.get(User, _U291["off"]).password_hash = _bcrypt_era291(_K291)
    db.session.commit()
check("upgrade: data migration 4 wraps a bcrypt-era password hash in Argon2id (layered), counted as run",
      _layered291.startswith("layered$sha256$$2b$04$") and "$argon2id$" in _layered291 and _ver291 == 4,
      repr((_layered291[:70], _ver291)))
check("upgrade: ...the layered hash still takes the right password and refuses a wrong one, and is "
      "re-encoded at the next sign-in",
      _auth291.check_password(_K291, _layered291) and not _auth291.check_password("x" + _K291, _layered291)
      and _auth291.needs_rehash(_layered291), _layered291[:70])
check("upgrade: ...and the reuse history's bcrypt-era hashes are layered too, still matching",
      len(_hist_after291) == 1 and _hist_after291[0].startswith("layered$")
      and _auth291.check_password("old " + _K291, _hist_after291[0]), repr(_hist_after291)[:120])
check("upgrade: ...an Argon2id hash is left as it is (control)",
      _hash_of291(_U291["argon"]).startswith("$argon2id$"), _hash_of291(_U291["argon"])[:30])

_paths291 = {}
_sftp_none291 = _sftp_legacy291 = _good291 = (None, None)
try:
    _auth291.run_off_hub = _count291
    _auth291._LEGACY_SEEN.update(at=None, any=True)
    _paths291 = {"unknown": _login291(1, "p291_nobody", "x" + _K291),
                 "inactive": _login291(2, "p291_off", "x" + _K291),
                 "argon2": _login291(3, "p291_argon", "x" + _K291),
                 "bcrypt-era": _login291(4, "p291_legacy", "x" + _K291),
                 "layered": _login291(5, "p291_layered", "x" + _K291)}
    # With no bcrypt-era hash anywhere, the extra bcrypt is not spent (the database is asked).
    with _p9.app_context():
        _keep291 = {u.id: u.password_hash for u in User.query.all()
                    if not (u.password_hash or "").startswith("$argon2id$")}
        for _uid291 in _keep291:
            db.session.get(User, _uid291).password_hash = _auth291.hash_password(_K291)
        db.session.commit()
    _auth291._LEGACY_SEEN.update(at=None, any=True)
    _paths291["unknown, no legacy hash"] = _login291(6, "p291_nobody2", "x" + _K291)
    _paths291["argon2, no legacy hash"] = _login291(7, "p291_argon", "x" + _K291)
    with _p9.app_context():
        for _uid291, _h291 in _keep291.items():
            db.session.get(User, _uid291).password_hash = _h291
        db.session.commit()
    # The SFTP service's sign-in, the other caller.
    _auth291._LEGACY_SEEN.update(at=None, any=True)
    with _p9.app_context():
        del _work291[:]
        _sftp_none291 = (_broker291._kbd_refusal(None, {"password": "x" + _K291}), sorted(_work291))
        del _work291[:]
        _sftp_legacy291 = (_broker291._kbd_refusal(db.session.get(User, _U291["legacy"]),
                                                   {"password": "x" + _K291}), sorted(_work291))
    _good291 = _login291(8, "p291_layered", _K291)
finally:
    _auth291.run_off_hub = _run_off291
    _auth291._LEGACY_SEEN.update(at=None, any=True)

_same291 = ["argon2", "bcrypt"]
_five291 = ("unknown", "inactive", "argon2", "bcrypt-era", "layered")
check("login timing: an unknown name, an inactive account, an Argon2id account, a bcrypt-era one and a "
      "layered one each run one Argon2id and one bcrypt while bcrypt-era hashes remain (the decoy ran "
      "Argon2id only, 20x faster than a bcrypt account)",
      all(_paths291.get(k, (0, None)) == (200, _same291) for k in _five291), repr(_paths291))
check("login timing: ...and only one Argon2id each once no bcrypt-era hash is left (control)",
      _paths291.get("unknown, no legacy hash", (0, None))[1] == ["argon2"]
      and _paths291.get("argon2, no legacy hash", (0, None))[1] == ["argon2"], repr(_paths291))
check("SFTP sign-in timing: an unknown name and a bcrypt-era account run the same hashing",
      _sftp_none291[1] == _sftp_legacy291[1] == _same291
      and _sftp_none291[0] == "no such user" and _sftp_legacy291[0] == "wrong password",
      repr((_sftp_none291, _sftp_legacy291)))
check("login: the right password on a layered account signs in and re-encodes it as Argon2id (control)",
      _good291[0] == 302 and _hash_of291(_U291["layered"]).startswith("$argon2id$"),
      repr((_good291, _hash_of291(_U291["layered"])[:30])))
with _p9.app_context():
    for _uid291 in _U291.values():
        db.session.delete(db.session.get(User, _uid291))
    db.session.commit()
