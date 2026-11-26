"""Part 291 of the unit suite: secrets off the command line, login timing, host findings.

1. File writes: a file the panel writes as a game account (the file editor, the config form, uploads) travels on
   the command's stdin as base64, never in the command, on every transport (local, Tailscale SSH, direct SSH).
2. Sign-in: POST /login and the SFTP service spend the same hashing work for an unknown name as for any account
   while bcrypt-era hashes remain; the upgrade layers those hashes in Argon2id, and a sign-in re-encodes them.
3. The helper's refusal of an account a sudoers rule for ALL users covers names that rule's file and line; the
   panel's enrolment passes it on whole; install.sh's can_already_sudo still answers yes and no.
4. The Panel Server page warns, never blocks, while the panel listens beyond loopback and the tailnet; an automatic
   bind (the setup wizard's blank field) listens on loopback behind Tailscale Serve.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; each transport is a recorder. The helper
reads a scratch sudoers policy, with the account and group lookups stood in.
"""
import base64 as _b64_291
import importlib.machinery as _mach291
import importlib.util as _ilu291
import json as _json291
import os as _os291
import re as _re291
import shutil as _shutil291
import subprocess as _sp291  # nosec B404 - python over this part's own scratch copy of the helper
import sys as _sys291
import tempfile as _tf291
from types import SimpleNamespace as _NS291

import bcrypt as _bcrypt291
from sqlalchemy import text as _text291

from unit.part01 import _root as _root291, check
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_LOCAL, RemoteServer, User, _p9, _p9_app, _p9_arm, _p9_client,
                         _p9_json, _p9_patch, _p9_restore_all, db)
from panel.db import models as _models291
from panel.ops import system_ops as _so291
from panel.ops.ssh_manager import _core as _core291, files as _files291
from panel.routes import server_files as _sf291
from panel.security import account_guard as _ag291, auth as _auth291
from panel.services import sftp_broker as _broker291

_HELPER291 = _os291.path.join(_root291, "tools", "panel-helper")

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
    _core291.run_command = _rec291("tailscale")
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

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The helper's "a sudoers rule for ALL users" refusal names the file and line to narrow
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The refusal said to narrow "that rule" without saying where it was; a host with a control panel's
# drop-in (`ALL ALL=(ALL) NOPASSWD: ...` in /etc/sudoers.d/<name>) left the operator hunting.
_spec291 = _ilu291.spec_from_loader("panel_helper_291", _mach291.SourceFileLoader("panel_helper_291", _HELPER291))
_helper291 = _ilu291.module_from_spec(_spec291)
_spec291.loader.exec_module(_helper291)
_SUD291 = _tf291.mkdtemp(prefix="p291-sudoers-")
_os291.makedirs(_os291.path.join(_SUD291, "sudoers.d"))
_DROP291 = _os291.path.join(_SUD291, "sudoers.d", "cloudpanel")


def _sudoers291(main, drop):
    with open(_os291.path.join(_SUD291, "sudoers"), "w", encoding="utf-8") as fh:
        fh.write(main)
    with open(_DROP291, "w", encoding="utf-8") as fh:
        fh.write(drop)


_ALLDROP291 = ("# added by a hosting control panel\n\nDefaults env_keep += \"X\"\n"
               "ALL ALL=(ALL) NOPASSWD: \\\n  /usr/bin/id\n")
_h291 = _helper291
_h291.SUDOERS_FILE, _h291.SUDOERS_DIR = _os291.path.join(_SUD291, "sudoers"), _os291.path.join(_SUD291, "sudoers.d")
_h291.NSSWITCH_FILE = _os291.path.join(_SUD291, "no-nsswitch.conf")
_h291._groups_of = lambda user: {"p291grp"}
_h291._doas_verdict = _h291._polkit_verdict = lambda user, names: None
_h291.pwd = _NS291(getpwnam=lambda user: _NS291(pw_uid=61291, pw_gid=61291))
_h291.grp = _NS291(getgrnam=lambda name: _NS291(gr_gid=61291))
_sudoers291("root ALL=(ALL) ALL\n", _ALLDROP291)
_v_all291 = _h291._escalation_verdict("p291acct")
_sudoers291("root ALL=(ALL) ALL\n@include %s\n" % _DROP291, "p291acct ALL=(ALL) ALL\n")
_v_named291 = _h291._escalation_verdict("p291acct")
_sudoers291("root ALL=(ALL) ALL\n", "%admins ALL=(ALL) ALL\n")
_v_none291 = _h291._escalation_verdict("p291acct")
check("helper: a sudoers rule for ALL users refuses the account and names its file and line (the line a "
      "continued rule starts on), so the operator knows what to narrow",
      _v_all291 == ("yes", "a sudoers rule for ALL users (%s:4) grants it sudo; narrow that rule to named users or "
                           "groups" % _DROP291), repr(_v_all291))
check("helper: ...a rule naming the account, reached through @include, is placed in the included file",
      _v_named291 == ("yes", "a sudoers rule (%s:1) grants it sudo" % _DROP291), repr(_v_named291))
check("helper: ...and a policy with no rule for it still lets it in (control)", _v_none291 == ("no", ""),
      repr(_v_none291))

# The panel's side: the enrolment's refusal reaches the add-on card whole (it was cut at 200
# characters, which a long account name and path pushed the location past).
_said291 = ("refusing to enrol p291-a-rather-long-game-account-name in lgsmpanel-games: it can already reach "
            "root (%s)" % _v_all291[1])
_enrol291 = None
try:
    _p9_patch(_core291, "is_local_server", lambda s: True)
    _p9_patch(_core291, "run_privileged", lambda *a, **k: ("", _said291, 1))
    _enrol291 = _core291.enrol_game_user(object(), "p291-a-rather-long-game-account-name")
finally:
    _p9_restore_all()
check("enrolment: the helper's refusal comes back whole, its file and line and what to do included",
      _enrol291 == _said291 and len(_said291) > 200, repr(_enrol291))

# install.sh's can_already_sudo prints the verdict's first word, which is unchanged: its own snippet,
# run on the helper's code over this sandbox, still answers yes and no.
_inst291 = open(_os291.path.join(_root291, "install.sh"), encoding="utf-8").read()
_cas291 = _re291.search(r"<<'CAS_PY' \|\| true\n(.*?)\nCAS_PY\n", _inst291, _re291.S)
_code291 = _os291.path.join(_SUD291, "helper-code.py")


def _cas_answer291(drop):
    _sudoers291("root ALL=(ALL) ALL\n", drop)
    with open(_HELPER291, encoding="utf-8") as fh, open(_code291, "w", encoding="utf-8") as out:
        out.write(fh.read() + "\nSUDOERS_FILE, SUDOERS_DIR = %r, %r\nNSSWITCH_FILE = %r\n"
                  "import types\n_groups_of = lambda user: {'p291grp'}\n"
                  "_doas_verdict = _polkit_verdict = lambda user, names: None\n"
                  "pwd = types.SimpleNamespace(getpwnam=lambda u: types.SimpleNamespace(pw_uid=61291, pw_gid=61291))\n"
                  "grp = types.SimpleNamespace(getgrnam=lambda n: types.SimpleNamespace(gr_gid=61291))\n"
                  % (_h291.SUDOERS_FILE, _h291.SUDOERS_DIR, _h291.NSSWITCH_FILE))
    feed = _cas291.group(1) if _cas291 else ""
    r = _sp291.run([_sys291.executable, "-I", "-", _code291, "p291acct"], input=feed,  # nosec B603 - own helper copy
                   capture_output=True, text=True, timeout=60)
    return r.stdout.strip()


_cas_got291 = (_cas_answer291(_ALLDROP291), _cas_answer291("%admins ALL=(ALL) ALL\n"))
check("install.sh: can_already_sudo's helper question still answers yes for a rule for ALL users, and no "
      "without one (control)", _cas291 is not None and _cas_got291 == ("yes", "no"), repr(_cas_got291))
_shutil291.rmtree(_SUD291, ignore_errors=True)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The Panel Server page warns while the panel listens beyond loopback and the tailnet
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A panel the setup wizard pinned to 0.0.0.0 went on listening on every interface after Tailscale
# Serve was put in front of it. The wizard's blank field is automatic now (setup_wizard_test), and
# the page says so, as a warning and never a block, whatever the stored setting: it reads the
# address this process really listens on.


def _manage291(bind):
    """The Panel Server page rendered while this process listens on `bind`: (status, warning paragraph or "")."""
    _p9.config["BOOT_BIND"] = bind
    r = _p9_client(P9_ADMIN).get("/remote/%d/manage" % P9_LOCAL)
    html = r.get_data(as_text=True)
    m = _re291.search(r'<p[^>]*id="panel-bind-public-warn".*?</p>', html, _re291.S)
    return r.status_code, (m.group(0) if m else "")


def _quiet291(*a, **k):
    return "", "", 0


_ANY291 = "0.0.0.0"  # nosec B104 - addresses under test, nothing binds
_boot_was291 = _p9.config.get("BOOT_BIND")
_pages291 = {}
try:
    _p9_arm(who="part291")
    for _n291 in ("_run", "_run_verb", "_git"):
        _p9_patch(_so291, _n291, _quiet291)
    _p9_patch(_core291, "run_command", _quiet291)
    _p9_patch(_core291, "run_privileged", _quiet291)
    for _b291 in (_ANY291, "::", "192.0.2.10", "127.0.0.1", "100.101.102.103", "fd7a:115c:a1e0::5"):
        _so291._status_cache["data"] = None
        _pages291[_b291] = _manage291(_b291)
finally:
    _p9_restore_all()
    _so291._status_cache["data"] = None
    _p9.config["BOOT_BIND"] = _boot_was291
check("Panel Server page: while the panel listens on every interface or a LAN or public address it warns, "
      "naming the address and what to choose",
      all(_pages291.get(b, (0, ""))[0] == 200 and ("<code data-no-i18n>%s</code>" % b) in _pages291[b][1]
          and "Localhost only" in _pages291[b][1] for b in (_ANY291, "::", "192.0.2.10")),
      repr({b: v[1][:160] for b, v in _pages291.items()}))
check("Panel Server page: ...and not while it listens on loopback or a Tailscale address (control); the "
      "Apply button is there either way",
      all(_pages291.get(b, (0, "x"))[0] == 200 and _pages291[b][1] == ""
          for b in ("127.0.0.1", "100.101.102.103", "fd7a:115c:a1e0::5")), repr(_pages291))

# The boot rule an automatic (empty) bind meets: 127.0.0.1 while Serve proxies the panel's port.
_rb_was291 = dict(_p9_app._RESOLVED_BIND)
try:
    _p9_patch(_p9_app.ts, "suggest_best_bind", lambda port, *a, **k: {"bind_host": "127.0.0.1"})
    _auto291 = _p9_app._resolved_bind({"bind_host": "", "port": 52911})
    _kept291 = _p9_app._resolved_bind({"bind_host": _ANY291, "port": 52912})
finally:
    _p9_restore_all()
    _p9_app._RESOLVED_BIND.clear()
    _p9_app._RESOLVED_BIND.update(_rb_was291)
check("boot: an automatic bind listens on 127.0.0.1 behind Tailscale Serve, where a stored 0.0.0.0 still wins",
      (_auto291, _kept291) == ("127.0.0.1", _ANY291), repr((_auto291, _kept291)))
