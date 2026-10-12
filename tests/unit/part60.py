"""Part 60 of the unit suite: New file and New folder in the file browser.

The owner asked to create a file or a folder from the file browser. POST
/api/server/<id>/create-path makes one empty file or folder in the folder the browser shows, held
to every gate rename-path has:

* the name is ONE path component, by the rules rename's new name is held to (name_problem, now
  shared, its wording naming neither) — refused before the host is asked anything, with a reason
  the Spanish and French catalogs translate; the kind is "file" or "folder" and nothing else;
* the folder stays inside the game account's home, resolved the way rename resolves its source
  (lexically, then on the host with `cd -P`), and a folder reached through a symlink is refused
  rather than followed; a folder that is not there says so;
* the new name is never a protected path (lgsm/, serverfiles, .ssh...) nor one the live console
  reads — by its text before the host is asked, and on the host by its resolved path;
* nothing is ever replaced: a name already there (a dangling symlink included) is taken, `mkdir`
  fails on an existing name and noclobber's O_EXCL refuses a file that appears during the create;
  success is read from the filesystem (the right type, not a symlink), not from an exit status;
* the account write gate (a root-capable game account is refused) is delete's and rename's;
* paramiko (raises) and the Tailscale and local transports (return rc -1) give one fixed answer;
* every outcome is audited as create_file or create_folder, the refusals made before the host is
  asked too, with " (name taken)" and " (unconfirmed)" as rename writes them.

HOW IT RUNS. As part40 does: on part12's Flask app, database and client helpers, part12's transport
tripwire re-armed for this part's duration, every stub undone in its finally. The host side runs in
a REAL bash over a throwaway home; a bash function standing in for `mkdir` or `set` plays one step
of a racing host, so a missing guard shows as a replaced file. It ends by checking nothing it drove
reached a real host.
"""
import json
import os
import shutil as _shutil60
import subprocess as _sp60  # nosec B404 - runs bash on the create command this part builds
import tempfile as _tf60
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_so, _p9_trip)
from unit.part40 import _HOSTILE40
from panel.db.models import AuditLog, GameServer, Group, RemoteServer, User, db
from panel.ops.ssh_manager import files as _files60
from panel.routes import _shared as _sh60
from panel.routes import server_files as _sf60
from panel.security import auth as _auth60

_TRIP60_START = len(_P9_TRIPPED)
_ROOT60 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_USER60 = "cr60"                      # the game account; its "home" is _HOME60
_HOME60 = os.path.realpath(_tf60.mkdtemp(prefix="lgsm-unit-p60-home-"))
_OUTSIDE60 = os.path.realpath(_tf60.mkdtemp(prefix="lgsm-unit-p60-out-"))
_LEAK60 = "LEAKMARK-p60"              # in every transport failure's own text; never in an answer
_REAL_SHELL60 = _p9_core.shell_as_game_user
_SHELLS60 = []                        # every script a create sent to the host
_PROBES60 = []                        # every account the write gate asked the host about
_PRELUDE60 = {"text": ""}             # bash run before the command: a stand-in for a race
_mine60 = {"hosts": [], "servers": [], "users": [], "groups": []}
_CR60 = "/api/server/%d/create-path"
_TAKEN_MSG60 = ("Something with that name already exists in this folder. Nothing was created — "
                "choose another name.")
# part40's hostile names, with the reason each must be refused for. Only the empty name's differs:
# a create asks for "a name", a rename for "a new name".
_HOSTILE60 = [(n, "Enter a name" if n == "" else w) for n, w in _HOSTILE40]
_ACTIONS60 = ("create_file", "create_folder")


# ── fixtures ────────────────────────────────────────────────────────────────────────────────────
def _bash60(server, user, sh, timeout=30, selfname=None):
    """shell_as_game_user, in a real bash, with /home/<account> pointing at the throwaway home."""
    _SHELLS60.append(sh)
    script = _PRELUDE60["text"] + sh.replace("/home/" + _USER60, _HOME60)
    p = _sp60.run(["bash", "-c", script], capture_output=True, text=True,  # nosec B603 B607 - bash on this part's own command
                  timeout=30)
    return p.stdout, p.stderr, p.returncode


def _privileged60(remote, users):
    """privileged_accounts as a host would answer it: `adminacct` is in sudo, the rest are plain."""
    _PROBES60.append(list(users))
    return {u: "it is in the sudo group, which can become root" for u in users if u == "adminacct"}


def _write60(rel, text):
    path = os.path.join(_HOME60, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read60(rel):
    try:
        with open(os.path.join(_HOME60, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _kind60(rel):
    """'link', 'dir', 'file' or None for what is at `rel` (lstat: a symlink is a link)."""
    p = os.path.join(_HOME60, rel)
    if os.path.islink(p):
        return "link"
    if os.path.isdir(p):
        return "dir"
    return "file" if os.path.exists(p) else None


def _clear60(where):
    for name in os.listdir(where):
        p = os.path.join(where, name)
        if os.path.islink(p) or not os.path.isdir(p):
            os.unlink(p)
        else:
            _shutil60.rmtree(p)


def _fresh_home60():
    """A known tree: files, a folder, the protected tree and symlinks."""
    _clear60(_HOME60)
    _clear60(_OUTSIDE60)
    for rel, text in (("cfg/a.cfg", "A"), ("maps/sub/m.bsp", "M"),
                      ("lgsm/config-lgsm/csgoserver/common.cfg", "L")):
        _write60(rel, text)
    os.symlink("cfg", os.path.join(_HOME60, "lnk"))                 # a folder link inside the home
    os.symlink("lgsm", os.path.join(_HOME60, "lg"))                 # ...onto the protected tree
    os.symlink(_OUTSIDE60, os.path.join(_HOME60, "esc"))            # ...and out of the home
    os.symlink("../maps", os.path.join(_HOME60, "cfg", "todir"))    # a folder link in cfg
    os.symlink("nowhere", os.path.join(_HOME60, "cfg", "dangle"))   # a dangling one


def _snapshot60():
    """{relative path: (kind, content or link target)} for everything under the home."""
    out = {}
    for dp, dns, fns in os.walk(_HOME60):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, _HOME60)
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
            elif os.path.isdir(p):
                out[rel] = ("dir", None)
            else:
                out[rel] = ("file", _read60(rel))
    return out


def _host60(name, host, **kw):
    with _p9.app_context():
        r = RemoteServer(name=name, host=host, port=22, username=kw.pop("username", "admin"),
                         auth_method=kw.pop("auth_method", "key"), auth_credential="",
                         is_online=True, **kw)
        db.session.add(r)
        db.session.commit()
        _mine60["hosts"].append(r.id)
        return r.id


def _server60(rid, short, port):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name="p60-" + short, short_name=short, game_type="csgo",
                        port=port, installed=True, status="offline")
        db.session.add(gs)
        db.session.commit()
        _mine60["servers"].append(gs.id)
        return gs.id


def _users60(rid):
    """A superadmin, and a viewer who can see the host's servers but not manage their files."""
    with _p9.app_context():
        pw = _auth60.hash_password("Str0ng!passw0rd-p60")
        admin = User(username="p60_admin", password_hash=pw, display_name="p60 admin",
                     is_superadmin=True, is_active=True)
        grp = Group(name="p60_view", description="", is_default=False)
        grp.set_permissions([_auth60.VIEW_CONSOLE])
        grp.servers.append(db.session.get(RemoteServer, rid))
        viewer = User(username="p60_viewer", password_hash=pw, display_name="p60 viewer",
                      is_superadmin=False, is_active=True)
        viewer.groups.append(grp)
        db.session.add_all([admin, grp, viewer])
        db.session.commit()
        _mine60["users"] += [admin.id, viewer.id]
        _mine60["groups"].append(grp.id)
        return admin.id, viewer.id


def _audits60():
    """Every create_file and create_folder audit row, oldest first."""
    with _p9.app_context():
        return [NS(action=a.action, target=a.target, detail=a.detail or "", success=a.success,
                   gsid=a.game_server_id)
                for a in AuditLog.query.filter(AuditLog.action.in_(_ACTIONS60))
                .order_by(AuditLog.id).all()]


def _last60():
    return (_audits60() or [NS(action=None, target=None, detail="", success=None, gsid=None)])[-1]


def _post60(client, sid, d, name, kind="file"):
    """(status, json), or (None, {"raised": ...}) when the request raised: a check FAILS by name."""
    try:
        r = client.post(_CR60 % sid, json={"dir": d, "name": name, "kind": kind})
    except Exception as exc:  # noqa: BLE001 - a crash fails the check that made it, not the part
        return None, {"raised": repr(exc)[:200]}
    return r.status_code, _p9_json(r)


def _refusal_rows60(n_before):
    """The create rows since `n_before`, and whether each is a failed refusal."""
    rows = _audits60()[n_before:]
    return rows, all(r.success is False and r.detail.startswith("refused: ") for r in rows)


def _reset60(prelude=""):
    """A fresh home, nothing recorded, no cached account verdict, and `prelude` before each run."""
    _fresh_home60()
    del _SHELLS60[:]
    del _PROBES60[:]
    _PRELUDE60["text"] = prelude
    with _sh60._ACCOUNT_VERDICTS_LOCK:
        _sh60._ACCOUNT_VERDICTS.clear()


# ── the route's own refusals: nothing reaches the host ──────────────────────────────────────────
def _hostile_names60(a_client, sid):
    """Each hostile name is refused (400) with its reason, before the host is asked anything."""
    _reset60()
    before = _snapshot60()
    n_audit = len(_audits60())
    bad = []
    for kind in ("file", "folder"):
        for name, why in _HOSTILE60:
            code, body = _post60(a_client, sid, "cfg", name, kind)
            if (code, why in (body.get("message") or "")) != (400, True):
                bad.append("%s %r -> %s %r" % (kind, name[:12], code, body))
    check("create route: a name with a slash, a control character, a separator, a text-direction "
          "control, a space at either end, '.', '..', empty, too long or not valid text is "
          "refused (400) with its own reason — for a file and for a folder",
          not bad, "; ".join(bad[:4]))
    check("create route: ...before the host is asked anything — no account probe, no command",
          (_PROBES60, _SHELLS60) == ([], []), repr((_PROBES60[:2], _SHELLS60[:1])))
    rows, refused = _refusal_rows60(n_audit)
    details = " ".join(r.detail for r in rows)
    check("create route: ...each is audited as a failed create_file or create_folder, the name "
          "written escaped (\\x00, \\u2028, \\u202e, \\ud800)",
          len(rows) == 2 * len(_HOSTILE60) and refused
          and sorted({r.action for r in rows}) == list(_ACTIONS60)
          and all(e in details for e in ("\\x00", "\\u2028", "\\u202e", "\\ud800")),
          "%d rows: %r" % (len(rows), [r.detail[:40] for r in rows][:4]))
    check("create route: ...and the home is exactly as it was", _snapshot60() == before, "")
    code, body = _post60(a_client, sid, "cfg", "y" * 251 + ".cfg")
    check("create route: a name of exactly 255 bytes is still allowed (control for 'too long')",
          (code, body.get("success"), _kind60("cfg/" + "y" * 251 + ".cfg")) == (200, True, "file"),
          repr((code, body)))


def _types60(a_client, sid):
    """A folder that is not text, or a kind that is not "file" or "folder", is a 400, not a crash."""
    _reset60()
    before = _snapshot60()
    n_audit = len(_audits60())
    got = [_post60(a_client, sid, d, "x.txt", k)
           for d, k in ((5, "file"), (["cfg"], "folder"), (None, "file"), ("cfg", True),
                        ("cfg", 1), ("cfg", "File"), ("cfg", "dir"), ("cfg", None),
                        ("cfg", ["file"]), ("cfg", {"file": 1}))]
    want = ["Invalid path"] * 3 + ["Choose a file or a folder."] * 7
    check("create route: a folder that is not text, or a kind that is not exactly \"file\" or "
          "\"folder\" (true, 1, \"File\", \"dir\", null, a list, an object), is refused (400) "
          "with its reason, before the host is asked anything — no account probe, no command",
          [(c, b.get("message")) for c, b in got] == [(400, m) for m in want]
          and (_PROBES60, _SHELLS60) == ([], []), repr((got, _PROBES60[:1])))
    rows, refused = _refusal_rows60(n_audit)
    check("create route: ...each is audited as a failed create, and nothing was made",
          len(rows) == len(got) and refused and _snapshot60() == before,
          repr([r.detail[:50] for r in rows]))


def _escapes60(a_client, sid):
    """A folder that leaves the home, or is not valid text, is refused and runs nothing."""
    _reset60()
    n_audit = len(_audits60())
    dirs = ("../x", "cfg/../../etc", "../../etc", "/..", "cfg/\ud800")
    bad = [(d, r) for d, r in ((d, _post60(a_client, sid, d, "y")) for d in dirs)
           if r != (400, {"success": False, "message": _files60.CREATE_REFUSED})]
    check("create route: a folder escaping the home through '..', or that is not valid text, is "
          "refused (400) and sends nothing", not bad and not _SHELLS60, repr(bad[:3]))
    rows, refused = _refusal_rows60(n_audit)
    check("create route: ...and each is audited", len(rows) == len(dirs) and refused, repr(rows))
    code, body = _post60(a_client, sid, "", "top.txt")
    check("create route: the home itself is a folder a file can be made in (control)",
          (code, body.get("success"), _kind60("top.txt")) == (200, True, "file"), repr(body))


def _protected60(a_client, sid):
    """A protected destination is refused by its text, before the host runs anything."""
    _reset60()
    n_audit = len(_audits60())
    cases = (("", "serverfiles", "folder"), ("", ".ssh", "folder"), ("", "lgsm", "folder"),
             ("lgsm", "x.cfg", "file"), ("lgsm/config-lgsm/csgoserver", "new.cfg", "file"),
             ("cfg/..", "serverfiles", "folder"))
    want = (400, {"success": False, "message": _files60.CREATE_RESERVED})
    bad = [(c, r) for c, r in ((c, _post60(a_client, sid, *c)) for c in cases) if r != want]
    check("create route: a name that would be protected where it lands (serverfiles, .ssh, lgsm, "
          "anything in lgsm/, however the folder is written) is refused (400)",
          not bad, repr(bad[:3]))
    rows, refused = _refusal_rows60(n_audit)
    check("create route: ...none of them sent a command, each is audited, nothing was made",
          not _SHELLS60 and len(rows) == len(cases) and refused
          and (_kind60("serverfiles"), _kind60(".ssh"), _kind60("lgsm/x.cfg")) == (None, None, None),
          repr((_SHELLS60[:1], rows[:2])))


def _console60(a_client, sid):
    """A name the live console reads is refused — by its text, and on the host when resolved."""
    _reset60()
    n_audit = len(_audits60())
    cases = (("", "log", "folder"), ("log", "console", "folder"),
             ("log/console", "csgoserver-console.log", "file"), ("./log/", "console", "folder"))
    want = (400, {"success": False, "message": _files60.CREATE_CONSOLE})
    bad = [(c, r) for c, r in ((c, _post60(a_client, sid, *c)) for c in cases) if r != want]
    check("create route: log, log/console and the console's own log are refused (400) by name, "
          "and nothing is sent", not bad and not _SHELLS60, repr(bad[:3]))
    rows, refused = _refusal_rows60(n_audit)
    check("create route: ...each is audited", len(rows) == len(cases) and refused, repr(rows))
    # The logs on another folder, through `log -> disk/logs`, not made yet: only the host sees
    # that disk/logs is where the console will read.
    _reset60()
    os.makedirs(os.path.join(_HOME60, "disk"))
    os.symlink("disk/logs", os.path.join(_HOME60, "log"))
    code, body = _post60(a_client, sid, "disk", "logs", "folder")
    check("create route (real bash): with log -> disk/logs, making disk/logs is refused on the "
          "host — the console's path, resolved", (code, body, _kind60("disk/logs"))
          == (200, {"success": False, "message": _files60.CREATE_CONSOLE}, None),
          repr((code, body)))
    code, body = _post60(a_client, sid, "disk", "other", "folder")
    check("create route (real bash): ...a folder beside it is made (control)",
          (code, body.get("success"), _kind60("disk/other")) == (200, True, "dir"),
          repr((code, body)))


def _permission60(v_client, sid):
    """Someone who may see the server but not manage its files gets a 403, and nothing runs."""
    _reset60()
    n_audit = len(_audits60())
    got = [_post60(v_client, sid, "cfg", "z.cfg", k)[0] for k in ("file", "folder")]
    check("create route: a user without the file-manager permission is refused (403)",
          got == [403, 403], repr(got))
    check("create route: ...nothing is asked, sent, audited or made",
          (_PROBES60, _SHELLS60, len(_audits60()), _kind60("cfg/z.cfg"))
          == ([], [], n_audit, None), repr((_PROBES60, _SHELLS60[:1])))


# ── the host side, end to end in a real bash ────────────────────────────────────────────────────
def _plain60(a_client, sid):
    """A file and a folder are made, empty, of the right kind, and nothing else changes."""
    _reset60()
    before = _snapshot60()
    code, body = _post60(a_client, sid, "cfg", "new file.cfg", "file")
    check("create route: a file is made (200, 'Created'): empty, a regular file",
          ((code, body), _kind60("cfg/new file.cfg"), _read60("cfg/new file.cfg"))
          == ((200, {"success": True, "message": "Created"}), "file", ""), repr((code, body)))
    row = _last60()
    check("create route: ...audited as create_file: the server, the new path, success",
          (row.action, row.success, row.target, row.gsid, row.detail)
          == ("create_file", True, "p60-" + _USER60, sid, "cfg/new file.cfg"), repr(row))
    code, body = _post60(a_client, sid, "maps/sub", "custom", "folder")
    check("create route: a folder is made (200), empty",
          ((code, body), _kind60("maps/sub/custom"),
           os.listdir(os.path.join(_HOME60, "maps/sub/custom")) if _kind60("maps/sub/custom") else None)
          == ((200, {"success": True, "message": "Created"}), "dir", []), repr((code, body)))
    row = _last60()
    check("create route: ...audited as create_folder",
          (row.action, row.success, row.detail) == ("create_folder", True, "maps/sub/custom"),
          repr(row))
    want = dict(before)
    want["cfg/new file.cfg"] = ("file", "")
    want["maps/sub/custom"] = ("dir", None)
    check("create route: ...and nothing else in the home changed", _snapshot60() == want,
          repr(sorted(set(_snapshot60().items()) ^ set(want.items()))[:4]))


def _taken60(a_client, sid):
    """A name already there — a file, a folder, a symlink, a dangling one — is a conflict."""
    _reset60()
    before = _snapshot60()
    bad = []
    for kind in ("file", "folder"):
        for name in ("a.cfg", "todir", "dangle"):
            code, body = _post60(a_client, sid, "cfg", name, kind)
            if (code, body) != (409, {"success": False, "conflict": True, "message": _TAKEN_MSG60}):
                bad.append("%s %s -> %s %r" % (kind, name, code, body))
        code, body = _post60(a_client, sid, "", "maps", kind)
        if code != 409:
            bad.append("%s maps -> %s %r" % (kind, code, body))
    check("create route: a name held by a file, a folder, a symlink to a folder or a DANGLING "
          "symlink is refused as a conflict (409) — for a new file and a new folder",
          not bad, "; ".join(bad[:4]))
    check("create route: ...and nothing changed: the file keeps its content, the links their "
          "targets, nothing was made inside the linked folder", _snapshot60() == before,
          repr(sorted(set(_snapshot60().items()) ^ set(before.items()))[:4]))
    row = _last60()
    check("create route: ...and the refusal is audited as a failure, name taken",
          (row.action, row.success, row.detail) == ("create_folder", False, "maps (name taken)"),
          repr(row))


# Each stands in for one step of the host: the name appearing between the check and the create.
_RACE_DIR60 = 'mkdir(){ command mkdir -- "${@: -1}"; printf K > "${@: -1}/keep"; command mkdir "$@"; }; '
_RACE_FILE60 = 'set(){ [ "$1" = -o ] && printf RACER > "$t"; builtin set "$@"; }; '
_MKDIR_LIES60 = 'mkdir(){ return 0; }; '


def _race60():
    """A name appearing during the create is refused — never replaced; success is read back."""
    _reset60(_RACE_DIR60)
    got = _files60.create_path(_SRV60, _USER60, "cfg", "new", "folder")
    check("create command (real bash): a folder appearing at the name during the create is "
          "reported as taken, and what is in it is kept",
          (got, _read60("cfg/new/keep")) == ((False, _files60.CREATE_EXISTS), "K"), repr(got))
    _reset60(_RACE_FILE60)
    got = _files60.create_path(_SRV60, _USER60, "cfg", "new.cfg", "file")
    check("create command (real bash): a file appearing at the name during the create is "
          "reported as taken and NOT emptied (noclobber's O_EXCL)",
          (got, _read60("cfg/new.cfg")) == ((False, _files60.CREATE_EXISTS), "RACER"), repr(got))
    _reset60(_MKDIR_LIES60)
    got = _files60.create_path(_SRV60, _USER60, "cfg", "ghost", "folder")
    check("create command (real bash): a mkdir that reports success but made nothing is not "
          "reported as created — the folder is looked for afterwards",
          (got[0], _kind60("cfg/ghost")) == (False, None), repr(got))


def _symlinks60(a_client, sid):
    """A folder reached through a symlink is refused, not followed; one out of the home too."""
    _reset60()
    code, body = _post60(a_client, sid, "lnk", "z.cfg")
    check("create route: a folder reached through a symlink (inside the home) is refused, not "
          "followed", (code, body.get("success"), "symbolic link" in (body.get("message") or ""),
                       _kind60("cfg/z.cfg")) == (200, False, True, None), repr((code, body)))
    code, body = _post60(a_client, sid, "lg/config-lgsm", "zz.cfg")
    check("create route: lgsm/ reached through a symlinked folder is refused",
          (body.get("success"), _kind60("lgsm/config-lgsm/zz.cfg")) == (False, None),
          repr((code, body)))
    code, body = _post60(a_client, sid, "esc", "y.txt", "folder")
    check("create route: a folder outside the home, reached through a symlink, is refused and "
          "nothing is made there", (body.get("success"), body.get("message"), os.listdir(_OUTSIDE60))
          == (False, _files60.CREATE_REFUSED, []), repr((code, body)))
    code, body = _post60(a_client, sid, "lg", "x.cfg")
    check("create route: a name landing in lgsm/ through `lg -> lgsm` is refused on the host as "
          "reserved", (body.get("message"), _kind60("lgsm/x.cfg"))
          == (_files60.CREATE_RESERVED, None), repr((code, body)))


def _gone60(a_client, sid):
    """A folder that is not there — or is a file — says so, rather than 'the host did not answer'."""
    _reset60()
    got = [_post60(a_client, sid, d, "x.cfg") for d in ("nodir", "cfg/a.cfg")]
    want = (200, {"success": False, "message": _files60.CREATE_NO_DIR})
    check("create route: a folder that is not there, or is a file, is reported as gone",
          got == [want, want] and _kind60("nodir") is None, repr(got))


def _builder_wall60():
    """create_path refuses a bad name, kind, escape or protected name itself, sending nothing."""
    _reset60()
    got = [_files60.create_path(_SRV60, _USER60, d, n, k, selfname="csgoserver")
           for d, n, k in (("cfg", "a/b", "file"), ("cfg", "..", "folder"), ("../x", "y", "file"),
                           ("", "lgsm", "folder"), ("cfg", "x" * 300, "file"),
                           ("cfg", "ok", "link"), ("log", "console", "folder"))]
    check("create_path: refuses a bad name, a bad kind, a folder out of the home, a protected or "
          "console name by itself (the route's checks are not its only wall), sending nothing",
          all(ok is False for ok, _m in got) and not _SHELLS60, repr((got, _SHELLS60[:1])))


def _names60():
    """The shared validator: rename keeps "Enter a new name.", a create asks for "a name", and
    the wording names neither a rename nor a create."""
    got = (_files60.rename_name_problem(""), _files60.name_problem(""),
           _files60.name_problem("a/b"), _files60.rename_name_problem("a/b"))
    check("name_problem: an empty name is asked for as 'a name' (create) and 'a new name' "
          "(rename); the slash reason is the same for both and says nothing about renaming",
          got[:2] == ("Enter a new name.", "Enter a name.") and got[2] == got[3]
          and "renam" not in got[2], repr(got))


def _catalog_keys60(lang):
    root = os.path.join(_ROOT60, "translations", lang)
    keys = set()
    for name in sorted(os.listdir(root)):
        if name.endswith(".json"):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                keys |= set(json.load(fh))
    return keys


def _catalog60():
    """Every message a create can show reaches a Spanish or French user in their language."""
    f = _files60
    msgs = {f.CREATE_UNCONFIRMED, f.CREATE_REFUSED, f.CREATE_RESERVED, f.CREATE_CONSOLE,
            f.CREATE_NO_DIR, _TAKEN_MSG60, "Choose a file or a folder."}
    msgs |= {m for _k, m in f._CREATE_OUTCOMES if m != f.CREATE_EXISTS}
    msgs |= {f.name_problem(n) for n, _w in _HOSTILE60} - {None}
    keys = {lg: _catalog_keys60(lg) for lg in ("es", "fr")}
    missing = ["%s: %s" % (lg, m[:50]) for lg in keys for m in sorted(msgs) if m not in keys[lg]]
    check("create: every message a create can answer (each refusal, the conflict, the "
          "unconfirmed one, each name reason) is in the Spanish and French catalogs",
          not missing and len(msgs) >= 15, "%d messages; missing: %s" % (len(msgs), "; ".join(missing[:3])))


# ── the account write gate, the transports, and a crash ────────────────────────────────────────
def _refused_account60(a_client, rid):
    """A root-capable game account is refused exactly as delete-path and rename-path refuse it."""
    _reset60()
    sid = _server60(rid, "adminacct", 27601)
    code, body = _post60(a_client, sid, "cfg", "z.cfg", "folder")
    d = a_client.post("/api/server/%d/delete-path" % sid, json={"path": "cfg/a.cfg"})
    check("create route: a game account that can become root is refused (409), saying why, as "
          "delete-path refuses it", code == 409 and "can become root" in (body.get("message") or "")
          and _p9_json(d).get("message") == body.get("message"), repr((code, body)))
    row = _last60()
    check("create route: ...nothing is sent to the host, and the refusal is audited",
          not _SHELLS60 and (row.action, row.success) == ("create_folder", False)
          and row.detail.startswith("refused: "), repr((_SHELLS60[:1], row)))


def _failing_transports60():
    """Fail every transport: paramiko raises, Tailscale and local return rc -1; each records it."""
    sent = []

    def _paramiko(server):
        sent.append("paramiko")
        raise ConnectionError("Authentication failed: %s" % _LEAK60)

    def _ts(server, command, timeout=30, sudo=None, stdin_text=None):
        sent.append("tailscale")
        return "", "ssh: connect to host box.ts.net port 22: %s timed out" % _LEAK60, -1

    def _local(cmd, timeout=30, sudo=False, stdin_text=None):
        sent.append("local")
        return "", "Command timed out (%s)" % _LEAK60, -1
    _p9_patch(_p9_core, "get_connection", _paramiko)
    _p9_patch(_p9_core, "_run_via_ssh_cli", _ts)
    _p9_patch(_p9_core, "_run_local", _local)
    return sent


def _transports60(a_client):
    """Every transport's failure is the same fixed answer, audited, with none of its own text."""
    _reset60()
    hosts = (("paramiko", _host60("p60-key", "192.0.2.161")),
             ("tailscale", _host60("p60-ts", "box.ts.net", auth_method="tailscale")),
             ("local", _host60("p60-local", "127.0.0.1", auth_method="local", is_local=True)))
    sids = {name: _server60(rid, _USER60, 27610 + i) for i, (name, rid) in enumerate(hosts)}
    _p9_patch(_p9_core, "shell_as_game_user", _REAL_SHELL60)
    sent = _failing_transports60()
    n_audit = len(_audits60())
    try:
        got = {name: _post60(a_client, sid, "cfg", "z.cfg") for name, sid in sids.items()}
    finally:
        _p9_patch(_p9_core, "shell_as_game_user", _bash60)
        _arm60()
    want = (200, {"success": False, "message": _files60.CREATE_UNCONFIRMED})
    check("create route: the premise — each transport was really reached",
          sorted(sent) == ["local", "paramiko", "tailscale"], repr(sent))
    check("create route: paramiko (raises), Tailscale and local (return rc -1) all give the same "
          "fixed answer, telling the user to reload", all(g == want for g in got.values())
          and "Reload" in _files60.CREATE_UNCONFIRMED, repr(got))
    check("create route: ...with none of the transport's own text in it",
          not any(_LEAK60 in repr(g) for g in got.values()), repr(got))
    rows = _audits60()[n_audit:]
    check("create route: ...and each is audited as an unconfirmed failure",
          len(rows) == 3 and all(r.success is False and r.detail == "cfg/z.cfg (unconfirmed)"
                                 for r in rows), repr(rows))


def _crash60(a_client, sid):
    """Anything else the create raises is a 500 with the generic text, not a traceback."""
    _reset60()

    def _boom(*_a, **_k):
        raise RuntimeError("p60 boom %s" % _LEAK60)
    _p9_patch(_files60, "create_path", _boom)
    try:
        code, body = _post60(a_client, sid, "cfg", "z.cfg")
    finally:
        _p9_patch(_files60, "create_path", _REAL_CREATE60)
    check("create route: an unexpected error is a 500 with the generic message, none of its text",
          code == 500 and body.get("success") is False and _LEAK60 not in repr(body)
          and bool(body.get("message")), repr((code, body)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
_SRV60 = NS(id=96001, host="192.0.2.160", is_local=False, auth_method="key")
_REAL_CREATE60 = _files60.create_path


def _arm60():
    """part12's tripwire, again: nothing below may reach a host or run a command on this machine."""
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part60's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_run_local", _p9_trip("local-run"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash60)
    _p9_patch(_sh60, "privileged_accounts", _privileged60)


def _cleanup60():
    with _p9.app_context():
        for sid in _mine60["servers"]:
            gs = db.session.get(GameServer, sid)
            if gs is not None:
                db.session.delete(gs)
        db.session.commit()
        for model, key in ((User, "users"), (Group, "groups"), (RemoteServer, "hosts")):
            for oid in _mine60[key]:
                o = db.session.get(model, oid)
                if o is not None:
                    db.session.delete(o)
        db.session.commit()
    with _sh60._ACCOUNT_VERDICTS_LOCK:
        _sh60._ACCOUNT_VERDICTS.clear()
    _shutil60.rmtree(_HOME60, ignore_errors=True)
    _shutil60.rmtree(_OUTSIDE60, ignore_errors=True)


try:
    _arm60()
    _H60 = _host60("p60-host", "192.0.2.160")
    _S60 = _server60(_H60, _USER60, 27600)
    _ADMIN60, _VIEWER60 = _users60(_H60)
    _A60, _V60 = _p9_client(_ADMIN60), _p9_client(_VIEWER60)
    check("part60: the route is registered, and reached through the module the tests stub",
          "api_server_create_path" in _p9.view_functions and hasattr(_sf60, "_create_answer"),
          "no create-path view")
    _hostile_names60(_A60, _S60)
    _types60(_A60, _S60)
    _escapes60(_A60, _S60)
    _protected60(_A60, _S60)
    _console60(_A60, _S60)
    _permission60(_V60, _S60)
    _plain60(_A60, _S60)
    _taken60(_A60, _S60)
    _race60()
    _symlinks60(_A60, _S60)
    _gone60(_A60, _S60)
    _builder_wall60()
    _names60()
    _catalog60()
    _refused_account60(_A60, _H60)
    _transports60(_A60)
    _crash60(_A60, _S60)
finally:
    _p9_restore_all()
    _cleanup60()

check("part60: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP60_START, repr(_P9_TRIPPED[_TRIP60_START:][:6]))
