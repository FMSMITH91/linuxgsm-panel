"""Part 40 of the unit suite: renaming a file or folder from the file browser.

The owner asked to rename what was just uploaded, through the file browser. POST
/api/server/<id>/rename-path renames one file or folder within the folder it is in, and it is held
to every gate the other file-browser writes have, plus the ones a rename needs of its own:

* the new name is ONE path component — no '/', no control character (NUL, newline, DEL, U+0085),
  no line or paragraph separator, no text-direction control, no whitespace at either end, not '.',
  '..' or empty, at most 255 bytes — checked before the host is asked anything (and again by the
  builder), each refused with a reason the Spanish and French catalogs translate;
* the source and the new name stay inside the game account's home: the path is resolved the way
  delete-path resolves it (lexically, then on the host with realpath and `cd -P`), and a source
  reached through a symlinked folder is refused rather than followed;
* an existing name is never replaced: refused before the move, and `mv -n -T` refuses one that
  appears during it — a race is reported as "taken", never clobbered, and a symlink to a folder
  at the new name is never moved INTO;
* the live console's log and the folders it is in are never renamed away, also when the logs are
  reached through a symlink;
* the account write gate (a root-capable game account is refused) is the same as delete-path's;
* paramiko (raises) and the Tailscale and local transports (return rc -1) give one fixed answer,
  with none of the transport's own text in it;
* every outcome is audited, like delete-path — the refusals made before the host is asked too;
* the browser's own listing shows a name holding U+2028, U+0085 or a newline whole, so its row can be
  acted on — and a name ENDING in whitespace too, through each real transport's strip of its output:
  the local _finish, the Tailscale ssh client and paramiko. Beside a file of the same name without
  the space, each row names its own file, and Rename, Delete and the upload check reach that one.

HOW IT RUNS. On part12's Flask app, database and client helpers (imported; part12 has run by then,
so importing it runs nothing again), with part12's transport tripwire re-armed for this part's
duration and every stub undone in its finally. The rename's host side runs in a REAL bash over a
throwaway home, as part08 runs delete_path's: route, guards and `mv` are driven end to end. For the
race checks a bash function named `mv` stands in for one step of the host — it makes the new name
appear just before the real `mv` runs, or drops `-n` — so a guard that is missing shows as a
clobbered file. _bash40 hands back bash's output untouched, which no transport does: the
whitespace-name checks run the REAL transports instead, with only what is under each standing in
(the process, the ssh client on PATH, the paramiko channel). It ends by checking nothing it drove
reached a real host.
"""
import json
import os
import re as _re40
import shutil as _shutil40
import subprocess as _sp40  # nosec B404 - runs bash on the rename command this part builds
import tempfile as _tf40
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_so, _p9_trip)
from panel.db.models import AuditLog, GameServer, Group, RemoteServer, User, db
from panel.ops.ssh_manager import files as _files40
from panel.routes import _shared as _sh40
from panel.security import auth as _auth40

_TRIP40_START = len(_P9_TRIPPED)
_ROOT40 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_USER40 = "rn40"                      # the game account; its "home" is _HOME40
_HOME40 = os.path.realpath(_tf40.mkdtemp(prefix="lgsm-unit-p40-home-"))
_OUTSIDE40 = os.path.realpath(_tf40.mkdtemp(prefix="lgsm-unit-p40-out-"))
_LEAK40 = "LEAKMARK-p40"              # in every transport failure's own text; never in an answer
_REAL_SHELL40 = _p9_core.shell_as_game_user
# The real transports, taken before _arm40 trips them: the whitespace-name checks run through them.
_REAL_LOCAL_SHELL40 = _p9_core._exec_local_shell
_REAL_SSH_CLI40 = _p9_core._run_via_ssh_cli
_PATH40 = os.environ.get("PATH", "")
_BIN40 = os.path.realpath(_tf40.mkdtemp(prefix="lgsm-unit-p40-bin-"))   # the stand-in `ssh`
_VIA40 = []                           # the transports a command went through, in order
_SHELLS40 = []                        # every script a rename sent to the host
_PROBES40 = []                        # every account the write gate asked the host about
_PRELUDE40 = {"text": ""}             # bash run before the command: a stand-in `mv` for a race
_mine40 = {"hosts": [], "servers": [], "users": [], "groups": []}
_RN40 = "/api/server/%d/rename-path"
_TAKEN_MSG40 = ("Something with that name already exists in this folder. Nothing was renamed — "
                "choose another name.")
# The hostile names, each with the reason the panel must give for it.
_HOSTILE40 = [("a/b", "slash"), ("..", "'..'"), (".", "'.'"), ("", "Enter a new name"),
              ("a\x00b", "control"), ("a\nb", "control"), ("a\x7fb", "control"),
              ("a\x85b", "control"), ("a\u2028b", "separator"), ("a\u2029b", "separator"),
              ("a\u202eb", "text-direction"), ("a\u2066b", "text-direction"),
              ("x" * 256, "too long"), ("é" * 128, "too long"), ("\ud800", "valid text"),
              ("a.cfg ", "start or end with a space"), (" a.cfg", "start or end with a space"),
              ("a.cfg\u00a0", "start or end with a space")]
_CONSOLE40 = "log/console/csgoserver-console.log"   # GameServer.console_log, for game_type csgo


# ── fixtures ────────────────────────────────────────────────────────────────────────────────────
def _bash40(server, user, sh, timeout=30, selfname=None):
    """shell_as_game_user, in a real bash, with /home/<account> pointing at the throwaway home."""
    _SHELLS40.append(sh)
    script = _PRELUDE40["text"] + sh.replace("/home/" + _USER40, _HOME40)
    p = _sp40.run(["bash", "-c", script], capture_output=True, text=True,  # nosec B603 B607 - bash on this part's own command
                  timeout=30)
    return p.stdout, p.stderr, p.returncode


def _privileged40(remote, users):
    """privileged_accounts as a host would answer it: `adminacct` is in sudo, the rest are plain."""
    _PROBES40.append(list(users))
    return {u: "it is in the sudo group, which can become root" for u in users if u == "adminacct"}


def _write40(rel, text):
    path = os.path.join(_HOME40, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read40(rel):
    try:
        with open(os.path.join(_HOME40, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _ino40(rel):
    """The inode at `rel`, or None when there is nothing there (a check fails, never crashes)."""
    try:
        return os.lstat(os.path.join(_HOME40, rel)).st_ino
    except OSError:
        return None


def _link40(rel):
    """Where the symlink at `rel` points, or None when it is not one."""
    try:
        return os.readlink(os.path.join(_HOME40, rel))
    except OSError:
        return None


def _ls40(rel):
    """The sorted names in the folder at `rel`, or None when it is not there."""
    try:
        return sorted(os.listdir(os.path.join(_HOME40, rel)))
    except OSError:
        return None


def _there40(rel):
    return os.path.lexists(os.path.join(_HOME40, rel))


def _clear40(where):
    for name in os.listdir(where):
        p = os.path.join(where, name)
        if os.path.islink(p) or not os.path.isdir(p):
            os.unlink(p)
        else:
            _shutil40.rmtree(p)


def _fresh_home40():
    """A known tree: files, folders, a just-uploaded file, protected names and symlinks."""
    _clear40(_HOME40)
    _clear40(_OUTSIDE40)
    for rel, text in (("cfg/a.cfg", "A"), ("cfg/b.cfg", "B"), ("cfg/c d.cfg", "CD"),
                      ("maps/sub/m.bsp", "M"), ("uploads/new.txt", "N"), ("junk/j.txt", "J"),
                      ("lgsm/config-lgsm/csgoserver/common.cfg", "L")):
        _write40(rel, text)
    with open(os.path.join(_OUTSIDE40, "x.txt"), "w", encoding="utf-8") as fh:
        fh.write("OUT")
    os.symlink("cfg", os.path.join(_HOME40, "lnk"))                 # a folder link inside the home
    os.symlink("lgsm", os.path.join(_HOME40, "lg"))                 # ...onto the protected tree
    os.symlink(_OUTSIDE40, os.path.join(_HOME40, "esc"))            # ...and out of the home
    os.symlink("../maps", os.path.join(_HOME40, "cfg", "todir"))    # a folder link at a new name
    os.symlink("nowhere", os.path.join(_HOME40, "cfg", "dangle"))   # a dangling one


def _snapshot40():
    """{relative path: (kind, content or link target)} for everything under the home."""
    out = {}
    for dp, dns, fns in os.walk(_HOME40):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, _HOME40)
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
            elif os.path.isdir(p):
                out[rel] = ("dir", None)
            else:
                out[rel] = ("file", _read40(rel))
    return out


def _host40(name, host, **kw):
    with _p9.app_context():
        r = RemoteServer(name=name, host=host, port=22, username=kw.pop("username", "admin"),
                         auth_method=kw.pop("auth_method", "key"), auth_credential="",
                         is_online=True, **kw)
        db.session.add(r)
        db.session.commit()
        _mine40["hosts"].append(r.id)
        return r.id


def _server40(rid, short, port):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name="p40-" + short, short_name=short, game_type="csgo",
                        port=port, installed=True, status="offline")
        db.session.add(gs)
        db.session.commit()
        _mine40["servers"].append(gs.id)
        return gs.id


def _users40(rid):
    """A superadmin, and a viewer who can see the host's servers but not manage their files."""
    with _p9.app_context():
        pw = _auth40.hash_password("Str0ng!passw0rd-p40")
        admin = User(username="p40_admin", password_hash=pw, display_name="p40 admin",
                     is_superadmin=True, is_active=True)
        grp = Group(name="p40_view", description="", is_default=False)
        grp.set_permissions([_auth40.VIEW_CONSOLE])
        grp.servers.append(db.session.get(RemoteServer, rid))
        viewer = User(username="p40_viewer", password_hash=pw, display_name="p40 viewer",
                      is_superadmin=False, is_active=True)
        viewer.groups.append(grp)
        db.session.add_all([admin, grp, viewer])
        db.session.commit()
        _mine40["users"] += [admin.id, viewer.id]
        _mine40["groups"].append(grp.id)
        return admin.id, viewer.id


def _audits40():
    """Every rename_file audit row, oldest first."""
    with _p9.app_context():
        return [NS(target=a.target, detail=a.detail or "", success=a.success,
                   gsid=a.game_server_id)
                for a in AuditLog.query.filter_by(action="rename_file").order_by(AuditLog.id).all()]


def _post40(client, sid, path, new_name):
    """(status, json), or (None, {"raised": ...}) when the request raised: a check FAILS by name."""
    try:
        r = client.post(_RN40 % sid, json={"path": path, "new_name": new_name})
    except Exception as exc:  # noqa: BLE001 - a crash fails the check that made it, not the part
        return None, {"raised": repr(exc)[:200]}
    return r.status_code, _p9_json(r)


def _refusal_rows40(n_before, prefix):
    """The rename_file rows since `n_before`, and whether each is a failed refusal of `prefix`."""
    rows = _audits40()[n_before:]
    return rows, all(r.success is False and r.detail.startswith("refused: " + prefix) for r in rows)


def _reset40(prelude=""):
    """A fresh home, nothing recorded, no cached account verdict, and `prelude` before each run."""
    _fresh_home40()
    del _SHELLS40[:]
    del _PROBES40[:]
    _PRELUDE40["text"] = prelude
    with _sh40._ACCOUNT_VERDICTS_LOCK:
        _sh40._ACCOUNT_VERDICTS.clear()


# ── the route's own refusals: nothing reaches the host ──────────────────────────────────────────
def _hostile_names40(a_client, sid):
    """Each hostile new name is refused (400) with its reason, before the host is asked anything."""
    _reset40()
    n_audit = len(_audits40())
    bad = []
    for name, why in _HOSTILE40:
        code, body = _post40(a_client, sid, "cfg/a.cfg", name)
        if (code, why in (body.get("message") or "")) != (400, True):
            bad.append("%r -> %s %r" % (name[:12], code, body))
    check("rename route: a new name with a slash, a control character (NUL, newline, DEL, U+0085), "
          "a line or paragraph separator, a text-direction control, a space (or NBSP) at either "
          "end, '.', '..', empty, too long (chars or UTF-8 bytes) or not valid text is refused "
          "(400), each with its own reason",
          not bad, "; ".join(bad[:4]))
    check("rename route: ...before the host is asked anything — no account probe, no command",
          (_PROBES40, _SHELLS40) == ([], []), repr((_PROBES40[:2], _SHELLS40[:1])))
    rows, refused = _refusal_rows40(n_audit, "cfg/a.cfg -> ")
    details = " ".join(r.detail for r in rows)
    check("rename route: ...and each is audited as a failed rename_file, the name written escaped "
          "(NUL, U+2028, U+202E and a lone surrogate are stored as \\x00, \\u2028, \\u202e, "
          "\\ud800)",
          len(rows) == len(_HOSTILE40) and refused
          and all(e in details for e in ("\\x00", "\\u2028", "\\u202e", "\\ud800")),
          "%d rows for %d names: %r"
          % (len(rows), len(_HOSTILE40), [r.detail[:40] for r in rows][:6]))
    check("rename route: ...and the home is exactly as it was",
          (_read40("cfg/a.cfg"), _ls40("cfg")) == ("A", ["a.cfg", "b.cfg", "c d.cfg", "dangle", "todir"]),
          repr(_ls40("cfg")))
    n_audit = len(_audits40())
    t1 = _post40(a_client, sid, "cfg/a.cfg", 5)
    t2 = _post40(a_client, sid, ["cfg/a.cfg"], "b.cfg")
    check("rename route: a path or new name that is not text is a 400, not a crash",
          (t1[0], t2[0], _SHELLS40) == (400, 400, []), repr((t1, t2)))
    rows, refused = _refusal_rows40(n_audit, "")
    check("rename route: ...and both are audited as failed renames",
          len(rows) == 2 and refused, repr(rows))
    edge = "y" * 251 + ".cfg"
    code, body = _post40(a_client, sid, "cfg/b.cfg", edge)
    check("rename route: a name of exactly 255 bytes is still allowed (control for 'too long')",
          (code, body.get("success"), _read40("cfg/" + edge)) == (200, True, "B"),
          repr((code, body)))


def _catalog_keys40(lang):
    """Every key of translations/<lang>/*.json, merged as panel.core.i18n.catalog merges them."""
    root = os.path.join(_ROOT40, "translations", lang)
    keys = set()
    for name in sorted(os.listdir(root)):
        if name.endswith(".json"):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                keys |= set(json.load(fh))
    return keys


def _catalog40():
    """Each reason a new name is refused for reaches a Spanish or French user in their language.

    The page shows the route's message under the field, and the DOM translator swaps it only when
    it is a catalog key verbatim, so a reason missing from a catalog shows in English.
    """
    reasons = sorted({_files40.rename_name_problem(n) for n, _w in _HOSTILE40} - {None})
    keys = {lg: _catalog_keys40(lg) for lg in ("es", "fr")}
    missing = ["%s: %s" % (lg, r[:50]) for lg in keys for r in reasons if r not in keys[lg]]
    check("rename: every reason a new name is refused for (a space at either end among them) is in "
          "the Spanish and French catalogs",
          not missing and _files40.RENAME_EDGE_SPACE in reasons,
          "%d reasons; missing: %s" % (len(reasons), "; ".join(missing[:3])))


def _escapes40(a_client, sid):
    """A path that leaves the home, or is the home itself, is refused and runs nothing."""
    _reset40()
    n_audit = len(_audits40())
    paths = ("../x", "cfg/../../etc", "../../etc/passwd", "", "/", ".", "cfg/..", "cfg/\ud800")
    bad = []
    for path in paths:
        code, body = _post40(a_client, sid, path, "y")
        if (code, body.get("message")) != (400, _files40.RENAME_REFUSED):
            bad.append("%r -> %s %r" % (path, code, body))
    check("rename route: a path escaping the home through '..', naming the home itself, or that "
          "is not valid text (a lone surrogate) is refused (400), not a crash", not bad,
          "; ".join(bad[:4]))
    check("rename route: ...and no rename command is sent for any of them", not _SHELLS40,
          repr(_SHELLS40[:1]))
    rows, refused = _refusal_rows40(n_audit, "")
    check("rename route: ...and each is audited as a failed rename_file, as delete-path audits its "
          "escapes", len(rows) == len(paths) and refused
          and all(_files40.RENAME_REFUSED in r.detail for r in rows),
          "%d rows for %d paths: %r" % (len(rows), len(paths), [r.detail[:50] for r in rows][:4]))


def _protected40(a_client, sid):
    """Protected sources and destinations are refused by name, before the host runs anything."""
    _reset40()
    n_audit = len(_audits40())
    cases = [("lgsm", "x", _files40.RENAME_PROTECTED),
             ("lgsm/config-lgsm", "x", _files40.RENAME_PROTECTED),
             ("junk", "serverfiles", "reserved"), ("uploads", ".ssh", "reserved"),
             ("cfg/a.cfg", "a.cfg", "already its name")]
    got = [(p, n, _post40(a_client, sid, p, n)) for p, n, _w in cases]
    bad = ["%s -> %s: %r" % (p, n, r) for (p, n, r), (_p, _n, want) in zip(got, cases)
           if (r[0], want in (r[1].get("message") or "")) != (400, True)]
    check("rename route: renaming lgsm/ (or anything in it) away, onto a reserved top-level name "
          "(serverfiles, .ssh), or to the name it already has is refused (400)",
          not bad, "; ".join(bad[:3]))
    check("rename route: ...and none of them sent a command", not _SHELLS40, repr(_SHELLS40[:1]))
    rows, refused = _refusal_rows40(n_audit, "")
    check("rename route: ...and each is audited as a failed rename_file with its reason — moving "
          "the LinuxGSM tree away by renaming leaves the trace deleting it does",
          len(rows) == len(cases) and refused
          and all(r.detail.startswith("refused: %s -> %s: " % (p, n))
                  for r, (p, n, _w) in zip(rows, cases)),
          repr([r.detail[:60] for r in rows]))
    check("rename route: ...and the tree is untouched (no serverfiles, no .ssh, lgsm intact)",
          (_there40("serverfiles"), _there40(".ssh"), _read40("lgsm/config-lgsm/csgoserver/common.cfg"))
          == (False, False, "L"), "")


def _permission40(v_client, sid):
    """Someone who may see the server but not manage its files gets a 403, and nothing runs."""
    _reset40()
    n_audit = len(_audits40())
    code, _body = _post40(v_client, sid, "cfg/a.cfg", "z.cfg")
    check("rename route: a user without the file-manager permission is refused (403)",
          code == 403, "got %d" % code)
    check("rename route: ...nothing is asked, sent or audited, and the file keeps its name",
          (_PROBES40, _SHELLS40, len(_audits40()), _read40("cfg/a.cfg")) == ([], [], n_audit, "A"),
          repr((_PROBES40, _SHELLS40[:1])))


# ── the host side, end to end in a real bash ────────────────────────────────────────────────────
def _plain40(a_client, sid):
    """A file and a folder are renamed in place — content, inode and everything else kept."""
    _reset40()
    before = _snapshot40()
    ino = _ino40("uploads/new.txt")
    code, body = _post40(a_client, sid, "uploads/new.txt", "renamed.txt")
    after = _snapshot40()
    want = dict(before)
    want["uploads/renamed.txt"] = want.pop("uploads/new.txt")
    check("rename route: a just-uploaded file is renamed (200, 'Renamed')",
          (code, body) == (200, {"success": True, "message": "Renamed"}), repr((code, body)))
    check("rename route: ...exactly: same inode, same content, and nothing else in the home moved",
          (after, _ino40("uploads/renamed.txt")) == (want, ino),
          repr(sorted(set(after.items()) ^ set(want.items()))[:4]))
    row = (_audits40() or [NS(target=None, detail="", success=None, gsid=None)])[-1]
    check("rename route: ...audited like delete-path: the server, the old and new names, success",
          (row.success, row.target, row.gsid, row.detail)
          == (True, "p40-" + _USER40, sid, "uploads/new.txt -> renamed.txt"), repr(row))
    code, body = _post40(a_client, sid, "maps", "maps-old")
    check("rename route: a folder is renamed with everything in it",
          (code, body.get("success"), _read40("maps-old/sub/m.bsp"), _there40("maps"))
          == (200, True, "M", False), repr((code, body)))
    code, body = _post40(a_client, sid, "cfg/c d.cfg", "e f.cfg")
    check("rename route: names with spaces go through the shell quoting intact",
          (code, _read40("cfg/e f.cfg")) == (200, "CD"), repr((code, body)))


def _existing40(a_client, sid):
    """An existing name is refused with a conflict, and both files keep their contents."""
    _reset40()
    code, body = _post40(a_client, sid, "cfg/a.cfg", "b.cfg")
    check("rename route: renaming onto an existing name is refused as a conflict (409)",
          (code, body) == (409, {"success": False, "conflict": True, "message": _TAKEN_MSG40}),
          repr((code, body)))
    check("rename route: ...and neither file changed",
          (_read40("cfg/a.cfg"), _read40("cfg/b.cfg")) == ("A", "B"),
          repr((_read40("cfg/a.cfg"), _read40("cfg/b.cfg"))))
    row = (_audits40() or [NS(detail="", success=None)])[-1]
    check("rename route: ...and the refused rename is audited as a failure",
          (row.success, row.detail) == (False, "cfg/a.cfg -> b.cfg (name taken)"), repr(row))
    for new, what in (("todir", "a symlink to a folder"), ("dangle", "a dangling symlink")):
        code, body = _post40(a_client, sid, "cfg/a.cfg", new)
        check("rename route: a new name held by %s is taken too (409) — nothing moves into it"
              % what, (code, _read40("cfg/a.cfg"), _ls40("maps"), _link40("cfg/" + new) is not None)
              == (409, "A", ["sub"], True), repr((code, body)))


def _audit_quotes40(a_client, sid):
    """A name with a space at either end is quoted in its audit row, and /logs keeps the spaces.

    The audit page drops a space at a line's end and collapses a run of them, so a delete of
    `server.cfg ` beside a real `server.cfg` read like a delete of the real config.
    """
    _reset40()
    _write40("cfg/sp.cfg ", "S")
    code, body = _post40(a_client, sid, "cfg/sp.cfg ", "sp2.cfg")
    row = (_audits40() or [NS(detail="", success=None)])[-1]
    check("rename route: a name ending in a space is quoted in its audit row",
          (code, _read40("cfg/sp2.cfg"), row.success, row.detail)
          == (200, "S", True, '"cfg/sp.cfg " -> sp2.cfg'), repr((code, body, row)))
    code, body = _post40(a_client, sid, "cfg/a.cfg", " x.cfg")
    row = (_audits40() or [NS(detail="", success=None)])[-1]
    check("rename route: ...and a refused new name with a space at its start is quoted too",
          (code, row.success, row.detail.startswith('refused: cfg/a.cfg -> " x.cfg": '))
          == (400, False, True), repr((code, row)))
    _write40("cfg/del.cfg ", "D")
    _write40("cfg/del.cfg", "R")
    try:
        r = a_client.post("/api/server/%d/delete-path" % sid, json={"path": "cfg/del.cfg "})
        code = r.status_code
    except Exception as exc:  # noqa: BLE001 - a crash fails the check that made it, not the part
        code = repr(exc)[:200]
    with _p9.app_context():
        last = AuditLog.query.filter_by(action="delete_file").order_by(AuditLog.id.desc()).first()
        got = (last.detail, last.success) if last is not None else None
    check("delete route: a path ending in a space is quoted in its audit row, so it reads apart "
          "from the real file beside it — which is still there",
          (code, got, _there40("cfg/del.cfg "), _read40("cfg/del.cfg"))
          == (200, ('"cfg/del.cfg "', True), False, "R"), repr((code, got)))
    with open(os.path.join(_ROOT40, "templates", "logs.html"), encoding="utf-8") as fh:
        cell = _re40.search(r'<td class="[^"]*audit-detail[^"]*"[^>]*>', fh.read())
    check("/logs: the audit detail cell keeps a row's spaces (white-space: pre-wrap)",
          cell is not None and "white-space:pre-wrap" in cell.group(0).replace(" ", ""),
          cell.group(0) if cell else "no audit-detail cell")


def _symlinks40(a_client, sid):
    """A source reached through a symlinked folder is refused; a symlink itself can be renamed."""
    _reset40()
    code, body = _post40(a_client, sid, "lnk/b.cfg", "z.cfg")
    check("rename route: a file reached through a symlinked folder (inside the home) is refused, "
          "not followed", (code, body.get("success"), "symbolic link" in (body.get("message") or ""),
                           _read40("cfg/b.cfg"), _there40("cfg/z.cfg")) == (200, False, True, "B", False),
          repr((code, body)))
    code, body = _post40(a_client, sid, "lg/config-lgsm", "zz")
    check("rename route: lgsm/ reached through a symlinked folder is refused",
          (body.get("success"), _read40("lgsm/config-lgsm/csgoserver/common.cfg")) == (False, "L"),
          repr((code, body)))
    code, body = _post40(a_client, sid, "esc/x.txt", "y.txt")
    check("rename route: a file outside the home, reached through a symlink, is refused",
          (body.get("success"), body.get("message"), os.listdir(_OUTSIDE40))
          == (False, _files40.RENAME_REFUSED, ["x.txt"]), repr((code, body)))
    code, body = _post40(a_client, sid, "esc", "esc2")
    check("rename route: a symlink that leads out of the home is refused, as delete-path refuses "
          "it — the link stays as it was",
          (code, body, _link40("esc"), _there40("esc2"))
          == (200, {"success": False, "message": _files40.RENAME_REFUSED}, _OUTSIDE40, False),
          repr((code, body)))
    code, body = _post40(a_client, sid, "lnk", "lnk2")
    check("rename route: a symlink itself is renamed as a link (control) — its target untouched",
          (body.get("success"), _link40("lnk2"), _read40("cfg/a.cfg")) == (True, "cfg", "A"),
          repr((code, body)))


def _gone40(a_client, sid):
    """A source or folder that is not there says so, rather than 'the host did not answer'."""
    _reset40()
    r1 = _post40(a_client, sid, "cfg/nope.cfg", "x.cfg")
    r2 = _post40(a_client, sid, "nodir/x.cfg", "y.cfg")
    gone = "no longer there"
    check("rename route: a file that is not there, or whose folder is not, is reported as gone",
          gone in (r1[1].get("message") or "") and gone in (r2[1].get("message") or "")
          and r1[1].get("success") is False and r2[1].get("success") is False, repr((r1, r2)))


def _console40(a_client, sid):
    """The live console's log, and the folders it is in, are never renamed away."""
    _reset40()
    _write40(_CONSOLE40, "CONSOLE")
    _write40("log/console/other.log", "O")
    n_audit = len(_audits40())
    paths = ("log", "log/console", _CONSOLE40, "./log/", "cfg/../log/console")
    want = (400, {"success": False, "message": _files40.RENAME_CONSOLE})
    bad = ["%s: %r" % (p, r) for p, r in ((p, _post40(a_client, sid, p, "moved")) for p in paths)
           if r != want]
    check("rename route: the live console's log, log/console and log/ itself are refused (400), "
          "however the path is written", not bad, "; ".join(bad[:3]))
    rows, refused = _refusal_rows40(n_audit, "")
    check("rename route: ...nothing is sent, the log stays where the console reads it, and each "
          "refusal is audited", not _SHELLS40 and _read40(_CONSOLE40) == "CONSOLE"
          and len(rows) == len(paths) and refused, repr((_SHELLS40[:1], rows[:2])))
    code, body = _post40(a_client, sid, "log/console/other.log", "other-old.log")
    check("rename route: ...another file in log/console is renamed (control)",
          (code, body.get("success"), _read40("log/console/other-old.log")) == (200, True, "O"),
          repr((code, body)))
    # The logs on another folder, reached through `log -> disk/logs`: only the host sees that
    # disk/logs, or disk, is what the console reads.
    _reset40()
    _write40("disk/logs/console/csgoserver-console.log", "CONSOLE")
    _write40("disk/other/x.txt", "X")
    os.symlink("disk/logs", os.path.join(_HOME40, "log"))
    want = (200, {"success": False, "message": _files40.RENAME_CONSOLE})
    got = {p: _post40(a_client, sid, p, "moved")
           for p in ("disk/logs", "disk", "disk/logs/console")}
    check("rename route (real bash): with log -> disk/logs, renaming disk/logs, disk or "
          "disk/logs/console is refused on the host — the console's log stays where it reads it",
          all(r == want for r in got.values()) and _read40(_CONSOLE40) == "CONSOLE",
          repr(got))
    code, body = _post40(a_client, sid, "disk/other", "other2")
    check("rename route (real bash): ...a folder beside them is renamed (control)",
          (code, body.get("success"), _read40("disk/other2/x.txt")) == (200, True, "X"),
          repr((code, body)))


def _listing40():
    """A name holding U+2028, U+2029, U+0085 or a newline is listed whole, so its row reaches it."""
    _reset40()
    odd = ("a\u2028b.cfg", "c\x85d.cfg", "e\u2029f.cfg", "g\nh.cfg")
    for name in odd:
        _write40("cfg/" + name, "S")
    got = _files40.browse_dir(_SRV40, _USER40, "cfg")
    names = sorted(e["name"] for e in (got or {}).get("entries", []))
    check("browse_dir (real bash): a name holding U+2028, U+2029, U+0085 or a newline is listed as "
          "itself, not cut at that character", names == _ls40("cfg"), repr((names, _ls40("cfg"))))
    hits = _files40.stat_upload_targets(_SRV40, _USER40, "cfg", list(odd))
    check("stat_upload_targets (real bash): ...and an upload onto such a name is flagged as a "
          "conflict, as any other existing name is",
          sorted(h.get("name") for h in (hits or [])) == sorted(odd), repr(hits))
    gone = _files40.delete_path(_SRV40, _USER40, "cfg/" + odd[0])
    check("browse_dir (real bash): ...so Delete on its row removes that file",
          (gone, _there40("cfg/" + odd[0])) == ((True, "Deleted"), False), repr(gone))


# ── a name that ENDS in whitespace, through the real transports ────────────────────────────────
# Every transport strips its whole stdout (_core._finish, _run_via_ssh_cli, _run_via_paramiko).
# When the listing ended each record with a newline, the record `find` printed LAST lost the
# whitespace that ended its name: `server.cfg ` was listed as `server.cfg`, and beside a real
# `server.cfg` both rows carried one path — Rename or Delete on the spaced row acted on the real
# config. _bash40 returns bash's output untouched, so nothing above could see it. These checks run
# the transports themselves; only what is under each stands in: the command runs as this account
# instead of `sudo -u <account>`, Tailscale's ssh client is a script on PATH, and paramiko's channel
# serves the bytes of a real bash. No real sudo can run: the prefix game_user_cmd puts on every
# command is dropped, and a `sudo` left anywhere is a shell function that runs its command as this
# account (tools/nosudo_runner refuses any command that names sudo, which is why it is dropped).
_AS40 = "sudo -u %s " % _USER40
_SUDO40 = 'sudo(){ [ "$1" = -u ] && shift 2; "$@"; }; '
_SSH40 = """#!/bin/bash
# part40's ssh client: runs the remote command (its last argument) in this bash, as this account.
printf 'tailscale\\n' >> "$P40_VIA"
c="${@: -1}"
c="${c#%s}"
sudo(){ [ "$1" = -u ] && shift 2; "$@"; }
eval "${c//\\/home\\/%s/$P40_HOME}"
""" % (_AS40, _USER40)


def _on_host40(cmd):
    """`cmd` as the host would run it here: as this account, /home/<account> the throwaway home."""
    cmd = cmd[len(_AS40):] if cmd.startswith(_AS40) else cmd
    return _SUDO40 + cmd.replace("/home/" + _USER40, _HOME40)


def _local40(cmd, timeout=30, sudo=False, stdin_text=None):
    """_run_local for the panel's own host: the real _exec_local_shell, and so the real _finish."""
    _VIA40.append("local")
    return _REAL_LOCAL_SHELL40(_on_host40(cmd), timeout=timeout)


class _Chan40:
    """A paramiko exec channel whose command has finished: its stdout, its stderr, its status."""

    def __init__(self, out, err, rc):
        self.streams, self.rc = {"out": [out] if out else [], "err": [err] if err else []}, rc

    def settimeout(self, _t):
        return None

    def recv_ready(self):
        return bool(self.streams["out"])

    def recv(self, _n):
        return self.streams["out"].pop(0) if self.streams["out"] else b""

    def recv_stderr_ready(self):
        return bool(self.streams["err"])

    def recv_stderr(self, _n):
        return self.streams["err"].pop(0) if self.streams["err"] else b""

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.rc

    def shutdown_write(self):
        return None

    def close(self):
        return None


class _Ssh40:
    """get_connection's client for a direct-SSH host: each exec runs in a real bash, here."""

    def exec_command(self, command, timeout=None):
        _VIA40.append("paramiko")
        p = _sp40.run(["bash", "-c", _on_host40(command)], capture_output=True,  # nosec B603 B607 - bash on this part's own command
                      timeout=30)
        chan = _Chan40(p.stdout, p.stderr, p.returncode)
        return NS(write=lambda _t: None, flush=lambda: None, channel=chan), NS(channel=chan), NS()


def _real_transports40():
    """Route every host command through the REAL transport for its host, over the stand-ins."""
    with open(os.path.join(_BIN40, "ssh"), "w", encoding="utf-8") as fh:
        fh.write(_SSH40)
    os.chmod(os.path.join(_BIN40, "ssh"), 0o700)  # nosec B103 - this part's own stand-in, in its own temp dir
    os.environ["PATH"] = _BIN40 + os.pathsep + _PATH40
    os.environ["P40_HOME"], os.environ["P40_VIA"] = _HOME40, os.path.join(_BIN40, "via")
    _p9_patch(_p9_core, "shell_as_game_user", _REAL_SHELL40)
    _p9_patch(_p9_core, "_run_local", _local40)
    _p9_patch(_p9_core, "_run_via_ssh_cli", _REAL_SSH_CLI40)
    # The ssh argv carries the remote command, `sudo -u <account> …` and all, and tools/nosudo_runner's
    # shim over this module's subprocess refuses any argv naming sudo — so it would never reach the
    # stand-in `ssh` above, which never runs sudo itself. The module the shim stands over, unshimmed.
    _p9_patch(_p9_core, "subprocess", _sp40)
    _p9_patch(_p9_core, "_ssh_mux_opts", lambda: [])
    _p9_patch(_p9_core, "_ssh_connect_timeout", lambda: 5)
    _p9_patch(_p9_core, "get_connection", lambda server, **kw: _Ssh40())


def _stand_ins_off40():
    """Back to the tripwires: nothing after this may reach a transport, the local one included."""
    os.environ["PATH"] = _PATH40
    os.environ.pop("P40_HOME", None)
    os.environ.pop("P40_VIA", None)
    _p9_patch(_p9_core, "_run_local", _p9_trip("local-run"))
    _arm40()


def _via40():
    """The transports used since the last call (the ssh client logs its own runs), then reset."""
    via = os.path.join(_BIN40, "via")
    try:
        with open(via, encoding="utf-8") as fh:
            ts = fh.read().split()
        os.unlink(via)
    except OSError:
        ts = []
    got = set(_VIA40) | set(ts)
    del _VIA40[:]
    return got


def _find_order40(rel):
    """The names in the folder at `rel`, in the order find prints them (no transport, no strip)."""
    p = _sp40.run(["find", os.path.join(_HOME40, rel), "-mindepth", "1", "-maxdepth", "1",  # nosec B603 B607 - find on this part's own temp dir
                   "-printf", "%f\\0"], capture_output=True, timeout=30)
    return [n.decode("utf-8", "replace") for n in p.stdout.split(b"\0")[:-1]]


def _spaced_dir40():
    """A fresh home with `<stem>` and `<stem> ` in one folder, `<stem> ` LAST in find's listing.

    `<stem>` holds "real" and `<stem> ` "spaced"; the last record is the one a strip cut. Returns
    (folder, stem), or (None, None).

    find lists a folder in its directory order — creation order or its reverse on tmpfs, name-hash
    order on ext4 — so the order is found, not assumed: stems are tried in both creation orders
    until find's own listing ends with the spaced name.
    """
    _reset40()
    for i in range(24):
        stem = "server.cfg" if i == 0 else "server%d.cfg" % i
        for spaced_first in (True, False):
            rel = "dup%d%s" % (i, "s" if spaced_first else "p")
            for name in ((stem + " ", stem) if spaced_first else (stem, stem + " ")):
                _write40(rel + "/" + name, "spaced" if name.endswith(" ") else "real")
            if _find_order40(rel)[-1:] == [stem + " "]:
                return rel, stem
            _shutil40.rmtree(os.path.join(_HOME40, rel))
    return None, None


def _rows40(a_client, sid, rel):
    """The browse route's rows for `rel`: (the path the page gives each row, its size), sorted."""
    try:
        r = a_client.get("/api/server/%d/browse" % sid, query_string={"path": rel})
    except Exception as exc:  # noqa: BLE001 - a crash fails the check that made it, not the part
        return [("raised", repr(exc)[:200])]
    # server_files.js browse(): `want ? want+'/'+e.name : e.name` — the folder asked for, plus the name.
    return sorted((rel + "/" + e.get("name", ""), e.get("size"))
                  for e in _p9_json(r).get("entries", []))


def _picked40(rows, size):
    """The path of the row showing `size` bytes: the row the user picks."""
    return next((p for p, n in rows if n == size), "(no %d-byte row)" % size)


def _spaced_via40(a_client, how, sid):
    """Through one real transport: two rows, two paths, and each row's actions reach its own file."""
    rel, stem = _spaced_dir40()
    _via40()
    check("whitespace names via %s: the premise — a folder where find lists the name that ends in "
          "a space LAST" % how, rel is not None, "no stem was listed last in 48 tries")
    if rel is None:
        return
    plain, spaced = rel + "/" + stem, rel + "/" + stem + " "
    rows = _rows40(a_client, sid, rel)
    check("file browser via %s (the real transport, its strip included): a folder whose last entry "
          "ends in a space lists both names exactly — each row's path is its own file" % how,
          rows == sorted([(plain, 4), (spaced, 6)]), repr(rows))
    ino = _ino40(plain)
    code, body = _post40(a_client, sid, _picked40(rows, 6), "picked.cfg")
    check("file browser via %s: ...Rename on the spaced row renames that file, and the real one "
          "keeps its name, inode and content" % how,
          (code, body.get("success"), _read40(rel + "/picked.cfg"), _read40(plain), _ino40(plain))
          == (200, True, "spaced", "real", ino), repr((code, body, _ls40(rel))))
    rel, stem = _spaced_dir40()
    if rel is None:
        return
    plain, spaced = rel + "/" + stem, rel + "/" + stem + " "
    rows = _rows40(a_client, sid, rel)
    up = _p9_json(a_client.post("/api/server/%d/upload-check" % sid,
                                json={"path": rel, "names": [stem + " "]}))
    check("upload check via %s: an upload onto the name that ends in a space is flagged, as the "
          "file it would replace (6 bytes)" % how,
          [(h.get("name"), h.get("size")) for h in up.get("existing", [])] == [(stem + " ", 6)],
          repr(up))
    d = a_client.post("/api/server/%d/delete-path" % sid, json={"path": _picked40(rows, 6)})
    check("file browser via %s: ...Delete on the spaced row deletes that file, and the real one "
          "stays" % how, (d.status_code, _p9_json(d).get("success"), _there40(spaced), _read40(plain))
          == (200, True, False, "real"), repr((d.status_code, _p9_json(d), _ls40(rel))))
    via = _via40()
    check("whitespace names via %s: ...the premise — every command went through %s and nothing else"
          % (how, how), via == {how}, repr(sorted(via)))


def _spaced40(a_client):
    """The whitespace-name checks, on a host of each transport."""
    hosts = (("local", _host40("p40-sp-local", "127.0.0.1", auth_method="local", is_local=True)),
             ("tailscale", _host40("p40-sp-ts", "box2.ts.net", auth_method="tailscale")),
             ("paramiko", _host40("p40-sp-key", "192.0.2.142")))
    sids = [(how, _server40(rid, _USER40, 27420 + i)) for i, (how, rid) in enumerate(hosts)]
    _real_transports40()
    try:
        servers = {"local": NS(id=94010, is_local=True, auth_method="local"),
                   "tailscale": NS(id=94011, host="box2.ts.net", port=22, username="admin",
                                   auth_method="tailscale", is_local=False, sudo_enabled=False),
                   "paramiko": NS(id=94012, host="192.0.2.142", port=22, username="admin",
                                  auth_method="key", is_local=False, sudo_enabled=False)}
        outs = {how: _p9_core.run_command(srv, "printf 'x \\n'", sudo=False)[0]
                for how, srv in servers.items()}
        check("whitespace names: the premise — each real transport strips its output (so a listing "
              "must not end with the bytes it needs)", outs == dict.fromkeys(servers, "x")
              and _via40() == set(servers), repr(outs))
        for how, sid in sids:
            _spaced_via40(a_client, how, sid)
    finally:
        _stand_ins_off40()


# ── the built command: renames exactly, never clobbers ─────────────────────────────────────────
_SRV40 = NS(id=94001, host="192.0.2.140", is_local=False, auth_method="key")
# Each stands in for `mv` and does one thing the real host could do between the check and the move.
# `gnumv` is defined to the same stand-in: the command prefers GNU's mv under that name (a uutils
# host), and a machine running this suite that has one must not slip past the stand-in.
_GNUMV40 = 'gnumv(){ mv "$@"; }; '
_RACE_FILE40 = 'mv(){ printf RACER > "${@: -1}"; command mv "$@"; }; ' + _GNUMV40
_RACE_LINK40 = 'mv(){ ln -s ../maps "${@: -1}"; command mv "$@"; }; ' + _GNUMV40
_NO_N40 = 'mv(){ command mv -T -- "${@: -2:1}" "${@: -1}"; }; ' + _GNUMV40   # ignores -n
_MV_FAILS40 = 'mv(){ return 1; }; ' + _GNUMV40


def _race40():
    """The new name appearing during the move is refused — never replaced, never moved into."""
    _reset40(_RACE_FILE40)
    got = _files40.rename_path(_SRV40, _USER40, "cfg/a.cfg", "new.cfg")
    check("rename command (real bash): a file appearing at the new name during the move is "
          "reported as taken and is NOT replaced",
          (got, _read40("cfg/new.cfg"), _read40("cfg/a.cfg"))
          == ((False, _files40.RENAME_EXISTS), "RACER", "A"), repr((got, _read40("cfg/new.cfg"))))
    _reset40(_RACE_LINK40)
    got = _files40.rename_path(_SRV40, _USER40, "cfg/a.cfg", "lnk2maps")
    check("rename command (real bash): a symlink to a folder appearing at the new name is never "
          "moved INTO (mv -T)", (got, _read40("cfg/a.cfg"), _ls40("maps"))
          == ((False, _files40.RENAME_EXISTS), "A", ["sub"]), repr((got, _ls40("maps"))))
    _reset40(_NO_N40)
    got = _files40.rename_path(_SRV40, _USER40, "cfg/a.cfg", "b.cfg")
    check("rename command (real bash): even an mv that ignores -n replaces nothing — the name is "
          "checked before the move", (got, _read40("cfg/b.cfg"), _read40("cfg/a.cfg"))
          == ((False, _files40.RENAME_EXISTS), "B", "A"), repr(got))
    _reset40(_MV_FAILS40)
    got = _files40.rename_path(_SRV40, _USER40, "cfg/a.cfg", "z.cfg")
    check("rename command (real bash): an mv the host refuses says so, in fixed text",
          (got[0], "host refused the rename" in got[1], _read40("cfg/a.cfg")) == (False, True, "A"),
          repr(got))
    marker = os.path.join(_OUTSIDE40, "gnumv-ran")
    _reset40('gnumv(){ : > %s; command mv "$@"; }; ' % marker)
    got = _files40.rename_path(_SRV40, _USER40, "cfg/a.cfg", "g.cfg")
    check("rename command (real bash): where GNU's mv is installed as gnumv (a uutils host), the "
          "move goes through it — its -n -T is the kernel's atomic no-replace",
          (got, os.path.exists(marker), _read40("cfg/g.cfg")) == ((True, "Renamed"), True, "A"),
          repr(got))


def _exact40():
    """The built command moves exactly the one name it was given, in the same folder."""
    _reset40()
    before = _snapshot40()
    ino = _ino40("cfg/a.cfg")
    got = _files40.rename_path(_SRV40, _USER40, "cfg/a.cfg", "a renamed.cfg")
    after = _snapshot40()
    want = dict(before)
    want["cfg/a renamed.cfg"] = want.pop("cfg/a.cfg")
    check("rename command (real bash): renames exactly — one name changed, same inode, the rest "
          "of the home byte for byte", got == (True, "Renamed") and after == want
          and os.stat(os.path.join(_HOME40, "cfg/a renamed.cfg")).st_ino == ino,
          repr((got, sorted(set(after.items()) ^ set(want.items()))[:4])))


def _builder_wall40():
    """rename_path refuses a bad name, an escape or a protected path on its own, sending nothing."""
    _reset40()
    got = [_files40.rename_path(_SRV40, _USER40, p, n, selfname="csgoserver")
           for p, n in (("cfg/a.cfg", "a/b"), ("cfg/a.cfg", ".."), ("../x", "y"),
                        ("lgsm", "x"), ("cfg/a.cfg", "x" * 300))]
    check("rename_path: refuses a bad name, a path out of the home and a protected path by "
          "itself (the route's checks are not its only wall), sending nothing",
          all(ok is False for ok, _m in got) and not _SHELLS40, repr((got, _SHELLS40[:1])))


# ── the account write gate, and the transports ─────────────────────────────────────────────────
def _refused_account40(a_client, rid):
    """A root-capable game account is refused exactly as delete-path refuses it."""
    _reset40()
    sid = _server40(rid, "adminacct", 27401)
    code, body = _post40(a_client, sid, "cfg/a.cfg", "z.cfg")
    d = a_client.post("/api/server/%d/delete-path" % sid, json={"path": "cfg/a.cfg"})
    check("rename route: a game account that can become root is refused (409), saying why",
          code == 409 and "can become root" in (body.get("message") or ""), repr((code, body)))
    check("rename route: ...the same accounts, the same answer, as delete-path",
          d.status_code == 409 and _p9_json(d).get("message") == body.get("message"),
          repr((d.status_code, _p9_json(d))))
    row = (_audits40() or [NS(detail="", success=None)])[-1]
    check("rename route: ...nothing is sent to the host, and the refusal is audited",
          not _SHELLS40 and row.success is False and row.detail.startswith("refused: "),
          repr((_SHELLS40[:1], row)))


def _failing_transports40():
    """Fail every transport: paramiko raises, Tailscale and local return rc -1; each records it."""
    sent = []

    def _paramiko(server):
        sent.append("paramiko")
        raise ConnectionError("Authentication failed: %s root@192.0.2.141" % _LEAK40)

    def _ts(server, command, timeout=30, sudo=None, stdin_text=None):
        sent.append("tailscale")
        return "", "ssh: connect to host box.ts.net port 22: %s timed out" % _LEAK40, -1

    def _local(cmd, timeout=30, sudo=False, stdin_text=None):
        sent.append("local")
        return "", "Command timed out (%s)" % _LEAK40, -1
    _p9_patch(_p9_core, "get_connection", _paramiko)
    _p9_patch(_p9_core, "_run_via_ssh_cli", _ts)
    # _run_local, not the _exec_local_shell under it: tools/nosudo_runner replaces _run_local
    # itself (it refuses the `sudo -u`), so a stub below it is never reached in a local run.
    _p9_patch(_p9_core, "_run_local", _local)
    return sent


def _transports40(a_client):
    """Every transport's failure is the same fixed answer, audited, with none of its own text."""
    _reset40()
    hosts = (("paramiko", _host40("p40-key", "192.0.2.141")),
             ("tailscale", _host40("p40-ts", "box.ts.net", auth_method="tailscale")),
             ("local", _host40("p40-local", "127.0.0.1", auth_method="local", is_local=True)))
    sids = {name: _server40(rid, _USER40, 27410 + i) for i, (name, rid) in enumerate(hosts)}
    _p9_patch(_p9_core, "shell_as_game_user", _REAL_SHELL40)
    sent = _failing_transports40()
    n_audit = len(_audits40())
    got = {name: _post40(a_client, sid, "cfg/a.cfg", "z.cfg") for name, sid in sids.items()}
    want = (200, {"success": False, "message": _files40.RENAME_UNCONFIRMED})
    check("rename route: the premise — each transport was really reached",
          sorted(sent) == ["local", "paramiko", "tailscale"], repr(sent))
    check("rename route: paramiko (raises), Tailscale and local (return rc -1) all give the same "
          "fixed answer", all(g == want for g in got.values()), repr(got))
    check("rename route: ...with none of the transport's own text in it",
          not any(_LEAK40 in repr(g) for g in got.values()), repr(got))
    rows = _audits40()[n_audit:]
    check("rename route: ...and each is audited as an unconfirmed failure",
          len(rows) == 3 and all(r.success is False and r.detail.endswith("(unconfirmed)")
                                 for r in rows), repr(rows))
    _p9_patch(_p9_core, "shell_as_game_user", _bash40)


# ════════════════════════════════════════════════════════════════════════════════════════════════
def _arm40():
    """part12's tripwire, again: nothing below may reach a host or run a command on this machine."""
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part40's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash40)
    _p9_patch(_sh40, "privileged_accounts", _privileged40)


def _cleanup40():
    with _p9.app_context():
        for sid in _mine40["servers"]:
            gs = db.session.get(GameServer, sid)
            if gs is not None:
                db.session.delete(gs)
        db.session.commit()
        for uid in _mine40["users"]:
            u = db.session.get(User, uid)
            if u is not None:
                db.session.delete(u)
        for gid in _mine40["groups"]:
            g = db.session.get(Group, gid)
            if g is not None:
                db.session.delete(g)
        for rid in _mine40["hosts"]:
            r = db.session.get(RemoteServer, rid)
            if r is not None:
                db.session.delete(r)
        db.session.commit()
    with _sh40._ACCOUNT_VERDICTS_LOCK:
        _sh40._ACCOUNT_VERDICTS.clear()
    _shutil40.rmtree(_HOME40, ignore_errors=True)
    _shutil40.rmtree(_OUTSIDE40, ignore_errors=True)
    _shutil40.rmtree(_BIN40, ignore_errors=True)
    os.environ["PATH"] = _PATH40


try:
    _arm40()
    _H40 = _host40("p40-host", "192.0.2.140")
    _S40 = _server40(_H40, _USER40, 27400)
    _ADMIN40, _VIEWER40 = _users40(_H40)
    _A40, _V40 = _p9_client(_ADMIN40), _p9_client(_VIEWER40)
    _hostile_names40(_A40, _S40)
    _catalog40()
    _escapes40(_A40, _S40)
    _protected40(_A40, _S40)
    _permission40(_V40, _S40)
    _plain40(_A40, _S40)
    _existing40(_A40, _S40)
    _audit_quotes40(_A40, _S40)
    _symlinks40(_A40, _S40)
    _gone40(_A40, _S40)
    _console40(_A40, _S40)
    _listing40()
    _spaced40(_A40)
    _race40()
    _exact40()
    _builder_wall40()
    _refused_account40(_A40, _H40)
    _transports40(_A40)
finally:
    _p9_restore_all()
    _cleanup40()

check("part40: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP40_START, repr(_P9_TRIPPED[_TRIP40_START:][:6]))
