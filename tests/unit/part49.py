"""Part 49 of the unit suite: two follow-ups PR #403 left open (2026-10-08).

* LinuxGSM's `logtimestamp="on"` block-buffers the console through gawk and freezes the panel's live
  console. #403 made lgsm_write_config refuse it, but the file browser's raw editor, the Config
  card's Raw tab and an upload write a WHOLE FILE and never went through that writer. They now
  refuse a file that sets it on when it lands in a LinuxGSM config — any .cfg under
  lgsm/config-lgsm/ (linuxgsm.sh sources _default, common, secrets-common, <instance> and
  secrets-<instance> from there) or lgsm/config-default/config-lgsm/ (copied over _default.cfg on
  every run) — also when reached through a symlinked folder. Rename cannot produce one: anything
  under lgsm/ is protected at both ends, and a source behind a symlinked folder is refused.
* A FAILED backup leaves LinuxGSM's partial archive behind, holding a `keep` slot. It is removed
  only when it is provably this run's (not in a listing taken just before, written since, named for
  this instance) and the run is provably over (LinuxGSM's own exit code 1-4, no lock, no tar).
  Kept on a timeout, a transport failure, a lock refusal, a failed pre-listing; a pre-existing
  archive is never touched.

HOW IT RUNS. On part12's Flask app and client helpers, as part40 does, with its tripwire re-armed:
every host command runs in a REAL bash over a throwaway home (/home/<account> rewritten to it), so
the routes, the guards and the writes are driven end to end. LinuxGSM's `backup` itself is a
stand-in that writes an archive into that home and answers with the exit code each check needs.
"""
import io
import os
import shutil as _shutil49
import tarfile as _tar49
import subprocess as _sp49  # nosec B404 - runs bash on the commands this part's code builds
import tempfile as _tf49
import time as _time49
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_so, _p9_trip)
from panel.db.models import GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import cron as _cron49
from panel.ops.ssh_manager import files as _files49
from panel.ops.ssh_manager import game as _game49
from panel.routes import _shared as _sh49
from panel.security import auth as _auth49

_TRIP49_START = len(_P9_TRIPPED)
_USER49 = "lt49"                       # the game account (csgo, so its script is csgoserver)
_SELF49 = "csgoserver"
_HOME49 = os.path.realpath(_tf49.mkdtemp(prefix="lgsm-unit-p49-home-"))
_SHELLS49 = []                         # every script sent to the "host"
_PRELUDE49 = {"text": ""}              # bash run before each command: a stand-in pgrep, say
_FAIL49 = {"when": None}               # a predicate on the script: answer it as a dead transport
_mine49 = {"hosts": [], "servers": [], "users": []}
_CFG49 = "lgsm/config-lgsm/%s/%s.cfg" % (_SELF49, _SELF49)
_ON49 = '#### Logging ####\nconsolelogging="on"\nlogtimestamp="on"\n'


def _bash49(server, user, sh, timeout=30, selfname=None, scope=False):
    """shell_as_game_user, in a real bash, with /home/<account> pointing at the throwaway home."""
    _SHELLS49.append(sh)
    when = _FAIL49["when"]
    if callable(when) and when(sh):
        return "", "SSH command timed out", -1
    script = _PRELUDE49["text"] + sh.replace("/home/" + _USER49, _HOME49)
    p = _sp49.run(["bash", "-c", script], capture_output=True, text=True,  # nosec B603 B607 - bash on this part's own command
                  timeout=60, check=False)
    return p.stdout, p.stderr, p.returncode


def _write49(rel, text, mtime=None):
    path = os.path.join(_HOME49, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def _read49(rel):
    try:
        with open(os.path.join(_HOME49, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _reset49(prelude=""):
    for name in os.listdir(_HOME49):
        p = os.path.join(_HOME49, name)
        if os.path.islink(p) or not os.path.isdir(p):
            os.unlink(p)
        else:
            _shutil49.rmtree(p)
    _write49(_CFG49, 'maxplayers="16"\n')
    _write49("lgsm/config-lgsm/%s/common.cfg" % _SELF49, "")
    _write49("lgsm/config-default/config-lgsm/%s/_default.cfg" % _SELF49, 'logtimestamp="off"\n')
    _write49("serverfiles/notes.txt", "notes\n")
    os.symlink("lgsm/config-lgsm/" + _SELF49, os.path.join(_HOME49, "cfglink"))
    del _SHELLS49[:]
    _PRELUDE49["text"] = prelude
    _FAIL49["when"] = None
    with _sh49._ACCOUNT_VERDICTS_LOCK:
        _sh49._ACCOUNT_VERDICTS.clear()


def _post49(client, url, **kw):
    """(status, json), or (None, {"raised": ...}) when the request raised: a check FAILS by name."""
    try:
        r = client.post(url, **kw)
    except Exception as exc:  # noqa: BLE001 - a crash fails the check that made it, not the part
        return None, {"raised": repr(exc)[:200]}
    return r.status_code, _p9_json(r)


def _refused49(body):
    return body.get("success") is False and "freezes the panel's live console" in (
        body.get("message") or "")


# ── logtimestamp: which text turns it on ────────────────────────────────────────────────────────
def _detector49():
    on = ['logtimestamp="on"', "logtimestamp=on", "logtimestamp='on'", "LOGTIMESTAMP=On",
          '  logtimestamp = "on"  ', 'logtimestamp="on" # stamp it', "export logtimestamp=on",
          'a=1; logtimestamp="o"n', "logtimestamp=$STAMP", 'x="a #b"; logtimestamp=on',
          'logtimestamp="on"\r']
    off = ['# logtimestamp="on"', '#logtimestamp=on', '   # logtimestamp="on"', 'logtimestamp="off"',
           "logtimestamp=OFF", 'logtimestamp=""', 'logtimestampformat="on"', "mylogtimestamp=on",
           'echo "x" # logtimestamp=on', 'consolelogging="on"']
    wrong = [t for t in on if not _files49._rawlts_turns_on(t)]
    wrong += [t for t in off if _files49._rawlts_turns_on(t)]
    wrong += [t for t in on if not _files49._rawlts_turns_on(t.encode())]
    check("raw cfg: logtimestamp set on is found quoted or not, in any case, with spaces, exported, "
          "split by quotes or behind a ; — and a commented-out line, 'off', '' and "
          "logtimestampformat are not",
          not wrong, repr(wrong))


# ── logtimestamp: the three write routes ────────────────────────────────────────────────────────
def _route_editor49(a_client, sid):
    """The raw editor refuses a LinuxGSM cfg that sets logtimestamp on, wherever it sits."""
    url = "/api/server/%d" % sid
    _reset49()
    code, body = _post49(a_client, url + "/file", json={"path": _CFG49, "content": _ON49})
    check("raw editor: a LinuxGSM instance cfg that sets logtimestamp on is refused, with the reason",
          code == 200 and _refused49(body), repr((code, body)))
    check("raw editor: ...and the file on the host is unchanged",
          _read49(_CFG49) == 'maxplayers="16"\n', repr(_read49(_CFG49)))
    for rel in ("lgsm/config-lgsm/%s/common.cfg" % _SELF49,
                "lgsm/config-lgsm/%s/secrets-%s.cfg" % (_SELF49, _SELF49),
                "lgsm/config-default/config-lgsm/%s/_default.cfg" % _SELF49):
        _reset49()
        before = _read49(rel)
        code, body = _post49(a_client, url + "/file", json={"path": rel, "content": _ON49})
        check("raw editor: %s with logtimestamp on is refused and left as it was" % rel,
              _refused49(body) and _read49(rel) == before, repr((code, body, _read49(rel))))
    _reset49()
    code, body = _post49(a_client, url + "/file", json={"path": "cfglink/common.cfg", "content": _ON49})
    check("raw editor: a LinuxGSM cfg reached through a symlinked folder is refused too (the host "
          "resolves it)",
          _refused49(body) and _read49("lgsm/config-lgsm/%s/common.cfg" % _SELF49) == "",
          repr((code, body)))


def _route_uploads49(a_client, sid):
    """The Config card's Raw tab and an upload refuse it too."""
    url = "/api/server/%d" % sid
    _reset49()
    code, body = _post49(a_client, url + "/config", json={"raw": _ON49})
    check("Config card Raw tab: logtimestamp on is refused, the cfg unchanged",
          _refused49(body) and _read49(_CFG49) == 'maxplayers="16"\n', repr((code, body)))
    for overwrite in ("1", "0"):
        _reset49()
        code, body = _post49(a_client, url + "/upload", content_type="multipart/form-data", data={
            "path": "lgsm/config-lgsm/" + _SELF49, "overwrite": overwrite,
            "file": (io.BytesIO(_ON49.encode()), "secrets-common.cfg")})
        check("upload (overwrite=%s): a new secrets-common.cfg that sets logtimestamp on is refused "
              "and never written" % overwrite,
              _refused49(body) and _read49("lgsm/config-lgsm/%s/secrets-common.cfg" % _SELF49) is None,
              repr((code, body)))
    _reset49()
    code, body = _post49(a_client, url + "/upload", content_type="multipart/form-data", data={
        "path": "lgsm/config-lgsm/" + _SELF49, "overwrite": "1",
        "file": (io.BytesIO(_ON49.encode()), _SELF49 + ".cfg")})
    check("upload: replacing the instance cfg with one that sets logtimestamp on is refused",
          _refused49(body) and _read49(_CFG49) == 'maxplayers="16"\n', repr((code, body)))


def _route_controls49(a_client, sid):
    """What must still save, and what is refused when the host cannot say."""
    url = "/api/server/%d" % sid
    for what, content in (("logtimestamp=\"off\"", 'logtimestamp="off"\n'),
                          ("a commented-out logtimestamp=\"on\"", '# logtimestamp="on"\nport="1"\n')):
        _reset49()
        code, body = _post49(a_client, url + "/file", json={"path": _CFG49, "content": content})
        check("raw editor: a LinuxGSM cfg with %s still saves (control)" % what,
              (code, body.get("success"), _read49(_CFG49)) == (200, True, content), repr((code, body)))
    _reset49()
    code, body = _post49(a_client, url + "/file", json={"path": "serverfiles/notes.txt", "content": _ON49})
    check("raw editor: a file outside LinuxGSM's config trees may say logtimestamp=on (control)",
          (code, body.get("success"), _read49("serverfiles/notes.txt")) == (200, True, _ON49),
          repr((code, body)))
    _reset49()
    _FAIL49["when"] = lambda sh: "__RAWLTS_" in sh
    code, body = _post49(a_client, url + "/file", json={"path": "serverfiles/notes.txt", "content": _ON49})
    check("raw editor: when the host cannot say whether the target is a LinuxGSM cfg, a file that "
          "sets logtimestamp on is NOT saved",
          body.get("success") is False and "could not be asked" in (body.get("message") or "")
          and _read49("serverfiles/notes.txt") == "notes\n", repr((code, body)))


def _route_rename49(a_client, sid):
    url = "/api/server/%d" % sid
    _reset49()
    code2, body2 = _post49(a_client, url + "/rename-path",
                           json={"path": "cfglink/common.cfg", "new_name": "secrets-common.cfg"})
    check("rename: cannot produce a LinuxGSM cfg — its tree is protected, and a symlinked folder "
          "into it is refused (why rename needs no logtimestamp check)",
          body2.get("success") is False
          and _read49("lgsm/config-lgsm/%s/secrets-common.cfg" % _SELF49) is None,
          repr((code2, body2)))


# ── partial archives after a failed backup ──────────────────────────────────────────────────────
_BK49 = "lgsm/backup"
_OLD49 = "%s-2026-01-01-000000.tar.zst" % _SELF49


def _lgsm49(rc, out="", lock=False, archive=True, err=""):
    """A stand-in run_as_game_user: LinuxGSM's backup writes its archive, then answers `rc`."""
    made = {}

    def _run(server, user, action, timeout=30, selfname=None, answers=None, tee_log=False):
        if archive:
            made["name"] = "%s-%s.tar.zst" % (_SELF49, _time49.strftime("%Y-%m-%d-%H%M%S"))
            _write49(os.path.join(_BK49, made["name"]), "partial")
        if lock:
            _write49("lgsm/lock/backup.lock", "1")
        return out, err, rc
    return _run, made


def _backup49(rc, **kw):
    """Run run_game_backup over the throwaway home: (result, the archive LinuxGSM wrote, listing)."""
    run, made = _lgsm49(rc, **{k: v for k, v in kw.items() if k in ("out", "lock", "archive", "err")})
    _p9_patch(_p9_core, "run_as_game_user", run)
    res = _game49.run_game_backup(NS(id=49, host="192.0.2.149"), _USER49, _SELF49, keep=3, force=True)
    return res, made.get("name"), sorted(os.listdir(os.path.join(_HOME49, _BK49)))


def _nth_listing49(k):
    """A _FAIL49 predicate: the k-th partial-archive listing (1 = before the run) gets no answer."""
    seen = []

    def _when(sh):
        if _game49._BKPART_DONE not in sh:
            return False
        seen.append(sh)
        return len(seen) == k
    return _when


def _fresh_backups49(prelude=""):
    _reset49(prelude)
    _write49(os.path.join(_BK49, _OLD49), "good", mtime=_time49.time() - 86400)


def _partials49():
    """A clean failure's own partial archive is removed; every other exit code keeps it."""
    _fresh_backups49()
    res, name, ls = _backup49(1, out="tar: write error: No space left on device")
    check("backup: after a clean FAILURE (LinuxGSM exit 1) its partial archive is removed, the "
          "older backup kept",
          name is not None and ls == [_OLD49], repr((res, name, ls)))
    check("backup: ...and the job's message says so, naming it",
          res[0] is False and "Removed the partial archive it left (%s)" % name in res[1], repr(res))

    for why, rc in (("a timeout or dead transport (-1)", -1), ("ssh's own failure (255)", 255),
                    ("a killed run (137)", 137), ("a success (0)", 0)):
        _fresh_backups49()
        res, name, ls = _backup49(rc, out="something")
        check("backup: the archive is KEPT after %s" % why,
              name in ls and _OLD49 in ls and "Removed the partial" not in res[1], repr((res, ls)))


def _partials_lock49():
    _fresh_backups49()
    res, name, ls = _backup49(1, out="Lockfile found: Backup is currently running")
    check("backup: an archive that appears during a LOCK-REFUSED run is kept (it is another run's)",
          name in ls and "lock" in res[1].lower() and "Removed" not in res[1], repr((res, ls)))
    n_sent = len(_SHELLS49)
    check("backup: ...and the cleanup refuses a lock-refused run by itself too, asking nothing",
          _game49._bkpart_cleanup(None, _USER49, _SELF49, (0, {}), 1, True) == ""
          and len(_SHELLS49) == n_sent, repr(_SHELLS49[n_sent:]))


def _partials_listing49():
    _fresh_backups49()
    _FAIL49["when"] = _nth_listing49(1)
    res, name, ls = _backup49(1, out="tar: error")
    check("backup: when the listing BEFORE the run failed, nothing is removed",
          name in ls and "Removed" not in res[1], repr((res, ls)))
    # The dangerous shape: a run that failed before writing anything, so the only archive "new"
    # against an empty before-listing is the good backup already there.
    _fresh_backups49()
    _FAIL49["when"] = _nth_listing49(1)
    res, name, ls = _backup49(1, out="tar: error", archive=False)
    check("backup: ...and an unreadable before-listing is never read as 'there was nothing', which "
          "would make the existing good backup this run's",
          ls == [_OLD49] and "Removed" not in res[1], repr((res, ls)))

    _fresh_backups49()
    _FAIL49["when"] = _nth_listing49(2)
    res, name, ls = _backup49(1, out="tar: error")
    check("backup: when the listing AFTER the run failed, nothing is removed",
          name in ls and "Removed" not in res[1], repr((res, ls)))


def _partials_busy49():
    _fresh_backups49()
    res, name, ls = _backup49(1, out="tar: error", lock=True)
    check("backup: with a backup.lock still present at removal time, the archive is kept",
          name in ls, repr((res, ls)))

    _fresh_backups49(prelude="pgrep() { return 0; }; ")
    res, name, ls = _backup49(1, out="tar: error")
    check("backup: with a tar still running as the account at removal time, the archive is kept",
          name in ls, repr((res, ls)))


def _partials_not_ours49():
    _fresh_backups49()
    path = os.path.join(_HOME49, _BK49, _OLD49)

    def _touch_old(server, user, action, **_k):
        os.utime(path, None)            # the pre-existing archive is written to during the run
        return "tar: error", "", 1
    _p9_patch(_p9_core, "run_as_game_user", _touch_old)
    res = _game49.run_game_backup(NS(id=49), _USER49, _SELF49, keep=3, force=True)
    check("backup: a PRE-EXISTING archive is never removed, even one written to during the run",
          os.path.exists(path) and "Removed" not in res[1], repr(res))

    _fresh_backups49()
    _write49(os.path.join(_BK49, "other-2026-01-01-000000.tar.zst"), "x")

    def _other(server, user, action, **_k):
        _write49(os.path.join(_BK49, "otherserver-2099-01-01-000000.tar.zst"), "x")
        return "tar: error", "", 1
    _p9_patch(_p9_core, "run_as_game_user", _other)
    _game49.run_game_backup(NS(id=49), _USER49, _SELF49, keep=3, force=True)
    check("backup: a new archive not named for this instance is not this run's, and is kept",
          os.path.exists(os.path.join(_HOME49, _BK49, "otherserver-2099-01-01-000000.tar.zst")), "")


def _partials_doubt49():
    _fresh_backups49()

    def _two(server, user, action, **_k):
        for n in ("%s-2026-10-08-000001.tar.zst" % _SELF49, "%s-2026-10-08-000002.tar.zst" % _SELF49):
            _write49(os.path.join(_BK49, n), "x")
        return "tar: error", "", 1
    _p9_patch(_p9_core, "run_as_game_user", _two)
    _game49.run_game_backup(NS(id=49), _USER49, _SELF49, keep=3, force=True)
    check("backup: two new archives after one failed run is not understood, and both are kept",
          len(os.listdir(os.path.join(_HOME49, _BK49))) == 3, repr(os.listdir(os.path.join(_HOME49, _BK49))))

    # The removal re-checks the mtime ON THE HOST: an archive older than the run start stays.
    _fresh_backups49()
    _write49(os.path.join(_BK49, "%s-2026-10-08-000003.tar.zst" % _SELF49), "x",
             mtime=_time49.time() - 3600)
    check("backup: the removal itself keeps an archive last written before the run started",
          _game49._bkpart_remove(None, _USER49, "%s-2026-10-08-000003.tar.zst" % _SELF49,
                                 int(_time49.time()) - 60) is False
          and os.path.exists(os.path.join(_HOME49, _BK49, "%s-2026-10-08-000003.tar.zst" % _SELF49)), "")


# ── exit 0 is not proof: the archive must be whole ──────────────────────────────────────────────
# LinuxGSM exits 0 after a failed tar when it restarts the server it stopped (game.py's note above
# _BKVERIFY_FAIL_RE cites the lines). Four good old backups and keep=3: a success prunes the oldest,
# so "olds all still there" is what a refused success looks like.
_OLDS49 = ["%s-2026-01-0%d-000000.tar.gz" % (_SELF49, d) for d in (1, 2, 3, 4)]


def _tgz49(rel, truncate=False):
    """A real .tar.gz at `rel` in the home (a few files, so it compresses to some KB); cut short."""
    src = os.path.join(_HOME49, "serverfiles")
    os.makedirs(src, exist_ok=True)
    for i in range(4):
        with open(os.path.join(src, "f%d.bin" % i), "wb") as fh:
            fh.write(os.urandom(8192))
    path = os.path.join(_HOME49, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _tar49.open(path, "w:gz") as tf:
        tf.add(src, arcname="serverfiles")
    if truncate:
        with open(path, "r+b") as fh:
            fh.truncate(os.path.getsize(path) // 2)


def _verify_run49(rc, out, write):
    """Run run_game_backup with a stand-in LinuxGSM that calls `write(name)` and answers rc/out."""
    _reset49()
    for i, n in enumerate(_OLDS49):
        _tgz49(os.path.join(_BK49, n))
        os.utime(os.path.join(_HOME49, _BK49, n), (_time49.time() - 86400 * (10 - i),) * 2)
    name = "%s-%s.tar.gz" % (_SELF49, _time49.strftime("%Y-%m-%d-%H%M%S"))

    def _run(server, user, action, **_k):
        if write:
            write(os.path.join(_BK49, name))
        return out.replace("NAME", name), "", rc
    _p9_patch(_p9_core, "run_as_game_user", _run)
    res = _game49.run_game_backup(NS(id=49), _USER49, _SELF49, keep=3, force=True)
    return res, name, sorted(os.listdir(os.path.join(_HOME49, _BK49)))


_DONE49 = "[  OK  ] Backup %s: Completed: \x1b[3mNAME\x1b[0m, total size 40K\n" % _SELF49
_TARFAIL49 = ("[ .... ] Backup %s: Backup (1G) NAME, in progress ...\r ... \x1b[31mFAIL\x1b[0m\n"
              "[ FAIL ] Backup %s: Starting backup\n[  OK  ] Starting %s: server\n"
              % (_SELF49, _SELF49, _SELF49))


def _verify49():
    res, name, ls = _verify_run49(0, _TARFAIL49, lambda rel: _tgz49(rel, truncate=True))
    check("backup verify: exit 0 WITH LinuxGSM's own tar FAIL lines is a failure, and nothing old is "
          "pruned", res[0] is False and all(o in ls for o in _OLDS49), repr((res, ls)))
    check("backup verify: ...and its partial archive is removed (the run did end), saying so",
          name not in ls and "Removed the partial archive" in res[1], repr((res, ls)))
    for what, write, why in (
            ("an EMPTY archive", lambda rel: _write49(rel, ""), "the archive is empty"),
            ("a truncated (corrupt) archive", lambda rel: _tgz49(rel, truncate=True),
             "does not read to the end"),
            ("no archive at all", None, "could not be found")):
        res, name, ls = _verify_run49(0, _DONE49 if write else "", write)
        check("backup verify: exit 0 with %s is NOT confirmed: reported as such (%s), nothing pruned"
              % (what, why),
              res[0] is False and "not confirmed: " in res[1] and why in res[1]
              and all(o in ls for o in _OLDS49), repr((res, ls)))


def _verify_good49():
    """Controls: a whole archive is still a success and still prunes; the read is bounded."""
    res, name, ls = _verify_run49(0, _DONE49, _tgz49)
    check("backup verify: exit 0 with a whole archive is 'Backed up' and still prunes to keep=3 "
          "(control)", res[0] is True and ls == sorted(_OLDS49[2:] + [name]), repr((res, ls)))
    res, name, ls = _verify_run49(0, "", _tgz49)
    check("backup verify: ...also when LinuxGSM's output does not name it (found by the listings)",
          res[0] is True and ls == sorted(_OLDS49[2:] + [name]), repr((res, ls)))
    sent = []
    _p9_patch(_p9_core, "shell_as_game_user",
              lambda server, user, sh, timeout=30, **k: (sent.append((sh, timeout)), ("", "", -1))[1])
    why = _game49._bkverify_archive(None, _USER49, _OLDS49[0], None)
    _p9_patch(_p9_core, "shell_as_game_user", _bash49)
    check("backup verify: the archive read is bounded — `timeout 1700` on the host inside an 1800 s "
          "transport timeout — and an unanswered host is not a confirmation",
          len(sent) == 1 and "timeout 1700 " in sent[0][0] and sent[0][1] == 1800
          and why == "the host could not be asked", repr((sent, why)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
def _arm49():
    """part12's tripwire: nothing below may reach a host or run a command on this machine."""
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part49's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash49)
    _p9_patch(_sh49, "privileged_accounts", lambda remote, users: {})


def _setup49():
    with _p9.app_context():
        r = RemoteServer(name="p49-host", host="192.0.2.149", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p49-" + _USER49, short_name=_USER49, game_type="csgo",
                        port=27490, installed=True, status="offline")
        admin = User(username="p49_admin", password_hash=_auth49.hash_password("Str0ng!passw0rd-p49"),
                     display_name="p49 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine49["hosts"].append(r.id)
        _mine49["servers"].append(gs.id)
        _mine49["users"].append(admin.id)
        return gs.id, admin.id


def _cleanup49():
    with _p9.app_context():
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine49[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    with _sh49._ACCOUNT_VERDICTS_LOCK:
        _sh49._ACCOUNT_VERDICTS.clear()
    _shutil49.rmtree(_HOME49, ignore_errors=True)


try:
    _arm49()
    _detector49()
    _S49, _ADMIN49 = _setup49()
    _A49 = _p9_client(_ADMIN49)
    for _step49 in (_route_editor49, _route_uploads49, _route_controls49, _route_rename49):
        _step49(_A49, _S49)
    _p9_patch(_cron49, "_ensure_backup_headroom", lambda *a, **k: "")
    _p9_patch(_cron49, "backup_disk_info", lambda *a, **k: {"free": 0, "total": 0})
    for _step49 in (_partials49, _partials_lock49, _partials_listing49, _partials_busy49,
                    _partials_not_ours49, _partials_doubt49, _verify49, _verify_good49):
        _step49()
finally:
    _p9_restore_all()
    _cleanup49()

check("part49: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP49_START, repr(_P9_TRIPPED[_TRIP49_START:][:6]))
