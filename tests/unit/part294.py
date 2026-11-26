"""Part 294 of the unit suite: review pass 36's runtime fixes.

1. The backup disk check measures the filesystem that holds ~/lgsm/backup (a symlink to another disk is
   how backups are moved), falling back to the home while the folder does not exist: the headroom prune
   and the pre-flight refusal no longer act on the home's free space.
2. A backup's database dump (the sweep, Back up now and the Backup button all dump through
   dump_for_backup) holds each database as the Databases tab's own dump does: one being restored is left
   out and said, and a restore asked for while the backup dumps it is refused (409).
3. A restore cut by a signal while it removes the aside copy leaves its state saying done, so the
   recovery that settles the lost answer reports the restore as completed, not "nothing was changed".
4. A retry of an archive whose earlier restore could not be undone (ROLLBACKFAIL) is refused before the
   staging step, which would have deleted the folder holding the server's own files.
5. A Kick or Ban that has to look the player up on the console (a list from gamedig), and a B3 Kick or
   Warn, say the console could not be read when it was not, instead of "couldn't find that player".
6. A Source/GoldSrc Kick by name is refused when the console lists two players with that name (the
   engine kicks the first match, and Steam names are not unique).
7. A settings save rewrites only the lines it changes: a Latin-1 byte and a U+2028 or form feed inside
   another value come back byte for byte.
8. The game-config form does not show (or save) a cfg field that a later line the form does not read
   as a field sets again: two commands on one line, or a quoted key.
9. The maintenance menu's Backup is refused while another backup of the server runs, and holds the
   server from before its database dump, so a sweep or "Back up now" sees it in that window.
10. Markup injected into a page cannot become a CSRF-valid form post: every POST form a template draws
    carries the token the server rendered, panel.js no longer gives every form in the page one, an ajax
    form without a token is not sent, and the dispatcher refuses the internal _r<digits> helpers.
11. The database browser's cut value in a keyless row sends only an editor to the SQL box; anyone else
    (no Edit database data, so no SQL box) is told the table has no key to read the value by.
12. A BlueMap Update removes the old client jar (and, after a new image, the old page) only once the new
    image and the record are in place: a failed pull leaves the running BlueMap what it uses.
13. An add-on whose new image carries the same version label as the installed one (B3 after a base image
    or requirements change) is offered as "a newer version", not as the version it already runs.
14. B3's namesake read selects the stored names the identity check can mean (a target stored as "^ABob"
    finds "Bob"), and no longer every name that merely holds the target's ("Grace" for "Ace").

HOW IT RUNS. Stand-in transports answer every host call; shell text the panel builds is run by bash over
this part's scratch directory, with stand-ins for the host tools it calls. Nothing reaches a host, /etc
or data/.
"""
import base64 as _b64_294
import glob as _glob294
import random as _random294
import json as _json294
import os
import re as _re294
import shutil as _shutil294
import subprocess as _sp294  # nosec B404 - bash over this part's own scratch files
import tempfile as _tf294
import time as _time294
from types import SimpleNamespace as _NS294

from unit.part01 import _root, check, eq, skip
from unit.part47 import _cut47, _node47
from unit.part272 import _bm272, _drop272, _fixture272, _getter272, _host272, _mojang272, _probe_out272, _writes272
from unit.part278 import _act278, _fixture278, _post278, _socket_stub278
from unit.part190 import _NAME190, _U190, _UNDO190, _Sb190, _missing190
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9Thread, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_threading)
from panel.core.config import encrypt_secret as _enc294
from panel.db.models import GameDatabase as _GD294, RemoteServer as _RS294, db as _db294
from panel.ops.ssh_manager import _core as _core294, cron as _cron294, files as _files294, game as _game294
from panel.routes import addons as _ra294
from panel.routes import _shared as _sh294, databases as _dbr294, server_detail as _sd294, server_files as _sf294
from panel.services import b3_players as _b3p294, game_restore as _grs294, lgsm_players as _lgp294

_TMP294 = _tf294.mkdtemp(prefix="p294-")


def _bash294(script, env=None):
    """(stdout, stderr, rc) of `script` run by bash in this part's scratch directory."""
    # nosec B603 B607 - fixed argv: bash over a script this part wrote, in its own scratch directory
    p = _sp294.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, cwd=_TMP294,  # nosec B603 B607
                   env=dict(os.environ, **(env or {})), check=False)
    return p.stdout, p.stderr, p.returncode


# ── 1. The backup disk check reads the backup folder's filesystem ─────────────────────────────────
_GB294 = 1024 ** 3
_HOME294 = os.path.join(_TMP294, "home")
# df stand-in: the home's filesystem has 3 GB free, the disk ~/lgsm/backup links to has 900 GB.
_DF294 = (r'df() { local p="${@: -1}" f; p=$(readlink -f -- "$p");'
          r' case "$p" in "$BIGDISK294"*) f=966367641600;; *) f=3221225472;; esac;'
          r' printf "Filesystem 1B-blocks Used Available Capacity Mounted on\n/dev/x 1099511627776 0 %s 1%% /\n" "$f"; }; ')
_BK_LIST294 = "".join("F\tgsu294-2026-11-2%d-010000.tar.zst\t%d\t17000%d0000\n" % (d, 5 * _GB294, d)
                      for d in range(4)) + _cron294._BACKUP_LIST_DONE + "\n"


def _host294(_server, cmd, *_a, **_k):
    """Answer the listing; run any df command through bash with the home moved under scratch."""
    if _cron294._BACKUP_LIST_DONE in cmd:
        return _BK_LIST294, "", 0
    if "df -PB1" not in cmd:
        return "", "unexpected", 1
    return _bash294(_DF294 + cmd.replace("/home/", _HOME294 + "/"),
                    env={"BIGDISK294": os.path.join(_TMP294, "bigdisk")})


def _disk_case294(linked):
    """(refusal, deleted names, card disk) for gsu294 with ~/lgsm/backup linked to the big disk or absent."""
    _shutil294.rmtree(_HOME294, ignore_errors=True)
    os.makedirs(os.path.join(_HOME294, "gsu294", "lgsm"))
    os.makedirs(os.path.join(_TMP294, "bigdisk"), exist_ok=True)
    if linked:
        os.symlink(os.path.join(_TMP294, "bigdisk"), os.path.join(_HOME294, "gsu294", "lgsm", "backup"))
    deleted = []
    try:
        _p9_patch(_core294, "run_command", _host294)
        _p9_patch(_core294, "shell_as_game_user", lambda s, u, sh, **k: _host294(s, sh))
        _p9_patch(_cron294, "delete_game_backup", lambda s, u, name: deleted.append(name) or True)
        note = _cron294._ensure_backup_headroom(object(), "gsu294", 3)
        refusal = _game294._backup_space_refusal(object(), "gsu294", note)
        return refusal, deleted, _cron294.backup_disk_info(object(), "gsu294")
    finally:
        _p9_restore_all()


_ref294, _del294, _disk294 = _disk_case294(linked=True)
check("backup disk: a ~/lgsm/backup linked to a big disk is measured there (900 GB free, not the home's 3 GB)",
      _disk294.get("free") == 966367641600, repr(_disk294))
check("backup disk: with the backup folder on a big disk, the headroom prune deletes nothing", _del294 == [], repr(_del294))
check("backup disk: with the backup folder on a big disk, the pre-flight check does not refuse the backup",
      _ref294 is None, repr(_ref294))
_ref294, _del294, _disk294 = _disk_case294(linked=False)
check("backup disk (control): no backup folder yet reads the home's filesystem", _disk294.get("free") == 3221225472, repr(_disk294))
check("backup disk (control): a tight home with no backup folder still refuses the backup",
      bool(_ref294) and "Not enough disk space" in _ref294, repr(_ref294))
_sent294 = []
try:
    _p9_patch(_core294, "run_command", lambda *a, **k: _sent294.append(a) or ("", "", 1))
    _p9_patch(_core294, "shell_as_game_user", lambda *a, **k: _sent294.append(a) or ("", "", 1))
    _disk294 = _cron294.backup_disk_info(object(), "root")
finally:
    _p9_restore_all()
check("backup disk: an unsafe account name sends nothing and reads zeros",
      _disk294 == {"free": 0, "total": 0} and not _sent294, repr((_disk294, _sent294)))


# ── 2. A backup's database dump holds each database ───────────────────────────────────────────────
def _db_rows294(sid, names):
    with _p9.app_context():
        rows = [_GD294(remote_id=P9_HOST, game_server_id=sid, name=n, secret=_enc294("Zp294" + "q" * 27),
                       auth_plugin="mysql_native_password", max_conn=10, created_by="p294") for n in names]
        _db294.session.add_all(rows)
        _db294.session.commit()
        return [r.id for r in rows]


def _backup_dump294(sid, account):
    with _p9.app_context():
        return _dbr294.dump_for_backup(sid, _db294.session.get(_RS294, P9_HOST), account)


_bd294 = {}
try:
    _p9_arm(who="part294")
    _sid294 = _p9_new_server(P9_HOST, "p294db", "pmc", 25594, name="p294 db")
    _rid294 = _db_rows294(_sid294, ("gs_p294a", "gs_p294b"))[0]
    _api294 = "/api/server/%d/databases/%d" % (_sid294, _rid294)
    _adm294 = _p9_client(P9_ADMIN)
    _hd294 = _NS294(auth_mode="socket")
    _p9_patch(_dbr294, "_restore_target", lambda gs, r: _hd294)
    _p9_patch(_dbr294, "_host_row", lambda remote_id: _hd294)
    _p9_patch(_dbr294, "game_account_write_refusal", lambda remote, user, **k: None)
    _p9_patch(_dbr294, "_forget_data", lambda db_id: None)
    _dumped294 = []

    def _dump294(remote, hostdb, dest, account, names):
        _dumped294.append(list(names))
        if _bd294.pop("post_nested", False):
            _bd294["nested"] = _adm294.post(_api294 + "/restore", json={"confirm": "gs_p294a"})
        return True, ""

    def _restore294(remote, hostdb, account, n, pw):
        _bd294["during_restore"] = (_backup_dump294(_sid294, "p294db"), list(_dumped294))
        return True, ""
    _p9_patch(_dbr294._dbs, "dump", _dump294)
    _p9_patch(_dbr294._dbs, "restore", _restore294)
    _bd294["restore"] = _adm294.post(_api294 + "/restore", json={"confirm": "gs_p294a"})
    _dumped294.clear()
    _bd294["post_nested"] = True
    _bd294["alone"] = _backup_dump294(_sid294, "p294db")
    _bd294["alone_dumped"] = list(_dumped294)
finally:
    _p9_restore_all()
_note294, _while294 = _bd294.get("during_restore") or (None, None)
check("backup dump: a database being restored is left out of the backup's dump and said",
      _while294 == [["gs_p294b"]] and "gs_p294a is being dumped, restored or deleted right now." in str(_note294 or ""),
      repr((_note294, _while294)))
eq("backup dump: the restore it overlapped still completes", getattr(_bd294.get("restore"), "status_code", 0), 200)
_nested294 = _bd294.get("nested")
check("backup dump: a restore asked for while the backup dumps that database is refused (409, being dumped)",
      _nested294 is not None and _nested294.status_code == 409
      and "being dumped" in _p9_json(_nested294).get("message", ""), repr(_nested294))
check("backup dump (control): with nothing else running, every database is dumped in one call and nothing is said",
      _bd294.get("alone") is None and _bd294.get("alone_dumped") == [["gs_p294a", "gs_p294b"]], repr(_bd294))


# ── 3. A restore cut while removing the aside copy is settled as done ─────────────────────────────
def _restore_cut294():
    """(restored file, outcome the recovery read, work files left after it) for a TERM after "done"."""
    sb = _Sb190()
    beat = _grs294.HEARTBEAT
    _grs294.HEARTBEAT = 1
    try:
        ready = sb.vet()[1][1]
        with open(os.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        rs = _grs294.restore_script(_U190, _U190, _NAME190, ready["t0"], ready["need"], _UNDO190, busy_polls=1,
                                    members=ready["members"])
        cut = rs.replace('echo done > "$st"; then ', 'echo done > "$st"; then kill -TERM $$; ', 1)
        sb.run(cut)
        outcome = _grs294.recover_outcome(sb.run(_grs294.recover_script(_U190, ready["t0"]))[0])
        wd = os.path.join(sb.home, _grs294.WORK_DIR)
        left = sorted(f for f in (os.listdir(wd) if os.path.isdir(wd) else []) if f != "panel-restore.lock")
        return cut != rs, sb.read("serverfiles/world/region/r.0.mca"), outcome, left
    finally:
        _grs294.HEARTBEAT = beat
        sb.gone()


if _missing190:
    skip("game restore: a signal during the clean-up is settled as a completed restore", "missing tools: %s" % _missing190)
else:
    eq("game restore: a signal during the clean-up is settled as a completed restore", _restore_cut294(),
       (True, "world v1", "done", []))


# ── 4. A retry after ROLLBACKFAIL keeps the aside folder ──────────────────────────────────────────
def _retry_after_fail294(failed):
    """(restore_outcome, aside file kept, live file unchanged) for a retry with or without $st.failed."""
    sb = _Sb190()
    beat = _grs294.HEARTBEAT
    _grs294.HEARTBEAT = 1
    try:
        ready = sb.vet()[1][1]
        with open(os.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        wd = os.path.join(sb.home, _grs294.WORK_DIR)
        aside = os.path.join(wd, "panel-restore-old-%d" % ready["t0"])
        os.makedirs(aside)
        with open(os.path.join(aside, "own.txt"), "w") as f:
            f.write("the server's own files")
        if failed:
            open(os.path.join(wd, "panel-restore-state-%d.failed" % ready["t0"]), "w").close()
        rs = _grs294.restore_script(_U190, _U190, _NAME190, ready["t0"], ready["need"], _UNDO190, busy_polls=1,
                                    members=ready["members"])
        out, rc = sb.run(rs)
        return (_grs294.restore_outcome(out, rc)[0], os.path.isfile(os.path.join(aside, "own.txt")),
                sb.read("serverfiles/world/region/r.0.mca"))
    finally:
        _grs294.HEARTBEAT = beat
        sb.gone()


if _missing190:
    skip("game restore: a retry after a failed undo keeps the aside folder", "missing tools: %s" % _missing190)
else:
    _st294, _kept294, _live294 = _retry_after_fail294(failed=True)
    check("game restore: a retry after a failed undo is refused and keeps the folder holding the server's own files",
          (_st294, _kept294, _live294) == ("refused", True, "world v2"), repr((_st294, _kept294, _live294)))
    _st294, _kept294, _live294 = _retry_after_fail294(failed=False)
    check("game restore (control): with no failed undo on record the same run restores the archive",
          (_st294, _live294) == ("done", "world v1"), repr((_st294, _kept294, _live294)))


# ── 5. An unread console is not "no such player" ──────────────────────────────────────────────────
def _moderate294(listed, game_type, action):
    """moderate()'s answer and the console lines it sent, with the console list answering `listed`."""
    sent = []
    try:
        _p9_patch(_game294, "console_player_list", lambda *a, **k: listed)
        _p9_patch(_core294, "send_console_command", lambda s, u, cmd, **k: sent.append(cmd) or ("", "", 0))
        return _game294.moderate(object(), "p294m", game_type, action, target="Bob"), sent
    finally:
        _p9_restore_all()


_unread294 = [_moderate294(None, gt, act) for gt, act in (("css", "ban"), ("cod4", "kick"))]
eq("moderation: a Valve ban and an idTech3 kick that must look the player up on an unread console say so and send "
   "nothing", _unread294, [((False, _game294.CONSOLE_LIST_UNREAD), [])] * 2)
eq("moderation (control): a console read that lists nobody by that name still says the player was not found",
   [_moderate294([{"name": "Alice", "num": "2", "steamid": "STEAM_0:1:2"}], gt, act)[0][1]
    for gt, act in (("css", "ban"), ("cod4", "kick"))],
   ["Couldn't find that player's SteamID to ban them.", "Couldn't find that player on the server."])
eq("moderation (control): a console read that lists the player bans and kicks them",
   [_moderate294([{"name": "Bob", "num": "3", "steamid": "STEAM_0:1:294"}], gt, act)
    for gt, act in (("css", "ban"), ("cod4", "kick"))],
   [((True, "Done."), ["banid 0 STEAM_0:1:294 kick; writeid"]), ((True, "Done."), ["clientkick 3"])])

_b3sid294 = _fixture278()
_b3got294 = {}
try:
    _p9_arm(who="part294")
    _done294 = '{"id": 1, "ok": true, "result": {"cid": "3", "client_id": 12}}\n'
    _seen294 = _socket_stub278(_done294, _game294.CONSOLE_UNREAD, name="Bob")
    _b3got294["unread"] = _post278(P9_ADMIN, _b3sid294, "kick", {"reason": "camping"}), len(_seen294["socket"])
    _seen294 = _socket_stub278(_done294, None, name="Bob")
    _b3got294["none"] = _post278(P9_ADMIN, _b3sid294, "kick", {"reason": "camping"}), len(_seen294["socket"])
finally:
    _p9_restore_all()
    _p9_delete_server(_b3sid294)
_b3st294, _b3calls294 = _b3got294.get("unread") or ((0, {}), -1)
eq("b3 kick: a console list that could not be read answers 503 saying so, and B3 is not asked",
   (_b3st294[0], _b3st294[1].get("error"), _b3calls294), (503, _game294.CONSOLE_LIST_UNREAD, 0))
_b3st294, _b3calls294 = _b3got294.get("none") or ((0, {}), -1)
eq("b3 kick (control): a console list read without the player still says they are not on the server",
   (_b3st294[0], _b3st294[1].get("error"), _b3calls294), (409, _act278.S_NOT_ONLINE, 0))


# ── 6. A Valve Kick by a name two players share ───────────────────────────────────────────────────
_two294 = [{"name": "Bob", "num": "3", "steamid": "STEAM_0:1:3"}, {"name": "Bob", "num": "5", "steamid": "STEAM_0:1:5"}]
eq("moderation: a Source Kick by a name two connected players share is refused, and nothing is sent",
   _moderate294(_two294, "css", "kick"), ((False, _game294.VALVE_NAME_SHARED), []))
eq("moderation (control): a Source Kick by a name one player has, or with a console that could not be read, is "
   "sent as before", [_moderate294(_two294[:1], "css", "kick"), _moderate294(None, "css", "kick")],
   [((True, "Done."), ['kick "Bob"'])] * 2)


# ── 7. A settings save is byte-faithful for the lines it does not change ──────────────────────────
_CFG294 = b'servername="Caf\xe9"\nmotd="a\xe2\x80\xa8b"\nff="x\x0cy"\nmaxplayers="8"\n'


def _cfg_save294(settings):
    """POST `settings` to the config route over _CFG294: (answer, the bytes written or None)."""
    writes = []
    framed = _files294._READ_BEGIN + _b64_294.b64encode(_CFG294).decode() + _files294._READ_END

    def shell(server, user, sh, **k):
        return (framed, "", 0) if _files294._READ_BEGIN in sh else ("", "unexpected", 1)
    try:
        _p9_arm(who="part294")
        _p9_patch(_core294, "shell_as_game_user", shell)
        _p9_patch(_files294, "_write_file_as_user",
                  lambda server, user, path, content, selfname: (writes.append(content), (True, ""))[1])
        _p9_patch(_sf294, "_write_refused", lambda gs, action: None)
        _p9_patch(_lgp294, "forget", lambda *a: None)
        got = _p9_json(_p9_client(P9_ADMIN).post("/api/server/%d/config" % P9_GS, json={"settings": settings}))
    finally:
        _p9_restore_all()
    return got.get("success"), (writes[0] if writes else None)


eq("config save: the other lines come back byte for byte (a Latin-1 byte, a U+2028 and a form feed inside values); "
   "only the changed one is rewritten", _cfg_save294({"maxplayers": "9"}),
   (True, _CFG294.replace(b'maxplayers="8"', b'maxplayers="9"')))
eq("config save (control): a new key is appended after the last line, with no blank line before it",
   _cfg_save294({"new_key": "n"}), (True, _CFG294 + b'new_key="n"\n'))


# ── 8. A cfg field set again by a later line the form does not read ───────────────────────────────
def _cfg_form294(sid, text, key, value):
    """GET the form over `text`, then save `value` into the last field named `key`: (fields, saved, written)."""
    writes = []
    _p9_arm(who="part294")
    _p9_patch_sm("read_file", lambda server, user, rel, **k: (text, None))
    _p9_patch_sm("write_file", lambda server, user, rel, content, **k: writes.append(content) or (True, ""))
    _p9_patch(_sf294, "_read_refused", lambda *a, **k: None)
    _p9_patch(_sf294, "_write_refused", lambda *a, **k: None)
    c, url = _p9_client(P9_ADMIN), "/api/server/%d/game-config/form" % sid
    try:
        got = _p9_json(c.get(url + "?path=serverfiles/cfg/p294.cfg"))
        fields = [(f["key"], f["value"], f["id"]) for g in (got.get("form") or {}).get("groups", []) for f in g["fields"]]
        fid = [i for k, _v, i in fields if k.lower() == key]
        saved = _p9_json(c.post(url, json={"path": "serverfiles/cfg/p294.cfg", "hash": got["form"]["hash"],
                                           "changes": {str(fid[-1]): value}})) if fid else {}
    finally:
        _p9_restore_all()
    return [(k, v) for k, v, _i in fields], saved.get("success"), writes[-1:]


_cfgsid294 = _p9_new_server(P9_HOST, "p294cfg", "cod4", 28294, name="p294 cfg")
try:
    _two_cmds294 = 'hostname "p294"\nrcon_password "old"\nsv_cheats 0\nsv_lan 0; rcon_password "live"\n'
    _quoted294 = 'hostname "p294"\nrcon_password "old"\nsv_cheats 0\n"rcon_password" "live"\n'
    _cfgseen294 = [_cfg_form294(_cfgsid294, t, "rcon_password", "rotated")[0] for t in (_two_cmds294, _quoted294)]
    _cfgctl294 = _cfg_form294(_cfgsid294, _two_cmds294, "hostname", "renamed")
finally:
    _p9_delete_server(_cfgsid294)
eq("config form: an RCON password set again by a later line of two commands, or by a quoted key, is not offered "
   "(the form showed the first line, and saving it said Saved while the game kept the later value)",
   _cfgseen294, [[("hostname", "p294"), ("sv_cheats", "0")]] * 2)
eq("config form (control): the other fields of that file are still shown and saved",
   _cfgctl294, ([("hostname", "p294"), ("sv_cheats", "0")], True, [_two_cmds294.replace('"p294"', '"renamed"')]))


# ── 9. The Backup button beside another backup ────────────────────────────────────────────────────
def _button294(sid):
    """{case: (dumps, teed actions, what a sweep saw during the dump)} for Backup-button runs."""
    teed, dumped, got = [], [], {}
    _p9_arm(who="part294")
    _p9_patch(_sd294, "threading", _p9_threading(_P9Thread))
    _p9_patch(_sd294, "_db_dump_before", lambda *a, **k: dumped.append(_sh294._button_backup_running(sid)))
    _p9_patch(_sd294, "_run_teed", lambda app, remote, s, short, action, *a, **k: teed.append(action) or ("", "", 0))
    try:
        with _p9.app_context():
            gs = _sd294.db.session.get(_sd294.GameServer, sid)
            _sh294._game_backup_status[sid] = {"running": True, "ok": None, "msg": "", "ts": _time294.time()}
            try:
                _sd294._bg_action(_p9, gs, gs.remote, "backup")
                _p9_drain()
            finally:
                _sh294._game_backup_status.pop(sid, None)
            row = _p9_audit("backup_complete")
            got["flag"] = (list(dumped), list(teed), (row.success, row.detail) if row is not None else None)
            with _sh294.button_backup_claim(sid, "backup") as free:
                _sd294._bg_action(_p9, gs, gs.remote, "backup")
                _p9_drain()
                got["claimed"] = (free, list(dumped), list(teed))
            _sd294._bg_action(_p9, gs, gs.remote, "backup")
            _p9_drain()
            got["alone"] = (list(dumped), list(teed), _sh294._button_backup_running(sid))
    finally:
        _p9_restore_all()
    return got


_bksid294 = _p9_new_server(P9_HOST, "p294bk", "cod4", 28295, name="p294 bk")
try:
    _bk294 = _button294(_bksid294)
finally:
    _p9_delete_server(_bksid294)
_flag294 = _bk294.get("flag") or ([None], [None], None)
check("Backup button: while a scheduled or queued backup of the server runs, it dumps nothing and runs no backup, and "
      "its outcome is audited as refused", _flag294[:2] == ([], []) and _flag294[2] is not None
      and not _flag294[2][0] and "another backup of this server is running" in (_flag294[2][1] or ""), repr(_flag294))
eq("Backup button: while another Backup-button run holds the server, a second one dumps nothing and runs nothing",
   _bk294.get("claimed"), (True, [], []))
eq("Backup button (control): alone it dumps and runs, a sweep asking during its dump sees it running, and it lets "
   "go after", _bk294.get("alone"), ([True], ["backup"], False))


# ── 10. An injected form gets no token, and is not sent ───────────────────────────────────────────
def _form_tag_end294(src, i):
    """Index of the `>` closing the tag that opens at `i`, past quoted values and Jinja blocks."""
    j, quote = i + 1, None
    while j < len(src):
        ch = src[j]
        if quote:
            quote = None if ch == quote else quote
        elif src.startswith(("{{", "{%", "{#"), j):
            j = src.index({"{{": "}}", "{%": "%}", "{#": "#}"}[src[j:j + 2]], j + 2) + 1
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return j
        j += 1
    return len(src)


def _post_forms294():
    """(POST form tags seen, those not followed at once by the server-rendered token) over every template."""
    seen, bare = 0, []
    token = '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">'
    for path in sorted(_glob294.glob(os.path.join(_root, "panel", "templates", "**", "*.html"), recursive=True)):
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for m in _re294.finditer(r"<form\b", src):
            end = _form_tag_end294(src, m.start())
            if _re294.search(r"\bmethod\s*=\s*[\"']?post\b", src[m.start():end], _re294.I):
                seen += 1
                if not src.startswith(token, end + 1):
                    bare.append("%s:%d" % (os.path.basename(path), src.count("\n", 0, m.start()) + 1))
    return seen, bare


_seen294, _bare294 = _post_forms294()
check("templates: every POST form carries the token the server rendered into it (panel.js no longer gives every "
      "form in the page one)", _seen294 >= 50 and not _bare294, "%d POST forms, without a token: %s" % (_seen294, _bare294[:6]))
_page294 = _p9_client(P9_ADMIN).get("/account").get_data(as_text=True)
_tags294 = _re294.findall(r"<form\b[^>]*method=\"POST\"[^>]*>(<input[^>]*>)?", _page294)
check("account page (rendered): each POST form opens with a csrf_token field holding a token",
      bool(_tags294) and all(_re294.fullmatch(r'<input type="hidden" name="csrf_token" value="[^"]+">', t or "")
                            for t in _tags294), repr(_tags294[:4]))

_PANEL294 = open(os.path.join(_root, "panel", "static", "js", "panel.js"), encoding="utf-8").read()
_js294 = _node47(
    "global.window = global; global.CSRF = 'tok'; const sent = [];\n"
    "global.fetch = (u, o) => { sent.push(u); return new Promise(() => 0); };\n"
    "global.document = {createElement: () => ({})};\n"
    "global._r30c_bkSave = function(){}; global.backupUpload = function(){}; global.gameTilesRefreshed = function(){};\n"
    + _PANEL294[_PANEL294.index("var _ACTION_DENY"):_PANEL294.index("// ── The console's command history")] + "\n"
    + _cut47(_PANEL294, "window.ensureCsrfFields = function") + "\n"
    + _cut47(_PANEL294, "function _serverForm(") + "\n"
    + _cut47(_PANEL294, "function _submitAjaxForm(") + "\n"
    "function mkForm(token) {\n"
    "  const kids = token === undefined ? [] : [{name: 'csrf_token', value: token}];\n"
    "  return {tagName: 'FORM', action: '/x', kids,\n"
    "    getAttribute: n => n === 'method' ? 'post' : null,\n"
    "    querySelector: q => q.indexOf('csrf_token') >= 0 ? (kids[0] || null) : null,\n"
    "    querySelectorAll: () => { throw new Error('walked the page'); },\n"
    "    appendChild: c => kids.push(Object.assign(c, {name: c.name}))};\n"
    "}\n"
    "global.FormData = function(){};\n"
    "const page = {tagName: undefined, querySelectorAll: () => { throw new Error('walked the page'); }};\n"
    "let walked = false; try { window.ensureCsrfFields(page); } catch (e) { walked = true; }\n"
    "const built = mkForm(); window.ensureCsrfFields(built);\n"
    "_submitAjaxForm(mkForm()); _submitAjaxForm(mkForm('')); const refused = sent.length;\n"
    "_submitAjaxForm(mkForm('tok'));\n"
    "console.log(JSON.stringify({walked, built: built.kids.length ? built.kids[0].value : null, refused,\n"
    "  sent: sent.length, r: _actionFn('_r30c_bkSave') === null, up: _actionFn('backupUpload') === null,\n"
    "  ok: typeof _actionFn('gameTilesRefreshed')}));\n")
if _js294 is None:
    skip("panel.js: an ajax form without a server token is not sent, and nothing walks the page", "node is not installed")
else:
    eq("panel.js: an ajax form without a server token is not sent, nothing walks the page giving forms a token, a "
       "form a script builds still gets one, and the dispatcher refuses _r<digits> helpers and backupUpload",
       _js294, {"walked": False, "built": "tok", "refused": 0, "sent": 1, "r": True, "up": True, "ok": "function"})


# ── 11. A cut value's note fits the viewer ────────────────────────────────────────────────────────
_DBM294 = open(os.path.join(_root, "panel", "static", "js", "databases_manager.js"), encoding="utf-8").read()
_dbm294 = _node47(
    "function T(s){ return s; }\nfunction TF(s){ return s; }\nfunction raw(e){ return e; }\n"
    "function node(t, c, x){ return {t: t, text: x || '', kids: [], appendChild: function (k) { this.kids.push(k); return k; }}; }\n"
    "function button(label){ return node('button', null, label); }\n"
    "var document = {createTextNode: function (x) { return node('#text', null, x); }};\n"
    "var st = {canEdit: false};\n"
    + (_cut47(_DBM294, "function cutNote(") if "function cutNote(" in _DBM294 else "") + "\n"
    + _cut47(_DBM294, "function cellNode(") + "\n"
    "var out = [false, true].map(function (e) { st.canEdit = e;\n"
    "  var td = cellNode({}, {text: 'long', more: true}, 0, 0, false); return td.kids[td.kids.length - 1].text; });\n"
    "console.log(JSON.stringify(out));\n")
if _dbm294 is None:
    skip("databases browser: a keyless row's cut value says what the viewer can do", "node is not installed")
else:
    eq("databases browser: a keyless row's cut value sends only an editor to the SQL box; a viewer without one is "
       "told the table has no key to read it by", _dbm294,
       ["Too long to show here: this table has no key to read the whole value by.",
        "Too long to show here: use the SQL box."])


# ── 12. BlueMap's tidy-up waits for the new image ─────────────────────────────────────────────────
_bmids294 = _fixture272()
try:
    _p9_arm(who="part294")
    _bmcalls294 = _host272(_probe_out272(meta={"kind": "bluemap", "image": "ghcr.io/bluemap-minecraft/bluemap@sha256:" + "0" * 64,
                                               "mc_version": "1.21.4", "port": 21008, "eula_accepted_by": "admin"},
                                         version="1.21.5"))
    _p9_patch(_bm272, "_get", _getter272(*_mojang272("1.21.5")))
    _bmr294 = _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/update" % _bmids294["mc"])
    _p9_drain()
    _bmsh294 = _writes272(_bmcalls294)[0]
finally:
    _p9_restore_all()
    _drop272(_bmids294)
_at294 = {k: _bmsh294.find(m) for k, m in (("fetch", "minecraft-client-1.21.5.jar.part"), ("pull", "ADDON_PULL_FAILED"),
                                            ("record", "/addon.json.new"), ("tidy", "/minecraft-client-*.jar; do"),
                                            ("page", "/web/index.html"))}
check("BlueMap update: the client file is fetched before the image, and the old jar and page are removed only after "
      "the image is pulled and the record written (before, a failed pull left BlueMap without them)",
      _bmr294.status_code == 202 and min(_at294.values()) >= 0
      and _at294["fetch"] < _at294["pull"] < _at294["record"] < _at294["tidy"] < _at294["page"], repr(_at294))

_bmdir294 = os.path.join(_TMP294, "bm", "addon")
_bmfiles294 = ("minecraft-client-1.21.4.jar", "minecraft-client-1.21.5.jar")
for _n294 in _bmfiles294 + ("index.html",):
    _sub294 = os.path.join(_bmdir294, "web" if _n294 == "index.html" else "data")
    os.makedirs(_sub294, exist_ok=True)
    open(os.path.join(_sub294, _n294), "w").close()
_EMPTY_SHA294 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"    # an empty file's: the 1.21.5 jar is kept, nothing fetched
_ls294 = "cd %s && ls -1 * | tr '\\n' ' '" % _bmdir294
_fetch294 = _bash294(_bm272.client_sh(_bmdir294, "1.21.5", "https://piston-data.mojang.com/x", _EMPTY_SHA294, True,
                                      tidy=False) + _ls294)[0].split()
_tidy294 = _bash294(_bm272.client_tidy_sh(_bmdir294, "1.21.5", True) + _ls294)[0].split()
eq("BlueMap update (bash): the fetch alone keeps the old jar and page; the tidy-up then removes them (control)",
   (_fetch294, _tidy294),
   (["data:", "minecraft-client-1.21.4.jar", "minecraft-client-1.21.5.jar", "web:", "index.html"],
    ["data:", "minecraft-client-1.21.5.jar", "web:"]))


# ── 13. A new image with the same label ───────────────────────────────────────────────────────────
_b3cat294 = _ra294._ad.CATALOG["b3"]


def _b3_row294(sid, meta):
    """The B3 row of the add-ons list route, with the host answering `meta` as B3's record."""
    probe = "os=24.04\npodman=podman version 5.0\nmeta.b3=%s\nstate.b3=active\n" % _ra294._ad._b64(_json294.dumps(meta))
    try:
        _p9_arm(who="part294")
        _p9_patch_sm("shell_as_game_user", lambda *a, **k: (probe, "", 0))
        _p9_patch(_ra294, "game_account_write_refusal", lambda *a, **k: None)
        got = _p9_json(_p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid)).get("addons") or []
    finally:
        _p9_restore_all()
    return next(((r.get("version"), r.get("version_new"), r.get("update")) for r in got if r.get("id") == "b3"), None)


_b3row_sid294 = _fixture278()
try:
    _b3rows294 = [_b3_row294(_b3row_sid294, {"kind": "b3", "image": "localhost/lgsm-addon-b3:oldbuild", "version": v,
                                             "database": "gs_b3_278"})
                  for v in (_b3cat294["version"], "2.0.1 (0123abcd)")]
finally:
    _p9_delete_server(_b3row_sid294)
eq("add-on rows: a new image with the installed version's label is offered with no version (the card says a newer "
   "version of the add-on); one with another label names it (control)", _b3rows294,
   [(_b3cat294["version"], "", "image"), ("2.0.1 (0123abcd)", _b3cat294["version"], "image")])


# ── 14. B3's namesake read ────────────────────────────────────────────────────────────────────────
def _sql_namesakes294(sql, target, stored):
    """What `sql`'s WHERE selects from `stored` for `target`, its REGEXP_REPLACE and TRIM steps run in Python.

    The statement's patterns are read back from its hex literals, in order; MariaDB's (?-i) flag is
    Python's default. A statement with no such steps (the substring test it replaced) selects nothing.
    """
    pats = [bytes.fromhex(h).decode().replace("(?-i)", "") for h in _re294.findall(r"X'([0-9A-F]+)'", sql)]
    side = pats[:len(pats) // 2]
    if not side or pats != side * 2 or sql.count("TRIM(REGEXP_REPLACE(") != len(pats):
        return None

    def key(name):
        for pat in side:
            name = _re294.sub(pat, "", name).strip(" ")
        return name.lower()
    return [n for n in stored if key(n) == key(target)]


_sql294 = _b3p294.namesakes_statement(12)["sql"]
eq("b3 namesakes: a target stored as \"^ABob\" finds \"Bob\" and \"^aBob\" (B3 kicked one of them), not \"Bobby\"; "
   "for \"Ace\", \"Grace\", \"Space\", \"FaceLess\" and \"aCeS\" are no namesakes (enough of them refused every Kick)",
   [_sql_namesakes294(_sql294, "^ABob", ["Bob", "^aBob", "Bobby", "^1Bob"]),
    _sql_namesakes294(_sql294, "Ace", ["Grace", "Space", "FaceLess", "aCeS", "ace", "^3Ace"])],
   [["Bob", "^aBob", "^1Bob"], ["ace", "^3Ace"]])


def _namesake_misses294(sql, rounds=20000):
    """Generated (target, listed, stored) triples the identity check calls namesakes that `sql` would not select."""
    rnd = _random294.Random(294)
    codes = ["^a", "^A", "^1", "^_", "^X12345", "^X123456", "^ ", "^x1"]

    def noisy(core):
        out = "".join((rnd.choice(codes) if rnd.random() < 0.3 else "") + ch for ch in core)
        return (" " if rnd.random() < 0.2 else "") + out + (rnd.choice(codes) if rnd.random() < 0.3 else "")
    misses, tried = [], 0
    for _i in range(rounds):
        core = "".join(rnd.choice("aAb Xb1_") for _j in range(rnd.randint(1, 5)))
        target, listed, other = noisy(core), noisy(core), noisy(core if rnd.random() < 0.7 else core + "b")
        if "^^" in target + listed + other or not _b3p294.plain(target).strip():
            continue        # a run of two carets: the check itself reads it two ways (the statement says so)
        row = [{"name": listed}]
        if len(_game294.console_name_matches("cod4", row, _b3p294.plain(target).strip())) != 1:
            continue
        if not _game294.console_name_matches("cod4", row, _b3p294.plain(other).strip()):
            continue
        tried += 1
        if not _sql_namesakes294(sql, target, [other]):
            misses.append((target, listed, other))
    return tried, misses[:4]


_tried294, _missed294 = _namesake_misses294(_sql294)
check("b3 namesakes: over generated colour-coded names, every stored name the identity check would call a namesake of "
      "the listed player is selected", _tried294 > 500 and not _missed294, repr((_tried294, _missed294)))
