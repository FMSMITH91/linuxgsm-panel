"""The Databases manager's dump routes: download a database's dump, and upload one to restore it.

DOWNLOAD. A POST dumps the database into its game server's files (~/panel-db-dumps/<name>.sql.gz,
the file a backup writes and Restore reads), signed in as the database's own account and written by
the game account (ssh_manager.databases.dump, behind the root-capable-account guard); a GET then
streams that file, read as the game account. The POST is what changes the host, so it carries the
CSRF token; the GET only reads.

UPLOAD. In pieces of UPLOAD_CHUNK bytes (the app-wide request cap stays), each a POST of raw bytes
written by the game account into a part file in ~/panel-db-dumps, as a game backup upload is
(routes/backup_upload.py): the panel holds one piece in memory at a time. The finish checks the whole
file on the host before anything is restored (OWASP File Upload: the content, never the name the
browser gave): gzip or plain text, UTF-8 SQL with no NUL byte, at most UPLOAD_PLAIN_MAX bytes once
unpacked, and no statement that switches or names another database (USE, CREATE/DROP/ALTER DATABASE,
CONNECT, or a `schema`. reference to a system schema or another panel database). Then it becomes
<name>.sql.gz and is restored by the existing import: run as the game account, signed in as the
database's own account (whose grant is that one database), the client in --binary-mode (no client
command in the dump but DELIMITER). The database server is what keeps a statement in that database;
the check is what refuses a dump made for another one before anything runs.

PERMISSION. MANAGE_DATABASES and access to the server, as the rest of the tab. An upload to restore
also takes the step-up confirm (account_guard) when it starts, and the database's name typed at the
finish, as Restore and Delete do.
"""
import base64
import re
import secrets
import threading
import time
from datetime import datetime, timezone

from flask import Response, jsonify, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import decrypt_secret
from panel.core.validation import _attachment_header
from panel.core.http import _json_body, _json_str, _log_and_generic
from panel.core.stdin_chunks import StdinChunks
from panel.db.models import db
from panel.ops import ssh_manager as _sm
from panel.ops.ssh_manager import databases as _dbs
from panel.ops.ssh_manager.db_upload_scan import SCAN_AWK as _SCAN_AWK
from panel.routes import databases as _dbr, databases_data as _ddr
from panel.routes._shared import game_account_write_refusal
from panel.security.account_guard import step_up_needed, step_up_refusal
from panel.security.auth import MANAGE_DATABASES, get_game, has_permission, log_action, server_access_required

UPLOAD_CHUNK = 4 * 1024 * 1024
UPLOAD_MAX = 2 * 1024 * 1024 * 1024          # what the import takes (db-import's DB_IMPORT_MAX)
UPLOAD_PLAIN_MAX = 16 * 1024 * 1024 * 1024    # the SQL inside, unpacked (a decompression bomb's bound)
UPLOAD_MARGIN = 256 * 1024 * 1024
UPLOAD_STALE_MIN = 120
UPLOAD_IDLE = 2 * 3600
_PIECE_TIMEOUT = 300
_FINISH_TIMEOUT = 3600
_UID_RE = re.compile(r"[0-9a-f]{32}\Z")
_DUMP_DIR = _dbs._priv.DB_DUMP_DIR
_DENIED = "Permission denied"

# upload id -> {"uid", "db", "user", "size", "ts"}: one upload per database at a time.
_UPLOADS = {}
_UPLOADS_LOCK = threading.Lock()

_M = {k: "__DBUP_%s__" % k for k in ("READY", "SIZE", "OFFSET", "NOPART", "FAIL", "SPACE", "STORED", "FORMAT",
                                     "NOTTEXT", "NOTSQL", "SWITCH", "OTHER", "BIG", "DAMAGED")}
_REFUSALS = {
    "NOPART": "the upload is no longer on the host (it was cancelled, or left too long)",
    "FAIL": "the host could not write the upload into the server's files",
    "SPACE": "there is not enough free space in the server's files for it",
    "FORMAT": "the file is neither gzip nor plain text",
    "NOTTEXT": "the file is not text (it holds NUL bytes)",
    "NOTSQL": "the file does not look like an SQL dump",
    "SWITCH": "the dump switches to another database (USE, CREATE DATABASE, DROP DATABASE or CONNECT): make it of "
              "this one database only, without --databases or --all-databases",
    "OTHER": "the dump names another database (a system schema or another server's database)",
    "BIG": "the SQL inside is larger than 16 GiB",
    "DAMAGED": "the file could not be read to its end (damaged, or cut short)",
}


def _say(status, sentence, **extra):
    return _dbr._say(status, sentence, **extra)


def _row(server_id, db_id):
    gs = get_game(server_id)
    return gs, _dbr._own_row(gs, db_id)


def _home(user):
    # Not a route: a path built from the validated game account name.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return "/home/%s" % user


# ── download ─────────────────────────────────────────────────────────────────────────────────────
def own_target(gs, r):
    """What a dump of `r` signs in to as the database's own account (never the admin login), or None."""
    local = _dbr._host_row(gs.remote_id)
    own = _dbr.own_view(local, r)
    if own is not None:
        return own
    return _dbs.target_view(local, login=(r.name, r.secret)) if local is not None else None


def _dump_answer(gs, r):
    """POST: a fresh dump of the database in the server's files, ready for the download GET."""
    target = own_target(gs, r)
    if target is None:
        return _say(409, _dbr._NOT_READY)
    ok, said = _dbs.dump(gs.remote, target, "game", gs.short_name, [r.name])
    if ok:
        r.dumped_at = _dbr._now()
        db.session.commit()
    log_action(current_user, "db_dump_download", target=gs.name, server=gs, success=bool(ok),
               detail=("dumped database %s for download" % r.name) if ok else
               "database %s not dumped: %s" % (r.name, i18n.tr(said)))
    if not ok:
        return _say(502, said or "Failed")
    return jsonify({"success": True, "message": i18n.tr("The dump is ready; the download starts now."),
                    "file": "%s/%s.sql.gz" % (_DUMP_DIR, r.name)})


def _download_answer(gs, r):
    """GET: the dump in the server's files, streamed as the game account reads it."""
    rel = "%s/%s.sql.gz" % (_DUMP_DIR, r.name)
    info = _sm.stat_path(gs.remote, gs.short_name, rel)
    if not info or info.get("type") != "f":
        return _say(404, "There is no dump of this database in the server's files yet. Make one first.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    resp = Response(_sm.stream_path(gs.remote, gs.short_name, rel, limit=info["size"]), mimetype="application/gzip")
    resp.headers["Content-Length"] = str(info["size"])
    resp.headers["Content-Disposition"] = _attachment_header("%s-%s.sql.gz" % (r.name, stamp))
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ── upload: the commands, run as the game account ────────────────────────────────────────────────
def _paths(user, uid):
    """Shell setting D (the dump folder) and p (upload `uid`'s part file)."""
    if not isinstance(uid, str) or not _UID_RE.match(uid):
        raise ValueError("bad upload id")
    # Not a route: shell text run as the game account, its parts quoted or matched by _UID_RE.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return 'D=%s; p="$D/.panel-upload-%s.part"' % (_sm._quote(_home(user) + "/" + _DUMP_DIR), uid)


def start_script(user, uid, size):
    """Make the empty part file once the folder's filesystem has room for `size` bytes and a margin."""
    need = int(size) + UPLOAD_MARGIN
    # Not a route: shell text run as the game account, its parts quoted.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return "\n".join([
        "umask 077", _paths(user, uid),
        'mkdir -p -- "$D" 2>/dev/null; if [ ! -d "$D" ] || [ -L "$D" ]; then echo %s; exit 6; fi' % _M["FAIL"],
        "find \"$D\" -maxdepth 1 -name '.panel-upload-*' -mmin +%d -delete 2>/dev/null" % UPLOAD_STALE_MIN,
        'free=$(df -PB1 -- "$D" 2>/dev/null | awk \'NR==2{print $4}\')',
        'case "$free" in ""|*[!0-9]*) echo %s; exit 5;; esac' % _M["SPACE"],
        'if [ "$free" -lt %d ]; then echo %s; exit 5; fi' % (need, _M["SPACE"]),
        'set -C; : > "$p" 2>/dev/null || { echo %s; exit 6; }' % _M["FAIL"],
        "echo " + _M["READY"]]) + "\n"


def piece_script(user, uid, offset):
    """Append the piece on stdin (base64) when the part file is exactly `offset` bytes long now."""
    # Not a route: shell text run as the game account, its parts quoted.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return "\n".join([
        _paths(user, uid), 'c="$p.piece"',
        'base64 -d > "$c" 2>/dev/null || { rm -f -- "$c"; cat > /dev/null; echo %s; exit 6; }' % _M["FAIL"],
        'if [ ! -f "$p" ] || [ -L "$p" ]; then rm -f -- "$c"; echo %s; exit 5; fi' % _M["NOPART"],
        's=$(stat -c %s -- "$p")',
        'if [ "$s" != %d ]; then rm -f -- "$c"; echo "%s $s"; exit 5; fi' % (int(offset), _M["OFFSET"]),
        'cat -- "$c" >> "$p" || { rm -f -- "$c"; echo %s; exit 6; }' % _M["FAIL"],
        'rm -f -- "$c"; echo "%s $(stat -c %%s -- "$p")"' % _M["SIZE"]]) + "\n"


# The scan's awk program and what it checks: ssh_manager/db_upload_scan.py.



# One finish (or cancel) of an upload at a time: one asked again while the first still runs on the host
# gives no answer, which reads as "ask again". flock is util-linux's; without it the step runs unlocked.
# The lock file goes when the holder ends (the trap is set only once the lock is held).
_FINISH_LOCK = ('exec 9>>"$p.lock" || exit 7; if command -v flock >/dev/null 2>&1; then flock -n 9 || exit 7; fi; '
                "trap 'rm -f -- \"$p.lock\"' EXIT")


def finish_script(user, uid, size, name):
    """Check the whole upload (format, text, SQL, the scan), gzip a plain one, and make it <name>.sql.gz."""
    rm = 'rm -f -- "$p" "$p.gz" "$p.stored";'
    keep = _sm._quote(name + ".sql.gz")
    scan = "awk -v me=%s -v max=%d %s" % (_sm._quote(name), UPLOAD_PLAIN_MAX, _sm._quote(_SCAN_AWK))
    # Not a route: shell text run as the game account, its parts quoted.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return "\n".join([
        "set -o pipefail", "export LC_ALL=C", "umask 077", _paths(user, uid), _FINISH_LOCK,
        # Asked again after an answer that was lost: an upload already put in place says so ($p.stored
        # is written just before the move, and settle or cancel removes it).
        'if [ ! -e "$p" ] && [ -f "$p.stored" ]; then echo %s; exit 0; fi' % _M["STORED"],
        'if [ ! -f "$p" ] || [ -L "$p" ]; then echo %s; exit 5; fi' % _M["NOPART"],
        's=$(stat -c %s -- "$p")',
        'if [ "$s" != %d ]; then %s echo "%s $s"; exit 5; fi' % (int(size), rm, _M["OFFSET"]),
        "m=$(head -c 2 -- \"$p\" | od -An -tx1 | tr -d ' \\n')",
        'if [ "$m" = 1f8b ]; then rd() { gzip -dc -- "$p"; }; else rd() { cat -- "$p"; }; fi',
        'h=$(rd 2>/dev/null | head -c 65536 | wc -c); n=$(rd 2>/dev/null | head -c 65536 | tr -d \'\\000\' | wc -c)',
        'if [ "$h" = 0 ]; then %s echo %s; exit 5; fi' % (rm, _M["FORMAT"]),
        'if [ "$h" != "$n" ]; then %s echo %s; exit 5; fi' % (rm, _M["NOTTEXT"]),
        # Counted, never `grep -q` under pipefail: grep stopping early ends the reader with SIGPIPE, and
        # a large dump would read as "not SQL".
        ("c=$(rd 2>/dev/null | head -c 65536 | grep -ciE '^(--|/\\*|CREATE |INSERT |SET |DROP |LOCK |ALTER |START |"
         + "BEGIN|DELIMITER )')"),
        'if [ "${c:-0}" -lt 1 ]; then %s echo %s; exit 5; fi' % (rm, _M["NOTSQL"]),
        # A verdict first (awk stopping early ends the reader with SIGPIPE); a scan that read everything
        # also needs the reader to have read it all without an error (a damaged or cut gzip).
        # NUL bytes become spaces for the scan only (the stored dump is unchanged): Ubuntu 22.04's mawk ends a
        # string at a NUL in match/index/split, so the rest of such a line would go unread there.
        "v=$(rd 2>/dev/null | tr '\\000' ' ' | %s); r=$?" % scan,
        'case "$v" in SCANNED) [ "$r" = 0 ] || { %s echo %s; exit 5; };; BIG|SWITCH|OTHER) %s echo "__DBUP_${v}__"; '
        'exit 5;; *) %s echo %s; exit 5;; esac' % (rm, _M["DAMAGED"], rm, rm, _M["DAMAGED"]),
        'if [ "$m" != 1f8b ]; then gzip -c -n -- "$p" > "$p.gz" && mv -f -- "$p.gz" "$p" || { %s echo %s; exit 6; }; fi'
        % (rm, _M["FAIL"]),
        # The dump the server's files held is kept aside (<name>.sql.gz.prev) until the restore has worked:
        # settle_script puts it back if it did not, so an upload that fails never replaces it.
        'f="$D"/%s; if [ -e "$f" ] && ! mv -f -- "$f" "$f.prev"; then %s echo %s; exit 6; fi' % (keep, rm, _M["FAIL"]),
        ': > "$p.stored" && mv -f -- "$p" "$f" && echo %s && exit 0' % _M["STORED"],
        # Not put in place: the dump kept aside goes back.
        rm + ' if [ -e "$f.prev" ]; then mv -f -- "$f.prev" "$f"; fi; echo ' + _M["FAIL"], "exit 6"]) + "\n"


def _settle_body(user, name, restored):
    f = _sm._quote(_home(user) + "/" + _DUMP_DIR + "/" + name + ".sql.gz")
    if restored:
        return "rm -f -- %s.prev" % f
    return "if [ -e %s.prev ]; then mv -f -- %s.prev %s; else rm -f -- %s; fi" % (f, f, f, f)


def settle_script(user, name, restored, uid):
    """After the restore: drop the dump kept aside (it worked), or put it back in place of the upload (it did not).

    With nothing kept aside, a failed upload's dump is removed: it is never left as the one Restore reads.
    Upload uid's mark that it was put in place ($p.stored) goes too.
    """
    body = _paths(user, uid) + "\n" + _settle_body(user, name, restored) + ' && rm -f -- "$p.stored"'
    # Not a route: shell text run as the game account, its parts quoted.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return body + " && echo " + _M["READY"] + "\n"


def cancel_script(user, uid, name=None):
    """Remove an upload's part file (and a staged piece); one already put in place gives the earlier dump back."""
    # Not a route: shell text run as the game account, its parts quoted.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    back = ['if [ -f "$p.stored" ]; then %s; fi' % _settle_body(user, name, False)] if name else []
    return "\n".join([_paths(user, uid), _FINISH_LOCK] + back + [
                      'rm -f -- "$p" "$p.piece" "$p.gz" "$p.stored"', "echo " + _M["READY"]]) + "\n"


def outcome(out):
    """(state, value) of an upload command.

    ("ok", number or ""), ("offset", bytes), ("refused", key) or ("unread", "") when none of its
    marks came back.
    """
    marks = {m: ln for ln in (out or "").splitlines() for m in re.findall(r"^__DBUP_[A-Z]+__", ln)}
    for key in ("STORED", "SIZE", "READY"):
        if _M[key] in marks:
            return "ok", (marks[_M[key]].split() + [""])[1]
    if _M["OFFSET"] in marks:
        got = (marks[_M["OFFSET"]].split() + [""])[1]
        return "offset", int(got) if got.isdecimal() else 0
    for key in _REFUSALS:
        if _M[key] in marks:
            return "refused", key
    return "unread", ""


def _upcmd(gs, script, timeout, stdin=None):
    """One upload command as the game account: outcome()."""
    try:
        out, err, _rc = _sm.run_command(gs.remote, _sm.game_user_cmd(gs.short_name, script), timeout=timeout,
                                        sudo=False, **({"stdin_text": stdin} if stdin is not None else {}))
    except Exception:
        _log_and_generic("database upload command failed")
        return "unread", ""
    return outcome((out or "") + "\n" + (err or ""))


# ── upload: the requests ─────────────────────────────────────────────────────────────────────────
def _new_upload(db_id, size):
    now = time.time()
    with _UPLOADS_LOCK:
        for uid in [u for u, e in _UPLOADS.items() if now - e["ts"] > UPLOAD_IDLE]:
            _UPLOADS.pop(uid, None)
        if any(e["db"] == db_id for e in _UPLOADS.values()):
            return None
        uid = secrets.token_hex(16)
        _UPLOADS[uid] = {"uid": uid, "db": db_id, "user": current_user.id, "size": size, "ts": now}
        return uid


def _get_upload(uid, db_id):
    if not isinstance(uid, str) or not _UID_RE.match(uid):
        return None
    with _UPLOADS_LOCK:
        e = _UPLOADS.get(uid)
        if e is None or e["db"] != db_id or e["user"] != current_user.id:
            return None
        e["ts"] = time.time()
        return e


def _drop_upload(uid):
    with _UPLOADS_LOCK:
        _UPLOADS.pop(uid, None)


S_PREV_BACK = "The uploaded dump was not kept: the server's files hold the dump they had before."
S_PREV_UNKNOWN = ("The host did not answer when the panel put the earlier dump back; check panel-db-dumps in the "
                  "server's files.")


def _refused(key):
    return i18n.Sentence("The dump was not restored: {why}.", why=i18n.Sentence(_REFUSALS[key]))


def _upload_start(gs, r):
    """Start an upload: the size checked, the account guard asked, the part file made."""
    size = _json_body().get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= UPLOAD_MAX:
        return _say(400, i18n.Sentence("Give the dump's size: a whole number of bytes, at most {limit}.",
                                       limit="2 GiB"))
    why = game_account_write_refusal(gs.remote, gs.short_name)
    if why is not None:
        log_action(current_user, "db_upload", target=gs.name, server=gs, success=False,
                   detail="%s: refused: %s" % (r.name, i18n.tr(why)))
        return _say(409, why)
    uid = _new_upload(r.id, size)
    if uid is None:
        return _say(409, "An upload to this database is already running.")
    state, val = _upcmd(gs, start_script(gs.short_name, uid, size), 60)
    if state != "ok":
        _drop_upload(uid)
        return _say(409 if state == "refused" else 502, _refused(val) if state == "refused" else _dbr._UNREAD)
    return jsonify({"success": True, "id": uid, "chunk": UPLOAD_CHUNK})


_B64_STEP = 49152           # a multiple of 3, so each slice's base64 joins the next without padding


def _b64_chunks(data):
    view = memoryview(data)
    return StdinChunks(base64.b64encode(view[i:i + _B64_STEP]) for i in range(0, len(view), _B64_STEP))


def _offset():
    try:
        return int(request.args.get("offset", ""))
    except ValueError:
        return -1


def _piece_refusal(e, data, off):
    """The refusal for a piece that does not fit upload `e` (empty, over UPLOAD_CHUNK, past its size), or None."""
    if not data or len(data) > UPLOAD_CHUNK:
        return _say(413, "Each piece must be 1 byte to 4 MB.")
    if off < 0 or off + len(data) > e["size"]:
        return _say(400, "That piece does not fit the upload.")
    return None


def _upload_piece(gs, r, uid):
    """Append one piece at its offset; answers how much the host holds now."""
    e = _get_upload(uid, r.id)
    if e is None:
        return _say(404, "No such upload.")
    data, off = request.get_data(cache=True), _offset()
    refused = _piece_refusal(e, data, off)
    if refused:
        return refused
    state, val = _upcmd(gs, piece_script(gs.short_name, e["uid"], off), _PIECE_TIMEOUT, stdin=_b64_chunks(data))
    if state == "ok" and str(val).isdecimal():
        return jsonify({"success": True, "received": int(val)})
    if state == "offset":
        return jsonify({"success": False, "received": val, "resume": True}), 409
    return _say(409 if state == "refused" else 502, _refused(val) if state == "refused" else _dbr._UNREAD)


def _upload_finish(gs, r, uid):
    """Check the whole dump on the host, put it in place, and restore the database from it."""
    e = _get_upload(uid, r.id)
    if e is None:
        return _say(404, "No such upload.")
    if _json_str(_json_body(), "confirm") != r.name:
        return _say(400, "Type the database's name to confirm.")
    hd = _dbr._restore_target(gs, r)
    if hd is None:
        return _say(409, _dbr._NOT_READY)
    state, val = _upcmd(gs, finish_script(gs.short_name, e["uid"], e["size"], r.name), _FINISH_TIMEOUT)
    if state == "unread":
        return jsonify({"success": False, "retry": True, "message": i18n.tr(_dbr._UNREAD)}), 200
    _drop_upload(e["uid"])
    if state != "ok":
        why = _refused(val) if state == "refused" else i18n.Sentence("The upload is not all on the host.")
        log_action(current_user, "db_upload", target=gs.name, server=gs, success=False,
                   detail="%s: dump of %d bytes refused: %s" % (r.name, e["size"], val))
        return _say(409, why)
    return _restore_upload(gs, r, e, hd)


def _settle(gs, r, uid, restored):
    """Forget the database's cached structure and run settle_script: outcome()'s state."""
    _ddr.forget(r.id)
    return _upcmd(gs, settle_script(gs.short_name, r.name, restored, uid), 60)[0]


def _restore_upload(gs, r, e, hd):
    """Restore the database from the upload now in place; keep it, or put the earlier dump back."""
    try:
        ok, said = _dbs.restore(gs.remote, hd, gs.short_name, r.name, decrypt_secret(r.secret))
    except Exception:
        # The earlier dump goes back whatever ended the restore; the caller answers the failure.
        _settle(gs, r, e["uid"], False)
        raise
    kept = _settle(gs, r, e["uid"], bool(ok))
    if not ok:
        said = i18n.Sentences(said or i18n.Sentence("Failed"), i18n.Sentence(
            S_PREV_BACK if kept == "ok" else S_PREV_UNKNOWN))
    log_action(current_user, "db_upload", target=gs.name, server=gs, success=bool(ok),
               detail=_dbr._done_or_not(ok, "restored database %s from an uploaded dump of %d bytes" % (r.name, e["size"]),
                                        "database %s not restored from an uploaded dump" % r.name, said))
    return jsonify({"success": bool(ok), "message": i18n.tr(said or ("Database restored." if ok else "Failed"))}), \
        200 if ok else 502


def _upload_cancel(gs, r, uid):
    e = _get_upload(uid, r.id)
    if e is None:
        return _say(404, "No such upload.")
    _drop_upload(e["uid"])
    state, _v = _upcmd(gs, cancel_script(gs.short_name, e["uid"], r.name), 60)
    return jsonify({"success": state == "ok"})


# ── routes ───────────────────────────────────────────────────────────────────────────────────────
def _guarded(server_id, db_id, answer, what, *args):
    gs, r = _row(server_id, db_id)
    if r is None:
        return _say(404, _dbr._NO_SUCH)
    try:
        return answer(gs, r, *args)
    except Exception as exc:
        return _dbr._failed(exc, what)


def _dump_routes(app):
    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/dump", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_dump(server_id, db_id):
        """Dump the database into the server's files as its own account, for the download that follows."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _dump_answer, "dump")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/dump/download")
    @login_required
    @server_access_required
    def api_server_database_dump_download(server_id, db_id):
        """Download the database's dump from the server's files (read as the game account)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _download_answer, "dump download")


def _upload_routes(app):
    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/upload", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_upload(server_id, db_id):
        """Start uploading a dump to restore the database from (the step-up confirm first)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        if step_up_needed():
            return step_up_refusal()
        return _guarded(server_id, db_id, _upload_start, "upload")

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/upload/<uid>", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_upload_piece(server_id, db_id, uid):
        """Append one piece of the dump at its offset."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _upload_piece, "upload", uid)

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/upload/<uid>/finish", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_upload_finish(server_id, db_id, uid):
        """Check the whole dump on the host and restore the database from it (the name typed to confirm)."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _upload_finish, "upload", uid)

    @app.route("/api/server/<int:server_id>/databases/<int:db_id>/upload/<uid>/cancel", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_database_upload_cancel(server_id, db_id, uid):
        """Cancel an upload: its part file removed."""
        if not has_permission(current_user, MANAGE_DATABASES):
            return _say(403, _DENIED)
        return _guarded(server_id, db_id, _upload_cancel, "upload", uid)


def register(app):
    """The manager's dump download and upload routes."""
    _dump_routes(app)
    _upload_routes(app)
