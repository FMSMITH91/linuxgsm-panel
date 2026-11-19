"""What the SFTP service lets a client do to a game server's files, and what it audits.

The web file manager's rules (ssh_manager/files.py), applied to the path the HOST resolved:

* a name must pass name_problem (no control or text-direction characters, no space at either end,
  at most 255 bytes) when something new is made or a name is given (OWASP File Upload Cheat Sheet,
  "Filename Safety");
* the LinuxGSM control tree, serverfiles, the script and the account's own dot-files are never
  deleted or renamed, and their names are never taken (_is_protected_path);
* the live console's log and its folders are never deleted, renamed, replaced or taken
  (_console_paths), whatever the server's state: the service cannot ask whether it runs without a
  round trip per request, so it takes the safe answer;
* the account's sign-in files (~/.ssh, ~/.bashrc and the rest) are never written (_is_login_path);
* LinuxGSM's own _default.cfg is never written (LinuxGSM puts its copy back on every run);
* a LinuxGSM config that would switch logtimestamp on is refused whole, since that freezes the live
  console: such a file is staged in memory (at most STAGE_MAX) and checked before any byte is written.

The extension allow-list in the OWASP File Upload Cheat Sheet ("List Allowed Extensions") does not
fit: a game server's files are configs, scripts, maps, mods and binaries of every kind, so no list
could be short without breaking the purpose. What stands in its place: only users with edit_files on
that server (which docs/permissions.md describes as running commands as the account), writes as the
game account only, the size cap and the free-space check ("Upload and Download Limits").
"""
import posixpath
import stat as _stat
import threading
import time
import os as _os

from paramiko import SFTP_FAILURE, SFTP_OK, SFTP_OP_UNSUPPORTED, SFTP_PERMISSION_DENIED, SFTPHandle

from panel.ops.ssh_manager.files import (CMPC_DEFAULT_CFG_REFUSED, CREATE_RESERVED, DELETE_PROTECTED,
                                         LOGIN_FILE_REFUSED, _CMPC_DEFAULT_CFG_RE,
                                         _RAWLTS_REFUSED, _console_paths, _is_login_path,
                                         _is_protected_path, _rawlts_cfg_path, _rawlts_turns_on,
                                         name_problem)
from panel.services import sftp_backend as bk
from panel.services import sftp_common as sc

CONSOLE_REFUSED = ("The live console uses this path, so it is not changed over SFTP. Stop the server "
                   "and use the panel's file manager if it really must change.")
TOO_BIG = "This upload is larger than the panel's SFTP size limit."
NO_SPACE = "There is not enough free space on the server's host for this upload."
NOT_A_FILE = "Only files can be opened."
TOP_REFUSED = "The top folder lists your servers; files go inside a server's folder."
CROSS_SERVER = "Files can only be moved within one server's folder."
OWNER_REFUSED = "Files keep the game account as their owner."
STAGE_MAX = 1024 * 1024
MAX_OPEN_FILES = 64          # open files per session
WRITE_FAILED = "The write failed."
AUTHZ_HOLD = 1.0             # seconds an open file's reads and writes reuse the last permission answer
DENIED = "Permission denied"


class Refused(Exception):
    """A request the service turns down: an SFTP status code and the text the client is shown."""

    def __init__(self, code, text):
        """A refusal with SFTP status `code`, shown as `text`."""
        super().__init__(text)
        self.code, self.text = code, text

    def answer(self):
        """The (code, text) pair the SFTP server sends as the status."""
        return (self.code, self.text)


def _refused(code, text):
    return Refused(code, text)


def _write_problem(target, rel, existed):
    """Why a file write at `rel` (relative to the home) is refused, or None. `existed`: a file is there."""
    if not rel:
        return TOP_REFUSED
    if _is_login_path(rel):
        return LOGIN_FILE_REFUSED
    if _CMPC_DEFAULT_CFG_RE.fullmatch(posixpath.join("/home", target.user, rel)):
        return CMPC_DEFAULT_CFG_REFUSED
    if rel in _console_paths(target.selfname) or _above_console(rel, target.selfname):
        return CONSOLE_REFUSED
    if not existed:
        # A new file's name, as the file manager's upload checks it (upload_file): its name rules
        # only. A config or a mod lands under lgsm/ or serverfiles/, which are protected from
        # deletion and renaming, not from new files in them.
        return name_problem(posixpath.basename(rel))
    return None


def _new_name_problem(target, rel):
    """Why a new file or folder may not be made at `rel`, or None."""
    problem = name_problem(posixpath.basename(rel))
    if problem:
        return problem
    if _is_protected_path(rel, target.selfname):
        return CREATE_RESERVED
    if rel in _console_paths(target.selfname):
        return CONSOLE_REFUSED
    if _is_login_path(rel):
        return LOGIN_FILE_REFUSED
    return None


def _above_console(rel, selfname):
    """Whether `rel` is a folder above the console's log (writing a FILE there blocks the log)."""
    return any(p.startswith(rel + "/") for p in _console_paths(selfname))


def _removal_problem(target, rel):
    """Why `rel` may not be deleted (or renamed away), or None."""
    if not rel or _is_protected_path(rel, target.selfname):
        return DELETE_PROTECTED
    if rel in _console_paths(target.selfname):
        return CONSOLE_REFUSED
    return None


def _flags_to_pflags(flags):
    """SFTP open flags for the os.O_* flags paramiko hands the service."""
    acc = flags & (_os.O_RDONLY | _os.O_WRONLY | _os.O_RDWR)
    out = bk.P_READ if acc in (_os.O_RDONLY, _os.O_RDWR) else 0
    if acc in (_os.O_WRONLY, _os.O_RDWR):
        out |= bk.P_WRITE
    for os_flag, pflag in ((_os.O_APPEND, bk.P_APPEND), (_os.O_CREAT, bk.P_CREAT),
                           (_os.O_TRUNC, bk.P_TRUNC), (_os.O_EXCL, bk.P_EXCL)):
        if flags & os_flag:
            out |= pflag
    return out


def _mode_attrs(attr):
    """The permission bits a client asked for, without setuid, setgid and sticky; {} when none."""
    if attr is None or not (getattr(attr, "_flags", 0) & attr.FLAG_PERMISSIONS) or attr.st_mode is None:
        return {}
    return {"mode": attr.st_mode & 0o777}


class Files:
    """The service's file operations: open, and the changes (remove, rmdir, mkdir, rename, chattr)."""

    def __init__(self, cfg):
        """The operations under the service's settings (`cfg`: the upload cap)."""
        self.cap = int(cfg["cap_mb"]) * 1024 * 1024

    # ── open ──
    def open(self, vfs, path, flags, attr):
        """A ReadHandle or WriteHandle for `path`. Raises Refused or BackendError."""
        writing = bool(flags & (_os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_TRUNC | _os.O_APPEND))
        if vfs.open_count >= MAX_OPEN_FILES:
            raise _refused(SFTP_FAILURE, "Too many files are open in this session.")
        target, backend, real, rel = vfs.resolve(path, write=writing)
        try:
            a = backend.stat(real)
        except bk.BackendError as exc:
            if exc.code != bk.NO_SUCH_FILE or not writing:
                raise
            a = None
        if a is not None and not _stat.S_ISREG(a.get("mode", 0)):
            raise _refused(SFTP_FAILURE, NOT_A_FILE)
        if not writing:
            return ReadHandle(vfs, path, target, backend, backend.open(real, bk.P_READ))
        return self._open_for_write(vfs, path, (target, backend, real, rel), a, (flags, attr))

    def _open_for_write(self, vfs, path, resolved, a, how):
        """A WriteHandle once the file manager's write rules pass (`a`: the file's attributes, or None)."""
        target, backend, real, rel = resolved
        flags, attr = how
        why = _write_problem(target, rel, a is not None)
        if why:
            vfs.audit(target, "upload_file", "refused: %s: %s" % (rel, why), success=False)
            raise _refused(SFTP_PERMISSION_DENIED, why)
        info = {"rel": rel, "real": real, "existed": a is not None, "old": a or {},
                "limit": self._limit(backend, real, a),
                "readable": (flags & 3) == _os.O_RDWR, "mode": _mode_attrs(attr) if a is None else {}}
        if _rawlts_cfg_path(posixpath.join("/home", target.user, rel)):
            # A LinuxGSM config: nothing reaches the host until the whole file has been checked.
            info["staged_to"] = _staged_name(real)
            return WriteHandle(vfs, path, target, backend, None, info,
                               _stage_from(backend, real, a, flags))
        if a is None or flags & _os.O_TRUNC:
            # A whole file: written beside it and renamed into place at the close, as the file
            # manager saves (ssh_manager/files.py _write_file_as_user), so a refused or broken upload
            # leaves the file as it was, and a reader never sees half of it.
            info["staged_to"] = _staged_name(real)
            handle = backend.open(info["staged_to"], bk.P_WRITE | bk.P_CREAT | bk.P_EXCL | (
                bk.P_READ if info["readable"] else 0), info["mode"])
        else:
            handle = backend.open(real, _flags_to_pflags(flags), info["mode"])
        return WriteHandle(vfs, path, target, backend, handle, info)

    def _limit(self, backend, real, existing):
        """The largest end offset an upload here may reach: the cap, and the free space less the headroom."""
        free = backend.free_bytes(posixpath.dirname(real))
        if free is None:
            return self.cap
        have = (existing or {}).get("size", 0)
        return min(self.cap, max(0, free - sc.FREE_SPACE_SLACK) + have)

    # ── changes ──
    def change(self, vfs, op, path, new=None, attr=None):
        """Run one change and audit it; SFTP_OK or a (code, text) refusal."""
        try:
            return getattr(self, "_" + op)(vfs, path, new, attr)
        except Refused as r:
            return r.answer()
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def _remove(self, vfs, path, _new, _attr):
        return self._delete(vfs, path, folder=False)

    def _rmdir(self, vfs, path, _new, _attr):
        return self._delete(vfs, path, folder=True)

    def _delete(self, vfs, path, folder):
        target, backend, real, rel = vfs.resolve(path, write=True, follow=False)
        why = _removal_problem(target, rel)
        label = rel + ("/" if folder else "")
        if why:
            vfs.audit(target, "delete_file", "refused: %s: %s" % (label, why), success=False)
            raise _refused(SFTP_PERMISSION_DENIED, why)
        try:
            (backend.rmdir if folder else backend.remove)(real)
        except bk.BackendError as exc:
            vfs.audit(target, "delete_file", "%s (failed: %s)" % (label, exc), success=False)
            raise
        vfs.audit(target, "delete_file", label)
        return SFTP_OK

    def _mkdir(self, vfs, path, _new, attr):
        target, backend, real, rel = vfs.resolve(path, write=True)
        why = _new_name_problem(target, rel) if rel else TOP_REFUSED
        if why:
            vfs.audit(target, "create_folder", "refused: %s: %s" % (rel, why), success=False)
            raise _refused(SFTP_PERMISSION_DENIED, why)
        backend.mkdir(real, _mode_attrs(attr))
        vfs.audit(target, "create_folder", rel + "/")
        return SFTP_OK

    def _rename(self, vfs, path, new, _attr):
        if vfs.split(path)[0] != vfs.split(new)[0]:
            return (SFTP_OP_UNSUPPORTED, CROSS_SERVER)
        target, backend, real, rel = vfs.resolve(path, write=True, follow=False)
        _t2, _b2, real_new, rel_new = vfs.resolve(new, write=True, follow=False)
        detail = "%s -> %s" % (rel, rel_new)
        why = (_removal_problem(target, rel) or (LOGIN_FILE_REFUSED if _is_login_path(rel) else None)
               or (_new_name_problem(target, rel_new) if rel_new else TOP_REFUSED))
        if why:
            vfs.audit(target, "rename_file", "refused: %s: %s" % (detail, why), success=False)
            raise _refused(SFTP_PERMISSION_DENIED, why)
        backend.rename(real, real_new)
        vfs.audit(target, "rename_file", detail)
        return SFTP_OK

    def _chattr(self, vfs, path, _new, attr):
        target, backend, real, rel = vfs.resolve(path, write=True)
        attrs, note = _chattr_attrs(attr)
        why = OWNER_REFUSED if note else _chattr_problem(target, rel, attrs)
        if why:
            vfs.audit(target, "edit_file", "refused: %s: %s" % (rel, why), success=False)
            raise _refused(SFTP_PERMISSION_DENIED, why)
        if "size" in attrs and attrs["size"] > self.cap:
            raise _refused(SFTP_FAILURE, TOO_BIG)
        if attrs:
            backend.setstat(real, attrs)
        if "mode" in attrs or "size" in attrs:
            vfs.audit(target, "edit_file", "%s (%s)" % (rel, _attr_words(attrs)))
        return SFTP_OK


def _staged_name(real):
    """The name a whole-file upload is written to before it is renamed over `real`: hidden, unique, beside it."""
    import secrets
    folder, name = posixpath.split(real)
    return posixpath.join(folder, ".%s.panel-sftp-%s" % (name[:200], secrets.token_hex(6)))


def _stage_from(backend, real, existing, flags):
    """The staged contents a LinuxGSM config starts from: empty, or the file as it is when not truncated."""
    if existing is None or flags & _os.O_TRUNC:
        return bytearray()
    if existing.get("size", 0) > STAGE_MAX:
        raise _refused(SFTP_FAILURE, STAGE_TOO_BIG)
    handle = backend.open(real, bk.P_READ)
    try:
        out, off = bytearray(), 0
        while True:
            chunk = backend.read(handle, off, 32768)
            if not chunk or len(out) + len(chunk) > STAGE_MAX:
                break
            out += chunk
            off += len(chunk)
    finally:
        backend.close_handle(handle)
    return out


STAGE_TOO_BIG = "A LinuxGSM config file this large is not written over SFTP."


def _chattr_problem(target, rel, attrs):
    """Why a permission or size change at `rel` is refused, or None (times alone are always allowed)."""
    if "mode" in attrs and (not rel or _is_protected_path(rel, target.selfname)):
        return MODE_PROTECTED
    if "size" in attrs or "mode" in attrs:
        return _write_problem(target, rel, True)
    return None


MODE_PROTECTED = "This file/folder is protected — changing its permissions could break the server."


def _chattr_attrs(attr):
    """(the backend attrs for a SETSTAT, whether it asked to change the owner)."""
    flags = getattr(attr, "_flags", 0)
    out = {}
    if flags & attr.FLAG_PERMISSIONS and attr.st_mode is not None:
        out["mode"] = attr.st_mode & 0o777
    if flags & attr.FLAG_AMTIME and attr.st_mtime is not None:
        out["atime"], out["mtime"] = int(attr.st_atime or attr.st_mtime), int(attr.st_mtime)
    if flags & attr.FLAG_SIZE and attr.st_size is not None:
        out["size"] = int(attr.st_size)
    return out, bool(flags & attr.FLAG_UIDGID)


def _attr_words(attrs):
    parts = []
    if "mode" in attrs:
        parts.append("permissions %04o" % attrs["mode"])
    if "size" in attrs:
        parts.append("size %d" % attrs["size"])
    return ", ".join(parts)


class _Handle(SFTPHandle):
    """An open file: re-asks the panel (at most once a second) before reading or writing."""

    def __init__(self, vfs, path, target, backend, handle, write):
        """An open file `path` of `target`, `handle` on `backend`; `write`: opened for writing."""
        super().__init__()
        self.vfs, self.path, self.target = vfs, path, target
        self.backend, self.handle, self.write_mode = backend, handle, write
        self._checked = 0.0
        self._lock = threading.Lock()
        self.closed = False
        vfs.open_count += 1

    def allowed(self):
        """Whether the user may still use this file: the panel's answer, at most AUTHZ_HOLD old."""
        now = time.monotonic()
        if now - self._checked < AUTHZ_HOLD:
            return True
        try:
            got = self.vfs.ask_folder(self.vfs.split(self.path)[0], self.write_mode)
        except Refused:
            return False
        if got.key != self.target.key:
            return False
        self._checked = now
        return True

    def stat(self):
        """The open file's attributes."""
        try:
            return self.vfs.attrs_for(posixpath.basename(self.path), self.backend.fstat(self.handle))
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def _finish(self):
        if self.closed:
            return False
        self.closed = True
        self.vfs.open_count -= 1
        return True


class ReadHandle(_Handle):
    """A file opened for reading, with read-ahead for a client reading it in order."""

    def __init__(self, vfs, path, target, backend, handle):
        """A file opened for reading."""
        super().__init__(vfs, path, target, backend, handle, write=False)
        self.reader = bk.Reader(backend, handle)

    def read(self, offset, length):
        """Up to `length` bytes at `offset`."""
        if not self.allowed():
            return (SFTP_PERMISSION_DENIED, DENIED_NOW)
        try:
            return self.reader.read(offset, length)
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def write(self, offset, data):
        """Not open for writing."""
        return (SFTP_PERMISSION_DENIED, "This file was opened for reading.")

    def chattr(self, attr):
        """Not open for writing."""
        return (SFTP_PERMISSION_DENIED, "This file was opened for reading.")

    def close(self):
        """Close the file on the host."""
        if not self._finish():
            return
        try:
            self.reader.drop()
            self.backend.close_handle(self.handle)
        except bk.BackendError:
            bk._log.debug("closing a read handle", exc_info=True)


DENIED_NOW = "You no longer have permission to use this server's files."


class WriteHandle(_Handle):
    """A file opened for writing: the cap, the free space, the staged LinuxGSM config, and the audit row."""

    def __init__(self, vfs, path, target, backend, handle, info, stage=None):
        """A file opened for writing (`handle` None while a LinuxGSM config is staged in `stage`)."""
        super().__init__(vfs, path, target, backend, handle, write=True)
        self.info = info
        self.writer = bk.Writer(backend, handle) if handle is not None else None
        self.stage = stage
        self.high = len(stage) if stage is not None else 0
        self.failed = None

    def write(self, offset, data):
        """Write `data` at `offset` (pipelined; a failure is reported on a later write or the close)."""
        if self.failed:
            return (SFTP_FAILURE, self.failed)
        if not self.allowed():
            self.failed = DENIED_NOW
            return (SFTP_PERMISSION_DENIED, DENIED_NOW)
        end = offset + len(data)
        self.failed = self._size_problem(end)
        if self.failed:
            return (SFTP_FAILURE, self.failed)
        self.high = max(self.high, end)
        try:
            if self.stage is not None:
                if len(self.stage) < offset:
                    self.stage.extend(b"\0" * (offset - len(self.stage)))
                self.stage[offset:end] = data
            else:
                self.writer.write(offset, data)
        except bk.BackendError as exc:
            self.failed = str(exc) or "The write failed."
            return (exc.code, self.failed)
        return SFTP_OK

    def _size_problem(self, end):
        """Why a write reaching offset `end` is refused (the cap, the free space, a staged config's size)."""
        if end > self.vfs.service.files.cap:
            return TOO_BIG
        if end > self.info["limit"]:
            return NO_SPACE
        if self.stage is not None and end > STAGE_MAX:
            return STAGE_TOO_BIG
        return None

    def read(self, offset, length):
        """Read back what an upload opened read-write has written."""
        if not self.info["readable"]:
            return (SFTP_PERMISSION_DENIED, "This file was opened for writing.")
        if not self.allowed():
            return (SFTP_PERMISSION_DENIED, DENIED_NOW)
        if self.stage is not None:
            return bytes(self.stage[offset:offset + length])
        try:
            self.writer.flush()
            return self.backend.read(self.handle, offset, length)
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def chattr(self, attr):
        """Permission bits and times on the open file; never its owner."""
        attrs, owner = _chattr_attrs(attr)
        if owner:
            return (SFTP_PERMISSION_DENIED, OWNER_REFUSED)
        if attrs.get("size", 0) > self.vfs.service.files.cap:
            return (SFTP_FAILURE, TOO_BIG)
        if self.stage is not None:
            if "size" in attrs:
                del self.stage[attrs["size"]:]
            return SFTP_OK          # permission bits and times of a staged config: as LinuxGSM left them
        try:
            self.writer.flush()
            if attrs:
                self.backend.fsetstat(self.handle, attrs)
        except bk.BackendError as exc:
            return (exc.code, str(exc))
        return SFTP_OK

    def close(self):
        """Finish the upload on the host and audit it; None, or the (code, text) of its failure."""
        if not self._finish():
            return None
        why = self._finish_on_host(self.failed)
        ok, rel = why is None, self.info["rel"]
        size = len(self.stage) if self.stage is not None else self.high
        # "(overwrote)" only when it did: a refused upload left the file as it was.
        detail = "%s (%d bytes)%s" % (rel, size, " (overwrote)" if ok and self.info["existed"] else "")
        self.vfs.audit(self.target, "upload_file", detail if ok else "refused: %s: %s" % (detail, why), success=ok)
        return None if ok else (SFTP_FAILURE, why or "The upload failed.")

    def _finish_on_host(self, why):
        """Write a staged config, wait for every write, close, rename into place. -> why it failed, or None.

        `why`: the upload already failed (a refused write): everything is still closed, and the
        staged copy removed, so nothing of it is left on the host.
        """
        try:
            if self.stage is not None and why is None:
                why = self._write_stage()
            if self.writer is not None:
                self.writer.flush()
        except bk.BackendError as exc:
            why = why or str(exc) or WRITE_FAILED
        return self._into_place(self._close_on_host(why))

    def _close_on_host(self, why):
        """Close the host's handle, if one is open; `why`, or the close's own failure."""
        if self.handle is None:
            return why
        try:
            self.backend.close_handle(self.handle)
        except bk.BackendError as exc:
            return why or str(exc) or WRITE_FAILED
        return why

    def _into_place(self, why):
        """Rename the staged copy over the file (with the file's mode), or remove it when the upload failed."""
        staged = self.info.get("staged_to")
        if staged is None or (self.stage is not None and self.handle is None):
            return why
        try:
            if why is None:
                if self.info["existed"] and "mode" in self.info.get("old", {}):
                    self.backend.setstat(staged, {"mode": self.info["old"]["mode"] & 0o7777})
                self.backend.replace(staged, self.info["real"])
                return None
        except bk.BackendError as exc:
            why = str(exc) or "The file could not be put in place."
        try:
            self.backend.remove(staged)
        except bk.BackendError:
            bk._log.debug("could not remove a staged upload", exc_info=True)
        return why

    def _write_stage(self):
        """Write a staged LinuxGSM config whole, unless it switches logtimestamp on. -> why not, or None.

        Refused, nothing of it reaches the host: the file stays exactly as it was.
        """
        data = bytes(self.stage)
        if _rawlts_turns_on(data):
            return _RAWLTS_REFUSED
        self.handle = self.backend.open(self.info["staged_to"], bk.P_WRITE | bk.P_CREAT | bk.P_EXCL, self.info["mode"])
        self.writer = bk.Writer(self.backend, self.handle)
        for off in range(0, len(data), 32768):
            self.writer.write(off, data[off:off + 32768])
        return None
