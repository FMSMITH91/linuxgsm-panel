"""A website's files: its document root, the disk it may use, and archives unpacked into it.

The file manager of a site reuses the game servers' primitives (ssh_manager/files.py) as the site's own
account, held to the document root ~/site/html by files.confined_to: the same lexical check, the same
host-side check of where a path resolves (a symbolic link included), the same sign-in path refusals.

ARCHIVES (Upload archive and extract). OWASP File Upload Cheat Sheet ("Upload and Download Limits":
sizes checked after decompression with a safe way of computing them; "Filename Safety"; "User
Permissions"; "Filesystem Permissions") and Input Validation Cheat Sheet ("Parse Safely, Then
Validate": limits before parsing). The panel reads the zip or tar.gz itself and refuses the whole
archive when one entry is absolute, climbs with "..", is a symbolic or hard link, a device, a fifo or
anything but a plain file or folder, when it holds more than MAX_ENTRIES entries or folders deeper than
MAX_DEPTH, when one zip entry is compressed more than MAX_RATIO to one (a zip bomb), or when what it
unpacks to is more than the site's free disk or ABS_MAX_UNPACKED. Sizes are counted from the bytes
actually read, never from the archive's own header. What passes is written again as a new tar of
plain files and folders only (modes 0644 and 0755, no owners), and that is what the host unpacks, as
the site's account (never root), into the folder chosen: nothing the uploader shaped reaches tar.
"""
import io
import posixpath
import stat
import tarfile
import tempfile
import zipfile

from panel.core import i18n
from panel.ops.ssh_manager import _core
from panel.ops.ssh_manager import files as _files

DOCROOT = "site/html"
BACKUPS = "site/backups"
MIB = 1024 * 1024
# The most entries one archive may hold, the deepest folder it may make, the most one zip entry may
# expand per compressed byte, and the most any archive may unpack to whatever the site's disk allows.
MAX_ENTRIES = 20000
MAX_DEPTH = 32
MAX_RATIO = 200
ABS_MAX_UNPACKED = 2048 * MIB
_READ = 1024 * 1024
_SPOOL = 16 * MIB

S_BAD_ENTRY = "The archive holds {name}, which is not a plain file or folder inside it. Nothing was unpacked."
S_TOO_MANY = "The archive holds more than {n} entries. Nothing was unpacked."
S_TOO_DEEP = "The archive has folders more than {n} levels deep. Nothing was unpacked."
S_BOMB = "The archive's entry {name} expands far more than real files do. Nothing was unpacked."
S_TOO_BIG = "The archive unpacks to more than the {mb} MB this website has free. Nothing was unpacked."
S_NOT_ARCHIVE = "This is not a zip or .tar.gz archive the panel can read. Nothing was unpacked."
S_DISK_FULL = "This website has used all of its {mb} MB of disk. Delete something first."
S_DISK_UNREAD = "Couldn't measure how much disk this website uses, so nothing was written. Try again."


class ArchiveRefused(Exception):
    """An archive the panel will not unpack; `sentence` (the panel's own words) is what the page is told."""

    def __init__(self, sentence):
        super().__init__(sentence)
        self.sentence = sentence


def docroot_rel(path):
    """`path` (relative to the document root, as the page sends it) relative to the account's home, or None.

    None for anything that climbs out of the document root by its text ("../x", "a/../../x"): refused,
    never clamped to the root. Where it resolves on the host is files.confined_to's question.
    """
    if not isinstance(path, str) or "\x00" in path or len(path) > 4096:
        return None
    rel = posixpath.normpath(path.lstrip("/") or ".")
    if rel == ".." or rel.startswith("../"):
        return None
    return DOCROOT if rel == "." else posixpath.join(DOCROOT, rel)


def page_rel(rel):
    """A path relative to the account's home as the page shows it: relative to the document root."""
    rel = (rel or "").strip("/")
    return "" if rel == DOCROOT else rel[len(DOCROOT) + 1:] if rel.startswith(DOCROOT + "/") else rel


def _unsafe_text(name):
    """Whether an entry name is not text a path can be made of: empty, NUL, a backslash, absolute, a drive."""
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        return True
    return name.startswith("/") or (len(name) > 1 and name[1] == ":")


def _entry_name(name):
    """An archive entry's name as a safe relative path ("a/b.txt"), or None when it may not be one."""
    if _unsafe_text(name):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or any(_files.name_problem(p) for p in parts):
        return None
    return "/".join(parts)


class _Budget:
    """Counts entries and unpacked bytes against the archive's limits."""

    def __init__(self, room):
        self.room = max(0, min(int(room), ABS_MAX_UNPACKED))
        self.entries = 0
        self.total = 0

    def entry(self, clean):
        self.entries += 1
        if self.entries > MAX_ENTRIES:
            raise ArchiveRefused(i18n.tr(S_TOO_MANY, n=MAX_ENTRIES))
        if clean.count("/") + 1 > MAX_DEPTH:
            raise ArchiveRefused(i18n.tr(S_TOO_DEEP, n=MAX_DEPTH))

    def take(self, n):
        self.total += n
        if self.total > self.room:
            raise ArchiveRefused(i18n.tr(S_TOO_BIG, mb=self.room // MIB))


def _refuse(name):
    raise ArchiveRefused(i18n.tr(S_BAD_ENTRY, name=repr(str(name)[:120])))


def _copy(src, dst, budget, limit=None, name=""):
    """Copy `src` to `dst`, counting every byte read against `budget` (and `limit` for entry `name`)."""
    got = 0
    while True:
        block = src.read(_READ)
        if not block:
            return got
        got += len(block)
        budget.take(len(block))
        if limit is not None and got > limit:
            raise ArchiveRefused(i18n.tr(S_BOMB, name=repr(name[:120])))
        dst.write(block)


class _Repack:
    """The clean tar being written: plain files and folders, each parent folder before what is in it."""

    def __init__(self, out):
        self.tar = tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT)  # pylint: disable=consider-using-with
        self.dirs = set()

    def folder(self, path):
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            sub = "/".join(parts[:i])
            if sub not in self.dirs:
                self.dirs.add(sub)
                info = tarfile.TarInfo(sub)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                self.tar.addfile(info)

    def file(self, path, size, data):
        if posixpath.dirname(path):
            self.folder(posixpath.dirname(path))
        info = tarfile.TarInfo(path)
        info.size, info.mode = size, 0o644
        self.tar.addfile(info, data)

    def close(self):
        self.tar.close()


def _stage(src, budget, limit=None, name=""):
    """`src` copied to a spooled temporary file (counted); -> (file at 0, size)."""
    tmp = tempfile.SpooledTemporaryFile(max_size=_SPOOL)  # pylint: disable=consider-using-with
    try:
        size = _copy(src, tmp, budget, limit, name)
    except Exception:
        tmp.close()
        raise
    tmp.seek(0)
    return tmp, size


def _from_zip(fh, budget, pack):
    with zipfile.ZipFile(fh) as zf:
        for info in zf.infolist():
            clean = _entry_name(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if clean is None or (mode and mode not in (stat.S_IFREG, stat.S_IFDIR)):
                _refuse(info.filename)
            budget.entry(clean)
            if info.is_dir():
                pack.folder(clean)
                continue
            limit = max(info.compress_size, 1) * MAX_RATIO
            with zf.open(info) as src:
                tmp, size = _stage(src, budget, limit, clean)
            with tmp:
                pack.file(clean, size, tmp)


def _from_tar(fh, budget, pack):
    with tarfile.open(fileobj=fh, mode="r:*") as tf:
        for member in tf:
            clean = _entry_name(member.name)
            if clean is None or not (member.isreg() or member.isdir()):
                _refuse(member.name)
            budget.entry(clean)
            if member.isdir():
                pack.folder(clean)
                continue
            src = tf.extractfile(member)
            if src is None:
                _refuse(member.name)
            with src:
                tmp, size = _stage(src, budget)
            with tmp:
                pack.file(clean, size, tmp)


def repack(fh, room):
    """The archive in file `fh` (zip, tar, tar.gz) checked and written again as a clean tar.

    -> (a file positioned at 0 holding the clean tar, its unpacked size in bytes). Raises
    ArchiveRefused naming the first entry or limit that refused it. `room` is the site's free disk
    in bytes.
    """
    budget = _Budget(room)
    out = tempfile.SpooledTemporaryFile(max_size=_SPOOL)  # pylint: disable=consider-using-with
    pack = _Repack(out)
    try:
        head = fh.read(4)
        fh.seek(0)
        if head.startswith(b"PK"):
            _from_zip(fh, budget, pack)
        else:
            _from_tar(fh, budget, pack)
        pack.close()
    except ArchiveRefused:
        out.close()
        raise
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, ValueError) as exc:
        out.close()
        raise ArchiveRefused(i18n.tr(S_NOT_ARCHIVE)) from exc
    out.seek(0)
    return out, budget.total


# ── disk ────────────────────────────────────────────────────────────────────────────────────────
def used_bytes(remote, account):
    """How many bytes the site's account uses in its home (du -sxb, as the account), or None."""
    home = _core._quote("/home/%s" % account)
    out, _err, rc = _core.shell_as_game_user(remote, account, "du -sxb -- %s 2>/dev/null | cut -f1" % home,
                                             timeout=60)
    text = (out or "").strip()
    return int(text) if rc == 0 and text.isdecimal() else None


def room_bytes(remote, site):
    """(bytes the site may still write, refusal sentence or None): its disk limit less what it uses."""
    used = used_bytes(remote, site.account)
    if used is None:
        return 0, i18n.tr(S_DISK_UNREAD)
    room = int(site.disk_mb) * MIB - used
    if room <= 0:
        return 0, i18n.tr(S_DISK_FULL, mb=int(site.disk_mb))
    return room, None


def extract(remote, account, reldir, tar_file):
    """Unpack the clean tar in `tar_file` into the folder `reldir` (home-relative) as `account`.

    -> (ok, message). Run under files.confined_to(DOCROOT) by the caller; the folder is checked on
    the host as every write is (it must resolve inside the document root and not be a sign-in path),
    and tar takes no owners or modes from the archive.
    """
    ap = _files._safe_abspath(account, reldir)
    if ap is None:
        return False, "Invalid path"
    inner = ('[ -d "$p" ] && [ ! -L "$p" ] || { echo __NOT_A_FOLDER__; exit 4; }; '
             'base64 -d | tar -x --no-same-owner --no-same-permissions --no-overwrite-dir -C "$p" -f - '
             '&& echo __OK__')
    body = io.BytesIO()
    while True:
        block = tar_file.read(_READ)
        if not block:
            break
        body.write(block)
    out, _err, rc = _core.shell_as_game_user(remote, account, _files._guarded_write(account, ap, inner),
                                             timeout=600, stdin_text=_files._b64_stdin(body.getvalue()))
    text = out or ""
    if _files._r12b_outside_home(text) or "__NOT_A_FOLDER__" in text:
        return False, "Invalid path"
    if rc == 0 and "__OK__" in text:
        return True, "Unpacked."
    return False, "The host could not unpack the archive. Nothing may have been written; check the folder."
