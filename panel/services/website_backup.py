"""A website's backups: a .tar.gz of its document root and its databases' dumps, in ~/site/backups.

Every command runs as the site's account (never root), so a backup can only read what the site
itself can, and a restore can only write where the site itself can. A backup holds `site/html` and,
when the site has databases, their dumps (`panel-db-dumps`, written by the Databases tab's own dump
verb just before). The newest `backup_keep` are kept.

A restore first takes a safety backup, then lists the archive and refuses it unless every entry is
a plain file or folder under site/html or panel-db-dumps with no ".." (OWASP File Upload Cheat
Sheet, archive handling; Path Traversal: the archive's names are never trusted), moves the current
document root aside, unpacks with no owners or modes from the archive, and puts the old one back if
unpacking fails.
"""
import re
import time

from panel.ops.ssh_manager import _core

NAME_RE = re.compile(r"backup-[0-9]{8}-[0-9]{6}\.tar\.gz\Z")
_TOPS = ("site/html", "panel-db-dumps")
S_CREATED = "Backup made."
S_FAILED = "The backup could not be made on the host."
S_BAD_NAME = "No such backup."
S_REFUSED = "That backup holds {name}, which a restore never writes. Nothing was restored."
S_RESTORED = "Backup restored."
S_RESTORE_FAILED = "The backup could not be unpacked; the website's files were put back as they were."


def new_name(now=None):
    """A backup file name for now (UTC)."""
    return time.strftime("backup-%Y%m%d-%H%M%S.tar.gz", time.gmtime(now))


def _run(remote, account, sh, timeout=600):
    return _core.shell_as_game_user(remote, account, sh, timeout=timeout)


def create(remote, account, keep, name=None):
    """Make a backup now and keep the newest `keep`: (ok, sentence, file name)."""
    name = name or new_name()
    q = _core._quote
    sh = ('cd ~ || exit 3; mkdir -p site/backups && chmod 0700 site/backups || exit 3; '
          'set -- site/html; [ -d panel-db-dumps ] && set -- "$@" panel-db-dumps; '
          f'tar -czf site/backups/{q(name)}.part --no-acls --no-xattrs -- "$@" '
          f'&& mv -f -- site/backups/{q(name)}.part site/backups/{q(name)} || {{ rm -f -- site/backups/{q(name)}.part; exit 4; }}; '
          f'ls -1t site/backups | grep -E {q("^backup-[0-9]{8}-[0-9]{6}[.]tar[.]gz$")} | tail -n +{int(keep) + 1} '
          '| while IFS= read -r old; do rm -f -- "site/backups/$old"; done; echo __OK__')
    out, _err, rc = _run(remote, account, sh)
    ok = rc == 0 and "__OK__" in (out or "")
    return ok, S_CREATED if ok else S_FAILED, name


def listing(remote, account):
    """The site's backups, newest first: [{name, size, mtime}], or None when the host did not answer."""
    sh = ('cd ~/site/backups 2>/dev/null || exit 0; '
          "find . -maxdepth 1 -type f -name 'backup-*.tar.gz' -printf '%f\\t%s\\t%T@\\n'")
    out, _err, rc = _run(remote, account, sh, timeout=30)
    if rc != 0:
        return None
    rows = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and NAME_RE.match(parts[0]) and parts[1].isdecimal():
            rows.append({"name": parts[0], "size": int(parts[1]), "mtime": int(float(parts[2] or 0))})
    return sorted(rows, key=lambda r: r["name"], reverse=True)


def delete(remote, account, name):
    """Delete backup `name`: (ok, sentence)."""
    if not NAME_RE.match(name or ""):
        return False, S_BAD_NAME
    out, _err, rc = _run(remote, account, "rm -f -- ~/site/backups/%s && echo __OK__" % _core._quote(name), 30)
    return (rc == 0 and "__OK__" in (out or "")), "Backup deleted."


def entry_problem(line):
    """The entry a `tar -tvzf --quoting-style=c` line names when a restore must refuse it, else None."""
    first, last = line.find('"'), line.rfind('"')
    if first < 0 or last <= first:
        return line[:120] or "(empty)"
    name = line[first + 1:last]
    clean = name.rstrip("/")
    ok_type = line[:1] in ("-", "d")
    under = any(clean == t or clean.startswith(t + "/") for t in _TOPS)
    if not ok_type or not under or ".." in clean.split("/") or "\\" in clean:
        return name[:120]
    return None


def check_archive(remote, account, name):
    """None when backup `name` may be restored, else the first entry that refuses it (or S_BAD_NAME)."""
    if not NAME_RE.match(name or ""):
        return S_BAD_NAME
    sh = "tar -tvzf ~/site/backups/%s --quoting-style=c" % _core._quote(name)
    out, _err, rc = _run(remote, account, sh, timeout=300)
    if rc != 0:
        return S_BAD_NAME
    for line in (out or "").splitlines():
        bad = entry_problem(line)
        if bad:
            return bad
    return None


def restore(remote, account, name):
    """Unpack backup `name` over the document root (it was checked by check_archive): (ok, sentence)."""
    q = _core._quote(name)
    stamp = str(int(time.time()))
    sh = ('cd ~ || exit 3; '
          f'mv -T -- site/html site/html.before-{stamp} || exit 3; '
          f'if tar -xzf site/backups/{q} --no-same-owner --no-same-permissions -- site/html; then '
          f'rm -rf -- site/html.before-{stamp}; '
          f'tar -xzf site/backups/{q} --no-same-owner --no-same-permissions -- panel-db-dumps 2>/dev/null; echo __OK__; '
          f'else rm -rf -- site/html; mv -T -- site/html.before-{stamp} site/html; exit 4; fi')
    out, _err, rc = _run(remote, account, sh)
    ok = rc == 0 and "__OK__" in (out or "")
    return ok, S_RESTORED if ok else S_RESTORE_FAILED
