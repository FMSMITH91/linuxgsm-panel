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

NAME_RE = re.compile(r"backup-[0-9]{8}-[0-9]{6}(?:-[0-9]{1,3})?\.tar\.gz\Z")
_TOPS = ("site/html", "panel-db-dumps")
S_CREATED = "Backup made."
S_FAILED = "The backup could not be made on the host."
S_BAD_NAME = "No such backup."
S_REFUSED = "That backup holds {name}, which a restore never writes. Nothing was restored."
S_RESTORED = "Backup restored."
S_RESTORE_FAILED = "The backup could not be unpacked; the website's files were put back as they were."


def new_stem(now=None):
    """A backup's name for now (UTC), without its extension: backup-YYYYmmdd-HHMMSS."""
    return time.strftime("backup-%Y%m%d-%H%M%S", time.gmtime(now))


def _home(account):
    """The site account's home, quoted for the shell: named, never `~` (sudo may keep the caller's HOME)."""
    return _core._quote("/home/%s" % account)


def _as_site(remote, account, sh, timeout=600):
    """Run panel-built shell `sh` as the site's account: (out, err, rc)."""
    return _core.shell_as_game_user(remote, account, sh, timeout=timeout)


def create(remote, account, keep, stem=None):
    """Make a backup now and keep the newest `keep`: (ok, sentence, file name).

    Two backups in one second (a restore's safety backup right after Back up now) never share a name:
    the host takes the first of backup-<time>.tar.gz, backup-<time>-1.tar.gz, ... that is free.
    """
    q = _core._quote
    stem = stem or new_stem()
    pattern = q("^backup-[0-9]{8}-[0-9]{6}(-[0-9]{1,3})?[.]tar[.]gz$")
    sh = (f'cd {_home(account)} || exit 3; mkdir -p site/backups && chmod 0700 site/backups || exit 3; '
          f'b={q(stem)}; n="$b.tar.gz"; i=1; '
          'while [ -e "site/backups/$n" ] || [ -L "site/backups/$n" ]; do n="$b-$i.tar.gz"; i=$((i+1)); '
          '[ "$i" -gt 999 ] && exit 5; done; '
          'set -- site/html; [ -d panel-db-dumps ] && set -- "$@" panel-db-dumps; '
          'tar -czf "site/backups/$n.part" --no-acls --no-xattrs -- "$@" '
          '&& mv -fT -- "site/backups/$n.part" "site/backups/$n" || { rm -f -- "site/backups/$n.part"; exit 4; }; '
          f'ls -1t site/backups | grep -E {pattern} | tail -n +{int(keep) + 1} '
          '| while IFS= read -r old; do rm -f -- "site/backups/$old"; done; echo "__OK__ $n"')
    out, _err, rc = _as_site(remote, account, sh)
    words = (out or "").split()
    name = words[words.index("__OK__") + 1] if "__OK__" in words[:-1] else ""
    ok = rc == 0 and bool(NAME_RE.match(name))
    return ok, S_CREATED if ok else S_FAILED, name if ok else ""


def listing(remote, account):
    """The site's backups, newest first: [{name, size, mtime}], or None when the host did not answer."""
    sh = (f'cd {_home(account)}/site/backups 2>/dev/null || exit 0; '
          "find . -maxdepth 1 -type f -name 'backup-*.tar.gz' -printf '%f\\t%s\\t%T@\\n'")
    out, _err, rc = _as_site(remote, account, sh, timeout=30)
    if rc != 0:
        return None
    rows = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and NAME_RE.match(parts[0]) and parts[1].isdecimal():
            rows.append({"name": parts[0], "size": int(parts[1]), "mtime": int(float(parts[2] or 0))})
    return sorted(rows, key=lambda r: (r["mtime"], r["name"]), reverse=True)


def delete(remote, account, name):
    """Delete backup `name`: (ok, sentence)."""
    if not NAME_RE.match(name or ""):
        return False, S_BAD_NAME
    sh = "rm -f -- %s/site/backups/%s && echo __OK__" % (_home(account), _core._quote(name))
    out, _err, rc = _as_site(remote, account, sh, 30)
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
    sh = "tar -tvzf %s/site/backups/%s --quoting-style=c" % (_home(account), _core._quote(name))
    out, _err, rc = _as_site(remote, account, sh, timeout=300)
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
    sh = (f'cd {_home(account)} || exit 3; '
          f'mv -T -- site/html site/html.before-{stamp} || exit 3; '
          f'if tar -xzf site/backups/{q} --no-same-owner --no-same-permissions -- site/html; then '
          f'rm -rf -- site/html.before-{stamp}; '
          f'tar -xzf site/backups/{q} --no-same-owner --no-same-permissions -- panel-db-dumps 2>/dev/null; echo __OK__; '
          f'else rm -rf -- site/html; mv -T -- site/html.before-{stamp} site/html; exit 4; fi')
    out, _err, rc = _as_site(remote, account, sh)
    ok = rc == 0 and "__OK__" in (out or "")
    return ok, S_RESTORED if ok else S_RESTORE_FAILED
