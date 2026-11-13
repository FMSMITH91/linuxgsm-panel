"""Restoring a game server from one of its own LinuxGSM backups: the parts that need no Flask.

LinuxGSM has no restore command (core_getopt.sh and docs.linuxgsm.com/commands/backup, master
2026-11), so the panel does it. What a LinuxGSM backup holds (lgsm/modules/command_backup.sh,
master 2026-11, #5129):

* `tar <flag> -hcf <backupdir>/<selfname>-<date>.tar.<zst|gz> --exclude <backupdir under rootdir>
  --exclude <lockdir> --exclude <tmpdir> -C <rootdir> ./. [-C / <extra dirs>]`. The panel's
  instances live in the game account's home, so rootdir IS the home and every member is named
  under it: "././<path>" from GNU tar 1.35 ("./<path>" from a tar that tidies the name).
* lockdir and tmpdir are given as absolute paths and match no member name, so lgsm/lock (with the
  backup's own backup.lock) and lgsm/tmp ARE in the archive. Only the backup dir is left out.
* `-h` stores what a symlink points to, not the link: a symlinked file comes back as a regular
  file, a symlinked folder as a real folder holding the link target's files.
* Extra dirs (game data kept outside rootdir) are added only when NOT under rootdir; with rootdir
  the home they are outside the account's home, which a restore refuses to write.

The restore, one command per step, each as the game account (no root, no helper path):

1. vet_script: LinuxGSM's locks; the archive read through its decompressor (`tar -tv`) to its
   end, every member checked (rootdir-relative, no `..`, only files, folders and hard links to
   members already vetted); the account owns everything it would clear; no symlinked folder points
   outside what is cleared; enough space; then the archive is renamed aside and touched
   (HOLD_INFIX) so the pre-restore backup's retention cannot prune it: LinuxGSM deletes by name
   (`*.tar.*`, oldest first, past maxbackups) and by age (any file older than maxbackupdays).
2. (the route) LinuxGSM `stop` when it was running, then a LinuxGSM backup of the stopped server
   through the panel's backup path: the undo.
3. restore_script: the server is down and nothing of the account still holds serverfiles, then
   the home is cleared except KEEP and extracted from the archive, and the archive is put back
   under its name and time on every exit.

KEEP is what is never cleared nor extracted: LinuxGSM's own backup, lock and tmp dirs (the
archive's copies of the last two are stale run-time state), and the account's own state that is not
the game's and lives outside the archive's world: ~/.ssh (an old authorized_keys would bring back a
key removed since), the panel's cron wrapper folder ~/.lgsm-cron (the crontab that runs it is not
in the archive) and its restart flag.
"""
import re

from panel.core import i18n, terminal
from panel.ops import ssh_manager as _sm
from panel.services import world_reset as _wwr

# Relative to the home. Never cleared, never extracted.
KEEP = ("lgsm/backup", "lgsm/lock", "lgsm/tmp", ".ssh", ".lgsm-cron", ".restart-pending")
# The compressions LinuxGSM writes (fn_select_compression), and GNU tar's flag to read each.
_GRS_FLAGS = {"zst": "--zstd", "gz": "--gzip"}
# A LinuxGSM backup's name: <selfname>-<date>.tar.<ext>. A ".tar." inside the stem is refused: the
# name the archive is held under while the undo is taken must not match LinuxGSM's `*.tar.*`.
_GRS_NAME = re.compile(r"([A-Za-z0-9_][A-Za-z0-9._-]{0,127})\.tar\.(zst|gz)\Z")
HOLD_INFIX = ".restore-source-"
# Free space left over once the archive is unpacked, so the game can still write its logs and saves.
MARGIN = 256 * 1024 * 1024
# How long the account's processes get to let go of serverfiles after the stop: polls of 2 seconds.
_GRS_BUSY_POLLS = 30

_M = {k: "__GRS_%s__" % k for k in (
    "LOCKED", "NOARCHIVE", "NOHOME", "NOPY", "TARFAIL", "BAD", "FOREIGN", "LINKOUT", "SPACE",
    "HOLDFAIL", "READY", "UP", "DOWN", "NOUNDO", "RUNNING", "BUSY", "CLEARING", "RMFAIL", "XFAIL",
    "RESTORED", "NOPART", "UPOFFSET", "UPSIZE", "UPREADY", "UPFAIL", "UPFORMAT", "UPSTORED")}

# A decompression bomb's bound: what the members declare may not pass RATIO times the archive's own
# size plus RATIO_SLACK. Game data packs at a few to one (worlds and assets are mostly compressed
# already); a hundred to one is past any real server, and the check stops reading at the first
# header that passes it, so tar is never made to unpack the rest. The space check bounds the disk
# on top of this.
RATIO = 100
RATIO_SLACK = 1024 * 1024 * 1024

# The member check, run by python3 (a LinuxGSM dependency on every distro it supports) over
# `tar -tv --quoting-style=c --numeric-owner`. Each line: type+mode, uid/gid, size, date, time,
# "name" [-> "target" | link to "target"]. A device's size is "major,minor" and matches nothing:
# refused as unreadable. Names are compared as GNU tar quoted them (the C style escapes only
# unprintable bytes, never "/" or "."), so no decoding is needed. Prints one verdict line.
_GRS_VET_PY = r'''import re,sys
bs=max(512,int(sys.argv[1]));me=sys.argv[2];cap=int(sys.argv[3])*%d+%d;keep=sys.argv[4:]
R=re.compile(r'^(\S)\S*\s+\d+/\d+\s+(\d+)\s+\S+\s+\S+\s+"((?:[^"\\]|\\.)*)"(?:\s+(?:->|link to)\s+"((?:[^"\\]|\\.)*)")?$')
def rel(n):
    for p in ("././","./"):
        if n.startswith(p):
            r=n[len(p):].rstrip("/")
            if r=="":
                return r
            if r.startswith("/") or any(c in ("",".","..") for c in r.split("/")):
                return None
            return r
    return None
def kept(r):
    return any(r==k or r.startswith(k+"/") for k in keep)
bad="";seen=set();size=0;n=0;script=False;tot=0
for raw in sys.stdin.buffer:
    if bad:
        continue
    m=R.match(raw.decode("utf-8","replace").rstrip("\n"))
    if not m:
        bad="parse";continue
    t,sz,name,link=m.group(1),int(m.group(2)),m.group(3),m.group(4)
    tot+=sz
    if tot>cap:
        print("__GRS_BAD__ bomb");sys.exit(0)
    r=rel(name)
    if r is None:
        bad="name";continue
    if t=="h":
        lr=rel(link or "")
        if lr is None or lr not in seen or kept(lr):
            bad="link";continue
    elif t not in "-d" or (r=="" and t!="d"):
        bad="type";continue
    if kept(r):
        continue
    n+=1
    if t=="-":
        seen.add(r);size+=-(-sz//bs)*bs;script=script or r==me
    elif t=="d":
        size+=bs
if not bad and not script:
    bad="script"
print("__GRS_BAD__ "+bad if bad else "__GRS_LIST__ %%d %%d"%%(size,n))
''' % (RATIO, RATIO_SLACK)


def archive_problem(name):
    """Why `name` is not an archive the panel restores (an i18n.Sentence), or None.

    The caller has already found it in the server's own listing; this is the shape on top.
    """
    m = _GRS_NAME.match(name or "")
    if not m or ".tar." in m.group(1) or HOLD_INFIX in m.group(1):
        return i18n.Sentence("Only a LinuxGSM backup named <script>-<date>.tar.zst or .tar.gz can be restored.")
    return None


def _q(s):
    return _sm._quote(s)


# The KEEP paths as words: relative for find (./x), under the resolved home for a case pattern.
# Every KEEP name is plain [A-Za-z0-9./-] text, so it needs no quoting beyond the double quotes.
_GRS_KEEP_FIND = " -o ".join("-path ./%s" % k for k in KEEP)
_GRS_KEEP_REAL = " ".join('"$HR/%s"' % k for k in KEEP)
_GRS_KEEP_REL = " ".join("./%s" % k for k in KEEP)


def _grs_head(user, selfname):
    """The world reset's opening lines (C locale, cd /, LinuxGSM's locks, $s), printing this module's lock mark."""
    return [ln.replace(_wwr._M_LOCKED, _M["LOCKED"]) for ln in _wwr._wwr_head(user, selfname)]


def _grs_home_lines(user):
    """$B (the backup dir) and the resolved home $HR, made the cwd; refuses when it does not resolve."""
    return [
        "B=%s" % _q("/home/%s/lgsm/backup" % user),
        'HR=$(cd -P -- %s 2>/dev/null && pwd -P && printf x) && HR=${HR%%?x} || HR=' % _q("/home/" + user),
        'case "$HR" in ""|/) echo %s; exit 3;; esac' % _M["NOHOME"],
    ]


def _grs_walks():
    """Lines (cwd the resolved home) refusing what the clear could not undo faithfully, then measuring space.

    * an entry the clear would remove that the account does not own: it could not remove it;
    * a symlinked folder whose target is not itself cleared and restored: outside the home, the
      home itself or above it, or a KEEP path or above one. The clear keeps every symlinked folder
      and the extraction writes through it (--keep-directory-symlink), so it must point at
      something the restore rebuilds anyway; anything else would mix old and new files, or put
      the archive's copy of it on another filesystem. The targets are kept in `lt` (restore_script
      makes them again after the clear, so the link is not left dangling).
    Then `tot` (the home's usage on its filesystem), `kb` (KEEP's share of it) and `free`.
    """
    return [
        "k=( \\( %s \\) -prune -o )" % _GRS_KEEP_FIND,
        'if [ -n "$(find . -mindepth 1 "${k[@]}" ! -user "$(id -u)" -print -quit 2>/dev/null)" ]; then '
        'echo %s; exit 5; fi' % _M["FOREIGN"],
        'lt=(); while IFS= read -r -d "" l; do r=$(readlink -f -- "$l" 2>/dev/null) || r=; '
        'case "$r" in "$HR"/*) ;; *) echo %s; exit 5;; esac; '
        'for kp in %s; do case "$r" in "$kp"|"$kp"/*) echo %s; exit 5;; esac; '
        'case "$kp" in "$r"/*) echo %s; exit 5;; esac; done; lt+=("$r"); '
        'done < <(find . -mindepth 1 "${k[@]}" -type l -xtype d -print0 2>/dev/null)'
        % (_M["LINKOUT"], _GRS_KEEP_REAL, _M["LINKOUT"], _M["LINKOUT"]),
        'tot=$(du -sxB1 . 2>/dev/null | cut -f1); kb=$(du -scxB1 -- %s 2>/dev/null | tail -n 1 | cut -f1)'
        % _GRS_KEEP_REL,
        'free=$(df -PB1 -- "$HR" 2>/dev/null | awk \'NR==2{print $4}\')',
        'case "$tot:$kb:$free" in *::*|:*|*:|*[!0-9:]*) echo "%s 0 0"; exit 5;; esac' % _M["SPACE"],
    ]


def _grs_putback_leftovers():
    """Put back, under its own name and time, any archive an interrupted restore left held aside."""
    return ('for f in "$B"/*%s*; do [ -f "$f" ] || continue; b=${f##*/}; st=${b%%%s*}; '
            'rs=${b##*%s}; t=${rs%%%%.*}; x=${rs#*.}; case "$t" in ""|*[!0-9]*) continue;; esac; '
            'case "$x" in zst|gz) ;; *) continue;; esac; o="$B/$st.tar.$x"; [ -e "$o" ] && continue; '
            'mv -n -- "$f" "$o" && touch -m -d "@$t" -- "$o"; done'
            % (HOLD_INFIX, HOLD_INFIX, HOLD_INFIX))


def _grs_paths(name):
    """`a` (the archive) and, once $t0 is set, `h` (where it is held). The name is plain text (_GRS_NAME)."""
    stem, ext = _GRS_NAME.match(name).groups()
    return 'a="$B/%s"' % name, 'h="$B/%s%s$t0.%s"' % (stem, HOLD_INFIX, ext)


def _grs_member_check(var, flag, selfname, on_refusal=""):
    """Lines reading archive $<var> through its decompressor to its end, every member checked (_GRS_VET_PY).

    Leaves `v` holding "__GRS_LIST__ <bytes unpacked> <members>" when it passed; else prints the
    refusal (after running `on_refusal`) and exits 5. `flag` is GNU tar's decompressor flag ("" for
    a plain tar, which tar reads as it is).
    """
    return [
        "command -v python3 >/dev/null 2>&1 || { %s echo %s; exit 5; }" % (on_refusal, _M["NOPY"]),
        'bs=$(stat -f -c %S -- "${' + var + '%/*}" 2>/dev/null); case "$bs" in ""|*[!0-9]*) bs=4096;; esac',
        'asz=$(stat -c %s -- "$' + var + '" 2>/dev/null); case "$asz" in ""|*[!0-9]*) asz=0;; esac',
        'v=$(tar %s -tv --quoting-style=c --numeric-owner -f "$%s" 2>/dev/null | python3 -I -c %s "$bs" %s "$asz" %s; '
        'echo " rc=${PIPESTATUS[0]}:${PIPESTATUS[1]}")'
        % (flag, var, _q(_GRS_VET_PY), _q(selfname), " ".join(KEEP)),
        'case "$v" in *__GRS_BAD__*) %s echo "${v%%%% rc=*}"; exit 5;; esac' % on_refusal,
        'case "$v" in *"__GRS_LIST__ "*" rc=0:0") ;; *) %s echo %s; exit 5;; esac' % (on_refusal, _M["TARFAIL"]),
    ]


def vet_script(user, selfname, name, undo_estimate):
    """The first command: every check before anything changes, then the archive held aside.

    Prints READY <up> <t0> <need> <have> when the restore may go on (<up> 1 when the server was
    running, <t0> the archive's mtime it is put back with), else one refusal mark and nothing
    changed. `undo_estimate`: bytes the pre-restore backup is expected to take, set aside by the
    space check. `name` must have passed archive_problem.
    """
    ext = _GRS_NAME.match(name).group(2)
    a_line, h_line = _grs_paths(name)
    lines = ["set -o pipefail"] + _grs_head(user, selfname) + _grs_home_lines(user) + [
        _grs_putback_leftovers(),
        a_line,
        'if [ ! -f "$a" ] || [ -L "$a" ]; then echo %s; exit 5; fi' % _M["NOARCHIVE"],
        "if %s; then up=1; else up=0; fi" % _wwr._wwr_tmux_up(selfname),
    ] + _grs_member_check("a", _GRS_FLAGS[ext], selfname) + [
        'set -- ${v#*__GRS_LIST__ }; need=$(( $1 + %d ))' % MARGIN,
        'cd -- "$HR" || exit 3',
    ] + _grs_walks() + [
        'have=$(( free + tot - kb - %d ))' % int(undo_estimate),
        'if [ "$have" -lt "$need" ]; then echo "%s $need $have"; exit 5; fi' % _M["SPACE"],
        't0=$(stat -c %Y -- "$a") || { echo ' + _M["HOLDFAIL"] + '; exit 6; }',
        h_line,
        'if [ -e "$h" ] || ! mv -n -- "$a" "$h" || [ -e "$a" ] || [ ! -f "$h" ]; then echo %s; exit 6; fi'
        % _M["HOLDFAIL"],
        'touch -m -- "$h"',
        'echo "%s $up $t0 $need $have"' % _M["READY"],
    ]
    return "\n".join(lines) + "\n"


def leftovers_script(user):
    """Put back any archive held aside, when the restore cannot tell whether its checks held one."""
    return "B=%s\n%s\ntrue\n" % (_q("/home/%s/lgsm/backup" % user), _grs_putback_leftovers())


def putback_script(user, name, t0):
    """Put the held archive back under its own name and time (a restore that stopped before its last step)."""
    a_line, h_line = _grs_paths(name)
    return "\n".join(["B=%s" % _q("/home/%s/lgsm/backup" % user), "t0=%d" % int(t0), a_line, h_line,
                      '[ -f "$h" ] && [ ! -e "$a" ] && mv -n -- "$h" "$a" && touch -m -d "@$t0" -- "$a"',
                      "true"]) + "\n"


def restore_script(user, selfname, name, t0, need, undo, busy_polls=_GRS_BUSY_POLLS):
    """The last command: the checks again, then clear the home (but KEEP) and extract the archive into it.

    Refused, nothing cleared: a LinuxGSM lock; the held archive or the undo backup `undo` missing; the
    server up (LinuxGSM's own test); a process of the account still in serverfiles after a bounded
    wait; the walks (_grs_walks); less space than `need` now that the undo exists. Then CLEARING,
    and from there a failure leaves the home part cleared: RMFAIL (something could not be removed),
    XFAIL (the extraction failed). RESTORED when tar exited 0. The archive is put back under its
    own name and time on every exit (the trap).
    """
    ext = _GRS_NAME.match(name).group(2)
    a_line, h_line = _grs_paths(name)
    excludes = " ".join("--exclude=./%s --exclude=././%s" % (k, k) for k in KEEP)
    lines = ["set -o pipefail"] + _grs_head(user, selfname) + _grs_home_lines(user) + [
        "t0=%d" % int(t0), a_line, h_line,
        "trap '[ -f \"$h\" ] && [ ! -e \"$a\" ] && mv -n -- \"$h\" \"$a\" && touch -m -d \"@$t0\" -- \"$a\"' EXIT",
        'if [ ! -f "$h" ]; then echo %s; exit 5; fi' % _M["NOARCHIVE"],
        'if [ ! -s "$B"/%s ]; then echo %s; exit 5; fi' % (_q(undo), _M["NOUNDO"]),
        "if %s; then echo %s; exit 4; fi" % (_wwr._wwr_tmux_up(selfname), _M["RUNNING"]),
        'sf=$(cd -P -- "$HR/serverfiles" 2>/dev/null && pwd -P && printf x) && sf=${sf%?x} || sf="$HR"',
    ] + [ln.replace(_wwr._M_BUSY, _M["BUSY"]) for ln in _wwr._wwr_busy_wait(busy_polls)] + [
        'cd -- "$HR" || exit 3',
    ] + _grs_walks() + [
        'have=$(( free + tot - kb ))',
        'if [ "$have" -lt %d ]; then echo "%s %d $have"; exit 5; fi' % (int(need), _M["SPACE"], int(need)),
        "echo " + _M["CLEARING"],
        'find . -mindepth 1 "${k[@]}" -type d ! -perm -u=wx -exec chmod u+wx -- {} + 2>/dev/null',
        'find . -mindepth 1 "${k[@]}" ! -type d ! -xtype d -exec rm -f -- {} + 2>/dev/null',
        'find . -mindepth 1 -depth -type d -empty %s -delete 2>/dev/null'
        % " ".join("! -path ./%s ! -path './%s/*'" % (k, k) for k in KEEP),
        # The targets of the symlinked folders kept, emptied above: made again, so no kept link dangles.
        'for r in "${lt[@]}"; do mkdir -p -- "$r"; done',
        'if [ -n "$(find . -mindepth 1 "${k[@]}" ! -type d ! -xtype d -print -quit 2>/dev/null)" ]; then '
        'echo %s; exit 6; fi' % _M["RMFAIL"],
        'x=$(tar %s -xpf "$h" -C "$HR" --keep-directory-symlink --no-overwrite-dir --anchored %s 2>&1); rc=$?'
        % (_GRS_FLAGS[ext], excludes),
        'if [ "$rc" = 0 ]; then echo %s; else printf "%s %%s %%s\\n" "$rc" "$(printf "%%s" "$x" | tail -n 1)"; '
        'exit 7; fi' % (_M["RESTORED"], _M["XFAIL"]),
    ]
    return "\n".join(lines) + "\n"


# ── reading what the commands printed ─────────────────────────────────────────────────────────────
_GRS_BAD_WHY = {
    "parse": "the archive's member list could not be read",
    "name": "a member of the archive is not under the server's folder (an absolute path, `..`, or game "
            "data kept outside the account's home)",
    "type": "the archive holds a device, pipe or symbolic link, which a LinuxGSM backup never stores",
    "link": "the archive holds a hard link to a file it does not restore",
    "script": "the archive does not hold the server's LinuxGSM script, so it is not a backup of this "
              "server's folder",
    "bomb": "the archive says it unpacks to far more than any game server's backup does (more than a hundred "
            "times its own size), so it is not read further",
}
_GRS_VET_REFUSALS = (
    ("LOCKED", "a LinuxGSM backup or update of this server is running"),
    ("NOHOME", "the game account's home folder could not be found"),
    ("NOARCHIVE", "the archive is no longer there"),
    ("NOPY", "python3, which LinuxGSM itself depends on, is not installed on the host"),
    ("TARFAIL", "the archive could not be read to its end (damaged, cut short, or its decompressor is "
                "missing)"),
    ("FOREIGN", "the game account's home holds files it does not own, which it could not clear"),
    ("LINKOUT", "a symbolic link in the game account's home points to a folder the restore does not "
                "rebuild (outside the home, or a backup or lock folder), so it cannot be restored "
                "faithfully"),
    ("HOLDFAIL", "the archive could not be set aside while the pre-restore backup runs"),
)


def _grs_marks(text):
    return {m: ln for ln in text.splitlines() for m in re.findall(r"^__GRS_[A-Z]+__", ln)}


def _grs_space(line):
    nums = [int(p) for p in re.findall(r"-?\d+", (line or "").split(None, 1)[-1])][:2]
    if len(nums) == 2 and nums[0] > 0:
        return i18n.Sentence("not enough free space: the restore needs about {need}, and {have} would be "
                             "free for it", need=_sm._fmt_size(nums[0]), have=_sm._fmt_size(max(0, nums[1])))
    return i18n.Sentence("the free space could not be measured")


def vet_outcome(out):
    """(state, value): ("ready", {"up", "t0"}), ("refused", sentence) or ("unread", sentence)."""
    text = terminal.strip_escapes(out or "")
    marks = _grs_marks(text)
    ready = marks.get(_M["READY"])
    if ready is not None:
        parts = ready.split()
        if len(parts) >= 3 and parts[1] in ("0", "1") and parts[2].isdecimal():
            return "ready", {"up": parts[1] == "1", "t0": int(parts[2]),
                             "need": int(parts[3]) if len(parts) > 3 and parts[3].isdecimal() else 0}
    bad = marks.get(_M["BAD"])
    if bad is not None:
        code = (bad.split() + [""])[1]
        return "refused", i18n.Sentence(_GRS_BAD_WHY.get(code, _GRS_BAD_WHY["parse"]))
    if _M["SPACE"] in marks:
        return "refused", _grs_space(marks[_M["SPACE"]])
    for key, why in _GRS_VET_REFUSALS:
        if _M[key] in marks:
            return "refused", i18n.Sentence(why)
    return "unread", i18n.Sentence("the checks' result did not come back")


_GRS_LATE_REFUSALS = _GRS_VET_REFUSALS + (
    ("NOUNDO", "the pre-restore backup is not in the backup folder"),
    ("RUNNING", "the server was still running after LinuxGSM's stop"),
    ("BUSY", "a process of the game account still had files open in serverfiles a minute after the stop"),
)


def restore_outcome(out, rc):
    """How restore_script went: (state, sentence).

    "refused": nothing was cleared. "failed": the clear began, so the home is partly cleared or
    partly restored. "done": extracted. "unread": none of its marks came back (a timeout, a dropped
    connection): whether it cleared anything is not known.
    """
    text = terminal.strip_escapes(out or "")
    marks = _grs_marks(text)
    if _M["RESTORED"] in marks:
        return "done", i18n.Sentence("restored")
    if _M["CLEARING"] in marks:
        if _M["RMFAIL"] in marks:
            return "failed", i18n.Sentence("a file in the home could not be removed, so the clear stopped part way")
        xf = (marks.get(_M["XFAIL"]) or "").split(None, 2)
        return "failed", i18n.Sentence("the extraction failed (tar exit {rc}): {last}",
                                       rc=xf[1] if len(xf) > 1 else rc, last=(xf[2] if len(xf) > 2 else "")[:200])
    if _M["SPACE"] in marks:
        return "refused", _grs_space(marks[_M["SPACE"]])
    for key, why in _GRS_LATE_REFUSALS:
        if _M[key] in marks:
            return "refused", i18n.Sentence(why)
    return "unread", i18n.Sentence("the restore's result did not come back (exit {rc})", rc=rc)


# ── uploading an archive into the backup dir ──────────────────────────────────────────────────────
# In pieces of UPLOAD_CHUNK bytes, each its own request and its own command as the game account
# (base64 on the command's stdin, decoded to a staged piece, then appended), into a part file whose
# name holds no ".tar.": neither the panel's listing nor LinuxGSM's prune sees it. The last request
# checks the whole file the way a restore does (_grs_member_check, the bomb bound included), turns a
# plain tar into a .tar.gz, and gives it a LinuxGSM backup's name. A part file left by an upload that
# never finished is removed by the next upload's first request once it is UPLOAD_STALE_MIN old.
UPLOAD_CHUNK = 4 * 1024 * 1024
UPLOAD_MAX = 32 * 1024 * 1024 * 1024
UPLOAD_STALE_MIN = 120
_GRS_UID = re.compile(r"[0-9a-f]{32}\Z")


def _grs_part(user, uid):
    """`B` and `p` (the part file) for upload `uid` (32 hex digits, checked)."""
    if not _GRS_UID.match(uid or ""):
        raise ValueError("bad upload id")
    return "B=%s; p=\"$B/.panel-upload-%s.part\"" % (_q("/home/%s/lgsm/backup" % user), uid)


def upload_start_script(user, uid, size):
    """Make the empty part file, once the backup dir's filesystem has room for `size` bytes and the margin."""
    return "\n".join([
        _grs_part(user, uid),
        'mkdir -p -- "$B" 2>/dev/null; [ -d "$B" ] || { echo %s; exit 6; }' % _M["UPFAIL"],
        "find \"$B\" -maxdepth 1 -name '.panel-upload-*' -mmin +%d -delete 2>/dev/null" % UPLOAD_STALE_MIN,
        'free=$(df -PB1 -- "$B" 2>/dev/null | awk \'NR==2{print $4}\')',
        'case "$free" in ""|*[!0-9]*) echo "%s 0 0"; exit 5;; esac' % _M["SPACE"],
        'if [ "$free" -lt %d ]; then echo "%s %d $free"; exit 5; fi'
        % (int(size) + MARGIN, _M["SPACE"], int(size) + MARGIN),
        'set -C; : > "$p" 2>/dev/null || { echo %s; exit 6; }' % _M["UPFAIL"],
        "echo " + _M["UPREADY"],
    ]) + "\n"


def upload_chunk_script(user, uid, offset):
    """Append the piece on stdin (base64) to the part file when it is exactly `offset` bytes long now.

    stdin is always read to its end first (into a staged piece), so the panel's write never meets a
    command that has already exited. Prints UPSIZE <bytes> after the append; UPOFFSET <bytes> when the
    part file is another length (an earlier piece whose answer was lost: the page goes on from there).
    """
    return "\n".join([
        _grs_part(user, uid), 'c="$p.piece"',
        'base64 -d > "$c" 2>/dev/null || { rm -f -- "$c"; cat > /dev/null; echo %s; exit 6; }' % _M["UPFAIL"],
        'if [ ! -f "$p" ] || [ -L "$p" ]; then rm -f -- "$c"; echo %s; exit 5; fi' % _M["NOPART"],
        's=$(stat -c %s -- "$p")',
        'if [ "$s" != %d ]; then rm -f -- "$c"; echo "%s $s"; exit 5; fi' % (int(offset), _M["UPOFFSET"]),
        'cat -- "$c" >> "$p" || { rm -f -- "$c"; echo %s; exit 6; }' % _M["UPFAIL"],
        'rm -f -- "$c"; echo "%s $(stat -c %%s -- "$p")"' % _M["UPSIZE"],
    ]) + "\n"


def upload_finish_script(user, selfname, uid, size, when):
    """Check the whole uploaded file as a restore does, then store it under a LinuxGSM backup's name.

    The format is read from the file's first bytes, never from what the browser called it: zstd,
    gzip, or a plain tar (ustar at byte 257), which is compressed with gzip here. A refusal removes
    the part file. The name is <selfname>-<date>.tar.<zst|gz>, the date `when` (epoch seconds) in
    the host's time as LinuxGSM writes it, a second later while one is taken.
    """
    rm = 'rm -f -- "$p";'
    names = ('for i in 0 1 2 3 4 5 6 7 8 9; do n=%s-$(date -d "@$((%d + i))" +%%Y-%%m-%%d-%%H%%M%%S).tar.$x; '
             '[ -e "$B/$n" ] && continue; if mv -n -- "$p" "$B/$n" && [ ! -e "$p" ]; then echo "%s $n"; exit 0; fi; '
             'done' % (_q(selfname), int(when), _M["UPSTORED"]))
    lines = [
        "set -o pipefail", "export LC_ALL=C", _grs_part(user, uid),
        'if [ ! -f "$p" ] || [ -L "$p" ]; then echo %s; exit 5; fi' % _M["NOPART"],
        's=$(stat -c %s -- "$p")',
        'if [ "$s" != %d ]; then echo "%s $s"; exit 5; fi' % (int(size), _M["UPOFFSET"]),
        "m=$(head -c 4 -- \"$p\" | od -An -tx1 | tr -d ' \\n')",
        'case "$m" in 28b52ffd) f=--zstd; x=zst;; 1f8b*) f=--gzip; x=gz;; '
        '*) if [ "$(dd if="$p" bs=1 skip=257 count=5 2>/dev/null)" = ustar ]; then f=; x=tar; '
        'else %s echo %s; exit 5; fi;; esac' % (rm, _M["UPFORMAT"]),
    ] + _grs_member_check("p", "$f", selfname, on_refusal=rm) + [
        'if [ "$x" = tar ]; then gzip -1 -n -- "$p" 2>/dev/null || { rm -f -- "$p" "$p.gz"; echo %s; exit 6; }; '
        'p="$p.gz"; x=gz; fi' % _M["UPFAIL"],
        names, rm + " echo " + _M["UPFAIL"], "exit 6",
    ]
    return "\n".join(lines) + "\n"


def upload_outcome(out):
    """(state, value) of an upload command: ("ok", the number or name it printed), ("offset", host size),
    or ("refused", sentence)."""
    text = terminal.strip_escapes(out or "")
    marks = _grs_marks(text)
    for key in ("UPSTORED", "UPSIZE", "UPREADY"):
        if _M[key] in marks:
            return "ok", (marks[_M[key]].split() + [""])[1]
    if _M["UPOFFSET"] in marks:
        got = (marks[_M["UPOFFSET"]].split() + [""])[1]
        return "offset", int(got) if got.isdecimal() else 0
    bad = marks.get(_M["BAD"])
    if bad is not None:
        return "refused", i18n.Sentence(_GRS_BAD_WHY.get((bad.split() + [""])[1], _GRS_BAD_WHY["parse"]))
    if _M["SPACE"] in marks:
        return "refused", _grs_space(marks[_M["SPACE"]])
    for key, why in _GRS_UPLOAD_REFUSALS:
        if _M[key] in marks:
            return "refused", i18n.Sentence(why)
    return "refused", i18n.Sentence("the host's answer did not come back")


_GRS_UPLOAD_REFUSALS = (
    ("UPFORMAT", "the file is not a tar archive compressed with zstd or gzip, nor a plain tar"),
    ("TARFAIL", "the archive could not be read to its end (damaged, cut short, or its decompressor is "
                "missing)"),
    ("NOPY", "python3, which LinuxGSM itself depends on, is not installed on the host"),
    ("NOPART", "the upload is no longer on the host (it was cancelled, or left too long)"),
    ("UPFAIL", "the host could not write the upload into the backup folder"),
)
