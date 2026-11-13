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
KEEP = ("lgsm/backup", "lgsm/lock", "lgsm/tmp", ".ssh", ".lgsm-cron", ".restart-pending", ".panel-restore")
# The restore's own working folder (staging, the aside copy, its state, the saved crontab, its lock): in the
# home, OUTSIDE lgsm/, so no LinuxGSM cleanup reaches it (an update that finds a new build ends with
# fn_clear_tmp, `rm -rf "${tmpdir:?}/"*` on lgsm/tmp; core_exit and the update modules clear only lgsm/tmp
# and lgsm/lock files: LinuxGSM master 2026-11). KEEP, so never cleared, extracted or moved; 0700.
WORK_DIR = ".panel-restore"
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
    "HOLDFAIL", "READY", "UP", "DOWN", "NOUNDO", "RUNNING", "BUSY",
    "RESTORED", "NOPART", "UPOFFSET", "UPSIZE", "UPREADY", "UPFAIL", "UPFORMAT", "UPSTORED", "KEEPLINK",
    "INODES", "ALIVE", "STAGING", "STAGEFAIL", "CRONFAIL", "LGSMBUSY", "SWITCHING",
    "ROLLEDBACK", "ROLLBACKFAIL", "RECDONE", "RECUNDONE", "RECFAIL", "RECBUSY")}

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
# Every KEEP path and every folder above one (lgsm for lgsm/backup): none may be a symlink (_grs_walks).
_GRS_KEEP_CHAIN = " ".join(sorted({"/".join(k.split("/")[:i + 1]) for k in KEEP for i in range(k.count("/") + 1)}))
# Inodes left over once the archive is unpacked, as MARGIN is for bytes.
INODE_MARGIN = 1000
# A line every HEARTBEAT seconds while a long step runs (a read of the whole archive, the extraction), so a
# transport that gives up after a silence (paramiko) does not give up on a command that is still working.
HEARTBEAT = 20


def _grs_heartbeat(extra_trap=""):
    """Lines that start the heartbeat (`hb`) and stop it on every exit, after `extra_trap`.

    SIGPIPE is ignored, so a write to a panel that has gone fails with an error the script can act
    on (vet_script's last line) instead of killing it between two steps.
    """
    return [
        "trap '' PIPE",
        # Its sleep is a child it kills on TERM: a sleep left running would hold the output open (and
        # the panel waiting) for up to HEARTBEAT seconds after the script has ended.
        # It ends with the script too ($$ is the script's own pid in the subshell): one killed outright
        # (SIGKILL runs no trap) must not leave it printing to the panel for ever. A killed script stays a
        # zombie until its parent reaps it, which kill -0 still answers for, so its state is read.
        "( trap 'kill $z 2>/dev/null; exit 0' TERM; up() { local a b c; read -r a b c _ < /proc/$$/stat 2>/dev/null "
        "&& [ \"$c\" != Z ]; }; while up; do sleep %d & z=$!; wait $z; up && echo %s || exit 0; done ) & hb=$!"
        % (HEARTBEAT, _M["ALIVE"]),
        "trap '%skill $hb 2>/dev/null' EXIT" % extra_trap,
    ]


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
    """Lines (cwd the resolved home) refusing what the restore could not put back faithfully, then measuring.

    * a KEEP path, or a folder above one, that is a symlink: the clear keeps a KEEP path by its name,
      so the folder a link points at would be cleared (every backup in it, the held archive and the
      undo included) and ~/.ssh's real folder would get the archive's old keys;
    * an entry the clear would remove that the account does not own: it could not remove it;
    * a symlinked folder whose target is not itself restored: outside the home, the home itself or
      above it, or a KEEP path or above one.
    Every symlink in what is cleared is recorded: `lp` (its path, relative), `lx` (its text, exactly as
    readlink gives it: LinuxGSM's ~/log/server link is absolute) and `lr` (a folder's resolved target,
    else ""). restore_script puts each back after the move (_grs_relink). Then `free` (bytes) and
    `itot`/`ifree` (the filesystem's inodes; 0 where it does not count them).
    """
    return [
        'for kp in %s; do if [ -L "./$kp" ]; then echo %s; exit 5; fi; done' % (_GRS_KEEP_CHAIN, _M["KEEPLINK"]),
        "k=( \\( %s \\) -prune -o )" % _GRS_KEEP_FIND,
        'if [ -n "$(find . -mindepth 1 "${k[@]}" ! -user "$(id -u)" -print -quit 2>/dev/null)" ]; then '
        'echo %s; exit 5; fi' % _M["FOREIGN"],
        'lp=(); lx=(); lr=(); while IFS= read -r -d "" l && IFS= read -r -d "" x; do r=; '
        'if [ -d "./$l" ]; then r=$(readlink -f -- "./$l" 2>/dev/null) || r=; '
        'case "$r" in "$HR"/*) ;; *) echo %s; exit 5;; esac; '
        'for kp in %s; do case "$r" in "$kp"|"$kp"/*) echo %s; exit 5;; esac; '
        'case "$kp" in "$r"/*) echo %s; exit 5;; esac; done; fi; lp+=("$l"); lx+=("$x"); lr+=("$r"); '
        'done < <(find . -mindepth 1 "${k[@]}" -type l -printf "%%P\\0%%l\\0" 2>/dev/null)'
        % (_M["LINKOUT"], _GRS_KEEP_REAL, _M["LINKOUT"], _M["LINKOUT"]),
        'free=$(df -PB1 -- "$HR" 2>/dev/null | awk \'NR==2{print $4}\')',
        'case "$free" in ""|*[!0-9]*) echo "%s 0 0"; exit 5;; esac' % _M["SPACE"],
        'read -r itot ifree <<< "$(df -Pi -- "$HR" 2>/dev/null | awk \'NR==2{print $2, $4}\')"',
        'case "$itot:$ifree" in *[!0-9:]*|:*|*:) itot=0; ifree=0;; esac',
    ]


def _grs_inode_check(members):
    """The line refusing when the filesystem counts inodes and `members` (a shell word) would not fit."""
    return ('if [ "$itot" -gt 0 ] && [ "$ifree" -lt $(( %s + %d )) ]; then echo "%s $(( %s + %d )) $ifree"; '
            'exit 5; fi' % (members, INODE_MARGIN, _M["INODES"], members, INODE_MARGIN))


# Held aside while the pre-restore backup runs: EVERY archive in the backup dir, not only the one being
# restored. LinuxGSM's own retention inside that backup (fn_backup_prune: past maxbackups, the oldest
# `*.tar.*` by name; past maxbackupdays, any file by age) would otherwise delete the operator's oldest
# archives. Held as <stem>.restore-source-<mtime>.<ext> (no ".tar.", so neither the panel's listing nor
# LinuxGSM's count sees it), touched (so its age prune does not), the mtime kept in the name to the
# nanosecond ("." written "_") and put back with it.
def _grs_hold_all():
    """Hold every archive in $B aside (see above). Names that would not round-trip are left alone."""
    return ('for f in "$B"/*.tar.*; do [ -f "$f" ] && [ ! -L "$f" ] || continue; b=${f##*/}; sm=${b%%.tar.*}; '
            'x=${b##*.tar.}; case "$sm" in ""|*.tar.*|*%s*) continue;; esac; case "$x" in ""|*[!A-Za-z0-9]*) continue;; esac; '
            't=$(stat -c %%.9Y -- "$f" 2>/dev/null) || continue; t=${t/./_}; g="$B/$sm%s$t.$x"; [ -e "$g" ] && continue; '
            'mv -n -- "$f" "$g" && touch -m -- "$g"; done' % (HOLD_INFIX, HOLD_INFIX))


def _grs_putback_leftovers(skip=""):
    """Put back, under its own name and time, every archive held aside (but the one held as $<skip>)."""
    guard = ('[ "$f" = "$%s" ] && continue; ' % skip) if skip else ""
    return ('for f in "$B"/*%s*; do [ -f "$f" ] || continue; %sb=${f##*/}; sm=${b%%%s*}; '
            'rs=${b##*%s}; t=${rs%%%%.*}; x=${rs#*.}; case "$t" in ""|*[!0-9_]*) continue;; esac; '
            'case "$x" in ""|*[!A-Za-z0-9]*) continue;; esac; o="$B/$sm.tar.$x"; [ -e "$o" ] && continue; '
            'mv -n -- "$f" "$o" && touch -m -d "@${t/_/.}" -- "$o"; done'
            % (HOLD_INFIX, guard, HOLD_INFIX, HOLD_INFIX))


def _grs_paths(name):
    """`a` (the archive) and `h` (where it is held, when it is: found by its stem, which is unique)."""
    stem, ext = _GRS_NAME.match(name).groups()
    return ('a="$B/%s"' % name,
            'h=; for g in "$B/%s%s"*".%s"; do [ -f "$g" ] && h=$g; done' % (stem, HOLD_INFIX, ext))


def _grs_member_check(var, flag, selfname, on_refusal=""):
    """Lines reading archive $<var> through its decompressor to its end, every member checked (_GRS_VET_PY).

    Leaves `v` holding "__GRS_LIST__ <bytes unpacked> <members>" when it passed; else prints the
    refusal (after running `on_refusal`) and exits 5. A bomb is said first (the check stops reading,
    so tar ends on a broken pipe); then a tar that did not read to its end (an unreadable or cut-short
    archive is that, whatever the member check made of the lines it got); then the member check's own
    verdict. `flag` is GNU tar's decompressor flag ("" for a plain tar, which tar reads as it is).
    """
    return [
        "command -v python3 >/dev/null 2>&1 || { %s echo %s; exit 5; }" % (on_refusal, _M["NOPY"]),
        'bs=$(stat -f -c %S -- "${' + var + '%/*}" 2>/dev/null); case "$bs" in ""|*[!0-9]*) bs=4096;; esac',
        'asz=$(stat -c %s -- "$' + var + '" 2>/dev/null); case "$asz" in ""|*[!0-9]*) asz=0;; esac',
        'v=$(tar %s -tv --quoting-style=c --numeric-owner -f "$%s" 2>/dev/null | python3 -I -c %s "$bs" %s "$asz" %s; '
        'echo " rc=${PIPESTATUS[0]}:${PIPESTATUS[1]}")'
        % (flag, var, _q(_GRS_VET_PY), _q(selfname), " ".join(KEEP)),
        'case "$v" in *"__GRS_BAD__ bomb"*) %s echo "${v%%%% rc=*}"; exit 5;; esac' % on_refusal,
        'case "$v" in *" rc=0:"*) ;; *) %s echo %s; exit 5;; esac' % (on_refusal, _M["TARFAIL"]),
        'case "$v" in *__GRS_BAD__*) %s echo "${v%%%% rc=*}"; exit 5;; esac' % on_refusal,
        'case "$v" in *"__GRS_LIST__ "*" rc=0:0") ;; *) %s echo %s; exit 5;; esac' % (on_refusal, _M["TARFAIL"]),
    ]


def vet_script(user, selfname, name, undo_estimate):
    """The first command: every check before anything changes, then every archive held aside.

    Prints READY <up> <t0> <need> <have> <members> when the restore may go on (<up> 1 when the server
    was running, <t0> the archive's mtime in seconds), else one refusal mark and nothing changed.
    The space check: the archive is unpacked into a staging folder while everything is still in place
    (restore_script), so the free space must hold it whole besides the pre-restore backup
    (`undo_estimate` bytes). `name` must have passed archive_problem.
    """
    ext = _GRS_NAME.match(name).group(2)
    a_line, h_line = _grs_paths(name)
    lines = ["set -o pipefail"] + _grs_head(user, selfname) + _grs_heartbeat() + _grs_home_lines(user) + [
        _grs_putback_leftovers(),
        a_line,
        'if [ ! -f "$a" ] || [ -L "$a" ]; then echo %s; exit 5; fi' % _M["NOARCHIVE"],
        "if %s; then up=1; else up=0; fi" % _wwr._wwr_tmux_up(selfname),
    ] + _grs_member_check("a", _GRS_FLAGS[ext], selfname) + [
        'set -- ${v#*__GRS_LIST__ }; need=$(( $1 + %d )); nmem=$2' % MARGIN,
        'cd -- "$HR" || exit 3',
    ] + _grs_walks() + [_grs_inode_check("nmem")] + [
        'have=$(( free - %d ))' % int(undo_estimate),
        'if [ "$have" -lt "$need" ]; then echo "%s $need $have"; exit 5; fi' % _M["SPACE"],
        't0=$(stat -c %Y -- "$a") || { echo ' + _M["HOLDFAIL"] + '; exit 6; }',
        _grs_hold_all(),
        h_line,
        'if [ -z "$h" ] || [ -e "$a" ]; then %s; echo %s; exit 6; fi' % (_grs_putback_leftovers(), _M["HOLDFAIL"]),
        # Said, or put back: a panel that gave up before this line never learns the archives were moved.
        'kill $hb 2>/dev/null',
        'if ! echo "%s $up $t0 $need $have $nmem"; then %s; exit 6; fi' % (_M["READY"], _grs_putback_leftovers()),
    ]
    return "\n".join(lines) + "\n"


def leftovers_script(user):
    """Put back every archive held aside (a restore that ended before its last step, or was cut off)."""
    return "B=%s\n%s\ntrue\n" % (_q("/home/%s/lgsm/backup" % user), _grs_putback_leftovers())


def putback_script(user, name, t0):
    """Put every held archive back under its own name and time. `name` and `t0` are kept for the callers."""
    del name, t0
    return leftovers_script(user)


# The folders above a KEEP path that are not KEEP themselves (lgsm): the switch moves their entries one
# by one; and the KEEP entries at the top of the home and inside such a folder, which it never moves.
_GRS_KEEP_PARENTS = tuple(sorted({k.split("/")[0] for k in KEEP if "/" in k}))
_GRS_KEEP_TOP = tuple(k for k in KEEP if "/" not in k)
_GRS_KEEP_SUB = tuple(sorted({k.split("/", 1)[1] for k in KEEP if "/" in k}))
# How long the switch waits for a LinuxGSM command of the account (one cron started before the crontab
# was set aside) to end: polls of 2 seconds.
_GRS_LGSM_POLLS = 60


def _grs_work_lock(busy):
    """Hold ~/.panel-restore/panel-restore.lock (flock, util-linux: a LinuxGSM dependency) for the command's life.

    The restore holds it while it runs; the recovery sweep takes it too, so it never undoes a switch a
    restore the panel lost sight of is still making. Taken: prints `busy` and exits.
    """
    return ('if [ -L "$T" ]; then echo %s; exit 5; fi; mkdir -p -m 700 -- "$T" && exec 9> "$T/panel-restore.lock" '
            '&& flock -n 9 || { echo %s; exit 4; }' % (_M["KEEPLINK"], busy))


def _grs_work_paths():
    """The restore's own paths under ~/.panel-restore (WORK_DIR, KEEP), each named for the run by its $t0."""
    return ('T="$HR/' + WORK_DIR + '"; S="$T/panel-restore-$t0"; O="$T/panel-restore-old-$t0"; F="$T/panel-restore-failed-$t0"; '
            'st="$T/panel-restore-state-$t0"; nm="$T/panel-restore-names-$t0"; ct="$T/panel-restore-crontab-$t0"')


def _grs_switch_functions():
    """Shell functions for the switch-over and its undo.

    entries DIR: the home-relative names a switch moves out of DIR (everything but KEEP; inside lgsm,
    entry by entry), NUL-separated. moveall SRC DST: each of them renamed from SRC into DST (the same
    filesystem: WORK_DIR is in the home and no KEEP path is a link), a folder made writable first, as
    a rename into another folder must update its "..". undo: the switch reversed from wherever it
    stopped ($st names the step): what came from the staging folder (names in $nm) set aside into $F,
    the home's own content moved back from $O. LinuxGSM's own links were moved as links, so they come
    back as they were.
    """
    parents = "|".join(_GRS_KEEP_PARENTS)
    top = "|".join(_GRS_KEEP_TOP)
    sub = "|".join(_GRS_KEEP_SUB)
    return [
        'entries() { local e f n; for e in "$1"/* "$1"/.[!.]* "$1"/..?*; do [ -e "$e" ] || [ -L "$e" ] || continue; '
        'n=${e##*/}; case "$n" in %s) for f in "$e"/* "$e"/.[!.]* "$e"/..?*; do [ -e "$f" ] || [ -L "$f" ] || continue; '
        'case "${f##*/}" in %s) continue;; esac; printf "%%s\\0" "$n/${f##*/}"; done;; %s) ;; '
        '*) printf "%%s\\0" "$n";; esac; done; }' % (parents, sub, top),
        'moveall() { local r; while IFS= read -r -d "" r; do case "$r" in */*) mkdir -p -- "$2/${r%/*}";; esac; '
        'if [ -d "$1/$r" ] && [ ! -L "$1/$r" ] && [ ! -w "$1/$r" ]; then chmod u+w -- "$1/$r"; fi; '
        'mv -T -- "$1/$r" "$2/$r" || return 1; done < <(entries "$1"); }',
        'undo() { local p; p=$(cat "$st" 2>/dev/null); [ -n "$p" ] || return 0; mkdir -p -- "$F" || return 1; '
        'if { [ "$p" = in ] || [ "$p" = link ] || [ "$p" = done ]; } && [ -f "$nm" ]; then while IFS= read -r -d "" r; do '
        'if [ -e "$HR/$r" ] || [ -L "$HR/$r" ]; then case "$r" in */*) mkdir -p -- "$F/${r%/*}";; esac; '
        'mv -T -- "$HR/$r" "$F/$r" || return 1; fi; '
        'done < "$nm"; fi; echo back > "$st" || return 1; [ ! -d "$O" ] || moveall "$O" "$HR" || return 1; '
        'rm -rf -- "$F" "$O"; rm -f -- "$st" "$nm" "$st.failed"; }',
    ]


def _grs_cron_lines():
    """The account's crontab set aside for the switch (and put back on every exit, the trap).

    LinuxGSM has no lock its own monitor honours before it touches files: command_monitor.sh runs
    check.sh first (check_gamedig.sh: `npm update` in lgsm, ~/.npm) and core_logs.sh, and only then
    looks at backup.lock / update.lock (master 2026-11). The panel's monitor line runs it every 5
    minutes whatever the server's state, so for the switch nothing of the account may run from cron:
    the whole crontab is saved to $ct and replaced by an empty one, then a LinuxGSM command already
    running (started before) is waited for; still running after the wait, the restore refuses.
    """
    return [
        'cs=; if crontab -l > "$ct" 2>/dev/null; then cs=1; printf "" | crontab - 2>/dev/null || { rm -f -- "$ct"; echo %s; exit 5; }; '
        'else rm -f -- "$ct"; fi' % _M["CRONFAIL"],
        'lgsm_running() { local p a; for p in /proc/[0-9]*; do [ -O "$p" ] || continue; [ "${p#/proc/}" = "$$" ] && continue; '
        'a=$(tr "\\0" "\\n" < "$p/cmdline" 2>/dev/null | sed -n 2p); case "$a" in "$SELF"|*/"$SELF") return 0;; esac; done; return 1; }',
        'i=0; while lgsm_running; do i=$((i+1)); if [ "$i" -ge %d ]; then echo %s; exit 5; fi; sleep 2; done'
        % (_GRS_LGSM_POLLS, _M["LGSMBUSY"]),
    ]


def _grs_put_cron():
    """Put the saved crontab back (and forget it); nothing when none was set aside."""
    return 'if [ -f "$ct" ]; then crontab "$ct" 2>/dev/null && rm -f -- "$ct"; fi'


def _grs_relink():
    """A shell function `relink`: every recorded symlink put back exactly as it was (its own text), deepest first.

    The archive holds what `tar -h` found through the link: a real folder (or file) at the link's path.
    A folder's files are also stored under its target, as hard links when the target is in the home
    (GNU tar stores a second name for an inode as a link to the first), so they are already there; a
    file that is only under the link's path is moved to the target first. Then the real entry is
    removed and the link made again. Returns 1 on the first that fails.
    """
    return ('relink() { local i p r e sp tp; for ((i=${#lp[@]}-1; i>=0; i--)); do p="$HR/${lp[$i]}"; r=${lr[$i]}; '
            'if [ -d "$p" ] && [ ! -L "$p" ] && [ -n "$r" ] && [ -d "$r" ]; then '
            'while IFS= read -r -d "" e; do sp="$p/${e#./}"; tp="$r/${e#./}"; '
            'if [ -d "$sp" ] && [ ! -L "$sp" ]; then mkdir -p -- "$tp"; '
            'elif [ ! -e "$tp" ] && [ ! -L "$tp" ]; then mv -- "$sp" "$tp"; fi; '
            'done < <(cd -- "$p" && find . -mindepth 1 -print0); fi; '
            'if [ -e "$p" ] || [ -L "$p" ]; then rm -rf -- "$p" || return 1; fi; '
            'mkdir -p -- "${p%/*}" && ln -s -- "${lx[$i]}" "$p" || return 1; done; }')


def _grs_switch():
    """The switch-over: the home's content set aside, the staged tree moved in, the links made again.

    Each step is noted in $st (aside, in, link, done) so the undo knows where it stopped. Any step that
    fails is undone (ROLLEDBACK: nothing changed); an undo that fails says where the home's own content
    is (ROLLBACKFAIL $O). Done: the aside copy and the staging folder are removed.
    """
    return [
        # Checked again after the waits: the staging folder whole, the saved crontab still there.
        'if [ ! -d "$S" ] || [ "$(find "$S" -mindepth 1 | wc -l)" -lt "$want" ] || { [ -n "$cs" ] && [ ! -f "$ct" ]; }; then '
        'echo "%s 0 the staging folder or the saved crontab changed during the waits"; exit 5; fi' % _M["STAGEFAIL"],
        'entries "$S" > "$nm" && [ -s "$nm" ] || { echo "%s names"; exit 5; }' % _M["ROLLEDBACK"],
        "echo " + _M["SWITCHING"],
        'step=; if echo aside > "$st" && mkdir -p -- "$O" && step=aside && moveall "$HR" "$O" && echo in > "$st" '
        '&& step=in && moveall "$S" "$HR" && echo link > "$st" && step=link && relink && echo done > "$st"; then '
        'rm -rf -- "$O" "$S"; rm -f -- "$st" "$nm"; echo %s; '
        'elif undo; then echo "%s ${step:-aside}"; exit 5; '
        'else : > "$st.failed"; echo "%s $O"; exit 7; fi' % (_M["RESTORED"], _M["ROLLEDBACK"], _M["ROLLBACKFAIL"]),
    ]


def restore_script(user, selfname, name, t0, need, undo, busy_polls=_GRS_BUSY_POLLS, members=0):
    """The last command: the checks again; unpack into a staging folder; then switch the home over, undoably.

    Refused, nothing changed: a LinuxGSM lock; the held archive or the undo backup `undo` missing; the
    server up (LinuxGSM's own test); a process of the account still in serverfiles after a bounded
    wait; the walks (_grs_walks); too little space for the staging copy (`need`) or too few inodes for
    `members`. The other held archives are put back. Then STAGING: the archive is unpacked into
    ~/.panel-restore/panel-restore-<t0>; a tar that does not exit 0, or fewer entries than the checks counted,
    refuses (STAGEFAIL). Then the account's crontab is set aside and a LinuxGSM command still running
    waited for (CRONFAIL, LGSMBUSY refuse). Then the switch (_grs_switch): RESTORED, or ROLLEDBACK
    (nothing changed), or ROLLBACKFAIL (the home's own content is in the aside folder it names). On
    every exit (the trap): a switch a signal cut short is undone, the crontab put back, the staging
    folder removed and every held archive put back under its own name and time.
    """
    ext = _GRS_NAME.match(name).group(2)
    a_line, h_line = _grs_paths(name)
    excludes = " ".join("--exclude=./%s --exclude=././%s" % (k, k) for k in KEEP)
    lines = ["set -o pipefail"] + _grs_head(user, selfname) + _grs_home_lines(user) + [
        "t0=%d" % int(t0), "SELF=%s" % _q(selfname), a_line, h_line, _grs_work_paths(), _grs_work_lock(_M["LOCKED"]),
    ] + _grs_switch_functions() + [_grs_relink()] + _grs_heartbeat(
        '[ -f "$st" ] && [ ! -f "$st.failed" ] && undo; %s; [ -f "$st" ] || rm -rf -- "$S"; rm -f -- "$nm"; %s; '
        % (_grs_put_cron(), _grs_putback_leftovers())) + [
        'if [ -z "$h" ]; then echo %s; exit 5; fi' % _M["NOARCHIVE"],
        'if [ ! -s "$B"/%s ]; then echo %s; exit 5; fi' % (_q(undo), _M["NOUNDO"]),
        "if %s; then echo %s; exit 4; fi" % (_wwr._wwr_tmux_up(selfname), _M["RUNNING"]),
        'sf=$(cd -P -- "$HR/serverfiles" 2>/dev/null && pwd -P && printf x) && sf=${sf%?x} || sf="$HR"',
    ] + [ln.replace(_wwr._M_BUSY, _M["BUSY"]) for ln in _wwr._wwr_busy_wait(busy_polls)] + [
        'cd -- "$HR" || exit 3',
    ] + _grs_walks() + [_grs_inode_check(str(int(members)))] + [
        'if [ "$free" -lt %d ]; then echo "%s %d $free"; exit 5; fi' % (int(need), _M["SPACE"], int(need)),
        _grs_putback_leftovers(skip="h"),
        "echo " + _M["STAGING"],
        'rm -rf -- "$S" "$O" "$F"; mkdir -p -- "$S" || { echo "%s 1 the staging folder could not be made"; exit 5; }'
        % _M["STAGEFAIL"],
        'x=$(tar %s -xpf "$h" -C "$S" --anchored %s 2>&1); rc=$?' % (_GRS_FLAGS[ext], excludes),
        'if [ "$rc" != 0 ]; then printf "%s %%s %%s\\n" "$rc" "$(printf "%%s" "$x" | tail -n 1)"; exit 5; fi'
        % _M["STAGEFAIL"],
        'cnt=$(find "$S" -mindepth 1 | wc -l)',
        'want=$(( %d - 1 )); if [ "$cnt" -lt "$want" ]; then echo "%s 0 unpacked $cnt of %d entries"; exit 5; fi'
        % (int(members), _M["STAGEFAIL"], int(members)),
    ] + _grs_cron_lines() + _grs_switch()
    return "\n".join(lines) + "\n"


def recover_script(user, t0):
    """After a panel restart cut a restore off: undo a switch it left part way, then tidy up and put back.

    Only the run's own paths (named for its `t0`, recorded in config.json): a switch noted as done
    keeps the restored home and drops the aside copy; one noted at any other step is undone. Then
    the staging and aside leftovers are removed, the crontab put back, and every held archive put
    back under its own name and time. Prints RECDONE (the restore had completed), RECUNDONE (a switch
    was undone), RECFAIL $O (the undo failed: the home's own content is there) or nothing (no switch
    had begun).
    """
    return "\n".join(["export LC_ALL=C", "cd / || exit 3"] + _grs_home_lines(user) + [
        "t0=%d" % int(t0), _grs_work_paths(), _grs_work_lock(_M["RECBUSY"]),
    ] + _grs_switch_functions() + [
        'p=$(cat "$st" 2>/dev/null)',
        'if [ "$p" = done ]; then rm -rf -- "$O"; rm -f -- "$st" "$nm"; echo %s; '
        'elif [ -n "$p" ]; then if undo; then echo %s; else echo "%s $O"; fi; fi' % (_M["RECDONE"], _M["RECUNDONE"], _M["RECFAIL"]),
        'rm -rf -- "$S"; [ -f "$st" ] || rm -rf -- "$F"; rm -f -- "$nm"',
        _grs_put_cron(),
        _grs_putback_leftovers(),
        "echo " + _M["UPREADY"],
    ]) + "\n"


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
    ("KEEPLINK", "the backup, lock or tmp folder, ~/.ssh or the panel's cron folder (or a folder above one) "
                 "is a symbolic link, so the restore could not keep it apart from what it clears"),
)


def _grs_marks(text):
    return {m: ln for ln in text.splitlines() for m in re.findall(r"^__GRS_[A-Z]+__", ln)}


def _grs_inodes(line):
    nums = [int(p) for p in re.findall(r"-?\d+", (line or "").split(None, 1)[-1])][:2]
    return i18n.Sentence("not enough free inodes: the archive holds {need} files and folders (with a margin), "
                         "and {have} would be free for them", need=nums[0] if nums else "?",
                         have=nums[1] if len(nums) > 1 else "?")


def _grs_space(line):
    nums = [int(p) for p in re.findall(r"-?\d+", (line or "").split(None, 1)[-1])][:2]
    if len(nums) == 2 and nums[0] > 0:
        return i18n.Sentence("not enough free space: the restore needs about {need}, and {have} would be "
                             "free for it", need=_sm._fmt_size(nums[0]), have=_sm._fmt_size(max(0, nums[1])))
    return i18n.Sentence("the free space could not be measured")


def _grs_refusal(marks, table):
    """The refusal `marks` hold (a member check's verdict, the space check, or the first of `table`), else None."""
    bad = marks.get(_M["BAD"])
    if bad is not None:
        return i18n.Sentence(_GRS_BAD_WHY.get((bad.split() + [""])[1], _GRS_BAD_WHY["parse"]))
    if _M["SPACE"] in marks:
        return _grs_space(marks[_M["SPACE"]])
    if _M["INODES"] in marks:
        return _grs_inodes(marks[_M["INODES"]])
    return next((i18n.Sentence(why) for key, why in table if _M[key] in marks), None)


def _grs_ready(line):
    """The values the READY line carries ({"up", "t0", "need", "members"}), or None when it is not whole."""
    got = (line or "").split()
    parts = got + ["0"] * 6
    if len(got) < 3 or parts[1] not in ("0", "1") or not parts[2].isdecimal():
        return None
    num = [int(p) if p.isdecimal() else 0 for p in (parts[3], parts[5])]
    return {"up": parts[1] == "1", "t0": int(parts[2]), "need": num[0], "members": num[1]}


def vet_outcome(out):
    """(state, value): ("ready", {"up", "t0", "need"}), ("refused", sentence) or ("unread", sentence)."""
    marks = _grs_marks(terminal.strip_escapes(out or ""))
    ready = _grs_ready(marks.get(_M["READY"]))
    if ready is not None:
        return "ready", ready
    why = _grs_refusal(marks, _GRS_VET_REFUSALS)
    if why is not None:
        return "refused", why
    return "unread", i18n.Sentence("the checks' result did not come back")


_GRS_LATE_REFUSALS = _GRS_VET_REFUSALS + (
    ("CRONFAIL", "the game account's crontab could not be set aside for the switch-over"),
    ("LGSMBUSY", "a LinuxGSM command of the game account was still running two minutes after its crontab was set aside"),
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
    marks = _grs_marks(terminal.strip_escapes(out or ""))
    if _M["RESTORED"] in marks:
        return "done", i18n.Sentence("restored")
    if _M["ROLLEDBACK"] in marks:
        return "refused", i18n.Sentence("the switch-over to the archive's files could not be completed, and it was undone")
    if _M["SWITCHING"] in marks:
        return "failed", _grs_late_failure(marks, rc)
    if _M["STAGEFAIL"] in marks:
        sf = (marks[_M["STAGEFAIL"]] or "").split(None, 2)
        return "refused", i18n.Sentence("the archive could not be unpacked into a staging folder (tar exit {rc}): "
                                        "{last}", rc=sf[1] if len(sf) > 1 else "?",
                                        last=(sf[2] if len(sf) > 2 else "")[:200])
    why = _grs_refusal(marks, _GRS_LATE_REFUSALS)
    if why is not None:
        return "refused", why
    return "unread", i18n.Sentence("the restore's result did not come back (exit {rc})", rc=rc)


def _grs_late_failure(marks, rc):
    """What went wrong once the switch had begun and was not undone (or did not answer)."""
    if _M["ROLLBACKFAIL"] in marks:
        return i18n.Sentence("the switch-over failed and could not be undone; the server's own files are in {path}",
                             path=(marks[_M["ROLLBACKFAIL"]].split(None, 1) + [""])[1])
    return i18n.Sentence("the switch-over did not report how it ended (exit {rc})", rc=rc)


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
    lines = ["set -o pipefail", "export LC_ALL=C"] + _grs_heartbeat() + [
        _grs_part(user, uid),
        'if [ ! -f "$p" ] || [ -L "$p" ]; then echo %s; exit 5; fi' % _M["NOPART"],
        's=$(stat -c %s -- "$p")',
        'if [ "$s" != %d ]; then %s echo "%s $s"; exit 5; fi' % (int(size), rm, _M["UPOFFSET"]),
        "m=$(head -c 4 -- \"$p\" | od -An -tx1 | tr -d ' \\n')",
        'case "$m" in 28b52ffd) f=--zstd; x=zst;; 1f8b*) f=--gzip; x=gz;; '
        '*) if [ "$(dd if="$p" bs=1 skip=257 count=5 2>/dev/null)" = ustar ]; then f=; x=tar; '
        'else %s echo %s; exit 5; fi;; esac' % (rm, _M["UPFORMAT"]),
    ] + _grs_member_check("p", "$f", selfname, on_refusal=rm) + [
        # gzip writes its copy beside the tar: room for a second copy first, or the game's own disk runs out.
        'if [ "$x" = tar ]; then free=$(df -PB1 -- "$B" 2>/dev/null | awk \'NR==2{print $4}\'); '
        'case "$free" in ""|*[!0-9]*) free=0;; esac; if [ "$free" -lt $(( s + %d )) ]; then %s '
        'echo "%s $(( s + %d )) $free"; exit 5; fi; fi' % (MARGIN, rm, _M["SPACE"], MARGIN),
        'if [ "$x" = tar ]; then gzip -1 -n -- "$p" 2>/dev/null || { rm -f -- "$p" "$p.gz"; echo %s; exit 6; }; '
        'p="$p.gz"; x=gz; fi' % _M["UPFAIL"],
        names, rm + " echo " + _M["UPFAIL"], "exit 6",
    ]
    return "\n".join(lines) + "\n"


def upload_cancel_script(user, uid):
    """Remove an upload's part file (and a staged piece)."""
    return "\n".join([_grs_part(user, uid), 'rm -f -- "$p" "$p.piece" "$p.gz"', "echo " + _M["UPREADY"]]) + "\n"


def recover_outcome(out):
    """What recover_script did: "done", "undone", ("failed", the aside path), "none", or None when it did not answer."""
    marks = _grs_marks(terminal.strip_escapes(out or ""))
    if _M["UPREADY"] not in marks:
        return None
    if _M["RECFAIL"] in marks:
        return ("failed", (marks[_M["RECFAIL"]].split(None, 1) + [""])[1])
    return next((v for k, v in (("RECDONE", "done"), ("RECUNDONE", "undone")) if _M[k] in marks), "none")


def upload_outcome(out):
    """(state, value) of an upload command.

    ("ok", the number or name it printed), ("offset", host size), ("refused", sentence) for a refusal
    the command printed, or ("unread", sentence) when none of its lines came back (worth a retry).
    """
    text = terminal.strip_escapes(out or "")
    marks = _grs_marks(text)
    for key in ("UPSTORED", "UPSIZE", "UPREADY"):
        if _M[key] in marks:
            return "ok", (marks[_M[key]].split() + [""])[1]
    if _M["UPOFFSET"] in marks:
        got = (marks[_M["UPOFFSET"]].split() + [""])[1]
        return "offset", int(got) if got.isdecimal() else 0
    why = _grs_refusal(marks, _GRS_UPLOAD_REFUSALS)
    if why is None:
        return "unread", i18n.Sentence("the host's answer did not come back")
    return "refused", why


_GRS_UPLOAD_REFUSALS = (
    ("UPFORMAT", "the file is not a tar archive compressed with zstd or gzip, nor a plain tar"),
    ("TARFAIL", "the archive could not be read to its end (damaged, cut short, or its decompressor is "
                "missing)"),
    ("NOPY", "python3, which LinuxGSM itself depends on, is not installed on the host"),
    ("NOPART", "the upload is no longer on the host (it was cancelled, or left too long)"),
    ("UPFAIL", "the host could not write the upload into the backup folder"),
)
