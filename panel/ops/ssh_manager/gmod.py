"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
from panel.ops.ssh_manager import (_core)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ── GMod mountable game content ────────────────────────────────────────────────────────────────
# Garry's Mod renders another Source game's maps/props only if that game's content is present AND
# mounted. We keep ONE shared copy per host under a "content user" and mount it read-only into each
# GMod server via garrysmod/cfg/mount.cfg (+ mountdepots.txt), so multiple GMod servers share it
# instead of each carrying gigabytes. Content is fetched with SteamCMD using the game's dedicated-
# content app id. Counter-Strike: Source is the essential one (the vast majority of GMod maps/addons
# expect it); more can be added to this map later.
GMOD_CONTENT_GAMES = {
    # mount-folder -> (label, LinuxGSM game name or None). We install content the same way a normal
    # LinuxGSM content box does — one shared content user with each game installed via LinuxGSM (so
    # SteamCMD, validation and a weekly `update` cron all come for free). A game NAME means the panel
    # can install it; None means MOUNT-ONLY: an owned single-player title with no LinuxGSM dedicated
    # server, mounted only when its content is already on the host.
    "cstrike":    ("Counter-Strike: Source", "cssserver"),
    "tf":         ("Team Fortress 2", "tf2server"),
    "dod":        ("Day of Defeat: Source", "dodsserver"),
    "hl2mp":      ("Half-Life 2: Deathmatch", "hl2dmserver"),
    "hl1mp":      ("Half-Life Deathmatch: Source", "hldmsserver"),
    "left4dead":  ("Left 4 Dead", "l4dserver"),
    "left4dead2": ("Left 4 Dead 2", "l4d2server"),
    "insurgency": ("Insurgency", "insserver"),
    "nmrih":      ("No More Room in Hell", "nmrihserver"),
    "fof":        ("Fistful of Frags", "fofserver"),
    "zps":        ("Zombie Panic! Source", "zpsserver"),
    "pvkii":      ("Pirates, Vikings & Knights II", "pvkiiserver"),
    "dystopia":   ("Dystopia", "dysserver"),
    "empires":    ("Empires Mod", "emserver"),
    "cure":       ("Codename CURE", "ccserver"),
    "dab":        ("Double Action: Boogaloo", "dabserver"),
    # Mount-only — owned single-player titles (no LinuxGSM dedicated server); mounted when already on
    # the host. (CS:GO is deliberately NOT here: since CS2 there's no GMod-usable download for it.)
    "hl1":        ("Half-Life: Source", None),
    "hl2":        ("Half-Life 2", None),
    "episodic":   ("Half-Life 2: Episode One", None),
    "ep2":        ("Half-Life 2: Episode Two", None),
    "lostcoast":  ("Half-Life 2: Lost Coast", None),
    "portal":     ("Portal", None),
    "portal2":    ("Portal 2", None),
}
# Rough download sizes for the UI so nobody accidentally pulls 13GB (installable games only).
GMOD_CONTENT_SIZES = {"cstrike": "~1.6 GB", "tf": "~13 GB", "dod": "~1.1 GB", "hl2mp": "~2 GB",
                      "hl1mp": "~1 GB", "left4dead": "~3 GB", "left4dead2": "~9 GB",
                      "insurgency": "~7 GB", "nmrih": "~6 GB", "fof": "~2 GB", "zps": "~2 GB",
                      "pvkii": "~3 GB", "dystopia": "~1.5 GB", "empires": "~2 GB", "cure": "~2 GB",
                      "dab": "~3 GB"}
_GMOD_SELFNAME = "gmodserver"   # GameServer.lgsm_name is always "<game_type>server"
_CONTENT_USER = "gmodcontent"                         # panel-managed content user, created if none exists
_CU_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]*\Z")   # Linux username charset (reaches root-run cmds)

# The LinuxGSM script names that exist on a host purely as GMod mountable content.
CONTENT_LGSM_NAMES = frozenset(n for _label, n in GMOD_CONTENT_GAMES.values() if n)


def content_box_users(found):
    """Which users in a discovery scan hold GMod CONTENT rather than game servers.

    Content is installed "the same way a normal LinuxGSM content box does" (see the note on
    GMOD_CONTENT_GAMES above): one shared user with each game installed through LinuxGSM, which
    means each content game has exactly the things discovery looks for — an
    `lgsm/config-lgsm/<game>server/` dir and an executable `~/<game>server`. So the host scan
    reports every mounted game as an importable server. It is not one: nothing ever runs it, its
    port is whatever LinuxGSM ships as the default, and importing it produces a panel row for a
    server that does not exist.

    Worse than cosmetic, because the panel keys a host's servers on the Linux user
    (`short_name = user`, unique per host): seven content games under one user cannot import as
    seven servers no matter what. Six are silently dropped as duplicates and the seventh becomes a
    bogus row claiming to be whichever game sorted first.

    Identified structurally, never by name. "Ignore the user called srcds" would be wrong twice
    over: the content user is whatever the host already had (`detect_content_user` deliberately
    reuses an existing srcds-style box, and the panel's own default is `gmodcontent`), and
    somebody's real Source server may perfectly well run under an account called srcds.

    A user is a content box when every LinuxGSM instance it holds is a mountable content game AND
    either it holds more than one of them, or it is the account the panel creates for exactly this
    purpose. The "more than one" is what keeps a genuine single-game server visible: one CS:S
    install under its own user is a server, and is left alone. A hand-rolled content box holding
    only CS:S is therefore still listed — there is nothing on the host that distinguishes it from
    that real server, and listing an install you can decline beats hiding one you wanted.
    """
    by_user = {}
    for f in (found or []):
        user = (f.get("user") or "").strip()
        name = (f.get("lgsm_name") or "").strip()
        if user and name:
            by_user.setdefault(user, set()).add(name)
    return {u for u, names in by_user.items()
            if names <= CONTENT_LGSM_NAMES and (len(names) > 1 or u == _CONTENT_USER)}


def _valid_content_games(games):
    """Keep only known content keys (each a constant [a-z] folder name), de-duped, order preserved."""
    seen, out = set(), []
    for g in (games or []):
        if g in GMOD_CONTENT_GAMES and g not in seen:
            seen.add(g)
            out.append(g)
    return out


def _user_primary_group(server, user):
    """The account's primary group name, or "" if we could not read it.

    It used to discard the rc and fall back to the USERNAME on failure. That is a guess, and it
    feeds `content-grant-read`, whose job is `usermod -aG <group> <gmod user>` — so a failed
    lookup granted membership of whatever group happened to share the account's name. On a remote
    host the only other thing standing in front of that is the denylist in privileged.py.

    "" instead, so the caller can tell a real group from a failed read; the grant refuses rather
    than guessing which group to join."""
    grp, _, rc = _core.run_command(server, f"id -gn {_core._quote(user)} 2>/dev/null", timeout=10)
    if rc != 0:
        _core._log.warning("could not read the primary group of %s", user)
        return ""
    return (grp or "").strip()


def detect_content_user(server, games=("cstrike",)):
    """Find a host user whose serverfiles already hold the wanted game content (e.g. an existing
    srcds / LinuxGSM cssserver). Returns {"user", "group", "present": {game: path}} for the user with
    the MOST wanted games present, else None — so a GMod install can reuse content already on the host
    instead of re-downloading gigabytes. One sudo scan; only constant game keys reach the shell."""
    wanted = _valid_content_games(games) or list(GMOD_CONTENT_GAMES)
    try:
        # Was a shell loop over /home building its inner list by interpolating the game keys. The
        # verb takes the keys as arguments and walks the directories itself.
        out, _, _ = _core.run_privileged(server, "content-scan", wanted, timeout=30, merge_stderr=False)
    except Exception:
        _core._log.debug("detect_content_user scan failed", exc_info=True)
        return None
    by_user = {}
    for line in (out or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3 and parts[0] == "HIT" and _CU_NAME_RE.match(parts[1]) and parts[2] in GMOD_CONTENT_GAMES:
            by_user.setdefault(parts[1], set()).add(parts[2])
    if not by_user:
        return None
    user = max(by_user, key=lambda u: len(by_user[u]))
    return {"user": user, "group": _user_primary_group(server, user),
            "present": {g: f"/home/{user}/serverfiles/{g}" for g in sorted(by_user[user])}}


def ensure_content_user(server):
    """Return an existing content user (reuse), else create a locked, non-login content user with an
    empty serverfiles dir to install content into. Returns {"user", "group", "present"} or None on
    failure. Never downloads here — just guarantees a home."""
    found = detect_content_user(server, tuple(GMOD_CONTENT_GAMES))
    if found:
        return found
    u = _CONTENT_USER
    exists, _, _ = _core.run_command(server, f"id {_core._quote(u)} >/dev/null 2>&1 && echo Y || echo N", timeout=10)
    if "Y" not in (exists or ""):
        # Was one root shell: useradd && passwd -l ; install -d. Three verbs, and the
        # serverfiles path is built by the helper from the validated name.
        _, err, rc = _core.create_game_user(server, u, timeout=30)
        if rc == 0:
            _core.run_privileged(server, "user-lock-password", [u], timeout=10, merge_stderr=False)
            _, err, rc = _core.run_privileged(server, "content-dir-create", [u], timeout=30)
        if rc != 0:
            _core._log.warning("ensure_content_user: could not create %s: %s", u, (err or "")[:200])
            return None
    return {"user": u, "group": _user_primary_group(server, u), "present": {}}


_DF_PATH_RE = re.compile(r"^/[\w./-]*\Z")   # absolute path, no shell metacharacters


def path_disk_free(server, path="/home"):
    """Free + total bytes of the filesystem holding `path` (where game content is stored). Returns
    (free_bytes, total_bytes) or (None, None). Best-effort; falls back to /home for a bad path."""
    p = path if _DF_PATH_RE.match(path or "") else "/home"
    # Was `df -PB1 <path> | awk 'NR==2{print $2, $4}'`. Same two fields, read in Python.
    out, _, _ = _core.run_privileged(server, "disk-free", [p], timeout=10, merge_stderr=False)
    rows = (out or "").splitlines()
    if len(rows) < 2:
        return None, None
    fields = rows[1].split()
    try:
        return int(fields[3]), int(fields[1])      # available, total
    except (IndexError, ValueError):
        return None, None


def content_present(server, content_user, game):
    """Whether <content_user>/serverfiles/<game> exists on the host: True, False, or None when the
    probe could not be RUN.

    The None is the point, the same way it is in gmod_current_mounts below. This used to be
    `return rc == 0`, which turned a call that never happened into the positive assertion "this
    game's content is NOT on the host" — and on the non-raising transports (tailscale, local) a
    call that never happened is exactly what a blip looks like: ("", "…timed out", -1), no
    exception. Only paramiko raises. All three callers took that False as fact: uninstall credited
    itself with a removal it had not confirmed (the operator is told gigabytes were freed that are
    still on disk), the cron sweep concluded nothing was installed and DELETED the weekly
    content-update cron, and install re-ran a multi-hour SteamCMD download over content already
    there. Two states cannot carry "I don't know", so there are three.

    The verb answers with its EXIT STATUS on both transports — the helper returns 0/1 and prints
    nothing, and the remote rendering is a bare `test -d`. It did not used to be: it ended in
    `&& echo Y || echo N`, which always exits 0, so `rc == 0 or ...` was unconditionally true on
    every remote host and this said "present" about content that had never been downloaded.

    That 0/1 is also why the third state is safe to name — but read the rule as "0 and 1 are the
    only ANSWERS", not as "nothing else can come back". This docstring used to say `test -d` has no
    other exit status to give, which is true of the remote rendering and NOT of the local path:
    tools/panel-helper exits 2 for a verb it does not know or an argument it refuses (its own usage
    banner says so), which is exactly what a host whose panel has been updated past its root-owned
    helper answers with. An rc of 2 is still not a reading of the disk — the probe never ran — so
    classifying on the two statuses that ARE answers, rather than on "anything but 0", is what
    keeps that host out of the "not installed" bucket it used to land in."""
    if not (_CU_NAME_RE.match(content_user or "") and game in GMOD_CONTENT_GAMES):
        return False
    _out, _err, rc = _core.run_privileged(server, "content-game-present", [content_user, game],
                                    timeout=10, merge_stderr=False)
    if rc == 0:
        return True
    if rc == 1:
        return False
    _core._log.warning("content_present: could not probe %s for %s — reporting unknown",
                       game, content_user)
    return None




def _content_update_cron_body(content_user, lgsm_names):
    """Pure: the /etc/cron.d text that weekly-updates each content game as the content user. Mirrors a
    standard LinuxGSM content box — `update-lgsm` (refresh scripts) Sunday 1AM then `update` (refresh
    content) Sunday 2AM, staggered so they don't all run at once. content_user is validated upstream;
    lgsm_names are constant script names, so the output is safe to write verbatim."""
    lines = ["# LinuxGSM Panel - weekly GMod content updates for %s (managed by the panel)." % content_user,
             "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    for i, lgsm in enumerate(lgsm_names):
        lines.append("%d 1 * * 0 %s /home/%s/%s update-lgsm > /dev/null 2>&1"
                     % (min(59, i * 2), content_user, content_user, lgsm))
    for i, lgsm in enumerate(lgsm_names):
        lines.append("%d 2 * * 0 %s /home/%s/%s update > /dev/null 2>&1"
                     % (min(59, i * 10), content_user, content_user, lgsm))
    return "\n".join(lines) + "\n"


def install_gmod_content(server, content_user, games, on_progress=None):
    """Install each game's content under the content user via LinuxGSM — the same way a normal
    LinuxGSM content box does: fetch the game's script, then `auto-install` (non-interactive; runs
    SteamCMD + validate). Multiple games share ~/serverfiles, each in its own game dir. Skips games
    already present, then (re)writes the weekly update cron so content stays current. Long-running.
    Returns (ok, installed_list, msg).

    `msg` says which of the five things happened to each game, because there is no single sentence
    that is true of all of them. It used to be `"installed: …" if installed else "already present"`,
    and that else-branch is the same defect this function's probe was fixed for, one level up: with
    every probe unreadable nothing is installed, nothing is SKIPPED-because-present either, and the
    function still answered "already present" — a positive claim about the host's disk built out of
    reads that never happened. A skipped mount-only game and a download that ran and produced
    nothing both landed on it too."""
    games = _valid_content_games(games)
    # _CU_NAME_RE is a username grammar, and "root" satisfies it: the commands below run AS this
    # account, so it is held to the builder's own check too — before any probe reaches the host.
    if not (_CU_NAME_RE.match(content_user or "") and _core.game_idents_ok(content_user)):
        return False, [], "invalid content user"
    # Each game ends in exactly one of these, and only the first is a claim that content is on the
    # host because THIS run put it there.
    installed, already, unchecked, failed, manual = [], [], [], [], []
    for g in games:
        _have = content_present(server, content_user, g)
        if _have is True:
            already.append(g)
            continue
        if _have is None:
            # Skip unless the probe CONFIRMED the content is absent. An unknown here used to read
            # as "absent" and start an up-to-7200s SteamCMD download over content that is probably
            # already on disk; skipping costs the operator a retry, downloading costs hours. It is
            # a skip, NOT a game we found — hence its own bucket in the message.
            unchecked.append(g)
            continue
        lgsm = GMOD_CONTENT_GAMES[g][1]
        if lgsm is None:
            manual.append(g)   # mount-only (owned game): no LinuxGSM server — mounts only if present
            continue
        if on_progress:
            on_progress("Installing %s content via LinuxGSM" % GMOD_CONTENT_GAMES[g][0])
        # Fetch linuxgsm.sh once (shared), create the game's script, then auto-install its content.
        inner = (f"cd /home/{content_user} && "
                 f"{{ [ -x linuxgsm.sh ] || {{ wget -q -O linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh; }}; }} && "
                 f"bash linuxgsm.sh {lgsm} && ./{lgsm} auto-install")
        _core.shell_as_game_user(server, content_user, inner, timeout=7200)
        _now = content_present(server, content_user, g)
        if _now is True:
            installed.append(g)   # only a CONFIRMED read credits an install; the route prints this
        elif _now is False:
            failed.append(g)      # the download ran and the content is genuinely not there
        else:
            unchecked.append(g)   # it may well be there; we cannot say, so we do not say
    # An unwritten update cron is part of the outcome, not a detail for the log: the content this
    # call just downloaded is exactly what that cron keeps current, and it is written HERE, at the
    # end of the install — so "could not, left it alone" means a content box with no update job at
    # all. Both of ensure_content_update_cron's callers throw its return value away, so the fact
    # has to travel in the message instead. See its docstring for the third state.
    _cron = None
    try:
        _cron = ensure_content_update_cron(server, content_user)
    except Exception:
        _core._log.debug("content update cron setup failed", exc_info=True)
    _parts = [_lbl + ": " + ", ".join(_gs) for _lbl, _gs in
              (("installed", installed), ("already present", already),
               ("could not check", unchecked), ("install failed", failed),
               ("no LinuxGSM installer", manual)) if _gs]
    if _cron is not True:
        _core._log.warning("gmod content install: %s's weekly update cron was not written (%s) — "
                           "its content will not be kept current until this runs again",
                           content_user, "host unreadable" if _cron is None else "the write failed")
        _parts.append("weekly update cron not written")
    return True, installed, ("; ".join(_parts) or "nothing to install")


def _installed_content_lgsm_names(server, content_user):
    """LinuxGSM game names of the content games currently installed under the content user (its
    serverfiles has that game's dir AND the game's script exists) — or None when any probe in the
    sweep could not be read. Used to build the update cron.

    None, not a short list. The only caller rewrites the cron to match exactly what comes back, so a
    game this could not see is a game whose weekly update job gets dropped; and when the host stops
    answering mid-sweep EVERY game goes unseen, which used to come back as [] — "nothing is
    installed" — and deleted the cron outright. A partial answer is worse than no answer here, so
    the first unreadable probe ends the sweep."""
    names = []
    for g, (_lbl, lgsm) in GMOD_CONTENT_GAMES.items():
        if not lgsm:
            continue
        present = content_present(server, content_user, g)
        if present is None:
            return None
        if not present:
            continue
        # Exit status only, on both transports — see content_present above for why the
        # `or "Y" in out` half had to go with the `&& echo Y || echo N` that produced it. And, as
        # there, `test -x` only ever exits 0 or 1, so any other rc is a failed read and not "the
        # script isn't there".
        _o, _e, _rc = _core.run_privileged(server, "content-script-present", [content_user, lgsm],
                                     timeout=10, merge_stderr=False)
        if _rc == 0:
            names.append(lgsm)
        elif _rc != 1:
            _core._log.warning("content script probe failed for %s/%s — reporting unknown",
                               content_user, lgsm)
            return None
    return names


# What `crontab -l` prints for a user who simply has no crontab. Same marker (and same reason for
# reading it) as cron.py's _NO_CRONTAB_RE; kept local so this module doesn't import its sibling.
_NO_CRONTAB_RE = re.compile(r"no crontab for", re.I)


def ensure_content_update_cron(server, content_user):
    """Write a weekly cron (as the content user) that keeps every installed content game current —
    Source games DO get content updates, and a stale copy eventually stops matching clients. Mirrors a
    standard LinuxGSM content box: `update-lgsm` (refresh scripts) Sunday 1AM, then `update` (refresh
    content via SteamCMD) Sunday 2AM, staggered so they don't all run at once. Idempotent — rewrites
    the whole file to match whatever is currently installed. Removes the file when nothing's left.

    Three answers, like every other read in this module: True when the host's cron now matches what
    is installed (written, removed, or already the admin's own job), False when there is nothing to
    manage or the write itself failed, and None when a probe could not be READ and this therefore
    changed NOTHING.

    None rather than False, and the distinction is the whole reason it exists. Declining to touch
    the cron is right when the host cannot be read — a partial view of it deletes update jobs for
    games that are still installed — but "declined" is not "done", and this runs at the END of a
    content install, where the cron it is leaving alone does not exist yet. A single blip on a 10s
    read would otherwise mean a content box that never gets an update cron at all, with nothing but
    a log line to say so; both callers discard this return value, so they must put the fact in the
    message they hand back instead. The read below also gets a second attempt before it gives up,
    because one timeout is a poor reason to leave a fresh install un-updated forever."""
    if not _CU_NAME_RE.match(content_user or ""):
        return False
    # If the content user already automates updates in its OWN crontab (e.g. a hand-rolled content box
    # like an existing srcds), leave it alone — never add duplicate update jobs on top of the admin's.
    #
    # `crontab -l` exits non-zero both when the user HAS no crontab and when the read failed, and
    # only the message tells them apart — the same test cron.py's read_cron_jobs makes. The rc was
    # discarded here, so a host that did not answer read as "this user automates nothing", and the
    # panel went on to manage a cron next to one it could not see.
    ct, ct_err, ct_rc, ct_read = "", "", -1, False
    for _ in range(2):          # one timeout is a poor reason to leave an install un-updated
        ct, ct_err, ct_rc = _core.run_privileged(server, "crontab-list", [content_user], timeout=10,
                                                 merge_stderr=False)
        ct_read = ct_rc == 0 or bool(_NO_CRONTAB_RE.search("%s\n%s" % (ct_err or "", ct or "")))
        if ct_read:
            break
    if not ct_read:
        _core._log.warning("content update cron: could not read %s's crontab — leaving the cron "
                           "as it is", content_user)
        return None
    for line in (ct or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and re.search(r"\bupdate(-lgsm)?\b", s):
            return True   # the user already updates its content; don't manage a second cron
    names = _installed_content_lgsm_names(server, content_user)
    if names is None:
        # An unreadable sweep is not an empty host. Removing the cron on one is how every content
        # game on a host that blipped stops updating — silently, and nothing puts it back.
        _core._log.warning("content update cron: install sweep unreadable for %s — leaving the "
                           "cron as it is", content_user)
        return None
    if not names:
        _core.run_privileged(server, "content-cron-remove", [content_user], timeout=10,
                       merge_stderr=False)
        return True
    _, _, rc = _core.write_content_cron(server, content_user,
                                  _content_update_cron_body(content_user, names), timeout=15)
    return rc == 0


def uninstall_gmod_content(server, content_user, games):
    """Remove each game's content from the host content user — the content dir plus its LinuxGSM
    install (script + config) — then refresh the weekly update cron so it no longer lists the removed
    games. HOST-WIDE: this frees disk for every GMod server on the host, so any server still mounting
    it just loses that content (GMod skips a missing mount). Returns (ok, removed_list, msg), where
    removed_list holds only the games whose absence was CONFIRMED afterwards — the caller prints it
    as what was freed, so a game the host would not answer about belongs in the message, not in
    that list."""
    games = _valid_content_games(games)
    # _CU_NAME_RE is a username grammar, and "root" satisfies it: the commands below run AS this
    # account, so it is held to the builder's own check too — before any probe reaches the host.
    if not (_CU_NAME_RE.match(content_user or "") and _core.game_idents_ok(content_user)):
        return False, [], "invalid content user"
    removed, unverified = [], []
    for g in games:
        lgsm = GMOD_CONTENT_GAMES[g][1]
        # The verb takes the NAMES; the helper builds the paths — three removals that used to be
        # `rm -rf`s built from an interpolated user name and game key. Validated names are NOT what
        # makes this safe as root: the content account owns every directory on the way and can
        # turn any of them into a symlink, which a fixed subpath does nothing about. The helper
        # walks each path by descriptor, O_NOFOLLOW at every step (_remove_under_home), so a link
        # on the way is refused rather than followed. The shared lgsm/ framework dir is left for
        # the other games.
        _core.run_privileged(server, "content-game-remove", [content_user, g, lgsm or "-"],
                       timeout=120, merge_stderr=False)
        # `is False`, not `not …`: the probe is the ONLY evidence this removal happened (the rm's
        # own rc says nothing about the other two paths), and an unknown used to be falsy — so a
        # host that stopped answering during the 120s rm put the game in `removed` and the operator
        # was told, verbatim, that gigabytes still on disk had been freed. Only a confirmed absence
        # counts; anything else is reported as unverified so the next run tries again.
        if content_present(server, content_user, g) is False:
            removed.append(g)
        else:
            unverified.append(g)
    _cron = None
    try:
        _cron = ensure_content_update_cron(server, content_user)   # rescan -> drop removed games
    except Exception:
        _core._log.debug("content update cron refresh after uninstall failed", exc_info=True)
    if unverified:
        _core._log.warning("gmod content uninstall: could not confirm %s was removed for %s",
                           ", ".join(unverified), content_user)
    _msg = ("removed: " + ", ".join(removed) if removed else "nothing to remove")
    if unverified:
        _msg += "; unverified: " + ", ".join(unverified)
    if _cron is not True:
        # Same reason as in install_gmod_content: the return is dropped by both callers, so the
        # only place this can be said is the message. Here it means the weekly cron still lists
        # games that are gone — harmless to run, but it is not the state the refresh promised.
        _core._log.warning("gmod content uninstall: %s's weekly update cron was not refreshed (%s)",
                           content_user, "host unreadable" if _cron is None else "the write failed")
        _msg += "; update cron not refreshed"
    return True, removed, _msg


def _gmod_mount_files(content_user, games):
    """Build the (mount.cfg, mountdepots.txt) text GMod reads to mount each game's content from the
    content user's serverfiles. Pure — content_user is a validated Linux username and every game is a
    constant key, so the output is safe to write verbatim. hl2 depot is always enabled (base content)."""
    mountcfg = '"mountcfg"\n{\n' + "".join(
        '\t"%s"\t"/home/%s/serverfiles/%s"\n' % (g, content_user, g) for g in games) + "}\n"
    depots = ('"gamedepotsystem"\n{\n\t"hl2"\t\t"1"\n'
              + "".join('\t"%s"\t\t"1"\n' % g for g in games) + "}\n")
    return mountcfg, depots


def _mount_needs_restart(server, gmod_user):
    """Whether a mount change still needs a server restart before GMod can act on it.

    Two separate reasons, both only cleared by a restart: GMod reads mount.cfg once at startup, and
    `content-grant-read`'s `usermod -aG` reaches only processes started AFTER it -- a running srcds
    keeps the group set it was spawned with and cannot read a single content file. Measured on the
    test host: before the restart the process had `Groups: 1003`, after it `Groups: 1003 1010`, and
    only then did GMod log `Adding mount.cfg path: /home/gmodcontent/serverfiles/cstrike`.

    A read that FAILS answers True. A spurious "restart to apply" costs a restart nobody needed; a
    missing one tells the user their content is mounted when it silently is not there."""
    inner = _core._tmux_live_socket_sh(_GMOD_SELFNAME) + "echo __LIVE__"
    try:
        out, _err, rc = _core.shell_as_game_user(server, gmod_user, inner, timeout=15)
    except Exception:
        _core._log.debug("mount restart check failed", exc_info=True)
        return True
    if rc == 3 and "NO_SESSION" in (out or ""):
        return False                     # positively stopped: the next start reads the new mounts
    return True


def gmod_mount_setup(server, gmod_user, content_user, games):
    """Write a GMod server's mount config to mount exactly `games` from the content user, granting the
    GMod user read access first. An EMPTY `games` writes an empty mount.cfg (unmounts everything).
    Idempotent. Returns (ok, msg). Group membership takes effect when the GMod server (re)starts."""
    import base64
    games = _valid_content_games(games)
    # Both accounts go into commands run AS them — see install_gmod_content for why the builder's
    # own check is applied on top of _CU_NAME_RE.
    if not (_CU_NAME_RE.match(gmod_user or "") and _core.game_idents_ok(gmod_user)):
        return False, "invalid gmod user"
    if games and not (_CU_NAME_RE.match(content_user or "") and _core.game_idents_ok(content_user)):
        return False, "invalid content user"
    if games:
        group = _user_primary_group(server, content_user)
        if not group:
            # No group, no grant. This used to receive the content user's NAME as a fallback when
            # the lookup failed, and hand that to `usermod -aG` — joining whatever group happened
            # to share the name. Refusing costs a mount that cannot read the shared content, which
            # the caller reports; guessing costs a group membership nobody asked for.
            return False, ("Couldn't read %s's group, so the content mount was not granted. "
                           "Check the account exists on this host." % content_user)
        # Read access: add the GMod user to the content group, and make the content group-traversable
        # (home) + group-readable (each game tree). Best-effort per command.
        _core.run_privileged(server, "content-grant-read",
                       [content_user, group, gmod_user] + list(games), timeout=180,
                       merge_stderr=False)
    # Write mount.cfg + mountdepots.txt AS the GMod user (base64 so no quoting/interpolation risk).
    mountcfg, depots = _gmod_mount_files(content_user or "", games)
    cfgdir = f"/home/{gmod_user}/serverfiles/garrysmod/cfg"
    b64c = base64.b64encode(mountcfg.encode()).decode()
    b64d = base64.b64encode(depots.encode()).decode()
    inner = (f"mkdir -p {cfgdir} && echo {b64c} | base64 -d > {cfgdir}/mount.cfg && "
             f"echo {b64d} | base64 -d > {cfgdir}/mountdepots.txt && echo __OK__")
    out, err, rc = _core.shell_as_game_user(server, gmod_user, inner, timeout=30)
    if rc != 0 or "__OK__" not in (out or ""):
        return False, (err or out or "mount write failed")[:200]
    _msg = ("Unmounted all content" if not games else
            "Mounted: " + ", ".join(GMOD_CONTENT_GAMES[g][0] for g in games))
    if _mount_needs_restart(server, gmod_user):
        _msg += " — restart the server to apply"
    return True, _msg


_MOUNT_LINE_RE = re.compile(r'"([a-z0-9_]+)"\s+"/')


def gmod_current_mounts(server, gmod_user):
    """Which content games a GMod server currently mounts, parsed from its garrysmod/cfg/mount.cfg.
    Returns a list of known game keys (order as written), [] when the file is absent or mounts
    nothing, or None when the mount state could not be READ. Read-only.

    The None is the whole point. This used to return [] for a failed read too, and the uninstall
    path computes `remaining = [g for g in gmod_current_mounts(...) if g not in games]` and writes
    THAT back — so a blip turned "remove CS:S" into an empty mount.cfg that dropped every other
    mount the server had, and reported "Unmounted all content". Measured on the test host: a server
    mounting cstrike AND hl2mp, asked to remove only hl2mp with the read failing, ended with an
    empty mountcfg and lost cstrike.

    The helper exits 0 whether or not a mount.cfg exists, so a non-zero rc here means the call
    itself did not complete — which is exactly the distinction "[] vs None" needs."""
    if not _CU_NAME_RE.match(gmod_user or ""):
        return []
    out, _, rc = _core.run_privileged(server, "gmod-mount-read", [gmod_user], timeout=10,
                               merge_stderr=False)
    if rc != 0:
        _core._log.warning("gmod_current_mounts: could not read mounts for %s — reporting unknown",
                           gmod_user)
        return None
    found = []
    for line in (out or "").splitlines():
        s = line.strip()
        if s.startswith("//"):
            continue   # a commented-out mount (Valve KeyValues // comment) is NOT active
        m = _MOUNT_LINE_RE.search(s)
        if m and m.group(1) in GMOD_CONTENT_GAMES and m.group(1) not in found:
            found.append(m.group(1))
    return found
