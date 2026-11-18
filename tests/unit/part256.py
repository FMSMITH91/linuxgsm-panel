"""Part 256 of the unit suite: install outcomes, re-created user journals, and a test checkout's update card.

1. LinuxGSM's own outcome: the exit status the install command prints after LinuxGSM ends, its FAIL
   lines, and its checksum report (core_dl.sh fn_dl_hash), read from output shaped as LinuxGSM prints it.
2. Installed or not: `details` prints its Status block for an account whose download failed, so the
   check also asks whether the executable LinuxGSM starts is there, from the instance's own config.
   The real shell runs under bash in a throwaway home, with a stand-in game script.
3. Step 4 of the install: a download that fails LinuxGSM's checksum is fetched once more (its cached
   file wiped) and then reported with LinuxGSM's numbers; another LinuxGSM failure is reported with
   its own FAIL line; a second good download installs.
4. The helper's forget path: after its rotation, the empty user journals journald re-created for
   accounts that are gone are deleted too, and nothing else is.
5. The update card for a checkout that is not on the branch it follows (a branch install): nothing is
   offered when the checkout already holds the branch's tip.

HOW IT RUNS. Host calls go through part12's seams with its transport tripwire armed; the shells run
under bash in a throwaway folder. The update card runs the real code over a scratch git history.
"""
import os
import shlex as _shlex256
import shutil as _shutil256
import subprocess as _sp256  # nosec B404 - bash and git on this part's own throwaway files
import tempfile as _tf256
from types import SimpleNamespace as _NS256

from unit.part01 import check, eq
from unit.part05 import _helper as _h256
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_ms, _p9_patch_sm, _p9_restore_all, _p9_sh
from panel.core import i18n as _i18n256
from panel.ops import system_ops as _so256
from panel.ops.ssh_manager import hosts as _hosts256

_trips256 = len(_P9_TRIPPED)
_TMP256 = _tf256.mkdtemp(prefix="p256-")
_ACCT256, _SELF256 = "nx256game", "codwawserver"
_ARCHIVE256 = "codwaw-1.7-linux-i386-linuxgsm-20261101.tar.xz"
_GOT256, _WANT256 = "0123456789abcdef0123456789abcdef", "d7bdc6b2a671c3e07184e1a3262ec14c"
# What LinuxGSM v26.6.0 prints when the archive fails its MD5 (core_dl.sh fn_fetch_file + fn_dl_hash),
# colours included, then the install command's own exit line.
_SUM_OUT256 = ("downloading file [ \x1b[3m%s\x1b[0m ]\n#################### 100.0%%\n"
               "downloading file [ \x1b[3m%s\x1b[0m ] ... \x1b[32mOK\x1b[0m\n"
               "verifying %s with MD5 ... \x1b[31mFAIL\x1b[0m\n%s returned MD5 checksum: %s\n"
               "expected MD5 checksum: %s\n" % (_ARCHIVE256, _ARCHIVE256, _ARCHIVE256, _ARCHIVE256, _GOT256,
                                                _WANT256))
_CFG_FAIL256 = ("\x1b[1m[\x1b[31m FAIL \x1b[0m]\x1b[0m Installing codwawserver: Installing Call of Duty: World at War "
                "Server failed, missing default configuration\n")


# ── 1. LinuxGSM's outcome ───────────────────────────────────────────────────────────────────────
def _outcome256():
    out = _SUM_OUT256 + "__LGSM_EXIT__=1\n"
    eq("install outcome: the exit status LinuxGSM ended with is read from the command's own line (the last one "
       "wins); none without it",
       [_hosts256.lgsm_exit_status(out), _hosts256.lgsm_exit_status("__LGSM_EXIT__=0\n" + out),
        _hosts256.lgsm_exit_status(_SUM_OUT256)], [1, 1, None])
    eq("install outcome: LinuxGSM's checksum report is read as (file, kind, got, expected)",
       _hosts256.lgsm_checksum_failure(out), (_ARCHIVE256, "MD5", _GOT256, _WANT256))
    eq("install outcome: LinuxGSM's FAIL lines, both forms, colours stripped",
       [_hosts256.lgsm_fail_lines(out), _hosts256.lgsm_fail_lines(_CFG_FAIL256), _hosts256.lgsm_fail_lines("OK\n")],
       ["verifying %s with MD5 ... FAIL" % _ARCHIVE256,
        "[ FAIL ] Installing codwawserver: Installing Call of Duty: World at War Server failed, missing default "
        "configuration", ""])
    why = _hosts256.classify_install_failure(out)
    check("install outcome: a checksum failure is classified, and its reason names the file and LinuxGSM's numbers",
          why is not None and why[0] == "download_checksum" and isinstance(why[1], _i18n256.Sentence)
          and all(x in str(why[1]) for x in (_ARCHIVE256, "MD5", _GOT256, _WANT256)), repr(why))


# ── 2. installed or not: the executable LinuxGSM starts ─────────────────────────────────────────
def _home256(tag):
    """A throwaway game home: a stand-in script, LinuxGSM's config folder, serverfiles/Logs (as install makes)."""
    home = os.path.join(_TMP256, tag)
    _shutil256.rmtree(home, ignore_errors=True)
    os.makedirs(os.path.join(home, "lgsm", "config-lgsm", _SELF256))
    os.makedirs(os.path.join(home, "serverfiles", "Logs"))
    os.makedirs(os.path.join(home, "lgsm", "tmp"))
    with open(os.path.join(home, _SELF256), "w", encoding="utf-8") as fh:
        fh.write('#!/bin/bash\ngameservername="%s"\nH=%s\n'
                 'if [ "$1" = details ]; then echo "Status: STOPPED"; echo "Server IP: 0.0.0.0:28960"; exit 0; fi\n'
                 'n=$(cat "$H/count" 2>/dev/null || echo 0); echo $((n + 1)) > "$H/count"\n'
                 'cat "$H/out.$n" 2>/dev/null; if [ -f "$H/exe.$n" ]; then : > "$H/serverfiles/codwaw_lnxded"; fi\n'
                 'exit "$(cat "$H/rc.$n" 2>/dev/null || echo 0)"\n' % (_SELF256, _shlex256.quote(home)))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(os.path.join(home, _SELF256), 0o700)  # nosec B103 - the stand-in script, owner only
    _cfg256(home, 'systemdir="${serverfiles}"\nexecutabledir="${systemdir}"\nexecutable="./codwaw_lnxded"\n')
    return home


def _cfg256(home, text):
    with open(os.path.join(home, "lgsm", "config-lgsm", _SELF256, "_default.cfg"), "w", encoding="utf-8") as fh:
        fh.write(text)


def _bash256(home, sh):
    """Run `sh` under bash with the account's home moved to `home` -> (out, err, rc)."""
    r = _sp256.run(["bash", "-c", sh.replace("/home/" + _ACCT256, home)],  # nosec B603 B607 - bash, own text
                   capture_output=True, text=True, timeout=60, check=False)
    return r.stdout, r.stderr, r.returncode


def _as_game256(home, seen):
    def run(remote, user, sh, timeout=30, selfname=None, **_k):
        seen.append(sh)
        return _bash256(home, sh)
    return run


def _looks256(home):
    _p9_patch_sm("shell_as_game_user", _as_game256(home, []))
    return _p9_sh._looks_installed(_p9, _NS256(), _ACCT256, _SELF256)


def _installed256():
    home = _home256("looks")
    got = [_looks256(home)]
    open(os.path.join(home, "serverfiles", "codwaw_lnxded"), "w").close()
    got.append(_looks256(home))
    eq("installed check: `details` prints its Status block, but with no executable where LinuxGSM's start looks "
       "for it the server is not installed; with it, it is", got, [False, True])
    os.remove(os.path.join(home, "serverfiles", "codwaw_lnxded"))
    _cfg256(home, 'systemdir="${serverfiles}"\nexecutabledir="${systemdir}/bin"\nexecutable=$([ "$(uname -m)" '
                  '== "x86_64" ] && echo -e "./run_x64.sh" || echo -e "./run_x86.sh")\n')
    os.makedirs(os.path.join(home, "serverfiles", "bin"))
    got = [_looks256(home)]
    for name in ("run_x64.sh", "run_x86.sh"):
        open(os.path.join(home, "serverfiles", "bin", name), "w").close()
    got.append(_looks256(home))
    eq("installed check: the values are LinuxGSM's own, sourced as it sources them ($(...) and ${systemdir})",
       got, [False, True])
    os.remove(os.path.join(home, "lgsm", "config-lgsm", _SELF256, "_default.cfg"))
    no_cfg = _looks256(home)
    _cfg256(home, "exit 0\n")
    exits = _looks256(home)
    eq("installed check: a config it cannot read, or one that ends the shell, falls back to `details` (controls)",
       [no_cfg, exits], [True, True])


# ── 3. step 4 of the install ────────────────────────────────────────────────────────────────────
def _scenario256(home, steps):
    """Write the stand-in's answers: steps = [(output, exit status, makes the executable)] per download."""
    for n, (out, rc, exe) in enumerate(steps):
        with open(os.path.join(home, "out.%d" % n), "w", encoding="utf-8") as fh:
            fh.write(out)
        with open(os.path.join(home, "rc.%d" % n), "w", encoding="utf-8") as fh:
            fh.write(str(rc))
        if exe:
            open(os.path.join(home, "exe.%d" % n), "w").close()


def _step4_256(tag, steps):
    """Run _install_game_files over the scenario -> (result, fails, downloads, wipes)."""
    home = _home256(tag)
    _scenario256(home, steps)
    fails, cmds, shells = [], [], []

    def run_command(remote, cmd, timeout=30, sudo=False, **_k):
        cmds.append(cmd)
        argv = _shlex256.split(cmd)
        return _bash256(home, argv[argv.index("-c") + 1])
    _p9_patch_sm("run_command", run_command)
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 0))
    _p9_patch_sm("shell_as_game_user", _as_game256(home, shells))
    job = _NS256(app=_p9, short_name=_ACCT256, lgsm_name=_SELF256, game_type="codwaw", p=lambda *a, **k: None,
                 fail=lambda name, detail="", retryable=True, explained=False: fails.append(
                     (str(name), _p9_ms.readable_reason(str(detail)), retryable, explained)))
    with _p9.app_context():
        ok = _p9_ms._install_game_files(job, _NS256(name="p256-host", id=-256), _NS256(lgsm_name=_SELF256))
    return ok, fails, sum("auto-install" in c for c in cmds), sum("lgsm/tmp" in s for s in shells)


def _step4_256_checks():
    ok, fails, downloads, wipes = _step4_256("sum2", [(_SUM_OUT256, 1, False)] * 3)
    check("install step 4: a download that fails LinuxGSM's checksum twice ends as a failed install with "
          "LinuxGSM's reason (file, its checksum, the expected one), retryable",
          ok is False and len(fails) == 1 and _WANT256 in fails[0][0] and _GOT256 in fails[0][0]
          and fails[0][2:] == (True, True), repr(fails))
    eq("install step 4: ...after one more download, with LinuxGSM's cached file wiped before it",
       (downloads, wipes), (2, 1))
    ok, fails, downloads, wipes = _step4_256("sum1", [(_SUM_OUT256, 1, False), ("Install Complete!\n", 0, True)])
    eq("install step 4: a checksum failure the second download gets past installs", (ok, fails, downloads, wipes),
       (True, [], 2, 1))
    ok, fails, downloads, _w = _step4_256("cfgfail", [(_CFG_FAIL256, 1, False)] * 3)
    check("install step 4: another LinuxGSM failure is reported with LinuxGSM's own FAIL line, after three tries",
          ok is False and downloads == 3 and len(fails) == 1 and "LinuxGSM stopped with this failure" in fails[0][0]
          and "missing default configuration" in fails[0][1] and fails[0][2] is True, repr((downloads, fails)))
    ok, fails, downloads, _w = _step4_256("quiet", [("", 0, False)] * 3)
    check("install step 4: no LinuxGSM failure to name keeps the general reason (control)",
          ok is False and downloads == 3 and len(fails) == 1 and "may be corrupt" in fails[0][0], repr(fails))


# ── 4. the helper: journals journald re-creates for accounts that are gone ──────────────────────
_EMPTY256 = b"LPKSHHRH" + b"\0" * 160      # a journal header that counts no entries
_HELD256 = b"LPKSHHRH" + b"\0" * 144 + (3).to_bytes(8, "little") + b"\0" * 8


def _journals256(archived_only):
    root = os.path.join(_TMP256, "journal-%s" % archived_only)
    _shutil256.rmtree(root, ignore_errors=True)
    mid = os.path.join(root, "0123456789abcdef0123456789abcdef")
    os.makedirs(mid)
    files = {"user-5000@00ab-0000000000000001-0005f3a1b2c3d4e5.journal": _HELD256, "user-5001.journal": _EMPTY256,
             "user-5002.journal": _HELD256, "user-5003.journal": _EMPTY256, "user-5004.journal": _EMPTY256,
             "user-5005@00ab-0000000000000001-0005f3a1b2c3d4e5.journal": _EMPTY256, "user-999.journal": _EMPTY256,
             "user-5006.journal": b""}
    if not archived_only:
        files["user-5000.journal"] = _HELD256
    for name, body in files.items():
        with open(os.path.join(mid, name), "wb") as fh:
            fh.write(body)
    proc = os.path.join(root, "proc")
    os.makedirs(os.path.join(proc, "4242"))
    os.makedirs(os.path.join(proc, "self"))
    with open(os.path.join(proc, "4242", "status"), "w", encoding="ascii") as fh:
        fh.write("Name:\tpasta\nUid:\t5004\t5004\t5004\t5004\nGid:\t5004\t5004\t5004\t5004\n")
    return root, mid, proc


def _forget_journals256(archived_only):
    root, mid, proc = _journals256(archived_only)
    ran = []

    def getpwuid(uid):
        if uid == 5003:
            return _NS256(pw_name="live", pw_uid=uid)
        raise KeyError(uid)
    saved = {k: getattr(_h256, k) for k in ("subprocess", "resolve", "JOURNAL_ROOTS", "ADDON_TMP_DIRS", "PROC_DIR",
                                             "pwd")}
    try:
        _h256.subprocess = _NS256(run=lambda argv, **_k: ran.append(argv) or _NS256(returncode=0))
        _h256.resolve = lambda prog: prog
        _h256.JOURNAL_ROOTS = (root,)
        _h256.ADDON_TMP_DIRS = (os.path.join(_TMP256, "notmp-%d"),)
        _h256.PROC_DIR = proc
        _h256.pwd = _NS256(getpwuid=getpwuid, getpwnam=saved["pwd"].getpwnam)
        gone = _h256._addon_forget_account(5000, True)
    finally:
        for k, v in saved.items():
            setattr(_h256, k, v)
    return gone, ran, sorted(os.listdir(mid))


def _journal256():
    gone, ran, left = _forget_journals256(False)
    eq("forget (helper): after its rotation, the empty journal re-created for a uid with no account and no process "
       "goes with the account's own files; one holding entries, an archived one, a live account's, a uid with a "
       "process, one below 1000 and a file that is not a journal stay",
       (gone, ran, left), (3, [["journalctl", "--rotate"]],
                           ["user-5002.journal", "user-5003.journal", "user-5004.journal",
                            "user-5005@00ab-0000000000000001-0005f3a1b2c3d4e5.journal", "user-5006.journal",
                            "user-999.journal"]))
    gone, ran, left = _forget_journals256(True)
    eq("forget (helper): with no rotation (only archived files of the account) no other uid's file is touched",
       (gone, ran, "user-5001.journal" in left), (1, [], True))


# ── 5. the update card for a checkout that is not on its branch ─────────────────────────────────
_GENV256 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
                GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")


def _git256(*args):
    # git on this part's own fixture repositories, with no global or system config
    return _sp256.run(["git", *args], capture_output=True, text=True, env=_GENV256,  # nosec B603 B607
                      check=False).stdout.strip()


def _commit256(repo, msg):
    with open(os.path.join(repo, "f.txt"), "a", encoding="utf-8") as fh:
        fh.write(msg + "\n")
    _git256("-C", repo, "add", "-A")
    _git256("-C", repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg)
    return _git256("-C", repo, "rev-parse", "HEAD")


def _card256(co, head, signed):
    """The update card's status for a checkout at `head`, with `signed` deciding the signature gate."""
    _git256("-C", co, "checkout", "-q", "--detach", head)
    return _card_status256(signed)


def _card_status256(signed):
    saved = (_so256._release_gate_for, _so256._update_touches_runtime, _so256._tracked_branch, _so256._remote_ci_state)
    try:
        _so256._release_gate_for = lambda branch: signed
        _so256._update_touches_runtime = lambda ref: True
        _so256._tracked_branch = lambda: "main"
        _so256._remote_ci_state = lambda sha: "passing"
        return _so256._compute_update_status()
    finally:
        _so256._release_gate_for, _so256._update_touches_runtime, _so256._tracked_branch, _so256._remote_ci_state = saved


def _update256():
    up, co = os.path.join(_TMP256, "up"), os.path.join(_TMP256, "co")
    _git256("init", "-q", "-b", "main", up)
    rel = {n: _commit256(up, n) for n in ("R5", "R6", "R7")}
    _git256("clone", "-q", up, co)
    _git256("-C", co, "checkout", "-q", "--detach", rel["R7"])
    test = _commit256(co, "T")      # test code on top of the branch's tip, as a branch install runs
    saved = _so256.PANEL_DIR
    try:
        _so256.PANEL_DIR = co
        on_test = _card256(co, test, lambda sha: True)
        before = _card256(co, rel["R5"], lambda sha: sha != rel["R7"])
        rel["R8"] = _commit256(up, "R8")
        newer = _card256(co, test, lambda sha: True)
    finally:
        _so256.PANEL_DIR = saved
    eq("update card: a checkout running test code on top of the branch's newest release is told it is up to date "
       "(no older release is offered, and nothing counts as behind)",
       (on_test.get("fetched"), on_test.get("update_available"), on_test.get("behind")), (True, False, 0))
    eq("update card: ...the '1 commit behind' an older release gets is from a checkout below it while the newest "
       "was not yet signed (control)",
       (before.get("update_available"), before.get("target_sha") == rel["R6"], before.get("behind")), (True, True, 1))
    eq("update card: ...and a release newer than the test code's base is offered, as install.sh would install it",
       (newer.get("update_available"), newer.get("target_sha") == rel["R8"]), (True, True))


try:
    _outcome256()
    _p9_arm(who="part256")
    _installed256()
    _p9_restore_all()
    _p9_arm(who="part256")
    _step4_256_checks()
finally:
    _p9_restore_all()
_journal256()
_update256()
check("part256: no check reached a real host", len(_P9_TRIPPED) == _trips256, repr(_P9_TRIPPED[_trips256:][:4]))
_shutil256.rmtree(_TMP256, ignore_errors=True)
