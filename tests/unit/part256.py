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
7. An add-on install on the panel's own host: the account is put in the game group (gameuser-group,
   with its own refusals) before addon-account-prepare, which readies only a member; the helper's,
   apt's and systemctl's own words follow the sentence of a step that failed, in the row and the audit.
8. A line added to a game's config whose last line has no newline (LinuxGSM's own cod2 cfg ends that way)
   starts on a line of its own: the instance cfg's startparameters, an ini key, and the persistent-bans
   exec lines (that one's shell run under bash).
6. The Add-ons tab when an add-on needs a database and the server has none free: the list route says
   whether the host has a database server (from what the panel stored, no host call), and the tab's
   script, run whole in node over a small DOM, shows Install disabled with the reason beside it and a
   button that opens the Databases tab as the section nav does.

HOW IT RUNS. Host calls go through part12's seams with its transport tripwire armed; the shells run
under bash in a throwaway folder. The update card runs the real code over a scratch git history.
"""
import json as _json256
import os
import shlex as _shlex256
import shutil as _shutil256
import subprocess as _sp256  # nosec B404 - bash and git on this part's own throwaway files
import tempfile as _tf256
import time as _time256
from types import SimpleNamespace as _NS256

from unit.part01 import _root, check, eq
from unit.part05 import _helper as _h256
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_drain, _p9_ms, _p9_new_server, _p9_patch, _p9_patch_sm,
                         _p9_restore_all, _p9_sh)
from unit.part255 import _host255, _probe255
from panel.db.models import GameDatabase as _GD256, db as _db256
from panel.ops.ssh_manager import files as _files256, game as _game256
from panel.routes import addons as _ra256, databases as _rdb256, workshop as _ws256
from panel.services import cod_mods as _codm256
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
                 # LinuxGSM downloads only a missing file and re-checks one it has (fn_fetch_file).
                 'if [ -e "$H/lgsm/tmp/%s" ]; then cat "$H/sumfail"; exit 1; fi\n'
                 'cat "$H/out.$n" 2>/dev/null; if [ -f "$H/exe.$n" ]; then : > "$H/serverfiles/codwaw_lnxded"; fi\n'
                 'if [ -f "$H/cut.$n" ]; then echo part > "$H/lgsm/tmp/%s"; fi\n'
                 'exit "$(cat "$H/rc.$n" 2>/dev/null || echo 0)"\n'
                 % (_SELF256, _shlex256.quote(home), _ARCHIVE256, _ARCHIVE256))
    with open(os.path.join(home, "sumfail"), "w", encoding="utf-8") as fh:
        fh.write(_SUM_OUT256)
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
    """Write the stand-in's answers: steps = [(output, exit status, makes the executable[, cut off])] per download.

    A download cut off leaves its partial archive in lgsm/tmp, as LinuxGSM's curl -o does.
    """
    for n, (out, rc, exe, *cut) in enumerate(steps):
        if cut and cut[0]:
            open(os.path.join(home, "cut.%d" % n), "w").close()
        with open(os.path.join(home, "out.%d" % n), "w", encoding="utf-8") as fh:
            fh.write(out)
        with open(os.path.join(home, "rc.%d" % n), "w", encoding="utf-8") as fh:
            fh.write(str(rc))
        if exe:
            open(os.path.join(home, "exe.%d" % n), "w").close()


def _step4_256(tag, steps, before=None):
    """Run _install_game_files over the scenario -> (result, fails, downloads, wipes after a failure).

    `before(home)` changes the home first (a partial archive left by an earlier try, a linked folder).
    """
    home = _home256(tag)
    _scenario256(home, steps)
    if before:
        before(home)
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


def _linked256(home):
    """Make lgsm/tmp a link to a folder outside it holding a file, and leave a file beside lgsm/tmp."""
    outside = os.path.join(_TMP256, "linked-outside")
    _shutil256.rmtree(outside, ignore_errors=True)
    os.makedirs(outside)
    open(os.path.join(outside, "precious"), "w").close()
    open(os.path.join(home, "lgsm", "keep"), "w").close()
    os.rmdir(os.path.join(home, "lgsm", "tmp"))
    os.symlink(outside, os.path.join(home, "lgsm", "tmp"))


def _step4_256_checks():
    ok, fails, downloads, wipes = _step4_256("sum2", [(_SUM_OUT256, 1, False)] * 3)
    check("install step 4: a download that fails LinuxGSM's checksum twice ends as a failed install with "
          "LinuxGSM's reason (file, its checksum, the expected one), retryable",
          ok is False and len(fails) == 1 and _WANT256 in fails[0][0] and _GOT256 in fails[0][0]
          and fails[0][2:] == (True, True), repr(fails))
    eq("install step 4: ...after one more download (and LinuxGSM's download folder is emptied once it fails)",
       (downloads, wipes), (2, 1))
    _step4_more256()


def _step4_more256():
    ok, fails, downloads, wipes = _step4_256("sum1", [("downloading file ... FAIL\n__x\n", 1, False, True),
                                                      ("Install Complete!\n", 0, True)])
    eq("install step 4: a download cut off part way (its partial archive left in lgsm/tmp) installs on the next "
       "download, which starts with lgsm/tmp emptied", (ok, fails, downloads, wipes), (True, [], 2, 0))
    ok, fails, downloads, _w = _step4_256("stale", [("Install Complete!\n", 0, True)],
                                          lambda h: open(os.path.join(h, "lgsm", "tmp", _ARCHIVE256), "w").close())
    eq("install step 4: a Retry over a partial archive an earlier install left installs at its first download",
       (ok, fails, downloads), (True, [], 1))
    ok, _f, _d, _w = _step4_256("linked", [("", 0, False)] * 3, _linked256)
    eq("install step 4: nothing outside lgsm/tmp is deleted, not through a linked lgsm/tmp either (the folder's "
       "files, and what a link points at, stay)",
       (ok, sorted(os.listdir(os.path.join(_TMP256, "linked-outside"))),
        os.path.exists(os.path.join(_TMP256, "linked", "lgsm", "keep"))), (False, ["precious"], True))
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


# ── 6. the Add-ons tab with no free database ────────────────────────────────────────────────────
def _db_host_route256():
    sid = _p9_new_server(P9_HOST, "cod2p256", "cod2", 28966, name="p256-cod2")
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("os=24.04\npodman=podman version 4.9.3\n", "", 0))
    _p9_patch(_ra256, "game_account_write_refusal", lambda remote, user, reading=False: None)
    saved = _rdb256._PROBES.pop(P9_HOST, None)
    got = []
    try:
        a = _p9_client(P9_ADMIN)
        got.append(a.get("/api/server/%d/addons" % sid).get_json().get("db_host"))
        _rdb256._PROBES[P9_HOST] = (_time256.monotonic(), {"state": "none"})
        got.append(a.get("/api/server/%d/addons" % sid).get_json().get("db_host"))
        with _p9.app_context():
            row = _GD256(remote_id=P9_HOST, game_server_id=sid, name="gs%d_b3" % sid, secret="")
            _db256.session.add(row)
            _db256.session.commit()
        got.append(a.get("/api/server/%d/addons" % sid).get_json().get("db_host"))
    finally:
        _rdb256._PROBES.pop(P9_HOST, None)
        if saved is not None:
            _rdb256._PROBES[P9_HOST] = saved
        with _p9.app_context():
            _GD256.query.filter_by(game_server_id=sid).delete()
            _db256.session.commit()
        _p9_delete_server(sid)
    eq("add-ons list: 'none' only when the Databases tab's last look found no database server on the host; not "
       "when it has not looked, nor once the server has a free database", got, ["", "none", ""])


_HARNESS256 = r"""'use strict';
const fs = require('fs'), vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
const clicks = [];
function El(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.className = '';
  this._text = ''; this.style = {}; this.disabled = false; this.id = ''; }
El.prototype.appendChild = function (c) { this.children.push(c); return c; };
Object.defineProperty(El.prototype, 'textContent', {
  get() { return this._text + this.children.map(function (c) { return c.textContent; }).join(''); },
  set(v) { this._text = String(v); this.children = []; }});
El.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); };
El.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
El.prototype.click = function () { clicks.push(this.getAttribute('data-sfsub-btn')); };
function walk(e, out) { out.push(e); (e.children || []).forEach(function (c) { if (c instanceof El) walk(c, out); }); return out; }
const fixed = {};
['ad-card', 'ad-list', 'ad-loading', 'ad-runtime', 'ad-msg'].forEach(function (id) { fixed[id] = new El('div'); fixed[id].id = id; });
const nav = new El('button'); nav.setAttribute('data-sfsub-btn', 'databases');
const document = {
  createElement: function (t) { return new El(t); },
  createTextNode: function (t) { return {textContent: String(t)}; },
  getElementById: function (id) { return fixed[id] || walk(fixed['ad-list'], []).filter(function (e) { return e.id === id; })[0] || null; },
  querySelector: function (sel) { return sel === '[data-sfsub-btn="databases"]' && cfg.tab ? nav : null; },
  addEventListener: function () {}};
const timers = [], gets = (cfg.gets || [cfg.data]).slice();
function answer(d) { return Promise.resolve({ok: true, json: function () { return Promise.resolve(d); }}); }
const ctx = {document: document, location: {hash: ''}, MOUNT: '', serverId: 7, JSON: JSON, Promise: Promise, Number: Number,
  setInterval: function (fn) { timers.push(fn); return timers.length; }, clearInterval: function () {}, Date: Date,
  confirmDialog: function (o) { o.onConfirm(); },
  fetch: function (url, opts) { return (opts && opts.method === 'POST') ? answer(cfg.post) : answer(gets.length > 1 ? gets.shift() : gets[0]); }};
ctx.window = ctx; ctx.addEventListener = function () {};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(cfg.src, 'utf8'), ctx);
const ticks = function () { return new Promise(function (r) { setTimeout(r, 20); }); };
const msg = function () { return {text: fixed['ad-msg'].textContent, cls: fixed['ad-msg'].className}; };
if (cfg.flow === 'install') {
  ctx.window.adLoad(true).then(function () { ctx.window.adInstall(cfg.install); return ticks(); }).then(function () {
    const started = msg();
    timers[0]();
    return ticks().then(function () {
      const errs = walk(fixed['ad-list'], []).filter(function (e) { return /text-danger/.test(e.className); });
      process.stdout.write(JSON.stringify({started: started, ended: msg(), polls: timers.length,
        row_error: errs.map(function (e) { return e.textContent; })}));
    });
  }).catch(function (e) { process.stdout.write(JSON.stringify({error: String(e && e.stack || e)})); });
} else ctx.window.adLoad(true).then(function () {
  const all = walk(fixed['ad-list'], []);
  const act = function (name) { return all.filter(function (e) { return e.getAttribute('data-action') === name; })[0]; };
  const inst = act('adInstall'), open = act('adOpenDatabases');
  const why = inst && all.filter(function (e) { return e.id === inst.getAttribute('aria-describedby'); })[0];
  const opened = open ? ctx.window.adOpenDatabases() : null;
  process.stdout.write(JSON.stringify({install: !!inst, disabled: !!(inst && inst.disabled), why: why ? why.textContent : null,
    open: !!open, opened: opened, clicks: clicks, select: all.some(function (e) { return e.tagName === 'SELECT'; })}));
}).catch(function (e) { process.stdout.write(JSON.stringify({error: String(e && e.stack || e)})); });
"""


def _tab_js256(db_host, tab, databases=()):
    """The add-ons tab's script, run whole in node over a B3 row -> what the row shows."""
    node = _shutil256.which("node")
    if not node:
        return {"error": "node is not installed"}
    path = os.path.join(_TMP256, "harness.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_HARNESS256)
    row = {"id": "b3", "name": "B3", "version": "1.12", "needs_database": True, "installed": False,
           "installing": False, "legacy": False, "geolocation_option": False}
    cfg = {"src": os.path.join(_root, "panel", "static", "js", "server_addons.js"), "tab": tab,
           "data": {"success": True, "addons": [row], "databases": list(databases), "db_host": db_host}}
    r = _sp256.run([node, path], input=_json256.dumps(cfg),  # nosec B603 - node on this part's harness
                   capture_output=True, text=True, timeout=120, check=False)
    try:
        return _json256.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _install_msg_js256():
    """The tab's script over an install that starts and then fails -> its message line before and after."""
    node = _shutil256.which("node")
    if not node:
        return {"error": "node is not installed"}
    path = os.path.join(_TMP256, "harness.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_HARNESS256)
    row = {"id": "iw4madmin", "name": "IW4MAdmin", "version": "2026.1", "needs_database": False, "installed": False,
           "legacy": False, "geolocation_option": False}
    busy, failed = dict(row, installing=True), dict(row, installing=False, error="Couldn't ready the account.")
    cfg = {"src": os.path.join(_root, "panel", "static", "js", "server_addons.js"), "tab": True, "flow": "install",
           "install": "iw4madmin", "post": {"success": True, "started": True, "message": "Installing the add-on."},
           "gets": [{"success": True, "addons": [row], "databases": []},
                    {"success": True, "addons": [busy], "databases": []},
                    {"success": True, "addons": [failed], "databases": []}]}
    r = _sp256.run([node, path], input=_json256.dumps(cfg),  # nosec B603 - node on this part's harness
                   capture_output=True, text=True, timeout=120, check=False)
    try:
        return _json256.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _tab256():
    none = _tab_js256("none", True)
    check("add-ons tab: with no free database, Install still shows, disabled, with the reason beside it (named by "
          "aria-describedby), and a host with no database server says so",
          none.get("install") and none.get("disabled") and "no database server yet" in (none.get("why") or ""),
          repr(none))
    eq("add-ons tab: ...an Open Databases button opens the Databases tab by its own section button",
       (none.get("open"), none.get("opened"), none.get("clicks")), (True, True, ["databases"]))
    plain = _tab_js256("", False)
    eq("add-ons tab: ...otherwise the reason asks for a database, and a viewer without the Databases tab gets no button",
       (plain.get("disabled"), (plain.get("why") or "").startswith("Add a database in the Databases tab first"),
        plain.get("open")), (True, True, False))
    free = _tab_js256("", True, [{"id": 1, "name": "gs7_b3", "used_by": ""}])
    eq("add-ons tab: ...with a free database Install is enabled, with the database select and no reason (control)",
       (free.get("install"), free.get("disabled"), free.get("why"), free.get("open"), free.get("select")),
       (True, False, None, False, True))
    flow = _install_msg_js256()
    check("add-ons tab: the green 'Installing the add-on' line is cleared once the install ends in a failure, which "
          "the row shows in red",
          "text-success" in (flow.get("started") or {}).get("cls", "") and (flow.get("ended") or {}).get("text") == ""
          and flow.get("row_error") == ["Couldn't ready the account."], repr(flow))


# ── 7. an add-on install on the panel's own host: enrolled, then readied ────────────────────────
def _install_verbs256(sid, answers, podman=True):
    """Install IW4MAdmin through the route with `answers` {verb: (out, err, rc)} -> (verbs run, audit, row error)."""
    probe = _probe255(extra="ports= 21004\n")
    calls = _host255(probe if podman else probe.replace("podman=podman version 4.9.3", "podman="))
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **_k: calls.append(("verb", verb, list(args)))
                 or answers.get(verb, ("", "", 0)))
    a = _p9_client(P9_ADMIN)
    a.post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    row = next((r for r in a.get("/api/server/%d/addons" % sid).get_json().get("addons") or []
                if r.get("id") == "iw4madmin"), {})
    with _ra256._JOBS_LOCK:
        _ra256._JOBS.pop((sid, "iw4madmin"), None)
    return [c[1] for c in calls if c[0] == "verb"], _p9_audit("addon_install").detail, row.get("error") or ""


def _enrol256():
    sid = _p9_new_server(P9_LOCAL, "cod4p256", "cod4", 28967, name="p256-cod4")
    try:
        verbs, _detail, _err = _install_verbs256(sid, {})
        pre = [v for v in verbs if v in ("gameuser-group", "addon-account-prepare")]
        eq("add-on install (panel host): the account is enrolled in the game group, then readied, in that order",
           pre, ["gameuser-group", "addon-account-prepare"])
        refusal = "refusing to enrol cod4p256 in lgsmpanel-games: it can reach root"
        verbs, detail, err = _install_verbs256(sid, {"gameuser-group": ("", refusal + "\n", 1)})
        check("add-on install (panel host): an enrolment the helper refuses stops before the account is readied, "
              "and its words follow the sentence in the audit row and on the row",
              "addon-account-prepare" not in verbs and refusal in detail and refusal in err, repr((verbs, detail, err)))
        linger = "Could not enable linger: Access denied"
        _v, detail, err = _install_verbs256(sid, {"addon-account-prepare": ("subids=present\n", "\x1b[31m%s\x1b[0m\n"
                                                                            % linger, 1)})
        check("add-on install: a prepare that fails shows the helper's own reason (colours stripped) after the "
              "sentence, in the audit row and on the row",
              "subordinate ids and lingering). The host said: " + linger in detail and linger in err, repr((detail, err)))
        _v, detail, err = _install_verbs256(sid, {"apt-install": ("", "E: Unable to locate package podman\n", 100)},
                                              podman=False)
        check("add-on install: apt's own reason follows 'Couldn't install Podman'",
              "Couldn't install Podman on this host. The host said: E: Unable to locate package podman" in detail
              and "Unable to locate package podman" in err, repr((detail, err)))
    finally:
        _p9_delete_server(sid)


# ── 8. lines added to a config file with no newline at its end ──────────────────────────────────
def _bans_cfg256():
    """Run ensure_persistent_bans' shell over a Source cfg that ends without a newline -> the file after."""
    home = os.path.join(_TMP256, "bans")
    cfgdir = os.path.join(home, "serverfiles", "csgo", "cfg")
    os.makedirs(cfgdir, exist_ok=True)
    path = os.path.join(cfgdir, "csgoserver.cfg")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('hostname "p256"')
    _p9_patch(_files256, "lgsm_get_values", lambda server, user, selfname, keys: {"servercfg": "${selfname}.cfg"})
    _p9_patch_sm("shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None, **_k: _sp256.run(
        ["bash", "-c", sh.replace("/home/" + user, home)], capture_output=True, text=True, timeout=30,  # nosec B603 B607
        check=False) and ("", "", 0))
    ok = _game256.ensure_persistent_bans(_NS256(), "csp256", "csgoserver")
    with open(path, encoding="utf-8") as fh:
        return ok, fh.read()


def _newlines256():
    eq("config appends: the instance cfg's startparameters line is added on a line of its own",
       _codm256._with_line('fn_parms="x"', "+set fs_game mods/x"), 'fn_parms="x"\nstartparameters=+set fs_game mods/x\n')
    eq("config appends: ...as is a key added to an ini that ends without a newline",
       _ws256.ini_set("[s]\na=1", {"b": "2"}), "[s]\na=1\nb=2\n")
    ok, text = _bans_cfg256()
    eq("config appends: ...and the persistent-bans exec lines (the shell, run under bash), leaving the last line whole",
       (ok, text.splitlines()), (True, ['hostname "p256"', "// panel: load persistent bans on every (re)start",
                                       "exec banned_user.cfg", "exec banned_ip.cfg"]))


try:
    _outcome256()
    _p9_arm(who="part256")
    _installed256()
    _p9_restore_all()
    _p9_arm(who="part256")
    _step4_256_checks()
    _p9_restore_all()
    _p9_arm(who="part256")
    _db_host_route256()
    _p9_restore_all()
    _p9_arm(who="part256")
    _enrol256()
    _p9_restore_all()
    _p9_arm(who="part256")
    _newlines256()
finally:
    _p9_restore_all()
_tab256()
_journal256()
_update256()
check("part256: no check reached a real host", len(_P9_TRIPPED) == _trips256, repr(_P9_TRIPPED[_trips256:][:4]))
_shutil256.rmtree(_TMP256, ignore_errors=True)
