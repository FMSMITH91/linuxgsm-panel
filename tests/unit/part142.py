"""Part 142 of the unit suite: an update installs only a release signed with the owner's own key.

Every commit on main is a GitHub squash merge signed by GitHub's key, which proves nothing against
someone holding the owner's GitHub account. install.sh now moves a checkout only to a commit that
also carries a signature made with the owner's SSH key (tools/sign-release.sh), and the update card
offers only such a commit. Held here:

* install.sh's update target: a signed tip or pin moves; an unsigned one HOLDS at HEAD (or fails
  when HEAD is not on the branch), never falling back to another commit; a signature for another
  branch or commit, a tampered one, one made with a key the TARGET commit names, no key, no
  signatures branch and a failed fetch all hold.
* the lost-key override works only on a run a person started by hand.
* as root, the key is root's own copy, taken from root's source floor when it is not placed yet,
  and root stages its own pieces only from a signed commit (root_source_commit).
* tools/sign-release.sh signs a first-parent commit of a local bare repository and refuses others.
* the panel: the walk offers a signed + passing commit and skips a newer unsigned one; an unsigned
  test-branch tip is not offered; the signatures branch is never a branch to switch to; the
  helper's and the wrapper's launches never carry the override.

HOW IT RUNS. Real install.sh functions cut out of the file and run under bash, against a real
upstream repository and clone in a throwaway directory, with a throwaway ed25519 key (never the
owner's); panel functions with their git reads stubbed or pointed at that clone.
"""
import os
import shutil as _shutil142
import subprocess as _sp142  # nosec B404 - git, bash and ssh-keygen over this part's own scratch files
import tempfile as _tf142
import shlex as _shlex142

from unit.part01 import check, skip
from unit.part05 import _helper as _helper142, _root
from unit.part06 import _inst, _inst_shfn
from unit.part03 import RELEASE_GATE_REAL03
from unit.part20 import _patch, _patched
from panel.ops import system_ops as _so142

_SB142 = _tf142.mkdtemp(prefix="p142-")
_ENV142 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
for _k142 in ("PANEL_ALLOW_UNSIGNED_UPDATE", "PANEL_SELF_UPDATE", "SUDO_UID", "PANEL_UPDATE_REF"):
    _ENV142.pop(_k142, None)
_NS142 = "linuxgsm-panel-release"


def _run142(argv, **kw):
    return _sp142.run(argv, capture_output=True, text=True, env=kw.pop("env", _ENV142), **kw)


def _git142(*a):
    return _run142(["git", *a]).stdout.strip()


def _key142(name):
    path = os.path.join(_SB142, name)
    _run142(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path])
    with open(path + ".pub", encoding="utf-8") as fh:
        return path, "release " + " ".join(fh.read().split()[:2]) + "\n"


def _sign142(key, branch, sha, ns=_NS142):
    """The armored signature `key` makes of the release message for `sha` on `branch`."""
    msg = os.path.join(_SB142, "msg")
    with open(msg, "w", encoding="utf-8") as fh:
        fh.write("linuxgsm-panel release\nbranch %s\ncommit %s\n" % (branch, sha))
    _run142(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", ns, msg])
    with open(msg + ".sig", encoding="utf-8") as fh:
        body = fh.read()
    os.unlink(msg + ".sig")
    return body


_HAVE142 = bool(_shutil142.which("ssh-keygen")) and bool(_shutil142.which("git"))
_UP142 = os.path.join(_SB142, "up")
_CO142 = os.path.join(_SB142, "co")


def _commit142(files, msg):
    for path, body in files.items():
        with open(os.path.join(_UP142, path), "w", encoding="utf-8") as fh:
            fh.write(body)
        _git142("-C", _UP142, "add", path)
    _git142("-C", _UP142, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", msg)
    return _git142("-C", _UP142, "rev-parse", "HEAD")


def _set_sigs142(sigs):
    """Make upstream's release-signatures branch hold exactly `sigs` ({path: text}); None deletes it."""
    _git142("-C", _UP142, "branch", "-q", "-D", "release-signatures")
    if sigs is None:
        return
    idx = os.path.join(_SB142, "sigidx")
    env = dict(_ENV142, GIT_INDEX_FILE=idx)
    if os.path.exists(idx):
        os.unlink(idx)
    _run142(["git", "-C", _UP142, "read-tree", "--empty"], env=env)
    for path, body in sigs.items():
        blob = _run142(["git", "-C", _UP142, "hash-object", "-w", "--stdin"], input=body).stdout.strip()
        _run142(["git", "-C", _UP142, "update-index", "--add", "--cacheinfo", "100644,%s,%s" % (blob, path)],
                env=env)
    tree = _run142(["git", "-C", _UP142, "write-tree"], env=env).stdout.strip()
    c = _run142(["git", "-C", _UP142, "-c", "commit.gpgsign=false", "commit-tree", "-m", "sigs", tree]).stdout.strip()
    _git142("-C", _UP142, "update-ref", "refs/heads/release-signatures", c)


_SH_NAMES142 = ("_gitc", "_ref_exists", "_fetch_branch", "_fetch_branch_history", "_on_first_parent_line",
                "_release_message", "_fetch_release_signatures", "_panel_started_run", "_unsigned_override",
                "_release_key_file", "_release_signed", "_update_target_signed", "_hold_unless_signed",
                "_source_floor", "_choose_update_target", "resolve_update_target")


def _target142(head, ref="", extra_env=None, root=None):
    """resolve_update_target on the clone reset to `head`: 'TARGET=<sha> WHY=<why> HOLD=<hold>' or
    'REFUSED <why>'. `root`, a dict, runs it as root (id -u answers 0) with HELPER_DIR, the floor
    file and root's clone named there."""
    _git142("-C", _CO142, "reset", "-q", "--hard", head)
    pre = ("set -uo pipefail\nwarn() { echo \"WARN $*\" >&2; }\nSRC=''\nPANEL_DIR=%s\nDEFAULT_BRANCH=main\n"
           "PANEL_USER=%s\n" % (_shlex142.quote(_CO142), _shlex142.quote(_run142(["id", "-un"]).stdout.strip())))
    rt = root or {}
    pre += "HELPER_DIR=%s\nROOT_SRC_FLOOR_FILE=%s\nROOT_GIT=%s\n" % (
        _shlex142.quote(rt.get("helper_dir", os.path.join(_SB142, "nohelper"))),
        _shlex142.quote(rt.get("floor", os.path.join(_SB142, "nofloor"))),
        _shlex142.quote(rt.get("root_git", os.path.join(_SB142, "norootgit"))))
    if root is not None:
        pre += ("id() { if [ \"$#\" -eq 1 ] && [ \"$1\" = -u ]; then echo 0; else command id \"$@\"; fi; }\n"
                "_rootgit() { git --git-dir=\"${ROOT_GIT}\" \"$@\"; }\n")
    body = "".join(_inst_shfn(n) for n in _SH_NAMES142)
    tail = ("UNSIGNED_OVERRIDE=\"${PANEL_ALLOW_UNSIGNED_UPDATE:-}\"\n"
            "RELEASE_SIG_NS=linuxgsm-panel-release\nRELEASE_SIG_BRANCH=release-signatures\n"
            "RELEASE_SIG_REF=refs/linuxgsm-panel/release-signatures\nRELEASE_SIGNERS=release-signers\n"
            "RELEASE_SIG_FETCHED=0\n"
            "if resolve_update_target; then echo \"TARGET=${TARGET_SHA} WHY=${UPD_WHY} HOLD=${UPD_HOLD} "
            "HOLDWHY=${UPD_HOLD_WHY}\"; else echo \"REFUSED ${RESOLVE_ERR}\"; fi\n")
    env = dict(_ENV142, PANEL_UPDATE_REF=ref, **(extra_env or {}))
    r = _run142(["bash", "-c", pre + body + tail], env=env)
    return (r.stdout.strip().splitlines() or [""])[-1] + ("" if r.stdout.strip() else " ERR " + r.stderr[-300:])


if not _HAVE142:
    skip("release signatures: install.sh's update gate, end to end", "git or ssh-keygen is not installed")
else:
    try:
        _K142, _KPUB142 = _key142("owner")
        _X142, _XPUB142 = _key142("attacker")
        _git142("init", "-q", "-b", "main", _UP142)
        _A142 = _commit142({"release-signers": _KPUB142, "app.py": "a\n"}, "A")
        _B142 = _commit142({"app.py": "b\n"}, "B")
        _C142 = _commit142({"app.py": "c\n"}, "C")
        _git142("clone", "-q", _UP142, _CO142)

        def _good142(*shas):
            return {"main/%s.sig" % s: _sign142(_K142, "main", s) for s in shas}

        # ── the target moves only to a signed commit ────────────────────────────────────────────
        _set_sigs142(_good142(_C142))
        _r = _target142(_A142)
        check("release signatures: a signed tip is the update's target (positive control)",
              _r.startswith("TARGET=%s WHY=tip" % _C142), _r)
        _set_sigs142(_good142(_B142))
        _r = _target142(_A142)
        check("release signatures: an UNSIGNED tip is not moved to: the update holds at HEAD, and does "
              "not fall back to the older signed commit",
              _r.startswith("TARGET=%s WHY=hold HOLD=unsigned" % _A142) and "not signed" in _r, _r)
        _r = _target142(_A142, ref=_B142)
        check("release signatures: a signed pin is moved to (positive control)",
              _r.startswith("TARGET=%s WHY=pin" % _B142), _r)
        _r = _target142(_A142, ref=_C142)
        check("release signatures: an unsigned pin holds at HEAD",
              _r.startswith("TARGET=%s WHY=hold HOLD=unsigned" % _A142), _r)
        _set_sigs142({"main/%s.sig" % _C142: _sign142(_K142, "dev", _C142)})
        _r = _target142(_A142)
        check("release signatures: a signature made for ANOTHER BRANCH does not pass for main",
              "HOLD=unsigned" in _r, _r)
        _set_sigs142({"main/%s.sig" % _C142: _sign142(_K142, "main", _B142)})
        _r = _target142(_A142)
        check("release signatures: a signature of ANOTHER COMMIT, filed under this one, does not pass",
              "HOLD=unsigned" in _r, _r)
        _sig = _sign142(_K142, "main", _C142).splitlines()
        _sig[2] = _sig[2][:10] + ("A" if _sig[2][10] != "A" else "B") + _sig[2][11:]
        _set_sigs142({"main/%s.sig" % _C142: "\n".join(_sig) + "\n"})
        _r = _target142(_A142)
        check("release signatures: a TAMPERED signature does not pass", "HOLD=unsigned" in _r, _r)
        _set_sigs142({"main/%s.sig" % _C142: _sign142(_K142, "main", _C142, ns="git")})
        _r = _target142(_A142)
        check("release signatures: a signature in another namespace (a git commit signature) does not "
              "pass", "HOLD=unsigned" in _r, _r)
        # The target names its OWN key and is signed with it: the host trusts HEAD's key, not that.
        _D142 = _commit142({"release-signers": _XPUB142, "app.py": "d\n"}, "D")
        _set_sigs142({"main/%s.sig" % _D142: _sign142(_X142, "main", _D142)})
        _r = _target142(_C142)
        check("release signatures: a commit that brings its own key, signed with that key, is NOT "
              "trusted: the key is the installed commit's",
              _r.startswith("TARGET=%s WHY=hold HOLD=unsigned" % _C142), _r)
        _set_sigs142(_good142(_D142))
        _r = _target142(_C142)
        check("release signatures: ...while the same commit signed with the installed key moves "
              "(rotation: a new key arrives inside a release the current one signed)",
              _r.startswith("TARGET=%s WHY=tip" % _D142), _r)
        _git142("-C", _UP142, "reset", "-q", "--hard", _C142)
        # ── fail closed on anything unreadable ───────────────────────────────────────────────────
        _set_sigs142(None)
        _git142("-C", _CO142, "update-ref", "-d", "refs/linuxgsm-panel/release-signatures")
        _r = _target142(_A142)
        check("release signatures: with no signatures branch upstream the update holds, and says the "
              "signatures could not be fetched",
              "HOLD=unsigned" in _r and "could not be fetched" in _r, _r)
        # A ref left by an earlier run, holding a valid signature, is not read once a fetch fails.
        _set_sigs142(_good142(_C142))
        _ok = _target142(_A142)
        _set_sigs142(None)
        _r = _target142(_A142)
        check("release signatures: a FAILED fetch holds, though a ref an earlier fetch left holds a "
              "valid signature",
              _ok.startswith("TARGET=%s WHY=tip" % _C142) and "HOLD=unsigned" in _r
              and _git142("-C", _CO142, "show-ref", "refs/linuxgsm-panel/release-signatures") != "", _ok + " | " + _r)
        _git142("-C", _UP142, "rm", "-q", "release-signers")
        _git142("-C", _UP142, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "drop key")
        _E142 = _git142("-C", _UP142, "rev-parse", "HEAD")
        _git142("-C", _CO142, "fetch", "-q", "origin", "+refs/heads/main:refs/remotes/origin/main")
        # HEAD (E) has no release-signers: a per-user host on it has no key.
        _F142 = _commit142({"release-signers": _KPUB142, "app.py": "f\n"}, "F")
        _set_sigs142(_good142(_F142))
        _r = _target142(_E142)
        check("release signatures: a per-user host whose installed commit has no release key holds, "
              "and the reason says how to recover",
              _r.startswith("TARGET=%s WHY=hold HOLD=unsigned" % _E142)
              and "PANEL_ALLOW_UNSIGNED_UPDATE=1" in _r, _r)
        # ── HEAD not on the branch: nothing to stay at, and no fallback ─────────────────────────
        _git142("-C", _CO142, "reset", "-q", "--hard", _A142)
        _git142("-C", _CO142, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "local")
        _L142 = _git142("-C", _CO142, "rev-parse", "HEAD")
        _set_sigs142({})
        _r = _target142(_L142)
        check("release signatures: an unsigned tip with HEAD off the branch is REFUSED, with no other "
              "commit chosen", _r.startswith("REFUSED") and "not a signed release" in _r, _r)
        # ── the override ─────────────────────────────────────────────────────────────────────────
        _r = _target142(_A142, extra_env={"PANEL_ALLOW_UNSIGNED_UPDATE": "1"})
        check("release signatures: PANEL_ALLOW_UNSIGNED_UPDATE=1 on a run by hand installs the unsigned "
              "tip (the lost-key recovery)", _r.startswith("TARGET=%s WHY=tip" % _F142), _r)
        _r = _target142(_A142, extra_env={"PANEL_ALLOW_UNSIGNED_UPDATE": "1", "PANEL_SELF_UPDATE": "1"})
        check("release signatures: ...but not on a run the panel's helper started (PANEL_SELF_UPDATE)",
              "HOLD=unsigned" in _r, _r)
        _r = _target142(_A142, extra_env={"PANEL_ALLOW_UNSIGNED_UPDATE": "1",
                                          "SUDO_UID": str(os.getuid())})
        check("release signatures: ...nor under sudo from the panel's own account (SUDO_UID)",
              "HOLD=unsigned" in _r, _r)
        _r = _target142(_A142, extra_env={"PANEL_ALLOW_UNSIGNED_UPDATE": "yes"})
        check("release signatures: ...and only the exact value 1 counts", "HOLD=unsigned" in _r, _r)
        # ── as root: root's own key copy, the floor bootstrap, fail closed ──────────────────────
        _hd = os.path.join(_SB142, "helper")
        os.makedirs(_hd)
        _rg = os.path.join(_SB142, "root.git")
        _git142("clone", "-q", "--bare", _UP142, _rg)
        _floor = os.path.join(_hd, ".source-floor")
        _set_sigs142(_good142(_F142))
        _rt142 = {"helper_dir": _hd, "floor": _floor, "root_git": _rg}
        with open(os.path.join(_hd, "release-signers"), "w", encoding="utf-8") as _fh:
            _fh.write(_KPUB142)
        _r = _target142(_A142, root=_rt142)
        check("release signatures (root): root's own key copy verifies a signed tip (positive control)",
              _r.startswith("TARGET=%s WHY=tip" % _F142), _r)
        with open(os.path.join(_hd, "release-signers"), "w", encoding="utf-8") as _fh:
            _fh.write(_XPUB142)
        _r = _target142(_A142, root=_rt142)
        check("release signatures (root): it is ROOT's copy that is trusted, not the checkout's HEAD",
              "HOLD=unsigned" in _r, _r)
        os.unlink(os.path.join(_hd, "release-signers"))
        _r = _target142(_A142, root=_rt142)
        check("release signatures (root): no key placed and no source floor: holds, saying how to "
              "recover", "HOLD=unsigned" in _r and "no release key" in _r
              and "PANEL_ALLOW_UNSIGNED_UPDATE=1" in _r, _r)
        with open(_floor, "w", encoding="utf-8") as _fh:
            _fh.write(_A142 + "\n")
        _r = _target142(_A142, root=_rt142)
        check("release signatures (root): no key placed yet (the first update after an older installer "
              "took this version): the key at root's source floor is used",
              _r.startswith("TARGET=%s WHY=tip" % _F142), _r)
        with open(_floor, "w", encoding="utf-8") as _fh:
            _fh.write(_E142 + "\n")
        _r = _target142(_A142, root=_rt142)
        check("release signatures (root): ...and a floor commit with no key is a hold", "HOLD=unsigned" in _r, _r)
    finally:
        _shutil142.rmtree(_SB142, ignore_errors=True)
        _SB142 = _tf142.mkdtemp(prefix="p142-")

# ── root_source_commit: root stages its own pieces only from a signed commit ───────────────────
_rsc142 = _inst_shfn("root_source_commit")
check("root_source_commit: fetches the signatures into root's own clone, by full name, and refuses a "
      "commit not signed with root's key (unless overridden by hand)",
      '"+refs/heads/${RELEASE_SIG_BRANCH}:refs/root-src/signatures"' in _rsc142
      and '_release_signed _rootgit refs/root-src/signatures "${want}" "${branch}"' in _rsc142
      and _rsc142.index("_release_signed _rootgit") < _rsc142.index('ROOT_SRC_COMMIT="${want}"'),
      _rsc142[-400:])
_irt142 = _inst_shfn("install_root_tools")
check("install_root_tools: places the release key root-owned beside the helper, from root's own source",
      'stage_root_source "${RELEASE_SIGNERS}" "${RELEASE_SIGNERS}"' in _irt142
      and 'install -o root -g root -m 0644 "${_stage}" "${HELPER_DIR}/${RELEASE_SIGNERS}"' in _irt142,
      _irt142[:200])
check("install.sh: ssh-keygen is a prerequisite (openssh-client), and release-signers is runtime",
      "cron ufw openssh-client" in _inst and "command -v ssh-keygen" in _inst
      and "\nruntime release-signers\n" in open(os.path.join(_root, ".github", "update-paths.txt")).read(),
      "")

# ── tools/sign-release.sh, against a local bare repository ──────────────────────────────────────
if _HAVE142:
    try:
        _K142, _KPUB142 = _key142("owner2")
        _bare = os.path.join(_SB142, "up.git")
        _dev = os.path.join(_SB142, "dev")
        _git142("init", "-q", "--bare", "-b", "main", _bare)
        _git142("clone", "-q", _bare, _dev)
        with open(os.path.join(_dev, "release-signers"), "w", encoding="utf-8") as _fh:
            _fh.write(_KPUB142)
        _git142("-C", _dev, "add", ".")
        _git142("-C", _dev, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "A")
        _git142("-C", _dev, "push", "-q", "origin", "main")
        _git142("-C", _dev, "config", "gpg.format", "ssh")
        _git142("-C", _dev, "config", "user.signingkey", _K142 + ".pub")
        _sa = _git142("-C", _dev, "rev-parse", "HEAD")
        _git142("-C", _dev, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "local")
        _sl = _git142("-C", _dev, "rev-parse", "HEAD")
        _tool = os.path.join(_root, "tools", "sign-release.sh")
        _senv = dict(_ENV142, SIGN_RELEASE_KEY=_K142, SIGN_RELEASE_NO_DEPLOY="1")
        _r1 = _run142(["bash", _tool, _sa], cwd=_dev, env=_senv)
        _blob = _git142("--git-dir", _bare, "cat-file", "blob", "release-signatures:main/%s.sig" % _sa)
        _vf = os.path.join(_SB142, "vmsg")
        with open(_vf, "w", encoding="utf-8") as _fh:
            _fh.write("linuxgsm-panel release\nbranch main\ncommit %s\n" % _sa)
        with open(_vf + ".sig", "w", encoding="utf-8") as _fh:
            _fh.write(_blob + "\n")
        with open(_vf + ".signers", "w", encoding="utf-8") as _fh:
            _fh.write(_KPUB142)
        with open(_vf, encoding="utf-8") as _fh:
            _ver = _run142(["ssh-keygen", "-Y", "verify", "-f", _vf + ".signers", "-I", "release", "-n", _NS142,
                            "-s", _vf + ".sig"], stdin=_fh)
        _cobj = _git142("--git-dir", _bare, "cat-file", "-p", "release-signatures")
        check("sign-release.sh: signs a first-parent commit, files <branch>/<sha>.sig on release-signatures "
              "(a SIGNED commit), and the signature verifies as a host checks it",
              _r1.returncode == 0 and _ver.returncode == 0 and "BEGIN SSH SIGNATURE" in _cobj
              and _git142("-C", _dev, "rev-parse", "HEAD") == _sl
              and _git142("-C", _dev, "status", "--porcelain") == "",
              "rc=%s %s %s" % (_r1.returncode, _r1.stderr[-200:], _ver.stderr[-200:]))
        _r2 = _run142(["bash", _tool, _sl], cwd=_dev, env=_senv)
        _r3 = _run142(["bash", _tool, _sa[:12]], cwd=_dev, env=_senv)
        _r4 = _run142(["bash", _tool, _sa, "release-signatures"], cwd=_dev, env=_senv)
        check("sign-release.sh: refuses a commit not on origin/main's first-parent line, a short id, and "
              "the signatures branch as a branch",
              _r2.returncode != 0 and "first-parent" in _r2.stderr and _r3.returncode != 0
              and _r4.returncode != 0,
              "%s | %s | %s" % (_r2.stderr[-150:], _r3.stderr[-150:], _r4.stderr[-150:]))
    finally:
        _shutil142.rmtree(_SB142, ignore_errors=True)

# ── the panel's offer ───────────────────────────────────────────────────────────────────────────
_C3, _C2, _C1 = "c" * 40, "b" * 40, "a" * 40


def _status142(walk, signed, branch=None):
    """_compute_update_status with the walk `walk` (newest first), every commit passing CI, and
    exactly the commits in `signed` signed. Returns (status, commits CI was asked about)."""
    asked = []

    def _git(args, timeout=45):
        if args[:2] == ["rev-list", "--first-parent"] and "--count" in args:
            return (str(len(walk)), "", 0)
        if args[:2] == ["rev-list", "--first-parent"]:
            return ("\n".join(walk), "", 0)
        if args[:2] == ["rev-parse", "--short"]:
            return ("abc1234", "", 0)
        if args[:1] == ["rev-parse"]:
            return (walk[0], "", 0)
        return ("", "", 0)
    with _patched():
        _patch(_so142, "_git", _git)
        _patch(_so142, "_is_git_checkout", lambda: True)
        _patch(_so142, "panel_version", lambda: "2026.11.1")
        _patch(_so142, "_tracked_branch", lambda: branch or _so142._DEFAULT_BRANCH)
        _patch(_so142, "_remote_ci_state", lambda sha: asked.append(sha) or "passing")
        _patch(_so142, "github_repo_url", lambda: "")
        _patch(_so142, "_update_touches_runtime", lambda ref: True)
        _patch(_so142, "version_for_commit", lambda ref: "2026.11.2")
        _patch(_so142, "_runtime_changelog", lambda rng, runtime_only=True: ["abc1234 x"])
        _patch(_so142, "_ci_note_walk", lambda *a: None)
        _patch(_so142, "_release_gate_for", lambda br: (lambda sha: sha in signed))
        return _so142._compute_update_status(), asked


_st, _asked = _status142([_C3, _C2, _C1], {_C2})
check("update card: offers the newest SIGNED + passing commit, skipping a newer unsigned one (and "
      "never asks GitHub about the unsigned one)",
      _st.get("update_available") is True and _st.get("target_sha") == _C2 and _C3 not in _asked,
      repr((_st.get("target_sha"), _asked)))
_st, _ = _status142([_C3, _C2, _C1], set())
check("update card: nothing signed, nothing offered (the card's plain up-to-date line, no message)",
      _st.get("update_available") is False and "message" not in _st, repr(_st))
_st, _ = _status142([_C3], {_C3})
check("update card: a signed + passing tip is offered (positive control)",
      _st.get("update_available") is True and _st.get("target_sha") == _C3, repr(_st.get("target_sha")))
_st, _ = _status142([_C3], set(), branch="dev")
_st2, _ = _status142([_C3], {_C3}, branch="dev")
check("update card: on a tracked test branch an unsigned tip is not offered, a signed one is",
      _st.get("update_available") is False and _st2.get("update_available") is True, repr((_st, _st2)))


def _gate142(sig_rc, key, sig_text, valid):
    """_release_gate_for('main')(C3) with the fetch answering sig_rc, the key `key`, the signature
    blob `sig_text` and the verifier answering `valid`. Returns (answer, what the verifier saw)."""
    seen = []

    def _git(args, timeout=45):
        if args[:1] == ["fetch"]:
            return ("", "", sig_rc)
        if args[:2] == ["cat-file", "blob"] and args[2].endswith(".sig"):
            return (sig_text, "", 0 if sig_text else 128)
        return ("", "", 1)
    with _patched():
        _patch(_so142, "_git", _git)
        _patch(_so142, "_release_key_text", lambda: key)
        _patch(_so142, "_release_signature_valid", lambda k, s, b, g: seen.append((k, s, b, g)) or valid)
        return RELEASE_GATE_REAL03("main")(_C3), seen


_g_ok = _gate142(0, "release ssh-ed25519 AAAA", "SIG", True)
check("update card: _release_gate_for verifies <branch>/<sha>.sig with the installed key (positive control)",
      _g_ok[0] is True and _g_ok[1] == [("release ssh-ed25519 AAAA", _C3, "main", "SIG")], repr(_g_ok))
check("update card: a failed signatures fetch, no key, or no signature is NOT signed",
      _gate142(1, "k", "SIG", True)[0] is False and _gate142(0, "", "SIG", True)[0] is False
      and _gate142(0, "k", "", True)[0] is False and _gate142(0, "k", "SIG", False)[0] is False, "")
if _HAVE142:
    _kd = _tf142.mkdtemp(prefix="p142k-")
    try:
        _kp = os.path.join(_kd, "k")
        _sp142.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", _kp], capture_output=True, check=False)
        with open(_kp + ".pub", encoding="utf-8") as _fh:
            _kt = "release " + " ".join(_fh.read().split()[:2])
        _sig = _sign142(_kp, "main", _C3) if os.path.isdir(_SB142) else ""
        check("update card: the real verifier passes the right signature and refuses it for another "
              "commit or branch",
              _so142._release_signature_valid(_kt, _C3, "main", _sig.strip())
              and not _so142._release_signature_valid(_kt, _C2, "main", _sig.strip())
              and not _so142._release_signature_valid(_kt, _C3, "dev", _sig.strip()), _sig[:40])
    finally:
        _shutil142.rmtree(_kd, ignore_errors=True)

_branches142 = []


def _git_br142(args, timeout=45):
    if args[:1] == ["for-each-ref"]:
        return ("refs/remotes/origin/main\nrefs/remotes/origin/release-signatures\nrefs/remotes/origin/dev",
                "", 0)
    return ("", "", 0)


with _patched():
    _patch(_so142, "_git", _git_br142)
    _patch(_so142, "_update_in_progress", lambda: True)
    _patch(_so142, "_tracked_branch", lambda: "main")
    _patch(_so142, "_is_git_checkout", lambda: True)
    _branches142 = _so142.list_panel_branches()
check("branch switcher: release-signatures is never offered as a code branch, nor accepted to switch to",
      "release-signatures" not in _branches142[0] and "dev" in _branches142[0]
      and _so142.panel_switch_branch("release-signatures") == (False, "Invalid branch name."),
      repr(_branches142))

# ── the panel's own launches never carry the override ──────────────────────────────────────────
os.environ["PANEL_ALLOW_UNSIGNED_UPDATE"] = "1"
try:
    _env142 = _helper142._self_update_env("-", "-")
finally:
    del os.environ["PANEL_ALLOW_UNSIGNED_UPDATE"]
check("helper: panel-self-update's environment drops PANEL_ALLOW_UNSIGNED_UPDATE and marks the run "
      "the panel's (PANEL_SELF_UPDATE)",
      "PANEL_ALLOW_UNSIGNED_UPDATE" not in _env142 and _env142.get("PANEL_SELF_UPDATE") == "1", repr(_env142))
_scripts142 = []
with _patched():
    _patch(_so142, "_r12a_start_installer",
           lambda path, script, ref, br, msg: _scripts142.append(script) or (False, "stub"))
    _patch(_so142, "_update_in_progress", lambda: False)
    _patch(_so142, "PANEL_DIR", _tf142.mkdtemp(prefix="p142w-"))
    with open(os.path.join(_so142.PANEL_DIR, "install.sh"), "w", encoding="utf-8") as _fh:
        _fh.write("#!/bin/bash\n")
    _so142._launch_installer(target_ref=_C3, branch="main")
    _shutil142.rmtree(_so142.PANEL_DIR, ignore_errors=True)
check("system_ops: the wrapper script the panel runs the installer with unsets the override before "
      "the installer starts",
      bool(_scripts142) and "unset PANEL_ALLOW_UNSIGNED_UPDATE\n" in _scripts142[0]
      and _scripts142[0].index("unset PANEL_ALLOW_UNSIGNED_UPDATE") < _scripts142[0].index("bash "),
      repr(_scripts142[:1])[:300])
_shutil142.rmtree(_SB142, ignore_errors=True)
