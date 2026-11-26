"""Part 293 of the unit suite: the signed add-on catalog's signer, the update rule, the scan and Renovate.

1. tools/sign-catalog.sh over a throwaway repository and key: the first catalog is seq 1, expires 30 days after it
   was issued, and is signed in the add-on namespace only; an unchanged catalog is not signed again, unless
   --refresh-catalog is given or it is near its expiry; a changed one is the next seq.
2. Its refusals: a commit off main's first-parent line, a commit older than the published catalog's source, checks
   that failed, still run or never ran, a key release-signers does not hold, a published catalog whose signature
   does not verify, and a wrong typed confirmation. Each leaves release-signatures where it was.
3. sign-release: a commit that changes only the catalog (and docs) is signed tooling-only (.inherit) with no release
   page, and publishes the catalog; one that also changes panel code is a release.
4. update-paths.txt: the catalog's source is noise, the build files beside it are not.
5. .github/scripts/addon_images.py scans what the catalog names; Renovate's add-on managers read the catalog.

HOW IT RUNS. git, bash and ssh-keygen over this part's scratch directory: a bare repository as the remote, keys
made here, and a stand-in GitHub CLI (a bash script, run as `bash <file>`) that answers check runs from a file.
"""
import calendar as _cal293
import importlib.util as _ilu293
import json as _json293
import os
import re as _re293
import shutil as _sh293
import subprocess as _sp293  # nosec B404 - git, bash and ssh-keygen over this part's own scratch files
import sys as _sys293
import tempfile as _tf293
import time as _time293

from unit.part01 import _root, check, eq, skip
from panel.ops import system_ops as _so293

_TMP293 = _tf293.mkdtemp(prefix="p293-")
_ENV293 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
_NS293 = "linuxgsm-panel-addons"
_CATALOG293 = os.path.join(_root, "panel", "addon_images", "catalog.json")
_REQ293 = ("checks (ubuntu)", "coverage", "js coverage", "gamedig lockfile (node 22)", "Analyze (python)",
           "Open code-scanning alerts", "Secret scanning (Gitleaks)", "Dependency vulnerabilities (pip-audit)")
_FAKEGH293 = r'''#!/bin/bash
printf '%s\n' "$*" >> "${FAKEGH293_LOG}"
case "$1 $2" in
    "api --paginate") cat "${FAKEGH293_CHECKS}" ;;
    "release view") exit 1 ;;
    *) exit 0 ;;
esac
'''


_AC_PATH293 = os.path.join(_root, "tools", "addon_catalog.py")
_ac_spec293 = _ilu293.spec_from_file_location("addon_catalog_p293", _AC_PATH293)
_AC293 = _ilu293.module_from_spec(_ac_spec293)
_ac_spec293.loader.exec_module(_AC293)
_AI_PATH293 = os.path.join(_root, ".github", "scripts", "addon_images.py")
_ai_spec293 = _ilu293.spec_from_file_location("addon_images_p293", _AI_PATH293)
_AI293 = _ilu293.module_from_spec(_ai_spec293)
_ai_spec293.loader.exec_module(_AI293)


def _run293(argv, **kw):
    # nosec B603 - fixed argv (git, bash, ssh-keygen) over this part's own scratch files
    return _sp293.run(argv, capture_output=True, text=True, env=kw.pop("env", _ENV293), **kw)  # nosec B603


def _git293(*a, **kw):
    return _run293(["git", *a], **kw).stdout.strip()


def _write293(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read293(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _key293(sb, name):
    key = os.path.join(sb, name)
    _run293(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key])
    return key, "release " + " ".join(_read293(key + ".pub").split()[:2]) + "\n"


def _checks293(sb, rows):
    path = os.path.join(sb, "checks.tsv")
    _write293(path, "".join("%s\t%s\t%s\n" % r for r in rows))
    return path


_GREEN293 = [(n, "completed", "success") for n in _REQ293]


def _rig293():
    """(scratch dir, key, bare remote, clone, stand-in gh) with main holding release-signers and the catalog."""
    sb = _tf293.mkdtemp(prefix="rig-", dir=_TMP293)
    key, pub = _key293(sb, "relkey")
    bare, dev = os.path.join(sb, "rel.git"), os.path.join(sb, "dev")
    _git293("init", "-q", "--bare", "-b", "main", bare)
    _git293("clone", "-q", bare, dev)
    _git293("-C", dev, "config", "gpg.format", "ssh")
    _git293("-C", dev, "config", "user.signingkey", key + ".pub")
    _write293(os.path.join(dev, "panel", "install", "release-signers"), pub)
    _write293(os.path.join(dev, "docs", "CHANGELOG.md"), "# Changelog\n")
    _write293(os.path.join(dev, ".github", "update-paths.txt"), _read293(os.path.join(_root, ".github", "update-paths.txt")))
    _write293(os.path.join(dev, "panel", "addon_images", "catalog.json"), _read293(_CATALOG293))
    gh = os.path.join(sb, "fakegh.sh")
    _write293(gh, _FAKEGH293)
    _checks293(sb, _GREEN293)
    return {"sb": sb, "key": key, "bare": bare, "dev": dev, "gh": gh, "n": 0}


def _commit293(rig, files, branch="main"):
    """Commit `files` ({path: text}) to the clone's `branch` and push it; the commit id."""
    rig["n"] += 1
    for rel, text in files.items():
        _write293(os.path.join(rig["dev"], rel), text)
    _git293("-C", rig["dev"], "add", "-A")
    day = "2026-03-04T12:00:%02d+00:00" % rig["n"]
    _git293("-C", rig["dev"], "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c%d" % rig["n"],
            env=dict(_ENV293, GIT_COMMITTER_DATE=day, GIT_AUTHOR_DATE=day))
    _git293("-C", rig["dev"], "push", "-q", "origin", "HEAD:refs/heads/" + branch)
    return _git293("-C", rig["dev"], "rev-parse", "HEAD")


def _env293(rig, **extra):
    env = dict(_ENV293, SIGN_RELEASE_KEY=rig["key"], SIGN_RELEASE_GH="bash " + rig["gh"],
               FAKEGH293_LOG=os.path.join(rig["sb"], "gh.log"), FAKEGH293_CHECKS=os.path.join(rig["sb"], "checks.tsv"),
               PYTHON=_sys293.executable)
    env.update(extra)   # a case may name its own key
    return env


def _sign293(rig, sha, *flags, typed=None, **extra):
    args = ["bash", os.path.join(_root, "tools", "sign-catalog.sh")] + (["--yes"] if typed is None else [])
    return _run293(args + list(flags) + [sha], cwd=rig["dev"], env=_env293(rig, **extra),
                   input="" if typed is None else typed + "\n")


def _tip293(rig):
    return _git293("--git-dir", rig["bare"], "rev-parse", "-q", "--verify", "refs/heads/release-signatures")


def _blob293(rig, path):
    r = _run293(["git", "--git-dir", rig["bare"], "cat-file", "blob", "release-signatures:" + path])
    return r.stdout if r.returncode == 0 else None


def _verifies293(rig, body, sig, ns):
    d = _tf293.mkdtemp(prefix="v-", dir=rig["sb"])
    _write293(os.path.join(d, "f"), body)
    _write293(os.path.join(d, "f.sig"), sig)
    _write293(os.path.join(d, "signers"), _read293(os.path.join(rig["dev"], "panel", "install", "release-signers")))
    with open(os.path.join(d, "f"), encoding="utf-8") as fh:
        return _run293(["ssh-keygen", "-Y", "verify", "-f", os.path.join(d, "signers"), "-I", "release", "-n", ns,
                        "-s", os.path.join(d, "f.sig")], stdin=fh).returncode == 0


def _t293(text):
    return _cal293.timegm(_time293.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))


def _src293(obj):
    return _json293.dumps(obj, indent=2, sort_keys=True) + "\n"


# ── 1. publishing ───────────────────────────────────────────────────────────────────────────────
def _s293_publish(rig):
    a = _commit293(rig, {"panel/a.py": "A = 1\n"})
    before = _time293.time()
    r1 = _sign293(rig, a)
    latest = _blob293(rig, "catalog/latest.json") or "{}"
    pub = _json293.loads(latest)
    sig = _blob293(rig, "catalog/latest.json.sig") or ""
    src = _json293.loads(_read293(_CATALOG293))
    eq("sign-catalog: the first catalog is seq 1, the commit's catalog plus seq, issued and expires, serialized as "
       "json.dumps(indent=2, sort_keys=True), published as catalog/1.json and catalog/latest.json with their .sig "
       "and the commit it came from",
       (r1.returncode, pub.get("seq"), {k: v for k, v in pub.items() if k not in ("seq", "issued", "expires")},
        latest == _src293(pub), _blob293(rig, "catalog/1.json") == latest, _blob293(rig, "catalog/1.json.sig") == sig,
        _blob293(rig, "catalog/latest.source")),
       (0, 1, src, True, True, True, "main %s\n" % a))
    issued, expires = _t293(pub.get("issued", "1970-01-01T00:00:00Z")), _t293(pub.get("expires", "1970-01-01T00:00:00Z"))
    eq("sign-catalog: ...issued now (UTC) and expiring 30 days later, the freeze protection panels check",
       (before - 5 <= issued <= _time293.time() + 5, expires - issued), (True, 30 * 86400))
    commit_obj = _git293("--git-dir", rig["bare"], "cat-file", "-p", "refs/heads/release-signatures")
    eq("sign-catalog: ...signed in the add-on namespace only (a catalog signature never passes as a release "
       "signature), and the release-signatures commit is itself signed",
       (_verifies293(rig, latest, sig, _NS293), _verifies293(rig, latest, sig, "linuxgsm-panel-release"),
        "gpgsig " in commit_obj),
       (True, False, True))
    tip = _tip293(rig)
    r2 = _sign293(rig, a)
    eq("sign-catalog: an unchanged catalog that is far from expiring is not signed again (success, nothing pushed)",
       (r2.returncode, _tip293(rig) == tip, "nothing to publish" in r2.stdout), (0, True, True))
    r3 = _sign293(rig, a, "--refresh-catalog")
    pub3 = _json293.loads(_blob293(rig, "catalog/latest.json") or "{}")
    eq("sign-catalog: --refresh-catalog signs the same catalog again as the next seq, so it never expires on panels",
       (r3.returncode, pub3.get("seq"), pub3.get("addons") == src["addons"], _blob293(rig, "catalog/2.json") is not None,
        _blob293(rig, "catalog/1.json") == latest),
       (0, 2, True, True, True))
    new = dict(src, addons=dict(src["addons"], bluemap={"image": "ghcr.io/bluemap-minecraft/bluemap@sha256:" + "a" * 64}))
    b = _commit293(rig, {"panel/addon_images/catalog.json": _src293(new)})
    r4 = _sign293(rig, b)
    pub4 = _json293.loads(_blob293(rig, "catalog/latest.json") or "{}")
    eq("sign-catalog: a changed catalog is published as the next seq, and the review names the field that changed",
       (r4.returncode, pub4.get("seq"), pub4.get("addons", {}).get("bluemap"),
        "bluemap.image: ghcr.io/bluemap-minecraft/bluemap@sha256:36e0" in r4.stdout),
       (0, 3, new["addons"]["bluemap"], True))
    return a, b


# ── 2. refusals ─────────────────────────────────────────────────────────────────────────────────
def _refused293(rig, name, run, want):
    tip = _tip293(rig)
    r = run()
    check("sign-catalog refuses %s, and release-signatures does not move" % name,
          r.returncode != 0 and want in r.stderr and _tip293(rig) == tip, repr((r.returncode, r.stdout[-300:], r.stderr[-400:])))


def _s293_refusals(rig, a, b):
    _refused293(rig, "an older commit's catalog over a newer one's (rollback)",
                lambda: _sign293(rig, a, "--refresh-catalog"), "roll panels back")
    side = _commit293(rig, {"panel/side.py": "S = 1\n"}, branch="side")
    _git293("-C", rig["dev"], "reset", "-q", "--hard", b)
    _refused293(rig, "a commit off main's first-parent line", lambda: _sign293(rig, side, "--refresh-catalog"),
                "first-parent line")
    for label, rows, want in (
            ("a commit with a failed check", _GREEN293 + [("Deep SAST (Semgrep)", "completed", "failure")], "a check failed"),
            ("a commit whose checks are still running", _GREEN293 + [("lighthouse", "in_progress", "")], "still running"),
            ("a commit missing a check it must pass", _GREEN293[1:], "have not run: checks ("),
            ("a commit whose required check was skipped",
             [("checks (ubuntu)", "completed", "skipped")] + _GREEN293[1:], "have not run: checks (")):
        _checks293(rig["sb"], rows)
        _refused293(rig, label, lambda: _sign293(rig, b, "--refresh-catalog"), want)
    _checks293(rig["sb"], _GREEN293 + [("deploy", "completed", "failure")])
    tip = _tip293(rig)
    r = _sign293(rig, b, "--refresh-catalog")
    check("sign-catalog: ...but a failed run of a check it ignores (deploy) does not hold it back (control)",
          r.returncode == 0 and _tip293(rig) != tip, repr((r.returncode, r.stderr[-300:])))
    _checks293(rig["sb"], _GREEN293)
    _refused293(rig, "a wrong typed confirmation", lambda: _sign293(rig, b, "--refresh-catalog", typed="0" * 12),
                "does not match")
    tip = _tip293(rig)
    r = _sign293(rig, b, "--refresh-catalog", typed=b[:12])
    check("sign-catalog: ...and signs once the first 12 characters of the commit id are typed (control)",
          r.returncode == 0 and _tip293(rig) != tip, repr((r.returncode, r.stderr[-300:])))
    other, _ = _key293(rig["sb"], "otherkey")
    _refused293(rig, "a key release-signers does not hold",
                lambda: _sign293(rig, b, "--refresh-catalog", SIGN_RELEASE_KEY=other), "does not verify against")


def _put293(rig, files):
    """Commit `files` ({path: text}) on release-signatures in the bare remote, as anyone who can push; the old tip."""
    bare, old = rig["bare"], _tip293(rig)
    env = dict(_ENV293, GIT_INDEX_FILE=os.path.join(rig["sb"], "put.index"))
    _run293(["git", "--git-dir", bare, "read-tree", old], env=env)
    for path, body in files.items():
        blob = _run293(["git", "--git-dir", bare, "hash-object", "-w", "--stdin"], input=body).stdout.strip()
        _run293(["git", "--git-dir", bare, "update-index", "--add", "--cacheinfo", "100644,%s,%s" % (blob, path)], env=env)
    tree = _run293(["git", "--git-dir", bare, "write-tree"], env=env).stdout.strip()
    new = _git293("--git-dir", bare, "commit-tree", "-p", old, "-m", "edit", tree)
    _git293("--git-dir", bare, "update-ref", "refs/heads/release-signatures", new, old)
    return old


def _s293_tampered(rig, b):
    """A published catalog whose bytes no longer match its signature is not trusted for its seq."""
    pub = _json293.loads(_blob293(rig, "catalog/latest.json") or "{}")
    old = _put293(rig, {"catalog/latest.json": _src293(dict(pub, seq=pub.get("seq", 0) + 1000))})
    _refused293(rig, "a published catalog that does not verify (it would trust a forged seq)",
                lambda: _sign293(rig, b, "--refresh-catalog"), "does not verify against release-signers")
    _git293("--git-dir", rig["bare"], "update-ref", "refs/heads/release-signatures", old)


def _s293_near_expiry(rig, b):
    """The published catalog 5 days from expiring: a plain run (sign-release's) signs it again."""
    pub = _json293.loads(_blob293(rig, "catalog/latest.json") or "{}")
    now = int(_time293.time())
    soon = dict(pub, issued=_time293.strftime("%Y-%m-%dT%H:%M:%SZ", _time293.gmtime(now - 25 * 86400)),
                expires=_time293.strftime("%Y-%m-%dT%H:%M:%SZ", _time293.gmtime(now + 5 * 86400)))
    path = os.path.join(rig["sb"], "soon.json")
    _write293(path, _src293(soon))
    _run293(["ssh-keygen", "-q", "-Y", "sign", "-f", rig["key"], "-n", _NS293, path])
    _put293(rig, {"catalog/latest.json": _src293(soon), "catalog/latest.json.sig": _read293(path + ".sig")})
    r = _sign293(rig, b)
    pub2 = _json293.loads(_blob293(rig, "catalog/latest.json") or "{}")
    eq("sign-catalog: a published catalog within 10 days of expiring is signed again by a plain run, as the next seq",
       (r.returncode, pub2.get("seq"), _t293(pub2.get("expires", "1970-01-01T00:00:00Z")) - now > 25 * 86400),
       (0, soon.get("seq", 0) + 1, True))


# ── 3. sign-release: catalog-only commits are tooling-only ──────────────────────────────────────
def _s293_sign_release():
    rig = _rig293()
    _commit293(rig, {"panel/a.py": "A = 1\n"})
    src = _json293.loads(_read293(_CATALOG293))
    new = dict(src, addons=dict(src["addons"], b3=dict(src["addons"]["b3"], base="docker.io/library/python@sha256:" + "b" * 64)))
    cat_only = _commit293(rig, {"panel/addon_images/catalog.json": _src293(new),
                                "docs/CHANGELOG.md": "# Changelog\n\n- **Add-on images updated.** New base.\n"})
    log = os.path.join(rig["sb"], "gh.log")
    r1 = _run293(["bash", os.path.join(_root, "tools", "sign-release.sh"), "--yes", cat_only], cwd=rig["dev"],
                 env=_env293(rig), input="")
    gh1 = _read293(log) if os.path.exists(log) else ""
    pub = _json293.loads(_blob293(rig, "catalog/latest.json") or "{}")
    eq("sign-release: a commit that changes only the catalog (and the changelog) is signed tooling-only (.inherit, no "
       "release page, so panels are offered no update) and publishes the catalog",
       (r1.returncode, _blob293(rig, "main/%s.sig" % cat_only) is not None, _blob293(rig, "main/%s.inherit" % cat_only),
        _blob293(rig, "main/%s.name" % cat_only), "release create" in gh1, pub.get("seq"),
        pub.get("addons", {}).get("b3", {}).get("base")),
       (0, True, "tooling only\n", None, False, 1, new["addons"]["b3"]["base"]))
    new2 = dict(new, addons=dict(new["addons"], b3=dict(new["addons"]["b3"], tag="v2.0.3", commit="c" * 40)))
    with_code = _commit293(rig, {"panel/addon_images/catalog.json": _src293(new2), "panel/services/x.py": "X = 1\n"})
    r2 = _run293(["bash", os.path.join(_root, "tools", "sign-release.sh"), "--yes", with_code], cwd=rig["dev"],
                 env=_env293(rig), input="")
    gh2 = _read293(log)[len(gh1):]
    eq("sign-release: ...one that changes the catalog AND panel code is a release (a release page and name, no "
       ".inherit), and publishes the catalog's next seq",
       (r2.returncode, _blob293(rig, "main/%s.inherit" % with_code), "release create" in gh2,
        _blob293(rig, "main/%s.name" % with_code) is not None,
        _json293.loads(_blob293(rig, "catalog/latest.json") or "{}").get("seq")),
       (0, None, True, True, 2))


# ── 4/5. the update rule, the scan, Renovate, the checks list ──────────────────────────────────
def _s293_static():
    eq("update rule: the catalog's source is noise (a change to it alone offers no update), the add-on build files "
       "beside it and addons.py are runtime (control)",
       [_so293._path_class(p) for p in ("panel/addon_images/catalog.json", "panel/addon_images/b3/Containerfile",
                                        "panel/addon_images/iw4madmin/entrypoint.sh", "panel/services/addons.py")],
       ["noise", "runtime", "runtime", "runtime"])


def _s293_scan():
    cat = _json293.loads(_read293(_CATALOG293))
    p = _AI293.plan()
    want_builds = {"b3": [("BASE_IMAGE", cat["addons"]["b3"]["base"]), ("B3_COMMIT", cat["addons"]["b3"]["commit"])],
                   "iw4madmin": [("BASE_IMAGE", cat["addons"]["iw4madmin"]["base"]),
                                 ("IW4MADMIN_TAG", cat["addons"]["iw4madmin"]["tag"]),
                                 ("IW4MADMIN_SHA256", cat["addons"]["iw4madmin"]["sha256"])]}
    eq("add-on scan: it pulls the image the catalog names and builds each built add-on with the catalog's values as "
       "build arguments, with nothing wrong on this tree",
       (p["upstream"], p["builds"], p["problems"], _AI293.CATALOG == _CATALOG293),
       ({"bluemap": cat["addons"]["bluemap"]["image"]}, want_builds, [], True))
    eq("add-on scan: ...the docker build carries those values as --build-arg flags",
       _AI293.build_arg_flags(want_builds["b3"]),
       ["--build-arg", "BASE_IMAGE=" + cat["addons"]["b3"]["base"], "--build-arg", "B3_COMMIT=" + cat["addons"]["b3"]["commit"]])
    seen, real_run = [], _AI293._run
    _AI293._run = lambda argv, **kw: seen.append(argv) or 0
    try:
        _AI293._images(dict(p, upstream={}), _TMP293, [])   # builds only: a pull also asks docker for its date
    finally:
        _AI293._run = real_run
    builds = [a for a in seen if a[:2] == ["docker", "build"]]
    eq("add-on scan: ...and its docker build of B3 and IW4MAdmin passes every one of those values as a --build-arg",
       [sorted(a[i + 1] for i, f in enumerate(a) if f == "--build-arg") for a in builds],
       [sorted("%s=%s" % kv for kv in want_builds[b]) for b in ("b3", "iw4madmin")])


def _caught293(mgrs, text):
    """Every value Renovate's managers `mgrs` capture in `text` (an image's digest without its name)."""
    pats = [_re293.compile(_re293.sub(r"\(\?<(?=[A-Za-z])", "(?P<", ms)) for m in mgrs for ms in m["matchStrings"]]
    return {v.split("@")[-1] for pat in pats for x in pat.finditer(text) for v in x.groupdict().values() if v}


def _s293_renovate():
    cat = _json293.loads(_read293(_CATALOG293))
    cfg = _json293.loads(_read293(os.path.join(_root, ".github", "renovate.json")))
    addon_mgrs = [m for m in cfg["customManagers"] if any("addon_images" in f for f in m.get("managerFilePatterns") or [])]
    caught = _caught293(addon_mgrs, _read293(_CATALOG293))
    pins = {v.split("@")[-1] for e in cat["addons"].values() for v in e.values()}
    eq("Renovate: the five add-on managers read the catalog (never addons.py) and between them match every pin in it",
       (len(addon_mgrs), [m for m in addon_mgrs if "/^panel/addon_images/catalog\\.json$/" not in m["managerFilePatterns"]],
        "services/addons" in _read293(os.path.join(_root, ".github", "renovate.json")), sorted(pins - caught)),
       (5, [], False, []))


def _s293_lists():
    dep = _read293(os.path.join(_root, ".github", "workflows", "deploy.yml"))
    req = _re293.search(r"(?m)^ *REQUIRED=\((.*)\)$", dep)
    ign = _re293.search(r"IGNORED='(\[[^']*\])'", dep)
    eq("sign-catalog: the checks a commit must pass are the ones the deploy waits for (the same two lists)",
       (_re293.findall(r'"([^"]*)"', req.group(0)) if req else None, _json293.loads(ign.group(1)) if ign else None),
       (list(_AC293.REQUIRED), list(_AC293.IGNORED)))
    eq("sign-catalog: its namespace is the add-on one, never the release namespace, in the script and its helper",
       (_re293.findall(r'(?m)^NS="([^"]*)"$', _read293(os.path.join(_root, "tools", "sign-catalog.sh"))), _AC293.NAMESPACE),
       ([_NS293], _NS293))


def _s293_build_refusals():
    src = _read293(_CATALOG293)
    obj = _json293.loads(src)
    bad = [
        dict(obj, addons=dict(obj["addons"], bluemap={"image": "ghcr.io/bluemap-minecraft/bluemap:v5"})),
        dict(obj, addons=dict(obj["addons"], b3=dict(obj["addons"]["b3"], commit="7c3bbe8"))),
        dict(obj, addons=dict(obj["addons"], b3=dict(obj["addons"]["b3"], url="https://example.invalid/x"))),
        dict(obj, schema=2),
        dict(obj, seq=9),
    ]
    got = [_AC293.build(_src293(o), "", 1800000000, "auto")[0] for o in bad]
    eq("sign-catalog: a catalog with a pin that is not a full digest or commit, an unknown field, another schema or a "
       "seq of its own is refused before anything is signed; today's catalog builds (control)",
       (got, _AC293.build(src, "", 1800000000, "auto")[0]), ([1, 1, 1, 1, 1], 0))


if not (_sh293.which("git") and _sh293.which("ssh-keygen")):
    skip("sign-catalog: publish, refuse and sign-release's catalog-only rule", "git or ssh-keygen is not installed")
else:
    _rig = _rig293()
    _a293, _b293 = _s293_publish(_rig)
    _s293_refusals(_rig, _a293, _b293)
    _s293_tampered(_rig, _b293)
    _s293_near_expiry(_rig, _b293)
    _s293_sign_release()
for _step293 in (_s293_static, _s293_scan, _s293_renovate, _s293_lists):
    _step293()
_s293_build_refusals()
_sh293.rmtree(_TMP293, ignore_errors=True)
