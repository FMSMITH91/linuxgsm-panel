"""Part 242 of the unit suite: CI images pinned by digest, and Harden-Runner block mode for two more jobs.

* ClusterFuzzLite builds and fuzzes on Ubuntu 24.04 images pinned by digest: the fuzz image's base
  (.clusterfuzzlite/Dockerfile), and this repository's copies of the vendor's two actions
  (.github/actions/cflite-*), which are upstream's files byte for byte but for the `image:` line.
  project.yaml selects the same base, every step names its copy by GitHub's self-repository form
  (`$/`, no checkout), and no workflow runs the vendor's actions, whose images are named by tag.
* Scorecard's image cannot be pinned in its job (its publishing rules), so scorecard.yml records its
  digest, checks the tag against it before the analysis, and checks what the analysis pulled after;
  both checks run here on stand-in tools, and the recorded tag follows the action's version.
* Renovate can propose every one of those digests, and only digests.
* The unit suites' `checks` matrix and Lighthouse block every host but their own lists (which jobs
  block is part223's; the shape of the step is part42's).

Nothing here touches the network: the registry, the GitHub API and the job log are stand-ins.
"""
import hashlib as _hash242
import json as _json242
import os
import re as _re242
import shutil as _shutil242
import subprocess as _sp242  # nosec B404 - runs bash on this part's own scratch copies of workflow steps
import tempfile as _tf242

from unit.part01 import check
from unit.part05 import _root
from unit.part06 import _wf_run_block
from unit.part29 import _job29, _jobs29, _steps29, _wf29
from unit.part223 import _egress223

_TMP242 = _tf242.mkdtemp(prefix="lgsm-unit-p242-")
_CFL242 = (".github", "actions")
# upstream's action.yml at google/clusterfuzzlite 884713a6c30a92e5e8544c39945cd7cb630abcd1: its image
# line, and the sha256 of the whole file as fetched from that commit.
_UPSTREAM242 = {
    "cflite-build-fuzzers": ("gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1",
                             "adb58e981a0348eaac2771a222441a4d0df16f241462e9a3b5de05dd6402274f"),
    "cflite-run-fuzzers": ("gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1",
                           "53bf730595b3a11d3d9236f609cef57a10399e7f97fcf2fcc2e3ff5d45024eac"),
}
_IMAGE_LINE242 = _re242.compile(r"^  image: 'docker://(gcr\.io/oss-fuzz-base/clusterfuzzlite-[a-z]+-fuzzers)"
                                r":ubuntu-24-04-v1@sha256:[0-9a-f]{64}'$", _re242.M)


def _read242(*parts):
    """Read a repository file as text."""
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. the two action copies are upstream's, but for an image pinned by digest ─────────────────────
def _copy_bad242(name, text):
    """What is wrong with one action copy: its image line, or anything else that is not upstream's."""
    old_image, digest = _UPSTREAM242[name]
    at = text.find("# action.yml\n")
    lines = _IMAGE_LINE242.findall(text)
    if at < 0 or lines != [old_image.rsplit(":", 1)[0]]:
        return ["%s: the image line is not %s:ubuntu-24-04-v1@sha256:<digest> (%r)" % (name, old_image, lines)]
    body = _IMAGE_LINE242.sub("  image: 'docker://%s'" % old_image, text[at:])
    if _hash242.sha256(body.encode("utf-8")).hexdigest() != digest:
        return ["%s: differs from upstream's action.yml in more than its image line" % name]
    return []


_copies242 = {n: _read242(*(_CFL242 + (n, "action.yml"))) for n in _UPSTREAM242}
_copy_all242 = [b for n, t in sorted(_copies242.items()) for b in _copy_bad242(n, t)]
_run242 = _copies242["cflite-run-fuzzers"]
_copy_ctl242 = {
    "an env value changed": _copy_bad242("cflite-run-fuzzers", _run242.replace("LOW_DISK_SPACE: 'True'",
                                                                             "LOW_DISK_SPACE: 'False'")),
    "the image by tag alone": _copy_bad242("cflite-run-fuzzers", _re242.sub(r"@sha256:[0-9a-f]{64}'", "'", _run242)),
    "the legacy image": _copy_bad242("cflite-run-fuzzers", _run242.replace(":ubuntu-24-04-v1@", ":v1@")),
}
check("cflite actions: both copies are upstream's action.yml byte for byte but for `image:`, which names the "
      "Ubuntu 24.04 image by tag and digest; a changed env line, an image by tag alone or the legacy image is "
      "caught",
      not _copy_all242 and all(_copy_ctl242.values()), repr((_copy_all242, _copy_ctl242)))


# ── 2. the base, the two action images and project.yaml agree on Ubuntu 24.04 ──────────────────────
# cifuzz reads base_os_version with this regex, line by line (oss-fuzz infra/cifuzz/config_utils.py).
_BASE_OS242 = _re242.compile(r"\s*base_os_version\s*:\s*([^\s]+)")


def _os_bad242(project_yaml, dockerfile, copies):
    """What disagrees: project.yaml's base_os_version, the Dockerfile's FROM, or an action's image."""
    found = [m.group(1).strip("'\"") for m in map(_BASE_OS242.match, project_yaml.splitlines()) if m]
    bad = [] if found == ["ubuntu-24-04"] else ["project.yaml: base_os_version %r" % found]
    froms = [ln for ln in dockerfile.splitlines() if ln.startswith("FROM ")]
    if not (len(froms) == 1 and _re242.fullmatch(r"FROM gcr\.io/oss-fuzz-base/base-builder-python:ubuntu-24-04"
                                                 r"@sha256:[0-9a-f]{64}", froms[0])):
        bad.append("Dockerfile: %r" % froms)
    bad += ["%s: not the 24.04 image" % n for n, t in sorted(copies.items()) if len(_IMAGE_LINE242.findall(t)) != 1]
    return bad


_py242, _df242 = _read242(".clusterfuzzlite", "project.yaml"), _read242(".clusterfuzzlite", "Dockerfile")
_os_all242 = _os_bad242(_py242, _df242, _copies242)
_os_ctl242 = {
    "no base_os_version": _os_bad242(_py242.replace("base_os_version:", "# base_os_version:"), _df242, _copies242),
    "the legacy base": _os_bad242(_py242, _df242.replace(":ubuntu-24-04@", ":latest@"), _copies242),
    "an action on the legacy image": _os_bad242(_py242, _df242, dict(
        _copies242, **{"cflite-build-fuzzers": _copies242["cflite-build-fuzzers"].replace(":ubuntu-24-04-v1@", ":v1@")})),
}
check("cflite images: project.yaml selects ubuntu-24-04, the Dockerfile's one FROM is base-builder-python:"
      "ubuntu-24-04 by digest, and both actions run the 24.04 image; each of the three on the legacy base is "
      "caught",
      not _os_all242 and all(_os_ctl242.values()), repr((_os_all242, _os_ctl242)))


# ── 3. every ClusterFuzzLite step names its copy in the self-repository form ───────────────────────
# `$/` reads the action from the commit the run is for, with no checkout; `./` would read whatever file
# sits at that path in the workspace when the step starts, which an earlier step can write (zizmor
# self-repository; GitHub changelog 2026-07-30, "Reference same-repository actions with self-repository
# syntax").
_CFL_STEP242 = _re242.compile(r"^        uses: (\S*cflite\S*|\S*clusterfuzzlite\S*)", _re242.M)


def _cfl_uses242(text):
    """(job, uses) for every ClusterFuzzLite step of one workflow."""
    return [(job, m.group(1)) for job in _jobs29(text) for s in _steps29(_job29(text, job))
            for m in _CFL_STEP242.finditer(s)]


def _cfl_bad242(found):
    """The steps that do not run a copy by `$/`, and how many jobs run one."""
    ok = ("$/.github/actions/cflite-build-fuzzers", "$/.github/actions/cflite-run-fuzzers")
    return [u for _, u in found if u not in ok], len({j for j, u in found if u in ok})


_cfl_found242 = [(f + "/" + j, u) for f in ("cflite_pr.yml", "cflite_batch.yml", "cflite_build.yml", "cflite_cron.yml")
                 for j, u in _cfl_uses242(_wf29(f))]
_cfl_all242 = _cfl_bad242(_cfl_found242)
_cfl_ctl242 = {
    "workspace-relative": _cfl_bad242(_cfl_uses242(_wf29("cflite_build.yml").replace(
        "uses: $/.github/actions/", "uses: ./.github/actions/")))[0],
    "the vendor's action": _cfl_bad242(_cfl_uses242(_wf29("cflite_build.yml").replace(
        "uses: $/.github/actions/cflite-build-fuzzers",
        "uses: google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1 # v1")))[0],
}
check("cflite workflows: all nine ClusterFuzzLite steps, in five jobs, run a copy by `$/` (the run's own "
      "commit, no checkout); a workspace-relative `./` path or the vendor's action is caught",
      _cfl_all242 == ([], 5) and len(_cfl_found242) == 9 and all(_cfl_ctl242.values()),
      repr((_cfl_all242, _cfl_found242, _cfl_ctl242)))

# actionlint v1.7.12 does not know `$/` yet; its config ignores exactly that message for exactly those steps.
_al242 = _read242(".github", "actionlint.yaml")
_al_ign242 = _re242.findall(r"^      - '(.*)'$", _al242[_al242.find("\npaths:\n"):], _re242.M)
check("actionlint: its one ignore is the `$/` cflite copies' 'ref is missing' message, on the cflite workflows only",
      "\npaths:\n  .github/workflows/cflite_*.yml:\n    ignore:\n" in _al242
      and _al_ign242 == [r'specifying action "\$/\.github/actions/cflite-(build|run)-fuzzers" in invalid format '
                         r'because ref is missing'], repr(_al_ign242))


# ── 4. Scorecard: the recorded digest, before the analysis and in its own pull ─────────────────────
_SC242 = _wf29("scorecard.yml")
_PIN242 = _re242.compile(r"^          # renovate: datasource=docker\n          SCORECARD_IMAGE: "
                         r"'(ghcr\.io/ossf/scorecard-action):(v[0-9.]+)@(sha256:[0-9a-f]{64})'$", _re242.M)
# What Scorecard's API accepts in the job that publishes (ossf/scorecard-action README, "Workflow
# Restrictions"; ossf/scorecard-infra api/app/server/verify_workflow.go): those actions, and no step without
# `uses:`. A digest-pinned `docker://` step is refused there, which is why the pin is checked from outside.
_SC_OK242 = ("actions/checkout", "actions/create-github-app-token", "ossf/scorecard-action", "actions/upload-artifact",
             "github/codeql-action/upload-sarif", "step-security/harden-runner")


def _sc_pin_bad242(text):
    """What is wrong with scorecard.yml's recorded image: not one, or not the action's own version."""
    pins = _PIN242.findall(text)
    ver = _re242.findall(r"uses: ossf/scorecard-action@[0-9a-f]{40} # (v[0-9.]+)$", text, _re242.M)
    return [] if len(pins) == 1 and ver == [pins[0][1]] else ["pin %r, action version %r" % (pins, ver)]


def _sc_bad242(text):
    """What is wrong with scorecard.yml's pin and its three jobs' wiring."""
    bad = _sc_pin_bad242(text)
    an = _job29(text, "analysis")
    uses = [_re242.search(r"^\s+uses: ([^@\s]+)@", s, _re242.M) for s in _steps29(an)]
    if not uses or not all(u and u.group(1) in _SC_OK242 for u in uses):
        bad.append("analysis: a step Scorecard's API refuses")
    if "    needs: image-pin\n" not in an:
        bad.append("analysis: does not wait for the pin check")
    after = _job29(text, "image-pulled")
    if "    needs: [image-pin, analysis]\n" not in after or "needs.analysis.result != 'skipped'" not in after:
        bad.append("image-pulled: not after both, whenever the analysis ran")
    return bad


_sc_all242 = _sc_bad242(_SC242)
_sc_ctl242 = {
    "a tag behind the action": _sc_bad242(_re242.sub(r"(scorecard-action):v[0-9.]+@", r"\1:v2.4.0@", _SC242)),
    "a run step in the analysis": _sc_bad242(_SC242.replace("      - name: Run Scorecard\n",
                                                            "      - run: true\n      - name: Run Scorecard\n")),
    "the analysis not waiting": _sc_bad242(_SC242.replace("    needs: image-pin\n", "")),
}
check("scorecard: one digest recorded for the action's own version, the analysis job holds only steps "
      "Scorecard's API accepts and waits for the pin check, and the pull check follows both; a tag behind the "
      "action, a run step and an analysis that does not wait are caught",
      not _sc_all242 and all(_sc_ctl242.values()), repr((_sc_all242, _sc_ctl242)))

# The two checks' own scripts, on stand-ins: `curl` answers the registry or the job log, `gh` the job id,
# `jq` the token. Each run's verdict is its exit status and whether it said ::error.
_BIN242 = os.path.join(_TMP242, "bin")
_STUBS242 = {
    "curl": "#!/bin/bash\n"
            "case \"$*\" in\n"
            "  *'/token?scope=repository:ossf/scorecard-action:pull'*) echo '{\"token\": \"tok\"}' ;;\n"
            "  *'-fsSI'*'Bearer tok'*'/v2/ossf/scorecard-action/manifests/v2.5.0'*)\n"
            "    printf 'HTTP/2 200\\r\\n'; [ -z \"$P242_DIGEST\" ] || printf 'Docker-Content-Digest: %s\\r\\n'"
            " \"$P242_DIGEST\" ;;\n"
            "  *'/actions/jobs/77/logs'*) cat \"$P242_LOG\" ;;\n"
            "  *) echo \"unexpected curl $*\" >&2; exit 22 ;;\n"
            "esac\n",
    "jq": "#!/bin/bash\n[ \"$*\" = '-r .token' ] && grep -q tok && echo tok\n",
    "gh": "#!/bin/bash\n"
          "[ \"$1 $2\" = 'api repos/o/r/actions/runs/9/attempts/1/jobs' ] || { echo \"gh $*\" >&2; exit 9; }\n"
          "echo 77\n",
}
os.makedirs(_BIN242)
for _n242, _t242 in _STUBS242.items():
    with open(os.path.join(_BIN242, _n242), "w", encoding="utf-8") as _fh242:
        _fh242.write(_t242)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(os.path.join(_BIN242, _n242), 0o700)  # nosec B103
_IMG242 = "ghcr.io/ossf/scorecard-action:v2.5.0@sha256:" + "1" * 64


def _sc_run242(step, digest="", log="", image=_IMG242):
    """(exit status, said ::error, wrote image=) for one scorecard.yml check step on the stand-ins."""
    script = os.path.join(_TMP242, "step.sh")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(_wf_run_block(_SC242, step))
    with open(os.path.join(_TMP242, "job.log"), "w", encoding="utf-8") as fh:
        fh.write(log)
    out = os.path.join(_TMP242, "out")
    open(out, "w").close()
    env = dict(os.environ, PATH=_BIN242 + os.pathsep + os.environ.get("PATH", ""), GITHUB_OUTPUT=out,
               SCORECARD_IMAGE=image, IMAGE=image, GH_TOKEN="t",  # nosec B106 - a stand-in, never sent anywhere
               GITHUB_REPOSITORY="o/r", GITHUB_RUN_ID="9",
               GITHUB_RUN_ATTEMPT="1", P242_DIGEST=digest, P242_LOG=os.path.join(_TMP242, "job.log"))
    r = _sp242.run(["bash", script], capture_output=True, text=True, env=env, timeout=60, check=False)  # nosec B603 B607
    with open(out, encoding="utf-8") as fh:
        wrote = fh.read()
    return r.returncode, "::error::" in r.stdout, wrote == "image=%s\n" % image


_PINSTEP242 = "The action's image tag still names the recorded digest"
_pin_runs242 = {
    "the tag names it": _sc_run242(_PINSTEP242, "sha256:" + "1" * 64),
    "the tag moved": _sc_run242(_PINSTEP242, "sha256:" + "2" * 64),
    "no digest answered": _sc_run242(_PINSTEP242, ""),
}
check("scorecard pin check: passes and hands the image on when the registry's digest for the tag is the "
      "recorded one, and fails, saying so, when the tag moved or the registry named none",
      _pin_runs242 == {"the tag names it": (0, False, True), "the tag moved": (1, True, False),
                       "no digest answered": (1, True, False)}, repr(_pin_runs242))

_PULL242 = "2026-11-18T00:00:01Z ##[group]Pull down action image 'ghcr.io/ossf/scorecard-action:v2.5.0'\n" \
           "2026-11-18T00:00:09Z Digest: sha256:%s\n2026-11-18T00:00:09Z Status: Downloaded newer image\n"
_OTHER242 = "2026-11-18T00:00:00Z Digest: sha256:%s\n" % ("3" * 64)
_PULLEDSTEP242 = "The analysis job pulled the recorded digest"
_pulled_runs242 = {
    "pulled it": _sc_run242(_PULLEDSTEP242, log=_OTHER242 + _PULL242 % ("1" * 64)),
    "pulled another": _sc_run242(_PULLEDSTEP242, log=_PULL242 % ("2" * 64)),
    "no pull in the log": _sc_run242(_PULLEDSTEP242, log=_OTHER242),
}
check("scorecard pull check: passes when the analysis job's own pull of the image printed the recorded digest "
      "(an earlier digest line for another image is not read), and fails, saying so, on another digest or "
      "a log with no pull of it",
      _pulled_runs242 == {"pulled it": (0, False, False), "pulled another": (1, True, False),
                          "no pull in the log": (1, True, False)}, repr(_pulled_runs242))


# ── 5. Renovate proposes each of those digests, and nothing else ──────────────────────────────────
_rn242 = _json242.loads(_read242(".github", "renovate.json"))


def _js_re242(pattern):
    """A Renovate (RE2, JavaScript-style) regex as Python's: `(?<name>` is `(?P<name>`; a /.../ pattern unwrapped."""
    if pattern.startswith("/") and pattern.endswith("/"):
        pattern = pattern[1:-1]
    return _re242.compile(_re242.sub(r"\(\?<(?=[A-Za-z])", "(?P<", pattern))


_img_mgr242 = [m for m in _rn242.get("customManagers", []) if "(?<datasource>docker)" in "".join(m["matchStrings"])]
_img_hits242 = [m.groupdict() for m in _js_re242(_img_mgr242[0]["matchStrings"][0]).finditer(_SC242)] \
    if len(_img_mgr242) == 1 else []
_pin242 = _PIN242.search(_SC242)
check("renovate: its image manager reads scorecard.yml's recorded image as one docker dependency, the tag as "
      "its value and the digest as its digest",
      _pin242 is not None and _img_mgr242[0].get("versioningTemplate") == "docker"
      and _img_hits242 == [{"datasource": "docker", "depName": _pin242.group(1), "currentValue": _pin242.group(2),
                            "currentDigest": _pin242.group(3)}], repr(_img_hits242))

# What a built-in manager really reads (review 1123): Renovate ADDS the configured managerFilePatterns to
# the manager's own defaults, which cannot be removed (docs/usage/configuration-options.md,
# "managerFilePatterns"); the defaults below are lib/modules/manager/<name>/index.ts's defaultConfig
# (renovatebot/renovate main, read 2026-11-20). So a manager reads every file its defaults or the
# configured patterns match, less the files a packageRule turns it off for (enabled: false). Judged on
# the configured patterns alone, the dockerfile manager "read one file" while it read B3's Containerfile
# (#598), and the github-actions manager "read no workflow" while it read every one.
_RN_DEFAULTS242 = {
    "github-actions": ["/(^|/)(workflow-templates|\\.(?:github|gitea|forgejo)/(?:workflows|actions))/.+\\.ya?ml$/",
                       "/(^|/)action\\.ya?ml$/"],
    "dockerfile": ["/(^|/|\\.)([Dd]ocker|[Cc]ontainer)file$/", "/(^|/)([Dd]ocker|[Cc]ontainer)file[^/]*$/"],
}


def _rn_files242():
    """Every file of the checkout, as repository paths (what Renovate's managers match against)."""
    out = []
    for dp, dirs, fns in os.walk(_root):
        dirs[:] = [d for d in dirs if d not in (".git", ".claude", "node_modules", ".venv", "venv", "__pycache__", "data")]
        out += [os.path.relpath(os.path.join(dp, f), _root).replace(os.sep, "/") for f in fns]
    return out


def _rn_name_re242(pattern):
    """A packageRule matchFileNames entry as a regex: `/re/` as written, else a glob (`**` crosses folders)."""
    if len(pattern) > 1 and pattern.startswith("/") and pattern.endswith("/"):
        return _js_re242(pattern)
    return _re242.compile("".join(".*" if t == "**" else "[^/]*" if t == "*" else _re242.escape(t)
                                  for t in _re242.split(r"(\*\*|\*)", pattern)) + r"\Z")


def _rn_names_match242(names, path):
    """Whether a matchFileNames list matches `path`, as Renovate reads a pattern list.

    docs/usage/string-pattern-matching.md: with positive patterns, at least one must match; with
    negative ones (`!` first), none may.
    """
    pos = [_rn_name_re242(n) for n in names if not n.startswith("!")]
    neg = [_rn_name_re242(n[1:]) for n in names if n.startswith("!")]
    return bool(names) and (not pos or any(r.match(path) for r in pos)) and not any(r.match(path) for r in neg)


def _rn_off242(cfg, manager):
    """The matchFileNames lists of the packageRules that only turn `manager` off for those files."""
    return [r.get("matchFileNames") or [] for r in cfg.get("packageRules") or [] if r.get("enabled") is False
            and manager in (r.get("matchManagers") or [])
            and set(r) <= {"description", "matchManagers", "matchFileNames", "enabled"}]


def _rn_reach242(cfg, manager, files):
    """The files `manager` reads under renovate config `cfg`: its defaults plus the configured, less the ones turned off."""
    pats = [_js_re242(p) for p in _RN_DEFAULTS242[manager] + ((cfg.get(manager) or {}).get("managerFilePatterns") or [])]
    off = _rn_off242(cfg, manager)
    return sorted(f for f in files if any(p.search(f) for p in pats) and not any(_rn_names_match242(n, f) for n in off))


_files242 = _rn_files242()
_gha_read242 = _rn_reach242(_rn242, "github-actions", _files242)
check("renovate: the github-actions manager reads the two ClusterFuzzLite copies and no other file (its built-in "
      "patterns read every workflow, so a packageRule turns it off there: the workflows' actions are Dependabot's)",
      _gha_read242 == [".github/actions/cflite-build-fuzzers/action.yml", ".github/actions/cflite-run-fuzzers/action.yml"],
      repr(_gha_read242))
_dock_read242 = _rn_reach242(_rn242, "dockerfile", _files242)
check("renovate: the dockerfile manager reads the fuzz image's Dockerfile and no other file (its built-in "
      "patterns read every Dockerfile and Containerfile; B3's, and any added later, are turned off)",
      _dock_read242 == [".clusterfuzzlite/Dockerfile"], repr(_dock_read242))
_rn_ctl242 = [_rn_reach242(_c, _m, [".github/workflows/ci.yml", ".github/actions/cflite-x/action.yml", "Containerfile",
                                    "panel/x/Dockerfile", ".clusterfuzzlite/Dockerfile"])
              for _m, _c in (("github-actions", {}), ("dockerfile", {}),
                             ("github-actions", {"packageRules": [{"matchManagers": ["github-actions"], "enabled": False,
                                                                   "matchFileNames": [".github/workflows/**"]}]}),
                             ("dockerfile", {"packageRules": [{"matchManagers": ["dockerfile"], "enabled": False,
                                                               "matchFileNames": ["!.clusterfuzzlite/Dockerfile"]}]}))]
check("renovate: (control) with nothing configured each manager reads what its defaults match; a rule turning it "
      "off by a folder glob takes those files off, and one with only a negation takes every file but that one",
      _rn_ctl242 == [[".github/actions/cflite-x/action.yml", ".github/workflows/ci.yml"],
                     [".clusterfuzzlite/Dockerfile", "Containerfile", "panel/x/Dockerfile"],
                     [".github/actions/cflite-x/action.yml"], [".clusterfuzzlite/Dockerfile"]], repr(_rn_ctl242))

_rules242 = _rn242.get("packageRules") or []
_group242 = [r for r in _rules242 if r.get("groupName")]
_grp_re242 = [_js_re242(p) for p in (_group242[0].get("matchPackageNames") or [])] if len(_group242) == 1 else []
_imgs242 = {"gcr.io/oss-fuzz-base/base-builder-python": True, "gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers": True,
            "gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers": True, "ghcr.io/ossf/scorecard-action": False,
            "docker.io/library/python": False}
check("renovate: docker images get digest updates only (no other tag), raised without a release timestamp "
      "(gcr.io and ghcr.io give none, so timestamp-required would hold them forever), and the three "
      "ClusterFuzzLite images move as one group that the Scorecard image is not in",
      any(r.get("matchDatasources") == ["docker"] and r.get("enabled") is False
          and sorted(r.get("matchUpdateTypes") or []) == ["major", "minor", "patch"] for r in _rules242)
      and any(r.get("matchDatasources") == ["docker"]
              and r.get("minimumReleaseAgeBehaviour") == "timestamp-optional" for r in _rules242)
      and {n: any(r.search(n) for r in _grp_re242) for n in _imgs242} == _imgs242,
      repr(_rules242))


# ── 6. the two jobs moved to block mode, and the exact hosts each may reach ────────────────────────
def _allowed242(workflow, job):
    """(policy, sorted allowed endpoints) of a job's Harden-Runner step.

    Read by part223's reader, which takes every word of `allowed-endpoints` in any spelling. A
    reader of one host per line at exactly twelve spaces stopped at a deeper-indented line or a line
    holding two hosts, so a host added there went unread while Harden-Runner allowed it.
    """
    policy, hosts = _egress223(_job29(_wf29(workflow), job))
    return policy, sorted(hosts)


_hr242 = {"checks": _allowed242("ci.yml", "checks"), "lighthouse": _allowed242("lighthouse.yml", "lighthouse")}
check("harden-runner: the unit suites' checks matrix blocks all but GitHub, PyPI, GitHub's release downloads "
      "and apt's mirrors (the region's plain-http one by wildcard), and Lighthouse all but GitHub, PyPI and "
      "the two hosts its panel fetches from",
      _hr242 == {"checks": ("block", ["*.archive.ubuntu.com:80", "api.github.com:443", "archive.ubuntu.com:443",
                                      "esm.ubuntu.com:443", "files.pythonhosted.org:443", "github.com:443",
                                      "objects.githubusercontent.com:443", "packages.microsoft.com:443",
                                      "pypi.org:443", "release-assets.githubusercontent.com:443",
                                      "security.ubuntu.com:443"]),
                 "lighthouse": ("block", ["api.github.com:443", "files.pythonhosted.org:443", "github.com:443",
                                          "linuxgsm.com:443", "pypi.org:443", "raw.githubusercontent.com:443"])},
      repr(_hr242))

_shutil242.rmtree(_TMP242, ignore_errors=True)
