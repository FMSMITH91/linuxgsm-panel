#!/usr/bin/env python3
"""Scan the container images the panel deploys for its add-ons, with Trivy and hadolint.

What is scanned is what a host runs, read from the repository, never typed into the workflow:
  * every upstream image panel/services/addons.py pins by digest (a module-level `*_IMAGE` constant
    of the form `registry/name@sha256:...`), pulled by that digest;
  * every image the panel builds on the host (panel/addon_images/<name>/Containerfile), built here
    from the Containerfile's own ARG defaults. Each default must be a value addons.py holds (the
    build arguments it passes), or the scan stops: an image built from other values is not the
    one hosts run.

The gate (OWASP Docker Security Cheat Sheet, rule 9; OWASP CI/CD Top 10, CICD-SEC-3): Trivy fails the
run on a High or Critical vulnerability that has a fixed version, and on a secret found in an image.
An accepted finding goes in .github/trivyignore.yaml with its reason and an expiry date, after which
it fails the run again until someone looks at it. hadolint lints each Containerfile, and the other
Dockerfiles CI builds (OTHER_DOCKERFILES), with the rules .github/hadolint.yaml turns off and why.
Nothing is pushed anywhere; no secret or token is used.

    addon_images.py plan    print what would be scanned (JSON); exit 1 on a problem with the pins
    addon_images.py scan    pull, build, scan and lint; exit 1 on any finding or failure
"""
import ast
import json
import os
import re
import subprocess  # nosec B404 - docker, with fixed argument lists
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADDONS = os.path.join(ROOT, "panel", "services", "addons.py")
IMAGES_DIR = os.path.join(ROOT, "panel", "addon_images")
TRIVY_IGNORE = os.path.join(ROOT, ".github", "trivyignore.yaml")
HADOLINT_CONFIG = os.path.join(ROOT, ".github", "hadolint.yaml")
# Dockerfiles linted beside the add-on Containerfiles, though no host runs them: ClusterFuzzLite's
# build image, which nothing else lints. Paths from the repository root.
OTHER_DOCKERFILES = (".clusterfuzzlite/Dockerfile",)

PINNED_RE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}\Z")
ARG_RE = re.compile(r"^ARG[ \t]+([A-Za-z_][A-Za-z0-9_]*)=(\S+)[ \t]*$", re.M)
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
# Trivy's databases from GitHub's registry, so its default mirror elsewhere is never asked.
TRIVY_DBS = ("--db-repository", "ghcr.io/aquasecurity/trivy-db:2",
             "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db:1")


def module_strings(text):
    """({NAME: value} of addons.py's module-level string constants, every string constant in it)."""
    tree = ast.parse(text)
    named = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            named[node.targets[0].id] = node.value.value
    every = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    return named, every


def upstream_images(named):
    """{NAME: image} for each `*_IMAGE` constant that pins an image by digest."""
    return {k: v for k, v in sorted(named.items()) if k.endswith("_IMAGE") and PINNED_RE.match(v)}


def build_dirs(images_dir=IMAGES_DIR):
    """The add-on build folders (each with a Containerfile), by name."""
    try:
        names = sorted(os.listdir(images_dir))
    except OSError:
        return []
    return [n for n in names if NAME_RE.match(n) and os.path.isfile(os.path.join(images_dir, n, "Containerfile"))]


def foreign_args(containerfile_text, every):
    """The ARG defaults in a Containerfile that addons.py does not hold: [(name, value)]."""
    return [(n, v) for n, v in ARG_RE.findall(containerfile_text) if v not in every]


def plan(addons_path=ADDONS, images_dir=IMAGES_DIR):
    """{"upstream": {NAME: image}, "builds": [name], "problems": [text]} for the tree as it is."""
    with open(addons_path, encoding="utf-8") as fh:
        named, every = module_strings(fh.read())
    builds, problems = build_dirs(images_dir), []
    for b in builds:
        with open(os.path.join(images_dir, b, "Containerfile"), encoding="utf-8") as fh:
            text = fh.read()
        if not ARG_RE.search(text):
            problems.append("%s: its Containerfile has no ARG defaults to build from" % b)
        for n, v in foreign_args(text, every):
            problems.append("%s: ARG %s=%s is not a value panel/services/addons.py passes" % (b, n, v))
    up = upstream_images(named)
    if not up and not builds:
        problems.append("nothing to scan: no pinned image in addons.py and no build folder")
    return {"upstream": up, "builds": builds, "problems": problems}


def trivy_argv(trivy_image, cache, tars, tar_name):
    """The docker command that runs Trivy's gate over one saved image.

    As this account (--user), so the database it caches in `cache` is this account's to remove.
    """
    return ["docker", "run", "--rm", "--user", "%d:%d" % (os.getuid(), os.getgid()), "-e", "HOME=/cache",
            "-v", cache + ":/cache", "-v", tars + ":/scan:ro",
            "-v", TRIVY_IGNORE + ":/trivyignore.yaml:ro", trivy_image,
            "image", "--cache-dir", "/cache", "--input", "/scan/" + tar_name,
            "--scanners", "vuln,secret", "--severity", "HIGH,CRITICAL", "--ignore-unfixed",
            "--ignorefile", "/trivyignore.yaml", "--exit-code", "1", "--no-progress", *TRIVY_DBS]


def hadolint_argv(hadolint_image):
    """The docker command that lints one Containerfile, read on stdin."""
    return ["docker", "run", "--rm", "-i", "--network", "none", "-v", HADOLINT_CONFIG + ":/hadolint.yaml:ro", hadolint_image,
            "hadolint", "--config", "/hadolint.yaml", "-"]


def _run(argv, **kw):
    """Run argv (a list, never a shell); its return code."""
    print("+ " + " ".join(argv), flush=True)
    return subprocess.run(argv, check=False, **kw).returncode  # nosec B603 - fixed docker argv


def _created(ref):
    out = subprocess.run(["docker", "image", "inspect", "--format", "{{.Created}}", ref],  # nosec B603 B607
                         capture_output=True, text=True, check=False)
    return out.stdout.strip() or "unknown"


def _images(p, work, results):
    """Pull or build each image and save it to `work`; [(label, tar name)] of those that got there."""
    saved = []
    for name, ref in p["upstream"].items():
        tar = name.lower() + ".tar"
        if _run(["docker", "pull", "--quiet", ref]) or _run(["docker", "save", "-o", os.path.join(work, tar), ref]):
            results.append((name, "could not be pulled or saved"))
            continue
        print("%s: %s, created %s" % (name, ref, _created(ref)), flush=True)
        saved.append((name, tar))
    for b in p["builds"]:
        tag, tar = "localhost/addon-scan-%s:ci" % b, "build-%s.tar" % b
        d = os.path.join(IMAGES_DIR, b)
        if (_run(["docker", "build", "--quiet", "-t", tag, "-f", os.path.join(d, "Containerfile"), d])
                or _run(["docker", "save", "-o", os.path.join(work, tar), tag])):
            results.append((b + " (built)", "could not be built or saved"))
            continue
        saved.append((b + " (built)", tar))
    return saved


def _verdict(rc, tool):
    return "passed" if rc == 0 else "FAILED (%s, exit %d)" % (tool, rc)


def _scan_images(p, trivy_image, results):
    """Pull or build every image, run Trivy's gate over each; append (label, verdict) to results."""
    with tempfile.TemporaryDirectory(prefix="addon-scan-") as work:
        cache = os.path.join(work, "cache")
        os.mkdir(cache)
        for label, tar in _images(p, work, results):
            results.append((label, _verdict(_run(trivy_argv(trivy_image, cache, work, tar)), "Trivy")))


def lint_targets(p):
    """[(label, path)] of every file hadolint lints: each build's Containerfile, then OTHER_DOCKERFILES."""
    return ([(b + " Containerfile", os.path.join(IMAGES_DIR, b, "Containerfile")) for b in p["builds"]]
            + [(rel, os.path.join(ROOT, *rel.split("/"))) for rel in OTHER_DOCKERFILES])


def _lint(p, hadolint_image, results):
    """Run hadolint over every lint_targets() file; append (label, verdict) to results."""
    for label, path in lint_targets(p):
        with open(path, "rb") as fh:
            results.append((label, _verdict(_run(hadolint_argv(hadolint_image), stdin=fh), "hadolint")))


def scan(trivy_image, hadolint_image):
    """Pull, build, scan and lint everything plan() names; 0 when all of it passed."""
    p = plan()
    if p["problems"]:
        for line in p["problems"]:
            print("ERROR: " + line)
        return 1
    results = []
    _scan_images(p, trivy_image, results)
    _lint(p, hadolint_image, results)
    lines = ["| Image | Result |", "| --- | --- |"] + ["| %s | %s |" % r for r in results]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## Add-on images\n\n" + "\n".join(lines) + "\n")
    return 0 if results and all(r[1] == "passed" for r in results) else 1


WORKFLOW = os.path.join(ROOT, ".github", "workflows", "addon-images.yml")
# A scanner image line in the workflow's env, where Renovate keeps the pins: name:tag@sha256:<64 hex>.
_PIN_RE = re.compile(r"^ +(TRIVY_IMAGE|HADOLINT_IMAGE): '([a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64})'$",
                     re.M)


def scanner_images(path=WORKFLOW):
    """The Trivy and hadolint images, read from the workflow file (None for one it does not pin by digest).

    Read from the checked-out file rather than the job's environment, so the docker command is built only
    from text in the repository, and only from a reference that names its digest.
    """
    with open(path, encoding="utf-8") as fh:
        found = dict(_PIN_RE.findall(fh.read()))
    return found.get("TRIVY_IMAGE"), found.get("HADOLINT_IMAGE")


def main(argv):
    """Run `plan` or `scan` (see the module's docstring); the exit status."""
    if argv[1:2] == ["plan"]:
        p = plan()
        print(json.dumps(p, indent=2))
        return 1 if p["problems"] else 0
    if argv[1:2] == ["scan"]:
        trivy, hadolint = scanner_images()
        if not trivy or not hadolint:
            print("ERROR: %s must pin TRIVY_IMAGE and HADOLINT_IMAGE, each as name:tag@sha256:<digest>" % WORKFLOW)
            return 1
        return scan(trivy, hadolint)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
