#!/usr/bin/env python3
"""Scan the container images the panel deploys for its add-ons, with Trivy and hadolint.

What is scanned is what the add-on catalog names, read from the repository, never typed into the
workflow. panel/addon_images/catalog.json is the source of the catalog that tools/sign-catalog.sh
signs and panels fetch, so a catalog change cannot merge without this scan passing:
  * every add-on whose entry has an `image` (`registry/name@sha256:...`), pulled by that digest;
  * every image the catalog's `sites` section names (the websites' static, PHP, WordPress, wp-cli,
    tunnel, object cache and Node images), pulled by digest, and each image the panel builds for the
    websites (panel/website_images/<name>/Containerfile: the page cache's proxy, and the PHP sites'
    image once per PHP version the catalog pins, labelled php@<version>), built from `sites`;
  * every add-on the panel builds on the host (panel/addon_images/<name>/Containerfile, an entry with
    a `base`), built here with the catalog's values passed as build arguments, as the panel passes
    them (BASE_IMAGE is `base`; <NAME>_TAG, <NAME>_SHA256 and <NAME>_COMMIT are `tag`, `sha256` and
    `commit`). The Containerfile declares those ARGs with NO default, so a catalog update changes no
    file a panel runs; the scan stops on an ARG with a default (a second copy of a pin, which could
    drift from the catalog) and on an ARG the catalog does not supply (the build would fail on hosts).

The gate (OWASP Docker Security Cheat Sheet, rule 9; OWASP CI/CD Top 10, CICD-SEC-3): Trivy fails the
run on a High or Critical vulnerability that has a fixed version, and on a secret found in an image.
An accepted finding goes in .github/trivyignore.yaml with its reason and an expiry date, after which
it fails the run again until someone looks at it. hadolint lints each Containerfile, and the other
Dockerfiles CI builds (OTHER_DOCKERFILES), with the rules .github/hadolint.yaml turns off and why.
Nothing is pushed anywhere; no secret or token is used.

    addon_images.py plan    print what would be scanned (JSON); exit 1 on a problem with the pins
    addon_images.py scan    pull, build, scan and lint; exit 1 on any finding or failure
"""
import json
import os
import re
import subprocess  # nosec B404 - docker, with fixed argument lists
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IMAGES_DIR = os.path.join(ROOT, "panel", "addon_images")
WEBSITE_IMAGES_DIR = os.path.join(ROOT, "panel", "website_images")
CATALOG = os.path.join(IMAGES_DIR, "catalog.json")
TRIVY_IGNORE = os.path.join(ROOT, ".github", "trivyignore.yaml")
HADOLINT_CONFIG = os.path.join(ROOT, ".github", "hadolint.yaml")
# Dockerfiles linted beside the add-on Containerfiles, though no host runs them: ClusterFuzzLite's
# build image, which nothing else lints. Paths from the repository root.
OTHER_DOCKERFILES = (".clusterfuzzlite/Dockerfile",)

PINNED_RE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}\Z")
ARG_RE = re.compile(r"^ARG[ \t]+([A-Za-z_][A-Za-z0-9_]*)=(\S+)[ \t]*$", re.M)
DECLARED_RE = re.compile(r"^ARG[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.M)
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
# Trivy's databases from GitHub's registry, so its default mirror elsewhere is never asked.
TRIVY_DBS = ("--db-repository", "ghcr.io/aquasecurity/trivy-db:2",
             "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db:1")


def read_catalog(path=CATALOG):
    """The catalog source's {add-on name: {field: value}}; ({}, problem) when it cannot be read."""
    try:
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError) as exc:
        return {}, "%s: cannot be read as JSON (%s)" % (path, exc)
    addons = obj.get("addons") if isinstance(obj, dict) and obj.get("schema") == 1 else None
    if not isinstance(addons, dict) or not all(isinstance(v, dict) for v in addons.values()):
        return {}, "%s: not a schema 1 catalog with an `addons` object" % path
    return addons, ""


def upstream_images(addons):
    """{name: image} for each add-on the catalog names a pulled image for, pinned by digest."""
    return {k: v["image"] for k, v in sorted(addons.items()) if isinstance(v.get("image"), str)}


def build_dirs(images_dir=IMAGES_DIR):
    """The add-on build folders (each with a Containerfile), by name."""
    try:
        names = sorted(os.listdir(images_dir))
    except OSError:
        return []
    return [n for n in names if NAME_RE.match(n) and os.path.isfile(os.path.join(images_dir, n, "Containerfile"))]


def build_args(name, entry):
    """[(ARG, value)] the build of add-on `name` takes from its catalog entry."""
    prefix = name.upper().replace("-", "_") + "_"
    out = [("BASE_IMAGE", entry["base"])] if "base" in entry else []
    return out + [(prefix + k.upper(), entry[k]) for k in ("tag", "sha256", "commit") if k in entry]


def defaulted_args(containerfile_text):
    """The ARGs a Containerfile gives a default: [(name, value)]. Their values belong to the catalog alone."""
    return ARG_RE.findall(containerfile_text)


def unsupplied_args(containerfile_text, args):
    """The ARGs a Containerfile declares that `args` (the catalog's build arguments) does not supply, sorted."""
    return sorted(set(DECLARED_RE.findall(containerfile_text)) - {n for n, _ in args})


def _pin_problems(addons):
    """Each pulled image or build base the catalog does not pin by digest."""
    out = ["%s: image %s is not pinned by digest" % (k, v) for k, v in upstream_images(addons).items()
           if not PINNED_RE.match(v)]
    return out + ["%s: base %s is not pinned by digest" % (k, v["base"]) for k, v in sorted(addons.items())
                  if isinstance(v.get("base"), str) and not PINNED_RE.match(v["base"])]


def _image_problems(addons, builds):
    """What is wrong with the pins themselves: a pulled image not pinned by digest, a build without its entry."""
    out = _pin_problems(addons)
    out += ["%s: has a Containerfile but no catalog entry with a base" % b for b in builds
            if not isinstance((addons.get(b) or {}).get("base"), str)]
    out += ["%s: the catalog names it a base to build from but there is no Containerfile" % k
            for k, v in sorted(addons.items()) if "base" in v and k not in builds]
    return out


def _build_plan(name, entry, images_dir, problems, offered=None):
    """[(ARG, value)] that build `name` takes from its catalog entry; what is wrong is appended to `problems`.

    Only the ARGs its Containerfile declares, as the panel passes them; every one must come from the catalog,
    and none may have a default. `offered` is the catalog's [(ARG, value)] for it (an add-on's by default).
    """
    with open(os.path.join(images_dir, name, "Containerfile"), encoding="utf-8") as fh:
        text = fh.read()
    declared = set(DECLARED_RE.findall(text))
    args = [(n, v) for n, v in (build_args(name, entry) if offered is None else offered) if n in declared]
    if not declared:
        problems.append("%s: its Containerfile declares no ARG to take the catalog's values" % name)
    problems.extend("%s: ARG %s has a default (%s); its value must come from the catalog alone" % (name, n, v)
                    for n, v in defaulted_args(text))
    problems.extend("%s: ARG %s is not supplied by the catalog" % (name, n) for n in unsupplied_args(text, args))
    return args


def read_sites(path=CATALOG):
    """The catalog source's `sites` section, or {} when it has none."""
    try:
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError):
        return {}
    sites = obj.get("sites") if isinstance(obj, dict) else None
    return sites if isinstance(sites, dict) else {}


def _image_of(entry):
    return entry.get("image") if isinstance(entry, dict) else None


def _versioned(prefix, entries):
    """{prefix + version: image} for {version: {"image": ...}}."""
    return {prefix + v: _image_of(e) for v, e in (entries or {}).items()}


def sites_images(sites):
    """{label: image} of every image the `sites` section names, as the websites pull them."""
    out = {"sites-static": _image_of(sites.get("static")), "sites-wpcli": _image_of(sites.get("wpcli")),
           "sites-object-cache": _image_of(sites.get("object_cache"))}
    out.update(_versioned("sites-php-", sites.get("php")))
    out.update(_versioned("sites-wordpress-php", (sites.get("wordpress") or {}).get("php")))
    out.update(_versioned("sites-tunnel-", sites.get("tunnel")))
    for runtime, entry in (sites.get("runtimes") or {}).items():
        out.update(_versioned("sites-%s-" % runtime, (entry or {}).get("versions")))
    return {k: v for k, v in sorted(out.items()) if isinstance(v, str)}


def site_builds(name, sites):
    """{label: [(ARG, value)]} of the builds of website folder `name`: the PHP image once per pinned PHP version."""
    if name != "php":
        return {name: site_build_args(name, sites)}
    return {"php@" + v: [("BASE_IMAGE", e["image"])] for v, e in sorted((sites.get("php") or {}).items())
            if isinstance(e, dict) and isinstance(e.get("image"), str)}


def build_folder(label):
    """The folder of a build's label: "php@8.4" is built from php/, every other label from its own name."""
    return label.split("@", 1)[0]


def site_build_args(name, sites):
    """[(ARG, value)] a websites build takes from `sites` (the page cache's proxy: caddy-cache)."""
    c = (sites.get("caddy_cache") or {}) if name == "caddy-cache" else {}
    keys = (("BUILDER_IMAGE", "builder"), ("BASE_IMAGE", "base"), ("CADDY_VERSION", "caddy"),
            ("CACHE_MODULE", "module"), ("CACHE_VERSION", "version"))
    return [(arg, c[k]) for arg, k in keys if isinstance(c.get(k), str)]


def sites_plan(catalog_path, images_dir, problems):
    """{"upstream": {label: image}, "builds": {name: [(ARG, value)]}} of the websites; problems appended."""
    sites = read_sites(catalog_path)
    if not sites:
        return {"upstream": {}, "builds": {}}
    up = sites_images(sites)
    problems.extend("%s: image %s is not pinned by digest" % (k, v) for k, v in up.items() if not PINNED_RE.match(v))
    builds = {label: _build_plan(b, {}, images_dir, problems, args)
              for b in build_dirs(images_dir) for label, args in site_builds(b, sites).items()}
    problems.extend("%s: base %s is not pinned by digest" % (b, v) for b, args in builds.items() for n, v in args
                    if n.endswith("_IMAGE") and not PINNED_RE.match(v))
    return {"upstream": up, "builds": builds}


def plan(catalog_path=CATALOG, images_dir=IMAGES_DIR, website_dir=WEBSITE_IMAGES_DIR):
    """{"upstream": {name: image}, "builds": {name: [(ARG, value)]}, "sites": {upstream, builds}, "problems": [text]}."""
    addons, problem = read_catalog(catalog_path)
    builds = build_dirs(images_dir)
    problems = [problem] if problem else _image_problems(addons, builds)
    args = {b: _build_plan(b, addons.get(b) or {}, images_dir, problems) for b in builds}
    up = upstream_images(addons)
    if not up and not builds and not problems:
        problems.append("nothing to scan: no pulled image in the catalog and no build folder")
    return {"upstream": up, "builds": args, "sites": sites_plan(catalog_path, website_dir, problems), "problems": problems}


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
    sites = p.get("sites") or {}
    return (_pull_all(dict(p["upstream"], **(sites.get("upstream") or {})), work, results)
            + _build_all(p["builds"], IMAGES_DIR, work, results)
            + _build_all(sites.get("builds") or {}, WEBSITE_IMAGES_DIR, work, results))


def _pull_all(upstream, work, results):
    """Pull and save each image of {label: ref}; [(label, tar name)] of those saved."""
    saved = []
    for name, ref in upstream.items():
        tar = "pull-%s.tar" % name
        if _run(["docker", "pull", "--quiet", ref]) or _run(["docker", "save", "-o", os.path.join(work, tar), ref]):
            results.append((name, "could not be pulled or saved"))
            continue
        print("%s: %s, created %s" % (name, ref, _created(ref)), flush=True)
        saved.append((name, tar))
    return saved


def _build_all(builds, images_dir, work, results):
    """Build and save each {name: [(ARG, value)]} from `images_dir`/<name>; [(label, tar name)] of those saved."""
    saved = []
    for b, args in builds.items():
        tag, tar = "localhost/addon-scan-%s:ci" % b.replace("@", "-"), "build-%s.tar" % b.replace("@", "-")
        d = os.path.join(images_dir, build_folder(b))
        if (_run(["docker", "build", "--quiet", "-t", tag, *build_arg_flags(args), "-f", os.path.join(d, "Containerfile"), d])
                or _run(["docker", "save", "-o", os.path.join(work, tar), tag])):
            results.append((b + " (built)", "could not be built or saved"))
            continue
        saved.append((b + " (built)", tar))
    return saved


def build_arg_flags(args):
    """Docker build's --build-arg flags for [(ARG, value)]."""
    return [f for n, v in args for f in ("--build-arg", "%s=%s" % (n, v))]


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
    sites = sorted({build_folder(b) for b in (p.get("sites") or {}).get("builds") or {}})
    return ([(b + " Containerfile", os.path.join(IMAGES_DIR, b, "Containerfile")) for b in p["builds"]]
            + [("websites " + b + " Containerfile", os.path.join(WEBSITE_IMAGES_DIR, b, "Containerfile")) for b in sites]
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
