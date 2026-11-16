"""Write a release's software bill of materials: CycloneDX 1.6 JSON (OWASP CycloneDX).

Usage: <requirements.txt> NUL <requirements.in> NUL <package-lock.json> | sbom.py <full commit id> <tag> <date>

Stdin is three files of the release, read from git by sign-release.sh (so this reads no file): the
panel's hashed Python lockfile, the list of what the panel itself asks for, and the lockfile of
gamedig (the player-query tool install.sh installs with npm). `date` is the commit's date, ISO 8601
in UTC. Prints the SBOM on stdout.

Every package a panel installs is a component: its name, version, package URL and the hashes pip or
npm checks it against, as the lockfiles pin them (pip installs requirements.txt --require-hashes
--no-deps, so the list is the whole Python closure; the packages its header leaves out are not
installed). The panel depends on what requirements.in and gamedig's package.json name; what those
depend on in turn is not recorded, so it is left out rather than guessed (CycloneDX: a missing
dependency entry means unknown). The output is the same for the same release, byte for byte: the
serial number comes from the commit id, the timestamp is the commit's date, and the lists are sorted,
so anyone can make it again from the tagged commit and compare.
"""
import base64
import json
import re
import sys
import uuid

REPO = "FMSMITH91/linuxgsm-panel"
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _pypi_name(name):
    """A Python package's name as its package URL writes it (PEP 503: lower case, runs of -_. as -)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def python_components(locked):
    """The components of a hashed requirements.txt, by name: {name: component}."""
    out = {}
    for entry in locked.replace("\\\n", " ").splitlines():
        m = _REQ_RE.match(entry.strip())
        if not m:
            continue
        name, version = _pypi_name(m.group(1)), m.group(2)
        purl = "pkg:pypi/%s@%s" % (name, version)
        out[name] = {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl,
                     "scope": "required",
                     "hashes": [{"alg": "SHA-256", "content": h} for h in sorted(set(_HASH_RE.findall(entry)))]}
    return out


def direct_python(wanted, components):
    """The bom-refs of the packages requirements.in names, that the lockfile pins."""
    names = (_pypi_name(re.split(r"[\s\[;<>=!~]", ln.strip(), maxsplit=1)[0])
             for ln in wanted.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", "-")))
    return sorted(components[n]["bom-ref"] for n in names if n in components)


def _npm_purl(name, version):
    scope, _, base = name.rpartition("/")
    return "pkg:npm/%s%s@%s" % (scope.replace("@", "%40") + "/" if scope else "", base, version)


def _npm_hashes(integrity):
    """The hashes in an npm `integrity` value (sha512-<base64> ...), as CycloneDX writes them."""
    out = []
    for part in (integrity or "").split():
        alg, _, b64 = part.partition("-")
        if alg in ("sha512", "sha384", "sha256", "sha1") and b64:
            try:
                out.append({"alg": {"sha1": "SHA-1"}.get(alg, "SHA-" + alg[3:]),
                            "content": base64.b64decode(b64, validate=True).hex()})
            except ValueError:
                continue
    return out


def npm_components(lock_text):
    """({bom-ref: component} of every package in an npm lockfile v2/v3, [bom-refs of the root's direct deps])."""
    try:
        lock = json.loads(lock_text or "{}")
    except ValueError:
        return {}, []
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(packages, dict):
        return {}, []
    out, by_name = {}, {}
    for path, pkg in sorted(packages.items()):
        if not path or not isinstance(pkg, dict) or pkg.get("dev") or not pkg.get("version"):
            continue
        name = pkg.get("name") or path.rsplit("node_modules/", 1)[-1]
        purl = _npm_purl(name, pkg["version"])
        comp = {"type": "library", "bom-ref": purl, "name": name, "version": pkg["version"], "purl": purl,
                "scope": "required", "hashes": _npm_hashes(pkg.get("integrity"))}
        if isinstance(pkg.get("license"), str) and pkg["license"]:
            comp["licenses"] = [{"expression": pkg["license"]}]
        out[purl] = comp
        if path == "node_modules/" + name:
            by_name[name] = purl
    root = packages.get("", {}) if isinstance(packages.get(""), dict) else {}
    direct = sorted(by_name[n] for n in (root.get("dependencies") or {}) if n in by_name)
    return out, direct


def sbom(commit, tag, date, locked, wanted, npm_lock):
    """The CycloneDX document for one release, as a dict."""
    py = python_components(locked)
    npm, npm_direct = npm_components(npm_lock)
    components = sorted(list(py.values()) + list(npm.values()), key=lambda c: c["bom-ref"])
    root = "pkg:github/%s@%s" % (REPO, commit)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/%s/commit/%s" % (REPO, commit)),
        "version": 1,
        "metadata": {
            "timestamp": date,
            "tools": {"components": [{"type": "application", "name": "linuxgsm-panel tools/sbom.py"}]},
            "component": {"type": "application", "bom-ref": root, "name": "linuxgsm-panel", "version": tag,
                          "purl": root,
                          "externalReferences": [{"type": "vcs", "url": "https://github.com/%s" % REPO}]},
        },
        "components": components,
        "dependencies": [{"ref": root, "dependsOn": sorted(direct_python(wanted, py) + npm_direct)}],
    }


def main(argv, stdin):
    """Read the three files from `stdin` and print the SBOM; 2 on bad arguments."""
    if len(argv) != 4 or not re.fullmatch(r"[0-9a-f]{40}", argv[1]):
        print("usage: <req.txt> NUL <req.in> NUL <package-lock.json> | sbom.py <commit> <tag> <date>", file=sys.stderr)
        return 2
    parts = (stdin.split("\0") + ["", "", ""])[:3]
    doc = sbom(argv[1], argv[2], argv[3], *parts)
    if not doc["components"]:
        print("sbom.py: no package found in the lockfiles", file=sys.stderr)
        return 1
    print(json.dumps(doc, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv, sys.stdin.read()))
