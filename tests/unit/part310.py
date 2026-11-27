r"""Part 310 of the unit suite: the website images built on the host, as CI scans them; the add-ons' Podman read.

Held here (.github/scripts/addon_images.py, panel/website_images/*/Containerfile, panel/services/addons.py):
* The image scan scans what the sites run: every pinned image a site runs unmodified is pulled and scanned,
  every image the panel builds on the host from a pin is built from its Containerfile with the catalog's
  values (WordPress per PHP version, Node.js per version with npm's version, wp-cli, the tunnel connector
  with its certificate authorities' image) and only the build is scanned; a pin that is only a build's base
  is not pulled on its own. A Containerfile's ARG the catalog does not supply stops the scan.
* The Containerfiles: each applies its distribution's security updates and leaves no package lists or cache;
  wp-cli's goes back to upstream's user (numerically); Node.js's installs npm at the catalog's exact version
  and fails the build otherwise; the tunnel connector is the program alone on an empty image, non-root.
* The add-on card's read (status_sh, in bash with a stand-in podman) and the install probe ask Podman's
  version in a runtime folder of their own, removed after: an account with no user manager (all its add-ons
  removed) got rootless Podman's fallback folders back in /tmp at every read.

HOW IT RUNS. Nothing is pulled or built: the scan's docker calls are recorded, and bash runs status_sh over a
scratch folder with a stand-in podman and id first on PATH. The route-level builds (install_sh through
POST /websites/<id>/update-image and tunnel_apply) are part305's section 13.
"""
import importlib.util as _ilu310
import json as _json310
import os
import shutil as _shutil310
import subprocess as _sp310  # nosec B404 - bash over the panel's own status shell, in a scratch folder
import tempfile as _tf310

from unit.part01 import _root, check, eq
from panel.services import addons as _ad310

_spec310 = _ilu310.spec_from_file_location("addon_images_p310", os.path.join(_root, ".github", "scripts", "addon_images.py"))
_AI310 = _ilu310.module_from_spec(_spec310)
_spec310.loader.exec_module(_AI310)
_IMAGES310 = os.path.join(_root, "panel", "website_images")
with open(os.path.join(_root, "panel", "addon_images", "catalog.json"), encoding="utf-8") as _fh310:
    _DOC310 = _json310.load(_fh310)
_SITES310 = _DOC310["sites"]


def _cf310(folder):
    with open(os.path.join(_IMAGES310, folder, "Containerfile"), encoding="utf-8") as fh:
        return fh.read()


# ── 1. the scan's scope ───────────────────────────────────────────────────────────────────────────────
def _s1_scope():
    p = _AI310.plan()
    up, builds = p["sites"]["upstream"], p["sites"]["builds"]
    node = _SITES310["runtimes"]["node"]
    tun = _SITES310["tunnel"]["cloudflare"]
    eq("image scan (plan): the images the panel builds from a pin are built and scanned as built, never pulled on "
       "their own (the raw WordPress, wp-cli, Node.js and cloudflared pins were scanned, though no site runs them)",
       (sorted(up), sorted(k for k in builds if not k.startswith(("php@", "caddy-cache")))),
       (["sites-object-cache", "sites-static"],
        sorted(["cloudflared", "wpcli"] + ["node@" + v for v in node["versions"]]
               + ["wordpress@php" + v for v in _SITES310["wordpress"]["php"]])))
    eq("image scan (plan): each build takes its catalog pins as build arguments: Node.js its version's image and "
       "npm's exact version, the tunnel connector its program's image and the certificate authorities' image",
       (builds.get("node@24"), builds.get("cloudflared"), builds.get("wpcli"), p["problems"]),
       ([("BASE_IMAGE", node["versions"]["24"]["image"]), ("NPM_VERSION", node["npm"])],
        [("BASE_IMAGE", tun["image"]), ("CERTS_IMAGE", tun["certs"])], [("BASE_IMAGE", _SITES310["wpcli"]["image"])], []))
    _s1_unbuilt(node)
    _s1_folders(p)
    _s1_missing()


def _s1_unbuilt(node):
    eq("image scan (sites_images): a site image the panel has no Containerfile for is still pulled and scanned as "
       "pinned (control: every image a site runs is scanned one way or the other)",
       sorted(_AI310.sites_images(_SITES310, ())), sorted(
           ["sites-static", "sites-object-cache", "sites-wpcli", "sites-tunnel-cloudflare"]
           + ["sites-php-" + v for v in _SITES310["php"]] + ["sites-wordpress-php" + v for v in _SITES310["wordpress"]["php"]]
           + ["sites-node-" + v for v in node["versions"]]))


def _s1_folders(p):
    seen, real = [], _AI310._run
    _AI310._run = lambda argv, **kw: seen.append(argv) or 0
    try:
        _AI310._images(dict(p, upstream={}, builds={}, sites=dict(p["sites"], upstream={})), _tf310.gettempdir(), [])
    finally:
        _AI310._run = real
    built = [a for a in seen if a[:2] == ["docker", "build"]]
    files = sorted({a[a.index("-f") + 1].split(os.sep)[-2] for a in built})
    eq("image scan (_images): every build runs from its own folder's Containerfile, and hadolint lints each",
       (files, sorted(t for t, _p in _AI310.lint_targets(p) if t.startswith("websites "))),
       (["caddy-cache", "cloudflared", "node", "php", "wordpress", "wpcli"],
        ["websites %s Containerfile" % f for f in ("caddy-cache", "cloudflared", "node", "php", "wordpress", "wpcli")]))


def _s1_missing():
    sites = _json310.loads(_json310.dumps(_SITES310))
    del sites["runtimes"]["node"]["npm"]
    del sites["tunnel"]["cloudflare"]["certs"]
    d = _tf310.mkdtemp(prefix="p310-scan-")
    try:
        path = os.path.join(d, "catalog.json")
        with open(path, "w", encoding="utf-8") as fh:
            _json310.dump(dict(_DOC310, sites=sites), fh)
        probs = _AI310.plan(path)["problems"]
    finally:
        _shutil310.rmtree(d, ignore_errors=True)
    eq("image scan (plan): a build whose Containerfile asks for a value the catalog lacks (npm's version, the "
       "certificate authorities' image) stops the scan before anything is built",
       (any("node: ARG NPM_VERSION" in x for x in probs), any("cloudflared: ARG CERTS_IMAGE" in x for x in probs)),
       (True, True))


# ── 2. the Containerfiles ─────────────────────────────────────────────────────────────────────────────
def _s2_containerfiles():
    wp, cli, node, cfd = (_cf310(f) for f in ("wordpress", "wpcli", "node", "cloudflared"))
    eq("Containerfiles: WordPress's and Node.js's apply Debian's security updates and keep no package lists; "
       "wp-cli's applies Alpine's with no package index",
       ("apt-get upgrade -y" in wp and "rm -rf /var/lib/apt/lists/*" in wp,
        "apt-get upgrade -y" in node and "rm -rf /var/lib/apt/lists/*" in node, "RUN apk upgrade --no-cache\n" in cli),
       (True, True, True))
    eq("Containerfiles: wp-cli's upgrades as root and then runs as upstream's www-data again (82:82, numeric)",
       [ln for ln in cli.splitlines() if ln.startswith(("USER", "RUN"))],
       ["USER 0:0", "RUN apk upgrade --no-cache", "USER 82:82"])
    eq("Containerfiles: Node.js's installs npm at the catalog's exact version (no default: npm@ alone is the "
       "newest), cleans npm's cache and fails the build when another npm runs",
       ('"npm@${NPM_VERSION}"' in node, "ARG NPM_VERSION\n" in node, "npm cache clean --force" in node,
        'test "$(npm --version)" = "${NPM_VERSION}"' in node, "ARG NPM_VERSION=" in node), (True, True, True, True, False))
    final = cfd[cfd.rindex("\nFROM "):]
    eq("Containerfiles: the tunnel connector is cloudflared alone on an empty image (no shell, no package manager, "
       "no distribution library), with the certificate authorities, as user 65532, its entry point unchanged",
       (final.splitlines()[1], "RUN " in final, "USER 65532:65532" in final,
        'ENTRYPOINT ["/usr/local/bin/cloudflared"]' in final,
        "COPY --from=cloudflared /usr/local/bin/cloudflared /usr/local/bin/cloudflared" in final,
        "/out/etc/ssl/certs" in cfd),
       ("FROM scratch", False, True, True, True, True))
    eq("Containerfiles: every value comes from the catalog (no ARG has a default)",
       {f: _AI310.defaulted_args(_cf310(f)) for f in ("wordpress", "wpcli", "node", "cloudflared")},
       {f: [] for f in ("wordpress", "wpcli", "node", "cloudflared")})


# ── 3. the add-ons' Podman version read ───────────────────────────────────────────────────────────────
# A stand-in podman: records the XDG_RUNTIME_DIR it got and whether that folder existed; with no usable one it
# makes rootless Podman's fallback folders in $TMPDIR, as Podman 4.9 and 5 do in /tmp.
_PODMAN310 = r'''#!/bin/bash
if [ -n "$XDG_RUNTIME_DIR" ] && [ -d "$XDG_RUNTIME_DIR" ]; then seen=1; else seen=0
  mkdir -p "$TMPDIR/podman-run-$(id -u)" "$TMPDIR/containers-user-$(id -u)"; fi
echo "$XDG_RUNTIME_DIR $seen" >> "$P310_LOG"
[ "$seen" = 1 ] && mkdir -p "$XDG_RUNTIME_DIR/libpod"
echo "podman version 5.4.2"
'''
# A stand-in id: `id -u` answers a uid with no /run/user folder (an account with no user manager).
_ID310 = '#!/bin/bash\n[ "$1" = -u ] && { echo 99931; exit 0; }\nexec /usr/bin/id "$@"\n'


def _status_run310(sh):
    """Run `sh` (an add-on account shell) in bash over a scratch folder: (output, podman's log, $TMPDIR's entries)."""
    base = _tf310.mkdtemp(prefix="p310-podman-")
    try:
        bin_, tmp = os.path.join(base, "bin"), os.path.join(base, "tmp")
        os.makedirs(bin_)
        os.makedirs(tmp)
        for name, text in (("podman", _PODMAN310), ("id", _ID310)):
            with open(os.path.join(bin_, name), "w", encoding="utf-8") as fh:
                fh.write(text)
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
            os.chmod(os.path.join(bin_, name), 0o700)
        env = {"PATH": bin_ + ":/usr/bin:/bin", "TMPDIR": tmp, "P310_LOG": os.path.join(base, "log"), "LC_ALL": "C.UTF-8"}
        out = _sp310.run(["bash", "-c", sh], capture_output=True, text=True, env=env, timeout=60, check=False).stdout
        log = []
        if os.path.exists(env["P310_LOG"]):
            with open(env["P310_LOG"], encoding="utf-8") as fh:
                log = fh.read().split()
        return out, log, sorted(os.listdir(tmp))
    finally:
        _shutil310.rmtree(base, ignore_errors=True)


def _s3_podman_read():
    if not _shutil310.which("bash"):
        check("add-on card (status_sh): SKIP: no bash on this machine", True)
        return
    out, log, left = _status_run310(_ad310.status_sh())
    eq("add-on card (status_sh): an account with no user manager (its add-ons all removed) asks Podman's version in "
       "a runtime folder of its own, removed after it, so rootless Podman makes nothing in /tmp (its fallback "
       "folders came back at every card read, just after the release had removed them)",
       (log[1:] if log else None, bool(log) and log[0].startswith(os.sep) and "/run/user/" not in log[0], left),
       (["1"], True, []))
    eq("add-on card (status_sh): the version still reaches the card's check (control)",
       _ad310.parse_status(out)["podman"], "podman version 5.4.2")
    probe = _ad310.probe_sh("b3", "cod4server", 4, "cod4", 1)
    check("add-on install probe (probe_sh): reads Podman's version the same way",
          _ad310.PODMAN_VERSION_SH in probe and probe.count("podman --version") == 1, probe[:400])


_s1_scope()
_s2_containerfiles()
_s3_podman_read()
