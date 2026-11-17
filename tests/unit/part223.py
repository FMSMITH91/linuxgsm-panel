"""Part 223 of the unit suite: CI/CD hardening, the new fuzz targets, the release SBOM and the threat model.

* Workflow tokens (OWASP Top 10 CI/CD Security Risks, CICD-SEC-5): every workflow starts with
  `permissions: {}` and every job states its own; no `pull_request_target`, and no secret but the job
  token in a workflow a pull request runs (CICD-SEC-4, CICD-SEC-6).
* Harden-Runner egress (CICD-SEC-7): exactly the jobs listed here run in block mode, each with an
  allow-list drawn from the hosts below; every other job says why it audits.
* Fuzzing: every harness is in fuzz.yml's matrix with seeds; the three new ones (db_data, push,
  upload_scan) run on their seeds and on generated inputs through a stand-in Atheris with nothing
  found, and each finds the break it exists for when the code it guards is broken.
* tools/sbom.py writes CycloneDX 1.6 for the lockfiles, and sign-release.sh attaches it to the
  release it publishes (the whole script, on a local repository with a stand-in GitHub CLI).
* docs/THREAT-MODEL.md answers the OWASP cheat sheet's four questions, covers the eight trust
  boundaries, and every file it points at exists; SECURITY.md links to it.

Nothing here touches the network or the checkout's data/.
"""
import glob as _glob223
import json as _json223
import os
import re as _re223
import shlex as _shlex223
import shutil as _shutil223
import subprocess as _sp223  # nosec B404 - runs python and bash on this part's own scratch files
import sys as _sys223
import tempfile as _tf223

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part29 import _code29, _job29, _jobs29, _wf29

_WF223 = os.path.join(_root, ".github", "workflows")
_FILES223 = sorted(os.path.basename(p) for p in _glob223.glob(os.path.join(_WF223, "*.yml")))
_SB223 = _tf223.mkdtemp(prefix="p223-")

# ── 1. tokens: none by default, each job its own ────────────────────────────────────────────────


def _perm_bad223(name, text):
    """What is wrong with one workflow's permissions: a top-level grant, or a job with none of its own."""
    bad = []
    top = _re223.findall(r"^permissions:(.*)$", text, _re223.M)
    if top != [" {}"]:
        bad.append("%s: top-level permissions %r" % (name, top))
    for job in _jobs29(text):
        jt = _job29(text, job)
        if not _re223.search(r"^    uses: ", jt, _re223.M) and "\n    permissions:" not in jt:
            bad.append("%s/%s: no permissions of its own" % (name, job))
    return bad


_perm_all223 = [b for f in _FILES223 for b in _perm_bad223(f, _wf29(f))]
_perm_ctl223 = (_perm_bad223("x", "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    permissions:\n"
                                  "      contents: read\n    steps:\n")
                + _perm_bad223("y", "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n"))
check("CI tokens: every workflow starts with permissions: {} and every job states its own (a top-level "
      "grant and a job without a block are both named)",
      not _perm_all223 and len(_FILES223) >= 22 and len(_perm_ctl223) == 2, repr((_perm_all223, _perm_ctl223)))


def _pr_secret_bad223(name, text):
    """A pull_request_target trigger, or a secret other than the job token in a workflow PRs run."""
    code = _code29(text)
    on = code[:code.find("\npermissions:")]
    bad = ["%s: pull_request_target" % name] if "pull_request_target" in on else []
    if _re223.search(r"^  pull_request:", on, _re223.M):
        bad += ["%s: %s" % (name, s) for s in sorted(set(_re223.findall(r"secrets\.([A-Z0-9_]+)", code)))
                if s != "GITHUB_TOKEN"]
    return bad


_sec_all223 = [b for f in _FILES223 for b in _pr_secret_bad223(f, _wf29(f))]
_sec_ctl223 = _pr_secret_bad223("x", "on:\n  pull_request:\npermissions: {}\njobs:\n  a:\n    env:\n"
                                     "      T: ${{ secrets.SONAR_TOKEN }}\n")
check("CI secrets: no workflow runs on pull_request_target, and none a pull request runs reads a secret "
      "but the job token (a stand-in that does is named)",
      not _sec_all223 and _sec_ctl223 == ["x: SONAR_TOKEN"], repr((_sec_all223, _sec_ctl223)))

# ── 2. Harden-Runner: which jobs block, and the hosts they may reach ─────────────────────────────
# Read from each job's own Harden-Runner log over four or more runs of every event it runs on: the
# hosts it called beyond the GitHub Actions service names the agent allows by itself.
_HOSTS223 = {"github.com:443", "api.github.com:443", "uploads.github.com:443", "objects.githubusercontent.com:443",
             "release-assets.githubusercontent.com:443", "pypi.org:443", "files.pythonhosted.org:443",
             "registry.npmjs.org:443", "api.osv.dev:443", "semgrep.dev:443", "sonarcloud.io:443"}
_BLOCK223 = {("actionlint.yml", "actionlint"), ("ci.yml", "gamedig-lockfile"), ("ci.yml", "coverage"),
             ("ci.yml", "js-coverage"), ("codeql.yml", "analyze"),
             ("codeql.yml", "pr-alerts"), ("complexity.yml", "complexity"),
             ("dependency-review.yml", "dependency-review"), ("fuzz.yml", "fuzz"),
             ("security-code.yml", "dependency-audit"), ("security-code.yml", "sast-bandit"),
             ("security-code.yml", "sast-semgrep"), ("security.yml", "secret-scan"),
             ("sonar-new-issues.yml", "sonar-new-issues"), ("zizmor.yml", "zizmor"), ("zizmor.yml", "upload")}
_MAIN_ONLY223 = "runs only on main (a push, a schedule or workflow_run), so no pull request can show a block list " \
                "is complete before it holds every panel's update"
_AUDIT223 = {
    ("ci.yml", "checks"): "the suites dial TEST-NET addresses on purpose, and apt's mirror host varies by region",
    ("lighthouse.yml", "lighthouse"): "Chrome's own calls and the page's fetches change the score it measures",
    ("cflite_pr.yml", "code-change"): "ClusterFuzzLite builds and fuzzes inside Docker images it pulls by tag",
    ("cflite_batch.yml", "batch"): _MAIN_ONLY223, ("cflite_build.yml", "build"): _MAIN_ONLY223,
    ("cflite_cron.yml", "prune"): _MAIN_ONLY223, ("cflite_cron.yml", "coverage"): _MAIN_ONLY223,
    ("cflite_cleanup.yml", "cleanup"): _MAIN_ONLY223, ("codacy-alerts.yml", "open-errors"): _MAIN_ONLY223,
    ("codacy-coverage.yml", "upload"): _MAIN_ONLY223, ("codeql-alerts.yml", "open-alerts"): _MAIN_ONLY223,
    ("scorecard.yml", "analysis"): _MAIN_ONLY223, ("sonar-main-issues.yml", "sonar-main-issues"): _MAIN_ONLY223,
    ("deploy.yml", "deploy"): "carries no Harden-Runner at all (part42)",
}


def _egress223(job_text):
    """("block", [hosts]) or ("audit", []) or (None, []) for a job's Harden-Runner step."""
    m = _re223.search(r"egress-policy: (audit|block)\n((?:          allowed-endpoints: >\n)?(?:            \S+\n)*)",
                      job_text)
    if not m:
        return None, []
    return m.group(1), _re223.findall(r"^            (\S+)$", m.group(2), _re223.M)


def _egress_bad223():
    bad, seen = [], set()
    for f in _FILES223:
        text = _wf29(f)
        for job in _jobs29(text):
            mode, hosts = _egress223(_job29(text, job))
            seen.add((f, job))
            if mode == "block":
                bad += ["%s/%s: blocks but is not listed" % (f, job)] * ((f, job) not in _BLOCK223)
                bad += ["%s/%s: may reach %s" % (f, job, h) for h in hosts if h not in _HOSTS223]
                bad += ["%s/%s: no GitHub" % (f, job)] * (not {"github.com:443", "api.github.com:443"} <= set(hosts))
            elif (f, job) in _BLOCK223 or (f, job) not in _AUDIT223:
                bad.append("%s/%s: audits (%s) without a reason here" % (f, job, mode))
    return bad, seen


_eg_bad223, _eg_seen223 = _egress_bad223()
check("harden-runner: exactly the listed pull-request jobs run in block mode, each allowed GitHub and only "
      "hosts from the list; every other job is named with why it audits",
      not _eg_bad223 and _BLOCK223 | set(_AUDIT223) == _eg_seen223 and not _BLOCK223 & set(_AUDIT223),
      repr((_eg_bad223, sorted(_eg_seen223 - _BLOCK223 - set(_AUDIT223)), sorted((_BLOCK223 | set(_AUDIT223))
                                                                               - _eg_seen223))))

# ── 3. fuzzing: every harness in the matrix, with seeds ─────────────────────────────────────────
_FZ223 = os.path.join(_root, "tests", "fuzz")
_targets223 = sorted(os.path.basename(p)[5:-3] for p in _glob223.glob(os.path.join(_FZ223, "fuzz_*.py")))
_mx223 = _re223.search(r"^        target: \[ ([a-z0-9_, ]+) \]$", _code29(_wf29("fuzz.yml")), _re223.M)
_matrix223 = sorted(t.strip() for t in _mx223.group(1).split(",")) if _mx223 else []
_seedless223 = [t for t in _targets223 if not _glob223.glob(os.path.join(_FZ223, "corpus", t, "*"))]
check("fuzz: every harness in tests/fuzz is a target of fuzz.yml's matrix (and the matrix names no other), "
      "each with seeds; db_data, push and upload_scan among them",
      _targets223 == _matrix223 and not _seedless223 and {"db_data", "push", "upload_scan"} <= set(_targets223),
      repr((_targets223, _matrix223, _seedless223)))

# A stand-in for Atheris: its FuzzedDataProvider calls, read from the bytes in order, and no-op setup.
# CI's unit jobs do not install Atheris, and the harnesses' checks are what is under test here.
_STUB223 = '''import contextlib
class FuzzedDataProvider:
    def __init__(self, data):
        self._d, self._i = bytes(data), 0
    def remaining_bytes(self):
        return len(self._d) - self._i
    def _take(self, n):
        b = self._d[self._i:self._i + max(0, n)]
        self._i += len(b)
        return b
    def ConsumeBytes(self, n):
        return self._take(n)
    def ConsumeIntInRange(self, lo, hi):
        if hi <= lo:
            return lo
        nb = ((hi - lo).bit_length() + 7) // 8
        return lo + int.from_bytes(self._take(nb).ljust(nb, b"\\0"), "big") % (hi - lo + 1)
    def ConsumeBool(self):
        return self.ConsumeIntInRange(0, 1) == 1
    def ConsumeUnicodeNoSurrogates(self, n):
        return "".join(chr(c) for c in self._take(n))
    def PickValueInList(self, values):
        return values[self.ConsumeIntInRange(0, len(values) - 1)]
def instrument_imports():
    return contextlib.nullcontext()
def Setup(*args, **kwargs):
    return None
def Fuzz():
    return None
'''
# Each harness on its seeds and 300 generated inputs (found must be 0), then once per break: the code it
# guards replaced by a broken one, and generated inputs until its check fires (found must be True).
_DRIVE223 = r'''import glob, importlib.util, json, os, random, sys
root, out = sys.argv[1], {}
def load(name):
    spec = importlib.util.spec_from_file_location("h_" + name, os.path.join(root, "tests", "fuzz", "fuzz_%s.py" % name))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
def inputs(name, n):
    seeds = [open(p, "rb").read() for p in sorted(glob.glob(os.path.join(root, "tests", "fuzz", "corpus", name, "*")))]
    rng = random.Random(223)
    return seeds + [bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 400))) for _ in range(n)]
def found(mod, name, n):
    for data in inputs(name, n):
        try:
            mod.TestOneInput(data)
        except AssertionError:
            return True
    return False
BREAKS = {
    "db_data": [("mask", lambda m: setattr(m._dd, "mask_literals", lambda t, limit=300: t[:limit])),
                ("kind", lambda m: setattr(m._dd, "sql_kind", lambda t: ("read", "select")))],
    "push": [("address", lambda m: setattr(m.webpush, "address_refused", lambda ip: False)),
             ("endpoint", lambda m: setattr(m.webpush, "parse_endpoint",
                                            lambda u: ("evil.com", "/", "fcm") if isinstance(u, str) else None))],
    "upload_scan": [("scan", lambda m: setattr(m.db_upload_scan, "SCAN_AWK", 'END { print "SCANNED" }'))],
}
for name, breaks in BREAKS.items():
    mod = load(name)
    try:
        out[name] = {"clean": not found(mod, name, 300)}
    except Exception as e:
        out[name] = {"clean": False, "error": repr(e)[:300]}
    for label, brk in breaks:
        mod = load(name)
        brk(mod)
        out[name][label] = found(mod, name, 600)
print(json.dumps(out))
'''


def _drive223():
    stub = os.path.join(_SB223, "stub")
    os.makedirs(stub, exist_ok=True)
    with open(os.path.join(stub, "atheris.py"), "w", encoding="utf-8") as fh:
        fh.write(_STUB223)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([stub, _root]), EVENTLET_NO_GREENDNS="yes")
    r = _sp223.run([_sys223.executable, "-W", "ignore", "-c", _DRIVE223, _root], capture_output=True, text=True,
                   cwd=_SB223, env=env, timeout=600, check=False)  # nosec B603 - fixed argv
    try:
        return _json223.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": r.stdout[-300:] + r.stderr[-900:]}


_dr223 = _drive223()
_want223 = {"db_data": {"clean": True, "mask": True, "kind": True},
            "push": {"clean": True, "address": True, "endpoint": True},
            "upload_scan": {"clean": True, "scan": True}}
check("fuzz: the db_data, push and upload_scan harnesses find nothing on their seeds and generated inputs, "
      "and each finds its break (masking that leaks, SQL called read, an internal address allowed, a "
      "foreign endpoint accepted, a scan that refuses nothing)",
      _dr223 == _want223, repr(_dr223))

# ── 4. the SBOM ─────────────────────────────────────────────────────────────────────────────────
_SBOM_TOOL223 = os.path.join(_root, "tools", "sbom.py")


def _read223(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _sbom223(stdin, sha="a" * 40):
    r = _sp223.run([_sys223.executable, _SBOM_TOOL223, sha, "2026.11.16", "2026-11-16T00:00:00Z"], input=stdin,
                   capture_output=True, text=True, timeout=60, check=False)  # nosec B603 - fixed argv
    return r.returncode, r.stdout


_lock223 = _read223("panel", "install", "requirements.txt")
_in223 = _read223("panel", "install", "requirements.in")
_npm223 = _read223("tools", "gamedig", "package-lock.json")
_rc223, _out223 = _sbom223(_lock223 + "\0" + _in223 + "\0" + _npm223)
_rc2_223, _out2_223 = _sbom223(_lock223 + "\0" + _in223 + "\0" + _npm223)
try:
    _doc223 = _json223.loads(_out223)
except ValueError:
    _doc223 = {}


def _py_missing223(comps):
    """The packages requirements.txt pins that are not components with exactly their hashes."""
    bad = []
    for name, ver, hashes in _re223.findall(r"^([a-z0-9][a-z0-9._-]*)==(\S+) \\\n((?:    --hash=sha256:[0-9a-f]{64}.*\n)+)",
                                           _lock223, _re223.M):
        c = comps.get("pkg:pypi/%s@%s" % (name, ver)) or {}
        got = {h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"}
        bad += [name] * (got != set(_re223.findall(r"sha256:([0-9a-f]{64})", hashes)))
    return bad


def _npm_missing223(comps):
    """The packages of gamedig's lockfile (not dev) with no npm component of their name."""
    have = {c.get("name") for c in comps.values() if c.get("purl", "").startswith("pkg:npm/")}
    paths = [k for k, v in _json223.loads(_npm223)["packages"].items() if k and not v.get("dev")]
    return [k for k in paths if k.rsplit("node_modules/", 1)[-1] not in have]


def _deps_bad223(doc):
    """The root's dependsOn when it lacks gamedig or flask."""
    deps = (doc.get("dependencies") or [{}])[0].get("dependsOn", [])
    ok = "pkg:npm/gamedig@5.3.3" in deps and any(d.startswith("pkg:pypi/flask@") for d in deps)
    return [] if ok else ["dependsOn %r" % deps[:4]]


def _sbom_bad223(doc):
    """What the SBOM misses of the lockfiles: a pinned package, one of its hashes, or a direct dependency."""
    comps = {c.get("purl"): c for c in doc.get("components", [])}
    return _py_missing223(comps) + _npm_missing223(comps) + _deps_bad223(doc)


_meta223 = _doc223.get("metadata", {}).get("component", {})
check("SBOM: tools/sbom.py writes CycloneDX 1.6 with every package requirements.txt pins (each with all its "
      "hashes) and every npm package of gamedig, the panel depending on what requirements.in and package.json "
      "name; the same bytes on a second run, the serial from the commit",
      _rc223 == 0 and _doc223.get("bomFormat") == "CycloneDX" and _doc223.get("specVersion") == "1.6"
      and _out223 == _out2_223 and not _sbom_bad223(_doc223) and len(_doc223.get("components", [])) >= 60
      and _meta223.get("purl") == "pkg:github/FMSMITH91/linuxgsm-panel@" + "a" * 40
      and _re223.fullmatch(r"urn:uuid:[0-9a-f-]{36}", _doc223.get("serialNumber", "")) is not None,
      repr((_rc223, _sbom_bad223(_doc223)[:5], _out223[:200])))
_rc_e223, _ = _sbom223("\0\0")
_rc_a223, _ = _sbom223(_lock223, sha="nothex")
check("SBOM: no package in the lockfiles is an error (exit 1), and a bad commit id is refused (exit 2)",
      (_rc_e223, _rc_a223) == (1, 2), repr((_rc_e223, _rc_a223)))

# ── 5. sign-release.sh attaches the SBOM to the release ─────────────────────────────────────────
_FAKEGH223 = r"""
printf '%s\n' "$*" >> "$FAKEGH_LOG"
if [ "$1" = release ] && [ "$2" = view ]; then exit 1; fi
if [ "$1" = release ] && [ "$2" = create ]; then
    for a in "$@"; do
        case "$a" in *.cdx.json) echo "SBOM: $(basename "$a") $(python3 "$FAKEGH_READ" "$a")";; esac
    done >> "$FAKEGH_LOG"
fi
exit 0
"""


# Fixed absolute paths (Bandit B607 refuses a bare name; Semgrep refuses one read from PATH): where
# Ubuntu (CI) and the other supported systems install them.
_GIT223 = "/usr/bin/git"
_BASH223 = "/bin/bash"


def _git223(*a, cwd=None):
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    return _sp223.run([_GIT223, *a], cwd=cwd, env=env, capture_output=True, text=True, check=False)  # nosec B603


def _release_repo223():
    """A bare main and a clone holding the release key, a changelog and the three lockfiles: (clone, key, sha)."""
    bare, dev, key = (os.path.join(_SB223, n) for n in ("rel.git", "dev", "relkey"))
    _git223("init", "-q", "--bare", "-b", "main", bare)
    _git223("clone", "-q", bare, dev)
    _sp223.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key], check=False,
               capture_output=True)  # nosec B603 B607
    files = {"panel/install/release-signers": "release " + " ".join(open(key + ".pub").read().split()[:2]) + "\n",
             "docs/CHANGELOG.md": "# Changelog\n\n## [Since 0.10.0-alpha]\n\n### Added\n\n- **New thing.** It works.\n",
             "panel/install/requirements.txt": _lock223, "panel/install/requirements.in": _in223,
             "tools/gamedig/package-lock.json": _npm223, "panel/x.py": "X = 1\n"}
    for rel, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(dev, rel)), exist_ok=True)
        with open(os.path.join(dev, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    # The signatures branch's commit is signed (git commit-tree -S), here with the release key.
    _git223("config", "gpg.format", "ssh", cwd=dev)
    _git223("config", "user.signingkey", key + ".pub", cwd=dev)
    _git223("add", ".", cwd=dev)
    _git223("-c", "commit.gpgsign=false", "commit", "-q", "-m", "first", cwd=dev)
    _git223("push", "-q", "origin", "main", cwd=dev)
    return dev, key, _git223("rev-parse", "HEAD", cwd=dev).stdout.strip()


# What the stand-in prints of an attached SBOM: its component count and the release it names.
_READ223 = "import json, sys\nd = json.load(open(sys.argv[1]))\nprint(len(d['components']), d['metadata']['component']['version'])\n"

if _shutil223.which("ssh-keygen") and _shutil223.which("git"):
    _dev223, _key223, _sha223 = _release_repo223()
    _gh223, _log223 = os.path.join(_SB223, "fakegh.sh"), os.path.join(_SB223, "gh.log")
    with open(_gh223, "w", encoding="utf-8") as _fh223:
        _fh223.write(_FAKEGH223)
    with open(os.path.join(_SB223, "read_sbom.py"), "w", encoding="utf-8") as _fh223:
        _fh223.write(_READ223)
    _env223 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", SIGN_RELEASE_KEY=_key223,
                   FAKEGH_LOG=_log223, FAKEGH_READ=os.path.join(_SB223, "read_sbom.py"),
                   SIGN_RELEASE_GH="bash %s" % _shlex223.quote(_gh223), GIT_AUTHOR_NAME="t",
                   GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    _r223 = _sp223.run([_BASH223, os.path.join(_root, "tools", "sign-release.sh"), "--yes", _sha223], cwd=_dev223,
                       env=_env223, input="", capture_output=True, text=True, timeout=300, check=False)  # nosec B603
    _ghlog223 = open(_log223, encoding="utf-8").read() if os.path.exists(_log223) else ""
    _sbom_line223 = _re223.search(r"^SBOM: linuxgsm-panel-(\S+)\.cdx\.json (\d+) (\S+)$", _ghlog223, _re223.M)
    check("sign-release.sh: the release it publishes carries the commit's SBOM beside the signature, named "
          "after the tag, with every package of the commit's lockfiles",
          _r223.returncode == 0 and _sbom_line223 is not None and _sbom_line223.group(1) == _sbom_line223.group(3)
          and int(_sbom_line223.group(2)) == len(_doc223.get("components", [])) and ".sig" in _ghlog223,
          "rc=%s %s | %s" % (_r223.returncode, _r223.stderr[-400:], _ghlog223[-500:]))
else:
    skip("sign-release.sh: the release carries the SBOM", "git or ssh-keygen is not installed")

# ── 6. the threat model ─────────────────────────────────────────────────────────────────────────
_tm223 = _read223("docs", "THREAT-MODEL.md")
_ptr223 = sorted({p for p in _re223.findall(r"`((?:panel|tools|tests|docs|\.github)/[A-Za-z0-9_./-]+)`", _tm223)})
_missing223 = [p for p in _ptr223 if not os.path.exists(os.path.join(_root, p.rstrip("/")))]
check("threat model: docs/THREAT-MODEL.md answers the four questions, covers TB1-TB8 with STRIDE tables, says "
      "the response to each residual risk, and every file it points at exists; SECURITY.md links to it",
      all(q in _tm223 for q in ("What are we working on?", "What can go wrong?", "What are we going to do about it?",
                                "Did we do a good enough job?"))
      and all("### TB%d:" % i in _tm223 for i in range(1, 9)) and _tm223.count("| STRIDE |") == 8
      and "## Residual risks" in _tm223 and len(_ptr223) >= 25 and not _missing223
      and "](../docs/THREAT-MODEL.md)" in _read223(".github", "SECURITY.md"),
      repr((_missing223, len(_ptr223))))

_shutil223.rmtree(_SB223, ignore_errors=True)
