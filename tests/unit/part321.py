"""Part 321 of the unit suite: CI's apt step.

1. CI: the unit legs' apt step takes the runner image's own packages.microsoft.com source out of apt's list before
   `apt-get update` (that repository answered 403 and failed the whole leg), and only that source; the step's own
   loop is run over a scratch sources folder.

HOW IT RUNS. The workflow is read as text (part06's run-block reader); the step's loop runs in bash over a
scratch folder.
"""
import os
import shutil as _shutil321
import subprocess as _sp321  # nosec B404 - bash over the workflow's own loop, in a scratch folder
import tempfile as _tf321

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block


# ── 1. CI: apt without the runner image's Microsoft source ────────────────────────────────────────
_APT_STEP321 = "Install zsh and systemd-journal-remote"


def _apt_body321():
    with open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8") as fh:
        return _wf_run_block(fh.read(), _APT_STEP321)


def _apt_loop321(body):
    """The step's lines from its `for src in` loop to its `done`, or "" when it has none."""
    lines = body.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("for src in /etc/apt/sources.list.d/")), None)
    if start is None:
        return ""
    end = next((i for i in range(start, len(lines)) if lines[i].strip() == "done"), None)
    return "\n".join(lines[start:end + 1]) + "\n" if end is not None else ""


def _s1_ci():
    body = _apt_body321()
    code = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    upd = next((i for i, ln in enumerate(code) if "apt-get update" in ln), -1)
    loop_at = next((i for i, ln in enumerate(code) if ln.startswith("for src in /etc/apt/sources.list.d/")), -1)
    eq("CI (ci.yml, the unit legs' apt step): a loop over apt's source files runs BEFORE `apt-get update`",
       (loop_at >= 0, upd >= 0, 0 <= loop_at < upd), (True, True, True))
    d = _tf321.mkdtemp(prefix="lgsm-unit-p321-apt-")
    try:
        src, aside = os.path.join(d, "sources.list.d"), os.path.join(d, "aside")
        os.makedirs(src)
        os.makedirs(aside)
        files = {"microsoft-prod.list": "deb [arch=amd64,armhf,arm64] https://packages.microsoft.com/ubuntu/24.04/prod "
                                        "noble main\n",
                 "azure-cli.sources": "Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\n",
                 "ubuntu.sources": "Types: deb\nURIs: http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\n",
                 "esm.list": "deb https://esm.ubuntu.com/apps/ubuntu noble-apps-security main\n"}
        for name, text in files.items():
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        loop = _apt_loop321(body).replace("/etc/apt/sources.list.d", src).replace("sudo ", "")
        r = _sp321.run(["bash", "-c", loop], env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": aside},
                       capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607 - bash, fixed
        got = (r.returncode, sorted(os.listdir(src)), sorted(os.listdir(aside)))
    finally:
        _shutil321.rmtree(d, ignore_errors=True)
    eq("CI (the step's own loop, run over a scratch sources folder): every source file naming packages.microsoft.com "
       "(one-line and deb822) is moved out of apt's list; the Ubuntu archive's and Ubuntu Pro's stay (control)",
       got, (0, ["esm.list", "ubuntu.sources"], ["azure-cli.sources", "microsoft-prod.list"]))


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _ran321(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran321.last)."""
    import traceback
    try:
        step(*args)
        _ran321.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _ran321.last = traceback.format_exc()[-1500:]
        return False


_ran321.last = ""
check("part321: _s1_ci ran to the end", _ran321(_s1_ci), _ran321.last)
