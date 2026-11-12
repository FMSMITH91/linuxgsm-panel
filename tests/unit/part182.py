"""Part 182 of the unit suite: checks that could pass without testing what they claim (review 1112).

Held here:

* the js coverage job skipped a pull request that changed only tools/nosudo_runner.py, the runner
  tools/js_coverage/run.py starts its panel under: every tools/ file run.py starts must keep the job
  running.
* the unit runner's tailscale guard did not read a nested shell glued to a separator
  (`x;bash -c 'sh f'`, `echo|bash -c 'sh f'`): the script file it ran was never read, so a tailscale
  in it was neither shimmed nor judged.

Text only: nothing here runs a shell or reaches a host.
"""
import importlib.util as _ilu182
import os
import re as _re182
import shutil as _shutil182
import tempfile as _tf182

from unit import ts_nested as _tn182
from unit.part01 import _root, check

# ── js coverage: what run.py starts keeps the job running ───────────────────────────────────────
_spec182 = _ilu182.spec_from_file_location("pr_scope182", os.path.join(_root, ".github", "scripts", "pr_scope.py"))
_ps182 = _ilu182.module_from_spec(_spec182)
_spec182.loader.exec_module(_ps182)
with open(os.path.join(_root, "tools", "js_coverage", "run.py"), encoding="utf-8") as _fh182:
    _run182 = _fh182.read()
# os.path.join(tree, "tools", "nosudo_runner.py") -> tools/nosudo_runner.py
_started182 = sorted({"/".join(["tools"] + _re182.findall(r'"([^"]+)"', _m.group(1)))
                      for _m in _re182.finditer(r'os\.path\.join\(tree,\s*"tools",\s*([^)]*)\)', _run182)})
check("pr_scope: every tools/ file js coverage's run.py starts keeps the js coverage job running when it "
      "alone changes (the runner its panel is served under, included)",
      "tools/nosudo_runner.py" in _started182 and "tools/js_coverage/serve.py" in _started182
      and not [_p for _p in _started182 if _ps182.job_skips("js coverage", [_p])],
      repr([(_p, _ps182.job_skips("js coverage", [_p])) for _p in _started182]))
check("pr_scope: ...while another tools/ file still skips it (control)",
      _ps182.job_skips("js coverage", ["tools/i18n_scan.py"]), "")

# ── the unit guard: a nested shell glued to a separator is read ─────────────────────────────────
_tmp182 = _tf182.mkdtemp(prefix="p182-")
try:
    _f182 = os.path.join(_tmp182, "inner-182.sh")
    with open(_f182, "w", encoding="utf-8") as _fh182:
        _fh182.write("tailscale version\n")
    _glued182 = {_s: _tn182.shell_text(["bash", "-c", _s % _f182], {}) for _s in (
        'x;bash -c "sh %s; true"', "x;bash -c 'sh %s'", "echo|bash -c 'sh %s'", "(bash -c 'sh %s')")}
finally:
    _shutil182.rmtree(_tmp182, ignore_errors=True)
check("unit suite guard: a nested shell glued to a separator (x;bash, echo|bash, a subshell) has the script "
      "file its -c script runs read",
      all("tailscale version" in (_t or "") for _t in _glued182.values()),
      repr({_k: (_v or "")[-160:] for _k, _v in _glued182.items()}))
