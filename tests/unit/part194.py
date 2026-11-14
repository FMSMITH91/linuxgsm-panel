"""Part 194 of the unit suite: the Semgrep job's OpenTelemetry packages, pinned apart from semgrep.

semgrep (1.183.0 pinned, 1.185.0 the newest) declares opentelemetry-api, -sdk and
-exporter-otlp-proto-http ~=1.37.0, and every 1.37 api has GHSA-mf5v-w3w3-f6cg (fixed in 1.45.2)
and GHSA-xcq7-p3pf-p88h (fixed in 1.45.1). The family is compiled out of semgrep.txt with
--unsafe-package and pinned in semgrep-otel.txt, as mcp is in semgrep-mcp.txt. Held here:

* semgrep.txt pins no opentelemetry package, and leaves out by name every one semgrep pulls in
  (semgrep.in's documented command names the same set);
* semgrep-otel.txt pins a fixed, matching family (api 1.45.2 or newer, the 1.x packages at one
  version, the 0.x betas at one version), hash-checked, constrained by semgrep.txt and pinning
  nothing else at another version; no CI lockfile pins a vulnerable api;
* the job's pip-check step, run as the runner runs it over the real lockfiles: it passes the report
  measured in python:3.11-slim (part27), and fails, naming semgrep-otel.in, when semgrep stops
  pinning one of the three or pins another version, and on any otel package at another version or
  missing.

HOW IT RUNS. Files and the workflow read as text; the pip-check step runs in bash with `python`
replaced by a stub that prints the given report (part27's runner). Nothing is installed.
"""
import os as _os194
import re as _re194

from unit.part01 import _root, check
from unit.part27 import _SG_PIN27, _read27, _sg_p27, _sg_pins27, _sg_pipcheck27

_DIR194 = (".github", "ci-requirements")
_SGT194 = _read27(*_DIR194, "semgrep.txt")
_SGI194 = _read27(*_DIR194, "semgrep.in")
_OTT194 = _read27(*_DIR194, "semgrep-otel.txt")
_OTI194 = _read27(*_DIR194, "semgrep-otel.in")
_ot194 = _sg_pins27(_OTT194)
# What semgrep itself declares (its PyPI metadata, 1.179.0 through 1.185.0), and what those pull in
# from the 1.37 family: every one of them must be left out of semgrep.txt.
_DIRECT194 = ("opentelemetry-api", "opentelemetry-sdk", "opentelemetry-exporter-otlp-proto-http",
              "opentelemetry-instrumentation-requests", "opentelemetry-instrumentation-threading")
_PULLED194 = ("opentelemetry-exporter-otlp-proto-common", "opentelemetry-instrumentation",
              "opentelemetry-proto", "opentelemetry-semantic-conventions", "opentelemetry-util-http")
_FAMILY194 = set(_DIRECT194 + _PULLED194)


def _unsafe194(text):
    """Every --unsafe-package name the text's non-blank lines give, lower-cased."""
    return {_m.lower() for _m in _re194.findall(r"--unsafe-package=([A-Za-z0-9._-]+)", text)}


def _header194(text):
    """The pip-compile command line in a lockfile's header."""
    _m = _re194.search(r"^#    pip-compile .*$", text, _re194.M)
    return _m.group(0) if _m else ""


_hdr194 = _header194(_SGT194)
_left194 = sorted(_n for _n in _sg_p27 if _n.startswith("opentelemetry"))
check("semgrep otel: semgrep.txt pins no opentelemetry package and leaves out by name every one "
      "semgrep pulls in, and semgrep.in's command names the same set",
      not _left194 and "semgrep" in _sg_p27 and "--allow-unsafe" not in _hdr194
      and {_n for _n in _unsafe194(_hdr194) if _n.startswith("opentelemetry")} == _FAMILY194
      and _unsafe194(_SGI194) == _unsafe194(_hdr194),
      repr((_left194, sorted(_unsafe194(_hdr194) ^ _unsafe194(_SGI194)))))


def _ver194(text):
    """A version's leading numbers, as a tuple ('1.45.2' -> (1, 45, 2); '0.66b2' -> (0, 66, 2))."""
    return tuple(int(_x) for _x in _re194.findall(r"\d+", text or "0"))


_core194 = {_n: _v for _n, _v in _ot194.items()
            if _n.startswith("opentelemetry") and not _re194.search(r"[a-z]", _v)}
_beta194 = {_n: _v for _n, _v in _ot194.items()
            if _n.startswith("opentelemetry") and _re194.search(r"[a-z]", _v)}
_unhashed194 = [_n for _n in _ot194 if not _re194.search(
    r"^%s==\S+ \\\n    --hash=sha256:[0-9a-f]{64}" % _re194.escape(_n), _OTT194, _re194.M | _re194.I)]
check("semgrep otel: semgrep-otel.txt pins the whole family, api 1.45.2 or newer (GHSA-mf5v-w3w3-f6cg), "
      "the 1.x packages at one version and the betas at one version, each with hashes",
      _FAMILY194 <= set(_ot194) and _ver194(_ot194.get("opentelemetry-api")) >= (1, 45, 2)
      and len(set(_core194.values())) == 1 and len(set(_beta194.values())) == 1
      and not _unhashed194,
      repr((sorted(_FAMILY194 - set(_ot194)), _core194, _beta194, _unhashed194)))
_drift194 = sorted(_n for _n, _v in _ot194.items()
                   if not _n.startswith("opentelemetry") and _sg_p27.get(_n) != _v)
check("semgrep otel: semgrep-otel.txt is constrained by semgrep.txt and pins nothing else at another "
      "version",
      _re194.search(r"^-c semgrep\.txt$", _OTI194, _re194.M) is not None
      and len(_ot194) > len(_FAMILY194) and not _drift194, repr(_drift194))


def _vulnerable_api194():
    """Each CI lockfile that pins opentelemetry-api below 1.45.2, with the version."""
    _out = []
    for _d in (".github/ci-requirements", ".github/ci-requirements-checks"):
        _p = _os194.path.join(_root, _d)
        for _f in sorted(_x for _x in _os194.listdir(_p) if _x.endswith(".txt")):
            _v = _sg_pins27(_read27(_d, _f)).get("opentelemetry-api")
            if _v and _ver194(_v) < (1, 45, 2):
                _out.append("%s/%s: %s" % (_d, _f, _v))
    return _out


check("semgrep otel: no CI lockfile pins a vulnerable opentelemetry-api (below 1.45.2)",
      not _vulnerable_api194(), repr(_vulnerable_api194()))

# The job's pip check, as part27 measured it, with one thing changed at a time.
_SEM194 = "semgrep %s" % _sg_p27.get("semgrep")
_API194 = "%s has requirement opentelemetry-api~=1.37.0, but you have opentelemetry-api %s.\n" % (
    _SEM194, _ot194.get("opentelemetry-api"))
_SDK194 = "%s has requirement opentelemetry-sdk~=1.37.0, but you have opentelemetry-sdk %s.\n" % (
    _SEM194, _ot194.get("opentelemetry-sdk"))
_pc_ok194 = _sg_pipcheck27(_SG_PIN27)
_pc_nosdk194 = _sg_pipcheck27(_SG_PIN27.replace(_SDK194, ""))
_pc_newer194 = _sg_pipcheck27(_SG_PIN27.replace("opentelemetry-api~=1.37.0", "opentelemetry-api~=1.45.0"))
_pc_older194 = _sg_pipcheck27(_SG_PIN27.replace(_API194, _API194.replace(
    "you have opentelemetry-api %s." % _ot194.get("opentelemetry-api"), "you have opentelemetry-api 1.37.0.")))
_pc_gone194 = _sg_pipcheck27(_SG_PIN27.replace(
    _API194, "%s requires opentelemetry-api, which is not installed.\n" % _SEM194))
_pc_beta194 = _sg_pipcheck27(_SG_PIN27 + "opentelemetry-sdk %s has requirement "
                             "opentelemetry-semantic-conventions==%s, but you have "
                             "opentelemetry-semantic-conventions 0.58b0.\n"
                             % (_ot194.get("opentelemetry-sdk"),
                                _ot194.get("opentelemetry-semantic-conventions")))
check("semgrep otel: the pip-check step passes semgrep's three opentelemetry pins as semgrep-otel.in "
      "records them, against what semgrep-otel.txt installs",
      _pc_ok194[0] == 0 and _API194 in _SG_PIN27 and _SDK194 in _SG_PIN27, repr(_pc_ok194))


def _err194(result):
    """What the step printed after its ::error:: line, or '' when it printed none."""
    return result[1].split("::error::", 1)[1] if "::error::" in result[1] else ""


check("semgrep otel: ...and fails, naming semgrep-otel.in, when semgrep stops pinning one of them or "
      "pins another version",
      all(_r[0] not in (0, 99) for _r in (_pc_nosdk194, _pc_newer194))
      and "no longer reports semgrep pinning opentelemetry-sdk as semgrep-otel.in records" in _err194(
          _pc_nosdk194)
      and "no longer reports semgrep pinning opentelemetry-api as semgrep-otel.in records" in _err194(
          _pc_newer194)
      and "opentelemetry-api~=1.45.0" in _err194(_pc_newer194),
      repr((_pc_nosdk194, _pc_newer194)))
check("semgrep otel: ...and on the api at another version, the api missing, or a beta out of step, "
      "naming it",
      all(_r[0] not in (0, 99) for _r in (_pc_older194, _pc_gone194, _pc_beta194))
      and "you have opentelemetry-api 1.37.0" in _err194(_pc_older194)
      and "requires opentelemetry-api, which" in _err194(_pc_gone194)
      and "opentelemetry-semantic-conventions 0.58b0" in _err194(_pc_beta194),
      repr((_pc_older194, _pc_gone194, _pc_beta194)))
