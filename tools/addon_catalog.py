r"""Build and check the signed add-on catalog that tools/sign-catalog.sh publishes.

Usage:
  addon_catalog.py build <now, epoch seconds> <auto|refresh>
      Stdin is the commit's panel/addon_images/catalog.json, a NUL byte, then the catalog/latest.json
      already published on release-signatures (nothing after the NUL when none is). Exit 0 prints the
      catalog to publish on stdout and what changed on stderr; exit 3 means nothing is due (the
      published catalog says the same and is more than REFRESH_DAYS from expiring, in auto mode);
      exit 1 refuses, saying why on stderr.
  addon_catalog.py seq
      Stdin is a published catalog; prints its seq.
  addon_catalog.py checks
      Stdin is one check run a line, `name TAB status TAB conclusion`; exit 0 when every check the
      commit must pass has passed, else 1 and why on stderr.

The published catalog is the source object plus `seq` (the previous published seq + 1), `issued` and
`expires` (issued + LIFETIME_DAYS), serialized as json.dumps(obj, indent=2, sort_keys=True) + "\n":
the version number and expiry The Update Framework gives its metadata against rollback and freeze
attacks. Panels refuse a catalog whose seq is not above the last one they accepted, or that expired.
"""
import calendar
import json
import re
import sys
import time

SCHEMA = 1
NAMESPACE = "linuxgsm-panel-addons"
LIFETIME_DAYS = 30
# A published catalog this close to expiring is signed again (new seq, issued, expires) by the next
# signing run, even when nothing in it changed.
REFRESH_DAYS = 10
_DAY = 86400
_TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}\Z")
_FIELDS = {"image": _IMAGE_RE, "base": _IMAGE_RE, "sha256": re.compile(r"[0-9a-f]{64}\Z"),
           "commit": re.compile(r"[0-9a-f]{40}\Z"), "tag": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")}
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}\Z")
_PUBLISHED_KEYS = ("expires", "issued", "seq")

# The checks a commit must have passed before its catalog is signed: the set deploy.yml's verify step
# waits for (a unit check holds the two lists equal). A name ending in "(" is a prefix, for a matrix job.
REQUIRED = ("checks (", "coverage", "js coverage", "gamedig lockfile (", "Analyze (", "Open code-scanning alerts",
            "Secret scanning (Gitleaks)", "Dependency vulnerabilities (pip-audit)")
IGNORED = ("deploy", "Upload coverage to Codacy", "Code-scanning alerts gate", "Scorecard analysis",
           "Scorecard image pin", "Scorecard image pulled", "Dependabot", "update-pip-graph")
_FAILED = ("failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale")



def _whole(value):
    """Whether `value` is an int and not a bool (True and False are ints in Python)."""
    return isinstance(value, int) and not isinstance(value, bool)

def serialize(obj):
    """The exact bytes that are signed and published (and that panels verify)."""
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _entry_problems(name, entry):
    if not _NAME_RE.match(name):
        return ["add-on name %r is not a lowercase name" % name]
    if not isinstance(entry, dict) or not entry:
        return ["%s: not an object of fields" % name]
    return _field_problems(name, entry)


def _field_problems(name, entry):
    out = ["%s.%s: not a field the catalog has" % (name, k) for k in sorted(entry) if k not in _FIELDS]
    out += ["%s.%s: %r is not a full pin of its kind" % (name, k, v) for k, v in sorted(entry.items())
            if k in _FIELDS and not (isinstance(v, str) and _FIELDS[k].match(v))]
    if ("image" in entry) == ("base" in entry):
        out.append("%s: needs exactly one of image (pulled) or base (built)" % name)
    return out


def source_problems(obj):
    """Why `obj` is not a catalog source (schema 1); [] when it is."""
    if not isinstance(obj, dict) or sorted(obj) != ["addons", "schema"]:
        return ["the catalog must hold exactly `schema` and `addons`"]
    out = [] if obj["schema"] == SCHEMA and _whole(obj["schema"]) else ["schema %r is not %d" % (obj["schema"], SCHEMA)]
    addons = obj["addons"]
    if not isinstance(addons, dict) or not addons:
        return out + ["`addons` must be a non-empty object"]
    for name in sorted(addons):
        out += _entry_problems(name, addons[name])
    return out


def _parse_time(text):
    if not isinstance(text, str) or not _TIME_RE.match(text):
        return None
    try:
        return calendar.timegm(time.strptime(text, _TIME_FMT))
    except ValueError:
        return None


def published_problems(obj):
    """Why `obj` is not a published catalog; [] when it is."""
    if not isinstance(obj, dict) or sorted(obj) != ["addons", "expires", "issued", "schema", "seq"]:
        return ["a published catalog holds exactly schema, addons, seq, issued and expires"]
    out = source_problems(core(obj))
    seq = obj["seq"]
    if not _whole(seq) or seq < 1:
        out.append("seq %r is not a positive whole number" % (seq,))
    if _parse_time(obj["issued"]) is None or _parse_time(obj["expires"]) is None:
        out.append("issued and expires must be UTC times as YYYY-MM-DDTHH:MM:SSZ")
    return out


def core(obj):
    """The catalog without what publishing adds."""
    return {k: v for k, v in obj.items() if k not in _PUBLISHED_KEYS}


def changes(before, after):
    """Lines naming each field that differs between two catalog sources."""
    old, new = (before or {}).get("addons") or {}, after["addons"]
    lines = []
    for name in sorted(set(old) | set(new)):
        a, b = old.get(name) or {}, new.get(name) or {}
        lines += ["  %s.%s: %s -> %s" % (name, k, a.get(k, "(none)"), b.get(k, "(none)"))
                  for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    return lines


def _loaded(text, check):
    """(object, "") for JSON text that `check` finds nothing wrong with, else (None, why)."""
    try:
        obj = json.loads(text)
    except ValueError as exc:
        return None, "not JSON (%s)" % exc
    bad = check(obj)
    return (None, "; ".join(bad)) if bad else (obj, "")


def _previous(latest, now):
    """(the published catalog or None when there is none, "" or why it cannot be built on)."""
    if not latest.strip():
        return None, ""
    prev, why = _loaded(latest, published_problems)
    if why:
        return None, "the published catalog/latest.json is not a catalog: " + why
    if now < _parse_time(prev["issued"]):
        return None, "this clock is behind the published catalog's issue time %s" % prev["issued"]
    return prev, ""


def build(source, latest, now, mode):
    """(exit status, catalog text or "", message) for the `build` command."""
    src, why = _loaded(source, source_problems)
    if why:
        return 1, "", "the commit's catalog is refused: " + why
    prev, why = _previous(latest, now)
    if why:
        return 1, "", why
    if prev and mode == "auto" and core(prev) == src and _parse_time(prev["expires"]) - now > REFRESH_DAYS * _DAY:
        return 3, "", "catalog seq %d already says this and expires %s: nothing to publish" % (prev["seq"], prev["expires"])
    out = dict(src, seq=(prev["seq"] + 1) if prev else 1, issued=time.strftime(_TIME_FMT, time.gmtime(now)),
               expires=time.strftime(_TIME_FMT, time.gmtime(now + LIFETIME_DAYS * _DAY)))
    diff = changes(core(prev) if prev else None, src)
    what = "\n".join(diff) if diff else "  (no add-on changes: signed again with a new seq and expiry)"
    return 0, serialize(out), "catalog seq %d, expires %s:\n%s" % (out["seq"], out["expires"], what)


def _runs(lines):
    """[(name, status, conclusion)] of the check runs in `lines` that count (IGNORED left out)."""
    parts = [line.rstrip("\n").split("\t") for line in lines]
    return [tuple(p) for p in parts if len(p) == 3 and p[0] and p[0] not in IGNORED]


def _ran(required, runs):
    """Whether a run that was not skipped answers `required` (a name, or a prefix ending in "(")."""
    return any(c != "skipped" and (n == required or (required.endswith("(") and n.startswith(required)))
               for n, _, c in runs)


def checks_problem(lines):
    """Why the check runs in `lines` do not all pass; "" when they do."""
    runs = _runs(lines)
    found = (("a check failed: ", sorted({n for n, s, c in runs if s == "completed" and c in _FAILED})),
             ("checks still running: ", sorted({n for n, s, _ in runs if s != "completed"})),
             ("checks it must pass have not run: ", [r for r in REQUIRED if not _ran(r, runs)]))
    return next((label + ", ".join(names) for label, names in found if names), "")


def _cmd_build(argv, text):
    if "\0" not in text:
        sys.stderr.write("addon_catalog.py: stdin must be <catalog> NUL <published latest or nothing>\n")
        return 2
    source, latest = text.split("\0", 1)
    rc, out, msg = build(source, latest, int(argv[2]), argv[3])
    sys.stdout.write(out)
    sys.stderr.write(msg + "\n")
    return rc


def _cmd_seq(text):
    obj, why = _loaded(text, published_problems)
    if why:
        sys.stderr.write("addon_catalog.py: not a published catalog: %s\n" % why)
        return 1
    sys.stdout.write("%d\n" % obj["seq"])
    return 0


def _cmd_checks(text):
    why = checks_problem(text.splitlines())
    if why:
        sys.stderr.write(why + "\n")
    return 1 if why else 0


def main(argv, stdin=None):
    """Run one command of the module docstring; its exit status."""
    text = (stdin or sys.stdin.buffer).read().decode("utf-8", "replace")
    if argv[1:2] == ["build"] and len(argv) == 4 and argv[2].isdecimal() and argv[3] in ("auto", "refresh"):
        return _cmd_build(argv, text)
    if argv[1:] == ["seq"]:
        return _cmd_seq(text)
    if argv[1:] == ["checks"]:
        return _cmd_checks(text)
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
