#!/usr/bin/env python3
"""Fail a pull request that makes a function or a file break Codacy's size and complexity limits.

Codacy's pull-request check counts an issue as new only on a line the pull request changed. Its
Lizard issues sit on a function's ``def`` line (complexity, length, parameters) or on line 1 (file
length), and Pylint's reimport sits on the OTHER import's line. So a pull request that grew a
function without touching its ``def`` passed Codacy as "0 new issues", and the issue appeared when
Codacy analysed main: 23 of them by 2026-09-30, from #365 and #374.

This compares the base and the head of every changed .py/.js file (and tools/panel-helper, which is
Python without the extension) with the limits the repository's Codacy coding standard sets:

* Lizard, per function: cyclomatic complexity over 10, more than 50 lines of code (NLOC), more
  than 8 parameters; per file: more than 1700 lines of code.
* Pylint W0404 (reimport), W0612 (unused variable) and W0108 (unnecessary lambda): the three
  Pylint patterns Codacy runs here.
* Prospector, with the repository's .prospector.yaml, on every changed Python file over 150,000
  bytes. Codacy Cloud does not analyse a file over 150 KB at all
  (https://docs.codacy.com/faq/troubleshooting/why-is-my-file-over-150-kb-missing/), so its
  required pull-request check reads nothing in app.py, system_ops.py, hosts.py, _core.py or
  tools/panel-helper and reports "0 new issues" on any change to them. This covers the pull-request
  side for Prospector, one of the tools Codacy would have run there; it does NOT make Codacy analyse
  those files, and Codacy's Opengrep, its wider Pylint set and its ShellCheck still see none of
  them. tools/panel-helper is not Python to Codacy either way: it has no suffix, and .codacy.yaml
  has no `languages:` entry naming it.

A violation the base already had is not new; only what the change adds fails the check, named
with its file and line. Usage:

    complexity_gate.py [BASE]     # BASE: a commit; default the first parent of a merge HEAD,
                                  # else main's merge base with HEAD
    complexity_gate.py --self-test
"""
import collections
import json
import os
import re
import subprocess  # nosec B404 - git and pylint, fixed argv, no shell
import sys
import tempfile

import lizard

CCN_MAX, FN_NLOC_MAX, PARAMS_MAX, FILE_NLOC_MAX = 10, 50, 8, 1700
PYLINT_CODES = ("W0404", "W0612", "W0108")
PYTHON_NAMED = {"tools/panel-helper"}   # Python without the extension; Codacy does not know that
# Codacy Cloud skips a file over 150 KB. 150,000 bytes is the lower of the two readings of "150 KB"
# (150 x 1024 is the other), so nothing the vendor might skip escapes this.
CODACY_MAX_BYTES = 150000
# The Prospector tools Codacy runs by default, which .prospector.yaml's `run:` lines reproduce. A run
# that did not use all of them read less than Codacy would have, and fails (a positive control).
PROSPECTOR_TOOLS = {"dodgy", "mccabe", "pycodestyle", "pydocstyle", "pyflakes"}
# A file of the gate's own, analysed in every Prospector run beside the files judged: its one
# finding must come back, or Prospector did not read the files it was given.
_CANARY = ("zz_complexity_gate_canary.py", "import os\n", ("pyflakes", "F401"))
# What Codacy's Prospector wrapper (codacy/codacy-prospector) drops: D203, the half of the
# D203/D211 pair it does not report (see .prospector.yaml).
CODACY_DROPS = {("pydocstyle", "D203")}
_ON_MAIN = " (Codacy reports this on main, not on the pull request)"


def _git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,  # nosec B603 B607
                          check=False)


def _lang_name(path):
    """The name Lizard picks the language from: tools/panel-helper is Python."""
    return path + ".py" if path in PYTHON_NAMED else path


def lizard_violations(path, code):
    """Return Lizard's violations in one file's text, as [(key, line, message)].

    The key ignores line numbers, so a violation the base had is matched however far it moved.
    """
    info = lizard.analyze_file.analyze_source_code(_lang_name(path), code)
    out = []
    for fn in info.function_list:
        if fn.cyclomatic_complexity > CCN_MAX:
            out.append((("ccn", fn.long_name), fn.start_line,
                        "%s has a cyclomatic complexity of %d (limit is %d)"
                        % (fn.long_name, fn.cyclomatic_complexity, CCN_MAX)))
        if fn.nloc > FN_NLOC_MAX:
            out.append((("nloc", fn.long_name), fn.start_line,
                        "%s has %d lines of code (limit is %d)" % (fn.long_name, fn.nloc, FN_NLOC_MAX)))
        if fn.parameter_count > PARAMS_MAX:
            out.append((("params", fn.long_name), fn.start_line,
                        "%s has %d parameters (limit is %d)"
                        % (fn.long_name, fn.parameter_count, PARAMS_MAX)))
    if info.nloc > FILE_NLOC_MAX:
        out.append((("file-nloc", ""), 1, "the file has %d lines of code (limit is %d)"
                    % (info.nloc, FILE_NLOC_MAX)))
    return out


_PYLINT_LINE = re.compile(r"^[^:]+:(\d+):\d+: (W\d{4}): (.*?)(?: \(([a-z-]+)\))?$")


def pylint_violations(path, code):
    """Return the three Pylint patterns' violations in one file's text, as [(key, line, message)].

    Pylint reads a file, so the text is written to a temporary one of the same name: the base side
    exists only in git.
    """
    if not (path.endswith(".py") or path in PYTHON_NAMED):
        return []
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, os.path.basename(_lang_name(path)))
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(code)
        r = subprocess.run([sys.executable, "-m", "pylint", "--disable=all",  # nosec B603
                            "--enable=" + ",".join(PYLINT_CODES), "--score=n", "--persistent=n",
                            "--msg-template={path}:{line}:{column}: {msg_id}: {msg} ({symbol})", f],
                           capture_output=True, text=True, check=False)
    out = []
    for ln in r.stdout.splitlines():
        m = _PYLINT_LINE.match(ln.strip())
        if m:
            # "(imported line 1749)" names a line too: drop every number from the key.
            out.append(((m.group(2), re.sub(r"\d+", "#", m.group(3))), int(m.group(1)),
                        "%s %s" % (m.group(2), m.group(3))))
    return out


def new_violations(path, base_code, head_code):
    """What the head has that the base does not, counted per key."""
    found = []
    for check in (lizard_violations, pylint_violations):
        before = collections.Counter(k for k, _l, _m in check(path, base_code)) if base_code else {}
        seen = collections.Counter()
        for key, line, msg in check(path, head_code):
            seen[key] += 1
            if seen[key] > before.get(key, 0):
                found.append((line, msg))
    return found


def _blob_size(rev, path, cwd=None):
    """Return the size in bytes of `path` as committed at `rev`, or 0 when it is not there."""
    r = _git("cat-file", "-s", "%s:%s" % (rev, path), cwd=cwd)
    return int(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip().isdigit() else 0


def _renamed_from(base, cwd=None):
    """Map each file the change renamed, head path to base path."""
    out = _git("diff", "--name-status", "-M", "--diff-filter=R", base, "HEAD", cwd=cwd).stdout
    return {f[2]: f[1] for f in (ln.split("\t") for ln in out.splitlines()) if len(f) == 3}


def oversized(base, files, cwd=None):
    """Return the changed Python files Codacy Cloud skips at the head, as [(head path, base path)]."""
    renamed = _renamed_from(base, cwd)
    return [(p, renamed.get(p, p)) for p in files
            if (p.endswith(".py") or p in PYTHON_NAMED)
            and _blob_size("HEAD", p, cwd) > CODACY_MAX_BYTES]


def _prospector_json(root, names):
    """Run Prospector in `root` over `names` and the canary: (messages, None), or (None, why).

    Run as Codacy runs it: from the project root, with no --profile, so .prospector.yaml is found
    the way Codacy's wrapper finds it. Anything short of a full, readable run is a reason, never an
    empty list: a crash, output that is not Prospector's JSON, a run missing one of Codacy's tools
    (the profile was not read), or a canary whose finding did not come back.
    """
    # `names` are paths git listed in a scratch tree this gate wrote; the interpreter is this one and
    # the argv is a list (no shell).
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    r = subprocess.run([sys.executable, "-m", "prospector", "--output-format", "json",  # nosec B603
                        "--zero-exit", *names, _CANARY[0]],
                       cwd=root, capture_output=True, text=True, check=False)
    try:
        out = json.loads(r.stdout)
        tools, msgs = set(out["summary"]["tools"]), list(out["messages"])
    except (ValueError, KeyError, TypeError):
        return None, "Prospector did not run (exit %d): %s" % (
            r.returncode, " ".join((r.stderr or r.stdout).split())[-300:])
    why = ("Prospector exited %d" % r.returncode) if r.returncode != 0 else _untrusted(tools, msgs)
    return (None, why) if why else (msgs, None)


def _is_canary(m):
    """Whether Prospector message `m` is the canary's expected finding."""
    return (((m.get("location") or {}).get("path"), m.get("source"), m.get("code"))
            == (_CANARY[0],) + _CANARY[2])


def _untrusted(tools, msgs):
    """Why a run that exited 0 still cannot be trusted, or None.

    A tool Codacy runs is missing (the profile was not read), the canary's finding did not come
    back, or Prospector reports that a tool failed.
    """
    if not PROSPECTOR_TOOLS <= tools:
        return "Prospector ran without %s, which Codacy runs" % ", ".join(sorted(PROSPECTOR_TOOLS - tools))
    if not any(_is_canary(m) for m in msgs):
        return "Prospector did not report its canary's finding, so it did not read the files it was given"
    failed = [m for m in msgs if m.get("source") == "prospector" or m.get("code") == "failure"]
    if failed:
        return "Prospector could not run %s: %s" % (failed[0].get("source"), failed[0].get("message"))
    return None


def _write_side(root, rev, pairs, profile, cwd=None):
    """Write one side's files into `root`: {name written: (head path, its lines)}.

    `pairs` is [(head path, path at `rev`)]. Each file is written under its HEAD path, so both sides
    are judged under the same name, and tools/panel-helper as a .py file. The profile and the canary
    go in only when there is a file to judge.
    """
    written = {}
    for head_path, path in pairs:
        text = _committed(rev, path, cwd)
        name = _lang_name(head_path)
        if text:
            os.makedirs(os.path.join(root, os.path.dirname(name) or "."), exist_ok=True)
            with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                fh.write(text)
            written[name] = (head_path, text.splitlines())
    for name, text in ((".prospector.yaml", profile), (_CANARY[0], _CANARY[1])):
        if text and written:
            with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                fh.write(text)
    return written


def _prospector_side(rev, pairs, profile, cwd=None):
    """Return Prospector's findings on one side, {(path, source, code): [(line, ident, text)]}.

    Or (None, why) when Prospector could not be read. A finding's ident is its message and the
    source line it names, so the same finding is matched on both sides wherever it moved.
    """
    with tempfile.TemporaryDirectory() as root:
        written = _write_side(root, rev, pairs, profile, cwd)
        if not written:
            return {}, None
        msgs, why = _prospector_json(root, sorted(written))
    if why:
        return None, why
    found = collections.defaultdict(list)
    for m in msgs:
        loc = m.get("location") or {}
        if loc.get("path") not in written or (m.get("source"), m.get("code")) in CODACY_DROPS:
            continue
        head_path, lines = written[loc["path"]]
        line = loc.get("line") or 1
        src = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        found[(head_path, m.get("source"), m.get("code"))].append(
            (line, (m.get("message"), src), m.get("message")))
    return found, None


def _risen(after, before):
    """Return (path, line, message) for each finding whose count rose from `before` to `after`.

    Counted per (file, tool, code), as Codacy counts issues. Which of the head's findings are the
    new ones is told by message and source line; a finding that matches one the base had is named
    only when the count rose by more than the unmatched ones explain.
    """
    out = []
    for (path, source, code), found in sorted(after.items()):
        old = before.get((path, source, code), [])
        rose = len(found) - len(old)
        if rose <= 0:
            continue
        spare = collections.Counter(ident for _l, ident, _t in old)
        fresh, matched = [], []
        for item in found:
            (matched if spare[item[1]] > 0 else fresh).append(item)
            spare[item[1]] -= 1
        out += [(path, line, "Prospector %s %s: %s (%d on the base, %d now; Codacy Cloud skips this "
                 "file, which is over 150 KB, so no Codacy check reports it)"
                 % (source, code, text, len(old), len(found)))
                for line, _ident, text in (fresh + matched)[:rose]]
    return out


def prospector_violations(base, pairs, cwd=None):
    """Return what Prospector finds in the head of `pairs` that it did not find in the base.

    Both sides run under the BASE's .prospector.yaml, so a change cannot quiet its own findings by
    editing the profile. A side that could not be read fails the check, named on the first file.
    """
    if not pairs:
        return []
    profile = _committed(base, ".prospector.yaml", cwd) or _committed("HEAD", ".prospector.yaml", cwd)
    before, why = _prospector_side(base, pairs, profile, cwd)
    after = None
    if not why:
        after, why = _prospector_side("HEAD", [(h, h) for h, _b in pairs], profile, cwd)
    if why:
        return [(pairs[0][0], 1, why)]
    return _risen(after, before)


def _default_base():
    parents = _git("rev-list", "--parents", "-n", "1", "HEAD").stdout.split()
    if len(parents) == 3:          # a pull request's merge commit: its first parent is the base
        return parents[1]
    return _git("merge-base", "HEAD", "origin/main").stdout.strip() or "HEAD~1"


def changed_files(base, cwd=None):
    out = _git("diff", "--name-only", "--diff-filter=AMR", base, "HEAD", cwd=cwd).stdout.split()
    return [p for p in out if p.endswith((".py", ".js")) or p in PYTHON_NAMED]


def _committed(rev, path, cwd=None):
    """Return the text of `path` as committed at `rev`, or "" when it is not there.

    Both sides are read from git, never the working tree: what is judged is what was committed, and
    a symlink is its target's NAME (what git stores), not a file it points at.
    """
    shown = _git("show", "%s:%s" % (rev, path), cwd=cwd)
    return shown.stdout if shown.returncode == 0 else ""


def run(base, cwd=None):
    """Return (problems, files checked, files over 150 KB): each problem is (path, line, message)."""
    problems, files = [], changed_files(base, cwd)
    for path in files:
        head = _committed("HEAD", path, cwd)
        if not head:
            continue
        problems += [(path, line, msg + _ON_MAIN)
                     for line, msg in new_violations(path, _committed(base, path, cwd), head)]
    big = oversized(base, files, cwd)
    return problems + prospector_violations(base, big, cwd), files, big


def _test_commit(d, env, files, msg):
    """Commit `files` ({path: text, or None to delete it}) into the scratch repository `d`.

    Through git's object store and index alone: nothing is written to the working tree, which the
    gate never reads.
    """
    for p, txt in files.items():
        if txt is None:
            subprocess.run(["git", "update-index", "--force-remove", p], cwd=d,  # nosec B603 B607
                           env=env, capture_output=True, check=True)
            continue
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], input=txt, cwd=d,  # nosec B603 B607
                              env=env, capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(["git", "update-index", "--add", "--cacheinfo",  # nosec B603 B607
                        "100644,%s,%s" % (blob, p)], cwd=d, env=env, capture_output=True, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", msg], cwd=d,  # nosec B603 B607
                   env=env, capture_output=True, check=True)


def _size_cases():
    """Return the Lizard and Pylint cases: (base files, head files, whether the head must fail)."""
    simple = "def f(a):\n    return a\n"
    grown = "def f(a):\n" + "".join("    if a == %d:\n        return %d\n" % (i, i) for i in range(12)) \
            + "    return a\n"
    old_bad = "def old(a):\n" + "".join("    if a == %d:\n        a += 1\n" % i for i in range(12)) \
              + "    return a\n"
    return {
        # a function that grew past CCN 10 without its def line changing: Codacy's blind spot
        "grown function fails": ({"m.py": simple}, {"m.py": grown}, True),
        # a violation the base already had, left as it was, is not this change's
        "pre-existing violation passes": ({"m.py": old_bad}, {"m.py": old_bad + "\nX = 1\n"}, False),
        # ...nor when the code above it moves it down
        "moved violation passes": ({"m.py": old_bad}, {"m.py": "Y = 2\n\n" + old_bad}, False),
        # a reimport, reported on the OTHER import's line
        "reimport fails": ({"m.py": "import os\nX = os.sep\n"},
                           {"m.py": "import os\nX = os.sep\n\n\ndef g():\n    pass\n\n\nimport os\n"},
                           True),
        # a file pushed over 1700 lines of code
        "long file fails": ({"m.py": "X0 = 0\n"},
                            {"m.py": "".join("X%d = %d\n" % (i, i) for i in range(1702))}, True),
        "unchanged complexity passes": ({"m.py": simple}, {"m.py": simple + "\nZ = 3\n"}, False),
        "JavaScript grown function fails": (
            {"a.js": "function f(a) { return a; }\n"},
            {"a.js": "function f(a) {\n" + "".join("  if (a === %d) { return %d; }\n" % (i, i)
                                                   for i in range(12)) + "  return a;\n}\n"}, True),
    }


def _prospector_cases():
    """Return the cases for files over 150 KB: a str verdict starts the problem that must come."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "..", ".prospector.yaml"), encoding="utf-8") as fh:
        prof = {".prospector.yaml": fh.read()}      # the repository's own profile, as CI runs it
    big = "".join("# %s\n" % ("x" * 69) for _ in range(2100))        # 151,200 bytes, no findings
    unused = "import os\n"                                           # pyflakes F401
    no_pyflakes = {".prospector.yaml": prof[".prospector.yaml"] + "\npyflakes:\n  run: false\n"}
    return {
        "Prospector: a finding added to a file over 150 KB fails": (
            dict(prof, **{"big.py": big}), {"big.py": big + unused}, "Prospector pyflakes F401"),
        "Prospector: a finding the base already had passes": (
            dict(prof, **{"big.py": big + unused}), {"big.py": big + unused + "# more\n"}, False),
        "Prospector: a file under 150 KB is left to Codacy": (
            dict(prof, **{"small.py": "X = 1\n"}), {"small.py": unused + "X = 1\n"}, False),
        "Prospector: tools/panel-helper is judged as Python": (
            dict(prof, **{"tools/panel-helper": "#!/usr/bin/env python3\n" + big}),
            {"tools/panel-helper": "#!/usr/bin/env python3\n" + big + unused},
            "Prospector pyflakes F401"),
        "Prospector: a renamed file is judged against its old self": (
            dict(prof, **{"old.py": big + unused}), {"old.py": None, "new.py": big + unused}, False),
        "Prospector: a profile that drops one of Codacy's tools fails": (
            dict(no_pyflakes, **{"big.py": big}), {"big.py": big + "# more\n"},
            "Prospector ran without pyflakes"),
    }


def _case_ok(problems, expect):
    """Return whether the problems found are the verdict a self-test case expects."""
    if isinstance(expect, str):
        return any(msg.startswith(expect) for _p, _l, msg in problems)
    return bool(problems) == expect


def self_test():
    """Build a repository, change it the ways that slipped past Codacy, and check each verdict."""
    cases = dict(_size_cases(), **_prospector_cases())
    bad = []
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t")
    for name, (before, after, expect) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", "-b", "main", d], capture_output=True,  # nosec B603 B607
                           check=True)
            _test_commit(d, env, before, "base")
            base = _git("rev-parse", "HEAD", cwd=d).stdout.strip()
            _test_commit(d, env, after, "head")
            problems = run(base, cwd=d)[0]
        if not _case_ok(problems, expect):
            bad.append("%s: got %r" % (name, [m[:160] for _p, _l, m in problems][:4]))
    for b in bad:
        print("SELF-TEST FAIL " + b)
    print("self-test: %d of %d cases right" % (len(cases) - len(bad), len(cases)))
    return 1 if bad else 0


def main(argv):
    """Judge HEAD against the base named in `argv` (or found), or run the self-test."""
    if argv[1:2] == ["--self-test"]:
        return self_test()
    base = argv[1] if len(argv) > 1 else _default_base()
    base = _git("rev-parse", "--verify", "%s^{commit}" % base).stdout.strip() or base
    problems, files, big = run(base)
    for path, line, msg in problems:
        print("::error file=%s,line=%d::%s" % (path, line, msg))
    print("complexity gate: %d changed file(s) checked against %s; %d over 150 KB run through "
          "Prospector (%s); %d new violation(s)"
          % (len(files), base[:12], len(big), ", ".join(h for h, _b in big) or "none", len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
