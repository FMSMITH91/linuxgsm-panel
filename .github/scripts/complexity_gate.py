#!/usr/bin/env python3
"""Fail a pull request that makes a function or a file break Codacy's size and complexity limits.

Codacy's pull-request check counts an issue as new only on a line the pull request changed. Its
Lizard issues sit on a function's ``def`` line (complexity, length, parameters) or on line 1 (file
length), and Pylint's reimport sits on the OTHER import's line. So a pull request that grew a
function without touching its ``def`` passed Codacy as "0 new issues", and the issue appeared when
Codacy analysed main: 23 of them by 2026-09-30, from #365 and #374.

This compares the base and the head of every changed .py/.js file (and tools/panel-helper, which
Codacy reads as Python) with the limits the repository's Codacy coding standard sets:

* Lizard, per function: cyclomatic complexity over 10, more than 50 lines of code (NLOC), more
  than 8 parameters; per file: more than 1700 lines of code.
* Pylint W0404 (reimport), W0612 (unused variable) and W0108 (unnecessary lambda): the three
  Pylint patterns Codacy runs here.

A violation the base already had is not new; only what the change adds fails the check, named
with its file and line. Usage:

    complexity_gate.py [BASE]     # BASE: a commit; default the first parent of a merge HEAD,
                                  # else main's merge base with HEAD
    complexity_gate.py --self-test
"""
import collections
import os
import re
import subprocess  # nosec B404 - git and pylint, fixed argv, no shell
import sys
import tempfile

import lizard

CCN_MAX, FN_NLOC_MAX, PARAMS_MAX, FILE_NLOC_MAX = 10, 50, 8, 1700
PYLINT_CODES = ("W0404", "W0612", "W0108")
PYTHON_NAMED = {"tools/panel-helper"}   # Python without the extension (.codacy.yaml says so)


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


def _default_base():
    parents = _git("rev-list", "--parents", "-n", "1", "HEAD").stdout.split()
    if len(parents) == 3:          # a pull request's merge commit: its first parent is the base
        return parents[1]
    return _git("merge-base", "HEAD", "origin/main").stdout.strip() or "HEAD~1"


def changed_files(base):
    out = _git("diff", "--name-only", "--diff-filter=AMR", base, "HEAD").stdout.split()
    return [p for p in out if p.endswith((".py", ".js")) or p in PYTHON_NAMED]


def run(base, cwd=None):
    """(problems, files checked): every new violation, as (path, line, message)."""
    if cwd:
        os.chdir(cwd)
    problems, files = [], changed_files(base)
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                head = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        shown = _git("show", "%s:%s" % (base, path))
        base_code = shown.stdout if shown.returncode == 0 else ""
        problems += [(path, line, msg) for line, msg in new_violations(path, base_code, head)]
    return problems, files


def self_test():
    """Build a repository, change it the ways that slipped past Codacy, and check each verdict."""
    simple = "def f(a):\n    return a\n"
    grown = "def f(a):\n" + "".join("    if a == %d:\n        return %d\n" % (i, i) for i in range(12)) \
            + "    return a\n"
    old_bad = "def old(a):\n" + "".join("    if a == %d:\n        a += 1\n" % i for i in range(12)) \
              + "    return a\n"
    cases = {
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
    bad = []
    for name, (before, after, should_fail) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                       GIT_COMMITTER_EMAIL="t@t")

            def commit(files, msg, d=d, env=env):
                for p, txt in files.items():
                    with open(os.path.join(d, p), "w", encoding="utf-8") as fh:
                        fh.write(txt)
                for argv in (["add", "-A"], ["-c", "commit.gpgsign=false", "commit", "-qm", msg]):
                    subprocess.run(["git", *argv], cwd=d, env=env, capture_output=True,  # nosec B603 B607
                                   check=True)
            subprocess.run(["git", "init", "-q", "-b", "main", d], capture_output=True,  # nosec B603 B607
                           check=True)
            commit(before, "base")
            base = _git("rev-parse", "HEAD", cwd=d).stdout.strip()
            commit(after, "head")
            here = os.getcwd()
            try:
                problems, _files = run(base, cwd=d)
            finally:
                os.chdir(here)
        if bool(problems) != should_fail:
            bad.append("%s: got %r" % (name, problems))
    for b in bad:
        print("SELF-TEST FAIL " + b)
    print("self-test: %d of %d cases right" % (len(cases) - len(bad), len(cases)))
    return 1 if bad else 0


def main(argv):
    if argv[1:2] == ["--self-test"]:
        return self_test()
    base = argv[1] if len(argv) > 1 else _default_base()
    base = _git("rev-parse", "--verify", "%s^{commit}" % base).stdout.strip() or base
    problems, files = run(base)
    for path, line, msg in problems:
        print("::error file=%s,line=%d::%s (Codacy reports this on main, not on the pull request)"
              % (path, line, msg))
    print("complexity gate: %d changed file(s) checked against %s, %d new violation(s)"
          % (len(files), base[:12], len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
