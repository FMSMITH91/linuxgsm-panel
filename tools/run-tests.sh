#!/usr/bin/env bash
# One command to run every local check before pushing. CI runs this same script,
# so "green locally" means "green in CI". Each step fails the whole run on error.
#
#   ./tools/run-tests.sh              # uses python3
#   PYTHON=./venv/bin/python ./tools/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root (this script lives in tools/)
PY="${PYTHON:-python3}"

# ORDER IS CHEAPEST-FIRST, and deliberately so. Every step aborts the run (set -e), so whatever
# runs first decides how long a BROKEN tree takes to tell you. The static checks and the sub-second
# suites therefore come before anything that boots the app: url_map and manage_test each take well
# under a second and catch a whole class of mechanical breakage (a route that lost a method, an
# endpoint renamed out from under url_for), but they used to run AFTER smoke and rbac — so a
# one-second failure was reported two minutes late, three times over in the CI matrix.
# Keep new suites in their place on that scale rather than appending them to the end.

# A local virtualenv usually lives in the repo (see the PYTHON= example above, and venv/ + .venv/
# in .gitignore), so both scanners have to skip it — third-party site-packages code is not ours to
# compile or lint, and flake8's defaults don't exclude it. CI installs deps globally and never has
# one, which is why this only ever bites a developer machine.
VENVS='(^|/)(\.?venv)/'

# ── Running a suite that owns the database ─────────────────────────────────────────────────────
# smoke, rbac and manage each REFUSE to run when data/panel.db exists — they will not touch a real
# install — and they say so and exit 0. A skip that exits 0 reads exactly like a pass.
#
# That is not hypothetical. url_map_test calls create_app(), which CREATES data/panel.db, so every
# DB-owning suite ordered after it silently skipped. manage_test had been skipping in CI for as
# long as it has been in this script: 21 checks reporting green without running. Reordering the
# script to put the fast suites first then did the same thing to smoke and rbac, which is how it
# was found — three suites "passing" in 30s when they take minutes.
#
# So the database is cleared BEFORE each of them (what the coverage job in ci.yml already does,
# which is why that job is the only one that has really been running all five), and a SKIP is
# treated as a FAILURE. Order is now a free choice rather than a hidden dependency.
run_suite() {
    local label="$1" path="$2" out rc
    echo "== ${label} =="
    rm -f data/panel.db data/panel.db-shm data/panel.db-wal data/panel.db.backup
    set +e
    out="$("$PY" "$path" 2>&1)"; rc=$?
    set -e
    printf '%s\n' "$out"
    if [ "$rc" -ne 0 ]; then
        echo "  !! ${path} exited ${rc}" >&2
        return "$rc"
    fi
    # The spellings a suite really uses: the DB-owning suites print "SKIP: ..." at the start of a
    # line, and the check-level suites print "SKIP  name" (two spaces), indented in their summary.
    # An anchored "^SKIP:" matched only the first, so an all-skipped run of the second sailed
    # through as a pass. The fix after that was case-insensitive and matched "skip" ANYWHERE
    # before a space — so a passing check named "...to the skip dialog" failed CI as a skipped
    # suite. Uppercase, at the start of the line after indentation, then a colon or two spaces.
    if printf '%s' "$out" | grep -qE '^[[:space:]]*SKIP(:|  )'; then
        echo "  !! ${path} SKIPPED — that is a gap, not a pass. See the note in $0." >&2
        return 1
    fi
}

echo "== byte-compile (syntax errors) =="
"$PY" -m compileall -q -x "$VENVS" .
# compileall walks *.py ONLY. tools/panel-helper is Python with a shebang and no extension — it is
# the root-owned end of the sudo boundary, and it was the one file in the repo no static check
# could see. Named explicitly here and below for the same reason.
"$PY" -m py_compile tools/panel-helper

echo "== lint: real bugs + unused imports/vars (undefined names, bad syntax, F401, F811, F841) =="
# REQUIRE_TOOLS=1 (set by CI) turns "the tool isn't here" from a skip into a failure. The probe
# below cannot tell "not installed" from "installed and raising on import" — a dependency conflict
# or a bad wheel — and either way it printed "skipping" and the script went on to say
# "All checks passed." Proven by execution: with flake8 made to raise, an injected F821 was
# reported as a clean run.
if "$PY" -m flake8 --version >/dev/null 2>&1; then
    # F401 (unused import) + F841 (unused local var) are included so dead code is caught
    # here rather than later by CodeQL / Codacy in the Security tab.
    #
    # F811 (redefinition of an unused name) was NOT in this list, and Codacy's pyflakes caught
    # what it missed: splitting register_routes() left server_files.py importing flask_socketio
    # twice, the second shadowing the first. Harmless there, but the same rule fires when a
    # def or a name is genuinely clobbered by a later one — a silent wrong-function bug. It is
    # the cheapest possible check for that, so it runs here rather than only in a cloud tool.
    "$PY" -m flake8 --select=E9,F63,F7,F82,F401,F811,F841 --show-source --statistics \
        --extend-exclude=venv,.venv . tools/panel-helper
elif [ "${REQUIRE_TOOLS:-0}" = "1" ]; then
    echo "  !! flake8 is required here (REQUIRE_TOOLS=1) and could not be run" >&2
    exit 1
else
    echo "  (flake8 not installed — skipping)"
fi

if command -v shellcheck >/dev/null 2>&1; then
    echo "== shellcheck (shell scripts) =="
    # Every tracked *.sh, not a hand-kept list: smoke-local.sh and .clusterfuzzlite/build.sh had
    # been missing from it. `git ls-files` so a new script is covered the day it is committed.
    # shellcheck disable=SC2046  # word-splitting is what we want here; no shell script has a space
    shellcheck -S warning $(git ls-files '*.sh')
elif [ "${REQUIRE_TOOLS:-0}" = "1" ]; then
    echo "  !! shellcheck is required here (REQUIRE_TOOLS=1) and is not on PATH" >&2
    exit 1
else
    echo "== shellcheck (not installed — skipping) =="
fi

echo "== unit tests (pure logic; no network) =="
"$PY" tests/unit_test.py

# Through run_suite, not bare: this suite can SKIP (esprima is optional locally), and a skip here
# silently removes the JS parse gate and four CSRF gates from the run. Bare, its exit code was the
# only signal and nothing looked at its output.
run_suite "template actions (JS parses; every data-action button is wired)" \
          tests/template_actions_test.py

echo "== url map (every rule, endpoint, method and guard, vs the committed baseline) =="
# The safety net for splitting register_routes() up. A route that silently loses a method, an
# endpoint that gets renamed out from under url_for(), a decorator dropped during a copy-paste —
# none of those raise at import. Regenerate deliberately with --update and read the diff.
"$PY" tests/url_map_test.py

run_suite "manage.py (the offline recovery CLI: lock-out guard, session revocation)" tests/manage_test.py

# Ordered beside manage_test because it is the other sub-second, DB-owning suite. It is the one
# suite that must NOT pre-complete setup — every other one does, which is exactly why the wizard
# (the only unauthenticated flow in the panel) sat at 21% coverage with its POST path never run.
run_suite "setup wizard (the unauthenticated first-run flow, and the lock that closes it)" \
    tests/setup_wizard_test.py

# Renders every GET page twice — same hosts, 5x the game servers — and fails if any page's query
# count grows with the servers. smoke_test budgets two endpoints by number; this one asserts the
# SHAPE, so a new page is covered the day it is added and nobody maintains a per-endpoint budget.
run_suite "perf budget (no page's query count scales with the number of game servers)" \
    tests/perf_budget_test.py

# Drives the numeric form fields with the values a browser never sends (0, 65536, "abc", a
# newline, Arabic-Indic digits) and asserts a refusal with NO row written — plus a positive control
# per field, so it cannot pass against a route that refuses everything. Ordered here because it
# boots the app like smoke but exercises far fewer pages. Same developer-machine caveat as smoke:
# use ./tools/smoke-local.sh tests/input_validation_test.py.
run_suite "input validation (numeric fields refuse hostile values, and still accept good ones)" \
    tests/input_validation_test.py

# CI runs this bare, which is right there. On a DEVELOPER machine use ./tools/smoke-local.sh
# instead of this script: booting the app fires real `sudo -n` probes (pam_faillock counts each
# one and will lock you out of your own sudo) and real outbound SSH to the fixture hosts. That
# wrapper runs the same suite with both refused. See its header.
run_suite "smoke test (boots the app; routes must not 5xx)" tests/smoke_test.py

run_suite "rbac test (permissions/IDOR enforced server-side; self-seeds on an empty DB)" tests/rbac_test.py

echo ""
echo "All checks passed."
