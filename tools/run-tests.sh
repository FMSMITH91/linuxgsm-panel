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
    if printf '%s' "$out" | grep -qiE '^SKIP:'; then
        echo "  !! ${path} SKIPPED — that is a gap, not a pass. See the note in $0." >&2
        return 1
    fi
}

echo "== byte-compile (syntax errors) =="
"$PY" -m compileall -q -x "$VENVS" .

echo "== lint: real bugs + unused imports/vars (undefined names, bad syntax, F401, F841) =="
if "$PY" -m flake8 --version >/dev/null 2>&1; then
    # F401 (unused import) + F841 (unused local var) are included so dead code is caught
    # here rather than later by CodeQL / Codacy in the Security tab.
    "$PY" -m flake8 --select=E9,F63,F7,F82,F401,F841 --show-source --statistics \
        --extend-exclude=venv,.venv .
else
    echo "  (flake8 not installed — skipping)"
fi

if command -v shellcheck >/dev/null 2>&1; then
    echo "== shellcheck (shell scripts) =="
    shellcheck -S warning install.sh uninstall.sh tools/run-tests.sh reset-password.sh recover.sh
else
    echo "== shellcheck (not installed — skipping) =="
fi

echo "== unit tests (pure logic; no network) =="
"$PY" tests/unit_test.py

echo "== template actions (JS parses; every data-action button is wired) =="
# esprima is optional locally (the test says so and skips); CI installs it so the JS parse
# gate always runs there.
"$PY" tests/template_actions_test.py

echo "== url map (every rule, endpoint, method and guard, vs the committed baseline) =="
# The safety net for splitting register_routes() up. A route that silently loses a method, an
# endpoint that gets renamed out from under url_for(), a decorator dropped during a copy-paste —
# none of those raise at import. Regenerate deliberately with --update and read the diff.
"$PY" tests/url_map_test.py

run_suite "manage.py (the offline recovery CLI: lock-out guard, session revocation)" tests/manage_test.py

# CI runs this bare, which is right there. On a DEVELOPER machine use ./tools/smoke-local.sh
# instead of this script: booting the app fires real `sudo -n` probes (pam_faillock counts each
# one and will lock you out of your own sudo) and real outbound SSH to the fixture hosts. That
# wrapper runs the same suite with both refused. See its header.
run_suite "smoke test (boots the app; routes must not 5xx)" tests/smoke_test.py

run_suite "rbac test (permissions/IDOR enforced server-side; self-seeds on an empty DB)" tests/rbac_test.py

echo ""
echo "All checks passed."
