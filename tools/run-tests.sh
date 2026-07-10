#!/usr/bin/env bash
# One command to run every local check before pushing. CI runs this same script,
# so "green locally" means "green in CI". Each step fails the whole run on error.
#
#   ./tools/run-tests.sh              # uses python3
#   PYTHON=./venv/bin/python ./tools/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root (this script lives in tools/)
PY="${PYTHON:-python3}"

echo "== byte-compile (syntax errors) =="
"$PY" -m compileall -q .

echo "== lint: real bugs + unused imports/vars (undefined names, bad syntax, F401, F841) =="
if "$PY" -m flake8 --version >/dev/null 2>&1; then
    # F401 (unused import) + F841 (unused local var) are included so dead code is caught
    # here rather than later by CodeQL / Codacy in the Security tab.
    "$PY" -m flake8 --select=E9,F63,F7,F82,F401,F841 --show-source --statistics .
else
    echo "  (flake8 not installed — skipping)"
fi

echo "== unit tests (pure logic; no network) =="
"$PY" tests/unit_test.py

echo "== template actions (every data-action button is wired) =="
"$PY" tests/template_actions_test.py

echo "== smoke test (boots the app; routes must not 5xx) =="
"$PY" tests/smoke_test.py

if command -v shellcheck >/dev/null 2>&1; then
    echo "== shellcheck (shell scripts) =="
    shellcheck -S warning install.sh uninstall.sh tools/run-tests.sh reset-password.sh recover.sh
else
    echo "== shellcheck (not installed — skipping) =="
fi

echo ""
echo "All checks passed."
