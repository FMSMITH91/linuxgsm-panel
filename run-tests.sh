#!/usr/bin/env bash
# One command to run every local check before pushing. CI runs this same script,
# so "green locally" means "green in CI". Each step fails the whole run on error.
#
#   ./run-tests.sh              # uses python3
#   PYTHON=./venv/bin/python ./run-tests.sh
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"

echo "== byte-compile (syntax errors) =="
"$PY" -m compileall -q .

echo "== lint: real bugs only (undefined names, bad syntax) =="
if "$PY" -m flake8 --version >/dev/null 2>&1; then
    "$PY" -m flake8 --select=E9,F63,F7,F82 --show-source --statistics .
else
    echo "  (flake8 not installed — skipping)"
fi

echo "== unit tests (pure logic; no network) =="
"$PY" tests/unit_test.py

echo "== smoke test (boots the app; routes must not 5xx) =="
"$PY" tests/smoke_test.py

if command -v shellcheck >/dev/null 2>&1; then
    echo "== shellcheck (shell scripts) =="
    shellcheck -S warning install.sh run-tests.sh
else
    echo "== shellcheck (not installed — skipping) =="
fi

echo ""
echo "All checks passed."
