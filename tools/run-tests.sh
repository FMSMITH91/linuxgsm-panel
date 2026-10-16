#!/usr/bin/env bash
# One command to run every local check before pushing. CI runs this same script,
# so "green locally" means "green in CI". Each step fails the whole run on error.
#
#   ./tools/run-tests.sh              # uses python3
#   PYTHON=./venv/bin/python ./tools/run-tests.sh
#   RUN_TESTS_PARALLEL=1 ./tools/run-tests.sh     # the suites in three lanes at once (CI does)
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root (this script lives in tools/)
PY="${PYTHON:-python3}"
# Absolute when it names a path, so a lane that runs in a copy of the tree (below) finds the same
# interpreter: ./venv/bin/python is not in the copy. Not resolved through its link, which would
# leave the venv.
if [[ "$PY" == */* ]]; then
    PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")"
fi
# Scratch for this run: the unit output when UNIT_LOG is not given, and the lanes' copies and logs.
if [[ -n "${RUNNER_TEMP:-}" ]]; then
    RT_TMP="$(mktemp -d "${RUNNER_TEMP}/lgsm-tests-XXXXXX")"
else
    RT_TMP="$(mktemp -d -t lgsm-tests-XXXXXX)"
fi
trap 'rm -rf "$RT_TMP"' EXIT
# The checkout itself. run_suite refuses to clear a database here (see it).
RT_ROOT="$PWD"

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
#
# Cleared only in a COPY of the tree (lane_tree), never in the checkout: there, data/panel.db is a
# developer's own panel (README's development steps run `python app.py` in it, which creates it:
# their admin account, hosts and stored credentials), and panel.db.backup is the known-good copy
# the panel restores it from. Both modes run these suites in a copy; this refusal is what keeps a
# later edit from calling one in the checkout again.
run_suite() {
    local label="$1" path="$2" out rc
    echo "== ${label} =="
    if [[ -n "${RT_ROOT:-}" && "$PWD" -ef "$RT_ROOT" ]]; then
        echo "  !! ${path} would run in the checkout and delete its data/panel.db; run it in a lane_tree copy" >&2
        return 1
    fi
    rm -f data/panel.db data/panel.db-shm data/panel.db-wal data/panel.db.backup
    set +e
    out="$("$PY" "$path" 2>&1)"; rc=$?
    set -e
    printf '%s\n' "$out"
    if [[ "$rc" -ne 0 ]]; then
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
    # ...and it must have counted to the end: exit 0 with no "N / N checks passed", or with two
    # different numbers in it, is a suite that stopped early or failed without saying so.
    local tally
    tally="$(printf '%s\n' "$out" | grep -E '^[0-9]+ / [0-9]+ checks passed$' | tail -n 1 || true)"
    if ! [[ "$tally" =~ ^([0-9]+)\ /\ ([0-9]+)\ checks\ passed$ ]] \
            || [[ "${BASH_REMATCH[1]}" != "${BASH_REMATCH[2]}" || "${BASH_REMATCH[1]}" -eq 0 ]]; then
        echo "  !! ${path} exited 0 without a full 'N / N checks passed' tally (${tally:-none})" >&2
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
elif [[ "${REQUIRE_TOOLS:-0}" = "1" ]]; then
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
elif [[ "${REQUIRE_TOOLS:-0}" = "1" ]]; then
    echo "  !! shellcheck is required here (REQUIRE_TOOLS=1) and is not on PATH" >&2
    exit 1
else
    echo "== shellcheck (not installed — skipping) =="
fi

unit_suite() {
    echo "== unit tests (pure logic; no network) =="
    # UNIT_LOG=<file> keeps a copy of this run's output. ci.yml sets it: its next step judges the
    # suite's root run against this one. Kept in this run's scratch otherwise, to read the tally.
    local UNIT_LOG="${UNIT_LOG:-$RT_TMP/unit.log}"
    "$PY" tests/unit_test.py | tee "${UNIT_LOG}"
    # Its exit code fails a FAIL; this fails a run that ended without counting to the end.
    if ! grep -qE '^[0-9]+ / [0-9]+ checks passed$' "${UNIT_LOG}"; then
        echo "  !! tests/unit_test.py printed no 'N / N checks passed' tally" >&2
        return 1
    fi
}

# Everything after unit up to smoke, in the order below. Each function is one lane when the suites
# run in parallel (run_lanes), and they run one after another, in this same order, when they do not.
other_suites() {
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
}

smoke_suite() {
    # CI runs this bare, which is right there. On a DEVELOPER machine use ./tools/smoke-local.sh
    # instead of this script: booting the app fires real `sudo -n` probes (pam_faillock counts each
    # one and will lock you out of your own sudo) and real outbound SSH to the fixture hosts. That
    # wrapper runs the same suite with both refused. See its header.
    run_suite "smoke test (boots the app; routes must not 5xx)" tests/smoke_test.py
}

rbac_suite() {
    run_suite "rbac test (permissions/IDOR enforced server-side; self-seeds on an empty DB)" tests/rbac_test.py
}

# ── RUN_TESTS_PARALLEL=1: three lanes at once ─────────────────────────────────────────────────
# One after another the suites took ~22 minutes on a CI runner: unit ~10, smoke ~10, the rest ~1.5.
# Each lane runs its suites in order, under set -e, exactly as below; the lanes run side by side.
#
# What they must not share is data/: smoke, rbac, manage, setup_wizard, perf_budget and
# input_validation each create data/panel.db (DATA_DIR is a fixed path in the tree, with no
# override) and refuse to run over one. So every lane but unit's runs in its OWN copy of the tree,
# made before any lane starts: the tracked and untracked-but-not-ignored files (what
# tools/smoke-local.sh copies), plus .git when it is a directory, as in CI's checkout, so a copy is
# the checkout a suite would have seen. Unit runs in the tree itself, where it always has; it writes
# nothing in data/.
#
# Each lane's output goes to its own log, printed whole when the lane ends, in lane order. A lane's
# result is its exit status (wait), and every suite in it has already failed that status on a FAIL,
# a SKIP, a crash or a missing tally. A lane that did not finish is not a pass: wait answers its
# signal, and nothing is reported as passed that has no status.
#
# Every step ends in `|| return 1`. lane_tree runs inside $(…), where bash clears set -e, so a
# failed mktemp, chmod, copy or `cp .git` (a full disk, say) would still print the half-made
# directory and return 0, and the lanes would start in it and fail on whatever file was missing.
lane_tree() {
    local dest
    dest="$(mktemp -d "$RT_TMP/lane-XXXXXX")" || return 1
    # The checkout's own mode, not mktemp's 0700: a check that runs a tool as another account
    # reads the tree through this directory as it would the checkout.
    chmod --reference=. "$dest" || return 1
    git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$dest" \
        || return 1
    if [[ -d .git ]]; then
        cp -a .git "$dest/.git" || return 1
    fi
    printf '%s\n' "$dest"
}

# Every suite, in the order the sequential mode runs them. run_lanes refuses lanes that do not run
# each of these exactly once: a suite dropped from a lane (rbac's 325 permission and IDOR checks,
# say) otherwise stops running in CI with every check still green, since a lane is judged only by
# what it ran. tests/unit/part85.py holds every tests/*_test.py to a function named here.
ALL_SUITES=("unit_suite" "other_suites" "smoke_suite" "rbac_suite")

# A process and everything below it, parents first: a lane is a subshell, and its suite (and that
# suite's own children) sit one or more levels under it.
_r22a_tree() {
    local p c
    for p in "$@"; do
        printf '%s\n' "$p"
        for c in $(pgrep -P "$p" 2>/dev/null || true); do
            _r22a_tree "$c"
        done
    done
}

# Ctrl-C (or a TERM) during the lanes. Without job control bash starts each `( … ) &` lane with
# SIGINT ignored, and the suites inherit that, so they never see a Ctrl-C and run on to the end
# (minutes) while this script sits in `wait`. Stop every lane's whole tree instead: TERM, then
# KILL for anything still there a moment later, then reap them before the EXIT trap removes the
# directories they run in.
_r22a_stop_lanes() {
    local -a tree
    mapfile -t tree < <(_r22a_tree "$@")
    echo "  !! interrupted: stopping the lanes" >&2
    kill -TERM "${tree[@]}" 2>/dev/null || true
    sleep 1
    kill -KILL "${tree[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
}

run_lanes() {
    local -a lanes=("unit_suite" "other_suites rbac_suite" "smoke_suite")
    local -a pids
    local i rc bad=0 other smoke want got
    # shellcheck disable=SC2048,SC2086  # a lane is a list of function names, split on purpose
    got="$(printf '%s\n' ${lanes[*]} | sort)"
    want="$(printf '%s\n' "${ALL_SUITES[@]}" | sort)"
    if [[ "$got" != "$want" ]]; then
        echo "  !! the lanes run [${got//$'\n'/ }], not each of [${want//$'\n'/ }] once" >&2
        return 1
    fi
    chmod --reference=. "$RT_TMP"
    # Plain assignments, so a copy that failed stops the run (set -e) before any lane starts:
    # lane_tree returns non-zero for that (see it), and an assignment takes its command's status.
    other="$(lane_tree)"
    smoke="$(lane_tree)"
    local -a dirs=("$PWD" "$other" "$smoke")
    for i in "${!lanes[@]}"; do
        # shellcheck disable=SC2086  # a lane is a list of function names, split on purpose
        ( set -e; cd "${dirs[$i]}"; for fn in ${lanes[$i]}; do "$fn"; done ) >"$RT_TMP/lane$i.log" 2>&1 &
        pids+=("$!")
        echo "== lane $i started: ${lanes[$i]} =="
    done
    trap '_r22a_stop_lanes "${pids[@]}"; exit 130' INT TERM
    for i in "${!lanes[@]}"; do
        set +e
        wait "${pids[$i]}"; rc=$?
        set -e
        echo "== lane $i (${lanes[$i]}) =="
        cat "$RT_TMP/lane$i.log"
        if [[ "$rc" -ne 0 ]]; then
            echo "  !! lane $i (${lanes[$i]}) exited ${rc}" >&2
            bad=1
        fi
    done
    echo "== lanes =="
    for i in "${!lanes[@]}"; do
        printf '  lane %s: %s\n' "$i" "$(grep -E '^[0-9]+ / [0-9]+ checks passed$' "$RT_TMP/lane$i.log" | tr '\n' ',' || true)"
    done
    trap - INT TERM
    return "$bad"
}

if [[ "${RUN_TESTS_PARALLEL:-0}" = "1" ]]; then
    run_lanes
else
    # One after another, in ALL_SUITES' order: unit in the tree, as in the lanes, and every suite
    # that owns data/ in ONE copy of it (see run_suite), never in the checkout.
    seq_tree="$(lane_tree)"
    for fn in "${ALL_SUITES[@]}"; do
        if [[ "$fn" == "unit_suite" ]]; then
            "$fn"
        else
            ( cd "$seq_tree"; "$fn" )
        fi
    done
fi

echo ""
echo "All checks passed."
