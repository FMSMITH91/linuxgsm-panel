# Development

Back to the [README](README.md).

## Running from a checkout

```bash
git clone https://github.com/FMSMITH91/linuxgsm-panel.git && cd linuxgsm-panel
python3 -m venv venv && source venv/bin/activate
pip install --no-deps -r panel/install/requirements.txt   # the whole closure; --no-deps keeps out what other packages declare and the panel does not use
python panel/install/app.py

# The test tools CI installs beside them
pip install --require-hashes -r .github/ci-requirements-checks/build.txt
pip install --require-hashes --no-build-isolation -r .github/ci-requirements-checks/checks.txt

# Every suite, each in a throwaway copy of the tree with sudo refused and outbound connections blocked
failed=""; for s in tests/*_test.py; do PYTHON=./venv/bin/python ./tools/smoke-local.sh "$s" || failed="$failed $s"; done; echo "failed:${failed:- none}"
```

Use `tools/smoke-local.sh`, not `tools/run-tests.sh` (what CI runs): the latter makes real `sudo -n` probes, which can lock you out of sudo, and real outbound SSH.

The unit suite can run in shards side by side, as CI runs it: `UNIT_SHARD=2/4 ./tools/smoke-local.sh tests/unit_test.py` runs shard 2 of 4 (`tests/unit/shard.py` says which parts each shard runs). Without `UNIT_SHARD` it runs every part, as before. In CI each test leg, and the coverage run, is split into four unit shards and one job for everything else; the check each leg reports, and `coverage`, pass only when every part passed. `js coverage` (the browser walk in `tools/js_coverage/`, which measures the panel's own JavaScript) runs in four parts the same way: `python tools/js_coverage/run.py --part 2/4` walks part 2 of 4 (`walk.py`'s `part_units` splits the walk's pages by the seconds each took in CI, every page in exactly one part), and `tools/js_coverage/merge.py` adds the parts' LCOV reports into the one report Codacy reads.

Where the time goes: `UNIT_PART_TIMES=/tmp/times.json ./tools/smoke-local.sh tests/unit_test.py` writes each part's wall time, CPU time, peak memory and the processes it started, and prints the slowest parts (`tests/unit/timing.py`). CI's unit runs print the same block. `python tests/unit/timing.py /tmp/times.json` rewrites `tests/unit/shard_weights.json` from an unsplit run, so the four shards stay even.

Running only what a change touches: on a pull request, each unit shard runs the setup (part01-part12), part15, every part that walks the tree, every part the change edits (and the parts importing it), and every part that ran, read or listed a changed file in main's last full run. That record is the impact map (`tests/unit/impact.py`), which CI's coverage run makes on every push to main. Everything runs instead when the change touches the runner, a shared test module, the requirements, a workflow, `install.sh` or `tools/`, when it changes a file the map never saw, when the map is missing or more than 7 days old, or when the pull request has the `full-tests` label. A push to main always runs every part, and main never reuses a pull request's selected run, so nothing is released that skipped a part. Locally, `UNIT_SELECT=auto UNIT_IMPACT_MAP=<map.json> ./tools/smoke-local.sh tests/unit_test.py` makes the same selection against `origin/main` (`UNIT_SELECT_BASE` names another base), and `UNIT_SELECT="part94 part190"` runs those parts with the setup. To make a map locally, run the whole suite once with `UNIT_IMPACT_RECORD=/tmp/rec.json` (Python 3.12 or later), then `python tests/unit/impact.py build /tmp/map.json HEAD /tmp/rec.json`.

CI also runs CodeQL, Bandit, Semgrep, zizmor, a dependency audit and fuzzing (`tests/fuzz/`). Every CI job except the deploy job starts with StepSecurity's Harden-Runner: it records outbound connections and root processes in the job's public log, routes the job's DNS through its own proxy, and blocks hosts on StepSecurity's global blocklist. The pull-request jobs that reach only a few known hosts (GitHub, PyPI, npm, OSV, Semgrep, SonarCloud, Ubuntu's and Microsoft's package mirrors, LinuxGSM's site) run it in block mode, which refuses every other host; the rest stay in audit mode. Each workflow's token starts with no permissions, and each job grants only what it uses. CI's own tools install from committed lockfiles that pin every package by hash: the Python ones from `.github/ci-requirements*` in pip's hash-checking mode, and Lighthouse CI (the `lighthouse` check, which audits the signed-in pages `.github/lighthouserc.json` lists) by `npm ci --ignore-scripts` from `.github/lhci`, driving the runner's own Chrome. Dependabot moves both, and osv-scanner audits them.

The application lives in `panel/` (`core`, `db`, `security`, `ops`, `services`, `routes`; each package's module-level imports reach only the ones before it, enforced by `tests/unit/part01.py`). The files installed panels address by path (`app.py`, `manage.py`, `db_maintenance.py`, `recover.sh`, `uninstall.sh`, `VERSION`, `release-signers`, `update-stops` and the requirements lockfiles) are in `panel/install/`. `install.sh` stays at the repo root because the install one-liner fetches it from there.

## Contributing

Issues and pull requests are welcome. Report security issues privately via [SECURITY.md](../.github/SECURITY.md), not a public issue. For code, fork and open a PR against `main`, run the suites through `tools/smoke-local.sh` first, and keep CI green. New functionality comes with tests, and a bug fix comes with a check that fails without the fix.

