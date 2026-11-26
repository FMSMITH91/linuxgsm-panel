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

The unit suite can run in shards side by side, as CI runs it: `UNIT_SHARD=2/4 ./tools/smoke-local.sh tests/unit_test.py` runs shard 2 of 4 (`tests/unit/shard.py` says which parts each shard runs). Without `UNIT_SHARD` it runs every part, as before. In CI each test leg, and the coverage run, is split into four unit shards and one job for everything else; the check each leg reports, and `coverage`, pass only when every part passed.

CI also runs CodeQL, Bandit, Semgrep, zizmor, a dependency audit and fuzzing (`tests/fuzz/`). Every CI job except the deploy job starts with StepSecurity's Harden-Runner: it records outbound connections and root processes in the job's public log, routes the job's DNS through its own proxy, and blocks hosts on StepSecurity's global blocklist. The pull-request jobs that reach only a few known hosts (GitHub, PyPI, npm, OSV, Semgrep, SonarCloud, Ubuntu's and Microsoft's package mirrors, LinuxGSM's site) run it in block mode, which refuses every other host; the rest stay in audit mode. Each workflow's token starts with no permissions, and each job grants only what it uses.

The application lives in `panel/` (`core`, `db`, `security`, `ops`, `services`, `routes`; each package's module-level imports reach only the ones before it, enforced by `tests/unit/part01.py`). The files installed panels address by path (`app.py`, `manage.py`, `db_maintenance.py`, `recover.sh`, `uninstall.sh`, `VERSION`, `release-signers`, `update-stops` and the requirements lockfiles) are in `panel/install/`. `install.sh` stays at the repo root because the install one-liner fetches it from there.

## Contributing

Issues and pull requests are welcome. Report security issues privately via [SECURITY.md](../.github/SECURITY.md), not a public issue. For code, fork and open a PR against `main`, run the suites through `tools/smoke-local.sh` first, and keep CI green. New functionality comes with tests, and a bug fix comes with a check that fails without the fix.

