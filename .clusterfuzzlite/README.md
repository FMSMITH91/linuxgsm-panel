# OSS-Fuzz / ClusterFuzzLite build integration

These three files are the OSS-Fuzz build contract for this repo:

| file | what it does |
|---|---|
| `Dockerfile` | `base-builder-python` + the panel's pinned requirements + the checkout |
| `build.sh` | compiles every `tests/fuzz/fuzz_*.py` harness into a fuzz target and zips its seed corpus |
| `project.yaml` | language, engine and sanitizers |

`.github/workflows/cflite_pr.yml` runs them on each PR in **code-change** mode: it fuzzes only what
the diff touched and files any crash as a SARIF finding in the Security tab, alongside the CodeQL
and Bandit alerts.

This overlaps with `.github/workflows/fuzz.yml` on purpose. That one is the broad sweep — every
target, fixed 60s, plain Atheris. This one is targeted, uses the real OSS-Fuzz toolchain, and
dedupes/reports crashes. Dropping either is a reasonable choice; keeping both is the current one.

## Running it locally

Needs Docker. From the repo root:

```bash
git clone --depth 1 https://github.com/google/oss-fuzz /tmp/oss-fuzz
python3 /tmp/oss-fuzz/infra/helper.py build_image --external $PWD
python3 /tmp/oss-fuzz/infra/helper.py build_fuzzers --external $PWD
python3 /tmp/oss-fuzz/infra/helper.py check_build --external $PWD --language python
python3 /tmp/oss-fuzz/infra/helper.py run_fuzzer --external $PWD fuzz_console
```

`check_build` is the one worth running after touching `build.sh`: a PyInstaller bundle can compile
cleanly and still die on its first import if a dynamically-imported module was not bundled. That is
why `build.sh` names `paramiko`, `eventlet`, `eventlet.tpool` and `config` as `--hidden-import` —
the harnesses pull them in via `importlib.import_module("...")`, a string PyInstaller cannot see.

## Batch fuzzing, pruning and coverage — written, dormant

`cflite_batch.yml` (nightly, all targets, 15 min) and `cflite_cron.yml` (weekly prune + coverage)
are committed and wired, but every job is guarded by `if: env.CFL_STORAGE_REPO != ''` and so does
nothing until that secret exists. They stay dormant rather than red.

They need somewhere to keep the corpus between runs — without it each run restarts from the seeds
in `tests/fuzz/corpus/` and learns nothing from the last one. To switch them on:

1. create an empty repo, e.g. `linuxgsm-panel-fuzz-corpus`
2. create a PAT that can write to it
3. add `CFL_STORAGE_REPO` as a repository secret here (the https URL with the token in it, per the
   ClusterFuzzLite docs)

Nothing else changes; the next scheduled run picks it up. See
<https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/>.

## Upstream OSS-Fuzz

The same three files, moved to `projects/linuxgsm-panel/` in a PR against
<https://github.com/google/oss-fuzz>, are a complete submission — the only change needed is a
`Dockerfile` that `git clone`s this repo instead of `COPY`ing the checkout, plus a
`primary_contact` email on a Google account.

Worth knowing before spending the effort: the stated bar is that a project *"must have a
significant user base and/or be critical to the global IT infrastructure"*. A self-hosted game
control panel is unlikely to clear it. ClusterFuzzLite exists precisely so that projects below that
bar get the same engine on their own CI, which is what is wired up here.
