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

`check_build` is the one worth running after touching `build.sh` or a harness's imports: a
PyInstaller bundle can compile cleanly and still die on its first import if a dynamically-imported
module was not bundled. That is why `build.sh` collects every submodule of `eventlet`, `paramiko` and
`dns` and names `panel.core.config` as a hidden import. The harnesses also pre-load SQLAlchemy and
Flask by name, uninstrumented, to keep their start-up short (see `tests/fuzz/fuzz_game_status.py`).
Those need no flag: the panel imports `flask_sqlalchemy` and `flask_login` in plain `import`
statements, and PyInstaller's own SQLAlchemy hook bundles every `sqlalchemy.dialects` module.

## Batch fuzzing, pruning, coverage and continuous builds

| workflow | when | what it keeps |
|---|---|---|
| `cflite_batch.yml` | nightly | fuzzes every target for 15 min and keeps the corpus (`cifuzz-corpus-<target>`) |
| `cflite_cron.yml` | weekly | prunes that corpus; reports fuzzing coverage (`cifuzz-coverage-latest`) |
| `cflite_build.yml` | each push to main | the build of that commit (`cifuzz-build-address-<commit>`) |

All of it is kept as Actions artifacts. ClusterFuzzLite's storage repository (a second repository
plus a write token) is optional: without one, "corpora and coverage reports will be uploaded as
GitHub artifacts instead" (the
[ClusterFuzzLite docs](https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/)).
Until 2026-10 these workflows waited for a `CFL_STORAGE_REPO` secret that was never created, and did
nothing.

`cflite_pr.yml` reads all three back: it starts from the batch corpus, fuzzes only the targets the
coverage report says a pull request's diff reaches, and drops a crash that main's stored build
already has.

**Every job that reads them first checks where they came from.** The action takes the newest artifact
of a name from any run in the repository. A fork's pull request runs its own copy of a workflow, so
it can upload a `cifuzz-*` artifact too, and the action unpacks it unchecked and runs what it holds.
So each of those jobs fails, and fuzzes nothing, while any stored `cifuzz-*` artifact was made
anywhere but a run of this repository's main. The error lists them. Delete one with
`gh api -X DELETE repos/FMSMITH91/linuxgsm-panel/actions/artifacts/<id>`.

## Upstream OSS-Fuzz

The same three files, moved to `projects/linuxgsm-panel/` in a PR against
<https://github.com/google/oss-fuzz>, are a complete submission — the only change needed is a
`Dockerfile` that `git clone`s this repo instead of `COPY`ing the checkout, plus a
`primary_contact` email on a Google account.

Worth knowing before spending the effort: the stated bar is that a project *"must have a
significant user base and/or be critical to the global IT infrastructure"*. A self-hosted game
control panel is unlikely to clear it. ClusterFuzzLite exists precisely so that projects below that
bar get the same engine on their own CI, which is what is wired up here.
