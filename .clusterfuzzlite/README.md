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

## Not enabled: batch fuzzing, corpus pruning, coverage

Those three modes want somewhere to keep a corpus between runs, which means a **separate storage
repo** and a personal access token. Without one, every run starts from the seeds in
`tests/fuzz/corpus/` and learns nothing from the last run. To turn them on: create an empty repo,
add a PAT with write access to it as a secret, then pass `storage-repo` to both actions and add
workflows with `mode: batch`, `mode: prune` and `mode: coverage`. See
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
