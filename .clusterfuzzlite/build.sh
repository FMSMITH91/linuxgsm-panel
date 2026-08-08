#!/bin/bash -eu
# Build every Atheris harness in tests/fuzz/ into an OSS-Fuzz fuzz target.
#
# The same script works for ClusterFuzzLite and for an upstream OSS-Fuzz project — compile_python_
# fuzzer comes from the base-builder-python image in both.

SRC_DIR="$SRC/linuxgsm-panel"

# The panel is an application, not a pip package: there is no setup.py, so `pip3 install .` (what the
# OSS-Fuzz Python guide shows) does not apply. Putting the repo root on PYTHONPATH is what makes the
# harnesses' `import ssh_manager` resolve, and it is what lets PyInstaller find those modules to
# bundle while compiling.
export PYTHONPATH="$SRC_DIR${PYTHONPATH:+:$PYTHONPATH}"

# The harnesses pre-load these through importlib.import_module("...") — a string, so PyInstaller's
# static analysis cannot see them and would ship a fuzzer that dies on its first import. Named here
# for every target rather than per target: the only cost is a slightly larger binary for the one
# harness (console) that does not need them, and a uniform build is worth more than those bytes.
HIDDEN_IMPORTS=(
  --hidden-import paramiko
  --hidden-import eventlet
  --hidden-import eventlet.tpool
  --hidden-import config
)

for fuzzer in "$SRC_DIR"/tests/fuzz/fuzz_*.py; do
  name="$(basename -s .py "$fuzzer")"
  compile_python_fuzzer "$fuzzer" "${HIDDEN_IMPORTS[@]}"

  # Seed corpus. The runner picks up <fuzz_target>_seed_corpus.zip sitting next to the binary in
  # $OUT. The corpora are named after the target minus its fuzz_ prefix (tests/fuzz/corpus/console
  # feeds fuzz_console), matching what .github/workflows/fuzz.yml already passes on the command line.
  corpus_dir="$SRC_DIR/tests/fuzz/corpus/${name#fuzz_}"
  if [ -d "$corpus_dir" ]; then
    zip -j -q -r "$OUT/${name}_seed_corpus.zip" "$corpus_dir"
  fi
done
