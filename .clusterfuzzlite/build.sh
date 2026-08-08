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

# PyInstaller only bundles what it can see in an `import` statement, and these packages reach for
# their real implementations through strings at import time. eventlet.hubs is the one that bit:
#
#   builtin_hub_modules = tuple(importlib.import_module('eventlet.hubs.' + name)
#                               for name in ('epolls', 'kqueue', 'poll', 'selects'))
#
# so naming --hidden-import eventlet.tpool built five targets that all died on
# `No module named 'eventlet.hubs.epolls'`. --collect-submodules takes the whole package and does
# not need updating when a new submodule shows up. dns arrives transitively (eventlet's greendns);
# paramiko resolves its kex/cipher backends the same dynamic way.
COMPILE_ARGS=(
  --collect-submodules eventlet
  --collect-submodules paramiko
  --collect-submodules dns
  --hidden-import config
)

for fuzzer in "$SRC_DIR"/tests/fuzz/fuzz_*.py; do
  name="$(basename -s .py "$fuzzer")"
  compile_python_fuzzer "$fuzzer" "${COMPILE_ARGS[@]}"

  # Seed corpus. The runner picks up <fuzz_target>_seed_corpus.zip sitting next to the binary in
  # $OUT. The corpora are named after the target minus its fuzz_ prefix (tests/fuzz/corpus/console
  # feeds fuzz_console), matching what .github/workflows/fuzz.yml already passes on the command line.
  corpus_dir="$SRC_DIR/tests/fuzz/corpus/${name#fuzz_}"
  if [ -d "$corpus_dir" ]; then
    zip -j -q -r "$OUT/${name}_seed_corpus.zip" "$corpus_dir"
  fi
done
