#!/usr/bin/env python3
"""Atheris fuzz harness: game-server status parsers (ssh_manager).

These parse the `status` / `list` console reply of a REMOTE game server into a player list. That
reply is fully UNTRUSTED — a hostile or buggy server controls every byte of it. The property under
test: no input, however malformed, may make a parser raise. They are best-effort and must degrade to
[] rather than throw (a raise here would blow up the player list / auto-reboot path).

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_game_status.py -max_total_time=60 tests/fuzz/corpus/game_status
"""
import importlib
import os
import sys

import atheris

# Running `python tests/fuzz/fuzz_x.py` puts tests/fuzz (not the project root) on sys.path, so make
# the project root importable before importing the panel's modules.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Pre-load ssh_manager's heavy dependencies UNINSTRUMENTED so instrument_imports() below instruments
# only the panel's own modules, not paramiko, eventlet, Flask or SQLAlchemy. importlib (rather than
# a static `import`) loads them purely for effect without an unused-import.
#
# Start-up is the budget that matters. ClusterFuzzLite's PR run gives each target a slice of
# fuzz-seconds and kills the process 10s after it: time spent instrumenting at import is time
# outside libFuzzer's clock. With only paramiko and eventlet pre-loaded, Atheris instrumented
# 280 modules here (131 of them SQLAlchemy, plus Flask, Werkzeug and Jinja2, which
# panel.db.models and panel.security pull in) and took ~27s on a runner before the first input,
# so every PR run killed this target and its three siblings as 'process timed out'. With the
# list below only the panel's own modules are instrumented. The same list is in fuzz_config,
# fuzz_cron and fuzz_firewall; part29 holds all four to it.
for _dep in ("paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
             "sqlalchemy.dialects.sqlite", "panel.core.config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    from panel.ops import ssh_manager


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    ssh_manager._parse_valve_status(text)     # Source / GoldSrc `status`
    ssh_manager._parse_idtech3_status(text)   # Quake3 / Call of Duty `status`
    ssh_manager._parse_minecraft_list(text)   # Minecraft `list`


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
