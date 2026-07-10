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
# only the parser module (not paramiko / eventlet) — faster, and coverage stays on target. importlib
# (rather than a static `import`) loads them purely for effect without an unused-import.
for _dep in ("paramiko", "eventlet.tpool", "config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    import ssh_manager


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
