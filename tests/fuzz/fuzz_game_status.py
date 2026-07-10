#!/usr/bin/env python3
"""Atheris fuzz harness: game-server status parsers (ssh_manager).

These parse the `status` / `list` console reply of a REMOTE game server into a player list. That
reply is fully UNTRUSTED — a hostile or buggy server controls every byte of it. The property under
test: no input, however malformed, may make a parser raise. They are best-effort and must degrade to
[] rather than throw (a raise here would blow up the player list / auto-reboot path).

Run locally:
    pip install atheris
    python tests/fuzz/fuzz_game_status.py -max_total_time=60 tests/fuzz/corpus/game_status
"""
import atheris

# Load ssh_manager's heavy dependencies UNINSTRUMENTED first, so instrument_imports() below
# instruments only the parser module (not paramiko / eventlet) — faster, coverage stays on target.
import paramiko              # noqa: F401
from eventlet import tpool   # noqa: F401
import config                # noqa: F401

with atheris.instrument_imports():
    import ssh_manager


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    ssh_manager._parse_valve_status(text)     # Source / GoldSrc `status`
    ssh_manager._parse_idtech3_status(text)   # Quake3 / Call of Duty `status`
    ssh_manager._parse_minecraft_list(text)   # Minecraft `list`


def main():
    import sys
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
