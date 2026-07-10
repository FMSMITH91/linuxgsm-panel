#!/usr/bin/env python3
"""Atheris fuzz harness: LinuxGSM config / apt / mod-list parsers (ssh_manager).

Each parses text produced on a remote host — a LinuxGSM `.cfg`, `apt list --upgradable`, and the
mods-install / mods-remove listings. All are best-effort and must never raise on malformed input.

Run locally:
    pip install atheris
    python tests/fuzz/fuzz_config.py -max_total_time=60 tests/fuzz/corpus/config
"""
import atheris

import paramiko              # noqa: F401  (see fuzz_game_status for why these are pre-imported)
from eventlet import tpool   # noqa: F401
import config                # noqa: F401

with atheris.instrument_imports():
    import ssh_manager


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    ssh_manager._parse_cfg(text)              # key="value" config lines
    ssh_manager._parse_upgradable(text)       # apt list --upgradable
    ssh_manager._parse_mods_available(text)   # mods-install listing
    ssh_manager._parse_mods_installed(text)   # mods-remove listing


def main():
    import sys
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
