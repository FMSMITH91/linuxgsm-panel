#!/usr/bin/env python3
"""Atheris fuzz harness: LinuxGSM config / apt / mod-list parsers (ssh_manager).

Each parses text produced on a remote host — a LinuxGSM `.cfg`, `apt list --upgradable`, and the
mods-install / mods-remove listings. All are best-effort and must never raise on malformed input.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_config.py -max_total_time=60 tests/fuzz/corpus/config
"""
import importlib
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

for _dep in ("paramiko", "eventlet.tpool", "config"):   # pre-load uninstrumented (see fuzz_game_status)
    importlib.import_module(_dep)

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
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
