#!/usr/bin/env python3
"""Atheris fuzz harness: UFW status parsers (ssh_manager).

Mirrors the real `remote_ufw_status` pipeline WITHOUT the network: fuzzed text is split into lines,
each line goes through `_parse_ufw_rule`, and lines matching UFW's numbered-rule format are grouped
by `_group_ufw_rules` exactly as the live parser feeds it (rule numbers come from the `\\d+` capture,
never arbitrary strings — feeding a non-numeric num would be a harness bug, not a real input).

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_firewall.py -max_total_time=60 tests/fuzz/corpus/firewall
"""
import importlib
import os
import re
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

for _dep in ("paramiko", "eventlet.tpool", "config"):   # pre-load uninstrumented (see fuzz_game_status)
    importlib.import_module(_dep)

with atheris.instrument_imports():
    import ssh_manager

# The exact line regex remote_ufw_status uses to pull "[ N] <detail>" numbered rules.
_RULE_RE = re.compile(r"^\s*\[\s*(\d+)\]\s*(.*)$")


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    rules = []
    for line in text.split("\n"):
        ssh_manager._parse_ufw_rule(line)             # per-line field parser
        m = _RULE_RE.match(line)
        if m:
            detail = re.sub(r"\s{2,}", "  ", m.group(2).strip())
            rules.append({"num": m.group(1), "detail": detail})
    ssh_manager._group_ufw_rules(rules)               # IPv4/IPv6 grouping + friendly fields


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
