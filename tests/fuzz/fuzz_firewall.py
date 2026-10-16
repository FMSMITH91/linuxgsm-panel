#!/usr/bin/env python3
r"""Atheris fuzz harness: UFW status parsers (ssh_manager).

Mirrors the real `remote_ufw_status` pipeline WITHOUT the network: fuzzed text is split into lines,
each line goes through `_parse_ufw_rule`, and lines matching UFW's numbered-rule format are grouped
by `_group_ufw_rules` exactly as the live parser feeds it (rule numbers come from the `\d+` capture,
never arbitrary strings — feeding a non-numeric num would be a harness bug, not a real input). The
same text also goes whole through `hosts._ufw_first_public_rule`, the read-back the rate limit and
the lockout guards decide by, for a fuzzed port and protocol, and through `hosts._r22b_not_limit`,
which reads it in both address families.

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

# Pre-load uninstrumented (see fuzz_game_status).
for _dep in ("paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
             "sqlalchemy.dialects.sqlite", "panel.core.config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    from panel.ops import ssh_manager
    from panel.ops.ssh_manager import firewall as _fw, hosts as _hosts

# The line regex remote_ufw_status itself uses to pull "[ N] <detail>" numbered rules — taken from
# the module, not copied: the copy that sat here was the old `\s*(.*)` shape production replaced
# for its quadratic backtracking, so the production regex was never the one fuzzed.
_RULE_RE = _fw._UFW_NUMBERED_RE


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    port = fdp.ConsumeIntInRange(0, 65535)
    proto = fdp.PickValueInList(["tcp", "udp"])
    unresolved, scoped = fdp.ConsumeBool(), fdp.ConsumeBool()
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    _hosts._ufw_first_public_rule(text, port, proto, unresolved=unresolved, scoped=scoped)
    # And both families, as the rate limit reads them (review 1015d): the call above is IPv4 only
    # (v6 defaults to False), so every `(v6)` row was filtered out before it was matched, and the
    # IPv6 half of the read-back was parsed but never matched under fuzzing. No extra bytes are
    # consumed, so the committed seed decodes as it did.
    _hosts._r22b_not_limit(text, port, proto)
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
