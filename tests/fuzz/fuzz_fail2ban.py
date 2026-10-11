#!/usr/bin/env python3
"""Atheris fuzz harness: fail2ban top-offenders parser (system_ops).

`_parse_top_ips` turns the tab-separated counting pipeline output (built from /var/log/fail2ban.log)
into ranked offender rows. The log is attacker-influenced input, so the parser must never raise.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_fail2ban.py -max_total_time=60 tests/fuzz/corpus/fail2ban
"""
import importlib
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Pre-load the heavy dependencies UNINSTRUMENTED (see fuzz_game_status). This said "system_ops
# imports only the standard library, so it can be instrumented directly", which stopped being true
# when system_ops began importing eventlet.patcher (#403): Atheris then instrumented 329 modules
# for this target (eventlet, dnspython, asyncio, cryptography...) against 20 for its siblings, and
# ClusterFuzzLite killed it as "process timed out" on every PR and nightly run while the job stayed
# green. The same list as the four ssh_manager harnesses; part29 holds all five to it.
for _dep in ("paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
             "sqlalchemy.dialects.sqlite", "panel.core.config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    from panel.ops import system_ops


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    # The pipeline has two halves and both parse untrusted text. _tally_f2b_lines reads the RAW
    # fail2ban log (from a remote host, over SSH, for the remote report) and regex-matches
    # `[jail] Ban|Found <ip>` out of it; _parse_top_ips reads the tab-separated rows that produces.
    # Only the second was fuzzed, which left the half doing the actual matching — and the half that
    # moved into Python most recently, when the awk came out of the root pipeline — uncovered.
    system_ops._tally_f2b_lines(text, 20)
    # ...and feed the real tally through, so the two halves are also exercised as a pair.
    system_ops._parse_top_ips(system_ops._tally_f2b_lines(text, 5), set(), {})
    # banned_now (a set of IPs) and blocked (ip -> tag) come from other trusted calls; keep them
    # simple so the fuzzer explores the untrusted `out` text, which is the real parse surface.
    system_ops._parse_top_ips(text, set(), {})


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
