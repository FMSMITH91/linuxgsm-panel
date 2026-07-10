#!/usr/bin/env python3
"""Atheris fuzz harness: fail2ban top-offenders parser (system_ops).

`_parse_top_ips` turns the tab-separated counting pipeline output (built from /var/log/fail2ban.log)
into ranked offender rows. The log is attacker-influenced input, so the parser must never raise.

Run locally:
    pip install atheris
    python tests/fuzz/fuzz_fail2ban.py -max_total_time=60 tests/fuzz/corpus/fail2ban
"""
import atheris

# system_ops imports only the standard library, so it can be instrumented directly.
with atheris.instrument_imports():
    import system_ops


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    # banned_now (a set of IPs) and blocked (ip -> tag) come from other trusted calls; keep them
    # simple so the fuzzer explores the untrusted `out` text, which is the real parse surface.
    system_ops._parse_top_ips(text, set(), {})


def main():
    import sys
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
