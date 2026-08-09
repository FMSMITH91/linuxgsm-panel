#!/usr/bin/env python3
"""Atheris fuzz harness: the crontab / cron-status parsers (ssh_manager).

Everything these read comes off a REMOTE host: the game user's crontab, and the base64-framed
status blob the panel's own cron wrapper writes after each run. Both are outside the panel's
control — a crontab can be edited by hand on the box, and the status blob carries whatever a
LinuxGSM command printed to stderr, which for an update means text fetched off the internet.

The Scheduled Tasks page renders all of it, and the panel's cron-status path has already produced
one real bug this way (a `tr` that missed \\r truncated every record at the transport, so errors
silently read as empty). These parsers are best-effort and must never raise: a crash here takes
out the whole page rather than one row.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_cron.py -max_total_time=60 tests/fuzz/corpus/cron
"""
import importlib
import os
import sys

import atheris

# Running `python tests/fuzz/fuzz_x.py` puts tests/fuzz (not the project root) on sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Pre-load ssh_manager's heavy dependencies UNINSTRUMENTED so instrument_imports() covers only the
# parsers (faster, and the coverage signal stays on target).
for _dep in ("paramiko", "eventlet.tpool", "config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    import ssh_manager


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    ssh_manager._split_cron_line(text)              # "*/5 * * * * cmd" -> (schedule, command)
    ssh_manager._unwrap_cron_command(text)          # strips the panel's recorder wrapper
    ssh_manager._cron_role(text, "gm", "gmserver")  # autostart / daily-restart label
    ssh_manager._cron_line_managed(text, "gm", "gmserver")
    ssh_manager._cron_log_text(text)                # lenient base64 decode of a status blob
    ssh_manager._clean_cron_error(text)             # terminal-render + trim for display


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
