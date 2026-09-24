#!/usr/bin/env python3
"""Atheris fuzz harness: the terminal renderer that turns raw console output into panel text.

Everything terminal.py sees is UNTRUSTED and, unlike the other targets, partly attacker-*authored*:
a game console echoes player names, chat and RCON replies, so a player picks the bytes — escape
sequences, lone carriage returns, backspaces, half-formed CSI/OSC introducers, invalid UTF-8. The
rendered result is then shown in the panel's console view.

Two properties under test:
  1. No input may make a renderer raise (the console poller and the cron-error path both call these,
     and a raise there breaks a page rather than one line).
  2. render() must not emit an ESC (0x1b) or a bare CR — those are exactly what it exists to strip,
     and leaking one through means raw control bytes reach the browser. render_colour(), which KEEPS
     colour, may emit an ESC only as the canonical SGR (`ESC[<digits;>m`) it writes itself.

render_colour is the renderer the LIVE console uses — the poller's _console_push and
app._clean_console_text call it, not render() — and it is the one that parses player-authored SGR
parameters as integers. It was not called here, so the path players actually reach had no coverage.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_console.py -max_total_time=60 tests/fuzz/corpus/console
"""
import os
import re
import sys

import atheris

# Running `python tests/fuzz/fuzz_x.py` puts tests/fuzz (not the project root) on sys.path, so make
# the project root importable before importing the panel's modules.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

with atheris.instrument_imports():
    from panel.core import terminal

# The only ESC render_colour may emit: an SGR of the form it writes itself.
_SGR_OUT = re.compile(r"\x1b\[[0-9;]*m")


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    terminal.strip_escapes(text)
    terminal.apply_carriage_returns(text)
    terminal.apply_backspaces(text)
    terminal.render_line(text)

    out = terminal.render(text)
    # The whole point of the renderer: control bytes must not survive into the panel.
    if "\x1b" in out:
        raise AssertionError("render() leaked an ESC byte")
    if "\r" in out:
        raise AssertionError("render() leaked a carriage return")

    coloured = terminal.render_colour(text)
    if "\x1b" in _SGR_OUT.sub("", coloured):
        raise AssertionError("render_colour() leaked an ESC outside an SGR it wrote")
    if "\r" in coloured:
        raise AssertionError("render_colour() leaked a carriage return")


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
