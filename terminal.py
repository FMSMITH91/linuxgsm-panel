"""Rendering terminal output as a terminal would.

Game-server consoles, LinuxGSM and JLine all write control sequences into their logs, and the panel
shows that text to people. Every module that displays or parses such output needs the same treatment,
so it lives here once rather than as a regex per call site.

It exists because it had drifted: four incompatible ANSI patterns across 16 sites (one SGR-only, so
`\\x1b[K` survived and rendered as a literal "[K"; one CSI-only, so `\\x1b>` survived and rendered as
">"), and two carriage-return renderers implementing OPPOSITE rules — each documenting the other as
wrong. The overwrite semantics below are the correct ones: a `\\r` returns the cursor to column 0, it
does not start a new line and it does not erase what it does not overwrite.

No imports beyond `re`, so anything in the codebase can use it.
"""
import re

# CSI: ESC [ params intermediates final. Covers colour (m), erase-line (K), cursor moves, and the
# private modes JLine uses (\x1b[?2004h bracketed paste, \x1b[?1l app-cursor).
CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# OSC: ESC ] ... terminated by BEL or ESC \ (window titles).
OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
# Two-byte escapes: ESC followed by one character — ESC>, ESC=, ESC(B. A CSI-only pattern leaves
# these behind, and they render as stray ">" / "=>" text.
ESC2_RE = re.compile(r"\x1b[ -/]*[0-~]")


def strip_escapes(text):
    """`text` with OSC, CSI and two-byte escape sequences removed. Control CHARACTERS (\\r, \\b) are
    left alone — they carry rendering meaning; see apply_carriage_returns / apply_backspaces."""
    if not text:
        return text
    text = ESC2_RE.sub("", CSI_RE.sub("", OSC_RE.sub("", text)))
    # Any ESC still standing is a sequence that never completed: a log read mid-write, or ESC
    # followed by something none of the three grammars accept (\x1b\t, \x1b\x00, a trailing \x1b).
    # Player names and chat reach this text, so those bytes are authored, not just accidental. They
    # carry no rendering meaning on their own, and the one guarantee this module owes its callers is
    # that control bytes do not reach the page.
    return text.replace("\x1b", "")


def apply_carriage_returns(line):
    """One line with `\\r` applied: the cursor returns to column 0 and what follows OVERWRITES from
    there, leaving any tail it does not cover.

    NOT `line.split("\\r")[-1]`. That looks equivalent and is not: a line merely ENDING in `\\r` —
    every line of a CRLF log — yields "" and the content is silently lost."""
    if not line or "\r" not in line:
        return line
    buf = ""
    for seg in line.split("\r"):
        buf = seg + buf[len(seg):]
    return buf


def apply_backspaces(line):
    """One line with BS (0x08) applied, as a terminal renders it. JLine echoes a typed command by
    rewriting it in place as it applies syntax colour, so without this every erased attempt remains:
    "say hi" arrives as "ssasay  hi"."""
    if not line or "\b" not in line:
        return line
    out = []
    for ch in line:
        if ch == "\b":
            if out:
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


def render_line(line):
    """One line as it would appear on screen: escapes stripped, `\\r` overwrites and backspaces
    applied."""
    return apply_backspaces(apply_carriage_returns(strip_escapes(line)))


def render(text):
    """Multi-line text as it would appear on screen. `\\r\\n` is a line break; a bare `\\r` is an
    overwrite within its line."""
    if not text:
        return text
    return "\n".join(render_line(ln) for ln in text.replace("\r\n", "\n").split("\n"))
