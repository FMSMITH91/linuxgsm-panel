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


# ── The same rendering, with COLOUR kept ──────────────────────────────────────────────────────
# LinuxGSM colours its output — `[  OK  ]` green, `[ FAIL ]` red, `[ INFO ]` blue — and that is
# most of what makes a long `update` readable at a glance in a terminal. The panel threw all of it
# away, because every display path went through strip_escapes, which is right for the paths that
# PARSE this text and wrong for the one that shows it to a person.
#
# WHY THE LINE STAYS A STRING. The obvious shape is to return [(text, style), …] and send that to
# the browser. But the console's payload is a line of text at every layer — the socket push, the
# /api/console window, the browser's scrollback and its overlap de-duplication all key on line
# strings — so a structured payload would ripple through all four. Instead the line keeps its type
# and this narrows what may appear in it: CR and backspace are applied here (where the semantics
# already live and are already tested), every other escape is removed, and what survives is ONLY
# `ESC[<codes>m` with codes from the allowlist below. The browser then has one trivial pattern to
# split on rather than a terminal emulator to implement.
#
# WHY CR/BS CANNOT JUST RUN OVER THE RAW STRING. apply_carriage_returns does index arithmetic on
# the line, so an escape sequence left in place would be counted as several columns and the
# overwrite would land in the wrong spot — silently, and only on the lines that use \r, which is
# exactly the download-progress spool this was added to show. So the text is carried as (char,
# style) pairs while those rules are applied, and only coalesced into runs at the end.

# SGR parameters worth keeping. Colour, bold/dim/italic/underline/reverse/strike and their resets.
# An allowlist rather than "any digits": it bounds what the browser has to understand, and a code
# nothing renders is noise on the page rather than colour.
_SGR_ALLOWED = frozenset(
    [0, 1, 2, 3, 4, 7, 9, 21, 22, 23, 24, 27, 29, 39, 49]
    + list(range(30, 38)) + list(range(40, 48))
    + list(range(90, 98)) + list(range(100, 108))
)

# One pass over the line: an SGR sets style, any other escape is dropped, everything else is text.
_TOKEN_RE = re.compile(
    r"(?P<sgr>\x1b\[(?P<codes>[0-9;]*)m)"
    r"|(?P<osc>\x1b\][^\x07\x1b]*(?:\x07|\x1b\\))"
    r"|(?P<csi>\x1b\[[0-9;?]*[ -/]*[@-~])"
    r"|(?P<esc2>\x1b[ -/]*[0-~])"
)


def _sgr_apply(style, codes):
    """The style after an SGR. `style` is a tuple of active codes, oldest first.

    A reset (0, or an empty parameter list — `ESC[m` means `ESC[0m`) clears everything; 39/49
    clear just the foreground/background. Anything else is appended, and a repeat of the same code
    is not added twice, so a spool that re-asserts its colour on every line does not grow an
    unbounded style."""
    out = list(style)
    nums = []
    for part in (codes or "0").split(";"):
        part = part.strip()
        nums.append(int(part) if part.isdecimal() else 0)   # `ESC[;32m` — an empty field is 0
    for n in nums:
        if n == 0:
            out = []
        elif n not in _SGR_ALLOWED:
            continue
        elif n == 39:
            out = [c for c in out if not (30 <= c <= 37 or 90 <= c <= 97)]
        elif n == 49:
            out = [c for c in out if not (40 <= c <= 47 or 100 <= c <= 107)]
        elif n not in out:
            out.append(n)
    return tuple(out)


def render_line_colour(line):
    """One line as it would appear on screen, with colour kept as canonical `ESC[<codes>m`.

    Same rendering rules as render_line — escapes removed, `\\r` overwrites, backspaces applied —
    except that SGR is carried through instead of dropped. Returns a plain string; the only
    control bytes that can survive are the SGR sequences this function writes itself."""
    if not line:
        return line
    # (char, style) pairs, so the overwrite rules below count COLUMNS and not escape bytes.
    cells, style, col = [], (), 0
    pos = 0
    for m in _TOKEN_RE.finditer(line):
        text, pos = line[pos:m.start()], m.end()
        for ch in text:
            col = _put(cells, col, ch, style)
        if m.group("sgr") is not None:
            style = _sgr_apply(style, m.group("codes"))
    for ch in line[pos:]:
        col = _put(cells, col, ch, style)
    # A lone ESC that completed none of the grammars above — a log read mid-write, or an authored
    # byte from a player name. strip_escapes drops those and so does this: the guarantee that no
    # control byte reaches the page except the SGR written here is the whole point.
    cells = [c for c in cells if c[0] != "\x1b"]
    return _coalesce(cells)


def _put(cells, col, ch, style):
    """Write one character at the cursor and return the new column. `\\r` returns to column 0
    WITHOUT erasing (see apply_carriage_returns); `\\b` steps back over the previous cell."""
    if ch == "\r":
        return 0
    if ch == "\b":
        return max(0, col - 1)
    if col < len(cells):
        cells[col] = (ch, style)
    else:
        cells.append((ch, style))
    return col + 1


def _coalesce(cells):
    """(char, style) pairs back into a string, emitting an SGR only where the style CHANGES.

    Each sequence is ABSOLUTE — the full active set, not a delta — so a run never depends on what
    the reader happens to have open and cannot leak its colour into the next one."""
    out, cur = [], ()
    for ch, style in cells:
        if style != cur:
            out.append("\x1b[0m" if not style
                       else "\x1b[" + ";".join(str(c) for c in style) + "m")
            cur = style
        out.append(ch)
    if cur:
        out.append("\x1b[0m")      # never end a line mid-style
    return "".join(out)


def render_colour(text):
    """Multi-line text as it would appear on screen, colour kept. See render_line_colour."""
    if not text:
        return text
    return "\n".join(render_line_colour(ln) for ln in text.replace("\r\n", "\n").split("\n"))
