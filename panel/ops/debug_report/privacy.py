"""The report's privacy backstop: pseudonymise known names, classify IPs, normalise paths (R72, R73).

Owner: builder B1. Sections are written never to print identifying values (see _base.py); this runs
over the finished text anyway, because log lines and installer output are free text.

scrub(ctx, text) -> text   applied by the assembler to the whole report and the summary.
footer(ctx) -> [lines]     what was pseudonymised and what was kept, stated truthfully.
"""


def scrub(ctx, text):
    """Not implemented yet: returns the text unchanged."""
    return text


def footer(ctx):
    """Not implemented yet."""
    return []
