"""V8 precise coverage -> LCOV line coverage, for tools/js_coverage/run.py.

Pure functions over plain data, standard library only, so the unit suite can check them without a
browser. run.py collects the inputs from Chrome over the DevTools protocol:

  * `locations`: every place V8 can stop in a file — Debugger.getPossibleBreakpoints over the whole
    script. That is V8's own answer to "which lines hold code", so a blank line, a comment, or the
    continuation of a statement is not a line here, and cannot count for or against a file.
  * `takes`: the function list of each Profiler.takePreciseCoverage for that file. Every take
    resets V8's counters, so the counts of a file are the SUM over its takes.

WHY NOT v8-to-istanbul (the usual route, via node). It makes every physical line of a file a
statement: a blank line or a comment line starts "covered" and is set to a range's count only when
a range spans it whole. This panel's JavaScript is commented at length, so a comment block inside a
function that ran would read as covered code, and one inside a function that did not would read as
missed code — the number would measure the comments as much as the code.

HOW A LOCATION GETS ITS COUNT. V8's ranges nest: a function's first range is the whole function,
and the block ranges inside it override the parts that ran a different number of times (a branch
not taken is a nested range with count 0). So the count at an offset is the count of the INNERMOST
range that contains it. Ranges are half-open [startOffset, endOffset), in UTF-16 code units, the
unit V8 measures a script in.

A line is hit when any location on it ran: `x ? a() : b()` with only a() taken is a hit line, as it
is for coverage.py and for istanbul's line counts.
"""
import re

# The line terminators of ECMAScript. V8 numbers lines by these, not by Python's splitlines (which
# also breaks on \v, \f, \x1c-\x1e and \x85, none of which end a line in JavaScript).
_JS_EOL = re.compile("\r\n|\r|\n|\u2028|\u2029")


def _utf16_len(text):
    return len(text.encode("utf-16-le")) // 2


def line_starts(source):
    """Return the UTF-16 offset at which each line of `source` begins (index 0: V8's line 0)."""
    starts, pos, last = [0], 0, 0
    for m in _JS_EOL.finditer(source):
        pos += _utf16_len(source[last:m.end()])
        last = m.end()
        starts.append(pos)
    return starts


def offsets_of(locations, starts):
    """Map [(line0, col0)] to [offset] for the same list, in UTF-16 units."""
    return [starts[ln] + col for ln, col in locations]


def _ranges(functions):
    """Every range of one take, outer-first: start ascending, and the longer first at a tie."""
    return sorted(((r["startOffset"], r["endOffset"], r["count"])
                   for f in functions for r in f.get("ranges", ())),
                  key=lambda r: (r[0], -r[1]))


def _sweep(ranges, offsets, order):
    """Assign each offset (visited in `order`, ascending) the count of its innermost range."""
    out = [0] * len(offsets)
    stack, i = [], 0
    for k in order:
        off = offsets[k]
        while i < len(ranges) and ranges[i][0] <= off:
            while stack and stack[-1][1] <= ranges[i][0]:
                stack.pop()
            stack.append(ranges[i])
            i += 1
        while stack and stack[-1][1] <= off:
            stack.pop()
        out[k] = stack[-1][2] if stack else 0
    return out


def counts_at(functions, offsets):
    """Return the execution count at each offset, from one take's function list for one script.

    One sweep: ranges sorted outer-first (start ascending, end descending) are pushed on a stack as
    the sweep passes their start and popped once it passes their end, so the top of the stack is
    the innermost open range. O((ranges + offsets) log) rather than a scan per offset.
    """
    return _sweep(_ranges(functions), offsets, sorted(range(len(offsets)), key=offsets.__getitem__))


class FileCounts:
    """One file's running totals: a count per V8 location, summed take by take as takes arrive.

    Kept per location rather than per take, so a run of a thousand navigations holds one list of
    integers per file instead of every function list V8 returned.
    """

    def __init__(self, locations, source):
        """Count at `locations` (0-based (line, column) pairs, V8's) in `source`."""
        starts = line_starts(source)
        # A file that ends with a line terminator has one more line start than it has lines, and
        # V8 puts the script's own end there: a location on a line that is not in the file, which
        # a report must not list (it would read as a line of code nobody can find).
        ends_with_eol = bool(source) and source[-1] in "\r\n\u2028\u2029"
        lines = len(starts) - 1 if ends_with_eol else len(starts)
        self.locations = [(ln, col) for ln, col in locations if 0 <= ln < lines]
        self.offsets = offsets_of(self.locations, starts)
        self.order = sorted(range(len(self.offsets)), key=self.offsets.__getitem__)
        self.totals = [0] * len(self.offsets)
        self.takes = 0

    def add(self, functions):
        """Add one take's function list for this file."""
        self.takes += 1
        ranges = _ranges(functions)
        if not any(r[2] for r in ranges):
            return      # nothing ran since the last take: nothing to add
        for k, c in enumerate(_sweep(ranges, self.offsets, self.order)):
            self.totals[k] += c

    def hits(self):
        """Return {line1: hits} for every line holding a location: the most any of them ran."""
        hits = {}
        for (ln, _col), c in zip(self.locations, self.totals):
            hits[ln + 1] = max(hits.get(ln + 1, 0), c)
        return hits


def line_hits(locations, source, takes):
    """Return {line1: hits} for every line that holds a location, summed over `takes`.

    `locations` are 0-based (lineNumber, columnNumber) pairs as the protocol reports them; the
    result is keyed by 1-based line, as LCOV is. A line's hits are the most any location on it
    ran — the line ran that many times at least.
    """
    fc = FileCounts(locations, source)
    for functions in takes:
        fc.add(functions)
    return fc.hits()


def to_lcov(files):
    """Return LCOV text for {repo-relative path: {line1: hits}}, files in sorted order.

    Line records only (DA, LF, LH): they are what Codacy reads, and what this harness measures
    faithfully. No FN records — V8 reports a function it never compiled only as part of the range
    of the function around it, so a function count here would undercount the functions a file has
    by exactly the ones that never ran.
    """
    out = []
    for path in sorted(files):
        hits = files[path]
        out.append("TN:")
        out.append("SF:%s" % path)
        for line in sorted(hits):
            out.append("DA:%d,%d" % (line, hits[line]))
        out.append("LF:%d" % len(hits))
        out.append("LH:%d" % sum(1 for h in hits.values() if h > 0))
        out.append("end_of_record")
    return "\n".join(out) + "\n" if out else ""


def missed_spans(hits, limit=None):
    """Return runs of consecutive executable lines with no hits, largest first.

    [(first, last, lines)]: what the summary lists under each file, as the answer to "what would
    raise this number".
    """
    spans, run = [], []
    for line in sorted(hits):
        if hits[line] == 0:
            run.append(line)
            continue
        if run:
            spans.append((run[0], run[-1], len(run)))
            run = []
    if run:
        spans.append((run[0], run[-1], len(run)))
    spans.sort(key=lambda s: (-s[2], s[0]))
    return spans[:limit] if limit else spans
