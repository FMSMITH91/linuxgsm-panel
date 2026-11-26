#!/usr/bin/env python3
"""Add the LCOV reports of the js coverage parts into one report, and write its summary.

    python tools/js_coverage/merge.py --out lcov.info [--summary js-coverage.txt] \
        [--part-summary js-coverage.p1.txt ...] lcov.p1.info lcov.p2.info ...

CI walks the panel in parallel parts (run.py --part I/N), each in its own browser, so each part's
report counts only what its own pages ran. Here they are added up, file by file (SF): a line's hits
(DA) are the sum over the parts, and a file's lines are the union of theirs, so a line any part ran is
hit; LF and LH are counted again from the merged lines. FN/FNDA and BRDA records, which run.py does
not write, are merged the same way when a report has them (a function's or a branch's counts summed,
"-" when no part ran it) and their totals (FNF/FNH, BRF/BRH) counted again.

Standard library only, beside v8_lcov.missed_spans for the summary's missed runs: CI's verdict job
runs it with the runner's own python3 and installs nothing. Anything that is not an LCOV record, or a
record outside an SF block, stops it with exit status 2 rather than merging a part it misread.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import v8_lcov  # noqa: E402

_TOTALS = {"LF", "LH", "FNF", "FNH", "BRF", "BRH", "TN"}   # counted again here, or dropped


class LcovError(ValueError):
    """A part's report is not LCOV this merge can read."""


def _new_file():
    return {"lines": {}, "fn_line": {}, "fn_hits": {}, "branches": {}}


def _add_branch(rec, val):
    line, block, branch, taken = val.split(",")
    key = (int(line), int(block), int(branch))
    if taken != "-":
        rec["branches"][key] = (rec["branches"].get(key) or 0) + int(taken)
    else:
        rec["branches"].setdefault(key, None)


def _add_record(rec, tag, val):
    """Add one record of an SF block into `rec`."""
    if tag == "DA":
        line, hits = val.split(",")[:2]
        rec["lines"][int(line)] = rec["lines"].get(int(line), 0) + int(hits)
    elif tag == "FN":
        line, name = val.split(",", 1)
        rec["fn_line"].setdefault(name, int(line))
        rec["fn_hits"].setdefault(name, 0)
    elif tag == "FNDA":
        hits, name = val.split(",", 1)
        rec["fn_hits"][name] = rec["fn_hits"].get(name, 0) + int(hits)
    elif tag == "BRDA":
        _add_branch(rec, val)
    elif tag not in _TOTALS:
        raise LcovError("not an LCOV record: %s" % tag)


def _open_block(files, line):
    """Read a line outside an SF block: skip a TN record, open an SF block, refuse anything else."""
    tag, sep, val = line.partition(":")
    if tag == "TN":
        return None
    if tag == "SF" and sep:
        return files.setdefault(val, _new_file())
    raise LcovError("a record outside an SF block")


def _take_line(files, cur, line):
    """Read one line of a report; return the SF block it leaves open (None outside one)."""
    if not line.strip():
        return cur
    if cur is None:
        return _open_block(files, line)
    if line == "end_of_record":
        return None
    tag, sep, val = line.partition(":")
    if not sep:
        raise LcovError("not an LCOV record")
    _add_record(cur, tag, val)
    return cur


def add_report(files, text, name="report"):
    """Add one LCOV report's records into `files` ({path: record}); return `files`."""
    cur = None
    for no, line in enumerate(text.splitlines(), 1):
        try:
            cur = _take_line(files, cur, line)
        except (LcovError, ValueError) as e:
            raise LcovError("%s line %d: %s (%r)" % (name, no, e, line[:80])) from None
    if cur is not None:
        raise LcovError("%s ends inside an SF block" % name)
    return files


def _fn_lines(rec):
    names = sorted(rec["fn_line"], key=lambda n: (rec["fn_line"][n], n))
    out = ["FN:%d,%s" % (rec["fn_line"][n], n) for n in names]
    out += ["FNDA:%d,%s" % (rec["fn_hits"][n], n) for n in names]
    out += ["FNF:%d" % len(names), "FNH:%d" % sum(1 for n in names if rec["fn_hits"].get(n))]
    return out


def _branch_lines(rec):
    br = rec["branches"]
    out = ["BRDA:%d,%d,%d,%s" % (k + ("-" if br[k] is None else br[k],)) for k in sorted(br)]
    out += ["BRF:%d" % len(br), "BRH:%d" % sum(1 for v in br.values() if v)]
    return out


def to_lcov(files):
    """Return the merged report in run.py's layout, with FN and BRDA records only where a part had them."""
    out = []
    for path in sorted(files):
        rec = files[path]
        out += ["TN:", "SF:%s" % path]
        out += _fn_lines(rec) if rec["fn_line"] else []
        out += _branch_lines(rec) if rec["branches"] else []
        out += ["DA:%d,%d" % (line, rec["lines"][line]) for line in sorted(rec["lines"])]
        out += ["LF:%d" % len(rec["lines"]), "LH:%d" % sum(1 for h in rec["lines"].values() if h > 0)]
        out.append("end_of_record")
    return "\n".join(out) + "\n" if out else ""


def _row(path, lines):
    """Return one file's row of the table, its lines and its lines hit."""
    f, h = len(lines), sum(1 for v in lines.values() if v)
    spans = ", ".join("%d-%d" % (a, b) if a != b else str(a) for a, b, _n in v8_lcov.missed_spans(lines, 3))
    row = "%-34s %5d %5d %6.1f%%%s  %s" % (path, f, h, 100.0 * h / f if f else 0.0,
                                          "" if h else "  (no line ran)", spans)
    return row, f, h


def _after_total(text):
    """Return what a part's own summary says after its TOTAL (its table is in the merged one)."""
    return text.split("\nTOTAL", 1)[1].split("\n", 1)[-1] if "\nTOTAL" in text else text


def summary_text(files, part_summaries=()):
    """Return the merged lines' per-file table and TOTAL, then what each part reported broken."""
    out, total, hit = ["%-34s %5s %5s %7s  %s" % ("file", "lines", "hit", "cover", "largest missed runs")], 0, 0
    for path in sorted(files):
        row, f, h = _row(path, files[path]["lines"])
        out.append(row)
        total, hit = total + f, hit + h
    out.append("%-34s %5d %5d %6.1f%%" % ("TOTAL", total, hit, 100.0 * hit / total if total else 0.0))
    for name, text in part_summaries:
        out += ["", "── %s ──" % name, _after_total(text).rstrip("\n")]
    return "\n".join(out) + "\n", hit


def parse_args(argv):
    """Parse the command line: the parts' reports, and where the merged ones go."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--summary", default="")
    ap.add_argument("--part-summary", action="append", default=[])
    ap.add_argument("reports", nargs="+")
    return ap.parse_args(argv)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def main(argv=None):
    """Merge the reports; exit 2 when one is missing or not LCOV, 3 when no line ran in any."""
    args = parse_args(argv)
    files = {}
    try:
        for path in args.reports:
            add_report(files, _read(path), os.path.basename(path))
    except (OSError, LcovError) as e:
        print("merge: %s" % e, file=sys.stderr)
        return 2
    parts = [(os.path.basename(p), _read(p)) for p in args.part_summary if os.path.isfile(p)]
    text, hit = summary_text(files, parts)
    # The tool's own --out and --summary (CI passes fixed names).
    with open(args.out, "w", encoding="utf-8") as fh:  # NOSONAR - the tool's own --out
        fh.write(to_lcov(files))
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as fh:  # NOSONAR - the tool's own --summary
            fh.write(text)
    print(text, end="")
    if hit == 0:
        print("merge: no line ran in any part", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
