"""Per-part wall time, peak memory and processes started, for the unit runner; opt-in.

UNIT_PART_TIMES=<file> makes the runner time each part it imports and, after the last one, write
{"ms": {part: milliseconds}, "cpu_ms", "rss_mb", "procs", "load1": {...}} to that file and print one summary
block (the slowest parts first), which is how CI's log shows where a shard spent its time. Unset or
empty, nothing is timed, written or printed: the run is what it was.

"procs" is how many processes the machine started while the part ran (the kernel's fork count in
/proc/stat), so it counts every process a part's bash, node or git starts too, and anything else
the machine ran beside it. "cpu_ms" is the CPU this process and its finished children used in it: a
part whose wall time is far above its CPU time was WAITING (a timeout, a lock, a starved machine).
"rss_mb" is this process's peak resident memory after the part, in MB, and "load1" the machine's
1-minute load average when it ended.

`python tests/unit/timing.py <times.json> [shard_weights.json]` rewrites the shard weights
(tests/unit/shard.py) from one unsplit run's times: every part keeps its measured milliseconds.
Nothing here imports the panel or eventlet.
"""
import json
import os
import resource
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
SUMMARY_HEAD = "unit part times (slowest first; wall ms, CPU ms, peak MB, processes started, 1-min load after):"
TOP = 40


def _forks():
    """Processes the machine has started since boot (the 'processes' line of /proc/stat), or None."""
    try:
        with open("/proc/stat", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("processes "):
                    return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def _cpu_ms():
    """CPU this process and its finished children have used, in milliseconds."""
    me, kids = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return int((me.ru_utime + me.ru_stime + kids.ru_utime + kids.ru_stime) * 1000)


def _load1():
    """The machine's 1-minute load average, or None."""
    try:
        return os.getloadavg()[0]
    except OSError:
        return None


def _rss_mb():
    """Peak resident memory of this process in MB (ru_maxrss is in KB on Linux)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024


class PartClock:
    """Times each part the runner imports, when UNIT_PART_TIMES names a file; does nothing otherwise."""

    def __init__(self, environ):
        """Read UNIT_PART_TIMES from `environ`; an empty or missing value turns every method into a no-op."""
        self.path = environ.get("UNIT_PART_TIMES") or None
        self.rows = []
        self._at = None

    def start(self, part):
        """Mark the start of `part`."""
        if self.path:
            self._at = (part, time.monotonic(), _forks(), _cpu_ms())

    def stop(self):
        """Record the part started last: its milliseconds, the peak memory so far, the processes started."""
        if self.path and self._at:
            part, began, forks, cpu = self._at
            now = _forks()
            self.rows.append((part, int(round((time.monotonic() - began) * 1000)), _rss_mb(),
                              now - forks if None not in (now, forks) else None, _cpu_ms() - cpu, _load1()))
            self._at = None

    def report(self, out=None):
        """Write the times file and print the summary block; nothing when timing is off."""
        if not self.path:
            return None
        data = {"ms": {r[0]: r[1] for r in self.rows}, "rss_mb": {r[0]: r[2] for r in self.rows},
                "procs": {r[0]: r[3] for r in self.rows}, "cpu_ms": {r[0]: r[4] for r in self.rows},
                "load1": {r[0]: r[5] for r in self.rows}}
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        out = out or sys.stdout
        total = sum(r[1] for r in self.rows)
        print("\n" + SUMMARY_HEAD, file=out)
        for part, ms, mb, procs, cpu, load in sorted(self.rows, key=lambda r: (-r[1], r[0]))[:TOP]:
            print("  %-8s %8d %8d %6d %8s %6s" % (part, ms, cpu, mb, "?" if procs is None else procs,
                                                "?" if load is None else "%.1f" % load), file=out)
        print("  %d parts, %.1f s in all, %.1f s of CPU" % (len(self.rows), total / 1000.0,
                                                          sum(r[4] for r in self.rows) / 1000.0), file=out)
        return data


def weights_from(times, about):
    """The shard_weights.json document for one unsplit run's times ({part: ms})."""
    return {"about": about, "ms": {p: int(ms) for p, ms in sorted(times.items(), key=lambda kv: int(kv[0][4:]))}}


def main(argv):
    """Rewrite shard_weights.json from a UNIT_PART_TIMES file of an unsplit run."""
    if not 2 <= len(argv) <= 3:
        print("usage: timing.py <times.json> [shard_weights.json]", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        times = json.load(fh)["ms"]
    dest = argv[2] if len(argv) == 3 else os.path.join(_HERE, "shard_weights.json")
    about = ("Seconds each unit part took (in milliseconds), measured on one local run of the whole suite on %s "
             "(UNIT_PART_TIMES, tests/unit/timing.py). tests/unit/shard.py reads them to even out the shards; a part "
             "not listed counts its FALLBACK_MS. Remeasure when the shards drift apart: the plan changes, no check "
             "does." % time.strftime("%Y-%m-%d"))
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(weights_from(times, about), fh, indent=1)
        fh.write("\n")
    print("wrote %d parts to %s" % (len(times), dest))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
