"""The fixed text and the parsing of the panel's live host reads.

ssh_manager runs them (host_live_metrics for the dashboard and the history sampler,
remote_live_metrics for a remote host page's live bars); what they print is read here, as plain code
with nothing to stub, like the interface rule in panel/ops/netdev.py.
"""
import logging

_log = logging.getLogger("panel.ssh")

# The host sample's awk (ssh_manager._core._HOST_SAMPLE_AWK) reads the rest of the host's figures
# straight from /proc after its per-user pass, where they were five more processes (free, nproc, and
# an awk each for loadavg, uptime and /proc/net/dev: 20 ms of the sample's 71 ms on the test box):
#   MEM     MemTotal and MemTotal - MemAvailable from /proc/meminfo, in bytes: the "used" free prints
#           since procps-ng 4 (Ubuntu 24.04), and what the host page's bars already show. /proc
#           labels are never translated, so the LC_ALL=C that free needed is gone with it;
#   LOAD    the three load averages, as /proc/loadavg writes them;
#   CORES   the online CPUs, the cpuN lines of /proc/stat (what nproc counts for an unpinned
#           process); not printed when none is found, which reads as 1 core, as before;
#   UPTIME  whole seconds of /proc/uptime;
#   NETIF   each interface's received and sent bytes, fields 1 and 9 after the name. The name is
#           glued to the first counter once it is large ("eth0:123456"), so the ":" becomes a space
#           before splitting. Filtered in panel/ops/netdev.py, where the rule can be tested.
# Byte counts go through printf "%.0f": mawk prints a large number with print in exponent form.
HOST_PROC_AWK = (
    'while ((getline l < "/proc/meminfo") > 0) { split(l, w, " "); if (w[1] == "MemTotal:") mt = w[2]; '
    'else if (w[1] == "MemAvailable:") ma = w[2] } close("/proc/meminfo"); '
    'if (mt > 0) printf "MEM %.0f %.0f\\n", mt * 1024, (mt - ma) * 1024; '
    'if ((getline l < "/proc/loadavg") > 0) { split(l, w, " "); print "LOAD", w[1], w[2], w[3] } '
    'close("/proc/loadavg"); '
    'while ((getline l < "/proc/stat") > 0) if (l ~ /^cpu[0-9]/) nc++; close("/proc/stat"); '
    'if (nc > 0) print "CORES", nc; '
    'if ((getline l < "/proc/uptime") > 0) { split(l, w, " "); printf "UPTIME %d\\n", w[1] } '
    'close("/proc/uptime"); '
    'while ((getline l < "/proc/net/dev") > 0) if (++nl > 2) { sub(/:/, " ", l); split(l, w, " "); '
    'print "NETIF", w[1], w[2], w[10] } close("/proc/net/dev"); '
)

# A remote host page's live read. The bars poll every 2 s; like the panel host's own read
# (system_ops.live_metrics), a steady poll takes ONE /proc/stat read and diffs it against the
# previous poll's, so the CPU figure is the average over the real poll interval and the command
# holds no 0.25 s window (it held the SSH channel and a pool thread 7.9 s a minute per open page).
# A cold start, a gap of 30 s or more, or a second caller within 0.5 s of the last read takes the
# two reads 0.25 s apart.
_REST = ("echo ===MEM; grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo; "
         "echo ===DISK; df -PB1 /")
ONE_READ = "echo ===B; grep '^cpu' /proc/stat; " + _REST
TWO_READS = "echo ===A; grep '^cpu' /proc/stat; echo ===B; sleep 0.25; grep '^cpu' /proc/stat; " + _REST
STEADY_MIN, STEADY_MAX = 0.5, 30


def steady(age):
    """Whether a previous read `age` seconds old (None: there is none) is the A side of this one."""
    return age is not None and STEADY_MIN <= age < STEADY_MAX


def keep_read(rid, rc, acc, age):
    """Whether this read's /proc/stat is kept as the next poll's A side.

    A read that answered, for a host with an id, and not a second caller's within STEADY_MIN of the
    last kept one (that would chain a tiny interval into the next poll's figure).
    """
    return rid is not None and rc == 0 and "cpu" in acc["B"] and (age is None or age >= STEADY_MIN)


def parse_sections(out):
    """A live read's output by section: {"A"/"B": {cpuN: jiffies}, "MEM": {...}, "disk"}."""
    section = None
    acc = {"A": {}, "B": {}, "MEM": {}, "disk": (0, 0)}
    for line in (out or "").splitlines():
        if line.startswith("==="):
            section = line[3:]
            continue
        parts = line.split()
        if parts:
            _section_line(section, parts, acc)
    return acc


def _section_line(section, parts, acc):
    """Fold one non-blank line of `section` into `acc`; a line of no known shape is skipped."""
    if section in ("A", "B") and parts[0].startswith("cpu") and len(parts) >= 8:
        acc[section][parts[0]] = [int(x) for x in parts[1:8]]
    elif section == "MEM" and len(parts) >= 2:
        _mem_line(parts, acc["MEM"])
    elif section == "DISK" and len(parts) >= 4 and parts[1].isdecimal():
        # df -PB1 data row: Filesystem 1B-blocks Used Available Use% Mounted (skip the header)
        acc["disk"] = (int(parts[1]), int(parts[2]))


def _mem_line(parts, mem):
    """One /proc/meminfo line into `mem`, in bytes; a value that is not a number is skipped."""
    try:
        mem[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB → bytes
    except ValueError:
        _log.debug("remote_live_metrics: ignored non-fatal error", exc_info=True)


def cpu_pct(a, b, n):
    """CPU% of /proc/stat line `n` between the A and B samples; 0.0 when either lacks it."""
    if n not in a or n not in b:
        return 0.0
    idle = b[n][3] - a[n][3]
    total = sum(b[n]) - sum(a[n])
    return round((1 - idle / total) * 100, 1) if total > 0 else 0.0


def core_names(a):
    """The per-core `cpuN` names in sample A, in core order."""
    return sorted((n for n in a if n != "cpu" and n.startswith("cpu")),
                  key=lambda x: int(x[3:]) if x[3:].isdecimal() else 0)
