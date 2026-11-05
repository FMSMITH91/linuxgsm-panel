"""A green `os.write` that lets a broken pipe raise, as the standard library expects.

eventlet's green `os.write` (eventlet/green/os.py, unchanged upstream as of 0.41.3) retries on
EPIPE as if it were EAGAIN. `eventlet.monkey_patch()` puts it on the `os` module, so it is what
`subprocess` calls. A pipe whose reader has gone stays "writable" forever, so the loop never ends:

    while True:
        hubs.trampoline(fd, write=True)       # returns at once: the pipe has no reader
        try: return orig_write(fd, data)
        except OSError as e:
            if e.errno not in (EAGAIN, EPIPE): raise   # EPIPE: go round again

`Popen.communicate(input)` and `subprocess.run(input=..., capture_output=True)` reach that write
from `_communicate`, which is written to catch `BrokenPipeError` and carry on. So feeding stdin to
a child that exits without reading it spins one core at 100% and never returns, and `timeout=` is no
help: the timeout is checked between writes, and this write never comes back. This was the
intermittent hang in CI's ubuntu-22.04 leg, where `bash tools/sign-release.sh <id>` exits before
reading the input it is given and the slow runner let it exit first.

The panel feeds stdin to short-lived children (ssh-keygen's signature check and the helper's
write-file both pass `input=`), so this is a runtime fix, not a test one. `install()` swaps in a
copy of eventlet's write that keeps everything it does (no wait for regular files, the trampoline,
0 on a closed fd, a retry on EAGAIN) and lets EPIPE raise. app.py calls it straight after
`monkey_patch()`.
"""
import errno
import os
import stat


def _fixed(orig_write, orig_stat, trampoline, io_closed):
    """Build eventlet's write with the EPIPE retry taken out."""
    def write(fd, data):
        """write(fd, data) -> bytes written; a broken pipe raises BrokenPipeError."""
        while True:
            if not stat.S_ISREG(orig_stat(fd).st_mode):
                try:
                    trampoline(fd, write=True)
                except io_closed:
                    return 0
            try:
                return orig_write(fd, data)
            except OSError as e:
                if e.errno != errno.EAGAIN:
                    raise
    write.lgsm_epipe_raises = True
    return write


def install():
    """Replace the green `os.write` with one that raises on EPIPE. Returns True if it is in place.

    Does nothing (and returns False) when eventlet is missing or has not patched `os`, since the
    standard `os.write` already raises; calling it twice is harmless.
    """
    if getattr(os.write, "lgsm_epipe_raises", False):
        return True
    try:
        from eventlet import hubs, patcher
        from eventlet.green import os as green_os
    except ImportError:
        return False
    if os.write is not green_os.write:
        return False
    os_orig = patcher.original("os")
    fixed = _fixed(os_orig.write, os_orig.stat, hubs.trampoline, hubs.IOClosed)
    green_os.write = fixed
    os.write = fixed
    return True
