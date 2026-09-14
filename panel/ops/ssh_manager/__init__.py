"""Everything the panel does over SSH (and the local equivalents), split by subject.

This was one 5,540-line module. The split follows the section boundaries its author already kept
in comments, so each file is a subject rather than an arbitrary slice:

    _core     connection pool, the exec primitives, server control, live metrics, discovery
    cron      the per-server cron manager and its run-history recorder
    game      engine families, player queries, console, moderation, per-game backups
    firewall  ufw rule parsing/grouping, exposed-port annotation, host specs
    hosts     node query tools, Ubuntu Pro, VPS bootstrap, SSH port changes, tailnet state
    files     LinuxGSM config read/write, the file browser, downloads
    gmod      GMod mountable game content
    portscan  the cached listening-port scan

WHY THE PACKAGE RESOLVES NAMES DYNAMICALLY, AND WHY THAT IS THE WHOLE POINT.

`run_privileged` is called from 98 places inside this package and `run_command` from 65, and both
are names the test suites STUB. While everything lived in one module those calls resolved through
that module's globals, so a stub on `ssh_manager.run_command` was seen by every one of them.

A naive split breaks exactly that, and breaks it SILENTLY: `from ._core import run_command` copies
the function object at import time, so the stub assigns cleanly, intercepts nothing, and the suite
makes real SSH connections while still reporting green. That is the failure mode this repository
has been bitten by more than any other.

So every cross-module reference goes through the MODULE object (`_core.run_command(...)`), which
resolves at call time, and this package exposes names through `__getattr__` rather than re-exporting
bound objects. The consequences are the ones you want:

  * `from panel.ops.ssh_manager import run_command` still works, for every existing caller.
  * `_sm.run_command(...)` (attribute access, which is how the route modules call these) resolves
    through `__getattr__` to the definition site — so it sees a stub placed there.
  * There is ONE stub target, `panel.ops.ssh_manager._core.run_command`, and it reaches both the
    163 internal call sites and every external caller. Before the split no single target did.

Do not "optimise" this into `from ._core import *`. It would restore the fast path and quietly
disconnect the tests.
"""
from panel.ops.ssh_manager import _core, cron, game, firewall, hosts, files, gmod, portscan  # noqa: F401,E402

_MODULES = (_core, cron, game, firewall, hosts, files, gmod, portscan)


def __getattr__(name):
    """Resolve a public name to whichever submodule defines it, at ACCESS time.

    PEP 562: Python calls this only when normal attribute lookup fails, so anything assigned
    directly onto this package shadows it. That is why a stub belongs on the defining submodule
    and not here — a stub set here would be seen by attribute-access callers and missed by this
    package's own internals, which is half a stub and no error."""
    for m in _MODULES:
        try:
            return getattr(m, name)
        except AttributeError:
            continue
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


def __dir__():
    out = set(globals())
    for m in _MODULES:
        out.update(n for n in dir(m) if not n.startswith("__"))
    return sorted(out)
