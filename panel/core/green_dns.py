"""Name lookups that never block eventlet's hub, without dnspython.

eventlet replaces `socket.getaddrinfo`, `gethostbyname`, `gethostbyname_ex` and `getnameinfo`
with greendns when it monkey-patches: a resolver of its own, written on dnspython
(eventlet/support/greendns.py, 0.41.3). eventlet/green/socket.py imports it only when the environment
variable EVENTLET_NO_GREENDNS is not "yes", and reads that variable ONCE, when eventlet is first
imported (any eventlet import loads eventlet.green.socket). The panel sets it before then
(panel/install/app.py, panel/__init__.py) and does not install dnspython at all
(panel/install/requirements.in says why).

With greendns off, eventlet's green socket module hands out the C library's lookups as they are,
and those block the calling thread. On the hub's thread that is every greenlet at once: one slow DNS
server would freeze the live console, the status poll and every request until it answered.
`install()` routes each of the four through `eventlet.tpool.execute` to the unpatched function
instead (eventlet.patcher.original("socket")), so the operating system's own resolver (nsswitch,
/etc/hosts, systemd-resolved, Tailscale's MagicDNS) answers on one of tpool's native threads while
the hub keeps turning. Results and exceptions (socket.gaierror) come back unchanged: tpool
re-raises what the worker raised (eventlet/tpool.py, execute).

A lookup made off the hub's thread is called directly: on a tpool worker (tpool would run it
inline itself) and on any other native thread, which has no hub that a tpool reply could wake.
So is one made from the hub greenlet, which has nothing to switch to while it waits.

app.py calls it straight after `monkey_patch()`. green `create_connection` reads `getaddrinfo`
from eventlet.green.socket's own globals, so both modules are patched.
"""
import socket

NAMES = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "getnameinfo")


def _routed(real_socket, name, run, native_ident, hub_ident, on_hub_greenlet):
    """Build a stand-in for lookup `name` that runs it through `run` from the hub thread's greenlets.

    The unpatched function is read from `real_socket` at each call, not bound here.
    """
    def lookup(*args, **kwargs):
        """Resolve on a worker thread from a greenlet on the hub's thread; directly anywhere else."""
        fn = getattr(real_socket, name)
        if native_ident() != hub_ident or on_hub_greenlet():
            return fn(*args, **kwargs)
        return run(fn, *args, **kwargs)
    lookup.lgsm_green_dns = True
    lookup.__name__ = name
    return lookup


def install():
    """Route the four name lookups through eventlet's thread pool. Returns True if they are routed.

    Does nothing (and returns False) when eventlet is missing or has not patched `socket`; calling
    it twice is harmless. The thread that calls it is taken as the hub's (app.py's main thread).
    """
    if getattr(socket.getaddrinfo, "lgsm_green_dns", False):
        return True
    try:
        from eventlet import hubs, patcher, tpool
        from eventlet.green import socket as green_socket
        from greenlet import getcurrent
    except ImportError:
        return False
    if not patcher.is_monkey_patched("socket"):
        return False
    real_socket = patcher.original("socket")
    native_ident = patcher.original("threading").get_ident

    def on_hub_greenlet():
        """True when running as the hub itself, which cannot wait on a tpool reply."""
        hub = hubs.get_hub()
        return getattr(hub, "greenlet", None) is not None and hub.greenlet is getcurrent()

    hub_ident = native_ident()
    for name in NAMES:
        routed = _routed(real_socket, name, tpool.execute, native_ident, hub_ident, on_hub_greenlet)
        setattr(socket, name, routed)
        setattr(green_socket, name, routed)
    return True
