"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import time
from panel.ops.ssh_manager import (_core)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.





# ── Listening-port scan, cached ──────────────────────────────────────────────────────────────
# Lives here rather than in app.py because it is a cache over run_command, which is this module's
# job, and because app.py is not importable from everything that needs it — the background jobs
# being pulled out of register_routes call _invalidate_port_scan, and a jobs module importing app
# would be a cycle. app.py imports these back under their old names, so its call sites and the
# tests that clear the cache are untouched (same dict object, not a copy).

_port_scan_cache = {}
_PORT_SCAN_TTL = 5

def _remote_listening_ports(remote):
    """Set of ports currently listening on `remote`, cached for _PORT_SCAN_TTL seconds so
    concurrent dashboard polls (multiple tabs/users, or a servers_changed broadcast) share one
    SSH scan instead of each running their own. A failed/empty scan isn't cached, so a transient
    SSH blip retries next poll instead of pinning every server 'offline' for the whole TTL."""
    now = time.time()
    hit = _port_scan_cache.get(remote.id)
    if hit and hit[0] > now:
        return hit[1]
    # No sudo: listing listening-socket *addresses* (no -p process info) is unprivileged, so this
    # frequent poll doesn't need root — avoids a sudo session per remote on every refresh.
    out, _, _ = _core.run_command(remote, "ss -H -lntu 2>/dev/null | awk '{print $5}'", timeout=8)
    ports = set()
    for addr in (out or "").split():
        if ":" in addr:
            p = addr.rsplit(":", 1)[1]
            if p.isdecimal():
                ports.add(int(p))
    if out:   # cache only a scan that returned something (empty output == SSH blip)
        _port_scan_cache[remote.id] = (now + _PORT_SCAN_TTL, ports)
    return ports

def _invalidate_port_scan(remote_id):
    """Drop a remote's cached port scan so the next status poll re-reads it — call after any
    action that changes what's listening (start/stop/restart), so status is fresh immediately."""
    _port_scan_cache.pop(remote_id, None)
