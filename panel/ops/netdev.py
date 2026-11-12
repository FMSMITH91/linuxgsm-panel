"""Which network interfaces count towards a host's traffic, and the NETIF line of the host read.

The host read (ssh_manager host_live_metrics) prints one `NETIF <name> <rx bytes> <tx bytes>` line
per interface in /proc/net/dev. The history sampler turns the summed counters into rates
(monitoring._hch_net_rates). Kept apart from the read itself so the interface rule is plain code
with nothing to stub.
"""
import time

# The ones whose bytes cross the wire once. `lo` is the host talking to itself. veth*, docker*, br-*
# and virbr* carry container and VM traffic that the physical interface also carries on its way in
# or out, so adding them counts it twice. tailscale* and wg* are tunnels: every byte on them is sent
# again, wrapped, over the physical interface, so they are skipped for the same reason. What is
# left is the physical (or virtual NIC) interfaces, ens3, eth0, enp0s3 and the like.
SKIP_PREFIXES = ("veth", "docker", "br-", "virbr", "tailscale", "wg")


def counted(name):
    """Whether interface `name` counts towards the host's traffic (see SKIP_PREFIXES)."""
    return name != "lo" and not name.startswith(SKIP_PREFIXES)


def netif_line(f, host, _acc=None):
    """Add one NETIF line's received/sent bytes to the host's totals, for a counted interface.

    `f` is the line split on whitespace. A line that is not two counters is skipped, as the host
    read's other tagged lines are. net_read_at is when the counters were read, for the sampler's
    rate: the output is parsed as soon as it arrives, and stamping it here rather than when the
    sample is stored keeps a cached read (a couple of seconds old by then) from skewing the rate.
    """
    if len(f) >= 4 and f[2].isdecimal() and f[3].isdecimal() and counted(f[1]):
        host["net_rx_bytes"] = (host.get("net_rx_bytes") or 0) + int(f[2])
        host["net_tx_bytes"] = (host.get("net_tx_bytes") or 0) + int(f[3])
        host["net_read_at"] = time.time()
