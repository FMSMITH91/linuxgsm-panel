"""Which network interfaces count towards a host's traffic, and the NETIF line of the host read.

The host read (ssh_manager host_live_metrics) prints one `NETIF <name> <rx bytes> <tx bytes>` line
per interface in /proc/net/dev. The history sampler turns the summed counters into rates
(monitoring._hch_net_rates). Kept apart from the read itself so the interface rule is plain code
with nothing to stub.
"""
import re
import time

# The ones whose bytes cross the wire once: the bottom of each interface stack, the one the bytes leave
# the host on. /proc/net/dev lists every interface flat, with no word on which rides on which, so what
# rides on another is told by the names the kernel and the usual tools give it. `lo` is the host talking
# to itself. Skipped, because the interface below them carries the same bytes:
#   * container and VM links and their bridges: veth*, docker*, br-*, virbr*, podman*, cni-*, lxdbr*,
#     lxcbr*, and libvirt's and Proxmox's guest taps and firewall links (vnet*, tap*, fwbr*, fwpr*, fwln*);
#   * bridges: br0 and the like (br*) and Proxmox's vmbr*. A NIC enslaved to one counts every frame on
#     the wire, the host's and its guests'; a bridge with no NIC in it is routed out of one;
#   * bond and team masters (bond*, team*): their counters are the sum of their member NICs';
#   * VLAN, macvlan, macvtap and ipvlan links (vlan*, macvlan*, macvtap*, ipvlan*), which ride on a NIC,
#     and ifb*, which mirrors one's traffic;
#   * tunnels and VPNs: tailscale*, wg*, tun*, ppp*, zt* (ZeroTier) and the kernel's own tunnel devices
#     (gre*, gretap*, erspan*, ip6tnl*, ip6gre*, ip_vti*, ip6_vti*, sit*, tunl*, vxlan*). Every byte on
#     them is sent again, wrapped, over the interface below.
# What is left is the physical (or virtual NIC) interfaces, ens3, eth0, enp0s3, eno1 and the like.
SKIP_PREFIXES = ("veth", "docker", "br", "virbr", "vmbr", "podman", "cni-", "lxdbr", "lxcbr", "vnet", "tap",
                 "fwbr", "fwpr", "fwln", "bond", "team", "macvlan", "macvtap", "ipvlan", "ifb", "tailscale",
                 "wg", "tun", "ppp", "zt", "gre", "erspan", "ip6tnl", "ip6gre", "ip_vti", "ip6_vti", "sit",
                 "vxlan", "vlan")

# A VLAN sub-interface (eno1.100, bond0.20, eno1.100.5; vlan100 is in SKIP_PREFIXES): the interface it is
# cut from counts the same frames. The names the kernel and udev give a NIC hold no dot.
_VLAN_NAME = re.compile(r"\.\d+\Z")


def counted(name):
    """Whether interface `name` counts towards the host's traffic (see SKIP_PREFIXES and _VLAN_NAME)."""
    return name != "lo" and not name.startswith(SKIP_PREFIXES) and not _VLAN_NAME.search(name)


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
