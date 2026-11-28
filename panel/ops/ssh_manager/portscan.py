"""The cached listening-port scan of a host.

Part of the SSH connection manager for remote LinuxGSM servers, which also supports local
execution for running on the panel's own machine (see the package docstring for how names
resolve across its submodules).
"""
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

_port_scan_cache = _core.register_remote_cache({})
_PORT_SCAN_TTL = 5


class Listening(set):
    """A host's listening ports (a set of ints), and the accounts holding each where the scan read them.

    `owners`: {port: {account name, a uid `ss` printed with no name in /etc/passwd, or "" for root's (or an owner
    not printed)}}. A port with no entry, and every port of a plain set (a stand-in, an older read), counts for
    every server, as it always did (held_by). `socks`: {port: {(protocol, owner)}}, each socket's protocol ("tcp"
    or "udp") beside its owner, where the scan printed it (port_holders).
    """

    def __init__(self, ports=(), owners=None, socks=None):
        """`ports` as the set's members; `owners` and `socks` copied, so a scan's copy never shares them."""
        super().__init__(ports)
        self.owners = {p: set(o) for p, o in (owners or {}).items()}
        self.socks = {p: set(o) for p, o in (socks or {}).items()}

    def add_socket(self, port, owner, proto=""):
        """Add one listening socket: `port`, its `owner` ("" for none printed) and its `proto` ("" when not read)."""
        self.add(port)
        self.owners.setdefault(port, set()).add(owner)
        if proto in PROTOCOLS:
            self.socks.setdefault(port, set()).add((proto, owner))

    def __eq__(self, other):
        """Equal as port sets: who holds a port is detail a caller may read, never part of the set's value."""
        return set.__eq__(self, other)

    __hash__ = None              # a set: never hashable

    def copy(self):
        """A copy that keeps who holds each port (set.copy would drop it)."""
        return Listening(self, self.owners, self.socks)


PROTOCOLS = ("tcp", "udp")
# The games whose game port is TCP only, as LinuxGSM's port table prints it (lgsm/modules/info_messages.sh,
# fn_info_messages_*: "Game" port tcp and no udp row for it): Minecraft Java and LinuxGSM's Paper and Waterfall
# (fn_info_messages_mc), Velocity, SCP: Secret Laboratory, Terraria, OpenRA, Vintage Story and Wurm Unlimited.
# Every other game counts both protocols on its port: most print the game port as udp and also listen on it over
# TCP (a Source game's RCON rides it), so another socket there of either kind can stop it.
_TCP_GAME_PORT = frozenset({"mc", "pmc", "wmc", "vpmc", "scpsl", "terraria", "orar", "vints", "wurm"})


def game_protocols(game_type):
    """The protocols a game listens on at its game port: ("tcp",) for a TCP-only game, else both."""
    return ("tcp",) if (game_type or "").lower() in _TCP_GAME_PORT else PROTOCOLS


def port_holders(ports, port, protos=PROTOCOLS):
    """The owners of the sockets of protocol `protos` on `port` in the scan `ports`, or None when not known.

    None: the scan printed no protocol for that port (a plain set, an older read); every socket on it then counts,
    as before. An empty set: only sockets of another protocol are there (another server's UDP query socket on the
    TCP port of a Minecraft server), so nothing a game of `protos` binds is in use.
    """
    socks = getattr(ports, "socks", {}).get(port)
    if not socks:
        return None
    return {owner for proto, owner in socks if proto in protos}


def held_by(ports, port, user):
    """Whether `port` of the scan `ports` is held by game account `user`, as far as the scan says.

    False only when the sockets on it name their owners and none is `user`: another account's socket on the same
    number (a Minecraft server's TCP 25565 and another server's UDP 25565 query socket) is not this game running. A
    port whose owners were not read, a uid with no name, or no `user` to compare (a row without its account) counts.
    """
    held = getattr(ports, "owners", {}).get(port) if user else None
    if not held or held == {""}:
        return True
    return user in held or any(o.isdecimal() for o in held)


def fresh_ports(rid, now):
    """A copy of the ports a scan of host `rid` read within _PORT_SCAN_TTL seconds, or None."""
    hit = _port_scan_cache.get(rid) if rid is not None else None
    return Listening(hit[1], getattr(hit[1], "owners", None), getattr(hit[1], "socks", None)) \
        if hit and hit[0] > now else None


def note_ports(rid, now, ports):
    """Keep the ports another read of host `rid` (the host sample's `ss`) took at `now`, as a scan."""
    if rid is not None:
        _port_scan_cache[rid] = (now + _PORT_SCAN_TTL, Listening(ports, getattr(ports, "owners", None),
                                                                 getattr(ports, "socks", None)))

def _remote_listening_ports(remote):
    """Set of ports currently listening on `remote`, or NONE when the scan could not be read.

    Cached for _PORT_SCAN_TTL seconds so concurrent dashboard polls (multiple tabs/users, or a
    servers_changed broadcast) share one SSH scan instead of each running their own. A failed scan
    isn't cached, so a transient SSH blip retries next poll instead of pinning every server
    'offline' for the whole TTL.

    None rather than an empty set, because they are different answers and the caller that matters
    most cannot tell them apart otherwise. On a local or Tailscale-SSH host a timed-out command
    does not raise — the transport returns ("", "...timed out", -1) — so an `ss` that never
    answered used to arrive at _probe_host as "reachable, nothing listening". _monitor_pass then
    declared every game server on that host down: a "Server offline" alert each, gs.status written
    offline in the database (so the bots and the dashboard repeated it), the one-shot "notify when
    empty" request falsely fired AND consumed, and a matching "back online" storm 60s later. The
    `if out:` below already knew empty output means a blip; only the return did not.
    """
    now = time.time()
    hit = _port_scan_cache.get(remote.id)
    if hit and hit[0] > now:
        return hit[1]
    # No sudo: listing listening-socket *addresses* (no -p process info) is unprivileged, so this
    # frequent poll doesn't need root — avoids a sudo session per remote on every refresh.
    #
    # sudo=False EXPLICITLY. The default is None, and None does not mean "no sudo" — for a remote
    # both transports read it as "the row's setting" (_core.py:866 and :744, `sudo if sudo is not
    # None else server.sudo_enabled`), which the Add Remote checkbox ships checked. So the comment
    # above was true only of the panel's own host, where the local branch coerces with bool(sudo):
    # every remote was opening a PAM session and a root bash every few seconds to read
    # world-readable socket state. On a host whose sudoers permits only named commands, or asks
    # for a password, `sudo bash -c 'ss …'` fails outright, out is "" and the scan reads as
    # unknown — which resolve_free_port turns into "no ports occupied" and hands a new game server
    # a port that is already listening, when the unprivileged `ss` would have answered.
    # Same idiom as the two siblings running this kind of read: _core.py:1258, firewall.py:395.
    #
    # -e: each socket's owner (uid:<n>), named from /etc/passwd, so a game is read up only on a socket of its own
    # account (held_by). `ss -e` prints nothing for root's.
    out, _, _ = _core.run_command(remote, "ss -H -lntue 2>/dev/null | awk " + _SCAN_AWK, timeout=8, sudo=False)
    if not out:
        return None      # nothing came back — a blip, not a host with no listening sockets
    ports = parse_scan(out)
    if out:   # cache only a scan that returned something (empty output == SSH blip)
        _port_scan_cache[remote.id] = (now + _PORT_SCAN_TTL, ports)
    return ports


# `<address> <protocol> <owner>` per listening socket (`ss`'s Netid column, tcp or udp; the owner left out for
# root's): _remote_listening_ports' read.
_SCAN_AWK = ("'BEGIN {while ((getline l < \"/etc/passwd\") > 0) {split(l, p, \":\"); u[p[3]] = p[1]}} "
             "{o = \"\"; for (i = 6; i <= NF; i++) if ($i ~ /^uid:/) {o = substr($i, 5); if (o in u) o = u[o]} "
             "print $5, $1, o}'")


def parse_scan(out):
    """The Listening ports of a scan's `<address> [protocol] [owner]` lines.

    An address alone, or an address and its owner, is what an older read printed: its protocol is then not known.
    """
    ports = Listening()
    for line in (out or "").splitlines():
        f = line.split()
        if not f or ":" not in f[0]:
            continue
        p = f[0].rsplit(":", 1)[1]
        if p.isdecimal():
            proto = f[1] if len(f) > 1 and f[1] in PROTOCOLS else ""
            rest = f[2:] if proto else f[1:]
            ports.add_socket(int(p), rest[0] if rest else "", proto)
    return ports


# Games that do not listen on the port the panel holds for them, and where they do instead, as
# offsets from it. Valheim: LinuxGSM's vhserver starts it with `-port ${port}` (2456) and, since
# v24.3.0, -crossplay (its _default.cfg); a crossplay server was found listening on 2457/udp only
# (port + 1, Valheim's Steam query port, gamedig's valheim port_query_offset 1), so a scan for
# 2456 read a running server as offline. Its own port still counts, for a server off crossplay.
_LISTENS_ALSO_ON = {"vh": (1,)}


def game_port_listening(game_type, port, ports, user=None):
    """Whether a game whose port is `port` is listening, by a scan's set of listening `ports`.

    `user`: the game's account; a port only another account holds is not counted (held_by).
    """
    return any(p in ports and held_by(ports, p, user) for p in listen_ports(game_type, port))


def listen_ports(game_type, port):
    """The ports any one of which listening means a game whose port is `port` is up: its own first.

    The one place the _LISTENS_ALSO_ON offsets are applied, so the host scan (game_port_listening)
    and the per-server live sample (_core._game_sample_cmd) cannot disagree about a server: they did
    once, and a crossplay Valheim read online on the dashboard and offline on its own page.
    """
    if not isinstance(port, int) or isinstance(port, bool):
        return (port,)
    offsets = _LISTENS_ALSO_ON.get((game_type or "").lower(), ())
    return (port,) + tuple(port + off for off in offsets if 0 < port + off <= 65535)


def metrics_for_game(sample, short_name, game_port, game_type=None):
    """One game's slice of a host_live_metrics() sample, shaped like server_live_metrics()."""
    m = dict(sample["host"])
    m.update(sample["users"].get(short_name or "",
                                 {"game_cpu_percent": 0.0, "game_ram_mb": 0, "game_procs": 0,
                                  "game_uptime_secs": 0, "game_ram_percent": 0.0}))
    # cron_port, not int(): a loaded row is never type-checked, and one GameServer whose port reads
    # as text (a restored backup, a hand edit — SQLite keeps it) raised out of
    # monitoring._query_host_metrics, which calls this outside its try, and through ex.map took the
    # dashboard's metrics for EVERY host, and every history sample, down with it.
    try:
        _port = _core.cron_port(game_port)
    except ValueError:
        _port = None
    m["port_open"] = bool(_port) and game_port_listening(game_type, _port, sample["ports"], short_name)
    return m


def _invalidate_port_scan(remote_id):
    """Drop a remote's cached port scan so the next status poll re-reads it.

    Call after any action that changes what's listening (start/stop/restart), so status is fresh
    immediately. The host's shared player lists go with it: a stopped server's players are gone.
    """
    _port_scan_cache.pop(remote_id, None)
    from panel.ops.ssh_manager import game as _game   # at call time: game imports this module's package
    _game.forget_lists(remote_id)
