"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import ipaddress as _ipaddress
import os
import re
import socket
from panel.core import clock, terminal
import time
import paramiko
from panel.core.config import decrypt_secret
from panel.security import privileged as _priv
from panel.ops.ssh_manager import (_core, firewall)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ── Keep the node player-query tools (npm + gamedig) current ───────────────────
# gamedig is installed once (bootstrap / install.sh) and never updates itself, so player queries can
# silently break as games and gamedig evolve. This weekly ROOT cron refreshes npm + gamedig alongside
# the host's other automatic updates (unattended-upgrades). Written to /etc/cron.d as root, idempotent;
# the `command -v npm` guard makes it a harmless no-op on a host that never got node.
_NODE_TOOLS_CRON = (
    "# LinuxGSM Panel - keep npm + gamedig current for player queries (managed by the panel).\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "30 4 * * 0 root command -v npm >/dev/null 2>&1 && "
    "npm install -g npm gamedig >/var/log/lgsm-node-tools.log 2>&1\n"
)


def ensure_node_tools_cron(server):
    """Idempotently install the weekly root cron that keeps npm + gamedig current on `server`, so the
    panel's player queries don't rot. Best-effort; never raises. Returns True if the write succeeded.
    Root-owned: locally the helper does the write itself, and remotely it is `sudo bash -c` with
    base64 so no quoting or `%` can mangle it. This used to claim it landed root-owned "regardless
    of any per-remote linuxgsm_user", which was the opposite of what happened — that field turned
    every sudo=True command into `sudo -u <that user>`, this one included. See _core.run_command."""
    try:
        _out, _err, rc = _core.write_root_file(server, "node-tools-cron", _NODE_TOOLS_CRON, timeout=20)
        return rc == 0
    except Exception:
        _core._log.debug("ensure_node_tools_cron failed", exc_info=True)
        return False


# `pro status` spawns Ubuntu's heavy advantage-tools client (slow + CPU-hungry, especially on a
# small VPS). Its result changes ONLY when someone attaches/detaches/toggles a service — all of
# which go through this module and invalidate the cache — so there's no reason to re-run it on a
# timer. The long TTL is just a safety net to eventually catch an out-of-band change (a lapsed
# subscription, or a manual `pro detach` on the host); day-to-day it's effectively set-and-forget.
# Registered (see _core.register_remote_cache) so a deleted host's id is forgotten — at a 24h TTL
# a recycled id would otherwise report the deleted machine's Ubuntu Pro subscription all day.
_pro_status_cache = _core.register_remote_cache({})   # remote id -> (expiry_epoch, result)
_PRO_STATUS_TTL = 86400  # 24h


def _pro_key(server):
    return getattr(server, "id", None) or getattr(server, "host", None) or "local"


def _pro_cache_invalidate(server):
    _pro_status_cache.pop(_pro_key(server), None)


def pro_status(server, force=False):
    """Ubuntu Pro attachment/service status for a host (cached 24h; pass force=True to refresh).

    The TTL was deliberately raised to _PRO_STATUS_TTL — see the note above it — and this said
    "~5 min" for long enough that someone debugging stale Pro state would look anywhere but here.
    """
    key = _pro_key(server)
    now = time.time()
    if not force:
        cached = _pro_status_cache.get(key)
        if cached and cached[0] > now:
            return cached[1]
    result = _compute_pro_status(server)
    _pro_status_cache[key] = (now + _PRO_STATUS_TTL, result)
    return result


def _compute_pro_status(server):
    """Run `pro status` and shape the result. Returns installed/attached plus the featured
    security services and their enabled/disabled state."""
    import json
    # `|| true` swallowed a non-zero exit so the caller always got a string; the check below
    # already treats anything that is not JSON as "not installed", so the rc can just be ignored.
    out, _, _ = _core.run_privileged(server, "pro-status", [], timeout=25, merge_stderr=False)
    if not out.strip() or not out.strip().startswith("{"):
        return {"installed": False, "attached": False, "services": []}
    try:
        data = json.loads(out)
    except Exception:
        return {"installed": True, "attached": False, "services": [],
                "error": "Could not parse pro status"}
    by_name = {s.get("name"): s for s in (data.get("services") or [])}
    featured = []
    for name in _PRO_FEATURED:
        s = by_name.get(name)
        if s:
            featured.append({
                "name": name,
                "description": s.get("description", ""),
                "status": s.get("status", ""),
                "entitled": s.get("entitled", ""),
                "available": s.get("available", ""),
            })
    contract = data.get("contract") or {}
    account = data.get("account") or {}
    expires = data.get("expires", "") or ""
    if expires.startswith("9999"):  # perpetual free sub — don't show a scary date
        expires = ""
    return {
        "installed": True,
        "attached": bool(data.get("attached")),
        "account": account.get("name", "") if isinstance(account, dict) else "",
        "contract": contract.get("name", "") if isinstance(contract, dict) else "",
        "expires": expires,
        "services": featured,
    }


def pro_attach(server, token):
    """Attach a host to Ubuntu Pro with a subscription token. Installs the pro client
    first if it's somehow missing. The token is NEVER echoed back in messages/logs."""
    token = (token or "").strip()
    if not token:
        return False, "No token provided"
    _pro_cache_invalidate(server)   # state is about to change; next status read must be fresh
    # Was one root shell: `(command -v pro || (apt-get update && apt-get install …)) ; pro attach`.
    # The presence test is now the pro-status verb's own exit code — rc 127 is "not installed" on
    # both transports — and the install is two verbs that already exist.
    _, _, pro_rc = _core.run_privileged(server, "pro-status", [], timeout=30, merge_stderr=False)
    if pro_rc == 127:
        _core.run_privileged(server, "apt-update", [], timeout=120, merge_stderr=False)
        _core.run_privileged(server, "apt-install", ["ubuntu-advantage-tools"], timeout=300)
    out, err, rc = _core.run_privileged(server, "pro-attach", [token], timeout=240)
    blob = ((out or "") + " " + (err or "")).replace(token, "<token>")
    low = blob.lower()
    if rc == 0 or "this machine is now attached" in low or "already attached" in low:
        return True, "Attached to Ubuntu Pro."
    return False, _pro_trim(blob) or "Attach failed"


def pro_service(server, service, action):
    """Enable or disable an Ubuntu Pro service (esm-infra, esm-apps, livepatch, …)."""
    if service not in _PRO_SERVICES:
        return False, "Unknown service"
    if action not in ("enable", "disable"):
        return False, "Unknown action"
    _pro_cache_invalidate(server)
    out, err, rc = _core.run_privileged(server, "pro-service", [action, service], timeout=300)
    blob = (out or "") + " " + (err or "")
    low = blob.lower()
    if rc == 0 or "is already enabled" in low or "is already disabled" in low \
            or "now enabled" in low or "updating package lists" in low:
        return True, _pro_trim(blob) or f"{service} {action}d"
    return False, _pro_trim(blob) or f"Could not {action} {service}"


def pro_detach(server):
    """Detach a host from Ubuntu Pro."""
    _pro_cache_invalidate(server)
    out, err, rc = _core.run_privileged(server, "pro-detach", [], timeout=120)
    blob = (out or "") + " " + (err or "")
    if rc == 0 or "detach" in blob.lower():
        return True, "Detached from Ubuntu Pro."
    return False, _pro_trim(blob) or "Detach failed"


def _ufw_port_int(port):
    """Coerce a UFW port to a validated int (1-65535), or raise ValueError. Ports and
    protocols are interpolated straight into a root shell command, so they must never
    carry anything but a number / a known protocol keyword."""
    p = int(port)   # rejects non-numeric ("abc", "22; rm -rf /") with ValueError
    if not (1 <= p <= 65535):
        raise ValueError("port out of range")
    return p


def _ufw_proto(protocol):
    """Normalise a UFW protocol to one of tcp/udp/both, or None for an invalid value.
    Anything outside the allowlist is rejected — it must never reach the shell."""
    p = (protocol or "").strip().lower()
    if p in ("", "both", "any"):
        return "both"
    if p in ("tcp", "udp"):
        return p
    return None


def remote_ufw_open_port(server, port, protocol="tcp", comment=""):
    """Open a port on the remote server via UFW. protocol 'both'/'any' opens TCP+UDP
    in a single rule (a bare `ufw allow <port>` covers both)."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto is None:
        return False, "Invalid protocol"
    cmt = re.sub(r"[^A-Za-z0-9 _.-]", "", comment or "")[:60]
    if proto == "both":
        verb, vargs, label = "ufw-allow-port", [str(port), cmt], f"{port} (TCP+UDP)"
    else:
        verb, vargs, label = "ufw-allow-proto-port", [proto, str(port), cmt], f"{port}/{proto}"
    out, err, rc = _core.run_privileged(server, verb, vargs, timeout=15)
    if rc == 0:
        return True, f"Port {label} opened on remote"
    return False, err or out or "Unknown error"


# What ufw accepts after `port`: one port, or a lo:hi range. The verb's own _portspec is the
# authority; this is the same shape, checked early so the answer is a message and not a 500.
_UFW_PORT_SPEC_RE = re.compile(r"^[0-9]{1,5}(?::[0-9]{1,5})?\Z")


def remote_ufw_allow_from(server, source, port, protocol="tcp", comment="", allow=True):
    """Open a port only FROM one address or network (or remove that rule).

    Every other allow path here opens a port to the whole internet — only DENY ever took an
    address — so "SSH from my home IP" or "RCON from the LAN" could not be said at all: the choice
    was world-open or closed. `source` is an IP or CIDR; the privileged verb validates it with
    ipaddress and refuses anything that is not a network, so nothing composable reaches the
    command line.

    A port RANGE is fine (27015:27020), which Source-engine games need."""
    src = (source or "").strip()
    if not src:
        return False, "Source address required"
    proto = _ufw_proto(protocol)
    if proto not in ("tcp", "udp"):
        # ufw's extended `from ... to any port ... proto ...` form names ONE protocol.
        return False, "A source rule needs a single protocol (tcp or udp)"
    spec = str(port or "").strip()
    if not spec:
        return False, "Port required"
    # Validated HERE, like remote_ufw_open_port's sibling checks. The verb validates too, but it
    # signals failure by RAISING VerbError — run_privileged does not catch it, nor does the route,
    # and the project has no Flask errorhandler — so a hostname in the "allow from" box or a
    # malformed port returned a bare 500 HTML page. The caller's `.then(r => r.json())` then failed
    # to parse it, so the user saw a generic "Failed" with no reason and the panel log got a
    # traceback. Same two answers the sibling gives, as (ok, msg).
    try:
        _ipaddress.ip_network(src, strict=False)
    except ValueError:
        return False, "Source must be an IP address or network (e.g. 10.0.0.0/24)"
    if not _UFW_PORT_SPEC_RE.match(spec):
        return False, "Port must be a number or a range like 27015:27020"
    if allow:
        cmt = re.sub(r"[^A-Za-z0-9 _.-]", "", comment or "")[:60]
        verb, vargs = "ufw-allow-from-port", [src, spec, proto, cmt]
    else:
        verb, vargs = "ufw-delete-allow-from-port", [src, spec, proto]
    out, err, rc = _core.run_privileged(server, verb, vargs, timeout=15)
    if rc == 0:
        return True, ("Port %s/%s open from %s" % (spec, proto, src) if allow
                      else "Rule for %s/%s from %s removed" % (spec, proto, src))
    return False, err or out or "Unknown error"


def remote_ufw_limit_port(server, port, protocol="tcp", limit=True):
    """Rate-limit (or stop rate-limiting) a port — UFW's own brute-force brake.

    `ufw limit` refuses an address that opens more than 6 connections to the port in 30 seconds.
    The panel has always used it when it hardens SSH on a bootstrap, and the privileged verb has
    been there the whole time; there was simply no way to ask for it from the UI. It is the right
    answer for any port where a person authenticates — SSH, RCON, a game's admin port — and the
    wrong one for gameplay traffic, where six connections in half a minute is a quiet evening.

    Rules are per (port, proto), so this deletes the plain `allow` first: leaving it in place would
    keep matching first and the limit would never be reached."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto not in ("tcp", "udp"):
        # `ufw limit` takes one rule; "both" would need two and they would report separately.
        return False, "Rate limiting needs a single protocol (tcp or udp)"
    spec = "%d/%s" % (port, proto)
    if not limit:
        out, err, rc = _core.run_privileged(server, "ufw-delete-limit-port", [spec], timeout=15)
        if rc == 0:
            return True, "Rate limit removed from %s" % spec
        return False, err or out or "Unknown error"
    # Drop the unlimited allow so the limit rule is the one that matches. A missing rule makes ufw
    # exit non-zero ("Could not delete non-existent rule"), which is fine and not worth reporting.
    _core.run_privileged(server, "ufw-delete-allow-proto-port", [proto, str(port)], timeout=15)
    out, err, rc = _core.run_privileged(server, "ufw-limit-port", [spec], timeout=15)
    if rc == 0:
        return True, "%s is now rate limited (6 connections per 30s per address)" % spec
    return False, err or out or "Unknown error"


def remote_ufw_close_port(server, port, protocol=None):
    """Close a port on the remote server via UFW. With protocol=None (or 'both'/'any'),
    deletes the bare `allow <port>` rule (both protocols); otherwise the proto-specific rule."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto is None:
        return False, "Invalid protocol"
    if proto in ("tcp", "udp"):
        verb, vargs = "ufw-delete-allow-proto-port", [proto, str(port)]
    else:
        verb, vargs = "ufw-delete-allow-port", [str(port)]
    out, err, rc = _core.run_privileged(server, verb, vargs, timeout=15)
    if rc == 0:
        return True, f"Port {port}{('/' + proto) if proto in ('tcp', 'udp') else ''} closed on remote"
    return False, err or out or "Unknown error"


def remote_ufw_delete_rule(server, num, force=False):
    """Delete a UFW rule by its number (as shown by `ufw status numbered`). This is
    the reliable way to remove any rule — deleting by spec requires an exact match.

    Unless force=True, refuses to delete a rule that is the last thing keeping SSH or
    Tailscale access open, so a click (or a direct API call) can't lock you out."""
    try:
        n = int(num)
    except (TypeError, ValueError):
        return False, "Invalid rule number"
    if n < 1:
        return False, "Invalid rule number"
    if not force:
        try:
            for g in firewall.remote_ufw_status(server).get("groups", []):
                if n in g.get("nums", []) and g.get("protected"):
                    return False, g.get("protect_reason") or \
                        "This rule protects your access to the host and can't be removed here."
        except Exception:
            _core._log.debug("don't let the safety check itself block a legitimate delete on error", exc_info=True)
    out, err, rc = _core.run_privileged(server, "ufw-delete-num", [n], timeout=15)
    if rc == 0:
        return True, f"Rule {n} deleted"
    return False, err or out or "Failed to delete rule"


def remote_ufw_allow_game_port(server, port, name="Game"):
    """Open the game server port for BOTH TCP and UDP in ONE UFW rule, tagging the
    rule with the game server's name (its LinuxGSM username) so the firewall list
    shows which server each port belongs to. A bare `ufw allow <port>` covers tcp+udp."""
    # Range-checked HERE, like every sibling in this module. The verb's _portspec raises
    # VerbError, run_privileged does not catch it, and there is no route-level handler — so
    # `POST /api/remote/<id>/game-port/70000/open` came back as a bare HTML 500 that the caller's
    # .then(r => r.json()) could not parse.
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return 0, "Invalid port"
    comment = re.sub(r"[^A-Za-z0-9 _.-]", "", name or "Game")[:60] or "Game"
    out, err, rc = _core.run_privileged(server, "ufw-allow-port", [str(port), comment], timeout=15)
    ok = rc == 0
    return (1 if ok else 0), f"Port {port}: {'opened (TCP+UDP)' if ok else (err or out or 'failed')}"


def remote_ufw_allow_game_ports(server, ports, name="Game"):
    """Open a LIST of ports (each bare rule = TCP+UDP), all tagged with the game
    server's name. Idempotent — re-opening an existing port is a no-op. Used to open
    every port a game actually needs (game/query/rcon/etc.), not just the main one."""
    opened = []
    for p in sorted({int(x) for x in ports if x}):
        cnt, _ = remote_ufw_allow_game_port(server, p, name)
        if cnt:
            opened.append(p)
    return opened, f"opened {len(opened)} port(s): {', '.join(map(str, opened)) or 'none'}"


def remote_ufw_close_by_name(server, name):
    """Delete ALL UFW rules tagged with a game server's name (its comment). Used on
    uninstall so multi-port games are fully cleaned up. Deletes highest-numbered
    rule first so the numbering stays valid as rules are removed."""
    comment = re.sub(r"[^A-Za-z0-9 _.-]", "", name or "")[:60]
    if not comment:
        return 0, "no name"
    out, _, _ = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15)
    nums = []
    for line in (out or "").splitlines():
        m = re.match(r"^\s*\[\s*(\d+)\]\s*(.*)$", line)
        if m and re.search(r"#\s*" + re.escape(comment) + r"\s*$", m.group(2)):
            nums.append(int(m.group(1)))
    deleted = sum(1 for n in sorted(nums, reverse=True) if remote_ufw_delete_rule(server, n)[0])
    return deleted, f"{deleted} rule(s) removed for {comment}"


def remote_ufw_close_game_port(server, port):
    """Remove the game server port rule (used on uninstall). Handles the new
    single bare rule plus any legacy proto-specific / port+1 rules from older installs."""
    n = 0
    ok, _ = remote_ufw_close_port(server, port)  # new-style bare rule (both protocols)
    n += 1 if ok else 0
    for p in (port, port + 1):  # legacy cleanup: old proto-specific + port+1 rules
        for proto in ("tcp", "udp"):
            ok, _ = remote_ufw_close_port(server, p, proto)
            n += 1 if ok else 0
    return n, f"Port {port}: {n} rule(s) removed"


# LinuxGSM dependencies common to most game servers on Debian/Ubuntu. The game
# user has no sudo, so the panel installs these as root before/around auto-install.
# A Debian package name, optionally with an architecture qualifier (libstdc++5:i386). Debian
# policy: lowercase alphanumeric plus + - . , at least two characters, starting alphanumeric.
APT_PKG_RE = re.compile(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9][a-z0-9-]*)?\Z")


def _apt_pkgs(names):
    """The names from `names` that really are package names, in order, without duplicates."""
    out = []
    for n in names:
        n = (n or "").strip()
        if n and n not in out and APT_PKG_RE.fullmatch(n):
            out.append(n)
        elif n and not APT_PKG_RE.fullmatch(n):
            _core._log.warning("dependency list: refusing %r — not a package name", n[:60])
    return out


LGSM_COMMON_DEPS = (
    "curl wget ca-certificates file bzip2 gzip xz-utils unzip bsdmainutils pigz "
    "python3 binutils bc jq tmux netcat-openbsd distro-info "
    # 32-bit runtimes for SteamCMD + game binaries. libstdc++5:i386 (universe) is the
    # ancient libstdc++.so.5 that old titles like Call of Duty need to start.
    "lib32gcc-s1 lib32stdc++6 lib32z1 libsdl2-2.0-0:i386 libc6:i386 libstdc++5:i386"
)


_DEPS_CSV_CACHE = {}


# Per-distro package lists, keyed by slug — one host may be 22.04 and another 24.04.
#
# Registered, and keyed by the remote id alone. It had NO expiry and was not registered, and its
# key was the tuple ("srv", id) — which forget_remote_caches could not have popped even if it had
# been. That is the exact shape firewall.py's _specs_cache note describes: delete a remote, add
# another that takes the same rowid (SQLite reuses them), and deps_for_game loads the DELETED
# host's distro package list. A Debian 12 box gets ubuntu-22.04.csv; apt-get install is atomic, so
# one nonexistent package aborts the batch and install_game_dependencies' per-package fallback
# silently drops the rest. The game server then fails to start on a missing library with nothing
# in the log pointing at why, for the life of the process.
_OS_SLUG_CACHE = _core.register_remote_cache({})


def host_os_slug(server):
    """The host's '<id>-<version>' from /etc/os-release ('ubuntu-22.04', 'debian-12'), or None.

    LinuxGSM names its package lists exactly this way, so the slug IS the filename. Cached per
    host: a box does not change release between two package installs, and this would otherwise be
    an extra SSH round trip on every install.
    """
    key = _pro_key(server)
    if key in _OS_SLUG_CACHE:
        return _OS_SLUG_CACHE[key]
    slug = None
    try:
        out, _, rc = _core.run_command(
            server,
            '. /etc/os-release 2>/dev/null; printf %s "${ID}-${VERSION_ID}"',
            timeout=10)
        cand = (out or "").strip().lower()
        # Validated by lgsm_data before it can reach a URL; this is just the cheap early reject.
        if rc == 0 and 3 < len(cand) < 24:
            slug = cand
    except Exception:
        _core._log.debug("could not read the host's os-release", exc_info=True)
    _OS_SLUG_CACHE[key] = slug
    return slug


def _load_deps_csv(os_slug=None):
    """LinuxGSM's package list for this host's distro, as {key: [packages]}; keys are 'all',
    'steamcmd', and each game shortname. Fetched and cached rather than committed here — see
    lgsm_data — and chosen per distro rather than always Ubuntu 24.04."""
    from panel.services import lgsm_data
    name = lgsm_data.deps_name(os_slug)
    if _DEPS_CSV_CACHE.get(name) is not None:
        return _DEPS_CSV_CACHE[name]
    data = lgsm_data.deps(os_slug)
    if data:                       # never memoise a failed fetch — a retry must be able to win
        _DEPS_CSV_CACHE[name] = data
    return data


def deps_for_game(game_type, os_slug=None):
    """Exact packages LinuxGSM needs for a game on THIS HOST'S distro: the 'all' base
    deps + steamcmd deps + the game's own extra deps (e.g. cod → libstdc++5:i386,
    mc → openjdk). Returns (packages, needs_steamcmd) — steamcmd is handled
    separately because it lives in `multiverse` and needs its EULA pre-accepted."""
    csv = _load_deps_csv(os_slug)
    pkgs = []
    needs_steamcmd = False
    for key in ("all", "steamcmd", game_type or ""):
        for p in csv.get(key, []):
            if not p:
                continue
            if p == "steamcmd":
                needs_steamcmd = True
                continue
            if p not in pkgs:
                pkgs.append(p)
    return pkgs, needs_steamcmd


def install_game_dependencies(server, game_type=None, extra=""):
    """Install the exact LinuxGSM dependencies for a game (from LinuxGSM's list for this host's
    distro — a 22.04 box gets 22.04's packages, not 24.04's),
    plus any extras, as root. Falls back to the common set if the CSV is missing.
    Enables i386 + universe + multiverse first, then installs the batch, and if that
    fails (apt-get install is atomic — one unavailable package aborts everything)
    falls back to installing each package individually so the critical libs still
    land. `steamcmd` (needed by every Steam game — gmod/cs/tf2/rust/…) is installed
    specially: it's in `multiverse` and its Steam license must be pre-accepted via
    debconf or apt hangs waiting for interactive input."""
    if game_type:
        per_game, needs_steamcmd = deps_for_game(game_type, host_os_slug(server))
    else:
        per_game, needs_steamcmd = [], True  # unknown game → make sure steamcmd is present
    # A retry may pass "steamcmd" back via `extra` (LinuxGSM lists it as missing).
    extra_pkgs = (extra or "").split()
    if "steamcmd" in extra_pkgs:
        needs_steamcmd = True
        extra_pkgs = [p for p in extra_pkgs if p != "steamcmd"]
    base = " ".join(per_game) if per_game else LGSM_COMMON_DEPS
    # Every name is checked against APT_PKG_RE before it reaches the pipeline below, which runs as
    # ROOT with the list interpolated bare (twice — the batch install and the per-package retry).
    #
    # `per_game` comes from lgsm_data.deps(), which parses data/lgsm/<distro>.csv with no charset
    # check at all: it splits on commas and keeps whatever is between them. _looks_like() guards
    # the FETCH path only — a cache file already on disk is read straight back, and data/lgsm/ is
    # inside the panel's own data directory. So a package list is panel-writable input arriving at
    # a root shell, and `cod,libstdc++5:i386 $(id > /tmp/pwned)` reached it intact. Commas are the
    # field separator, which rules out nothing: $(), backticks and ; need no comma.
    #
    # Dropping a bad name rather than refusing the batch: an unparseable entry in LinuxGSM's own
    # CSV must not make "install dependencies" fail shut on every game.
    pkgs = " ".join(_apt_pkgs(base.split() + extra_pkgs))
    steam_block = ""
    if needs_steamcmd:
        steam_block = (
            "echo steam steam/question select 'I AGREE' | debconf-set-selections ; "
            "echo steam steam/license note '' | debconf-set-selections ; "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y steamcmd steamcmd:i386 2>&1 | tail -3 "
            "|| DEBIAN_FRONTEND=noninteractive apt-get install -y steamcmd 2>&1 | tail -3 || true ; "
        )
    pipeline = (
        "dpkg --add-architecture i386 >/dev/null 2>&1 ; "
        "add-apt-repository -y universe >/dev/null 2>&1 || true ; "
        "add-apt-repository -y multiverse >/dev/null 2>&1 || true ; "
        "apt-get update -qq >/dev/null 2>&1 ; "
        f"{steam_block}"
        f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkgs} 2>&1 | tail -4 "
        f"|| for p in {pkgs} ; do DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \"$p\" >/dev/null 2>&1 || true ; done ; "
        "echo deps-done"
    )
    # sudo=True, not a hand-built `sudo bash -c` with sudo=False — which is what this was, and
    # which produces the IDENTICAL command while being invisible to all three escalation ratchets:
    # one counts calls to a function NAMED _sudo_sh, one counts the sudo=True keyword, and one
    # scans for argv LISTS starting with the literal "sudo". An f-string passed with sudo=False
    # matches none of them, so SECURITY.md's "0 — the route is gone" was contradicted by the code
    # and no gate could say so. The two other steps in this module that deliberately keep a shell
    # (NodeSource, Tailscale) already pass sudo=True and carry a comment saying why.
    out, err, rc = _core.run_command(server, pipeline, timeout=1200, sudo=True)
    return rc == 0, (out or err)


def parse_missing_deps(output):
    """Extract package names LinuxGSM reported as missing (from its
    'Missing dependencies: pkg1 pkg2 ... Run:' warning)."""
    text = terminal.strip_escapes(output or "")
    deps = []
    for m in re.finditer(r"[Mm]issing dependencies:\s*(.+?)(?:\s+Run:|[\r\n]|$)", text):
        for pkg in m.group(1).split():
            if re.match(r"^[a-z0-9][a-z0-9+._:-]*\Z", pkg) and pkg not in deps:
                deps.append(pkg)
    return deps




# ─── Remote OS Commands ───────────────────────────────────────


def _parse_upgradable(out):
    """Parse `apt list --upgradable` output — the local check parses the identical format, so both
    go through system_ops.parse_upgradable rather than keeping two copies in step by hand."""
    from panel.ops import system_ops
    return system_ops.parse_upgradable(out)


def remote_os_check_updates(server):
    """Check for OS updates on the remote server.
    Returns {ok, count, packages:[{name,version,from,suite}]}.

    "ok" is apt's own exit status, and it matters: a check that FAILED (the apt lock held by
    unattended-upgrades, the host mid-reboot) produces no output, which reads exactly like a clean
    host. A caller that takes that for "nothing waiting" will re-announce the same package list the
    next time the check succeeds. The filtering greps this pipeline used to end with are gone for
    the same reason — grep exits 1 when a clean host matches nothing, so its status masked apt's."""
    _core.run_privileged(server, "apt-update", [], timeout=60, merge_stderr=False)
    out, _, rc = _core.run_command(server, "apt list --upgradable 2>/dev/null", timeout=30)
    pkgs = _parse_upgradable(out)
    return {"ok": rc == 0, "count": len(pkgs), "packages": pkgs}


def remote_os_run_updates(server):
    """Run apt upgrade on the remote server (blocking; kept for callers that want a one-shot).
    The UI uses the streaming remote_os_update_start/_status pair instead."""
    out, err, rc = _core.run_privileged(server, "apt-full-upgrade", ["phased"], timeout=600)
    return rc == 0, out[-300:] if out else err[:300]


# The panel no longer names the OS-update log at all. Until #122 the detached runner lived here and
# wrote the file by name, so this module needed its own alias for the path; now the helper owns both
# the writing and the reading (the os-update-log verb hands back the contents), and the only copies
# that must agree are privileged.OS_UPDATE_LOG and the helper's. The alias outlived that move as an
# unused global — CodeQL alert #352 — and is gone rather than left to imply a coupling that ended.
#
# The sentinel the detached job ends with; the verb table owns it so the writer and this
# reader cannot disagree about what "finished" looks like.
_OS_UPDATE_DONE = _priv.OS_UPDATE_DONE


def remote_os_update_start(server):
    """Kick off `apt upgrade` DETACHED, streaming output to a log the UI polls, so it survives the
    request and can be watched live. Fully non-interactive with SAFE auto-answers — keep any existing
    config file on a conflict (never clobber your edits) and assume-yes — so it can't hang waiting on
    a prompt; the log records what it decided. Returns (ok, message)."""
    # Don't launch a second run on top of one already going.
    # pgrep exits 0 when it matched something, 1 when it did not — the `&& echo RUN || echo IDLE`
    # only translated that into text for a string check.
    _, _, chk_rc = _core.run_privileged(server, "apt-upgrade-running", [], timeout=10, merge_stderr=False)
    if chk_rc == 0:
        return True, "An update is already running — watching it."
    # Was one `setsid bash -c '<script>'` wrapping seven shell statements. It took no caller input
    # at all — the only variables in it were two constants — which is what lets it be a
    # zero-argument verb rather than a command the panel composes.
    out, _, _ = _core.run_privileged(server, "os-update-run", [], timeout=20)
    if _priv.OS_UPDATE_STARTED in (out or ""):
        return True, "Update started."
    return False, "Couldn't start the update."


def remote_os_update_status(server):
    """Live status of the running/last OS update: {running, done, rc, log}. `done` is set once the
    detached job appends its sentinel; `running` reflects whether apt is still working."""
    out, _, _ = _core.run_privileged(server, "os-update-log", [], timeout=15, merge_stderr=False)
    log = out or ""
    m = re.search(re.escape(_OS_UPDATE_DONE) + r"(-?\d+)", log)
    done = m is not None
    rc = int(m.group(1)) if m else None
    if done:
        log = re.sub(r"\n?" + re.escape(_OS_UPDATE_DONE) + r"-?\d+\s*$", "", log)
        return {"running": False, "done": True, "rc": rc, "log": log}
    # No sentinel yet — is apt still working?
    _, _, alive_rc = _core.run_privileged(server, "apt-any-running", [], timeout=10, merge_stderr=False)
    return {"running": alive_rc == 0, "done": False, "rc": None, "log": log}


def remote_reboot(server):
    """Reboot the remote server."""
    _core.run_privileged(server, "reboot", [], timeout=10)
    return True, "Reboot command sent to remote"


def remote_reboot_required(server):
    """Whether a host needs a reboot to finish applying updates. Debian/Ubuntu drop
    /var/run/reboot-required after a kernel/libc upgrade, and list the responsible packages in
    /var/run/reboot-required.pkgs. Works for the panel host too (run_command runs it locally when
    the server is is_local). Returns {'required': bool, 'packages': [str, ...]}. Best-effort."""
    try:
        out, _, _ = _core.run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=12)
    except Exception:
        return {"required": False, "packages": []}
    if "YES" not in (out or ""):
        return {"required": False, "packages": []}
    packages = []
    try:
        pk, _, _ = _core.run_command(server, "cat /var/run/reboot-required.pkgs 2>/dev/null", timeout=12)
        packages = sorted({p.strip() for p in (pk or "").splitlines() if p.strip()})
    except Exception:
        packages = []
    return {"required": True, "packages": packages}


_uptime_cache = _core.register_remote_cache({})   # server.id -> (expiry, dict), de-dups viewers
_UPTIME_TTL = 8      # the manage-remotes card polls ~every 15s; this only collapses overlap


def remote_uptime(server, force=False):
    """Uptime, CPU%, RAM, disk, kernel from the remote — in a SINGLE SSH round-trip (this used
    to be EIGHT separate commands, incl. a `top -bn1`, on every 15s poll). CPU% is a /proc/stat
    delta over 0.25s, which is far lighter than spawning top. Cached briefly so several viewers
    of the Remotes page share one read instead of each doing their own."""
    now = time.time()
    if not force and server is not None:
        hit = _uptime_cache.get(server.id)
        if hit and hit[0] > now:
            return hit[1]
    # One composite command with tagged lines, parsed below — one round-trip, one process spawn.
    parts = [
        "echo UPTIME $(uptime -p)",
        "awk '{print \"LOAD\",$1,$2,$3}' /proc/loadavg",
        "df -h / | tail -1 | awk '{print \"DISK\",$3\"/\"$2}'",
        "free -h | awk '/Mem:/{print \"MEM\",$3\"/\"$2}'",
        "free | awk '/Mem:/{printf \"MEMPCT %.1f\\n\", $3/$2*100}'",
        "echo KERNEL $(uname -r)",
        "echo CORES $(nproc)",
        "grep '^cpu ' /proc/stat", "sleep 0.25", "grep '^cpu ' /proc/stat",
    ]
    out, _, _ = _core.run_command(server, " ; ".join(parts), timeout=15)
    d = {"uptime": "unknown", "load": "?", "disk": "?", "memory": "?", "memory_percent": "?",
         "kernel": "?", "cpu_percent": "?", "cpu_cores": "?", "cpu_per_core": ""}
    cpu_lines = []
    for line in (out or "").splitlines():
        f = line.split()
        if not f:
            continue
        tag = f[0]
        if tag == "cpu" and len(f) >= 8:
            cpu_lines.append([int(x) for x in f[1:8]])
        elif tag == "UPTIME":
            d["uptime"] = line[7:].replace("up ", "").strip() or "unknown"
        elif tag == "LOAD" and len(f) >= 4:
            d["load"] = f"{f[1]} {f[2]} {f[3]}"
        elif tag == "DISK" and len(f) >= 2:
            d["disk"] = f[1]
        elif tag == "MEM" and len(f) >= 2:
            d["memory"] = f[1]
        elif tag == "MEMPCT" and len(f) >= 2:
            d["memory_percent"] = f[1]
        elif tag == "KERNEL" and len(f) >= 2:
            d["kernel"] = f[1]
        elif tag == "CORES" and len(f) >= 2:
            d["cpu_cores"] = f[1]
    if len(cpu_lines) >= 2:
        a, b = cpu_lines[0], cpu_lines[1]
        idle = b[3] - a[3]
        total = sum(b) - sum(a)
        if total > 0:
            d["cpu_percent"] = f"{round((1 - idle / total) * 100, 1)}"
    if d["cpu_percent"] not in ("?", "") and d["cpu_cores"].isdecimal():
        try:
            d["cpu_per_core"] = f"{float(d['cpu_percent']) / int(d['cpu_cores']):.1f}"
        except (ValueError, ZeroDivisionError):
            _core._log.debug("remote_uptime: per-core calc skipped", exc_info=True)
    if server is not None and out:   # don't cache a failed/empty read
        _uptime_cache[server.id] = (now + _UPTIME_TTL, d)
    return d


# ─── Full VPS Bootstrap ─────────────────────────────────


def _wait_for_reboot(server, on_wait=None, down_timeout=150, up_timeout=480):
    """After issuing a reboot, wait for the remote to drop then come back on SSH.
    Returns True if it came back online within the timeout."""
    def _up():
        try:
            ok, _ = ssh_test_connection(
                server.host, server.port or 22, server.username,
                server.auth_method, decrypt_secret(server.auth_credential),
                host_key=server.host_key or "",
            )
            return ok
        except Exception:
            return False

    # Phase 1: wait for it to actually go down (confirms the reboot began).
    t0 = time.time()
    while time.time() - t0 < down_timeout:
        if not _up():
            break
        if on_wait:
            on_wait("Waiting for server to go down for reboot…")
        time.sleep(5)

    # Phase 2: wait for SSH to come back.
    t0 = time.time()
    while time.time() - t0 < up_timeout:
        if _up():
            return True
        if on_wait:
            on_wait("Rebooting — waiting for server to come back online…")
        time.sleep(5)
    return False


def remote_bootstrap_vps(server, set_timezone="UTC", enable_ufw=True, install_lgsm_deps=True,
                           username="", install_fail2ban=True, do_reboot=True,
                           progress=None):
    """One-shot bootstrap of a fresh Ubuntu VPS.

    Runs: system updates → essential packages → timezone → UFW firewall →
    SSH hardening → swap → disable bloat → LinuxGSM user → fail2ban → reboot.

    `progress`, if given, is called as progress(step, total, name, status) after
    each step so the caller can stream live status ("running" / "rebooting" / ...).

    Returns (success, message, log).
    """
    log = []
    step = 0

    # Precompute the total step count so the progress bar is accurate.
    is_local = _core.is_local_server(server)
    total = 8  # lock, update, full-upgrade, autoremove, install, node-lts, gamedig, unattended-upgrades
    total += 1 if set_timezone else 0
    total += 1 if enable_ufw else 0
    total += 2  # ssh hardening, swap
    total += 1  # disable services
    total += 1 if username else 0
    total += 1 if install_fail2ban else 0
    total += 1 if not is_local else 0   # a reboot-check step (may reboot, skip, or report none needed)

    def emit(name, status="running", detail=None):
        nonlocal step
        step += 1
        log.append(f"[{step}/{total}] {name}")
        if detail:
            log.append(f"   {detail}")
        if progress:
            try:
                progress(step, total, name, status)
            except Exception:
                _core._log.debug("emit: ignored non-fatal error", exc_info=True)

    def note(text, status="running"):
        log.append(f"   {text}")
        if progress:
            try:
                progress(step, total, text, status)
            except Exception:
                _core._log.debug("note: ignored non-fatal error", exc_info=True)

    # ── 1. Wait for cloud-init / apt to settle ──
    emit("Waiting for package manager to be free")
    _core._wait_for_dpkg_lock(server, timeout=180)

    # ── 2. Update apt cache + full upgrade ──
    emit("Updating package lists (apt update)")
    _core.run_privileged(server, "apt-update", [], timeout=180)

    emit("Full-upgrading all packages (apt full-upgrade — may take several minutes)")
    out, _, _ = _core.run_privileged(server, "apt-full-upgrade", ["standard"], timeout=1800)
    out = _core._last_lines(out, 8)
    note(out or "OK")

    emit("Removing unused packages (autoremove)")
    _core.run_privileged(server, "apt-autoremove", [], timeout=180)

    # ── 3. Install essential packages (jq parses gamedig's JSON output) ──
    emit("Installing essential packages")
    pkgs = ("curl wget git ufw tmux htop net-tools unzip jq ca-certificates "
            "software-properties-common unattended-upgrades apt-listchanges")
    if install_lgsm_deps:
        # LinuxGSM base dependencies (32-bit libs for SteamCMD, etc.)
        pkgs += " python3 python3-pip bc lib32gcc-s1 lib32stdc++6 libsdl2-2.0-0:i386"
    if install_fail2ban:
        pkgs += " fail2ban"
    # Three statements joined with ';' in one root shell — three verbs now.
    _core.run_privileged(server, "dpkg-add-arch", ["i386"], timeout=120, merge_stderr=False)
    _core.run_privileged(server, "apt-add-repo", ["universe"], timeout=120, merge_stderr=False)
    _core.run_privileged(server, "apt-update", [], timeout=120, merge_stderr=False)
    out, _, _ = _core.run_privileged(server, "apt-install", pkgs.split(), timeout=600)
    note(_core._last_lines(out, 6) or "OK")

    # ── 3a. Node.js LTS via NodeSource — apt's own nodejs is too old for current gamedig
    # (gamedig v5 needs Node >=18; e.g. Ubuntu 22.04's apt ships Node 12). Idempotent. ──
    emit("Installing Node.js LTS")
    # NOT converted to a verb, deliberately. This pipes a downloaded script into a root shell, and
    # that IS the operation — a verb could pin the URL, but only by giving the helper the ability to
    # execute a downloaded script, which is exactly the capability its tool allowlist exists to
    # deny. Wrapping it would move the risk, not reduce it. Named in SECURITY.md instead.
    node_cmd = (
        'n=$(node -v 2>/dev/null | grep -oE "[0-9]+" | head -1); '
        'if [ "${n:-0}" -lt 18 ]; then '
        'curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1 && '
        'DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs 2>&1 | tail -3; '
        'else echo "Node $(node -v) already present"; fi'
    )
    nd_out, _, _ = _core.run_command(server, node_cmd, timeout=300, sudo=True)
    note(nd_out or "Node.js LTS installed")

    # ── 3b. gamedig (game-server query tool) via npm — idempotent (skip if already present) ──
    emit("Installing gamedig (game server query tool)")
    # `command -v gamedig || npm install -g gamedig` was a shell builtin guarding an install.
    # npm install -g is idempotent, so the guard only saved time — and it cost a root shell.
    gd_out, _, _ = _core.run_privileged(server, "npm-install-global", ["gamedig"], timeout=300)
    note(_core._last_lines(gd_out, 3) or "gamedig installed")
    ensure_node_tools_cron(server)   # weekly auto-update for npm + gamedig, alongside apt auto-updates
    note("weekly npm/gamedig auto-update scheduled")

    # ── 3c. Enable + configure unattended-upgrades (auto security updates) ──
    emit("Enabling automatic security updates (unattended-upgrades)")
    au_conf = (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
        'APT::Periodic::Download-Upgradeable-Packages "1";\n'
    )
    _core.write_root_file(server, "apt-auto-upgrades", au_conf, timeout=30)
    _core.run_privileged(server, "service-enable-now", ["unattended-upgrades"], timeout=30)

    # ── 4. Set timezone ──
    if set_timezone:
        emit(f"Setting timezone to {set_timezone}")
        # set_timezone is user-supplied and runs as root — quote it against injection.
        _core.run_privileged(server, "set-timezone", [set_timezone], timeout=10)

    # ── 5. Configure UFW ──
    if enable_ufw:
        emit("Configuring UFW firewall (deny incoming, rate-limit SSH)")
        # Rate-limit SSH by default — `ufw limit` allows SSH (so we never lock ourselves
        # out) while throttling brute-force sources. We do NOT add a plain `allow 22`:
        # a lower-numbered allow rule would match first and shadow the limit, leaving SSH
        # effectively unthrottled.
        _core.run_privileged(server, "ufw-limit-port", ["22/tcp"], timeout=15)
        _core.run_privileged(server, "ufw-default", ["deny", "incoming"], timeout=15)
        _core.run_privileged(server, "ufw-default", ["allow", "outgoing"], timeout=15)
        _core.run_privileged(server, "ufw-enable", [], timeout=15)

    # ── 6. Basic SSH hardening ──
    emit("Hardening SSH configuration")
    # These keepalive tweaks are always safe (they never affect how you log in).
    # Each of these was a `sed -i 's/^#\\?Key.*/Key value/'` in a joined root shell. They are
    # verbs now, and both the directive and the value come from a closed set — the panel can set
    # exactly the four it hardens, to exactly the values it hardens them to.
    hardening = [("ClientAliveInterval", "300"), ("ClientAliveCountMax", "2")]
    if server.auth_method != "password":
        # Only lock down root-password + password login when we authenticate with a
        # key or Tailscale. NEVER touch these on a password-auth remote or the reboot
        # would lock everyone (including you via PuTTY) out of the box.
        hardening += [("PermitRootLogin", "prohibit-password"), ("PasswordAuthentication", "no")]
    for _key, _val in hardening:
        _core.run_privileged(server, "sshd-set-directive", [_key, _val], timeout=20, merge_stderr=False)
    if server.auth_method != "password":
        _core._restart_sshd(server, timeout=15)
    else:
        note("Password + root-password SSH login left ENABLED — this remote authenticates with a password, so SSH access was not restricted.")

    # ── 7. Create swap if none exists ──
    emit("Ensuring swap space exists")
    swap_out, _, _ = _core.run_command(server, "swapon --show | wc -l", timeout=10)
    if swap_out.strip() == "0":
        _core.run_privileged(server, "create-swapfile", [], timeout=60, merge_stderr=False)
        note("2G swap file created")
    else:
        note("Swap already present")

    # ── 8. Disable unnecessary services ──
    emit("Disabling unnecessary services")
    for svc in ["whoopsie", "cups", "modemmanager"]:
        _core.run_privileged(server, "service-disable-now", [svc], timeout=10, merge_stderr=False)

    # ── 9. Create linuxgsm user if username provided ──
    # `username` arrives raw from the bootstrap request (it doesn't pass through the model's
    # @validates), and it's interpolated into root-run useradd/id/passwd — so validate it to a
    # safe Linux-username charset (must start with a letter/underscore; no shell metacharacters,
    # no leading dash) and refuse anything else rather than let it reach the shell.
    if username and not re.match(r"^[A-Za-z_][A-Za-z0-9._-]*\Z", username):
        note(f"Skipped account creation: '{username[:32]}' isn't a valid username")
    elif username:
        emit(f"Creating LinuxGSM user: {username}")
        out, _, _ = _core.run_command(server, f"id {_core._quote(username)} 2>/dev/null && echo 'EXISTS' || echo 'NOTEXISTS'", timeout=10)
        if "NOTEXISTS" not in out:
            note(f"User {username} already exists")
        else:
            _core.run_privileged(server, "user-create", [username], timeout=15)
            _core.run_privileged(server, "user-lock-password", [username], timeout=10)
            note(f"User {username} created (login password locked)")

    # ── 10. Configure fail2ban ──
    if install_fail2ban:
        emit("Configuring fail2ban (SSH brute-force protection)")
        jail_content = (
            "[DEFAULT]\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\n\n"
            "[sshd]\nenabled = true\nport = 22\n"
        )
        _core.write_root_file(server, "fail2ban-jail-local", jail_content, timeout=15)
        _core.run_privileged(server, "service-enable-now", ["fail2ban"], timeout=20)
        _core.run_privileged(server, "service-restart", ["fail2ban"], timeout=20)

    # ── 11. Reboot ONLY if an update actually requires one, and NEVER out from under running game
    #        servers (a reboot would drop the players). We check /var/run/reboot-required and, before
    #        rebooting, that no tmux/screen game-server sessions are live — otherwise we just flag the
    #        pending reboot so the operator can do it when the host is empty. ──
    if not is_local:
        reboot_req, _, _ = _core.run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=10)
        needs_reboot = "YES" in (reboot_req or "")
        gs_out, _, _ = _core.run_command(server, "if pgrep -x tmux >/dev/null 2>&1 || pgrep -x SCREEN "
                                   ">/dev/null 2>&1; then echo YES; else echo NO; fi", timeout=10)
        servers_running = "YES" in (gs_out or "")
        if not needs_reboot:
            emit("No reboot needed", detail="Updates applied without requiring a reboot.")
        elif servers_running or not do_reboot:
            emit("Reboot required — skipped to protect running servers", status="reboot-required",
                 detail="A kernel/library update needs a reboot. Reboot this host from its page "
                        "once its game servers are empty.")
        else:
            emit("Rebooting to apply a kernel/library update", status="rebooting",
                 detail="A system update requires a reboot and no game servers are running.")
            # Schedule the reboot slightly in the future so this command returns cleanly.
            _core.run_privileged(server, "reboot-delayed", [], timeout=15, merge_stderr=False)
            _core.close_connection(server)
            came_back = _wait_for_reboot(server, on_wait=lambda t: note(t, status="rebooting"))
            if not came_back:
                return False, "Server was rebooted but did not come back online within the timeout.", "\n".join(log)
            note("Server is back online.", status="running")
    else:
        note("Reboot check skipped — this is the panel's own host.")

    if progress:
        try:
            progress(total, total, "Bootstrap complete", "done")
        except Exception:
            _core._log.debug("remote_bootstrap_vps: ignored non-fatal error", exc_info=True)
    return True, f"VPS bootstrap complete ({step}/{total} steps).", "\n".join(log)


# ─── Remote Tailscale Bootstrap ─────────────────────────────


def remote_check_tailscale(server):
    """Check if Tailscale is already installed and running on the remote."""
    installed_out, _, installed_rc = _core.run_command(server, "which tailscale 2>/dev/null && echo 'INSTALLED' || echo 'NOTINSTALLED'", timeout=10)
    installed = "NOTINSTALLED" not in installed_out  # "INSTALLED" is a substring of "NOTINSTALLED"

    running = False
    ts_ip = ""
    dns_name = ""
    if installed:
        out, _, rc = _core.run_command(server, "tailscale status --json 2>/dev/null || echo '{}'", timeout=10)
        if rc == 0 and out:
            try:
                import json
                data = json.loads(out)
                running = data.get("BackendState") == "Running"
                self_data = data.get("Self", {})
                if self_data:
                    dns = self_data.get("DNSName", "")
                    dns_name = dns.rstrip(".") if dns else ""
                    ts_ip = ", ".join(self_data.get("TailscaleIPs", []))
            except Exception:
                _core._log.debug("remote_check_tailscale: ignored non-fatal error", exc_info=True)

    return {
        "installed": installed,
        "running": running,
        "tailscale_ip": ts_ip,
        "dns_name": dns_name,
    }


def remote_install_tailscale(server):
    """Install Tailscale on a remote Ubuntu/Debian VPS.
    Returns (success, message, log).
    """
    log = []

    # 1. Detect OS/distro
    os_out, _, _ = _core.run_command(server, "cat /etc/os-release 2>/dev/null | head -5", timeout=10)
    log.append(f"OS: {os_out[:200]}")

    # 2. Install curl if missing
    out, _, _ = _core.run_privileged(server, "apt-install", ["curl"], timeout=60)
    out = _core._last_lines(out, 3)
    log.append(f"curl: {out}")

    # 3. Add Tailscale repo and install.
    # NOT a verb, for the same reason as the NodeSource step: this pipes a downloaded script into a
    # root shell, and that IS the operation. A verb could pin the URL, but only by giving the helper
    # the ability to execute a downloaded script — the capability its tool allowlist exists to deny.
    cmds = [
        "curl -fsSL https://tailscale.com/install.sh | sh 2>&1",
    ]
    for cmd in cmds:
        out, _, rc = _core.run_command(server, cmd, timeout=120, sudo=True)
        log.append(out[-200:])
        if rc != 0:
            return False, "Tailscale install script failed", "\n".join(log)

    # 4. Verify install
    out, _, rc = _core.run_command(server, "which tailscale && tailscale version 2>&1 | head -1", timeout=10)
    log.append(f"Installed: {out}")
    if rc != 0:
        return False, "Tailscale binary not found after install", "\n".join(log)

    return True, "Tailscale installed successfully", "\n".join(log)


# The login URL `tailscale up` prints. Same charset the remote-side grep looks for, re-checked on
# THIS side because the remote's output is not something we control. Defined in privileged.py so
# this and tailscale_integration's panel-host twin cannot check it differently — they did.
_TS_LOGIN_URL_RE = _priv.TS_LOGIN_URL_RE


def remote_tailscale_up_url(server, enable_ssh=True, advertise_routes=""):
    """Run `tailscale up` (no auth key) in the background and return the browser
    login URL — the user just pastes it into their browser to authorize the node,
    exactly like `tailscale up` on the CLI. tailscale up keeps waiting for auth."""
    if advertise_routes:
        _core.write_root_file(server, "sysctl-tailscale", "net.ipv4.ip_forward = 1\n", timeout=15)
        _core.run_privileged(server, "sysctl-reload", ["tailscale"], timeout=15)
    # Was a shell one-liner: rm, nohup, a redirect, a background job, a seq loop and a grep. The
    # verb starts `tailscale up` detached and polls its OWN log — whose path is fixed in the verb
    # table and lives in /run rather than /tmp, where any local user could have pre-created it.
    out, err, rc = _core.run_privileged(server, "tailscale-up-login",
                                  ["yes" if enable_ssh else "no", advertise_routes or "-"],
                                  timeout=40)
    line = (out or "").strip().split("\n")[-1].strip() if out else ""
    # fullmatch, not startswith: the charset above is enforced by a grep running ON the remote host,
    # so a compromised host simply ignores it and can return anything after the trusted prefix. This
    # URL is rendered into the panel's HTML, so the whole string has to be pinned here, once, rather
    # than left for each consumer to escape.
    if _TS_LOGIN_URL_RE.fullmatch(line):
        return True, line
    status = remote_check_tailscale(server)
    if status.get("running") or line == "ALREADY_CONNECTED":
        return True, "ALREADY_CONNECTED"
    return False, (err or out or "Could not get a Tailscale login link — is Tailscale installed on the remote?")


def remote_bootstrap_tailscale(server, auth_key="", enable_ssh=True, advertise_routes="", tags=""):
    """Authenticate and configure Tailscale on a remote VPS.
    Args:
        auth_key: Tailscale pre-auth key (required for headless setup)
        enable_ssh: Whether to enable Tailscale SSH
        advertise_routes: subnet routes to advertise (e.g. "192.168.1.0/24")
        tags: Comma-separated ACL tags (e.g. "tag:server,tag:lgsm")
    Returns:
        (success, message, full_log)
    """
    log = []

    if not auth_key:
        return False, "Auth key is required. Generate one at https://login.tailscale.com/admin/keys", "\n".join(log)

    # 1. Enable IP forwarding for subnet routing
    if advertise_routes:
        _core.write_root_file(server, "sysctl-tailscale",
                        "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n",
                        timeout=15)
        _core.run_privileged(server, "sysctl-reload", ["tailscale"], timeout=15)
        log.append("IP forwarding enabled")

    # 2. Build the up command. auth_key / advertise_routes / tags are user-supplied and run
    # in a root shell, so every one is shell-quoted to prevent command injection.
    # Every flag was shell-quoted into a root command. They are validated arguments now: routes are
    # PARSED as networks, tags must each be `tag:name`, and the auth key is charset-checked and
    # never echoed back — not even in a rejection message.
    out, err, rc = _core.run_privileged(server, "tailscale-up-key",
                                  [auth_key, "yes" if enable_ssh else "no",
                                   advertise_routes or "-", tags or "-"], timeout=60)
    log.append(f"tailscale up: {out[-300:] if out else ''}")
    if rc != 0:
        return False, f"Tailscale auth failed: {err or out[-200:]}", "\n".join(log)

    # 3. Enable UFW for Tailscale if UFW is active
    ufw_out, _, _ = _core.run_privileged(server, "ufw-status", ["plain"], timeout=10)
    if firewall._ufw_is_active(ufw_out):
        _core.run_privileged(server, "ufw-allow-iface", ["tailscale0"], timeout=15)
        log.append("UFW: allowed tailscale0 interface")

    # 4. Get status
    status = remote_check_tailscale(server)
    log.append(f"Status: ip={status['tailscale_ip']} dns={status['dns_name']}")

    if status["running"]:
        return True, f"Tailscale connected! IP: {status['tailscale_ip']} DNS: {status['dns_name']}", "\n".join(log)
    else:
        return False, "Tailscale installed but not running after auth", "\n".join(log)


def remote_migrate_to_tailscale(server, new_auth_method="tailscale"):
    """After Tailscale is bootstrapped on a remote, update the local RemoteServer
    record to use Tailscale SSH instead of raw SSH. Also closes port 22 on UFW
    since we've verified the tailscale0 interface is allowed.
    This is done via the caller, not here, since we need the DB session.
    Returns the new host IP/hostname to use.
    """
    status = remote_check_tailscale(server)
    if not status["running"]:
        return None, "Tailscale is not running on the remote"
    # Prefer MagicDNS name, fall back to Tailscale IP.
    #
    # The parentheses are load-bearing. `a or b if c else d` binds as `(a or b) if c else d`, so
    # without them a node that HAS a MagicDNS name but reports no address returned server.host —
    # the pre-migration address — while the caller went on to set auth_method="tailscale", blank
    # the stored SSH credential and force port 22. The record then pointed at the old host with no
    # way back, and the panel reported "Migrated to Tailscale SSH: <old host>".
    new_host = status["dns_name"] or (status["tailscale_ip"].split(", ")[0]
                                      if status["tailscale_ip"] else server.host)

    # Safely close port 22 on UFW since tailscale0 is already allowed
    try:
        remote_ufw_close_port_22(server)
    except Exception:
        _core._log.debug("Non-fatal — might already be removed", exc_info=True)

    return new_host, status


def remote_tailscale_finalize(server):
    """Run right after a node joins the tailnet (login-URL flow): ensure the
    tailscale0 interface is allowed through UFW so tailnet traffic and Tailscale
    SSH are never blocked. Idempotent. Returns (status_dict, log)."""
    log = []
    ufw_out, _, _ = _core.run_privileged(server, "ufw-status", ["plain"], timeout=10)
    if firewall._ufw_is_active(ufw_out):
        _core.run_privileged(server, "ufw-allow-iface", ["tailscale0"], timeout=15)
        log.append("UFW: allowed tailscale0 interface (in)")
    status = remote_check_tailscale(server)
    return status, "\n".join(log)


def remote_ufw_close_port_22(server):
    """Remove port 22/tcp UFW rule (safe if Tailscale SSH is active)."""
    out, err, rc = _core.run_privileged(server, "ufw-delete-allow-port", ["22/tcp"], timeout=15)
    if rc == 0:
        return True, "Port 22 rule removed from UFW"
    return False, err or out or "Failed to remove port 22"


def _sshd_current_ports(server):
    """The ports sshd currently listens on (from its *effective* config). Empty on failure."""
    # Was `sshd -T | awk 'tolower($1)=="port"{print $2}'` — an awk program running as root to do
    # what a list comprehension does. The verb returns the effective config; the parsing is here.
    out, _, _ = _core.run_privileged(server, "sshd-effective-config", [], timeout=15, merge_stderr=False)
    ports = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "port" and parts[1].isdecimal():
            ports.append(parts[1])
    return ports


def _canonical_ip(s):
    """`s` as its CANONICAL address string, or None if it isn't an IP.

    Canonical matters: fail2ban and ufw store the normalised form, so unbanning
    "2001:0DB8::0001" against a stored "2001:db8::1" silently matches nothing. Two of the three
    remote helpers already normalised; the unban one compared the raw string."""
    import ipaddress
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return None


def _valid_ip(s):
    """True if `s` is a valid IPv4 or IPv6 literal. Prefer _canonical_ip when the value is going to
    be COMPARED or sent to a tool that stores a normalised form."""
    return _canonical_ip(s) is not None


_F2B_JAIL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")


def remote_fail2ban_overview(server):
    """fail2ban jails + their current bans on a REMOTE host, over SSH. Mirrors the panel-host version
    but runs fail2ban-client on the remote. {'installed': bool, 'jails': [detail,...]}."""
    # `command -v fail2ban-client` was a shell builtin probe, and it escalated on any host with
    # sudo enabled. Asking fail2ban for its status answers the same question: a missing tool is
    # rc 127 from the helper and from the SSH path alike.
    out, err, rc = _core.run_privileged(server, "f2b-status", [], timeout=15, merge_stderr=False)
    if rc == 127 or "not found" in (out + err).lower():
        return {"installed": False, "jails": []}
    m = re.search(r"Jail list:\s*(.*)", out or "")
    jails = [j.strip() for j in (m.group(1).split(",") if m else []) if _F2B_JAIL_RE.match(j.strip())]
    details = []
    for jail in jails:
        jo, _, jrc = _core.run_privileged(server, "f2b-status-jail", [jail], timeout=15,
                                    merge_stderr=False)
        if jrc != 0 or not jo:
            continue

        def _num(label):
            mm = re.search(label + r":\s*(\d+)", jo)
            return int(mm.group(1)) if mm else 0
        mi = re.search(r"Banned IP list:\s*(.*)", jo)
        ips = [ip for ip in (mi.group(1).split() if mi else []) if ip]
        details.append({"jail": jail, "currently_banned": _num("Currently banned"),
                        "total_banned": _num("Total banned"), "total_failed": _num("Total failed"),
                        "banned_ips": ips})
    return {"installed": True, "jails": details}


# Default UFW comment tag so the panel recognises its OWN deny rules. The rolling-auto-block tag
# ("panel-autoblock") is passed in by the caller (app.py) when it reconciles.
_UFW_BLOCK_TAG = "panel-block"          # a one-off manual block


def remote_ufw_deny_ip(server, ip, tag=_UFW_BLOCK_TAG):
    """Firewall-block an IP on ALL ports via a UFW deny rule, inserted at the top so it beats any
    allow, and tagged in the rule comment so the panel recognises its own blocks. The IP is reparsed
    to its canonical ipaddress form so nothing request-supplied reaches the shell unchecked. (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    tag = re.sub(r"[^a-z0-9-]", "", (tag or ""))[:32] or _UFW_BLOCK_TAG
    # Drop any existing deny for this IP first (no duplicate rules), then insert at position 1.
    # run_command wraps the whole compound in `sudo bash -c`, so both parts run as root and rc is
    # the insert's exit status.
    # Two statements used to be joined with ';' inside one `sudo bash -c`. They are two verbs now;
    # the delete's result is discarded exactly as `>/dev/null 2>&1` discarded it, and rc still comes
    # from the insert.
    _core.run_privileged(server, "ufw-delete-deny-ip", [ip], timeout=20)
    out, err, rc = _core.run_privileged(server, "ufw-deny-ip", [ip, tag], timeout=20)
    if rc == 0:
        return True, "Blocked %s (all ports)." % ip
    return False, ((out or err or "Block failed").replace("\n", " ")[:200])


def remote_ufw_undeny_ip(server, ip):
    """Remove a UFW deny rule for an IP (canonicalised first). (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    _core.run_privileged(server, "ufw-delete-deny-ip", [ip], timeout=15)
    return True, "Unblocked %s." % ip


def remote_ufw_blocked_ips(server):
    """{ip: tag} for the panel's own UFW deny rules — tag read from the rule comment. Best-effort."""
    out, _, _ = _core.run_privileged(server, "ufw-status", ["plain"], timeout=15)
    blocked = {}
    for line in (out or "").splitlines():
        if "DENY" not in line or "panel-" not in line:
            continue
        mi = re.search(r"DENY(?:\s+IN)?\s+([0-9a-fA-F:.]+)", line)
        mt = re.search(r"#\s*(panel-[a-z-]+)", line)
        if mi and mt:
            blocked[mi.group(1)] = mt.group(1)
    return blocked


def remote_fail2ban_top_ips(server, limit=20, days=7):
    """Top offending IPs from a REMOTE host's fail2ban log over the last `days` days (current +
    rotated logs), ranked by detected attempts. Each: {ip, attempts, bans, banned_now, blocked}.
    Fixed counting pipeline (no request input in the shell). Best-effort ([] on failure)."""
    from datetime import datetime, timedelta
    try:
        limit = max(1, min(int(limit or 20), 100))
    except (TypeError, ValueError):
        limit = 20
    try:
        days = max(1, min(int(days or 7), 90))
    except (TypeError, ValueError):
        days = 7
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")   # panel clock; no shell input
    # The remote twin of system_ops.fail2ban_top_ips, which #118 converted. Same split: the verb
    # reads and filters the rotated logs, and the tally — the second awk — is the shared Python.
    from panel.ops import system_ops as _so
    # None, not [], when the read FAILED — see system_ops.fail2ban_top_ips for why the two have to
    # be distinguishable. On a local or Tailscale-SSH host a timeout does not raise: the transport
    # returns ("", "...timed out", -1), so without the rc this looked exactly like "no offenders".
    out, _, rc = _core.run_privileged(server, "f2b-log-lines", [cutoff], timeout=25,
                                      merge_stderr=False)
    if rc != 0:
        _core._log.debug("remote top-ips: the fail2ban log read failed (rc=%s)", rc)
        return None
    out = _so._tally_f2b_lines(out, limit)
    banned = set()
    try:
        for j in remote_fail2ban_overview(server).get("jails", []):
            banned.update(j.get("banned_ips", []))
    except Exception:
        _core._log.debug("remote top-ips: couldn't read current bans", exc_info=True)
    try:
        blocked = remote_ufw_blocked_ips(server)
    except Exception:
        _core._log.debug("remote top-ips: couldn't read ufw blocks", exc_info=True)
        blocked = {}
    rows = []
    for line in (out or "").splitlines():
        p = line.split("\t")
        if len(p) >= 3 and p[2].strip():
            ip = p[2].strip()
            jails = [j for j in (p[3].split(",") if len(p) > 3 and p[3] else []) if j]
            rows.append({"ip": ip,
                         "attempts": int(p[0]) if p[0].isdecimal() else 0,
                         "bans": int(p[1]) if p[1].isdecimal() else 0,
                         "banned_now": ip in banned,
                         "blocked": ip in blocked,
                         "jails": jails})
    return rows


def remote_fail2ban_unban(server, jail, ip):
    """Lift a fail2ban ban on a REMOTE host (jail + IP validated). (ok, msg)."""
    # fullmatch, not match: .match anchors only the START, so "sshd; rm -rf /" would pass a
    # pattern that only says what the FIRST characters may be. (`\Z` rather than `$` is the
    # separate half of the same question — see the anchor gate in tests/unit/part06.py.) It is
    # shell-quoted below so this was never an injection, but the panel-host version fullmatches
    # and two validators disagreeing is exactly what this audit was looking for.
    if not _F2B_JAIL_RE.fullmatch((jail or "").strip()):
        return False, "Invalid jail name."
    jail = jail.strip()
    # Rebind against the jails the host actually reports, like the panel-host helper does, so a
    # well-formed but unknown jail is refused here rather than by fail2ban-client.
    # "jails" holds DETAIL dicts, not names — comparing the name against them would refuse every
    # unban. Also skip the rebind entirely when fail2ban is absent or the status read failed, so a
    # transient SSH hiccup cannot turn into "Unknown jail".
    _ov = remote_fail2ban_overview(server) or {}
    known = [d.get("jail") for d in (_ov.get("jails") or []) if d.get("jail")]
    if known and jail not in known:
        return False, "Unknown jail on that host."
    ip = _canonical_ip(ip)
    if not ip:
        return False, "Invalid IP address."
    out, err, rc = _core.run_privileged(server, "f2b-unban", [jail, ip], timeout=20)
    if rc == 0:
        return True, "Unbanned %s from %s." % (ip, jail)
    return False, ((out or err or "Unban failed").replace("\n", " ")[:200])


def _f2b_dropin_ignoreip_body(ignore_ips):
    """A fail2ban `[DEFAULT] ignoreip` drop-in body built from validated entries only (localhost is
    always included). Every entry is re-parsed through ipaddress, so a non-IP token can never reach
    the file."""
    import ipaddress
    entries = ["127.0.0.1/8", "::1"]
    for raw in (ignore_ips or []):
        s = (str(raw) or "").strip()
        try:
            entries.append(str(ipaddress.ip_network(s, strict=False)) if "/" in s
                           else str(ipaddress.ip_address(s)))
        except ValueError:
            continue
    seen, uniq = set(), []
    for e in entries:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    return "[DEFAULT]\nignoreip = %s\n" % " ".join(uniq)




def remote_set_fail2ban_ignoreip(server, ignore_ips, unban_ip=None):
    """Make a REMOTE host's fail2ban ignore the panel whitelist, so a whitelisted IP is never banned
    on ANY of that host's jails (sshd included) — the remote counterpart of the panel's own
    ignoreip. Writes a dedicated panel-owned drop-in (`jail.d/zz-panel-whitelist.local`) — its own
    file, so it never clobbers the host's existing config — and reloads. Optionally lifts one IP that
    is already banned (used when whitelisting). No-op if fail2ban isn't installed. (ok, msg)."""
    jails_out, jails_err, jails_rc = _core.run_privileged(server, "f2b-status", [], timeout=10,
                                                    merge_stderr=False)
    if jails_rc == 127 or "not found" in (jails_out + jails_err).lower():
        return False, "fail2ban not installed on this host"
    _core.write_root_file(server, "fail2ban-panel-whitelist",
                    _f2b_dropin_ignoreip_body(ignore_ips), timeout=15)
    _core._f2b_reload(server)
    # ignoreip only stops FUTURE bans; lift a current ban across every jail so a just-whitelisted
    # admin isn't left banned until it expires. `$J` is a jail name from fail2ban's own output.
    if unban_ip and _valid_ip(unban_ip):
        # Was a `for J in $(… | sed | tr)` loop in one root shell. The jail list is already in
        # hand from the status read above; iterate it here and unban per jail, skipping anything
        # that does not look like a jail name (the loop fed fail2ban's own output straight back).
        _m = re.search(r"Jail list:\s*(.*)", jails_out or "")
        for _j in [x.strip() for x in (_m.group(1).split(",") if _m else []) if x.strip()]:
            if _F2B_JAIL_RE.match(_j):
                _core.run_privileged(server, "f2b-unban", [_j, unban_ip], timeout=30, merge_stderr=False)
    return True, "ignoreip applied on %s" % getattr(server, "name", "remote")


def remote_security_log(server, which, lines=200, jail=None):
    """Tail of a whitelisted security log on a REMOTE host: 'fail2ban' or 'ssh'. `which` is a fixed
    set, never a path from the request. For 'fail2ban', an optional charset-validated `jail` narrows
    the activity to that one jail. Returns text."""
    lines = max(20, min(int(lines or 200), 1000))
    if which == "fail2ban":
        # /var/log/fail2ban.log holds the real Ban/Unban/Found activity (journalctl only has the
        # unit's start/stop noise), so read the file first and fall back to the journal.
        out, _, _ = _core.run_privileged(server, "log-tail", ["fail2ban", "4000"], timeout=20,
                                   merge_stderr=False)
        if not out:
            out, _, _ = _core.run_privileged(server, "journal", ["fail2ban", "4000"], timeout=20,
                                       merge_stderr=False)
        rows = (out or "").splitlines()
        if jail and _F2B_JAIL_RE.match(jail):   # charset-only guard; used solely for in-Python filtering
            tag = "[%s]" % jail
            rows = [ln for ln in rows if tag in ln]
        return "\n".join(rows[-lines:])
    if which == "ssh":
        # journalctl first, auth.log as the fallback — that was `journalctl ... || tail ...`, where
        # the `||` fired on journalctl's exit status. Systemd exits 0 with no output on a host that
        # keeps no journal, so checking the OUTPUT is what the fallback was actually for.
        out, _, _ = _core.run_privileged(server, "journal", ["ssh", str(lines * 2)], timeout=20,
                                   merge_stderr=False)
        if not (out or "").strip():
            out, _, _ = _core.run_privileged(server, "log-tail", ["auth", str(lines)], timeout=20,
                                       merge_stderr=False)
        return "\n".join((out or "").splitlines()[-lines:])
    return ""


def _tcp_reachable(host, port, timeout=8):
    """Whether the panel can open a TCP connection to host:port — used to confirm it won't lose its
    way in before committing an SSH bind-address change. Best-effort; False on any error."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _restart_ssh_listener(server, socket_mode):
    """Restart whichever unit owns the listening socket.

    Socket-activated: restart ssh.socket — restarting ssh.service alone re-execs the daemon behind
    a socket systemd is still holding on the OLD port, so the change appears to do nothing. Also
    restart the service, so a connection already being served does not outlive the config."""
    if socket_mode:
        out, err, rc = _core.run_privileged(server, "service-restart", ["ssh.socket"], timeout=20)
        _core._restart_sshd(server, timeout=20)
        return out, err, rc
    return _core._restart_sshd(server, timeout=20)


def _sshd_socket_activated(server):
    """Whether this host's sshd is SOCKET-ACTIVATED (Ubuntu 22.10+ default).

    When it is, ssh.socket holds the listening socket and sshd inherits it, so `Port` and
    `ListenAddress` in sshd_config are parsed, pass `sshd -t`, and are then IGNORED. Writing the
    port to an sshd_config drop-in on such a host changes nothing: the panel opened the firewall,
    wrote the file, restarted sshd, found the port not listening and reverted — correct and safe,
    and the feature simply never worked on the current Ubuntu LTS. Measured on 24.04.5.

    `systemctl is-active ssh.socket` prints "active" and exits 0 only when the socket unit is the
    thing listening. Anything else — inactive, not-found, no systemd, a failed read — answers False
    and the caller takes the sshd_config path, which is what every pre-24.04 host needs."""
    try:
        out, _err, rc = _core.run_privileged(server, "sshd-socket-active", [], timeout=10,
                                             merge_stderr=False)
    except Exception:
        _core._log.debug("sshd socket-activation check failed", exc_info=True)
        return False
    return rc == 0 and (out or "").strip() == "active"


def _socket_listen_lines(ports, bind_addr):
    """The ssh.socket drop-in body for `ports`.

    The bare `ListenStream=` first is load-bearing: systemd APPENDS to a unit's list, so without it
    the unit's own ListenStream=0.0.0.0:22 survives and a bind change restricts nothing. With no
    bind address both families are emitted, because that is what the shipped unit does and a
    port-only change must not quietly drop IPv6."""
    body = "[Socket]\nListenStream=\n"
    for p in ports:
        if bind_addr:
            a = "[%s]" % bind_addr if ":" in bind_addr else bind_addr
            body += "ListenStream=%s:%s\n" % (a, p)
        else:
            body += "ListenStream=0.0.0.0:%s\nListenStream=[::]:%s\n" % (p, p)
    return body


def change_ssh_port(server, new_port, bind_addr=""):
    """Move this host's sshd onto `new_port`, optionally restricting it to a single `bind_addr` IP
    (for hosts with several IPs), WITHOUT risking a lockout.

    Port-only change: every current port stays open on all interfaces the whole time, so a bad new
    port can't cut the panel off — we open the new port in UFW, add it (alongside the old ones) via
    an sshd drop-in, validate with `sshd -t`, repoint fail2ban's [sshd] jail, restart sshd and
    confirm the new port is listening (reverting if not).

    Bind-address change: sshd's ListenAddress is all-or-nothing (once set, sshd listens ONLY on the
    given addresses), so the always-open fallback doesn't apply. Instead we snapshot the current
    drop-in, apply the binding, restart, and verify the panel can still REACH SSH on the host —
    reverting to the snapshot if it can't. So a bind address that would cut the panel off is rolled
    back automatically; the operator must include the address the panel connects on.

    Works for a remote (over SSH) and the panel host itself. Returns (ok, message)."""
    try:
        new_port = int(new_port)
    except (TypeError, ValueError):
        return False, "Enter a valid port number."
    if not (1 <= new_port <= 65535):
        return False, "Port must be between 1 and 65535."
    bind_addr = (str(bind_addr) if bind_addr else "").strip()
    if bind_addr and not _valid_ip(bind_addr):
        return False, "Bind address must be a valid IP address, or blank for all interfaces."

    old_ports = _sshd_current_ports(server) or [str(int(getattr(server, "port", 22) or 22))]
    if not bind_addr and old_ports == [str(new_port)]:
        return False, "SSH is already on port %d." % new_port

    # Keep every current port plus the new one (new first).
    ports = []
    for p in [str(new_port)] + old_ports:
        if p not in ports:
            ports.append(p)

    # 1. Open the new port in the firewall FIRST (best-effort; a host without UFW just no-ops).
    remote_ufw_open_port(server, new_port, "tcp", comment="SSH (panel)")

    # 2. Snapshot any existing drop-in (so a failed bind change restores the EXACT prior state),
    #    then write the new one. Ubuntu 22.04/24.04 Include /etc/ssh/sshd_config.d/*.conf by default.
    socket_mode = _sshd_socket_activated(server)
    _backup_verb, _restore_verb, _discard_verb, _target = (
        ("sshd-socket-backup", "sshd-socket-restore", "sshd-socket-discard", "sshd-socket-dropin")
        if socket_mode else
        ("sshd-backup-dropin", "sshd-restore-dropin", "sshd-discard-backup", "sshd-port-dropin"))
    _core.run_privileged(server, _backup_verb, [], timeout=10, merge_stderr=False)
    header = ("# Managed by LinuxGSM Panel. The previous SSH port is kept as a fallback; close it\n"
              "# from the panel's Firewall page once you've confirmed the new port works.\n")
    if socket_mode:
        # Socket-activated: the port lives on ssh.socket, and sshd_config's Port is ignored.
        body = _socket_listen_lines(ports, bind_addr)
    elif bind_addr:
        # sshd needs an IPv6 literal bracketed when a port follows: ListenAddress [::1]:22.
        _a = "[%s]" % bind_addr if ":" in bind_addr else bind_addr
        body = "".join("ListenAddress %s:%s\n" % (_a, p) for p in ports)
    else:
        body = "".join("Port %s\n" % p for p in ports)
    _core.write_root_file(server, _target, header + body, timeout=15)
    if socket_mode:
        # A changed unit file is inert until systemd re-reads it.
        _core.run_privileged(server, "systemd-daemon-reload", [], timeout=20, merge_stderr=False)

    def _revert(msg):
        # Restore the snapshot if we took one, else drop the file, then restart sshd. The prior
        # binding is untouched the whole time, so SSH keeps working.
        _core.run_privileged(server, _restore_verb, [], timeout=10, merge_stderr=False)
        if socket_mode:
            _core.run_privileged(server, "systemd-daemon-reload", [], timeout=20, merge_stderr=False)
        # ...and close the hole step 1 opened. It only restored the drop-in before, so every revert
        # path left a public ALLOW for a port nothing serves — including the step-3 path, whose
        # message says "sshd rejected the new config — nothing changed". Best-effort, like the
        # open: a host without UFW no-ops either way.
        remote_ufw_close_port(server, new_port, "tcp")
        _restart_ssh_listener(server, socket_mode)
        return False, msg

    # 3. Validate the WHOLE sshd config; if the drop-in breaks it, roll back and abort (no restart).
    tout, terr, trc = _core.run_privileged(server, "sshd-validate", [], timeout=15)
    terr = terr or tout
    if trc != 0:
        return _revert("sshd rejected the new config — nothing changed. (%s)" % ((terr or "invalid")[:120]))

    # 4. Point fail2ban's [sshd] jail at the new + old ports so its bans target the right port.
    _core.run_privileged(server, "f2b-set-sshd-ports", [",".join(ports)], timeout=20,
                   merge_stderr=False)
    _core.run_privileged(server, "service-restart", ["fail2ban"], timeout=20, merge_stderr=False)

    # 5. Restart whatever actually holds the port. Established sessions survive either way.
    _restart_ssh_listener(server, socket_mode)

    # 6. Verify. A bind change must confirm the panel can still REACH the host (no all-interfaces
    #    fallback); a port-only change just confirms sshd bound the new port.
    if bind_addr and not _core.is_local_server(server):
        if not _tcp_reachable(server.host, new_port, timeout=8):
            return _revert("After binding SSH to %s, the panel couldn't reach it on %s:%d — reverted. "
                           "The bind address has to be the one the panel connects to."
                           % (bind_addr, server.host, new_port))
    else:
        # Was `ss -lnt | grep -qE '[:.]<port>[[:space:]]' && echo OK || echo NO` — the new port
        # was interpolated into a regex running as root. Same match in Python.
        out, _, _ = _core.run_privileged(server, "listening-sockets", [], timeout=15, merge_stderr=False)
        if not re.search(r"[:.]%d\s" % new_port, out or ""):
            return _revert("sshd didn't come up on port %d — reverted. Your existing SSH still works." % new_port)

    _core.run_privileged(server, _discard_verb, [], timeout=10,
                   merge_stderr=False)   # success — drop the snapshot
    where = (" on %s" % bind_addr) if bind_addr else ""
    return True, ("SSH now listens on port %d%s (firewall + fail2ban updated). The previous port is "
                  "still available as a fallback — once you've confirmed you can reach SSH on %d, "
                  "close the old one from the Firewall page." % (new_port, where, new_port))


# A ufw rule whose To column IS port 22 — the number (with or without /tcp) or the app profile.
# Anchored: the To column is the first thing on the line.
_SSH22_RE = re.compile(r"\s*(?:22(?:/tcp)?|OpenSSH)\s", re.I)


def remote_public_ssh_status(server, panel_port=None):
    """Report public SSH state on port 22: 'allow', 'limit', or 'off' (no rule —
    reachable only over tailscale0), plus whether UFW is active at all. When
    `panel_port` is given, also report whether that port has a public ALLOW rule
    (`panel_port_open`) so the UI can disable "Close public panel port" once it's
    already closed."""
    out, _, _ = _core.run_privileged(server, "ufw-status", ["plain"], timeout=12)
    active = "Status: active" in (out or "")
    mode = "off"
    panel_open = False
    port_re = re.compile(r"\b%d\b" % int(panel_port)) if panel_port else None
    for line in (out or "").splitlines():
        low = line.lower()
        # ANCHORED to the To column, which is what `ufw status` prints first. `"22/tcp" in low`
        # is a substring test, and "2222/tcp" contains it — so after the panel's own
        # change_ssh_port moved sshd to 2222 and the operator closed 22 as the panel told them
        # to, this still reported port 22 rate-limited, marked that button active-and-disabled,
        # and never once showed the true `off` state. 8022, 1022 and 22022 read the same way, and
        # so did a source address ending in .22 once you widen the test to a word boundary.
        if _SSH22_RE.match(line) and " (v6)" not in low:
            if "limit" in low:
                mode = "limit"
            elif "allow" in low:
                mode = "allow" if mode != "limit" else mode
        # A public ALLOW rule for the panel port (ignore IPv6 duplicates and the
        # tailscale0 interface rule, which isn't the *public* port).
        if (port_re and "allow" in low and " (v6)" not in low
                and "tailscale" not in low and port_re.search(line)):
            panel_open = True
    res = {"active": active, "mode": mode}
    if panel_port:
        res["panel_port"] = int(panel_port)
        res["panel_port_open"] = panel_open
    return res


def _tailscale_conn_state(server):
    """(running, ssh_enabled) — whether Tailscale is up on this host and advertises its
    SSH server. Tailscale SSH works regardless of UFW, so when it's on the host always
    has a way in. Best-effort; fails safe to (False, False)."""
    import json as _json
    running = ssh_enabled = False
    try:
        out, _, _ = _core.run_command(server, "tailscale status --json 2>/dev/null || echo '{}'", timeout=10)
        running = _json.loads(out or "{}").get("BackendState") == "Running"
    except Exception:
        running = False   # can't confirm → treat as not running (fail safe)
    if running:
        try:  # authoritative: prefs RunSSH
            out, _, _ = _core.run_command(server, "tailscale debug prefs 2>/dev/null || echo '{}'", timeout=10)
            ssh_enabled = bool(_json.loads(out or "{}").get("RunSSH", False))
        except Exception:
            ssh_enabled = False   # fail safe
    return running, ssh_enabled


# Tailscale peers get CGNAT addresses from 100.64.0.0/10. A public attacker can't have a source in
# that range, so the panel never firewall-blocks a tailnet IP while Tailscale is up — blocking one
# would cut off tailnet access (and, inserted at UFW position 1, it would override the tailscale0
# allow rule).
_TAILNET_CGNAT = "100.64.0.0/10"


def tailnet_exempt_ips(server, ips):
    """Of `ips`, the Tailscale-range (100.64.0.0/10) addresses that must NOT be firewall-blocked —
    but only when Tailscale is actually running on this host. Returns a set of canonical IP strings
    (empty if Tailscale is down or nothing is in range). Works for local + remote (run_command
    dispatches). Best-effort; fails safe to no exemptions."""
    import ipaddress
    try:
        net = ipaddress.ip_network(_TAILNET_CGNAT)
    except ValueError:
        return set()
    cand = set()
    for ip in ips or ():
        try:
            addr = ipaddress.ip_address((ip or "").strip())
        except (ValueError, TypeError):
            continue
        if addr in net:
            cand.add(str(addr))
    if not cand:
        return set()   # nothing in the tailnet range → skip the (relatively costly) tailscale probe
    try:
        return cand if _tailscale_conn_state(server)[0] else set()
    except Exception:
        return set()   # can't confirm Tailscale → don't exempt


def _tailnet_ssh_state(server):
    """(running, ssh_enabled, iface_allowed) — the inputs to deciding whether removing
    public SSH is safe. iface_allowed = the tailscale0 interface is allowed in UFW (so
    sshd is reachable over the tailnet). Works for local + remote hosts; fails safe."""
    running, ssh_enabled = _tailscale_conn_state(server)
    iface_allowed = False
    if running:
        try:  # tailscale interface allowed in UFW → sshd is reachable over the tailnet
            out, _, _ = _core.run_privileged(server, "ufw-status", ["verbose"], timeout=12)
            iface_allowed = any("tailscale" in ln.lower() for ln in (out or "").splitlines())
        except Exception:
            iface_allowed = False   # fail safe
    return running, ssh_enabled, iface_allowed


def remote_set_public_ssh(server, mode):
    """Control PUBLIC (non-tailnet) SSH on port 22 via UFW:
      allow → `ufw allow 22/tcp`  (open to the internet)
      limit → `ufw limit 22/tcp`  (rate-limited brute-force protection; recommended)
      off   → remove the allow/limit rules (SSH only via the tailscale0 interface)
    tailscale0 SSH is unaffected either way. `off` is REFUSED unless there is a working
    Tailscale path back in (Tailscale running + SSH enabled or the tailscale0 interface
    allowed in UFW) — otherwise it would strand you with no way to reach the host."""
    mode = (mode or "").lower()
    if mode == "allow":
        steps = [("ufw-delete-limit-port", ["22/tcp"]), ("ufw-allow-port", ["22/tcp", ""])]
    elif mode == "limit":
        steps = [("ufw-delete-allow-port", ["22/tcp"]), ("ufw-limit-port", ["22/tcp"])]
    elif mode == "off":
        running, ssh_enabled, iface_allowed = _tailnet_ssh_state(server)
        if not (running and (ssh_enabled or iface_allowed)):
            return False, ("Refused — there's no Tailscale way back into this host, so disabling "
                           "public SSH would lock you out. Enable Tailscale SSH, or make sure "
                           "Tailscale is running and the tailscale0 interface is allowed in UFW, first.")
        steps = [("ufw-delete-allow-port", ["22/tcp"]), ("ufw-delete-limit-port", ["22/tcp"]),
                 ("ufw-delete-allow-app", ["OpenSSH"])]
    else:
        return False, "Invalid mode"
    for verb, vargs in steps:
        _core.run_privileged(server, verb, vargs, timeout=15)  # deletes of absent rules are harmless
    labels = {"allow": "open (allow)", "limit": "rate-limited", "off": "disabled (tailnet-only)"}
    # ASK THE HOST what it ended up with. This used to return True unconditionally, so on a host
    # with no ufw at all every verb failed and the operator still got "✓ Public SSH is now disabled
    # (tailnet-only)", an audit row saying the hardening succeeded, and port 22 open to the
    # internet. The exit codes cannot answer it either: a delete of an absent rule is a normal
    # non-zero, which is exactly why they were being ignored.
    state = remote_public_ssh_status(server)
    if not state.get("active"):
        return False, ("UFW is not active on this host, so public SSH cannot be controlled from "
                       "here — port 22 is governed by whatever else is in front of it.")
    if state.get("mode") != mode:
        return False, ("Could not set public SSH to %s — the firewall still reports it as %s."
                       % (labels[mode], labels.get(state.get("mode"), state.get("mode"))))
    return True, f"Public SSH is now {labels[mode]}"


def ssh_test_connection(host, port=22, username="root", auth_method="key", credential="",
                        host_key=""):
    """Test an SSH connection and return (success, message).

    `host_key` is the pin to check against, for the callers that HAVE one. It was not a parameter
    at all, so `expected` was always "" and this accepted any key from any server — while three of
    the four callers pass an EXISTING remote's stored credential: the "Test connection" button
    (routes/remotes.py), _wait_for_reboot below, and the setup wizard. For a password remote that
    means offering the plaintext SSH password to whoever answers on that address, and reporting
    "Connection successful" afterwards. get_connection() pins correctly (_core.get_connection), so
    this was a hole in an implemented control rather than an absent one — and _wait_for_reboot is
    the attractive window, because the host is EXPECTED to be down and the panel retries for up to
    ten minutes while the operator watches a progress bar.

    Left unpinned only where there is genuinely nothing to compare against: adding a remote, which
    is the first contact the TOFU pin is established from."""
    # Tailscale SSH must use the system ssh client (tailscaled handles auth).
    if auth_method == "tailscale":
        class _S:
            pass
        s = _S()
        s.host, s.port, s.username = host, port, username
        s.auth_method, s.linuxgsm_user, s.sudo_enabled = "tailscale", "", False
        out, err, rc = _core._run_via_ssh_cli(s, "echo ok && whoami", timeout=15, sudo=False)
        if rc == 0:
            return True, "Tailscale SSH connection successful"
        low = (err or "").lower()
        if "permission denied" in low:
            return False, "Tailscale SSH denied — check the tailnet ACL allows SSH to this node/user."
        if "timed out" in low or "timeout" in low:
            return False, f"Timed out reaching {host} over Tailscale. Is the node online?"
        return False, f"Tailscale SSH failed: {(err or out or 'unknown')[:150]}"

    client = paramiko.SSHClient()
    # Pinned when the caller has a pin (an existing remote); capture-only on genuine first contact,
    # where there is nothing to compare against. Never AutoAddPolicy either way.
    client.set_missing_host_key_policy(
        _core._PinPolicy(expected=host_key or "", reject_on_change=bool(host_key)))
    try:
        if auth_method == "password":
            if not credential:
                # A password remote with no usable credential must FAIL, not fall through to the
                # key branch below and authenticate with the panel user's own ~/.ssh/id_rsa — a
                # different credential, against a host the operator never authorised it for.
                # decrypt_secret() returns "" both for "nothing stored" and for "stored but could
                # not be decrypted" (a restored backup with a mismatched cred_key, a corrupt row),
                # so this is also the only place that failure becomes visible.
                return False, ("No usable SSH password is stored for this host. If the panel was "
                               "restored from a backup, its credential key may not match.")
            client.connect(
                host, port=port, username=username,
                password=credential, timeout=10,
                allow_agent=False, look_for_keys=False,
            )
        else:
            key_path = credential or os.path.expanduser("~/.ssh/id_rsa")
            client.connect(
                host, port=port, username=username,
                key_filename=key_path, timeout=10,
            )
        client.close()
        return True, "Connection successful"
    except paramiko.AuthenticationException:
        return False, "SSH authentication failed. Check your credentials."
    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out. Is the host reachable?"
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}"
    except Exception:
        # Don't surface the raw exception text to the browser — it can carry internal detail
        # (key paths, host internals). Log the full trace server-side (no user-supplied host/port
        # in the message — exc_info already carries the detail), show a generic message.
        _core._log.warning("ssh_test_connection failed", exc_info=True)
        return False, "Connection failed. Check the host, port, credentials, and that SSH is reachable."


# ── Ubuntu Pro (ubuntu-advantage-tools / `pro`) ────────────────────────────
# Moved here from firewall.py, where the split's line boundary had landed mid-section. Every
# consumer of these is in this module, and a module-private name read only from ANOTHER module
# reads as dead to CodeQL (py/unused-global-variable) — which is how the misplacement announced
# itself: two alerts on main, minutes after the split merged. See panel/routes/__init__.py for
# the same finding and the same rule: move it to its consumer, do not annotate it.
# The security-relevant services we surface (the rest — fips/cis/anbox/etc. —
# aren't relevant to a game-server host and just add noise).
_PRO_FEATURED = ["esm-infra", "esm-apps", "livepatch"]
_PRO_SERVICES = {
    "esm-infra", "esm-apps", "livepatch", "fips", "fips-updates", "fips-preview",
    "cis", "usg", "realtime-kernel", "landscape", "anbox-cloud", "ros", "ros-updates",
}


def _pro_trim(blob):
    """Collapse a pro CLI output blob to a short, single-line message."""
    import re as _re
    return _re.sub(r"\s+", " ", blob or "").strip()[-300:]


def host_timezone(server):
    """The host's own IANA timezone ("Etc/UTC", "America/Chicago"), or "" if it can't be read.

    Unprivileged on purpose — this is read on ordinary page loads and must not cost a sudo session
    per host. Three sources because not every box has all three: `timedatectl` is absent on a
    container without systemd, `/etc/timezone` is Debian-family only, and the symlink is the one
    thing every glibc system has. Never raises.

    WHY THE PANEL NEEDS THIS AT ALL. Cron fires on the host's clock, so a schedule's number is
    meaningless until you know which clock it is — and the panel's own bootstrap sets new hosts to
    UTC, which is almost never the operator's zone."""
    sh = ("timedatectl show -p Timezone --value 2>/dev/null "
          "|| cat /etc/timezone 2>/dev/null "
          "|| readlink -f /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##'")
    try:
        out, _, _ = _core.run_command(server, sh, timeout=10)
    except Exception:
        _core._log.debug("host timezone read failed for %s", getattr(server, "name", "?"),
                         exc_info=True)
        return ""
    # First non-empty line only: the `||` chain can print more than one if an earlier command
    # succeeds with empty output and the next one then runs.
    for line in (out or "").splitlines():
        tz = clock.valid_timezone(line.strip())
        if tz:
            return tz
    return ""
