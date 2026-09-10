"""Tailscale integration for LinuxGSM Panel.

Auto-detects Tailscale status, manages Serve/Funnel configuration,
provides network diagnostics, and recommends optimal bind settings.
"""
import json
import logging
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import privileged as _priv
import system_ops as _so

_log = logging.getLogger(__name__)


@dataclass
class TailscaleInfo:
    """All discovered Tailstate information for this node."""
    installed: bool = False
    running: bool = False
    backend_state: str = ""  # Tailscale BackendState: Running, NeedsLogin, Stopped, NoState…
    tailscale_ips: list = field(default_factory=list)
    hostname: str = ""
    dns_name: str = ""
    magic_dns_enabled: bool = False
    accept_routes: bool = False
    version: str = ""
    serve_config: dict = field(default_factory=dict)
    funnel_enabled: bool = False
    peers: list = field(default_factory=list)  # List of peer dicts


# Cache results to avoid hammering `tailscale` CLI on every page load
_cache = {"info": None, "ts": 0, "ttl": 15}  # 15 second cache
_cache_lock = threading.Lock()


def _run_ts(args, timeout=5):
    """Run a tailscale CLI command. Returns (stdout, stderr, exit_code)."""
    try:
        r = subprocess.run(
            ["tailscale"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return "", "tailscale binary not found", -1
    except subprocess.TimeoutExpired:
        return "", "tailscale command timed out", -1
    except Exception:
        # Never return str(e): this stderr channel can surface in the /api/tailscale
        # response, and an exception message is a stack-trace-exposure sink. Log it
        # server-side for debugging and hand the caller a generic message instead.
        _log.exception("tailscale command failed")
        return "", "tailscale command failed", -1


def _current_os_user():
    """The OS user the panel runs as (the one that should own Tailscale management)."""
    try:
        import os
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        import getpass
        return getpass.getuser()


def ensure_operator():
    """Make the panel's own user the Tailscale 'operator' so `tailscale serve` config AND
    `tailscale serve status` work as the panel user without root — Tailscale's recommended
    fix for 'Access denied: serve config denied'. Idempotent, best-effort (needs sudo once)."""
    user = _current_os_user()
    if not user or user == "root":
        return True, "root"
    # Was `sudo tailscale set --operator=<user>`. A sudoers rule permitting the tailscale binary
    # would cover every tailscale subcommand — `up`, `logout`, `set --exit-node`, the lot — so this
    # goes through the verb table, where the subcommand and flag are fixed and the user name is
    # validated on the far side.
    _so._run_verb("tailscale-set-operator", [user], timeout=10)
    return True, user


def allow_tailscale_ufw():
    """Best-effort: allow the Tailscale interface through UFW on the panel host, so the node
    stays reachable over the tailnet. A common lockout is UFW active but tailscale0 not
    allowed — then Serve/SSH over the tailnet silently can't reach the node. Idempotent."""
    try:
        import system_ops
        return system_ops.ufw_allow_tailscale()
    except Exception as e:
        return False, str(e)


def _run_ts_json(args, timeout=5):
    """Run tailscale with --json flag and parse output."""
    out, err, rc = _run_ts(args + ["--json"], timeout=timeout)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _get_tailscale_info() -> TailscaleInfo:
    """Internal - discover all Tailscale info by calling the CLI."""
    info = TailscaleInfo()

    # Check if tailscale binary exists
    info.installed = _run_ts(["version"])[0] != "" or \
                     _run_ts(["--version"])[0] != ""

    if not info.installed:
        return info

    # Get version
    ver, _, _ = _run_ts(["version"])
    info.version = ver.split("\n")[0] if ver else ""

    # Get status
    status = _run_ts_json(["status"])
    if status:
        info.backend_state = status.get("BackendState") or ""
        info.running = info.backend_state == "Running"
        # NOTE: `.get(key, default)` only uses the default when the key is ABSENT. When
        # Tailscale is installed but not yet authenticated (BackendState "NeedsLogin",
        # after `tailscale up` prints a login URL the user hasn't clicked), the JSON has
        # "Peer": null / "TailscaleIPs": null / "Self": null — .get returns None, and
        # None.items()/iteration then 500s the page. Coerce nulls with `or <default>`.
        info.tailscale_ips = status.get("TailscaleIPs") or []
        self_data = status.get("Self") or {}
        if self_data:
            info.hostname = self_data.get("HostName", "")
            dns = self_data.get("DNSName", "")
            info.dns_name = dns.rstrip(".") if dns else ""
        info.accept_routes = status.get("TUN", False)
        info.magic_dns_enabled = bool(info.dns_name)

        # Collect peers. Trust Tailscale's own `Online` field — it is authoritative.
        # (Do NOT downgrade based on LastSeen: for an online peer the last handshake
        # can legitimately be many minutes old on a long-lived connection, so a
        # "last seen > 2 min" heuristic wrongly marks live peers offline.)
        peer_data = status.get("Peer") or {}
        for peer_id, peer in peer_data.items():
            ts_online = bool(peer.get("Online", False))
            last_seen_str = peer.get("LastSeen", "")

            info.peers.append({
                "id": peer_id,
                "hostname": peer.get("HostName", ""),
                "dns_name": peer.get("DNSName", "").rstrip(".") if peer.get("DNSName") else "",
                "ips": peer.get("TailscaleIPs", []),
                "os": peer.get("OS", ""),
                "online": ts_online,
                "last_seen": last_seen_str,
                "relay": peer.get("Relay", ""),
            })
    else:
        # Fallback: simpler check
        out, _, rc = _run_ts(["status"])
        info.running = rc == 0 and "stopped" not in out.lower()
        info.backend_state = "Running" if info.running else "Stopped"

        # Parse hostname from status
        if info.running:
            for line in out.split("\n"):
                if "100." in line and "@" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[1].split(".")[0] if "." in parts[1] else parts[1]
                        info.hostname = name
                    break

    # Get Serve status
    serve_out, _, serve_rc = _run_ts(["serve", "status"])
    if serve_rc == 0 and serve_out:
        info.serve_config = _parse_serve_status(serve_out)
        info.funnel_enabled = any(
            srv.get("funnel", False) for srv in info.serve_config.get("services", [info.serve_config])
        )

    # Detect MagicDNS from resolveconf or tailscale
    if not info.magic_dns_enabled:
        try:
            # Check if .ts.net resolves
            if info.hostname:
                test_name = f"{info.hostname}.tailscale.net"
                socket.getaddrinfo(test_name, 80, socket.AF_INET)
                info.magic_dns_enabled = True
        except OSError:
            _log.debug("name doesn't resolve → MagicDNS simply stays disabled", exc_info=True)

    return info


def _parse_serve_status(text):
    """Parse `tailscale serve status` output into a structured dict."""
    result = {"services": [], "raw": text}
    current_url = None
    current_funnel = False
    current_routes = []

    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        # Match URL line
        url_match = re.match(r'^(https?://\S+)\s*(\(.*\))?$', stripped)
        if url_match:
            if current_url and current_routes:
                result["services"].append({
                    "url": current_url,
                    "funnel": current_funnel,
                    "routes": current_routes,
                })
            current_url = url_match.group(1).rstrip(".")
            current_funnel = "funnel" in (url_match.group(2) or "")
            current_routes = []
            continue

        # Match route line
        route_match = re.match(r'\|--\s+(\S+)\s+proxy\s+(\S+)', stripped)
        if route_match and current_url:
            current_routes.append({
                "mount": route_match.group(1),
                "target": route_match.group(2),
            })

        # Funnel-only line
        if "funnel" in stripped.lower() and current_url and not current_funnel:
            current_funnel = True

    if current_url and current_routes:
        result["services"].append({
            "url": current_url,
            "funnel": current_funnel,
            "routes": current_routes,
        })

    return result


def get_tailscale_info(force_refresh=False) -> TailscaleInfo:
    """Get cached Tailscale info. Refreshes every `ttl` seconds."""
    # (_cache is a module-level dict mutated in place — no `global` needed.)
    now = time.time()
    with _cache_lock:
        if force_refresh or _cache["info"] is None or (now - _cache["ts"]) > _cache["ttl"]:
            _cache["info"] = _get_tailscale_info()
            _cache["ts"] = now
    return _cache["info"]


def get_magic_url(port=None, protocol="https") -> Optional[str]:
    """Get the MagicDNS URL for this node, optionally with a custom port."""
    info = get_tailscale_info()
    if info.dns_name:
        base = f"{protocol}://{info.dns_name}"
        if port and port not in (443, 80):
            base += f":{port}"
        return base
    return None


def get_tailscale_ip(version=4) -> Optional[str]:
    """Get this node's Tailscale IP."""
    info = get_tailscale_info()
    for ip in info.tailscale_ips:
        if version == 4 and "." in ip:
            return ip
        if version == 6 and ":" in ip:
            return ip
    return info.tailscale_ips[0] if info.tailscale_ips else None


def check_peer_reachability(host) -> dict:
    """Check if a host (IP or hostname) responds on the tailnet via ping."""
    reachable = False
    latency_ms = 0
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "3", host],
            capture_output=True, text=True, timeout=5,
        )
        reachable = r.returncode == 0
        if reachable:
            m = re.search(r'time[=<]\s*(\d+\.?\d*)', r.stdout)
            if m:
                latency_ms = float(m.group(1))
    except Exception:  # nosec B110
        _log.debug("ping unavailable or output unparseable — return reachable/latency as-is", exc_info=True)
    return {"reachable": reachable, "latency_ms": latency_ms}


def _ts_serve_args(verb, grammar, mount, scheme, port):
    """The `tailscale serve|funnel` arguments, WITHOUT the leading binary name.

    Deliberately delegates to privileged.ts_serve_argv and drops argv[0], so the unprivileged path
    and the root path cannot drift: one definition of what the command is, used by both."""
    return _priv.ts_serve_argv(verb, grammar, mount, scheme, str(port))[1:]


def setup_tailscale_serve(port=5000, mount="/", funnel=False, backend_scheme="http"):
    """Configure Tailscale Serve to proxy this panel.

    Args:
        port: Local port the panel runs on (default 5000)
        mount: URL mount point (default '/')
        funnel: Whether to enable Funnel (public internet access)
        backend_scheme: how to reach the panel on loopback — "http" (default) or
            "https+insecure" when the panel is terminating its own self-signed TLS.
            Tailscale re-terminates TLS with the real ts.net cert either way; this just
            has to match how the panel is actually listening or the proxy 502s.

    Returns:
        (success, message)
    """
    verb = "funnel" if funnel else "serve"
    mount = mount or "/"

    # serve/funnel is privileged — make the panel user the Tailscale operator first so it
    # works (and status reads back) without root. Also make sure the tailnet interface is
    # allowed through UFW, or the Serve URL would be unreachable on a firewalled host.
    ensure_operator()
    allow_tailscale_ufw()

    # Two things vary by Tailscale version/setup: (1) the CLI grammar changed — newer
    # (~1.58+) takes the target as the only positional with a --set-path mount, older took
    # the mount as a positional ("... 443 / URL"); (2) privilege — usually the operator set
    # above is enough, but fall back to sudo if not. Try each combination and use the first
    # that succeeds, so it works across Tailscale versions and permission setups.
    err = ""
    for grammar in ("modern", "legacy"):
        # Unprivileged first: ensure_operator() above normally makes this work as the panel user,
        # and a command that needs no root should not ask for it.
        out, e, rc = _run_ts(_ts_serve_args(verb, grammar, mount, backend_scheme, port), timeout=10)
        if rc != 0:
            # Root fallback, for a host where the operator setting did not take. This used to be
            # `sudo tailscale <args>`; a sudoers rule permitting the tailscale binary would cover
            # every subcommand it has — up, logout, set --exit-node — so it goes through the verb
            # table, which fixes the subcommand and validates the rest.
            out, e, rc = _so._run_verb(
                "tailscale-serve", [verb, grammar, mount, backend_scheme, str(port)],
                timeout=10, merge_stderr=False)
        if rc == 0:
            with _cache_lock:
                _cache["info"] = None
            return True, "Tailscale Serve enabled" + (" (with Funnel)" if funnel else "")
        err = e or out or err
    return False, f"Failed to configure Tailscale Serve: {err or 'Unknown error'}"


@dataclass
class _SimpleResult:
    """The three fields of subprocess.CompletedProcess that this module reads.

    _run_verb returns (out, err, rc); the callers below were written against a
    CompletedProcess. Rather than rewrite every read, adapt the shape — the point of the
    change is WHICH path runs the command, not how its result is spelled."""
    stdout: str
    stderr: str
    returncode: int


def install_tailscale_local():
    """Install Tailscale on THIS host (needs root). Returns (success, log tail).

    Was `sudo bash -c "curl -fsSL … | sh"`. A sudoers rule permitting bash is exactly NOPASSWD:ALL,
    so this one line was on its own enough to keep the grant wide open. The verb has no pipe and no
    shell string: curl writes the installer to a root-owned 0600 file under /run and sh runs that
    file. Still remote code as root — that is what installing Tailscale is — but the URL is fixed
    on the far side and the caller supplies nothing."""
    try:
        out, err, rc = _so._run_verb("tailscale-install", [], timeout=180, merge_stderr=False)
        with _cache_lock:
            _cache["info"] = None
        return rc == 0, ((out or "") + (err or ""))[-1500:]
    except Exception:
        # This message is echoed back to /api/tailscale/install — keep the raw
        # exception text out of the response (stack-trace-exposure); log it instead.
        _log.exception("tailscale install failed")
        return False, "Install failed — see panel logs for details."


def tailscale_up_local(enable_ssh=True):
    """Run `tailscale up` on THIS host detached and return the browser login URL to
    paste in (mirrors the remote flow). Returns (True, url) | (True, 'ALREADY_CONNECTED')
    | (False, message).

    This used to build its own `sudo bash -c` script — a backgrounded `tailscale up`, a redirect,
    a poll loop and a grep, all needing a shell. The REMOTE flow was converted to the
    `tailscale-up-login` verb some time ago; this local twin was simply never switched over, so
    two things stayed true of it that are no longer true anywhere else:

      1. It wrote root's output to /tmp/tsup.log. /tmp is world-writable, so any local user could
         pre-create or symlink that path and redirect what root wrote. The verb writes to
         /run/panel-tailscale-up.log instead — root-owned, 0600, tmpfs, cleared on reboot.
      2. It needed `sudo bash`, and a sudoers rule permitting /bin/bash is exactly equivalent to
         NOPASSWD:ALL. That is one of the handful of call sites blocking the grant from being
         narrowed to the helper alone.

    Every path below now goes through the verb table: the helper when it is installed, the tool
    directly when already root, and the verb's own rendered shell form otherwise — and that
    rendering uses the /run path too, so the /tmp hazard is gone even on a host that has not had
    install.sh re-run as root."""
    out, err, rc = _so._run_verb("tailscale-up-login",
                                 ["yes" if enable_ssh else "no", "-"],
                                 timeout=40, merge_stderr=False)
    r = _SimpleResult(stdout=out, stderr=err, returncode=rc)
    line = (r.stdout or "").strip().split("\n")[-1].strip()
    if line.startswith("https://login.tailscale.com/"):
        with _cache_lock:
            _cache["info"] = None
        return True, line
    info = get_tailscale_info(force_refresh=True)
    if info.running or line == "ALREADY_CONNECTED":
        ensure_operator()      # so the panel user can manage Serve without root afterward
        allow_tailscale_ufw()  # keep the node reachable over the tailnet if UFW is active
        return True, "ALREADY_CONNECTED"
    return False, (r.stderr or r.stdout or "Could not get a login link — is Tailscale installed on this host?")


def disable_tailscale_serve(mount="/"):
    """Remove a Tailscale Serve/Funnel mapping."""
    out, err, rc = _run_ts(
        ["serve", "--bg", "--remove", mount],
        timeout=10,
    )
    if rc == 0:
        with _cache_lock:
            _cache["info"] = None
        return True, "Tailscale Serve mapping removed"
    return False, f"Failed to remove: {err or out}"


def is_tailscale_ip(host):
    """Check if a host/IP looks like a Tailscale address."""
    if not host:
        return False
    if host.startswith("100.") or host.startswith("fd7a:"):
        return True
    if host.endswith(".ts.net") or ".taile" in host:
        return True
    return False


def suggest_best_bind(port=5000):
    """Suggest the best way to expose the panel based on what's available.

    Returns a dict with keys:
      - method: "tailscale-serve", "tailscale-direct", "direct"
      - bind_host: recommended bind address
      - url: URL the user can reach it at
      - description: human-readable explanation
    """
    info = get_tailscale_info()

    if info.running and info.dns_name and info.serve_config.get("services"):
        # Serve is ACTUALLY proxying the panel — bind to localhost and reach it via the ts.net cert.
        # (We must confirm Serve is configured, not just that Tailscale is up with a MagicDNS name —
        # otherwise a fresh Tailscale-enabled install would bind loopback with nothing proxying to it
        # and be unreachable.)
        url = f"https://{info.dns_name}"
        return {
            "method": "tailscale-serve",
            "bind_host": "127.0.0.1",
            "port": port,
            "url": url,
            "description": f"Bind to localhost and expose via Tailscale Serve at {url}",
        }
    elif info.running and info.tailscale_ips:
        # Tailscale running but no MagicDNS
        ts_ip = get_tailscale_ip(4)
        return {
            "method": "tailscale-direct",
            "bind_host": ts_ip or "0.0.0.0",
            "port": port,
            "url": f"http://{ts_ip}:{port}" if ts_ip else f"http://<tailscale-ip>:{port}",
            "description": f"Bind to Tailscale IP {ts_ip} and access directly",
        }
    elif info.installed and info.backend_state == "NeedsLogin":
        # Installed but never authorized — the recommendation is to finish linking, not to
        # open the panel to all interfaces.
        return {
            "method": "direct",
            "bind_host": "0.0.0.0",
            "port": port,
            "url": f"http://<your-server-ip>:{port}",
            "description": ("Tailscale is installed but not linked yet. Link this machine above "
                            "to reach the panel privately over your tailnet."),
        }
    else:
        return {
            "method": "direct",
            "bind_host": "0.0.0.0",
            "port": port,
            "url": f"http://<your-server-ip>:{port}",
            "description": "No Tailscale detected. Bind to all interfaces.",
        }
