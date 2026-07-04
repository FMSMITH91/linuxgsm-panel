"""Tailscale integration for LinuxGSM Panel.

Auto-detects Tailscale status, manages Serve/Funnel configuration,
provides network diagnostics, and recommends optimal bind settings.
"""
import json
import os
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class TailscaleInfo:
    """All discovered Tailstate information for this node."""
    installed: bool = False
    running: bool = False
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
    except Exception as e:
        return "", str(e), -1


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
        info.running = status.get("BackendState") == "Running"
        info.tailscale_ips = status.get("TailscaleIPs", [])
        self_data = status.get("Self", {})
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
        peer_data = status.get("Peer", {})
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
        except Exception:
            pass

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
    except Exception:
        pass
    return {"reachable": reachable, "latency_ms": latency_ms}


def setup_tailscale_serve(port=5000, mount="/", funnel=False):
    """Configure Tailscale Serve to proxy this panel.

    Args:
        port: Local port the panel runs on (default 5000)
        mount: URL mount point (default '/')
        funnel: Whether to enable Funnel (public internet access)

    Returns:
        (success, message)
    """
    if funnel:
        out, err, rc = _run_ts(
            ["funnel", "--bg", "--https", "443", mount, f"http://127.0.0.1:{port}"],
            timeout=10,
        )
    else:
        out, err, rc = _run_ts(
            ["serve", "--bg", "--https", "443", mount, f"http://127.0.0.1:{port}"],
            timeout=10,
        )

    if rc == 0:
        msg = "Tailscale Serve enabled" + (" (with Funnel)" if funnel else "")
        # Flush cache
        with _cache_lock:
            _cache["info"] = None
        return True, msg
    else:
        error = err or out or "Unknown error"
        return False, f"Failed to configure Tailscale Serve: {error}"


def install_tailscale_local():
    """Install Tailscale on THIS host (needs sudo). Returns (success, log tail)."""
    try:
        r = subprocess.run(
            ["sudo", "bash", "-c", "curl -fsSL https://tailscale.com/install.sh | sh"],
            capture_output=True, text=True, timeout=180,
        )
        with _cache_lock:
            _cache["info"] = None
        return r.returncode == 0, ((r.stdout or "") + (r.stderr or ""))[-1500:]
    except Exception as e:
        return False, str(e)


def tailscale_up_local(enable_ssh=True):
    """Run `tailscale up` on THIS host detached and return the browser login URL to
    paste in (mirrors the remote flow). Returns (True, url) | (True, 'ALREADY_CONNECTED')
    | (False, message)."""
    up = "tailscale up --accept-routes --timeout=600s"
    if enable_ssh:
        up += " --ssh"
    cmd = (
        "rm -f /tmp/tsup.log ; "
        f"nohup {up} > /tmp/tsup.log 2>&1 & "
        "for i in $(seq 1 20); do "
        "u=$(grep -oE 'https://login\\.tailscale\\.com/[A-Za-z0-9/]+' /tmp/tsup.log | head -1) ; "
        "[ -n \"$u\" ] && { echo \"$u\" ; break ; } ; "
        "grep -qi 'success' /tmp/tsup.log && { echo ALREADY_CONNECTED ; break ; } ; "
        "sleep 1 ; done"
    )
    try:
        r = subprocess.run(["sudo", "bash", "-c", cmd], capture_output=True, text=True, timeout=40)
    except Exception as e:
        return False, str(e)
    line = (r.stdout or "").strip().split("\n")[-1].strip()
    if line.startswith("https://login.tailscale.com"):
        with _cache_lock:
            _cache["info"] = None
        return True, line
    info = get_tailscale_info(force_refresh=True)
    if info.running or line == "ALREADY_CONNECTED":
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

    if info.running and info.dns_name:
        # Tailscale is running - bind to localhost and use Serve
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
    else:
        return {
            "method": "direct",
            "bind_host": "0.0.0.0",
            "port": port,
            "url": f"http://<your-server-ip>:{port}",
            "description": "No Tailscale detected. Bind to all interfaces.",
        }


# ─── Remote VPS Connectivity via Tailscale ─────────────────────

def check_remote_via_tailscale(remote_server):
    """Check if a RemoteServer is reachable via Tailscale.

    Uses the host as-is if it's already a Tailscale IP, otherwise
    tries to resolve via MagicDNS and peers.
    """
    host = remote_server.host
    info = get_tailscale_info()

    # Try direct ping
    reachable = check_peer_reachability(host)

    # If not reachable, check peer list for the hostname
    if not reachable["reachable"]:
        for peer in info.peers:
            if peer["hostname"] == host or host in peer["dns_name"]:
                # Found as a peer - try their Tailscale IP
                for ip in peer["ips"]:
                    p = check_peer_reachability(ip)
                    if p["reachable"]:
                        return {
                            "reachable": True,
                            "latency_ms": p["latency_ms"],
                            "via": "tailscale_ip",
                            "ip": ip,
                            "hostname": peer["dns_name"],
                        }
                if peer["online"]:
                    return {
                        "reachable": True,
                        "latency_ms": -1,
                        "via": "tailscale_peer",
                        "ip": peer["ips"][0] if peer["ips"] else host,
                        "hostname": peer["dns_name"],
                    }

    return {
        "reachable": reachable["reachable"],
        "latency_ms": reachable["latency_ms"],
        "via": "direct" if reachable["reachable"] else "unreachable",
        "ip": host,
        "hostname": host,
    }
