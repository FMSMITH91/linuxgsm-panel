"""Tailscale integration for LinuxGSM Panel.

Auto-detects Tailscale status, manages Serve/Funnel configuration,
provides network diagnostics, and recommends optimal bind settings.
"""
import json
import logging
import ipaddress
import re
import socket
import subprocess  # nosec B404 - argv lists only (tailscale, ping), never a shell
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from panel.core import i18n
from panel.core.validation import canonical_host, ip_address_or_none
from panel.security import privileged as _priv
from panel.ops import system_ops as _so

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
    # The --accept-routes pref (RouteAll, from `tailscale debug prefs`), or None when it could not
    # be read. It was filled from status JSON's TUN field, which says whether tailscaled runs a
    # kernel TUN device or userspace networking — nothing about subnet routes — so every ordinary
    # kernel-mode node read "Accept Routes: Yes" whether or not routes were accepted.
    accept_routes: Optional[bool] = None
    version: str = ""
    serve_config: dict = field(default_factory=dict)
    # serve_config is {} for BOTH "nothing is published" and "`tailscale serve status` did not
    # answer", and the page stated the first of those as a fact about the host. The second happens:
    # an older Tailscale answers it only to root or the operator ("Access denied: serve config
    # denied"), and the panel's account is not the operator (_read_serve_status asks the helper
    # then), and /tailscale said "No Serve routes configured yet." while the panel was being served
    # over the very mapping it was reporting as absent. Defaults to False so a reader that never
    # sets it keeps the old, positive wording.
    serve_unreadable: bool = False
    funnel_enabled: bool = False
    peers: list = field(default_factory=list)  # List of peer dicts
    # The parsed `tailscale status --json` and `tailscale debug prefs` this reading came from, or
    # None when they were not read. Kept for the debug report (debug_report/_src_tailscale.py),
    # which prints counts and booleans from them and never a value: no second CLI call for them.
    status_json: Optional[dict] = None
    prefs_json: Optional[dict] = None


# Cache results to avoid hammering `tailscale` CLI on every page load
_cache = {"info": None, "ts": 0, "ttl": 15}  # 15 second cache
_cache_lock = threading.Lock()


def _run_ts(args, timeout=5):
    """Run a tailscale CLI command. Returns (stdout, stderr, exit_code)."""
    try:
        # The program name is a literal and there is no shell, so only the ARGUMENTS vary —
        # which is this function's whole job. They are built by privileged.ts_serve_argv /
        # tool_argv, which validate every input and rebuild the mount from a literal alphabet
        # (CodeQL #375 closed on that change). Not a static string by design.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        # In the C locale: callers match its words (_read_serve_status's "Access denied").
        from panel.ops.ssh_manager import _core as _smc   # lazy: ssh_manager imports system_ops
        r = subprocess.run(  # nosec B603 - literal program, validated args (see above), no shell
            ["tailscale"] + args,
            capture_output=True, text=True, timeout=timeout, env=_smc._r20a_c_env(),
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return "", "tailscale binary not found", -1
    except _so._SOPS_TIMEOUTS:   # both classes: eventlet's run() raises the original module's
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


def release_operator():
    """Stop the panel's own account being the Tailscale operator, if it is; return what happened.

    "root" (the panel runs as root: nothing to release), "not-operator", "released" or "failed".
    Called once at every start (app._boot_serve), so a host an earlier panel set up switches with
    its first start on new code, whichever way the update arrived. ONE rule, the same as
    install.sh's release_tailscale_operator: wherever the panel's account holds the role, it is
    taken back, helper or not.

    The panel used to MAKE its account the operator (ensure_operator, after Connect, Serve setup,
    the setup wizard and a leftover route's removal), because then Serve and Tailscale SSH work
    without root. But an operator writes to tailscaled with no sudo and no helper: it can log the
    host out, join it to another tailnet with an auth key, and turn Tailscale SSH on, which admits
    root logins by THAT tailnet's rules — round the narrow sudo grant, whose point is that the
    panel's account cannot choose what root does. Every Tailscale write on the panel's host is a
    helper verb now, and the helper refuses the unsafe ones. Only the panel's own account is
    released: an operator someone chose for their own login is theirs (the helper checks that too).
    Never raises: it runs at boot, before anything else about Tailscale.
    """
    try:
        return _r24t_release_operator()
    except Exception:  # noqa: BLE001 - a boot step: logged, and the boot goes on
        _log.debug("Tailscale operator release failed", exc_info=True)
        return "failed"


def _r24t_release_operator():
    """release_operator's body (it only adds the never-raise)."""
    user = _current_os_user()
    if not user or user == "root":
        return "root"
    prefs = _read_prefs_json()     # prefs answer any local account: read, not write
    if not prefs or prefs.get("OperatorUser") != user:
        return "not-operator"
    if _so._helper_present():
        done = _r24t_release_via_helper(user)
        if done is not None:
            return done
    # No helper, one too old for the verb, or one that sudo refused (a password required): the
    # operator clears ITSELF, as install.sh does.
    # tailscaled lets the operator edit its own prefs, and clearing the operator can only take
    # power away, so this is the one write the panel's account makes to tailscaled.
    _out, _err, rc = _run_ts(["set", "--operator="], timeout=10)
    if rc != 0:
        _log.warning("Tailscale operator release as the panel's own account failed: rc %s", rc)
        return "failed"
    return _r24t_released()


def _r24t_release_via_helper(user):
    """The release through the helper's verb: "released", or None to clear the role as the account.

    None on ANY failure, not only a helper too old for the verb. This answered "failed" for the
    rest -- sudo refusing the helper (a sudoers.d rule sorting after the grant, a per-user install
    without NOPASSWD), a timeout -- and the caller returned it, so the account kept the operator
    role at every boot although the self-clear needs no privilege. Clearing can only take power
    away, and the caller has already checked the role is this account's, so falling back is safe.
    """
    out, err, rc = _so._run_verb("tailscale-release-operator", [user], timeout=20, merge_stderr=False)
    if rc == 0:
        return _r24t_released()
    if not (rc == 2 and "unknown verb" in (err or "") + (out or "")):
        _log.warning("Tailscale operator release through the helper failed (rc %s); releasing it "
                     "as the panel's own account instead", rc)
        return None
    # The installed helper predates the verb: new code arrived without install.sh being run (a
    # plain git pull). Said apart, because the cure is not a retry. The caller then releases the
    # role as the panel's own account.
    _log.warning("The installed root helper is older than this panel and has no "
                 "tailscale-release-operator verb: re-run install.sh as root to update it. "
                 "Releasing the Tailscale operator role as the panel's own account instead.")
    return None


def _r24t_released():
    """Log a release that took, and say what it means on a per-user install; "released"."""
    _log.info("The panel's account is no longer the Tailscale operator")
    if not _so._is_system_service():
        # Per-user install: the panel's account is the owner's own login, so it was the owner who
        # lost the role. Tell them once, now, why their own `tailscale serve` starts asking for sudo.
        _log.warning("This is a per-user install, so the panel's account is your own login: your "
                     "own `tailscale serve` and `tailscale set` now need sudo. An operator account "
                     "can move this host to another tailnet and turn on Tailscale SSH without "
                     "root, so the panel no longer leaves your account holding that role.")
    return "released"


def allow_tailscale_ufw():
    """Best-effort: allow the Tailscale interface through UFW on the panel host.

    So the node stays reachable over the tailnet. A common lockout is UFW active but tailscale0
    not allowed — then Serve/SSH over the tailnet silently can't reach the node. Idempotent.
    """
    try:
        return _so.ufw_allow_tailscale()
    except Exception as e:
        return False, str(e)


def _run_ts_json(args, timeout=5):
    """Run tailscale with --json flag and parse output."""
    out, _, rc = _run_ts(args + ["--json"], timeout=timeout)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _read_prefs_json():
    """The parsed `tailscale debug prefs` dict, or None when the prefs can't be read."""
    out, _, rc = _run_ts(["debug", "prefs"])
    if rc != 0 or not out:
        return None
    try:
        prefs = json.loads(out)
    except ValueError:
        return None
    return prefs if isinstance(prefs, dict) else None


def _read_route_all():
    """The node's --accept-routes preference (RouteAll), or None when the prefs can't be read."""
    return _route_all_of(_read_prefs_json())


def _route_all_of(prefs):
    """The RouteAll pref of a prefs dict, or None when there is none or it is not a bool."""
    v = prefs.get("RouteAll") if isinstance(prefs, dict) else None
    return v if isinstance(v, bool) else None


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
        _read_status_json(info, status)
    else:
        _read_status_text(info)

    _read_serve_status(info)
    _detect_magic_dns(info)
    return info


def _read_status_json(info, status):
    """Fill `info` from `tailscale status --json` (a non-empty dict)."""
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
    info.status_json = status
    info.prefs_json = _read_prefs_json()
    info.accept_routes = _route_all_of(info.prefs_json)
    info.magic_dns_enabled = bool(info.dns_name)

    # Collect peers. Trust Tailscale's own `Online` field — it is authoritative.
    # (Do NOT downgrade based on LastSeen: for an online peer the last handshake
    # can legitimately be many minutes old on a long-lived connection, so a
    # "last seen > 2 min" heuristic wrongly marks live peers offline.)
    peer_data = status.get("Peer") or {}
    for peer_id, peer in peer_data.items():
        info.peers.append(_peer_entry(peer_id, peer))


def _peer_entry(peer_id, peer):
    """One peer of `tailscale status --json`'s "Peer" map, as the dict the page lists."""
    ts_online = bool(peer.get("Online", False))
    last_seen_str = peer.get("LastSeen", "") or ""
    # tailscaled reports Go's zero time ("0001-01-01T00:00:00Z") for a peer it has never seen go
    # away, which is every peer connected right now. That is "no time", not a date: shown as one it
    # read "12/31/1, 6:09 PM" (year 1, in the viewer's zone) beside "Online".
    if last_seen_str.startswith("0001-01-01"):
        last_seen_str = ""

    return {
        "id": peer_id,
        "hostname": peer.get("HostName", ""),
        "dns_name": peer.get("DNSName", "").rstrip(".") if peer.get("DNSName") else "",
        "ips": peer.get("TailscaleIPs", []),
        "os": peer.get("OS", ""),
        "online": ts_online,
        "last_seen": last_seen_str,
        "relay": peer.get("Relay", ""),
        # Whether the peer is reached directly (it has a current endpoint) rather than through a
        # DERP relay. The endpoint itself (CurAddr, an address) is never kept.
        "direct": bool(peer.get("CurAddr")),
    }


def _read_status_text(info):
    """Fill `info` from plain `tailscale status`, when the JSON form gave nothing."""
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


def _read_serve_status(info):
    """Fill `info`'s Serve fields from `tailscale serve status`."""
    serve_out, serve_err, serve_rc = _run_ts(["serve", "status"])
    if serve_rc != 0 and _so._helper_present() and (
            info.running or "access denied" in (serve_err or "").lower()):
        # An older Tailscale answers `serve status` only to root or the operator, and the panel's
        # account is not the operator (release_operator). The helper's read verb, then: only with
        # the helper, so a host without one never sends a failing sudo per page load. And only
        # when the read was REFUSED (the CLI's "Access denied: …", read in the C locale; its exit
        # code is 1 for every error) or tailscaled is up: a stopped or hung tailscaled fails the
        # same read as root too, and each try is a sudo (a journal line, up to 10 s).
        serve_out, _, serve_rc = _so._run_verb("tailscale-serve-status", [], timeout=10,
                                               merge_stderr=False)
    # rc 0 with no output is a READING — `tailscale serve status` prints "No serve config" and
    # exits 0 when nothing is published — so only a non-zero rc means the panel did not learn
    # anything. Carried on the info rather than inferred from an empty serve_config, because
    # emptiness cannot tell the two apart.
    if serve_rc != 0:
        info.serve_unreadable = True
    elif serve_out:
        info.serve_config = _parse_serve_status(serve_out)
        info.funnel_enabled = any(
            srv.get("funnel", False) for srv in info.serve_config.get("services", [info.serve_config])
        )


def _detect_magic_dns(info):
    """Set info.magic_dns_enabled when the status did not, but the node's name resolves."""
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


_SERVE_URL_RE = re.compile(r"https?://\S+")


def _serve_url_line(line):
    r"""Return (url, parenthesised note or None) for a `serve status` URL line, else None.

    `line` is already stripped. It answers what `^(https?://\S+)\s*(\(.*\))?$` answered. That
    pattern, when the note failed, gave the URL back one character at a time and retried the note
    at every '(' inside it, each retry reading to the end of the line: quadratic in a URL full of
    '('. The note is "(" … ")" after the URL's blanks; failing that, the pattern ended the URL at
    its last '(' (keeping a character of URL) when the line ends in ')', so that is kept too.
    """
    m = _SERVE_URL_RE.match(line)
    if not m:
        return None
    note = line[m.end():].lstrip()
    if not note:
        return m.group(), None
    if note.startswith("(") and note.endswith(")"):
        return m.group(), note
    cut = line.rfind("(", line.index("://") + 4, m.end()) if line.endswith(")") else -1
    return (line[:cut], line[cut:]) if cut > 0 else None


# The kind and what it serves are optional: a handler of a kind the CLI cannot describe (a
# Redirect, which only `serve set-raw` writes) prints as a bare `|-- <mount>`, and skipping it made
# a mount another app holds read as free. Such a route has type "" and target "".
_SERVE_ROUTE_KINDS = ("proxy", "path", "text")


def _parse_serve_status(text):
    """Parse `tailscale serve status` output into a structured dict."""
    result = {"services": [], "raw": text}
    current_url = None
    current_funnel = False
    current_svc = ""
    current_routes = []

    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        # Match URL line
        url_line = _serve_url_line(stripped)
        if url_line:
            _append_service(result["services"], current_url, current_funnel, current_routes,
                            current_svc)
            current_url = url_line[0].rstrip(".")
            # A Tailscale Service's listener ends "(svc:<name>)" (upstream printWebStatusTree). It
            # is not the node's own: the panel's `serve --https=443` never writes it, so its routes
            # and Funnel say nothing about the listener the panel shares.
            _svc = re.search(r"\((svc:[^()]*)\)\Z", url_line[1] or "")
            current_svc = _svc.group(1) if _svc else ""
            # Tailscale prints "(Funnel on)" or "(tailnet only)" after the URL, with a CAPITAL F.
            # This compared case-sensitively against "funnel", so it was always False, and the page
            # called a panel that was on the public internet "private - tailnet only".
            current_funnel = "funnel on" in (url_line[1] or "").lower()
            current_routes = []
            continue

        # Match route line: `|-- <mount> <type> <what>`, the type `proxy`, `path` (a directory
        # `tailscale serve <dir>` shares) or `text` (upstream serveHandlerDesc). Only proxy routes
        # were kept, so a file share on the panel's listener was invisible: the panel's Serve write
        # flipped its Funnel (Funnel is per listener) and the wizard published over its mount.
        route = _r14a_serve_route(stripped)
        if route and current_url:
            current_routes.append(route)
        # There used to be a "funnel anywhere in the line" fallback here. It could never see the
        # URL line (that `continue`s above), and the "# Funnel on:" header comes before any URL, so
        # all it could ever match was a ROUTE — a mount or backend with "funnel" in its name.

    _append_service(result["services"], current_url, current_funnel, current_routes, current_svc)

    return result


def _r14a_serve_route(line):
    """One `|-- <mount> [<kind> <what>]` line as {mount, type, target}, else None.

    Read by splitting, not by one regular expression: a non-space run beside an optional group backtracked
    super-linearly on a long line (Sonar S8786). `line` is already stripped by the caller.
    """
    if not line.startswith("|--") or not line[3:4].isspace():
        return None
    parts = line[3:].split(None, 2)
    if len(parts) == 1:
        return {"mount": parts[0], "type": "", "target": ""}
    if len(parts) == 3 and parts[1] in _SERVE_ROUTE_KINDS:
        return {"mount": parts[0], "type": parts[1], "target": parts[2].strip()}
    return None


def _append_service(services, url, funnel, routes, svc=""):
    """Append one parsed Serve service to `services` — only when it has a URL and routes.

    `svc` is the Tailscale Service it belongs to ("svc:<name>"), "" for the node's own listener.
    """
    if url and routes:
        services.append({
            "url": url,
            "funnel": funnel,
            "routes": routes,
            "svc": svc,
        })


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


# A host name / IP the panel may hand to `ping`. Same charset as app.HOST_RE (hostname, IPv4,
# bracketed IPv6, MagicDNS), with the first character pinned to alphanumeric: `ping` takes options,
# and this value is argv[-1], so a leading dash is read as one. There is no shell here, so this is
# option injection rather than command injection — but "the argument cannot be an option" is the
# same rule privileged.USERNAME_RE and models._SHELL_IDENT_RE already apply for the same reason.
_PEER_HOST_RE = re.compile(r"^[A-Za-z0-9\[][A-Za-z0-9._:\[\]-]{0,254}\Z")


def valid_peer_host(host):
    """True if `host` is something the panel may ping.

    Checked at the route (for a clear 400) and again here, so a future caller cannot skip it.
    """
    return bool(_PEER_HOST_RE.match(str(host or "").strip()))


def check_peer_reachability(host) -> dict:
    """Check if a host (IP or hostname) responds on the tailnet via ping."""
    reachable = False
    latency_ms = 0
    if not valid_peer_host(host):
        return {"reachable": False, "latency_ms": 0}
    # Brackets off an IP literal (validation.canonical_host, the panel's one canonicalisation):
    # `[fd7a:115c:a1e0::1]` is how the panel prints an IPv6 host, and valid_peer_host accepts it,
    # but ping reads it as a host NAME, fails to resolve it, and the peer read "not responding".
    # The result is an address's own text or the name unchanged, so it cannot start with a dash.
    host = canonical_host(str(host).strip())
    from panel.ops.ssh_manager import _core as _smc     # lazy: ssh_manager imports this module
    try:
        # An argv list, no shell, and `host` passed valid_peer_host: its first character is a
        # letter, a digit or '[', so ping never reads it as an option.
        # In C.UTF-8 (_core._r20a_c_env): `time=` below is read by its English word, and iputils
        # ping prints through gettext in the service's own language.
        r = subprocess.run(  # nosec B603 B607  # NOSONAR - argv list; host passed valid_peer_host
            ["ping", "-c", "1", "-W", "3", host],
            capture_output=True, text=True, timeout=5, env=_smc._r20a_c_env(),
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
    and the root path cannot drift: one definition of what the command is, used by both.
    """
    return _priv.ts_serve_argv(verb, grammar, mount, scheme, str(port))[1:]


def setup_tailscale_serve(port=5000, mount="/", funnel=False, backend_scheme="http",
                          keep_shared_funnel=False):
    """Configure Tailscale Serve to proxy this panel; return (success, message).

    `port` is the local port the panel runs on (default 5000), `mount` the URL mount point
    (default '/'), and `funnel` whether to enable Funnel (public internet access).

    Funnel is a property of the LISTENER (host:443), not of a mount: every `serve` write turns it
    off and every `funnel` write turns it on for each app on :443 (serve_v2.go setServe ->
    applyFunnel -> SetFunnel(dnsName, srvPort, ...)). So a write whose Funnel differs from the
    listener's while another app shares it is refused (_r12a_serve_verb): it would take that app
    off the internet, or put it on. `keep_shared_funnel` (the boot re-point) instead re-points the
    panel's EXISTING route with the listener's Funnel as it is, so a restart never changes the
    panel's exposure or the other app's.

    `backend_scheme` is how to reach the panel on loopback — "http" (default) or "https+insecure"
    when the panel is terminating its own self-signed TLS. Tailscale re-terminates TLS with the
    real ts.net cert either way; this just has to match how the panel is actually listening or the
    proxy 502s.
    """
    mount = mount or "/"
    # Validate HERE and answer, rather than letting _ts_mount raise out of the call below.
    # `mount` is request JSON (POST /api/tailscale/serve), and the chain from the route down to
    # the validator — api_tailscale_serve -> here -> _ts_serve_args -> ts_serve_argv -> _ts_mount
    # — caught nothing, so a typo in the mount box answered 500 with an HTML error page and no
    # word about what was wrong. This function's contract is (ok, message); a rejected argument is
    # one of the things it is FOR.
    #
    # The message is FIXED, with nothing from the exception in it. VerbError's own docstring
    # promises its text never contains the rejected value, so interpolating it was safe in fact —
    # but it is still an exception's text reaching a response, which is what py/stack-trace-exposure
    # flags (six alerts, across this function's callers) and what _log_and_generic exists to
    # prevent everywhere else here. The rule is worth more than the three words it added.
    try:
        mount = _priv._ts_mount(mount)
    except _priv.VerbError:
        return False, ("That isn't a usable mount point. Use \"/\" or a short path like "
                       "\"/lgsm\".")

    # serve/funnel is privileged: the write goes through the helper's verb (_apply_serve). The
    # tailnet interface is allowed through UFW too, or the Serve URL would be unreachable on a
    # firewalled host.
    verb, note = _r12a_serve_verb(port, mount, funnel, keep_shared_funnel)
    if verb is None:
        return False, note
    # After the refusal, not before: the refusal says "Nothing was changed", and the tailscale0
    # rule (every port open to the tailnet) stayed behind when the write was then refused.
    allow_tailscale_ufw()
    ok, err = _apply_serve(verb, mount, backend_scheme, port)
    if ok:
        with _cache_lock:
            _cache["info"] = None
        # Sentences: each part translated whole where it is shown (i18n.tr); the note was a clause
        # appended to the English.
        return True, i18n.Sentences(i18n.Sentence("Tailscale Serve enabled (with Funnel)") if verb == "funnel"
                                    else i18n.Sentence("Tailscale Serve enabled"), note)
    return False, i18n.Sentence("Failed to configure Tailscale Serve: {why}", why=err or "Unknown error")


def _r12a_listener_funnel(serve_config, port):
    """(Funnel on?, [mounts of OTHER apps]) for the :443 listener the panel writes; (False, []) if none."""
    for svc in (serve_config or {}).get("services") or []:
        if _serve_port_flag(svc.get("url")) == "--https=443" and not svc.get("svc"):
            return (bool(svc.get("funnel")),
                    [r.get("mount", "") for r in svc.get("routes") or []
                     if not route_targets_port(r.get("target"), port)])
    return False, []


def _r12a_serve_verb(port, mount, funnel, keep_shared_funnel):
    """("serve"|"funnel", note) for setup_tailscale_serve to write, or (None, why) to write nothing.

    Read fresh (through the helper's read verb where Tailscale answers only root). An unreadable
    config is written as asked, as it always was: it cannot show another app, and refusing would
    stop the boot re-point keeping the panel's own route on the scheme it serves.
    """
    want = "funnel" if funnel else "serve"
    info = get_tailscale_info(force_refresh=True)
    if info.serve_unreadable:
        return want, ""
    shared, others = _r12a_listener_funnel(info.serve_config, port)
    if not others or shared == bool(funnel):
        return want, ""
    names = _r12a_apps_at(others)
    if keep_shared_funnel and _r12a_panel_on_443(info.serve_config, port, mount):
        _log.warning("Tailscale Serve: Funnel left as it is on the :443 listener it shares with %s",
                     names)
        return ("funnel" if shared else "serve"), _r12a_kept_note(shared, others)
    return None, _r12a_funnel_refusal(funnel, others)


def _r12a_kept_note(shared, others):
    """What a boot re-point that left the shared listener's Funnel as it was says after its answer.

    `others` are the other apps' mounts. A whole Sentence; the apps are named one phrase each.
    """
    if shared:
        return i18n.Sentence("(Funnel left on: it is set per listener, and {apps} shares it, so the "
                             "panel is reachable from the internet too)", apps=_r15e_apps(others))
    return i18n.Sentence("(Funnel left off: it is set per listener, and {apps} shares it)",
                         apps=_r15e_apps(others))


def _r15e_apps(mounts):
    """_r12a_apps_at for a sentence the viewer reads: each "the app at …" a phrase translated alone."""
    return [i18n.Sentence("the app at {mount}", mount=m) for m in mounts]


def _r12a_apps_at(mounts):
    """Other apps named by where they are mounted: "the app at /", never a bare "/"."""
    return ", ".join("the app at %s" % m for m in mounts)


def shared_funnel_apps(serve_config, port, use_funnel):
    """The other apps' mounts when the panel is on Funnel only because they share its listener.

    [] unless the panel has a route on the :443 listener, that listener has Funnel on, the panel's
    own setting (`use_funnel`, tailscale_use_funnel) is off, and another app holds a mount there.
    Funnel is per listener, so then the panel IS on the public internet against its own setting,
    and every page that shows its Serve or Funnel state has to say so (the boot keeps it that way
    rather than take the other app off the internet: _r12a_serve_verb).
    """
    shared, others = _r12a_listener_funnel(serve_config, port)
    if not shared or use_funnel or not others:
        return []
    return others if _r13a_panel_on_listener(serve_config, port) else []


def _r13a_panel_on_listener(serve_config, port):
    """Whether the panel has a route on the node's own :443 listener (a Tailscale Service's is not)."""
    return any(_serve_port_flag(r["url"]) == "--https=443" and not r.get("svc")
               for r in panel_serve_routes(serve_config, port))


def panel_funnel_facts(cfg):
    """{"funnelled", "shared_funnel", "unread"} for a page that says where the panel can be reached.

    Read from the host (the cached reading) and only once Serve is set up; False/[]/False
    otherwise. "funnelled": a Serve route to the panel is on a Funnel listener. "shared_funnel":
    shared_funnel_apps — on Funnel against its own setting, for another app. "unread": `tailscale
    serve status` did not answer, so neither was read.
    """
    if not cfg.get("tailscale_setup_done"):
        return {"funnelled": False, "shared_funnel": [], "unread": False}
    info = get_tailscale_info()
    if info.serve_unreadable:
        # An unread Serve has an empty serve_config, which read as "not on Funnel", and the close
        # route then said "reachable only over your tailnet" of a panel Funnel still published.
        # The panel's own record of choosing Funnel is the best that is known.
        return {"funnelled": bool(cfg.get("tailscale_use_funnel")), "shared_funnel": [],
                "unread": True}
    ports = _r13b_panel_ports(cfg)
    shared = []
    for port in ports:
        shared = shared or shared_funnel_apps(info.serve_config, port,
                                              cfg.get("tailscale_use_funnel"))
    return {"funnelled": any(panel_funnelled(info.serve_config, p) for p in ports),
            "shared_funnel": shared, "unread": False}


def _r13b_panel_ports(cfg):
    """The ports a Serve route to this panel may target: the one it is bound to, and config.json's.

    The same port unless a port change is saved and the restart is pending. Then Serve's routes
    reach the bound port, and config.json's found no panel route: a panel on Funnel read as "not
    reachable from the internet". A question about whether it IS reachable asks both.
    """
    bound, stored = _r13b_bound_port(cfg), cfg.get("port", 5000)
    return [bound] if bound == stored else [bound, stored]


def _r13b_bound_port(cfg):
    """The port this process is bound to (app.config BOOT_PORT), else config.json's."""
    boot = None
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            boot = current_app.config.get("BOOT_PORT")
    except Exception:  # noqa: BLE001 - no app to ask: config.json's port, as before
        boot = None
    if isinstance(boot, int) and not isinstance(boot, bool) and 0 < boot < 65536:
        return boot
    return cfg.get("port", 5000)


def panel_funnelled(serve_config, port):
    """Whether any Serve route to the panel is on a listener with Funnel on (internet-reachable)."""
    return any(r["funnel"] for r in panel_serve_routes(serve_config, port))


def _r12a_panel_on_443(serve_config, port, mount):
    """Whether the panel already has its route at `mount` on the :443 listener."""
    want = norm_mount(mount)
    return any(norm_mount(r["mount"]) == want and _serve_port_flag(r["url"]) == "--https=443"
               and not r.get("svc") for r in panel_serve_routes(serve_config, port))


def _r12a_funnel_refusal(funnel, others):
    """Why a Serve write that would change another app's Funnel (at mounts `others`) was not made."""
    if funnel:
        return i18n.Sentence("Funnel is set per listener, not per app: publishing the panel with Funnel "
                             "here would also put {apps} on the public internet. Nothing was changed.",
                             apps=_r15e_apps(others))
    return i18n.Sentence("Funnel is set per listener, not per app, and it is on for {apps}: publishing "
                         "the panel here without Funnel would take it off the public internet. Nothing "
                         "was changed; turn Funnel off for that app first, or publish the panel with "
                         "Funnel.", apps=_r15e_apps(others))


def _apply_serve(verb, mount, backend_scheme, port):
    """Run the Serve/Funnel command in the first grammar that works; return (ok, last error text)."""
    # The CLI grammar changed by Tailscale version — newer (~1.58+) takes the target as the only
    # positional with a --set-path mount, older took the mount as a positional ("... 443 / URL") —
    # so both are tried, newest first. Only through the helper's verb: this tried the panel's own
    # account first, which worked because the panel had made itself the Tailscale operator, and
    # an operator can change anything about tailscaled without the helper (release_operator).
    # The verb fixes the subcommand and validates the rest; a sudoers rule naming the tailscale
    # binary would have covered every subcommand it has (up, logout, set --exit-node).
    err = ""
    for grammar in ("modern", "legacy"):
        out, e, rc = _so._run_verb(
            "tailscale-serve", [verb, grammar, mount, backend_scheme, str(port)],
            timeout=10, merge_stderr=False)
        if rc == 0:
            return True, ""
        err = e or out or err
    return False, err


@dataclass
class _SimpleResult:
    """The three fields of subprocess.CompletedProcess that this module reads.

    _run_verb returns (out, err, rc); the callers below were written against a
    CompletedProcess. Rather than rewrite every read, adapt the shape — the point of the
    change is WHICH path runs the command, not how its result is spelled.
    """

    stdout: str
    stderr: str
    returncode: int


def install_tailscale_local():
    """Install Tailscale on THIS host (needs root). Returns (success, log tail).

    Was `sudo bash -c "curl -fsSL … | sh"`. A sudoers rule permitting bash is exactly NOPASSWD:ALL,
    so this one line was on its own enough to keep the grant wide open. The verb has no pipe and no
    shell string: curl writes the installer to a root-owned 0600 file under /run and sh runs that
    file. Still remote code as root — that is what installing Tailscale is — but the URL is fixed
    on the far side and the caller supplies nothing.
    """
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
    """Run `tailscale up` on THIS host detached and return the browser login URL to paste in.

    Mirrors the remote flow. Returns (True, url) | (True, 'ALREADY_CONNECTED') | (False, message).

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
    install.sh re-run as root. That last form is a compound script, so system_ops runs it under
    `sudo bash -c` whole (a bare `sudo ` elevated only its leading `rm`, and `tailscale up` never
    started); only a host with no helper takes it, and its grant is the old broad one anyway.
    """
    # SSH only where the owner chose it at install (system_ops.tailscale_ssh_allowed): the helper
    # refuses `--ssh` otherwise, and Connect must still join, so it asks without it.
    enable_ssh = enable_ssh and _so.tailscale_ssh_allowed()
    out, err, rc = _so._run_verb("tailscale-up-login",
                                 ["yes" if enable_ssh else "no", "-"],
                                 timeout=40, merge_stderr=False)
    r = _SimpleResult(stdout=out, stderr=err, returncode=rc)
    line = (r.stdout or "").strip().split("\n")[-1].strip()
    # FULLMATCH, not startswith. This URL is rendered into the panel's HTML (tailscale.html and
    # setup_tailscale.html both put it in an href AND in the link text), and the charset is enforced
    # by a grep running on the host being joined — so a prefix test accepts anything at all after
    # "https://login.tailscale.com/". The REMOTE twin in ssh_manager has pinned the whole string for
    # a while and says why; this panel-host copy was never switched over. Same regex, one definition.
    if _priv.TS_LOGIN_URL_RE.fullmatch(line):
        with _cache_lock:
            _cache["info"] = None
        return True, line
    info = get_tailscale_info(force_refresh=True)
    if info.running or line == "ALREADY_CONNECTED":
        allow_tailscale_ufw()  # keep the node reachable over the tailnet if UFW is active
        return True, "ALREADY_CONNECTED"
    return False, (r.stderr or r.stdout or "Could not get a login link — is Tailscale installed on this host?")


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")


def route_targets_port(target, port):
    """True when a Serve route's backend is loopback on `port`, whatever the scheme.

    The backend as `tailscale serve status` prints it ("http://127.0.0.1:5000",
    "https+insecure://localhost:5000", ...) — i.e. true when the route proxies an app listening on
    THIS machine at that port.
    """
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    host, sep, p = t.split("/", 1)[0].rpartition(":")
    if not sep:
        return False
    try:
        return host.lower() in _LOOPBACK_HOSTS and int(p) == int(port)
    except (TypeError, ValueError):
        return False


def panel_serve_routes(serve_config, port):
    """The Serve mappings on this node that proxy the PANEL (loopback on its `port`).

    As [{"url", "mount", "target", "funnel"}], in the order the host printed them.

    A node can serve other apps beside the panel — the setup wizard picks /lgsm precisely because
    something else already holds "/" — so "the first route listed" is not the panel's. Tailscale
    prints routes shortest mount first, so it was the OTHER app's "/" whenever one existed.
    """
    out = []
    for svc in (serve_config or {}).get("services") or []:
        for r in svc.get("routes") or []:
            if route_targets_port(r.get("target"), port):
                out.append({"url": svc.get("url", ""), "mount": r.get("mount", ""),
                            "target": r.get("target", ""), "funnel": bool(svc.get("funnel")),
                            "svc": svc.get("svc", "")})
    return out


def _serve_port_flag(url):
    """`--https=<port>` / `--http=<port>` naming the listener a Serve URL is on (443/80 by default)."""
    m = re.match(r"^(https?)://[^/:]+(?::(\d{1,5}))?(?:/|$)", url or "")
    if not m:
        return None
    port = int(m.group(2)) if m.group(2) else (443 if m.group(1) == "https" else 80)
    if not 1 <= port <= 65535:
        return None
    return "--%s=%d" % (m.group(1), port)


def listener_flag(url):
    """`--https=<port>` / `--http=<port>` for the listener a Serve URL is on, or None."""
    return _serve_port_flag(url)


def norm_mount(mount):
    """'/lgsm/' and '/lgsm' are one mount; empty is '/' (PrefixMiddleware reads it the same way)."""
    return str(mount or "/").rstrip("/") or "/"


def off_mount(mount):
    """`mount` validated for `--set-path=`, spelled EXACTLY as the host stores it.

    Tailscale keeps a trailing "/" (its cleanURLPath accepts "/x/" beside "/x", and they are two
    handlers), so `off` has to name it with the slash or it answers "handler does not exist".
    _ts_mount refuses "/x/", so the slash comes off for the check and goes back on as a literal:
    every other character still comes from _ts_mount's alphabet.
    """
    return _priv._r24t_off_mount(mount)     # the helper's verb validates it the same way


def serve_off_args(url, mount):
    """The `tailscale serve` arguments that remove ONE mapping: `mount` on the listener `url` is on.

    `tailscale serve --https=443 --set-path=<mount> off` is the CLI's own removal grammar. The path
    is always given, "/" included: with no --set-path, `off` removes EVERY mount on that port — the
    other apps' mappings with the panel's. Removing the last mount on a port also clears that
    port's Funnel flag. Returns None for a URL whose listener cannot be read.
    """
    flag = _serve_port_flag(url)
    if not flag:
        return None
    return ["serve", flag, "--set-path=%s" % off_mount(mount), "off"]


def route_url(route):
    """The address a Serve route answers at: its listener's URL, then its mount."""
    mount = norm_mount(route.get("mount"))
    return (route.get("url") or "").rstrip("/") + ("" if mount == "/" else mount)


def route_scheme(route):
    """The backend scheme of a Serve route ("http", "https+insecure", ...)."""
    target = route.get("target") or ""
    return target.split("://", 1)[0] if "://" in target else "http"


def managed_mount(mount):
    """The mount the panel writes for `mount` (tailscale_mount), spelled as Serve stores it, or None.

    _ts_mount's spelling, the one setup_tailscale_serve hands to --set-path: "/lgsm", never
    "/lgsm/". Serve keeps the two apart (cleanURLPath accepts both) and looks "/lgsm/" up FIRST for
    every /lgsm/* request (ipnlocal getServeHandler tries pth+"/" before pth at each level). So a
    "/lgsm/" beside the "/lgsm" the boot writes is a second route, and the one that answers: on the
    wrong scheme it 502s the whole panel while the route the boot re-pointed reads as fine. They
    were compared normalised, so that twin counted as managed — never removed, never listed with a
    Remove, and reported as one "a panel restart re-points". None when the panel cannot write the
    mount at all (setup_tailscale_serve refuses it too), so no route is managed then.
    """
    try:
        return _priv._ts_mount(mount or "/")
    except _priv.VerbError:
        return None


def is_managed_route(route, cfg):
    """True for THE route the panel manages: the one at tailscale_mount on the :443 listener.

    The panel writes only that one (privileged.ts_serve_argv hard-codes --https=443), and the boot
    re-point keeps only that one on the scheme the panel serves. Every other route to the panel's
    port was made some other way, and nothing re-points it, so it answers 502 after the next flip
    of the panel's own scheme. With Serve not set up, no route is managed. The mount is compared
    exactly as the panel writes it (managed_mount): a trailing-slash twin is another route. A
    Tailscale Service's listener ("svc") is never the node's own :443, whatever its port reads.
    """
    want = managed_mount(cfg.get("tailscale_mount"))
    return (bool(cfg.get("tailscale_setup_done")) and want is not None and not route.get("svc")
            and _serve_port_flag(route.get("url")) == "--https=443"
            and route.get("mount") == want)


def panel_route(serve_config, port, mount, scheme=None):
    """The panel's own Serve route at `mount` (normalised), or None when nothing proxies it there.

    That is the one address that works: PrefixMiddleware builds every URL under tailscale_mount, so a
    panel route at another mount is a doorway whose links all lead back to this one. The :443
    listener comes first (the one the panel writes). With `scheme`, only a route whose backend
    scheme is `scheme` counts: one on any other scheme answers 502.
    """
    want = norm_mount(mount)
    hits = [r for r in panel_serve_routes(serve_config, port) if norm_mount(r["mount"]) == want
            and (scheme is None or route_scheme(r) == scheme)]
    hits.sort(key=lambda r: _serve_port_flag(r["url"]) != "--https=443")
    return hits[0] if hits else None


def _r13a_taken_on_443(serve_config, port):
    """The mounts other apps hold on the node's own :443 listener (a Tailscale Service's is not it)."""
    return {norm_mount(r.get("mount"))
            for svc in (serve_config or {}).get("services") or []
            if _serve_port_flag(svc.get("url")) == "--https=443" and not svc.get("svc")
            for r in svc.get("routes") or []
            if not route_targets_port(r.get("target"), port)}


def free_panel_mount(serve_config, port, mount):
    """Where to publish the panel: `mount`, unless ANOTHER app holds it on :443; then /lgsm.

    None when both belong to other apps. A mount the panel's own route holds counts as free: that
    route is the panel's, and publishing there replaces it rather than adding a second one beside
    it. Counting it as taken is how the setup wizard published the panel twice, at "/" and then at
    /lgsm, and left the "/" route behind to answer 502 at the next flip of the panel's scheme.
    """
    taken = _r13a_taken_on_443(serve_config, port)
    for cand in dict.fromkeys((norm_mount(mount), "/lgsm")):
        if cand not in taken:
            return cand
    return None


def stale_panel_routes(serve_config, port, mount):
    """The panel's own routes on :443 at a mount other than `mount`, as the panel writes it.

    Only :443, the one listener the panel writes: a route to the panel on any other listener was
    made by hand, on purpose, and is left alone. Only routes to loopback on the panel's `port`
    (panel_serve_routes): another app's route is never one of these. "Other" is exact
    (managed_mount): a "/lgsm/" beside the "/lgsm" just written is stale, and the one Serve would
    answer /lgsm/* with. Nothing when `mount` is not one the panel can write. Not a route on a
    Tailscale Service's listener ("svc"): that is not the node's :443, and the panel cannot remove
    one (remove_panel_route).
    """
    want = managed_mount(mount)
    if want is None:
        return []
    return [r for r in panel_serve_routes(serve_config, port)
            if _serve_port_flag(r["url"]) == "--https=443" and r["mount"] != want
            and not r.get("svc")]


def _fresh_panel_route(route, port):
    """`route` as the host reports it now: the fresh dict, False when it is gone, None when unread.

    "Gone" includes a mount that now proxies something other than the panel: it is no longer the
    panel's to remove.
    """
    info = get_tailscale_info(force_refresh=True)
    if not info.installed or info.serve_unreadable:
        return None
    for r in panel_serve_routes(info.serve_config, port):
        if r["url"] == route.get("url") and r["mount"] == route.get("mount"):
            return r
    return False


# Two of remove_panel_route's own reasons, by name: serve_upkeep records a failed leftover removal
# as a reason class, and it told these apart from "an unexpected error" by their template.
R17A_UNNAMED_MOUNT = "its mount is not one the panel can name on the command line"
R17A_LISTENER_UNREAD = "the listener it is on could not be read"


def remove_panel_route(route, port):
    """Remove ONE of the panel's own Serve routes; return (state, error text).

    state is "removed", "gone" (not there any more, or no longer the panel's), "unread" (Serve
    could not be read just before, so nothing ran) or "failed" (the CLI refused; its text comes
    back). Serve is read again right before the command, so a mount another app took in the
    meantime is not removed: the CLI has no compare-and-delete, and this is as narrow as the window
    gets. The path is always named (serve_off_args), and only a route to loopback on `port` is ever
    a candidate.

    The `off` is the helper's `tailscale-serve-off` verb, named by listener and mount. It ran as
    the panel's account, which worked only while the panel made itself the Tailscale operator
    (release_operator says why it no longer does). A refusal answers "failed", with its text.

    A route on a Tailscale Service's listener ("svc") answers "failed" and runs nothing. The
    removal grammar has no --service here, so its `off` named the NODE's own :443 at that mount:
    it took down whatever app the node served there (Grafana at "/", say), audited as the panel's
    route, and left the Service route in place to fail the same way at every boot.
    """
    fresh = _fresh_panel_route(route, port)
    if fresh is None:
        return "unread", ""
    if fresh is False:
        return "gone", ""
    if fresh.get("svc"):
        # Sentences: these panel-worded reasons go into "Failed to remove: {why}" and the leftover
        # note, translated whole; as plain text they stayed English inside a translated sentence.
        return "failed", i18n.Sentence("it is on the Tailscale Service {svc}, which the panel does not "
                                       "manage", svc=fresh["svc"])
    try:
        args = serve_off_args(fresh["url"], fresh["mount"])
    except _priv.VerbError:
        return "failed", i18n.Sentence(R17A_UNNAMED_MOUNT)
    if args is None:
        return "failed", i18n.Sentence(R17A_LISTENER_UNREAD)
    out, err, rc = _so._run_verb("tailscale-serve-off", _r24t_off_verb_args(args), timeout=10,
                                 merge_stderr=False)
    with _cache_lock:
        _cache["info"] = None
    if rc != 0:
        return "failed", err or out or "tailscale exited %d" % rc
    return "removed", ""


def _r24t_off_verb_args(args):
    """serve_off_args' `["serve", "--https=443", "--set-path=/x", "off"]` as the verb's arguments.

    `["https", "443", "/x"]`: the listener's scheme and port and the mount, which the helper
    validates and assembles back into the same command.
    """
    scheme, _, port = args[1][2:].partition("=")
    return [scheme, port, args[2][len("--set-path="):]]


def remove_stale_panel_routes(port, mount):
    """Remove the panel's own :443 routes at mounts other than `mount`; return (state, removed, err).

    state is "none" (nothing to remove), "removed" (`removed` lists the mounts), "unread" (Serve
    could not be read, so nothing was removed) or "failed" (`err` is the CLI's text; `removed`
    lists what went before it). Called after every successful Serve write the panel makes, with the
    mount it just wrote, so the panel is published at ONE mount: the boot re-point, Enable on
    /tailscale and both of the setup wizard's writes.

    Each of these wrote one mount and read nothing first. So a panel route at any other mount — the
    wizard's own "/" before it moved to /lgsm, a README `tailscale serve` line, the route an Enable
    at a new mount left behind — stayed on the scheme it was written with, and answered 502 from
    the next flip of the panel's own (a bind change, an update, a restore). The boot re-point still
    said "ok", because the one mount it wrote did work.
    """
    info = get_tailscale_info(force_refresh=True)
    if not info.installed or info.serve_unreadable:
        return "unread", [], ""
    removed = []
    for r in stale_panel_routes(info.serve_config, port, mount):
        state, err = remove_panel_route(r, port)
        if state == "removed":
            removed.append(r["mount"])
        elif state != "gone":
            return state, removed, err
    return ("removed" if removed else "none"), removed, ""


def disable_tailscale_serve(mount, port):
    """Stop publishing the panel over Tailscale Serve/Funnel; return (ok, message).

    `mount` must be one of the panel's own routes (loopback on `port`): asked for a mount that is
    another app's, nothing is touched. Then EVERY route to the panel comes down, not only that one.
    Removing one left the others published while the caller cleared tailscale_mount, so the page in
    use rebuilt its links for a mount Serve no longer had. And Funnel is per listener: a second
    panel route on a Funnel listener stayed on the public internet while the config said Funnel was
    off.

    This ran `tailscale serve --bg --remove <mount>`. --bg exists only in the serve CLI that has no
    --remove (that flag belonged to the 1.34-1.36 alpha CLI), so the command exited 2 ("flag
    provided but not defined: -remove") before doing anything, and every Disable failed —
    including the one meant to take a Funnelled panel back off the internet.

    The mount is validated before it becomes an argument (CodeQL #375, py/command-line-injection:
    a value beginning with "-" would be read by `tailscale` as an OPTION). The host's Serve config
    is then read fresh, and again right before each removal. When nothing proxies the panel at all
    there is nothing to take down, and that is reported as done, so the caller stops re-applying
    Serve at boot.
    """
    try:
        mount = _priv._ts_mount(mount or "/")
    except _priv.VerbError:
        return False, "That isn't a usable mount point."
    info = get_tailscale_info(force_refresh=True)
    if info.serve_unreadable:
        return False, ("Couldn't read this host's Tailscale Serve configuration, so nothing was "
                       "removed.")
    routes = panel_serve_routes(info.serve_config, port)
    # The node's own routes only. One on a Tailscale Service's listener cannot be removed by the
    # panel (remove_panel_route), and its `off` used to land on the node's :443 instead; it is
    # named in the answer, so "removed" is not read as "no longer published".
    ours = [r for r in routes if not r.get("svc")]
    on_svc = _r14a_svc_note(routes)
    if not any(r["mount"] == mount for r in ours):
        return _r14a_nothing_at_mount(ours, mount, on_svc)
    ok, msg = _remove_serve_mappings(ours, port)
    if not ok:
        return False, msg
    with _cache_lock:
        _cache["info"] = None
    return True, i18n.Sentences(i18n.Sentence("Tailscale Serve mapping removed.") if len(ours) == 1
                                else i18n.Sentence("Tailscale Serve mappings removed."),
                                _r12a_funnel_kept_note(info, port), on_svc)


def _r14a_svc_note(routes):
    """A sentence naming the Tailscale Services among `routes` that still publish the panel, else ""."""
    names = sorted({r["svc"] for r in routes if r.get("svc")})
    if not names:
        return ""
    return i18n.Sentence("The panel is still published on the Tailscale Service {names}, which the panel "
                         "does not manage (remove it with `tailscale serve --service=<name> ... off`).",
                         names=", ".join(names))


# Disable's refusal for a mount that is not the panel's: a designed answer about what was asked,
# not a host failure. disable_refused() names it by this template, never by its (translated) words.
_R26J_NOT_AT_MOUNT = "The panel is published at {ours}, not at {mount}, so nothing was removed."


def disable_refused(msg):
    """Whether disable_tailscale_serve's failure `msg` is its designed refusal (nothing asked of the host)."""
    return isinstance(msg, i18n.Sentence) and msg.template == _R26J_NOT_AT_MOUNT


def _r14a_nothing_at_mount(ours, mount, on_svc):
    """Disable's answer when nothing at `mount` proxies the panel; another app's is never touched."""
    if ours:
        return False, i18n.Sentence(_R26J_NOT_AT_MOUNT, ours=ours[0]["mount"], mount=mount)
    if on_svc:
        return True, i18n.Sentences(i18n.Sentence("Tailscale Serve wasn't publishing the panel on this "
                                                  "node, so there was nothing to remove."), on_svc)
    return True, "Tailscale Serve wasn't publishing the panel, so there was nothing to remove."


def _r12a_funnel_kept_note(info, port):
    """A sentence for Disable's answer when Funnel stays on for another app on :443, else "".

    Funnel is per listener: it stays on while another app still holds a mount on :443, and that
    is the other app's setting to change, not the panel's. Said, so "off" is not assumed.
    """
    shared, others = _r12a_listener_funnel(info.serve_config, port)
    if shared and others:
        return i18n.Sentence("Funnel stays on for the :443 listener, which still serves {apps}.",
                             apps=_r15e_apps(others))
    return ""


def _remove_serve_mappings(routes, port):
    """Remove each of the panel's `routes`; return (ok, why) — why only on failure.

    Stops at the first route that cannot be removed, as the caller reports that one.
    """
    for r in routes:
        if _serve_port_flag(r["url"]) is None:
            return False, i18n.Sentence("Couldn't tell which listener {url} is on, so nothing was removed.",
                                        url=r["url"])
        state, err = remove_panel_route(r, port)
        if state == "unread":
            return False, ("Couldn't read this host's Tailscale Serve configuration, so not every "
                           "mapping was removed.")
        if state == "failed":
            return False, i18n.Sentence("Failed to remove: {why}", why=err)
    return True, ""


# A tailnet's MagicDNS name is <host>.<tailnet>.ts.net, and Tailscale's own IPv4 range is the
# CGNAT block 100.64.0.0/10 (its IPv6 is fd7a:115c:a1e0::/48): system_ops._TAILNET_RANGES, the one
# copy the firewall and fail2ban code read, rather than a second one here.
_TS_DNS_RE = re.compile(r"\.ts\.net\Z", re.IGNORECASE)
_TS_NETS = tuple(ipaddress.ip_network(n) for n in _so._TAILNET_RANGES)


def is_tailscale_ip(host):
    """Check if a host/IP looks like a Tailscale address.

    Anchored, and the address halves are parsed rather than prefix-matched. `".taile" in host` is
    an UNANCHORED substring anywhere in the string, so evil.tailed-hosting.example answered True;
    `host.startswith("100.")` is a string prefix, not a range, so 100.telemetry.example.com did
    too — and 100.0.0.1 is a public address outside the CGNAT block. Nothing branches on this
    today (it feeds a display flag on check-peer), which is precisely when a wrong answer is
    cheapest to fix and most likely to become load-bearing later.
    """
    # The bracketed IPv6 form too (see check_peer_reachability): ip_address_or_none parses no
    # brackets, so `[fd7a:115c:a1e0::1]` read as not a Tailscale address.
    host = canonical_host((host or "").strip())
    if not host:
        return False
    if _TS_DNS_RE.search(host):
        return True
    addr = ip_address_or_none(host)
    if addr is None:
        return False
    return any(addr in n for n in _TS_NETS)   # a v4 network holds no v6 address, and back


def suggest_best_bind(port=5000, scheme="http", mount=None):
    """Suggest the best way to expose the panel based on what's available.

    `scheme` is how the panel itself is serving on `port` ("https" when it terminates its own
    self-signed TLS, which is the default) — the direct URLs below are built with it. They were
    hardcoded http://, so the page linked the operator to plain HTTP on a port that only speaks TLS.

    `mount` is the panel's tailscale_mount: the Serve link is the panel's route there when it has
    one. It was the panel's FIRST route, and Tailscale lists "/" first, so a host with a leftover
    "/" route beside the configured /lgsm linked the operator to the leftover — the one answering 502.

    Returns a dict with keys:
      - method: "tailscale-serve", "tailscale-direct", "direct"
      - bind_host: recommended bind address
      - url: URL the user can reach it at
      - description: human-readable explanation
      - note, note_value: the same as a catalog-key sentence and the address it names (the SUGGEST_*
        constants), which the page shows as separate nodes so the sentence can be translated
    """
    info = get_tailscale_info()
    scheme = "https" if scheme == "https" else "http"
    ours = panel_serve_routes(info.serve_config, port)

    if info.running and info.dns_name and ours:
        # Serve is ACTUALLY proxying the panel — bind to localhost and reach it via the ts.net cert.
        # (We must confirm Serve is configured, not just that Tailscale is up with a MagicDNS name —
        # otherwise a fresh Tailscale-enabled install would bind loopback with nothing proxying to it
        # and be unreachable.) And "configured" means a route to THIS panel's port: any mapping used
        # to count, so a node already serving Grafana bound a fresh panel to 127.0.0.1 with nothing
        # proxying to it, and the first-run wizard — the only way to create the first admin — was
        # reachable only through an SSH tunnel. app._resolved_bind uses this as the real bind
        # address whenever bind_host is unset, which it is until the wizard's first step.
        return _serve_suggestion(port, _suggested_route(info.serve_config, port, mount, ours))
    elif info.running and info.tailscale_ips:
        # Tailscale running but no MagicDNS
        return _tailnet_ip_suggestion(port, scheme)
    elif info.installed and info.backend_state == "NeedsLogin":
        # Installed but never authorized — the recommendation is to finish linking, not to
        # open the panel to all interfaces.
        return _direct_suggestion(port, scheme, SUGGEST_NOT_LINKED)
    else:
        return _direct_suggestion(port, scheme, SUGGEST_NO_TAILSCALE)


# What the Tailscale page says about each suggestion: `note`, a catalog key the page's translator
# swaps whole, then `note_value` (the address, verbatim) in an element of its own. `description`
# stays for the API; it is the same sentence with the value spliced in, which is why the page could
# not show it: one text node no catalog key matches, so it was English in every language.
SUGGEST_SERVE = "Bind to localhost and expose the panel through Tailscale Serve at:"
SUGGEST_TAILNET_IP = "Bind to this machine's Tailscale IP and open the panel directly at:"
SUGGEST_NOT_LINKED = ("Tailscale is installed but not linked yet. Link this machine above to reach "
                      "the panel privately over your tailnet.")
SUGGEST_NO_TAILSCALE = "No Tailscale detected. Bind to all interfaces."


def _suggested_route(serve_config, port, mount, ours):
    """The panel's route at `mount` when it has one there, else the first of `ours`."""
    hit = panel_route(serve_config, port, mount) if mount is not None else None
    return hit if hit is not None else ours[0]


def _serve_suggestion(port, route):
    """suggest_best_bind's answer when the Serve `route` proxies the panel."""
    url = route_url(route)
    return {
        "method": "tailscale-serve",
        "bind_host": "127.0.0.1",
        "port": port,
        "url": url,
        "description": f"Bind to localhost and expose via Tailscale Serve at {url}",
        "note": SUGGEST_SERVE, "note_value": url,
    }


def _tailnet_ip_suggestion(port, scheme):
    """suggest_best_bind's answer when Tailscale runs with no Serve route to the panel."""
    ts_ip = get_tailscale_ip(4)
    # get_tailscale_ip falls back to the node's IPv6 address when it has no IPv4 one (a tailnet
    # with IPv4 disabled), and a URL needs that one in brackets: http://fd7a:…::1:5000 opens nothing.
    host = "[%s]" % ts_ip if ts_ip and ":" in ts_ip else ts_ip
    return {
        "method": "tailscale-direct",
        "bind_host": ts_ip or "0.0.0.0",  # nosec B104 - a suggestion shown to the operator, not a bind
        "port": port,
        "url": f"{scheme}://{host}:{port}" if ts_ip else f"{scheme}://<tailscale-ip>:{port}",
        "description": f"Bind to Tailscale IP {ts_ip} and access directly",
        "note": SUGGEST_TAILNET_IP,
        "note_value": f"{scheme}://{host}:{port}" if ts_ip else "",
    }


def _direct_suggestion(port, scheme, description):
    """suggest_best_bind's answer when the panel is reached directly: all interfaces."""
    return {
        "method": "direct",
        "bind_host": "0.0.0.0",  # nosec B104 - a suggestion shown to the operator, not a bind
        "port": port,
        "url": f"{scheme}://<your-server-ip>:{port}",
        "description": description,
        "note": description, "note_value": "",
    }
