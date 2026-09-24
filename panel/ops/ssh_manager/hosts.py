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
    # Only a READING gets memoised. _compute_pro_status tells "could not read" apart from "not
    # installed" now, but this line cached either for _PRO_STATUS_TTL — a day — so one timed-out
    # read of a rebooting host (the tailscale/local transports return ("", "…timed out", -1)
    # instead of raising) pinned "Ubuntu Pro status unknown" onto its card until the panel
    # restarted. The host being back up seconds later changed nothing, because nothing re-probed:
    # only attach/detach/service invalidate this, and the page never sends force. A read that
    # never happened is not an answer to remember, so leaving the memo empty is what makes the
    # next page load ask again — same guard as remote_uptime's `if server is not None and out`
    # and host_specs' "cache only a good read; a transient failure retries next time".
    if not result.get("unreadable"):
        _pro_status_cache[key] = (now + _PRO_STATUS_TTL, result)
    return result


def _compute_pro_status(server):
    """Run `pro status` and shape the result. Returns installed/attached plus the featured
    security services and their enabled/disabled state."""
    import json
    # Three answers, not two. The comment here used to say "the check below already treats
    # anything that is not JSON as 'not installed', so the rc can just be ignored" — and that is
    # the assumption: it makes a read that never happened indistinguishable from a host without
    # Ubuntu Pro. On the tailscale and local transports a timed-out command does not raise, it
    # returns ("", "…timed out", -1), so the common failure produced "Ubuntu Pro is not installed"
    # about a host that was never asked.
    #
    # That is not a passing glitch: _pro_status_cached PERSISTS this to the database and serves it
    # for _PRO_MAX_AGE (a day), across restarts.
    #
    # rc 127 / "not found" IS a reading — `pro` is genuinely absent — and keeps the old answer.
    out, err, rc = _core.run_privileged(server, "pro-status", [], timeout=25, merge_stderr=False)
    _txt = (out or "") + (err or "")
    if rc == 127 or "not found" in _txt or "No such file" in _txt:
        return {"installed": False, "attached": False, "services": []}
    if not out.strip() or not out.strip().startswith("{"):
        return {"installed": False, "attached": False, "services": [], "unreadable": True}
    try:
        data = json.loads(out)
    except Exception:
        # Bytes that start with '{' and then fail to parse are the same non-reading as the branch
        # above, arriving through a second door: output truncated by run_command's 2 MiB cap, a
        # warning line glued onto the JSON, a stream cut off mid-object. This used to answer
        # {"installed": True, "attached": False, "error": …} — two positive claims read out of
        # text nobody could read, and no `unreadable` key, so pro_status memoised it for
        # _PRO_STATUS_TTL and _pro_status_cached persisted it to the database. `error` is
        # rendered nowhere, so what the operator saw for a day was "Not attached" plus the
        # attach-token pitch on a host that may be fully attached. Flagging it unreadable is what
        # keeps it out of both caches and makes the next page load ask the host again.
        return {"installed": False, "attached": False, "services": [], "unreadable": True,
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

    ufw stops at the FIRST rule a connection matches, so a limit only works when nothing that
    allows the port sits above it. `ufw limit N/tcp` rewrites an existing `N/tcp` allow in place.
    A BARE `N` allow (tcp+udp — how the panel opens every game port) is a different rule to ufw:
    it used to be left where it was, ahead of the appended limit, and this reported the port
    limited while every connection matched the allow. That allow is now split — the other
    protocol re-allowed with its comment, the bare rule removed — and the result is READ BACK:
    success means the first rule for N/proto is the LIMIT."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto not in ("tcp", "udp"):
        # `ufw limit` takes one rule; "both" would need two and they would report separately.
        return False, "Rate limiting needs a single protocol (tcp or udp)"
    spec = "%d/%s" % (port, proto)
    before, _, brc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15)
    before = (before or "") if brc == 0 else ""
    if not limit:
        # "Remove the rate limit", not "close the port": the LIMIT rule is what lets N/proto in,
        # and deleting it closed a port the operator only wanted un-throttled — including the
        # half of a game port the split below moved onto it. `ufw allow N/proto` rewrites the
        # LIMIT in place. Only when there IS one: otherwise this would open a closed port.
        if brc != 0:
            return False, ("Could not read the firewall to find the rate limit on %s, so nothing "
                           "was changed." % spec)
        # An inactive ufw lists NO rules, stored ones included, so the test below found none and
        # answered "has no rate limit to remove" about a host whose stored rules hold one.
        if not firewall._ufw_is_active(before):
            return False, ("UFW is not active on this host, so its stored rules cannot be read "
                           "here to find the rate limit on %s — nothing was changed." % spec)
        if not any(r["to"] == spec and r["action"] == "LIMIT" for r in _ufw_public_rules(before)):
            return False, "%s has no rate limit to remove." % spec
        out, err, rc = _core.run_privileged(server, "ufw-allow-port", [spec, ""], timeout=15)
        if rc == 0:
            return True, "Rate limit removed from %s (it stays open)" % spec
        return False, err or out or "Unknown error"
    out, err, rc = _core.run_privileged(server, "ufw-limit-port", [spec], timeout=15)
    if rc != 0:
        return False, err or out or "Unknown error"
    # A bare allow for this port covers BOTH protocols and matches ahead of the limit. Keep the
    # other protocol open under the same comment, THEN drop the bare rule (this protocol is
    # already covered by the limit above, so nothing is ever left unallowed).
    other = "udp" if proto == "tcp" else "tcp"
    split, unsplit = False, ""
    for r in _ufw_public_rules(before):
        if r["to"] == str(port) and r["action"] == "ALLOW":
            _cmt = re.sub(r"[^A-Za-z0-9 _.-]", "", r["comment"])[:60]
            o_out, o_err, o_rc = _core.run_privileged(
                server, "ufw-allow-port", ["%d/%s" % (port, other), _cmt], timeout=15)
            # ...and ONLY once it is. Its exit code was ignored, so when the re-allow failed (the
            # timeout, on a ufw slowed by hundreds of auto-block rules) the bare rule went anyway:
            # the other protocol closed — gameplay, on a Source-style server — and the read-back,
            # which looked at the limited protocol only, answered "now rate limited". Now the bare
            # rule stays, and the read-back decides whether the limit is reached anyway.
            if o_rc != 0:
                unsplit = (" The panel could not split it: re-opening %d/%s on its own failed (%s), "
                           "so the rule opening both was left in place."
                           % (port, other, (o_err or o_out or "exit %s" % o_rc)
                              .replace("\n", " ").strip()[:120]))
                break
            _core.run_privileged(server, "ufw-delete-allow-port", [str(port)], timeout=15)
            split = True
            break
    after, _, arc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15)
    # Unread is a failed call or an empty answer — NOT a missing English "Status:". ufw translates
    # that whole line (`État : actif`), so on a French or Spanish host a limit that fully applied,
    # bare rule split and all, came back as "could not be read back". Active or not, in any
    # locale, is _ufw_is_active's question, one line down.
    if arc != 0 or not (after or "").strip():
        return False, ("The limit for %s was added, but the firewall could not be read back to "
                       "confirm it is the rule connections meet first." % spec)
    if not firewall._ufw_is_active(after):
        return False, ("The limit for %s is stored, but UFW is not active on this host, so "
                       "nothing is limited until it is enabled." % spec)
    first = _ufw_first_public_rule(after, port, proto)
    if first is None or first["action"] != "LIMIT":
        return False, ("%s is still matched first by `%s`, so the limit is never reached — remove "
                       "or narrow that rule.%s" % (spec, first["detail"] if first else "nothing",
                                                   unsplit))
    if split:
        # The split must not have closed what the bare rule kept open for the other protocol.
        o_was = _ufw_first_public_rule(before, port, other)
        o_now = _ufw_first_public_rule(after, port, other)
        if (o_was and o_was["action"] in ("ALLOW", "LIMIT")
                and not (o_now and o_now["action"] in ("ALLOW", "LIMIT"))):
            return False, ("%s is now rate limited, but %d/%s is no longer open — re-open it from "
                           "the Firewall page." % (spec, port, other))
    return True, "%s is now rate limited (6 connections per 30s per address)" % spec


# `To` column of a port rule: a port or lo:hi range, optionally /tcp or /udp (none = both).
_UFW_TO_PORT_RE = re.compile(r"^(\d{1,5})(?::(\d{1,5}))?(?:/(tcp|udp))?\Z")


def _ufw_public_rules(status_out):
    """The IPv4 rules in `ufw status [numbered]` output that govern traffic from ANYWHERE —
    inbound, on no particular interface — in the order ufw evaluates them. Each is
    _parse_ufw_rule's dict plus its `detail` text. Source-restricted rules, interface rules and
    the (v6) twins are left out: none of them decides what the public meets first."""
    rules = []
    for line in (status_out or "").splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s*(.*)\Z", line)
        detail = (m.group(1) if m else line).strip()
        p = firewall._parse_ufw_rule(detail)
        if (not p["action"] or p["v6"] or p["iface"] or p["direction"] not in ("", "IN")
                or p["from"].lower() != "anywhere"):
            continue
        p["detail"] = re.sub(r"\s{2,}", "  ", detail)
        rules.append(p)
    return rules


def _ufw_first_public_rule(status_out, port, proto):
    """The first public rule a `proto` connection to `port` meets, or None."""
    for p in _ufw_public_rules(status_out):
        m = _UFW_TO_PORT_RE.match(p["to"])
        if m and int(m.group(1)) <= port <= int(m.group(2) or m.group(1)) and m.group(3) in (None, proto):
            return p
    return None


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
        # The guard reads the firewall to find out which rules are load-bearing. If that read
        # FAILS it returns no groups — and iterating nothing marked nothing protected, so every
        # rule became deletable, including the one keeping SSH or the tailnet open. The old
        # `except` said as much out loud ("don't let the safety check itself block a legitimate
        # delete on error"), which is the wrong trade for a guard whose entire job is preventing a
        # lockout: "I could not check" is not "it is safe".
        #
        # So an unverifiable firewall refuses, and says how to proceed. force=True remains the
        # deliberate override — the caller has to mean it.
        try:
            status = firewall.remote_ufw_status(server)
        except Exception:
            _core._log.warning("ufw delete: the safety check could not read the firewall",
                               exc_info=True)
            status = None
        if status is None or status.get("unreachable"):
            return False, ("Couldn't read the firewall to check whether rule %d is the one "
                           "keeping your access open, so this refuses rather than risk locking "
                           "you out. Check the host is reachable and try again." % n)
        if not status.get("installed"):
            # A different answer, not the same failure: UFW genuinely is not here, so there is no
            # rule numbered anything and the delete would fail regardless. Say that rather than
            # send someone checking a connection that is fine.
            return False, "UFW isn't installed on this host, so there's no rule %d to delete." % n
        for g in status.get("groups", []):
            if n in g.get("nums", []) and g.get("protected"):
                return False, g.get("protect_reason") or \
                    "This rule protects your access to the host and can't be removed here."
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
    # `.get()`, not `key in` — a membership test made a FAILED read a cache HIT. The read below is
    # guarded (`rc == 0 and 3 < len(cand) < 24`), so a timed-out /etc/os-release leaves slug None —
    # and this then stored that None in a cache with no TTL, so it was returned for the life of the
    # process and nothing but deleting the host cleared it. None flows to deps_for_game →
    # _load_deps_csv → lgsm_data.deps_name(None), which falls back to ubuntu-24.04.csv: a Debian 12
    # box got Ubuntu's package list, and apt-get install is atomic, so one nonexistent package
    # aborted the whole batch on every install from then on.
    cached = _OS_SLUG_CACHE.get(key)
    if cached:
        return cached
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
    if slug:      # never memoise a failed read — a retry must be able to win
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
    pkgs = _apt_pkgs(base.split() + extra_pkgs)

    # ── one shell pipeline -> a sequence of verbs ────────────────────────────────────────────
    # This ran as `run_command(pipeline, sudo=True)`, which on the panel's own host becomes
    # `sudo bash -c '<pipeline>'`. The narrow sudoers grant install.sh writes permits the helper
    # and becoming a game account, and NEITHER covers that — so on the install the panel calls
    # hardened, step 3 of "Install Server" was refused outright. Measured on a test host, as the
    # panel user: `sudo -n bash -c 'apt-get install -y --dry-run ca-certificates'` answered
    # "sudo: a password is required". The call site swallowed it in a bare `except`, so the
    # install carried on and failed later looking like a download problem.
    #
    # Every step already had a verb or needed a small one. Nothing here builds a command string.
    def _verb(name, args=(), timeout=120, **kw):
        return _core.run_privileged(server, name, list(args), timeout=timeout, **kw)

    # i386 for SteamCMD and the 32-bit game runtimes; universe+multiverse for libstdc++5:i386
    # and steamcmd. All three are idempotent and non-fatal — a box that already has them, or a
    # distro without `add-apt-repository`, must not fail the whole dependency step.
    _verb("dpkg-add-arch", ["i386"], timeout=120, merge_stderr=False)
    for _repo in ("universe", "multiverse"):
        _verb("apt-add-repo", [_repo], timeout=120, merge_stderr=False)
    _verb("apt-update", [], timeout=300, merge_stderr=False)

    steam_ok = True
    if needs_steamcmd:
        _s_out, _s_err, _s_rc = _verb("steamcmd-install", [], timeout=1800)
        steam_ok = (_s_rc == 0)
        if not steam_ok:
            _core._log.warning("steamcmd install failed: %s", (_s_err or _s_out or "")[:200])

    if not pkgs:
        return steam_ok, "no dependencies to install"

    # apt-get install is ATOMIC — one unavailable package aborts the batch — so a failed batch
    # falls back to one at a time, which is what the shell `|| for p in …` loop did. Chunked
    # because the verb table caps a Rest() argument list, and a game's list plus the common set
    # plus retries can be long.
    def _chunks(seq, size=48):
        for i in range(0, len(seq), size):
            yield seq[i:i + size]

    out, err, rc = "", "", 0
    for chunk in _chunks(pkgs):
        c_out, c_err, c_rc = _verb("apt-install-minimal", chunk, timeout=1800)
        out, err = (out + (c_out or ""))[-4000:], (err + (c_err or ""))[-2000:]
        if c_rc != 0:
            rc = c_rc
            for one in chunk:
                _verb("apt-install-minimal", [one], timeout=600, merge_stderr=False)

    # rc now reports the BATCH. It used to report `echo deps-done`, the last command in the
    # pipeline, so this function returned True however badly the install had gone — which is the
    # other half of why a refused step never surfaced.
    return (rc == 0 and steam_ok), (out or err or "")


# Which classified causes a RETRY cannot get past. Only one: the rest are all "do this, then try
# again", and their own messages say so — free a dump slot, put a Steam account in the config, or
# let the panel run the two-step Windows-prime workaround. Marking those non-retryable takes the
# Retry button away from the person the message just told to press it.
#
# os_unsupported is different in kind: LinuxGSM caps the game at an older release than the host
# runs, and nothing the operator does on this host changes that answer.
INSTALL_FAILURE_FINAL = frozenset({"os_unsupported"})


def classify_install_failure(output):
    """Why a LinuxGSM install failed, as (code, message), or None when nothing is recognised.

    The panel used to answer every failed install with "the download may be corrupt or the mirror
    unreachable. Try again shortly.", after retrying three times. For the three causes below that
    advice is wrong and the retries cannot help: nothing about a second download changes whether
    the account owns the game or whether Steam has a crash-dump slot left.

    `code` is for the caller's retry decision, `message` is for the operator:

      steam_dumps   Steam's ten /tmp/dumps slots are all held by live accounts. Sweep first; this
                    is what is left when the sweep freed nothing.
      steam_login   the game is not downloadable anonymously — it needs a Steam account that owns
                    it, set in the server's LinuxGSM config.
      steam_platform  SteamCMD refused the app with "Invalid platform". A SteamCMD bug rather
                    than a missing Linux build — the two-step install below gets past it, so this
                    one IS retryable, unlike the other two.
      os_unsupported  LinuxGSM caps this game at an older Ubuntu than the host runs.

    Deliberately NOT classified: "Not enough disk space". LinuxGSM prints that for SteamCMD app
    state 0x202, which it is not — 0x202 came back on this host for games the account had no
    licence for, with 27 GB free. Repeating a wrong diagnosis with more confidence is worse than
    the generic message, so 0x202 alone stays generic and only the unambiguous lines are named.
    """
    text = terminal.strip_escapes(output or "")
    low = text.lower()
    # Bandit's hard-coded-/tmp rule: this is a substring of SteamCMD's error text being matched,
    # not a path anything here opens or writes.
    if "please delete some /tmp/dumps" in low or "/tmp/dumps* directories" in low:   # nosec B108
        return ("steam_dumps", (
            "Steam keeps only ten crash-dump slots on a host (/tmp/dumps … /tmp/dumps09), one per "
            "Linux account, and every one of them is in use by a game account that still exists. "
            "SteamCMD cannot run at all until one is freed — remove a game server you no longer "
            "need, or delete one of those directories on the host."))
    if "steam login not set" in low or 'change steamuser="username"' in low \
            or "no license" in low or "no subscription" in low:
        return ("steam_login", (
            "This game is not downloadable with an anonymous Steam login — it needs an account "
            "that owns it. Put a Steam username and password in the server's LinuxGSM config "
            "(steamuser / steampass) and install again."))
    if "invalid platform" in low:
        # NOT "Steam dropped Linux support", which is what this looks like and what the panel said
        # at first. It is a SteamCMD bug, and LinuxGSM's maintainer found the way through it in
        # GameServerManagers/LinuxGSM#4754 (still open, last touched 2026-05-03):
        #
        #   "The fix is to add steamcmdforcewindows=yes into common.cfg, run the installer and
        #    then remove steamcmdforcewindows=yes then validate. This will download the windows
        #    depot then download the linux depot to get the binary. Once done it works. This is
        #    definitely a bug with SteamCMD"                      — dgibbs64, 2025-06-22
        #
        # Which matches what the app metadata says: app 222860 has BOTH depots (222862 windows,
        # 222863 linux) and one launch entry, oslist=windows. SteamCMD checks the launch entry and
        # refuses; priming it with the Windows depot gets it past that, and the validate afterwards
        # pulls the Linux binaries it should have fetched in the first place.
        #
        # So the honest answer is "this needs a two-step install", not "give up" — and the panel
        # does that itself rather than making an operator follow a GitHub thread.
        return ("steam_platform", (
            "SteamCMD refused this game with \"Invalid platform\" — a known SteamCMD bug, not a "
            "problem with this host: the game does have a Linux server. The way through it is to "
            "prime the download with the Windows depot and then validate, which pulls the Linux "
            "binaries. The panel does that automatically on a retry."))
    m = re.search(r"is not supported on ([^\r\n(]{3,60})", text)
    if m:
        return ("os_unsupported", (
            "LinuxGSM does not support this game on %s. It caps this one at an older Ubuntu "
            "release; the game picker marks those." % m.group(1).strip()))
    return None


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
    """Reboot the remote server. (ok, msg).

    A reboot is the one command whose SUCCESS looks like a failure: the host goes down mid-command,
    so the transport reports a dropped connection. That is why this returned True unconditionally,
    and why it must not simply start failing on non-zero — `rc == 0` would reject most real
    reboots.

    What it CAN tell apart is a refusal, which comes back promptly and positively: sudo declining
    ("a password is required"), an unknown verb, a helper that is not installed. `_core` uses -1 for
    "the transport gave up" (a timeout or a dropped connection), so a POSITIVE rc is the helper
    having answered and said no. Only that is reported as a failure.

    It matters because both callers use the boolean: panel/routes/remote_vps.py hands it to the
    operator, and monitoring._reboot_when_empty_watch writes it as `success=ok` on the audit row —
    so a refused auto-reboot was recorded as a reboot that happened, on a host that never went
    down."""
    out, err, rc = _core.run_privileged(server, "reboot", [], timeout=10)
    if rc is not None and rc > 0:
        return False, ((out or err or "Reboot refused").replace("\n", " ")[:200])
    return True, "Reboot command sent to remote"


def remote_reboot_required(server):
    """Whether a host needs a reboot to finish applying updates. Debian/Ubuntu drop
    /var/run/reboot-required after a kernel/libc upgrade, and list the responsible packages in
    /var/run/reboot-required.pkgs. Works for the panel host too (run_command runs it locally when
    the server is is_local). Returns {'required': bool, 'packages': [str, ...], 'known': bool}.

    `known` is False when the probe did not answer, and it is not decoration: `required: False`
    with `known: False` means "we could not look", which is a different fact from "this host does
    not need a reboot" and must not retract a banner an earlier successful poll put up."""
    # A NEGATIVE sentinel was the whole bug: `"YES" not in out` is True of "" as well, and the
    # tailscale and local transports return ("", "SSH command timed out", -1) WITHOUT raising —
    # so a probe that never ran was published as the definite answer "no reboot needed", and the
    # kernel-update nag on an unpatched host disappeared. Require one of the probe's OWN two
    # tokens plus rc 0, the way remote_bootstrap_vps requires EXISTS/NOTEXISTS below.
    try:
        out, _, rc = _core.run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=12)
    except Exception:
        return {"required": False, "packages": [], "known": False}
    text = out or ""
    if rc != 0 or not ("YES" in text or "NO" in text):
        _core._log.debug("reboot-required probe did not answer (rc=%s)", rc)
        return {"required": False, "packages": [], "known": False}
    if "YES" not in text:
        return {"required": False, "packages": [], "known": True}
    packages = []
    try:
        pk, _, _ = _core.run_command(server, "cat /var/run/reboot-required.pkgs 2>/dev/null", timeout=12)
        packages = sorted({p.strip() for p in (pk or "").splitlines() if p.strip()})
    except Exception:
        packages = []
    return {"required": True, "packages": packages, "known": True}


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
    # Say plainly whether the host actually answered. The dict is otherwise indistinguishable
    # from a real reading of a very quiet machine — "unknown"/"?" are also what a SUCCESSFUL parse
    # produces for a field it could not find — and callers that persist it need to tell the two
    # apart. This flag is what the cache guard below has always keyed on; it is now visible.
    d["read_ok"] = bool(out)
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
    ufw_not_enabled = None
    if enable_ufw:
        emit("Configuring UFW firewall (deny incoming, rate-limit SSH)")
        # Rate-limit SSH by default — `ufw limit` allows SSH (so we never lock ourselves
        # out) while throttling brute-force sources. We do NOT add a plain `allow 22`:
        # a lower-numbered allow rule would match first and shadow the limit, leaving SSH
        # effectively unthrottled.
        _l_out, _l_err, _l_rc = _core.run_privileged(server, "ufw-limit-port", ["22/tcp"], timeout=15)
        if _l_rc == 0:
            # The same goes for `ufw allow OpenSSH` / a bare `ufw allow 22` already on the host:
            # to ufw neither is the `22/tcp` rule above, so the limit is appended AFTER them and
            # never reached. Removed only now that the limit is in place, so SSH is never left
            # unallowed.
            for _verb, _args in _SSH22_SHADOWING:
                _core.run_privileged(server, _verb, _args, timeout=15)
            _core.run_privileged(server, "ufw-default", ["deny", "incoming"], timeout=15)
            _core.run_privileged(server, "ufw-default", ["allow", "outgoing"], timeout=15)
            _core.run_privileged(server, "ufw-enable", [], timeout=15)
        else:
            # The limit's exit code was never read, so when it failed the rules that DO let SSH in
            # were deleted "now that the limit is in place" and UFW was switched on at deny-incoming
            # — a fresh host cut off from SSH mid-bootstrap. Nothing is removed and the firewall is
            # left as it was; the job says so rather than "complete".
            ufw_not_enabled = ((_l_err or _l_out or "exit %s" % _l_rc)
                               .replace("\n", " ").strip()[:160])
            note("NOT DONE: `ufw limit 22/tcp` failed (%s). UFW was left as it was — turning it on "
                 "without a rule letting SSH in would lock this host out." % ufw_not_enabled)

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
    # The write is not the result. Ubuntu's sshd_config Includes sshd_config.d/*.conf at its top
    # and sshd keeps the FIRST value it reads, so on a cloud image whose 50-cloud-init.conf says
    # `PasswordAuthentication yes` the edit above changes nothing — and this step used to discard
    # every tuple and say nothing, so the log read "Hardening SSH configuration … VPS bootstrap
    # complete" about a host still taking password logins from the internet. Ask sshd what it will
    # actually use (`sshd -T` parses the config; no restart needed) and say so when it disagrees.
    hardening_failed = []
    _unapplied, _readable = _sshd_unapplied_directives(server, hardening)
    # Unknown is not "applied": the final message carries it, rather than a bare "complete".
    hardening_unverified = (not _readable) and server.auth_method != "password"
    if not _readable:
        note("Could not read sshd's effective configuration to confirm the SSH hardening took "
             "effect — check `sshd -T` on the host.")
    for _key, _want, _got in _unapplied:
        note("NOT IN EFFECT: sshd reports %s as '%s', not '%s' — something it reads first "
             "overrides the edit (usually a file in /etc/ssh/sshd_config.d)."
             % (_key, _got or "unset", _want))
        if _key in _SSHD_SECURITY_DIRECTIVES:
            hardening_failed.append((_key, _got or "unset"))
    if any(k == "PasswordAuthentication" for k, _ in hardening_failed):
        note("Password SSH login is still ENABLED on this host.")
    if server.auth_method != "password":
        _core._restart_sshd(server, timeout=15)
    else:
        note("Password + root-password SSH login left ENABLED — this remote authenticates with a password, so SSH access was not restricted.")

    # ── 7. Create swap if none exists ──
    emit("Ensuring swap space exists")
    # `== "0"` alone is an unread probe reported as "Swap already present": run_command returns
    # ("", "...timed out", -1) rather than raising, and "" is not "0", so a host that never
    # answered was recorded as having swap and never got any. Read the rc and require a NUMBER.
    swap_out, _, _swap_rc = _core.run_command(server, "swapon --show | wc -l", timeout=10)
    _swap_txt = (swap_out or "").strip()
    if _swap_rc == 0 and _swap_txt.isdecimal():
        if _swap_txt == "0":
            _core.run_privileged(server, "create-swapfile", [], timeout=60, merge_stderr=False)
            note("2G swap file created")
        else:
            note("Swap already present")
    else:
        # Not "no swap" — unknown. Creating one anyway on a host that has some would waste 2G of
        # disk on the very box whose disk we could not read, so say so and leave it.
        note("Could not check for swap on this host — left alone. Check it from the host's page.")

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
        # Same correction: an unread probe is not "the account is already there". Reading it that
        # way SKIPPED the account creation below, and the bootstrap then carried on against a user
        # that does not exist.
        if "NOTEXISTS" not in out and "EXISTS" in out:
            note(f"User {username} already exists")
        else:
            _core.create_game_user(server, username, timeout=15)
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
        # Both probes are read for rc AND for one of their own two answers, because run_command
        # does not raise: a dropped connection returns ("", "...timed out", -1), and `"YES" in ""`
        # is False. Read that way the second probe answered "no game servers are running" about a
        # host it never reached — and this is the branch that REBOOTS. An unread probe now means
        # unknown, and unknown skips the reboot.
        reboot_req, _, _rb_rc = _core.run_command(
            server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=10)
        _rb_txt = reboot_req or ""
        reboot_known = _rb_rc == 0 and ("YES" in _rb_txt or "NO" in _rb_txt)
        needs_reboot = reboot_known and "YES" in _rb_txt
        gs_out, _, _gs_rc = _core.run_command(server, "if pgrep -x tmux >/dev/null 2>&1 || pgrep -x SCREEN "
                                   ">/dev/null 2>&1; then echo YES; else echo NO; fi", timeout=10)
        _gs_txt = gs_out or ""
        gs_known = _gs_rc == 0 and ("YES" in _gs_txt or "NO" in _gs_txt)
        # Unknown counts as running. The cost of being wrong that way is a reboot the operator
        # does by hand; the other way it is every player on the box disconnected mid-bootstrap.
        servers_running = (not gs_known) or "YES" in _gs_txt
        if not reboot_known:
            emit("Could not check whether a reboot is needed", status="reboot-required",
                 detail="The host did not answer the reboot-required check, so this was left "
                        "alone. Check it from the host's page.")
        elif not needs_reboot:
            emit("No reboot needed", detail="Updates applied without requiring a reboot.")
        elif servers_running or not do_reboot:
            emit("Reboot required — skipped to protect running servers", status="reboot-required",
                 detail=("A kernel/library update needs a reboot. Reboot this host from its page "
                         "once its game servers are empty.") if gs_known else
                        ("A kernel/library update needs a reboot. The host did not answer the "
                         "check for running game servers, so it was not rebooted — a reboot "
                         "would drop any players on it. Reboot it from its page once you know "
                         "it is empty."))
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

    # The same reasoning for a firewall that was asked for and not switched on: a door left open.
    ufw_msg = (("the firewall was NOT enabled: `ufw limit 22/tcp` failed (%s), and turning UFW on "
                "without a rule letting SSH in would have locked this host out. Fix ufw on the "
                "host and run the bootstrap again." % ufw_not_enabled) if ufw_not_enabled else "")
    if hardening_failed:
        # Not "complete": the one step whose whole point is closing a door reported the door is
        # still open. The rest of the work did happen, and the message says both.
        return False, ("Bootstrap finished, but the SSH hardening did not take effect: sshd "
                       "still reports %s. Something sshd reads first overrides the edit — look "
                       "in /etc/ssh/sshd_config.d (cloud images ship 50-cloud-init.conf)."
                       % "; ".join("%s %s" % kv for kv in hardening_failed)
                       + (" And " + ufw_msg if ufw_msg else "")), "\n".join(log)
    if ufw_msg:
        return False, "Bootstrap finished, but " + ufw_msg, "\n".join(log)
    if progress:
        try:
            progress(total, total, "Bootstrap complete", "done")
        except Exception:
            _core._log.debug("remote_bootstrap_vps: ignored non-fatal error", exc_info=True)
    if hardening_unverified:
        return True, (f"VPS bootstrap complete ({step}/{total} steps), but the SSH hardening could "
                      "not be verified — sshd's effective configuration was unreadable. Check "
                      "`sshd -T` on the host for passwordauthentication."), "\n".join(log)
    return True, f"VPS bootstrap complete ({step}/{total} steps).", "\n".join(log)


# ─── Remote Tailscale Bootstrap ─────────────────────────────


def remote_check_tailscale(server):
    """Check if Tailscale is already installed and running on the remote."""
    installed_out, _, installed_rc = _core.run_command(server, "which tailscale 2>/dev/null && echo 'INSTALLED' || echo 'NOTINSTALLED'", timeout=10)
    # BOTH halves, and the same shape manage_servers.py already uses for its `id` probe:
    # `"NOTEXISTS" not in idout and "EXISTS" in idout`. A bare negative test reads an EMPTY answer
    # as the positive one — "NOTINSTALLED" is not in "", so a probe that never ran said Tailscale
    # IS installed. run_command returns ("", "...timed out", -1) rather than raising for the local
    # and Tailscale transports, so that is the ordinary unreachable case, not a rare one.
    installed = ("NOTINSTALLED" not in installed_out    # "INSTALLED" is a substring of it
                 and "INSTALLED" in installed_out)

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

    # 3. Enable UFW for Tailscale if UFW is active — or if we could not tell.
    #
    # _ufw_is_active("") is False, and an unread status is the ordinary way to get "". Skipping
    # the allow on a host whose firewall IS active is how the panel loses the tailnet it just
    # brought up: the rule is what keeps tailscale0 reachable. `ufw allow in on tailscale0` is
    # idempotent and does nothing at all while UFW is inactive, so adding it on an unknown
    # answer costs nothing and not adding it can cost the host.
    ufw_out, _, _ufw_rc = _core.run_privileged(server, "ufw-status", ["plain"], timeout=10)
    _ufw_known = _ufw_rc == 0 and bool((ufw_out or "").strip())
    if firewall._ufw_is_active(ufw_out) or not _ufw_known:
        _core.run_privileged(server, "ufw-allow-iface", ["tailscale0"], timeout=15)
        log.append("UFW: allowed tailscale0 interface"
                   if _ufw_known else
                   "UFW: status could not be read — allowed tailscale0 anyway (no-op if UFW is off)")

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

    # Do not burn the bridge until the new one carries weight.
    #
    # This closed port 22 and let the caller blank auth_credential — the record's ONLY credential —
    # on the strength of BackendState == Running. That says tailscaled is up. It says nothing about
    # whether this node runs Tailscale SSH, and nothing about whether the panel can actually log in
    # that way. With RunSSH off, or a tailnet ACL that does not permit SSH to this node/user, the
    # panel had just closed the only door and thrown away the key, with no way back from the UI.
    #
    # Both checks already live in this module; neither was called from here.
    _running, _ssh_enabled = _tailscale_conn_state(server)
    if not _ssh_enabled:
        return None, ("Tailscale is running on this host, but its SSH server is not enabled, so "
                      "the panel would have no way back in once port 22 is closed. Run "
                      "`tailscale set --ssh` on the host, then try again.")
    _login_ok, _login_msg = ssh_test_connection(new_host, 22, server.username,
                                                auth_method="tailscale")
    if not _login_ok:
        return None, ("Tailscale SSH did not work from here, so the migration stopped before "
                      "changing anything: %s" % _login_msg)

    # Verified: the tailnet really is a way in. NOW the public door can close.
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


# The hardening directives whose failure leaves a door open, as opposed to the keepalive pair.
_SSHD_SECURITY_DIRECTIVES = frozenset({"PermitRootLogin", "PasswordAuthentication"})
# `sshd -T` prints one canonical name per value, and which one has changed between OpenSSH
# releases: PERMIT_NO_PASSWD dumps as `without-password` on older sshd and `prohibit-password` on
# current ones. Both are the same setting.
_SSHD_VALUE_ALIASES = {"without-password": "prohibit-password"}
# A directive whose values are ORDERED, least to most restrictive: any value at least as strict as
# the one the panel sets does what the hardening is for. Compared for equality, a host with
# `PermitRootLogin no` in sshd_config.d — stricter than the panel asks — read as "hardening did not
# take effect", and the bootstrap FAILED on it. PasswordAuthentication has only `no` to accept.
_SSHD_VALUE_ORDER = {"permitrootlogin": ("yes", "prohibit-password", "forced-commands-only", "no")}


def _sshd_value_applied(key, want, got):
    """True when sshd's effective `got` for `key` gives at least what `want` asks for."""
    want = _SSHD_VALUE_ALIASES.get(want.lower(), want.lower())
    got = _SSHD_VALUE_ALIASES.get(got, got)
    order = _SSHD_VALUE_ORDER.get(key.lower())
    if order and want in order and got in order:
        return order.index(got) >= order.index(want)
    return got == want


def _sshd_unapplied_directives(server, wanted):
    """([(key, wanted, effective)], readable) for the `wanted` (key, value) pairs sshd will NOT use.

    Read from `sshd -T`, which parses the whole config the way the daemon does — Include order and
    first-value-wins included — so a value written to sshd_config and overridden by a
    sshd_config.d file shows up here as the override. `readable` is False when that read failed or
    printed no settings at all: then nothing is known, and the list is empty rather than a claim
    that everything took."""
    out, _, rc = _core.run_privileged(server, "sshd-effective-config", [], timeout=15,
                                      merge_stderr=False)
    effective = {}
    for line in (out or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            effective[parts[0].lower()] = parts[1].strip().lower()
    if rc != 0 or not effective:
        return [], False
    unapplied = []
    for key, want in wanted:
        got = effective.get(key.lower(), "")
        if not _sshd_value_applied(key, want, got):
            unapplied.append((key, want, got))
    return unapplied, True


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
    # rc 127 above is a reading — fail2ban is genuinely absent. ANY other failure was not: with
    # no "Jail list:" line the regex simply found nothing, jails came out empty, and this returned
    # {"installed": True, "jails": []} — which the Security card renders as "fail2ban is installed
    # and running with no jails configured". A host where the read timed out, or where fail2ban is
    # installed but STOPPED, is exactly the host an operator needs told about, and it got the
    # reassuring answer instead.
    #
    # `fail2ban-client status` always prints "Jail list:" when it really runs, which is the same
    # positive-token test firewall.remote_ufw_status makes on "Status:".
    m = re.search(r"Jail list:\s*(.*)", out or "")
    if rc != 0 or not m:
        return {"installed": True, "jails": [], "unreadable": True}
    jails = [j.strip() for j in m.group(1).split(",") if _F2B_JAIL_RE.match(j.strip())]
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
    # The same decision as the panel host's ufw_deny_ip — one implementation, so the twins cannot
    # drift. It used to delete any deny for the address first, whoever wrote it (see
    # system_ops._ufw_deny_with for what that cost); a rule the panel did not write is left alone.
    from panel.ops import system_ops as _so
    shadowed = {}
    existing = (remote_ufw_blocked_ips(server, shadowed) or {}).get(ip)
    return _so._ufw_deny_with(
        ip, tag, existing,
        lambda verb, args: _core.run_privileged(server, verb, args, timeout=20),
        shadowed.get(ip))


def remote_ufw_undeny_ip(server, ip):
    """Remove a UFW deny rule for an IP (canonicalised first). (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    # Read the result — the same fix system_ops.ufw_undeny_ip already carries, for the same
    # reason, and this is the REMOTE twin that was missed. It discarded the tuple and returned
    # True unconditionally, while remote_ufw_deny_ip six lines up captures (out, err, rc) and
    # fails on non-zero. So a timeout ("", "Command timed out", -1), a missing helper, or a sudo
    # refusal all reported "Unblocked", showed a green toast, and wrote an audit row saying the
    # unblock succeeded — for a deny rule still in the firewall.
    #
    # monitoring._autoblock_reconcile is the caller that makes it worse than a wrong toast: its
    # "count what applied" block tallies `removed` from this return value and collects failures
    # into a list that could never fill, so the hourly reconcile reported releases that had not
    # happened on every remote host, while the panel-host path (already fixed) told the truth.
    out, err, rc = _core.run_privileged(server, "ufw-delete-deny-ip", [ip], timeout=15)
    if rc == 0:
        return True, "Unblocked %s." % ip
    return False, ((out or err or "Unblock failed").replace("\n", " ")[:200])


def remote_ufw_blocked_ips(server, shadowed=None):
    """{ip: tag} for the host's UFW all-ports deny rules — the panel's own, tagged from the rule
    comment, and anyone else's, tagged "" (system_ops._ufw_deny_sources: skipping those made an
    operator's own block look like no block, and the reconcile replaced it and later lifted it).
    An operator's deny below the allow rules blocks nothing, so it goes in `shadowed` instead.

    None when the host could not be read; see ufw_blocked_ips for why that is not {}. An INACTIVE
    firewall is None too, as it already was on the panel host: its stored rules drop nothing, and
    answering {} for it had the reconcile re-block every offender, every hour, against a firewall
    that is off.
    """
    from panel.ops import system_ops as _so
    out, _, rc = _core.run_privileged(server, "ufw-status", ["plain"], timeout=15)
    if rc != 0:
        _core._log.debug("remote_ufw_blocked_ips: read failed on %s (rc=%s)",
                         getattr(server, "name", "?"), rc)
        return None
    if not _so.ufw_status_active(out):
        return None
    return _so._ufw_deny_sources(out, shadowed)


def remote_fail2ban_attempt_counts(server, days=7):
    """{ip: detected attempts} for EVERY offender in a REMOTE host's fail2ban log over the last
    `days` days, or None when the read failed — the remote twin of
    system_ops.fail2ban_attempt_counts, for the auto-block reconcile (which must see every count,
    not the display's top 100)."""
    from panel.ops import system_ops as _so
    out, _, rc = _core.run_privileged(server, "f2b-log-lines", [_so._f2b_cutoff(days)], timeout=25,
                                      merge_stderr=False)
    if rc != 0:
        _core._log.debug("remote attempt counts: the fail2ban log read failed (rc=%s)", rc)
        return None
    return _so._tally_f2b_events(out)[0]


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
        blocked = remote_ufw_blocked_ips(server) or {}   # None = unreadable; blank annotation is fine
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
    # A LOOPBACK bind is the one lockout this function cannot undo, so it is refused before
    # anything is touched rather than caught afterwards.
    #
    # Every other bad bind address fails loudly: sshd cannot bind an address the host does not
    # have, so it does not come up, the listening check below sees that, and the drop-in is
    # reverted. 127.0.0.1 is a real address on every host, so sshd starts perfectly, the port IS
    # listening, and the verification passes — while remote SSH is gone. Measured on the test host:
    # ok=True, "SSH now listens on port 22 on 127.0.0.1", listeners 127.0.0.1:22, and nothing
    # answering on the host's real IP. For the panel's OWN host there is not even a reachability
    # test to fall back on: `_tcp_reachable` only runs for a remote.
    #
    # The panel's own bind address has carried this guard for a while (routes/remote_security.py
    # refuses a loopback-only panel bind unless Tailscale Serve is in front of it). sshd has no
    # equivalent proxy, so here it is refused outright.
    if bind_addr:
        import ipaddress
        try:
            if ipaddress.ip_address(bind_addr).is_loopback:
                return False, ("Binding SSH to %s would make it reachable only from the host "
                               "itself — remote SSH would stop working, and binding is "
                               "all-or-nothing so there is no fallback to revert to. Use the "
                               "address you actually connect on." % bind_addr)
        except ValueError:
            return False, "Bind address must be a valid IP address, or blank for all interfaces."
        # ...and on the panel's own host, an address the host does not HAVE. This used to be caught
        # for free: sshd could not bind a missing address, so it failed to start and the listening
        # check reverted. Under socket activation systemd creates the socket anyway, so something
        # IS listening on the port and that check passes while SSH is reachable nowhere. Measured:
        # `ListenStream=192.0.2.99:22` left `192.0.2.99:22` in ss and nothing answering on the
        # host's real IP. For a remote, _tcp_reachable below is still the backstop.
        if _core.is_local_server(server):
            from panel.ops import system_ops as _so
            if not _so.host_has_ip(bind_addr):
                return False, ("%s isn't an address on this host, so sshd could only bind it in "
                               "name — SSH would answer nowhere. Use one of the host's own "
                               "addresses." % bind_addr)

    # Hoisted above old_ports (it used to be computed at step 2) because on a socket-activated
    # host it CHANGES WHAT old_ports MEANS. _sshd_current_ports runs `sshd -T`, i.e. sshd_config —
    # but when ssh.socket holds the listening socket the panel writes its port to the ssh.socket
    # drop-in and sshd_config's Port is parsed and then ignored. So `sshd -T` still prints `port 22`
    # however many times the panel has moved the port: moving 2222 -> 2022 read old_ports as ["22"]
    # (truthy, so the stored-port fallback never fired), wrote a drop-in whose leading bare
    # `ListenStream=` clears everything before it, and DROPPED 2222 — the port the operator, their
    # backups and their monitoring were connected on — while reporting "The previous port is still
    # available as a fallback" about a port that had just stopped listening.
    socket_mode = _sshd_socket_activated(server)
    old_ports = _sshd_current_ports(server) or [str(int(getattr(server, "port", 22) or 22))]
    if socket_mode:
        # There is no read verb for the ssh.socket drop-in, so `sshd -T` is the best the helper can
        # answer here — but the port the panel is CONNECTED ON is known for certain, and it is the
        # one whose loss locks everybody out. Union it in unconditionally rather than only as the
        # empty-read fallback. (Not done on the sshd_config path: there `sshd -T` is authoritative,
        # and adding a stale stored port would re-open a port the operator had deliberately closed.)
        _stored = str(int(getattr(server, "port", 22) or 22))
        if _stored not in old_ports:
            old_ports = old_ports + [_stored]
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
    #    (socket_mode is read above — old_ports depends on it.)
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
        if bind_addr:
            # The ADDRESS has to appear, not just the port. `ss` prints "0.0.0.0:22" / "[::1]:22",
            # so a port-only match is satisfied by any listener on that port — including sshd bound
            # somewhere useless, which is exactly the case this is here to catch.
            _a = re.escape("[%s]" % bind_addr if ":" in bind_addr else bind_addr)
            if not re.search(r"(?:^|\s)%s:%d\s" % (_a, new_port), out or "", re.M):
                return _revert("sshd isn't listening on %s:%d — reverted. Your existing SSH still "
                               "works." % (bind_addr, new_port))
        elif not re.search(r"[:.]%d\s" % new_port, out or ""):
            return _revert("sshd didn't come up on port %d — reverted. Your existing SSH still works." % new_port)

    _core.run_privileged(server, _discard_verb, [], timeout=10,
                   merge_stderr=False)   # success — drop the snapshot
    if bind_addr:
        # No fallback sentence here: ListenAddress is all-or-nothing (this function's own docstring
        # says so), so sshd is now on THIS address and nothing else. Telling the operator a previous
        # port is still available would be untrue exactly when it matters most.
        return True, ("SSH now listens on %s:%d, and only there (firewall + fail2ban updated). "
                      "Confirm you can still reach it before closing anything."
                      % (bind_addr, new_port))
    return True, ("SSH now listens on port %d (firewall + fail2ban updated). The previous port is "
                  "still available as a fallback — once you've confirmed you can reach SSH on %d, "
                  "close the old one from the Firewall page." % (new_port, new_port))


# A ufw rule whose To column IS port 22 — the number (with or without /tcp) or the app profile.
# Anchored: the To column is the first thing on the line.
_SSH22_RE = re.compile(r"\s*(?:22(?:/tcp)?|OpenSSH)\s", re.I)

# The rules that open SSH without being `22/tcp` to ufw: the OpenSSH app profile and a bare `22`
# (protocol any). ufw never matches either against a `22/tcp` rule, so a delete or a limit of
# `22/tcp` leaves them in place — AHEAD of whatever was just appended, where every connection
# meets them first. Removed wherever the panel sets what public SSH is.
_SSH22_SHADOWING = (("ufw-delete-allow-app", ["OpenSSH"]), ("ufw-delete-allow-port", ["22"]))


def remote_public_ssh_status(server, panel_port=None):
    """Report public SSH state on port 22: 'allow', 'limit', or 'off' (no rule —
    reachable only over tailscale0), plus whether UFW is active at all. When
    `panel_port` is given, also report whether that port has a public ALLOW rule
    (`panel_port_open`) so the UI can disable "Close public panel port" once it's
    already closed."""
    # rc, and an answer at all — do not describe a firewall you could not read. (This required
    # the literal "Status:" line, as firewall.remote_ufw_status does; ufw translates that line
    # whole, so a French host — `État : actif` — read as unreachable and _ufw_is_active's
    # locale-aware reading below was never reached.)
    #
    # This discarded both. An unreadable host produced out="" -> active=False, mode="off", which
    # the UI states as "public SSH is disabled — this host is reachable over the tailnet only".
    # That is the most dangerous direction for this particular sentence: it is the reassurance an
    # operator acts on before closing port 22 or walking away from a host whose SSH may in fact be
    # wide open. `unreachable` is the flag the sibling already established for it.
    out, err, rc = _core.run_privileged(server, "ufw-status", ["plain"], timeout=12)
    _txt = (out or "") + (err or "")
    if rc == 127 or "not found" in _txt or "not installed" in _txt:
        # ufw is ABSENT, which is a reading and not a failure to read — but it is still not
        # "off". `off` in this function means "no rule, so tailnet-only", and with no firewall at
        # all nothing governs port 22, so that label would point the wrong way.
        res = {"active": False, "mode": "unknown", "installed": False}
    elif rc != 0 or not (out or "").strip():
        res = {"active": False, "mode": "unknown", "unreachable": True}
    else:
        res = None
    if res is not None:
        if panel_port:
            res["panel_port"] = int(panel_port)
            res["panel_port_open"] = False
        return res
    active = firewall._ufw_is_active(out)
    mode = "off"
    first_found = False
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
        #
        # And the FIRST such rule decides, because ufw stops at the first rule a packet matches.
        # This read "any LIMIT anywhere wins", so `OpenSSH ALLOW` followed by `22/tcp LIMIT` —
        # the list `ufw allow OpenSSH` plus the Limit button produce — was reported as
        # rate-limited while every connection matched the ALLOW above it and nothing was ever
        # throttled. Only rules that govern the PUBLIC: from Anywhere, inbound, on no interface.
        if not first_found and _SSH22_RE.match(line) and " (v6)" not in low:
            _p = firewall._parse_ufw_rule(line)
            if (not _p["iface"] and _p["direction"] in ("", "IN")
                    and _p["from"].lower() == "anywhere" and _p["action"]):
                first_found = True
                mode = {"LIMIT": "limit", "ALLOW": "allow"}.get(_p["action"], "off")
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
    # "Can't confirm" must EXEMPT here, which is the opposite of what fail-safe means everywhere
    # else in this file. The only consumer is _autoblock_reconcile, and a missing exemption does not
    # mean "do nothing" — it means the address gets a UFW deny inserted at POSITION 1, which the
    # note above _TAILNET_CGNAT says "would cut off tailnet access ... it would override the
    # tailscale0 allow rule". So a failed probe has to fall the protective way.
    #
    # This used to be `_tailscale_conn_state(server)[0]`, which collapses "Tailscale is not running"
    # and "the probe did not run" into the same False — correct for _tailnet_ssh_state, which is
    # deciding whether a way in EXISTS, and wrong here, where it decides whether to take one away.
    # Its own command hid the difference too: `tailscale status --json 2>/dev/null || echo '{}'`
    # always exits 0. The plain command is run here so the rc survives.
    #
    # rc == -1 is the panel's sentinel for "the command did not run" (run_command returns
    # ("", "…timed out", -1) and never raises). Any other rc means the HOST answered — tailscale
    # missing (127) or stopped (non-zero with a Stopped backend) are real answers, and an address
    # in the CGNAT range genuinely is not protected then, so blocking it is allowed.
    import json as _json
    try:
        out, _err, rc = _core.run_command(server, "tailscale status --json", timeout=10)
    except Exception:
        _core._log.debug("tailnet exemption probe failed", exc_info=True)
        return cand      # could not even attempt it → protect the address
    if rc == -1:
        _core._log.warning("tailnet exemption: tailscale probe did not run on %s — exempting %d "
                           "tailnet address(es) rather than risk blocking one",
                           getattr(server, "name", "?"), len(cand))
        return cand
    try:
        running = _json.loads(out or "{}").get("BackendState") == "Running"
    except ValueError:
        return cand      # the host answered with something unparseable → protect the address
    return cand if running else set()


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
    # The new rule goes in FIRST: ufw rewrites a rule that differs only in its action where it
    # stands (`ufw limit 22/tcp` turns `22/tcp ALLOW` into `22/tcp LIMIT` in place), so there is
    # no moment with nothing letting SSH in. Then everything else that would match port 22 AHEAD
    # of it goes — `ufw allow OpenSSH` and a bare `ufw allow 22` are how most Ubuntu hosts opened
    # SSH, neither is the same rule as `22/tcp` to ufw, and whichever sorts first is the one a
    # connection meets. Leaving them made 'limit' a rule nothing ever reached.
    _shadowing = list(_SSH22_SHADOWING)
    if mode == "allow":
        steps = [("ufw-allow-port", ["22/tcp", ""]), ("ufw-delete-limit-port", ["22/tcp"])] + _shadowing
    elif mode == "limit":
        steps = [("ufw-limit-port", ["22/tcp"]), ("ufw-delete-allow-port", ["22/tcp"])] + _shadowing
    elif mode == "off":
        running, ssh_enabled, iface_allowed = _tailnet_ssh_state(server)
        if not (running and (ssh_enabled or iface_allowed)):
            return False, ("Refused — there's no Tailscale way back into this host, so disabling "
                           "public SSH would lock you out. Enable Tailscale SSH, or make sure "
                           "Tailscale is running and the tailscale0 interface is allowed in UFW, first.")
        steps = [("ufw-delete-allow-port", ["22/tcp"]), ("ufw-delete-limit-port", ["22/tcp"])] + _shadowing
    else:
        return False, "Invalid mode"
    # ...but only once it IS in. The loop below ignores every exit code, because a delete of an
    # absent rule is a normal non-zero — and it ignored the add's too, so when `ufw limit 22/tcp`
    # failed (a timeout, a held lock) it went on to delete the OpenSSH and bare-22 allows anyway,
    # and a host opened only by `ufw allow OpenSSH` was left with nothing letting SSH in. The
    # read-back below reported the failure after the lockout. The add is the gate: if it fails,
    # nothing that lets SSH in is removed.
    gate_err = None
    if mode in ("allow", "limit"):
        _g_out, _g_err, _g_rc = _core.run_privileged(server, steps[0][0], steps[0][1], timeout=15)
        if _g_rc != 0:
            gate_err = ((_g_err or _g_out or "exit %s" % _g_rc).replace("\n", " ").strip()[:160])
            steps = []
        else:
            steps = steps[1:]
    for verb, vargs in steps:
        _core.run_privileged(server, verb, vargs, timeout=15)  # deletes of absent rules are harmless
    labels = {"allow": "open (allow)", "limit": "rate-limited", "off": "disabled (tailnet-only)"}
    # ASK THE HOST what it ended up with. This used to return True unconditionally, so on a host
    # with no ufw at all every verb failed and the operator still got "✓ Public SSH is now disabled
    # (tailnet-only)", an audit row saying the hardening succeeded, and port 22 open to the
    # internet. The exit codes cannot answer it either: a delete of an absent rule is a normal
    # non-zero, which is exactly why they were being ignored.
    state = remote_public_ssh_status(server)
    # "I could not read the firewall" is not "UFW is not active" — both refuse, but only one of
    # them is a fact about the host, and the other message sends the operator to check a setting
    # that may be fine.
    if state.get("unreachable"):
        return False, ("Could not read this host's firewall afterwards, so whether public SSH "
                       "changed is unknown — check the host and try again.")
    if not state.get("active"):
        return False, ("UFW is not active on this host, so public SSH cannot be controlled from "
                       "here — port 22 is governed by whatever else is in front of it.")
    if state.get("mode") != mode:
        return False, ("Could not set public SSH to %s — the firewall still reports it as %s.%s"
                       % (labels[mode], labels.get(state.get("mode"), state.get("mode")),
                          (" The new 22/tcp rule was refused (%s), so no other SSH rule was "
                           "removed." % gate_err) if gate_err else ""))
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
