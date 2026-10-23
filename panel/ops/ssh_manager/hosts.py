"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import contextvars
import functools
import ipaddress as _ipaddress
import re
import socket
from panel.core import clock, i18n, terminal
import time
import paramiko
from panel.core.config import decrypt_secret
from panel.core.validation import canonical_ip, ip_address_or_none, ip_network_or_none
from panel.security import privileged as _priv
from panel.ops.ssh_manager import (_core, firewall)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ── gamedig, the player-query tool: installed from its pinned lockfile, and kept that way ──────────
# gamedig is installed from tools/gamedig's package-lock.json by install-gamedig.sh, into
# _priv.GAMEDIG_DIR on every host (the script's header has the layout). This weekly ROOT cron re-runs
# that script. It fetches nothing while the tree the lockfile names is in place and working, so it
# is a repair job: it puts back a deleted tree or a link something else overwrote. A new gamedig
# arrives only as a new lockfile, from a reviewed Dependabot pull request.
#
# It used to be `npm install -g --ignore-scripts gamedig@5`, and before that `npm install -g npm
# gamedig`: root fetching, every Sunday with nobody watching, whatever gamedig 5.x and whatever
# versions of its ~50 floating dependencies the registry served, then every game account running
# them hourly. A compromise of any of those packages at any later point reached every host by the
# next Sunday. `[ -x … ]` keeps it a no-op on a host whose script has not been placed yet.
# Byte-identical to tools/panel-helper's NODE_TOOLS_CRON_BODY and install.sh's copy (a unit gate).
_NODE_TOOLS_CRON = (
    "# LinuxGSM Panel - keep gamedig installed from its pinned lockfile (managed by the panel).\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "30 4 * * 0 root [ -x /usr/local/lib/linuxgsm-panel/gamedig/install-gamedig.sh ] && "
    "/usr/local/lib/linuxgsm-panel/gamedig/install-gamedig.sh >/var/log/lgsm-node-tools.log 2>&1\n"
)


def install_gamedig(server, timeout=600):
    """Install gamedig on a REMOTE host from the panel's pinned lockfile: the gamedig-install verb
    writes tools/gamedig's three files into _priv.GAMEDIG_DIR and runs install-gamedig.sh there.
    Returns (output, rc). Never raises: a failure is (message, -1).

    The panel's own host is not done here: the helper refuses the verb, and install.sh places the
    files there from root's own source (see tools/panel-helper's do_gamedig_install). Nothing is
    fetched when the host already has the lockfile's tree, so running this daily costs one short
    run of gamedig."""
    if _core.is_local_server(server):
        return "gamedig on the panel's own host is installed by install.sh", 0
    try:
        out, _err, rc = _core.run_privileged(server, "gamedig-install", [], timeout=timeout)
        return out or "", rc
    except Exception as e:
        _core._log.debug("install_gamedig failed", exc_info=True)
        return "gamedig install could not be run: %s" % type(e).__name__, -1


def _write_node_tools_cron(server):
    """Write the weekly cron (_NODE_TOOLS_CRON). True if the write succeeded; never raises.
    Root-owned: locally the helper does the write itself (and ignores the content sent, writing its
    own identical body), and remotely it is `sudo bash -c` with base64 so no quoting or `%` can
    mangle it. This used to claim it landed root-owned "regardless of any per-remote
    linuxgsm_user", which was the opposite of what happened — that field turned every sudo=True
    command into `sudo -u <that user>`, this one included. See _core.run_command."""
    try:
        _out, _err, rc = _core.write_root_file(server, "node-tools-cron", _NODE_TOOLS_CRON, timeout=20)
        return rc == 0
    except Exception:
        _core._log.debug("ensure_node_tools_cron failed", exc_info=True)
        return False


def ensure_node_tools_cron(server):
    """The daily pass's gamedig step for one host (app._node_tools_cron_pass): on a REMOTE, first
    the files the weekly cron runs, and gamedig from them (install_gamedig), THEN the cron. In that
    order so a cron is never left naming a script that is not there. The panel's own host gets only
    the cron: its files are install.sh's. Best-effort; never raises. Returns True if the cron write
    succeeded — the one thing every host gets. A remote whose install failed is logged, and its
    gamedig, if it had one, is untouched: the script only switches to a tree that runs."""
    if not _core.is_local_server(server):
        out, rc = install_gamedig(server)
        if rc != 0:
            _core._log.info("gamedig install on %s did not complete (rc=%s): %s",
                            getattr(server, "name", "?"), rc, _core._last_lines(out, 1))
    return _write_node_tools_cron(server)


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


def _r21b_pro_token_refusal(token):
    """The refusal for no token, or one the pro-attach verb's own validator refuses, else None.

    Asked BEFORE anything runs: such a token (a hyphen or quote picked up while copying, a
    truncated paste) raised its VerbError out of run_privileged, past the route's ConnectionError
    handler — "Something went wrong", a traceback, and an audit row saying only "raised VerbError".
    The value is a secret, so the refusal never names it.
    """
    if not token:
        return "No token provided"
    try:
        _priv.check_args("pro-attach", [token])
    except _priv.VerbError:
        return i18n.Sentence("That isn't a valid Ubuntu Pro token — copy it again from your Ubuntu Pro "
                             "dashboard.")
    return None


def pro_attach(server, token):
    """Attach a host to Ubuntu Pro with a subscription token. Installs the pro client
    first if it's somehow missing. The token is NEVER echoed back in messages/logs."""
    token = (token or "").strip()
    refused = _r21b_pro_token_refusal(token)
    if refused:
        return False, refused
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
        return True, _pro_trim(blob) or (i18n.Sentence("{service} enabled", service=service)
                                          if action == "enable" else
                                          i18n.Sentence("{service} disabled", service=service))
    return False, _pro_trim(blob) or (i18n.Sentence("Could not enable {service}", service=service)
                                      if action == "enable" else
                                      i18n.Sentence("Could not disable {service}", service=service))


def pro_detach(server):
    """Detach a host from Ubuntu Pro."""
    _pro_cache_invalidate(server)
    out, err, rc = _core.run_privileged(server, "pro-detach", [], timeout=120)
    blob = (out or "") + " " + (err or "")
    # pro's OWN success sentence, not the word. `"detach" in blob` was met by every failure that
    # names the verb: the helper's "pro-detach timed out" / "failed" / "is not installed", an older
    # helper's "unknown verb 'pro-detach'", and sudo's "not allowed to execute ... pro-detach" —
    # each reported "Detached from Ubuntu Pro." with a success audit row on a host still attached.
    if rc == 0 or "this machine is now detached" in blob.lower():
        return True, "Detached from Ubuntu Pro."
    return False, _pro_trim(blob) or "Detach failed"


def _ufw_port_int(port):
    """Coerce a UFW port to a validated int (1-65535), or raise ValueError. Ports and
    protocols are interpolated straight into a root shell command, so they must never
    carry anything but a number / a known protocol keyword."""
    try:
        p = int(port)   # rejects non-numeric ("abc", "22; rm -rf /") with ValueError
    except OverflowError:
        # int(float("inf")) raises OverflowError, not ValueError — and a JSON body can carry
        # Infinity or 1e400 (Python's json parses both to inf). Every caller catches ValueError
        # for "not a port", so an infinite one escaped them as a 500. Same answer as "abc".
        raise ValueError("port out of range") from None
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
        return True, i18n.Sentence("Port {port} opened on remote", port=label)
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

    A port RANGE is fine (27015:27020), which Source-engine games need. An IPv6 zone id is not an
    address or a network, though ipaddress parses one, so it is refused here; what is passed on and
    reported is the verb's canonical spelling of the source, never the typed text."""
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
    # signals failure by RAISING VerbError — run_privileged does not catch it, nor does the route —
    # so a hostname in the "allow from" box or a malformed port returned a bare 500 HTML page that
    # the caller's `.then(r => r.json())` could not parse. app.py's _json_for_api_errors now makes
    # that 500 JSON, but its message is the generic "Something went wrong — see the panel log.",
    # so the user still got no reason and the panel log still got a traceback. Same two answers
    # the sibling gives, as (ok, msg).
    try:
        src = _priv.canonical_cidr(src)
    except ValueError:
        return False, "Source must be an IP address or network (e.g. 10.0.0.0/24)"
    if not _UFW_PORT_SPEC_RE.match(spec):
        return False, "Port must be a number or a range like 27015:27020"
    if allow:
        cmt = re.sub(r"[^A-Za-z0-9 _.-]", "", comment or "")[:60]
        out, err, rc = _core.run_privileged(server, "ufw-allow-from-port", [src, spec, proto, cmt],
                                            timeout=15)
    else:
        # The delete removes the rule by its spec, so it goes past the lockout guard the Firewall
        # page's x (remote_ufw_delete_rule) answers to: "SSH from my home IP" — this function's own
        # example — is the host's only SSH rule exactly when it matters, and Remove deleted it.
        refusal, out, err, rc = _r15a_guarded_spec_delete(
            server, "ufw-delete-allow-from-port", [src, spec, proto],
            lambda g: _r15a_spec_names(g, spec, proto.upper(), src))
        if refusal:
            return False, refusal
        # ufw exits 0 for a rule that is not there, saying so in words (C locale: run_privileged's),
        # so rc 0 alone answered "Rule ... removed" about a rule that never existed.
        if rc == 0 and _r23b_deleted_nothing(out):
            return False, i18n.Sentence("There is no rule for {spec}/{proto} from {src}, so nothing was removed.",
                                        spec=spec, proto=proto, src=src)
    if rc == 0:
        return True, (i18n.Sentence("Port {spec}/{proto} open from {src}", spec=spec, proto=proto, src=src)
                      if allow else
                      i18n.Sentence("Rule for {spec}/{proto} from {src} removed", spec=spec, proto=proto, src=src))
    return False, err or out or "Unknown error"


def _r15a_src_key(text):
    """A rule's source as ufw itself stores it.

    So a delete's source and a listed rule compare the way ufw's own match does
    (ufw.util.normalize_address + UFWRule._fix_anywhere):

    - any /0 network on the unspecified address, and the Firewall page's "Any address", is "any":
      `ufw delete allow from 0.0.0.0/0 ...` (or ::/0) removes that family's half of an
      `allow 22/tcp`, which ufw lists as "Anywhere";
    - IPv4 is masked to its network (ufw stores 203.0.113.7/24 as 203.0.113.0/24, and a delete
      typed with the host bits removes it), a /32 is the bare address;
    - IPv6 keeps its host bits (ufw does) and loses only a /128.

    Comparing ipaddress's text as typed missed all three, and Remove under "Allow from source"
    deleted the host's only SSH rule past the lockout guard. ufw prints sources lowercased.
    """
    s = str(text or "").strip().lower()
    if s in ("any", "anywhere", "any address"):
        return "any"
    try:
        iface = _ipaddress.ip_interface(s)
    except ValueError:
        return s
    plen = iface.network.prefixlen
    if iface.version == 4:
        if plen == 0:
            # ufw masks v4 host bits first, so 1.2.3.4/0 is 0.0.0.0/0 to it too.
            return "any"
        return str(iface.ip) if plen == 32 else str(iface.network)
    if plen == 128:
        return str(iface.ip)
    if plen == 0 and iface.ip == _ipaddress.IPv6Address("::"):
        return "any"
    return "%s/%d" % (iface.ip, plen)


def _r15a_spec_names(g, port, proto_label, src=None):
    """Would a by-spec `ufw delete allow ...` remove group `g`?

    An inbound ALLOW on no interface, for `port` with `proto_label` (BOTH for a bare rule), from
    anywhere — or from `src` when one is named. The port is the To column's last word, so a rule
    scoped to a destination address still matches: a refusal it did not need is the safe side of
    this test, a protected rule it missed is not.
    """
    if g.get("is_iface") or g.get("action") != "ALLOW" or g.get("direction", "IN") != "IN":
        return False
    if g.get("proto_label") != proto_label:
        return False
    words = str(g.get("port_num", "")).split()
    if not words or words[-1] != str(port):
        return False
    if src is None:
        return g.get("scope") == "Any address"
    # The group's scope is ufw's own From column ("Any address" for Anywhere); `src` is what the
    # operator typed. Both go through ufw's normalisation, so either spelling of a rule finds it.
    return _r15a_src_key(g.get("scope")) == _r15a_src_key(src)


def _r15a_guarded_spec_delete(server, verb, vargs, names):
    """Run a by-spec ufw delete only if no protected rule is among those it removes.

    -> (refusal or None, out, err, rc); `names` None runs the delete unguarded (a caller's force).
    The same guard remote_ufw_delete_rule applies by number,
    held under the host's ufw_lock from the read to the delete: a firewall that cannot be read
    refuses ("I could not check" is not "it is safe"), and a protected rule the spec names is
    refused with its own reason. A host without UFW goes on to the delete, which answers for itself.
    """
    if names is None:
        out, err, rc = _core.run_privileged(server, verb, vargs, timeout=15)
        return None, out, err, rc
    with _core.ufw_lock(server):
        try:
            status = firewall.remote_ufw_status(server)
        except Exception:
            _core._log.warning("ufw delete: the safety check could not read the firewall",
                               exc_info=True)
            status = None
        if status is None or status.get("unreachable"):
            return (i18n.Sentence("Couldn't read the firewall to check whether this rule is the one keeping "
                                  "your access open, so this refuses rather than risk locking you out. "
                                  "Check the host is reachable and try again."), "", "", None)
        for g in (status.get("groups", []) if status.get("installed") else []):
            if g.get("protected") and names(g):
                return _r16c_protect_refusal(g), "", "", None
        out, err, rc = _core.run_privileged(server, verb, vargs, timeout=15)
        return None, out, err, rc


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
            return False, i18n.Sentence("Could not read the firewall to find the rate limit on {spec}, so "
                                        "nothing was changed.", spec=spec)
        # An inactive ufw lists NO rules, stored ones included, so the test below found none and
        # answered "has no rate limit to remove" about a host whose stored rules hold one.
        if not firewall._ufw_is_active(before):
            return False, i18n.Sentence("UFW is not active on this host, so its stored rules cannot be read "
                                        "here to find the rate limit on {spec} — nothing was changed.", spec=spec)
        if not any(r["to"] == spec and r["action"] == "LIMIT" for r in _ufw_public_rules(before)):
            return False, i18n.Sentence("{spec} has no rate limit to remove.", spec=spec)
        out, err, rc = _core.run_privileged(server, "ufw-allow-port", [spec, ""], timeout=15)
        if rc == 0:
            return True, i18n.Sentence("Rate limit removed from {spec} (it stays open)", spec=spec)
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
                unsplit = i18n.Sentence(
                    "The panel could not split it: re-opening {port}/{proto} on its own failed ({why}), so the rule "
                    "opening both was left in place.", port=port, proto=other,
                    why=(o_err or o_out or "exit %s" % o_rc).replace("\n", " ").strip()[:120])
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
        return False, i18n.Sentence("The limit for {spec} was added, but the firewall could not be read back "
                                    "to confirm it is the rule connections meet first.", spec=spec)
    if not firewall._ufw_is_active(after):
        return False, i18n.Sentence("The limit for {spec} is stored, but UFW is not active on this host, so "
                                    "nothing is limited until it is enabled.", spec=spec)
    # Both families: a `(v6)` ALLOW above the v6 LIMIT left IPv6 clients unthrottled while this
    # answered "now rate limited" from the IPv4 list alone.
    first = _r22b_not_limit(after, port, proto)
    if first is not None and first.get("unresolved"):
        # An app profile other than OpenSSH (`Nginx Full`, `Apache`): its ports are in a file on the
        # host the panel does not read, so whether it shadows the limit is unknown. Not a success.
        return False, i18n.Sentence("The limit for {spec} was added, but `{rule}` above it is an application "
                                    "profile the panel cannot read, so it cannot confirm the limit is the rule "
                                    "connections meet first.", spec=spec, rule=first["detail"])
    if first is not None:
        return False, i18n.Sentences(i18n.Sentence(
            "{spec} is still matched first by `{rule}`, so the limit is never reached — remove or narrow that "
            "rule.", spec=spec, rule=first["detail"]), unsplit)
    if split and _r22b_closed_by_split(before, after, port, other):
        # The split must not have closed what the bare rule kept open for the other protocol.
        return False, i18n.Sentence("{spec} is now rate limited, but {port}/{proto} is no longer open — "
                                    "re-open it from the Firewall page.", spec=spec, port=port, proto=other)
    return True, i18n.Sentence("{spec} is now rate limited (6 connections per 30s per address)", spec=spec)


def _r22b_closed_by_split(before, after, port, proto):
    """Whether `port`/`proto` was open to the public before the split, and is not after, in either family."""
    def _open(out, v6):
        f = _ufw_first_public_rule(out, port, proto, v6=v6)
        return bool(f and f["action"] in ("ALLOW", "LIMIT"))
    return any(_open(before, v6) and not _open(after, v6) for v6 in (False, True))


# A protocol ufw prints after a To or From column ("22,80/tcp", "Anywhere/udp", "<ip>/gre"). Letters
# only: "10.0.0.0/8" is an address, not a protocol.
_R21B_PROTO_SUFFIX_RE = re.compile(r"/([A-Za-z]+)\Z")


def _ufw_public_rules(status_out, v6=False):
    """The public rules of one family in `ufw status [numbered]` output, in ufw's order.

    IPv4, or IPv6 with `v6`: the rules that govern traffic from ANYWHERE — inbound, on no
    particular interface. Each is _parse_ufw_rule's dict plus its `detail` text. Source-restricted
    rules and interface rules are left out: neither decides what the public meets first. The two
    families are separate chains (ufw6 is its own table), so each is read on its own: a `(v6)`
    ALLOW above the v6 LIMIT leaves every IPv6 client unthrottled whatever the IPv4 list says.
    """
    rules = []
    for line in (status_out or "").splitlines():
        # The row after its `[ N]` number, sliced off: a splitlines() line holds no newline, so the
        # `\s*(.*)\Z` this used to capture with was always the rest of the line anyway.
        m = re.match(r"\s*\[\s*\d+\]\s*", line)
        detail = (line[m.end():] if m else line).strip()
        p = firewall._parse_ufw_rule(detail)
        # From "Anywhere/udp" is still everyone (`ufw allow proto udp from any`): the protocol is
        # _r21b_rule_matches' to read, not a reason to leave the rule out.
        if (not p["action"] or p["v6"] != v6 or p["iface"] or p["direction"] not in ("", "IN")
                or _R21B_PROTO_SUFFIX_RE.sub("", p["from"]).lower() != "anywhere"):
            continue
        p["detail"] = re.sub(r"\s{2,}", "  ", detail)
        rules.append(p)
    return rules


def _r21b_rule_matches(p, port, proto):
    """Whether public rule `p` matches a `proto` connection to `port`: True, False or None.

    None when its To column is an app profile other than OpenSSH, whose ports the panel cannot know.
    Every shape ufw prints, not only `N` / `N/proto` / `lo:hi`: the OpenSSH profile (port 22), a
    port list (`27015,27016/tcp`), a destination before the port (`203.0.113.5 22/tcp`), and no
    port at all (`Anywhere`, an address alone) — each matches ahead of a LIMIT appended below it.
    Read by the To pattern alone they were skipped, so the LIMIT read as the first rule and the
    port was reported rate limited while every connection met the ALLOW above it.
    """
    words = p["to"].split()
    last = words[-1] if words else ""
    for column in (last, p["from"]):
        m = _R21B_PROTO_SUFFIX_RE.search(column)
        if m and m.group(1).lower() != proto:
            return False
    return _r21b_port_column_matches(_R21B_PROTO_SUFFIX_RE.sub("", last), port, proto)


def _r21b_port_column_matches(body, port, proto):
    """_r21b_rule_matches for the To column's last word, its protocol already taken off."""
    if body.lower() in firewall._SSH_APP_PROFILES:
        return port == 22 and proto == "tcp"
    if body and all(_UFW_PORT_ITEM_RE.match(i) for i in body.split(",")):
        return firewall._r12a_names_port(body, {port})      # a port, a list, a range
    return _r21b_portless_matches(body or "Anywhere")


def _r21b_portless_matches(body):
    """A To column with no port: every port (`Anywhere`, an address) — True; None when unknown."""
    if body.lower() == "anywhere" or firewall._r14a_net(body) is not None:
        # Every port, unless the address is one no TCP or unicast reaches (multicast).
        return firewall._r13a_every_port({}, body)
    return None


def _r21b_dest_scoped(p):
    """Whether public rule `p` names one destination address in its To column."""
    words = p["to"].split()
    return bool(words) and firewall._r14a_net(words[0]) is not None


def _r22b_dest_loopback(p):
    """Whether public rule `p` is for a loopback destination (`127.0.0.1 22/tcp`) only.

    No connection from outside the host is addressed to one (the kernel drops such a packet as a
    martian before ufw sees it), so it is no way in for the public and shadows nothing they meet.
    Counted, `127.0.0.1 22/tcp ALLOW` read as public SSH "open (allow)", and "off" could never
    succeed while it stood. A network that only CONTAINS loopback (`0.0.0.0/0`) is not one.
    """
    words = p["to"].split()
    net = firewall._r14a_net(words[0]) if words else None
    return net is not None and net.is_loopback


def _ufw_first_public_rule(status_out, port, proto, unresolved=False, scoped=True, v6=False):
    """The first public rule a `proto` connection to `port` meets, or None.

    With `unresolved`, an app profile whose ports are unknown (_r21b_rule_matches None) ahead of
    every match is returned marked "unresolved": the caller cannot say what it shadows.

    `scoped=False` leaves out a rule for one destination address (`203.0.113.5 22/tcp`, an address
    alone): it matches only connections to that address. Counted as matching first, it decides a
    limit is shadowed (the safe answer there); for "is this port already open?" it is not, since
    the host's other addresses still meet whatever comes after it.

    One family: IPv4, or IPv6 with `v6` (_r22b_first_rules reads both).
    """
    for p in _ufw_public_rules(status_out, v6=v6):
        if _r22b_dest_loopback(p) or (not scoped and _r21b_dest_scoped(p)):
            continue
        hit = _r21b_rule_matches(p, port, proto)
        if hit is None and unresolved:
            return dict(p, unresolved=True)
        if hit:
            return p
    return None


def _r22b_first_rules(status_out, port, proto, **kw):
    """[the IPv4 first public rule, then the IPv6 one] (_ufw_first_public_rule's, `kw` passed on).

    The IPv6 entry is left out when no v6 rule matches at all: a host with IPv6 off in ufw, or with
    no v6 rule for the port, has nothing there to shadow or open it. The IPv4 one is always there,
    None when nothing matches.
    """
    v6 = _ufw_first_public_rule(status_out, port, proto, v6=True, **kw)
    return [_ufw_first_public_rule(status_out, port, proto, **kw)] + ([v6] if v6 is not None else [])


def _r22b_not_limit(status_out, port, proto):
    """The first public rule, in either family, that a connection meets ahead of (or instead of) a
    LIMIT: None when the LIMIT is first in both. An IPv4 list with no match is {"detail": "nothing"}."""
    for first in _r22b_first_rules(status_out, port, proto, unresolved=True):
        if first is None:
            return {"action": "", "detail": "nothing"}
        if first.get("unresolved") or first["action"] != "LIMIT":
            return first
    return None


def _r16c_protect_refusal(g):
    """The refusal to delete protected rule `g`: its protect reason, as a Sentence the route translates.

    The group carries the reason's fixed template and values (firewall.R14A_REASONS) beside the
    English. Handed back as that English, the route's i18n.tr() looked up a sentence with the
    ports already in it — never a key — so a Spanish or French viewer read the refusal in English
    while the Firewall page showed the same reason translated. As a str it is the same English.
    """
    key = g.get("protect_reason_key")
    if key:
        return i18n.Sentence(key, **dict(g.get("protect_reason_params") or {}))
    return g.get("protect_reason") or i18n.Sentence("This rule protects your access to the host and can't be "
                                                    "removed here.")


def remote_ufw_close_port(server, port, protocol=None, force=False, deleted=None):
    """Close a port on the remote server via UFW. With protocol=None (or 'both'/'any'),
    deletes the bare `allow <port>` rule (both protocols); otherwise the proto-specific rule.

    Unless force=True, refuses when the rule it would remove is protected (the host's only SSH
    rule, the panel's own web port), as remote_ufw_delete_rule does: `POST /firewall/close` for 22
    deleted the rule the Firewall page's x refuses. force=True is for the panel's own moves, which
    close a port they opened themselves or one the config no longer names.

    `deleted`, a list, is told the address families whose rule the delete really removed ("v4",
    "v6"), from ufw's own words: the answer is whether the port is closed NOW, which is not whether
    anything was removed (a port already closed, or open only from one address, answers True too)."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto is None:
        return False, "Invalid protocol"
    if proto in ("tcp", "udp"):
        verb, vargs, label = "ufw-delete-allow-proto-port", [proto, str(port)], proto.upper()
    else:
        verb, vargs, label = "ufw-delete-allow-port", [str(port)], "BOTH"
    refusal, out, err, rc = _r15a_guarded_spec_delete(
        server, verb, vargs, None if force else (lambda g: _r15a_spec_names(g, port, label)))
    if refusal:
        return False, refusal
    if deleted is not None:
        deleted.extend(_r30j_deleted_families(out))
    if rc != 0:
        return False, err or out or "Unknown error"
    return _r23b_closed_answer(server, port, proto, out)


def _r30j_deleted_families(out):
    """The address families ("v4", "v6") whose rule a by-spec `ufw delete` removed.

    ufw prints "Rule deleted" for the IPv4 rule and "Rule deleted (v6)" for the IPv6 one, and "Could
    not delete non-existent rule[ (v6)]" for a family that had none (C locale: run_privileged's;
    measured with ufw 0.36 on Ubuntu 24.04). A delete by spec removes only its own shape, so a LIMIT
    or a rule for one source address is never among them.
    """
    lines = {ln.strip() for ln in (out or "").splitlines()}
    return [fam for fam, said in (("v4", "Rule deleted"), ("v6", "Rule deleted (v6)")) if said in lines]


def _r23b_closed_answer(server, port, proto, out=""):
    """remote_ufw_close_port's answer once its delete exited 0: read back, never taken from rc.

    rc 0 is not "closed": ufw exits 0 deleting a rule that is not there, and a delete by spec
    matches only its own shape — `delete allow proto tcp ... port N` leaves a bare `N` allow, a
    `N/tcp LIMIT` or a port list in place. So this answered "Port N closed" with N still open.

    `out` is the delete's own output. When the firewall could not be read back AND that output says
    no rule matched, nothing confirms the port is closed and nothing was removed: it answered
    "Port N closed" for a rule that may still let N in.
    """
    one = proto in ("tcp", "udp")
    label = ("%s/%s" % (port, proto)) if one else port
    read = []
    left = _r23b_still_open(server, port, (proto,) if one else ("tcp", "udp"), read)
    if left is not None:
        return False, i18n.Sentence("Port {port} is still open: connections meet `{rule}` first — remove or "
                                    "narrow that rule.", port=label, rule=left["detail"])
    if read != [True] and _r23b_deleted_nothing(out):
        if read == ["inactive"]:
            # Read, and inactive: it lists no rules, stored ones included. "Could not be read back"
            # sent the operator to retry, or to check a host that had answered every call.
            return False, i18n.Sentence("No rule for port {port} matched, so nothing was removed. UFW is not "
                                        "active on this host, so it filters nothing now, and its stored rules "
                                        "cannot be listed to say whether another one opens the port.", port=label)
        return False, i18n.Sentence("No rule for port {port} matched, so nothing was removed, and the firewall "
                                    "could not be read back to say whether the port is open.", port=label)
    return True, i18n.Sentence("Port {port} closed on remote", port=label)


def _r23b_deleted_nothing(out):
    """Whether a by-spec `ufw delete` removed nothing: every family answered that no rule matched.

    ufw (backend_iptables.set_rule) prints "Could not delete non-existent rule" per family and exits
    0 — measured on the test VPS — so the exit code cannot tell; one "Rule deleted" line can.
    """
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    return (any(ln.startswith("Could not delete non-existent rule") for ln in lines)
            and not any(ln.startswith("Rule deleted") for ln in lines))


def _r23b_still_open(server, port, protos, read=None):
    """After a close, the first public rule that still lets `port` in (ALLOW or LIMIT), else None.

    Either family, for any of `protos`.

    None too when the firewall cannot be read back or is not active: an inactive UFW filters
    nothing and lists no rules, so there is nothing to read the answer from; the delete's own
    answer stands there, as it always did.
    """
    out, _err, rc = _core.run_privileged(server, "ufw-status", ["plain"], timeout=15)
    state = _r26b_listing_state(out, rc)
    if read is not None and state:
        # `read`: told that the listing was read (None here is then "none open"), or that it was
        # read and is inactive, which answers nothing either way.
        read.append(state)
    if state is not True:
        return None
    for proto in protos:
        for first in _r22b_first_rules(out, port, proto):
            if first and first["action"] in ("ALLOW", "LIMIT"):
                return first
    return None


def _r26b_listing_state(out, rc):
    """A `ufw status` read: True (an active listing), "inactive", or None (not read)."""
    if rc != 0 or not (out or "").strip():
        return None
    return True if firewall._ufw_is_active(out) else "inactive"


def remote_ufw_delete_rule(server, num, force=False, expect_key=None):
    """Delete a UFW rule by its number (as shown by `ufw status numbered`). This is
    the reliable way to remove any rule — deleting by spec requires an exact match.

    Unless force=True, refuses to delete a rule that is the last thing keeping SSH or
    Tailscale access open, so a click (or a direct API call) can't lock you out.

    `expect_key` is the rule's identity (a group `key` from firewall.remote_ufw_status). ufw
    numbers are POSITIONS and renumber on every insert (the auto-block inserts its denies at 1), so
    a number read earlier can name a different rule by now; with a key, the delete happens only if
    rule `num` is still that rule in a fresh read."""
    try:
        n = int(num)
    except (TypeError, ValueError, OverflowError):
        return False, "Invalid rule number"
    if n < 1:
        return False, "Invalid rule number"
    if expect_key is not None and not isinstance(expect_key, str):
        return False, "Invalid rule identity"
    # The check below and the `ufw delete n` are two commands, and n is a position. The expect_key
    # re-read closed the gap between the PAGE's read and this one, but not the one between this
    # read and the delete: the auto-block reconcile inserts its denies at 1 from its own thread,
    # so an insert landing there moved every rule down one and `ufw delete n` removed whatever
    # now sat at n — the rule ABOVE the one that was checked, which can be the protected rule
    # keeping SSH open, deleted by a request the guard had just approved. Both run under the host's
    # ufw_lock now (run_privileged takes it for every ufw change, the auto-block's inserts
    # included), and this holds it from the read to the delete.
    with _core.ufw_lock(server):
        return _delete_rule_locked(server, n, force, expect_key)


def _delete_rule_locked(server, n, force, expect_key):
    """remote_ufw_delete_rule's guard and delete. Called with the host's ufw_lock held."""
    if not force or expect_key is not None:
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
            return False, i18n.Sentence("Couldn't read the firewall to check whether rule {n} is the one keeping "
                                        "your access open, so this refuses rather than risk locking you out. Check "
                                        "the host is reachable and try again.", n=n)
        if not status.get("installed"):
            # A different answer, not the same failure: UFW genuinely is not here, so there is no
            # rule numbered anything and the delete would fail regardless. Say that rather than
            # send someone checking a connection that is fine.
            return False, i18n.Sentence("UFW isn't installed on this host, so there's no rule {n} to delete.", n=n)
        if expect_key is not None and not any(
                g.get("key") == expect_key and n in g.get("nums", [])
                for g in status.get("groups", [])):
            return False, i18n.Sentence("Rule {n} is no longer the rule that was picked — the firewall changed "
                                        "since it was read, so nothing was removed. Refresh and try again.", n=n)
        for g in (status.get("groups", []) if not force else []):
            if n in g.get("nums", []) and g.get("protected"):
                return False, _r16c_protect_refusal(g)
        verb, args = _delete_verb(n, status, expect_key)
    else:
        verb, args = "ufw-delete-num", [n]
    out, err, rc = _core.run_privileged(server, verb, args, timeout=15)
    if verb == "ufw-delete-num-if" and rc == 2 and "unknown verb" in (err or ""):
        # A panel-host helper installed before ufw-delete-num-if existed (the root pieces are
        # refreshed by install.sh, which may not have run yet). Delete the way it did before: still
        # under ufw_lock, and the guard above has already matched the rule.
        verb, args = "ufw-delete-num", [n]
        out, err, rc = _core.run_privileged(server, verb, args, timeout=15)
    if rc == 0:
        return True, i18n.Sentence("Rule {n} deleted", n=n)
    if verb == "ufw-delete-num-if" and rc == _priv.UFW_RULE_MOVED:
        return False, i18n.Sentence("Rule {n} changed on the host while it was being removed (someone else "
                                    "edited the firewall), so nothing was removed. Refresh and try again.", n=n)
    return False, err or out or "Failed to delete rule"


def _delete_verb(n, status, expect_key):
    """(verb, args) that deletes rule `n` — re-checked on the host itself when there is a key.

    ufw_lock serialises the PANEL's ufw changes on a host, so nothing the panel does can move rule
    n between the read above and the delete. A `ufw` somebody types on the host can: it renumbers
    the rules, and `ufw delete n` then removes whatever sits at n by the time it runs — possibly the
    rule the guard above refused to delete. So when the caller named the rule it means
    (expect_key), the delete goes as ufw-delete-num-if with the text rule n had in that read, and
    the host deletes n only if it still reads that — the check and the delete in one root
    invocation (tools/panel-helper do_ufw_delete_num_if, or its shell form over SSH).

    A rule whose text the verb's strict validator refuses (a hand-made rule with a comment outside
    the characters the panel writes) falls back to the plain delete, still under the lock and
    still checked above: refusing it outright would make such a rule undeletable from the panel.
    """
    if expect_key is None:
        return "ufw-delete-num", [n]
    text = next((" ".join((r.get("detail") or "").split()) for r in status.get("rules", [])
                 if str(r.get("num")) == str(n)), None)
    try:
        return "ufw-delete-num-if", _priv.check_args("ufw-delete-num-if", [n, text])
    except _priv.VerbError:
        return "ufw-delete-num", [n]


def _game_rule_comment(name, default="Game"):
    """The UFW comment a game server's rules carry: its name, cut to what ufw's comment accepts."""
    return re.sub(r"[^A-Za-z0-9 _.-]", "", name or default)[:60] or default


def remote_ufw_allow_game_port(server, port, name="Game"):
    """Open ONE game server's port, tagged with the server's name: (1 when it is open, message).

    Through remote_ufw_allow_game_ports, so it never takes over a rule someone else holds. It ran a
    bare `ufw allow <port> comment <name>` itself, which REPLACES a rule on that port that differs
    only in comment or action — another server's allow re-tagged as this one's (and deleted with
    it at this server's uninstall), an operator's DENY turned into an allow. The list opener was
    fixed for that; this single-port route was not.
    """
    # Range-checked HERE, like every sibling in this module. The verb's _portspec raises
    # VerbError, run_privileged does not catch it, and there is no route-level handler — so
    # `POST /api/remote/<id>/game-port/70000/open` came back as a bare HTML 500 that the caller's
    # .then(r => r.json()) could not parse.
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return 0, "Invalid port"
    opened, msg = remote_ufw_allow_game_ports(server, [port], name)
    return (1 if port in opened else 0), i18n.Sentence("Port {port}: {what}", port=port, what=msg)


def _is_public_port_rule(g, port, protos=("BOTH",)):
    """True when group `g` is an inbound rule from anywhere, on no interface, for exactly `port`
    with one of `protos` ("BOTH" is a bare rule — what `ufw allow <port>` writes)."""
    return (not g.get("is_iface") and g.get("direction", "IN") == "IN"
            and g.get("scope") == "Any address" and g.get("proto_label") in protos
            and str(g.get("port_num", "")).strip() == str(port))


def _is_panel_allow(g):
    """Is group `g` the shape of rule the panel itself opens for a game server?

    An inbound ALLOW from anywhere, on no interface, for ONE port — bare, /tcp or /udp. A LIMIT, a
    DENY, an allow from one address, an interface rule or a range was somebody's own decision,
    whatever its comment says."""
    pn = str(g.get("port_num", "")).strip()
    return (g.get("action") == "ALLOW" and pn.isdecimal()
            and _is_public_port_rule(g, pn, ("BOTH", "TCP", "UDP")))


_UFW_PROTOS = ("tcp", "udp")
# One entry of a rule's port column: a port, or a lo:hi range. ufw lists several with commas.
_UFW_PORT_ITEM_RE = re.compile(r"^\s*(\d{1,5})(?::(\d{1,5}))?\s*\Z")


def _rule_covers(g, port, proto):
    """Does group `g` decide what a `proto` connection to `port` from anywhere meets? Inbound, from
    anywhere, on no interface, naming the port (alone, in a range or in a list); a bare rule
    decides both protocols."""
    if g.get("is_iface") or g.get("direction", "IN") != "IN" or g.get("scope") != "Any address":
        return False
    if g.get("proto_label") not in ("BOTH", proto.upper()):
        return False
    for item in str(g.get("port_num", "")).split(","):
        m = _UFW_PORT_ITEM_RE.match(item)
        if m and int(m.group(1)) <= port <= int(m.group(2) or m.group(1)):
            return True
    return False


def _first_rule_for(groups, port, proto):
    """The rule a `proto` connection to `port` from anywhere meets first (ufw stops at the first
    match), or None when no rule names it."""
    hits = [g for g in groups if g.get("nums") and _rule_covers(g, port, proto)]
    return min(hits, key=lambda g: min(g["nums"])) if hits else None


def _rule_label(g):
    """A rule as a person reads it: its port, then what it does when that is not a plain public
    allow — `47828 DENY`, `47829/tcp LIMIT`, `47810/tcp from 10.0.0.0/8`."""
    parts = [str(g.get("port_label") or g.get("port_num") or "?")]
    if g.get("action", "ALLOW") != "ALLOW":
        parts.append(g["action"])
    if g.get("direction", "IN") != "IN":
        parts.append(g["direction"])
    if g.get("iface"):
        parts.append("on " + g["iface"])
    elif g.get("scope", "Any address") != "Any address":
        parts.append("from " + g["scope"])
    return " ".join(parts)


def _readable_groups(server):
    """The firewall's rule groups, or [] when it cannot be read (or UFW is not installed)."""
    try:
        status = firewall.remote_ufw_status(server)
    except Exception:
        _core._log.debug("game ports: the firewall could not be read before opening", exc_info=True)
        return []
    if not status or not status.get("installed") or status.get("unreachable"):
        return []
    return status.get("groups", [])


def _open_game_port(server, groups, port, comment):
    """Open `port` for the server whose rules carry `comment`. -> (open now, rules it was left to).

    Per protocol: one another rule already decides is left to that rule, whatever it does, and
    only the protocols no rule names get this server's allow — the bare rule when that is both,
    `<port>/tcp` or `/udp` when it is one. An allow is appended, so it never sits ahead of a rule
    that is already there. "Open" means both protocols now let a connection in, so a port a DENY
    still blocks for one of them is not reported open."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, []
    first = {pr: _first_rule_for(groups, port, pr) for pr in _UFW_PROTOS}
    spec = _spec_for_unruled(port, first)
    added = bool(spec) and _core.run_privileged(
        server, "ufw-allow-port", [spec, comment], timeout=15)[2] == 0
    lets_in = all(added if g is None else g.get("action") in ("ALLOW", "LIMIT")
                  for g in first.values())
    return lets_in, _decided_by_others(first, comment)


def _spec_for_unruled(port, first):
    """The allow that covers exactly the protocols no rule names yet ({proto: first rule}), or ""."""
    free = [pr for pr in _UFW_PROTOS if first[pr] is None]
    if len(free) == len(_UFW_PROTOS):
        return str(port)
    return "%d/%s" % (port, free[0]) if free else ""


def _decided_by_others(first, comment):
    """The rules ({proto: first rule}) other than this server's own allow that decide a protocol."""
    labels = []
    for g in first.values():
        if g is None or (g.get("action") == "ALLOW" and g.get("comment") == comment):
            continue
        if _rule_label(g) not in labels:
            labels.append(_rule_label(g))
    return labels


def remote_ufw_allow_game_ports(server, ports, name="Game"):
    """Open a LIST of ports, all tagged with the game server's name. Idempotent — a port this
    server's own rule already opens is left as it is. Used to open every port a game actually
    needs (game/query/rcon/etc.), not just the main one.

    A protocol some OTHER rule already decides is left to that rule. `ufw allow <port> comment
    <name>` does not add a rule beside one that differs from it only in comment or action: it
    REPLACES it (ufw's set_rule swaps any match short of exact on a non-delete). So opening a port
    another server's rule held re-tagged that rule as THIS server's, and this server's uninstall
    (remote_ufw_close_by_name) then deleted it; an operator's `deny 3306` became an allow. The
    ports come from LinuxGSM's `details` run as the game account, which reads a config that account
    can write — so which rule got taken over was the account's choice.

    Only BARE rules used to be looked at. With `deny 27015/tcp` in place the bare allow went in
    after it and 27015 was reported opened while every TCP connection still met the DENY. The rule
    each protocol meets first is what decides now (_open_game_port): a port is reported open only
    when both protocols let a connection in, and the rules it was left to are named, with what
    they do (`27015/tcp DENY`, `27016 LIMIT`).

    A firewall that cannot be read is opened as it always was: nothing an attacker does makes this
    read fail, and holding back every port of a freshly installed server on a busy host (a Tailscale
    host after a long SteamCMD run times out routinely) is the worse failure."""
    comment = _game_rule_comment(name)
    groups = _readable_groups(server)
    opened, left_to = [], []
    for p in sorted({int(x) for x in ports if x}):
        is_open, rules = _open_game_port(server, groups, p, comment)
        if is_open:
            opened.append(p)
        left_to += [r for r in rules if r not in left_to]
    # A Sentence: remote_ufw_allow_game_port shows it as the {what} of "Port {port}: {what}".
    shown = ", ".join(map(str, opened)) or i18n.Sentence("none")
    if left_to:
        return opened, i18n.Sentence("opened {n} port(s): {ports}; left to an existing rule: {rules}",
                                     n=len(opened), ports=shown, rules=", ".join(left_to))
    return opened, i18n.Sentence("opened {n} port(s): {ports}", n=len(opened), ports=shown)


# How many times a cleanup tries one rule, each against a fresh read. ufw numbers are positions and
# the auto-block inserts its denies at 1 from another thread, so a delete refused because the rule
# moved (remote_ufw_delete_rule's expect_key) is a reason to read again, not to give the rule up.
_UFW_DELETE_TRIES = 3


def _delete_picked_rules(server, pick, bound):
    """Delete every rule `pick(group)` takes, highest number first, each by number against a fresh
    read and naming the rule it means. -> (rules deleted, the last read).

    A rule that is refused is read again and retried, up to _UFW_DELETE_TRIES times; any `pick`
    still takes on the last read is one that would not go. That read is an unreachable one when the
    firewall stopped answering, and then nothing is known about what is left."""
    deleted, refused = 0, {}
    status = {}
    for _ in range(bound):
        status = firewall.remote_ufw_status(server)
        if status.get("unreachable") or not status.get("installed"):
            break
        nxt = _next_pick(status, pick, refused)
        if nxt is None:
            break
        n, key = nxt
        if remote_ufw_delete_rule(server, n, expect_key=key)[0]:
            deleted += 1
        else:
            refused[key] = refused.get(key, 0) + 1
    else:
        status = firewall.remote_ufw_status(server)
    return deleted, status


def _next_pick(status, pick, refused):
    """The highest-numbered (number, key) `pick` takes that has tries left ({key: refusals}), or
    None. Highest first, so this loop's own deletes never move the rules still to go."""
    mine = [(n, g["key"]) for g in status.get("groups", [])
            if pick(g) and refused.get(g["key"], 0) < _UFW_DELETE_TRIES
            for n in g.get("nums", [])]
    return max(mine) if mine else None


# A cleanup that could not read the firewall knows nothing about what it left. Shared with the
# uninstall route, which says the same when the cleanup raised.
# The notes below are Sentences: the uninstall answer translates each one whole (_r15e_uninstalled),
# and %-built English matched no catalog key, so es and fr viewers read them in English.
UFW_UNREAD_NOTE = i18n.Sentence("The firewall could not be read, so this server's rules may still be open — "
                                "check the host's Firewall page.")


def _still_there(status, pick):
    """What a cleanup meant to remove and did not, as sentences for its result ([] = nothing)."""
    if status.get("unreachable"):
        return [UFW_UNREAD_NOTE]
    if not status.get("installed"):
        return []
    if not status.get("enabled"):
        # An inactive ufw lists no rules, stored ones included: nothing here could be seen or removed.
        return [i18n.Sentence("UFW is not active on this host, so its stored rules cannot be listed, and any "
                              "this server had are still stored — they apply again if UFW is enabled.")]
    stuck = [_rule_label(g) for g in status.get("groups", []) if pick(g)]
    if not stuck:
        return []
    if len(stuck) == 1:
        return [i18n.Sentence("Still open, as it could not be removed: {rules} — remove it from the host's "
                              "Firewall page.", rules=stuck[0])]
    return [i18n.Sentence("Still open, as it could not be removed: {rules} — remove them from the host's "
                          "Firewall page.", rules=", ".join(stuck))]


def _left_on_purpose(status, comment, removable, protected):
    """Sentences naming the rules carrying `comment` that a name cleanup does not take."""
    kept = [g for g in status.get("groups", [])
            if g.get("comment") == comment and not removable(g)]
    on_host = [g for g in kept if _is_panel_allow(g) and _port_of(g) in protected]
    return (_naming(i18n.Sentence(_R16A_NOT_OURS), [g for g in kept if g not in on_host])
            + _naming(i18n.Sentence(_R16A_ON_HOST_PORT), on_host))


def _rule_port_words(g):
    """Rule group `g`'s port column split in words: a destination address, when ufw prints one, then
    the port (`203.0.113.10 27015/tcp`). [] for a rule with no port column."""
    return str(g.get("port_label") or g.get("port_num") or "").split()


def _rule_names_port_in(g, ports):
    """Does inbound rule group `g` name one of `ports`?

    Alone, in a range or in a list; for either protocol, from any source, on any interface, and to
    any address — ufw prints a destination before the port, `203.0.113.10 27015/tcp`, which the
    port pattern (anchored at the start) never matched, so such a rule was never named."""
    if g.get("direction", "IN") != "IN":
        return False
    words = str(g.get("port_num", "")).split()
    for item in (words[-1] if words else "").split(","):
        m = _UFW_PORT_ITEM_RE.match(item)
        if m and any(int(m.group(1)) <= p <= int(m.group(2) or m.group(1)) for p in ports):
            return True
    return False


def _unnamed_rule_label(g):
    """A rule with no name on it, as an uninstall's answer names it: its port and what it does.

    Not the address it admits from, nor its interface or destination — said only as "from some
    addresses", "on one interface", "to one address". That answer goes to whoever may uninstall the
    server (Uninstall servers plus that server), while reading the host's rules takes Manage
    Remotes (the Firewall page): an operator's allow from a home address is not theirs to read."""
    words = _rule_port_words(g) or ["?"]
    parts = [words[-1]]
    if g.get("action", "ALLOW") != "ALLOW":
        parts.append(g["action"])
    if g.get("iface"):
        parts.append("on one interface")
    elif g.get("scope", "Any address") != "Any address":
        parts.append("from some addresses")
    if len(words) > 1:
        parts.append("to one address")
    return " ".join(parts)


def _left_on_own_ports(status, ports, protected, taken):
    """Sentences naming each rule with no comment left on `ports` that `taken` did not mean to take.

    [] when there is none, or no ports were given. `ports` are the uninstalled server's own block,
    less any port another server still holds; SSH's and the panel's (`protected`) are never its
    own. A rule nobody's name is on is not the panel's to delete, but it is still what keeps the
    port open once the server is gone: the Firewall page's rate limit writes an untagged
    `27015/tcp LIMIT` (`ufw limit` sends no comment, and replaces the server's tagged allow with
    it), and the cleanup neither took nor named it, so the port stayed open under a clean
    "uninstalled". A rule carrying a name has an owner who still needs it; one carrying this
    server's name is named by the cleanup already. Each is named by _unnamed_rule_label, once."""
    ports = set(ports) - set(protected)
    if not ports:
        return []
    stray = [g for g in status.get("groups", [])
             if not g.get("comment") and not taken(g) and _rule_names_port_in(g, ports)]
    labels = list(dict.fromkeys(map(_unnamed_rule_label, stray)))
    if not labels:
        return []
    if len(ports) > 1:
        return [i18n.Sentence("Left in place on its ports: {rules}.", rules=", ".join(labels))]
    return [i18n.Sentence("Left in place on its port: {rules}.", rules=", ".join(labels))]


def _port_of(g):
    """The one port a _is_panel_allow group is on, as an int."""
    return int(str(g["port_num"]).strip())


_R16A_NOT_OURS = "Left in place, as the panel does not make rules like these: {rules}."
_R16A_ON_HOST_PORT = "Left in place on SSH's or the panel's own port: {rules}."


def _naming(lead, groups):
    """[`lead` (a Sentence of one of the two above) naming each rule of `groups`], or [] when none.

    The caller hands the module constant to Sentence by name, so tools/i18n_scan holds it to the
    catalogs; a template passed on as a plain parameter is one the gate cannot read.
    """
    return [i18n.Sentence(lead.template, rules=", ".join(map(_rule_label, groups)))] if groups else []


def _with_notes(message, notes):
    """`message`, then each of `notes` as a sentence of its own."""
    return message + ("." + "".join(" " + n for n in notes) if notes else "")


def remote_ufw_close_by_name(server, name, ports=None, held=(), tagged=None):
    """Delete the ALLOW rules tagged with a game server's name (its comment). Used on uninstall so
    multi-port games are fully cleaned up. -> (rules removed, message, what is left).

    The firewall is RE-READ before every delete, and each delete names the rule it means
    (expect_key). The numbers used to be read once and deleted highest-first, which kept them valid
    only against this loop's own deletes: the hourly auto-block reconcile inserts its denies at
    position 1 from another thread, and one insert mid-loop shifted every remaining number onto
    the rule above it — another server's port, or the deny holding an attacker out — while this
    reported "8 rule(s) removed". A delete refused because its rule MOVED was then given up for
    good, so the same insert left the server's port open, v4 and v6, still reported as a clean
    "2 rule(s) removed"; it is retried now (_delete_picked_rules).

    Only rules the panel itself makes (_is_panel_allow), and never one on SSH's or the panel's own
    port (protected_host_ports). Anything carrying the name was taken: an operator's DENY or LIMIT,
    an allow from one address, and a `22` allow the old "Open all ports" takeover could leave
    tagged with a server — guarded only by the last-way-in check.

    The third value names, as sentences, every rule carrying the name that is still there — ones
    that would not go, and ones left on purpose — or that the firewall could not be read. With
    `ports` (the server's own block), it also names every rule with no comment still on one of them
    (_left_on_own_ports), from the same last read — and on every port a public allow carrying the
    name was on, which is the server's too: the install tags the ports LinuxGSM reports, and a
    Query port can sit outside the game's span (Rust's 28017, beyond 28015-28016). Less `held`,
    the ports another server on the host holds, whose rules are that server's. `ports` None (the
    default) names none of that; any other value turns it on, an empty block included, so a caller
    whose later step names what is left passes None. Empty means the server's rules are gone; the
    message says the same things.

    `tagged`, a set when given, receives the ports those tagged allows were on, as this read them,
    for a later step that names what is left instead (the uninstall's legacy sweep)."""
    comment = re.sub(r"[^A-Za-z0-9 _.-]", "", name or "")[:60]
    if not comment:
        return 0, "no name", []
    protected = protected_host_ports(server)
    seen = set() if tagged is None else tagged

    def removable(g):
        if g.get("comment") != comment or not _is_panel_allow(g):
            return False
        seen.add(_port_of(g))
        return _port_of(g) not in protected

    deleted, status = _delete_picked_rules(server, removable, 256)
    own = () if ports is None else (set(ports) | seen) - set(held)
    left = (_still_there(status, removable)
            + _left_on_purpose(status, comment, removable, protected)
            + _left_on_own_ports(status, own, protected, removable))
    return deleted, _with_notes(f"{deleted} rule(s) removed for {comment}", left), left


def remote_ufw_tagged_ports(server, name):
    """The ports an inbound public ALLOW tagged with `name` already opens, as a set of ints.

    Empty when there is no name or the firewall cannot be read — so a caller using this to excuse
    something is excused nothing it could not see.
    """
    comment = _game_rule_comment(name, "")
    if not comment:
        return set()
    try:
        status = firewall.remote_ufw_status(server)
    except Exception:
        _core._log.debug("tagged ports: the firewall could not be read", exc_info=True)
        return set()
    return {_port_of(g) for g in status.get("groups", [])
            if g.get("comment") == comment and _is_panel_allow(g)}


def protected_host_ports(server):
    """The ports on `server` no game server may open, adopt or clean up, as a set of ints.

    SSH — 22, the port the panel connects on, and every port sshd serves (_sshd_current_ports) — and,
    on the panel's own host, the panel's web port. A game server's ports are read from LinuxGSM's
    `details`, run AS THE GAME ACCOUNT over a config that account (and anyone with MANAGE_SERVERS,
    through the file manager) can write, so "Query 22" is a line they can make the panel act on as
    root. An `sshd -T` that cannot be read leaves the first two: a failed read narrows this set,
    never empties it.
    """
    ports = set(firewall._ssh_ports(server))
    try:
        ports.update(int(p) for p in _sshd_current_ports(server))
    except Exception:
        _core._log.debug("protected ports: sshd's effective config could not be read",
                         exc_info=True)
    try:
        # Each of the panel's ports: the one it serves on now, and a saved one waiting for its restart.
        web = firewall._r31a_panel_web_ports(server)
    except Exception:
        _core._log.debug("protected ports: the panel's web port could not be read", exc_info=True)
        web = []
    ports.update(int(p) for p in web if p)
    return ports


def _is_game_rule_for(g, port, comment, legacy):
    """Is group `g` a rule remote_ufw_close_game_port may take as the server's on `port`?

    An inbound public ALLOW on exactly that port (bare, /tcp or /udp) — never a LIMIT or DENY —
    tagged `comment`, or, with `legacy`, carrying no comment at all."""
    return (_is_public_port_rule(g, port, ("BOTH", "TCP", "UDP")) and g.get("action") == "ALLOW"
            and ((bool(comment) and g.get("comment") == comment)
                 or (legacy and not g.get("comment"))))


def remote_ufw_close_game_port(server, port, name="", legacy=False, ports=()):
    """Remove THIS server's rules on `port`. -> (rules removed, message, what is left).

    Which rules are this server's: an inbound public ALLOW on exactly `port` (bare, /tcp or /udp)
    tagged with `name`; and with legacy=True, one with NO comment, which is what a panel that did
    not tag its rules yet left behind. Nothing else, ever.

    It used to delete by SPEC — `ufw delete allow <port>`, then the same `proto tcp` and `proto udp`
    — with no comment. ufw removes a rule matching all but its comment when the delete's comment is
    empty, so those three took every ALLOW on the port whoever it belonged to: another server's, a
    rule the operator opened from the Firewall page, or an operator's `allow 22/tcp comment ssh`,
    a lockout — and none of it went through remote_ufw_delete_rule's guard. On a fresh install the
    adoption step ran it on the port the panel had allocated, which cannot hold a rule of this
    server's yet (the ports are opened after it).

    So every delete is now by number against a fresh read, names the rule it means (expect_key),
    and is never forced: the guard that refuses to delete the last way into the host still stands.
    An untagged rule is a guess at ownership, so legacy=True is refused on a port SSH or the panel
    is on, and never takes a LIMIT or a DENY. The CALLER must also know that no other game server
    on the host holds the port — that is a database fact this module does not have.

    NOT port+1. That sweep deleted `port+1/tcp` and `/udp` with no idea whose they were — commonly
    the NEXT server's game port, or a rule the operator opened from the Firewall page — so
    uninstalling the server on 27015 closed 27016/udp and its neighbour stopped taking players,
    with nothing in the uninstall output saying so. The server's tagged rules, extra ports
    included, are removed by remote_ufw_close_by_name.

    A delete refused because the rule MOVED (an insert between the read and the delete) is read
    again and retried; it used to be given up at once, leaving the rule open with nothing said.
    The third value names, as sentences, a rule of this server's that is still there after its
    tries, or that the firewall could not be read; empty means none is left. With `ports` (the
    server's own block, when this is an uninstall's last step), it also names every rule with no
    comment still on one of them that this did not mean to take (_left_on_own_ports)."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return 0, "Invalid port", []
    comment = _game_rule_comment(name, "")
    protected = protected_host_ports(server) if legacy or ports else set()
    legacy = legacy and port not in protected
    if not comment and not legacy and not ports:
        return 0, f"Port {port}: no rule here is known to be this server's", []

    def mine(g):
        return _is_game_rule_for(g, port, comment, legacy)

    deleted, status = _delete_picked_rules(server, mine, 64)
    left = _still_there(status, mine) + _left_on_own_ports(status, ports, protected, mine)
    return deleted, _with_notes(f"Port {port}: {deleted} rule(s) removed", left), left


# LinuxGSM dependencies common to most game servers on Debian/Ubuntu. The game
# user has no sudo, so the panel installs these as root before/around auto-install.
# A Debian package name, optionally with an architecture qualifier (libstdc++5:i386). Debian
# policy: lowercase alphanumeric plus + - . , at least two characters, starting alphanumeric.
#
# ENDING alphanumeric too, which policy does not require and apt-get needs. `apt-get install`
# reads a trailing `-` as "remove this one" and a trailing `+` as "install it" (apt-get(8)), so
# `openssh-server-` in an install list REMOVES openssh-server, as root — and that name satisfied
# this pattern. The arch qualifier ends alphanumeric for the same reason (`libc6:i386-`). Every
# name in LinuxGSM's package lists ends alphanumeric, so nothing real is refused; the helper's
# v_package and privileged._package say the same.
APT_PKG_RE = re.compile(r"[a-z0-9][a-z0-9+.-]*[a-z0-9](?::[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)?\Z")


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


# Per-distro package lists, keyed by slug — one host may be 22.04 and another 24.04.
#
# Registered, and keyed by the remote id alone. It had NO expiry and was not registered, and its
# key was the tuple ("srv", id) — which forget_remote_caches could not have popped even if it had
# been. That is the exact shape firewall.py's _specs_cache note describes: delete a remote, add
# another that takes the same rowid (SQLite reused them; it still does where id_sequence.py
# could not add AUTOINCREMENT), and deps_for_game loads the DELETED host's distro package list.
# A Debian 12 box gets ubuntu-22.04.csv; apt-get install is atomic, so
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
            timeout=10, sudo=False)
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
    # lgsm_data keeps the parsed list itself, and re-reads it weekly. A second copy here was kept
    # for the life of the process, so an upstream package fix (a package renamed for a distro)
    # never reached an install until the panel restarted.
    return lgsm_data.deps(os_slug)


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


def _listed_dependencies(names, per_game):
    """Split `names` into (those a LinuxGSM package list names, the rest), each in order.

    Listed means: in `per_game` — LinuxGSM's own list for this game on this host's distro, the only
    place its check_deps takes names from — or in the panel's common set, which is what an install
    falls back to when that list cannot be had, or `steamcmd`.
    """
    allowed = set(per_game) | set(LGSM_COMMON_DEPS.split()) | {"steamcmd"}
    keep, refused = [], []
    for n in names:
        (keep if n in allowed else refused).append(n)
    return keep, refused


def _listed_extras(server, game_type, names, per_game, account=None, selfname=None):
    """Split `names` into (keep, refused) like _listed_dependencies, then look again at refused.

    The panel's copy of LinuxGSM's list is master's, fetched weekly, and the game account's
    LinuxGSM asks from a list that can differ from it either way: an account on an older release
    reads THAT release's list (measured on the test host: mcserver and fctrserver run v26.1.0, whose
    list names openjdk-21-jre for pmc/pz/rw/vpmc/wmc and dotnet-runtime-8.0 for vints, where master
    names -25- and 10.0), and a release newer than the weekly copy lists what that copy has not
    seen yet. Refusing those broke the install: vints' check_deps greps for its exact runtime.

    The account's own copy (~/lgsm/data/<distro>.csv) is the one list that must NOT be consulted:
    the account can write it, and this check exists because that account is less trusted than
    root. So the second look is at LinuxGSM's own repository only (_upstream_names).
    """
    keep, refused = _listed_dependencies(names, per_game)
    if not refused:
        return keep, refused
    also = _upstream_names(server, game_type, refused, account, selfname)
    return keep + [n for n in refused if n in also], [n for n in refused if n not in also]


def _names_for_game(table, game_type):
    """Every name a LinuxGSM package table lists for a game: its 'all', 'steamcmd' and own rows."""
    return {p for key in ("all", "steamcmd", game_type or "") for p in table.get(key, ())}


def _upstream_names(server, game_type, refused, account, selfname):
    """Collect the set LinuxGSM's repository lists for this game where the panel's copy lags.

    First the list at the release the account's script runs, which is exactly the one its
    check_deps read (lgsm_data.deps_at_release). Then, only for names still refused, master
    fetched now rather than up to a week ago (lgsm_data.refresh_deps). Both fetch only here, after
    a refusal during an install, and both are rate-limited; neither is on any page's path.
    """
    from panel.services import lgsm_data
    slug = host_os_slug(server)
    names = set()
    tag = lgsm_release(server, account, selfname)
    if tag:
        names |= _names_for_game(lgsm_data.deps_at_release(slug, tag), game_type)
    if not set(refused) <= names:
        names |= _names_for_game(lgsm_data.refresh_deps(slug), game_type)
    return names


def lgsm_release(server, account, selfname):
    """The LinuxGSM release a game account's script runs, as its tag ('v26.1.0'), or None.

    From the `version=` line of the account's own script, /home/<account>/<selfname>: the value
    its LinuxGSM fetches its modules and package list at (see lgsm_data._RELEASE_BASE). The
    instance script, not ~/linuxgsm.sh: update-lgsm rewrites the first and leaves the second, and
    on the test host gmodserver's two said v26.2.0 and v26.1.0, with its list v26.2.0's.

    The account can edit that file, so this chooses only WHICH of LinuxGSM's published releases is
    read; lgsm_data.release_tag refuses anything that is not a plain tag. None when it cannot be
    read: an empty answer is a failed read, not a version.
    """
    if not (account and selfname):
        return None
    script = _core._quote("/home/%s/%s" % (account, selfname))
    try:
        out, _err, rc = _core.read_as_game_user(
            server, account, "grep -m1 -E '^version=' " + script, timeout=10, selfname=selfname)
    except Exception:
        _core._log.debug("could not read the account's LinuxGSM version", exc_info=True)
        return None
    from panel.services import lgsm_data
    line = (out or "").strip().splitlines()[:1] if rc == 0 else []
    value = line[0].partition("=")[2].strip().strip("\"'") if line else ""
    return lgsm_data.release_tag(value)


def install_game_dependencies(server, game_type=None, extra="", account=None, selfname=None):
    """Install the exact LinuxGSM dependencies for a game (from LinuxGSM's list for this host's
    distro — a 22.04 box gets 22.04's packages, not 24.04's),
    plus any extras THAT LIST NAMES, as root. Falls back to the common set if the CSV is missing.
    Enables i386 + universe + multiverse first, then installs the batch, and if that
    fails (apt-get install is atomic — one unavailable package aborts everything)
    falls back to installing each package individually so the critical libs still
    land. `steamcmd` (needed by every Steam game — gmod/cs/tf2/rust/…) is installed
    specially: it's in `multiverse` and its Steam license must be pre-accepted via
    debconf or apt hangs waiting for interactive input.

    `account` and `selfname` name the game account and its LinuxGSM script, for a retry: the
    release that script runs is where a name the panel's own copy refuses is looked up again."""
    if game_type:
        per_game, needs_steamcmd = deps_for_game(game_type, host_os_slug(server))
    else:
        per_game, needs_steamcmd = [], True  # unknown game → make sure steamcmd is present
    # A retry passes back what LinuxGSM printed as missing. That is the output of a script run AS
    # THE GAME ACCOUNT, out of that account's home, reading a config that account can edit (and
    # that MANAGE_SERVERS can, through the file manager) — and the names went to apt-get install as
    # ROOT, checked for syntax alone. So the account chose what root installed: an MTA that starts
    # listening, anything in the host's repositories. LinuxGSM's check_deps only ever reports names
    # from its package list for this game, so a name that list does not have is refused, logged,
    # and said in the result — never installed. The list is loaded above for exactly this game on
    # exactly this distro; when it cannot be had, the common set is all that passes. A name the
    # panel's weekly copy refuses is looked up once more in LinuxGSM's repository, at the release
    # the account runs and on master now — never in the account's own copy (_listed_extras).
    extra_pkgs, refused = _listed_extras(server, game_type, (extra or "").split(), per_game,
                                         account, selfname)
    for _name in refused:
        _core._log.warning("dependency list: refusing %r — LinuxGSM reported it missing, but "
                           "no LinuxGSM package list the panel could read for %s names it",
                           _name[:60], game_type or "this game")
    refusal = ("Not installed — not in LinuxGSM's package list for this game on this host: %s. "
               % ", ".join(n[:60] for n in refused)) if refused else ""
    # A retry may pass "steamcmd" back via `extra` (LinuxGSM lists it as missing).
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
        return (steam_ok and not refused), (refusal or "no dependencies to install")

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
            # The batch failed; the chunk still counts as installed when every package in it then
            # installed on its own (the retries' results were dropped, and a batch that failed for
            # a reason a retry got past reported "some dependencies did not install").
            failed = [one for one in chunk
                      if _verb("apt-install-minimal", [one], timeout=600, merge_stderr=False)[2] != 0]
            if failed:
                rc = c_rc

    # rc now reports the packages: a batch that failed, unless each of its packages then installed
    # on its own. It used to report `echo deps-done`, the last command in the pipeline, so this
    # function returned True however badly the install had gone — which is the
    # other half of why a refused step never surfaced. A refused name fails it too: LinuxGSM will
    # still report that package missing, and the result is where the refusal is said.
    return (rc == 0 and steam_ok and not refused), refusal + (out or err or "")


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
    # Bandit's hard-coded-/tmp rule (and Sonar's S5443): this is a substring of SteamCMD's error
    # text being matched, not a path anything here opens or writes.
    # Each message is an i18n.Sentence so the catalog gate holds it to a key: it becomes the failed
    # install's step name, which install-status translates for whoever asks.
    if "please delete some /tmp/dumps" in low or "/tmp/dumps* directories" in low:   # nosec B108  # NOSONAR - error text, not a path
        return ("steam_dumps", i18n.Sentence(
            "Steam keeps only ten crash-dump slots on a host (/tmp/dumps … /tmp/dumps09), one per "
            "Linux account, and every one of them is in use by a game account that still exists. "
            "SteamCMD cannot run at all until one is freed — remove a game server you no longer "
            "need, or delete one of those directories on the host."))
    if "steam login not set" in low or 'change steamuser="username"' in low \
            or "no license" in low or "no subscription" in low:
        return ("steam_login", i18n.Sentence(
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
        return ("steam_platform", i18n.Sentence(
            "SteamCMD refused this game with \"Invalid platform\" — a known SteamCMD bug, not a "
            "problem with this host: the game does have a Linux server. The way through it is to "
            "prime the download with the Windows depot and then validate, which pulls the Linux "
            "binaries. The panel does that automatically on a retry."))
    m = re.search(r"is not supported on ([^\r\n(]{3,60})", text)
    if m:
        return ("os_unsupported", i18n.Sentence(
            "LinuxGSM does not support this game on {os}. It caps this one at an older Ubuntu release; the "
            "game picker marks those.", os=m.group(1).strip()))
    return None


def parse_missing_deps(output):
    """Extract package names LinuxGSM reported as missing (from its
    'Missing dependencies: pkg1 pkg2 ... Run:' warning)."""
    text = terminal.strip_escapes(output or "")
    deps = []
    # The list runs to the end of its line, or to the " Run:" LinuxGSM puts after it. Read as ONE
    # greedy pass that stops before a blank followed by "Run:", not the lazy
    # `\s*(.+?)(?:\s+Run:|[\r\n]|$)` this was: that tried to end the list at every character, and
    # at each blank read the rest of the run of blanks looking for "Run:", so a long run of blanks
    # cost its square. The names found are the same — the old stopping point sat at the start of
    # the blanks before "Run:" and this one at their end, and only blanks lie between the two.
    for m in re.finditer(r"[Mm]issing dependencies:\s*((?:(?!\sRun:)[^\r\n])*)", text):
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


# apt's own simulation of the upgrade Install updates runs, after the C-locale prefix: its Inst lines
# are what an upgrade installs now (system_ops.parse_inst). The native architecture first, for an
# Inst line that names none. -s: a simulation, installs nothing; Debug::NoLocking: it needs no lock,
# so it runs without root and never waits on unattended-upgrades. The last command's status is
# apt's, so `rc` is apt's. The panel host runs the same text (system_ops._r27p_local_probe).
_R27P_UPGRADE_SIM = ("echo R27P-ARCH $(dpkg --print-architecture 2>/dev/null); "
                     "apt-get -s -o Debug::NoLocking=1 full-upgrade 2>/dev/null")


def remote_os_check_updates(server):
    """Check for OS updates on the remote server.
    Returns {ok, count, packages:[{name,version,from,suite}], deferred:[...], deferred_known} —
    system_ops.r27p_updates_result's shape, the panel host's too.

    "ok" is apt's own exit status, and it matters: a check that FAILED (the apt lock held by
    unattended-upgrades, the host mid-reboot) produces no output, which reads exactly like a clean
    host. A caller that takes that for "nothing waiting" will re-announce the same package list the
    next time the check succeeds. The filtering greps this pipeline used to end with are gone for
    the same reason — grep exits 1 when a clean host matches nothing, so its status masked apt's."""
    _core.run_privileged(server, "apt-update", [], timeout=60, merge_stderr=False)
    # C.UTF-8 and no LANGUAGE, as the verb above runs: apt translates "[upgradable from: …]", and
    # parse_upgradable reads the English words (see system_ops.os_update_available).
    # sudo=False: the package lists are world-readable, as every read #436 moved off sudo.
    out, _, rc = _core.run_command(server, _core._R19A_C_LOCALE + "apt list --upgradable 2>/dev/null",
                                   timeout=30, sudo=False)
    from panel.ops import system_ops

    def _probe():
        """What an upgrade installs now: apt's own simulation, in the same locale, without sudo.

        _R27P_UPGRADE_SIM, run only when the list read found packages. A probe that raised
        (paramiko does; the other transports return rc -1) after the list read worked is an unread
        split, not a failed check: the list stands, every package counted.
        """
        try:
            p_out, _, p_rc = _core.run_command(
                server, _core._R19A_C_LOCALE + _R27P_UPGRADE_SIM, timeout=60, sudo=False)
        except Exception:
            _core._log.debug("upgrade simulation failed on host %s", getattr(server, "id", "?"),
                             exc_info=True)
            return "", -1
        return p_out, p_rc
    return system_ops.r27p_updates_result(out, rc, _probe)


def remote_os_run_updates(server):
    """Start the remote's OS update: remote_os_update_start's detached job. (ok, message).

    It was a blocking `apt-get full-upgrade` over SSH with a 600 s kill. An upgrade that took
    longer, or a connection that dropped, ended root's shell on the host and apt with it, mid-dpkg
    ("dpkg was interrupted"). The card has used the detached job for that reason since #122; this,
    reached only by POST .../run-updates (no page calls it), now starts the same job.
    """
    return remote_os_update_start(server)


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
    from panel.ops import system_ops
    _, _, chk_rc = _core.run_privileged(server, "apt-upgrade-running", [], timeout=10, merge_stderr=False)
    busy = system_ops.r31b_update_running_answer(chk_rc, functools.partial(_r31b_own_update_rc, server))
    if busy is not None:
        return busy
    # Was one `setsid bash -c '<script>'` wrapping seven shell statements. It took no caller input
    # at all — the only variables in it were two constants — which is what lets it be a
    # zero-argument verb rather than a command the panel composes.
    out, _, _ = _core.run_privileged(server, "os-update-run", [], timeout=20)
    if _priv.OS_UPDATE_STARTED in (out or ""):
        return True, "Update started."
    return False, "Couldn't start the update."


def _r31b_own_update_rc(server):
    """os-update-own-running's answer: 0 while the panel's own OS-update job runs, 1 when not.

    "unknown_verb" from a local row's helper older than the verb (system_ops.r31j_own_update_answer).
    """
    from panel.ops import system_ops
    return system_ops.r31j_own_update_answer(
        _core.run_privileged(server, "os-update-own-running", [], timeout=10, merge_stderr=False),
        "helper" if getattr(server, "is_local", False) else "remote")


def _r32b_own_job_ended(server):
    """Whether the panel's own OS-update job has ended: True, False (still running), None (unread).

    os-update-own-running answers 0 (running) or 1 (not). A panel-host helper older than that verb
    ("unknown_verb") never will, so there apt-upgrade-running answers instead, the start gate's
    probe and what the job runs: unread forever would have reported every finished update on such a
    host as a lost contact. Anything else is no answer.
    """
    own = _r31b_own_update_rc(server)
    if own == "unknown_verb":
        own = _core.run_privileged(server, "apt-upgrade-running", [], timeout=10, merge_stderr=False)[2]
    return {0: False, 1: True}.get(own)


def _r31b_finished(server, log):
    """remote_os_update_status's answer when `log` ends in the job's sentinel, else None."""
    m = re.search(re.escape(_OS_UPDATE_DONE) + r"(-?\d+)", log)
    if m is None:
        return None
    own = _r32b_own_job_ended(server)
    if own is False:
        # The sentinel is the LAST thing the job writes, so with the job still running it is the
        # previous run's: the new job has not truncated the log yet (it is only just starting).
        # Read as finished, the popup said "Updates installed." for a run that had just begun.
        return {"running": True, "done": False, "rc": None, "log": ""}
    if own is None:
        # No answer is not "the job has ended". This read anything but 0 as ended, so a probe that
        # did not run (rc -1 from the Tailscale and local transports, an SSH blip) in that same
        # window painted "Updates installed." from the previous run's sentinel and stopped watching.
        # Unread: the popup counts it as a miss and keeps polling.
        return {"running": None, "done": False, "rc": None, "log": "", "unread": True}
    log = re.sub(r"\n?" + re.escape(_OS_UPDATE_DONE) + r"-?\d+\s*$", "", log)
    return {"running": False, "done": True, "rc": int(m.group(1)), "log": log}


def remote_os_update_status(server):
    """Live status of the running/last OS update: {running, done, rc, log}. `done` is set once the
    detached job appends its sentinel; `running` reflects whether apt is still working.

    `unread` is set when the log could not be read at all. The Tailscale and local transports
    return ("", ..., -1) rather than raising, and that read as {done: False, log: ""} plus
    `running: False` from a probe that did not answer either: the watch popup wiped apt's output
    and, three polls later, declared an update that was still unpacking "ended without a
    completion marker". `running` is None when its own probe did not answer.

    A log that does not EXIST is an answer, though: the verb is `tail` of a file on /run (tmpfs),
    which only the panel's own job writes, and tail exits 1 naming the file. An update the panel did
    not start — one already running when Start was pressed ("watching it") — has no such file, and
    every poll of it read as unread, so the popup said "Lost contact with the host" about a host
    that answered every call. That case reads as an empty log and still asks apt whether it is
    running. Matched on the path in tail's own error, which no locale translates and which sudo's
    refusal (also exit 1) does not contain."""
    out, err, lrc = _core.run_privileged(server, "os-update-log", [], timeout=15, merge_stderr=False)
    if lrc == 1 and _priv.OS_UPDATE_LOG in (err or ""):
        out = ""                              # answered: there is no log (yet)
    elif lrc != 0:
        return {"running": None, "done": False, "rc": None, "log": "", "unread": True}
    log = out or ""
    finished = _r31b_finished(server, log)
    if finished is not None:
        return finished
    # No sentinel yet — is apt still working? pgrep answers 0 (yes) or 1 (no); anything else is no
    # answer, which is not "apt has stopped".
    _, _, alive_rc = _core.run_privileged(server, "apt-any-running", [], timeout=10, merge_stderr=False)
    running = True if alive_rc == 0 else False if alive_rc == 1 else None
    return {"running": running, "done": False, "rc": None, "log": log}


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
        out, _, rc = _core.run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=12,
                                       sudo=False)
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
        pk, _, _ = _core.run_command(server, "cat /var/run/reboot-required.pkgs 2>/dev/null", timeout=12,
                                     sudo=False)
        packages = sorted({p.strip() for p in (pk or "").splitlines() if p.strip()})
    except Exception:
        packages = []
    return {"required": True, "packages": packages, "known": True}


_BOOT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}\Z")
# `systemctl is-system-running` answers one word; these are all it can say (systemctl(1)).
_SYSTEM_STATES = frozenset(("initializing", "starting", "running", "degraded", "maintenance",
                            "stopping", "offline", "unknown"))


def host_boot_identity(server):
    """{boot, mid, uptime, now, state} for a host, from ONE command, or None. Never raises.

    `boot` is the kernel's boot id, which changes on every boot and on nothing else, so it is what
    tells "the host rebooted" from "the host stopped answering for a while" — the monitor's
    down-then-up never could (a fast reboot is not seen as down at all). `mid` is the machine id,
    which tells "the same machine" from "another machine now answering at this address". `state`
    is systemd's own word for where the host is ("starting" just after a boot, "stopping" while it
    shuts down), or None where there is no systemd to ask.

    None unless the host answered with a boot id and a machine id in their own formats: the
    tailscale and local transports return ("", "...timed out", -1) without raising, and an empty
    answer is not "a boot id of nothing".
    """
    try:
        out, _err, _rc = _core.run_command(
            server, "cat /proc/sys/kernel/random/boot_id /etc/machine-id /proc/uptime; date +%s; "
                    "systemctl is-system-running 2>/dev/null || true", timeout=12, sudo=False)
    except Exception:
        return None
    return _parse_boot_identity(out)


def _parse_boot_identity(out):
    """host_boot_identity's answer from its command's output, or None when it is not one."""
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if len(lines) < 4 or not _BOOT_ID_RE.match(lines[0]) or not _MACHINE_ID_RE.match(lines[1]):
        return None
    try:
        uptime = float(lines[2].split()[0])
        now = int(lines[3])
    except (ValueError, IndexError):
        return None
    state = lines[4] if len(lines) > 4 and lines[4] in _SYSTEM_STATES else None
    return {"boot": lines[0], "mid": lines[1], "uptime": uptime, "now": now, "state": state}


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
    # uptime, df and free in the C locale: their words ("up", "Mem:") and decimal commas are
    # translated on a host set to another language, and the awk below reads them (see _core's
    # _host_sample_cmd). The MEMPCT awk too: mawk, Ubuntu's default awk, printf's a decimal comma
    # in the caller's locale ("30,2" on a German host, measured), and LC_ALL on `free` is not its.
    # One composite command with tagged lines, parsed below — one round-trip, one process spawn.
    parts = [
        "echo UPTIME $(LC_ALL=C uptime -p)",
        "awk '{print \"LOAD\",$1,$2,$3}' /proc/loadavg",
        "LC_ALL=C df -h / | tail -1 | awk '{print \"DISK\",$3\"/\"$2}'",
        "LC_ALL=C free -h | awk '/Mem:/{print \"MEM\",$3\"/\"$2}'",
        "LC_ALL=C free | LC_ALL=C awk '/Mem:/{printf \"MEMPCT %.1f\\n\", $3/$2*100}'",
        "echo KERNEL $(uname -r)",
        "echo CORES $(nproc)",
        "grep '^cpu ' /proc/stat", "sleep 0.25", "grep '^cpu ' /proc/stat",
    ]
    # sudo=False: everything read here is world-readable, and the default (the row's sudo_enabled)
    # made this poll a `sudo bash -c` on a remote, failing outright where sudo wants a password.
    out, _, _ = _core.run_command(server, " ; ".join(parts), timeout=15, sudo=False)
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


# What _wait_for_reboot answers when the host never went down: truthy like "came back", so a
# caller must test for it FIRST.
_RBWAIT_NEVER_DOWN = "never-down"


def _wait_for_reboot(server, on_wait=None, down_timeout=150, up_timeout=480):
    """After issuing a reboot, wait for the remote to drop then come back on SSH.
    Returns True if it came back online within the timeout, False if it went down and did not,
    and _RBWAIT_NEVER_DOWN if it never went down at all — a reboot that did not happen, which
    phase 2's first look would otherwise report as "back online" with the update still pending."""
    def _up():
        try:
            ok, _ = ssh_test_connection(
                server.host, server.port or 22, server.username,
                server.auth_method, decrypt_secret(server.auth_credential),
                host_key=server.host_key,   # the row's own value: an unreadable pin must refuse
            )
            return ok
        except Exception:
            return False

    # Phase 1: wait for it to actually go down (confirms the reboot began).
    t0 = time.time()
    went_down = False
    while time.time() - t0 < down_timeout:
        if not _up():
            went_down = True
            break
        if on_wait:
            on_wait("Waiting for server to go down for reboot…")
        time.sleep(5)
    if not went_down:
        return _RBWAIT_NEVER_DOWN

    # Phase 2: wait for SSH to come back.
    t0 = time.time()
    while time.time() - t0 < up_timeout:
        if _up():
            return True
        if on_wait:
            on_wait("Rebooting — waiting for server to come back online…")
        time.sleep(5)
    return False


def _node_major(text):
    """The major version in `node -v` output ("v22.3.0" -> 22), or None when there is none."""
    m = re.match(r"\s*v?(\d+)\.", text or "")
    return int(m.group(1)) if m else None


def _bootstrap_node(server):
    """Node.js 18+ and npm on a REMOTE host being prepared, for gamedig. Returns log lines.

    A Node 18+ already there is kept (Ubuntu 24.04 and 26.04 ship one). Otherwise NodeSource's
    repository is configured by the nodesource-setup verb — its signing key pinned by fingerprint,
    exactly as install.sh does on the panel host — and nodejs installed from it. This was one root
    shell running `curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -`: whoever could serve
    that URL ran code as root on the host. Now nothing downloaded is executed, and the one file
    fetched, the key, is trusted only if it is the pinned one.

    npm is installed when Node 18+ is there without it: the distro's nodejs ships without npm
    (NodeSource's bundles it), and gamedig is an npm install, so a host with a distro Node never got
    gamedig. install.sh has the same rule. Never when the Node step failed: `apt-get install npm`
    on a host without a usable Node would pull the distro's nodejs, which on 22.04 is Node 12.

    The two reads run as the connecting account (sudo=False), since neither needs root, and each
    distinguishes "not there" from "could not ask". A tailscale or local transport answers a failed
    connection with rc -1 rather than raising, and reading that as "no Node" would set NodeSource up
    over a host's working Node — so it skips the step and says so instead."""
    lines = []
    out, _, rc = _core.run_command(server, "node -v 2>/dev/null", timeout=20, sudo=False)
    if rc == -1:
        return ["Could not read this host's Node.js version (no answer) — Node.js step skipped"]
    major = _node_major(out) if rc == 0 else None
    if major is not None and major >= 18:
        lines.append("Node %s already present" % out.strip())
    else:
        ns_out, _, ns_rc = _core.run_privileged(server, "nodesource-setup", [], timeout=240)
        if ns_rc != 0:
            return [_core._last_lines(ns_out, 2) or "NodeSource's repository could not be set up",
                    "Node.js was not installed: player queries stay unavailable on this host "
                    "until Node.js 18+ is"]
        lines.append(_core._last_lines(ns_out, 1) or "NodeSource repository configured")
        in_out, _, in_rc = _core.run_privileged(server, "apt-install", ["nodejs"], timeout=600)
        lines.append(_core._last_lines(in_out, 3) or "nodejs installed")
        if in_rc != 0:
            return lines + ["Node.js install failed: player queries stay unavailable on this host "
                            "until Node.js 18+ is"]
    npm_out, _, npm_rc = _core.run_command(server, "command -v npm", timeout=20, sudo=False)
    if npm_rc == 1 and not (npm_out or "").strip():
        np_out, _, _ = _core.run_privileged(server, "apt-install", ["npm"], timeout=600)
        lines.append(_core._last_lines(np_out, 3) or "npm installed")
    elif npm_rc != 0:
        lines.append("Could not check for npm (no answer) — npm not installed")
    return lines


def _bsval_refusal(set_timezone, username):
    """Why remote_bootstrap_vps must not start with these values, or None when it may.

    An i18n.Sentence: the worker records it in English, and the route shows it translated whole.
    """
    if set_timezone:
        try:
            _priv.check_args("set-timezone", [set_timezone])
        except (_priv.VerbError, TypeError):
            return i18n.Sentence("Refused before any change: '{value}' isn't a timezone name (use one "
                                 "like Etc/UTC or America/New_York).", value=str(set_timezone)[:40])
    if username:
        try:
            if not re.match(r"^[A-Za-z_][A-Za-z0-9._-]*\Z", username):
                raise _priv.VerbError("charset")
            # user-lock-password's validator is user-create's (_managed_user: the shape, at most
            # 32 characters, never a uid-0 name); naming the create verb here would be a second
            # call site of it outside create_game_user, which part05 gates against.
            _priv.check_args("user-lock-password", [username])
        except (_priv.VerbError, TypeError):
            return i18n.Sentence("Refused before any change: '{value}' isn't a valid username (a letter "
                                 "or _, then letters, digits, . _ or -, at most 32 characters).",
                                 value=str(username)[:40])
    return None


# The "are game servers running here?" probe the bootstrap's reboot step asks, and install.sh's
# twin of it. `pgrep -x` matches the WHOLE process name, and tmux renames its server process to
# "tmux: server" — so the old `pgrep -x tmux` matched nothing on a host running four LinuxGSM
# servers (measured on the test VPS), and both places rebooted a busy host. The client is "tmux".
GAME_SESSIONS_PROBE = ("if pgrep -x 'tmux: server|tmux|SCREEN|screen' >/dev/null 2>&1; "
                       "then echo YES; else echo NO; fi")


def _r11a_why(res):
    """A failed (out, err, rc)'s reason on one line, for a bootstrap NOT DONE note."""
    out, err, rc = res
    return (err or out or "exit %s" % rc).replace("\n", " ").strip()[:160]


def _r11a_step_failed(note, not_done, res, what):
    """Record a bootstrap step whose (out, err, rc) failed, and return whether it failed.

    A failure is a NOT DONE note, and `what` in `not_done` for the final "finished, but" message.
    """
    if res[2] == 0:
        return False
    msg = i18n.Sentence("{what} ({why})", what=what, why=_r11a_why(res))
    not_done.append(msg)
    note(i18n.Sentence("NOT DONE: {why}.", why=msg))
    return True


def remote_bootstrap_vps(server, set_timezone="UTC", enable_ufw=True, install_lgsm_deps=True,
                           username="", install_fail2ban=True, do_reboot=True,
                           progress=None):
    """One-shot bootstrap of a fresh Ubuntu VPS.

    Runs: system updates → essential packages → timezone → UFW firewall →
    SSH hardening → swap → disable bloat → LinuxGSM user → fail2ban → reboot.

    `progress`, if given, is called as progress(step, total, name, status) after
    each step so the caller can stream live status ("running" / "rebooting" / ...).

    A caller that knows a game server it manages here was last seen online passes do_reboot=False:
    the reboot step then only reports a pending reboot, whatever the process probe says.

    Returns (success, message, log).
    """
    # Both values arrive raw from the request and reach verbs whose validators RAISE. Checked here,
    # before anything runs, with the verbs' own validators: found at their step, a timezone like
    # "America/New York" stopped the job after the upgrades and before UFW, SSH hardening and
    # fail2ban — a fresh internet-facing host left half prepared — and a 33-character account name
    # (the charset test below has no length cap) stopped it before fail2ban and the reboot.
    refused = _bsval_refusal(set_timezone, username)
    if refused:
        return False, refused, refused

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
    out, _, _ = _core.run_privileged(server, "apt-full-upgrade", [], timeout=1800)
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

    # ── 3a. Node.js 18+ and npm, for gamedig (v5 needs Node >=18; Ubuntu 22.04's apt ships 12) ──
    emit("Installing Node.js LTS")
    for line in _bootstrap_node(server):
        note(line)

    # ── 3b. gamedig (game-server query tool), from the panel's pinned lockfile ──
    # It was `npm install -g --ignore-scripts gamedig@5`: whatever the registry served that day.
    # install_gamedig pushes tools/gamedig's lockfile and installer and runs it; `npm ci` checks
    # every package against the lockfile's sha512. Then the weekly cron that re-runs it, AFTER the
    # files it names are there.
    emit("Installing gamedig (game server query tool)")
    gd_out, gd_rc = install_gamedig(server)
    note(_core._last_lines(gd_out, 3) or ("gamedig installed" if gd_rc == 0
                                          else "gamedig could not be installed"))
    if _write_node_tools_cron(server):
        note("weekly gamedig check scheduled (re-installs it from the pinned lockfile if it breaks)")
    else:
        note("the weekly gamedig check could not be scheduled")

    # ── 3c. Enable + configure unattended-upgrades (auto security updates) ──
    emit("Enabling automatic security updates (unattended-upgrades)")
    au_conf = (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
        'APT::Periodic::Download-Upgradeable-Packages "1";\n'
    )
    _au = _core.write_root_file(server, "apt-auto-upgrades", au_conf, timeout=30)
    if _au[2] == 0:
        _au = _core.run_privileged(server, "service-enable-now", ["unattended-upgrades"], timeout=30)

    # Steps that ran and FAILED, by their exit codes: each is "finished, but", never "complete".
    # The timezone, swap and fail2ban steps discarded their tuples and logged success — a typo'd
    # timezone, a full disk, a fail2ban that never installed all read "VPS bootstrap complete".
    # So did automatic security updates (above): neither the config write nor the enable was read.
    not_done = []
    _r11a_step_failed(note, not_done, _au, i18n.Sentence("automatic security updates were not enabled"))

    # ── 4. Set timezone ──
    if set_timezone:
        emit(i18n.Sentence("Setting timezone to {tz}", tz=set_timezone))
        # set_timezone is user-supplied and runs as root — quote it against injection.
        _tz = _core.run_privileged(server, "set-timezone", [set_timezone], timeout=10)
        _r11a_step_failed(note, not_done, _tz, i18n.Sentence("the timezone was not set to {tz}", tz=set_timezone))

    # ── 5. Configure UFW ──
    ufw_not_enabled = None
    ufw_enable_failed = ""
    # The ports SSH answers on, read ONCE for both steps that name them (UFW here, fail2ban's jail
    # at step 10). Both said 22: a host whose sshd had been moved to 2222 had UFW switched on at
    # deny-incoming with only 22 let in — the panel's next connection, and the operator's, met a
    # closed port — and its fail2ban jail banned on a port nothing listened on.
    ssh_ports = _bootstrap_ssh_ports(server) if (enable_ufw or install_fail2ban) else []
    if enable_ufw:
        emit(i18n.Sentence("Configuring UFW firewall (deny incoming, rate-limit SSH on port {ports})",
                           ports=", ".join(ssh_ports)))
        # Rate-limit SSH by default — `ufw limit` allows SSH (so we never lock ourselves
        # out) while throttling brute-force sources. We do NOT add a plain `allow 22`:
        # a lower-numbered allow rule would match first and shadow the limit, leaving SSH
        # effectively unthrottled. EVERY SSH port, and all of them before anything is removed or
        # switched on: one that failed would be a port UFW is about to close.
        _l_rc, _l_why = 0, ""
        for _sp in ssh_ports:
            _l_out, _l_err, _l_rc = _core.run_privileged(server, "ufw-limit-port", ["%s/tcp" % _sp],
                                                         timeout=15)
            if _l_rc != 0:
                _l_why = i18n.Sentence("`ufw limit {port}/tcp` failed ({why})", port=_sp,
                                       why=(_l_err or _l_out or "exit %s" % _l_rc).replace("\n", " ").strip()[:160])
                break
        if _l_rc == 0:
            # The same goes for `ufw allow OpenSSH` / a bare `ufw allow 22` already on the host:
            # to ufw neither is the `22/tcp` rule above, so the limit is appended AFTER them and
            # never reached. Removed only now that the limit is in place, so SSH is never left
            # unallowed — and only when 22 IS one of the ports just limited.
            if "22" in ssh_ports:
                for _verb, _args in _SSH22_SHADOWING:
                    _core.run_privileged(server, _verb, _args, timeout=15)
            # Read, both: a container-class VPS whose `ufw --force enable` fails ("problem running
            # ufw-init") or times out was reported "VPS bootstrap complete" with its firewall off.
            _dd = _core.run_privileged(server, "ufw-default", ["deny", "incoming"], timeout=15)
            _core.run_privileged(server, "ufw-default", ["allow", "outgoing"], timeout=15)
            _en = _core.run_privileged(server, "ufw-enable", [], timeout=15)
            # Worded apart: a failed default with `ufw enable` at 0 leaves UFW ON, so "the
            # firewall was NOT enabled" was false there; what failed is the incoming policy.
            if _en[2] != 0:
                ufw_enable_failed = i18n.Sentence("the firewall was NOT enabled: `ufw enable` failed ({why})",
                                                  why=_r11a_why(_en))
                note(i18n.Sentence("NOT DONE: {why} — the firewall is not protecting this host.",
                                   why=ufw_enable_failed))
            elif _dd[2] != 0:
                ufw_enable_failed = i18n.Sentence("UFW is on, though its default incoming policy could not be set to "
                                                  "deny: `ufw default deny incoming` failed ({why})", why=_r11a_why(_dd))
                note(i18n.Sentence("NOT DONE: {why} — run `ufw status verbose` on the host to see the "
                                   "policy in force.", why=ufw_enable_failed))
        else:
            # The limit's exit code was never read, so when it failed the rules that DO let SSH in
            # were deleted "now that the limit is in place" and UFW was switched on at deny-incoming
            # — a fresh host cut off from SSH mid-bootstrap. Nothing is removed and the firewall is
            # left as it was; the job says so rather than "complete".
            ufw_not_enabled = _l_why
            note(i18n.Sentence("NOT DONE: {why}. UFW was left as it was — turning it on without a rule "
                               "letting SSH in would lock this host out.", why=ufw_not_enabled))

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
        note(i18n.Sentence("NOT IN EFFECT: sshd reports {key} as '{got}', not '{want}' — something it "
                           "reads first overrides the edit (usually a file in /etc/ssh/sshd_config.d).",
                           key=_key, got=_got or "unset", want=_want))
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
            _sw = _core.run_privileged(server, "create-swapfile", [], timeout=60, merge_stderr=False)
            if not _r11a_step_failed(note, not_done, _sw, i18n.Sentence("the swap file was not created")):
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
    # (Refused up front by _bsval_refusal, with the user-create verb's own length cap; the test
    # stays here so this step can never be the one that lets a bad name through.)
    user_msg = ""
    if username and not re.match(r"^[A-Za-z_][A-Za-z0-9._-]*\Z", username):
        note(i18n.Sentence("Skipped account creation: '{user}' isn't a valid username", user=username[:32]))
    elif username:
        emit(i18n.Sentence("Creating LinuxGSM user: {user}", user=username))
        out, _, _ = _core.run_command(server, f"id {_core._quote(username)} 2>/dev/null && echo 'EXISTS' || echo 'NOTEXISTS'", timeout=10)
        out = out or ""
        # Same correction: an unread probe is not "the account is already there". Reading it that
        # way SKIPPED the account creation below, and the bootstrap then carried on against a user
        # that does not exist. Nor is it "the account is NOT there": that fell into the create
        # branch, whose `useradd` then failed on an existing account while `passwd -l` still
        # locked it — the operator's own password login, if that is the name they typed.
        if "NOTEXISTS" not in out and "EXISTS" in out:
            note(i18n.Sentence("User {user} already exists", user=username))
        elif "NOTEXISTS" in out:
            _cu_out, _cu_err, _cu_rc = _core.create_game_user(server, username, timeout=15)
            if _cu_rc != 0:
                user_msg = i18n.Sentence("the account {user} was not created ({why})", user=username,
                                         why=(_cu_err or _cu_out or "exit %s" % _cu_rc).replace("\n", " ").strip()[:160])
                note(i18n.Sentence("NOT DONE: {why}; its password was not touched.", why=user_msg))
            else:
                _lk_out, _lk_err, _lk_rc = _core.run_privileged(server, "user-lock-password",
                                                                [username], timeout=10)
                if _lk_rc != 0:
                    user_msg = i18n.Sentence("the account {user} was created but its login password could not be locked",
                                             user=username)
                    note(i18n.Sentence("NOT DONE: {why}.", why=user_msg))
                else:
                    note(i18n.Sentence("User {user} created (login password locked)", user=username))
        else:
            user_msg = i18n.Sentence("the account {user} was not created: the host did not answer whether it "
                                     "already exists", user=username)
            note(i18n.Sentence("NOT DONE: {why}.", why=user_msg))

    # ── 10. Configure fail2ban ──
    if install_fail2ban:
        emit("Configuring fail2ban (SSH brute-force protection)")
        # The ports sshd answers on, not 22: this file is also where change_ssh_port keeps
        # `port = <new>,<old>`, and writing 22 over it pointed every ban at a port nothing served.
        jail_content = (
            "[DEFAULT]\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\n\n"
            "[sshd]\nenabled = true\nport = %s\n" % ",".join(ssh_ports)
        )
        # Each read, and the first that fails is the step's answer: a fail2ban whose package
        # install failed at step 3 got its jail written, `enable --now` failed, and the job said
        # SSH brute-force protection was configured.
        for _f2b_call, _f2b_what in (
                (lambda: _core.write_root_file(server, "fail2ban-jail-local", jail_content,
                                               timeout=15), i18n.Sentence("its jail could not be written")),
                (lambda: _core.run_privileged(server, "service-enable-now", ["fail2ban"],
                                              timeout=20), i18n.Sentence("it could not be started")),
                (lambda: _core.run_privileged(server, "service-restart", ["fail2ban"],
                                              timeout=20), i18n.Sentence("it could not be restarted"))):
            if _r11a_step_failed(note, not_done, _f2b_call(),
                                 i18n.Sentence("fail2ban is not protecting SSH: {what}", what=_f2b_what)):
                break

    # ── 11. Reboot ONLY if an update actually requires one, and NEVER out from under running game
    #        servers (a reboot would drop the players). We check /var/run/reboot-required and, before
    #        rebooting, that no tmux/screen game-server sessions are live — otherwise we just flag the
    #        pending reboot so the operator can do it when the host is empty. ──
    reboot_msg = ""
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
        gs_out, _, _gs_rc = _core.run_command(server, GAME_SESSIONS_PROBE, timeout=10)
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
                 detail=("A kernel/library update needs a reboot. Reboot this host from its "
                         "Power card: running game servers are stopped cleanly first, and its "
                         "dialog lists which come back.") if gs_known else
                        ("A kernel/library update needs a reboot. The host did not answer the "
                         "check for running game servers, so it was not rebooted — a reboot "
                         "would drop any players on it. Reboot it from its Power card: running "
                         "game servers are stopped cleanly first, and its dialog lists which "
                         "come back."))
        else:
            emit("Rebooting to apply a kernel/library update", status="rebooting",
                 detail="A system update requires a reboot and no game servers are running.")
            # Schedule the reboot slightly in the future so this command returns cleanly.
            # Its rc and the host going down are both read: a refused or timed-out reboot left the
            # host up, phase 2's first look said "back online", and the job reported "complete"
            # with the kernel update still waiting for a reboot nobody was told about.
            _rb_out, _rb_err, _rb_send_rc = _core.run_privileged(server, "reboot-delayed", [],
                                                                 timeout=15, merge_stderr=False)
            if _rb_send_rc != 0:
                reboot_msg = i18n.Sentence("the reboot a kernel/library update needs was not sent ({why}) — reboot this "
                                           "host from its Power card",
                                           why=(_rb_err or _rb_out or "exit %s" % _rb_send_rc).replace("\n", " ").strip()[:160])
                note(i18n.Sentence("NOT DONE: {why}.", why=reboot_msg), status="reboot-required")
            else:
                _core.close_connection(server)
                came_back = _wait_for_reboot(server, on_wait=lambda t: note(t, status="rebooting"))
                if came_back == _RBWAIT_NEVER_DOWN:
                    reboot_msg = i18n.Sentence("the host never went down for the reboot a kernel/library update needs — "
                                               "reboot it from its Power card")
                    note(i18n.Sentence("NOT DONE: {why}.", why=reboot_msg), status="reboot-required")
                elif not came_back:
                    return False, "Server was rebooted but did not come back online within the timeout.", "\n".join(log)
                else:
                    note("Server is back online.", status="running")
    else:
        note("Reboot check skipped — this is the panel's own host.")

    # The same reasoning for a firewall that was asked for and not switched on: a door left open.
    ufw_msg = (i18n.Sentence("the firewall was NOT enabled: {why}, and turning UFW on without a rule letting "
                             "SSH in would have locked this host out. Fix ufw on the host and run the "
                             "bootstrap again.", why=ufw_not_enabled) if ufw_not_enabled else
               i18n.Sentence("{why}. Fix ufw on the host and run the bootstrap again.", why=ufw_enable_failed)
               if ufw_enable_failed else "")
    # Steps that were asked for and did not happen; each is "finished, but", never "complete".
    # The clauses that did not happen, each a Sentence, joined by a translated "; and " (i18n.Sentences).
    _undone = [m for m in [ufw_msg] + not_done + [user_msg, reboot_msg] if m]
    ufw_msg = i18n.Sentences(*_undone, sep="; and ") if _undone else ""
    if hardening_failed:
        # Not "complete": the one step whose whole point is closing a door reported the door is
        # still open. The rest of the work did happen, and the message says both.
        return False, i18n.Sentences(i18n.Sentence(
            "Bootstrap finished, but the SSH hardening did not take effect: sshd still reports {settings}. "
            "Something sshd reads first overrides the edit — look in /etc/ssh/sshd_config.d (cloud images ship "
            "50-cloud-init.conf).", settings="; ".join("%s %s" % kv for kv in hardening_failed)),
            i18n.Sentence("And {rest}", rest=ufw_msg) if ufw_msg else ""), "\n".join(log)
    if ufw_msg:
        return False, i18n.Sentence("Bootstrap finished, but {rest}", rest=ufw_msg), "\n".join(log)
    if progress:
        try:
            progress(total, total, "Bootstrap complete", "done")
        except Exception:
            _core._log.debug("remote_bootstrap_vps: ignored non-fatal error", exc_info=True)
    if hardening_unverified:
        return True, i18n.Sentence("VPS bootstrap complete ({step}/{total} steps), but the SSH hardening could "
                                   "not be verified — sshd's effective configuration was unreadable. Check "
                                   "`sshd -T` on the host for passwordauthentication.", step=step,
                                   total=total), "\n".join(log)
    return True, i18n.Sentence("VPS bootstrap complete ({step}/{total} steps).", step=step,
                               total=total), "\n".join(log)


# ─── Remote Tailscale Bootstrap ─────────────────────────────


def remote_check_tailscale(server):
    """Check if Tailscale is already installed and running on the remote."""
    # sudo=False here and below: neither `which` nor `tailscale status` needs root (tailscaled's
    # LocalAPI answers reads to any local user), and a sudo that wants a password made the host
    # read as unreachable.
    installed_out, _, installed_rc = _core.run_command(
        server, "which tailscale 2>/dev/null && echo 'INSTALLED' || echo 'NOTINSTALLED'", timeout=10, sudo=False)
    # BOTH halves, and the same shape manage_servers.py already uses for its `id` probe:
    # `"NOTEXISTS" not in idout and "EXISTS" in idout`. A bare negative test reads an EMPTY answer
    # as the positive one — "NOTINSTALLED" is not in "", so a probe that never ran said Tailscale
    # IS installed. run_command returns ("", "...timed out", -1) rather than raising for the local
    # and Tailscale transports, so that is the ordinary unreachable case, not a rare one.
    installed = ("NOTINSTALLED" not in installed_out    # "INSTALLED" is a substring of it
                 and "INSTALLED" in installed_out)
    # ...but "not installed" is itself only a reading when the probe ANSWERED — one sentinel or the
    # other. An empty answer came back as {"installed": False}, and the Tailscale modal printed
    # "Tailscale is not installed on <host>" with an Install button, about a host nobody reached.
    # `installed` stays falsy so every existing caller keeps refusing; `unreachable` says why.
    unread = "INSTALLED" not in (installed_out or "")

    running = False
    ts_ip = ""
    dns_name = ""
    if installed:
        out, _, rc = _core.run_command(server, "tailscale status --json 2>/dev/null || echo '{}'", timeout=10,
                                       sudo=False)
        # `|| echo '{}'` makes an answered failure "{}", so nothing at all is the probe not running
        # — not "installed but not running", which offers to re-authenticate the node.
        unread = unread or not (out or "").strip()
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

    res = {
        "installed": installed,
        "running": running,
        "tailscale_ip": ts_ip,
        "dns_name": dns_name,
    }
    if unread:
        res["unreachable"] = True
    return res


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
    # NOT a verb: this pipes a downloaded script into a root shell, and that IS the operation. A verb
    # could pin the URL, but only by giving the helper the ability to execute a downloaded script —
    # the capability its tool allowlist exists to deny. (The NodeSource step used to be the same
    # shape; it now fetches only a signing key, pinned by fingerprint — see _bootstrap_node.)
    # --proto '=https': the script goes straight into a root shell with nothing to check it
    # against, and -L follows redirects, so the least it can do is refuse any hop that is not
    # HTTPS — a downgraded or redirected-to-plain-http fetch is a script anyone on the path wrote.
    cmds = [
        "curl --proto '=https' -fsSL https://tailscale.com/install.sh | sh 2>&1",
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


# The one body of /etc/sysctl.d/99-tailscale.conf, for both ways of joining. The login-link flow
# wrote IPv4 forwarding alone over the file the auth-key flow writes with both families, so an
# IPv6 route it advertised carried nothing, and re-running it on a host joined by key dropped that
# host's IPv6 forwarding at the next reboot.
_R19A_TS_FORWARDING = "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"


def _r19a_enable_forwarding(server):
    """Write the forwarding drop-in and load it: the (out, err, rc) of the step that decided."""
    res = _core.write_root_file(server, "sysctl-tailscale", _R19A_TS_FORWARDING, timeout=15)
    if res[2] == 0:
        res = _core.run_privileged(server, "sysctl-reload", ["tailscale"], timeout=15)
    return res


# Said instead of joining when the route list is not one: before any root write on the host.
_R20A_BAD_ROUTES = "Routes must be comma-separated networks, e.g. 192.168.1.0/24,10.0.0.0/24"


def _r20a_routes_or_none(advertise_routes):
    """The route list as the verb will take it ("" for none), or None when it is not one.

    Checked BEFORE IP forwarding is switched on. Both joins wrote and loaded the forwarding drop-in
    first and only then handed the list to the verb, whose validator refused `a, b` (the space)
    with a VerbError: the host was left forwarding IPv4 and IPv6 with nothing joined, and the
    key flow told the operator their auth key was bad. Spaces around the commas are dropped, as a
    person types a list; anything else the verb's own validator refuses is refused here first.
    """
    text = ",".join(p.strip() for p in (advertise_routes or "").split(","))
    if text in ("", "-"):     # "-" is the verb's own "no routes"; it switched forwarding on
        return ""
    try:
        routes = _priv._routes(text)
        # ...and what `tailscale up` refuses after it: the verb takes an address (`10.0.0.1`) or a
        # prefix with host bits (`192.168.1.5/24`, a gateway typed for its LAN), and tailscale's
        # CalcAdvertiseRoutes refuses both — so the host was left forwarding with nothing joined.
        for part in routes.split(","):
            if "/" not in part:
                return None
            _ipaddress.ip_network(part, strict=True)
    except (_priv.VerbError, ValueError):
        return None
    return routes


def remote_tailscale_up_url(server, enable_ssh=True, advertise_routes=""):
    """Run `tailscale up` (no auth key) in the background and return the browser
    login URL — the user just pastes it into their browser to authorize the node,
    exactly like `tailscale up` on the CLI. tailscale up keeps waiting for auth."""
    advertise_routes = _r20a_routes_or_none(advertise_routes)
    if advertise_routes is None:
        return False, i18n.Sentence(_R20A_BAD_ROUTES)
    if advertise_routes:
        # Read, as the auth-key flow reads it: this answer carries only the login URL, so a failed
        # write or reload goes to the log rather than passing unseen.
        _fw = _r19a_enable_forwarding(server)
        if _fw[2] != 0:
            _core._log.warning("IP forwarding was NOT enabled on %s (%s): the advertised routes will "
                               "not carry traffic", getattr(server, "name", "?"), _r11a_why(_fw))
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
    advertise_routes = _r20a_routes_or_none(advertise_routes)
    if advertise_routes is None:
        return False, i18n.Sentence(_R20A_BAD_ROUTES), "\n".join(log)
    # Every argument through the verb's own validator BEFORE forwarding is switched on: a key the
    # boundary refuses (a stray quote, a truncated paste) raised its VerbError only at the join,
    # with IPv4 and IPv6 forwarding already written and loaded. Raised as it was, so the route's
    # answer ("That isn't a usable Tailscale auth key.", a 400) is unchanged.
    _priv.check_args("tailscale-up-key", [auth_key, "yes" if enable_ssh else "no",
                                          advertise_routes or "-", tags or "-"])

    # 1. Enable IP forwarding for subnet routing
    if advertise_routes:
        _fw = _r19a_enable_forwarding(server)
        # Read, not assumed: a write or reload that failed was logged "IP forwarding enabled", and
        # the advertised routes then carried nothing with no word of why.
        log.append("IP forwarding enabled" if _fw[2] == 0
                   else "IP forwarding was NOT enabled (%s): the advertised routes will not carry "
                        "traffic" % _r11a_why(_fw))

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
        return False, i18n.Sentence("Tailscale auth failed: {why}", why=err or out[-200:]), "\n".join(log)

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
        return True, i18n.Sentence("Tailscale connected! IP: {ip} DNS: {dns}", ip=status['tailscale_ip'],
                                   dns=status['dns_name']), "\n".join(log)
    else:
        return False, "Tailscale installed but not running after auth", "\n".join(log)


def remote_migrate_to_tailscale(server, new_auth_method="tailscale", refuse=None):
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
    # The caller's say on the address before anything on the host changes (the public port 22 rule
    # is deleted below): `refuse(new_host)` -> why the record may not move there, or None. The
    # route refuses an address another host row already uses (remotes.r36c_same_host_refusal).
    why = refuse(new_host) if refuse is not None else None
    if why:
        return None, why

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
                      "the panel would have no way back in once public SSH is closed. Run "
                      "`tailscale set --ssh` on the host, then try again.")
    _login_ok, _login_msg = ssh_test_connection(new_host, 22, server.username,
                                                auth_method="tailscale")
    if not _login_ok:
        # A Sentence, so the route can show it whole in the viewer's language: %-spliced, the
        # English matched no catalog key and es/fr viewers read it in English.
        return None, i18n.Sentence("Tailscale SSH did not work from here, so the migration stopped "
                                   "before changing anything: {why}", why=_login_msg)

    # Verified: the tailnet really is a way in. NOW the public door can close.
    try:
        _r15c_delete_port_22(server)
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
        # The log line is the caller's evidence that the rule went in (the route reports
        # ufw_allowed = bool(log), to the UI and the audit row), so it follows the allow's exit
        # code. It was appended whatever the allow answered: a refused or timed-out rule read as
        # "UFW now allows tailscale0" on a firewall that still blocks it.
        a_out, a_err, a_rc = _core.run_privileged(server, "ufw-allow-iface", ["tailscale0"],
                                                  timeout=15)
        if a_rc == 0:
            log.append("UFW: allowed tailscale0 interface (in)")
        else:
            _core._log.warning("tailscale finalize: allowing tailscale0 in UFW failed on %s "
                               "(rc=%s): %s", getattr(server, "name", "?"), a_rc,
                               (a_err or a_out or "")[:200])
    status = remote_check_tailscale(server)
    return status, "\n".join(log)


def remote_ufw_close_port_22(server):
    """Remove the public UFW rules for every port sshd serves (safe if Tailscale SSH is active).

    Only on a firewall that is on: with UFW inactive (or unread) this answered "Port 22 rule removed
    from UFW", true of the stored rules, while nothing filtered port 22 and it stayed open.
    remote_set_public_ssh refuses the same state with the same words.

    Every port sshd serves, not 22: after the panel's own port move (change_ssh_port) the port the
    public reaches sshd on is the new one, and closing only 22 answered "removed" with SSH still open
    to the internet on it (_r32b_public_ssh_ports has the details). Refused when those ports cannot
    be read, rather than closing a guessed 22.
    """
    state = remote_public_ssh_status(server)
    if state.get("unreachable"):
        return False, ("Could not read this host's firewall, so public SSH was not closed — check the "
                       "host and try again.")
    if not state.get("active"):
        return False, ("UFW is not active on this host, so public SSH cannot be controlled from "
                       "here — the SSH port is governed by whatever else is in front of it.")
    ports = state.get("ssh_ports") or []
    if not ports:
        return False, _R32B_PORTS_UNREAD
    _r15c_delete_port_22(server, ports)
    # ASK THE HOST, as remote_set_public_ssh(..., "off") does. This answered from the delete's exit
    # code, and ufw exits 0 deleting a rule that is not there ("Could not delete non-existent
    # rule", measured on the test VPS). Every host the panel bootstrapped holds SSH open with
    # `22/tcp LIMIT`, which no `delete allow` matches, so "Close Port 22" said "Port 22 rule removed
    # from UFW", wrote a success audit row, and left port 22 open to the internet.
    after = remote_public_ssh_status(server)
    refused = _r32b_after_refusal(after)
    if refused is not None:
        return False, refused
    if after.get("mode") != "off":
        # The rule still in the way is one the panel does not remove: a port list, a destination,
        # an every-port allow. Named, so the operator can find it on the Firewall page.
        return False, i18n.Sentence("Port {port} is still open to the public: connections meet `{rule}` first — "
                                    "remove or narrow that rule.", port=after.get("rule_port") or "?",
                                    rule=after.get("rule") or "?")
    return True, i18n.Sentence("Public SSH rules removed from UFW (port {ports})",
                               ports=", ".join(str(p) for p in ports))


def _r15c_delete_port_22(server, ports=None):
    """Delete every public rule the panel knows opens SSH, unchecked; the caller reads back.

    Also the Tailscale migration's last step, which has proved its own way back in and removes the
    stored rules whether or not UFW is on. It deleted only `allow 22/tcp`, so a bootstrapped host
    (`22/tcp LIMIT`) kept its public door after a migration that said it closed it. Exit codes are
    not read: ufw answers 0 for a rule that was never there, so they say nothing either way.

    `ports`: the SSH ports to close (_r32b_public_ssh_ports). Read here when not given, and 22 when
    that read fails: the migration, which closes behind a proven tailnet login, closed 22 before
    this read existed, and closing less than it did is not what an unread port list should do.
    """
    if ports is None:
        ports = _r32b_public_ssh_ports(server)[1] or [22]
    for verb, vargs in _r32b_ssh_rule_steps(ports, "off"):
        _core.run_privileged(server, verb, vargs, timeout=15)


def _bootstrap_ssh_ports(server):
    """The ports SSH must stay reachable on when the bootstrap switches UFW on and writes the
    fail2ban jail: every port sshd's effective config names, plus the one the panel connects on.

    The stored port is unioned in, not only used as the empty-read fallback: under socket
    activation `sshd -T` prints sshd_config's Port while ssh.socket listens elsewhere (see
    change_ssh_port), and the port the panel reached the host on is the one whose loss locks
    everybody out. An unread `sshd -T` leaves just that port — never nothing, which would switch
    UFW on at deny-incoming with SSH shut."""
    ports = []
    for p in _sshd_current_ports(server) + [str(int(getattr(server, "port", 22) or 22))]:
        if p not in ports:
            ports.append(p)
    return ports


def _sshd_current_ports(server):
    """Return the ports sshd currently listens on. Empty on failure.

    ssh.socket's while that unit holds the listening socket, else its *effective* config's.
    """
    # Under socket activation `sshd -T` prints sshd_config's Port, which systemd ignores, so a port
    # the panel moved sshd to lives only in ssh.socket. Every caller unioned in the stored port to
    # cover that, and on a host the panel reaches over Tailscale SSH the stored port stays 22
    # whatever sshd serves: a second move dropped the first move's port from the drop-in (while
    # saying "the previous port is still available"), the bootstrap and the firewall's protection
    # stopped counting it, and a game server could take it.
    #
    # REPLACED, not unioned, as sshd_listen_ports does: with sshd moved off 22, `sshd -T` still says
    # 22, and counted as served, a leftover `22/tcp ALLOW` read as another way in, so the rule for
    # the port sshd really serves came back warn instead of protected and could be deleted.
    # change_ssh_port, for which more is the safe direction, unions `sshd -T` back in itself.
    sock = _r26b_socket_ports(server)
    return list(sock) if sock else _r26b_sshd_t_ports(server)


def _r26b_sshd_t_ports(server):
    """The Port lines of sshd's effective config (`sshd -T`), as strings. Empty on failure."""
    # Was `sshd -T | awk 'tolower($1)=="port"{print $2}'` — an awk program running as root to do
    # what a list comprehension does. The verb returns the effective config; the parsing is here.
    out, _, _ = _core.run_privileged(server, "sshd-effective-config", [], timeout=15, merge_stderr=False)
    ports = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "port" and parts[1].isdecimal():
            ports.append(parts[1])
    return ports


def sshd_listen_ports(server):
    """The ports sshd serves, as ints, for the host page: [] when they could not be read.

    ssh.socket's own list while it holds the socket (sshd_config's Port is ignored then), else
    `sshd -T`'s. Not the stored port: on a host the panel reaches over Tailscale SSH that stays 22,
    the port tailscaled answers on, whatever sshd listens on.
    """
    return [int(p) for p in _sshd_current_ports(server)]


# What systemd reports for ssh.socket: whether it is active, and every address it listens on.
# Read-only and world-readable (no sudo), in the C locale like every read parsed by its words.
_R26B_SOCKET_SHOW = _core._R19A_C_LOCALE + "systemctl show ssh.socket -p ActiveState -p Listen"


def _r26b_socket_ports(server):
    """The TCP ports ssh.socket listens on, as strings, when it is the active listener; else None.

    None too when systemd could not be read: the callers then keep what they had (sshd -T, and the
    stored port). systemd prints one `Listen=<address>:<port> (Stream)` line per socket, after the
    panel's drop-in and Ubuntu's sshd-socket-generator have been applied, so this is what is
    actually bound — the one reading that names a port the panel moved sshd to on such a host.
    """
    try:
        out, _err, rc = _core.run_command(server, _R26B_SOCKET_SHOW, timeout=15, sudo=False)
    except Exception:
        _core._log.debug("ssh.socket's listen addresses could not be read", exc_info=True)
        return None
    return _r26b_listen_ports(out) if rc == 0 else None


def _r26b_listen_ports(out):
    """`systemctl show -p ActiveState -p Listen` output's TCP ports while active, else None."""
    lines = [ln.strip().partition("=") for ln in (out or "").splitlines()]
    if ("ActiveState", "=", "active") not in lines:
        return None
    ports = []
    for port in (_r26b_stream_port(val) for key, _eq, val in lines if key == "Listen"):
        if port and port not in ports:
            ports.append(port)
    return ports or None


def _r26b_stream_port(listen):
    """The TCP port of one systemd `Listen=` value (`[::]:22 (Stream)`), as a string, or None."""
    addr, _sp, kind = listen.partition(" ")
    port = addr.rpartition(":")[2]
    if kind != "(Stream)" or not re.fullmatch(r"[0-9]{1,5}", port):
        return None
    return str(int(port))


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
    remote helpers already normalised; the unban one compared the raw string.

    An IPv6 zone id is refused: ipaddress kept it verbatim, so "canonical" was request text, and it
    reached fail2ban-client's argv through the root helper."""
    return canonical_ip(s)


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
    to its canonical ipaddress form, with a zone id refused, so nothing request-supplied reaches the
    shell unchecked. (ok, msg)."""
    ip = canonical_ip(ip)
    if ip is None:
        return False, "Invalid IP address."
    tag = re.sub(r"[^a-z0-9-]", "", (tag or ""))[:32] or _UFW_BLOCK_TAG
    # The same decision as the panel host's ufw_deny_ip — one implementation, so the twins cannot
    # drift. It used to delete any deny for the address first, whoever wrote it (see
    # system_ops._ufw_deny_with for what that cost); a rule the panel did not write is left alone.
    from panel.ops import system_ops as _so
    # Read and write under the host's ufw_lock: what _ufw_deny_with decides (replace, re-tag,
    # leave) is decided from this read, and it deletes and inserts by what the read found.
    with _core.ufw_lock(server):
        shadowed = {}
        existing = (remote_ufw_blocked_ips(server, shadowed) or {}).get(ip)
        return _so._ufw_deny_with(
            ip, tag, existing,
            lambda verb, args: _core.run_privileged(server, verb, args, timeout=20),
            shadowed.get(ip))


def remote_ufw_undeny_ip(server, ip):
    """Remove a UFW deny rule for an IP (canonicalised first, a zone id refused). (ok, msg)."""
    ip = canonical_ip(ip)
    if ip is None:
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
    with _core.ufw_lock(server):
        out, err, rc = _core.run_privileged(server, "ufw-delete-deny-ip", [ip], timeout=15)
        if rc != 0:
            return False, ((out or err or "Unblock failed").replace("\n", " ")[:200])
        # rc 0 is not "unblocked" either: ufw exits 0 when no rule matched ("Could not delete
        # non-existent rule", measured on the test VPS), and `delete deny from <ip>` matches only a
        # plain deny, not a REJECT or a deny scoped to a port. So the firewall is read again under
        # the same lock, and an address it still lists as blocked is not reported unblocked — the
        # panel host's ufw_undeny_ip does the same. A read that fails says nothing either way, and
        # the delete's own answer stands — unless that answer is that it removed nothing.
        blocked = remote_ufw_blocked_ips(server)
    return _r26b_unblock_answer(ip, out, blocked)


def _r26b_unblock_answer(ip, out, blocked):
    """An unblock's answer once its delete exited 0 with output `out`; `blocked` is the read-back.

    For both hosts (system_ops.ufw_undeny_ip too). `blocked` is None when the firewall could not be
    listed (unreadable, or inactive, which lists no rules). A delete that removed nothing with no
    listing to read was still "Unblocked", the case close-port already refuses (_r23b_closed_answer):
    a deny the delete did not match — a REJECT, one scoped to a port — went on blocking the address.
    """
    if blocked is not None and ip in blocked:
        return False, i18n.Sentence("{ip} is still blocked: the firewall rule that blocks it is not a plain "
                                    "deny from that address, which is the only kind the panel removes. "
                                    "Remove it on the host.", ip=ip)
    if blocked is None and _r23b_deleted_nothing(out):
        return False, i18n.Sentence("No deny rule for {ip} matched, so nothing was removed, and the firewall's "
                                    "rules could not be listed to say whether another one still blocks it.",
                                    ip=ip)
    return True, i18n.Sentence("Unblocked {ip}.", ip=ip)


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
    # A cut read keeps the FIRST bytes — the oldest days — so its tally undercounts the recent
    # offenders, and the auto-block reconcile RELEASES any block whose IP falls below the threshold:
    # on a busy host a cut read unblocked the attackers it was built to hold. Unread, not partial.
    # Decided from the rc, as on the panel host: the remote form stops at the helper's own ceiling
    # and exits 3 (privileged._f2b_log_lines_remote). It was the answer's length — anything within
    # 64 KB of the transport's cap — which also threw away a complete log just under it.
    if _so._f2b_unread(rc, "remote attempt counts"):
        return None
    return _so._tally_f2b_events(out)[0]


def remote_fail2ban_top_ips(server, limit=20, days=7):
    """Top offending IPs from a REMOTE host's fail2ban log over the last `days` days (current +
    rotated logs), ranked by detected attempts. Each: {ip, attempts, bans, banned_now, blocked}.
    Fixed counting pipeline (no request input in the shell). Best-effort ([] on failure)."""
    from datetime import datetime, timedelta
    try:
        limit = max(1, min(int(limit or 20), 100))
    except (TypeError, ValueError, OverflowError):
        limit = 20
    try:
        days = max(1, min(int(days or 7), 90))
    except (TypeError, ValueError, OverflowError):
        days = 7
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")   # panel clock; no shell input
    # The remote twin of system_ops.fail2ban_top_ips, which #118 converted. Same split: the verb
    # reads and filters the rotated logs, and the tally — the second awk — is the shared Python.
    from panel.ops import system_ops as _so
    # None, not [], when the read FAILED — see system_ops.fail2ban_top_ips for why the two have to
    # be distinguishable. On a local or Tailscale-SSH host a timeout does not raise: the transport
    # returns ("", "...timed out", -1), so without the rc this looked exactly like "no offenders".
    # rc 3 is a read cut at the ceiling: unread too, and said so, as fail2ban_top_ips answers it.
    out, _, rc = _core.run_privileged(server, "f2b-log-lines", [cutoff], timeout=25,
                                      merge_stderr=False)
    if _so._f2b_unread(rc, "remote top-ips"):
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
        return True, i18n.Sentence("Unbanned {ip} from {jail}.", ip=ip, jail=jail)
    return False, ((out or err or "Unban failed").replace("\n", " ")[:200])


def _f2b_dropin_ignoreip_body(ignore_ips):
    """A fail2ban `[DEFAULT] ignoreip` drop-in body built from validated entries only (localhost is
    always included). The panel host's own copy of the file is built by the same function
    (system_ops.f2b_whitelist_dropin_body), so the two cannot validate differently: this one used
    to re-parse entries through ipaddress alone, which keeps an IPv6 zone id verbatim — newline
    and all — where the panel host's builder drops it."""
    from panel.ops.system_ops import f2b_whitelist_dropin_body
    return f2b_whitelist_dropin_body(ignore_ips)


# remote_set_fail2ban_ignoreip's answer for a host with no fail2ban: nothing to apply, not a failure.
F2B_NOT_INSTALLED = "fail2ban not installed on this host"


def remote_set_fail2ban_ignoreip(server, ignore_ips, unban_ip=None):
    """Make a REMOTE host's fail2ban ignore the panel whitelist, so a whitelisted IP is never banned
    on ANY of that host's jails (sshd included) — the remote counterpart of the panel's own
    ignoreip. Writes a dedicated panel-owned drop-in (`jail.d/zz-panel-whitelist.local`) — its own
    file, so it never clobbers the host's existing config — and reloads. Optionally lifts one IP that
    is already banned (used when whitelisting). No-op if fail2ban isn't installed. (ok, msg)."""
    jails_out, jails_err, jails_rc = _core.run_privileged(server, "f2b-status", [], timeout=10,
                                                    merge_stderr=False)
    if jails_rc == 127 or "not found" in (jails_out + jails_err).lower():
        return False, F2B_NOT_INSTALLED
    # Both steps' rc, as _point_f2b_sshd_at reads them. They were statements: a write or reload
    # that failed (on the tailscale and local transports a timeout RETURNS rc -1, it does not
    # raise) still answered True, and that host's fail2ban went on banning the whitelisted address
    # with nothing anywhere saying the whitelist never reached it.
    if _rc_of(_core.write_root_file(server, "fail2ban-panel-whitelist",
                                    _f2b_dropin_ignoreip_body(ignore_ips), timeout=15)) != 0:
        return False, i18n.Sentence("the whitelist drop-in could not be written")
    if _rc_of(_core._f2b_reload(server)) != 0:
        return False, i18n.Sentence("fail2ban did not reload")
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
    the activity to that one jail. Returns text, or None when NO read answered.

    None, not "": the Tailscale and local transports return ("", ..., -1) rather than raising, and
    two unanswered reads joined to "" were shown as "(log is empty)", i.e. no SSH or ban activity,
    on the card whose job is showing attacks. A read that ANSWERED (rc 0) with nothing in it is a
    real empty log and still comes back as ""."""
    lines = max(20, min(int(lines or 200), 1000))
    if which == "fail2ban":
        # /var/log/fail2ban.log holds the real Ban/Unban/Found activity (journalctl only has the
        # unit's start/stop noise), so read the file first and fall back to the journal.
        out, _, frc = _core.run_privileged(server, "log-tail", ["fail2ban", "4000"], timeout=20,
                                           merge_stderr=False)
        answered = frc == 0
        if not out:
            out, _, jrc = _core.run_privileged(server, "journal", ["fail2ban", "4000"], timeout=20,
                                               merge_stderr=False)
            answered = answered or jrc == 0
        if not answered and not out:
            return None
        rows = (out or "").splitlines()
        if jail and _F2B_JAIL_RE.match(jail):   # charset-only guard; used solely for in-Python filtering
            tag = "[%s]" % jail
            rows = [ln for ln in rows if tag in ln]
        return "\n".join(rows[-lines:])
    if which == "ssh":
        # journalctl first, auth.log as the fallback — that was `journalctl ... || tail ...`, where
        # the `||` fired on journalctl's exit status. Systemd exits 0 with no output on a host that
        # keeps no journal, so checking the OUTPUT is what the fallback was actually for.
        out, _, jrc = _core.run_privileged(server, "journal", ["ssh", str(lines * 2)], timeout=20,
                                           merge_stderr=False)
        answered = jrc == 0
        if not (out or "").strip():
            out, _, arc = _core.run_privileged(server, "log-tail", ["auth", str(lines)], timeout=20,
                                               merge_stderr=False)
            answered = answered or arc == 0
        if not answered and not (out or "").strip():
            return None
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


def _port_has_listener(ss_out, port):
    """Whether `ss -lnt` output has a listener on `port` (any address). It names no process."""
    # Was `ss -lnt | grep -qE '[:.]<port>[[:space:]]'` in a root shell; the same match in Python.
    return bool(re.search(r"[:.]%d\s" % int(port), ss_out or ""))


# The units sshd runs as: Debian/Ubuntu name it ssh.service, most other distributions sshd.service.
_SSHD_UNITS = ("ssh.service", "sshd.service")
# ...and the socket units that hold its listening socket under socket activation. systemd creates
# an AF_INET socket inside the SOCKET unit's cgroup when BPF firewalling is available (so the
# unit's IPAddressDeny= applies to it), and in its own (init.scope) when it is not.
_SSHD_SOCKET_UNITS = ("ssh.socket", "sshd.socket")


def _ss_listeners(ss_out):
    """The LISTEN rows of `ss -lnt[e]` output, as (address, port, extended fields) tuples.

    Parsed by COLUMN: `-e` appends `uid:1001 ino:2222 sk:…`, and a port match over the whole line
    would read `ino:2222` as a listener on 2222."""
    rows = []
    for line in (ss_out or "").splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] != "LISTEN":
            continue
        addr, _, port = cols[3].rpartition(":")
        if port.isdecimal():
            rows.append((addr, int(port), cols[5:]))
    return rows


def _listener_not_sshd(fields, socket_mode):
    """Why a listening socket (its `ss -e` fields) is not sshd's, or None when it can be.

    `ss -e` prints `uid:N` only for a socket a NON-root process created, and, where the kernel
    reports it, the systemd cgroup it was created in. A local game account can bind a free port
    >= 1024 in the window between the free-port check and sshd's restart; sshd then logs a failed
    bind on that Port and carries on with the others, and a port-only listening check was answered
    by the squatter. Its socket is uid:<game user>, which it cannot change — while the process
    NAME it can (a binary called `sshd`), which is why this does not read `ss -p`. Under socket
    activation systemd holds sshd's listening socket: in ssh.socket's cgroup, or init.scope."""
    uid = next((f[4:] for f in fields if f.startswith("uid:")), None)
    if uid not in (None, "0"):
        return i18n.Sentence("a socket owned by uid {uid}, not root", uid=uid)
    cgroup = next((f[7:] for f in fields if f.startswith("cgroup:")), "")
    unit = cgroup.rstrip("/").rsplit("/", 1)[-1]
    if unit in _SSHD_UNITS or (socket_mode and (unit in _SSHD_SOCKET_UNITS
                                                or cgroup == "/init.scope")):
        return None
    if cgroup == "/init.scope" or cgroup.startswith("/system.slice/"):
        return i18n.Sentence("held by {owner}, not sshd", owner=unit or cgroup)
    return None            # no cgroup reported (cgroup v1, a container): root-owned is what we know


def _sshd_holds_port(server, port, bind_addr, socket_mode):
    """Whether every listener on `port` (on `bind_addr`, when given) is sshd's.

    (True, "") when it is; (False, why) when something else holds it; (None, why) when the owners
    could not be read — an installed panel-helper older than the `listening-sockets-owner` verb
    refuses it, and that must not fail a port change the port-only check already confirmed."""
    try:
        out, _err, rc = _core.run_privileged(server, "listening-sockets-owner", [], timeout=15,
                                             merge_stderr=False)
    except Exception:
        _core._log.debug("listening-sockets-owner failed", exc_info=True)
        out, rc = "", -1
    rows = _ss_listeners(out)
    if rc != 0 or not any(f.startswith("ino:") for _a, _p, fs in rows for f in fs):
        return None, i18n.Sentence("the panel could not read which process holds it")
    def _same_ip(ss_addr):
        # ss prints "[fd00::5]" and the canonical form; the operator may have typed "fd00:0::5".
        try:
            return (_ipaddress.ip_address(ss_addr.strip("[]").split("%", 1)[0])
                    == _ipaddress.ip_address(bind_addr))
        except ValueError:
            return False
    held = [fs for a, p, fs in rows if p == int(port) and (not bind_addr or _same_ip(a))]
    if not held:
        return False, i18n.Sentence("nothing is listening there")
    for fs in held:
        why = _listener_not_sshd(fs, socket_mode)
        if why:
            return False, why
    return True, ""


# fail2ban's [sshd] jail, pointed at the ports sshd serves. A drop-in of the panel's own rather than
# an edit of jail.local: jail.d/*.local is read AFTER jail.local, so it applies however fail2ban was
# installed. The jail.local edit alone (f2b-set-sshd-ports) did nothing on a stock install, which
# has no jail.local — the jail kept banning on 22 while the panel said "fail2ban updated".
# Printable ASCII only: the helper's fail2ban content rule refuses anything else.
_F2B_SSHD_DROPIN_HEADER = (
    "# Managed by LinuxGSM Panel: the ports fail2ban's sshd jail bans on, written when the SSH\n"
    "# port is changed from the panel. Read after jail.local, so it overrides a port set there.\n")
# How long fail2ban gets to bring the sshd jail back after a reload that fell through to a restart.
_F2B_JAIL_SETTLE_S = 6


def _f2b_sshd_dropin_body(ports):
    """The [sshd] drop-in body for `ports` (validated ints, as strings)."""
    return _F2B_SSHD_DROPIN_HEADER + "[sshd]\nport = %s\n" % ",".join(str(int(p)) for p in ports)


def _rc_of(result):
    """The return code of a (out, err, rc) transport answer; -1 for anything else."""
    return result[2] if isinstance(result, tuple) and len(result) == 3 else -1


def _point_f2b_sshd_at(server, ports):
    """Make fail2ban's sshd jail ban on `ports`: ("updated" | "absent" | "failed", why).

    "updated" only when the drop-in was written, fail2ban reloaded, and the sshd jail answers
    afterwards — each of those has failed in a way the old step never looked at. Never raises: a
    transport error here must not turn a port change that worked into a 500."""
    try:
        out, err, rc = _core.run_privileged(server, "f2b-status", [], timeout=10,
                                            merge_stderr=False)
        if rc == 127 or "not found" in ((out or "") + (err or "")).lower():
            return "absent", i18n.Sentence("fail2ban is not installed on this host")
        portlist = ",".join(ports)
        # Hosts the panel prepared have a jail.local [sshd] port line; keep it in step.
        _core.run_privileged(server, "f2b-set-sshd-ports", [portlist], timeout=20,
                             merge_stderr=False)
        if _rc_of(_core.write_root_file(server, "fail2ban-panel-sshd",
                                        _f2b_sshd_dropin_body(ports), timeout=15)) != 0:
            return "failed", (i18n.Sentence("its sshd drop-in could not be written; the panel-helper on this host "
                                             "may predate it, and re-running install.sh updates it")
                               if _core.is_local_server(server) else
                               i18n.Sentence("its sshd drop-in could not be written"))
        if _rc_of(_core._f2b_reload(server)) != 0:
            return "failed", i18n.Sentence("fail2ban did not reload")
        deadline = time.time() + _F2B_JAIL_SETTLE_S
        while True:
            _o, _e, jrc = _core.run_privileged(server, "f2b-status-jail", ["sshd"], timeout=10,
                                               merge_stderr=False)
            if jrc == 0:
                return "updated", ""
            if time.time() >= deadline:
                return "failed", i18n.Sentence("its sshd jail is not running")
            time.sleep(1)
    except Exception:
        _core._log.warning("fail2ban sshd port update failed", exc_info=True)
        return "failed", i18n.Sentence("the host did not answer")


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


def _r22b_ssh_port_reading(status_out, port):
    """(already open, the rule blocking it or None) for TCP `port`, both families read.

    A `(v6)` DENY first blocks every IPv6 client, whatever the IPv4 list says. Open already only
    when IPv4 has a rule letting it in and nothing blocks it (the IPv6 list may have no rule).
    scoped=False: an allow to ONE of the host's addresses does not open the port on the others.
    """
    firsts = _r22b_first_rules(status_out, port, "tcp", scoped=False)
    blocking = next((f for f in firsts if f and f["action"] not in ("ALLOW", "LIMIT")), None)
    return blocking is None and firsts[0] is not None, blocking


def _open_ssh_port_rule(server, port, panel_way_in):
    """Step 1 of change_ssh_port: let `port`/tcp through ufw. (added, refusal).

    `added` is truthy only when THIS call put the allow there, which is what makes it the revert's
    to delete (_R25B_V4_ADDED when that was only the IPv4 rule; see _r25b_close_added_ssh_rule).
    Nothing is opened when:
      * `port` is in `panel_way_in`: the port the panel's own SSH connection to this host is made
        on right now. Whatever lets that connection in works today (it may be a tailscale0 rule,
        and a public allow would widen it);
      * the first public rule a TCP connection to it meets already allows it (ALLOW or LIMIT, a
        bare `N`, `N/tcp` or a range): the operator's rule stays as it is.
    It used to skip any port sshd LISTENS on (review 1016e). After the panel's own 22 -> 2222 move
    on a socket-activated host, ssh.socket keeps 22 listening beside 2222; the operator closes
    22/tcp as the move advises; the move back to 22 then opened nothing and the panel was pointed at
    a port UFW drops. Listening says nothing about the firewall: only the rules read below do.
    `refusal` is a message when that first rule DENIES or REJECTS it: the move would have
    "succeeded" (the listening check does not go through the firewall) onto a port nobody can
    reach, and the advice that follows is to close the old one. Nothing has been changed by then.

    An inactive firewall lists none of its rules in `status`, stored ones included, so its stored
    rules are read with `ufw show added` (_r26j_inactive_open). A firewall that cannot be read, or
    an inactive one whose stored rules cannot be read either, is opened as it always was — but NOT
    counted as added: a rule that may have been there before is not one to delete on the way out.
    """
    if str(port) in panel_way_in:
        return False, None
    with _core.ufw_lock(server):
        before, _, brc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15)
        known = brc == 0 and firewall._ufw_is_active(before or "")
        if brc == 0 and not known:
            return _r26j_inactive_open(server, port)
        is_open, first = _r22b_ssh_port_reading(before, port) if known else (False, None)
        if is_open:
            return False, None
        if first is not None:
            return False, _r26j_blocked(port, first["detail"])
        added = _r25b_add_ssh_rule(server, port, known, before)
        _r34b_note_added(port, added)
        return added, (_r28j_open_unconfirmed(server, port, added) if known else None)


def _r34b_note_added(port, added):
    """Record step 1's own rule in the running move's undo record the moment it is in UFW.

    change_ssh_port recorded it only after step 1 returned, so a transport that RAISED in step 1's
    re-read (_r28j_open_unconfirmed, _r26j_inactive_open) left a public allow for a port nothing
    serves: the exact leftover _r32b_undo_on_raise exists to remove.
    """
    _r32b_move_undo().update(port=port, added=added)


def _r28j_open_unconfirmed(server, port, added):
    """After the open on an ACTIVE firewall: None when a re-read shows `port`/tcp let in, else the refusal.

    ufw can answer 0 and still not hold the rule (a refused verb on an old helper, a transport that
    timed out without raising). Unconfirmed, the move went on and the route pointed the panel at a
    port the firewall may drop. A rule this call did add is taken back before refusing.
    """
    after, _, arc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15)
    if arc == 0 and _r22b_ssh_port_reading(after, port)[0]:
        return None
    return _r28j_not_opened(port, _r36b_close_confirmed(server, port, added))


def _r28j_not_opened(port, closed=True):
    """The refusal when the firewall does not show `port`/tcp open after the panel opened it.

    `closed`: whether the allow the panel added was confirmed removed (_r36b_close_confirmed).
    """
    return i18n.Sentences(i18n.Sentence("The firewall did not show port {port}/tcp open after the panel opened it, "
                                        "so SSH moved there could be unreachable. Nothing was changed.", port=port),
                          "" if closed else _r36b_rule_left_note(port))


def _r26j_blocked(port, rule):
    """_open_ssh_port_rule's refusal when `rule` (active, or stored on an inactive firewall) blocks `port`/tcp."""
    return i18n.Sentence("Port {port}/tcp is blocked by the firewall rule `{rule}`, so SSH moved there would be "
                         "unreachable — remove or change that rule first. Nothing was changed.", port=port, rule=rule)


def _r25b_add_ssh_rule(server, port, known, before):
    """_open_ssh_port_rule's open, once nothing lets `port` in or blocks it: its `added`.

    The caller holds ufw_lock. `known`: `before` is an active firewall's listing.
    """
    # An IPv6-only allow or LIMIT for exactly `port`/tcp is the operator's, and `ufw allow
    # port/tcp` takes it over: ufw rewrites a rule that differs only in comment or action in
    # place, so a LIMIT became a plain ALLOW (IPv6 SSH lost its brute-force brake whether the
    # move worked or not) and the revert's `delete allow port/tcp` would remove it. So only the
    # IPv4 half goes in: a source of 0.0.0.0/0 is an IPv4-only rule that ufw lists as
    # "Anywhere", and the revert deletes exactly that rule (_R25B_V4_ADDED), never the v6 one.
    # "SSH panel" is what remote_ufw_open_port stores for "SSH (panel)": the verb refuses "()".
    if known and _r23b_v6_exact_open(before, port):
        _o, _e, rc = _core.run_privileged(server, "ufw-allow-from-port",
                                          [_R25B_V4_ANYWHERE, str(port), "tcp", "SSH panel"],
                                          timeout=15)
        return _R25B_V4_ADDED if rc == 0 else False
    ok, _ = remote_ufw_open_port(server, port, "tcp", comment="SSH (panel)")
    return bool(ok and known)


# A stored rule `ufw show added` prints in short form for exactly `<port>/tcp` from anywhere, inbound:
# the rule `ufw allow proto tcp to any port <port>` would rewrite in place (ufw matches a rule by
# everything but its action and comment). Both families print the same line, so this cannot tell a
# `(v6)`-only LIMIT from a both-family one, and does not need to: either is the operator's. The
# commands are ufw's own syntax, never translated; the heading line above them is, and is skipped.
_R26J_STORED_RULE_RE = re.compile(r"ufw (?:allow|deny|reject|limit)(?: in)?(?: log(?:-all)?)? "
                                  r"(\d{1,5})/tcp(?: comment .*)?")
# Any stored rule from anywhere, inbound, whose ports a TCP connection to `<port>` meets: a bare `N` (both
# protocols), `N/tcp`, a list (`22,2222/tcp`) or a range (`2200:2300/tcp`). Its action and port spec.
_R26J_STORED_COVER_RE = re.compile(r"ufw (allow|deny|reject|limit)(?: in)?(?: log(?:-all)?)? "
                                   r"([0-9][0-9,:]*)(?:/(tcp|udp))?(?: comment .*)?")


def _r26j_inactive_open(server, port):
    """_open_ssh_port_rule's open on an inactive firewall: its (added, refusal). The caller holds ufw_lock.

    `ufw status` lists none of an inactive firewall's stored rules, so the open ran `ufw allow`
    blind: a stored `port/tcp` LIMIT (either family) became an ALLOW, which applies the moment UFW
    is enabled, and the revert did not count it as the panel's to delete. Now:
      * the first stored rule a TCP connection to `port` meets DENIES or REJECTS it: refused, as the
        active firewall's same rule is (_r26j_blocked). Kept silently, the move went on to tell the
        operator to close the old port, while the rule shut the new one the moment UFW came on;
      * a stored allow or LIMIT for exactly `port`/tcp is the operator's: nothing is added or rewritten;
      * none stored: the allow goes in, and it is the panel's own, so the revert deletes it;
      * stored rules that cannot be read (a host without the verb, a failed read): opened as
        before, not counted as added.
    """
    out, _err, rc = _core.run_privileged(server, "ufw-show-added", [], timeout=15)
    stored, blocking = _r26j_stored_reading(out if rc == 0 else "", port)
    if blocking:
        return False, _r26j_blocked(port, blocking)
    if stored:
        return False, None
    ok, _ = remote_ufw_open_port(server, port, "tcp", comment="SSH (panel)")
    added = bool(ok and stored is False)
    _r34b_note_added(port, added)
    if stored is False:
        # Re-read: a stored rule that is not there shuts the port the moment UFW is enabled.
        out, _err, rc = _core.run_privileged(server, "ufw-show-added", [], timeout=15)
        if not _r26j_stored_reading(out if rc == 0 else "", port)[0]:
            return False, _r28j_not_opened(port, _r36b_close_confirmed(server, port, added))
    return added, None


def _r26j_stored_reading(out, port):
    """(stored, blocking) for `port` from `ufw show added`'s `out`.

    `stored`: whether an allow or LIMIT for exactly `port`/tcp is stored (None when nothing was
    read). `blocking`: the first stored rule a TCP connection to `port` meets, when that rule denies
    or rejects it (else None).
    """
    if not (out or "").strip():
        return None, None
    lines = [line.strip() for line in out.splitlines()]
    first = next((line for line in lines if _r26j_stored_covers(line, port)), None)
    if first is not None and _R26J_STORED_COVER_RE.fullmatch(first).group(1) in ("deny", "reject"):
        return True, first
    return any(m and int(m.group(1)) == int(port) for m in map(_R26J_STORED_RULE_RE.fullmatch, lines)), None


def _r26j_stored_covers(line, port):
    """Whether stored rule `line` (`ufw show added`'s short form) is met by TCP to `port` from anywhere."""
    m = _R26J_STORED_COVER_RE.fullmatch(line)
    if not m or m.group(3) == "udp":
        return False
    for part in m.group(2).split(","):
        lo, _sep, hi = part.partition(":")
        if lo.isdecimal() and (hi or lo).isdecimal() and int(lo) <= int(port) <= int(hi or lo):
            return True
    return False


# Every IPv4 source: ufw stores `allow from 0.0.0.0/0` as an IPv4-only rule listed "Anywhere".
_R25B_V4_ANYWHERE = "0.0.0.0/0"  # NOSONAR(S1313) - the IPv4 "any source" network, not a host
# _open_ssh_port_rule's `added` when it put in only the IPv4 rule above: the revert deletes that.
_R25B_V4_ADDED = "v4-only"


def _r25b_close_added_ssh_rule(server, port, added):
    """Remove the rule _open_ssh_port_rule added for `port` (its `added`), and nothing else.

    -> True when it is gone (or there was none to remove), False when that was not confirmed: a
    Tailscale or local transport answers a lost command -1 rather than raising, and the result used
    to be dropped, so a failed close left a public allow for a port nothing serves under "nothing
    changed".
    """
    if added == _R25B_V4_ADDED:
        with _core.ufw_lock(server):
            return _rc_of(_core.run_privileged(server, "ufw-delete-allow-from-port",
                                               [_R25B_V4_ANYWHERE, str(port), "tcp"], timeout=15)) == 0
    if added:
        # force: the rule step 1 added, for a port sshd may already be listening on.
        return bool(remote_ufw_close_port(server, port, "tcp", force=True)[0])
    return True


def _r36b_close_confirmed(server, port, added):
    """_r25b_close_added_ssh_rule, run once more when it was not confirmed. -> True when the rule is gone.

    Safe to repeat: each close is a by-spec `ufw delete` of the one rule step 1 put in, and ufw
    exits 0 removing nothing when that rule is already gone. The first close's raise goes on (the
    undo wrapper still owes it); the second's is logged, as an unconfirmed close.
    """
    if _r25b_close_added_ssh_rule(server, port, added):
        return True
    _core._log.warning("ssh port move: closing the port %s/tcp allow it added on %s was not confirmed; trying "
                       "once more", int(port), _r34j_log_name(server))
    try:
        if _r25b_close_added_ssh_rule(server, port, added):
            return True
    except Exception:
        _core._log.warning("ssh port move: the second close of port %s/tcp on %s failed", int(port),
                           _r34j_log_name(server), exc_info=True)
    _core._log.warning("ssh port move: the port %s/tcp allow it added on %s may still be in UFW", int(port),
                       _r34j_log_name(server))
    return False


def _r36b_rule_left_note(port):
    """Said after a failure the move undid, when the allow step 1 added could not be confirmed removed."""
    return i18n.Sentence("One thing may not have been undone: the firewall rule this change opened for port "
                         "{port}/tcp could not be confirmed removed — remove it from the Firewall page if it is "
                         "still there.", port=port)


# Every IPv6 source, as _R25B_V4_ANYWHERE is every IPv4 one: `allow from ::/0` is an IPv6-only rule
# listed "Anywhere (v6)".
_R30J_V6_ANYWHERE = "::/0"


def remote_ufw_put_back_tcp(server, port, families, comment=""):
    """Re-add the public `port`/tcp ALLOW that remote_ufw_close_port removed, in exactly `families`.

    -> (ok, msg). One rule per family, from that family's every-source network. `ufw allow proto
    tcp to any port N` adds BOTH families on a host with IPv6 on, so an IPv4-only rule put back that
    way also opened the port over IPv6. ufw stores the same rule the delete removed (`N/tcp ALLOW
    Anywhere`, or its `(v6)` twin), and the same by-spec delete removes it again.
    """
    for fam in families:
        ok, msg = remote_ufw_allow_from(server, _R25B_V4_ANYWHERE if fam == "v4" else _R30J_V6_ANYWHERE,
                                        port, "tcp", comment)
        if not ok:
            return False, msg
    return True, ""


def _r23b_v6_exact_open(status_out, port):
    """Whether an IPv6 public ALLOW or LIMIT for exactly `port`/tcp is listed (ufw would take it over)."""
    return any(r["to"] == "%s/tcp" % port and r["action"] in ("ALLOW", "LIMIT")
               for r in _ufw_public_rules(status_out, v6=True))


def _r26b_dials_after_bind(server):
    """Whether change_ssh_port confirms a bind change by dialling the host on the new port.

    Only where the panel comes in through sshd: not its own host, and not a host it reaches over
    Tailscale SSH (tailscaled answers port 22 there, whatever sshd is bound to).
    """
    return not _core.is_local_server(server) and getattr(server, "auth_method", "") != "tailscale"


# A remote's own addresses: unprivileged, and in the C locale like every read parsed by its words.
_R26J_ADDR_SHOW = _core._R19A_C_LOCALE + "ip -o addr show"


def _r26j_remote_has_ip(server, addr):
    """Whether `addr` is one of remote `server`'s interface addresses: True/False, None when unread.

    system_ops.host_has_ip's question for a host the panel reaches over SSH. A host always has
    loopback, so a listing with no address in it was not read, and says nothing either way.
    """
    want = ip_address_or_none(addr)
    try:
        out, _err, rc = _core.run_command(server, _R26J_ADDR_SHOW, timeout=15, sudo=False)
    except Exception:
        _core._log.debug("the host's addresses could not be read", exc_info=True)
        return None
    have = set()
    for line in (out or "").splitlines() if rc == 0 else ():
        parts = line.split()
        for i, word in enumerate(parts[:-1]):
            if word in ("inet", "inet6"):
                have.add(ip_address_or_none(parts[i + 1].partition("/")[0]))
    have.discard(None)
    return (want in have) if have else None


# ── change_ssh_port as one transaction ──────────────────────────────────────────────────────────
# Every step it takes, in order, and what a failure at each may undo. The undo record (`undo`) holds
# exactly what is still owed. COMMIT (_r35b_commit, once step 6 has VERIFIED the move) empties it, and
# nothing after that point undoes the move: a later step that fails or raises is reported or logged.
# Point fixes to the undo left a new lock-out path four review passes running (review 1022b): the
# discard at step 8 raised after it had run, and the wrapper restored from the snapshot it had just
# removed, which DELETES the verified drop-in.
#
#   step                              committed  a failure here undoes                   owed from here
#   P  reads, the refusals            no         nothing: nothing was changed            -
#   1  UFW allow for the new port     no         that allow, ONLY if this step added it  port, added (the moment
#                                                                                         the rule is in)
#   2a snapshot the drop-in           no         the allow. No restore: no snapshot is   restore, reload (socket),
#                                                known to exist (rc 0 only). Refused     relisten
#                                                (R35J_SNAPSHOT_HELD) while a snapshot
#                                                is there that DIFFERS from the drop-in,
#                                                whatever `sshd -t` says: an earlier move
#                                                did not finish, and it may be the good
#                                                copy. Its rc 0 says whether a drop-in
#                                                was there (R36B_SNAP_*), for _revert's
#                                                unconfirmed-restore message
#   2b write the new drop-in          no         restore, reload, the allow; a failed    -
#                                                write (rc) no restart, as nothing read it
#   2c daemon-reload (socket)         no         restore, reload, the allow, restart     -
#   3  sshd -t                        no         the same                                -
#   5  restart the listener           no         the same                                -
#   6  verify: listening, reached,    no         the same                                -
#      held by sshd
#   C  COMMIT                         YES        -                                       nothing, for good
#   7  fail2ban repointed             yes        never: its outcome is in the message
#   8  snapshot discarded             yes        never: tried once more when not 0. A snapshot left behind
#                                                differs from the new drop-in, so the next move's 2a refuses
#                                                until it is deleted; the success message says so
#   9  the route stores the port      yes        (routes/remote_vps.py, only on success)
#
# Each part of an undo runs at most once in effect, whoever runs it (_revert for a failure the move
# saw, the wrapper for a step that raised), in this order: restore, reload, close the allow, restart.
#   * The restore copies the snapshot back and keeps it, so a second run is the first again. One that
#     never reached the host stays owed, and the wrapper's single retry puts the snapshot back
#     (_r34b_restore_once). One that answered but not 0, or raised after its command went out (its
#     answer lost), is run once more at once and then retired; still unconfirmed, _revert says so and
#     names the file (never "nothing changed"), the snapshot stays, and 2a above keeps it.
#   * The reload, the close and the restart are idempotent: retired once they returned, so one that
#     raised is tried once more by the wrapper. A reload that answered but not 0 is run once more at
#     once; still not (or still owed after a raise), the restart is skipped, as systemd may still hold
#     the moved socket unit, and _revert adds that it may not have re-read it. A restart that is not
#     confirmed (not 0, -1, a raise; it already falls back from `ssh` to `sshd`) may leave nothing
#     listening on any port, so _revert's first sentence says that and how to recover in place of
#     "Your existing SSH still works".
#   * The close (a by-spec `ufw delete`: ufw exits 0 removing nothing once the rule is gone) that
#     answered but was not confirmed is run once more at once; still not, _revert adds that the rule
#     may be left and names its port (_r36b_rule_left_note). Step 1's own refusals do the same.
#   * The restart only onto a config `sshd -t` accepts (_r34j_sshd_config_ok): a restore can have been
#     retired without having run, and a restart stops the serving daemon before it starts a new one.
# Per greenlet (each request runs in its own), so two moves on two hosts never share one record.
_R32B_MOVE_UNDO = contextvars.ContextVar("r32b_move_undo", default=None)


def _r32b_undo_on_raise(move):
    """Wrap change_ssh_port: a step that RAISES undoes what the move still owes, then raises on.

    Every failure the move can SEE reverts itself (_revert). A transport that raises instead
    (paramiko does, mid-step) left the step-1 allow for the new port in UFW, and from step 2 on a
    changed drop-in, with the route answering only "failed": a firewall more open than before for a
    port nothing may be serving. Undone best effort; a committed move owes nothing (see the table above).
    """
    @functools.wraps(move)
    def _wrapped(server, new_port, bind_addr=""):
        undo = {}
        token = _R32B_MOVE_UNDO.set(undo)
        try:
            return move(server, new_port, bind_addr)
        except Exception:
            _r35b_unwind(server, undo, quiet=True)
            raise
        finally:
            _R32B_MOVE_UNDO.reset(token)
    return _wrapped


def _r32b_move_undo():
    """The running move's undo record (a scratch dict when change_ssh_port's body runs unwrapped)."""
    undo = _R32B_MOVE_UNDO.get()
    return {} if undo is None else undo


def _r35b_commit(undo):
    """COMMIT: the move is verified, so it stands. Nothing is owed any more, whatever happens next."""
    undo.clear()


def _r35b_unwind(server, undo, quiet=False):
    """Undo what the running move still owes (`undo`), in the table's order, each part at most once.

    quiet=False (_revert): the first part that raises stops the undo and the raise goes on, every
    part after it still owed, for the wrapper. quiet=True (the wrapper, a step raised): every part
    still owed is tried and each raise is logged, never passed on (one is already in flight).
    """
    for part in _R35B_UNDO_ORDER:
        if not undo.get(part):
            continue
        try:
            _R35B_UNDO_PARTS[part](server, undo)
        except Exception:
            if not quiet:
                raise
            _core._log.warning("ssh port move: undoing a step that raised also failed on %s",
                               _r34j_log_name(server), exc_info=True)


def _r36b_left(undo, note):
    """Record that a part of the undo returned without being confirmed: _revert adds `note` to its answer.

    Each part used to be retired however it answered, and a transport that answers a lost command -1
    rather than raising (Tailscale, local) left the move half-undone under "nothing changed".
    """
    undo.setdefault("left", []).append(note)


def _r35b_undo_reload(server, undo):
    """Socket-activated: systemd re-reads the unit once its drop-in is back. Idempotent: retired once it returned.

    Not 0 is tried once more; still not, systemd may hold the moved socket unit in memory, so the
    restart below is skipped (`reload_unconfirmed`) while ssh.socket is active, and _revert says so.
    That restart re-opened the moved port's listener when the undo had already closed its firewall
    rule. A socket that is not active is restarted all the same, after one more reload
    (_r35b_undo_relisten): a restart without one rebinds the moved list systemd still holds.
    """
    for _ in range(2):
        if _rc_of(_core.run_privileged(server, "systemd-daemon-reload", [], timeout=20, merge_stderr=False)) == 0:
            break
    else:
        _core._log.warning("ssh port move: systemd's re-read of ssh.socket on %s after the undo was not confirmed",
                           _r34j_log_name(server))
        undo["reload_unconfirmed"] = True
        if not undo.get("relisten"):
            # Nothing restarts it after this (the undo's restart is not owed): said here. When it is
            # owed, _r35b_undo_relisten says which way it went.
            _r36b_left(undo, _R36J_NOT_RESTARTED)
    undo.pop("reload", None)


_R36J_NOT_RESTARTED = i18n.Sentence("One thing may not have been undone: systemd could not be confirmed to have "
                                    "re-read ssh.socket after the change was undone, so ssh.socket was not "
                                    "restarted — run `systemctl daemon-reload` on the host, then restart "
                                    "ssh.socket.")
_R36J_RESTARTED = i18n.Sentence("One thing may not have been undone: systemd could not be confirmed to have "
                                "re-read ssh.socket after the change was undone, and ssh.socket was not "
                                "confirmed to be listening, so it was restarted and may listen on the new "
                                "port too — run "
                                "`systemctl daemon-reload` on the host, then restart ssh.socket.")


def _r35b_undo_close(server, undo):
    """Close the allow step 1 added, and nothing else. Idempotent: retired once it returned.

    One that answered but was not confirmed is run once more at once (_r36b_close_confirmed); still
    not, _revert says the rule may be left. It was retired however it answered, and _revert said
    "nothing changed" over a public allow for a port nothing serves.
    """
    if not _r36b_close_confirmed(server, undo["port"], undo["added"]):
        _r36b_left(undo, _r36b_rule_left_note(undo["port"]))
    undo["added"] = False


def _r35b_undo_relisten(server, undo):
    """Restart the listener onto the restored config, only when `sshd -t` accepts it. Retired once it returned."""
    # A restore that raised once its command went out is retired as run (_r34b_restore_once), but it
    # may not have run, and transports that answer -1 instead of raising say nothing either: the
    # drop-in can still be the one step 3 rejected, and a restart stops the serving daemon and cannot
    # start a new one.
    unsure = undo.get("reload") or undo.get("reload_unconfirmed")
    if unsure and _sshd_socket_activated(server):
        # Socket-activated, and systemd was not confirmed to have re-read ssh.socket (its reload raised and
        # is still owed, or answered non-zero twice): it may still hold the moved unit, and restarting
        # ssh.socket would re-open the moved port, whose firewall rule the undo has already closed.
        # Skipped only while ssh.socket is confirmed ACTIVE, so a listener is there to protect: a step 6
        # whose restart failed (a port another process holds: Ubuntu's ssh.socket has FreeBind=yes, so
        # an address the host lacks does not fail it) leaves it failed with no listener on any port,
        # the old one included, and then it is restarted below.
        _core._log.warning("ssh port move: NOT restarting ssh.socket on %s after undoing a step: systemd was "
                           "not confirmed to have re-read it", _r34j_log_name(server))
        _r36j_reload_note(undo, _R36J_NOT_RESTARTED)
    elif _r34j_sshd_config_ok(server):
        _r36j_restart_after_undo(server, undo, unsure)
    else:
        _core._log.warning(
            "ssh port move: NOT restarting ssh on %s after undoing a step: `sshd -t` "
            "does not accept the config now (or could not be run), so the sshd that is running was "
            "left as it is. Check /etc/ssh/sshd_config.d/ (and ssh.socket.d on a socket-activated "
            "host), then run `sshd -t` before restarting ssh.", _r34j_log_name(server))
        if unsure:
            # ssh.socket was not confirmed active (the branch above), so it may be the failed one a
            # step 6 left with no listener on any port, and nothing restarts it here.
            undo["down"] = _R36J_DOWN_INVALID
        else:
            _r36j_reload_note(undo, _R36J_NOT_RESTARTED)
    undo.pop("relisten", None)


def _r36j_restart_after_undo(server, undo, unsure):
    """_r35b_undo_relisten's restart onto a config `sshd -t` accepts. `unsure`: systemd's re-read was not confirmed."""
    if unsure:
        _r36j_reload_again(server, undo)
    # Not run again (the restart of `ssh` already falls back to `sshd`). One not confirmed (an
    # answer not 0, -1) may have left nothing listening on any port: a socket restart that fails
    # drops every listener, and `systemctl restart ssh` stops the daemon first.
    try:
        _up = _rc_of(_restart_ssh_listener(server, undo.get("socket"))) == 0
    except Exception:
        if not unsure:
            raise       # still owed: the wrapper tries it once more (the table above _R32B_MOVE_UNDO)
        # Behind a socket that was not active, a raise is said like any unconfirmed restart: the
        # route's generic failure would leave the operator no way back to a host nothing answers on.
        _core._log.warning("ssh port move: the undo's restart of ssh.socket on %s raised",
                           _r34j_log_name(server), exc_info=True)
        _up = False
    if _up:
        _r36j_reload_note(undo, _R36J_RESTARTED)
    else:
        _core._log.warning("ssh port move: restarting ssh on %s after the undo was not confirmed: SSH may not "
                           "be listening on any port", _r34j_log_name(server))
        undo["down"] = _R36J_DOWN_SOCKET if undo.get("socket") else _R36J_DOWN_SERVICE


def _r36j_reload_again(server, undo):
    """Run systemd's re-read once more, before restarting a socket that is not active after an unconfirmed one.

    A restart without it rebinds the MOVED port list systemd still holds in memory (measured on
    systemd 255): it fails again on the port another process holds, and nothing listens on any port.
    Harmless when an earlier one ran: the drop-in is already put back. Confirmed, nothing is owed or said.
    """
    try:
        if _rc_of(_core.run_privileged(server, "systemd-daemon-reload", [], timeout=20, merge_stderr=False)) == 0:
            undo.pop("reload", None)
            undo.pop("reload_unconfirmed", None)
    except Exception:
        _core._log.debug("ssh port move: the undo's daemon-reload before the restart raised", exc_info=True)


# _revert's first sentence when the undo's restart was not confirmed: "Your existing SSH still works" is
# not known then, and may be false.
_R36J_DOWN_SOCKET = i18n.Sentence("The SSH port change did not work, and SSH could not be confirmed listening again "
                                  "after undoing it: SSH on this host may not be listening on any port now. From "
                                  "the host's console or another way in (Tailscale SSH, for one), run `systemctl "
                                  "daemon-reload`, then `systemctl restart ssh.socket`.")
_R36J_DOWN_SERVICE = i18n.Sentence("The SSH port change did not work, and SSH could not be confirmed listening "
                                   "again after undoing it: SSH on this host may not be listening on any port now. "
                                   "From the host's console or another way in (Tailscale SSH, for one), run "
                                   "`systemctl restart ssh`.")
_R36J_DOWN_INVALID = i18n.Sentence("The SSH port change did not work, and ssh.socket was not restarted after "
                                   "undoing it because `sshd -t` did not accept the configuration (or could not be "
                                   "run): SSH on this host may not be listening on any port now. From the host's "
                                   "console or another way in (Tailscale SSH, for one), run `sshd -t` and fix what "
                                   "it reports, then run `systemctl daemon-reload`, then `systemctl restart "
                                   "ssh.socket`.")


def _r36j_reload_note(undo, note):
    """Say `note` (whether ssh.socket was restarted) when the undo's daemon-reload was not confirmed."""
    if undo.get("reload_unconfirmed"):
        _r36b_left(undo, note)


def _r34j_sshd_config_ok(server):
    """True only when the host's `sshd -t` (the sshd-validate verb) accepts the config; a raise is False."""
    try:
        return _core.run_privileged(server, "sshd-validate", [], timeout=15)[2] == 0
    except Exception:
        _core._log.debug("sshd-validate could not be run", exc_info=True)
        return False


def _r34j_log_name(server):
    """The host's name for a log line, with line breaks taken out (a name is operator-entered)."""
    return str(getattr(server, "name", "?")).replace("\r", " ").replace("\n", " ")


def _r34b_restore_once(server, undo):
    """change_ssh_port's restore of its drop-in snapshot, retired from `undo` once it may have run.

    One that raised before the command went out (no connection, a refused session) is still owed,
    and the wrapper's retry is what puts the snapshot back.

    A restore that ANSWERED but not 0 (a Tailscale or local transport answers -1 rather than
    raising), or whose answer was lost after it went out (paramiko marks that raise
    `command_started`), is tried once more at once: the verb copies the snapshot over the drop-in and
    keeps the snapshot (review 1022b's integration), or with no snapshot removes the drop-in, so a
    second run puts back the same file or removes nothing more. The lost-answer one used to be
    retired unconfirmed and unsaid, from when a second run deleted the drop-in the first restored.
    Retried only when 2a's snapshot verb printed its SNAPSHOT= word (`undo["copies"]`): a helper older
    than that restores by MOVING the snapshot, and a second run would delete the drop-in the first put
    back. Still not confirmed, `undo["unconfirmed"]` tells _revert to say so: the drop-in on disk may be
    the one this move wrote, the good one only in the snapshot, and "nothing changed" would send the
    host's next ssh restart (a reboot) onto it.
    """
    try:
        rc = _rc_of(_core.run_privileged(server, undo["restore"], [], timeout=10, merge_stderr=False))
    except Exception as e:
        if not getattr(e, "command_started", False):
            raise
        _core._log.warning("ssh port move: the drop-in restore on %s went out but its answer was lost",
                           _r34j_log_name(server), exc_info=True)
        rc = None
    if rc != 0 and not undo.get("copies"):
        # A helper that did not print 2a's SNAPSHOT= word predates the copy-and-keep restore: its restore
        # MOVES the snapshot back, so a second run finds none and deletes the drop-in the first one put
        # back. Not retried; said as unconfirmed.
        _core._log.warning("ssh port move: the drop-in restore on %s was not confirmed (%s), and the helper "
                           "is too old to run it twice safely", _r34j_log_name(server),
                           "its answer was lost" if rc is None else "it answered %s" % rc)
        undo["unconfirmed"] = True
    elif rc != 0:
        # rc None: the first run went out and its answer was lost (the except above), not an answer of "None".
        _core._log.warning("ssh port move: the drop-in restore on %s was not confirmed (%s); trying it once more",
                           _r34j_log_name(server), "its answer was lost" if rc is None else "it answered %s" % rc)
        try:
            rc = _rc_of(_core.run_privileged(server, undo["restore"], [], timeout=10, merge_stderr=False))
        except Exception:
            _core._log.warning("ssh port move: the second drop-in restore on %s failed", _r34j_log_name(server),
                               exc_info=True)
            rc = None
        if rc != 0:
            # Logged here too: on the wrapper's path (a step raised) the raise goes on, not _revert's message.
            _core._log.warning("ssh port move: the drop-in restore on %s was not confirmed; the drop-in on disk "
                               "may be the one this move wrote", _r34j_log_name(server))
            undo["unconfirmed"] = True
    undo.pop("restore", None)
    undo.pop("copies", None)


def _r35j_dropin_paths(socket_mode):
    """(the move's drop-in, its snapshot) on this host: ssh.socket's when socket-activated, else sshd's."""
    if socket_mode:
        return _priv.SSHD_SOCKET_DROPIN, _priv.SSHD_SOCKET_DROPIN_BAK
    return _priv.SSHD_DROPIN, _priv.SSHD_DROPIN_BAK


def _r35j_unconfirmed_message(socket_mode, prior=None):
    """_revert's message when the restore could not be confirmed: where to look, and why it matters.

    `prior` is what 2a's snapshot found (_r36b_snap_prior): True, a drop-in was there and its copy is
    at {bak}; False, there was none, so no {bak} exists and the host is recovered by removing {path};
    None, not said (a helper too old to print it), so both cases are named. It used to say "the
    previous one is kept at {bak}" whatever 2a found, pointing the operator at a file that was not
    there when the move was the host's first.
    """
    path, bak = _r35j_dropin_paths(socket_mode)
    if prior is False:
        return i18n.Sentence("The SSH port change did not work, and putting the previous configuration back could "
                             "not be confirmed — there was no {path} before this change, so remove it if it is "
                             "there before restarting ssh (`sshd -t` must accept the config).", path=path)
    if prior is None:
        return i18n.Sentence("The SSH port change did not work, and putting the previous configuration back could "
                             "not be confirmed — check {path} before restarting ssh: if {bak} exists it is the "
                             "previous one, so copy it over {path}; if it does not, there was no {path} before "
                             "this change, so remove it (`sshd -t` must accept the config).", path=path, bak=bak)
    return i18n.Sentence("The SSH port change did not work, and putting the previous configuration back could not "
                         "be confirmed — check {path} before restarting ssh (the previous one is kept at {bak}, "
                         "and `sshd -t` must accept the config).", path=path, bak=bak)


def _r36b_snap_prior(out):
    """What 2a's snapshot verb found, from its stdout: True (it copied a drop-in), False (there was none), None."""
    words = (out or "").split()
    if _priv.R36B_SNAP_COPIED in words:
        return True
    return False if _priv.R36B_SNAP_NONE in words else None


# The snapshot verbs' answer when they refuse: a snapshot is already there and DIFFERS from the drop-in,
# so an earlier move did not finish (privileged.py's _r35b_snapshot_sh, the helper's _r35b_snapshot).
_R35J_SNAPSHOT_HELD = _priv.R35J_SNAPSHOT_HELD


def _r35j_held_message(socket_mode):
    """2a's message when the snapshot verb kept a snapshot that differs from the drop-in.

    It held only while `sshd -t` rejected the config and blamed the snapshot for that; the verb now
    holds on the difference alone, so this names the two files and how to clear it, and nothing else.
    """
    path, bak = _r35j_dropin_paths(socket_mode)
    return i18n.Sentence("{bak} differs from {path}: an earlier SSH port change on this host was not undone, or "
                         "its snapshot was not removed after it worked. If {path} is the configuration you want, "
                         "delete {bak}; otherwise copy {bak} over {path} to go back to the one before that "
                         "change. Then try again. Nothing changed.", path=path, bak=bak)


# The undo's parts, in the order they run (the table above).
_R35B_UNDO_PARTS = {"restore": _r34b_restore_once, "reload": _r35b_undo_reload, "added": _r35b_undo_close,
                    "relisten": _r35b_undo_relisten}
_R35B_UNDO_ORDER = ("restore", "reload", "added", "relisten")


def _r35b_after_commit(server, ports, discard_verb):
    """Steps 7 and 8, after COMMIT: each best effort, and neither can raise.

    -> (fail2ban's (state, why), whether the snapshot was removed).

    The move is verified by now. A raise here used to reach the undo wrapper, which restored from a
    snapshot the discard had already removed: the restore verb then deleted the new drop-in, sshd fell
    back to sshd_config's port alone, and the route kept the panel dialling the port just dropped.
    """
    try:
        f2b = _point_f2b_sshd_at(server, ports)     # catches its own; this keeps COMMIT final regardless
    except Exception:
        _core._log.warning("ssh port move: fail2ban could not be repointed on %s", _r34j_log_name(server),
                           exc_info=True)
        f2b = ("failed", i18n.Sentence("the host did not answer"))
    return f2b, _r35j_discard_snapshot(server, discard_verb)


def _r35j_discard_snapshot(server, discard_verb):
    """Step 8: remove the snapshot, tried once more when the answer was not 0. -> True when it is gone.

    One left behind differs from the drop-in the move just wrote, and the next move's snapshot verb
    refuses over it (_R35J_SNAPSHOT_HELD) until it is removed, so the success message has to say so.
    """
    for _ in range(2):
        try:
            if _rc_of(_core.run_privileged(server, discard_verb, [], timeout=10, merge_stderr=False)) == 0:
                return True
        except Exception:
            _core._log.warning("ssh port move on %s: its drop-in snapshot could not be removed",
                               _r34j_log_name(server), exc_info=True)
    return False


def _r35j_snapshot_left_note(socket_mode, gone):
    """The success message's note when step 8 could not remove the snapshot; "" when it was removed."""
    if gone:
        return ""
    path, bak = _r35j_dropin_paths(socket_mode)
    return i18n.Sentence("The snapshot {bak} may not have been removed: while it is there, the next SSH port "
                         "change refuses until you delete it ({path} is the configuration in use).",
                         path=path, bak=bak)


def _r35b_moved_message(new_port, bind_addr, f2b, unchecked):
    """change_ssh_port's success message, from fail2ban's (state, why) and the sshd-holds note."""
    _f2b, _f2b_why = f2b
    if _f2b == "updated":
        _done = i18n.Sentence("firewall + fail2ban updated")
    elif _f2b == "absent":
        _done = i18n.Sentence("firewall updated; {why}, so nothing bans SSH brute force on any port",
                              why=_f2b_why)
    else:
        _done = i18n.Sentence("firewall updated, but fail2ban was NOT: {why}, so it may not be banning SSH "
                              "brute force on port {port}", why=_f2b_why, port=new_port)
    if bind_addr:
        # No fallback sentence here: ListenAddress is all-or-nothing (change_ssh_port's own docstring
        # says so), so sshd is now on THIS address and nothing else. Telling the operator a previous
        # port is still available would be untrue exactly when it matters most.
        return i18n.Sentences(i18n.Sentence(
            "SSH now listens on {address}:{port}, and only there ({done}). Confirm you can still reach it "
            "before closing anything.", address=bind_addr, port=new_port, done=_done), unchecked)
    if _f2b == "failed":
        # Closing the old port is the advice that assumes fail2ban covers the new one.
        return i18n.Sentences(i18n.Sentence(
            "SSH now listens on port {port} ({done}). The previous port is still available as a fallback; fix "
            "fail2ban before relying on it for port {port}.", port=new_port, done=_done), unchecked)
    return i18n.Sentences(i18n.Sentence(
        "SSH now listens on port {port} ({done}). The previous port is still available as a fallback — "
        "once you've confirmed you can reach SSH on {port}, close the old one from the Firewall page.",
        port=new_port, done=_done), unchecked)


@_r32b_undo_on_raise
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
    undo = _r32b_move_undo()
    try:
        new_port = int(new_port)
    except (TypeError, ValueError, OverflowError):
        return False, "Enter a valid port number."
    if not (1 <= new_port <= 65535):
        return False, "Port must be between 1 and 65535."
    # Canonical from here on, and never with a zone id. _valid_ip used to keep the typed text, and
    # ipaddress keeps a zone verbatim, newlines included: 'fe80::1%a' + a newline + anything closed
    # the ListenAddress line and wrote the rest as lines of their own into a root-owned sshd or
    # ssh.socket drop-in on a remote — where no line grammar checks the file, and the socket unit
    # is reloaded before anything validates it. That is past what MANAGE_REMOTES grants.
    bind_addr = (str(bind_addr) if bind_addr else "").strip()
    if bind_addr:
        bind_addr = canonical_ip(bind_addr)
        if bind_addr is None:
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
        if ip_address_or_none(bind_addr).is_loopback:
            return False, i18n.Sentence("Binding SSH to {address} would make it reachable only from the host "
                                        "itself — remote SSH would stop working, and binding is all-or-nothing so "
                                        "there is no fallback to revert to. Use the address you actually connect "
                                        "on.", address=bind_addr)
        # ...and on the panel's own host, an address the host does not HAVE. This used to be caught
        # for free: sshd could not bind a missing address, so it failed to start and the listening
        # check reverted. Under socket activation systemd creates the socket anyway, so something
        # IS listening on the port and that check passes while SSH is reachable nowhere. Measured:
        # `ListenStream=192.0.2.99:22` left `192.0.2.99:22` in ss and nothing answering on the
        # host's real IP. For a remote, _tcp_reachable below is still the backstop.
        if _core.is_local_server(server):
            from panel.ops import system_ops as _so
            if not _so.host_has_ip(bind_addr):
                return False, i18n.Sentence("{address} isn't an address on this host, so sshd could only bind it in "
                                            "name — SSH would answer nowhere. Use one of the host's own addresses.",
                                            address=bind_addr)

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
    # Two lists. `served` is what sshd really serves now, and decides the "already served" skips of
    # steps 0 and 1. `old_ports` is what the new drop-in keeps beside the new port, where one port
    # too many is the safe direction. They differ under socket activation: `sshd -T`'s Port, which
    # systemd ignores, belongs in the drop-in but is NOT served. Counted as served, a move back onto
    # it (2222 -> 22, after the operator had closed 22/tcp as the move advised) skipped opening it
    # in UFW and skipped the free-port check, reported success, and the route pointed the panel at a
    # port the firewall drops.
    if socket_mode:
        # ssh.socket's own ports only. Unread, nothing is known to be served but the stored port
        # (added below): step 1 then opens the port (the safe direction), and a port sshd really
        # holds fails step 0's free-port check instead of being "moved onto".
        served = list(_r26b_socket_ports(server) or [])
        old_ports = served + [p for p in _r26b_sshd_t_ports(server) if p not in served]
    else:
        served = old_ports = _sshd_current_ports(server)
    old_ports = old_ports or [str(int(getattr(server, "port", 22) or 22))]
    served = served or [str(int(getattr(server, "port", 22) or 22))]
    if socket_mode:
        # _sshd_current_ports reads ssh.socket's own listen ports (systemd's answer, after
        # the drop-in) — but that read can fail, and the port the panel is CONNECTED ON is known for
        # certain, and it is the one whose loss locks everybody out. Union it in unconditionally
        # rather than only as the empty-read fallback. It is not enough on its own: on a host the
        # panel reaches over Tailscale SSH the stored port stays 22 after a move. (Not done on the
        # sshd_config path: there `sshd -T` is authoritative, and adding a stale stored port would
        # re-open a port the operator had deliberately closed.)
        _stored = str(int(getattr(server, "port", 22) or 22))
        if _stored not in old_ports:
            old_ports = old_ports + [_stored]
        if _stored not in served:
            served = served + [_stored]
    if not bind_addr and old_ports == [str(new_port)]:
        return False, i18n.Sentence("SSH is already on port {port}.", port=new_port)
    # The panel's own host is checked above. A socket-activated host the panel reaches over Tailscale
    # SSH has the same hole and no backstop either: step 6 does not dial it (tailscaled answers there),
    # and the address check finds the socket systemd bound in name. So the host's own list decides.
    if bind_addr and socket_mode and not _r26b_dials_after_bind(server) and not _core.is_local_server(server):
        _has = _r26j_remote_has_ip(server, bind_addr)
        if _has is None:
            return False, i18n.Sentence("Could not list this host's addresses, so the panel can't tell whether "
                                        "{address} is one of them — nothing was changed.", address=bind_addr)
        if not _has:
            return False, i18n.Sentence("{address} isn't an address on this host, so sshd could only bind it in "
                                        "name — SSH would answer nowhere. Use one of the host's own addresses.",
                                        address=bind_addr)

    # Keep every current port plus the new one (new first).
    ports = []
    for p in [str(new_port)] + old_ports:
        if p not in ports:
            ports.append(p)

    # 0. The new port must be FREE. The check that sshd came up on it (step 6) is `ss -lnt`, which
    #    names no process, so any listener on the port answers it. With a web app on 8080, moving
    #    SSH there left sshd failing to bind it and serving the old port only, while ss showed
    #    0.0.0.0:8080, the snapshot was discarded, the route repointed the panel at a port that
    #    answers HTTP, and the message told the operator to close the one real SSH port. A port sshd
    #    already serves (a bind change on the current port) is its own listener and passes.
    if str(new_port) not in served:
        pre, _, pre_rc = _core.run_privileged(server, "listening-sockets", [], timeout=15,
                                              merge_stderr=False)
        if pre_rc != 0 or not (pre or "").strip():
            return False, i18n.Sentence("Could not list the ports this host listens on, so the panel can't tell "
                                        "whether {port} is free — nothing was changed.", port=new_port)
        if _port_has_listener(pre, new_port):
            return False, i18n.Sentence("Something on this host is already listening on port {port}, so sshd "
                                        "could not take it and the panel could not tell sshd from that service "
                                        "afterwards. Pick a free port — nothing was changed.", port=new_port)

    # 1. Open the new port in the firewall FIRST (best-effort; a host without UFW just no-ops) —
    #    unless a rule for it is already there, and remember whether THIS step added one: that is
    #    the only rule the revert may take away.
    #
    #    It used to open unconditionally and the revert closed `new_port/tcp` unconditionally. On a
    #    bind-address change that keeps port 22, or a move onto a port sshd already serves
    #    ([22, 2222] -> 2222), that rule existed before any of this — it is the one the panel's own
    #    connection comes in on — and a failed bind deleted it on the way out, under a message
    #    saying "Your existing SSH still works". And the open itself was not harmless there: ufw
    #    REPLACES a rule that differs only in action or comment (see remote_ufw_allow_game_ports),
    #    so `allow 22/tcp` turned the bootstrap's `LIMIT 22/tcp` into a plain ALLOW, silently
    #    dropping the brute-force brake, whether the move succeeded or not.
    #    Decided by the firewall's rules, never by what listens (see _open_ssh_port_rule): only the
    #    port the panel's own connection uses right now is left as it is.
    #
    #    ...and a BIND change on a port sshd already serves opens nothing on any row. It narrows
    #    who reaches that port; it never needs the firewall to let in more than it does today. On
    #    the panel host and a Tailscale-SSH row (no stored port in the way-in list) with public SSH
    #    turned "off" — only `on tailscale0` left, no public 22 rule — binding 22 to an address
    #    added `allow 22/tcp`, which stayed after the move worked: public SSH silently back on, the
    #    card reading "on", and nothing in the message saying so (review 1016e, adversarial F1).
    #    A move ONTO the port is a request to reach SSH there and is still decided by the rules
    #    (the move back to 22 after 22/tcp was closed must open it).
    _way_in = [str(int(getattr(server, "port", 22) or 22))] if _r26b_dials_after_bind(server) else []
    if bind_addr and str(new_port) in served:
        _way_in = _way_in + [str(new_port)]
    _ufw_added, _ufw_refused = _open_ssh_port_rule(server, new_port, _way_in)
    if _ufw_refused:
        return False, _ufw_refused
    undo.update(port=new_port, added=_ufw_added, socket=socket_mode)

    # 2. Snapshot any existing drop-in (so a failed bind change restores the EXACT prior state),
    #    then write the new one. Ubuntu 22.04/24.04 Include /etc/ssh/sshd_config.d/*.conf by default.
    #    (socket_mode is read above — old_ports depends on it.)
    _backup_verb, _restore_verb, _discard_verb, _target = (
        ("sshd-socket-backup", "sshd-socket-restore", "sshd-socket-discard", "sshd-socket-dropin")
        if socket_mode else
        ("sshd-backup-dropin", "sshd-restore-dropin", "sshd-discard-backup", "sshd-port-dropin"))

    # What 2a's snapshot found (a drop-in, none, or not said): the unconfirmed-restore message depends on it.
    _prior = None

    def _revert(msg, restart=True):
        # Undo what the move still owes (the table above _R32B_MOVE_UNDO): restore the snapshot if one
        # was taken, else drop the file; close the allow step 1 added and nothing else; restart the
        # listener onto a config sshd -t accepts. The prior binding is untouched the whole time, so
        # SSH keeps working. Each part is retired from `undo` as it is done, so a raise in here leaves
        # _r32b_undo_on_raise only what is still owed. restart=False: nothing reloaded or restarted
        # anything yet, so the running listener never read the new drop-in.
        if not restart:
            undo.pop("relisten", None)
        _r35b_unwind(server, undo)
        left = undo.pop("left", [])
        # Set when the undo's restart was not confirmed: SSH may be listening nowhere, so `msg` (which
        # can end "Your existing SSH still works.") is logged and this is said in its place.
        down = undo.pop("down", "")
        if undo.pop("unconfirmed", False):
            _core._log.warning("ssh port move on %s failed (%s) and its restore was not confirmed",
                               _r34j_log_name(server), str(msg).replace("\r", " ").replace("\n", " "))
            return False, i18n.Sentences(_r35j_unconfirmed_message(socket_mode, _prior), down, *left)
        if down:
            _core._log.warning("ssh port move on %s failed (%s) and SSH may not be listening after the undo",
                               _r34j_log_name(server), str(msg).replace("\r", " ").replace("\n", " "))
            return False, i18n.Sentences(down, *left)
        return False, i18n.Sentences(msg, *left) if left else msg

    # 2a. The snapshot decides whether a failure can be undone at all. Its rc used to be dropped (and
    #     the shell form ended `|| true`): a copy that failed left no snapshot, or half of one, and the
    #     undo then removed the drop-in or put the half back. After an earlier move (2222 + 22, 22
    #     closed as advised) that took sshd off the port the panel dials. Unsnapshotted, nothing goes on.
    _snap = _core.run_privileged(server, _backup_verb, [], timeout=10, merge_stderr=False)
    _snap_rc = _rc_of(_snap)
    if _snap_rc == _R35J_SNAPSHOT_HELD:
        # A snapshot is already there and DIFFERS from the drop-in: an earlier move did not finish (its
        # restore was not confirmed, or its discard failed after it worked), so the snapshot may be the
        # only good copy. Held on the difference alone, whatever `sshd -t` says. A new snapshot would
        # put the drop-in in its place.
        return _revert(_r35j_held_message(socket_mode), restart=False)
    if _snap_rc != 0:
        return _revert(i18n.Sentence("The current SSH port configuration could not be backed up, so a failed "
                                     "change could not be undone — nothing changed."), restart=False)
    # A snapshot exists now (or, with no drop-in, none is left): from here a failure restores it.
    _prior = _r36b_snap_prior(_snap[0] if isinstance(_snap, tuple) else "")
    # copies: the snapshot verb said what it found, so the restore is the copy-and-keep one a second run
    # of is safe (_r34b_restore_once retries only then).
    undo.update(restore=_restore_verb, reload=socket_mode, relisten=True, copies=_prior is not None)
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

    # The write's rc decides before anything validates or restarts. It used to be dropped: on a
    # remote whose drop-in directory did not exist (stock socket-activated 24.04 has no
    # /etc/systemd/system/ssh.socket.d) the write failed, `sshd -t` passed the UNCHANGED config,
    # and a port move was reverted as "sshd didn't come up" — or a bind change on the current port
    # reported "SSH now listens on <ip>:22, and only there" while sshd still answered everywhere.
    # Nothing was restarted yet, so the running listener is still the old one: no restart.
    _wr = _core.write_root_file(server, _target, header + body, timeout=15)
    if _wr[2] != 0:
        return _revert(i18n.Sentence("The new SSH port configuration could not be written ({why}) — "
                                     "nothing changed.", why=_r11a_why(_wr)), restart=False)
    if socket_mode:
        # A changed unit file is inert until systemd re-reads it.
        _core.run_privileged(server, "systemd-daemon-reload", [], timeout=20, merge_stderr=False)

    # 3. Validate the WHOLE sshd config; if the drop-in breaks it, roll back and abort (no restart).
    tout, terr, trc = _core.run_privileged(server, "sshd-validate", [], timeout=15)
    terr = terr or tout
    if isinstance(trc, int) and trc < 0:
        # No answer (a Tailscale or local transport answers a lost command -1): nothing says sshd
        # rejected anything, so the message does not claim it. Undone all the same.
        return _revert(i18n.Sentence("`sshd -t` could not be run to check the new config ({why}), so the change "
                                     "was undone — nothing changed.", why=(terr or "no answer")[:120]))
    if trc != 0:
        return _revert(i18n.Sentence("sshd rejected the new config — nothing changed. ({why})",
                                     why=(terr or "invalid")[:120]))

    # 4. (fail2ban is repointed at step 7, once the move is VERIFIED: done here, before the restart,
    #    a reverted change left fail2ban banning on a port nothing serves.)

    # 5. Restart whatever actually holds the port. Established sessions survive either way.
    _restart_ssh_listener(server, socket_mode)

    # 6. Verify. A bind change must confirm the panel can still REACH the host (no all-interfaces
    #    fallback); a port-only change just confirms sshd bound the new port.
    #    Not on a host the panel reaches over Tailscale SSH: its way in is tailscaled on port 22,
    #    which no sshd bind touches, so dialling `server.host` (the tailnet address) on the new port
    #    reverted every bind to the host's public address as "not the one the panel connects to".
    #    There, as on the panel's own host, the address check below confirms sshd bound it.
    if bind_addr and _r26b_dials_after_bind(server):
        if not _tcp_reachable(server.host, new_port, timeout=8):
            return _revert(i18n.Sentence("After binding SSH to {address}, the panel couldn't reach it on "
                                         "{host}:{port} — reverted. The bind address has to be the one the panel "
                                         "connects to.", address=bind_addr, host=server.host, port=new_port))
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
                return _revert(i18n.Sentence("sshd isn't listening on {address}:{port} — reverted. Your existing "
                                             "SSH still works.", address=bind_addr, port=new_port))
        elif not _port_has_listener(out, new_port):
            return _revert(i18n.Sentence("sshd didn't come up on port {port} — reverted. Your existing SSH still "
                                         "works.", port=new_port))

    #    ...and that what answers there IS sshd. Both checks above are process-blind (`ss -lnt` and
    #    a TCP connect), so a local account that bound the port after step 0 passed them, the route
    #    repointed the panel at it, and the next connection offered it the stored credential.
    _holds, _why = _sshd_holds_port(server, new_port, bind_addr, socket_mode)
    if _holds is False:
        return _revert(i18n.Sentence("Port {port} is not held by sshd ({why}) — reverted. Your existing SSH "
                                     "still works.", port=new_port, why=_why))
    _unchecked = ("" if _holds else
                  i18n.Sentence("(The panel could not confirm that sshd itself holds port {port}: {why} — "
                                "the panel-helper on this host may predate that check; re-running "
                                "install.sh updates it.)", port=new_port, why=_why))

    # C. COMMIT: verified, so the move stands. Nothing below can undo it (the table above _R32B_MOVE_UNDO).
    _r35b_commit(undo)
    # 7 + 8. Point fail2ban's sshd jail at the new + old ports so its bans cover the port now served,
    #    and drop the snapshot: best effort, after the commit.
    _f2b, _gone = _r35b_after_commit(server, ports, _discard_verb)
    return True, _r35b_moved_message(new_port, bind_addr, _f2b,
                                     i18n.Sentences(_unchecked, _r35j_snapshot_left_note(socket_mode, _gone)))


# The rules that open SSH without being `22/tcp` to ufw: the OpenSSH app profile and a bare `22`
# (protocol any). ufw never matches either against a `22/tcp` rule, so a delete or a limit of
# `22/tcp` leaves them in place — AHEAD of whatever was just appended, where every connection
# meets them first. Removed wherever the panel sets what public SSH is.
_SSH22_SHADOWING = (("ufw-delete-allow-app", ["OpenSSH"]), ("ufw-delete-allow-port", ["22"]))


_R22B_OPENNESS = {"off": 0, "limit": 1, "allow": 2}


# The Public SSH card's refusal when it cannot tell which ports sshd serves (_r32b_public_ssh_ports).
_R32B_PORTS_UNREAD = ("Could not read which port sshd serves on this host, so public SSH was not changed — "
                      "check the host and try again.")
_R32B_PORTS_UNREAD_AFTER = ("Could not read which port sshd serves on this host afterwards, so whether public "
                            "SSH changed is unknown — check the host and try again.")


def _r32b_after_refusal(state):
    """What a public-SSH change says when the read-back cannot say what it did, else None.

    "I could not read the firewall" is not "UFW is not active" — both refuse, but only one of them
    is a fact about the host, and the other message sends the operator to check a setting that may
    be fine. Nor is an unread port list "off".
    """
    if state.get("unreachable"):
        return ("Could not read this host's firewall afterwards, so whether public SSH changed is "
                "unknown — check the host and try again.")
    if not state.get("active"):
        return ("UFW is not active on this host, so public SSH cannot be controlled from here — the "
                "SSH port is governed by whatever else is in front of it.")
    return _R32B_PORTS_UNREAD_AFTER if state.get("ports_unread") else None


def _r32b_dial_port(server):
    """The port the panel dials sshd on, as an int, or None when the panel does not dial sshd.

    None on the panel's own host (it does not SSH to itself) and on a Tailscale-SSH host, where the
    stored port is tailscaled's 22 whatever sshd serves (sshd_listen_ports says why).
    """
    if _core.is_local_server(server) or getattr(server, "auth_method", "") == "tailscale":
        return None
    try:
        port = int(getattr(server, "port", 22) or 22)
    except (TypeError, ValueError, OverflowError):
        return None
    return port if 1 <= port <= 65535 else None


def _r32b_public_ssh_ports(server):
    """(sshd's own ports, the ports the Public SSH card manages): ints in sshd's order, [] when unread.

    The card and its actions acted on port 22 whatever sshd served. After the panel's own move
    (change_ssh_port, which tells the operator to close the old port) sshd answered on 2222, the
    card reported "disabled — tailnet only" from 22's rules while 2222 stayed open to the internet,
    and Limit / Disable / Close changed 22 alone. These are the ports sshd really serves
    (sshd_listen_ports: ssh.socket's while it holds the socket, else `sshd -T`'s), plus the one the
    panel dials it on, as _bootstrap_ssh_ports does: under socket activation an unread systemd falls
    back to `sshd -T`, which names sshd_config's Port and not the socket's. Not on a host the panel
    does not dial sshd on (_r32b_dial_port): there an unread sshd leaves [], and the card refuses
    rather than act on a guessed 22.
    """
    try:
        sshd = sshd_listen_ports(server)
    except Exception:
        _core._log.debug("public SSH: sshd's ports could not be read", exc_info=True)
        sshd = []
    dial = _r32b_dial_port(server)
    return sshd, sshd + ([dial] if dial and dial not in sshd else [])


# Public SSH's allow/limit: (the add that gates, the other action's delete), per port.
_R32B_SET_VERBS = {"allow": ("ufw-allow-port", "ufw-delete-limit-port"),
                   "limit": ("ufw-limit-port", "ufw-delete-allow-port")}


def _r32b_ssh_rule_steps(ports, mode):
    """The ufw steps that set public SSH on `ports` to `mode`: (gates, then the rest), flattened for "off".

    allow/limit: the adds for every port come first and are the gate (remote_set_public_ssh runs the
    rest only once all of them took); then the other action's rule for each port and the rules that
    shadow it. off: every port's ALLOW and LIMIT, and the shadowing rules.
    """
    specs = ["%d/tcp" % int(p) for p in ports]
    if mode in _R32B_SET_VERBS:
        add, drop = _R32B_SET_VERBS[mode]
        extra = [""] if add == "ufw-allow-port" else []     # ufw-allow-port's (empty) comment
        return ([(add, [sp] + extra) for sp in specs],
                [(drop, [sp]) for sp in specs] + _r32b_shadowing(ports))
    return ([("ufw-delete-allow-port", [sp]) for sp in specs]
            + [("ufw-delete-limit-port", [sp]) for sp in specs] + _r32b_shadowing(ports))


def _r32b_shadowing(ports):
    """The deletes of the rules that open `ports` without being `N/tcp` to ufw (_SSH22_SHADOWING's).

    The OpenSSH profile is port 22's alone (ufw's profile fixes it), so it goes only when 22 is one
    of `ports`; a bare `N` (any protocol) is removed for every port, as `22` was.
    """
    nums = [int(p) for p in ports]
    return ([("ufw-delete-allow-app", ["OpenSSH"])] if 22 in nums else []) + \
        [("ufw-delete-allow-port", [str(n)]) for n in nums]


def _r32b_run_gates(server, gates):
    """Run every gating add in turn; at the first refused one stop: "<spec>: <ufw's words>", else None."""
    for verb, vargs in gates:
        out, err, rc = _core.run_privileged(server, verb, vargs, timeout=15)
        if rc != 0:
            # The spec that failed, then ufw's own words (host text, not translated).
            return "%s: %s" % (vargs[0], (err or out or "exit %s" % rc).replace("\n", " ").strip()[:160])
    return None


def _r32b_public_mode(out, ports):
    """(mode, first rule, its port) of public SSH across `ports`: the most open port's answer.

    One port's answer is its first public rule in each family (_r22b_first_rules), the more open one
    standing; across ports the same, since public SSH is as open as its most open door.
    """
    first, mode, at = None, "off", None
    for port in ports:
        for f in _r22b_first_rules(out, port, "tcp"):
            m = {"LIMIT": "limit", "ALLOW": "allow"}.get(f["action"], "off") if f else "off"
            if first is None or _R22B_OPENNESS[m] > _R22B_OPENNESS[mode]:
                first, mode, at = f, m, port
    return mode, first, at


def remote_public_ssh_status(server, panel_port=None):
    """Report public SSH state: 'allow', 'limit', or 'off' (no rule — reachable only over
    tailscale0), plus whether UFW is active at all, on every port sshd serves (`ssh_ports`,
    _r32b_public_ssh_ports; sshd's own as `sshd_ports`). An unread port list is mode 'unknown'
    with `ports_unread`. When
    `panel_port` is given, also report whether that port has a public ALLOW rule
    (`panel_port_open`) so the UI can disable "Close public panel port" once it's
    already closed. `panel_port` may be a list of the panel's ports (the one it serves
    on, then a saved one waiting for its restart): reported as the first, and open
    while any of them is, as Close closes them all."""
    ports = _r31a_port_list(panel_port)
    panel_port = ports[0] if ports else None
    sshd_ports, ssh_ports = _r32b_public_ssh_ports(server)
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
    out, _err, rc = _core.run_privileged(server, "ufw-status", ["plain"], timeout=12)
    # rc 127 alone, as remote_ufw_status reads it: a missing ufw is 127 from every transport, and
    # a text test read the whole listing, rule comments included — "plex not installed yet" or a
    # game server named "map not found" made an active firewall read as no UFW at all.
    if rc == 127:
        # ufw is ABSENT, which is a reading and not a failure to read — but it is still not
        # "off". `off` in this function means "no rule, so tailnet-only", and with no firewall at
        # all nothing governs port 22, so that label would point the wrong way.
        res = {"active": False, "mode": "unknown", "installed": False}
    elif rc != 0 or not (out or "").strip():
        res = {"active": False, "mode": "unknown", "unreachable": True}
    else:
        res = None
    if res is not None:
        res.update(ssh_ports=ssh_ports, sshd_ports=sshd_ports)
        if panel_port:
            res["panel_port"] = int(panel_port)
            res["panel_port_open"] = False
        return res
    active = firewall._ufw_is_active(out)
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
    #
    # Both are now _ufw_first_public_rule's, which reads every shape ufw prints for port 22. The
    # `_SSH22_RE` this matched with knew
    # only `22`, `22/tcp` and OpenSSH, so a host whose SSH was open through a list (`22,80/tcp`), a
    # destination (`203.0.113.5 22/tcp`) or an every-port allow read "off" — "reachable over the
    # tailnet only", the reassurance an operator closes port 22 on — and `off` / `limit` reported
    # success with every connection still meeting that rule.
    # Each family read on its own, and the more open answer stands: a `(v6)` ALLOW above the v6
    # LIMIT is public SSH unthrottled for every IPv6 client, whatever the IPv4 list says.
    # And every port sshd serves, the most open one standing (_r32b_public_mode): 22 alone read
    # "off" on a host whose sshd the panel had moved to 2222, with 2222 open to the internet.
    if ssh_ports:
        mode, first, first_port = _r32b_public_mode(out, ssh_ports)
    else:
        mode, first, first_port = "unknown", None, None
    panel_open = False
    for line in (out or "").splitlines():
        # A rule that holds the panel port open to the public, read the way the close route
        # (remote_vps _panel_port_rule_nums) reads it: inbound ALLOW *or LIMIT*, on no interface.
        # This was `"allow" in low`, so a rate-limited port (`ufw limit 5000/tcp`, which
        # firewall._is_panel_rule calls "an ordinary thing to do") read as closed, and the card
        # disabled "Close public panel port" saying the panel was tailnet-only while the port was
        # open to the internet. An IPv6-only rule is open too, and a comment that happens to say
        # "tailscale" is no interface.
        # (Parsed, not searched for the number first: a range `4000:6000` never contains "5000".)
        if panel_port and _r31a_holds_any_open(line, ports):
            panel_open = True
    res = {"active": active, "mode": mode, "ssh_ports": ssh_ports, "sshd_ports": sshd_ports}
    if not ssh_ports:
        res["ports_unread"] = True
    if first:
        # The row itself, so a change that could not take (remote_set_public_ssh) names it.
        res["rule"] = first["detail"]
        res["rule_port"] = first_port
    if panel_port:
        res["panel_port"] = int(panel_port)
        res["panel_port_open"] = panel_open
    return res


def _r31a_port_list(panel_port):
    """remote_public_ssh_status's `panel_port` as a list of ports: [] for none.

    A list whichever shape it came in, so every return is one type (CodeQL py/mixed-tuple-returns
    read the one- and zero-element tuples as two).
    """
    if isinstance(panel_port, (list, tuple)):
        return [p for p in panel_port if p]
    return [panel_port] if panel_port else []


def _r31a_holds_any_open(line, ports):
    """Whether one `ufw status` row lets the public in on any of `ports` (_r14a_holds_port_open)."""
    return any(_r14a_holds_port_open(line, p) for p in ports)


def _r14a_holds_port_open(line, port):
    """Whether one `ufw status` row lets the public in on `port` (firewall._r14a_panel_port_scope)."""
    p = firewall._parse_ufw_rule(line)
    if not p["action"]:
        return False
    p["port_num"], p["proto_label"] = firewall._split_ufw_proto(firewall._ufw_port_label(p))
    p["src"] = p["from"]        # the display group's names, which the UDP and host-only tests read
    return bool(firewall._r14a_panel_port_scope(p, port))


def _tailscale_conn_state(server):
    """(running, ssh_enabled) — whether Tailscale is up on this host and advertises its
    SSH server. Tailscale SSH works regardless of UFW, so when it's on the host always
    has a way in. Best-effort; fails safe to (False, False)."""
    import json as _json
    running = ssh_enabled = False
    try:
        out, _, _ = _core.run_command(server, "tailscale status --json 2>/dev/null || echo '{}'", timeout=10,
                                      sudo=False)
        running = _json.loads(out or "{}").get("BackendState") == "Running"
    except Exception:
        running = False   # can't confirm → treat as not running (fail safe)
    if running:
        try:  # authoritative: prefs RunSSH
            out, _, _ = _core.run_command(server, "tailscale debug prefs 2>/dev/null || echo '{}'", timeout=10,
                                          sudo=False)
            ssh_enabled = bool(_json.loads(out or "{}").get("RunSSH", False))
        except Exception:
            ssh_enabled = False   # fail safe
    return running, ssh_enabled


# Tailscale peers get CGNAT addresses from 100.64.0.0/10. A public attacker can't have a source in
# that range, so the panel never firewall-blocks a tailnet IP while Tailscale is up — blocking one
# would cut off tailnet access (and, inserted at UFW position 1, it would override the tailscale0
# allow rule).
_TAILNET_CGNAT = "100.64.0.0/10"  # NOSONAR - the range Tailscale assigns every node from, fixed by Tailscale


def tailnet_exempt_ips(server, ips):
    """Of `ips`, the Tailscale-range (100.64.0.0/10) addresses that must NOT be firewall-blocked —
    but only when Tailscale is actually running on this host. Returns a set of canonical IP strings
    (empty if Tailscale is down or nothing is in range). Works for local + remote (run_command
    dispatches). Best-effort; fails safe to no exemptions."""
    net = ip_network_or_none(_TAILNET_CGNAT)
    if net is None:
        return set()
    cand = set()
    for ip in ips or ():
        addr = ip_address_or_none(ip)
        if addr is None:
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
    #
    # sudo=False: a read any local user may make. Under sudo, a remote whose sudo wants a password
    # answered rc 1 with nothing on stdout, which read as "the host answered: not running", and the
    # tailnet addresses lost their exemption — the unsafe direction for this guard.
    import json as _json
    try:
        out, _err, rc = _core.run_command(server, "tailscale status --json", timeout=10, sudo=False)
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


# A kernel interface name as /sys/class/net lists it (IFNAMSIZ is 16 including the NUL).
_TSIFACE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")


def _tsiface_names(server):
    """The host's Tailscale TUN interfaces (names containing "tailscale"), from /sys/class/net.

    [] when there is none — tailscaled in userspace-networking mode has no TUN, so no UFW interface
    rule can carry SSH there — AND when the listing could not be read: this feeds a lockout guard,
    so "unknown" must answer the same as "absent". Every Linux host lists `lo`, so a listing
    without it (an empty answer from a transport that timed out) is not a reading.
    """
    try:
        out, _err, rc = _core.run_command(server, "ls -1 /sys/class/net", timeout=10, sudo=False)
    except Exception:
        _core._log.debug("tailscale interface probe failed", exc_info=True)
        return []
    names = [n.strip() for n in (out or "").splitlines() if _TSIFACE_NAME_RE.fullmatch(n.strip())]
    if rc != 0 or "lo" not in names:
        return []
    return [n for n in names if "tailscale" in n.lower()]


def _tsiface_ufw_rules(status_out):
    """`ufw status verbose` rows as system_ops._ufw_rule_split shapes them, in UFW's order.

    Not system_ops.ufw_status's loop: that one drops every row with a parenthesis in it, which
    takes a `DENY IN` on tailscale0 whose comment says "(old)" out of the first-match walk and
    lets the allow below it answer. Every row is kept here; a `(v6)` To column cannot read as the
    whole-interface allow (ufw_allows_iface_in compares it exactly), so it can only answer False.
    """
    from panel.ops import system_ops as _so
    rules = []
    for line in (status_out or "").splitlines():
        rule = _so._r14a_ufw_row(line.strip())   # the comment out of `from`
        if rule:
            rules.append(rule)
    return rules


def _tailnet_ssh_state(server):
    """(running, ssh_enabled, iface_allowed) — the inputs to deciding whether removing
    public SSH is safe. iface_allowed = the tailscale0 interface is allowed in UFW (so
    sshd is reachable over the tailnet). Works for local + remote hosts; fails safe."""
    running, ssh_enabled = _tailscale_conn_state(server)
    iface_allowed = False
    if running:
        # The same structured, first-match, IN-only test the panel host's own page uses
        # (system_ops.ufw_allows_iface_in — its docstring has the history). This was a substring
        # match for "tailscale" over the whole `ufw status verbose` text, so `ALLOW OUT ... on
        # tailscale0`, `on tailscale0 DENY IN`, or any rule commented "tailscale" (the common
        # `41641/udp ALLOW # tailscale`) read as "sshd is reachable over the tailnet", and "Disable
        # public SSH" / "Close port 22" then removed the only way in. A failed read, a rule set
        # that does not open the interface, or no Tailscale interface on the host all answer False.
        try:
            out, _, rc = _core.run_privileged(server, "ufw-status", ["verbose"], timeout=12)
            if rc == 0:
                from panel.ops import system_ops as _so
                rules = _tsiface_ufw_rules(out)
                iface_allowed = any(_so.ufw_allows_iface_in(rules, i) for i in _tsiface_names(server))
                # The firewall letting tailscale0 in is not sshd answering there: after the panel's
                # own bind-address change (change_ssh_port's ListenAddress is all-or-nothing) sshd
                # listens on the public address alone, and removing public SSH then left no way in.
                if iface_allowed and _r11a_sshd_off_tailnet(server):
                    iface_allowed = False
        except Exception:
            iface_allowed = False   # fail safe
    return running, ssh_enabled, iface_allowed


# Tailscale's address ranges: IPv4 CGNAT (_TAILNET_CGNAT, above), and its IPv6 ULA prefix.
_r11a_tailnet_nets = (_ipaddress.ip_network(_TAILNET_CGNAT),
                      _ipaddress.ip_network("fd7a:115c:a1e0::/48"))


def _r11a_sshd_off_tailnet(server):
    """True when sshd is SEEN listening only on addresses tailnet traffic cannot reach.

    Every listener on an sshd port (sshd -T's, as `ss -lnt` lists them) is a specific address that
    is neither a wildcard nor a Tailscale address. Only positive evidence answers True: an unread
    port list or listing, no listener seen, or an address it cannot parse is False, which leaves
    the firewall test above as the whole answer — what it was before this check existed — rather
    than refusing on a helper too old to answer.
    """
    try:
        ports = {int(p) for p in _sshd_current_ports(server)}
        if not ports:
            return False
        # With the port the panel connects on, as _bootstrap_ssh_ports does: under socket
        # activation `sshd -T` prints sshd_config's Port while ssh.socket listens where it was
        # edited to, so a socket moved to <public-ip>:2222 showed no listener on 22 and answered
        # False. Only once sshd -T was read: an unread one still leaves the firewall test to decide.
        ports.add(int(getattr(server, "port", 22) or 22))
        out, _err, rc = _core.run_privileged(server, "listening-sockets", [], timeout=15,
                                             merge_stderr=False)
    except Exception:
        _core._log.debug("sshd listener read failed", exc_info=True)
        return False
    addrs = [a for a, p, _f in _ss_listeners(out) if p in ports] if rc == 0 else []
    return bool(addrs) and all(_r11a_off_tailnet_addr(a) for a in addrs)


def _r11a_off_tailnet_addr(a):
    """True when listener address `a` is a specific address that is not a Tailscale one."""
    a = a.strip("[]").split("%", 1)[0]
    if a in ("*", "0.0.0.0", "::"):
        return False
    ip = ip_address_or_none(a)
    return not (ip is None or any(ip.version == n.version and ip in n for n in _r11a_tailnet_nets))


def _r28b_resolve(host):
    """Every address `host` resolves to on the panel host, as text; [] when it does not resolve."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    except (OSError, UnicodeError):
        return []


def _r32b_panel_dials_public(server):
    """True when the panel's OWN connection to `server` comes in through its public SSH rules.

    The "off"/close gate asks only whether the OPERATOR has a Tailscale way back in. A key or
    password host the panel reaches at a public address passed it, and removing the public SSH
    rules dropped the panel's next connection (the one open now survives as established, so the
    read-back still said it worked): the host read unreachable from then on.
    Not the panel host (it does not SSH), a Tailscale-SSH host (tailscaled answers on the tailnet).
    A name is resolved here: a tailnet name passes, and one that does not resolve counts as public,
    the side that keeps the rule.

    Whatever port it dials: this was "port 22 only" while "off" removed 22 alone, and "off" now
    removes the rules for every port sshd serves AND the one the panel dials (_r32b_public_ssh_ports),
    so the panel's port is always among them — and a dial port sshd does not list is a forward to
    one that it does, whose rule goes too.
    """
    if _core.is_local_server(server) or getattr(server, "auth_method", "") == "tailscale":
        return False
    return not _r28b_host_on_tailnet((getattr(server, "host", "") or "").strip().strip("[]"))


def _r28b_host_on_tailnet(host):
    """True when `host` (an address or a name) is reached over the tailnet; an unresolved name is not."""
    if host.lower().rstrip(".").endswith(".ts.net"):
        return True
    addrs = [host] if ip_address_or_none(host) is not None else _r28b_resolve(host)
    return bool(addrs) and all(_r28b_tailnet_addr(a) for a in addrs)


def _r28b_tailnet_addr(a):
    """True when address `a` is a Tailscale one (CGNAT 100.64/10 or Tailscale's IPv6 prefix)."""
    ip = ip_address_or_none(a.split("%", 1)[0])
    return ip is not None and any(ip.version == n.version and ip in n for n in _r11a_tailnet_nets)


def _r28b_panel_way_in_refusal(server):
    """The refusal for removing public SSH while the panel itself comes in through it, else None."""
    if not _r32b_panel_dials_public(server):
        return None
    return i18n.Sentence("Refused — the panel itself connects to this host at {host} on port {port} through the "
                         "public SSH rule, so removing it would cut the panel off. Move this host to Tailscale SSH "
                         "(or point it at its Tailscale address) first.", host=getattr(server, "host", ""),
                         port=getattr(server, "port", "") or 22)


def _r34b_ports_to_open(server, ports):
    """Allow/Limit's share of `ports` (_r32b_public_ssh_ports'): the ones public SSH is open on now.

    That is each port whose first public rule lets TCP in (ALLOW or LIMIT), plus the port the panel
    dials sshd on, in `ports`' order. Every port sshd listens on was re-opened: after the panel's own
    move 22 -> 2222 sshd keeps 22 as a fallback, the operator closes 22/tcp as the move advises, and
    Limit put `22/tcp LIMIT` back, public again. A port with no public rule stays closed. With none
    open at all (public SSH "off", or a listing that cannot be read) there is no way to tell a
    deliberately closed port from the one meant, so sshd's first port only: the one the panel's own
    move writes first.
    """
    out, _err, rc = _core.run_privileged(server, "ufw-status", ["plain"], timeout=12)
    listed = rc == 0 and bool((out or "").strip())
    dial = _r32b_dial_port(server)
    keep = [p for p in ports if p == dial or (listed and _r32b_public_mode(out, [p])[0] != "off")]
    return keep or ports[:1]


def remote_set_public_ssh(server, mode):
    """Control PUBLIC (non-tailnet) SSH via UFW, on every port sshd serves (_r32b_public_ssh_ports):
      allow → `ufw allow N/tcp`  (open to the internet)
      limit → `ufw limit N/tcp`  (rate-limited brute-force protection; recommended)
      off   → remove the allow/limit rules (SSH only via the tailscale0 interface)
    tailscale0 SSH is unaffected either way. `off` is REFUSED unless there is a working
    Tailscale path back in (Tailscale running + SSH enabled or the tailscale0 interface
    allowed in UFW) — otherwise it would strand you with no way to reach the host. Every
    mode is refused when sshd's ports cannot be read: a guessed 22 is the bug this replaced."""
    mode = (mode or "").lower()
    if mode not in ("allow", "limit", "off"):
        return False, "Invalid mode"
    # The new rule goes in FIRST: ufw rewrites a rule that differs only in its action where it
    # stands (`ufw limit 22/tcp` turns `22/tcp ALLOW` into `22/tcp LIMIT` in place), so there is
    # no moment with nothing letting SSH in. Then everything else that would match the port AHEAD
    # of it goes — `ufw allow OpenSSH` and a bare `ufw allow 22` are how most Ubuntu hosts opened
    # SSH, neither is the same rule as `22/tcp` to ufw, and whichever sorts first is the one a
    # connection meets. Leaving them made 'limit' a rule nothing ever reached.
    if mode == "off":
        running, ssh_enabled, iface_allowed = _tailnet_ssh_state(server)
        if not (running and (ssh_enabled or iface_allowed)):
            return False, ("Refused — there's no Tailscale way back into this host, so disabling "
                           "public SSH would lock you out. Enable Tailscale SSH, or make sure "
                           "Tailscale is running and the tailscale0 interface is allowed in UFW, first.")
        _cut = _r28b_panel_way_in_refusal(server)
        if _cut is not None:
            return False, _cut
    ports = _r32b_public_ssh_ports(server)[1]
    if not ports:
        return False, _R32B_PORTS_UNREAD
    if mode == "off":
        gates, steps = [], _r32b_ssh_rule_steps(ports, "off")
    else:
        ports = _r34b_ports_to_open(server, ports)
        gates, steps = _r32b_ssh_rule_steps(ports, mode)
    # ...but only once it IS in. The loop below ignores every exit code, because a delete's says
    # nothing (ufw exits 0 for a rule that is not there, and non-zero for a held lock) — and it ignored the add's too, so when `ufw limit 22/tcp`
    # failed (a timeout, a held lock) it went on to delete the OpenSSH and bare-22 allows anyway,
    # and a host opened only by `ufw allow OpenSSH` was left with nothing letting SSH in. The
    # read-back below reported the failure after the lockout. The add is the gate: if it fails,
    # nothing that lets SSH in is removed. Every port's add, before any delete.
    gate_err = _r32b_run_gates(server, gates)
    if gate_err:
        steps = []
    for verb, vargs in steps:
        _core.run_privileged(server, verb, vargs, timeout=15)  # deletes of absent rules are harmless
    labels = {"allow": i18n.Sentence("open (allow)"), "limit": i18n.Sentence("rate-limited"),
              "off": i18n.Sentence("disabled (tailnet-only)")}
    # ASK THE HOST what it ended up with. This used to return True unconditionally, so on a host
    # with no ufw at all every verb failed and the operator still got "✓ Public SSH is now disabled
    # (tailnet-only)", an audit row saying the hardening succeeded, and port 22 open to the
    # internet. The exit codes cannot answer it either: ufw exits 0 deleting a rule that is not
    # there ("Could not delete non-existent rule"), so a delete's rc never says a rule went.
    state = remote_public_ssh_status(server)
    refused = _r32b_after_refusal(state)
    if refused is not None:
        return False, refused
    if state.get("mode") != mode:
        return False, i18n.Sentences(
            i18n.Sentence("Could not set public SSH to {mode} — the firewall still reports it as {now}.",
                          mode=labels[mode], now=labels.get(state.get("mode"), state.get("mode"))),
            i18n.Sentence("The new SSH rule was refused ({why}), so no other SSH rule was removed.",
                          why=gate_err) if gate_err else "",
            # Which rule is in the way: one the panel does not remove (a port list, a destination,
            # an every-port allow), as remote_ufw_limit_port names it in the same situation.
            i18n.Sentence("Connections to port {port} meet `{rule}` first — remove or narrow that rule.",
                          port=state.get("rule_port") or "?", rule=state["rule"])
            if state.get("rule") and not gate_err else "")
    return True, i18n.Sentence("Public SSH is now {mode} (port {ports})", mode=labels[mode],
                               ports=", ".join(str(p) for p in ports))     # the ports acted on


def ssh_test_connection(host, port=22, username="root", auth_method="key", credential="",
                        host_key="", captured=None):
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
    is the first contact the TOFU pin is established from.

    `captured`, when given, is a list the key seen on that first contact is appended to — on
    SUCCESS only, never after a failed login — so the caller can store it with the row it creates.
    Enrolment used to throw it away and commit the row unpinned, leaving the pin to whichever
    connection came next, which for a host added in the setup wizard is a background worker.

    A pin that exists but cannot be DECRYPTED is refused before anything is sent. `host_key` is
    then an UnreadableSecret, which is "" — and "" is first contact, so the Test button offered the
    stored password to whoever answered and reported success. Callers must pass the row's value
    itself, not `host_key or ""`, which drops the type.

    The client is closed on every way out. It used to be closed on success alone, so each refused
    test login and each changed host key left paramiko's Transport thread and socket open, as
    get_connection's refusals did (see _core._open_client)."""
    # Tailscale SSH must use the system ssh client (tailscaled handles auth).
    if auth_method == "tailscale":
        return _ssh_test_tailscale(host, port, username)

    from panel.db.models import UnreadableSecret
    if isinstance(host_key, UnreadableSecret):
        return False, ("The stored SSH host key for this server cannot be decrypted on this host, "
                       "so it cannot be checked. Nothing was sent. Click \"Re-trust host key\" on "
                       "the server page if you are sure this is the right server.")
    client = paramiko.SSHClient()
    # Pinned when the caller has a pin (an existing remote); capture-only on genuine first contact,
    # where there is nothing to compare against. Never AutoAddPolicy either way.
    policy = _core._PinPolicy(expected=host_key or "", reject_on_change=bool(host_key))
    client.set_missing_host_key_policy(policy)
    try:
        refused = _ssh_test_login(client, host, port, username, auth_method, credential)
    except Exception as e:
        return False, _ssh_test_failure(e, host, port)
    finally:
        _core._close_quietly(client)
    if refused:
        return False, refused
    if captured is not None and policy.captured:
        captured.append(policy.captured)
    return True, "Connection successful"


def _ssh_test_tailscale(host, port, username):
    """Run ssh_test_connection over Tailscale SSH, with the system ssh client, unprivileged."""
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
        return False, i18n.Sentence("Timed out reaching {host} over Tailscale. Is the node online?", host=host)
    return False, i18n.Sentence("Tailscale SSH failed: {why}", why=(err or out or "unknown")[:150])


def _ssh_test_login(client, host, port, username, auth_method, credential):
    """Log `client` in for ssh_test_connection. None when it connected, else why it was not tried.

    Raises what paramiko raises; the caller turns that into a message and closes the client.
    """
    if auth_method == "password":
        if not credential:
            # A password remote with no usable credential must FAIL, not fall through to the
            # key branch below and authenticate with the panel user's own ~/.ssh/id_rsa — a
            # different credential, against a host the operator never authorised it for.
            # decrypt_secret() returns "" both for "nothing stored" and for "stored but could
            # not be decrypted" (a restored backup with a mismatched cred_key, a corrupt row),
            # so this is also the only place that failure becomes visible.
            return ("No usable SSH password is stored for this host. If the panel was "
                    "restored from a backup, its credential key may not match.")
        client.connect(
            host, port=port, username=username,
            password=credential, timeout=10,
            allow_agent=False, look_for_keys=False,
        )
    else:
        # The same keys get_connection offers (_core.key_login_kwargs): a named key only, never
        # the agent — so the Test button cannot pass on a key the real connection would not use.
        client.connect(
            host, port=port, username=username, timeout=10,
            **_core.key_login_kwargs(credential),
        )
    return None


def _ssh_test_failure(exc, host, port):
    """The message ssh_test_connection shows for a connect that raised `exc`."""
    if isinstance(exc, paramiko.AuthenticationException):
        return "SSH authentication failed. Check your credentials."
    if isinstance(exc, socket.timeout):
        return f"Connection to {host}:{port} timed out. Is the host reachable?"
    if isinstance(exc, socket.gaierror):
        return f"Cannot resolve hostname: {host}"
    # Don't surface the raw exception text to the browser — it can carry internal detail
    # (key paths, host internals). Log the full trace server-side (no user-supplied host/port
    # in the message — exc_info already carries the detail), show a generic message.
    _core._log.warning("ssh_test_connection failed", exc_info=exc)
    return "Connection failed. Check the host, port, credentials, and that SSH is reachable."


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
        # sudo=False: everything read here is world-readable, and the default (the row's sudo_enabled)
        # made this poll a `sudo bash -c` on a remote, failing outright where sudo wants a password.
        out, _, _ = _core.run_command(server, sh, timeout=10, sudo=False)
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
