"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
from panel.ops.ssh_manager import (_core, hosts)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ─── Remote Firewall Management (UFW) ─────────────────────────


def _parse_ufw_rule(detail):
    """Parse one `ufw status numbered` rule line into structured fields, so the UI can
    show clean columns instead of the raw string. Handles the optional `on <iface>`
    clause, the `# comment` suffix, and the `(v6)` family markers."""
    v6 = "(v6)" in detail
    s = detail.replace("(v6)", " ")
    comment = ""
    if "#" in s:
        s, comment = s.split("#", 1)
        comment = comment.strip()
    iface = ""
    m = re.search(r"\bon\s+(\S+)", s)
    if m:
        iface = m.group(1)
        s = s[:m.start()] + s[m.end():]
    toks = s.split()
    action = direction = ""
    ai = None
    for a in ("ALLOW", "DENY", "REJECT", "LIMIT"):
        if a in toks:
            action = a
            ai = toks.index(a)
            break
    if ai is not None:
        to = " ".join(toks[:ai])
        rest = toks[ai + 1:]
        if rest and rest[0] in ("IN", "OUT", "FWD"):
            direction = rest[0]
            rest = rest[1:]
        frm = " ".join(rest)
    else:
        to = " ".join(toks)
        frm = ""
    return {
        "v6": v6, "to": to.strip(), "action": action, "direction": direction,
        "from": frm.strip(), "iface": iface, "comment": comment,
    }


# ufw ships these as fixed app-profile names (`ufw app list`); they are what `ufw allow OpenSSH`
# puts in the To column. Lowercased for comparison.
_SSH_APP_PROFILES = frozenset({"openssh", "ssh"})


def _group_ufw_rules(rules):
    """Collapse the raw numbered rules into user-friendly groups, merging the separate
    IPv4 and IPv6 entries UFW keeps for the same rule into a single row (with the list
    of underlying rule numbers so a group can be deleted as a unit)."""
    groups = []
    index = {}
    for r in rules:
        p = _parse_ufw_rule(r["detail"])
        key = (p["to"], p["action"], p["direction"], p["from"], p["iface"], p["comment"])
        g = index.get(key)
        if not g:
            # Friendly derived fields.
            iface = p["iface"]
            to = p["to"]
            is_iface = bool(iface)
            if is_iface and to.lower() in ("anywhere", ""):
                port_label = "All ports"
            else:
                port_label = to or "—"
            # Split the protocol out of the port so the UI can show it in its own
            # column (e.g. "5000/tcp" -> port "5000", protocol "TCP"). A bare
            # numeric port with no suffix means UFW allowed both TCP and UDP.
            m_proto = re.match(r"^(.*)/(tcp|udp)$", port_label, re.IGNORECASE)
            if m_proto:
                port_num = m_proto.group(1)
                proto_label = m_proto.group(2).upper()
            elif re.search(r"\d", port_label):
                port_num = port_label
                proto_label = "BOTH"
            else:
                port_num = port_label
                proto_label = "—"
            if iface:
                scope = iface + (" (Tailscale)" if iface.startswith("tailscale") else "")
            else:
                scope = "Any address" if p["from"].lower() == "anywhere" else (p["from"] or "—")
            # A "deny/reject from <specific IP>" rule is an IP block (its own UI section), as opposed
            # to an open-port / access rule. Interface rules and "deny to a port" (no from-IP) aren't.
            from_ip = "" if p["from"].lower() == "anywhere" else (p["from"] or "")
            is_block = ((p["action"] or "").upper() in ("DENY", "REJECT")
                        and bool(from_ip) and not iface)
            g = {
                "nums": [], "families": [], "port_label": port_label,
                "port_num": port_num, "proto_label": proto_label,
                "comment": p["comment"], "scope": scope, "iface": iface,
                "action": p["action"] or "ALLOW", "direction": p["direction"] or "IN",
                "is_iface": is_iface, "is_block": is_block,
                "block_ip": from_ip if is_block else "",
            }
            index[key] = g
            groups.append(g)
        g["nums"].append(int(r["num"]))
        fam = "IPv6" if p["v6"] else "IPv4"
        if fam not in g["families"]:
            g["families"].append(fam)
    # Stable, readable family label.
    for g in groups:
        fams = g["families"]
        g["family_label"] = " + ".join(sorted(fams)) if len(fams) > 1 else (fams[0] if fams else "")
        g["nums"].sort()
    return groups


def _ssh_ports(server):
    """Ports whose firewall rule keeps SSH reachable. Always includes 22 (the default)
    and the port the panel actually connects on — which covers a CUSTOM SSH port,
    since that's exactly what's stored on the remote."""
    ports = {22}
    try:
        if getattr(server, "port", None):
            ports.add(int(server.port))
    except (TypeError, ValueError):
        _core._log.debug("a non-numeric stored port just means there's no extra SSH port to track", exc_info=True)
    return ports


def _panel_web_port(server):
    """If `server` is the panel's OWN host and the panel UI isn't reachable over Tailscale
    yet, the public web port is the only way in — return it so its rule can be protected.
    Returns None for a remote, or once Tailscale Serve is actually serving the panel.

    Note: a `tailscale0` UFW rule (Tailscale SSH being reachable) is NOT enough to unprotect
    it — that's only a recovery path, not panel-UI access. The panel UI is only reachable
    over the tailnet once Serve is configured (tailscale_setup_done), so gate on that."""
    if not _core.is_local_server(server):
        return None
    try:
        from panel.core.config import load_config
        cfg = load_config()
    except Exception:
        return None
    if cfg.get("tailscale_setup_done"):
        return None  # served via Tailscale; the public port isn't the only way in
    try:
        return int(cfg.get("port", 5000))
    except (TypeError, ValueError):
        return 5000


def _panel_served_over_tailscale(server):
    """True when THIS host is the panel AND its web UI is published over Tailscale Serve
    (tailscale_setup_done). In that case the *inbound* tailscale0 UFW rule is exactly what
    keeps the panel reachable over the tailnet — with UFW default-deny, deleting it drops
    inbound tailnet traffic to Serve and locks you out of the panel. It's the mirror image
    of _panel_web_port: once Serve is the way in, the public port is free to close BUT the
    tailscale0 rule becomes load-bearing and must be protected."""
    try:
        if not _core.is_local_server(server):
            return False
        from panel.core.config import load_config
        return bool(load_config().get("tailscale_setup_done"))
    except Exception:
        return False


def _annotate_firewall_protection(server, enabled, groups):
    """Flag rules whose removal could LOCK YOU OUT, so the UI and API can refuse to
    delete the last way in. Access rules: the SSH-port ALLOW and the Tailscale-
    interface ALLOW — a rule is *blocked* only when it's the sole remaining one (no
    SSH and no Tailscale would be left); otherwise it's flagged to warn on. On the
    panel's OWN host, the panel's web port is also protected when Tailscale isn't an
    alternate route (otherwise you'd delete your only way into the panel UI). If UFW
    is disabled it isn't enforcing anything, so nothing is protected."""
    ssh_ports = _ssh_ports(server)
    for g in groups:
        pn = str(g.get("port_num", ""))
        # Only an INCOMING rule is a "way in". An `allow out on tailscale0` rule (or any
        # OUT rule) must not count. A rate-limited SSH rule (`ufw limit`, action LIMIT) is
        # just as much a way in as an ALLOW — miss it and the panel would let you delete
        # your only SSH access.
        inbound = g.get("direction", "IN") != "OUT"
        _iface = str(g.get("iface", "") or "")
        _ts_iface = _iface.startswith("tailscale")
        # An SSH rule the panel can recognise is one of three shapes, and it used to see only the
        # first:
        #   22/tcp                     — a bare port number
        #   OpenSSH                    — ufw's APP PROFILE, which is the form Ubuntu's own docs and
        #                                `ufw app list` steer people to. It prints the profile name
        #                                in the To column, so pn.isdecimal() was False.
        #   22 on eth0                 — interface-scoped, which `not is_iface` threw away
        # Both missed shapes came back is_ssh=False AND is_access=False, so protected and warn were
        # both False and remote_ufw_delete_rule — which gates only on protected — deleted the
        # host's only way in without a word. Reproduced against this module's own parser.
        # A tailscale-scoped rule stays out of is_ssh so the two categories remain disjoint;
        # is_tailscale already covers it and the messages below differ.
        _named_ssh = pn.strip().lower() in _SSH_APP_PROFILES
        g["is_ssh"] = (g.get("action") in ("ALLOW", "LIMIT") and inbound and not _ts_iface
                       and ((pn.isdecimal() and int(pn) in ssh_ports) or _named_ssh))
        # LIMIT here too, for the reason spelled out above: a rate-limited rule is a way in.
        g["is_tailscale"] = (bool(g.get("is_iface")) and g.get("action") in ("ALLOW", "LIMIT")
                             and inbound and _ts_iface)
        g["is_access"] = g["is_ssh"] or g["is_tailscale"]

    panel_port = _panel_web_port(server)
    served_over_ts = _panel_served_over_tailscale(server)
    ssh_count = sum(1 for g in groups if g.get("is_ssh"))
    has_ts_iface = any(g.get("is_tailscale") for g in groups)

    # A Tailscale rule only counts as a real fallback when Tailscale is ACTUALLY running —
    # a lingering `allow tailscale0` UFW rule with Tailscale down/uninstalled is no route at
    # all. Query the live state once (only when it could change a decision).
    ts_running = ts_ssh_enabled = False
    if enabled and any(g.get("is_access") for g in groups):
        ts_running, ts_ssh_enabled = hosts._tailscale_conn_state(server)
    ts_ssh_ok = ts_running and ts_ssh_enabled    # Tailscale SSH → a way in regardless of UFW
    ts_iface_ok = ts_running and has_ts_iface     # regular SSH over the tailnet (needs the iface rule)

    for g in groups:
        g["protected"] = False
        g["warn"] = False
        g["protect_reason"] = ""
        # ALLOW *or LIMIT*, and inbound — the same two corrections is_ssh already carries.
        # `ufw limit 5000/tcp` on the panel's own web port is an ordinary thing to do and left the
        # only route to the panel UI deletable; an `ALLOW OUT` rule on that port was conversely
        # treated AS the panel rule and made undeletable.
        g["is_panel"] = (panel_port is not None and not g.get("is_iface")
                         and g.get("action") in ("ALLOW", "LIMIT")
                         and g.get("direction", "IN") != "OUT"
                         and str(g.get("port_num", "")).isdecimal()
                         and int(g["port_num"]) == panel_port)
        if not enabled:
            continue
        if g["is_panel"]:
            # No Tailscale route, so this public port is the only way into the panel.
            g["protected"] = True
            g["protect_reason"] = (
                "Port %d is where this panel's own web interface listens, and it isn't reachable "
                "over Tailscale — removing it would lock you out of the panel. Set up Tailscale "
                "first if you want to close it." % panel_port)
            continue
        if not g["is_access"]:
            continue
        if g["is_ssh"]:
            # Deleting this SSH rule is safe only if another way in remains: another SSH rule,
            # Tailscale SSH, or regular SSH over a running tailnet (Tailscale isn't affected).
            other_way = (ssh_count > 1) or ts_ssh_ok or ts_iface_ok
            reason_last = (
                "Port %s is the SSH port used to reach this host, and there's no working Tailscale "
                "route to fall back on — removing it would lock you out. Enable Tailscale SSH, or "
                "connect Tailscale and allow the tailscale0 interface, first." % g["port_num"])
        else:  # is_tailscale — deleting it drops regular SSH over the tailnet; Tailscale SSH is unaffected
            if served_over_ts:
                # This is the panel host and its UI is published over Tailscale Serve, so this
                # inbound tailscale0 rule is what keeps the PANEL reachable over the tailnet —
                # not just SSH. With UFW default-deny, removing it drops inbound tailnet traffic
                # to Serve and locks you out of the panel, and an available SSH path doesn't save
                # the UI. Protect it outright (blocks the UI's × and any direct delete API call).
                g["protected"] = True
                g["protect_reason"] = (
                    "This Tailscale interface rule keeps the panel reachable over your tailnet "
                    "(Tailscale Serve). With the firewall's default-deny, removing it would drop "
                    "inbound tailnet traffic and lock you out of the panel — so it can't be "
                    "deleted here.")
                continue
            other_way = (ssh_count > 0) or ts_ssh_ok
            reason_last = (
                "This is the Tailscale interface rule and currently the only way in — removing it "
                "would lock you out. Open your SSH port (or enable Tailscale SSH) first.")
        if not other_way:
            g["protected"] = True
            g["protect_reason"] = reason_last
        else:
            g["warn"] = True
            g["protect_reason"] = (
                "This keeps you connected (SSH or Tailscale). Another way in exists so it can be "
                "removed, but make sure you won't lock yourself out.")
    return groups


def _ufw_is_active(status_out):
    """True when `ufw status` reports an active firewall.

    Was `ufw status | grep -q active && echo ACTIVE || echo INACTIVE`, read back with
    `"INACTIVE" not in out` — which needed a comment explaining that ACTIVE is a substring of
    INACTIVE. Reading the Status: line directly needs no such warning."""
    for line in (status_out or "").splitlines():
        if line.strip().lower().startswith("status:"):
            return line.split(":", 1)[1].strip().lower() == "active"
    return False


def remote_ufw_status(server):
    """Get UFW status and rules from the remote server."""
    # sudo=None keeps this host's own setting, as it always did — this is the one ufw read that
    # never forced escalation. `|| echo NOTINSTALLED` is gone with the shell; a missing tool is
    # rc 127 from both transports, which is what the check below now leads with.
    out, err, rc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15, sudo=None)
    if rc == 127 or "NOTINSTALLED" in out or "not found" in (out + err) or "not installed" in (out + err):
        return {"installed": False, "enabled": False, "rules": [], "groups": []}
    # `ufw status` always prints a "Status:" line when it actually runs. If it's missing (or the
    # command failed), the host is unreachable / the command errored — don't claim UFW is installed
    # (that would show a misleading empty-rules "installed" firewall for a down remote).
    if rc != 0 or "Status:" not in out:
        return {"installed": False, "enabled": False, "rules": [], "groups": [], "unreachable": True}

    enabled = "Status: active" in out
    rules = []
    # `ufw status numbered` prints each rule as "[ N] <to>  <action>  <from>".
    # Collapse runs of spaces so the detail reads cleanly.
    for line in out.split("\n"):
        m = re.match(r"^\s*\[\s*(\d+)\]\s*(.*)$", line)
        if m:
            detail = re.sub(r"\s{2,}", "  ", m.group(2).strip())
            rules.append({"num": m.group(1), "detail": detail})

    groups = _annotate_firewall_protection(server, enabled, _group_ufw_rules(rules))
    return {"installed": True, "enabled": enabled, "rules": rules, "groups": groups}


# Single shell script that prints static host specs as TAB-separated KEY<TAB>VALUE
# lines. POSIX-sh compatible (no sudo needed — everything read here is world-readable),
# with fallbacks so it works on x86 servers and ARM SBCs (Raspberry Pi) alike.
_SPECS_CMD = (
    r'''OS=$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME"); '''
    r'''CPU=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^Model[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''MAXMHZ=$(lscpu 2>/dev/null | sed -n 's/^CPU max MHz:[[:space:]]*//p' | head -1); '''
    r'''MEM=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo); '''
    r'''DISK=$(df -hP / 2>/dev/null | awk 'NR==2{print $2}'); '''
    r'''VIRT=$(systemd-detect-virt 2>/dev/null || true); '''
    r'''printf 'OS\t%s\nKERNEL\t%s\nARCH\t%s\nHOST\t%s\nCPU\t%s\nCORES\t%s\nMAXMHZ\t%s\nMEM\t%s\nDISK\t%s\nVIRT\t%s\n' '''
    r'''"$OS" "$(uname -r)" "$(uname -m)" "$(hostname)" "$CPU" "$(nproc)" "$MAXMHZ" "$MEM" "$DISK" "$VIRT"'''
)


# Registered (see _core.register_remote_cache): this one has NO expiry — specs cannot change while
# the machine is up — so without forgetting a deleted host's id, the next host to take that id
# reports the deleted machine's CPU, RAM, disk and OS for the life of the process.
_specs_cache = _core.register_remote_cache({})   # remote id -> result


def host_specs(server, force=False):
    """Static hardware/OS specs for a host (OS, CPU, cores, RAM, disk, kernel, arch, virt). Probed
    ONCE and cached for the panel's whole lifetime — these don't change while the machine is up, and
    a reboot/resize restarts the panel anyway, so there's no periodic re-check. force=True re-probes
    (e.g. after resizing the box without a reboot)."""
    key = hosts._pro_key(server)
    if not force and key in _specs_cache:
        return _specs_cache[key]
    result = _compute_host_specs(server)
    if not result.get("error"):     # cache only a good read; a transient failure retries next time
        _specs_cache[key] = result
    return result


def _compute_host_specs(server):
    """Probe hardware/OS specs (OS, CPU model, cores, RAM, disk, kernel, arch, virt)."""
    try:
        out, err, rc = _core.run_command(server, _SPECS_CMD, timeout=20, sudo=False)
    except Exception:
        # Never surface raw exception text — it flows to a JSON response (CodeQL
        # py/stack-trace-exposure). Log it server-side; the caller shows a generic message.
        _core._log.warning("host specs probe failed", exc_info=True)
        return {"error": "Could not read system specs"}
    if not out:
        _core._log.debug("host specs: empty output (stderr: %s)", (err or "")[:200])
        return {"error": "Could not read system specs"}
    d = {}
    for line in out.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            d[k.strip()] = v.strip()
    mhz = d.get("MAXMHZ", "")
    ghz = ""
    try:
        if mhz:
            ghz = f"{float(mhz) / 1000:.1f} GHz"
    except ValueError:
        ghz = ""
    mem = d.get("MEM", "")
    virt = d.get("VIRT", "")
    return {
        "os": d.get("OS", "") or "Unknown",
        "kernel": d.get("KERNEL", ""),
        "arch": d.get("ARCH", ""),
        "hostname": d.get("HOST", ""),
        "cpu": d.get("CPU", "") or "Unknown CPU",
        "cores": d.get("CORES", ""),
        "cpu_speed": ghz,
        "ram": (mem + " GB") if mem else "",
        "disk": d.get("DISK", ""),
        "virt": "" if virt in ("none", "") else virt,
    }
