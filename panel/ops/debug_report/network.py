"""Debug-report section(s): network, access.

Owner: builder B3. network: Tailscale/Serve/Funnel (R36), proxy trust (R37), this request (R38),
cookies (R39), UFW (R40), fail2ban (R41). access: sign-ins/auth.log (R43), throttle and ban gate
(R44), accounts/2FA counts (R45).

R37 and R39 are builder B1's, in config_section. R38 is printed by `access`, which runs in the
request greenlet: it needs the request, and `network` runs in a worker thread.

Nothing here prints an address (only its class), a host name, an account, a jail's logpath, a rule's
source or comment, or a header value. The privileged reads (ufw, fail2ban-client) run only through
the root-owned helper or as root: never the pre-helper `sudo` form, which has no -n.
"""
import calendar
import os
import re
import subprocess  # nosec B404 - one `sudo -n` argv built from privileged.py's verb table
import sys
import threading
import time

from panel.core import runtime_stats
from panel.ops import system_ops as so
from panel.ops.debug_report import _src_db, _src_net, _src_tailscale
from panel.ops.debug_report._base import Result, ago, unread_line

AREA = "Network & access"
_MOUNT_RE = re.compile(r"/[A-Za-z0-9_-]{0,32}\Z")
_STATES = frozenset(("Running", "NeedsLogin", "Stopped", "NoState", "Starting", "NeedsMachineAuth",
                     "InUseOtherUser"))
PANEL_JAIL = "linuxgsm-panel"
# Jail names fail2ban itself ships (jail.conf); any other name is the operator's own text.
STANDARD_JAILS = frozenset(("sshd", "recidive", "sshd-ddos", "dropbear", "selinux-ssh", "pam-generic",
                            "nginx-http-auth", "nginx-botsearch", "nginx-limit-req", "apache-auth",
                            "apache-badbots", "postfix", "dovecot", "vsftpd", "proftpd", "pure-ftpd"))
F2B_TIMEOUT = 5
UFW_TIMEOUT = 10
NOT_READ = "not read (no helper, and passwordless sudo not confirmed; it would need sudo)"


# ── running the slow reads side by side, each under the report's deadline ───────────────────────
def _job(fn, name, slots, done):
    try:
        slots[name] = ("ok", fn())
    except Exception as exc:  # noqa: BLE001 - reported by class
        slots[name] = ("error", type(exc).__name__)
    finally:
        done.set()


def bounded(ctx, jobs, reserve=0.5):
    """{name: ("ok", value) | ("error", class) | ("timeout", None)}, each job in its own thread.

    A job still running at the deadline is reported as timed out and left to finish on its own:
    every read in a job carries its own timeout, so it does end.
    """
    slots, waits = {}, []
    for name, fn in jobs:
        done = threading.Event()
        threading.Thread(target=_job, args=(fn, name, slots, done), daemon=True,
                         name="debug-report-net-" + name).start()
        waits.append((name, done))
    for _name, done in waits:
        done.wait(max(0.0, ctx.remaining() - reserve))
    return {name: slots.get(name) or ("timeout", None) for name, _done in waits}


def _may_escalate():
    """Whether _run_verb may make the read: through the helper (sudo -n) or as root.

    Its third branch, the pre-helper shell form, is a `sudo` with no -n, so it is never reached
    from here.
    """
    return bool(so._helper_present()) or (hasattr(os, "geteuid") and os.geteuid() == 0)


def _sudo_cached_ok():
    """Whether system_ops' CACHED probe already found passwordless sudo.

    Never probes: a failed probe counts toward pam_faillock.
    """
    probe = getattr(so, "_SUDO_PROBE", None) or {}
    # Within the probe's own TTL only, as _check_sudo reads it: an "ok" from days ago says nothing
    # about a grant revoked since, and a refused `sudo -n` may count toward pam_faillock.
    age = time.time() - (probe.get("at") or 0)
    return probe.get("ok") is True and 0 <= age < getattr(so, "_SUDO_PROBE_TTL", 300)


def may_read_privileged():
    """A privileged read can be made without a password prompt and without a new sudo probe."""
    return _may_escalate() or _sudo_cached_ok()


def sudo_n_verb(verb, args, timeout):
    """(out, err, rc) of `sudo -n <the verb's tool argv>`: an argv, never a shell, never a prompt.

    For the per-user install on an account with passwordless sudo and no helper, where _run_verb's
    own fallback would be a plain `sudo` in a shell. Output is capped as _run_verb caps it.
    """
    from panel.security import privileged as _priv
    try:
        argv = ["sudo", "-n"] + _priv.tool_argv(verb, args)
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        p = subprocess.Popen(argv, shell=False,  # nosec B603 - sudo -n plus privileged.py's argv
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
        out, err, rc = so._collect_verb_output(p, argv, timeout)
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except OSError:
        return "", "Command not found", -1
    except _priv.VerbError:
        return "", "invalid argument", -1
    if rc != 0 and "command not found" in (err or "").lower():
        rc = 127
    return (out or "").strip(), (err or "").strip(), rc


def priv_read(verb, args, timeout):
    """(out, err, rc) of a read-only privileged verb, or None when it may not be run at all."""
    if _may_escalate():
        return so._run_verb(verb, args, timeout=timeout, merge_stderr=False)
    if _sudo_cached_ok():
        return sudo_n_verb(verb, args, timeout)
    return None


def running_port(ctx, cfg):
    """The port this process serves on: the boot record's BOOT_PORT, else config.json's.

    A port changed in config.json takes effect at the next restart; until then Serve and the
    firewall must reach the port the panel is actually bound to.
    """
    boot = (getattr(ctx.app, "config", None) or {}).get("BOOT_PORT") if ctx is not None else None
    if isinstance(boot, int) and not isinstance(boot, bool) and 0 < boot < 65536:
        return boot
    return int(cfg.get("port", 5000) or 5000)


def _load_cfg():
    from panel.core import config as _cfg
    cfg = _cfg.load_config()
    return cfg, not _cfg.is_unreadable(cfg)


def _yn(flag):
    return "yes" if flag else "no"


# ── R36: Tailscale, Serve and Funnel ─────────────────────────────────────────────────────────────
def _key_text(expiry, now=None):
    if not expiry:
        return "node key expiry not recorded"
    if expiry.startswith("0001-"):
        return "node key expiry disabled"
    try:
        exp = calendar.timegm(time.strptime(expiry[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return "node key expiry unreadable"
    left = exp - (time.time() if now is None else now)
    return "node key EXPIRED" if left <= 0 else "node key expires in %d days" % (left // 86400)


def _operator_text(op):
    if op is None:
        return "not recorded"
    if os.geteuid() == 0:
        return "n/a (the panel runs as root)"
    try:
        import pwd
        me = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return "unknown"
    return "yes" if op == me else "NO"


def _ts_head(v):
    ver = re.match(r"\d+\.\d+(?:\.\d+)?", v.get("version") or "")
    state = v.get("backend_state") if v.get("backend_state") in _STATES else "other"
    health = v.get("health")
    return ("v%s · %s · MagicDNS %s · %s · panel account is the operator: %s · health warnings %s"
            % (ver.group(0) if ver else "?", state, "on" if v.get("magic_dns") else "off",
               _key_text(v.get("key_expiry")), _operator_text(v.get("operator_user")),
               "not recorded" if health is None else len(health)))


def _mount(m):
    return m if _MOUNT_RE.match(m or "") else "custom"


def _plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _route_text(r, port, want):
    """'/lgsm → http to loopback:5000 ✓': the mount if plain, the scheme, never the URL."""
    scheme = _scheme(r)
    mark = ""
    if want:
        mark = " ✓" if scheme == want else " ✗ expected %s" % want
    return "%s → %s to loopback:%d%s" % (_mount(r["mount"]), _tok(scheme), port, mark)


def _serve_text(v, port, want):
    """'readable · 1 route to the panel at /lgsm → http to loopback:5000 ✓ · 1 other app route'."""
    from panel.ops import tailscale_integration as ts
    if v.get("serve_unreadable"):
        return "UNREADABLE (the panel account may not be the operator), not the same as no routes", []
    services = v.get("serve_services") or []
    routes = ts.panel_serve_routes({"services": services}, port)
    total = sum(len(s.get("routes") or []) for s in services)
    shown = "; ".join(_route_text(r, port, want) for r in routes)
    return ("readable · %s to the panel%s · %s" % (
        _plural(len(routes), "route"), (" at " + shown) if shown else "",
        _plural(total - len(routes), "other app route"))), routes


def _tok(value):
    return value if re.match(r"[a-z+]{1,20}\Z", value or "") else "other"


def _expected_scheme(conf, cfg):
    if "BOOT_TLS" in conf:
        return "https+insecure" if conf.get("BOOT_TLS") else "http"
    mod = sys.modules.get("app")
    try:
        return mod._ts_backend_scheme(cfg) if mod is not None else None
    except Exception:  # noqa: BLE001
        return None


def _ts_findings(res, v, cfg, routes):
    if v.get("backend_state") == "NeedsLogin":
        res.find("fail", AREA, "Tailscale needs login (node key expired or logged out)")
    elif v.get("backend_state") != "Running" and cfg.get("tailscale_setup_done"):
        res.find("fail", AREA, "Tailscale is not running, and the panel is set up behind it")
    if v.get("serve_unreadable"):
        res.find("warn", AREA, "Tailscale Serve status is unreadable (not the same as no routes)")
    elif cfg.get("tailscale_setup_done") and not routes:
        res.find("warn", AREA, "no Tailscale Serve route reaches the panel")
    if v.get("funnel_enabled") and not cfg.get("tailscale_use_funnel"):
        res.find("fail", AREA, "Funnel is ON in Serve but off in the panel's config (switched on "
                               "outside the panel)")
    if "EXPIRED" in _key_text(v.get("key_expiry")):
        res.find("fail", AREA, "the Tailscale node key has expired")


def _route_findings(res, cfg, routes, want, readable):
    """Findings for a panel route Serve cannot use.

    The wrong backend scheme (Serve answers 502), or, once set up, a mount other than the
    configured one (every URL the panel builds is under that one).
    """
    if want and any(_scheme(r) != want for r in routes):
        res.find("fail", AREA, "a Tailscale Serve route reaches the panel with the wrong scheme "
                               "(Serve answers 502)")
    if readable and routes and cfg.get("tailscale_setup_done"):
        if _norm_mount(cfg.get("tailscale_mount")) not in {_norm_mount(r["mount"]) for r in routes}:
            res.find("warn", AREA, "the Serve route's mount is not the panel's configured "
                                   "tailscale_mount (links and assets break)")


def _norm_mount(mount):
    """'/lgsm/' and '/lgsm' are one mount; empty is '/' (middleware.py reads it the same way)."""
    return str(mount or "/").rstrip("/") or "/"


def _scheme(route):
    target = route.get("target") or ""
    return target.split("://", 1)[0] if "://" in target else "http"


def _onoff(flag):
    return "on" if flag else "off"


def _ts_unread(res, facts, got):
    """Print why there is no Tailscale reading; True when there is none."""
    status, val = got
    if status != "ok":
        res.add("- **Tailscale**: %s" % ("timed out (not shown)" if status == "timeout"
                                         else "could not be read (%s)" % val))
        res.find("unread", AREA, "Tailscale status could not be read")
        return True
    state, v = val
    if state == "ok":
        return False
    facts["ts"] = "not installed" if state == "absent" else "unreadable"
    res.add("- **Tailscale**: %s" % ("not installed" if state == "absent"
                                     else "status could not be read (%s)" % v))
    return True


def _funnel_line(cfg, readable, v, routes):
    mounts = ", ".join(sorted({_mount(r["mount"]) for r in routes})) or "none"
    return "config %s · Serve says %s · **Mount**: Serve %s, config %s" % (
        _onoff(cfg.get("tailscale_use_funnel")) if readable else "unread",
        _onoff(v.get("funnel_enabled")), mounts,
        _mount(cfg.get("tailscale_mount") or "/") if readable else "unread")


def _tailscale_lines(ctx, res, facts, got):
    """R36: state, Serve and Funnel from the one cached reading; names, IPs and URLs never."""
    if _ts_unread(res, facts, got):
        return
    v = got[1][1]
    cfg, readable = _load_cfg()
    cfg = cfg if readable else {}
    port = running_port(ctx, cfg)
    want = _expected_scheme(getattr(ctx.app, "config", None) or {}, cfg) if readable else None
    res.add("- **Tailscale**: " + _ts_head(v))
    text, routes = _serve_text(v, port, want)
    res.add("- **Serve**: " + text)
    res.add("- **Funnel**: " + _funnel_line(cfg, readable, v, routes))
    _ts_findings(res, v, cfg, routes)
    _route_findings(res, cfg, routes, want, readable)
    state = v.get("backend_state")
    facts["ts"] = "%s, Funnel %s" % (state if state in _STATES else "other",
                                     _onoff(v.get("funnel_enabled")))


# ── R40: UFW, read once through the helper ───────────────────────────────────────────────────────
def _ufw_failed(out, err, rc):
    """The state of a ufw-status read that did not answer, or None when it did."""
    from panel.ops.ssh_manager import firewall as fw
    out, err = out or "", (err or "").lower()
    if rc == 127 or (rc == -1 and "not found" in err):
        return {"state": "not-installed"}
    if fw._SUDO_REFUSED_RE.search(out + "\n" + err):
        return {"state": "refused"}
    return _ufw_unanswered(out, err, rc)


def _ufw_unanswered(out, err, rc):
    if rc == -1 and "timed out" in err:
        return {"state": "timeout"}
    if rc != 0 or not out.strip():
        return {"state": "unreadable", "rc": rc}
    return None


def ufw_classify(out, err, rc):
    """The ufw-status read as a state: never 'inactive' for a read that did not answer."""
    failed = _ufw_failed(out, err, rc)
    if failed is not None:
        return failed
    rows = [so._ufw_rule_split(line.strip()) for line in out.splitlines()]
    shadowed = {}
    blocks = so._ufw_deny_sources(out, shadowed)
    m = re.search(r"Default:\s*([a-z]+)\s*\(incoming\)", out)
    return {"state": "ok", "active": bool(so.ufw_status_active(out)),
            "rules": [r for r in rows if r], "default_in": m.group(1) if m else "unknown",
            "blocks": blocks, "shadowed": len(shadowed)}


def ufw_read():
    """One `ufw status verbose` (helper, root, or cached passwordless `sudo -n`), classified."""
    got = priv_read("ufw-status", ["verbose"], UFW_TIMEOUT)
    if got is None:
        return {"state": "not-read"}
    return ufw_classify(*got)


def _src_kind(rule):
    src = (rule.get("from") or "").split("#", 1)[0].strip()
    return "Anywhere" if src.startswith("Anywhere") else "a specific source"


def _port_rules(rules, port):
    pat = re.compile(r"%s(?:/(?:tcp|udp))?(?: \(v6\))?\Z" % re.escape(str(port)))
    return [r for r in rules if r["direction"] == "IN" and r["action"] in ("ALLOW", "LIMIT")
            and pat.match(r["to"])]


def _ways_in(u, port, cfg):
    rules = u["rules"]
    ssh = _port_rules(rules, 22) + [r for r in rules if r["to"].startswith("OpenSSH")
                                    and r["direction"] == "IN" and r["action"] in ("ALLOW", "LIMIT")]
    ssh_text = ("SSH %s from %s" % (ssh[0]["action"], _src_kind(ssh[0]))) if ssh else "SSH: no rule"
    panel = _port_rules(rules, port)
    panel_text = ("allowed from %s" % ", ".join(sorted({_src_kind(r) for r in panel})) if panel
                  else "not allowed" + (" (tailnet-only, Serve up)"
                                        if cfg.get("tailscale_setup_done") else ""))
    return "%s · tailscale0 allow-in: %s · panel port %s: %s" % (
        ssh_text, _yn(so.ufw_allows_iface_in(rules, "tailscale0")), port, panel_text)


def _deny_text(u):
    counts = {}
    for tag in u["blocks"].values():
        label = tag if re.match(r"panel-[a-z-]{1,30}\Z", tag or "") else "operator"
        counts[label] = counts.get(label, 0) + 1
    text = " · ".join("%s %d" % kv for kv in sorted(counts.items())) or "none"
    if u["shadowed"]:
        text += " (+%d operator rule%s below an allow, so it blocks nothing)" % (
            u["shadowed"], "" if u["shadowed"] == 1 else "s")
    return text


_UFW_STATES = {
    "not-read": NOT_READ,
    "not-installed": "not installed",
    "refused": "UNREADABLE, sudo refused (a password is required); see the sudoers.d order",
    "timeout": "UNREADABLE (timed out)",
}


def _ufw_lines(res, facts, got, cfg, port):
    """R40's lines; `port` is the one the panel serves on (running_port)."""
    status, u = got
    if status != "ok":
        res.add("- **UFW**: %s" % ("timed out (not shown)" if status == "timeout"
                                   else "could not be read (%s)" % u))
        res.find("unread", AREA, "UFW could not be read")
        return
    if u["state"] != "ok":
        text = _UFW_STATES.get(u["state"]) or "UNREADABLE (rc %s)" % u.get("rc")
        res.add("- **UFW**: " + text)
        facts["ufw"] = u["state"]
        if u["state"] in ("refused", "timeout", "unreadable"):
            res.find("fail" if u["state"] == "refused" else "unread", AREA,
                     "UFW could not be read" + (": sudo refused" if u["state"] == "refused" else ""))
        return
    facts["ufw"] = "active" if u["active"] else "inactive"
    res.add("- **UFW**: %s · %d rules · default incoming: %s" % (
        facts["ufw"], len(u["rules"]), _tok(u["default_in"])))
    res.add("- **Ways in**: " + _ways_in(u, port, cfg))
    res.add("- **Deny-all-ports rules**: " + _deny_text(u))


# ── R41: fail2ban, the panel jail's file and its runtime state ───────────────────────────────────
def auth_log_path():
    """data/auth.log, where the app module that the routes use writes it."""
    mod = sys.modules.get("app")
    path = getattr(mod, "AUTH_LOG_PATH", None) if mod is not None else None
    if path:
        return str(path)
    from panel.core import config as _cfg
    return os.path.join(str(_cfg.DATA_DIR), "auth.log")


def panel_jail_health(auth_log, web_port, ignore_ips=None):
    """{check: bool} of the panel jail FILE: system_ops.panel_jail_health, the self-heal's own test."""
    return so.panel_jail_health(auth_log, web_port, ignore_ips)


def _jail_file_text(cfg):
    path = so._F2B_PANEL_JAIL
    try:
        with open(path, encoding="utf-8"):
            pass
    except FileNotFoundError:
        return "jail file absent", None
    except OSError as exc:
        return "jail file unreadable (%s)" % type(exc).__name__, None
    h = panel_jail_health(auth_log_path(), cfg.get("port", 5000),
                          list(cfg.get("security_whitelist", []) or []))
    labels = (("logpath", "watching the panel's auth.log"), ("port", "port = config"),
              ("backend", "backend auto"), ("banaction", "banaction %s" % (
                  "all-ports (proxied)" if h["allports"] else "web port")),
              ("ignoreip", "ignoreip tailnet + whitelist"), ("filter", "filter current"))
    return " · ".join("%s %s" % (text, "✓" if h[key] else "✗") for key, text in labels), h


def f2b_runtime():
    """{key: (rc, out) | "timeout" | "not-read"} from at most three helper calls, 5 s each.

    The status, the panel jail and sshd; after the first timeout the rest are not made. None when
    neither the helper nor root is available to make them.
    """
    if not may_read_privileged():
        return None
    out = {}
    calls = (("status", "f2b-status", []), ("panel", "f2b-status-jail", [PANEL_JAIL]),
             ("sshd", "f2b-status-jail", ["sshd"]))
    stopped = False
    for key, verb, args in calls:
        out[key] = "not-read" if stopped else _f2b_call(verb, args)
        stopped = stopped or out[key] == "timeout"
    return out


def _f2b_call(verb, args):
    """(rc, out) of one fail2ban-client read, or "timeout"; a missing tool is rc 127."""
    o, e, rc = priv_read(verb, args, F2B_TIMEOUT) or ("", "not read", -2)
    err = (e or "").lower()
    if rc == -1 and "timed out" in err:
        return "timeout"
    return (127 if rc == -1 and "not found" in err else rc, o or "")


def jail_list(text):
    """The jail names of a `fail2ban-client status`, or None when it has no 'Jail list:' line."""
    m = re.search(r"Jail list:\s*(.*)", text or "")
    if not m:
        return None
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def jail_counts(text):
    """{banned_now, total_banned, failed, file_list, journal} of one jail's status text."""
    def num(label):
        m = re.search(label + r":\s*(\d+)", text or "")
        return int(m.group(1)) if m else None
    m = re.search(r"File list:\s*(.*)", text or "")
    return {"banned_now": num("Currently banned"), "total_banned": num("Total banned"),
            "failed": num("Total failed"), "file_list": m.group(1).split() if m else None,
            "journal": "Journal matches:" in (text or "")}


def _watch_text(c, watch_path):
    """Whether a jail's runtime reads the panel's auth.log: never the path itself."""
    if c["journal"]:
        return "ACTIVE BUT NOT WATCHING auth.log (journal backend), so it can never ban"
    return "watching the panel's auth.log %s" % ("✓" if _watching(c, watch_path) else "✗ NO")


def _watching(c, watch_path):
    """Whether a jail's runtime File list includes `watch_path` (both resolved)."""
    want = os.path.realpath(watch_path)
    return any(os.path.realpath(p) == want for p in c["file_list"] or [])


def _jail_status_text(entry, watch_path=None):
    """(text, counts or None) for one jail's runtime read."""
    if entry in ("timeout", "not-read"):
        return "not read (fail2ban did not answer)", None
    rc, out = entry
    if rc != 0 or "Currently banned" not in out:
        return "UNREADABLE (rc %s)" % rc, None
    c = jail_counts(out)
    parts = [_watch_text(c, watch_path)] if watch_path is not None else []
    parts.append("banned now %s · total banned %s · failed %s" % tuple(
        "?" if c[k] is None else c[k] for k in ("banned_now", "total_banned", "failed")))
    return " · ".join(parts), c


def _f2b_names(names):
    shown = [n for n in names if n == PANEL_JAIL or n in STANDARD_JAILS]
    others = len(names) - len(shown)
    return ", ".join(shown) + (" + " + _plural(others, "other jail") if others else "")


def _f2b_status_names(res, facts, status):
    """The jail list of the status read, or None after printing why there is none."""
    if status in ("timeout", "not-read"):
        res.add("- **fail2ban**: not read (fail2ban did not answer)")
        res.find("unread", AREA, "fail2ban did not answer")
        facts["f2b"] = "unread"
        return None
    if status[0] == 127:
        res.add("- **fail2ban**: not installed")
        facts["f2b"] = "not installed"
        return None
    names = jail_list(status[1]) if status[0] == 0 else None
    if names is None:
        res.add("- **fail2ban**: status UNREADABLE (rc %s), not the same as no jails" % status[0])
        res.find("unread", AREA, "fail2ban's status could not be read")
        facts["f2b"] = "unreadable"
    return names


def _f2b_runtime_lines(res, facts, rt):
    names = _f2b_status_names(res, facts, rt.get("status"))
    if names is None:
        return
    facts["f2b"] = "running"
    res.add("- **fail2ban**: running · jails: %s" % (_f2b_names(names) or "none"))
    if PANEL_JAIL not in names:
        res.find("warn", AREA, "fail2ban runs without the panel-login jail")
    else:
        text, c = _jail_status_text(rt.get("panel"), auth_log_path())
        res.add("- **%s jail (runtime)**: %s" % (PANEL_JAIL, text))
        _panel_jail_findings(res, c)
    if "sshd" in names:
        res.add("- **sshd jail**: %s" % _jail_status_text(rt.get("sshd"))[0])


def _panel_jail_findings(res, c):
    """The panel jail's runtime read as findings: unread, watching no file, or another file."""
    if c is None:
        res.find("unread", AREA, "the panel's fail2ban jail could not be read")
    elif c["journal"]:
        res.find("fail", AREA, "the panel's fail2ban jail is active but watches no file, "
                               "so it can never ban")
    elif not _watching(c, auth_log_path()):
        res.find("fail", AREA, "the panel's fail2ban jail watches another file, not this "
                               "install's auth.log, so it can never ban")


def _f2b_lines(res, facts, got, cfg, readable):
    status, rt = got
    if readable:
        text, health = _jail_file_text(cfg)
        res.add("- **%s jail file**: %s" % (PANEL_JAIL, text))
        if health is not None and not health["logpath"]:
            res.find("fail", AREA, "the panel's fail2ban jail does not watch this install's auth.log")
    else:
        res.add("- **%s jail file**: not compared (config.json could not be read)" % PANEL_JAIL)
    if status != "ok":
        res.add("- **fail2ban**: %s" % ("timed out (not shown)" if status == "timeout"
                                        else "could not be read (%s)" % rt))
        res.find("unread", AREA, "fail2ban could not be read")
        return
    if rt is None:
        res.add("- **fail2ban**: " + NOT_READ)
        facts["f2b"] = "not read"
        return
    _f2b_runtime_lines(res, facts, rt)


# ── the network section (a worker) ───────────────────────────────────────────────────────────────
def section_network(ctx):
    """R36, R40, R41: the three slow reads run side by side, each under the report's deadline."""
    res, facts = Result(), {}
    got = bounded(ctx, (("tailscale", lambda: _src_tailscale.shared_read(ctx)),
                        ("ufw", ufw_read), ("f2b", f2b_runtime)))
    cfg, readable = _load_cfg()
    parts = (("Tailscale", lambda: _tailscale_lines(ctx, res, facts, got["tailscale"])),
             ("UFW", lambda: _ufw_lines(res, facts, got["ufw"], cfg,
                                        running_port(ctx, cfg if readable else {}))),
             ("fail2ban", lambda: _f2b_lines(res, facts, got["f2b"], cfg, readable)))
    for title, part in parts:
        try:
            part()
        except Exception as exc:  # noqa: BLE001 - one part's failure is printed, the rest still run
            res.add(unread_line(title, exc))
            res.find("unread", AREA, "%s could not be read" % title)
    res.verdict = "Network & security: Tailscale %s · UFW %s · fail2ban %s" % (
        facts.get("ts", "unread"), facts.get("ufw", "unread"), facts.get("f2b", "unread"))
    return res


# ── R38: how this report's own request reached the panel ─────────────────────────────────────────
def _peer_role(uid):
    if uid is None:
        return "unknown owner"
    if uid == 0:
        return "owned by root"
    return "owned by the panel's account" if uid == os.geteuid() else "owned by another account"


def _peer_text(env):
    """(peer address, 'loopback peer, owned by root'): the class and the owner's role only."""
    from panel.security import auth
    peer = (env.get("werkzeug.proxy_fix.orig") or {}).get("REMOTE_ADDR") or env.get("REMOTE_ADDR")
    cls = _src_net.addr_class(peer)
    who = (", " + _peer_role(auth._loopback_peer_uid_memo())) if cls == "loopback" else ""
    return peer, "%s peer%s" % (cls, who)


def _self_tls(conf):
    """Whether the panel terminates TLS itself, asked as app.py's after_request asks it.

    That is the current config through _effective_https; the boot record when that module is not
    loaded.
    """
    mod = sys.modules.get("app")
    if mod is not None and hasattr(mod, "_effective_https"):
        cfg, readable = _load_cfg()
        if readable:
            return bool(mod._effective_https(cfg))
    return bool(conf.get("BOOT_TLS"))


def hsts_expected(forwarded_proto, is_secure, self_tls):
    """app.py's HSTS rule: HTTPS from a proxy or Tailscale, never the panel's own self-signed TLS."""
    return forwarded_proto == "https" or (bool(is_secure) and not self_tls)


def _request_lines(res, conf):
    """R38: fixed booleans and categories only. Never a header's value or an address."""
    from flask import has_request_context, request
    if not has_request_context():
        res.add("- **This request**: not generated from a browser request (CLI or test)")
        return
    from panel.security import auth
    env = request.environ
    peer, peer_text = _peer_text(env)
    mount = request.script_root or "/"
    res.add("- **This request**: from a %s · X-Forwarded-For present: %s · "
            "Tailscale-Funnel-Request: %s · scheme %s · mount %s" % (
                peer_text, _yn(env.get("HTTP_X_FORWARDED_FOR")),
                _yn(env.get("HTTP_TAILSCALE_FUNNEL_REQUEST")), _tok(request.scheme),
                "/" if mount == "/" else _mount(mount)))
    client = _src_net.addr_class(auth.client_ip())
    res.add("- **Client address as the panel keys it**: %s · forwarded headers believed: %s" % (
        client, _yn(auth._request_came_through_proxy(peer))))
    res.add("- **HSTS on this response**: %s" % _yn(hsts_expected(
        env.get("HTTP_X_FORWARDED_PROTO", ""), request.is_secure, _self_tls(conf))))
    if client == "loopback" and env.get("HTTP_X_FORWARDED_FOR"):
        res.find("warn", AREA, "this proxied request was keyed as loopback: every proxied client "
                               "shares one throttle bucket, and fail2ban ignores them")


# ── R43: sign-ins and auth.log ───────────────────────────────────────────────────────────────────
SIGNIN_ACTIONS = ("login", "login_failed", "login_blocked", "api_token_blocked", "fail2ban_ban")
AUTHLOG_MAX = 512 * 1024
# 'panel login failed from X' is written once per failed sign-in, so it is what the audit log's
# login_failed rows can be held against. 'panel login blocked' and 'panel api token blocked' are
# written on EVERY refused request while the audit log keeps one row per block window, so they are
# counted apart and never compared.
_AUTHLOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) panel (login failed|login blocked|"
                         r"api token blocked) from (\S+)\s*\Z")
# The queries, whole literals: nothing is formatted into them, every value is a bound parameter.
# The failed-login sources are classified IN SQL (the CASE below), so no address leaves the database.
_SQL_SIGNINS = ("SELECT action, SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), COUNT(*) "
                "FROM audit_log WHERE action IN (?, ?, ?, ?, ?) AND timestamp >= ? GROUP BY action")
_SQL_SOURCES = (
    "SELECT cls, COUNT(DISTINCT ip_address) FROM (SELECT ip_address, "
    "CASE WHEN ip_address IS NULL OR ip_address IN ('', 'unknown') THEN 'unknown' "
    "WHEN ip_address IN ('::1') OR ip_address LIKE '127.%' OR ip_address LIKE '::ffff:127.%' "
    "THEN 'loopback' "
    "WHEN ip_address LIKE 'fd7a:115c:a1e0:%' OR (ip_address LIKE '100.%' AND "
    "CAST(substr(ip_address, 5, instr(substr(ip_address, 5), '.') - 1) AS INTEGER) "
    "BETWEEN 64 AND 127) THEN 'tailnet' "
    "WHEN ip_address LIKE '10.%' OR ip_address LIKE '192.168.%' OR ip_address LIKE 'fe80:%' "
    "OR ip_address LIKE 'fc%' OR ip_address LIKE 'fd%' OR (ip_address LIKE '172.%' AND "
    "CAST(substr(ip_address, 5, instr(substr(ip_address, 5), '.') - 1) AS INTEGER) "
    "BETWEEN 16 AND 31) THEN 'private' ELSE 'public' END AS cls "
    "FROM audit_log WHERE action = 'login_failed' AND timestamp >= ?) GROUP BY cls")
_SQL_USERS = ("SELECT COALESCE(SUM(is_active), 0), COALESCE(SUM(is_active AND is_superadmin), 0), "
              "COALESCE(SUM(NOT is_active), 0), "
              "COALESCE(SUM(is_active AND is_superadmin AND totp_enabled), 0), "
              "COALESCE(SUM(is_active AND NOT is_superadmin AND totp_enabled), 0), "
              "COALESCE(SUM(is_active AND must_change_password), 0), "
              "COALESCE(SUM(is_active AND must_change_password AND api_token IS NOT NULL), 0), "
              "COALESCE(SUM(is_active AND api_token IS NOT NULL), 0) FROM \"user\"")
_SQL_INVITES = ("SELECT COUNT(*), COALESCE(SUM(grants_superadmin), 0) FROM invite WHERE "
                "used_at IS NULL AND revoked_at IS NULL AND expires_at > ?")
_SQL_SESSIONS = "SELECT COUNT(*), COALESCE(SUM(remember), 0) FROM user_session WHERE last_seen >= ?"
_SQL_SETUP = "SELECT COALESCE(MAX(complete), 0) FROM setup_state"


def _utc(seconds_ago):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - seconds_ago))


def signin_queries():
    """The SQL for R43 and R45: counts and GROUP BYs only, never a value the report cannot print."""
    day, week, now = _utc(86400), _utc(7 * 86400), _utc(0)
    return {"signins": (_SQL_SIGNINS, (day,) + SIGNIN_ACTIONS + (week,)),
            "sources": (_SQL_SOURCES, (week,)),
            "users": (_SQL_USERS, ()),
            "invites": (_SQL_INVITES, (now,)),
            "sessions": (_SQL_SESSIONS, (week,)),
            "setup": (_SQL_SETUP, ())}


def _db_counts(ctx):
    return ctx.memo("access_counts", lambda: _src_db.run_ro(signin_queries(), timeout=10))


def _rows(counts, name):
    """The rows of query `name`, or raise LookupError naming the class it failed with."""
    rows = counts.get(name)
    if isinstance(rows, str) or rows is None:
        raise LookupError(str(rows or "error:missing").split(":", 1)[-1][:40])
    return rows


def _signin_lines(res, counts, facts):
    try:
        by = {r[0]: (int(r[1] or 0), int(r[2] or 0)) for r in _rows(counts, "signins")}
        src = {r[0]: int(r[1] or 0) for r in _rows(counts, "sources")}
    except LookupError as exc:
        res.add("- **Sign-ins**: audit log not queryable (%s)" % exc.args[0])
        res.find("unread", AREA, "the audit log could not be counted")
        return
    labels = (("login", "ok"), ("login_failed", "failed"), ("login_blocked", "throttled"),
              ("api_token_blocked", "API token throttled"), ("fail2ban_ban", "fail2ban bans"))
    res.add("- **Sign-ins, 24 h / 7 d**: " + " · ".join(
        "%s %d/%d" % (label, by.get(a, (0, 0))[0], by.get(a, (0, 0))[1]) for a, label in labels))
    res.add("- **Failed-login sources, 7 d**: %d distinct (%s)" % (sum(src.values()), " · ".join(
        "%s %d" % (k, src.get(k, 0)) for k in ("public", "tailnet", "private", "loopback", "unknown"))))
    # Only login_failed: it is the one action with exactly one auth.log line per audit row.
    facts["audit_fail_24h"] = by.get("login_failed", (0, 0))[0]


def _authlog_tail(path):
    """(size, the lines of the file's last AUTHLOG_MAX bytes); raises OSError."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        fh.seek(max(0, size - AUTHLOG_MAX))
        tail = fh.read(AUTHLOG_MAX).decode("utf-8", "replace").splitlines()
    if size > AUTHLOG_MAX and tail:
        tail = tail[1:]                      # the first line is cut mid-way
    return size, tail


def authlog_scan(path, now=None):
    """{size, lines_24h, blocked_24h, last_age, unknown} of auth.log's last 512 KB.

    lines_24h counts 'login failed' lines only (one per failed sign-in); blocked_24h the refusals.
    The stamps are the handler's local time, as logging writes them. Raises OSError.
    """
    now = time.time() if now is None else now
    size, tail = _authlog_tail(path)
    out = {"size": size, "lines_24h": 0, "blocked_24h": 0, "last_age": None, "unknown": 0}
    last = None
    for line in tail:
        m = _AUTHLOG_RE.match(line)
        if not m:
            continue
        try:
            at = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
        last = at if last is None else max(last, at)
        key = "lines_24h" if m.group(2) == "login failed" else "blocked_24h"
        out[key] += now - at <= 86400
        out["unknown"] += m.group(3) == "unknown"
    out["last_age"] = None if last is None else now - last
    return out


def _authlog_handler():
    import logging
    return any(getattr(h, "_panel_auth", False) for h in logging.getLogger("panel.auth").handlers)


def _authlog_text(scan, attached, want):
    agree = "" if want is None else " (audit log says %d %s)" % (
        want, "✓" if want == scan["lines_24h"] else "✗")
    return ("handler attached %s · %d failed-login lines in 24 h%s · %d refusal lines · last line "
            "%s · %d KB · 'unknown' addresses: %d" % (
                "✓" if attached else "✗", scan["lines_24h"], agree, scan["blocked_24h"],
                "never" if scan["last_age"] is None else ago(scan["last_age"]) + " ago",
                scan["size"] // 1024, scan["unknown"]))


def _authlog_lines(res, facts):
    attached = _authlog_handler()
    if not attached:
        res.find("fail", AREA, "the auth.log handler is not attached: no failed login reaches fail2ban")
    try:
        scan = authlog_scan(auth_log_path())
    except FileNotFoundError:
        res.add("- **auth.log**: handler attached %s · missing (fail2ban 0.11 refuses to start a "
                "jail whose logpath does not exist)" % ("✓" if attached else "✗"))
        res.find("warn", AREA, "auth.log is missing")
        return
    except OSError as exc:
        res.add(unread_line("auth.log", exc))
        return
    res.add("- **auth.log**: " + _authlog_text(scan, attached, facts.get("audit_fail_24h")))
    if scan["unknown"]:
        res.find("warn", AREA, "auth.log holds failures with no usable address, which no jail can ban")


# ── R44: the in-memory throttles and the ban gate ────────────────────────────────────────────────
def _copy_locked(lock, mapping):
    """A copy of `mapping` taken under `lock` (1 s at most), or None when the lock was not had."""
    if not lock.acquire(timeout=1):
        return None
    try:
        return {k: list(v or ()) for k, v in mapping.items()}
    finally:
        lock.release()


def throttle_summary(fails, limit, window, now=None):
    """(tracked keys, {class: blocked count}) of a throttle map {key: [failure times]}."""
    now = time.time() if now is None else now
    blocked = {}
    for key, times in fails.items():
        if sum(1 for t in times if now - t < window) >= limit:
            cls = _src_net.addr_class(str(key).split("/", 1)[0])
            blocked[cls] = blocked.get(cls, 0) + 1
    return len(fails), blocked


def _throttle_line(res):
    mod = sys.modules.get("app")
    from panel.security import auth
    if mod is None or not hasattr(mod, "_LOGIN_FAILS"):
        res.add("- **Login throttle now**: unavailable in this process")
        return
    fails = _copy_locked(mod._LOGIN_FAILS_LOCK, mod._LOGIN_FAILS)
    tokens = _copy_locked(auth._TOKEN_FAILS_LOCK, auth._TOKEN_FAILS)
    if fails is None or tokens is None:
        res.add("- **Login throttle now**: busy (its lock was held for over a second)")
        return
    n, blocked = throttle_summary(fails, mod.LOGIN_MAX_FAILS, mod.LOGIN_WINDOW)
    _tn, tblocked = throttle_summary(tokens, auth.TOKEN_MAX_FAILS, auth.TOKEN_WINDOW)
    res.add("- **Login throttle now**: %d client keys tracked, %d blocked%s · API-token throttle: "
            "%d blocked" % (n, sum(blocked.values()), (" (%s)" % ", ".join(
                "%s %d" % kv for kv in sorted(blocked.items()))) if blocked else "",
                sum(tblocked.values())))
    if blocked.get("loopback"):
        res.find("fail", AREA, "the login throttle has blocked a loopback key, so every proxied "
                               "client is locked out")


def _age(taken):
    if taken is None or taken == float("-inf"):
        return "never read since boot"
    return "read %s ago" % ago(time.monotonic() - taken)


def _ufw_checked(banlist):
    """' (rule files unchanged, checked X ago)' when the ban-watcher's last UFW check SKIPPED a read.

    Without it, "read 14m ago" under the gate looks like a watcher that stopped. Only a skip earns
    it: a read that answered None (ufw inactive or unreadable) or a check whose stat failed also
    leaves the last read behind the last check, and giving either this reason would explain a UFW
    set that was never read with something that did not happen.
    """
    state = banlist.ufw_gate_state() if hasattr(banlist, "ufw_gate_state") else {}
    if state.get("last_skipped") is not True:
        return ""
    checked = state.get("checked_at")
    if not isinstance(checked, float) or checked == float("-inf"):
        return ""
    return " (rule files unchanged, checked %s ago)" % ago(time.monotonic() - checked)


def _bangate_line(res):
    from panel.security import banlist
    taken = dict(getattr(banlist, "_taken", {}) or {})
    gate = runtime_stats.snapshot("bangate")
    last = gate.get("last")
    res.add("- **Ban gate (Funnel / remote proxy)**: fail2ban set %d networks, %s · UFW set %d, %s%s"
            " · whitelist %d · refusals since boot %d%s" % (
                len(getattr(banlist, "_f2b", ()) or ()), _age(taken.get("f2b")),
                len(getattr(banlist, "_ufw", ()) or ()), _age(taken.get("ufw")), _ufw_checked(banlist),
                len(getattr(banlist, "_allow", ()) or ()), int(gate.get("refused", 0) or 0),
                (" (last %s ago)" % ago(time.time() - last[0])) if isinstance(last, tuple) else ""))
    if taken.get("f2b") in (None, float("-inf")):
        res.find("warn", AREA, "the ban gate's fail2ban set was never read since boot (the "
                               "ban-watcher is not running, or every read failed)")


# ── R45: accounts as counts ──────────────────────────────────────────────────────────────────────
def _funnel_on():
    v = _src_tailscale.cached()
    if v is not None:
        return bool(v.get("funnel_enabled"))
    cfg, readable = _load_cfg()
    return bool(readable and cfg.get("tailscale_use_funnel"))


def account_counts(counts):
    """The R45 numbers from the run_ro results; raises LookupError naming a failed query's class."""
    try:
        users = [int(x or 0) for x in _rows(counts, "users")[0]]
        inv = [int(x or 0) for x in _rows(counts, "invites")[0]]
        ses = [int(x or 0) for x in _rows(counts, "sessions")[0]]
        setup_done = bool(_rows(counts, "setup")[0][0])
    except IndexError:
        raise LookupError("empty") from None
    keys = ("active", "supers", "off", "s2fa", "o2fa", "mcp", "mcp_tok", "tokens")
    out = dict(zip(keys, users))
    out.update(invites=inv[0], invites_super=inv[1], sessions=ses[0], remember=ses[1],
               setup_done=setup_done)
    return out


def _account_lines(res, counts):
    from panel.core import config as _cfg
    try:
        c = account_counts(counts)
    except LookupError as exc:
        res.add("- **Accounts**: DB not queryable (%s)" % exc.args[0])
        return
    others = c["active"] - c["supers"]
    res.add("- **Accounts**: %d active (%d superadmin, %d other) · %d deactivated · 2FA on: "
            "superadmins %d/%d, others %d/%d · API tokens %d · sessions seen in 7 d %d (%d "
            "remember-me) · open invites %d (%d grant superadmin)" % (
                c["active"], c["supers"], others, c["off"], c["s2fa"], c["supers"], c["o2fa"],
                others, c["tokens"], c["sessions"], c["remember"], c["invites"], c["invites_super"]))
    token_file = _cfg.SETUP_TOKEN_FILE.exists()
    res.add("- **Must change password**: %d (%d holding an API token, whose API calls get 403 "
            "password_change_required) · **setup token file present**: %s%s" % (
                c["mcp"], c["mcp_tok"], _yn(token_file),
                " (and setup is complete)" if token_file and c["setup_done"] else ""))
    # Posture stays out of the public summary and At a glance (it tells an attacker which target is
    # weak), except this one aggregated line when the panel is on the public internet.
    if c["s2fa"] < c["supers"] and _funnel_on():
        res.find("warn", AREA, "Funnel is on and not every superadmin has 2FA")


# ── the access section (in the request greenlet) ─────────────────────────────────────────────────
def section_access(ctx):
    """R38, R43, R44, R45. The audit and account counts run off the hub (_src_db.run_ro)."""
    res, facts = Result(), {}
    conf = getattr(ctx.app, "config", None) or {}
    try:
        counts = _db_counts(ctx)
    except Exception as exc:  # noqa: BLE001 - every count below then says it could not be read
        counts = {k: "error:" + type(exc).__name__ for k in signin_queries()}
    parts = (("This request", lambda: _request_lines(res, conf)),
             ("Sign-ins", lambda: _signin_lines(res, counts, facts)),
             ("auth.log", lambda: _authlog_lines(res, facts)),
             ("Login throttle", lambda: _throttle_line(res)),
             ("Ban gate", lambda: _bangate_line(res)),
             ("Accounts", lambda: _account_lines(res, counts)))
    for title, part in parts:
        try:
            part()
        except Exception as exc:  # noqa: BLE001 - one part's failure is printed, the rest still run
            res.add(unread_line(title, exc))
            res.find("unread", AREA, "%s could not be read" % title)
    return res
