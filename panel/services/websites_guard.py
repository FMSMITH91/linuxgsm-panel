"""Blocked visitors: fail2ban for the websites, with the ban kept INSIDE the web proxy so it works behind a CDN.

WHY INSIDE THE PROXY
    Behind a CDN or a tunnel every request reaches the host from the CDN's (or the connector's) address, so a
    firewall ban would ban the CDN. The proxy already decides each visitor's real address with the trusted-proxy
    rules (websites_proxy, FORWARDED HEADERS: a client-address header is believed only from a trusted network,
    never from anyone else); that address, Caddy's client_ip, is the one logged and the one refused here.

WHAT IS WATCHED (guard_lines, in every site block while the guard is on)
    Only these requests are written to the proxy's security log (SECURITY_LOG), each tagged with the jail that
    counts it, and with no more than the jail needs: the time, the visitor's address, the method, the site's name
    and the status (OWASP Logging Cheat Sheet, "Data to exclude": no path, query, header or cookie):
      login   a POST to a sign-in path of the apps the panel installs (WordPress's wp-login.php and xmlrpc.php,
              Drupal's /user/login, phpBB's ucp.php?mode=login, MyBB's member.php, SMF's index.php?action=login2).
              WordPress answers 200 to a wrong password, so attempts are counted, not failures.
      scan    a path only a scanner asks for (SCAN_PATHS: .env, .git, backups of wp-config.php, server-status,
              phpMyAdmin...) and the site's own denied paths (its rules): the proxy refuses those anyway.
    Every other request is logged only where the site's own access log is on, as before (masked).

THE BAN
    fail2ban (two jails, lgsm-web-login and lgsm-web-scan, written by the root helper from guard_doc) counts the
    tagged lines per address and bans through the helper: the address becomes a file in DENY_DIR, which each site
    block's `file` matcher reads on every request and answers 403 before anything else runs (no page from the
    cache, no redirect). Nothing is reloaded or restarted for a ban. In public mode the jails also ban on ports 80
    and 443 at the firewall. Bans are temporary, and grow for an address banned again (OWASP Credential Stuffing
    Prevention Cheat Sheet, "IP Mitigation and Intelligence": blocks "should be temporary", a "graduated response";
    Authentication Cheat Sheet, "Login Throttling": a threshold, an observation window, a lockout duration that
    may double each time). Never banned (never_list): the loopback, the host's own addresses (the helper adds them),
    the tailnet, every CDN preset's networks, the host's allow list and the panel's whitelist, so a CDN's own
    address is never in the list.

THE SETTINGS (per host, WebsiteProxy.guard; the Websites page's proxy card, superadmin)
    OWASP gives no number for a threshold, a window or a duration. It gives a fixed lockout of ten minutes as an
    example, asks for temporary blocks and for a duration that grows. Those are the recommendations shown beside
    the fields (OWASP_TEXT), with a note, never a block, for a value outside them (owasp_notes).
"""
import ipaddress
import json

DENY_DIR = "/etc/lgsm-web-proxy/deny"
SECURITY_LOG = "/var/log/lgsm-web-proxy/security.log"
# What the Blocked visitors list says of each jail.
JAIL_LABELS = {"lgsm-web-login": "Too many sign-in attempts", "lgsm-web-scan": "Asked for paths only scanners ask for"}
LOGIN_PATHS = ("/wp-login.php", "/xmlrpc.php", "/user/login", "/member.php")
LOGIN_QUERIES = (("/ucp.php", "mode=login"), ("/index.php", "action=login2"))
SCAN_PATHS = ("/.env", "/.env.*", "/.git", "/.git/*", "/.svn/*", "/.hg/*", "/.DS_Store", "/.htpasswd", "/.aws/*",
              "/.ssh/*", "/wp-config.php", "/wp-config.php.*", "/wp-config.php~", "/wp-config.bak", "/wp-config.old",
              "/wp-config.txt", "/server-status", "/server-status/*", "/server-info", "/phpmyadmin", "/phpmyadmin/*",
              "/pma", "/pma/*", "/myadmin", "/myadmin/*", "/vendor/phpunit/*", "/cgi-bin/*", "/actuator/*",
              "/boaform/*", "/config.php.bak", "/backup.sql", "/dump.sql", "/database.sql")
# The tailnet's ranges, fixed by Tailscale: a tailnet peer is never banned anywhere by the panel.
TAILNET = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")
LOOPBACK = ("127.0.0.0/8", "::1/128")

DEFAULTS = {"enabled": True, "login": 10, "scan": 3, "findtime": 600, "bantime": 600, "increment": True,
            "maxtime": 86400, "allow": []}
LIMITS = {"login": (1, 1000), "scan": (1, 1000), "findtime": (60, 86400), "bantime": (60, 2592000),
          "maxtime": (60, 31536000)}
ALLOW_MAX = 100
OWASP_BANTIME = 600     # OWASP's example of a fixed lockout (Authentication Cheat Sheet, "Account Lockout"): 10 minutes
# OWASP's own words beside each field (it gives no number but the lockout example).
OWASP_TEXT = {
    "login": "OWASP gives no number: a limit of attempts within a window.",
    "scan": "OWASP gives no number.",
    "findtime": "OWASP gives no number: the observation window.",
    "bantime": "OWASP's example of a fixed lockout: 10 minutes.",
    "increment": "OWASP recommends a duration that grows each time (exponential backoff).",
    "maxtime": "OWASP recommends temporary blocks.",
}


def _int(value, key):
    low, high = LIMITS[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return None
    return value


def _net(text):
    """`text` as a canonical network (an address is its /32 or /128), or None."""
    if not isinstance(text, str) or "%" in text or len(text) > 64:
        return None
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except ValueError:
        return None


def is_address(text):
    """Whether `text` is one visitor's address as the deny list names it (IPv4 or IPv6, no zone, no network)."""
    if not isinstance(text, str) or "%" in text or "/" in text or len(text) > 45:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def settings(raw):
    """DEFAULTS overlaid with the valid keys of `raw` (WebsiteProxy.guard, JSON text or a dict)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except ValueError:
            raw = {}
    out = dict(DEFAULTS, allow=[])
    for key, value in (raw if isinstance(raw, dict) else {}).items():
        got = _setting(key, value)
        if got is not None:
            out[key] = got
    out["maxtime"] = max(out["maxtime"], out["bantime"])
    return out


def _setting(key, value):
    """One stored setting checked: its value, or None when it is not one of its shape."""
    if key in ("enabled", "increment"):
        return value if isinstance(value, bool) else None
    if key in LIMITS:
        return _int(value, key)
    if key == "allow" and isinstance(value, list):
        return [n for n in (_net(v) for v in value[:ALLOW_MAX]) if n]
    return None


# The card's number fields: (key, label, the unit the card uses in seconds).
_FORM_FIELDS = (("login", "Sign-in attempts", 1), ("scan", "Scanner requests", 1), ("findtime", "The window (minutes)", 60),
                ("bantime", "The first ban (minutes)", 60), ("maxtime", "The longest ban (hours)", 3600))
S_NUMBER = "{field} is a whole number from {low} to {high}."
S_NOT_NET = "{value} is not an address or network, like 203.0.113.7 or 2001:db8::/48."
S_MAX_BELOW = "The longest ban is at least the first ban."


def _form_value(raw, unit):
    if isinstance(raw, str) and raw.strip().isdecimal() and len(raw.strip()) <= 9:
        return int(raw.strip()) * unit
    return raw * unit if isinstance(raw, int) and not isinstance(raw, bool) else None


def parse(form, before):
    """(settings, [problems as Sentences]) from the card's form: minutes and hours in, seconds stored.

    `before` (settings()) fills each field the form leaves out.
    """
    from panel.core import i18n
    out, problems = dict(before), []
    for key in ("enabled", "increment"):
        if key in form:
            out[key] = form.get(key) in (True, "1", "true", "on")
    for key, label, unit in _FORM_FIELDS:
        if key not in form:
            continue
        got = _int(_form_value(form.get(key), unit), key)
        if got is None:
            problems.append(i18n.Sentence(S_NUMBER, field=i18n.Sentence(label), low=-(-LIMITS[key][0] // unit),
                                          high=LIMITS[key][1] // unit))
        else:
            out[key] = got
    if "allow" in form:
        out["allow"], bad = _allow(form.get("allow"))
        problems += [i18n.Sentence(S_NOT_NET, value=b) for b in bad]
    if out["maxtime"] < out["bantime"]:
        problems.append(S_MAX_BELOW)
    return out, problems


def _allow(raw):
    items = raw.split() if isinstance(raw, str) else raw if isinstance(raw, list) else []
    good, bad = [], []
    for item in items[:ALLOW_MAX]:
        net = _net(item) if isinstance(item, str) else None
        (good if net else bad).append(net or str(item)[:64])
    return sorted(set(good)), bad


def owasp_notes(s):
    """{field: sentence} for each setting outside OWASP's recommendation (a note beside it, never a block)."""
    notes = {}
    if not s["enabled"]:
        notes["enabled"] = ("OWASP recommends throttling sign-in attempts; with blocking off, nothing limits them "
                            "on these websites.")
    if not s["increment"]:
        notes["increment"] = "OWASP recommends a ban that grows each time the same address is banned again."
    if s["bantime"] < OWASP_BANTIME:
        notes["bantime"] = "Shorter than OWASP's example of a 10-minute lockout. It is still saved."
    return notes


def never_list(proxy, whitelist=()):
    """The networks never banned: loopback, the tailnet, every CDN preset's, the allow list, the panel's whitelist.

    The host's own addresses are added by the helper, which reads them on the host.
    """
    from panel.services import websites_catalog as _wc     # imported here: the render tests need no catalog
    nets = list(LOOPBACK) + list(TAILNET)
    for _preset, ranges in sorted(_wc.cdn_ranges().items()):
        nets += ranges
    if proxy is not None:
        nets += proxy.cidrs() + proxy.url_nets() + settings(getattr(proxy, "guard", "{}"))["allow"]
    nets += [n for n in (_net(w) for w in whitelist) if n]
    out = []
    for n in nets:
        canon = _net(n)
        if canon and canon not in out:
            out.append(canon)
    return out


def doc(proxy, whitelist=()):
    """The guard part of website-proxy-apply's document: the jails' numbers, the never list, the firewall ban."""
    s = settings(getattr(proxy, "guard", "{}") if proxy is not None else "{}")
    return {"enabled": bool(s["enabled"]), "login": s["login"], "scan": s["scan"], "findtime": s["findtime"],
            "bantime": s["bantime"], "maxtime": s["maxtime"], "increment": bool(s["increment"]),
            "firewall": proxy is None or proxy.exposure_mode == "public", "never": never_list(proxy, whitelist)}


def enabled(proxy):
    """Whether the guard's lines go into the proxy's configuration (a host's settings; never with no row)."""
    return proxy is not None and hasattr(proxy, "guard") and settings(proxy.guard)["enabled"]


# ── the proxy's lines ────────────────────────────────────────────────────────────────────────────
def _security_log(name):
    """The block's security logger, mapped to the block's names (never `no_hostname`).

    The proxy decides whether a request is logged at all before any handler runs, by its Host: a host no logger is
    mapped to is not logged, and a `log_name` cannot bring it back (with a catch-all block in the configuration, the
    server skips unmapped hosts). A security logger with `no_hostname` on a site without its own access log was
    mapped to nothing, so no watched request was ever written and nothing was banned. Mapped, it would also receive
    every other request of the block: those are skipped (`log_skip @lgsmquiet`) or, with the site's access log on,
    named to the access logger alone (`log_name @lgsmquiet`).
    """
    return ["\tlog %s {" % name, "\t\toutput file %s {" % SECURITY_LOG, "\t\t\troll_size 10MiB",
            "\t\t\troll_keep 2", "\t\t\troll_keep_for 48h", "\t\t\tmode 0600", "\t\t}", "\t\tformat filter {",
            "\t\t\twrap json {", "\t\t\t\ttime_format iso8601", "\t\t\t}"] + [
        "\t\t\t%s delete" % f for f in ("request>remote_ip", "request>remote_port", "request>proto", "request>uri",
                                        "request>headers", "request>tls", "resp_headers", "user_id", "bytes_read",
                                        "size", "duration")] + ["\t\t}", "\t}"]


def _watch_matchers(deny_paths):
    lines = ["\t@lgsmlogin {", "\t\tmethod POST", "\t\tpath %s" % " ".join(LOGIN_PATHS), "\t}"]
    for i, (path, query) in enumerate(LOGIN_QUERIES):
        lines += ["\t@lgsmlogin%d {" % i, "\t\tmethod POST", "\t\tpath %s" % path, "\t\tquery %s" % query, "\t}"]
    lines.append("\t@lgsmscan path %s" % " ".join(list(SCAN_PATHS) + list(deny_paths)))
    return lines


def _quiet_matcher(deny_paths, access):
    """Every request the guard does not watch: kept out of the security log the block's names map to.

    With the site's access log off it is skipped by every logger; on (`access`, its logger's name), it is written by
    that logger alone.
    """
    lines = ["\t@lgsmquiet {", "\t\tnot {", "\t\t\tmethod POST", "\t\t\tpath %s" % " ".join(LOGIN_PATHS), "\t\t}"]
    for path, query in LOGIN_QUERIES:
        lines += ["\t\tnot {", "\t\t\tmethod POST", "\t\t\tpath %s" % path, "\t\t\tquery %s" % query, "\t\t}"]
    return lines + ["\t\tnot path %s" % " ".join(list(SCAN_PATHS) + list(deny_paths)), "\t}",
                    "\tlog_name @lgsmquiet %s" % access if access else "\tlog_skip @lgsmquiet"]


def guard_lines(site_id, block, deny_paths, access_log):
    """A site block's guard: the deny list's 403, the watched requests to the security log, tagged.

    `block` numbers the site's blocks (one per certificate source), so each logger name is its own. The security
    logger is mapped to the block's names (_security_log). With the site's access log on, its logger is named too
    (access_name): a watched request goes to both, every other request to the access logger alone; with it off,
    every other request is skipped by every logger.
    """
    sec = "lgsmsec%d_%d" % (site_id, block)
    names = sec + (" " + access_name(site_id, block) if access_log else "")
    lines = ["\t@lgsmdeny file {", "\t\troot %s" % DENY_DIR, "\t\ttry_files {client_ip}", "\t}", "\terror @lgsmdeny 403"]
    lines += _watch_matchers(deny_paths)
    for matcher, tag in (("lgsmlogin", "login"), ("lgsmlogin0", "login"), ("lgsmlogin1", "login"), ("lgsmscan", "scan")):
        lines += ["\tlog_name @%s %s" % (matcher, names), "\tlog_append @%s lgsm %s" % (matcher, tag)]
    lines += _quiet_matcher(deny_paths, access_name(site_id, block) if access_log else None)
    return lines + _security_log(sec)


def access_name(site_id, block):
    """The name of a site block's own access logger while the guard is on (a watched request goes to it too)."""
    return "lgsmacc%d_%d" % (site_id, block)
