"""The web proxy's configuration (a Caddyfile), rendered from the database.

render() is a pure function of the enabled sites, the host's WebsiteProxy row (exposure mode, allow
list, origin TLS) and the panel-wide options (HSTS, minimum TLS version, ACME contact and CA). The
helper verb website-proxy-apply validates the text with the proxy's own `caddy validate` as the proxy's
user before it replaces the running file, so a bad site rule never takes down the other sites.

WHAT EVERY CONFIGURATION HOLDS
    `admin off` and `persist_config off` (no admin API, nothing written back); HTTP/1.1 and HTTP/2 only
    (no HTTP/3: no UDP port to open); server timeouts against slow clients; a catch-all that aborts any
    request for a name the configuration does not hold, the bare IP included, so the panel's own name
    and port are never reachable through the proxy. Automatic HTTPS only for the names listed, never
    on-demand. Per site: the proxy's token header that the site's own server requires (a local account
    reaching the loopback port directly gets 403), a body size limit, compression, security headers,
    and the server's own Server and X-Powered-By headers removed.

FORWARDED HEADERS (OWASP HTTP Headers Cheat Sheet; Caddy's trusted_proxies)
    Caddy replaces every incoming X-Forwarded-* header with its own unless the peer is a trusted proxy.
    Only exposure mode 'restricted' (the allow list) and 'tunnel' (the connector on loopback) name any:
    exactly the allow list, or 127.0.0.1 and ::1. The client address header is read only from them
    (CF-Connecting-IP with the Cloudflare preset or a tunnel, else X-Forwarded-For read right to left).

HEADERS (OWASP HTTP Headers and HTTP Strict Transport Security cheat sheets)
    Strict-Transport-Security with the operator's max-age (OWASP's 63072000 by default), with
    includeSubDomains and preload only when the operator turns them on: the panel cannot know a
    customer's other subdomains are all HTTPS, and preload has permanent consequences.
    X-Content-Type-Options nosniff and Referrer-Policy strict-origin-when-cross-origin always.
    X-Frame-Options SAMEORIGIN and a Permissions-Policy only when the site sends none of its own
    (SAMEORIGIN, not OWASP's DENY: WordPress's customizer frames its own pages). No default
    Content-Security-Policy: it breaks WordPress and most forum software; a site may add one with a
    custom header rule.
"""
import ipaddress
import json
import re

# The panel-wide options the Websites settings card edits (config.json), and OWASP's recommended
# value of each where OWASP gives one (the card prints it beside the field and notes a value outside it).
DEFAULTS = {"hsts_max_age": 63072000, "hsts_subdomains": False, "hsts_preload": False, "tls_min": "1.2",
            "acme_email": "", "acme_staging": False, "local_certs": False, "cache_build": False,
            "access_log_days": 7}
OWASP = {"hsts_max_age": 63072000, "hsts_subdomains": True, "hsts_preload": True, "tls_min": "1.2"}
TLS_MIN = ("1.2", "1.3")
STORAGE = "/var/lib/lgsm-web-proxy"
CERT_DIR = "/etc/lgsm-web-proxy/certs"
ORIGIN_PULL_CA = "/etc/lgsm-web-proxy/origin-pull-ca.pem"
TOKEN_HEADER = "X-Panel-Proxy-Token"
# Tunnel mode: the proxy listens on this loopback port only, plain HTTP; the connector reaches it.
TUNNEL_PORT = 19080
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
STATIC_TYPES = ("css", "js", "mjs", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "woff", "woff2",
                "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "pdf")
STATIC_MAX_AGE = 2592000
# Requests the page cache never serves or stores: logged-in cookies, writes and admin paths.
CACHE_BYPASS_COOKIES = r"(wordpress_logged_in_|wp-postpass_|comment_author_|phpbb[0-9a-z_]*_(sid|u|k)|SESS|SSESS|PHPSESSID|mybbuser|SMFCookie)"
CACHE_BYPASS_PATHS = ("/wp-admin*", "/wp-login.php*", "/adm*", "/admin*", "/user*", "/install*", "/xmlrpc.php*")
RULES_MAX = 50
SNIPPET_MAX = 4000
# Response headers a custom rule may not set: they belong to the proxy, the browser's session or HTTP.
PROTECTED_HEADERS = ("set-cookie", "server", "content-length", "transfer-encoding", "connection", "host",
                     TOKEN_HEADER.lower(), "strict-transport-security", "x-content-type-options")
_PATH_RE = re.compile(r"/[A-Za-z0-9._~/%+-]{0,200}\*?\Z")
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}\Z")
_HEADER_VALUE_RE = re.compile(r"[\x20-\x7e]{1,500}\Z")
_TARGET_RE = re.compile(r"(?:/[A-Za-z0-9._~/%+=&?#-]{0,300}|https://[a-z0-9.-]{1,253}(?:/[A-Za-z0-9._~/%+=&?#-]{0,300})?)\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_DOMAIN_RE = re.compile(r"[a-z0-9.-]{1,253}\Z")
REDIRECT_CODES = (301, 302, 307, 308)


def options(raw=None):
    """DEFAULTS overlaid with the known keys of `raw` (config.json's websites options), types held."""
    out = dict(DEFAULTS)
    for key, value in (raw or {}).items():
        if key in out and type(value) is type(out[key]):  # noqa: E721 - exact type: True is not a max-age
            out[key] = value
    if out["tls_min"] not in TLS_MIN:
        out["tls_min"] = DEFAULTS["tls_min"]
    if not 0 <= out["hsts_max_age"] <= 10 * 63072000:
        out["hsts_max_age"] = DEFAULTS["hsts_max_age"]
    return out


def owasp_notes(opts):
    """{option: sentence} for each option outside OWASP's recommendation (the card shows a note, never a block)."""
    notes = {}
    if opts["hsts_max_age"] < OWASP["hsts_max_age"]:
        notes["hsts_max_age"] = "OWASP recommends a max-age of 63072000 seconds (two years)."
    if not opts["hsts_subdomains"]:
        notes["hsts_subdomains"] = ("OWASP recommends includeSubDomains once every subdomain of every site is "
                                    "served over HTTPS.")
    return notes


# ── the allow list ──────────────────────────────────────────────────────────────────────────────
def allow_list(proxy):
    """The canonical networks `proxy` admits in 'restricted' mode: its CIDRs plus its presets' ranges.

    Sorted IPv4 first, without duplicates and without a network another one already holds.
    """
    if proxy is None:
        return []
    from panel.services import websites_catalog as _wc    # imported here: render's tests need no catalog
    nets = set(proxy.cidrs())
    for preset in proxy.presets():
        nets.update(_wc.preset_ranges(preset))
    parsed = sorted({ipaddress.ip_network(n) for n in nets}, key=lambda n: (n.version, n.network_address, n.prefixlen))
    kept = [n for n in parsed if not any(o != n and o.version == n.version and n.subnet_of(o) for o in parsed)]
    return [str(n) for n in kept]


# ── custom rules ────────────────────────────────────────────────────────────────────────────────
def _rule_problem(rule):
    """Why one custom rule is refused, or ""."""
    kind = rule.get("type") if isinstance(rule, dict) else None
    shapes = {"redirect": {"type", "from", "to", "code"}, "header": {"type", "name", "value"},
              "deny": {"type", "path"}}
    if kind not in shapes or set(rule) != shapes[kind]:
        return "Each rule is a redirect (from, to, code), a header (name, value) or a denied path."
    if kind == "redirect":
        if not (isinstance(rule["from"], str) and _PATH_RE.match(rule["from"])):
            return "A redirect starts from a path on the site, like /old-page."
        if not (isinstance(rule["to"], str) and _TARGET_RE.match(rule["to"])):
            return "A redirect goes to a path on the site or an https:// address."
        if rule["code"] not in REDIRECT_CODES or isinstance(rule["code"], bool):
            return "A redirect's code is 301, 302, 307 or 308."
        return ""
    if kind == "header":
        if not (isinstance(rule["name"], str) and _HEADER_NAME_RE.match(rule["name"])):
            return "A header name is letters, digits and hyphens."
        if rule["name"].lower() in PROTECTED_HEADERS:
            return "The %s header is set by the web proxy itself and cannot be changed." % rule["name"]
        value = rule["value"]
        if not (isinstance(value, str) and _HEADER_VALUE_RE.match(value)) or any(c in value for c in '"\\{}'):
            return "A header value is one line of plain characters, without quotes, backslashes or braces."
        return ""
    if not (isinstance(rule["path"], str) and _PATH_RE.match(rule["path"])):
        return "A denied path starts with /, like /private or /backup*."
    return ""


def rules_problems(rules):
    """What is wrong with a site's custom rules (a list of dicts), as a list of sentences (empty: none)."""
    if not isinstance(rules, list):
        return ["The rules are a list."]
    if len(rules) > RULES_MAX:
        return ["A site may have at most %d rules." % RULES_MAX]
    out = []
    for i, rule in enumerate(rules, 1):
        why = _rule_problem(rule)
        if why:
            out.append("Rule %d: %s" % (i, why))
    return out


def snippet_problems(text):
    """What is wrong with a raw proxy snippet (superadmin only), as sentences; [] when none.

    The snippet goes inside its site's block: its braces must balance there, and it may not read
    the proxy's environment or files ({env.*}, {$...}, import), which would print secrets into a page.
    """
    if not isinstance(text, str):
        return ["The snippet is text."]
    if len(text) > SNIPPET_MAX or "\x00" in text:
        return ["A snippet is at most %d characters." % SNIPPET_MAX]
    out = []
    depth = 0
    for ch in text:
        depth += 1 if ch == "{" else -1 if ch == "}" else 0
        if depth < 0:
            break
    if depth != 0:
        out.append("Its braces { } must balance inside the site's block.")
    if re.search(r"\{\$|\{env\.|\{file\.|^\s*import\b", text, re.M):
        out.append("It may not read the proxy's environment or files ({env.*}, {$...}, {file.*}, import).")
    return out


# ── render ──────────────────────────────────────────────────────────────────────────────────────
def _quote(text):
    """`text` as one Caddyfile token in double quotes (validated values carry no quote or backslash)."""
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')


def _secret_of(site):
    from panel.core.config import decrypt_secret    # imported here: render is tested without a key
    return decrypt_secret(site.proxy_secret or "")


def _domains(site):
    """The site's domains the proxy serves: verified, valid, primary first."""
    rows = sorted(site.domains or [], key=lambda d: (not d.is_primary, d.id or 0))
    return [d.domain for d in rows if d.verified_at is not None and _DOMAIN_RE.match(d.domain or "")]


def _global(mode, opts, proxy, trusted):
    lines = ["{", "\tadmin off", "\tpersist_config off", "\tgrace_period 10s", "\tstorage file_system %s" % STORAGE]
    if mode == "tunnel":
        lines += ["\tauto_https off", "\tdefault_bind 127.0.0.1", "\thttp_port %d" % TUNNEL_PORT]
    else:
        if opts["acme_email"]:
            lines.append("\temail %s" % _quote(opts["acme_email"]))
        if opts["local_certs"]:
            lines.append("\tlocal_certs")
        elif opts["acme_staging"]:
            lines.append("\tacme_ca %s" % LE_STAGING)
        lines.append("\tskip_install_trust")
    if opts["cache_build"]:
        lines += ["\torder cache before rewrite", "\tcache {", "\t\tttl 300s", "\t}"]
    lines += ["\tservers {", "\t\tprotocols h1 h2",
              "\t\ttimeouts {", "\t\t\tread_header 10s", "\t\t\tread_body 60s", "\t\t\twrite 120s", "\t\t\tidle 2m",
              "\t\t}"]
    if trusted:
        lines.append("\t\ttrusted_proxies static %s" % " ".join(trusted))
        if mode == "tunnel" or (proxy is not None and "cloudflare" in proxy.presets()):
            lines.append("\t\tclient_ip_headers CF-Connecting-IP")
        else:
            lines += ["\t\tclient_ip_headers X-Forwarded-For", "\t\ttrusted_proxies_strict"]
    lines += ["\t}", "}", ""]
    return lines


def _hsts(opts):
    value = "max-age=%d" % opts["hsts_max_age"]
    if opts["hsts_subdomains"]:
        value += "; includeSubDomains"
    if opts["hsts_preload"] and opts["hsts_subdomains"]:
        value += "; preload"
    return value


def _tls_lines(site, opts, proxy):
    """The site's `tls` block: protocols, its own certificate files, and the CDN's client certificate."""
    inner = ["\t\tprotocols tls%s tls1.3" % opts["tls_min"]] if opts["tls_min"] != "1.3" else ["\t\tprotocols tls1.3"]
    if proxy is not None and proxy.origin_pull_mtls:
        inner += ["\t\tclient_auth {", "\t\t\tmode require_and_verify", "\t\t\ttrust_pool file %s" % ORIGIN_PULL_CA,
                  "\t\t}"]
    own = [d for d in (site.domains or []) if d.cert_mode == "own" and d.verified_at is not None]
    head = "\ttls {"
    if own:
        head = "\ttls %s/%s.crt %s/%s.key {" % (CERT_DIR, own[0].domain, CERT_DIR, own[0].domain)
    return [head] + inner + ["\t}"]


def _header_lines(site, opts, mode):
    lines = ["\theader {"]
    if mode != "tunnel":
        lines.append("\t\tStrict-Transport-Security %s" % _quote(_hsts(opts)))
    lines += ["\t\tX-Content-Type-Options nosniff", "\t\tReferrer-Policy strict-origin-when-cross-origin",
              "\t\t?X-Frame-Options SAMEORIGIN", '\t\t?Permissions-Policy "geolocation=(), camera=(), microphone=()"',
              "\t\t-Server", "\t\t-X-Powered-By"]
    for rule in _rules(site):
        if rule["type"] == "header":
            lines.append("\t\t%s %s" % (rule["name"], _quote(rule["value"])))
    lines.append("\t}")
    if site.static_cache:
        lines += ["\t@static path %s" % " ".join("*.%s" % t for t in STATIC_TYPES),
                  "\theader @static ?Cache-Control %s" % _quote("public, max-age=%d" % STATIC_MAX_AGE)]
    return lines


def _rules(site):
    try:
        rules = json.loads(site.custom_rules or "[]")
    except ValueError:
        return []
    return rules if not rules_problems(rules) else []


def _rule_lines(site):
    lines = []
    for i, rule in enumerate(_rules(site)):
        if rule["type"] == "deny":
            lines += ["\t@deny%d path %s" % (i, rule["path"]), "\trespond @deny%d 404" % i]
        elif rule["type"] == "redirect":
            lines.append("\tredir %s %s %d" % (rule["from"], _quote(rule["to"]), rule["code"]))
    return lines


def _cache_lines(site, opts):
    if not (opts["cache_build"] and site.page_cache):
        return []
    ttl = max(10, min(int(site.page_cache_ttl or 300), 86400))
    return ["\t@pagecache {", "\t\tmethod GET HEAD", "\t\tnot header_regexp Cookie %s" % _quote(CACHE_BYPASS_COOKIES),
            "\t\tnot path %s" % " ".join(CACHE_BYPASS_PATHS), "\t}",
            "\tcache @pagecache {", "\t\tttl %ds" % ttl, "\t}"]


def _log_lines(site):
    if not site.access_log:
        return []
    return ["\tlog {", "\t\toutput stderr", "\t\tformat filter {", "\t\t\twrap json",
            "\t\t\trequest>remote_ip ip_mask {", "\t\t\t\tipv4 24", "\t\t\t\tipv6 48", "\t\t\t}",
            "\t\t\trequest>client_ip ip_mask {", "\t\t\t\tipv4 24", "\t\t\t\tipv6 48", "\t\t\t}",
            "\t\t\trequest>headers delete", "\t\t\tresp_headers delete", "\t\t}", "\t}"]


def _site_lines(site, opts, proxy, mode, secret_of):
    names = _domains(site)
    token = secret_of(site)
    if not names or not site.port or not _TOKEN_RE.match(token or ""):
        return []
    addresses = ", ".join(("http://%s" % n) if mode == "tunnel" else n for n in names)
    lines = ["# site %s (%s)" % (site.id, site.name), "%s {" % addresses]
    if mode != "tunnel":
        lines += _tls_lines(site, opts, proxy)
    lines += ["\tencode zstd gzip", "\trequest_body {", "\t\tmax_size %dMB" % max(1, int(site.max_body_mb or 1)), "\t}"]
    lines += _header_lines(site, opts, mode) + _rule_lines(site) + _cache_lines(site, opts) + _log_lines(site)
    if site.raw_proxy_snippet and not snippet_problems(site.raw_proxy_snippet):
        lines += ["\t# the superadmin's own lines for this site"] + [
            "\t" + ln for ln in site.raw_proxy_snippet.strip("\n").split("\n")]
    lines += ["\treverse_proxy 127.0.0.1:%d {" % int(site.port),
              "\t\theader_up %s %s" % (TOKEN_HEADER, _quote(token)),
              "\t\ttransport http {", "\t\t\tdial_timeout 5s", "\t\t\tresponse_header_timeout 120s", "\t\t}",
              "\t}", "}", ""]
    return lines


def render(sites, proxy=None, opts=None, secret_of=None):
    """The proxy configuration text for `sites` (enabled, with verified domains) under `proxy`'s settings.

    `opts` is options()'s dict (DEFAULTS when None); `secret_of(site)` returns the site's proxy token
    in clear (decrypt_secret of proxy_secret by default). A site without a verified domain, a port or a
    token is left out, never served half-configured.
    """
    opts = options(opts)
    secret_of = secret_of or _secret_of
    mode = proxy.exposure_mode if proxy is not None else "public"
    trusted = {"restricted": allow_list(proxy), "tunnel": ["127.0.0.1/32", "::1/128"]}.get(mode, [])
    lines = ["# Written by linuxgsm-panel from its database: the panel rewrites this file; edits are lost.", ""]
    lines += _global(mode, opts, proxy, trusted)
    for site in sorted(sites, key=lambda s: s.id or 0):
        if site.enabled:
            lines += _site_lines(site, opts, proxy, mode, secret_of)
    lines += ["# Any other name, and the bare address: the connection is closed.", "http:// {", "\tabort", "}", ""]
    return "\n".join(lines)


def served_domains(sites):
    """Every domain render() serves for `sites`, sorted (what the certificate probe asks about)."""
    return sorted(d for s in sites if s.enabled for d in _domains(s))
