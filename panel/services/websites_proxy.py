"""The web proxy's configuration (a Caddyfile), rendered from the database.

render() is a pure function of the enabled sites, the host's WebsiteProxy row (exposure mode, allow
list, origin TLS) and the panel-wide options (HSTS, minimum TLS version, ACME contact and CA). The
helper verb website-proxy-apply validates the text with the proxy's own `caddy validate` as the proxy's
user before it replaces the running file, so a bad site rule never takes down the other sites.

WHAT EVERY CONFIGURATION HOLDS
    `persist_config off` (nothing written back) and `admin off` (no admin API), except while the page cache is on:
    then the admin API listens on a unix socket in the proxy's runtime folder (ADMIN_SOCKET, mode 0200: the proxy's
    own user, and root), never on a TCP port, so the root helper can empty one site's cache through the cache's
    API without restarting the proxy (website-proxy-apply purge); a site's account cannot reach it. HTTP/1.1 and HTTP/2 only
    (no HTTP/3: no UDP port to open); server timeouts against slow clients; a catch-all that aborts any
    request for a name the configuration does not hold, the bare IP included, so the panel's own name
    and port are never reachable through the proxy (an `http://` catch-all and, outside tunnel mode, an
    `https://` one: an unknown Host over HTTPS gets no response at all). Automatic HTTPS only for the
    names listed, never on-demand. Per site: the proxy's token header that the site's own server requires (a local account
    reaching the loopback port directly gets 403), a body size limit, compression, security headers,
    and the server's own Server and X-Powered-By headers removed.

WHERE IT LISTENS
    Not here: the helper (website-proxy-apply) puts in `default_bind` with the host's own addresses at
    each apply, leaving out the loopback, link-local and tailnet ones (Tailscale Serve holds the tailnet
    address's 443), and refuses in words when another program holds 80 or 443 on them. Tunnel mode
    binds 127.0.0.1 itself (TUNNEL_PORT).

FORWARDED HEADERS (OWASP HTTP Headers Cheat Sheet; Caddy's trusted_proxies)
    Caddy replaces every incoming X-Forwarded-* header with its own unless the peer is a trusted proxy.
    Only exposure mode 'restricted' (the allow list) and 'tunnel' (the connector on loopback) name any:
    exactly the allow list, or 127.0.0.1 and ::1. The client address header is read only from them.
    Each preset carries its CDN's header (PRESET_HEADERS): CF-Connecting-IP, which Cloudflare sets on
    every request, is read only while every trusted network is Cloudflare's, since a request through
    any other trusted proxy could carry one a visitor made up. Otherwise (Fastly, whose Fastly-Client-IP
    keeps a visitor's own value; presets of two CDNs; the operator's trusted networks) the address is read
    from X-Forwarded-For right to left: the first address that is not a trusted proxy, which every one of
    them appends. The operator's own networks (typed, or a list read from an address) are allow-only: the firewall admits them, but they are
    trusted proxies only when the superadmin says so (WebsiteProxy.custom_trusted), since anyone on a
    trusted network can make the sites see any address. A tunnel reads CF-Connecting-IP from the
    connector on loopback.

BLOCKED VISITORS (services/websites_guard)
    While a host's guard is on, each site block starts with the deny list's 403 (`order error first`: before the
    page cache, a redirect or anything else), and the requests fail2ban counts go to the proxy's security log.
    Requests the guard does not watch are logged only by a site's own access log, as before; the catch-alls log
    nothing.

SITES IN FOLDERS (services/website_folders)
    A domain that has a site in a folder (example.org/forums) gets ONE block of its own, whichever sites hold it: a
    `handle` per folder, the longest folder first (a folder never holds another site's, but the order is still
    written out, not left to Caddy's sorting of named matchers), each matching the folder itself and everything
    under it (`path /forums /forums/*`, so /forumsx is not the folder's), then the root site's `handle`, or a 404
    when no site holds the root. The folder without its slash (/forums) is answered here with a 308 to /forums/
    (a path, so the browser keeps its own scheme and host; the query kept): the site's own server would build
    that redirect from its inside port (http://<domain>:8080/forums/). The prefix is KEPT, never stripped: each site's own server maps its folder to its
    files (services/websites: an Alias in Apache, an alias in nginx) and each app is told it (its URLs and cookie
    path, websites_recipes), so redirects, links and cookies name the folder the browser asked for. A runtime app
    gets the folder too and is told so on its Domains tab. The certificate is the domain's: the root site's
    source, else the first address's, as in every mode before. A loggers' definitions are site-block options, so
    each site's (the guard's security logger, its access log) is defined on the domain's block and each handle names
    its own for every request it serves (`log_name`, or `log_skip`); the guard's watched paths and a site's rules
    are its folder's paths, and a watched request carries its folder (`lgsm_folder`) so a ban is shown on the right
    site. A refused request of a banned visitor (`error` runs first) is logged untagged by every logger the block
    maps, as in a block of one site; no jail counts an untagged line. Validate-then-swap is unchanged: the whole
    configuration is checked before it replaces the running one.

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

from panel.services import websites_guard as _wg

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
GATE_HEADER = "X-Panel-Proxy-Token"
ADMIN_SOCKET = "/run/lgsm-web-proxy/admin.sock"
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
                     GATE_HEADER.lower(), "strict-transport-security", "x-content-type-options")
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
XFF = "X-Forwarded-For"
CF_HEADER = "CF-Connecting-IP"
# The header each preset's CDN gives the visitor's address in (see FORWARDED HEADERS above).
PRESET_HEADERS = {"cloudflare": CF_HEADER, "fastly": XFF}


def _canonical(nets):
    """`nets` sorted IPv4 first, without duplicates and without a network another one already holds."""
    parsed = sorted({ipaddress.ip_network(n) for n in nets}, key=lambda n: (n.version, n.network_address, n.prefixlen))
    kept = [n for n in parsed if not any(o != n and o.version == n.version and n.subnet_of(o) for o in parsed)]
    return [str(n) for n in kept]


def _preset_nets(proxy):
    from panel.services import websites_catalog as _wc    # imported here: render's tests need no catalog
    nets = []
    for preset in proxy.presets():
        nets += _wc.preset_ranges(preset)
    return nets


def _own_nets(proxy):
    """The operator's own networks: the ones typed on the card and the list read from an address."""
    return proxy.cidrs() + proxy.url_nets()


def allow_list(proxy):
    """The canonical networks `proxy` admits in 'restricted' mode: the operator's networks plus its presets' ranges."""
    if proxy is None:
        return []
    return _canonical(_own_nets(proxy) + _preset_nets(proxy))


def trusted_list(proxy):
    """The networks whose requests may name the visitor's address: the presets', the operator's when trusted."""
    if proxy is None:
        return []
    return _canonical(_preset_nets(proxy) + (_own_nets(proxy) if proxy.custom_trusted else []))


def client_header(proxy):
    """The header the visitor's address is read from in 'restricted' mode (FORWARDED HEADERS above).

    A preset's own header only while every trusted network is that one CDN's; X-Forwarded-For otherwise.
    """
    headers = {PRESET_HEADERS.get(p, XFF) for p in proxy.presets()}
    if proxy.custom_trusted and _own_nets(proxy):
        headers.add(XFF)
    return headers.pop() if len(headers) == 1 else XFF


# ── custom rules ────────────────────────────────────────────────────────────────────────────────
def _redirect_problem(rule):
    if not (isinstance(rule["from"], str) and _PATH_RE.match(rule["from"])):
        return "A redirect starts from a path on the site, like /old-page."
    if not (isinstance(rule["to"], str) and _TARGET_RE.match(rule["to"])):
        return "A redirect goes to a path on the site or an https:// address."
    if isinstance(rule["code"], bool) or rule["code"] not in REDIRECT_CODES:
        return "A redirect's code is 301, 302, 307 or 308."
    return ""


def _header_problem(rule):
    if not (isinstance(rule["name"], str) and _HEADER_NAME_RE.match(rule["name"])):
        return "A header name is letters, digits and hyphens."
    if rule["name"].lower() in PROTECTED_HEADERS:
        return "The %s header is set by the web proxy itself and cannot be changed." % rule["name"]
    value = rule["value"]
    if not (isinstance(value, str) and _HEADER_VALUE_RE.match(value)) or any(c in value for c in '"\\{}'):
        return "A header value is one line of plain characters, without quotes, backslashes or braces."
    return ""


def _deny_problem(rule):
    if not (isinstance(rule["path"], str) and _PATH_RE.match(rule["path"])):
        return "A denied path starts with /, like /private or /backup*."
    return ""


_RULE_SHAPES = {"redirect": ({"type", "from", "to", "code"}, _redirect_problem),
                "header": ({"type", "name", "value"}, _header_problem),
                "deny": ({"type", "path"}, _deny_problem)}


def _rule_problem(rule):
    """Why one custom rule is refused, or ""."""
    shape = _RULE_SHAPES.get(rule.get("type")) if isinstance(rule, dict) else None
    if shape is None or set(rule) != shape[0]:
        return "Each rule is a redirect (from, to, code), a header (name, value) or a denied path."
    return shape[1](rule)


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


def _served(site, mode="public"):
    """The site's address rows the proxy serves: verified, valid, primary first.

    In tunnel mode every valid domain of the site, checked or not: its DNS points at the tunnel's provider, never
    at this host, so no check could ever pass. The tunnel is the only way in (the proxy listens on the loopback
    and asks for no certificate), and it reaches only the names the operator routes to it in the provider's
    dashboard; a domain is still unique across sites and never the panel's own name (websites_domains).
    """
    rows = sorted(site.domains or [], key=lambda d: (not d.is_primary, d.id or 0))
    return [d for d in rows if (mode == "tunnel" or d.verified_at is not None) and _DOMAIN_RE.match(d.domain or "")]


def _path(row):
    """A served row's folder ("" for a whole domain, and for a row of a version before folders)."""
    return getattr(row, "path", "") or ""


def _domains(site, mode="public"):
    """The names of the site's domains the proxy serves (_served) under exposure mode `mode`."""
    return [d.domain for d in _served(site, mode)]


def site_domains(site, mode="public"):
    """The addresses render() serves for `site` once it is online under exposure mode `mode` (example.org/forums): [] means none."""
    return [d.domain + _path(d) for d in _served(site, mode)]


def _admin_line(opts):
    """The admin API's line: on the owner-only unix socket while the page cache is on (its purge), else off."""
    return "\tadmin unix/%s|0200" % ADMIN_SOCKET if opts["cache_build"] else "\tadmin off"


def cert_source(domain):
    """(file stem, chain PEM, encrypted key) of the operator's certificate the proxy serves `domain` with, or None.

    A domain on its site's certificate (cert_mode 'site') names the site's one pair, under the stem site-<id> (a
    domain always holds a dot, so no domain's own stem is ever one); a domain with a certificate of its own ('own',
    pasted before sites had one) names its own, under its name. Only a verified domain is served at all.
    """
    if domain.verified_at is None:
        return None
    site = getattr(domain, "website", None) if domain.cert_mode == "site" else None
    if site is not None and site.own_cert_pem and site.own_key_secret:
        return "site-%d" % site.id, site.own_cert_pem, site.own_key_secret
    if domain.cert_mode == "own" and domain.own_cert_pem and domain.own_key_secret:
        return domain.domain, domain.own_cert_pem, domain.own_key_secret
    return None


def own_cert(domain):
    """Whether the proxy serves `domain` (a WebsiteDomain) with the operator's own certificate files.

    The same test (cert_source) decides the configuration's `tls <file> <file>` line and the files
    website-proxy-apply is sent (ssh_manager.websites.apply_doc), so a configuration never names a file that is
    not shipped.
    """
    return cert_source(domain) is not None


def _cert_groups(site, skip=()):
    """[(names, certificate file stem or None)]: one site block per certificate source.

    The automatic names share one block, and so do the names on the site's own certificate; a name with a
    certificate of its own gets a block of its own. A block's `tls <cert> <key>` line covers every name in it
    and turns automatic certificates off for all of them. Blocks come in the order of their first name, the
    primary first. Not used in tunnel mode, where the tunnel's provider holds the certificate and every name
    shares one plain-HTTP block.
    """
    groups, by_stem = [], {}
    for d in _served(site):
        if d.domain in skip:
            continue        # a domain with a site in a folder: its own block (_folder_block)
        src = cert_source(d)
        stem = src[0] if src else None
        if stem not in by_stem:
            by_stem[stem] = []
            groups.append((by_stem[stem], stem))
        by_stem[stem].append(d.domain)
    return groups


def _global(mode, opts, proxy, trusted):
    lines = ["{", _admin_line(opts), "\tpersist_config off", "\tgrace_period 10s", "\tstorage file_system %s" % STORAGE]
    if _wg.enabled(proxy):
        lines.append("\torder error first")        # a banned visitor's 403 before the page cache or a redirect
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
        lines += ["\torder cache before rewrite", "\tcache {", "\t\tttl 300s", "\t\tapi {", "\t\t\tsouin", "\t\t}", "\t}"]
    lines += ["\tservers {", "\t\tprotocols h1 h2",
              "\t\ttimeouts {", "\t\t\tread_header 10s", "\t\t\tread_body 60s", "\t\t\twrite 120s", "\t\t\tidle 2m",
              "\t\t}"]
    if trusted:
        lines.append("\t\ttrusted_proxies static %s" % " ".join(trusted))
        if mode == "tunnel" or client_header(proxy) == CF_HEADER:
            lines.append("\t\tclient_ip_headers %s" % CF_HEADER)
        else:
            lines += ["\t\tclient_ip_headers %s" % XFF, "\t\ttrusted_proxies_strict"]
    lines += ["\t}", "}", ""]
    return lines


def _hsts(opts):
    value = "max-age=%d" % opts["hsts_max_age"]
    if opts["hsts_subdomains"]:
        value += "; includeSubDomains"
    if opts["hsts_preload"] and opts["hsts_subdomains"]:
        value += "; preload"
    return value


def _tls_lines(stem, opts, proxy):
    """A site block's `tls` block: protocols, the certificate files named `stem` (None: automatic), the CDN's one."""
    inner = ["\t\tprotocols tls%s tls1.3" % opts["tls_min"]] if opts["tls_min"] != "1.3" else ["\t\tprotocols tls1.3"]
    if proxy is not None and proxy.origin_pull_mtls:
        inner += ["\t\tclient_auth {", "\t\t\tmode require_and_verify", "\t\t\ttrust_pool file %s" % ORIGIN_PULL_CA,
                  "\t\t}"]
    head = "\ttls {"
    if stem is not None:
        head = "\ttls %s/%s.crt %s/%s.key {" % (CERT_DIR, stem, CERT_DIR, stem)
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


def _in_folder(prefix, path):
    """A site's own path (a rule's, a watched one) as the proxy sees it: under the site's folder `prefix` ("" at a root)."""
    return prefix + path if prefix and path.startswith("/") else path


def _rule_lines(site, prefix=""):
    lines = []
    for i, rule in enumerate(_rules(site)):
        if rule["type"] == "deny":
            lines += ["\t@deny%d path %s" % (i, _in_folder(prefix, rule["path"])), "\trespond @deny%d 404" % i]
        elif rule["type"] == "redirect":
            lines.append("\tredir %s %s %d" % (_in_folder(prefix, rule["from"]), _quote(_in_folder(prefix, rule["to"])),
                                                 rule["code"]))
    return lines


def _cache_lines(site, opts, prefix=""):
    if not (opts["cache_build"] and site.page_cache):
        return []
    ttl = max(10, min(int(site.page_cache_ttl or 300), 86400))
    # The cache module puts its default_cache_control, empty unless set, on a response whose site sent no
    # Cache-Control: every such page went out with an empty `Cache-Control:` header. Setting a default would change
    # what the module stores (it reads a missing header as public), so the empty header alone is taken away, as the
    # response leaves; a site's own value, WordPress's no-cache for a signed-in visitor among them, is left as sent.
    return ["\t@pagecache {", "\t\tmethod GET HEAD", "\t\tnot header_regexp Cookie %s" % _quote(CACHE_BYPASS_COOKIES),
            "\t\tnot path %s" % " ".join(_in_folder(prefix, p) for p in CACHE_BYPASS_PATHS), "\t}",
            "\tcache @pagecache {", "\t\tttl %ds" % ttl, "\t}",
            "\theader {", "\t\t-Cache-Control", '\t\tmatch header Cache-Control ""', "\t}"]


def _log_lines(site, name=None):
    if not site.access_log:
        return []
    return ["\tlog %s {" % name if name else "\tlog {", "\t\toutput stderr", "\t\tformat filter {", "\t\t\twrap json",
            "\t\t\trequest>remote_ip ip_mask {", "\t\t\t\tipv4 24", "\t\t\t\tipv6 48", "\t\t\t}",
            "\t\t\trequest>client_ip ip_mask {", "\t\t\t\tipv4 24", "\t\t\t\tipv6 48", "\t\t\t}",
            "\t\t\trequest>headers delete", "\t\t\tresp_headers delete", "\t\t}", "\t}"]


def _snippet_lines(site):
    if not site.raw_proxy_snippet or snippet_problems(site.raw_proxy_snippet):
        return []
    return ["\t# the superadmin's own lines for this site"] + [
        "\t" + ln for ln in site.raw_proxy_snippet.strip("\n").split("\n")]


def _deny_paths(site):
    return [r["path"] for r in _rules(site) if r["type"] == "deny"]


def _log_routing(site, guard, block, folder):
    """The lines that log a request of a site in a folder block, or define its logger in a block of its own.

    In a block of its own, the access logger (named while the guard is on, which routes each request itself). In a
    folder block the loggers are the block's (_folder_loggers): with the guard on its lines name them; off, every
    request is named to the site's access logger, or skipped when the site has none.
    """
    if not folder:
        return _log_lines(site, _wg.access_name(site.id, block) if guard else None)
    if guard:
        return []
    return ["\tlog_name %s" % _wg.access_name(site.id, block)] if site.access_log else ["\tlog_skip"]


def _site_body(site, opts, mode, token, guard, block, prefix="", folder=False):
    """A site block's body, or (`folder`) a handle's in a folder block, without its closing brace.

    With the guard on (`guard`), its lines first. `prefix` is the site's folder: its rules', the guard's and the
    page cache's paths are under it.
    """
    body = _wg.guard_lines(site.id, block, _deny_paths(site), bool(site.access_log), prefix=prefix,
                           logger=not folder) if guard else []
    body += ["\tencode zstd gzip", "\trequest_body {", "\t\tmax_size %dMB" % max(1, int(site.max_body_mb or 1)), "\t}"]
    body += (_header_lines(site, opts, mode) + _rule_lines(site, prefix) + _cache_lines(site, opts, prefix)
             + _log_routing(site, guard, block, folder) + _snippet_lines(site))
    return body + ["\treverse_proxy 127.0.0.1:%d {" % int(site.port),
                   "\t\theader_up %s %s" % (GATE_HEADER, _quote(token)),
                   "\t\ttransport http {", "\t\t\tdial_timeout 5s", "\t\t\tresponse_header_timeout 120s", "\t\t}",
                   "\t}"]


def _token_of(site, secret_of):
    """The site's proxy token in clear when the site can be served (a port and a token of its shape), else ""."""
    token = secret_of(site) or ""
    return token if site.port and _TOKEN_RE.match(token) else ""


def _site_lines(site, opts, proxy, mode, token, blocks, skip=()):
    """The blocks of `site`'s whole domains (`skip`: the domains with a site in a folder, written by _folder_block)."""
    names = [n for n in _domains(site, mode) if n not in skip]
    if not names:
        return []
    guard = _wg.enabled(proxy)
    if mode == "tunnel":        # the tunnel's provider holds the certificate: one plain-HTTP block for every name
        return (["# site %s (%s)" % (site.id, site.name), "%s {" % ", ".join("http://%s" % n for n in names)]
                + _site_body(site, opts, mode, token, guard, _next_block(blocks, site)) + ["}", ""])
    lines = []
    for group, stem in _cert_groups(site, skip):
        lines += (["# site %s (%s)" % (site.id, site.name), "%s {" % ", ".join(group)] + _tls_lines(stem, opts, proxy)
                  + _site_body(site, opts, mode, token, guard, _next_block(blocks, site)) + ["}", ""])
    return lines


def _next_block(blocks, site):
    """The next number of `site`'s blocks (its loggers' names are numbered per block, so each is its own)."""
    n = blocks.get(site.id, 0)
    blocks[site.id] = n + 1
    return n


def _folder_entries(served, domain):
    """[(row, site, token)] of `domain`: the folders longest first, then the root. `served` holds every served row."""
    rows = [e for e in served if e[0].domain == domain]
    return sorted(rows, key=lambda e: (not _path(e[0]), -len(_path(e[0])), _path(e[0])))


def _folder_loggers(entries, guard, numbers):
    """The loggers of a folder block's sites, defined on the block (a `log` is a site-block option)."""
    lines = []
    for row, site, _token in entries:
        n = numbers[row.id]
        if guard:
            lines += _wg.security_log("lgsmsec%d_%d" % (site.id, n))
        if site.access_log:
            lines += _log_lines(site, _wg.access_name(site.id, n))
    return lines


def _indented(lines):
    return ["\t" + ln if ln else ln for ln in lines]


def _bare_folder_lines(site, folder):
    """The folder asked for without its slash (/forums): a 308 to /forums/, query kept, before the site sees it.

    The site's own server would answer it with a redirect built from its inside address (Apache's DirectorySlash
    named http://<domain>:8080/forums/). The Location is a path, so the browser keeps the scheme and the host it
    asked; 308 keeps the method and body. A banned visitor's 403 still comes first (`order error first`).
    """
    bare = "@lgsmbare%d" % site.id
    return ["\t\t%s path %s" % (bare, folder), "\t\tredir %s %s/{?query} 308" % (bare, folder)]


def _folder_handles(entries, opts, mode, guard, numbers):
    lines = []
    for row, site, token in entries:
        body = _indented(_site_body(site, opts, mode, token, guard, numbers[row.id], prefix=_path(row), folder=True))
        if _path(row):
            matcher = "@lgsmfolder%d" % site.id
            lines += ["\t# site %s (%s) in %s" % (site.id, site.name, _path(row)),
                      "\t%s path %s %s/*" % (matcher, _path(row), _path(row)), "\thandle %s {" % matcher]
            lines += _bare_folder_lines(site, _path(row)) + body + ["\t}"]
        else:
            lines += ["\t# site %s (%s)" % (site.id, site.name), "\thandle {"] + body + ["\t}"]
    if all(_path(row) for row, _s, _t in entries):
        quiet = ["\t\tlog_skip"] if guard or any(s.access_log for _r, s, _t in entries) else []
        lines += ["\t# no website at the root of this domain", "\thandle {"] + quiet + ["\t\trespond 404", "\t}"]
    return lines


def _folder_block(domain, entries, opts, proxy, mode, blocks):
    """The block of a domain that has a site in a folder: a handle per site, the longest folder first (SITES IN FOLDERS)."""
    guard = _wg.enabled(proxy)
    numbers = {row.id: _next_block(blocks, site) for row, site, _t in entries}
    if mode == "tunnel":
        head = ["# domain %s (websites in folders)" % domain, "http://%s {" % domain]
    else:
        root = next((row for row, _s, _t in entries if not _path(row)), None)
        src = cert_source(root if root is not None else min((r for r, _s, _t in entries), key=lambda r: r.id or 0))
        head = (["# domain %s (websites in folders)" % domain, "%s {" % domain]
                + _tls_lines(src[0] if src else None, opts, proxy))
    return head + _folder_loggers(entries, guard, numbers) + _folder_handles(entries, opts, mode, guard, numbers) + ["}", ""]


def _live(sites, secret_of):
    """[(site, its token in clear)] of the enabled sites that can be served, by id."""
    out = []
    for site in sorted(sites, key=lambda s: s.id or 0):
        token = _token_of(site, secret_of) if site.enabled else ""
        if token:
            out.append((site, token))
    return out


def _site_blocks(sites, opts, proxy, mode, secret_of):
    """Every site block: each site's whole domains, then each domain with a site in a folder (one block per domain)."""
    live = _live(sites, secret_of)
    served = [(d, s, t) for s, t in live for d in _served(s, mode)]
    shared = sorted({d.domain for d, _s, _t in served if _path(d)})
    lines, blocks = [], {}
    for site, token in live:
        lines += _site_lines(site, opts, proxy, mode, token, blocks, set(shared))
    for domain in shared:
        lines += _folder_block(domain, _folder_entries(served, domain), opts, proxy, mode, blocks)
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
    trusted = {"restricted": trusted_list(proxy), "tunnel": ["127.0.0.1/32", "::1/128"]}.get(mode, [])
    lines = ["# Written by linuxgsm-panel from its database: the panel rewrites this file; edits are lost.", ""]
    lines += _global(mode, opts, proxy, trusted)
    lines += _site_blocks(sites, opts, proxy, mode, secret_of)
    quiet = ["\tlog_skip"] if _wg.enabled(proxy) else []      # the guard's loggers never see a catch-all's request
    if mode != "tunnel":
        # A request over HTTPS whose Host is none of the names above (a served certificate's name, any Host):
        # aborted too, never Caddy's empty 200 with its Server header.
        lines += ["# Any other Host over HTTPS: the request is aborted.", "https:// {"] + quiet + ["\tabort", "}", ""]
    lines += ["# Any other name, and the bare address: the connection is closed.", "http:// {"] + quiet + ["\tabort", "}", ""]
    return "\n".join(lines)


_SITE_MARK_RE = re.compile(r"\s*# site ([0-9]+) \(")
_CACHE_TTL_RE = re.compile(r"\s*ttl ([0-9]+)s\Z")


def cached_sites(text):
    """{site id: ttl seconds} of the sites whose block in the rendered configuration `text` has the page cache.

    Read from what render() wrote, so the answer is what the proxy really runs: a site's page cache turned on while
    the proxy has no cache module is left out of the configuration, and so out of this.
    """
    out, site, in_cache = {}, None, False
    for line in (text or "").split("\n"):
        m = _SITE_MARK_RE.match(line)
        if m:
            site, in_cache = int(m.group(1)), False
        elif line.strip() == "cache @pagecache {":
            in_cache = True
        elif in_cache and site is not None:
            t = _CACHE_TTL_RE.match(line)
            if t:
                out[site] = int(t.group(1))
            in_cache = False
    return out


def served_domains(sites):
    """Every domain render() serves for `sites`, sorted, each once (what the certificate probe asks about)."""
    return sorted({d for s in sites if s.enabled for d in _domains(s)})
