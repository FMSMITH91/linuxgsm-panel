"""The Websites tab's tables: a site, its domains, its host's web proxy, and the group grant.

Kept apart from models.py (which imports them back, so `from panel.db.models import Website` works) only
for size. The tenant rule they carry is websites_access's: a site is reached through group_websites and
nothing else. Every value a shell, the proxy or the firewall will read is held to its shape here too, so
no code path can store a name, account, port, domain or network the routes would have refused.
"""
import json

from sqlalchemy.orm import validates

from panel.core.clock import utcnow
from panel.core.validation import (WEBSITE_ACCOUNT_RE, WEBSITE_ALLOW_PRESETS, WEBSITE_APP_PORT_MIN,
                                   WEBSITE_APP_RECIPE_RE, WEBSITE_APP_VERSION_RE, WEBSITE_COMMAND_MAX,
                                   WEBSITE_EXPOSURE_MODES, WEBSITE_KINDS,
                                   WEBSITE_PHP_VERSION_RE, WEBSITE_PORT_MAX, WEBSITE_PORT_MIN,
                                   WEBSITE_RUNTIME_RE, WEBSITE_RUNTIME_VERSION_RE, WEBSITE_STATES,
                                   WEBSITE_TUNNEL_PROVIDERS, website_cidr, website_domain,
                                   website_folder, website_name_problem)
from panel.db.sqla import db

# Association table: group -> websites (panel/services/websites_access.py). THE tenant concept: a
# customer is a user in a customer group (Group.is_customer) that has their sites here. Nothing else
# grants a site: no host grant and no owner column reaches one.
group_websites = db.Table(
    "group_websites",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("website_id", db.Integer, db.ForeignKey("website.id"), primary_key=True),
)


def _website_choice(key, value, allowed):
    """A @validates body: `value` if it is one of `allowed`, else ValueError naming the field."""
    if value not in allowed:
        raise ValueError("%s must be one of %s, got %r" % (key, ", ".join(allowed), value))
    return value


def _website_json(key, value, shape):
    """A @validates body: `value` if it is JSON text of `shape` (dict or list), else ValueError."""
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        parsed = None
    if not isinstance(parsed, shape):
        raise ValueError("%s must be a JSON %s" % (key, "object" if shape is dict else "list"))
    return value


class Website(db.Model):
    """One website the panel runs: a rootless container under its own account (ws<id>) on one host.

    The tenant boundary is `groups` (group_websites): websites_access.site_for is the one access check,
    and a site nobody may see answers 404 exactly like one that does not exist. `account` and `port`
    are the panel's own choices, set once the id is known, and held to their shapes here so no code
    path can store a name or port a shell command would misread. `proxy_secret` is the token the web
    proxy adds to every request so the container can refuse anyone reaching its loopback port
    directly; encrypted with encrypt_secret (at_rest.SECRET_COLUMNS) and never shown.
    A host removed takes its sites' rows with it (_register_website_cleanup).
    """

    __tablename__ = "website"
    # AUTOINCREMENT: a page, an audit row or a group grant holding a removed site's id must never
    # reach a new site.
    __table_args__ = (db.UniqueConstraint("remote_id", "name", name="uq_website_remote_name"),
                      db.UniqueConstraint("remote_id", "account", name="uq_website_remote_account"),
                      db.UniqueConstraint("remote_id", "port", name="uq_website_remote_port"),
                      {"sqlite_autoincrement": True})
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, db.ForeignKey("remote_server.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    name = db.Column(db.String(32), nullable=False)
    kind = db.Column(db.String(16), nullable=False, default="static")
    account = db.Column(db.String(16), nullable=True)          # ws<id>, set once the id is known
    port = db.Column(db.Integer, nullable=True)                # 127.0.0.1:<port> on the host
    state = db.Column(db.String(12), nullable=False, default="creating")
    state_reason = db.Column(db.String(200), default="")       # why it is `failed`, in plain words
    enabled = db.Column(db.Boolean, default=False, nullable=False)   # served by the web proxy
    image_key = db.Column(db.String(32), default="")
    image_digest = db.Column(db.String(200), default="")
    proxy_secret = db.Column(db.Text, default="")              # encrypt_secret(token)
    mem_mb = db.Column(db.Integer, default=512, nullable=False)
    cpu_milli = db.Column(db.Integer, default=1000, nullable=False)
    pids = db.Column(db.Integer, default=256, nullable=False)
    disk_mb = db.Column(db.Integer, default=2048, nullable=False)
    max_body_mb = db.Column(db.Integer, default=64, nullable=False)
    access_log = db.Column(db.Boolean, default=False, nullable=False)   # off by default: privacy
    # Outbound network for the container: off for every kind; WordPress reaches only its update
    # hosts unless this per-site switch (superadmin, warned) gives it the internet. Never the host's
    # own addresses either way (the egress guard).
    full_egress = db.Column(db.Boolean, default=False, nullable=False)
    backup_keep = db.Column(db.Integer, default=7, nullable=False)
    backup_schedule = db.Column(db.String(64), default="")
    customer_note = db.Column(db.Text, default="")             # admins only
    # PHP (the php, wordpress and phpbb kinds): the version (one the signed catalog pins, "" for a
    # static site), the form's php.ini values as a JSON object, and the site's own "Advanced php.ini"
    # text. All validated before they are written to the site's conf.d; the panel's hardening lines
    # always follow them there.
    php_version = db.Column(db.String(8), default="")
    php_settings = db.Column(db.Text, default="{}")
    php_ini_custom = db.Column(db.Text, default="")
    # Performance: OPcache (on for PHP kinds), a per-site object cache container (off; its password
    # is object_cache_secret, encrypt_secret), the proxy's page cache (off) and its TTL in seconds,
    # long cache headers and compression for static files (on).
    opcache = db.Column(db.Boolean, default=True, nullable=False)
    object_cache = db.Column(db.Boolean, default=False, nullable=False)
    object_cache_secret = db.Column(db.Text, default="")
    page_cache = db.Column(db.Boolean, default=False, nullable=False)
    page_cache_ttl = db.Column(db.Integer, default=300, nullable=False)
    static_cache = db.Column(db.Boolean, default=True, nullable=False)
    # Per-site proxy rules from the form (redirects, extra headers, denied paths) as a JSON list, and a
    # raw proxy snippet only a superadmin may set; both are validated by the proxy before they apply.
    custom_rules = db.Column(db.Text, default="[]")
    raw_proxy_snippet = db.Column(db.Text, default="")
    # A runtime app (kind "app"): the runtime and version (catalog entries, e.g. "node" and "22"), the
    # install/build and start commands run INSIDE the container as the site's account, the port the app
    # listens on in there, and its environment variables (a JSON object, encrypt_secret, written to a
    # 0600 file; never on argv, never logged). Empty: the catalog's defaults for the runtime.
    runtime = db.Column(db.String(16), default="")
    runtime_version = db.Column(db.String(16), default="")
    build_command = db.Column(db.Text, default="")
    start_command = db.Column(db.Text, default="")
    app_port = db.Column(db.Integer, nullable=True)
    env_enc = db.Column(db.Text, default="")
    # A one-click app (WordPress, phpBB, ...): the signed catalog's recipe and the version installed.
    # The install runs as a job of steps; install_step is the one running (or the one that failed) and
    # install_steps_done the JSON list of steps finished, so a failure, or a panel restarted mid-install,
    # can undo exactly those and leave no half-installed site. The generated admin password is shown
    # once and never stored.
    # The site's own certificate (Domains tab, "Certificate"): the chain once (public) and its private key once
    # (encrypt_secret, at_rest.SECRET_COLUMNS, never shown again). Each domain it covers uses it (WebsiteDomain
    # cert_mode 'site'); "" while the site's domains get automatic certificates.
    own_cert_pem = db.Column(db.Text, default="")
    own_key_secret = db.Column(db.Text, default="")
    app_recipe = db.Column(db.String(32), default="")
    app_version = db.Column(db.String(32), default="")
    install_step = db.Column(db.String(32), default="")
    install_steps_done = db.Column(db.Text, default="[]")
    install_started_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    created_by = db.Column(db.String(80), default="")
    remote = db.relationship("RemoteServer")
    groups = db.relationship("Group", secondary=group_websites, back_populates="websites")
    domains = db.relationship("WebsiteDomain", back_populates="website", cascade="all, delete-orphan",
                              order_by="WebsiteDomain.id")

    @validates("name")
    def _v_name(self, key, value):
        problem = website_name_problem(value)
        if problem:
            raise ValueError("%s: %s" % (key, problem))
        return value

    @validates("kind")
    def _v_kind(self, key, value):
        return _website_choice(key, value, WEBSITE_KINDS)

    @validates("state")
    def _v_state(self, key, value):
        return _website_choice(key, value, WEBSITE_STATES)

    @validates("account")
    def _v_account(self, key, value):
        if value is not None and not (isinstance(value, str) and WEBSITE_ACCOUNT_RE.match(value)):
            raise ValueError("%s must be ws<digits>, got %r" % (key, value))
        return value

    @validates("port")
    def _v_port(self, key, value):
        if value is not None and not (isinstance(value, int) and not isinstance(value, bool)
                                      and WEBSITE_PORT_MIN <= value <= WEBSITE_PORT_MAX):
            raise ValueError("%s must be %d-%d, got %r" % (key, WEBSITE_PORT_MIN, WEBSITE_PORT_MAX, value))
        return value

    @validates("php_version")
    def _v_php_version(self, key, value):
        if not isinstance(value, str) or not WEBSITE_PHP_VERSION_RE.match(value):
            raise ValueError("%s must be '' or <major>.<minor>, got %r" % (key, value))
        return value

    @validates("runtime", "runtime_version")
    def _v_runtime(self, key, value):
        pattern = WEBSITE_RUNTIME_RE if key == "runtime" else WEBSITE_RUNTIME_VERSION_RE
        if not isinstance(value, str) or not pattern.match(value):
            raise ValueError("%s has a shape the catalog never uses: %r" % (key, value))
        return value

    @validates("build_command", "start_command")
    def _v_command(self, key, value):
        if not isinstance(value, str) or len(value) > WEBSITE_COMMAND_MAX or any(c in value for c in "\x00\r\n"):
            raise ValueError("%s must be one line of at most %d characters" % (key, WEBSITE_COMMAND_MAX))
        return value

    @validates("app_port")
    def _v_app_port(self, key, value):
        if value is not None and not (isinstance(value, int) and not isinstance(value, bool)
                                      and WEBSITE_APP_PORT_MIN <= value <= 65535):
            raise ValueError("%s must be %d-65535, got %r" % (key, WEBSITE_APP_PORT_MIN, value))
        return value

    @validates("app_recipe", "app_version")
    def _v_app(self, key, value):
        pattern = WEBSITE_APP_RECIPE_RE if key == "app_recipe" else WEBSITE_APP_VERSION_RE
        if not isinstance(value, str) or not pattern.match(value):
            raise ValueError("%s has a shape the catalog never uses: %r" % (key, value))
        return value

    @validates("install_steps_done")
    def _v_steps_done(self, key, value):
        return _website_json(key, value, list)

    @validates("php_settings")
    def _v_php_settings(self, key, value):
        return _website_json(key, value, dict)

    @validates("custom_rules")
    def _v_custom_rules(self, key, value):
        return _website_json(key, value, list)

    @property
    def primary_domain(self):
        """The domain marked primary, else the first one, else None."""
        rows = list(self.domains or [])
        return next((d for d in rows if d.is_primary), rows[0] if rows else None)

    @property
    def base_path(self):
        """The folder the site lives in ("/forums"), or "" at the root of its domains: every address has the same one."""
        dom = self.primary_domain
        return dom.path if dom is not None and dom.path else ""


class WebsiteDomain(db.Model):
    """One address a website serves: a domain, and the folder of it the site lives in ("" for the whole domain).

    (domain, path) is globally unique: no two sites, on any host, share an address. A domain may be held by several
    sites of one host, at most one at its root and the others each in a folder none of the others' folders holds
    (website_folders checks that, and that every address of a site has the same folder: the site's app is told one
    base path).

    Held to validation.website_domain here as well as in the routes, so no path can store an IP
    literal, a wildcard or a reserved name. dns_state / cert_state are what the last check found
    (unchecked|matching|mismatch|private|failed and pending|issued|failed); cert_error is a short
    reason, never a whole log. cert_mode 'site' is the site's own certificate (Website.own_cert_pem and
    own_key_secret, stored once for every domain it covers). 'own' is a certificate pasted for this domain
    alone, before a site had one (data migration 5 moved those to their site where it could); own_key_secret
    holds its private key (encrypt_secret, at_rest.SECRET_COLUMNS).
    """

    __tablename__ = "website_domain"
    __table_args__ = (db.UniqueConstraint("domain", "path", name="uq_website_domain_address"),
                      {"sqlite_autoincrement": True})
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey("website.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    domain = db.Column(db.String(253), nullable=False)
    # The folder ("/forums"; validation.website_folder), "" for the whole domain.
    path = db.Column(db.String(64), nullable=False, default="", server_default="")
    is_primary = db.Column(db.Boolean, default=False, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    last_check_at = db.Column(db.DateTime, nullable=True)
    dns_state = db.Column(db.String(12), default="unchecked")
    dns_cdn = db.Column(db.String(20), default="")               # the CDN preset a 'cdn' state goes through
    cert_state = db.Column(db.String(12), default="pending")
    cert_not_after = db.Column(db.DateTime, nullable=True)
    cert_error = db.Column(db.String(200), default="")
    cert_mode = db.Column(db.String(8), default="acme")          # 'acme' | 'site' | 'own'
    own_cert_pem = db.Column(db.Text, default="")                # a certificate chain is public
    own_key_secret = db.Column(db.Text, default="")              # encrypt_secret(private key PEM)
    created_at = db.Column(db.DateTime, default=utcnow)
    created_by = db.Column(db.String(80), default="")
    website = db.relationship("Website", back_populates="domains")

    @validates("domain")
    def _v_domain(self, key, value):
        clean = website_domain(value)
        if clean is None or clean != value:
            raise ValueError("%s must be a lowercase public domain name, got %r" % (key, value))
        return value

    @validates("path")
    def _v_path(self, key, value):
        if value is None or website_folder(value) != value:
            raise ValueError("%s must be '' or a folder like /forums, got %r" % (key, value))
        return value

    @validates("cert_mode")
    def _v_cert_mode(self, key, value):
        return _website_choice(key, value, ("acme", "own", "site"))

    @property
    def address(self):
        """The address as visitors type it: the domain, and its folder when it has one (example.org/forums)."""
        return (self.domain or "") + (self.path or "")


class WebsiteProxy(db.Model):
    """The web proxy on one host: how its sites are reached, and what the panel last applied.

    exposure_mode 'public' opens 80/443 to everyone while a site is enabled; 'restricted' opens them
    only to `allow_cidrs` plus the networks of `allow_presets` (the catalog's CDN ranges), and
    the proxy trusts a client-address header only from the presets' networks, and from `allow_cidrs`
    and the list read from `allow_url` only when `custom_trusted` is on; 'tunnel' opens nothing and connects out
    with `tunnel_token_enc` (encrypt_secret, at_rest.SECRET_COLUMNS; never logged, never on argv).
    allow_cidrs / allow_presets are JSON lists, written only through validation.website_cidr and
    WEBSITE_ALLOW_PRESETS. Settings that are the same for every host (HSTS, TLS minimum, ACME contact)
    live in config.json, not here. A host removed takes its row with it.
    """

    __tablename__ = "website_proxy"
    __table_args__ = {"sqlite_autoincrement": True}
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, db.ForeignKey("remote_server.id", ondelete="CASCADE"),
                          unique=True, nullable=False)
    exposure_mode = db.Column(db.String(12), default="public", nullable=False)
    allow_cidrs = db.Column(db.Text, default="[]")
    allow_presets = db.Column(db.Text, default="[]")
    tunnel_provider = db.Column(db.String(16), default="")
    tunnel_token_enc = db.Column(db.Text, default="")
    origin_pull_mtls = db.Column(db.Boolean, default=False, nullable=False)
    # Whether the operator's own networks are trusted proxies: their requests may give the visitor's address in
    # X-Forwarded-For. Off, they are allow-only (services/websites_proxy.py, FORWARDED HEADERS).
    custom_trusted = db.Column(db.Boolean, default=False, nullable=False)
    # A list of networks read from an https address (services/websites_allow_url.py): the address, the last good
    # list (JSON, canonical networks), when it was read, and why the last try failed ("" when it did not).
    allow_url = db.Column(db.String(500), default="", nullable=False)
    allow_url_nets = db.Column(db.Text, default="[]")
    allow_url_at = db.Column(db.DateTime, nullable=True)
    allow_url_error = db.Column(db.String(300), default="")
    # Blocked visitors (services/websites_guard): the jails' numbers, the ban times and the allow list, as JSON.
    guard = db.Column(db.Text, default="{}")
    installed_version = db.Column(db.String(40), default="")
    applied_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.String(200), default="")

    @validates("exposure_mode")
    def _v_exposure(self, key, value):
        return _website_choice(key, value, WEBSITE_EXPOSURE_MODES)

    @validates("tunnel_provider")
    def _v_tunnel(self, key, value):
        return _website_choice(key, value, WEBSITE_TUNNEL_PROVIDERS)

    @validates("allow_cidrs")
    def _v_cidrs(self, key, value):
        rows = json.loads(value or "[]")
        if not isinstance(rows, list) or any(not isinstance(c, str) or website_cidr(c) != c for c in rows):
            raise ValueError("%s must be a JSON list of canonical networks" % key)
        return value

    @validates("allow_presets")
    def _v_presets(self, key, value):
        rows = json.loads(value or "[]")
        if not isinstance(rows, list) or any(p not in WEBSITE_ALLOW_PRESETS for p in rows):
            raise ValueError("%s must be a JSON list of %s" % (key, ", ".join(WEBSITE_ALLOW_PRESETS)))
        return value

    def cidrs(self):
        """The allow list as a list of canonical network strings."""
        return list(json.loads(self.allow_cidrs or "[]"))

    def presets(self):
        """The allow-list presets as a list of names."""
        return list(json.loads(self.allow_presets or "[]"))

    @validates("allow_url_nets")
    def _v_url_nets(self, key, value):
        return self._v_cidrs(key, value)

    def url_nets(self):
        """The last good list read from `allow_url`, as canonical network strings."""
        return list(json.loads(self.allow_url_nets or "[]"))


# ── data migration 5 (models._DATA_MIGRATIONS) ─────────────────────────────────────────────────────
def _most_held(doms):
    """The chain most of `doms` hold (the first such domain's on a tie)."""
    counts = {}
    for d in doms:
        counts[d.own_cert_pem] = counts.get(d.own_cert_pem, 0) + 1
    best = max(counts.values())
    return next(d.own_cert_pem for d in doms if counts[d.own_cert_pem] == best)


def _own_by_site():
    """{site id: [its domains holding a certificate of their own, by id]}."""
    out = {}
    for d in WebsiteDomain.query.filter(WebsiteDomain.cert_mode == "own").order_by(WebsiteDomain.id).all():
        if d.own_cert_pem and d.own_key_secret:
            out.setdefault(d.website_id, []).append(d)
    return out


def site_certs_from_domains():
    """Migration 5: an own certificate pasted per domain becomes its site's one certificate.

    For each site with domains in cert_mode 'own' and no certificate of its own yet: the chain held by the most of
    those domains (the first such domain on a tie) is stored once on the site, key and all (the ciphertext copied as
    it is), and each domain that held that same chain uses the site's (cert_mode 'site', its own copy cleared). A
    domain that held a different chain keeps it (still served for that domain alone). Safe to repeat: a site that has
    a certificate is skipped, and a domain already on 'site' is no longer 'own'.
    """
    for site_id, doms in _own_by_site().items():
        site = db.session.get(Website, site_id)
        if site is None or site.own_cert_pem:
            continue
        pem = _most_held(doms)
        site.own_cert_pem = pem
        site.own_key_secret = next(d.own_key_secret for d in doms if d.own_cert_pem == pem)
        for d in doms:
            if d.own_cert_pem == pem:
                d.cert_mode, d.own_cert_pem, d.own_key_secret = "site", "", ""
