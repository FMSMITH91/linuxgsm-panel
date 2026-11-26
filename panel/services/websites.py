"""A website's containers on its host: the unit files, server configs and shell the panel runs as the site's account.

WHERE A SITE RUNS
    Under its own account (ws<site id>, made by the helper's website-account-create: home 0700, no login
    shell, subordinate ids, lingering, enrolled in the panel's group first), in rootless Podman, from an
    image pinned by digest in the signed catalog (websites_catalog). Folders in the account's home:
    ~/site/html (the files, the only thing the container may write besides tmpfs), ~/site/backups,
    ~/site/conf (0700: the server config holding the proxy token, php.ini, the object cache's config,
    an app's environment and commands) and ~/panel-websites/site.json (what the panel installed).

THE CONTAINER (OWASP Docker Security Cheat Sheet: rule 2 a user, 3 capabilities, 4 no new
privileges, 5 inter-container connectivity, 7 resources, 8 read-only file system, 11 rootless, 13
images by digest; the same hardening as panel/services/addons.py)
    UserNS=keep-id with the account's own numeric uid and gid (an image's USER wins over keep-id's
    default on Podman 4.9.3), DropCapability=all, NoNewPrivileges, ReadOnly with tmpfs for /tmp and the
    server's run folders, memory with no swap, CPU, pids and open files limited, a start limit, no
    DNS. Its server listens on 8080 inside and is published on 127.0.0.1:<site port> only.

THE PROXY TOKEN
    Every request the web proxy forwards carries X-Panel-Proxy-Token, the site's own secret. The
    site's server answers 403 without it, so another account on the host reaching the loopback port
    directly gets nothing. nginx (static sites, and the gate in front of a runtime app) compares it in
    its config; Apache (PHP kinds) refuses the request in a <Location> <If> that applies after every
    .htaccess, and removes the header before PHP runs. The token lives in ~/site/conf (0600), written
    from stdin, never on a command line.

THE NETWORK (pasta; see addons.network)
    No route out: the container reaches only what pasta forwards to the host's loopback: its database
    (3306 inside) and, for WordPress and an app's build, an egress proxy (3128 inside:
    panel/services/websites_egress.py, run as the account) that connects to a fixed list of hosts on
    443 only. The egress guard (helper verb website-egress-guard) keeps the site's uid off the host's
    other local addresses, which pasta on Ubuntu 24.04 does not. An object cache (Valkey) and a runtime
    app's gate join the site's own network namespace (Network=container:), so they are private to it.
"""
import base64
import json
import re
import shlex
import zoneinfo

from panel.services import addons as _ad

HOME_DIR = "panel-websites"
META_FILE = "site.json"
SITE = "site"
HTML = SITE + "/html"
BACKUPS = SITE + "/backups"
CONF = SITE + "/conf"
QUADLET_DIR = _ad.QUADLET_DIR
USER_UNIT_DIR = _ad.USER_UNIT_DIR
UNIT = "lgsm-site"
CACHE_UNIT = "lgsm-site-cache"
GATE_UNIT = "lgsm-site-gate"
EGRESS_UNIT = "lgsm-site-egress"
DB_RELAY_UNIT = "lgsm-site-db"
TUNNEL_ACCOUNT = "lgsmtunnel"
TUNNEL_UNIT = "lgsm-tunnel"
INNER_PORT = 8080
EGRESS_INNER_PORT = 3128
# Host ports beside the site's own (Website.port, 20000-20999): its egress proxy and its database relay.
EGRESS_PORT_BASE = 22000
DB_RELAY_PORT_BASE = 23000
RESTART_BURST = 5
RESTART_WINDOW = 600
NOFILE = 4096
OBJECT_CACHE_MB = 64
TUNNEL_MEMORY_MB = 256
STOP_TIMEOUT = 20
KINDS_PHP = ("php", "wordpress", "phpbb")
DOCROOT = {"static": "/usr/share/nginx/html", "app": "/app"}
DOCROOT_PHP = "/var/www/html"
GATE_HEADER = "X-Panel-Proxy-Token"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_ACCOUNT_RE = re.compile(r"ws[1-9][0-9]{0,8}\Z")

_MARK_INSTALLED = "SITE_INSTALLED"
_MARK_STARTED = "SITE_STARTED"
_MARK_STOPPED = "SITE_STOPPED"
_MARK_REMOVED = "SITE_REMOVED"
FAIL_MARKS = {
    "SITE_PULL_FAILED": "The site's image could not be downloaded. Check the host's internet connection and try again.",
    "SITE_FILES_REFUSED": "The panel refused to write one of the site's files. Nothing was changed.",
    "SITE_START_LIMIT": "The site was started too often in a short time. Wait ten minutes, then start it again.",
    "SITE_START_FAILED": "The site's container did not start. Its last log lines are below.",
    "SITE_NOT_EMPTY": "The site's folder already holds files, so the app was not unpacked over them.",
    "SITE_SHA_MISMATCH": "The downloaded file did not match the catalog's checksum and was deleted. Nothing was installed.",
    "SITE_DOWNLOAD_FAILED": "The app's release could not be downloaded. Try again later.",
    "SITE_UNPACK_FAILED": "The app's archive could not be unpacked safely, so nothing was kept.",
    "SITE_STEP_FAILED": "An install step failed. Its output is below; the steps already done were undone.",
    "SITE_INSTALLER_LEFT": "The app's installer folder is still there after install, so the site was not made public.",
}

# The account's shell starts here (the addons' _ENV: the user manager's runtime folder, home, cd).
_ENV = _ad._ENV


def _q(text):
    return shlex.quote(text)


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _home(account):
    if not _ACCOUNT_RE.match(account or "") and account != TUNNEL_ACCOUNT:
        raise ValueError("not a website account: %r" % (account,))
    return "/home/%s" % account


def unit_service(name=UNIT):
    """The systemd user service Quadlet generates from the unit `name`."""
    return "%s.service" % name


# ── settings and their checks ───────────────────────────────────────────────────────────────────
def _settings(site):
    try:
        got = json.loads(site.php_settings or "{}")
    except ValueError:
        got = {}
    return got if isinstance(got, dict) else {}


# The form's php.ini values: (key, default, check) where check returns "" or a sentence.
_SIZE_RE = re.compile(r"([1-9][0-9]{0,4})([KMG])\Z")


def _size_mb(text):
    m = _SIZE_RE.match(text or "") if isinstance(text, str) else None
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n / 1024 if unit == "K" else n * 1024 if unit == "G" else n


def _check_size(lo, hi):
    def check(value):
        mb = _size_mb(value)
        if mb is None or not lo <= mb <= hi:
            return "a size like 256M, from %dM to %dM" % (lo, hi)
        return ""
    return check


def _check_int(lo, hi):
    def check(value):
        ok = isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,6}", value) and lo <= int(value) <= hi
        return "" if ok else "a whole number from %d to %d" % (lo, hi)
    return check


def _check_tz(value):
    return "" if isinstance(value, str) and value in zoneinfo.available_timezones() else "a time zone like Europe/Paris"


def _check_onoff(value):
    return "" if value in ("On", "Off") else "On or Off"


PHP_FORM = (
    ("memory_limit", "256M", _check_size(16, 4096)),
    ("upload_max_filesize", "64M", _check_size(1, 4096)),
    ("post_max_size", "64M", _check_size(1, 4096)),
    ("max_execution_time", "60", _check_int(1, 3600)),
    ("max_input_time", "60", _check_int(-1, 3600)),
    ("max_input_vars", "3000", _check_int(100, 100000)),
    ("date.timezone", "UTC", _check_tz),
    ("display_errors", "Off", _check_onoff),
    ("opcache.memory_consumption", "128", _check_int(16, 1024)),
    ("opcache.revalidate_freq", "2", _check_int(0, 3600)),
)
PHP_FORM_KEYS = tuple(k for k, _d, _c in PHP_FORM)


def php_settings_problems(values):
    """What is wrong with the form's php.ini values (a dict of strings), as sentences; [] when none."""
    if not isinstance(values, dict):
        return ["The settings are a set of named values."]
    out = ["%s is not a setting of this form." % k for k in sorted(values) if k not in PHP_FORM_KEYS]
    for key, _default, check in PHP_FORM:
        if key in values:
            why = check(values[key])
            if why:
                out.append("%s must be %s." % (key, why))
    return out


# The panel's defaults (OWASP PHP Configuration Cheat Sheet: error handling, general settings, session
# handling), written before the site's own values so the site may change them...
PHP_DEFAULTS = (
    ("display_startup_errors", "Off"), ("log_errors", "On"), ("error_log", "/proc/self/fd/2"),
    ("html_errors", "Off"), ("allow_url_fopen", "Off"), ("enable_dl", "Off"), ("zend.exception_ignore_args", "On"),
    ("session.use_strict_mode", "1"), ("session.use_only_cookies", "1"), ("session.cookie_httponly", "1"),
    ("session.cookie_secure", "1"), ("session.cookie_samesite", "Lax"),
    ("session.save_path", "/tmp"),  # nosec B108 - the site container's own tmpfs, not the host's /tmp
    ("upload_tmp_dir", "/tmp"),  # nosec B108 - the site container's own tmpfs, not the host's /tmp
)
# ...and the hardening written after everything, which no setting of the site can undo (PHP reads
# the last value of a key; the Advanced editor refuses both keys anyway).
PHP_FORCED = (("expose_php", "Off"), ("allow_url_include", "Off"))
# Keys the Advanced editor refuses: they load code into PHP, run a program, or are the panel's.
PHP_REFUSED = ("extension", "zend_extension", "extension_dir", "sendmail_path", "mail.log", "opcache.preload",
               "opcache.preload_user", "ffi.enable", "ffi.preload", "user_ini.filename", "cgi.fix_pathinfo",
               "doc_root", "user_dir") + tuple(k for k, _v in PHP_FORCED)
# Keys whose value is a path: allowed only inside the site's files or /tmp.
PHP_PATH_KEYS = ("auto_prepend_file", "auto_append_file", "open_basedir", "include_path", "session.save_path",
                 "upload_tmp_dir", "error_log", "opcache.file_cache", "sys_temp_dir")
PHP_INI_MAX = 8192
PHP_INI_LINES = 200
_INI_LINE_RE = re.compile(r"([a-z][a-z0-9_.]{0,63})[ \t]*=[ \t]*(.{0,1024})\Z")
_PATH_OK_RE = re.compile(r"/(?:var/www/html|tmp)(?:/[A-Za-z0-9_.-]{1,64})*\Z")


def _path_value_ok(key, value):
    raw = value.strip().strip('"')
    if key == "error_log" and raw == "/proc/self/fd/2":
        return True
    parts = raw.split(":") if key in ("open_basedir", "include_path") else [raw]
    return all(p == "." or (_PATH_OK_RE.match(p) and "/../" not in p + "/") for p in parts if p)


def _ini_line_problem(key, value):
    if key in PHP_REFUSED:
        return "%s cannot be set here: the panel sets it, or it loads code or runs a program" % key
    if "${" in value or "\x00" in value:
        return "%s: a value may not read the environment" % key
    if key in PHP_PATH_KEYS and not _path_value_ok(key, value):
        return "%s may only name a path inside the site's files (/var/www/html) or /tmp" % key
    return ""


def php_ini_problems(text):
    """What is wrong with an Advanced php.ini text, line by line, as a list of sentences (empty: none)."""
    if not isinstance(text, str):
        return ["The advanced settings are text."]
    if len(text) > PHP_INI_MAX:
        return ["The advanced settings are at most %d characters." % PHP_INI_MAX]
    lines = text.splitlines()
    if len(lines) > PHP_INI_LINES:
        return ["The advanced settings are at most %d lines." % PHP_INI_LINES]
    out = []
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped[0] in ";#":
            continue
        m = _INI_LINE_RE.match(stripped)
        if not m:
            out.append("Line %d: write one setting as key = value." % n)
            continue
        why = _ini_line_problem(m.group(1), m.group(2))
        if why:
            out.append("Line %d: %s." % (n, why))
    return out


def php_ini(site):
    """The site's conf.d/zz-panel.ini text: its form values, its Advanced lines, then the panel's hardening."""
    values = _settings(site)
    lines = ["; Written by linuxgsm-panel for this site. The panel rewrites it.", "; The panel's defaults"]
    lines += ["%s = %s" % kv for kv in PHP_DEFAULTS]
    lines.append("; The site's settings")
    for key, default, check in PHP_FORM:
        if key.startswith("opcache."):
            continue
        value = values.get(key, default)
        lines.append("%s = %s" % (key, value if not check(value) else default))
    lines += _opcache_lines(site, values)
    custom = site.php_ini_custom or ""
    if custom.strip() and not php_ini_problems(custom):
        lines += ["; The site's advanced settings"] + [ln.strip() for ln in custom.splitlines()]
    lines.append("; The panel's hardening: always last, never removable")
    lines += ["%s = %s" % kv for kv in PHP_FORCED]
    return "\n".join(lines) + "\n"


def _opcache_lines(site, values):
    if not site.opcache:
        return ["opcache.enable = 0"]
    form = dict((k, (d, c)) for k, d, c in PHP_FORM)
    mem = values.get("opcache.memory_consumption", form["opcache.memory_consumption"][0])
    freq = values.get("opcache.revalidate_freq", form["opcache.revalidate_freq"][0])
    mem = mem if not form["opcache.memory_consumption"][1](mem) else form["opcache.memory_consumption"][0]
    freq = freq if not form["opcache.revalidate_freq"][1](freq) else form["opcache.revalidate_freq"][0]
    return ["; OPcache", "zend_extension = opcache", "opcache.enable = 1", "opcache.validate_timestamps = 1",
            "opcache.memory_consumption = %s" % mem, "opcache.revalidate_freq = %s" % freq]


def php_effective_sh(account):
    """Shell (as the account) printing the PHP settings in effect inside the site's container, key=value."""
    keys = ",".join("'%s'" % k for k in PHP_FORM_KEYS + tuple(k for k, _v in PHP_FORCED) + ("opcache.enable",))
    code = "foreach([%s] as $k){echo $k,'=',var_export(ini_get($k),true),PHP_EOL;}" % keys
    _home(account)
    return _ENV + "podman exec %s php -r %s" % (UNIT, _q(code))


def parse_effective(out):
    """php_effective_sh's output as {key: value} (quotes of var_export removed)."""
    got = {}
    for line in (out or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in PHP_FORM_KEYS + ("expose_php", "allow_url_include", "opcache.enable"):
            got[key] = value.strip().strip("'")
    return got


# ── the in-container servers ────────────────────────────────────────────────────────────────────
def _token(token):
    if not _TOKEN_RE.match(token or ""):
        raise ValueError("a proxy token is 32-128 URL-safe characters")
    return token


def nginx_conf(token, upstream_port=None):
    """The static site's (or a runtime app's gate's) nginx server block, refusing requests without `token`."""
    _token(token)
    lines = ["# Written by linuxgsm-panel. Requests without the web proxy's token are refused.",
             "server {", "    listen %d;" % INNER_PORT, "    server_name _;", "    server_tokens off;",
             "    absolute_redirect off;", "    client_max_body_size 0;",
             '    if ($http_x_panel_proxy_token != "%s") {' % token, "        return 403;", "    }"]
    if upstream_port is None:
        lines += ["    root %s;" % DOCROOT["static"], "    index index.html index.htm;",
                  "    location ~ /\\. {", "        deny all;", "    }",
                  "    location / {", "        try_files $uri $uri/ =404;", "    }"]
    else:
        lines += ["    location / {", "        proxy_pass http://127.0.0.1:%d;" % int(upstream_port),
                  "        proxy_http_version 1.1;", "        proxy_set_header %s \"\";" % GATE_HEADER,
                  "        proxy_set_header Host $host;", "        proxy_set_header Upgrade $http_upgrade;",
                  '        proxy_set_header Connection "upgrade";',
                  "        proxy_set_header X-Forwarded-For $http_x_forwarded_for;",
                  "        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;",
                  "        proxy_read_timeout 120s;", "    }"]
    return "\n".join(lines + ["}", ""])


def apache_conf(token):
    """The PHP kinds' Apache config: 8080, the token checked after every .htaccess, then removed before PHP."""
    _token(token)
    return "\n".join([
        "# Written by linuxgsm-panel. Requests without the web proxy's token are refused.",
        "Listen %d" % INNER_PORT, "ServerName localhost", "ServerTokens Prod", "ServerSignature Off", "TraceEnable Off",
        "<IfModule !headers_module>", "    LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so",
        "</IfModule>",
        "<VirtualHost *:%d>" % INNER_PORT, "    DocumentRoot %s" % DOCROOT_PHP,
        "    <Directory %s>" % DOCROOT_PHP, "        Options -Indexes +SymLinksIfOwnerMatch", "        AllowOverride All",
        "        Require all granted", "    </Directory>",
        '    <Location "/">', "        <If \"%%{HTTP:%s} != '%s'\">" % (GATE_HEADER, token),
        "            Require all denied", "        </If>", "    </Location>",
        "    RequestHeader unset %s" % GATE_HEADER,
        "    ErrorLog /proc/self/fd/2", "    CustomLog /dev/null common", "</VirtualHost>", ""])


APACHE_PORTS = "# Written by linuxgsm-panel: the site's server listens in apache_conf.\n"


def valkey_conf(password):
    """The object cache's config: loopback in the site's namespace, a password, no persistence, a memory cap."""
    if not _TOKEN_RE.match(password or ""):
        raise ValueError("an object cache password is 32-128 URL-safe characters")
    return "\n".join([
        "# Written by linuxgsm-panel: this site's private object cache.", "bind 127.0.0.1 -::1", "port 6379",
        "protected-mode yes", "requirepass %s" % password, 'save ""', "appendonly no",
        "maxmemory %dmb" % OBJECT_CACHE_MB, "maxmemory-policy allkeys-lru", "enable-debug-command no",
        "enable-module-command no", "enable-protected-configs no", "dir /tmp", ""])


# ── the units ───────────────────────────────────────────────────────────────────────────────────
def _limits(site, cpu=True):
    """The container's podman limits; --cpus only where the host delegates the cpu controller (`cpu`)."""
    out = ["--memory=%dm" % int(site.mem_mb), "--memory-swap=%dm" % int(site.mem_mb)]
    out += ["--cpus=%.2f" % (int(site.cpu_milli) / 1000.0)] if cpu else []
    out += ["--stop-timeout=%d" % STOP_TIMEOUT]
    return out if site.full_egress else out + ["--dns=none"]


# Where a site's CPU limit is enforced (the site card and docs say which, never silently none):
#   container: --cpus on the container (the account's user manager has the cpu controller);
#   account:   the host does not delegate it, so the helper's website-cpu-limit sets CPUQuota and
#              CPUWeight on the account's whole user slice (its site, cache and gate together);
#   none:      neither could be set.
CPU_MODES = {
    "container": "CPU limit: applied to the website's container.",
    "account": ("CPU limit: this host does not let the website's account limit its own containers, so the panel "
                "limits the whole account (its share and its quota) instead."),
    "none": "CPU limit: this host allows no CPU limit for websites, so this website runs without one.",
}


def _hardening(ids, pids):
    return ["UserNS=keep-id", "User=%d" % int(ids[0]), "Group=%d" % int(ids[1]), "ReadOnly=true",
            "DropCapability=all", "NoNewPrivileges=true", "PidsLimit=%d" % int(pids),
            "Ulimit=nofile=%d:%d" % (NOFILE, NOFILE), "HealthCmd=none"]


def _head(desc, needs=()):
    return (["# Written by linuxgsm-panel for this website. The panel rewrites it.", "[Unit]",
             "Description=%s (linuxgsm-panel website)" % desc,
             "StartLimitIntervalSec=%d" % RESTART_WINDOW, "StartLimitBurst=%d" % RESTART_BURST]
            + ["Requires=%s" % n for n in needs] + ["After=%s" % n for n in needs])


def _tail(restart="always"):
    return ["", "[Service]", "Restart=%s" % restart, "RestartSec=10", "TimeoutStartSec=300",
            "", "[Install]", "WantedBy=default.target", ""]


def image_for(site):
    """The pinned image `site` runs (its kind and PHP or runtime version), or None when the catalog offers none."""
    from panel.services import websites_catalog as _wc     # imported here: the unit text is tested without it
    if site.kind == "static":
        return _wc.static_image()
    if site.kind in ("php", "phpbb"):
        return _wc.php_image("php", site.php_version)
    if site.kind == "wordpress":
        return _wc.php_image("wordpress", site.php_version)
    if site.kind == "app":
        return _wc.runtimes().get(site.runtime, {}).get("versions", {}).get(site.runtime_version)
    return None


def network(site, db_port=None, relays=(), splice=False):
    """The site container's Network= value: addons.network with the site's forwards (database, egress proxy)."""
    rl = list(relays)
    if needs_egress(site):
        rl.append(("egress", "127.0.0.1", EGRESS_INNER_PORT, EGRESS_PORT_BASE + int(site.port) - 20000,
                   "egress proxy"))
    net = _ad.network(None, db_port, rl, splice)
    if site.full_egress:
        # The superadmin's per-site switch: outbound to the internet (and DNS), still never the host's
        # own other addresses (the egress guard). --splice-only would close the internet too.
        net = net.replace("pasta:--splice-only", "pasta:-4").replace("pasta:-4,-o,127.0.0.1", "pasta:-4")
    return net


def needs_egress(site):
    """Whether the running site gets the egress proxy: WordPress (its update hosts) without full egress."""
    return site.kind == "wordpress" and not site.full_egress


def quadlet(site, ids, net, image=None, cpu=True):
    """The site's Quadlet .container text for numeric `ids` (uid, gid) and network options `net`.

    `image` defaults to image_for(site). A runtime app has its own: app_quadlet. `cpu` False leaves
    --cpus out (the host does not delegate the cpu controller; CPU_MODES "account" limits it instead).
    """
    if site.kind == "app":
        return app_quadlet(site, ids, net, image, cpu)
    image = image or image_for(site)
    home = _home(site.account)
    lines = _head("website %s" % site.name, [DB_RELAY_UNIT + ".socket"] if "-T,3306:%d" % (
        DB_RELAY_PORT_BASE + int(site.port) - 20000) in net else []) + [
        "", "[Container]", "Image=%s" % image, "ContainerName=%s" % UNIT, "Pull=never", "Network=%s" % net,
        "PublishPort=127.0.0.1:%d:%d" % (int(site.port), INNER_PORT)]
    if site.kind == "static":
        lines += ["Volume=%s/%s:%s:ro" % (home, HTML, DOCROOT["static"]),
                  "Volume=%s/%s/nginx.conf:/etc/nginx/conf.d/default.conf:ro" % (home, CONF),
                  "Tmpfs=/tmp:rw,mode=1777,size=64m"]
    else:
        lines += ["Volume=%s/%s:%s" % (home, HTML, DOCROOT_PHP),
                  "Volume=%s/%s/apache.conf:/etc/apache2/sites-enabled/000-default.conf:ro" % (home, CONF),
                  "Volume=%s/%s/ports.conf:/etc/apache2/ports.conf:ro" % (home, CONF),
                  "Volume=%s/%s/php.ini:/usr/local/etc/php/conf.d/zz-panel.ini:ro" % (home, CONF),
                  "Tmpfs=/tmp:rw,mode=1777,size=256m", "Tmpfs=/run/apache2:rw,mode=1777,size=16m",
                  "Tmpfs=/run/lock/apache2:rw,mode=1777,size=4m"]
    lines += _hardening(ids, site.pids) + ["PodmanArgs=%s" % " ".join(_limits(site, cpu))]
    if site.kind in KINDS_PHP:
        lines.append("Exec=apache2-foreground")
    return "\n".join(lines + _tail())


def app_quadlet(site, ids, net, image=None, cpu=True):
    """A runtime app's Quadlet text: the runtime's pinned image, its start command and port (behind the gate)."""
    image = image or image_for(site)
    home = _home(site.account)
    port = int(site.app_port or 0)
    if port == INNER_PORT or not 1024 <= port <= 65535:
        raise ValueError("an app's port is 1024-65535 and not %d (the gate's)" % INNER_PORT)
    lines = _head("website %s (app)" % site.name) + [
        "", "[Container]", "Image=%s" % image, "ContainerName=%s" % UNIT, "Pull=never", "Network=%s" % net,
        "PublishPort=127.0.0.1:%d:%d" % (int(site.port), INNER_PORT),
        "Volume=%s/%s:/app" % (home, HTML), "Volume=%s/%s/start.sh:/panel/start.sh:ro" % (home, CONF),
        "EnvironmentFile=%s/%s/app.env" % (home, CONF), "Environment=PORT=%d" % port, "Environment=NODE_ENV=production",
        "Environment=HOME=/tmp", "WorkingDir=/app", "Tmpfs=/tmp:rw,mode=1777,size=256m",
    ] + _hardening(ids, site.pids) + ["PodmanArgs=%s" % " ".join(_limits(site, cpu)), "Exec=/bin/sh /panel/start.sh"]
    return "\n".join(lines + _tail())


def gate_quadlet(site, ids, image):
    """The token gate in front of a runtime app: nginx in the app's own network namespace, on 8080."""
    home = _home(site.account)
    lines = _head("website %s (gate)" % site.name, [unit_service(UNIT)]) + [
        "BindsTo=%s" % unit_service(UNIT), "", "[Container]", "Image=%s" % image, "ContainerName=%s" % GATE_UNIT,
        "Pull=never", "Network=container:%s" % UNIT,
        "Volume=%s/%s/nginx.conf:/etc/nginx/conf.d/default.conf:ro" % (home, CONF),
        "Tmpfs=/tmp:rw,mode=1777,size=32m"] + _hardening(ids, 64) + [
        "PodmanArgs=--memory=64m --memory-swap=64m --dns=none --stop-timeout=%d" % STOP_TIMEOUT]
    return "\n".join(lines + _tail())


def object_cache_quadlet(site, ids, image=None):
    """The site's object cache (Valkey) Quadlet text, in the site's own network namespace (private to it)."""
    if image is None:
        from panel.services import websites_catalog as _wc
        image = _wc.pins("object_cache")["image"]
    home = _home(site.account)
    lines = _head("website %s (object cache)" % site.name, [unit_service(UNIT)]) + [
        "BindsTo=%s" % unit_service(UNIT), "", "[Container]", "Image=%s" % image, "ContainerName=%s" % CACHE_UNIT,
        "Pull=never", "Network=container:%s" % UNIT,
        "Volume=%s/%s/valkey.conf:/etc/valkey/valkey.conf:ro" % (home, CONF), "Tmpfs=/tmp:rw,mode=1777,size=16m",
    ] + _hardening(ids, 64) + [
        "PodmanArgs=--memory=%dm --memory-swap=%dm --dns=none --stop-timeout=%d" % (
            OBJECT_CACHE_MB * 2, OBJECT_CACHE_MB * 2, STOP_TIMEOUT),
        "Exec=valkey-server /etc/valkey/valkey.conf"]
    return "\n".join(lines + _tail())


def tunnel_quadlet(proxy, ids, image=None):
    """The tunnel connector's Quadlet .container text (exposure mode 'tunnel'); its token goes in a 0600 file.

    It runs as its own account (TUNNEL_ACCOUNT), reaches the web proxy on the host's loopback port
    TUNNEL_PORT (forwarded by pasta) and connects out to its provider; the egress guard keeps it off
    the host's other local addresses. The token is read from a file (--token-file), never argv or env.
    """
    from panel.services import websites_proxy as _wp
    if (proxy.tunnel_provider or "") != "cloudflare":
        raise ValueError("no tunnel provider is set")
    if image is None:
        from panel.services import websites_catalog as _wc
        image = _wc.pins("tunnel")["cloudflare"]["image"]
    home = _home(TUNNEL_ACCOUNT)
    lines = _head("web proxy tunnel") + [
        "", "[Container]", "Image=%s" % image, "ContainerName=%s" % TUNNEL_UNIT, "Pull=never",
        "Network=pasta:-T,%d" % _wp.TUNNEL_PORT, "Volume=%s/tunnel/token:/etc/cloudflared/token:ro" % home,
        "Tmpfs=/tmp:rw,mode=1777,size=16m"] + _hardening(ids, 128) + [
        "PodmanArgs=--memory=%dm --memory-swap=%dm --stop-timeout=%d" % (TUNNEL_MEMORY_MB, TUNNEL_MEMORY_MB,
                                                                          STOP_TIMEOUT),
        "Exec=tunnel --no-autoupdate run --token-file /etc/cloudflared/token"]
    return "\n".join(lines + _tail())


def egress_unit(site, hosts):
    """The site's egress proxy user unit: CONNECT to `hosts` on 443 only, listening on 127.0.0.1."""
    from panel.services import websites_catalog as _wc
    bad = [h for h in hosts if h not in _wc.EGRESS_HOSTS]
    if bad or not hosts:
        raise ValueError("egress hosts must come from the catalog's list: %r" % bad)
    port = EGRESS_PORT_BASE + int(site.port) - 20000
    return ("# Written by linuxgsm-panel: this website's only way out (CONNECT to the listed hosts on 443).\n"
            "[Unit]\nDescription=linuxgsm-panel website egress proxy\n\n[Service]\n"
            "ExecStart=/usr/bin/python3 -I %%h/%s/egress_proxy.py %d %s\nRestart=on-failure\nRestartSec=10\n"
            "MemoryMax=64M\nTasksMax=64\n\n[Install]\nWantedBy=default.target\n"
            % (HOME_DIR, port, " ".join(sorted(set(hosts)))))


def db_relay_units(site, target):
    """A database on another machine: a socket on the host's loopback relaying to `target` ("host:port")."""
    if not re.fullmatch(r"[0-9a-f.:]{3,45}:[0-9]{1,5}", target or ""):
        raise ValueError("a relay target is an address and port")
    port = DB_RELAY_PORT_BASE + int(site.port) - 20000
    return {DB_RELAY_UNIT + ".socket": ("# Written by linuxgsm-panel: this website's database relay.\n[Unit]\n"
                                        "Description=linuxgsm-panel website database relay\n\n[Socket]\n"
                                        "ListenStream=127.0.0.1:%d\n\n[Install]\nWantedBy=sockets.target\n" % port),
            DB_RELAY_UNIT + ".service": ("# Written by linuxgsm-panel: this website's database relay.\n[Unit]\n"
                                         "Description=linuxgsm-panel website database relay\nRequires=%s.socket\n"
                                         "After=%s.socket\n\n[Service]\nExecStart=%s --exit-idle-time=5min %s\n"
                                         % (DB_RELAY_UNIT, DB_RELAY_UNIT, _ad.SOCKET_PROXYD, target))}


def db_forward(site, db_host, db_port):
    """(the db_port network() forwards, the relay target or None) for a database at `db_host`:`db_port`."""
    if not db_host:
        return None, None
    if db_host == "127.0.0.1":
        return int(db_port), None
    return DB_RELAY_PORT_BASE + int(site.port) - 20000, "%s:%d" % (db_host, int(db_port))


# ── an app's environment and commands ───────────────────────────────────────────────────────────
_ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
ENV_MAX = 100
_ENV_RESERVED = ("PORT", "NODE_ENV", "HOME", "PATH")


def env_problems(env):
    """What is wrong with an app's variables ({KEY: value}), as sentences; [] when none."""
    if not isinstance(env, dict) or len(env) > ENV_MAX:
        return ["An app has at most %d variables." % ENV_MAX]
    out = []
    for key, value in sorted(env.items()):
        if not _ENV_KEY_RE.match(str(key)) or key in _ENV_RESERVED:
            out.append("%s is not a variable name an app may set." % key)
        elif not isinstance(value, str) or len(value) > 4096 or any(c in value for c in "\x00\r\n"):
            out.append("The value of %s must be one line of at most 4096 characters." % key)
    return out


def env_file(site, env=None):
    """The app's 0600 environment file text from its decrypted variables (KEY=value lines, keys validated)."""
    if env is None:
        from panel.core.config import decrypt_secret
        raw = decrypt_secret(site.env_enc or "") or "{}"
        try:
            env = json.loads(raw)
        except ValueError:
            env = {}
    if env_problems(env):
        raise ValueError("the app's variables are refused")
    return "".join("%s=%s\n" % (k, env[k]) for k in sorted(env))


def _command(site, field):
    from panel.services import websites_catalog as _wc
    text = getattr(site, field) or _wc.runtimes().get(site.runtime, {}).get(field.split("_")[0], "")
    if not text or len(text) > 1000 or any(c in text for c in "\x00\r\n"):
        raise ValueError("the app's %s is not one line" % field)
    return text


def start_script(site):
    """The app's start script (mounted read-only at /panel/start.sh), from its start command."""
    return "#!/bin/sh\n# Written by linuxgsm-panel: this app's start command.\nexec %s\n" % _command(site, "start_command")


def build_script(site):
    """The app's build script, run once in its image with the build-time egress proxy."""
    return "#!/bin/sh\n# Written by linuxgsm-panel: this app's install and build.\nset -e\n%s\n" % _command(
        site, "build_command")


def build_sh(account, site, ids=None, image=None):
    """Bash that runs the app's install/build command inside its container as the site's account.

    A one-off container with the same hardening, its files at /app, and the build-time egress proxy
    (the runtime's hosts only: npm's registry) at 127.0.0.1:3128 through HTTPS_PROXY. The proxy is a
    unit started for the build and stopped after it; the running app gets none unless granted.
    """
    home = _home(account)
    image = image or image_for(site)
    eport = EGRESS_PORT_BASE + int(site.port) - 20000
    args = ["podman", "run", "--rm", "--name", "lgsm-site-build", "--pull=never", "--userns=keep-id",
            "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges", "--pids-limit=%d" % int(site.pids),
            "--memory=%dm" % int(site.mem_mb), "--memory-swap=%dm" % int(site.mem_mb), "--dns=none",
            "--network=pasta:-4,-o,127.0.0.1,-T,%d:%d" % (EGRESS_INNER_PORT, eport),
            "--tmpfs=/tmp:rw,mode=1777,size=512m", "-v", "%s/%s:/app" % (home, HTML),
            "-v", "%s/%s/build.sh:/panel/build.sh:ro" % (home, CONF), "-w", "/app",
            "-e", "HOME=/tmp", "-e", "HTTPS_PROXY=http://127.0.0.1:%d" % EGRESS_INNER_PORT,
            "-e", "npm_config_https_proxy=http://127.0.0.1:%d" % EGRESS_INNER_PORT, "-e", "npm_config_cache=/tmp/npm"]
    if ids:
        args += ["--user", "%d:%d" % (int(ids[0]), int(ids[1]))]
    args += [image, "/bin/sh", "/panel/build.sh"]
    return (_ENV + "systemctl --user start %s.service || exit 1; " % EGRESS_UNIT
            + "%s > %s/build.log 2>&1; rc=$?; systemctl --user stop %s.service; " % (shlex.join(args), _q(home + "/" + CONF), EGRESS_UNIT)
            + "tail -n 40 %s/build.log; echo \"build_rc=$rc\"; exit $rc" % _q(home + "/" + CONF))


# ── what is written to the account's home ───────────────────────────────────────────────────────
# Files the account-side writer accepts, by path relative to the home: nothing else is written.
FILE_NAMES = ("%s/%s.container" % (QUADLET_DIR, UNIT), "%s/%s.container" % (QUADLET_DIR, CACHE_UNIT),
              "%s/%s.container" % (QUADLET_DIR, GATE_UNIT), "%s/%s.container" % (QUADLET_DIR, TUNNEL_UNIT),
              "%s/%s.service" % (USER_UNIT_DIR, EGRESS_UNIT), "%s/%s.socket" % (USER_UNIT_DIR, DB_RELAY_UNIT),
              "%s/%s.service" % (USER_UNIT_DIR, DB_RELAY_UNIT), CONF + "/nginx.conf", CONF + "/apache.conf",
              CONF + "/ports.conf", CONF + "/php.ini", CONF + "/valkey.conf", CONF + "/app.env", CONF + "/start.sh",
              CONF + "/build.sh", HOME_DIR + "/" + META_FILE, HOME_DIR + "/egress_proxy.py", "tunnel/token")


def bundle(files):
    """The stdin text write_files_sh reads: one `<path> <base64>` line per file (paths from FILE_NAMES only)."""
    bad = [p for p in files if p not in FILE_NAMES]
    if bad:
        raise ValueError("not a file the panel writes for a site: %r" % bad)
    return "".join("%s %s\n" % (p, _b64(files[p])) for p in sorted(files))


def write_files_sh():
    """Shell (as the account) writing each file of the stdin bundle, 0600 or 0700 folders, atomically.

    Every path is matched against FILE_NAMES in the shell too; anything else prints SITE_FILES_REFUSED
    and writes nothing more. No content is ever on the command line.
    """
    names = "|".join(FILE_NAMES)
    return ("umask 077; mkdir -p %s %s %s %s %s tunnel || exit 1; chmod 0700 %s %s; "
            "while read -r p b; do case \"$p\" in %s) ;; *) echo SITE_FILES_REFUSED; exit 25 ;; esac; "
            "printf %%s \"$b\" | base64 -d > \"$p.new\" && mv -f -T \"$p.new\" \"$p\" || exit 1; done; "
            % (_q(QUADLET_DIR), _q(USER_UNIT_DIR), _q(CONF), _q(HOME_DIR), _q(HTML), _q(CONF), _q(HOME_DIR), names))


def egress_proxy_source():
    """The egress proxy's source (panel/services/websites_egress.py, standard library only), for the account's home."""
    from panel.services import websites_egress as _eg
    with open(_eg.__file__, encoding="utf-8") as fh:
        return fh.read()


def site_files(site, ids, net, token, cache_password=None, image=None, egress_hosts=(), cpu=True):
    """{path: text} of every file `site` needs in its account's home (bundle() turns it into stdin)."""
    files = {"%s/%s.container" % (QUADLET_DIR, UNIT): quadlet(site, ids, net, image, cpu),
             HOME_DIR + "/" + META_FILE: json.dumps({"kind": site.kind, "image": image or image_for(site),
                                                     "port": int(site.port), "name": site.name}, sort_keys=True)}
    if site.kind == "static":
        files[CONF + "/nginx.conf"] = nginx_conf(token)
    elif site.kind == "app":
        from panel.services import websites_catalog as _wc
        files[CONF + "/nginx.conf"] = nginx_conf(token, site.app_port)
        files["%s/%s.container" % (QUADLET_DIR, GATE_UNIT)] = gate_quadlet(site, ids, _wc.static_image())
        files[CONF + "/start.sh"] = start_script(site)
        files[CONF + "/build.sh"] = build_script(site)
        files[CONF + "/app.env"] = env_file(site)
    else:
        files[CONF + "/apache.conf"] = apache_conf(token)
        files[CONF + "/ports.conf"] = APACHE_PORTS
        files[CONF + "/php.ini"] = php_ini(site)
    if site.object_cache and cache_password:
        files[CONF + "/valkey.conf"] = valkey_conf(cache_password)
        files["%s/%s.container" % (QUADLET_DIR, CACHE_UNIT)] = object_cache_quadlet(site, ids)
    if egress_hosts:
        files[HOME_DIR + "/egress_proxy.py"] = egress_proxy_source()
        files["%s/%s.service" % (USER_UNIT_DIR, EGRESS_UNIT)] = egress_unit(site, egress_hosts)
    return files


# ── the shell run as the account ────────────────────────────────────────────────────────────────
def _units(site):
    units = [UNIT]
    if site.kind == "app":
        units.append(GATE_UNIT)
    if site.object_cache:
        units.append(CACHE_UNIT)
    return units


def install_sh(account, site, image=None):
    """Bash that lays out the site's folders, writes its files from stdin, pulls its pinned image and reloads units.

    stdin is bundle(site_files(...)). Prints SITE_INSTALLED, or a FAIL_MARKS key and exits non-zero.
    """
    _home(account)
    image = image or image_for(site)
    pull = "podman pull -q %s >/dev/null || { echo SITE_PULL_FAILED; exit 23; }; " % _q(image)
    if site.kind == "app":
        from panel.services import websites_catalog as _wc
        pull += "podman pull -q %s >/dev/null || { echo SITE_PULL_FAILED; exit 23; }; " % _q(_wc.static_image())
    if site.object_cache:
        from panel.services import websites_catalog as _wc
        pull += "podman pull -q %s >/dev/null || { echo SITE_PULL_FAILED; exit 23; }; " % _q(
            _wc.pins("object_cache")["image"])
    return (_ENV + write_files_sh() + "mkdir -p %s && chmod 0700 %s %s || exit 1; " % (
        _q(BACKUPS), _q(SITE), _q(BACKUPS)) + pull + "systemctl --user daemon-reload; echo %s" % _MARK_INSTALLED)


def start_sh(account, site):
    """Bash that starts the site's container (and its gate, object cache and egress proxy), clearing the start limit."""
    _home(account)
    units = " ".join(unit_service(u) for u in _units(site))
    egress = "systemctl --user enable --now %s.service; " % EGRESS_UNIT if needs_egress(site) else ""
    return (_ENV + egress + "systemctl --user reset-failed %s 2>/dev/null; " % units
            + "if systemctl --user start %s; then echo %s; else " % (units, _MARK_STARTED)
            + "[ \"$(systemctl --user show -p Result --value %s 2>/dev/null)\" = start-limit-hit ] "
              "&& echo SITE_START_LIMIT || echo SITE_START_FAILED; " % unit_service(UNIT)
            + "journalctl --user -u %s -n 20 --no-pager -o cat 2>/dev/null | tail -n 20; exit 1; fi" % unit_service(UNIT))


def stop_sh(account, site):
    """Bash that stops the site's container (its gate, object cache and egress proxy with it)."""
    _home(account)
    units = " ".join(unit_service(u) for u in reversed(_units(site)))
    return (_ENV + "systemctl --user stop %s %s.service 2>/dev/null; echo %s" % (units, EGRESS_UNIT, _MARK_STOPPED))


def remove_sh(account, site):
    """Bash that stops and removes the site's containers and units (the account is removed by the helper)."""
    _home(account)
    units = " ".join(unit_service(u) for u in (UNIT, GATE_UNIT, CACHE_UNIT))
    files = " ".join(_q(p) for p in FILE_NAMES if p.startswith((QUADLET_DIR, USER_UNIT_DIR)))
    return (_ENV + "systemctl --user disable --now %s.service %s.socket 2>/dev/null; " % (EGRESS_UNIT, DB_RELAY_UNIT)
            + "systemctl --user stop %s 2>/dev/null; rm -f %s; systemctl --user daemon-reload; " % (units, files)
            + "podman rm -f -i %s %s %s >/dev/null 2>&1; podman image prune -a -f >/dev/null 2>&1; echo %s"
            % (UNIT, GATE_UNIT, CACHE_UNIT, _MARK_REMOVED))


LOG_LINES = 500


def logs_sh(account, lines=LOG_LINES):
    """Bash (as the site's account) printing the last `lines` log lines of the site's containers, oldest first.

    The containers' own output (Podman's journald driver names them), with the time; nothing of the host.
    """
    _home(account)
    names = " + ".join("CONTAINER_NAME=%s" % u for u in (UNIT, GATE_UNIT, CACHE_UNIT))
    return (_ENV + "journalctl --user %s -n %d --no-pager -o short-iso 2>/dev/null | grep -v '^-- No entries --$'; true"
            % (names, max(1, min(int(lines), 2000))))


def probe_sh(account, site):
    """Bash that prints the site's state as key=value lines for parse_probe (one SSH round trip)."""
    _home(account)
    return (_ENV + '. /etc/os-release 2>/dev/null; echo "os=${VERSION_ID:-}"; '
            'echo "podman=$(podman --version 2>/dev/null | head -n 1)"; '
            'pasta --help 2>&1 | grep -q -- "--splice-only" && echo splice=1; echo "uid=$(id -u)"; echo "gid=$(id -g)"; '
            "echo \"state=$(systemctl --user is-active %s 2>/dev/null | head -n 1)\"; " % unit_service(UNIT)
            + "echo \"result=$(systemctl --user show -p Result --value %s 2>/dev/null)\"; " % unit_service(UNIT)
            + "echo \"image=$(podman inspect --format '{{.ImageName}}' %s 2>/dev/null)\"; " % UNIT
            + "echo \"mem=$(podman stats --no-stream --format '{{.MemUsage}}' %s 2>/dev/null | head -n 1)\"; " % UNIT
            + "echo \"disk_mb=$(du -sxm %s 2>/dev/null | cut -f1)\"; " % _q(SITE)
            + 'u=$(id -u); grep -qw cpu "/sys/fs/cgroup/user.slice/user-$u.slice/user@$u.service/cgroup.controllers" '
              '2>/dev/null && echo cpu_delegated=1; '
            + "[ -f %s ] && echo installed=1; true" % _q(HOME_DIR + "/" + META_FILE))


_STATES = {"active": "running", "activating": "starting", "deactivating": "stopping", "inactive": "stopped",
           "failed": "failed", "reloading": "running"}


def parse_probe(out):
    """probe_sh's output as a dict: state, result, image, mem, disk_mb (int or None), uid, gid, installed, splice."""
    kv = _ad.kv_lines(out)
    disk = kv.get("disk_mb", "")
    return {"state": _STATES.get(kv.get("state", ""), "unknown"), "result": kv.get("result", ""),
            "image": kv.get("image", ""), "mem": kv.get("mem", ""), "disk_mb": int(disk) if disk.isdecimal() else None,
            "uid": int(kv["uid"]) if kv.get("uid", "").isdecimal() else None,
            "gid": int(kv["gid"]) if kv.get("gid", "").isdecimal() else None,
            "installed": kv.get("installed") == "1", "splice": kv.get("splice") == "1",
            "cpu_delegated": kv.get("cpu_delegated") == "1",
            "os": kv.get("os", ""), "podman": kv.get("podman", "")}


def runtime_refusal(os_version, podman_version):
    """Why this host can't run websites (an English sentence), or ""."""
    why = _ad.runtime_refusal(os_version, podman_version)
    return why.replace("Add-ons need", "Websites need").replace("on the game's host", "on the website's host")


# ── disk ────────────────────────────────────────────────────────────────────────────────────────
DISK_WARN = 0.8
DISK_REFUSE = 1.0
DISK_STOP = 1.2


def disk_state(used_mb, limit_mb):
    """'ok', 'warn' (80 %), 'full' (100 %: uploads refused) or 'over' (120 %: the site is stopped)."""
    if used_mb is None or not limit_mb:
        return "ok"
    ratio = used_mb / float(limit_mb)
    return "over" if ratio >= DISK_STOP else "full" if ratio >= DISK_REFUSE else "warn" if ratio >= DISK_WARN else "ok"


# ── one-click app recipes ───────────────────────────────────────────────────────────────────────
def recipe_steps(recipe):
    """A one-click app recipe's install steps, each one of the fixed step types the panel implements.

    `recipe` is a catalog recipe, or its name (the signed catalog's entry is used; [] when it has none).
    Raises ValueError for a recipe websites_catalog would refuse. Each step is a copy with its index
    (`n`) and a `name` (type and index) the install job records in Website.install_steps_done.
    """
    from panel.services import websites_catalog as _wc
    if isinstance(recipe, str):
        recipe = _wc.recipe(recipe)
        if recipe is None:
            return []
    bad = _wc.recipe_problems("recipe", recipe)
    if bad:
        raise ValueError("the recipe is refused: %s" % bad[0])
    return [dict(step, n=i, name="%s-%d" % (step["type"], i)) for i, step in enumerate(recipe["steps"])]


def step_sh(account, site, step, values):
    """Bash that runs one install step as the site's account (websites_recipes.step_sh); secrets on stdin."""
    from panel.services import websites_recipes as _wr
    return _wr.step_sh(account, site, step, values)


def undo_sh(account, site, step):
    """Bash that undoes one finished install step (the job runs these in reverse on a failure)."""
    from panel.services import websites_recipes as _wr
    return _wr.undo_sh(account, site, step)
