"""A host's websites over the root helper and as each site's own account: the layer the Websites routes call.

Every call returns (ok, text), where text is a fixed sentence for the page (or key=value lines a
caller parses: site_probe, proxy_status, php_effective), never a command's raw output with a secret
in it. Writes as a site's account go through _core.shell_as_game_user after
routes._shared.game_account_write_refusal (an account the host cannot confirm is not root-capable is
refused); the helper's website-* verbs refuse any account it did not make itself. Secrets (the proxy
token, the object cache's password, an app's variables, the tunnel token, an installer's passwords)
travel on stdin only, never on a command line.

THE PANEL'S OWN HOST ONLY, FOR NOW
    The website verbs need the root helper (root-owned units, nftables, the proxy binary), which only
    the panel's own host has; a managed host is refused with ONLY_LOCAL until it can run them.

Not one of the package's _MODULES (its generic names must not shadow another submodule's through the
package's __getattr__): import it by name, `from panel.ops.ssh_manager import websites`. Its names must
still differ from every other submodule's (a unit gate): hence site_probe, not probe (databases has one).
"""
import json
import secrets as _secrets

from panel.ops.ssh_manager import _core


def _ws():
    """panel.services.websites, imported when first used (ops sits below services)."""
    from panel.services import websites as mod
    return mod


def _wp():
    """panel.services.websites_proxy, imported when first used."""
    from panel.services import websites_proxy as mod
    return mod

ONLY_LOCAL = ("Websites run on the panel's own host for now: a managed host cannot run the panel's root "
              "helper, which websites need.")
NO_HELPER = ("This host's panel helper is missing or out of date. Run install.sh again as root, then try "
             "again.")
MISSING_GATE = "This website has no proxy token yet. Save its settings again, then try again."
NO_IMAGE = "The signed catalog offers no image for this website's kind and version."
REFUSED = "The panel refused the request."
OK_STARTED = "The website was started."
OK_STOPPED = "The website was stopped."
OK_REMOVED = "The website and its account were removed."
OK_PROXY = "The web proxy was installed."
OK_CACHE_BUILD = "The web proxy with the page cache was built and installed."
CACHE_BUILD_FAILED = ("The web proxy with the page cache could not be built, so the plain one was kept. Check the "
                      "host's internet connection and try again.")
OK_APPLIED = "The web proxy's configuration was checked and applied."
BAD_CONFIG = "The web proxy refused the new configuration, so the running one was kept: {why}"
OK_PROXY_STOPPED = "The web proxy was stopped: nothing listens on ports 80 and 443."
FAILED = "That did not work on the host. Try again; if it keeps failing, look at the site's log."
OK_PORTS = "Ports 80 and 443 are set for the web proxy's exposure mode."
OK_TUNNEL = "The tunnel connector was updated."
OK_GUARD = "The egress guard is on: websites cannot reach this host's other addresses."
OK_QUOTA = "The website's disk quota is set."
NO_QUOTA = "This host's file system has no user quotas, so the panel measures the website's disk use instead."
OK_PHP = "The website's PHP settings were written and it was restarted."
OK_PURGED = "The page cache was emptied (the web proxy restarted)."
OK_BUILT = "The app was built."
OK_ENV = "The app's variables were written and it was restarted."
OK_STEP = "Step done."
PROXY_COMMENT = "lgsmpanel-websites"
PORTS = ("80", "443")


def _mark(out):
    """The FAIL_MARKS sentence for the first mark `out` holds, else FAILED."""
    for key, sentence in _ws().FAIL_MARKS.items():
        if key in (out or ""):
            return sentence
    return FAILED


def _helper(remote, verb, args=(), timeout=120, doc=None):
    """(ok, out) of a helper verb on the panel's own host; (False, ONLY_LOCAL / NO_HELPER) elsewhere."""
    if not _core.is_local_server(remote):
        return False, ONLY_LOCAL
    if not _core.helper_present():
        return False, NO_HELPER
    if doc is None:
        out, _err, rc = _core.run_privileged(remote, verb, list(args), timeout=timeout)
        return rc == 0, out or ""
    # A verb that reads a document on stdin (privileged_websites.STDIN_VERBS): the helper, that stdin.
    from panel.security import privileged as _priv
    out, err, rc = _core._exec_local_argv(_priv.helper_argv(verb, list(args)), timeout=timeout, stdin_text=doc)
    return rc == 0, "\n".join(x for x in (out, err) if x).strip()


def _as_site(remote, account, sh, timeout=120, stdin_text=None):
    """(ok, out) of shell `sh` run as the site's account, after the write refusal check."""
    if not _core.is_local_server(remote):
        return False, ONLY_LOCAL
    from panel.routes._shared import game_account_write_refusal   # imported here: routes sit above ops
    why = game_account_write_refusal(remote, account)
    if why:
        return False, str(why)
    out, _err, rc = _core.shell_as_game_user(remote, account, sh, timeout=timeout, stdin_text=stdin_text)
    return rc == 0, out or ""


def _secret(value):
    from panel.core.config import decrypt_secret
    return decrypt_secret(value or "") or ""


def _ids(remote, site):
    """((uid, gid), probe dict) of the site's account, or (None, probe) when unread."""
    ok, out = _as_site(remote, site.account, _ws().probe_sh(site.account, site), timeout=60)
    probe = _ws().parse_probe(out) if ok else {}
    ids = (probe["uid"], probe["gid"]) if probe.get("uid") is not None and probe.get("gid") is not None else None
    return ids, probe


def _egress_hosts(site):
    """The hosts the site's egress proxy may reach: its recipe's (WordPress's update hosts), an app's build hosts."""
    from panel.services import websites_catalog as _wc
    if site.kind == "app":
        return _wc.runtimes().get(site.runtime, {}).get("egress", [])
    if not _ws().needs_egress(site):
        return []
    return (_wc.recipe(site.app_recipe) or {}).get("egress") or ["api.wordpress.org", "downloads.wordpress.org"]


def _site_bundle(site, ids, probe, db=None):
    """(stdin bundle of the site's files, image, None), or (None, None, refusal) with no token or no image.

    A ValueError from building the files (a value the panel's own checks should have refused) is raised.
    """
    token = _secret(site.proxy_secret)
    if not _ws()._TOKEN_RE.match(token):
        return None, None, MISSING_GATE
    image = _ws().image_for(site)
    if not image:
        return None, None, NO_IMAGE
    db_port, relay_target = _ws().db_forward(site, *(db or (None, None)))
    net = _ws().network(site, db_port, splice=probe.get("splice", False))
    cache_pw = _secret(site.object_cache_secret) if site.object_cache else None
    files = _ws().site_files(site, ids, net, token, cache_password=cache_pw, image=image,
                             egress_hosts=_egress_hosts(site), cpu=probe.get("cpu_delegated", False))
    if relay_target:
        files.update({"%s/%s" % (_ws().USER_UNIT_DIR, k): v for k, v in _ws().db_relay_units(site, relay_target).items()})
    return _ws().bundle(files), image, None


def install(remote, site, db=None):
    """Create the site's account and folders, pull its image, write its unit and start it.

    `db` is (host, port) of the site's database as the host sees it, or None.
    """
    ok, out = _helper(remote, "website-account-create", [site.account])
    if not ok:
        return False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED
    ids, probe = _ids(remote, site)
    if ids is None:
        return False, FAILED
    why = _ws().runtime_refusal(probe.get("os", ""), probe.get("podman", ""))
    if why:
        return False, why
    try:
        stdin, image, refused = _site_bundle(site, ids, probe, db)
    except ValueError:
        # The reason stays in the panel's log; the page gets the generic sentence (OWASP Error Handling).
        _core._log.warning("website %s: its files could not be built from its settings", site.id, exc_info=True)
        return False, FAILED
    if refused:
        return False, refused
    ok, out = _as_site(remote, site.account, _ws().install_sh(site.account, site, image), timeout=900, stdin_text=stdin)
    if not ok:
        return False, _mark(out)
    quota_set(remote, site)
    cpu_limit(remote, site, probe)
    return start(remote, site)


def cpu_limit(remote, site, probe=None):
    """Where the site's CPU limit is enforced: (ok, websites.CPU_MODES key) — container, account or none.

    The container's own --cpus where the host delegates the cpu controller to the account (written in its
    unit); else the helper limits the account's whole user slice. Never silently unlimited: "none" is said.
    """
    if probe is None:
        _ids_got, probe = _ids(remote, site)
    if probe.get("cpu_delegated"):
        return True, "container"
    ok, _out = _helper(remote, "website-cpu-limit", [site.account, str(int(site.cpu_milli))], timeout=60)
    return ok, "account" if ok else "none"


def start(remote, site):
    """Start the site's container."""
    ok, out = _as_site(remote, site.account, _ws().start_sh(site.account, site), timeout=180)
    return (True, OK_STARTED) if ok else (False, _mark(out))


def stop(remote, site):
    """Stop the site's container."""
    ok, out = _as_site(remote, site.account, _ws().stop_sh(site.account, site), timeout=120)
    return (True, OK_STOPPED) if ok else (False, _mark(out))


def remove(remote, site):
    """Stop and remove the site's container, its unit and its account."""
    _as_site(remote, site.account, _ws().remove_sh(site.account, site), timeout=180)
    ok, out = _helper(remote, "website-account-remove", [site.account], timeout=180)
    return (True, OK_REMOVED) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED)


def site_probe(remote, site):
    """Read the site's state (one SSH round trip): (ok, probe_sh's key=value lines)."""
    return _as_site(remote, site.account, _ws().probe_sh(site.account, site), timeout=60)


def proxy_install(remote):
    """Install the pinned web proxy binary and its service on the host."""
    from panel.services import websites_catalog as _wc
    ok, out = _helper(remote, "website-proxy-status", timeout=30)
    if not ok:
        return False, out
    arch = "arm64" if "aarch64" in _host_machine(remote) else "amd64"
    asset = _wc.caddy_asset(arch)
    if not asset:
        return False, NO_IMAGE
    ok, out = _helper(remote, "website-proxy-install", [asset["version"], arch, asset["sha256"]], timeout=900)
    return (True, OK_PROXY) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED)


def cpu_note(mode):
    """The site card's sentence for where the CPU limit is enforced (cpu_limit's mode)."""
    modes = _ws().CPU_MODES
    return modes.get(mode, modes["none"])


def proxy_install_cache(remote):
    """Build and install the web proxy with the page cache module, from the signed catalog's pins."""
    from panel.services import websites_catalog as _wc
    pins = _wc.pins("caddy_cache")
    ok, out = _helper(remote, "website-proxy-install-cache",
                      [pins["caddy"], pins["builder"], pins["base"], pins["version"]], timeout=1900)
    return (True, OK_CACHE_BUILD) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else CACHE_BUILD_FAILED)


def _host_machine(remote):
    out, _err, _rc = _core.run_command(remote, "uname -m", timeout=15, sudo=False)
    return out or ""


def apply_doc(text, sites=(), proxy=None):
    """website-proxy-apply's stdin: the configuration and the certificate files it names (operators' own, the CA)."""
    files = {}
    for site in sites:
        for d in site.domains or []:
            if d.cert_mode == "own" and d.verified_at is not None and d.own_cert_pem:
                files["%s.crt" % d.domain] = d.own_cert_pem
                files["%s.key" % d.domain] = _secret(d.own_key_secret)
    if proxy is not None and proxy.origin_pull_mtls:
        from panel.services import websites_catalog as _wc
        files["origin-pull-ca.pem"] = _wc.origin_pull_ca("cloudflare")
    return json.dumps({"caddyfile": text, "files": files})


def proxy_apply(remote, text, sites=(), proxy=None, start_it=False):
    """Validate and apply a rendered proxy configuration, keeping the previous one on failure."""
    ok, out = _helper(remote, "website-proxy-apply", ["start" if start_it else "reload"], timeout=180,
                      doc=apply_doc(text, sites, proxy))
    if ok:
        return True, OK_APPLIED
    errors = [ln[len("error="):] for ln in out.splitlines() if ln.startswith("error=")]
    if errors:
        return False, BAD_CONFIG.format(why=errors[-1][:200])
    return False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED


def proxy_stop(remote):
    """Stop the web proxy (the last enabled site went offline)."""
    ok, out = _helper(remote, "website-proxy-stop", timeout=120)
    return (True, OK_PROXY_STOPPED) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED)


def proxy_status(remote):
    """The web proxy's state and each domain's certificate state: (ok, key=value lines)."""
    return _helper(remote, "website-proxy-status", timeout=60)


def parse_proxy_status(out):
    """proxy_status's lines as {installed, version, active, certs: {domain: {issuer, not_after}}}."""
    got = {"installed": False, "version": "", "active": "unknown", "cache": False, "certs": {}}
    for line in (out or "").splitlines():
        if line.startswith("cert="):
            parts = dict(p.split("=", 1) for p in line.split() if "=" in p)
            if parts.get("not_after", "").isdecimal():
                got["certs"][parts["cert"]] = {"issuer": parts.get("issuer", ""), "not_after": int(parts["not_after"])}
        elif "=" in line:
            key, _sep, value = line.partition("=")
            if key in ("installed", "version", "active", "cache"):
                got[key] = (value == "yes") if key in ("installed", "cache") else value
    return got


def wanted_rules(proxy, enabled):
    """[(from cidr or None, port)] ports 80/443 should be open for: none in tunnel mode or with no site enabled."""
    if not enabled or proxy is None or proxy.exposure_mode == "tunnel":
        return []
    if proxy.exposure_mode == "public":
        return [(None, p) for p in PORTS]
    return [(cidr, p) for cidr in _wp().allow_list(proxy) for p in PORTS]


def _website_rule(line):
    """(from cidr or None, port) when one `ufw status numbered` line is a labelled website ALLOW rule, else None."""
    from panel.ops.ssh_manager import firewall as _fw
    _num, sep, detail = line.partition("]")
    if not sep or PROXY_COMMENT not in detail:
        return None
    rule = _fw._parse_ufw_rule(detail)
    port = rule["to"].replace("/tcp", "").split()[-1] if rule["to"] else ""
    if rule["comment"].strip() != PROXY_COMMENT or rule["action"] != "ALLOW" or port not in PORTS:
        return None
    frm = rule["from"].replace("(v6)", "").strip()
    return None if frm.lower() == "anywhere" else frm, port


def _rule_key(rule):
    return rule[0] or "", rule[1]


def rules_in(ufw_numbered):
    """[(from cidr or None, port)] of the labelled website rules in `ufw status numbered` output."""
    got = {_website_rule(line) for line in (ufw_numbered or "").splitlines()}
    return sorted((r for r in got if r is not None), key=_rule_key)


def _rule_verb(frm, port, add):
    """The ufw verb and arguments that add (or delete) one website rule."""
    if frm is None:
        return ("ufw-allow-proto-port", ["tcp", port, PROXY_COMMENT]) if add else ("ufw-delete-allow-proto-port", ["tcp", port])
    return (("ufw-allow-from-port", [frm, port, "tcp", PROXY_COMMENT]) if add
            else ("ufw-delete-allow-from-port", [frm, port, "tcp"]))


def ports_apply(remote, proxy, enabled):
    """Open or close ports 80/443 for the host's exposure mode: to all, to the allow list only, or not at all.

    Order (brief 1.3): rules are added before the proxy starts and removed after it stops (the
    caller's order), and the labelled rules the mode no longer wants are deleted here, so a list that
    changed converges in one call. Every rule is labelled PROXY_COMMENT.
    """
    if not _core.is_local_server(remote):
        return False, ONLY_LOCAL
    out, _err, rc = _core.run_privileged(remote, "ufw-status", ["numbered"], timeout=45)
    if rc != 0:
        return False, FAILED
    have, want = set(rules_in(out)), set(wanted_rules(proxy, enabled))
    steps = ([_rule_verb(f, p, True) for f, p in sorted(want - have, key=_rule_key)]
             + [_rule_verb(f, p, False) for f, p in sorted(have - want, key=_rule_key)])
    for verb, args in steps:
        if _core.run_privileged(remote, verb, args, timeout=60)[2] != 0:
            return False, FAILED
    return True, OK_PORTS


def _tunnel_ids(remote):
    """(uid, gid) of the tunnel connector's account, or None."""
    ok, out = _as_site(remote, _ws().TUNNEL_ACCOUNT, _ws()._ENV + 'echo "uid=$(id -u)"; echo "gid=$(id -g)"', timeout=30)
    kv = dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln) if ok else {}
    if kv.get("uid", "").isdecimal() and kv.get("gid", "").isdecimal():
        return int(kv["uid"]), int(kv["gid"])
    return None


def _tunnel_token_ok(token):
    return bool(token) and len(token) <= 4096 and not any(c in token for c in "\r\n\x00 ")


def tunnel_apply(remote, proxy):
    """Start, restart or stop the outbound tunnel connector for exposure mode 'tunnel'."""
    acct, unit = _ws().TUNNEL_ACCOUNT, _ws().unit_service(_ws().TUNNEL_UNIT)
    if proxy is None or proxy.exposure_mode != "tunnel" or not proxy.tunnel_provider:
        _as_site(remote, acct, _ws()._ENV + "systemctl --user stop %s 2>/dev/null; true" % unit)
        return True, OK_TUNNEL
    token = _secret(proxy.tunnel_token_enc)
    if not _tunnel_token_ok(token):
        return False, "The tunnel token is missing or not one line. Paste it again."
    ok, out = _helper(remote, "website-account-create", [acct])
    ids = _tunnel_ids(remote) if ok else None
    if ids is None:
        return False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED
    from panel.services import websites_catalog as _wc
    image = _wc.pins("tunnel")["cloudflare"]["image"]
    files = {"%s/%s.container" % (_ws().QUADLET_DIR, _ws().TUNNEL_UNIT): _ws().tunnel_quadlet(proxy, ids, image),
             "tunnel/token": token}
    sh = (_ws()._ENV + _ws().write_files_sh() + "podman pull -q %s >/dev/null || { echo SITE_PULL_FAILED; exit 23; }; "
          "systemctl --user daemon-reload && systemctl --user restart %s" % (image, unit))
    ok, out = _as_site(remote, acct, sh, timeout=600, stdin_text=_ws().bundle(files))
    return (True, OK_TUNNEL) if ok else (False, _mark(out))


def egress_guard(remote):
    """Load the egress guard that keeps site containers off the host's other local addresses."""
    ok, out = _helper(remote, "website-egress-guard", ["on"], timeout=60)
    return (True, OK_GUARD) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED)


def quota_set(remote, site):
    """Set the site account's disk quota where the file system has quotas on."""
    ok, out = _helper(remote, "website-quota-set", [site.account, str(int(site.disk_mb))], timeout=60)
    if ok and "quota=unavailable" in out:
        return True, NO_QUOTA
    return (True, OK_QUOTA) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED)


def _rewrite_and_restart(remote, site, files):
    sh = (_ws()._ENV + _ws().write_files_sh() + "systemctl --user daemon-reload; systemctl --user restart %s"
          % _ws().unit_service(_ws().UNIT))
    return _as_site(remote, site.account, sh, timeout=180, stdin_text=_ws().bundle(files))


def php_apply(remote, site):
    """Write the site's php.ini and restart its container gracefully."""
    if site.kind not in _ws().KINDS_PHP:
        return False, REFUSED
    ok, out = _rewrite_and_restart(remote, site, {_ws().CONF + "/php.ini": _ws().php_ini(site)})
    return (True, OK_PHP) if ok else (False, _mark(out))


def php_effective(remote, site):
    """The PHP settings in effect inside the site's container (php -i), for the form to show: (ok, {key: value})."""
    ok, out = _as_site(remote, site.account, _ws().php_effective_sh(site.account), timeout=60)
    return ok, _ws().parse_effective(out) if ok else {}


def cache_purge(remote, site):
    """Empty the site's page cache at the proxy: a restart (its admin API is off, so nothing else can)."""
    ok, out = _helper(remote, "website-proxy-apply", ["restart"], timeout=120, doc="")
    return (True, OK_PURGED) if ok else (False, out if out in (ONLY_LOCAL, NO_HELPER) else FAILED)


def app_build(remote, site):
    """Run the app's install/build step in its container (the build-time egress allow list only)."""
    ids, _probe = _ids(remote, site)
    if ids is None:
        return False, FAILED
    ok, _out = _as_site(remote, site.account, _ws().build_sh(site.account, site, ids), timeout=1800)
    return (True, OK_BUILT) if ok else (False, FAILED)


def env_apply(remote, site):
    """Write the app's environment file (0600, as the site's account, content on stdin) and restart it."""
    try:
        files = {_ws().CONF + "/app.env": _ws().env_file(site)}
    except ValueError:
        return False, REFUSED
    ok, out = _rewrite_and_restart(remote, site, files)
    return (True, OK_ENV) if ok else (False, _mark(out))


def _step_values(site, step):
    """(the step without its secrets, values_for()'s dict) from a step that carries the job's `secrets`.

    The install job passes the generated or typed admin details and the new database's name and password in
    step["secrets"]; they become the placeholder values and travel on stdin only (websites_recipes).
    """
    step = dict(step)
    sec = step.pop("secrets", None) or {}
    from panel.services import websites_recipes as _wr
    domains = [d.domain for d in sorted(site.domains or [], key=lambda d: (not d.is_primary, d.id or 0))]
    admin = {"user": sec.get("admin_user", ""), "email": sec.get("admin_email", ""),
             "password": sec.get("admin_password", ""), "site_name": site.name}
    db = {"name": sec.get("db_name", ""), "user": sec.get("db_user", ""), "password": sec.get("db_password", "")}
    return step, _wr.values_for(site, db=db, admin=admin if sec.get("admin_user") else None, domains=domains)


def app_install_step(remote, site, step, values=None, recipe=None):
    """Run one install step of the site's app recipe; (ok, text). create-database is the caller's (Databases code).

    `values` is websites_recipes.values_for()'s dict, or the step carries the job's `secrets` (the admin
    details and the database's) and they are turned into it here; `recipe` defaults to the site's catalog
    recipe. The account's ids and the site's network are added for a container step. Every secret goes on
    the step's stdin, never on a command line.
    """
    from panel.services import websites_recipes as _wr
    from panel.services import websites_catalog as _wc
    if step["type"] == "create-database":
        return True, OK_STEP
    if "secrets" in step:
        try:
            step, values = _step_values(site, step)
        except ValueError:
            return False, REFUSED
    values = dict(values or {})
    recipe = recipe or _wc.recipe(site.app_recipe) or {}
    if step["type"] == "run-in-container" and not _container_values(remote, site, recipe, values):
        return False, FAILED
    body, stdin = _wr.step_sh(site.account, site, step, values, recipe=recipe, token=_secret(site.proxy_secret))
    ok, out = _as_site(remote, site.account, body, timeout=1800, stdin_text=stdin)
    return (True, OK_STEP) if ok else (False, _mark(out))


def _container_values(remote, site, recipe, values):
    """Add the account's ids and the site's network to `values` for a container step; False when unread."""
    ids, probe = _ids(remote, site)
    if ids is None:
        return False
    db_port = values.get("_db_port") or (3306 if recipe.get("database") else None)
    values.update(_uid=str(ids[0]), _gid=str(ids[1]),
                  _network=_ws().network(site, db_port, splice=probe.get("splice", False)))
    return True


def site_logs(remote, site):
    """The site's containers' last log lines (one SSH round trip): (ok, text)."""
    ok, out = _as_site(remote, site.account, _ws().logs_sh(site.account), timeout=60)
    return (True, out) if ok else (False, FAILED)


def app_undo_step(remote, site, step):
    """Undo one finished install step; (ok, text)."""
    body = _ws().undo_sh(site.account, site, step)
    if not body:
        return True, OK_STEP
    ok, _out = _as_site(remote, site.account, body, timeout=300)
    return (True, OK_STEP) if ok else (False, FAILED)


def new_token():
    """A fresh proxy token or object-cache password: 48 URL-safe characters from the CSPRNG."""
    return _secrets.token_urlsafe(36)
