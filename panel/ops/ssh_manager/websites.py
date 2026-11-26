"""A host's websites over SSH and the root helper: the service layer the Websites routes call (scaffold).

Builder W2 fills this in. Every call returns (ok, text), where text is a fixed sentence for the page,
never a command's raw output. Writes as a site's account go through the helper's website-* verbs and
_core.game_user_cmd, and refuse an account the panel did not create. Secrets (the proxy token, the
tunnel token) travel as the call's `secrets`, on stdin, never on argv.

Not one of the package's _MODULES (its generic names must not shadow another submodule's through the
package's __getattr__): import it by name, `from panel.ops.ssh_manager import websites`. Its names must
still differ from every other submodule's (a unit gate): hence site_probe, not probe (databases has one).
"""
# pylint: disable=unused-argument  # scaffold signatures; the builder that fills them in removes this


def _todo(name):
    """The scaffold's answer for a call not built yet."""
    return False, "%s is not built yet" % name


def install(remote, site):
    """Create the site's account and folders, pull its image, write its unit and start it."""
    return _todo("install")


def start(remote, site):
    """Start the site's container."""
    return _todo("start")


def stop(remote, site):
    """Stop the site's container."""
    return _todo("stop")


def remove(remote, site):
    """Stop and remove the site's container, its unit and its account."""
    return _todo("remove")


def site_probe(remote, site):
    """Read the site's state (one SSH round trip)."""
    return _todo("site_probe")


def proxy_install(remote):
    """Install the pinned web proxy binary and its service on the host."""
    return _todo("proxy_install")


def proxy_apply(remote, text):
    """Validate and apply a rendered proxy configuration, keeping the previous one on failure."""
    return _todo("proxy_apply")


def proxy_stop(remote):
    """Stop the web proxy (the last enabled site went offline)."""
    return _todo("proxy_stop")


def proxy_status(remote):
    """The web proxy's state and each domain's certificate state."""
    return _todo("proxy_status")


def ports_apply(remote, proxy, enabled):
    """Open or close ports 80/443 for the host's exposure mode: to all, to the allow list only, or not at all."""
    return _todo("ports_apply")


def tunnel_apply(remote, proxy):
    """Start, restart or stop the outbound tunnel connector for exposure mode 'tunnel'."""
    return _todo("tunnel_apply")


def egress_guard(remote):
    """Load the egress guard that keeps site containers off the host's other local addresses."""
    return _todo("egress_guard")


def quota_set(remote, site):
    """Set the site account's disk quota where the file system has quotas on."""
    return _todo("quota_set")


def php_apply(remote, site):
    """Write the site's php.ini and restart its container gracefully."""
    return _todo("php_apply")


def php_effective(remote, site):
    """The PHP settings in effect inside the site's container (php -i), for the form to show."""
    return _todo("php_effective")


def cache_purge(remote, site):
    """Empty the site's page cache at the proxy."""
    return _todo("cache_purge")


def app_build(remote, site):
    """Run the app's install/build step in its container (the build-time egress allow list only)."""
    return _todo("app_build")


def env_apply(remote, site):
    """Write the app's environment file (0600, as the site's account, content on stdin) and restart it."""
    return _todo("env_apply")


def app_install_step(remote, site, step):
    """Run one install step of the site's app recipe; (ok, text)."""
    return _todo("app_install_step")


def app_undo_step(remote, site, step):
    """Undo one finished install step; (ok, text)."""
    return _todo("app_undo_step")
