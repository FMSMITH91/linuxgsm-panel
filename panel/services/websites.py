"""A website's container on its host: the shell text the panel runs as the site's account (scaffold).

Builder W2 fills this in. The signatures below are agreed with the routes (W3) and stay as they are:
each *_sh function returns the bash text to run as the site's account (ssh_manager.websites runs it),
parse_probe reads probe_sh's output, and quadlet renders the site's Quadlet unit text. The hardening
follows panel/services/addons.py (rootless, every capability dropped, no new privileges, read-only
root file system, numeric user, memory and pids limits, image by digest, published on 127.0.0.1 only).
"""
# pylint: disable=unused-argument  # scaffold signatures; the builder that fills them in removes this


def install_sh(account, site):
    """Bash that lays out the site's folders, pulls its pinned image and writes its Quadlet unit."""
    raise NotImplementedError("websites.install_sh is not built yet")


def start_sh(account, site):
    """Bash that starts the site's container."""
    raise NotImplementedError("websites.start_sh is not built yet")


def stop_sh(account, site):
    """Bash that stops the site's container."""
    raise NotImplementedError("websites.stop_sh is not built yet")


def remove_sh(account, site):
    """Bash that stops and removes the site's container and unit (the account is removed by the helper)."""
    raise NotImplementedError("websites.remove_sh is not built yet")


def probe_sh(account, site):
    """Bash that prints the site's state as key=value lines for parse_probe."""
    raise NotImplementedError("websites.probe_sh is not built yet")


def parse_probe(out):
    """probe_sh's output as a dict (state, image, memory and disk in use)."""
    raise NotImplementedError("websites.parse_probe is not built yet")


def quadlet(site, ids, net):
    """The site's Quadlet .container text for numeric `ids` (uid, gid) and network options `net`."""
    raise NotImplementedError("websites.quadlet is not built yet")


def tunnel_quadlet(proxy, ids):
    """The tunnel connector's Quadlet .container text (exposure mode 'tunnel'); its token goes in a 0600 file."""
    raise NotImplementedError("websites.tunnel_quadlet is not built yet")


def php_ini(site):
    """The site's conf.d/zz-panel.ini text: its form values, its Advanced lines, then the panel's hardening."""
    raise NotImplementedError("websites.php_ini is not built yet")


def php_ini_problems(text):
    """What is wrong with an Advanced php.ini text, line by line, as a list of sentences (empty: none)."""
    raise NotImplementedError("websites.php_ini_problems is not built yet")


def object_cache_quadlet(site, ids):
    """The site's object cache (Redis or Valkey) Quadlet text, on the site's own private network."""
    raise NotImplementedError("websites.object_cache_quadlet is not built yet")


def build_sh(account, site):
    """Bash that runs the app's install/build command inside its container as the site's account."""
    raise NotImplementedError("websites.build_sh is not built yet")


def app_quadlet(site, ids, net):
    """A runtime app's Quadlet .container text: the runtime's pinned image, its start command and port."""
    raise NotImplementedError("websites.app_quadlet is not built yet")


def env_file(site):
    """The app's 0600 environment file text from its decrypted variables (KEY=value lines, keys validated)."""
    raise NotImplementedError("websites.env_file is not built yet")


def recipe_steps(recipe):
    """A one-click app recipe's install steps, each one of the fixed step types the panel implements."""
    raise NotImplementedError("websites.recipe_steps is not built yet")


def undo_sh(account, site, step):
    """Bash that undoes one finished install step (the job runs these in reverse on a failure)."""
    raise NotImplementedError("websites.undo_sh is not built yet")
