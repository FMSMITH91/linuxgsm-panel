"""The walk tools/js_coverage/run.py takes through the panel: which pages, in what order, and what
is done on each beyond pressing every control once.

Ids are serve.py's seed: servers 1 Survival MC (panel host, online), 2 Garry's Mod (panel host,
restart pending), 3 Rust (vps-one, offline), 4 CS2 (vps-one), 5 Valheim (vps-two, host down),
6 ARK (installing), 7 Broken Install (failed); hosts 1 panel-host (local), 2 vps-one, 3 vps-two.

Three passes. The first presses every control on every page and CANCELS every confirmation, so the
seeded world is still there for the next page; a page's FLOWS (below) then do what pressing each
control once cannot — type into the console, open a file, drag one in. The second switches the
account to Spanish and reloads a few pages (i18n.js only runs for a language other than English).
The last goes back round the pages whose confirmations lead somewhere and presses OK — deleting,
stopping, revoking — ending with the page that deletes hosts, because that takes their servers
with it.
"""
import time

from driver import log
from flows import FLOWS

PAGES = [
    "/", "/server/1", "/server/2", "/server/3", "/server/4",
    "/server/1/files", "/server/2/files", "/server/7/files",
    "/servers/install", "/remotes",
    "/remote/1/manage", "/remote/2/manage", "/remote/3/manage",
    "/remote/2/firewall", "/remote/1/firewall",
    "/users", "/groups", "/logs", "/account", "/settings", "/notifications", "/tailscale",
    "/server-management", "/commands", "/global-bans", "/terminal/1", "/terminal/2",
]

# Pressed with OK in the last pass, in this order.
ACCEPT_PAGES = [
    "/server/1/files", "/server/1", "/server/4", "/remote/2/firewall", "/remote/2/manage",
    "/remote/1/manage", "/server-management", "/settings", "/commands", "/global-bans",
    "/groups", "/users", "/", "/remotes",
]

# Controls never pressed: they end the session this walk is signed in with.
SKIP = ["Sign out", "_acctSignOutAll"]


def _page(d, path, accept=False, limit=250):
    t0 = time.monotonic()
    n = d.exercise(path, skip=SKIP, accept=accept, limit=limit)
    flows = [] if accept else FLOWS.get(path, [])
    for name, script in flows:
        if d.path() != path.split("?")[0]:
            d.goto(path)
        d.run(script)
    log("- %-22s %3d controls%s%s  %5.1fs" % (
        path, n, ", %d flows" % len(flows) if flows else "", ", confirmed" if accept else "",
        time.monotonic() - t0))


def walk(d, only=None):
    pages = [p for p in PAGES if not only or p in only]
    for p in pages:
        _page(d, p)

    if not only:
        # Spanish: i18n.js translates the page and everything added to it afterwards.
        d.goto("/")
        d.run("await fetch(window.MOUNT + '/set-language/es?ajax=1', {method: 'POST'}); return 1;")
        for p in ("/", "/server/1", "/remote/2/manage", "/users"):
            _page(d, p, limit=15)
        d.run("await fetch(window.MOUNT + '/set-language/en?ajax=1', {method: 'POST'}); return 1;")

    for p in ACCEPT_PAGES:
        if not only or p in only:
            _page(d, p, accept=True)
