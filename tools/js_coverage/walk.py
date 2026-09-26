"""The walk tools/js_coverage/run.py takes through the panel: which pages, in what order, and what
is done on each beyond pressing every control once.

Ids are serve.py's seed: servers 1 Survival MC (panel host, online), 2 Garry's Mod (panel host,
restart pending), 3 Rust (vps-one, offline), 4 CS2 (vps-one), 5 Valheim (vps-two, host down),
6 ARK (installing), 7 Broken Install (failed); hosts 1 panel-host (local), 2 vps-one, 3 vps-two.

Four passes. The first presses every control on every page and CANCELS every confirmation, so the
seeded world is still there for the next page; a page's FLOWS (flows.py) then do what pressing
each control once cannot. The second switches the account to Spanish with the language picker and
reloads a few pages (i18n.js only runs for a language other than English), then back. The third
goes back round the pages whose confirmations lead somewhere and presses OK — deleting, stopping,
revoking — ending with the page that deletes hosts, because that takes their servers with it. The
last lets the session expire under an open page, which is how every page's poller finds out.
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

# Pressed with OK in the third pass, in this order.
ACCEPT_PAGES = [
    "/server/1/files", "/server/1", "/server/4", "/remote/2/firewall", "/remote/2/manage",
    "/remote/1/manage", "/server-management", "/settings", "/commands", "/global-bans",
    "/account", "/groups", "/users", "/", "/remotes",
]

# Controls never pressed: they end the session this walk is signed in with.
SKIP = ["Sign out", "_acctSignOutAll"]

# The i18n pass: these pages, in Spanish, a few controls each.
I18N_PAGES = ["/", "/server/1", "/remote/2/manage", "/users"]


def _page(d, path, accept=False, limit=250):
    """Exercise one page (and, in the first pass, run its flows); log what was done."""
    t0 = time.monotonic()
    n = d.exercise(path, skip=SKIP, accept=accept, limit=limit)
    flows = [] if accept or path.split("?")[0] in {u for u, _w in d.unreached} \
        else FLOWS.get(path, [])
    for _name, flow in flows:
        if d.path() != path.split("?")[0]:
            d.goto(path)
        flow(d)
    log("- %-22s %3d controls%s%s  %5.1fs" % (
        path, n, ", %d flows" % len(flows) if flows else "", ", confirmed" if accept else "",
        time.monotonic() - t0))


def _pick_language(d, lang):
    """Choose `lang` in the language picker, as a person would; the page reloads in it."""
    d.run("const s = document.querySelector('select[data-lang-select]');"
          "if (!s) return 0; J.setValue(s, %r);"
          "s.dispatchEvent(new Event('change', {bubbles: true})); await J.sleep(1500); return 1;"
          % lang)
    d.goto("/")


def _i18n(d):
    """The pages in Spanish, then back to English."""
    d.goto("/")
    _pick_language(d, "es")
    for p in I18N_PAGES:
        _page(d, p, limit=15)
    _pick_language(d, "en")


def _session_expires(d):
    """End the session under an open page: its next request is refused and it goes to /login."""
    d.goto("/")
    d.cdp.call("Network.clearBrowserCookies")
    d.run("document.dispatchEvent(new Event('visibilitychange')); await J.sleep(1500);"
          "await fetch(window.MOUNT + '/api/servers').catch(() => 0); await J.sleep(1500); return 1;")
    d.wait(1.5)
    log("- session expired: now at %s" % (d.path() or "?"))


def walk(d, only=None):
    """Take the walk: every page, the i18n pass, the confirming pass, and the expiry."""
    for p in [p for p in PAGES if not only or p in only]:
        _page(d, p)
    if not only:
        _i18n(d)
    for p in ACCEPT_PAGES:
        if not only or p in only:
            _page(d, p, accept=True)
    if not only:
        _session_expires(d)
