"""Take the walk tools/js_coverage/run.py makes through the panel.

Which pages, in what order, and what is done on each beyond pressing every control once.

Ids are serve.py's seed: servers 1 Survival MC (panel host, online), 2 Garry's Mod (panel host,
restart pending), 3 Rust (vps-one, offline), 4 CS2 (vps-one), 5 Valheim (vps-two, host down),
6 ARK (installing), 7 Broken Install (failed); hosts 1 panel-host (local), 2 vps-one, 3 vps-two.

First the setup wizard, which the seed leaves unfinished. Then four passes. The first presses every
control on every page and CANCELS every confirmation, so the seeded world is still there for the
next page; a page's FLOWS (flows.py) then do what pressing each control once cannot. The second
switches the account to Spanish with the language picker and reloads a few pages (i18n.js only runs
for a language other than English), then back. The third goes back round the pages whose
confirmations lead somewhere and presses OK — deleting, stopping, revoking — ending with the page
that deletes hosts, because that takes their servers with it. The last turns on two-factor sign-in
(it ends on the backup codes page) and then lets the session expire under an open page, which is
how every page's poller finds out.

CI walks it in parts (run.py --part i/n), one browser and one freshly seeded panel each, and merges
their LCOV (merge.py). A part owns whole units (`units()`): a page, with its flows and, when it is on
ACCEPT_PAGES, its confirming pass (that pass presses only the controls the page's first pass found
opening a confirmation, so the two must share one browser session); the i18n pass; and the end
(two-factor, then the expiry, which signs the session out and so comes last). Inside a part every
unit keeps its place in the order above, so the confirming pass still ends with the page that
deletes hosts.
"""
import time

from driver import log
from flows import FLOWS, setup_wizard, two_factor

PAGES = [
    "/", "/server/1", "/server/2", "/server/3", "/server/4",
    "/server/1/files", "/server/2/files", "/server/7/files",
    "/servers/install", "/remotes",
    "/remote/1/manage", "/remote/2/manage", "/remote/3/manage",
    "/users", "/groups", "/logs", "/account", "/settings", "/notifications", "/tailscale",
    "/server-management", "/commands", "/global-bans", "/terminal/1", "/terminal/2", "/databases",
]

# Pressed with OK in the third pass, in this order.
ACCEPT_PAGES = [
    "/server/1/files", "/server/1", "/server/4", "/remote/2/manage",
    "/remote/1/manage", "/server-management", "/settings", "/commands", "/global-bans",
    "/account", "/groups", "/users", "/", "/remotes",
]

# Controls never pressed: they end the session this walk is signed in with, (Transfer ownership: its
# fold toggle and its form, on the panel owner's Account page) would hand the panel away, change a
# database's contents, or (the Account page's alerts buttons) would ask the browser for notification
# permission, subscribe it to a real push service or send a push.
SKIP = ["Sign out", "_acctSignOutAll", "Transfer ownership", "/account/owner/transfer",
        # The Databases manager's changes: a new database, a row saved, a statement run, a dump made.
        "dbmAdd", "dbmSaveRow", "dbmRunSql", "dbmDump", "dbmUpload",
        "push-enable", "push-disable", "push-test", "/account/push/devices/"]
# ...and never confirmed: each asks the panel to reboot the host it runs on, restore over its own
# database, update, re-bind or repair itself. Faked or not, the panel then behaves as though that
# were under way (a restore really does replace the throwaway database the walk is signed in to),
# which is not a state the pages after it should be measured in.
# (A host reboot has no confirmDialog to accept any more: its own dialog's buttons all say "reboot",
# and helpers.js never presses a control whose text does.)
SKIP_CONFIRMING = SKIP + ["restoreBackup", "doPanelUpdate", "switchPanelBranch",
                          "changePanelBinding", "repairPanel"]

# The i18n pass: these pages, in Spanish, a few controls each.
I18N_PAGES = ["/", "/server/1", "/remote/2/manage", "/users"]

# The two units of the walk that are not a page of PAGES (see units()).
I18N, END = "(i18n pass)", "(two-factor, then the expiry)"

# Seconds each unit took in CI (pull request #613's js coverage job, 2026-11-26: a page's first
# pass and flows plus its confirming pass), which part_units() balances the parts by. A unit that
# is not here (a page added since) counts NEW_UNIT_SECONDS until the table is measured again.
UNIT_SECONDS = {
    "/": 49, "/server/1": 68, "/server/2": 20, "/server/3": 14, "/server/4": 54,
    "/server/1/files": 148, "/server/2/files": 33, "/server/7/files": 27, "/servers/install": 14,
    "/remotes": 85, "/remote/1/manage": 64, "/remote/2/manage": 108, "/remote/3/manage": 46,
    "/users": 27, "/groups": 76, "/logs": 8, "/account": 41, "/settings": 35, "/notifications": 13,
    "/tailscale": 43, "/server-management": 153, "/commands": 18, "/global-bans": 10,
    "/terminal/1": 6, "/terminal/2": 6, "/databases": 7, I18N: 158, END: 15,
}
NEW_UNIT_SECONDS = 30


def units():
    """Return the units a part of the walk can own, in walk order: each page, the i18n pass, the end."""
    return PAGES + [I18N, END]


def part_units(part, parts):
    """Return the units part `part` of `parts` (1-based) walks: every unit is in exactly one part.

    Heaviest unit first, each to the part with the least time so far (the lowest part on a tie), so
    every part of a run computes the same split.
    """
    if not 1 <= part <= parts:
        raise ValueError("part %d of %d" % (part, parts))
    order = units()
    totals, owner = [0] * parts, {}
    for unit in sorted(order, key=lambda u: (-UNIT_SECONDS.get(u, NEW_UNIT_SECONDS), order.index(u))):
        k = min(range(parts), key=lambda i: (totals[i], i))
        totals[k] += UNIT_SECONDS.get(unit, NEW_UNIT_SECONDS)
        owner[unit] = k + 1
    return [u for u in order if owner[u] == part]


def _page(d, path, accept=False, limit=250):
    """Exercise one page (and, in the first pass, run its flows); log what was done."""
    t0 = time.monotonic()
    n = d.exercise(path, skip=SKIP_CONFIRMING if accept else SKIP, accept=accept, limit=limit)
    flows = [] if accept or path.split("?")[0] in {u for u, _w in d.unreached} \
        else FLOWS.get(path, [])
    for name, flow in flows:
        if d.path() != path.split("?")[0]:
            d.goto(path)
        _run_flow(d, path, name, flow)
    log("- %-22s %3d controls%s%s  %5.1fs" % (
        path, n, ", %d flows" % len(flows) if flows else "", ", confirmed" if accept else "",
        time.monotonic() - t0))


def _run_flow(d, path, name, flow):
    """Run one flow; one that breaks is reported and the walk goes on without it.

    A flow is the harness's code, not the panel's: when it breaks (an element renamed, a request
    refused) the cost is the coverage it would have produced, which the report shows. It must not
    take the rest of the measurement with it.
    """
    try:
        flow(d)
    except Exception as e:  # noqa: BLE001 - any failure of a flow is reported the same way
        d.flow_errors.append((path, name, "%s: %s" % (type(e).__name__, str(e)[:200])))
        log("  ! %s: flow %s failed: %s" % (path, name, d.flow_errors[-1][2]))


def _pick_language(d, lang):
    """Choose `lang` in the language picker, as a person would; the page reloads in it."""
    d.run("const s = document.querySelector('select[data-lang-select]');"
          "if (!s) return 0; J.setValue(s, %r);"
          "s.dispatchEvent(new Event('change', {bubbles: true})); await J.sleep(1500); return 1;"
          % lang)
    d.goto("/")


def _i18n(d):
    """Walk a few pages in Spanish, then switch back to English."""
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


def chosen_units(only=None, part_list=None):
    """Return the units to walk: `part_list` (all of them when None), cut down to the pages `only` names."""
    chosen = set(units() if part_list is None else part_list)
    if only:
        chosen &= set(only)
    return chosen


def walk(d, only=None, part_list=None):
    """Take the walk: the wizard, every page, i18n, the confirming pass, 2FA, and the expiry.

    `only` (page paths) or `part_list` (part_units()) narrows it; the wizard always runs.
    """
    chosen = chosen_units(only, part_list)
    # Always, even for --only: until the wizard is done every page redirects to it.
    _run_flow(d, "/setup", "wizard", setup_wizard)
    for p in PAGES:
        if p in chosen:
            _page(d, p)
    if I18N in chosen:
        _i18n(d)
    for p in ACCEPT_PAGES:
        if p in chosen:
            _page(d, p, accept=True)
    if END in chosen:
        _run_flow(d, "/account/2fa/enable", "two-factor", two_factor)
        _session_expires(d)
