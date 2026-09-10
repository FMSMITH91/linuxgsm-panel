"""Per-user UI preferences: dashboard ordering and panel layout.

Four functions that were scattered through app.py between the app factory and the context
processors. They take a user (or an already-loaded prefs dict) and plain data, touch no Flask
globals, and are pure enough to test directly — which they could not be while they sat next to
2,000 lines of unrelated boot code.
"""
import logging
import re

from config import load_config
from models import UI_PREF_KEYS

_log = logging.getLogger("panel.prefs")

_PANEL_KEY_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def _clean_panel_map(raw):
    """A {region: [panel key]} map from a request body, charset- and size-capped. Anything that is
    not a plain lowercase key is dropped rather than rejected: the layout is cosmetic, and a hostile
    or stale body should still leave the user with a sane one."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for region, keys in list(raw.items())[:20]:
        if not (isinstance(region, str) and _PANEL_KEY_RE.match(region) and isinstance(keys, list)):
            continue
        seen = []
        for key in keys[:60]:
            if isinstance(key, str) and _PANEL_KEY_RE.match(key) and key not in seen:
                seen.append(key)
        out[region] = seen
    return out


def _apply_user_order(items, order, key=lambda o: o.id):
    """`items` in a user's saved order: saved ids first in their saved order, then everything else
    in the order it arrived. Ids that no longer exist and items missing from the order are both
    NORMAL (a host was deleted; a server was just added), so neither is an error. An empty or junk
    order returns `items` untouched — that is what makes "no saved layout" mean "ship default".

    The sort is stable, so items the user never ordered keep their relative default order instead of
    being shuffled. Pure and module-level so it is unit-testable with no app context."""
    pos = {}
    for ident in (order or []):
        try:
            num = int(ident)
        except (TypeError, ValueError):
            continue                           # hand-edited blob: skip the junk, keep the rest
        # len(pos), NOT the loop index: positions must stay dense, or a skipped junk entry leaves a
        # gap and the len(pos) fallback below sorts un-ordered items AHEAD of ordered ones.
        pos.setdefault(num, len(pos))          # first occurrence wins; a dupe can't displace it
    if not pos:
        return list(items)
    return sorted(items, key=lambda o: pos.get(key(o), len(pos)))

def _effective_prefs(user, cfg=None):
    """The layout a page should render for `user`: their own saved keys over the install default a
    superadmin published, over the code default (no keys at all).

    Per-KEY, not whole-object: someone who has only ever reordered their stat tiles still gets the
    house host order, instead of the admin default being all-or-nothing. Falling back this way also
    makes "reset" mean "back to the house layout" rather than "back to bare defaults", which is what
    an admin publishing one would expect."""
    try:
        default = (cfg if cfg is not None else load_config()).get("default_ui_prefs") or {}
    except Exception:
        default = {}
    if not isinstance(default, dict):
        default = {}
    prefs = {k: v for k, v in default.items() if k in UI_PREF_KEYS}
    try:
        prefs.update(user.get_ui_prefs() if getattr(user, "is_authenticated", False) else {})
    except Exception:
        _log.debug("reading user ui_prefs failed; using the install default", exc_info=True)
    return prefs

def _panel_layout(prefs, region, default_keys):
    """(visible, hidden) panel keys for one reorderable region, in this user's saved order.

    Only keys the CALLER declares are ever returned. That is the safety property: a saved key can
    never conjure a panel the page did not offer (several are permission-gated), and a panel retired
    in a later version stops appearing the moment it leaves default_keys. Saved-but-unknown keys are
    dropped; known-but-unsaved keys are appended in their default order, so a panel added by a future
    version shows up for existing users instead of silently vanishing.

    Pure, so the ordering rules are unit-testable with no app context."""
    saved = hidden_saved = None
    if isinstance(prefs, dict):
        panels, hidden = prefs.get("panels"), prefs.get("hidden")
        if isinstance(panels, dict):
            saved = panels.get(region)
        if isinstance(hidden, dict):
            hidden_saved = hidden.get(region)
    known = [k for k in (default_keys or [])]
    hidden = [k for k in known if isinstance(hidden_saved, list) and k in hidden_saved]
    order = []
    if isinstance(saved, list):
        for key in saved:
            if key in known and key not in order:
                order.append(key)
    order += [k for k in known if k not in order]
    return [k for k in order if k not in hidden], hidden

def _apply_user_server_order(servers, prefs):
    """`servers` with each host's rows in that user's saved order. The dashboard slices this one
    list per host (`servers|selectattr('remote_id', ...)`), so ordering it per host in a single pass
    is enough — no need to know the host order here, since the slice preserves whatever we produce.

    Hosts with no saved order keep their default order because _apply_user_order is stable and only
    the ids it knows about move. Pure, so it is unit-testable without an app context."""
    per_host = prefs.get("server_order") if isinstance(prefs, dict) else None
    if not isinstance(per_host, dict) or not per_host:
        return list(servers)
    out = list(servers)
    slots = {}                                   # host id -> the positions its servers occupy
    for i, gs in enumerate(out):
        slots.setdefault(gs.remote_id or 0, []).append(i)
    for host_id, idxs in slots.items():
        order = per_host.get(str(host_id))
        if not order:
            continue                             # this host has no saved order: leave it alone
        # Permute a host's members among the slots they ALREADY occupy, so nothing about the
        # surrounding list — including the caller's host ordering — can shift underneath us.
        for slot, gs in zip(idxs, _apply_user_order([out[i] for i in idxs], order)):
            out[slot] = gs
    return out
