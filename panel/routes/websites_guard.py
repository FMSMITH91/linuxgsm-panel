"""Blocked visitors: a site's list and its Unban, the host's guard settings, and the audit of every ban.

A site's list (GET /websites/<id>/blocked) is the host's deny list (services/websites_guard: fail2ban's bans kept
inside the web proxy) narrowed to the addresses banned while asking for one of that site's names: their address,
why (the jail), since when and until when. The ban holds for every site on the host (a visitor that tried one
site's sign-in is kept from all of them), and the page says so. Unban (POST /websites/<id>/blocked/unban) lifts
one of those addresses: fail2ban forgets it (and its firewall ban in public mode) and the proxy's list drops it,
audited. Both need the site's manage permission (site_for, 404 otherwise), as the other per-site routes.

The host's settings (the numbers, the ban times, the allow list) are saved through the proxy card's settings route
(websites_proxy, superadmin), and applied with the proxy's configuration.

AUDIT. fail2ban bans as root at any moment; the helper numbers each ban and unban in a file the panel reads after
the last it recorded (record_events): at each list read and Unban, and on the update-check thread
every 30 minutes, so each ban is an audit row (its own time in the detail) even when nobody opens the list.
"""
from datetime import datetime, timezone

from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n
from panel.db.models import RemoteServer, Website, WebsiteDomain, db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.security.auth import log_action, log_website_action
from panel.services import websites_access as _wa
from panel.services import websites_guard as _wg

CURSOR_KEY = "websites_guard_seq"
S_NOT_BLOCKED = "That address is not blocked on this website."
_KINDS = {"ban": "website_ban", "unban": "website_unban", "flush": "website_unban"}


def _when(epoch):
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _cursor(remote_id):
    from panel.core.config import load_config
    got = load_config().get(CURSOR_KEY) or {}
    value = got.get(str(remote_id)) if isinstance(got, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _set_cursor(remote_id, seq):
    from panel.core.config import update_config

    def put(cfg):
        got = cfg.get(CURSOR_KEY) if isinstance(cfg.get(CURSOR_KEY), dict) else {}
        got[str(remote_id)] = int(seq)
        cfg[CURSOR_KEY] = got
    update_config(put)


def _site_of(remote, host):
    """The site on `remote` that serves `host` (one of its domains), or None."""
    row = (WebsiteDomain.query.join(Website, WebsiteDomain.website_id == Website.id)
           .filter(Website.remote_id == remote.id, WebsiteDomain.domain == host).first())
    return row.website if row is not None else None


def _event_detail(kind, ip, jail, host, at):
    label = _wg.JAIL_LABELS.get(jail, jail)
    if kind == "ban":
        return "%s blocked: %s, on %s, at %s" % (ip, label, host, _when(at))
    if kind == "flush":
        return "every address the %s jail held was unblocked (the jail stopped), at %s" % (jail, _when(at))
    return "%s unblocked: its ban ended, at %s" % (ip, _when(at))


def record_events(remote, events):
    """Write an audit row for each ban event numbered after the last one recorded for `remote`, then move the cursor.

    A release (the panel's own Unban) is audited by its route, with who asked, so it is not written again. Events
    numbered below the cursor mean the host's file started again (the proxy was installed anew): the cursor follows.
    """
    if not events:
        return
    after = _cursor(remote.id)
    if max(e[0] for e in events) < after:
        after = 0
    for seq, at, kind, ip, jail, host in sorted(events):
        if seq <= after or kind not in _KINDS:
            continue
        site = _site_of(remote, host) if host != "-" else None
        detail = _event_detail(kind, ip, jail, host, at)
        if site is not None:
            log_website_action(None, site, _KINDS[kind], detail, kind != "ban")
        else:
            log_action(None, _KINDS[kind], target=ip if ip != "-" else remote.name, detail=detail,
                       success=kind != "ban", remote=remote)
    _set_cursor(remote.id, max(e[0] for e in events))


def read(remote):
    """(ok, entries or a sentence): the host's deny list, its new events audited on the way."""
    ok, got = _w.host_call(_sw.guard_list, remote, _cursor(remote.id))
    if not ok:
        return False, got
    entries, events = got
    record_events(remote, events)
    return True, entries


def tick(app):
    """The update-check thread's pass (every 30 minutes): each host with a web proxy has its new ban events audited."""
    try:
        with app.app_context():
            from panel.db.models import WebsiteProxy
            for row in WebsiteProxy.query.filter(WebsiteProxy.installed_version != "").all():
                remote = db.session.get(RemoteServer, row.remote_id)
                if remote is not None and _sw.runs_websites(remote):
                    read(remote)
    except Exception:  # noqa: BLE001 - a background pass; the next one reads the same events again
        app.logger.debug("website ban audit tick failed", exc_info=True)


def _entry_json(e):
    return {"ip": e["ip"], "jail": e["jail"], "reason": i18n.tr(_wg.JAIL_LABELS.get(e["jail"], e["jail"])),
            "since": _when(e["at"]), "until": _when(e["until"])}


def site_entries(site, entries):
    """The entries of the host's list banned while asking for one of `site`'s names."""
    names = {d.domain for d in site.domains}
    return [e for e in entries if e["host"] in names]


def guard_json(remote_id):
    """What the pages say of the host's guard: on or off, and whether fail2ban took the last apply."""
    from panel.routes.websites import proxy_row
    s = _wg.settings(proxy_row(remote_id).guard)
    state = _sw.GUARD_STATE.get(remote_id) or {}
    return {"enabled": bool(s["enabled"]), "fail2ban": state.get("fail2ban", "")}


def register(app):
    """The blocked visitors routes."""
    @app.route("/websites/<int:site_id>/blocked")
    @login_required
    def website_blocked(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        ok, got = read(site.remote)
        if not ok:
            return _w.say(502, got)
        mine = site_entries(site, got)
        return jsonify({"success": True, "entries": [_entry_json(e) for e in mine], "count": len(mine),
                        "guard": guard_json(site.remote_id)})

    @app.route("/websites/<int:site_id>/blocked/unban", methods=["POST"])
    @login_required
    def website_blocked_unban(site_id):
        site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
        ip = _w.field(_w.body(), "ip").lower()
        ok, got = read(site.remote)
        if not ok:
            return _w.say(502, got)
        if ip not in {e["ip"] for e in site_entries(site, got)}:
            return _w.say(404, S_NOT_BLOCKED)
        ok, said = _w.host_call(_sw.guard_release, site.remote, ip)
        return _w.acted(site, "website_unban", ok, said, "%s unblocked by hand" % ip if ok
                        else "%s not unblocked: %s" % (ip, i18n.tr(said)))
