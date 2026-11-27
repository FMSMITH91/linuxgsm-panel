"""The Updates page: every update waiting, in one list, the nightly window's settings, and one history.

GET /updates              the page (updates.html, js/updates.js), for anyone who can see a group below.
GET /api/updates          {groups, count, safe, settings, history}: what this viewer may see, read from what the
                          panel already holds (services/updates). A row's action is its item's own route.
GET /api/updates/count    the nav's count (cached per viewer for a minute).
POST /api/updates/window  the window's start and end (superadmin).
POST /api/updates/auto    automatic updates on or off for one item (who may update that item).
POST /api/updates/safe    "Update everything safe now": every listed update this viewer may run that kicks no
                          player and needs no reboot (websites, add-ons on an empty server, LinuxGSM's
                          update-lgsm), one at a time in the background, each through its own code
                          (services/updates_auto, routes/server_detail._run_action). Confirmed with the password
                          (step-up, as an add-on's Update is): it runs new images as the servers' accounts.

Who sees what: the panel's update and the panel host's packages a superadmin; another host's packages who may
manage it (remote_vps.os_update_hosts); a game server's LinuxGSM who may run update-lgsm on it; its add-ons
who holds Manage add-ons on it; a website whoever may see it (a customer their own sites), its Update now only
who administers it.
"""
import threading

from flask import jsonify, render_template, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.http import _json_body
from panel.db.models import AuditLog, GameServer, db
from panel.security.account_guard import step_up_required
from panel.security.auth import (MANAGE_ADDONS, MANAGE_REMOTES, MANAGE_WEBSITES, VIEW_WEBSITES, _perm_for_action,
                                 get_user_servers, has_permission, log_action, superadmin_required)
from panel.services import updates as U, updates_auto as UA, websites_access as _wa

HISTORY_ACTIONS = ("panel_self_update", "os_update_run", "remote_os_update", "update-lgsm_server", "update_server",
                   "force-update_server", "addon_update", "website_update", "update_skipped")
HISTORY_MAX = 40
_LGSM = "update-lgsm"
S_NOTHING_SAFE = "Nothing to update that is safe to run now."
S_SAFE_STARTED = "Updating {n} item(s) one at a time. The history below shows each one as it ends."
S_DENIED = "You can't change that."


# ── who may see what ───────────────────────────────────────────────────────────────────────────
def _may_addons(user):
    return user.is_superadmin or has_permission(user, MANAGE_ADDONS)


def _may_lgsm(user):
    return user.is_superadmin or has_permission(user, _perm_for_action(_LGSM))


def may_open(user):
    """Whether `user` sees any group of the page (the nav entry shows only then)."""
    if not getattr(user, "is_authenticated", False):
        return False
    return bool(user.is_superadmin or has_permission(user, MANAGE_REMOTES) or _may_addons(user)
                or _may_lgsm(user) or _wa.can_open_page(user))


def nav_url():
    """updates_nav(): the page's address when the viewer may open it, else ''."""
    try:
        return url_for("updates_page") if may_open(current_user) else ""
    except Exception:  # noqa: BLE001 - the sidebar never breaks a page
        db.session.rollback()
        return ""


# ── the rows ───────────────────────────────────────────────────────────────────────────────────
def _when_auto(auto, security, cfg):
    if auto:
        return U.tr("By itself tonight at {at} (the host's clock).", at=cfg["start"])
    if security:
        return U.tr("A security update: it installs by itself tonight at {at}, though automatic updates are off "
                    "for it.", at=cfg["start"])
    return U.tr("Automatic updates are off for it: it waits for Update now.")


def _row(kind, ref, name, **kw):
    row = {"kind": kind, "ref": ref, "name": name, "host": "", "what": [], "notes": [], "cost": "", "security": False,
           "safe": False, "auto": None, "auto_editable": False, "when": "", "action": None, "link": ""}
    row.update(kw)
    return row


def _panel_rows(user):
    from panel.ops import system_ops as so
    st = so.panel_update_cached() if user.is_superadmin else None
    if not st or not st.get("update_available"):
        return []
    ver = "%s (%s)" % (st.get("remote_version") or "", (st.get("target_sha") or st.get("remote_sha") or "")[:7])
    return [_row("panel", "panel", "LinuxGSM Panel", what=[U.tr("Update available: {version}", version=ver)]
                 + [c[:120] for c in (st.get("changes") or [])[:8]], cost=U.tr(U.COST_PANEL),
                 when=U.tr("Waits for Update now: the panel never updates itself."),
                 action={"href": url_for("server_management", update="panel") + "#updates"},
                 link=url_for("server_management") + "#updates")]


def _os_rows(user):
    if not (user.is_superadmin or has_permission(user, MANAGE_REMOTES)):
        return []
    from panel.core.panel_state import _os_update_seen
    from panel.routes.remote_vps import os_update_hosts
    rows = []
    for h in os_update_hosts(user):
        pkgs = (_os_update_seen.get(h["id"]) or {}).get("packages") or []
        names = [p.get("label") or p.get("name", "?") for p in pkgs][:10]
        what = [U.tr("{n} package(s), {sec} of them security updates.", n=h["count"], sec=h["security"])]
        rows.append(_row("os", "os:%d" % h["id"], h["name"], what=what + ([", ".join(names)] if names else []),
                         security=bool(h["security"]), cost=U.tr(U.COST_OS),
                         when=U.tr("Security packages install by themselves where automatic security updates are on "
                                   "(the host's page says); the rest wait for Update now."),
                         action={"href": h["url"] + "?update=os#os-updates"}, link=h["url"]))
    return rows


def _servers(user):
    return [gs for gs in get_user_servers(user) if gs.installed]


def _lgsm_rows(user, servers):
    if not _may_lgsm(user):
        return []
    from panel.routes import _lgsm_update
    rows = []
    for gs in servers:
        info = U.lgsm_seen(gs.id)
        if not info.get("behind"):
            continue
        notes = [{"title": r["tag"], "url": r["url"]} for r in _lgsm_update.notes_behind(info)][:6]
        rows.append(_row("lgsm", "lgsm:%d" % gs.id, gs.name, host=gs.remote.display_name if gs.remote else "",
                         what=[U.tr("LinuxGSM {old} to {new}.", old=info["release"], new=info["latest"])], notes=notes,
                         cost=U.tr(U.COST_LGSM), safe=True,
                         when=U.tr("By itself: LinuxGSM's own weekly job, Sundays at 05:30 (the host's clock)."),
                         action={"post": url_for("api_server_action", server_id=gs.id), "body": {"action": _LGSM}},
                         link=url_for("server_detail", server_id=gs.id)))
    return rows


def _addon_rows(user, servers, cfg, sec):
    if not _may_addons(user):
        return []
    from panel.services import addons as _ad
    return [_addon_row(gs, k, seen, cfg, sec) for gs in servers for k, seen in sorted(U.addons_seen(gs.id).items())
            if seen.get("reason") == "image" and k in _ad.CATALOG]


def _addon_row(gs, k, seen, cfg, sec):
    """The row of add-on `k` on server `gs`, whose image differs from the catalog's (`seen`: note_addons's)."""
    from panel.services import addons as _ad
    ref, security = "addon:%d:%s" % (gs.id, k), k in sec["addons"]
    auto = U.auto_on(ref, cfg)
    what = [U.tr("{old} to {new}.", old=seen.get("version") or "?",
                 new=seen.get("new") or U.tr("a newer version of the add-on"))]
    return _row("addon", ref, "%s · %s" % (_ad.CATALOG[k]["name"], gs.name),
                host=gs.remote.display_name if gs.remote else "",
                what=what + ([sec["note"]] if security and sec["note"] else []),
                notes=[{"title": U.tr("Release notes"), "url": _ad.CATALOG[k]["source"] + "/releases"}],
                cost=U.tr(U.COST_ADDON), safe=True, security=security, auto=auto, auto_editable=True,
                when=_when_auto(auto, security, cfg),
                action={"post": url_for("api_server_addon_update", server_id=gs.id, addon_id=k), "step_up": True},
                link=url_for("server_detail", server_id=gs.id))


def site_changes(site):
    """What a website's Update brings, in the viewer's words ([] when nothing)."""
    from panel.routes import websites as _w
    from panel.services import websites as _svc
    if not _w.update_available(site):
        return []
    out = []
    if site.image_digest != _w.current_image(site):
        out.append(U.tr("A newer signed image of its software: base system and security fixes."))
    if site.image_key != _svc.SITE_FILES_REV:
        out.append(U.tr("New server settings from the panel for its container."))
    return out


def site_schedule(site, cfg=None, sec=None):
    """{"auto", "security", "at", "when"} of a website: whether and when the nightly window updates it."""
    cfg = cfg or U.settings()
    sec = sec or U.security()
    ref = "website:%d" % site.id
    auto, security = U.auto_on(ref, cfg), U.site_part(site) in sec["sites"]
    return {"auto": auto, "security": security, "at": cfg["start"], "when": _when_auto(auto, security, cfg),
            "note": "" if auto else U.tr(U.S_AUTO_OFF_NOTE)}


def _site_rows(user, cfg, sec):
    sites = _wa.visible_sites(user, VIEW_WEBSITES).all()
    admin = {s.id for s in _wa.visible_sites(user, MANAGE_WEBSITES).all()} if sites else set()
    rows = []
    for site in sites:
        what = site_changes(site)
        if not what:
            continue
        sched = site_schedule(site, cfg, sec)
        rows.append(_row("website", "website:%d" % site.id, site.name, what=what
                         + ([sec["note"]] if sched["security"] and sec["note"] else []),
                         cost=U.tr(U.COST_SITE), safe=True, security=sched["security"], auto=sched["auto"],
                         auto_editable=site.id in admin, when=sched["when"],
                         action={"post": url_for("website_update_image", site_id=site.id)} if site.id in admin else None,
                         link=url_for("website_page", site_id=site.id)))
    return rows


GROUPS = (("panel", "Panel"), ("os", "Host system"), ("lgsm", "Game servers"), ("addon", "Add-ons"),
          ("website", "Websites"))


def collect(user):
    """{"groups": [{key, title, items}], "count"}: every update `user` may see, grouped as the page shows them."""
    cfg, sec = U.settings(), U.security()
    servers = _servers(user) if (_may_lgsm(user) or _may_addons(user)) else []
    rows = (_panel_rows(user) + _os_rows(user) + _lgsm_rows(user, servers) + _addon_rows(user, servers, cfg, sec)
            + _site_rows(user, cfg, sec))
    groups = [{"key": k, "title": i18n.tr(t), "items": [r for r in rows if r["kind"] == k]} for k, t in GROUPS]
    return {"groups": [g for g in groups if g["items"]], "count": len(rows)}


def history(user):
    """The last HISTORY_MAX update rows of the audit log that `user` may read (audit.audit_scope)."""
    from panel.routes.audit import audit_scope
    q = AuditLog.query.filter(AuditLog.action.in_(HISTORY_ACTIONS))
    scope = audit_scope(user)
    if scope is not None:
        q = q.filter(scope)
    return [{"at": r.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if r.timestamp else "", "who": r.username or "",
             "action": r.action, "target": r.target or "", "ok": bool(r.success), "detail": (r.detail or "")[:300]}
            for r in q.order_by(AuditLog.id.desc()).limit(HISTORY_MAX).all()]


def _settings_json(user, cfg):
    return {"start": cfg["start"], "end": cfg["end"], "can_edit": bool(user.is_superadmin),
            "owasp_auto": U.OWASP_AUTO, "off": len(cfg["off"])}


# ── Update everything safe now ─────────────────────────────────────────────────────────────────
def _safe_rows(user):
    """The listed rows `user` may start that kick no player and need no reboot."""
    from panel.services.monitoring import _cached_player_count
    out = []
    for g in collect(user)["groups"]:
        for r in g["items"]:
            if not (r["safe"] and r["action"] and "post" in r["action"]):
                continue
            if r["kind"] == "addon" and (_cached_player_count(int(r["ref"].split(":")[1])) or 0) > 0:
                continue        # an add-on on a server with players on waits (as the nightly window does)
            out.append(r["ref"])
    return out


def _run_safe(app, user_id, refs):
    """Run each update in `refs` in turn, as the viewer who asked (their audit rows)."""
    from panel.db.models import User
    with UA.RUN_LOCK, app.app_context():      # never beside the nightly window's own pass
        user = db.session.get(User, user_id)
        for ref in refs:
            try:
                _run_one(app, user, ref)
            except Exception:  # noqa: BLE001 - one item failing never stops the next
                db.session.rollback()
                app.logger.debug("update %s failed", ref, exc_info=True)
        U.forget_counts()


def _run_one(app, user, ref):
    from panel.db.models import Website
    kind, _sep, rest = ref.partition(":")
    if kind == "website":
        site = db.session.get(Website, int(rest))
        if site is not None:
            UA.update_site(app, site, user.username, user)
        return
    gs = db.session.get(GameServer, int(rest.split(":")[0]))
    if gs is None:
        return
    if kind == "addon":
        UA.update_addon(app, gs, rest.split(":", 1)[1], user.username)
    elif kind == "lgsm":
        from panel.routes.server_detail import _run_action
        _run_action(app, gs, gs.remote, _LGSM, user)


def _auto_target(ref, on):
    """(the viewer's row `ref`, None) when they may switch its automatic updates to `on`, else (None, the refusal).

    Only a row the viewer sees with its switch (who may update that item): anything else is refused.
    """
    if not isinstance(on, bool) or not isinstance(ref, str) or not U.REF_RE.match(ref):
        return None, (jsonify({"success": False, "message": i18n.tr(U.S_BAD_REF)}), 400)
    row = next((r for g in collect(current_user)["groups"] for r in g["items"] if r["ref"] == ref), None)
    if row is None or not row["auto_editable"]:
        return None, (jsonify({"success": False, "message": i18n.tr(S_DENIED)}), 403)
    return row, None


def register(app, supervise):
    """The page, its API, the nav entry (updates_nav) and the nightly window's loop."""
    app.jinja_env.globals["updates_nav"] = nav_url

    @app.route("/updates")
    @login_required
    def updates_page():
        if not may_open(current_user):
            return render_template("updates.html", allowed=False), 404
        return render_template("updates.html", allowed=True)

    @app.route("/api/updates")
    @login_required
    def api_updates():
        if not may_open(current_user):
            return jsonify({"success": False, "message": i18n.tr(S_DENIED)}), 404
        got = collect(current_user)
        cfg = U.settings()
        return jsonify({"success": True, "groups": got["groups"], "count": got["count"],
                        "settings": _settings_json(current_user, cfg), "history": history(current_user)})

    @app.route("/api/updates/count")
    @login_required
    def api_updates_count():
        if not may_open(current_user):
            return jsonify({"count": 0})
        return jsonify({"count": U.count_cached(current_user.id, lambda: collect(current_user)["count"])})

    @app.route("/api/updates/window", methods=["POST"])
    @login_required
    @superadmin_required
    def api_updates_window():
        data = _json_body()
        why = U.save_window(data.get("start"), data.get("end"))
        if why:
            return jsonify({"success": False, "message": i18n.tr(why)}), 400
        log_action(current_user, "updates_window", target="automatic updates",
                   detail="%s-%s" % (data["start"], data["end"]))
        return jsonify({"success": True, "message": i18n.tr("Saved.")})

    @app.route("/api/updates/auto", methods=["POST"])
    @login_required
    def api_updates_auto():
        data = _json_body()
        ref, on = data.get("ref"), data.get("on")
        row, refused = _auto_target(ref, on)
        if refused:
            return refused
        U.set_auto(ref, on)
        log_action(current_user, "updates_auto", target=row["name"], detail="%s %s" % (ref, "on" if on else "off"))
        U.forget_counts()
        return jsonify({"success": True, "auto": on, "note": "" if on else i18n.tr(U.S_AUTO_OFF_NOTE)})

    @app.route("/api/updates/safe", methods=["POST"])
    @login_required
    @step_up_required
    def api_updates_safe():
        if not may_open(current_user):
            return jsonify({"success": False, "message": i18n.tr(S_DENIED)}), 404
        refs = _safe_rows(current_user)
        if not refs:
            return jsonify({"success": True, "started": 0, "message": i18n.tr(S_NOTHING_SAFE)})
        log_action(current_user, "updates_safe", target="updates", detail=", ".join(refs)[:400])
        threading.Thread(target=_run_safe, args=(app, current_user.id, refs), daemon=True).start()
        return jsonify({"success": True, "started": len(refs), "message": i18n.tr(S_SAFE_STARTED, n=len(refs))}), 202

    supervise("auto-updates", lambda: UA.loop(app))
