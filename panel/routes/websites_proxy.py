"""The web proxy of a host: its status, installing it, applying its configuration, and how sites are reached.

Superadmin only: the proxy is a root-installed service that owns the host's public ports 80 and 443,
and these settings decide who on the internet reaches them (a host's root powers stay with the
superadmin). The host is named by `remote_id` in the query or the body.

Exposure modes (WebsiteProxy.exposure_mode): 'public' opens 80/443 to everyone while a site is
online; 'restricted' opens them only to an allow list (custom networks, held to
validation.website_cidr, and presets: the signed catalog's CDN ranges), and the proxy
trusts a client-address header only from those; 'tunnel' opens nothing and connects out with the
operator's tunnel token. The token is stored encrypted (encrypt_secret), sent to the host on stdin by
the runtime layer, never shown back, never logged; the page sees only whether one is set (OWASP
Secrets Management Cheat Sheet, "Encryption", "8.3 Detection lifecycle"; Logging Cheat Sheet, "Data
to exclude"). A change is applied at once when a site is online: ports and proxy through
websites.reconcile_proxy, the tunnel through ssh_manager.websites.tunnel_apply.
"""
import json
import re
import threading

from flask import abort, current_app, jsonify, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import encrypt_secret
from panel.core.validation import WEBSITE_ALLOW_PRESETS, WEBSITE_EXPOSURE_MODES, WEBSITE_TUNNEL_PROVIDERS, website_cidr
from panel.db.models import RemoteServer, User, Website, WebsiteProxy, db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.security.account_guard import step_up_required
from panel.security.auth import log_action, superadmin_required
from panel.services import websites_allow_url as _wau

MAX_CIDRS = 200
TOKEN_MAX = 4096
S_MODE = "Choose how the websites are reached: public, restricted or tunnel."
S_CIDR = "{cidr} is not a network address like 203.0.113.0/24 or 2001:db8::/32."
S_TOKEN = "Paste the tunnel's token: one line of at most 4096 characters."  # nosec B105 - a sentence for the page, not a credential
S_RESTRICTED_EMPTY = "A restricted host needs at least one network or preset in its allow list."
S_TUNNEL_NO_TOKEN = "A tunnel needs its token."  # nosec B105 - a sentence for the page, not a credential
S_TUNNEL_NO_PROVIDER = "A tunnel needs its provider."
S_APPLIED = "Saved and applied: the web proxy now uses these settings."
S_NOT_APPLIED = "Not saved: the web proxy refused the new settings, so it kept the running ones. {why}"
_UNSET = object()
S_CACHE_BUILDING = ("Saved. The web proxy with the page cache is being built on the host, which takes a few minutes; "
                    "the websites' page caches start when it is done.")
S_TUNNEL_CLOSED = "Ports 80 and 443 are closed: in tunnel mode visitors come in only through the tunnel."


def _remote():
    """The host the request names by host_id (or remote_id), in the query or the body, else 404 (superadmin only)."""
    form = _w.body()
    raw = request.args.get("host_id") or request.args.get("remote_id") or form.get("host_id") or form.get("remote_id")
    try:
        remote = db.session.get(RemoteServer, int(raw))
    except (TypeError, ValueError):
        remote = None
    if remote is None:
        abort(404)
    return remote


def _preset_infos():
    """{preset: {ranges, issued}} of the signed catalog's allow-list presets, as the card lists them."""
    from panel.services import websites_catalog
    out = {}
    for name in WEBSITE_ALLOW_PRESETS:
        try:
            out[name] = websites_catalog.preset_info(name)
        except (KeyError, NotImplementedError):
            continue
    return out


def proxy_json(row):
    """The proxy row as the Settings card reads it: never the tunnel token, only whether one is set."""
    from panel.services.websites_proxy import TUNNEL_PORT
    return {"exposure_mode": row.exposure_mode, "allow_cidrs": row.cidrs(), "allow_presets": row.presets(),
            "presets": list(WEBSITE_ALLOW_PRESETS), "preset_info": _preset_infos(),
            "tunnel_service": "http://localhost:%d" % TUNNEL_PORT, "tunnel_provider": row.tunnel_provider or "",
            "tunnel_token_set": bool(row.tunnel_token_enc),
            "origin_pull_mtls": bool(row.origin_pull_mtls), "custom_trusted": bool(row.custom_trusted),
            "allow_url": row.allow_url or "", "allow_url_nets": row.url_nets(), "allow_url_error": row.allow_url_error or "",
            "allow_url_at": row.allow_url_at.strftime("%Y-%m-%d") if row.allow_url_at else "",
            "allow_url_on": _wau.allowed(), "installed_version": row.installed_version or "",
            "last_error": row.last_error or ""}


def _cidrs(data, problems):
    raw = data.get("allow_cidrs", [])
    raw = raw if isinstance(raw, list) else str(raw or "").replace(",", "\n").split()
    out = []
    for text in raw[:MAX_CIDRS + 1]:
        net = website_cidr(text) if isinstance(text, str) else None
        if net is None:
            problems.append(i18n.tr(S_CIDR, cidr=repr(str(text)[:64])))
        elif net not in out:
            out.append(net)
    if len(raw) > MAX_CIDRS:
        problems.append(i18n.tr("At most {n} networks.", n=MAX_CIDRS))
    return out


def _allow_url(row, data, changes, problems):
    """A new list address from the form: checked (https, port 443, the Outside services switch), or cleared.

    The list itself is read by the route once the change is staged (_read_new_list); an unchanged address is
    not read again here (the daily refresh does).
    """
    url = data.get("allow_url") if isinstance(data.get("allow_url"), str) else ""
    url = url.strip()
    if url == (row.allow_url or ""):
        return
    if not url:
        changes.update(allow_url="", allow_url_nets="[]", allow_url_at=None, allow_url_error="")
        return
    why = _wau.url_problem(url) or ("" if _wau.allowed() else _wau.S_OFF)
    if why:
        problems.append(i18n.tr(why))
    else:
        changes["allow_url"] = url


def _read_new_list(row, changes):
    """Read the list at the address just staged on `row`: "" when it is used, else the sentence refusing the save."""
    if not changes.get("allow_url"):
        return ""
    from panel.core.clock import utcnow
    _changed, why = _wau.refresh(row, utcnow())
    return i18n.tr(why[0], **why[1]) if why else ""


def _choices(data, changes, problems):
    """The tunnel provider from the form, held to its list."""
    for key, allowed in (("tunnel_provider", WEBSITE_TUNNEL_PROVIDERS),):
        if key in data:
            value = _w.field(data, key)
            if value not in allowed:
                problems.append(i18n.tr("{key} must be one of {allowed}.", key=key, allowed=", ".join(a for a in allowed if a)))
            changes[key] = value


def _token(data, changes, problems):
    """The tunnel token, when one was typed: encrypted for the row, or refused (one line, at most TOKEN_MAX)."""
    token = data.get("tunnel_token")
    if not (isinstance(token, str) and token.strip()):
        return
    token = token.strip()
    if len(token) > TOKEN_MAX or any(c in token for c in "\x00\r\n"):
        problems.append(i18n.tr(S_TOKEN))
    else:
        changes["tunnel_token_enc"] = encrypt_secret(token)


def parse_settings(row, data):
    """(changes {column: value}, [problems]) for the proxy settings form; nothing is stored here."""
    problems, changes = [], {}
    mode = _w.field(data, "exposure_mode", row.exposure_mode)
    if mode not in WEBSITE_EXPOSURE_MODES:
        problems.append(i18n.tr(S_MODE))
    changes["exposure_mode"] = mode
    if "allow_cidrs" in data:
        changes["allow_cidrs"] = json.dumps(_cidrs(data, problems))
    if "allow_presets" in data:
        presets = data.get("allow_presets") if isinstance(data.get("allow_presets"), list) else []
        changes["allow_presets"] = json.dumps(sorted({p for p in presets if p in WEBSITE_ALLOW_PRESETS}))
    if "allow_url" in data:
        _allow_url(row, data, changes, problems)
    _choices(data, changes, problems)
    for key in ("origin_pull_mtls", "custom_trusted"):
        if key in data:
            changes[key] = _w.flag(data, key)
    _token(data, changes, problems)
    return changes, problems + _mode_problems(row, changes)


def _allows_nothing(row, changes):
    """Whether a restricted host would be left with no network, preset or list address at all."""
    cidrs = json.loads(changes.get("allow_cidrs", row.allow_cidrs or "[]"))
    presets = json.loads(changes.get("allow_presets", row.allow_presets or "[]"))
    return not cidrs and not presets and not changes.get("allow_url", row.allow_url)


def _mode_problems(row, changes):
    mode = changes.get("exposure_mode", row.exposure_mode)
    if mode == "restricted" and _allows_nothing(row, changes):
        return [i18n.tr(S_RESTRICTED_EMPTY)]
    if mode != "tunnel":
        return []
    # Both are needed: without a provider the apply only stops the connector, while the firewall's
    # public 80/443 rules are taken away for tunnel mode, so the sites would go offline under "applied".
    problems = [] if changes.get("tunnel_provider", row.tunnel_provider) else [i18n.tr(S_TUNNEL_NO_PROVIDER)]
    if not (changes.get("tunnel_token_enc") or row.tunnel_token_enc):
        problems.append(i18n.tr(S_TUNNEL_NO_TOKEN))
    return problems


def _detail(changes):
    """The audit row's words for a settings change: what changed, the token only as "token replaced"."""
    words = []
    for key in sorted(changes):
        if key == "tunnel_token_enc":
            words.append("tunnel token replaced")
        elif key == "allow_url":
            words.append("allow_url=%s" % (_wau.where(changes[key]) if changes[key] else "none"))
        elif not key.startswith("allow_url_"):
            words.append("%s=%s" % (key, changes[key]))
    return ", ".join(words)


_EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")


# The Security settings card's labels, so a refusal names the field the way the card does.
OPTION_LABELS = {"hsts_max_age": "HSTS max-age (seconds)", "access_log_days": "Keep access logs (days)",
                 "max_sites": "Sites per customer", "mem_mb": "Memory per site (MB)",
                 "cpu_milli": "CPU per site (1000 = one core)", "pids": "Processes per site",
                 "disk_mb": "Disk per site (MB)", "max_body_mb": "Largest upload (MB)"}


def _number_option(key, value, low, high):
    ok = isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
    return (value, None) if ok else (None, i18n.tr("{key} must be a whole number from {low} to {high}.",
                                                   key=i18n.Sentence(OPTION_LABELS[key]), low=low, high=high))


def _contact_option(value):
    text = value.strip() if isinstance(value, str) else ""
    if text and (len(text) > 254 or not _EMAIL_RE.fullmatch(text)):
        return None, i18n.tr("The certificate contact is an email address, or empty.")
    return text, None


def _option(key, value):
    """(the value to store for option `key`, None) or (None, the sentence refusing it)."""
    from panel.routes.websites_view import OPTIONS, TLS_CHOICES
    default, low, high = OPTIONS[key]
    if isinstance(default, bool):
        return value is True, None
    if isinstance(default, int):
        return _number_option(key, value, low, high)
    if key == "tls_min":
        return (value, None) if value in TLS_CHOICES else (None, i18n.tr("The minimum TLS version is 1.2 or 1.3."))
    return _contact_option(value)


def parse_options(form):
    """(the global website settings to store {key: value}, [problems]) from the Settings card's `options`.

    Every key is held to its type and range (websites_view.OPTIONS); a value outside OWASP's
    recommendation is stored (the page says so beside the field), never refused for that.
    """
    from panel.routes.websites_view import OPTIONS
    out, problems = {}, []
    for key, value in form.items():
        if key in OPTIONS:
            got, why = _option(key, value)
            if why:
                problems.append(why)
            else:
                out[key] = got
    return out, problems


def _options_detail(values):
    return ", ".join("%s=%s" % (k, "set" if k == "acme_contact" and v else v) for k, v in sorted(values.items()))


def _put_options(values):
    """Store `values` under their config keys; {config key: the value before, or _UNSET} for putting them back."""
    from panel.core.config import load_config, update_config
    from panel.routes.websites_view import config_key
    cfg = load_config()
    before = {config_key(k): cfg.get(config_key(k), _UNSET) for k in values}
    update_config(lambda c: c.update({config_key(k): v for k, v in values.items()}))
    return before


def _restore_options(before):
    from panel.core.config import update_config

    def put_back(cfg):
        for key, value in before.items():
            if value is _UNSET:
                cfg.pop(key, None)
            else:
                cfg[key] = value
    update_config(put_back)


def _apply_options(changed):
    """Apply changed proxy options to every host with an online site: (ok, sentence, [hosts applied]).

    Only the options the proxy's configuration reads (websites_view.PROXY_OPTION_NAMES) are applied; the page
    cache's own switch is applied by its build (cache_build_start). Stops at the first host that refuses.
    """
    from panel.routes.websites_view import PROXY_OPTION_NAMES
    if not {k for k in changed if k != "cache_build"} & set(PROXY_OPTION_NAMES):
        return True, "", []
    hosts = sorted({s.remote_id for s in Website.query.filter_by(enabled=True)})
    done = []
    for rid in hosts:
        remote = db.session.get(RemoteServer, rid)
        ok, said = _w.reconcile_proxy(remote)
        if not ok:
            return False, said, done
        done.append(remote)
    return True, S_APPLIED if done else "", done


def _save_options(form):
    """Store the global website settings and apply the proxy's to every host with an online site.

    A host that refuses the new configuration (its proxy kept the running one) puts every value back, and the
    hosts already applied are applied again with them: the saved settings and the running proxies never disagree.
    """
    values, problems = parse_options(form if isinstance(form, dict) else {})
    if problems:
        return _w.say(400, " ".join(problems))
    from panel.routes.websites_view import options
    old = options()
    changed = {k: v for k, v in values.items() if old.get(k) != v}
    before = _put_options(values)
    ok, said, done = _apply_options(changed)
    if not ok:
        _restore_options(before)
        for remote in done:
            _w.reconcile_proxy(remote)
        log_action(current_user, "website_settings_global", target="websites", success=False,
                   detail="not saved (%s): %s" % (_options_detail(changed), i18n.tr(said)))
        return _w.done(False, i18n.Sentence(S_NOT_APPLIED, why=i18n.tr(said)))
    if "require_2fa" in values:
        current_app.config["WEBSITES_CUSTOMER_2FA"] = values["require_2fa"]
    log_action(current_user, "website_settings_global", target="websites", detail=_options_detail(values))
    started = _cache_turned_on(values, old["cache_build"])
    return _w.done(True, S_CACHE_BUILDING if started else said or "Saved.")


def _cache_turned_on(values, before):
    """Start the page cache's proxy build on every host with a web proxy when the option was just turned on."""
    if not values.get("cache_build") or before:
        return False
    hosts = [p.remote_id for p in WebsiteProxy.query.filter(WebsiteProxy.installed_version != "").all()]
    if hosts:
        cache_build_start(hosts)
    return bool(hosts)


# ── the page cache's proxy ───────────────────────────────────────────────────────────────────────
def cache_build_start(remote_ids):
    """Build the web proxy with the page cache on each host of `remote_ids`, in the background (minutes).

    Started when the Security settings' "Page cache in the web proxy" is turned on, and after the plain proxy is
    installed while it is on (that install puts the plain binary back). The outcome is an audit row, and a
    failure is the proxy row's last_error, which the Security settings card shows.
    """
    app = current_app._get_current_object()
    for rid in remote_ids:
        threading.Thread(target=_cache_build_worker, args=(app, rid, current_user.id), daemon=True).start()


def _cache_build_worker(app, remote_id, uid):
    with app.app_context():
        remote, user = db.session.get(RemoteServer, remote_id), db.session.get(User, uid)
        if remote is None:
            return
        ok, out = _w.host_call(_sw.proxy_status, remote)
        built = bool(ok) and _sw.parse_proxy_status(out)["cache"]
        ok, said = (True, _sw.OK_CACHE_BUILD) if built else _w.host_call(_sw.proxy_install_cache, remote)
        row = _w.proxy_row(remote_id)
        row.last_error = "" if ok else i18n.tr(said)[:200]
        db.session.commit()
        if ok and Website.query.filter_by(remote_id=remote_id, enabled=True).count():
            ok, said = _w.reconcile_proxy(remote)
        log_action(user, "remote_website_proxy_cache", target=remote.name, remote=remote, success=bool(ok),
                   detail="the web proxy with the page cache %s" % (
                       "was already built" if built and ok else "was built and installed" if ok
                       else "failed: %s" % i18n.tr(said)))


def _apply(remote, row):
    """Apply the host's proxy settings now: tunnel, then ports and proxy. -> (ok, sentence).

    In tunnel mode ports 80 and 443 are closed first, whatever becomes of the tunnel. A token the tunnel's provider
    refused, or a connector that did not start, ended the apply before its firewall step, so the public rules of the
    mode before stayed open (the sites still reachable straight at the host) while the saved mode said tunnel. A
    failed apply then says the ports were closed (or why they were not). last_error keeps the tunnel's own sentence,
    which _note_tunnel clears once the connector connects.
    """
    tunnel = row.exposure_mode == "tunnel"
    closed = _w.host_call(_sw.ports_apply, remote, row, False) if tunnel else (True, "")
    ok, said = _w.host_call(_sw.tunnel_apply, remote, row)
    if ok:
        ok, said = _w.reconcile_proxy(remote)
    row.last_error = "" if ok else i18n.tr(said)[:200]
    db.session.commit()
    if tunnel and not ok:
        said = i18n.Sentences(said, S_TUNNEL_CLOSED if closed[0] else closed[1])
    return ok, said


def _note_version(row, status):
    """Record on the proxy row the version the host says is installed ("" when none), as the Websites page reads it."""
    version = str(status.get("version") or "").lstrip("v")[:40] if status.get("installed") else ""
    if row.installed_version != version:
        row.installed_version = version
        db.session.commit()


def _note_tunnel(row, status):
    """Store what the connector's log says of its token: Cloudflare's refusal as last_error, cleared once connected.

    Only the tunnel's own sentences are cleared: another failure (the proxy refused its settings) stays.
    """
    if row.exposure_mode != "tunnel":
        return
    said = {"refused": i18n.tr(_sw.TUNNEL_REFUSED)[:200], "connected": ""}.get(status.get("tunnel_link"))
    ours = {i18n.tr(_sw.TUNNEL_REFUSED)[:200], i18n.tr(_sw.TUNNEL_FAILED)[:200]}
    if said is None or row.last_error == said or (not said and (row.last_error or "") not in ours):
        return
    row.last_error = said
    db.session.commit()


def register(app):
    """The proxy routes."""
    @app.route("/websites/proxy/status")
    @login_required
    @superadmin_required
    def website_proxy_status():
        remote = _remote()
        row = _w.proxy_row(remote.id)
        db.session.commit()
        ok, said = _w.host_call(_sw.proxy_status, remote, row)
        status = _sw.parse_proxy_status(said) if ok else {}
        if ok:
            from panel.routes.websites_domains import apply_certs
            apply_certs(remote, status)
            _note_version(row, status)
            _note_tunnel(row, status)
        online = Website.query.filter_by(remote_id=remote.id, enabled=True).count()
        return jsonify(dict(proxy_json(row), online_sites=online, status_ok=bool(ok), status=status,
                            message="" if ok else i18n.tr(said)))

    @app.route("/websites/proxy/install", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required
    def website_proxy_install():
        remote = _remote()
        ok, said = _w.host_call(_sw.proxy_install, remote)
        if ok:
            from panel.routes.websites_view import options
            from panel.services import websites_catalog
            _note_version(_w.proxy_row(remote.id), {"installed": True, "version": websites_catalog.pins("caddy")["version"]})
            ok, said = _w.host_call(_sw.egress_guard, remote)
            if ok and options()["cache_build"]:
                cache_build_start([remote.id])      # the plain install put the plain binary back
        log_action(current_user, "remote_website_proxy_install", target=remote.name, remote=remote, success=bool(ok),
                   detail="web proxy and egress guard installed" if ok else "failed: %s" % i18n.tr(said))
        return _w.done(ok, said or "The web proxy is installed.")

    @app.route("/websites/proxy/settings", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required
    def website_proxy_settings():
        form = _w.body()
        if isinstance(form.get("options"), dict):
            return _save_options(form["options"])
        remote = _remote()
        row = _w.proxy_row(remote.id)
        exposure = form.get("exposure") if isinstance(form.get("exposure"), dict) else form
        changes, problems = parse_settings(row, exposure)
        if problems:
            db.session.rollback()
            return _w.say(400, " ".join(problems))
        for key, value in changes.items():
            setattr(row, key, value)
        refused = _read_new_list(row, changes)
        if refused:
            db.session.rollback()
            return _w.say(400, refused)
        db.session.commit()
        ok, said = _apply(remote, row)
        read = "; the list read: %d networks" % len(row.url_nets()) if changes.get("allow_url") else ""
        log_action(current_user, "remote_website_proxy_settings", target=remote.name, remote=remote, success=bool(ok),
                   detail=_detail(changes) + read + ("" if ok else "; not applied: %s" % i18n.tr(said)))
        return _w.done(ok, said or "Saved and applied.", proxy=proxy_json(row))

    @app.route("/websites/proxy/options", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required
    def website_proxy_options():
        form = _w.body()
        return _save_options(form.get("options") if isinstance(form.get("options"), dict) else form)

    @app.route("/websites/proxy/apply", methods=["POST"])
    @login_required
    @superadmin_required
    def website_proxy_apply():
        remote = _remote()
        row = _w.proxy_row(remote.id)
        ok, said = _apply(remote, row)
        log_action(current_user, "remote_website_proxy_apply", target=remote.name, remote=remote, success=bool(ok),
                   detail="configuration applied" if ok else "failed: %s" % i18n.tr(said))
        return _w.done(ok, said or "Applied.")
