"""The web proxy of a host: its status, installing it, applying its configuration, and how sites are reached.

Superadmin only: the proxy is a root-installed service that owns the host's public ports 80 and 443,
and these settings decide who on the internet reaches them (a host's root powers stay with the
superadmin). The host is named by `remote_id` in the query or the body.

Exposure modes (WebsiteProxy.exposure_mode): 'public' opens 80/443 to everyone while a site is
online; 'restricted' opens them only to an allow list (custom networks, held to
validation.website_cidr, and presets such as the signed catalog's Cloudflare ranges), and the proxy
trusts a client-address header only from those; 'tunnel' opens nothing and connects out with the
operator's tunnel token. The token is stored encrypted (encrypt_secret), sent to the host on stdin by
the runtime layer, never shown back, never logged; the page sees only whether one is set (OWASP
Secrets Management Cheat Sheet, "Encryption", "8.3 Detection lifecycle"; Logging Cheat Sheet, "Data
to exclude"). A change is applied at once when a site is online: ports and proxy through
websites.reconcile_proxy, the tunnel through ssh_manager.websites.tunnel_apply.
"""
import json
import re

from flask import abort, jsonify, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import encrypt_secret
from panel.core.validation import (WEBSITE_ALLOW_PRESETS, WEBSITE_EXPOSURE_MODES, WEBSITE_ORIGIN_TLS,
                                   WEBSITE_TUNNEL_PROVIDERS, website_cidr)
from panel.db.models import RemoteServer, Website, db
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.security.account_guard import step_up_required
from panel.security.auth import log_action, superadmin_required

MAX_CIDRS = 200
TOKEN_MAX = 4096
S_MODE = "Choose how the websites are reached: public, restricted or tunnel."
S_CIDR = "{cidr} is not a network address like 203.0.113.0/24 or 2001:db8::/32."
S_TOKEN = "Paste the tunnel's token: one line of at most 4096 characters."  # nosec B105 - a sentence for the page, not a credential
S_RESTRICTED_EMPTY = "A restricted host needs at least one network or preset in its allow list."
S_TUNNEL_NO_TOKEN = "A tunnel needs its token."  # nosec B105 - a sentence for the page, not a credential


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


def proxy_json(row):
    """The proxy row as the Settings card reads it: never the tunnel token, only whether one is set."""
    return {"exposure_mode": row.exposure_mode, "allow_cidrs": row.cidrs(), "allow_presets": row.presets(),
            "presets": list(WEBSITE_ALLOW_PRESETS), "tunnel_provider": row.tunnel_provider or "",
            "tunnel_token_set": bool(row.tunnel_token_enc), "origin_tls": row.origin_tls,
            "origin_pull_mtls": bool(row.origin_pull_mtls), "installed_version": row.installed_version or "",
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


def _choices(data, changes, problems):
    """The tunnel provider and origin TLS choice from the form, each held to its list."""
    for key, allowed in (("tunnel_provider", WEBSITE_TUNNEL_PROVIDERS), ("origin_tls", WEBSITE_ORIGIN_TLS)):
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
    _choices(data, changes, problems)
    if "origin_pull_mtls" in data:
        changes["origin_pull_mtls"] = _w.flag(data, "origin_pull_mtls")
    _token(data, changes, problems)
    return changes, problems + _mode_problems(row, changes)


def _mode_problems(row, changes):
    mode = changes.get("exposure_mode", row.exposure_mode)
    if mode == "restricted":
        cidrs = json.loads(changes.get("allow_cidrs", row.allow_cidrs or "[]"))
        presets = json.loads(changes.get("allow_presets", row.allow_presets or "[]"))
        if not cidrs and not presets:
            return [i18n.tr(S_RESTRICTED_EMPTY)]
    if mode == "tunnel" and not (changes.get("tunnel_token_enc") or row.tunnel_token_enc):
        return [i18n.tr(S_TUNNEL_NO_TOKEN)]
    return []


def _detail(changes):
    """The audit row's words for a settings change: what changed, the token only as "token replaced"."""
    words = []
    for key in sorted(changes):
        if key == "tunnel_token_enc":
            words.append("tunnel token replaced")
        else:
            words.append("%s=%s" % (key, changes[key]))
    return ", ".join(words)


_EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")


def _number_option(key, value, low, high):
    ok = isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
    return (value, None) if ok else (None, i18n.tr("{key} must be a whole number from {low} to {high}.",
                                                   key=key, low=low, high=high))


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


def _save_options(form):
    from panel.core.config import update_config
    values, problems = parse_options(form if isinstance(form, dict) else {})
    if problems:
        return _w.say(400, " ".join(problems))
    from flask import current_app
    from panel.routes.websites_view import config_key
    update_config(lambda cfg: cfg.update({config_key(k): v for k, v in values.items()}))
    if "require_2fa" in values:
        current_app.config["WEBSITES_CUSTOMER_2FA"] = values["require_2fa"]
    log_action(current_user, "website_settings_global", target="websites",
               detail=", ".join("%s=%s" % (k, "set" if k == "acme_contact" and v else v) for k, v in sorted(values.items())))
    return _w.done(True, "Saved.")


def _apply(remote, row):
    """Apply the host's proxy settings now: tunnel, then ports and proxy. -> (ok, sentence)."""
    ok, said = _w.host_call(_sw.tunnel_apply, remote, row)
    if ok:
        ok, said = _w.reconcile_proxy(remote)
    row.last_error = "" if ok else i18n.tr(said)[:200]
    db.session.commit()
    return ok, said


def register(app):
    """The proxy routes."""
    @app.route("/websites/proxy/status")
    @login_required
    @superadmin_required
    def website_proxy_status():
        remote = _remote()
        row = _w.proxy_row(remote.id)
        db.session.commit()
        ok, said = _w.host_call(_sw.proxy_status, remote)
        status = _sw.parse_proxy_status(said) if ok else {}
        if ok:
            from panel.routes.websites_domains import apply_certs
            apply_certs(remote, status)
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
            ok, said = _w.host_call(_sw.egress_guard, remote)
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
        db.session.commit()
        ok, said = _apply(remote, row)
        log_action(current_user, "remote_website_proxy_settings", target=remote.name, remote=remote, success=bool(ok),
                   detail=_detail(changes) + ("" if ok else "; not applied: %s" % i18n.tr(said)))
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
