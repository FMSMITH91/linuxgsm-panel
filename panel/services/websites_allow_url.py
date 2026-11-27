"""A host's web proxy allow list read from an address the superadmin types (Restricted mode, the proxy card).

WHAT IT IS
    A list of networks published at an https address (an office's or another provider's list, one network a
    line), added to the host's allow list beside its presets and typed networks. The address is fetched when
    the card's form is saved with a new one, and again once a day by the update-check thread (tick). A
    list is used only whole: every line must be an IPv4 or IPv6 network (blank lines and lines starting
    with # are skipped), no wider than /8 or /16, at most MAX_NETS of them, in at most MAX_BYTES. A save
    whose list fails that is refused with the reason and the lines at fault; a daily refresh that fails
    keeps the last good list and records why (WebsiteProxy.allow_url_error), which the card shows. A
    changed list is applied to the host at once (firewall and proxy, websites.reconcile_proxy) and every
    refresh that changed something or failed is an audit row. The networks are allow-only unless the
    superadmin also marks the operator's networks as trusted proxies (WebsiteProxy.custom_trusted).

    Nothing is fetched while Settings -> Outside services has its switch off (outside_services
    WEBSITE_ALLOW_URL): a save with a new address is refused in words, and the daily refresh keeps the
    list it has.

SSRF (OWASP Server Side Request Forgery Prevention Cheat Sheet, "Case 2: Application can send requests to
ANY external IP address or domain name", "Available protections" -> "Application layer")
    The address is the superadmin's own choice, so there is no host allowlist; what can be checked is:
    - input validation (url_problem): https only, a host name, port 443 (the checked connect's port), no
      user or password part, no fragment, printable ASCII, at most MAX_URL characters;
    - the block-list check on the resolved addresses, and DNS rebinding: the request goes through
      services/public_https.py, which resolves the name once, connects only when EVERY answer is a public
      unicast address, and connects to those checked answers (the name kept for TLS's SNI and
      certificate check);
    - no redirect is followed, to any host, and no proxy is used (public_https's handlers);
    - the answer is only ever parsed as networks: a size cap, a timeout, and nothing of it is shown but
      the lines at fault (cut short).
    The cheat sheet's "proof of legitimacy" token does not apply: the list's host is a third party that
    cannot be asked to echo one. Only a superadmin, after a fresh step-up, can set the address.
"""
import json
import logging
import time
import urllib.parse
import urllib.request

from panel.core import outside_services as _outside
from panel.core.validation import website_cidr
from panel.services import public_https as _https

_log = logging.getLogger("panel.websites.allow_url")

MAX_URL = 500
MAX_BYTES = 256 * 1024
MAX_NETS = 200
TIMEOUT = 20
# The daily refresh: a list is read again once its last good read is this old; after a failure the
# address is not asked again for RETRY_S, so a host that is down is not asked every half hour.
EVERY_S = 23 * 3600
RETRY_S = 6 * 3600
_UA = "linuxgsm-panel (web proxy allow list)"
_TRIED = {}

S_URL = "The list's address is an https:// address on port 443, without a user name or password."
S_OFF = ("Reading an allow list from an address is turned off in Settings \u2192 Outside services. "
         "Turn it on there, or clear the address.")
S_FETCH = "The list at that address could not be read ({why})."
S_EMPTY = "The list at that address holds no network."
S_TOO_MANY = "The list at that address holds more than {n} networks."
S_BAD_LINES = "Not used: some lines of the list are not networks ({lines})."


def allowed():
    """Whether Settings -> Outside services lets the panel read an allow list from an address."""
    return _outside.enabled(_outside.WEBSITE_ALLOW_URL)


def _plain_text(url):
    """Whether `url` is a string of 1 to MAX_URL printable ASCII characters (no space, no control)."""
    return isinstance(url, str) and 0 < len(url) <= MAX_URL and all(" " < c <= "~" for c in url)


def _https_443(url):
    """Whether `url` is https to a host name on port 443, with no user, password or fragment."""
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        return False
    return p.scheme == "https" and bool(p.hostname) and port in (None, 443) and not (p.username or p.password or p.fragment)


def url_problem(url):
    """Why `url` is not an address the panel reads a list from ("" when it is)."""
    return "" if _plain_text(url) and _https_443(url) else S_URL


def where(url):
    """The address as the audit log keeps it: scheme, host and path, never the query (it may hold a key)."""
    p = urllib.parse.urlsplit(url or "")
    return "%s://%s%s%s" % (p.scheme, p.hostname or "", p.path, "?\u2026" if p.query else "")


def _bad_net(net):
    """Whether canonical network `net` is too wide to come from a list (wider than /8 or /16)."""
    return int(net.rsplit("/", 1)[1]) < (16 if ":" in net else 8)


def parse(text):
    """([canonical networks], [(line number, the line cut short)]) of one list: every line a network or skipped."""
    nets, bad = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        net = website_cidr(line)
        if net is None or _bad_net(net):
            bad.append((number, line[:40]))
        elif net not in nets:
            nets.append(net)
    return nets, bad


def _get(url):
    """GET `url` (url_problem passed): (body bytes, None) or (None, why). Never raises."""
    if url_problem(url):
        return None, "not an allowed address"
    # No redirect, no proxy, public addresses only (services/public_https.py).
    opener = urllib.request.build_opener(*_https.handlers())
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "text/plain, */*"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with opener.open(req, timeout=TIMEOUT) as resp:  # nosec B310 - https only, public addresses only, checked above
            if getattr(resp, "status", 200) != 200:
                return None, "HTTP %s" % resp.status
            body = resp.read(MAX_BYTES + 1)
    except Exception as e:  # noqa: BLE001 - every failure is "could not be read"
        return None, e.__class__.__name__
    if len(body) > MAX_BYTES:
        return None, "larger than %d KB" % (MAX_BYTES // 1024)
    return body, None


def load(url):
    """(the list's canonical networks, None) or (None, the sentence saying why it is not used). Never raises."""
    body, why = _get(url)
    if why:
        return None, (S_FETCH, {"why": why})
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, (S_FETCH, {"why": "not text"})
    nets, bad = parse(text)
    if bad:
        shown = "; ".join("%d: %s" % b for b in bad[:10]) + ("; \u2026" if len(bad) > 10 else "")
        return None, (S_BAD_LINES, {"lines": shown})
    if not nets:
        return None, (S_EMPTY, {})
    if len(nets) > MAX_NETS:
        return None, (S_TOO_MANY, {"n": MAX_NETS})
    return nets, None


def refresh(row, now):
    """Read `row`'s address again and store the outcome on it: (whether its networks changed, why or None).

    A good list replaces the networks and clears the error; a failure keeps the networks it had and is
    recorded in allow_url_error. The caller commits.
    """
    from panel.core import i18n
    nets, why = load(row.allow_url)
    _TRIED[row.id] = time.time()
    if why:
        row.allow_url_error = i18n.tr(why[0], **why[1])[:300]
        return False, why
    changed = nets != row.url_nets()
    row.allow_url_nets, row.allow_url_at, row.allow_url_error = _dumps(nets), now, ""
    return changed, None


def _dumps(nets):
    return json.dumps(nets)


def _due(row, now, now_s):
    """Whether `row`'s list is read again now: its last good read is a day old, and no try in the last RETRY_S."""
    old = row.allow_url_at is None or (now - row.allow_url_at).total_seconds() >= EVERY_S
    return old and now_s - _TRIED.get(row.id, 0) >= RETRY_S


def tick(app):
    """One pass from the update-check thread: refresh each host's list that is due. Never raises."""
    try:
        with app.app_context():
            if allowed():
                _tick_rows()
    except Exception:  # noqa: BLE001 - a background pass: the next one tries again
        _log.warning("allow list refresh failed", exc_info=True)


def _tick_rows():
    from panel.core.clock import utcnow
    from panel.db.models import WebsiteProxy, db
    now, now_s = utcnow(), time.time()
    rows = [r for r in WebsiteProxy.query.filter(WebsiteProxy.allow_url != "").all() if _due(r, now, now_s)]
    for row in rows:
        changed, why = refresh(row, utcnow())
        db.session.commit()
        if changed or why:
            _after_refresh(row, changed, why)


def _after_refresh(row, changed, why):
    """Apply a changed list to its host when it is in use, and write the audit row."""
    from panel.core import i18n
    from panel.db.models import RemoteServer, Website, db
    from panel.routes import websites as _w
    from panel.security.auth import log_action
    remote = db.session.get(RemoteServer, row.remote_id)
    if remote is None:
        return
    ok, said = True, ""
    if changed and row.exposure_mode == "restricted" and Website.query.filter_by(remote_id=remote.id, enabled=True).count():
        ok, said = _w.reconcile_proxy(remote)
        row.last_error = "" if ok else i18n.tr(said)[:200]
        db.session.commit()
    if why:
        detail = "the allow list at %s was not read again; the last good list is kept: %s" % (
            where(row.allow_url), row.allow_url_error)
    else:
        detail = "the allow list at %s changed: %d networks%s" % (
            where(row.allow_url), len(row.url_nets()), "" if ok else "; not applied: %s" % i18n.tr(said))
    log_action(None, "remote_website_proxy_allow_url", target=remote.name, remote=remote,
               success=not why and bool(ok), detail=detail, actor="panel")
