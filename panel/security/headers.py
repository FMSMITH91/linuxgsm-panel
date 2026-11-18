"""The security headers that only mean something on a response a browser shows as a page.

Content-Security-Policy, X-Frame-Options and Permissions-Policy govern a DOCUMENT: what its scripts
may load and run, whether another site may frame it, which browser features it may ask for. A
browser never makes a document of a JSON answer, a stylesheet, a script, an image or a font: it
hands them to the page that asked (and X-Content-Type-Options: nosniff, still on every response,
stops it guessing otherwise). On those types the three headers protected nothing and cost ~400
bytes per response, about a quarter of every dashboard poll over HTTP/1.1; the CSP also carries the
per-request nonce, so it never repeats for HTTP/2's header table either.

So the full set is kept on everything a browser could show as a document: HTML, SVG and XML (which
can run script when opened), plain text, a download, and any type not named here. The types in
_INERT_TYPES get only INERT_CSP instead, ~45 bytes in place of ~400: the API-response policy OWASP
recommends, so that an answer opened on its own can load nothing, run nothing and be framed by no one.
Cross-Origin-Resource-Policy goes on every response: it is what stops another site loading one.
X-Content-Type-Options, Referrer-Policy and X-Robots-Tag stay on every response (app.py): the last
exists for the responses that are NOT HTML, where no <meta> tag can say it.
"""

_INERT_TYPES = frozenset((
    "application/json", "application/manifest+json",
    "text/css", "text/javascript", "application/javascript",
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon",
    "font/woff", "font/woff2", "font/ttf", "font/otf", "application/font-woff",
))

# For a response that never renders as a page (OWASP REST Security Cheat Sheet, "Security headers").
INERT_CSP = "default-src 'none'; frame-ancestors 'none'"

# The panel uses none of these powerful browser features, so a page is denied them outright: a
# defence-in-depth limit on what an injected or compromised script could reach for (OWASP HTTP Headers
# Cheat Sheet, "Permissions-Policy": disable all the features the site does not need).
PERMISSIONS_POLICY = ("camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=(), "
                      "accelerometer=(), gyroscope=(), magnetometer=(), serial=()")
# Only features browsers recognise: Chrome logs "Unrecognized feature" for each unknown one on every
# page (`bluetooth` was dropped for that; a real browser on the test box logged it).

# OWASP HTTP Headers Cheat Sheet, "Strict-Transport-Security (HSTS)": two years. Without `preload`:
# submitting a name to the browsers' preload list is permanent and belongs to whoever owns the domain
# (a *.ts.net name or the operator's own), not to the panel. Sent only for trusted TLS (app.py).
HSTS = "max-age=63072000; includeSubDomains"

# The browsing-context and resource isolation the HTTP Headers Cheat Sheet recommends. The panel opens
# no window it needs to script (its target=_blank links carry rel="noopener noreferrer") and nothing
# loads its responses from another origin (Tailscale Serve and a reverse proxy are the same origin to
# the browser), so both can be as strict as there is.
COOP = "same-origin"
CORP = "same-origin"
# HTTP Headers Cheat Sheet, "Cross-Origin-Embedder-Policy (COEP)": require-corp, so a page loads only
# same-origin resources or ones that opt in. Every resource a panel page loads is its own (the CSP
# allows 'self' and data: only; the vendored libraries are served from /static), and a same-origin
# resource needs no opt-in, so nothing changes for the panel's own pages. A download is a navigation,
# which COEP does not restrict, and the alerts service worker (static/push/sw.js, a script response,
# so it gets no COEP) fetches nothing. CORP stays same-origin, stricter than the cheat sheet's
# same-site: no other site, a sibling subdomain included, has a reason to load a panel response.
COEP = "require-corp"

# What the after-request cache step gives a response that set no Cache-Control of its own (app.py).
PRIVATE_REVALIDATE = "no-cache, private"
# OWASP HTTP Headers Cheat Sheet, "Cache-Control": no-store for sensitive responses. Every JSON answer
# is one (server state, a user's details, a generated password, a debug report), and no page reads a
# JSON answer back from the cache. HTML pages keep PRIVATE_REVALIDATE so the back/forward cache still
# works (panel.js re-checks the session on a restore), except a page that shows a secret (no_store).
NO_STORE = "no-store"


def renders_as_page(resp):
    """Whether a browser could show `resp` as a document (any type not known to be inert)."""
    return (resp.mimetype or "").lower() not in _INERT_TYPES


def set_page_headers(resp, csp):
    """Set the document headers on a page and the inert ones on the rest; no-store on JSON.

    A page gets CSP (csp() builds it), X-Frame-Options DENY (the CSP's frame-ancestors 'none' for the
    browsers that predate it: OWASP Clickjacking Defense Cheat Sheet), Permissions-Policy,
    Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy and X-DNS-Prefetch-Control off (HTTP
    Headers Cheat Sheet: the page's links are not all the panel's own). Every response gets Cross-Origin-Resource-Policy. A JSON answer
    left at PRIVATE_REVALIDATE by the cache step (which runs before this one) becomes NO_STORE.
    """
    resp.headers.setdefault("Cross-Origin-Resource-Policy", CORP)
    if not renders_as_page(resp):
        resp.headers.setdefault("Content-Security-Policy", INERT_CSP)
        if (resp.mimetype or "").lower() == "application/json" \
                and resp.headers.get("Cache-Control", PRIVATE_REVALIDATE) == PRIVATE_REVALIDATE:
            resp.headers["Cache-Control"] = NO_STORE
        return
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    resp.headers.setdefault("Cross-Origin-Opener-Policy", COOP)
    resp.headers.setdefault("Cross-Origin-Embedder-Policy", COEP)
    resp.headers.setdefault("X-DNS-Prefetch-Control", "off")
    resp.headers.setdefault("Content-Security-Policy", csp())


def no_store(body):
    """A response for `body` (a rendered page) that no cache keeps: for a page that shows a secret.

    The API token just generated, a TOTP enrolment secret and its QR code, and the 2FA backup codes are
    each shown once; with no-store neither the disk cache nor the back/forward cache holds a copy for
    the next person at the browser.
    """
    from flask import make_response
    resp = make_response(body)
    resp.headers["Cache-Control"] = NO_STORE
    return resp
