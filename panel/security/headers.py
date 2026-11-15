"""The security headers that only mean something on a response a browser shows as a page.

Content-Security-Policy, X-Frame-Options and Permissions-Policy govern a DOCUMENT: what its scripts
may load and run, whether another site may frame it, which browser features it may ask for. A
browser never makes a document of a JSON answer, a stylesheet, a script, an image or a font: it
hands them to the page that asked (and X-Content-Type-Options: nosniff, still on every response,
stops it guessing otherwise). On those types the three headers protected nothing and cost ~400
bytes per response, about a quarter of every dashboard poll over HTTP/1.1; the CSP also carries the
per-request nonce, so it never repeats for HTTP/2's header table either.

So they are left off exactly the types in _INERT_TYPES, and kept on everything else: HTML, SVG and
XML (which can run script when opened), plain text, a download, and any type not named here.
X-Content-Type-Options, Referrer-Policy and X-Robots-Tag stay on every response (app.py): the last
exists for the responses that are NOT HTML, where no <meta> tag can say it.
"""

_INERT_TYPES = frozenset((
    "application/json", "application/manifest+json",
    "text/css", "text/javascript", "application/javascript",
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon",
    "font/woff", "font/woff2", "font/ttf", "font/otf", "application/font-woff",
))

# The panel uses none of these powerful browser features, so a page is denied them outright: a
# defence-in-depth limit on what an injected or compromised script could reach for.
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=()"


def renders_as_page(resp):
    """Whether a browser could show `resp` as a document (any type not known to be inert)."""
    return (resp.mimetype or "").lower() not in _INERT_TYPES


def set_page_headers(resp, csp):
    """Set CSP (csp() builds it), X-Frame-Options and Permissions-Policy on a response that renders as a page."""
    if renders_as_page(resp):
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
        resp.headers.setdefault("Content-Security-Policy", csp())
