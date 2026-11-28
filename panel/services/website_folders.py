"""Websites in a folder of a domain (example.org/forums) beside the one at its root: who may add which address.

THE ADDRESS
    A site's address is a domain and a folder ("" for the whole domain; validation.website_folder for its shape).
    (domain, folder) is unique across every host (the table's constraint is the backstop). A domain may be held by
    several sites of ONE host, since the host's web proxy routes its folders: at most one at its root, the others
    each in a folder that is not another's and holds none of the others' ("/forums" and "/forums/old" never both).
    Every address of a site has the same folder: its app is told one base path (its URLs, its cookie path).

WHO MAY PUT A SITE IN A FOLDER OF A DOMAIN
    Only someone who may manage a site that already holds the domain on the same host (websites_access.site_for's
    rule, per site): a folder goes on "a domain you already have". Otherwise one customer could put a site under
    another customer's domain and serve pages, or a sign-in form, on it. A domain nobody of the user's holds gets
    the same answer as one that does not exist anywhere, so the refusal tells nobody which domains other sites use
    (OWASP Insecure Direct Object Reference Prevention Cheat Sheet, "Mitigation").

THE SHARED ORIGIN (never a block; the Domains tab says it beside the folder form and on each folder address)
    Sites in folders of one domain are ONE origin to a browser: a script one of them serves can read the other's
    pages and storage, and set cookies for the other's paths. OWASP recommends a separate subdomain per app (HTML5
    Security Cheat Sheet, "Local Storage": "Avoid hosting multiple applications on the same origin"; Session
    Management Cheat Sheet, "Domain and Path Attributes": it is highly recommended not to run different apps on one
    host). Each app's cookie path is set to its folder (websites_recipes), as that cheat sheet asks (Path as narrow
    as possible), and the panel never claims it isolates: RFC 6265 section 8.5 says a path gives no integrity
    protection from another path of the same host.

MOVING A SITE INTO OR OUT OF A FOLDER
    A static, PHP or runtime site moves when its first address goes on: its own server is written again with the
    folder (refusal's `moves`), as its files are the operator's and need nothing else. A one-click app keeps the
    address it was installed with in its own database and settings, so its folder is chosen at install only.
"""
from panel.core import i18n
from panel.core.validation import folders_overlap
from panel.db.models import Website, WebsiteDomain

S_TAKEN = "That address is already used by a website."
S_DOMAIN_TAKEN = "That domain is already used by a website."     # a whole domain, as before folders
S_NOT_YOURS = "Add the domain to one of your websites first: a folder goes on a domain one of your websites has."
S_OTHER_HOST = "That domain is served by a website on another host. Sites in folders of a domain share one host."
S_OVERLAP = "Another website on {domain} is in {folder}: a folder may not hold, or be inside, another website's folder."
S_ONE_FOLDER = "Every address of a website is in the same folder. This website's addresses are at {where}."
S_APP_FOLDER = ("This app keeps the address it was installed with in its own settings, so it does not move into a "
                "folder. Choose the folder when you install an app.")
WHERE_ROOT = "the root of their domains"
# The one line under each folder address (the Domains tab); the folder form says OWASP's recommendation itself.
SHARED_NOTE = ("Shares {domain} with your other apps: browsers do not keep their sign-ins apart. A subdomain "
               "({sub}) does.")


def _where(path):
    return path if path else i18n.Sentence(WHERE_ROOT)


def shared_note(row):
    """The one line under a folder address: it shares its domain's origin; a subdomain would not. "" at a root."""
    if not row.path:
        return ""
    label = row.path.rsplit("/", 1)[-1]
    return i18n.tr(SHARED_NOTE, domain=row.domain, sub="%s.%s" % (label, row.domain))


def _manageable(user, site_ids, perm_of):
    """Whether `user` may manage any of the sites `site_ids` (site_for's rule, one site at a time)."""
    from panel.services import websites_access as _wa
    for sid in site_ids:
        if _wa.visible_sites(user, perm_of(sid)).filter(Website.id == sid).first() is not None:
            return True
    return False


def _domain_refusal(user, site, domain, path, held, perm_of):
    """The refusal from the other sites holding `domain` (`held`, its rows), or None."""
    others = [r for r in held if r.website_id != site.id]
    if (path or others) and not _manageable(user, sorted({r.website_id for r in held}), perm_of):
        # A folder needs a domain the user's sites hold; a root needs the folders' sites to be the user's too. Asked
        # first, so a domain the user holds nowhere is answered alike wherever it is used.
        return 409, S_NOT_YOURS if path else S_DOMAIN_TAKEN
    if any(r.website is not None and r.website.remote_id != site.remote_id for r in held):
        return 409, S_OTHER_HOST
    for r in held:
        if folders_overlap(r.path, path):
            return 409, i18n.Sentence(S_OVERLAP, domain=domain, folder=r.path)
    return None


def _site_refusal(site, path):
    """The refusal from the site's own addresses and app (one folder per site; an app's is chosen at install)."""
    own = {d.path or "" for d in site.domains or []}
    if own and own != {path}:
        return 409, i18n.Sentence(S_ONE_FOLDER, where=_where(sorted(own)[0]))
    if not own and path and site.app_recipe and site.state != "creating":
        return 409, S_APP_FOLDER
    return None


def refusal(user, site, domain, path, perm_of):
    """(status, sentence) refusing address (`domain`, `path`) on `site` for `user`, or None when it may be added.

    `perm_of(site id)` is the permission that manages a site (routes.websites.manage_perm). The domain's own shape,
    the panel's name and the site's quota are the caller's checks (websites_domains.domain_refusal).
    """
    held = WebsiteDomain.query.filter_by(domain=domain).all()
    if any((r.path or "") == path for r in held):
        return 409, S_TAKEN if path else S_DOMAIN_TAKEN
    if path == "" and not held:
        return _site_refusal(site, path)
    return _domain_refusal(user, site, domain, path, held, perm_of) or _site_refusal(site, path)


def moves(site, path):
    """Whether adding an address in `path` moves an existing site into a folder: its own server is written again."""
    return bool(path) and not site.domains and site.state != "creating" and not site.app_recipe


def host_domains(user, site, perm_of):
    """The domains a folder can go on for `site`: those held by sites `user` manages on the same host, sorted."""
    rows = (WebsiteDomain.query.join(Website, WebsiteDomain.website_id == Website.id)
            .filter(Website.remote_id == site.remote_id).all())
    mine = {}
    for r in rows:
        if r.website_id not in mine:
            mine[r.website_id] = _manageable(user, [r.website_id], perm_of)
    return sorted({r.domain for r in rows if mine[r.website_id]})
