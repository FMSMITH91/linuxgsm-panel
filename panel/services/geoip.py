"""The offline country database for B3's geolocation: DB-IP "IP to Country Lite", in the MMDB format.

WHAT AND WHY
    B3's geolocation plugin can look a player's country up offline, in a MaxMind DB (.mmdb) file (its
    `mmdb` service), so no player's IP address leaves the game's host. DB-IP publishes a free country
    database every month under CC BY 4.0, with no account: https://db-ip.com/db/download/ip-to-country-lite
    (read 2026-11-18). That page links the month's file, dbip-country-lite-YYYY-MM.mmdb.gz on
    download.db-ip.com, and shows its MD5 and SHA1 in the block just above that link (the CSV's block,
    with its own sums, comes first). Both sums are of the unpacked database, not of the .gz (checked
    against the November 2026 file); there is no SHA-256. The licence asks for credit,
    which CREDIT is, shown on the add-on's card and in docs/addons.md.

HOW IT IS FETCHED
    Only when a B3 add-on is set to offline geolocation (install, settings or update), and only while
    Settings -> Outside services has DB-IP on. The panel's host asks for the page, then the file, over
    HTTPS from those two hosts only (a redirect anywhere else is refused), with a size cap on each. The
    file must unpack to at most UNPACKED_CAP bytes, match the SHA1 the page shows for it, and end with
    MaxMind's metadata marker. It is
    kept in data/geoip/ for the month, so every add-on that month gets the same file from one download.
    No player data is sent: the request carries only the panel's User-Agent.

    OWASP's cheat sheets have no rule for a downloaded data file. The checks follow the OWASP Top 10
    A08 (Software and Data Integrity Failures) advice: a trusted source over TLS, and an integrity check
    before use.
"""
import gzip
import hashlib
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request

from panel import REPO_ROOT as _ROOT
from panel.core import outside_services as _outside

PAGE = "https://db-ip.com/db/download/ip-to-country-lite"
HOSTS = frozenset({"db-ip.com", "download.db-ip.com"})
CREDIT = "IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0."
# The file's name, here and in the add-on's geoip folder (mounted read-only at /geoip in the container).
FILE_NAME = "dbip-country-lite.mmdb"
CACHE_DIR = _ROOT / "data" / "geoip"
# Caps: the page (a few hundred KB of HTML), the .gz (about 4 MB in 2026) and the database (about 8 MB).
PAGE_CAP = 2 * 1024 * 1024
GZ_CAP = 64 * 1024 * 1024
UNPACKED_CAP = 256 * 1024 * 1024
TIMEOUT = 60
_UA = "linuxgsm-panel (B3 country database)"
# Every MaxMind DB file ends its data section with this marker before the metadata (MaxMind DB spec 2.0).
MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"
_FILE_RE = re.compile(r"https://download\.db-ip\.com/free/dbip-country-lite-(\d{4}-\d{2})\.mmdb\.gz")
# Any of the page's download links: the one before the MMDB's ends the CSV's block.
_ANY_FILE_RE = re.compile(r"https://download\.db-ip\.com/free/")
# The SHA1 a block shows: its SHA1SUM label, then the 40 hex digits.
_SHA1_RE = re.compile(r"SHA1SUM\s*</dt>\s*<dd[^>]*>\s*([0-9a-fA-F]{40})\s*</dd>", re.I)

OFF = "The DB-IP country database is turned off in Settings → Outside services."
UNREACHABLE = "Couldn't download the DB-IP country database. Try again later."
UNREADABLE = ("DB-IP's download page no longer shows the country database's link and checksum where the panel looks "
              "for them, so it wasn't downloaded.")
BAD_FILE = "The DB-IP country database didn't match its published checksum, so it wasn't used."


def month_now():
    """The current month in UTC as YYYY-MM: the release a current file carries."""
    return time.strftime("%Y-%m", time.gmtime())


def download_allowed():
    """Whether Settings -> Outside services lets the panel download DB-IP's database."""
    return _outside.enabled(_outside.DBIP)


def _allowed(url):
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return (p.scheme == "https" and p.hostname in HOSTS and p.port in (None, 443)
            and not p.username and not p.password)


class _AllowedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an https URL on HOSTS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse (None) a redirect off HOSTS; follow one on them."""
        if not _allowed(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url, cap):
    """GET `url` from HOSTS: (body bytes, None) or (None, why). Never raises."""
    if not _allowed(url):
        return None, "not an allowed URL"
    opener = urllib.request.build_opener(_AllowedRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with opener.open(req, timeout=TIMEOUT) as resp:  # nosec B310 - https on HOSTS only, checked above
            if getattr(resp, "status", 200) != 200:
                return None, "HTTP %s" % resp.status
            body = resp.read(cap + 1)
    except Exception as e:  # noqa: BLE001 - every failure is "could not be downloaded"
        return None, e.__class__.__name__
    if len(body) > cap:
        return None, "too large"
    return body, None


def parse_page(html):
    """(file URL, its month YYYY-MM, its SHA1) from the download page's HTML, or None.

    Each file has a block on the page: its details, its MD5SUM and SHA1SUM, then its link. The SHA1 is
    the last SHA1SUM between the previous download link (the CSV's) and the MMDB's link, so the CSV's
    own sums are never taken.
    """
    html = html or ""
    m = _FILE_RE.search(html)
    if not m:
        return None
    start = 0
    for prev in _ANY_FILE_RE.finditer(html, 0, m.start()):
        start = prev.end()
    found = _SHA1_RE.findall(html, start, m.start())
    return (m.group(0), m.group(1), found[-1].lower()) if found else None


def sha1_hex(data):
    """The SHA1 of `data`, as DB-IP's page publishes it (its only checksums are MD5 and SHA1).

    What it guards is a second preimage (a different file with the published sum), which SHA1 still
    resists; the page and the file both come over TLS from db-ip.com, and the file must then also be an
    MMDB file. No collision-dependent use (signatures, certificates) is made of it.
    """
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()  # nosec B324 - DB-IP publishes SHA1 only


def unpack(gz, sha1):
    """The database inside `gz`, once it matches `sha1` (DB-IP's sum is the database's) and is an MMDB file."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(gz)) as fh:
            data = fh.read(UNPACKED_CAP + 1)
    except (OSError, EOFError):
        return None
    if len(data) > UNPACKED_CAP:
        return None
    if sha1_hex(data) != sha1:
        return None
    return data if MMDB_MARKER in data[-512 * 1024:] else None


def _cached():
    """(path, month) of the file kept in data/geoip, or (None, "")."""
    try:
        with open(CACHE_DIR / "current.json", encoding="utf-8") as fh:
            rec = json.load(fh)
        path = CACHE_DIR / FILE_NAME
        if isinstance(rec, dict) and re.fullmatch(r"\d{4}-\d{2}", str(rec.get("month", ""))) and path.is_file():
            return path, rec["month"]
    except (OSError, ValueError):
        pass  # no record yet, or an unreadable one: treated as no file kept, so the month is downloaded again
    return None, ""


def _keep(data, month, sha1):
    """Write the database and its record to data/geoip, atomically. -> its path."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / FILE_NAME
    tmp = CACHE_DIR / (FILE_NAME + ".new")
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
    rec = CACHE_DIR / "current.json.new"
    with open(rec, "w", encoding="utf-8") as fh:
        json.dump({"month": month, "sha1": sha1, "fetched": int(time.time())}, fh)
    os.replace(rec, CACHE_DIR / "current.json")
    return path


def latest():
    """(path, month, why): this month's database, from data/geoip or downloaded once; why is "" when found.

    With DB-IP turned off in Settings, or unreachable, a file kept from an earlier month is still
    returned (with why saying so), so an add-on keeps working; None when there is none.
    """
    path, month = _cached()
    if path is not None and month >= month_now():
        return path, month, ""
    if not download_allowed():
        return path, month, OFF
    page, _why = _get(PAGE, PAGE_CAP)
    if page is None:
        return path, month, UNREACHABLE
    found = parse_page(page.decode("utf-8", "replace"))
    if found is None:
        return path, month, UNREADABLE
    url, new_month, sha1 = found
    if path is not None and new_month <= month:
        return path, month, ""
    gz, _why = _get(url, GZ_CAP)
    if gz is None:
        return path, month, UNREACHABLE
    data = unpack(gz, sha1)
    if data is None:
        return path, month, BAD_FILE
    return _keep(data, new_month, sha1), new_month, ""
