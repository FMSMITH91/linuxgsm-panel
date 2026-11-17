"""Refuse a password found in a breach: a downloaded list first, then Pwned Passwords if allowed.

OWASP Authentication Cheat Sheet, "Implement Proper Password Strength Controls" (read 2026-11-17):
block common and previously breached passwords, checked against the Pwned Passwords service or a
downloaded list. Runs only after common_passwords.is_common() has passed the password, in this order:

1. The downloaded list: SecLists' 100k-most-used-passwords-NCSC.txt (MIT), fetched by install.sh
   and every update into data/ (LIST_NAME), pinned by SHA-256 (install.sh's PW_LIST_SHA256 is
   the same value; its PW_LIST_URL names the SecLists commit). A missing file, or one whose hash is
   not LIST_SHA256, is skipped, never trusted. Read and searched on each check rather than held in
   memory: a set of its entries kept ~4.5 MB resident for a check made only when a password is set,
   and one read and search of the 835 KB file takes a few milliseconds.
2. Only when the list does not have it, and the `breach_check_online` setting is not off: the Pwned
   Passwords range API. k-anonymity: the password's SHA-1 is computed here and only its first five
   hex characters are sent; the service answers with every suffix under that prefix, padded with
   decoy count-0 lines (Add-Padding), and the match is made here. No answer within TIMEOUT seconds,
   or any error, is "not found": the local result stands and the password is accepted.

The one network call is _fetch_range(). The environment variable OFFLINE_ENV, when set, stops it
whatever the setting says (for a host with no outside access; every test suite sets it).
"""
import hashlib
import logging
import os
import urllib.error
import urllib.request

_log = logging.getLogger("panel.breached_passwords")

LIST_NAME = "common-passwords-100k.txt"
LIST_SHA256 = "c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0"
LIST_MAX_BYTES = 2 * 1024 * 1024
RANGE_URL = "https://api.pwnedpasswords.com/range/"
PREFIX_LEN = 5
TIMEOUT = 3
_MAX_RANGE_BYTES = 256 * 1024     # a padded answer is ~1,000 lines of ~40 bytes
SETTING = "breach_check_online"
OFFLINE_ENV = "LGSM_PANEL_OFFLINE"


def list_path():
    """Where install.sh puts the downloaded list (the panel's data directory)."""
    from panel.core import config
    return os.path.join(str(config.DATA_DIR), LIST_NAME)


def _read_list(path):
    """The list's text, case folded, or None when it is missing, a link or not the pinned file.

    Hashed on every read (about a millisecond for 835 KB): a verdict cached by size and mtime is
    one a rewritten file with both put back would inherit.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        raw = fh.read(LIST_MAX_BYTES + 1)
    if hashlib.sha256(raw).hexdigest() != LIST_SHA256:
        _log.warning("%s does not match its pinned SHA-256; not used", path)
        return None
    return raw.decode("utf-8", errors="replace").casefold()


def in_downloaded_list(password):
    """Whether the downloaded list holds `password` (case folded); False when there is no usable list."""
    needle = (password or "").strip().casefold()
    if not needle or "\n" in needle:
        return False
    text = _read_list(list_path())
    return bool(text) and ("\n" + needle + "\n") in ("\n" + text + "\n")


def online_enabled():
    """Whether the Pwned Passwords call may be made: the setting is not off and OFFLINE_ENV is unset."""
    if os.environ.get(OFFLINE_ENV):
        return False
    from panel.core.config import config_value
    return config_value(SETTING, True) is not False


def sha1_parts(password):
    """The (prefix sent, suffix kept) halves of the password's upper-case SHA-1 hex digest."""
    # The range API is keyed by SHA-1 (it names the bucket of breached hashes); it protects nothing here.
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- the API's own key
    digest = hashlib.sha1((password or "").encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:PREFIX_LEN], digest[PREFIX_LEN:]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the request goes to RANGE_URL's host and nowhere it points next."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None, which makes urllib raise the 3xx as an HTTPError."""
        return None


def _fetch_range(prefix):
    """The range API's answer for a five-character `prefix`, or None. The only network call here."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(RANGE_URL + prefix,
                                 headers={"Add-Padding": "true", "User-Agent": "linuxgsm-panel"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:  # nosec B310 - fixed https host
            if getattr(resp, "status", 200) != 200:
                return None
            return resp.read(_MAX_RANGE_BYTES).decode("ascii", errors="replace")
    except (OSError, ValueError, urllib.error.URLError) as e:
        _log.info("Pwned Passwords did not answer (%s); the local checks stand", e.__class__.__name__)
        return None


def count_in_range(body, suffix):
    """How often `suffix` appears in a range answer; 0 when absent or only a count-0 padding line."""
    for line in (body or "").splitlines():
        found, _sep, count = line.strip().partition(":")
        if found.upper() == suffix:
            try:
                return max(0, int(count))
            except ValueError:
                return 0
    return 0


def pwned_count(password):
    """Times Pwned Passwords has seen `password`, or None when the call is off or got no answer."""
    if not online_enabled():
        return None
    prefix, suffix = sha1_parts(password)
    body = _fetch_range(prefix)
    return None if body is None else count_in_range(body, suffix)


def is_breached(password):
    """Whether `password` is on the downloaded list or, failing that, in Pwned Passwords."""
    if in_downloaded_list(password):
        return True
    return bool(pwned_count(password))
