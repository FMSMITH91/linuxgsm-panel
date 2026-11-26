"""The add-on catalog: the image or source pin each add-on installs, and where that pin came from.

TWO SOURCES
    The floor: panel/addon_images/catalog.json, shipped with the panel, read at import. A panel that has
    never fetched anything installs exactly these pins.
    The signed catalog: the same object plus `seq`, `issued` and `expires`, published on the repository's
    release-signatures branch as catalog/latest.json with catalog/latest.json.sig, an SSH signature
    (`ssh-keygen -Y sign -n linuxgsm-panel-addons`) by a key in the release-signers file the panel update
    check already trusts. It lets a new add-on image reach panels without a panel update.

WHAT IS REFUSED (OWASP has no cheat sheet for signed update metadata: the checks follow The Update
Framework's client workflow, 5.4: signature, rollback, freeze, then content)
    A signature that does not verify (or none), checked over the exact bytes BEFORE they are parsed; a
    schema other than 1; a `seq` not above the last accepted one (rollback); an `expires` already past
    (freeze); an add-on this panel does not know, or one missing; an image or base not pinned by a full
    sha256 digest, or a source pin of the wrong shape. A refused catalog changes nothing.

WHICH WINS (effective())
    The stored catalog counts only when it was issued after this panel's own commit: a panel updated
    since then ships a floor at least as new, so the floor wins until a newer catalog is signed. A
    catalog entry older than the floor's release (B3's and IW4MAdmin's tags) is never used either. An
    expired catalog keeps its pins (going back to the floor would offer an older image as an update) but
    offers no update from them until a newer one is fetched. Nothing is ever installed by this module:
    the add-on card's Update button offers what differs, and only a person pressing it installs.

The last accepted catalog is kept in data/ (0600) with its signature, and checked again when the panel
starts. Fetching uses the update check's own source (git over the checkout's origin remote, the same
ref) and its Outside services switch: with the update check off, nothing is fetched.
"""
import json
import logging
import os
import re
import subprocess  # nosec B404 - ssh-keygen with an argument list, no shell
import tempfile
import threading
import time
from datetime import datetime, timezone


_log = logging.getLogger("panel.addons.catalog")

SCHEMA = 1
NAMESPACE = "linuxgsm-panel-addons"
FLOOR_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addon_images", "catalog.json")
PUBLISHED = "catalog/latest.json"
# Where the accepted catalog is kept: the data folder's addon-catalog.json (store_file()); set by tests.
STORE_FILE = None
# The largest catalog and signature read: today's catalog is under 1 KB, an SSH signature under 1 KB.
MAX_BYTES = 65536
MAX_SIG_BYTES = 8192
# How often the daily task fetches, and the shortest gap between two fetches from the card's Refresh.
EVERY = 86400
REFRESH_GAP = 60

_DIGEST = r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}"
# Each add-on's fields and the exact shape of each (Input Validation Cheat Sheet: allow-list, fullmatch).
FIELDS = {
    "b3": {"base": _DIGEST, "tag": r"v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", "commit": r"[0-9a-f]{40}"},
    "bluemap": {"image": _DIGEST},
    "iw4madmin": {"base": _DIGEST, "tag": r"[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}(?:-prerelease)?",
                  "sha256": r"[0-9a-f]{64}"},
}
_TOP = {"schema", "seq", "issued", "expires", "addons"}
_TIME = "%Y-%m-%dT%H:%M:%SZ"
_TIME_RE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"

# Why a catalog was refused, in words the card shows after "The add-on catalog was refused: ".
BAD_SIGNATURE = "its signature did not verify with this panel's release key"
BAD_FORMAT = "it is not a catalog this panel can read"
BAD_SCHEMA = "it is in a format version this panel does not read"
ROLLBACK = "it is older than the catalog this panel already has"
EXPIRED = "it has expired"
UNKNOWN_ADDON = "it names an add-on this panel does not know, or leaves one out"
BAD_PIN = "an add-on in it is not pinned by a full sha256 digest and release"

# Answers to a fetch (the card's Refresh and the daily task).
OFF = ("The update check is turned off (Settings → Outside services), so the add-on catalog is not "
       "fetched either.")
NOT_GIT = "This panel is not a git checkout, so it can't fetch the add-on catalog."
UNREACHABLE = "Couldn't fetch the add-on catalog from GitHub. Try again later."
NONE_PUBLISHED = "No signed add-on catalog has been published yet: the versions built into this panel are used."
NO_KEY = "This panel has no release key to check the add-on catalog with."
REFUSED = "The add-on catalog was refused: {why}."
ACCEPTED = "Signed add-on catalog #{seq} of {date} accepted."
SAME = "No newer add-on catalog: #{seq} of {date} is the latest."
SAVE_FAILED = "The add-on catalog verified, but the panel couldn't save it."

_lock = threading.Lock()
# What is in use: the stored catalog (None until one is accepted or loaded), and the last fetch.
_state = {"loaded": False, "stored": None, "fetched_at": 0.0, "answer": None, "floor_time": None}


def _check_addons(addons):
    """"" when `addons` is a complete, well-formed add-on map, else the reason it is refused."""
    if not isinstance(addons, dict) or set(addons) != set(FIELDS):
        return UNKNOWN_ADDON
    for addon_id, shape in FIELDS.items():
        entry = addons[addon_id]
        if not isinstance(entry, dict) or set(entry) != set(shape):
            return BAD_PIN
        if not all(isinstance(entry[k], str) and re.fullmatch(rx, entry[k]) for k, rx in shape.items()):
            return BAD_PIN
    return ""


def read_floor(path=FLOOR_FILE):
    """The floor's add-on map from `path` (the repository's catalog.json). Raises ValueError when it is not one."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or set(doc) != {"schema", "addons"} or doc["schema"] != SCHEMA:
        raise ValueError("%s: not a schema %d add-on catalog" % (path, SCHEMA))
    why = _check_addons(doc["addons"])
    if why:
        raise ValueError("%s: %s" % (path, why))
    return {k: dict(v) for k, v in doc["addons"].items()}


FLOOR = read_floor()


def _when(text):
    """The epoch of a catalog time ("YYYY-MM-DDTHH:MM:SSZ", UTC), or None when it is not one."""
    if not isinstance(text, str) or not re.fullmatch(_TIME_RE, text):
        return None
    try:
        return datetime.strptime(text, _TIME).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def verify_signature(key, data, sig):
    """Whether `sig` (armored text) is a signature of the bytes `data` by a key in `key` (allowed-signers text).

    ssh-keygen -Y verify, principal "release", namespace NAMESPACE: a release signature (its own namespace)
    can never pass as a catalog signature, nor the reverse. Anything that can't be checked is False.
    """
    if not key or not sig:
        return False
    with tempfile.TemporaryDirectory(prefix="lgsm-addoncat-") as d:
        kf, sf = os.path.join(d, "key"), os.path.join(d, "sig")
        with open(kf, "w", encoding="utf-8") as fh:
            fh.write(key.strip() + "\n")
        with open(sf, "w", encoding="utf-8") as fh:
            fh.write(sig.strip() + "\n")
        try:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", kf, "-I", "release",  # nosec B603 B607
                                "-n", NAMESPACE, "-s", sf], input=data, capture_output=True, timeout=20,
                               check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"})
        except (subprocess.TimeoutExpired, OSError):
            return False
    return r.returncode == 0


def check_signed(data, sig, key, last_seq, now, allow_expired=False):
    """(catalog dict, "") when the published bytes `data` are a catalog to accept, else (None, the reason).

    The order is TUF's (5.4): the signature over the exact bytes first, nothing parsed before it; then the
    format and schema, rollback (`seq` above `last_seq`), freeze (`expires` after `now`, unless
    `allow_expired`: the stored copy, re-read at start) and the add-on entries.
    """
    if not isinstance(data, bytes) or len(data) > MAX_BYTES or not verify_signature(key, data, sig):
        return None, BAD_SIGNATURE
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, BAD_FORMAT
    if not isinstance(doc, dict) or set(doc) != _TOP:
        return None, BAD_FORMAT
    if type(doc["schema"]) is not int or doc["schema"] != SCHEMA:
        return None, BAD_SCHEMA
    seq, issued, expires = doc["seq"], _when(doc["issued"]), _when(doc["expires"])
    if type(seq) is not int or seq < 1 or issued is None or expires is None or expires <= issued:
        return None, BAD_FORMAT
    if seq <= last_seq:
        return None, ROLLBACK
    if expires <= now and not allow_expired:
        return None, EXPIRED
    why = _check_addons(doc["addons"])
    return (None, why) if why else (doc, "")


# ── the stored catalog ─────────────────────────────────────────────────────────────────────────
def store_file():
    """The stored catalog's path: STORE_FILE, else addon-catalog.json in the data folder (config read only now)."""
    if STORE_FILE:
        return STORE_FILE
    from panel.core import config as _config    # imported here: it makes the data folder, which the floor never needs
    return str(_config.DATA_DIR / "addon-catalog.json")


def _write_store(data, sig):
    """Write the accepted catalog's bytes and signature to STORE_FILE (0600, replaced atomically)."""
    body = json.dumps({"catalog": data.decode("utf-8"), "signature": sig}).encode("utf-8")
    path = store_file()
    tmp = os.path.join(os.path.dirname(path), ".addon-catalog.%d.tmp" % os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        fh = os.fdopen(fd, "wb")
    except OSError:
        os.close(fd)
        raise
    with fh:
        fh.write(body)
    os.replace(tmp, path)


def _read_store(key):
    """The stored catalog, checked again with `key` (expired allowed), or None when there is none to use."""
    try:
        with open(store_file(), "rb") as fh:
            raw = fh.read(4 * MAX_BYTES)
        doc = json.loads(raw.decode("utf-8"))
        data, sig = doc["catalog"].encode("utf-8"), doc["signature"]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    cat, _why = check_signed(data, sig if isinstance(sig, str) else "", key, 0, time.time(), allow_expired=True)
    return cat


def _release_key():
    """The release key the update check trusts (system_ops), as text, or ""."""
    from panel.ops import system_ops as _so    # imported here: system_ops is heavy and imports much of the panel
    try:
        return _so._release_key_text()
    except Exception:   # noqa: BLE001 - no key read is no key: nothing is trusted
        _log.debug("release key unread", exc_info=True)
        return ""


def _floor_time():
    """When this panel's own commit was made (epoch), or None when it can't be read: the floor's date."""
    if _state["floor_time"] is None:
        from panel.ops import system_ops as _so
        out, _err, rc = _so._git(["log", "-1", "--format=%ct", "HEAD"], timeout=10)
        _state["floor_time"] = int(out) if rc == 0 and out.strip().isdigit() else 0
    return _state["floor_time"] or None


def _release_tuple(tag):
    """A release tag as numbers to compare (B3's vX.Y.Z, IW4MAdmin's build number)."""
    return tuple(int(n) for n in re.findall(r"[0-9]+", tag.split("-", 1)[0]))


def effective(stored, floor_time, now):
    """({add-on id: its pins}, {add-on id: where they came from}) from the floor and the catalog `stored`.

    A source is {"kind": "floor"} or {"kind": "catalog", "seq", "issued", "expired"}. `stored` (a checked
    catalog, or None) counts only when issued after `floor_time` (this panel's commit time; None when
    unknown: the floor wins); `now` decides whether it has expired.
    """
    pins = {k: dict(v) for k, v in FLOOR.items()}
    sources = {k: {"kind": "floor"} for k in FLOOR}
    if not stored or not floor_time or _when(stored["issued"]) <= floor_time:
        return pins, sources
    src = {"kind": "catalog", "seq": stored["seq"], "issued": stored["issued"],
           "expired": _when(stored["expires"]) <= now}
    for k, entry in stored["addons"].items():
        if "tag" in entry and _release_tuple(entry["tag"]) < _release_tuple(FLOOR[k]["tag"]):
            continue                                       # an older release than this panel ships
        pins[k], sources[k] = dict(entry), dict(src)
    return pins, sources


def current():
    """effective() for the stored catalog, this panel's commit time and the clock."""
    stored = _state["stored"]
    return effective(stored, _floor_time() if stored else None, time.time())


def _apply():
    from panel.services import addons as _ad   # it imports this module for the floor
    pins, sources = current()
    _ad.use_pins(pins, sources)


def ensure_loaded():
    """Read the stored catalog once per process (checked again) and put the effective pins in use."""
    if _state["loaded"]:
        return
    with _lock:
        if _state["loaded"]:
            return
        stored = None
        if os.path.isfile(store_file()):
            stored = _read_store(_release_key())
        _state["stored"], _state["loaded"] = stored, True
        _apply()


def _date(cat):
    return cat["issued"][:10]


def _published():
    """(catalog bytes, signature text, "") from the update check's source, or (None, None, the answer)."""
    from panel.core import outside_services as _outside
    from panel.ops import system_ops as _so
    if not _outside.enabled(_outside.UPDATE_CHECK):
        return None, None, OFF
    if not _so._is_git_checkout():
        return None, None, NOT_GIT
    ref = _so._RELEASE_SIG_REF
    _out, _err, frc = _so._git(["fetch", "--quiet", "--no-tags", "origin",
                                "+refs/heads/%s:%s" % (_so._RELEASE_SIG_BRANCH, ref)], timeout=45)
    if frc != 0:
        return None, None, UNREACHABLE
    listed, _err, lrc = _so._git(["ls-tree", "--name-only", ref, "--", PUBLISHED, PUBLISHED + ".sig"], timeout=10)
    if lrc != 0:
        return None, None, UNREACHABLE
    if PUBLISHED not in listed.split("\n"):
        return None, None, NONE_PUBLISHED
    data = _blob(_so, ref, PUBLISHED, MAX_BYTES)
    sig = _blob(_so, ref, PUBLISHED + ".sig", MAX_SIG_BYTES)
    return data, (sig.decode("utf-8", "replace") if sig else ""), ""


def _blob(so, ref, path, limit):
    """The exact bytes of `path` at `ref` (git cat-file, no text decoding), or b"" when unread or over `limit`."""
    try:
        r = subprocess.run(["git", "-C", so.PANEL_DIR, "cat-file", "blob", "%s:%s" % (ref, path)],  # nosec B603 B607
                           capture_output=True, timeout=10, check=False,
                           env=dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true"))
    except (subprocess.TimeoutExpired, OSError):
        return b""
    return r.stdout if r.returncode == 0 and len(r.stdout) <= limit else b""


def accept(data, sig, key, now=None):
    """Check the published `data` and `sig` against the stored catalog; store and use them when newer.

    Returns (success, the answer in words, its values for i18n.tr).
    """
    now = time.time() if now is None else now
    have = _state["stored"]
    cat, why = check_signed(data, sig, key, have["seq"] if have else 0, now)
    if cat is None:
        if have and why == ROLLBACK:
            same, _w = check_signed(data, sig, key, have["seq"] - 1, now, allow_expired=True)
            if same is not None and same["seq"] == have["seq"]:
                return True, SAME, {"seq": have["seq"], "date": _date(have)}
        _log.warning("add-on catalog refused: %s", why)
        from panel.core.i18n import Sentence   # imported here: the floor alone needs no Flask
        return False, REFUSED, {"why": Sentence(why)}
    try:
        _write_store(data, sig)
    except OSError:
        _log.warning("add-on catalog not saved", exc_info=True)
        return False, SAVE_FAILED, {}
    _state["stored"] = cat
    _apply()
    _log.info("add-on catalog #%d accepted", cat["seq"])
    return True, ACCEPTED, {"seq": cat["seq"], "date": _date(cat)}


def refresh(force=False):
    """Fetch, check and keep the published catalog. Returns (success, answer, values), as accept().

    Not more than once per REFRESH_GAP seconds: a click inside that gap gets the last answer.
    """
    ensure_loaded()
    with _lock:
        last = _state["answer"]
        if last is not None and not force and time.time() - _state["fetched_at"] < REFRESH_GAP:
            return last
        _state["fetched_at"] = time.time()
        data, sig, why = _published()
        if why:
            ans = (why == NONE_PUBLISHED, why, {})
        else:
            key = _release_key()
            ans = accept(data, sig, key) if key else (False, NO_KEY, {})
        _state["answer"] = ans
        return ans


def daily_tick():
    """The daily fetch, from the update-check thread: at its first pass, then every EVERY seconds. Never raises."""
    try:
        if _state["answer"] is None or time.time() - _state["fetched_at"] >= EVERY:
            refresh(force=True)
    except Exception:   # noqa: BLE001 - background pass; the next one tries again
        _log.warning("add-on catalog fetch failed", exc_info=True)


def source_words(source):
    """(sentence, values) naming where an add-on's version came from, for the card (i18n.tr)."""
    if source.get("kind") != "catalog":
        return "Version source: built into this panel.", {}
    return "Version source: signed add-on catalog #{seq} of {date}.", {"seq": source["seq"],
                                                                         "date": source["issued"][:10]}


EXPIRED_NOTE = ("The signed add-on catalog #{seq} expired on {date} and no newer one has been fetched, so it "
                "offers no updates until one is.")


def expired_note():
    """(sentence, values) while the catalog in use has expired, else ("", {})."""
    stored = _state["stored"]
    if stored and any(s.get("expired") for s in current()[1].values()):
        return EXPIRED_NOTE, {"seq": stored["seq"], "date": stored["expires"][:10]}
    return "", {}
