"""Part 292 of the unit suite: the signed add-on catalog (add-on updates without a panel update).

1. The floor: panel/addon_images/catalog.json parses as a schema 1 catalog, every image and base is pinned by a
   full sha256 digest, its pins are the Containerfiles' ARG defaults, and addons.py's pin names and CATALOG
   images are built from it.
2. Accepting, through the card's Refresh route (POST /api/server/<id>/addons/catalog): a catalog signed with a
   throwaway key in this part's own allowed-signers text is accepted, stored 0600 and put in use; the list route
   then offers Update to a record of the floor's image and says where the version came from.
3. Refusals, each through the same route from the same starting catalog: no signature, another key, the release
   namespace, schema 2, a seq not above the last (rollback), an expired catalog, a digest short of 64 hex
   characters, an unknown add-on, a missing one. Each answers why and changes nothing in use.
4. Which wins: a catalog issued before this panel's own commit loses to the floor, and so does an entry with an
   older release than the floor's; an expired catalog keeps its pins but offers no update and the card says so.
5. The stored copy: read again at start and checked again (a tampered copy is not used); the daily task fetches
   at its first pass and then not again within a day; with the update check off nothing is fetched; a published
   ref with no catalog is not a failure; Manage add-ons is needed for Refresh.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed. Signing uses ssh-keygen with a key made in
a throwaway folder (never a real key); git is a recorder; nothing reaches GitHub or a host.
"""
import json as _json292
import os
import re as _re292
import shutil as _shutil292
import subprocess as _sp292  # nosec B404 - ssh-keygen over this part's own throwaway key
import tempfile as _tf292
from types import SimpleNamespace as _NS292

from unit.part01 import _root, check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.ops import system_ops as _so292
from panel.routes import addons as _ra292
from panel.services import addons as _ad292, addons_catalog as _cat292

_trips292 = len(_P9_TRIPPED)
_TMP292 = _tf292.mkdtemp(prefix="p292-")
_FLOOR_AT292 = 1764000000            # this panel's commit time in these checks (2025-11-24)
_ISSUED292 = "2026-11-25T10:00:00Z"  # after it
_EXPIRES292 = "2099-01-01T00:00:00Z"
_NEW_COMMIT292 = "1" * 40
_NEW_BLUEMAP292 = "ghcr.io/bluemap-minecraft/bluemap@sha256:" + "2" * 64
_HAVE_KEYGEN292 = _shutil292.which("ssh-keygen") is not None


def _keygen292(name):
    """A throwaway ed25519 signing pair in _TMP292: (private file, allowed-signers line for principal release)."""
    path = os.path.join(_TMP292, name)
    _sp292.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "p292", "-f", path],  # nosec B603 B607
               check=True, capture_output=True, timeout=30)
    with open(path + ".pub", encoding="utf-8") as fh:
        return path, "release " + " ".join(fh.read().split()[:2])


def _sign292(priv, data, namespace=_cat292.NAMESPACE):
    """The armored ssh-keygen -Y sign signature of the bytes `data` with `priv` in `namespace`."""
    msg = os.path.join(_TMP292, "msg")
    with open(msg, "wb") as fh:
        fh.write(data)
    if os.path.exists(msg + ".sig"):
        os.remove(msg + ".sig")
    _sp292.run(["ssh-keygen", "-q", "-Y", "sign", "-n", namespace, "-f", priv, msg],  # nosec B603 B607
               check=True, capture_output=True, timeout=30)
    with open(msg + ".sig", encoding="utf-8") as fh:
        return fh.read()


def _addons292(**changes):
    """The floor's add-on map with B3's commit and BlueMap's image moved on, then `changes` per add-on."""
    out = {k: dict(v) for k, v in _cat292.FLOOR.items()}
    out["b3"]["commit"] = _NEW_COMMIT292
    out["bluemap"]["image"] = _NEW_BLUEMAP292
    for k, v in changes.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def _doc292(seq, addons=None, issued=_ISSUED292, expires=_EXPIRES292, schema=1):
    return _json292.dumps({"schema": schema, "seq": seq, "issued": issued, "expires": expires,
                           "addons": _addons292() if addons is None else addons}, indent=2).encode("utf-8")


def _reset292(stored=None):
    """Put the catalog module back to "nothing fetched", or to the checked catalog `stored`, and apply it."""
    _cat292._state.update(loaded=True, stored=stored, fetched_at=0.0, answer=None, floor_time=None)
    _cat292._apply()


def _serve292(data, sig, key):
    """Have Refresh's fetch answer `data` and `sig`, and the release key be `key`; returns the fetch count."""
    seen = []

    def published():
        seen.append(1)
        return data, sig, ""
    _p9_patch(_cat292, "_published", published)
    _p9_patch(_cat292, "_release_key", lambda: key)
    _p9_patch(_cat292, "_floor_time", lambda: _FLOOR_AT292)
    return seen


def _refresh292(sid, client=None):
    _cat292._state["fetched_at"] = 0.0          # Refresh's minute gap is its own check below
    r = (client or _p9_client(P9_ADMIN)).post("/api/server/%d/addons/catalog" % sid, json={})
    return r.status_code, r.get_json(silent=True) or {}


def _host292(meta):
    """The host answers a status read with `meta` installed as BlueMap (stand-in shell)."""
    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        status = ("installed=1\nmeta.bluemap=%s\nstate.bluemap=active\n" % _ad292._b64(_json292.dumps(meta))
                  if meta else "")
        return "os=24.04\npodman=podman version 4.9.3\nuid=1004\ngid=1005\n" + status, "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch(_ra292, "game_account_write_refusal", lambda remote, user, reading=False: None)


def _row292(sid, addon_id="bluemap"):
    d = _p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid).get_json(silent=True) or {}
    return next((x for x in d.get("addons") or [] if x.get("id") == addon_id), {}), d


# ── 1. the floor ────────────────────────────────────────────────────────────────────────────────
def _floor292():
    with open(os.path.join(_root, "panel", "addon_images", "catalog.json"), encoding="utf-8") as fh:
        doc = _json292.load(fh)
    digests = [doc["addons"]["bluemap"]["image"], doc["addons"]["b3"]["base"], doc["addons"]["iw4madmin"]["base"]]
    eq("catalog floor: catalog.json is schema 1 with exactly the three add-ons, each image and base pinned by a full "
       "sha256 digest, and it reads as the module's floor",
       (doc.get("schema"), sorted(doc.get("addons") or {}),
        [bool(_re292.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", d)) for d in digests],
        _cat292.read_floor() == doc["addons"]),
       (1, ["b3", "bluemap", "iw4madmin"], [True, True, True], True))
    args = {}
    for build in ("b3", "iw4madmin"):
        with open(os.path.join(_root, "panel", "addon_images", build, "Containerfile"), encoding="utf-8") as fh:
            args[build] = dict(_re292.findall(r"^ARG ([A-Z0-9_]+)=(\S+)$", fh.read(), _re292.M))
    eq("catalog floor: its pins are the Containerfiles' ARG defaults (B3's base and commit, IW4MAdmin's base, release "
       "and archive sha256)",
       args, {"b3": {"BASE_IMAGE": doc["addons"]["b3"]["base"], "B3_COMMIT": doc["addons"]["b3"]["commit"]},
              "iw4madmin": {"BASE_IMAGE": doc["addons"]["iw4madmin"]["base"],
                            "IW4MADMIN_TAG": doc["addons"]["iw4madmin"]["tag"],
                            "IW4MADMIN_SHA256": doc["addons"]["iw4madmin"]["sha256"]}})
    eq("catalog floor: addons.py's pin names and CATALOG are built from it while nothing is fetched",
       (_ad292.B3_COMMIT, _ad292.B3_TAG, _ad292.B3_BASE, _ad292.IW4MADMIN_TAG, _ad292.IW4MADMIN_SHA256,
        _ad292.IW4MADMIN_BASE, _ad292.BLUEMAP_IMAGE, _ad292.CATALOG["bluemap"]["image"],
        _ad292.CATALOG["b3"]["image"].startswith("localhost/lgsm-addon-b3:%s-" % doc["addons"]["b3"]["commit"][:12]),
        _ad292.PIN_SOURCES["b3"]),
       (doc["addons"]["b3"]["commit"], doc["addons"]["b3"]["tag"], doc["addons"]["b3"]["base"],
        doc["addons"]["iw4madmin"]["tag"], doc["addons"]["iw4madmin"]["sha256"], doc["addons"]["iw4madmin"]["base"],
        doc["addons"]["bluemap"]["image"], doc["addons"]["bluemap"]["image"], True, {"kind": "floor"}))
    bad = os.path.join(_TMP292, "bad-floor.json")
    with open(bad, "w", encoding="utf-8") as fh:
        _json292.dump(dict(doc, addons=_addons292(bluemap={"image": "ghcr.io/x/y:v5"})), fh)
    try:
        _cat292.read_floor(bad)
        refused = False
    except ValueError:
        refused = True
    check("catalog floor: a floor with an image pinned by tag, not digest, is refused at import", refused)


# ── 2. accepting ────────────────────────────────────────────────────────────────────────────────
def _accept292(sid, priv, key):
    meta = {"kind": "bluemap", "image": _cat292.FLOOR["bluemap"]["image"], "mc_version": "1.21.4", "port": 21008}
    _host292(meta)
    _serve292(b"", "", key)
    row0, _d = _row292(sid)
    data = _doc292(5)
    _serve292(data, _sign292(priv, data), key)
    code, body = _refresh292(sid)
    mode = os.stat(_cat292.store_file()).st_mode & 0o777 if os.path.exists(_cat292.store_file()) else None
    eq("catalog accept (route): a catalog signed by a release key is accepted, said with its seq and date, audited",
       (code, body.get("success"), body.get("message"), _p9_audit("addon_catalog_refresh").success),
       (200, True, "Signed add-on catalog #5 of 2026-11-25 accepted.", True))
    if os.geteuid() == 0:
        skip("catalog accept: the stored copy is owner-only (0600)", "root ignores file modes")
    else:
        eq("catalog accept: the stored copy is owner-only (0600)", mode, 0o600)
    eq("catalog accept: its pins are in use (B3's commit, BlueMap's image, where they came from)",
       (_ad292.B3_COMMIT, _ad292.BLUEMAP_IMAGE, _ad292.CATALOG["bluemap"]["image"],
        _ad292.CATALOG["b3"]["build_args"][1], _ad292.PIN_SOURCES["bluemap"].get("seq")),
       (_NEW_COMMIT292, _NEW_BLUEMAP292, _NEW_BLUEMAP292, ("B3_COMMIT", _NEW_COMMIT292), 5))
    row, _d = _row292(sid)
    eq("catalog accept (list route): a BlueMap installed at the floor's image is up to date before and offered "
       "Update after, and the row names the catalog it compared with",
       ((row0.get("update"), row0.get("pin_source")), (row.get("update"), row.get("pin_source"), row.get("version_new"))),
       (("", "Version source: built into this panel."),
        ("image", "Version source: signed add-on catalog #5 of 2026-11-25.", "v5 " + "2" * 12)))
    return data


# ── 3. refusals ─────────────────────────────────────────────────────────────────────────────────
def _refusals292(sid, priv, other, key, base, base_bytes):
    """Each refusal from the accepted catalog #5 (`base`, checked; `base_bytes`, as published), then #5 again."""
    expired = _doc292(6, issued="2026-01-01T00:00:00Z", expires="2026-02-01T00:00:00Z")
    short = _addons292(bluemap={"image": "ghcr.io/bluemap-minecraft/bluemap@sha256:" + "3" * 63})
    cases = [
        ("no signature", _doc292(6), "", _cat292.BAD_SIGNATURE),
        ("a key not in release-signers", _doc292(6), None, _cat292.BAD_SIGNATURE),
        ("the release namespace", _doc292(6), "release-ns", _cat292.BAD_SIGNATURE),
        ("schema 2", _doc292(6, schema=2), "", _cat292.BAD_SCHEMA),
        ("a lower seq (rollback)", _doc292(4), "", _cat292.ROLLBACK),
        ("an expired catalog", expired, "", _cat292.EXPIRED),
        ("a digest short of 64 hex", _doc292(6, addons=short), "", _cat292.BAD_PIN),
        ("an unknown add-on", _doc292(6, addons=_addons292(other={"image": _NEW_BLUEMAP292})), "",
         _cat292.UNKNOWN_ADDON),
        ("a missing add-on", _doc292(6, addons=_addons292(iw4madmin=None)), "", _cat292.UNKNOWN_ADDON),
    ]
    for name, data, how, why in cases:
        _reset292(base)
        if how is None:
            sig = _sign292(other, data)
        elif how == "release-ns":
            sig = _sign292(priv, data, namespace="linuxgsm-panel-release")
        else:
            sig = _sign292(priv, data) if name != "no signature" else ""
        _serve292(data, sig, key)
        code, body = _refresh292(sid)
        eq("catalog refused (route): %s is refused with its reason, and catalog #5 stays in use" % name,
           (code, body.get("success"), body.get("error"), _cat292._state["stored"]["seq"],
            _ad292.CATALOG["bluemap"]["image"]),
           (200, False, "The add-on catalog was refused: %s." % why, 5, _NEW_BLUEMAP292))
    _reset292(base)
    _serve292(base_bytes, _sign292(priv, base_bytes), key)
    code, body = _refresh292(sid)
    eq("catalog refresh (control): catalog #5 offered again is no newer, said as such, not a failure",
       (code, body.get("success"), body.get("message")), (200, True, "No newer add-on catalog: #5 of 2026-11-25 is the latest."))


# ── 4. which wins ───────────────────────────────────────────────────────────────────────────────
def _wins292(sid, base):
    _p9_patch(_cat292, "_floor_time", lambda: _FLOOR_AT292)
    stored = _json292.loads(base.decode("utf-8"))
    pins, src = _cat292.effective(stored, 1796000000, 1796000001)        # this panel's commit after the catalog
    eq("catalog wins: a catalog issued before this panel's own commit loses to the floor (the panel is newer)",
       (pins["b3"]["commit"], src["b3"]), (_cat292.FLOOR["b3"]["commit"], {"kind": "floor"}))
    pins, src = _cat292.effective(stored, None, 0)
    eq("catalog wins: with this panel's commit time unknown, the floor wins", pins["bluemap"], _cat292.FLOOR["bluemap"])
    older = dict(stored, addons=_addons292(b3=dict(_cat292.FLOOR["b3"], tag="v1.9.9", commit="4" * 40)))
    pins, src = _cat292.effective(older, _FLOOR_AT292, 0)
    eq("catalog wins: an entry with an older release than the floor's is not used; the others are",
       (pins["b3"]["commit"], src["b3"]["kind"], pins["bluemap"]["image"], src["bluemap"]["kind"]),
       (_cat292.FLOOR["b3"]["commit"], "floor", _NEW_BLUEMAP292, "catalog"))
    pins, src = _cat292.effective(stored, _FLOOR_AT292, 4102444800)        # 2100: past its expiry
    eq("catalog freeze: an expired catalog keeps its pins (the older floor is not offered) and is marked expired",
       (pins["bluemap"]["image"], src["bluemap"].get("expired")), (_NEW_BLUEMAP292, True))
    # Through the list route: a BlueMap installed at the floor's image, the catalog #5 in use but expired.
    _p9_patch(_cat292, "time", _NS292(time=lambda: 4102444800.0))
    _reset292(stored)
    row, d = _row292(sid)
    eq("catalog freeze (list route): an expired catalog offers no update and the card says it expired",
       (row.get("update"), d.get("catalog_note")),
       ("", "The signed add-on catalog #5 expired on 2099-01-01 and no newer one has been fetched, so it offers no "
            "updates until one is."))


# ── 5. the stored copy, the daily task, the switch, the permission ─────────────────────────────
def _stored292(priv, key):
    _serve292(b"", "", key)
    _reset292(None)
    _cat292._state["loaded"] = False
    _cat292.ensure_loaded()
    eq("catalog store: read again at start, checked again, and put in use",
       (_cat292._state["stored"] or {}).get("seq"), 5)
    with open(_cat292.store_file(), encoding="utf-8") as fh:
        doc = _json292.load(fh)
    with open(_cat292.store_file(), "w", encoding="utf-8") as fh:
        _json292.dump(dict(doc, catalog=doc["catalog"].replace("1" * 40, "5" * 40)), fh)
    _reset292(None)
    _cat292._state["loaded"] = False
    _cat292.ensure_loaded()
    eq("catalog store: a stored copy changed after it was signed is not used (the floor is)",
       (_cat292._state["stored"], _ad292.B3_COMMIT), (None, _cat292.FLOOR["b3"]["commit"]))
    data = _doc292(7)
    seen = _serve292(data, _sign292(priv, data), key)
    _reset292(None)
    _cat292.daily_tick()
    _cat292.daily_tick()
    first = (len(seen), (_cat292._state["stored"] or {}).get("seq"))
    _cat292._state["fetched_at"] -= _cat292.EVERY
    _cat292.daily_tick()
    eq("catalog daily: it fetches at its first pass, not again within the day, and again a day later",
       (first, len(seen)), ((1, 7), 2))
    seen[:] = []
    _cat292._state["fetched_at"] = 0.0
    a = _cat292.refresh()
    b = _cat292.refresh()
    eq("catalog refresh: a second Refresh inside a minute gets the last answer without fetching again",
       (len(seen), a == b), (1, True))


def _published292():
    calls = []

    def git(args, timeout=45):
        calls.append(list(args))
        return "", "", 0
    _p9_patch(_so292, "_git", git)
    _p9_patch(_so292, "_is_git_checkout", lambda: True)
    from panel.core import outside_services as _out292
    _p9_patch(_out292, "enabled", lambda key: False)
    got_off = _cat292._published()
    off_calls = len(calls)
    _p9_patch(_out292, "enabled", lambda key: True)
    got_none = _cat292._published()
    eq("catalog fetch: with the update check off nothing is fetched; a published ref with no catalog is said so",
       (got_off[2], off_calls, got_none[2], calls[0][:4], calls[0][-1]),
       (_cat292.OFF, 0, _cat292.NONE_PUBLISHED, ["fetch", "--quiet", "--no-tags", "origin"],
        "+refs/heads/release-signatures:refs/linuxgsm-panel/release-signatures"))


def _permission292(sid):
    code, body = _refresh292(sid, _p9_client(P9_VIEWER))
    eq("catalog refresh (route): without Manage add-ons, Refresh's fetch is refused", (code, body.get("success")),
       (403, False))


# ── run ─────────────────────────────────────────────────────────────────────────────────────────
_floor292()
if not _HAVE_KEYGEN292:
    skip("catalog: ssh-keygen present to sign and verify throwaway catalogs", "no ssh-keygen on this runner")
else:
    _priv292, _key292 = _keygen292("signer")
    _other292 = _keygen292("stranger")[0]
    _sid292 = _p9_new_server(P9_HOST, "mcp292", "mc", 25565, name="p292-mc")
    _cat292.STORE_FILE = os.path.join(_TMP292, "addon-catalog.json")
    try:
        _p9_restore_all()
        _p9_arm(who="part292")
        _reset292(None)
        _base292 = _accept292(_sid292, _priv292, _key292)
        _refusals292(_sid292, _priv292, _other292, _key292,
                     _cat292.check_signed(_base292, _sign292(_priv292, _base292), _key292, 0, 0)[0], _base292)
        _p9_restore_all()
        _p9_arm(who="part292")
        _host292({"kind": "bluemap", "image": _cat292.FLOOR["bluemap"]["image"], "mc_version": "1.21.4"})
        _wins292(_sid292, _base292)
        _p9_restore_all()
        _p9_arm(who="part292")
        _stored292(_priv292, _key292)
        _p9_restore_all()
        _published292()
        _p9_restore_all()
        _p9_arm(who="part292")
        _permission292(_sid292)
    finally:
        _p9_restore_all()
        _cat292.STORE_FILE = None
        _reset292(None)
        _cat292._state["loaded"] = False
        _p9_delete_server(_sid292)
check("part292: the floor is back in use when the part ends",
      (_ad292.CATALOG["bluemap"]["image"], _ad292.B3_COMMIT, _ad292.PIN_SOURCES["b3"])
      == (_cat292.FLOOR["bluemap"]["image"], _cat292.FLOOR["b3"]["commit"], {"kind": "floor"}))
check("part292: no check reached a real host", len(_P9_TRIPPED) == _trips292, repr(_P9_TRIPPED[_trips292:][:4]))
_shutil292.rmtree(_TMP292, ignore_errors=True)
