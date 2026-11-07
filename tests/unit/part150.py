"""Part 150 of the unit suite: the app shell — install as an app, the light theme, "What's new".

* /manifest.webmanifest is public, says nothing but the site title and icon URLs, and its
  start_url, scope and icons follow the prefix the panel is served under;
* an account's colour scheme is saved by /account/theme and drawn by the SERVER into <html>, so a
  page never paints in the other scheme first ("system" is decided by the head script);
* "What's new" lists the changelog entries an account has not seen, as text, once per update:
  dismissing it records them, a new account starts at what is there now, and an upgrade stamps
  every existing account instead of showing them the whole history.
"""
import os
import re
import struct
import tempfile

from flask import Flask as _Flask150
from sqlalchemy import text as _sa_text150

from unit.part01 import check
from unit.part12 import P9_ADMIN, P9_VIEWER, _p9, _p9_client, _p9_patch, _p9_restore_all
from panel.core import whats_new as _wn150
from panel.db import models as _models150
from panel.db.models import User, db

_root150 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── the changelog parser ─────────────────────────────────────────────────────────────────────────
_CL150 = """# Changelog

- a preamble line that is not an entry

## [Unreleased]

### Added

- **Phones can install it.** The panel has a manifest,
  wrapped onto a second line, with `code` and a [link](https://example.test/x).
  - a nested point that belongs to it
- A bullet with no bold lead. Its first sentence is the title.

### Fixed

- **Console lines no longer double.** They did.

<!-- a comment ends the list -->

## [0.1.0] — 2026-01-01

### Fixed

- **An old fix.** From long ago.
"""
_e150 = _wn150.parse(_CL150)
check("whats_new.parse: every top-level bullet under a category heading, in file order, and nothing "
      "from the preamble",
      [(e["category"], e["title"]) for e in _e150] == [
          ("Added", "Phones can install it."),
          ("Added", "A bullet with no bold lead."),
          ("Fixed", "Console lines no longer double."),
          ("Fixed", "An old fix.")], repr([(e["category"], e["title"]) for e in _e150]))
check("whats_new.parse: a wrapped bullet's body is one line of plain text — no **, backticks or link "
      "URL — and keeps its nested points",
      _e150[0]["body"] == "The panel has a manifest, wrapped onto a second line, with code and a link. "
                          "- a nested point that belongs to it", repr(_e150[0]["body"]))
_moved150 = _wn150.parse(_CL150.replace("- **Phones can install it.**", "- **Moved.**", 1)
                         + "\n### Added\n\n- **Phones can install it.** Now released.\n")
check("whats_new: an entry moved to another section (or with its body reworded) keeps its key",
      _e150[0]["key"] in {e["key"] for e in _moved150}
      and next(e for e in _moved150 if e["title"] == "Phones can install it.")["key"] == _e150[0]["key"])

_older150 = _wn150.stamp(_e150[1:])          # an account that saw the file before the first entry
check("whats_new.unseen: an account that saw the older file is shown exactly the added entry",
      [e["title"] for e in _wn150.unseen(_older150, _e150)] == ["Phones can install it."],
      repr(_wn150.unseen(_older150, _e150)))
check("whats_new.unseen: nothing once it has seen the current file",
      _wn150.unseen(_wn150.stamp(_e150), _e150) == [])
check("whats_new.unseen: nothing for an account that never recorded anything (None or empty)",
      _wn150.unseen(None, _e150) == [] and _wn150.unseen("", _e150) == [])
check("whats_new.stamp: nothing to record for a changelog that could not be read",
      _wn150.stamp([]) == "" and _wn150.current_entries(os.path.join(_root150, "no-such.md")) == [])

_real150 = _wn150.current_entries()
check("whats_new.current_entries: the panel's own CHANGELOG parses, this change's entries included",
      len(_real150) > 100 and any(e["title"] == "A light theme." for e in _real150)
      and any(e["title"] == "Install the panel on a phone's home screen." for e in _real150),
      repr(len(_real150)))

# ── the migration: an upgrade stamps the accounts that exist, a new account starts at "now" ───────
_NOLOGIN150 = "!"               # not a hash any password matches: these rows never sign in
_TMP150 = tempfile.mkdtemp(prefix="lgsm-unit-p150-")
_mig150 = _Flask150("unit_part150_mig")
_mig150.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP150, "upgrade.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
db.init_app(_mig150)
with _mig150.app_context():
    db.create_all()
    db.session.add(User(username="p150old", password_hash=_NOLOGIN150))
    db.session.commit()
    db.session.execute(_sa_text150("ALTER TABLE user DROP COLUMN whats_new_seen"))
    db.session.execute(_sa_text150("ALTER TABLE user DROP COLUMN theme"))
    db.session.commit()
    _models150._run_light_migrations()
    _upg150 = db.session.execute(_sa_text150(
        "SELECT theme, whats_new_seen FROM user WHERE username = 'p150old'")).one()
    db.session.add(User(username="p150new", password_hash=_NOLOGIN150))
    db.session.commit()
    _new150 = db.session.execute(_sa_text150(
        "SELECT theme, whats_new_seen FROM user WHERE username = 'p150new'")).one()
    db.session.remove()
_now150 = _wn150.current_stamp()
check("migration: an upgraded account gains theme='system' and is stamped with the changelog as it "
      "is now (so it is not shown every entry ever written)",
      _upg150[0] == "system" and _now150 and _upg150[1] == _now150, repr((_upg150[0], (_upg150[1] or "")[:20])))
check("a brand-new account starts at the changelog as it is now: it sees nothing until an update",
      _new150[0] == "system" and _new150[1] == _now150, repr((_new150[0], (_new150[1] or "")[:20])))


# ── the manifest ─────────────────────────────────────────────────────────────────────────────────
def _png_size150(path):
    with open(path, "rb") as f:
        head = f.read(24)
    return struct.unpack(">II", head[16:24]) if head[:8] == b"\x89PNG\r\n\x1a\n" else None


_anon150 = _p9.test_client()
_mr150 = _anon150.get("/manifest.webmanifest")
_m150 = _mr150.get_json(force=True, silent=True) or {}
check("manifest: public (no session), served as application/manifest+json",
      _mr150.status_code == 200 and _mr150.mimetype == "application/manifest+json",
      repr((_mr150.status_code, _mr150.mimetype)))
check("manifest: installable — standalone, a name, start_url and scope at the panel's root",
      _m150.get("display") == "standalone" and isinstance(_m150.get("name"), str) and _m150["name"]
      and _m150.get("start_url") == "/" and _m150.get("scope") == "/", repr(_m150))
check("manifest: carries nothing but its own fields (no user, host or server data)",
      set(_m150) == {"name", "short_name", "id", "start_url", "scope", "display",
                     "background_color", "theme_color", "icons"}, repr(sorted(_m150)))
_icons150 = {(i["sizes"], i["purpose"]): i["src"] for i in _m150.get("icons", [])}
_files_ok150 = []
for (_sz150, _pu150), _src150 in _icons150.items():
    # The URL is /static/...; the files behind it are in panel/static/ (app.py's static_folder).
    _path150 = os.path.join(_root150, "panel", _src150.lstrip("/"))
    _w150 = int(_sz150.split("x")[0])
    _files_ok150.append(_png_size150(_path150) == (_w150, _w150))
check("manifest: a 192 and a 512 icon, and a maskable 512, each a PNG of the size it claims",
      set(_icons150) == {("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")}
      and all(_files_ok150) and len(_files_ok150) == 3, repr((_icons150, _files_ok150)))
_mp150 = _anon150.get("/manifest.webmanifest", base_url="http://localhost/lgsm").get_json(force=True, silent=True) or {}
check("manifest: under a path prefix (Tailscale Serve) start_url, scope and icons follow it",
      _mp150.get("start_url") == "/lgsm/" and _mp150.get("scope") == "/lgsm/"
      and all(i["src"].startswith("/lgsm/static/icons/") for i in _mp150.get("icons", [])), repr(_mp150))
check("apple-touch-icon: the file base.html links is a 180px PNG",
      _png_size150(os.path.join(_root150, "panel", "static", "icons", "apple-touch-icon.png")) == (180, 180))


# ── the colour scheme ────────────────────────────────────────────────────────────────────────────
def _html_tag150(page):
    m = re.search(r"<html\b[^>]*>", page)
    return m.group(0) if m else ""


def _row150(uid, *cols):
    with _p9.app_context():
        u = db.session.get(User, uid)
        return tuple(getattr(u, c) for c in cols)


def _put150(uid, **fields):
    with _p9.app_context():
        u = db.session.get(User, uid)
        for k, v in fields.items():
            setattr(u, k, v)
        db.session.commit()


_saved150 = {uid: _row150(uid, "theme", "whats_new_seen") for uid in (P9_ADMIN, P9_VIEWER)}
try:
    _adm150 = _p9_client(P9_ADMIN)
    _r1 = _adm150.post("/account/theme", json={"theme": "light"})
    _acct150 = _adm150.get("/account").get_data(as_text=True)
    check("theme: /account/theme saves 'light' to the account",
          _r1.status_code == 200 and (_r1.get_json() or {}).get("success") is True
          and _row150(P9_ADMIN, "theme") == ("light",), repr((_r1.status_code, _row150(P9_ADMIN, "theme"))))
    check("theme: a light account's pages are drawn light by the server, in the <html> tag",
          'data-bs-theme="light"' in _html_tag150(_acct150)
          and 'data-theme-pref="light"' in _html_tag150(_acct150), _html_tag150(_acct150))
    check("theme: the Account page's picker shows the saved choice",
          re.search(r'<option value="light"\s+selected>', _acct150) is not None)
    _bad150 = _adm150.post("/account/theme", json={"theme": "solarized"})
    check("theme: anything but system / dark / light is refused and changes nothing",
          _bad150.status_code == 400 and _row150(P9_ADMIN, "theme") == ("light",),
          repr((_bad150.status_code, _row150(P9_ADMIN, "theme"))))
    _adm150.post("/account/theme", data={"theme": "system"})
    _sys150 = _adm150.get("/account").get_data(as_text=True)
    _head150 = _sys150[:_sys150.find("</head>")]
    check("theme: 'system' is drawn dark with the preference on <html>, and the script that follows "
          "the device runs before the first stylesheet",
          'data-bs-theme="dark"' in _html_tag150(_sys150) and 'data-theme-pref="system"' in _html_tag150(_sys150)
          and 0 < _head150.find("prefers-color-scheme: light") < _head150.find('rel="stylesheet"'),
          _html_tag150(_sys150))
    check("theme: every page links the manifest and the apple-touch-icon",
          'rel="manifest" href="/manifest.webmanifest"' in _head150
          and 'rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png"' in _head150)
    _put150(P9_ADMIN, theme="neon")
    check("theme: a stored value the panel does not know reads as 'system'",
          'data-theme-pref="system"' in _html_tag150(_adm150.get("/account").get_data(as_text=True)))
    _anon_t150 = _anon150.post("/account/theme", json={"theme": "light"})
    check("theme: saving needs a signed-in account",
          _anon_t150.status_code in (302, 401, 403), repr(_anon_t150.status_code))

    # ── What's new ─────────────────────────────────────────────────────────────────────────────
    _fake150 = [{"category": "Added", "title": "Entry %d <img src=x onerror=alert(1)>" % i,
                 "body": "Body %d <script>alert(1)</script>" % i, "key": "%08x" % i} for i in range(50)]
    _p9_patch(_wn150, "current_entries", lambda path=None: _fake150)
    _put150(P9_ADMIN, whats_new_seen=_wn150.stamp(_fake150[3:]))
    _page150 = _adm150.get("/account").get_data(as_text=True)
    _dlg150 = _page150[_page150.find('<dialog id="whats-new"'):_page150.find("</dialog>")]
    check("what's new: an account behind the changelog is shown the dialog with exactly the new entries",
          bool(_dlg150) and all("Entry %d " % i in _dlg150 for i in range(3))
          and "Entry 3 " not in _dlg150, _dlg150[:300])
    check("what's new: the changelog's text is escaped, never markup from the file",
          "<img src=x" not in _dlg150 and "<script>alert" not in _dlg150
          and "&lt;img src=x onerror=alert(1)&gt;" in _dlg150)
    _put150(P9_ADMIN, whats_new_seen=None)
    _big150 = _adm150.get("/account").get_data(as_text=True)
    check("what's new: an account with nothing recorded is shown nothing",
          'id="whats-new"' not in _big150)
    _put150(P9_ADMIN, whats_new_seen=_wn150.stamp(_fake150[:1]))
    _big150 = _adm150.get("/account").get_data(as_text=True)
    _shown150 = len(re.findall(r'<details>\s*<summary><span class="badge wn-cat">', _big150))
    check("what's new: a long list shows five, folds the rest under 'More changes' with the full count, "
          "and renders at most SHOW_MAX",
          _shown150 == _wn150.SHOW_MAX and "More changes" in _big150
          and "(%d)" % (49 - 5) in _big150 and "The rest are in the full changelog." in _big150,
          repr(_shown150))
    # The viewer is behind BEFORE the admin dismisses: a dismissal that wrote every account would
    # otherwise be overwritten here and never seen.
    _put150(P9_VIEWER, whats_new_seen=_wn150.stamp(_fake150[1:]))
    _seen150 = _adm150.post("/api/account/whats-new/seen")
    check("what's new: dismissing records the changelog as it is now, and the dialog does not come back",
          _seen150.status_code == 200 and _row150(P9_ADMIN, "whats_new_seen") == (_wn150.stamp(_fake150),)
          and 'id="whats-new"' not in _adm150.get("/account").get_data(as_text=True),
          repr(_seen150.status_code))
    check("what's new: it is per account — another account behind the changelog still sees it",
          'id="whats-new"' in _p9_client(P9_VIEWER).get("/account").get_data(as_text=True))
    check("what's new: recording needs a signed-in account",
          _anon150.post("/api/account/whats-new/seen").status_code in (302, 401, 403))
finally:
    _p9_restore_all()
    for _uid150, (_t150, _s150) in _saved150.items():
        _put150(_uid150, theme=_t150, whats_new_seen=_s150)


# ── Published titles stay put ───────────────────────────────────────────────────────────────────
# An entry's key is a hash of its title, and a panel shows every key an account has not recorded,
# so rewording a title already on main shows that old change to everyone again as if it were new
# (2026-11-07: "Updates install only releases signed with the …" was reworded, and the update
# showed it as the only "new" item). whats_new_published.txt lists every published key.
def _published150():
    """{key: title} from tests/unit/whats_new_published.txt (comments and blanks skipped)."""
    out = {}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "whats_new_published.txt"),
              encoding="utf-8") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                key, _sp, title = line.rstrip("\n").partition(" ")
                out[key] = title
    return out


def _title_drift150(published, entries):
    """(published titles no longer in `entries`, entries whose key is not published)."""
    have = {e["key"] for e in entries}
    return ([published[k] for k in published if k not in have],
            [e["title"] for e in entries if e["key"] not in published])


_pub150 = _published150()
with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                       "docs", "CHANGELOG.md"), encoding="utf-8") as _fh150:
    _cl150 = _fh150.read()
_gone150, _new150 = _title_drift150(_pub150, _wn150.parse(_cl150))
check("what's new: no published title was reworded or dropped (a reworded title re-shows an old "
      "change as new to every account; put the old title back, or drop the line here only with "
      "its entry)", not _gone150 and len(_pub150) > 100, repr(_gone150[:5]))
check("what's new: every entry's key is listed in tests/unit/whats_new_published.txt (add one "
      "line '<key> <title>' for a genuinely new entry)", not _new150,
      "\n".join("%s %s" % (_wn150._cmpb_key(t), t) for t in _new150[:10]))
# Control: the check sees a rename. Reword the first published title in a copy of the file.
_first150 = next((t for t in _pub150.values() if "**" + t in _cl150), "")
_ren150 = _title_drift150(
    _pub150, _wn150.parse(_cl150.replace("**" + _first150, "**Renamed: " + _first150, 1)))
check("what's new: (control) a reworded title is caught as dropped AND as unlisted",
      bool(_first150) and _first150 in _ren150[0] and len(_ren150[1]) == 1, repr(_ren150))
