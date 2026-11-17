"""Part 231 of the unit suite: the breached-password check (panel/core/breached_passwords.py).

OWASP Authentication Cheat Sheet, "Implement Proper Password Strength Controls": block common and
previously breached passwords. The order: the bundled screen (common_passwords), then the downloaded
100k list (pinned by SHA-256), then Pwned Passwords' range API only when both pass and the
`breach_check_online` setting is on — five SHA-1 hex characters sent, padded lines ignored, no
answer accepted. Driven through password_problem, the Account page's password change and the setup
wizard's first-admin step; install.sh's ensure_password_list is run as written against file:// URLs.
Every network call is stubbed: the suites' LGSM_PANEL_OFFLINE and part12's tripwire are checked too.
"""
import glob as _glob231
import hashlib as _hl231
import os as _os231
import re as _re231
from shlex import quote as _shq231
import subprocess as _sub231  # nosec B404 - bash over the repo's own install.sh function text
import tempfile as _tf231
import urllib.error as _ue231
import urllib.request as _ur231
from types import SimpleNamespace as _NS231

from unit.part01 import _r21d_urlopen_of, _root, check
from unit.part06 import _inst, _inst_shfn
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_flashes, _p9_patch, _p9_restore_all
from panel.core import breached_passwords as _bp231, config as _cfg231
from panel.core.validation import password_problem as _pp231
from panel.db.models import User as _U231, db as _db231
from panel.routes import route_helpers as _rh231
from panel.security import auth as _auth231

_trips231 = len(_P9_TRIPPED)
_IDS231 = []
_K231 = "orchard tidal compass"              # the fixtures' sign-in password (no real credential)
_LISTED231 = "Kestrel-Window-2093"           # on the fixture list only (passes the bundled screen)
_PWNED231 = "violet anchor sideways"         # "breached" only by the stubbed range answer
_FRESH231 = "granite puzzle meadow"          # on nothing
_BREACH_MSG231 = "appeared in a data breach"
_DIR231 = _tf231.mkdtemp(prefix="p231-")
_CALLS231 = []
# The real network function, taken before any check arms part12's tripwire over it (part12 has put
# it back by now). The checks that exercise it give it a urlopen stand-in, never the network.
_REAL_FETCH231 = _bp231._fetch_range
_PIN231 = _bp231.LIST_SHA256                  # before _fixture_list231 pins a fixture's hash over it


def _range_for231(secret, count=7):
    """A padded range answer holding `secret`'s suffix with `count`, plus count-0 decoys."""
    _pre, suf = _bp231.sha1_parts(secret)
    return "\r\n".join(["0018A45C4D1DEF81644B54AB7F969B88D65:1", "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0",
                        "%s:%d" % (suf, count), "011053FD0102E94D6AE2F8B83D76FAF94F6:0"])


def _stub_fetch231(answer):
    """Replace the one network function: record each prefix asked, answer `answer(prefix)`."""
    def _fetch(prefix):
        _CALLS231.append(prefix)
        return answer(prefix)
    _CALLS231.clear()
    _p9_patch(_bp231, "_fetch_range", _fetch)


class _Online231:
    """Within the block, the suite's LGSM_PANEL_OFFLINE is unset (the stubs stand in for the network)."""

    def __enter__(self):
        self.saved = _os231.environ.pop(_bp231.OFFLINE_ENV, None)
        return self

    def __exit__(self, *_exc):
        if self.saved is not None:
            _os231.environ[_bp231.OFFLINE_ENV] = self.saved


def _setting231(value):
    """Store breach_check_online as `value` (None removes it: the default)."""
    def _mut(cfg):
        if value is None:
            cfg.pop(_bp231.SETTING, None)
        else:
            cfg[_bp231.SETTING] = value
    _cfg231.update_config(_mut)


def _fixture_list231(words=("123456", "password", _LISTED231.lower(), "sunflower99")):
    """Write a small list at a scratch list_path() and pin its hash; its bytes."""
    raw = ("\n".join(words) + "\n").encode()
    path = _os231.path.join(_DIR231, _bp231.LIST_NAME)
    if _os231.path.lexists(path):
        _os231.unlink(path)
    with open(path, "wb") as fh:
        fh.write(raw)
    _p9_patch(_bp231, "list_path", lambda: path)
    _p9_patch(_bp231, "LIST_SHA256", _hl231.sha256(raw).hexdigest())
    return raw


# ── 1. k-anonymity: what is sent ────────────────────────────────────────────────────────────────
class _Resp231:
    """A urlopen response holding `body`."""

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def read(self, n=-1):
        """The body, at most `n` bytes."""
        return self.body[:n] if n and n > 0 else self.body


def _capture231():
    """Run the real _fetch_range against a stand-in opener; (requests seen, handlers given, body)."""
    seen, handlers = [], []

    def _open(req, timeout=None):
        seen.append((req.full_url, dict(req.header_items()), timeout))
        return _Resp231(_range_for231(_PWNED231).encode())

    _p9_patch(_bp231, "_fetch_range", _REAL_FETCH231)
    _uo = _r21d_urlopen_of(_bp231)
    _uo.build_opener = lambda *h: handlers.extend(h) or _NS231(open=_open)
    try:
        return seen, handlers, _bp231._fetch_range(_bp231.sha1_parts(_PWNED231)[0])
    finally:
        del _uo.build_opener


def _s231_request_shape():
    seen, handlers, body = _capture231()
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- the range API's key
    digest = _hl231.sha1(_PWNED231.encode(), usedforsecurity=False).hexdigest().upper()
    url, headers, timeout = seen[0] if seen else ("", {}, None)
    check("breach check: the request names only the hash's first five hex characters",
          url == "https://api.pwnedpasswords.com/range/" + digest[:5], url)
    check("breach check: ...and neither the rest of the hash nor the password is in the URL or a header",
          not any(digest[5:] in str(v) or _PWNED231 in str(v) for v in [url, *headers.values()]), repr(headers))
    check("breach check: the request asks for padding and names the panel, with a 3-second timeout",
          headers.get("Add-padding") == "true" and headers.get("User-agent") == "linuxgsm-panel" and timeout == 3,
          repr((headers, timeout)))
    check("breach check: sha1_parts splits the upper-case SHA-1 into 5 + 35 characters",
          _bp231.sha1_parts("password") == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
          repr(_bp231.sha1_parts("password")))
    _request_rest231(handlers, body)


def _request_rest231(handlers, body):
    refusers = [h for h in handlers if isinstance(h, type) and issubclass(h, _ur231.HTTPRedirectHandler)]
    check("breach check: the request refuses every redirect",
          len(refusers) == 1 and refusers[0]().redirect_request(None, None, 302, "", {}, "https://elsewhere.test/") is None,
          repr(handlers))
    check("breach check: the answer is returned as text", body is not None and _bp231.sha1_parts(_PWNED231)[1] in body,
          repr(body)[:80])


def _s231_padding_and_failure():
    suf = _bp231.sha1_parts(_PWNED231)[1]
    padded = "\r\n".join(["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0", "%s:0" % suf])
    check("breach check: a count-0 padding line for the suffix is not a hit",
          _bp231.count_in_range(padded, suf) == 0, repr(_bp231.count_in_range(padded, suf)))
    check("breach check: a real line is read with its count (lower-case answer too)",
          _bp231.count_in_range(_range_for231(_PWNED231, 41).lower(), suf) == 41,
          repr(_bp231.count_in_range(_range_for231(_PWNED231, 41).lower(), suf)))

    def _down(_req, timeout=None):
        raise _ue231.URLError("unreachable")

    _p9_patch(_bp231, "_fetch_range", _REAL_FETCH231)
    _uo = _r21d_urlopen_of(_bp231)
    _uo.build_opener = lambda *h: _NS231(open=_down)
    try:
        with _Online231():
            _setting231(None)
            try:
                got, verdict = _bp231.pwned_count(_PWNED231), _pp231(_PWNED231)
            except Exception as e:      # recorded, so the checks below fail by name
                got = verdict = e
    finally:
        del _uo.build_opener
    check("breach check: the network function is the module's own, not a stand-in left by another part",
          _REAL_FETCH231.__module__ == _bp231.__name__ and _REAL_FETCH231.__name__ == "_fetch_range",
          repr(_REAL_FETCH231))
    check("breach check: the service not answering is no answer, not an exception", got is None, repr(got))
    check("breach check: ...and the password is accepted on the local result", verdict is None, repr(verdict))


# ── 2. the order: bundled screen, list, then the service ──────────────────────────────────────
def _s231_order():
    _fixture_list231()
    _stub_fetch231(lambda prefix: _range_for231(_PWNED231))
    with _Online231():
        _setting231(None)
        common = _pp231("Password12345678")
        asked_common = list(_CALLS231)
        listed = _pp231(_LISTED231, has_mfa=True)
        asked_listed = list(_CALLS231)
        pwned = _pp231(_PWNED231)
        asked_pwned = list(_CALLS231)
        fresh = _pp231(_FRESH231)
    check("breach check: a password the bundled screen refuses is refused without asking the service",
          common is not None and "too common" in common and asked_common == [], repr((common, asked_common)))
    check("breach check: a password on the downloaded list is refused as breached, without asking the service",
          listed is not None and _BREACH_MSG231 in listed and asked_listed == [], repr((listed, asked_listed)))
    check("breach check: ...the list match ignores case",
          _bp231.in_downloaded_list(_LISTED231.upper()) and not _bp231.in_downloaded_list(_LISTED231[:-1]),
          _LISTED231)
    check("breach check: a password on neither is sent to the service, which refuses it when it has it",
          pwned is not None and _BREACH_MSG231 in pwned and asked_pwned == [_bp231.sha1_parts(_PWNED231)[0]],
          repr((pwned, asked_pwned)))
    check("breach check: ...and one the service does not have is accepted", fresh is None, repr(fresh))


def _s231_list_trust():
    _fixture_list231()
    path = _bp231.list_path()
    with open(path, "ab") as fh:
        fh.write(b"tampered entry\n")
    tampered = _bp231.in_downloaded_list(_LISTED231)
    _fixture_list231()
    _os231.unlink(path)
    missing = _bp231.in_downloaded_list(_LISTED231)
    real = _fixture_list231()
    elsewhere = _os231.path.join(_DIR231, "elsewhere.txt")
    with open(elsewhere, "wb") as fh:
        fh.write(real)
    _os231.unlink(path)
    _os231.symlink(elsewhere, path)
    linked = _bp231.in_downloaded_list(_LISTED231)
    _os231.unlink(path)
    check("breach check: a list that does not hash to its pin is not used", tampered is False, repr(tampered))
    check("breach check: a missing list is skipped, not an error", missing is False, repr(missing))
    check("breach check: a list reached through a link is not read", linked is False, repr(linked))
    with open(_os231.path.join(_root, "install.sh")) as fh:
        pins = _re231.findall(r'^PW_LIST_SHA256="([0-9a-f]{64})"$', fh.read(), _re231.M)
    check("breach check: the panel pins the same SHA-256 install.sh downloads by",
          pins == [_PIN231] and len(set(_PIN231)) > 1, repr((pins, _PIN231)))


# ── 3. the switch and the suites' guard ─────────────────────────────────────────────────────────
def _s231_switch():
    _stub_fetch231(lambda prefix: _range_for231(_PWNED231))
    with _Online231():
        _setting231(False)
        off = _pp231(_PWNED231)
        asked_off = list(_CALLS231)
        _setting231(True)
        on = _pp231(_PWNED231)
    _setting231(None)
    with _Online231():
        default = _bp231.online_enabled()
    _CALLS231.clear()
    guarded = _pp231(_PWNED231)
    check("breach check: with the setting off the service is not asked and the password is accepted",
          off is None and asked_off == [], repr((off, asked_off)))
    check("breach check: ...and with it on, it is", on is not None and _BREACH_MSG231 in on, repr(on))
    check("breach check: the setting is on by default", default is True, repr(default))
    check("breach check: with LGSM_PANEL_OFFLINE set the service is never asked, the setting on",
          guarded is None and _CALLS231 == [], repr((guarded, _CALLS231)))


def _s231_suites_offline():
    runners = sorted(_glob231.glob(_os231.path.join(_root, "tests", "*_test.py")))
    missing = [r for r in runners
               if not _re231.search(r"^(import suite_deadline|.*import_module\(\"suite_deadline\"\))", open(r).read(), _re231.M)]
    with open(_os231.path.join(_root, "tests", "suite_deadline.py")) as fh:
        sd = fh.read()
    before = len(_P9_TRIPPED)
    answer = _bp231._fetch_range("00000")       # part12's tripwire, armed by the loop below
    tripped = _P9_TRIPPED[before:]
    del _P9_TRIPPED[before:]                    # an expected trip, not a leak: the last check counts
    check("breach check: part12's tripwire stands in for the one network call and records it",
          answer is None and [t[0] for t in tripped] == ["breached_passwords._fetch_range"], repr(tripped))
    check("breach check: every suite runner imports suite_deadline", len(runners) >= 9 and not missing,
          repr((len(runners), missing)))
    check("breach check: ...which sets LGSM_PANEL_OFFLINE for the run and what it starts",
          'OFFLINE_ENV = "%s"' % _bp231.OFFLINE_ENV in sd and "os.environ[OFFLINE_ENV] = \"1\"" in sd
          and _os231.environ.get(_bp231.OFFLINE_ENV) == "1", _bp231.OFFLINE_ENV)


# ── 4. through the routes ──────────────────────────────────────────────────────────────────────
def _user231(name):
    with _p9.app_context():
        u = _U231(username=name, password_hash=_auth231.hash_password(_K231), display_name=name,
                  is_superadmin=False, is_active=True)
        _db231.session.add(u)
        _db231.session.commit()
        _IDS231.append(u.id)
        return u.id


def _hash_of231(uid):
    with _p9.app_context():
        return _db231.session.get(_U231, uid).password_hash


def _s231_account_route():
    uid = _user231("p231_change")
    before = _hash_of231(uid)
    _stub_fetch231(lambda prefix: _range_for231(_PWNED231))
    c = _p9_client(uid)
    form = {"current_password": _K231, "new_password": _PWNED231, "confirm_password": _PWNED231}
    with _Online231():
        _setting231(None)
        r = c.post("/account/password", data=form)
        said = _p9_flashes(c)
        asked = list(_CALLS231)
        unchanged = _hash_of231(uid) == before
        _stub_fetch231(lambda prefix: None)
        r2 = c.post("/account/password", data=form)
        said2 = _p9_flashes(c)
    check("breach check: the Account page refuses a breached new password, saying why, and keeps the old one",
          r.status_code == 302 and any(_BREACH_MSG231 in m for m in said) and unchanged, repr(said))
    check("breach check: ...asking the service once, with five characters", asked == [_bp231.sha1_parts(_PWNED231)[0]],
          repr(asked))
    check("breach check: ...and with no answer from the service it accepts the password",
          r2.status_code == 302 and any("has been changed" in m for m in said2) and _hash_of231(uid) != before,
          repr(said2))


def _s231_setup_step():
    made = []

    _none = _NS231(first=lambda: None)
    _p9_patch(_rh231, "User", _NS231(query=_NS231(filter_by=lambda **_k: _none)))
    _p9_patch(_rh231, "_create_first_admin", lambda *a: made.append(a[2]) or "created")
    _stub_fetch231(lambda prefix: _range_for231(_PWNED231))
    form = {"username": "p231first", "password": _PWNED231, "confirm_password": _PWNED231}
    with _Online231(), _p9.test_request_context("/setup", method="POST", data=form):
        _setting231(None)
        _rh231._setup_admin_user({}, {})
        from flask import get_flashed_messages
        said = get_flashed_messages()
    check("breach check: the setup wizard refuses a breached first-admin password, asking the service once",
          not made and any(_BREACH_MSG231 in m for m in said) and len(_CALLS231) == 1, repr((said, _CALLS231)))


# ── 5. install.sh's ensure_password_list ────────────────────────────────────────────────────────
def _run_list231(panel_dir, url, pin):
    script = "\n".join(["set -euo pipefail", 'ok() { echo "OK $*"; }', 'warn() { echo "WARN $*"; }',
                        "PANEL_USER=nobody", "PANEL_DIR=%s" % _shq231(panel_dir),
                        _inst_shfn("_r42i_tree_owner"), _inst_shfn("ensure_password_list"),
                        "PW_LIST_URL=%s" % _shq231(url), "PW_LIST_SHA256=%s" % _shq231(pin),
                        "ensure_password_list; echo RC=$?"])
    p = _sub231.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)  # nosec B603 B607
    return p.stdout + p.stderr


_LIST_BYTES231 = b"123456\npassword\n"


def _list_src231():
    """A scratch list file and its SHA-256: (file:// URL, pin, panel dir, the list's place in it)."""
    src = _os231.path.join(_DIR231, "src-list.txt")
    with open(src, "wb") as fh:
        fh.write(_LIST_BYTES231)
    pd = _tf231.mkdtemp(prefix="p231-pd-", dir=_DIR231)
    return "file://" + src, _hl231.sha256(_LIST_BYTES231).hexdigest(), pd, _os231.path.join(pd, "data", _bp231.LIST_NAME)


def _read_or231(path):
    """The file's bytes, or b"" when it is not there."""
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def _s231_installer():
    url, pin, pd, dest = _list_src231()
    first = _run_list231(pd, url, pin)
    got = _read_or231(dest)
    mtime = _os231.stat(dest).st_mtime_ns if got else None
    again = _run_list231(pd, "file:///nonexistent-p231", pin)
    kept = bool(got) and _os231.stat(dest).st_mtime_ns == mtime
    if got:
        _os231.unlink(dest)
    wrong = _run_list231(pd, url, "0" * 64)
    check("install.sh: ensure_password_list saves the pinned list into data/ and says so",
          got == _LIST_BYTES231 and "OK Breached-password list downloaded" in first and "RC=0" in first, first)
    check("install.sh: ...a host that has the pinned list downloads nothing and prints nothing",
          kept and again.strip() == "RC=0", again)
    check("install.sh: ...a download that does not hash to the pin is refused and not saved, the run goes on",
          not _os231.path.lexists(dest) and "did not match its pinned SHA-256" in wrong and "RC=0" in wrong, wrong)


def _s231_installer_failures():
    url, pin, pd, dest = _list_src231()
    down = _run_list231(pd, "file:///nonexistent-p231", pin)
    target = _os231.path.join(_DIR231, "not-the-list.txt")
    with open(target, "wb") as fh:
        fh.write(b"keep me\n")
    _os231.makedirs(_os231.path.dirname(dest), exist_ok=True)
    _os231.symlink(target, dest)
    linked = _run_list231(pd, url, pin)
    check("install.sh: ...a failed download warns and the run goes on",
          "Could not download the breached-password list" in down and "RC=0" in down, down)
    check("install.sh: ...a link planted at the list's name is replaced, not written through",
          _read_or231(target) == b"keep me\n" and not _os231.path.islink(dest)
          and _read_or231(dest) == _LIST_BYTES231 and "RC=0" in linked, linked)


def _s231_installer_calls():
    fresh = _inst[_inst.index('info "[2/4] Creating virtual environment'):_inst.index('info "[3/4] Registering the service')]
    full = _inst[_inst.index('info "[4/6] Installing dependencies'):_inst.index('info "[5/6] Starting the service')]
    noop = _inst[_inst.index("        install_gamedig\n        # The breached-password list"):
                 _inst.index("        update_noop_line\n        exit 0")]
    check("install.sh: the list is fetched on a fresh install, a full update and an up-to-date run",
          all("ensure_password_list" in part for part in (fresh, full, noop)), repr([len(fresh), len(full), len(noop)]))
    check("install.sh: ...and left out of the update snapshot of data/",
          "--exclude=./%s" % _bp231.LIST_NAME in _inst, _bp231.LIST_NAME)


try:
    for _fn231 in (_s231_request_shape, _s231_padding_and_failure, _s231_order, _s231_list_trust,
                   _s231_switch, _s231_suites_offline, _s231_account_route, _s231_setup_step,
                   _s231_installer, _s231_installer_failures, _s231_installer_calls):
        _p9_arm(who="part231")
        try:
            _fn231()
        finally:
            _p9_restore_all()
            _setting231(None)
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _uid231 in _IDS231:
            _u231 = _db231.session.get(_U231, _uid231)
            if _u231 is not None:
                _db231.session.delete(_u231)
        _db231.session.commit()

check("part231: nothing reached a real transport or Pwned Passwords", len(_P9_TRIPPED) == _trips231,
      repr(_P9_TRIPPED[_trips231:]))
