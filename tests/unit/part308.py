"""Part 308 of the unit suite: B3's country database, fetched as OWASP's SSRF Prevention Cheat Sheet asks.

1. The fetch (services/geoip._get and latest, through urllib's own opener): the connection goes only to a
   public address the host name resolved to, and only when every address it resolved to is public; no
   redirect is followed, even to db-ip.com; a month that has not begun is refused; the file kept is 0600.

HOW IT RUNS. The resolver and the connect are stand-ins on geoip's own `socket` name, and the opener it builds
gets no proxy (geoip's own `urllib` name), so nothing reaches db-ip.com or any address. (The code before the fix
used the process's own socket: its mutation proof ran in a network namespace with no network.)
"""
import email.message as _msg308
import gzip as _gzip308
import io as _io308
import os
import pathlib as _pl308
import shutil as _shutil308
import socket as _sock308
import stat as _stat308
import tempfile as _tf308
import urllib.error as _urlerr308
import urllib.request as _urlreq308

from unit.part01 import check, eq
from unit.part10 import _Over
from unit.part12 import _P9_TRIPPED, _p9_patch, _p9_restore_all
from panel.core import outside_services as _os308
from panel.services import geoip as _geo308

_trips308 = len(_P9_TRIPPED)
_TMP308 = _tf308.mkdtemp(prefix="p308-")
_MONTH308, _NEXT308 = "2026-11", "2026-12"
_DB308 = b"\x01" * 48 + _geo308.MMDB_MARKER + b"\xe1\x00metadata-308"
_GZ308 = _gzip308.compress(_DB308)
_SHA308 = _geo308.sha1_hex(_DB308)


def _page308(month, sha=_SHA308):
    """DB-IP's page as it is laid out (part258 has the full markup): the CSV's block, then the MMDB's."""
    return ('<dl><dt>SHA1SUM</dt><dd class="small">%s</dd></dl>'
            "<a href='https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz'>CSV</a> "
            '<dl><dt>MD5SUM</dt><dd class="small">%s</dd><dt>SHA1SUM</dt><dd class="small">%s</dd></dl>'
            "<a href='https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz'>MMDB</a>"
            % ("c" * 40, month, "a" * 32, sha, month))


def _file_url308(month):
    return "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz" % month


def _net308(addrs, built=None):
    """Stand-ins for the resolver (answers `addrs`) and the connect (recorded, then refused), on geoip's names only.

    The opener geoip builds is given an empty ProxyHandler (an https_proxy in the environment would otherwise
    carry the connection), and is appended to `built`.
    """
    seen = []
    real = _urlreq308.build_opener

    def build(*handlers):
        opener = real(*(handlers + (_urlreq308.ProxyHandler({}),)))
        if built is not None:
            built.append(opener)
        return opener

    def resolve(host, port, *a, **k):
        seen.append(("resolve", host))
        return [(_sock308.AF_INET6 if ":" in x else _sock308.AF_INET, _sock308.SOCK_STREAM, 6, "", (x, port))
                for x in addrs]

    def connect(address, *a, **k):
        seen.append(("connect", address[0]))
        raise OSError("part308: no network")
    _p9_patch(_geo308, "socket", _Over(_sock308, getaddrinfo=resolve, create_connection=connect))
    _p9_patch(_geo308, "urllib", _Over(_geo308.urllib, request=_Over(_urlreq308, build_opener=build)))
    return seen


def _connects308():
    """For each resolver answer: (what _get returned, the addresses it connected to)."""
    out = {}
    for label, addrs in (("loopback", ["127.0.0.1"]), ("private", ["10.1.2.3"]), ("link-local v6", ["fe80::1"]),
                         ("public and private", ["1.0.0.1", "192.168.1.9"]), ("public", ["1.0.0.1"]),
                         ("public v6", ["2606:4700:4700::1001"])):
        seen = _net308(addrs)
        got = _geo308._get(_geo308.PAGE, 1000)
        out[label] = (got[0], [s[1] for s in seen if s[0] == "connect"])
        _p9_restore_all()
    return out


def _redirects308():
    """What the opener _get builds does with a 302 to db-ip.com's own file host and to another host."""
    built, out = [], {}
    for where in ("https://download.db-ip.com/free/x.mmdb.gz", "https://evil.example/x"):
        _net308(["1.0.0.1"], built)
        _geo308._get(_geo308.PAGE, 1000)
        hdrs = _msg308.Message()
        hdrs["Location"] = where
        req = _urlreq308.Request(_geo308.PAGE)
        req.timeout = 5                       # as the opener's open() sets it
        try:
            built[-1].error("https", req, _io308.BytesIO(b""), 302, "Found", hdrs)
            out[where] = "followed"
        except _urlerr308.HTTPError as e:
            out[where] = "refused %d" % e.code
        except _urlerr308.URLError:
            out[where] = "followed"
        except Exception as e:  # noqa: BLE001 - named in the check's answer rather than ending the part
            out[where] = "raised %s" % e.__class__.__name__
        _p9_restore_all()
    return out


def _latest308(page, folder, before=None):
    """latest() with DB-IP's two URLs answered from `page` and the file -> (its answer, the URLs asked)."""
    asked = []

    def get(url, cap):
        asked.append(url)
        return {_geo308.PAGE: (page.encode(), None)}.get(url, (_GZ308, None) if url.startswith(
            "https://download.db-ip.com/") else (None, "unreachable"))
    _p9_patch(_geo308, "_get", get)
    _p9_patch(_geo308, "CACHE_DIR", _pl308.Path(_TMP308) / folder)
    _p9_patch(_geo308, "month_now", lambda: _MONTH308)
    _p9_patch(_os308, "enabled", lambda key: True)
    if before is not None:
        os.makedirs(_geo308.CACHE_DIR, exist_ok=True)
        with open(_geo308.CACHE_DIR / (_geo308.FILE_NAME + ".new"), "wb") as fh:
            fh.write(before)
        os.chmod(_geo308.CACHE_DIR / (_geo308.FILE_NAME + ".new"), 0o644)
    try:
        return _geo308.latest(), asked
    finally:
        _p9_restore_all()


def _fetch_checks308():
    eq("DB-IP fetch (_get through urllib's opener): it connects only to the address db-ip.com resolved to, and only "
       "when every address is public; loopback, private, link-local or a mix is never connected to "
       "(SSRF Prevention Cheat Sheet, Case 1: DNS rebinding)",
       _connects308(),
       {"loopback": (None, []), "private": (None, []), "link-local v6": (None, []), "public and private": (None, []),
        "public": (None, ["1.0.0.1"]), "public v6": (None, ["2606:4700:4700::1001"])})
    eq("DB-IP fetch: a redirect is not followed, not even to db-ip.com's own file host (SSRF Prevention Cheat Sheet, "
       "Case 1: disable redirects)", _redirects308(),
       {"https://download.db-ip.com/free/x.mmdb.gz": "refused 302", "https://evil.example/x": "refused 302"})
    got, asked = _latest308(_page308(_NEXT308), "future")
    eq("DB-IP: a page naming a month that has not begun is refused, and its file is never asked for",
       (got, asked), ((None, "", _geo308.UNREADABLE), [_geo308.PAGE]))
    got, asked = _latest308(_page308(_MONTH308), "mode", before=b"left by an older panel")
    mode = _stat308.S_IMODE(os.stat(got[0]).st_mode) if got[0] is not None else None
    eq("DB-IP: the month's file is kept 0600 (a .new left behind 0644 does not pass its mode on), and it is the "
       "checked database (File Upload Cheat Sheet: Filesystem Permissions)",
       (got[1:], oct(mode or 0), got[0] is not None and got[0].read_bytes() == _DB308, asked),
       ((_MONTH308, ""), "0o600", True, [_geo308.PAGE, _file_url308(_MONTH308)]))
    eq("DB-IP: this month's page and file still give this month's database (control)",
       _latest308(_page308(_MONTH308), "control")[0][1:], (_MONTH308, ""))


try:
    _fetch_checks308()
finally:
    _p9_restore_all()
check("part308: no check reached a real host", len(_P9_TRIPPED) == _trips308, repr(_P9_TRIPPED[_trips308:][:4]))
_shutil308.rmtree(_TMP308, ignore_errors=True)
