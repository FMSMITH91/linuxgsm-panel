"""Part 230 of the unit suite: a form the panel must refuse because it cannot tell its own address says how to fix it.

* Behind a proxy that rewrites Host to loopback, passes on no X-Forwarded-Host, with no site_domain:
  a browser that sends no Sec-Fetch-Site has its form refused (the Origin cannot be checked against
  the panel's address), and the journal is told once, with the two ways to give the panel its address.
* With X-Forwarded-Host, with site_domain set, or arriving on a real host name, there is no such line.
  The refusal itself is unchanged (403): the check stays.

HOW IT RUNS. Through the real route and the real Fetch Metadata guard on part12's Flask app.
"""
import logging as _logging230

from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9_client, _p9_patch, _p9_restore_all
from panel.routes import account_security as _as230
from panel.security import account_guard as _ag230

_trips230 = len(_P9_TRIPPED)
_URL230 = "/api/account/ui-order/reset"
_FOREIGN230 = {"Origin": "http://elsewhere.example", "X-Requested-With": "XMLHttpRequest"}


def _post230(base, extra=None):
    return _p9_client(P9_ADMIN).post(_URL230, headers=dict(_FOREIGN230, **(extra or {})), base_url=base)


def _warnings230(fn):
    seen = []
    h = _logging230.Handler()
    h.emit = lambda rec: seen.append(rec.getMessage())
    _ag230._log.addHandler(h)
    try:
        fn()
    finally:
        _ag230._log.removeHandler(h)
    return [m for m in seen if "cannot tell its own address" in m]


def _address230():
    _p9_patch(_as230, "load_config", lambda: {})
    _as230._WARNED_ADDRESS[0] = False
    codes = []
    lines = _warnings230(lambda: codes.extend(_post230("http://127.0.0.1:5000").status_code for _ in range(2)))
    eq("unknown address: behind a loopback-rewriting proxy, a foreign-looking form is still refused (403), and the "
       "journal is told once, naming set-site-domain and the Host header", (codes, len(lines),
       all("manage.py set-site-domain" in m and "Host header" in m for m in lines)), ([403, 403], 1, True))
    _as230._WARNED_ADDRESS[0] = False
    fwd = _warnings230(lambda: _post230("http://127.0.0.1:5000", {"X-Forwarded-Host": "panel.example.com"}))
    real = _warnings230(lambda: _post230("http://panel.example.com"))
    _p9_patch(_as230, "load_config", lambda: {"site_domain": "panel.example.com"})
    set_ = _warnings230(lambda: _post230("http://127.0.0.1:5000"))
    eq("unknown address: no such line when a proxy passes X-Forwarded-Host, the request names a real host, or "
       "site_domain is set", (fwd, real, set_), ([], [], []))


try:
    _address230()
finally:
    _as230._WARNED_ADDRESS[0] = False
    _p9_restore_all()
check("unknown address: nothing in this part reached a real transport (part12's tripwire)",
      len(_P9_TRIPPED) == _trips230)
