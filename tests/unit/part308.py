"""Part 308 of the unit suite: B3's country database, fetched as OWASP's SSRF Prevention Cheat Sheet asks, and
refreshed by itself every month.

1. The fetch (services/geoip._get and latest, through urllib's own opener): the connection goes only to a
   public address the host name resolved to, and only when every address it resolved to is public; no
   redirect is followed, even to db-ip.com; a month that has not begun is refused; the file kept is 0600.
2. The monthly refresh (routes/addons_geoip.tick, as the update-check thread calls it): one download a month
   for the whole panel, and only when an offline B3 needs it; a back-off between failed tries; each offline
   B3 gets the file and reloads it without a restart, holding the add-on's job slot; an older B3 (no reload)
   restarts only once its game reads 0 players; DB-IP turned off downloads nothing; the account check comes
   first; the card says what waits. Its shells run under bash; the card runs in node.

HOW IT RUNS. Section 2 drives part12's app: every host call is a recorder standing in for the game hosts.
The resolver and the connect are stand-ins on geoip's own `socket` name, and the opener it builds
gets no proxy (geoip's own `urllib` name), so nothing reaches db-ip.com or any address. (The code before the fix
used the process's own socket: its mutation proof ran in a network namespace with no network.)
"""
import base64 as _b64m308
import email.message as _msg308
import gzip as _gzip308
import io as _io308
import json as _json308
import os
import re as _re308
import subprocess as _sp308  # nosec B404 - bash and node over this part's own throwaway files
import pathlib as _pl308
import shutil as _shutil308
import socket as _sock308
import stat as _stat308
import tempfile as _tf308
import urllib.error as _urlerr308
import urllib.request as _urlreq308

from types import SimpleNamespace as _NS308

from unit.part01 import _root, check, eq
from unit.part10 import _Over
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part257 import _HARNESS257
from panel.core import i18n as _i18n308, outside_services as _os308
from panel.services import notifications as _notif308
from panel.routes import addons as _ra308, addons_geoip as _gr308
from panel.services import addons as _ad308, geoip as _geo308, monitoring as _mon308

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
    """Stand-ins for the resolver (answers `addrs`) and the connect (recorded, then refused): geoip's names, and the
    panel's checked connect (notifications._connect_infos) it hands the answers to.

    The opener geoip builds is appended to `built`, with the handlers geoip passed for it.
    """
    seen = []
    real = _urlreq308.build_opener

    def build(*handlers):
        opener = real(*handlers)
        if built is not None:
            built.append((opener, handlers))
        return opener

    def resolve(host, port, *a, **k):
        seen.append(("resolve", host))
        return [(_sock308.AF_INET6 if ":" in x else _sock308.AF_INET, _sock308.SOCK_STREAM, 6, "", (x, port))
                for x in addrs]

    def connect(infos, *a, **k):
        seen.append(("connect", infos[0][4][0]))
        raise OSError("part308: no network")
    _p9_patch(_geo308, "socket", _Over(_sock308, getaddrinfo=resolve))
    _p9_patch(_notif308, "_connect_infos", connect)
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
            built[-1][0].error("https", req, _io308.BytesIO(b""), 302, "Found", hdrs)
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


def _proxy308():
    """The proxies of the ProxyHandlers geoip passes to the opener it builds."""
    built = []
    _net308(["1.0.0.1"], built)
    _geo308._get(_geo308.PAGE, 1000)
    _p9_restore_all()
    return [h.proxies for h in (built[-1][1] if built else ()) if isinstance(h, _urlreq308.ProxyHandler)]


def _fetch_checks308():
    eq("DB-IP fetch: the opener is given an empty ProxyHandler (no proxy from the environment), so the address "
       "checked is the address connected to", _proxy308(), [{}])
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


# ── 2. the monthly refresh ──────────────────────────────────────────────────────────────────────
_PREV308 = "2026-10"
_OLD_DB308 = b"\x02" * 48 + _geo308.MMDB_MARKER + b"\xe1\x00metadata-prev"
_OLD308 = "920d736648e2544714ee58a74e556fbbb3881892"   # B3 v2.0.0+ as #587 pinned it: no plugin reload
_RELOADED308 = '{"reloaded": ["admin", "geolocation"], "failed": {}}'
_UNIT308 = _ad308.unit_name(_ad308.B3)
_PUT_RE308 = _re308.compile(r"printf %s (\S+) \| base64 -d > (\S+)\.new")
_USERS308 = ("b3a308", "b3b308", "b3c308", "b3d308", "b3e308")


def _meta308(**kw):
    return dict({"kind": "b3", "geolocation": "offline", "geoip": _PREV308, "commit": _ad308.B3_COMMIT,
                 "image": _ad308.CATALOG["b3"]["image"], "plugins": ["stats"]}, **kw)


class _Hosts308:
    """The game accounts as the refresh finds them: {user: {"meta", "active", "reload", "players"}}; calls recorded."""

    def __init__(self, accounts):
        self.acc = accounts
        self.calls = []
        self.during_push = None

    def _written(self, user, sh):
        for b64, path in _PUT_RE308.findall(sh):
            if path.endswith("/addon.json"):
                self.acc[user]["meta"] = _json308.loads(_ad308._unb64(b64))

    def _answer(self, user, sh):
        a = self.acc[user]
        if '"meta.b3=' in sh:
            meta = "" if a["meta"] is None else "meta.b3=%s\nstate.b3=%s\n" % (
                _ad308._b64(_json308.dumps(a["meta"])), "active" if a["active"] else "inactive")
            return "status", "os=24.04\npodman=podman version 4.9.3\n" + meta
        self._written(user, sh)
        if "dbip-country-lite.mmdb.new" in sh:
            told = ("GEOIP_RELOADED\nreload.b64=%s\n" % _ad308._b64(a["reload"]) if "GEOIP_RELOADED" in sh
                    else "GEOIP_RUNNING\n") if a["active"] else "GEOIP_IDLE\n"
            return "push", "GEOIP_PUT\nGEOIP_RECORDED\n" + told
        if "GEOIP_RESTARTED" in sh:
            return "restart", ("GEOIP_RESTARTED\n" if a["active"] else "GEOIP_IDLE\n") + "GEOIP_RECORDED\n"
        return "record", "GEOIP_RECORDED\n"

    def shell(self, server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        if user not in self.acc:
            self.calls.append((user, "other", sh, stdin_text))
            return "", "", 1
        kind, out = self._answer(user, sh)
        self.calls.append((user, kind, sh, stdin_text))
        if kind == "push" and self.during_push is not None:
            self.during_push(user)
        return out, "", 0

    def kinds(self, user):
        return [c[1] for c in self.calls if c[0] == user]

    def of(self, user, kind):
        return [c for c in self.calls if c[0] == user and c[1] == kind]


def _scene308(accounts, pages=None, switch=True, clock=None):
    """Stand-ins for one scene -> (hosts, the URLs asked of DB-IP). The panel keeps last month's file."""
    _p9_restore_all()
    _p9_arm(who="part308")
    hosts = _Hosts308(accounts)
    asked = []
    pages = {_geo308.PAGE: _page308(_MONTH308)} if pages is None else pages

    def get(url, cap):
        asked.append(url)
        if url in pages:
            return (pages[url].encode(), None) if pages[url] is not None else (None, "unreachable")
        return (_GZ308, None) if url == _file_url308(_MONTH308) else (None, "unreachable")
    _p9_patch_sm("shell_as_game_user", hosts.shell)
    _p9_patch(_gr308, "game_account_write_refusal", lambda remote, user, now=None, reading=False: None)
    _p9_patch(_ra308, "game_account_write_refusal", lambda remote, user, now=None, reading=False: None)
    _p9_patch(_geo308, "_get", get)
    _p9_patch(_geo308, "CACHE_DIR", _pl308.Path(_TMP308) / ("cache-%d" % len(os.listdir(_TMP308))))
    _p9_patch(_geo308, "month_now", lambda: _MONTH308)
    switch = switch if isinstance(switch, list) else [switch]
    _p9_patch(_os308, "enabled", lambda key: switch[0] if key == _os308.DBIP else True)
    _p9_patch(_mon308, "_server_slots", lambda gs, *a, **k: ((accounts.get(gs.short_name) or {}).get("players"),
                                                              None, None))
    clock = [1_800_000_000.0] if clock is None else clock
    _p9_patch(_gr308, "time", _NS308(time=lambda: clock[0]))
    _geo308._keep(_OLD_DB308, _PREV308, _geo308.sha1_hex(_OLD_DB308))
    _gr308._DONE.clear()
    return hosts, asked


def _tick308(times=1):
    for _ in range(times):
        _gr308.tick(_p9)


def _row308(sid):
    """B3's row on the add-ons tab (GET /api/server/<id>/addons, as the card loads it)."""
    rows = (_p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid).get_json() or {}).get("addons") or []
    return next((r for r in rows if r.get("id") == "b3"), {})


def _pushed308(hosts, users):
    """Per user: (pushes, the first one's stdin is the new database, it asks B3 to reload, restarts)."""
    b64 = _b64m308.b64encode(_DB308).decode()
    out = []
    for u in users:
        pushes = hosts.of(u, "push")
        sh = pushes[0][2] if pushes else ""
        out.append((len(pushes), bool(pushes) and pushes[0][3] == b64,
                    "podman kill --signal HUP" in sh and "reload_plugins" in sh, len(hosts.of(u, "restart"))))
    return out


def _roll308(ids):
    """Two offline B3s, last month's file on the panel: this month's is downloaded once and reaches both."""
    acc = {u: {"meta": _meta308(), "active": True, "reload": _RELOADED308, "players": 4} for u in ("b3a308", "b3b308")}
    hosts, asked = _scene308(acc)
    before = _p9_audit_count("addon_geoip")
    busy = []
    hosts.during_push = lambda user: busy.append(
        _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/start" % ids[user]).get_json() or {})
    _tick308()
    first = sum(len(hosts.kinds(u)) for u in ("b3a308", "b3b308"))
    _tick308(2)
    eq("refresh: this month's file is downloaded ONCE for the panel (three ticks, two servers: the page and the file, "
       "asked once each), and each offline B3 gets it on stdin and reloads it (SIGHUP or the control socket), with "
       "no restart, while players are on",
       (asked, _pushed308(hosts, ("b3a308", "b3b308"))),
       ([_geo308.PAGE, _file_url308(_MONTH308)], [(1, True, True, 0), (1, True, True, 0)]))
    eq("refresh: each record now names this month, with no restart waiting; the panel keeps the new file; the next "
       "ticks ask the hosts nothing more",
       ([(acc[u]["meta"].get("geoip"), _gr308.RESTART_KEY in acc[u]["meta"]) for u in ("b3a308", "b3b308")],
        _geo308._cached()[1], sum(len(hosts.kinds(u)) for u in ("b3a308", "b3b308")) - first),
       ([(_MONTH308, False), (_MONTH308, False)], _MONTH308, 0))
    eq("refresh: each push is audited on its server (addon_geoip) with the month and what B3 did",
       (_p9_audit_count("addon_geoip") - before, _p9_audit("addon_geoip").success, _p9_audit("addon_geoip").detail),
       (2, True, "b3 country database %s: B3 reloaded it" % _MONTH308))
    eq("refresh: it holds the add-on's job slot while it writes, so a Start then is refused with its own reason "
       "(409), and the slot is free afterwards",
       ([b.get("message") for b in busy], (_ra308._JOBS.get((ids["b3a308"], "b3")) or {}).get("running")),
       ([_i18n308.tr(_ra308._BUSY_GEOIP)] * 2, None))


def _backoff308(ids):
    """DB-IP unreachable, then not yet published: the waits between asks, kept in data/geoip."""
    clock = [1_800_000_000.0]
    acc = {"b3c308": {"meta": _meta308(), "active": True, "reload": _RELOADED308, "players": 0}}
    pages = {_geo308.PAGE: None}
    hosts, asked = _scene308(acc, pages=pages, clock=clock)
    counts = []
    for step in (0, 10, 3591, 7199, 2, 14399, 2):
        clock[0] += step
        _tick308()
        counts.append(len(asked))
    note = _gr308.card_note(acc["b3c308"]["meta"])
    st = _gr308.state()
    eq("refresh: after a failed download the panel waits an hour, then two, then four (no ask before), and keeps "
       "the wait in data/geoip/refresh.json; the B3 keeps last month's file",
       (counts, st["fails"], st["why"], acc["b3c308"]["meta"]["geoip"], hosts.of("b3c308", "push")),
       ([1, 1, 2, 2, 3, 3, 4], 4, _geo308.UNREACHABLE, _PREV308, []))
    eq("card: while the download fails, the offline B3's card says so and that B3 keeps the file it has",
       note, _i18n308.tr(_gr308.S_FAILED, why=_i18n308.tr(_geo308.UNREACHABLE)))
    pages[_geo308.PAGE] = _page308(_PREV308)
    n = []
    for step in (8 * 3600, 1, 6 * 3600 - 2, 2):
        clock[0] += step
        _tick308()
        n.append(len(asked))
    pages[_geo308.PAGE] = _page308(_MONTH308)
    clock[0] += 6 * 3600 + 1
    _tick308()
    eq("refresh: a page still showing last month is asked again only after six hours; once this month's is out, the "
       "file is downloaded and pushed",
       (n, asked[-2:], acc["b3c308"]["meta"]["geoip"], _gr308.state()["fails"]),
       ([5, 5, 5, 6], [_geo308.PAGE, _file_url308(_MONTH308)], _MONTH308, 0))


def _off308(ids):
    """DB-IP turned off in Outside services: nothing is downloaded, B3 keeps its file, the card says so."""
    acc = {"b3c308": {"meta": _meta308(), "active": True, "reload": _RELOADED308, "players": 0}}
    switch = [False]
    hosts, asked = _scene308(acc, switch=switch)
    _tick308(2)
    row = _row308(ids["b3c308"])
    eq("refresh, DB-IP off: nothing is asked of db-ip.com and nothing is pushed; the card shows the month B3 has, "
       "that the download is off, and that B3 keeps its database",
       (asked, hosts.of("b3c308", "push"), row.get("geoip"), row.get("geoip_off"), row.get("geoip_note")),
       ([], [], _PREV308, _i18n308.tr(_geo308.OFF), _i18n308.tr(_gr308.S_KEPT_OFF)))
    switch[0] = True
    _tick308()
    eq("refresh: turned back on, the download is tried at once (the time it was off counted as no failure)",
       (asked, _gr308.state()["fails"], acc["b3c308"]["meta"]["geoip"]),
       ([_geo308.PAGE, _file_url308(_MONTH308)], 0, _MONTH308))


def _old308(ids):
    """A B3 with no plugin reload: the file goes in, and it restarts only once the game reads 0 players."""
    acc = {"b3d308": {"meta": _meta308(commit=_OLD308), "active": True, "reload": "", "players": 3}}
    hosts, _asked = _scene308(acc)
    _tick308()
    push = hosts.of("b3d308", "push")
    waiting = dict(acc["b3d308"]["meta"])
    row = _row308(ids["b3d308"])
    acc["b3d308"]["players"] = None
    _tick308()
    unread = len(hosts.of("b3d308", "restart"))
    acc["b3d308"]["players"] = 0
    _tick308()
    restart = hosts.of("b3d308", "restart")
    _tick308()
    eq("refresh, a B3 with no reload (SIGHUP would end it): the file and the record go in, B3 is not signalled, "
       "and the record says a restart waits",
       (len(push), any("podman kill" in c[2] or "reload_plugins" in c[2] for c in push), waiting.get("geoip"),
        waiting.get(_gr308.RESTART_KEY)), (1, False, _MONTH308, _MONTH308))
    eq("card: the waiting restart is said on the B3's card", row.get("geoip_note"),
       _i18n308.tr(_gr308.S_WAITING, month=_MONTH308))
    eq("refresh: no restart while players are on or the count can't be read; at 0 players B3 restarts (its start "
       "limit cleared first) and the record drops the wait; then nothing more",
       (hosts.kinds("b3d308").count("restart"), unread, len(restart),
        bool(restart) and "systemctl --user reset-failed %s.service" % _UNIT308 in restart[0][2]
        and "systemctl --user restart %s.service" % _UNIT308 in restart[0][2],
        _gr308.RESTART_KEY in acc["b3d308"]["meta"], acc["b3d308"]["meta"].get("geoip"),
        _p9_audit("addon_geoip").detail),
       (1, 0, 1, True, False, _MONTH308, "b3 country database %s: B3 restarted with it, the server empty" % _MONTH308))


def _silent308(ids):
    """A B3 that doesn't answer the reload is restarted instead, at once when the game is empty."""
    acc = {"b3e308": {"meta": _meta308(), "active": True, "reload": "", "players": 0}}
    hosts, _asked = _scene308(acc)
    _tick308()
    # Each B3 is read twice in the pass that downloads: with the panel's old file, then under the new one.
    eq("refresh: a reload with no answer becomes a restart (the game empty, in the same pass), and the record is clean",
       (hosts.kinds("b3e308"), _gr308.RESTART_KEY in acc["b3e308"]["meta"], acc["b3e308"]["meta"]["geoip"]),
       (["status", "status", "push", "restart"], False, _MONTH308))


def _idle308(ids):
    """A B3 that isn't running gets the file, and no reload or restart: its next start reads it."""
    acc = {"b3e308": {"meta": _meta308(), "active": False, "reload": "", "players": 2}}
    hosts, _asked = _scene308(acc)
    _tick308()
    eq("refresh: a stopped B3 gets the file and a clean record, with no reload or restart",
       (hosts.kinds("b3e308"), _gr308.RESTART_KEY in acc["b3e308"]["meta"], _p9_audit("addon_geoip").detail),
       (["status", "status", "push", "record"], False,
        "b3 country database %s: B3 isn't running: it reads it at its next start" % _MONTH308))


def _none308(ids):
    """No offline B3 anywhere (online, or no B3): nothing is downloaded and nothing written."""
    acc = {"b3a308": {"meta": _meta308(geolocation="online"), "active": True, "reload": "", "players": 0},
           "b3b308": {"meta": None, "active": False, "reload": "", "players": 0}}
    hosts, asked = _scene308(acc)
    _tick308(2)
    eq("refresh: with no B3 set to offline, nothing is asked of db-ip.com and each account is read once (then not "
       "again this month)", (asked, hosts.kinds("b3a308"), hosts.kinds("b3b308")), ([], ["status"], ["status"]))


def _guards308(ids):
    """The account check and the job slot: a refused account is not touched; a running job is waited for."""
    acc = {"b3a308": {"meta": _meta308(), "active": True, "reload": _RELOADED308, "players": 0},
           "b3b308": {"meta": _meta308(), "active": True, "reload": _RELOADED308, "players": 0}}
    hosts, _asked = _scene308(acc)
    _p9_patch(_gr308, "game_account_write_refusal",
              lambda remote, user, now=None, reading=False: "refused" if user == "b3a308" else None)
    running = {"running": True, "why": "", "tail": "", "kind": "settings"}
    key = (ids["b3b308"], "b3")
    with _ra308._JOBS_LOCK:
        _ra308._JOBS[key] = dict(running)
    try:
        _tick308()
        held = dict(_ra308._JOBS.get(key) or {})
    finally:
        with _ra308._JOBS_LOCK:
            _ra308._JOBS[key] = {"running": False, "why": "B3 refused the new settings.", "tail": "", "kind": "settings"}
    eq("refresh: an account the host can't confirm is a plain game account is not read or written "
       "(game_account_write_refusal); a B3 with an Apply running is left to it",
       (hosts.kinds("b3a308"), hosts.kinds("b3b308"), held), ([], [], running))
    _tick308()
    eq("refresh: once the Apply has ended, the B3 gets the file, and the card keeps that Apply's own outcome",
       (hosts.kinds("b3b308"), (_ra308._JOBS.get(key) or {}).get("why")),
       (["status", "status", "push", "record"], "B3 refused the new settings."))
    with _ra308._JOBS_LOCK:
        _ra308._JOBS.pop(key, None)


def _bash308(sh, home, active, stdin=None):
    """Run a refresh shell under bash, /home/b3s308 at `home`, a systemctl that says `active` -> (stdout, its calls)."""
    bindir = os.path.join(home, "bin")
    os.makedirs(bindir, exist_ok=True)
    log = os.path.join(home, "systemctl.log")
    if os.path.exists(log):
        os.remove(log)
    with open(os.path.join(bindir, "systemctl"), "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\necho "$*" >> %s\ncase "$*" in *is-active*) exit %d;; esac\nexit 0\n'
                 % (log, 0 if active else 3))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(os.path.join(bindir, "systemctl"), 0o700)  # nosec B103 - a stand-in tool in the part's own temp dir
    r = _sp308.run(["bash", "-c", sh.replace("/home/b3s308", home)], input=stdin,  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, check=False, env={"PATH": bindir + ":/usr/bin:/bin"})
    if not os.path.exists(log):
        return r.stdout, []
    with open(log, encoding="utf-8") as fh:
        return r.stdout, [c for c in fh.read().splitlines() if not c.startswith("--user is-active")]


def _marks308(out, marks=("GEOIP_PUT", "GEOIP_RECORDED", "GEOIP_RESTARTED", "GEOIP_IDLE", "GEOIP_RUNNING")):
    return [m for m in marks if m in out]


def _shells308():
    home = os.path.join(_TMP308, "bash-home")
    rec = _meta308(geoip=_MONTH308, **{_gr308.RESTART_KEY: _MONTH308})
    f = os.path.join(home, "panel-addons", "b3", "geoip", "dbip-country-lite.mmdb")
    meta = os.path.join(home, "panel-addons", "b3", "addon.json")
    feed = _b64m308.b64encode(_DB308).decode()
    out, _calls = _bash308(_gr308.push_sh("b3s308", rec, False), home, False, feed)
    with open(f, "rb") as fh:
        landed = fh.read() == _DB308
    with open(meta, encoding="utf-8") as fh:
        written = _json308.loads(fh.read())
    eq("push shell (bash): the database from stdin lands in the add-on's geoip folder, 0600, the record beside it; a "
       "stopped B3 is said to be idle",
       (landed, oct(_stat308.S_IMODE(os.stat(f).st_mode)), written == rec, _marks308(out)),
       (True, "0o600", True, ["GEOIP_PUT", "GEOIP_RECORDED", "GEOIP_IDLE"]))
    out, calls = _bash308(_gr308.push_sh("b3s308", rec, False), home, True, feed)
    eq("push shell (bash): a running B3 with no reload asked is said to be running, and is not restarted",
       (_marks308(out), calls), (["GEOIP_PUT", "GEOIP_RECORDED", "GEOIP_RUNNING"], []))
    clean = _meta308(geoip=_MONTH308)
    out, calls = _bash308(_gr308.restart_sh("b3s308", clean), home, True)
    with open(meta, encoding="utf-8") as fh:
        written = _json308.loads(fh.read())
    eq("restart shell (bash): a running B3's start limit is cleared, it is restarted, and the record drops the wait",
       (_marks308(out), calls, written),
       (["GEOIP_RECORDED", "GEOIP_RESTARTED"],
        ["--user reset-failed %s.service" % _UNIT308, "--user restart %s.service" % _UNIT308], clean))
    out, calls = _bash308(_gr308.restart_sh("b3s308", clean), home, False)
    eq("restart shell (bash): a stopped B3 is not started", (_marks308(out), calls), (["GEOIP_RECORDED", "GEOIP_IDLE"], []))


def _card308(job):
    node = _shutil308.which("node")
    if not node:
        return {"error": "node is not installed"}
    path = os.path.join(_TMP308, "harness.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_HARNESS257)
    row = {"id": "b3", "name": "B3", "version": "x", "installed": True, "state": "active", "legacy": True,
           "needs_database": True, "data_kept": True, "database": "gs7_b3", "geolocation_option": True,
           "geolocation": "offline", "geoip": _MONTH308, "credit": _geo308.CREDIT, "plugins": ["stats"],
           "geoip_note": "NOTE-308", "switchable": list(_ad308.B3_SWITCHABLE),
           "geo_switchable": list(_ad308.B3_GEO_SWITCHABLE), "update": "", "note": "",
           "installing": bool(job), "job": job}
    cfg = {"src": os.path.join(_root, "panel", "static", "js", "server_addons.js"),
           "data": {"success": True, "addons": [row], "databases": []}}
    r = _sp308.run([node, path], input=_json308.dumps(cfg), capture_output=True, text=True,  # nosec B603
                   timeout=120, check=False)
    try:
        return _json308.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _cards308():
    busy, idle = _card308("geoip"), _card308("")
    eq("card: the refresh's note and the database month are shown; while the refresh holds the add-on, its badge "
       "says so and no settings or buttons are offered (control: they are, once it ends)",
       ("NOTE-308" in busy.get("text", ""), "Country database:" in busy.get("text", ""),
        "Getting this month's country database…" in busy.get("text", ""), busy.get("fold"), idle.get("fold"),
        "NOTE-308" in idle.get("text", "")), (True, True, True, False, True, True))


def _wiring308():
    with open(os.path.join(_root, "panel", "routes", "os_updates.py"), encoding="utf-8") as fh:
        src = fh.read()
    loop = src[src.find("def update_check_ticker"):src.find('supervise("update-check"')]
    check("refresh: the update-check thread's 30-minute pass calls it, outside the panel-update check's own try",
          "\n            _addons_geoip.tick(app)" in loop and "time.sleep(1800)" in loop, loop[-600:])


def _refresh_checks308():
    _shells308()
    _cards308()
    _wiring308()
    ids = {u: _p9_new_server(P9_HOST, u, "cod2", 28970 + i, name="p308-" + u) for i, u in enumerate(_USERS308)}
    try:
        for step in (_roll308, _backoff308, _off308, _old308, _silent308, _idle308, _none308, _guards308):
            step(ids)
            _p9_restore_all()
    finally:
        _p9_restore_all()
        for sid in ids.values():
            _p9_delete_server(sid)


try:
    _fetch_checks308()
    _p9_restore_all()
    _refresh_checks308()
finally:
    _p9_restore_all()
check("part308: no check reached a real host", len(_P9_TRIPPED) == _trips308, repr(_P9_TRIPPED[_trips308:][:4]))
_shutil308.rmtree(_TMP308, ignore_errors=True)
