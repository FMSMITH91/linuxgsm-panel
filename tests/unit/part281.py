"""Part 281 of the unit suite: review pass 35's security fixes.

1. A game backup's download and delete, and a database dump's download, ask the root-capable-account
   refusal before anything runs as the game account (an archive holds that account's ~/.ssh).
2. The add-on page proxy: a request a panel page sent (Fetch Metadata same-origin, other than a top-level
   navigation) is refused, so an add-on's file can't be loaded as a panel page's script or stylesheet; a
   refused link's audit row carries the client address; a link is made only for a per-device sign-in and
   lives only while its session row does (an API token or an older cookie gets none); an answer is readable
   by the sandboxed page's own (opaque) origin only; 'unsafe-eval' is on BlueMap's page alone, sandbox kept.
3. The page policy: scripts by nonce with 'strict-dynamic' and styles by nonce, no 'self' (no other file on
   the origin passes), and every stylesheet <link> carries the nonce.
4. Discord: server and host names and alert text are shown as written in both senders (markdown escaped,
   code kept), and mentions stay off.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the host reads, the backup and dump
streams, the add-on tunnel and Discord's HTTP post are stand-ins. Nothing reaches a host, /etc or data/.
"""
import ast as _ast281
import json as _json281
import os
import re as _re281

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server, _p9_new_server,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part279 import (_drop_member279, _member279, _open_answer279, _routes_setup279, _session_client279,
                          _set_perms279)
from panel.core import i18n as _i18n281
from panel.db import models as _m281
from panel.routes import addon_web as _rw281, databases_files as _df281, panel_backup as _pb281
from panel.security import auth as _auth281
from panel.services import addon_web as _aw281, addons as _ad281, notifications as _n281
from panel.services.bots import commands as _cmd281, discord as _dcm281

_ROOT281 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_WHY281 = "p281: that account can become root"
_SEALED281 = "p281-sealed"
_ARCHIVE281 = "p281bk-2026-11-20-010203.tar.zst"


# ── 1. backups and dumps ──────────────────────────────────────────────────────────────────────────
def _backup_stubs281(calls, verdict):
    def refusal(remote, user, now=None, reading=False):
        calls.append(("ask", user, reading))
        return verdict[0]
    _p9_patch(_pb281, "game_account_write_refusal", refusal)
    _p9_patch(_pb281, "list_game_backups",
              lambda remote, user, locks=None: calls.append(("list",)) or [{"name": _ARCHIVE281, "size": 3}])
    _p9_patch(_pb281, "stream_game_backup",
              lambda remote, user, name, chunk=262144: calls.append(("cat", name)) or iter([b"abc"]))
    _p9_patch(_pb281, "delete_game_backup", lambda remote, user, name: calls.append(("rm", name)) or True)


def _backup_round281(client, sid, calls):
    dl = client.get("/backup/game/%d/download?name=%s" % (sid, _ARCHIVE281))
    got = (dl.status_code, dl.mimetype, dl.get_data(as_text=True), list(calls), _p9_audit("game_backup_download"))
    calls.clear()
    rm = client.post("/api/panel/backup/game/%d/delete" % sid, json={"name": _ARCHIVE281})
    gone = (rm.status_code, (rm.get_json(silent=True) or {}).get("message"), list(calls), _p9_audit("game_backup_delete"))
    calls.clear()
    return got, gone


def _backups281():
    calls, verdict = [], [_WHY281]
    _p9_arm(who="part281")
    sid = _p9_new_server(P9_HOST, "p281bk", "csgo", 27115, name="p281-bk")
    try:
        _backup_stubs281(calls, verdict)
        client = _p9_client(P9_ADMIN)
        refused = _backup_round281(client, sid, calls)
        verdict[0] = None
        allowed = _backup_round281(client, sid, calls)
        return refused, allowed
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)


_bk281 = _backups281()
_bkd281, _bkr281 = _bk281[0]
check("backup download: a root-capable game account is refused (409, plain text: the link's answer) before the "
      "listing or the read runs as it, and it is asked as a READ",
      (_bkd281[0], _bkd281[1], _bkd281[2].strip(), _bkd281[3]) == (409, "text/plain", _WHY281, [("ask", "p281bk", True)]),
      repr(_bkd281[:4]))
check("backup download: ...the refusal is audited as a failed download with the archive's name and the reason",
      _bkd281[4].success is False and _ARCHIVE281 in _bkd281[4].detail and _WHY281 in _bkd281[4].detail,
      repr(_bkd281[4]))
check("backup delete: a root-capable game account is refused (409) before anything runs as it, asked as a WRITE, "
      "and audited", (_bkr281[0], _bkr281[1], _bkr281[2]) == (409, _WHY281, [("ask", "p281bk", False)])
      and _bkr281[3].success is False and _WHY281 in _bkr281[3].detail, repr(_bkr281))
eq("backup: a plain game account still downloads (the archive's bytes) and deletes",
   ((_bk281[1][0][0], _bk281[1][0][2]), [c[0] for c in _bk281[1][0][3]], _bk281[1][1][0],
    [c[0] for c in _bk281[1][1][2]]),
   ((200, "abc"), ["ask", "list", "cat"], 200, ["ask", "list", "rm"]))


def _dump281():
    calls, verdict = [], [_WHY281]
    _p9_arm(who="part281")
    sid = _p9_new_server(P9_HOST, "p281db", "mc", 25581, name="p281-db")
    with _p9.app_context():
        row = _m281.GameDatabase(remote_id=P9_HOST, game_server_id=sid, name="p281db", secret=_SEALED281)
        _m281.db.session.add(row)
        _m281.db.session.commit()
        dbid = row.id
    try:
        def refusal(remote, user, now=None, reading=False):
            calls.append(("ask", reading))
            return verdict[0]
        _p9_patch(_df281, "game_account_write_refusal", refusal)
        _p9_patch_sm("stat_path", lambda server, user, rel: calls.append(("stat",)) or
                     {"type": "f", "size": 3, "name": "p281db.sql.gz", "rel": rel})
        _p9_patch_sm("stream_path", lambda server, user, rel, as_tar=False, limit=None, chunk=262144:
                     calls.append(("cat",)) or iter([b"abc"]))
        url = "/api/server/%d/databases/%d/dump/download" % (sid, dbid)
        client = _p9_client(P9_ADMIN)
        r = client.get(url)
        out = [(r.status_code, (r.get_json(silent=True) or {}).get("message"), list(calls),
                _p9_audit("db_dump_download"))]
        calls.clear()
        verdict[0] = None
        r = client.get(url)
        out.append((r.status_code, r.get_data(), list(calls)))
        return out
    finally:
        _p9_restore_all()
        with _p9.app_context():
            _m281.GameDatabase.query.filter_by(id=dbid).delete()
            _m281.db.session.commit()
        _p9_delete_server(sid)


_dp281 = _dump281()
check("dump download: a root-capable game account is refused (409) before the stat or the read runs as it, asked "
      "as a READ, and audited", (_dp281[0][0], _dp281[0][1], _dp281[0][2]) == (409, _WHY281, [("ask", True)])
      and _dp281[0][3].success is False and _WHY281 in _dp281[0][3].detail, repr(_dp281[0]))
eq("dump download: a plain game account still gets the dump's bytes", _dp281[1], (200, b"abc", [("ask", True), ("stat",),
                                                                                              ("cat",)]))


# ── 2. the add-on page proxy ──────────────────────────────────────────────────────────────────────
_FROM_PAGE281 = {"script": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"},
                 "style": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "style"},
                 "module": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "script"},
                 "frame": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}}
_LET_THROUGH281 = {"open": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
                   "own page": {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"},
                   "reload": {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
                   "old browser": {}}


def _fetch_meta281(ctx, res):
    fresh, loc, opened = ctx["fresh"], ctx["loc"], ctx["opened"]
    n0 = len(opened)
    res["refused"] = {k: fresh.get(loc + "x.js", headers=h).status_code for k, h in _FROM_PAGE281.items()}
    res["refused_dialled"] = len(opened) - n0
    res["through"] = {k: fresh.get(loc + "x.js", headers=h).status_code for k, h in _LET_THROUGH281.items()}
    own = fresh.get(loc + "x.js", headers=_LET_THROUGH281["own page"])
    res["cors"] = (own.headers.get("Access-Control-Allow-Origin"), own.headers.get("Cross-Origin-Resource-Policy"))
    res["csp"] = {"bluemap": own.headers.get("Content-Security-Policy", ""),
                  "refusal": fresh.get("/addon-web/" + "C" * 43 + "/").headers.get("Content-Security-Policy", "")}


def _iw4_csp281(ctx, res):
    """The same proxy answering an IW4MAdmin link (made for the same sign-in): its own policy."""
    with _p9.app_context():
        u = _m281.db.session.get(_m281.User, ctx["member"][0])
        row = _m281.UserSession.query.filter_by(user_id=u.id).first()
        key = "%d:%d:%s" % (u.id, u.auth_epoch or 0, row.sid)
    tok = _aw281.mint(key, u.id, (ctx["sid"], P9_HOST, _ad281.IW4MADMIN, ctx["port"]), "en", 1800.0, 28800.0)
    r = ctx["fresh"].get("/addon-web/%s/" % tok)
    res["csp"]["iw4madmin"] = (r.status_code, r.headers.get("Content-Security-Policy", ""))


def _audit_ip281(ctx, res):
    _set_perms279(ctx["member"][1], [_auth281.VIEW_SERVERS])
    r = ctx["fresh"].get(ctx["loc"], environ_base={"REMOTE_ADDR": "198.51.100.28"})
    with _p9.app_context():
        row = _m281.AuditLog.query.filter_by(action="addon_web_refused").order_by(_m281.AuditLog.id.desc()).first()
        res["ip"] = (r.status_code, getattr(row, "ip_address", None), getattr(row, "detail", ""))
    _set_perms279(ctx["member"][1], [_auth281.VIEW_SERVERS, _auth281.VIEW_ADDON_PAGES])


def _bearer281(ctx, res):
    with _p9.app_context():
        u = _m281.db.session.get(_m281.User, ctx["member"][0])
        token = u.generate_api_token()
        epoch = u.auth_epoch or 0
        _m281.db.session.commit()
    reads0 = len(ctx["reads"])
    r = _p9.test_client().post("/api/server/%d/addons/%s/web" % (ctx["sid"], _ad281.BLUEMAP),
                               headers={"Authorization": "Bearer " + token})
    res["bearer"] = (r.status_code, r.headers.get("Location"), "only from a browser signed in" in r.get_data(as_text=True),
                     len(ctx["reads"]) - reads0, _p9_audit("addon_web_refused").detail)
    # A link bound to a login id with no session (what a Bearer user's or an older cookie's id is).
    bare = _aw281.mint("%d:%d" % (ctx["member"][0], epoch), ctx["member"][0],
                       (ctx["sid"], P9_HOST, _ad281.BLUEMAP, ctx["port"]), "en", 1800.0, 28800.0)
    n0 = len(ctx["opened"])
    res["bare"] = (ctx["fresh"].get("/addon-web/%s/" % bare).status_code, len(ctx["opened"]) - n0)


def _proxy281():
    res = {}
    ctx = {"opened": [], "reads": [], "answers": []}
    _p9_arm(who="part281")
    _routes_setup279(ctx["answers"], ctx["opened"], ctx["reads"])
    ctx["sid"] = _p9_new_server(P9_HOST, "mcp281", "mc", 25566, name="p281-mc")
    ctx["member"] = _member279([_auth281.VIEW_SERVERS, _auth281.VIEW_ADDON_PAGES])
    ctx["port"] = _ad281.PORT_BASE + ctx["sid"]
    try:
        ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
        r = _session_client279(ctx["member"][0]).post("/api/server/%d/addons/%s/web" % (ctx["sid"], _ad281.BLUEMAP))
        ctx["loc"], ctx["fresh"] = r.headers.get("Location", ""), _p9.test_client()
        res["open"] = (r.status_code, ctx["loc"].startswith("/addon-web/"))
        for step in (_fetch_meta281, _iw4_csp281, _audit_ip281, _bearer281):
            try:
                step(ctx, res)
            except Exception as e:       # a step that raised fails its checks by name (below), not the suite
                res.setdefault("raised", []).append("%s: %r" % (step.__name__, e))
    finally:
        _p9_restore_all()
        _aw281._LINKS.clear()
        _drop_member279(*ctx["member"])
        _p9_delete_server(ctx["sid"])
    return res


_px281 = _proxy281()
eq("proxy: no step of the proxy's checks raised, and Open made a link from a per-device sign-in",
   (_px281.get("raised", []), _px281.get("open")), ([], (303, True)))
eq("proxy: a panel page's request for a link's file as a script, a stylesheet, a module or a frame "
   "(Sec-Fetch-Site same-origin, not a top-level navigation) is refused, and nothing is dialled",
   (_px281.get("refused"), _px281.get("refused_dialled")), ({k: 403 for k in _FROM_PAGE281}, 0))
eq("proxy: Open's own navigation, the sandboxed page's requests (cross-site), a reload and a browser that sends "
   "no Fetch Metadata still get the add-on's answer", _px281.get("through"), {k: 200 for k in _LET_THROUGH281})
eq("proxy: an answer lets only the sandboxed page's own origin read it (Access-Control-Allow-Origin null, not *) "
   "and sends no Cross-Origin-Resource-Policy (same-site or same-origin would refuse the page's own loads)",
   _px281.get("cors"), ("null", None))
_pc281 = _px281.get("csp", {})
_sandboxed281 = [(v if isinstance(v, str) else v[1]) for v in _pc281.values()]
check("proxy: every answer (BlueMap's, IW4MAdmin's, a refusal) keeps the sandbox WITHOUT allow-same-origin (the "
      "opaque origin that keeps an add-on's script away from the panel)",
      len(_sandboxed281) == 3 and all(c.startswith("sandbox allow-scripts allow-forms;") and "allow-same-origin" not in c
                                      for c in _sandboxed281), repr(_pc281)[:600])
eq("proxy: 'unsafe-eval' only on the page of an add-on that needs it: BlueMap's (its web app compiles strings), not "
   "IW4MAdmin's, not the proxy's own refusal",
   ["'unsafe-eval'" in _pc281.get("bluemap", ""), _pc281.get("iw4madmin", (0, ""))[0],
    "'unsafe-eval'" in _pc281.get("iw4madmin", (0, ""))[1], "'unsafe-eval'" in _pc281.get("refusal", "x'unsafe-eval'")],
   [True, 200, False, False])
_ip281 = _px281.get("ip", (0, None, ""))
eq("proxy: a refused link's audit row records the address it was used from (403, the client's address)",
   _ip281[:2], (403, "198.51.100.28"))
_br281 = _px281.get("bearer", (0, None, False, -1, ""))
eq("Open: an API token (Bearer, no browser sign-in) gets no link: 409 with the reason, the host is not asked",
   _br281[:4], (409, None, True, 0))
check("Open: ...and the refusal is audited with why", "no browser sign-in" in _br281[4], _br281[4])
eq("proxy: a link bound to a login id with no session (a token's, an older cookie's) is refused and nothing is "
   "dialled: nothing would end it when the token is revoked or at logout", _px281.get("bare"), (403, 0))


# ── 3. the page policy ────────────────────────────────────────────────────────────────────────────
def _policy281():
    """The policy _csp builds, read from app.py's own source (its string literals in order, nonce filled in)."""
    with open(os.path.join(_ROOT281, "panel", "install", "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    body = src[src.index("    def _csp():"):src.index("    @app.after_request")]
    consts = [n for n in _ast281.walk(_ast281.parse("if True:\n" + body))
              if isinstance(n, _ast281.Constant) and isinstance(n.value, str) and n.value not in ("csp_nonce", "")]
    csp = "".join(n.value for n in sorted(consts, key=lambda n: (n.lineno, n.col_offset))).replace("%s", "n281")
    return dict((d.split(" ", 1) + [""])[:2] for d in (p.strip() for p in csp.split(";")) if d)


_cs281 = _policy281()
eq("policy: scripts by this request's nonce with 'strict-dynamic' only (OWASP's nonce-based strict policy), and "
   "styles and style elements by the nonce only: no 'self', so no other file on the panel's origin (an add-on "
   "page's) passes as a script or a stylesheet",
   (_cs281.get("script-src"), _cs281.get("style-src"), _cs281.get("style-src-elem"), _cs281.get("style-src-attr")),
   ("'nonce-n281' 'strict-dynamic'", "'nonce-n281'", "'nonce-n281'", "'none'"))


def _stylesheets281():
    bare, seen = [], 0
    tdir = os.path.join(_ROOT281, "panel", "templates")
    for name in sorted(os.listdir(tdir)):
        if name.endswith(".html"):
            with open(os.path.join(tdir, name), encoding="utf-8") as fh:
                for tag in _re281.findall(r"<link\b[^>]*>", fh.read()):
                    if "stylesheet" in tag:
                        seen += 1
                        bare += [] if 'nonce="{{ csp_nonce }}"' in tag else [name]
    page = _p9.test_client().get("/login").get_data(as_text=True)
    links = [t for t in _re281.findall(r"<link\b[^>]*>", page) if "stylesheet" in t]
    return seen, bare, len(links), all('nonce="p09"' in t for t in links)


_ss281 = _stylesheets281()
check("policy: every stylesheet <link> in the templates carries the request's nonce, and a rendered page's do "
      "(without it the browser refuses the panel's own CSS)",
      _ss281[0] >= 4 and _ss281[1] == [] and _ss281[2] >= 3 and _ss281[3], repr(_ss281))


# ── 4. Discord ────────────────────────────────────────────────────────────────────────────────────
eq("discord: the escaper shows a masked link, a heading, a quote, a list, a spoiler, a mention and a backslash "
   "as written, and leaves code (a block, an inline span) as it is",
   [_n281.discord_plain(t) for t in ("[Sign in](https://evil.example/x)", "# Head\n> quote\n- item\n-# small",
                                     "a_b *c* ~~d~~ ||e|| <@1> \\", "`!status` and ```\n[x](y)\n```")],
   ["\\[Sign in\\](https://evil.example/x)", "\\# Head\n\\> quote\n\\- item\n\\-# small",
    "a\\_b \\*c\\* \\~\\~d\\~\\~ \\|\\|e\\|\\| \\<@1\\> \\\\", "`!status` and ```\n[x](y)\n```"])


def _posted281(sent):
    """The Discord JSON bodies the stand-in _post took, decoded."""
    return [_json281.loads(body.decode()) for _url, body in sent]


def _discord_alert281():
    sent = []
    _p9_patch(_n281, "_post", lambda url, data, headers, **k: sent.append((url, data)) or (True, "sent"))
    _p9_patch(_n281, "decrypt_secret", lambda v: v)
    try:
        text = "p281-bk: the backup failed: [Sign in again](https://evil.example/x)\n# Re-authenticate now"
        senders = _n281._channel_senders({}, {"enabled": True, "webhook": "https://discord.com/api/webhooks/123456/p281"},
                                         {}, text)
        dict((n, send) for n, _on, send in senders)["discord"]()
        return _posted281(sent)
    finally:
        _p9_restore_all()


_da281 = _discord_alert281()
check("discord alert (webhook): the body's markdown is escaped, so a reason LinuxGSM printed can't post a masked "
      "link or a heading, and mentions are off",
      len(_da281) == 1 and "\\[Sign in again\\](https://evil.example/x)" in _da281[0]["content"]
      and "\n\\# Re-authenticate" in _da281[0]["content"] and _da281[0]["allowed_mentions"] == {"parse": []},
      repr(_da281)[:400])


def _discord_bot281():
    sent = []
    _p9_arm(who="part281")
    sid = _p9_new_server(P9_HOST, "p281dc", "csgo", 27181, name="[Sign in](https://evil.example/x) *p281*")
    _p9_patch(_n281, "_post", lambda url, data, headers, **k: sent.append((url, data)) or (True, "sent"))
    _p9_patch(_cmd281, "load_config", lambda: {})
    try:
        _dcm281._handle_discord_command(_p9, "A" * 50, "112233445566778899", "!servers")
        _dcm281._handle_discord_command(_p9, "A" * 50, "112233445566778899", "!help")
        return _posted281(sent)
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)


_db281 = _discord_bot281()
_dbs281 = [b.get("content", "") for b in _db281]
check("discord bot: a server's name in a reply (!servers) is shown as written: no masked link, no bold, and "
      "mentions are off", len(_dbs281) == 2 and "\\[Sign in\\](https://evil.example/x) \\*p281\\*" in _dbs281[0]
      and "[Sign in](" not in _dbs281[0] and all(b.get("allowed_mentions") == {"parse": []} for b in _db281),
      repr(_dbs281[:1])[:400])
check("discord bot: ...and the help's code spans are still code", len(_dbs281) == 2 and "`!status`" in _dbs281[1]
      and "\\`" not in _dbs281[1], repr(_dbs281[1:])[:300])
eq("text: the new refusal is in Spanish and French",
   [_i18n281.translate(lang, _rw281._NO_SIGN_IN) == _rw281._NO_SIGN_IN for lang in ("es", "fr")], [False, False])
