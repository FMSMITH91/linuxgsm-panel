"""Part 322 of the unit suite: website blocking as it really runs on a host, and the Updates page's words.

1. The first proxy apply with blocking on: `caddy validate` (run as the proxy's user) opens the security log's writer,
   so the helper makes the log folder (the proxy's own, 0700) before it validates; with blocking off it makes none.
2. Every site block's security logger is mapped to the block's names: the proxy decides whether a request is logged
   by its Host before any handler runs, and skips a host no logger is mapped to, so a site without its own access
   log logged nothing and nothing was ever banned. Unwatched requests stay out of the security log.
3. A deny entry is the proxy's to read (0640 root:proxy group), written atomically, by a ban and again by an apply
   for an entry an older helper wrote 0600: the proxy's file matcher matches only an entry it can read.
4. Unblock (the route down to the helper, with fail2ban's unbanip running the action's own unban) says it worked
   when it did, lifts the address idempotently, and is audited once, as done; fail2ban still banning it is refused.
5. A change of the jails' actions (Restricted <-> Public adds or takes away the firewall ban) restarts those jails
   only (a reload keeps a running jail's actions); the same settings only reload.
6. Each way a ban ends is told apart: by its time, lifted on the host, a jail stopped or restarted (actionflush).
7. An apply refusal reads as a plain sentence: no Go value dumped, never cut mid-word; the whole line stays in the log.
8. The pages: the proxy card's status line after a refused save, a site's Blocked visitors (since and until, the
   host's other bans counted, a lifted row gone at once), a first ban below OWASP's example noted.
9. The Updates page: LinuxGSM's own row from the server's real crontab, an item tried tonight waits for the next
   night, History on the host's clock, what an update costs and brings for what it really is, the greyed button's
   reason, Update now's result left in place, the Overview's words for a viewer without Update now.
10. A site's own certificate is warned about once, on its line, not again on each domain it serves.

HOW IT RUNS. The root helper is loaded by path and its verbs are run over scratch folders, every host command at its
_run_quiet seam; the routes through part12's app (its tripwire armed, so nothing reaches a host); the pages' scripts in
node over the rendered markup (part301's harness).
"""
import contextlib as _ctx322
import io as _io322
import json as _json322
import os
import re as _re322
import shutil as _shutil322
import stat as _stat322
import subprocess as _sp322  # nosec B404 - node over the panel's own scripts
import sys as _sys322
import tempfile as _tf322
import time as _time322
from types import SimpleNamespace as _NS322

from flask import g as _g322

from unit.part01 import _root, check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_patch_sm, _p9_restore_all
from panel.core import config as _cfg322
from panel.core.clock import utcnow as _utcnow322
from panel.db.models import (AuditLog as _Audit322, GameServer as _GS322, RemoteServer as _Remote322, User as _User322,
                             Website as _Site322, WebsiteDomain as _Dom322, WebsiteProxy as _Proxy322, db as _db322)
from panel.ops.ssh_manager import websites as _sw322

_TOKEN322 = "w" * 40
_ROWS322 = {"sites": [], "remotes": [], "users": [], "servers": []}
_VISITOR322 = "198.51.100.77"
_OTHER322 = "192.0.2.44"


def _helper322():
    import importlib.machinery as _mach
    import importlib.util as _ilu
    spec = _ilu.spec_from_loader("panel_helper_p322", _mach.SourceFileLoader(
        "panel_helper_p322", os.path.join(_root, "tools", "panel-helper")))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_H322 = _helper322()
_GUARD322 = {"enabled": True, "login": 10, "scan": 3, "findtime": 600, "bantime": 600, "maxtime": 86400,
             "increment": True, "firewall": False, "never": ["127.0.0.0/8", "::1/128"]}
_PROXY_GID322 = 4321          # the proxy's group as the stand-in passwd names it (not this account's own)


def _me322():
    import pwd as _pwd
    return _pwd.getpwuid(os.getuid())


def _quiet322(fn, *a):
    out = _io322.StringIO()
    with _ctx322.redirect_stdout(out):
        rc = fn(*a)
    return rc, out.getvalue()


class _Seams322:
    """The helper's module attributes replaced for one run, put back by restore()."""

    def __init__(self, **stubs):
        self.saved = {k: getattr(_H322, k) for k in stubs}
        for k, v in stubs.items():
            setattr(_H322, k, v)

    def restore(self):
        for k, v in self.saved.items():
            setattr(_H322, k, v)


# ── 1. The log folder is there before `caddy validate` ──────────────────────────────────────────────
def _apply_seen322(d, guard):
    """Run website-proxy-apply with `guard`; what the validate step found of the log folder (exists, mode)."""
    seen = []
    log_dir = os.path.join(d, "log")

    def validated(text, pw):
        st = os.stat(log_dir) if os.path.isdir(log_dir) else None
        seen.append((st is not None, _stat322.S_IMODE(st.st_mode) if st else None))
        return False                      # stop there: the start that follows is not this check's
    seams = _Seams322(WEB_PROXY_BIN=_sys322.executable, pwd=_NS322(getpwnam=lambda n: _me322()),
                      WEB_PROXY_CONF=os.path.join(d, "Caddyfile"), WEB_LOG_DIR=log_dir,
                      _web_listen_ok=lambda text, pw: (text, ["127.0.0.1"]), _web_validated=validated)
    try:
        doc = {"caddyfile": _H322.WEB_CONF_HEAD + "\n", "files": {}, "guard": guard}
        rc, _out = _quiet322(_H322.do_website_proxy_apply, ["reload"], _json322.dumps(doc))
    finally:
        seams.restore()
    return rc, seen


def _s1_log_dir():
    d = _tf322.mkdtemp(prefix="lgsm-unit-p322-log-")
    try:
        on = _apply_seen322(d, _GUARD322)
        _shutil322.rmtree(os.path.join(d, "log"), ignore_errors=True)
        off = _apply_seen322(d, dict(_GUARD322, enabled=False))
    finally:
        _shutil322.rmtree(d, ignore_errors=True)
    eq("blocked visitors (helper website-proxy-apply, blocking on): the security log's folder is made, the proxy's own "
       "and 0700, before `caddy validate` opens the log writer as the proxy's user (it cannot make a folder in /var/log)",
       on, (1, [(True, 0o700)]))
    eq("blocked visitors (helper website-proxy-apply, control: blocking off): validate runs and no log folder is made",
       off, (1, [(False, None)]))


# ── the guard's scratch tree (sections 3 to 6) ─────────────────────────────────────────────────────
def _tree322(d, writes, f2b):
    """The helper's guard paths in scratch folder `d`; every file write recorded in `writes` as (name, mode, uid,
    gid); fail2ban answered by `f2b(argv)` (argv without the tool's path)."""
    paths = {"WEB_DENY_DIR": os.path.join(d, "deny"), "WEB_GUARD_NEVER": os.path.join(d, "guard-never"),
             "WEB_GUARD_EVENTS": os.path.join(d, "guard-events"), "WEB_LOG_DIR": os.path.join(d, "log"),
             "WEB_SECURITY_LOG": os.path.join(d, "log", "security.log"), "WEB_F2B_DIR": d,
             "WEB_GUARD_JAIL_FILE": os.path.join(d, "jail.conf"), "WEB_GUARD_FILTER_FILE": os.path.join(d, "%s.conf"),
             "WEB_GUARD_ACTION_FILE": os.path.join(d, "action.conf")}
    os.makedirs(paths["WEB_DENY_DIR"], exist_ok=True)
    os.makedirs(paths["WEB_LOG_DIR"], exist_ok=True)
    with open(paths["WEB_SECURITY_LOG"], "a", encoding="utf-8"):
        pass                    # the helper would make it the proxy's: a chown this account cannot do

    def write(path, data, mode, uid=0, gid=0):
        writes.append((os.path.relpath(path, d), mode, uid, gid))
        with open(path, "wb") as fh:
            fh.write(data)
    proxy = _NS322(pw_uid=os.getuid(), pw_gid=_PROXY_GID322, pw_name="lgsmweb")
    return _Seams322(**dict(paths, pwd=_NS322(getpwnam=lambda n: proxy), _web_write=write,
                            _web_own_nets=lambda: ["203.0.113.5/32"], resolve=lambda name: name,
                            _web_deny_dir=lambda gid: None, _web_log_dir=lambda pw: None,
                            _run_quiet=lambda argv, timeout=60, **k: f2b(list(argv)))), proxy


def _line322(ip, tag, host):
    return _json322.dumps({"level": "info", "ts": "2026-11-27T10:00:00.000Z", "logger": "http.log.access.lgsmsec5_0",
                           "msg": "handled request", "request": {"client_ip": ip, "method": "POST", "host": host},
                           "status": 200, "lgsm": tag}, separators=(",", ":"))


# ── 3. Deny entries the proxy can read ─────────────────────────────────────────────────────────────
def _s3_deny_modes():
    d = _tf322.mkdtemp(prefix="lgsm-unit-p322-deny-")
    writes = []
    seams, proxy = _tree322(d, writes, lambda argv: (0, ""))
    try:
        _quiet322(_H322._web_guard_apply, dict(_GUARD322), proxy)
        with open(_H322.WEB_SECURITY_LOG, "a", encoding="utf-8") as fh:
            fh.write(_line322(_VISITOR322, "login", "p322.example.org") + "\n")
        del writes[:]
        ban = _quiet322(_H322.do_website_guard_ban, [_VISITOR322, "lgsm-web-login", "600"], "")
        banned = [w for w in writes if w[0].startswith("deny")]
        # An entry an older helper wrote: 0600 root, the proxy cannot read it. The next apply writes it again.
        old = os.path.join(_H322.WEB_DENY_DIR, _OTHER322)
        fd = os.open(old, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"jail=lgsm-web-scan at=100 until=%d host=p322.example.org\n" % (int(_time322.time()) + 600))
        os.close(fd)
        del writes[:]
        _quiet322(_H322._web_guard_apply, dict(_GUARD322), proxy)
        redone = [w for w in writes if w[0] == os.path.join("deny", _OTHER322)]
        never = _quiet322(_H322.do_website_guard_ban, ["127.0.0.1", "lgsm-web-login", "600"], "")
    finally:
        seams.restore()
        _shutil322.rmtree(d, ignore_errors=True)
    entry = os.path.join("deny", _VISITOR322)
    eq("blocked visitors (helper website-guard-ban): the deny entry is written 0640, root's and the proxy's group "
       "(the proxy's file matcher, as the proxy's user, matches only an entry it can read: 0600 root let a banned "
       "visitor through, cached pages and all)", (ban, banned), ((0, "ban=yes\n"), [(entry, 0o640, 0, _PROXY_GID322)]))
    eq("blocked visitors (helper website-proxy-apply's guard step): an entry an older helper wrote 0600 is written "
       "again 0640 root:the proxy's group, so a ban from before the update blocks too",
       redone, [(os.path.join("deny", _OTHER322), 0o640, 0, _PROXY_GID322)])
    eq("blocked visitors (helper, control): the host's own loopback is never banned, nothing written",
       never, (1, "ban=refused\n"))


# ── 4 and 6. Unblock end to end, and the ways a ban ends ───────────────────────────────────────────
class _F2b322:
    """fail2ban as the helper's action sees it: unbanip runs the action's own unban (website-guard-unban)."""

    def __init__(self, lifts=True):
        self.banned = {"lgsm-web-login": set(), "lgsm-web-scan": set()}
        self.lifts, self.calls = lifts, []

    def __call__(self, argv):
        self.calls.append(argv[1:])
        if argv[1:2] == ["set"] and argv[3:4] == ["unbanip"]:
            jail, ip = argv[2], argv[4]
            if self.lifts and ip in self.banned.get(jail, ()):
                self.banned[jail].discard(ip)
                _H322.do_website_guard_unban([ip, jail], "")
                return 0, "1"
            return 255, ""
        if argv[1:2] == ["get"] and argv[3:4] == ["banip"]:
            return 0, " ".join(sorted(self.banned.get(argv[2], ())))
        return 0, ""


def _host_helper322(remote, verb, args=(), timeout=120, doc=None):
    """ssh_manager.websites' helper call answered by the helper's own verb, run here over the scratch tree."""
    rc, out = _quiet322(_H322.ACTIONS[verb], list(args), doc or "")
    return rc == 0, out


class _Client322:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g322.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g322.pop("_login_user", None)
        _g322.__dict__.pop("_websites_access_cache", None)
        return self.c.get(*a, **k)


def _rows322():
    r = _Remote322(name="p322-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.122", timezone="America/New_York")
    su = _User322(username="p322-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db322.session.add_all([r, su])
    _db322.session.commit()
    _ROWS322["remotes"].append(r.id)
    _ROWS322["users"].append(su.id)
    return _NS322(host=r, su=su)


def _site322(st, name, kind="static", **kw):
    extra = {"php_version": "8.4"} if kind in ("php", "wordpress") else {}
    s = _Site322(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg322.encrypt_secret(_TOKEN322), **dict(extra, **kw))
    _db322.session.add(s)
    _db322.session.flush()
    s.account, s.port = "ws%d" % s.id, 20500 + s.id % 400
    _db322.session.add(_Dom322(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=_utcnow322(), dns_state="matching"))
    _db322.session.commit()
    _ROWS322["sites"].append(s.id)
    return s


def _blocked322(su, site):
    body = _p9_json(su.get("/websites/%d/blocked" % site.id))
    return [e.get("ip") for e in body.get("entries") or []], body.get("others")


def _unblock_run322(st, f2b):
    """Two addresses banned (one at this site, one elsewhere), then this site's Unblock: what the pages saw."""
    from panel.routes import websites_guard as _rg
    site = _site322(st, "p322b%d" % len(_ROWS322["sites"]))
    d = _tf322.mkdtemp(prefix="lgsm-unit-p322-unban-")
    seams, _proxy = _tree322(d, [], f2b)
    try:
        _quiet322(_H322._web_guard_apply, dict(_GUARD322), _proxy)
        with open(_H322.WEB_SECURITY_LOG, "a", encoding="utf-8") as fh:
            fh.write(_line322(_VISITOR322, "login", site.domains[0].domain) + "\n")
            fh.write(_line322(_OTHER322, "scan", "elsewhere.example.org") + "\n")
        for ip, jail in ((_VISITOR322, "lgsm-web-login"), (_OTHER322, "lgsm-web-scan")):
            f2b.banned[jail].add(ip)
            _quiet322(_H322.do_website_guard_ban, [ip, jail, "600"], "")
        _p9_patch(_sw322, "_helper", _host_helper322)
        _rg._set_cursor(st.host.id, 0)
        su = _Client322(st.su.id)
        before = _blocked322(su, site)
        r = su.post("/websites/%d/blocked/unban" % site.id, json={"ip": _VISITOR322})
        after = _blocked322(su, site)
        again = _quiet322(_H322.do_website_guard_release, [_VISITOR322], "")
        rows = [(a.detail, bool(a.success)) for a in _Audit322.query.filter_by(action="website_unban", website_id=site.id)]
        return {"before": before, "status": r.status_code, "ok": _p9_json(r).get("success"), "after": after,
                "again": again, "audit": rows}
    finally:
        seams.restore()
        _shutil322.rmtree(d, ignore_errors=True)


def _s4_unblock(st):
    got = _unblock_run322(st, _F2b322())
    eq("blocked visitors (GET /websites/<id>/blocked, the helper's real list): this site's attacker is listed, and the "
       "host's other blocked address (another site's) is counted, never named", got["before"], ([_VISITOR322], 1))
    eq("blocked visitors (POST /websites/<id>/blocked/unban down to the helper, fail2ban's unbanip running the "
       "action's unban): it says it worked, the address is gone from the next list, the audit row is the Unblock's "
       "one, marked done (no second row saying its ban ended), and a second Unblock is idempotent",
       (got["status"], got["ok"], got["after"][0], [(("unblocked by hand" in a), ok) for a, ok in got["audit"]],
        got["again"]), (200, True, [], [(True, True)], (0, "released=yes\n")))
    still = _unblock_run322(st, _F2b322(lifts=False))
    eq("blocked visitors (Unblock, control: fail2ban keeps banning the address): refused, audited as not done",
       (still["ok"], [ok for _a, ok in still["audit"]]), (False, [False]))


# ── 5. A change of the jails' actions restarts those jails ─────────────────────────────────────────
# ── 7. An apply refusal in plain words ─────────────────────────────────────────────────────────────
_CADDY_RAW322 = ('Error: loading initial config: loading new config: setting up custom log \'lgsmsec3_0\': opening log '
                 'writer using &logging.FileWriter{Filename:"/var/log/lgsm-web-proxy/security.log", Mode:0x180, '
                 'DirMode:"", Roll:(*bool)(nil), RollSizeMB:10, RollInterval:0, RollAtMinutes:[]int(nil), '
                 'RollAt:[]string(nil), RollKeep:2, RollKeepDays:2}: mkdir /var/log/lgsm-web-proxy: permission denied')


# ── 2. The security logger is mapped to the block's names ──────────────────────────────────────────
def _caddy322(text):
    """Caddy's adapter and request logging, modelled: {host: (block body, [logger names mapped])}, skip_unmapped.

    A `log` without `no_hostname` maps the block's names to it; a catch-all block with no logger makes the server skip
    unmapped hosts (httpcaddyfile's serversFromPairings; caddyhttp Server.shouldLogRequest).
    """
    hosts = {}
    for block in text.split("\n# site ")[1:]:
        head, _sep, rest = block.partition(" {\n")
        body = rest.split("\n}\n")[0]
        mapped = [m.group(1) for m in _re322.finditer(r"^\tlog (\S+) \{\n(.*?)^\t\}$", body, _re322.M | _re322.S)
                  if "\t\tno_hostname" not in m.group(2)]
        for h in head.split("\n", 1)[1].split(", "):
            hosts[h.replace("http://", "")] = (body, mapped)
    return hosts, ("https:// {" in text or "http:// {" in text)


def _logged322(model, host, watched):
    """The loggers a request to `host` is written to: a watched sign-in POST, or anything else."""
    hosts, skip_unmapped = model
    body, mapped = hosts[host]
    if not mapped and skip_unmapped:
        return []                       # decided before any handler: log_name cannot bring it back
    if watched:
        return _re322.search(r"^\tlog_name @lgsmlogin (.+)$", body, _re322.M).group(1).split()
    if "\tlog_skip @lgsmquiet" in body:
        return []
    named = _re322.search(r"^\tlog_name @lgsmquiet (.+)$", body, _re322.M)
    return named.group(1).split() if named else mapped


def _s2_mapped(st):
    from panel.routes import websites as _w
    from panel.services import websites_proxy as _wp
    quiet, logged = _site322(st, "p322q", enabled=True), _site322(st, "p322l", enabled=True, access_log=True)
    row = _w.proxy_row(st.host.id)
    row.exposure_mode, row.guard = "public", "{}"
    _db322.session.commit()
    model = _caddy322(_wp.render([quiet, logged], row, {}, secret_of=lambda s: _TOKEN322))
    q, lg = "p322q.example.org", "p322l.example.org"
    sec_q, sec_l, acc_l = "lgsmsec%d_0" % quiet.id, "lgsmsec%d_0" % logged.id, "lgsmacc%d_0" % logged.id
    eq("blocked visitors (render, a site with no access log of its own): its names map to its security logger, so a "
       "sign-in POST is written to the security log (with `no_hostname` the proxy skipped the host before any "
       "handler and nothing was ever banned); every other request is written nowhere",
       (_logged322(model, q, True), _logged322(model, q, False)), ([sec_q], []))
    eq("blocked visitors (render, control: a site with its access log on): a sign-in POST goes to both loggers, every "
       "other request to its access log alone (masked), never to the security log",
       (sorted(_logged322(model, lg, True)), _logged322(model, lg, False)), (sorted([sec_l, acc_l]), [acc_l]))
    for s in (quiet, logged):
        s.enabled = False
    _db322.session.commit()


# ── 8. The pages' scripts ────────────────────────────────────────────────────────────────────────
def _node322(page, scripts, scenario, routes):
    """part301's node harness, with addEventListener on its elements (the Updates page wires its buttons that way)."""
    from unit.part301 import _HARNESS301, _JS301, _tree301
    node = _shutil322.which("node")
    if not node:
        return {"error": "node is not installed"}
    harness = _HARNESS301.replace("El.prototype.click = ", "El.prototype.addEventListener = function (t, f) { "
                                  "(this._on = this._on || {})[t] = f; };\nEl.prototype.click = ", 1)
    tmp = _tf322.mkdtemp(prefix="p322-")
    try:
        path = os.path.join(tmp, "harness.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(harness)
        cfg = {"tree": _tree301(page), "scripts": [os.path.join(_JS301, s) for s in scripts], "scenario": scenario,
               "routes": routes or {}, "search": ""}
        r = _sp322.run([node, path], input=_json322.dumps(cfg),  # nosec B603 - node on this part's harness
                       capture_output=True, text=True, timeout=120, check=False)
        try:
            return _json322.loads(r.stdout)
        except ValueError:
            return {"error": (r.stdout + r.stderr)[-1200:]}
    finally:
        _shutil322.rmtree(tmp, ignore_errors=True)


def _s8_blocked_page():
    from unit.part301 import _site_ad301
    entry = {"ip": _VISITOR322, "jail": "lgsm-web-login", "reason": "Too many sign-in attempts",
             "since": "2026-11-27 10:00:00 UTC", "until": "2026-11-27 10:10:00 UTC"}
    routes = {"/websites/7/blocked": {"success": True, "entries": [entry], "count": 1, "others": 2,
                                      "guard": {"enabled": True, "fail2ban": "yes"}},
              "/websites/7/blocked/unban": {"success": True, "message": "%s is no longer blocked." % _VISITOR322}}
    got = _node322(_site_ad301, ["websites_common.js", "website_site.js", "website_blocked.js"], r"""
  WS.loadBlocked();
  for (let i = 0; i < 4; i++) await tick();
  const row = $('wv-list').children[0];
  const shown = {text: row ? row.textContent : '', state: $('wv-state').textContent, n: $('wv-count').textContent};
  window.wsUnblock('198.51.100.77');
  for (let i = 0; i < 4; i++) await tick();
  return {shown: shown, left: $('wv-list').children.length, n: $('wv-count').textContent, msg: $('wv-msg').textContent};
""", routes)
    shown = got.get("shown") or {}
    eq("Blocked visitors (js/website_blocked.js): each address says since when as well as until when",
       ("since" in shown.get("text", "") and "2026-11-27 10:00:00 UTC" in shown.get("text", ""), got.get("error")),
       (True, None))
    eq("Blocked visitors (js/website_blocked.js): the host's other bans (they hold for this site too) are counted under "
       "the list, never named", "2 more address(es)" in shown.get("state", ""), True)
    eq("Blocked visitors (js/website_blocked.js, Unblock): the row is gone at once, the count follows, the answer kept",
       (got.get("left"), got.get("n"), got.get("msg")), (0, "0", "%s is no longer blocked." % _VISITOR322))


# ── 9. The Updates page ──────────────────────────────────────────────────────────────────────────
def _server322(st):
    gs = _GS322(name="p322-game", game_type="cod4", short_name="p322cod", port=28961, remote_id=st.host.id,
                installed=True, status="online")
    _db322.session.add(gs)
    _db322.session.commit()
    _ROWS322["servers"].append(gs.id)
    return gs


def _updates322(su):
    body = _p9_json(su.get("/api/updates"))
    return {r["ref"]: r for g in body.get("groups") or [] for r in g["items"]}, body


def _pending322(st, name, kind, image_same, files):
    from panel.routes import websites as _w
    s = _site322(st, name, kind)
    s.image_digest = _w.current_image(s) if image_same else "localhost/p322-old:1"
    s.image_key = files
    _db322.session.commit()
    return s


_UPD_SCN322 = r"""
  for (let i = 0; i < 6; i++) await tick();
  const btn = $('upd-safe'), why = $('upd-safe-why');
  const out = {disabled: btn.disabled, why: why.hidden ? '' : why.textContent,
               hist: $('upd-history-list').textContent};
  const run = $('upd-list').querySelectorAll('button')[0];
  if (run) {
    setTimeout = function (f) { f(); return 0; };
    const f0 = fetch;
    fetch = function (url, init) {
      if (String(url).indexOf('/api/updates') >= 0 && !(init && init.method)) {
        return Promise.resolve({json: function () { return Promise.resolve({success: true, groups: [], count: 0,
          settings: {}, history: []}); }});
      }
      return f0(url, init);
    };
    run._on.click();
    for (let i = 0; i < 8; i++) await tick();
    out.row = $('upd-list').textContent;
    out.button = $('upd-list').querySelectorAll('button').length;
  }
  return out;
"""


def _upd_answer322(action):
    row = {"kind": "website", "ref": "website:9", "name": "shop", "host": "", "what": ["x"], "notes": [], "cost": "c",
           "security": False, "safe": True, "auto": True, "auto_editable": False, "when": "w", "when_link": None,
           "action": action, "link": ""}
    return {"success": True, "count": 1, "groups": [{"key": "website", "title": "Websites", "items": [row]}],
            "settings": {"start": "04:00", "end": "05:00"},
            "history": [{"at": "2026-11-27T04:54:00Z", "at_host": "2026-11-26 23:54", "who": "automatic",
                         "action": "website_update", "target": "shop", "ok": True, "detail": ""}]}


# ── 10. The site's certificate is warned about once ────────────────────────────────────────────────
def _pem322(names):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _cleanup322():
    _db322.session.rollback()
    remotes = _ROWS322["remotes"] or [0]
    sites = sorted(set(_ROWS322["sites"]) | {s.id for s in _Site322.query.filter(_Site322.remote_id.in_(remotes))})
    _Audit322.query.filter(_Audit322.website_id.in_(sites or [0])).delete(synchronize_session=False)
    _Audit322.query.filter(_Audit322.remote_id.in_(remotes)).delete(synchronize_session=False)
    for d in _Dom322.query.filter(_Dom322.website_id.in_(sites or [0])).all():
        _db322.session.delete(d)
    for p in _Proxy322.query.filter(_Proxy322.remote_id.in_(remotes)).all():
        _db322.session.delete(p)
    for model, ids in ((_Site322, sites), (_GS322, _ROWS322["servers"]), (_User322, _ROWS322["users"]),
                       (_Remote322, _ROWS322["remotes"])):
        for i in ids:
            row = _db322.session.get(model, i)
            if row is not None:
                _db322.session.delete(row)
    _db322.session.commit()
    from panel.routes import websites_guard as _rg
    _cfg322.update_config(lambda cfg: cfg.pop(_rg.CURSOR_KEY, None))


def _ran322(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran322.last)."""
    import traceback
    try:
        step(*args)
        _ran322.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        from flask import has_app_context
        if has_app_context():
            _db322.session.rollback()
        _ran322.last = traceback.format_exc()[-1500:]
        return False


_ran322.last = ""
for _sec322 in (_s1_log_dir, _s3_deny_modes, _s8_blocked_page):
    check("part322: %s ran to the end" % _sec322.__name__, _ran322(_sec322), _ran322.last)
_trips322 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part322")
        _p9_patch(_sw322, "site_probe", lambda remote, site: (False, "not read in part322"))
        _st322 = _rows322()
        for _sec322 in (_s2_mapped, _s4_unblock):
            check("part322: %s ran to the end" % _sec322.__name__, _ran322(_sec322, _st322), _ran322.last)
        eq("part322: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips322:], [])
    finally:
        _p9_restore_all()
        _cleanup322()
