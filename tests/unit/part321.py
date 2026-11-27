"""Part 321 of the unit suite: CI's apt step, the tunnel's closed ports, a stopped database server, website bans.

1. CI: the unit legs' apt step takes the runner image's own packages.microsoft.com source out of apt's list before
   `apt-get update` (that repository answered 403 and failed the whole leg), and only that source; the step's own
   loop is run over a scratch sources folder.
2. Tunnel mode closes ports 80 and 443 whatever becomes of the tunnel: a token the provider refuses ended the apply
   before its firewall step, and the public rules stayed open while the saved mode said tunnel. The answer says so.
3. A database server the panel set up and that stopped since: an app install and a site's database create ask the
   host again instead of trusting the row's "ready" (up to 10 minutes old), so they are refused with the Start
   button's entry before anything is made, and the add dialog's list shows that entry at once.
4. WordPress's Site Health page cache test answers from the web proxy's real state: each proxy apply writes, into
   every WordPress site's files, whether the configuration it runs caches that site's pages (and for how long), and
   the loopback plugin replaces WordPress's own test (which looks for caching headers on requests that never pass
   the proxy) with one reading that word. The page cache's block also takes away the empty Cache-Control header the
   cache module put on a page whose site sent none, and only that one.

HOW IT RUNS. part12's app and its database for the routes; every host call at ssh_manager's seams (part12's
tripwire is armed, so nothing reaches a host). The workflow is read as text (part06's run-block reader).
"""
import os
import shutil as _shutil321
import subprocess as _sp321  # nosec B404 - bash over the workflow's own loop, in a scratch folder
import tempfile as _tf321
from types import SimpleNamespace as _NS321

from flask import g as _g321

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg321
from panel.core.clock import utcnow as _utcnow321
from panel.db.models import (HostDatabaseServer as _HDS321, RemoteServer as _Remote321, User as _User321,
                             Website as _Site321, WebsiteDomain as _Dom321, WebsiteProxy as _Proxy321, db as _db321)
from panel.ops.ssh_manager import databases as _dbs321
from panel.ops.ssh_manager import websites as _sw321
from panel.routes import databases as _dbr321
from panel.routes import websites as _w321
from panel.routes import websites_apps as _wapps321
from panel.routes import websites_view as _wview321

_TOKEN321 = "k" * 40
_ROWS321 = {"sites": [], "remotes": [], "users": []}
_REC321 = {"ports": [], "apply": []}
# The sentence a failed tunnel-mode apply ends with, pinned as written (a revert of the fix has no such name).
_CLOSED321 = "Ports 80 and 443 are closed: in tunnel mode visitors come in only through the tunnel."
_REAL_APPLY321 = _sw321.proxy_apply      # the real apply for section 4; section 2's seams stub it
_STOPPED321 = {"state": "unsupported", "detail": "stopped", "flavor": "mariadb"}


class _Client321:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g321.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g321.pop("_login_user", None)
        return self.c.get(*a, **k)


class _Inline321:
    """threading.Thread that runs its target at start(), in the caller's thread."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)


def _rows321():
    r = _Remote321(name="p321-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.121")
    su = _User321(username="p321-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db321.session.add_all([r, su])
    _db321.session.commit()
    _ROWS321["remotes"].append(r.id)
    _ROWS321["users"].append(su.id)
    return _NS321(host=r, su=su)


def _site321(st, name, kind="static", **kw):
    extra = {"php_version": "8.4"} if kind in ("php", "wordpress") else {}
    s = _Site321(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg321.encrypt_secret(_TOKEN321), **dict(extra, **kw))
    _db321.session.add(s)
    _db321.session.flush()
    s.account, s.port = "ws%d" % s.id, 20500 + s.id % 400
    _db321.session.add(_Dom321(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=_utcnow321(), dns_state="matching"))
    _db321.session.commit()
    _ROWS321["sites"].append(s.id)
    return s


# ── 1. CI: apt without the runner image's Microsoft source ────────────────────────────────────────
_APT_STEP321 = "Install zsh and systemd-journal-remote"


def _apt_body321():
    with open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8") as fh:
        return _wf_run_block(fh.read(), _APT_STEP321)


def _apt_loop321(body):
    """The step's lines from its `for src in` loop to its `done`, or "" when it has none."""
    lines = body.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("for src in /etc/apt/sources.list.d/")), None)
    if start is None:
        return ""
    end = next((i for i in range(start, len(lines)) if lines[i].strip() == "done"), None)
    return "\n".join(lines[start:end + 1]) + "\n" if end is not None else ""


def _s1_ci():
    body = _apt_body321()
    code = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    upd = next((i for i, ln in enumerate(code) if "apt-get update" in ln), -1)
    loop_at = next((i for i, ln in enumerate(code) if ln.startswith("for src in /etc/apt/sources.list.d/")), -1)
    eq("CI (ci.yml, the unit legs' apt step): a loop over apt's source files runs BEFORE `apt-get update`",
       (loop_at >= 0, upd >= 0, 0 <= loop_at < upd), (True, True, True))
    d = _tf321.mkdtemp(prefix="lgsm-unit-p321-apt-")
    try:
        src, aside = os.path.join(d, "sources.list.d"), os.path.join(d, "aside")
        os.makedirs(src)
        os.makedirs(aside)
        files = {"microsoft-prod.list": "deb [arch=amd64,armhf,arm64] https://packages.microsoft.com/ubuntu/24.04/prod "
                                        "noble main\n",
                 "azure-cli.sources": "Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\n",
                 "ubuntu.sources": "Types: deb\nURIs: http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\n",
                 "esm.list": "deb https://esm.ubuntu.com/apps/ubuntu noble-apps-security main\n"}
        for name, text in files.items():
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        loop = _apt_loop321(body).replace("/etc/apt/sources.list.d", src).replace("sudo ", "")
        r = _sp321.run(["bash", "-c", loop], env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": aside},
                       capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607 - bash, fixed
        got = (r.returncode, sorted(os.listdir(src)), sorted(os.listdir(aside)))
    finally:
        _shutil321.rmtree(d, ignore_errors=True)
    eq("CI (the step's own loop, run over a scratch sources folder): every source file naming packages.microsoft.com "
       "(one-line and deb822) is moved out of apt's list; the Ubuntu archive's and Ubuntu Pro's stay (control)",
       got, (0, ["esm.list", "ubuntu.sources"], ["azure-cli.sources", "microsoft-prod.list"]))


# ── 2. Tunnel mode closes the public ports ────────────────────────────────────────────────────────
def _seams321(tunnel_answer):
    def ports(remote, proxy, enabled):
        _REC321["ports"].append((proxy.exposure_mode, _sw321.wanted_rules(proxy, enabled)))
        return True, _sw321.OK_PORTS

    def apply(remote, text, sites=(), proxy=None, start_it=False):
        _REC321["apply"].append(text)
        return True, _sw321.OK_APPLIED
    _p9_patch(_sw321, "ports_apply", ports)
    _p9_patch(_sw321, "proxy_apply", apply)
    _p9_patch(_sw321, "proxy_stop", lambda *a, **k: (True, _sw321.OK_PROXY_STOPPED))
    _p9_patch(_sw321, "tunnel_apply", lambda *a, **k: tunnel_answer)


def _save321(st, exposure):
    _REC321["ports"], _REC321["apply"] = [], []
    r = _Client321(st.su.id).post("/websites/proxy/settings", json={"host_id": st.host.id, "exposure": exposure})
    row = _Proxy321.query.filter_by(remote_id=st.host.id).first()
    _db321.session.refresh(row)
    return r, row


def _s2_tunnel(st):
    _site321(st, "p321-tun", enabled=True)
    _seams321((True, _sw321.OK_TUNNEL))
    r, _row = _save321(st, {"exposure_mode": "public"})
    eq("tunnel ports (control, POST /websites/proxy/settings in public mode): ports 80 and 443 open to everyone, the "
       "proxy applied, no word of closed ports",
       (r.status_code, _REC321["ports"], len(_REC321["apply"]), _CLOSED321 in (_p9_json(r).get("message") or "")),
       (200, [("public", [(None, "80"), (None, "443")])], 1, False))
    _seams321((False, _sw321.TUNNEL_REFUSED))
    r, row = _save321(st, {"exposure_mode": "tunnel", "tunnel_provider": "cloudflare", "tunnel_token": "t" * 60})
    msg = _p9_json(r).get("message") or ""
    eq("tunnel ports (POST /websites/proxy/settings to tunnel mode with a token the provider refuses): the public "
       "rules are taken away all the same (the firewall wants none in tunnel mode), the answer says why it failed AND "
       "that the ports are closed, and last_error keeps the tunnel's own sentence alone",
       (r.status_code, _REC321["ports"], msg.startswith(_sw321.TUNNEL_REFUSED), msg.endswith(_CLOSED321),
        row.exposure_mode, row.last_error),
       (502, [("tunnel", [])], True, True, "tunnel", _sw321.TUNNEL_REFUSED))
    _seams321((False, _sw321.TUNNEL_REFUSED))
    r = _Client321(st.su.id).post("/websites/proxy/apply", json={"host_id": st.host.id})
    eq("tunnel ports (POST /websites/proxy/apply in tunnel mode, the token still refused): the ports are closed again "
       "and the answer says so", (r.status_code, [m for m, _w in _REC321["ports"]][-1:],
                                  (_p9_json(r).get("message") or "").endswith(_CLOSED321)),
       (502, ["tunnel"], True))


# ── 3. A database server stopped since it was set up ──────────────────────────────────────────────
def _hds321(st):
    hd = _HDS321(remote_id=st.host.id, flavor="mariadb", version="11.8.3-MariaDB", installed_by_panel=True,
                 auth_mode="socket", port=3306, checked_at=_dbr321._now())
    _db321.session.add(hd)
    _db321.session.commit()
    return hd


def _install_form321(st, name):
    return {"app": "wordpress", "name": name, "remote_id": st.host.id, "admin_user": "siteowner",
            "admin_email": "owner@example.org", "domain": "%s.example.org" % name}


def _s3_db_stopped(st):
    _hds321(st)
    _dbr321._PROBES.pop(st.host.id, None)
    asked, answers = [], [dict(_STOPPED321)]
    _p9_patch(_dbs321, "probe", lambda remote: asked.append(remote.id) or (answers.pop(0) if answers else
                                                                           {"state": "ready"}))
    _p9_patch(_wapps321, "_worker", lambda app, sid, uid, secrets: None)
    _p9_patch(_w321, "threading", _NS321(Thread=_Inline321))
    eq("stopped database (before: the row checked a minute ago): the add dialog's list, which never probes, reads it "
       "ready", (_wview321.database_missing(st.host), asked), (None, []))
    su = _Client321(st.su.id)
    r = su.post("/websites/install-app", json=_install_form321(st, "p321-wp"))
    body = _p9_json(r)
    made = _Site321.query.filter_by(remote_id=st.host.id, name="p321-wp").first()
    if made is not None:
        _ROWS321["sites"].append(made.id)
    eq("stopped database (POST /websites/install-app, WordPress, the server stopped since its row was checked): the "
       "host is asked again, and the install is refused before anything is made with the entry the Start button "
       "fixes",
       (r.status_code, asked, made is None, [(m.get("key"), m.get("host_id")) for m in body.get("missing") or []]),
       (409, [st.host.id], True, [("database-stopped", st.host.id)]))
    eq("stopped database (the add dialog's list after it, which does not probe): the newer probe's word wins over the "
       "row, so the Start button shows at once, not 10 minutes later",
       ((_wview321.database_missing(st.host) or {}).get("key"), asked), ("database-stopped", [st.host.id]))
    created = []
    _p9_patch(_dbs321, "create", lambda *a, **k: created.append(a[2]) or (True, "created"))
    site = _site321(st, "p321-dbsite", kind="php")
    answers[:] = [dict(_STOPPED321)]
    r = su.post("/websites/%d/databases/add" % site.id, json={"name": "app"})
    eq("stopped database (POST /websites/<id>/databases/add): asked again, refused with nothing created on the "
       "host, and the answer carries the Start button's entry",
       (r.status_code, created, [m.get("key") for m in _p9_json(r).get("missing") or []]),
       (502, [], ["database-stopped"]))
    answers[:] = [{"state": "ready", "flavor": "mariadb", "version": "11.8.3-MariaDB"}]
    r = su.post("/websites/install-app", json=_install_form321(st, "p321-wp2"))
    made = _Site321.query.filter_by(remote_id=st.host.id, name="p321-wp2").first()
    if made is not None:
        _ROWS321["sites"].append(made.id)
    eq("stopped database (control: the server started again, the host answers ready): the install starts, and the "
       "dialog's list reads ready", (r.status_code, made is not None, _wview321.database_missing(st.host)),
       (200, True, None))


# ── 4. The page cache, as WordPress's Site Health and the response headers see it ──────────────────
def _s4_render(st):
    from panel.services import websites_proxy as _wp
    wp = _site321(st, "p321-wpc", kind="wordpress", enabled=True, page_cache=True, page_cache_ttl=300)
    plain = _site321(st, "p321-wpn", kind="wordpress", enabled=True, page_cache=False)
    on = _wp.render([wp, plain], None, {"cache_build": True}, secret_of=lambda s: _TOKEN321)
    off = _wp.render([wp, plain], None, {"cache_build": False}, secret_of=lambda s: _TOKEN321)
    blocks = {sid: on.split("# site %d (" % sid)[1].split("\n}\n")[0] for sid in (wp.id, plain.id)}
    strip = ["\theader {", "\t\t-Cache-Control", '\t\tmatch header Cache-Control ""', "\t}"]
    eq("page cache headers (render): a site whose pages the proxy caches has a header block that takes away a "
       "Cache-Control header only when it is empty (as the response leaves); a site without the cache has none, and "
       "no default Cache-Control is set anywhere (that would change what is stored)",
       ("\n".join(strip) in blocks[wp.id], "\n".join(strip) in blocks[plain.id], "default_cache_control" in on),
       (True, False, False))
    eq("page cache state (cached_sites over the rendered text): the cached site with its TTL; nothing when the proxy "
       "has no cache module, though the site's switch is on", (_wp.cached_sites(on), _wp.cached_sites(off)),
       ({wp.id: 300}, {}))
    return wp, plain


def _s4_apply(st):
    from panel.ops.ssh_manager import _core as _smcore
    from panel.routes import _shared as _shared321
    wp, plain = _s4_render(st)
    static = _site321(st, "p321-wps", kind="static", enabled=True)
    writes = []

    def shell(server, user, sh, timeout=30, stdin_text=None, **k):
        writes.append((user, stdin_text or ""))
        return "", "", 0
    _p9_patch(_sw321, "ports_apply", lambda *a, **k: (True, _sw321.OK_PORTS))
    _p9_patch(_sw321, "proxy_apply", _REAL_APPLY321)
    _p9_patch(_sw321, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "applied=yes"))
    _p9_patch(_sw321, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nversion=2.11.9\nactive=active\n"
                                                                  "cache=yes\n"))
    _p9_patch(_smcore, "shell_as_game_user", shell)
    _p9_patch(_shared321, "game_account_write_refusal", lambda remote, user, *a, **k: None)
    _p9_patch(_wview321, "proxy_options", lambda: {"cache_build": True})
    _sw321._PAGE_CACHE_NOTED.clear()

    def written():
        import base64
        out = {}
        for user, stdin in writes:
            for line in stdin.splitlines():
                path, b64 = line.split(" ", 1)
                out[(user, path)] = base64.b64decode(b64).decode()
        writes[:] = []
        return out
    from panel.services import websites as _ws321
    ok, _said = _w321.reconcile_proxy(st.host)
    first = written()
    eq("page cache state (reconcile_proxy -> proxy_apply, the proxy built with the cache): each WordPress site's "
       "files get the state the applied configuration gives it (on with its TTL, off); a static site gets nothing",
       (ok, first), (True, {(wp.account, _ws321.PAGE_CACHE_FILE): "on 300\n",
                            (plain.account, _ws321.PAGE_CACHE_FILE): "off\n"}))
    ok, _said = _w321.reconcile_proxy(st.host)
    eq("page cache state (the same apply again): nothing is written when nothing changed", (ok, written()), (True, {}))
    wp.page_cache = False
    _db321.session.commit()
    ok, _said = _w321.reconcile_proxy(st.host)
    eq("page cache state (the site's page cache turned off, applied): its file says off", (ok, written()),
       (True, {(wp.account, _ws321.PAGE_CACHE_FILE): "off\n"}))
    for s in (wp, plain, static):
        s.enabled = False
    _db321.session.commit()


def _s4_plugin():
    from panel.services import websites as _ws321
    php = _ws321.loopback_plugin()
    test_fn = php[php.find("function lgsm_panel_site_status_tests"):] if "lgsm_panel_site_status_tests" in php else ""
    eq("Site Health (the loopback plugin): WordPress's own page cache test (async, header-based) is taken out and a "
       "direct one under the same key answers from the file the panel writes (/run/panel/page-cache, read-only in "
       "the container); no header is made up",
       ("add_filter( 'site_status_tests', 'lgsm_panel_site_status_tests' );" in php,
        "unset( $tests['async']['page_cache'] );" in test_fn,
        "$tests['direct']['page_cache'] = array( 'label' => __( 'Page cache' ), 'test' => 'lgsm_panel_page_cache_test' );"
        in test_fn, "define( 'LGSM_PANEL_PAGE_CACHE_FILE', '/run/panel/page-cache' );" in php,
        "'status'      => $on ? 'good' : 'recommended'," in php, "header(" in php.replace("wp_remote_retrieve_header(", "")),
       (True, True, True, True, True, False))
    eq("Site Health (the file the plugin reads): one of the files the panel writes for a site, and a new files "
       "revision so installed WordPress sites are offered Update for the new plugin",
       (_ws321.PAGE_CACHE_FILE in _ws321.FILE_NAMES, _ws321.PAGE_CACHE_FILE, _ws321.SITE_FILES_REV),
       (True, "site/conf/panel/page-cache", "files-7"))


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _cleanup321():
    _db321.session.rollback()
    remotes = _ROWS321["remotes"] or [0]
    sites = set(_ROWS321["sites"]) | {s.id for s in _Site321.query.filter(_Site321.remote_id.in_(remotes)).all()}
    from panel.db.models import GameDatabase as _GDB321
    _GDB321.query.filter(_GDB321.remote_id.in_(remotes)).delete(synchronize_session=False)
    for d in _Dom321.query.filter(_Dom321.website_id.in_(sorted(sites) or [0])).all():
        _db321.session.delete(d)
    for model in (_Proxy321, _HDS321):
        for p in model.query.filter(model.remote_id.in_(remotes)).all():
            _db321.session.delete(p)
    for model, ids in ((_Site321, sorted(sites)), (_User321, _ROWS321["users"]), (_Remote321, _ROWS321["remotes"])):
        for i in ids:
            row = _db321.session.get(model, i)
            if row is not None:
                _db321.session.delete(row)
    _db321.session.commit()
    for rid in _ROWS321["remotes"]:
        _dbr321._PROBES.pop(rid, None)


def _ran321(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran321.last)."""
    import traceback
    try:
        step(*args)
        _ran321.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        from flask import has_app_context
        if has_app_context():
            _db321.session.rollback()
        _ran321.last = traceback.format_exc()[-1500:]
        return False


_ran321.last = ""
_trips321 = len(_P9_TRIPPED)
for _sec321 in (_s1_ci, _s4_plugin):
    check("part321: %s ran to the end" % _sec321.__name__, _ran321(_sec321), _ran321.last)
with _p9.app_context():
    try:
        _p9_arm(who="part321")
        _st321 = _rows321()
        for _sec321 in (_s2_tunnel, _s3_db_stopped, _s4_apply):
            check("part321: %s ran to the end" % _sec321.__name__, _ran321(_sec321, _st321), _ran321.last)
        eq("part321: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips321:], [])
    finally:
        _p9_restore_all()
        _w321._STATUS.clear()
        _sw321._PAGE_CACHE_NOTED.clear()
        _cleanup321()
