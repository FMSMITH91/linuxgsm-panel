"""Part 305 of the unit suite: fixes the websites' second proof round on the test host (P2) turned up.

1. PHP versions: the Websites page, a new PHP site and every one-click app get the catalog's supported PHP
   versions (the catalog's `php` section is {version: {image, eol}}), and a new PHP version re-installs the site.
2. The web proxy's installed version is recorded when it is installed and read back from its status.
3. wp-cli's pinned image is pulled before the WordPress step that runs it.
4. A site with a database gets its database's port forwarded into its container, from every install path.
5. An install restarts the site, so a running container takes its rewritten unit.
6. phpBB's install configuration holds no empty value, and an app is installed only for a domain.
7. The finished install's admin address is the recipe's own admin page.
8. Deleting a website drops its databases and their user; one that cannot be dropped stops the delete.
9. PHP sites run an image built on the host from the pinned PHP image with the apps' extensions; CI builds it.
10. Every recipe ends by checking what the installer left (settings file, tables, a page), so a silent failure is
    undone, not recorded as done.
11. No secret reaches argv, an environment, a prompt's echo, the journal or the panel's log: each step's values
    reach its container as 0600 files removed after the step, and step containers never log to the journal.
12. The Security settings card: TLS 1.3 preferred with TLS 1.2 allowed, one style for every note; the site's tab
    strip wraps on a phone; a domain's certificate warning does not repeat its label.

HOW IT RUNS. part12's app and its database for the routes, with the host stand-ins at ssh_manager.websites' own
seams (its helper, the account shell, the account's ids). Sections 3, 10 and 11 run the real step shells in bash
over a scratch home, with stand-in podman and curl on PATH that record their argv, environment and the values
they were handed (as hashes). Nothing reaches a host (part12's tripwire is armed).
"""
import hashlib as _hashlib305
import json as _json305
import logging as _logging305
import os
import re as _re305
import shutil as _shutil305
import subprocess as _sp305  # nosec B404 - bash over the panel's own step shells, in a scratch home
import sys as _sys305
import tempfile as _tf305
from types import SimpleNamespace as _NS305

from flask import g as _g305

from unit.part01 import _root, check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg305
from panel.db.models import (GameDatabase as _GDB305, RemoteServer as _Remote305, User as _User305,
                             Website as _Site305, WebsiteDomain as _Dom305, WebsiteProxy as _Proxy305, db as _db305)
from panel.ops.ssh_manager import _core as _core305
from panel.ops.ssh_manager import websites as _sw305
from panel.routes import _shared as _shared305
from panel.routes import websites as _w305
from panel.routes import websites_apps as _wapps305
from panel.routes import websites_domains as _wd305
from panel.services import websites as _ws305
from panel.services import websites_catalog as _wc305
from panel.services import websites_recipes as _wr305

_TREE305 = _tf305.mkdtemp(prefix="lgsm-unit-p305-")
# The real functions a section stands in for, put back by the next section that needs them.
_REAL305 = {n: getattr(_sw305, n) for n in ("install", "php_apply", "_as_site", "app_install_step", "remove")}
_BIN305 = os.path.join(_TREE305, "bin")
_CALLS305 = os.path.join(_TREE305, "calls.jsonl")
_TOKEN305 = "t" * 40
_ADMIN_PW305 = "Adm1n-" + "q" * 24
_DB_PW305 = "Db-" + "z" * 30
_SECRETS305 = (_ADMIN_PW305, _DB_PW305, _TOKEN305)

# The stand-in tools: each records its argv and environment (one JSON line), and for a container run the files of
# its values folder (name, mode, sha256: never the value) and the folder's mode. curl writes FAKE_PAGE to -o and
# answers 404 to a check that throws the page away (-o /dev/null), else FAKE_CODE; a container whose command
# counts tables exits FAKE_TABLES_RC.
_FAKE305 = r'''
import hashlib, json, os, stat, sys
argv = sys.argv[1:]
tool = os.path.basename(sys.argv[0])
rec = {"tool": tool, "argv": argv, "env": dict(os.environ)}
def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()
rc = 0
if tool == "podman" and argv[:2] == ["image", "exists"]:
    rc = int(os.environ.get("FAKE_IMAGE_EXISTS", "1"))
elif tool == "podman" and argv[:1] == ["run"]:
    for i, a in enumerate(argv):
        if a == "-v" and argv[i + 1].endswith(":/run/panel-values:ro"):
            d = argv[i + 1].rsplit(":", 2)[0]
            rec["values_dir_mode"] = oct(stat.S_IMODE(os.stat(d).st_mode))
            rec["values"] = {n: [oct(stat.S_IMODE(os.stat(os.path.join(d, n)).st_mode)), sha(os.path.join(d, n))]
                             for n in sorted(os.listdir(d))}
    rec["stdin_sha"] = hashlib.sha256(sys.stdin.buffer.read()).hexdigest()
    if any("information_schema" in a for a in argv):
        rc = int(os.environ.get("FAKE_TABLES_RC", "0"))
elif tool == "curl":
    out = argv[argv.index("-o") + 1] if "-o" in argv else None
    rec["fields"] = {}
    for i, a in enumerate(argv):
        if a == "--data-urlencode" and "@" in argv[i + 1].split("=", 1)[0]:
            name, path = argv[i + 1].split("@", 1)
            rec["fields"][name] = sha(path)
    if out and out != "/dev/null":
        with open(out, "w") as fh:
            fh.write(os.environ.get("FAKE_PAGE", ""))
    if "-w" in argv:
        sys.stdout.write("404" if out == "/dev/null" else os.environ.get("FAKE_CODE", "200"))
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps(rec) + "\n")
sys.exit(rc)
'''


def _tools305():
    os.makedirs(_BIN305, exist_ok=True)
    for name in ("podman", "curl", "systemctl"):
        path = os.path.join(_BIN305, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!%s\n%s" % (_sys305.executable, _FAKE305))
        os.chmod(path, 0o755)  # nosec B103 - a scratch stand-in this part runs


def _home305(account):
    return os.path.join(_TREE305, "home", account)


_RUN305 = {"env": {}, "shells": []}


def _bash305(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
    """shell_as_game_user over a scratch home: the panel's shell in real bash, the stand-in tools first on PATH."""
    _RUN305["shells"].append(sh)
    if not sh.startswith(_ws305._ENV):
        return "", "part305: not an account shell", 99
    home = _home305(user)
    text = 'cd "$HOME" || exit 1; ' + sh[len(_ws305._ENV):].replace("/home/%s" % user, home)
    env = dict(os.environ, HOME=home, PATH=_BIN305 + os.pathsep + os.environ.get("PATH", ""), FAKE_CALLS=_CALLS305,
               **_RUN305["env"])
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp305.run(["bash", "-c", text], input=(stdin_text or "").encode(), capture_output=True, timeout=timeout,  # nosec B603 B607
                   env=env, check=False)
    return r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"), r.returncode


def _calls305():
    if not os.path.exists(_CALLS305):
        return []
    with open(_CALLS305, encoding="utf-8") as fh:
        return [_json305.loads(ln) for ln in fh if ln.strip()]


def _reset305(**env):
    if os.path.exists(_CALLS305):
        os.unlink(_CALLS305)
    _RUN305["env"] = {k: str(v) for k, v in env.items()}
    _RUN305["shells"] = []


def _sha305(text):
    return _hashlib305.sha256(text.encode()).hexdigest()


class _Records305(_logging305.Handler):
    def __init__(self):
        super().__init__(level=_logging305.DEBUG)
        self.lines = []

    def emit(self, record):
        try:
            self.lines.append(record.getMessage() + " " + repr(record.args) + " " + str(record.exc_text or ""))
        except Exception:  # noqa: BLE001 - a record that cannot be formatted is kept by its template
            self.lines.append(str(record.msg))


class _Client305:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def get(self, *a, **k):
        _g305.pop("_login_user", None)
        return self.c.get(*a, **k)

    def post(self, *a, **k):
        _g305.pop("_login_user", None)
        return self.c.post(*a, **k)


_ROWS305 = {"sites": [], "remotes": [], "users": [], "dbs": []}


def _rows305():
    r = _Remote305(name="p305-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.75")
    su = _User305(username="p305-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db305.session.add_all([r, su])
    _db305.session.commit()
    _ROWS305["remotes"].append(r.id)
    _ROWS305["users"].append(su.id)
    return _NS305(host=r, su=su)


def _site305(st, name, kind="php", **kw):
    s = _Site305(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg305.encrypt_secret(_TOKEN305), **dict({"php_version": "8.4"}, **kw))
    _db305.session.add(s)
    _db305.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db305.session.add(_Dom305(website_id=s.id, domain="%s.example.org" % name, is_primary=True))
    _db305.session.commit()
    _ROWS305["sites"].append(s.id)
    return s


def _db_row305(site):
    row = _GDB305(remote_id=site.remote_id, website_id=site.id, name="ws%d_app" % site.id, secret="")
    _db305.session.add(row)
    _db305.session.commit()
    _ROWS305["dbs"].append(row.id)
    return row


def _host_seams305():
    """ssh_manager.websites' own seams: Podman ready, the helper answering, the account's ids, its shell recorded.

    Returns the list of (shell, stdin) every account shell got; each answers SITE_INSTALLED / SITE_STARTED.
    """
    seen = []

    def as_site(remote, account, sh, timeout=120, stdin_text=None):
        seen.append((sh, stdin_text or ""))
        return True, "SITE_INSTALLED SITE_STARTED"
    for name in ("install", "php_apply", "remove"):
        _p9_patch(_sw305, name, _REAL305[name])
    _p9_patch(_sw305, "runtime_ready", lambda remote: "")
    _p9_patch(_sw305, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "account=exists"))
    _p9_patch(_sw305, "_ids", lambda remote, site: ((1005, 1005), {"splice": True, "cpu_delegated": True, "os": "24.04",
                                                                   "podman": "podman version 4.9.3"}))
    _p9_patch(_sw305, "_as_site", as_site)
    return seen


def _bundle305(stdin):
    import base64
    out = {}
    for line in stdin.splitlines():
        path, _sep, b64 = line.partition(" ")
        out[path] = base64.b64decode(b64).decode("utf-8", "replace")
    return out


def _quadlet305(seen):
    """The site's Quadlet text from the last install shell's bundle ("" when none was written)."""
    for sh, stdin in reversed(seen):
        if "SITE_INSTALLED" in sh and stdin:
            return _bundle305(stdin).get(".config/containers/systemd/lgsm-site.container", "")
    return ""


# ── 1. PHP versions ─────────────────────────────────────────────────────────────────────────────
def _s1_php_versions(st):
    want = _wc305.php_versions()
    su = _Client305(st.su.id)
    listed = _p9_json(su.get("/api/websites")).get("php_versions")
    eq("PHP versions (GET /api/websites): the catalog's supported versions, read from its {version: {image, eol}} "
       "section (it answered [] and every PHP site failed)", (listed, len(want) >= 2), (want, True))
    seen = _host_seams305()
    _p9_patch(_w305, "start_install", lambda site: _w305._install_worker(_p9, site.id))
    r = su.post("/websites/add", json={"name": "p305-php", "kind": "php", "remote_id": st.host.id})
    site = _db305.session.get(_Site305, _p9_json(r).get("id") or 0)
    _ROWS305["sites"].append(getattr(site, "id", 0))
    got = (r.status_code, getattr(site, "php_version", None), getattr(site, "state", None) if getattr(
        site, "state", None) != "failed" else "failed: %s" % site.state_reason,
           "Image=localhost/lgsm-site-php:%s-" % want[-1] in _quadlet305(seen))
    eq("PHP versions (POST /websites/add): a PHP site made without a version gets the newest offered one, and its "
       "install has an image to run", got, (200, want[-1], "running", True))
    bad = su.post("/websites/add", json={"name": "p305-php9", "kind": "php", "php_version": "9.9", "remote_id": st.host.id})
    eq("PHP versions (POST /websites/add): a version the catalog does not offer is refused (control)",
       bad.status_code, 400)
    _s1_version_change(st, site)


def _s1_version_change(st, site):
    calls = []
    _p9_patch(_sw305, "install", lambda remote, s, db=None: calls.append(("install", s.php_version)) or (True, "ok"))
    _p9_patch(_sw305, "php_apply", lambda remote, s: calls.append(("php_apply", s.php_version)) or (True, "ok"))
    old = _wc305.php_versions()[0]
    su = _Client305(st.su.id)
    r1 = su.post("/websites/%d/php" % site.id, json={"version": old, "settings": {}})
    r2 = su.post("/websites/%d/php" % site.id, json={"settings": {"memory_limit": "256M"}})
    eq("PHP versions (POST /websites/<id>/php): a new PHP version installs the site again (a new image); a settings "
       "change only rewrites its php.ini", (r1.status_code, r2.status_code, calls),
       (200, 200, [("install", old), ("php_apply", old)]))


def _s1_apps(st):
    _p9_patch(_w305, "threading", _NS305(Thread=_Inline305))
    _p9_patch(_wapps305, "_worker", lambda app, sid, uid, secrets: None)
    su = _Client305(st.su.id)
    form = {"app": "phpbb", "name": "p305-bb", "remote_id": st.host.id, "admin_user": "boardowner",
            "admin_email": "owner@example.org", "domain": "p305-bb.example.org"}
    r = su.post("/websites/install-app", json=form)
    site = _db305.session.get(_Site305, _p9_json(r).get("id") or 0)
    _ROWS305["sites"].append(getattr(site, "id", 0))
    offered = [v for v in _wc305.php_versions() if v in _wc305.recipe("phpbb")["php"]]
    eq("PHP versions (POST /websites/install-app): an app's site gets the newest PHP version both the catalog and its "
       "recipe offer, so its image exists (every app failed at its first step)",
       (r.status_code, getattr(site, "php_version", None), bool(site is not None and _ws305.image_for(site))),
       (200, offered[-1], True))


class _Inline305:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)


# ── 2. The proxy's installed version ────────────────────────────────────────────────────────────
def _s2_proxy_version(st):
    su = _Client305(st.su.id)
    _p9_patch(_sw305, "proxy_install", lambda remote: (True, _sw305.OK_PROXY))
    _p9_patch(_sw305, "egress_guard", lambda remote: (True, "guard=on"))
    r = su.post("/websites/proxy/install", json={"host_id": st.host.id})
    row = _Proxy305.query.filter_by(remote_id=st.host.id).first()
    missing = [m.get("key") for m in _p9_json(su.get("/api/websites")).get("missing") or []]
    eq("proxy (POST /websites/proxy/install): the installed version is recorded, so the page stops saying the proxy "
       "is not installed", (r.status_code, getattr(row, "installed_version", None), "proxy" in missing),
       (200, _wc305.pins("caddy")["version"], False))
    _p9_patch(_sw305, "proxy_status", lambda remote: (True, "installed=no\nversion=\nactive=inactive\n"))
    su.get("/websites/proxy/status?host_id=%d" % st.host.id)
    _db305.session.expire_all()
    gone = getattr(_Proxy305.query.filter_by(remote_id=st.host.id).first(), "installed_version", None)
    _p9_patch(_sw305, "proxy_status", lambda remote: (True, "installed=yes\nversion=v2.11.9\nactive=active\n"))
    su.get("/websites/proxy/status?host_id=%d" % st.host.id)
    _db305.session.expire_all()
    back = getattr(_Proxy305.query.filter_by(remote_id=st.host.id).first(), "installed_version", None)
    eq("proxy (GET /websites/proxy/status): the row follows what the host says is installed (a host installed before "
       "this fix included)", (gone, back), ("", "2.11.9"))


# ── 4 and 5. The database forward, and the restart ──────────────────────────────────────────────
def _s4_db_forward(st):
    seen = _host_seams305()
    site = _site305(st, "p305-fwd", kind="wordpress")
    _db_row305(site)
    plain = _site305(st, "p305-nodb", kind="php")
    su = _Client305(st.su.id)
    r = su.post("/websites/%d/update-image" % site.id)
    with_db = _quadlet305(seen)
    del seen[:]
    r2 = su.post("/websites/%d/update-image" % plain.id)
    without = _quadlet305(seen)
    net = [ln for ln in with_db.split("\n") if ln.startswith("Network=")]
    eq("database forward (POST /websites/<id>/update-image): a site with a database gets its port forwarded into the "
       "container; one without gets none (control)",
       (r.status_code, r2.status_code, bool(net) and "-T,3306:3306" in net[0], "3306" in without),
       (200, 200, True, False))
    del seen[:]
    su.post("/websites/%d/settings" % site.id, json={"limits": {"mem_mb": 600}})
    eq("database forward (POST /websites/<id>/settings): a limits change keeps the forward",
       "-T,3306:3306" in _quadlet305(seen), True)
    return seen, site


def _s5_restart(st, seen, site):
    del seen[:]
    su = _Client305(st.su.id)
    su.post("/websites/%d/update-image" % site.id)
    starts = [sh for sh, _i in seen if "SITE_STARTED" in sh]
    del seen[:]
    su.post("/websites/%d/start" % site.id)
    plain = [sh for sh, _i in seen if "SITE_STARTED" in sh]
    eq("restart: an install restarts the site's units, so a running container takes its rewritten unit; the Start "
       "button only starts (control)",
       ([("systemctl --user restart lgsm-site.service" in s) for s in starts],
        [("systemctl --user start lgsm-site.service" in s) for s in plain]), ([True], [True]))


def _s4_apps_forward(st):
    """The app job: the site is installed again with its new database forwarded before the installer steps run."""
    seen = []
    _p9_patch(_sw305, "install", lambda remote, s, db=None: seen.append(db) or (True, "ok"))
    _p9_patch(_sw305, "app_install_step", lambda remote, s, step: (True, "ok"))
    from panel.routes import databases_sites as _ds305

    def fake_create(site, slug):
        return True, "made", _db_row305(site), _DB_PW305
    _p9_patch(_ds305, "create_for", fake_create)
    site = _site305(st, "p305-job", kind="php", app_recipe="phpbb", install_steps_done="[]")
    ok, step, _said, _steps = _wapps305._install(site, {"admin_user": "boardowner", "admin_email": "o@example.org",
                                                        "admin_password": _ADMIN_PW305})
    eq("database forward (the app job): the account is installed first, then again with the new database forwarded",
       (ok, step, seen), (True, "", [None, ("127.0.0.1", 3306)]))


# ── 6. phpBB's configuration and the app's domain ───────────────────────────────────────────────
def _s6_phpbb(st):
    site = _NS305(account="ws5", name="board", kind="php", php_version="8.4", port=20005, pids=256, mem_mb=512,
                  domains=[_NS305(domain="board.example.org", is_primary=True, id=1)], app_recipe="phpbb",
                  proxy_secret=_cfg305.encrypt_secret(_TOKEN305))
    recipe = _wc305.recipe("phpbb")
    step = [s for s in _ws305.recipe_steps(recipe) if s["type"] == "render-config"][0]
    vals = _wr305.values_for(site, db={"name": "ws5_app", "user": "ws5_app", "password": _DB_PW305},
                             admin={"user": "boardowner", "email": "o@example.org", "password": _ADMIN_PW305,
                                    "site_name": "board"}, domains=["board.example.org"])
    _body, text = _wr305.step_sh("ws5", site, step, vals, recipe=recipe, token=_TOKEN305)
    empty = [ln.strip() for ln in text.split("\n") if _re305.search(r':\s*""\s*$', ln)]
    eq("phpBB: its install configuration has no empty value (phpbbcli refuses one: board.description was \"\")",
       (empty, 'description: "board"' in text), ([], True))
    su = _Client305(st.su.id)
    _p9_patch(_wapps305, "_worker", lambda app, sid, uid, secrets: None)
    _p9_patch(_w305, "threading", _NS305(Thread=_Inline305))
    form = {"app": "phpbb", "name": "p305-nodom", "remote_id": st.host.id, "admin_user": "boardowner",
            "admin_email": "owner@example.org"}
    r = su.post("/websites/install-app", json=form)
    taken = su.post("/websites/install-app", json=dict(form, name="p305-taken", domain="p305-fwd.example.org"))
    eq("apps: an install without a domain, or with one already used, is refused and leaves no site (every installer "
       "writes the site's address)", (r.status_code, taken.status_code,
                                      _Site305.query.filter(_Site305.name.in_(["p305-nodom", "p305-taken"])).count()),
       (400, 400, 0))


# ── 7. The admin address ────────────────────────────────────────────────────────────────────────
def _s7_admin_url(st):
    out = {}
    for app in ("phpbb", "wordpress", "smf"):
        site = _site305(st, "p305-adm-%s" % app, kind="wordpress" if app == "wordpress" else "php", app_recipe=app,
                        install_steps_done="[]")
        out[app] = (_p9_json(_Client305(st.su.id).get("/api/websites/%d" % site.id)).get("install") or {}).get("admin_url")
    eq("apps (GET /api/websites/<id>): the admin address is the recipe's own admin page (it was the site's root for "
       "every app but WordPress)",
       out, {"phpbb": "https://p305-adm-phpbb.example.org/adm/", "wordpress": "https://p305-adm-wordpress.example.org/wp-admin/",
             "smf": "https://p305-adm-smf.example.org/index.php"})


# ── 8. Deleting a website ───────────────────────────────────────────────────────────────────────
def _s8_delete(st):
    from panel.routes import databases_sites as _ds305
    dropped, removed = [], []

    def drop(site, row):
        dropped.append(row.name)
        _db305.session.delete(row)
        _db305.session.commit()
        return True, "dropped"
    _p9_patch(_ds305, "drop", drop)
    _p9_patch(_sw305, "remove", lambda remote, s: removed.append(s.id) or (True, _sw305.OK_REMOVED))
    site = _site305(st, "p305-del", kind="php")
    name = _db_row305(site).name
    sid = site.id
    r = _Client305(st.su.id).post("/websites/%d/delete" % sid, json={"confirm": "p305-del"})
    eq("delete (POST /websites/<id>/delete): the site's database and its user are dropped with it, then its account",
       (r.status_code, dropped, removed, _GDB305.query.filter_by(name=name).count(), _db305.session.get(_Site305, sid)),
       (200, [name], [sid], 0, None))
    _p9_patch(_ds305, "drop", lambda site, row: (False, "The database server did not answer."))
    del removed[:]
    keep = _site305(st, "p305-keep", kind="php")
    _db_row305(keep)
    r2 = _Client305(st.su.id).post("/websites/%d/delete" % keep.id, json={"confirm": "p305-keep"})
    _db305.session.expire_all()
    eq("delete: a database that cannot be dropped stops the delete with the site and its account kept, offline",
       (r2.status_code >= 400, removed, getattr(_db305.session.get(_Site305, keep.id), "enabled", None)),
       (True, [], False))


# ── 9. The PHP sites' image ─────────────────────────────────────────────────────────────────────
_CF305 = os.path.join(_root, "panel", "website_images", "php", "Containerfile")


def _s9_php_image(st):
    seen = _host_seams305()
    site = _site305(st, "p305-img", kind="php")
    static = _site305(st, "p305-static", kind="static")
    su = _Client305(st.su.id)
    su.post("/websites/%d/update-image" % site.id)
    sh, stdin = [x for x in seen if "SITE_INSTALLED" in x[0]][-1]
    base = _wc305.php_image("php", "8.4")
    tag = _ws305.php_build_tag("8.4", base)
    with open(_CF305, encoding="utf-8") as fh:
        cf = fh.read()
    eq("PHP image (POST /websites/<id>/update-image): a PHP site's image is built on the host from the catalog's PHP "
       "image (by digest) and the panel's Containerfile, unless it is there; its unit runs that build",
       ("podman image exists %s ||" % tag in sh, "--build-arg BASE_IMAGE=%s" % base in sh,
        _bundle305(stdin).get("site/image/Containerfile") == cf, "Image=%s" % tag in _quadlet305(seen),
        "podman pull -q %s" % base in sh), (True, True, True, True, False))
    del seen[:]
    su.post("/websites/%d/update-image" % static.id)
    sh2 = [x[0] for x in seen if "SITE_INSTALLED" in x[0]][-1]
    eq("PHP image: a static site still pulls its pinned image and builds nothing (control)",
       ("podman pull -q %s" % _wc305.static_image() in sh2, "podman build" in sh2), (True, False))
    exts = _re305.search(r"docker-php-ext-install -j \"\$\{jobs\}\" ([a-z_ ]+)", cf)
    eq("PHP image: the Containerfile adds mysqli, pdo_mysql, gd, intl and zip, takes its base only from the catalog "
       "(no default) and checks every extension loads",
       (sorted((exts.group(1) if exts else "").split()), "ARG BASE_IMAGE\n" in cf, "the PHP extension" in cf),
       (["gd", "intl", "mysqli", "pdo_mysql", "zip"], True, True))
    _s9_ci()


def _s9_ci():
    import importlib.util as _ilu
    spec = _ilu.spec_from_file_location("addon_images_p305", os.path.join(_root, ".github", "scripts", "addon_images.py"))
    ai = _ilu.module_from_spec(spec)
    spec.loader.exec_module(ai)
    p = ai.plan()
    php = {k: v for k, v in p["sites"]["builds"].items() if k.startswith("php@")}
    eq("PHP image (CI): the image scan builds the Containerfile once per PHP version the catalog pins, each from that "
       "version's image, and lints it", (sorted(php), sorted(v[0][1] for v in php.values()), p["problems"],
                                         any(t.endswith(os.path.join("website_images", "php", "Containerfile"))
                                             for _l, t in ai.lint_targets(p))),
       (sorted("php@" + v for v in _wc305.pins("php")),
        sorted(e["image"] for e in _wc305.pins("php").values()), [], True))


# ── the step shells in bash (sections 3, 10, 11) ────────────────────────────────────────────────
def _app_site305(app, kind):
    return _NS305(id=900, account="ws905", name="p305app", kind=kind, php_version="8.4", port=20905, pids=256,
                  mem_mb=512, domains=[_NS305(domain="p305app.example.org", is_primary=True, id=1)], app_recipe=app,
                  proxy_secret=_cfg305.encrypt_secret(_TOKEN305), object_cache=False, full_egress=False)


def _rmtree305(path):
    """Remove `path` whole, folders an install step made read-only included."""
    for top, dirs, _files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(top, d), 0o700)
    _shutil305.rmtree(path, ignore_errors=True)


def _app_home305(site, recipe):
    """A scratch home for `site`: its folders, and the files the earlier steps of `recipe` leave."""
    home = _home305(site.account)
    _rmtree305(home)
    html = os.path.join(home, "site", "html")
    for d in ("install", "sites/default", "inc", "other"):
        os.makedirs(os.path.join(html, d), exist_ok=True)
    for f in ("config.php", "sites/default/settings.php", "inc/config.php", "Settings.php", "wp-config.php"):
        with open(os.path.join(html, f), "w", encoding="utf-8") as fh:
            fh.write("<?php // written by the installer\n")
    return home


_SECRET_STEP305 = {"admin_user": "siteowner", "admin_email": "owner@example.org", "admin_password": _ADMIN_PW305,
                   "db_name": "ws905_app", "db_user": "ws905_app", "db_password": _DB_PW305}
_KINDS305 = {"wordpress": "wordpress", "phpbb": "php", "drupal": "php", "mybb": "php", "smf": "php"}


def _run_app305(app, skip=("download-verify-unpack", "create-database")):
    """Run every step of `app`'s catalog recipe through app_install_step in bash; [(step type, ok, text)]."""
    recipe = _wc305.recipe(app)
    site = _app_site305(app, _KINDS305[app])
    _app_home305(site, recipe)
    page = " ".join(p["expect"] for s in recipe["steps"] for p in s.get("pages", []))
    page += " " + " ".join(s["page"]["expect"] for s in recipe["steps"] if "page" in s)
    _RUN305["env"]["FAKE_PAGE"] = page
    out = []
    for step in _ws305.recipe_steps(recipe):
        if step["type"] in skip:
            continue
        ok, said = _sw305.app_install_step(_NS305(is_local=True), site, dict(step, secrets=dict(_SECRET_STEP305)))
        out.append((step["type"], ok, said))
    return out, site


def _bash_seams305():
    for name in ("_as_site", "app_install_step"):
        _p9_patch(_sw305, name, _REAL305[name])
    _p9_patch(_core305, "shell_as_game_user", _bash305)
    _p9_patch(_core305, "is_local_server", lambda server: True)
    _p9_patch(_shared305, "game_account_write_refusal", lambda remote, account: None)
    _p9_patch(_sw305, "_ids", lambda remote, site: ((os.getuid(), os.getgid()), {"splice": True}))


def _s3_wpcli(st):
    _bash_seams305()
    _reset305()
    steps, _site = _run_app305("wordpress", skip=("download-verify-unpack", "create-database", "render-config",
                                                  "set-permissions", "verify-install"))
    wpcli = _wc305.pins("wpcli")["image"]
    tools = [(c["argv"][:2], wpcli in c["argv"]) for c in _calls305() if c["tool"] == "podman"]
    eq("wp-cli (app_install_step): its pinned image is looked for and pulled by digest before the step runs it (it was "
       "never pulled: `wp core install` always failed); the site-image step pulls nothing (control)",
       ([ok for _t, ok, _s in steps], tools),
       ([True, True], [(["run", "--rm"], False), (["image", "exists"], True), (["pull", "-q"], True),
                       (["run", "--rm"], True)]))


def _s10_verify(st):
    _bash_seams305()
    recipes = {name: _wc305.recipe(name) for name in _KINDS305}
    eq("verify (catalog): each of the five recipes ends with a verify-install step naming its settings file, its "
       "table prefix and a page", {n: (r["steps"][-1]["type"], bool(r["steps"][-1].get("files")), "tables" in r["steps"][-1],
                                       "page" in r["steps"][-1]) for n, r in recipes.items()},
       {n: ("verify-install", True, True, True) for n in recipes})
    bad = dict(recipes["phpbb"], steps=recipes["phpbb"]["steps"][:-1])
    check("verify (catalog): a recipe that does not end with the check is refused",
          any("verify-install" in p for p in _wc305.recipe_problems("phpbb", bad)), repr(_wc305.recipe_problems("phpbb", bad)))
    site = _app_site305("phpbb", "php")
    step = _ws305.recipe_steps(recipes["phpbb"])[-1]
    results = {}
    for label, env, empty in (("good", {}, False), ("empty config", {}, True), ("no tables", {"FAKE_TABLES_RC": 3}, False),
                              ("page redirects", {"FAKE_CODE": 302}, False), ("wrong page", {"FAKE_PAGE": "x"}, False)):
        _reset305(**dict({"FAKE_PAGE": "phpBB"}, **env))
        home = _app_home305(site, recipes["phpbb"])
        if empty:
            open(os.path.join(home, "site", "html", "config.php"), "w").close()
        ok, said = _sw305.app_install_step(_NS305(is_local=True), site, dict(step, secrets=dict(_SECRET_STEP305)))
        results[label] = (ok, said == _ws305.FAIL_MARKS["SITE_VERIFY_FAILED"])
    eq("verify (app_install_step): phpBB's install counts as done only with its config.php not empty, its phpbb_ tables "
       "present and its index answering 200 with its text (phpbbcli exits 0 on an error, and the job said done over "
       "an empty config.php and no tables)",
       results, {"good": (True, False), "empty config": (False, True), "no tables": (False, True),
                 "page redirects": (False, True), "wrong page": (False, True)})


def _s11_run305():
    """Every step of the five recipes through app_install_step in bash: ({app: [ok]}, the panel's log lines)."""
    _bash_seams305()
    rec = _Records305()
    root = _logging305.getLogger()
    root.addHandler(rec)
    try:
        _reset305()
        results = {app: _run_app305(app)[0] for app in _KINDS305}
    finally:
        root.removeHandler(rec)
    return {a: [ok for _t, ok, _s in r] for a, r in results.items()}, rec.lines


def _env_names305(runs):
    """How many `-e NAME` (a value taken from podman's own environment) the container runs were given."""
    return sum(1 for c in runs for i, a in enumerate(c["argv"]) if a == "-e" and "=" not in c["argv"][i + 1])


def _s11_secrets(st):
    oks, lines = _s11_run305()
    calls = _calls305()
    eq("secrets: every step of the five recipes ran (the stand-ins answer as an installed app)",
       oks, {a: [True] * len(r) for a, r in oks.items()})
    blob = _json305.dumps(calls) + "\n".join(_RUN305["shells"]) + "\n".join(lines)
    eq("secrets: neither the admin password, the database password nor the proxy token is in any command's argv or "
       "environment, any shell the host's sudo logs, or any line the panel logged",
       [s[:4] for s in _SECRETS305 if s in blob], [])
    runs = [c for c in calls if c["tool"] == "podman" and c["argv"][:1] == ["run"]]
    eq("secrets: every step container's output stays out of the journal (--log-driver=none), none is handed an "
       "environment variable from podman's own environment, none asks for a prompt",
       ([("--log-driver=none" in c["argv"]) for c in runs].count(False), _env_names305(runs),
        any("--prompt" in a for c in runs for a in c["argv"]), len(runs) >= 6), (0, 0, False, True))
    _s11_wordpress(runs)


def _s11_wordpress(runs):
    prompt = _json305.loads(_json305.dumps(_wc305.recipe("wordpress")))
    prompt["steps"][3]["argv"] = ["wp", "core", "install", "--prompt=admin_password"]
    check("secrets (catalog): a recipe step that asks its command for a prompt is refused (wp-cli echoes the answer)",
          any("prompt" in p for p in _wc305.recipe_problems("wordpress", prompt)), repr(_wc305.recipe_problems("wordpress", prompt)))
    wp = [c for c in runs if _wc305.pins("wpcli")["image"] in c["argv"]]
    got = (wp[-1].get("values") or {}) if wp else {}
    eq("secrets: WordPress's admin password reaches wp-cli as a 0600 file in a 0700 folder (and is set from it), "
       "not on its prompt (wp-cli echoed it into the journal)",
       (got.get("ADMIN_PASSWORD"), wp[-1].get("values_dir_mode") if wp else None),
       (["0o600", _sha305(_ADMIN_PW305)], "0o700"))
    left = [n for n in os.listdir(os.path.join(_home305("ws905"), "site")) if n.startswith(".step.")]
    eq("secrets: each step's values folder is removed when the step ends", left, [])


# ── 12. The page ────────────────────────────────────────────────────────────────────────────────
def _s12_ui(st):
    with open(os.path.join(_root, "panel", "templates", "_website_proxy.html"), encoding="utf-8") as fh:
        card = fh.read()
    box = card[card.index('id="wp-opts"'):card.index("</form>", card.index('id="wp-opts"'))]
    notes = _re305.findall(r'<div id="(wp-[a-z0-9-]+)" class="([^"]+)" hidden>', box)
    eq("Security settings: OWASP's TLS value reads 1.3 preferred with 1.2 allowed for compatibility, and the TLS 1.3 "
       "note is information, not a warning against TLS 1.3",
       ("OWASP: TLS 1.3 preferred; TLS 1.2 allowed for compatibility." in box, "cannot open your sites" in box),
       (True, False))
    eq("Security settings: every note has one style (form-text, amber), none the larger `small` text",
       sorted({c for _i, c in notes}), ["form-text text-warning"])
    with open(os.path.join(_root, "panel", "templates", "website.html"), encoding="utf-8") as fh:
        page = fh.read()
    with open(os.path.join(_root, "panel", "static", "css", "websites.css"), encoding="utf-8") as fh:
        css = fh.read()
    strip = _re305.search(r'<div class="(ws-tabs [^"]+)"', page)
    phone = _re305.search(r"@media \(width <= 767\.98px\) \{\s*\.ws-tabs \{([^}]*)\}", css)
    eq("site tabs: on a phone the strip wraps (no tab cut off behind a scroll bar at 375px)",
       ("flex-nowrap" in (strip.group(1) if strip else "flex-nowrap"), "flex-wrap: wrap" in (phone.group(1) if phone else "")),
       (False, True))
    label = "Test certificate (browsers do not trust it)"
    eq("Domains tab: the certificate warning says what to do and does not repeat its label's \"browsers do not trust\"",
       [("do not trust" in str(w)) for w in (_wd305.S_CERT_STAGING, _wd305.S_CERT_LOCAL)] + [label in _read_common305()],
       [False, False, True])


def _read_common305():
    with open(os.path.join(_root, "panel", "static", "js", "websites_common.js"), encoding="utf-8") as fh:
        return fh.read()


def _drop305(model, ids):
    for i in ids:
        row = _db305.session.get(model, i) if i else None
        if row is not None:
            _db305.session.delete(row)


def _cleanup305():
    _db305.session.rollback()
    _drop305(_GDB305, _ROWS305["dbs"])
    sites = set(_ROWS305["sites"]) | {s.id for s in _Site305.query.filter(
        _Site305.remote_id.in_(_ROWS305["remotes"] or [0])).all()}
    for d in _Dom305.query.filter(_Dom305.website_id.in_(sorted(sites) or [0])).all():
        _db305.session.delete(d)
    for p in _Proxy305.query.filter(_Proxy305.remote_id.in_(_ROWS305["remotes"] or [0])).all():
        _db305.session.delete(p)
    _drop305(_Site305, sorted(sites))
    _drop305(_User305, _ROWS305["users"])
    _drop305(_Remote305, _ROWS305["remotes"])
    _db305.session.commit()
    _rmtree305(_TREE305)


def _ran305(step, st, *extra):
    """Run one section: None when it ran to the end, else the traceback (kept in _ran305.last)."""
    import traceback
    try:
        got = step(st, *extra)
        _ran305.last = ""
        return got
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db305.session.rollback()
        _ran305.last = traceback.format_exc()[-1500:]
        return _ran305


_ran305.last = ""
_tools305()
_trips305 = len(_P9_TRIPPED)
with _p9.app_context():
    _st305 = None
    try:
        _p9_arm(who="part305")
        _p9_patch(_sw305, "ports_apply", lambda *a, **k: (True, _sw305.OK_PORTS))
        _p9_patch(_sw305, "proxy_apply", lambda *a, **k: (True, _sw305.OK_APPLIED))
        _p9_patch(_sw305, "proxy_stop", lambda *a, **k: (True, "stopped"))
        _p9_patch(_sw305, "tunnel_apply", lambda *a, **k: (True, _sw305.OK_TUNNEL))
        _p9_patch(_sw305, "quota_set", lambda *a, **k: (True, _sw305.OK_QUOTA))
        _p9_patch(_sw305, "cpu_limit", lambda *a, **k: (True, "container"))
        _st305 = _rows305()
        for _sec305 in (_s1_php_versions, _s1_apps, _s2_proxy_version):
            check("part305: %s ran to the end" % _sec305.__name__, _ran305(_sec305, _st305) is not _ran305, _ran305.last)
        _got305 = _ran305(_s4_db_forward, _st305)
        check("part305: _s4_db_forward ran to the end", _got305 is not _ran305, _ran305.last)
        if _got305 is not _ran305:
            check("part305: _s5_restart ran to the end", _ran305(_s5_restart, _st305, *_got305) is not _ran305, _ran305.last)
        for _sec305 in (_s4_apps_forward, _s6_phpbb, _s7_admin_url, _s8_delete, _s9_php_image, _s3_wpcli, _s10_verify,
                        _s11_secrets, _s12_ui):
            check("part305: %s ran to the end" % _sec305.__name__, _ran305(_sec305, _st305) is not _ran305, _ran305.last)
        eq("part305: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips305:], [])
    finally:
        _p9_restore_all()
        _w305._STATUS.clear()
        _wapps305._JOBS.clear()
        _cleanup305()
