"""Part 315 of the unit suite: the websites' journeys (install, app, database, add dialog, delete) and a clean
WordPress Site Health on a fresh install.

B2  An app install that failed and undid every step: its site is gone, so the dialog reads the job's outcome
    (GET /websites/install-app/status?id=<id>, the starter only) and says it failed, why, and that nothing was left,
    with Try again (the form back as filled in); never "Done." and a link to a page that is not there.
B3  Retry on a failed site installs it again (account, files, image, units) and starts it: a start alone could
    never recover a first install that removed the account. An app whose install stopped part-way is refused
    there, and its page offers Delete and add again (administrators) instead of a Retry that cannot work.

C9  Delete is refused while the site's install (a plain install's thread, or an app install's job) runs, plainly:
    it would remove the account the install still runs as.

P8  The delete confirmation says the site's databases are dropped too, and that a copy of each is kept on the host
    for 30 days (the database archive's retention).

B5  The first database made on a site's Database tab is reachable at once: the site is installed again with the
    database server's port forwarded (a running site restarted, a stopped one from its next start); a later
    database is on the same server, so nothing is reinstalled.

M7  The add dialog's "the web proxy is not installed yet: sites can be made, but none can go online" is a note
    (blocking: false): Create stays available beside it, as the sentence says and as the server allows. An entry
    that concerns only some kinds of site (kinds) shows, and blocks, only for those.

C4  A host with no database server: an app install is refused BEFORE anything is made (the host probed when the
    Databases code knows nothing), its answer carrying the add dialog's entry with the button that sets databases
    up (a superadmin); the list's missing entries carry it once known, for app installs only; the Database tab's
    refusal offers the same button.

C5  The add dialog lists only the hosts that run websites (the panel's own host, today), and an add naming any
    other host is refused before its row is made (it failed at once and led to the failed-site dead end). The
    web proxy card's Install acts on the card's host, the dialog's note on the dialog's host.

B10 An administrator below a superadmin has no host that runs websites (the panel's own host is a superadmin's),
    so Add a website is not offered to them (every Create failed for want of a host): the list says why instead.

M2  Customers' site limits are true: Add a customer grants "add their own websites" (CREATE_WEBSITES) only when its
    switch is on, with the limit the card sends, else the superadmin's Sites per customer setting (read nowhere
    before); a group that may not add sites is held to the sites it is given, and its customers see no quota line.

WP1 WordPress's requests to its own address (Site Health's REST API and loopback tests) reach its own server: a
    must-use plugin, written into the site's files at every install by a writer that refuses links, sends them
    to the container's own listener with the site's name, the scheme and the proxy token, read from a 0600 file
    in a read-only folder mounted at /run/panel (never on a command line, in a log or in the plugin). No new way
    out: the request never leaves the container.

C1  A plain, PHP or Node.js site being added shows its setup's steps as an app install does (the account, the
    image built or downloaded, the container started), from the install's own progress: the dialog showed a heading
    over nothing for minutes while a PHP image was built.

C2  A new Node.js app that waits for its files says so under its header, with the way to upload them, and its main
    button builds and starts it (it showed Stopped and a Start that could only fail).

WP3 The egress proxy (WordPress's only way to WordPress.org): each validated address is tried in turn, bytes
    sent after the CONNECT head are passed on, every refusal and failed connection is a line in its journal (the
    host and the reason only), a thread it cannot start costs one connection and not the proxy, and its unit's
    task limit fits its connection cap.

B4  The object cache is usable: while it is on, its password is a 0600 file in the site's /run/panel folder
    (present and gone with the switch, with no restart), the WordPress recipe's wp-config defines the Redis Object
    Cache plugin's WP_REDIS_* constants from it, and the Performance tab shows the address, the plugin to install,
    and Show connection settings (step-up, audited, no-store) for other code.

HOW IT RUNS. part12's app and its database for the routes, every host call at ssh_manager.websites' seams;
the scripts run in node over the real rendered pages (part301's harness). Nothing reaches a host (part12's
tripwire is armed).
"""
import json as _json315
import os
import shutil as _shutil315
import subprocess as _sp315  # nosec B404 - bash over the panel's own account shells, in a scratch home
import sys as _sys315
import tempfile as _tf315
from types import SimpleNamespace as _NS315

from flask import g as _g315

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg315
from panel.db.models import (RemoteServer as _Remote315, User as _User315, Website as _Site315,
                             WebsiteDomain as _Dom315, WebsiteProxy as _Proxy315, db as _db315)
from panel.ops.ssh_manager import websites as _sw315
from panel.services import websites as _ws315
from panel.routes import websites as _w315
from panel.routes import websites_apps as _wapps315

_TOKEN315 = "q" * 40
_ROWS315 = {"sites": [], "remotes": [], "users": []}
_REAL315 = {"_worker": _wapps315._worker}


class _Client315:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g315.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g315.pop("_login_user", None)
        return self.c.get(*a, **k)


class _Inline315:
    """threading.Thread that runs its target at start(), in the caller's thread."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)


# ── real bash over a scratch home (part311's pattern) ─────────────────────────────────────────────
_TREE315 = _tf315.mkdtemp(prefix="lgsm-unit-p315-")
_BIN315 = os.path.join(_TREE315, "bin")
_CALLS315 = os.path.join(_TREE315, "calls.jsonl")
_REAL315.update({n: getattr(_sw315, n) for n in ("install", "remove", "start", "stop")})
# Stand-in podman and systemctl: each records its argv (one JSON line) and succeeds.
_FAKE315 = r"""
import json, os, sys
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps({"tool": os.path.basename(sys.argv[0]), "argv": sys.argv[1:]}) + "\n")
if os.path.basename(sys.argv[0]) == "systemctl" and "show" in sys.argv:
    sys.stdout.write("active\n")
"""


def _tools315():
    os.makedirs(_BIN315, exist_ok=True)
    for name in ("podman", "systemctl", "journalctl"):
        path = os.path.join(_BIN315, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!%s\n%s" % (_sys315.executable, _FAKE315))
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
        os.chmod(path, 0o700)


def _home315(account):
    return os.path.join(_TREE315, "home", account)


_RUN315 = {"shells": [], "stdin": []}


def _as_site315(remote, account, sh, timeout=120, stdin_text=None):
    """ssh_manager.websites._as_site over a scratch home: the panel's account shell in real bash."""
    _RUN315["shells"].append(sh)
    _RUN315["stdin"].append(stdin_text or "")
    if not sh.startswith(_ws315._ENV):
        return False, "part315: not an account shell"
    home = _home315(account)
    os.makedirs(home, exist_ok=True)
    text = 'cd "$HOME" || exit 1; ' + sh[len(_ws315._ENV):].replace("/home/%s" % account, home)
    env = dict(os.environ, HOME=home, PATH=_BIN315 + os.pathsep + os.environ.get("PATH", ""), FAKE_CALLS=_CALLS315)
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp315.run(["bash", "-c", text], input=(stdin_text or "").encode(), capture_output=True, timeout=120,  # nosec B603 B607
                   env=env, check=False)
    return r.returncode == 0, r.stdout.decode("utf-8", "replace")


def _calls315(tool=None):
    if not os.path.exists(_CALLS315):
        return []
    with open(_CALLS315, encoding="utf-8") as fh:
        got = [_json315.loads(ln) for ln in fh if ln.strip()]
    return [c["argv"] for c in got if tool is None or c["tool"] == tool]


def _reset315():
    if os.path.exists(_CALLS315):
        os.unlink(_CALLS315)
    _RUN315["shells"], _RUN315["stdin"] = [], []


def _read315(account, rel):
    path = os.path.join(_home315(account), rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _mode315(account, rel):
    path = os.path.join(_home315(account), rel)
    return oct(os.stat(path).st_mode & 0o777) if os.path.exists(path) else None


def _seams315():
    """The host's answers at ssh_manager.websites' own seams; every account shell runs in bash (_as_site315)."""
    for name in ("install", "remove", "start", "stop"):
        _p9_patch(_sw315, name, _REAL315[name])
    _p9_patch(_sw315, "runtime_ready", lambda remote: "")
    _p9_patch(_sw315, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "account=exists"))
    _p9_patch(_sw315, "_ids", lambda remote, site: ((1005, 1005), {"splice": True, "cpu_delegated": True, "os": "24.04",
                                                                   "podman": "podman version 4.9.3"}))
    _p9_patch(_sw315, "_as_site", _as_site315)
    _p9_patch(_sw315, "quota_set", lambda *a, **k: (True, _sw315.OK_QUOTA))
    _p9_patch(_sw315, "cpu_limit", lambda *a, **k: (True, "container"))


def _quadlet315(account):
    return _read315(account, ".config/containers/systemd/lgsm-site.container") or ""


def _user315(name, superadmin=False):
    u = _User315(username=name, password_hash=os.urandom(8).hex(), is_superadmin=superadmin, is_active=True)
    _db315.session.add(u)
    _db315.session.commit()
    _ROWS315["users"].append(u.id)
    return u


def _rows315():
    r = _Remote315(name="p315-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.88")
    _db315.session.add(r)
    _db315.session.commit()
    _ROWS315["remotes"].append(r.id)
    return _NS315(host=r, su=_user315("p315-super", True), su2=_user315("p315-super2", True))


def _site315(st, name, kind="php", **kw):
    extra = {"php_version": "8.4"} if kind in ("php", "wordpress", "phpbb") else {}
    s = _Site315(remote_id=st.host.id, name=name, kind=kind, proxy_secret=_cfg315.encrypt_secret(_TOKEN315),
                 **dict(dict(extra, state="running"), **kw))
    _db315.session.add(s)
    _db315.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db315.session.add(_Dom315(website_id=s.id, domain="%s.example.org" % name, is_primary=True))
    _db315.session.commit()
    _ROWS315["sites"].append(s.id)
    return s


def _node315(page, scripts, scenario, routes):
    """part301's node harness over `page` (imported here: part301 renders the pages it runs over)."""
    from unit.part301 import _node301
    got = _node301(page, scripts, scenario, routes=routes)
    check("node: the %s harness ran" % scripts[-1], isinstance(got, dict) and "error" not in got,
          got.get("error") if isinstance(got, dict) else repr(got))
    return got if isinstance(got, dict) else {}


def _list_page315():
    from unit.part12 import P9_ADMIN
    from unit.part301 import _page301
    return _page301("websites.html", P9_ADMIN, can_add=True, site_admin=True)


_LIST315 = {"success": True, "sites": [], "missing": [], "php_versions": ["8.4"], "runtimes": {"node": ["24"]},
            "hosts": [{"id": 1, "name": "h"}], "apps": [{"key": "wordpress", "name": "WordPress", "version": "7.1.5"}],
            "customers": []}


# ── B2. A failed app install that undid every step ────────────────────────────────────────────────
def _no_db_check315(state="unknown"):
    """The Databases code's answer for the host (part315's C4 asks it before an app install)."""
    from panel.routes import databases as _dbr315
    _p9_patch(_dbr315, "host_state", lambda remote, may_probe=False: (state, None, {}))


def _b2_job(st):
    """POST /websites/install-app whose first step fails; its job runs in this thread. -> (response, site id)."""
    _no_db_check315()
    _p9_patch(_w315, "threading", _NS315(Thread=_Inline315))
    _p9_patch(_wapps315, "_worker", _REAL315["_worker"])
    _p9_patch(_sw315, "install", lambda remote, site, db=None, *a, **k: (False, "The host refused the account."))
    _p9_patch(_sw315, "remove", lambda remote, site: (True, _sw315.OK_REMOVED))
    form = {"app": "wordpress", "name": "p315-wp", "remote_id": st.host.id, "admin_user": "siteowner",
            "admin_email": "owner@example.org", "domain": "p315-wp.example.org"}
    r = _Client315(st.su.id).post("/websites/install-app", json=form)
    sid = _p9_json(r).get("id") or 0
    _ROWS315["sites"].append(sid)
    return r, sid


def _b2_failed_undone(st):
    r, sid = _b2_job(st)
    _db315.session.expire_all()
    su, other = _Client315(st.su.id), _Client315(st.su2.id)
    page = su.get("/api/websites/%d" % sid)
    mine = su.get("/websites/install-app/status?id=%d" % sid)
    theirs = other.get("/websites/install-app/status?id=%d" % sid)
    got = _p9_json(mine).get("install") or {}
    eq("B2 (POST /websites/install-app, the first step fails and every step is undone): the site is gone (its page "
       "answers 404), and GET /websites/install-app/status tells the user who started it that the install failed, "
       "why, and that nothing is left", (r.status_code, _db315.session.get(_Site315, sid) is None, page.status_code,
                                        mine.status_code, got.get("state"), got.get("gone"),
                                        "The host refused the account." in (got.get("error") or ""),
                                        [s.get("state") for s in got.get("steps") or []][:1]),
       (200, True, 404, 200, "failed", True, True, ["failed"]))
    eq("B2 control (another superadmin, and an id with no job): the outcome is the starter's only, 404 as for no job "
       "(the same answer, so no oracle for which installs ran)",
       (theirs.status_code, su.get("/websites/install-app/status?id=%d" % (sid + 100000)).status_code), (404, 404))
    _b2_dialog()


def _b2_dialog():
    scenario = r"""
      window.wsOpenAdd();
      $('ws-kind-install').checked = true; window.wsKind('install'); window.wsPickApp('wordpress');
      $('ws-add-name').value = 'blog'; $('ws-add-domain').value = 'blog.example.org';
      $('ws-add-admin-user').value = 'boss'; $('ws-add-admin-email').value = 'boss@example.org';
      $('ws-add-admin-pass').value = 'typed-but-never-kept-1';
      window.wsAddSubmit({preventDefault: function () {}});
      for (let i = 0; i < 12; i++) await tick();
      const res = $('ws-result');
      const links = res.querySelectorAll('a').map(function (a) { return a.href; });
      const again = res.querySelector('button');
      const before = {text: res.textContent, links: links, again: again ? again.getAttribute('data-action') : null,
                      formHidden: $('ws-add-form').hidden};
      if (again) window.wsAddAgain();
      return {before: before, formShown: !$('ws-add-form').hidden, footerShown: !$('ws-add-footer').hidden,
              progressHidden: $('ws-progress-wrap').hidden, name: $('ws-add-name').value, pass: $('ws-add-admin-pass').value,
              asked: calls.map(function (c) { return c[1]; }).filter(function (u) { return u.indexOf('install-app/status') >= 0; })};
    """
    routes = {"/api/websites": _LIST315, "/websites/install-app": {"success": True, "id": 5, "password": ""},
              "/api/websites/5": {"success": False, "message": "Not found"},
              "/websites/install-app/status": {"success": True, "install": {
                  "state": "failed", "error": "The download did not match. Every step was undone.", "gone": True,
                  "steps": [{"key": "account", "state": "undone"}, {"key": "download", "state": "failed"}]}}}
    got = _node315(_list_page315(), ["websites_common.js", "websites.js"], scenario, routes)
    before = got.get("before") or {}
    eq("B2 (the add dialog, js/websites.js): a site that is gone after its install is read from the job: the dialog "
       "says the install failed, nothing was left, and why, offers Try again, and links nowhere (it said \"Done.\" "
       "and linked to a 404)",
       (got.get("asked"), "The install failed, and nothing of it was left on the host." in (before.get("text") or ""),
        "The download did not match." in (before.get("text") or ""), "Done." in (before.get("text") or ""),
        before.get("links"), before.get("again")),
       (["/m/websites/install-app/status?id=5"], True, True, False, [], "wsAddAgain"))
    eq("B2 (Try again): the form comes back as it was filled in, the typed password not kept",
       (got.get("formShown"), got.get("footerShown"), got.get("progressHidden"), got.get("name"), got.get("pass")),
       (True, True, True, "blog", ""))


# ── B3. Retry on a failed site ────────────────────────────────────────────────────────────────────
def _b3_retry(st):
    calls = []
    _p9_patch(_sw315, "install", lambda remote, site, db=None, *a, **k: calls.append(("install", site.id))
              or (True, _sw315.OK_STARTED))
    _p9_patch(_sw315, "start", lambda remote, site, *a, **k: calls.append(("start", site.id)) or (True, _sw315.OK_STARTED))
    su = _Client315(st.su.id)
    failed = _site315(st, "p315-failed", kind="php", state="failed", state_reason="The host refused the account.")
    r = su.post("/websites/%d/start" % failed.id)
    _db315.session.expire_all()
    row = _db315.session.get(_Site315, failed.id)
    eq("B3 (POST /websites/<id>/start on a failed site, its page's Retry): the site is installed again (account, "
       "files, image and units, then started), not only started, and it runs again",
       (r.status_code, calls, row.state, row.state_reason), (200, [("install", failed.id)], "running", ""))
    stopped = _site315(st, "p315-stopped", kind="php", state="stopped")
    del calls[:]
    r = su.post("/websites/%d/start" % stopped.id)
    eq("B3 control (a stopped site's Start): only started, as before", (r.status_code, calls),
       (200, [("start", stopped.id)]))
    app = _site315(st, "p315-cut", kind="wordpress", app_recipe="wordpress", state="failed",
                   install_step="verify-install-6", install_steps_done="[]")
    del calls[:]
    r = su.post("/websites/%d/start" % app.id)
    eq("B3 (an app whose install stopped part-way): refused with the sentence saying to delete it and add it again, "
       "nothing run on the host", (r.status_code, (_p9_json(r).get("message") or ""), calls),
       (409, _w315.S_RETRY_APP, []))
    _b3_page()


def _b3_site_answer(**site):
    base = {"id": 7, "name": "shop", "kind": "wordpress", "state": "failed", "state_reason": "It failed.", "enabled": False,
            "setup_unfinished": False}
    return {"success": True, "site": dict(base, **site), "install": {"state": "", "steps": []}, "domains": [],
            "dns": {}, "logs": [], "can": {"manage": True, "files": True, "admin": True}}


def _site_page315(admin=True):
    from unit.part12 import P9_ADMIN
    from unit.part301 import _page301
    site = _NS315(id=7, name="shop", kind="wordpress")
    return _page301("website.html", P9_ADMIN, site=site, can_manage=True, can_files=True, site_admin=admin)


def _b3_page():
    scenario = r"""
      return {label: $('ws-main-label').textContent, verb: $('ws-main').getAttribute('data-verb'),
              disabled: $('ws-main').disabled, retryShown: !$('ws-failed-retry').hidden};
    """
    scripts = ["websites_common.js", "website_site.js"]
    cut = _node315(_site_page315(), scripts, scenario, {"/api/websites/7": _b3_site_answer(setup_unfinished=True)})
    ask = _node315(_site_page315(admin=False), scripts, scenario,
                   {"/api/websites/7": _b3_site_answer(setup_unfinished=True)})
    plain = _node315(_site_page315(), scripts, scenario, {"/api/websites/7": _b3_site_answer()})
    eq("B3 (the site page, js/website_site.js): an app whose install stopped part-way offers an administrator Delete "
       "and add again, and hides the alert's Retry (it could never work)",
       (cut.get("label"), cut.get("verb"), cut.get("disabled"), cut.get("retryShown")),
       ("Delete and add again", "delete", False, False))
    eq("B3 (...anyone else): told to ask an administrator, with nothing to press",
       (ask.get("label"), ask.get("disabled")), ("Ask an administrator to delete it", True))
    eq("B3 control (any other failed site): Retry, which installs it again", (plain.get("label"), plain.get("verb"),
                                                                              plain.get("retryShown")),
       ("Retry", "start", True))


# ── C9. Delete while the site is being set up ─────────────────────────────────────────────────────
def _c9_delete_busy(st):
    removed = []
    _p9_patch(_sw315, "remove", lambda remote, site: removed.append(site.id) or (True, _sw315.OK_REMOVED))
    su = _Client315(st.su.id)
    plain = _site315(st, "p315-busy", kind="php", state="creating")
    app = _site315(st, "p315-busyapp", kind="wordpress", app_recipe="wordpress", state="creating")
    _w315._INSTALLING.add(plain.id)
    _wapps315._job(app.id, state="running", step="render-config-2")
    try:
        r1 = su.post("/websites/%d/delete" % plain.id, json={"confirm": plain.name})
        r2 = su.post("/websites/%d/delete" % app.id, json={"confirm": app.name})
    finally:
        _w315._INSTALLING.discard(plain.id)
        _wapps315._JOBS.pop(app.id, None)
    _db315.session.expire_all()
    eq("C9 (POST /websites/<id>/delete while its install thread or app job runs): refused, saying to wait until "
       "setup finishes or fails; nothing removed, both rows kept",
       (r1.status_code, r2.status_code, _p9_json(r1).get("message"), removed,
        _db315.session.get(_Site315, plain.id) is not None, _db315.session.get(_Site315, app.id) is not None),
       (409, 409, _w315.S_BUSY, [], True, True))
    r3 = su.post("/websites/%d/delete" % plain.id, json={"confirm": plain.name})
    eq("C9 control (the same site once its install ended): deleted", (r3.status_code, removed), (200, [plain.id]))


# ── P8. The delete confirmation ───────────────────────────────────────────────────────────────────
def _p8_delete_text(st):
    got = _node315(_site_page315(), ["websites_common.js", "website_site.js"], r"""
      window.wsDelete();
      return {body: dialogs.length ? dialogs[0].bodyText : '', need: dialogs.length ? dialogs[0].requireText : ''};
    """, {"/api/websites/7": _b3_site_answer(state="running")})
    body = got.get("body") or ""
    eq("P8 (Delete website's confirmation, js/website_site.js): it says the databases are removed too and that a "
       "copy of each is kept on the host for 30 days; the name is still typed to confirm",
       ("databases" in body, "kept on the host for 30 days" in body, got.get("need")), (True, True, "shop"))


# ── B5. A database made on the Database tab ───────────────────────────────────────────────────────
def _b5_create_for(site, slug):
    from panel.db.models import GameDatabase
    row = GameDatabase(remote_id=site.remote_id, website_id=site.id, name="ws%d_%s" % (site.id, slug), secret="")
    _db315.session.add(row)
    _db315.session.commit()
    return True, "", row, "Db-" + "y" * 30


def _b5_database(st):
    from panel.routes import databases_sites as _ds315
    calls = []
    _p9_patch(_ds315, "create_for", _b5_create_for)
    _p9_patch(_sw315, "install", lambda remote, site, db=None, start_it=True, restart=True: calls.append(
        (site.name, db, start_it)) or (True, _sw315.OK_STARTED))
    su = _Client315(st.su.id)
    run = _site315(st, "p315-db", kind="php")
    r1 = su.post("/websites/%d/databases/add" % run.id, json={"name": "shop"})
    r2 = su.post("/websites/%d/databases/add" % run.id, json={"name": "logs"})
    eq("B5 (POST /websites/<id>/databases/add, a running site's first database): the site is installed again with "
       "the database server's port forwarded and restarted, and the answer says so (its code reached nothing until "
       "a reinstall)", (r1.status_code, _p9_json(r1).get("message"), calls[:1]),
       (200, "Database added. The website was restarted so it can reach it.", [("p315-db", ("127.0.0.1", 3306), True)]))
    eq("B5 control (its second database: the same server, already forwarded): nothing reinstalled",
       (r2.status_code, _p9_json(r2).get("message"), len(calls)), (200, "Database added.", 1))
    stopped = _site315(st, "p315-dbstop", kind="php", state="stopped")
    r3 = su.post("/websites/%d/databases/add" % stopped.id, json={"name": "shop"})
    eq("B5 (a stopped site's first database): its units are written with the forward and nothing is started",
       (r3.status_code, _p9_json(r3).get("message"), calls[1:]),
       (200, "Database added. The website reaches it from its next start.", [("p315-dbstop", ("127.0.0.1", 3306), False)]))
    _b5_cleanup([run.id, stopped.id])


def _b5_cleanup(site_ids):
    from panel.db.models import GameDatabase
    for row in GameDatabase.query.filter(GameDatabase.website_id.in_(site_ids)).all():
        _db315.session.delete(row)
    _db315.session.commit()


# ── M7. The missing-proxy note and Create ─────────────────────────────────────────────────────────
def _m7_note(st):
    installed = _Proxy315.query.filter(_Proxy315.installed_version != "").all()
    kept = [(p, p.installed_version) for p in installed]
    for p in installed:
        p.installed_version = ""
    _db315.session.commit()
    try:
        got = _p9_json(_Client315(st.su.id).get("/api/websites")).get("missing") or []
    finally:
        for p, v in kept:
            p.installed_version = v
        _db315.session.commit()
    eq("M7 (GET /api/websites, no web proxy installed): the note says sites can be made and does not block Create",
       [(m.get("key"), m.get("blocking")) for m in got if m.get("key") == "proxy"], [("proxy", False)])
    note = {"key": "proxy", "text": "The web proxy is not installed yet: sites can be made, but none can go online.",
            "fix_url": "/websites#proxy", "blocking": False}
    only = {"key": "database", "text": "No database server.", "kinds": ["install"]}
    got = _node315(_list_page315(), ["websites_common.js", "websites.js"], r"""
      window.wsOpenAdd();
      const a = {shown: !$('ws-missing').hidden, disabled: $('ws-add-create').disabled, msg: $('ws-add-msg').textContent,
                 fix: $('ws-missing-fix').textContent.trim()};
      return a;
    """, {"/api/websites": dict(_LIST315, missing=[note])})
    eq("M7 (the add dialog, js/websites.js): the missing-proxy line shows with its Install button, and Create stays "
       "available with no \"available once this is fixed\" beside it (the line said sites can be made)",
       (got.get("shown"), got.get("disabled"), got.get("msg"), got.get("fix")), (True, False, "", "Install the web proxy"))
    kinds = _node315(_list_page315(), ["websites_common.js", "websites.js"], r"""
      window.wsOpenAdd();
      const plain = {shown: !$('ws-missing').hidden, disabled: $('ws-add-create').disabled};
      $('ws-kind-install').checked = true; window.wsKind('install');
      return {plain: plain, app: {shown: !$('ws-missing').hidden, disabled: $('ws-add-create').disabled,
                                  text: $('ws-missing-text').textContent}};
    """, {"/api/websites": dict(_LIST315, missing=[only])})
    eq("M7 control (an entry for app installs only): a plain site is not held back by it; choosing Install an app "
       "shows it and makes Create unavailable", (kinds.get("plain"), kinds.get("app")),
       ({"shown": False, "disabled": False}, {"shown": True, "disabled": True, "text": "No database server."}))


# ── C4. No database server on the host ────────────────────────────────────────────────────────────
def _c4_form(name):
    return {"app": "wordpress", "name": name, "remote_id": None, "admin_user": "siteowner",
            "admin_email": "owner@example.org", "domain": "%s.example.org" % name}


def _c4_no_db(st):
    from panel.routes import databases as _dbr315
    asked = []
    _p9_patch(_dbr315, "host_state", lambda remote, may_probe=False: asked.append(may_probe) or ("none", None, {}))
    _p9_patch(_w315, "start_install", lambda site: None)
    su = _Client315(st.su.id)
    form = dict(_c4_form("p315-nodb"), remote_id=st.host.id)
    r = su.post("/websites/install-app", json=form)
    body = _p9_json(r)
    made = _Site315.query.filter_by(remote_id=st.host.id, name="p315-nodb").first()
    eq("C4 (POST /websites/install-app on a host with no database server): refused before anything is made (no site "
       "row, no account), the host asked when nothing was known, and the answer carries the dialog's entry with the "
       "host to set databases up on",
       (r.status_code, body.get("message"), made is None, asked[-1:], [(m.get("key"), m.get("kinds"), m.get("host_id"))
                                                                      for m in body.get("missing") or []]),
       (409, _view315().S_NO_DB, True, [True], [("database", ["install"], st.host.id)]))
    lst = _p9_json(su.get("/api/websites")).get("missing") or []
    eq("C4 (GET /api/websites): the list's missing entries say so too, for app installs only, from what is known (no "
       "probe on a list read)", ([(m.get("key"), m.get("kinds")) for m in lst if m.get("key") == "database"], asked[-1:]),
       ([("database", ["install"])], [False]))
    plain = su.post("/websites/add", json={"name": "p315-plain-nodb", "kind": "static", "host_id": st.host.id})
    eq("C4 control (a plain site on the same host): made as before, a database is no business of it",
       (plain.status_code, _p9_json(plain).get("success")), (200, True))
    _no_db_check315("ready")
    _p9_patch(_wapps315, "_worker", lambda app, sid, uid, secrets: None)
    _p9_patch(_w315, "threading", _NS315(Thread=_Inline315))
    ready = su.post("/websites/install-app", json=dict(form, name="p315-withdb", domain="p315-withdb.example.org"))
    _ROWS315["sites"].append(_p9_json(ready).get("id") or 0)
    eq("C4 control (a host whose database server is ready): the install starts", (ready.status_code,
                                                                                  bool(_p9_json(ready).get("id"))),
       (200, True))
    _c4_tab(st)
    _c4_dialog(st)


def _view315():
    from panel.routes import websites_view
    return websites_view


def _c4_tab(st):
    from panel.routes import databases_sites as _ds315
    _no_db_check315("none")
    _p9_patch(_ds315, "create_for", lambda site, slug: (False, "This host has no database server.", None, ""))
    site = _site315(st, "p315-tabnodb", kind="php")
    r = _Client315(st.su.id).post("/websites/%d/databases/add" % site.id, json={"name": "shop"})
    eq("C4 (POST /websites/<id>/databases/add, no database server): the refusal carries the entry for the button that "
       "sets databases up", (r.status_code, [m.get("key") for m in _p9_json(r).get("missing") or []]), (502, ["database"]))
    got = _node315(_site_page315(), ["websites_common.js", "website_site.js"], r"""
      $('wdb-name').value = 'shop'; window.wsDbAdd({preventDefault: function () {}});
      for (let i = 0; i < 6; i++) await tick();
      const b = $('wdb-msg').querySelector('button');
      if (b) window.wsDbSetupHost(JSON.parse(b.getAttribute('data-args'))[0]);
      for (let i = 0; i < 6; i++) await tick();
      return {action: b ? b.getAttribute('data-action') : null, posts: calls.filter(function (c) { return c[0] === 'POST'; })
              .map(function (c) { return c[1]; })};
    """, {"/api/websites/7": _b3_site_answer(state="running"),
          "/websites/7/databases/add": {"success": False, "message": "No server.", "missing": [
              {"key": "database", "host_id": 4, "kinds": ["install"]}]},
          "/api/remote/4/databases/setup": {"success": True, "message": "Setting up databases on this host."}})
    eq("C4 (the Database tab, js/website_site.js): a superadmin gets Set up databases beside the refusal, and it "
       "starts the host's database setup", (got.get("action"), got.get("posts")),
       ("wsDbSetupHost", ["/m/websites/7/databases/add", "/m/api/remote/4/databases/setup"]))


def _c4_dialog(st):
    entry = {"key": "database", "text": "No database server yet.", "kinds": ["install"], "host_id": 4, "fix_url": ""}
    got = _node315(_list_page315(), ["websites_common.js", "websites.js"], r"""
      window.wsOpenAdd();
      $('ws-kind-install').checked = true; window.wsKind('install'); window.wsPickApp('wordpress');
      $('ws-add-name').value = 'blog'; $('ws-add-domain').value = 'blog.example.org';
      $('ws-add-admin-user').value = 'boss'; $('ws-add-admin-email').value = 'boss@example.org';
      const before = !$('ws-missing').hidden;
      window.wsAddSubmit({preventDefault: function () {}});
      for (let i = 0; i < 6; i++) await tick();
      const b = $('ws-missing-fix').querySelector('button');
      const after = {shown: !$('ws-missing').hidden, text: $('ws-missing-text').textContent,
                     action: b ? b.getAttribute('data-action') : null, disabled: $('ws-add-create').disabled};
      if (b) window.wsDbSetup(JSON.parse(b.getAttribute('data-args'))[0]);
      for (let i = 0; i < 6; i++) await tick();
      return {before: before, after: after, msg: $('ws-add-msg').textContent,
              posts: calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return c[1]; })};
    """, {"/api/websites": _LIST315, "/websites/install-app": {"success": False, "message": "No database server yet.",
                                                               "missing": [entry]},
          "/api/remote/4/databases/setup": {"success": True, "message": "Setting up databases on this host."}})
    eq("C4 (the add dialog, js/websites.js): the app install's refusal becomes the dialog's first line with Set up "
       "databases, Create unavailable; the button starts the host's database setup and says to create the app again",
       (got.get("before"), got.get("after"), got.get("posts"), got.get("msg")),
       (False, {"shown": True, "text": "No database server yet.", "action": "wsDbSetup", "disabled": True},
        ["/m/websites/install-app", "/m/api/remote/4/databases/setup"],
        "Databases are being set up. Create the app again in a few minutes."))


# ── C5. Hosts that cannot run websites ────────────────────────────────────────────────────────────
def _c5_hosts(st):
    managed = _Remote315(name="p315-managed", host="198.51.100.89", port=22, username="u", auth_method="key",
                         auth_credential="", is_local=False)
    _db315.session.add(managed)
    _db315.session.commit()
    _ROWS315["remotes"].append(managed.id)
    _p9_patch(_w315, "start_install", lambda site: None)
    su = _Client315(st.su.id)
    hosts = [h.get("id") for h in _p9_json(su.get("/api/websites")).get("hosts") or []]
    eq("C5 (GET /api/websites, a superadmin with a managed host too): the add dialog lists only the hosts that run "
       "websites, so the panel's own host, never the managed one", (st.host.id in hosts, managed.id in hosts),
       (True, False))
    r = su.post("/websites/add", json={"name": "p315-elsewhere", "kind": "static", "host_id": managed.id})
    eq("C5 (POST /websites/add naming a managed host): refused with the reason before anything is made (it was made "
       "and then failed at once)", (r.status_code, _p9_json(r).get("message"),
                                    _Site315.query.filter_by(name="p315-elsewhere").count()),
       (409, _sw315.ONLY_LOCAL, 0))
    ok = su.post("/websites/add", json={"name": "p315-here", "kind": "static", "host_id": st.host.id})
    eq("C5 control (the panel's own host): added", (ok.status_code, _p9_json(ok).get("success")), (200, True))
    got = _node315(_list_page315(), ["websites_common.js", "websites.js"], r"""
      const o = document.createElement('option'); o.value = '9'; $('wp-host').appendChild(o);
      window.wsProxyInstall(); for (let i = 0; i < 4; i++) await tick();
      window.wsProxyInstall('add'); for (let i = 0; i < 4; i++) await tick();
      return {sent: calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return c[2].host_id; })};
    """, {"/api/websites": dict(_LIST315, hosts=[{"id": 1, "name": "h"}]), "/websites/proxy/install": {"success": True}})
    eq("C5 (js/websites.js): the proxy card's Install sends the card's host, the add dialog's note the dialog's host "
       "(the card used the dialog's)", got.get("sent"), ["9", "1"])


# ── B10. An administrator below a superadmin ──────────────────────────────────────────────────────
def _b10_admin(st):
    from panel.db.models import Group
    from panel.security.auth import MANAGE_WEBSITES, VIEW_WEBSITES
    managed = _Remote315(name="p315-theirs", host="198.51.100.90", port=22, username="u", auth_method="key",
                         auth_credential="", is_local=False)
    _db315.session.add(managed)
    _db315.session.commit()
    _ROWS315["remotes"].append(managed.id)
    user = _user315("p315-webadmin")
    group = Group(name="p315-webadmins", description="", is_default=False, is_customer=False)
    group.set_permissions([MANAGE_WEBSITES, VIEW_WEBSITES])
    group.servers.append(managed)
    group.users.append(user)
    _db315.session.add(group)
    _db315.session.commit()
    theirs = _Site315(remote_id=managed.id, name="p315-theirsite", kind="static", state="running",
                      proxy_secret=_cfg315.encrypt_secret(_TOKEN315))
    _db315.session.add(theirs)
    _db315.session.flush()
    theirs.account, theirs.port = "ws%d" % theirs.id, 20899
    _db315.session.commit()
    _ROWS315["sites"].append(theirs.id)
    try:
        _b10_checks(st, user)
    finally:
        _db315.session.rollback()
        _db315.session.delete(_db315.session.get(Group, group.id))
        _db315.session.commit()


def _b10_checks(st, user):
    me = _Client315(user.id)
    page = me.get("/websites").get_data(as_text=True)
    add = me.post("/websites/add", json={"name": "p315-tryadd", "kind": "static", "host_id": st.host.id})
    eq("B10 (GET /websites, an administrator in an ordinary group): no Add a website button, and the list says why "
       "(websites run on the panel's own host, a superadmin's); their customer card stays, for the site they "
       "administer", ('id="ws-add-open"' in page, 'id="ws-add-why"' in page, 'id="wc-box"' in page), (False, True, True))
    eq("B10 (POST /websites/add and GET /api/websites for them): the add is not theirs (404, as for no route), and "
       "the list says they cannot create", (add.status_code, _p9_json(me.get("/api/websites")).get("can_create")),
       (404, False))
    su_page = _Client315(st.su.id).get("/websites").get_data(as_text=True)
    eq("B10 control (a superadmin): Add a website, and no such sentence",
       ('id="ws-add-open"' in su_page, 'id="ws-add-why"' in su_page), (True, False))


# ── M2. Customers' site limits ────────────────────────────────────────────────────────────────────
def _m2_limits(st):
    from panel.db.models import Group
    from panel.routes.websites_view import options
    from panel.security.auth import CREATE_WEBSITES
    site = _site315(st, "p315-cust", kind="static")
    su = _Client315(st.su.id)
    made = {}
    for label, extra in (("p315-plain", {}), ("p315-adds", {"permissions": ["view_websites", "manage_website",
                                                                             CREATE_WEBSITES], "max_sites": 5}),
                         ("p315-default", {"permissions": [CREATE_WEBSITES, "view_websites"]})):
        r = su.post("/websites/customers/add", json=dict({"name": label, "sites": [site.id]}, **extra))
        g = Group.query.filter_by(name="customer-" + label).first()
        made[label] = (r.status_code, CREATE_WEBSITES in g.get_permissions() if g else None, g.max_sites if g else None)
    try:
        eq("M2 (POST /websites/customers/add): a customer who may not add sites gets none to add (held to the 1 given); "
           "one who may gets the limit sent, else the Sites per customer setting (it was read nowhere)", made,
           {"p315-plain": (200, False, 1), "p315-adds": (200, True, 5),
            "p315-default": (200, True, max(1, options()["max_sites"]))})
        _m2_quota(st, site)
    finally:
        _m2_cleanup(["customer-p315-plain", "customer-p315-adds", "customer-p315-default"])
    _m2_card()


def _m2_cleanup(names):
    from panel.db.models import Group, Invite
    _db315.session.rollback()
    for inv in Invite.query.filter(Invite.note.like("customer p315-%")).all():
        _db315.session.delete(inv)
    for g in Group.query.filter(Group.name.in_(names)).all():
        g.users = []
        _db315.session.delete(g)
    _db315.session.commit()


def _m2_quota(st, site):
    from panel.db.models import Group
    from panel.security.auth import CREATE_WEBSITES
    saved = _p9.config.get("WEBSITES_CUSTOMER_2FA", True)
    _p9.config["WEBSITES_CUSTOMER_2FA"] = False
    got = {}
    try:
        for label in ("p315-plain", "p315-adds"):
            user = _user315("p315-u-" + label[5:])
            group = Group.query.filter_by(name="customer-" + label).first()
            group.users.append(user)
            _db315.session.commit()
            got[label] = _p9_json(_Client315(user.id).get("/api/websites")).get("quota")
    finally:
        _p9.config["WEBSITES_CUSTOMER_2FA"] = saved
    eq("M2 (GET /api/websites for a customer): the \"{used} of {max} websites used\" line only for a group that may "
       "add its own sites", got, {"p315-plain": None, "p315-adds": {"used": 1, "max": 5}})
    lst = _p9_json(_Client315(st.su.id).get("/api/websites"))
    eq("M2 (GET /api/websites for an administrator): the card's limit starts at the Sites per customer setting",
       isinstance(lst.get("customer_max_sites"), int) and lst.get("customer_max_sites") >= 1, True)
    assert CREATE_WEBSITES


def _m2_card():
    scenario = r"""
      for (let i = 0; i < 4; i++) await tick();
      const start = $('wc-max').value, wrapHidden = $('wc-max-wrap').hidden;
      $('wc-name').value = 'acme'; document.querySelectorAll('[data-wc-site]')[0].checked = true;
      const off = WS.customerBody();
      $('wc-create').checked = true; window.wsCustomerCreate();
      $('wc-max').value = '4';
      return {start: start, wrapHidden: wrapHidden, off: off, wrapShown: !$('wc-max-wrap').hidden, on: WS.customerBody()};
    """
    got = _node315(_list_page315(), ["websites_common.js", "websites.js"], scenario,
                   {"/api/websites": dict(_LIST315, customer_max_sites=7, sites=[
                       {"id": 3, "name": "shop", "kind": "static", "state": "running", "enabled": False}])})
    eq("M2 (the Add a customer card, js/websites.js): by default the customer gets the ticked sites and nothing to add "
       "(no limit sent, its field hidden); turned on, the card sends the right to add their own and the limit, which "
       "starts at the Sites per customer setting",
       (got.get("start"), got.get("wrapHidden"), got.get("off"), got.get("wrapShown"), got.get("on")),
       ("7", True, {"name": "acme", "sites": [3]}, True,
        {"name": "acme", "sites": [3], "permissions": ["view_websites", "edit_website_files", "manage_website",
                                                       "create_websites"], "max_sites": 4}))


# ── WP1. WordPress's requests to its own address ──────────────────────────────────────────────────
_PLUGIN315 = "site/html/wp-content/mu-plugins/lgsm-panel-loopback.php"


def _wp1_loopback(st):
    _seams315()
    su = _Client315(st.su.id)
    wp = _site315(st, "p315-wpself", kind="wordpress", app_recipe="wordpress")
    _reset315()
    r = su.post("/websites/%d/update-image" % wp.id)
    plugin = _read315(wp.account, _PLUGIN315) or ""
    token = _read315(wp.account, "site/conf/panel/proxy-token")
    mount = "Volume=/home/%s/site/conf/panel:/run/panel:ro" % wp.account
    eq("WP1 (POST /websites/<id>/update-image, WordPress): the must-use plugin is written into the site's files and "
       "sends a request for the site's own names to its own listener (127.0.0.1:8080) with the scheme and the proxy "
       "token's header, the token read from /run/panel; the egress proxy is bypassed for that loopback only",
       (r.status_code, "add_filter( 'pre_http_request', 'lgsm_panel_loopback'" in plugin,
        "define( 'LGSM_PANEL_PORT', 8080 )" in plugin, "'/run/panel/proxy-token'" in plugin,
        "$headers['X-Panel-Proxy-Token']" in plugin, "X-Forwarded-Proto" in plugin,
        "'pre_http_send_through_proxy'" in plugin and "'127.0.0.1' === $check['host']" in plugin),
       (200, True, True, True, True, True, True))
    argv = " ".join(" ".join(a) for a in _calls315())
    eq("WP1 (the token): a 0600 file in the site's 0700 run folder, mounted read-only at /run/panel; never in the plugin, "
       "a shell's text or a program's arguments (it travels on stdin only)",
       (token, _mode315(wp.account, "site/conf/panel/proxy-token"), _mode315(wp.account, "site/conf/panel"),
        _quadlet315(wp.account).count(mount), _TOKEN315 in plugin, any(_TOKEN315 in sh for sh in _RUN315["shells"]),
        _TOKEN315 in argv),
       (_TOKEN315, "0o600", "0o700", 1, False, False, False))
    _wp1_refused(st, su)


def _wp1_refused(st, su):
    wp = _site315(st, "p315-wplink", kind="wordpress", app_recipe="wordpress")
    home = _home315(wp.account)
    outside = os.path.join(home, "elsewhere")
    os.makedirs(os.path.join(home, "site", "html", "wp-content"), exist_ok=True)
    os.makedirs(outside, exist_ok=True)
    os.symlink(outside, os.path.join(home, "site", "html", "wp-content", "mu-plugins"))
    _reset315()
    r = su.post("/websites/%d/update-image" % wp.id)
    eq("WP1 (a site whose own code made wp-content/mu-plugins a link): the writer refuses it (nothing written through "
       "the link) and the install still goes on", (r.status_code, os.listdir(outside)), (200, []))
    php = _site315(st, "p315-phpself", kind="php")
    _reset315()
    r = su.post("/websites/%d/update-image" % php.id)
    eq("WP1 control (a PHP site): no plugin and no token file, but the same read-only run folder (for its object "
       "cache's password)", (r.status_code, _read315(php.account, _PLUGIN315), _read315(php.account,
                                                                                        "site/conf/panel/proxy-token"),
                             _quadlet315(php.account).count("Volume=/home/%s/site/conf/panel:/run/panel:ro" % php.account)),
       (200, None, None, 1))


# ── C1. A plain site's setup steps ────────────────────────────────────────────────────────────────
def _c1_steps(st):
    _seams315()
    site = _site315(st, "p315-parts", kind="static")
    seen = []
    _reset315()
    ok, _said = _sw315.install(st.host, site, None, True, True, seen.append)
    eq("C1 (ssh_manager.websites.install): it reports each part as it begins: the account and folders, the image, the "
       "container", (ok, seen), (True, ["account", "image", "container"]))
    mid = {}

    def fake(remote, s, db=None, start_it=True, restart=True, progress=None):
        for part in ("account", "image"):
            progress(part)
        mid["json"] = _wapps315.install_json(s)
        progress("container")
        return True, _sw315.OK_STARTED
    _p9_patch(_sw315, "install", fake)
    _p9_patch(_w315, "start_install", lambda s: _w315._install_worker(_p9, s.id))
    su = _Client315(st.su.id)
    r = su.post("/websites/add", json={"name": "p315-plainsteps", "kind": "php", "host_id": st.host.id})
    sid = _p9_json(r).get("id") or 0
    _ROWS315["sites"].append(sid)
    during = mid.get("json") or {}
    after = _p9_json(su.get("/api/websites/%d" % sid)).get("install") or {}
    eq("C1 (POST /websites/add, a PHP site, during its install): the install block has its steps, the account done and "
       "the image being built or downloaded (it had none: empty steps until the end)",
       (r.status_code, during.get("state"), [(x["key"], x["state"]) for x in during.get("steps") or []]),
       (200, "running", [("account", "done"), ("image", "running"), ("container", "pending")]))
    eq("C1 (GET /api/websites/<id> once it ran): every step done, so the dialog stops and says Done",
       (after.get("state"), [x["state"] for x in after.get("steps") or []]), ("done", ["done", "done", "done"]))
    _c1_dialog()


def _c1_dialog():
    got = _node315(_list_page315(), ["websites_common.js", "websites.js"], r"""
      window.wsOpenAdd();
      $('ws-add-name').value = 'plain';
      window.wsAddSubmit({preventDefault: function () {}});
      for (let i = 0; i < 8; i++) await tick();
      return {labels: $('ws-progress').querySelectorAll('.ws-step-label').map(function (l) { return l.textContent; })};
    """, {"/api/websites": _LIST315, "/websites/add": {"success": True, "id": 5},
          "/api/websites/5": {"success": True, "site": {"id": 5, "state": "creating"}, "install": {
              "state": "running", "steps": [{"key": "account", "state": "done"}, {"key": "image", "state": "running"},
                                            {"key": "container", "state": "pending"}]}}})
    eq("C1 (the add dialog, js/websites.js): a plain site's steps are labelled in plain words, the image one saying it "
       "takes a few minutes on a small host", got.get("labels"),
       ["Create the site account", "Build or download the site image (a few minutes on a small host)",
        "Start the site container"])


# ── C2. A Node.js app waiting for its files ───────────────────────────────────────────────────────
def _c2_waiting(st):
    reason = _sw315.OK_WAITING
    scenario = r"""
      const shown = !$('ws-waiting').hidden;
      const out = {shown: shown, reason: $('ws-waiting-reason').textContent, label: $('ws-main-label').textContent,
                   verb: $('ws-main').getAttribute('data-verb'),
                   upload: $('ws-waiting').querySelector('button') ? $('ws-waiting').querySelector('button').getAttribute('data-args') : null};
      window.wsMain();
      for (let i = 0; i < 4; i++) await tick();
      out.posts = calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return c[1]; });
      return out;
    """
    routes = {"/api/websites/7": _b3_site_answer(kind="app", state="stopped", state_reason=reason),
              "/websites/7/app/build": {"success": True, "message": "Built."}}
    got = _node315(_site_page315(), ["websites_common.js", "website_site.js"], scenario, routes)
    eq("C2 (the site page, js/website_site.js): a new Node.js app says it waits for its files, with Upload its files "
       "(the Files tab), and its main button is Build and start, which builds it (it showed Stopped and a Start)",
       (got.get("shown"), got.get("reason"), got.get("upload"), got.get("label"), got.get("verb"), got.get("posts")),
       (True, reason, '["files"]', "Build and start", "app/build", ["/m/websites/7/app/build"]))
    plain = _node315(_site_page315(), ["websites_common.js", "website_site.js"], scenario,
                     {"/api/websites/7": _b3_site_answer(kind="static", state="stopped")})
    eq("C2 control (a stopped plain site): no such note, and Start", (plain.get("shown"), plain.get("label")),
       (False, "Start"))


# ── WP3. The egress proxy ─────────────────────────────────────────────────────────────────────────
def _wp3_egress(st):
    import socket as _so315
    from panel.services import websites_egress as _eg315
    listener = _so315.socket(_so315.AF_INET, _so315.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    said = []
    _p9_patch(_eg315, "say", said.append)
    try:
        conn = _eg315.connect(["127.0.0.3", "127.0.0.1"], port)
        ok = conn is not None and conn.getpeername()[0] == "127.0.0.1"
        if conn is not None:
            conn.close()
        none = _eg315.connect(["127.0.0.3"], port)
    finally:
        listener.close()
    eq("WP3 (websites_egress.connect): the first validated address that does not answer is passed over for the next "
       "(the proxy tried only the first), only those addresses tried, and each failure is a journal line",
       (ok, none, len(said) >= 2, all("127.0.0.3" in x for x in said)), (True, None, True, True))
    _wp3_handle(st, _eg315)


def _recv315(sock):
    """Up to 64 bytes from `sock`, or b"" when none come within its timeout (a check then fails by its name)."""
    import socket as _so315
    try:
        return sock.recv(64)
    except (_so315.timeout, OSError):
        return b""


def _wp3_handle(st, eg):
    import socket as _so315
    import threading as _th315
    client, proxy_side = _so315.socketpair()
    upstream, far = _so315.socketpair()
    said = []
    _p9_patch(eg, "say", said.append)
    _p9_patch(eg, "resolve", lambda host, port, getaddrinfo=None: ["192.0.2.10"])
    _p9_patch(eg, "connect", lambda addrs, port=443: upstream)
    slots = _th315.BoundedSemaphore(1)
    slots.acquire()
    t = _th315.Thread(target=eg.handle, args=(proxy_side, frozenset(["api.wordpress.org"]), slots), daemon=True)
    t.start()
    client.sendall(b"CONNECT api.wordpress.org:443 HTTP/1.1\r\nHost: api.wordpress.org:443\r\n\r\nHELLO-TLS")
    client.settimeout(5)
    far.settimeout(5)
    reply, early = _recv315(client), _recv315(far)
    client.close()
    far.close()
    t.join(5)
    eq("WP3 (websites_egress.handle): the CONNECT is answered 200 and the bytes the client sent after its head (a TLS "
       "hello) reach the upstream (they were dropped)", (reply, early), (b"HTTP/1.1 200 Connection established\r\n\r\n",
                                                                         b"HELLO-TLS"))
    client, proxy_side = _so315.socketpair()
    slots.acquire(timeout=5)
    t = _th315.Thread(target=eg.handle, args=(proxy_side, frozenset(["api.wordpress.org"]), slots), daemon=True)
    t.start()
    client.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\n")
    client.settimeout(5)
    refused = _recv315(client)
    client.close()
    t.join(5)
    eq("WP3 (a host not on the list): refused 403, and the journal says which host and why, never a header",
       (refused.startswith(b"HTTP/1.1 403"), [x for x in said if "evil.example" in x],
        any("c2VjcmV0" in x or "Basic" in x for x in said)),
       (True, ["refused CONNECT evil.example:443: not an allowed host on 443"], False))
    site = _NS315(port=20001)
    unit = _ws315.egress_unit(site, ["api.wordpress.org"])
    eq("WP3 (the egress unit): its task limit fits two threads per connection at the cap, the main thread and a margin "
       "(64 fell one short, and the accept loop died)", ("TasksMax=%d" % _ws315.EGRESS_TASKS in unit,
                                                         _ws315.EGRESS_TASKS >= 2 * eg.MAX_CONNECTIONS + 1), (True, True))


# ── B4. The object cache wired to the site ────────────────────────────────────────────────────────
_CACHE_PW315 = "c" * 40


def _b4_cache(st):
    _seams315()
    su = _Client315(st.su.id)
    wp = _site315(st, "p315-wpcache", kind="wordpress", app_recipe="wordpress",
                  object_cache_secret=_cfg315.encrypt_secret(_CACHE_PW315))
    _reset315()
    on = su.post("/websites/%d/performance" % wp.id, json={"object_cache": True})
    pw_file = "site/conf/panel/object-cache-password"
    got_on = (on.status_code, _read315(wp.account, pw_file), _mode315(wp.account, pw_file),
              any("restart" in a and "lgsm-site.service" in a for a in _calls315("systemctl")),
              any(_CACHE_PW315 in " ".join(a) for a in _calls315()), any(_CACHE_PW315 in sh for sh in _RUN315["shells"]))
    _reset315()
    off = su.post("/websites/%d/performance" % wp.id, json={"object_cache": False})
    eq("B4 (POST /websites/<id>/performance, object cache on then off): its password is a 0600 file in the site's "
       "read-only /run/panel folder while it is on and gone when it is off, the site never restarted, the password "
       "never in a program's arguments or a shell's text (it was set in the cache and written nowhere the site reads)",
       (got_on, off.status_code, _read315(wp.account, pw_file)),
       ((200, _CACHE_PW315, "0o600", False, False, False), 200, None))
    _b4_recipe()
    _b4_reveal(st)


def _b4_recipe():
    from panel.services import websites_recipes as _wr315
    step = next(x for x in _ws315.recipe_steps("wordpress") if x["type"] == "render-config")
    text = _wr315.render_template(step["template"], {"db_password": "p"}, step["escape"])
    block = text[text.find("is_readable( '/run/panel/object-cache-password' )"):]
    eq("B4 (the WordPress recipe's wp-config): the Redis Object Cache plugin's host, port and password constants, "
       "defined while the panel's password file is there and read from it (no password written into the site's files), "
       "before WordPress loads", (bool(block), "define( 'WP_REDIS_HOST', '127.0.0.1' );" in block,
                                  "define( 'WP_REDIS_PORT', 6379 );" in block,
                                  "file_get_contents( '/run/panel/object-cache-password' )" in block,
                                  block.find("WP_REDIS_PASSWORD") < block.find("wp-settings.php")),
       (True, True, True, True, True))


def _b4_reveal(st):
    from panel.db.models import AuditLog
    su = _Client315(st.su.id)
    site = _site315(st, "p315-phpcache", kind="php", object_cache=True,
                    object_cache_secret=_cfg315.encrypt_secret(_CACHE_PW315))
    off = _site315(st, "p315-phpnocache", kind="php")
    r = su.post("/websites/%d/object-cache/credentials" % site.id)
    rows = AuditLog.query.filter(AuditLog.website_id == site.id, AuditLog.action == "website_cache_reveal").all()
    eq("B4 (POST /websites/<id>/object-cache/credentials): the address, port and password once, no-store, one audit "
       "row that holds no password",
       (r.status_code, _p9_json(r).get("password"), _p9_json(r).get("port"), _p9_json(r).get("file"),
        r.headers.get("Cache-Control"), len(rows), any(_CACHE_PW315 in (x.detail or "") for x in rows)),
       (200, _CACHE_PW315, 6379, "/run/panel/object-cache-password", "no-store", 1, False))
    eq("B4 control (a site whose cache is off, and another superadmin's view of no site): refused, nothing revealed",
       (su.post("/websites/%d/object-cache/credentials" % off.id).status_code,
        su.post("/websites/%d/object-cache/credentials" % (site.id + 100000)).status_code), (409, 404))
    perf = {"opcache": True, "object_cache": True, "object_cache_host": "127.0.0.1", "object_cache_port": 6379,
            "object_cache_file": "/run/panel/object-cache-password", "page_cache": False, "static_cache": False}
    got = _node315(_site_page315(), ["websites_common.js", "website_site.js", "website_tuning.js"], r"""
      for (let i = 0; i < 6; i++) await tick();
      const info = $('wperf-obj-info');
      const b = info.querySelector('button');
      if (b) window.wsCacheReveal();
      for (let i = 0; i < 6; i++) await tick();
      return {text: info.textContent, action: b ? b.getAttribute('data-action') : null,
              conn: $('wperf-obj-conn') ? $('wperf-obj-conn').textContent : ''};
    """, {"/api/websites/7": dict(_b3_site_answer(state="running"), perf=dict(perf, object_cache_wordpress=True),
                                  rules=[]),
          "/websites/7/object-cache/credentials": {"success": True, "host": "127.0.0.1", "port": 6379,
                                                   "password": "shown-once"}})
    eq("B4 (the Performance tab, js/website_tuning.js): WordPress is told its address and password are set and which "
       "plugin to install; Show connection settings gives the password after the password check",
       ("Redis Object Cache plugin" in (got.get("text") or ""), got.get("action"), "shown-once" in (got.get("conn") or "")),
       (True, "wsCacheReveal", True))


# ── running the sections ──────────────────────────────────────────────────────────────────────────
def _cleanup315():
    _db315.session.rollback()
    sites = set(_ROWS315["sites"]) | {s.id for s in _Site315.query.filter(
        _Site315.remote_id.in_(_ROWS315["remotes"] or [0])).all()}
    for d in _Dom315.query.filter(_Dom315.website_id.in_(sorted(sites) or [0])).all():
        _db315.session.delete(d)
    _b5_cleanup(sorted(sites) or [0])
    for p in _Proxy315.query.filter(_Proxy315.remote_id.in_(_ROWS315["remotes"] or [0])).all():
        _db315.session.delete(p)
    for model, ids in ((_Site315, sorted(sites)), (_User315, _ROWS315["users"]), (_Remote315, _ROWS315["remotes"])):
        for i in ids:
            row = _db315.session.get(model, i)
            if row is not None:
                _db315.session.delete(row)
    _db315.session.commit()
    _shutil315.rmtree(_TREE315, ignore_errors=True)


def _ran315(step, st):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran315.last)."""
    import traceback
    try:
        step(st)
        _ran315.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db315.session.rollback()
        _ran315.last = traceback.format_exc()[-1500:]
        return False


_ran315.last = ""
_tools315()
_trips315 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part315")
        _st315 = _rows315()
        for _sec315 in (_b2_failed_undone, _b3_retry, _c9_delete_busy, _p8_delete_text, _b5_database, _m7_note, _c4_no_db, _c5_hosts, _b10_admin, _m2_limits, _wp1_loopback, _c1_steps, _c2_waiting, _wp3_egress, _b4_cache):
            check("part315: %s ran to the end" % _sec315.__name__, _ran315(_sec315, _st315), _ran315.last)
        eq("part315: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips315:], [])
    finally:
        _p9_restore_all()
        _w315._STATUS.clear()
        _wapps315._JOBS.clear()
        _cleanup315()
