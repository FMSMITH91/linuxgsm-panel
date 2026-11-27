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

HOW IT RUNS. part12's app and its database for the routes, every host call at ssh_manager.websites' seams;
the scripts run in node over the real rendered pages (part301's harness). Nothing reaches a host (part12's
tripwire is armed).
"""
import os
from types import SimpleNamespace as _NS315

from flask import g as _g315

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg315
from panel.db.models import (RemoteServer as _Remote315, User as _User315, Website as _Site315,
                             WebsiteDomain as _Dom315, WebsiteProxy as _Proxy315, db as _db315)
from panel.ops.ssh_manager import websites as _sw315
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
    s = _Site315(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg315.encrypt_secret(_TOKEN315), **dict(extra, **kw))
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
def _b2_job(st):
    """POST /websites/install-app whose first step fails; its job runs in this thread. -> (response, site id)."""
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


# ── running the sections ──────────────────────────────────────────────────────────────────────────
def _cleanup315():
    _db315.session.rollback()
    sites = set(_ROWS315["sites"]) | {s.id for s in _Site315.query.filter(
        _Site315.remote_id.in_(_ROWS315["remotes"] or [0])).all()}
    for d in _Dom315.query.filter(_Dom315.website_id.in_(sorted(sites) or [0])).all():
        _db315.session.delete(d)
    for p in _Proxy315.query.filter(_Proxy315.remote_id.in_(_ROWS315["remotes"] or [0])).all():
        _db315.session.delete(p)
    for model, ids in ((_Site315, sorted(sites)), (_User315, _ROWS315["users"]), (_Remote315, _ROWS315["remotes"])):
        for i in ids:
            row = _db315.session.get(model, i)
            if row is not None:
                _db315.session.delete(row)
    _db315.session.commit()


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
_trips315 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part315")
        _st315 = _rows315()
        for _sec315 in (_b2_failed_undone, _b3_retry, _c9_delete_busy):
            check("part315: %s ran to the end" % _sec315.__name__, _ran315(_sec315, _st315), _ran315.last)
        eq("part315: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips315:], [])
    finally:
        _p9_restore_all()
        _w315._STATUS.clear()
        _wapps315._JOBS.clear()
        _cleanup315()
