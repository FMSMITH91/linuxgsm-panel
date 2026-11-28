"""Part 330 of the unit suite: website app administrators' passwords, and stored secrets on the pages.

1. Reset admin password (POST /websites/<id>/app-admin/users and /reset, down to the wp-cli step's shell and
   stdin, the host's shell at ssh_manager.websites._as_site): the administrators are listed from the step's
   own marked lines only; a reset sends the administrator, the new password and the email on stdin only, never
   in the shell text; a generated password comes back once, no-store; a typed one never comes back; a typed
   password outside 15-128 characters, a login or an email that is not one is refused before any host call;
   the audit row names the administrator, never the password or the address; WordPress's refusal is said; a
   site that is not WordPress, a viewer and a stale password check are refused. The step signs the
   administrator out everywhere and changes only an administrator.
2. The page (node, over the rendered website page): Reset admin password lists the administrators, the form
   posts the chosen one, and a generated password is drawn masked: not in the page's text until Show, which is
   aria-pressed; Copy copies without showing; a shown password hides again after 30 seconds and when the tab
   is hidden.

HOW IT RUNS. The routes through part12's app (its tripwire armed, so nothing reaches a host), the host's shell
answered here; the page's scripts in node over the rendered markup (part301's harness, with timers, listeners and
the clipboard recorded).
"""
import base64 as _b64_330
import json as _json330
import os
import shutil as _shutil330
import subprocess as _sp330  # nosec B404 - node over the panel's own scripts
import tempfile as _tf330

from flask import g as _g330

from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from unit.part301 import _HARNESS301, _JS301, _page301, _tree301
from panel.core import config as _cfg330
from panel.db.models import (AuditLog as _Audit330, RemoteServer as _Remote330, User as _User330, Website as _Site330,
                             db as _db330)
from panel.ops.ssh_manager import websites as _sw330

_TOKEN330 = "t" * 40
_ROWS330 = {"sites": [], "remotes": [], "users": []}
# Stand-in values, named so no credential-shaped literal sits beside a credential-shaped name.
_TYPED330 = "Typed-Long-Enough-1234"
_SHORT330 = "short-one"
_ADDR330 = "owner@example.org"
_NONE330 = ""


def _b64(text):
    return _b64_330.b64encode(text.encode("utf-8")).decode("ascii")


class _Client330:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g330.pop("_login_user", None)
        _g330.__dict__.pop("_websites_access_cache", None)
        k.setdefault("headers", {"X-Requested-With": "XMLHttpRequest"})     # as the page's fetch wrapper sends
        return self.c.post(*a, **k)


def _rows330():
    r = _Remote330(name="p330-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.130")
    su = _User330(username="p330-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    vw = _User330(username="p330-viewer", password_hash=os.urandom(8).hex(), is_superadmin=False, is_active=True)
    _db330.session.add_all([r, su, vw])
    _db330.session.commit()
    _ROWS330["remotes"].append(r.id)
    _ROWS330["users"] += [su.id, vw.id]
    return r, su, vw


def _site330(remote, name, kind="wordpress", **kw):
    s = _Site330(remote_id=remote.id, name=name, kind=kind, state="running", php_version="8.4" if kind != "static" else "",
                 proxy_secret=_cfg330.encrypt_secret(_TOKEN330), **kw)
    _db330.session.add(s)
    _db330.session.flush()
    s.account, s.port = "ws%d" % s.id, 20900 + s.id % 90
    _db330.session.commit()
    _ROWS330["sites"].append(s.id)
    return s


class _Host330:
    """ssh_manager.websites._as_site answered here: each call's (account, shell, stdin) kept, `out` answered."""

    def __init__(self, out):
        self.out, self.calls = out, []

    def __call__(self, remote, account, sh, timeout=120, stdin_text=None):
        self.calls.append((account, sh, stdin_text or ""))
        return "SITE_STEP_FAILED" not in self.out, self.out


def _stub330(out):
    host = _Host330(out)
    _p9_patch(_sw330, "_as_site", host)
    _p9_patch(_sw330, "_ids", lambda remote, site: ((1000, 1000), {}))
    return host


def _audits330(site):
    return [(a.action, a.detail, bool(a.success)) for a in
            _Audit330.query.filter_by(website_id=site.id).order_by(_Audit330.id)]


# ── 1. the routes ─────────────────────────────────────────────────────────────────────────────────
def _s1_list(st):
    host = _stub330("WARNING: a plugin said something\nWPADMIN=alice\nWPADMIN=bob smith\nWPADMIN=<b>x</b>\nWPADMIN=alice\n")
    r = st.su.post("/websites/%d/app-admin/users" % st.wp.id, json={})
    body = _p9_json(r)
    eq("reset admin password (POST /websites/<id>/app-admin/users): the administrators are the step's own WPADMIN= lines, "
       "each a WordPress login, once each; the answer is no-store",
       (r.status_code, body.get("users"), r.headers.get("Cache-Control")), (200, ["alice", "bob smith"], "no-store"))
    sh = host.calls[0][1] if host.calls else ""
    eq("reset admin password (the list's shell): one call, as the site's account, a wp-cli container listing the "
       "administrator role, its log driver off",
       (len(host.calls), host.calls[0][0] if host.calls else "", "--role=administrator" in sh, "--log-driver=none" in sh),
       (1, st.wp.account, True, True))
    _stub330("Error: Error establishing a database connection.\nSITE_STEP_FAILED\n")
    r = st.su.post("/websites/%d/app-admin/users" % st.wp.id, json={})
    eq("reset admin password (list, control: WordPress does not answer): refused with the plain reason, no list",
       (r.status_code, _p9_json(r).get("success"), "users" in _p9_json(r), "WordPress did not answer" in
        (_p9_json(r).get("message") or "")), (502, False, False, True))


def _reset330(st, out, body):
    host = _stub330(out)
    r = st.su.post("/websites/%d/app-admin/reset" % st.wp.id, json=body)
    return r, _p9_json(r), host


def _s1_reset(st):
    before = len(_audits330(st.wp))
    r, body, host = _reset330(st, "WPADMIN_DONE\n", {"user": "alice", "password": _NONE330, "email": ""})
    made = body.get("password") or ""
    sh, stdin = (host.calls[0][1], host.calls[0][2]) if host.calls else ("", "")
    eq("reset admin password (POST /reset, none typed): done, a generated 24-character password once, no-store",
       (r.status_code, body.get("success"), body.get("generated"), len(made), r.headers.get("Cache-Control")),
       (200, True, True, 24, "no-store"))
    eq("reset admin password (the reset's shell and stdin): the password and the administrator are on stdin (the "
       "step's values lines) and nowhere in the shell text",
       ("val ADMIN_PASSWORD %s" % _b64(made) in stdin, "val ADMIN_USER %s" % _b64("alice") in stdin, made in sh,
        _b64(made) in sh, "alice" in sh), (True, True, False, False, False))
    rows = _audits330(st.wp)[before:]
    eq("reset admin password (audit): one row, done, naming the administrator, never the password",
       ([(a, "alice" in d, made in d, ok) for a, d, ok in rows]), [("website_app_admin_password", True, False, True)])

    r, body, host = _reset330(st, "WPADMIN_DONE\n", {"user": "alice", "password": _TYPED330, "email": _ADDR330})
    stdin = host.calls[0][2] if host.calls else ""
    rows = _audits330(st.wp)[-1:]
    eq("reset admin password (typed, with an email): done, the typed password not sent back, both on stdin only, the "
       "audit says the email changed without the address",
       (body.get("success"), body.get("password"), body.get("generated"), "val ADMIN_PASSWORD %s" % _b64(_TYPED330) in stdin,
        "val ADMIN_EMAIL %s" % _b64(_ADDR330) in stdin, _TYPED330 in host.calls[0][1], [("new email" in d, _ADDR330 in d,
                                                                                      _TYPED330 in d) for _a, d, _ok in rows]),
       (True, "", False, True, True, False, [(True, False, False)]))


def _s1_refused(st):
    refused = {}
    for name, body in (("short", {"user": "alice", "password": _SHORT330}), ("long", {"user": "alice", "password": "x" * 129}),
                       ("login", {"user": "al\nice"}), ("email", {"user": "alice", "email": "not-an-address"})):
        r, got, host = _reset330(st, "WPADMIN_DONE\n", body)
        refused[name] = (r.status_code, got.get("success"), len(host.calls))
    eq("reset admin password (refused before any host call): a typed password under 15 or over 128 characters, a login "
       "that is not one, an email that is not one",
       refused, {k: (400, False, 0) for k in ("short", "long", "login", "email")})
    r, got, host = _reset330(st, "WPADMIN_NO_SUCH\nSITE_STEP_FAILED\n", {"user": "mallory"})
    eq("reset admin password (WordPress: not an administrator): refused with that reason, no password sent back, "
       "audited as not done",
       (r.status_code, got.get("success"), "password" in got, "not an administrator" in (got.get("message") or ""),
        _audits330(st.wp)[-1][2]), (502, False, False, True, False))
    r, got, host = _reset330(st, "WPADMIN_EMAIL_TAKEN\nSITE_STEP_FAILED\n", {"user": "alice", "email": _ADDR330})
    eq("reset admin password (WordPress: the email belongs to another account): refused with that reason",
       (got.get("success"), "already has that email" in (got.get("message") or "")), (False, True))
    r, got, host = _reset330(st, "Warning: something\n", {"user": "alice"})
    eq("reset admin password (no done mark from WordPress): not reported as done", got.get("success"), False)


def _s1_who(st):
    host = _stub330("WPADMIN=alice\n")
    r_php = st.su.post("/websites/%d/app-admin/users" % st.php.id, json={})
    r_view = st.vw.post("/websites/%d/app-admin/users" % st.wp.id, json={})
    from panel.routes import websites_app_admin as _r
    _p9_patch(_r, "step_up_needed", lambda: True)
    r_step = st.su.post("/websites/%d/app-admin/reset" % st.wp.id, json={"user": "alice"})
    eq("reset admin password (refused): a PHP site that is not WordPress 409, a user who may not run the site 404, a "
       "stale password check 403 reauth; none reached the host",
       (r_php.status_code, r_view.status_code, r_step.status_code, _p9_json(r_step).get("error"), len(host.calls)),
       (409, 404, 403, "reauth_required", 0))


def _s1_step_text():
    from panel.services import website_app_admin as _a
    php = _a.reset_step()["argv"][-1]
    eq("reset admin password (the step): only an administrator is changed, it is signed out everywhere, WordPress's "
       "email-change mail is not sent, and plugins are not loaded",
       ("in_array('administrator', (array) $u->roles, true)" in php, "destroy_all()" in php,
        "send_email_change_email" in php, "--skip-plugins" in _a.reset_step()["argv"]), (True, True, True, True))


# ── 2. the page ───────────────────────────────────────────────────────────────────────────────────
def _harness330():
    h = _HARNESS301
    swaps = (
        ("El.prototype.click = ", "El.prototype.addEventListener = function (t, f) { (this._on = this._on || {})[t] = f; };\n"
         "El.prototype.fire = function (t) { if (this._on && this._on[t]) this._on[t]({}); };\nEl.prototype.click = "),
        ("setTimeout: function () { return 0; }, clearTimeout: function () {},",
         "setTimeout: function (f, ms) { timers.push([f, ms]); return timers.length; }, "
         "clearTimeout: function (i) { if (timers[i - 1]) timers[i - 1][0] = null; },"),
        ("  addEventListener: function () {}, body: root};",
         "  addEventListener: function (n, f) { (listeners[n] = listeners[n] || []).push(f); },\n"
         "  removeEventListener: function (n, f) { listeners[n] = (listeners[n] || []).filter(function (x) { return x !== f; }); },\n"
         "  hidden: false, body: root};"),
        ("const root = build(cfg.tree), clicked = [], calls = [], dialogs = [];",
         "const root = build(cfg.tree), clicked = [], calls = [], dialogs = [], timers = [], listeners = {}, copies = [];"),
        ("  confirmDialog: function (o) { dialogs.push(o); },",
         "  copyText: function (t) { copies.push(t); }, confirmDialog: function (o) { dialogs.push(o); },"),
        ("ctx.calls = calls;", "ctx.timers = timers; ctx.listeners = listeners; ctx.copies = copies; ctx.calls = calls;"),
    )
    for old, new in swaps:
        if h.count(old) != 1:
            raise AssertionError("part301's harness changed: %r" % old[:60])
        h = h.replace(old, new)
    return h


def _node330(page, scripts, scenario, routes):
    node = _shutil330.which("node")
    if not node:
        return {"error": "node is not installed"}
    tmp = _tf330.mkdtemp(prefix="p330-")
    try:
        path = os.path.join(tmp, "harness.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_harness330())
        cfg = {"tree": _tree301(page), "scripts": [os.path.join(_JS301, s) for s in scripts], "scenario": scenario,
               "routes": routes or {}, "search": ""}
        r = _sp330.run([node, path], input=_json330.dumps(cfg),  # nosec B603 - node on this part's harness
                       capture_output=True, text=True, timeout=120, check=False)
        try:
            return _json330.loads(r.stdout)
        except ValueError:
            return {"error": (r.stdout + r.stderr)[-1200:]}
    finally:
        _shutil330.rmtree(tmp, ignore_errors=True)


_MADE330 = "Generated-24-chars-here0"
# What each step of the page saw: the page's text after a step, whether the made password is in it, and the
# Show button's state.
_SCN_ADMIN330 = r"""
  for (let i = 0; i < 4; i++) await tick();
  const made = '%s';
  window.wsAdminOpen();
  for (let i = 0; i < 4; i++) await tick();
  const users = $('wadm-user').options.map(function (o) { return o.value; }), formShown = !$('wadm-form').hidden;
  $('wadm-user')._value = 'bob';
  $('wadm-email').value = ' new@example.org ';
  window.wsAdminReset({preventDefault: function () {}});
  for (let i = 0; i < 4; i++) await tick();
  const box = $('wadm-result'), show = box.querySelector('button[aria-pressed]');
  const btns = box.querySelectorAll('button');
  const masked = box.textContent;
  btns[1].fire('click');
  for (let i = 0; i < 4; i++) await tick();
  const afterCopy = box.textContent;
  show.fire('click');
  for (let i = 0; i < 4; i++) await tick();
  const shown = box.textContent, pressed = show.getAttribute('aria-pressed'), label = show.getAttribute('aria-label');
  const live = timers.filter(function (t) { return t[0]; });
  const wait = live.length ? live[live.length - 1][1] : null;
  if (live.length) live[live.length - 1][0]();
  const timedOut = box.textContent, pressedAfter = show.getAttribute('aria-pressed');
  show.fire('click');
  for (let i = 0; i < 4; i++) await tick();
  document.hidden = true;
  (listeners.visibilitychange || []).slice().forEach(function (f) { f(); });
  const hiddenTab = box.textContent;
  const posts = calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return [c[1], c[2]]; });
  return {users: users, formShown: formShown, posts: posts, masked: masked.indexOf(made) >= 0, maskDots: masked.indexOf('••••••••••••') >= 0,
          copies: copies, afterCopy: afterCopy.indexOf(made) >= 0, shown: shown.indexOf(made) >= 0, pressed: pressed, label: label,
          wait: wait, timedOut: timedOut.indexOf(made) >= 0, pressedAfter: pressedAfter, hiddenTab: hiddenTab.indexOf(made) >= 0};
""" % _MADE330


def _s2_page():
    from unit.part301 import _SITE301
    page = _page301("website.html", P9_ADMIN, site=_SITE301, can_manage=True, can_files=True, site_admin=True)
    routes = {"/api/websites/7": {"success": True, "site": {"id": 7, "name": "shop", "kind": "wordpress", "state": "running"},
                                  "databases": []},
              "/websites/7/app-admin/users": {"success": True, "users": ["alice", "bob"]},
              "/websites/7/app-admin/reset": {"success": True, "message": "Done.", "user": "bob", "password": _MADE330,
                                              "generated": True}}
    got = _node330(page, ["websites_common.js", "website_site.js", "secret_field.js", "website_app_admin.js"],
                   _SCN_ADMIN330, routes)
    check("reset admin password (node): the harness ran", "error" not in got, got.get("error"))
    eq("reset admin password (page): the button lists the administrators, then the form posts the chosen one, the typed "
       "email trimmed, an empty password (the panel makes one)",
       (got.get("users"), got.get("formShown"), got.get("posts")),
       (["alice", "bob"], True, [["/m/websites/7/app-admin/users", {}],
                                 ["/m/websites/7/app-admin/reset", {"user": "bob", "password": _NONE330, "email": "new@example.org"}]]))
    eq("stored secret on the page (a generated admin password): drawn as twelve dots, not in the page's text; Copy "
       "copies it without showing it",
       (got.get("masked"), got.get("maskDots"), got.get("copies"), got.get("afterCopy")), (False, True, [_MADE330], False))
    eq("stored secret on the page: Show puts it in the page's text, aria-pressed true, its label then Hide",
       (got.get("shown"), got.get("pressed"), got.get("label")), (True, "true", "Hide the password"))
    eq("stored secret on the page: a shown password hides again by itself after 30 seconds, and when the tab is hidden",
       (got.get("wait"), got.get("timedOut"), got.get("pressedAfter"), got.get("hiddenTab")), (30000, False, "false", False))


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _cleanup330():
    _db330.session.rollback()
    remotes = _ROWS330["remotes"] or [0]
    sites = sorted(set(_ROWS330["sites"]) | {s.id for s in _Site330.query.filter(_Site330.remote_id.in_(remotes))})
    _Audit330.query.filter(_Audit330.website_id.in_(sites or [0])).delete(synchronize_session=False)
    for model, ids in ((_Site330, sites), (_User330, _ROWS330["users"]), (_Remote330, _ROWS330["remotes"])):
        for i in ids:
            row = _db330.session.get(model, i)
            if row is not None:
                _db330.session.delete(row)
    _db330.session.commit()


def _ran330(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran330.last)."""
    import traceback
    try:
        step(*args)
        _ran330.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        from flask import has_app_context
        if has_app_context():
            _db330.session.rollback()
        _ran330.last = traceback.format_exc()[-1500:]
        return False


_ran330.last = ""
for _sec330 in (_s1_step_text, _s2_page):
    check("part330: %s ran to the end" % _sec330.__name__, _ran330(_sec330), _ran330.last)
_trips330 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part330")
        _r330, _su330, _vw330 = _rows330()

        class _St330:
            pass
        _st330 = _St330()
        _st330.su, _st330.vw = _Client330(_su330.id), _Client330(_vw330.id)
        _st330.wp = _site330(_r330, "p330wp", app_recipe="wordpress")
        _st330.php = _site330(_r330, "p330php", kind="php")
        for _sec330 in (_s1_list, _s1_reset, _s1_refused, _s1_who):
            check("part330: %s ran to the end" % _sec330.__name__, _ran330(_sec330, _st330), _ran330.last)
        eq("part330: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips330:], [])
    finally:
        _p9_restore_all()
        _cleanup330()
