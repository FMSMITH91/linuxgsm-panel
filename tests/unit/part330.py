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
3. Every other stored secret on a page: a site database's connection settings and a reset's new password, the
   object cache's password, a game server's Databases tab and the Databases page's dialog: masked until Show
   (aria-pressed), hidden again by itself; the reset dialog says what happens to the site's app.
4. The rewriter that gives an app's settings file the new database password (run over a scratch site): only the
   assignment holding the current password changes, the file keeps its mode, a read-only folder is read-only
   again, a file without the current password or a link is refused.
5. Reset password through the route: the app's settings first, then the database, then the site's database must
   answer the new password, then it is stored; each failure puts the old password back where it was changed; a
   database no app uses gets the warning and its new password in the no-store answer; a Node.js app's variable.

HOW IT RUNS. The routes through part12's app (its tripwire armed, so nothing reaches a host), the host's shell
answered here; the page's scripts in node over the rendered markup (part301's harness, with timers, listeners and
the clipboard recorded); a game server's Databases tab in part208's harness; the rewriter as bash over a scratch
home.
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
from unit.part208 import _fresh208
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

    def get(self, *a, **k):
        _g330.pop("_login_user", None)
        _g330.__dict__.pop("_websites_access_cache", None)
        return self.c.get(*a, **k)


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
         "El.prototype.insertBefore = function (n, ref) { if (n.parentNode) n.parentNode.removeChild(n); "
         "const i = this.children.indexOf(ref); this.children.splice(i < 0 ? this.children.length : i, 0, n); n.parentNode = this; return n; };\n"
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


# ── 3. stored secrets on the other pages ─────────────────────────────────────────────────────────
_SECRET330 = "Db-Secret-Value-77"
_APP_WORDS330 = "WordPress's settings get the new password; the site keeps working."
_SCN_SITE330 = r"""
  for (let i = 0; i < 4; i++) await tick();
  const made = '%s', dots = '••••••••••••', has = function (e) { return e.textContent.indexOf(made) >= 0; };
  const args = $('wdb-list').querySelectorAll('button[data-action="wsDbReset"]').map(function (b) { return JSON.parse(b.getAttribute('data-args')); });
  args.forEach(function (a) { window.wsDbReset.apply(null, a); });
  const bodies = dialogs.map(function (d) { return d.bodyText; });
  dialogs[1].onConfirm();
  for (let i = 0; i < 4; i++) await tick();
  const reset = $('wdb-conn-10');
  window.wsDbReveal(9);
  for (let i = 0; i < 4; i++) await tick();
  const conn = $('wdb-conn-9'), connMasked = !has(conn) && conn.textContent.indexOf(dots) >= 0 && conn.textContent.indexOf('ws7_app') >= 0;
  conn.querySelector('button[aria-pressed]').fire('click');
  for (let i = 0; i < 4; i++) await tick();
  const connShown = has(conn);
  const c = document.createElement('div'); c.id = 'wperf-obj-conn'; document.body.appendChild(c);
  window.wsCacheReveal();
  for (let i = 0; i < 4; i++) await tick();
  const cacheMasked = !has(c) && c.textContent.indexOf(dots) >= 0;
  c.querySelectorAll('button')[1].fire('click');
  for (let i = 0; i < 4; i++) await tick();
  return {bodies: bodies, resetMasked: !has(reset) && reset.textContent.indexOf(dots) >= 0, connMasked: connMasked,
          connShown: connShown, cacheMasked: cacheMasked, copies: copies};
""" % _SECRET330


def _s3_site_pages():
    from unit.part301 import _SITE301
    page = _page301("website.html", P9_ADMIN, site=_SITE301, can_manage=True, can_files=True, site_admin=True)
    conn = {"success": True, "host": "127.0.0.1", "port": 3306, "name": "ws7_app", "user": "ws7_app", "password": _SECRET330}
    routes = {"/api/websites/7": {"success": True, "site": {"id": 7, "name": "shop", "kind": "wordpress", "state": "running"},
                                  "databases": [{"id": 9, "name": "ws7_app", "user": "ws7_app", "app_settings": _APP_WORDS330},
                                                {"id": 10, "name": "ws7_own", "user": "ws7_own", "app_settings": ""}]},
              "/websites/7/databases/credentials": conn,
              "/websites/7/databases/10/reset-password": {"success": True, "message": "ok", "password": _SECRET330},
              "/websites/7/object-cache/credentials": {"success": True, "host": "127.0.0.1", "port": 6379,
                                                       "password": _SECRET330}}
    got = _node330(page, ["websites_common.js", "website_site.js", "secret_field.js", "website_tuning.js"], _SCN_SITE330,
                   routes)
    check("stored secrets (node, the site's Database and Performance tabs): the harness ran", "error" not in got,
          got.get("error"))
    eq("reset password (the site's Database tab): the app's database says what happens to the app (the server's words); "
       "one no app is known to use keeps the warning",
       got.get("bodies"), [_APP_WORDS330, "The site stops reaching the database until its settings have the new password."])
    eq("stored secrets (the site's Database tab): a reset's new password, the connection settings' password and the "
       "object cache's password are drawn as dots, not in the page's text, until Show; Copy copies without showing",
       (got.get("resetMasked"), got.get("connMasked"), got.get("connShown"), got.get("cacheMasked"), got.get("copies")),
       (True, True, True, True, [_SECRET330]))


def _s3_game_tab():
    got = _fresh208(
        "  const hides = []; global.secretHideLater = f => { hides.push(f); return () => { hides.cancelled = (hides.cancelled || 0) + 1; }; };\n"
        "  const eye = () => { let b = null; walk(document.getElementById('db-list'), e => {\n"
        "    if (e.attrs && e.attrs['data-action'] === 'dbReveal') b = e; }); return b; };\n"
        "  out.before = eye().attrs['aria-pressed'];\n"
        "  reply({success: true, password: 'REALPW'}); await dbReveal(4); await settle();\n"
        "  out.pressed = eye().attrs['aria-pressed']; out.shown = txt('db-list').includes('REALPW'); out.hides = hides.length;\n"
        "  hides[0](); await settle();\n"
        "  out.after = txt('db-list').includes('REALPW'); out.pressedAfter = eye().attrs['aria-pressed'];\n"
        "  reply({success: true, password: 'REALPW'}); await dbReveal(4); await settle(); await dbReveal(4);\n"
        "  out.cancelled = hides.cancelled || 0;\n")
    eq("stored secrets (a game server's Databases tab): Show is aria-pressed; a shown password is handed to the hiding "
       "by itself (secret_field.js), which masks it again; Hide cancels that",
       None if got is None else (got.get("before"), got.get("pressed"), got.get("shown"), got.get("hides"),
                                 got.get("after"), got.get("pressedAfter"), got.get("cancelled")),
       ("false", "true", True, 1, False, "false", 1))


_DBM_PAGE330 = ('<div id="dbm-modal"><h5 id="dbm-title"></h5><div id="dbm-msg"></div><button data-dbm-tab="conn"></button>'
                '<div data-dbm-pane="conn"><div id="dbm-conn"></div></div></div>')
_SCN_DBM330 = r"""
  const made = '%s';
  // The harness's selectors have no descendant combinator: the dialog's own lookups, read inside it.
  document.querySelectorAll = function (s) { return document.body.querySelectorAll(s.replace(/^#dbm-modal /, '')); };
  window.dbmOpen(3, 4, 'gs3_lp', '127.0.0.1', 3306);
  const eye = function () { return $('dbm-conn').querySelector('button[aria-pressed]'); };
  const before = $('dbm-conn').textContent.indexOf(made) >= 0;
  window.dbmReveal();
  for (let i = 0; i < 4; i++) await tick();
  const shown = $('dbm-conn').textContent.indexOf(made) >= 0, pressed = eye().getAttribute('aria-pressed');
  const live = timers.filter(function (t) { return t[0]; }), wait = live.length ? live[live.length - 1][1] : null;
  if (live.length) live[live.length - 1][0]();
  return {before: before, shown: shown, pressed: pressed, wait: wait, after: $('dbm-conn').textContent.indexOf(made) >= 0,
          pressedAfter: eye().getAttribute('aria-pressed')};
""" % _SECRET330


def _s3_manager():
    got = _node330(_DBM_PAGE330, ["secret_field.js", "databases_manager.js"], _SCN_DBM330,
                   {"/api/server/3/databases/4/reveal": {"success": True, "password": _SECRET330}})
    check("stored secrets (node, the Databases page's dialog): the harness ran", "error" not in got, got.get("error"))
    eq("stored secrets (the Databases page's dialog): masked, Show is aria-pressed, and a shown password is masked again "
       "after 30 seconds",
       (got.get("before"), got.get("shown"), got.get("pressed"), got.get("wait"), got.get("after"), got.get("pressedAfter")),
       (False, True, "true", 30000, False, "false"))


# ── 4. the app's settings get a reset password (the rewriter, over a scratch home) ───────────────
_OLD330 = "OldPw-1.a"
_NEW330 = "NewPw_2.b"


def _rewrite330(home, rec, old, new):
    from panel.services import website_db_password as _w
    _name, files, before = _w.APP_SETTINGS[rec]
    r = _sp330.run(["bash", "-c", _w.rewrite_sh(files, before)], input=_w.rewrite_stdin(old, new),  # nosec B603 B607
                       capture_output=True, text=True, timeout=60, check=False,
                       env={"HOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    return r.returncode, r.stdout.strip()


def _s4_rewriter():
    home = _tf330.mkdtemp(prefix="lgsm-unit-p330-")
    html = os.path.join(home, "site", "html")
    try:
        os.makedirs(os.path.join(html, "sites", "default"))
        wp = os.path.join(html, "wp-config.php")
        with open(wp, "w", encoding="utf-8") as fh:
            fh.write("<?php\ndefine( 'DB_USER', 'ws1_app' );\ndefine( 'DB_PASSWORD', '%s' );\n"
                     "define( 'AUTH_KEY', '%s' );\n" % (_OLD330, _OLD330 + "x"))
        os.chmod(wp, 0o440)
        dr = os.path.join(html, "sites", "default", "settings.php")
        with open(dr, "w", encoding="utf-8") as fh:
            fh.write("<?php\n$databases['default']['default'] = array (\n  'password' => '%s',\n);\n" % _OLD330)
        os.chmod(os.path.dirname(dr), 0o500)
        got = {"wp": _rewrite330(home, "wordpress", _OLD330, _NEW330), "drupal": _rewrite330(home, "drupal", _OLD330, _NEW330)}
        with open(wp, encoding="utf-8") as fh:
            wp_text = fh.read()
        modes = (oct(os.stat(wp).st_mode & 0o777), oct(os.stat(os.path.dirname(dr)).st_mode & 0o777))
        again = _rewrite330(home, "wordpress", _OLD330, _NEW330)
        eq("reset password (the app's settings, rewriter over a scratch site): WordPress's DB_PASSWORD and Drupal's "
           "'password' get the new password, nothing else in the file changes, the file keeps its mode and a read-only "
           "folder is read-only again", (got, "'DB_PASSWORD', '%s'" % _NEW330 in wp_text, _OLD330 + "x" in wp_text,
                                         wp_text.count(_NEW330), modes),
           ({"wp": (0, "SITE_DBPW_DONE"), "drupal": (0, "SITE_DBPW_DONE")}, True, True, 1, ("0o440", "0o500")))
        eq("reset password (rewriter, control: the settings do not hold the current password): refused, file unchanged",
           (again, open(wp, encoding="utf-8").read() == wp_text), ((35, "SITE_DBPW_NOT_FOUND"), True))
        if os.geteuid() != 0:
            os.chmod(os.path.dirname(dr), 0o700)
        os.remove(dr)
        os.symlink(wp, dr)
        eq("reset password (rewriter): a settings file that is a link is refused", _rewrite330(home, "drupal", _NEW330, _OLD330),
           (25, "SITE_FILES_REFUSED"))
    finally:
        for root, dirs, _files in os.walk(home):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700)
        _shutil330.rmtree(home, ignore_errors=True)


# ── 5. Reset password through the route, the app kept in step ─────────────────────────────────────
class _DbHost330:
    """The host as a reset sees it: the database's set_password and the site account's shell, each call kept."""

    def __init__(self, rewrite="SITE_DBPW_DONE\n", verify="verify=done\n", set_ok=True):
        self.rewrite, self.verify, self.set_ok, self.calls = rewrite, verify, set_ok, []

    def set_password(self, remote, hd, name, pw):
        self.calls.append(("db", pw))
        return self.set_ok, "Password changed."

    def as_site(self, remote, account, sh, timeout=120, stdin_text=None):
        if "panel-db-" in sh:
            old, new = (_b64_330.b64decode(x).decode() for x in (stdin_text or "").split()[:2])
            self.calls.append(("app", old, new, _OLD330 in sh or _NEW330 in sh))
            return "SITE_DBPW_DONE" in self.rewrite, self.rewrite
        if "information_schema" in sh:
            self.calls.append(("check", "val DB_PASSWORD %s" % _b64(_NEW330) in (stdin_text or "")))
            return "verify=done" in self.verify, self.verify
        self.calls.append(("other", sh[:40]))
        return False, ""


def _db_rows330(st, site, slug):
    from panel.db.models import GameDatabase, HostDatabaseServer
    if HostDatabaseServer.query.filter_by(remote_id=site.remote_id).first() is None:
        _db330.session.add(HostDatabaseServer(remote_id=site.remote_id, flavor="mariadb", port=3306))
    row = GameDatabase(remote_id=site.remote_id, game_server_id=None, website_id=site.id, name="ws%d_%s" % (site.id, slug),
                       secret=_cfg330.encrypt_secret(_OLD330))
    _db330.session.add(row)
    _db330.session.commit()
    return row


def _reset_run330(st, site, row, host):
    from panel.ops.ssh_manager import databases as _dbs
    _p9_patch(_dbs, "set_password", host.set_password)
    _p9_patch(_sw330, "_as_site", host.as_site)
    _p9_patch(_sw330, "_ids", lambda remote, s: ((1000, 1000), {}))
    from panel.services import website_db_password as _w
    _p9_patch(_dbs, "new_password", lambda: _NEW330)
    r = st.su.post("/websites/%d/databases/%d/reset-password" % (site.id, row.id), json={})
    _db330.session.expire_all()
    return r, _p9_json(r), _cfg330.decrypt_secret(row.secret), _w


def _s5_reset_routes(st):
    site = _site330(st.remote, "p330rs", app_recipe="wordpress")
    app_row, own_row = _db_rows330(st, site, "app"), _db_rows330(st, site, "own")
    listed = {d["name"]: d.get("app_settings") for d in _p9_json(st.su.get("/websites/%d/databases" % site.id))["databases"]}
    eq("reset password (GET /websites/<id>/databases): the app's database says WordPress's settings get the new password; "
       "a database no app is known to use says nothing", (listed.get(app_row.name), listed.get(own_row.name)),
       (_APP_WORDS330, ""))
    host = _DbHost330()
    r, body, stored, _w = _reset_run330(st, site, app_row, host)
    eq("reset password (the app's database, POST .../reset-password): the app's settings get it first (both passwords "
       "on stdin only), then the database, then the database must answer it from the site's network; then it is stored",
       (r.status_code, body.get("success"), "password" in body, host.calls, stored),
       (200, True, False, [("app", _OLD330, _NEW330, False), ("db", _NEW330), ("check", True)], _NEW330))
    eq("reset password (audit): kept in step, never the password",
       [(a, "kept in step" in d, _NEW330 in d or _OLD330 in d) for a, d, _ok in _audits330(site)[-1:]],
       [("website_db_password", True, False)])

    app_row.secret = _cfg330.encrypt_secret(_OLD330)
    _db330.session.commit()
    host = _DbHost330(verify="SITE_VERIFY_FAILED\ncheck=tables\n")
    r, body, stored, _w = _reset_run330(st, site, app_row, host)
    eq("reset password (the new password does not answer): the old one goes back to the database and the app's "
       "settings, the stored one stays, and the page is told so",
       (body.get("success"), host.calls, stored, "old one was put back" in (body.get("message") or "")),
       (False, [("app", _OLD330, _NEW330, False), ("db", _NEW330), ("check", True), ("db", _OLD330),
                ("app", _NEW330, _OLD330, False)], _OLD330, True))

    host = _DbHost330(rewrite="SITE_DBPW_NOT_FOUND\n")
    r, body, stored, _w = _reset_run330(st, site, app_row, host)
    eq("reset password (the app's settings do not hold the current password): nothing changed, the database untouched",
       (body.get("success"), [c[0] for c in host.calls], stored, "was not changed" in (body.get("message") or "")),
       (False, ["app"], _OLD330, True))

    host = _DbHost330(set_ok=False)
    r, body, stored, _w = _reset_run330(st, site, app_row, host)
    eq("reset password (the database refuses it): the app's settings get the old password back",
       (body.get("success"), [c[:3] for c in host.calls], stored),
       (False, [("app", _OLD330, _NEW330), ("db", _NEW330), ("app", _NEW330, _OLD330)], _OLD330))

    host = _DbHost330()
    r, body, stored, _w = _reset_run330(st, site, own_row, host)
    eq("reset password (control: a database no app is known to use): the database alone, the new password in the "
       "no-store answer for the page to show masked, and the warning",
       (body.get("success"), host.calls, body.get("password"), r.headers.get("Cache-Control"), stored,
        "must be given it" in (body.get("message") or "")),
       (True, [("db", _NEW330)], _NEW330, "no-store", _NEW330, True))


def _s5_env_app(st):
    site = _site330(st.remote, "p330node", kind="app", runtime="node", runtime_version="22",
                    env_enc=_cfg330.encrypt_secret(_json330.dumps({"DB_PASS": _OLD330, "OTHER": "x"})))
    row = _db_rows330(st, site, "main")
    seen = []

    def env_apply(remote, s, restart=True):
        seen.append(_json330.loads(_cfg330.decrypt_secret(s.env_enc)))
        return True, "The app's variables were written and it was restarted."
    _p9_patch(_sw330, "env_apply", env_apply)
    host = _DbHost330()
    _r, body, stored, _w = _reset_run330(st, site, row, host)
    eq("reset password (a Node.js app whose variable holds the password): the database first, then the variable gets the "
       "new password and the app is restarted; the other variables stay",
       (body.get("success"), host.calls, seen, stored, "DB_PASS" in (body.get("message") or "")),
       (True, [("db", _NEW330)], [{"DB_PASS": _NEW330, "OTHER": "x"}], _NEW330, True))


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
for _sec330 in (_s1_step_text, _s2_page, _s3_site_pages, _s3_game_tab, _s3_manager, _s4_rewriter):
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
        _st330.remote = _r330
        for _sec330 in (_s1_list, _s1_reset, _s1_refused, _s5_reset_routes, _s5_env_app, _s1_who):
            check("part330: %s ran to the end" % _sec330.__name__, _ran330(_sec330, _st330), _ran330.last)
        eq("part330: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips330:], [])
    finally:
        _p9_restore_all()
        _cleanup330()
