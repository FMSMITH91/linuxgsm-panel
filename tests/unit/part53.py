"""Part 53 of the unit suite: the 2026-10-11 review's routes, installer, tools and page fixes (builder C).

Held here, each against the code path the finding named:

* routes: the panel's bind address judged as an ADDRESS (any spelling of ::1 is loopback, and is
  stored canonical); ssh-mode, the backup passphrase, the repair `paths` and a game's backup
  schedule refuse a value of the wrong type or shape with a 400 instead of a 500 or a widened
  default; the panel host is not login-tested over SSH; a bootstrap with a bad timezone is refused
  before its audit row; Funnel is on only for a literal true; Add Remote's "existing server" answers
  a fetch with where to go; a command's stored engine scope survives a save.
* pages: base.html's panel-host control and palette flags; the invite card always there for a
  superadmin; the install page's Retry only for a superadmin; no user-named host, server or peer
  as a bare text node the translator can reach.
* scripts, run in node against stubs (as part47 does): the ajax-form after-hook and `go`; Load
  older and a priming window restarting an in-flight catch-up; the panel host's reboot banner for
  a delegate; the reboot watch's reload; the OS-update poll's failures; the palette's retry and
  `need`; the Add form's reset; the file editor's latest open; the game list's in-place refresh;
  js_coverage's settleDialogs never pressing a reboot.
* tools: install.sh's firewall probe and auto-open with an operator's rule on the port; the fake
  host listing a `find -H`; a flow's own check failing the coverage run; serve.py's subprocess
  shim list; lhci_serve's cleanup; the i18n scanners' expression labels and one-word UI strings.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node and bash on this part's own fixtures.
"""
import ast as _ast53
import contextlib as _ctx53
import importlib.util as _ilu53
import io as _io53
import os
import re as _re53
import shutil as _shutil53
import subprocess as _sp53  # nosec B404 - runs bash on install.sh's own blocks
import sys as _sys53
import tempfile as _tf53
from types import SimpleNamespace as _NS53

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_LOCAL, _P9_CFG_PATH, _p9, _p9_cfg, _p9_client,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_so)
from unit.part47 import _cut47, _node47
from panel.db.models import AuditLog, CustomCommand, Group, RemoteServer, User, db
from panel.ops import backup as _bk53
from panel.routes import custom_commands as _cc53
from panel.routes import remote_bootstrap as _rb53
from panel.routes import remote_security as _rs53
from panel.routes import remote_vps as _rv53
from panel.routes import remotes as _rm53
from panel.routes import tailscale as _ts53
from panel.security import auth as _auth53

_JS53 = os.path.join(_root, "static", "js")
_TPL53 = os.path.join(_root, "templates")
_CFG53_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
_mine53 = {"remotes": [], "users": [], "groups": [], "commands": []}
# The stored hash of the users this part makes: no password hashes to it, so none can log in.
_NO_LOGIN53 = "x"


def _read53(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _audits53(action):
    with _p9.app_context():
        return [(a.target, a.detail) for a in AuditLog.query.filter_by(action=action)
                .order_by(AuditLog.id).all()]


def _node53(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


_A53 = _p9_client(P9_ADMIN)
try:
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 1. routes
    # ════════════════════════════════════════════════════════════════════════════════════════════

    # ── the panel's bind address is an ADDRESS ─────────────────────────────────────────────────
    _p9_patch(_p9_so, "host_has_ip", lambda ip: True)
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _p9_patch(_p9_so, "restart_panel", lambda: (True, "scheduled"))
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda *a, **k: (True, "jail updated"))
    _p9_patch(_rs53, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
    _p9_patch(_rs53, "remote_ufw_close_port", lambda *a, **k: (True, "ok"))
    _spell53 = {b: _rs53._bind_refusal(False, b) for b in ("0:0:0:0:0:0:0:1", "0::1", "::1", "127.0.0.1")}
    check("change-port: any spelling of ::1 is loopback, refused without Tailscale Serve (the text test "
          "let 0:0:0:0:0:0:0:1 bind the panel to loopback with nothing in front of it)",
          all(_v and "lock you out" in _v for _v in _spell53.values()), repr(_spell53))
    check("change-port: ...and a host's own non-loopback address is still allowed (control)",
          _rs53._bind_refusal(False, "192.0.2.5") is None, repr(_rs53._bind_refusal(False, "192.0.2.5")))
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, bind_host="0.0.0.0",  # nosec B104 - a stored value
                             tailscale_setup_done=False))
    _r53 = _A53.post("/api/panel/change-port", json={"port": 5000, "bind_host": "0::1"})
    check("change-port: the route refuses 0::1 without Serve, and saves nothing",
          _r53.status_code == 400 and _p9_cfg.load_config().get("bind_host") == "0.0.0.0",  # nosec B104
          repr((_r53.status_code, _p9_json(_r53), _p9_cfg.load_config().get("bind_host"))))
    _r53 = _A53.post("/api/panel/change-port", json={"port": 5000, "bind_host": "0:0:0:0:0:0:0:0"})
    check("change-port: a bind is stored in canonical form (0:0:0:0:0:0:0:0 is the wildcard ::)",
          _p9_json(_r53).get("success") is True and _p9_cfg.load_config().get("bind_host") == "::",
          repr((_p9_json(_r53), _p9_cfg.load_config().get("bind_host"))))

    # ── ssh-mode: a validated mode, or a 400 ─────────────────────────────────────────────────────
    _ssh53 = []
    _p9_patch(_rv53, "remote_set_public_ssh", lambda remote, mode: (_ssh53.append(mode) or (True, "ok")))
    _n53 = len(_audits53("remote_ssh_mode"))
    _bad53 = [_A53.post("/api/remote/%d/ssh-mode" % P9_HOST, json={"mode": _m}).status_code
              for _m in (1, {"a": 1}, "x" * 200, "")]
    check("ssh-mode: a non-string or unknown mode is a 400 (an int was a 500), the helper is not asked, "
          "and nothing is written to the audit trail",
          _bad53 == [400] * 4 and _ssh53 == [] and len(_audits53("remote_ssh_mode")) == _n53,
          repr((_bad53, _ssh53, _audits53("remote_ssh_mode")[_n53:])))
    _r53 = _A53.post("/api/remote/%d/ssh-mode" % P9_HOST, json={"mode": " LIMIT "})
    check("ssh-mode: ...while a real one is acted on and audited as what was done (control)",
          _p9_json(_r53).get("success") is True and _ssh53 == ["limit"]
          and _audits53("remote_ssh_mode")[-1][0] == "p9-host:limit",
          repr((_p9_json(_r53), _ssh53, _audits53("remote_ssh_mode")[-1:])))

    # ── the backup passphrase is text ────────────────────────────────────────────────────────────
    _pp53 = []
    _p9_patch(_bk53, "set_passphrase", _pp53.append)
    _bad53 = [_A53.post("/api/panel/backup/settings", json={"passphrase": _p}).status_code
              for _p in (1234567890123, ["a"] * 12, {"k": "v" * 12})]
    check("backup settings: a passphrase that is not text is a 400, never a 500, and nothing is set",
          _bad53 == [400] * 3 and _pp53 == [], repr((_bad53, _pp53)))
    _typed53 = "  twelve chars ok  "
    _r53 = _A53.post("/api/panel/backup/settings", json={"passphrase": _typed53})
    check("backup settings: ...and a text passphrase is set exactly as typed, spaces kept (control)",
          _r53.status_code == 200 and _pp53 == [_typed53], repr((_r53.status_code, _pp53)))

    # ── repair: a malformed `paths` is not "restore everything" ──────────────────────────────────
    _rep53 = []
    _p9_patch(_p9_so, "panel_repair", lambda paths: (_rep53.append(paths) or (True, "ok", [])))
    _bad53 = [_A53.post("/api/panel/repair", json={"paths": _p}).status_code
              for _p in ("app.py", {"app.py": 1}, 7)]
    check("panel repair: a `paths` that is not a list is refused, not read as restore-all",
          _bad53 == [400] * 3 and _rep53 == [], repr((_bad53, _rep53)))
    _A53.post("/api/panel/repair", json={"paths": ["app.py"]})
    _A53.post("/api/panel/repair", json={})
    check("panel repair: ...a list restores those files and an empty body restores all (control)",
          _rep53 == [["app.py"], None], repr(_rep53))

    # ── a game's backup schedule: unreadable is refused, not "clear the override" ────────────────
    _sch53 = []
    _p9_patch(_bk53, "set_game_schedule",
              lambda sid, iv, kp: (_sch53.append((iv, kp)) or {"interval_days": iv, "keep": kp}))
    _url53 = "/api/panel/backup/game/%d/schedule" % P9_GS
    _bad53 = [_A53.post(_url53, json=_b).status_code
              for _b in ({"interval": "7d"}, {"keep": "five"}, {"interval": 7, "keep": [3]})]
    check("backup schedule: a value that is not a number is a 400, and the override is left alone "
          "(it was cleared, resetting the server to the global schedule)",
          _bad53 == [400] * 3 and _sch53 == [], repr((_bad53, _sch53)))
    _A53.post(_url53, json={"interval": "7"})
    _A53.post(_url53, json={"keep": ""})
    check("backup schedule: ...a number is set and an empty box still clears it (control)",
          _sch53 == [(7, _bk53.UNCHANGED), (_bk53.UNCHANGED, None)], repr(_sch53))

    # ── the panel host is not login-tested over SSH ──────────────────────────────────────────────
    _tst53 = []
    _p9_patch(_rm53, "ssh_test_connection", lambda *a, **k: (_tst53.append(a[:4]) or (False, "refused")))
    with _p9.app_context():
        _loc53 = db.session.get(RemoteServer, P9_LOCAL)
        _loc53.is_online = True
        db.session.commit()
    _r53 = _A53.post("/remotes/%d/test" % P9_LOCAL, headers={"X-Requested-With": "XMLHttpRequest"})
    with _p9.app_context():
        _on53 = db.session.get(RemoteServer, P9_LOCAL).is_online
    check("test connection: the panel host is refused, not SSH-tested — the test always failed there "
          "and marked the panel host offline",
          _r53.status_code == 400 and _tst53 == [] and _on53 is True, repr((_r53.status_code, _tst53, _on53)))
    _A53.post("/remotes/%d/test" % P9_HOST, headers={"X-Requested-With": "XMLHttpRequest"})
    check("test connection: ...a remote is still tested (control)",
          len(_tst53) == 1 and _tst53[0][0] == "192.0.2.10", repr(_tst53))
    with _p9.app_context():
        db.session.get(RemoteServer, P9_HOST).is_online = True
        db.session.commit()

    # ── a bootstrap with a bad timezone or account is refused before its audit row ───────────────
    _boot53 = []
    _p9_patch(_rb53, "_begin_bootstrap", lambda *a, **k: (_boot53.append(a[2]) or (True, "")))
    _n53 = len(_audits53("remote_bootstrap"))
    _bad53 = [_A53.post("/api/remote/%d/bootstrap" % P9_HOST, json=_b).status_code
              for _b in ({"timezone": "Not/A Zone; rm"}, {"lgsm_user": "root$(id)"}, {"timezone": 5})]
    check("bootstrap: a timezone or account the worker would refuse is refused by the route, before "
          "anything starts or is audited (its text was written into the audit row first)",
          _bad53 == [400] * 3 and _boot53 == [] and len(_audits53("remote_bootstrap")) == _n53,
          repr((_bad53, _boot53, _audits53("remote_bootstrap")[_n53:])))
    _r53 = _A53.post("/api/remote/%d/bootstrap" % P9_HOST, json={"timezone": "Etc/UTC", "lgsm_user": "csgo"})
    check("bootstrap: ...valid options start it and are audited (control)",
          _p9_json(_r53).get("started") is True and len(_boot53) == 1
          and len(_audits53("remote_bootstrap")) == _n53 + 1, repr((_p9_json(_r53), _boot53)))

    # ── Funnel only for a literal true ───────────────────────────────────────────────────────────
    _fun53 = []
    _p9_patch(_ts53, "_serve_enable", lambda port, mount, funnel, page: (_fun53.append(funnel)
                                                                         or _ts53.jsonify({"success": True})))
    for _f53 in ("false", "0", 1, True):
        _A53.post("/api/tailscale/serve", json={"action": "enable", "mount": "/", "funnel": _f53})
    check("tailscale serve: Funnel (public exposure) is on only for a JSON true — the string \"false\" "
          "turned it on",
          _fun53 == [False, False, False, True], repr(_fun53))

    # ── Add Remote, existing server: a fetch is told where to go ─────────────────────────────────
    _p9_patch(_rm53, "ssh_test_connection", lambda *a, **k: (True, "ok"))
    _form53 = {"name": "p53-existing", "host": "192.0.2.53", "ssh_user": "root", "ssh_port": "22",
               "auth_method": "key", "credential": "~/.ssh/id_rsa", "setup_type": "existing"}
    _r53 = _A53.post("/remotes/add", data=_form53, headers={"X-Requested-With": "XMLHttpRequest"})
    with _p9.app_context():
        _new53 = RemoteServer.query.filter_by(name="p53-existing").first()
        _new53_id = _new53.id if _new53 else None
    if _new53_id:
        _mine53["remotes"].append(_new53_id)
    check("add remote (existing server): a fetch gets JSON naming the scan to go to, not a followed "
          "302 the page read as \"Not permitted\"",
          _r53.status_code == 200 and _r53.is_json and _p9_json(_r53).get("success") is True
          and _p9_json(_r53).get("go") == "/remote/%s/manage?scan=1" % _new53_id,
          repr((_r53.status_code, _r53.headers.get("Location"), _r53.get_data(as_text=True)[:200])))
    _r53 = _A53.post("/remotes/add", data=dict(_form53, name="p53-existing2", host="192.0.2.54"))
    with _p9.app_context():
        _new53b = RemoteServer.query.filter_by(name="p53-existing2").first()
        if _new53b:
            _mine53["remotes"].append(_new53b.id)
    check("add remote (existing server): ...a plain form post is still redirected to the scan (control)",
          _r53.status_code == 302 and _r53.headers.get("Location", "").endswith("/manage?scan=1"),
          repr((_r53.status_code, _r53.headers.get("Location"))))

    # ── a command's stored engine scope survives a save ──────────────────────────────────────────
    import app as _app53
    _p9_patch(_cc53, "load_game_list", lambda *a, **k: [])
    _stored53 = _NS53(scope_type="engine", scope_value="retiredengine")
    _form53 = {"name": "x", "command_template": "say hi", "scope": "engine|retiredengine"}
    with _p9.test_request_context("/", method="POST", data=_form53):
        _kept53 = _app53._custom_cmd_form(_stored53)
        _new53c = _app53._custom_cmd_form(None)
    check("custom command: an engine scope the list no longer names is kept on an unrelated save (the "
          "form selected \"All games\" and Save widened it)",
          _kept53[1] is None and _kept53[0].get("scope_value") == "retiredengine"
          and _new53c[0] is None and "valid engine" in (_new53c[1] or ""), repr((_kept53, _new53c)))
    with _p9.app_context():
        _cmd53 = CustomCommand(name="p53cmd", command_template="say hi", scope_type="engine",
                               scope_value="retiredengine", enabled=True)
        db.session.add(_cmd53)
        db.session.commit()
        _mine53["commands"].append(_cmd53.id)
    _page53 = _A53.get("/commands").get_data(as_text=True)
    check("custom command: ...and the edit form offers that engine, selected",
          _re53.search(r'<option value="engine\|retiredengine" selected data-no-i18n>retiredengine</option>',
                       _page53) is not None, _page53[:0] + "option not found")

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 2. pages
    # ════════════════════════════════════════════════════════════════════════════════════════════
    with _p9.app_context():
        _g53 = Group(name="p53_hostadmins", description="", is_default=False)
        _g53.set_permissions([_auth53.MANAGE_REMOTES])
        _g53.servers.append(db.session.get(RemoteServer, P9_LOCAL))
        db.session.add(_g53)
        db.session.flush()
        _u53 = User(username="p53_hostadmin", password_hash=_NO_LOGIN53, display_name="Host admin",
                    is_superadmin=False, is_active=True)
        _u53.groups.append(_g53)
        db.session.add(_u53)
        db.session.commit()
        _mine53["groups"].append(_g53.id)
        _mine53["users"].append(_u53.id)
        _U53 = _u53.id
    _D53 = _p9_client(_U53)
    _dash_a53 = _A53.get("/").get_data(as_text=True)
    _dash_d53 = _D53.get("/").get_data(as_text=True)
    check("base.html: the panel host's reboot controls are a superadmin's (LOCAL_HOST_CTL), while a "
          "delegated host admin still gets its banner (LOCAL_HOST_ID)",
          "window.LOCAL_HOST_CTL = true;" in _dash_a53 and "window.LOCAL_HOST_CTL = false;" in _dash_d53
          and ("window.LOCAL_HOST_ID = %d;" % P9_LOCAL) in _dash_d53,
          repr([_l.strip() for _l in _dash_d53.splitlines() if "LOCAL_HOST" in _l]))
    _can53 = [_re53.search(r"window\.PALETTE_CAN = \{\s*superadmin: (\w+),\s*edit_tags: (\w+)", _p)
              for _p in (_dash_a53, _dash_d53)]
    check("base.html: the palette is told which stricter-gated cards this user is shown",
          [(_m.group(1), _m.group(2)) if _m else None for _m in _can53]
          == [("true", "true"), ("false", "false")], repr([_m and _m.groups() for _m in _can53]))
    from panel.routes import users as _us53
    _p9_patch(_us53, "_invite_listing", lambda: [])
    _users53 = _A53.get("/users").get_data(as_text=True)
    check("users page: a superadmin with no invites still has the Invite links card the palette lands "
          "on, saying there are none",
          'id="sec-invites"' in _users53 and "No invite links yet." in _users53,
          repr('id="sec-invites"' in _users53))

    from panel.routes import manage_servers as _ms53
    _p9_patch(_ms53, "load_game_list", lambda *a, **k: [])
    with _p9.app_context():
        _g53i = Group(name="p53_installers", description="", is_default=False)
        _g53i.set_permissions([_auth53.INSTALL_SERVER, _auth53.MANAGE_SERVERS])
        _g53i.servers.append(db.session.get(RemoteServer, P9_HOST))
        db.session.add(_g53i)
        db.session.flush()
        _u53i = User(username="p53_installer", password_hash=_NO_LOGIN53, display_name="Installer",
                     is_superadmin=False, is_active=True)
        _u53i.groups.append(_g53i)
        db.session.add(_u53i)
        db.session.commit()
        _mine53["groups"].append(_g53i.id)
        _mine53["users"].append(_u53i.id)
        _I53 = _u53i.id
    _ins_a53 = _A53.get("/servers/install").get_data(as_text=True)
    _ins_i53 = _p9_client(_I53).get("/servers/install").get_data(as_text=True)
    check("install page: with no game list, Retry is offered to a superadmin only (the refresh route is "
          "superadmin-only, so anyone else got \"administrators only\")",
          ">Retry</button>" in _ins_a53 and ">Retry</button>" not in _ins_i53
          and "Ask a superadmin to retry fetching it." in _ins_i53,
          repr(("Retry" in _ins_a53, "Retry" in _ins_i53, "Couldn't load" in _ins_i53)))

    # A user-authored name as a whole text node is a catalog key the page's translator swaps: a host
    # called "Server" read "Servidor" in its own page's title. Each must sit in a data-no-i18n element.
    _NAME53 = _re53.compile(r"\{\{\s*(?:server|gs|srv|remote|r|peer|g)\.(?:name|display_name|hostname)\s*\}\}")

    def _bare_names53():
        bad = []
        for fname in sorted(os.listdir(_TPL53)):
            if not fname.endswith(".html"):
                continue
            src = _read53(_TPL53, fname)
            for m in _NAME53.finditer(src):
                before = src[:m.start()]
                lt, gt = before.rfind("<"), before.rfind(">")
                if lt > gt:
                    continue                  # inside a tag: an attribute value
                after = src[m.end():]
                strip = lambda t: _re53.sub(r"\{%.*?%\}|\{#.*?#\}", "", t, flags=_re53.S).strip()  # noqa: E731
                if strip(before[gt + 1:]) or strip(after[:after.find("<")]):
                    continue                  # part of a longer text node, never matched whole
                tag = before[lt:gt + 1]
                if tag.startswith("</") or "data-no-i18n" not in tag:
                    bad.append("%s:%d" % (fname, src.count("\n", 0, m.start()) + 1))
        return bad
    _bare53 = _bare_names53()
    check("templates: no host, server or peer name is a bare text node the translator can swap",
          not _bare53, repr(_bare53))

    # ── js_coverage's fake host lists the folder browse_dir asks for ─────────────────────────────
    # browse_dir has passed `find -H` since #403, and the fake host's pattern had no room for it:
    # every folder listed empty, so the walk's rename flow found no row (broken on main since).
    _spec53 = _ilu53.spec_from_file_location("jscov53_fake_host",
                                             os.path.join(_root, "tools", "js_coverage", "fake_host.py"))
    _fh53 = _ilu53.module_from_spec(_spec53)
    _spec53.loader.exec_module(_fh53)
    from panel.ops.ssh_manager import _core as _core53
    from panel.ops.ssh_manager import files as _files53
    _sent53 = []
    _p9_patch(_core53, "shell_as_game_user", lambda server, user, sh, timeout=30, selfname=None:
              (_sent53.append(sh) or ("", "", 0)))
    _files53.browse_dir(_NS53(host="h", is_local=False), "mcserver", "")
    _ans53 = _fh53.answer(_sent53[-1])[0] if _sent53 else ""
    check("js coverage: the fake host answers the file browser's real listing command with the "
          "home's files (it listed nothing for `find -H`)",
          "notes.txt" in _ans53 and "serverfiles" in _ans53, repr((_sent53[-1:], _ans53[:120])))
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _rid in _mine53["remotes"]:
            _row = db.session.get(RemoteServer, _rid)
            if _row is not None:
                db.session.delete(_row)
        for _cid in _mine53["commands"]:
            _row = db.session.get(CustomCommand, _cid)
            if _row is not None:
                db.session.delete(_row)
        for _uid in _mine53["users"]:
            _row = db.session.get(User, _uid)
            if _row is not None:
                db.session.delete(_row)
        for _gid in _mine53["groups"]:
            _row = db.session.get(Group, _gid)
            if _row is not None:
                db.session.delete(_row)
        db.session.commit()
    if _CFG53_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG53_SNAPSHOT)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. scripts, in node
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SETTLE53 = "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
_PANEL53 = _read53(_JS53, "panel.js")
_SD53 = _read53(_JS53, "server_detail.js")
_NAGS53 = _read53(_JS53, "nags.js")

# ── the ajax-form after-hook goes through _actionFn; `go` is a path on this panel ────────────────
_name53 = "ajax form: the after-hook and go"
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; const calls = [], gone = [];\n"
    "global.location = {assign: u => gone.push(u)};\n"
    "global.myHook = function(){ calls.push('myHook'); };\n"
    "global.sessionExpired = function(){ calls.push('sessionExpired'); };\n"
    "global.refreshSection = () => calls.push('refresh');\n"
    + _PANEL53[_PANEL53.index("var _ACTION_DENY"):_PANEL53.index("// ── Live cross-user updates")] + "\n"
    + (_cut47(_PANEL53, "function _r11c_goPath(") if "function _r11c_goPath(" in _PANEL53 else "") + "\n"
    + _cut47(_PANEL53, "function _ajaxFormSucceeded(") + "\n"
    "const form = after => ({getAttribute: n => n === 'data-ajax-after' ? after : null,\n"
    "  reset(){}, closest: () => null});\n"
    "for (const a of ['sessionExpired', 'myHook']) _ajaxFormSucceeded(form(a), {d: {success: true}});\n"
    "for (const g of ['/remote/5/manage?scan=1', '//evil.example/x', '/\\\\evil.example', 'https://evil.example/'])\n"
    "  _ajaxFormSucceeded(form(null), {d: {success: true, go: g}});\n"
    "console.log(JSON.stringify({calls, gone}));\n"))
if _out53 is not None:
    check("ajax form: a data-ajax-after hook runs through _actionFn on the no-refresh path too — a denied "
          "name (sessionExpired) is refused, an ordinary hook runs",
          _out53.get("calls") == ["myHook"], repr(_out53))
    check("ajax form: a success's `go` is followed only to a path on this panel, never another origin",
          _out53.get("gone") == ["/remote/5/manage?scan=1"], repr(_out53))

# ── Load older, and a priming window, while a catch-up is in flight ──────────────────────────────
_name53 = "console: a rebuild restarts an in-flight catch-up"
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.toast = () => 0;\n"
    "var _resync = null, _logAt = [0, 1, 100], _consoleLines = [], _consolePrimed = false, _consoleSig = 'x';\n"
    "var _returnOwed = false, _primeOwed = false, restarted = [], primed = 0;\n"
    "var consoleEl = {innerHTML: ''}, socket = {connected: true};\n"
    "function _rebuildMark(){ return 'm'; } function _rebuildRestore(){} function _renderPanelLines(){}\n"
    "function _loadOlderRows(x){ return x || []; }\n"
    "function _appendConsoleRows(rows, ts, at){ _logAt = Array.isArray(at) ? at : null; }\n"
    "function _startResync(prime){ restarted.push([prime, _logAt]); }\n"
    "function _primeCatchUp(){ primed++; }\n"
    + (_cut47(_SD53, "function _r11c_resyncFrom(") if "function _r11c_resyncFrom(" in _SD53 else "") + "\n"
    + _cut47(_SD53, "function loadMoreConsole(") + "\n" + _cut47(_SD53, "function _primeAt(") + "\n"
    "global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve(\n"
    "  {lines: [{t: null, line: 'a'}], at: [0, 1, 500]})});\n"
    "(async () => {\n"
    "  const out = {};\n"
    "  _resync = {prime: false}; loadMoreConsole(null); await settle(); out.older = restarted.splice(0);\n"
    "  _resync = null; loadMoreConsole(null); await settle(); out.olderIdle = restarted.splice(0);\n"
    "  _resync = {prime: false}; _returnOwed = true; _primeAt([0, 2, 10], 'm'); out.prime = restarted.splice(0);\n"
    "  _resync = null; _primeAt([0, 2, 20], 'm'); out.primeIdle = [restarted.splice(0), primed];\n"
    "  _returnOwed = false; _primeAt([0, 2, 30], 'm'); out.primeFresh = [restarted.splice(0), primed];\n"
    "  console.log(JSON.stringify(out));\n"
    "})();\n"))
if _out53 is not None:
    check("console: Load older pressed during a catch-up asks it again from where the rebuilt console "
          "ends (its answer appended from the OLD place, showing those lines twice)",
          _out53.get("older") == [[False, [0, 1, 500]]] and _out53.get("olderIdle") == [], repr(_out53))
    check("console: ...and a priming window (after Clear) restarts a return's catch-up already in "
          "flight from the window's place",
          _out53.get("prime") == [[False, [0, 2, 10]]], repr(_out53))
    check("console: ...while with none in flight a priming window changes nothing it did (control)",
          _out53.get("primeIdle") == [[], 0] and _out53.get("primeFresh") == [[], 1], repr(_out53))

# ── the panel host's reboot banner, for a delegate ───────────────────────────────────────────────
_name53 = "reboot banner: no panel-host buttons for a delegate"
_out53 = _node53(_name53, (
    "global.window = global;\n"
    "function mk(tag, cls, text){ return {tag, cls, text, children: [], style: {},\n"
    "  appendChild(c){ this.children.push(c); }, setAttribute(){} }; }\n"
    "global.document = {createTextNode: t => ({text: t})};\n"
    "function _rbEl(tag, cls, text){ return mk(tag, cls, text); }\n"
    "function _rbHost(l){ return {text: l}; }\n"
    "function _rbButton(text){ return {button: text}; }\n"
    + _NAGS53[_NAGS53.index("var _RB_PHASE"):_NAGS53.index("};", _NAGS53.index("var _RB_PHASE")) + 2] + "\n"
    + (_cut47(_NAGS53, "function _r11c_rbStateOnly(") if "function _r11c_rbStateOnly(" in _NAGS53 else "") + "\n"
    + _cut47(_NAGS53, "window.rebootNagRender = function(") + "\n"
    "const btns = n => !n || typeof n !== 'object' ? 0\n"
    "  : (n.button ? 1 : 0) + (n.children || []).reduce((a, c) => a + btns(c), 0);\n"
    "const render = (host, ctl, d) => { window.LOCAL_HOST_ID = 5; window.LOCAL_HOST_CTL = ctl;\n"
    "  const el = mk('div'); el.textContent = ''; rebootNagRender(el, host, 'x', d); return btns(el); };\n"
    "console.log(JSON.stringify({\n"
    "  delegate: [render(5, false, {required: true}), render(5, false, {pending_empty: true}),\n"
    "             render(5, false, {job: {phase: 'warning', sent: false}})],\n"
    "  admin: [render(5, true, {required: true}), render(5, true, {pending_empty: true})],\n"
    "  remote: render(7, false, {required: true})}));\n"))
if _out53 is not None:
    check("reboot banner: a delegated host admin sees the panel host's state with no Reboot, Wait or "
          "Cancel button (each ended in a 403 toast)",
          _out53.get("delegate") == [0, 0, 0], repr(_out53))
    check("reboot banner: ...a superadmin keeps them, and a delegate keeps a remote's (control)",
          _out53.get("admin") == [2, 2] and _out53.get("remote") == 2, repr(_out53))

# ── the reboot watch reloads after a failed read only while a reboot is under way ───────────────
_name53 = "reboot watch: one failed read on an idle page does not reload it"
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; global.MOUNT = ''; let reloads = 0; const q = [];\n"
    "global.location = {reload: () => reloads++};\n"
    "global.setTimeout = fn => { q.push(fn); return q.length; }; global.clearTimeout = () => 0;\n"
    "global.document = {hidden: false, getElementById: () => ({})};\n"
    "var _rbPolls = {}; let answers = [];\n"
    "function _rbRenderState(box, h, l, local, st){ return !!st.job; }\n"
    "global.fetch = () => { const a = answers.shift(); return a === 'fail' ? Promise.reject(new Error('502'))\n"
    "  : Promise.resolve({ok: true, json: () => Promise.resolve(a)}); };\n"
    + _cut47(_NAGS53, "window.rebootStateWatch = function(") + "\n"
    "const run = async (seq) => { answers = seq.slice(); reloads = 0; q.length = 0;\n"
    "  rebootStateWatch(1, 'x', true); await settle();\n"
    "  for (let i = 0; i < 5 && q.length; i++) { q.shift()(); await settle(); } return reloads; };\n"
    "(async () => { console.log(JSON.stringify({\n"
    "  idle: await run(['fail', {}]),\n"
    "  rebooting: await run([{job: {phase: 'preflight'}}, 'fail', {}])})); })();\n"))
if _out53 is not None:
    check("reboot watch: on the panel host, one failed read on an idle page does not reload it 10 s "
          "later (losing what was typed), while a failure during a reboot still does",
          _out53 == {"idle": 0, "rebooting": 1}, repr(_out53))

# ── the OS-update watch gives up on a panel that stopped answering ───────────────────────────────
_name53 = "os update: failed polls count towards giving up"
_RM53 = _read53(_JS53, "remote_manage.js")
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; global.MOUNT = ''; global.REMOTE_ID = 1; const q = []; let polls = 0;\n"
    "global.setTimeout = fn => { q.push(fn); return q.length; };\n"
    "global.document = {getElementById: () => ({style: {}, className: '', textContent: ''})};\n"
    "var _osuTimer = null, _osuStale = 0, _osuMiss = 0;\n"
    "global.fetch = () => { polls++; return Promise.reject(new Error('down')); };\n"
    + _cut47(_RM53, "function _pollOsUpdate(") + "\n" + _cut47(_RM53, "function _osuLostContact(") + "\n"
    "(async () => { _pollOsUpdate(); await settle();\n"
    "  for (let i = 0; i < 100 && q.length; i++) { q.shift()(); await settle(); }\n"
    "  console.log(JSON.stringify({polls, pending: q.length})); })();\n"))
if _out53 is not None:
    check("os update: a poll the panel does not answer counts towards the two-minute give-up (it polled "
          "every 3 s for the page's life)",
          _out53 == {"polls": 40, "pending": 0}, repr(_out53))

# ── the palette retries a failed server read; `need` gates two cards ─────────────────────────────
_PAL53 = _read53(_JS53, "palette.js")
_name53 = "palette: a failed server read is retried"
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; var servers = null, EL = {box: {hidden: true}}; function render(){}\n"
    + _cut47(_PAL53, "function loadServers(") + "\n"
    "(async () => { const out = {};\n"
    "  global.fetch = () => Promise.reject(new Error('asleep'));\n"
    "  loadServers(); await settle(); out.rejected = servers;\n"
    "  global.fetch = () => Promise.resolve({ok: false}); loadServers(); await settle(); out.refused = servers;\n"
    "  global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve([{id: 1}])});\n"
    "  loadServers(); await settle(); out.ok = servers; console.log(JSON.stringify(out)); })();\n"))
if _out53 is not None:
    check("palette: a server list that could not be read is asked for again on the next open (it was "
          "kept as an empty list until a reload)",
          _out53 == {"rejected": None, "refused": None, "ok": [{"id": 1}]}, repr(_out53))
_needs53 = dict(_re53.findall(r"hash: '(sec-[a-z]+)',\s*label: '[^']+', need: '([a-z_]+)'", _PAL53))
check("palette: the Invite links and Server tags results need what their cards need, and the list "
      "skips a section whose need this user lacks",
      _needs53 == {"sec-invites": "superadmin", "sec-tags": "edit_tags"}
      and "if (sec.need && !(window.PALETTE_CAN || {})[sec.need]) return;" in _PAL53, repr(_needs53))

# ── the Add Remote form's reset puts the credential field back in step ───────────────────────────
_MR53 = _read53(_JS53, "manage_remotes.js")
_i53 = _MR53.find("(function(){\n  var sel = document.getElementById('manage-remotes-auth_method');")
_name53 = "add remote form: a reset re-runs toggleCreds"
_out53 = _node53(_name53, _SETTLE53 + (
    "const handlers = {}, calls = [];\n"
    "const sel = {value: 'password', form: {addEventListener: (ev, fn) => { handlers[ev] = fn; }}};\n"
    "global.document = {getElementById: id => id === 'manage-remotes-auth_method' ? sel : null};\n"
    "function toggleCreds(s){ calls.push(s.value); }\n"
    + (_MR53[_i53:_MR53.index("})();", _i53) + 5] if _i53 >= 0 else "") + "\n"
    "(async () => { if (handlers.reset) { handlers.reset(); sel.value = 'key'; }\n"
    "  await new Promise(r => setTimeout(r, 50));\n"
    "  console.log(JSON.stringify({calls})); })();\n"))
if _out53 is not None:
    check("add remote form: after the form is reset (a successful Add) the credential field is set for the "
          "method the select shows, read after the reset restored it",
          _out53 == {"calls": ["key"]}, repr(_out53))

# ── the file editor shows the LATEST open ────────────────────────────────────────────────────────
_name53 = "file editor: only the latest open is shown"
_SF53 = _read53(_JS53, "server_files.js")
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; global.MOUNT = ''; global.serverId = 1; var curFile = null;\n"
    "const els = {}; global.document = {getElementById: id => (els[id] = els[id] || {style: {}, setAttribute(){}})};\n"
    "function syncGutter(){}\n"
    "const pending = {}; global.fetch = u => new Promise(res => { pending[decodeURIComponent(u.split('path=')[1])] =\n"
    "  c => res({json: () => Promise.resolve({content: c})}); });\n"
    + _SF53[_SF53.index("var _openSeq"):_SF53.index("\n", _SF53.index("var _openSeq"))]
    if "var _openSeq" in _SF53 else "") + "\n" + _cut47(_SF53, "function openFile(") + "\n" + (
    "(async () => { openFile('a.cfg'); openFile('b.cfg');\n"
    "  pending['b.cfg']('B'); await settle(); pending['a.cfg']('A'); await settle();\n"
    "  console.log(JSON.stringify({curFile, text: els.editor.value})); })();\n"))
if _out53 is not None:
    check("file editor: two quick opens answered out of order leave the second file open, matching the "
          "row highlighted last",
          _out53 == {"curFile": "b.cfg", "text": "B"}, repr(_out53))

# ── Refresh list swaps the game column, not the page ─────────────────────────────────────────────
_name53 = "install page: Refresh list keeps the form"
_MS53 = _read53(_JS53, "manage_servers.js")
_out53 = _node53(_name53, _SETTLE53 + (
    "global.window = global; global.MOUNT = ''; global.toast = () => 0; let reloads = 0; const swaps = [];\n"
    "global.location = {reload: () => reloads++}; global.setTimeout = fn => fn();\n"
    "global.refreshSection = (sel, after) => swaps.push([sel, after]);\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve({success: true, games: 141})});\n"
    + _cut47(_MS53, "function refreshGameList(") + "\n"
    "(async () => { refreshGameList({innerHTML: '', getAttribute: () => null}); await settle();\n"
    "  console.log(JSON.stringify({reloads, swaps})); })();\n"))
if _out53 is not None:
    check("install page: a refreshed game list replaces the game column and re-greys it for the chosen "
          "host, instead of reloading the page (which discarded the host and name chosen)",
          _out53 == {"reloads": 0, "swaps": [["#game-col", "filterGamesForHost"]]}, repr(_out53))
check("install page: ...and the column it swaps is there to swap",
      'id="game-col"' in _read53(_TPL53, "install_server.html"))

# ── js_coverage never presses a reboot ───────────────────────────────────────────────────────────
_HJ53 = _read53(_root, "tools", "js_coverage", "helpers.js")
_name53 = "js coverage: settleDialogs never presses a reboot"
_out53 = _node53(_name53, (
    "let pressed = [], backdrop = 0, buttons = [];\n"
    "global.MouseEvent = class { constructor(t){ this.type = t; } };\n"
    "const ov = {style: {position: 'fixed', inset: '0px'}, querySelector: () => null,\n"
    "  querySelectorAll: () => buttons, dispatchEvent: () => backdrop++};\n"
    "global.document = {querySelectorAll: s => s === 'body > div' ? [ov] : [], getElementById: () => null};\n"
    "global.window = global;\n"
    "const b = t => ({id: '', getAttribute: () => null, hasAttribute: () => false, textContent: t,\n"
    "  click: () => pressed.push(t)});\n"
    + _cut47(_HJ53, "function settleDialogs(") + "\n"
    "const run = texts => { pressed = []; backdrop = 0; buttons = texts.map(b); settleDialogs(true, 'pw');\n"
    "  return [pressed, backdrop]; };\n"
    "console.log(JSON.stringify({\n"
    "  reboot: run(['Wait: reboot when everyone has left', 'Reboot now: disconnect them', 'Cancel']),\n"
    "  other: run(['Ban everywhere', 'Cancel'])}));\n"))
if _out53 is not None:
    check("js coverage: the confirming pass closes a host's reboot dialog by its backdrop and presses no "
          "reboot button (it put the panel into a reboot plan for every page after)",
          _out53.get("reboot") == [[], 1], repr(_out53))
    check("js coverage: ...and still accepts any other overlay by its first button (control)",
          _out53.get("other") == [["Ban everywhere"], 0], repr(_out53))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. tools
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _bash53(script, env=None):
    return _sp53.run(["bash", "-c", script], capture_output=True, text=True,  # nosec B603 B607 - fixture script
                     timeout=60, env=dict(os.environ, **(env or {})), check=False)


# ── install.sh: an operator's rule on the panel port is left as it stands ───────────────────────
_INS53 = _read53(_root, "install.sh")
_blk53 = _INS53[_INS53.index("UFW_ACTIVE=0; TS_UFW=0; PORT_OPEN=0; UFW_READ=0"):
                _INS53.index("\n# While the wizard has no administrator")]
_fw53 = {}
for _k53, _st53 in (("tailnet only", "5000/tcp   ALLOW   100.64.0.0/10\n"),
                    ("deny", "5000/tcp   DENY   Anywhere\n"),
                    ("v6 only", "5000/tcp (v6)   ALLOW   Anywhere (v6)\n"),
                    ("deny then allow", "5000/tcp   DENY   Anywhere\n5000/tcp   ALLOW   Anywhere\n"),
                    ("allow then deny", "5000/tcp   ALLOW   Anywhere\n5000/tcp   DENY   Anywhere\n"),
                    ("no rule", "22/tcp   ALLOW   Anywhere\n")):
    _r53 = _bash53("set -euo pipefail\nPORT=5000 SUDO= TS_ADDR=\nok() { echo \"OK $*\"; }\n"
                   "command() { [ \"$1\" = -v ] && [ \"$2\" = ufw ] && return 0; builtin command \"$@\"; }\n"
                   "ufw() { case \"$1\" in status) printf 'Status: active\\n\\nTo   Action  From\\n%%s' \"$ST\";;\n"
                   "  allow) echo \"ALLOWED $2\";; esac; }\n%s\necho \"OPEN=${PORT_OPEN}\"\n" % _blk53,
                   env={"ST": _st53})
    _fw53[_k53] = ("OK Opened 5000/tcp" in _r53.stdout, (_r53.stdout.strip().splitlines() or [""])[-1])
check("install.sh: a fresh install leaves an operator's rule on the panel port as it stands — no "
      "`ufw allow` over a tailnet-only rule (it opened the admin panel to the internet) or behind a DENY",
      _fw53["tailnet only"] == (False, "OPEN=0") and _fw53["deny"] == (False, "OPEN=0"), repr(_fw53))
check("install.sh: ...the port is publicly open only by an IPv4 rule UFW reaches first: not a (v6) rule "
      "alone, not an ALLOW listed after a DENY",
      _fw53["v6 only"][1] == "OPEN=0" and _fw53["deny then allow"][1] == "OPEN=0"
      and _fw53["allow then deny"] == (False, "OPEN=1"), repr(_fw53))
check("install.sh: ...and with no rule for the port it is still opened, so a plain-IP install works "
      "(control)", _fw53["no rule"] == (True, "OPEN=1"), repr(_fw53))
_bin53 = os.path.join(os.path.realpath(_tf53.mkdtemp(prefix="lgsm-unit-p53-bin-")))
try:
    for _n53, _body53 in (("ufw", 'printf "%b" "${FAKE_UFW_OUT:-}"\n'),
                          ("sudo", '[ "$1" = "-n" ] && shift\nexec "$@"\n')):
        with open(os.path.join(_bin53, _n53), "w", encoding="utf-8") as _fh53:
            _fh53.write("#!/bin/sh\n" + _body53)
        # A stand-in in this part's own throwaway dir, on PATH for the one run below.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(os.path.join(_bin53, _n53), 0o755)  # nosec B103 - a fixture stand-in in a throwaway dir
    _fn53 = _INS53[_INS53.index("\nufw_port_state() {") + 1:]
    _fn53 = _fn53[:_fn53.index("\n}\n") + 3]
    _states53 = [_bash53("set -euo pipefail\n" + _fn53 + "ufw_port_state 5000\n",
                         env={"FAKE_UFW_OUT": "Status: active\\n\\n" + _o53,
                              "PATH": _bin53 + os.pathsep + "/usr/bin:/bin"}).stdout.strip()
                 for _o53 in ("5000/tcp (v6)   ALLOW   Anywhere (v6)\\n",
                              "5000/tcp   DENY   Anywhere\\n5000/tcp   ALLOW   Anywhere\\n",
                              "5000/tcp   ALLOW   Anywhere\\n")]
finally:
    _shutil53.rmtree(_bin53, ignore_errors=True)
check("install.sh update hint: ufw_port_state reads the same way — a (v6) rule alone or an ALLOW behind "
      "a DENY is closed, an IPv4 ALLOW from Anywhere open (control)",
      _states53 == ["closed", "closed", "open"], repr(_states53))

# ── js_coverage: a flow's own check failing fails the run ───────────────────────────────────────
_spec53 = _ilu53.spec_from_file_location("jscov53_run", os.path.join(_root, "tools", "js_coverage", "run.py"))
_run53 = _ilu53.module_from_spec(_spec53)
_spec53.loader.exec_module(_run53)
_flows53, _walk53, _drv53 = _sys53.modules["flows"], _sys53.modules["walk"], _sys53.modules["driver"]


class _Drv53:
    def __init__(self, flow_errors):
        self.loaded, self.errors, self.held, self.unreached = {"static/js/a.js"}, [], 0, []
        self.flow_errors = list(flow_errors)

    def snapshot(self):
        return None

    def hits(self):
        return {"static/js/a.js": {1: 2, 2: 0}}


_d53 = _Drv53([])
with _ctx53.redirect_stdout(_io53.StringIO()):
    _walk53._run_flow(_d53, "/server/1/files", "rename",
                      lambda _d: _flows53._expect(False, "at 375px the field fits the row", {"vw": 375}))
check("js coverage: a flow's failed check is recorded as a FlowAssertion, not as the harness breaking",
      len(_d53.flow_errors) == 1 and _d53.flow_errors[0][2].startswith("FlowAssertion: rename: at 375px"),
      repr(_d53.flow_errors))
_tmp53 = _tf53.mkdtemp(prefix="lgsm-unit-p53-jscov-")
_rc53 = {}
try:
    for _k53, _errs53 in (("assertion", _d53.flow_errors),
                          ("broken", [("/users", "users", "CDPError: no reply")])):
        try:
            with _ctx53.redirect_stdout(_io53.StringIO()):
                _run53.measure_and_report(_Drv53(_errs53), os.path.join(_tmp53, "lcov.info"), None)
            _rc53[_k53] = 0
        except _run53.Abort as _e53:
            _rc53[_k53] = _e53.code
finally:
    _shutil53.rmtree(_tmp53, ignore_errors=True)
check("js coverage: a failed flow check (the 375px rename fit) fails the run with its own exit status — "
      "it was only a warning, so it could never fail CI — while a broken flow still only warns",
      _rc53 == {"assertion": 4, "broken": 0}, repr(_rc53))


# ── js_coverage's serve.py refuses subprocess in every module that imports it ───────────────────
def _subprocess_importers53():
    out = set()
    for dirpath, _dirs, files in os.walk(os.path.join(_root, "panel")):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(dirpath, f)
                tree = _ast53.parse(_read53(path))
                if any(isinstance(n, _ast53.Import) and any(a.name == "subprocess" and not a.asname
                                                            for a in n.names) for n in tree.body):
                    rel = os.path.relpath(path, _root)[:-3].replace(os.sep, ".")
                    out.add(rel[:-len(".__init__")] if rel.endswith(".__init__") else rel)
    return out | {"db_maintenance"}


def _import_names53(fn):
    """{local name: dotted module} for the imports inside function node `fn`."""
    names = {}
    for n in _ast53.walk(fn):
        if isinstance(n, _ast53.Import):
            names.update((a.asname or a.name, a.name) for a in n.names)
        elif isinstance(n, _ast53.ImportFrom):
            names.update((a.asname or a.name, "%s.%s" % (n.module, a.name)) for a in n.names)
    return names


def _serve_shimmed53():
    tree = _ast53.parse(_read53(_root, "tools", "js_coverage", "serve.py"))
    fn = next(n for n in tree.body if isinstance(n, _ast53.FunctionDef) and n.name == "_stub_subprocess")
    names = _import_names53(fn)
    loop = next(n for n in _ast53.walk(fn) if isinstance(n, _ast53.For))
    return {names.get(e.id, e.id) for e in loop.iter.elts if isinstance(e, _ast53.Name)}


_imp53, _shim53 = _subprocess_importers53(), _serve_shimmed53()
check("js coverage: serve.py's deny-all subprocess shim covers every panel module that imports "
      "subprocess (the debug report's readers ran `systemctl show` and `sudo --version` for real)",
      len(_imp53) >= 10 and not (_imp53 - _shim53), "not shimmed: %s" % sorted(_imp53 - _shim53))

# ── lhci_serve removes the auth log and setup token it created ──────────────────────────────────
_lh53 = _ast53.parse(_read53(_root, "tools", "lhci_serve.py"))
_clean53 = next(n for n in _lh53.body if isinstance(n, _ast53.FunctionDef) and n.name == "_cleanup")
_loop53 = next(n for n in _ast53.walk(_clean53) if isinstance(n, _ast53.For))
_rm53n = {_ast53.unparse(e) for e in _loop53.iter.elts}
_auth53a = [n for n in _lh53.body if isinstance(n, _ast53.Assign) and _ast53.unparse(n.targets[0]) == "AUTH_LOG"]
check("lhci_serve: its cleanup removes the failed-login log create_app always opens, and a setup "
      "token, when it created them",
      {"AUTH_LOG", "SETUP_TOKEN_FILE"} <= _rm53n and len(_auth53a) == 1
      and _ast53.unparse(_auth53a[0].value) == "DATA_DIR / 'auth.log'", repr(sorted(_rm53n)))

# ── the i18n scanners see the labels they skipped ───────────────────────────────────────────────
_sys53.path.insert(0, os.path.join(_root, "tools"))
import i18n_scan as _i18n53  # noqa: E402
_tdir53 = _tf53.mkdtemp(prefix="lgsm-unit-p53-i18n-")
try:
    with open(os.path.join(_tdir53, "t.html"), "w", encoding="utf-8") as _fh53:
        _fh53.write("<p>{{ 'Regenerate token' if t else 'Generate token' }}</p>\n"
                    "<th>{{ sort_th('target', 'Target') }}</th>\n"
                    "<a data-u=\"{{ url_for('set_language', lang='LANGCODE') }}\">{{ x }}</a>\n")
    _tpl53, _ = _i18n53.scan_template(os.path.join(_tdir53, "t.html"))
    with open(os.path.join(_tdir53, "a.js"), "w", encoding="utf-8") as _fh53:
        _fh53.write("toast(d.message || 'Deleted', 'success');\nb.textContent = on ? 'Inactive' : 'Active';\n"
                    "if (e.key === 'Escape') close();\nvar kind = 'Widget';\n")
    _js53 = set(_i18n53.scan_js(_tdir53))
finally:
    _shutil53.rmtree(_tdir53, ignore_errors=True)
check("i18n scan: a label inside a {{ }} expression or a macro argument is asked for, not a URL "
      "builder's argument",
      {"Regenerate token", "Generate token", "Target"} <= set(_tpl53) and "LANGCODE" not in _tpl53,
      repr(sorted(_tpl53)))
check("i18n scan: a one-word string in a toast or a textContent write is asked for, a key name or an "
      "identifier is not",
      _js53 == {"Deleted", "Inactive", "Active"}, repr(sorted(_js53)))
