"""Part 290 of the unit suite: permissions on routes (security scan of 2026-11-22).

1. Re-trusting a host's SSH key is superadmin-only: the next connection pins whatever machine answers
   and signs in with the host's saved credential, often the panel's own key. A delegated host admin
   is refused (403, the pin kept) and the host page tells them why next to a disabled button.
2. Scheduled Tasks run any command as the game account: adding, changing, deleting or running one needs
   EDIT_FILES as well as MANAGE_SERVERS, a failed task's output needs VIEW_FILES, and Run now runs only
   a line read back from the account's crontab. The card keeps its form, disabled, and says why.
3. A delegated host admin's add-remote connection test, and their edit of a host's address or port, may
   not aim at a loopback, private, link-local or tailnet address (every record of a name checked), and
   the test dials the address that was checked. A superadmin is not limited.
4. A console command that sets a secret (`rcon_password X`) is kept in the audit log, and in the command
   form's notice, with its value masked; the game is still sent it as typed.
5. A console (or terminal) socket opened with an API token fails its per-tick credential check once the
   token has expired, not only when it is revoked.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host-facing call a
route makes is a stand-in. Nothing reaches a host, /etc or data/.
"""
import os as _os290
from datetime import timedelta as _td290

from unit.part01 import check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_GS, P9_HOST, _p9, _p9_arm, _p9_audit_count, _p9_client,
                         _p9_host_row, _p9_patch, _p9_patch_sm, _p9_quiet_lookups, _p9_restore_all, _p9_set_host)
from unit.part131 import _STATUS131
from panel.core.clock import utcnow as _now290
from panel.db.models import (AuditLog as _Audit290, CustomCommand as _CC290, Group as _Group290,
                             RemoteServer as _Remote290, User as _User290, db as _db290)
from panel.ops import system_ops as _so290, tailscale_integration as _ts290
from panel.ops.ssh_manager import _core as _core290
from panel.core.validation import ip_address_or_none as _ip290
from panel.routes import (_shared as _sh290, remote_vps as _rv290, remotes as _rm290, server_detail as _sd290,
                          server_files as _sf290)
from panel.security import auth as _auth290
from panel.services import console_secrets as _csec290


def _user290(name, perms, hosts=(), servers=()):
    """A non-superadmin in one group holding `perms` on `hosts` (RemoteServer ids) and `servers`. -> (uid, gid)."""
    from panel.db.models import GameServer as _GS290
    with _p9.app_context():
        grp = _Group290(name=name, description="", is_default=False)
        grp.set_permissions(list(perms))
        grp.servers.extend(_db290.session.get(_Remote290, h) for h in hosts)
        grp.game_servers.extend(_db290.session.get(_GS290, s) for s in servers)
        _db290.session.add(grp)
        _db290.session.flush()
        u = _User290(username=name, password_hash=_os290.urandom(8).hex(), display_name=name,
                     is_superadmin=False, is_active=True)
        u.groups.append(grp)
        _db290.session.add(u)
        _db290.session.commit()
        return u.id, grp.id


def _drop290(uid, gid):
    with _p9.app_context():
        for model, rid in ((_User290, uid), (_Group290, gid)):
            row = _db290.session.get(model, rid)
            if row is not None:
                _db290.session.delete(row)
        _db290.session.commit()


def _j290(resp):
    return resp.get_json(silent=True) or {}


# ── 1. Re-trust host key: superadmin-only ─────────────────────────────────────────────────────────
_PIN290 = "AAAAC3NzaC1lZDI1NTE5AAAAIP290pinnedkeyp290pinnedkeyp290pinnedkey"
_hk290 = {}
_d1_290 = None
try:
    _p9_arm(who="part290")
    _trips290 = len(_P9_TRIPPED)
    _closed290 = []
    _p9_patch(_rv290, "close_connection", lambda remote: _closed290.append(remote.id))
    _p9_patch(_so290, "get_server_status", lambda *a, **k: _STATUS131)
    _p9_patch(_ts290, "panel_funnel_facts", lambda cfg: {})
    _p9_patch(_core290, "run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_core290, "run_command", lambda *a, **k: ("", "", 1))
    _saved_key290 = _p9_host_row(P9_HOST).host_key
    _d1_290 = _user290("p290_hosts", [_auth290.MANAGE_REMOTES, _auth290.VIEW_SERVERS], hosts=[P9_HOST])
    _D290 = _p9_client(_d1_290[0])
    _p9_set_host(P9_HOST, host_key="ssh-ed25519 " + _PIN290)
    _audits290 = _p9_audit_count("retrust_hostkey")
    _r = _D290.post("/api/remote/%d/retrust-hostkey" % P9_HOST)
    _hk290["delegate"] = (_r.status_code, _j290(_r).get("success"), _j290(_r).get("message", ""),
                          _p9_host_row(P9_HOST).host_key, _p9_audit_count("retrust_hostkey") - _audits290,
                          list(_closed290))
    _page290 = _D290.get("/remote/%d/manage" % P9_HOST)
    _hk290["delegate_page"] = (_page290.status_code, _page290.get_data(as_text=True))
    _pageA290 = _p9_client(P9_ADMIN).get("/remote/%d/manage" % P9_HOST)
    _hk290["admin_page"] = (_pageA290.status_code, _pageA290.get_data(as_text=True))
    _r = _p9_client(P9_ADMIN).post("/api/remote/%d/retrust-hostkey" % P9_HOST)
    _hk290["admin"] = (_r.status_code, _j290(_r).get("success"), _p9_host_row(P9_HOST).host_key,
                       _p9_audit_count("retrust_hostkey") - _audits290, list(_closed290))
    _hk290["trips"] = len(_P9_TRIPPED) - _trips290
finally:
    _p9_restore_all()
    if _d1_290:
        _drop290(*_d1_290)
    _p9_set_host(P9_HOST, host_key=_saved_key290)
_d290 = _hk290.get("delegate", (None,) * 6)
eq("retrust host key: a delegated MANAGE_REMOTES admin on the host is refused (403), the pin is kept, "
   "nothing is audited and no connection is dropped",
   _d290[:2] + _d290[3:], (403, False, "ssh-ed25519 " + _PIN290, 0, []))
check("retrust host key: ...and the refusal says only a superadmin can, and why",
      _d290[2] == _rv290.RETRUST_SUPERADMIN_ONLY and "superadmin" in _d290[2], repr(_d290[2]))
eq("retrust host key (control): a superadmin clears the pin, the row is audited and the cached connection dropped",
   _hk290.get("admin"), (200, True, "", 1, [P9_HOST]))
_dp290 = _hk290.get("delegate_page", (None, ""))
_ap290 = _hk290.get("admin_page", (None, ""))
check("retrust host key: the delegate's host page shows the button disabled with the sentence saying why, "
      "and no live Re-trust action",
      _dp290[0] == 200 and 'data-action="retrustHostKey"' not in _dp290[1]
      and 'disabled aria-describedby="hostkey-why"' in _dp290[1]
      and _rv290.RETRUST_SUPERADMIN_ONLY in _dp290[1], repr(_dp290[0]))
check("retrust host key (control): a superadmin's host page keeps the working Re-trust button",
      _ap290[0] == 200 and 'data-action="retrustHostKey"' in _ap290[1] and "hostkey-why" not in _ap290[1],
      repr(_ap290[0]))
eq("part290 retrust: nothing reached a real transport", _hk290.get("trips"), 0)


# ── 2. Scheduled Tasks: writes need EDIT_FILES, job output needs VIEW_FILES, run-now a listed line ──
_RAW290 = "0 5 * * * /home/csgoserver/backup.sh"
_JOBS290 = [{"raw": _RAW290, "schedule": "0 5 * * *", "command": "/home/csgoserver/backup.sh", "managed": False,
             "last_run": 1700000000, "ok": False, "error": "rconpassword=p290-hunter2"}]
_cron290 = {}
_mgr290 = _ed290 = None
try:
    _p9_arm(who="part290")
    _trips290 = len(_P9_TRIPPED)
    _calls290 = []
    _p9_quiet_lookups()
    _p9_patch(_sh290, "privileged_accounts", lambda remote, users: {})
    _p9_patch(_sf290, "_sync_toggles_from_cron", lambda gs, jobs: None)
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: None)
    _p9_patch_sm("list_cron_jobs", lambda remote, user, lgsm: [dict(j) for j in _JOBS290])
    for _n290 in ("add_cron_job", "update_cron_job", "run_cron_job_now"):
        _p9_patch(_sf290, _n290, (lambda n: lambda *a, **k: _calls290.append((n, a[2])) or (True, "Started"))(_n290))
    _p9_patch_sm("delete_cron_job", lambda *a, **k: _calls290.append(("delete_cron_job", a[2])) or (True, ""))
    _p9_patch(_core290, "run_command", lambda *a, **k: ("", "", 1))
    _mgr290 = _user290("p290_sched", [_auth290.MANAGE_SERVERS, _auth290.VIEW_SERVERS], hosts=[P9_HOST])
    _ed290 = _user290("p290_files", [_auth290.MANAGE_SERVERS, _auth290.VIEW_SERVERS, _auth290.EDIT_FILES,
                                     _auth290.VIEW_FILES], hosts=[P9_HOST])
    _M290, _E290 = _p9_client(_mgr290[0]), _p9_client(_ed290[0])
    _u290 = "/api/server/%d/cron" % P9_GS
    _bodies290 = (("add", "", {"schedule": "* * * * *", "command": "cat lgsm/config-lgsm/*/*.cfg"}),
                  ("update", "/update", {"raw": _RAW290, "schedule": "* * * * *", "command": "id"}),
                  ("delete", "/delete", {"raw": _RAW290}),
                  ("run", "/run", {"raw": _RAW290}))
    for _k290, _sfx290, _b290 in _bodies290:
        _r = _M290.post(_u290 + _sfx290, json=_b290)
        _cron290["mgr_" + _k290] = (_r.status_code, _j290(_r).get("message"))
    _cron290["mgr_calls"] = list(_calls290)
    _cron290["mgr_list"] = _j290(_M290.get(_u290)).get("jobs")
    _cron290["ed_list"] = _j290(_E290.get(_u290)).get("jobs")
    _r = _E290.post(_u290 + "/run", json={"raw": "0 5 * * * id; cat lgsm/config-lgsm/*/*.cfg"})
    _cron290["ed_run_typed"] = (_r.status_code, _j290(_r), list(_calls290))
    _r = _E290.post(_u290 + "/run", json={"raw": _RAW290})
    _cron290["ed_run_listed"] = (_r.status_code, _j290(_r).get("success"), list(_calls290))
    del _calls290[:]
    _r = _E290.post(_u290, json={"schedule": "0 6 * * *", "command": "/home/csgoserver/backup.sh"})
    _cron290["ed_add"] = (_r.status_code, _j290(_r).get("success"), list(_calls290))
    for _k290, _c290 in (("mgr_page", _M290), ("ed_page", _E290)):
        _pg290 = _c290.get("/server/%d/files" % P9_GS)
        _cron290[_k290] = (_pg290.status_code, _pg290.get_data(as_text=True))
    _cron290["trips"] = len(_P9_TRIPPED) - _trips290
finally:
    _p9_restore_all()
    for _du290 in (_mgr290, _ed290):
        if _du290:
            _drop290(*_du290)
eq("scheduled tasks: MANAGE_SERVERS without EDIT_FILES may not add, change, delete or run a task "
   "(403, the reason given), and no crontab writer or runner is called",
   {k: _cron290.get("mgr_" + k) for k in ("add", "update", "delete", "run", "calls")},
   {"add": (403, _sf290.CRON_NEEDS_EDIT_FILES), "update": (403, _sf290.CRON_NEEDS_EDIT_FILES),
    "delete": (403, _sf290.CRON_NEEDS_EDIT_FILES), "run": (403, _sf290.CRON_NEEDS_EDIT_FILES), "calls": []})
_ml290 = _cron290.get("mgr_list") or [{}]
_el290 = _cron290.get("ed_list") or [{}]
check("scheduled tasks: without VIEW_FILES the listing withholds a failed task's output (the Failed state stays)",
      _ml290[0].get("error") == _sf290.CRON_OUTPUT_NEEDS_VIEW_FILES and _ml290[0].get("ok") is False
      and "p290-hunter2" not in repr(_ml290), repr(_ml290))
check("scheduled tasks (control): with VIEW_FILES the listing shows the task's output as recorded",
      _el290[0].get("error") == "rconpassword=p290-hunter2", repr(_el290))
_rt290 = _cron290.get("ed_run_typed", (None, {}, None))
eq("scheduled tasks: Run now refuses a line that is not in the account's crontab, and runs nothing",
   (_rt290[1].get("success"), _rt290[2]), (False, []))
check("scheduled tasks: ...and says the task changed since the page loaded",
      "changed since the page loaded" in (_rt290[1].get("message") or ""), repr(_rt290[1]))
eq("scheduled tasks (control): Run now runs a line read back from the crontab, for an EDIT_FILES holder",
   _cron290.get("ed_run_listed"), (200, True, [("run_cron_job_now", _RAW290)]))
eq("scheduled tasks (control): an EDIT_FILES holder still adds a task",
   _cron290.get("ed_add"), (200, True, [("add_cron_job", "0 6 * * *")]))
_mp290 = _cron290.get("mgr_page", (None, ""))
_ep290 = _cron290.get("ed_page", (None, ""))
check("scheduled tasks: without EDIT_FILES the card keeps its Add task button, disabled, with the sentence "
      "saying why, and tells the script not to offer row actions",
      _mp290[0] == 200 and 'id="cron-ro"' in _mp290[1] and 'data-cron-edit="0"' in _mp290[1]
      and 'id="cron-submit" disabled aria-describedby="cron-ro"' in _mp290[1]
      and _sf290.CRON_NEEDS_EDIT_FILES in _mp290[1], repr(_mp290[0]))
check("scheduled tasks (control): with EDIT_FILES the card's form is live and carries no such sentence",
      _ep290[0] == 200 and 'id="cron-ro"' not in _ep290[1] and 'data-cron-edit="1"' in _ep290[1]
      and 'id="cron-submit">' in _ep290[1], repr(_ep290[0]))
eq("part290 scheduled tasks: nothing reached a real transport", _cron290.get("trips"), 0)


# ── 3. The add-remote connection test: a delegated admin may not aim it at an internal address ─────
_XHR290 = {"X-Requested-With": "XMLHttpRequest"}
_NAMES290 = {"p290-lan.example": ["203.0.113.9", "10.0.0.7"], "p290-pub.example": ["203.0.113.10"],
             "localhost.p290.example": ["::1"]}
_INTERNAL290 = ("127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.9", "169.254.169.254", "100.100.100.100",
                "0.0.0.0", "fd7a:115c:a1e0::1", "fe80::1", "::1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
                "2002:a00:1::1", "2130706433", "p290-lan.example", "localhost.p290.example")
_ssrf290 = {}
_d3_290 = _row290 = None
try:
    _p9_arm(who="part290")
    _trips290 = len(_P9_TRIPPED)
    _tested290 = []
    _p9_patch(_rm290, "ssh_test_connection",
              lambda host, *a, **k: _tested290.append(host) or (False, "p290 stand-in: no SSH here"))
    _p9_patch(_rm290, "_resolve_host", lambda host: [_ip290(a) for a in _NAMES290.get(host, [])])
    with _p9.app_context():
        _h290 = _Remote290(name="p290-own", host="203.0.113.60", port=22, username="root", auth_method="password",
                           auth_credential="", is_online=True)
        _db290.session.add(_h290)
        _db290.session.commit()
        _row290 = _h290.id
    _d3_290 = _user290("p290_hostadm", [_auth290.MANAGE_REMOTES, _auth290.VIEW_SERVERS], hosts=[_row290])
    _H290 = _p9_client(_d3_290[0])

    def _add290(client, host):
        del _tested290[:]
        r = client.post("/remotes/add", headers=_XHR290, data={
            "name": "p290new", "host": host, "ssh_port": "22", "ssh_user": "root", "auth_method": "password",
            "credential": "p290-not-a-real-password"})
        return r.status_code, _j290(r).get("message") or "", list(_tested290)

    _ssrf290["internal"] = {h: _add290(_H290, h) for h in _INTERNAL290}
    _ssrf290["public"] = _add290(_H290, "203.0.113.7")
    _ssrf290["public_name"] = _add290(_H290, "p290-pub.example")
    _ssrf290["unresolved"] = _add290(_H290, "p290-nowhere.example")
    _ssrf290["admin_internal"] = _add290(_p9_client(P9_ADMIN), "10.1.2.3")
    _r = _H290.post("/remotes/%d/edit" % _row290, headers=_XHR290,
                    data={"host": "10.9.9.9", "ssh_port": "22", "auth_method": "password",
                          "credential": "p290-new-password"})
    _ssrf290["edit_internal"] = (_r.status_code, _j290(_r).get("message"), _p9_host_row(_row290).host)
    _r = _H290.post("/remotes/%d/edit" % _row290, headers=_XHR290,
                    data={"ssh_port": "2222", "auth_method": "password", "credential": "p290-new-password"})
    _ssrf290["edit_public_port"] = (_r.status_code, _p9_host_row(_row290).port)
    _ssrf290["trips"] = len(_P9_TRIPPED) - _trips290
finally:
    _p9_restore_all()
    if _d3_290:
        _drop290(*_d3_290)
    with _p9.app_context():
        for _rr290 in _Remote290.query.filter(_Remote290.name.in_(["p290-own", "p290new"])).all():
            _db290.session.delete(_rr290)
        _db290.session.commit()
_in290 = _ssrf290.get("internal") or {}
eq("add remote: a delegated admin's connection test is refused for every loopback, private, link-local, "
   "tailnet, unspecified and embedded-IPv4 address, and for a name with any such record; nothing is dialled",
   {h: v for h, v in _in290.items() if v != (403, _rm290.INTERNAL_TARGET_REFUSAL, [])}, {})
check("add remote: ...every one of those addresses was asked", len(_in290) == len(_INTERNAL290), repr(sorted(_in290)))
eq("add remote (control): a delegated admin's test of a public address is dialled", _ssrf290.get("public", ())[2:],
   (["203.0.113.7"],))
eq("add remote: a delegated admin's name is dialled at the address that was checked, never looked up again",
   _ssrf290.get("public_name", ())[2:], (["203.0.113.10"],))
check("add remote: a name that does not resolve is refused before anything is dialled",
      _ssrf290.get("unresolved", (0, "", None))[2] == []
      and "did not resolve" in _ssrf290.get("unresolved", (0, "", None))[1], repr(_ssrf290.get("unresolved")))
eq("add remote (control): a superadmin may still test a private address", _ssrf290.get("admin_internal", ())[2:],
   (["10.1.2.3"],))
eq("edit remote: a delegated admin may not repoint their host at a private address (403, the row unchanged)",
   _ssrf290.get("edit_internal"), (403, _rm290.INTERNAL_TARGET_REFUSAL, "203.0.113.60"))
check("edit remote (control): a delegated admin may still move their public host's SSH port with a new password",
      _ssrf290.get("edit_public_port", (0, 0))[1] == 2222, repr(_ssrf290.get("edit_public_port")))
eq("part290 add remote: nothing reached a real transport", _ssrf290.get("trips"), 0)


# ── 4. Console commands that set a secret are audited (and flashed) with the value masked ──────────
def _audit_detail290(action):
    with _p9.app_context():
        r = _Audit290.query.filter_by(action=action).order_by(_Audit290.id.desc()).first()
        return None if r is None else r.detail


_cmd290 = {}
_cc290 = None
try:
    _p9_arm(who="part290")
    _trips290 = len(_P9_TRIPPED)
    _sent290 = []
    for _m290 in (_sf290, _sd290):
        _p9_patch(_m290, "send_console_command", lambda remote, user, text, **k: _sent290.append(text) or ("", "", 0))
    _p9_patch(_csec290, "_values", {P9_GS: (float("inf"), frozenset({"p290cfgvalue"}))})
    _A290 = _p9_client(P9_ADMIN)
    for _k290, _t290 in (("rcon", "rcon_password N3wS3cret"), ("sv", 'sv_password "p290 join"'),
                         ("chain", "status; rcon_password Another1"), ("flag", "+sv_setsteamaccount P290TOKEN"),
                         ("cached", "say p290cfgvalue"), ("plain", "say password reset tonight"),
                         ("clear", 'sv_password ""'), ("status", "status")):
        _A290.post("/api/command/%d" % P9_GS, json={"command": _t290})
        _cmd290["api_" + _k290] = _audit_detail290("send_command")
    _A290.post("/server/%d/command" % P9_GS, data={"command": "rcon_password FormS3cret"})
    with _A290.session_transaction() as _s290:
        _cmd290["flashes"] = [m for _c, m in _s290.get("_flashes", [])]
        _s290.pop("_flashes", None)
    _cmd290["form"] = _audit_detail290("send_command")
    with _p9.app_context():
        _ccr290 = _CC290(name="p290 rcon", command_template="rcon_password {}", enabled=True, scope_type="all")
        _db290.session.add(_ccr290)
        _db290.session.commit()
        _cc290 = _ccr290.id
    _A290.post("/api/server/%d/custom-command/%d" % (P9_GS, _cc290), json={"value": "CustomS3cret"})
    _cmd290["custom"] = _audit_detail290("custom_command")
    _cmd290["sent"] = list(_sent290)
    _cmd290["trips"] = len(_P9_TRIPPED) - _trips290
finally:
    _p9_restore_all()
    if _cc290:
        with _p9.app_context():
            _db290.session.delete(_db290.session.get(_CC290, _cc290))
            _db290.session.commit()
eq("send command: a command that sets a secret is audited with its value masked (live console route)",
   {k: _cmd290.get("api_" + k) for k in ("rcon", "sv", "chain", "flag", "cached")},
   {"rcon": "rcon_password ********", "sv": "sv_password ********", "chain": "status; rcon_password ********",
    "flag": "+sv_setsteamaccount ********", "cached": "say ********"})
eq("send command (control): ordinary commands, prose and an emptied password are audited as typed",
   {k: _cmd290.get("api_" + k) for k in ("plain", "clear", "status")},
   {"plain": "say password reset tonight", "clear": 'sv_password ""', "status": "status"})
eq("send command: the command form's audit row and its 'Command sent' notice (in the session cookie) are masked",
   (_cmd290.get("form"), [f for f in _cmd290.get("flashes", []) if "Command sent" in f]),
   ("rcon_password ********", ["Command sent: rcon_password ********"]))
eq("custom command: a template that sets a secret is audited with the typed value masked",
   _cmd290.get("custom"), "p290 rcon: rcon_password ********")
check("send command (control): the game is still sent every command exactly as typed",
      "rcon_password N3wS3cret" in _cmd290.get("sent", []) and "rcon_password FormS3cret" in _cmd290.get("sent", [])
      and "rcon_password CustomS3cret" in _cmd290.get("sent", []), repr(_cmd290.get("sent")))
eq("part290 send command: nothing reached a real transport", _cmd290.get("trips"), 0)


# ── 5. A console socket opened with an API token is dropped once the token expires ─────────────────
_tok290 = {}
_d5_290 = None
try:
    _d5_290 = _user290("p290_token", [_auth290.VIEW_CONSOLE], hosts=[P9_HOST])
    with _p9.app_context():
        _u5_290 = _db290.session.get(_User290, _d5_290[0])
        _u5_290.api_token = "a" * 64
        _u5_290.api_token_expires = _now290() + _td290(hours=1)
        _db290.session.commit()
        _login290 = _u5_290.get_id()
    _cred290 = (_login290, "a" * 64)
    with _p9.app_context():
        _tok290["valid"] = _sf290._viewer_still_allowed(_d5_290[0], P9_GS, _cred290)
    with _p9.app_context():
        _db290.session.get(_User290, _d5_290[0]).api_token_expires = _now290() - _td290(seconds=1)
        _db290.session.commit()
    with _p9.app_context():
        _tok290["expired"] = _sf290._viewer_still_allowed(_d5_290[0], P9_GS, _cred290)
        _tok290["no_digest"] = _sf290._viewer_still_allowed(_d5_290[0], P9_GS, (_login290, None))
    with _p9.app_context():
        _db290.session.get(_User290, _d5_290[0]).api_token_expires = None
        _db290.session.commit()
    with _p9.app_context():
        _tok290["no_expiry"] = _sf290._viewer_still_allowed(_d5_290[0], P9_GS, _cred290)
        _tok290["other_token"] = _sf290._viewer_still_allowed(_d5_290[0], P9_GS, (_login290, "b" * 64))
finally:
    if _d5_290:
        _drop290(*_d5_290)
eq("console socket: the poller's per-tick check drops a bearer socket once its token has expired",
   _tok290.get("expired"), False)
eq("console socket (control): an unexpired token, a token with no expiry and a session socket still pass; "
   "another token does not",
   (_tok290.get("valid"), _tok290.get("no_expiry"), _tok290.get("no_digest"), _tok290.get("other_token")),
   (True, True, True, False))
