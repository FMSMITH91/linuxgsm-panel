"""Part 130 of the unit suite: the twenty-third review's routes and UI (builder C).

* Every action that starts, stops or reconfigures a server on a host is refused while the panel is
  stopping that host's servers to reboot it (host_reboot.reboot_busy), as the uninstall is since
  #449: Scheduled tasks' add, edit, delete and Run now; the GMod content POST (asked again where
  nothing yields before its job is marked running); the mods POST; the Backups card's "Back up now";
  deleting the host; an SSH port move (and a reboot is blocked while one runs); and an install asks
  again right before its row exists. A cron write after the reboot is sent that turns Autostart on
  or off leaves the server out of the restore, as the Autostart switch does.
* The Tailscale migration's refusals reach es/fr viewers in their language.
* Remote Servers: a failed stats read is a failure (a down Tailscale-SSH host's card swapped its
  last good figures for "?"), kept figures are marked stale, and the Reachable badge follows the
  poll; the dashboard's tag filter runs again after a row's tags change or a tag is deleted.

HOW IT RUNS. The routes on part12's app with its transport tripwire armed and every host call stubbed;
manage_remotes.js, dashboard.js's filter and server_tags.js in node on part121's small DOM. Nothing
reaches a host, sudo or the checkout's data/.
"""
import json
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GM, P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_host_row, _p9_json, _p9_ms, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row,
                         _p9_rv, _p9_set, _p9_sf, _p9_sh)
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part121 import _DOM121
from panel.core import i18n as _i18n130
from panel.db.models import User as _User130, db as _db130
from panel.routes import panel_backup as _pb130, remotes as _rm130
from panel.services import host_reboot as _hr130

_TRIP130_START = len(_P9_TRIPPED)
_XHR130 = {"X-Requested-With": "XMLHttpRequest"}
_ADDR130 = "198.51.100.7"   # NOSONAR(S1313) - a documentation address in a stand-in host row; never dialled
_ADDR130B = "198.51.100.8"  # NOSONAR(S1313) - a documentation address in a stand-in host row; never dialled
_REAUTH_FIELD130 = "pass" + "word"     # the re-authentication field delete_remote reads


def _busy130(flag):
    """reboot_busy answers `flag` for P9_HOST (a list, so a stub may flip it mid-request)."""
    _p9_patch(_hr130, "reboot_busy", lambda rid: bool(flag[0]) and rid == P9_HOST)


def _arm130():
    """part12's tripwire, and its plain-game-account answer to the write gate's host probe."""
    _p9_arm(who="part130")
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})


class _Stop130(Exception):
    """Raised by a stub that marks how far a request got; the route answers it with a 500."""


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Files & Config while the host's servers are being stopped for a reboot
# ════════════════════════════════════════════════════════════════════════════════════════════════
_GMOD130 = {"action": "mount", "games": ["cstrike"]}
_GMOD_RM130 = {"action": "uninstall", "games": ["cstrike"]}
_CRON130 = {"schedule": "0 4 * * *", "command": "/home/csgoserver/csgoserver restart",
            "raw": "0 4 * * * /home/csgoserver/csgoserver restart"}
# (case, url, body, the stub a request that went ahead reaches)
_POSTS130 = (("cron add", "/api/server/%d/cron" % P9_GS, _CRON130, "add"),
             ("cron update", "/api/server/%d/cron/update" % P9_GS, _CRON130, "update"),
             ("cron delete", "/api/server/%d/cron/delete" % P9_GS, _CRON130, "delete"),
             ("cron run now", "/api/server/%d/cron/run" % P9_GS, _CRON130, "run"),
             ("mods install", "/api/server/%d/mods" % P9_GS, {"action": "install", "mod": "sourcemod"}, "mods"),
             ("gmod mount", "/api/server/%d/gmod-content" % P9_GM, _GMOD130, "gmod-scan"),
             ("gmod uninstall", "/api/server/%d/gmod-content" % P9_GM, _GMOD_RM130, "gmod-uninstall-job"),
             ("back up now", "/api/panel/backup/game/%d" % P9_GS, {}, "backup"))


def _stub_files130(reached):
    """Every host call the Files & Config POSTs make, each recording that it was reached."""
    def _mark(name, ret):
        return lambda *a, **k: (reached.append(name), ret)[1]

    def _stop(name):
        return lambda *a, **k: (reached.append(name), (_ for _ in ()).throw(_Stop130()))[1]

    for name, step, ret in (("add_cron_job", "add", (True, "")), ("update_cron_job", "update", (True, "")),
                            ("run_cron_job_now", "run", (True, "Started")), ("mods_action", "mods", ("", "", 1)),
                            ("gmod_current_mounts", "gmod-scan", []), ("_bg_gmod_content_apply", "gmod-job", None),
                            ("_bg_gmod_content_uninstall", "gmod-uninstall-job", None)):
        _p9_patch(_p9_sf, name, _mark(step, ret))
    _p9_patch_sm("delete_cron_job", _mark("delete", (True, "")))
    _p9_patch_sm("list_cron_jobs", lambda *a, **k: [])
    _p9_patch(_p9_sf, "_claim_gmod_content_host", lambda rid: True)
    _p9_patch(_pb130.bk, "game_prune_keep", _stop("backup"))


def _files_gates130():
    reached = []
    _stub_files130(reached)
    client = _p9_client(P9_ADMIN)
    got = {}
    flag = [True]
    _busy130(flag)
    for busy in (True, False):
        flag[0] = busy
        for case, url, body, step in _POSTS130:
            reached.clear()
            r = client.post(url, json=body, headers=_XHR130)
            got[(case, busy)] = (r.status_code if busy else None, step in reached)
        got[busy] = _p9_audit("cron_run_now")
    refused = {c: got[(c, True)] for c, _u, _b, _s in _POSTS130}
    ran = {c: got[(c, False)][1] for c, _u, _b, _s in _POSTS130}
    check("Files & Config: Scheduled tasks' add, edit, delete and Run now, the mods install, GMod content "
          "mount and uninstall and the Backups card's Back up now are refused (409, the host never asked) "
          "while a clean reboot of the host is stopping its servers — Run now on a restart line was a second "
          "starter, and a download started after the reboot's census was cut off by it",
          refused == {c: (409, False) for c in refused}, repr(refused))
    check("Files & Config: ...and with no reboot each of them goes ahead (control)",
          ran == {c: True for c in ran}, repr(ran))
    check("Files & Config: a refused Run now is audited as refused, with the reason",
          (got[True].success, "being rebooted" in got[True].detail) == (False, True), repr(got[True]))


def _gmod_late130():
    """A reboot registered during the content scan is asked about again before the job starts.

    The scan is SSH; the job's running mark is what the census reads, so the job is never started
    under the reboot.
    """
    reached = []
    _stub_files130(reached)
    flag = [False]
    _busy130(flag)
    client = _p9_client(P9_ADMIN)
    got = {}
    _p9_patch(_p9_sf, "gmod_current_mounts", lambda *a, **k: (flag.__setitem__(0, True), [])[1])
    for case, body, job in (("mount", _GMOD130, "gmod-job"), ("uninstall", _GMOD_RM130, "gmod-uninstall-job")):
        flag[0] = False
        reached.clear()
        # (the uninstall reads nothing before its job: its refusal check stands in for "a scan")
        _p9_patch(_p9_sf, "_sf_gmod_host_refusal",
                  lambda *a, _u=(case == "uninstall"), **k: flag.__setitem__(0, True) if _u else None)
        r = client.post("/api/server/%d/gmod-content" % P9_GM, json=body, headers=_XHR130)
        got[case] = (r.status_code, job in reached)
    check("GMod content: a clean reboot registered while the request read the host (mount's scan, or "
          "the refusal check before an uninstall) is asked about again where nothing yields before the "
          "job is marked running: refused, no job (the census had run before the job existed)",
          got == {"mount": (409, False), "uninstall": (409, False)}, repr(got))


def _cron_after_send130():
    """After the reboot is sent: a cron write that changes Autostart leaves the restore."""
    flag = [False]
    _busy130(flag)
    rec = json.dumps({"v": 1, "owner": "panel"})
    _p9_patch_sm("delete_cron_job", lambda *a, **k: (True, ""))
    _p9_patch(_p9_sf, "add_cron_job", lambda *a, **k: (True, ""))
    client = _p9_client(P9_ADMIN)
    got = {}
    for case, jobs, url in (("monitor line deleted", [], "/api/server/%d/cron/delete" % P9_GS),
                            ("another line added (control)", [{"role": "autostart"}], "/api/server/%d/cron" % P9_GS)):
        _p9_set(P9_GS, autostart=True, reboot_restore=rec)
        _p9_patch_sm("list_cron_jobs", lambda *a, _j=jobs, **k: list(_j))
        r = client.post(url, json={"raw": "*/5 * * * * x monitor", "schedule": "0 4 * * *", "command": "x"},
                        headers=_XHR130)
        row = _p9_row(P9_GS)
        got[case] = (r.status_code, bool(row.autostart), row.reboot_restore is None)
    _p9_set(P9_GS, autostart=False, reboot_restore=None)
    check("Scheduled tasks after the reboot is sent: deleting the monitor (Autostart) line takes the server "
          "out of the restore, as the Autostart switch does (the plan would wait on a line that is gone); "
          "a write that leaves Autostart as it was keeps it in the plan (control)",
          got == {"monitor line deleted": (200, False, True), "another line added (control)": (200, True, False)},
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Install, delete host and SSH port move while the host is rebooted
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _install_recheck130():
    flag = [False]
    _busy130(flag)
    made = []
    _p9_patch(_p9_ms, "_install_form_refusal", lambda *a: None)
    _p9_patch(_p9_ms, "_desired_install_port", lambda *a: 27230)
    _p9_patch(_p9_ms, "host_account_state", lambda *a: "absent")
    _p9_patch(_p9_ms, "_r31b_free_host_name", lambda remote, named, server_name, default: (named[0], False, None))
    _p9_patch(_p9_ms, "_create_install_row",
              lambda *a: (made.append(a[2]), (_ for _ in ()).throw(_Stop130()))[1])
    got = {}
    client = _p9_client(P9_ADMIN)
    for case, during_scan in (("a reboot starts during the port scan", True), ("no reboot (control)", False)):
        made.clear()
        flag[0] = False
        _p9_patch(_p9_ms, "_pick_install_port",
                  lambda *a, _d=during_scan: (flag.__setitem__(0, _d), (27230, False, None))[1])
        r = client.post("/servers/add", data={"remote_id": str(P9_HOST), "game_type": "csgo",
                                              "server_name": "p130inst", "port": "27230"}, headers=_XHR130)
        got[case] = (r.status_code if during_scan else None, list(made))
    check("install: a clean reboot of the host that starts while the install reads the host (the port scan, "
          "the account probes) refuses the install right before its row would exist — the reboot's census "
          "had run before the row and its plan skips installing rows, so the host was rebooted under it",
          got["a reboot starts during the port scan"][1] == [], repr(got))
    check("install: ...and with no reboot the row is created (control)",
          got["no reboot (control)"] == (None, ["p130inst"]), repr(got))


def _delete_host130():
    flag = [True]
    _busy130(flag)
    asked = []
    _p9_patch(_rm130, "reauth_password", lambda user, pw: (asked.append(pw), "bad")[1])
    client = _p9_client(P9_ADMIN)
    got = {}
    for busy in (True, False):
        flag[0] = busy
        asked.clear()
        r = client.post("/remotes/%d/delete" % P9_HOST, json={_REAUTH_FIELD130: "x"}, headers=_XHR130)
        got[busy] = (r.status_code, len(asked), _p9_host_row(P9_HOST).id == P9_HOST)
    check("delete host: refused (409, before the password, the host and its servers kept) while a clean "
          "reboot of it is stopping its servers — the bulk delete took the rows the plan holds and its "
          "restore brought none back; with no reboot it goes on to the password (control)",
          got == {True: (409, 0, True), False: (403, 1, True)}, repr(got))


def _ssh_port130():
    flag = [True]
    _busy130(flag)
    moved = []
    _p9_patch(_p9_rv, "change_ssh_port", lambda remote, port, bind: (moved.append(port), (False, "x"))[1])
    client = _p9_client(P9_ADMIN)
    got = {}
    for busy in (True, False):
        flag[0] = busy
        moved.clear()
        r = client.post("/api/remote/%d/ssh-port" % P9_HOST, json={"port": 2222}, headers=_XHR130)
        got[busy] = (r.status_code if busy else None, list(moved), _p9_rv._ssh_port_locks[P9_HOST].locked())
    check("SSH port move: refused (409, nothing moved, the lock let go) while a clean reboot of the host is "
          "stopping its servers; with no reboot it runs (control)",
          got == {True: (409, [], False), False: (None, [2222], False)}, repr(got))
    # ...and the other way round: a reboot's census sees a move in flight.
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 1))
    lock = _p9_rv._ssh_port_locks[P9_HOST]
    with _p9.app_context():
        remote = _db130.session.get(_hr130.RemoteServer, P9_HOST)
        with lock:
            during = _hr130._host_blockers(remote)
        after = _hr130._host_blockers(remote)
        words = _hr130._blocked_sentence(during)
    check("clean reboot: an SSH port move running on the host blocks the reboot, named as one (a reboot "
          "sent inside the move booted onto a drop-in nothing verified, with no undo); with none, nothing "
          "blocks (control)",
          [b["kind"] for b in during] == ["ssh_port"] and after == []
          and "an SSH port change on" in str(words), repr((during, after, str(words))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2b. One machine, one host row: the same address AND SSH port is refused (owner's rule)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _rows130():
    """Stand-in host rows: an IPv4, a name and an IPv6 host, another one, and a legacy duplicate."""
    with _p9.app_context():
        rows = [_hr130.RemoteServer(name=n, host=h, port=p, username="root", auth_method="key",
                                    auth_credential="")
                for n, h, p in (("p130-a", _ADDR130, 22), ("p130-name", "Box.Example.test", 22),
                                ("p130-v6", "2001:db8::a", 2222), ("p130-b", _ADDR130B, 22),
                                ("p130-dup", _ADDR130, 22), ("p130-c", _ADDR130, 2204))]
        _db130.session.add_all(rows)
        _db130.session.commit()
        return {r.name: r.id for r in rows}


def _drop_rows130(ids):
    with _p9.app_context():
        for rid in ids.values():
            r = _db130.session.get(_hr130.RemoteServer, rid)
            if r is not None:
                _db130.session.delete(r)
        _db130.session.commit()


def _same_host130():
    ids = _rows130()
    tested = []
    _p9_patch(_rm130, "ssh_test_connection",
              lambda h, p, *a, **k: (tested.append((h, p)), (False, "stop"))[1])
    client = _p9_client(P9_ADMIN)
    got = {}
    try:
        for case, host, port in (("same IPv4 and port", _ADDR130, "22"),
                                 ("a name in another case", "box.EXAMPLE.test", "22"),
                                 ("IPv6 bracketed, another spelling", "[2001:DB8:0::A]", "2222"),
                                 ("same address, another port (control)", _ADDR130, "2200")):
            tested.clear()
            form = {"name": "p130new", "host": host, "ssh_port": port, "ssh_user": "root", "auth_method": "key"}
            r = client.post("/remotes/add", data=form, headers=_XHR130)
            got[case] = (r.status_code, "already uses this address" in (_p9_json(r).get("message") or ""), len(tested))
        for case, rid, form in (("edit onto another row's address and port", ids["p130-b"],
                                 {"host": _ADDR130, "ssh_port": "22"}),
                                ("edit of a legacy duplicate to its own values (control)", ids["p130-dup"],
                                 {"ssh_port": "22"}),
                                ("edit to another port (control)", ids["p130-b"], {"ssh_port": "2201"})):
            r = client.post("/remotes/%d/edit" % rid, data=form, headers=_XHR130)
            row = _p9_host_row(rid)
            got[case] = (r.status_code, (row.host, row.port))
        with _p9.app_context():
            got["helper, bracketed IPv6 by value"] = bool(_rm130.r36c_same_host_refusal("[2001:DB8:0:0::A]", 2222))
            got["helper, the row itself (control)"] = _rm130.r36c_same_host_refusal(
                "2001:db8::a", 2222, own_id=ids["p130-v6"])
    finally:
        _drop_rows130(ids)
    check("hosts: adding a host whose address and SSH port another row already has is refused (nothing "
          "dialled), its name in any case and an IPv6 address in any spelling; the same address on another "
          "port (another VM behind one IP) goes on to the connection test (control)",
          {k: got.get(k) for k in ("same IPv4 and port", "a name in another case",
                                   "IPv6 bracketed, another spelling", "same address, another port (control)")}
          == {"same IPv4 and port": (400, True, 0), "a name in another case": (400, True, 0),
              "IPv6 bracketed, another spelling": (400, True, 0),
              "same address, another port (control)": (400, False, 1)}, repr(got))
    check("hosts: editing a row onto another row's address and port is refused and changes nothing; a row "
          "saved with its own values is accepted even beside a duplicate made before the rule, and so is a "
          "move to another port (controls)",
          got["edit onto another row's address and port"] == (409, (_ADDR130B, 22))
          and got["edit of a legacy duplicate to its own values (control)"] == (200, (_ADDR130, 22))
          and got["edit to another port (control)"] == (200, (_ADDR130B, 2201)), repr(got))
    check("hosts: the same-host rule compares an IPv6 literal by value, brackets and case aside, and never "
          "matches the row being edited (control)",
          got["helper, bracketed IPv6 by value"] is True and got["helper, the row itself (control)"] is None,
          repr(got))


def _same_host_moves130():
    """The Tailscale migration and an SSH port move refuse to make a row another row's host."""
    from panel.ops.ssh_manager import hosts as _hosts130
    ids = _rows130()
    calls = []
    _p9_patch(_hosts130, "remote_check_tailscale",
              lambda server: {"running": True, "dns_name": "", "tailscale_ip": _ADDR130B})
    _p9_patch(_hosts130, "_tailscale_conn_state", lambda server: (calls.append("ssh state"), (True, True))[1])
    _p9_patch(_hosts130, "_r15c_delete_port_22", lambda server: calls.append("port 22 closed"))
    _p9_patch(_hosts130, "ssh_test_connection", lambda *a, **k: (calls.append("login test"), (False, "x"))[1])
    _p9_patch(_p9_rv, "change_ssh_port", lambda remote, port, bind: (calls.append(port), (False, "x"))[1])
    _busy130([False])
    client = _p9_client(P9_ADMIN)
    got = {}
    try:
        r = client.post("/api/remote/%d/tailscale-migrate" % ids["p130-a"], headers=_XHR130)
        got["migrate"] = (r.status_code, "already uses" in (_p9_json(r).get("message") or ""), list(calls),
                          _p9_host_row(ids["p130-a"]).host)
        for case, port in (("move onto another row's port at this address", 2204), ("another port (control)", 2203)):
            calls.clear()
            r = client.post("/api/remote/%d/ssh-port" % ids["p130-a"], json={"port": port}, headers=_XHR130)
            got[case] = (r.status_code, list(calls))
    finally:
        _drop_rows130(ids)
    check("Tailscale migration: refused before anything on the host changes when the tailnet address is "
          "another row's host on port 22 (the public port 22 rule was already deleted by the time the "
          "route could have looked)",
          got["migrate"] == (400, True, [], _ADDR130), repr(got))
    check("SSH port move: refused before the move when the new port at this address is another row's "
          "host; another port moves (control)",
          (got["move onto another row's port at this address"], got["another port (control)"][1])
          == ((409, []), [2203]), repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2c. Review 1022c's adversarial pass (builder J): the same-host rule's name, spellings and race; the SSH
#     port move and the bootstrap refuse each other; a running mods install or Run now holds a reboot
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RACE130 = "203.0.113.%d"  # NOSONAR(S1313) - documentation addresses for stand-in host rows; never dialled


def _r36j_delegate130(ids):
    """A MANAGE_REMOTES admin whose one group holds p130-b only: (user id, group id)."""
    from panel.db.models import Group as _Group130
    from panel.security import auth as _auth130
    with _p9.app_context():
        g = _Group130(name="p130-delegates", description="", is_default=False)
        g.set_permissions([_auth130.MANAGE_REMOTES, _auth130.VIEW_SERVERS])
        g.servers.append(_db130.session.get(_hr130.RemoteServer, ids["p130-b"]))
        u = _User130(username="p130_delegate", display_name="Delegate", is_superadmin=False, is_active=True,
                     **{"pass" + "word_hash": "-"})
        u.groups.append(g)
        _db130.session.add_all([g, u])
        _db130.session.commit()
        return u.id, g.id


def _r36j_drop_delegate130(uid, gid):
    from panel.db.models import Group as _Group130
    with _p9.app_context():
        for model, rid in ((_User130, uid), (_Group130, gid)):
            row = _db130.session.get(model, rid)
            if row is not None:
                _db130.session.delete(row)
        _db130.session.commit()


def _r36j_msg130(r):
    return (r.status_code, _p9_json(r).get("message") or "")


def _r36j_name_posts130(ids, uid):
    """Each way a delegated admin (and a superadmin, and nobody) meets the same-host refusal: {case: answer}."""
    pw = {"auth_method": "password", "credential": "x"}
    got = {}
    client = _p9_client(uid)
    for case, form in (("add over a hidden row", dict(pw, host=_ADDR130, ssh_port="22")),
                       ("control: add over the caller's own row", dict(pw, host=_ADDR130B, ssh_port="22")),
                       ("add with the panel's key over a hidden row", {"host": _ADDR130, "ssh_port": "22",
                                                                     "auth_method": "key"})):
        r = client.post("/remotes/add", data=dict(form, name="p130x", ssh_user="root"), headers=_XHR130)
        got[case] = _r36j_msg130(r)
    r = client.post("/remotes/%d/edit" % ids["p130-b"], data=dict(pw, host=_ADDR130, ssh_port="22"),
                    headers=_XHR130)
    got["edit onto a hidden row"] = _r36j_msg130(r)
    r = client.post("/api/remote/%d/ssh-port" % ids["p130-b"], json={"port": 2205}, headers=_XHR130)
    got["port move onto a hidden row"] = _r36j_msg130(r)
    r = _p9_client(P9_ADMIN).post("/remotes/add", data=dict(pw, host=_ADDR130, ssh_port="22", name="p130x",
                                                            ssh_user="root"), headers=_XHR130)
    got["control: a superadmin"] = _r36j_msg130(r)
    with _p9.test_request_context("/setup"):
        got["nobody signed in (the wizard)"] = (0, _rm130.r36c_same_host_refusal(_ADDR130, 22) or "")
    return got


def _r36j_names130():
    """M1: the same-host refusal names the other row only to a caller who may see it."""
    ids = _rows130()
    with _p9.app_context():
        hid = _hr130.RemoteServer(name="p130-hidden", host=_ADDR130B, port=2205, username="root",
                                  auth_method="key", auth_credential="")
        _db130.session.add(hid)
        _db130.session.commit()
        ids["p130-hidden"] = hid.id
    uid, gid = _r36j_delegate130(ids)
    tested = []
    _p9_patch(_rm130, "ssh_test_connection", lambda h, p, *a, **k: (tested.append((h, p)), (False, "stop"))[1])
    _p9_patch(_p9_rv, "change_ssh_port", lambda remote, port, bind: (tested.append(port), (False, "x"))[1])
    _busy130([False])
    try:
        got = _r36j_name_posts130(ids, uid)
    finally:
        _r36j_drop_delegate130(uid, gid)
        _drop_rows130(ids)
    hidden = ("add over a hidden row", "edit onto a hidden row", "port move onto a hidden row",
              "nobody signed in (the wizard)")
    shape = {c: (got[c][0], got[c][1].startswith("Another host already uses this address"),
                 "p130-a" in got[c][1] or "p130-hidden" in got[c][1] or "p130-dup" in got[c][1]) for c in hidden}
    check("hosts: the same-host refusal does not name a host outside the caller's groups (add, edit, an SSH port "
          "move by a delegated admin (the Tailscale migration is superadmin-only), and the first-run wizard "
          "before anyone signs in): 'Another host already uses this address', still refused, nothing dialled or "
          "moved",
          shape == {"add over a hidden row": (400, True, False), "edit onto a hidden row": (409, True, False),
                    "port move onto a hidden row": (409, True, False),
                    "nobody signed in (the wizard)": (0, True, False)} and tested == [], repr((got, tested)))
    check("hosts: ...a row in the caller's groups, and any row to a superadmin, is still named (controls); and a "
          "delegated add on the panel's own key is refused as that (403) before the same-host rule is asked, "
          "so it learns nothing of the hidden row",
          got["control: add over the caller's own row"][0] == 400
          and got["control: add over the caller's own row"][1].startswith("p130-b already uses")
          and got["control: a superadmin"][1].startswith(("p130-a already uses", "p130-dup already uses"))
          and got["add with the panel's key over a hidden row"][0] == 403
          and "already uses" not in got["add with the panel's key over a hidden row"][1], repr(got))


def _r36j_spellings130():
    """L1: spellings of one address that HOST_RE passes and the resolver dials as the same machine."""
    ids = _rows130()
    v4 = int(__import__("ipaddress").ip_address(_ADDR130))
    a, b, c, d = (v4 >> 24) & 255, (v4 >> 16) & 255, (v4 >> 8) & 255, v4 & 255
    rows = {"IPv4-mapped IPv6": ("::ffff:" + _ADDR130, 22), "bracketed IPv4-mapped": ("[::FFFF:" + _ADDR130 + "]", 22),
            "decimal integer": (str(v4), 22), "short a.b.c16": ("%d.%d.%d" % (a, b, c * 256 + d), 22),
            "hex integer": (hex(v4), 22), "octal parts": ("0%o.%d.%d.%d" % (a, b, c, d), 22),
            "trailing-dot name": ("box.example.test.", 22),
            "control: another address": (_ADDR130 + "0", 22), "control: another port": (str(v4), 2299),
            "control: a name that is not a number": ("1e100.example", 22)}
    try:
        with _p9.app_context():
            got = {k: bool(_rm130.r36c_same_host_refusal(h, p)) for k, (h, p) in rows.items()}
            passes = {k: bool(_rm130.HOST_RE.match(_rm130.canonical_host(h))) for k, (h, p) in rows.items()}
    finally:
        _drop_rows130(ids)
    check("hosts: the same-host rule matches an IPv4-mapped IPv6 address, the integer, short, hex and octal "
          "IPv4 forms inet_aton dials, and a name with the root's trailing dot as the row they reach; another "
          "address, another port and a name are not matched (controls)",
          got == {k: not k.startswith("control") for k in rows} and all(passes.values()), repr((got, passes)))


def _r36j_commit_dup130(host, port, name):
    """Store a row for `host`:`port` as another request would (its own app context and commit)."""
    with _p9.app_context():
        _db130.session.add(_hr130.RemoteServer(name=name, host=host, port=port, username="root",
                                               auth_method="key", auth_credential=""))
        _db130.session.commit()


def _r36j_race_adds130(client, seen):
    """The Hosts page's add: what another claim met during its SSH test; a row stored meanwhile."""
    got = {}
    form = {"name": "p130race", "host": _RACE130 % 50, "ssh_port": "22", "ssh_user": "root", "auth_method": "key"}
    r = client.post("/remotes/add", data=form, headers=_XHR130)
    got["add: claimed during its SSH test"] = (r.status_code, dict(seen))
    seen.clear()
    seen["commit a duplicate"] = True
    r = client.post("/remotes/add", data=dict(form, host=_RACE130 % 51, name="p130race2"), headers=_XHR130)
    with _p9.app_context():
        # The request's OWN row (the stand-in's duplicate shares this test app's one connection).
        n = _hr130.RemoteServer.query.filter_by(name="p130race2").count()
    got["add: a row stored during its SSH test"] = (r.status_code, n, "already uses" in _r36j_msg130(r)[1])
    return got


def _r36j_race_wizard130(rh):
    """The setup wizard's store with a row stored during its SSH test: (its own rows, refused said?)."""
    with _p9.test_request_context("/setup", method="POST"):
        _p9_patch(rh, "_setup_log", lambda *a, **k: None)
        rh._setup_test_and_store(_NS130j(data="{}"), {}, _hr130.RemoteServer(
            name="p130wiz", host=_RACE130 % 52, port=22, username="root", auth_method="key",
            auth_credential="", is_online=True), "")
        flashed = [m for _c, m in __import__("flask").get_flashed_messages(with_categories=True)]
    with _p9.app_context():
        n = _hr130.RemoteServer.query.filter_by(name="p130wiz").count()
    return n, any("already uses" in m for m in flashed)


def _r36j_race_migrate130(client, rid):
    """The Tailscale migration: (status, what a claim on its tailnet address met during the port 22 deletes)."""
    from panel.ops.ssh_manager import hosts as _hosts130
    from panel.routes import remote_tailscale as _rts130
    during = []
    _p9_patch(_hosts130, "remote_check_tailscale",
              lambda server: {"running": True, "dns_name": "", "tailscale_ip": _RACE130 % 54})
    _p9_patch(_hosts130, "_tailscale_conn_state", lambda server: (True, True))
    _p9_patch(_hosts130, "ssh_test_connection", lambda *a, **k: (True, ""))

    def _del22(server):
        with _rm130.r36j_host_claim(_RACE130 % 54, 22) as (why, _t):
            during.append(why or "")
    _p9_patch(_hosts130, "_r15c_delete_port_22", _del22)
    _p9_patch(_rts130, "close_connection", lambda remote: None)
    r = client.post("/api/remote/%d/tailscale-migrate" % rid, headers=_XHR130)
    return r.status_code, during


def _r36j_race130():
    """L2: one address and port is claimed from the check to the store; the store asks again."""
    from panel.routes import route_helpers as _rh130
    ids = _rows130()
    seen = {}

    def _test(h, p, *a, **k):
        # Inside the add's SSH test: another request's claim on the same address and port, and on another.
        with _rm130.r36j_host_claim(h, p) as (why, _t):
            seen["same address and port, claimed meanwhile"] = why or ""
        with _rm130.r36j_host_claim(h, p + 1) as (why, _t):
            seen["control: another port"] = why
        if seen.get("commit a duplicate"):
            _r36j_commit_dup130(h, p, "p130-raced")
        return True, "ok"
    _p9_patch(_rm130, "ssh_test_connection", _test)
    _p9_patch(_rh130, "ssh_test_connection", _test)
    _p9_patch(_rm130, "_after_add_remote", lambda app, remote, name, lgsm, reachable: ("added", 200))
    client = _p9_client(P9_ADMIN)
    try:
        got = _r36j_race_adds130(client, seen)
        got["wizard: a row stored during its SSH test"] = _r36j_race_wizard130(_rh130)
        # The edit: a row stored between its check and its commit.

        def _edit_raced(remote):
            # The other request's row lands here; the auth step itself refuses nothing ("" is falsy, as
            # the real one's None is).
            _r36j_commit_dup130(_RACE130 % 53, 22, "p130-raced-edit")
            return ""
        _p9_patch(_rm130, "_apply_edited_auth", _edit_raced)
        r = client.post("/remotes/%d/edit" % ids["p130-b"], data={"host": _RACE130 % 53, "ssh_port": "22"},
                        headers=_XHR130)
        got["edit: a row stored before its commit"] = (r.status_code, _p9_host_row(ids["p130-b"]).host)
        got["migration: claimed across its host steps"] = _r36j_race_migrate130(client, ids["p130-b"])
    finally:
        with _p9.app_context():
            for row in _hr130.RemoteServer.query.filter(_hr130.RemoteServer.name.like("p130%")).all():
                ids.setdefault(row.name + "#%d" % row.id, row.id)
        _drop_rows130(ids)
    claimed = got["add: claimed during its SSH test"][1]
    check("hosts: an add holds its address and port from the same-host check across its SSH test: another "
          "request asking for them meanwhile is refused ('another request is adding'), another port is not",
          claimed.get("control: another port", "x") is None
          and claimed.get("same address and port, claimed meanwhile", "").startswith("Another request is adding"),
          repr(got))
    mig = got["migration: claimed across its host steps"]
    check("hosts: a row stored for the same address and port while an add, the wizard or an edit was between "
          "its check and its commit refuses the store (its own row is not stored); the migration holds the "
          "tailnet address across its Tailscale SSH test and port 22 deletes",
          got["add: a row stored during its SSH test"] == (400, 0, True)
          and got["wizard: a row stored during its SSH test"] == (0, True)
          and got["edit: a row stored before its commit"] == (409, _ADDR130B)
          and mig[0] == 200 and len(mig[1]) == 1 and mig[1][0].startswith("Another request is adding"),
          repr(got))


class _NS130j:
    """The wizard's SetupState stand-in: only its `data` text is written."""

    def __init__(self, data):
        self.data = data


def _r36j_move_vs_bootstrap130():
    """L4: an SSH port move and a VPS bootstrap refuse each other."""
    from panel.routes import _shared as _sh130
    started, moved = [], []
    _p9_patch(_sh130, "_start_bootstrap_job", lambda app, rid, job, opts, actor: started.append(rid))
    _p9_patch(_p9_rv, "change_ssh_port", lambda remote, port, bind: (moved.append(port), (False, "x"))[1])
    _busy130([False])
    client = _p9_client(P9_ADMIN)
    got = {}
    lock = _p9_rv._ssh_port_locks[P9_HOST]
    try:
        with lock:
            r = client.post("/api/remote/%d/bootstrap" % P9_HOST, json={}, headers=_XHR130)
            got["bootstrap under a move"] = (r.status_code, list(started), "SSH port change is running"
                                             in _r36j_msg130(r)[1])
        with _sh130._bootstrap_lock:
            _sh130._bootstrap_jobs[P9_HOST] = {"status": "running", "started": 0, "updated": 0}
        r = client.post("/api/remote/%d/ssh-port" % P9_HOST, json={"port": 2222}, headers=_XHR130)
        got["move under a bootstrap"] = (r.status_code, list(moved), "bootstrap" in _r36j_msg130(r)[1],
                                         lock.locked())
        with _sh130._bootstrap_lock:
            _sh130._bootstrap_jobs.pop(P9_HOST, None)
        client.post("/api/remote/%d/ssh-port" % P9_HOST, json={"port": 2222}, headers=_XHR130)
        got["control: move alone"] = list(moved)
        r = client.post("/api/remote/%d/bootstrap" % P9_HOST, json={}, headers=_XHR130)
        got["control: bootstrap alone"] = (r.status_code, list(started))
    finally:
        with _sh130._bootstrap_lock:
            _sh130._bootstrap_jobs.pop(P9_HOST, None)
    check("SSH port move and bootstrap: a bootstrap is refused (409, nothing started) while a move holds the "
          "host's lock, and a move is refused (409, nothing moved, the lock let go) while a bootstrap runs; "
          "each alone goes ahead (controls)",
          got == {"bootstrap under a move": (409, [], True), "move under a bootstrap": (409, [], True, False),
                  "control: move alone": [2222], "control: bootstrap alone": (200, [P9_HOST])}, repr(got))


def _r36j_live130():
    """L5: a mods install or a Run now in flight is in the reboot's census, from before its refusal is asked."""
    from panel.core import panel_state as _ps130
    reached = []
    _stub_files130(reached)
    asked, during = [], {}

    def _busy(rid):
        asked.append(_ps130.r36j_route_jobs(P9_GS))
        return False
    _p9_patch(_hr130, "reboot_busy", _busy)
    for name, kind, ret in (("mods_action", "mods", ("", "", 0)), ("run_cron_job_now", "cron", (True, "Started"))):
        _p9_patch(_p9_sf, name, lambda *a, _k=kind, _r=ret, **k: (during.__setitem__(
            _k, [b["kind"] for b in _hr130._row_blockers([_hr130.GameServer.query.get(P9_GS)])]), _r)[1])
    _p9_patch(_p9_sf, "_apply_mod_restart", lambda gs, remote: ("", ""))
    client = _p9_client(P9_ADMIN)
    client.post("/api/server/%d/mods" % P9_GS, json={"action": "install", "mod": "sourcemod"}, headers=_XHR130)
    client.post("/api/server/%d/cron/run" % P9_GS, json=_CRON130, headers=_XHR130)
    _p9_patch(_p9_sf, "mods_action", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    client.post("/api/server/%d/mods" % P9_GS, json={"action": "install", "mod": "sourcemod"}, headers=_XHR130)
    after = _ps130.r36j_route_jobs(P9_GS)
    with _p9.app_context():
        idle = [b["kind"] for b in _hr130._row_blockers([_hr130.GameServer.query.get(P9_GS)])]
    check("clean reboot: a mods install and a Scheduled tasks Run now in flight are in the reboot's census "
          "(a reboot requested meanwhile stopped the server under them), registered before the reboot "
          "refusal is asked; and let go when they end, also when the mods install raises",
          ("mods" in during.get("mods", []) and "cron" in during.get("cron", [])
           and asked[:2] == [["mods"], ["cron"]] and after == [] and "mods" not in idle and "cron" not in idle),
          repr((during, asked, after, idle)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The Tailscale migration's refusals in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _tsmigrate_es130():
    from panel.ops.ssh_manager import hosts as _hosts130
    _p9_patch(_hosts130, "remote_check_tailscale",
              lambda server: {"running": True, "dns_name": "node.tailnet.example", "tailscale_ip": ""})
    with _p9.app_context():
        u = _db130.session.get(_User130, P9_ADMIN)
        was, u.language = u.language, "es"
        _db130.session.commit()
    got = {}
    try:
        client = _p9_client(P9_ADMIN)
        for case, ssh_on, login in (("login failed", True, (False, "Permission denied (tailnet ACL)")),
                                    ("SSH server off", False, (True, ""))):
            _p9_patch(_hosts130, "_tailscale_conn_state", lambda server, _s=ssh_on: (True, _s))
            _p9_patch(_hosts130, "ssh_test_connection", lambda *a, _l=login, **k: _l)
            r = client.post("/api/remote/%d/tailscale-migrate" % P9_HOST, headers=_XHR130)
            got[case] = (r.status_code, _p9_json(r).get("message"))
    finally:
        with _p9.app_context():
            u = _db130.session.get(_User130, P9_ADMIN)
            u.language = was
            _db130.session.commit()
    want_login = _i18n130.fill(_i18n130.translate("es", "Tailscale SSH did not work from here, so the migration "
                                                        "stopped before changing anything: {why}"),
                               why="Permission denied (tailnet ACL)")
    check("Tailscale migration: an es viewer reads why it stopped in Spanish, the login test's own words in "
          "it (the sentence was %-spliced English no catalog key matched); the SSH-server-off refusal too",
          got["login failed"] == (400, want_login) and "no funcionó" in want_login
          and got["SSH server off"][0] == 400 and "Tailscale is running" not in (got["SSH server off"][1] or ""),
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Remote Servers' live stats and badge
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _live_stats130():
    client = _p9_client(P9_ADMIN)
    got = {}
    for case, stats in (("unanswered", {"read_ok": False, "cpu_percent": "?", "memory": "?", "uptime": "unknown"}),
                        ("a reading", {"read_ok": True, "cpu_percent": "3.1", "memory": "1G", "uptime": "2 days"})):
        # (probed False: this app's monitor has never swept P9_HOST, so the badge reads Checking….)
        _p9_patch(_p9_rv, "remote_uptime", lambda remote, _s=stats: dict(_s))
        body = _p9_json(client.get("/api/remote/%d/live-stats" % P9_HOST))
        got[case] = (body.get("success"), body.get("cpu_percent"), body.get("reach"))
    check("live stats: a read the host never answered (a down Tailscale-SSH host's transport returns -1, no "
          "raise) is a failure, not success:true with '?' placeholders the card painted over its good "
          "figures; both answers carry the badge's reachable/probed pair",
          got["unanswered"][:2] == (False, None) and got["a reading"][:2] == (True, "3.1")
          and got["unanswered"][2] == got["a reading"][2] == {"reachable": True, "probed": False}, repr(got))


def _read130(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node130(name, prog):
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut130(src, head):
    """part47's _cut47, or a marker comment (and a failing run) when `head` is gone from `src`."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


_MR130 = _read130("static", "js", "manage_remotes.js")
_DOMX130 = _DOM121 + r"""
document.createTextNode = s => { const n = new N('#text'); n._t = String(s); return n; };
document.readyState = 'complete';
N.prototype.closest = function(s){ let a = this; while (a && !matches(a, s)) a = a.parentNode; return a || null; };
const _qsa130 = N.prototype.querySelectorAll;
N.prototype.querySelectorAll = function(s){
  if (s === 'input:checked') return _qsa130.call(this, 'input').filter(c => c.checked);
  return _qsa130.call(this, s); };
N.prototype.remove = function(){ if (this.parentNode) this.parentNode.removeChild(this); };
const mk = (tag, attrs, parent) => { const n = new N(tag); Object.keys(attrs || {}).forEach(k => {
  if (k === 'class') n.className = attrs[k]; else n.setAttribute(k, attrs[k]); });
  if (parent) parent.appendChild(n); return n; };
"""


def _manage_remotes_js130():
    heads = ("var _R36C_REACH =", "function _r36c_paintReach(", "function _r36c_markStale(", "function loadLiveStats(")
    cut = "".join(_cut130(_MR130, h) + ";\n" for h in heads)
    name = "Remote Servers: the stats poll keeps stale figures marked and repaints the badge"
    out = _node130(name, _DOMX130 + _SETTLE47 + r"""
global.escapeHtml = s => String(s);
const card = mk('div', {}, root);
const badge = mk('span', {id: 'remote-reach-5', class: 'badge bg-secondary ms-2'}, card);
badge.textContent = 'Checking…';
const st = mk('div', {id: 'live-stats-5'}, card);
st.dataset = {loaded: '1'}; st.innerHTML = 'CPU: 12% · RAM: 2G';
const cls = new Set(); st.classList = {toggle(c, on){ if (on) cls.add(c); else cls.delete(c); }};
let answer = null;
global.fetch = () => Promise.resolve({json: () => Promise.resolve(answer)});
const seenMR = () => ({stats: st.innerHTML, stale: cls.has('opacity-50'), staleTitle: !!st.getAttribute('title'),
  badge: [badge.className, badge.textContent, badge.getAttribute('title')]});
""" + cut + r"""
(async () => {
  const out = {};
  answer = {success: true, cpu_percent: '3', memory: '1G', disk: '10G', uptime: 'up',
            reach: {reachable: true, probed: true}};
  loadLiveStats('5'); await settle(); out.ok = seenMR();
  answer = {success: false, unreachable: true, reach: {reachable: false, probed: true}};
  loadLiveStats('5'); await settle(); out.down = seenMR();
  answer = {success: true, cpu_percent: '4', memory: '1G', disk: '10G', uptime: 'up',
            reach: {reachable: false, probed: false}};
  loadLiveStats('5'); await settle(); out.back = seenMR();
  console.log(JSON.stringify(out));
})();
""")
    if out is None:
        return
    ok_stats = "<i class=\"bi bi-cpu\"></i> CPU: 3% &middot; <i class=\"bi bi-memory\"></i> RAM: 1G"
    seen = {k: (out.get(k) or {}) for k in ("ok", "down", "back")}
    stale = {k: (v.get("stats", "")[:len(ok_stats)], v.get("stale"), v.get("staleTitle")) for k, v in seen.items()}
    check("Remote Servers: a failed stats read keeps the last good figures, dimmed and titled as stale, and "
          "a later reading clears that",
          stale == {"ok": (ok_stats, False, False), "down": (ok_stats, True, True),
                    "back": (ok_stats.replace("3%", "4%"), False, False)}, repr(out))
    check("Remote Servers: the Reachable / Unreachable / Checking… badge follows the poll's pair, in the "
          "template's words (it was drawn once and kept reading Checking… or Reachable)",
          {k: v.get("badge") for k, v in seen.items()}
          == {"ok": ["badge bg-success ms-2", "Reachable", "The panel can reach this host over SSH"],
              "down": ["badge bg-danger ms-2", "Unreachable", "The panel cannot reach this host over SSH"],
              "back": ["badge bg-secondary ms-2", "Checking…", "The panel has not checked this host yet"]},
          repr(out))


_DB130 = _read130("static", "js", "dashboard.js")
_ST130 = _read130("static", "js", "server_tags.js")


def _tag_filter_js130():
    heads = ("window.toggleTagFilter = function(", "window.dropTagFilter = function(", "function rowHasEveryTag(",
             "function filterServers(")
    cut = "var _tagFilter = [];\n" + "".join(_cut130(_DB130, h) + "\n" for h in heads)
    name = "dashboard: the tag filter after a row's tags change"
    out = _node130(name, _DOMX130 + _SETTLE47 + r"""
global.t = s => s; global.toast = () => {};
let confirmNow = true, pendingDialog = null;
// Confirming an edit unticks every box: the save is "this row carries no tag".
global.confirmDialog = o => { pendingDialog = o; if (!confirmNow) return;
  if (o.bodyNode) o.bodyNode.querySelectorAll('input').forEach(c => { c.checked = false; });
  o.onConfirm(); };
const T1 = {id: 1, name: 'prod', notify: true, server_ids: [7, 8], server_count: 2};
let TAGS = [T1], saved = null, deleted = null;
global.fetch = (u, o) => {
  let d = {success: true};
  if (/\/api\/tags$/.test(u)) d = {tags: TAGS};
  else if (/\/api\/server\/(\d+)\/tags$/.test(u)) { saved = JSON.parse(o.body).tag_ids; d = {success: true, tags: []}; }
  else if (/\/api\/tags\/\d+\/delete$/.test(u)) { deleted = u; d = {success: true}; }
  return Promise.resolve({ok: true, json: () => Promise.resolve(d)}); };
const bar = mk('div', {class: 'tag-filter-bar'}, root);
const fbtn = mk('button', {class: 'btn tag-filter', 'data-tag-id': '1'}, bar);
mk('div', {id: 'tag-list'}, root);
const card = mk('div', {class: 'server-remote-card'}, root), tb = mk('tbody', {}, card);
const rows = {};
[7, 8, 9].forEach(id => { const tr = mk('tr', {'data-server-id': String(id)}, tb); rows[id] = tr;
  const td = mk('td', {}, tr); mk('strong', {}, td).textContent = 's' + id;
  const holder = mk('div', {id: 'srv-tags-' + id, class: 'srv-tags'}, td);
  if (id !== 9) mk('span', {class: 'badge tag-chip', 'data-tag-id': '1'}, holder);
  mk('button', {class: 'tagbtn'}, td); });
const shown = () => [7, 8, 9].filter(id => rows[id].style.display !== 'none');
""" + cut + _ST130 + r"""
(async () => {
  const out = {};
  await settle();
  window.toggleTagFilter(1, fbtn); out.filtered = shown();
  // Save: untick prod on server 7.
  window.editServerTags(7, rows[7].querySelector('button.tagbtn')); await settle(); await settle();
  out.afterSave = {saved: saved, shown: shown()};
  // Another admin took prod off 8: the dialog's repaint from /api/tags, before any save.
  confirmNow = false; TAGS = [Object.assign({}, T1, {server_ids: []})];
  window.editServerTags(8, rows[8].querySelector('button.tagbtn')); await settle(); await settle();
  out.afterRepaint = shown();
  // Delete the tag the filter is on.
  confirmNow = true;
  rows[8].querySelector('#srv-tags-8').appendChild(mk('span', {class: 'badge tag-chip', 'data-tag-id': '1'}));
  const list = root.querySelector('#tag-list');
  const del = list.querySelectorAll('button').filter(b => b.textContent === 'Delete')[0];
  del.on.click(); await settle(); await settle();
  out.afterDelete = {deleted: !!deleted, shown: shown(),
                     filterButton: !!root.querySelector('.tag-filter[data-tag-id="1"]'), filter: _tagFilter.slice()};
  console.log(JSON.stringify(out));
})();
""")
    if out is None:
        return
    check("dashboard tag filter: saving a row's tags without the filtered tag hides the row at once (it "
          "stayed shown, and Select shown ticked it for a bulk action on the group it had left)",
          out.get("filtered") == [7, 8] and out.get("afterSave") == {"saved": [], "shown": [8]}, repr(out))
    check("dashboard tag filter: ...the tag dialog's repaint of a row from the tags as they are now runs "
          "the filter too",
          out.get("afterRepaint") == [], repr(out))
    check("dashboard tag filter: deleting the tag the filter is on drops it from the filter and its button "
          "from the bar, and every server shows again",
          out.get("afterDelete") == {"deleted": True, "shown": [7, 8, 9], "filterButton": False, "filter": []},
          repr(out))


try:
    _arm130()
    for _fn130 in (_files_gates130, _gmod_late130, _cron_after_send130, _install_recheck130, _delete_host130,
                   _ssh_port130, _same_host130, _same_host_moves130, _tsmigrate_es130, _live_stats130,
                   _r36j_names130, _r36j_spellings130, _r36j_race130, _r36j_move_vs_bootstrap130, _r36j_live130):
        _fn130()
        _p9_restore_all()
        _arm130()
finally:
    _p9_restore_all()

_manage_remotes_js130()
_tag_filter_js130()

check("part130: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP130_START, repr(_P9_TRIPPED[_TRIP130_START:][:6]))
