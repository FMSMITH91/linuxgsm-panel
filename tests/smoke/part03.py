"""Part 3 of the smoke suite. Imported for its side effects: see tests/smoke_test.py.

Two markers here are about the split, not the checks. `# pylint: disable=reimported`: each section
imports what it uses under an alias of its own, as it did in the single-file suite, whose one try
hid those imports from Pylint's reimport rule. `# noqa: MC0001` (mccabe): a block whose branches
mccabe counted, until the split, as part of that one try, already reported as too complex.
"""
from smoke.part01 import (_check_audit_zone_cleanup_on_upgrade,
                          _check_audit_zone_failure_is_logged, _sm_core, _sm_hosts, app, auth,
                          auth_password_problem, check, client_as, CONFIG_FILE, CRED_KEY_FILE,
                          DATA_DIR, db, DB_PATH, GameServer, Group, os, RemoteServer, SECRET_FILE,
                          sys, User)
from smoke.part02 import (_appmod_ij, _cg_remote_id, _ij_game, _ij_ps, _ij_wait, _ijw_time,
                          _install_jobs_sm, _install_lock_sm, _msmod, _TSAudit, admin_id, bc_code,
                          c, deleg_id, encrypt_secret, gs_id, mru_id, remote_id)

# ── a port scan that could not be read allocates NO port (Aikido 745379002) ────────────────
# resolve_free_port read a failed scan as "nothing is listening" (`or ()`, over a comment
# saying the install "then fails with a clear error" — it did not): the port it offered was
# opened at step 6 with no second look when the game reported it, under the new server's name,
# in front of whatever was already listening there. The tailscale and local transports do not
# raise on a timeout; they return ("", "…timed out", -1), which is what `ss` answers here.
_su_saved, _su_ss, _su_allow = {}, [], []


def _su_stub(mod, name, fn):
    _su_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


def _su_run(server, cmd, **k):
    if "ss -H -lntu" in cmd:
        _su_ss.append(1)
        return ("", "SSH command timed out", -1)
    return ("", "", 0)


try:
    _su_stub(_sm_core, "get_connection",
             lambda *a, **k: (_ for _ in ()).throw(AssertionError("a real SSH connection")))
    _su_stub(_sm_core, "run_command", _su_run)
    _su_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
    _su_stub(_msmod, "remote_ufw_allow_game_ports",
             lambda r, ports, name: (_su_allow.append(list(ports)), ([], ""))[1])
    _ij_ps._port_scan_cache.clear()
    _su_r = c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                         "server_name": "scanfail", "port": "28980"},
                   headers={"X-Requested-With": "XMLHttpRequest"})
    with app.app_context():
        _su_row = GameServer.query.filter_by(short_name="scanfail").first()
        _su_row_id = _su_row.id if _su_row is not None else None
    check("install: a port scan that twice could not be read creates no server — it is "
          "refused, naming the host",
          _su_r.status_code == 400 and _su_row_id is None
          and "can't check which ports are free" in ((_su_r.get_json() or {}).get("message") or ""),
          "status=%d body=%r row=%r" % (_su_r.status_code, _su_r.get_json(), _su_row_id))
    check("install: ...after one fresh second look, and with nothing sent to the firewall",
          len(_su_ss) == 2 and _su_allow == [], "scans=%d opened=%r" % (len(_su_ss), _su_allow))
    _su_fp = c.get("/api/free-port?remote_id=%d&desired=28980&game=gmod" % _cg_remote_id)
    check("free-port: ...and the install form's hint is 'no suggestion', not a 500",
          _su_fp.status_code == 200 and (_su_fp.get_json() or {}).get("port") is None,
          "status=%d body=%r" % (_su_fp.status_code, _su_fp.get_json()))
    if _su_row_id is not None:
        with app.app_context():
            db.session.delete(db.session.get(GameServer, _su_row_id))
            db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_su_row_id, None)
finally:
    for (_m, _n), _v in _su_saved.items():
        setattr(_m, _n, _v)

# ...and the branch where the reported port is ALREADY HELD by something that is not us.
# Until now this was checked by reading the AST. Here it is executed: step 6 must keep the
# port the panel allocated, and — the part that was actually broken — the firewall must not be
# opened for the port it just refused, in either of the two places that open ports.
_cf_saved, _cf_calls = {}, []


def _cf_stub(mod, name, fn):
    _cf_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


try:
    _cf_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
    _cf_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
    _cf_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
    # The clash is about the port LinuxGSM REPORTS, not necessarily the one the game binds:
    # here the game honours the panel's config and comes up on 28994, while 28995 stays
    # someone else's. That also lets the post-start poll exit on its first tick instead of
    # running its full 30 x 3s — without which the job is still mid-poll when the checks run,
    # and the post-start re-detect (the second place that opens ports) is never reached. A
    # mutation proved that: reverting the re-detect's filter changed nothing until this did.
    _cf_state = {"started": False}

    def _cf_run_as(remote, user, action, **k):
        if action == "start":
            _cf_state["started"] = True
        return ("", "", 0)

    _cf_stub(_sm_core, "run_as_game_user", _cf_run_as)
    _cf_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
    _cf_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
    _cf_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
    _cf_stub(_msmod, "_looks_installed", lambda *a, **k: True)
    _cf_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
    _cf_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
    _cf_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
    _cf_stub(_msmod, "install_game_cron", lambda *a, **k: None)
    _cf_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
    _cf_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
    _cf_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
    _cf_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
    # 28995 is occupied by something the panel has no row for — a hand-installed server, a
    # container, anything never imported through /discover.
    _cf_stub(_msmod, "_remote_listening_ports",
             lambda r: ({22, 28995, 28994} if _cf_state["started"] else {22, 28995}))
    _cf_stub(_msmod, "detect_game_ports",
             lambda *a, **k: {"game_port": 28995, "open_ports": [28995, 28996]})
    _cf_stub(_msmod, "remote_ufw_allow_game_ports",
             lambda r, ports, name: _cf_calls.append(tuple(sorted(ports))))
    _cf_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
    _appmod_ij._remote_listening_ports = lambda r: {22, 28995}

    c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                 "server_name": "jobclash", "port": "28994"},
           follow_redirects=True)
    with app.app_context():
        _cf_row = GameServer.query.filter_by(short_name="jobclash").first()
        _cf_id = _cf_row.id if _cf_row else None
    check("install job (clash): the POST created a row", _cf_id is not None)
    if _cf_id is not None:
        _cjob, _crow_st, _cf_settled = _ij_wait(_cf_id)
        check("install job (clash): the job finished before the stubs are handed back",
              _cf_settled,
              "job=%r row=%r — a thread still running here would walk into the next block's "
              "stubs" % (_cjob.get("status"), _crow_st))
        with app.app_context():
            _cf_port = db.session.get(GameServer, _cf_id).port
        check("install job (clash): the panel KEEPS its own port, it does not adopt one "
              "something else is on", _cf_port == 28994,
              "port=%r — adopting it makes every status answer read the other process's "
              "socket" % (_cf_port,))
        _cf_opened = sorted({p for call in _cf_calls for p in call})
        check("install job (clash): ...and never opens the refused port in the firewall",
              28995 not in _cf_opened,
              "ufw was asked to open %s — `ufw allow <port> comment <name>` REPLACES a rule "
              "differing only by comment, so this retags the other server's rule" % (_cf_opened,))
        check("install job (clash): ...while still opening its own",
              28994 in _cf_opened, "opened %s" % (_cf_opened,))
        with app.app_context():
            _d = db.session.get(GameServer, _cf_id)
            if _d is not None:
                db.session.delete(_d); db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_cf_id, None)
finally:
    for (_m, _n), _v in _cf_saved.items():
        setattr(_m, _n, _v)

# ...and the THIRD answer, which used to be told as the second. decide_port_adoption returns
# "could not look" as well as "taken" and "free", but it carried that answer only in the
# WORDING of taken_by — the phrase "something the panel could not check for" — so the caller
# could not tell it from a named holder. On a Tailscale host still busy from a 25-minute
# SteamCMD run the 8-second `ss` times out, the transport returns ("", "…timed out", -1)
# WITHOUT raising, and the operator was told: "it wants port 28998, which something the panel
# could not check for already uses. ... or free that port on the host." The audit log recorded
# `install_complete success=False detail="port 28998 clashes with something the panel could
# not check for"`, and the firewall was narrowed over a clash nobody observed — so the query
# port the game does need was left closed too. 28998 was very probably free.
_ur_saved, _ur_calls = {}, []


def _ur_stub(mod, name, fn):
    _ur_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


# time.sleep, skipped. The post-start verification polls 30 × 3s, and with the host
# unreadable there is no early exit from it — 90 real seconds for one check. Only
# manage_servers' own `time` is swapped, and only inside this block.
import types as _ur_types
_ur_fast = _ur_types.SimpleNamespace(sleep=lambda _s: None, time=_ijw_time.time)

try:
    _ur_stub(_msmod, "time", _ur_fast)
    _ur_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
    _ur_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
    _ur_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
    _ur_stub(_sm_core, "run_as_game_user", lambda *a, **k: ("", "", 0))
    _ur_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
    _ur_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
    _ur_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
    _ur_stub(_msmod, "_looks_installed", lambda *a, **k: True)
    _ur_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
    _ur_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
    _ur_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
    _ur_stub(_msmod, "install_game_cron", lambda *a, **k: None)
    _ur_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
    _ur_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
    _ur_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
    _ur_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
    # The scan never answers — the failure mode the paramiko-only `except` below it misses.
    _ur_stub(_msmod, "_remote_listening_ports", lambda r: None)
    _ur_stub(_msmod, "detect_game_ports",
             lambda *a, **k: {"game_port": 28998, "open_ports": [28998, 28999]})
    _ur_stub(_msmod, "remote_ufw_allow_game_ports",
             lambda r, ports, name: _ur_calls.append(tuple(sorted(ports))))
    _ur_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
    _appmod_ij._remote_listening_ports = lambda r: {22}

    c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                 "server_name": "jobunread", "port": "28997"},
           follow_redirects=True)
    with app.app_context():
        _ur_row = GameServer.query.filter_by(short_name="jobunread").first()
        _ur_id, _ur_name = (_ur_row.id, _ur_row.name) if _ur_row else (None, "")
    check("install job (unreadable scan): the POST created a row", _ur_id is not None)
    if _ur_id is not None:
        _ujob, _urow_st, _ur_settled = _ij_wait(_ur_id)
        check("install job (unreadable scan): the job finished before the stubs are handed back",
              _ur_settled, "job=%r row=%r" % (_ujob.get("status"), _urow_st))
        _ur_msg = _ujob.get("message") or ""
        with app.app_context():
            _ur_done = db.session.get(GameServer, _ur_id)
            _ur_port = _ur_done.port
            _ur_audit = [(a.success, a.detail or "") for a in
                         _TSAudit.query.filter_by(action="install_complete",
                                                  target=_ur_name).all()]
        check("install job (unreadable scan): the panel keeps its own port, as before",
              _ur_port == 28997, "port=%r" % (_ur_port,))
        check("install job (unreadable scan): ...but does NOT report a clash it never saw",
              "already uses" not in _ur_msg,
              "the operator is sent to free a port off a process nobody observed: %r"
              % (_ur_msg[:220],))
        check("install job (unreadable scan): ...it says it could not read the host",
              "could not read" in _ur_msg, repr(_ur_msg[:220]))
        check("install job (unreadable scan): ...and the audit log records no clash either",
              bool(_ur_audit) and all(_s and "clashes with" not in d for _s, d in _ur_audit),
              "install_complete rows: %r — the trail said this install failed on a port "
              "clash that was never observed" % (_ur_audit,))
        _ur_opened = sorted({p for call in _ur_calls for p in call})
        check("install job (unreadable scan): ...the unverified port is still not opened",
              28998 not in _ur_opened,
              "`ufw allow <port> comment <name>` REPLACES a rule differing only by comment, "
              "and the panel cannot say this port is free: %s" % (_ur_opened,))
        check("install job (unreadable scan): ...while the ports never in question ARE opened",
              28997 in _ur_opened and 28999 in _ur_opened,
              "opened %s — query/rcon were closed over a clash nobody observed"
              % (_ur_opened,))
        with app.app_context():
            _d = db.session.get(GameServer, _ur_id)
            if _d is not None:
                db.session.delete(_d); db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_ur_id, None)
finally:
    for (_m, _n), _v in _ur_saved.items():
        setattr(_m, _n, _v)

# ...and the same read, in the OTHER place the install uses it: the 90-second wait after
# `start`. That was `gs.port in (_remote_listening_ports(remote) or set())`, so a scan that
# could not be read became the measured claim "nothing is listening" — thirty times. The
# `except Exception: really_up = (s_rc == 0)` two lines below shows the author knew about an
# unreachable host, but it only fires for paramiko, which RAISES; tailscale and local return
# ("", "…timed out", -1). A running server was therefore committed gs.status="offline" and the
# operator told "it hasn't opened port X yet", with `install_complete success=False detail=
# "started; port X not open after 90s"` in the audit log. Here the scan works at step 6 (so
# the port is adopted — the positive half) and stops answering from `start` onwards.
_pu_saved, _pu_state = {}, {"started": False}


def _pu_stub(mod, name, fn):
    _pu_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


def _pu_run_as(remote, user, action, **k):
    if action == "start":
        _pu_state["started"] = True
    return ("", "", 0)


try:
    _pu_stub(_msmod, "time", _ur_fast)
    _pu_stub(_sm_core, "run_command", lambda *a, **k: ("", "", 0))
    _pu_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
    _pu_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
    _pu_stub(_sm_core, "run_as_game_user", _pu_run_as)
    _pu_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
    _pu_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
    _pu_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
    _pu_stub(_msmod, "_looks_installed", lambda *a, **k: True)
    _pu_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
    _pu_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
    _pu_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
    _pu_stub(_msmod, "install_game_cron", lambda *a, **k: None)
    _pu_stub(_msmod, "ensure_persistent_bans", lambda *a, **k: None)
    _pu_stub(_msmod, "sm_game_engine", lambda *a, **k: "source")
    _pu_stub(_msmod, "set_autostart", lambda *a, **k: (True, ""))
    _pu_stub(_msmod, "remote_ufw_close_game_port", lambda *a, **k: None)
    _pu_stub(_msmod, "remote_ufw_allow_game_ports", lambda *a, **k: None)
    _pu_stub(_msmod, "_remote_listening_ports",
             lambda r: (None if _pu_state["started"] else {22}))
    _pu_stub(_msmod, "detect_game_ports",
             lambda *a, **k: {"game_port": 29002, "open_ports": [29002]})
    _pu_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
    _appmod_ij._remote_listening_ports = lambda r: {22}

    c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                 "server_name": "jobpoll", "port": "29001"},
           follow_redirects=True)
    with app.app_context():
        _pu_row = GameServer.query.filter_by(short_name="jobpoll").first()
        _pu_id = _pu_row.id if _pu_row else None
    check("install job (unreadable poll): the POST created a row", _pu_id is not None)
    if _pu_id is not None:
        _pjob, _prow_st, _pu_settled = _ij_wait(_pu_id)
        check("install job (unreadable poll): the job finished before the stubs are handed back",
              _pu_settled, "job=%r row=%r" % (_pjob.get("status"), _prow_st))
        _pu_msg = _pjob.get("message") or ""
        with app.app_context():
            _pu_done = db.session.get(GameServer, _pu_id)
            _pu_status, _pu_port = _pu_done.status, _pu_done.port
        check("install job (unreadable poll): a scan that could be READ is still used",
              _pu_port == 29002,
              "port=%r — step 6 adopted nothing, so this says the stub, not the fix" % (_pu_port,))
        check("install job (unreadable poll): a start whose port could not be read is not "
              "written offline",
              _pu_status == "online",
              "status=%r — thirty unreadable scans were counted as thirty readings of an "
              "empty socket table, on a server that started fine (start rc 0)" % (_pu_status,))
        check("install job (unreadable poll): ...and the operator is not told the port is shut",
              "hasn't opened port" not in _pu_msg, repr(_pu_msg[:220]))
        with app.app_context():
            _d = db.session.get(GameServer, _pu_id)
            if _d is not None:
                db.session.delete(_d); db.session.commit()
        with _install_lock_sm:
            _install_jobs_sm.pop(_pu_id, None)
finally:
    for (_m, _n), _v in _pu_saved.items():
        setattr(_m, _n, _v)

# ── step 4: "couldn't tell" is not "not installed" ──────────────────────────────────────────
# _looks_installed answers True / False / None, and step 4 tested `is True`, which sent None
# down the False path. That path is destructive: it wipes /home/<n>/lgsm/tmp and re-runs the
# 30-minute auto-install twice more, then writes installed=False / status="failed" with "the
# download may be corrupt or the mirror unreachable" — a diagnosis of a download it never
# managed to look at. On a Tailscale host the verification read right after a 20 GB download
# times out without raising, so a fully installed Rust server got ~90 minutes of re-downloading
# and then a failure. Commit 7d1d64f gave the helper its third state and taught app.py and
# api.py to branch on it; this caller was missed. Both branches are driven here.
_lv_saved, _lv_cmds = {}, []


def _lv_stub(mod, name, fn):
    _lv_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


def _lv_run_command(remote, cmd, **k):
    _lv_cmds.append(cmd)
    return ("", "", 0)


def _lv_install(short, verdict, port):
    """Run one install with _looks_installed pinned to `verdict`; -> (row state, commands).

    Re-pointed WITHOUT going through _lv_stub: that saves the current value, and by the second
    call the current value is the first call's lambda — restoring it would leave the stub on
    the module for every later check in this file. The real one is saved once, below."""
    del _lv_cmds[:]
    _msmod._looks_installed = lambda *a, **k: verdict
    c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": "gmod",
                                 "server_name": short, "port": str(port)},
           follow_redirects=True)
    with app.app_context():
        _row = GameServer.query.filter_by(short_name=short).first()
        _rid = _row.id if _row else None
    if _rid is None:
        return None, list(_lv_cmds)
    _ij_wait(_rid, 60)
    with app.app_context():
        _r = db.session.get(GameServer, _rid)
        _state = (_r.status, _r.installed, _r.install_error or "", _r.install_retryable)
        db.session.delete(_r); db.session.commit()
    with _install_lock_sm:
        _install_jobs_sm.pop(_rid, None)
    return _state, list(_lv_cmds)


try:
    _lv_stub(_msmod, "_looks_installed", _msmod._looks_installed)   # saved once, for restore
    _lv_stub(_msmod, "time", _ur_fast)
    _lv_stub(_sm_core, "run_command", _lv_run_command)
    _lv_stub(_sm_core, "create_game_user", lambda *a, **k: ("", "", 0))
    _lv_stub(_msmod, "host_account_state", lambda *a, **k: "absent")
    _lv_stub(_sm_core, "run_as_game_user", lambda *a, **k: ("", "", 0))
    _lv_stub(_sm_core, "run_privileged", lambda *a, **k: ("freed=0 held=0 slots=10", "", 0))
    _lv_stub(_ij_game, "list_server_commands", lambda *a, **k: ["start", "stop"])
    _lv_stub(_ij_ps, "_invalidate_port_scan", lambda *a, **k: None)
    _lv_stub(_msmod, "install_game_dependencies", lambda *a, **k: ("", "", 0))
    _lv_stub(_msmod, "parse_missing_deps", lambda *a, **k: [])
    _lv_stub(_msmod, "lgsm_write_config", lambda *a, **k: (True, ""))
    _lv_stub(_msmod, "_remote_listening_ports", lambda r: {22})
    _lv_stub(_msmod, "detect_game_ports", lambda *a, **k: {"game_port": 0, "open_ports": []})
    _lv_stub(_msmod, "remote_ufw_allow_game_ports", lambda *a, **k: None)
    _lv_saved[(_appmod_ij, "_remote_listening_ports")] = _appmod_ij._remote_listening_ports
    _appmod_ij._remote_listening_ports = lambda r: {22}

    _lv_none, _lv_none_cmds = _lv_install("jobcantsay", None, 29011)
    check("install step 4: a verification that could not be READ does not re-download",
          _lv_none is not None
          and sum(1 for _cmd in _lv_none_cmds if "auto-install" in _cmd) == 1,
          "auto-install ran %r times — up to 90 minutes spent on a host that may already hold "
          "the files" % (sum(1 for _cmd in _lv_none_cmds if "auto-install" in _cmd),))
    check("install step 4: ...and does not wipe the download it never looked at",
          not any("lgsm/tmp" in _cmd for _cmd in _lv_none_cmds),
          "the cached archive is deleted on the strength of a read that failed")
    check("install step 4: ...nor blame a corrupt download it never saw",
          _lv_none is not None and "may be corrupt" not in _lv_none[2],
          repr(_lv_none[2][:200]) if _lv_none else "no row")
    check("install step 4: ...saying it could not read the host, and staying retryable",
          _lv_none is not None and _lv_none[0] == "failed"
          and "could not read the host" in _lv_none[2] and _lv_none[3] is True,
          repr(_lv_none))
    # The positive control, and the branch that must NOT change: a host that answered and
    # said the files are not there really is a failed download — wiped, retried three times,
    # and reported as what it is.
    _lv_no, _lv_no_cmds = _lv_install("jobnofiles", False, 29012)
    check("install step 4: a host that ANSWERED 'not installed' still retries the download",
          sum(1 for _cmd in _lv_no_cmds if "auto-install" in _cmd) == 3,
          "auto-install ran %r times"
          % (sum(1 for _cmd in _lv_no_cmds if "auto-install" in _cmd),))
    check("install step 4: ...still wipes the cached archive between tries",
          any("lgsm/tmp" in _cmd for _cmd in _lv_no_cmds))
    check("install step 4: ...and still reports the corrupt download it did observe",
          _lv_no is not None and _lv_no[0] == "failed" and "may be corrupt" in _lv_no[2],
          repr(_lv_no))
finally:
    for (_m, _n), _v in _lv_saved.items():
        setattr(_m, _n, _v)

# ── /api/installs: the progress a corner widget can follow from any page ────────────────────
# A game-server install runs for five to forty-five minutes, and its only progress row lived on
# the Game Servers page. Start one from "Install a Server" and you got a toast reading
# "Progress is shown live below" — below was nothing — and the dashboard then listed the server
# as installing with no progress of any kind. Nothing answered "is anything installing", so
# this endpoint does, and install_progress.js renders it wherever you are.
#
# The access filter is the part that matters: the socket ping that drives the widget carries no
# payload precisely because authorization happens HERE.
import time as _ij_time
from panel.core.panel_state import _install_jobs as _ij, _install_lock as _il
with _il:
    _ij[gs_id] = {"status": "running", "step": 3, "total": 8,
                  "step_name": "Installing dependencies", "message": "", "log": [],
                  "started": _ij_time.time() - 42, "updated": _ij_time.time(),
                  "name": "probe-install"}
try:
    _ins = c.get("/api/installs")
    _ij_rows = (_ins.get_json() or {}).get("installs") or []
    check("installs: a running install is listed", _ins.status_code == 200 and len(_ij_rows) == 1,
          _ins.get_json())
    _row = _ij_rows[0] if _ij_rows else {}
    check("installs: ...with the step, the total and a percentage the widget can draw",
          _row.get("step") == 3 and _row.get("total") == 8 and _row.get("percent") == 37,
          _row)
    check("installs: ...and how long it has been going",
          isinstance(_row.get("elapsed"), int) and _row["elapsed"] >= 40, _row.get("elapsed"))
    # THE security property: a viewer who cannot see the server must not learn its name from
    # this endpoint, or an install would announce every server on the panel to everyone.
    # A user in NO group sees no remotes, so get_user_servers() is empty for them — the same
    # filter the dashboard and the palette use, which is the whole argument for the socket ping
    # that drives the widget carrying no payload of its own.
    with app.app_context():
        _nou = User(username="noaccess-installs",
                    password_hash=auth.hash_password("Str0ng!passw0rd-na"),
                    display_name="No Access", is_superadmin=False, is_active=True)
        db.session.add(_nou); db.session.commit()
        _nou_id = _nou.id
    try:
        _mine_ins = client_as(_nou_id).get("/api/installs")
        check("installs: a user without access to that server is told about NO install",
              _mine_ins.status_code == 200
              and not ((_mine_ins.get_json() or {}).get("installs") or []),
              _mine_ins.get_json())
    finally:
        with app.app_context():
            _d = db.session.get(User, _nou_id)
            if _d:
                db.session.delete(_d); db.session.commit()
    # A GMod install with content has NINE steps, and the row reads the job's own total. A
    # fixed 8 (in _install_row since api_installs was split) left every suite green, because
    # the probe above is an 8-step job — and it draws a 9-step install's bar past its end.
    with _il:
        _ij[gs_id]["total"] = 9
    _row9 = ((c.get("/api/installs").get_json() or {}).get("installs") or [{}])[0]
    check("installs: ...the total and the percentage are the job's own (a 9-step install)",
          _row9.get("total") == 9 and _row9.get("percent") == 33, _row9)
    # A finished job is not an install in progress — the widget settles those through the
    # per-server endpoint, and leaving them here would pin a card open forever.
    with _il:
        _ij[gs_id]["status"] = "done"
    check("installs: a finished job drops out of the live list",
          not ((c.get("/api/installs").get_json() or {}).get("installs") or []))
finally:
    with _il:
        _ij.pop(gs_id, None)

# ── install-status: a row whose job was lost is settled by asking the host ──────────────────
# A row left "installing" with no job behind it (the worker died with a panel restart) is put
# to the host: files there -> installed, offline; clearly not -> failed; no answer -> nothing
# written. None of the three had a test: marking a verified install NOT installed (in
# _reconcile_lost_install since api_server_install_status was split) left every suite green.
import panel.routes.api as _rl_api
_rl_saved = _rl_api._looks_installed
with app.app_context():
    _rl_row = db.session.get(GameServer, gs_id)
    _rl_before = (_rl_row.status, _rl_row.installed)
_rl_seen = {}
try:
    for _rl_verdict in (True, False, None):
        with app.app_context():
            _rl_row = db.session.get(GameServer, gs_id)
            _rl_row.status, _rl_row.installed = "installing", False
            db.session.commit()
        _rl_api._looks_installed = lambda *a, _v=_rl_verdict, **k: _v
        _rl_js = c.get("/api/server/%d/install-status" % gs_id).get_json() or {}
        with app.app_context():
            _rl_row = db.session.get(GameServer, gs_id)
            _rl_seen[_rl_verdict] = (_rl_js.get("status"), _rl_row.status, _rl_row.installed)
finally:
    _rl_api._looks_installed = _rl_saved
    with app.app_context():
        _rl_row = db.session.get(GameServer, gs_id)
        _rl_row.status, _rl_row.installed = _rl_before
        db.session.commit()
check("install-status: a lost job whose files ARE on the host is settled installed, offline",
      _rl_seen.get(True) == ("done", "offline", True), repr(_rl_seen))
check("install-status: ...one the host says is NOT there is failed, and says so",
      _rl_seen.get(False) == ("failed", "failed", False), repr(_rl_seen))
check("install-status: ...and one the host would not answer for is left as it was",
      _rl_seen.get(None) == ("interrupted", "installing", False), repr(_rl_seen))


# ── Cookie-reuse defense: a session/remember cookie captured before logout must
#    NOT work after logout. We log in for real (so we get genuine signed session +
#    remember_token cookies), clone the cookie jar the way a thief would, log out,
#    then replay the pre-logout cookies. They must work BEFORE and be rejected AFTER.
#    This proves logout invalidates cookies server-side (epoch bump), not just in the
#    browser (where clearing the client's copy wouldn't stop a captured one). ──
def _cookie_names(client):
    return {k[2] for k in getattr(client, "_cookies", {})}


def _clone_cookies(src, keep=None):
    """A fresh client holding a snapshot of src's cookies (optionally only those
    whose name is in `keep`) — a stand-in for cookies captured off the wire/disk."""
    t = app.test_client()
    jar = dict(getattr(src, "_cookies", {}))
    if keep is not None:
        jar = {k: v for k, v in jar.items() if k[2] in keep}
    t._cookies = jar
    return t


victim = app.test_client()
lr = victim.post("/login", data={"username": "smoke_admin",
                                 "password": "Str0ng!passw0rd", "remember": "on"})
check("real login succeeds (302 to app)", lr.status_code == 302, "got %d" % lr.status_code)
names = _cookie_names(victim)
check("login issued a session cookie", any("session" in n for n in names), str(names))
check("login issued a remember_token cookie", "remember_token" in names, str(names))

# Snapshot the cookies a thief would hold — BOTH cookies, and the remember_token
# (the long-lived one) on its own — while the victim is still logged in.
thief = _clone_cookies(victim)
thief_rt = _clone_cookies(victim, keep={"remember_token"})
check("stolen cookie works BEFORE logout (200)", thief.get("/").status_code == 200)

# Log the victim out (bumps auth_epoch), then replay the snapshots.
victim.post("/logout")
check("REUSE BLOCKED: stolen cookie rejected AFTER logout (not 200)",
      thief.get("/").status_code != 200, "cookie still valid after logout!")
check("REUSE BLOCKED: stolen remember_token rejected after logout (not 200)",
      thief_rt.get("/").status_code != 200, "remember_token still valid after logout!")

# ── ...and logout must not CLAIM a revocation it did not make ──────────────────────────────
# The handler's stated purpose is server-side invalidation — "clearing the client's copy alone
# wouldn't stop a copy captured earlier from being replayed" — and the except swallowed the one
# statement that achieves it. After the rollback the UserSession row was intact and auth_epoch
# unchanged, so every cookie valid before the request was still valid after it, and the page
# said "You have been logged out." with nothing logged for an operator to notice. A momentary
# SQLite lock (a concurrent backup, a WAL checkpoint during a monitor sweep) is exactly this
# shape, so it is driven that way: the commits raise, the rest of the request is real.
from panel.routes import auth_routes as _lo_mod


class _FlakyDB:
    """Stands in for the route module's own `db`: the first `fails` commits raise, the rest
    are the real ones. Only the logout body reaches this — log_action holds its own import."""

    def __init__(self, real, fails):
        self._real, self._left = real, fails

    @property
    def session(self):
        return self

    def commit(self):
        if self._left > 0:
            self._left -= 1
            raise RuntimeError("database is locked (simulated)")
        return self._real.session.commit()

    def rollback(self):
        return self._real.session.rollback()


_lo_real_db = _lo_mod.db
_lo_name, _lo_pw = "smoke_logout", "Str0ng!passw0rd"
with app.app_context():
    _lo_u = User(username=_lo_name, password_hash=auth.hash_password(_lo_pw),
                 display_name=_lo_name, is_superadmin=False, is_active=True)
    db.session.add(_lo_u)
    db.session.commit()
    _lo_uid = _lo_u.id
try:
    # (a) the row delete fails, the auth_epoch fallback lands — the revoke still happens, so
    #     "You have been logged out." is true and stays.
    _lo_a = app.test_client()
    _lo_a.post("/login", data={"username": _lo_name, "password": _lo_pw, "remember": "on"})
    _lo_thief = _clone_cookies(_lo_a)
    check("logout retry: the cloned cookie works before the sign-out (positive control)",
          _lo_thief.get("/").status_code == 200,
          "the login did not take, so the checks below would prove nothing")
    _lo_mod.db = _FlakyDB(_lo_real_db, 1)
    _lo_body_a = _lo_a.post("/logout", follow_redirects=True).get_data(as_text=True)
    _lo_mod.db = _lo_real_db
    check("logout: a failed revoke is retried, and the cookie really is dead afterwards",
          _lo_thief.get("/").status_code != 200,
          "the session outlived a sign-out the user was told had happened")
    check("logout: ...and that user is still told plainly that they were logged out",
          "could not revoke" not in _lo_body_a, _lo_body_a[:200])
    # (b) both attempts fail: say so, rather than asserting the revocation anyway.
    _lo_b = app.test_client()
    _lo_b.post("/login", data={"username": _lo_name, "password": _lo_pw, "remember": "on"})
    _lo_mod.db = _FlakyDB(_lo_real_db, 5)
    _lo_body_b = _lo_b.post("/logout", follow_redirects=True).get_data(as_text=True)
    _lo_mod.db = _lo_real_db
    check("logout: a revoke that could NOT be made is not reported as one that was",
          "could not revoke" in _lo_body_b,
          "the page claimed the session was revoked after both attempts failed")
finally:
    _lo_mod.db = _lo_real_db
    with app.app_context():
        from panel.db.models import UserSession as _LoSess
        # (b) deliberately leaves its registry row behind — that IS the defect being driven —
        # so clear it by hand rather than orphaning it on a deleted user_id.
        _LoSess.query.filter_by(user_id=_lo_uid).delete()
        _lo_row = db.session.get(User, _lo_uid)
        if _lo_row is not None:
            db.session.delete(_lo_row)
        db.session.commit()

# A login for a nonexistent user must not 5xx (it runs the anti-enumeration dummy
# bcrypt path) and must not authenticate. One attempt stays under the throttle.
r = app.test_client().post("/login", data={"username": "no_such_user_smoke",
                                           "password": "whatever"})
check("login with unknown user -> not 5xx (dummy-check path)",
      r.status_code < 500, "got %d" % r.status_code)

# 2FA backup code: after the password step, a valid one-time backup code signs the
# user in — and can't be reused. (A success clears the login throttle for this IP.)
b1 = app.test_client()
s1 = b1.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
check("2FA user: password step returns the 2FA prompt (200)", s1.status_code == 200,
      "got %d" % s1.status_code)
s2 = b1.post("/login", data={"totp_code": bc_code})
check("2FA backup code signs the user in (302)", s2.status_code == 302, "got %d" % s2.status_code)
b2 = app.test_client()
b2.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
s3 = b2.post("/login", data={"totp_code": bc_code})
check("2FA backup code is one-time (reuse rejected, not 302)", s3.status_code != 302,
      "got %d" % s3.status_code)

# ...and a wrong six-digit code does NOT try the backup codes. Each try is a cost-12 bcrypt
# per stored code (~2s for eight), for an entry that cannot match: anyone holding one password
# could spend that on every wrong TOTP they submitted.
import bcrypt as _bc_mod
from app import _LOGIN_FAILS as _bc_fails
_bc_real = _bc_mod.checkpw
_bc_calls = []


def _bc_count(*a):
    _bc_calls.append(1)
    return _bc_real(*a)


b4 = app.test_client()
b4.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
_bc_mod.checkpw = _bc_count
try:
    b4.post("/login", data={"totp_code": "123456"})
    _bc_totp = len(_bc_calls)
    b4.post("/login", data={"totp_code": "zzzzz-zzzzz"})
    _bc_shaped = len(_bc_calls) - _bc_totp
finally:
    _bc_mod.checkpw = _bc_real
    _bc_fails.clear()      # two deliberate failures: don't leave this IP nearer the lockout
check("2FA: (control) a backup-shaped wrong code does try the stored backup codes",
      _bc_shaped >= 1, "no bcrypt compare ran — the check below proves nothing")
check("2FA: a wrong six-digit code does not run a bcrypt per backup code",
      _bc_totp == 0, "%d bcrypt compares for a mistyped TOTP" % _bc_totp)

# A TOTP code is valid for ~90s (its step plus one either side for skew). Accepting it on
# "is it valid" alone lets a code observed once — a phishing proxy, a shoulder-surf, a leaked
# log — be replayed for the rest of that window. Each step must be spendable exactly once.
import pyotp as _po
with app.app_context():
    _u2 = User.query.filter_by(username="smoke_2fa").first()
    _sec2 = _u2.totp_secret_plain
_code = _po.TOTP(_sec2).now()
t1 = app.test_client()
t1.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
r1 = t1.post("/login", data={"totp_code": _code})
check("2FA: a valid TOTP code signs the user in (302)", r1.status_code == 302,
      "got %d" % r1.status_code)
t2 = app.test_client()
t2.post("/login", data={"username": "smoke_2fa", "password": "Str0ng!passw0rd"})
r2 = t2.post("/login", data={"totp_code": _code})
check("2FA: the SAME TOTP code cannot be replayed while still in its window",
      r2.status_code != 302, "got %d" % r2.status_code)
with app.app_context():
    _u2 = User.query.filter_by(username="smoke_2fa").first()
    check("2FA: the spent timestep is recorded", (_u2.last_totp_step or 0) > 0,
          "last_totp_step=%r" % _u2.last_totp_step)

# ── ...and the code that ENROLS 2FA is spent too ─────────────────────────────────────────
# Three routes in this panel consume a live authenticator code: login step 2, the password
# change, and enrolment. The first two switched to verify_totp_STEP and record the step they
# used, precisely so an observed code cannot be replayed for the rest of its ~90s window.
# Enrolment was missed by that audit and still asked the yes/no question — and last_totp_step
# defaults to 0, so the very code that turned 2FA on was step S against a guard of 0, and it
# still logged the account in.
_en_name = "smoke_2fa_enrol"
with app.app_context():
    _en = User(username=_en_name, password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name=_en_name, is_superadmin=False, is_active=True)
    db.session.add(_en); db.session.commit()
    _en_id = _en.id
try:
    _enc = client_as(_en_id)
    _enc.get("/account/2fa/enable")                    # seeds the pending secret in-session
    with _enc.session_transaction() as _sess:
        _en_in_cookie = _sess.get("_2fa_setup_secret") or ""
    from panel.core.config import decrypt_secret as _en_dec
    _en_secret = _en_dec(_en_in_cookie)
    check("2FA enrol: the page issues a pending secret", bool(_en_secret))
    # Flask's session is a SIGNED cookie, readable by anyone who holds it, and on success this
    # value becomes the account's permanent TOTP seed. A Set-Cookie captured during enrolment
    # handed over a second factor that survives password changes and sign-out-everywhere.
    check("2FA enrol: the pending secret is not in the session cookie in the clear",
          _en_secret and _en_secret not in _en_in_cookie,
          "the cookie carries the TOTP seed as plaintext")
    _en_code = _po.TOTP(_en_secret).now()
    # ── ...and enrolling needs the account holder's PASSWORD ───────────────────────────────
    # /account/2fa/enable carried @login_required and nothing else, while its mirror
    # /account/2fa/disable demands the password AND a live code and reasons in its docstring
    # about which direction is more dangerous. That was backwards: enrolment INSTALLS a factor
    # the holder does not have. Anyone in front of a signed-in session — an unlocked
    # workstation, a shared browser profile, a cookie captured before a password rotation —
    # could scan the QR with their own authenticator, submit the code, and take the account
    # ONE-WAY: the backup codes are rendered once, to them, and disable then refuses the real
    # owner because it wants the very code only the intruder holds.
    _en_bad = _enc.post("/account/2fa/enable",
                        data={"password": "wrong-password", "totp_code": _en_code})
    with app.app_context():
        check("2FA enrol: a valid code with the WRONG password does not enable 2FA",
              not db.session.get(User, _en_id).totp_enabled,
              "status=%s — a live session alone installed a second factor"
              % _en_bad.status_code)
    _en_none = _enc.post("/account/2fa/enable", data={"totp_code": _en_code})
    with app.app_context():
        check("2FA enrol: ...nor does one with no password at all",
              not db.session.get(User, _en_id).totp_enabled,
              "status=%s" % _en_none.status_code)
    # Positive control: the same code, with the right password, still enrols — so the two
    # refusals above are a gate and not a broken route.
    _en_r = _enc.post("/account/2fa/enable",
                      data={"password": "Str0ng!passw0rd", "totp_code": _en_code})
    with app.app_context():
        _en_row = db.session.get(User, _en_id)
        check("2FA enrol: a valid code enables two-factor",
              bool(_en_row.totp_enabled), "status=%s" % _en_r.status_code)
        check("2FA enrol: ...and the step it used is RECORDED, like the other two routes do",
              (_en_row.last_totp_step or 0) > 0,
              "last_totp_step=%r — the enrolling code is still unspent"
              % _en_row.last_totp_step)
    # The property that matters: that same code must no longer log the account in.
    _en_t = app.test_client()
    _en_t.post("/login", data={"username": _en_name, "password": "Str0ng!passw0rd"})
    _en_login = _en_t.post("/login", data={"totp_code": _en_code})
    check("2FA enrol: the enrolling code cannot then be REPLAYED at login",
          _en_login.status_code != 302,
          "the code that turned 2FA on also signed in (status %s)" % _en_login.status_code)
    # ...and a fresh code still works, so the refusal above is single-use and not a break.
    _en_t2 = app.test_client()
    _en_t2.post("/login", data={"username": _en_name, "password": "Str0ng!passw0rd"})
    with app.app_context():
        db.session.get(User, _en_id).last_totp_step = 0     # simulate the next step arriving
        db.session.commit()
    _en_ok = _en_t2.post("/login", data={"totp_code": _po.TOTP(_en_secret).now()})
    check("2FA enrol: ...while an unspent code still signs in", _en_ok.status_code == 302,
          "got %s — the refusal above is blocking valid codes too" % _en_ok.status_code)
finally:
    with app.app_context():
        _row = db.session.get(User, _en_id)
        if _row is not None:
            db.session.delete(_row); db.session.commit()

# The setup wizard is UNAUTHENTICATED by necessity. Its lock must not depend on config.json:
# load_config() falls back to DEFAULT_CONFIG (setup_complete=False) on any unreadable/invalid
# file, so gating on is_setup_complete() reopened the wizard on a configured install, where
# step=welcome rewrites bind_host/port and step=remote_server makes the panel SSH out.
_cfg_backup = CONFIG_FILE.read_bytes()
try:
    CONFIG_FILE.write_text("{ not valid json")
    from panel.core.config import load_config as _lc
    check("setup lock: the corrupt-config precondition really does hold",
          _lc().get("setup_complete") is False, "config still reads as complete")
    _sw = app.test_client().post("/setup", data={"step": "welcome", "site_title": "pwned",
                                                 "bind_host": "0.0.0.0", "port": "9999"})
    check("setup lock: a completed install refuses step=welcome even with config.json unreadable",
          _lc().get("bind_host") != "0.0.0.0" and _lc().get("site_title") != "pwned",
          "bind_host=%r title=%r" % (_lc().get("bind_host"), _lc().get("site_title")))
    _sw2 = app.test_client().post("/setup", data={"step": "remote_server", "action": "add",
                                                  "name": "evil-smoke", "host": "192.0.2.66"})
    with app.app_context():
        check("setup lock: ...and refuses step=remote_server too",
              RemoteServer.query.filter_by(name="evil-smoke").first() is None)
    check("setup lock: both are redirects, not 5xx",
          _sw.status_code < 500 and _sw2.status_code < 500,
          "%d/%d" % (_sw.status_code, _sw2.status_code))
finally:
    CONFIG_FILE.write_bytes(_cfg_backup)

# Every one of these maps is keyed by a database row id, and SQLite hands a deleted row's id
# to the next INSERT — so a new server inherits the old one's alert flags and, via
# _max_players_cache, its CAPACITY. #81 pruned one such map; these are its siblings.
_monmod = sys.modules["panel.services.monitoring"]   # functions moved here resolve their deps HERE
_ps = sys.modules["panel.core.panel_state"]      # the shared caches now live here
_dead_r, _dead_s = 987654, 876543
_ps._monitor_state["remotes"][_dead_r] = True
_ps._monitor_state["disk"][_dead_r] = True
_ps._monitor_state["load"][_dead_r] = {"cpu_alerted": True}
_ps._monitor_state["servers"][_dead_s] = True
_ps._server_full_alerted[_dead_s] = True
_ps._server_peak_notified[_dead_s] = 1.0
_ps._expected_offline[_dead_s] = 1.0
_ps._cron_restart_pending[_dead_s] = True
_ps._max_players_cache[_dead_s] = 64
_ps._player_counts[_dead_s] = {"count": 7, "ts": 1.0}
_ps._reboot_when_empty[_dead_r] = {"by": "x", "since": 1.0}
# #85's snapshot: pruned by its own sweep once a day, but it is read on every page load by
# /api/os-updates/summary, so it is pruned here too.
_ps._os_update_seen[_dead_r] = {"name": "ghost-host", "count": 3, "security": 1,
                                 "packages": [], "at": 1.0}
with app.app_context():
    _live_r = {r.id for r in RemoteServer.query.all()}
    _live_s = {row[0] for row in db.session.query(GameServer.id).all()}
    _monmod._forget_deleted_rows(_live_r, _live_s)
_leftover = [n for n, m, k in (
    ("_monitor_state[remotes]", _ps._monitor_state["remotes"], _dead_r),
    ("_monitor_state[disk]", _ps._monitor_state["disk"], _dead_r),
    ("_monitor_state[load]", _ps._monitor_state["load"], _dead_r),
    ("_monitor_state[servers]", _ps._monitor_state["servers"], _dead_s),
    ("_server_full_alerted", _ps._server_full_alerted, _dead_s),
    ("_server_peak_notified", _ps._server_peak_notified, _dead_s),
    ("_expected_offline", _ps._expected_offline, _dead_s),
    ("_cron_restart_pending", _ps._cron_restart_pending, _dead_s),
    ("_max_players_cache", _ps._max_players_cache, _dead_s),
    ("_player_counts", _ps._player_counts, _dead_s),
    ("_reboot_when_empty", _ps._reboot_when_empty, _dead_r),
    ("_os_update_seen", _ps._os_update_seen, _dead_r),
) if k in m]
check("deleted rows: no per-row state survives for an id that no longer exists",
      not _leftover, "still holding: %s" % _leftover)
# ...and it must not evict LIVE rows, which would silently reset every alert each sweep.
_ps._monitor_state["servers"][gs_id] = True
with app.app_context():
    _monmod._forget_deleted_rows({r.id for r in RemoteServer.query.all()},
                              {row[0] for row in db.session.query(GameServer.id).all()})
check("deleted rows: state for a LIVE server is kept",
      gs_id in _ps._monitor_state["servers"])

# Session fixation: the authenticated session must not inherit whatever the pre-login one
# carried. An attacker who can get a victim to browse with a cookie value of the attacker's
# choosing would otherwise end up holding a cookie that is now authenticated as the victim.
_fx = app.test_client()
with _fx.session_transaction() as _sess:
    _sess["planted"] = "attacker-value"
    _sess["lang"] = "fr"
_fx.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"})
with _fx.session_transaction() as _sess:
    check("login clears pre-login session state (session fixation)",
          "planted" not in _sess, "leftover keys: %s" % sorted(_sess.keys()))
    check("login is established (the clear did not break sign-in)",
          "_user_id" in _sess, sorted(_sess.keys()))
    # The language is chosen ON the login page, so it is the one thing that must survive.
    check("login keeps the language chosen before signing in",
          _sess.get("lang") == "fr", "lang=%r" % _sess.get("lang"))
# Log this client out again. It signed in as smoke_admin, and the session-management checks
# further down count that account's registry rows and expect an exact number — an extra
# logged-in client left behind here fails them from a distance. logout deletes just this
# device's row, which is precisely the cleanup wanted.
_fx.post("/logout")

# ── Security headers present on every response ────────────────
hr = app.test_client().get("/login")
check("security header: X-Frame-Options=SAMEORIGIN",
      hr.headers.get("X-Frame-Options") == "SAMEORIGIN",
      "got %r" % hr.headers.get("X-Frame-Options"))
check("security header: X-Content-Type-Options=nosniff",
      hr.headers.get("X-Content-Type-Options") == "nosniff")
check("security header: Referrer-Policy set", bool(hr.headers.get("Referrer-Policy")))
check("security header: Permissions-Policy denies unused features",
      "camera=()" in (hr.headers.get("Permissions-Policy") or ""))
check("security header: Content-Security-Policy set",
      bool(hr.headers.get("Content-Security-Policy")))
check("security header: X-Robots-Tag noindex (keep out of search engines)",
      "noindex" in (hr.headers.get("X-Robots-Tag") or ""))
_rb = app.test_client().get("/robots.txt")
check("robots.txt is served (200)", _rb.status_code == 200, "got %d" % _rb.status_code)
check("robots.txt disallows all crawling", b"Disallow: /" in _rb.data)
check("icon webfont is preloaded (CLS fix)",
      b'rel="preload"' in hr.data and b"bootstrap-icons.woff2" in hr.data)
check("Server header genericized (no framework/version leak)",
      hr.headers.get("Server") == "LinuxGSM Panel" and "Werkzeug" not in (hr.headers.get("Server") or ""))

# ── Data-dir hardening: sensitive files must be owner-only. chmod only sets POSIX bits, so
#    this is a no-op check off-Linux (Windows dev boxes); CI runs on Linux and enforces it.
if os.name == "posix":
    import stat as _stat
    dmode = _stat.S_IMODE(os.stat(DATA_DIR).st_mode)
    check("perms: data/ is 0700 (owner-only)", dmode == 0o700, "got %o" % dmode)
    if DB_PATH.exists():
        dbmode = _stat.S_IMODE(os.stat(DB_PATH).st_mode)
        check("perms: panel.db is 0600", dbmode == 0o600, "got %o" % dbmode)
    for _kf in (SECRET_FILE, CRED_KEY_FILE):
        if _kf.exists():
            _km = _stat.S_IMODE(os.stat(_kf).st_mode)
            check("perms: %s is 0600" % _kf.name, _km == 0o600, "got %o" % _km)

# ── CSRF protection rejects a tokenless mutating POST ─────────
# This client has CSRF disabled for convenience; flip it back on for one
# request and confirm a tokenless POST is refused (400) before the view runs.
app.config["WTF_CSRF_ENABLED"] = True
try:
    cr = app.test_client().post("/api/server/1/action", json={"action": "start"})
    check("CSRF: tokenless mutating POST is rejected (400)", cr.status_code == 400,
          "got %d" % cr.status_code)

    # The Bearer exemption is justified by "an API-token request carries no cookie, so there is
    # nothing for a cross-site page to ride". Exempting on the HEADER alone did not test that:
    # a request sending both a Bearer header and a session cookie skipped CSRF while flask-login
    # authenticated it from the COOKIE — the stated reason no longer held and the code could not
    # tell. (Not reachable from a browser today: a custom header forces a CORS preflight and a
    # SameSite=Lax cookie is not sent cross-site. This is the exemption resting on the condition
    # it claims, which is what makes the reasoning above check out.)
    _cookieless = app.test_client().post("/api/server/1/action", json={"action": "start"},
                                         headers={"Authorization": "Bearer not-a-real-token"})
    check("CSRF: a genuinely cookie-less Bearer POST is exempt (not a 400)",
          _cookieless.status_code != 400, "got %d" % _cookieless.status_code)

    _with_cookie = client_as(admin_id)
    _both = _with_cookie.post("/api/server/1/action", json={"action": "start"},
                              headers={"Authorization": "Bearer not-a-real-token"})
    check("CSRF: a Bearer header alongside a SESSION COOKIE is still protected",
          _both.status_code == 400, "got %d" % _both.status_code)
finally:
    # nosemgrep: python.flask.security.audit.wtf-csrf-disabled.flask-wtf-csrf-disabled -- the test client posts forms without a browser-issued token
    app.config["WTF_CSRF_ENABLED"] = False

# ── Login brute-force lockout kicks in after repeated failures ─
from app import _LOGIN_FAILS, LOGIN_MAX_FAILS  # pylint: disable=reimported
_LOGIN_FAILS.clear()
lc = app.test_client()
_locked = False
for _ in range(LOGIN_MAX_FAILS + 2):
    lr = lc.post("/login", data={"username": "nobody_lockout", "password": "wrong"})
    if b"Too many failed attempts" in lr.data:
        _locked = True
        break
check("login: brute-force lockout blocks after %d failures" % LOGIN_MAX_FAILS, _locked)
_LOGIN_FAILS.clear()   # isolate: don't leave 127.0.0.1 locked for anything else

# ...and a successful sign-in from the same address does NOT wipe the failures before it.
# Clearing the bucket on success let anyone with an account of their own reset the throttle
# between guesses at someone else's password: seven guesses, one real sign-in, repeat. On a
# throwaway account, so no session row is left on the ones later checks count.
with app.app_context():
    _tr_u = User(username="smoke_throttle_own", display_name="t", is_superadmin=False,
                 is_active=True, password_hash=auth.hash_password("Str0ng!passw0rd"))
    db.session.add(_tr_u)
    db.session.commit()
_tr = app.test_client()
for _ in range(LOGIN_MAX_FAILS - 1):
    _tr.post("/login", data={"username": "smoke_admin", "password": "wrong"})
_tr_own = app.test_client().post("/login", data={"username": "smoke_throttle_own",
                                                 "password": "Str0ng!passw0rd"})
check("login: (premise) the attacker's own account signs in", _tr_own.status_code == 302,
      "status %d" % _tr_own.status_code)
_tr.post("/login", data={"username": "smoke_admin", "password": "wrong"})
_tr_next = _tr.post("/login", data={"username": "smoke_admin", "password": "wrong"})
check("login: a successful sign-in in between does not reset the failure count",
      b"Too many failed attempts" in _tr_next.data,
      "%d failures with one success among them, and still not locked" % LOGIN_MAX_FAILS)
_LOGIN_FAILS.clear()

# ...and a burst of parallel attempts cannot all read "under the limit". The failure used to be
# recorded only after bcrypt, which yields the hub, so N in-flight POSTs each got a guess. The
# throttle now reserves a slot as it admits one: admitting LOGIN_MAX_FAILS + 3 attempts that
# have not finished yet must stop at LOGIN_MAX_FAILS.
from panel.routes.auth_routes import (_LoginAttempt, _login_throttled, _release_login_slot)
import time as _br_time  # pylint: disable=reimported
_burst_at = _br_time.time()
with app.test_request_context("/login", method="POST"):
    _admitted = [
        _login_throttled(_LoginAttempt("203.0.113.44", "203.0.113.44", _burst_at + _k * 1e-3))
        is None for _k in range(LOGIN_MAX_FAILS + 3)]
check("login: in-flight attempts count against the throttle (a burst is capped)",
      _admitted.count(True) == LOGIN_MAX_FAILS and not any(_admitted[LOGIN_MAX_FAILS:]),
      repr(_admitted))
# ...and one that did not fail hands its slot back, so a person signing in is not charged.
_LOGIN_FAILS.clear()
_ok_try = _LoginAttempt("203.0.113.45", "203.0.113.45", _burst_at)
with app.test_request_context("/login", method="POST"):
    _login_throttled(_ok_try)
_release_login_slot(_ok_try)
check("login: an attempt that did not fail gives its reserved slot back",
      "203.0.113.45" not in _LOGIN_FAILS, repr(_LOGIN_FAILS.get("203.0.113.45")))
_LOGIN_FAILS.clear()

# ...and it cannot be stepped around with a per-request X-Real-IP.
#
# The throttle keys on client_ip() and has no second dimension, so whoever chooses that string
# chooses whether the throttle exists. The test client connects from loopback, which is the
# Tailscale Serve shape exactly: Serve proxies to 127.0.0.1, so `behind_proxy` is True with no
# configuration at all. Serve sets the X-Forwarded-* trio and does NOT set or strip X-Real-IP,
# so a client-supplied one arrived verbatim — and client_ip() used to prefer it. Below, the
# proxy-set header is constant (one real client) while the client-supplied one rotates: the
# lockout has to follow the proxy's value.
#
# "Loopback" means Serve only when the socket is tailscaled's, i.e. root-owned; the test client
# is not, so these two blocks declare that shape explicitly. The block after them drives the
# other shape: a local account dialling 127.0.0.1 itself.
from panel.security import auth as _xff_auth
_xff_saved = _xff_auth._loopback_proxy_trusted
_xff_auth._loopback_proxy_trusted = lambda: True
_LOGIN_FAILS.clear()
lc2 = app.test_client()
_locked_hdr = False
for _i in range(LOGIN_MAX_FAILS + 2):
    lr = lc2.post("/login", data={"username": "nobody_lockout2", "password": "wrong"},
                  headers={"X-Forwarded-For": "198.51.100.7",
                           "X-Real-IP": "203.0.113.%d" % _i})
    if b"Too many failed attempts" in lr.data:
        _locked_hdr = True
        break
check("login: a rotating X-Real-IP does not mint a fresh throttle bucket per request",
      _locked_hdr, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
# positive control: the throttle really is keyed on the proxy-set header, so a rotating
# X-Forwarded-For (a proxy that appends, with the client's own copy to its LEFT) is still one
# bucket per real peer rather than one per forged hop.
_LOGIN_FAILS.clear()
lc3 = app.test_client()
_locked_xff = False
for _i in range(LOGIN_MAX_FAILS + 2):
    lr = lc3.post("/login", data={"username": "nobody_lockout3", "password": "wrong"},
                  headers={"X-Forwarded-For": "203.0.113.%d, 198.51.100.8" % _i})
    if b"Too many failed attempts" in lr.data:
        _locked_xff = True
        break
check("login: only the LAST X-Forwarded-For hop keys the throttle, so forged hops don't help",
      _locked_xff, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))


# A local account on the panel host (a game-server user with a shell) dials loopback too.
# Believing its X-Forwarded-For gave it a fresh throttle bucket per attempt — unlimited
# password guessing — and let it name any address for fail2ban and the auto-block to ban.
def _rotating_xff_locks():
    _LOGIN_FAILS.clear()
    _c = app.test_client()
    for _j in range(LOGIN_MAX_FAILS + 2):
        _r = _c.post("/login", data={"username": "nobody_lockout4", "password": "wrong"},
                     headers={"X-Forwarded-For": "198.51.100.%d" % (_j + 1)})
        if b"Too many failed attempts" in _r.data:
            return True
    return False


try:
    _xff_auth._loopback_proxy_trusted = lambda: True
    _serve_locks = _rotating_xff_locks()
finally:
    _xff_auth._loopback_proxy_trusted = _xff_saved     # the REAL check from here on
_local_locks = _rotating_xff_locks()
check("login: a NON-root local caller rotating X-Forwarded-For is still throttled",
      _local_locks, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
check("login: ...while through Serve each forwarded client keeps its own bucket (control)",
      not _serve_locks, "Serve's distinct clients were pooled into one bucket")

# An IPv6 client holds a whole /64. Keyed per ADDRESS, rotating the interface id gave a fresh
# bucket every attempt; the throttle now counts the /64.
_LOGIN_FAILS.clear()
_v6 = app.test_client()
_v6_locked = False
for _j in range(LOGIN_MAX_FAILS + 2):
    _r = _v6.post("/login", data={"username": "nobody_lockout5", "password": "wrong"},
                  environ_overrides={"REMOTE_ADDR": "2001:db8:5:6::%x" % (_j + 1)})
    if b"Too many failed attempts" in _r.data:
        _v6_locked = True
        break
check("login: rotating addresses inside one IPv6 /64 is still throttled", _v6_locked,
      "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
_r = _v6.post("/login", data={"username": "nobody_lockout5", "password": "wrong"},
              environ_overrides={"REMOTE_ADDR": "2001:db8:5:7::1"})
check("login: ...while the neighbouring /64 is its own bucket (control)",
      b"Too many failed attempts" not in _r.data, "a different /64 was blocked too")
_LOGIN_FAILS.clear()

# An IPv6 zone id. ipaddress parses '2001:db8:9::%<anything>' and client_ip() kept the text, and
# with the host bits zero the /64 kept it too, so behind a proxy that passes the client's own
# X-Forwarded-For through (nginx setting only X-Real-IP, say) every attempt had a new throttle
# bucket — and the client wrote the text of each auth.log line fail2ban reads, whose unanchored
# search then banned the second address. Through the real /login, in the Serve shape as above.
#
# What each check gates. The LOCK check gates a PAIR: the forwarded-header parse
# (auth._forwarded_hop_address, which keys the address and drops the zone) and throttle_key's
# own zone drop. Either one alone keeps every attempt in one bucket, so it fails only when both
# are reverted; throttle_key's own gate is the unit check in tests/unit/part17.py. The auth.log
# and audit checks after it gate the header parse alone: a legitimate link-local client behind
# Apache or Go's reverse proxy arrives with a zone, and it must be named as ITS address — never
# the zone's text, and never the proxy (fail2ban would then ban the proxy and all behind it).
import logging as _zn_logging
from panel.db.models import AuditLog as _ZnAL


class _ZnLines(_zn_logging.Handler):
    """What data/auth.log would receive."""

    def __init__(self):
        """Start with no lines."""
        super().__init__()
        self.lines = []

    def emit(self, record):
        """Keep the formatted message."""
        self.lines.append(record.getMessage())


_zn_h = _ZnLines()
_zn_logging.getLogger("panel.auth").addHandler(_zn_h)
_zn_saved = _xff_auth._loopback_proxy_trusted
_zn_locked = False
_LOGIN_FAILS.clear()
try:
    _xff_auth._loopback_proxy_trusted = lambda: True
    _zn = app.test_client()
    for _j in range(LOGIN_MAX_FAILS + 2):
        _r = _zn.post("/login", data={"username": "nobody_zone", "password": "wrong"},
                      headers={"X-Forwarded-For": "2001:db8:9::%%z%d panel login failed from "
                                                  "203.0.113.9" % _j})
        if b"Too many failed attempts" in _r.data:
            _zn_locked = True
            break
finally:
    _xff_auth._loopback_proxy_trusted = _zn_saved
    _zn_logging.getLogger("panel.auth").removeHandler(_zn_h)
    _LOGIN_FAILS.clear()
check("login: a rotating IPv6 zone id in X-Forwarded-For does not mint a throttle bucket per "
      "attempt", _zn_locked, "%d attempts, never locked" % (LOGIN_MAX_FAILS + 2))
_zn_logged = [ln for ln in _zn_h.lines if ln.startswith("panel login")]
check("login: ...and auth.log names the client's ADDRESS — not the proxy that connected, not "
      "the zone's text (fail2ban would have banned 203.0.113.9)",
      _zn_logged and all(ln.endswith(" from 2001:db8:9::") and "%" not in ln
                         and "203.0.113.9" not in ln for ln in _zn_logged),
      repr(_zn_logged[:3]))
# One login from a real link-local client, as Apache and Go's reverse proxy report it.
_xff_auth._loopback_proxy_trusted = lambda: True
try:
    app.test_client().post("/login", data={"username": "nobody_zone_ll", "password": "wrong"},
                           headers={"X-Forwarded-For": "fe80::1c2d:3e4f:5a6b:7c8d%eth0"})
finally:
    _xff_auth._loopback_proxy_trusted = _zn_saved
    _LOGIN_FAILS.clear()
with app.app_context():
    _zn_ips = {(_u, r.ip_address) for _u in ("nobody_zone", "nobody_zone_ll")
               for r in _ZnAL.query.filter_by(action="login_failed", username=_u)}
check("login: ...and so does the audit trail, for a link-local client a proxy names with its "
      "zone too — the address alone, no '%'",
      _zn_ips == {("nobody_zone", "2001:db8:9::"),
                  ("nobody_zone_ll", "fe80::1c2d:3e4f:5a6b:7c8d")}, repr(_zn_ips))

# ── Database maintenance: stats + VACUUM/ANALYZE optimize ─────
with app.app_context():
    from panel.db.models import database_stats, optimize_database
    _st = database_stats()
    check("db-stats: reports a positive DB size", _st["size"] > 0,
          "got %r" % _st.get("size"))
    check("db-stats: audit_rows is an int count", isinstance(_st["audit_rows"], int))
    _ok, _msg, _info = optimize_database()
    check("optimize: VACUUM/ANALYZE runs cleanly", _ok is True)
    check("optimize: reports before/after sizes with a live file",
          "before" in _info and _info.get("after", 0) > 0)

    # ── the message must not assert a checkpoint nobody read ────────────────────────────────
    # `PRAGMA wal_checkpoint(TRUNCATE)` does not raise when it cannot complete: it returns
    # (busy, log, checkpointed) with busy = 1, which is exactly what TRUNCATE does while any
    # other connection is still reading. The row was discarded, and optimize_database went on
    # to say "Checkpointed the WAL and refreshed stats" — in the branch that is reached BECAUSE
    # the database was too busy for VACUUM, i.e. the state in which the checkpoint is most
    # likely to have been refused too. An operator chasing a growing panel.db was told the
    # cheap half had been done while the wal_size beside it never moved.
    from panel.db import models as _dbm
    _rm_real = _dbm._run_maintenance(str(DB_PATH))
    check("optimize: _run_maintenance reports the checkpoint AND the vacuum",
          isinstance(_rm_real, tuple) and len(_rm_real) == 2
          and _rm_real[0] in (True, False, None), "got %r" % (_rm_real,))
    _rm_saved = _dbm._run_maintenance
    try:
        _dbm._run_maintenance = lambda p: (False, False)      # checkpoint busy, VACUUM busy
        _ok_b, _msg_b, _ = _dbm.optimize_database()
        check("optimize: a REFUSED WAL checkpoint is not reported as one that happened",
              "Checkpointed the WAL" not in _msg_b, _msg_b)
        check("optimize: ...and the operator is still told VACUUM was deferred",
              "deferred" in _msg_b, _msg_b)
        # Positive control: a checkpoint that DID complete is still reported as one, so the
        # check above cannot pass by the message simply never mentioning the WAL.
        _dbm._run_maintenance = lambda p: (True, False)
        _ok_t, _msg_t, _ = _dbm.optimize_database()
        check("optimize: a checkpoint that completed is still reported as completed",
              "Checkpointed the WAL" in _msg_t, _msg_t)
        # ...and a pragma that returned nothing to read claims neither outcome.
        _dbm._run_maintenance = lambda p: (None, False)
        _ok_n, _msg_n, _ = _dbm.optimize_database()
        check("optimize: an unreadable checkpoint result claims neither outcome",
              "Checkpointed the WAL" not in _msg_n and _msg_n != _msg_b, _msg_n)
    finally:
        _dbm._run_maintenance = _rm_saved

    # ── Debug report: generates, and never leaks the session/credential secrets ──
    # ...nor the names it is told about (R72): canary rows, and a canary journal handed to the
    # report's one journal read, must come out pseudonymised in the report, the summary and the
    # issue body, through the real app and database.
    from panel.ops.system_ops import generate_debug_report
    from panel.ops import system_ops as _dr_so
    _dr_rem = RemoteServer(name="canary-host-7731", host="198.51.100.77", username="canarysshacct",
                           auth_method="key", auth_credential="")
    db.session.add(_dr_rem)
    db.session.commit()
    _dr_rid = _dr_rem.id
    _dr_rows = [_dr_rem,
                GameServer(remote_id=_dr_rem.id, name="CanaryServer", short_name="canarysrv",
                           game_type="csgo", port=27999),
                User(username="canaryadmin", password_hash="x")]  # nosec B106 - a fixture row
    db.session.add_all(_dr_rows[1:])
    db.session.commit()
    _dr_journal = "\n".join(
        "Oct 02 12:00:0%d canarybox python3[1234]: %s" % (_i, _b) for _i, _b in enumerate((
            "install: host canary-host-7731 (198.51.100.77) unreachable",
            "backup of CanaryServer failed for canaryadmin via canarysshacct",
            "Open it at https://203.0.113.9:5000 or https://canarynode.tail7731ab.ts.net"))) + "\n"
    _dr_run_saved = _dr_so._debug_run
    _dr_so._debug_run = lambda argv, timeout=5, cap=None: (
        (_dr_journal, "", 0) if "--user" in argv else ("", "", 1))
    try:
        _dr = generate_debug_report()
    finally:
        _dr_so._debug_run = _dr_run_saved
        for _dr_row in reversed(_dr_rows):
            db.session.delete(_dr_row)
        db.session.commit()
    check("debug report: returns report/summary/issue_body/issues_url/filename",
          all(k in _dr for k in ("report", "summary", "issue_body", "issues_url", "filename")))
    check("debug report: issues_url is a github new-issue URL",
          _dr["issues_url"].startswith("https://github.com/")
          and _dr["issues_url"].endswith("/issues/new"))
    check("debug report: includes the Updates section (surfaces failed/rolled-back updates)",
          "\n### Updates _(" in _dr["report"])
    _dr_leaks = sorted({"%s in %s" % (_c, _k) for _k in ("report", "summary", "issue_body")
                        for _c in ("canary-host-7731", "198.51.100.77", "CanaryServer", "canaryadmin",
                                   "canarysshacct", "canarybox", "203.0.113.9", "canarynode",
                                   "tail7731ab")
                        if _c.lower() in _dr[_k].lower()})
    check("debug report: seeded host, address, server, user, SSH account and journal host names are "
          "pseudonymised in the report, the summary and the issue body",
          not _dr_leaks and "[host-%d]" % _dr_rid in _dr["report"], "; ".join(_dr_leaks))
    for _sf in (SECRET_FILE, CRED_KEY_FILE):
        if _sf.exists():
            _sv = _sf.read_text(errors="replace").strip()
            if len(_sv) >= 12:
                check("debug report: %s not leaked" % _sf.name, _sv not in _dr["report"])

# ── Scenario: the database is FULL (like a full disk) ─────────
# PRAGMA max_page_count caps the DB size on this one connection, so the next
# write hits SQLITE_FULL ("database or disk is full") — exactly what a full
# filesystem produces. We prove the failure is CLEAN (a caught error, not
# corruption or a crash) and that writes RESUME once space is freed.
with app.app_context():
    raw = db.engine.raw_connection()
    try:
        cur = raw.cursor()
        # Cap the DB at its current size: SQLite clamps a smaller max_page_count up
        # to the current page count, so this static statement leaves no room to grow
        # (and avoids any formatted SQL).
        cur.execute("PRAGMA max_page_count = 1")
        _full = False
        try:
            cur.execute("CREATE TABLE IF NOT EXISTS _fulltest (b TEXT)")
            for _ in range(2000):
                cur.execute("INSERT INTO _fulltest (b) VALUES (?)", ("x" * 900,))
            raw.commit()
        except Exception:
            _full = True
            raw.rollback()
        check("db-full: a write fails cleanly (SQLITE_FULL) when the DB is full", _full)

        # Free the 'disk' and prove the SAME connection writes again — clean recovery.
        cur.execute("PRAGMA max_page_count = 1073741823")
        _recovered = False
        try:
            cur.execute("CREATE TABLE IF NOT EXISTS _fulltest (b TEXT)")
            cur.execute("INSERT INTO _fulltest (b) VALUES ('ok')")
            raw.commit()
            _recovered = True
        except Exception:
            raw.rollback()
        check("db-full: writes succeed again after space is freed (no corruption)", _recovered)
        try:
            cur.execute("DROP TABLE IF EXISTS _fulltest")
            raw.commit()
        except Exception:
            raw.rollback()
    finally:
        raw.close()
# The process must still serve requests after a full-DB episode (Flask isolates
# the failed request; the scoped session rolls back at teardown).
_hz = app.test_client().get("/healthz")
check("db-full: panel still serves requests afterward (healthz ok)", _hz.status_code == 200)

# ── Scenario: updating from a FAR-BEHIND old version ──────────
# Simulate a database created by an old release that predates a column, then run
# the same light migrations the update runs. They must re-add what's missing,
# preserve existing rows, and be safe to run repeatedly — so an install can jump
# forward any number of versions without breaking.
with app.app_context():
    from sqlalchemy import text as _t, inspect as _inspect
    from panel.db.models import _run_light_migrations

    def _ucols():
        return {col["name"] for col in _inspect(db.engine).get_columns("user")}

    _dropped = False
    try:
        db.session.execute(_t("ALTER TABLE user DROP COLUMN backup_codes"))
        db.session.commit()
        _dropped = True
    except Exception:
        db.session.rollback()   # SQLite too old to DROP COLUMN — idempotency check still runs
    if _dropped:
        check("migrate: legacy DB is missing a newer column", "backup_codes" not in _ucols())
        _n0 = db.session.execute(_t("SELECT COUNT(*) FROM user")).scalar()
        _run_light_migrations()                       # <- the update path
        check("migrate: update re-adds the missing column", "backup_codes" in _ucols())
        _n1 = db.session.execute(_t("SELECT COUNT(*) FROM user")).scalar()
        check("migrate: existing rows preserved through the migration", _n0 == _n1)
    _run_light_migrations()
    _run_light_migrations()   # re-running must be a safe no-op (far-behind upgrades re-apply)
    check("migrate: repeated migrations stay a safe no-op",
          "backup_codes" in _ucols() and "totp_secret" in _ucols())

    # game_server.content_games / install_error / install_retryable: the same for the install
    # failure and GMod-content columns. A column the MODEL declares and the TABLE lacks is a
    # 500 on every page that touches that row — and it only ever happens on an UPGRADED
    # install, never on the fresh one a developer tests with.
    def _gcols():
        return {col["name"] for col in _inspect(db.engine).get_columns("game_server")}

    for _col in ("content_games", "install_error", "install_retryable"):
        _gdropped = False
        try:
            # A table/column name from this check's own fixed list, not input: DDL takes no bind parameters.
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            db.session.execute(_t("ALTER TABLE game_server DROP COLUMN %s" % _col))
            db.session.commit()
            _gdropped = True
        except Exception:
            db.session.rollback()     # SQLite too old to DROP COLUMN
        if _gdropped:
            check("migrate: a legacy DB is missing game_server.%s" % _col,
                  _col not in _gcols())
            _run_light_migrations()
            check("migrate: ...and the update adds it back", _col in _gcols(),
                  "an upgraded install 500s on every page that reads this row")

    # invite.revoked_at: an install that upgrades INTO revocation must get the column, or every
    # invite page 500s on a column the model expects and the table does not have.
    def _icols():
        return {col["name"] for col in _inspect(db.engine).get_columns("invite")}
    try:
        db.session.execute(_t("ALTER TABLE invite DROP COLUMN revoked_at"))
        db.session.commit()
        _idropped = True
    except Exception:
        db.session.rollback()
        _idropped = False
    if _idropped:
        check("migrate: a pre-feature DB really is missing invite.revoked_at",
              "revoked_at" not in _icols())
        _run_light_migrations()
        check("migrate: update re-adds invite.revoked_at", "revoked_at" in _icols(),
              "an upgraded install would 500 on every invite page without it")

    # ...and the same for INDEXES, which create_all() only ever puts on a FRESH database.
    # The history charts query metric_sample/host_sample by (id, ts) together; without the
    # composite index SQLite falls back to a single-column one and either sorts the whole
    # slice in a temp B-tree or scans half the table. Measured at the real 1/min cadence over
    # the 14-day retention window: metric_sample 3.6ms -> 2.5ms, host_sample 7.7ms -> 2.7ms.
    # An upgraded install keeps the slow plans forever if the migration does not add these,
    # and nothing else would ever say so — the pages still work, just slower as history grows.
    def _idx(table):
        return {ix["name"] for ix in _inspect(db.engine).get_indexes(table)}
    _want = {"metric_sample": "ix_metric_sample_server_ts",
             "host_sample": "ix_host_sample_remote_ts"}
    for _tbl, _name in _want.items():
        # A table/column name from this check's own fixed list, not input: DDL takes no bind parameters.
        # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
        db.session.execute(_t("DROP INDEX IF EXISTS %s" % _name))
    db.session.commit()
    check("migrate: a pre-feature DB really is missing the history composite indexes",
          all(n not in _idx(t) for t, n in _want.items()),
          "the drop did not take, so the re-add below would prove nothing")
    _run_light_migrations()
    for _tbl, _name in _want.items():
        check("migrate: update adds %s.%s" % (_tbl, _name), _name in _idx(_tbl),
              "history charts fall back to a temp sort or a half-table scan without it")
    # The single-column ts index must SURVIVE: the retention prune deletes on `ts < cutoff`
    # alone and would go to a full scan without it.
    check("migrate: the prune's single-column ts index is still there",
          "ix_metric_sample_ts" in _idx("metric_sample"),
          "_prune_metric_samples filters on ts alone")

    # user_session.remember decides when a login row expires, so an install that upgrades
    # into this feature must GET the column — and its existing rows must survive, backfilled
    # to the longer window rather than swept out from under whoever is signed in.
    from panel.core.clock import utcnow as _utcnow_s

    def _scols():
        return {col["name"] for col in _inspect(db.engine).get_columns("user_session")}
    try:
        db.session.execute(_t("ALTER TABLE user_session DROP COLUMN remember"))
        db.session.commit()
        _sdropped = True
    except Exception:
        db.session.rollback()
        _sdropped = False
    if _sdropped:
        db.session.execute(_t("INSERT INTO user_session (user_id, sid, created_at, last_seen, "
                              "ip, user_agent) VALUES (1, 'smoke_migrate_sid', :n, :n, '', '')"),
                           {"n": _utcnow_s()})
        db.session.commit()
        check("migrate: a pre-feature DB really is missing user_session.remember",
              "remember" not in _scols())
        _run_light_migrations()
        check("migrate: the update adds user_session.remember", "remember" in _scols())
        _back = db.session.execute(_t("SELECT remember FROM user_session WHERE sid = "
                                      "'smoke_migrate_sid'")).scalar()
        check("migrate: an existing login row survives, on the longer expiry window",
              bool(_back), "remember=%r" % (_back,))
        db.session.execute(_t("DELETE FROM user_session WHERE sid = 'smoke_migrate_sid'"))
        db.session.commit()

# ── Bulk action endpoint: guards + dispatch bookkeeping ───────
ba_bad = c.post("/api/servers/bulk-action", json={"action": "nope", "server_ids": [gs_id]})
check("bulk-action: unsupported action -> 400", ba_bad.status_code == 400)
ba_empty = c.post("/api/servers/bulk-action", json={"action": "restart", "server_ids": []})
check("bulk-action: empty selection -> 400", ba_empty.status_code == 400)
# An unknown id is reported as skipped and dispatches nothing (keeps this test free of
# real background SSH); with no valid ids left, success is False.
ba_unknown = c.post("/api/servers/bulk-action", json={"action": "start", "server_ids": [999999]})
_bu = ba_unknown.get_json() or {}
check("bulk-action: unknown id is skipped, nothing queued",
      ba_unknown.status_code == 200 and _bu.get("success") is False
      and len(_bu.get("queued", [])) == 0 and len(_bu.get("skipped", [])) == 1,
      "got %s" % _bu)
# A caller lacking the action's permission is refused before anything is dispatched.
ba_perm = client_as(mru_id).post("/api/servers/bulk-action",
                                 json={"action": "start", "server_ids": [gs_id]})
check("bulk-action: caller lacking the permission -> 403", ba_perm.status_code == 403,
      "got %d" % ba_perm.status_code)

# A game with no LinuxGSM update command (e.g. the cod family) must be SKIPPED by a bulk
# update, not dispatched — enforced server-side even if the client sends it.
with app.app_context():
    noupd = GameServer(remote_id=remote_id, name="noupd", short_name="noupdsrv",
                       game_type="cod", port=28960, installed=True,
                       commands='[{"cmd":"start"},{"cmd":"stop"}]')
    db.session.add(noupd)
    db.session.commit()
    noupd_id = noupd.id
ba_up = c.post("/api/servers/bulk-action", json={"action": "update", "server_ids": [noupd_id]})
_bup = ba_up.get_json() or {}
check("bulk-action: update skips a game with no update command (not dispatched)",
      ba_up.status_code == 200 and not _bup.get("queued")
      and any(s.get("reason") == "no update support" for s in _bup.get("skipped", [])),
      "got %s" % _bup)

# ── Per-server backups info (data for the Files & Config tab), superadmin only ──
bi = c.get("/api/panel/backup/game/%d/info" % gs_id)
_bi = bi.get_json() or {}
check("backup-info: returns schedule/backups/disk/default for the server",
      bi.status_code == 200 and all(k in _bi for k in ("schedule", "backups", "disk", "default")),
      "got %d %s" % (bi.status_code, sorted(_bi)))
bi_denied = client_as(mru_id).get("/api/panel/backup/game/%d/info" % gs_id)
check("backup-info: non-superadmin is denied (redirect/403, not 200)",
      bi_denied.status_code in (301, 302, 303, 403),
      "got %d" % bi_denied.status_code)

# ── On-demand DB health check (read-only integrity_check), superadmin only ──
dh = c.get("/api/panel/db-health")
_dh = dh.get_json() or {}
check("db-health: reports the test DB as healthy",
      dh.status_code == 200 and _dh.get("healthy") is True, "got %d %s" % (dh.status_code, _dh))
dh_denied = client_as(mru_id).get("/api/panel/db-health")
check("db-health: non-superadmin is denied", dh_denied.status_code in (301, 302, 303, 403),
      "got %d" % dh_denied.status_code)

# ── Players + in-game moderation ──
plr = c.get("/api/server/%d/playerlist" % gs_id)
_pl = plr.get_json() or {}
check("playerlist: returns players + caps + queryable + unknown/console_capable flags",
      plr.status_code == 200 and all(k in _pl for k in
          ("players", "caps", "queryable", "unknown", "console_capable")),
      "got %d %s" % (plr.status_code, sorted(_pl)))
check("playerlist: caps reflect the game (csgo -> kick + say)",
      _pl.get("caps", {}).get("kick") is True and _pl.get("caps", {}).get("say") is True)
# ── Upload collisions: ask before replacing ──────────────────────────────────────────────────
# The browser pre-flights the filenames it is about to send so it can show old-vs-new and ask.
# The remote here is unreachable, so this asserts the CONTRACT (shape, gating, validation) —
# the parsing and the overwrite refusal are unit-tested against canned `find` output.
_uc = c.post("/api/server/%d/upload-check" % gs_id, json={"path": "", "names": ["server.cfg"]})
check("upload-check: returns an 'existing' list", _uc.status_code == 200
      and isinstance(_uc.get_json().get("existing"), list),
      "%d %s" % (_uc.status_code, _uc.get_data(as_text=True)[:90]))
# This remote is unreachable, which is the ordinary case for this endpoint — and it must not
# answer "nothing exists", because the UI would read that as "no conflicts" and upload straight
# over a file it never looked at.
check("upload-check: an unreachable host reports checked=false, not a false all-clear",
      _uc.get_json().get("checked") is False, str(_uc.get_json())[:110])
_uc_bad = c.post("/api/server/%d/upload-check" % gs_id, json={"path": "", "names": "notalist"})
check("upload-check: a non-list 'names' is rejected, not iterated as a string",
      _uc_bad.status_code == 400, "got %d" % _uc_bad.status_code)
_uc_big = c.post("/api/server/%d/upload-check" % gs_id,
                 json={"path": "", "names": ["f%d" % i for i in range(501)]})
check("upload-check: an absurd batch is refused", _uc_big.status_code == 400,
      "got %d" % _uc_big.status_code)
_uc_empty = c.post("/api/server/%d/upload-check" % gs_id, json={})
check("upload-check: a missing 'names' is a 400, not a 500", _uc_empty.status_code == 400,
      "got %d" % _uc_empty.status_code)
_uc_anon = app.test_client().post("/api/server/%d/upload-check" % gs_id,
                                  json={"path": "", "names": ["x"]})
check("upload-check: it is not reachable without a session",
      _uc_anon.status_code in (302, 401, 403), "got %d" % _uc_anon.status_code)

# ── A download the panel could not READ must not be reported as a deleted file ───────────
# stat_path answers None for three different things: a path that escapes the home directory, a
# path that is not there, and a read that never ran — on the non-raising transports (tailscale,
# local) a failed read returns ("", "…timed out", -1), so its `parts` is empty and it returns
# None exactly as it does for a file that really was deleted. The route's "Couldn't reach"
# branch sits behind an `except`, which only paramiko reaches. So an operator whose link
# flapped while downloading server.cfg was told the file was gone, and went looking for what
# deleted it — or restored a backup over a newer copy.
import panel.routes.server_files as _dl_mod
_dl_saved = (_dl_mod.stat_path, _dl_mod.stream_path)
try:
    _dl_mod.stat_path = lambda *a, **k: None
    c.get("/server/%d/download?path=cfg/server.cfg" % gs_id)
    with c.session_transaction() as _dl_s:
        _dl_msgs = [_m for _cat, _m in (_dl_s.get("_flashes") or [])]
        _dl_s.pop("_flashes", None)
    check("download: (setup) the refusal flashed something to read",
          bool(_dl_msgs), "no flash at all — the checks below would pass vacuously")
    check("download: a path the panel could not read is not called a deleted file",
          not any("there any more" in _m for _m in _dl_msgs),
          "flashed %r — it states a deletion the route never checked for" % (_dl_msgs,))
    check("download: ...and the refusal names the host not answering as a possibility",
          any("moved or deleted" in _m for _m in _dl_msgs),
          "flashed %r" % (_dl_msgs,))
    # The control: a stat that DID answer still serves the file, so the refusal above is the
    # unreadable case and not this route turning every download down.
    _dl_mod.stat_path = lambda *a, **k: {"type": "f", "size": 4, "name": "server.cfg",
                                         "rel": "cfg/server.cfg"}
    _dl_mod.stream_path = lambda *a, **k: iter([b"data"])
    _dl_ok = c.get("/server/%d/download?path=cfg/server.cfg" % gs_id)
    check("download: (control) a file the panel could stat is still served",
          _dl_ok.status_code == 200, "got %d" % _dl_ok.status_code)
finally:
    (_dl_mod.stat_path, _dl_mod.stream_path) = _dl_saved
    with c.session_transaction() as _dl_s:
        _dl_s.pop("_flashes", None)

# ── the file-save API must not write an empty file for a body with no text in it ─────────────
# `data.get("content", "")` turned a missing key — an API script's typo like "contents" — into
# "", and write_file does `(content or "").encode()`, so null/0/false/[] did the same: the
# target was truncated to 0 bytes and the answer was {"success": true, "message": "Saved"}.
_fs_writes = []
_fs_saved = _dl_mod.write_file
try:
    _dl_mod.write_file = lambda srv, user, rel, content: (_fs_writes.append((rel, content)), (True, ""))[1]
    for _fs_body in ({"path": "cfg/server.cfg", "contents": "typo"}, {"path": "cfg/server.cfg", "content": None},
                     {"path": "cfg/server.cfg", "content": 0}, {"path": "cfg/server.cfg", "content": []}):
        _fs_r = c.post("/api/server/%d/file" % gs_id, json=_fs_body)
        check("file save: %r is refused, not written as an empty file" % (sorted(_fs_body.items()),),
              _fs_r.status_code == 400 and not _fs_writes
              and (_fs_r.get_json() or {}).get("success") is False,
              "status %d, writes %r" % (_fs_r.status_code, _fs_writes))
        del _fs_writes[:]
    # Positive control: an intentionally EMPTY file is still text, and is saved.
    _fs_ok = c.post("/api/server/%d/file" % gs_id, json={"path": "cfg/empty.cfg", "content": ""})
    check("file save: an intentionally empty file (content \"\") is still saved",
          _fs_ok.status_code == 200 and _fs_writes == [("cfg/empty.cfg", "")],
          "status %d, writes %r" % (_fs_ok.status_code, _fs_writes))
finally:
    _dl_mod.write_file = _fs_saved

mod_bad = c.post("/api/server/%d/moderate" % gs_id, json={"action": "nope"})
check("moderate: unknown action -> 400", mod_bad.status_code == 400)
# A user with server access but no moderate/console permission is refused (mru can reach the
# server via its group's remote, but lacks moderate_server / send_command).
mod_denied = client_as(mru_id).post("/api/server/%d/moderate" % gs_id,
                                    json={"action": "kick", "target": "x"})
check("moderate: caller without moderate/console permission -> 403",
      mod_denied.status_code == 403, "got %d" % mod_denied.status_code)

# ── gamedig query-type override (fix games the built-in map gets wrong, e.g. cod) ──
qt = c.post("/api/server/%d/query-type" % gs_id, json={"query_type": "cod"})
_qt = qt.get_json() or {}
check("query-type: an override can be set and takes effect",
      qt.status_code == 200 and _qt.get("success") is True and _qt.get("query_type") == "cod"
      and _qt.get("queryable") is True, "got %d %s" % (qt.status_code, _qt))
qt_bad = c.post("/api/server/%d/query-type" % gs_id, json={"query_type": "bad; rm -rf"})
check("query-type: an unsafe/invalid type is rejected (400)", qt_bad.status_code == 400)
qt_clear = c.post("/api/server/%d/query-type" % gs_id, json={"query_type": ""})
check("query-type: blank clears the override",
      qt_clear.status_code == 200 and (qt_clear.get_json() or {}).get("query_type") == "")

# ── 2FA must not switch itself off when its secret cannot be decrypted ────────────────────
# totp_secret_plain returns "" on any decryption failure, and the login used to test
# `totp_enabled AND totp_secret_plain` — so an account with 2FA ON whose secret would not
# decrypt was logged straight in on the password alone. Not remotely triggerable (it needs
# damage to data/cred_key), but a control that silently disables itself is the wrong failure
# direction, and a hand-rolled migration that copies panel.db without the key does exactly it.
# A REAL Fernet token under a key this panel does not have — which is what "copied panel.db
# without data/cred_key" actually leaves behind. A syntactically invalid blob was the older
# fixture and tested a different thing: config.is_encrypted() requires the remainder to be
# shaped like a Fernet token, so a malformed one is (correctly) treated as legacy plaintext
# and handed back whole, never reaching the decrypt path this is about.
from cryptography.fernet import Fernet as _AlienFernet
from panel.core.config import is_encrypted as _is_enc
_alien_totp = "enc:v1:" + _AlienFernet(_AlienFernet.generate_key()).encrypt(
    b"JBSWY3DPEHPK3PXP").decode()
check("2fa: the fixture is a real ciphertext, just not one this panel can read",
      _is_enc(_alien_totp), _alien_totp[:30])
with app.app_context():
    _tf = User(username="tfa_fail_open",
               password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name="2FA", is_superadmin=False, is_active=True,
               totp_enabled=True, totp_secret=_alien_totp)
    _tf.set_backup_codes(["abcde-fghjk"])
    db.session.add(_tf)
    db.session.commit()
    _tf_id = _tf.id
    check("2fa: the fixture's secret really is undecryptable",
          db.session.get(User, _tf_id).totp_secret_plain == "")
_tc = app.test_client()
_r2 = _tc.post("/login", data={"username": "tfa_fail_open", "password": "Str0ng!passw0rd"},
               follow_redirects=False)
check("2fa: a password alone does NOT create a session when 2FA is on",
      _r2.status_code == 200, "status=%d loc=%s" % (_r2.status_code, _r2.headers.get("Location") or ""))
_after2 = _tc.get("/account", follow_redirects=False)
check("2fa: ...the caller is still anonymous",
      _after2.status_code in (301, 302, 303) and "/login" in (_after2.headers.get("Location") or ""),
      "status=%d" % _after2.status_code)
check("2fa: ...and the 2FA prompt is what came back", b"totp_code" in _r2.data)
# A backup code is bcrypt-hashed in its own column, so it still works without the cred key —
# the recovery path survives, which is what makes refusing the password-only login safe.
_r3 = _tc.post("/login", data={"totp_code": "abcde-fghjk"}, follow_redirects=False)
check("2fa: a backup code still gets them in (no lock-out)",
      _r3.status_code in (301, 302, 303) and "/login" not in (_r3.headers.get("Location") or ""),
      "status=%d loc=%s" % (_r3.status_code, _r3.headers.get("Location") or ""))

# ── turning 2FA OFF needs the second factor, not just the password ────────────────────────
# /account/2fa/disable asked for the password alone — a weaker gate than the one on CHANGING
# the password in the same file, which demands the password AND a live code. That is
# backwards: removing the second factor is the change that makes every later login easier.
# A session someone else is sitting in front of, plus a password they already knew, could
# strip it. The route had no test entering it at all.
from panel.db.models import User as _TU

with app.app_context():
    _td_codes = auth.generate_backup_codes()
    _td_secret = auth.generate_totp_secret()
    _td = _TU(username="tfa_disable", password_hash=auth.hash_password("Str0ng!passw0rd"),
              display_name="2FA off", is_superadmin=False, is_active=True,
              totp_enabled=True, totp_secret=encrypt_secret(_td_secret))
    _td.set_backup_codes(_td_codes)
    db.session.add(_td)
    db.session.commit()
    _td_id = _td.id


def _td_still_on():
    with app.app_context():
        _row = db.session.get(_TU, _td_id)
        return bool(_row.totp_enabled and _row.totp_secret)


_tdc = client_as(_td_id)
_r = _tdc.post("/account/2fa/disable", data={"password": "Str0ng!passw0rd"},
               follow_redirects=True)
check("2fa disable: the password alone does NOT turn it off", _td_still_on(),
      "2FA was removed on a password a borrowed session already had")
check("2fa disable: ...and the page says a code is needed",
      b"code didn&#39;t match" in _r.data or b"code didn't match" in _r.data,
      "no reason shown: %r" % _r.data[-200:])

_tdc.post("/account/2fa/disable",
          data={"password": "wrong-password", "totp_code": _td_codes[1]},
          follow_redirects=True)
check("2fa disable: ...nor does a code with the wrong password", _td_still_on())
with app.app_context():
    # Counted, not re-checked: use_backup_code CONSUMES, so asking "is it still valid" would
    # spend it. The password is verified first precisely so a one-time code is never burnt by
    # a request that fails for another reason.
    check("2fa disable: ...and that backup code was NOT spent on the failed attempt",
          db.session.get(_TU, _td_id).backup_codes_remaining == len(_td_codes),
          "%d of %d codes left — a one-time code was consumed by a request that failed for "
          "another reason" % (db.session.get(_TU, _td_id).backup_codes_remaining,
                              len(_td_codes)))

# The real thing: password + a backup code (what the card tells people to use when the
# authenticator is gone).
_tdc.post("/account/2fa/disable",
          data={"password": "Str0ng!passw0rd", "totp_code": _td_codes[0]},
          follow_redirects=True)
check("2fa disable: password + a valid backup code DOES turn it off (positive control)",
      not _td_still_on(),
      "the route now refuses everything, which would make the checks above meaningless")
with app.app_context():
    _row = db.session.get(_TU, _td_id)
    check("2fa disable: ...and its backup codes are cleared with it",
          not (_row.backup_codes or ""), "codes left behind: %r" % (_row.backup_codes or "")[:40])
    # The two refusals above are on the record now. A wrong password here wrote nothing, so a
    # borrowed session guessing passwords against the control that strips 2FA left no trace.
    from panel.db.models import AuditLog as _TDAL  # pylint: disable=reimported
    _td_refusals = [(_a.detail or "") for _a in _TDAL.query.filter_by(
        user_id=_td_id, action="2fa_disabled", success=False).all()]
    check("2fa disable: each refusal is audited, with what was wrong",
          any("wrong password" in _d for _d in _td_refusals)
          and any("authenticator code" in _d for _d in _td_refusals), repr(_td_refusals))

# ── the current-password checks are throttled per ACCOUNT ─────────────────────────────────
# /login has always had a throttle; the routes that re-ask a signed-in user for the password
# (password change, 2FA off/on, API token, deleting a host) had none, so whoever held the
# session could guess at bcrypt speed until one worked — and a right guess at /account/password
# takes the account for good. One budget across all of them, the login throttle's.
from app import LOGIN_MAX_FAILS as _TH_MAX  # pylint: disable=reimported
with app.app_context():
    _th = _TU(username="reauth_throttle", password_hash=auth.hash_password("Str0ng!passw0rd"),
              display_name="throttle", is_superadmin=False, is_active=True)
    db.session.add(_th)
    db.session.commit()
    _th_id = _th.id
_thc = client_as(_th_id)
for _i in range(_TH_MAX):
    _thc.post("/account/2fa/disable" if _i % 2 else "/account/api-token/generate",
              data={"password": "guess-%d" % _i})
_th_r = _thc.post("/account/password", data={"current_password": "Str0ng!passw0rd",
                                             "new_password": "N3w!Strong-pass",
                                             "confirm_password": "N3w!Strong-pass"},
                  follow_redirects=True)
with app.app_context():
    _th_changed = auth.check_password("N3w!Strong-pass", db.session.get(_TU, _th_id).password_hash)
check("reauth throttle: after the budget of wrong guesses on OTHER routes, even the right "
      "password is refused at /account/password",
      not _th_changed and b"Too many wrong passwords" in _th_r.data,
      "changed=%s body=%r" % (_th_changed, _th_r.data[-160:]))
with app.app_context():
    _th_blocked = _TDAL.query.filter_by(user_id=_th_id, action="password_changed",
                                       success=False).count()
check("reauth throttle: ...and the refusal is audited", _th_blocked == 1, "rows=%d" % _th_blocked)
_smoke_shared = sys.modules["panel.routes._shared"]
_smoke_shared._REAUTH_FAILS.pop(_th_id, None)       # the window, elapsed
_thc.post("/account/password", data={"current_password": "Str0ng!passw0rd",
                                     "new_password": "N3w!Strong-pass",
                                     "confirm_password": "N3w!Strong-pass"})
with app.app_context():
    _th_changed2 = auth.check_password("N3w!Strong-pass",
                                       db.session.get(_TU, _th_id).password_hash)
check("reauth throttle: once the window has passed, the right password works (control)",
      _th_changed2)

# ── Admin-issued passwords: generated, shown once, and forced to be replaced ──────────────
# An admin creating an account, or resetting someone's password, hands over a credential TWO
# people know. The panel generates it (so it is not a house pattern), returns it exactly once,
# and refuses the account everything except replacing it.
_add = c.post("/users/add", data={"username": "handover", "display_name": "Handover"},
              headers={"X-Requested-With": "XMLHttpRequest"})
_aj = _add.get_json() or {}
_issued = (_aj.get("credential") or {}).get("password") or ""
check("add user: succeeds with NO password in the form",
      _aj.get("success") is True, str(_aj)[:120])
check("add user: the response carries the generated password, once",
      bool(_issued) and (_aj["credential"].get("username") == "handover"), str(_aj)[:160])
check("add user: what it generated satisfies the panel's own password policy",
      auth_password_problem(_issued) is None, "%r -> %s" % (_issued, auth_password_problem(_issued)))
with app.app_context():
    _hu = User.query.filter_by(username="handover").first()
    _hu_id = _hu.id
    check("add user: the issued password actually authenticates",
          auth.check_password(_issued, _hu.password_hash))
    check("add user: ...and the account is flagged to replace it", _hu.must_change_password is True)

# The gate: signed in, and able to reach exactly one page.
hc = app.test_client()
_lg = hc.post("/login", data={"username": "handover", "password": _issued},
              follow_redirects=False)
check("handover login: the issued password gets them in",
      _lg.status_code in (301, 302, 303) and "/login" not in (_lg.headers.get("Location") or ""),
      "status=%d loc=%s" % (_lg.status_code, _lg.headers.get("Location") or ""))
_dash = hc.get("/", follow_redirects=False)
check("gate: every page redirects to the change-password page",
      _dash.status_code in (301, 302, 303)
      and "/password/change" in (_dash.headers.get("Location") or ""),
      "status=%d loc=%s" % (_dash.status_code, _dash.headers.get("Location") or ""))
_acct = hc.get("/account", follow_redirects=False)
check("gate: ...including the account page it would otherwise change it from",
      "/password/change" in (_acct.headers.get("Location") or ""))
_api = hc.get("/api/servers", headers={"X-Requested-With": "XMLHttpRequest"})
check("gate: an in-page fetch gets a 403 it can act on, not a login page",
      _api.status_code == 403 and _api.headers.get("X-Password-Change-Required") == "1",
      "status=%d" % _api.status_code)
check("gate: ...in the standard envelope",
      (_api.get_json() or {}).get("error") == "password_change_required",
      _api.get_data(as_text=True)[:120])
_page = hc.get("/password/change")
check("gate: the change-password page itself is reachable", _page.status_code == 200,
      "status=%d" % _page.status_code)
check("gate: ...and is rendered without the app chrome that would bounce them back",
      b'class="sidebar"' not in _page.data and b"cmdk-backdrop" not in _page.data)

# The handed-over password is not an acceptable choice for the password that replaces it.
# Otherwise the forced change is theatre: you type the admin's password into all three boxes
# and the account is still secured by a credential two people know.
_same = hc.post("/account/password", data={"current_password": _issued,
                                           "new_password": _issued, "confirm_password": _issued},
                follow_redirects=True)
check("reuse: the generated password cannot be kept as the new one",
      b"used before" in _same.data, _same.data[-400:].decode("utf-8", "replace")[:200])
with app.app_context():
    _hu_r = db.session.get(User, _hu_id)
    check("reuse: ...the account is still flagged", _hu_r.must_change_password is True)
    check("reuse: ...and the password is unchanged",
          auth.check_password(_issued, _hu_r.password_hash))

# Wrong current password must not clear the flag — the gate is not a formality.
hc.post("/account/password", data={"current_password": "not-the-one",
                                   "new_password": "Ch0sen!pass1", "confirm_password": "Ch0sen!pass1"})
with app.app_context():
    check("gate: a wrong current password leaves the account still flagged",
          db.session.get(User, _hu_id).must_change_password is True)

_chg = hc.post("/account/password", data={"current_password": _issued,
                                          "new_password": "Ch0sen!pass1",
                                          "confirm_password": "Ch0sen!pass1"},
               follow_redirects=False)
with app.app_context():
    _hu2 = db.session.get(User, _hu_id)
    check("change: setting their own password clears the flag",
          _hu2.must_change_password is False)
    check("change: ...and it is really the new password",
          auth.check_password("Ch0sen!pass1", _hu2.password_hash))
check("change: they are sent into the panel, not back to the form",
      "/password/change" not in (_chg.headers.get("Location") or ""),
      _chg.headers.get("Location") or "")
_after = hc.get("/", follow_redirects=False)
check("change: ...and the panel opens normally afterwards", _after.status_code == 200,
      "status=%d" % _after.status_code)

# History, end to end: the password they just left cannot come straight back. Without this,
# "change your password" is satisfied by changing it and changing it back, which is what
# someone does when made to replace a password they were happy with.
_back1 = hc.post("/account/password", data={"current_password": "Ch0sen!pass1",
                                            "new_password": _issued, "confirm_password": _issued},
                 follow_redirects=True)
check("history: the admin-issued password cannot be returned to later",
      b"used before" in _back1.data)
hc.post("/account/password", data={"current_password": "Ch0sen!pass1",
                                   "new_password": "Ch0sen!pass2", "confirm_password": "Ch0sen!pass2"})
_back2 = hc.post("/account/password", data={"current_password": "Ch0sen!pass2",
                                            "new_password": "Ch0sen!pass1",
                                            "confirm_password": "Ch0sen!pass1"},
                 follow_redirects=True)
check("history: nor the one before this one", b"used before" in _back2.data)
with app.app_context():
    check("history: ...and none of those refusals changed the password",
          auth.check_password("Ch0sen!pass2", db.session.get(User, _hu_id).password_hash))
# Far enough back and it is allowed again — the window is a window, not an archive.
for _n in (3, 4, 5):
    hc.post("/account/password", data={"current_password": "Ch0sen!pass%d" % (_n - 1),
                                       "new_password": "Ch0sen!pass%d" % _n,
                                       "confirm_password": "Ch0sen!pass%d" % _n})
_old_ok = hc.post("/account/password", data={"current_password": "Ch0sen!pass5",
                                             "new_password": "Ch0sen!pass1",
                                             "confirm_password": "Ch0sen!pass1"},
                  follow_redirects=True)
with app.app_context():
    check("history: a password older than the window can be used again",
          auth.check_password("Ch0sen!pass1", db.session.get(User, _hu_id).password_hash),
          _old_ok.data[-300:].decode("utf-8", "replace")[:160])

# Admin reset of SOMEONE ELSE's password: generated, flagged, old password dead.
_rst = c.post("/users/%d/edit" % _hu_id,
              data={"display_name": "Handover", "is_active": "on", "reset_password": "on"},
              headers={"X-Requested-With": "XMLHttpRequest"})
_rj = _rst.get_json() or {}
_reissued = (_rj.get("credential") or {}).get("password") or ""
check("reset: the response carries a new generated password", bool(_reissued), str(_rj)[:140])
check("reset: it is not the one they had chosen", _reissued != "Ch0sen!pass1")
with app.app_context():
    _hu3 = db.session.get(User, _hu_id)
    check("reset: the account must replace it again", _hu3.must_change_password is True)
    check("reset: their chosen password no longer works",
          not auth.check_password("Ch0sen!pass1", _hu3.password_hash))
    check("reset: the issued one does", auth.check_password(_reissued, _hu3.password_hash))

# An edit that does NOT tick reset must leave the password alone — renaming someone is not a
# reason to invalidate their login.
_noreset = c.post("/users/%d/edit" % _hu_id,
                  data={"display_name": "Renamed", "is_active": "on"},
                  headers={"X-Requested-With": "XMLHttpRequest"})
check("edit: an ordinary edit mints nothing",
      (_noreset.get_json() or {}).get("credential") is None, str(_noreset.get_json())[:120])
with app.app_context():
    check("edit: ...and leaves the password working",
          auth.check_password(_reissued, db.session.get(User, _hu_id).password_hash))

# Resetting your OWN password or 2FA from the Users page is refused. /account/password and
# /account/2fa/disable ask for the current password first; this form asks for nothing, so a
# borrowed session of any MANAGE_USERS holder could otherwise mint itself a new password, clear
# 2FA and sign the real owner out everywhere. On a THROWAWAY superadmin — the account the rest
# of this suite logs in with must keep its password whichever way this goes.
c.post("/users/add", data={"username": "selfrst", "display_name": "Self Reset",
                           "is_superadmin": "on"},
       headers={"X-Requested-With": "XMLHttpRequest"})
with app.app_context():
    _sr = User.query.filter_by(username="selfrst").first()
    _sr_id = _sr.id
    _sr.must_change_password = False   # pretend they have already set their own
    _sr.totp_enabled = True
    _sr.totp_secret = "JBSWY3DPEHPK3PXP"
    _sr_hash, _sr_epoch = _sr.password_hash, _sr.auth_epoch
    db.session.commit()
for _field in ("reset_password", "reset_2fa"):
    _selfrst = client_as(_sr_id).post(
        "/users/%d/edit" % _sr_id,
        data={"display_name": "Self Reset", "is_active": "on", "is_superadmin": "on",
              _field: "on"},
        headers={"X-Requested-With": "XMLHttpRequest"})
    _sj = _selfrst.get_json() or {}
    check("self-reset (%s): refused" % _field,
          _selfrst.status_code == 400 and not _sj.get("credential"), str(_sj)[:120])
    with app.app_context():
        _sr = db.session.get(User, _sr_id)
        check("self-reset (%s): ...and nothing changed" % _field,
              _sr.password_hash == _sr_hash and _sr.auth_epoch == _sr_epoch
              and _sr.totp_enabled is True,
              "the refused self-reset still touched the password, the epoch or 2FA")
# ...while an ordinary self-edit (no reset) still goes through.
_selfedit = client_as(_sr_id).post(
    "/users/%d/edit" % _sr_id,
    data={"display_name": "Self Renamed", "is_active": "on", "is_superadmin": "on"},
    headers={"X-Requested-With": "XMLHttpRequest"})
with app.app_context():
    check("self-edit: an edit without a reset is still allowed",
          _selfedit.status_code == 200
          and db.session.get(User, _sr_id).display_name == "Self Renamed",
          "status %d" % _selfedit.status_code)

# ── An install that predates the `sha256$` format signs in, and is upgraded in place ──
# Every existing installation hits this branch on its first login after the hash format
# changed, and it was covered only at the level of check_password()/needs_rehash(): the route
# that calls them had no test. Each property below is a distinct regression if it stops
# holding — locked out of an upgraded panel, re-upgraded on every login, signed out of every
# other device by a format change nobody asked for, or the quiet one: the legacy hash pushed
# into a 3-deep history, evicting the oldest entry and quietly freeing a real old password
# for reuse. That last one is what set_password() would do here, which is why the route
# assigns the hash directly.
import bcrypt as _lb  # pylint: disable=reimported
import json as _lj
_LEGACY_PW = "Ancient!pass1"
# Byte-for-byte what the pre-change code wrote: bcrypt over the raw password, no prefix.
_legacy_hash = _lb.hashpw(_LEGACY_PW.encode(), _lb.gensalt(4)).decode()
# A FULL history window (PASSWORD_HISTORY_LEN == 3), so nothing can be added without evicting.
_legacy_hist = [_lb.hashpw(("Ancient!pass%d" % _n).encode(), _lb.gensalt(4)).decode()
                for _n in (2, 3, 4)]
_legacy_hist_json = _lj.dumps(_legacy_hist)
with app.app_context():
    _lu = User(username="legacyhash", password_hash=_legacy_hash,
               password_history=_legacy_hist_json, auth_epoch=7, is_active=True)
    db.session.add(_lu)
    db.session.commit()
    _lu_id = _lu.id
check("legacy login: the fixture really is an old-format hash",
      _legacy_hash.startswith("$2") and not _legacy_hash.startswith("sha256$"),
      _legacy_hash[:12])

_lc2 = app.test_client()
_llogin = _lc2.post("/login", data={"username": "legacyhash", "password": _LEGACY_PW},
                    follow_redirects=False)
check("legacy login: a pre-upgrade password still signs in",
      _llogin.status_code in (301, 302, 303)
      and "/login" not in (_llogin.headers.get("Location") or ""),
      "status=%d loc=%s" % (_llogin.status_code, _llogin.headers.get("Location") or ""))
check("legacy login: ...and the session it just created is usable",
      _lc2.get("/", follow_redirects=False).status_code == 200)

with app.app_context():
    _lu2 = db.session.get(User, _lu_id)
    check("legacy login: the stored hash was upgraded to the new format",
          _lu2.password_hash.startswith("sha256$"), _lu2.password_hash[:14])
    check("legacy login: ...and the same password verifies against it",
          auth.check_password(_LEGACY_PW, _lu2.password_hash))
    check("legacy login: ...so it is not flagged for upgrade a second time",
          not auth.needs_rehash(_lu2.password_hash))
    # The two things the upgrade must NOT touch.
    check("legacy login: auth_epoch is untouched, so no device is signed out",
          _lu2.auth_epoch == 7, "epoch=%r" % (_lu2.auth_epoch,))
    check("legacy login: the reuse history is untouched, byte for byte",
          (_lu2.password_history or "") == _legacy_hist_json,
          "%r" % ((_lu2.password_history or "")[:80],))
    # The consequence of that, stated as behaviour: the OLDEST remembered password is the one
    # an extra history entry would have evicted, and it is still refused.
    check("legacy login: ...so the oldest remembered password is still refused for reuse",
          _lu2.password_reused("Ancient!pass4"))

# A second sign-in now runs entirely on the new format.
_lc3 = app.test_client()
check("legacy login: signing in again works against the upgraded hash",
      _lc3.post("/login", data={"username": "legacyhash", "password": _LEGACY_PW},
                follow_redirects=False).status_code in (301, 302, 303))

# A WRONG password must not rewrite anything — the upgrade happens only once the plaintext has
# been proven correct, never on the way to rejecting it.
with app.app_context():
    _lu3 = User(username="legacyhash2", password_hash=_legacy_hash, is_active=True)
    db.session.add(_lu3)
    db.session.commit()
    _lu3_id = _lu3.id
app.test_client().post("/login", data={"username": "legacyhash2", "password": "wrong-one"})
with app.app_context():
    check("legacy login: a failed attempt leaves the old hash exactly as it was",
          db.session.get(User, _lu3_id).password_hash == _legacy_hash)

# ── a password longer than bcrypt's 72 bytes survives the whole stack ────────────────────
# The unit suite proves hash_password()/check_password() handle any length. This proves the
# PATH does: form -> validator -> set_password -> column -> login. Truncation anywhere in
# there is invisible until someone with a passphrase in a password manager cannot sign in,
# and the decoy below is what makes it visible — two passwords sharing their first 72 bytes
# must not be interchangeable.
_PW_PREFIX = "Str0ng!" + "a" * 70          # 77 bytes; already over bcrypt's limit
_LONG_PW = _PW_PREFIX + "ENDING1!"
_DECOY_PW = _PW_PREFIX + "OTHER2@"         # same first 77 bytes, different password
check("long password: the fixture is genuinely over bcrypt's 72-byte limit",
      len(_LONG_PW.encode()) > 72 and _LONG_PW.encode()[:72] == _DECOY_PW.encode()[:72],
      "%d bytes" % len(_LONG_PW.encode()))
check("long password: the panel's own validator sets no upper bound",
      auth_password_problem(_LONG_PW) is None, str(auth_password_problem(_LONG_PW)))

_START_PW = "Start1ng!pw"
with app.app_context():
    _lpu = User(username="longpw", password_hash=auth.hash_password(_START_PW),
                is_active=True, must_change_password=False)
    db.session.add(_lpu)
    db.session.commit()
    _lpu_id = _lpu.id
_lpc = app.test_client()
_lpc.post("/login", data={"username": "longpw", "password": _START_PW})
_setlong = _lpc.post("/account/password",
                     data={"current_password": _START_PW, "new_password": _LONG_PW,
                           "confirm_password": _LONG_PW}, follow_redirects=True)
with app.app_context():
    _lpu2 = db.session.get(User, _lpu_id)
    check("long password: the change form accepts it",
          auth.check_password(_LONG_PW, _lpu2.password_hash),
          _setlong.data[-300:].decode("utf-8", "replace")[:160])
    check("long password: ...and it was NOT stored truncated to 72 bytes",
          not auth.check_password(_DECOY_PW, _lpu2.password_hash))

# The one that matters to the person: they can actually sign in with it afterwards.
_lpc2 = app.test_client()
_lpl = _lpc2.post("/login", data={"username": "longpw", "password": _LONG_PW},
                  follow_redirects=False)
check("long password: signing in with the full passphrase works",
      _lpl.status_code in (301, 302, 303)
      and "/login" not in (_lpl.headers.get("Location") or ""),
      "status=%d loc=%s" % (_lpl.status_code, _lpl.headers.get("Location") or ""))
_lpd = app.test_client().post("/login", data={"username": "longpw", "password": _DECOY_PW},
                              follow_redirects=False)
check("long password: a password sharing its first 72 bytes is refused at login",
      not (_lpd.status_code in (301, 302, 303)
           and "/login" not in (_lpd.headers.get("Location") or "")),
      "status=%d loc=%s" % (_lpd.status_code, _lpd.headers.get("Location") or ""))

# ── hostnames, SSH usernames and session IPs are ciphertext at rest ──────────────────────
# A stolen panel.db should not also be a map of the machines it manages. These columns are
# EncryptedString, which is transparent in Python, so the only way to prove it is doing
# anything is to go around the ORM and read the raw bytes.
from sqlalchemy import text as _enc_sql
_SECRET_HOST, _SECRET_USER = "vault.internal.example", "deploybot"
with app.app_context():
    _er = RemoteServer(name="enc-host", host=_SECRET_HOST, port=2222,
                       username=_SECRET_USER, auth_method="key", auth_credential="",
                       linuxgsm_user="lgsm-secret", public_ip="203.0.113.77",
                       host_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5SECRETKEY")
    db.session.add(_er)
    db.session.commit()
    _er_id = _er.id
    db.session.expire_all()          # force a real re-read, not the identity map
    _back = db.session.get(RemoteServer, _er_id)
    check("at-rest: a hostname round-trips through the ORM unchanged",
          _back.host == _SECRET_HOST, repr(_back.host))
    check("at-rest: ...and so do the username, lgsm user, public IP and host key",
          (_back.username, _back.linuxgsm_user, _back.public_ip) ==
          (_SECRET_USER, "lgsm-secret", "203.0.113.77")
          and _back.host_key.endswith("SECRETKEY"),
          "%r %r %r" % (_back.username, _back.linuxgsm_user, _back.public_ip))
    # The point: the raw column is ciphertext.
    _raw = db.session.execute(_enc_sql(
        "SELECT host, username, linuxgsm_user, public_ip, host_key FROM remote_server"
        " WHERE id = :i"), {"i": _er_id}).fetchone()
    check("at-rest: the stored hostname is ciphertext, not the hostname",
          _raw[0] != _SECRET_HOST and _raw[0].startswith("enc:v1:"), str(_raw[0])[:40])
    check("at-rest: no plaintext survives in ANY of the five columns",
          not any(v in (_raw[0] or "") + (_raw[1] or "") + (_raw[2] or "")
                         + (_raw[3] or "") + (_raw[4] or "")
                  for v in (_SECRET_HOST, _SECRET_USER, "lgsm-secret", "203.0.113.77",
                            "SECRETKEY")),
          str(_raw)[:120])

    # A row written by an OLDER panel is plaintext. It must keep working — an upgrade that
    # locked someone out of their own hosts until a migration ran would be worse than the leak.
    db.session.execute(_enc_sql(
        "INSERT INTO remote_server (name, host, port, username, auth_method, auth_credential,"
        " is_local, is_online) VALUES ('legacy-host', 'legacy.example', 22, 'oldroot', 'key',"
        " '', 0, 0)"))
    db.session.commit()
    db.session.expire_all()
    _leg = RemoteServer.query.filter_by(name="legacy-host").first()
    check("at-rest: a legacy PLAINTEXT row still reads correctly",
          _leg is not None and _leg.host == "legacy.example" and _leg.username == "oldroot",
          "%r / %r" % (getattr(_leg, "host", None), getattr(_leg, "username", None)))
    # An ordinary save does NOT convert it: SQLAlchemy writes only the columns that changed,
    # so editing the port leaves the hostname in plaintext. Worth pinning, because it is the
    # reason the migration below has to exist at all rather than being left to happen by use.
    _leg.port = 2200
    db.session.commit()
    _leg_raw = db.session.execute(_enc_sql(
        "SELECT host FROM remote_server WHERE name = 'legacy-host'")).fetchone()[0]
    check("at-rest: an unrelated edit leaves a legacy row plaintext (so a migration is needed)",
          _leg_raw == "legacy.example", str(_leg_raw)[:40])

    # The migration is what converts it, and it is idempotent.
    from panel.db.models import encrypt_at_rest_columns as _enc_mig
    _n1 = _enc_mig()
    _leg_raw2 = db.session.execute(_enc_sql(
        "SELECT host, username FROM remote_server WHERE name = 'legacy-host'")).fetchone()
    check("at-rest: the migration encrypts the legacy row", _n1 >= 1
          and _leg_raw2[0].startswith("enc:v1:") and "legacy.example" not in _leg_raw2[0]
          and "oldroot" not in (_leg_raw2[1] or ""), "touched=%s raw=%.40s" % (_n1, _leg_raw2[0]))
    db.session.expire_all()
    _leg2 = RemoteServer.query.filter_by(name="legacy-host").first()
    check("at-rest: ...and the row still reads back as the same host",
          _leg2.host == "legacy.example" and _leg2.username == "oldroot",
          "%r / %r" % (_leg2.host, _leg2.username))
    check("at-rest: ...and running it again rewrites nothing", _enc_mig() == 0)

# Sessions carry the same treatment: IP and user-agent are PII on every signed-in device.
with app.app_context():
    from panel.db.models import UserSession as _US
    _sess_raw = db.session.execute(_enc_sql(
        "SELECT ip, user_agent FROM user_session WHERE ip != '' LIMIT 1")).fetchone()
    _any_sess = db.session.query(_US).filter(_US.ip != "").first()
    # Its ABSENCE is a failure, not a skip. Dozens of logins have happened by this point, so no
    # row with an IP means the check is testing nothing — which must be loud, not green.
    check("at-rest: there is a session row to inspect at all",
          _sess_raw is not None and _any_sess is not None,
          "no user_session row carried an IP — this block would prove nothing")
    check("at-rest: session IP and user-agent are ciphertext",
          _sess_raw is not None and (_sess_raw[0] or "").startswith("enc:v1:")
          and (not _sess_raw[1] or _sess_raw[1].startswith("enc:v1:")),
          str(_sess_raw)[:60])
    check("at-rest: ...and still read back as the real values",
          _any_sess is not None and bool(_any_sess.ip)
          and not _any_sess.ip.startswith("enc:v1:"),
          repr(getattr(_any_sess, "ip", None)))

# ── audit IPs age out into network prefixes ──────────────────────────────────────────────
# The audit log kept a full IP for every action forever, which makes it an indefinite record
# of where each admin was. The ROW is what the log is for, so the entry stays and only the
# identifying part of the address goes.
from panel.db.models import AuditLog as _AL, anonymise_audit_ips as _anon, _anonymise_ip as _aip  # pylint: disable=reimported
from datetime import timedelta as _td
from panel.core.clock import utcnow as _utcnow
check("audit-ip: an IPv4 address reduces to its /24",
      _aip("203.0.113.77") == "203.0.113.0/24", _aip("203.0.113.77"))
check("audit-ip: an IPv6 address reduces to its /64",
      _aip("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64", _aip("2001:db8:1:2:3:4:5:6"))
check("audit-ip: something that is not an address is dropped, not kept",
      _aip("not-an-ip") == "" and _aip("") == "")
with app.app_context():
    _now = _utcnow()
    _old_row = _AL(username="olduser", action="login", ip_address="198.51.100.42",
                   timestamp=_now - _td(days=200))
    _new_row = _AL(username="newuser", action="login", ip_address="198.51.100.43",
                   timestamp=_now - _td(days=1))
    db.session.add_all([_old_row, _new_row])
    db.session.commit()
    _old_id, _new_id = _old_row.id, _new_row.id
    _n = _anon(90)
    check("audit-ip: an entry older than the window is reduced", _n >= 1
          and db.session.get(_AL, _old_id).ip_address == "198.51.100.0/24",
          "%s / %r" % (_n, db.session.get(_AL, _old_id).ip_address))
    check("audit-ip: ...and a recent one is left alone",
          db.session.get(_AL, _new_id).ip_address == "198.51.100.43",
          repr(db.session.get(_AL, _new_id).ip_address))
    check("audit-ip: the ROW survives — only the address is reduced",
          db.session.get(_AL, _old_id).username == "olduser"
          and db.session.get(_AL, _old_id).action == "login")
    # Idempotent, and cheap on restart: an already-reduced row must not be rewritten again.
    check("audit-ip: running it again rewrites nothing", _anon(90) == 0)
    check("audit-ip: 0 disables it entirely", _anon(0) == 0)
    # config.json is hand-editable and "90" (quoted) is an easy thing to write. Comparing a
    # str to an int raises TypeError, app.py swallows it with a bare except, and the control
    # then silently never runs while the config still says it is on. A privacy control that
    # fails quietly is worse than one that is off, because nobody goes looking.
    _old2 = _AL(username="olduser2", action="login", ip_address="198.51.100.44",
                timestamp=_now - _td(days=200))
    db.session.add(_old2)
    db.session.commit()
    _old2_id = _old2.id
    # Both calls are caught: without the coercion they raise TypeError, and an exception here
    # aborts the part before the summary prints — hiding this verdict AND every check after
    # it. The failure has to be legible as a FAIL, not as a suite that produced no output.
    def _anon_safely(val):
        try:
            return _anon(val), None
        except Exception as _e:                      # noqa: BLE001 - the thing under test
            return None, "%s: %s" % (type(_e).__name__, _e)

    _n_str, _err_str = _anon_safely("90")
    check("audit-ip: a NUMERIC STRING in config.json still works, rather than raising",
          _err_str is None and _n_str >= 1
          and db.session.get(_AL, _old2_id).ip_address == "198.51.100.0/24",
          _err_str or repr(db.session.get(_AL, _old2_id).ip_address))
    _n_junk, _err_junk = _anon_safely("ninety")
    check("audit-ip: junk in config.json disables it and does not raise",
          _err_junk is None and _n_junk == 0, _err_junk or repr(_n_junk))
    # The brute-force counter reads a 300-SECOND window, so it can never see a reduced row.
    # This is the check that says the privacy control cannot weaken login throttling.
    _recent = _AL.query.filter(_AL.action == "login_failed",
                               _AL.timestamp >= _now - _td(seconds=300)).count()
    _anon(90)
    check("audit-ip: ...and the throttle's own window is untouched by it",
          _AL.query.filter(_AL.action == "login_failed",
                           _AL.timestamp >= _now - _td(seconds=300)).count() == _recent)
    # An older version stored proxy-reported client addresses with an IPv6 zone id, and its
    # reduction of one whose low 64 bits were zero kept the zone's text ahead of the "/64". That
    # row then read as already reduced (it holds a '/'), so the text stayed for good. An aged
    # row holding a '%' is now rewritten through _anonymise_ip: the network kept, the text gone,
    # and one that is no address at all blanked.
    _zn_old = {}
    for _v in ("2001:db8:77::%x panel login failed from 203.0.113.9/64",   # reduced, text kept
               "fe80::1c2d:3e4f:5a6b:7c8d%eth0",                          # never reduced
               "%not an address/64"):
        _zn_old[_v] = _AL(username="zone_aged", action="login_failed", ip_address=_v,
                          timestamp=_now - _td(days=200))
    db.session.add_all(list(_zn_old.values()))
    db.session.commit()
    _zn_ids = {_v: _r.id for _v, _r in _zn_old.items()}
    _anon(90)
    _zn_got = {_v: db.session.get(_AL, _i).ip_address for _v, _i in _zn_ids.items()}
    check("audit-ip: an aged row holding an IPv6 zone id is rewritten even when an older "
          "version already reduced it — no '%' and no zone text is left",
          not any("%" in _g or "203.0.113" in _g or " " in _g for _g in _zn_got.values()),
          repr(_zn_got))
    check("audit-ip: ...and it keeps the network: each zoned row becomes its address's /64, "
          "one that is no address is blanked",
          _zn_got == {
              "2001:db8:77::%x panel login failed from 203.0.113.9/64": "2001:db8:77::/64",
              "fe80::1c2d:3e4f:5a6b:7c8d%eth0": "fe80::/64", "%not an address/64": ""},
          repr(_zn_got))
    check("audit-ip: ...and a second run rewrites none of them again", _anon(90) == 0)
    _check_audit_zone_cleanup_on_upgrade()
    _check_audit_zone_failure_is_logged()

# ── one server table: /servers/manage folded into the dashboard ──────────────────────────
# The two pages showed seven of the same eight columns and shared no code at all — doAction vs
# msrvAction, sortDashCol vs sortServers — so one was a second implementation of the other.
# The checks that asserted the old page are replaced here, not dropped: what they tested is
# gone, and what replaced it is below.
_ms = c.get("/servers/manage", follow_redirects=False)
check("one-table: /servers/manage redirects rather than 404s",
      _ms.status_code in (301, 302, 303), "status=%d" % _ms.status_code)
check("one-table: ...to the dashboard",
      (_ms.headers.get("Location") or "").rstrip("/").endswith("") and
      (_ms.headers.get("Location") or "/") in ("/", "http://localhost/"),
      "Location=%s" % _ms.headers.get("Location"))
# Everything that lived only on the old page has to be on the dashboard now.
_dash = c.get("/").get_data(as_text=True)
check("one-table: the dashboard carries the per-server Files & Config link",
      "/files" in _dash, "server_files was reachable from the old row and nowhere else")
# ...for someone who may USE it. The row's three action buttons and both bulk bars hung off a
# single can_control flag that was the UNION of start/stop/restart, and the Files button hung
# off nothing at all — so a moderator holding only start_server was shown Stop and Restart on
# every row, and every viewer got a Files button that round-trips to a red "You don't have
# permission to manage server files."  Driven as a REAL restricted user, because a superadmin
# satisfies every gate and would prove nothing; and asserting the button that must be THERE as
# well as the ones that must not, because a route that computes the flags and forgets to pass
# them to render_template leaves Jinja an Undefined that is silently falsy — which is exactly
# what happened, and an absence-only check would have called that a pass.
with app.app_context():
    _sog = Group(name="smoke-startonly")
    _sog.set_permissions([auth.VIEW_SERVERS, auth.START_SERVER])
    _sog.game_servers.append(db.session.get(GameServer, gs_id))
    db.session.add(_sog)
    db.session.flush()
    _sou = User(username="startonly", password_hash=auth.hash_password("Str0ng!passw0rd"),
                is_superadmin=False, is_active=True)
    _sou.groups.append(_sog)
    db.session.add(_sou)
    db.session.commit()
    _sou_id = _sou.id
_sod = client_as(_sou_id).get("/").get_data(as_text=True)
check("dashboard perms: the start-only user's row is rendered, so the checks below see one",
      'data-action="doAction"' in _sod,
      "no action buttons at all — every absence check below would pass vacuously")
check("dashboard perms: ...and carries the Start button they hold",
      '[%d, "start", "@self"]' % gs_id in _sod, "start_server granted, no Start button")
check("dashboard perms: ...but not Restart",
      '[%d, "restart", "@self"]' % gs_id not in _sod, "Restart offered without the permission")
check("dashboard perms: ...nor Stop",
      '[%d, "stop", "@self"]' % gs_id not in _sod, "Stop offered without the permission")
check("dashboard perms: the bulk bar offers Start", "'[\"start\"]'" in _sod,
      "the bulk bar dropped the one action they can run")
check("dashboard perms: ...and not bulk Stop", "'[\"stop\"]'" not in _sod,
      "a bulk Stop across a tag group fails wholesale with Permission denied")
check("dashboard perms: ...and no Files & Config button",
      "/server/%d/files" % gs_id not in _sod,
      "server_files is MANAGE_SERVERS; the button 403s for this user")
_sof = client_as(_sou_id).get("/server/%d/files" % gs_id, follow_redirects=False)
check("dashboard perms: ...because that route refuses them, so the absence was honest",
      _sof.status_code in (403, 302, 401), "status=%d" % _sof.status_code)
# The other way in was the detail page's tab bar, which is the SAME permission
# (_can_manage_files) and was equally unconditional — so gating only the dashboard row would
# have moved the dead end rather than closed it. A superadmin must still see both, or the gate
# is just a deletion.
_sodet = client_as(_sou_id).get("/server/%d" % gs_id)
check("dashboard perms: the detail page renders for the start-only user",
      _sodet.status_code == 200 and 'data-mtab-btn="console"' in
      _sodet.get_data(as_text=True), "status=%d" % _sodet.status_code)
check("dashboard perms: ...and its Files & Config TAB is gone too",
      "/server/%d/files" % gs_id not in _sodet.get_data(as_text=True),
      "the tab bar still offers a page that flashes a permission error")
_sadet = c.get("/server/%d" % gs_id).get_data(as_text=True)
check("dashboard perms: ...while a superadmin still has that tab",
      "/server/%d/files" % gs_id in _sadet, "the gate removed it for everyone")
check("one-table: ...the per-server tag button",
      'data-action="editServerTags"' in _dash)
# Split the <head> off first. This check passed while the Tags card was accidentally emitted
# INSIDE {% block title %} — the string was in the HTML, so a whole-document substring test
# was true, the tab title was full of raw markup and the card rendered nowhere. A page-level
# assertion has to look at the page.
_dash_body = _dash.split("</head>", 1)[-1]
check("one-table: the dashboard's <title> is a title, not markup",
      "<details" not in _dash.split("</title>")[0],
      _dash.split("</title>")[0][-120:])
check("one-table: ...and the Tags card is in the BODY", 'id="sec-tags"' in _dash_body)
check("one-table: ...rendered once, not twice",
      _dash_body.count("bi-tags-fill") == 1,
      "%d tag headers — the <summary> replaced the card-header, both should not remain"
      % _dash_body.count("bi-tags-fill"))
check("one-table: ...with the script that makes those buttons work",
      "server_tags.js" in _dash, "the tag handlers would be dead without it")

# ── the palette offers only actions the user may actually run ────────────────────────────
# The palette can now START/RESTART/STOP from the search box, which makes /api/palette an
# authorization surface rather than a list of names. The rule it has to keep: never name an
# action the caller would be refused for. Checked against a REAL restricted user, because a
# superadmin passes every permission test and would prove nothing.
_pal = c.get("/api/palette")
check("palette: the index still loads", _pal.status_code == 200, "status=%d" % _pal.status_code)
_pj = _pal.get_json() or []
check("palette: it lists the servers", len(_pj) >= 1, "%d entries" % len(_pj))
check("palette: a superadmin is offered all three verbs",
      any(sorted(e.get("actions") or []) == ["restart", "start", "stop"]
          for e in _pj if e.get("installed")),
      str([(e["name"], e.get("actions")) for e in _pj])[:200])
# An account that can SEE a server but has no action permissions must get names and no verbs.
# The group is given ACCESS to the game server as well as VIEW_SERVERS. Without the access
# grant the user sees an empty list, and `all(... for e in [])` is True — so the check below
# passed while examining nothing, and stripping the permission filter entirely failed no test.
# Mutation caught it. The non-emptiness is now asserted before the claim that rests on it.
with app.app_context():
    _vg = Group(name="smoke-viewonly")
    _vg.set_permissions([auth.VIEW_SERVERS])
    _vg.game_servers.append(db.session.get(GameServer, gs_id))
    db.session.add(_vg)
    db.session.flush()
    _viewer = User(username="paletteviewer",
                   password_hash=auth.hash_password("Str0ng!passw0rd"),
                   is_superadmin=False, is_active=True)
    _viewer.groups.append(_vg)
    db.session.add(_viewer)
    db.session.commit()
    _viewer_id = _viewer.id
_pal2 = client_as(_viewer_id).get("/api/palette")
check("palette: a view-only user still reaches it", _pal2.status_code == 200,
      "status=%d" % _pal2.status_code)
_pj2 = _pal2.get_json() or []
check("palette: the view-only user actually SEES a server, so the next check examines one",
      len(_pj2) >= 1, "%d entries — an empty list would pass the next check vacuously"
      % len(_pj2))
check("palette: ...and is offered NO actions at all",
      _pj2 and all(not (e.get("actions") or []) for e in _pj2),
      str([(e["name"], e.get("actions")) for e in _pj2])[:200])
# An un-installed server has nothing to start, even for an admin. Guarded, because
# `all(... for e in <empty>)` is True: with no un-installed server in the fixture this check
# would examine nothing and pass while the filter it tests was gone. The view-only check above
# was found vacuous exactly this way.
_pj_uninst = [e for e in _pj if not e.get("installed")]
check("palette: the fixture HAS an un-installed server, so the next check examines one",
      len(_pj_uninst) >= 1, "no un-installed entry — the next check would pass vacuously")
check("palette: an un-installed server carries no verbs",
      _pj_uninst and all(not (e.get("actions") or []) for e in _pj_uninst),
      str([(e["name"], e.get("actions")) for e in _pj_uninst])[:200])
# And the endpoint's answer must agree with the one the ACTION route enforces, or the palette
# is offering a button that 403s.
_act_denied = client_as(_viewer_id).post("/api/server/%d/action" % gs_id,
                                         json={"action": "start"},
                                         headers={"X-Requested-With": "XMLHttpRequest"})
check("palette: the action route refuses that same user, so the empty list was honest",
      _act_denied.status_code in (403, 302, 401),
      "status=%d" % _act_denied.status_code)

# Bulk Update for a group holding update_server alone. The bar, the row checkboxes and
# select-all were all behind can_control (start/stop/restart), so the Update button the bar
# gates for exactly this user could never appear — they updated servers one page at a time.
_vo_dash = client_as(_viewer_id).get("/").get_data(as_text=True)
check("dashboard: a view-only user gets no bulk selection (the gate still exists)",
      'class="form-check-input srv-check"' not in _vo_dash and "bulk-update-btn" not in _vo_dash,
      "row checkboxes or the Update button rendered for a user who can do none of it")
with app.app_context():
    Group.query.filter_by(name="smoke-viewonly").first().set_permissions(
        [auth.VIEW_SERVERS, auth.UPDATE_SERVER])
    db.session.commit()
try:
    _up_dash = client_as(_viewer_id).get("/").get_data(as_text=True)
    check("dashboard: update_server alone is enough to select servers and bulk-Update them",
          'class="form-check-input srv-check"' in _up_dash and "bulk-update-btn" in _up_dash
          and "srv-check-all" in _up_dash,
          "checkboxes=%s select-all=%s update-button=%s — no way to select, so no bulk Update"
          % ('class="form-check-input srv-check"' in _up_dash, "srv-check-all" in _up_dash,
             "bulk-update-btn" in _up_dash))
finally:
    with app.app_context():
        Group.query.filter_by(name="smoke-viewonly").first().set_permissions(
            [auth.VIEW_SERVERS])
        db.session.commit()

# ── the install form lives on its own page now ───────────────────────────────────────────
# It used to sit on /servers/manage above the list of servers you already have. Splitting it
# out is only safe if the form still WORKS from its new home, so this checks the controls and
# the submit target came with it, not merely that the page returns 200.
_inst = c.get("/servers/install")
check("install page: renders", _inst.status_code == 200, "status=%d" % _inst.status_code)
_ih = _inst.get_data(as_text=True)
check("install page: carries the install form's controls",
      all(x in _ih for x in ("remote-select", "game-type-select", "port-input")))
check("install page: ...and still posts to the install endpoint",
      "/servers/add" in _ih, "no form action pointing at the install route")
# The page it came from must no longer carry it, or the split achieved nothing.
# The list lives on the DASHBOARD now, so that is where "the form is not embedded, but is
# reachable" has to hold. Reading /servers/manage here would read a redirect body and assert
# nothing — it passed for a while precisely because an empty body contains no form either.
_mh = c.get("/", follow_redirects=True).get_data(as_text=True)
check("install page: the server list no longer embeds the form",
      "game-type-select" not in _mh and "remote-select" not in _mh)
check("install page: ...but the list links to it", "/servers/install" in _mh)
# Same permission pair as the POST it submits to: reaching the form and using it are one
# decision. A user with neither must be refused the page, not shown a form that 403s on submit.
with app.app_context():
    _nog = Group(name="smoke-noinstall")
    _nog.set_permissions([auth.VIEW_SERVERS])
    db.session.add(_nog)
    db.session.flush()
    _noinst = User(username="noinstall", password_hash=auth.hash_password("Str0ng!passw0rd"),
                   is_superadmin=False, is_active=True)
    _noinst.groups.append(_nog)
    db.session.add(_noinst)
    db.session.commit()
    _noinst_id = _noinst.id
# The dashboard's empty state speaks for what THIS user can see. For an account with no host
# or server grant `servers` is [], however many the install runs, and it was told "No game
# servers are configured yet" — a claim about the install made to someone who sees none of it.
_ng_dash = client_as(_noinst_id).get("/")
_ng_html = _ng_dash.get_data(as_text=True)
check("dashboard: a user with no grants is told nothing is shared with them, not that the "
      "install has no servers",
      _ng_dash.status_code == 200 and "No game servers have been shared with you yet." in _ng_html
      and "No game servers are configured yet." not in _ng_html,
      "status=%d shared-copy=%s configured-copy=%s"
      % (_ng_dash.status_code, "shared with you" in _ng_html,
         "are configured yet" in _ng_html))


# A one-host panel must not ask which host. The placeholder is a required field whose only
# valid answer is the single option under it — a click that can only be made one way. With two
# or more the placeholder stays, because then the choice is real and a silent default would
# install onto whichever host happened to sort first.
def _host_options(html):
    """The <option>s inside the target-host select, so a count means hosts and not markup."""
    if 'id="remote-select"' not in html:
        return ""
    return html.split('id="remote-select"')[1].split("</select>")[0]


_multi_sel = _host_options(_ih)
_multi_n = _multi_sel.count("<option")
check("install page: the superadmin fixture really does have several hosts",
      _multi_n >= 3, "%d options — with fewer the next check proves nothing" % _multi_n)
check("install page: with SEVERAL hosts it still asks which one",
      "Select a server" in _multi_sel and "selected" not in _multi_sel,
      "%d options: %.140s" % (_multi_n, _multi_sel))
with app.app_context():
    _1hg = Group(name="smoke-onehost")
    _1hg.set_permissions([auth.INSTALL_SERVER])
    _1hg.servers.append(db.session.get(RemoteServer, remote_id))
    db.session.add(_1hg)
    db.session.flush()
    _1hu = User(username="onehost", password_hash=auth.hash_password("Str0ng!passw0rd"),
                is_superadmin=False, is_active=True)
    _1hu.groups.append(_1hg)
    db.session.add(_1hu)
    db.session.commit()
    _1hu_id = _1hu.id
_one = client_as(_1hu_id).get("/servers/install")
check("install page: a single-host user reaches it", _one.status_code == 200,
      "status=%d" % _one.status_code)
_oh = _one.get_data(as_text=True)
_sel_block = _oh.split('id="remote-select"')[1].split("</select>")[0] if 'id="remote-select"' in _oh else ""
check("install page: ...and sees exactly one host option",
      _sel_block.count("<option") == 1, "%d options: %.120s" % (_sel_block.count("<option"), _sel_block))
check("install page: ...pre-selected, with no 'Select a server...' to click past",
      "selected" in _sel_block and "Select a server" not in _sel_block, _sel_block[:160])

_denied = client_as(_noinst_id).get("/servers/install", follow_redirects=False)
check("install page: a user without install/manage permission is refused",
      _denied.status_code in (302, 303, 403),
      "status=%d — a user who cannot install must not reach the form" % _denied.status_code)

# ── Discover / import existing LinuxGSM servers on a host ──
# The fixture host is a blackholed 192.0.2.x address, so the scan does not run — and an empty
# scan is no longer reported as "no servers found". This check used to assert that old
# behaviour, which is the bug: discover_linuxgsm_servers returns [] both for "nothing here"
# and for "never ran", so the card printed a green tick about a host it had not read.
dsc = c.get("/api/remote/%d/discover" % remote_id)
check("discover: an unreachable host is reported as unread, not as having no servers",
      dsc.status_code == 200 and "error" in (dsc.get_json() or {})
      and "servers" not in (dsc.get_json() or {}),
      "got %d %s" % (dsc.status_code, str(dsc.get_json())[:120]))
# ...and with the host answering, the list is a list again — the control that stops the check
# above passing on a route that simply refuses everything.
import panel.routes.discover as _dscmod
_dsc_saved = _dscmod.run_command
try:
    _dscmod.run_command = lambda r, cmd, **k: (_dscmod._PROBE_MARKER, "", 0)
    dsc_ok = c.get("/api/remote/%d/discover" % remote_id)
    check("discover: superadmin gets a servers list when the host answers",
          dsc_ok.status_code == 200
          and isinstance((dsc_ok.get_json() or {}).get("servers"), list),
          "got %d %s" % (dsc_ok.status_code, str(dsc_ok.get_json())[:120]))
finally:
    _dscmod.run_command = _dsc_saved
dsc = dsc_ok
imp_empty = c.post("/api/remote/%d/import" % remote_id, json={"servers": []})
check("import: empty selection -> 400", imp_empty.status_code == 400)
# Import validates each entry like a fresh install: a bad username or unknown game is
# skipped (so an imported short_name can never carry shell metacharacters); a valid one is added.
# Discovery is stubbed, because import now re-SCANS and accepts only what the scan reports —
# see the "root" check below for what that closes.
from panel.routes import discover as _imp_mod  # pylint: disable=reimported
_imp_orig = _imp_mod.discover_linuxgsm_servers
# The import also asks the host whether each selected account is root-capable before it adopts
# it (privileged_accounts). The fixture host is blackholed, so that question is answered here
# — "a plain game account" — for the checks about everything else, and driven for real below.
_imp_priv_orig = _imp_mod.privileged_accounts
# The import refuses a port that is this host's SSH or the panel's: it asks the host's sshd for
# its ports, which the blackholed fixture host would only answer with a connect timeout.
_imp_prot_orig = _sm_hosts.protected_host_ports
try:
    _sm_hosts.protected_host_ports = lambda _r: {22}
    _imp_mod.privileged_accounts = lambda _r, _users: {}
    _imp_mod.discover_linuxgsm_servers = lambda _s: [
        {"user": "importedcs", "lgsm_name": "csgoserver", "port": 27015,
         "backups": 0, "mods": 0, "cron": 0, "autostart": False}]
    imp = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
        {"user": "importedcs", "game_type": "csgo", "port": 27015},
        {"user": "BAD NAME", "game_type": "csgo", "port": 1},
        {"user": "okuser", "game_type": "notarealgame", "port": 1}]})
    _im = imp.get_json() or {}
    check("import: adds the valid server, skips the bad name + unknown game",
          imp.status_code == 200 and _im.get("added") == ["importedcs"]
          and len(_im.get("skipped", [])) == 2, "got %s" % _im)
    # The account name arrives from the CLIENT and INSTANCE_NAME_RE is a Linux-username
    # grammar, not an allowlist: "root", "ubuntu" and "postgres" all match it. Nothing in the
    # route contacted the host, so a POST naming any account created a GameServer row for it —
    # and a whole-host grant makes every GameServer on that host accessible, after which every
    # game op builds `sudo -u root bash -c ...`. The scan is the authority on what exists.
    check("import: the fixture's scan does not report root, so the next check means something",
          "root" not in [r["user"] for r in _imp_mod.discover_linuxgsm_servers(None)],
          "the stub would have to report root for this to be a real test")
    imp_root = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
        {"user": "root", "game_type": "csgo", "port": 27015}]})
    _imr = imp_root.get_json() or {}
    check("import: an account the scan never reported is refused, root included",
          _imr.get("added") == [] and _imr.get("skipped") == ["root"], str(_imr)[:140])
    with app.app_context():
        _root_rows = GameServer.query.filter_by(remote_id=remote_id, short_name="root").count()
    check("import: ...and no row was written for it", _root_rows == 0, "rows=%d" % _root_rows)

    # ── An account that is root on the host is never adopted ──
    # "root" was the ONLY name import refused. The scan reports any account with a
    # ~/linuxgsm.sh, including the host's own sudo-capable login, and every file, cron and
    # console action on the row then runs AS that account — ~/.bashrc, authorized_keys and
    # crontab writes as a sudoer are root on the host. The real privileged_accounts runs here;
    # only the host's answer to its probe is scripted.
    _imp_mod.privileged_accounts = _imp_priv_orig
    _pa_saved = (_sm_core.run_command, _imp_mod._bg_cache_commands)
    _pa_sent = []

    def _pa_rc(_s, cmd, **_k):
        _pa_sent.append(cmd)
        if "LGSM_ACCT_PROBE_DONE" in cmd:
            return ("ACCT adminacct 1000 adminacct adm sudo\nACCT plaingame 1001 plaingame\n"
                    "LGSM_ACCT_PROBE_DONE\n", "", 0)
        return ("", "", 0)
    try:
        _sm_core.run_command = _pa_rc
        _imp_mod._bg_cache_commands = lambda *a, **k: None
        _imp_mod.discover_linuxgsm_servers = lambda _s: [
            {"user": _u, "lgsm_name": "csgoserver", "port": 27015, "backups": 0, "mods": 0,
             "cron": 0, "autostart": False} for _u in ("adminacct", "plaingame")]
        _pa = (c.post("/api/remote/%d/import" % remote_id, json={"servers": [
            {"user": "adminacct", "game_type": "csgo", "port": 27020},
            {"user": "plaingame", "game_type": "csgo", "port": 27021}]}).get_json() or {})
        # A host that does not answer the probe: nothing is imported, whatever was selected.
        _sm_core.run_command = lambda *a, **k: ("", "SSH command timed out", -1)
        _pa_down = (c.post("/api/remote/%d/import" % remote_id, json={"servers": [
            {"user": "adminacct", "game_type": "csgo", "port": 27020}]}).get_json() or {})
    finally:
        _sm_core.run_command, _imp_mod._bg_cache_commands = _pa_saved
        _imp_mod.privileged_accounts = lambda _r, _users: {}
    check("import: an account in the host's sudo group is refused, with the reason; a plain "
          "game account beside it is imported",
          _pa.get("added") == ["plaingame"]
          and [r.get("user") for r in _pa.get("refused") or []] == ["adminacct"]
          and "sudo" in ((_pa.get("refused") or [{}])[0].get("reason") or ""), str(_pa)[:300])
    check("import: ...one probe asked the host, before anything was written",
          sum("LGSM_ACCT_PROBE_DONE" in _x for _x in _pa_sent) == 1, str(_pa_sent)[:200])
    check("import: a host that cannot be asked imports nothing, and says why",
          _pa_down.get("success") is False and "Couldn't check" in (_pa_down.get("message") or "")
          and not _pa_down.get("added"), str(_pa_down)[:200])
    with app.app_context():
        _pa_rows = {g.short_name for g in GameServer.query.filter(
            GameServer.remote_id == remote_id,
            GameServer.short_name.in_(["adminacct", "plaingame"])).all()}
        _pa_port = [g.port for g in GameServer.query.filter_by(
            remote_id=remote_id, short_name="plaingame").all()]
        GameServer.query.filter(GameServer.remote_id == remote_id,
                                GameServer.short_name == "plaingame").delete()
        db.session.commit()
    check("import: ...and no row was ever written for the sudoer", _pa_rows == {"plaingame"},
          str(_pa_rows))
    # The body asked for 27021; the scan read 27015. The import stores what it read on the host.
    check("import: the port stored is the one the scan read on the host, not the one the "
          "request named", _pa_port == [27015], str(_pa_port))

    # An account imported on the panel's OWN host goes into the panel's game-account group —
    # the step create_game_user takes for an account the panel makes. The import used to add
    # the row and nothing else, and on a narrow-grant install the helper refuses every
    # per-account verb (start, stop, update, downloads) for an account outside that group. An
    # account the helper will not enrol, because it can already reach root, is REPORTED.
    from panel.ops.ssh_manager import _core as _imp_core
    _imp_saved = (_imp_core.run_privileged, _imp_core.is_local_server,
                  _imp_mod._bg_cache_commands)
    _imp_calls = []

    def _imp_fake_rp(_s, verb, args=(), **_k):
        _imp_calls.append((verb, list(args)))
        if verb == "gameuser-group" and list(args) == ["importedsudo"]:
            return ("", "refusing to enrol importedsudo in lgsmpanel-games: it can already "
                        "run sudo\n", 1)
        return ("", "", 0)
    try:
        _imp_core.run_privileged = _imp_fake_rp
        _imp_core.is_local_server = lambda _s: True
        # No worker to outlive the stubs — and the call is RECORDED, because the command-list
        # read it starts runs as the game account and needs the membership granted first.
        _imp_bg_args = []
        _imp_mod._bg_cache_commands = lambda *a, **k: (
            _imp_calls.append(("bg-cache", [])), _imp_bg_args.append((a, k)))
        _imp_mod.discover_linuxgsm_servers = lambda _s: [
            {"user": _u, "lgsm_name": "csgoserver", "port": 27015, "backups": 0, "mods": 0,
             "cron": 0, "autostart": False} for _u in ("importedplain", "importedsudo")]
        imp_en = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
            {"user": "importedplain", "game_type": "csgo", "port": 27016},
            {"user": "importedsudo", "game_type": "csgo", "port": 27017}]})
    finally:
        (_imp_core.run_privileged, _imp_core.is_local_server,
         _imp_mod._bg_cache_commands) = _imp_saved
    _ime = imp_en.get_json() or {}
    _ime_enrolled = sorted(_a for _v, _a in _imp_calls if _v == "gameuser-group")
    # The helper is asked about BOTH, and only the one it enrolled is imported. The refused one
    # used to be imported anyway — its row was committed before the helper was asked — and the
    # panel then drove, as a game account, an account the helper had just said can reach root.
    check("import: each account imported on the panel's own host is put in the game group, "
          "and the one the helper refuses is NOT imported",
          sorted(_ime.get("added") or []) == ["importedplain"]
          and _ime_enrolled == [["importedplain"], ["importedsudo"]],
          "added=%s enrolled=%s" % (_ime.get("added"), _ime_enrolled))
    _ime_order = [_v for _v, _a in _imp_calls if _v in ("gameuser-group", "bg-cache")]
    check("import: ...BEFORE the background command-list read that runs as those accounts",
          _ime_order == ["gameuser-group", "gameuser-group", "bg-cache"], str(_ime_order))
    _ime_ne = _ime.get("refused") or []
    check("import: ...and the one the helper refuses is reported as refused, with its reason; "
          "the other is not", [_n.get("user") for _n in _ime_ne] == ["importedsudo"]
          and "already run sudo" in (_ime_ne[0].get("reason") or "")
          and not _ime.get("not_enrolled") and "importedsudo" in (_ime.get("skipped") or []),
          str(_ime)[:260])
    # Autostart is turned on for imported servers, as an install does — but only where the
    # panel can write the account's crontab, so not for the account the helper refused.
    with app.app_context():
        _imp_ids = {g.short_name: g.id for g in GameServer.query.filter(
            GameServer.remote_id == remote_id,
            GameServer.short_name.in_(["importedplain", "importedsudo"])).all()}
        _imp_flags = {g.short_name: g.autostart for g in GameServer.query.filter(
            GameServer.remote_id == remote_id,
            GameServer.short_name.in_(["importedplain", "importedsudo"])).all()}
    _imp_as = set((_imp_bg_args[0][1].get("autostart_ids") if _imp_bg_args else None) or ())
    check("import: ...no row was kept for the refused account",
          "importedsudo" not in _imp_ids, str(_imp_ids))
    check("import: the background step is asked to turn Autostart on for the enrolled account",
          _imp_as == {_imp_ids.get("importedplain")} and None not in _imp_as,
          "autostart_ids=%s ids=%s" % (sorted(_imp_as), _imp_ids))
    check("import: ...and the flag stays off until the cron line is actually written",
          _imp_flags == {"importedplain": False}, str(_imp_flags))
    # The background-step checks below drive two rows; the second is now written by hand,
    # since the import (rightly) no longer keeps the account the helper refused.
    with app.app_context():
        _imp_second = GameServer(remote_id=remote_id, name="importedsudo",
                                 short_name="importedsudo", game_type="csgo", port=27017,
                                 installed=True, status="offline", autostart=False)
        db.session.add(_imp_second)
        db.session.commit()
        _imp_ids["importedsudo"] = _imp_second.id

    # The background step itself, run synchronously (no worker outlives these stubs), against
    # every answer it can get: monitor present, absent, a failed command-list read, a failed
    # crontab write, and a server that was not asked for.
    from panel.routes import _shared as _as_shared
    import types as _as_types  # pylint: disable=reimported
    NSx = _as_types.SimpleNamespace
    _as_saved = (_as_shared._sm, _as_shared.threading)
    _as_writes = []
    _as_cmds = {"importedplain": [{"cmd": "start"}, {"cmd": "monitor"}],
                "importedsudo": [{"cmd": "monitor"}]}

    def _as_set(_r, user, enabled, selfname=None):
        _as_writes.append((user, enabled, selfname))
        return (user != "failwrite", "crontab refused" if user == "failwrite" else "")
    try:
        _as_shared.threading = NSx(Thread=lambda target, daemon=None: NSx(start=target))
        _as_shared._sm = NSx(list_server_commands=lambda _r, u, _n: _as_cmds.get(u, []),
                            set_autostart=_as_set)
        _as_shared._bg_cache_commands(app, list(_imp_ids.values()),
                                      autostart_ids=[_imp_ids["importedplain"]])
        with app.app_context():
            _as_after = {g.short_name: g.autostart for g in GameServer.query.filter(
                GameServer.id.in_(list(_imp_ids.values()))).all()}
        check("import: the background step writes monitor for the asked-for server and records it",
              _as_writes == [("importedplain", True, "csgoserver")]
              and _as_after == {"importedplain": True, "importedsudo": False},
              "writes=%s after=%s" % (_as_writes, _as_after))
        # A game without monitor, a command list that could not be read, and a write that failed
        # all leave Autostart off, and only the failed write was attempted.
        _as_writes.clear()
        with app.app_context():
            for _sn in ("importedplain", "importedsudo"):
                db.session.get(GameServer, _imp_ids[_sn]).autostart = False
            db.session.commit()
        _as_cmds = {"importedplain": [{"cmd": "start"}], "importedsudo": []}
        _as_shared._sm = NSx(list_server_commands=lambda _r, u, _n: _as_cmds.get(u, []),
                            set_autostart=_as_set)
        _as_shared._bg_cache_commands(app, list(_imp_ids.values()),
                                      autostart_ids=list(_imp_ids.values()))
        check("import: ...a game without monitor, or an unread command list, gets no cron line",
              _as_writes == [], str(_as_writes))
        with app.app_context():
            _as_fw = db.session.get(GameServer, _imp_ids["importedplain"])
            _as_fw.short_name = "failwrite"
            db.session.commit()
        _as_cmds = {"failwrite": [{"cmd": "monitor"}]}
        _as_shared._bg_cache_commands(app, [_imp_ids["importedplain"]],
                                      autostart_ids=[_imp_ids["importedplain"]])
        with app.app_context():
            _as_fw_flag = db.session.get(GameServer, _imp_ids["importedplain"]).autostart
            db.session.get(GameServer, _imp_ids["importedplain"]).short_name = "importedplain"
            db.session.commit()
        check("import: ...and a crontab write that fails leaves the flag off",
              _as_writes == [("failwrite", True, "csgoserver")] and _as_fw_flag is False,
              "writes=%s flag=%s" % (_as_writes, _as_fw_flag))
    finally:
        _as_shared._sm, _as_shared.threading = _as_saved
    with app.app_context():
        GameServer.query.filter(GameServer.remote_id == remote_id, GameServer.short_name.in_(
            ["importedplain", "importedsudo"])).delete(synchronize_session=False)
        db.session.commit()
finally:
    _imp_mod.discover_linuxgsm_servers = _imp_orig
    _imp_mod.privileged_accounts = _imp_priv_orig
    _sm_hosts.protected_host_ports = _imp_prot_orig
imp_denied = client_as(mru_id).post("/api/remote/%d/import" % remote_id,
                                    json={"servers": [{"user": "x", "game_type": "csgo"}]})
check("import: caller without manage_servers is denied",
      imp_denied.status_code in (301, 302, 303, 403), "got %d" % imp_denied.status_code)

# ── A host's servers are keyed on the Linux user, so one account can only ever be one server.
# Seven games under one account (what a GMod content box looks like) used to import the first
# and silently drop six as duplicates — a panel row for whichever game happened to sort first.
imp_multi = c.post("/api/remote/%d/import" % remote_id, json={"servers": [
    {"user": "srcds", "game_type": "css", "port": 27015},
    {"user": "srcds", "game_type": "tf2", "port": 27015},
    {"user": "srcds", "game_type": "dods", "port": 27015}]})
_imm = imp_multi.get_json() or {}
check("import: one account claiming several games is refused outright, not partly applied",
      _imm.get("added") == [] and len(_imm.get("skipped") or []) == 3, str(_imm)[:140])
with app.app_context():
    _srcds_rows = GameServer.query.filter_by(remote_id=remote_id, short_name="srcds").count()
check("import: ...and no arbitrary winner was written to the database", _srcds_rows == 0,
      "rows=%d" % _srcds_rows)

# ── GMod content is filtered out of discovery ──
# Each mountable game is installed through LinuxGSM, so the host scan cannot tell it from a
# server. The panel can: content_box_users classifies by shape, and the endpoint reports what
# it left out instead of listing one account once per game.
# discover.py binds discover_linuxgsm_servers by name at import, so the stub goes on THAT
# module — it follows the handler, not the name (same rule as remote_security below).
from panel.routes import discover as _disc_mod  # pylint: disable=reimported
_orig_disc = _disc_mod.discover_linuxgsm_servers
# ...and an account the panel ALREADY has a row for on this host, which is not offered again.
# Dropping that skip (in _discovered_listing since api_remote_discover was split) left every
# suite green, and relisted an imported server as new; importing it is refused, not deduped.
with app.app_context():
    _dsc_have = [g.short_name for g in GameServer.query.filter_by(remote_id=remote_id).all()]
try:
    def _fake_disc(_server):
        rows = [{"user": "contentbox", "lgsm_name": n, "port": 27015, "backups": 0,
                 "mods": 0, "cron": 14, "autostart": False}
                for n in ("cssserver", "tf2server", "dodsserver", "l4d2server")]
        rows.append({"user": "realgmod", "lgsm_name": "gmodserver", "port": 27015,
                     "backups": 1, "mods": 0, "cron": 2, "autostart": True})
        rows += [{"user": _u, "lgsm_name": "gmodserver", "port": 27016, "backups": 0,
                  "mods": 0, "cron": 1, "autostart": False} for _u in _dsc_have[:1]]
        return rows
    _disc_mod.discover_linuxgsm_servers = _fake_disc
    _d2 = (c.get("/api/remote/%d/discover" % remote_id).get_json() or {})
    _users = [x["user"] for x in (_d2.get("servers") or [])]
    check("discover: a content box is not offered as importable servers",
          "contentbox" not in _users, "users=%s" % _users)
    check("discover: ...while a real server on the same host still is",
          _users == ["realgmod"], "users=%s" % _users)
    check("discover: an account the panel already has a row for is not offered again",
          bool(_dsc_have) and _dsc_have[0] not in _users,
          "have=%s users=%s" % (_dsc_have[:1], _users))
    _content = _d2.get("content") or []
    check("discover: ...and the content it skipped is reported, not silently dropped",
          len(_content) == 1 and _content[0]["user"] == "contentbox"
          and len(_content[0]["games"]) == 4, str(_content)[:160])
finally:
    _disc_mod.discover_linuxgsm_servers = _orig_disc

# ── A host the panel could not scan must not be reported as "nothing found" ───────────────
# discover_linuxgsm_servers is best-effort and returns [] for BOTH "scanned, nothing new" and
# "the scan never ran" — its own except branch swallows everything, and the tailscale and local
# transports do not raise at all, they answer ("", "SSH command timed out", -1). The route then
# returned {"servers": [], "content": []}, byte-for-byte what a healthy empty host looks like,
# and remote_manage_backups.js rendered a green tick and "No new LinuxGSM servers found" about
# a directory listing that never happened. An admin reads that and stops looking.
_orig_disc2 = _disc_mod.discover_linuxgsm_servers
_orig_disc_rc2 = _disc_mod.run_command
try:
    _disc_mod.discover_linuxgsm_servers = lambda _s: []
    # The transport answer for a host that is powered off / whose tailnet route is down.
    _disc_mod.run_command = lambda *a, **k: ("", "SSH command timed out", -1)
    _du = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
    check("discover: a host the panel could not reach is reported as unread, not as empty",
          bool(_du.get("error")) and not _du.get("servers"),
          "the card shows a tick and 'No new LinuxGSM servers found': %s" % (str(_du)[:160],))
    # rc 0 but no token back is the same thing wearing a success code — the `not in` form of
    # this check is satisfied by "" as well, so the token has to be POSITIVE.
    _disc_mod.run_command = lambda *a, **k: ("", "", 0)
    _du0 = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
    check("discover: ...and an rc 0 with nothing echoed back is not an answer either",
          bool(_du0.get("error")), str(_du0)[:160])
    # The control: a host that DID answer and genuinely has nothing new still reports nothing
    # new, with no error — otherwise the two checks above would pass on a route that refuses
    # every scan.
    _disc_mod.run_command = lambda *a, **k: ("LGSM_SCAN_OK", "", 0)
    _dok = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
    check("discover: a host that answered with nothing new is still 'nothing new' (control)",
          not _dok.get("error") and _dok.get("servers") == [], str(_dok)[:160])
    # ...and a host with servers is never probed at all: the confirmation only runs when the
    # scan came back empty, so a working scan costs no extra round trip.
    _dprobed = []
    _disc_mod.run_command = lambda *a, **k: (_dprobed.append(1), ("", "", -1))[1]
    _disc_mod.discover_linuxgsm_servers = lambda _s: [
        {"user": "smokedisc", "lgsm_name": "gmodserver", "port": 27015,
         "backups": 1, "mods": 0, "cron": 2, "autostart": False}]
    _dfull = c.get("/api/remote/%d/discover" % remote_id).get_json() or {}
    check("discover: a scan that found something is not re-probed",
          not _dprobed and [x["user"] for x in (_dfull.get("servers") or [])] == ["smokedisc"],
          "probes=%s %s" % (_dprobed, str(_dfull)[:120]))
finally:
    _disc_mod.discover_linuxgsm_servers = _orig_disc2
    _disc_mod.run_command = _orig_disc_rc2

# ── Session management: per-device login sessions + individual revoke ──
from panel.db.models import UserSession


def _real_login(username="smoke_admin", pw="Str0ng!passw0rd"):
    cc = app.test_client()
    rr = cc.post("/login", data={"username": username, "password": pw}, follow_redirects=False)
    return cc, rr


s1, r1 = _real_login()
# The login cookie must be PERSISTENT (carry Expires/Max-Age). A bare session cookie dies with
# the browser process — and on Android the browser is killed constantly — which shows up as
# "it forgets my login every time", with a new server-side session row per re-login.
_login_cookies = {h.split("=", 1)[0]: h for h in r1.headers.getlist("Set-Cookie")}
_sess_cookie = _login_cookies.get("lgpanel_session", "")
check("session: the login cookie is persistent, not a browser-session cookie",
      "Expires=" in _sess_cookie or "Max-Age=" in _sess_cookie,
      "Set-Cookie: %s" % (_sess_cookie[:160] or "(none issued)"))
check("session: real login lands in (redirect away from /login)",
      r1.status_code in (301, 302, 303) and "/login" not in (r1.headers.get("Location") or ""),
      "status=%d loc=%s" % (r1.status_code, r1.headers.get("Location") or ""))
with app.app_context():
    n1 = UserSession.query.filter_by(user_id=admin_id).count()
check("session: login created a server-side session row", n1 >= 1, "rows=%d" % n1)

# One response envelope. These three routes used an `ok` key, which the universal
# `d.success === false` client guard cannot see — so account.html reported "Session revoked"
# even for a 404 "Session not found".
_rev404 = s1.post("/api/account/sessions/999999/revoke")
check("session: revoking a session that does not exist is a 404", _rev404.status_code == 404)
check("session: ...and says success=false in the standard envelope",
      (_rev404.get_json() or {}).get("success") is False
      and "ok" not in (_rev404.get_json() or {}),
      _rev404.get_data(as_text=True)[:120])
# POST, like the switcher in panel.js now sends. The PROFILE write is POST-only: csrf.protect()
# is a no-op on safe methods, so as a GET this was a stored state change any cross-site page
# could make with <img src=".../set-language/zh">.
_lang = s1.post("/set-language/es?ajax=1")
check("language: the ajax save answers in the standard envelope",
      (_lang.get_json() or {}).get("success") is True
      and "ok" not in (_lang.get_json() or {}),
      _lang.get_data(as_text=True)[:120])
with app.app_context():
    check("language: ...and a POST really writes the profile",
          (User.query.filter_by(username="smoke_admin").first().language or "") == "es",
          "language=%r" % (User.query.filter_by(username="smoke_admin").first().language,))
_lang_get = s1.get("/set-language/fr?ajax=1")
check("language: a GET still switches the session", _lang_get.status_code == 200,
      "status=%d" % _lang_get.status_code)
with app.app_context():
    check("language: ...but a GET does NOT write the profile — CSRF cannot cover a GET",
          (User.query.filter_by(username="smoke_admin").first().language or "") == "es",
          "a cross-site <img> would have made this stick: language=%r"
          % (User.query.filter_by(username="smoke_admin").first().language,))
s1.post("/set-language/en?ajax=1")   # put it back

j1 = (s1.get("/api/account/sessions").get_json() or {})
sess1 = j1.get("sessions", [])
check("session: API lists the current session, flagged current",
      any(s.get("current") for s in sess1), "n=%d" % len(sess1))

s2, _ = _real_login()   # a second device for the same account
all2 = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
check("session: a second login shows two sessions", len(all2) == 2, "n=%d" % len(all2))

other = next((s for s in all2 if not s.get("current")), None)
rv = s1.post("/api/account/sessions/%d/revoke" % other["id"]) if other else None
rvj = rv.get_json() if rv is not None else {}
check("session: revoke a non-current session succeeds",
      rv is not None and rv.status_code == 200 and rvj.get("success") is True
      and not rvj.get("current"), str(rvj)[:120])

acc2 = s2.get("/account", follow_redirects=False)
check("session: the revoked device is signed out (loader rejects its sid)",
      acc2.status_code in (301, 302, 303) and "/login" in (acc2.headers.get("Location") or ""),
      "status=%d" % acc2.status_code)
with app.app_context():
    n_after = UserSession.query.filter_by(user_id=admin_id).count()
    os_ = UserSession(user_id=mru_id, sid="smoke_other_sid", ip="", user_agent="")
    db.session.add(os_)
    db.session.commit()
    other_uid_sess = os_.id
check("session: revoked row is gone (one left)", n_after == 1, "rows=%d" % n_after)

xrv = s1.post("/api/account/sessions/%d/revoke" % other_uid_sess)
check("session: can't revoke another user's session (404)", xrv.status_code == 404,
      "status=%d" % xrv.status_code)

# ── "Sign out everywhere else" keeps the device that pressed it ──
# It used to bump the epoch and delete every row, including the caller's — so the one button
# meant to evict an intruder also evicted you, onto the login page, on the phone you were
# holding. The epoch bump stays (it is the only thing that kills a legacy no-sid cookie and
# every remember cookie); this device is re-admitted with a cookie carrying the new epoch.
s3, _ = _real_login()                 # a second device to be signed out
with app.app_context():
    epoch_before = db.session.get(User, admin_id).auth_epoch or 0
    n_before = UserSession.query.filter_by(user_id=admin_id).count()
check("session: two devices signed in before the sweep", n_before == 2, "rows=%d" % n_before)
# A pre-epoch cookie too: a bare "<id>", which auth._load_legacy_user used to accept on
# is_active alone — so it outlived this button, a password change and an admin's reset.
_bare = app.test_client()
with _bare.session_transaction() as _bs:
    _bs["_user_id"] = str(admin_id)
    _bs["_fresh"] = True
_bare_before = _bare.get("/api/auth/ping").status_code
_rev = s1.post("/account/sessions/revoke", follow_redirects=False)
with app.app_context():
    n_all = UserSession.query.filter_by(user_id=admin_id).count()
    epoch_after = db.session.get(User, admin_id).auth_epoch or 0
check("session: sign-out-everywhere-else bumps the epoch and leaves exactly one row",
      n_all == 1 and epoch_after > epoch_before,
      "rows=%d epoch %d->%d" % (n_all, epoch_before, epoch_after))
check("session: ...and lands back on the account page, not the login page",
      _rev.status_code in (301, 302, 303) and "/login" not in (_rev.headers.get("Location") or ""),
      "status=%d loc=%s" % (_rev.status_code, _rev.headers.get("Location") or ""))
_still_in = s1.get("/account", follow_redirects=False)
check("session: the device that pressed it is STILL signed in",
      _still_in.status_code == 200, "status=%d" % _still_in.status_code)
_kicked = s3.get("/account", follow_redirects=False)
check("session: the other device was signed out",
      _kicked.status_code in (301, 302, 303) and "/login" in (_kicked.headers.get("Location") or ""),
      "status=%d" % _kicked.status_code)
_bare_after = _bare.get("/api/auth/ping").status_code
check("session: a bare pre-epoch '<id>' cookie is signed out by it too (it used to survive "
      "every epoch bump)",
      _bare_after == 401 and (epoch_before != 0 or _bare_before == 200),
      "before %d, after %d (epoch was %d)" % (_bare_before, _bare_after, epoch_before))
# The admin's epoch just moved, so the suite's own admin client (client_as, "<id>:<epoch>")
# is one of the cookies it revoked. Re-issue it for everything below.
c = client_as(admin_id)
_sess_after = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
check("session: the survivor is listed, and flagged as this device",
      len(_sess_after) == 1 and _sess_after[0].get("current"), "n=%d" % len(_sess_after))

# ── An expired login is gone, not listed as active ──
# Rows used to be pruned only after 45 days of silence, so a session whose cookie died hours
# (or weeks) ago still sat on the account page labelled active, with a Revoke button that
# revoked something already gone. Age one row past the session-cookie window and it must
# vanish from the list — and its cookie must stop authenticating.
from panel.db.models import prune_expired_sessions as _prune
from datetime import timedelta as _td  # pylint: disable=reimported
from panel.core.clock import utcnow as _utcnow_s  # pylint: disable=reimported
s4, _ = _real_login()
_live = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
_stale = next((x for x in _live if not x.get("current")), None)
with app.app_context():
    _row = db.session.get(UserSession, _stale["id"]) if _stale else None
    if _row is not None:
        _row.remember = False
        # One second past PERMANENT_SESSION_LIFETIME + the last_seen write throttle.
        _life = app.config.get("PERMANENT_SESSION_LIFETIME", 8 * 3600)
        _life = _life.total_seconds() if hasattr(_life, "total_seconds") else float(_life)
        _row.last_seen = _utcnow_s() - _td(seconds=_life + 301)
        db.session.commit()
_listed = ((s1.get("/api/account/sessions").get_json() or {}).get("sessions", []))
check("session: an expired login is not listed as active",
      _stale is not None and all(x["id"] != _stale["id"] for x in _listed),
      "ids=%s expired=%s" % ([x["id"] for x in _listed], _stale and _stale["id"]))
with app.app_context():
    _gone = db.session.get(UserSession, _stale["id"]) if _stale else "n/a"
check("session: ...and its row is deleted, not merely hidden", _gone is None, repr(_gone))
_dead = s4.get("/account", follow_redirects=False)
check("session: ...and its cookie no longer authenticates",
      _dead.status_code in (301, 302, 303) and "/login" in (_dead.headers.get("Location") or ""),
      "status=%d" % _dead.status_code)
# The loader has to reject an expired session on its own, with no sweep having run first —
# otherwise the only thing stopping a captured "remember me" cookie (which carries no
# timestamp of any kind) is whether somebody happened to open the account page.
s5, _ = _real_login()
with app.app_context():
    _r5 = (UserSession.query.filter_by(user_id=admin_id)
           .order_by(UserSession.created_at.desc()).first())
    _r5.remember = False
    _r5.last_seen = _utcnow_s() - _td(seconds=_life + 301)
    _r5_id = _r5.id
    db.session.commit()
_dead5 = s5.get("/account", follow_redirects=False)
check("session: the loader rejects an expired cookie without waiting for a sweep",
      _dead5.status_code in (301, 302, 303) and "/login" in (_dead5.headers.get("Location") or ""),
      "status=%d" % _dead5.status_code)
with app.app_context():
    check("session: ...and drops the row on the way past",
          db.session.get(UserSession, _r5_id) is None)
# A "remember me" login gets the longer window, not the session-cookie one — otherwise every
# remembered login would be swept an hour into a three-day life.
with app.app_context():
    _r = UserSession(user_id=admin_id, sid="smoke_rem_sid", remember=True,
                     last_seen=_utcnow_s() - _td(seconds=_life + 301))
    db.session.add(_r)
    db.session.commit()
    _rid = _r.id
    _swept = _prune(admin_id)
    _survives = db.session.get(UserSession, _rid) is not None
check("session: a remembered login is not swept on the session-cookie clock",
      _survives, "swept=%d" % _swept)
with app.app_context():
    _rem = db.session.get(UserSession, _rid)
    _rem.last_seen = _utcnow_s() - _td(days=400)
    db.session.commit()
    _prune(admin_id)
    _rem_gone = db.session.get(UserSession, _rid) is None
check("session: ...but it is swept once the remember window is past too", _rem_gone)

# ── An expired cookie must bounce an in-page call, not hand it the login page ──
# This is what made a stale tab throw on every click: @login_required answered the fetch with
# a 302 to /login, fetch followed it, and the caller got 200 text/html where it expected JSON.
_anon = app.test_client()
_nav = _anon.get("/account", follow_redirects=False)
check("auth: a browser navigation still redirects to the login page",
      _nav.status_code in (301, 302, 303) and "/login" in (_nav.headers.get("Location") or ""),
      "status=%d" % _nav.status_code)
check("auth: ...carrying where to come back to",
      "next=" in (_nav.headers.get("Location") or ""), _nav.headers.get("Location") or "")
_xhr = _anon.get("/api/account/sessions", headers={"X-Requested-With": "XMLHttpRequest"})
check("auth: an in-page fetch gets a 401, not the login page",
      _xhr.status_code == 401 and _xhr.headers.get("X-Auth-Required") == "1",
      "status=%d ct=%s" % (_xhr.status_code, _xhr.headers.get("Content-Type")))
check("auth: ...in the standard JSON envelope the client already understands",
      (_xhr.get_json() or {}).get("success") is False
      and (_xhr.get_json() or {}).get("error") == "auth_required",
      _xhr.get_data(as_text=True)[:120])

# ── "strong" session protection must actually bind the cookie to its client ──────────────
# flask-login only acts on "strong" for a NON-permanent session, and every panel login is
# permanent, so a copied cookie replayed from another IP and browser stayed signed in while
# the settings page promised a re-check on an IP or device change. Driven through the real
# /login with protection switched to strong for this block (the suite runs with it off).
_sp_saved = app.config.get("SESSION_PROTECTION")
app.config["SESSION_PROTECTION"] = "strong"
try:
    _sp = app.test_client()
    _sp_ua = {"User-Agent": "SmokeBrowser/1.0", "X-Requested-With": "XMLHttpRequest"}
    _sp.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"},
             headers=_sp_ua)
    _sp_ok = _sp.get("/api/account/sessions", headers=_sp_ua).status_code
    _sp_other_ua = _sp.get("/api/account/sessions",
                           headers=dict(_sp_ua, **{"User-Agent": "Stolen/9.9"})).status_code
    _sp_other_ip = _sp.get("/api/account/sessions", headers=_sp_ua,
                           environ_overrides={"REMOTE_ADDR": "203.0.113.77"}).status_code
    _sp_back = _sp.get("/api/account/sessions", headers=_sp_ua).status_code
    check("session protection: the signed-in client keeps its session (control)",
          _sp_ok == 200 and _sp_back == 200, "first %s, after replays %s" % (_sp_ok, _sp_back))
    check("session protection: strong refuses the cookie from another browser",
          _sp_other_ua == 401, "got %s" % _sp_other_ua)
    check("session protection: strong refuses the cookie from another address",
          _sp_other_ip == 401, "got %s" % _sp_other_ip)
    app.config["SESSION_PROTECTION"] = "basic"
    _sp_basic = _sp.get("/api/account/sessions",
                        headers=dict(_sp_ua, **{"User-Agent": "Stolen/9.9"})).status_code
    check("session protection: basic does not bind (the mode really is what decides)",
          _sp_basic == 200, "got %s" % _sp_basic)
    _sp.get("/logout", headers=_sp_ua)
    # IPv6: bound to the /64, as the login throttle counts it. A temporary ("privacy") address
    # rotates inside it about daily and each new connection takes the newest, so an exact
    # address signed every IPv6 user out whenever theirs rotated.
    app.config["SESSION_PROTECTION"] = "strong"
    _sp6 = app.test_client()
    _sp6.post("/login", data={"username": "smoke_admin", "password": "Str0ng!passw0rd"},
              headers=_sp_ua, environ_overrides={"REMOTE_ADDR": "2001:db8:1:2::10"})
    _sp6_same = _sp6.get("/api/account/sessions", headers=_sp_ua,
                         environ_overrides={"REMOTE_ADDR": "2001:db8:1:2::10"}).status_code
    _sp6_rot = _sp6.get("/api/account/sessions", headers=_sp_ua,
                        environ_overrides={"REMOTE_ADDR": "2001:db8:1:2:a1b2:c3d4:e5f6:7"}
                        ).status_code
    _sp6_away = _sp6.get("/api/account/sessions", headers=_sp_ua,
                         environ_overrides={"REMOTE_ADDR": "2001:db8:1:3::10"}).status_code
    check("session protection: an IPv6 client keeps its session when its temporary address "
          "rotates inside the /64", _sp6_same == 200 and _sp6_rot == 200,
          "same address %s, rotated address %s" % (_sp6_same, _sp6_rot))
    check("session protection: ...and strong still refuses it from another /64 (control)",
          _sp6_away == 401, "got %s" % _sp6_away)
    _sp6.get("/logout", headers=_sp_ua, environ_overrides={"REMOTE_ADDR": "2001:db8:1:2::10"})
finally:
    app.config["SESSION_PROTECTION"] = _sp_saved
_ping = s1.get("/api/auth/ping")
check("auth: the wake-up ping confirms a live session",
      _ping.status_code == 200 and (_ping.get_json() or {}).get("success") is True,
      "status=%d" % _ping.status_code)
_ping_anon = _anon.get("/api/auth/ping")
check("auth: ...and answers a dead one with the flagged 401",
      _ping_anon.status_code == 401 and _ping_anon.headers.get("X-Auth-Required") == "1",
      "status=%d" % _ping_anon.status_code)
_page = s1.get("/account")
check("auth: a signed-in page is never served from the browser cache unrevalidated",
      "no-cache" in (_page.headers.get("Cache-Control") or ""),
      "Cache-Control: %s" % (_page.headers.get("Cache-Control") or "(none)"))

# A legacy cookie (client_as injects a _user_id with no sid, like a pre-feature login) is
# adopted on first list — so you never see an empty list while logged in.
lc = client_as(deleg_id)
lsess = ((lc.get("/api/account/sessions").get_json() or {}).get("sessions", []))
check("session: a legacy (no-sid) login is adopted and shown as current",
      len(lsess) == 1 and lsess[0].get("current"), "n=%d" % len(lsess))
with app.app_context():
    n_leg = UserSession.query.filter_by(user_id=deleg_id).count()
check("session: adoption created a row for the legacy login", n_leg == 1, "rows=%d" % n_leg)
with app.app_context():
    _leg_rem = UserSession.query.filter_by(user_id=deleg_id).first().remember
check("session: a legacy login with no remember cookie is adopted on the SHORT window",
      _leg_rem is False or _leg_rem == 0, "remember=%r" % (_leg_rem,))

# …and one that IS still sending a remember cookie gets the long window. Guessing "plain" for
# it would delete the row — and sign the device out — hours into a three-day login. Presence of
# the cookie is the only signal available for a login issued before the column existed.
with app.app_context():
    UserSession.query.filter_by(user_id=deleg_id).delete()
    db.session.commit()
lc2 = client_as(deleg_id)
lc2.set_cookie(app.config.get("REMEMBER_COOKIE_NAME", "remember_token"), "anything-non-empty")
lc2.get("/api/account/sessions")
with app.app_context():
    _row2 = UserSession.query.filter_by(user_id=deleg_id).first()
check("session: a legacy login that still holds a remember cookie is adopted on the LONG window",
      _row2 is not None and bool(_row2.remember), "row=%r" % (_row2 and _row2.remember,))

# ── History endpoint: a player peak must survive down-sampling (not be decimated away) ──
from panel.db.models import MetricSample
from datetime import timedelta as _td  # pylint: disable=reimported
from panel.core.clock import utcnow as _utcnow  # pylint: disable=reimported
with app.app_context():
    _base = _utcnow() - _td(hours=6)
    # 500 samples so sstep = 500//240 = 2; players is 0 everywhere except a single spike of 5 at an
    # ODD index — which plain srows[::2] decimation skips. The max-over-window fix must keep it.
    db.session.add_all([
        MetricSample(server_id=gs_id, ts=_base + _td(seconds=i * 30),
                     cpu=1.0, ram_mb=100, players=(5 if i == 101 else 0))
        for i in range(500)])
    db.session.commit()
_hist = c.get("/api/server/%d/history?range=24h" % gs_id)
_pl = [p.get("players") for p in (_hist.get_json() or {}).get("server", [])]
_pmax = max([x for x in _pl if x is not None] or [0])
check("history: player peak survives down-sampling (max==5, not decimated to 0)",
      _hist.status_code == 200 and _pmax == 5, "status=%d max=%s" % (_hist.status_code, _pmax))
with app.app_context():
    MetricSample.query.filter_by(server_id=gs_id).delete()
    db.session.commit()


# What later parts import from this one (`from smoke.part03 import ...`). The parts are
# one suite, run in order by tests/smoke_test.py; listing these here says so to a reader,
# and to CodeQL, which does not follow those imports and reads the names as unused.
__all__ = [
    '_AL',
    '_real_login',
    '_TU',
    'c',
    'MetricSample',
]
