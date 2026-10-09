"""Part 6 of the smoke suite. Imported for its side effects: see tests/smoke_test.py.

Two markers here are about the split, not the checks. `# pylint: disable=reimported`: each section
imports what it uses under an alias of its own, as it did in the single-file suite, whose one try
hid those imports from Pylint's reimport rule. `# noqa: MC0001` (mccabe): a block whose branches
mccabe counted, until the split, as part of that one try, already reported as too complex.
"""
from smoke.part01 import (_lgsm_pathlib, _sm_core, _sm_game, app, auth, check, client_as,
                          CONFIG_FILE, CustomCommand, db, GameServer, Group, load_config,
                          RemoteServer, save_config, sys, User)
from smoke.part02 import (_appmod_ij, _cg_remote_id, _ijw_time, _install_seam_closed, admin_id,
                          encrypt_secret, gs_id, mru_id, remote_id)
from smoke.part03 import (_AL, _real_login)
from smoke.part04 import (_re_ab, _repo_root)
from smoke.part05 import (c)

# ── Deactivating an account must END its open sessions, and nothing asserted that it did.
# It does — but through a coupling nobody would find by reading the panel: this model is
# `User(UserMixin, db.Model)` with `is_active` as a Column, and UserMixin.is_authenticated is
# `return self.is_active`, so declaring the column also redefines is_authenticated and
# @login_required refuses the account. Declare an is_authenticated of your own, or drop
# UserMixin, and every open session of every deactivated account silently works again.
# These pin the BEHAVIOUR, so it survives whichever layer happens to provide it.
with app.app_context():
    _victim = User(username="deactivateme", is_active=True,
                   password_hash=auth.hash_password("Str0ng!passw0rd"))
    db.session.add(_victim)
    db.session.commit()
    _vid = _victim.id


# BOTH cookie shapes, because load_user has two branches and client_as() only exercises one.
# A bare "<id>" is the legacy cookie; a real login carries "<id>:<auth_epoch>", and that is the
# branch every current session actually takes — a gate that covers only the legacy form would
# pass with the modern branch wide open.
def _client_with_id(raw_id):
    _c = app.test_client()
    with _c.session_transaction() as _s:
        _s["_user_id"] = str(raw_id)
        _s["_fresh"] = True
    return _c


with app.app_context():
    _modern_id = db.session.get(User, _vid).get_id()
check("deactivation: the modern cookie form is <id>:<epoch>, not a bare id",
      ":" in _modern_id, _modern_id)
_vc_legacy, _vc_modern = _client_with_id(_vid), _client_with_id(_modern_id)
check("deactivation: the legacy-cookie session works while the account is active",
      _vc_legacy.get("/api/servers").status_code == 200)
check("deactivation: the epoch-cookie session works while the account is active",
      _vc_modern.get("/api/servers").status_code == 200)
with app.app_context():
    db.session.get(User, _vid).is_active = False
    db.session.commit()
_after_l = _vc_legacy.get("/api/servers").status_code
_after_m = _vc_modern.get("/api/servers").status_code
check("deactivation: the legacy-cookie session stops working once deactivated",
      _after_l != 200, "status=%s" % _after_l)
check("deactivation: the epoch-cookie session stops working once deactivated",
      _after_m != 200, "status=%s" % _after_m)

# ── two more "reported success without reading the result" ────────────────────────────────
# Both stubbed at the seam that actually fails on this codebase: run_command returns
# ("", "...timed out", -1) rather than raising, which is why neither route's except branch
# ever saw these.
from panel.ops.ssh_manager import _core as _sw_core

_sw_saved = {}


def _sw_stub(mod, name, fn):
    _sw_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


try:
    # 1. upload-check answered "we looked, nothing conflicts" from a listing that never ran.
    #    stat_upload_targets discarded rc, so out="" meant no matches, and the route reported
    #    checked=true. The browser then uploads without asking, and the upload route's own
    #    re-check is the only thing left between that and a clobbered file.
    _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "ssh: connect to host ... timed out", -1))
    _uc = c.post("/api/server/%d/upload-check" % gs_id,
                 json={"path": "", "names": ["server.cfg"]},
                 headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    check("upload-check: a listing that never ran is not reported as 'no conflicts'",
          _uc.get("checked") is False,
          "answered checked=%r existing=%r — the browser reads that as a clear and uploads "
          "without asking" % (_uc.get("checked"), _uc.get("existing")))
    # ...and a listing that DID run still reports checked=true, so the guard is not "always
    # say we could not look".
    _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "", 0))
    _uc2 = c.post("/api/server/%d/upload-check" % gs_id,
                  json={"path": "", "names": ["server.cfg"]},
                  headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    check("upload-check: ...while a real listing still answers checked=true",
          _uc2.get("checked") is True, "%r" % (_uc2,))

    # 2. "Run now" on a scheduled task reported "Started" from a launch that never happened.
    #    The job is detached, so the rc says nothing about how the job ENDS — but it does say
    #    whether it began, and that was discarded.
    _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "sudo: a password is required", 1))
    _cr = c.post("/api/server/%d/cron/run" % gs_id, json={"raw": "0 5 * * * /home/x/x update"},
                 headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    check("cron run-now: a launch that failed is not reported as 'Started'",
          _cr.get("success") is False,
          "answered %r — Last run never changes, and the audit row says it succeeded"
          % (_cr.get("message"),))
    _sw_stub(_sw_core, "run_command", lambda *a, **k: ("", "", 0))
    _cr2 = c.post("/api/server/%d/cron/run" % gs_id, json={"raw": "0 5 * * * /home/x/x update"},
                  headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    check("cron run-now: ...while a launch that started still says so",
          _cr2.get("success") is True, "%r" % (_cr2,))
finally:
    for (_m, _n), _v in _sw_saved.items():
        setattr(_m, _n, _v)

# ── "the mounts could not be read" is not "this server mounts nothing" ────────────────────
# gmod_current_mounts has three answers and its docstring calls the third the whole point:
# a list, [] for "mounts nothing", and None for "could not be read". The status route did
# `or []`, so a failed read painted every checkbox unticked — and Apply rewrites mount.cfg to
# exactly the visible ticks, so applying that card unmounts everything the server had. The
# uninstall worker in the same file already guards the identical call for the identical
# reason.
# Stubbed on the ROUTE module: server_files.py imports these BY NAME, so a stub on the
# ssh_manager submodule is never seen. detect_content_user and path_disk_free are stubbed too
# — they SSH, and against this suite's unreachable host they raise, which sends the whole
# handler into its `except` and returns {"error": ...}. That is what the first version of
# this test actually measured.
import panel.routes.server_files as _gm_mod

_gm_saved = (_gm_mod.gmod_current_mounts, _gm_mod.detect_content_user, _gm_mod.path_disk_free)
try:
    _gm_mod.detect_content_user = lambda *a, **k: {"user": "gmodcontent", "present": {}}
    _gm_mod.path_disk_free = lambda *a, **k: (10 * 1024 ** 3, 50 * 1024 ** 3)
    with app.app_context():
        _gm_gs = db.session.get(GameServer, gs_id)
        _gm_type_before = _gm_gs.game_type
        _gm_gs.game_type = "gmod"
        db.session.commit()

    _gm_mod.gmod_current_mounts = lambda *a, **k: None       # the host did not answer
    _gm_get = c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}
    check("gmod mounts: an unreadable mount state is reported as unreadable",
          _gm_get.get("mounts_readable") is False,
          "answered %r — the card renders every box unticked, i.e. 'mounts nothing'"
          % (_gm_get.get("mounts_readable"),))
    _gm_post = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": []},
                      headers={"X-Requested-With": "XMLHttpRequest"})
    check("gmod mounts: ...and applying a selection against it is REFUSED",
          (_gm_post.get_json() or {}).get("success") is False,
          "the panel rewrote mount.cfg from a state it could not read — an empty selection "
          "unmounts everything the server had")

    # The control: a readable state still reports and still applies.
    _gm_mod.gmod_current_mounts = lambda *a, **k: ["cstrike"]
    _gm_get2 = c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}
    check("gmod mounts: a readable state says so", _gm_get2.get("mounts_readable") is True,
          "%r" % (_gm_get2.get("mounts_readable"),))
    # From here the background APPLY worker's own dependencies are stubbed too. An apply spawns
    # a thread, and left real it would SSH at this suite's unreachable host for a minute and
    # land its write in the middle of a later check.
    import time as _gm_time
    _gm_state = _gm_mod._gmod_content_apply_state
    _gm_saved2 = (_gm_mod.ensure_content_user, _gm_mod.install_gmod_content,
                  _gm_mod.gmod_mount_setup)
    _gm_mounted = []

    def _gm_mount_spy(_remote, _gmod_user, _content_user, _games):
        _gm_mounted.append(list(_games))
        return True, "Mounted: %s — restart the server to apply" % (", ".join(_games) or "(none)")

    def _gm_settle(_timeout=20):
        _dl2 = _gm_time.time() + _timeout
        while (_gm_time.time() < _dl2
               and (_gm_state.get(gs_id) or {}).get("status") == "running"):
            _gm_time.sleep(0.02)
        return dict(_gm_state.get(gs_id) or {})

    try:
        _gm_mod.ensure_content_user = lambda *a, **k: {"user": "gmodcontent",
                                                       "group": "gmodcontent", "present": {}}
        _gm_mod.gmod_mount_setup = _gm_mount_spy
        # SteamCMD ran and put nothing on disk — the out-of-free-disk case that this card's
        # own "Host disk" readout exists to warn about. ok=True, installed=[].
        _gm_mod.install_gmod_content = lambda *a, **k: (True, [], "already present")
        _gm_state.pop(gs_id, None)
        _gm_post2 = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                           headers={"X-Requested-With": "XMLHttpRequest"})
        check("gmod mounts: ...and an apply against it still goes through",
              (_gm_post2.get_json() or {}).get("success") is True,
              "the control failed — the refusal above proves nothing")

        # ── content that never downloaded must not be reported as mounted ───────────────
        # install_gmod_content returns (ok, installed, msg), where `installed` is the games it
        # re-verified are on disk AFTERWARDS. The worker discarded it and wrote the mount for
        # everything the operator ticked, then stored "Mounted: Counter-Strike: Source —
        # restart the server to apply" as the job result. mount.cfg pointed at a directory
        # that is not there, and the operator restarted as instructed into purple ERROR
        # textures on every map. The uninstall worker below it already reports what it
        # actually removed rather than what was asked.
        _gm_res = _gm_settle()
        check("gmod content: a game whose content did not install is NOT mounted",
              bool(_gm_mounted) and "cstrike" not in _gm_mounted[-1],
              "mount.cfg was written for %r — a mount pointing at content that is not on the "
              "host" % (_gm_mounted,))
        check("gmod content: ...and the job says that, instead of reporting a mount",
              _gm_res.get("status") == "error"
              and "Counter-Strike" in (_gm_res.get("msg") or ""),
              "job=%r" % (_gm_res,))

        # The control: content that IS on the host is mounted, and the job reports done — or
        # the checks above would pass on a card that simply refuses every apply.
        _gm_mod.install_gmod_content = lambda *a, **k: (True, ["cstrike"], "installed: cstrike")
        _gm_mounted[:] = []
        _gm_state.pop(gs_id, None)
        c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
               headers={"X-Requested-With": "XMLHttpRequest"})
        _gm_res2 = _gm_settle()
        check("gmod content: (control) content that DID install is mounted and reported done",
              _gm_mounted and _gm_mounted[-1] == ["cstrike"]
              and _gm_res2.get("status") == "done",
              "mounted=%r job=%r" % (_gm_mounted, _gm_res2))

        # ── every terminal result reaches the card that polls for it ────────────────────
        # The status GET filtered to status == "running", so a job that ended in error — "No
        # content storage could be prepared on the host.", "Content setup failed — check the
        # server logs.", gmod_mount_setup's "Couldn't read <user>'s group, so the content
        # mount was not granted" — was indistinguishable from no job at all: the spinner
        # vanished, the card said nothing, and the operator restarted the server into ERROR
        # textures. Every failure mode of a job that can run for two hours behaved this way.
        _gm_state[gs_id] = {"status": "error", "ts": _gm_time.time(),
                            "msg": "No content storage could be prepared on the host."}
        _gm_j = (c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}).get("job") or {}
        check("gmod content: a job that ended in error reaches the card that polls for it",
              _gm_j.get("status") == "error" and "content storage" in (_gm_j.get("msg") or ""),
              "job=%r — the failure was recorded and then filtered out of the only endpoint "
              "that reports it" % (_gm_j,))
        _gm_state[gs_id] = {"status": "running", "msg": "", "ts": _gm_time.time()}
        _gm_jr = (c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}).get("job") or {}
        check("gmod content: (control) a running job is still reported",
              _gm_jr.get("status") == "running", "job=%r" % (_gm_jr,))
        # ...and a long-finished one expires rather than greeting every later page load, the
        # way remote_bootstrap's job poll expires its done/failed card.
        _gm_state[gs_id] = {"status": "error", "msg": "an old failure",
                            "ts": _gm_time.time() - (_gm_mod._GMOD_JOB_TTL + 60)}
        _gm_je = (c.get("/api/server/%d/gmod-content" % gs_id).get_json() or {}).get("job")
        check("gmod content: ...and a long-finished one expires instead of reappearing",
              _gm_je is None and gs_id not in _gm_state,
              "job=%r — a month-old error greets every later visit to this server"
              % (_gm_je,))

        # ── one content job per HOST ─────────────────────────────────────────────────────
        # Content is host-wide (one content user, one ~/serverfiles), but nothing stopped a
        # second job on the same host while the first ran: two SteamCMD installs into one
        # directory, or an uninstall deleting what another server's job was mounting. The
        # first job is held mid-install here, so the second request really does overlap it.
        import threading as _gm_thr
        _gm_gate = _gm_thr.Event()

        def _gm_slow_install(*a, **k):
            _gm_gate.wait(20)
            return (True, ["cstrike"], "installed: cstrike")
        _gm_mod.install_gmod_content = _gm_slow_install
        _gm_state.pop(gs_id, None)
        _gm_first = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                           headers={"X-Requested-With": "XMLHttpRequest"})
        _gm_second = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                            headers={"X-Requested-With": "XMLHttpRequest"})
        _gm_third = c.post("/api/server/%d/gmod-content" % gs_id,
                           json={"action": "uninstall", "games": ["cstrike"]},
                           headers={"X-Requested-With": "XMLHttpRequest"})
        _gm_gate.set()
        _gm_after = _gm_settle()
        check("gmod content: a second apply on the same host while one runs is refused (409)",
              (_gm_first.get_json() or {}).get("success") is True
              and _gm_second.status_code == 409
              and "already running" in ((_gm_second.get_json() or {}).get("message") or ""),
              "first %r, second %d %r" % (_gm_first.get_json(), _gm_second.status_code,
                                          _gm_second.get_json()))
        check("gmod content: ...and so is an uninstall on that host",
              _gm_third.status_code == 409, "got %d %r" % (_gm_third.status_code, _gm_third.get_json()))
        check("gmod content: ...and the first job still finished on its own",
              _gm_after.get("status") == "done", "job=%r" % (_gm_after,))
        # Positive control: the host is free again the moment the job reports done.
        _gm_mod.install_gmod_content = lambda *a, **k: (True, ["cstrike"], "installed: cstrike")
        _gm_again = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": ["cstrike"]},
                           headers={"X-Requested-With": "XMLHttpRequest"})
        _gm_settle()
        check("gmod content: (control) once it finishes, the next job on that host is accepted",
              (_gm_again.get_json() or {}).get("success") is True,
              "got %d %r — the host stayed held" % (_gm_again.status_code, _gm_again.get_json()))

        # ── content is the HOST's: a one-server admin may mount what is there, no more ────
        # Uninstalling content removes it for every GMod server on the host (every tenant's),
        # and fetching new content fills the host's disk; the route asked for MANAGE_SERVERS and
        # access to ONE server. A MANAGE_SERVERS admin granted this server alone, not its host.
        with app.app_context():
            _gmg = Group(name="smoke-gmod-one")
            _gmg.set_permissions([auth.VIEW_SERVERS, auth.MANAGE_SERVERS])
            _gmg.game_servers.append(db.session.get(GameServer, gs_id))
            db.session.add(_gmg)
            db.session.flush()
            _gmu = User(username="gmodone", password_hash=auth.hash_password("Str0ng!passw0rd"),
                        is_superadmin=False, is_active=True)
            _gmu.groups.append(_gmg)
            db.session.add(_gmu)
            db.session.commit()
            _gmu_id = _gmu.id
        _gm_one = client_as(_gmu_id)
        _gm_calls = []
        _gm_mod.install_gmod_content = lambda *a, **k: (_gm_calls.append("install"),
                                                        (True, ["cstrike"], "x"))[1]
        _gm_saved_un = _gm_mod.uninstall_gmod_content
        _gm_mod.uninstall_gmod_content = lambda *a, **k: (_gm_calls.append("uninstall"),
                                                          (True, ["cstrike"], "x"))[1]
        try:
            _gm_state.pop(gs_id, None)
            _gm_u = _gm_one.post("/api/server/%d/gmod-content" % gs_id,
                                 json={"action": "uninstall", "games": ["cstrike"]},
                                 headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_mod.detect_content_user = lambda *a, **k: {"user": "gmodcontent", "present": {}}
            _gm_d = _gm_one.post("/api/server/%d/gmod-content" % gs_id,
                                 json={"games": ["cstrike"]},
                                 headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_refused_calls = list(_gm_calls)   # before the control's worker runs
            _gm_mod.detect_content_user = lambda *a, **k: {"user": "gmodcontent",
                                                           "present": {"cstrike": 1}}
            _gm_m = _gm_one.post("/api/server/%d/gmod-content" % gs_id,
                                 json={"games": ["cstrike"]},
                                 headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_settle()
            _gm_bad = c.post("/api/server/%d/gmod-content" % gs_id,
                             json={"action": "unmount", "games": ["cstrike"]},
                             headers={"X-Requested-With": "XMLHttpRequest"})
            _gm_bad2 = c.post("/api/server/%d/gmod-content" % gs_id, json={"games": 5},
                              headers={"X-Requested-With": "XMLHttpRequest"})
        finally:
            _gm_mod.uninstall_gmod_content = _gm_saved_un
            _gm_mod.detect_content_user = lambda *a, **k: {"user": "gmodcontent", "present": {}}
        check("gmod content: a one-server admin cannot uninstall the host's shared content",
              _gm_u.status_code == 403 and "uninstall" not in _gm_refused_calls,
              "got %d %r calls=%r" % (_gm_u.status_code, _gm_u.get_json(), _gm_refused_calls))
        check("gmod content: ...nor download content the host does not have yet",
              _gm_d.status_code == 403 and "install" not in _gm_refused_calls,
              "got %d %r calls=%r" % (_gm_d.status_code, _gm_d.get_json(), _gm_refused_calls))
        check("gmod content: ...but may still mount content already on the host (control)",
              (_gm_m.get_json() or {}).get("success") is True,
              "got %d %r" % (_gm_m.status_code, _gm_m.get_json()))
        check("gmod content: an unknown action is a 400, not a silent mount",
              _gm_bad.status_code == 400, "got %d" % _gm_bad.status_code)
        check("gmod content: games that are not a list is a 400, not a 500",
              _gm_bad2.status_code == 400, "got %d" % _gm_bad2.status_code)
    finally:
        (_gm_mod.ensure_content_user, _gm_mod.install_gmod_content,
         _gm_mod.gmod_mount_setup) = _gm_saved2
        _gm_settle()
        _gm_state.pop(gs_id, None)
finally:
    (_gm_mod.gmod_current_mounts, _gm_mod.detect_content_user,
     _gm_mod.path_disk_free) = _gm_saved
    with app.app_context():
        db.session.get(GameServer, gs_id).game_type = _gm_type_before
        db.session.commit()

# ── a game LinuxGSM caps BELOW this host's release must be refused up front ───────────────
# The picker marks these against the newest OS in the CATALOGUE — a stand-in, because the list
# renders before a host is chosen. At install time the host IS chosen, so the comparison can
# be the real one: LinuxGSM caps btl and onset at 20.04 and bf1942/bfv at 22.04, and on a
# newer host those fail every time, minutes into the download, leaving a failed row behind.
# Reported from the panel: Battalion 1944 offered and accepted on a 24.04 host.
#
# The catalogue is STUBBED, not read: this suite seeds a minimal serverlist.csv with no capped
# game in it, so reading the real list would make every check below pass on an empty set. The
# first version of this test did exactly that and reported it.
import panel.routes.manage_servers as _os_mod
# The DEFINITION site, not the package: panel/ops/ssh_manager/__init__.py exposes these
# through __getattr__ so there is one stub target, and a unit check enforces that — it caught
# this exact line. See ssh-manager-stub-seam-scope.
from panel.ops.ssh_manager import hosts as _os_sm

_os_saved = _os_sm.host_os_slug
_os_before = _appmod_ij._remote_listening_ports
_os_real_list = _os_mod.load_game_list


def _os_try(name, port, game="btl"):
    """POST an install and say whether a row was created.

    Under the seam for the same reason the content-capture POST is: an accepted install starts
    a background worker, and the row is deleted below while it runs. Draining it here is what
    keeps its failure off the next row to be handed that id.
    """
    with _install_seam_closed("install-OS"):
        c.post("/servers/add", data={"remote_id": str(_cg_remote_id), "game_type": game,
                                     "server_name": name, "port": str(port)},
               follow_redirects=True)
    with app.app_context():
        _row = GameServer.query.filter_by(short_name=name).first()
        _made = _row is not None
        if _row is not None:
            db.session.delete(_row)
            db.session.commit()
    return _made


_os_has = _os_mod.host_account_state
try:
    _appmod_ij._remote_listening_ports = lambda r: {22}
    _os_mod.host_account_state = lambda r, n: "absent"
    _os_mod.load_game_list = lambda: [
        {"shortname": "btl", "name": "BATTALION: Legacy", "os": "ubuntu-20.04",
         "legacy_os": "ubuntu-20.04"},
        {"shortname": "csgo", "name": "CS:GO", "os": "ubuntu-24.04", "legacy_os": ""},
    ]

    _os_sm.host_os_slug = lambda s: "ubuntu-24.04"
    check("install OS: a game capped at 20.04 is refused on a 24.04 host, before the download",
          not _os_try("osrefuse", 28850),
          "the install started and will fail minutes in, leaving a failed row to clean up")

    # The control, and the case the operator actually asked about: the SAME game on a host
    # that CAN run it. A 20.04 remote under a 24.04 panel must still install it.
    _os_sm.host_os_slug = lambda s: "ubuntu-20.04"
    check("install OS: ...while the same game on a 20.04 REMOTE is still allowed",
          _os_try("osallow", 28851),
          "the guard is refusing installs that would have worked — the panel's own OS is not "
          "the one that matters here")

    # Fails OPEN: an unreadable host OS is not evidence of a problem.
    _os_sm.host_os_slug = lambda s: None
    check("install OS: ...and a host whose OS could not be read is not refused",
          _os_try("osunknown", 28852),
          "this fails closed — an unreadable OS blocks an install that may be fine")

    # The host NEWER than the whole catalogue. Every game declares the newest release LinuxGSM
    # builds its dependency list for — 136 of 140 say ubuntu-24.04 — so a guard that compares
    # that column against the host refuses EVERYTHING on an Ubuntu 26.04 box. The first
    # version of this change did, and the 26.04 leg of CI caught it. Only the catalogue-
    # relative cap (legacy_os) may decide.
    _os_sm.host_os_slug = lambda s: "ubuntu-26.04"
    check("install OS: ...and an ordinary game is still installable on a host NEWER than the "
          "whole catalogue",
          _os_try("osnewhost", 28853, game="csgo"),
          "every game declares 24.04, so this refuses the entire catalogue on a 26.04 host")
    check("install OS: ...while a capped game on that same newer host is still refused",
          not _os_try("osnewcap", 28854),
          "the 20.04 cap is real whatever the host is, and a 26.04 box is further past it")
finally:
    _os_mod.load_game_list = _os_real_list
    _os_mod.host_account_state = _os_has
    _os_sm.host_os_slug = _os_saved
    _appmod_ij._remote_listening_ports = _os_before

# ── a ban the engine drops at the next map change is not a ban ────────────────────────────
# `banid ...; writeid` persists the id to cfg/banned_user.cfg, but the engine only reloads that
# file if the server config EXECS it — and ensure_persistent_bans is what appends that line.
# It ran on the install path and on the two GLOBAL-ban paths, whose docstring states the rule
# outright ("this is the one place that knows a ban is about to be applied to this server"),
# and not on the per-server moderate route. A server IMPORTED rather than installed through
# the panel never had the line, so every ban issued from the Players panel lasted until the
# map changed.
_ban_ensured, _ban_saved = [], {}
try:
    _bn_game = _sm_game
    _ban_saved["ensure"] = _bn_game.ensure_persistent_bans
    _ban_saved["moderate"] = _bn_game.moderate
    _bn_game.ensure_persistent_bans = lambda r, u, sn=None: _ban_ensured.append(u)
    _bn_game.moderate = (lambda r, u, gt, action, target="", message="", selfname=None,
                         steamid="", num=None: (True, "ok"))
    c.post("/api/server/%d/moderate" % gs_id,
           json={"action": "ban", "steamid": "STEAM_0:1:1234"},
           headers={"X-Requested-With": "XMLHttpRequest"})
    check("ban: the server is made to reload its ban list before the ban is issued",
          bool(_ban_ensured),
          "ensure_persistent_bans was never called, so on an imported server the engine "
          "drops this ban at the next map change")
    # ...and a NON-ban action must not pay for it — this runs an SSH round trip.
    _ban_ensured.clear()
    c.post("/api/server/%d/moderate" % gs_id,
           json={"action": "kick", "target": "someone"},
           headers={"X-Requested-With": "XMLHttpRequest"})
    check("ban: ...but a kick does not, since nothing is being persisted",
          not _ban_ensured, "called on a kick: %s" % (_ban_ensured,))
finally:
    _bn_game.ensure_persistent_bans = _ban_saved["ensure"]
    _bn_game.moderate = _ban_saved["moderate"]

# ── a ban "on all servers" must say which servers it did NOT reach ────────────────────────
# The fan-out counted only its successes: `applied = sum(1 for r in ex.map(...) if r)`, with
# _ban_other collapsing every other outcome to False — its `except Exception: return False`
# swallowed the ConnectionError a paramiko host raises, and _sm.moderate returns ok=False for a
# host reached over Tailscale or locally, because those transports return ("", "…", -1|255)
# instead of raising. `if applied:` then gated BOTH the audit row and the message, so a
# fan-out that reached nothing wrote no moderate_ban_all row at all and answered with the
# origin server's bare "Done.", while the origin's own row still said success=True. An
# operator reading either one believed the player was banned install-wide.
from panel.db.models import AuditLog as _fo_AL
_fo_saved, _fo_ids = {}, []
try:
    _fo_saved["ensure"] = _sm_game.ensure_persistent_bans
    _fo_saved["moderate"] = _sm_game.moderate
    _sm_game.ensure_persistent_bans = lambda r, u, sn=None: True
    with app.app_context():
        _fo_rid = db.session.get(GameServer, gs_id).remote_id
        for _n, _sn in (("smoke-fanout-a", "fanoutaserver"), ("smoke-fanout-b", "fanoutbserver")):
            _row = GameServer(remote_id=_fo_rid, name=_n, short_name=_sn, game_type="csgo",
                              port=27801 + len(_fo_ids), installed=True, status="offline")
            db.session.add(_row)
            db.session.commit()
            _fo_ids.append(_row.id)

    def _fo_moderate(r, u, gt, action, target="", message="", selfname=None, steamid="",
                     num=None):
        # The ORIGIN call succeeds; a named fan-out target is the unreachable host.
        return (u != _fo_dead["name"]), "ok"

    _fo_dead = {"name": "\0none"}      # nothing fails on the positive-control pass
    _sm_game.moderate = _fo_moderate
    with app.app_context():
        _fo_before = _fo_AL.query.filter_by(action="moderate_ban_all").count()
    _fo_ok = c.post("/api/server/%d/moderate" % gs_id,
                    json={"action": "ban", "steamid": "STEAM_0:1:770001", "scope": "all"},
                    headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    with app.app_context():
        _fo_row = _fo_AL.query.filter_by(action="moderate_ban_all").order_by(
            _fo_AL.id.desc()).first()
        _fo_after = _fo_AL.query.filter_by(action="moderate_ban_all").count()
    check("ban fan-out: an all-servers ban that reached every server logs success (control)",
          _fo_after == _fo_before + 1 and _fo_row is not None and _fo_row.success is True
          and "Also banned on" in (_fo_ok.get("message") or ""),
          "rows %d->%d row=%r msg=%r" % (_fo_before, _fo_after,
                                         getattr(_fo_row, "target", None),
                                         _fo_ok.get("message")))
    check("ban fan-out: ...and there were targets to fan out to, so this is not a vacuous pass",
          _fo_row is not None and not (_fo_row.target or "").startswith("0 of 0"),
          "target=%r — with no other valve server the checks below prove nothing"
          % (getattr(_fo_row, "target", None),))
    # Now one target is unreachable. That is the case the old code was silent about.
    _fo_dead["name"] = "fanoutbserver"
    with app.app_context():
        _fo_before = _fo_AL.query.filter_by(action="moderate_ban_all").count()
    _fo_bad = c.post("/api/server/%d/moderate" % gs_id,
                     json={"action": "ban", "steamid": "STEAM_0:1:770002", "scope": "all"},
                     headers={"X-Requested-With": "XMLHttpRequest"}).get_json() or {}
    with app.app_context():
        _fo_row2 = _fo_AL.query.filter_by(action="moderate_ban_all").order_by(
            _fo_AL.id.desc()).first()
        _fo_after = _fo_AL.query.filter_by(action="moderate_ban_all").count()
    check("ban fan-out: a server the ban did not reach is recorded, not dropped",
          _fo_after == _fo_before + 1 and _fo_row2 is not None
          and _fo_row2.success is False and "fanoutbserver" in (_fo_row2.detail or ""),
          "rows %d->%d success=%r detail=%r — the audit row used to be gated on `applied`, so "
          "a partial or total miss left nothing to read"
          % (_fo_before, _fo_after, getattr(_fo_row2, "success", None),
             getattr(_fo_row2, "detail", None)))
    check("ban fan-out: ...and the reply says so instead of claiming the whole install",
          "could not be reached" in (_fo_bad.get("message") or ""),
          "message=%r" % (_fo_bad.get("message"),))
finally:
    _sm_game.ensure_persistent_bans = _fo_saved["ensure"]
    _sm_game.moderate = _fo_saved["moderate"]
    with app.app_context():
        for _fid in _fo_ids:
            _row = db.session.get(GameServer, _fid)
            if _row is not None:
                db.session.delete(_row)
        db.session.commit()

# ── a moderate body whose VALUES are not strings is a 400, never a 500 ────────────────────
# `scope` was read as `(data.get("scope") or "this").strip()` — raw off the body, and ABOVE the
# handler's try:, so a truthy non-string raised AttributeError that nothing here caught and the
# app-wide handler turned into a JSON 500 "Internal server error" with a traceback in the log.
# _json_body guarantees the BODY is a dict and says nothing about the VALUES, which is exactly
# why _json_str exists and was already used on the next line for `reason`.
import panel.routes.server_detail as _ms_rt
_ms_saved = (_sm_game.moderate, _sm_game.ensure_persistent_bans, _ms_rt._resolve_from_console)
try:
    _sm_game.moderate = (lambda r, u, gt, action, target="", message="", selfname=None,
                         steamid="", num=None: (True, "ok"))
    # The ban branch reaches these two before the try:, and both SSH. Stubbed so this block
    # tests the TYPING and never opens a connection.
    _sm_game.ensure_persistent_bans = lambda r, u, sn=None: True
    _ms_rt._resolve_from_console = lambda *a, **k: None
    for _lbl, _mb in (("scope", {"action": "kick", "target": "bob", "scope": 1}),
                      ("target", {"action": "kick", "target": {"a": 1}}),
                      ("message", {"action": "say", "message": ["x"]}),
                      ("num", {"action": "kick", "target": "bob", "num": {"z": 2}}),
                      ("steamid", {"action": "ban", "steamid": 5, "target": "bob"})):
        _mr = c.post("/api/server/%d/moderate" % gs_id, json=_mb,
                     headers={"X-Requested-With": "XMLHttpRequest"})
        check("moderate: a non-string %s is not a 500" % _lbl,
              _mr.status_code < 500, "%r -> %d" % (_mb, _mr.status_code))
    # Positive control: the ordinary body still works, so this is not "refuse everything".
    _mr_ok = c.post("/api/server/%d/moderate" % gs_id,
                    json={"action": "kick", "target": "bob"},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    check("moderate: ...while a well-formed kick still succeeds",
          _mr_ok.status_code == 200 and (_mr_ok.get_json() or {}).get("success") is True,
          "%d %r" % (_mr_ok.status_code, _mr_ok.get_json()))
finally:
    (_sm_game.moderate, _sm_game.ensure_persistent_bans,
     _ms_rt._resolve_from_console) = _ms_saved

# ── a backup must prune to THIS server's retention, not the global default ────────────────
# The per-server override is first-class: the schedule route writes it, get_game_schedule
# resolves "its override where set, else the global default", the API and the disk projection
# in the UI both show it. But only the scheduled ticker read it. The three other paths that
# run a backup — "Back up now", the full backup, and the queued-when-empty sweep — passed the
# GLOBAL keep, and pruning is an unconditional `rm` of everything past it. A server whose
# operator had deliberately raised its retention lost those archives the next time any of
# those three ran.
#
# Asserted on the number actually handed to run_game_backup, because that is the value the
# prune uses; anything else would be testing the config layer twice.
import panel.routes.panel_backup as _bkroute
from panel.ops import backup as _bkmod
from panel.core.panel_state import _full_backup_lock as _bk_lock_chk

_keep_seen = []
_bk_saved = {}


def _bk_stub(mod, name, fn):
    _bk_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


# Wait for any backup worker still running before stubbing: the stub records every call by
# the name it replaces, and a straggler's call is not this route's. See the lock held across
# the typed-body sweep above, which is where one came from.
for _ in range(200):
    if not _bk_lock_chk.locked():
        break
    _ijw_time.sleep(0.05)
try:
    _bk_stub(_bkroute, "run_game_backup",
             lambda remote, short, lgsm, keep, **k: (_keep_seen.append(keep),
                                                     (True, "", False))[1])
    _bk_global = _bkmod.get_full_settings()["keep"]
    _bk_override = int(_bk_global) + 7          # unmistakably not the global value
    _bkmod.set_game_schedule(gs_id, 1, _bk_override)
    try:
        c.post("/api/panel/backup/game/%d" % gs_id,
               headers={"X-Requested-With": "XMLHttpRequest"})
        for _ in range(100):
            if _keep_seen:
                break
            _ijw_time.sleep(0.05)
        check("backup keep: 'Back up now' prunes to THIS server's retention",
              _keep_seen and _keep_seen[0] == _bk_override,
              "handed keep=%r, but this server's override is %r (global is %r) — the extra "
              "archives are deleted" % (_keep_seen[:1], _bk_override, _bk_global))
    finally:
        _bkmod.set_game_schedule(gs_id, None, None)
finally:
    for (_m, _n), _v in _bk_saved.items():
        setattr(_m, _n, _v)

# ── a failed READ must not be written down as a fact ──────────────────────────────────────
# Two routes did it in different ways. Both are driven here with the read stubbed to fail the
# way it actually fails on this codebase: run_command does not raise, it returns
# ("", "...timed out", -1).
import panel.routes.remote_vps as _rvmod
import panel.ops.ssh_manager as _fr_pkg   # noqa: F401  (documented: stub the DEFINITION site)
from panel.ops.ssh_manager import game as _fr_game

# 1. close-panel-port answered "already closed" from a firewall it never managed to read.
#    remote_ufw_status returns {"installed": False, ..., "groups": []} for a missing ufw and
#    adds "unreachable": True when the command failed — its docstring says it does that so a
#    down remote is not shown as an installed firewall with no rules. Reading only .get(
#    "groups") threw that away: no rules found, so "closed", success=True, no audit row, while
#    the panel was still listening on 0.0.0.0.
_fr_saved = {}


def _fr_stub(mod, name, fn):
    _fr_saved[(mod, name)] = getattr(mod, name)
    setattr(mod, name, fn)


try:
    # The LOCAL host: this route refuses anything else with "Only applies to the panel host."
    # Picking a remote one made the check pass on that refusal instead of on the firewall
    # read — green, and measuring nothing. Flagged back afterwards.
    with app.app_context():
        _fr_remote = RemoteServer.query.filter_by(is_local=True).first() \
            or RemoteServer.query.first()
        _fr_rid = _fr_remote.id
        _fr_was_local = bool(_fr_remote.is_local)
        _fr_remote.is_local = True
        db.session.commit()
    _fr_cfg = load_config()
    _fr_cfg_saved = dict(_fr_cfg)
    _fr_cfg["tailscale_setup_done"] = True
    save_config(_fr_cfg)
    _fr_stub(_rvmod, "remote_ufw_status",
             lambda r: {"installed": False, "enabled": False, "rules": [], "groups": [],
                        "unreachable": True})
    _fr_deleted = []
    _fr_stub(_rvmod, "remote_ufw_delete_rule",
             lambda r, n, force=False, **k: _fr_deleted.append(n))
    _fr_r = c.post("/api/remote/%d/close-panel-port" % _fr_rid,
                   headers={"X-Requested-With": "XMLHttpRequest"})
    _fr_j = _fr_r.get_json() or {}
    check("failed read: an unreadable firewall is NOT reported as 'port already closed'",
          _fr_j.get("success") is not True,
          "answered %r — the panel is still listening on that port"
          % (_fr_j.get("message"),))
    check("failed read: ...and nothing was deleted from a firewall it could not read",
          not _fr_deleted, "deleted rule numbers %s" % (_fr_deleted,))
    # A READABLE firewall: its forced deletes by number must each name the rule they mean.
    # The numbers are read once and the auto-block inserts at 1 from another thread, so a
    # forced delete by bare number could take the rule above the panel port's.
    _fr_port = int(_fr_cfg.get("port", 5000))
    setattr(_rvmod, "remote_ufw_status",     # original already saved by _fr_stub above
             lambda r: {"installed": True, "enabled": True, "rules": [], "groups": [
                 {"nums": [4, 9], "port_num": str(_fr_port), "action": "ALLOW",
                  "direction": "IN", "is_iface": False, "key": "k-panel-port"}]})
    _fr_keys = []
    setattr(_rvmod, "remote_ufw_delete_rule",
             lambda r, n, force=False, expect_key=None, **k: (_fr_keys.append((n, expect_key)),
                                                              (True, ""))[1])
    c.post("/api/remote/%d/close-panel-port" % _fr_rid,
           headers={"X-Requested-With": "XMLHttpRequest"})
    check("close panel port: each forced delete names the rule it means, not just its number",
          _fr_keys == [(9, "k-panel-port"), (4, "k-panel-port")], "deleted %r" % (_fr_keys,))
finally:
    for (_m, _n), _v in _fr_saved.items():
        setattr(_m, _n, _v)
    save_config(_fr_cfg_saved)
    _fr_saved.clear()
    with app.app_context():
        _r = db.session.get(RemoteServer, _fr_rid)
        if _r is not None:
            _r.is_local = _fr_was_local
            db.session.commit()

# 2. refresh-commands overwrote the stored list with whatever came back, and [] is what
#    list_server_commands returns for a timeout, a non-zero exit or an empty pane.
try:
    with app.app_context():
        _rc_gs = db.session.get(GameServer, gs_id)
        _rc_before = _rc_gs.commands
        _rc_gs.set_commands([{"cmd": "start", "short": "st", "desc": "Start the server."},
                             {"cmd": "stop", "short": "sp", "desc": "Stop it."}])
        db.session.commit()
    _fr_stub(_fr_game, "list_server_commands", lambda *a, **k: [])
    c.post("/server/%d/refresh-commands" % gs_id)
    with app.app_context():
        _rc_after = db.session.get(GameServer, gs_id).get_commands()
    check("failed read: an empty command list does not wipe the stored one",
          len(_rc_after) == 2,
          "the stored list became %r — Start/Stop/Update vanish from the control bar for "
          "everyone" % (_rc_after,))
    # ...and a real answer still replaces it, so the guard is not "never update".
    _fr_stub(_fr_game, "list_server_commands",
             lambda *a, **k: [{"cmd": "start", "short": "st", "desc": "Start."},
                              {"cmd": "stop", "short": "sp", "desc": "Stop."},
                              {"cmd": "update", "short": "u", "desc": "Update."}])
    c.post("/server/%d/refresh-commands" % gs_id)
    with app.app_context():
        _rc_new = db.session.get(GameServer, gs_id).get_commands()
    check("failed read: ...while a real answer still replaces it", len(_rc_new) == 3,
          "got %r" % (_rc_new,))
finally:
    for (_m, _n), _v in _fr_saved.items():
        setattr(_m, _n, _v)
    with app.app_context():
        db.session.get(GameServer, gs_id).commands = _rc_before
        db.session.commit()


# ── the custom-command FORM: the guard that stops a template smuggling a second command ──────
# A custom command's template is sent to tmux as a console LINE. A newline in it is a second
# keystroke sequence — a command the author did not write and the reviewer did not see.
# _custom_cmd_form() refuses control characters for exactly that reason, and nothing executed
# it: /commands/add, /edit and /delete were three of the 65 routes no suite ever entered.
# Superadmin-only, and the url_map baseline pins that, so this is about the BODY.
def _cc_count():
    with app.app_context():
        return CustomCommand.query.count()


def _cc_add(name, template, **extra):
    _before = _cc_count()
    data = {"name": name, "command_template": template, "scope": "all", "enabled": "on"}
    data.update(extra)
    c.post("/commands/add", data=data)
    return _cc_count() - _before


check("custom command form: a valid template is accepted (the control)",
      _cc_add("cc_ok", "say hello") == 1,
      "the positive control failed — every refusal below proves nothing")
check("custom command form: a NEWLINE in the template is refused",
      _cc_add("cc_nl", "say hi\nquit") == 0,
      "a template that smuggles a second console line was stored")
check("custom command form: ...as is a carriage return",
      _cc_add("cc_cr", "say hi\rquit") == 0)
check("custom command form: ...and a NUL", _cc_add("cc_nul", "say hi\x00quit") == 0)
check("custom command form: ...and an escape, which starts a terminal sequence",
      _cc_add("cc_esc", "say \x1b[2J") == 0)
check("custom command form: two placeholders are refused",
      _cc_add("cc_two", "say {} and {}") == 0,
      "a second {} makes the argument substitution ambiguous")
check("custom command form: an empty template is refused", _cc_add("cc_empty", "") == 0)
check("custom command form: a scope naming a game that does not exist is refused",
      _cc_add("cc_badgame", "say hi", scope="game|nosuchgame") == 0)
check("custom command form: ...and an engine that does not exist",
      _cc_add("cc_badengine", "say hi", scope="engine|nosuchengine") == 0)
# ...but an EXISTING command scoped to a game the current list lacks (dropped upstream, or no
# list could be fetched) keeps that scope. Its edit form had no matching option, the browser
# selected "All games", and a Save to fix the label widened the command to every game.
with app.app_context():
    _oc = CustomCommand(name="cc_orphan", command_template="say hi", scope_type="game",
                        scope_value="nosuchgame", enabled=True)
    db.session.add(_oc)
    db.session.commit()
    _oc_id = _oc.id
try:
    check("custom command edit form: a stored game scope the list lacks is offered, and selected",
          'value="game|nosuchgame" selected' in c.get("/commands").get_data(as_text=True),
          "no option matches, so the browser submits the first one — All games")
    c.post("/commands/%d/edit" % _oc_id, data={"name": "cc_orphan", "command_template": "say hello",
                                                "scope": "game|nosuchgame", "enabled": "on"})
    with app.app_context():
        _oc2 = db.session.get(CustomCommand, _oc_id)
        _oc_state = (_oc2.scope_type, _oc2.scope_value, _oc2.command_template)
    check("custom command edit: saving it keeps that game scope and applies the edit",
          _oc_state == ("game", "nosuchgame", "say hello"), "stored %r" % (_oc_state,))
    c.post("/commands/%d/edit" % _oc_id, data={"name": "cc_orphan", "command_template": "say bye",
                                                "scope": "game|othernosuchgame", "enabled": "on"})
    with app.app_context():
        _oc3 = db.session.get(CustomCommand, _oc_id)
        _oc_state = (_oc3.scope_value, _oc3.command_template)
    check("custom command edit: ...while moving it to a DIFFERENT unknown game is still refused",
          _oc_state == ("nosuchgame", "say hello"), "stored %r" % (_oc_state,))
finally:
    with app.app_context():
        db.session.delete(db.session.get(CustomCommand, _oc_id))
        db.session.commit()
# An unparseable argument pattern must not 500 or store itself — it falls back to the default.
_cc_re_added = _cc_add("cc_badre", "say {}", argument_pattern="([unclosed")
check("custom command form: an invalid argument pattern does not store a broken regex",
      _cc_re_added in (0, 1), "unexpected result %s" % _cc_re_added)
if _cc_re_added == 1:
    with app.app_context():
        _bad = CustomCommand.query.filter_by(name="cc_badre").first()
        check("custom command form: ...it falls back to a pattern that compiles",
              _bad is not None and _bad.argument_pattern != "([unclosed",
              "stored %r" % (getattr(_bad, "argument_pattern", None),))
with app.app_context():
    for _n in ("cc_ok", "cc_badre"):
        _row = CustomCommand.query.filter_by(name=_n).first()
        if _row is not None:
            db.session.delete(_row)
    db.session.commit()

# ── can_run_custom_command: who may press a superadmin-authored console button ────────────────
# Every branch of this decides whether a non-superadmin gets to run a console command on a
# server, and none of it was asserted.
from panel.security.auth import can_run_custom_command as _crcc
with app.app_context():
    _gs = db.session.get(GameServer, gs_id)          # game_type "csgo" on host #1
    _cmd = CustomCommand(name="Say", command_template="say {}", scope_type="all", enabled=True)
    db.session.add(_cmd)
    _grp = Group(name="smoke_cc", description="", is_default=False)
    _grp.set_permissions([auth.VIEW_SERVERS])
    _grp.servers.append(db.session.get(RemoteServer, remote_id))
    db.session.add(_grp)
    db.session.flush()
    _cu = User(username="smoke_cc_user", password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name="CC", is_superadmin=False, is_active=True)
    _cu.groups.append(_grp)
    db.session.add(_cu)
    db.session.commit()
    _adm = db.session.get(User, admin_id)

    check("custom command: a superadmin may run an enabled, in-scope command",
          _crcc(_adm, _cmd, _gs) is True)
    # The core rule: having ACCESS to the server is not having the COMMAND.
    check("custom command: a user whose groups lack the command may NOT run it",
          _crcc(_cu, _cmd, _gs) is False, "access to the server leaked the command")
    _grp.custom_commands.append(_cmd)
    db.session.commit()
    check("custom command: granting it to the user's group lets them run it",
          _crcc(_cu, _cmd, _gs) is True)

    _cmd.enabled = False
    db.session.commit()
    check("custom command: a disabled command is refused even to a superadmin",
          _crcc(_adm, _cmd, _gs) is False)
    _cmd.enabled = True
    # Scope: this command is for a different game, so it must not appear on this server.
    _cmd.scope_type, _cmd.scope_value = "game", "minecraft"
    db.session.commit()
    check("custom command: a command scoped to another game is refused",
          _crcc(_adm, _cmd, _gs) is False)
    _cmd.scope_value = _gs.game_type
    db.session.commit()
    check("custom command: scoping it to THIS game allows it again",
          _crcc(_adm, _cmd, _gs) is True)

    # A user with no groups has no access to the host, so the access check must refuse first.
    _nu = User(username="smoke_cc_none", password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name="None", is_superadmin=False, is_active=True)
    db.session.add(_nu)
    db.session.commit()
    check("custom command: a user with no groups is refused", _crcc(_nu, _cmd, _gs) is False)
    check("custom command: a missing command is refused, not an exception",
          _crcc(_adm, None, _gs) is False)

# ── a superadmin resetting SOMEONE ELSE's 2FA ─────────────────────────────────────────────
# rbac_test covers the refusal (a MANAGE_USERS admin must not reach a more-privileged
# account). The path that is supposed to WORK had no test at all, and it is the one the whole
# 2FA design leans on: /account/2fa/disable now demands a second factor, and "an admin can
# clear it for someone who lost both" is what makes that safe to require.
from panel.db.models import User as _R2U

with app.app_context():
    _r2 = _R2U(username="reset2fa_target",
               password_hash=auth.hash_password("Str0ng!passw0rd"),
               display_name="target", is_superadmin=False, is_active=True,
               totp_enabled=True, totp_secret=encrypt_secret(auth.generate_totp_secret()))
    _r2.set_backup_codes(auth.generate_backup_codes())
    db.session.add(_r2)
    db.session.commit()
    _r2_id = _r2.id
    _AL.query.filter_by(action="2fa_reset").delete()
    db.session.commit()

# The control is only reachable if the page TELLS the modal this account has 2FA — the switch
# is disabled without it. Assert the data island carries the flag, not just that the route
# works, or the feature can be correct and unreachable at the same time.
import json as _r2_json
import re as _r2_re
_r2_page = c.get("/users").get_data(as_text=True)
_r2_m = _r2_re.search(r'id="users-data"[^>]*>(.*?)</script>', _r2_page, _r2_re.S)
_r2_island = _r2_json.loads(_r2_m.group(1)) if _r2_m else []
_r2_row = next((r for r in _r2_island if r.get("id") == _r2_id), None)
check("admin 2fa reset: the users page tells the edit modal this account HAS 2FA",
      (_r2_row or {}).get("totp_enabled") is True,
      "island row %r — without this the switch renders disabled and the admin cannot use it"
      % (_r2_row,))

c.post("/users/%d/edit" % _r2_id,
       data={"username": "reset2fa_target", "display_name": "target",
             "is_active": "on", "reset_2fa": "on"}, follow_redirects=True)
with app.app_context():
    _r2_after = db.session.get(_R2U, _r2_id)
    _r2_still = bool(_r2_after.totp_enabled and _r2_after.totp_secret)
    _r2_codes = _r2_after.backup_codes_remaining
    _r2_audit = _AL.query.filter_by(action="2fa_reset").count()
check("admin 2fa reset: a superadmin clears another user's 2FA", not _r2_still,
      "2FA survived the reset, so an operator who lost their authenticator has no way back in")
check("admin 2fa reset: ...and its backup codes go with it", _r2_codes == 0,
      "%d backup codes still accepted for a second factor that is gone" % _r2_codes)
check("admin 2fa reset: ...and it is audited", _r2_audit == 1,
      "%d 2fa_reset rows — clearing someone's second factor must leave a trace" % _r2_audit)

# ...and it does NOT fire when the box is left unticked, which is every other edit.
with app.app_context():
    _r2b = db.session.get(_R2U, _r2_id)
    _r2b.totp_enabled = True
    _r2b.totp_secret = encrypt_secret(auth.generate_totp_secret())
    db.session.commit()
c.post("/users/%d/edit" % _r2_id,
       data={"username": "reset2fa_target", "display_name": "target renamed",
             "is_active": "on"}, follow_redirects=True)
with app.app_context():
    check("admin 2fa reset: ...and an ordinary edit leaves 2FA alone (positive control)",
          bool(db.session.get(_R2U, _r2_id).totp_enabled),
          "every save now strips the user's second factor")
    db.session.delete(db.session.get(_R2U, _r2_id))
    db.session.commit()

# ── the SSH-port and SSH-mode routes, which nothing entered ───────────────────────────────
# Both change how an operator reaches a host, and a wrong outcome written down is how someone
# believes they still have a way in. Neither route body was executed by any suite: the port
# one validates input, then updates RemoteServer.port so the panel's own future connections
# follow — and that update must happen only when the change actually took.
import panel.routes.remote_vps as _shmod  # pylint: disable=reimported

_sh_saved = (_shmod.change_ssh_port, _shmod.remote_set_public_ssh)
_sh_calls = []


def _al_last(action):
    """The most recent audit row for `action`, as a plain dict (the row is detached after)."""
    with app.app_context():
        _row = _AL.query.filter_by(action=action).order_by(_AL.id.desc()).first()
        return {"success": _row.success, "detail": _row.detail} if _row else None


try:
    with app.app_context():
        _sh_before = db.session.get(RemoteServer, remote_id).port

    def _sh_port(remote, port):
        return c.post("/api/remote/%d/ssh-port" % remote_id, json={"port": port})

    def _sh_stored():
        with app.app_context():
            return db.session.get(RemoteServer, remote_id).port

    _shmod.change_ssh_port = lambda r, p, b="": (_sh_calls.append(p), (True, "moved"))[1]
    for _bad, _why in ((0, "zero"), (65536, "above the range"), ("nope", "not a number"),
                       (None, "missing")):
        _sh_calls.clear()
        _r = _sh_port(remote_id, _bad)
        check("ssh port: %r (%s) is refused before anything is changed" % (_bad, _why),
              _r.status_code == 400 and not _sh_calls,
              "status=%d, change_ssh_port called with %s" % (_r.status_code, _sh_calls))
    check("ssh port: ...and the stored port is untouched by all of that",
          _sh_stored() == _sh_before, "port moved to %r on a refused request" % _sh_stored())

    # A change that FAILED must not move the panel's own idea of the port: it would then
    # connect to a port sshd is not on, and the operator's next visit says the host is down.
    _shmod.change_ssh_port = lambda r, p, b="": (False, "sshd rejected the new config")
    _r = _sh_port(remote_id, 2222)
    check("ssh port: a change that FAILED does not repoint the panel at the new port",
          _sh_stored() == _sh_before,
          "stored port is now %r though the change failed — the panel will dial a port "
          "nothing is listening on" % _sh_stored())
    check("ssh port: ...and it is audited as a failure",
          (_al_last("change_ssh_port") or {}).get("success") is False,
          "audited %r" % ((_al_last("change_ssh_port") or {}).get("success"),))

    # ...and the control: one that worked DOES move it, and is audited as a success.
    _shmod.change_ssh_port = lambda r, p, b="": (True, "moved")
    _r = _sh_port(remote_id, 2223)
    check("ssh port: a change that WORKED repoints the panel (positive control)",
          _sh_stored() == 2223,
          "stored port is %r — the panel keeps dialling the old one" % _sh_stored())
    check("ssh port: ...and is audited as a success",
          (_al_last("change_ssh_port") or {}).get("success") is True,
          "audited %r" % ((_al_last("change_ssh_port") or {}).get("success"),))

    # ssh-mode: its whole job is the audit row, since the outcome is on the host.
    _shmod.remote_set_public_ssh = lambda r, m: (False, "ufw refused")
    c.post("/api/remote/%d/ssh-mode" % remote_id, json={"mode": "limit"})
    check("ssh mode: a refused change is audited as a failure",
          (_al_last("remote_ssh_mode") or {}).get("success") is False,
          "audited %r" % ((_al_last("remote_ssh_mode") or {}).get("success"),))
    _shmod.remote_set_public_ssh = lambda r, m: (True, "ok")
    c.post("/api/remote/%d/ssh-mode" % remote_id, json={"mode": "off"})
    check("ssh mode: ...and one that worked is audited as a success (positive control)",
          (_al_last("remote_ssh_mode") or {}).get("success") is True,
          "audited %r" % ((_al_last("remote_ssh_mode") or {}).get("success"),))
finally:
    (_shmod.change_ssh_port, _shmod.remote_set_public_ssh) = _sh_saved
    with app.app_context():
        db.session.get(RemoteServer, remote_id).port = _sh_before
        db.session.commit()

# ── close-port-22, which removed public SSH with nothing checked at all ───────────────────
# The route ran `ufw delete allow 22/tcp` on whatever host id was posted and answered "Port 22
# rule removed from UFW" with a success audit row. On a key-auth host reachable only over its
# public IP that locks the panel AND the operator out, with no way back from the UI — while
# ssh-mode above, which makes the SAME change, has always refused without a tailnet path back.
# remote_ufw_close_port_22 checks nothing either; "safe if Tailscale SSH is active" is its
# docstring, not a guard.
import panel.routes.close_port22 as _cpmod
_cp_saved = (_cpmod._tailnet_ssh_state, _cpmod.remote_ufw_close_port_22)
_cp_closed = []
try:
    _cpmod.remote_ufw_close_port_22 = lambda r: (_cp_closed.append(getattr(r, "id", "?")),
                                                 (True, "Port 22 rule removed from UFW"))[1]
    _cpmod._tailnet_ssh_state = lambda r: (False, False, False)      # no tailnet way back
    _cpj = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
    check("close port 22: refused when there is no Tailscale way back into the host",
          _cpj.get("success") is False and not _cp_closed,
          "answered %s and called ufw for %s" % (str(_cpj)[:120], _cp_closed))
    check("close port 22: ...and the refusal is audited as a failure, not as a change",
          (_al_last("remote_close_port_22") or {}).get("success") is False,
          "audited %r" % ((_al_last("remote_close_port_22") or {}).get("success"),))
    # Tailscale merely RUNNING is not a way in: with its SSH server off and tailscale0 not
    # allowed in UFW there is still nothing listening for you. This is the state the Tailscale
    # migrate path already refuses on, and the one the docstring's "safe if Tailscale SSH is
    # active" was being read as covering.
    _cpmod._tailnet_ssh_state = lambda r: (True, False, False)
    _cpj2 = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
    check("close port 22: ...and Tailscale running with SSH OFF is not a way back either",
          _cpj2.get("success") is False and not _cp_closed,
          "answered %s and called ufw for %s" % (str(_cpj2)[:120], _cp_closed))
    # The control: a host that really can be reached over the tailnet still closes, so the two
    # checks above cannot be passing on a route that refuses everything.
    _cpmod._tailnet_ssh_state = lambda r: (True, True, False)
    _cpj3 = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
    check("close port 22: a host with Tailscale SSH working still closes (positive control)",
          _cpj3.get("success") is True and _cp_closed == [remote_id],
          "answered %s and called ufw for %s" % (str(_cpj3)[:120], _cp_closed))
    # ...and so does one reachable only because tailscale0 is allowed in UFW, which is the
    # other half of the gate remote_set_public_ssh("off") applies.
    _cp_closed[:] = []
    _cpmod._tailnet_ssh_state = lambda r: (True, False, True)
    _cpj4 = (c.post("/api/remote/%d/close-port-22" % remote_id).get_json() or {})
    check("close port 22: ...and an allowed tailscale0 interface counts as a way back too",
          _cpj4.get("success") is True and _cp_closed == [remote_id],
          "answered %s and called ufw for %s" % (str(_cpj4)[:120], _cp_closed))
finally:
    (_cpmod._tailnet_ssh_state, _cpmod.remote_ufw_close_port_22) = _cp_saved

# ── deleting a UFW rule by number, which nothing entered either ───────────────────────────
# The route hands `num` to a helper whose whole job is refusing a delete that would lock the
# operator out — including when the firewall could not be READ, because "I could not check"
# is not "it is safe". The route's own contribution is the audit row, and that it never
# passes force=True: a caller cannot reach the override through the API.
import panel.routes.remote_vps as _fwmod  # pylint: disable=reimported

_fw_saved = _fwmod.remote_ufw_delete_rule
_fw_args = []
try:
    def _fw_stub(server, num, force=False, expect_key=None):
        _fw_args.append({"num": num, "force": force, "key": expect_key})
        return (False, "refused")
    _fwmod.remote_ufw_delete_rule = _fw_stub
    c.post("/api/remote/%d/firewall/delete-rule" % remote_id, json={"num": 3})
    check("ufw delete: the route never asks for the force override",
          _fw_args and _fw_args[-1]["force"] is False,
          "called with force=%r — the API would be able to delete the rule keeping SSH open"
          % (_fw_args[-1:] or None,))
    check("ufw delete: a refusal is audited as a failure",
          (_al_last("remote_ufw_delete_rule") or {}).get("success") is False,
          "audited %r" % ((_al_last("remote_ufw_delete_rule") or {}).get("success"),))
    # The number is a position; the page sends the rule's key with it, and the route has to
    # hand that on, or the helper cannot notice the number now names a different rule.
    _fw_key = '["27015", "ALLOW", "IN", "Anywhere", "", "gamea"]'
    c.post("/api/remote/%d/firewall/delete-rule" % remote_id, json={"num": 3, "key": _fw_key})
    check("ufw delete: the route passes the rule's key on, so a moved number is refused",
          _fw_args and _fw_args[-1]["key"] == _fw_key, "called with %r" % (_fw_args[-1:] or None,))
    check("ufw delete: ...and a request with no key is no identity check, not an empty one",
          len(_fw_args) >= 2 and _fw_args[-2]["key"] is None, "called with %r" % (_fw_args,))
    _fwmod.remote_ufw_delete_rule = lambda s, n, force=False, expect_key=None: (True, "deleted")
    c.post("/api/remote/%d/firewall/delete-rule" % remote_id, json={"num": 3})
    check("ufw delete: ...and a delete that happened is audited as a success (control)",
          (_al_last("remote_ufw_delete_rule") or {}).get("success") is True,
          "audited %r" % ((_al_last("remote_ufw_delete_rule") or {}).get("success"),))
finally:
    _fwmod.remote_ufw_delete_rule = _fw_saved

# ── revoking an invite must claim it, not read it and then write ─────────────────────────────
# Redemption claims the row atomically — "UPDATE ... WHERE used_at IS NULL", with a comment
# saying that checking is_usable and trusting it would be a race. Revocation was the
# read-then-write half of that same race: it checked used_at, and stamped revoked_at after.
# A link redeemed in between left a row stamped BOTH used and revoked, and told the admin the
# link no longer works — about an invite whose account had just been created.
#
# Driven deterministically by opening the window by hand: utcnow() is what the route calls
# between the two, so a stub that marks the invite used is exactly the redemption landing
# there. The atomic version evaluates it BEFORE the UPDATE, so the WHERE clause sees the
# claim and matches nothing.
import panel.routes.admin_notifications as _ivmod
from panel.db.models import Invite as _IvR
from sqlalchemy import text as _iv_text

_iv_saved_now = _ivmod.utcnow
try:
    with app.app_context():
        _iv_admin = db.session.get(User, admin_id)
        _iv_row, _ = _IvR.mint(_iv_admin, hours=24)
        db.session.add(_iv_row)
        db.session.commit()
        _iv_id = _iv_row.id
        _AL.query.filter_by(action="invite_revoked").delete()
        db.session.commit()

    def _iv_redeem_mid_flight():
        """The redemption, landing in the window the route leaves open."""
        db.session.execute(_iv_text("UPDATE invite SET used_at = :t WHERE id = :i"),
                           {"t": _iv_saved_now(), "i": _iv_id})
        return _iv_saved_now()

    _ivmod.utcnow = _iv_redeem_mid_flight
    _iv_resp = c.post("/users/invite/%d/revoke" % _iv_id, follow_redirects=True)
    _ivmod.utcnow = _iv_saved_now
    _iv_body = _iv_resp.get_data(as_text=True)
    with app.app_context():
        _iv_after = db.session.get(_IvR, _iv_id)
        _iv_used = _iv_after.used_at is not None
        _iv_revoked = _iv_after.revoked_at is not None
        _iv_audit = _AL.query.filter_by(action="invite_revoked").count()
    check("invite revoke: the redemption really did land first (positive control)",
          _iv_used, "the window never opened, so the checks below prove nothing")
    check("invite revoke: a link redeemed in the same instant is not ALSO stamped revoked",
          not _iv_revoked,
          "the row is stamped used AND revoked — a read-then-write lost the race")
    check("invite revoke: ...and the admin is told it was redeemed, not that it was revoked",
          "already redeemed" in _iv_body and "no longer works" not in _iv_body,
          "the page reported a revocation of an invite that had just made an account")
    check("invite revoke: ...and nothing is audited as a revocation",
          _iv_audit == 0, "%d invite_revoked row(s) for an invite that was redeemed" % _iv_audit)

    # The ordinary path still works: an unredeemed invite is revoked and audited.
    with app.app_context():
        _iv_row2, _ = _IvR.mint(db.session.get(User, admin_id), hours=24)
        db.session.add(_iv_row2)
        db.session.commit()
        _iv_id2 = _iv_row2.id
    _iv_body2 = c.post("/users/invite/%d/revoke" % _iv_id2,
                       follow_redirects=True).get_data(as_text=True)
    with app.app_context():
        _iv_after2 = db.session.get(_IvR, _iv_id2)
        _iv_ok = _iv_after2.revoked_at is not None and not _iv_after2.is_usable
        _iv_audit2 = _AL.query.filter_by(action="invite_revoked").count()
    check("invite revoke: an unredeemed invite is still revoked (positive control)",
          _iv_ok and "no longer works" in _iv_body2,
          "revoking stopped working altogether, so the checks above would pass with the "
          "route removed")
    check("invite revoke: ...and that one IS audited", _iv_audit2 == 1,
          "%d invite_revoked rows" % _iv_audit2)
finally:
    _ivmod.utcnow = _iv_saved_now

# ── the invite list must be bounded over REDEEMABLE invites, not over all of them ───────────
# /users took `Invite.query.order_by(created_at.desc()).limit(25)` — the 25 newest rows of ANY
# state — while its own comment said the useful part of the list is what is still redeemable.
# The Revoke button is rendered only for rows in that list, and revoke_invite is linked from
# nowhere else, so 25 newer used/expired links pushed a live one off the page and left it
# working and unrevokable through the UI for the rest of its TTL.
from datetime import timedelta as _iv_td
from panel.core.clock import utcnow as _iv_now
_iv_made = []
try:
    with app.app_context():
        _iv_admin3 = db.session.get(User, admin_id)
        _iv_live, _ = _IvR.mint(_iv_admin3, hours=720, note="smoke-live-invite")
        _iv_live.created_at = _iv_now() - _iv_td(days=40)
        db.session.add(_iv_live)
        db.session.flush()
        _iv_live_id = _iv_live.id
        _iv_made.append(_iv_live_id)
        # 30 NEWER rows, every one of them finished: under the old bound these alone filled
        # the page and the live one above never appeared.
        for _n in range(30):
            _iv_dead, _ = _IvR.mint(_iv_admin3, hours=720, note="smoke-dead-%02d" % _n)
            _iv_dead.created_at = _iv_now() - _iv_td(minutes=(30 - _n))
            _iv_dead.used_at = _iv_dead.created_at
            db.session.add(_iv_dead)
            db.session.flush()
            _iv_made.append(_iv_dead.id)
        # One that EXPIRED without being used or revoked: finished, shown once for context,
        # and not live. Counting it live (in _invite_listing since manage_users was split) left
        # every suite green — the dead rows above are all used — and listed it twice.
        _iv_exp, _ = _IvR.mint(_iv_admin3, hours=1, note="smoke-expired-invite")
        _iv_exp.expires_at = _iv_now() - _iv_td(minutes=5)
        db.session.add(_iv_exp)
        db.session.flush()
        _iv_made.append(_iv_exp.id)
        db.session.commit()
        _iv_live_row = db.session.get(_IvR, _iv_live_id)
        _iv_live_usable = _iv_live_row.is_usable
        _iv_live_older = all(db.session.get(_IvR, i).created_at > _iv_live_row.created_at
                             for i in _iv_made[1:])
    # The setup has to be the setup the bug needs, or the check below proves nothing.
    check("invite list: the fixture really is one live invite behind 30 newer dead ones",
          _iv_live_usable and _iv_live_older,
          "live=%r, all 30 newer=%r" % (_iv_live_usable, _iv_live_older))
    _iv_page = c.get("/users").get_data(as_text=True)
    check("invite list: a still-redeemable invite is not crowded out by newer finished ones",
          ("/users/invite/%d/revoke" % _iv_live_id) in _iv_page,
          "the only Revoke button a live link ever gets was pushed off the page")
    # Positive control: finished invites are still shown for context, so the fix is a
    # re-bounding of the list and not a filter that emptied it.
    check("invite list: finished invites are still listed for context",
          "smoke-dead-29" in _iv_page,
          "the page now shows nothing but live invites")
    check("invite list: an expired invite is listed once, as finished, with no Revoke",
          _iv_page.count(">smoke-expired-invite<") == 1
          and ("/users/invite/%d/revoke" % _iv_made[-1]) not in _iv_page,
          "listed %d time(s)" % _iv_page.count(">smoke-expired-invite<"))
finally:
    with app.app_context():
        if _iv_made:
            _IvR.query.filter(_IvR.id.in_(_iv_made)).delete(synchronize_session=False)
            db.session.commit()

# ── and the ROUTE must not publish a reading nobody took ──────────────────────────────────
# The helper now says read_ok; this is the caller that has to act on it. Driven through the
# endpoint the page actually polls, because a flag no route reads changes nothing on screen.
import panel.routes.ubuntu_pro as _lrmod

_lr_saved = _lrmod.remote_live_metrics
try:
    _lr_zeros = {"read_ok": False, "cpu_overall": 0.0, "cpu_cores": [], "core_count": 0,
                 "ram_used": 0, "ram_total": 0, "ram_percent": 0, "swap_used": 0,
                 "swap_total": 0, "swap_percent": 0, "disk_used": 0, "disk_total": 0,
                 "disk_percent": 0}
    _lrmod.remote_live_metrics = lambda r: _lr_zeros
    _lr = c.get("/api/remote/%d/live" % remote_id).get_json() or {}
    check("live route: a read that produced nothing answers an error, not zeros",
          bool(_lr.get("error")) and "cpu_overall" not in _lr,
          "published %r — the card renders CPU 0%%, 0 cores and RAM 0 of 0 for a host that "
          "never answered" % (sorted(_lr.items())[:4],))
    check("live route: ...and says the host did not answer, so the card can say so too",
          _lr.get("unreachable") is True, "no unreachable flag: %r" % (_lr,))

    _lrmod.remote_live_metrics = lambda r: dict(_lr_zeros, read_ok=True, cpu_overall=12.5,
                                                ram_total=2048, ram_used=1024, core_count=2)
    _lr2 = c.get("/api/remote/%d/live" % remote_id).get_json() or {}
    check("live route: ...while a real reading is still published (positive control)",
          _lr2.get("cpu_overall") == 12.5 and not _lr2.get("error"),
          "the route stopped publishing readings at all: %r" % (_lr2,))
finally:
    _lrmod.remote_live_metrics = _lr_saved

# ── backups: the schedule clock, and an audit line that matches what happened ─────────────
# Three accounting bugs, all the same shape: a backup path that did (or did not do) something
# and told the rest of the panel otherwise.
import panel.routes.panel_backup as _bkmod  # pylint: disable=reimported
import panel.routes._shared as _bksh
import time
from panel.core.panel_state import _full_backup_lock as _bk_lock  # pylint: disable=reimported
from panel.ops import backup as _bkops  # pylint: disable=reimported


def _bk_clock(sid):
    """This server's schedule last-run, the number game_backup_due measures against."""
    return _bkops.get_game_schedule(sid)["last"]


def _bk_wait(sid, before, secs=5.0):
    """Wait for the background worker to move the clock (or give up and let the check fail)."""
    _end = time.time() + secs
    while time.time() < _end:
        if _bk_clock(sid) != before:
            return True
        time.sleep(0.05)
    return False


_bk_saved_pb = _bkmod.run_game_backup
_bk_saved_sh = _bksh.run_game_backup
_bk_saved_trig = None
with app.app_context():
    _bk_gs = db.session.get(GameServer, gs_id)
    _bk_gs.installed = True
    db.session.commit()
try:  # noqa: MC0001
    # A refused full backup must be audited as a REFUSAL. The route hardcoded success=True, so
    # "a full backup is already running" — a request that did nothing — was indistinguishable
    # in /logs from one that ran, and the failures filter (the one an operator reaches for
    # when a backup is missing) hid it. The reboot route already carries this exact fix.
    with app.app_context():
        _AL.query.filter_by(action="panel_full_backup").delete()
        db.session.commit()
    _bk_lock.acquire()          # exactly what a full backup in progress looks like
    try:
        _r = c.post("/api/panel/backup/full", json={"mode": ""})
        _busy = (_r.get_json() or {}).get("running")
    finally:
        _bk_lock.release()
    with app.app_context():
        _al = _AL.query.filter_by(action="panel_full_backup").order_by(_AL.id.desc()).first()
    check("full backup: a request refused because one is already running is audited as a "
          "FAILURE", _al is not None and _al.success is False,
          "audited success=%r — /logs filtered to failures hides this, and the history shows "
          "two full backups where one happened" % (None if _al is None else _al.success,))
    check("full backup: ...and the refusal says so in the entry",
          _al is not None and "refused" in (_al.detail or ""),
          "detail=%r" % (None if _al is None else _al.detail,))
    check("full backup: ...and the caller was told it was busy (positive control)",
          _busy is True,
          "the route did not take the refusal path at all, so the checks above prove nothing")

    # An on-demand "Back up now" must move that server's schedule clock. record_game_backup
    # was called from ONE place (the hourly ticker), so a backup taken by hand left the
    # scheduler believing none had happened and it archived the same server again within the
    # hour — twice the disk, twice the stop/start.
    _bkmod.run_game_backup = lambda *a, **k: (True, "", False)
    _bkops.record_game_backup(gs_id)        # a known starting point, not whatever ran before
    time.sleep(1.05)                        # the clock is whole seconds
    _bk_before = _bk_clock(gs_id)
    _r = c.post("/api/panel/backup/game/%d" % gs_id, json={})
    _moved = _bk_wait(gs_id, _bk_before)
    check("game backup: 'back up now' moves the server's schedule clock",
          _moved,
          "last=%r unchanged (%r) — the hourly ticker still thinks this server is overdue and "
          "will archive it again within the hour" % (_bk_clock(gs_id), _bk_before))

    # ...but only when a backup actually HAPPENED. Skipped = players online, and the ticker
    # deliberately leaves the clock alone there so the server stays due and is retried once it
    # empties. Recording a skip would silently drop that backup for a whole interval.
    _bkmod.run_game_backup = lambda *a, **k: (True, "players online", True)
    _bkops.record_game_backup(gs_id)
    time.sleep(1.05)
    _bk_before = _bk_clock(gs_id)
    c.post("/api/panel/backup/game/%d" % gs_id, json={})
    time.sleep(1.2)
    check("game backup: ...but a SKIPPED one does not (it stays due, and is retried)",
          _bk_clock(gs_id) == _bk_before,
          "a backup that never ran moved the clock, so the server waits a full interval")

    # The 'wait until empty' queue is a third path to the same archive, and it recorded
    # nothing either: a server backed up by THIS sweep still looked overdue to the ticker in
    # the same tick.
    _bksh.run_game_backup = lambda *a, **k: (True, "", False)
    with app.app_context():
        db.session.get(GameServer, gs_id).backup_pending = True
        db.session.commit()
    _bkops.record_game_backup(gs_id)
    time.sleep(1.05)
    _bk_before = _bk_clock(gs_id)
    _bksh._run_pending_backups(app)
    with app.app_context():
        _pend_after = db.session.get(GameServer, gs_id).backup_pending
    check("queued backup: the 'wait until empty' sweep moves the clock too",
          _bk_clock(gs_id) != _bk_before,
          "last=%r unchanged — the ticker backs the same server up again on the next tick"
          % (_bk_clock(gs_id),))
    check("queued backup: ...and the server leaves the queue (positive control)",
          _pend_after is False,
          "the sweep never backed this server up, so the check above proves nothing")

    def _bk_settle():
        """Wait for whatever the checks above started to let go of the backup lock."""
        if _bk_lock.acquire(timeout=8):
            _bk_lock.release()
            return True
        return False

    # ── every backup path hands run_game_backup the server's gamedig override ──────────────
    # Without query_type, player_count has no gamedig type for the games that need an override
    # (Project Zomboid, ARK, Mordhau, Killing Floor), answers None, and run_game_backup reads
    # None as "empty" and runs LinuxGSM `backup`, which STOPS the server with players on it.
    # All four callers left it out. Driven through each real path.
    _qt_seen = []
    with app.app_context():
        _qt_short = db.session.get(GameServer, gs_id).short_name

    def _qt_rgb(*a, **k):
        if a[1] == _qt_short:
            _qt_seen.append(k.get("query_type"))
        return (True, "", False)
    _qt_due_saved = _bkops.game_backup_due
    _qt_prev_sh, _qt_prev_pb = _bksh.run_game_backup, _bkmod.run_game_backup
    try:
        with app.app_context():
            _qt_gs = db.session.get(GameServer, gs_id)
            _qt_gs.query_type = "projectzomboid"
            _qt_gs.backup_pending = True
            db.session.commit()
        _bksh.run_game_backup = _bkmod.run_game_backup = _qt_rgb
        _bkops.game_backup_due = lambda sid: sid == gs_id
        _bkops.record_game_backup(gs_id)
        _bkops.set_game_schedule(gs_id, 1, 2)
        for _qt_label, _qt_run in (
                ("the 'wait until empty' sweep", lambda: _bksh._run_pending_backups(app)),
                ("the scheduled ticker", lambda: _bksh._run_due_game_backups(app)),
                ("'back up now'", lambda: c.post("/api/panel/backup/game/%d" % gs_id, json={})),
                ("the full backup", lambda: c.post("/api/panel/backup/full", json={"mode": ""}))):
            del _qt_seen[:]
            _bk_settle()
            _qt_run()
            _bk_settle()
            check("backup query_type: %s passes the server's gamedig override" % _qt_label,
                  _qt_seen == ["projectzomboid"],
                  "run_game_backup saw query_type %r ([] = never called for this server) — "
                  "player_count answers None, and None reads as empty" % (_qt_seen,))
    finally:
        _bksh.run_game_backup = _qt_prev_sh
        _bkmod.run_game_backup = _qt_prev_pb
        _bkops.game_backup_due = _qt_due_saved
        _bkops.set_game_schedule(gs_id, None, None)
        with app.app_context():
            _qt_gs = db.session.get(GameServer, gs_id)
            _qt_gs.query_type = None
            _qt_gs.backup_pending = False
            db.session.commit()

    # ── the backup runners say a backup is RUNNING, and stand aside for the Backup button ──
    # Only the manual route set _game_backup_status running, so _run_due_restarts (its own
    # 90 s thread, whose guard reads exactly that flag) could stop or restart a server a
    # scheduled backup had just stopped to archive. And the maintenance menu's Backup button
    # runs outside the backup lock with no flag at all: the hourly ticker took its live
    # backup.lock for an orphan and started a second archive of the same files.
    from panel.core.panel_state import _action_output as _rb_ao, _game_backup_status as _rb_st
    _rb_seen = []
    _rb_prev = _bksh.run_game_backup
    _rb_due_saved = _bkops.game_backup_due
    with app.app_context():
        _rb_short = db.session.get(GameServer, gs_id).short_name

    def _rb_rgb(*a, **k):
        if a[1] == _rb_short:
            _rb_seen.append((_rb_st.get(gs_id) or {}).get("running"))
        return (True, "", False)
    try:
        _bkops.game_backup_due = lambda sid: sid == gs_id
        _bkops.record_game_backup(gs_id)
        _bkops.set_game_schedule(gs_id, 1, 2)
        _bksh.run_game_backup = _rb_rgb
        for _rb_label, _rb_pend, _rb_run in (
                ("the scheduled ticker", False, lambda: _bksh._run_due_game_backups(app)),
                ("the 'wait until empty' sweep", True, lambda: _bksh._run_pending_backups(app))):
            del _rb_seen[:]
            _rb_st.pop(gs_id, None)
            with app.app_context():
                db.session.get(GameServer, gs_id).backup_pending = _rb_pend
                db.session.commit()
            _bk_settle()
            _rb_run()
            check("backup running flag: %s marks the server running while it backs up" % _rb_label,
                  _rb_seen == [True] and (_rb_st.get(gs_id) or {}).get("running") is False,
                  "running during=%r, after=%r" % (_rb_seen, _rb_st.get(gs_id)))
            # ...and stands aside while the Backup button is archiving the same server.
            del _rb_seen[:]
            with app.app_context():
                db.session.get(GameServer, gs_id).backup_pending = _rb_pend
                db.session.commit()
            _rb_ao[gs_id] = {"action": "backup", "path": "/dev/null", "user": _rb_short, "pos": 0}
            try:
                _bk_settle()
                _rb_run()
            finally:
                _rb_ao.pop(gs_id, None)
            check("backup running flag: %s does not start a second archive over a Backup-button run"
                  % _rb_label, _rb_seen == [], "run_game_backup called %d time(s)" % len(_rb_seen))
        # The FULL run (panel_backup, its own reference to run_game_backup) set no flag either,
        # and it too must leave a server alone while the Backup button is archiving it.
        _rb_prev_pb = _bkmod.run_game_backup
        _bkmod.run_game_backup = _rb_rgb
        try:
            del _rb_seen[:]
            _rb_st.pop(gs_id, None)
            _bk_settle()
            c.post("/api/panel/backup/full", json={"mode": ""})
            _bk_settle()
            check("backup running flag: the full backup marks the server running while it backs up",
                  _rb_seen == [True] and (_rb_st.get(gs_id) or {}).get("running") is False,
                  "running during=%r, after=%r" % (_rb_seen, _rb_st.get(gs_id)))
            del _rb_seen[:]
            _rb_ao[gs_id] = {"action": "backup", "path": "/dev/null", "user": _rb_short, "pos": 0}
            try:
                _bk_settle()
                c.post("/api/panel/backup/full", json={"mode": ""})
                _bk_settle()
                _rb_now = c.post("/api/panel/backup/game/%d" % gs_id, json={})
                _bk_settle()
            finally:
                _rb_ao.pop(gs_id, None)
            check("backup running flag: the full backup does not start a second archive over a "
                  "Backup-button run", _rb_seen == [], "run_game_backup called %d time(s)" % len(_rb_seen))
            check("backup running flag: ...nor does 'back up now', and it says why",
                  (_rb_now.get_json() or {}).get("success") is False
                  and "already being backed up" in ((_rb_now.get_json() or {}).get("message") or ""),
                  "answered %r" % (_rb_now.get_json(),))
            # Positive control: the chain is walked, so a backup DISPLACED by a later long action
            # (an update started while it runs) still counts; an ended one does not.
            _rb_ao[gs_id] = {"action": "update", "path": "/dev/null", "user": _rb_short, "pos": 0,
                             "prev": {"action": "backup", "path": "/dev/null", "user": _rb_short,
                                      "pos": 0}}
            try:
                _rb_disp = _bksh._button_backup_running(gs_id)
                _rb_ao[gs_id]["prev"]["ended"] = True
                _rb_ended = _bksh._button_backup_running(gs_id)
            finally:
                _rb_ao.pop(gs_id, None)
            check("backup running flag: a Backup-button run displaced by a later action still counts; "
                  "an ended one does not", _rb_disp is True and _rb_ended is False,
                  "displaced=%r ended=%r" % (_rb_disp, _rb_ended))
        finally:
            _bkmod.run_game_backup = _rb_prev_pb
        # A run that RAISES must not leave the flag set, or the restart sweep skips it for ever.

        def _rb_boom(*a, **k):
            raise RuntimeError("ssh fell over")
        _bksh.run_game_backup = _rb_boom
        _rb_st.pop(gs_id, None)
        _bk_settle()
        _bksh._run_due_game_backups(app)
        check("backup running flag: a run that raises clears the flag",
              (_rb_st.get(gs_id) or {}).get("running") is False, "status %r" % (_rb_st.get(gs_id),))
    finally:
        _bksh.run_game_backup = _rb_prev
        _bkops.game_backup_due = _rb_due_saved
        _bkops.set_game_schedule(gs_id, None, None)
        _rb_st.pop(gs_id, None)
        with app.app_context():
            db.session.get(GameServer, gs_id).backup_pending = False
            db.session.commit()

    # ── an unreadable config.json must not prune a server past its own retention ──────────
    # get_game_schedule answers the DEFAULT keep (2) when config.json cannot be read, and
    # "Back up now" and the full run pruned to it: a server set to keep 10 lost 8 archives.
    # The sweeps skip in that state; these two now prune no lower than the largest retention
    # any setting can hold.
    #
    # The unreadable file is what the BACKUP module reads (its load_config), not the real
    # config.json: with that broken the app redirects every request before a route runs.
    from panel.core.config import UnreadableConfig as _PkUC
    _pk_seen = []
    _pk_prev_pb, _pk_load = _bkmod.run_game_backup, _bkops.load_config
    with app.app_context():
        _pk_short = db.session.get(GameServer, gs_id).short_name
    try:
        _bkops.set_game_schedule(gs_id, 1, 10)
        _bkmod.run_game_backup = lambda *a, **k: (
            _pk_seen.append(a[3]) if a[1] == _pk_short else None, (True, "", False))[1]
        for _pk_label, _pk_run in (
                ("'back up now'", lambda: c.post("/api/panel/backup/game/%d" % gs_id, json={})),
                ("the full backup", lambda: c.post("/api/panel/backup/full", json={"mode": ""}))):
            for _pk_bad, _pk_want in ((True, _bkops.MAX_FULL_KEEP), (False, 10)):
                del _pk_seen[:]
                _bk_settle()
                if _pk_bad:
                    _bkops.load_config = lambda: _PkUC(_pk_load())
                try:
                    _pk_r = _pk_run()
                    _bk_settle()
                finally:
                    _bkops.load_config = _pk_load
                check("backup keep: %s with config.json %s prunes to %d"
                      % (_pk_label, "UNREADABLE" if _pk_bad else "readable (control)", _pk_want),
                      _pk_seen == [_pk_want],
                      "run_game_backup got keep %r (status %d)" % (_pk_seen, _pk_r.status_code))
    finally:
        _bkmod.run_game_backup = _pk_prev_pb
        _bkops.load_config = _pk_load
        _bkops.set_game_schedule(gs_id, None, None)

    # ── a scheduled backup that FAILS has to say so somewhere ─────────────────────────────
    # run_game_backup does not raise for a failed backup: it returns (False, reason, False),
    # and a host that is down reaches it as rc=-1/255 from run_command on the tailscale and
    # local transports rather than as an exception. The ticker's only notify() sat in its
    # `except`, so the failure shape that actually happens took no branch at all — and the
    # ticker records the clock for a genuine failure (deliberately, so it does not retry
    # hourly), which makes the silence last a whole interval: no alert, no audit row, no
    # retry. The operator learns of it when they need a restore.
    _bk_notes = []
    _bk_notify_saved = _bksh.notifications.notify
    _bk_due_saved = _bkops.game_backup_due
    try:
        _bksh.notifications.notify = lambda k, t, b="": _bk_notes.append((k, t))
        _bkops.game_backup_due = lambda sid: sid == gs_id    # only OUR server is due
        _bkops.record_game_backup(gs_id)                     # a clock: not "never run before"
        _bkops.set_game_schedule(gs_id, 1, 2)                # ...and the schedule is ON
        with app.app_context():
            _AL.query.filter_by(action="scheduled_backup").delete()
            db.session.commit()
        _bksh.run_game_backup = lambda *a, **k: (False, "Not enough disk space to back up",
                                                 False)
        _bk_free = _bk_settle()
        _bksh._run_due_game_backups(app)
        with app.app_context():
            _bk_row = (_AL.query.filter_by(action="scheduled_backup")
                       .order_by(_AL.id.desc()).first())
        check("scheduled backup: the lock was free, so the ticker actually ran",
              _bk_free, "a backup from an earlier check still held it — the checks below "
                        "would fail for the wrong reason")
        check("scheduled backup: a failure that RETURNS (rather than raises) is alerted",
              any(k == "backup_failed" for k, _ in _bk_notes),
              "notified %s — the alert lives in an except branch a returned failure never "
              "enters, on exactly the transports the panel steers users towards" % (_bk_notes,))
        check("scheduled backup: ...and audited as a failure, so /logs' failures filter finds it",
              _bk_row is not None and _bk_row.success is False,
              "audit row %r — the whole record was an in-memory dict"
              % (None if _bk_row is None else (_bk_row.action, _bk_row.success),))
        check("scheduled backup: ...with the reason, not just the fact",
              _bk_row is not None and "disk space" in (_bk_row.detail or ""),
              "detail=%r" % (None if _bk_row is None else _bk_row.detail,))
        # Positive control: a backup that WORKED is recorded as a success and alerts nobody.
        _bk_notes.clear()
        with app.app_context():
            _AL.query.filter_by(action="scheduled_backup").delete()
            db.session.commit()
        _bksh.run_game_backup = lambda *a, **k: (True, "", False)
        _bk_settle()
        _bksh._run_due_game_backups(app)
        with app.app_context():
            _bk_ok_row = (_AL.query.filter_by(action="scheduled_backup")
                          .order_by(_AL.id.desc()).first())
        check("scheduled backup: one that worked is recorded as a success, and alerts nobody",
              _bk_ok_row is not None and _bk_ok_row.success is True and not _bk_notes,
              "row success=%r, notified %s — the checks above would pass just as well with "
              "every backup reported as a failure"
              % (None if _bk_ok_row is None else _bk_ok_row.success, _bk_notes))
        # The 'wait until empty' sweep reported nothing at all, on any path.
        _bk_notes.clear()
        with app.app_context():
            _AL.query.filter_by(action="queued_backup").delete()
            db.session.get(GameServer, gs_id).backup_pending = True
            db.session.commit()
        _bksh.run_game_backup = lambda *a, **k: (False, "Not enough disk space to back up",
                                                 False)
        _bk_settle()
        _bksh._run_pending_backups(app)
        with app.app_context():
            _bk_q_row = (_AL.query.filter_by(action="queued_backup")
                         .order_by(_AL.id.desc()).first())
        check("queued backup: a failed one is alerted and audited too",
              _bk_q_row is not None and _bk_q_row.success is False
              and any(k == "backup_failed" for k, _ in _bk_notes),
              "row=%r notified %s — this sweep clears backup_pending either way, so nothing "
              "picks the server up again until its own schedule comes round"
              % (None if _bk_q_row is None else (_bk_q_row.action, _bk_q_row.success),
                 _bk_notes))
    finally:
        _bksh.notifications.notify = _bk_notify_saved
        _bkops.game_backup_due = _bk_due_saved
        _bkops.set_game_schedule(gs_id, None, None)

    # ── every clock write goes through the helpers that survive an unreadable config ───────
    # record_game_backup / record_full_backup RAISE ConfigUnreadable while config.json is there
    # but unparseable. The backup paths below were moved onto _record_game_clock; the install
    # route was not, and its call sat one line after committing the new server row — so an
    # install started while the file was bad answered 500 and left a row "installing" with no
    # job behind it. Gate the class: only the two helpers may call the raising writers.
    import ast as _bkc_ast
    _bkc_direct = []
    for _bkc_py in sorted((_lgsm_pathlib.Path(_repo_root) / "panel").rglob("*.py")) + [
            _lgsm_pathlib.Path(_repo_root) / "app.py"]:
        for _bkc_fn in _bkc_ast.walk(_bkc_ast.parse(_bkc_py.read_text(encoding="utf-8"))):
            if not isinstance(_bkc_fn, _bkc_ast.FunctionDef) or _bkc_fn.name in (
                    "_record_game_clock", "_record_full_clock"):
                continue
            for _bkc_c in _bkc_ast.walk(_bkc_fn):
                if (isinstance(_bkc_c, _bkc_ast.Call) and isinstance(_bkc_c.func, _bkc_ast.Attribute)
                        and _bkc_c.func.attr in ("record_game_backup", "record_full_backup",
                                                 "start_game_clock")):
                    _bkc_direct.append("%s:%d in %s()" % (_bkc_py.name, _bkc_c.lineno, _bkc_fn.name))
    check("backup clock: nothing but the two safe helpers calls the writers that raise on a bad "
          "config.json", not _bkc_direct,
          "direct calls: %s — each one turns a readable-later config into a 500 or a false "
          "failure" % sorted(set(_bkc_direct)))

    # ── config.json going bad under a backup that WORKED ──────────────────────────────────
    # update_config now refuses to write while config.json is there but unparseable (it used
    # to replace it with the defaults). Every backup path writes its clock AFTER the archive,
    # and that refusal reached each path's `except`: a backup that worked was audited and
    # alerted as "backup error (ConfigUnreadable)", a manual one told the user to check the
    # host's disk, and a full run alerted that it "errored before completing". And a sweep
    # that STARTS on an unreadable file works from the defaults — including the `keep` its
    # prune deletes past.
    from panel.core.config import ConfigUnreadable as _BkcCU
    from panel.core.panel_state import _game_backup_status as _bkc_status
    _bkc_good = CONFIG_FILE.read_bytes()
    _bkc_bad = b"{ not valid json"
    _bkc_notes, _bkc_ran, _bkc_refused, _bkc_full_refused, _bkc_spawned = [], [], [], [], []

    def _bkc_break_config(*a, **k):
        """A backup that works — and config.json goes bad while it runs."""
        _bkc_ran.append(1)
        CONFIG_FILE.write_bytes(_bkc_bad)
        return True, "", False

    _bkc_rec_real, _bkc_full_real = _bkops.record_game_backup, _bkops.record_full_backup
    _bkc_start_real = _bkops.start_game_clock
    _bkc_sched_real = _bkops.get_game_schedule

    def _bkc_rec(sid):
        try:
            return _bkc_rec_real(sid)
        except _BkcCU:
            _bkc_refused.append(sid)
            raise

    def _bkc_start(sid):
        """start_game_clock, recording a refused write: a first sight STARTS the clock."""
        try:
            return _bkc_start_real(sid)
        except _BkcCU:
            _bkc_refused.append(sid)
            raise

    def _bkc_full(summary):
        try:
            return _bkc_full_real(summary)
        except _BkcCU:
            _bkc_full_refused.append(summary)
            raise

    def _bkc_rows(action):
        with app.app_context():
            return [(r.success, r.detail) for r in _AL.query.filter_by(action=action).all()]

    def _bkc_reset(pending=False):
        CONFIG_FILE.write_bytes(_bkc_good)
        for _l in (_bkc_notes, _bkc_ran, _bkc_refused, _bkc_full_refused):
            del _l[:]
        _bkc_status.pop(gs_id, None)
        with app.app_context():
            _AL.query.filter(_AL.action.in_(("queued_backup", "scheduled_backup"))).delete(
                synchronize_session=False)
            db.session.get(GameServer, gs_id).backup_pending = pending
            db.session.commit()
        _bk_settle()

    class _BkcNoThread:
        class Thread:
            def __init__(self, target=None, daemon=None, **kw):
                self.target = target

            def start(self):
                _bkc_spawned.append(self.target)

    _bkc_saved = (_bksh.notifications.notify, _bkops.game_backup_due, _bksh.run_game_backup,
                  _bkmod.run_game_backup, _bkmod.threading)
    try:
        _bksh.notifications.notify = lambda k, t, b="": _bkc_notes.append((k, t))
        _bkops.game_backup_due = lambda sid: sid == gs_id    # only OUR server is due
        _bkops.record_game_backup, _bkops.record_full_backup = _bkc_rec, _bkc_full
        _bkops.start_game_clock = _bkc_start
        _bkc_rec_real(gs_id)                                 # a clock: not "never run before"
        _bkops.set_game_schedule(gs_id, 1, 2)                # ...and the schedule is ON
        _bksh.run_game_backup = _bkmod.run_game_backup = _bkc_break_config
        _bkc_good = CONFIG_FILE.read_bytes()                 # what each case starts from

        # The 'wait until empty' sweep.
        _bkc_reset(pending=True)
        _bksh._run_pending_backups(app)
        _bkc_left = CONFIG_FILE.read_bytes()
        _bkc_rs = _bkc_rows("queued_backup")
        check("backup + bad config: a QUEUED backup that worked is not reported as failed",
              _bkc_rs and all(_s is True for _s, _ in _bkc_rs) and not _bkc_notes
              and (_bkc_status.get(gs_id) or {}).get("ok") is True,
              "audit %r, notified %s, status %r — the refused clock write reached the sweep's "
              "except" % (_bkc_rs, _bkc_notes, _bkc_status.get(gs_id)))
        check("backup + bad config: ...it did back up, and its clock write WAS refused, "
              "leaving the file alone (positive control)",
              _bkc_ran and gs_id in _bkc_refused and _bkc_left == _bkc_bad,
              "ran=%r refused=%r file=%r" % (_bkc_ran, _bkc_refused, _bkc_left[:20]))

        # The scheduled ticker, after an archive...
        _bkc_reset()
        _bksh._run_due_game_backups(app)
        _bkc_rs = _bkc_rows("scheduled_backup")
        check("backup + bad config: a SCHEDULED backup that worked is not reported as failed",
              _bkc_rs and all(_s is True for _s, _ in _bkc_rs) and not _bkc_notes
              and (_bkc_status.get(gs_id) or {}).get("ok") is True,
              "audit %r, notified %s, status %r" % (_bkc_rs, _bkc_notes, _bkc_status.get(gs_id)))
        check("backup + bad config: ...it did back up, and its clock write WAS refused "
              "(positive control)", _bkc_ran and gs_id in _bkc_refused,
              "ran=%r refused=%r" % (_bkc_ran, _bkc_refused))

        # ...and where it only STARTS a never-run server's clock, which archives nothing.
        def _bkc_fresh(sid):
            if sid != gs_id:
                return _bkc_sched_real(sid)
            CONFIG_FILE.write_bytes(_bkc_bad)
            return {"interval_days": 1, "keep": 2, "last": 0}
        _bkc_reset()
        _bkops.get_game_schedule = _bkc_fresh
        try:
            _bksh._run_due_game_backups(app)
        finally:
            _bkops.get_game_schedule = _bkc_sched_real
        _bkc_rs = _bkc_rows("scheduled_backup")
        check("backup + bad config: starting a new server's clock is not a failed backup",
              not any(_s is False for _s, _ in _bkc_rs) and not _bkc_notes,
              "audit %r, notified %s — no backup was even attempted" % (_bkc_rs, _bkc_notes))
        check("backup + bad config: ...that clock write WAS refused (positive control)",
              gs_id in _bkc_refused and not _bkc_ran,
              "refused=%r ran=%r" % (_bkc_refused, _bkc_ran))

        # "Back up now": the worker's own status is what the page shows.
        _bkc_reset()
        c.post("/api/panel/backup/game/%d" % gs_id, json={})
        _bk_settle()
        _bkc_st = _bkc_status.get(gs_id) or {}
        check("backup + bad config: a MANUAL backup that worked says so, not 'check the host "
              "is reachable and has free disk space'",
              _bkc_st.get("ok") is True and "error" not in (_bkc_st.get("msg") or ""),
              "status %r" % (_bkc_st,))
        check("backup + bad config: ...it did back up, and its clock write WAS refused "
              "(positive control)", _bkc_ran and gs_id in _bkc_refused,
              "ran=%r refused=%r" % (_bkc_ran, _bkc_refused))

        # A full run: its one clock write comes after every server is archived.
        _bkc_reset()
        _bkmod.threading = _BkcNoThread
        c.post("/api/panel/backup/full", json={"mode": ""})
        _bkmod.threading = _bkc_saved[4]
        for _t in _bkc_spawned:
            _t()                                             # the worker, here, to the end
        check("backup + bad config: a FULL run that completed is not alerted as one that "
              "'errored before completing'",
              _bkc_spawned and not any(k == "backup_failed" for k, _ in _bkc_notes),
              "spawned %d, notified %s" % (len(_bkc_spawned), _bkc_notes))
        check("backup + bad config: ...it did back up, and its clock write WAS refused "
              "(positive control)", _bkc_ran and _bkc_full_refused and not _bk_lock.locked(),
              "ran=%r refused=%r lock held=%r" % (_bkc_ran, _bkc_full_refused, _bk_lock.locked()))

        # A sweep that STARTS on an unreadable file does nothing: its schedules and its prune's
        # `keep` would all be the defaults, and nothing it did could be recorded.
        _bkc_reset(pending=True)
        _bksh.run_game_backup = lambda *a, **k: (_bkc_ran.append(a), (True, "", False))[1]
        CONFIG_FILE.write_bytes(_bkc_bad)
        _bksh._run_pending_backups(app)
        _bksh._run_due_game_backups(app)
        CONFIG_FILE.write_bytes(_bkc_good)
        with app.app_context():
            _bkc_still = db.session.get(GameServer, gs_id).backup_pending
        check("backup + bad config: a sweep that starts on an unreadable config.json backs "
              "nothing up and writes nothing",
              not _bkc_ran and not _bkc_refused and _bkc_still is True
              and _bkc_rows("queued_backup") == [] and _bkc_rows("scheduled_backup") == [],
              "ran=%r refused=%r still queued=%r — a prune to the DEFAULT keep deletes "
              "archives a server's own retention kept" % (_bkc_ran, _bkc_refused, _bkc_still))
        _bksh._run_pending_backups(app)
        _bksh._run_due_game_backups(app)
        check("backup + bad config: ...and both sweeps run once it reads (positive control)",
              len(_bkc_ran) >= 2, "ran %d time(s)" % len(_bkc_ran))
    finally:
        CONFIG_FILE.write_bytes(_bkc_good)
        (_bksh.notifications.notify, _bkops.game_backup_due, _bksh.run_game_backup,
         _bkmod.run_game_backup, _bkmod.threading) = _bkc_saved
        _bkops.record_game_backup, _bkops.record_full_backup = _bkc_rec_real, _bkc_full_real
        _bkops.start_game_clock = _bkc_start_real
        _bkops.get_game_schedule = _bkc_sched_real
        _bkops.set_game_schedule(gs_id, None, None)
        with app.app_context():
            db.session.get(GameServer, gs_id).backup_pending = False
            db.session.commit()

    # ── "Full backup started" must not be decided by a test the lock can lose ─────────────
    # _trigger_full_backup checked `_full_backup_lock.locked()` and the worker acquired it
    # later — two steps, with three other holders (the per-server backup, the hourly ticker,
    # the 'wait until empty' sweep) able to take it in between. The worker's own acquire then
    # lost and returned in total silence, while the route had already answered "Full backup
    # started" and written the audit row whose success flag exists precisely so /logs cannot
    # hide a refusal. Driven by never letting the worker run: after a started=True answer the
    # lock must ALREADY be held by the request that answered.
    class _BkNoThread:
        class Thread:
            def __init__(self, target=None, daemon=None, **kw):
                self.target = target

            def start(self):
                _bk_spawned.append(self.target)   # ...and never run it

    _bk_spawned = []
    _bk_thr_saved = _bkmod.threading
    _bk_held = False
    try:
        _bk_settle()
        _bkmod.threading = _BkNoThread
        _bk_full = c.post("/api/panel/backup/full", json={"mode": ""})
        _bk_full_running = (_bk_full.get_json() or {}).get("running")
        _bk_held = _bk_lock.locked()
    finally:
        _bkmod.threading = _bk_thr_saved
        if _bk_held:
            _bk_lock.release()
    check("full backup: the REQUEST takes the lock, rather than leaving it to the thread it "
          "spawns", _bk_held,
          "the lock was free after a 'started' answer — anything that takes it before the "
          "worker does makes that answer, and its success=True audit row, a record of a "
          "backup that never ran")
    check("full backup: ...and the request still reports it started (positive control)",
          _bk_full_running is True and len(_bk_spawned) == 1,
          "answered running=%r, spawned %d worker(s)" % (_bk_full_running, len(_bk_spawned)))

    # ── the two buttons on a backup ROW, against a host that did not answer ───────────────
    # list_game_backups returns None for "could not read" (#330) and _find_game_backup
    # iterated it, so both raised TypeError: the browser got a 500 whose body says the panel
    # is broken, a traceback went to the panel log, and the real cause — the host did not
    # answer — was never stated. Before #330 they answered a calm, wrong "Backup not found."
    _bk_lgb_saved = _bkmod.list_game_backups
    try:
        _bkmod.list_game_backups = lambda *a, **k: None       # the host did not answer
        _bk_delr = c.post("/api/panel/backup/game/%d/delete" % gs_id,
                          json={"name": "an-archive.tar.gz"})
        _bk_delj = _bk_delr.get_json() or {}
        _bk_dlr = c.get("/backup/game/%d/download?name=an-archive.tar.gz" % gs_id)
        check("backup row: deleting one when the listing can't be read is not a 500",
              _bk_delr.status_code < 500 and _bk_delj.get("success") is False,
              "status %d, body %r" % (_bk_delr.status_code, _bk_delj))
        check("backup row: ...and it says the host didn't answer, not 'Backup not found.'",
              "didn't answer" in (_bk_delj.get("message") or ""),
              "message %r — 'not found' is a claim about a directory nobody reached"
              % (_bk_delj.get("message"),))
        check("backup row: downloading one is not a 500 either",
              _bk_dlr.status_code == 502,
              "status %d — a Werkzeug HTML error page where a file should be"
              % _bk_dlr.status_code)
        # Positive control: a listing that WAS read still answers 404 for a name not in it.
        _bkmod.list_game_backups = lambda *a, **k: []
        _bk_delr2 = c.post("/api/panel/backup/game/%d/delete" % gs_id,
                           json={"name": "an-archive.tar.gz"})
        check("backup row: a listing that was READ still answers 'Backup not found.'",
              _bk_delr2.status_code == 404
              and "not found" in ((_bk_delr2.get_json() or {}).get("message") or "").lower(),
              "status %d, body %r — the route now refuses everything, so the checks above "
              "prove nothing" % (_bk_delr2.status_code, _bk_delr2.get_json()))
    finally:
        _bkmod.list_game_backups = _bk_lgb_saved
finally:
    _bkmod.run_game_backup = _bk_saved_pb
    _bksh.run_game_backup = _bk_saved_sh
    with app.app_context():
        _bk_gs = db.session.get(GameServer, gs_id)
        _bk_gs.backup_pending = False
        db.session.commit()

# ── a host reboot must not report a server it could not read as an empty one ───────────────
# A None count is "the query failed" or "this game is not queryable", never "empty": folded into
# a `pc > 0` test, an online server the panel could not read was simply absent from the answer,
# the confirm said nothing, and the reboot disconnected whoever was on it (verified on the test
# box: an online server with a query_type override answered {"busy":[],"total":0}). The census
# is host_reboot.host_player_state; this host is a fixture, so the session read is stubbed and
# the gamedig query recorded.
import panel.services.host_reboot as _rphr
import panel.services.monitoring as _rpmon

_rp_saved = [(_rphr, "_probe_rows", _rphr._probe_rows), (_rphr, "_host_blockers", _rphr._host_blockers),
             (_rpmon, "_host_reachable", _rpmon._host_reachable),
             (_rpmon, "_batched_slots", _rpmon._batched_slots),
             (_rpmon, "sm_player_slots", _rpmon.sm_player_slots),
             (_rpmon, "_lgsm_query_count", _rpmon._lgsm_query_count)]
_rp_args, _rp_sess = [], {}


def _rp_get():
    return (c.get("/api/remote/%d/players" % remote_id).get_json() or {})


def _rp_unknown(d):
    return [u["name"] for u in (d.get("unknown") or [])]


def _rp_busy(d):
    return [b["name"] for b in (d.get("busy") or [])]


_rp_count = {"n": None}


def _rp_slots(server, short, game_type=None, port=None, query_type=None):
    _rp_args.append({"short": short, "query_type": query_type})
    return _rp_count["n"], None, None


try:
    with app.app_context():
        _rp_gs = db.session.get(GameServer, gs_id)
        _rp_status_before, _rp_qt_before = _rp_gs.status, _rp_gs.query_type
        _rp_gs.status, _rp_gs.query_type = "online", "unreal3"
        db.session.commit()
        _rp_name, _rp_short = _rp_gs.name, _rp_gs.short_name
    _rphr._probe_rows = lambda remote, rows: {g.id: {"ok": True, "session": _rp_sess.get(g.id, 0),
                                                     "maint": 0} for g in rows}
    _rphr._host_blockers = lambda remote: []
    _rpmon._host_reachable = lambda remote: True
    _rpmon._batched_slots = lambda servers: {}
    _rpmon.sm_player_slots = _rp_slots
    _rpmon._lgsm_query_count = lambda g: None
    _rp_sess[gs_id] = 1
    _rp = _rp_get()
    check("host reboot: a running server whose player count could not be read is reported",
          _rp_name in _rp_unknown(_rp) and _rp_name not in _rp_busy(_rp),
          "unknown=%r busy=%r — the confirm says nothing about it, and the reboot disconnects "
          "whoever was on it" % (_rp_unknown(_rp), _rp_busy(_rp)))
    _rp_mine = [a for a in _rp_args if a["short"] == _rp_short]
    check("host reboot: ...and the per-server query type override reaches the query",
          _rp_mine and _rp_mine[-1]["query_type"] == "unreal3",
          "called with %r" % (_rp_mine[-1:] or None,))
    _rp_sess[gs_id] = 0
    check("host reboot: ...but a stopped server is not reported as unreadable",
          _rp_name not in _rp_unknown(_rp_get()),
          "every idle server raises a warning, so the real one stops being read")
    _rp_sess[gs_id] = 1
    _rp_count["n"] = 3
    _rp = _rp_get()
    check("host reboot: a server with players is still reported as busy (positive control)",
          _rp_name in _rp_busy(_rp) and _rp_name not in _rp_unknown(_rp)
          and _rp.get("total", 0) >= 3,
          "busy=%r unknown=%r total=%r" % (_rp_busy(_rp), _rp_unknown(_rp), _rp.get("total")))
    _rp_count["n"] = 0
    check("host reboot: ...and a server that answers ZERO is empty, not unknown",
          _rp_name not in _rp_unknown(_rp_get()),
          "a confirmed-empty server is being reported as unreadable")
finally:
    for _m, _n, _v in _rp_saved:
        setattr(_m, _n, _v)
    with app.app_context():
        _rp_gs = db.session.get(GameServer, gs_id)
        _rp_gs.status, _rp_gs.query_type = _rp_status_before, _rp_qt_before
        db.session.commit()

# ── the default group cannot be deleted by a direct POST ──────────────────────────────────
# manage_groups.html hides the delete button behind `{% if not group.is_default %}`, and that
# was the ONLY thing stopping it: the route never looked at the flag. The default group is
# what every new account and every invite starts pre-ticked with, so deleting it leaves the
# install with no default for anyone created afterwards. A guard that lives in the markup is
# not a guard — anything that can POST bypasses it.
# A FRESH login. s1 is long dead by this point in the suite and an unauthenticated POST
# answers success=False all on its own — which is exactly what several of these checks are
# looking for, so they passed against a session that had expired. Prove the client is logged
# in before trusting anything it says.
_lc, _lr = _real_login()
check("late-suite client: the fresh login actually authenticated (the checks below need it)",
      _lc.get("/groups").status_code == 200,
      "GET /groups answered %s — every check below would pass for the wrong reason"
      % (_lc.get("/groups").status_code,))
with app.app_context():
    _dflt = Group.query.filter_by(is_default=True).first()
    if _dflt is None:
        _dflt = Group(name="smoke-default-grp", description="", is_default=True)
        db.session.add(_dflt)
        db.session.commit()
    _dflt_id = _dflt.id
_dg = _lc.post("/groups/%d/delete" % _dflt_id, follow_redirects=False)
with app.app_context():
    _dflt_after = db.session.get(Group, _dflt_id)
check("groups: a direct POST cannot delete the default group", _dflt_after is not None,
      "the default group was deleted by POST /groups/%d/delete (status %s)"
      % (_dflt_id, _dg.status_code))
check("groups: ...and it is still marked default",
      _dflt_after is not None and bool(_dflt_after.is_default),
      "the flag was cleared instead")
# Positive control: a NON-default group still deletes, so the guard above is not just a
# broken route.
with app.app_context():
    _ndg = Group(name="smoke-deletable-grp", description="", is_default=False)
    db.session.add(_ndg)
    db.session.commit()
    _ndg_id = _ndg.id
_lc.post("/groups/%d/delete" % _ndg_id, follow_redirects=False)
with app.app_context():
    check("groups: ...while an ordinary group still deletes (positive control)",
          db.session.get(Group, _ndg_id) is None,
          "the guard is refusing every delete, not just the default one")

# ── sync-ports reports what the firewall TOOK, not what was asked for ─────────────────────
# It discarded remote_ufw_allow_game_ports' return value and answered
# "Ports 27015, 27016 opened." with an audit row saying success=True, whether or not a single
# rule landed. An audit row recording an action that did not happen is worse than no row.
import panel.routes.remote_vps as _rv_mod  # pylint: disable=reimported
from panel.db.models import AuditLog as _SPAudit  # pylint: disable=reimported
_rv_detect = _rv_mod.detect_game_ports
_rv_allow = _rv_mod.remote_ufw_allow_game_ports
try:
    _rv_mod.detect_game_ports = lambda *a, **k: {"game_port": 27015,
                                                 "open_ports": [27015, 27016],
                                                 "ports": [27015, 27016]}
    _rv_mod.remote_ufw_allow_game_ports = lambda *a, **k: ([], "opened 0 port(s): none")
    _sp = _lc.post("/api/server/%d/sync-ports" % gs_id, json={})
    _spj = _sp.get_json() or {}
    check("sync-ports: a firewall that opened nothing is not reported as success",
          _spj.get("success") is False,
          "answered success=%r message=%r" % (_spj.get("success"), _spj.get("message")))
    check("sync-ports: ...and the message names the ports that failed",
          "27015" in (_spj.get("message") or "") and "27016" in (_spj.get("message") or ""),
          "message=%r" % (_spj.get("message"),))
    with app.app_context():
        _spa = (_SPAudit.query.filter_by(action="sync_ports")
                .order_by(_SPAudit.id.desc()).first())
    check("sync-ports: ...and the audit row does not claim it succeeded",
          _spa is not None and not _spa.success,
          "audit row: %r" % (getattr(_spa, "success", "no row"),))
    # Positive control: when the firewall takes them, it says so and audits success.
    _rv_mod.remote_ufw_allow_game_ports = lambda *a, **k: ([27015, 27016], "opened 2")
    _sp2 = _lc.post("/api/server/%d/sync-ports" % gs_id, json={})
    _spj2 = _sp2.get_json() or {}
    check("sync-ports: ...while ports that really opened are reported as success",
          _spj2.get("success") is True and _spj2.get("open_ports") == [27015, 27016],
          "answered %r" % (_spj2,))
    # A PARTIAL result is the case the old code hid completely.
    _rv_mod.remote_ufw_allow_game_ports = lambda *a, **k: ([27015], "opened 1")
    _sp3 = _lc.post("/api/server/%d/sync-ports" % gs_id, json={})
    _spj3 = _sp3.get_json() or {}
    check("sync-ports: ...and a PARTIAL open is reported as a failure naming the missing port",
          _spj3.get("success") is False and _spj3.get("failed_ports") == [27016]
          and "27016" in (_spj3.get("message") or ""),
          "answered %r" % (_spj3,))
finally:
    _rv_mod.detect_game_ports = _rv_detect
    _rv_mod.remote_ufw_allow_game_ports = _rv_allow

# ── sync-ports is a firewall write: MANAGE_REMOTES on the host, like every other (745379031) ─
# It accepted INSTALL_SERVER, so the stock "admin" group — install, manage and uninstall
# servers, NOT manage remotes — could put root-owned allow rules on a host's firewall, from
# ports `details` reads out of a config that group can edit through the file manager. Through
# the real route and real permissions, with the host calls stubbed.
_sp_saved = (_rv_mod.detect_game_ports, _rv_mod.remote_ufw_allow_game_ports,
             _sm_core.run_privileged)
try:
    with app.app_context():
        _apg = Group(name="smoke-admin-preset", description="", is_default=False)
        _apg.set_permissions([auth.INSTALL_SERVER, auth.MANAGE_SERVERS, auth.UNINSTALL_SERVER])
        _apg.servers.append(db.session.get(RemoteServer, remote_id))
        db.session.add(_apg)
        db.session.flush()
        _apu = User(username="smoke_adminpreset", is_superadmin=False, is_active=True,
                    password_hash=auth.hash_password("Str0ng!passw0rd"))
        _apu.groups.append(_apg)
        db.session.add(_apu)
        db.session.commit()
        _apu_id = _apu.id
    _sp_opened = []
    _rv_mod.detect_game_ports = lambda *a, **k: {"game_port": 27015, "open_ports": [27015],
                                                 "ports": []}
    _rv_mod.remote_ufw_allow_game_ports = lambda r, ports, name: (
        _sp_opened.append(list(ports)), (list(ports), "opened"))[1]
    _sm_core.run_privileged = lambda *a, **k: ("", "", 0)    # sshd's ports: none extra
    _spa = client_as(_apu_id).post("/api/server/%d/sync-ports" % gs_id, json={})
    check("sync-ports: the stock admin group (no MANAGE_REMOTES) is refused, and opens nothing",
          _spa.status_code == 403 and _sp_opened == [],
          "status=%d opened=%r" % (_spa.status_code, _sp_opened))
    _spm = client_as(mru_id).post("/api/server/%d/sync-ports" % gs_id, json={})
    check("sync-ports: ...while MANAGE_REMOTES on that host still syncs (positive control)",
          _spm.status_code == 200 and (_spm.get_json() or {}).get("success") is True
          and _sp_opened == [[27015]], "status=%d body=%r" % (_spm.status_code, _spm.get_json()))
finally:
    (_rv_mod.detect_game_ports, _rv_mod.remote_ufw_allow_game_ports,
     _sm_core.run_privileged) = _sp_saved

# ── a validation regex is not silently truncated into a DIFFERENT one ─────────────────────
# The pattern was compiled in full and then stored as arg_pattern[:200]. A cut does not always
# break a regex: an alternation sliced just after a `|` leaves a trailing empty branch, and an
# empty branch matches everything — so a superadmin's whitelist became "accept anything" for
# everyone allowed to run the command. The pattern below is built so that its first 200
# characters are exactly that: still valid, and wide open.
# Built by arithmetic, not by searching for a cut point: each branch below is exactly 8
# characters, so 25 of them are exactly 200 and the 200-character prefix ends on the `|`.
# (A search loop here spun forever — the separator never lands on index 199 for a branch
# length that does not divide into it.)
_branch = "^(?:x)$|"                      # 8 chars
_wide = _branch * 25 + "^(?:y)$"          # [:200] is exactly 25 branches, ending in `|`
import re as _spre  # pylint: disable=reimported
_cut = _wide[:200]
check("commands: the test's own pattern really does widen when cut (not a vacuous check)",
      len(_wide) > 200 and _cut.endswith("|")
      and _spre.match(_wide, "anything-at-all; rm -rf /") is None
      and _spre.match(_cut, "anything-at-all; rm -rf /") is not None,
      "the constructed pattern does not demonstrate the widening: full=%r cut=%r"
      % (_wide[-20:], _cut[-20:]))
_cf = {"name": "smoke-trunc-cmd", "command_template": "say {}", "argument_label": "Map",
       "scope": "all|", "enabled": "on", "argument_pattern": _wide}
_cr = _lc.post("/commands/add", data=_cf, follow_redirects=False)
with app.app_context():
    _stored = CustomCommand.query.filter_by(name="smoke-trunc-cmd").first()
    _stored_pat = _stored.argument_pattern if _stored else None
check("commands: an over-long validation pattern is refused, not truncated",
      _stored is None or _stored_pat == _wide,
      "stored a %d-char pattern from a %d-char one — %r"
      % (len(_stored_pat or ""), len(_wide), (_stored_pat or "")[-30:]))
# Positive control: a pattern that FITS is still accepted, in full.
_ok_pat = "^(?:de_dust2|de_inferno|de_nuke)$"
_lc.post("/commands/add", data=dict(_cf, name="smoke-ok-cmd", argument_pattern=_ok_pat),
         follow_redirects=False)
with app.app_context():
    _ok_cmd = CustomCommand.query.filter_by(name="smoke-ok-cmd").first()
    check("commands: ...while a pattern that fits is stored exactly as written",
          _ok_cmd is not None and _ok_cmd.argument_pattern == _ok_pat,
          "stored %r" % (getattr(_ok_cmd, "argument_pattern", None),))
    for _c in (CustomCommand.query.filter_by(name="smoke-trunc-cmd").first(),
               CustomCommand.query.filter_by(name="smoke-ok-cmd").first()):
        if _c is not None:
            _c.groups = []
            db.session.delete(_c)
    db.session.commit()

# ── the terminal page must name the account it is ACTUALLY running as ────────────────────
# It carried one fixed sentence for every host — "running as the panel's own account — not as
# root" — which was written for the panel host and printed on remotes too. On a remote the
# session runs as whatever account that host is configured with, and for most installs that is
# root: `whoami` in a terminal on the test VPS answers root, under a line promising it was not.
#
# This creates BOTH hosts itself. Two earlier versions asked about rows seeded 6000 lines up:
# the first used an id captured back then and compared the wrong page, and the second queried
# for is_local=True and found None — by this point in the suite no local host survives — then
# crashed the whole run formatting that None into a URL. A test that depends on another test's
# leftovers is testing the leftovers.
_tp_user = "deployacct"          # distinctive, so "it names the account" cannot match by luck
with app.app_context():
    _tp_loc = RemoteServer(name="smoke-term-local", host="127.0.0.1", port=22,
                           username="root", auth_method="key", auth_credential="",
                           is_local=True)
    _tp_rem = RemoteServer(name="smoke-term-remote", host="198.51.100.7", port=22,
                           username=_tp_user, auth_method="key", auth_credential="",
                           is_local=False)
    db.session.add_all([_tp_loc, _tp_rem])
    db.session.commit()
    _tp_loc_id, _tp_rem_id = _tp_loc.id, _tp_rem.id
try:
    _t_local = _lc.get("/terminal/%d" % _tp_loc_id)
    _t_remote = _lc.get("/terminal/%d" % _tp_rem_id)
    check("terminal page: both hosts render (the copy checks below need them)",
          _t_local.status_code == 200 and _t_remote.status_code == 200,
          "local=%d remote=%d" % (_t_local.status_code, _t_remote.status_code))
    _tl = _t_local.get_data(as_text=True)
    _tr = _t_remote.get_data(as_text=True)
    # The local page NAMES the account now rather than promising what it is not: "running as
    # the panel's own account — not as root" is true of a root install's service account and
    # misleading on a per-user one, where that account is usually able to become root without
    # a password. Asserting the real OS account name also catches the Jinja trap — a forgotten
    # `local_user=` kwarg is silently Undefined and falsy, so the fallback would render and
    # this would look fine.
    import panel.ops.terminal_session as _tp_ts
    _tp_acct = _tp_ts.panel_account()
    # The FALLBACK phrase is the discriminator, not the account name: the name also appears in
    # the sudo hint higher up the page, so `acct in html` is satisfied whether or not the
    # footer rendered it. Checked by removing the kwarg and watching the first version of this
    # pass 977/977 — the exact Jinja trap this change could have walked into.
    check("terminal page: the local host names the account the shell runs as",
          bool(_tp_acct) and ("<code>%s</code>" % _tp_acct) in _tl
          and "the account the panel runs under" not in _tl   # the local_user-missing branch
          and "not as root" not in _tl,
          "expected the footer to name %r inside <code>; fallback-branch present=%r means the "
          "route did not pass local_user"
          % (_tp_acct, "the account the panel runs under" in _tl))
    check("terminal page: a REMOTE does not claim to be 'not as root'",
          "not as root" not in _tr,
          "a remote whose configured account is root renders a promise that it is not root")
    check("terminal page: ...it names the account the panel connects with",
          _tp_user in _tr and "the account the panel connects with" in _tr,
          "the remote's copy does not name %r as the account the session runs as" % (_tp_user,))

    # ── ...and its way back must be a page that has actually read this host ──────────────
    # "Back to host" pointed EVERY host at remote_manage, which renders remote_manage.html
    # with no `status` — and status is what the Connection & SSH card reads. Jinja's Undefined
    # is silently falsy, so on the PANEL host that page states Tailscale SSH is Disabled,
    # tailscale0 is Not allowed in UFW and that disabling public SSH would lock you out,
    # having probed nothing, with both firewall buttons disabled. server_management is the
    # only route that calls get_server_status(), and the two checks below it pin exactly that
    # gap. Read off the ANCHOR, not the page: base.html's nav links /server-management on
    # every page for a superadmin, so `in html` would be true either way.
    def _back_href(_html):
        # The rendered SPAN, not the bare words: base.html embeds window.I18N inline, and in a
        # non-English session that catalog carries "Back to host" as a key further up the page.
        _i = _html.find("<span>Back to host</span>")
        if _i < 0:
            return ""
        _a = _html.rfind('<a href="', 0, _i)
        if _a < 0:
            return ""
        _s = _a + len('<a href="')
        return _html[_s:_html.find('"', _s)]

    check("terminal page: the panel host's way back is the route that owns its card",
          _back_href(_tl).endswith("/server-management"),
          "the local terminal's back link is %r — a page rendered without status"
          % (_back_href(_tl),))
    # POSITIVE CONTROL: a real remote still goes back to its own manage page, which IS the
    # page that owns it — this must not have become "everything goes to /server-management".
    check("terminal page: ...and a remote still goes back to its own manage page",
          _back_href(_tr).endswith("/remote/%d/manage" % _tp_rem_id),
          "the remote's back link is %r" % (_back_href(_tr),))
    # The card that links here carried the same sentence, so check it the same way.
    _c_local = _lc.get("/remote/%d/manage" % _tp_loc_id).get_data(as_text=True)
    _c_remote = _lc.get("/remote/%d/manage" % _tp_rem_id).get_data(as_text=True)
    check("host page: the Terminal card names the account on a remote",
          "as the panel's own account" in _c_local
          and "as the panel's own account" not in _c_remote
          and _tp_user in _c_remote,
          "the card says 'the panel's own account' on a host where the account is %r"
          % (_tp_user,))
    # ── ...and its Connection & SSH card must read the host, not an Undefined ────────────
    # remote_manage() rendered this template without `status`. Jinja's Undefined is silently
    # falsy, so `ts_up` and `ssh_lockdown_safe` were false on a panel host with Tailscale SSH
    # running: "Tailscale SSH: Disabled", "Not allowed", both setup buttons greyed with "Set
    # up Tailscale first", and "Disable (tailnet-only)" given data-lockdown="1" — which
    # remote_manage_host.js deliberately never re-enables, so that control could not be
    # reached on this page at all. /server-management renders the same card correctly, which
    # is what made it look like a working gate.
    import panel.ops.system_ops as _sso
    _o_gss = _sso.get_server_status
    try:
        _sso.get_server_status = lambda force=False: {
            "has_sudo": True, "ufw": {"enabled": True, "installed": True},
            "tailscale_ssh": {"running": True, "enabled": True},
            "tailscale_interface": "tailscale0", "tailscale_ufw_allowed": True,
            "updates": {}, "uptime": "1 day"}
        _ms_up = _lc.get("/remote/%d/manage" % _tp_loc_id).get_data(as_text=True)
        check("host page: a panel host WITH Tailscale SSH is not told to set Tailscale up",
              "Set up Tailscale first" not in _ms_up and 'data-lockdown="1"' not in _ms_up
              and "Disable Tailscale SSH" in _ms_up,
              "the card still reads as if Tailscale were absent — status was not passed")
        # POSITIVE CONTROL: a host that really has no Tailscale must still be guarded, or the
        # check above would pass by the card simply never locking anything down.
        _sso.get_server_status = lambda force=False: {
            "has_sudo": True, "ufw": {"enabled": True, "installed": True},
            "tailscale_ssh": {"running": False, "enabled": False},
            "tailscale_interface": "", "tailscale_ufw_allowed": False,
            "updates": {}, "uptime": "1 day"}
        _ms_down = _lc.get("/remote/%d/manage" % _tp_loc_id).get_data(as_text=True)
        check("host page: ...and a host without it still gets the lock-out guard",
              "Set up Tailscale first" in _ms_down and 'data-lockdown="1"' in _ms_down,
              "the guard no longer fires for a host with no way back in")
    finally:
        _sso.get_server_status = _o_gss
finally:
    with app.app_context():
        for _tid in (_tp_loc_id, _tp_rem_id):
            _row = db.session.get(RemoteServer, _tid)
            if _row is not None:
                db.session.delete(_row)
        db.session.commit()

# ── a custom command's argument guard, driven through the real route ─────────────────────
# The route COMPILES the stored pattern and MATCHES the value in two separate try blocks, and
# the comment there records why: they used to be one, so `raise ValueError` for a value that
# did not match was caught by the same `except (re.error, ValueError)` as a broken stored
# pattern and fell through to the lenient default. A command restricted to
# ^(easy|normal|hard)$ accepted 9999. The shell-injection half still held — the default
# charset has no metacharacters — but the AUTHORIZATION half did nothing at all.
#
# That was found and fixed by hand. No suite enters this route, so nothing would catch it
# coming back. The helpers are covered in unit; this is the CALLER.
import panel.routes.server_detail as _cc_mod  # pylint: disable=reimported
_cc_sent = []


def _fake_send(remote, short, cmd, timeout=10, selfname=None):
    _cc_sent.append(cmd)
    return ("", "", 0)


_cc_saved = _cc_mod.send_console_command
_cc_mod.send_console_command = _fake_send
with app.app_context():
    _cc = CustomCommand(name="smoke-difficulty", command_template="difficulty {}",
                        argument_label="Difficulty",
                        argument_pattern="^(easy|normal|hard)$",
                        scope_type="all", scope_value="", enabled=True,
                        created_by="smoke_admin")
    db.session.add(_cc)
    db.session.commit()
    _cc_id = _cc.id
try:
    _u = "/api/server/%d/custom-command/%d" % (gs_id, _cc_id)
    _cc_sent[:] = []
    _r_ok = _lc.post(_u, json={"value": "hard"})
    check("custom command: a value the pattern allows runs, substituted into the template",
          _r_ok.status_code == 200 and _cc_sent == ["difficulty hard"],
          "status=%d sent=%r" % (_r_ok.status_code, _cc_sent))
    _cc_sent[:] = []
    _r_no = _lc.post(_u, json={"value": "9999"})
    check("custom command: a value the pattern REFUSES is rejected, not run",
          _r_no.status_code == 400 and _cc_sent == [],
          "status=%d sent=%r — the authorization half of the guard is back to doing nothing"
          % (_r_no.status_code, _cc_sent))
    # A BROKEN stored pattern must fall back to the safe default, not become a bypass.
    with app.app_context():
        db.session.get(CustomCommand, _cc_id).argument_pattern = "^(unclosed"
        db.session.commit()
    _cc_sent[:] = []
    _r_meta = _lc.post(_u, json={"value": "a;rm -rf /"})
    check("custom command: a broken stored pattern still refuses a value the default refuses",
          _r_meta.status_code == 400 and _cc_sent == [],
          "status=%d sent=%r — an uncompilable pattern became an ALLOW-ALL"
          % (_r_meta.status_code, _cc_sent))
    _cc_sent[:] = []
    _r_plain = _lc.post(_u, json={"value": "9999"})
    check("custom command: ...and it falls back to the DEFAULT, not to refusing everything",
          _r_plain.status_code == 200 and _cc_sent == ["difficulty 9999"],
          "status=%d sent=%r — 9999 matches the default charset, so this should run; "
          "refusing it would mean the fallback is 'deny all' rather than the documented default"
          % (_r_plain.status_code, _cc_sent))
finally:
    _cc_mod.send_console_command = _cc_saved
    with app.app_context():
        _row = db.session.get(CustomCommand, _cc_id)
        if _row is not None:
            _row.groups = []
            db.session.delete(_row)
            db.session.commit()

# ── "Is the server running?" must not be the panel's answer to every failure ──────────────
# send_console_command documents exactly ONE failure code: rc 3 with NO_SESSION, meaning there
# is no tmux session to send to. Both console routes branched on `rc != 0` alone and printed
# that one sentence for all of them — including rc 255 from `ssh: connect to host … No route to
# host`, which a Tailscale/local transport RETURNS rather than raising, so the except never
# fired. The operator was sent to look at their game server while the panel could not reach the
# machine, on a page still showing that server's cached status. And the form route logged only
# on success, so the failed attempt left no audit row at all — the JSON sibling in
# server_files.py has always logged unconditionally with success=(rc == 0).
from panel.db.models import AuditLog as _sc_AL  # pylint: disable=reimported
_sc_rc = {"v": ("", "", 0)}
_sc_saved = _cc_mod.send_console_command
try:
    _cc_mod.send_console_command = (lambda remote, short, cmd, timeout=10, selfname=None:
                                    _sc_rc["v"])

    def _sc_post(rc, err):
        """POST the detail page's command box and hand back (page html, new audit rows)."""
        _sc_rc["v"] = ("", err, rc)
        with app.app_context():
            _before = _sc_AL.query.filter_by(action="send_command").count()
        _h = _lc.post("/server/%d/command" % gs_id, data={"command": "changelevel de_dust2"},
                      follow_redirects=True).get_data(as_text=True)
        with app.app_context():
            _rows = _sc_AL.query.filter_by(action="send_command").order_by(
                _sc_AL.id.desc()).limit(1).all()
            _added = _sc_AL.query.filter_by(action="send_command").count() - _before
        return _h, _added, (_rows[0] if _rows else None)

    _h3, _n3, _r3 = _sc_post(3, "NO_SESSION")
    check("console send: rc 3 is the one case that means 'that server isn't running'",
          "no console session to send to" in _h3,
          "the page does not say the server is stopped")
    _h255, _n255, _r255 = _sc_post(255, "ssh: connect to host gmod1 port 22: No route to host")
    check("console send: an unreachable HOST is not reported as a stopped game server",
          "Is the server running" not in _h255
          and "could not run that on the host" in _h255,
          "the page still blames the game server for a host the panel never reached")
    check("console send: ...and it surfaces what the host actually said",
          "No route to host" in _h255, "the ssh error never reaches the operator")
    check("console send: a failed attempt is audited, not silently dropped",
          _n255 == 1 and _r255 is not None and _r255.success is False,
          "rows added=%d success=%r — the form route used to log only on success"
          % (_n255, getattr(_r255, "success", None)))
    # Positive control: the ordinary send still works, and still logs a success.
    _h0, _n0, _r0 = _sc_post(0, "")
    check("console send: ...while a command that went through still reports and logs success",
          "Command sent" in _h0 and _n0 == 1 and _r0 is not None and _r0.success is True,
          "rows added=%d success=%r" % (_n0, getattr(_r0, "success", None)))
    # The JSON custom-command route answers from the same helper, so it gets the same split.
    with app.app_context():
        _sc_cmd = CustomCommand(name="smoke-sendfail", command_template="status",
                                scope_type="all", scope_value="", enabled=True,
                                created_by="smoke_admin")
        db.session.add(_sc_cmd)
        db.session.commit()
        _sc_cmd_id = _sc_cmd.id
    try:
        _sc_u = "/api/server/%d/custom-command/%d" % (gs_id, _sc_cmd_id)
        _sc_rc["v"] = ("", "ssh: connect to host gmod1 port 22: No route to host", 255)
        _sc_j = (_lc.post(_sc_u, json={}).get_json() or {})
        check("custom command: an unreachable host is not 'Is the server running?' either",
              "Is the server running" not in (_sc_j.get("message") or "")
              and "could not run that on the host" in (_sc_j.get("message") or ""),
              "message=%r" % (_sc_j.get("message"),))
        _sc_rc["v"] = ("", "NO_SESSION", 3)
        _sc_j3 = (_lc.post(_sc_u, json={}).get_json() or {})
        check("custom command: ...and rc 3 still says the server is not running",
              "no console session to send to" in (_sc_j3.get("message") or ""),
              "message=%r" % (_sc_j3.get("message"),))
        _sc_rc["v"] = ("", "", 0)
        _sc_j0 = (_lc.post(_sc_u, json={}).get_json() or {})
        check("custom command: ...while a successful run is unchanged (positive control)",
              _sc_j0.get("success") is True, "json=%r" % (_sc_j0,))
    finally:
        with app.app_context():
            _row = db.session.get(CustomCommand, _sc_cmd_id)
            if _row is not None:
                _row.groups = []
                db.session.delete(_row)
                db.session.commit()
finally:
    _cc_mod.send_console_command = _sc_saved

# ── the terminal's two audit promises, driven through a real socket ──────────────────────
# The feature claims "a row per session opened and closed, and NEVER what was typed", and
# nothing checked either. Socket events are covered by neither CSRFProtect nor rbac_test's
# url_map sweeps — host_terminal.py's own docstring says so — which makes this the code path
# with the least watching it.
#
# The transport is stubbed: the question is what the ROUTE records, not whether a shell
# spawns. The disconnect leg is the real prize — it goes through the console's disconnect
# handler and the socket_hooks chain, which is what #323 broke and a later commit fixed.
import panel.ops.terminal_session as _tsmod
_TERM_SECRET = "hunter2-do-not-log-this"


class _FakeTermSess(object):
    def __init__(self): self.writes = []
    def write(self, d): self.writes.append(d)
    def resize(self, c, r): pass


_fake_sessions = {}
_ts_saved = (_tsmod.open_session, _tsmod.get, _tsmod.close_for_sid)


def _fake_open(sid, server, is_local, user_key, on_output, on_exit, cols=80, rows=24):
    _fake_sessions[sid] = _FakeTermSess()
    return _fake_sessions[sid]


with app.app_context():
    _ta_host = RemoteServer(name="smoke-audit-host", host="127.0.0.1", port=22,
                            username="root", auth_method="key", auth_credential="",
                            is_local=True)
    db.session.add(_ta_host)
    db.session.commit()
    _ta_id, _ta_name = _ta_host.id, _ta_host.name
_tsmod.open_session = _fake_open
_tsmod.get = lambda sid: _fake_sessions.get(sid)
_tsmod.close_for_sid = lambda sid, reason="": _fake_sessions.pop(sid, None)
_ta_err = ""
try:
    _ta_c = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
    _ta_ok = _ta_c.is_connected()
except Exception as _e:
    _ta_c, _ta_ok, _ta_err = None, False, "%s: %s" % (type(_e).__name__, _e)
check("terminal audit: a terminal socket client connects", _ta_ok, _ta_err)
try:
    if _ta_ok:
        _ta_c.emit("term_open", {"remote_id": _ta_id, "cols": 80, "rows": 24})
        with app.app_context():
            _opened = _SPAudit.query.filter_by(action="terminal_open",
                                               target=_ta_name).first()
        check("terminal audit: opening a session writes a row naming the host",
              _opened is not None,
              "no terminal_open row for %r — the feature claims one per session" % (_ta_name,))
        _ta_c.emit("term_input", {"data": _TERM_SECRET})
        _wrote = [w for s_ in _fake_sessions.values() for w in s_.writes]
        check("terminal audit: ...and the keystrokes really did reach the session",
              _TERM_SECRET in _wrote,
              "the input event did nothing, so the next check would pass vacuously: %r"
              % (_wrote,))
        with app.app_context():
            _leaked = [r.id for r in _SPAudit.query.all()
                       if _TERM_SECRET in ((r.detail or "") + (r.target or "")
                                           + (r.action or ""))]
        check("terminal audit: ...and NOTHING typed is written to the audit log",
              not _leaked,
              "what was typed into the terminal appears in audit row(s) %r — people type "
              "passwords into terminals" % (_leaked,))
        _ta_c.disconnect()
        with app.app_context():
            _closed = _SPAudit.query.filter_by(action="terminal_close",
                                               target=_ta_name).first()
        check("terminal audit: a disconnect writes the closing row",
              _closed is not None,
              "no terminal_close row — the socket_hooks chain did not reach the terminal, "
              "which is exactly what a second disconnect handler would cause")
finally:
    (_tsmod.open_session, _tsmod.get, _tsmod.close_for_sid) = _ts_saved
    try:
        if _ta_c is not None and _ta_c.is_connected():
            _ta_c.disconnect()
    except Exception:
        pass
    with app.app_context():
        _row = db.session.get(RemoteServer, _ta_id)
        if _row is not None:
            db.session.delete(_row)
            db.session.commit()

# ── a terminal on the PANEL'S OWN host is superadmin-only, whatever the grants say ──────────
# A shell there runs as the account that owns panel.db, secret_key and cred_key, so it is the
# panel itself. It was reachable with USE_TERMINAL plus any group granting the panel host —
# two ordinary, delegable grants that together added up to superadmin. The page route, the
# term_open event and the per-keystroke re-check all refuse it now; a REMOTE stays reachable
# on the same grants (the positive controls), since the panel is root there by design.
import panel.routes.host_terminal as _htmod
_lt_sessions = {}


def _lt_open(sid, server, is_local, user_key, on_output, on_exit, cols=80, rows=24):
    _lt_sessions[sid] = _FakeTermSess()
    _lt_sessions[sid].host = server.id
    return _lt_sessions[sid]


with app.app_context():
    _lt_local = RemoteServer(name="smoke-lt-local", host="127.0.0.1", port=22,
                             username="panel", auth_method="local", auth_credential="",
                             is_local=True)
    _lt_remote = RemoteServer(name="smoke-lt-remote", host="192.0.2.77", port=22,
                              username="root", auth_method="key", auth_credential="",
                              is_local=False)
    db.session.add_all([_lt_local, _lt_remote])
    db.session.flush()
    _lt_grp = Group(name="smoke-term-both", description="", is_default=False)
    _lt_grp.set_permissions([auth.USE_TERMINAL, auth.MANAGE_REMOTES])
    _lt_grp.servers.append(_lt_local)
    _lt_grp.servers.append(_lt_remote)
    db.session.add(_lt_grp)
    db.session.flush()
    _lt_u = User(username="smoke-term-deleg", password_hash=auth.hash_password("Str0ng!passw0rd"),
                 is_superadmin=False, is_active=True)
    _lt_u.groups.append(_lt_grp)
    db.session.add(_lt_u)
    db.session.commit()
    _lt_lid, _lt_rid, _lt_uid, _lt_gid = _lt_local.id, _lt_remote.id, _lt_u.id, _lt_grp.id
_tsmod.open_session = _lt_open
_tsmod.get = lambda sid: _lt_sessions.get(sid)
_tsmod.close_for_sid = lambda sid, reason="": _lt_sessions.pop(sid, None)
_lt_c = _lt_c2 = None
try:
    _lt_http = client_as(_lt_uid)
    _lt_pg = _lt_http.get("/terminal/%d" % _lt_lid, headers={"Accept": "application/json"})
    check("terminal: a non-superadmin with use_terminal and a panel-host grant is refused the "
          "panel host's terminal PAGE", _lt_pg.status_code == 403,
          "status=%d — the page offers a shell as the account that owns panel.db and the keys"
          % _lt_pg.status_code)
    _lt_pr = _lt_http.get("/terminal/%d" % _lt_rid)
    check("terminal: ...while the same grants still reach a REMOTE's terminal page "
          "(positive control)", _lt_pr.status_code == 200, "status=%d" % _lt_pr.status_code)
    # The panel records no input, but the shell is an ordinary interactive one and writes its
    # own history on the host. "Nothing typed here is recorded" was stated as absolute, on the
    # page where operators type secrets.
    _lt_prt = _lt_pr.get_data(as_text=True)
    check("terminal: the page does not promise nothing typed is kept — the shell's own "
          "history is",
          "Nothing typed here is recorded" not in _lt_prt and "command history" in _lt_prt,
          "the page still says nothing is recorded while ~/.bash_history is written")
    # xterm's DOM renderer gives each colour run its own <span>, and the catalog walker swaps
    # any text node equal to a key: a French viewer saw the host print ERREUR.
    _lt_mount = _re_ab.search(r'<div[^>]*\bid="terminal"[^>]*>', _lt_prt)
    check("terminal: the xterm mount point is exempt from the translation walker",
          _lt_mount is not None and "data-no-i18n" in _lt_mount.group(0),
          "mount tag: %r — host output gets translated" % (_lt_mount and _lt_mount.group(0)))
    import panel.ops.system_ops as _lt_so
    _lt_gss = _lt_so.get_server_status
    _lt_so.get_server_status = lambda force=False: None      # reads THIS machine; not the question
    try:
        _lt_mg = _lt_http.get("/remote/%d/manage" % _lt_lid).get_data(as_text=True)
        _lt_mr = _lt_http.get("/remote/%d/manage" % _lt_rid).get_data(as_text=True)
    finally:
        _lt_so.get_server_status = _lt_gss
    check("terminal: ...and the manage page hides the panel host's terminal card from them",
          ("/terminal/%d" % _lt_lid) not in _lt_mg and ("/terminal/%d" % _lt_rid) in _lt_mr,
          "local card shown=%s, remote card shown=%s"
          % (("/terminal/%d" % _lt_lid) in _lt_mg, ("/terminal/%d" % _lt_rid) in _lt_mr))

    _lt_c = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
    _lt_c.emit("term_open", {"remote_id": _lt_lid, "cols": 80, "rows": 24})
    _lt_err = [e for e in _lt_c.get_received() if e.get("name") == "term_error"]
    check("terminal: ...and term_open on the panel host opens NO shell for them",
          not any(getattr(v, "host", None) == _lt_lid for v in _lt_sessions.values())
          and _lt_err and _htmod.LOCAL_HOST_REFUSAL in str(_lt_err[0].get("args")),
          "sessions=%r errors=%r" % ({k: getattr(v, "host", None)
                                      for k, v in _lt_sessions.items()}, _lt_err))
    _lt_c.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
    check("terminal: ...while term_open on a granted REMOTE does (positive control)",
          any(getattr(v, "host", None) == _lt_rid for v in _lt_sessions.values()),
          "no session on the remote — the gate refuses everything")
    # term_open asks _may_use_terminal itself: a socket event never passes the before_request
    # that sends a must-change-password account to the change page, and carries no permission
    # decorator. With that call gone (in _terminal_target since on_term_open was split) every
    # suite stayed green, while this same account, host grant intact, got a shell on the
    # remote on a handed-over temporary password — or with no use_terminal at all.
    _lt_sessions.clear()
    _lt_c.get_received()
    with app.app_context():
        db.session.get(User, _lt_uid).must_change_password = True
        db.session.commit()
    _lt_c.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
    _lt_err = [e for e in _lt_c.get_received() if e.get("name") == "term_error"]
    check("terminal: term_open refuses an account that must change its password, grant or not",
          not _lt_sessions and _lt_err
          and "permission to open a terminal" in str(_lt_err[0].get("args")),
          "sessions=%r errors=%r" % (list(_lt_sessions), _lt_err))
    with app.app_context():
        db.session.get(User, _lt_uid).must_change_password = False
        db.session.get(Group, _lt_gid).set_permissions([auth.MANAGE_REMOTES])
        db.session.commit()
    _lt_c.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
    _lt_err = [e for e in _lt_c.get_received() if e.get("name") == "term_error"]
    check("terminal: ...and one whose groups no longer grant use_terminal",
          not _lt_sessions and _lt_err
          and "permission to open a terminal" in str(_lt_err[0].get("args")),
          "sessions=%r errors=%r" % (list(_lt_sessions), _lt_err))
    with app.app_context():
        db.session.get(Group, _lt_gid).set_permissions([auth.USE_TERMINAL, auth.MANAGE_REMOTES])
        db.session.commit()
    _lt_c.disconnect()
    _lt_sessions.clear()

    # The per-keystroke re-check asks the same question: a superadmin with a panel-host shell
    # open who is demoted keeps nothing, even though their groups still grant the host.
    with app.app_context():
        db.session.get(User, _lt_uid).is_superadmin = True
        db.session.commit()
    _lt_c2 = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
    _lt_c2.emit("term_open", {"remote_id": _lt_lid, "cols": 80, "rows": 24})
    _lt_c2.emit("term_input", {"data": "before-demotion"})
    _lt_w = [w for v in _lt_sessions.values() for w in v.writes]
    check("terminal: a superadmin's panel-host shell takes keystrokes (control for the next)",
          "before-demotion" in _lt_w, "writes=%r" % (_lt_w,))
    with app.app_context():
        db.session.get(User, _lt_uid).is_superadmin = False
        db.session.commit()
    _htmod._sid_access.clear()          # the 10 s cache, not the question under test
    _lt_c2.emit("term_input", {"data": "after-demotion"})
    _lt_w = [w for v in _lt_sessions.values() for w in v.writes]
    check("terminal: ...and once they are demoted the re-check refuses the panel host, "
          "though a group still grants it",
          "after-demotion" not in _lt_w, "writes=%r" % (_lt_w,))

    # Losing the terminal ITSELF must close the shell, not only refuse the keystroke. When
    # _may_use_terminal() said no, the handlers returned: the shell stayed up and its output
    # kept streaming to the socket until the 15-minute idle sweep. Driven through the real
    # events, with use_terminal taken off the user's only group between two keystrokes.
    _lt_c2.disconnect()
    _lt_sessions.clear()
    _lt_c3 = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
    _lt_c3.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
    _lt_c3.emit("term_input", {"data": "before-revoke"})
    _lt_open3 = [k for k, v in _lt_sessions.items() if getattr(v, "host", None) == _lt_rid]
    check("terminal: a delegated user's remote shell takes keystrokes (control for the next)",
          bool(_lt_open3)
          and "before-revoke" in [w for v in _lt_sessions.values() for w in v.writes],
          "sessions=%r" % (list(_lt_sessions),))
    with app.app_context():
        db.session.get(Group, _lt_gid).set_permissions([auth.MANAGE_REMOTES])
        db.session.commit()
    _lt_c3.get_received()
    _lt_c3.emit("term_input", {"data": "after-revoke"})
    _lt_err3 = [e for e in _lt_c3.get_received() if e.get("name") == "term_error"]
    check("terminal: taking use_terminal away CLOSES the open shell at its next event",
          _lt_open3 and not any(k in _lt_sessions for k in _lt_open3) and _lt_err3,
          "still open=%r, term_error=%r — the keystroke is refused but the shell and its "
          "output stay up for another fifteen minutes"
          % ([k for k in _lt_open3 if k in _lt_sessions], _lt_err3))
    with app.app_context():
        db.session.get(Group, _lt_gid).set_permissions([auth.USE_TERMINAL,
                                                        auth.MANAGE_REMOTES])
        db.session.commit()

    # ...and with NO event at all. A shell following a log is sent nothing, so a check made
    # only when a keystroke arrives never runs for it: the timer sweep has to. Signing the
    # user out everywhere (auth_epoch bumped) must close it on the sweep alone.
    _lt_c4 = app.socketio.test_client(app, flask_test_client=client_as(_lt_uid))
    _lt_before4 = set(_lt_sessions)
    _lt_c4.emit("term_open", {"remote_id": _lt_rid, "cols": 80, "rows": 24})
    _lt_open4 = [k for k in _lt_sessions if k not in _lt_before4]
    with app.app_context():
        _htmod.sweep_revoked_terminals(app, app.socketio)
    check("terminal: the revocation sweep leaves a shell whose login still holds alone "
          "(positive control)",
          bool(_lt_open4) and all(k in _lt_sessions for k in _lt_open4),
          "opened=%r, still open=%r" % (_lt_open4, [k for k in _lt_open4 if k in _lt_sessions]))

    def _lt_revoked_rows():
        return _SPAudit.query.filter_by(action="terminal_close",
                                        detail="terminal access was revoked",
                                        username="smoke-term-deleg").count()
    with app.app_context():
        _lt_aud_before4 = _lt_revoked_rows()
        _lt_u4 = db.session.get(User, _lt_uid)
        _lt_u4.auth_epoch = (_lt_u4.auth_epoch or 0) + 1
        db.session.commit()
    _lt_c4.get_received()
    with app.app_context():
        _htmod.sweep_revoked_terminals(app, app.socketio)
        _lt_aud4 = _lt_revoked_rows() - _lt_aud_before4
    _lt_err4 = [e for e in _lt_c4.get_received() if e.get("name") == "term_error"]
    check("terminal: a shell sent no input is closed by the sweep once its login is revoked",
          _lt_open4 and not any(k in _lt_sessions for k in _lt_open4) and _lt_err4,
          "still open=%r, term_error=%r — its output keeps reaching the signed-out browser"
          % ([k for k in _lt_open4 if k in _lt_sessions], _lt_err4))
    check("terminal: ...and the closing row names the user whose access went",
          _lt_aud4 >= 1, "no new terminal_close row for smoke-term-deleg with that reason")
    for _cl in (_lt_c3, _lt_c4):
        try:
            if _cl.is_connected():
                _cl.disconnect()
        except Exception:
            pass
finally:
    (_tsmod.open_session, _tsmod.get, _tsmod.close_for_sid) = _ts_saved
    for _cl in (_lt_c, _lt_c2):
        try:
            if _cl is not None and _cl.is_connected():
                _cl.disconnect()
        except Exception:
            pass
    with app.app_context():
        _u = db.session.get(User, _lt_uid)
        if _u is not None:
            _u.groups = []
            db.session.delete(_u)
        _g = db.session.get(Group, _lt_gid)
        if _g is not None:
            _g.servers = []
            db.session.delete(_g)
        for _rid in (_lt_lid, _lt_rid):
            _row = db.session.get(RemoteServer, _rid)
            if _row is not None:
                db.session.delete(_row)
        db.session.commit()

# ── the two exemptions that rest on SameSite ─────────────────────────────────────────────
# A WebSocket handshake is NOT subject to the same-origin policy: any page the operator visits
# can open one to the panel, and the browser attaches cookies for the target origin. What
# stops that page getting a console — or, since this branch, a SHELL — is that the session
# cookie is SameSite=Lax and so is not sent cross-site, which leaves the socket's connect gate
# seeing an anonymous client and refusing it.
#
# The socket's origin check is the first layer: with no site_domain and no explicit
# socketio_cors_origins it is same-origin, port included (the 'socket origin' checks below),
# never "*" unless the operator lists it. This cookie is the second layer under it — where the
# check does let a cross-site page through (an operator's "*"), that page still reaches the
# connect gate anonymously — and the CSRF Bearer exemption a few hundred lines above rests on
# it alone. Nothing asserted it. Setting it to "None" — which is what anyone embedding the
# panel in an iframe would reach for — silently removes the floor under both.
check("cookie: the session cookie is SameSite-restricted",
      app.config.get("SESSION_COOKIE_SAMESITE") in ("Lax", "Strict"),
      "SESSION_COOKIE_SAMESITE is %r — the socket connect gate and the CSRF Bearer exemption "
      "both rely on this cookie not being sent cross-site"
      % (app.config.get("SESSION_COOKIE_SAMESITE"),))
check("cookie: ...and is not readable from JavaScript",
      app.config.get("SESSION_COOKIE_HTTPONLY") is True,
      "SESSION_COOKIE_HTTPONLY is %r" % (app.config.get("SESSION_COOKIE_HTTPONLY"),))
# ...and the socket's origin check. Driven through the engineio server the app really built, so
# it covers the wiring too. It was a list fixed at startup — ["https://<site_domain>",
# "http://<site_domain>"], no port, else "*" — so the default direct install (site_domain typed
# into the wizard, browsed on :5000) had every handshake refused, a Settings change needed a
# restart, and with no domain ANY page could complete the handshake.
from panel.core.config import load_config as _lc_cfg, save_config as _sc_cfg
_eio = app.socketio.server.eio


def _sio_ok(origin, scheme="https", host="panel.example.com:5000", **extra):
    _env = dict({"wsgi.url_scheme": scheme, "HTTP_HOST": host, "HTTP_ORIGIN": origin}, **extra)
    return _eio._cors_allowed_origins(_env) in (None, [origin])


_cfg_before = _lc_cfg()
try:
    _sc_cfg(dict(_cfg_before, site_domain="panel.example.com", socketio_cors_origins=None))
    check("socket: a page on the host:port the panel is reached on may connect (site_domain set)",
          _sio_ok("https://panel.example.com:5000"),
          "the default direct install's own origin was refused — no console, no terminal")
    check("socket: ...and so may site_domain, reached through a proxy that rewrote Host",
          _sio_ok("https://panel.example.com", scheme="http", host="127.0.0.1:5000"))
    check("socket: ...and so may the origin a proxy forwards (X-Forwarded-Proto/Host)",
          _sio_ok("https://node.example.ts.net", scheme="http", host="127.0.0.1:5000",
                  HTTP_X_FORWARDED_PROTO="https", HTTP_X_FORWARDED_HOST="node.example.ts.net"))
    check("socket: a page on any other origin may not",
          not _sio_ok("https://evil.example"),
          "a wildcard lets any page complete the handshake, leaving the session cookie as the "
          "only thing between a visited page and a shell")
    _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=None))
    check("socket: with no domain it is same-origin, not '*' — a foreign page is refused",
          not _sio_ok("https://evil.example", scheme="http", host="203.0.113.5:5000"))
    check("socket: ...while plain IP:port access still connects",
          _sio_ok("http://203.0.113.5:5000", scheme="http", host="203.0.113.5:5000"))
    _sc_cfg(dict(_cfg_before, site_domain="later.example", socketio_cors_origins=None))
    check("socket: a site_domain saved at runtime applies without a restart",
          _sio_ok("https://later.example", scheme="http", host="127.0.0.1:5000"))
    _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=["https://only.example"]))
    check("socket: an explicit socketio_cors_origins list still wins",
          _sio_ok("https://only.example") and not _sio_ok("https://panel.example.com:5000"))
    # No domain and NO explicit list: the check above leaves socketio_cors_origins set, and an
    # explicit list wins outright — every case below would then pass or fail for that reason.
    _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=None))
    # Two review fixes changed this check two ways; one survives, and the other's cases are
    # asserted against it here. A SITE ignores the port, so a page on another port of the
    # panel's own address (a game's web map) is same-site: the Lax cookie rides along, and only
    # the port refuses it. Compared as (host, port): a Host with no port takes the ORIGIN's
    # scheme default, so a TLS proxy that forwards the host but not X-Forwarded-Proto still
    # matches — requiring the scheme too refused exactly those proxies, with no message.
    for _so_origin, _so_kw, _so_want, _so_what in (
            ("http://1.2.3.4:8123", dict(scheme="http", host="1.2.3.4:5000"), False,
             "a page on another port of the panel's own address"),
            ("http://127.0.0.1:8123", dict(scheme="http", host="127.0.0.1:5000"), False,
             "...on loopback too"),
            ("https://panel.example.com", dict(scheme="http", host="panel.example.com"), True,
             "TLS proxy forwards Host without X-Forwarded-Proto"),
            ("https://panel.example.com", dict(scheme="http", host="127.0.0.1:5000",
                                               HTTP_X_FORWARDED_HOST="panel.example.com"), True,
             "TLS proxy forwards X-Forwarded-Host without X-Forwarded-Proto"),
            ("https://other.example.ts.net", dict(scheme="http", host="127.0.0.1:5000",
                                                  HTTP_X_FORWARDED_PROTO="https",
                                                  HTTP_X_FORWARDED_HOST="node.example.ts.net"),
             False, "a sibling host on the same site (another tailnet node)"),
            ("https://panel.example.com:8443", dict(scheme="http", host="panel.example.com"),
             False, "another port of a host forwarded without a port"),
            ("http://panel.lan:8123", dict(scheme="http", host="panel.lan:5000"), False,
             "...by hostname too"),
            ("https://panel.lan:8443", dict(scheme="http", host="127.0.0.1:5000",
                                            HTTP_X_FORWARDED_PROTO="https",
                                            HTTP_X_FORWARDED_HOST="panel.lan"), False,
             "...and against the host a proxy forwarded"),
            ("http://1.2.3.4:5000", dict(scheme="http", host="1.2.3.4:5000"), True,
             "the panel's own page"),
            ("https://panel.lan", dict(scheme="https", host="panel.lan:443"), True,
             "an implied default port"),
            ("https://panel.lan", dict(scheme="http", host="127.0.0.1:5000",
                                       HTTP_X_FORWARDED_PROTO="https",
                                       HTTP_X_FORWARDED_HOST="panel.lan"), True,
             "a proxy that forwards the original host and scheme"),
            ("null", dict(scheme="http", host="1.2.3.4:5000"), False, "an opaque origin")):
        check("socket origin: %s is %s" % (_so_what, "accepted" if _so_want else "refused"),
              _sio_ok(_so_origin, **_so_kw) is _so_want, "%r with %r" % (_so_origin, _so_kw))
    # A proxy that rewrites Host to loopback and forwards NOTHING cannot be told from a local
    # page, so with no site_domain it is refused: set site_domain (the README's nginx and
    # Caddy examples, and Tailscale Serve, all forward the host).
    check("socket origin: a proxy that hides the host is refused without a site_domain",
          not _sio_ok("https://panel.lan", scheme="http", host="127.0.0.1:5000"))
    # Aikido 745379243. An explicit "*" answered True before any of the checks above ran, so a
    # page on another port of the panel's own address (same-site: the Lax cookie rides along)
    # or on a sibling tailnet node could open a terminal as whoever was logged in. A "*"
    # anywhere in a list did the same. It is ignored now, with a warning saying what to set.
    _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins="*"))
    import logging as _so_logging

    class _SoWarned(_so_logging.Handler):
        def __init__(self):
            _so_logging.Handler.__init__(self)
            self.got = []

        def emit(self, rec):
            if rec.levelno >= _so_logging.WARNING:
                self.got.append(rec.getMessage())

    _so_h = _SoWarned()
    _so_logging.getLogger("panel.app").addHandler(_so_h)
    try:
        _so_star_other = _sio_ok("http://1.2.3.4:8123", scheme="http", host="1.2.3.4:5000")
        _sio_ok("http://1.2.3.4:8124", scheme="http", host="1.2.3.4:5000")
    finally:
        _so_logging.getLogger("panel.app").removeHandler(_so_h)
    check("socket: an explicit '*' does not admit a page on another port of the panel's address",
          not _so_star_other)
    _so_said = [m for m in _so_h.got if "socketio_cors_origins" in m]
    check("socket: ...and the log says it is ignored and what to set instead, once",
          len(_so_said) == 1 and "site_domain" in _so_said[0], repr(_so_h.got))
    check("socket: ...nor a sibling host on the same tailnet",
          not _sio_ok("https://other.example.ts.net", scheme="http", host="127.0.0.1:5000",
                      HTTP_X_FORWARDED_PROTO="https",
                      HTTP_X_FORWARDED_HOST="node.example.ts.net"))
    check("socket: ...nor any other origin",
          not _sio_ok("https://evil.example", scheme="http", host="1.2.3.4:5000"))
    check("socket: ...while under '*' the panel's own page still connects (control)",
          _sio_ok("http://1.2.3.4:5000", scheme="http", host="1.2.3.4:5000"))
    _sc_cfg(dict(_cfg_before, site_domain="", socketio_cors_origins=["https://only.example", "*"]))
    check("socket: a '*' hidden in a list is not a wildcard either",
          not _sio_ok("http://1.2.3.4:8123", scheme="http", host="1.2.3.4:5000")
          and not _sio_ok("https://evil.example"))
    check("socket: ...and the exact origins in that list still connect (control)",
          _sio_ok("https://only.example"))
finally:
    _sc_cfg(_cfg_before)
# The app's REAL engine.io server, driven over HTTP: its handshake refuses the other-port page
# and still answers the panel's own. Only meaningful when the app came up without a domain,
# which is how this suite builds it; the first check says so if that ever changes.
_so_eio = app.socketio.server.eio
_so_app = sys.modules["app"]   # loaded by `from app import` above
check("socket origin: the running engine.io server was built with the per-request origin check",
      _so_eio.cors_allowed_origins is _so_app._socket_origin_allowed,
      "cors_allowed_origins is %r" % (_so_eio.cors_allowed_origins,))
_so_c = app.test_client()
_so_bad = _so_c.get("/socket.io/?EIO=4&transport=polling", base_url="http://1.2.3.4:5000",
                    headers={"Origin": "http://1.2.3.4:8123"})
_so_ok = _so_c.get("/socket.io/?EIO=4&transport=polling", base_url="http://1.2.3.4:5000",
                   headers={"Origin": "http://1.2.3.4:5000"})
check("socket origin: the live handshake refuses a page on another port of the same address",
      _so_bad.status_code == 400, "status %d %r" % (_so_bad.status_code, _so_bad.data[:80]))
check("socket origin: ...and completes for the panel's own origin (control)",
      _so_ok.status_code == 200, "status %d %r" % (_so_ok.status_code, _so_ok.data[:80]))
# ...and the same two over the live handshake with an operator's "*" in config.json, the case
# Aikido 745379243 is about. Then the ways the panel is really reached, so the fix is known
# not to cost anyone the console: Tailscale Serve at the root and under a mount (it forwards
# the host it was asked for), and a TLS reverse proxy that rewrites Host with site_domain set.
_so_cfg0 = _lc_cfg()


def _so_handshake(cfg_over, base_url, origin, path="/socket.io/", **headers):
    _sc_cfg(dict(_so_cfg0, **cfg_over))
    _r = _so_c.get(path + "?EIO=4&transport=polling", base_url=base_url,
                   headers=dict(headers, Origin=origin))
    return _r.status_code, _r.data[:60]


try:
    _so_star = dict(site_domain="", socketio_cors_origins="*")
    _so_r = _so_handshake(_so_star, "http://1.2.3.4:5000", "http://1.2.3.4:8123")
    check("socket origin: with '*' configured the live handshake still refuses another port",
          _so_r[0] == 400, repr(_so_r))
    _so_r = _so_handshake(_so_star, "http://1.2.3.4:5000", "http://1.2.3.4:5000")
    check("socket origin: ...and still completes for the panel's own origin (control)",
          _so_r[0] == 200, repr(_so_r))
    _so_r = _so_handshake(dict(site_domain="", socketio_cors_origins=None),
                          "http://node.example.ts.net", "https://node.example.ts.net",
                          **{"X-Forwarded-Proto": "https",
                             "X-Forwarded-Host": "node.example.ts.net"})
    check("socket origin: Tailscale Serve at the root still connects",
          _so_r[0] == 200, repr(_so_r))
    _so_r = _so_handshake(dict(site_domain="", socketio_cors_origins=None,
                               tailscale_mount="/lgsm"),
                          "http://node.example.ts.net", "https://node.example.ts.net",
                          path="/lgsm/socket.io/",
                          **{"X-Forwarded-Proto": "https",
                             "X-Forwarded-Host": "node.example.ts.net"})
    check("socket origin: ...and under a /lgsm mount",
          _so_r[0] == 200, repr(_so_r))
    _so_r = _so_handshake(dict(site_domain="panel.example.com", socketio_cors_origins=None),
                          "http://127.0.0.1:5000", "https://panel.example.com")
    check("socket origin: a TLS reverse proxy that rewrites Host connects with site_domain set",
          _so_r[0] == 200, repr(_so_r))
finally:
    _sc_cfg(_so_cfg0)

# ── GHSA-hh39-76g3-wxcx: a LOADED row with an injected account name drives no command ─────────
# The advisory end to end, through the real app. A game_server row whose short_name carries a
# shell payload is written RAW — a tampered restore, a database from before the validator, a
# hand edit: @validates sees none of them — and then everything that builds a command for a
# server runs against it: the pages and polls a browser drives, the synchronous toggles, the
# unattended monitor / player / metrics passes, and Retry install. A CONTROL row with a plain,
# distinctive name goes through the same sweep, so "no command carried the payload" cannot
# pass on a sweep that never reached a command builder at all.
import threading as _gh_thr
import time as _gh_time  # pylint: disable=reimported
from sqlalchemy import text as _gh_sql  # pylint: disable=reimported
from panel.core.panel_state import _install_jobs as _gh_jobs, _install_lock as _gh_jlock
_gh_mon = sys.modules["panel.services.monitoring"]
_gh_appmod = sys.modules["app"]
_GH_MARK = "ghsapwn"
_gh_ids = {}
with app.app_context():
    # The review of the first fix added two more rows: the SCRIPT name injected through
    # game_type (F1 — the console reads built their path from it unchecked) and the PORT
    # stored as text (F3 — the hourly restart line interpolated it raw).
    # The port row is a gmod server: a game with a gamedig type is one whose restart line
    # carries the port at all (csgo has none, so the line would never show it).
    for _gh_k, _gh_col, _gh_val, _gh_port, _gh_gt in (
            ("bad", "short_name", "x; touch /tmp/%s; #" % _GH_MARK, 27881, "csgo"),
            ("ctl", "short_name", "ghsactl", 27882, "csgo"),
            ("type", "game_type", "cs; touch /tmp/%s; #" % _GH_MARK, 27883, "csgo"),
            ("port", "port", "27884; touch /tmp/%s; true" % _GH_MARK, 27884, "gmod")):
        _gh_row = GameServer(remote_id=remote_id, name="ghsa-" + _gh_k, short_name="ghsaseed" + _gh_k,
                             game_type=_gh_gt, port=_gh_port, installed=True, status="online")
        db.session.add(_gh_row)
        db.session.commit()
        _gh_ids[_gh_k] = _gh_row.id
        # Past @validates, exactly as a restored or hand-edited database would be.
        db.session.execute(_gh_sql("UPDATE game_server SET %s = :n WHERE id = :i" % _gh_col),  # nosec B608 - names from a literal tuple
                           {"n": _gh_val, "i": _gh_row.id})
        db.session.commit()
_gh_sent, _gh_sent_lock = [], _gh_thr.Lock()


def _gh_note(text):
    with _gh_sent_lock:
        _gh_sent.append(str(text))


def _gh_noconn(*a, **k):
    raise ConnectionError("no SSH host in this suite")


def _gh_quiesce(before, what):
    """Wait out every thread this block started, so none of them lands in a LATER stub."""
    for _ in range(600):
        _new = [t for t in _gh_thr.enumerate() if t not in before and t.is_alive()]
        if not _new:
            return
        _gh_time.sleep(0.05)
    check("GHSA-hh39 smoke: no thread started by %s outlives it" % what, False,
          "%d still running after 30s" % len(_new))


_gh_saved = {n: getattr(_sm_core, n) for n in ("run_command", "_exec_local_argv", "get_connection",
                                               "_gamedig_host")}
_gh_saved_notify = _gh_appmod.notifications.notify
_gh_threads0 = set(_gh_thr.enumerate())
_gh_status = {}
try:
    # run_privileged is left REAL: on this (remote) host it renders its verb through the real
    # argument table and hands the text to run_command, exactly as it would go over SSH.
    _sm_core.run_command = lambda s, c, **k: (_gh_note(c), ("", "", 0))[1]
    _sm_core._exec_local_argv = lambda argv, **k: (_gh_note(" ".join(map(str, argv))), ("", "", 0))[1]
    _sm_core.get_connection = _gh_noconn
    _sm_core._gamedig_host = lambda s: "127.0.0.1"
    _gh_appmod.notifications.notify = lambda *a, **k: None
    _gh_c = client_as(admin_id)
    for _gh_k, _gh_id in sorted(_gh_ids.items()):
        for _gh_path in ("/", "/api/servers", "/api/server/%d", "/api/server/%d/stats",
                         "/api/server/%d/version", "/api/server/%d/players",
                         "/api/server/%d/playerlist", "/api/server/%d/config",
                         "/api/server/%d/game-config", "/api/server/%d/alerts",
                         "/api/server/%d/mods", "/api/server/%d/browse",
                         "/api/server/%d/file?path=a.cfg", "/api/server/%d/cron",
                         "/api/server/%d/log-timestamps", "/server/%d", "/server/%d/files",
                         "/api/console/%d"):
            _gh_url = _gh_path % _gh_id if "%d" in _gh_path else _gh_path
            _gh_r = _gh_c.get(_gh_url)
            _gh_status[(_gh_k, _gh_url)] = (_gh_r.status_code, _gh_r.get_data(as_text=True)[:400])
        for _gh_path, _gh_body in (("/api/server/%d/autostart", {"enabled": True}),
                                   ("/api/server/%d/daily-restart", {"enabled": True}),
                                   ("/api/server/%d/cron", {"schedule": "@daily", "command": "/bin/true"}),
                                   ("/api/server/%d/cron/run", {"raw": "@daily /bin/true"}),
                                   ("/api/server/%d/action", {"action": "start"})):
            _gh_r = _gh_c.post(_gh_path % _gh_id, json=_gh_body)
            _gh_status[(_gh_k, _gh_path % _gh_id)] = (_gh_r.status_code,
                                                      _gh_r.get_data(as_text=True)[:400])
    with app.app_context():
        _gh_mon._monitor_pass()
    _gh_mon._refresh_player_counts(app)
    _gh_mon._record_metric_samples(app)
    # The console POLLER's tick (review F1): it runs every two seconds for any console someone
    # has open, reading a path built from the row's game_type. First sight is a stat read.
    import types as _gh_types
    import panel.routes.server_files as _gh_sf  # pylint: disable=reimported
    from panel.core.panel_state import _console_offsets as _gh_coffs
    _gh_tick_sent = {}
    for _gh_k in ("type", "ctl"):
        _gh_coffs.pop(_gh_ids[_gh_k], None)
        with _gh_sent_lock:
            _gh_before = len(_gh_sent)
        with app.app_context():
            _gh_sf._console_tick(app, _gh_types.SimpleNamespace(emit=lambda *a, **k: None),
                                 db.session.get(GameServer, _gh_ids[_gh_k]), _gh_ids[_gh_k])
        with _gh_sent_lock:
            _gh_tick_sent[_gh_k] = _gh_sent[_gh_before:]
        _gh_coffs.pop(_gh_ids[_gh_k], None)
    # Retry install takes both names from the stored row — the path a restored backup feeds.
    with app.app_context():
        db.session.execute(_gh_sql("UPDATE game_server SET status='failed', installed=0, "
                                   "install_retryable=1, install_error='' WHERE id IN (:a, :b, :c)"),
                           {"a": _gh_ids["bad"], "b": _gh_ids["ctl"], "c": _gh_ids["type"]})
        db.session.commit()
    for _gh_k in ("bad", "ctl", "type"):
        _gh_r = _gh_c.post("/servers/%d/retry-install" % _gh_ids[_gh_k])
        _gh_status[(_gh_k, "retry-install")] = (_gh_r.status_code, _gh_r.get_data(as_text=True)[:400])
    _gh_quiesce(_gh_threads0, "the sweep")
finally:
    for _gh_n, _gh_v in _gh_saved.items():
        setattr(_sm_core, _gh_n, _gh_v)
    _gh_appmod.notifications.notify = _gh_saved_notify
with _gh_sent_lock:
    _gh_texts = list(_gh_sent)
_gh_leaked = [t for t in _gh_texts if _GH_MARK in t]
check("GHSA-hh39 smoke: no command built for the injected row carries its payload — not from a "
      "page, a poll, a toggle, the monitor passes or Retry install",
      not _gh_leaked, "%d leaked, e.g. %r" % (len(_gh_leaked), _gh_leaked[:1]))
check("GHSA-hh39 smoke F1: the console poller's tick on a row whose game_type is a payload sends "
      "nothing, while the control row's tick sends its stat read",
      not _gh_tick_sent.get("type") and any("stat -c" in t and "ghsactl" in t
                                              for t in _gh_tick_sent.get("ctl") or ()),
      "type=%r ctl=%r" % ([t[:80] for t in _gh_tick_sent.get("type") or ()][:1],
                          [t[:80] for t in _gh_tick_sent.get("ctl") or ()][:1]))
_gh_type_cmds = [t for t in _gh_texts if "ghsaseedtype" in t]
check("GHSA-hh39 smoke F1: ...and the game_type row still ran what does not name its script (the "
      "refusal is per name, not per row)",
      any(t.startswith("sudo -u ghsaseedtype ") for t in _gh_type_cmds),
      "%d command(s) for it: %r" % (len(_gh_type_cmds), [t[:60] for t in _gh_type_cmds[:3]]))
_gh_dr = _gh_status.get(("port", "/api/server/%d/daily-restart" % _gh_ids["port"]), (0, ""))
check("GHSA-hh39 smoke F3: the daily-restart toggle on a row whose port is text is refused, and "
      "says why", "invalid port" in _gh_dr[1], repr(_gh_dr)[:200])
_gh_ctl_cmds = [t for t in _gh_texts if "ghsactl" in t]
check("GHSA-hh39 smoke: ...and the same sweep DID build commands for the control row (it reached "
      "the builders)", len(_gh_ctl_cmds) >= 5 and any(t.startswith("sudo -u ghsactl ") for t in _gh_ctl_cmds),
      "%d control command(s): %r" % (len(_gh_ctl_cmds), [t[:60] for t in _gh_ctl_cmds[:3]]))
with app.app_context():
    _gh_bad_row = db.session.execute(_gh_sql(
        "SELECT status, install_error, install_retryable FROM game_server WHERE id = :i"),
        {"i": _gh_ids["bad"]}).fetchone()
check("GHSA-hh39 smoke: Retry install on the injected row fails at step 1 and says why, with no "
      "retry offered", _gh_bad_row is not None and _gh_bad_row[0] == "failed"
      and "not a plain account name" in (_gh_bad_row[1] or "") and not _gh_bad_row[2],
      repr(_gh_bad_row))
# A refusal may come back as the route's own failure status (the autostart toggle has always
# answered a failed crontab write with 500 and its reason); what must not happen is a CRASH:
# the generic handler's "Internal server error", or Flask's own HTML error page.
_gh_crashed = {k[1]: v for k, v in _gh_status.items() if k[0] in ("bad", "type", "port") and v[0] >= 500
               and ("Internal server error" in v[1] or v[1].lstrip().startswith("<"))}
check("GHSA-hh39 smoke: nothing in the sweep crashed a request for the injected rows",
      len(_gh_status) >= 80 and not _gh_crashed, repr(_gh_crashed)[:300])
_gh_auto = _gh_status.get(("bad", "/api/server/%d/autostart" % _gh_ids["bad"]), (0, ""))
check("GHSA-hh39 smoke: ...and a refused toggle says why, rather than failing silently",
      "invalid account or script name" in _gh_auto[1], repr(_gh_auto)[:200])
with _gh_jlock:
    for _gh_id in _gh_ids.values():
        _gh_jobs.pop(_gh_id, None)
with app.app_context():
    # Raw, like the insert, and the samples the metrics pass wrote go with them: the ORM's
    # after_delete prune does not see a raw DELETE.
    for _gh_tbl, _gh_col in (("metric_sample", "server_id"), ("game_server", "id")):
        db.session.execute(_gh_sql("DELETE FROM %s WHERE %s IN (:a, :b, :c, :d)" % (_gh_tbl, _gh_col)),  # nosec B608 - names from a literal tuple
                           {"a": _gh_ids["bad"], "b": _gh_ids["ctl"], "c": _gh_ids["type"],
                            "d": _gh_ids["port"]})
    db.session.commit()
