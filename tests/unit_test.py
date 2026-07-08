"""Fast unit tests for the pure-logic helpers — no network, no SSH, no live DB.

These lock in the behaviour of the parsing/classification code where subtle bugs
tend to hide: firewall rule grouping + lock-out protection, game-port selection,
password policy, safe int parsing, and secret encryption. Several of these would
have caught real regressions (wrong protocol split, opening non-essential ports,
deleting the last SSH rule, a non-numeric port 500).

    python tests/unit_test.py      # exits 0 if all pass, 1 otherwise
"""
import os
import sys
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import ssh_manager as sm
from app import password_problem, _int_or
from auth import can_access_remote, client_ip

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


# ── perf guard: importing `auth` must NOT compute the ~400ms bcrypt "dummy" hash.
#    It's lazy (computed on the first bad-login attempt, warmed off-thread by init_auth)
#    so panel startup stays fast — a regression here re-adds ~0.4s to every boot. This
#    runs BEFORE the dummy_password_check() call later in this file, which is what
#    actually populates it. ──
check("perf: auth import does no bcrypt work (dummy hash stays lazy)",
      sys.modules["auth"]._DUMMY_BCRYPT_HASH is None)

# ── password policy ───────────────────────────────────────────
check("weak: too short", password_problem("Ab1!") is not None)
check("weak: no upper", password_problem("test1234!@") is not None)
check("weak: no lower", password_problem("TEST1234!@") is not None)
check("weak: no digit", password_problem("TestTest!@") is not None)
check("weak: no symbol", password_problem("TestTest12") is not None)
check("strong password accepted", password_problem("Test1234!@") is None)

# ── safe int parsing (a non-numeric port must not raise) ──────
eq("_int_or valid", _int_or("2222", 22), 2222)
eq("_int_or blank -> default", _int_or("", 22), 22)
eq("_int_or junk -> default", _int_or("abc", 22), 22)
eq("_int_or None -> default", _int_or(None, 5000), 5000)
eq("_int_or whitespace", _int_or("  80 ", 1), 80)

# ── cron manager (pure logic; no crontab touched) ─────────────
# schedule validation
check("cron: 5-field ok", sm._validate_cron("*/5 * * * *", "/bin/true")[0])
check("cron: @daily ok", sm._validate_cron("@daily", "/home/gm/backup.sh")[0])
check("cron: @reboot ok", sm._validate_cron("@reboot", "echo hi")[0])
check("cron: ranges/steps ok", sm._validate_cron("0-30/2 1,3 * * mon-fri", "x")[0])
check("cron: normalises inner ws", sm._validate_cron("0   5  *  *  *", "x")[2] == "0 5 * * * x")
check("cron: 4 fields rejected", not sm._validate_cron("* * * *", "x")[0])
check("cron: bad @shortcut rejected", not sm._validate_cron("@sometimes", "x")[0])
check("cron: empty command rejected", not sm._validate_cron("@daily", "")[0])
check("cron: newline in command rejected", not sm._validate_cron("@daily", "a\nb")[0])
check("cron: embedded CR rejected", not sm._validate_cron("@daily", "a\rb")[0])
check("cron: embedded CR in schedule rejected", not sm._validate_cron("0 5 *\r* *", "x")[0])
check("cron: shell metachars allowed in command", sm._validate_cron("@daily", "a && b | c")[0])
# managed-line detection (must never let the generic editor touch panel entries)
check("cron: autostart is managed",
      sm._cron_line_managed("@reboot /home/gm/gmodserver start > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: maintenance update is managed",
      sm._cron_line_managed("15 5 * * * /home/gm/gmodserver update > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: update-lgsm is managed",
      sm._cron_line_managed("30 5 * * 0 /home/gm/gmodserver update-lgsm > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: daily-restart flag is managed",
      sm._cron_line_managed("0 5 * * * touch /home/gm/.restart-pending", "gm", "gmodserver"))
check("cron: user backup line is NOT managed",
      not sm._cron_line_managed("0 3 * * * /home/gm/backup.sh", "gm", "gmodserver"))

# ── UFW port/protocol validation (both interpolate into a ROOT shell command) ──
eq("ufw: tcp normalises", sm._ufw_proto("tcp"), "tcp")
eq("ufw: UDP case-folds", sm._ufw_proto("UDP"), "udp")
eq("ufw: blank -> both", sm._ufw_proto(""), "both")
eq("ufw: None -> both", sm._ufw_proto(None), "both")
eq("ufw: 'any' -> both", sm._ufw_proto("any"), "both")
check("ufw: injection protocol rejected", sm._ufw_proto("tcp; rm -rf /") is None)
check("ufw: unknown protocol rejected", sm._ufw_proto("sctp") is None)
eq("ufw: valid port coerced to int", sm._ufw_port_int("27015"), 27015)


def _ufw_raises(fn):
    try:
        fn()
        return False
    except (TypeError, ValueError):
        return True


check("ufw: non-numeric port rejected", _ufw_raises(lambda: sm._ufw_port_int("22; reboot")))
check("ufw: port 0 rejected", _ufw_raises(lambda: sm._ufw_port_int(0)))
check("ufw: port 70000 rejected", _ufw_raises(lambda: sm._ufw_port_int(70000)))
# End-to-end: a malicious protocol/port must NOT reach run_command (no shell runs).
_orig_ufw_rc = sm.run_command
try:
    _ufw_calls = []
    sm.run_command = lambda *a, **k: (_ufw_calls.append(a), ("", "", 0))[1]
    _ok, _m = sm.remote_ufw_open_port(None, 27015, "tcp; touch /tmp/x #")
    check("ufw: open rejects injection proto, runs nothing", _ok is False and not _ufw_calls)
    _ok, _m = sm.remote_ufw_close_port(None, "22; reboot", "tcp")
    check("ufw: close rejects injection port, runs nothing", _ok is False and not _ufw_calls)
finally:
    sm.run_command = _orig_ufw_rc

# ── shell-identifier validation (usernames/short_names reach ssh + shell) ──
from models import _validate_shell_ident as _vsi
check("ident: normal value accepted", _vsi("k", "gmodserver") == "gmodserver")
check("ident: internal dash/dot/underscore ok", _vsi("k", "game-1.beta_2") == "game-1.beta_2")
check("ident: empty allowed (optional field)", _vsi("k", "") == "")
check("ident: leading dash rejected (ssh option-injection guard)",
      _ufw_raises(lambda: _vsi("k", "-oProxyCommand=x")))
check("ident: leading dot rejected", _ufw_raises(lambda: _vsi("k", ".hidden")))
check("ident: shell metachar rejected", _ufw_raises(lambda: _vsi("k", "a;b")))

# ── Tailscale bootstrap quotes user-supplied auth_key/routes/tags (root shell) ──
_orig_ts_rc = sm.run_command
try:
    _ts_cmds = []
    sm.run_command = lambda s, c, **k: (_ts_cmds.append(c), ("ok", "", 0))[1]
    sm.remote_bootstrap_tailscale(None, auth_key="tskey; touch /tmp/x",
                                  advertise_routes="1.2.3.0/24; reboot", tags="tag:x; rm -rf /")
    _joined = " ".join(_ts_cmds)
    check("tailscale: auth_key is shell-quoted", sm._quote("tskey; touch /tmp/x") in _joined)
    check("tailscale: routes are shell-quoted", sm._quote("1.2.3.0/24; reboot") in _joined)
    check("tailscale: tags are shell-quoted", sm._quote("tag:x; rm -rf /") in _joined)
finally:
    sm.run_command = _orig_ts_rc
# update/delete must REFUSE a panel-managed line before touching SSH (server=None
# proves no connection is attempted — the guard returns first). This is the security
# invariant that the generic editor can't tamper with autostart/maintenance/restart.
_up = sm.update_cron_job(None, "gm", "@reboot /home/gm/gmodserver start > /dev/null 2>&1",
                         "@daily", "/home/gm/x.sh", "gmodserver")
check("cron: update refuses a managed line (no SSH)", _up[0] is False and "managed" in _up[1])
_dl = sm.delete_cron_job(None, "gm", "0 5 * * * touch /home/gm/.restart-pending", "gmodserver")
check("cron: delete refuses a managed line (no SSH)", _dl[0] is False and "managed" in _dl[1])
# a bad schedule is rejected by update before any SSH too
_bad = sm.update_cron_job(None, "gm", "0 3 * * * /home/gm/backup.sh", "not-a-schedule", "x", "gmodserver")
check("cron: update rejects a bad schedule (no SSH)", _bad[0] is False)
# cron run-history: the recorder wrap/unwrap round-trips, and status files parse.
import base64 as _b64
_ccmd = "/home/gm/backup.sh --full && echo done"
_cjid = sm._cron_job_id(_ccmd)
check("cron: job id is a stable 12-hex hash",
      _cjid == sm._cron_job_id(_ccmd) and len(_cjid) == 12
      and all(c in "0123456789abcdef" for c in _cjid))
_wrapped = "/home/gm/.lgsm-cron/run %s %s" % (_cjid, _b64.b64encode(_ccmd.encode()).decode())
check("cron: unwrap recovers the original command",
      sm._unwrap_cron_command(_wrapped) == (_ccmd, _cjid))
check("cron: unwrap leaves a plain command untouched",
      sm._unwrap_cron_command("/home/gm/x.sh") == ("/home/gm/x.sh", None))
# Managed jobs use the INLINE recorder: the command stays visible (so the grep-based
# managed-line detection/removal still works) and unwraps to the core command + a job id.
_mrec = sm._record_managed_cmd("gm", "/home/gm/gmodserver update")
check("managed cron: wrapped line is still detected as managed",
      sm._cron_line_managed(_mrec, "gm", "gmodserver"))
check("managed cron: wrapped line still matches the maintenance remove-regex (no dup on re-apply)",
      bool(__import__("re").search(r"/home/gm/gmodserver (monitor|mods-update|update|update-lgsm) ", _mrec)))
check("managed cron: unwrap recovers the core command + id",
      sm._unwrap_cron_command(_mrec)
      == ("/home/gm/gmodserver update", sm._cron_job_id("/home/gm/gmodserver update")))
# upgrade_managed_cron_tracking rewraps EXISTING managed lines in place, leaving user jobs and
# the compound restart-check untouched (so old installs get success/error without a reinstall).
_upcap = {}
_orig_rw_u = sm._rewrite_crontab
_orig_run_u = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "*/5 * * * * /home/gm/gmodserver monitor > /dev/null 2>&1\n"
        "@reboot /home/gm/gmodserver start > /dev/null 2>&1\n"
        "0 3 * * * /home/gm/backup.sh\n"
        "10 * * * * [ -f /home/gm/.restart-pending ] && { /home/gm/gmodserver restart; }\n", "", 0)
    sm._rewrite_crontab = lambda s, u, grep, add, extra_pre="": (_upcap.update(add=list(add)) or (True, "ok"))
    _ures = sm.upgrade_managed_cron_tracking(None, "gm", "gmodserver")
    _uadd = _upcap.get("add", [])
    check("cron upgrade: reports a change", _ures is True)
    check("cron upgrade: monitor line wrapped in place", any(
        ln.startswith("*/5 * * * * ") and "/home/gm/gmodserver monitor" in ln and ".status" in ln for ln in _uadd))
    check("cron upgrade: autostart line wrapped in place", any(
        ln.startswith("@reboot ") and "/home/gm/gmodserver start" in ln and ".status" in ln for ln in _uadd))
    check("cron upgrade: user job left untouched", "0 3 * * * /home/gm/backup.sh" in _uadd)
    check("cron upgrade: compound restart-check left untouched", any(
        ln.startswith("10 * * * * [ -f") and ".status" not in ln for ln in _uadd))
finally:
    sm._rewrite_crontab = _orig_rw_u
    sm.run_command = _orig_run_u
_orig_run3 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("aaaaaaaaaaaa\t0\t100\t142\t\n"
                                        "bbbbbbbbbbbb\t1\t200\t205\tboom: exit 1\n", "", 0)
    _cst = sm._read_cron_status(None, "gm")
    check("cron status: a successful run parses (ok + last_run)",
          _cst["aaaaaaaaaaaa"]["ok"] is True and _cst["aaaaaaaaaaaa"]["last_run"] == 142)
    check("cron status: a failed run parses with its error tail",
          _cst["bbbbbbbbbbbb"]["ok"] is False and _cst["bbbbbbbbbbbb"]["error"] == "boom: exit 1")
finally:
    sm.run_command = _orig_run3
# cron run-times from the journald cron log (last-run TIME for managed/legacy jobs)
_orig_run4 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "1720000000 host CRON[11]: (gm) CMD (/home/gm/gmodserver monitor > /dev/null 2>&1)\n"
        "1720003600 host CRON[12]: (gm) CMD (/home/gm/gmodserver monitor > /dev/null 2>&1)\n"
        "1720007200 host CRON[13]: (gm) CMD (touch /home/gm/.restart-pending)\n", "", 0)
    _rt = sm._read_cron_run_times(None, "gm")
    check("cron run-times: newest run wins for a repeated command",
          _rt["/home/gm/gmodserver monitor > /dev/null 2>&1"] == 1720003600)
    check("cron run-times: parses a second distinct command",
          _rt["touch /home/gm/.restart-pending"] == 1720007200)
finally:
    sm.run_command = _orig_run4
# _match_run_time: a wrapped job's CORE command matches its logged line (old or wrapped form),
# so a freshly-upgraded job shows its run time instead of "—" until the recorder status lands.
_rtm = {"/home/gm/gmodserver monitor > /dev/null 2>&1": 100,
        "mkdir -p /home/gm/.lgsm-cron && /home/gm/gmodserver monitor > /home/gm/.lgsm-cron/ab.log 2>&1": 200}
check("run-time match: core command matches wrapped/old log line (newest wins)",
      sm._match_run_time(_rtm, "/home/gm/gmodserver monitor") == 200)
check("run-time match: exact command matches",
      sm._match_run_time({"touch /home/gm/.restart-pending": 50}, "touch /home/gm/.restart-pending") == 50)
check("run-time match: no match returns None",
      sm._match_run_time({"a b c": 1}, "/home/gm/nothing") is None)
# run_cron_job_now: runs the job's UNWRAPPED core command, detached, as the game user, and
# records to the job's own status file (so Last-run updates).
import base64 as _b64rn, re as _rern
_wl = ("*/5 * * * * /home/gm/.lgsm-cron/run " + sm._cron_job_id("/home/gm/backup.sh --full")
       + " " + _b64rn.b64encode(b"/home/gm/backup.sh --full").decode())
_rncap = {}
_orig_run6 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_rncap.update(cmd=c), ("", "", 0))[1]
    _rok, _ = sm.run_cron_job_now(None, "gm", _wl, "gmodserver")
    _c = _rncap["cmd"]
    check("run now: dispatched ok", _rok is True)
    check("run now: detached run as the game user",
          "sudo -u gm bash -c" in _c and "setsid bash" in _c)
    _m = _rern.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d", _c)
    _rec = _b64rn.b64decode(_m.group(1)).decode() if _m else ""
    check("run now: runs the unwrapped core command", "/home/gm/backup.sh --full >" in _rec)
    check("run now: records to the job's own status file",
          ("/home/gm/.lgsm-cron/" + sm._cron_job_id("/home/gm/backup.sh --full") + ".status") in _rec)
finally:
    sm.run_command = _orig_run6

# ── backup module: create / list / prune + path-traversal guard ──
import backup as _bk
import tempfile as _tf, sqlite3 as _sq, pathlib as _pl, os as _osb, tarfile as _tar, shutil as _sh2
_bktmp = _pl.Path(_tf.mkdtemp())
_bk.BACKUP_DIR = _bktmp / "backups"; _bk.DATA_DIR = _bktmp; _bk.DB_PATH = _bktmp / "panel.db"
_bk.CONFIG_FILE = _bktmp / "config.json"; _bk.SECRET_FILE = _bktmp / "secret_key"; _bk.CRED_KEY_FILE = _bktmp / "cred_key"
_dbc = _sq.connect(str(_bk.DB_PATH)); _dbc.execute("create table t(x)"); _dbc.commit(); _dbc.close()
_bk.CONFIG_FILE.write_text("{}"); _bk.SECRET_FILE.write_text("s"); _bk.CRED_KEY_FILE.write_text("k")
_bok, _bname = _bk.create_backup("manual")
check("backup: create returns a valid name", _bok and bool(_bk._NAME_RE.match(_bname)))
_blist = _bk.list_backups()
check("backup: appears in the list as 'manual'",
      len(_blist) == 1 and _blist[0]["kind"] == "manual" and _blist[0]["size"] > 0)
with _tar.open(_bk.BACKUP_DIR / _bname) as _t:
    check("backup: archive holds db+config+keys",
          set(_t.getnames()) == {"panel.db", "config.json", "secret_key", "cred_key"})
check("backup: _safe_path allows a real backup, rejects traversal/junk",
      _bk._safe_path(_bname) is not None and _bk._safe_path("../../etc/passwd") is None
      and _bk._safe_path("panel-backup-x.tar.gz") is None)
_old = _bk.BACKUP_DIR / "panel-backup-20000101-000000-daily.tar.gz"
_sh2.copy(_bk.BACKUP_DIR / _bname, _old); _osb.utime(_old, (0, 0))
check("backup: prune drops an old DAILY backup but keeps the manual one",
      _bk.prune_backups(7) == 1 and all(b["kind"] != "daily" for b in _bk.list_backups()))
_sh2.rmtree(_bktmp, ignore_errors=True)

# ── per-server backup schedules (config-backed; swap in an in-memory config) ──
_sched_load, _sched_save = _bk.load_config, _bk.save_config
_fakecfg = {}
_bk.load_config = lambda: dict(_fakecfg)
_bk.save_config = lambda c: (_fakecfg.clear(), _fakecfg.update(c))
try:
    _d = _bk.get_game_schedule(4242)
    check("schedule: unset server inherits the global default",
          _d["overridden"] is False and _d["interval_set"] is False and _d["keep"] == _bk.DEFAULT_FULL_KEEP)
    _bk.set_game_schedule(4242, 1, 5)
    _o = _bk.get_game_schedule(4242)
    check("schedule: override sets interval + keep",
          _o["interval_days"] == 1 and _o["keep"] == 5 and _o["interval_set"] and _o["keep_set"])
    check("schedule: due immediately when never run", _bk.game_backup_due(4242) is True)
    _bk.record_game_backup(4242)
    check("schedule: not due right after a run", _bk.game_backup_due(4242) is False)
    _bk.set_game_schedule(4242, 0, None)   # interval 0 = off for this server, keep back to default
    check("schedule: interval 0 disables and keep falls back to default",
          _bk.game_backup_due(4242) is False and _bk.get_game_schedule(4242)["keep"] == _bk.DEFAULT_FULL_KEEP)
    _bk.set_game_schedule(4242, None, None)
    check("schedule: clearing the override returns to inherit",
          _bk.get_game_schedule(4242)["overridden"] is False)
    # corrupted config (game_schedules not a dict, or an entry not a dict) must not crash —
    # it should degrade to the global default, and set/record must repair it.
    for _i, _bad in enumerate(({"game_schedules": "notadict"}, {"game_schedules": {"4242": "notadict"}},
                               {"game_schedules": {"4242": {"interval_days": "x", "keep": None, "last": "y"}}})):
        _fakecfg.clear(); _fakecfg.update(_bad)
        _s = _bk.get_game_schedule(4242)   # must not raise; garbage values clamp to sane defaults
        check("schedule: corrupted config degrades safely (case %d)" % _i,
              _s["keep"] == _bk.DEFAULT_FULL_KEEP and isinstance(_s["interval_days"], int)
              and _bk.game_backup_due(4242) in (True, False))
        _bk.record_game_backup(4242)   # must not raise on a corrupted entry
    # remove_game_schedule (uninstall cleanup) drops the entry entirely, and is a safe no-op on
    # a missing/corrupted map.
    _fakecfg.clear(); _fakecfg.update({"game_schedules": {"77": {"interval_days": 7, "last": 1}}})
    _bk.remove_game_schedule(77)
    check("schedule: remove_game_schedule drops the entry",
          "77" not in _fakecfg.get("game_schedules", {}))
    _fakecfg.clear(); _fakecfg.update({"game_schedules": "corrupt"})
    _bk.remove_game_schedule(77)   # must not raise on a corrupted map
    check("schedule: remove_game_schedule is a safe no-op on junk", True)
finally:
    _bk.load_config, _bk.save_config = _sched_load, _sched_save

# ── full (game-file) backups: per-server LinuxGSM backup + settings/due ──
_orig_run7 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "F\tgmodserver-2026.tar.gz\t1048576\t1720000000\nF\told.tar.gz\t500\t1719000000\n", "", 0)
    _gbl = sm.list_game_backups(None, "gm")
    check("game backups: parsed newest-first with sizes",
          len(_gbl) == 2 and _gbl[0]["name"] == "gmodserver-2026.tar.gz" and _gbl[0]["size"] == 1048576)
    check("game backups: no lock -> nothing marked in-progress",
          not any(b.get("in_progress") for b in _gbl))
    # Lock present + a NEW archive written after the backup started (lock mtime 1720000050) -> that
    # new one is in-progress; the pre-existing older backup is not.
    sm.run_command = lambda s, c, **k: (
        "F\tgmodserver-new.tar.zst\t2000\t1720000100\nF\tgmodserver-old.tar.zst\t1048576\t1720000000\n"
        "LOCK\t1720000050.5\n", "", 0)
    _gbl2 = sm.list_game_backups(None, "gm")
    check("game backups: active lock flags the new archive in-progress only",
          _gbl2[0]["name"] == "gmodserver-new.tar.zst" and _gbl2[0].get("in_progress") is True
          and not _gbl2[1].get("in_progress"))
    # Early in a backup (lock present, new archive not created yet): the existing backup predates the
    # lock, so it must NOT be flagged/hidden — this is the "existing backup disappears" regression.
    sm.run_command = lambda s, c, **k: (
        "F\tgmodserver-old.tar.zst\t1048576\t1720000000\nLOCK\t1720000050.5\n", "", 0)
    _gbl3 = sm.list_game_backups(None, "gm")
    check("game backups: a pre-existing backup isn't hidden while a new one is starting",
          len(_gbl3) == 1 and not _gbl3[0].get("in_progress"))
finally:
    sm.run_command = _orig_run7
_cap7 = {"cmds": []}
_orig_run8 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_cap7["cmds"].append(c), ("", "", 0))[1]
    _gok, _, _gskip = sm.run_game_backup(None, "gm", "gmodserver", 2)
    _joined = " ".join(_cap7["cmds"])
    check("run_game_backup: runs LinuxGSM backup as the game user",
          _gok is True and _gskip is False and "sudo -u gm bash -c" in _joined and "./gmodserver backup" in _joined)
    check("run_game_backup: prunes to keep N (keep=2 -> tail +3)", "tail -n +3" in _joined)
finally:
    sm.run_command = _orig_run8

# ── players-online guard: don't kick players for a backup unless forced ──
_orig_run8b = sm.run_command
try:
    # gamedig query reports 2 players; the LinuxGSM backup command must NOT run.
    def _run_busy(s, c, **k):
        if "gamedig" in c:
            return ("2", "", 0)
        return ("", "", 0)
    _cap_busy = {"cmds": []}
    sm.run_command = lambda s, c, **k: (_cap_busy["cmds"].append(c), _run_busy(s, c, **k))[1]
    _pc = sm.player_count(None, "gm", "gmod", 27015)
    check("player_count: parses gamedig player count", _pc == 2)
    _bok, _bmsg, _bskip = sm.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: skips (no backup) when players are online",
          _bok is False and _bskip is True and "backup" not in " ".join(c for c in _cap_busy["cmds"] if "gamedig" not in c))
    # force=True backs up anyway even with players on
    _cap_busy["cmds"] = []
    _fok, _fmsg, _fskip = sm.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015, force=True)
    check("run_game_backup: force=True backs up even with players online",
          _fok is True and _fskip is False and "./gmodserver backup" in " ".join(_cap_busy["cmds"]))
finally:
    sm.run_command = _orig_run8b

# ── empty/unqueryable server: player_count None, backup proceeds ──
_orig_run8c = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("0", "", 0) if "gamedig" in c else ("", "", 0)
    check("player_count: 0 players -> 0", sm.player_count(None, "gm", "gmod", 27015) == 0)
    check("player_count: unmapped game -> None (unknown)", sm.player_count(None, "gm", "nosuchgame", 27015) is None)
    check("player_count: no port -> None", sm.player_count(None, "gm", "gmod", None) is None)
    _eok, _emsg, _eskip = sm.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: empty server backs up normally", _eok is True and _eskip is False)
finally:
    sm.run_command = _orig_run8c

# ── 'Lockfile found' (LinuxGSM exits 0 but made no backup) must NOT read as success ──
_orig_lock = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("[ INFO ] Backup gmodserver: Lockfile found: Backup is currently running", "", 0)
    _lok, _lmsg, _lskip = sm.run_game_backup(None, "gm", "gmodserver", 2)
    check("run_game_backup: 'Lockfile found' at exit 0 is treated as failure",
          _lok is False and _lskip is False and "lock" in _lmsg.lower())
finally:
    sm.run_command = _orig_lock

# ── pre-flight disk guard: don't start a doomed backup when the disk is full ──
check("_fmt_size: bytes/MB/GB readable",
      sm._fmt_size(0) == "0 B" and sm._fmt_size(512) == "512 B"
      and sm._fmt_size(5 * 1024 * 1024) == "5.0 MB" and sm._fmt_size(2 * 1024 ** 3) == "2.0 GB")
_hs_saved = (sm._ensure_backup_headroom, sm.list_game_backups, sm.backup_disk_info, sm.run_command)
try:
    _GB2 = 1024 ** 3
    sm._ensure_backup_headroom = lambda s, u, k: ""       # nothing left to free
    sm.list_game_backups = lambda s, u: [{"name": "b-1", "size": int(1.2 * _GB2), "created": 1}]
    sm.backup_disk_info = lambda s, u: {"free": 22 * 1024 * 1024, "total": 23 * _GB2}   # ~22 MB free
    _pf_cmds = []
    sm.run_command = lambda s, c, **k: (_pf_cmds.append(c), ("", "", 0))[1]
    _pok, _pmsg, _pskip = sm.run_game_backup(None, "cs", "codserver", 2)
    check("run_game_backup: full disk -> clear 'Not enough disk space' failure, no backup run",
          _pok is False and _pskip is False and "Not enough disk space" in _pmsg
          and not any("./codserver backup" in c for c in _pf_cmds))
finally:
    (sm._ensure_backup_headroom, sm.list_game_backups, sm.backup_disk_info, sm.run_command) = _hs_saved

# ── mod-restart decision (pure): restart when empty, defer when busy/unknown, force wins ──
check("mod_restart_decision: stopped server -> idle (loads on next start)",
      sm.mod_restart_decision("offline", None) == "idle")
check("mod_restart_decision: online + empty -> restart now",
      sm.mod_restart_decision("online", 0) == "restart")
check("mod_restart_decision: online + players -> pending (don't kick)",
      sm.mod_restart_decision("online", 3) == "pending")
check("mod_restart_decision: online + unknown count -> pending (can't confirm empty)",
      sm.mod_restart_decision("online", None) == "pending")
check("mod_restart_decision: unknown status -> pending",
      sm.mod_restart_decision("unknown", None) == "pending")
check("mod_restart_decision: force restarts even with players online",
      sm.mod_restart_decision("online", 5, force=True) == "restart")
check("mod_restart_decision: force on a stopped server stays idle (nothing to restart)",
      sm.mod_restart_decision("offline", 5, force=True) == "idle")

# ── smart headroom: free space before a backup only when the disk is tight ──
_hr_saved = (sm.list_game_backups, sm.backup_disk_info, sm.delete_game_backup)
try:
    _GB = 1024 ** 3
    _hr_deleted = []
    sm.delete_game_backup = lambda s, u, name: (_hr_deleted.append(name), True)[1]
    _three = [{"name": "g-3", "size": 4 * _GB, "created": 300},
              {"name": "g-2", "size": 4 * _GB, "created": 200},
              {"name": "g-1", "size": 4 * _GB, "created": 100}]
    sm.list_game_backups = lambda s, u: list(_three)
    # plenty of room -> no deletion
    sm.backup_disk_info = lambda s, u: {"free": 57 * _GB, "total": 60 * _GB}
    _hr_deleted[:] = []
    _n1 = sm._ensure_backup_headroom(None, "gm", 2)
    check("headroom: with free disk, nothing is deleted", _hr_deleted == [] and _n1 == "")
    # tight -> delete oldest first, protect the newest (keep-1)
    sm.backup_disk_info = lambda s, u: {"free": 1 * _GB, "total": 60 * _GB}
    _hr_deleted[:] = []
    _n2 = sm._ensure_backup_headroom(None, "gm", 2)
    check("headroom: tight disk frees the OLDEST backup first, protects newest",
          _hr_deleted[:1] == ["g-1"] and "g-3" not in _hr_deleted and _n2)
    # no backups yet -> nothing to free
    sm.list_game_backups = lambda s, u: []
    _hr_deleted[:] = []
    check("headroom: no backups yet -> no deletion", sm._ensure_backup_headroom(None, "gm", 2) == "" and _hr_deleted == [])
    # 0-byte newest is a failed backup (junk): delete it first, protect the good older one, and
    # estimate from the LARGEST (so a 0-byte newest doesn't make it skip on a full disk).
    sm.list_game_backups = lambda s, u: [{"name": "junk", "size": 0, "created": 300},
                                         {"name": "good", "size": 226 * _GB, "created": 200}]
    sm.backup_disk_info = lambda s, u: {"free": 50 * 1024 * 1024, "total": 25 * _GB}
    _hr_deleted[:] = []
    sm._ensure_backup_headroom(None, "pmc", 2)
    check("headroom: deletes 0-byte junk first, protects the valid backup",
          _hr_deleted == ["junk"])
finally:
    sm.list_game_backups, sm.backup_disk_info, sm.delete_game_backup = _hr_saved

_fake_cfg = {}
_orig_bkload, _orig_bksave = _bk.load_config, _bk.save_config
_bk.load_config = lambda: dict(_fake_cfg); _bk.save_config = lambda c: _fake_cfg.update(c)
try:
    _fs = _bk.set_full_settings(interval_days=7, keep=2)
    check("full backup: settings save round-trip", _fs["interval_days"] == 7 and _fs["keep"] == 2)
    check("full backup: due when never run", _bk.full_backup_due() is True)
    _bk.record_full_backup("2 server(s) backed up")
    check("full backup: not due right after a run", _bk.full_backup_due() is False)
    _bk.set_full_settings(interval_days=0)
    check("full backup: interval 0 = off (never due)", _bk.full_backup_due() is False)
finally:
    _bk.load_config, _bk.save_config = _orig_bkload, _orig_bksave

# ── alerts: lgsm_get_values reads merged config, instance overrides win ──
_orig_run9 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        'discordalert="off"\ndiscordwebhook="default"\nemailalert="on"\n'
        'discordalert="on"\ndiscordwebhook="https://x/hook"\n', "", 0)
    _av = sm.lgsm_get_values(None, "gm", "gmodserver",
                             ["discordalert", "discordwebhook", "emailalert", "missingkey"])
    check("lgsm_get_values: later (instance) value wins",
          _av["discordwebhook"] == "https://x/hook" and _av["discordalert"] == "on")
    check("lgsm_get_values: reads other toggles; missing key -> empty",
          _av["emailalert"] == "on" and _av["missingkey"] == "")
finally:
    sm.run_command = _orig_run9

# line splitting
eq("cron: split 5-field", sm._split_cron_line("0 3 * * * /home/gm/b.sh a"), ("0 3 * * *", "/home/gm/b.sh a"))
eq("cron: split @shortcut", sm._split_cron_line("@reboot /home/gm/x start"), ("@reboot", "/home/gm/x start"))
eq("cron: split rejects short line", sm._split_cron_line("0 3 * *"), (None, None))

# ── anti-lockout: disabling public SSH must be refused with no Tailscale path back in ──
_orig_rc = sm.run_command
def _rc_no_tailnet(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Stopped"}', "", 0)   # Tailscale not running
    return ("", "", 0)
sm.run_command = _rc_no_tailnet
_ok, _msg = sm.remote_set_public_ssh(object(), "off")
check("ssh off REFUSED when no Tailscale path (anti-lockout)", _ok is False and "lock you out" in _msg.lower())

def _rc_ts_ssh(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Running"}', "", 0)
    if "debug prefs" in cmd:
        return ('{"RunSSH": true}', "", 0)                # Tailscale SSH enabled
    return ("", "", 0)
sm.run_command = _rc_ts_ssh
check("ssh off ALLOWED when Tailscale SSH enabled", sm.remote_set_public_ssh(object(), "off")[0] is True)

def _rc_iface(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Running"}', "", 0)
    if "debug prefs" in cmd:
        return ('{"RunSSH": false}', "", 0)
    if "ufw status" in cmd:
        return ("Anywhere on tailscale0     ALLOW IN    Anywhere", "", 0)  # tailscale0 allowed
    return ("", "", 0)
sm.run_command = _rc_iface
check("ssh off ALLOWED when tailscale0 allowed in UFW", sm.remote_set_public_ssh(object(), "off")[0] is True)

sm.run_command = lambda *a, **k: ("", "", 0)
check("ssh allow is never lockout-guarded", sm.remote_set_public_ssh(object(), "allow")[0] is True)
check("ssh limit is never lockout-guarded", sm.remote_set_public_ssh(object(), "limit")[0] is True)
sm.run_command = _orig_rc

# ── secret encryption round-trip ──────────────────────────────
_pre = {p for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE)
        if os.path.exists(p)}
enc = config.encrypt_secret("hunter2")
check("encrypt adds enc: prefix", enc.startswith("enc:v1:"))
check("is_encrypted true for ciphertext", config.is_encrypted(enc))
eq("decrypt round-trips", config.decrypt_secret(enc), "hunter2")
eq("encrypt empty -> empty", config.encrypt_secret(""), "")
eq("decrypt legacy plaintext passthrough", config.decrypt_secret("plainpw"), "plainpw")

# ── UFW rule grouping: port / protocol split ──────────────────
def _rules(rs):
    return [{"num": str(i + 1), "detail": d} for i, d in enumerate(rs)]


groups = sm._group_ufw_rules(_rules([
    "22/tcp  ALLOW IN  Anywhere",
    "22/tcp (v6)  ALLOW IN  Anywhere (v6)",
    "5000/tcp  ALLOW IN  Anywhere",
    "28960  ALLOW IN  Anywhere  # codserver",
    "27015/udp  ALLOW IN  Anywhere",
]))
by_port = {g["port_num"]: g for g in groups}
eq("22 -> TCP", by_port["22"]["proto_label"], "TCP")
eq("22 merges v4+v6", by_port["22"]["family_label"], "IPv4 + IPv6")
eq("bare port -> BOTH", by_port["28960"]["proto_label"], "BOTH")
eq("bare port keeps comment", by_port["28960"]["comment"], "codserver")
eq("udp suffix -> UDP", by_port["27015"]["proto_label"], "UDP")

# ── firewall lock-out protection ──────────────────────────────
def protect(server, rules, enabled=True, cfg=None, is_local=False, tailscale=(False, False)):
    sm.is_local_server = lambda s: is_local
    sm._tailscale_conn_state = lambda s: tailscale   # (running, ssh_enabled) — deterministic in tests
    if cfg is not None:
        config.load_config = lambda: cfg
    return sm._annotate_firewall_protection(server, enabled, sm._group_ufw_rules(_rules(rules)))


# SSH-only: port 22 is the last way in -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("SSH-only: 22 protected", gp["22"]["protected"])
check("SSH-only: game port not protected", not gp["28960"]["protected"])

# A rate-limited SSH rule (`ufw limit`, action LIMIT — now the default) is still SSH access,
# and the only way in here -> protected. Regression: LIMIT != ALLOW was letting it be deleted.
g = protect(NS(port=22), ["22/tcp LIMIT IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("LIMIT SSH rule recognised as SSH", gp["22"]["is_ssh"])
check("LIMIT SSH rule protected as the only way in", gp["22"]["protected"])

# Custom SSH port + a tailscale0 rule, WITH Tailscale actually running -> two real ways in
# -> the SSH rule can be removed (warn); custom port recognised as SSH.
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"], tailscale=(True, False))
gp = {x["port_num"]: x for x in g}
check("custom 2222 recognised as SSH", gp["2222"]["is_ssh"])
check("2222 warn when Tailscale is up (another way in)", gp["2222"]["warn"] and not gp["2222"]["protected"])

# Same rules but Tailscale is DOWN -> the tailscale0 rule is no real route -> 2222 is the only
# way in and must be PROTECTED (the reported bug: don't let me delete SSH with no tailnet path).
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"], tailscale=(False, False))
gp = {x["port_num"]: x for x in g}
check("2222 protected when Tailscale is down (no real fallback)", gp["2222"]["protected"])

# Tailscale SSH enabled -> a guaranteed way in -> the sole SSH rule can be removed (warn).
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere"], tailscale=(True, True))
gp = {x["port_num"]: x for x in g}
check("SSH rule removable when Tailscale SSH is enabled", gp["22"]["warn"] and not gp["22"]["protected"])

# Tailscale-only: the tailscale rule is the last way in -> protected.
g = protect(NS(port=22), ["Anywhere ALLOW IN Anywhere on tailscale0",
                          "28960 ALLOW IN Anywhere"])
ts = next(x for x in g if x["is_tailscale"])
check("tailscale-only: protected", ts["protected"])

# `allow in on tailscale0` + `allow out on tailscale0` (the pair ufw adds), no SSH: only the
# IN rule is a "way in", so it's the last route and must be protected. The OUT rule must NOT
# count as access, or the protection would think there are two routes and let you delete the
# real (in) one.
g = protect(NS(port=22), ["Anywhere ALLOW IN Anywhere on tailscale0",
                          "Anywhere ALLOW OUT Anywhere on tailscale0"])
ins = [x for x in g if x["is_tailscale"]]
check("tailscale in+out: only the IN rule counts as access", len(ins) == 1)
check("tailscale in+out: the last-way-in IN rule is protected", bool(ins) and ins[0]["protected"])

# UFW disabled -> nothing protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere"], enabled=False)
check("ufw disabled: nothing protected", not any(x["protected"] for x in g))

# Panel web port on the LOCAL host, no Tailscale -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"],
            cfg={"port": 5000}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local, no tailscale: panel 5000 protected", gp["5000"]["protected"] and gp["5000"]["is_panel"])

# Panel web port with a tailscale0 rule but Serve NOT set up -> STILL protected. The
# tailscale interface only provides SSH recovery, not panel-UI access, so the public web
# port is still the only way into the panel.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local + tailscale0 but no Serve: panel 5000 STILL protected", gp["5000"]["protected"])

# Once Tailscale Serve is configured, the panel IS reachable over the tailnet -> the public
# port is no longer the only way in -> NOT protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local + Serve set up: panel 5000 NOT protected", not gp["5000"]["protected"])
# ...and with Serve serving the panel, the inbound tailscale0 rule is now what keeps the
# panel reachable over the tailnet, so it must be PROTECTED (the reported bug: the UI let
# you delete tailscale0 while the panel was served over it — a lock-out).
_tsrule = next(x for x in g if x["is_tailscale"])
check("local + Serve set up: inbound tailscale0 rule protected", _tsrule["protected"])

# On a REMOTE host the panel port is never protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"],
            cfg={"port": 5000}, is_local=False)
gp = {x["port_num"]: x for x in g}
check("remote host: panel 5000 not protected", not gp["5000"]["protected"])

# ── ssh-status: panel_port_open (gates the "Close public panel port" button) ──
_orig_run = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("Status: active\n5000/tcp  ALLOW  Anywhere\n"
                                        "22/tcp  ALLOW  Anywhere\n", "", 0)
    check("ssh-status: panel port open detected",
          sm.remote_public_ssh_status(NS(), panel_port=5000).get("panel_port_open") is True)
    # Closed: only a tailscale0 rule and a *different* port — must read as closed, and 27015
    # must not word-boundary-match 5000.
    sm.run_command = lambda s, c, **k: ("Status: active\nAnywhere  ALLOW  Anywhere on tailscale0\n"
                                        "27015  ALLOW  Anywhere\n", "", 0)
    check("ssh-status: panel port closed detected (no false match on 27015)",
          sm.remote_public_ssh_status(NS(), panel_port=5000).get("panel_port_open") is False)
    # Without panel_port the key is omitted entirely (remote hosts don't report it).
    check("ssh-status: panel_port_open omitted when not asked",
          "panel_port_open" not in sm.remote_public_ssh_status(NS()))
finally:
    sm.run_command = _orig_run

# ── game-port selection: open only what's needed ──────────────
_GMOD_DETAILS = """\
Some header text
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Client 27005 udp
SourceTV 27020 udp
"""
sm.run_as_game_user = lambda *a, **k: (_GMOD_DETAILS, "", 0)
res = sm.detect_game_ports(NS(), "gmodserver")
eq("gmod game_port", res["game_port"], 27015)
eq("gmod opens ONLY 27015 (no SourceTV/Client)", res["open_ports"], [27015])

_SRC_DETAILS = """\
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Query 27016 udp
RCON 27015 tcp
SourceTV 27020 udp
Client 27005 udp
"""
sm.run_as_game_user = lambda *a, **k: (_SRC_DETAILS, "", 0)
res = sm.detect_game_ports(NS(), "srv")
eq("source: opens game + query only", res["open_ports"], [27015, 27016])

# ── per-remote access control (fix: MANAGE_REMOTES alone must NOT grant every host) ──
def _user(is_admin, *group_remote_ids):
    return NS(is_superadmin=is_admin,
              groups=[NS(servers=[NS(id=i) for i in group_remote_ids])])


check("remote access: granted host allowed", can_access_remote(_user(False, 1, 2), 1))
check("remote access: non-granted host DENIED", not can_access_remote(_user(False, 1, 2), 3))
check("remote access: superadmin allowed anywhere", can_access_remote(_user(True), 999))
check("remote access: string id handled", can_access_remote(_user(False, 5), "5"))
check("remote access: junk id denied", not can_access_remote(_user(False, 5), "abc"))

# ── client_ip: trust X-Forwarded-For ONLY from the loopback proxy ─────
from flask import Flask as _Flask
_app = _Flask(__name__)
with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                               environ_base={"REMOTE_ADDR": "127.0.0.1"}):
    eq("loopback proxy: trust XFF", client_ip(), "1.2.3.4")
with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                               environ_base={"REMOTE_ADDR": "203.0.113.9"}):
    eq("direct connection: ignore spoofed XFF, use socket", client_ip(), "203.0.113.9")

# ── TOTP (2FA) ────────────────────────────────────────────────
from auth import generate_totp_secret, verify_totp
import pyotp as _pyotp
_sec = generate_totp_secret()
check("verify_totp accepts the current code", verify_totp(_sec, _pyotp.TOTP(_sec).now()))
check("verify_totp accepts a spaced code", verify_totp(_sec, " " + _pyotp.TOTP(_sec).now() + " "))
check("verify_totp rejects a wrong code", not verify_totp(_sec, "000000"))
check("verify_totp rejects empty", not verify_totp(_sec, ""))

# ── password check robustness (a bad stored hash must never raise) ───
from auth import check_password, hash_password, dummy_password_check
_h = hash_password("Test1234!@")
check("check_password: correct password -> True", check_password("Test1234!@", _h))
check("check_password: wrong password -> False", not check_password("nope", _h))
check("check_password: empty stored hash -> False (no raise)", not check_password("x", ""))
check("check_password: None stored hash -> False (no raise)", not check_password("x", None))
check("check_password: garbage stored hash -> False (no raise)", not check_password("x", "not-a-bcrypt-hash"))
check("dummy_password_check always returns False", dummy_password_check("anything") is False)

# ── login-throttle map must not grow unbounded (prune stale/empty IP buckets) ──
# _LOGIN_FAILS is the same dict object app.py mutates, so in-place edits here are seen
# by _prune_login_fails. (Single import style — CodeQL flags mixing import/from-import.)
from app import _prune_login_fails, _LOGIN_FAILS
_now = 1_000_000.0
_LOGIN_FAILS.clear()
_LOGIN_FAILS["fresh"] = [_now - 10]     # last failure within the window
_LOGIN_FAILS["stale"] = [_now - 9999]   # last failure aged out
_LOGIN_FAILS["empty"] = []              # bucket emptied by trimming
_prune_login_fails(_now)
check("login-throttle prune keeps a recently-active IP", "fresh" in _LOGIN_FAILS)
check("login-throttle prune drops an aged-out IP", "stale" not in _LOGIN_FAILS)
check("login-throttle prune drops an empty bucket", "empty" not in _LOGIN_FAILS)
_LOGIN_FAILS.clear()

# ── 2FA backup codes ──────────────────────────────────────────
from auth import generate_backup_codes
from models import User as _User
_codes = generate_backup_codes()
check("backup: generates 8 codes", len(_codes) == 8)
check("backup: codes are unique", len(set(_codes)) == 8)
check("backup: xxxxx-xxxxx format", all(len(c) == 11 and c[5] == "-" for c in _codes))
check("backup: unambiguous alphabet (no 0/o/1/l/i)",
      all(ch in "23456789abcdefghjkmnpqrstuvwxyz-" for c in _codes for ch in c))
_u = _User()
_u.set_backup_codes(_codes)
check("backup: 8 remaining after set", _u.backup_codes_remaining == 8)
check("backup: wrong code rejected", not _u.use_backup_code("00000-00000"))
check("backup: valid code accepted (ignores case + dashes)",
      _u.use_backup_code(_codes[0].upper().replace("-", "")))
check("backup: remaining drops to 7 after use", _u.backup_codes_remaining == 7)
check("backup: a used code can't be reused (one-time)", not _u.use_backup_code(_codes[0]))
check("backup: a different code still works", _u.use_backup_code(_codes[1]))
check("backup: no codes set is handled", not _User().use_backup_code("whatever"))

# ── one-click connect URI (steam://connect for Source/GoldSrc) ─
from models import GameServer as _GS
_steam = _GS(game_type="gmod", port=27015)
eq("connect: steam game -> steam://connect", _steam.connect_uri("1.2.3.4"),
   "steam://connect/1.2.3.4:27015")
_cs16 = _GS(game_type="cs", port=27015)
eq("connect: goldsrc game -> steam://connect", _cs16.connect_uri("host.example"),
   "steam://connect/host.example:27015")
_cod = _GS(game_type="cod", port=28960)
eq("connect: non-steam game (cod) -> no URI", _cod.connect_uri("1.2.3.4"), "")
_mc = _GS(game_type="mc", port=25565)
eq("connect: minecraft -> no URI", _mc.connect_uri("1.2.3.4"), "")
eq("connect: no host -> no URI", _steam.connect_uri(""), "")

# ── install port auto-assignment: span-aware, sequential packing ──
#    Regression guard for the "increments by 2" bug — a single-port game (Call of Duty, Source,
#    Minecraft) must pack sequentially, while a multi-port game reserves its whole adjacent block.
from app import _port_span, _first_free_block
eq("port-span: cod is single-port", _port_span("cod"), 1)
eq("port-span: source game is single-port", _port_span("gmod"), 1)
eq("port-span: unknown game defaults to 1", _port_span("totally-made-up"), 1)
eq("port-span: rust reserves 2", _port_span("rust"), 2)
eq("port-span: valheim reserves 3", _port_span("valheim"), 3)
eq("port-span: case-insensitive", _port_span("RUST"), 2)


def _pack(seq_spans, desired_of):
    """Simulate installing servers in order; each reserves its span. Returns assigned ports."""
    occupied, assigned = set(), []
    for gt in seq_spans:
        span = _port_span(gt)
        p = _first_free_block(desired_of[gt], span, occupied)
        for k in range(span):
            occupied.add(p + k)
        assigned.append(p)
    return assigned

eq("port-pack: 3 cod servers are sequential (no +2 gap)",
   _pack(["cod", "cod", "cod"], {"cod": 28960}), [28960, 28961, 28962])
eq("port-pack: cod then coduo pack tightly",
   _pack(["cod", "coduo"], {"cod": 28960, "coduo": 28960}), [28960, 28961])
eq("port-pack: 2 rust servers keep a 2-port block each",
   _pack(["rust", "rust"], {"rust": 28015}), [28015, 28017])
eq("port-pack: 2 valheim servers keep a 3-port block each",
   _pack(["valheim", "valheim"], {"valheim": 2456}), [2456, 2459])
eq("port-block: a live listening port is skipped",
   _first_free_block(28960, 1, {28960, 28961}), 28962)
eq("port-block: multi-port block steps past a partial overlap",
   _first_free_block(28015, 2, {28016}), 28017)

# ── panel file integrity + repair (git-based) ─────────────────
import system_ops as _so
_so._is_git_checkout = lambda: True
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"]
    else ("M\tapp.py\nD\ttemplates/base.html\n", "", 0) if list(args) == ["diff", "--name-status", "HEAD"]
    else ("", "", 0))
_intg = _so.panel_integrity(force=True)   # force: each scenario mocks a different git state
check("integrity: reports git checkout", _intg["git"] is True)
eq("integrity: counts tampered files", _intg["count"], 2)
check("integrity: not clean when files differ", _intg["clean"] is False)

# ── update-noise filter: only real runtime changes should raise the "update available" badge ──
check("runtime-path: app.py counts", _so._is_runtime_path("app.py") is True)
check("runtime-path: a template counts", _so._is_runtime_path("templates/base.html") is True)
check("runtime-path: static asset counts", _so._is_runtime_path("static/js/app.js") is True)
check("runtime-path: requirements counts", _so._is_runtime_path("requirements.txt") is True)
check("runtime-path: install.sh counts", _so._is_runtime_path("install.sh") is True)
check("runtime-path: README is noise", _so._is_runtime_path("README.md") is False)
check("runtime-path: any .md is noise", _so._is_runtime_path("docs/SECURITY.md") is False)
check("runtime-path: .github workflow is noise", _so._is_runtime_path(".github/workflows/ci.yml") is False)
check("runtime-path: tests are noise", _so._is_runtime_path("tests/unit_test.py") is False)
check("runtime-path: LICENSE is noise", _so._is_runtime_path("LICENSE") is False)
check("runtime-path: dotfiles are noise", _so._is_runtime_path(".gitignore") is False)
_orig_utr_git = _so._git
try:
    _so._git = lambda args, timeout=45: ("README.md\ndocs/x.md\n.github/workflows/ci.yml\n", "", 0)
    check("update-touches-runtime: docs-only diff -> no update", _so._update_touches_runtime("origin/main") is False)
    _so._git = lambda args, timeout=45: ("README.md\napp.py\n", "", 0)
    check("update-touches-runtime: any code change -> update", _so._update_touches_runtime("origin/main") is True)
    _so._git = lambda args, timeout=45: ("", "err", 1)
    check("update-touches-runtime: unknown diff -> assume update (fail safe)",
          _so._update_touches_runtime("origin/main") is True)
finally:
    _so._git = _orig_utr_git

# ── panel fail2ban: input validation rejects bad port / path before touching the host ──
check("panel-f2b: out-of-range port rejected", _so.configure_panel_fail2ban("/x", 70000)[0] is False)
check("panel-f2b: zero port rejected", _so.configure_panel_fail2ban("/x", 0)[0] is False)
check("panel-f2b: non-numeric port rejected", _so.configure_panel_fail2ban("/x", "nope")[0] is False)
check("panel-f2b: newline in log path rejected", _so.configure_panel_fail2ban("bad\npath", 5000)[0] is False)

# ── panel_commit: always a string (short SHA, or '' when not a git checkout) ──
check("panel-commit: returns a string", isinstance(_so.panel_commit(), str))

# ── change panel port: port_in_use + restart_panel dispatch ──
_orig_sorun = _so._run
try:
    _so._run = lambda c, **k: ("0.0.0.0:5000\n127.0.0.1:22\n[::]:8080\n", "", 0)
    check("port_in_use: detects a listening port", _so.port_in_use(5000) is True)
    check("port_in_use: ignores a free port", _so.port_in_use(9999) is False)
    check("port_in_use: matches bracketed IPv6 address", _so.port_in_use(8080) is True)
finally:
    _so._run = _orig_sorun

_orig_sorun2 = _so._run
try:
    _so._run = lambda c, **k: ("127.0.0.1\n100.84.48.111\n45.76.63.211\n", "", 0)
    check("host_has_ip: recognises a local address", _so.host_has_ip("100.84.48.111") is True)
    check("host_has_ip: rejects an address not on the host", _so.host_has_ip("10.0.0.9") is False)
finally:
    _so._run = _orig_sorun2

# ── perf guard: the /server-management host probe (sudo ufw + tailscale + apt, ~1.2s of
#    CPU across several subprocesses) is cached for _STATUS_TTL, so a page render and its
#    follow-up poll don't each re-run it. Mock the single subprocess entrypoint and count
#    how often it's actually hit across cold call / cached call / after invalidation. ──
_orig_ss_run = _so._run
_ss = {"n": 0}
try:
    _so._run = lambda c, **k: (_ss.__setitem__("n", _ss["n"] + 1), ("", "", 0))[1]
    _so._status_cache["data"] = None
    _so.get_server_status(force=True)          # cold: must probe the host
    check("perf: get_server_status probes the host on a cold call", _ss["n"] > 0)
    _ss["n"] = 0
    _so.get_server_status()                    # within TTL: served from cache, no subprocess
    check("perf: get_server_status is cached (no host re-probe on the next render)", _ss["n"] == 0)
    _so.invalidate_server_status()
    _so.get_server_status()                    # cache dropped: must probe again
    check("perf: invalidate_server_status forces a fresh probe", _ss["n"] > 0)
finally:
    _so._run = _orig_ss_run
    _so._status_cache["data"] = None

_orig_popen = _so.subprocess.Popen
_cap = {}
try:
    _so.subprocess.Popen = lambda a, **k: (_cap.update(args=a), type("P", (), {})())[1]
    _ok, _ = _so.restart_panel()
    check("restart_panel: dispatches successfully", _ok is True)
    check("restart_panel: targets the panel service via systemd-run restart",
          "systemd-run" in _cap["args"] and "restart" in _cap["args"]
          and "linuxgsm-panel.service" in _cap["args"])
    check("restart_panel: delays so the HTTP response can flush",
          any(str(x).startswith("--on-active=") for x in _cap["args"]))
finally:
    _so.subprocess.Popen = _orig_popen
check("integrity: parses modified status",
      {"path": "app.py", "status": "modified"} in _intg["modified"])
check("integrity: parses deleted status",
      {"path": "templates/base.html", "status": "deleted"} in _intg["modified"])

# Repair must ONLY ever check out files git itself reported as changed — a caller
# can't smuggle in an arbitrary path (path-traversal / arbitrary checkout).
_co = {}
def _repair_git(args, timeout=45):
    a = list(args)
    if a[:1] == ["checkout"]:
        _co["args"] = a
        return ("", "", 0)
    if a == ["rev-parse", "--short", "HEAD"]:
        return ("abc1234\n", "", 0)
    if a == ["diff", "--name-status", "HEAD"]:
        return ("M\tapp.py\n", "", 0)
    return ("", "", 0)
_so._git = _repair_git
_ok, _msg, _restored = _so.panel_repair(["app.py", "/etc/passwd", "../../secret"])
check("repair: restores only git-reported files", _restored == ["app.py"])
check("repair: rejects paths not in tampered set",
      "/etc/passwd" not in _co.get("args", []) and "../../secret" not in _co.get("args", []))
check("repair: uses HEAD + '--' path guard", _co["args"][:3] == ["checkout", "HEAD", "--"])

_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "", 0))
_ok2, _msg2, _ = _so.panel_repair()
check("repair: no-op when nothing is tampered", _ok2 is True and "Nothing to repair" in _msg2)

# Fail-safe: if git itself errors we must NOT claim the files are verified-clean.
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "fatal", 1))
_intgf = _so.panel_integrity(force=True)
check("integrity: fail-safe when git errors (not verified)",
      _intgf.get("verified") is False and _intgf["clean"] is True)
_okf, _msgf, _ = _so.panel_repair()
check("repair: refuses when integrity can't be verified", _okf is False)

_so._is_git_checkout = lambda: False
check("integrity: handles non-git checkout", _so.panel_integrity(force=True)["git"] is False)
_ok3, _msg3, _ = _so.panel_repair()
check("repair: refuses when not a git checkout", _ok3 is False)

# ── automatic security updates detection ──────────────────────
def _mk_run(installed_rc, apt_out):
    def _r(cmd, timeout=30, sudo=False, text=True):
        if "dpkg-query" in cmd:
            return ("", "", installed_rc)
        if "apt-config" in cmd:
            return (apt_out, "", 0)
        return ("", "", 0)
    return _r
_so._run = _mk_run(0, 'APT::Periodic::Unattended-Upgrade "1";')
_au = _so.unattended_upgrades_status()
check("auto-updates: installed + enabled detected", _au["installed"] and _au["enabled"])
_so._run = _mk_run(0, 'APT::Periodic::Unattended-Upgrade "0";')
_au = _so.unattended_upgrades_status()
check("auto-updates: installed but disabled detected", _au["installed"] and not _au["enabled"])
_so._run = _mk_run(1, "")
_au = _so.unattended_upgrades_status()
check("auto-updates: not installed detected", not _au["installed"] and not _au["enabled"])

# ── shell-identifier validation (the core injection defense) ──
from models import _validate_shell_ident as _vsi
for _bad in ("a;b", "a b", "a`b", "a$(x)", "a|b", "../x", "a&b", "a>b", "x'y", 'x"y', "a\nb", "a/b"):
    _rej = False
    try:
        _vsi("field", _bad)
    except ValueError:
        _rej = True
    check("shell-ident rejects %r" % _bad, _rej)
for _good in ("gmodserver", "cod", "my-server_1", "a.b", ""):
    _acc = True
    try:
        _vsi("field", _good)
    except ValueError:
        _acc = False
    check("shell-ident accepts %r" % _good, _acc)

# ── _quote() single-quoting neutralizes shell metacharacters ──
eq("_quote wraps a plain string in single quotes", sm._quote("abc"), "'abc'")
eq("_quote escapes an embedded single quote", sm._quote("a'b"), "'a'\\''b'")
_q = sm._quote("; rm -rf / #")
check("_quote fully single-quotes a metachar payload", _q[0] == "'" and _q[-1] == "'")
check("_quote leaves no unescaped quote to break out",
      _q.count("'") % 2 == 0)  # every quote is balanced/escaped

# ── cron builders generate correct + safe crontab lines ───────
# Capture what would be written instead of touching a real crontab.
_cron = {}
def _cap_rewrite(server, user, grep_args, add_lines, extra_pre=""):
    _cron.update(grep=grep_args, add=list(add_lines), pre=extra_pre)
    return True, "ok"
sm._rewrite_crontab = _cap_rewrite

sm.set_autostart(None, "gmodserver", True)
# Autostart is now the LinuxGSM monitor cron (every 5 min), NOT a @reboot start line — monitor
# respects the server's intended state via the lockfile. The managed line runs through the inline
# recorder so the command stays VISIBLE (grep-based detection/removal still works).
check("autostart(on): adds the */5 monitor line, recorder-wrapped",
      _cron["add"][0].startswith("*/5 * * * * ")
      and "/home/gmodserver/gmodserver monitor" in _cron["add"][0]
      and ".lgsm-cron/" in _cron["add"][0] and ".status" in _cron["add"][0])
check("autostart(on): also strips any legacy @reboot start line",
      "@reboot" in _cron["grep"] and "monitor" in _cron["grep"])
sm.set_autostart(None, "gmodserver", False)
eq("autostart(off): removes line, adds none", _cron["add"], [])

sm.install_game_cron(None, "gmodserver", supported={"monitor", "update-lgsm"})
check("install_game_cron: monitor every 5 min (recorder-wrapped, command visible)",
      any(ln.startswith("*/5 * * * * ") and "/home/gmodserver/gmodserver monitor" in ln
          and ".status" in ln for ln in _cron["add"]))
check("install_game_cron: weekly update-lgsm (recorder-wrapped)",
      any(ln.startswith("30 5 * * 0 ") and "/home/gmodserver/gmodserver update-lgsm" in ln
          and ".status" in ln for ln in _cron["add"]))
eq("install_game_cron: only supported commands scheduled", len(_cron["add"]), 2)

sm.set_daily_restart(None, "gmodserver", game_type="gmod", port=27015, enabled=True)
check("daily_restart(mapped): sets pending flag at 05:00 (recorder-wrapped)",
      _cron["add"][0].startswith("0 5 * * * ")
      and "touch /home/gmodserver/.restart-pending" in _cron["add"][0]
      and ".status" in _cron["add"][0])
check("daily_restart(mapped): queries gamedig for player count",
      "gamedig --type garrysmod 127.0.0.1:27015" in _cron["add"][1])
sm.set_daily_restart(None, "noqueryserver", game_type="noquerygame", port=28960, enabled=True)
check("daily_restart(unmapped game): skips gamedig, no player query",
      "gamedig" not in _cron["add"][1] and "P=; " in _cron["add"][1])
sm.set_daily_restart(None, "gmodserver", enabled=False)
check("daily_restart(disable): adds nothing and clears the flag",
      _cron["add"] == [] and "rm -f" in _cron["pre"])

# ── server_live_metrics parses SSH output into a numeric dict ──
_METRICS_OUT = "\n".join([
    "cpu 100 0 100 800 0 0 0", "GJA 1000",
    "cpu 110 0 110 880 0 0 0", "GJB 1100",
    "MEM 8000000000 4000000000", "LOAD 0.5 0.4 0.3",
    "DISK 100000000000 33000000000", "CORES 4", "UPTIME 123456",
    "GAMERAM 524288 3", "GUP 3600", "PORT 1",
])
sm.run_command = lambda server, cmd, timeout=30, sudo=None: (_METRICS_OUT, "", 0)
_m = sm.server_live_metrics(None, "gmodserver", 27015)
eq("metrics: ram_total parsed", _m["ram_total"], 8000000000)
eq("metrics: ram_percent computed", _m["ram_percent"], 50.0)
eq("metrics: disk_percent computed", _m["disk_percent"], 33.0)
eq("metrics: cores parsed", _m["cores"], 4)
eq("metrics: uptime parsed", _m["uptime_secs"], 123456)
eq("metrics: game_ram_mb parsed", _m["game_ram_mb"], 512)
eq("metrics: game_procs parsed", _m["game_procs"], 3)
check("metrics: port_open true when a socket is listening", _m["port_open"] is True)
eq("metrics: cpu_percent from the /proc/stat delta", _m["cpu_percent"], 20.0)
eq("metrics: game_cpu_percent from the jiffie delta", _m["game_cpu_percent"], 100.0)

# ── remote_live_metrics parses CPU/MEM/DISK sections (incl. new disk fields) ──
_RLM_OUT = "\n".join([
    "===A", "cpu 100 0 100 800 0 0 0", "cpu0 25 0 25 200 0 0 0",
    "===B", "cpu 110 0 110 880 0 0 0", "cpu0 28 0 28 220 0 0 0",
    "===MEM", "MemTotal: 8000000 kB", "MemAvailable: 4000000 kB",
    "SwapTotal: 0 kB", "SwapFree: 0 kB",
    "===DISK", "Filesystem 1B-blocks Used Available Use% Mounted on",
    "/dev/vda2 100000000000 40000000000 60000000000 40% /",
])
sm.run_command = lambda server, cmd, timeout=12, **k: (_RLM_OUT, "", 0)
_rlm = sm.remote_live_metrics(NS(is_local=False, auth_method="tailscale", host="x", name="x"))
eq("remote metrics: disk_total parsed", _rlm["disk_total"], 100000000000)
eq("remote metrics: disk_used parsed", _rlm["disk_used"], 40000000000)
eq("remote metrics: disk_percent computed", _rlm["disk_percent"], 40.0)
eq("remote metrics: swap 0 -> no divide-by-zero", _rlm["swap_percent"], 0)

# ── pro_status is cached (don't respawn the heavy Ubuntu Pro client every page load) ──
_pro_n = {"n": 0}
_orig_pro_run = sm.run_command
try:
    def _procount(s, c, **k):
        _pro_n["n"] += 1
        return ('{"attached": true, "services": []}', "", 0)
    sm.run_command = _procount
    sm._pro_status_cache.clear()
    _psrv = NS(id=42, host="h")
    sm.pro_status(_psrv)         # primes the cache; return value isn't checked
    _r2 = sm.pro_status(_psrv)   # served from cache — no second run_command
    check("pro_status: cached (one run_command for two reads)", _pro_n["n"] == 1 and _r2["attached"] is True)
    sm.pro_status(_psrv, force=True)
    check("pro_status: force=True bypasses cache", _pro_n["n"] == 2)
    sm._pro_cache_invalidate(_psrv)
    sm.pro_status(_psrv)
    check("pro_status: invalidate forces a refetch", _pro_n["n"] == 3)
finally:
    sm.run_command = _orig_pro_run
    sm._pro_status_cache.clear()

# ── host_specs is cached (static hardware — don't re-run lscpu every page load) ──
_hs_n = {"n": 0}
_orig_hs_run = sm.run_command
try:
    def _hscount(s, c, **k):
        _hs_n["n"] += 1
        return ("OS\tUbuntu\nCORES\t1\nMEM\t0.9\n", "", 0)
    sm.run_command = _hscount
    sm._specs_cache.clear()
    _hsrv = NS(id=7, host="h")
    sm.host_specs(_hsrv)
    sm.host_specs(_hsrv)   # cached
    check("host_specs: cached (one run_command for two reads)", _hs_n["n"] == 1)
finally:
    sm.run_command = _orig_hs_run
    sm._specs_cache.clear()

# ── set_game_priority renices the game user's processes as ROOT (negative nice needs root) ──
_gp_cmds = []
_orig_gp = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_gp_cmds.append(c), ("", "", 0))[1]
    sm.set_game_priority(None, "codserver")
    check("set_game_priority: renices the game user via sudo (root)",
          any("renice -n -1 -u codserver" in c and "sudo bash -c" in c for c in _gp_cmds))
    _gp_cmds.clear()
    sm.set_game_priority_bulk(None, ["codserver", "gmodserver"])
    check("set_game_priority_bulk: renices every game user in one sudo renice (keeper for cron restarts)",
          any("renice -n -1 -u codserver gmodserver" in c and "sudo bash -c" in c for c in _gp_cmds))
    _gp_cmds.clear()
    sm.set_game_priority_bulk(None, [])
    check("set_game_priority_bulk: no users -> no command", _gp_cmds == [])
finally:
    sm.run_command = _orig_gp

# ── remote_uptime is ONE ssh round-trip (was eight) + parses the composite output + caches ──
_orig_ru = sm.run_command
try:
    _ru_n = {"n": 0}
    _ru_out = "\n".join([
        "UPTIME up 3 days, 4 hours", "LOAD 0.15 0.10 0.05", "DISK 5.0G/20G",
        "MEM 1.2G/4.0G", "MEMPCT 30.0", "KERNEL 6.1.0", "CORES 2",
        "cpu 100 0 100 800 0 0 0",   # sample A: total 1000, idle 800
        "cpu 150 0 150 900 0 0 0",   # sample B: total 1200, idle 900 → idleΔ100/totalΔ200 = 50% busy
    ])

    def _ru_fake(server, cmd, **k):
        _ru_n["n"] += 1
        return (_ru_out, "", 0)
    sm.run_command = _ru_fake
    sm._uptime_cache.clear()
    _usrv = NS(id=7)
    _ru = sm.remote_uptime(_usrv)
    check("uptime: a SINGLE ssh round-trip (was 8 separate commands)", _ru_n["n"] == 1)
    eq("uptime: parses the uptime string", _ru["uptime"], "3 days, 4 hours")
    eq("uptime: parses cores", _ru["cpu_cores"], "2")
    eq("uptime: parses memory", _ru["memory"], "1.2G/4.0G")
    eq("uptime: cpu% from /proc/stat delta", _ru["cpu_percent"], "50.0")
    eq("uptime: cpu per-core derived", _ru["cpu_per_core"], "25.0")
    sm.remote_uptime(_usrv)   # within TTL → served from cache, no 2nd ssh
    check("uptime: second call served from cache", _ru_n["n"] == 1)
    sm.remote_uptime(_usrv, force=True)   # force bypasses cache
    check("uptime: force=True re-reads", _ru_n["n"] == 2)
finally:
    sm.run_command = _orig_ru
    sm._uptime_cache.clear()

# ── apt upgradable parsing: name + old→new version ──
_APT_OUT = "\n".join([
    "Listing...",
    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.12]",
    "curl/jammy-updates 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]",
    "",
])
_pu = sm._parse_upgradable(_APT_OUT)
eq("apt parse: count (Listing/blank skipped)", len(_pu), 2)
eq("apt parse: sorted by name (curl first)", _pu[0]["name"], "curl")
eq("apt parse: new version", _pu[1]["name"] == "libssl3" and _pu[1]["version"], "3.0.2-0ubuntu1.15")
eq("apt parse: old (from) version", _pu[1]["from"], "3.0.2-0ubuntu1.12")
_pu2 = sm._parse_upgradable("")
eq("apt parse: empty -> no packages", len(_pu2), 0)

# ── config save/load round-trips (guards the atomic-write path) ─
_cfg_backup = config.CONFIG_FILE.read_text() if config.CONFIG_FILE.exists() else None
try:
    _c = config.load_config()
    _c["_roundtrip_probe"] = "value-123"
    config.save_config(_c)
    check("config: value survives a save/load round-trip",
          config.load_config().get("_roundtrip_probe") == "value-123")
    check("config: file exists after atomic save", config.CONFIG_FILE.exists())
finally:
    if _cfg_backup is not None:
        config.CONFIG_FILE.write_text(_cfg_backup)

# ── database corruption detection + self-heal (bad drive / power loss) ─
import sqlite3 as _sqlite
import tempfile as _tempfile
import shutil as _shutil
from models import _db_quick_check, _ensure_db_healthy
_dbdir = _tempfile.mkdtemp()
_dbp = os.path.join(_dbdir, "t.db")
try:
    _c = _sqlite.connect(_dbp)
    _c.execute("CREATE TABLE x (a INTEGER)")
    _c.executemany("INSERT INTO x VALUES (?)", [(i,) for i in range(200)])
    _c.commit()
    _c.close()
    check("corrupt: a healthy DB passes quick_check", _db_quick_check(_dbp) is True)

    # A healthy startup makes/refreshes the rolling backup.
    _ensure_db_healthy(_dbp)
    check("corrupt: a rolling backup is created for a healthy DB", os.path.exists(_dbp + ".backup"))

    # Simulate a bad drive: clobber the middle of the file (leave the 100-byte
    # header so it still 'opens' as a DB but is malformed).
    with open(_dbp, "r+b") as _f:
        _f.seek(100)
        _f.write(b"\x00" * 4000)
    check("corrupt: a malformed DB fails quick_check", _db_quick_check(_dbp) is False)

    # Self-heal: restore from the backup, preserve the corrupt file aside, keep data.
    _ensure_db_healthy(_dbp)
    check("corrupt: DB is auto-restored to a healthy state", _db_quick_check(_dbp) is True)
    check("corrupt: the corrupt file is preserved aside (not destroyed)",
          any(fn.startswith("t.db.corrupt-") for fn in os.listdir(_dbdir)))
    _r = _sqlite.connect(_dbp).execute("SELECT COUNT(*) FROM x").fetchone()[0]
    eq("corrupt: restored data is intact", _r, 200)

    # No good backup + corrupt live DB -> move the corrupt file aside so the app can
    # start fresh instead of crash-looping (the bad file is preserved, not deleted).
    _dbp2 = os.path.join(_dbdir, "u.db")
    with open(_dbp2, "wb") as _f:
        _f.write(b"this is not a database at all, just garbage bytes" * 50)
    _ensure_db_healthy(_dbp2)   # no u.db.backup exists — must not raise
    check("corrupt: with no backup, the corrupt DB is moved aside (start-fresh)",
          not os.path.exists(_dbp2) and any(fn.startswith("u.db.corrupt-")
                                            for fn in os.listdir(_dbdir)))
finally:
    _shutil.rmtree(_dbdir, ignore_errors=True)

# ── config._create_key_once: atomic create-exactly-once (race-safe key files) ──
# Guards against two concurrent first-time saves each generating a different cred_key and
# clobbering the other (which would make the first-encrypted secret undecryptable).
_kd = _tempfile.mkdtemp()
try:
    _kp = os.path.join(_kd, "k")
    config._create_key_once(_kp, lambda: b"FIRST")
    with open(_kp, "rb") as _f:
        check("keyonce: creates the file with the generated bytes", _f.read() == b"FIRST")
    config._create_key_once(_kp, lambda: b"SECOND")   # must be a no-op (O_EXCL)
    with open(_kp, "rb") as _f:
        check("keyonce: never overwrites an existing key file", _f.read() == b"FIRST")
    # And a full encrypt→decrypt round-trip still works against a created cred key.
    _sec = config.encrypt_secret("hunter2-secret")
    check("keyonce: encrypt produces an enc:v1: blob", config.is_encrypted(_sec))
    check("keyonce: decrypt round-trips the plaintext", config.decrypt_secret(_sec) == "hunter2-secret")
finally:
    _shutil.rmtree(_kd, ignore_errors=True)

# ── Ubuntu Pro status persists (set-and-forget: no re-running the slow client every visit) ──
from models import RemoteServer as _RS
_pr = _RS()
check("pro-cache: empty -> None", _pr.cached_pro is None)
_pr.update_pro_cache({"attached": True, "installed": True, "services": []})
_pc = _pr.cached_pro
check("pro-cache: round-trips the status dict", bool(_pc) and _pc["data"]["attached"] is True)
check("pro-cache: stamps a timestamp for staleness checks", isinstance(_pc.get("ts"), int) and _pc["ts"] > 0)
_pr.pro_cache = "{not valid json"
check("pro-cache: malformed stored value -> None (never raises)", _pr.cached_pro is None)

# ── dashboard port-scan cache: concurrent polls share ONE ssh scan per remote ──
_app = sys.modules["app"]   # already imported via `from app import ...` above
_o_ps_rc = _app.run_command
try:
    _scan_n = {"n": 0}

    def _fake_ss(remote, cmd, **k):
        _scan_n["n"] += 1
        return ("127.0.0.1:22\n*:27015\n[::]:27016", "", 0)

    _app.run_command = _fake_ss
    _app._port_scan_cache.clear()
    _rem = NS(id=99)
    _p1 = _app._remote_listening_ports(_rem)
    _app._remote_listening_ports(_rem)   # within TTL → cache hit, no 2nd ssh
    check("portscan: parses listening ports", 27015 in _p1 and 22 in _p1 and 27016 in _p1)
    check("portscan: second concurrent poll served from cache (one ssh)", _scan_n["n"] == 1)
    _app._invalidate_port_scan(99)
    _app._remote_listening_ports(_rem)   # invalidated → re-scans
    check("portscan: invalidate forces a fresh scan", _scan_n["n"] == 2)
    # A failed scan (empty output) must NOT be cached, so a blip doesn't pin servers offline.
    _app.run_command = lambda remote, cmd, **k: ("", "err", -1)
    _app._port_scan_cache.clear()
    _app._remote_listening_ports(_rem)
    check("portscan: an empty/failed scan is not cached", 99 not in _app._port_scan_cache)
finally:
    _app.run_command = _o_ps_rc
    _app._port_scan_cache.clear()

# ── debug report: redaction + secret-key whitelist (must not leak) ─
_rd = _so._redact
check("redact: masks email addresses", "[email]" in _rd("reach me at admin@example.com now"))
check("redact: masks long token/key strings",
      "[redacted]" in _rd("key exampletokenexampletokenexampletoken12345"))
check("redact: masks key=value secrets", "[redacted]" in _rd("password=hunter2superSecret"))
check("redact: masks token: value", "[redacted]" in _rd("auth_token: abc.def.ghi"))
check("redact: leaves ordinary text intact", "server is offline" in _rd("server is offline"))
_secret_keys = {"secret_key", "cred_key", "secret", "credentials", "auth_credential",
                "host_key", "totp_secret", "backup_codes", "password"}
check("debug whitelist excludes every secret key",
      not (set(_so._DEBUG_CONFIG_KEYS) & _secret_keys))

# ── panel self-update CI gate: don't offer an update until its CI has passed ──
# _repo_slug must parse both HTTPS and SSH remote URLs (so the check works on forks).
_orig_rslug_git = _so._git
try:
    def _slug_git(args, timeout=45):
        return ("https://github.com/FMSMITH91/linuxgsm-panel.git\n", "", 0)
    _so._git = _slug_git
    eq("update: repo slug parsed from origin URL", _so._repo_slug(), "FMSMITH91/linuxgsm-panel")
finally:
    _so._git = _orig_rslug_git

# _remote_ci_state maps GitHub's Actions API response to passing/pending/failing, and
# never raises on a network/parse error (returns 'unknown', treated leniently).
import io as _io
_orig_ci_slug = _so._repo_slug
_orig_urlopen = _so.urllib.request.urlopen
try:
    _so._repo_slug = lambda: "o/r"

    def _fake_open(payload):
        def _op(req, timeout=8):
            return _io.BytesIO(payload.encode() if isinstance(payload, str) else payload)
        return _op

    # The gate now requires EVERY check-run (except 'deploy') to be completed + successful.
    _all_ok = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
               '{"name":"Analyze (python)","status":"completed","conclusion":"success"},'
               '{"name":"lighthouse","status":"completed","conclusion":"success"}]}')
    _so.urllib.request.urlopen = _fake_open(_all_ok)
    eq("ci-gate: all checks passed -> passing", _so._remote_ci_state("a"*40), "passing")
    # CI passed but Lighthouse still running -> pending (the exact case the user hit).
    _lh_running = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                   '{"name":"lighthouse","status":"in_progress","conclusion":null}]}')
    _so.urllib.request.urlopen = _fake_open(_lh_running)
    eq("ci-gate: one check still running -> pending", _so._remote_ci_state("a"*40), "pending")
    # One check failed (even if the rest passed) -> failing.
    _one_fail = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                 '{"name":"lighthouse","status":"completed","conclusion":"failure"}]}')
    _so.urllib.request.urlopen = _fake_open(_one_fail)
    eq("ci-gate: any check failed -> failing", _so._remote_ci_state("a"*40), "failing")
    # 'deploy' is ignored: a pending deploy alongside all-passing checks is still passing.
    _deploy_pending = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                       '{"name":"deploy","status":"in_progress","conclusion":null}]}')
    _so.urllib.request.urlopen = _fake_open(_deploy_pending)
    eq("ci-gate: pending 'deploy' is ignored -> passing", _so._remote_ci_state("a"*40), "passing")
    _so.urllib.request.urlopen = _fake_open('{"check_runs":[]}')
    eq("ci-gate: no checks yet -> pending", _so._remote_ci_state("a"*40), "pending")

    def _boom(req, timeout=8):
        raise _so.urllib.error.URLError("offline")
    _so.urllib.request.urlopen = _boom
    eq("ci-gate: network error -> unknown (never raises)", _so._remote_ci_state("a"*40), "unknown")
finally:
    _so._repo_slug = _orig_ci_slug
    _so.urllib.request.urlopen = _orig_urlopen

# panel_self_update ENFORCES the CI gate server-side (not just by hiding the button), and
# re-checks fresh so it also catches a bad commit that landed between page-load and click.
_orig_isgit = _so._is_git_checkout
_orig_pus = _so.panel_update_status
_orig_isfile = _so.os.path.isfile
try:
    _so._is_git_checkout = lambda: True
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "failing"}
    _ok, _m = _so.panel_self_update()
    check("self-update: refuses a commit that FAILED CI", _ok is False and "didn't pass" in _m)
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "pending"}
    _ok, _m = _so.panel_self_update()
    check("self-update: refuses while CI is still running", _ok is False and "being verified" in _m)
    # A CI-passing commit must get PAST the gate. Make install.sh look missing so it stops
    # there (proving the gate let it through) instead of actually launching an update.
    _so.os.path.isfile = lambda p: False
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "passing"}
    _ok, _m = _so.panel_self_update()
    check("self-update: a CI-passing commit is NOT blocked by the gate",
          _ok is False and "install.sh is missing" in _m)
finally:
    _so._is_git_checkout = _orig_isgit
    _so.panel_update_status = _orig_pus
    _so.os.path.isfile = _orig_isfile

# ── _compute_update_status targets the newest VERIFIED commit ──
# When the tip is still verifying but an earlier commit already passed CI, the panel must
# offer that earlier verified commit (not block entirely, and not jump to the pending tip).
_cus_git = _so._git
_cus_isco = _so._is_git_checkout
_cus_ver = _so.panel_version
_cus_ci = _so._remote_ci_state
try:
    _so._is_git_checkout = lambda: True
    _so.panel_version = lambda: "1.0.0"

    def _mk_git(behind, commits):
        # commits: full SHAs, newest (tip) first.
        def _g(args, timeout=45):
            if args[0] == "fetch":
                return ("", "", 0)
            if args[:3] == ["rev-parse", "--short", "HEAD"]:
                return ("headabc", "", 0)
            if args[:2] == ["rev-list", "--count"]:
                return (str(behind), "", 0)
            if args[:3] == ["rev-parse", "--short", "origin/main"]:
                return (commits[0][:7] if commits else "", "", 0)
            if args[0] == "rev-list" and "-n" in args:
                return ("\n".join(commits), "", 0)
            if args[0] == "show" and str(args[-1]).endswith(":VERSION"):
                return ("9.9.9", "", 0)
            if args[0] == "log":
                return ("c1 a change", "", 0)
            return ("", "", 0)
        return _g

    _C = ["a" * 40, "b" * 40, "c" * 40]   # tip=a, mid=b, old=c

    # tip pending, middle passed → offer the middle (skip the pending tip).
    _so._git = _mk_git(3, _C)
    _so._remote_ci_state = lambda sha: {"a" * 40: "pending", "b" * 40: "passing",
                                        "c" * 40: "passing"}.get(sha, "unknown")
    _r = _so._compute_update_status()
    check("update-target: offers the verified commit when the tip is pending",
          _r["update_available"] and _r["target_sha"] == "b" * 40)
    eq("update-target: newer unverified counted", _r.get("newer_unverified"), 1)
    eq("update-target: behind is measured to the target, not the tip", _r["behind"], 2)

    # tip passed → target is the tip, nothing pending above it.
    _so._remote_ci_state = lambda sha: "passing"
    _r = _so._compute_update_status()
    check("update-target: tip passed -> target is the tip",
          _r["update_available"] and _r["target_sha"] == "a" * 40 and _r["newer_unverified"] == 0)

    # everything still verifying → offer nothing, explain why.
    _so._remote_ci_state = lambda sha: "pending"
    _r = _so._compute_update_status()
    check("update-target: all pending -> no update offered",
          _r["update_available"] is False and _r["ci_state"] == "pending")
finally:
    _so._git = _cus_git
    _so._is_git_checkout = _cus_isco
    _so.panel_version = _cus_ver
    _so._remote_ci_state = _cus_ci

# ── Tailscale: installed-but-not-authenticated (NeedsLogin) must not 500 ─
import tailscale_integration as _tsi
_tsi._run_ts = lambda args, timeout=5: (("1.0", "", 0) if args and args[0] in ("version", "--version")
                                        else ("", "", 0))
# After `tailscale up` prints a login URL the user hasn't clicked, status --json has
# null Peer/Self/TailscaleIPs — the page used to crash iterating None.
_tsi._run_ts_json = lambda args, timeout=5: {"BackendState": "NeedsLogin",
                                             "Self": None, "Peer": None, "TailscaleIPs": None}
_tsinfo = _tsi._get_tailscale_info()
check("tailscale: NeedsLogin state parses without crashing", _tsinfo.installed and not _tsinfo.running)
check("tailscale: null Peer -> no peers (no None.items())", _tsinfo.peers == [])
check("tailscale: null TailscaleIPs -> empty list", _tsinfo.tailscale_ips == [])
check("tailscale: backend_state captured as NeedsLogin", _tsinfo.backend_state == "NeedsLogin")
# The bind suggestion must point the user at linking (not "no Tailscale detected") in NeedsLogin,
# so the page can offer a clear "Link this machine" action instead of looking un-installed.
_tsi._cache["info"] = None  # bypass the 15s cache so suggest_best_bind re-reads our mock
_tssug = _tsi.suggest_best_bind(5000)
check("tailscale: NeedsLogin suggestion tells user to link, not 'not detected'",
      "not linked" in _tssug["description"].lower())
_tsi._cache["info"] = None

# ── Debug report: repeated tracebacks in the log tail get collapsed ───
_pfx = "Jul 05 23:44:%02d vultr python[74699]: "
_one_tb = [
    _pfx % 14 + "Traceback (most recent call last):",
    _pfx % 14 + '  File "/x.py", line 1, in main',
    _pfx % 14 + "    do()",
    _pfx % 14 + "ssl.SSLError: sslv3 alert certificate unknown",
]
# same traceback logged 3× at different timestamps, interleaved with unique lines
_noisy = "\n".join(
    _one_tb + [_pfx % 15 + "Removing descriptor: 12"]
    + _one_tb + [_pfx % 16 + "Removing descriptor: 13"]
    + _one_tb + [_pfx % 17 + "Removing descriptor: 14"]
)
_dd = _so._dedupe_log_tracebacks(_noisy)
check("log dedupe: keeps exactly one full copy of a repeated traceback",
      _dd.count("Traceback (most recent call last):") == 1)
check("log dedupe: annotates the collapsed repeats", "repeated 2× more" in _dd)
check("log dedupe: preserves the surrounding unique lines",
      "Removing descriptor: 12" in _dd and "Removing descriptor: 14" in _dd)
# distinct tracebacks must NOT be collapsed into each other
_distinct = "\n".join([
    _pfx % 14 + "Traceback (most recent call last):",
    _pfx % 14 + "ValueError: bad",
    _pfx % 15 + "Traceback (most recent call last):",
    _pfx % 15 + "KeyError: nope",
])
_dd2 = _so._dedupe_log_tracebacks(_distinct)
check("log dedupe: distinct tracebacks are both kept",
      _dd2.count("Traceback (most recent call last):") == 2
      and "ValueError" in _dd2 and "KeyError" in _dd2)

# ── mods parsing (real LinuxGSM formats, verified on a live Garry's Mod box) ──
_mods_avail_out = (
    "\x1b[1mGarry's Mod Installing Mods\x1b[0m\n"
    "=================================\n"
    "Available addons/mods\n"
    "=================================\n"
    "Metamod: Source - Plugins Framework - https://www.sourcemm.net\n"
    " * \x1b[36mmetamodsource\x1b[0m\n"
    "SourceMod - Admin Features (requires Metamod: Source) - http://www.sourcemod.net\n"
    " * \x1b[36msourcemod\x1b[0m\n"
    "Wiremod Extras - Addition to Wiremod - https://github.com/wiremod/wire-extras/\n"
    " * \x1b[36mwiremod-extras\x1b[0m\n"
)
_av = sm._parse_mods_available(_mods_avail_out)
check("mods: available parses id + name from ' * <id>' format",
      [m["id"] for m in _av] == ["metamodsource", "sourcemod", "wiremod-extras"]
      and _av[0]["name"] == "Metamod: Source")
_mods_inst_out = (
    "Garry's Mod Removing Mods\n"
    "=================================\n"
    "Remove addons/mods\n"
    "=================================\n"
    "metamodsource - Metamod: Source - Plugins Framework\n"
    "Enter an addon/mod to remove (or exit to abort): "
)
_in = sm._parse_mods_installed(_mods_inst_out)
check("mods: installed parses '<id> - <name>' format",
      len(_in) == 1 and _in[0]["id"] == "metamodsource" and _in[0]["name"] == "Metamod: Source")
check("mods: 'No installed mods' output yields empty list",
      sm._parse_mods_installed("Failure! No installed mods or addons were found") == [])
# A game with no mods installer (cod) prints 'Unknown command' + a 'LinuxGSM - <Game> - Version …'
# banner — that banner must NOT be parsed as an installed mod.
_cod_out = ("Error! Unknown command: ./codserver mods-remove\n"
            "LinuxGSM - Call of Duty - Version v26.1.0\nstart st | Start the server.")
check("mods: 'Unknown command' output -> game not supported", sm._game_supports_mods(_cod_out) is False)
check("mods: version banner isn't parsed as an installed mod",
      not any(m["id"] == "LinuxGSM" for m in sm._parse_mods_installed(_cod_out)))
check("mods: a real mods list is still 'supported'",
      sm._game_supports_mods("metamodsource - Metamod: Source - desc") is True)
# mods_action rejects unsafe ids before ever building a shell command (injection guard)
check("mods: mods_action rejects an unsafe id",
      sm.mods_action(None, "u", "u", "install", "foo; rm -rf x")[1] == "invalid mod id")

# game-backup download/delete validate the file name before touching any path (server=None here,
# so a passing regex would crash — proving rejection happens purely on the name)
check("game backup: delete rejects an unsafe name",
      sm.delete_game_backup(None, "u", "x; rm -rf y") is False)
check("game backup: delete rejects a path-traversal name",
      sm.delete_game_backup(None, "u", "../../etc/passwd") is False)
check("game backup: stream yields nothing for an unsafe name",
      list(sm.stream_game_backup(None, "u", "../../etc/passwd")) == [])
check("game backup: name shape accepts a real archive",
      bool(sm._GAME_BACKUP_NAME.match("gmodserver-2026-07-06-141117.tar.zst")))

# ── discover_linuxgsm_servers: parse the one-shot host scan output ──
_orig_disc_rc = sm.run_command
try:
    sm.run_command = lambda *a, **k: (
        "FOUND|gmodserver|gmodserver|27015|3|2|4|1\n"
        "FOUND|myrust|rustserver|28015|0|0|0|0\n"
        "some unrelated line\n"
        "FOUND|shortline|gmodserver|0\n"          # missing the count fields -> skipped
        "FOUND|zeroport|csgoserver|0|0|0|0|0\n", "", 0)
    _disc = sm.discover_linuxgsm_servers(None)
    eq("discover: keeps only well-formed (8-field) FOUND lines", len(_disc), 3)
    check("discover: parses user / lgsm_name / port + backup/mod/cron counts + autostart",
          _disc[0] == {"user": "gmodserver", "lgsm_name": "gmodserver", "port": 27015,
                       "backups": 3, "mods": 2, "cron": 4, "autostart": True})
    check("discover: a 0/blank port becomes None and autostart is False",
          _disc[2]["user"] == "zeroport" and _disc[2]["port"] is None
          and _disc[2]["autostart"] is False)
    sm.run_command = lambda *a, **k: ("", "err", 1)
    check("discover: returns [] when the scan command fails", sm.discover_linuxgsm_servers(None) == [])
finally:
    sm.run_command = _orig_disc_rc

# ── lgsm_name_to_game_type: gameservername -> panel game_type, from serverlist.csv ──
check("lgsm-name map: gmodserver -> gmod", _app.lgsm_name_to_game_type("gmodserver") == "gmod")
check("lgsm-name map: rustserver -> rust", _app.lgsm_name_to_game_type("rustserver") == "rust")
check("lgsm-name map: an unknown script -> None", _app.lgsm_name_to_game_type("notagameserver") is None)

# ── GameServer.supports_update: drives the (bulk) Update button + backend skip per game ──
check("supports_update: fetched list exposing 'update' -> True",
      _GS(commands='[{"cmd":"update"},{"cmd":"start"}]').supports_update is True)
check("supports_update: fetched list with no 'update' -> False",
      _GS(commands='[{"cmd":"start"},{"cmd":"stop"}]').supports_update is False)
check("supports_update: empty list + known no-update game (cod) -> False",
      _GS(commands='[]', game_type='cod').supports_update is False)
check("supports_update: empty list + SteamCMD game -> True (fail open)",
      _GS(commands='[]', game_type='csgo').supports_update is True)

# ── player moderation: engine-aware caps, status/list parsers + injection-safe commands ──
check("moderation: gmod (valve) supports kick + ban + say",
      sm.moderation_caps("gmod") == {"kick": True, "ban": True, "say": True})
check("moderation: minecraft supports kick + ban + say",
      sm.moderation_caps("mc") == {"kick": True, "ban": True, "say": True})
check("moderation: cod (idTech3) supports kick + ban + say",
      sm.moderation_caps("cod") == {"kick": True, "ban": True, "say": True})
check("moderation: a non-console game (rust) supports nothing",
      sm.moderation_caps("rust") == {"kick": False, "ban": False, "say": False})
check("engine: gmod->valve, cod->idtech3, mc->minecraft, rust->''",
      (sm.game_engine("gmod"), sm.game_engine("cod"), sm.game_engine("mc"), sm.game_engine("rust"))
      == ("valve", "idtech3", "minecraft", ""))
check("moderation: cod is now queryable (via console); a game with neither engine nor gamedig is not",
      sm.is_player_queryable("cod") is True and sm.is_player_queryable("nosuchgame") is False)
check("moderation: console metacharacters are stripped from a name (no injection)",
      sm._mod_sanitize('a;b"c`d\ne') == "abcde")

# per-engine status/list parsers (sample output — I can't live-fire each engine)
_SRC = ('# userid name uniqueid connected ping loss state adr\n'
        '#  2 "Alice" STEAM_0:1:12345 15:30 45 0 active 5.6.7.8:27005\n'
        '#  5 "Bob ^S" [U:1:99] 02:11 67 0 active 9.9.9.9:27005\n'
        '#  7 "aBot" BOT 00:00 0 0 active\n')
check("parser(valve): names + steamids (legacy / modern / bot-empty)",
      [(p["name"], p["steamid"]) for p in sm._parse_valve_status(_SRC)]
      == [("Alice", "STEAM_0:1:12345"), ("Bob ^S", "[U:1:99]"), ("aBot", "")])
_COD = ('num score ping guid                             name            lastmsg address       qport rate\n'
        '--- ----- ---- -------------------------------- --------------- ------- ------------- ----- ----\n'
        '  0     5   45 1100001aaaaaaaaaaaaaaaaaaaaaaaaa ^1Alice^7             0 5.6.7.8:28960 12345 25000\n'
        '  1     0   67 1100001bbbbbbbbbbbbbbbbbbbbbbbbb Bob Smith            50 9.9.9.9:28961 54321 25000\n')
check("parser(idtech3): slot numbers + names (colours stripped, spaces kept)",
      [(p["num"], p["name"]) for p in sm._parse_idtech3_status(_COD)] == [(0, "Alice"), (1, "Bob Smith")])
_MC = "[12:34:56] [Server thread/INFO]: There are 2 of a max of 20 players online: Alice, Bob_1"
check("parser(minecraft): names from a prefixed log line",
      [p["name"] for p in sm._parse_minecraft_list(_MC)] == ["Alice", "Bob_1"])
check("parser(minecraft): empty server -> no players",
      sm._parse_minecraft_list("There are 0 of a max of 20 players online: ") == [])

# player_list: gamedig is PRIMARY (no console spam); the console is only a backup when gamedig
# can't query the game at all (_gamedig_player_list returns None for that, [] for empty).
_orig_cpl, _orig_gpl = sm.console_player_list, sm._gamedig_player_list
try:
    sm.console_player_list = lambda *a, **k: [{"name": "Ace"}]
    sm._gamedig_player_list = lambda *a, **k: [{"name": "Zed", "steamid": "", "num": None,
                                                "score": None, "time": None}]
    check("player_list: gamedig is primary — the console isn't touched when gamedig answers",
          [p["name"] for p in sm.player_list(None, "u", "cod", 28960, None, "codserver")] == ["Zed"])
    sm._gamedig_player_list = lambda *a, **k: []   # gamedig says the server is empty
    check("player_list: a gamedig-confirmed empty server does NOT fall back to the console",
          sm.player_list(None, "u", "cod", 28960, None, "codserver") == [])
    sm._gamedig_player_list = lambda *a, **k: None  # gamedig couldn't query at all
    check("player_list: falls back to the console only when gamedig can't query",
          [p["name"] for p in sm.player_list(None, "u", "cod", 28960, None, "codserver")] == ["Ace"])
finally:
    sm.console_player_list, sm._gamedig_player_list = _orig_cpl, _orig_gpl

# injection-safe command building, dispatched by engine
_msent = {}
_orig_scc = sm.send_console_command
_orig_cpl_m = sm.console_player_list
try:
    sm.send_console_command = lambda *a, **k: (_msent.__setitem__("cmd", a[2]), ("", "", 0))[1]
    sm.moderate(None, "u", "gmod", "kick", target='Bad;Guy"x')
    check("moderation: valve kick quotes the sanitized name (injection neutralised)",
          _msent.get("cmd") == 'kick "BadGuyx"')
    sm.moderate(None, "u", "gmod", "ban", steamid="STEAM_0:1:5; rcon x")
    check("moderation: valve ban uses banid+writeid on the re-validated SteamID only",
          _msent.get("cmd") == "banid 0 STEAM_0:1:5; writeid")
    check("moderation: valve ban with no SteamID and no name is refused",
          sm.moderate(None, "u", "gmod", "ban", steamid="")[0] is False)
    sm.moderate(None, "u", "cod", "kick", num="3")
    check("moderation: idTech3 kick is clientkick <slot>", _msent.get("cmd") == "clientkick 3")
    sm.moderate(None, "u", "cod", "ban", num="3")
    check("moderation: idTech3 ban is banclient <slot>", _msent.get("cmd") == "banclient 3")
    check("moderation: idTech3 with a junk slot and no name is refused",
          sm.moderate(None, "u", "cod", "ban", num="3; quit")[0] is False)
    sm.moderate(None, "u", "mc", "ban", target="Steve")
    check("moderation: minecraft ban is a bare name command", _msent.get("cmd") == "ban Steve")
    check("moderation: a non-console game (rust) refuses moderation",
          sm.moderate(None, "u", "rust", "ban", target="x")[0] is False)
    # on-demand id resolution: a gamedig-sourced list carries no ids, so kick/ban looks the player
    # up on the console by name and uses the slot / SteamID it finds there.
    sm.console_player_list = lambda *a, **k: [{"name": "Ace", "num": 4, "steamid": "STEAM_0:1:9"}]
    _msent.clear()
    sm.moderate(None, "u", "cod", "kick", target="Ace")   # no num supplied
    check("moderation: idTech3 kick resolves the slot from the console when given only a name",
          _msent.get("cmd") == "clientkick 4")
    _msent.clear()
    sm.moderate(None, "u", "gmod", "ban", target="Ace")   # no steamid supplied
    check("moderation: valve ban resolves the SteamID from the console when given only a name",
          _msent.get("cmd") == "banid 0 STEAM_0:1:9; writeid")
finally:
    sm.send_console_command = _orig_scc
    sm.console_player_list = _orig_cpl_m

# ── gamedig query type: per-server override wins over the built-in map, sanitized ──
check("query-type: an explicit override wins over the built-in map",
      sm._gamedig_type("gmod", "customtype") == "customtype")
check("query-type: unmapped game with no override -> '' (no gamedig type)",
      sm._gamedig_type("noquerygame", None) == "")
check("query-type: a mapped game with no override uses the map",
      sm._gamedig_type("gmod", None) == "garrysmod")
check("query-type: the override is sanitized to a gamedig-safe charset",
      sm._gamedig_type("cod", "co d;rm -rf") == "codrm-rf")
check("query-type: the Call of Duty family is mapped, so its player count (restart/backup) works",
      sm._gamedig_type("cod", None) == "cod" and sm._gamedig_type("cod4", None) == "cod4")
check("query-type: a game with neither engine nor map becomes queryable once an override is set",
      sm.is_player_queryable("nosuchgame", None) is False
      and sm.is_player_queryable("nosuchgame", "quake3") is True)

# ── change_ssh_port: input validation rejects bad ports BEFORE touching the host ──
check("ssh-port: non-numeric rejected", sm.change_ssh_port(None, "abc")[0] is False)
check("ssh-port: port 0 rejected", sm.change_ssh_port(None, 0)[0] is False)
check("ssh-port: port 70000 (out of range) rejected", sm.change_ssh_port(None, 70000)[0] is False)
check("ssh-port: negative port rejected", sm.change_ssh_port(None, -5)[0] is False)
check("ssh-port: invalid bind IP rejected", sm.change_ssh_port(None, 2222, "not-an-ip")[0] is False)
check("valid-ip: accepts IPv4", sm._valid_ip("192.168.1.5") is True)
check("valid-ip: accepts IPv6", sm._valid_ip("::1") is True)
check("valid-ip: rejects junk", sm._valid_ip("nope") is False)
check("valid-ip: rejects host:port form", sm._valid_ip("1.2.3.4:22") is False)

# ── db_maintenance: offline SQLite check / repair / optimize (updater + health card) ──
import db_maintenance as _dbm
import sqlite3 as _sq3
import tempfile as _tf
import shutil as _sh

_dbm_dir = _tf.mkdtemp(prefix="dbm-")


def _mk_db(p, rows=40):
    c = _sq3.connect(p)
    try:
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        c.executemany("INSERT INTO t (v) VALUES (?)", [("x" * 80,) for _ in range(rows)])
        c.commit()
    finally:
        c.close()


def _garbage(p, n=9000):
    with open(p, "wb") as f:
        f.write(os.urandom(n))


try:
    _good = os.path.join(_dbm_dir, "good.db")
    _mk_db(_good)
    check("db-maint: a healthy DB passes integrity_check", _dbm.integrity_check(_good)[0] is True)
    check("db-maint: a missing DB counts as healthy (fresh install)",
          _dbm.integrity_check(os.path.join(_dbm_dir, "nope.db"))[0] is True)
    _garbage(os.path.join(_dbm_dir, "bad.db"))
    check("db-maint: a non-database file is flagged as unhealthy",
          _dbm.integrity_check(os.path.join(_dbm_dir, "bad.db"))[0] is False)
    check("db-maint: optimize a healthy DB succeeds", _dbm.optimize(_good)[0] is True)

    # repair a healthy DB → rebuilds it, and it stays healthy
    _rep_ok, _ = _dbm.repair(_good, None)
    check("db-maint: repair rebuilds a DB that verifies healthy",
          _rep_ok is True and _dbm.integrity_check(_good)[0] is True)

    # corrupt DB + healthy backup → restores the backup, keeps the corrupt copy aside
    _main = os.path.join(_dbm_dir, "main.db")
    _garbage(_main)
    _bkp = _main + ".backup"
    _mk_db(_bkp, rows=8)
    _r2_ok, _ = _dbm.repair(_main, _bkp)
    _aside = any(f.startswith("main.db.corrupt-") for f in os.listdir(_dbm_dir))
    check("db-maint: repair restores a healthy backup when a rebuild can't salvage",
          _r2_ok is True and _dbm.integrity_check(_main)[0] is True and _aside)

    # unsalvageable + no backup → fails safely, original never deleted
    _m2 = os.path.join(_dbm_dir, "m2.db")
    _garbage(_m2)
    _r3_ok, _ = _dbm.repair(_m2, os.path.join(_dbm_dir, "absent.backup"))
    check("db-maint: repair fails safely (keeps the original) when nothing is salvageable",
          _r3_ok is False and os.path.exists(_m2))
finally:
    _sh.rmtree(_dbm_dir, ignore_errors=True)

# ── granular moderation permissions + custom-command scope/argument safety ──
import re as _re
from types import SimpleNamespace as _NS
from auth import can_moderate_action, _custom_command_scope_matches
from models import CUSTOM_ARG_DEFAULT_PATTERN


class _FakeGroup:
    def __init__(self, perms):
        self._p = set(perms)

    def get_permissions(self):
        return self._p


def _u(perms=(), superadmin=False):
    return _NS(is_superadmin=superadmin, groups=[_FakeGroup(perms)])


# A mod granted ONLY kick can kick, but not ban or announce.
_kicker = _u(["kick_player"])
check("mod perm: kick_player -> can kick", can_moderate_action(_kicker, "kick"))
check("mod perm: kick_player -> can NOT ban", not can_moderate_action(_kicker, "ban"))
check("mod perm: kick_player -> can NOT say", not can_moderate_action(_kicker, "say"))
# The umbrella moderate_server (legacy groups) still grants all three.
_umb = _u(["moderate_server"])
check("mod perm: umbrella grants kick+ban+say",
      can_moderate_action(_umb, "kick") and can_moderate_action(_umb, "ban")
      and can_moderate_action(_umb, "say"))
# Full console access implies moderation; no perms implies none; superadmin gets all.
check("mod perm: send_command implies ban", can_moderate_action(_u(["send_command"]), "ban"))
check("mod perm: no perms -> cannot kick", not can_moderate_action(_u([]), "kick"))
check("mod perm: superadmin can do everything",
      can_moderate_action(_u(superadmin=True), "ban"))

# Custom-command scope matching (all / by engine / by game).
_cod2 = _NS(game_type="cod2")
_gmod = _NS(game_type="gmod")
check("cmd scope all -> matches any game",
      _custom_command_scope_matches(_NS(scope_type="all", scope_value=""), _cod2))
check("cmd scope game=cod2 -> matches cod2",
      _custom_command_scope_matches(_NS(scope_type="game", scope_value="cod2"), _cod2))
check("cmd scope game=cod2 -> does NOT match gmod",
      not _custom_command_scope_matches(_NS(scope_type="game", scope_value="cod2"), _gmod))
check("cmd scope engine=idtech3 -> matches cod2 (idTech3)",
      _custom_command_scope_matches(_NS(scope_type="engine", scope_value="idtech3"), _cod2))
check("cmd scope engine=idtech3 -> does NOT match gmod (valve)",
      not _custom_command_scope_matches(_NS(scope_type="engine", scope_value="idtech3"), _gmod))

# Argument charset: real map/entity names pass; anything that could break out of the console
# line (metacharacters, spaces, command substitution, empty) is rejected.
_arg_ok = lambda v: _re.fullmatch(CUSTOM_ARG_DEFAULT_PATTERN, v) is not None
check("custom arg: map name accepted", _arg_ok("mp_toujane"))
check("custom arg: dotted/dashed accepted", _arg_ok("de_dust2-v2.1"))
check("custom arg: rejects ; injection", not _arg_ok("a;rm -rf /"))
check("custom arg: rejects command substitution", not _arg_ok("$(reboot)"))
check("custom arg: rejects backtick", not _arg_ok("`id`"))
check("custom arg: rejects spaces", not _arg_ok("mp toujane"))
check("custom arg: rejects newline", not _arg_ok("a\nb"))
check("custom arg: rejects empty", not _arg_ok(""))

# ── panel branch-switch: git-ref name validation (fed to git + the root installer) ──
# _so is the `import system_ops as _so` from the integrity-tests section above.
check("branch: main valid", _so._valid_branch("main"))
check("branch: feature/x valid", _so._valid_branch("feature/moderation-permissions"))
check("branch: release/v1.2.3 valid", _so._valid_branch("release/v1.2.3"))
check("branch: rejects leading dash (option injection)", not _so._valid_branch("-oProxyCommand=x"))
check("branch: rejects traversal", not _so._valid_branch("a..b"))
check("branch: rejects space", not _so._valid_branch("a b"))
check("branch: rejects ; metachar", not _so._valid_branch("a;reboot"))
check("branch: rejects command substitution", not _so._valid_branch("$(id)"))
check("branch: rejects empty", not _so._valid_branch(""))

# ── cleanup: remove key/config files this run created ─────────
for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE):
    if p not in _pre and os.path.exists(p):
        try:
            p.unlink()
        except OSError:
            pass

passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if results and passed == len(results) else 1)
