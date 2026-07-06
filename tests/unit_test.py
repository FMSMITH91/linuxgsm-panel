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

# ── full (game-file) backups: per-server LinuxGSM backup + settings/due ──
_orig_run7 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "gmodserver-2026.tar.gz\t1048576\t1720000000\nold.tar.gz\t500\t1719000000\n", "", 0)
    _gbl = sm.list_game_backups(None, "gm")
    check("game backups: parsed newest-first with sizes",
          len(_gbl) == 2 and _gbl[0]["name"] == "gmodserver-2026.tar.gz" and _gbl[0]["size"] == 1048576)
finally:
    sm.run_command = _orig_run7
_cap7 = {"cmds": []}
_orig_run8 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_cap7["cmds"].append(c), ("", "", 0))[1]
    _gok, _ = sm.run_game_backup(None, "gm", "gmodserver", 2)
    _joined = " ".join(_cap7["cmds"])
    check("run_game_backup: runs LinuxGSM backup as the game user",
          _gok is True and "sudo -u gm bash -c" in _joined and "./gmodserver backup" in _joined)
    check("run_game_backup: prunes to keep N (keep=2 -> tail +3)", "tail -n +3" in _joined)
finally:
    sm.run_command = _orig_run8

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
check("backup: generates 10 codes", len(_codes) == 10)
check("backup: codes are unique", len(set(_codes)) == 10)
check("backup: xxxxx-xxxxx format", all(len(c) == 11 and c[5] == "-" for c in _codes))
check("backup: unambiguous alphabet (no 0/o/1/l/i)",
      all(ch in "23456789abcdefghjkmnpqrstuvwxyz-" for c in _codes for ch in c))
_u = _User()
_u.set_backup_codes(_codes)
check("backup: 10 remaining after set", _u.backup_codes_remaining == 10)
check("backup: wrong code rejected", not _u.use_backup_code("00000-00000"))
check("backup: valid code accepted (ignores case + dashes)",
      _u.use_backup_code(_codes[0].upper().replace("-", "")))
check("backup: remaining drops to 9 after use", _u.backup_codes_remaining == 9)
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

# ── panel file integrity + repair (git-based) ─────────────────
import system_ops as _so
_so._is_git_checkout = lambda: True
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"]
    else ("M\tapp.py\nD\ttemplates/base.html\n", "", 0) if list(args) == ["diff", "--name-status", "HEAD"]
    else ("", "", 0))
_intg = _so.panel_integrity()
check("integrity: reports git checkout", _intg["git"] is True)
eq("integrity: counts tampered files", _intg["count"], 2)
check("integrity: not clean when files differ", _intg["clean"] is False)

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
_intgf = _so.panel_integrity()
check("integrity: fail-safe when git errors (not verified)",
      _intgf.get("verified") is False and _intgf["clean"] is True)
_okf, _msgf, _ = _so.panel_repair()
check("repair: refuses when integrity can't be verified", _okf is False)

_so._is_git_checkout = lambda: False
check("integrity: handles non-git checkout", _so.panel_integrity()["git"] is False)
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
# The managed lines now run through the inline recorder — the command stays VISIBLE (so the
# grep-based detection/removal still works) but a status-recording suffix is appended.
check("autostart(on): @reboot start line, recorder-wrapped",
      _cron["add"][0].startswith("@reboot ")
      and "/home/gmodserver/gmodserver start" in _cron["add"][0]
      and ".lgsm-cron/" in _cron["add"][0] and ".status" in _cron["add"][0])
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
sm.set_daily_restart(None, "codserver", game_type="cod", port=28960, enabled=True)
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
