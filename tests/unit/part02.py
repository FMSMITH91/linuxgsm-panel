"""Part 2 of the unit suite. Imported for its side effects."""
from unit.part01 import (NS, SO, _privmod, _sm_core, _sm_cron, _sm_files, _sm_firewall, _sm_game, _sm_gmod, _sm_hosts, can_access_remote, check, client_ip, config, eq, os)  # noqa: F401,E402


# ── local-host injection defenses: system_ops runs commands on THIS machine (shell=True), so its
#    request-fed values (block/unban IPs, jail names) must be neutralised before reaching _run. ──
_orig_so_run = SO._run
try:
    _so = []
    SO._run = lambda cmd, *a, **k: (_so.append(cmd), ("", "", 0))[1]

    _ok, _ = SO.ufw_deny_ip("1.2.3.4; rm -rf /")
    check("ufw_deny_ip: non-IP rejected, runs nothing", _ok is False and not _so)
    _so.clear()
    _ok, _ = SO.ufw_deny_ip("10.0.0.5", tag="panel-test")
    check("ufw_deny_ip: valid IP reaches ufw insert",
          _ok is True and any("ufw insert 1 deny from 10.0.0.5" in c for c in _so))
    _so.clear()
    SO.ufw_deny_ip("10.0.0.6", tag="ev;il`x`")   # tag must be charset-stripped
    check("ufw_deny_ip: tag stripped of shell metacharacters",
          all(";" not in c and "`" not in c for c in _so))
    _so.clear()
    _ok, _ = SO.ufw_undeny_ip("not-an-ip")
    check("ufw_undeny_ip: non-IP rejected, runs nothing", _ok is False and not _so)
finally:
    SO._run = _orig_so_run

# ── fail2ban_unban: jail must be metacharacter-free AND on the host's real jail allowlist;
#    IP is canonicalised through ipaddress. Both are shlex-quoted at the sink. ──
_orig_so_run2, _orig_jails = SO._run, SO._fail2ban_jails
try:
    _fb = []
    SO._run = lambda cmd, *a, **k: (_fb.append(cmd), ("", "", 0))[1]
    SO._fail2ban_jails = lambda: ["sshd", "panel-login"]

    _ok, _ = SO.fail2ban_unban("sshd; rm -rf /", "1.2.3.4")
    check("fail2ban_unban: metachar jail rejected, runs nothing", _ok is False and not _fb)
    _fb.clear()
    _ok, _ = SO.fail2ban_unban("nftables", "1.2.3.4")   # charset-ok but not on the host
    check("fail2ban_unban: jail not on host allowlist rejected", _ok is False and not _fb)
    _fb.clear()
    _ok, _ = SO.fail2ban_unban("sshd", "9.9.9.9; reboot")
    check("fail2ban_unban: bad IP rejected, runs nothing", _ok is False and not _fb)
    _fb.clear()
    _ok, _ = SO.fail2ban_unban("sshd", "9.9.9.9")
    check("fail2ban_unban: valid jail+IP reaches fail2ban-client",
          _ok is True and any("fail2ban-client set sshd unbanip 9.9.9.9" in c for c in _fb))
finally:
    SO._run, SO._fail2ban_jails = _orig_so_run2, _orig_jails

# ── GMod mountable content: the game picker is allow-listed, and the mount config is generated from a
#    validated content username + constant game keys (so it's safe to write verbatim). ──
eq("gmod content: unknown games filtered, order + dedupe preserved",
   _sm_gmod._valid_content_games(["cstrike", "tf", "doom", "cstrike"]), ["cstrike", "tf"])
eq("gmod content: empty -> []", _sm_gmod._valid_content_games([]), [])
_gmc, _gmd = _sm_gmod._gmod_mount_files("srcds", ["cstrike", "tf"])
check("gmod content: mount.cfg points each game at the content user's serverfiles",
      _gmc.startswith('"mountcfg"') and '"cstrike"\t"/home/srcds/serverfiles/cstrike"' in _gmc
      and '"tf"\t"/home/srcds/serverfiles/tf"' in _gmc)
check("gmod content: mountdepots enables hl2 + each game",
      _gmd.startswith('"gamedepotsystem"') and '"hl2"' in _gmd and '"cstrike"' in _gmd and '"tf"' in _gmd)
check("gmod content: installable games map to a LinuxGSM name, mount-only map to None",
      all(isinstance(v[1], str) for v in _sm_gmod.GMOD_CONTENT_GAMES.values() if v[1] is not None)
      and _sm_gmod.GMOD_CONTENT_GAMES["cstrike"][1] == "cssserver"
      and _sm_gmod.GMOD_CONTENT_GAMES["hl1mp"][1] == "hldmsserver"     # free via LinuxGSM, not owned-only
      and _sm_gmod.GMOD_CONTENT_GAMES["zps"][1] == "zpsserver"         # extra free Source game
      and _sm_gmod.GMOD_CONTENT_GAMES["hl2"][1] is None                # owned single-player -> mount-only
      and "csgo" not in _sm_gmod.GMOD_CONTENT_GAMES                    # dropped (CS2 now, unmountable)
      and sum(1 for v in _sm_gmod.GMOD_CONTENT_GAMES.values() if v[1] is not None) == 16)
# Weekly content-update cron: update-lgsm (scripts) then update (content), Sunday, staggered, as the
# content user — so mounted content stays current (Source games get content updates).
_cron_body = _sm_gmod._content_update_cron_body("srcds", ["cssserver", "tf2server"])
check("gmod content cron: per-game update + update-lgsm as the content user, Sunday, staggered",
      "0 1 * * 0 srcds /home/srcds/cssserver update-lgsm" in _cron_body
      and "2 1 * * 0 srcds /home/srcds/tf2server update-lgsm" in _cron_body
      and "0 2 * * 0 srcds /home/srcds/cssserver update >" in _cron_body
      and "10 2 * * 0 srcds /home/srcds/tf2server update >" in _cron_body)
# uninstall removes the content dir + the LinuxGSM install (host-wide), and rejects a bad user.
_orig_un_rc, _orig_un_rp = _sm_core.run_command, _sm_core.run_privileged
try:
    # These used to assert on the three `rm -rf` strings the call site built. It builds NAMES now
    # and the helper builds the paths, so the assertion moves to the verb — and the paths those
    # names produce are checked once, here, against privileged.content_path().
    _un = []
    _sm_core.run_command = lambda s, c, **k: (_un.append(("cmd", c)), ("N", "", 0))[1]
    _sm_core.run_privileged = lambda s, v, a=(), **k: (_un.append((v, list(a))), ("N", "", 1))[1]
    _uok, _urem, _ = _sm_gmod.uninstall_gmod_content(object(), "gmodcontent", ["cstrike"])
    check("gmod content uninstall: asks to remove the game, its script and its config",
          ("content-game-remove", ["gmodcontent", "cstrike", "cssserver"]) in _un
          and _urem == ["cstrike"], str(_un))
    _un[:] = []
    _uok3, _urem3, _ = _sm_gmod.uninstall_gmod_content(object(), "srcds", ["hl2"])   # mount-only game
    check("gmod content uninstall: a mount-only (owned) game passes '-' for 'no script'",
          ("content-game-remove", ["srcds", "hl2", "-"]) in _un and _urem3 == ["hl2"], str(_un))
    _un[:] = []
    _uok2, _, _ = _sm_gmod.uninstall_gmod_content(object(), "bad;user", ["cstrike"])
    check("gmod content uninstall: rejects an invalid content user, runs nothing",
          _uok2 is False and not _un)
finally:
    _sm_core.run_command, _sm_core.run_privileged = _orig_un_rc, _orig_un_rp

# And the names really do resolve to the three paths the shell form removed — asserted against the
# path builder rather than against a command string, so it holds for both transports.
eq("gmod content uninstall: the game's content dir",
   _privmod.content_path("gmodcontent", "serverfiles", "cstrike"),
   "/home/gmodcontent/serverfiles/cstrike")
eq("gmod content uninstall: the LinuxGSM script",
   _privmod.content_path("gmodcontent", "cssserver"), "/home/gmodcontent/cssserver")
eq("gmod content uninstall: the LinuxGSM config",
   _privmod.content_path("gmodcontent", "lgsm", "config-lgsm", "cssserver"),
   "/home/gmodcontent/lgsm/config-lgsm/cssserver")
# free disk on the content filesystem (shown on the card so nobody starts a 13GB install without room)
_orig_df_rp = _sm_core.run_privileged
try:
    # The fixture is now REAL `df -PB1` output, header and all, because the awk that used to
    # reduce it to two fields (under root) is gone and the parsing happens in Python. That makes
    # this a stronger test than it was: it exercises the column indices, not awk's answer.
    _DF_OUT = ("Filesystem       1B-blocks         Used    Available Use% Mounted on\n"
               "/dev/sda1     500107862016 376651072004 123456789012  76% /home\n")
    _sm_core.run_privileged = lambda s, v, a=(), **k: (_DF_OUT, "", 0)
    eq("path_disk_free: parses (free, total) from real df output",
       _sm_gmod.path_disk_free(object(), "/home/gmodcontent/serverfiles"), (123456789012, 500107862016))
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("garbage", "", 0)
    eq("path_disk_free: junk output -> (None, None)", _sm_gmod.path_disk_free(object(), "/home"), (None, None))
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "", 0)
    eq("path_disk_free: empty output -> (None, None)", _sm_gmod.path_disk_free(object(), "/home"), (None, None))
finally:
    _sm_core.run_privileged = _orig_df_rp
# gmod_current_mounts: parse a real mount.cfg, keep only known games, ignore the header + unknowns.
_orig_gm_rc2 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (
        '"mountcfg"\n{\n\t"cstrike"\t"/home/srcds/serverfiles/cstrike"\n'
        '\t"tf"\t"/home/srcds/serverfiles/tf"\n'
        '//\t"csgo"\t"/home/srcds/serverfiles/csgo"\n'      # commented-out mount must NOT count
        '\t"notagame"\t"/x"\n}\n', "", 0)
    eq("gmod content: current mounts skip commented (//) lines + header + unknowns",
       _sm_gmod.gmod_current_mounts(object(), "gmodserver"), ["cstrike", "tf"])
finally:
    _sm_core.run_command = _orig_gm_rc2
# detect_content_user: parse a host scan, reject non-username tokens, resolve the primary group.
_orig_gm_rc = _sm_core.run_command
try:
    def _gm_fake(server, cmd, **k):
        if "for u in" in cmd:
            return "HIT|srcds|cstrike\nHIT|b@d|cstrike\nHIT|srcds|cstrike", "", 0
        if "id -gn" in cmd:
            return "srcds", "", 0
        return "", "", 0
    _sm_core.run_command = _gm_fake
    _det = _sm_gmod.detect_content_user(object(), ("cstrike",))
    check("gmod content: detect reuses a valid content user, rejects bad usernames",
          bool(_det) and _det["user"] == "srcds" and _det["group"] == "srcds"
          and _det["present"].get("cstrike") == "/home/srcds/serverfiles/cstrike")
finally:
    _sm_core.run_command = _orig_gm_rc

# a bad schedule is rejected by update before any SSH
_bad = _sm_cron.update_cron_job(None, "gm", "0 3 * * * /home/gm/backup.sh", "not-a-schedule", "x", "gmodserver")
check("cron: update rejects a bad schedule (no SSH)", _bad[0] is False)
# cron run-history: the recorder wrap/unwrap round-trips, and status files parse.
import base64 as _b64
_ccmd = "/home/gm/backup.sh --full && echo done"
_cjid = _sm_cron._cron_job_id(_ccmd)
check("cron: job id is a stable 12-hex hash",
      _cjid == _sm_cron._cron_job_id(_ccmd) and len(_cjid) == 12
      and all(c in "0123456789abcdef" for c in _cjid))
_wrapped = "/home/gm/.lgsm-cron/run %s %s" % (_cjid, _b64.b64encode(_ccmd.encode()).decode())
check("cron: unwrap recovers the original command",
      _sm_cron._unwrap_cron_command(_wrapped) == (_ccmd, _cjid))
check("cron: unwrap leaves a plain command untouched",
      _sm_cron._unwrap_cron_command("/home/gm/x.sh") == ("/home/gm/x.sh", None))
# Maintenance + autostart jobs use the INLINE recorder: the command stays visible (so the grep-based
# dedup/removal + last-run detection still work) and unwraps to the core command + a job id.
_mrec = _sm_cron._record_managed_cmd("gm", "/home/gm/gmodserver update")
check("managed cron: inline-recorded maintenance line still matches the dedup remove-regex",
      bool(__import__("re").search(r"/home/gm/gmodserver (monitor|mods-update|update|update-lgsm) ", _mrec)))
check("managed cron: unwrap recovers the core command + id",
      _sm_cron._unwrap_cron_command(_mrec)
      == ("/home/gm/gmodserver update", _sm_cron._cron_job_id("/home/gm/gmodserver update")))
# Nothing is managed now: an inline-recorded line (even monitor) is editable/deletable — the role
# label is all that distinguishes a panel line.
check("cron: an inline-recorded maintenance line is not managed (editable/deletable)",
      not _sm_cron._cron_line_managed(_mrec, "gm", "gmodserver"))
check("cron: an inline-recorded monitor line is not managed either — just role-labelled 'autostart'",
      not _sm_cron._cron_line_managed(_sm_cron._record_managed_cmd("gm", "/home/gm/gmodserver monitor"), "gm", "gmodserver")
      and _sm_cron._cron_role("/home/gm/gmodserver monitor", "gm", "gmodserver") == "autostart")
# upgrade_managed_cron_tracking rewraps EXISTING managed lines in place, leaving user jobs and
# the compound restart-check untouched (so old installs get success/error without a reinstall).
_upcap = {}
_orig_rw_u = _sm_core._rewrite_crontab
_orig_run_u = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (
        "*/5 * * * * /home/gm/gmodserver monitor > /dev/null 2>&1\n"
        "@reboot /home/gm/gmodserver start > /dev/null 2>&1\n"
        "0 3 * * * /home/gm/backup.sh\n"
        "10 * * * * [ -f /home/gm/.restart-pending ] && { /home/gm/gmodserver restart; }\n", "", 0)
    _sm_core._rewrite_crontab = lambda s, u, grep, add, extra_pre="": (_upcap.update(add=list(add)) or (True, "ok"))
    _ures = _sm_cron.upgrade_managed_cron_tracking(None, "gm", "gmodserver")
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
    _sm_core._rewrite_crontab = _orig_rw_u
    _sm_core.run_command = _orig_run_u
import base64 as _b64cr


def _cron_wire(jobs):
    """Build the reader's wire reply: one tab-delimited line per job, log tail base64'd."""
    return "".join("%s\t%s\t%s\t%s\t%s\n"
                   % (jid, rc, st, en, _b64cr.b64encode(log.encode()).decode())
                   for jid, rc, st, en, log in jobs)


_orig_run3 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (_cron_wire([("aaaaaaaaaaaa", 0, 100, 142, ""),
                                                    ("bbbbbbbbbbbb", 1, 200, 205, "boom: exit 1")]),
                                        "", 0)
    _cst = _sm_cron._read_cron_status(None, "gm")
    check("cron status: a successful run parses (ok + last_run)",
          _cst["aaaaaaaaaaaa"]["ok"] is True and _cst["aaaaaaaaaaaa"]["last_run"] == 142)
    check("cron status: a failed run parses with its error tail",
          _cst["bbbbbbbbbbbb"]["ok"] is False and _cst["bbbbbbbbbbbb"]["error"] == "boom: exit 1")
finally:
    _sm_core.run_command = _orig_run3
# A FAITHFUL aborted `update-lgsm` log, byte-for-byte in the shape LinuxGSM writes one: fn_print_dots
# repaints the first line with \r, the reason arrives mid-log, and fn_print_*_eol_nl appends its
# verdict as a separate " ... FAIL" line. The \r is the whole point — it used to end the wire record
# early (text=True transports fold \r into \n; str.splitlines() splits on it), so the panel showed a
# red Failed badge with NO reason: worse than the ANSI soup this was meant to replace.
_lgsm_log = ("\x1b[1m\r\x1b[K[\x1b[0m .... \x1b[0m]\x1b[0m Updating LinuxGSM pmcserver: "
             "\x1b[0m\x1b[1m\r\x1b[K[\x1b[32m  OK  \x1b[0m]\x1b[0m Updating LinuxGSM: repo: GitHub\x1b[0m\n"
             "checking GitHub config [ \x1b[3mubuntu-24.04.csv\x1b[0m ] ... \x1b[33mUPDATE\x1b[0m\n"
             "fetching GitHub [ \x1b[3mubuntu-24.04.csv\x1b[0m ]"
             "curl: (22) The requested URL returned error: 404\n"
             " ... \x1b[31mERROR\x1b[0m\n"
             "fetching Bitbucket [ \x1b[3mubuntu-24.04.csv\x1b[0m ]"
             "curl: (22) The requested URL returned error: 404\n"
             " ... \x1b[31mFAIL\x1b[0m\n")
_orig_run3r = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (_cron_wire([("cc33dd44ee55", 1, 100, 106, _lgsm_log)]), "", 0)
    _rerr = _sm_cron._read_cron_status(None, "gm")["cc33dd44ee55"]["error"]
finally:
    _sm_core.run_command = _orig_run3r
# These go THROUGH the reader, not straight to the helper: that is the link the fix is about, and a
# revert of either half (the base64 wire or the _clean_cron_error call) fails them.
check("cron error (via reader): the reason survives a \\r-repainted log",
      "curl: (22) The requested URL returned error: 404" in _rerr and "ubuntu-24.04.csv" in _rerr)
check("cron error (via reader): no escape bytes reach the UI",
      "\x1b" not in _rerr and "[31m" not in _rerr and "[K" not in _rerr)
check("cron error (via reader): bare verdict lines dropped", "FAIL" not in _rerr)
check("cron error (via reader): fits the UI cell", 0 < len(_rerr) <= 240)
check("cron error (via reader): both mirror attempts are shown (they are different lines)",
      "fetching GitHub" in _rerr and "fetching Bitbucket" in _rerr)
check("cron error: an IDENTICAL repeated line is not shown twice",
      _sm_cron._clean_cron_error("fetching GitHub [ x.csv ]curl: (22) 404\n ... ERROR\n"
                           "fetching GitHub [ x.csv ]curl: (22) 404\n ... FAIL\n")
      == "fetching GitHub [ x.csv ]curl: (22) 404")
check("cron error (via reader): undecodable payload costs only that job's reason",
      _sm_cron._cron_log_text("not valid base64 !!") == ""
      and _sm_cron._cron_log_text(_b64cr.b64encode(b"caf\xe9: cannot start").decode()).startswith("caf"))
_lgsm_err = _sm_cron._clean_cron_error(_lgsm_log)
check("cron error: ANSI colour codes stripped", "\x1b" not in _lgsm_err and "[31m" not in _lgsm_err)
check("cron error: keeps the line that says why",
      "curl: (22) The requested URL returned error: 404" in _lgsm_err
      and "ubuntu-24.04.csv" in _lgsm_err)
check("cron error: bare ' ... FAIL' verdict lines dropped",
      "FAIL" not in _lgsm_err and "ERROR" not in _lgsm_err)
check("cron error: only a line's final \\r repaint is kept",
      _sm_cron._clean_cron_error("checking....\rchecking [ done ] failed to start") ==
      "checking [ done ] failed to start")
check("cron error: informative lines win over surrounding chatter",
      _sm_cron._clean_cron_error("step 1 ok\nstep 2 ok\nstep 3 ok\nstep 4 ok\n"
                           "cannot write /home/gm/x: permission denied\n ... FAIL")
      == "cannot write /home/gm/x: permission denied")
check("cron error: falls back to the tail when nothing looks like a reason",
      _sm_cron._clean_cron_error("aaa\nbbb\nccc\nddd") == "bbb ccc ddd")
check("cron error: capped for the UI cell", len(_sm_cron._clean_cron_error("error " + "x" * 900)) <= 240)
check("cron error: a line too long for the budget is not dropped entirely",
      _sm_cron._clean_cron_error("error " + "x" * 900).startswith("error x"))
_pack = _sm_cron._clean_cron_error("\n".join("failed step %d %s" % (i, "y" * 70) for i in range(4)))
check("cron error: the budget packs whole lines and never cuts mid-line",
      len(_pack) <= 240 and _pack.endswith("y" * 70)
      and "failed step 2" in _pack and "failed step 3" in _pack
      and "failed step 0" not in _pack)
# A CRLF log tail is the case the old `.split("\r")[-1]` silently emptied: every line ends in \r,
# so the "last repaint" was "" and the failure reason vanished — the blank red "Failed" badge again,
# in the module the console fix did not touch.
eq("cron error: a CRLF log still yields its reason",
   _sm_cron._clean_cron_error("checking config\r\ncurl: (22) The requested URL returned error: 404\r\n"),
   "curl: (22) The requested URL returned error: 404")
check("cron error: a mid-line repaint keeps what is on screen",
      _sm_cron._clean_cron_error("working...\rdone: permission denied") == "done: permission denied")
check("cron error: empty output stays empty", _sm_cron._clean_cron_error("") == ""
      and _sm_cron._clean_cron_error(None) == "")
# The reader must base64 the tail (so no log byte can break the record) and cap it BEFORE encoding.
_cronrd = {}
_orig_run3b = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (_cronrd.update(cmd=c), ("", "", 0))[1]
    _sm_cron._read_cron_status(None, "gm")
    check("cron status: reads a wide tail, base64-framed, byte-capped before encoding",
          "tail -n 40" in _cronrd["cmd"] and "base64" in _cronrd["cmd"]
          and _cronrd["cmd"].index("tail -c 3000") < _cronrd["cmd"].index("base64"))
finally:
    _sm_core.run_command = _orig_run3b
# cron run-times from the journald cron log (last-run TIME for managed/legacy jobs)
_orig_run4 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (
        "1720000000 host CRON[11]: (gm) CMD (/home/gm/gmodserver monitor > /dev/null 2>&1)\n"
        "1720003600 host CRON[12]: (gm) CMD (/home/gm/gmodserver monitor > /dev/null 2>&1)\n"
        "1720007200 host CRON[13]: (gm) CMD (touch /home/gm/.restart-pending)\n", "", 0)
    _rt = _sm_cron._read_cron_run_times(None, "gm")
    check("cron run-times: newest run wins for a repeated command",
          _rt["/home/gm/gmodserver monitor > /dev/null 2>&1"] == 1720003600)
    check("cron run-times: parses a second distinct command",
          _rt["touch /home/gm/.restart-pending"] == 1720007200)
finally:
    _sm_core.run_command = _orig_run4
# _match_run_time: a wrapped job's CORE command matches its logged line (old or wrapped form),
# so a freshly-upgraded job shows its run time instead of "—" until the recorder status lands.
_rtm = {"/home/gm/gmodserver monitor > /dev/null 2>&1": 100,
        "mkdir -p /home/gm/.lgsm-cron && /home/gm/gmodserver monitor > /home/gm/.lgsm-cron/ab.log 2>&1": 200}
check("run-time match: core command matches wrapped/old log line (newest wins)",
      _sm_cron._match_run_time(_rtm, "/home/gm/gmodserver monitor") == 200)
check("run-time match: exact command matches",
      _sm_cron._match_run_time({"touch /home/gm/.restart-pending": 50}, "touch /home/gm/.restart-pending") == 50)
check("run-time match: no match returns None",
      _sm_cron._match_run_time({"a b c": 1}, "/home/gm/nothing") is None)
# run_cron_job_now: runs the job's UNWRAPPED core command, detached, as the game user, and
# records to the job's own status file (so Last-run updates).
import base64 as _b64rn, re as _rern
_wl = ("*/5 * * * * /home/gm/.lgsm-cron/run " + _sm_cron._cron_job_id("/home/gm/backup.sh --full")
       + " " + _b64rn.b64encode(b"/home/gm/backup.sh --full").decode())
_rncap = {}
_orig_run6 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (_rncap.update(cmd=c), ("", "", 0))[1]
    _rok, _ = _sm_cron.run_cron_job_now(None, "gm", _wl, "gmodserver")
    _c = _rncap["cmd"]
    check("run now: dispatched ok", _rok is True)
    check("run now: detached run as the game user",
          "sudo -u gm bash -c" in _c and "setsid bash" in _c)
    _m = _rern.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d", _c)
    _rec = _b64rn.b64decode(_m.group(1)).decode() if _m else ""
    check("run now: runs the unwrapped core command", "/home/gm/backup.sh --full >" in _rec)
    check("run now: records to the job's own status file",
          ("/home/gm/.lgsm-cron/" + _sm_cron._cron_job_id("/home/gm/backup.sh --full") + ".status") in _rec)
finally:
    _sm_core.run_command = _orig_run6

# ── backup module: create / list / prune + path-traversal guard ──
from panel.ops import backup as _bk
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

# ── encrypted backups ────────────────────────────────────────────────────────────────────────
# An unencrypted archive is a skeleton key: panel.db AND secret_key AND cred_key in one file, so a
# single copy off the machine undoes every encrypted column at once.
#
# get_passphrase() is STUBBED rather than set through set_passphrase(): that writes the real
# data/config.json via update_config(), which no unit test may touch. The path constants above are
# redirected at the module, but panel.core.config's are not.
_bk_pass = "correct horse battery staple"
_orig_getpass = _bk.get_passphrase
_bk.get_passphrase = lambda: _bk_pass
try:
    _eok, _ename = _bk.create_backup("manual")
    check("backup/enc: a passphrase makes the archive .enc",
          _eok and _ename.endswith(".enc") and bool(_bk._NAME_RE.match(_ename)), str(_ename))
    _epath = _bk._safe_path(_ename)
    check("backup/enc: the .enc name still resolves through _safe_path", _epath is not None)
    _eblob = _epath.read_bytes()
    check("backup/enc: it carries the format header", _eblob.startswith(_bk._ENC_MAGIC))
    # The point of the whole feature: nothing readable is left in the file.
    check("backup/enc: the archive is no longer an openable tar",
          not _bk._is_readable_tar(_epath), "it still opens as a tar — it is not encrypted")
    check("backup/enc: no member names or key material survive in the clear",
          b"panel.db" not in _eblob and b"cred_key" not in _eblob and b"secret_key" not in _eblob)
    check("backup/enc: written 0600", (_osb.stat(_epath).st_mode & 0o777) == 0o600,
          oct(_osb.stat(_epath).st_mode & 0o777))
    check("backup/enc: the listing flags it, and the plain one is not flagged",
          all(b["encrypted"] is b["name"].endswith(".enc") for b in _bk.list_backups()))
    check("backup/enc: kind is still parsed correctly with the .enc suffix",
          [b["kind"] for b in _bk.list_backups() if b["name"] == _ename] == ["manual"])

    # Every assertion below reports a FAIL rather than raising. An exception here aborts the whole
    # part file before the summary prints, which hides both this block's result AND every check
    # after it — a broken encryption path would look like a suite that simply produced no output.
    _out = str(_bktmp / "rt.tar.gz")
    _dec_ok, _dec_msg = _bk._decrypt_archive(str(_epath), _out, _bk_pass)
    check("backup/enc: the right passphrase decrypts it", _dec_ok, _dec_msg)
    _members = None
    if _dec_ok and _osb.path.exists(_out):
        try:
            with _tar.open(_out) as _t2:
                _members = set(_t2.getnames())
        except Exception as _e:
            _members = "unreadable: %s" % _e
    check("backup/enc: ...back to the same four members",
          _members == {"panel.db", "config.json", "secret_key", "cred_key"}, str(_members))
    check("backup/enc: a wrong passphrase is refused",
          not _bk._decrypt_archive(str(_epath), _out, "wrong one entirely")[0])
    check("backup/enc: no passphrase is refused, and says why",
          _bk._decrypt_archive(str(_epath), _out, "") == (False,
              "This backup is encrypted — a passphrase is required."))
    # Fernet authenticates; a modified archive must never be unpacked over a live install.
    _tamp = bytearray(_eblob); _tamp[-20] ^= 0xFF
    _tpath = str(_bktmp / "tampered.enc"); open(_tpath, "wb").write(bytes(_tamp))
    check("backup/enc: a single flipped ciphertext bit is refused",
          not _bk._decrypt_archive(_tpath, _out, _bk_pass)[0])
    # A truncated/garbage header must fail cleanly rather than raise.
    open(_tpath, "wb").write(_bk._ENC_MAGIC + b"not json\n" + b"x" * 40)
    check("backup/enc: a damaged header fails cleanly, without raising",
          _bk._decrypt_archive(_tpath, _out, _bk_pass)[0] is False)
    check("backup/enc: a plain tar.gz is not mistaken for an encrypted one",
          _bk._decrypt_archive(str(_bk._safe_path(_bname)), _out, _bk_pass)[0] is False)
    # Salt is per-archive, so two backups of identical input share no ciphertext prefix.
    _eok2, _ename2 = _bk.create_backup("manual")
    check("backup/enc: each archive gets its own salt",
          _bk._safe_path(_ename2).read_bytes()[:200] != _eblob[:200])

    # ── restore_backup end to end on an ENCRYPTED archive ──────────────────────────────────
    # The destructive step is the privileged verb, so stubbing it leaves the whole real path
    # covered: decrypt -> validate members -> pre-restore safety backup -> stage -> dispatch.
    # Splitting restore_backup in two to fit decryption in front of it left `name` out of scope
    # in the second half — an UnboundLocalError on the success line of every restore, which no
    # suite would have hit because restore is destructive and nothing called it. flake8 caught
    # that one; this check is what makes it stay caught.
    _o_hp, _o_rv = _bk._helper_present, _bk._run_verb
    _bk._helper_present = lambda: True
    _bk._run_verb = lambda *a, **k: ("", "", 0)
    try:
        _rok, _rmsg = _bk.restore_backup(_ename, passphrase=_bk_pass)
        check("backup/enc: restoring an encrypted archive succeeds end to end", _rok, str(_rmsg))
        check("backup/enc: ...and the message names the backup, not the temp file",
              _ename in str(_rmsg) and "/tmp" not in str(_rmsg), str(_rmsg))
        # listdir must not raise when the restore failed: the dispatch swallows exceptions and
        # REMOVES the stage dir on its way out, so a broken restore leaves nothing to list — and
        # an abort here would hide this block's own verdict along with every later check.
        _stage_dir = _osb.path.join(str(_bk.DATA_DIR), ".restore-stage")
        _staged = sorted(_osb.listdir(_stage_dir)) if _osb.path.isdir(_stage_dir) else None
        check("backup/enc: ...and it staged the real members",
              _staged == ["config.json", "cred_key", "panel.db", "secret_key"], str(_staged))
        # A wrong passphrase must stop BEFORE anything is touched — no pre-restore backup, no
        # staging. Getting this order wrong means a mistyped passphrase still churns the install.
        _sh2.rmtree(_stage_dir, ignore_errors=True)
        # COUNTING backups cannot see this: create_backup names files to the second, so two
        # pre-restore backups in the same second collide on one name and the count never moves.
        # Counting the CALL is exact, and it is the actual claim — nothing is touched until the
        # archive has been opened, so a mistyped passphrase costs nothing.
        _pre_calls = []
        _o_create = _bk.create_backup
        _bk.create_backup = lambda kind="manual", encrypt=True: (
            _pre_calls.append((kind, encrypt)), (True, "stub"))[1]
        try:
            _wok, _wmsg = _bk.restore_backup(_ename, passphrase="not the passphrase")
        finally:
            _bk.create_backup = _o_create
        check("backup/enc: a wrong passphrase refuses the restore", not _wok, str(_wmsg))
        check("backup/enc: ...and takes no pre-restore backup before it knows the archive opens",
              _pre_calls == [], "create_backup called with %r" % (_pre_calls,))
        check("backup/enc: ...and stages nothing", not _osb.path.exists(_stage_dir))

        # ── The pre-restore safety copy is the ONE thing standing between a mistaken restore and
        # an unrecoverable install, and two things were wrong with it.
        #
        # 1. Its result was discarded. create_backup swallows every exception and answers
        #    (False, "Backup failed — see panel logs.") — a full disk, a BACKUP_DIR whose mode
        #    changed, a _snapshot_db failure on a database that is already damaged. Execution fell
        #    straight through to the destructive verb while the UI said "the panel will restart in
        #    a few seconds". Losing cred_key that way makes every stored SSH credential unreadable.
        _sh2.rmtree(_stage_dir, ignore_errors=True)
        _pre_calls.clear()
        _bk.create_backup = lambda kind="manual", encrypt=True: (
            _pre_calls.append((kind, encrypt)), (False, "Backup failed — see panel logs."))[1]
        try:
            _fok, _fmsg = _bk.restore_backup(_ename, passphrase=_bk_pass)
        finally:
            _bk.create_backup = _o_create
        check("backup: a failed pre-restore safety copy stops the restore",
              _fok is False and "safety copy" in _fmsg, str(_fmsg))
        check("backup: ...before anything is staged", not _osb.path.exists(_stage_dir))
        check("backup: ...and the refusal says what would be lost and how to go ahead",
              "cred_key" in _fmsg and "Confirm again" in _fmsg, str(_fmsg))
        # The operator's override still works — refusing outright would strand exactly the person
        # who needs restore most, the one whose panel.db is already too damaged to snapshot.
        _pre_calls.clear()
        _bk.create_backup = lambda kind="manual", encrypt=True: (
            _pre_calls.append((kind, encrypt)), (False, "Backup failed — see panel logs."))[1]
        try:
            _sok, _smsg = _bk.restore_backup(_ename, passphrase=_bk_pass, skip_safety_backup=True)
        finally:
            _bk.create_backup = _o_create
        check("backup: ...unless the operator says to go ahead without one",
              _sok is True and _pre_calls == [] and "NO pre-restore safety copy" in _smsg,
              "%s %r" % (_smsg, _pre_calls))
        # 2. It was encrypted with get_passphrase() — read from config.json under cred_key, BOTH
        #    of which the next step overwrites from the archive being restored. Restoring an
        #    archive written under a different passphrase (from before a set_passphrase, or from
        #    another install — the case restore's own docstring calls out) left the safety net
        #    locked by a key that no longer existed.
        _sh2.rmtree(_stage_dir, ignore_errors=True)
        _pre_calls.clear()
        _bk.create_backup = lambda kind="manual", encrypt=True: (
            _pre_calls.append((kind, encrypt)), (True, "prerestore-stub"))[1]
        try:
            _eok3, _emsg3 = _bk.restore_backup(_ename, passphrase=_bk_pass)
        finally:
            _bk.create_backup = _o_create
        check("backup: the pre-restore copy is written UNENCRYPTED, not under a key it is about to destroy",
              _pre_calls == [("prerestore", False)], repr(_pre_calls))
        check("backup: ...and the operator is told its name, since the panel is about to restart",
              _eok3 and "prerestore-stub" in _emsg3, str(_emsg3))
        # And create_backup honours that for real: a passphrase IS configured in this block.
        _uok, _uname = _bk.create_backup("prerestore", encrypt=False)
        check("backup: create_backup(encrypt=False) writes a plain archive despite a configured passphrase",
              _uok and not _bk.is_encrypted_backup(_uname)
              and _tar.open(str(_bk._safe_path(_uname))).getnames(), "%s %s" % (_uok, _uname))
        check("backup: ...and it is still 0600 inside the 0700 backup dir",
              _osb.stat(str(_bk._safe_path(_uname))).st_mode & 0o777 == 0o600,
              oct(_osb.stat(str(_bk._safe_path(_uname))).st_mode & 0o777))
        _sh2.rmtree(_stage_dir, ignore_errors=True)
    finally:
        _bk._helper_present, _bk._run_verb = _o_hp, _o_rv
finally:
    _bk.get_passphrase = _orig_getpass

# set_passphrase / get_passphrase against an IN-MEMORY config. Both reach panel.core.config, whose
# CONFIG_FILE is the real data/config.json and is NOT redirected by the path overrides above — so
# load_config/update_config are stubbed in the backup module's namespace instead. Calling the real
# ones here would write the developer's own config.
_fakecfg = {}
_o_load, _o_upd = _bk.load_config, _bk.update_config


def _fake_upd_pass(m):
    m(_fakecfg)
    return _fakecfg


_bk.load_config = lambda: dict(_fakecfg)
_bk.update_config = _fake_upd_pass
try:
    _bk.set_passphrase("a passphrase worth protecting")
    _raw = _fakecfg.get("backup_passphrase", "")
    # The archive CARRIES config.json, so a passphrase stored in the clear would ship inside every
    # backup it protects — the one place it must never be readable.
    check("backup/enc: the passphrase is stored encrypted, not in the clear",
          bool(_raw) and "a passphrase worth protecting" not in _raw and config.is_encrypted(_raw),
          _raw[:40])
    check("backup/enc: ...and reads back correctly",
          _bk.get_passphrase() == "a passphrase worth protecting")
    _bk.set_passphrase("")
    check("backup/enc: clearing it empties the stored value and turns encryption off",
          not _fakecfg.get("backup_passphrase") and _bk.get_passphrase() == "")
    # A short passphrase must be refused by set_passphrase ITSELF, not only by the route. It is
    # the only thing between a leaked archive and every secret in it, and a second caller — a
    # manage.py subcommand, a setup step — would otherwise set a two-character one unopposed.
    _short_ok = False
    try:
        _bk.set_passphrase("short")
    except ValueError:
        _short_ok = True
    check("backup/enc: set_passphrase refuses a passphrase under the minimum", _short_ok)
    check("backup/enc: ...and refusing it did not change what is stored",
          not _fakecfg.get("backup_passphrase"))
    check("backup/enc: the route and the helper share one minimum, so they cannot drift",
          _bk.MIN_PASSPHRASE_LEN == 12)
finally:
    _bk.load_config, _bk.update_config = _o_load, _o_upd

# KDF parameters come out of the archive HEADER, so they are only as trustworthy as the file.
# Nothing can upload one today, but scrypt's n is a memory parameter and n=2**30 asks for a
# gigabyte before it fails — bound it while that is three lines rather than an incident.
_kdf_tmp = _pl.Path(_tf.mkdtemp())
_kdf_out = str(_kdf_tmp / "out.tar.gz")


def _kdf_blob(n=2 ** 15, r=8, p=1, salt_len=16):
    import base64 as _b64, json as _js
    head = _js.dumps({"kdf": "scrypt", "n": n, "r": r, "p": p,
                      "salt": _b64.b64encode(b"s" * salt_len).decode()},
                     separators=(",", ":"), sort_keys=True).encode()
    blob = _bk._ENC_MAGIC + head + b"\n" + b"not-a-real-token"
    _f = str(_kdf_tmp / "probe.enc")
    open(_f, "wb").write(blob)
    return _f


check("backup/enc: an absurd scrypt n is refused before any memory is allocated",
      _bk._decrypt_archive(_kdf_blob(n=2 ** 30), _kdf_out, "pw")
      == (False, "The encrypted backup's header asks for parameters this panel will not use."))
check("backup/enc: ...and so is an absurd r, an absurd p, and an oversized salt",
      not _bk._decrypt_archive(_kdf_blob(r=4096), _kdf_out, "pw")[0]
      and not _bk._decrypt_archive(_kdf_blob(p=9999), _kdf_out, "pw")[0]
      and not _bk._decrypt_archive(_kdf_blob(salt_len=8192), _kdf_out, "pw")[0])
check("backup/enc: the parameters this panel itself writes are still accepted",
      _bk._decrypt_archive(_kdf_blob(), _kdf_out, "pw")[1]
      != "The encrypted backup's header asks for parameters this panel will not use.")
_sh2.rmtree(_kdf_tmp, ignore_errors=True)

_sh2.rmtree(_bktmp, ignore_errors=True)

# ── per-server backup schedules (config-backed; swap in an in-memory config) ──
def _fake_update(fakecfg, m):   # mirror config.update_config (backup now writes via update_config)
    c = dict(fakecfg)
    m(c)
    fakecfg.clear()
    fakecfg.update(c)
    return c


_sched_load, _sched_update = _bk.load_config, _bk.update_config
_fakecfg = {}
_bk.load_config = lambda: dict(_fakecfg)
_bk.update_config = lambda m: _fake_update(_fakecfg, m)
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
    # check(..., True) after the call could only ever CRASH the suite, never fail it — a raise
    # here took the whole run down with a traceback instead of reporting one red line. Catch it,
    # so the assertion is about the behaviour rather than about the interpreter surviving.
    try:
        _bk.remove_game_schedule(77)
        _junk_ok, _junk_err = True, ""
    except Exception as _je:
        _junk_ok, _junk_err = False, repr(_je)
    check("schedule: remove_game_schedule is a safe no-op on junk", _junk_ok, _junk_err)
finally:
    _bk.load_config, _bk.update_config = _sched_load, _sched_update

# ── full (game-file) backups: per-server LinuxGSM backup + settings/due ──
_orig_run7 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (
        "F\tgmodserver-2026.tar.gz\t1048576\t1720000000\nF\told.tar.gz\t500\t1719000000\n", "", 0)
    _gbl = _sm_cron.list_game_backups(None, "gm")
    check("game backups: parsed newest-first with sizes",
          len(_gbl) == 2 and _gbl[0]["name"] == "gmodserver-2026.tar.gz" and _gbl[0]["size"] == 1048576)
    check("game backups: no lock -> nothing marked in-progress",
          not any(b.get("in_progress") for b in _gbl))
    # Lock present + a NEW archive written after the backup started (lock mtime 1720000050) -> that
    # new one is in-progress; the pre-existing older backup is not.
    _sm_core.run_command = lambda s, c, **k: (
        "F\tgmodserver-new.tar.zst\t2000\t1720000100\nF\tgmodserver-old.tar.zst\t1048576\t1720000000\n"
        "LOCK\t1720000050.5\n", "", 0)
    _gbl2 = _sm_cron.list_game_backups(None, "gm")
    check("game backups: active lock flags the new archive in-progress only",
          _gbl2[0]["name"] == "gmodserver-new.tar.zst" and _gbl2[0].get("in_progress") is True
          and not _gbl2[1].get("in_progress"))
    # Early in a backup (lock present, new archive not created yet): the existing backup predates the
    # lock, so it must NOT be flagged/hidden — this is the "existing backup disappears" regression.
    _sm_core.run_command = lambda s, c, **k: (
        "F\tgmodserver-old.tar.zst\t1048576\t1720000000\nLOCK\t1720000050.5\n", "", 0)
    _gbl3 = _sm_cron.list_game_backups(None, "gm")
    check("game backups: a pre-existing backup isn't hidden while a new one is starting",
          len(_gbl3) == 1 and not _gbl3[0].get("in_progress"))
finally:
    _sm_core.run_command = _orig_run7
_cap7 = {"cmds": []}
_orig_run8 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (_cap7["cmds"].append(c), ("", "", 0))[1]
    _gok, _, _gskip = _sm_game.run_game_backup(None, "gm", "gmodserver", 2)
    _joined = " ".join(_cap7["cmds"])
    check("run_game_backup: runs LinuxGSM backup as the game user",
          _gok is True and _gskip is False and "sudo -u gm bash -c" in _joined and "./gmodserver backup" in _joined)
    check("run_game_backup: prunes to keep N (keep=2 -> tail +3)", "tail -n +3" in _joined)
finally:
    _sm_core.run_command = _orig_run8

# ── players-online guard: don't kick players for a backup unless forced ──
_orig_run8b = _sm_core.run_command
try:
    # gamedig query reports 2 players; the LinuxGSM backup command must NOT run.
    def _run_busy(s, c, **k):
        if "gamedig" in c:
            return ("2", "", 0)
        return ("", "", 0)
    _cap_busy = {"cmds": []}
    _sm_core.run_command = lambda s, c, **k: (_cap_busy["cmds"].append(c), _run_busy(s, c, **k))[1]
    _pc = _sm_cron.player_count(None, "gm", "gmod", 27015)
    check("player_count: parses gamedig player count", _pc == 2)
    _bok, _bmsg, _bskip = _sm_game.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: skips (no backup) when players are online",
          _bok is False and _bskip is True and "backup" not in " ".join(c for c in _cap_busy["cmds"] if "gamedig" not in c))
    # force=True backs up anyway even with players on
    _cap_busy["cmds"] = []
    _fok, _fmsg, _fskip = _sm_game.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015, force=True)
    check("run_game_backup: force=True backs up even with players online",
          _fok is True and _fskip is False and "./gmodserver backup" in " ".join(_cap_busy["cmds"]))
finally:
    _sm_core.run_command = _orig_run8b

# ── empty/unqueryable server: player_count None, backup proceeds ──
_orig_run8c = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: ("0", "", 0) if "gamedig" in c else ("", "", 0)
    check("player_count: 0 players -> 0", _sm_cron.player_count(None, "gm", "gmod", 27015) == 0)
    check("player_count: unmapped game -> None (unknown)", _sm_cron.player_count(None, "gm", "nosuchgame", 27015) is None)
    check("player_count: no port -> None", _sm_cron.player_count(None, "gm", "gmod", None) is None)
    _eok, _emsg, _eskip = _sm_game.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: empty server backs up normally", _eok is True and _eskip is False)
finally:
    _sm_core.run_command = _orig_run8c

# ── 'Lockfile found' (LinuxGSM exits 0 but made no backup) must NOT read as success ──
_orig_lock = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: ("[ INFO ] Backup gmodserver: Lockfile found: Backup is currently running", "", 0)
    _lok, _lmsg, _lskip = _sm_game.run_game_backup(None, "gm", "gmodserver", 2)
    check("run_game_backup: 'Lockfile found' at exit 0 is treated as failure",
          _lok is False and _lskip is False and "lock" in _lmsg.lower())
finally:
    _sm_core.run_command = _orig_lock

# ── pre-flight disk guard: don't start a doomed backup when the disk is full ──
check("_fmt_size: bytes/MB/GB readable",
      _sm_cron._fmt_size(0) == "0 B" and _sm_cron._fmt_size(512) == "512 B"
      and _sm_cron._fmt_size(5 * 1024 * 1024) == "5.0 MB" and _sm_cron._fmt_size(2 * 1024 ** 3) == "2.0 GB")
_hs_saved = (_sm_cron._ensure_backup_headroom, _sm_cron.list_game_backups, _sm_cron.backup_disk_info, _sm_core.run_command)
try:
    _GB2 = 1024 ** 3
    _sm_cron._ensure_backup_headroom = lambda s, u, k: ""       # nothing left to free
    _sm_cron.list_game_backups = lambda s, u: [{"name": "b-1", "size": int(1.2 * _GB2), "created": 1}]
    _sm_cron.backup_disk_info = lambda s, u: {"free": 22 * 1024 * 1024, "total": 23 * _GB2}   # ~22 MB free
    _pf_cmds = []
    _sm_core.run_command = lambda s, c, **k: (_pf_cmds.append(c), ("", "", 0))[1]
    _pok, _pmsg, _pskip = _sm_game.run_game_backup(None, "cs", "codserver", 2)
    check("run_game_backup: full disk -> clear 'Not enough disk space' failure, no backup run",
          _pok is False and _pskip is False and "Not enough disk space" in _pmsg
          and not any("./codserver backup" in c for c in _pf_cmds))
finally:
    (_sm_cron._ensure_backup_headroom, _sm_cron.list_game_backups, _sm_cron.backup_disk_info, _sm_core.run_command) = _hs_saved

# ── mod-restart decision (pure): restart when empty, defer when busy/unknown, force wins ──
check("mod_restart_decision: stopped server -> idle (loads on next start)",
      _sm_game.mod_restart_decision("offline", None) == "idle")
check("mod_restart_decision: online + empty -> restart now",
      _sm_game.mod_restart_decision("online", 0) == "restart")
check("mod_restart_decision: online + players -> pending (don't kick)",
      _sm_game.mod_restart_decision("online", 3) == "pending")
check("mod_restart_decision: online + unknown count -> pending (can't confirm empty)",
      _sm_game.mod_restart_decision("online", None) == "pending")
check("mod_restart_decision: unknown status -> pending",
      _sm_game.mod_restart_decision("unknown", None) == "pending")
check("mod_restart_decision: force restarts even with players online",
      _sm_game.mod_restart_decision("online", 5, force=True) == "restart")
check("mod_restart_decision: force on a stopped server stays idle (nothing to restart)",
      _sm_game.mod_restart_decision("offline", 5, force=True) == "idle")

# ── smart headroom: free space before a backup only when the disk is tight ──
_hr_saved = (_sm_cron.list_game_backups, _sm_cron.backup_disk_info, _sm_cron.delete_game_backup)
try:
    _GB = 1024 ** 3
    _hr_deleted = []
    _sm_cron.delete_game_backup = lambda s, u, name: (_hr_deleted.append(name), True)[1]
    _three = [{"name": "g-3", "size": 4 * _GB, "created": 300},
              {"name": "g-2", "size": 4 * _GB, "created": 200},
              {"name": "g-1", "size": 4 * _GB, "created": 100}]
    _sm_cron.list_game_backups = lambda s, u: list(_three)
    # plenty of room -> no deletion
    _sm_cron.backup_disk_info = lambda s, u: {"free": 57 * _GB, "total": 60 * _GB}
    _hr_deleted[:] = []
    _n1 = _sm_cron._ensure_backup_headroom(None, "gm", 2)
    check("headroom: with free disk, nothing is deleted", _hr_deleted == [] and _n1 == "")
    # tight -> delete oldest first, protect the newest (keep-1)
    _sm_cron.backup_disk_info = lambda s, u: {"free": 1 * _GB, "total": 60 * _GB}
    _hr_deleted[:] = []
    _n2 = _sm_cron._ensure_backup_headroom(None, "gm", 2)
    check("headroom: tight disk frees the OLDEST backup first, protects newest",
          _hr_deleted[:1] == ["g-1"] and "g-3" not in _hr_deleted and _n2)
    # no backups yet -> nothing to free
    _sm_cron.list_game_backups = lambda s, u: []
    _hr_deleted[:] = []
    check("headroom: no backups yet -> no deletion", _sm_cron._ensure_backup_headroom(None, "gm", 2) == "" and _hr_deleted == [])
    # 0-byte newest is a failed backup (junk): delete it first, protect the good older one, and
    # estimate from the LARGEST (so a 0-byte newest doesn't make it skip on a full disk).
    _sm_cron.list_game_backups = lambda s, u: [{"name": "junk", "size": 0, "created": 300},
                                         {"name": "good", "size": 226 * _GB, "created": 200}]
    _sm_cron.backup_disk_info = lambda s, u: {"free": 50 * 1024 * 1024, "total": 25 * _GB}
    _hr_deleted[:] = []
    _sm_cron._ensure_backup_headroom(None, "pmc", 2)
    check("headroom: deletes 0-byte junk first, protects the valid backup",
          _hr_deleted == ["junk"])
finally:
    _sm_cron.list_game_backups, _sm_cron.backup_disk_info, _sm_cron.delete_game_backup = _hr_saved

_fake_cfg = {}
_orig_bkload, _orig_bkupdate = _bk.load_config, _bk.update_config
_bk.load_config = lambda: dict(_fake_cfg)
_bk.update_config = lambda m: _fake_update(_fake_cfg, m)
try:
    _fs = _bk.set_full_settings(interval_days=7, keep=2)
    check("full backup: settings save round-trip", _fs["interval_days"] == 7 and _fs["keep"] == 2)
    check("full backup: due when never run", _bk.full_backup_due() is True)
    _bk.record_full_backup("2 server(s) backed up")
    check("full backup: not due right after a run", _bk.full_backup_due() is False)
    _bk.set_full_settings(interval_days=0)
    check("full backup: interval 0 = off (never due)", _bk.full_backup_due() is False)
finally:
    _bk.load_config, _bk.update_config = _orig_bkload, _orig_bkupdate

# ── alerts: lgsm_get_values reads merged config, instance overrides win ──
_orig_run9 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (
        'discordalert="off"\ndiscordwebhook="default"\nemailalert="on"\n'
        'discordalert="on"\ndiscordwebhook="https://x/hook"\n', "", 0)
    _av = _sm_files.lgsm_get_values(None, "gm", "gmodserver",
                             ["discordalert", "discordwebhook", "emailalert", "missingkey"])
    check("lgsm_get_values: later (instance) value wins",
          _av["discordwebhook"] == "https://x/hook" and _av["discordalert"] == "on")
    check("lgsm_get_values: reads other toggles; missing key -> empty",
          _av["emailalert"] == "on" and _av["missingkey"] == "")
finally:
    _sm_core.run_command = _orig_run9

# line splitting
eq("cron: split 5-field", _sm_cron._split_cron_line("0 3 * * * /home/gm/b.sh a"), ("0 3 * * *", "/home/gm/b.sh a"))
eq("cron: split @shortcut", _sm_cron._split_cron_line("@reboot /home/gm/x start"), ("@reboot", "/home/gm/x start"))
eq("cron: split rejects short line", _sm_cron._split_cron_line("0 3 * *"), (None, None))

# ── anti-lockout: disabling public SSH must be refused with no Tailscale path back in ──
# ...and the RESULT must be read back off the host. remote_set_public_ssh used to return True
# unconditionally after firing its verbs, so a host with no ufw at all answered "✓ Public SSH is
# now disabled (tailnet-only)" with port 22 open to the internet, and wrote an audit row saying
# the hardening succeeded. Its exit codes cannot settle it either — a delete of an absent rule is
# a normal non-zero, which is exactly why they were being ignored — so it asks ufw what it ended
# up with. That makes the firewall state part of these fixtures.
_orig_rc = _sm_core.run_command
_orig_rp = _sm_core.run_privileged

# `ufw status` as it reads for each resulting mode. remote_public_ssh_status parses this.
_UFW_BY_MODE = {
    "allow": "Status: active\n\n22/tcp                     ALLOW IN    Anywhere\n",
    "limit": "Status: active\n\n22/tcp                     LIMIT IN    Anywhere\n",
    "off": "Status: active\n\n27015                      ALLOW IN    Anywhere\n",
}


def _ufw_says(mode, tailscale_iface=False):
    """Stub run_privileged so the host reports having ended up in `mode`.

    `ufw-status verbose` is a DIFFERENT question — _tailnet_ssh_state asks it to find out whether
    the tailscale0 interface is allowed — so the two are answered separately."""
    def _rp(s, v, a=(), **k):
        if v != "ufw-status":
            return ("", "", 0)
        if list(a)[:1] == ["verbose"]:
            return ("Anywhere on tailscale0     ALLOW IN    Anywhere\n" if tailscale_iface
                    else "Status: active\n", "", 0)
        return (_UFW_BY_MODE[mode], "", 0)
    _sm_core.run_privileged = _rp


try:
    def _rc_no_tailnet(server, cmd, **kw):
        if "status --json" in cmd:
            return ('{"BackendState":"Stopped"}', "", 0)   # Tailscale not running
        return ("", "", 0)
    _sm_core.run_command = _rc_no_tailnet
    _ufw_says("off")
    _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), "off")
    check("ssh off REFUSED when no Tailscale path (anti-lockout)",
          _ok is False and "lock you out" in _msg.lower(), str(_msg))

    def _rc_ts_ssh(server, cmd, **kw):
        if "status --json" in cmd:
            return ('{"BackendState":"Running"}', "", 0)
        if "debug prefs" in cmd:
            return ('{"RunSSH": true}', "", 0)                # Tailscale SSH enabled
        return ("", "", 0)
    _sm_core.run_command = _rc_ts_ssh
    _ufw_says("off")
    check("ssh off ALLOWED when Tailscale SSH enabled",
          _sm_hosts.remote_set_public_ssh(object(), "off")[0] is True)

    def _rc_iface(server, cmd, **kw):
        if "status --json" in cmd:
            return ('{"BackendState":"Running"}', "", 0)
        if "debug prefs" in cmd:
            return ('{"RunSSH": false}', "", 0)
        if "ufw status" in cmd:
            return ("Anywhere on tailscale0     ALLOW IN    Anywhere", "", 0)  # tailscale0 allowed
        return ("", "", 0)
    _sm_core.run_command = _rc_iface
    _ufw_says("off", tailscale_iface=True)
    check("ssh off ALLOWED when tailscale0 allowed in UFW",
          _sm_hosts.remote_set_public_ssh(object(), "off")[0] is True)

    _sm_core.run_command = lambda *a, **k: ("", "", 0)
    _ufw_says("allow")
    check("ssh allow is never lockout-guarded",
          _sm_hosts.remote_set_public_ssh(object(), "allow")[0] is True)
    _ufw_says("limit")
    check("ssh limit is never lockout-guarded",
          _sm_hosts.remote_set_public_ssh(object(), "limit")[0] is True)

    # A host with no ufw: every verb fails and the firewall reports nothing. This used to answer
    # (True, "Public SSH is now rate-limited").
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "ufw: command not found", 127)
    _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), "limit")
    check("ssh mode: a host with no active UFW is refused, not reported as hardened",
          _ok is False and "not active" in _msg.lower(), str(_msg))

    # ...and a host where UFW is up but the rule did not take.
    _ufw_says("allow")
    _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), "limit")
    check("ssh mode: a rule that did not take is reported as the failure it is",
          _ok is False and "still reports" in _msg.lower(), str(_msg))
finally:
    _sm_core.run_command = _orig_rc
    _sm_core.run_privileged = _orig_rp

# ── secret encryption round-trip ──────────────────────────────
_pre = {p for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE)
        if os.path.exists(p)}
enc = config.encrypt_secret("hunter2")
check("encrypt adds enc: prefix", enc.startswith("enc:v1:"))
check("is_encrypted true for ciphertext", config.is_encrypted(enc))
eq("decrypt round-trips", config.decrypt_secret(enc), "hunter2")
eq("encrypt empty -> empty", config.encrypt_secret(""), "")
eq("decrypt legacy plaintext passthrough", config.decrypt_secret("plainpw"), "plainpw")

# A secret that ITSELF starts with the marker must not be mistaken for ciphertext. The prefix
# check alone stored it verbatim — plaintext, in the one function whose job is to prevent that —
# and decrypt_secret then returned "" forever, so the credential was both exposed and destroyed.
# Reachable with any user-chosen secret: an SSH password, a Telegram/Discord/ntfy token.
_looks_enc = "enc:v1:MyActualSSHPassw0rd!"
_stored = config.encrypt_secret(_looks_enc)
check("encrypt: a secret starting with enc:v1: is NOT stored in plaintext",
      _stored != _looks_enc and "MyActualSSHPassw0rd" not in _stored, _stored[:40])
eq("encrypt: ...and it round-trips back intact", config.decrypt_secret(_stored), _looks_enc)
check("is_encrypted: false for a plaintext value that merely carries the prefix",
      not config.is_encrypted(_looks_enc))
eq("decrypt: such a legacy value is handed back whole, not lost as ''",
   config.decrypt_secret(_looks_enc), _looks_enc)
# Idempotency — the reason the prefix check existed — must survive the stricter test.
eq("encrypt: re-encrypting real ciphertext is still a no-op",
   config.encrypt_secret(_stored), _stored)
eq("encrypt: ...round-tripped after the second call too",
   config.decrypt_secret(config.encrypt_secret(_stored)), _looks_enc)
# The structural token test must not need the key: with cred_key gone, a real ciphertext still has
# to read as encrypted, or the startup migration would re-encrypt it under a new key and put it
# permanently out of reach of the original one.
check("is_encrypted: a real ciphertext still reads as encrypted without consulting the key",
      config._is_fernet_token(_stored[len("enc:v1:"):]))
check("is_encrypted: rejects a prefix followed by valid base64 that is not a Fernet token",
      not config.is_encrypted("enc:v1:aGVsbG8gd29ybGQ="))

# ── UFW rule grouping: port / protocol split ──────────────────
def _rules(rs):
    return [{"num": str(i + 1), "detail": d} for i, d in enumerate(rs)]


groups = _sm_firewall._group_ufw_rules(_rules([
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
    # Restores what it replaces. It used to leave sm.is_local_server stubbed for the REST of the
    # suite — every later test saw whatever the last protect() call happened to pass, which is how
    # a stub stops being scaffolding and starts being a silent global. Nothing depended on the leak
    # (this fix changed no other result), but the transport tests further down do read the real
    # is_local_server, and would have been testing the wrong branch.
    _saved = (_sm_core.is_local_server, _sm_hosts._tailscale_conn_state, config.load_config)
    try:
        _sm_core.is_local_server = lambda s: is_local
        _sm_hosts._tailscale_conn_state = lambda s: tailscale   # (running, ssh_enabled) — deterministic
        if cfg is not None:
            config.load_config = lambda: cfg
        return _sm_firewall._annotate_firewall_protection(server, enabled, _sm_firewall._group_ufw_rules(_rules(rules)))
    finally:
        _sm_core.is_local_server, _sm_hosts._tailscale_conn_state, config.load_config = _saved


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

# `ufw allow OpenSSH` — ufw's APP PROFILE, the form Ubuntu's own docs and `ufw app list` steer
# people to. It prints the profile NAME in the To column, so port_num is "OpenSSH" and the
# pn.isdecimal() test was False: is_ssh and is_access were both False, which means protected AND
# warn were both False, and remote_ufw_delete_rule (which gates only on protected) deleted the
# host's only way in without a word.
g = protect(NS(port=22), ["OpenSSH ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("ufw app profile 'OpenSSH' is recognised as SSH", gp["OpenSSH"]["is_ssh"])
check("...and protected as the only way in", gp["OpenSSH"]["protected"])
check("...while a non-SSH profile-less port beside it is not", not gp["5000"]["is_ssh"])

# `ufw allow in on eth0 to any port 22` — interface-scoped SSH. It prints "22 on eth0", so
# is_iface was True and the blanket `not is_iface` threw it away. An inbound rule on ANY interface
# to an SSH port is still a way in.
g = protect(NS(port=22), ["22 on eth0 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("interface-scoped SSH is recognised as SSH", gp["22"]["is_ssh"])
check("...and protected as the only way in", gp["22"]["protected"])

# The panel's own web port opened with `ufw limit` — is_ssh learned that LIMIT is a way in and
# is_panel did not, so the only route to the panel UI stayed deletable. And is_panel never checked
# direction, so an ALLOW OUT rule on that port was treated AS the panel rule and made undeletable.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp LIMIT IN Anywhere"],
            is_local=True, cfg={"port": 5000})
gp = {x["port_num"]: x for x in g}
check("a rate-limited panel web port is still the panel rule", gp["5000"]["is_panel"])
check("...and is protected", gp["5000"]["protected"])
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW OUT Anywhere"],
            is_local=True, cfg={"port": 5000})
gp = {x["port_num"]: x for x in g}
check("an OUTbound rule on the panel port is not the panel rule", not gp["5000"]["is_panel"])
check("...and is therefore deletable", not gp["5000"]["protected"])

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
_orig_run = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: ("Status: active\n5000/tcp  ALLOW  Anywhere\n"
                                        "22/tcp  ALLOW  Anywhere\n", "", 0)
    check("ssh-status: panel port open detected",
          _sm_hosts.remote_public_ssh_status(NS(), panel_port=5000).get("panel_port_open") is True)
    # Closed: only a tailscale0 rule and a *different* port — must read as closed, and 27015
    # must not word-boundary-match 5000.
    _sm_core.run_command = lambda s, c, **k: ("Status: active\nAnywhere  ALLOW  Anywhere on tailscale0\n"
                                        "27015  ALLOW  Anywhere\n", "", 0)
    check("ssh-status: panel port closed detected (no false match on 27015)",
          _sm_hosts.remote_public_ssh_status(NS(), panel_port=5000).get("panel_port_open") is False)
    # Without panel_port the key is omitted entirely (remote hosts don't report it).
    check("ssh-status: panel_port_open omitted when not asked",
          "panel_port_open" not in _sm_hosts.remote_public_ssh_status(NS()))
finally:
    _sm_core.run_command = _orig_run

# ── game-port selection: open only what's needed ──────────────
_GMOD_DETAILS = """\
Some header text
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Client 27005 udp
SourceTV 27020 udp
"""
_sm_core.run_as_game_user = lambda *a, **k: (_GMOD_DETAILS, "", 0)
res = _sm_game.detect_game_ports(NS(), "gmodserver")
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
_sm_core.run_as_game_user = lambda *a, **k: (_SRC_DETAILS, "", 0)
res = _sm_game.detect_game_ports(NS(), "srv")
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
import time as _time
from panel.security.auth import generate_totp_secret, verify_totp
import pyotp as _pyotp
_sec = generate_totp_secret()
check("verify_totp accepts the current code", verify_totp(_sec, _pyotp.TOTP(_sec).now()))
check("verify_totp accepts a spaced code", verify_totp(_sec, " " + _pyotp.TOTP(_sec).now() + " "))
check("verify_totp rejects a wrong code", not verify_totp(_sec, "000000"))
check("verify_totp rejects empty", not verify_totp(_sec, ""))

# A TOTP code stays valid for ~90s (its own step plus one either side for clock skew), so
# "is it valid" alone lets an observed code be replayed for the rest of that window. The login
# path records WHICH step was spent, so it needs the step back, not a boolean.
from panel.security.auth import verify_totp_step
_step = verify_totp_step(_sec, _pyotp.TOTP(_sec).now())
check("verify_totp_step returns the step for a valid code", isinstance(_step, int) and _step > 0)
eq("verify_totp_step is stable for the same code", verify_totp_step(_sec, _pyotp.TOTP(_sec).now()), _step)
eq("verify_totp_step: the step matches the clock", _step, int(_time.time()) // 30)
check("verify_totp_step rejects a wrong code", verify_totp_step(_sec, "000000") is None)
check("verify_totp_step rejects empty", verify_totp_step(_sec, "") is None)
check("verify_totp_step tolerates a junk secret", verify_totp_step("not-base32!", "123456") is None)
# The previous step must still verify (clock skew) and report ITS step, not the current one —
# otherwise a code accepted near a boundary would look like a replay of the newer step.
_prev = _pyotp.TOTP(_sec).at(int(_time.time()) - 30)
_prev_step = verify_totp_step(_sec, _prev)
check("verify_totp_step accepts the previous step and reports it as older",
      _prev_step is not None and _prev_step == _step - 1, "%r vs %r" % (_prev_step, _step))

# ── password check robustness (a bad stored hash must never raise) ───
from panel.security.auth import check_password, hash_password, dummy_password_check
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
from panel.security.auth import generate_backup_codes
from panel.db.models import User as _User
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

# ── Password history ──────────────────────────────────────────
# "Change your password" is satisfiable by putting back the one you just left, which is exactly
# what someone does when made to change a password they were happy with. set_password remembers
# the outgoing one; password_reused refuses it coming back.
import json
from panel.db.models import PASSWORD_HISTORY_LEN as _PHL


def _hist(u):
    """The stored history as a list, whatever is actually in the column.

    Tolerant on purpose: several checks below assert that set_password REPAIRS a malformed value,
    and a bare json.loads would crash on the un-repaired column instead of failing the check —
    turning "this assertion caught the bug" into "the whole suite stopped at import"."""
    try:
        parsed = json.loads(u.password_history or "[]")
        return parsed if isinstance(parsed, list) else []
    except (ValueError, TypeError):
        return []
from panel.security.auth import hash_password as _hp
_pu = _User()
_pu.password_hash = _hp("First1!pass")
check("history: the CURRENT password counts as reused", _pu.password_reused("First1!pass"))
check("history: an unrelated password does not", not _pu.password_reused("Totally2@other"))
_pu.set_password(_hp("Second2@pass"))
check("history: after a change, the new one is current", _pu.password_reused("Second2@pass"))
check("history: ...and the one it replaced is remembered", _pu.password_reused("First1!pass"))
# Walk past the window: the oldest must fall out, or "history" would grow without bound and every
# change would cost another bcrypt comparison.
_chain = ["Third3#pass", "Fourth4$pass", "Fifth5%pass", "Sixth6^pass"]
for _p in _chain:
    _pu.set_password(_hp(_p))
_pu_hist = _hist(_pu)
check("history: the window holds exactly PASSWORD_HISTORY_LEN previous passwords",
      len(_pu_hist) == _PHL, "len=%d want=%d" % (len(_pu_hist), _PHL))
check("history: the last few are all still refused",
      all(_pu.password_reused(p) for p in _chain[-_PHL:]))
check("history: one older than the window is allowed again",
      not _pu.password_reused("First1!pass"))
# A repeat inside the window must not consume a second slot — it would silently shorten the
# window by pushing a genuinely older password out and remembering the same one twice.
_du = _User()
_du.password_hash = _hp("Alpha1!pass")
_du.set_password(_hp("Beta2@pass"))
_du.set_password(_hp("Alpha1!pass"))
_du.set_password(_hp("Gamma3#pass"))
_du_hist = _hist(_du)
check("history: a repeated password is de-duped, not stored twice",
      _du_hist and len(_du_hist) == len(set(_du_hist)), repr(_du_hist)[:80])
check("history: ...and everything in the window is still refused",
      _du.password_reused("Alpha1!pass") and _du.password_reused("Beta2@pass")
      and _du.password_reused("Gamma3#pass"))
# A row written by an older version, or corrupted, must not 500 a password change.
_bu = _User()
_bu.password_hash = _hp("Only1!pass")
for _bad in ("", "not json", "null", '{"not": "a list"}', '[123, null]'):
    _bu.password_history = _bad
    check("history: a malformed history column is ignored, not fatal (%r)" % _bad[:12],
          _bu.password_reused("Only1!pass") and not _bu.password_reused("Other2@pass"))
_bu.password_history = "not json"
_bu.set_password(_hp("Next2@pass"))
check("history: ...and set_password replaces the garbage with a real one-entry history",
      len(_hist(_bu)) == 1 and _bu.password_reused("Only1!pass"),
      repr(_bu.password_history)[:80])
# A brand-new account has nothing to remember.
_nu = _User()
_nu.set_password(_hp("Brand1!new"))
check("history: a first password records no history", not _hist(_nu))
